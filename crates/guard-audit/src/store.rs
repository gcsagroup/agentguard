//! SQLite-backed audit store (optional SQLCipher via `sqlcipher` feature).

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::{apply_key, cipher_active, resolve_passphrase, sqlcipher_enabled};
use crate::signing::{
    is_valid_hash, receipt_signing_message, record_signing_message, AuditSigner, AuditVerifyKey,
    SignatureVerifyReport,
};
use crate::types::{AuditRecord, SessionSummary, UserDecision};

#[path = "recovery.rs"]
pub mod recovery;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  timestamp_ms INTEGER NOT NULL,
  platform TEXT,
  event_type TEXT,
  source_app TEXT,
  agent_session_id TEXT,
  rule_id TEXT,
  severity TEXT,
  action TEXT,
  human_message TEXT,
  evidence_ref TEXT,
  user_decision TEXT,
  event_json TEXT,
  attributed_agent TEXT,
  prev_hash TEXT NOT NULL DEFAULT '',
  record_hash TEXT NOT NULL DEFAULT '',
  record_sig TEXT NOT NULL DEFAULT '',
  signer_key_id TEXT NOT NULL DEFAULT '',
  seq INTEGER NOT NULL DEFAULT 0
);

-- 这三个计数器是**不作数的缓存**,不是证据:它们由 UPDATE 累加,不在哈希链、也没签名,
-- 谁能写库就能改。`session_summary` **不读**它们 —— 它从 audit_events(action/agent_session_id
-- 都在 record_hash 覆盖内)现算,那才是防篡改的。计数器留着只为让写入侧便宜、以及历史兼容。
CREATE TABLE IF NOT EXISTS agent_sessions (
  id TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  agent_app TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,   -- 缓存,非证据(见上)
  block_count INTEGER NOT NULL DEFAULT 0,   -- 缓存,非证据
  alert_count INTEGER NOT NULL DEFAULT 0    -- 缓存,非证据
);

CREATE TABLE IF NOT EXISTS decision_receipts (
  audit_id TEXT NOT NULL,
  decision TEXT NOT NULL,
  decided_at_ms INTEGER NOT NULL,
  prev_hash TEXT NOT NULL,
  receipt_hash TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'user',
  receipt_sig TEXT NOT NULL DEFAULT '',
  signer_key_id TEXT NOT NULL DEFAULT '',
  seq INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(agent_session_id);
-- 见证包含性检查(chain_contains_hash)按 record_hash / prev_hash 查存在性。
-- 没有这两个索引它是全表扫;audit-verify 现在每次都跑一次,所以给它们建索引。
CREATE INDEX IF NOT EXISTS idx_audit_record_hash ON audit_events(record_hash);
CREATE INDEX IF NOT EXISTS idx_audit_prev_hash ON audit_events(prev_hash);
"#;

const SELECT_COLS: &str = "id, timestamp_ms, platform, event_type, source_app, agent_session_id,
       rule_id, severity, action, human_message, evidence_ref, user_decision, event_json,
       attributed_agent";

/// Same columns, for a database written before `attributed_agent` existed.
///
/// A literal `NULL` in the column's place, so the projection keeps its width and every
/// index into it stays valid. Selecting the real column unconditionally made
/// `audit-verify`, `audit-export` and `audit-report` fail outright on a legacy
/// database — `open_read_only` deliberately runs no migration, so the only way to
/// verify such a log was to `audit-migrate` it first, i.e. to **write to the audit log
/// in order to verify it**, which is the one thing the read-only handle exists to
/// prevent. Same `has_column` pattern as the signature columns two functions away.
const SELECT_COLS_LEGACY: &str =
    "id, timestamp_ms, platform, event_type, source_app, agent_session_id,
       rule_id, severity, action, human_message, evidence_ref, user_decision, event_json,
       NULL";

/// SQLite's on-disk header. An encrypted SQLCipher database must not expose it.
const SQLITE_PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Domain-separated probe used before a signer is attached to a writable store.
///
/// Without a probe, a signer that loads successfully but cannot actually sign is
/// discovered only on the first append. By then the encrypted database and signer
/// metadata may already exist as two independently committed artifacts.
const SIGNER_PREFLIGHT: &[u8] = b"AGENTGUARD-AUDIT-SIGNER-PREFLIGHT-v1";

/// 必须和所引用审计日志一起移动的桌面运行时状态。
///
/// `guard-audit` 刻意不解释值：桌面壳拥有 `PersistedPending` schema，本 crate 只拥有
/// 加密且逐库隔离的存储边界。key 保持私有，避免调用方把审计元数据表变成无版本的通用 KV。
const PENDING_CONFIRMATIONS_META_KEY: &str = "runtime.pending_confirmations.v1";

#[derive(Debug)]
pub struct AuditStore {
    conn: Connection,
    /// When set, every appended record and receipt is signed. Absent = the store
    /// is tamper-evident (hash chain) but not attributed to anyone.
    signer: Option<Box<dyn AuditSigner>>,
}

fn map_record_row_at(row: &rusqlite::Row<'_>, base: usize) -> rusqlite::Result<AuditRecord> {
    // 一个 NULL 单元格**不能**让整个读取路径失败。
    //
    // 这些列是 `TEXT` 且映射到非 `Option<String>`。旧代码用 `row.get::<_, String>()`,遇到
    // NULL 会返回 `InvalidColumnType`,而这个错误一路冒泡,让 `verify_chain` / `export_jsonl`
    // / `list_recent` —— **整条读取路径** —— 全部失败。也就是攻击者只要把一个单元格改成
    // NULL,就让整个审计库无法被验证。这是对审计本身的拒绝服务。
    //
    // NULL 只可能来自篡改(`append` 写的都是非空值),而篡改已经会破坏那一行的链哈希。
    // 所以正确的方向是把 NULL 当成空串**继续读**,让验证跑到那一行、正确地把它报成链
    // 不匹配 —— 而不是拒绝去看整个库。fail-closed 应当落在那**一行**,不是落在能不能
    // 打开库上。
    let text = |i: usize| -> rusqlite::Result<String> {
        Ok(row.get::<_, Option<String>>(i)?.unwrap_or_default())
    };
    Ok(AuditRecord {
        id: text(base)?,
        timestamp_ms: row.get::<_, Option<i64>>(base + 1)?.unwrap_or(0),
        platform: text(base + 2)?,
        event_type: text(base + 3)?,
        source_app: text(base + 4)?,
        agent_session_id: row.get(base + 5)?,
        rule_id: text(base + 6)?,
        severity: text(base + 7)?,
        action: text(base + 8)?,
        human_message: text(base + 9)?,
        evidence_ref: row.get(base + 10)?,
        user_decision: row.get(base + 11)?,
        event_json: text(base + 12)?,
        attributed_agent: row.get(base + 13)?,
    })
}

fn map_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    map_record_row_at(row, 0)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn windows_release_requires_protected() -> bool {
    cfg!(all(target_os = "windows", not(debug_assertions)))
}

fn audit_sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

/// Detect a legacy plaintext container without asking SQLite to mutate it.
fn reject_legacy_plaintext(path: &std::path::Path) -> Result<()> {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect existing audit database {}", path.display()))
        }
    };
    let mut header = [0u8; SQLITE_PLAINTEXT_HEADER.len()];
    let read = file
        .read(&mut header)
        .with_context(|| format!("read audit header {}", path.display()))?;
    if read == header.len() && &header == SQLITE_PLAINTEXT_HEADER {
        let wal = audit_sidecar(path, "-wal");
        let shm = audit_sidecar(path, "-shm");
        bail!(
            "legacy plaintext audit database detected at {}. It was not opened or modified. Stop the old build, make an access-controlled offline backup of {}, {} and {} (when present), then follow the approved clear-or-migrate procedure; automatic in-place migration is disabled to prevent data loss",
            path.display(),
            path.display(),
            wal.display(),
            shm.display()
        );
    }
    Ok(())
}

/// Prove that the signer can sign now, and that an exported public key matches
/// both the produced signature and the advertised key id.
fn preflight_signer(signer: &dyn AuditSigner) -> Result<(String, Option<String>)> {
    let key_id = signer.key_id();
    if key_id.trim().is_empty() {
        bail!("audit signer returned an empty key id");
    }
    if signer.key_id() != key_id {
        bail!("audit signer key id changed during preflight");
    }
    let signature = signer
        .sign_message(SIGNER_PREFLIGHT)
        .context("audit signer preflight signature failed")?;
    let public_hex = signer.public_hex();
    if let Some(public) = public_hex.as_deref() {
        let verify_key = AuditVerifyKey::from_hex(public)
            .context("audit signer returned an invalid public key")?;
        if verify_key.key_id() != key_id {
            bail!(
                "audit signer key id {} does not match exported public key {}",
                key_id,
                verify_key.key_id()
            );
        }
        verify_key
            .verify_message(SIGNER_PREFLIGHT, &signature)
            .context("audit signer preflight signature did not verify")?;
    }
    Ok((key_id, public_hex))
}

fn verify_cipher_integrity(conn: &Connection) -> Result<()> {
    let mut statement = conn
        .prepare("PRAGMA cipher_integrity_check")
        .context("prepare PRAGMA cipher_integrity_check")?;
    let mut rows = statement
        .query([])
        .context("run PRAGMA cipher_integrity_check")?;
    let mut failures = Vec::new();
    while let Some(row) = rows.next()? {
        let message: String = row.get(0)?;
        if !message.eq_ignore_ascii_case("ok") {
            failures.push(message);
        }
    }
    if !failures.is_empty() {
        bail!("cipher_integrity_check reported: {}", failures.join("; "));
    }
    Ok(())
}

impl AuditStore {
    /// Open (or create) a plain SQLite audit DB. Honors `AGENTGUARD_AUDIT_KEY`
    /// when the `sqlcipher` feature is enabled.
    ///
    /// This compatibility entry is intentionally unavailable in Windows Release:
    /// a caller could otherwise omit the key or attach no signer and silently
    /// recreate the old plaintext path. Windows Release writers must use
    /// [`Self::open_runtime`] or [`Self::open_protected`].
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        if windows_release_requires_protected() {
            bail!(
                "AuditStore::open is disabled in Windows Release because it can create an unsigned or plaintext database; use AuditStore::open_runtime/open_protected"
            );
        }
        Self::open_with_key_unchecked(path.as_ref(), resolve_passphrase(None).as_deref())
    }

    /// Open with an explicit passphrase (`None` = unencrypted / env already applied by caller).
    /// Windows Release must use [`Self::open_protected`] so encryption and signing
    /// are one fail-closed startup requirement.
    pub fn open_with_key(
        path: impl AsRef<std::path::Path>,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        if windows_release_requires_protected() {
            bail!(
                "AuditStore::open_with_key is disabled in Windows Release because it does not attach a signer; use AuditStore::open_protected"
            );
        }
        Self::open_with_key_unchecked(path.as_ref(), passphrase)
    }

    /// Open a writer used by CLI/local API/native-host runtimes.
    ///
    /// Development builds and non-Windows targets retain the existing explicit
    /// plaintext option. Windows Release is different: both a non-empty
    /// `AGENTGUARD_AUDIT_KEY` and an already provisioned signer are mandatory,
    /// and validation completes before the store is returned to the engine.
    pub fn open_runtime(
        path: impl AsRef<std::path::Path>,
        signer: Option<Box<dyn AuditSigner>>,
    ) -> Result<Self> {
        let passphrase = resolve_passphrase(None);
        Self::open_runtime_with_mode(
            path.as_ref(),
            passphrase.as_deref(),
            signer,
            windows_release_requires_protected(),
        )
    }

    fn open_runtime_with_mode(
        path: &std::path::Path,
        passphrase: Option<&str>,
        signer: Option<Box<dyn AuditSigner>>,
        require_protected: bool,
    ) -> Result<Self> {
        if require_protected {
            let passphrase = passphrase.filter(|value| !value.is_empty()).ok_or_else(|| {
                anyhow::anyhow!(
                    "Windows Release audit requires a non-empty AGENTGUARD_AUDIT_KEY; refusing before creating {}",
                    path.display()
                )
            })?;
            let signer = signer.ok_or_else(|| {
                anyhow::anyhow!(
                    "Windows Release audit requires a provisioned signing key; refusing before creating {}",
                    path.display()
                )
            })?;
            return Self::open_protected(path, passphrase, signer);
        }

        let store = Self::open_with_key_unchecked(path, passphrase)?;
        match signer {
            Some(signer) => store.with_signer(signer),
            None => Ok(store),
        }
    }

    /// Open an encrypted, signed audit writer or return no usable store.
    ///
    /// A legacy plaintext SQLite header is detected before SQLite is opened. We
    /// deliberately do not auto-migrate it: the product owner has not selected
    /// clear-vs-migrate, and an in-place conversion without an independently
    /// retained backup/rollback contract risks data loss. The error names the DB
    /// and sidecars so an operator can back them up and take the approved path.
    pub fn open_protected(
        path: impl AsRef<std::path::Path>,
        passphrase: &str,
        signer: Box<dyn AuditSigner>,
    ) -> Result<Self> {
        let path = path.as_ref();
        if passphrase.is_empty() {
            bail!(
                "protected audit passphrase is empty; refusing before creating {}",
                path.display()
            );
        }

        // A broken signer must be discovered before the database is opened or
        // created. `with_signer` repeats this check to protect every caller.
        preflight_signer(signer.as_ref())?;
        reject_legacy_plaintext(path)?;
        if !sqlcipher_enabled() {
            bail!(
                "protected audit requires a SQLCipher-linked build; refusing before creating {}",
                path.display()
            );
        }

        let store = Self::open_with_key_unchecked(path, Some(passphrase))?;
        if !cipher_active(&store.conn) {
            bail!(
                "protected audit connection for {} is not SQLCipher; refusing an unencrypted writer",
                path.display()
            );
        }
        verify_cipher_integrity(&store.conn)
            .with_context(|| format!("SQLCipher integrity check failed for {}", path.display()))?;
        store.with_signer(signer)
    }

    fn open_with_key_unchecked(path: &std::path::Path, passphrase: Option<&str>) -> Result<Self> {
        if let Some(passphrase) = passphrase.filter(|value| !value.is_empty()) {
            // apply_key 的首次读以及失败连接的关闭都可能恢复/合并 WAL。先在加密副本上
            // 验证，不能以“最后返回 Err”冒充 DB/WAL/SHM 原件未被触碰。
            reject_legacy_plaintext(path)?;
            if !crate::sqlcipher_enabled() {
                bail!("加密审计需要 sqlcipher 构建，原文件未打开写入");
            }
            let snapshot = crate::snapshot::EncryptedSnapshot::capture(path)?;
            let probe = match &snapshot {
                Some(snapshot) => Connection::open(&snapshot.path)?,
                None => Connection::open_in_memory()?,
            };
            probe.pragma_update(None, "temp_store", "MEMORY")?;
            probe.pragma_update(None, "trusted_schema", false)?;
            apply_key(&probe, Some(passphrase))
                .context("AUDIT_KEY_OR_DATABASE_INVALID: 密钥或数据库无效，原文件未打开写入")?;
            if snapshot.is_some() {
                verify_cipher_integrity(&probe).context(
                    "AUDIT_KEY_OR_DATABASE_INVALID: 加密完整性检查失败，原文件未打开写入",
                )?;
            }
            let integrity: String =
                probe.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
            if integrity != "ok" {
                bail!("AUDIT_KEY_OR_DATABASE_INVALID: 数据库结构检查失败，原文件未打开写入");
            }
            drop(probe);
            if let Some(snapshot) = &snapshot {
                snapshot.verify_source()?;
            }
        }
        let conn =
            Connection::open(path).with_context(|| format!("open audit db {}", path.display()))?;
        apply_key(&conn, passphrase)?;
        // 跨进程写这同一个文件是**正常使用**(nm-host 每个连接一个进程),所以两件事都要设:
        //
        // * `busy_timeout` —— 后到的写者等而不是立刻 `SQLITE_BUSY`。没有它,`append` 里新加
        //   的事务只是把一个静默的链断裂换成一个随机失败。
        // * WAL —— 读者不阻塞写者,而验证走的是只读连接。
        //
        // 这两条以前都没有,`PRAGMA` 在这个文件里一次都没出现过。
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .context("set audit db busy_timeout")?;
        // WAL 设不上不是致命的(某些文件系统不支持),但要说出来而不是静默。
        if let Err(e) = conn.pragma_update(None, "journal_mode", "WAL") {
            eprintln!("agentguard: audit db WAL unavailable ({e}); concurrent readers may block");
        }
        let store = Self { conn, signer: None };
        store.migrate()?;
        Ok(store)
    }

    /// Open for verification only: no migrations, no writes.
    ///
    /// `audit-verify` must never touch the file it audits. The previous version
    /// ran migrations on open, which meant blanking `record_hash` made the
    /// verifier rebuild — and persist — a valid chain over forged content.
    pub fn open_read_only(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open audit db read-only {}", path.as_ref().display()))?;
        apply_key(&conn, resolve_passphrase(None).as_deref())?;
        // Belt and braces: reject writes even if a code path tries.
        conn.pragma_update(None, "query_only", true).ok();
        Ok(Self { conn, signer: None })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn, signer: None };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory store with SQLCipher key (only meaningful with `sqlcipher` feature).
    pub fn open_in_memory_with_key(passphrase: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        apply_key(&conn, Some(passphrase))?;
        let store = Self { conn, signer: None };
        store.migrate()?;
        Ok(store)
    }

    /// Attach a signer (Aura §4.4.6 attribution). Records appended from now on
    /// carry an Ed25519 signature over their chain hash; **existing rows are not
    /// retro-signed** — backdating an attestation would be a lie, so they stay
    /// `unsigned` in [`Self::verify_record_signatures`].
    ///
    /// The signer's public key is stored in `audit_meta` for tooling
    /// convenience. Verification should still take the key out of band: an
    /// attacker who can swap the key can swap that copy too.
    pub fn with_signer(mut self, signer: Box<dyn AuditSigner>) -> Result<Self> {
        let (key_id, public_hex) = preflight_signer(signer.as_ref())?;
        let tx = self
            .conn
            .transaction()
            .context("begin atomic audit signer attachment")?;
        if let Some(pk) = public_hex {
            tx.execute(
                "INSERT INTO audit_meta (key, value) VALUES ('signer_public_hex', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![pk],
            )?;
        } else {
            tx.execute("DELETE FROM audit_meta WHERE key = 'signer_public_hex'", [])?;
        }
        tx.execute(
            "INSERT INTO audit_meta (key, value) VALUES ('signer_key_id', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key_id],
        )?;
        tx.commit()
            .context("commit atomic audit signer attachment")?;
        self.signer = Some(signer);
        Ok(self)
    }

    pub fn signer_key_id(&self) -> Option<String> {
        self.signer.as_ref().map(|s| s.key_id())
    }

    /// Public key recorded in the database, if any. Informational only — see
    /// [`Self::with_signer`].
    pub fn embedded_public_hex(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM audit_meta WHERE key = 'signer_public_hex'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    /// 读取绑定到本审计库的桌面待确认快照。
    ///
    /// JSON schema 属于桌面壳。本方法原样返回已存字符串，使损坏值能留作诊断，而不是被
    /// 静默丢弃或重新解释。
    pub fn pending_confirmations_json(&self) -> Result<Option<String>> {
        self.meta(PENDING_CONFIRMATIONS_META_KEY)
    }

    /// 替换绑定到本审计库的桌面待确认快照。
    ///
    /// 单条 SQLite upsert 是原子的；受保护桌面构建中，该值和它引用的 audit id 处在同一
    /// SQLCipher 容器与密钥生命周期里。
    pub fn save_pending_confirmations_json(&self, json: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![PENDING_CONFIRMATIONS_META_KEY, json],
        )?;
        Ok(())
    }

    /// 删除本审计库里的桌面待确认快照。
    pub fn clear_pending_confirmations(&self) -> Result<()> {
        self.conn.execute(
            "DELETE FROM audit_meta WHERE key = ?1",
            params![PENDING_CONFIRMATIONS_META_KEY],
        )?;
        Ok(())
    }

    /// 原子提交一次桌面待确认状态转换。
    ///
    /// `decisions` 中的回执与 `remaining_json` 对运行时快照的替换共用一个 SQLite 事务。
    /// 任一记录不存在、签名失败或元数据写入失败都会回滚整批操作；调用方据此保持内存队列
    /// 不变并稍后重试。`remaining_json=None` 表示队列已空，应删除专用 key。
    pub fn commit_pending_confirmation_transition(
        &self,
        decisions: &[(&str, UserDecision)],
        remaining_json: Option<&str>,
    ) -> Result<()> {
        let mut unique_ids = std::collections::HashSet::with_capacity(decisions.len());
        for (audit_id, _) in decisions {
            if audit_id.trim().is_empty() {
                bail!("pending-confirmation transition contains an empty audit id");
            }
            if !unique_ids.insert(*audit_id) {
                bail!("pending-confirmation transition repeats audit id {audit_id}");
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin pending-confirmation transition")?;
        for (audit_id, decision) in decisions {
            // `unchecked_transaction` 已在同一 Connection 上执行 BEGIN；这些通过 `self.conn`
            // 发出的语句仍属于该事务。下面的回滚测试同时钉住这个 rusqlite 行为。
            self.set_user_decision(audit_id, *decision)?;
        }
        match remaining_json {
            Some(json) => self.save_pending_confirmations_json(json)?,
            None => self.clear_pending_confirmations()?,
        }
        tx.commit()
            .context("commit pending-confirmation transition")?;
        Ok(())
    }

    /// 把同库待确认项全部记为系统超时，并在同一事务中删除重启快照。
    ///
    /// 任一 audit id 不存在、签名失败或数据库写入失败都会回滚此前已写的回执，同时保留
    /// 原快照。这样下次启动不会给已处理前缀重复铸造回执，也不会把未处理后缀静默丢掉。
    pub fn timeout_pending_confirmations_and_clear(&self, audit_ids: &[&str]) -> Result<()> {
        let decisions: Vec<_> = audit_ids
            .iter()
            .map(|audit_id| (*audit_id, UserDecision::Timeout))
            .collect();
        self.commit_pending_confirmation_transition(&decisions, None)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        self.ensure_chain_columns()?;
        self.ensure_signature_columns()?;
        self.ensure_attribution_column()?;
        self.ensure_log_id()?;
        Ok(())
    }

    /// Per-database random id, mixed into every signature so a signed row cannot
    /// be transplanted from another log.
    fn ensure_log_id(&self) -> Result<String> {
        if let Some(existing) = self.meta("log_id")? {
            return Ok(existing);
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO audit_meta (key, value) VALUES ('log_id', ?1)
             ON CONFLICT(key) DO NOTHING",
            params![id],
        )?;
        Ok(self.meta("log_id")?.unwrap_or(id))
    }

    fn meta(&self, key: &str) -> Result<Option<String>> {
        if !self.has_table("audit_meta")? {
            return Ok(None);
        }
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM audit_meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    fn has_table(&self, name: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1")?
            .exists(params![name])?)
    }

    /// The record projection this database can actually satisfy.
    fn record_cols(&self) -> Result<&'static str> {
        Ok(if self.has_column("audit_events", "attributed_agent")? {
            SELECT_COLS
        } else {
            SELECT_COLS_LEGACY
        })
    }

    fn has_column(&self, table: &str, column: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare(&format!(
                "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
            ))?
            .exists(params![column])?)
    }

    /// The log id, when this database has one.
    pub fn log_id(&self) -> Result<Option<String>> {
        self.meta("log_id")
    }

    /// Add signature columns to pre-existing databases. Unlike the hash
    /// backfill, signatures are deliberately left empty: a hash can be
    /// recomputed from the row, but an attestation cannot be invented after the
    /// fact.
    fn ensure_signature_columns(&self) -> Result<()> {
        for (table, columns) in [
            (
                "audit_events",
                ["record_sig", "signer_key_id", "seq"].as_slice(),
            ),
            (
                "decision_receipts",
                ["actor", "receipt_sig", "signer_key_id", "seq"].as_slice(),
            ),
        ] {
            for col in columns {
                let exists: bool = self
                    .conn
                    .prepare(&format!(
                        "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
                    ))?
                    .exists(params![col])?;
                if !exists {
                    let (ty, default) = match *col {
                        "actor" => ("TEXT", "'user'"),
                        "seq" => ("INTEGER", "0"),
                        _ => ("TEXT", "''"),
                    };
                    self.conn.execute_batch(&format!(
                        "ALTER TABLE {table} ADD COLUMN {col} {ty} NOT NULL DEFAULT {default};"
                    ))?;
                }
            }
        }
        Ok(())
    }

    /// Add the Aura §4.4.6 attribution column to pre-existing databases.
    ///
    /// Nullable and with no default, so rows written before it existed stay `NULL` —
    /// and `chain::canonical_content` appends the field only when present, so those
    /// rows hash to exactly what they hashed when they were written and still verify.
    /// A `NOT NULL DEFAULT ''` column would have re-hashed every historical row into a
    /// broken chain, which reads as tampering.
    fn ensure_attribution_column(&self) -> Result<()> {
        let exists: bool = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('audit_events') WHERE name = ?1")?
            .exists(params!["attributed_agent"])?;
        if !exists {
            self.conn
                .execute_batch("ALTER TABLE audit_events ADD COLUMN attributed_agent TEXT;")?;
        }
        Ok(())
    }

    /// Add hash-chain columns to pre-existing databases.
    ///
    /// Deliberately does **not** backfill hashes: `open()` used to do that, which
    /// meant `audit-verify` recomputed and persisted a valid chain over whatever
    /// content it found whenever `record_hash` was empty — an attacker could blank
    /// the hash columns and have the verifier repair the log for them. Backfilling
    /// legacy rows is now an explicit [`Self::backfill_chain`] / `audit-migrate`
    /// step.
    fn ensure_chain_columns(&self) -> Result<()> {
        let has_col: bool = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('audit_events') WHERE name = 'record_hash'")?
            .exists([])?;
        if !has_col {
            self.conn.execute_batch(
                "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
                 ALTER TABLE audit_events ADD COLUMN record_hash TEXT NOT NULL DEFAULT '';",
            )?;
        }
        Ok(())
    }

    /// Number of rows that predate the hash chain and carry no hash.
    pub fn unhashed_rows(&self) -> Result<usize> {
        if !self.has_column("audit_events", "record_hash")? {
            return Ok(0);
        }
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE record_hash = ''",
            [],
            |row| row.get::<_, i64>(0),
        )? as usize)
    }

    /// Explicitly hash legacy rows written before the chain existed.
    ///
    /// Never call this from a verification path: a hash recomputed from current
    /// content says nothing about whether that content is original.
    pub fn backfill_chain(&self) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT rowid FROM audit_events WHERE record_hash = '' ORDER BY rowid ASC")?;
        let pending: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut done = 0usize;
        for rowid in pending {
            let prev: String = self
                .conn
                .query_row(
                    "SELECT record_hash FROM audit_events WHERE rowid < ?1 ORDER BY rowid DESC LIMIT 1",
                    params![rowid],
                    |row| row.get(0),
                )
                .optional()?
                .filter(|h: &String| !h.is_empty())
                .unwrap_or_else(|| crate::chain::GENESIS.to_string());
            let record = self.record_by_rowid(rowid)?;
            let hash = crate::chain::chain_hash(&prev, &record);
            self.conn.execute(
                "UPDATE audit_events SET prev_hash = ?2, record_hash = ?3 WHERE rowid = ?1",
                params![rowid, prev, hash],
            )?;
            done += 1;
        }
        Ok(done)
    }

    fn record_by_rowid(&self, rowid: i64) -> Result<AuditRecord> {
        let cols = self.record_cols()?;
        let sql = format!("SELECT {cols} FROM audit_events WHERE rowid = ?1");
        Ok(self.conn.query_row(&sql, params![rowid], map_record_row)?)
    }

    /// Next position number for `table`. Positions are contiguous from 1, which
    /// is what makes deleting a row from the middle of the log detectable.
    fn next_seq(&self, table: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            &format!("SELECT COALESCE(MAX(seq), 0) + 1 FROM {table}"),
            [],
            |row| row.get::<_, i64>(0),
        )?)
    }

    fn last_hash(&self) -> Result<String> {
        Ok(self
            .conn
            .query_row(
                "SELECT record_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| crate::chain::GENESIS.to_string()))
    }

    /// Verify the full hash chain (tamper-evident; see
    /// [`Self::verify_record_signatures`] for attribution).
    ///
    /// An empty `record_hash` counts as a **mismatch**, not as a row awaiting
    /// backfill — treating it as the latter is what let the verifier "repair" a
    /// forged log.
    pub fn verify_chain(&self) -> Result<crate::chain::ChainVerifyReport> {
        if !self.has_column("audit_events", "record_hash")? {
            let total = self
                .conn
                .query_row("SELECT COUNT(*) FROM audit_events", [], |r| {
                    r.get::<_, i64>(0)
                })? as usize;
            return Ok(crate::chain::ChainVerifyReport {
                ok: total == 0,
                total,
                verified: 0,
                first_mismatch_id: None,
            });
        }
        let sql = format!(
            "SELECT rowid, prev_hash, record_hash, {cols} FROM audit_events ORDER BY rowid ASC",
            cols = self.record_cols()?
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                map_record_row_at(row, 3)?,
            ))
        })?;
        let mut prev = crate::chain::GENESIS.to_string();
        let mut total = 0usize;
        let mut verified = 0usize;
        let mut first_mismatch_id = None;
        for row in rows {
            let (prev_stored, hash_stored, record) = row?;
            total += 1;
            let expected = crate::chain::chain_hash(&prev, &record);
            let ok = prev_stored == prev
                && hash_stored == expected
                && crate::signing::is_valid_hash(&hash_stored);
            if !ok && first_mismatch_id.is_none() {
                first_mismatch_id = Some(record.id.clone());
            }
            if ok {
                verified += 1;
                prev = hash_stored;
            } else {
                // Continue with stored hash to localize further damage.
                prev = hash_stored;
            }
        }
        Ok(crate::chain::ChainVerifyReport {
            ok: first_mismatch_id.is_none(),
            total,
            verified,
            first_mismatch_id,
        })
    }

    pub fn append(&self, record: &AuditRecord) -> Result<()> {
        // 整个"读头 → 算哈希 → 取 seq → 插入"必须在**一个事务**里。
        //
        // 这个文件里以前一处 `BEGIN` 都没有(`grep transaction|BEGIN|savepoint` 无匹配),
        // 而 `append` 先读 `last_hash()` 和 `next_seq()` 再 INSERT。两个进程同时写就会拿到
        // 同一个 `prev_hash` 和同一个 `seq`,链**永久**断掉 —— 而且一声不响:
        //
        // ```text
        // 两个并发写者各 25 次 append:rows=50 chain.ok=false verified=48/50
        // duplicate seq values: 2 / 2 / 1   (三次运行)
        // append errors: 0                  <- 一次错误都没有,调用方无从知晓
        // ```
        //
        // 这不在威胁模型里,在**正常使用**里:`guard-nm-host` 每个原生消息连接一个进程,
        // 各自打开同一个 `~/.local/share/agentguard/nm-audit.db`,跨进程无锁;或者
        // `api-serve` 加任意一条指向同一个 `--audit-db` 的 CLI 命令。进程**内**有
        // `Mutex<Engine>`,所以单进程是安全的 —— 问题只在跨进程。
        //
        // 后果是双向的:日志永久不可验证,同时给想抵赖的人递上现成台词("工具自己就会把
        // 日志搞坏")。而验证器给出的提示是 `"position N where M was expected (row deleted
        // or reordered)"` —— 一句谎话。
        //
        // `BEGIN IMMEDIATE` 在语句开始时就取写锁,所以两个写者里后到的那个会等(见
        // `busy_timeout`),而不是读到一个即将过期的头。
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin audit append transaction")?;
        self.append_in_tx(record)?;
        tx.commit().context("commit audit append")?;
        Ok(())
    }

    fn append_in_tx(&self, record: &AuditRecord) -> Result<()> {
        let prev_hash = self.last_hash()?;
        let record_hash = crate::chain::chain_hash(&prev_hash, record);
        let seq = self.next_seq("audit_events")?;
        let (record_sig, signer_key_id) = match &self.signer {
            Some(signer) => {
                let key_id = signer.key_id();
                let log_id = self.ensure_log_id()?;
                let msg = record_signing_message(&key_id, &log_id, seq, &record_hash);
                (signer.sign_message(&msg)?, key_id)
            }
            None => (String::new(), String::new()),
        };
        self.conn.execute(
            r#"
            INSERT INTO audit_events (
              id, timestamp_ms, platform, event_type, source_app, agent_session_id,
              rule_id, severity, action, human_message, evidence_ref, user_decision, event_json,
              attributed_agent, prev_hash, record_hash, record_sig, signer_key_id, seq
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)
            "#,
            params![
                record.id,
                record.timestamp_ms,
                record.platform,
                record.event_type,
                record.source_app,
                record.agent_session_id,
                record.rule_id,
                record.severity,
                record.action,
                record.human_message,
                record.evidence_ref,
                record.user_decision,
                record.event_json,
                record.attributed_agent,
                prev_hash,
                record_hash,
                record_sig,
                signer_key_id,
                seq,
            ],
        )?;

        if let Some(session_id) = &record.agent_session_id {
            self.bump_session_counters(
                session_id,
                &record.action,
                record.timestamp_ms,
                &record.source_app,
            )?;
        }
        Ok(())
    }

    fn bump_session_counters(
        &self,
        session_id: &str,
        action: &str,
        ts: i64,
        agent_app: &str,
    ) -> Result<()> {
        let exists: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM agent_sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        if exists.is_none() {
            self.conn.execute(
                r#"INSERT INTO agent_sessions (id, started_at, agent_app, event_count, block_count, alert_count)
                   VALUES (?1, ?2, ?3, 0, 0, 0)"#,
                params![session_id, ts, agent_app],
            )?;
        }

        let block_inc = if action.contains("Block") { 1 } else { 0 };
        let alert_inc = if action.contains("Alert") { 1 } else { 0 };
        self.conn.execute(
            r#"UPDATE agent_sessions
               SET event_count = event_count + 1,
                   block_count = block_count + ?2,
                   alert_count = alert_count + ?3
               WHERE id = ?1"#,
            params![session_id, block_inc, alert_inc],
        )?;
        Ok(())
    }

    pub fn end_session(&self, session_id: &str, ended_at: i64) -> Result<()> {
        let protected = crate::types::audit_session_id(session_id);
        self.conn.execute(
            "UPDATE agent_sessions SET ended_at = ?3 WHERE id = ?1 OR id = ?2",
            params![session_id, protected, ended_at],
        )?;
        Ok(())
    }

    pub fn set_user_decision(&self, record_id: &str, decision: UserDecision) -> Result<()> {
        self.set_user_decision_at(record_id, decision, now_ms())
    }

    /// Record a user decision and append a chained, optionally signed receipt so
    /// approvals/denials are tamper-evident and attributable (Aura §4.4.6).
    ///
    /// The receipt carries an **actor**: `user` for a real approve/deny, `system`
    /// for a timeout. A timeout is not a decision anybody made, and the actor is
    /// part of the signed payload so it cannot later be presented as one.
    pub fn set_user_decision_at(
        &self,
        record_id: &str,
        decision: UserDecision,
        decided_at_ms: i64,
    ) -> Result<()> {
        let updated = self.conn.execute(
            "UPDATE audit_events SET user_decision = ?2 WHERE id = ?1",
            params![record_id, decision.as_str()],
        )?;
        if updated == 0 {
            anyhow::bail!(
                "no audit record {record_id}; refusing to mint a receipt for a nonexistent record"
            );
        }
        let prev: String = self
            .conn
            .query_row(
                "SELECT receipt_hash FROM decision_receipts ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| crate::chain::GENESIS.to_string());
        let hash = crate::chain::receipt_hash(&prev, record_id, decision.as_str(), decided_at_ms);
        let actor = decision.actor();
        let seq = self.next_seq("decision_receipts")?;
        let (sig, signer_key_id) = match &self.signer {
            Some(signer) => {
                let key_id = signer.key_id();
                let log_id = self.ensure_log_id()?;
                let msg = receipt_signing_message(&key_id, &log_id, seq, &hash, actor, record_id);
                (signer.sign_message(&msg)?, key_id)
            }
            None => (String::new(), String::new()),
        };
        self.conn.execute(
            "INSERT INTO decision_receipts
               (audit_id, decision, decided_at_ms, prev_hash, receipt_hash, actor, receipt_sig,
                signer_key_id, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record_id,
                decision.as_str(),
                decided_at_ms,
                prev,
                hash,
                actor,
                sig,
                signer_key_id,
                seq
            ],
        )?;
        Ok(())
    }

    /// Verify per-record signatures against an **out-of-band** public key.
    ///
    /// Strict by design. `report.ok` is false when **any** row is unsigned,
    /// signed by another key, out of sequence, or fails to verify. An earlier
    /// draft treated unsigned rows as merely "not covered", which meant an
    /// attacker could edit rows and blank the `record_sig` column to get a clean
    /// `OK` — no key required. Legacy rows that genuinely predate signing are an
    /// operator decision (`--allow-unsigned`), not a silent default.
    ///
    /// Also re-derives each `record_hash` from the row itself, so this call alone
    /// is sufficient: verifying a signature over a hash read out of a column
    /// proves nothing about the column's row.
    pub fn verify_record_signatures(&self, key: &AuditVerifyKey) -> Result<SignatureVerifyReport> {
        let mut report = SignatureVerifyReport::new(key.key_id());
        if !self.has_column("audit_events", "record_sig")? {
            report.ok = false;
            report.note = Some(
                "database predates signature columns; run `audit-migrate` then re-sign is \
                 impossible — this log cannot be attributed"
                    .into(),
            );
            report.total = self
                .conn
                .query_row("SELECT COUNT(*) FROM audit_events", [], |r| {
                    r.get::<_, i64>(0)
                })? as usize;
            report.unsigned = report.total;
            return Ok(report);
        }
        let log_id = self.meta("log_id")?.unwrap_or_default();
        let sql = format!(
            "SELECT rowid, seq, prev_hash, record_hash, record_sig, signer_key_id, {cols}
             FROM audit_events ORDER BY rowid ASC",
            cols = self.record_cols()?
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    map_record_row_at(row, 6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut prev = crate::chain::GENESIS.to_string();
        let mut expected_seq = 1i64;
        for (seq, prev_stored, hash_stored, sig, signer_key_id, record) in rows {
            report.total += 1;
            let id = record.id.clone();

            // Position: contiguous from 1. A gap means a row was deleted.
            if seq != expected_seq {
                report.fail(&mut report_note_seq(seq, expected_seq), &id);
            }
            expected_seq = seq.max(expected_seq) + 1;

            // Content: re-derive the hash instead of trusting the column.
            let derived = crate::chain::chain_hash(&prev, &record);
            if hash_stored != derived || prev_stored != prev || !is_valid_hash(&hash_stored) {
                report.fail(
                    &mut Some("record_hash does not match row content".into()),
                    &id,
                );
            }
            prev = hash_stored.clone();

            if sig.is_empty() {
                report.unsigned += 1;
                report.fail(&mut None, &id);
                continue;
            }
            report.signed += 1;
            if !signer_key_id.is_empty() && signer_key_id != report.key_id {
                report.other_key += 1;
                report.fail(
                    &mut Some(format!("row signed by foreign key {signer_key_id}")),
                    &id,
                );
                continue;
            }
            let msg = record_signing_message(&report.key_id, &log_id, seq, &hash_stored);
            if key.verify_message(&msg, &sig).is_ok() {
                report.verified += 1;
            } else {
                report.fail(&mut None, &id);
            }
        }
        Ok(report)
    }

    /// Verify decision-receipt signatures, and cross-check them against the
    /// mutable `audit_events.user_decision` column.
    ///
    /// Two holes this closes:
    /// * `user_decision` is excluded from the chain's canonical content (it is
    ///   written after the fact), so it is covered by no hash and no signature.
    ///   Editing it alone used to leave every check green. Every non-null
    ///   `user_decision` must now equal the latest valid receipt for that record,
    ///   and a decision with no receipt at all is a failure.
    /// * `actor` and `audit_id` are inside the signed payload, so a timeout
    ///   cannot be relabelled as a user approval and a receipt cannot be moved
    ///   onto a different record.
    pub fn verify_receipt_signatures(&self, key: &AuditVerifyKey) -> Result<SignatureVerifyReport> {
        let mut report = SignatureVerifyReport::new(key.key_id());
        if !self.has_column("decision_receipts", "receipt_sig")? {
            report.ok = false;
            report.note = Some("database predates receipt signature columns".into());
            return Ok(report);
        }
        let log_id = self.meta("log_id")?.unwrap_or_default();
        let mut stmt = self.conn.prepare(
            "SELECT audit_id, decision, decided_at_ms, prev_hash, receipt_hash, actor,
                    receipt_sig, signer_key_id, seq
             FROM decision_receipts ORDER BY rowid ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut prev = crate::chain::GENESIS.to_string();
        let mut expected_seq = 1i64;
        // Latest *verified* decision per audit id, for the cross-check below.
        let mut latest_ok: std::collections::HashMap<String, String> = Default::default();
        for (audit_id, decision, ts, prev_stored, hash_stored, actor, sig, signer_key_id, seq) in
            rows
        {
            report.total += 1;
            if seq != expected_seq {
                report.fail(&mut report_note_seq(seq, expected_seq), &audit_id);
            }
            expected_seq = seq.max(expected_seq) + 1;

            let derived = crate::chain::receipt_hash(&prev, &audit_id, &decision, ts);
            if hash_stored != derived || prev_stored != prev {
                report.fail(
                    &mut Some("receipt_hash does not match receipt content".into()),
                    &audit_id,
                );
            }
            prev = hash_stored.clone();

            if sig.is_empty() {
                report.unsigned += 1;
                report.fail(&mut None, &audit_id);
                continue;
            }
            report.signed += 1;
            if !signer_key_id.is_empty() && signer_key_id != report.key_id {
                report.other_key += 1;
                report.fail(
                    &mut Some(format!("receipt signed by foreign key {signer_key_id}")),
                    &audit_id,
                );
                continue;
            }
            let msg = receipt_signing_message(
                &report.key_id,
                &log_id,
                seq,
                &hash_stored,
                &actor,
                &audit_id,
            );
            if key.verify_message(&msg, &sig).is_ok() {
                report.verified += 1;
                latest_ok.insert(audit_id.clone(), decision.clone());
            } else {
                report.fail(&mut None, &audit_id);
            }
        }

        // Cross-check the unsigned, un-hashed user_decision column.
        let mut stmt = self.conn.prepare(
            "SELECT id, user_decision FROM audit_events
             WHERE user_decision IS NOT NULL AND user_decision != ''",
        )?;
        let decided = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, column_decision) in decided {
            report.decisions_checked += 1;
            match latest_ok.get(&id) {
                Some(receipt_decision) if *receipt_decision == column_decision => {}
                Some(receipt_decision) => {
                    let note = format!(
                        "user_decision '{column_decision}' contradicts signed receipt \
                         '{receipt_decision}'"
                    );
                    report.fail(&mut Some(note), &id);
                }
                None => {
                    let note =
                        format!("user_decision '{column_decision}' has no valid signed receipt");
                    report.fail(&mut Some(note), &id);
                }
            }
        }
        Ok(report)
    }

    /// Confirm counts recomputed from **verified** decision receipts.
    ///
    /// Only receipts whose signature checks out are counted, so this is the
    /// evidence-grade version of [`crate::SessionReport`]'s confirm block (which
    /// reads the unsigned `user_decision` column). `pending` counts actionable
    /// records with no verified receipt at all.
    pub fn confirm_stats_from_receipts(&self, key: &AuditVerifyKey) -> Result<crate::ConfirmStats> {
        let mut stats = crate::ConfirmStats::default();
        if !self.has_column("decision_receipts", "receipt_sig")? {
            return Ok(stats);
        }
        let log_id = self.meta("log_id")?.unwrap_or_default();
        let mut stmt = self.conn.prepare(
            "SELECT audit_id, decision, receipt_hash, actor, receipt_sig, signer_key_id, seq
             FROM decision_receipts ORDER BY rowid ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let key_id = key.key_id();
        let mut latest: std::collections::HashMap<String, String> = Default::default();
        for (audit_id, decision, hash, actor, sig, signer_key_id, seq) in rows {
            if sig.is_empty() || (!signer_key_id.is_empty() && signer_key_id != key_id) {
                continue;
            }
            let msg = receipt_signing_message(&key_id, &log_id, seq, &hash, &actor, &audit_id);
            if key.verify_message(&msg, &sig).is_ok() {
                latest.insert(audit_id, decision);
            }
        }
        for decision in latest.values() {
            match decision.as_str() {
                "approve" => stats.approve += 1,
                "deny" => stats.deny += 1,
                "timeout" => stats.timeout += 1,
                _ => {}
            }
        }
        let mut stmt = self.conn.prepare(
            "SELECT id FROM audit_events WHERE action LIKE '%Block%' OR action LIKE '%Alert%'",
        )?;
        let actionable = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        stats.pending = actionable
            .iter()
            .filter(|id| !latest.contains_key(*id))
            .count();
        Ok(stats)
    }

    /// 这个哈希出现在链上吗 —— 作为某行自己的哈希,或作为某行的 `prev_hash`。
    ///
    /// 给 `HeadWitness::check_inclusion` 用:见证时的头哈希必须还在链上,否则日志不是
    /// "增长了",而是从那个点或更早被重写了。
    pub fn chain_contains_hash(&self, hash: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE record_hash = ?1 OR prev_hash = ?1",
            [hash],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Head of the log, for an out-of-band witness file. `None` on an empty log.
    pub fn head(&self) -> Result<Option<crate::HeadWitness>> {
        let log_id = self.meta("log_id")?.unwrap_or_default();
        let row = self
            .conn
            .query_row(
                "SELECT seq, record_hash, COUNT(*) OVER () FROM audit_events
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?;
        // 收据也要进 witness。见 `HeadWitness::receipt_count` —— 少了它,删掉一条签名收据
        // 就能把一条 deny 变成 approve,而五项检查全绿。
        let receipt_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM decision_receipts", [], |r| r.get(0))?;
        let last_receipt_hash: String = self
            .conn
            .query_row(
                "SELECT receipt_hash FROM decision_receipts ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_default();
        Ok(row.map(|(seq, hash, _)| crate::HeadWitness {
            log_id,
            seq,
            count: count as usize,
            last_record_hash: hash,
            receipt_count: receipt_count as usize,
            last_receipt_hash,
        }))
    }

    /// Verify the decision-receipt hash chain (empty chain is trivially valid).
    /// This catches edits by someone who did not recompute the chain; use
    /// [`Self::verify_receipt_signatures`] for edits by someone who did.
    pub fn verify_receipts(&self) -> Result<crate::chain::ChainVerifyReport> {
        let mut stmt = self.conn.prepare(
            "SELECT audit_id, decision, decided_at_ms, prev_hash, receipt_hash
             FROM decision_receipts ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut prev = crate::chain::GENESIS.to_string();
        let mut total = 0usize;
        let mut verified = 0usize;
        let mut first_mismatch_id = None;
        for row in rows {
            let (audit_id, decision, ts, prev_stored, hash_stored) = row?;
            total += 1;
            let expected = crate::chain::receipt_hash(&prev, &audit_id, &decision, ts);
            if prev_stored == prev && hash_stored == expected {
                verified += 1;
            } else if first_mismatch_id.is_none() {
                first_mismatch_id = Some(audit_id.clone());
            }
            prev = hash_stored;
        }
        Ok(crate::chain::ChainVerifyReport {
            ok: first_mismatch_id.is_none(),
            total,
            verified,
            first_mismatch_id,
        })
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let cols = self.record_cols()?;
        // `ORDER BY rowid`,不是 `timestamp_ms` —— `timestamp_ms` 来自事件,是**智能体
        // 提供**的值。按它排序,一个攻击者给恶意事件填一个很旧的时间戳,就能把它挤出
        // "最近 N 条"的窗口,或者让审计看起来乱序。`rowid`(追加顺序)是单调的、不受
        // 攻击者控制的,也是哈希链走的那个顺序。
        let sql = format!("SELECT {cols} FROM audit_events ORDER BY rowid DESC LIMIT ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit as i64], map_record_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 会话摘要。元数据(起止时间、app)来自 `agent_sessions`,但三个**计数从 `audit_events`
    /// 现算**,不读 `agent_sessions` 里那三个可变计数器(第七轮复核发现)。
    ///
    /// 那三个计数器(`event_count` / `block_count` / `alert_count`)是 `UPDATE` 出来的聚合,
    /// **不在哈希链、也没签名** —— 谁能写库就能改,而桌面 UI 把它们当审计的一部分显示。相反,
    /// `audit_events` 的 `action` 和 `agent_session_id` 都在 `record_hash` 的覆盖范围内,所以从
    /// 它们数出来的计数是**防篡改的**:改一行 `action` 会让链验不过(`verify_chain` 抓得到)。
    /// 因此这里从签名过的事件行现算,`agent_sessions` 的计数器降级成一个不作数的缓存(见 schema
    /// 注释)。
    pub fn session_summary(&self, session_id: &str) -> Result<Option<SessionSummary>> {
        let protected = crate::types::audit_session_id(session_id);
        let meta: Option<(String, i64, Option<i64>, String)> = self
            .conn
            .query_row(
                "SELECT id, started_at, ended_at, agent_app FROM agent_sessions WHERE id = ?1 OR id = ?2 ORDER BY CASE WHEN id = ?1 THEN 0 ELSE 1 END LIMIT 1",
                params![session_id, protected],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((session, started_at, ended_at, agent_app)) = meta else {
            return Ok(None);
        };
        // 计数从哈希覆盖的事件行现算。`idx_audit_session` 索引让这几次 COUNT 走索引。
        let count = |pred: &str| -> Result<i64> {
            let sql =
                format!("SELECT COUNT(*) FROM audit_events WHERE agent_session_id = ?1{pred}");
            Ok(self.conn.query_row(&sql, params![&session], |r| r.get(0))?)
        };
        let event_count = count("")?;
        let block_count = count(" AND action LIKE '%Block%'")?;
        let alert_count = count(" AND action LIKE '%Alert%'")?;
        Ok(Some(SessionSummary {
            session_id: session,
            started_at,
            ended_at,
            agent_app,
            event_count,
            block_count,
            alert_count,
        }))
    }

    /// JSONL export including chain hash, signature and position, so the
    /// artifact handed to an auditor can actually be verified. Exporting the row
    /// alone would strip exactly the fields that make it attributable.
    pub fn export_jsonl(&self, limit: usize) -> Result<String> {
        let has_sig = self.has_column("audit_events", "record_sig")?;
        // 同 `list_recent`:按追加顺序(`rowid`)导出,不按智能体提供的 `timestamp_ms`。
        // 导出物要交给审计员**验证哈希链**,而链是按追加顺序走的 —— 用攻击者能控制的
        // 时间戳排序,既能挤掉证据,又让导出物的顺序和链的顺序对不上。
        let sql = format!(
            "SELECT {cols}, prev_hash, record_hash{extra} FROM audit_events
             ORDER BY rowid DESC LIMIT ?1",
            cols = self.record_cols()?,
            extra = if has_sig {
                ", record_sig, signer_key_id, seq"
            } else {
                ""
            }
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                let record = map_record_row(row)?;
                // `SELECT_COLS` is 14 columns wide; the extras start after it.
                const EXTRA: usize = 14;
                Ok((
                    record,
                    row.get::<_, String>(EXTRA)?,
                    row.get::<_, String>(EXTRA + 1)?,
                    if has_sig {
                        (
                            row.get::<_, String>(EXTRA + 2)?,
                            row.get::<_, String>(EXTRA + 3)?,
                            row.get::<_, i64>(EXTRA + 4)?,
                        )
                    } else {
                        (String::new(), String::new(), 0)
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let log_id = self.meta("log_id")?.unwrap_or_default();
        let mut out = String::new();
        for (record, prev_hash, record_hash, (record_sig, signer_key_id, seq)) in
            rows.into_iter().rev()
        {
            let mut value = serde_json::to_value(&record)?;
            if let Some(obj) = value.as_object_mut() {
                obj.insert("log_id".into(), serde_json::Value::String(log_id.clone()));
                obj.insert("seq".into(), serde_json::Value::from(seq));
                obj.insert("prev_hash".into(), serde_json::Value::String(prev_hash));
                obj.insert("record_hash".into(), serde_json::Value::String(record_hash));
                obj.insert("record_sig".into(), serde_json::Value::String(record_sig));
                obj.insert(
                    "signer_key_id".into(),
                    serde_json::Value::String(signer_key_id),
                );
            }
            out.push_str(&serde_json::to_string(&value)?);
            out.push('\n');
        }
        Ok(out)
    }
}

/// Note for an out-of-order position.
fn report_note_seq(actual: i64, expected: i64) -> Option<String> {
    Some(format!(
        "position {actual} where {expected} was expected (row deleted or reordered)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::{Decision, DecisionAction, EventType, GuardEvent, Severity};
    use std::collections::HashMap;

    #[derive(Debug)]
    struct FailingSigner;

    impl AuditSigner for FailingSigner {
        fn key_id(&self) -> String {
            "failing-signer".into()
        }

        fn sign_message(&self, _message: &[u8]) -> Result<String> {
            anyhow::bail!("injected signing failure")
        }

        fn public_hex(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn pending_confirmations_round_trip_in_the_same_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let expected = r#"[{"request_id":7,"audit_id":"audit-7"}]"#;

        {
            let store = AuditStore::open_with_key(&path, None).unwrap();
            assert_eq!(store.pending_confirmations_json().unwrap(), None);
            store.save_pending_confirmations_json(expected).unwrap();
        }

        let reopened = AuditStore::open_with_key(&path, None).unwrap();
        assert_eq!(
            reopened.pending_confirmations_json().unwrap().as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn clearing_pending_confirmations_removes_only_the_runtime_key() {
        let store = AuditStore::open_in_memory().unwrap();
        let log_id = store.log_id().unwrap();
        store.save_pending_confirmations_json("[]").unwrap();

        store.clear_pending_confirmations().unwrap();

        assert_eq!(store.pending_confirmations_json().unwrap(), None);
        assert_eq!(
            store.log_id().unwrap(),
            log_id,
            "clear removed audit metadata"
        );
    }

    #[test]
    fn pending_confirmations_are_isolated_per_audit_database() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first.db");
        let second_path = dir.path().join("second.db");
        let first = AuditStore::open_with_key(&first_path, None).unwrap();
        let second = AuditStore::open_with_key(&second_path, None).unwrap();

        first
            .save_pending_confirmations_json(r#"[{"request_id":1}]"#)
            .unwrap();

        assert!(first.pending_confirmations_json().unwrap().is_some());
        assert_eq!(second.pending_confirmations_json().unwrap(), None);
    }

    #[test]
    fn pending_timeout_recovery_is_atomic_and_clears_only_on_success() {
        let store = AuditStore::open_in_memory().unwrap();
        let record = allow_record(7);
        let id = record.id.clone();
        store.append(&record).unwrap();
        store
            .save_pending_confirmations_json(r#"[{"request_id":7}]"#)
            .unwrap();

        let error = store
            .timeout_pending_confirmations_and_clear(&[id.as_str(), "missing-audit-id"])
            .expect_err("任一无效 id 都必须回滚整批恢复");
        assert!(error.to_string().contains("no audit record"), "{error:#}");
        assert!(store.pending_confirmations_json().unwrap().is_some());
        assert_eq!(store.list_recent(1).unwrap()[0].user_decision, None);
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 0);

        store
            .timeout_pending_confirmations_and_clear(&[id.as_str()])
            .unwrap();
        assert_eq!(store.pending_confirmations_json().unwrap(), None);
        assert_eq!(
            store.list_recent(1).unwrap()[0].user_decision.as_deref(),
            Some("timeout")
        );
        assert_eq!(store.head().unwrap().unwrap().receipt_count, 1);
    }

    #[test]
    fn signer_preflight_failure_leaves_no_signer_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        let error = store
            .with_signer(Box::new(FailingSigner))
            .expect_err("a signer that cannot sign must not attach");
        assert!(error.to_string().contains("preflight"), "{error:#}");

        let conn = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM audit_meta WHERE key LIKE 'signer_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "failed attachment wrote signer metadata");
    }

    #[test]
    fn protected_open_signer_failure_leaves_no_database_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("must-not-exist.db");
        let error = AuditStore::open_protected(&path, "configured-key", Box::new(FailingSigner))
            .expect_err("a signer that cannot sign must fail before database creation");
        assert!(error.to_string().contains("preflight"), "{error:#}");
        assert!(
            !path.exists(),
            "signer failure created an unsigned database"
        );
        assert!(!audit_sidecar(&path, "-wal").exists());
        assert!(!audit_sidecar(&path, "-shm").exists());
    }

    #[test]
    fn signer_metadata_attachment_is_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        store
            .conn
            .execute_batch(
                "CREATE TRIGGER reject_signer_key_id
                 BEFORE INSERT ON audit_meta
                 WHEN NEW.key = 'signer_key_id'
                 BEGIN SELECT RAISE(ABORT, 'injected metadata failure'); END;",
            )
            .unwrap();
        let error = store
            .with_signer(Box::new(crate::signing::FileDeviceKey::generate()))
            .expect_err("the injected second metadata write must fail");
        assert!(
            error.to_string().contains("injected metadata failure"),
            "{error:#}"
        );

        let conn = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM audit_meta WHERE key LIKE 'signer_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "public key metadata committed even though key-id attachment failed"
        );
    }

    #[test]
    fn windows_release_runtime_refuses_missing_protection_before_creating_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("must-not-exist.db");

        let no_key = AuditStore::open_runtime_with_mode(&path, None, None, true)
            .expect_err("release without an encryption key must fail");
        assert!(no_key.to_string().contains("AGENTGUARD_AUDIT_KEY"));
        assert!(!path.exists(), "missing key still created a database");

        let no_signer =
            AuditStore::open_runtime_with_mode(&path, Some("configured-key"), None, true)
                .expect_err("release without a signer must fail");
        assert!(no_signer.to_string().contains("signing key"));
        assert!(!path.exists(), "missing signer still created a database");

        if !crate::crypto::sqlcipher_enabled() {
            let no_cipher = AuditStore::open_runtime_with_mode(
                &path,
                Some("configured-key"),
                Some(Box::new(crate::signing::FileDeviceKey::generate())),
                true,
            )
            .expect_err("release without SQLCipher must fail before opening the path");
            assert!(no_cipher.to_string().contains("SQLCipher"), "{no_cipher:#}");
            assert!(
                !path.exists(),
                "missing SQLCipher still created a partial database"
            );
        }
    }

    #[test]
    fn protected_open_rejects_legacy_plaintext_without_modifying_db_or_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        {
            let store = AuditStore::open(&path).unwrap();
            store.append(&allow_record(1)).unwrap();
        }
        let wal = audit_sidecar(&path, "-wal");
        let shm = audit_sidecar(&path, "-shm");
        std::fs::write(&wal, b"legacy-wal-backup-canary").unwrap();
        std::fs::write(&shm, b"legacy-shm-backup-canary").unwrap();
        let before_db = std::fs::read(&path).unwrap();
        let before_wal = std::fs::read(&wal).unwrap();
        let before_shm = std::fs::read(&shm).unwrap();

        let error = AuditStore::open_protected(
            &path,
            "new-encryption-key",
            Box::new(crate::signing::FileDeviceKey::generate()),
        )
        .expect_err("a legacy plaintext database must not be opened in place");
        let message = error.to_string();
        assert!(message.contains("legacy plaintext"), "{error:#}");
        assert!(message.contains("clear-or-migrate"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), before_db);
        assert_eq!(std::fs::read(&wal).unwrap(), before_wal);
        assert_eq!(std::fs::read(&shm).unwrap(), before_shm);
    }

    #[test]
    fn hash_chain_verifies_and_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        for i in 0..3 {
            let event = GuardEvent {
                event_id: format!("e{i}"),
                timestamp_ms: 1000 + i,
                platform: "mac".into(),
                event_type: EventType::UiTreeDelta,
                source_app: "t".into(),
                agent_context_id: Some("s".into()),
                metadata: HashMap::new(),
            };
            let decision = Decision {
                action: DecisionAction::Allow,
                severity: Severity::Info,
                rule_id: "ALLOW".into(),
                human_message: "ok".into(),
                require_confirm: false,
            };
            store
                .append(&AuditRecord::from_event_decision(&event, &decision))
                .unwrap();
        }
        let report = store.verify_chain().unwrap();
        assert!(report.ok, "chain should verify: {report:?}");
        assert_eq!(report.total, 3);
        drop(store);

        // Tamper: rewrite one row's action directly in SQLite.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET action = 'Block' WHERE rowid = 2",
            [],
        )
        .unwrap();
        drop(conn);

        let store = AuditStore::open(&path).unwrap();
        let report = store.verify_chain().unwrap();
        assert!(!report.ok, "tampered chain must fail verification");
        assert!(report.first_mismatch_id.is_some());
        // New appends chain from the last stored hash and still verify structure.
        let event = GuardEvent {
            event_id: "e4".into(),
            timestamp_ms: 2000,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "t".into(),
            agent_context_id: Some("s".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "ALLOW".into(),
            human_message: "ok".into(),
            require_confirm: false,
        };
        store
            .append(&AuditRecord::from_event_decision(&event, &decision))
            .unwrap();
        let report = store.verify_chain().unwrap();
        assert!(!report.ok);
        assert_eq!(report.total, 4);
    }

    #[test]
    fn append_and_query_session() {
        let store = AuditStore::open_in_memory().unwrap();
        let event = GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1000,
            platform: "windows".into(),
            event_type: EventType::FormFill,
            source_app: "Claude".into(),
            agent_context_id: Some("sess-1".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "CRIT-001".into(),
            human_message: "payment".into(),
            require_confirm: true,
        };
        let record = AuditRecord::from_event_decision(&event, &decision);
        store.append(&record).unwrap();
        store.end_session("sess-1", 2000).unwrap();

        let recent = store.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert!(recent[0].action.contains("Block"));

        let summary = store.session_summary("sess-1").unwrap().unwrap();
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.ended_at, Some(2000));
    }

    #[test]
    fn durable_store_never_contains_raw_observation_canaries() {
        const UI_CANARY: &str = "AGENTGUARD_RAW_UI_CANARY_8f4c2a19";
        const OCR_CANARY: &str = "AGENTGUARD_RAW_OCR_CANARY_31d7e5b0";
        const CLIPBOARD_CANARY: &str = "AGENTGUARD_RAW_CLIPBOARD_CANARY_6a09c3ef";
        const SOURCE_CANARY: &str = "AGENTGUARD RAW SOURCE CANARY 19c0";
        const SESSION_CANARY: &str = "AGENTGUARD-RAW-SESSION-CANARY-2de7";
        const AGENT_CANARY: &str = "AGENTGUARD RAW AGENT CANARY 73ab";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data00.db");
        let store = AuditStore::open(&path).unwrap();
        let event = GuardEvent {
            event_id: "data00".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: SOURCE_CANARY.into(),
            agent_context_id: Some(SESSION_CANARY.into()),
            metadata: HashMap::from([
                ("ui_text".into(), UI_CANARY.into()),
                ("ocr_text".into(), OCR_CANARY.into()),
                ("clipboard_text".into(), CLIPBOARD_CANARY.into()),
            ]),
        };
        let decision = Decision {
            action: DecisionAction::Alert,
            severity: Severity::High,
            rule_id: "DATA-00".into(),
            human_message: format!("observed {UI_CANARY} {OCR_CANARY} {CLIPBOARD_CANARY}"),
            require_confirm: false,
        };
        let record =
            AuditRecord::from_event_decision(&event, &decision).attributed_to(AGENT_CANARY);
        store.append(&record).unwrap();
        let rows = store.list_recent(1).unwrap();
        assert_eq!(rows.len(), 1);
        for canary in [
            UI_CANARY,
            OCR_CANARY,
            CLIPBOARD_CANARY,
            SOURCE_CANARY,
            SESSION_CANARY,
            AGENT_CANARY,
        ] {
            assert!(
                !rows[0].event_json.contains(canary),
                "{}",
                rows[0].event_json
            );
            assert!(
                !rows[0].human_message.contains(canary),
                "{}",
                rows[0].human_message
            );
        }
        drop(store);

        for candidate in [
            path.clone(),
            audit_sidecar(&path, "-wal"),
            audit_sidecar(&path, "-shm"),
        ] {
            if !candidate.exists() {
                continue;
            }
            let raw = std::fs::read(&candidate).unwrap();
            for canary in [
                UI_CANARY.as_bytes(),
                OCR_CANARY.as_bytes(),
                CLIPBOARD_CANARY.as_bytes(),
                SOURCE_CANARY.as_bytes(),
                SESSION_CANARY.as_bytes(),
                AGENT_CANARY.as_bytes(),
            ] {
                assert!(
                    !raw.windows(canary.len()).any(|window| window == canary),
                    "raw observation reached durable storage: {}",
                    candidate.display()
                );
            }
        }
    }

    /// 会话计数是从签名过的 audit_events 现算的,不是读 agent_sessions 里那个可变缓存 ——
    /// 所以篡改缓存计数器骗不了 session_summary(第七轮复核发现)。
    #[test]
    fn 会话计数从事件现算而不信可变缓存() {
        let store = AuditStore::open_in_memory().unwrap();
        let event = GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1000,
            platform: "windows".into(),
            event_type: EventType::FormFill,
            source_app: "Claude".into(),
            agent_context_id: Some("sess-1".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::Critical,
            rule_id: "CRIT-001".into(),
            human_message: "payment".into(),
            require_confirm: true,
        };
        store
            .append(&AuditRecord::from_event_decision(&event, &decision))
            .unwrap();

        // 攻击者直接改可变缓存计数器,想把"1 次拦截"抹成 0。
        store
            .conn
            .execute(
                "UPDATE agent_sessions SET event_count = 999, block_count = 0, alert_count = 999 WHERE id = 'sess-1'",
                [],
            )
            .unwrap();

        // session_summary 从 audit_events 现算,无视被篡改的缓存。
        let summary = store.session_summary("sess-1").unwrap().unwrap();
        assert_eq!(summary.event_count, 1, "计数必须来自事件行,不是缓存");
        assert_eq!(summary.block_count, 1, "拦截计数不能被缓存篡改抹掉");
        assert_eq!(summary.alert_count, 0);
    }

    #[test]
    fn decision_receipts_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        let event = GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1000,
            platform: "mac".into(),
            event_type: EventType::FormFill,
            source_app: "t".into(),
            agent_context_id: Some("s".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::High,
            rule_id: "X".into(),
            human_message: "h".into(),
            require_confirm: true,
        };
        let record = AuditRecord::from_event_decision(&event, &decision);
        let rid = record.id.clone();
        store.append(&record).unwrap();
        store
            .set_user_decision_at(&rid, UserDecision::Approve, 1500)
            .unwrap();
        store
            .set_user_decision_at(&rid, UserDecision::Deny, 1600)
            .unwrap();
        let report = store.verify_receipts().unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.total, 2);
        drop(store);

        // Tamper with a receipt.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE decision_receipts SET decision = 'approve' WHERE rowid = 2",
            [],
        )
        .unwrap();
        drop(conn);
        let store = AuditStore::open(&path).unwrap();
        let report = store.verify_receipts().unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_mismatch_id.as_deref(), Some(rid.as_str()));
        // Main chain unaffected (decisions excluded from canonical content).
        assert!(store.verify_chain().unwrap().ok);
    }

    #[test]
    fn key_without_sqlcipher_feature_errors() {
        if crate::crypto::sqlcipher_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.db");
        let err = AuditStore::open_with_key(&path, Some("secret")).unwrap_err();
        assert!(err.to_string().contains("sqlcipher"), "unexpected: {err}");
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn sqlcipher_roundtrip_rejects_wrong_key() {
        const PLAINTEXT_CANARY: &str = "AGENTGUARD_SQLCIPHER_PLAINTEXT_CANARY_7f3b6d19";
        const PENDING_CANARY: &str = "AGENTGUARD_PENDING_PLAINTEXT_CANARY_4be92c11";
        const RAW_UI_CANARY: &str = "AGENTGUARD_SQLCIPHER_RAW_UI_CANARY_a19f20d4";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.db");
        {
            let store = AuditStore::open_with_key(&path, Some("correct-horse")).unwrap();
            let event = GuardEvent {
                event_id: "e1".into(),
                timestamp_ms: 1,
                platform: "mac".into(),
                event_type: EventType::UiTreeDelta,
                source_app: PLAINTEXT_CANARY.into(),
                agent_context_id: None,
                metadata: HashMap::from([
                    ("package".into(), PLAINTEXT_CANARY.into()),
                    ("ui_text".into(), RAW_UI_CANARY.into()),
                ]),
            };
            let decision = Decision {
                action: DecisionAction::Alert,
                severity: Severity::High,
                rule_id: "X".into(),
                human_message: format!("observed {RAW_UI_CANARY}"),
                require_confirm: false,
            };
            store
                .append(&AuditRecord::from_event_decision(&event, &decision))
                .unwrap();
            store
                .save_pending_confirmations_json(&format!(
                    r#"[{{"request_id":1,"audit_id":"{PENDING_CANARY}"}}]"#
                ))
                .unwrap();
        }

        // SQLCipher 也必须加密 WAL，而不只是主数据库。关闭连接后逐个检查仍存在的容器，
        // 避免“正确密钥能读”被误当成“磁盘上没有明文”的证明。
        for candidate in [
            path.clone(),
            std::path::PathBuf::from(format!("{}-wal", path.display())),
            std::path::PathBuf::from(format!("{}-shm", path.display())),
        ] {
            if !candidate.exists() {
                continue;
            }
            let raw = std::fs::read(&candidate).unwrap();
            for canary in [
                PLAINTEXT_CANARY.as_bytes(),
                PENDING_CANARY.as_bytes(),
                RAW_UI_CANARY.as_bytes(),
            ] {
                assert!(
                    !raw.windows(canary.len()).any(|window| window == canary),
                    "SQLCipher container leaked plaintext canary: {}",
                    candidate.display()
                );
            }
        }

        assert!(AuditStore::open_with_key(&path, Some("wrong-key")).is_err());
        let ok = AuditStore::open_with_key(&path, Some("correct-horse")).unwrap();
        let records = ok.list_recent(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_app, PLAINTEXT_CANARY);
        assert!(!records[0].event_json.contains(RAW_UI_CANARY));
        assert!(!records[0].human_message.contains(RAW_UI_CANARY));
        assert!(ok
            .pending_confirmations_json()
            .unwrap()
            .unwrap()
            .contains(PENDING_CANARY));
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn 离线只读连接读取明文_wal但不改原件() {
        use rusqlite::{config::DbConfig, OpenFlags};
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let candidate = dir.path().join("candidate.db");
        let writer = AuditStore::open(&source).unwrap();
        writer.append(&allow_record(902)).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            std::fs::copy(
                audit_sidecar(&source, suffix),
                audit_sidecar(&candidate, suffix),
            )
            .unwrap();
        }
        drop(writer);
        let before = crate::snapshot::identity(&candidate).unwrap();
        let vfs = if cfg!(windows) {
            "win32-none"
        } else {
            "unix-none"
        };
        let reader = Connection::open_with_flags_and_vfs(
            &candidate,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs,
        )
        .unwrap();
        reader
            .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
            .unwrap();
        reader
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .unwrap();
        let count: i64 = reader
            .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "不能忽略只存在于 WAL 的已提交记录");
        drop(reader);
        assert_eq!(crate::snapshot::identity(&candidate).unwrap(), before);
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn 错误密钥启动保留未合并的数据库和全部附属文件() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let candidate = dir.path().join("candidate.db");
        let signer = crate::signing::FileDeviceKey::generate();
        let writer =
            AuditStore::open_protected(&source, "correct-key", Box::new(signer.clone())).unwrap();
        writer
            .conn
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        writer.append(&allow_record(901)).unwrap();
        let mut before = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let bytes = std::fs::read(audit_sidecar(&source, suffix)).unwrap();
            assert!(!bytes.is_empty(), "必须覆盖真实的未合并 WAL: {suffix}");
            let path = audit_sidecar(&candidate, suffix);
            std::fs::write(&path, &bytes).unwrap();
            before.push((path, bytes));
        }
        drop(writer);
        assert!(AuditStore::open_protected(&candidate, "wrong-key", Box::new(signer)).is_err());
        for (path, bytes) in before {
            assert!(
                std::fs::read(&path).ok().as_deref() == Some(bytes.as_slice()),
                "错误密钥不得更改或删除原件: {}",
                path.display()
            );
        }
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn protected_sqlcipher_open_is_encrypted_signed_and_queryable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("protected.db");
        let key = crate::signing::FileDeviceKey::generate();
        let verify_key = key.verifying_key();
        {
            let store = AuditStore::open_protected(&path, "protected-passphrase", Box::new(key))
                .expect("protected open");
            store.append(&allow_record(42)).unwrap();
            let report = store.verify_record_signatures(&verify_key).unwrap();
            assert!(report.fully_covered(), "{report:?}");
            assert_eq!(store.list_recent(10).unwrap().len(), 1);
        }
        let raw = std::fs::read(&path).unwrap();
        assert_ne!(
            raw.get(..SQLITE_PLAINTEXT_HEADER.len()),
            Some(SQLITE_PLAINTEXT_HEADER.as_slice()),
            "protected database exposed a plaintext SQLite header"
        );
        assert!(
            AuditStore::open_with_key(&path, Some("wrong-passphrase")).is_err(),
            "wrong encryption key opened the protected database"
        );
    }

    fn allow_record(i: i64) -> AuditRecord {
        let event = GuardEvent {
            event_id: format!("e{i}"),
            timestamp_ms: 1000 + i,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "t".into(),
            agent_context_id: Some("s".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "ALLOW".into(),
            human_message: "ok".into(),
            require_confirm: false,
        };
        AuditRecord::from_event_decision(&event, &decision)
    }

    /// A database written before the attribution column existed must still verify —
    /// **read-only**, without being migrated first.
    ///
    /// This is the shape of the regression the column introduced: `SELECT_COLS` named
    /// the new column unconditionally, `open_read_only` deliberately runs no migration,
    /// so `audit-verify` / `audit-export` / `audit-report` failed outright on any legacy
    /// log. The only route to verification was `audit-migrate`, which opens read-write:
    /// the operator would have had to *write to the audit log in order to verify it*.
    #[test]
    fn a_legacy_database_verifies_read_only_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        {
            // Write with the current code, then drop the column to simulate a log
            // written by the previous build. SQLite can drop a plain column.
            let store = AuditStore::open(&path).unwrap();
            store.append(&allow_record(1)).unwrap();
            store.append(&allow_record(2)).unwrap();
            store.append(&allow_record(3)).unwrap();
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("ALTER TABLE audit_events DROP COLUMN attributed_agent;")
            .unwrap();
        drop(conn);
        let store = AuditStore::open_read_only(&path).unwrap();
        let chain = store.verify_chain().unwrap();
        assert!(chain.ok, "legacy chain must verify unmigrated: {chain:?}");
        assert_eq!(chain.verified, 3);
        // The other read paths must work too — they share the projection.
        assert_eq!(store.list_recent(10).unwrap().len(), 3);
        let jsonl = store.export_jsonl(10).unwrap();
        assert_eq!(jsonl.lines().count(), 3);
        assert!(
            store
                .list_recent(10)
                .unwrap()
                .iter()
                .all(|r| r.attributed_agent().is_none()),
            "a legacy row has no attribution, and must not invent one"
        );
    }

    /// The property the keyless chain cannot provide: an attacker who edits a row
    /// AND recomputes every downstream hash passes verify_chain, and still fails
    /// signature verification because they cannot forge a signature.
    #[test]
    fn rehashed_tamper_passes_chain_but_fails_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key.clone()))
                .unwrap();
            for i in 0..3 {
                store.append(&allow_record(i)).unwrap();
            }
            let sigs = store.verify_record_signatures(&pubkey).unwrap();
            assert!(sigs.fully_covered(), "{sigs:?}");
            assert_eq!(sigs.signed, 3);
            assert_eq!(sigs.verified, 3);
        }

        // Attacker: flip an action, then recompute the whole chain properly.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "UPDATE audit_events SET action = 'Allow' WHERE rowid = 2",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE audit_events SET human_message = 'nothing to see here' WHERE rowid = 2",
                [],
            )
            .unwrap();
            drop(conn);
            // Rebuild the chain exactly as an informed attacker would.
            let store = AuditStore::open(&path).unwrap();
            let ids: Vec<i64> = {
                let mut stmt = store
                    .conn
                    .prepare("SELECT rowid FROM audit_events ORDER BY rowid ASC")
                    .unwrap();
                stmt.query_map([], |r| r.get(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            };
            let mut prev = crate::chain::GENESIS.to_string();
            for rowid in ids {
                let record = store.record_by_rowid(rowid).unwrap();
                let hash = crate::chain::chain_hash(&prev, &record);
                store
                    .conn
                    .execute(
                        "UPDATE audit_events SET prev_hash = ?2, record_hash = ?3 WHERE rowid = ?1",
                        params![rowid, prev, hash],
                    )
                    .unwrap();
                prev = hash;
            }
        }

        let store = AuditStore::open(&path).unwrap();
        let chain = store.verify_chain().unwrap();
        assert!(
            chain.ok,
            "a re-hashed edit is invisible to the hash chain — that is the gap: {chain:?}"
        );
        let sigs = store.verify_record_signatures(&pubkey).unwrap();
        assert!(
            !sigs.ok,
            "signatures must catch the re-hashed edit: {sigs:?}"
        );
        assert!(sigs.first_bad_id.is_some());
        // Only row 1 still verifies: row 2's content changed, and row 3's
        // record_hash changed because its prev_hash did. Signing the chain hash
        // (rather than the row alone) means an edit invalidates the whole tail.
        assert_eq!(sigs.verified, 1, "{sigs:?}");
        assert_eq!(sigs.signed, 3);
    }

    #[test]
    fn unsigned_legacy_rows_are_reported_not_retro_signed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        // Phase 1: no signer.
        {
            let store = AuditStore::open(&path).unwrap();
            store.append(&allow_record(1)).unwrap();
        }
        // Phase 2: signer attached; the old row must stay unsigned.
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        let store = AuditStore::open(&path)
            .unwrap()
            .with_signer(Box::new(key))
            .unwrap();
        store.append(&allow_record(2)).unwrap();
        let sigs = store.verify_record_signatures(&pubkey).unwrap();
        assert_eq!(sigs.total, 2);
        assert_eq!(sigs.signed, 1);
        assert_eq!(sigs.verified, 1);
        assert_eq!(sigs.unsigned, 1, "legacy row must not be back-signed");
        // Strict: an unsigned row FAILS. Otherwise blanking record_sig would be a
        // free bypass — no key needed.
        assert!(!sigs.ok, "unsigned rows must fail verification");
        assert!(!sigs.fully_covered());
        // …and the operator can see it is only the legacy rows.
        assert!(
            sigs.only_unsigned_failures(),
            "distinguishable from a real forgery: {sigs:?}"
        );
    }

    #[test]
    fn signature_from_another_key_is_flagged_not_silently_ok() {
        let store = AuditStore::open_in_memory()
            .unwrap()
            .with_signer(Box::new(crate::signing::FileDeviceKey::generate()))
            .unwrap();
        store.append(&allow_record(1)).unwrap();
        let other = crate::signing::FileDeviceKey::generate();
        let sigs = store
            .verify_record_signatures(&other.verifying_key())
            .unwrap();
        assert_eq!(sigs.other_key, 1, "{sigs:?}");
        assert!(
            !sigs.ok,
            "a foreign-key signature must fail, not just reduce coverage"
        );
        assert!(!sigs.fully_covered());
        assert!(!sigs.only_unsigned_failures());
    }

    /// A timeout is the policy acting, not the user. Relabelling it as an
    /// approval must fail signature verification.
    #[test]
    fn timeout_receipt_cannot_be_relabelled_as_user_approval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        let rid;
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            let record = allow_record(1);
            rid = record.id.clone();
            store.append(&record).unwrap();
            store
                .set_user_decision_at(&rid, UserDecision::Timeout, 1500)
                .unwrap();
            let sigs = store.verify_receipt_signatures(&pubkey).unwrap();
            assert!(sigs.fully_covered(), "{sigs:?}");
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE decision_receipts SET actor = 'user', decision = 'approve' WHERE rowid = 1",
            [],
        )
        .unwrap();
        drop(conn);
        let store = AuditStore::open(&path).unwrap();
        let sigs = store.verify_receipt_signatures(&pubkey).unwrap();
        assert!(!sigs.ok, "actor is part of the signed payload: {sigs:?}");
        assert_eq!(sigs.first_bad_id.as_deref(), Some(rid.as_str()));
    }

    #[test]
    fn user_and_system_actors_are_distinguished() {
        let store = AuditStore::open_in_memory().unwrap();
        let record = allow_record(1);
        let rid = record.id.clone();
        store.append(&record).unwrap();
        store
            .set_user_decision_at(&rid, UserDecision::Approve, 10)
            .unwrap();
        store
            .set_user_decision_at(&rid, UserDecision::Timeout, 20)
            .unwrap();
        let actors: Vec<String> = {
            let mut stmt = store
                .conn
                .prepare("SELECT actor FROM decision_receipts ORDER BY rowid ASC")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(actors, vec!["user".to_string(), "system".to_string()]);
        assert!(UserDecision::Approve.is_user_action());
        assert!(!UserDecision::Timeout.is_user_action());
    }

    #[test]
    fn embedded_public_key_is_recorded_for_tooling() {
        let key = crate::signing::FileDeviceKey::generate();
        let expected = key.public_hex().unwrap();
        let key_id = key.key_id();
        let store = AuditStore::open_in_memory()
            .unwrap()
            .with_signer(Box::new(key))
            .unwrap();
        assert_eq!(store.embedded_public_hex().unwrap(), Some(expected));
        assert_eq!(store.signer_key_id(), Some(key_id));
    }

    /// Attack S1: edit rows, then blank the signature column. Previously reported
    /// `ok = true` with the rows merely counted as "unsigned" — no key required.
    #[test]
    fn blanking_the_signature_column_is_not_a_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            store.append(&allow_record(1)).unwrap();
            store.append(&allow_record(2)).unwrap();
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE audit_events SET action='Allow', human_message='nothing to see here' WHERE rowid=1", []).unwrap();
        conn.execute("UPDATE audit_events SET record_sig=''", [])
            .unwrap();
        drop(conn);
        let store = AuditStore::open_read_only(&path).unwrap();
        let sigs = store.verify_record_signatures(&pubkey).unwrap();
        assert!(!sigs.ok, "blanked signatures must fail: {sigs:?}");
        assert_eq!(sigs.unsigned, 2);
    }

    /// Attack S2: blank the hash columns. Previously `open()` ran a backfill that
    /// recomputed and PERSISTED a valid chain over the forged content, so the
    /// verifier repaired the log for the attacker and then reported `chain: OK`.
    #[test]
    fn verifier_does_not_repair_a_blanked_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        {
            let store = AuditStore::open(&path).unwrap();
            store.append(&allow_record(1)).unwrap();
            store.append(&allow_record(2)).unwrap();
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET action='Allow', human_message='wiped' WHERE rowid=1",
            [],
        )
        .unwrap();
        conn.execute("UPDATE audit_events SET prev_hash='', record_hash=''", [])
            .unwrap();
        drop(conn);

        let before = std::fs::metadata(&path).unwrap().len();
        let store = AuditStore::open_read_only(&path).unwrap();
        let chain = store.verify_chain().unwrap();
        assert!(
            !chain.ok,
            "an empty record_hash is a mismatch, not a hole to fill"
        );
        drop(store);

        // And the file was not modified by verification.
        let conn = rusqlite::Connection::open(&path).unwrap();
        let still_blank: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE record_hash = ''",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(still_blank, 2, "verification must not rewrite hashes");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);

        // Backfill is available, but only when asked for explicitly.
        let store = AuditStore::open(&path).unwrap();
        assert_eq!(store.unhashed_rows().unwrap(), 2);
        assert_eq!(store.backfill_chain().unwrap(), 2);
        assert_eq!(store.unhashed_rows().unwrap(), 0);
    }

    /// Attack S3: `user_decision` is excluded from the canonical content, so it is
    /// covered by no hash and no signature. Editing it alone used to leave every
    /// check green — including with full signature coverage.
    #[test]
    fn forged_user_decision_is_caught_by_the_receipt_cross_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        let rid;
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            let record = allow_record(1);
            rid = record.id.clone();
            store.append(&record).unwrap();
        }
        // No receipt exists; attacker writes an approval straight into the column.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE audit_events SET user_decision='approve' WHERE id=?1",
            params![rid],
        )
        .unwrap();
        drop(conn);

        let store = AuditStore::open_read_only(&path).unwrap();
        assert!(
            store.verify_chain().unwrap().ok,
            "column is outside the chain by design"
        );
        assert!(
            store.verify_record_signatures(&pubkey).unwrap().ok,
            "and outside the record signature too"
        );
        let receipts = store.verify_receipt_signatures(&pubkey).unwrap();
        assert!(!receipts.ok, "the cross-check must catch it: {receipts:?}");
        assert_eq!(receipts.decisions_checked, 1);
        assert!(
            receipts
                .note
                .as_deref()
                .unwrap_or("")
                .contains("no valid signed receipt"),
            "{receipts:?}"
        );
    }

    /// A decision that contradicts its signed receipt is caught too.
    #[test]
    fn user_decision_contradicting_its_receipt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        let rid;
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            let record = allow_record(1);
            rid = record.id.clone();
            store.append(&record).unwrap();
            store
                .set_user_decision_at(&rid, UserDecision::Deny, 1500)
                .unwrap();
            assert!(store.verify_receipt_signatures(&pubkey).unwrap().ok);
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE audit_events SET user_decision='approve'", [])
            .unwrap();
        drop(conn);
        let store = AuditStore::open_read_only(&path).unwrap();
        let receipts = store.verify_receipt_signatures(&pubkey).unwrap();
        assert!(!receipts.ok, "{receipts:?}");
        assert!(
            receipts
                .note
                .as_deref()
                .unwrap_or("")
                .contains("contradicts"),
            "{receipts:?}"
        );
    }

    /// Attack S4a: delete a row from the middle. The chain is rebuilt by the
    /// attacker, but positions now have a gap.
    #[test]
    fn deleting_a_middle_row_leaves_a_position_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            for i in 0..3 {
                store.append(&allow_record(i)).unwrap();
            }
        }
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq = 2", [])
            .unwrap();
        drop(conn);
        let store = AuditStore::open_read_only(&path).unwrap();
        let sigs = store.verify_record_signatures(&pubkey).unwrap();
        assert!(!sigs.ok, "{sigs:?}");
        assert!(
            sigs.note.as_deref().unwrap_or("").contains("position"),
            "{sigs:?}"
        );
    }

    /// Attack S4b: an emptied or truncated log used to verify as "fully covered".
    /// Only a witness kept outside the DB can catch that.
    #[test]
    fn head_witness_catches_truncation_that_verification_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        let witness;
        {
            let store = AuditStore::open(&path)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            for i in 0..3 {
                store.append(&allow_record(i)).unwrap();
            }
            witness = store.head().unwrap().expect("head");
            assert_eq!(witness.seq, 3);
            assert_eq!(witness.count, 3);
        }
        // Attacker truncates the tail.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq = 3", [])
            .unwrap();
        drop(conn);

        let store = AuditStore::open_read_only(&path).unwrap();
        // Everything internal still looks perfect — that is the point.
        assert!(store.verify_chain().unwrap().ok);
        assert!(store
            .verify_record_signatures(&pubkey)
            .unwrap()
            .fully_covered());
        // The witness is what notices.
        let current = store.head().unwrap();
        let err = witness
            .check_against(current.as_ref())
            .unwrap_err()
            .to_string();
        assert!(err.contains("went backwards"), "{err}");

        // A wiped log is caught too, where verification reports a clean bill.
        drop(store);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_events", []).unwrap();
        drop(conn);
        let store = AuditStore::open_read_only(&path).unwrap();
        assert!(store
            .verify_record_signatures(&pubkey)
            .unwrap()
            .fully_covered());
        assert!(witness
            .check_against(store.head().unwrap().as_ref())
            .is_err());
    }

    /// Attack S4c: transplant a signed row into a different database.
    #[test]
    fn signed_rows_cannot_be_transplanted_between_logs() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.db");
        let b = dir.path().join("b.db");
        let key = crate::signing::FileDeviceKey::generate();
        let pubkey = key.verifying_key();
        {
            let store_a = AuditStore::open(&a)
                .unwrap()
                .with_signer(Box::new(key.clone()))
                .unwrap();
            store_a.append(&allow_record(1)).unwrap();
            let store_b = AuditStore::open(&b)
                .unwrap()
                .with_signer(Box::new(key))
                .unwrap();
            store_b.append(&allow_record(9)).unwrap();
            assert_ne!(
                store_a.log_id().unwrap(),
                store_b.log_id().unwrap(),
                "each log gets its own id"
            );
        }
        // Move A's signed row into B (same device key, so the signature is genuine).
        let row: (String, String, String, String, i64) = {
            let conn = rusqlite::Connection::open(&a).unwrap();
            conn.query_row(
                "SELECT id, record_hash, record_sig, signer_key_id, seq FROM audit_events LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap()
        };
        let conn = rusqlite::Connection::open(&b).unwrap();
        conn.execute(
            "UPDATE audit_events SET id=?1, record_hash=?2, record_sig=?3, signer_key_id=?4, seq=?5",
            params![row.0, row.1, row.2, row.3, row.4],
        )
        .unwrap();
        drop(conn);
        let store_b = AuditStore::open_read_only(&b).unwrap();
        let sigs = store_b.verify_record_signatures(&pubkey).unwrap();
        assert!(
            !sigs.ok,
            "log_id binding must reject the transplant: {sigs:?}"
        );
    }

    #[test]
    fn receipt_for_unknown_record_is_refused() {
        let store = AuditStore::open_in_memory().unwrap();
        let err = store
            .set_user_decision_at("no-such-record", UserDecision::Approve, 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no audit record"), "{err}");
    }
}

#[cfg(test)]
mod b6_并发与见证复核 {
    use super::*;

    fn rec(i: usize) -> AuditRecord {
        AuditRecord {
            id: format!("id-{i}"),
            timestamp_ms: 1_700_000_000_000 + i as i64,
            platform: "test".into(),
            event_type: "ui_tree_delta".into(),
            source_app: "App".into(),
            agent_session_id: None,
            rule_id: format!("R{i}"),
            severity: "info".into(),
            action: "Allow".into(),
            human_message: format!("event {i}"),
            evidence_ref: None,
            user_decision: None,
            event_json: "{}".into(),
            attributed_agent: None,
        }
    }

    /// 两个**并发写者**不能把哈希链弄断,而且绝不能静默地弄断。
    ///
    /// 复核实测(修复前,连跑三次全部复现):
    ///
    /// ```text
    /// two concurrent writers, 50 appends: rows=50 chain.ok=false verified=48/50
    /// duplicate seq values: 2 / 2 / 1
    /// append errors (0) e.g. None          <- 一次错误都没有
    /// ```
    ///
    /// 这不在威胁模型里,在正常使用里:`guard-nm-host` 每个原生消息连接一个进程,各自打开
    /// 同一个 `~/.local/share/agentguard/nm-audit.db`。后果是双向的 —— 日志永久不可验证,
    /// 同时给想抵赖的人递上"工具自己就会把日志搞坏"这句台词。
    ///
    /// 这里用两个线程各自**独立打开**同一个文件(不是共享 `Connection`),因为跨进程才是
    /// 真实形状;`unchecked_transaction` + `busy_timeout` 要在这个形状下成立。
    #[test]
    fn 并发写不弄断哈希链() {
        let dir = std::env::temp_dir().join(format!("ag-audit-concurrent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("a.db");
        // 先建库,免得两个写者同时跑 migrate。
        drop(AuditStore::open(&db).unwrap());

        let mut handles = Vec::new();
        for w in 0..2 {
            let db = db.clone();
            handles.push(std::thread::spawn(move || {
                let store = AuditStore::open(&db).expect("open");
                let mut errs = 0usize;
                for i in 0..25 {
                    if store.append(&rec(w * 100 + i)).is_err() {
                        errs += 1;
                    }
                }
                errs
            }));
        }
        let errs: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

        let store = AuditStore::open_read_only(&db).unwrap();
        let v = store.verify_chain().unwrap();
        let dup: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM (SELECT seq FROM audit_events GROUP BY seq HAVING COUNT(*) > 1)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(dup, 0, "有 {dup} 个重复的 seq —— 两个写者拿到了同一个位置");
        assert!(
            v.ok,
            "并发写之后链断了:verified={}/{} first_mismatch={:?}(本轮 append 报错 {} 次)",
            v.verified, v.total, v.first_mismatch_id, errs
        );
    }

    /// 删尾再回填必须被 witness 抓到。
    ///
    /// `last_record_hash` 一直被写进 witness 文件、文档也把它列为组成部分,而
    /// `check_against` **从不读它**。于是"删掉末尾 N 条 + 补 N 条伪造记录把 count/seq
    /// 恢复到原值"通过全部检查,日志内容变成攻击者写的那几条。
    #[test]
    fn 删尾回填被见证抓到() {
        let dir = std::env::temp_dir().join(format!("ag-audit-refill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("a.db");
        let store = AuditStore::open(&db).unwrap();
        for i in 0..5 {
            store.append(&rec(i)).unwrap();
        }
        let witness = store.head().unwrap().unwrap();

        // 删掉末尾 3 条,再补 3 条 —— seq 和 count 回到原值。
        store
            .conn
            .execute("DELETE FROM audit_events WHERE seq > 2", [])
            .unwrap();
        for i in 100..103 {
            store.append(&rec(i)).unwrap();
        }
        let after = store.head().unwrap().unwrap();
        assert_eq!(after.seq, witness.seq, "夹具必须把 seq 恢复到原值");
        assert_eq!(after.count, witness.count, "夹具必须把 count 恢复到原值");
        assert_ne!(
            after.last_record_hash, witness.last_record_hash,
            "回填之后头哈希必然不同,否则这条测试证明不了什么"
        );

        let verdict = witness.check_against(Some(&after));
        let _ = std::fs::remove_dir_all(&dir);
        let e = verdict.expect_err("删尾回填必须被抓到");
        assert!(
            e.to_string().contains("rewritten"),
            "错误信息应当说清是历史被重写:{e}"
        );
    }

    /// 删掉一条签名收据必须被 witness 抓到 —— 那是"用户决策"的唯一证据。
    #[test]
    fn 删除收据被见证抓到() {
        let dir = std::env::temp_dir().join(format!("ag-audit-receipt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("a.db");
        let store = AuditStore::open(&db).unwrap();
        store.append(&rec(1)).unwrap();
        store
            .set_user_decision("id-1", crate::UserDecision::Deny)
            .unwrap();
        let witness = store.head().unwrap().unwrap();
        assert_eq!(witness.receipt_count, 1, "夹具应当产生一条收据");

        store
            .conn
            .execute("DELETE FROM decision_receipts", [])
            .unwrap();
        store
            .conn
            .execute("UPDATE audit_events SET user_decision = NULL", [])
            .unwrap();
        let after = store.head().unwrap().unwrap();
        let verdict = witness.check_against(Some(&after));
        let _ = std::fs::remove_dir_all(&dir);
        let e = verdict.expect_err("删掉一条签名收据必须被抓到");
        assert!(
            e.to_string().contains("receipts went backwards"),
            "错误信息应当点名收据:{e}"
        );
    }

    /// 见证的那一段被换掉、但日志继续增长 —— 靠包含性证明抓。
    ///
    /// 这一格 `check_against` 抓不到:删尾 K 条、补 K+1 条,seq 和 count 都变大,同位置
    /// 比较也不触发。必须去看链本身。
    #[test]
    fn 增长中被重写靠包含性抓到() {
        let dir = std::env::temp_dir().join(format!("ag-audit-incl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("a.db");
        let store = AuditStore::open(&db).unwrap();
        for i in 0..5 {
            store.append(&rec(i)).unwrap();
        }
        let witness = store.head().unwrap().unwrap();
        // 见证时的头哈希此刻当然在链上。
        witness
            .check_inclusion(|h| store.chain_contains_hash(h))
            .expect("刚见证完必须包含");

        // 删尾 2 条、补 3 条:seq 和 count 都变大。
        store
            .conn
            .execute("DELETE FROM audit_events WHERE seq > 3", [])
            .unwrap();
        for i in 200..203 {
            store.append(&rec(i)).unwrap();
        }
        let after = store.head().unwrap().unwrap();
        assert!(after.seq > witness.seq, "夹具必须让 seq 变大");
        assert!(
            witness.check_against(Some(&after)).is_ok(),
            "这一格本来就不该被 check_against 抓到 —— 否则这条测试测的是别的东西"
        );
        let verdict = witness.check_inclusion(|h| store.chain_contains_hash(h));
        let _ = std::fs::remove_dir_all(&dir);
        let e = verdict.expect_err("包含性证明必须抓到");
        assert!(e.to_string().contains("no longer appears"), "{e}");
    }
}

#[cfg(test)]
mod b6_审计次要洞 {
    use super::*;

    fn rec(i: usize, ts: i64) -> AuditRecord {
        AuditRecord {
            id: format!("id-{i}"),
            timestamp_ms: ts,
            platform: "test".into(),
            event_type: "ui_tree_delta".into(),
            source_app: "App".into(),
            agent_session_id: None,
            rule_id: format!("R{i}"),
            severity: "info".into(),
            action: "Allow".into(),
            human_message: format!("event {i}"),
            evidence_ref: None,
            user_decision: None,
            event_json: "{}".into(),
            attributed_agent: None,
        }
    }

    /// 导出与"最近"按**追加顺序**排,不按智能体提供的时间戳。
    ///
    /// 攻击者给一条晚追加的恶意事件填一个很旧的时间戳,不能把它挤出"最近 N 条"。
    #[test]
    fn 排序不被攻击者时间戳左右() {
        let dir = std::env::temp_dir().join(format!("ag-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = AuditStore::open(dir.join("a.db")).unwrap();
        // 先追加两条正常事件(新时间戳),再追加一条恶意事件但填一个**很旧**的时间戳。
        store.append(&rec(1, 2_000_000)).unwrap();
        store.append(&rec(2, 2_000_001)).unwrap();
        store.append(&rec(99, 1)).unwrap(); // 恶意:时间戳 = 1

        let recent = store.list_recent(1).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(recent.len(), 1, "list_recent(1) 应当返回一条");
        assert_eq!(
            recent[0].id, "id-99",
            "最新追加的事件(即使时间戳很旧)应当是'最近'的第一条,得到 {}",
            recent[0].id
        );
    }

    /// 一个 NULL 单元格不能让整个审计库无法读取/验证。
    #[test]
    fn 一个null不让整库不可读() {
        let dir = std::env::temp_dir().join(format!("ag-null-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = AuditStore::open(dir.join("a.db")).unwrap();
        for i in 0..3 {
            store.append(&rec(i, 1_000 + i as i64)).unwrap();
        }
        // 篡改:把中间一条的 platform 置 NULL。
        store
            .conn
            .execute(
                "UPDATE audit_events SET platform = NULL WHERE id = 'id-1'",
                [],
            )
            .unwrap();

        // 读取路径必须**能跑完**,并把那一行报成链不匹配 —— 而不是整个 verify 报错。
        let v = store.verify_chain();
        let recent = store.list_recent(10);
        let export = store.export_jsonl(10);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(v.is_ok(), "verify_chain 因为一个 NULL 而彻底失败:{v:?}");
        assert!(
            recent.is_ok(),
            "list_recent 因为一个 NULL 而失败:{recent:?}"
        );
        assert!(
            export.is_ok(),
            "export_jsonl 因为一个 NULL 而失败:{export:?}"
        );
        let report = v.unwrap();
        assert!(
            !report.ok,
            "被 NULL 篡改的行应当被报成链不匹配,而不是被跳过"
        );
    }
}
