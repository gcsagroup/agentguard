//! 用户明确确认后进行的离线升级：原件零写入、加密备份、独立目标、签名激活回执。
//!
//! 本模块不清空旧库，不恢复旧待确认操作，不把验签失败的历史伪装成可信历史。

use super::{preflight_signer, verify_cipher_integrity, AuditStore, SQLITE_PLAINTEXT_HEADER};
use crate::crypto::{apply_key, cipher_active};
use crate::signing::{AuditSigner, AuditVerifyKey};
use crate::snapshot::{identity, sidecar, FileIdentity, SUFFIXES};
use anyhow::{bail, Context, Result};
use rusqlite::{config::DbConfig, params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

// POSIX 字节锁属于进程；本进程另一个状态查询关闭原文件也会释放它。
// 将本模块的同库查询和迁移串行化，状态查询用 try_lock，不阻塞界面。
fn source_access(path: &Path) -> Result<Arc<Mutex<()>>> {
    type Locks = std::collections::HashMap<PathBuf, Weak<Mutex<()>>>;
    static LOCKS: OnceLock<Mutex<Locks>> = OnceLock::new();
    let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("历史库访问锁异常"))?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}

const RECEIPT_DOMAIN: &[u8] = b"AGENTGUARD-AUDIT-RECOVERY-v1\0";
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub version: u32,
    pub migration_id: String,
    pub created_at_ms: i64,
    pub history_records: u64,
    pub unsigned_history_records: u64,
    source_files: Vec<Option<FileIdentity>>,
    backup_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReceipt {
    receipt: RecoveryReceipt,
    signature: String,
}

fn receipt_message(receipt: &RecoveryReceipt) -> Result<Vec<u8>> {
    let mut message = RECEIPT_DOMAIN.to_vec();
    message.extend(serde_json::to_vec(receipt)?);
    Ok(message)
}

pub fn has_legacy_plaintext_audit(path: &Path) -> Result<bool> {
    let access = source_access(path)?;
    let _guard = access
        .try_lock()
        .map_err(|_| anyhow::anyhow!("AUDIT_SOURCE_BUSY: 历史库正在升级"))?;
    has_legacy_header(path)
}

fn has_legacy_header(path: &Path) -> Result<bool> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("无法检查历史审计文件"),
    };
    let mut header = [0u8; 16];
    Ok(file.read(&mut header)? == header.len() && &header == SQLITE_PLAINTEXT_HEADER)
}

fn receipt_path(source: &Path) -> PathBuf {
    sidecar(source, ".recovery.json")
}

fn recovery_dir(source: &Path, migration_id: &str) -> Result<PathBuf> {
    let id = uuid::Uuid::parse_str(migration_id).context("升级回执标识无效")?;
    if id.to_string() != migration_id {
        bail!("升级回执标识格式无效");
    }
    Ok(source
        .parent()
        .context("历史库没有父目录")?
        .join(format!("audit-migration-{id}")))
}

fn regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("升级输入不是普通文件");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("升级输入不能是重解析点");
        }
    }
    Ok(())
}

/// 正常重启只接受受当前设备签名密钥认证的激活回执；绝不偷偷寻找同目录备用库。
pub fn resolve_recovered_audit(source: &Path, signer: &dyn AuditSigner) -> Result<PathBuf> {
    let access = source_access(source)?;
    let _guard = access
        .try_lock()
        .map_err(|_| anyhow::anyhow!("AUDIT_SOURCE_BUSY: 历史库正在升级"))?;
    let manifest = receipt_path(source);
    match fs::symlink_metadata(&manifest) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(source.into()),
        Err(error) => return Err(error).context("无法读取升级回执"),
        Ok(metadata) if metadata.len() > 64 * 1024 => bail!("升级回执超出长度限制"),
        Ok(_) => regular_file(&manifest)?,
    }
    let signed: SignedReceipt = serde_json::from_slice(&fs::read(&manifest)?)
        .context("升级回执损坏，请保留数据并恢复；未选择其他数据库")?;
    if signed.receipt.version != 1 {
        bail!("不支持的升级回执版本");
    }
    let public = signer.public_hex().context("升级回执验证需要设备公钥")?;
    AuditVerifyKey::from_hex(&public)?
        .verify_message(&receipt_message(&signed.receipt)?, &signed.signature)
        .context("升级回执签名无效，请勿删除旧数据")?;
    let directory = recovery_dir(source, &signed.receipt.migration_id)?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("升级目录无效");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("升级目录不能是重解析点");
        }
    }
    if identity(source)? != signed.receipt.source_files {
        bail!("AUDIT_LEGACY_CHANGED: 旧版本又修改了历史库，请停止旧版本并处理新增历史；未忽略这些记录");
    }
    let target = directory.join("encrypted.db");
    regular_file(&target)?;
    Ok(target)
}

/// 原库的 SQLite 字节范围锁/Windows 共享访问限制，不创建锁文件，不修改原数据。
/// Unix 锁持有期间只能通过这个主文件句柄读取；关闭同进程其它主文件句柄会释放 POSIX 锁。
struct OfflineSource {
    path: PathBuf,
    file: File,
}

impl OfflineSource {
    fn lock(path: &Path) -> Result<Self> {
        regular_file(path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1); // 允许只读检查；拒绝已存在或新建的写者及删除者。
        }
        let file = options
            .open(path)
            .context("AUDIT_SOURCE_BUSY: 请先退出旧版本；不能独占历史库")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SQLite pending/reserved/shared 锁区；已有连接持有共享锁也必须先退出。
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_start = 0x4000_0000;
            lock.l_len = 512;
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("AUDIT_SOURCE_BUSY: 请先退出旧版本；历史库仍被占用");
            }
        }
        Ok(Self {
            path: path.into(),
            file,
        })
    }

    fn with_file<T>(
        &mut self,
        suffix: &str,
        operation: impl FnOnce(&mut File) -> Result<T>,
    ) -> Result<Option<T>> {
        if suffix.is_empty() {
            self.file.seek(SeekFrom::Start(0))?;
            return operation(&mut self.file).map(Some);
        }
        let path = sidecar(&self.path, suffix);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
            Ok(_) => {
                regular_file(&path)?;
                operation(&mut File::open(path)?).map(Some)
            }
        }
    }

    fn identity(&mut self) -> Result<Vec<Option<FileIdentity>>> {
        SUFFIXES
            .iter()
            .map(|suffix| {
                self.with_file(suffix, |file| {
                    let mut hash = Sha256::new();
                    let mut bytes = 0;
                    let mut buffer = [0u8; 65536];
                    loop {
                        let size = file.read(&mut buffer)?;
                        if size == 0 {
                            break;
                        }
                        bytes += size as u64;
                        if bytes > MAX_SOURCE_BYTES {
                            bail!("历史文件超过本地升级限额，请保留原件并使用离线恢复流程");
                        }
                        hash.update(&buffer[..size]);
                    }
                    Ok(FileIdentity {
                        bytes,
                        sha256: hex::encode(hash.finalize()),
                    })
                })
            })
            .collect()
    }
}

fn encrypted_connection(path: &Path, key: &str) -> Result<Connection> {
    // 先原子占位且限制权限，SQLite 不会以默认 0644 暴露新文件。
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.sync_all()?;
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "trusted_schema", false)?;
    apply_key(&conn, Some(key))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "journal_mode", "DELETE")?;
    Ok(conn)
}

fn backup_original(
    source: &mut OfflineSource,
    path: &Path,
    key: &str,
    expected: &[Option<FileIdentity>],
) -> Result<()> {
    let mut conn = encrypted_connection(path, key)?;
    conn.execute_batch("CREATE TABLE source_chunks(file_index INTEGER, chunk_index INTEGER, payload BLOB NOT NULL, PRIMARY KEY(file_index,chunk_index));")?;
    let tx = conn.transaction()?;
    for (index, suffix) in SUFFIXES.iter().enumerate() {
        let actual = source.with_file(suffix, |file| {
            let mut buffer = [0u8; 65536];
            let mut hash = Sha256::new();
            let mut bytes = 0;
            let mut chunk = 0;
            loop {
                let size = file.read(&mut buffer)?;
                if size == 0 {
                    break;
                }
                hash.update(&buffer[..size]);
                bytes += size as u64;
                tx.execute(
                    "INSERT INTO source_chunks VALUES (?1,?2,?3)",
                    params![index as i64, chunk, &buffer[..size]],
                )?;
                chunk += 1;
            }
            Ok(FileIdentity {
                bytes,
                sha256: hex::encode(hash.finalize()),
            })
        })?;
        if actual != expected[index] {
            bail!("历史库备份时发生变化，已停止升级");
        }
    }
    tx.commit()?;
    for (index, expected) in expected.iter().enumerate() {
        let Some(expected) = expected else {
            continue;
        };
        let mut statement = conn.prepare(
            "SELECT payload FROM source_chunks WHERE file_index=?1 ORDER BY chunk_index",
        )?;
        let mut rows = statement.query([index as i64])?;
        let mut hash = Sha256::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let data: Vec<u8> = row.get(0)?;
            bytes += data.len() as u64;
            hash.update(data);
        }
        if bytes != expected.bytes || hex::encode(hash.finalize()) != expected.sha256 {
            bail!("加密备份逐字节校验失败，原件未切换");
        }
    }
    verify_cipher_integrity(&conn)?;
    conn.close().map_err(|(_, error)| error)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn migrate_legacy_audit(
    source: &Path,
    key: &str,
    signer: &dyn AuditSigner,
) -> Result<RecoveryReceipt> {
    migrate_legacy_audit_at_stage(source, key, signer, |_| Ok(()))
}

fn migrate_legacy_audit_at_stage(
    source: &Path,
    key: &str,
    signer: &dyn AuditSigner,
    stage: impl Fn(&str) -> Result<()>,
) -> Result<RecoveryReceipt> {
    let access = source_access(source)?;
    let _guard = access
        .try_lock()
        .map_err(|_| anyhow::anyhow!("AUDIT_SOURCE_BUSY: 历史库正在升级"))?;
    if key.is_empty() || !crate::sqlcipher_enabled() {
        bail!("升级需要已就绪的加密密钥与 SQLCipher 构建");
    }
    preflight_signer(signer)?;
    if receipt_path(source).try_exists()? {
        bail!("已存在升级回执，请重新启动并验证，不能重复迁移");
    }
    if !has_legacy_header(source)? {
        bail!("未发现可升级的旧版明文数据库");
    }
    let mut original = OfflineSource::lock(source)?;
    let before = original.identity()?;
    if before[3].as_ref().is_some_and(|entry| entry.bytes > 0) {
        bail!("发现未完成的回滚日志，请先由旧版完成恢复；原件未修改");
    }
    let migration_id = uuid::Uuid::new_v4().to_string();
    let directory = recovery_dir(source, &migration_id)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    // 中断的目录只含加密文件，保留供诊断；没有激活回执就不会被启动路径选中。
    let backup = directory.join("source-backup.db");
    backup_original(&mut original, &backup, key, &before)?;
    stage("backup_verified")?;
    let target = directory.join("encrypted.db");
    let conn = encrypted_connection(&target, key)?;
    let mut uri = url::Url::from_file_path(fs::canonicalize(source)?)
        .map_err(|_| anyhow::anyhow!("升级路径无效"))?;
    let vfs = if cfg!(windows) {
        "win32-none"
    } else {
        "unix-none"
    };
    uri.query_pairs_mut()
        .append_pair("mode", "ro")
        .append_pair("vfs", vfs);
    // 原库已被 OS 锁独占。只读/no-lock VFS + EXCLUSIVE 使用内存 WAL 索引，避免写原 SHM。
    // 不用 immutable：它可能漏掉 WAL 中的已提交记录。连接一直保留到激活回执落盘。
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    // ATTACH 自身会读 schema；必须在附加前设置默认模式，不能等第一次 WAL 访问之后。
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    conn.execute("ATTACH DATABASE ?1 AS legacy KEY ''", [uri.as_str()])
        .context("只读附加历史数据库")?;
    conn.pragma_update(
        Some(rusqlite::DatabaseName::Attached("legacy")),
        "locking_mode",
        "EXCLUSIVE",
    )
    .context("设置历史库内存 WAL 索引")?;
    let source_integrity: String = conn
        .query_row("PRAGMA legacy.integrity_check", [], |row| row.get(0))
        .context("检查历史库完整性")?;
    if source_integrity != "ok" {
        bail!("历史数据库完整性检查失败，已保留原件和加密备份");
    }
    let unsafe_schema: i64 = conn.query_row("SELECT count(*) FROM legacy.sqlite_master WHERE type IN ('trigger','view') OR (type='table' AND name NOT IN ('audit_events','agent_sessions','decision_receipts','audit_meta','sqlite_sequence'))", [], |row| row.get(0))?;
    if unsafe_schema != 0 {
        bail!("历史数据库包含未知结构，不能自动执行升级");
    }
    let old_count: u64 = conn.query_row("SELECT count(*) FROM legacy.audit_events", [], |row| {
        row.get(0)
    })?;
    conn.query_row("SELECT sqlcipher_export('main','legacy')", [], |_| Ok(()))
        .context("导出历史到加密目标")?;
    let user_version: i64 = conn.query_row("PRAGMA legacy.user_version", [], |row| row.get(0))?;
    conn.pragma_update(None, "user_version", user_version)?;
    stage("history_exported")?;
    // 旧待确认状态只保留在加密原始备份，不得在新版本重放为放行或超时回执。
    conn.execute(
        "DELETE FROM audit_meta WHERE key=?1",
        [super::PENDING_CONFIRMATIONS_META_KEY],
    )?;
    let store = AuditStore { conn, signer: None };
    let chain = store.verify_chain()?;
    if !chain.ok || chain.verified as u64 != old_count {
        bail!("历史记录校验失败，不能把未经验证的历史标成可信；原件未切换");
    }
    verify_cipher_integrity(&store.conn)?;
    if !cipher_active(&store.conn) {
        bail!("升级目标没有实际启用加密");
    }
    let unsigned_history_records: u64 = store.conn.query_row(
        "SELECT count(*) FROM audit_events WHERE record_sig IS NULL OR record_sig=''",
        [],
        |row| row.get(0),
    )?;
    let receipt = RecoveryReceipt {
        version: 1,
        migration_id,
        created_at_ms: super::now_ms(),
        history_records: old_count,
        unsigned_history_records,
        source_files: before.clone(),
        backup_sha256: identity(&backup)?[0]
            .as_ref()
            .context("备份消失")?
            .sha256
            .clone(),
    };
    File::open(&target)?.sync_all()?;
    #[cfg(unix)]
    File::open(&directory)?.sync_all()?;
    if original.identity()? != before {
        bail!("历史文件发生变化，升级取消；未激活新库");
    }
    stage("before_activation")?;
    let signed = SignedReceipt {
        signature: signer.sign_message(&receipt_message(&receipt)?)?,
        receipt: receipt.clone(),
    };
    let mut temporary = tempfile::NamedTempFile::new_in(source.parent().context("缺少父目录")?)?;
    temporary.write_all(&serde_json::to_vec(&signed)?)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(receipt_path(source))
        .map_err(|error| error.error)
        .context("无法发布升级回执，未覆盖已有回执")?;
    #[cfg(unix)]
    File::open(source.parent().unwrap())?.sync_all()?;
    // 原库连接关闭可能释放本进程 POSIX 锁，所以放在全部校验和激活之后。
    drop(store);
    Ok(receipt)
}

#[cfg(all(test, feature = "sqlcipher"))]
mod tests {
    use super::*;
    use crate::{AuditRecord, FileDeviceKey};

    fn fixture(directory: &Path) -> PathBuf {
        let live = directory.join("fixture-live.db");
        let source = directory.join("legacy.db");
        let writer = AuditStore::open_with_key_unchecked(&live, None).unwrap();
        let record = AuditRecord {
            id: "legacy-record".into(),
            timestamp_ms: 1234,
            platform: "mac".into(),
            event_type: "UiTreeDelta".into(),
            source_app: "LEGACY_CANARY_DO_NOT_LEAK".into(),
            agent_session_id: None,
            rule_id: "ALLOW".into(),
            severity: "Info".into(),
            action: "Allow".into(),
            human_message: "历史记录".into(),
            evidence_ref: None,
            user_decision: None,
            event_json: "{}".into(),
            attributed_agent: None,
        };
        writer.append(&record).unwrap();
        writer
            .save_pending_confirmations_json("untrusted-pending")
            .unwrap();
        for suffix in ["", "-wal", "-shm"] {
            fs::copy(sidecar(&live, suffix), sidecar(&source, suffix)).unwrap();
        }
        drop(writer);
        source
    }

    #[test]
    fn 保留原件迁移包含_wal历史并隔离旧待确认() {
        let dir = tempfile::tempdir().unwrap();
        let source = fixture(dir.path());
        let before = identity(&source).unwrap();
        let signer = FileDeviceKey::generate();
        let receipt = migrate_legacy_audit_at_stage(&source, "migration-secret", &signer, |_| {
            // 模拟迁移过程中界面定时查询，不能另开/关闭原件释放 POSIX 锁。
            assert!(has_legacy_plaintext_audit(&source).is_err());
            assert!(resolve_recovered_audit(&source, &signer).is_err());
            Ok(())
        })
        .unwrap();
        assert_eq!(receipt.history_records, 1);
        assert_eq!(receipt.unsigned_history_records, 1);
        assert_eq!(
            identity(&source).unwrap(),
            before,
            "源 DB/WAL/SHM 必须逐字节不变"
        );
        let path = resolve_recovered_audit(&source, &signer).unwrap();
        let store = AuditStore::open_protected(&path, "migration-secret", Box::new(signer.clone()))
            .unwrap();
        assert_eq!(store.list_recent(10).unwrap().len(), 1);
        assert!(store.verify_chain().unwrap().ok);
        assert!(store.pending_confirmations_json().unwrap().is_none());
        assert_eq!(
            store
                .verify_record_signatures(&signer.verifying_key())
                .unwrap()
                .unsigned,
            1
        );
        drop(store);
        assert!(migrate_legacy_audit(&source, "migration-secret", &signer).is_err());
        assert_eq!(
            resolve_recovered_audit(&source, &signer).unwrap(),
            path,
            "重启仍选择同一个已确认目标"
        );
        let recovery = recovery_dir(&source, &receipt.migration_id).unwrap();
        for file in fs::read_dir(recovery).unwrap() {
            let path = file.unwrap().path();
            let bytes = fs::read(path).unwrap();
            assert!(!bytes
                .windows(b"LEGACY_CANARY_DO_NOT_LEAK".len())
                .any(|slice| slice == b"LEGACY_CANARY_DO_NOT_LEAK"));
        }
    }

    #[test]
    fn 任一提交前中断均保留原件且不激活半成品() {
        for stopping in ["backup_verified", "history_exported", "before_activation"] {
            let dir = tempfile::tempdir().unwrap();
            let source = fixture(dir.path());
            let before = identity(&source).unwrap();
            let signer = FileDeviceKey::generate();
            let result =
                migrate_legacy_audit_at_stage(&source, "migration-secret", &signer, |stage| {
                    if stage == stopping {
                        bail!("测试注入中断");
                    }
                    Ok(())
                });
            assert!(result.is_err(), "{stopping}");
            assert_eq!(identity(&source).unwrap(), before, "{stopping}");
            assert!(!receipt_path(&source).exists());
            assert_eq!(resolve_recovered_audit(&source, &signer).unwrap(), source);
            let completed = migrate_legacy_audit(&source, "migration-secret", &signer).unwrap();
            assert_eq!(completed.history_records, 1, "失败后可重试，不复用半成品");
        }
    }

    #[test]
    fn 回执篡改或旧库新增数据不静默忽略() {
        let dir = tempfile::tempdir().unwrap();
        let source = fixture(dir.path());
        let signer = FileDeviceKey::generate();
        migrate_legacy_audit(&source, "migration-secret", &signer).unwrap();
        assert!(resolve_recovered_audit(&source, &FileDeviceKey::generate()).is_err());
        let path = receipt_path(&source);
        let original = fs::read(&path).unwrap();
        let mut signed: SignedReceipt = serde_json::from_slice(&original).unwrap();
        signed.receipt.history_records += 1;
        fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
        assert!(resolve_recovered_audit(&source, &signer).is_err());
        fs::write(&path, original).unwrap();
        OpenOptions::new()
            .append(true)
            .open(sidecar(&source, "-wal"))
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        assert!(resolve_recovered_audit(&source, &signer).is_err());
    }

    #[test]
    fn 数据库占用子进程() {
        let Some(path) = std::env::var_os("AGENTGUARD_TEST_RECOVERY_LOCK") else {
            return;
        };
        let writer = AuditStore::open_with_key_unchecked(Path::new(&path), None).unwrap();
        println!("RECOVERY_FIXTURE_LOCKED");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        drop(writer);
    }

    #[test]
    fn 其他进程未退出时拒绝迁移() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        let source = fixture(dir.path());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::recovery::tests::数据库占用子进程",
                "--nocapture",
            ])
            .env("AGENTGUARD_TEST_RECOVERY_LOCK", &source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let ready = loop {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                break false;
            }
            if line.contains("RECOVERY_FIXTURE_LOCKED") {
                break true;
            }
        };
        let result = migrate_legacy_audit(&source, "migration-secret", &FileDeviceKey::generate());
        drop(child.stdin.take());
        let finished = child.wait().unwrap();
        assert!(ready && finished.success());
        assert!(format!("{:#}", result.unwrap_err()).contains("AUDIT_SOURCE_BUSY"));
        assert!(!receipt_path(&source).exists());
    }
}
