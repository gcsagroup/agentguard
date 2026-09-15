//! 可信宿主的持久记忆库。复用签名审计，不向客户端暴露签名者或写库句柄。
//! 外部见证必须保存在隔离任务不可写的宿主目录；已攻陷宿主不在此边界内。

use super::AuditStore;
use crate::{AuditRecord, AuditSigner, AuditVerifyKey, HeadWitness};
use anyhow::{ensure, Context, Result};
use guard_privacy::{MemoryDraft, MemoryState};
use guard_schema::{ApprovalChoice, ApprovalRecord, Sha256Digest, ValidatedId};
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_VERSIONS: usize = 4096;
const MAX_BYTES: i64 = 16 * 1024 * 1024;
const PREFLIGHT: &[u8] = b"AGENTGUARD-MEMORY-PREFLIGHT-v1";

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_encryption(passphrase: Option<&str>) -> Result<()> {
    ensure!(
        passphrase.is_none()
            || passphrase.is_some_and(|v| !v.is_empty()) && crate::sqlcipher_enabled(),
        "请求加密时必须提供非空口令和 SQLCipher 构建"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryApprovalReference {
    pub approval_id: ValidatedId,
    pub actor_id: ValidatedId,
    pub session_id: ValidatedId,
    pub action_id: ValidatedId,
    pub request_id: ValidatedId,
    pub policy_version: ValidatedId,
    pub action_sha256: Sha256Digest,
    pub nonce_sha256: Sha256Digest,
    pub approved_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryEntry {
    pub draft: MemoryDraft,
    pub content_sha256: Sha256Digest,
    pub approval: MemoryApprovalReference,
    pub committed_at_ms: i64,
}

impl MemoryEntry {
    pub fn sha256(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::new(sha(&serde_json::to_vec(self)?))?)
    }

    fn from_approved(draft: MemoryDraft, approval: &ApprovalRecord, now_ms: i64) -> Result<Self> {
        draft.validate_at(now_ms)?;
        approval.validate()?;
        ensure!(
            approval.choice == ApprovalChoice::Approved,
            "记忆写入未批准"
        );
        approval
            .binding
            .validate_for_action(approval.binding.action(), now_ms)?;
        ensure!(approval.decided_at_ms <= now_ms, "批准时间晚于提交时间");
        let action = approval.binding.action().spec();
        ensure!(
            action.tool.service == "agentguard-memory"
                && action.tool.name == "memory_write"
                && action.tool.version == "1",
            "记忆批准的工具身份不匹配"
        );
        ensure!(
            action.target == draft.target()
                && action.parameters == serde_json::to_value(&draft)?
                && action.sources == draft.sources,
            "记忆批准未绑定完整正文、来源和最终目标"
        );
        Ok(Self {
            content_sha256: Sha256Digest::new(sha(draft.content.as_bytes()))?,
            draft,
            approval: MemoryApprovalReference {
                approval_id: approval.binding.approval_id().clone(),
                actor_id: approval.actor_id.clone(),
                session_id: action.session_id.clone(),
                action_id: action.action_id.clone(),
                request_id: action.request_id.clone(),
                policy_version: action.policy_version.clone(),
                action_sha256: Sha256Digest::new(sha(&approval
                    .binding
                    .action()
                    .canonical_bytes()))?,
                nonce_sha256: Sha256Digest::new(sha(approval.binding.nonce().as_bytes()))?,
                approved_at_ms: approval.decided_at_ms,
                expires_at_ms: approval.binding.expires_at_ms(),
            },
            committed_at_ms: now_ms,
        })
    }

    fn validate(&self) -> Result<()> {
        self.draft.validate_at(self.committed_at_ms)?;
        ensure!(
            self.content_sha256.as_str() == sha(self.draft.content.as_bytes()),
            "记忆正文摘要不一致"
        );
        ensure!(
            self.approval.approved_at_ms >= 0
                && self.approval.approved_at_ms <= self.committed_at_ms
                && self.committed_at_ms < self.approval.expires_at_ms,
            "记忆批准引用期限不一致"
        );
        Ok(())
    }

    fn record(&self) -> Result<AuditRecord> {
        Ok(AuditRecord {
            id: format!("memory/{}", self.sha256()?.as_str()),
            timestamp_ms: self.committed_at_ms,
            platform: "host".into(),
            event_type: "MemoryVersionCommitted".into(),
            source_app: "AgentGuard".into(),
            agent_session_id: Some(sha(self.approval.session_id.as_str().as_bytes())),
            rule_id: "MEMORY-STORE".into(),
            severity: "Info".into(),
            action: "committed".into(),
            human_message: "受控记忆版本已提交".into(),
            evidence_ref: None,
            user_decision: None,
            event_json: serde_json::to_string(self)?,
            attributed_agent: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    schema_version: u16,
    scope_id: ValidatedId,
    key_id: String,
    head: HeadWitness,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRecovery {
    pub old_count: usize,
    pub recovered_count: usize,
    pub current_head_sha256: String,
    pub replayed_writes: usize,
}

struct PrivateFiles {
    database: PathBuf,
    anchor: PathBuf,
    lock_path: PathBuf,
    lock: File,
    database_identity: Option<(u64, u64)>,
}

fn private_parent(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("记忆文件缺少父目录")?;
    let canonical = parent.canonicalize()?;
    let metadata = fs::metadata(&canonical)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "记忆目录必须是当前用户的私有目录"
    );
    Ok(canonical.join(path.file_name().context("记忆路径缺少文件名")?))
}

fn private_metadata(path: &Path) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "记忆文件必须是当前用户的私有普通文件且不可有硬链接"
    );
    Ok(m)
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn private_open(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = private_metadata(path)?;
    let opened = file.metadata()?;
    ensure!(
        (m.dev(), m.ino()) == (opened.dev(), opened.ino()),
        "记忆文件在打开时被替换"
    );
    Ok(file)
}

impl PrivateFiles {
    fn lock(database: &Path, anchor: &Path) -> Result<Self> {
        let database = private_parent(database)?;
        let anchor = private_parent(anchor)?;
        let mut lock_name = database.as_os_str().to_os_string();
        lock_name.push(".memory-lock");
        let lock_path = PathBuf::from(lock_name);
        ensure!(
            database != anchor
                && lock_path != anchor
                && !crate::snapshot::SUFFIXES
                    .iter()
                    .any(|suffix| crate::snapshot::sidecar(&database, suffix) == anchor),
            "记忆数据库、见证和锁路径必须独立"
        );
        let lock = private_open(&lock_path, true)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "记忆库已有写入者或检查者"
        );
        Ok(Self {
            database,
            anchor,
            lock_path,
            lock,
            database_identity: None,
        })
    }

    fn bind_database(&mut self) -> Result<()> {
        let m = private_metadata(&self.database)?;
        self.database_identity = Some((m.dev(), m.ino()));
        Ok(())
    }

    fn check(&self) -> Result<()> {
        private_parent(&self.database)?;
        private_parent(&self.anchor)?;
        let lock = private_metadata(&self.lock_path)?;
        let opened = self.lock.metadata()?;
        ensure!(
            (lock.dev(), lock.ino()) == (opened.dev(), opened.ino()),
            "记忆锁文件被替换"
        );
        let m = private_metadata(&self.database)?;
        ensure!(
            Some((m.dev(), m.ino())) == self.database_identity,
            "记忆数据库路径被替换"
        );
        for suffix in &crate::snapshot::SUFFIXES[1..] {
            let path = crate::snapshot::sidecar(&self.database, suffix);
            if exists(&path)? {
                private_metadata(&path)?;
            }
        }
        Ok(())
    }

    fn read_anchor(&self) -> Result<Anchor> {
        let m = private_metadata(&self.anchor)?;
        ensure!(m.len() <= 8192, "记忆见证超过读取上限");
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.anchor)?;
        let opened = input.metadata()?;
        ensure!(
            (m.dev(), m.ino()) == (opened.dev(), opened.ino()),
            "记忆见证被替换"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut input)
            .take(8193)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 8192, "记忆见证超过读取上限");
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_anchor(&self, value: &Anchor, create: bool) -> Result<()> {
        self.check()?;
        let parent = self.anchor.parent().context("见证父目录缺失")?;
        if !create {
            private_metadata(&self.anchor)?;
        }
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(&serde_json::to_vec(value)?)?;
        temp.as_file().sync_all()?;
        if create {
            temp.persist_noclobber(&self.anchor)?;
        } else {
            temp.persist(&self.anchor)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

impl Drop for PrivateFiles {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// 只由可信宿主持有。批准记录由宿主先认证；这里不把序列化对象当认证凭据。
pub struct MemoryStore {
    store: AuditStore,
    files: PrivateFiles,
    key: AuditVerifyKey,
    anchor: Anchor,
    faulted: Cell<bool>,
}

fn genesis(scope: &ValidatedId) -> AuditRecord {
    AuditRecord {
        id: "memory/genesis".into(),
        timestamp_ms: 0,
        platform: "host".into(),
        event_type: "MemoryStoreCreated".into(),
        source_app: "AgentGuard".into(),
        agent_session_id: None,
        rule_id: "MEMORY-STORE".into(),
        severity: "Info".into(),
        action: "created".into(),
        human_message: "受控记忆存储已创建".into(),
        evidence_ref: None,
        user_decision: None,
        event_json: serde_json::json!({"schema":"memory_store_v1","scope_id":scope}).to_string(),
        attributed_agent: None,
    }
}

fn anchor_for(store: &AuditStore, scope: &ValidatedId, key: &AuditVerifyKey) -> Result<Anchor> {
    Ok(Anchor {
        schema_version: 1,
        scope_id: scope.clone(),
        key_id: key.key_id(),
        head: store.head()?.context("记忆库缺少已签名初始化记录")?,
    })
}

fn stored_size(store: &AuditStore) -> Result<(i64, i64)> {
    let fields = format!(
        "{},prev_hash,record_hash,record_sig,signer_key_id,seq",
        store.record_cols()?
    );
    let sizes = fields
        .split(',')
        .map(|field| format!("coalesce(length(cast({} AS BLOB)),0)", field.trim()))
        .collect::<Vec<_>>()
        .join("+");
    Ok(store.conn.query_row(
        &format!("SELECT count(*),coalesce(sum({sizes}),0) FROM audit_events"),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}

/// 调用方持有同一数据库事务；签名核对与返回正文不得取自不同快照。
fn verify_in_tx(
    store: &AuditStore,
    scope: &ValidatedId,
    key: &AuditVerifyKey,
) -> Result<(Anchor, Vec<MemoryEntry>)> {
    // 先限制随后验签会读取的元数据；记忆库不使用可追加的普通决策回执。
    let (meta_count, meta_bytes): (i64, i64) = store.conn.query_row(
        "SELECT count(*),coalesce(sum(length(cast(key AS BLOB))+length(cast(value AS BLOB))),0) FROM audit_meta",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let extra_receipts: bool = store.conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM decision_receipts)",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        meta_count <= 64 && meta_bytes <= 8192 && !extra_receipts,
        "记忆元数据或额外决策超过完整恢复上限"
    );
    let (count, bytes) = stored_size(store)?;
    ensure!(
        count > 0 && count as usize <= MAX_VERSIONS + 1 && bytes <= MAX_BYTES,
        "记忆库为空或超过完整恢复上限"
    );
    let signatures = store.verify_record_signatures(key)?;
    ensure!(
        signatures.fully_covered() && signatures.total == count as usize,
        "记忆签名、顺序或正文被修改"
    );
    let snapshot = store.collect_verified_snapshot(count)?;
    let first = &snapshot.records()[0];
    ensure!(
        serde_json::to_value(first)? == serde_json::to_value(genesis(scope))?,
        "记忆库初始化身份或作用域不一致"
    );
    let current = anchor_for(store, scope, key)?;
    ensure!(
        current.head.receipt_count == 0 && current.head.count == count as usize,
        "记忆库出现不支持的额外决策记录"
    );
    let mut latest: HashMap<String, MemoryEntry> = HashMap::new();
    let mut approvals = HashSet::new();
    let mut actions = HashSet::new();
    let mut nonces = HashSet::new();
    let mut entries = Vec::new();
    let mut last_time = 0;
    for record in &snapshot.records()[1..] {
        let entry: MemoryEntry = serde_json::from_str(&record.event_json)?;
        entry.validate()?;
        ensure!(
            serde_json::to_value(record)? == serde_json::to_value(entry.record()?)?,
            "记忆记录字段与版本正文不一致"
        );
        ensure!(
            entry.draft.scope_id == *scope && entry.committed_at_ms >= last_time,
            "记忆作用域或提交顺序无效"
        );
        ensure!(
            approvals.insert(entry.approval.approval_id.clone())
                && actions.insert((
                    entry.approval.session_id.clone(),
                    entry.approval.action_id.clone()
                ))
                && nonces.insert(entry.approval.nonce_sha256.as_str().to_string()),
            "记忆批准、动作或随机值被重复使用"
        );
        check_previous(&entry, latest.get(entry.draft.key.as_str()))?;
        last_time = entry.committed_at_ms;
        latest.insert(entry.draft.key.as_str().to_string(), entry.clone());
        entries.push(entry);
    }
    Ok((current, entries))
}

fn check_previous(entry: &MemoryEntry, previous: Option<&MemoryEntry>) -> Result<()> {
    if let Some(previous) = previous {
        ensure!(
            entry.draft.version
                == previous
                    .draft
                    .version
                    .checked_add(1)
                    .context("记忆版本溢出")?
                && entry.draft.previous_sha256.as_ref() == Some(&previous.sha256()?),
            "记忆版本冲突或前驱摘要不匹配"
        );
        ensure!(
            entry.draft.preserves(&previous.draft),
            "记忆更新或恢复不能降低旧标签或丢失来源"
        );
    } else {
        ensure!(
            entry.draft.version == 1 && entry.draft.previous_sha256.is_none(),
            "新记忆必须从第一版开始"
        );
    }
    Ok(())
}

impl MemoryStore {
    /// 显式创建新库；已有库或见证不能被重建为全新历史。
    pub fn create(
        database: &Path,
        witness: &Path,
        scope: ValidatedId,
        signer: Box<dyn AuditSigner>,
        key: AuditVerifyKey,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        key.verify_message(PREFLIGHT, &signer.sign_message(PREFLIGHT)?)?;
        validate_encryption(passphrase)?;
        let mut files = PrivateFiles::lock(database, witness)?;
        ensure!(
            !exists(&files.anchor)? && !exists(&files.database)?,
            "记忆库或见证已存在，不能重新初始化"
        );
        for suffix in &crate::snapshot::SUFFIXES[1..] {
            ensure!(
                !exists(&crate::snapshot::sidecar(&files.database, suffix))?,
                "存在旧记忆恢复文件，不能新建"
            );
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&files.database)?
            .sync_all()?;
        files.bind_database()?;
        let store = AuditStore::open_with_key(&files.database, passphrase)?.with_signer(signer)?;
        store.enforce_durable_writes()?;
        store.append(&genesis(&scope))?;
        let anchor = anchor_for(&store, &scope, &key)?;
        files.write_anchor(&anchor, true)?;
        Ok(Self {
            store,
            files,
            key,
            anchor,
            faulted: Cell::new(false),
        })
    }

    /// 原件先只读验签和见证核对；不对损坏库进行自动迁移或补签。
    pub fn open(
        database: &Path,
        witness: &Path,
        scope: ValidatedId,
        signer: Box<dyn AuditSigner>,
        key: AuditVerifyKey,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        validate_encryption(passphrase)?;
        key.verify_message(PREFLIGHT, &signer.sign_message(PREFLIGHT)?)?;
        let mut files = PrivateFiles::lock(database, witness)?;
        files.bind_database()?;
        files.check()?;
        let anchor = files.read_anchor()?;
        {
            let store = AuditStore::open_read_only_with_key(&files.database, passphrase)?;
            let tx = store.conn.unchecked_transaction()?;
            let (current, _) = verify_in_tx(&store, &scope, &key)?;
            ensure!(
                current == anchor,
                "记忆头与宿主见证不一致，禁止读取或自动重试"
            );
            tx.commit()?;
        }
        let store = AuditStore::open_with_key(&files.database, passphrase)?.with_signer(signer)?;
        store.enforce_durable_writes()?;
        let memory = Self {
            store,
            files,
            key,
            anchor,
            faulted: Cell::new(false),
        };
        memory.history()?;
        Ok(memory)
    }

    fn checked_in_tx(&self) -> Result<Vec<MemoryEntry>> {
        ensure!(!self.faulted.get(), "记忆句柄已停止，须核对持久状态");
        self.files.check()?;
        ensure!(
            self.files.read_anchor()? == self.anchor,
            "宿主记忆见证发生变化"
        );
        let (current, entries) = verify_in_tx(&self.store, &self.anchor.scope_id, &self.key)?;
        ensure!(current == self.anchor, "记忆头与见证不一致");
        Ok(entries)
    }

    /// 供宿主记录页使用的完整历史；工具检索须使用 get，不能把历史版本当可用版本。
    pub fn history(&self) -> Result<Vec<MemoryEntry>> {
        let tx = self.store.conn.unchecked_transaction()?;
        let entries = self.checked_in_tx();
        if entries.is_err() {
            self.faulted.set(true);
        }
        let entries = entries?;
        tx.commit()?;
        Ok(entries)
    }

    pub fn get(&self, key: &ValidatedId, now_ms: i64) -> Result<Option<MemoryEntry>> {
        let entries = self.history()?;
        ensure!(
            now_ms >= 0 && entries.last().is_none_or(|v| now_ms >= v.committed_at_ms),
            "宿主时钟早于记忆提交，禁止使用"
        );
        Ok(entries
            .into_iter()
            .rev()
            .find(|v| v.draft.key == *key)
            .filter(|v| {
                v.draft.state == MemoryState::Active
                    && now_ms >= v.draft.created_at_ms
                    && now_ms < v.draft.expires_at_ms
            }))
    }

    pub fn commit(
        &mut self,
        draft: MemoryDraft,
        approval: &ApprovalRecord,
        now_ms: i64,
    ) -> Result<MemoryEntry> {
        ensure!(!self.faulted.get(), "记忆句柄已停止");
        let entry = MemoryEntry::from_approved(draft, approval, now_ms)?;
        ensure!(
            entry.draft.scope_id == self.anchor.scope_id,
            "记忆写入超出宿主作用域"
        );
        let tx = Transaction::new_unchecked(&self.store.conn, TransactionBehavior::Immediate)?;
        let previous = self.checked_in_tx();
        if previous.is_err() {
            self.faulted.set(true);
        }
        let previous = previous?;
        ensure!(previous.len() < MAX_VERSIONS, "记忆版本总数已达上限");
        ensure!(
            previous.last().is_none_or(|v| now_ms >= v.committed_at_ms),
            "提交时钟倒退"
        );
        check_previous(
            &entry,
            previous
                .iter()
                .rev()
                .find(|v| v.draft.key == entry.draft.key),
        )?;
        ensure!(
            !previous
                .iter()
                .any(|v| v.approval.approval_id == entry.approval.approval_id
                    || v.approval.nonce_sha256 == entry.approval.nonce_sha256
                    || v.approval.session_id == entry.approval.session_id
                        && v.approval.action_id == entry.approval.action_id),
            "记忆批准或动作已消费"
        );
        let record = entry.record()?;
        let (_, bytes) = stored_size(&self.store)?;
        // JSON 编码长度还包含字段名，另留签名与链字段余量，比实际行大小更保守。
        ensure!(
            bytes + serde_json::to_vec(&record)?.len() as i64 + 512 <= MAX_BYTES,
            "记忆库超过总恢复上限"
        );
        // 签名失败或 SQL 失败会随事务回滚；之后再次使用仍须重新验证原头。
        self.store.append_in_tx(&record)?;
        let current = anchor_for(&self.store, &self.anchor.scope_id, &self.key)?;
        if let Err(error) = tx.commit() {
            self.faulted.set(true);
            return Err(error).context("记忆数据库提交未确认，不得自动重试");
        }
        if let Err(error) = self.files.write_anchor(&current, false) {
            self.faulted.set(true);
            return Err(error).context("记忆数据库已提交但见证未确认；停止使用，不得重放旧批准");
        }
        self.anchor = current;
        Ok(entry)
    }

    /// 明确的宿主恢复操作：仅推进仍被完整签名链包含的见证，不补写任何记忆。
    pub fn recover_anchor(
        database: &Path,
        witness: &Path,
        scope: &ValidatedId,
        key: &AuditVerifyKey,
        passphrase: Option<&str>,
    ) -> Result<MemoryRecovery> {
        validate_encryption(passphrase)?;
        let mut files = PrivateFiles::lock(database, witness)?;
        files.bind_database()?;
        files.check()?;
        let old = files.read_anchor()?;
        let store = AuditStore::open_read_only_with_key(&files.database, passphrase)?;
        let tx = store.conn.unchecked_transaction()?;
        let (current, _) = verify_in_tx(&store, scope, key)?;
        ensure!(
            old.schema_version == 1
                && old.scope_id == *scope
                && old.key_id == key.key_id()
                && old.head.count > 0,
            "不能恢复未知见证"
        );
        old.head.check_against(Some(&current.head))?;
        old.head
            .check_inclusion(|hash| store.chain_contains_hash(hash))?;
        files.write_anchor(&current, false)?;
        tx.commit()?;
        Ok(MemoryRecovery {
            old_count: old.head.count,
            recovered_count: current.head.count,
            current_head_sha256: current.head.last_record_hash,
            replayed_writes: 0,
        })
    }
}
