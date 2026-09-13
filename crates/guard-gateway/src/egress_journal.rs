//! 本机出口的独占持久日志。先同步派发意图，进程重启后将无终态记录记为未知。
//! 日志目录属于可信宿主控制面，不能挂载给任务；本版不覆盖同一宿主用户主动篡改路径。

use crate::egress::{AuditStage, EgressAudit, EgressJournal, MAX_REQUEST_BYTES};
use anyhow::{bail, Context, Result};
use guard_audit::{AuditRecord, AuditStore};
use guard_schema::ExecutionOutcome;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct JournalState {
    store: AuditStore,
    pending: HashMap<String, EgressAudit>,
    healthy: bool,
}
pub struct DurableEgressJournal {
    state: Mutex<JournalState>,
    _lock: File,
    parent: File,
    path: PathBuf,
    database: File,
    recovered_unknown: usize,
}
impl Drop for DurableEgressJournal {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // fork中临时继承的fd不应延长本实例的日志锁寿命。
            unsafe {
                libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
fn time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_event(event: &EgressAudit) -> bool {
    let code = matches!(
        event.code,
        "EGRESS_DISPATCH_INTENT"
            | "EGRESS_OK"
            | "EGRESS_CONNECT"
            | "EGRESS_IO"
            | "EGRESS_CANCELLED"
            | "EGRESS_TIMEOUT"
            | "EGRESS_HTTP_FORMAT"
            | "EGRESS_RESPONSE_LIMIT"
            | "EGRESS_REDIRECT"
            | "EGRESS_HTTP_STATUS"
            | "EGRESS_JSON_TYPE"
            | "EGRESS_JSON_FORMAT"
    );
    event.version == 1
        && hash(&event.event_id)
        && hash(&event.session_sha256)
        && hash(&event.service_sha256)
        && hash(&event.purpose_sha256)
        && hash(&event.request_sha256)
        && event.response_sha256.as_ref().is_none_or(|s| hash(s))
        && event.request_bytes <= MAX_REQUEST_BYTES
        && code
        && match event.stage {
            AuditStage::BeforeDispatch => {
                event.outcome == ExecutionOutcome::Unknown
                    && !event.dispatched
                    && event.code == "EGRESS_DISPATCH_INTENT"
                    && event.response_sha256.is_none()
            }
            AuditStage::Completed => {
                event.code != "EGRESS_DISPATCH_INTENT"
                    && !(event.outcome == ExecutionOutcome::Refused && event.dispatched)
                    && !(event.outcome == ExecutionOutcome::Success
                        && (!event.dispatched || event.code != "EGRESS_OK"))
                    && (event.response_sha256.is_none()
                        || event.outcome == ExecutionOutcome::Success)
            }
        }
}
fn same_binding(a: &EgressAudit, b: &EgressAudit) -> bool {
    a.event_id == b.event_id
        && a.session_sha256 == b.session_sha256
        && a.service_sha256 == b.service_sha256
        && a.purpose_sha256 == b.purpose_sha256
        && a.request_sha256 == b.request_sha256
        && a.epoch == b.epoch
        && a.request_bytes == b.request_bytes
}
fn record(event: &EgressAudit) -> Result<AuditRecord> {
    let state = serde_json::to_value(event.outcome)?;
    let mut summary = serde_json::to_value(event)?;
    summary["schema"] = json!("egress_execution_v1");
    // 派发意图的false只表示此记录发生于socket操作前；重启不能据此推断没有发出。
    summary["side_effects"] = json!(
        if event.stage == AuditStage::Completed && !event.dispatched {
            "not_dispatched"
        } else {
            "unknown"
        }
    );
    let finished = event.stage == AuditStage::Completed;
    Ok(AuditRecord {
        id: format!(
            "egress/{}{}",
            event.event_id,
            if finished { "/result" } else { "" }
        ),
        timestamp_ms: time_ms(),
        platform: "gateway".into(),
        event_type: if finished {
            "EgressDispatchFinished"
        } else {
            "EgressDispatchStarted"
        }
        .into(),
        source_app: "agentguard-egress".into(),
        agent_session_id: Some(event.session_sha256.clone()),
        rule_id: "EGRESS-EXECUTION".into(),
        severity: "Info".into(),
        action: if finished {
            state.as_str().unwrap_or("unknown")
        } else {
            "dispatch_intent"
        }
        .into(),
        human_message: "本机出口执行回执；仅保存摘要与固定状态".into(),
        evidence_ref: None,
        user_decision: None,
        event_json: serde_json::to_string(&summary)?,
        attributed_agent: None,
    })
}

#[cfg(unix)]
fn private_file(path: &Path, create: bool) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).context("不能打开出口审计文件")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("出口审计文件必须由本用户独占且不能有硬链接");
    }
    Ok(file)
}
#[cfg(not(unix))]
fn private_file(_path: &Path, _create: bool) -> Result<File> {
    bail!("出口审计尚未验证此宿主平台");
}
fn parent_handle(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        crate::isolation::open_absolute_dir(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("出口审计尚未验证此宿主平台")
    }
}
impl DurableEgressJournal {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        bail!("出口审计尚未验证此宿主平台");
        if !path.is_absolute()
            || path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            bail!("出口审计需要规范绝对路径");
        }
        let logical_parent = path.parent().context("出口审计路径缺少父目录")?;
        let physical_parent = logical_parent
            .canonicalize()
            .context("出口审计父目录必须先由宿主创建")?;
        if guard_schema::paths::dealias_platform_volumes(logical_parent)
            != guard_schema::paths::dealias_platform_volumes(&physical_parent)
        {
            bail!("出口审计父目录含用户符号链接");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = std::fs::metadata(&physical_parent)?;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o022 != 0
            {
                bail!("出口审计目录必须属于本用户且禁止其他用户写入");
            }
        }
        let path = physical_parent.join(path.file_name().context("出口审计文件名无效")?);
        let parent = parent_handle(&physical_parent)?;
        let lock = private_file(&path.with_extension("egress-lock"), true)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("出口审计已有写入者，拒绝并发恢复");
            }
        }
        // 先约束主文件与可能已有的sidecar。不会修改已存在的不安全权限。
        let database = private_file(&path, true)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", path.to_string_lossy()));
            match std::fs::symlink_metadata(&sidecar) {
                Ok(_) => {
                    private_file(&sidecar, false)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // 出口只保存摘要，不自动读取环境中的账号/加密凭据；本版明示未加密未签名。
        let store = AuditStore::open_with_key(&path, None)?;
        store.enforce_durable_writes()?;
        if !store.verify_chain()?.ok {
            bail!("出口审计链损坏，拒绝继续执行");
        }
        let mut recovered_unknown = 0;
        for previous in store.unfinished_egress_actions()? {
            let mut summary: Value =
                serde_json::from_str(&previous.event_json).context("出口恢复记录格式无效")?;
            // 记录已经过哈希链核对；另外拒绝把异类行伪装成本代理的启动记录。
            if summary.get("schema").and_then(Value::as_str) != Some("egress_execution_v1")
                || summary.get("stage").and_then(Value::as_str) != Some("before_dispatch")
                || summary
                    .get("event_id")
                    .and_then(Value::as_str)
                    .is_none_or(|id| !hash(id) || previous.id != format!("egress/{id}"))
            {
                bail!("出口恢复记录不属于此版本");
            }
            summary["stage"] = json!("completed");
            summary["outcome"] = json!("unknown");
            summary["dispatched"] = Value::Null;
            summary["side_effects"] = json!("unknown");
            summary["code"] = json!("EGRESS_RECOVERED_UNKNOWN");
            summary["recovery"] = json!("process_restarted_without_terminal_receipt");
            store.append(&AuditRecord {
                id: format!("{}/result", previous.id),
                timestamp_ms: time_ms(),
                event_type: "EgressDispatchFinished".into(),
                action: "unknown".into(),
                human_message: "进程重启后缺少出口终态，结果未知，未自动重试".into(),
                event_json: serde_json::to_string(&summary)?,
                ..previous
            })?;
            recovered_unknown += 1;
        }
        parent.sync_all()?;
        let journal = Self {
            state: Mutex::new(JournalState {
                store,
                pending: HashMap::new(),
                healthy: true,
            }),
            _lock: lock,
            parent,
            path,
            database,
            recovered_unknown,
        };
        journal.check_identity()?;
        Ok(journal)
    }
    pub fn recovered_unknown_count(&self) -> usize {
        self.recovered_unknown
    }
    pub fn status(&self) -> Value {
        let healthy = self
            .state
            .lock()
            .map(|state| state.healthy)
            .unwrap_or(false);
        json!({"persistent":true,"healthy":healthy,"recovered_unknown":self.recovered_unknown,
            "contents":"ids_and_digests_only","automatic_retry":false,"encrypted":false,"signed":false})
    }
    fn check_identity(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let expected_parent = self.parent.metadata()?;
            let parent = std::fs::symlink_metadata(self.path.parent().context("缺少父目录")?)?;
            let expected_database = self.database.metadata()?;
            let database = std::fs::symlink_metadata(&self.path)?;
            if !parent.is_dir()
                || parent.ino() != expected_parent.ino()
                || parent.dev() != expected_parent.dev()
                || parent.permissions().mode() & 0o022 != 0
                || !database.is_file()
                || database.ino() != expected_database.ino()
                || database.dev() != expected_database.dev()
                || database.nlink() != 1
                || database.permissions().mode() & 0o077 != 0
            {
                bail!("出口审计路径或权限发生变化");
            }
        }
        Ok(())
    }
}
impl EgressJournal for DurableEgressJournal {
    fn record(&self, event: &EgressAudit) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "EGRESS_JOURNAL_STATE".to_string())?;
        let result = (|| -> Result<()> {
            if !state.healthy || !valid_event(event) {
                bail!("出口审计已关闭或记录无效");
            }
            self.check_identity()?;
            match event.stage {
                AuditStage::BeforeDispatch => {
                    if state.pending.contains_key(&event.event_id) {
                        bail!("出口开始记录重复");
                    }
                }
                AuditStage::Completed => {
                    if state
                        .pending
                        .get(&event.event_id)
                        .is_none_or(|before| !same_binding(before, event))
                    {
                        bail!("出口终态缺少相同绑定的开始记录");
                    }
                }
            }
            state.store.append(&record(event)?)?;
            match event.stage {
                AuditStage::BeforeDispatch => {
                    state.pending.insert(event.event_id.clone(), event.clone());
                }
                AuditStage::Completed => {
                    state.pending.remove(&event.event_id);
                }
            }
            Ok(())
        })();
        if result.is_err() {
            state.healthy = false;
            return Err("EGRESS_JOURNAL_FAILED".into());
        }
        Ok(())
    }
}
