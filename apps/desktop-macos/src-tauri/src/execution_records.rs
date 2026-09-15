//! 仅浏览应用自己的任务审计目录。前端只能给规范 UUID，不能给文件路径、密钥或 URL。
use guard_gateway::execution_view::{read_execution_log, ExecutionLogView};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tauri::Manager;

#[derive(Serialize)]
pub(crate) struct SessionChoice {
    id: String,
    modified_ms: u64,
}

#[derive(Serialize)]
pub(crate) struct SessionList {
    sessions: Vec<SessionChoice>,
    truncated: bool,
}

#[derive(Serialize)]
pub(crate) struct ChannelView {
    channel: &'static str,
    status: &'static str,
    log: Option<ExecutionLogView>,
}

#[derive(Serialize)]
pub(crate) struct SessionView {
    session_id: String,
    channels: Vec<ChannelView>,
}

fn root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| "EXECUTION_STORAGE")?
        .join("local-agent-sessions"))
}

#[cfg(unix)]
fn checked(path: &Path, directory: bool, private: bool) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "EXECUTION_STORAGE")?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err("EXECUTION_STORAGE_UNSAFE".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn checked(_: &Path, _: bool, _: bool) -> Result<(u64, u64), String> {
    Err("EXECUTION_STORAGE_UNSUPPORTED".into())
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id)
}

fn list(root: &Path) -> Result<SessionList, String> {
    if std::fs::symlink_metadata(root).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(SessionList {
            sessions: vec![],
            truncated: false,
        });
    }
    checked(root, true, false)?;
    let mut sessions = Vec::new();
    for (index, entry) in std::fs::read_dir(root)
        .map_err(|_| "EXECUTION_STORAGE")?
        .enumerate()
    {
        if index >= 4096 {
            return Err("EXECUTION_STORAGE_LIMIT".into());
        }
        let entry = entry.map_err(|_| "EXECUTION_STORAGE")?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if !valid_id(&id) {
            continue;
        }
        checked(&entry.path(), true, true)?;
        let modified_ms = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        sessions.push(SessionChoice { id, modified_ms });
    }
    // 只供选择最近使用的目录；具体动作顺序来自各日志的追加序号，不以时间戳重排。
    sessions.sort_by(|a, b| b.modified_ms.cmp(&a.modified_ms).then(a.id.cmp(&b.id)));
    let truncated = sessions.len() > 256;
    sessions.truncate(256);
    Ok(SessionList {
        sessions,
        truncated,
    })
}

fn read(root: &Path, id: &str) -> Result<SessionView, String> {
    if !valid_id(id) {
        return Err("EXECUTION_SESSION_ID".into());
    }
    let root_identity = checked(root, true, false)?;
    let directory = root.join(id);
    let identity = checked(&directory, true, true)?;
    let mut channels = Vec::new();
    for (channel, name) in [("gateway", "audit.db"), ("browser", "browser-audit.db")] {
        let path = directory.join(name);
        if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            channels.push(ChannelView {
                channel,
                status: "not_recorded",
                log: None,
            });
            continue;
        }
        let result = (|| {
            let file_identity = checked(&path, false, false)?;
            for suffix in ["-wal", "-shm", "-journal"] {
                let sibling = directory.join(format!("{name}{suffix}"));
                if std::fs::symlink_metadata(&sibling).is_ok() {
                    checked(&sibling, false, false)?;
                }
            }
            // 受管网关清空环境且不接收 App 的桌面审计口令。这些旧日志明确为无正文的明文摘要。
            // 不能拿桌面密钥试读，也不能因密钥不匹配降级重建数据库。
            let log = read_execution_log(&path, None).map_err(|_| "EXECUTION_LOG_INVALID")?;
            if checked(&path, false, false)? != file_identity {
                return Err("EXECUTION_STORAGE_CHANGED".to_string());
            }
            Ok(log)
        })();
        channels.push(match result {
            Ok(log) => ChannelView {
                channel,
                status: "verified",
                log: Some(log),
            },
            Err(_) => ChannelView {
                channel,
                status: "unavailable",
                log: None,
            },
        });
    }
    if checked(root, true, false)? != root_identity || checked(&directory, true, true)? != identity
    {
        return Err("EXECUTION_STORAGE_CHANGED".into());
    }
    Ok(SessionView {
        session_id: id.into(),
        channels,
    })
}

#[tauri::command]
pub(crate) async fn list_execution_sessions(app: tauri::AppHandle) -> Result<SessionList, String> {
    let root = root(&app)?;
    tauri::async_runtime::spawn_blocking(move || list(&root))
        .await
        .map_err(|_| "EXECUTION_READER")?
}

#[tauri::command]
pub(crate) async fn read_execution_session(
    app: tauri::AppHandle,
    session_id: String,
) -> Result<SessionView, String> {
    let root = root(&app)?;
    tauri::async_runtime::spawn_blocking(move || read(&root, &session_id))
        .await
        .map_err(|_| "EXECUTION_READER")?
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use guard_audit::AuditStore;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("agd-history-view-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn session(&self) -> (String, PathBuf) {
            let id = uuid::Uuid::new_v4().to_string();
            let path = self.0.join(&id);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            (id, path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn 只接受私有宿主目录内的规范会话编号() {
        let f = Fixture::new();
        let (id, path) = f.session();
        let db = AuditStore::open_with_key(path.join("audit.db"), None).unwrap();
        drop(db);
        assert_eq!(list(&f.0).unwrap().sessions.len(), 1);
        let view = read(&f.0, &id).unwrap();
        assert_eq!(view.channels[0].status, "verified");
        assert_eq!(view.channels[1].status, "not_recorded");
        for invalid in ["../audit.db", "/tmp/a", "not-a-uuid"] {
            assert!(read(&f.0, invalid).is_err());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read(&f.0, &id).is_err());
    }
    #[test]
    fn 缺失目录只返回未登记不创建目录() {
        let f = Fixture::new();
        let path = f.0.join("missing");
        assert!(list(&path).unwrap().sessions.is_empty());
        assert!(!path.exists());
    }
    #[test]
    fn 拒绝目录和数据库符号链接且不打开外部内容() {
        let f = Fixture::new();
        let outside = Fixture::new();
        let (id, path) = f.session();
        let external = outside.0.join("audit.db");
        std::fs::write(&external, b"EXTERNAL_UNCHANGED").unwrap();
        symlink(&external, path.join("audit.db")).unwrap();
        let view = read(&f.0, &id).unwrap();
        assert_eq!(view.channels[0].status, "unavailable");
        assert!(view.channels[0].log.is_none());
        let linked = uuid::Uuid::new_v4().to_string();
        symlink(&outside.0, f.0.join(&linked)).unwrap();
        assert!(read(&f.0, &linked).is_err());
        assert!(list(&f.0).is_err());
        assert_eq!(std::fs::read(external).unwrap(), b"EXTERNAL_UNCHANGED");
    }
    #[test]
    fn 损坏通道不可读但不会伪装成空日志或吞掉另一通道() {
        let f = Fixture::new();
        let (id, path) = f.session();
        std::fs::write(path.join("audit.db"), b"INVALID_DB").unwrap();
        let db = AuditStore::open_with_key(path.join("browser-audit.db"), None).unwrap();
        drop(db);
        let view = read(&f.0, &id).unwrap();
        assert_eq!(view.channels[0].status, "unavailable");
        assert_eq!(view.channels[1].status, "verified");
        assert_eq!(std::fs::read(path.join("audit.db")).unwrap(), b"INVALID_DB");
    }
    #[test]
    #[ignore = "显式读取本次私有测试目录并导出实际宿主接口输出，不启动 App"]
    fn 导出宿主执行记录接口() {
        let root = std::env::var_os("AGENTGUARD_EXECUTION_ROOT").unwrap();
        let output = std::env::var_os("AGENTGUARD_EXECUTION_OUTPUT").unwrap();
        let id = std::env::var("AGENTGUARD_EXECUTION_SESSION").unwrap();
        let result = serde_json::json!({"sessions":list(Path::new(&root)).unwrap(),"view":read(Path::new(&root),&id).unwrap()});
        std::fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    }
}
