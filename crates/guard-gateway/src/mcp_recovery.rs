//! 第三方进程的持久恢复索引：执行前 fsync，重启只清理原容器，绝不重放调用。
use crate::exec::run_command_with_cancel;
use crate::isolation::{endpoint_command, verify_local_endpoint};
use crate::mcp_service::{LaunchReceipt, PreparedService};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRecord {
    name: String,
    session: String,
    image: String,
    phase: String,
}
pub(crate) struct RecoveryLog {
    file: File,
    bytes: usize,
    healthy: bool,
    pub recovered: usize,
}
impl RecoveryLog {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "服务恢复索引已有写入者"
        );
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "服务恢复索引必须是当前宿主的私有普通文件"
        );
        ensure!(metadata.len() <= 1024 * 1024, "服务恢复索引超出上限");
        file.sync_all()?;
        File::open(path.parent().context("恢复索引缺少父目录")?)?.sync_all()?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;
        ensure!(
            raw.is_empty() || raw.ends_with('\n'),
            "服务恢复索引存在不完整写入，禁止新服务"
        );
        let mut active = BTreeMap::new();
        for line in raw.lines() {
            let record: RunRecord = serde_json::from_str(line)?;
            validate_id(&record.name, "agentguard-mcp-")?;
            validate_id(&record.session, "mcp-session-")?;
            ensure!(
                record.image.starts_with("sha256:") && record.image.len() == 71,
                "恢复镜像身份无效"
            );
            match record.phase.as_str() {
                "starting" => {
                    ensure!(!active.contains_key(&record.name), "服务重复开始记录");
                    active.insert(record.name.clone(), record);
                }
                "removed" | "recovered_unknown" => {
                    let prior = active
                        .remove(&record.name)
                        .context("服务终态缺少开始记录")?;
                    ensure!(
                        prior.session == record.session && prior.image == record.image,
                        "服务恢复身份不一致"
                    );
                }
                _ => anyhow::bail!("服务恢复阶段无效"),
            }
        }
        let mut log = Self {
            file,
            bytes: raw.len(),
            healthy: true,
            recovered: 0,
        };
        if !active.is_empty() {
            let endpoint = verify_local_endpoint()?;
            for mut record in active.into_values() {
                let existing = run_command_with_cancel(
                    endpoint_command(
                        &endpoint,
                        &["ps", "-aq", "--filter", &format!("name=^/{}$", record.name)],
                    ),
                    Duration::from_secs(10),
                    &|| false,
                );
                ensure!(existing.ok && !existing.truncated, "不能查询未完成服务");
                if !existing.detail.trim().is_empty() {
                    let inspected = run_command_with_cancel(
                        endpoint_command(&endpoint, &["inspect", &record.name]),
                        Duration::from_secs(10),
                        &|| false,
                    );
                    ensure!(
                        inspected.ok && !inspected.truncated,
                        "不能核实未完成服务身份"
                    );
                    let result: Value = serde_json::from_str(&inspected.detail)?;
                    ensure!(
                        result.as_array().is_some_and(|a| a.len() == 1)
                            && result[0]["Name"] == format!("/{}", record.name)
                            && result[0]["Image"] == record.image
                            && result[0]["Config"]["Labels"]["com.agentguard.mcp-session"]
                                == record.session,
                        "未完成服务身份不匹配，拒绝删除"
                    );
                    ensure!(
                        crate::mcp_service::remove_container(&endpoint, &record.name),
                        "未完成服务清理仍未知"
                    );
                }
                record.phase = "recovered_unknown".into();
                log.append(&record)?;
                log.recovered += 1;
            }
        }
        Ok(log)
    }
    fn append(&mut self, record: &RunRecord) -> Result<()> {
        ensure!(self.healthy, "服务恢复索引已失效");
        let mut wire = serde_json::to_vec(record)?;
        wire.push(b'\n');
        ensure!(
            self.bytes + wire.len() <= 1024 * 1024,
            "服务恢复索引已达上限"
        );
        if self
            .file
            .write_all(&wire)
            .and_then(|_| self.file.sync_all())
            .is_err()
        {
            self.healthy = false;
            anyhow::bail!("服务恢复记录不能持久写入");
        }
        self.bytes += wire.len();
        Ok(())
    }
    pub fn starting(&mut self, prepared: &PreparedService<'_>) -> Result<()> {
        self.record(prepared.container_name(), prepared.receipt(), "starting")
    }
    pub fn removed(&mut self, name: &str, receipt: &LaunchReceipt) -> Result<()> {
        self.record(name, receipt, "removed")
    }
    fn record(&mut self, name: &str, receipt: &LaunchReceipt, phase: &str) -> Result<()> {
        self.append(&RunRecord {
            name: name.into(),
            session: receipt.session_id.clone(),
            image: receipt.image.clone(),
            phase: phase.into(),
        })
    }
    pub fn status(&self) -> Value {
        json!({"healthy":self.healthy,"recovered_unknown":self.recovered,"automatic_retry":false})
    }
}
impl Drop for RecoveryLog {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn validate_id(value: &str, prefix: &str) -> Result<()> {
    ensure!(
        value.strip_prefix(prefix).is_some_and(|s| s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "恢复容器或会话名称无效"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("agd-recovery-{}", crate::browser_bridge::token()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn 空索引可恢复但拒绝双写链接公开权限和不完整写入() {
        let f = Fixture::new();
        let path = f.0.join("runs");
        let log = RecoveryLog::open(&path).unwrap();
        assert!(RecoveryLog::open(&path).is_err());
        drop(log);
        assert!(RecoveryLog::open(&path).is_ok());
        let link = f.0.join("link");
        symlink(&path, &link).unwrap();
        assert!(RecoveryLog::open(&link).is_err());
        let hard = f.0.join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(RecoveryLog::open(&path).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RecoveryLog::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"{\"name\":").unwrap();
        assert!(RecoveryLog::open(&path).is_err());
    }
    #[test]
    fn 伪造名字错阶段和不匹配终态在查询容器之前拒绝() {
        let f = Fixture::new();
        let path = f.0.join("runs");
        drop(RecoveryLog::open(&path).unwrap());
        let base = json!({"name":format!("agentguard-mcp-{}","a".repeat(64)),"session":format!("mcp-session-{}","b".repeat(64)),"image":format!("sha256:{}","c".repeat(64)),"phase":"starting"});
        for patch in [
            json!({"name":"other-project"}),
            json!({"session":"wrong"}),
            json!({"phase":"fake"}),
            json!({"phase":"removed"}),
        ] {
            let mut record = base.clone();
            record
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            std::fs::write(&path, format!("{record}\n")).unwrap();
            assert!(RecoveryLog::open(&path).is_err());
        }
        let mut terminal = base.clone();
        terminal["phase"] = json!("removed");
        terminal["session"] = json!(format!("mcp-session-{}", "d".repeat(64)));
        std::fs::write(&path, format!("{base}\n{terminal}\n")).unwrap();
        assert!(RecoveryLog::open(&path).is_err());
    }
}
