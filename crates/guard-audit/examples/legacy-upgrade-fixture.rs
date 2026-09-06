//! 仅供验收构造合成旧库，不读取现有历史、不生成密钥、不运行迁移。
use anyhow::{bail, Context, Result};
use guard_audit::{AuditRecord, AuditStore};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--create-isolated-legacy" {
        bail!("用法：legacy-upgrade-fixture --create-isolated-legacy <新建隔离验收库绝对路径>");
    }
    let path = PathBuf::from(&args[2]);
    let parent = path.parent().context("缺少父目录")?;
    if !path.is_absolute()
        || !path
            .components()
            .any(|part| part.as_os_str() == "agentguard-acceptance")
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || parent.exists()
    {
        bail!("只允许在尚不存在的 agentguard-acceptance 子工作区构造合成库");
    }
    std::fs::create_dir_all(parent)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let store = AuditStore::open(&path)?;
    store.append(&AuditRecord {
        id: "acceptance-legacy-record-001".into(),
        timestamp_ms: 1788566400000,
        platform: "acceptance-fixture".into(),
        event_type: "UiTreeDelta".into(),
        source_app: "AgentGuard 合成升级验收".into(),
        agent_session_id: None,
        rule_id: "ACCEPTANCE-HISTORY".into(),
        severity: "Info".into(),
        action: "LogOnly".into(),
        human_message: "这是一条合成旧版历史记录，用于验证升级后仍可查看。".into(),
        evidence_ref: None,
        user_decision: None,
        event_json: "{}".into(),
        attributed_agent: None,
    })?;
    drop(store);
    println!("已创建 1 条合成旧版历史：{}", path.display());
    Ok(())
}
