//! 宿主固定的签名仓库：动作策略摘要同时绑定启动配置与当前发布代次。
use anyhow::{ensure, Context, Result};
use guard_intel::package::{
    store::{PackageStore, PolicyLease, RuntimeSnapshot, RuntimeStore},
    PackageKind, RulePayload,
};
use guard_schema::{ActionSnapshot, DecisionAction, EventType, GuardEvent};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePackageConfig {
    pub store: PathBuf,
    pub public_key_base64: String,
    pub stream: String,
    pub device_id: String,
}
impl RulePackageConfig {
    pub fn read(path: &Path) -> Result<Self> {
        use std::io::Read;
        validate_private_path(path)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path)?;
        ensure!(file.metadata()?.is_file(), "规则包配置不是普通文件");
        let mut bytes = Vec::new();
        file.take(16385).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16384, "规则包配置过大");
        let config: Self = serde_json::from_slice(&bytes)?;
        validate_private_path(&config.store)?;
        Ok(config)
    }
    pub fn open(&self) -> Result<RuntimeStore> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode(&self.public_key_base64)?;
        let key = guard_intel::PublicKeyBytes::from_bytes(
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("规则包公钥必须为32字节"))?,
        );
        validate_private_path(&self.store)?;
        RuntimeStore::new(PackageStore::open_existing(
            &self.store,
            key,
            &self.stream,
            PackageKind::Rules,
            &self.device_id,
        )?)
    }
}
fn validate_private_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "规则包路径必须是无 .. 的绝对路径"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "规则包路径必须是已有普通文件，不能是符号链接"
    );
    ensure!(
        guard_schema::paths::dealias_platform_volumes(&path.canonicalize()?)
            == guard_schema::paths::dealias_platform_volumes(path),
        "规则包路径不能含用户符号链接"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
            "规则包文件必须由当前宿主持有且仅本人可读写"
        );
        let parent = std::fs::metadata(path.parent().context("规则包路径没有父目录")?)?;
        ensure!(
            parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o022 == 0,
            "规则包父目录不能由其他用户写入"
        );
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct RuntimePolicy {
    store: RuntimeStore,
    base: String,
}
pub(crate) struct PolicyContext {
    pub version: String,
    pub snapshot: Arc<RuntimeSnapshot>,
}
impl RuntimePolicy {
    pub fn new(store: RuntimeStore, base: String) -> Result<Self> {
        let policy = Self { store, base };
        policy.context()?;
        Ok(policy)
    }
    pub fn context(&self) -> Result<PolicyContext> {
        let snapshot = self.store.snapshot()?;
        ensure!(
            snapshot.package().is_some(),
            "当前规则包为空或已撤销，拒绝新动作"
        );
        let mut hash = Sha256::new();
        hash.update(b"agentguard.gateway-rule-policy.v1\0");
        hash.update((self.base.len() as u64).to_be_bytes());
        hash.update(self.base.as_bytes());
        hash.update(snapshot.binding_sha256().as_bytes());
        Ok(PolicyContext {
            version: format!("sha256-{:x}", hash.finalize()),
            snapshot,
        })
    }
    pub fn acquire(&self, version: &str) -> Result<PolicyLease> {
        let context = self.context()?;
        ensure!(
            context.version == version,
            "规则包发布已变化，旧动作批准不能派发"
        );
        self.store.acquire(context.snapshot.binding_sha256())
    }
    pub fn receipt(&self, version: &str) -> Result<serde_json::Value> {
        let context = self.context()?;
        ensure!(context.version == version, "构造动作期间规则包已变化");
        Ok(context.receipt())
    }
}
impl PolicyContext {
    pub fn payload(&self) -> Result<RulePayload> {
        let package = self.snapshot.package().context("当前规则包不可执行")?;
        // RuntimeSnapshot 只能由逐条重验签名的规则仓库生成。
        Ok(serde_json::from_value(package.content.clone())?)
    }
    pub fn receipt(&self) -> serde_json::Value {
        serde_json::json!({"binding_sha256":self.snapshot.binding_sha256(), "status":self.snapshot.status(), "instruction_authority":"none"})
    }
    /// 无状态内容判据只增加约束；浏览器／回写入口继续执行各自的宿主控制。
    pub fn judge(
        &self,
        action: &ActionSnapshot,
        event_type: EventType,
    ) -> Result<crate::gate::Outcome> {
        let spec = action.spec();
        let event = GuardEvent {
            event_id: spec.action_id.to_string(),
            timestamp_ms: spec.issued_at_ms,
            platform: "gateway".into(),
            event_type,
            source_app: "agentguard-mcp".into(),
            agent_context_id: Some(spec.session_id.to_string()),
            metadata: [
                (
                    "ui_text".into(),
                    format!("{} {}", spec.target, spec.parameters),
                ),
                ("url".into(), spec.target.clone()),
            ]
            .into(),
        };
        let decision = guard_core::Engine::rule_content_decision(self.payload()?, &event)?;
        let findings = vec![crate::gate::Finding {
            rule_id: decision.rule_id,
            layer: "signed-rule-package".into(),
            severity: format!("{:?}", decision.severity).to_lowercase(),
            message: decision.human_message,
        }];
        Ok(if decision.action == DecisionAction::Block {
            crate::gate::Outcome::Refuse { findings }
        } else if decision.require_confirm {
            crate::gate::Outcome::NeedsConfirmation { findings }
        } else {
            crate::gate::Outcome::Execute { findings }
        })
    }
}

pub(crate) fn acquire(
    policy: Option<&RuntimePolicy>,
    version: &str,
) -> Result<Option<PolicyLease>> {
    policy.map(|p| p.acquire(version)).transpose()
}
