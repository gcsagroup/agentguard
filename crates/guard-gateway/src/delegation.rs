//! 宿主持有签名密钥的委托授权器；每条消息都认证，授权对象不是 Bearer 凭据。
use crate::delegation_budget::BudgetLimits;
use crate::delegation_governance::BudgetManager;
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use guard_audit::{AuditSigner, FileDeviceKey};
use guard_schema::delegation::*;
use guard_schema::{Sha256Digest, ValidatedId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const MAX_GRANTS: usize = 128;
fn id(prefix: &str) -> ValidatedId {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    ValidatedId::new(format!(
        "{prefix}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
    .expect("宿主生成固定格式标识")
}
fn key(hex: &str) -> Result<VerifyingKey> {
    ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "公钥必须是 32 字节小写十六进制"
    );
    ensure!(
        guard_schema::publicly_known_agent_key(hex).is_none(),
        "公开夹具密钥不能认证委托主体"
    );
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    let key = VerifyingKey::from_bytes(&bytes)?;
    ensure!(!key.is_weak(), "弱公钥不能认证委托主体");
    Ok(key)
}
fn signature(hex: &str) -> Result<Signature> {
    ensure!(
        hex.len() == 128
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "签名编码无效"
    );
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(Signature::from_bytes(&bytes))
}
pub(crate) fn grant_digest(grant: &DelegationGrant) -> Result<Sha256Digest> {
    Ok(crate::tool_registry::digest(&grant.signing_bytes()?))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPrincipal {
    pub subject_id: ValidatedId,
    pub public_key: String,
    pub permissions: DelegationPermissions,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationConfig {
    pub version: u16,
    pub authority_id: ValidatedId,
    pub signing_key: PathBuf,
    pub public_key: String,
    pub root_subject_id: ValidatedId,
    pub target_id: ValidatedId,
    pub lifetime_ms: i64,
    pub principals: Vec<DelegationPrincipal>,
    #[serde(default)]
    pub budgets: BudgetLimits,
}
impl DelegationConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(&crate::memory_config::read_private(path, 256 * 1024)?)?;
        config.validate()?;
        ensure!(
            config.signing_key.is_absolute()
                && !config
                    .signing_key
                    .components()
                    .any(|c| matches!(c, Component::ParentDir)),
            "委托私钥必须为无 .. 的绝对路径"
        );
        let parent = std::fs::metadata(config.signing_key.parent().context("私钥缺少父目录")?)?;
        ensure!(
            parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o077 == 0,
            "委托签名目录必须由宿主私有持有"
        );
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        self.budgets.validate()?;
        ensure!(
            self.version == DELEGATION_VERSION
                && (1..=DELEGATION_MAX_TTL_MS).contains(&self.lifetime_ms),
            "委托配置版本或期限无效"
        );
        ensure!(
            !self.principals.is_empty() && self.principals.len() <= 32,
            "主体清单必须为 1～32 项"
        );
        key(&self.public_key)?;
        let mut subjects = HashSet::new();
        let mut keys = HashSet::new();
        keys.insert(self.public_key.as_str());
        for principal in &self.principals {
            key(&principal.public_key)?;
            principal.permissions.validate()?;
            ensure!(
                subjects.insert(principal.subject_id.as_str())
                    && keys.insert(principal.public_key.as_str()),
                "主体或公钥重复，无法区分身份"
            );
        }
        ensure!(
            subjects.contains(self.root_subject_id.as_str()),
            "根主体未登记"
        );
        for principal in &self.principals {
            for to in &principal.permissions.delegate_to {
                ensure!(subjects.contains(to.as_str()), "权限指向未登记主体");
            }
        }
        Ok(())
    }
    pub fn open(self, parent: &guard_shell::paths::Workspace) -> Result<DelegationAuthority> {
        self.validate()?;
        let secret = crate::memory_config::read_private(&self.signing_key, 128)?;
        let signing = FileDeviceKey::from_secret_hex(std::str::from_utf8(&secret)?)?;
        ensure!(
            signing.verifying_key().to_hex() == self.public_key,
            "委托签名私钥与钉住公钥不一致"
        );
        let mut principals = HashMap::new();
        for mut principal in self.principals {
            // 文件上限再取实际父工作区交集；不同操作保持独立，不把可写推断成可删。
            for (files, grants) in [
                (&mut principal.permissions.read_files, parent.read_grants()),
                (
                    &mut principal.permissions.write_files,
                    parent.write_grants(),
                ),
                (
                    &mut principal.permissions.delete_files,
                    parent.write_grants(),
                ),
            ] {
                files.retain(|file| {
                    let path = guard_schema::paths::dealias_platform_volumes(Path::new(file));
                    grants
                        .iter()
                        .any(|root| path != *root && path.starts_with(root))
                });
            }
            principals.insert(principal.subject_id.to_string(), principal);
        }
        Ok(DelegationAuthority {
            authority_id: self.authority_id,
            signing,
            public_key: self.public_key,
            root_subject: self.root_subject_id,
            target: self.target_id,
            lifetime_ms: self.lifetime_ms,
            principals,
            grants: HashMap::new(),
            root: None,
            host_session: None,
            budget: BudgetManager::default(),
            budgets: self.budgets,
        })
    }
}

struct GrantState {
    signed: SignedDelegationGrant,
    last_sequence: u64,
}
pub struct DelegationAuthority {
    pub(crate) budget: BudgetManager,
    pub(crate) budgets: BudgetLimits,
    authority_id: ValidatedId,
    signing: FileDeviceKey,
    public_key: String,
    root_subject: ValidatedId,
    target: ValidatedId,
    lifetime_ms: i64,
    principals: HashMap<String, DelegationPrincipal>,
    grants: HashMap<String, GrantState>,
    root: Option<String>,
    host_session: Option<ValidatedId>,
}
/// 构造器只在认证器内部；不可由 JSON 反序列化或客户端自报。
pub(crate) struct VerifiedDelegation {
    pub(crate) envelope: DelegationEnvelope,
    pub(crate) grant: SignedDelegationGrant,
    public_key: String,
}
impl VerifiedDelegation {
    pub(crate) fn receipt(&self) -> Value {
        json!({"message":self.envelope.message,"signature":self.envelope.signature,"subject_public_key":self.public_key,
            "grant_sha256":self.envelope.message.grant_sha256,"instruction_authority":"none"})
    }
    pub(crate) fn deadline(&self) -> i64 {
        self.envelope
            .message
            .expires_at_ms
            .min(self.grant.grant.expires_at_ms)
    }
}
impl DelegationAuthority {
    fn sign(&self, grant: DelegationGrant) -> Result<SignedDelegationGrant> {
        let signature = self.signing.sign_message(&grant.signing_bytes()?)?;
        key(&self.public_key)?
            .verify_strict(&grant.signing_bytes()?, &self::signature(&signature)?)?;
        Ok(SignedDelegationGrant {
            grant,
            key_id: ValidatedId::new(self.signing.key_id())?,
            signature,
        })
    }
    pub(crate) fn start(&mut self, host: &str, now: i64) -> Result<SignedDelegationGrant> {
        self.grants.clear();
        self.root = None;
        self.host_session = None;
        let host = ValidatedId::new(host)?;
        let signed = self.sign(DelegationGrant {
            version: 1,
            authority_id: self.authority_id.clone(),
            host_session_id: host.clone(),
            grant_id: id("grant"),
            session_id: id("delegate-session"),
            parent_session_id: None,
            parent_grant_sha256: None,
            delegator_id: None,
            subject_id: self.root_subject.clone(),
            target_id: self.target.clone(),
            permissions: self.principals[self.root_subject.as_str()]
                .permissions
                .clone(),
            issued_at_ms: now,
            expires_at_ms: now.checked_add(self.lifetime_ms).context("授权时钟溢出")?,
        })?;
        let mut limits = self.budgets.clone();
        limits.max_elapsed_ms = limits.max_elapsed_ms.min(self.lifetime_ms as u64);
        self.budget
            .start(host.as_str(), signed.grant.grant_id.as_str(), limits)?;
        self.root = Some(signed.grant.grant_id.to_string());
        self.host_session = Some(host);
        self.grants.insert(
            signed.grant.grant_id.to_string(),
            GrantState {
                signed: signed.clone(),
                last_sequence: 0,
            },
        );
        Ok(signed)
    }
    pub(crate) fn status(&self) -> Value {
        json!({"enabled":true,"protocol_version":1,"authority_id":self.authority_id,"authority_public_key":self.public_key,
            "root_grant":self.root.as_ref().and_then(|id|self.grants.get(id).map(|state|&state.signed)),"active_grants":self.grants.len(),
            "supported_tools":["read_file","write_file","delete_file"],"scope":"经本协议认证的隔离文件工具；客户端其它入口未覆盖","restart":"old_grants_invalid_no_replay",
            "budgets":self.budget.status().unwrap_or_else(|_|json!({"unavailable":true}))})
    }
    pub(crate) fn authenticate(
        &self,
        envelope: DelegationEnvelope,
        host: &str,
        now: i64,
    ) -> Result<VerifiedDelegation> {
        envelope.validate_at(now)?;
        ensure!(
            self.host_session.as_ref().map(ValidatedId::as_str) == Some(host)
                && envelope.message.host_session_id.as_str() == host,
            "委托不属于当前宿主会话"
        );
        let message = &envelope.message;
        let principal = self
            .principals
            .get(message.actor_id.as_str())
            .context("委托主体未登记")?;
        key(&principal.public_key)?
            .verify_strict(&message.signing_bytes()?, &signature(&envelope.signature)?)?;
        ensure!(
            message.operation_sha256
                == crate::tool_registry::digest(&envelope.command.binding_bytes()?),
            "委托操作与签名摘要不一致"
        );
        let state = self
            .grants
            .get(message.grant_id.as_str())
            .context("委托授权不存在或已失效")?;
        let grant = &state.signed.grant;
        grant.validate_at(now)?;
        ensure!(
            message.grant_sha256 == grant_digest(grant)?
                && message.actor_id == grant.subject_id
                && message.session_id == grant.session_id
                && message.target_id == grant.target_id
                && message.issued_at_ms >= grant.issued_at_ms
                && message.expires_at_ms <= grant.expires_at_ms,
            "委托主体、父链、目标或期限绑定不一致"
        );
        ensure!(
            state.last_sequence.checked_add(1) == Some(message.sequence),
            "旧消息重放、乱序或序号溢出"
        );
        ensure!(
            grant.permissions.allows(&envelope.command)
                && principal.permissions.allows(&envelope.command),
            "委托操作超出实际权限交集"
        );
        if let DelegationCommand::Delegate {
            subject_id,
            expires_at_ms,
            ..
        } = &envelope.command
        {
            ensure!(
                self.principals.contains_key(subject_id.as_str()) && *expires_at_ms > now,
                "接收主体或委托期限无效"
            );
            ensure!(self.grants.len() < MAX_GRANTS, "委托表达到实现容量上限");
        }
        Ok(VerifiedDelegation {
            envelope,
            grant: state.signed.clone(),
            public_key: principal.public_key.clone(),
        })
    }
    pub(crate) fn child(
        &self,
        verified: &VerifiedDelegation,
        now: i64,
    ) -> Result<Option<SignedDelegationGrant>> {
        let DelegationCommand::Delegate {
            subject_id,
            permissions,
            expires_at_ms,
        } = &verified.envelope.command
        else {
            return Ok(None);
        };
        let parent = &verified.grant.grant;
        parent.validate_at(now)?;
        let ceiling = &self
            .principals
            .get(subject_id.as_str())
            .context("接收主体未登记")?
            .permissions;
        let permissions = parent
            .permissions
            .intersect(permissions)?
            .intersect(ceiling)?;
        let grant = DelegationGrant {
            version: 1,
            authority_id: self.authority_id.clone(),
            host_session_id: parent.host_session_id.clone(),
            grant_id: id("grant"),
            session_id: id("delegate-session"),
            parent_session_id: Some(parent.session_id.clone()),
            parent_grant_sha256: Some(grant_digest(parent)?),
            delegator_id: Some(parent.subject_id.clone()),
            subject_id: subject_id.clone(),
            target_id: parent.target_id.clone(),
            permissions,
            issued_at_ms: now,
            expires_at_ms: (*expires_at_ms).min(parent.expires_at_ms),
        };
        ensure!(
            !self.grants.contains_key(grant.grant_id.as_str()),
            "宿主授权标识碰撞"
        );
        Ok(Some(self.sign(grant)?))
    }
    /// 必须先持久记下认证接收事件，再消费序号并公开子授权；调用方只有一个串行宿主执行者。
    pub(crate) fn consume(
        &mut self,
        verified: &VerifiedDelegation,
        child: Option<SignedDelegationGrant>,
        now: i64,
    ) -> Result<()> {
        verified.envelope.validate_at(now)?;
        verified.grant.grant.validate_at(now)?;
        let state = self
            .grants
            .get_mut(verified.envelope.message.grant_id.as_str())
            .context("父委托失效")?;
        ensure!(
            state.last_sequence.checked_add(1) == Some(verified.envelope.message.sequence),
            "序号已被消费"
        );
        state.last_sequence = verified.envelope.message.sequence;
        if let Some(signed) = child {
            self.grants.insert(
                signed.grant.grant_id.to_string(),
                GrantState {
                    signed,
                    last_sequence: 0,
                },
            );
        }
        Ok(())
    }
    pub(crate) fn revalidate(
        &self,
        verified: &VerifiedDelegation,
        host: &str,
        now: i64,
    ) -> Result<()> {
        ensure!(
            self.host_session.as_ref().map(ValidatedId::as_str) == Some(host),
            "宿主会话已经变化"
        );
        verified.envelope.validate_at(now)?;
        verified.grant.grant.validate_at(now)?;
        let state = self
            .grants
            .get(verified.envelope.message.grant_id.as_str())
            .context("委托失效")?;
        ensure!(
            state.last_sequence == verified.envelope.message.sequence
                && state.signed == verified.grant,
            "当前消息或授权已被替换"
        );
        Ok(())
    }
}

pub(crate) fn tools() -> Vec<Value> {
    vec![crate::mcp::tool("delegation_send", "发送已签名的委托或隔离文件操作；每条消息绑定主体、父链、目标、权限、期限和序号，不能自报授权", json!({"type":"object","required":["message","command","signature"],"properties":{"message":{"type":"object"},"command":{"type":"object"},"signature":{"type":"string","minLength":128,"maxLength":128}},"additionalProperties":false}))]
}

#[cfg(test)]
#[path = "delegation_tests.rs"]
mod tests;
