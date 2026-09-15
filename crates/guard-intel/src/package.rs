//! 知识资料与可执行规则包使用不同类型；签名只证明签发身份，不授予指令权限。
//!
//! 更新序号、兼容版本、灰度范围、撤销和恢复目标全部纳入同一个 Ed25519 签名。
//! 此模块只校验格式和真实性；持久防回滚和实际激活由包存储层负责。

mod json;
pub mod store;

use crate::{
    knowledge::KnowledgeCatalog, sign_digest, verify_digest, KeyPair, PublicKeyBytes, ThreatBundle,
};
use anyhow::{ensure, Context, Result};
use guard_schema::RuleSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};

pub const PACKAGE_READER_VERSION: u32 = 1;
pub const MAX_RELEASE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_UPDATE_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    Knowledge,
    Rules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub kind: PackageKind,
    pub version: String,
    pub content: Value,
}

/// 包内规则和检测情报共同决定行为；知识库目录不在此类型中。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePayload {
    pub rules: RuleSet,
    pub indicators: ThreatBundle,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub min_reader: u32,
    pub max_reader: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    /// 0～10000；宿主固定设备标识的 SHA-256 分桶，不接受模型选择分组。
    pub basis_points: u16,
    /// 同一批推广复用盐，使提高比例时保留已经选中的设备。
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Install {
        package: Package,
    },
    Revoke {
        digests: Vec<String>,
        reason: String,
    },
    Recover {
        digest: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub schema_version: u32,
    pub stream: String,
    pub kind: PackageKind,
    pub sequence: u64,
    /// 单调安全代次；受控恢复也不能低于已接受的安全下限。
    pub security_epoch: u64,
    pub compatibility: Compatibility,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub rollout: Rollout,
    pub operation: Operation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub release: Release,
    pub signature: String,
}

/// 无公开构造器，调用方必须用自己固定的公钥验证；不能由包内字段替换信任根。
pub struct VerifiedRelease {
    signed: SignedRelease,
    signer_sha256: String,
    release_sha256: String,
}

impl Package {
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&domain_bytes("content", self)?))
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            version_valid(&self.version),
            "包版本必须是无前导零的三段数字"
        );
        match self.kind {
            PackageKind::Knowledge => {
                let catalog: KnowledgeCatalog = exact_value(&self.content)?;
                ensure!(
                    catalog.validate().is_empty(),
                    "知识库内容未通过结构和引用校验"
                );
                ensure!(
                    catalog.catalog_version == self.version,
                    "知识库版本与包版本不一致"
                );
            }
            PackageKind::Rules => {
                let payload: RulePayload = exact_value(&self.content)?;
                // 旧规则和情报类型允许额外字段；包入口必须拒绝，不能验签后静默丢弃。
                ensure!(
                    payload.indicators.signature.is_none(),
                    "规则包不接受嵌套情报签名"
                );
                ensure!(
                    !payload.rules.version.trim().is_empty()
                        && !payload.indicators.version.trim().is_empty(),
                    "规则与情报版本不能为空"
                );
                ensure!(
                    !payload.rules.rules.is_empty() && payload.rules.rules.len() <= 4096,
                    "规则数量无效"
                );
                let mut ids = BTreeSet::new();
                for rule in &payload.rules.rules {
                    ensure!(
                        identifier(&rule.id, 128) && ids.insert(&rule.id),
                        "规则编号无效或重复"
                    );
                    ensure!(!rule.name.trim().is_empty(), "规则显示名称不能为空");
                    ensure!(
                        rule.match_any_text.iter().all(|s| !s.is_empty()),
                        "规则文本条件不能为空"
                    );
                }
            }
        }
        Ok(())
    }
}

impl Release {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RELEASE_BYTES,
            "待签发布为空或超过大小上限"
        );
        let release: Self = serde_json::from_value(json::strict(bytes)?)?;
        release.validate()?;
        Ok(release)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && identifier(&self.stream, 64),
            "包协议版本或更新流无效"
        );
        ensure!(
            self.sequence > 0
                && self.sequence <= i64::MAX as u64
                && self.security_epoch > 0
                && self.security_epoch <= i64::MAX as u64,
            "更新序号或安全代次无效"
        );
        ensure!(
            self.compatibility.min_reader > 0
                && self.compatibility.min_reader <= self.compatibility.max_reader,
            "兼容范围无效"
        );
        ensure!(
            self.issued_at_ms > 0
                && self.expires_at_ms > self.issued_at_ms
                && self.expires_at_ms - self.issued_at_ms <= MAX_UPDATE_LIFETIME_MS,
            "更新有效期无效或超过七天"
        );
        ensure!(
            self.rollout.basis_points <= 10000 && identifier(&self.rollout.salt, 64),
            "灰度范围无效"
        );
        match &self.operation {
            Operation::Install { package } => {
                ensure!(package.kind == self.kind, "包类型与更新流类型不一致");
                package.validate()?;
            }
            Operation::Revoke { digests, reason } => {
                ensure!(self.rollout.basis_points == 10000, "撤销必须覆盖所有分组");
                ensure!(
                    !digests.is_empty()
                        && digests.len() <= 128
                        && !reason.trim().is_empty()
                        && reason.len() <= 2048,
                    "撤销清单或原因无效"
                );
                let mut seen = BTreeSet::new();
                ensure!(
                    digests.iter().all(|d| sha_valid(d) && seen.insert(d)),
                    "撤销摘要无效或重复"
                );
            }
            Operation::Recover { digest, reason } => {
                ensure!(self.rollout.basis_points == 10000, "恢复必须覆盖所有分组");
                ensure!(
                    sha_valid(digest) && !reason.trim().is_empty() && reason.len() <= 2048,
                    "恢复摘要或原因无效"
                );
            }
        }
        Ok(())
    }

    /// 时间和读取协议由可信宿主提供；加载已经激活的缓存不能重新把过期更新当新更新。
    pub fn check_update_context(&self, now_ms: i64, reader: u32) -> Result<()> {
        ensure!(
            now_ms >= self.issued_at_ms && now_ms < self.expires_at_ms,
            "更新尚未生效或已过期"
        );
        ensure!(
            (self.compatibility.min_reader..=self.compatibility.max_reader).contains(&reader),
            "当前读取协议与包不兼容"
        );
        Ok(())
    }

    pub fn selected(&self, host_device_id: &str) -> Result<bool> {
        ensure!(
            !host_device_id.is_empty() && host_device_id.len() <= 256,
            "宿主设备标识无效"
        );
        let bytes = domain_bytes(
            "rollout",
            &(&self.stream, &self.rollout.salt, host_device_id),
        )?;
        let hash = Sha256::digest(bytes);
        let slot = u32::from_be_bytes(hash[..4].try_into().expect("固定摘要长度")) % 10000;
        Ok(slot < u32::from(self.rollout.basis_points))
    }
}

impl SignedRelease {
    pub fn sign(release: Release, keypair: &KeyPair) -> Result<Self> {
        release.validate()?;
        let hash = Sha256::digest(domain_bytes("release", &release)?);
        let signature = format!(
            "ed25519:{}",
            sign_digest(keypair, &hash).map_err(anyhow::Error::msg)?
        );
        let signed = Self { release, signature };
        ensure!(
            serde_json::to_vec(&signed)?.len() <= MAX_RELEASE_BYTES,
            "签名包超过大小上限"
        );
        Ok(signed)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RELEASE_BYTES,
            "签名包为空或超过大小上限"
        );
        let value = json::strict(bytes)?;
        let signed: Self = serde_json::from_value(value).context("签名包字段无效")?;
        signed.release.validate()?;
        Ok(signed)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((MAX_RELEASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn verify(self, trusted_key: &PublicKeyBytes) -> Result<VerifiedRelease> {
        self.release.validate()?;
        ensure!(
            serde_json::to_vec(&self)?.len() <= MAX_RELEASE_BYTES,
            "签名包超过大小上限"
        );
        let signature = self
            .signature
            .strip_prefix("ed25519:")
            .context("签名包只接受 Ed25519")?;
        let hash = Sha256::digest(domain_bytes("release", &self.release)?);
        verify_digest(trusted_key, &hash, signature)
            .map_err(|_| anyhow::anyhow!("签名包验签失败"))?;
        Ok(VerifiedRelease {
            signed: self,
            signer_sha256: digest(&trusted_key.0),
            release_sha256: hex::encode(hash),
        })
    }
}

impl VerifiedRelease {
    pub fn release(&self) -> &Release {
        &self.signed.release
    }
    pub fn signer_sha256(&self) -> &str {
        &self.signer_sha256
    }
    pub fn release_sha256(&self) -> &str {
        &self.release_sha256
    }
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.signed)?)
    }

    /// 知识库即使验签成功也不能转成可执行规则。
    pub fn rule_payload(&self) -> Result<RulePayload> {
        match &self.release().operation {
            Operation::Install { package } if package.kind == PackageKind::Rules => {
                exact_value(&package.content)
            }
            _ => anyhow::bail!("这不是经过验证的规则安装包"),
        }
    }
}

fn exact_value<T: DeserializeOwned + Serialize>(value: &Value) -> Result<T> {
    let typed: T = serde_json::from_value(value.clone()).context("包内容类型无效")?;
    ensure!(
        serde_json::to_value(&typed)? == *value,
        "包内容包含未知、遗漏或非规范字段"
    );
    Ok(typed)
}
fn domain_bytes(domain: &str, value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = format!("agentguard.package-{domain}.v1\0").into_bytes();
    // JSON 对象显式递归排序，不依赖调用方构造顺序。
    bytes.extend(json::canonical(&serde_json::to_value(value)?)?);
    Ok(bytes)
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn sha_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn version_valid(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && (p.len() == 1 || !p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok()
        })
}
