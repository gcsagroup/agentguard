//! Enterprise / multi-device policy sync POC (local file + optional HTTP pull).
//!
//! # 策略同步是一条入站信任边界(第七轮复核发现 11)
//!
//! `DevicePolicy` 携带安全开关(`require_confirm_critical`、`block_malicious_domains`、
//! `allowed_agents`)。这条通道以前**没有任何认证或完整性**:裸 http 明文可拉、`read_to_end`
//! 无上限、解析完就返回。一个 MITM 或恶意策略主机能静默下推一份被削弱的策略。
//!
//! 现在:
//! * [`pull_policy_verified`] 是推荐的生产路径 —— 要求一份分离的 Ed25519 签名
//!   (`<源>.sig`,签的是策略字节的 SHA-256),用带外机构公钥验证,验不过就拒。
//! * 明文 `http://` **默认被拒**(可被 MITM);用 `https://` 或 `file://`。
//! * 响应/文件有大小上限([`MAX_POLICY_BYTES`]),不再无上限读。
//! * [`pull_policy`](未认证)保留给**本地/开发**用,并如实标注它不认证。

use anyhow::{bail, Context, Result};
use guard_intel::{sign_digest, verify_digest, KeyPair, PublicKeyBytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// 策略字节的上限:1 MiB。一份设备策略是几十行 YAML,给到 1 MiB 已经是天文数字;
/// 上限存在是为了让一个恶意主机不能用一个无限响应体把内存吃光。
pub const MAX_POLICY_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePolicy {
    pub policy_id: String,
    pub version: String,
    #[serde(default)]
    pub require_confirm_critical: bool,
    #[serde(default)]
    pub block_malicious_domains: bool,
    #[serde(default)]
    pub pro_features: ProFeatures,
    #[serde(default)]
    pub allowed_agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProFeatures {
    #[serde(default)]
    pub unlimited_audit: bool,
    #[serde(default)]
    pub custom_rules: bool,
    #[serde(default)]
    pub enterprise_export: bool,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        Self {
            policy_id: "standard".into(),
            version: "1.0.0".into(),
            require_confirm_critical: true,
            block_malicious_domains: true,
            pro_features: ProFeatures::default(),
            allowed_agents: vec![],
        }
    }
}

impl DevicePolicy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        Ok(serde_yaml::from_str(&raw)?)
    }

    pub fn write_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let raw = serde_yaml::to_string(self)?;
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, raw)?;
        Ok(())
    }

    pub fn is_pro(&self) -> bool {
        self.pro_features.unlimited_audit
            || self.pro_features.custom_rules
            || self.pro_features.enterprise_export
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub latest_version: String,
    pub policy_url: String,
}

/// 读一个来源(本地路径 / `file://` / `https://`)的字节,**拒明文 http、限大小**。
fn read_source(url_or_path: &str) -> Result<Vec<u8>> {
    if url_or_path.starts_with("http://") {
        bail!(
            "拒绝用明文 http:// 拉策略 {url_or_path}:它可被 MITM 下推一份降级策略。\
             用 https:// 或 file://。"
        );
    }
    if url_or_path.starts_with("https://") {
        let resp = ureq::get(url_or_path)
            .call()
            .with_context(|| format!("GET {url_or_path}"))?;
        let mut buf = Vec::new();
        // take(N+1) 后再判:超限的响应体在读满上限就停,不会先把整个吃进内存。
        resp.into_reader()
            .take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_POLICY_BYTES {
            bail!("策略响应超过 {MAX_POLICY_BYTES} 字节上限");
        }
        Ok(buf)
    } else {
        let path = url_or_path.strip_prefix("file://").unwrap_or(url_or_path);
        let meta = std::fs::metadata(path).with_context(|| format!("stat 策略文件 {path}"))?;
        if meta.len() > MAX_POLICY_BYTES {
            bail!("策略文件 {path} 超过 {MAX_POLICY_BYTES} 字节上限");
        }
        Ok(std::fs::read(path)?)
    }
}

fn parse_policy(bytes: &[u8]) -> Result<DevicePolicy> {
    let text = std::str::from_utf8(bytes).context("策略不是 UTF-8")?;
    if text.trim_start().starts_with('{') {
        Ok(serde_json::from_str(text)?)
    } else {
        Ok(serde_yaml::from_str(text)?)
    }
}

/// 给策略字节算一份分离签名(`sign_digest` over SHA-256)。签发方 / 测试用。
pub fn sign_policy(bytes: &[u8], keypair: &KeyPair) -> Result<String> {
    sign_digest(keypair, &Sha256::digest(bytes)).map_err(|e| anyhow::anyhow!(e))
}

/// 验证策略字节的分离签名。缺签名 / 对不上都是错误。
pub fn verify_policy(bytes: &[u8], sig_b64: &str, pubkey: &PublicKeyBytes) -> Result<()> {
    verify_digest(pubkey, &Sha256::digest(bytes), sig_b64)
        .map_err(|e| anyhow::anyhow!("策略签名验证失败:{e}"))
}

/// **未认证**地拉策略。仅本地 / 开发用 —— 不验证任何签名。生产走 [`pull_policy_verified`]。
///
/// 仍然拒明文 http、限大小(那两条和认证无关,是任何来源都该有的下限)。
pub fn pull_policy(url_or_path: &str) -> Result<DevicePolicy> {
    parse_policy(&read_source(url_or_path)?)
}

/// **已认证**地拉策略:要求 `<源>.sig` 分离签名,用 `pubkey` 验证后才解析。
///
/// 这是生产 / 企业下发该走的路。签名对不上、`.sig` 拉不到,都拒绝 —— 一份没验过的策略
/// 不会被当真。
pub fn pull_policy_verified(url_or_path: &str, pubkey: &PublicKeyBytes) -> Result<DevicePolicy> {
    let bytes = read_source(url_or_path)?;
    let sig_src = format!("{url_or_path}.sig");
    let sig_bytes = read_source(&sig_src)
        .with_context(|| format!("读策略分离签名 {sig_src}(已认证拉取要求它存在)"))?;
    let sig_b64 = std::str::from_utf8(&sig_bytes)
        .context("签名不是 UTF-8")?
        .trim()
        .to_string();
    verify_policy(&bytes, &sig_b64, pubkey)?;
    parse_policy(&bytes)
}

/// 未认证同步到本地缓存(仅本地 / 开发)。生产用 [`sync_to_cache_verified`]。
pub fn sync_to_cache(url_or_path: &str, cache: impl AsRef<Path>) -> Result<DevicePolicy> {
    let policy = pull_policy(url_or_path)?;
    policy.write_path(cache.as_ref())?;
    Ok(policy)
}

/// 已认证同步到本地缓存。
pub fn sync_to_cache_verified(
    url_or_path: &str,
    pubkey: &PublicKeyBytes,
    cache: impl AsRef<Path>,
) -> Result<DevicePolicy> {
    let policy = pull_policy_verified(url_or_path, pubkey)?;
    policy.write_path(cache.as_ref())?;
    Ok(policy)
}

pub fn default_cache_path() -> PathBuf {
    PathBuf::from("policies/device-cache.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        let mut p = DevicePolicy::default();
        p.pro_features.unlimited_audit = true;
        p.write_path(&path).unwrap();
        let loaded = DevicePolicy::from_path(&path).unwrap();
        assert!(loaded.is_pro());
    }

    #[test]
    fn pull_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote.yaml");
        let p = DevicePolicy {
            policy_id: "corp".into(),
            version: "2.0.0".into(),
            ..DevicePolicy::default()
        };
        p.write_path(&path).unwrap();
        let got = pull_policy(&path.to_string_lossy()).unwrap();
        assert_eq!(got.policy_id, "corp");
    }

    /// 明文 http:// 被拒(可被 MITM 下推降级策略)。
    #[test]
    fn 明文http被拒() {
        let err = pull_policy("http://policy.corp.example/p.yaml").unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
    }

    /// 已认证拉取:正确签名过,篡改被拒,缺签名被拒。
    #[test]
    fn 已认证拉取验证分离签名() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        let sigpath = dir.path().join("p.yaml.sig");
        let p = DevicePolicy {
            policy_id: "corp".into(),
            ..DevicePolicy::default()
        };
        p.write_path(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let kp = guard_intel::generate_keypair();

        // 缺 .sig → 拒。
        assert!(pull_policy_verified(&path.to_string_lossy(), &kp.public).is_err());

        // 正确签名 → 过。
        std::fs::write(&sigpath, sign_policy(&bytes, &kp).unwrap()).unwrap();
        let got = pull_policy_verified(&path.to_string_lossy(), &kp.public).unwrap();
        assert_eq!(got.policy_id, "corp");

        // 换一把公钥(冒充签发方)→ 拒。
        let other = guard_intel::generate_keypair();
        assert!(pull_policy_verified(&path.to_string_lossy(), &other.public).is_err());

        // 策略被篡改(签名没跟着变)→ 拒。
        let mut tampered = p.clone();
        tampered.require_confirm_critical = false;
        tampered.write_path(&path).unwrap();
        assert!(
            pull_policy_verified(&path.to_string_lossy(), &kp.public).is_err(),
            "篡改后的策略必须验不过"
        );
    }

    /// 超过大小上限的文件被拒。
    #[test]
    fn 超大策略被拒() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.yaml");
        std::fs::write(&path, vec![b'#'; (MAX_POLICY_BYTES + 10) as usize]).unwrap();
        assert!(pull_policy(&path.to_string_lossy()).is_err());
    }
}
