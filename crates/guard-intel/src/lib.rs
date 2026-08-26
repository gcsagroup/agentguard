//! Threat intel bundles with Ed25519 signatures (sha256: digest still accepted for legacy).

mod crypto;
mod update;

pub use crypto::{generate_keypair, sign_digest, verify_digest, KeyPair, PublicKeyBytes};
pub use update::{
    apply_update_bytes, fetch_bytes, fetch_from_manifest, is_newer_version, persist_bundle,
    UpdateManifest, UpdateResult,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntelError {
    #[error("parse intel bundle: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("signature verification failed")]
    BadSignature,
    #[error("bundle integrity mismatch")]
    Integrity,
    #[error("crypto: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBundle {
    pub version: String,
    /// `ed25519:<base64>` or legacy `sha256:<hex>`
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub malicious_domains: Vec<String>,
    #[serde(default)]
    pub deeplink_patterns: Vec<String>,
    #[serde(default)]
    pub injection_patterns: Vec<String>,
    #[serde(default)]
    pub overlay_markers: Vec<String>,
}

impl Default for ThreatBundle {
    fn default() -> Self {
        Self {
            version: "0.0.0".into(),
            signature: None,
            malicious_domains: vec!["evil.example".into(), "phish-agent.test".into()],
            deeplink_patterns: vec!["intent://".into(), "myapp://transfer".into()],
            injection_patterns: vec![
                "ignore previous instructions".into(),
                "忽略之前的指令".into(),
                "system override".into(),
                "<!-- agentguard:poison -->".into(),
            ],
            overlay_markers: vec![
                "[AG_INVISIBLE_TEXT]".into(),
                "[AG_TRANSPARENT_OVERLAY]".into(),
                "[AG_SCREENSHOT_TAMPER]".into(),
            ],
        }
    }
}

impl ThreatBundle {
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, IntelError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn write_path(&self, path: impl AsRef<std::path::Path>) -> Result<(), IntelError> {
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(path, raw)?;
        Ok(())
    }

    /// Canonical bytes used for hashing / signing (signature field cleared).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).unwrap_or_default()
    }

    pub fn content_digest(&self) -> String {
        let hash = Sha256::digest(self.signing_bytes());
        hex::encode(hash)
    }

    pub fn sign_ed25519(&mut self, keypair: &KeyPair) -> Result<(), IntelError> {
        let digest = Sha256::digest(self.signing_bytes());
        let sig = sign_digest(keypair, &digest).map_err(IntelError::Crypto)?;
        self.signature = Some(format!("ed25519:{sig}"));
        Ok(())
    }

    /// 验证签名。
    ///
    /// **给了 `public_key` = 调用方要的是「真实性」(authenticity),不只是「完整性」。**
    ///
    /// 这里以前有一个签名算法降级绕过:`sha256:` 分支只把签名和自算摘要比一下、**完全不看
    /// `public_key`**。可 sha256 只证明字节没损坏,证明不了字节出自谁——谁能提供 bundle 字节
    /// 谁就能重算那个摘要。于是攻击者把一个 Ed25519 包的签名换成 `sha256:<自算>`,即便公钥已
    /// 钉扎也「验过」。所以现在:**一旦调用方给了公钥,`sha256:` 和未签名一律不够,直接拒。**
    /// 只有 `public_key == None` 的软加载路径(开发/完整性自检)才接受它们。
    pub fn verify(&self, public_key: Option<&PublicKeyBytes>) -> Result<(), IntelError> {
        match &self.signature {
            None => {
                // 未签名的包无法被认证。要认证(给了公钥)就拒;软加载(没给)才接受。
                if public_key.is_some() {
                    return Err(IntelError::BadSignature);
                }
                Ok(())
            }
            Some(sig) if sig.starts_with("ed25519:") => {
                let pk = public_key.ok_or(IntelError::BadSignature)?;
                let b64 = &sig["ed25519:".len()..];
                let digest = Sha256::digest(self.signing_bytes());
                verify_digest(pk, &digest, b64).map_err(|_| IntelError::BadSignature)
            }
            Some(sig) if sig.starts_with("sha256:") => {
                // 只是完整性,不是真实性。要认证时它一律不够——降级绕过被堵在这里。
                if public_key.is_some() {
                    return Err(IntelError::BadSignature);
                }
                let expected = format!("sha256:{}", self.content_digest());
                if sig == &expected {
                    Ok(())
                } else {
                    Err(IntelError::Integrity)
                }
            }
            Some(_) => Err(IntelError::BadSignature),
        }
    }

    /// Backward-compatible alias.
    pub fn verify_integrity(&self) -> Result<(), IntelError> {
        self.verify(None)
    }

    pub fn matches_injection(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        self.injection_patterns
            .iter()
            .any(|p| lower.contains(&p.to_lowercase()))
            || self.overlay_markers.iter().any(|m| text.contains(m))
    }

    pub fn is_malicious_domain(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        self.malicious_domains
            .iter()
            .any(|d| host == d.to_lowercase() || host.ends_with(&format!(".{}", d.to_lowercase())))
    }

    pub fn matches_deeplink(&self, text: &str) -> bool {
        self.deeplink_patterns.iter().any(|p| text.contains(p))
    }
}

/// 软加载:**仅供开发 / CLI 本地评测**。不认证 Ed25519。
///
/// 生产消费者(`api-serve`、桌面壳)一律走 `load_release` 并给公钥——见 `load_release`。
/// 这个函数曾被 `api-serve` 用作情报来源,而它的 Ed25519 分支是个静默空操作(接受任何
/// 未验证甚至伪造签名的包),那是那条 HTTP 守卫「从不验签」的根源。现在:
///
/// * 未签名 / `sha256:` —— 做完整性自检(`verify(None)`),这是开发期的合理便利;
/// * `ed25519:` —— **无法在没有公钥的路径上认证**,所以照旧加载(否则本地评测拿不到磁盘上的
///   包),但**打一条显式告警**说明它未经验证。不再是静默的——但每个进程只打一次,免得
///   每条 CLI 命令都刷屏。
pub fn load_or_default(path: impl AsRef<std::path::Path>) -> Result<ThreatBundle> {
    let path = path.as_ref();
    if path.exists() {
        let b =
            ThreatBundle::from_path(path).with_context(|| format!("load {}", path.display()))?;
        match &b.signature {
            None => {}
            Some(sig) if sig.starts_with("sha256:") => b.verify(None)?,
            Some(sig) if sig.starts_with("ed25519:") => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    eprintln!(
                        "agentguard: 警告:{} 是 ed25519 签名,但 load_or_default 没有公钥可验 —— \
                         以**未经验证**的方式加载(仅开发/评测用)。生产请走 load_release + 公钥。",
                        path.display()
                    );
                });
            }
            Some(_) => return Err(anyhow::anyhow!("unsupported intel signature scheme")),
        }
        Ok(b)
    } else {
        Ok(ThreatBundle::default())
    }
}

/// Release / production loader: Ed25519 bundles **must** verify against pubkey.
///
/// - Missing file → empty default (safe)
/// - `ed25519:` signature without valid pubkey → **error** (fail-closed)
/// - Legacy `sha256:` still integrity-checked
pub fn load_release(
    path: impl AsRef<std::path::Path>,
    public_key_path: impl AsRef<std::path::Path>,
) -> Result<ThreatBundle> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(ThreatBundle::default());
    }
    let b = ThreatBundle::from_path(path).with_context(|| format!("load {}", path.display()))?;
    let pk = PublicKeyBytes::from_path(public_key_path.as_ref())
        .map_err(|e| anyhow::anyhow!("load pubkey: {e}"))?;
    match &b.signature {
        None => {
            // Unsigned intel is rejected in release path.
            bail!("release intel requires a signature (unsigned bundle rejected)");
        }
        Some(sig) if sig.starts_with("ed25519:") => {
            b.verify(Some(&pk))?;
            Ok(b)
        }
        Some(sig) if sig.starts_with("sha256:") => {
            // 发布路径**不接受** sha256:它只有完整性、没有真实性(攻击者能重算),
            // 而 `load_release` 的全部意义就是「用公钥认证」。以前这里 `b.verify(None)`
            // 把它降级成完整性自检 —— 正是那个降级绕过。传输/开发期的 legacy 支持留在
            // 软加载路径(`load_or_default`,pubkey=None)。
            bail!(
                "release intel rejects legacy sha256 signature (integrity only, not \
                 authenticity); sign the bundle with ed25519"
            );
        }
        Some(_) => bail!("unsupported intel signature scheme"),
    }
}

pub fn load_verified(
    path: impl AsRef<std::path::Path>,
    public_key_path: Option<impl AsRef<std::path::Path>>,
) -> Result<ThreatBundle> {
    let b = ThreatBundle::from_path(path)?;
    let pk = if let Some(p) = public_key_path {
        Some(PublicKeyBytes::from_path(p).map_err(|e| anyhow::anyhow!(e))?)
    } else {
        None
    };
    b.verify(pk.as_ref())?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_injection() {
        let b = ThreatBundle::default();
        assert!(b.matches_injection("Please ignore previous instructions now"));
        assert!(b.matches_injection("[AG_TRANSPARENT_OVERLAY]"));
        assert!(!b.matches_injection("hello world"));
    }

    #[test]
    fn legacy_sha256_integrity() {
        let mut b = ThreatBundle {
            version: "2026.07.30".into(),
            ..Default::default()
        };
        let digest = b.content_digest();
        b.signature = Some(format!("sha256:{digest}"));
        b.verify(None).unwrap();
        b.signature = Some("sha256:deadbeef".into());
        assert!(b.verify(None).is_err());
    }

    #[test]
    fn ed25519_sign_verify() {
        let kp = generate_keypair();
        let mut b = ThreatBundle {
            version: "2026.08.01".into(),
            ..Default::default()
        };
        b.malicious_domains.push("evil.example".into());
        b.sign_ed25519(&kp).unwrap();
        b.verify(Some(&kp.public)).unwrap();
        // Tamper
        b.version = "tampered".into();
        assert!(b.verify(Some(&kp.public)).is_err());
    }

    #[test]
    fn load_release_rejects_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("b.json");
        let pk = dir.path().join("pk.hex");
        let kp = generate_keypair();
        std::fs::write(&pk, kp.public.to_hex()).unwrap();
        let b = ThreatBundle::default();
        std::fs::write(&bundle, serde_json::to_string(&b).unwrap()).unwrap();
        assert!(load_release(&bundle, &pk).is_err());
    }

    /// **签名算法降级绕过**:把一个内容拿去做 `sha256:<自算>`,在**给了公钥**时必须被拒。
    /// 没有这条,攻击者把 ed25519 签名换成 sha256 自摘要就绕过了公钥钉扎。
    #[test]
    fn 有公钥时拒绝sha256冒充签名() {
        let kp = generate_keypair();
        let mut b = ThreatBundle {
            version: "2026.08.01".into(),
            ..Default::default()
        };
        b.malicious_domains.push("attacker-injected.example".into());
        // 攻击者能做的:算出内容摘要,当成 sha256 「签名」。
        b.signature = Some(format!("sha256:{}", b.content_digest()));
        // 完整性自检(无公钥)会过——这是它唯一还成立的语义。
        b.verify(None).unwrap();
        // 但一旦要认证(给公钥),sha256 一律不够。
        assert!(matches!(
            b.verify(Some(&kp.public)),
            Err(IntelError::BadSignature)
        ));
    }

    /// 发布加载器不接受 sha256 降级(即便摘要自洽)。
    #[test]
    fn load_release拒绝sha256降级() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("b.json");
        let pk = dir.path().join("pk.hex");
        let kp = generate_keypair();
        std::fs::write(&pk, kp.public.to_hex()).unwrap();
        let mut b = ThreatBundle {
            version: "2026.08.01".into(),
            ..Default::default()
        };
        b.signature = Some(format!("sha256:{}", b.content_digest()));
        std::fs::write(&bundle, serde_json::to_string(&b).unwrap()).unwrap();
        let err = load_release(&bundle, &pk).unwrap_err().to_string();
        assert!(err.contains("sha256"), "{err}");
    }

    /// 未签名的包在**给了公钥**时也必须被拒(未签名 = 无法认证)。
    #[test]
    fn 有公钥时拒绝未签名() {
        let kp = generate_keypair();
        let b = ThreatBundle {
            version: "2026.08.01".into(),
            signature: None,
            ..Default::default()
        };
        assert!(b.verify(Some(&kp.public)).is_err());
        // 软加载(无公钥)仍接受未签名。
        assert!(b.verify(None).is_ok());
    }

    /// 合法 ed25519 包仍然验得过(修复没有误伤正常路径)。
    #[test]
    fn 合法ed25519仍然通过() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("b.json");
        let pk = dir.path().join("pk.hex");
        let kp = generate_keypair();
        std::fs::write(&pk, kp.public.to_hex()).unwrap();
        let mut b = ThreatBundle {
            version: "2026.08.01".into(),
            ..Default::default()
        };
        b.sign_ed25519(&kp).unwrap();
        b.write_path(&bundle).unwrap();
        assert!(load_release(&bundle, &pk).is_ok());
    }
}
