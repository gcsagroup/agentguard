//! Local Pro entitlement store (no live payment provider wired yet).
//!
//! Activation uses an HMAC-style license token derived from a shared secret so
//! offline builds can validate Pro without calling a network billing API.
//! Optional local HTTP webhook receiver: [`http::serve_billing_webhook`].

mod http;

pub use http::{apply_file_to_store, serve_billing_webhook};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PlanTier {
    #[default]
    Free,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub plan: PlanTier,
    pub license_id: String,
    pub activated_at_ms: i64,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub features: EntitlementFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct EntitlementFeatures {
    pub unlimited_audit: bool,
    pub custom_rules: bool,
    pub enterprise_export: bool,
}

impl Entitlement {
    pub fn free() -> Self {
        Self {
            plan: PlanTier::Free,
            license_id: "free".into(),
            activated_at_ms: now_ms(),
            expires_at_ms: None,
            features: EntitlementFeatures::default(),
        }
    }

    pub fn is_active(&self) -> bool {
        match self.expires_at_ms {
            None => !matches!(self.plan, PlanTier::Free),
            Some(exp) => now_ms() <= exp && !matches!(self.plan, PlanTier::Free),
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn write_path(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(p) = path.as_ref().parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// `license_id:plan:hex_token` where token = sha256(secret || license_id || plan).
pub fn issue_license_token(secret: &str, license_id: &str, plan: PlanTier) -> String {
    let plan_s = match plan {
        PlanTier::Free => "free",
        PlanTier::Pro => "pro",
        PlanTier::Enterprise => "enterprise",
    };
    let digest = Sha256::digest(format!("{secret}|{license_id}|{plan_s}").as_bytes());
    format!("{license_id}:{plan_s}:{}", hex::encode(digest))
}

pub fn activate_license_token(secret: &str, token: &str) -> Result<Entitlement> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        bail!("license token must be license_id:plan:hex");
    }
    let (license_id, plan_s, hex_tok) = (parts[0], parts[1], parts[2]);
    let plan = match plan_s {
        "pro" => PlanTier::Pro,
        "enterprise" => PlanTier::Enterprise,
        "free" => PlanTier::Free,
        other => bail!("unknown plan {other}"),
    };
    let expected = issue_license_token(secret, license_id, plan.clone());
    let expected_hex = expected.split(':').nth(2).unwrap_or("");
    if expected_hex != hex_tok {
        bail!("invalid license token");
    }
    let features = match plan {
        PlanTier::Free => EntitlementFeatures::default(),
        PlanTier::Pro => EntitlementFeatures {
            unlimited_audit: true,
            custom_rules: true,
            enterprise_export: false,
        },
        PlanTier::Enterprise => EntitlementFeatures {
            unlimited_audit: true,
            custom_rules: true,
            enterprise_export: true,
        },
    };
    Ok(Entitlement {
        plan,
        license_id: license_id.into(),
        activated_at_ms: now_ms(),
        expires_at_ms: None,
        features,
    })
}

pub fn load_or_free(path: impl AsRef<Path>) -> Entitlement {
    Entitlement::from_path(path).unwrap_or_else(|_| Entitlement::free())
}

/// 授权门控:功能已授予**且**授权仍有效。
///
/// 在此之前没有任何地方读 features —— 授权是纯装饰的(计算了 plan 却不门控任何行为,
/// 第七轮复核发现)。这个方法是「真的门」的判据:Free / 过期 / 未授予该功能都返回 false。
impl Entitlement {
    pub fn allows_enterprise_export(&self) -> bool {
        self.is_active() && self.features.enterprise_export
    }
}

/// 加载授权:显式路径 > `AGENTGUARD_ENTITLEMENT` 环境变量 > 默认路径;都没有 → Free。
///
/// Free 不是错误,是「没买」。门控在调用点做(见 `allows_*`),这里只负责取到当前授权。
pub fn load_entitlement(explicit: Option<&Path>) -> Entitlement {
    if let Some(p) = explicit {
        return load_or_free(p);
    }
    if let Some(p) = std::env::var_os("AGENTGUARD_ENTITLEMENT") {
        return load_or_free(std::path::PathBuf::from(p));
    }
    if let Some(p) = default_entitlement_path() {
        if p.exists() {
            return load_or_free(p);
        }
    }
    Entitlement::free()
}

/// `~/.config/agentguard/entitlement.json`(存在才用)。
pub fn default_entitlement_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        std::path::PathBuf::from(home)
            .join(".config")
            .join("agentguard")
            .join("entitlement.json"),
    )
}

// ---- Webhook 认证:HMAC-SHA256(不引新依赖,用已有的 sha2 手写标准构造) ----

/// HMAC-SHA256(RFC 2104)。block size 64,key 超长先哈希。
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// 常数时间比较,避免定时侧信道。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

/// 给一个 body 算出 webhook 签名头值:`sha256=<hex>`。测试和签发方用它。
pub fn sign_webhook_body(secret: &str, body: &str) -> String {
    format!(
        "sha256={}",
        hex::encode(hmac_sha256(secret.as_bytes(), body.as_bytes()))
    )
}

/// 验证 webhook 签名头(`sha256=<hex>`,大小写不敏感的前缀)对 body 成立。
///
/// 缺头、格式错、对不上都返回 false。**没有签名就不是合法 webhook** —— 这条守卫存在的
/// 全部意义就是:一个匿名 POST 不能自铸 Enterprise 授权。
pub fn verify_webhook_signature(secret: &str, body: &str, header: Option<&str>) -> bool {
    let Some(h) = header else {
        return false;
    };
    let hex_sig = h.trim().strip_prefix("sha256=").unwrap_or_else(|| h.trim());
    let Ok(provided) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    let expected = hmac_sha256(secret.as_bytes(), body.as_bytes());
    ct_eq(&expected, &provided)
}

pub fn default_dev_secret() -> &'static str {
    // Dev-only; production should inject via env AGENTGUARD_LICENSE_SECRET.
    "agentguard-dev-secret-change-me"
}

pub fn resolve_secret() -> String {
    std::env::var("AGENTGUARD_LICENSE_SECRET").unwrap_or_else(|_| default_dev_secret().into())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Provider-agnostic purchase/refund webhook payload (Stripe-like).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingWebhookEvent {
    /// purchase | refund | entitlement.updated
    #[serde(rename = "type")]
    pub event_type: String,
    pub license_id: String,
    #[serde(default = "default_plan_pro")]
    pub plan: String,
    #[serde(default)]
    pub provider: Option<String>,
}

fn default_plan_pro() -> String {
    "pro".into()
}

/// Apply a billing webhook to the local entitlement store.
pub fn apply_webhook_event(
    event: &BillingWebhookEvent,
    store: impl AsRef<Path>,
) -> Result<Entitlement> {
    match event.event_type.as_str() {
        "purchase" | "entitlement.updated" | "checkout.session.completed" => {
            let plan = match event.plan.as_str() {
                "enterprise" => PlanTier::Enterprise,
                "free" => PlanTier::Free,
                _ => PlanTier::Pro,
            };
            let secret = resolve_secret();
            let token = issue_license_token(&secret, &event.license_id, plan);
            let ent = activate_license_token(&secret, &token)?;
            ent.write_path(store.as_ref())?;
            Ok(ent)
        }
        "refund" | "customer.subscription.deleted" => {
            let ent = Entitlement::free();
            ent.write_path(store.as_ref())?;
            Ok(ent)
        }
        other => bail!("unsupported webhook type: {other}"),
    }
}

pub fn apply_webhook_json(raw: &str, store: impl AsRef<Path>) -> Result<Entitlement> {
    let event: BillingWebhookEvent = serde_json::from_str(raw)?;
    apply_webhook_event(&event, store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_activate_pro() {
        let secret = "test-secret";
        let tok = issue_license_token(secret, "lic-1", PlanTier::Pro);
        let e = activate_license_token(secret, &tok).unwrap();
        assert!(e.is_active());
        assert!(e.features.unlimited_audit);
        assert!(!e.features.enterprise_export);
    }

    #[test]
    fn reject_tampered() {
        let secret = "test-secret";
        let tok = issue_license_token(secret, "lic-1", PlanTier::Pro);
        let bad = format!("{tok}x");
        assert!(activate_license_token(secret, &bad).is_err());
    }

    #[test]
    fn roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ent.json");
        let e = activate_license_token("s", &issue_license_token("s", "x", PlanTier::Enterprise))
            .unwrap();
        e.write_path(&path).unwrap();
        let loaded = Entitlement::from_path(&path).unwrap();
        assert_eq!(loaded.plan, PlanTier::Enterprise);
    }

    /// 授权门控的判据:只有**有效**的 Enterprise 授权才放行 enterprise_export。
    /// 这是「授权不再是装饰」的那条测试 —— Free / Pro / 过期都被拒。
    #[test]
    fn enterprise_export门控() {
        assert!(
            !Entitlement::free().allows_enterprise_export(),
            "Free 不该有 enterprise_export"
        );
        let pro =
            activate_license_token("s", &issue_license_token("s", "x", PlanTier::Pro)).unwrap();
        assert!(
            !pro.allows_enterprise_export(),
            "Pro 不含 enterprise_export"
        );
        let ent = activate_license_token("s", &issue_license_token("s", "x", PlanTier::Enterprise))
            .unwrap();
        assert!(ent.allows_enterprise_export(), "Enterprise 应当放行");
        // 过期的 Enterprise 也拒。
        let mut expired = ent.clone();
        expired.expires_at_ms = Some(0);
        assert!(!expired.allows_enterprise_export(), "过期授权不该放行");
    }

    /// load_entitlement 显式路径读得到已写入的 Enterprise 授权。
    #[test]
    fn load_entitlement_显式路径() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ent.json");
        let ent = activate_license_token("s", &issue_license_token("s", "x", PlanTier::Enterprise))
            .unwrap();
        ent.write_path(&p).unwrap();
        assert!(load_entitlement(Some(&p)).allows_enterprise_export());
    }

    #[test]
    fn webhook_purchase_and_refund() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ent.json");
        let raw = r#"{"type":"purchase","license_id":"wh-1","plan":"pro","provider":"stripe-sim"}"#;
        let e = apply_webhook_json(raw, &path).unwrap();
        assert!(e.is_active());
        let refund = r#"{"type":"refund","license_id":"wh-1","plan":"pro"}"#;
        let e2 = apply_webhook_json(refund, &path).unwrap();
        assert!(!e2.is_active());
        assert_eq!(e2.plan, PlanTier::Free);
    }
}
