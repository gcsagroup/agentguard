//! Local entitlement store.
//!
//! 两档来源(真机报告 P2-7):
//! * **商业边界**:厂商 Ed25519 签名的授权([`license`] 模块)。客户端只带公钥,签不出任何东西;
//!   必须有到期日、到期后 7 天离线宽限、厂商签名的撤销名单。只有这一档解锁企业功能。
//! * **演示档**:HMAC 令牌(`issue_license_token` / `activate_license_token`,共享秘密写在源码里)
//!   与本地 webhook 接收器。以前它们被当成边界用——本地 CLI 一条命令就能给自己签 Enterprise。
//!   现在它们照常工作,但落库的授权带 `source = dev_hmac / webhook`,`allows_enterprise_export()`
//!   对它们永远为 false。演示还能演示,只是不再被当成钱。
//!
//! Optional local HTTP webhook receiver: [`http::serve_billing_webhook`].

mod http;
pub mod license;

pub use http::{apply_file_to_store, serve_billing_webhook};
pub use license::{
    activate_signed_token, LicenseClaims, LicenseSigningKey, LicenseStatus, LicenseVerifyKey,
    RevocationList, RevokedLicense, SignedLicense, FIXTURE_PUBLIC_KEY_HEX, FIXTURE_SECRET_KEY_HEX,
    OFFLINE_GRACE_MS, TOKEN_PREFIX,
};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
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
    /// 这份授权从哪来——决定它是不是商业边界。老文件没有这个字段:按 `Legacy` 读,等同演示档。
    #[serde(default)]
    pub source: EntitlementSource,
    /// 签名授权的 serial(续期递增);其他来源为 0。
    #[serde(default)]
    pub serial: u64,
}

/// 授权的来源。只有 `Signed`(且公钥不是仓库夹具)是商业边界。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EntitlementSource {
    /// 没买。
    #[default]
    Free,
    /// 厂商 Ed25519 签名,用配置的(非夹具)公钥验过。`in_grace`:已到期但在离线宽限内。
    Signed { key_id: String, in_grace: bool },
    /// 签名有效但公钥是仓库自带的公开夹具——演示档。
    SignedByFixture,
    /// HMAC 令牌(共享秘密写在源码里)——演示档。
    DevHmac,
    /// 本地 webhook 接收器(共享秘密)——演示档。
    Webhook,
    /// 签名授权已被厂商撤销名单撤销;plan 已落回 Free,留下为什么。
    Revoked { license_id: String },
    /// 签名授权已过期且过了宽限;plan 已落回 Free。
    Expired { license_id: String },
    /// P2-7 之前写的文件,没有 source 字段。等同演示档。
    Legacy,
}

impl EntitlementSource {
    pub fn is_commercial(&self) -> bool {
        matches!(self, Self::Signed { .. })
    }

    /// 给 UI / CLI 的一句人话。
    pub fn describe(&self) -> String {
        match self {
            Self::Free => "free — nothing purchased".into(),
            Self::Signed { key_id, in_grace: false } => {
                format!("vendor-signed license (key {key_id})")
            }
            Self::Signed { key_id, in_grace: true } => format!(
                "vendor-signed license (key {key_id}) — EXPIRED, in the {}-day offline grace period",
                license::OFFLINE_GRACE_MS / 86_400_000
            ),
            Self::SignedByFixture => {
                "DEMO — signed with the repository's public fixture key; unlocks nothing commercial".into()
            }
            Self::DevHmac => {
                "DEMO — HMAC dev token (shared secret in source); unlocks nothing commercial".into()
            }
            Self::Webhook => {
                "DEMO — local webhook receiver (shared secret); unlocks nothing commercial".into()
            }
            Self::Revoked { license_id } => format!("license {license_id} was REVOKED by the vendor"),
            Self::Expired { license_id } => format!("license {license_id} expired beyond the grace period"),
            Self::Legacy => "written before signed licenses existed; treated as DEMO".into(),
        }
    }
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
            source: EntitlementSource::Free,
            serial: 0,
        }
    }

    /// 这份授权是不是商业边界(厂商签名、非夹具)。演示档的 Enterprise 显示成 Enterprise,
    /// 但这里是 false。
    pub fn is_commercial(&self) -> bool {
        self.source.is_commercial()
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
        // HMAC 令牌是演示档:秘密写在源码里,持有验签方就能签发。
        source: EntitlementSource::DevHmac,
        serial: 0,
    })
}

pub fn load_or_free(path: impl AsRef<Path>) -> Entitlement {
    Entitlement::from_path(path).unwrap_or_else(|_| Entitlement::free())
}

/// 授权门控:功能已授予**且**授权仍有效**且**来源是商业边界。
///
/// 在此之前没有任何地方读 features —— 授权是纯装饰的(计算了 plan 却不门控任何行为,
/// 第七轮复核发现)。这个方法是「真的门」的判据:Free / 过期 / 未授予该功能都返回 false。
/// P2-7 加了第三个条件:HMAC / webhook / 夹具签名这三种**演示档**授权即便写着 Enterprise 也不放行——
/// 它们是本机任何人一条命令就能给自己发的。
impl Entitlement {
    pub fn allows_enterprise_export(&self) -> bool {
        self.is_active() && self.features.enterprise_export && self.is_commercial()
    }
}

/// 加载授权:显式路径 > `AGENTGUARD_ENTITLEMENT` 环境变量 > 默认路径;都没有 → Free。
///
/// Free 不是错误,是「没买」。门控在调用点做(见 `allows_*`),这里只负责取到当前授权。
///
/// 签名授权在加载时**重新验**(store 旁的 `.license.token`):到期、宽限、撤销都是时间函数,
/// 不能只信落库那一刻的结论。再验失败(公钥换了、CRL 验不过)→ Free,不是沿用旧结论。
pub fn load_entitlement(explicit: Option<&Path>) -> Entitlement {
    let path = if let Some(p) = explicit {
        Some(p.to_path_buf())
    } else if let Some(p) = std::env::var_os("AGENTGUARD_ENTITLEMENT") {
        Some(std::path::PathBuf::from(p))
    } else {
        default_entitlement_path().filter(|p| p.exists())
    };
    let Some(path) = path else {
        return Entitlement::free();
    };
    if let Ok(pubkey) = LicenseVerifyKey::resolve() {
        match SignedLicense::revalidate(&path, &pubkey, now_ms()) {
            Ok(Some(ent)) => return ent,
            Ok(None) => {}
            Err(_) => return Entitlement::free(),
        }
    }
    load_or_free(&path)
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
///
/// 入站面 #2(见 `docs/入站信任.md` §一)。处置 = [`OnUnverified::Refuse`](guard_trust::OnUnverified::Refuse):
/// webhook 一旦被接受就**放宽**行为(可授予 Enterprise),所以验不过必须拒(`http.rs` 里返回 503),
/// 不能降级。相等比较走[唯一的常数时间实现](guard_trust::constant_time_eq)。
pub fn verify_webhook_signature(secret: &str, body: &str, header: Option<&str>) -> bool {
    let Some(h) = header else {
        return false;
    };
    let hex_sig = h.trim().strip_prefix("sha256=").unwrap_or_else(|| h.trim());
    let Ok(provided) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    let expected = hmac_sha256(secret.as_bytes(), body.as_bytes());
    guard_trust::constant_time_eq(&expected, &provided)
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
///
/// P1-7:三个字段让接收端能拒绝重放与乱序——
/// * `event_id`:签发方的事件 ID。见过的直接幂等返回,不再改动授权;
/// * `created_ms`:事件时刻。离现在超过 [`WEBHOOK_MAX_SKEW_MS`] 的拒收(一份旧的合法 purchase
///   在 refund 之后被重放,就是靠这条和下一条挡住的);
/// * `version`:授权状态版本(单调)。不高于本地已应用版本的拒收。
///
/// 三个都是**必填**:没有它们的 webhook 无法与重放区分,而这个接收端会自铸并激活授权。
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
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub created_ms: Option<i64>,
    #[serde(default)]
    pub version: Option<u64>,
}

fn default_plan_pro() -> String {
    "pro".into()
}

/// webhook 事件时刻与本机时钟允许的最大偏差(过去与将来各 10 分钟)。
pub const WEBHOOK_MAX_SKEW_MS: i64 = 10 * 60 * 1000;
/// 幂等表保留的事件 ID 上限(超过就丢最旧的;时间窗已经挡住更旧的重放)。
const WEBHOOK_SEEN_MAX: usize = 512;

/// 接收端在授权文件旁维护的幂等/版本状态。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookState {
    pub last_version: u64,
    #[serde(default)]
    pub seen_event_ids: Vec<String>,
}

impl WebhookState {
    pub fn path_for(store: &Path) -> PathBuf {
        let mut p = store.as_os_str().to_owned();
        p.push(".webhook-state.json");
        PathBuf::from(p)
    }

    pub fn load(store: &Path) -> Self {
        std::fs::read_to_string(Self::path_for(store))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, store: &Path) -> Result<()> {
        let path = Self::path_for(store);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

/// 一次 webhook 处理的结果。
#[derive(Debug, Clone)]
pub struct WebhookOutcome {
    pub entitlement: Entitlement,
    /// false = 幂等命中(同一 event_id 已应用过),授权未改动。
    pub applied: bool,
}

/// 只做字段/重放/版本判定,不碰文件——便于单测。`Ok(())` 表示可以应用。
pub fn admit_webhook(
    event: &BillingWebhookEvent,
    state: &WebhookState,
    now_ms: i64,
) -> std::result::Result<(), String> {
    let Some(id) = event
        .event_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err("webhook missing event_id (required for idempotency)".into());
    };
    if id.len() > 200 {
        return Err("webhook event_id too long".into());
    }
    let Some(created) = event.created_ms else {
        return Err("webhook missing created_ms (required for replay window)".into());
    };
    if (now_ms - created).abs() > WEBHOOK_MAX_SKEW_MS {
        return Err(format!(
            "webhook created_ms {created} is outside the ±{}s window of now {now_ms}",
            WEBHOOK_MAX_SKEW_MS / 1000
        ));
    }
    let Some(version) = event.version else {
        return Err("webhook missing version (required for ordering)".into());
    };
    if version <= state.last_version {
        return Err(format!(
            "webhook version {version} is not newer than applied version {}",
            state.last_version
        ));
    }
    Ok(())
}

/// Apply a billing webhook to the local entitlement store(幂等、拒重放、拒乱序)。
pub fn apply_webhook_event(
    event: &BillingWebhookEvent,
    store: impl AsRef<Path>,
) -> Result<Entitlement> {
    Ok(apply_webhook_event_at(event, store, now_ms())?.entitlement)
}

/// [`apply_webhook_event`] 的可注入时钟版本,返回是否真的应用了。
pub fn apply_webhook_event_at(
    event: &BillingWebhookEvent,
    store: impl AsRef<Path>,
    now_ms: i64,
) -> Result<WebhookOutcome> {
    let store = store.as_ref();
    let mut state = WebhookState::load(store);
    // 幂等:同一 event_id 再来一次,原样返回当前授权,不改任何东西(签发方重试是常态)。
    if let Some(id) = event.event_id.as_deref() {
        if state.seen_event_ids.iter().any(|s| s == id) {
            let current = Entitlement::from_path(store).unwrap_or_else(|_| Entitlement::free());
            return Ok(WebhookOutcome {
                entitlement: current,
                applied: false,
            });
        }
    }
    admit_webhook(event, &state, now_ms).map_err(|e| anyhow::anyhow!(e))?;
    let ent = apply_admitted(event, store)?;
    state.last_version = event.version.unwrap_or(state.last_version);
    state
        .seen_event_ids
        .push(event.event_id.clone().unwrap_or_default());
    while state.seen_event_ids.len() > WEBHOOK_SEEN_MAX {
        state.seen_event_ids.remove(0);
    }
    state.save(store)?;
    Ok(WebhookOutcome {
        entitlement: ent,
        applied: true,
    })
}

fn apply_admitted(event: &BillingWebhookEvent, store: &Path) -> Result<Entitlement> {
    match event.event_type.as_str() {
        "purchase" | "entitlement.updated" | "checkout.session.completed" => {
            let plan = match event.plan.as_str() {
                "enterprise" => PlanTier::Enterprise,
                "free" => PlanTier::Free,
                _ => PlanTier::Pro,
            };
            let secret = resolve_secret();
            let token = issue_license_token(&secret, &event.license_id, plan);
            let mut ent = activate_license_token(&secret, &token)?;
            // webhook 路径是共享秘密——演示档,不是商业边界(P2-7)。
            ent.source = EntitlementSource::Webhook;
            ent.write_path(store)?;
            Ok(ent)
        }
        "refund" | "customer.subscription.deleted" => {
            let ent = Entitlement::free();
            ent.write_path(store)?;
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

    fn ev(kind: &str, id: &str, created: i64, version: u64) -> BillingWebhookEvent {
        BillingWebhookEvent {
            event_type: kind.into(),
            license_id: "lic-replay".into(),
            plan: "pro".into(),
            provider: Some("test".into()),
            event_id: Some(id.into()),
            created_ms: Some(created),
            version: Some(version),
        }
    }

    /// P1-7:refund 之后重放一份旧的合法 purchase,不能把授权变回 Pro。
    #[test]
    fn refund后重放旧purchase被版本与时间窗双重拒绝() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("ent.json");
        let t0 = 1_700_000_000_000i64;
        let purchase = ev("purchase", "evt-1", t0, 1);
        let out = apply_webhook_event_at(&purchase, &store, t0 + 1_000).unwrap();
        assert!(out.applied && out.entitlement.is_active());
        let refund = ev("refund", "evt-2", t0 + 60_000, 2);
        let out = apply_webhook_event_at(&refund, &store, t0 + 61_000).unwrap();
        assert!(out.applied && !out.entitlement.is_active());
        // 重放 evt-1(同 id)→ 幂等命中,授权仍是 Free,未改动。
        let out = apply_webhook_event_at(&purchase, &store, t0 + 62_000).unwrap();
        assert!(!out.applied);
        assert!(!out.entitlement.is_active(), "重放不能恢复 Pro");
        // 换个 id 但版本旧 → 拒。
        let replay = ev("purchase", "evt-1b", t0, 1);
        let err = apply_webhook_event_at(&replay, &store, t0 + 62_000).unwrap_err();
        assert!(err.to_string().contains("not newer"), "{err}");
        // 版本新但时间戳太旧(超过窗口)→ 拒。
        let stale = ev("purchase", "evt-3", t0, 3);
        let err =
            apply_webhook_event_at(&stale, &store, t0 + WEBHOOK_MAX_SKEW_MS + 60_000).unwrap_err();
        assert!(err.to_string().contains("window"), "{err}");
        assert!(!Entitlement::from_path(&store).unwrap().is_active());
    }

    #[test]
    fn 缺event_id_created_ms_version任一即拒() {
        let state = WebhookState::default();
        let now = 1_700_000_000_000i64;
        let mut e = ev("purchase", "x", now, 1);
        assert!(admit_webhook(&e, &state, now).is_ok());
        e.event_id = None;
        assert!(admit_webhook(&e, &state, now)
            .unwrap_err()
            .contains("event_id"));
        let mut e = ev("purchase", "x", now, 1);
        e.created_ms = None;
        assert!(admit_webhook(&e, &state, now)
            .unwrap_err()
            .contains("created_ms"));
        let mut e = ev("purchase", "x", now, 1);
        e.version = None;
        assert!(admit_webhook(&e, &state, now)
            .unwrap_err()
            .contains("version"));
        // 将来的时间戳同样超窗
        let e = ev("purchase", "x", now + WEBHOOK_MAX_SKEW_MS + 1, 1);
        assert!(admit_webhook(&e, &state, now).is_err());
        // 恰在窗内
        let e = ev("purchase", "x", now - WEBHOOK_MAX_SKEW_MS, 1);
        assert!(admit_webhook(&e, &state, now).is_ok());
    }

    #[test]
    fn 幂等表有界且状态文件落在授权文件旁() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("ent.json");
        let now = 1_700_000_000_000i64;
        for i in 0..(WEBHOOK_SEEN_MAX as u64 + 10) {
            let e = ev("purchase", &format!("evt-{i}"), now, i + 1);
            apply_webhook_event_at(&e, &store, now).unwrap();
        }
        let st = WebhookState::load(&store);
        assert_eq!(st.seen_event_ids.len(), WEBHOOK_SEEN_MAX);
        assert_eq!(st.last_version, WEBHOOK_SEEN_MAX as u64 + 10);
        assert!(WebhookState::path_for(&store).exists());
        assert!(WebhookState::path_for(&store)
            .to_string_lossy()
            .ends_with("ent.json.webhook-state.json"));
    }

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

    /// 授权门控的判据:只有**有效**、**厂商签名**的 Enterprise 授权才放行 enterprise_export。
    /// 这是「授权不再是装饰」的那条测试 —— Free / Pro / 过期都被拒;P2-7 之后 HMAC 演示档也被拒。
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
        // HMAC 令牌签出来的 Enterprise:显示成 Enterprise、is_active,但**不是商业边界**——
        // 秘密写在源码里,本机任何人一条命令就能给自己发一份(真机报告 P2-7)。
        let demo =
            activate_license_token("s", &issue_license_token("s", "x", PlanTier::Enterprise))
                .unwrap();
        assert_eq!(demo.plan, PlanTier::Enterprise);
        assert!(demo.is_active());
        assert_eq!(demo.source, EntitlementSource::DevHmac);
        assert!(!demo.is_commercial());
        assert!(
            !demo.allows_enterprise_export(),
            "HMAC 演示授权不能解锁企业功能"
        );
        // 厂商签名的 Enterprise 才放行。
        let vendor = LicenseSigningKey::generate();
        let now = now_ms();
        let lic = SignedLicense::issue(
            &vendor,
            LicenseClaims {
                license_id: "acme".into(),
                plan: PlanTier::Enterprise,
                issued_at_ms: now,
                expires_at_ms: now + 30 * 86_400_000,
                serial: 1,
            },
        )
        .unwrap();
        let st = lic.verify_at(&vendor.verifying(), None, now).unwrap();
        let ent = lic.to_entitlement(&st, now);
        assert!(ent.is_commercial());
        assert!(
            ent.allows_enterprise_export(),
            "厂商签名的 Enterprise 应当放行"
        );
        // 过期(且过了宽限)的也拒。
        let mut expired = ent.clone();
        expired.expires_at_ms = Some(0);
        assert!(!expired.allows_enterprise_export(), "过期授权不该放行");
    }

    /// load_entitlement 显式路径读得到已写入的授权;签名授权在加载时**再验**。
    #[test]
    fn load_entitlement_显式路径() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ent.json");
        // 演示档:读得到,但不解锁。
        let ent = activate_license_token("s", &issue_license_token("s", "x", PlanTier::Enterprise))
            .unwrap();
        ent.write_path(&p).unwrap();
        let loaded = load_entitlement(Some(&p));
        assert_eq!(loaded.plan, PlanTier::Enterprise);
        assert!(!loaded.allows_enterprise_export());
        // 签名档:落库 + 旁文件,load 时用夹具公钥再验(测试进程里没配 AGENTGUARD_LICENSE_PUBKEY
        // → resolve() 给夹具)→ 夹具签的 = 演示档,依旧不解锁;而用真正厂商公钥直接再验则解锁。
        let fixture = LicenseSigningKey::from_secret_hex(FIXTURE_SECRET_KEY_HEX).unwrap();
        let now = now_ms();
        let lic = SignedLicense::issue(
            &fixture,
            LicenseClaims {
                license_id: "demo".into(),
                plan: PlanTier::Enterprise,
                issued_at_ms: now,
                expires_at_ms: now + 86_400_000,
                serial: 1,
            },
        )
        .unwrap();
        let p2 = dir.path().join("ent2.json");
        let (_, st) = activate_signed_token(&lic.encode(), &p2, &fixture.verifying(), now).unwrap();
        assert_eq!(st, LicenseStatus::SignedByFixture);
        let loaded = load_entitlement(Some(&p2));
        assert_eq!(loaded.source, EntitlementSource::SignedByFixture);
        assert!(!loaded.allows_enterprise_export(), "夹具签的不是商业边界");
    }

    #[test]
    fn webhook_purchase_and_refund() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ent.json");
        let now = now_ms();
        let raw = format!(
            r#"{{"type":"purchase","license_id":"wh-1","plan":"pro","provider":"stripe-sim","event_id":"wh-evt-1","created_ms":{now},"version":1}}"#
        );
        let e = apply_webhook_json(&raw, &path).unwrap();
        assert!(e.is_active());
        // P1-7:没有 event_id/created_ms/version 的 webhook 一律拒——这就是旧夹具的形状。
        let legacy = r#"{"type":"purchase","license_id":"wh-1","plan":"pro"}"#;
        assert!(apply_webhook_json(legacy, &path).is_err());
        let refund = format!(
            r#"{{"type":"refund","license_id":"wh-1","plan":"pro","event_id":"wh-evt-2","created_ms":{now},"version":2}}"#
        );
        let e2 = apply_webhook_json(&refund, &path).unwrap();
        assert!(!e2.is_active());
        assert_eq!(e2.plan, PlanTier::Free);
    }
}
