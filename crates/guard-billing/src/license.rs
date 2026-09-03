//! 厂商签名的授权(真机报告 P2-7:商业授权边界需要重新定义)。
//!
//! # 以前的边界是什么
//!
//! `issue_license_token` / `activate_license_token` 是 **HMAC**:`sha256(secret|license_id|plan)`。
//! 秘密在 `default_dev_secret()` 里——一个写在源码里、任何人都读得到的字符串;`AGENTGUARD_LICENSE_SECRET`
//! 可以换,但装在用户机器上的二进制要验签就必须**带着**这个秘密,而带着秘密的一方就能签发。
//! 所以本地 CLI 能给自己签 Enterprise:`entitlement-issue --plan enterprise` 一条命令。webhook 路径也是
//! 共享秘密。这是**演示**授权,不是商业边界;而 `allows_enterprise_export()` 却把它当边界用。
//!
//! # 现在的边界
//!
//! 非对称:厂商持 **Ed25519 私钥**签发 [`SignedLicense`];客户端只带**公钥**验签。持公钥的一方签不出
//! 任何东西——这是"边界"两个字的全部含义。规则:
//!
//! 1. **必须有到期日。** `expires_at_ms` 是必填;没有到期的授权没有撤销手段(除了 CRL)。
//! 2. **离线宽限。** 到期后 [`OFFLINE_GRACE_MS`](7 天)内功能仍可用、状态显示 `in_grace`——用户在飞机上
//!    不该被锁出去;宽限过了就是 Free。
//! 3. **撤销。** 厂商签一份 [`RevocationList`](license_id 列表 + 签发时间);客户端在
//!    `<store>.revocations.json` 找到它就验签并拒掉名单上的授权。取回 CRL 的传输(HTTP / 随更新包)
//!    不在这个 crate 里——这里只管"拿到一份就认"。
//! 4. **公开夹具不算。** 仓库里带一对**夹具**密钥(`eval/fixtures/license-fixture-*.hex`)供演示与
//!    测试。用夹具公钥验过的授权被标成 `SignedByFixture`:签名有效,但证明不了任何事——私钥每个
//!    拿到仓库的人都有。它和 HMAC 一样是演示档,**不解锁企业功能**;preflight 报
//!    `license.pubkey.fixture` FAIL,直到 `AGENTGUARD_LICENSE_PUBKEY` 指向一把真正的厂商公钥。
//!
//! HMAC 与 webhook 两条老路**保留**,但落库的授权带 `source = dev_hmac / webhook`,
//! `allows_enterprise_export()` 只对 `source = signed`(且非夹具)为真。演示还能演示,只是不再被当成钱。
//!
//! # 签的是什么
//!
//! 不签 JSON——JSON 没有规范序列化,签它就得先规范化它。签一条带域分隔的定长文本
//! (`agentguard-license-v1|<license_id>|<plan>|<issued>|<expires>|<serial>`),和 `adapter_body_message`
//! 同一思路。token 形态 `agl1.<base64url(JSON)>`,JSON 只是搬运声明与签名的容器;验签时从声明重建那条
//! 文本。

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{Entitlement, EntitlementFeatures, EntitlementSource, PlanTier};

/// 到期后仍放行的离线宽限:7 天。
pub const OFFLINE_GRACE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// token 前缀,认得出"这是签名授权,不是 HMAC 令牌"。
pub const TOKEN_PREFIX: &str = "agl1.";
const DOMAIN: &str = "agentguard-license-v1";
const CRL_DOMAIN: &str = "agentguard-license-revocations-v1";

/// 仓库自带的**公开**夹具公钥(私钥在 eval/fixtures/license-fixture-secret.hex,人人可见)。
/// 用它验过的授权是演示档。见 [`SignedLicense::verify_at`]。
pub const FIXTURE_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// 对应的夹具私钥 hex(**公开**——这是 RFC 8032 §7.1 的 TEST 1 向量,印在标准里;只给测试与
/// `make` 演示用)。它出现在这里正是为了让 preflight 与 `verify_at` 能认出它——没有人应该用它签
/// 真正的授权。
pub const FIXTURE_SECRET_KEY_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// 厂商私钥。只在签发机上存在。
pub struct LicenseSigningKey {
    signing: SigningKey,
}

impl std::fmt::Debug for LicenseSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseSigningKey")
            .field("public_key_hex", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

impl LicenseSigningKey {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("license secret key is not hex")?;
        if bytes.len() != 32 {
            bail!("license secret key must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read license secret {}", path.as_ref().display()))?;
        Self::from_secret_hex(&raw)
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    pub fn verifying(&self) -> LicenseVerifyKey {
        LicenseVerifyKey {
            key: self.signing.verifying_key(),
        }
    }

    fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.signing.sign(message).to_bytes())
    }
}

/// 厂商公钥。客户端唯一需要带的东西。
#[derive(Clone)]
pub struct LicenseVerifyKey {
    key: VerifyingKey,
}

impl LicenseVerifyKey {
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("license public key is not hex")?;
        if bytes.len() != 32 {
            bail!("license public key must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            key: VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?,
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    /// 这把公钥是不是仓库自带的公开夹具。
    pub fn is_fixture(&self) -> bool {
        self.to_hex().eq_ignore_ascii_case(FIXTURE_PUBLIC_KEY_HEX)
    }

    fn verify_hex(&self, message: &[u8], sig_hex: &str) -> Result<()> {
        let bytes = hex::decode(sig_hex.trim()).context("signature is not hex")?;
        let sig = Signature::from_slice(&bytes).context("signature has the wrong length")?;
        self.key
            .verify(message, &sig)
            .map_err(|_| anyhow::anyhow!("license signature does not verify"))
    }

    /// 客户端应当用的公钥:`AGENTGUARD_LICENSE_PUBKEY`(hex,或指向 hex 文件的路径)→ 夹具。
    /// 返回值第二项是"这是夹具吗"——调用方据此把授权降成演示档。
    pub fn resolve() -> Result<Self> {
        if let Ok(v) = std::env::var("AGENTGUARD_LICENSE_PUBKEY") {
            let v = v.trim().to_string();
            if v.is_empty() {
                return Self::from_hex(FIXTURE_PUBLIC_KEY_HEX);
            }
            if Path::new(&v).exists() {
                let raw = std::fs::read_to_string(&v)
                    .with_context(|| format!("read AGENTGUARD_LICENSE_PUBKEY file {v}"))?;
                return Self::from_hex(&raw);
            }
            return Self::from_hex(&v);
        }
        Self::from_hex(FIXTURE_PUBLIC_KEY_HEX)
    }
}

/// 授权声明——被签名的全部内容。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseClaims {
    pub license_id: String,
    pub plan: PlanTier,
    pub issued_at_ms: i64,
    /// 必填。没有到期日的授权只能靠 CRL 收回,而 CRL 的送达不受我们控制。
    pub expires_at_ms: i64,
    /// 同一 license_id 的续期/改档递增;CRL 可以按 `(license_id, serial <= n)` 撤旧留新。
    pub serial: u64,
}

impl LicenseClaims {
    /// 被签名的字节:带域分隔的定长文本,不是 JSON。
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "{DOMAIN}|{}|{}|{}|{}|{}",
            self.license_id,
            plan_str(&self.plan),
            self.issued_at_ms,
            self.expires_at_ms,
            self.serial
        )
        .into_bytes()
    }
}

/// 一份签过名的授权。`agl1.<base64url(JSON)>` 是它的搬运形态。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedLicense {
    pub claims: LicenseClaims,
    /// 签发公钥的 hex 前 16 位——让"验不过"的错误信息能说"你配的公钥不是签这份的那把"。
    pub key_id: String,
    pub signature: String,
}

/// 验签后的状态,给 UI / CLI 显示;[`Entitlement`] 由它推出。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum LicenseStatus {
    Active,
    /// 已到期,但在离线宽限内。
    InGrace {
        expired_for_ms: i64,
    },
    Expired {
        expired_for_ms: i64,
    },
    Revoked,
    /// 签名有效,但签发公钥是仓库自带的公开夹具——演示档。
    SignedByFixture,
}

impl SignedLicense {
    pub fn issue(key: &LicenseSigningKey, claims: LicenseClaims) -> Result<Self> {
        if claims.expires_at_ms <= claims.issued_at_ms {
            bail!("expires_at_ms must be after issued_at_ms — a license without an expiry has no revocation path except the CRL");
        }
        if claims.license_id.trim().is_empty() || claims.license_id.contains('|') {
            bail!("license_id must be non-empty and must not contain '|'");
        }
        let signature = key.sign_hex(&claims.signing_bytes());
        Ok(Self {
            key_id: key.public_key_hex()[..16].to_string(),
            claims,
            signature,
        })
    }

    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("SignedLicense serializes");
        format!("{TOKEN_PREFIX}{}", base64url(&json))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let body = token.trim().strip_prefix(TOKEN_PREFIX).ok_or_else(|| {
            anyhow::anyhow!("not a signed license token (expected prefix {TOKEN_PREFIX})")
        })?;
        let json = base64url_decode(body).context("license token body is not base64url")?;
        serde_json::from_slice(&json).context("license token body is not a SignedLicense")
    }

    pub fn is_signed_token(token: &str) -> bool {
        token.trim().starts_with(TOKEN_PREFIX)
    }

    /// 验签 + 时效 + 撤销 → 状态。签名不对是 `Err`,不是一种状态:一份签名不对的授权不是"过期的
    /// 授权",它根本不是授权。
    pub fn verify_at(
        &self,
        pubkey: &LicenseVerifyKey,
        crl: Option<&RevocationList>,
        now_ms: i64,
    ) -> Result<LicenseStatus> {
        pubkey
            .verify_hex(&self.claims.signing_bytes(), &self.signature)
            .with_context(|| {
                format!(
                    "license {} signed by key {} does not verify against the configured public key {}",
                    self.claims.license_id,
                    self.key_id,
                    &pubkey.to_hex()[..16]
                )
            })?;
        if let Some(crl) = crl {
            if crl.revokes(&self.claims) {
                return Ok(LicenseStatus::Revoked);
            }
        }
        if pubkey.is_fixture() {
            return Ok(LicenseStatus::SignedByFixture);
        }
        if now_ms <= self.claims.expires_at_ms {
            return Ok(LicenseStatus::Active);
        }
        let expired_for_ms = now_ms - self.claims.expires_at_ms;
        if expired_for_ms <= OFFLINE_GRACE_MS {
            Ok(LicenseStatus::InGrace { expired_for_ms })
        } else {
            Ok(LicenseStatus::Expired { expired_for_ms })
        }
    }

    /// 把一份验过的授权落成 [`Entitlement`]。`Revoked` / `Expired` 落成 Free(source 仍记着为什么)。
    pub fn to_entitlement(&self, status: &LicenseStatus, now_ms: i64) -> Entitlement {
        let (plan, features, source) = match status {
            LicenseStatus::Active | LicenseStatus::InGrace { .. } => (
                self.claims.plan.clone(),
                features_for(&self.claims.plan),
                EntitlementSource::Signed {
                    key_id: self.key_id.clone(),
                    in_grace: matches!(status, LicenseStatus::InGrace { .. }),
                },
            ),
            LicenseStatus::SignedByFixture => (
                self.claims.plan.clone(),
                features_for(&self.claims.plan),
                EntitlementSource::SignedByFixture,
            ),
            LicenseStatus::Revoked => (
                PlanTier::Free,
                EntitlementFeatures::default(),
                EntitlementSource::Revoked {
                    license_id: self.claims.license_id.clone(),
                },
            ),
            LicenseStatus::Expired { .. } => (
                PlanTier::Free,
                EntitlementFeatures::default(),
                EntitlementSource::Expired {
                    license_id: self.claims.license_id.clone(),
                },
            ),
        };
        Entitlement {
            plan,
            license_id: self.claims.license_id.clone(),
            activated_at_ms: now_ms,
            expires_at_ms: Some(self.claims.expires_at_ms),
            features,
            source,
            serial: self.claims.serial,
        }
    }
}

/// 厂商签名的撤销名单。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationList {
    pub issued_at_ms: i64,
    /// 被撤销的条目。`max_serial` 为 `None` 时该 license_id 的**所有** serial 都撤;否则只撤
    /// `serial <= max_serial`(续期后的新授权继续有效)。
    pub revoked: Vec<RevokedLicense>,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedLicense {
    pub license_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_serial: Option<u64>,
}

impl RevocationList {
    fn signing_bytes(issued_at_ms: i64, revoked: &[RevokedLicense]) -> Vec<u8> {
        let mut s = format!("{CRL_DOMAIN}|{issued_at_ms}");
        for r in revoked {
            s.push('|');
            s.push_str(&r.license_id);
            s.push(':');
            match r.max_serial {
                Some(n) => s.push_str(&n.to_string()),
                None => s.push('*'),
            }
        }
        s.into_bytes()
    }

    pub fn issue(key: &LicenseSigningKey, issued_at_ms: i64, revoked: Vec<RevokedLicense>) -> Self {
        let signature = key.sign_hex(&Self::signing_bytes(issued_at_ms, &revoked));
        Self {
            issued_at_ms,
            revoked,
            key_id: key.public_key_hex()[..16].to_string(),
            signature,
        }
    }

    pub fn verify(&self, pubkey: &LicenseVerifyKey) -> Result<()> {
        pubkey
            .verify_hex(
                &Self::signing_bytes(self.issued_at_ms, &self.revoked),
                &self.signature,
            )
            .context("revocation list signature does not verify")
    }

    pub fn revokes(&self, claims: &LicenseClaims) -> bool {
        self.revoked.iter().any(|r| {
            r.license_id == claims.license_id && r.max_serial.is_none_or(|n| claims.serial <= n)
        })
    }

    /// `<store>.revocations.json`。
    pub fn path_for(store: &Path) -> std::path::PathBuf {
        let mut p = store.as_os_str().to_owned();
        p.push(".revocations.json");
        std::path::PathBuf::from(p)
    }

    /// 从 store 旁边读一份**已验签**的 CRL;没有文件是 `Ok(None)`;有文件但验不过是 `Err`——
    /// 一份验不过的 CRL 不是"没有 CRL",是有人在动它。
    pub fn load_verified(store: &Path, pubkey: &LicenseVerifyKey) -> Result<Option<Self>> {
        let p = Self::path_for(store);
        if !p.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&p)
            .with_context(|| format!("read revocation list {}", p.display()))?;
        let crl: Self = serde_json::from_str(&raw).context("revocation list is not JSON")?;
        crl.verify(pubkey)?;
        Ok(Some(crl))
    }
}

/// 激活一份签名 token:验签 → 状态 → 落库。返回 (授权, 状态) 让 CLI 说清楚发生了什么。
pub fn activate_signed_token(
    token: &str,
    store: &Path,
    pubkey: &LicenseVerifyKey,
    now_ms: i64,
) -> Result<(Entitlement, LicenseStatus)> {
    let lic = SignedLicense::decode(token)?;
    let crl = RevocationList::load_verified(store, pubkey)?;
    let status = lic.verify_at(pubkey, crl.as_ref(), now_ms)?;
    let ent = lic.to_entitlement(&status, now_ms);
    ent.write_path(store)?;
    // 把 token 原样留在旁边:下次启动可以**重新验**(到期 / 宽限 / CRL 都是时间函数,
    // 不能只信落库那一刻的结论)。
    std::fs::write(SignedLicense::sidecar_path(store), token.trim())
        .with_context(|| format!("write license sidecar next to {}", store.display()))?;
    Ok((ent, status))
}

impl SignedLicense {
    /// `<store>.license.token`——激活时留下的原始 token,供再验。
    pub fn sidecar_path(store: &Path) -> std::path::PathBuf {
        let mut p = store.as_os_str().to_owned();
        p.push(".license.token");
        std::path::PathBuf::from(p)
    }

    /// 再验:旁边有 token 就按**现在**重新算状态并刷新 store;没有就返回 `None`(store 里是
    /// HMAC / webhook / Free 那类,原样用)。
    pub fn revalidate(
        store: &Path,
        pubkey: &LicenseVerifyKey,
        now_ms: i64,
    ) -> Result<Option<Entitlement>> {
        let p = Self::sidecar_path(store);
        if !p.exists() {
            return Ok(None);
        }
        let token = std::fs::read_to_string(&p)?;
        let (ent, _) = activate_signed_token(&token, store, pubkey, now_ms)?;
        Ok(Some(ent))
    }
}

pub(crate) fn features_for(plan: &PlanTier) -> EntitlementFeatures {
    match plan {
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
    }
}

pub(crate) fn plan_str(plan: &PlanTier) -> &'static str {
    match plan {
        PlanTier::Free => "free",
        PlanTier::Pro => "pro",
        PlanTier::Enterprise => "enterprise",
    }
}

// base64url(无填充),手写 —— 不为 20 行引一个依赖。
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    let val = |c: u8| -> Result<u32> {
        B64.iter()
            .position(|&b| b == c)
            .map(|p| p as u32)
            .ok_or_else(|| anyhow::anyhow!("invalid base64url character {:?}", c as char))
    };
    let bytes = s.trim().as_bytes();
    if bytes.len() % 4 == 1 {
        bail!("invalid base64url length");
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn vendor() -> LicenseSigningKey {
        // 测试里的"厂商":随机新键,不是夹具——夹具那条路单独测。
        LicenseSigningKey::generate()
    }

    /// `Entitlement::is_active()` 看真实时钟,所以凡是要断言 allows_* 的地方用"现在"做基准。
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn claims(id: &str, plan: PlanTier, issued: i64, days: i64, serial: u64) -> LicenseClaims {
        LicenseClaims {
            license_id: id.into(),
            plan,
            issued_at_ms: issued,
            expires_at_ms: issued + days * DAY,
            serial,
        }
    }

    #[test]
    fn 签发_编码_解码_验签_往返() {
        let k = vendor();
        let t0 = now();
        let lic =
            SignedLicense::issue(&k, claims("acme-1", PlanTier::Enterprise, t0, 30, 1)).unwrap();
        let token = lic.encode();
        assert!(token.starts_with(TOKEN_PREFIX));
        let back = SignedLicense::decode(&token).unwrap();
        assert_eq!(back, lic);
        let st = back.verify_at(&k.verifying(), None, t0 + DAY).unwrap();
        assert_eq!(st, LicenseStatus::Active);
        let ent = back.to_entitlement(&st, t0 + DAY);
        assert_eq!(ent.plan, PlanTier::Enterprise);
        assert!(matches!(
            ent.source,
            EntitlementSource::Signed {
                in_grace: false,
                ..
            }
        ));
        assert!(
            ent.allows_enterprise_export(),
            "真正厂商签的 Enterprise 才解锁企业功能"
        );
    }

    /// 持公钥的一方签不出任何东西:改一个字段、换一把私钥、改签名,都验不过。
    #[test]
    fn 篡改声明或换钥都验不过() {
        let k = vendor();
        let lic = SignedLicense::issue(&k, claims("acme-1", PlanTier::Pro, 1_000, 30, 1)).unwrap();
        let now = 2_000;
        // 改档:Pro → Enterprise。
        let mut t = lic.clone();
        t.claims.plan = PlanTier::Enterprise;
        assert!(t.verify_at(&k.verifying(), None, now).is_err());
        // 改到期日。
        let mut t = lic.clone();
        t.claims.expires_at_ms += 365 * DAY;
        assert!(t.verify_at(&k.verifying(), None, now).is_err());
        // 改 serial(CRL 绕过的方向)。
        let mut t = lic.clone();
        t.claims.serial += 1;
        assert!(t.verify_at(&k.verifying(), None, now).is_err());
        // 另一把私钥签的。
        let other = vendor();
        let forged = SignedLicense::issue(&other, lic.claims.clone()).unwrap();
        let err = forged
            .verify_at(&k.verifying(), None, now)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not verify") && err.contains(&forged.key_id),
            "{err}"
        );
        // 改签名一个字节。
        let mut t = lic.clone();
        let mut sig = t.signature.clone().into_bytes();
        sig[0] = if sig[0] == b'a' { b'b' } else { b'a' };
        t.signature = String::from_utf8(sig).unwrap();
        assert!(t.verify_at(&k.verifying(), None, now).is_err());
        // 没有 `|` 注入:license_id 含分隔符在签发时就拒。
        assert!(SignedLicense::issue(&k, claims("a|enterprise", PlanTier::Free, 1, 1, 1)).is_err());
    }

    #[test]
    fn 到期后先宽限再free_且必须有到期日() {
        let k = vendor();
        let issued = 1_000;
        let lic = SignedLicense::issue(&k, claims("acme-1", PlanTier::Pro, issued, 30, 1)).unwrap();
        let exp = lic.claims.expires_at_ms;
        assert_eq!(
            lic.verify_at(&k.verifying(), None, exp).unwrap(),
            LicenseStatus::Active
        );
        let st = lic.verify_at(&k.verifying(), None, exp + 3 * DAY).unwrap();
        assert_eq!(
            st,
            LicenseStatus::InGrace {
                expired_for_ms: 3 * DAY
            }
        );
        let ent = lic.to_entitlement(&st, exp + 3 * DAY);
        assert_eq!(ent.plan, PlanTier::Pro, "宽限内功能仍在");
        assert!(matches!(
            ent.source,
            EntitlementSource::Signed { in_grace: true, .. }
        ));
        let st = lic
            .verify_at(&k.verifying(), None, exp + OFFLINE_GRACE_MS + 1)
            .unwrap();
        assert!(matches!(st, LicenseStatus::Expired { .. }));
        let ent = lic.to_entitlement(&st, exp + OFFLINE_GRACE_MS + 1);
        assert_eq!(ent.plan, PlanTier::Free);
        assert!(!ent.allows_enterprise_export());
        assert!(matches!(ent.source, EntitlementSource::Expired { .. }));
        // 没有到期日(expires <= issued)签不出来。
        let bad = LicenseClaims {
            expires_at_ms: issued,
            ..claims("x", PlanTier::Pro, issued, 1, 1)
        };
        assert!(SignedLicense::issue(&k, bad).is_err());
    }

    #[test]
    fn 撤销名单按serial撤旧留新_且名单自己要验签() {
        let k = vendor();
        let v1 =
            SignedLicense::issue(&k, claims("acme-1", PlanTier::Enterprise, 1_000, 30, 1)).unwrap();
        let v2 =
            SignedLicense::issue(&k, claims("acme-1", PlanTier::Enterprise, 2_000, 30, 2)).unwrap();
        let other =
            SignedLicense::issue(&k, claims("beta-9", PlanTier::Pro, 1_000, 30, 1)).unwrap();
        let crl = RevocationList::issue(
            &k,
            5_000,
            vec![
                RevokedLicense {
                    license_id: "acme-1".into(),
                    max_serial: Some(1),
                },
                RevokedLicense {
                    license_id: "beta-9".into(),
                    max_serial: None,
                },
            ],
        );
        crl.verify(&k.verifying()).unwrap();
        let now = 6_000;
        assert_eq!(
            v1.verify_at(&k.verifying(), Some(&crl), now).unwrap(),
            LicenseStatus::Revoked
        );
        assert_eq!(
            v2.verify_at(&k.verifying(), Some(&crl), now).unwrap(),
            LicenseStatus::Active,
            "续期后的 serial 2 不受 max_serial=1 影响"
        );
        assert_eq!(
            other.verify_at(&k.verifying(), Some(&crl), now).unwrap(),
            LicenseStatus::Revoked
        );
        let ent = v1.to_entitlement(&LicenseStatus::Revoked, now);
        assert_eq!(ent.plan, PlanTier::Free);
        assert!(matches!(ent.source, EntitlementSource::Revoked { .. }));
        // 篡改名单(把 acme-1 删掉)→ 验不过。
        let mut tampered = crl.clone();
        tampered.revoked.remove(0);
        assert!(tampered.verify(&k.verifying()).is_err());
        // 别人签的名单也验不过。
        let forged = RevocationList::issue(&vendor(), 5_000, vec![]);
        assert!(forged.verify(&k.verifying()).is_err());
    }

    /// 夹具公钥验过的授权是演示档:签名有效,但不解锁企业功能。
    #[test]
    fn 夹具签的授权不是商业边界() {
        let fixture = LicenseSigningKey::from_secret_hex(FIXTURE_SECRET_KEY_HEX).unwrap();
        assert_eq!(
            fixture.public_key_hex(),
            FIXTURE_PUBLIC_KEY_HEX,
            "夹具公钥常量必须和夹具私钥配对"
        );
        assert!(fixture.verifying().is_fixture());
        let lic =
            SignedLicense::issue(&fixture, claims("demo", PlanTier::Enterprise, 1_000, 30, 1))
                .unwrap();
        let st = lic.verify_at(&fixture.verifying(), None, 2_000).unwrap();
        assert_eq!(st, LicenseStatus::SignedByFixture);
        let ent = lic.to_entitlement(&st, 2_000);
        assert_eq!(ent.plan, PlanTier::Enterprise, "演示仍显示成 Enterprise");
        assert!(!ent.allows_enterprise_export(), "但不解锁企业功能");
        assert!(!ent.is_commercial());
    }

    #[test]
    fn 激活落库并可再验_crl旁文件验不过就报错() {
        let k = vendor();
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("entitlement.json");
        let t0 = now();
        let lic =
            SignedLicense::issue(&k, claims("acme-1", PlanTier::Enterprise, t0, 30, 1)).unwrap();
        let (ent, st) =
            activate_signed_token(&lic.encode(), &store, &k.verifying(), t0 + 1_000).unwrap();
        assert_eq!(st, LicenseStatus::Active);
        assert!(ent.allows_enterprise_export());
        assert!(SignedLicense::sidecar_path(&store).exists());
        // 时间过去 33 天(到期 3 天,宽限 7 天内):再验 → 宽限;40 天 → Free。
        let re = SignedLicense::revalidate(&store, &k.verifying(), t0 + 33 * DAY)
            .unwrap()
            .unwrap();
        assert!(
            matches!(re.source, EntitlementSource::Signed { in_grace: true, .. }),
            "{:?}",
            re.source
        );
        let re = SignedLicense::revalidate(&store, &k.verifying(), t0 + 40 * DAY)
            .unwrap()
            .unwrap();
        assert_eq!(re.plan, PlanTier::Free);
        // 有人在 store 旁放了一份别人签的 CRL → 激活报错,而不是当没有 CRL。
        let forged = RevocationList::issue(&vendor(), t0, vec![]);
        std::fs::write(
            RevocationList::path_for(&store),
            serde_json::to_string(&forged).unwrap(),
        )
        .unwrap();
        let err = activate_signed_token(&lic.encode(), &store, &k.verifying(), t0 + 1_000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("revocation list"), "{err}");
        // 换成真的 CRL,撤掉它 → Free / Revoked。
        let crl = RevocationList::issue(
            &k,
            t0,
            vec![RevokedLicense {
                license_id: "acme-1".into(),
                max_serial: None,
            }],
        );
        std::fs::write(
            RevocationList::path_for(&store),
            serde_json::to_string(&crl).unwrap(),
        )
        .unwrap();
        let (ent, st) =
            activate_signed_token(&lic.encode(), &store, &k.verifying(), t0 + 1_000).unwrap();
        assert_eq!(st, LicenseStatus::Revoked);
        assert_eq!(ent.plan, PlanTier::Free);
    }

    #[test]
    fn base64url往返与坏输入() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
            let enc = base64url(&data);
            assert!(!enc.contains('=') && !enc.contains('+') && !enc.contains('/'));
            assert_eq!(base64url_decode(&enc).unwrap(), data, "n={n}");
        }
        assert!(base64url_decode("a").is_err());
        assert!(base64url_decode("ab$c").is_err());
        assert!(SignedLicense::decode("nope").is_err());
        assert!(SignedLicense::decode("agl1.!!!").is_err());
    }
}
