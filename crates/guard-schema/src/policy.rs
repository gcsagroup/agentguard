//! GuardContract policy: LOW/HIGH tiers and enforcement modes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Parsed, but says something that cannot hold — e.g. a plan clause naming a
    /// step the plan forbids, which would read as a constraint while being
    /// unreachable.
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Privacy data tier aligned with MyPhoneBench iMy LOW/HIGH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataTier {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Allow,
    Deny,
    Ask,
    Alert,
    Block,
    RequireConfirm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardContract {
    pub policy_id: String,
    pub version: String,
    #[serde(default)]
    pub low_keys: Vec<String>,
    #[serde(default)]
    pub high_keys: Vec<String>,
    pub on_high_access: EnforcementMode,
    pub on_optional_pii_fill: EnforcementMode,
    pub on_trap_widget_fill: EnforcementMode,
    pub on_memory_write: EnforcementMode,
    /// Aura §4.3.1 No-Write-Down: untrusted (`TAG_TAINTED`) content populating a
    /// parameter of a Critical Node — the injection-to-action path. This is the
    /// paper's rule of that name; the confidentiality rule below is ours.
    #[serde(default = "default_flow_mode")]
    pub on_no_write_down: EnforcementMode,
    /// Our confidentiality rule: a value whose confidentiality exceeds the sink's
    /// clearance. `Block`/`Ask` actually *enforces* the lattice; the previous
    /// alert-only `PRIV-XAPP` behaviour is `Alert`, and is not enforcement.
    #[serde(default = "default_flow_mode")]
    pub on_confidentiality_downgrade: EnforcementMode,
    /// A declared flow whose value has no provenance label, or no `value_id` at
    /// all. Fails **closed**: leaving it on `Alert` meant the entire lattice could
    /// be bypassed by simply not naming the value, and no deployment had a knob to
    /// tighten it. Only `data_flow` events are affected — an adapter that emits no
    /// flows is untouched — so failing closed costs nothing it should not cost.
    #[serde(default = "default_flow_mode")]
    pub on_unlabelled_flow: EnforcementMode,
    /// Aura §4.3.2: a step that cannot be justified against the declared task plan.
    ///
    /// `Alert` by default. The plan library is new and incomplete, and a wrong plan
    /// blocks legitimate work — an over-strict `order` clause would stop a real
    /// booking mid-flow. Alerting first lets an operator see what their plans
    /// actually reject before it costs anyone a task; tighten to `Ask`/`Block` once
    /// the library has been through real traffic.
    #[serde(default = "default_drift_mode")]
    pub on_plan_drift: EnforcementMode,
    /// Aura §4.2: observed content forging an origin or a conversation turn boundary.
    ///
    /// `Alert` by default, and the reason is a boundary rather than caution. The guard
    /// does not build the agent's prompt, so it cannot know whether this content will
    /// reach a model inside an isolation envelope (where the markers are inert) or
    /// concatenated raw (where they are the attack). Blocking the *event* would refuse a
    /// screen for what the host might do with it. Alerting names the content and lets
    /// the taint lattice do the enforcing: the value is `Tainted`, so it cannot
    /// authorise a critical action either way.
    #[serde(default = "default_drift_mode")]
    pub on_context_breakout: EnforcementMode,
    /// AgentScan §3.7: screen text shaped to read differently to a model than it renders to
    /// a person — invisible characters, bidi overrides, homoglyphs, glitch tokens.
    ///
    /// `Alert` by default, and for a different reason than the breakout knob's. This is
    /// evidence about the *screen*, not about an action: nothing here says the agent is about
    /// to do something wrong, only that what it read is not what the user saw. Blocking the
    /// event would refuse a page for how it is encoded; naming it lets a human decide, and
    /// the taint lattice already refuses to let that content authorise anything critical.
    #[serde(default = "default_drift_mode")]
    pub on_text_anomaly: EnforcementMode,
}

fn default_drift_mode() -> EnforcementMode {
    EnforcementMode::Alert
}

fn default_flow_mode() -> EnforcementMode {
    EnforcementMode::RequireConfirm
}

impl Default for GuardContract {
    fn default() -> Self {
        Self {
            policy_id: "standard".into(),
            version: "1.0".into(),
            // Ordinary, non-identifying task fields.
            //
            // This list was three entries, and `flow_tier_for_key` fails closed to
            // High for anything unlisted — so the very field a task exists to fill
            // (`destination` for a navigation task, `check_in` for a booking) was
            // classified as a HIGH-tier disclosure. On the trajectory axis that made
            // four out of four ordinary flows trip their own plan: a plan that
            // rejects the task it describes.
            //
            // Fail-closed on genuinely unknown keys is still right — an unrecognised
            // field is more likely to be sensitive than not — but "unknown" has to
            // mean unknown, not "we never bothered to list the obvious ones".
            low_keys: vec![
                "name".into(),
                "food_preference".into(),
                "language".into(),
                "destination".into(),
                "origin".into(),
                "check_in".into(),
                "check_out".into(),
                "guest_count".into(),
                "quantity".into(),
                "order_note".into(),
                "search_query".into(),
                "loyalty_tier".into(),
                "seat_preference".into(),
                "diet_note".into(),
            ],
            high_keys: vec![
                "phone_number".into(),
                "email".into(),
                "id_number".into(),
                "home_address".into(),
                "payment_info".into(),
                "date_of_birth".into(),
                "passport_number".into(),
                // 这三个是 `docs/information-flow.md` 点名的那三个,而它们一直不在这张表里。
                //
                // 后果比"少一条告警"更具体:`decide_high_access` 和跨应用支点检查都按这张表
                // 判 tier,于是在 `Booking` 里填一张信用卡号、再在 `RandomSMSApp` 里填同一个
                // 键,判决是 `Allow` —— 没有告警,审计里没有 finding。`payment_info` 在表里
                // 而 `credit_card_number` 不在,只是命名的偶然。
                "credit_card_number".into(),
                "social_security_number".into(),
                "medical_record_id".into(),
            ],
            on_high_access: EnforcementMode::RequireConfirm,
            on_optional_pii_fill: EnforcementMode::Alert,
            on_trap_widget_fill: EnforcementMode::Block,
            on_memory_write: EnforcementMode::RequireConfirm,
            on_no_write_down: default_flow_mode(),
            on_confidentiality_downgrade: default_flow_mode(),
            on_unlabelled_flow: default_flow_mode(),
            on_plan_drift: default_drift_mode(),
            on_context_breakout: default_drift_mode(),
            on_text_anomaly: default_drift_mode(),
        }
    }
}

impl GuardContract {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Tier for the OP / scoring path. `Low` for anything not listed, matching
    /// MyPhoneBench's two-tier profile model, which is where these semantics come
    /// from. Do **not** use this to decide a flow: see
    /// [`Self::flow_confidentiality_for_key`].
    pub fn tier_for_key(&self, key: &str) -> DataTier {
        if self.high_keys.iter().any(|k| k == key) {
            DataTier::High
        } else {
            DataTier::Low
        }
    }

    /// Whether `key` is one this contract has actually classified.
    pub fn key_is_classified(&self, key: &str) -> bool {
        self.high_keys.iter().any(|k| k == key) || self.low_keys.iter().any(|k| k == key)
    }

    /// Tier for the *information-flow* path, which fails **closed**.
    ///
    /// `tier_for_key` treats every unlisted key as `Low`, which is right for
    /// scoring — the paper's model has two tiers and an unlisted field is not
    /// evidence of over-collection. For a flow decision it is wrong in the unsafe
    /// direction: the default `high_keys` list has seven entries, so
    /// `social_security_number`, `credit_card_number` and `medical_record_id` were
    /// all `Low`, and a LOW-clearance sink accepted them silently. An unrecognised
    /// profile key is treated as `High` here: the cost of being wrong is a confirm
    /// prompt, versus an unprompted disclosure.
    pub fn flow_tier_for_key(&self, key: &str) -> DataTier {
        if self.key_is_classified(key) {
            self.tier_for_key(key)
        } else {
            DataTier::High
        }
    }
}

/// Known-app registry (AgentScan system layer).
///
/// AgentScan reports package-name forgery succeeding against **all four**
/// system-interacting agents it tested, and the reason is structural: a package
/// name is a string the attacker chooses. An `apps:` list keyed on that string
/// gates nothing. Registered apps therefore carry **signer digests** — the
/// SHA-256 of the signing certificate — and an app's identity is its signer, not
/// its name. See docs/app-identity.md for what actually produces the digest on
/// each platform, and for the trust boundary that remains.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownAppsPolicy {
    #[serde(default)]
    pub apps: Vec<KnownApp>,
    /// Whether a registered app must present a verified signing certificate before
    /// it inherits its privileges.
    ///
    /// **Off by default, and that is not timidity — it is what the adapters can
    /// currently deliver.** Only the Android companion reads a digest from the OS;
    /// the desktop shells and the browser host send no `package` at all. Turning
    /// enforcement on globally would alert on every UI event from a registered app
    /// and block its own deeplinks — the shipped companion's normal traffic — which
    /// is how a security feature gets switched off for good.
    ///
    /// With it **off**: identity is still resolved and reported, impersonation
    /// (`APP-SIGNER-MISMATCH`, `APP-NAME-MISMATCH`) is still blocked, and a missing
    /// attestation falls back to the pre-existing name/package match for the
    /// deeplink allow-list. It never grants HIGH-tier flow clearance.
    ///
    /// With it **on**: an unattested app inherits nothing. Turn it on once every
    /// adapter in the deployment attests.
    #[serde(default)]
    pub require_attestation: bool,
    /// Lazily-built appearance index. See [`KnownAppsPolicy::faces`].
    #[serde(skip)]
    faces: LazyFaces,
}

/// A `OnceLock` that can live inside a `Clone` + `Default` policy struct.
///
/// Cloning yields an **empty** cache rather than a copy: the clone rebuilds on first use, which is
/// correct because the cache is derived entirely from `apps`. The field is `#[serde(skip)]`, so
/// serde never touches it — `Default` is all it needs, and the `PartialEq`/`Serialize`/`Deserialize`
/// impls an earlier version carried were dead code describing a struct `KnownAppsPolicy` is not
/// (it derives no `PartialEq`).
///
/// **Invariant:** `KnownAppsPolicy::apps` must not be mutated after [`KnownAppsPolicy::faces`] has
/// run, or the index goes stale. `apps` is `pub` for construction and inspection; nothing in this
/// workspace mutates it post-load, and a caller that needs to should rebuild the policy.
#[derive(Debug, Default)]
pub struct LazyFaces(std::sync::OnceLock<crate::visual::FaceIndex>);

impl Clone for LazyFaces {
    fn clone(&self) -> Self {
        Self(std::sync::OnceLock::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownApp {
    /// Display name, for messages. **Never** an identity: a name match is what the
    /// forgery attack exploits, so `identify` will not resolve an app by name.
    pub name: String,
    /// Allowed deeplink prefixes, e.g. `imeituan://` or `https://www.amap.com/`.
    #[serde(default)]
    pub deeplink_prefixes: Vec<String>,
    /// Package / bundle identifiers, matched **exactly** (case-insensitively).
    /// Substring matching let `com.sankuai.meituan.evil` inherit Meituan's
    /// deeplink allow-list.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Accepted signing-certificate digests: lowercase hex SHA-256, no separators.
    ///
    /// An app with an empty list can never be `Verified` — it is registered but
    /// unattestable, which is reported rather than quietly treated as fine.
    #[serde(default)]
    pub signers: Vec<String>,
    /// Display names this app legitimately presents, besides [`Self::name`]: the
    /// localised ones above all (`微信` for WeChat, `美团` for Meituan).
    ///
    /// This is the **accusation** side of identity, not the trust side — see
    /// [`crate::visual`]. An entry here can only ever make an app that is *not* this
    /// app into a finding; it never makes an app into this app.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Difference hashes of this app's published icon, as 16 hex characters (case-insensitive).
    ///
    /// A list because an app ships more than one icon over its life and a registry
    /// pinning only the current one goes stale silently. The exact algorithm is
    /// normative and documented on [`crate::visual::IconHash`]; `guard-cli icon-dhash`
    /// computes it.
    #[serde(default)]
    pub icon_dhash: Vec<String>,
}

impl KnownApp {
    /// Every display name this app declares, folded for comparison.
    ///
    /// Computed on demand rather than cached in a `#[serde(skip)]` field: a cached
    /// field is populated by a normalisation step, and this registry is constructed
    /// in five places (CLI, local API, FFI, native-messaging host, eval) — the one
    /// that forgot to normalise would get an app with no faces and no error, which is
    /// exactly the silent-disablement failure this project keeps finding. The registry
    /// is a handful of entries and the fold is linear, so recomputing is cheaper than
    /// the bug.
    pub fn folded_labels(&self) -> Vec<String> {
        // **Opt-in.** An entry that declares neither `labels:` nor `icon_dhash:` is registered for
        // its package, its signer and its deeplink allow-list, and is claiming no appearance at
        // all. Including [`Self::name`] regardless armed an accusation template out of every such
        // entry: a registry with a deeplink-only `Settings` entry made the *real* Android Settings
        // app a Critical block with `require_confirm`, because `folded_labels` returned `settings`
        // while `validate_faces` reasoned the entry had opted into nothing.
        if !self.declares_appearance() {
            return Vec::new();
        }
        // Sub-floor and over-long labels are **dropped**, not returned-and-ignored. `label_match`
        // refuses both, so keeping `amap` (weight 4) or a 65-character label in this list would
        // mean `validate_faces` saw a protectable face where none exists.
        let mut out: Vec<String> = std::iter::once(&self.name)
            .chain(self.labels.iter())
            .map(|l| crate::visual::fold_label(l))
            .filter(|f| {
                crate::visual::label_weight(f) >= crate::visual::MIN_LABEL_WEIGHT
                    && f.chars().count() <= crate::visual::MAX_FOLDED_LEN
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Parsed icon hashes. Malformed entries are **dropped**, and
    /// [`Self::malformed_icon_hashes`] reports them so a loader can refuse.
    pub fn icon_hashes(&self) -> Vec<crate::visual::IconHash> {
        self.icon_dhash
            .iter()
            .filter_map(|h| crate::visual::IconHash::parse(h))
            .collect()
    }

    /// Registry `icon_dhash` entries that are not 16 hex characters, or that are
    /// degenerate enough to match every flat icon.
    ///
    /// Returned rather than ignored on the same principle as the fixture warning at the
    /// top of `known-apps.yaml`: a registry entry that silently does nothing looks like
    /// coverage. A degenerate *registered* hash is worse than a missing one, because it
    /// would accuse every app with a flat icon.
    pub fn malformed_icon_hashes(&self) -> Vec<String> {
        self.icon_dhash
            .iter()
            .filter(|h| crate::visual::IconHash::parse(h).is_none_or(|p| p.is_degenerate()))
            .cloned()
            .collect()
    }

    /// Whether this entry claims appearance protection at all (AgentScan §3.6).
    ///
    /// Declaring a `labels:` alias or an `icon_dhash:` is the opt-in. Without one, the entry's
    /// display name is not an accusation template and [`Self::folded_labels`] is empty.
    pub fn declares_appearance(&self) -> bool {
        !self.labels.is_empty() || !self.icon_dhash.is_empty()
    }

    pub fn accepts_signer(&self, digest: &str) -> bool {
        let Some(d) = canonical_digest(digest) else {
            return false;
        };
        self.signers
            .iter()
            .filter_map(|s| canonical_digest(s))
            .any(|s| s == d)
    }

    pub fn owns_package(&self, package: &str) -> bool {
        let p = package.trim().to_lowercase();
        !p.is_empty() && self.packages.iter().any(|k| k.trim().to_lowercase() == p)
    }
}

/// Signing digests are written with separators in most tooling output
/// (`AA:BB:CC…` from `keytool`, `apksigner`, `codesign`). Strip formatting so a
/// policy file that pastes tool output works unchanged.
pub fn normalize_digest(d: &str) -> String {
    d.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A digest normalised **and** validated as 64 lowercase hex characters, i.e. a
/// SHA-256. `None` for anything else.
///
/// Without this, any non-empty string was a usable digest: the engine's own test
/// pinned `"aa11"` and it verified, and a policy file could pin 64 `z`s. A
/// four-character "certificate digest" is trivially guessable, and a
/// non-hex one cannot be a digest at all — accepting either turns identity
/// verification into a string-equality check on a shared secret nobody chose.
pub fn canonical_digest(d: &str) -> Option<String> {
    let n = normalize_digest(d);
    (n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit())).then_some(n)
}

/// The outcome of resolving an app's identity. Every variant that is not
/// [`AppIdentity::Verified`] is a *reason*, so a decision can explain itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppIdentity {
    /// Package and signer both check out, but the app is presenting a *display
    /// name* the registry does not associate with that package. Identity is
    /// consumed per name in places that only have a name (a flow sink), so an app
    /// calling itself `Booking` while attesting Meituan's package and Meituan's
    /// (public) certificate would otherwise inherit Booking's clearance.
    NameMismatch {
        name: String,
        claimed: String,
        package: String,
    },
    /// Package is registered **and** the attested signer is one this app's entry
    /// accepts. The only variant that may inherit an app's privileges.
    Verified { name: String, package: String },
    /// The package claims to be a registered app, but the signer does not match.
    /// This is the forgery attack itself, caught: an APK named
    /// `com.sankuai.meituan` signed by someone who is not Meituan.
    SignerMismatch {
        name: String,
        package: String,
        got: String,
    },
    /// Registered package, but no signer digest was attested — the adapter did not
    /// (or could not) query the platform. Not an attack, and not a verification
    /// either; callers must not treat it as one.
    Unattested { name: String, package: String },
    /// Registered package whose entry lists no signers, so verification is
    /// impossible by construction. A registry gap, reported as such.
    NoSignerOnRecord { name: String, package: String },
    /// Not in the registry.
    Unregistered { package: String },
    /// 签名摘要**对上了**,但携带它的适配器自己没有被验证 —— 所以这不构成证明。
    ///
    /// 应用签名证书摘要是**公开**的:从发布的应用里就能提出来。它是标识符,不是
    /// 秘密。于是"事件里带了正确的摘要"这件事,任何拿到 API 令牌的调用方都做得到,
    /// 那正是 AgentScan 那个包名伪造,只换了一层 —— 从"攻击者随便填一个包名"
    /// 变成"攻击者填一个查得到的摘要"。
    ///
    /// 名字仍然给出来(`app_name()` 返回 `Some`),所以这个身份**照样**受该应用
    /// 自己的允许表约束 —— 只是不继承它的特权。这是那条不对称规则在应用身份上的
    /// 同一副面孔:未经验证的断言可以升高风险,不能授予信任。
    AttestationUnverified {
        name: String,
        package: String,
        /// 携带这条断言的适配器身份,用于解释为什么不算验证过。
        carrier: String,
    },
}

impl AppIdentity {
    /// Only a verified identity may inherit a registered app's privileges —
    /// its deeplink allow-list, or HIGH-tier sink clearance.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// 这次**看到过一个对得上的签名摘要** —— 不管携带它的适配器验没验过。
    ///
    /// 和 `is_verified()` 分开,是因为两者管的是两个方向:
    ///
    ///   - `is_verified()`:能不能**继承**这个应用的特权。要求摘要有可信来源。
    ///   - `had_matching_digest()`:之前有没有钉住过一个摘要。用来发现**换人** ——
    ///     同一个包先出示 A 后出示 B,那个「变」本身就是证据,和谁送来的无关。
    ///
    /// 这个区分是被自己的评测集抓出来的。把 `AttestationUnverified` 引进来的时候
    /// 漏了这一条,于是 `prev.is_verified()` 变成 false,**中途换签名者不再被发现** ——
    /// 一个修复换来了另一个洞。那正是这个项目反复警惕的形状:
    /// 证据**反对**一个声明的时候,谁送来的都算。
    pub fn had_matching_digest(&self) -> bool {
        matches!(
            self,
            Self::Verified { .. } | Self::AttestationUnverified { .. }
        )
    }

    /// The registry's own name for this app, when the package resolved *and* the
    /// presented name agrees with it. This — never `event.source_app` — is what a
    /// name-keyed lookup may trust.
    pub fn verified_name(&self) -> Option<&str> {
        match self {
            Self::Verified { name, .. } => Some(name),
            _ => None,
        }
    }

    /// True when the evidence positively contradicts the claimed identity.
    pub fn is_impersonation(&self) -> bool {
        matches!(
            self,
            Self::SignerMismatch { .. } | Self::NameMismatch { .. }
        )
    }

    pub fn package(&self) -> &str {
        match self {
            Self::Verified { package, .. }
            | Self::NameMismatch { package, .. }
            | Self::SignerMismatch { package, .. }
            | Self::Unattested { package, .. }
            | Self::NoSignerOnRecord { package, .. }
            | Self::AttestationUnverified { package, .. }
            | Self::Unregistered { package } => package,
        }
    }

    /// Registered app name, when the package resolved to one.
    pub fn app_name(&self) -> Option<&str> {
        match self {
            Self::Verified { name, .. }
            | Self::NameMismatch { name, .. }
            | Self::SignerMismatch { name, .. }
            | Self::Unattested { name, .. }
            | Self::NoSignerOnRecord { name, .. }
            // 名字照样给出来:这个身份**仍然**受该应用自己的允许表约束,
            // 只是不继承它的特权。返回 None 会让它掉进"未注册"那条路,
            // 反而绕开了允许表 —— 更宽松,不是更严。
            | Self::AttestationUnverified { name, .. } => Some(name),
            Self::Unregistered { .. } => None,
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Verified { name, package } => {
                format!("'{package}' verified as {name} by signing certificate")
            }
            Self::NameMismatch {
                name,
                claimed,
                package,
            } => format!(
                "'{package}' is verifiably {name} but presents itself as '{claimed}'; a name-keyed privilege must not follow the presented name"
            ),
            Self::SignerMismatch { name, package, got } => format!(
                "'{package}' claims to be {name} but is signed by {got}, which {name} does not use (package-name forgery)"
            ),
            Self::Unattested { name, package } => format!(
                "'{package}' matches {name} but no signing certificate was attested; identity unverified"
            ),
            Self::NoSignerOnRecord { name, package } => format!(
                "'{package}' matches {name}, which has no signer digest on record; identity cannot be verified"
            ),
            Self::AttestationUnverified {
                name,
                package,
                carrier,
            } => format!(
                "'{package}' attested a signing certificate that matches {name}, but the assertion came from an unverified adapter ({carrier}); app signing digests are public, so an attested digest alone proves nothing. Held to {name}'s own allow-list, inherits none of its privileges."
            ),
            Self::Unregistered { package } => format!("'{package}' is not a registered app"),
        }
    }
}

impl KnownAppsPolicy {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(yaml)?;
        policy.validate_faces()?;
        Ok(policy)
    }

    /// Reject a registry whose declared appearance cannot work.
    ///
    /// Three failures, all of which would otherwise be silent:
    ///
    /// * a malformed or degenerate `icon_dhash` (see [`KnownApp::malformed_icon_hashes`]) — a
    ///   typo'd digest that quietly never matches reads as coverage, and a degenerate one would
    ///   accuse every app with a flat icon;
    /// * two entries whose folded labels collide — they would accuse each other on every event,
    ///   since neither is the other's own entry;
    /// * an entry with **no protectable face at all**: no label above
    ///   [`crate::visual::MIN_LABEL_WEIGHT`] and no icon hash. This is the check that keeps
    ///   raising the weight floor from being a silent loss — `AMap` is four characters and is no
    ///   longer protectable by label, so the registry must say how it *is* protected.
    fn validate_faces(&self) -> Result<(), PolicyError> {
        for app in &self.apps {
            let bad = app.malformed_icon_hashes();
            if !bad.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "app '{}' has unusable icon_dhash entries {bad:?}: each must be 16 hex \
                     characters and must not be a flat-icon hash (see visual::IconHash)",
                    app.name
                )));
            }
            // Only entries that **opt in** to appearance protection are held to it. A registry
            // that wants package + signer + deeplink protection and nothing else is a legitimate
            // registry, and the first version of this check rejected those — the mechanism
            // deciding for the operator.
            //
            // For those that do opt in, the requirement is a face that can produce an
            // **intervention**, which means a label. An icon-only face satisfied the first version
            // of this check and cannot ever block: icon evidence is advisory, because its
            // false-match rate is measured at 6.6% over unrelated simple icons. So `AMap` —
            // four Latin letters, below the information floor, with an icon — passed the "no
            // usable face" net while having no interventional protection against the paper's exact
            // attack, and the docs claimed its icon protected it.
            if app.declares_appearance() && app.folded_labels().is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "app '{}' declares an appearance and has no label that can produce a finding: \
                     every candidate folds to less than visual::MIN_LABEL_WEIGHT of information (a \
                     four-letter Latin name does) or exceeds visual::MAX_FOLDED_LEN. An \
                     icon_dhash alone is not enough — icon evidence is advisory and never blocks. \
                     Add a longer localised label (`labels: [\"高德地图\"]`), or drop the \
                     appearance declaration and rely on the package and signer.",
                    app.name
                )));
            }
        }
        // Collision detection in near-linear time. The first version compared every folded label
        // against every other with `label_match`, which is O(apps² · labels²) and took **24 s**
        // to load a 2000-app registry — and a registry is loaded on every `guard-cli` run and
        // every `guard-nm-host` spawn, which Chrome does once per native-messaging connection.
        // `label_match` only accepts an exact match or one of two typo shapes, and both shapes
        // have O(n) variants, so the whole question is answerable with a map.
        // Two entries may not share a `name`. `FaceIndex` resolves an app by name, so a duplicate
        // makes the second entry impersonate *itself*: measured, two entries both named
        // "Acme Wallet" produced `Impersonation { registered: "Acme Wallet", actual:
        // Some("Acme Wallet") }` at Block/Critical, self-blocking the genuine app. An operator
        // listing an app twice for a key rotation or a staged package migration would hit it.
        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for app in &self.apps {
            if !names.insert(app.name.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "two registered apps share the name '{}'. Identity is resolved by name, so the \
                     second entry would be reported as impersonating itself. Merge them — \
                     `packages:` and `signers:` are both lists.",
                    app.name
                )));
            }
        }
        // Two maps, and never variant-against-variant. `label_match(a, b)` holds when `a == b`
        // or when one is a typo-variant of the other — it does **not** hold merely because both
        // share a variant, and the first version of this check compared variant sets, so
        // `Zetaaaa…` and `Zetaaap…` were rejected for both having the variant `zetaaaap…` while
        // the runtime rule would never have matched them.
        let mut exacts: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
        let mut variants: std::collections::HashMap<String, &str> =
            std::collections::HashMap::new();
        let collide = |other: &str, app: &str, form: &str| -> Result<(), PolicyError> {
            if other == app {
                return Ok(());
            }
            Err(PolicyError::Invalid(format!(
                "registered apps '{other}' and '{app}' have display names that fold onto each \
                 other ({form:?}); they would accuse each other of impersonation on every event"
            )))
        };
        for app in &self.apps {
            let name = app.name.as_str();
            for folded in app.folded_labels() {
                if let Some(other) = exacts.get(folded.as_str()) {
                    collide(other, name, &folded)?;
                }
                if let Some(other) = variants.get(folded.as_str()) {
                    collide(other, name, &folded)?;
                }
                for v in crate::visual::typo_variants(&folded) {
                    if let Some(other) = exacts.get(v.as_str()) {
                        collide(other, name, &v)?;
                    }
                }
                exacts.insert(folded.clone(), name);
                for v in crate::visual::typo_variants(&folded) {
                    variants.entry(v).or_insert(name);
                }
            }
        }
        Ok(())
    }

    /// Folded labels and parsed icon hashes for the whole registry, computed once.
    ///
    /// Lazily built rather than produced by a normalisation step the five construction sites
    /// (CLI, local API, FFI, native-messaging host, eval) could each forget — that failure mode
    /// is why `KnownApp::folded_labels` recomputes. But recomputing it *per event* was the wrong
    /// end of the trade: `resolve_appearance` rebuilt the entire registry — folding every name
    /// and re-parsing every hex hash — on every event carrying a `package`, i.e. on every
    /// accessibility frame, measured at 8.9 ms/event on a 2000-app registry. Lazy caching keeps
    /// both properties: nothing to forget, nothing repeated.
    fn faces(&self) -> &crate::visual::FaceIndex {
        self.faces.0.get_or_init(|| {
            let owned: Vec<(String, Vec<String>, Vec<crate::visual::IconHash>)> = self
                .apps
                .iter()
                .map(|a| (a.name.clone(), a.folded_labels(), a.icon_hashes()))
                .collect();
            crate::visual::FaceIndex::build(owned.iter().map(|(name, folded, icons)| {
                crate::visual::RegisteredFace {
                    name,
                    folded,
                    icons,
                }
            }))
        })
    }

    /// What an observed appearance says about an app, given the registry.
    ///
    /// `own` carries both the registered name the **package** belongs to and how that is known
    /// — see [`crate::visual::OwnIdentity`]. Passing a label-derived name here would make the
    /// check circular and turn a forged label into a clean bill of health, which is the one
    /// direction [`crate::visual`] forbids.
    pub fn resolve_appearance(
        &self,
        label: Option<&str>,
        icon: Option<&crate::visual::IconHash>,
        own: crate::visual::OwnIdentity<'_>,
    ) -> crate::visual::Appearance {
        crate::visual::Appearance::resolve_indexed(label, icon, own, self.faces())
    }

    /// Resolve an app's identity from its **package** and attested signer digests.
    ///
    /// Deliberately takes no display name. Resolving by name is the forgery, and
    /// keeping the name out of the signature makes that unrepresentable rather than
    /// merely discouraged.
    ///
    /// `attested` is a list because multiple signers are normal: an APK can be
    /// signed by several certificates, and a publisher that has rotated its key
    /// presents the new one while the registry may still pin the old (or both).
    /// **Any** attested digest matching **any** accepted digest verifies; accepting
    /// only the first would fail legitimately-rotated apps, and the failure would
    /// look like an attack.
    pub fn identify(&self, package: &str, attested: &[String]) -> AppIdentity {
        self.identify_as(package, None, attested)
    }

    /// [`Self::identify`] plus a consistency check on the display name the app
    /// presents. `presented` is `event.source_app`: untrusted, and therefore
    /// checked *against* the registry rather than used to look anything up.
    pub fn identify_as(
        &self,
        package: &str,
        presented: Option<&str>,
        attested: &[String],
    ) -> AppIdentity {
        let id = self.identify_inner(package, attested);
        match (&id, presented) {
            (AppIdentity::Verified { name, package }, Some(p))
                if !p.trim().is_empty()
                    && !p.eq_ignore_ascii_case(name)
                    && !p.eq_ignore_ascii_case(package) =>
            {
                AppIdentity::NameMismatch {
                    name: name.clone(),
                    claimed: p.to_string(),
                    package: package.clone(),
                }
            }
            _ => id,
        }
    }

    fn identify_inner(&self, package: &str, attested: &[String]) -> AppIdentity {
        let pkg = package.trim().to_string();
        let Some(app) = self.apps.iter().find(|a| a.owns_package(&pkg)) else {
            return AppIdentity::Unregistered { package: pkg };
        };
        if app.signers.is_empty() {
            return AppIdentity::NoSignerOnRecord {
                name: app.name.clone(),
                package: pkg,
            };
        }
        let digests: Vec<String> = attested
            .iter()
            .filter_map(|d| canonical_digest(d))
            .collect();
        if digests.is_empty() {
            return AppIdentity::Unattested {
                name: app.name.clone(),
                package: pkg,
            };
        }
        if digests.iter().any(|d| app.accepts_signer(d)) {
            AppIdentity::Verified {
                name: app.name.clone(),
                package: pkg,
            }
        } else {
            AppIdentity::SignerMismatch {
                name: app.name.clone(),
                package: pkg,
                got: digests.join(", "),
            }
        }
    }

    /// The registered entry for an already-resolved identity.
    pub fn app_for(&self, identity: &AppIdentity) -> Option<&KnownApp> {
        self.apps
            .iter()
            .find(|a| a.owns_package(identity.package()))
    }

    /// Name/package substring resolution — **the forgeable path**.
    ///
    /// This is what the registry did before signer pinning existed, and it is kept
    /// for exactly one purpose: with `require_attestation: false`, an app that
    /// attests nothing should still be held to its *own* deeplink allow-list, as it
    /// was before. Removing it silently downgraded `DL-ALLOWLIST` (High block) to
    /// `DL-UNKNOWN` (Medium alert) for every event from an adapter that sends no
    /// `package` — i.e. every desktop and browser event.
    ///
    /// It must never grant a privilege that identity is supposed to gate: no
    /// HIGH-tier flow clearance, and no bypass of an impersonation verdict.
    pub fn find_app_unverified(&self, presented: &str) -> Option<&KnownApp> {
        let needle = presented.to_lowercase();
        self.apps.iter().find(|a| {
            !a.name.is_empty()
                && (needle.contains(&a.name.to_lowercase())
                    || a.packages
                        .iter()
                        .any(|p| needle.contains(&p.to_lowercase())))
        })
    }

    /// Extract a canonical deeplink prefix `scheme://host/` (or `scheme://`) from a URI.
    pub fn deeplink_matches(uri: &str, prefix: &str) -> bool {
        uri.to_lowercase().starts_with(&prefix.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tiers() {
        let c = GuardContract::default();
        assert_eq!(c.tier_for_key("phone_number"), DataTier::High);
        assert_eq!(c.tier_for_key("name"), DataTier::Low);
    }

    #[test]
    fn known_apps_lookup_and_deeplink_prefix() {
        let yaml = r#"
apps:
  - name: AMap
    packages: ["com.autonavi.minimap"]
    deeplink_prefixes: ["amapuri://", "androidamap://", "https://www.amap.com/"]
  - name: Meituan
    packages: ["com.sankuai.meituan"]
    deeplink_prefixes: ["imeituan://"]
"#;
        let p = KnownAppsPolicy::from_yaml_str(yaml).unwrap();
        let amap = p
            .apps
            .iter()
            .find(|a| a.owns_package("com.autonavi.minimap"))
            .unwrap();
        assert!(KnownAppsPolicy::deeplink_matches(
            "amapuri://route/plan?dl=1",
            &amap.deeplink_prefixes[0]
        ));
        assert!(!KnownAppsPolicy::deeplink_matches(
            "evil-scheme://steal",
            &amap.deeplink_prefixes[0]
        ));
        // Package ownership is exact; a clone package owns nothing.
        assert!(
            amap.owns_package("COM.AUTONAVI.MINIMAP"),
            "case-insensitive"
        );
        assert!(!amap.owns_package("com.malicious.clone"));
        assert!(!amap.owns_package("com.autonavi.minimap.evil"));
    }

    fn registry() -> KnownAppsPolicy {
        KnownAppsPolicy::from_yaml_str(
            r#"
apps:
  - name: Meituan
    packages: ["com.sankuai.meituan"]
    signers: ["AA:BB:CC:11:22:33:AA:BB:CC:11:22:33:AA:BB:CC:11:22:33:AA:BB:CC:11:22:33:AA:BB:CC:11:22:33:AA:BB", "ddeeff445566ddeeff445566ddeeff445566ddeeff445566ddeeff445566ddee"]
    deeplink_prefixes: ["imeituan://"]
  - name: LegacyPOS
    packages: ["com.example.legacypos"]
    signers: []
"#,
        )
        .unwrap()
    }

    fn digests(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const ACCEPTED: &str = "aabbcc112233aabbcc112233aabbcc112233aabbcc112233aabbcc112233aabb";
    const ROTATED: &str = "ddeeff445566ddeeff445566ddeeff445566ddeeff445566ddeeff445566ddee";

    /// The forgery AgentScan reports working against all four agents it tested:
    /// an APK installed under the registered package name.
    #[test]
    fn a_forged_package_name_does_not_verify() {
        let r = registry();
        let id = r.identify("com.sankuai.meituan", &digests(&[&"9".repeat(64)]));
        assert!(id.is_impersonation(), "{id:?}");
        assert!(!id.is_verified());
        assert_eq!(id.app_name(), Some("Meituan"));
        assert!(
            id.explain().contains("package-name forgery"),
            "{}",
            id.explain()
        );
    }

    /// Substring matching on the package let `com.sankuai.meituan.evil` inherit
    /// Meituan's deeplink allow-list.
    #[test]
    fn package_match_is_exact_not_substring() {
        let r = registry();
        for pkg in [
            "com.sankuai.meituan.evil",
            "evil.com.sankuai.meituan",
            "com.sankuai.meitua",
        ] {
            let id = r.identify(pkg, &digests(&[ACCEPTED]));
            assert!(
                matches!(id, AppIdentity::Unregistered { .. }),
                "{pkg} resolved to {id:?}"
            );
        }
        // …and the exact package, with an accepted signer, does verify.
        assert!(r
            .identify("com.sankuai.meituan", &digests(&[ACCEPTED]))
            .is_verified());
    }

    /// There is no way to resolve an app by its display name, by construction.
    #[test]
    fn a_display_name_is_never_an_identity() {
        let r = registry();
        assert!(matches!(
            r.identify("Meituan", &digests(&[ACCEPTED])),
            AppIdentity::Unregistered { .. }
        ));
    }

    /// Tool output has colons; the policy file should not have to be reformatted.
    #[test]
    fn digest_comparison_ignores_formatting_and_case() {
        let r = registry();
        for form in [
            ACCEPTED,
            &ACCEPTED.to_uppercase(),
            &ACCEPTED
                .as_bytes()
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).to_string())
                .collect::<Vec<_>>()
                .join(":"),
            &ACCEPTED
                .as_bytes()
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            assert!(
                r.identify("com.sankuai.meituan", &digests(&[form]))
                    .is_verified(),
                "{form}"
            );
        }
    }

    /// A rotated or multiply-signed APK presents several digests; any accepted one
    /// verifies. Taking only the first would fail a legitimate app and the failure
    /// would look like an attack.
    #[test]
    fn any_attested_digest_may_match_any_accepted_digest() {
        let r = registry();
        let id = r.identify("com.sankuai.meituan", &digests(&[&"0".repeat(64), ROTATED]));
        assert!(id.is_verified(), "{id:?}");
    }

    /// "Cannot verify" must never collapse into "verified". These are the two
    /// variants that used to be indistinguishable from a plain name match.
    #[test]
    fn unverifiable_is_its_own_answer() {
        let r = registry();
        let none = r.identify("com.sankuai.meituan", &[]);
        assert!(matches!(none, AppIdentity::Unattested { .. }), "{none:?}");
        assert!(!none.is_verified() && !none.is_impersonation());

        // Empty / whitespace digests are no attestation, not a failed one.
        let blank = r.identify("com.sankuai.meituan", &digests(&["", "   ", ":::"]));
        // Too short, too long, and non-hex are all "no attestation", not a failed
        // one: a four-character "certificate digest" is guessable, and the first cut
        // accepted any non-empty string.
        for junk in [
            &"ab".repeat(2),
            &"a".repeat(63),
            &"a".repeat(65),
            &"z".repeat(64),
        ] {
            let id = r.identify("com.sankuai.meituan", &digests(&[junk]));
            assert!(
                matches!(id, AppIdentity::Unattested { .. }),
                "{junk} → {id:?}"
            );
        }
        assert!(matches!(blank, AppIdentity::Unattested { .. }), "{blank:?}");

        // Registered with no signer on record: unverifiable by construction.
        let legacy = r.identify("com.example.legacypos", &digests(&[ACCEPTED]));
        assert!(
            matches!(legacy, AppIdentity::NoSignerOnRecord { .. }),
            "{legacy:?}"
        );
        assert!(!legacy.is_verified());
    }

    #[test]
    fn app_for_resolves_the_entry_behind_an_identity() {
        let r = registry();
        let id = r.identify("com.sankuai.meituan", &digests(&[ACCEPTED]));
        let app = r.app_for(&id).expect("entry");
        assert_eq!(app.deeplink_prefixes, vec!["imeituan://"]);
        assert!(r
            .app_for(&AppIdentity::Unregistered {
                package: "com.nope".into()
            })
            .is_none());
    }

    /// The registry that actually ships must not contain an entry that can never
    /// verify without saying so, and must not pin a digest that looks real.
    #[test]
    fn repo_registry_is_internally_consistent() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/known-apps.yaml");
        let raw = std::fs::read_to_string(&path).unwrap();
        let r = KnownAppsPolicy::from_yaml_str(&raw).unwrap();
        assert!(r.apps.len() >= 5);
        for app in &r.apps {
            assert!(!app.packages.is_empty(), "{} has no package", app.name);
            for s in &app.signers {
                assert!(
                    canonical_digest(s).is_some(),
                    "{} digest is not a 64-char hex SHA-256: {s}",
                    app.name
                );
            }
        }
        // The shipped digests are fixtures. Assert they *stay* obvious, so nobody
        // mistakes them for pinned production values — and so that pinning a real
        // one is a deliberate act that trips this test.
        let fixtures: Vec<&KnownApp> = r.apps.iter().filter(|a| !a.signers.is_empty()).collect();
        for app in fixtures {
            for s in &app.signers {
                let d = normalize_digest(s);
                let first = d.chars().next().unwrap();
                assert!(
                    d.chars().all(|c| c == first),
                    "{}'s digest {s} is not an obvious fixture; if it is a real pinned certificate, update this test and docs/app-identity.md",
                    app.name
                );
            }
        }
        assert!(
            raw.contains("FIXTURES, NOT REAL PUBLISHER CERTIFICATES"),
            "the registry must say plainly that its digests are fixtures"
        );
    }
}

#[cfg(test)]
mod visual_registry_tests {
    use super::*;
    use crate::visual::{Appearance, Evidence, IconHash, LabelMatch, OwnIdentity};

    const ICON_WECHAT: &str = "0f1e2d3c4b5a6978";

    fn registry() -> KnownAppsPolicy {
        KnownAppsPolicy::from_yaml_str(
            "apps:\n  \
             - name: WeChat\n    packages: [\"com.tencent.mm\"]\n    signers: [\"aa11\"]\n    \
             labels: [\"微信\"]\n    icon_dhash: [\"0f1e2d3c4b5a6978\"]\n  \
             - name: Meituan\n    packages: [\"com.sankuai.meituan\"]\n    signers: [\"bb22\"]\n    \
             labels: [\"美团\"]\n    icon_dhash: [\"123456789abcdef0\"]\n",
        )
        .unwrap()
    }

    /// The §3.6 attack: a package nobody registered, wearing a registered face.
    #[test]
    fn a_clone_is_reported_against_the_registry() {
        let r = registry();
        let icon = IconHash::parse(ICON_WECHAT).unwrap();
        let got = r.resolve_appearance(Some("微信"), Some(&icon), OwnIdentity::Unregistered);
        assert!(
            matches!(
                got,
                Appearance::Impersonation {
                    ref registered,
                    actual: None,
                    evidence: Evidence::Both { label: LabelMatch::Exact, distance: 0 },
                } if registered == "WeChat"
            ),
            "{got:?}"
        );
    }

    /// The normal path: the real app, **verified**.
    #[test]
    fn the_verified_real_app_is_consistent() {
        let r = registry();
        let icon = IconHash::parse(ICON_WECHAT).unwrap();
        assert_eq!(
            r.resolve_appearance(Some("微信"), Some(&icon), OwnIdentity::Verified("WeChat")),
            Appearance::Consistent
        );
        assert_eq!(
            r.resolve_appearance(Some("WeChat"), None, OwnIdentity::Verified("WeChat")),
            Appearance::Consistent
        );
    }

    /// A package that merely *claims* WeChat's entry and wears WeChat's face is not consistent —
    /// it is unprovable. Collapsing this into `Consistent` is what let a clone forge the package
    /// name and be downgraded from a Critical block to a Low log line.
    #[test]
    fn a_claimed_but_unproven_own_entry_is_unprovable() {
        let r = registry();
        let icon = IconHash::parse(ICON_WECHAT).unwrap();
        assert_eq!(
            r.resolve_appearance(Some("微信"), Some(&icon), OwnIdentity::Claimed("WeChat")),
            Appearance::Unprovable {
                registered: "WeChat".into()
            }
        );
        // And the message says what it is and is not.
        let msg = r
            .resolve_appearance(Some("微信"), None, OwnIdentity::Claimed("WeChat"))
            .explain("com.tencent.mm");
        assert!(msg.contains("has not proved"), "{msg}");
        assert!(msg.contains("not evidence of impersonation"), "{msg}");
    }

    /// A **disproven** claim excuses nothing, but does not make the app impersonate itself
    /// either: `APP-SIGNER-MISMATCH` has already said the useful thing.
    #[test]
    fn a_disproven_claim_excuses_nothing_and_accuses_nothing_extra() {
        let r = registry();
        let icon = IconHash::parse(ICON_WECHAT).unwrap();
        assert_eq!(
            r.resolve_appearance(Some("微信"), Some(&icon), OwnIdentity::Disproven("WeChat")),
            Appearance::Consistent,
            "self-impersonation is not a sentence worth printing"
        );
        // But wearing a *third* app's face is still reported.
        let got = r.resolve_appearance(Some("美团"), None, OwnIdentity::Disproven("WeChat"));
        assert!(
            matches!(
                got,
                Appearance::Impersonation { ref registered, .. } if registered == "Meituan"
            ),
            "{got:?}"
        );
    }

    /// **Each channel is excused separately.** The first version short-circuited on the whole
    /// resolution, so keeping one of your own faces silenced a clone of the other.
    #[test]
    fn one_own_channel_does_not_excuse_the_other() {
        let r = registry();
        let own_icon = IconHash::parse(ICON_WECHAT).unwrap();
        let meituan_icon = IconHash::parse("123456789abcdef0").unwrap();
        // WeChat's own icon + Meituan's label → still an impersonation of Meituan.
        let got = r.resolve_appearance(
            Some("美团"),
            Some(&own_icon),
            OwnIdentity::Verified("WeChat"),
        );
        assert!(
            matches!(
                got,
                Appearance::Impersonation {
                    ref registered,
                    evidence: Evidence::Label(LabelMatch::Exact),
                    ..
                } if registered == "Meituan"
            ),
            "{got:?}"
        );
        // WeChat's own label + Meituan's icon → advisory impersonation of Meituan.
        let got = r.resolve_appearance(
            Some("微信"),
            Some(&meituan_icon),
            OwnIdentity::Verified("WeChat"),
        );
        assert!(
            matches!(
                got,
                Appearance::Impersonation {
                    ref registered,
                    evidence: Evidence::Icon { distance: 0 },
                    ..
                } if registered == "Meituan"
            ),
            "{got:?}"
        );
    }

    /// A registry whose entries would accuse each other must not load.
    #[test]
    fn a_self_colliding_registry_is_rejected() {
        // Both must *declare* an appearance, or they claim no display protection and cannot
        // accuse each other — that opt-in is what stops a deeplink-only registry from arming
        // accusation templates out of generic names like "Settings".
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: Booking\n    packages: [\"com.a\"]\n    labels: [\"Booking\"]\n  \
             - name: Bookingg\n    packages: [\"com.b\"]\n    labels: [\"Bookingg\"]\n",
        )
        .expect_err("must not load");
        let msg = err.to_string();
        assert!(msg.contains("Booking") && msg.contains("accuse"), "{msg}");
        // Aliases collide too, not just the primary names.
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: WeChat\n    labels: [\"微信\"]\n    packages: [\"com.a\"]\n  \
             - name: Weixin\n    labels: [\"微信\"]\n    packages: [\"com.b\"]\n",
        )
        .expect_err("must not load");
        assert!(err.to_string().contains("accuse"), "{err}");
        // A transposition collides, because `LabelMatch::Typo` accepts one.
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: Booking\n    packages: [\"com.a\"]\n    labels: [\"Booking\"]\n  \
             - name: Bookign\n    packages: [\"com.b\"]\n    labels: [\"Bookign\"]\n",
        )
        .expect_err("transposition must not load");
        assert!(err.to_string().contains("accuse"), "{err}");
        // A *substitution* is not a collision, because `label_match` does not accept one.
        KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: Stripe\n    packages: [\"com.a\"]\n    labels: [\"Stripe\"]\n  \
             - name: Stride\n    packages: [\"com.b\"]\n    labels: [\"Stride\"]\n",
        )
        .expect("substitution is not a match, so this registry is loadable");
        // Two entries sharing a name would make the second impersonate itself.
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: Acme Wallet\n    packages: [\"com.a\"]\n    labels: [\"Acme\"]\n  \
             - name: Acme Wallet\n    packages: [\"com.b\"]\n    labels: [\"Acme\"]\n",
        )
        .expect_err("duplicate names must not load");
        assert!(err.to_string().contains("share the name"), "{err}");
        // A 64-character label and its 65-character doubled form are **not** a collision: the
        // longer one is past `MAX_FOLDED_LEN`, so `label_match` returns None for the pair. Inferred
        // from variant-set membership, this was a false rejection.
        let long = "a".repeat(63) + "b";
        let longer = "a".repeat(64) + "b";
        KnownAppsPolicy::from_yaml_str(&format!(
            "apps:\n  - name: LongA\n    packages: [\"com.a\"]\n    labels: [\"{long}\"]\n  \
             - name: LongB\n    packages: [\"com.b\"]\n    labels: [\"{longer}\", \"LongBAlias\"]\n"
        ))
        .expect("a pair label_match rejects on length is not a collision");
    }

    /// `typo_variants` must cover exactly the shapes `label_match` accepts, or the collision
    /// check silently stops detecting collisions the runtime rule would produce.
    #[test]
    fn typo_variants_covers_every_shape_label_match_accepts() {
        let base = "wechat";
        for v in crate::visual::typo_variants(base) {
            assert_eq!(
                crate::visual::label_match(&v, base),
                Some(LabelMatch::Typo),
                "{v:?} is generated but not matched"
            );
        }
        // And the other direction, exhaustively over one alphabet: every string that
        // `label_match` calls a Typo must be in the variant set.
        let variants: std::collections::HashSet<String> =
            crate::visual::typo_variants(base).into_iter().collect();
        let alphabet = ['w', 'e', 'c', 'h', 'a', 't', 'x'];
        // Substitutions, insertions and deletions of length ±1, checked against both.
        let mut candidates: Vec<String> = Vec::new();
        let cs: Vec<char> = base.chars().collect();
        for i in 0..cs.len() {
            for a in alphabet {
                let mut v = cs.clone();
                v[i] = a;
                candidates.push(v.into_iter().collect());
                let mut v = cs.clone();
                v.insert(i, a);
                candidates.push(v.into_iter().collect());
            }
            let mut v = cs.clone();
            v.remove(i);
            candidates.push(v.into_iter().collect());
        }
        for c in candidates {
            if crate::visual::label_match(&c, base) == Some(LabelMatch::Typo) {
                assert!(variants.contains(&c), "{c:?} matches but is not generated");
            }
        }
    }

    /// A typo'd or flat icon hash must be a load error, not a line that quietly never
    /// matches (or, for the flat one, matches everything).
    #[test]
    fn unusable_icon_hashes_are_a_load_error() {
        for bad in [
            "0f1e2d3c4b5a697",
            "not-a-hash",
            "0000000000000000",
            "ffffffffffffffff",
        ] {
            let yaml = format!(
                "apps:\n  - name: WeChat\n    packages: [\"com.tencent.mm\"]\n    icon_dhash: [\"{bad}\"]\n"
            );
            let err = KnownAppsPolicy::from_yaml_str(&yaml)
                .expect_err(&format!("{bad} must be rejected"));
            assert!(err.to_string().contains("icon_dhash"), "{err}");
        }
    }

    /// An entry with no protectable face at all must not load silently. `AMap` is four
    /// characters, which is below the weight floor, so a label-only entry protects nothing.
    #[test]
    fn an_entry_with_no_protectable_face_is_a_load_error() {
        // Opting in with a label that can never match is the error…
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: AMap\n    packages: [\"com.autonavi.minimap\"]\n    labels: [\"AMap\"]\n",
        )
        .expect_err("a labels: list that can never match must not load");
        assert!(
            err.to_string()
                .contains("no label that can produce a finding"),
            "{err}"
        );
        // …while declaring no appearance at all is a legitimate registry: package, signer and
        // deeplink protection without any §3.6 claim. Its *name* is then not an accusation
        // template either, which is what stops a deeplink-only `Settings` entry from making the
        // real Android Settings app a Critical block.
        let plain = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: Settings\n    packages: [\"com.example.settings\"]\n",
        )
        .expect("an entry may decline appearance protection entirely");
        assert!(
            plain.apps[0].folded_labels().is_empty(),
            "a name alone is not a face"
        );
        assert!(!plain.apps[0].declares_appearance());
        // An **icon alone is not enough**, because icon evidence is advisory and never blocks: an
        // icon-only face passed the earlier version of this check while leaving the entry with no
        // interventional protection against the paper's exact attack.
        let err = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: AMap\n    packages: [\"com.a\"]\n    icon_dhash: [\"0f1e2d3c4b5a6978\"]\n",
        )
        .expect_err("an icon-only face cannot intervene");
        assert!(err.to_string().contains("advisory"), "{err}");
        // A longer localised label is enough.
        KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: AMap\n    packages: [\"com.a\"]\n    labels: [\"高德地图\"]\n",
        )
        .expect("a four-character CJK label carries enough information");
        // And a label past MAX_FOLDED_LEN is not a face either.
        let err = KnownAppsPolicy::from_yaml_str(&format!(
            "apps:\n  - name: Ab\n    packages: [\"com.a\"]\n    labels: [\"{}\"]\n",
            "z".repeat(70)
        ))
        .expect_err("a 70-character label can never match");
        assert!(err.to_string().contains("MAX_FOLDED_LEN"), "{err}");
    }

    /// The shipped registry must load, and every entry must have a face that can actually match.
    #[test]
    fn the_shipped_registry_loads_and_every_entry_is_protectable() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../policies/known-apps.yaml");
        let yaml = std::fs::read_to_string(&path).expect("shipped registry must be readable");
        let policy = KnownAppsPolicy::from_yaml_str(&yaml).expect("shipped registry must load");
        assert!(policy.apps.len() >= 5);
        // Every entry that *declares* an appearance must have a label that can produce a finding.
        // Entries that decline (LegacyPOS) have no face at all, and that is correct: their name is
        // not an accusation template.
        for app in &policy.apps {
            if app.declares_appearance() {
                assert!(
                    !app.folded_labels().is_empty(),
                    "{} declares an appearance with no label that can block",
                    app.name
                );
            } else {
                assert!(
                    app.folded_labels().is_empty(),
                    "{} claims no appearance, so its name must not be a face",
                    app.name
                );
            }
        }
        // `AMap` is the entry the weight floor excludes from *Latin* label protection. Asserted
        // here so the loss is visible rather than discovered — its localised label is what blocks.
        let amap = policy.apps.iter().find(|a| a.name == "AMap").unwrap();
        assert!(
            !amap.folded_labels().contains(&"amap".to_string()),
            "a four-letter Latin name must not be protectable by label"
        );
        assert!(
            amap.folded_labels().contains(&"高德地图".to_string()),
            "AMap needs a label that can actually block"
        );
    }

    /// `folded_labels` is recomputed rather than cached, so a registry built by any of the
    /// five construction sites has faces without needing a normalisation call.
    #[test]
    fn faces_need_no_normalisation_step() {
        let app = KnownApp {
            name: "WeChat".into(),
            deeplink_prefixes: vec![],
            packages: vec!["com.tencent.mm".into()],
            signers: vec![],
            labels: vec!["微信".into(), "  WeChat  ".into()],
            icon_dhash: vec![],
        };
        assert_eq!(
            app.folded_labels(),
            vec!["wechat".to_string(), "微信".to_string()]
        );
        // And a policy built by hand — not through `from_yaml_str` — still resolves, because
        // the face index is lazy rather than a step a caller could skip.
        let policy = KnownAppsPolicy {
            apps: vec![app],
            require_attestation: false,
            faces: LazyFaces::default(),
        };
        assert!(matches!(
            policy.resolve_appearance(Some("微信"), None, OwnIdentity::Unregistered),
            Appearance::Impersonation { .. }
        ));
    }

    /// Loading a large registry must not take seconds. The pairwise collision check took 24 s
    /// on 2000 apps, and a registry is loaded on every CLI run and every native-messaging spawn.
    #[test]
    fn a_large_registry_loads_quickly_and_resolves_quickly() {
        let mut yaml = String::from("apps:\n");
        // Names chosen so no two can collide under `label_match`. Each code is a **strictly
        // increasing** triple of letters: a transposition of one is no longer increasing, so it
        // cannot equal another code, and a doubled letter changes the length. Digit-suffixed
        // names do not have that property — `app0001alias` transposes into `app0010alias` — and
        // neither do dense letter codes, as two earlier drafts of this test discovered when the
        // validator correctly rejected them.
        let mut codes: Vec<String> = Vec::new();
        'outer: for a in 0..26u8 {
            for b in (a + 1)..26 {
                for c in (b + 1)..26 {
                    codes.push(
                        [b'a' + a, b'a' + b, b'a' + c]
                            .iter()
                            .map(|x| *x as char)
                            .collect(),
                    );
                    if codes.len() == 2000 {
                        break 'outer;
                    }
                }
            }
        }
        assert_eq!(codes.len(), 2000);
        for (i, k) in codes.iter().enumerate() {
            yaml.push_str(&format!(
                "  - name: Zeta{k}Prime\n    packages: [\"com.example.a{i}\"]\n    \
                 labels: [\"Omega{k}Second\", \"Kappa{k}Third\"]\n"
            ));
        }
        let t = std::time::Instant::now();
        let policy = KnownAppsPolicy::from_yaml_str(&yaml).expect("must load");
        let load = t.elapsed();
        assert!(load.as_millis() < 3_000, "load took {load:?}");
        // Per-event cost must be independent of registry size: the label channel is a lookup,
        // not a scan. Compared against a six-app registry rather than against an absolute
        // microsecond budget, so the assertion means the same thing on a slow CI box as here.
        let small = KnownAppsPolicy::from_yaml_str(
            "apps:\n  - name: OnlyOneApp\n    packages: [\"com.only\"]\n    labels: [\"OnlyOne\"]\n",
        )
        .unwrap();
        let measure = |p: &KnownAppsPolicy| {
            // Warm the lazy index first, so the measurement is the event path.
            let _ = p.resolve_appearance(Some("warm up label"), None, OwnIdentity::Unregistered);
            let t = std::time::Instant::now();
            for _ in 0..2_000 {
                let _ = p.resolve_appearance(
                    Some("Some Ordinary App"),
                    None,
                    OwnIdentity::Unregistered,
                );
            }
            t.elapsed() / 2_000
        };
        let big_us = measure(&policy).as_nanos().max(1);
        let small_us = measure(&small).as_nanos().max(1);
        assert!(
            big_us < small_us * 8 + 20_000,
            "2000-app registry costs {big_us} ns/event vs {small_us} ns/event for one app — the \
             label channel has gone back to scanning"
        );
    }
}
