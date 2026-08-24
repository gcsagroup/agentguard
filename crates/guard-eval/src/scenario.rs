//! Eval scenario schema (self-authored; inspired by MyPhoneBench probes).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScenarioError {
    #[error("parse scenario YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario_id: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub platform: Vec<String>,
    #[serde(default)]
    pub task_profile: Option<String>,
    #[serde(default)]
    pub goal: Option<String>,
    #[serde(default)]
    pub probes: Vec<ProbeSpec>,
    #[serde(default)]
    pub verification: Vec<Verification>,
    #[serde(default)]
    pub agent_under_test: Option<String>,
    /// MyPhoneBench `completed(t)`: did the underlying task succeed? Required
    /// for PQSR; scenarios that only exercise guard behaviour leave it unset
    /// and are excluded from the PQSR denominator rather than assumed to pass.
    #[serde(default)]
    pub task_success: Option<bool>,
    /// Whether this scenario depicts an attack or ordinary benign activity.
    ///
    /// Without benign scenarios a guard cannot be evaluated at all: blocking
    /// everything scores perfectly against an attack-only corpus. `kind` splits
    /// the corpus so the miss rate and the false-positive rate are both reported.
    #[serde(default)]
    pub kind: ScenarioKind,
    /// Optional synthetic event stream for offline replay.
    #[serde(default)]
    pub events: Vec<ScenarioEvent>,
    /// Override `KnownAppsPolicy::require_attestation` for this scenario.
    ///
    /// The shipped registry leaves it **off**, because only the Android companion
    /// can read a signing certificate today and enforcing globally would block a
    /// registered app's own deeplinks on every other adapter. Enforcement is still a
    /// real, shipped code path, so the corpus has to exercise both modes — this is
    /// how, without pretending the default is something it is not.
    #[serde(default)]
    pub require_attestation: Option<bool>,
    /// Override `TaskPlanLibrary::require_plan` for this scenario, so both the
    /// permissive default and the fail-closed mode are exercised.
    #[serde(default)]
    pub require_plan: Option<bool>,
    /// Override `AgentRegistry::require_attestation`, so both the permissive default
    /// and the attributable-sessions-only mode are exercised.
    #[serde(default)]
    pub require_agent_attestation: Option<bool>,
    /// Override `GuardContract::on_plan_drift` (`alert` | `ask` | `block` |
    /// `allow`). The default is `alert`, because a new plan library rejecting real
    /// work is the likelier failure — but the confirming mode is a shipped code path
    /// (it is what makes re-anchoring reachable), so the corpus exercises it too.
    #[serde(default)]
    pub on_plan_drift: Option<String>,
    /// When set to `deny` or `approve`, run events through gated confirm handling.
    #[serde(default)]
    pub confirm_mode: Option<String>,
}

/// Attack vs benign, for the paired miss-rate / false-positive-rate metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    /// Depicts a published attack. The guard is expected to intervene
    /// (Block or Alert); not intervening is a **miss**.
    #[default]
    Attack,
    /// Depicts ordinary activity. The guard is expected **not** to intervene;
    /// intervening is a **false positive** and costs the user utility.
    Benign,
}

impl ScenarioKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Attack => "attack",
            Self::Benign => "benign",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSpec {
    #[serde(rename = "type")]
    pub probe_type: String,
    #[serde(default)]
    pub layout: Option<String>,
    #[serde(default)]
    pub optional_fields: Vec<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub trap_fields: Vec<String>,
    #[serde(default)]
    pub optional_high: Vec<String>,
    #[serde(default)]
    pub required_low: Vec<String>,
    #[serde(default)]
    pub match_any_text: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub threshold: Option<f32>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub over_permissioning: Option<f32>,
    #[serde(default)]
    pub trap_resistance: Option<f32>,
    #[serde(default)]
    pub form_minimization: Option<f32>,
    /// For `privacy_qualified`: expected outcome of `completed(t) ∧ privacy ≥ τ`.
    #[serde(default)]
    pub expect: Option<bool>,
    /// For `no_intervention`: rule ids whose intervention is expected and
    /// therefore not counted as a false positive (e.g. the memory-write confirm,
    /// which is a contract choice rather than a threat detection).
    #[serde(default)]
    pub ignore_rules: Vec<String>,
    /// For `decision_message_contains`: substrings the final decision's
    /// `human_message` must include.
    ///
    /// Exists because decisions are merged by severity: when two findings land on
    /// one event, only the more severe rule id survives. Without a way to assert on
    /// the message, a merge that silently drops the *reason* — "an app claiming to
    /// be Meituan is not verified" — would look identical to one that keeps it.
    #[serde(default)]
    pub contains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioEvent {
    pub event_type: String,
    #[serde(default)]
    pub source_app: Option<String>,
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
    /// 这个事件是**由一个已验证的适配器**送进来的,值是那个适配器的 id。
    ///
    /// # 为什么评测集需要能表达这个
    ///
    /// 适配器断言签名整套机制以前在评测集里**一条覆盖都没有** —— 场景格式压根
    /// 表达不了"这个事件的签名验过了"。于是那套机制只有单元测试,而单元测试看不到
    /// 端到端的判决。
    ///
    /// 更直接的原因:应用签名摘要的证明力不超过携带它的适配器
    /// (见 `AdapterIdentity::may_grant_trust`)。所以一个想描述"这个应用的身份
    /// **确实**验证通过"的场景,必须能说出摘要是谁送来的 —— 否则它描述的是一个
    /// 在真实部署里不成立的状态。
    ///
    /// 写在 YAML 里是刻意的:一个给自己发信任的场景应该在 diff 里一眼看得见。
    #[serde(default)]
    pub via_verified_adapter: Option<String>,
}

impl Scenario {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ScenarioError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, ScenarioError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&raw)
    }
}
