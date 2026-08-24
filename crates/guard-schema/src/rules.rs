//! Rule DSL loaded from YAML (CRIT / OVL / PRIV families).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::events::{DecisionAction, Severity};

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("failed to parse rules YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub action: DecisionAction,
    #[serde(default)]
    pub require_confirm: bool,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub match_any_text: Vec<String>,
    /// Event types this rule may fire on. Empty means any.
    ///
    /// Exists because `match_any_text` searches `ui_text`, and `ui_text` is *screen
    /// content* — so a page that simply displays `[AG_BROADCAST_INPUT_SINK]` forged an
    /// `ENV-A5` **Critical block** describing a device condition that did not exist. The
    /// marker was intended as a channel from the adapter to the engine and is in fact a
    /// channel from whatever is on screen.
    ///
    /// Constraining the environment rules to `environment_survey` closes the case that
    /// matters most: an environment finding is a claim *about the device*, and only the
    /// companion's own survey event can make it. The markers that describe screen content
    /// (overlays, steganography, revalidation) are deliberately left unconstrained —
    /// content is exactly what they are about — and remain forgeable in the same way. The
    /// general fix is a separate metadata channel for adapter assertions instead of
    /// smuggling them through `ui_text`; that is not built. See docs/log-hygiene.md.
    #[serde(default)]
    pub event_types: Vec<crate::events::EventType>,
    #[serde(default)]
    pub match_field_categories: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// What kind of *step* a match on this rule represents, for trajectory
    /// alignment (Aura §4.3.2).
    ///
    /// Declared on the rule rather than re-derived from `ui_text` elsewhere, and
    /// checked across **every** matching rule rather than only the winning one. The
    /// first cut keyed the step kind on `decision.rule_id == "CRIT-001"`, so any text
    /// whose longest match belonged to a different rule — appending
    /// `[AG_STEGO_LSB]` was enough — made the payment fall through to `Observe`:
    /// uncounted, and the trajectory then reported perfect conformance. The
    /// controlling input was attacker-authored screen text.
    #[serde(default)]
    pub step_kind: Option<crate::plan::StepKind>,
}

impl RuleSet {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, RuleError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&raw)
    }

    pub fn find(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_ruleset() {
        let yaml = r#"
version: "1.0"
rules:
  - id: CRIT-001
    name: payment_confirmation
    severity: critical
    action: block
    require_confirm: true
    match_any_text: ["确认支付", "Confirm Payment"]
"#;
        let set = RuleSet::from_yaml_str(yaml).unwrap();
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].id, "CRIT-001");
    }
}
