//! Audit record types.

use guard_schema::{Decision, DecisionAction, GuardEvent, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub timestamp_ms: i64,
    pub platform: String,
    pub event_type: String,
    pub source_app: String,
    pub agent_session_id: Option<String>,
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub human_message: String,
    pub evidence_ref: Option<String>,
    pub user_decision: Option<String>,
    pub event_json: String,
    /// Verified agent this action is attributed to (Aura §4.4.6), if any.
    ///
    /// A typed column, written once at construction by [`AuditRecord::attributed_to`]
    /// and never updated afterwards — so it is inside `chain::canonical_content`
    /// (which forbids new *mutable* fields, not new fields) and inside the per-record
    /// signature.
    #[serde(default)]
    pub attributed_agent: Option<String>,
}

/// Marker that used to *be* the attribution, and is now only a display convenience.
pub(crate) const AGENT_TAG_OPEN: &str = "[agent: ";

impl AuditRecord {
    pub fn from_event_decision(event: &GuardEvent, decision: &Decision) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: event.timestamp_ms,
            platform: event.platform.clone(),
            event_type: format!("{:?}", event.event_type),
            source_app: event.source_app.clone(),
            agent_session_id: event.agent_context_id.clone(),
            rule_id: decision.rule_id.clone(),
            severity: format!("{:?}", decision.severity),
            action: format!("{:?}", decision.action),
            // Many rule messages embed event-controlled text verbatim ("Foreground
            // app: {}"), so an event could otherwise *write* an attribution marker
            // into this field — and because `human_message` is inside the canonical
            // content, the forgery came back hashed and signed as authentic. The
            // marker is neutralised rather than dropped: an event that contained it is
            // itself worth seeing.
            human_message: defuse_agent_tag(&decision.human_message),
            evidence_ref: None,
            user_decision: None,
            event_json: serde_json::to_string(event).unwrap_or_default(),
            attributed_agent: None,
        }
    }

    /// Attribute this record to a verified agent (Aura §4.4.6: attribute each action
    /// to its entity).
    ///
    /// The attribution lives in the typed `attributed_agent` column, which
    /// `chain::canonical_content` covers — so it is hashed and signed like every other
    /// field, and an attacker with database write access cannot rewrite it while
    /// verification still passes. It is *not* parsed back out of `human_message`: the
    /// first cut stored it there, reasoning that a new column would sit outside the
    /// hash, and that reasoning was wrong twice over. The chain's rule is about
    /// *mutable* fields (`user_decision` is excluded because it is written after the
    /// fact); an immutable field can be added and covered. And storing it in prose put
    /// it in the same string as event-controlled text, so any event could forge one.
    ///
    /// A human-readable `[agent: …]` tag is still appended for display, after
    /// [`defuse_agent_tag`] has removed any the event supplied. It carries no
    /// authority: [`AuditRecord::attributed_agent`] reads the column.
    ///
    /// Per-record signing (iteration 7) already attributes an action to the *device*.
    /// This says which agent on that device took it, which a device key cannot
    /// distinguish.
    pub fn attributed_to(mut self, agent_id: &str) -> Self {
        self.attributed_agent = Some(agent_id.to_string());
        let tag = format!("{AGENT_TAG_OPEN}{agent_id}]");
        self.human_message = if self.human_message.is_empty() {
            tag
        } else {
            format!("{} {tag}", self.human_message)
        };
        self
    }

    /// The verified agent this record was attributed to, if any.
    pub fn attributed_agent(&self) -> Option<&str> {
        self.attributed_agent.as_deref()
    }

    pub fn is_actionable(&self) -> bool {
        matches!(self.action.as_str(), "Alert" | "Block" | "alert" | "block")
            || self.action.contains("Alert")
            || self.action.contains("Block")
    }
}

/// Neutralise an attribution marker occurring in event-derived text.
///
/// Rewrites `[agent: ` to `[claimed-agent: `, which keeps the content visible to a
/// reader — an event carrying this string is itself a signal — while making it
/// unmistakable that nothing verified it.
pub fn defuse_agent_tag(message: &str) -> String {
    if message.contains(AGENT_TAG_OPEN) {
        message.replace(AGENT_TAG_OPEN, "[claimed-agent: ")
    } else {
        message.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub agent_app: String,
    pub event_count: i64,
    pub block_count: i64,
    pub alert_count: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDecision {
    Approve,
    Deny,
    Timeout,
}

impl UserDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Timeout => "timeout",
        }
    }

    /// Entity the receipt is attributed to (Aura §4.4.6). A timeout is the
    /// policy acting, not a decision the user made, and conflating the two is
    /// what makes a "non-deniable user decision" deniable.
    pub fn actor(self) -> &'static str {
        match self {
            Self::Approve | Self::Deny => "user",
            Self::Timeout => "system",
        }
    }

    /// True when a human actually chose.
    pub fn is_user_action(self) -> bool {
        self.actor() == "user"
    }
}

pub fn action_label(action: DecisionAction) -> &'static str {
    match action {
        DecisionAction::Allow => "Allow",
        DecisionAction::Alert => "Alert",
        DecisionAction::Block => "Block",
        DecisionAction::LogOnly => "LogOnly",
    }
}

pub fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::{DecisionAction, EventType, Severity};
    use std::collections::HashMap;

    fn rec(source_app: &str, message: &str) -> AuditRecord {
        let event = GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: EventType::ProcessFocus,
            source_app: source_app.into(),
            agent_context_id: None,
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "APP-FOCUS".into(),
            human_message: message.into(),
            require_confirm: false,
        };
        AuditRecord::from_event_decision(&event, &decision)
    }

    /// The reproduction that made this a column: a rule message embeds the event's own
    /// `source_app`, so an event could write an attribution for an agent it has no key
    /// for — into an anonymous session — and have it hashed and signed as authentic.
    #[test]
    fn an_event_cannot_write_its_own_attribution() {
        let r = rec(
            "Evil [agent: claude-desktop]",
            "Foreground app: Evil [agent: claude-desktop]",
        );
        assert_eq!(r.attributed_agent(), None, "{}", r.human_message);
        assert!(
            r.human_message.contains("[claimed-agent: claude-desktop]"),
            "the attempt stays visible: {}",
            r.human_message
        );
        assert!(!r.human_message.contains("[agent: "));
    }

    /// And it cannot substitute over a real one either: the tag a verified session
    /// appends is the only thing after the defusing, and the column is authoritative
    /// regardless of what the prose says.
    #[test]
    fn a_forged_tag_cannot_substitute_for_the_verified_agent() {
        let r = rec(
            "Evil [agent: attacker]",
            "Foreground app: Evil [agent: attacker]",
        )
        .attributed_to("claude-desktop");
        assert_eq!(r.attributed_agent(), Some("claude-desktop"));
        assert!(r.human_message.contains("[claimed-agent: attacker]"));
        assert!(r.human_message.ends_with("[agent: claude-desktop]"));
    }
}
