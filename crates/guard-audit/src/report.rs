//! Session / audit summary report for export (JSON + Markdown).

use crate::types::AuditRecord;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub generated_at_ms: i64,
    pub record_count: usize,
    pub block_count: usize,
    pub alert_count: usize,
    pub allow_count: usize,
    pub log_only_count: usize,
    pub confirm_decisions: ConfirmStats,
    /// Provenance of `confirm_decisions`.
    pub confirm_source: ConfirmSource,
    pub by_rule: Vec<RuleCount>,
    pub by_source_app: Vec<AppCount>,
    pub top_messages: Vec<String>,
    pub privacy_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfirmStats {
    pub approve: usize,
    pub deny: usize,
    pub timeout: usize,
    pub pending: usize,
}

/// Where the confirm counts came from — this matters for anyone treating the
/// report as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmSource {
    /// The mutable `audit_events.user_decision` column, which is excluded from
    /// the hash chain and covered by no signature. Anyone who can write the DB
    /// can set it. Fine for a status dashboard, **not** evidence.
    UserDecisionColumn,
    /// Recomputed from decision receipts whose signatures verified against a
    /// supplied public key.
    SignedReceipts,
}

impl ConfirmSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::UserDecisionColumn => {
                "user_decision column — unsigned and unhashed; not evidence"
            }
            Self::SignedReceipts => "verified signed receipts",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCount {
    pub source_app: String,
    pub count: usize,
}

impl SessionReport {
    pub fn from_records(records: &[AuditRecord]) -> Self {
        let mut block = 0usize;
        let mut alert = 0usize;
        let mut allow = 0usize;
        let mut log_only = 0usize;
        let mut confirm = ConfirmStats::default();
        let mut rules: BTreeMap<String, usize> = BTreeMap::new();
        let mut apps: BTreeMap<String, usize> = BTreeMap::new();
        let mut top_messages = Vec::new();

        for r in records {
            let action = r.action.to_lowercase();
            if action.contains("block") {
                block += 1;
            } else if action.contains("alert") {
                alert += 1;
            } else if action.contains("allow") {
                allow += 1;
            } else {
                log_only += 1;
            }

            match r.user_decision.as_deref() {
                Some("approve") => confirm.approve += 1,
                Some("deny") => confirm.deny += 1,
                Some("timeout") => confirm.timeout += 1,
                None if r.action.contains("Block") || r.action.contains("Alert") => {
                    confirm.pending += 1;
                }
                _ => {}
            }

            *rules.entry(r.rule_id.clone()).or_default() += 1;
            *apps.entry(r.source_app.clone()).or_default() += 1;

            if (action.contains("block") || action.contains("alert")) && top_messages.len() < 8 {
                // A report is a *summary*, not the evidence — the audit rows are the
                // evidence. So it is redacted more aggressively than they are: rule
                // templates build `human_message` from event text, and this file gets
                // attached to tickets.
                top_messages.push(format!(
                    "[{}] {}",
                    r.rule_id,
                    guard_privacy::log_safe(&r.human_message)
                ));
            }
        }

        let mut by_rule: Vec<_> = rules
            .into_iter()
            .map(|(rule_id, count)| RuleCount { rule_id, count })
            .collect();
        by_rule.sort_by_key(|r| Reverse(r.count));

        let mut by_source_app: Vec<_> = apps
            .into_iter()
            .map(|(source_app, count)| AppCount { source_app, count })
            .collect();
        by_source_app.sort_by_key(|a| Reverse(a.count));

        let privacy_note = if block + alert == 0 {
            "本窗口未捕获高危拦截；继续保持低权限与表单最小化。".into()
        } else {
            format!(
                "本窗口拦截/告警 {} 次；优先审查支付、注入与外传类规则命中。",
                block + alert
            )
        };

        Self {
            generated_at_ms: now_ms(),
            record_count: records.len(),
            block_count: block,
            alert_count: alert,
            allow_count: allow,
            log_only_count: log_only,
            confirm_decisions: confirm,
            confirm_source: ConfirmSource::UserDecisionColumn,
            by_rule,
            by_source_app,
            top_messages,
            privacy_note,
        }
    }

    /// Replace the confirm counts with numbers recomputed from **verified signed
    /// receipts**, and record that provenance.
    ///
    /// `from_records` reads `audit_events.user_decision`, which is excluded from
    /// the hash chain (it is written after the fact) and covered by no signature —
    /// so it is exactly the wrong column to build an evidence claim on.
    pub fn with_verified_confirms(mut self, stats: ConfirmStats) -> Self {
        self.confirm_decisions = stats;
        self.confirm_source = ConfirmSource::SignedReceipts;
        self
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# AgentGuard 会话摘要\n\n");
        md.push_str(&format!("生成时间 (ms): {}\n\n", self.generated_at_ms));
        md.push_str("## 概览\n\n");
        md.push_str(&format!(
            "| 指标 | 值 |\n| --- | --- |\n| 记录数 | {} |\n| Block | {} |\n| Alert | {} |\n| Allow | {} |\n| LogOnly | {} |\n\n",
            self.record_count,
            self.block_count,
            self.alert_count,
            self.allow_count,
            self.log_only_count
        ));
        md.push_str(&format!(
            "确认：approve={} deny={} timeout={} pending≈{}（来源：{}）\n\n",
            self.confirm_decisions.approve,
            self.confirm_decisions.deny,
            self.confirm_decisions.timeout,
            self.confirm_decisions.pending,
            self.confirm_source.label()
        ));
        md.push_str(&format!("> {}\n\n", self.privacy_note));
        md.push_str("## 规则命中\n\n");
        for r in &self.by_rule {
            md.push_str(&format!("- `{}`: {}\n", r.rule_id, r.count));
        }
        md.push_str("\n## 来源应用\n\n");
        for a in &self.by_source_app {
            md.push_str(&format!("- {}: {}\n", a.source_app, a.count));
        }
        if !self.top_messages.is_empty() {
            md.push_str("\n## 高危摘要\n\n");
            for m in &self.top_messages {
                md.push_str(&format!("- {}\n", m));
            }
        }
        md
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(p) = path.as_ref().parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn write_markdown(&self, path: impl AsRef<Path>) -> Result<()> {
        if let Some(p) = path.as_ref().parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, self.to_markdown())?;
        Ok(())
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `top_messages` is not a print sink, so the source scanner cannot see it — and a
/// reviewer showed that stripping its redactor went undetected. The guarantee needs a test
/// where the guarantee lives.
#[cfg(test)]
mod redaction_tests {
    use crate::types::AuditRecord;
    use guard_schema::{Decision, DecisionAction, EventType, GuardEvent, Severity};
    use std::collections::HashMap;

    #[test]
    fn a_report_summary_does_not_carry_a_card_number() {
        let event = GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Booking".into(),
            agent_context_id: Some("s1".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Alert,
            severity: Severity::High,
            rule_id: "PRIV-003".into(),
            human_message: "Saved card 4242 4242 4242 4242 for ming.lin@lbemobile.com".into(),
            require_confirm: false,
        };
        let rec = AuditRecord::from_event_decision(&event, &decision);
        let summary = crate::report::SessionReport::from_records(&[rec]);
        let joined = summary.top_messages.join(" | ");
        assert!(!joined.contains("4242 4242 4242"), "{joined}");
        assert!(!joined.contains("ming.lin@"), "{joined}");
        assert!(joined.contains("PRIV-003"), "{joined}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuditRecord;

    fn sample(action: &str, rule: &str) -> AuditRecord {
        AuditRecord {
            id: "1".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: "UiTreeDelta".into(),
            source_app: "Chrome".into(),
            agent_session_id: None,
            rule_id: rule.into(),
            severity: "High".into(),
            action: action.into(),
            human_message: "demo".into(),
            evidence_ref: None,
            user_decision: Some("deny".into()),
            event_json: "{}".into(),
            attributed_agent: None,
        }
    }

    #[test]
    fn aggregates_blocks() {
        let records = vec![sample("Block", "CRIT-001"), sample("Alert", "PRIV-002")];
        let r = SessionReport::from_records(&records);
        assert_eq!(r.block_count, 1);
        assert_eq!(r.alert_count, 1);
        assert_eq!(r.confirm_decisions.deny, 2);
        assert!(r.to_markdown().contains("CRIT-001"));
    }
}
