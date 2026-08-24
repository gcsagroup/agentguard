//! Tamper-evident hash chain over audit records.
//!
//! Implements the "non-deniable, on-device audit" pillar from Aura: each
//! record stores `record_hash = SHA-256(prev_hash || canonical(record))`, so
//! post-hoc deletion/editing of rows breaks the chain and is detected by
//! [`AuditStore::verify_chain`](crate::AuditStore::verify_chain).
//!
//! Note: the mutable `user_decision` column is deliberately excluded from the
//! canonical content (it is written after the fact by `set_user_decision`).

use sha2::{Digest, Sha256};

use crate::types::AuditRecord;

/// Hash of the virtual record preceding the first row.
pub const GENESIS: &str = "AGENTGUARD-AUDIT-GENESIS-v1";

/// Field separator (ASCII unit separator, cannot appear in normal text).
const SEP: char = '\u{1f}';

/// Canonical content string used for hashing. Must stay stable across versions
/// once records are written; new mutable fields must NOT be added here.
///
/// `attributed_agent` (Aura §4.4.6) **is** covered. The rule above is about *mutable*
/// fields — `user_decision` is excluded because `set_user_decision` writes it after the
/// fact — and an attribution is written once, when the record is constructed, and never
/// updated. An attribution outside the hash would be worse than none, because an
/// attacker with write access to the database could rewrite it while every verification
/// still passed.
///
/// It is appended only when present, behind its own `agent=` tag, so a record with no
/// attribution hashes to exactly what it hashed before the column existed: an audit
/// database written by an older build still verifies. Agent ids are rejected at the
/// registry if they contain a control character, so the value cannot forge the
/// separator.
pub fn canonical_content(r: &AuditRecord) -> String {
    let mut s = String::with_capacity(256);
    s.push_str(&r.id);
    s.push(SEP);
    s.push_str(&r.timestamp_ms.to_string());
    s.push(SEP);
    s.push_str(&r.platform);
    s.push(SEP);
    s.push_str(&r.event_type);
    s.push(SEP);
    s.push_str(&r.source_app);
    s.push(SEP);
    s.push_str(r.agent_session_id.as_deref().unwrap_or(""));
    s.push(SEP);
    s.push_str(&r.rule_id);
    s.push(SEP);
    s.push_str(&r.severity);
    s.push(SEP);
    s.push_str(&r.action);
    s.push(SEP);
    s.push_str(&r.human_message);
    s.push(SEP);
    s.push_str(r.evidence_ref.as_deref().unwrap_or(""));
    s.push(SEP);
    s.push_str(&r.event_json);
    if let Some(agent) = &r.attributed_agent {
        s.push(SEP);
        s.push_str("agent=");
        s.push_str(agent);
    }
    s
}

/// `SHA-256(prev_hash \n canonical)` hex-encoded.
pub fn chain_hash(prev_hash: &str, record: &AuditRecord) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(canonical_content(record).as_bytes());
    hex::encode(h.finalize())
}

/// Hash for a decision receipt (post-hoc user approve/deny/timeout).
pub fn receipt_hash(prev_hash: &str, audit_id: &str, decision: &str, decided_at_ms: i64) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\n");
    h.update(audit_id.as_bytes());
    h.update(b"\n");
    h.update(decision.as_bytes());
    h.update(b"\n");
    h.update(decided_at_ms.to_string().as_bytes());
    hex::encode(h.finalize())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainVerifyReport {
    pub ok: bool,
    pub total: usize,
    pub verified: usize,
    /// Row id where the chain first breaks (edited/deleted row).
    pub first_mismatch_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_schema::{Decision, DecisionAction, EventType, GuardEvent, Severity};
    use std::collections::HashMap;

    fn sample_record(id_ts: i64) -> AuditRecord {
        let event = GuardEvent {
            event_id: format!("e{id_ts}"),
            timestamp_ms: id_ts,
            platform: "mac".into(),
            event_type: EventType::FormFill,
            source_app: "test".into(),
            agent_context_id: Some("s".into()),
            metadata: HashMap::new(),
        };
        let decision = Decision {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "ALLOW".into(),
            human_message: "ok".into(),
            require_confirm: false,
        };
        AuditRecord::from_event_decision(&event, &decision)
    }

    #[test]
    fn chain_hash_is_deterministic_and_sensitive() {
        let r1 = sample_record(1);
        let h1 = chain_hash(GENESIS, &r1);
        assert_eq!(h1, chain_hash(GENESIS, &r1));
        let h2 = chain_hash(&h1, &sample_record(2));
        assert_ne!(h1, h2);
        // Tampering with a record changes its hash.
        let mut tampered = sample_record(1);
        tampered.action = "Block".into();
        assert_ne!(h1, chain_hash(GENESIS, &tampered));
    }

    /// Attribution is inside the hash, so rewriting it in the database breaks the
    /// chain — the property that makes it evidence rather than a label.
    #[test]
    fn attribution_is_covered_by_the_hash() {
        let plain = sample_record(1);
        let attributed = plain.clone().attributed_to("claude-desktop");
        assert_ne!(
            chain_hash(GENESIS, &plain),
            chain_hash(GENESIS, &attributed)
        );
        let mut swapped = attributed.clone();
        swapped.attributed_agent = Some("someone-else".into());
        assert_ne!(
            chain_hash(GENESIS, &attributed),
            chain_hash(GENESIS, &swapped),
            "swapping the attributed agent must break the chain"
        );
    }

    /// An unattributed record hashes to exactly what it did before the column
    /// existed, so audit databases written by older builds still verify.
    #[test]
    fn the_new_column_is_backwards_compatible_when_absent() {
        let r = sample_record(1);
        assert_eq!(r.attributed_agent, None);
        let legacy = {
            let mut s = String::new();
            for f in [
                r.id.as_str(),
                &r.timestamp_ms.to_string(),
                &r.platform,
                &r.event_type,
                &r.source_app,
                r.agent_session_id.as_deref().unwrap_or(""),
                &r.rule_id,
                &r.severity,
                &r.action,
                &r.human_message,
                r.evidence_ref.as_deref().unwrap_or(""),
                &r.event_json,
            ] {
                if !s.is_empty() {
                    s.push(SEP);
                }
                s.push_str(f);
            }
            s
        };
        assert_eq!(canonical_content(&r), legacy);
    }
}
