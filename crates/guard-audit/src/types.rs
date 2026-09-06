//! Audit record types.

use guard_schema::{Decision, DecisionAction, GuardEvent, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const PERSISTABLE_EVENT_SCHEMA: &str = "persistable_event_v1";
const MAX_HUMAN_MESSAGE_CHARS: usize = 512;

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
        let (event_json, mut removed_values) = persistable_event_v1(event);
        let source_app = persistable_source_app(event);
        if source_app != event.source_app && !event.source_app.is_empty() {
            removed_values.push(event.source_app.clone());
        }
        let agent_session_id = event.agent_context_id.as_deref().map(audit_session_id);
        if event.agent_context_id.as_deref() != agent_session_id.as_deref() {
            if let Some(raw) = event
                .agent_context_id
                .as_ref()
                .filter(|raw| !raw.is_empty())
            {
                removed_values.push(raw.clone());
            }
        }
        let rule_id = persistable_rule_id(&decision.rule_id);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp_ms: event.timestamp_ms,
            platform: persistable_platform(&event.platform).to_string(),
            // 存的是 Rust 枚举的 **Debug** 名(`UiTreeDelta`),不是 serde 的 snake_case 名。
            // 现在改不了:`guard_core::acceptance_trace` 的 OBSERVATION_EVENT_TYPES 与已经落盘的
            // 审计库都认这个拼法。危险在于 Debug 名不是稳定契约——改一次枚举变体名,审计内容
            // 会**静默**跟着变,而验收 trace 检查会从此认不出观察记录(那是 fail-open 方向)。
            // 下面 `debug名是被依赖的契约_改枚举变体名要同步改审计与验收检查` 那条测试把这层
            // 依赖钉住:重命名变体时它会当场红,而不是等下一份真机报告。
            event_type: format!("{:?}", event.event_type),
            source_app,
            agent_session_id,
            rule_id: rule_id.clone(),
            severity: format!("{:?}", decision.severity),
            action: format!("{:?}", decision.action),
            // Rule messages often interpolate metadata. Remove the exact raw values that
            // were intentionally excluded or reduced by `persistable_event_v1` before
            // applying the general log redactor. This prevents the prose column from
            // becoming a second route around event minimisation.
            human_message: persistable_human_message(
                &decision.human_message,
                &removed_values,
                &rule_id,
                decision,
            ),
            evidence_ref: None,
            user_decision: None,
            event_json,
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
    /// A human-readable `[agent: …]` tag is still appended for display. Event values
    /// excluded by durable minimisation cause the original prose to be replaced by a
    /// fixed rule summary, so an event-supplied marker does not survive. The tag carries
    /// no authority: [`AuditRecord::attributed_agent`] reads the column.
    ///
    /// Per-record signing (iteration 7) already attributes an action to the *device*.
    /// This says which agent on that device took it, which a device key cannot
    /// distinguish.
    pub fn attributed_to(mut self, agent_id: &str) -> Self {
        let agent_id = persistable_agent_id(agent_id);
        self.attributed_agent = Some(agent_id.clone());
        let tag = format!("{AGENT_TAG_OPEN}{agent_id}]");
        self.human_message = if self.human_message.is_empty() {
            tag
        } else {
            let tag_chars = tag.chars().count();
            let body_chars = MAX_HUMAN_MESSAGE_CHARS.saturating_sub(tag_chars + 1);
            format!("{} {tag}", truncate_chars(&self.human_message, body_chars))
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

/// Produce the only event shape that may enter the durable audit chain.
///
/// The raw `GuardEvent` remains the in-memory rule input. Durable rows carry a versioned,
/// allow-listed projection: raw UI/OCR/clipboard text, paths, command operands, free-form
/// labels and arbitrary unknown fields are absent. Values that remain are parsed into JSON
/// booleans/numbers, validated enums/identifiers, fixed-format digests, or reduced URL
/// components. Existing database columns remain unchanged and old rows stay readable.
fn persistable_event_v1(event: &GuardEvent) -> (String, Vec<String>) {
    let mut metadata = BTreeMap::<String, Value>::new();
    let mut removed_values = Vec::<String>::new();

    for (key, raw) in &event.metadata {
        let value = raw.trim();
        let kept = match key.as_str() {
            "url" | "uri" => {
                if let Some(reduced) = reduced_url(value, key == "url") {
                    metadata.insert(key.clone(), reduced);
                    true
                } else {
                    false
                }
            }
            key if boolean_key(key) => value
                .parse::<bool>()
                .ok()
                .map(|parsed| {
                    metadata.insert(key.to_string(), Value::Bool(parsed));
                })
                .is_some(),
            "bytes" | "bytes_out" => value
                .parse::<u64>()
                .ok()
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::Number(parsed.into()));
                })
                .is_some(),
            "capture_width" | "capture_height" | "ui_tree_read_errors" => value
                .parse::<u32>()
                .ok()
                .filter(|parsed| *parsed > 0)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::Number(parsed.into()));
                })
                .is_some(),
            "low_opacity_ratio" => value
                .parse::<f64>()
                .ok()
                .filter(|parsed| parsed.is_finite() && (0.0..=1.0).contains(parsed))
                .and_then(Number::from_f64)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::Number(parsed));
                })
                .is_some(),
            key if enum_values(key).is_some() => canonical_enum(key, value)
                .map(|parsed| {
                    metadata.insert(key.to_string(), Value::String(parsed.to_string()));
                })
                .is_some(),
            "profile_key" | "task_profile" => bounded_slug(value, 64)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::String(parsed));
                })
                .is_some(),
            "package" => bounded_package_id(value)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::String(parsed));
                })
                .is_some(),
            "icon_dhash" => fixed_hex(value, 16)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::String(parsed));
                })
                .is_some(),
            "signer_sha256" => signer_digests(value)
                .map(|parsed| {
                    metadata.insert(
                        key.clone(),
                        Value::Array(parsed.into_iter().map(Value::String).collect()),
                    );
                })
                .is_some(),
            "frame_digest" => frame_digest(value)
                .map(|parsed| {
                    metadata.insert(key.clone(), Value::String(parsed));
                })
                .is_some(),
            key if counted_list_key(key).is_some() => {
                let count = count_list(value);
                metadata.insert(
                    counted_list_key(key).expect("matched list key").to_string(),
                    Value::Number((count as u64).into()),
                );
                true
            }
            _ => false,
        };

        // URL/URI and list values were deliberately reduced; their original spelling must
        // not survive in `human_message`. Rejected/unknown fields are equally untrusted.
        let lossy = matches!(key.as_str(), "url" | "uri") || counted_list_key(key).is_some();
        if (!kept || lossy) && !raw.is_empty() {
            removed_values.push(raw.clone());
        }
    }

    let payload = serde_json::json!({
        "schema": PERSISTABLE_EVENT_SCHEMA,
        "event_type": event.event_type.as_str(),
        "metadata": metadata,
    });
    // `Value` contains no map key or number form that serde_json cannot encode.
    let json =
        serde_json::to_string(&payload).expect("persistable_event_v1 is always JSON-serializable");
    (json, removed_values)
}

fn persistable_human_message(
    message: &str,
    removed_values: &[String],
    rule_id: &str,
    decision: &Decision,
) -> String {
    let mut sanitized = defuse_agent_tag(message);
    let mut values: Vec<&str> = removed_values
        .iter()
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .collect();
    values.sort_unstable_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    for value in values {
        sanitized = sanitized.replace(value, "[redacted]");
    }
    let sanitized = truncate_chars(
        &guard_privacy::log_safe(&sanitized),
        MAX_HUMAN_MESSAGE_CHARS,
    );
    if removed_values.is_empty() {
        return sanitized;
    }

    // Exact replacement is useful when a rule copied a raw value unchanged, but it is not a
    // security boundary: a rule can lowercase, normalise whitespace, quote only a prefix, or
    // otherwise rewrite observed text. Once any event-controlled value was removed/reduced,
    // persist a deterministic rule summary instead of trusting arbitrary decision prose.
    let summary = format!(
        "rule={rule_id} action={:?} severity={:?} detail_omitted=true",
        decision.action, decision.severity
    );
    truncate_chars(&guard_privacy::log_safe(&summary), MAX_HUMAN_MESSAGE_CHARS)
}

fn persistable_platform(value: &str) -> &'static str {
    match value.trim().to_ascii_lowercase().as_str() {
        "mac" | "macos" => "macos",
        "windows" | "win" => "windows",
        "android" => "android",
        "ios" => "ios",
        "browser" | "chromium" | "chrome" | "edge" | "extension" => "browser",
        "gateway" => "gateway",
        _ => "unknown",
    }
}

fn persistable_source_app(event: &GuardEvent) -> String {
    if let Some(package) = event
        .metadata
        .get("package")
        .and_then(|value| bounded_package_id(value.trim()))
    {
        return package;
    }
    stable_subject("app", &event.source_app)
}

/// Stable non-secret representation used for an external session id in audit storage.
///
/// Exposed so callers that need to correlate a returned row can transform the same raw id;
/// the original value is never required to leave process memory.
pub fn audit_session_id(value: &str) -> String {
    stable_subject("session", value)
}

fn persistable_agent_id(value: &str) -> String {
    if let Some(id) = bounded_agent_id(value.trim()) {
        return id;
    }
    stable_subject("agent", value)
}

fn persistable_rule_id(value: &str) -> String {
    let value = value.trim();
    if !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return value.to_string();
    }
    stable_subject("rule", value)
}

fn bounded_agent_id(value: &str) -> Option<String> {
    let mut chars = value.chars();
    let first = chars.next()?;
    if !first.is_ascii_lowercase()
        || value.len() > 64
        || !chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    Some(value.to_string())
}

fn stable_subject(kind: &str, value: &str) -> String {
    if value.is_empty() {
        return format!("{kind}:unknown");
    }
    let digest = Sha256::digest(value.as_bytes());
    format!("{kind}:sha256:{}", hex::encode(&digest[..16]))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn boolean_key(key: &str) -> bool {
    matches!(
        key,
        "env_surveyed"
            | "granted"
            | "is_trap"
            | "log_readers_enumerable"
            | "overlay_marker"
            | "path_checked"
            | "required"
            | "task_success"
            | "value_filled"
    )
}

fn enum_values(key: &str) -> Option<&'static [&'static str]> {
    match key {
        "necessity" => Some(&["required", "plausible", "unnecessary", "forbidden"]),
        "probe_type" => Some(&["over_permissioning", "trap_resistance", "form_minimization"]),
        "value_source" => Some(&["user", "memory", "generated"]),
        "outcome" => Some(&["asked", "answered", "declined"]),
        "sink_kind" => Some(&[
            "app_field",
            "network",
            "clipboard",
            "shell_arg",
            "critical_action",
            "memory",
        ]),
        "sink_clearance" | "to_confidentiality" => Some(&["public", "low", "high"]),
        "to_integrity" => Some(&["tainted", "verified"]),
        "verdict" | "fs_decision" => Some(&[
            "allow", "deny", "ask", "alert", "block", "log_only", "refuse", "execute",
        ]),
        "gateway_tool" => Some(&[
            "run_shell",
            "run_terminal",
            "read_file",
            "write_file",
            "delete_file",
        ]),
        "gateway_action" => Some(&[
            "read", "write", "delete", "rm", "cp", "mv", "mkdir", "touch", "create", "append",
            "truncate",
        ]),
        _ => None,
    }
}

fn canonical_enum(key: &str, value: &str) -> Option<&'static str> {
    let lowered = value.to_ascii_lowercase();
    enum_values(key)?
        .iter()
        .copied()
        .find(|candidate| *candidate == lowered)
}

fn bounded_slug(value: &str, max_len: usize) -> Option<String> {
    let mut chars = value.chars();
    let first = chars.next()?;
    if !first.is_ascii_lowercase()
        || value.len() > max_len
        || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    Some(value.to_string())
}

fn bounded_package_id(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with(['.', '-', '_'])
        || value.ends_with(['.', '-', '_'])
        || value.contains("..")
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return None;
    }
    Some(value.to_string())
}

fn fixed_hex(value: &str, len: usize) -> Option<String> {
    (value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn signer_digests(value: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    if parts.is_empty() || parts.len() > 8 {
        return None;
    }
    parts.into_iter().map(|part| fixed_hex(part, 64)).collect()
}

fn frame_digest(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split('|').collect();
    if !matches!(parts.len(), 3 | 4)
        || parts
            .iter()
            .any(|part| part.len() != 144 || !part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn reduced_url(value: &str, include_non_http_host: bool) -> Option<Value> {
    let parsed = url::Url::parse(value).ok()?;
    let scheme = parsed.scheme();
    if scheme.is_empty() || scheme.len() > 32 {
        return None;
    }
    let mut reduced = Map::new();
    reduced.insert("scheme".to_string(), Value::String(scheme.to_string()));
    if matches!(scheme, "http" | "https") {
        let host = parsed.host_str()?;
        if host.len() > 253 {
            return None;
        }
        reduced.insert("host".to_string(), Value::String(host.to_string()));
    } else if include_non_http_host {
        let host = parsed.host_str()?.to_string();
        if host.len() > 253 {
            return None;
        }
        reduced.insert("host".to_string(), Value::String(host.to_string()));
    }
    Some(Value::Object(reduced))
}

fn counted_list_key(key: &str) -> Option<&'static str> {
    match key {
        "broadcast_input_receivers" => Some("broadcast_input_receivers_count"),
        "foreign_a11y_services" => Some("foreign_a11y_services_count"),
        "text_capturing_services" => Some("text_capturing_services_count"),
        "assistive_system_services" => Some("assistive_system_services_count"),
        "log_readers" => Some("log_readers_count"),
        "broadcast_actions" => Some("broadcast_actions_count"),
        "scan_errors" => Some("scan_errors_count"),
        "task_apps" => Some("task_apps_count"),
        "task_data_keys" => Some("task_data_keys_count"),
        "task_hosts" => Some("task_hosts_count"),
        "parents" => Some("parents_count"),
        "ui_tree_truncated" => Some("ui_tree_truncated_count"),
        _ => None,
    }
}

fn count_list(value: &str) -> usize {
    value
        .split([',', ';', '\n'])
        .filter(|item| !item.trim().is_empty())
        .count()
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

    /// `AuditRecord::event_type` 存的是 `format!("{:?}")` 的结果,而 Debug 名**不是稳定契约**:
    /// 谁重命名一个 `EventType` 变体,审计库里写入的字符串就静默跟着变,
    /// 而 `guard_core::acceptance_trace::OBSERVATION_EVENT_TYPES` 会从此认不出观察记录 ——
    /// "会话结束后零观测"这项检查于是可能在**该红的时候通过**(fail-open 方向)。
    ///
    /// 这条测试把那层跨 crate 的隐式依赖变成显式的:重命名变体 → 当场红,红在这里,
    /// 而不是等下一次真机验收发现 trace 检查突然什么都匹配不到。
    /// (要换成 `as_str()` 的 snake_case 拼法是可以的,但那要同时迁移已落盘的审计库与
    /// 验收检查的常量表,属于单独一次有人点头的改动,不是顺手改。)
    #[test]
    fn debug名是被依赖的契约_改枚举变体名要同步改审计与验收检查() {
        // acceptance_trace 的 OBSERVATION_EVENT_TYPES 逐字认这三个。
        assert_eq!(format!("{:?}", EventType::UiTreeDelta), "UiTreeDelta");
        assert_eq!(format!("{:?}", EventType::ScreenFrame), "ScreenFrame");
        assert_eq!(format!("{:?}", EventType::FormFill), "FormFill");
        // 会话边界那两条同样按 Debug 名匹配。
        assert_eq!(
            format!("{:?}", EventType::AgentSessionStart),
            "AgentSessionStart"
        );
        assert_eq!(
            format!("{:?}", EventType::AgentSessionEnd),
            "AgentSessionEnd"
        );
        // 顺带钉住:Debug 名与 serde/as_str 的稳定名**不是**同一个字符串。
        // 哪天有人以为它们一样、把两边混用,这行会提醒他先做迁移。
        assert_eq!(EventType::UiTreeDelta.as_str(), "ui_tree_delta");
        assert_ne!(
            format!("{:?}", EventType::UiTreeDelta),
            EventType::UiTreeDelta.as_str()
        );
    }

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

    fn record_with_metadata(metadata: HashMap<String, String>, message: &str) -> AuditRecord {
        let event = GuardEvent {
            event_id: "raw-event-id-must-not-be-copied".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "Booking".into(),
            agent_context_id: Some("session-column-only".into()),
            metadata,
        };
        let decision = Decision {
            action: DecisionAction::Block,
            severity: Severity::High,
            rule_id: "DATA-00".into(),
            human_message: message.into(),
            require_confirm: true,
        };
        AuditRecord::from_event_decision(&event, &decision)
    }

    #[test]
    fn persistable_event_v1_drops_raw_observation_and_reduces_destinations() {
        let url = "https://user:secret@example.com/private/token-abc?access_token=xyz#card";
        let uri = "booking://payment/transfer?clipboard=raw";
        let raw_ui = "OCR clipboard passport X1234567";
        let record = record_with_metadata(
            HashMap::from([
                ("ui_text".into(), raw_ui.into()),
                ("ocr_text".into(), "OCR-RAW-CANARY".into()),
                ("clipboard_text".into(), "CLIPBOARD-RAW-CANARY".into()),
                ("path".into(), "/Users/alice/secret.txt".into()),
                ("argv0".into(), "/bin/private-tool".into()),
                ("url".into(), url.into()),
                ("uri".into(), uri.into()),
                ("unexpected_secret".into(), "UNKNOWN-RAW-CANARY".into()),
            ]),
            &format!("blocked {raw_ui}; target {url}; path /Users/alice/secret.txt"),
        );
        let payload: Value = serde_json::from_str(&record.event_json).unwrap();
        assert_eq!(payload["schema"], PERSISTABLE_EVENT_SCHEMA);
        assert_eq!(payload["event_type"], "ui_tree_delta");
        assert_eq!(payload["metadata"]["url"]["scheme"], "https");
        assert_eq!(payload["metadata"]["url"]["host"], "example.com");
        assert_eq!(payload["metadata"]["uri"]["scheme"], "booking");
        assert!(payload["metadata"]["uri"].get("host").is_none());
        for canary in [
            raw_ui,
            "OCR-RAW-CANARY",
            "CLIPBOARD-RAW-CANARY",
            "/Users/alice/secret.txt",
            "/bin/private-tool",
            "user:secret",
            "access_token",
            "UNKNOWN-RAW-CANARY",
            "raw-event-id-must-not-be-copied",
        ] {
            assert!(
                !record.event_json.contains(canary),
                "{canary}: {}",
                record.event_json
            );
            assert!(
                !record.human_message.contains(canary),
                "{canary}: {}",
                record.human_message
            );
        }
        assert!(record.human_message.contains("detail_omitted=true"));
    }

    #[test]
    fn persistable_metadata_is_typed_and_invalid_structures_are_rejected() {
        let frame = std::iter::repeat_n("a".repeat(144), 4)
            .collect::<Vec<_>>()
            .join("|");
        let signer = "b".repeat(64);
        let record = record_with_metadata(
            HashMap::from([
                ("required".into(), "true".into()),
                ("bytes".into(), "42".into()),
                ("low_opacity_ratio".into(), "0.125".into()),
                ("necessity".into(), "REQUIRED".into()),
                ("sink_kind".into(), "network".into()),
                ("profile_key".into(), "passport_number".into()),
                ("package".into(), "com.example.app".into()),
                ("icon_dhash".into(), "0F1E2D3C4B5A6978".into()),
                ("signer_sha256".into(), signer),
                ("frame_digest".into(), frame),
                ("capture_width".into(), "-1".into()),
                ("granted".into(), "yes".into()),
                ("task_profile".into(), "contains a secret".into()),
                ("fs_decision".into(), "invented".into()),
                (
                    "foreign_a11y_services".into(),
                    "one.service,two.service".into(),
                ),
            ]),
            "ordinary decision",
        );
        let payload: Value = serde_json::from_str(&record.event_json).unwrap();
        let metadata = payload["metadata"].as_object().unwrap();
        assert_eq!(metadata["required"], true);
        assert_eq!(metadata["bytes"], 42);
        assert_eq!(metadata["low_opacity_ratio"], 0.125);
        assert_eq!(metadata["necessity"], "required");
        assert_eq!(metadata["sink_kind"], "network");
        assert_eq!(metadata["profile_key"], "passport_number");
        assert_eq!(metadata["package"], "com.example.app");
        assert_eq!(metadata["icon_dhash"], "0f1e2d3c4b5a6978");
        assert!(metadata["signer_sha256"].is_array());
        assert!(metadata["frame_digest"].as_str().is_some());
        assert_eq!(metadata["foreign_a11y_services_count"], 2);
        for rejected in ["capture_width", "granted", "task_profile", "fs_decision"] {
            assert!(!metadata.contains_key(rejected), "{rejected}: {metadata:?}");
        }
        assert!(!record.event_json.contains("one.service"));
        assert!(!record.event_json.contains("two.service"));
    }

    #[test]
    fn persistable_human_message_redacts_removed_values_and_is_bounded() {
        let raw_reason = "USER-SUPPLIED-DECLASSIFY-REASON";
        let long = format!("{} {raw_reason}", "safe ".repeat(300));
        let record =
            record_with_metadata(HashMap::from([("reason".into(), raw_reason.into())]), &long);
        assert!(!record.human_message.contains(raw_reason));
        assert!(record.human_message.contains("detail_omitted=true"));
        assert!(record.human_message.chars().count() <= MAX_HUMAN_MESSAGE_CHARS);
        assert!(!record.human_message.ends_with('…'));

        // When every event field is already a validated durable value, ordinary rule prose
        // may remain, but it still passes `log_safe` and the character cap.
        let event = GuardEvent {
            event_id: "bounded-message".into(),
            timestamp_ms: 1,
            platform: "mac".into(),
            event_type: EventType::UiTreeDelta,
            source_app: "com.example.booking".into(),
            agent_context_id: None,
            metadata: HashMap::from([("package".into(), "com.example.booking".into())]),
        };
        let decision = Decision {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "DATA-00".into(),
            human_message: format!("card 4242 4242 4242 4242 {}", "safe ".repeat(300)),
            require_confirm: false,
        };
        let bounded = AuditRecord::from_event_decision(&event, &decision);
        assert!(bounded.human_message.chars().count() <= MAX_HUMAN_MESSAGE_CHARS);
        assert!(bounded.human_message.ends_with('…'));
        assert!(!bounded.human_message.contains("4242 4242 4242"));

        let agent_id = "a".repeat(64);
        let attributed = bounded.attributed_to(&agent_id);
        assert!(attributed.human_message.chars().count() <= MAX_HUMAN_MESSAGE_CHARS);
        assert!(attributed
            .human_message
            .ends_with(&format!("[agent: {agent_id}]")));
        assert_eq!(attributed.attributed_agent(), Some(agent_id.as_str()));
    }

    #[test]
    fn rewritten_raw_text_and_free_form_identity_fields_cannot_bypass_minimisation() {
        let raw_ui = "TOP SECRET    PHRASE";
        let record = record_with_metadata(
            HashMap::from([("ui_text".into(), raw_ui.into())]),
            // Different case and whitespace: exact replacement cannot match this form.
            "blocked top secret phrase after normalisation",
        )
        .attributed_to("ATTACKER SUPPLIED AGENT LABEL");
        assert!(!record
            .human_message
            .to_ascii_lowercase()
            .contains("secret phrase"));
        assert!(!record.human_message.contains("ATTACKER"));
        assert!(!record.source_app.contains("Booking"));
        assert!(!record
            .agent_session_id
            .as_deref()
            .unwrap()
            .contains("session-column-only"));
        assert!(
            record.source_app.starts_with("app:sha256:"),
            "{}",
            record.source_app
        );
        assert!(
            record
                .agent_session_id
                .as_deref()
                .unwrap()
                .starts_with("session:sha256:"),
            "{:?}",
            record.agent_session_id
        );
        assert!(
            record
                .attributed_agent()
                .unwrap()
                .starts_with("agent:sha256:"),
            "{:?}",
            record.attributed_agent()
        );
    }

    #[test]
    fn url_and_http_uri_drop_userinfo_path_query_fragment_and_normalise_idn_host() {
        let record = record_with_metadata(
            HashMap::from([
                (
                    "url".into(),
                    "https://user:pass@BÜCHER.example/private?q=secret#fragment".into(),
                ),
                (
                    "uri".into(),
                    "https://token@例子.测试/authorize?code=secret#fragment".into(),
                ),
            ]),
            "destination checked",
        );
        let payload: Value = serde_json::from_str(&record.event_json).unwrap();
        assert_eq!(payload["metadata"]["url"]["host"], "xn--bcher-kva.example");
        assert_eq!(payload["metadata"]["uri"]["scheme"], "https");
        assert_eq!(
            payload["metadata"]["uri"]["host"],
            "xn--fsqu00a.xn--0zwm56d"
        );
        for forbidden in [
            "user",
            "pass",
            "private",
            "secret",
            "fragment",
            "token",
            "authorize",
            "code",
        ] {
            assert!(
                !record.event_json.contains(forbidden),
                "{forbidden}: {}",
                record.event_json
            );
        }
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
            !r.human_message.contains("claude-desktop"),
            "{}",
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
        assert!(!r.human_message.contains("attacker"));
        assert!(r.human_message.ends_with("[agent: claude-desktop]"));
    }
}
