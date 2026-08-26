//! Browser adapter: extension findings → GuardEvent.

use anyhow::Result;
use guard_schema::{EventType, GuardEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEnvelope {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub events: Vec<BrowserEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub field_id: Option<String>,
    #[serde(default)]
    pub profile_key: Option<String>,
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub value_filled: Option<bool>,
    #[serde(default)]
    pub is_trap: Option<bool>,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// 转换结果:成功的事件,以及每个失败事件的 `(下标, 原因)`。
pub type LenientEvents = (Vec<GuardEvent>, Vec<(usize, String)>);

#[derive(Debug, Default)]
pub struct BrowserAdapter {
    session_id: Option<String>,
    seq: u64,
}

impl BrowserAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_session(&mut self, session_id: Option<String>) {
        self.session_id = session_id;
    }

    pub fn parse_envelope(&mut self, json: &str) -> Result<Vec<GuardEvent>> {
        let env: BrowserEnvelope = serde_json::from_str(json)?;
        self.convert_envelope(&env)
    }

    pub fn convert_envelope(&mut self, env: &BrowserEnvelope) -> Result<Vec<GuardEvent>> {
        let mut out = Vec::new();
        for ev in &env.events {
            out.push(self.convert_event(ev)?);
        }
        Ok(out)
    }

    /// Convert what can be converted; report the rest instead of discarding the batch.
    ///
    /// `convert_envelope` fails the *whole* envelope on the first event it does not
    /// recognise, and `guard-nm-host` turned that error into `unwrap_or_default()` — an
    /// empty event list, judged as a ping, answered `ok:true, processed:0`. So a single
    /// `{"type":"click"}` appended to a batch made every Critical event in that batch
    /// disappear with no stderr, no audit row and a success-shaped response. Two separate
    /// things reach that: an attacker who wants selective silence, and an honest extension
    /// that shipped a new event kind before the host learned it — a fail-open forward
    /// compatibility trap that needs no attacker at all.
    ///
    /// Returns the events that converted, paired with `(index, reason)` for each that did
    /// not, so the caller can judge the good ones and still report the gap.
    pub fn convert_envelope_lenient(&mut self, env: &BrowserEnvelope) -> LenientEvents {
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for (i, ev) in env.events.iter().enumerate() {
            match self.convert_event(ev) {
                Ok(e) => out.push(e),
                Err(e) => skipped.push((i, e.to_string())),
            }
        }
        (out, skipped)
    }

    /// Same, from raw JSON. An envelope that does not parse at all is still an error:
    /// that is a framing failure, not one unrecognised member of a list.
    pub fn parse_envelope_lenient(&mut self, json: &str) -> Result<LenientEvents> {
        let env: BrowserEnvelope = serde_json::from_str(json)?;
        Ok(self.convert_envelope_lenient(&env))
    }

    fn convert_event(&mut self, ev: &BrowserEvent) -> Result<GuardEvent> {
        self.seq += 1;
        let app = ev.app.clone().unwrap_or_else(|| "browser".into());
        let mut metadata = HashMap::new();
        if let Some(url) = &ev.url {
            metadata.insert("url".into(), url.clone());
        }
        let (event_type, metadata) = match ev.kind.as_str() {
            "ui_text" => {
                metadata.insert("ui_text".into(), ev.text.clone().unwrap_or_default());
                (EventType::UiTreeDelta, metadata)
            }
            "form_fill" => {
                metadata.insert("field_id".into(), ev.field_id.clone().unwrap_or_default());
                metadata.insert(
                    "profile_key".into(),
                    ev.profile_key.clone().unwrap_or_default(),
                );
                metadata.insert("required".into(), ev.required.unwrap_or(false).to_string());
                metadata.insert(
                    "value_filled".into(),
                    ev.value_filled.unwrap_or(true).to_string(),
                );
                metadata.insert("is_trap".into(), ev.is_trap.unwrap_or(false).to_string());
                if let Some(p) = &ev.probe_type {
                    metadata.insert("probe_type".into(), p.clone());
                }
                (EventType::FormFill, metadata)
            }
            other => anyhow::bail!("unsupported browser event type: {other}"),
        };
        Ok(GuardEvent {
            event_id: format!("br-{}", self.seq),
            timestamp_ms: now_ms(),
            platform: "browser".into(),
            event_type,
            source_app: app,
            agent_context_id: self.session_id.clone(),
            metadata,
        })
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_and_fm_from_extension_payload() {
        let raw = r#"{
          "type": "browser_events",
          "source": "extension-chromium",
          "events": [
            {"type":"ui_text","app":"browser","text":"确认支付","url":"https://shop.example/checkout"},
            {"type":"form_fill","app":"browser","field_id":"dob","profile_key":"date_of_birth","required":false,"value_filled":true,"is_trap":false,"probe_type":"form_minimization"}
          ]
        }"#;
        let mut adapter = BrowserAdapter::new();
        adapter.set_session(Some("ext-sess".into()));
        let events = adapter.parse_envelope(raw).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].metadata.get("ui_text").map(String::as_str),
            Some("确认支付")
        );
        assert!(matches!(events[1].event_type, EventType::FormFill));
    }
}
