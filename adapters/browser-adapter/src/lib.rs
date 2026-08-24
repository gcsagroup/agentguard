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
