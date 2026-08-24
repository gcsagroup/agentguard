//! Simulation backend for developing the event bridge without Windows UIA.

use anyhow::Result;
use guard_schema::{EventType, GuardEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SimObservation {
    Focus {
        app: String,
    },
    UiText {
        app: String,
        text: String,
    },
    FormFill {
        app: String,
        field_id: String,
        profile_key: String,
        required: bool,
        value_filled: bool,
        is_trap: bool,
        probe_type: Option<String>,
    },
    PermissionRequest {
        app: String,
        item_key: String,
        necessity: String,
        granted: bool,
    },
    /// Inject OVL rule markers (e.g. `[AG_TRANSPARENT_OVERLAY]`).
    OverlayMarker {
        app: String,
        marker: String,
    },
}

#[derive(Debug, Default)]
pub struct WinAdapter {
    queue: VecDeque<GuardEvent>,
    session_id: Option<String>,
    seq: u64,
}

impl WinAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_session(&self) -> bool {
        self.session_id.is_some()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Push a pre-built GuardEvent (used by platform-specific AX bridges).
    pub fn push_raw(&mut self, mut event: GuardEvent) {
        if event.agent_context_id.is_none() {
            event.agent_context_id = self.session_id.clone();
        }
        self.push(event);
    }

    pub fn start_session(&mut self, session_id: impl Into<String>, app: &str) {
        self.start_task_session(session_id, app, &guard_schema::TaskDeclaration::default());
    }

    /// Open a session **declaring the task** (Aura §4.4), so the plan library can select a ceiling.
    ///
    /// `start_session` sends no metadata, which meant no shipped event stream ever named a task
    /// profile: the plan library was loaded by four hosts and selected by none of them. A host that
    /// knows what it was asked to do passes it here.
    pub fn start_task_session(
        &mut self,
        session_id: impl Into<String>,
        app: &str,
        task: &guard_schema::TaskDeclaration,
    ) {
        let sid = session_id.into();
        self.session_id = Some(sid.clone());
        let event_id = self.next_id();
        self.push(GuardEvent {
            event_id,
            timestamp_ms: now_ms(),
            platform: "windows".into(),
            event_type: EventType::AgentSessionStart,
            source_app: app.into(),
            agent_context_id: Some(sid),
            metadata: task.to_metadata(),
        });
    }

    pub fn end_session(&mut self, app: &str) {
        let sid = self.session_id.clone();
        let event_id = self.next_id();
        self.push(GuardEvent {
            event_id,
            timestamp_ms: now_ms(),
            platform: "windows".into(),
            event_type: EventType::AgentSessionEnd,
            source_app: app.into(),
            agent_context_id: sid,
            metadata: HashMap::new(),
        });
        self.session_id = None;
    }

    pub fn ingest(&mut self, obs: SimObservation) {
        let event_id = self.next_id();
        let session = self.session_id.clone();
        let event = match obs {
            SimObservation::Focus { app } => GuardEvent {
                event_id,
                timestamp_ms: now_ms(),
                platform: "windows".into(),
                event_type: EventType::ProcessFocus,
                source_app: app,
                agent_context_id: session,
                metadata: HashMap::new(),
            },
            SimObservation::UiText { app, text } => {
                let mut metadata = HashMap::new();
                metadata.insert("ui_text".into(), text);
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "windows".into(),
                    event_type: EventType::UiTreeDelta,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::FormFill {
                app,
                field_id,
                profile_key,
                required,
                value_filled,
                is_trap,
                probe_type,
            } => {
                let mut metadata = HashMap::new();
                metadata.insert("field_id".into(), field_id);
                metadata.insert("profile_key".into(), profile_key);
                metadata.insert("required".into(), required.to_string());
                metadata.insert("value_filled".into(), value_filled.to_string());
                metadata.insert("is_trap".into(), is_trap.to_string());
                if let Some(p) = probe_type {
                    metadata.insert("probe_type".into(), p);
                }
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "windows".into(),
                    event_type: EventType::FormFill,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::PermissionRequest {
                app,
                item_key,
                necessity,
                granted,
            } => {
                let mut metadata = HashMap::new();
                metadata.insert("item_key".into(), item_key);
                metadata.insert("necessity".into(), necessity);
                metadata.insert("granted".into(), granted.to_string());
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "windows".into(),
                    event_type: EventType::PermissionRequest,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::OverlayMarker { app, marker } => {
                let mut metadata = HashMap::new();
                metadata.insert("ui_text".into(), marker);
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "windows".into(),
                    event_type: EventType::UiTreeDelta,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
        };
        self.push(event);
    }

    pub fn drain(&mut self) -> Result<Vec<GuardEvent>> {
        Ok(self.queue.drain(..).collect())
    }

    fn push(&mut self, event: GuardEvent) {
        self.queue.push_back(event);
    }

    fn next_id(&mut self) -> String {
        self.seq += 1;
        format!("win-{}", self.seq)
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
    use guard_schema::EventType;

    #[test]
    fn form_fill_bridge() {
        let mut adapter = WinAdapter::new();
        adapter.start_session("s1", "Claude");
        adapter.ingest(SimObservation::FormFill {
            app: "Chrome".into(),
            field_id: "dob".into(),
            profile_key: "date_of_birth".into(),
            required: false,
            value_filled: true,
            is_trap: false,
            probe_type: Some("form_minimization".into()),
        });
        let events = adapter.drain().unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event_type, EventType::AgentSessionStart));
        assert!(matches!(events[1].event_type, EventType::FormFill));
        assert_eq!(
            events[1].metadata.get("profile_key").map(String::as_str),
            Some("date_of_birth")
        );
    }
}
