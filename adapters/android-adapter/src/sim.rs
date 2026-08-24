//! Simulation backend for developing the Android bridge without the Android SDK.

use anyhow::Result;
use guard_schema::{EventType, GuardEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SimObservation {
    UiText {
        app: String,
        text: String,
        #[serde(default)]
        package: Option<String>,
        /// Signing-certificate digests, as the companion reads them (AgentScan §3.5).
        #[serde(default)]
        signer_sha256: Option<String>,
        /// The label `PackageManager` reports for `package` (AgentScan §3.6).
        #[serde(default)]
        app_label: Option<String>,
        /// Difference hash of that package's icon; see `guard_schema::visual::IconHash`.
        #[serde(default)]
        icon_dhash: Option<String>,
        /// Why attestation failed, when it did (`unsigned`, or an exception class name).
        #[serde(default)]
        attest_error: Option<String>,
        /// Why the appearance could not be read at all — usually package-visibility filtering.
        /// Without this the simulator could not reach `APP-FACE-UNREADABLE`, which is the rule
        /// that reports §3.6 having been unable to run.
        #[serde(default)]
        face_error: Option<String>,
    },
    FormFill {
        app: String,
        field_id: String,
        profile_key: String,
        required: bool,
        value_filled: bool,
        is_trap: bool,
        #[serde(default)]
        probe_type: Option<String>,
    },
    OverlayMarker {
        app: String,
        marker: String,
    },
    Deeplink {
        app: String,
        uri: String,
        /// The emitting package. Absent at first, which meant neither app identity (§3.5) nor the
        /// appearance check (§3.6) ran on a simulated deeplink — the event type where a forged
        /// deeplink from a cloned app is most consequential.
        #[serde(default)]
        package: Option<String>,
    },
    PermissionRequest {
        app: String,
        item_key: String,
        necessity: String,
        granted: bool,
    },
    NetworkMeta {
        app: String,
        #[serde(default)]
        url: Option<String>,
        hint: String,
    },
}

#[derive(Debug, Default)]
pub struct AndroidSimAdapter {
    queue: VecDeque<GuardEvent>,
    session_id: Option<String>,
    seq: u64,
}

impl AndroidSimAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_session(&self) -> bool {
        self.session_id.is_some()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
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
            platform: "android".into(),
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
            platform: "android".into(),
            event_type: EventType::AgentSessionEnd,
            source_app: app.into(),
            agent_context_id: sid,
            metadata: HashMap::new(),
        });
        self.session_id = None;
    }

    pub fn ingest(&mut self, obs: SimObservation) {
        let session = self.session_id.clone();
        let event_id = self.next_id();
        let event = match obs {
            SimObservation::UiText {
                app,
                text,
                package,
                signer_sha256,
                app_label,
                icon_dhash,
                attest_error,
                face_error,
            } => {
                let mut metadata = HashMap::new();
                metadata.insert("ui_text".into(), text);
                if let Some(pkg) = package {
                    metadata.insert("package".into(), pkg);
                }
                // Identity keys, so `sim-android` can exercise §3.5 and §3.6 without a device.
                // Without them the simulator could reach neither, which would make the demo path
                // structurally unable to show the two mechanisms it ships — a smaller version of
                // the severed-channel defect this iteration fixed at the real boundary.
                for (key, value) in [
                    ("signer_sha256", signer_sha256),
                    ("app_label", app_label),
                    ("icon_dhash", icon_dhash),
                    ("attest_error", attest_error),
                    ("face_error", face_error),
                ] {
                    if let Some(v) = value
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                    {
                        metadata.insert(key.into(), v);
                    }
                }
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "android".into(),
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
                    platform: "android".into(),
                    event_type: EventType::FormFill,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::OverlayMarker { app, marker } => {
                let mut metadata = HashMap::new();
                metadata.insert("ui_text".into(), marker);
                metadata.insert("overlay_marker".into(), "true".into());
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "android".into(),
                    event_type: EventType::UiTreeDelta,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::Deeplink { app, uri, package } => {
                let mut metadata = HashMap::new();
                metadata.insert("uri".into(), uri.clone());
                metadata.insert("ui_text".into(), uri);
                if let Some(pkg) = package {
                    metadata.insert("package".into(), pkg);
                }
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "android".into(),
                    event_type: EventType::Deeplink,
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
                    platform: "android".into(),
                    event_type: EventType::PermissionRequest,
                    source_app: app,
                    agent_context_id: session,
                    metadata,
                }
            }
            SimObservation::NetworkMeta { app, url, hint } => {
                let mut metadata = HashMap::new();
                metadata.insert("ui_text".into(), hint);
                if let Some(u) = url {
                    metadata.insert("url".into(), u);
                }
                GuardEvent {
                    event_id,
                    timestamp_ms: now_ms(),
                    platform: "android".into(),
                    event_type: EventType::NetworkFlow,
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
        format!("and-sim-{}", self.seq)
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
