//! Android adapter: Accessibility / companion JSON → GuardEvent.

mod sim;

use anyhow::Result;
use guard_schema::{EventType, GuardEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use sim::{AndroidSimAdapter, SimObservation};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidEnvelope {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub events: Vec<AndroidEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
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
    pub marker: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub item_key: Option<String>,
    #[serde(default)]
    pub necessity: Option<String>,
    #[serde(default)]
    pub granted: Option<bool>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub hint: Option<String>,
    /// Packages with a registered receiver for the agent's text-input broadcast
    /// ((A)I Sees A5). A receiver needs no permission, so any third-party
    /// package here reads everything the agent types.
    ///
    /// `None` means **not surveyed** (old companion build, or the scan failed) —
    /// deliberately distinct from `Some([])`, "surveyed and nothing found". An
    /// absent field must never be able to clear a latched risk.
    #[serde(default)]
    pub broadcast_input_receivers: Option<Vec<String>>,
    /// Enabled accessibility services other than AgentGuard's own ((A)I Sees A6).
    /// A service on this list sees `TYPE_VIEW_TEXT_CHANGED`, which includes
    /// password fields in plaintext. `None` = not surveyed.
    #[serde(default)]
    pub foreign_a11y_services: Option<Vec<String>>,
    /// Subset of `foreign_a11y_services` whose event mask actually includes
    /// `TYPE_VIEW_TEXT_CHANGED`, i.e. those really on the typed-text stream.
    #[serde(default)]
    pub text_capturing_services: Option<Vec<String>>,
    /// Packages holding `READ_LOGS` (AgentScan §3.8): who can read what the agent,
    /// its host and this guard write to logcat.
    #[serde(default)]
    pub log_readers: Option<Vec<String>>,
    /// Whether package enumeration actually ran. Absent or `false` means `log_readers`
    /// is bounded by Android's package visibility, not that the device is clean.
    #[serde(default)]
    pub log_readers_enumerable: Option<bool>,
    /// Broadcast action names the survey looked for (for the audit trail).
    #[serde(default)]
    pub broadcast_actions: Vec<String>,
    /// Parts of the survey that could not be completed (package-visibility
    /// limits, exceptions). Non-empty means the result is partial, so "clean"
    /// is not a conclusion that can be drawn from it.
    #[serde(default)]
    pub scan_errors: Vec<String>,
    /// SHA-256 of the observed package's signing certificates, comma-separated
    /// (AgentScan §3.5). Read from `PackageManager.GET_SIGNING_CERTIFICATES` by the
    /// companion, i.e. from the OS.
    ///
    /// **This field did not exist until iteration 19, and its absence was a severed
    /// mechanism.** `AppAttestor` computed the digest, `PayloadSerializer` put it in the
    /// envelope JSON, and this struct — which is the only path from the companion to the
    /// engine, via `guard-localapi` — had no field to receive it, so serde dropped it.
    /// Every app on a real device was therefore `AppIdentity::Unattested` and the whole
    /// §3.5 signer-pinning defence was inert. The eval corpus did not catch it because
    /// scenarios write `signer_sha256` straight into `metadata` and never cross this
    /// boundary. Same shape as iteration 17's logcat leak: Kotlin computes it, Rust never
    /// receives it, and the docs describe the intent.
    #[serde(default)]
    pub signer_sha256: Option<String>,
    /// Why attestation failed, when it did: `unsigned`, or the exception class name.
    #[serde(default)]
    pub attest_error: Option<String>,
    /// The label the OS reports for the package — `PackageManager.getApplicationLabel`,
    /// not text scraped off the screen (AgentScan §3.6).
    #[serde(default)]
    pub app_label: Option<String>,
    /// Difference hash of the package's icon as the OS renders it, 16 lowercase hex
    /// characters. See `guard_schema::visual::IconHash` for the normative algorithm.
    #[serde(default)]
    pub icon_dhash: Option<String>,
    /// The task this session is for (`session_start` only) — selects the plan and its Aura §4.4
    /// resource ceiling.
    #[serde(default)]
    pub task_profile: Option<String>,
    /// A request to narrow the plan's app / data-key / host ceilings. Comma-separated. These can
    /// only ever narrow — see `guard_schema::TaskScope::narrow`.
    #[serde(default)]
    pub task_apps: Option<String>,
    #[serde(default)]
    pub task_data_keys: Option<String>,
    #[serde(default)]
    pub task_hosts: Option<String>,
    /// Why the appearance could not be read at all: the exception class name, usually
    /// `NameNotFoundException` (Android 11+ package-visibility filtering).
    ///
    /// Present only when **neither** label nor icon could be read. An absent appearance and a
    /// clean appearance are different claims, and this keeps the engine from confusing them —
    /// the same rule `log_readers_enumerable` and `scan_errors` already follow.
    #[serde(default)]
    pub face_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct AndroidAdapter {
    session_id: Option<String>,
    seq: u64,
}

#[derive(Debug, Clone)]
pub struct AndroidCapabilities {
    pub simulation: bool,
    pub accessibility_native: bool,
}

pub fn android_capabilities() -> AndroidCapabilities {
    AndroidCapabilities {
        simulation: true,
        accessibility_native: cfg!(target_os = "android"),
    }
}

impl AndroidAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_session(&mut self, session_id: Option<String>) {
        self.session_id = session_id;
    }

    pub fn parse_envelope(&mut self, json: &str) -> Result<Vec<GuardEvent>> {
        let env: AndroidEnvelope = serde_json::from_str(json)?;
        self.convert_envelope(&env)
    }

    pub fn convert_envelope(&mut self, env: &AndroidEnvelope) -> Result<Vec<GuardEvent>> {
        if self.session_id.is_none() {
            self.session_id = env.session_id.clone();
        }
        let mut out = Vec::new();
        for ev in &env.events {
            out.push(self.convert_event(ev)?);
        }
        Ok(out)
    }

    fn convert_event(&mut self, ev: &AndroidEvent) -> Result<GuardEvent> {
        self.seq += 1;
        // `filter`, not just `or_else`: `{"app": ""}` deserialises to `Some("")`, so the package
        // fallback never ran and the event reached the engine with `source_app: ""`. An empty
        // `source_app` satisfied `apps_match` — which treats an empty side as matching everything —
        // and so switched the Critical app-grant check off for that event while keeping the package
        // field the identity checks read. Blank is absent.
        let app = ev
            .app
            .clone()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .or_else(|| ev.package.clone())
            .unwrap_or_else(|| "android".into());
        let mut metadata = HashMap::new();
        if let Some(pkg) = &ev.package {
            metadata.insert("package".into(), pkg.clone());
        }
        if let Some(url) = &ev.url {
            metadata.insert("url".into(), url.clone());
        }
        if let Some(bytes) = ev.bytes {
            metadata.insert("bytes".into(), bytes.to_string());
        }
        // Identity keys, forwarded by an explicit **allow-list** rather than
        // `#[serde(flatten)]`. A flatten would forward every key the poster invents, and
        // the poster is whatever process reached `127.0.0.1:8788` — including the ENV
        // markers iteration 17 showed a page can forge into a Critical block, and
        // `agent_id`. Adding a key here is a decision; inheriting one is not.
        for (key, value) in [
            ("signer_sha256", ev.signer_sha256.as_deref()),
            ("attest_error", ev.attest_error.as_deref()),
            ("app_label", ev.app_label.as_deref()),
            ("icon_dhash", ev.icon_dhash.as_deref()),
            ("face_error", ev.face_error.as_deref()),
        ] {
            if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
                metadata.insert(key.into(), v.to_string());
            }
        }

        let (event_type, metadata) = match ev.kind.as_str() {
            // Aura §4.4 / §4.3.2: the companion can open a session **naming its task**, which is
            // what selects the plan and with it the resource ceiling. Without this kind the envelope
            // had no way to say a session was starting at all, so the plan library `guard-localapi`
            // loads could never be selected from — loaded by the host, reachable by nothing.
            "session_start" => {
                for (key, value) in [
                    ("task_profile", ev.task_profile.as_deref()),
                    ("task_apps", ev.task_apps.as_deref()),
                    ("task_data_keys", ev.task_data_keys.as_deref()),
                    ("task_hosts", ev.task_hosts.as_deref()),
                ] {
                    if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
                        metadata.insert(key.into(), v.to_string());
                    }
                }
                (EventType::AgentSessionStart, metadata)
            }
            "session_end" => (EventType::AgentSessionEnd, metadata),
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
            "overlay_marker" => {
                let marker = ev
                    .marker
                    .clone()
                    .or_else(|| ev.text.clone())
                    .unwrap_or_default();
                metadata.insert("ui_text".into(), marker);
                metadata.insert("overlay_marker".into(), "true".into());
                (EventType::UiTreeDelta, metadata)
            }
            "deeplink" => {
                let uri = ev.uri.clone().unwrap_or_default();
                metadata.insert("uri".into(), uri.clone());
                metadata.insert("ui_text".into(), uri);
                (EventType::Deeplink, metadata)
            }
            "permission_request" => {
                metadata.insert("item_key".into(), ev.item_key.clone().unwrap_or_default());
                metadata.insert(
                    "necessity".into(),
                    ev.necessity.clone().unwrap_or_else(|| "unnecessary".into()),
                );
                metadata.insert("granted".into(), ev.granted.unwrap_or(false).to_string());
                (EventType::PermissionRequest, metadata)
            }
            "env_survey" => {
                // Environment risk, not an agent action: two attack classes from
                // (A)I Sees (arXiv 2607.00333 §IV-C) that succeeded 20/20 against
                // the agents surveyed, and that AgentGuard is well placed to see
                // because it is itself an accessibility consumer.
                let receivers = ev.broadcast_input_receivers.as_deref();
                let services = ev.foreign_a11y_services.as_deref();
                let surveyed = receivers.is_some() || services.is_some();
                let mut markers: Vec<&str> = Vec::new();
                if receivers.map(|r| !r.is_empty()).unwrap_or(false) {
                    markers.push("[AG_BROADCAST_INPUT_SINK]");
                }
                if services.map(|s| !s.is_empty()).unwrap_or(false) {
                    markers.push("[AG_FOREIGN_A11Y_SERVICE]");
                }
                if ev
                    .log_readers
                    .as_deref()
                    .map(|l| !l.is_empty())
                    .unwrap_or(false)
                {
                    markers.push("[AG_LOG_READER]");
                }
                // Emit the lists whenever the field was present, empty included:
                // the engine needs "surveyed and empty" to clear a latched risk,
                // and must not read a missing field as empty.
                if let Some(r) = receivers {
                    metadata.insert("broadcast_input_receivers".into(), r.join(","));
                }
                if let Some(s) = services {
                    metadata.insert("foreign_a11y_services".into(), s.join(","));
                }
                if let Some(t) = &ev.text_capturing_services {
                    metadata.insert("text_capturing_services".into(), t.join(","));
                }
                if let Some(l) = &ev.log_readers {
                    metadata.insert("log_readers".into(), l.join(","));
                }
                if let Some(e) = ev.log_readers_enumerable {
                    metadata.insert("log_readers_enumerable".into(), e.to_string());
                }
                if !ev.broadcast_actions.is_empty() {
                    metadata.insert("broadcast_actions".into(), ev.broadcast_actions.join(","));
                }
                if !ev.scan_errors.is_empty() {
                    metadata.insert("scan_errors".into(), ev.scan_errors.join("; "));
                }
                // `env_surveyed` is the flag the engine keys on. A partial scan is
                // reported as *not* surveyed: a failed lookup that returns an empty
                // list would otherwise unlatch a critical risk.
                metadata.insert(
                    "env_surveyed".into(),
                    (surveyed && ev.scan_errors.is_empty()).to_string(),
                );
                metadata.insert("ui_text".into(), markers.join(" "));
                (EventType::EnvironmentSurvey, metadata)
            }
            "network_meta" => {
                let hint = ev
                    .hint
                    .clone()
                    .or_else(|| ev.text.clone())
                    .unwrap_or_default();
                metadata.insert("ui_text".into(), hint);
                (EventType::NetworkFlow, metadata)
            }
            other => anyhow::bail!("unsupported android event type: {other}"),
        };

        Ok(GuardEvent {
            event_id: format!("and-{}", self.seq),
            timestamp_ms: now_ms(),
            platform: "android".into(),
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

    /// **The cross-language guard.** Every metadata key the Kotlin companion writes into the
    /// envelope must have a field on [`AndroidEvent`] to receive it.
    ///
    /// This test exists because `signer_sha256` did not have one for six iterations. The
    /// companion computed a signing-certificate digest, `PayloadSerializer` put it in the
    /// JSON, serde dropped it here, and the engine saw `Unattested` for every app on every
    /// real device — while `docs/app-identity.md` described signer pinning as shipped. The
    /// eval corpus could not catch it: scenarios write metadata directly and never cross
    /// this boundary. Nor could any Rust test that did not read the Kotlin.
    ///
    /// Scanning source is a regression guard, not a proof — it sees `obj.put("literal"` and
    /// `out["literal"] =`, so a key assembled from a variable is invisible to it. That is
    /// stated rather than implied, and it is why the assertion also fails when it can find
    /// no keys at all: a scanner that silently matched nothing would pass forever.
    #[test]
    fn every_key_the_companion_sends_has_a_field_here() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = root.join("apps/android-companion/app/src/main/java/com/agentguard/companion");
        // Keys the adapter builds itself from typed fields, or that are envelope-level
        // rather than per-event.
        let handled: &[&str] = &[
            "type",
            "app",
            "package",
            "text",
            "field_id",
            "profile_key",
            "required",
            "value_filled",
            "is_trap",
            "probe_type",
            "marker",
            "uri",
            "item_key",
            "necessity",
            "granted",
            "url",
            "bytes",
            "hint",
            "broadcast_input_receivers",
            "foreign_a11y_services",
            "text_capturing_services",
            "log_readers",
            "log_readers_enumerable",
            "broadcast_actions",
            "scan_errors",
            "events",
            "session_id",
            "source",
            "signer_sha256",
            "attest_error",
            "app_label",
            "icon_dhash",
            "face_error",
            // Aura §4.4 session scope. These fields existed on `AndroidEvent` from the day
            // `session_start` was added to the adapter, but no Kotlin ever wrote them, so they
            // were absent from this list and the list was still correct. The companion now
            // emits them, and this test is what noticed.
            "task_profile",
            "task_apps",
            "task_data_keys",
            "task_hosts",
        ];
        // Files whose JSON does **not** cross this boundary, each with the reason. The list
        // is an exclusion list rather than an inclusion list on purpose: a new companion file
        // is scanned by default, so the failure mode is a noisy test rather than a blind one.
        // Iteration 17's print-sink scanner was an inclusion list and was blind to the two
        // sinks that mattered.
        let not_envelope: &[(&str, &str)] = &[(
            "EnvelopeSink.kt",
            "writes the on-device risk record the companion UI reads back, plus the envelope \
             archive; its keys never travel to the engine as event metadata",
        )];
        let mut found = 0usize;
        let mut missing: Vec<(String, String)> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("companion sources must be readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("kt") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if not_envelope.iter().any(|(f, _)| *f == name) {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            for (pattern, offset) in [(".put(\"", 6), ("out[\"", 5)] {
                let mut from = 0;
                while let Some(at) = src[from..].find(pattern) {
                    let start = from + at + offset;
                    let Some(end) = src[start..].find('"') else {
                        break;
                    };
                    let key = &src[start..start + end];
                    from = start + end;
                    if key.is_empty() || key.contains('$') {
                        continue;
                    }
                    found += 1;
                    if !handled.contains(&key) {
                        missing.push((file.clone(), key.to_string()));
                    }
                }
            }
        }
        assert!(
            found > 20,
            "the scanner found only {found} keys — it has stopped matching the companion's \
             source, which makes it a test that always passes"
        );
        assert!(
            missing.is_empty(),
            "the companion writes these keys and `AndroidEvent` cannot receive them, so \
             serde will drop them silently: {missing:?}"
        );
    }

    /// The companion must be able to open a session **naming its task**, or the plan library that
    /// `guard-localapi` loads can never be selected from — loaded by the host, reachable by nothing.
    #[test]
    fn the_envelope_can_open_a_scoped_session() {
        let mut a = AndroidAdapter::new();
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[
                   {"type":"session_start","app":"Claude","task_profile":"book_hotel",
                    "task_apps":"Booking","task_data_keys":"name,check_in","task_hosts":"stripe.com"},
                   {"type":"session_end","app":"Claude"}]}"#,
            )
            .unwrap();
        assert_eq!(evs[0].event_type, EventType::AgentSessionStart);
        assert_eq!(
            evs[0].metadata.get("task_profile").map(String::as_str),
            Some("book_hotel")
        );
        assert_eq!(
            evs[0].metadata.get("task_apps").map(String::as_str),
            Some("Booking")
        );
        assert_eq!(
            evs[0].metadata.get("task_data_keys").map(String::as_str),
            Some("name,check_in")
        );
        assert_eq!(
            evs[0].metadata.get("task_hosts").map(String::as_str),
            Some("stripe.com")
        );
        assert_eq!(evs[1].event_type, EventType::AgentSessionEnd);
        // A session start with no task is still a session start, and declares nothing.
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[{"type":"session_start","app":"Claude"}]}"#,
            )
            .unwrap();
        assert_eq!(evs[0].event_type, EventType::AgentSessionStart);
        for k in ["task_profile", "task_apps", "task_data_keys", "task_hosts"] {
            assert!(
                !evs[0].metadata.contains_key(k),
                "{k}: {:?}",
                evs[0].metadata
            );
        }
    }

    /// A blank `app` must fall back to the package, not reach the engine as an empty `source_app`.
    /// An empty `source_app` satisfies `apps_match` and switched the session app grant off per-event.
    #[test]
    fn a_blank_app_name_falls_back_to_the_package() {
        let mut a = AndroidAdapter::new();
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[
                   {"type":"ui_text","app":"","package":"com.evil.bank","text":"Balance"},
                   {"type":"ui_text","app":"   ","package":"com.evil.bank","text":"Balance"},
                   {"type":"ui_text","package":"com.evil.bank","text":"Balance"}]}"#,
            )
            .unwrap();
        for (i, ev) in evs.iter().enumerate() {
            assert_eq!(ev.source_app, "com.evil.bank", "event {i}");
        }
        // With neither, the platform name is the last resort — still never empty.
        let evs = a
            .parse_envelope(r#"{"type":"batch","events":[{"type":"ui_text","text":"x"}]}"#)
            .unwrap();
        assert_eq!(evs[0].source_app, "android");
    }

    /// The companion attests; the engine must receive it. This test exists because it did
    /// not: `signer_sha256` was in the envelope JSON and had no field on `AndroidEvent`, so
    /// serde dropped it and every app on a real device was `Unattested`.
    #[test]
    fn identity_keys_reach_the_engine() {
        let mut a = AndroidAdapter::new();
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[{"type":"ui_text","app":"WeChat",
                   "package":"com.tencent.mm","signer_sha256":"aa11,bb22",
                   "app_label":"微信","icon_dhash":"0f1e2d3c4b5a6978","text":"hi"}]}"#,
            )
            .unwrap();
        let m = &evs[0].metadata;
        assert_eq!(m.get("package").map(String::as_str), Some("com.tencent.mm"));
        assert_eq!(
            m.get("signer_sha256").map(String::as_str),
            Some("aa11,bb22")
        );
        assert_eq!(m.get("app_label").map(String::as_str), Some("微信"));
        assert_eq!(
            m.get("icon_dhash").map(String::as_str),
            Some("0f1e2d3c4b5a6978")
        );
        // And the "could not read the appearance at all" reason, which must be distinguishable
        // from "read it and it was clean".
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[{"type":"ui_text","app":"X","package":"com.evil.clone",
                   "face_error":"NameNotFoundException","text":"hi"}]}"#,
            )
            .unwrap();
        assert_eq!(
            evs[0].metadata.get("face_error").map(String::as_str),
            Some("NameNotFoundException")
        );
    }

    /// An attestation failure is forwarded as a *reason*, and an empty string is not
    /// forwarded at all — the engine distinguishes "no attestation" from "a digest that did
    /// not match", and an empty value would blur the two.
    #[test]
    fn attest_error_is_forwarded_and_blanks_are_not() {
        let mut a = AndroidAdapter::new();
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[{"type":"ui_text","app":"X","package":"com.x",
                   "attest_error":"NameNotFoundException","signer_sha256":"  ",
                   "app_label":"","text":"hi"}]}"#,
            )
            .unwrap();
        let m = &evs[0].metadata;
        assert_eq!(
            m.get("attest_error").map(String::as_str),
            Some("NameNotFoundException")
        );
        assert!(!m.contains_key("signer_sha256"), "{m:?}");
        assert!(!m.contains_key("app_label"), "{m:?}");
    }

    /// The forwarding list is an **allow-list**. Anything can POST to the local API, so a
    /// key the companion never sends must not appear in engine metadata just because it was
    /// in the JSON — `agent_id` and the ENV markers are Critical-block inputs.
    #[test]
    fn unlisted_keys_are_not_forwarded() {
        let mut a = AndroidAdapter::new();
        let evs = a
            .parse_envelope(
                r#"{"type":"batch","events":[{"type":"ui_text","app":"X","package":"com.x",
                   "agent_id":"claude-desktop","env_surveyed":"true",
                   "broadcast_input_receivers_raw":"x","session_nonce":"1","text":"hi"}]}"#,
            )
            .unwrap();
        let m = &evs[0].metadata;
        for forged in ["agent_id", "session_nonce", "broadcast_input_receivers_raw"] {
            assert!(!m.contains_key(forged), "{forged} was forwarded: {m:?}");
        }
        // `env_surveyed` is set by the adapter for env_survey events only, from a field it
        // controls — never copied from the poster's JSON.
        assert!(!m.contains_key("env_surveyed"), "{m:?}");
    }

    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("fixture")
    }

    #[test]
    fn payment_and_fm_from_companion_payload() {
        let raw = fixture("android_accessibility_payload.json");
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(&raw).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].metadata.get("ui_text").map(String::as_str),
            Some("确认支付")
        );
        assert!(matches!(events[1].event_type, EventType::FormFill));
        assert_eq!(events[0].platform, "android");
    }

    #[test]
    fn all_finding_types_convert() {
        let raw = r#"{
          "type": "android_events",
          "source": "android-companion",
          "session_id": "sess-1",
          "events": [
            {"type":"ui_text","app":"Chrome","package":"com.android.chrome","text":"Pay now"},
            {"type":"form_fill","app":"Booking","field_id":"phone","profile_key":"phone_number","required":false,"value_filled":true,"is_trap":true,"probe_type":"trap_resistance"},
            {"type":"overlay_marker","app":"SystemUI","marker":"[AG_SCREENSHOT_TAMPER]"},
            {"type":"deeplink","app":"Browser","uri":"intent://pay/confirm?amount=999"},
            {"type":"permission_request","app":"Agent","item_key":"contacts","necessity":"unnecessary","granted":true},
            {"type":"network_meta","app":"Upload","url":"https://unknown.cdn/upload","hint":"Upload started [AG_LARGE_UPLOAD] 50MB"}
          ]
        }"#;
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(raw).unwrap();
        assert_eq!(events.len(), 6);
        assert!(matches!(events[0].event_type, EventType::UiTreeDelta));
        assert!(matches!(events[1].event_type, EventType::FormFill));
        assert!(matches!(events[2].event_type, EventType::UiTreeDelta));
        assert!(matches!(events[3].event_type, EventType::Deeplink));
        assert!(matches!(events[4].event_type, EventType::PermissionRequest));
        assert!(matches!(events[5].event_type, EventType::NetworkFlow));
    }

    /// The simulator must be able to reach §3.5 and §3.6, or `sim-android` is structurally unable
    /// to demonstrate two of the mechanisms this project ships.
    #[test]
    fn sim_ui_text_carries_the_identity_keys() {
        let obs: SimObservation = serde_json::from_str(
            r#"{"kind":"ui_text","app":"WeChat","text":"hi","package":"com.evil.clone",
               "signer_sha256":"aa11","app_label":"微信","icon_dhash":"3333333333333333"}"#,
        )
        .unwrap();
        let mut a = AndroidSimAdapter::new();
        a.start_session("and-demo", "Claude");
        a.ingest(obs);
        let events = a.drain().unwrap();
        let ev = events.last().expect("one event");
        assert_eq!(
            ev.metadata.get("package").map(String::as_str),
            Some("com.evil.clone")
        );
        assert_eq!(
            ev.metadata.get("signer_sha256").map(String::as_str),
            Some("aa11")
        );
        assert_eq!(
            ev.metadata.get("app_label").map(String::as_str),
            Some("微信")
        );
        assert_eq!(
            ev.metadata.get("icon_dhash").map(String::as_str),
            Some("3333333333333333")
        );
        // Omitted keys stay omitted rather than becoming empty strings.
        let plain: SimObservation =
            serde_json::from_str(r#"{"kind":"ui_text","app":"X","text":"hi"}"#).unwrap();
        let mut a = AndroidSimAdapter::new();
        a.start_session("and-demo2", "Claude");
        a.ingest(plain);
        let ev = a.drain().unwrap().last().unwrap().clone();
        for key in ["signer_sha256", "app_label", "icon_dhash"] {
            assert!(!ev.metadata.contains_key(key), "{key}: {:?}", ev.metadata);
        }
    }

    #[test]
    fn sim_bridge_without_sdk() {
        let mut adapter = AndroidSimAdapter::new();
        adapter.start_session("and-demo", "Claude");
        adapter.ingest(SimObservation::UiText {
            app: "Chrome".into(),
            text: "确认支付".into(),
            package: Some("com.android.chrome".into()),
            signer_sha256: None,
            app_label: None,
            icon_dhash: None,
            attest_error: None,
            face_error: None,
        });
        adapter.ingest(SimObservation::Deeplink {
            app: "Browser".into(),
            uri: "intent://pay/confirm".into(),
            package: None,
        });
        let events = adapter.drain().unwrap();
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0].event_type, EventType::AgentSessionStart));
        assert_eq!(events[1].platform, "android");
    }

    /// (A)I Sees A5/A6: the companion reports what else on the device can read
    /// the agent's input.
    #[test]
    fn hostile_env_survey_emits_both_markers() {
        let raw = fixture("android_env_survey_hostile.json");
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(&raw).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert!(matches!(ev.event_type, EventType::EnvironmentSurvey));
        let ui = ev.metadata.get("ui_text").unwrap();
        assert!(ui.contains("[AG_BROADCAST_INPUT_SINK]"), "{ui}");
        assert!(ui.contains("[AG_FOREIGN_A11Y_SERVICE]"), "{ui}");
        assert_eq!(
            ev.metadata
                .get("broadcast_input_receivers")
                .map(String::as_str),
            Some("com.evil.keylog/.InputReceiver")
        );
        assert!(ev
            .metadata
            .get("broadcast_actions")
            .unwrap()
            .contains("ADB_INPUT_B64"));
    }

    /// A clean survey must still be reportable, so the engine can clear a
    /// previously latched risk instead of staying pessimistic forever.
    #[test]
    fn clean_env_survey_has_no_markers_but_is_marked_surveyed() {
        let raw = fixture("android_env_survey_clean.json");
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(&raw).unwrap();
        let ev = &events[0];
        assert!(matches!(ev.event_type, EventType::EnvironmentSurvey));
        assert_eq!(ev.metadata.get("ui_text").map(String::as_str), Some(""));
        // Present-but-empty: the engine needs this to clear a latch.
        assert_eq!(
            ev.metadata.get("foreign_a11y_services").map(String::as_str),
            Some("")
        );
        assert_eq!(
            ev.metadata.get("env_surveyed").map(String::as_str),
            Some("true")
        );
    }

    /// A partial scan is reported as *not surveyed*. An empty list from a failed
    /// lookup must never be able to clear a latched risk.
    #[test]
    fn partial_env_survey_is_not_reported_as_surveyed() {
        let raw = fixture("android_env_survey_partial.json");
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(&raw).unwrap();
        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("env_surveyed").map(String::as_str),
            Some("false")
        );
        assert!(ev
            .metadata
            .get("scan_errors")
            .unwrap()
            .contains("visibility"));
    }

    /// An envelope from a build that predates the survey must still parse, and
    /// must not claim to have surveyed anything.
    #[test]
    fn legacy_envelope_without_survey_fields_parses_as_unsurveyed() {
        let raw = r#"{
          "type": "android_events",
          "session_id": "old",
          "events": [{"type":"env_survey","app":"Companion"}]
        }"#;
        let mut adapter = AndroidAdapter::new();
        let events = adapter.parse_envelope(raw).unwrap();
        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("env_surveyed").map(String::as_str),
            Some("false")
        );
        assert!(!ev.metadata.contains_key("foreign_a11y_services"));
    }
}
