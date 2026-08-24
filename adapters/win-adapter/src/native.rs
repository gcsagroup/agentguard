//! The native Windows adapter: a real observer, not a queue.
//!
//! # What changed
//!
//! This type used to wrap the simulation bridge behind two "hint" structs and a
//! `// TODO(windows): replace with UIA element → FormFill / UiText mapping`. It was
//! constructed nowhere in the repository. It now observes: [`NativeWinAdapter::poll_once`] is
//! the Windows equivalent of the macOS `poll_ax_once` — walk the foreground window's UI tree,
//! capture its pixels, and hand both to the shared analysis in `guard-vision`.
//!
//! # Why the COM client is thread-local and not a field
//!
//! The first version of this file held a [`crate::uia::UiaClient`] in a field. That was wrong
//! twice over, and only the first way was loud.
//!
//! **It does not compile.** The desktop shell stores this adapter in Tauri's managed state,
//! which requires `Send + Sync`, and a `Mutex<T>` is `Sync` only when `T: Send`. A COM
//! interface in the `windows` crate is a `NonNull<c_void>`, which is not `Send`. The failure
//! is a build error **on Windows only** — and the Linux and macOS jobs compile the shell with
//! the `#[cfg(windows)]` observer field absent, so every green run said nothing about it. The
//! compile-time assertion at the bottom of this file is where that now fails.
//!
//! **And it would have been unsound if it had compiled.** `CoInitializeEx` initialises COM for
//! *the calling thread*. Constructing the adapter on the main thread and then polling it from
//! the spawned poller thread would use an interface across apartments without marshalling —
//! undefined behaviour that in practice returns `RPC_E_WRONG_THREAD` sometimes and works
//! sometimes, which is the worst available outcome for a security tool.
//!
//! A thread-local client fixes both: every thread that polls initialises COM once and owns its
//! own interfaces, and the adapter itself carries only plain data.

#![cfg(windows)]

use anyhow::Result;
use guard_privacy::AppFormSchema;
use guard_schema::{EventType, GuardEvent};
use guard_vision::{analyze_frame, FrameConsistency};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::sim::{SimObservation, WinAdapter};
use crate::uia::{UiaClient, WalkOutcome};
use crate::PlatformAdapter;

/// This platform's stamp on every event it produces.
pub const PLATFORM: &str = "windows";

thread_local! {
    /// This thread's UI Automation client, created on first use.
    ///
    /// The `Result` is cached, failure included: creating the client fails for a reason that
    /// does not change within a process (no COM, no UIA), so retrying per poll would be a
    /// guaranteed cross-process activation attempt twice a second.
    static UIA: RefCell<Option<Result<UiaClient, String>>> = const { RefCell::new(None) };
}

/// Run `f` with this thread's UIA client, initialising it if needed.
fn with_uia<R>(f: impl FnOnce(Result<&UiaClient, &str>) -> R) -> R {
    UIA.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(UiaClient::new());
        }
        match slot.as_ref().expect("just initialised") {
            Ok(client) => f(Ok(client)),
            Err(e) => f(Err(e.as_str())),
        }
    })
}

/// Whether this thread can create a UI Automation client, and why not when it cannot.
pub fn uia_status() -> Result<(), String> {
    with_uia(|c| c.map(|_| ()).map_err(str::to_string))
}

/// A single poll's worth of observation.
#[derive(Debug, Default)]
pub struct PollOutcome {
    pub events: Vec<GuardEvent>,
    /// Non-fatal problems. Also placed in the first event's metadata, so they reach the signed
    /// audit record rather than living only in a UI that may not be open.
    pub warnings: Vec<String>,
}

/// Native Windows adapter.
///
/// Carries no COM state, deliberately: see the module note.
pub struct NativeWinAdapter {
    inner: WinAdapter,
    consistency: FrameConsistency,
    pending: VecDeque<GuardEvent>,
    seq: u64,
    session_id: Option<String>,
    schemas: Vec<AppFormSchema>,
    last_ui_text: Option<String>,
    /// Frames captured this session, for the shared OCR cadence.
    ///
    /// Counted per adapter rather than per process: the cadence exists so the viewtree
    /// comparison has a screen-side input, and that is a property of one observed session.
    frame_seq: u64,
}

impl Default for NativeWinAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeWinAdapter {
    pub fn new() -> Self {
        Self {
            inner: WinAdapter::new(),
            consistency: FrameConsistency::default(),
            pending: VecDeque::new(),
            seq: 0,
            session_id: None,
            schemas: Vec::new(),
            last_ui_text: None,
            frame_seq: 0,
        }
    }

    /// Form schemas used to classify observed fields, so `profile_key`, `required` and the trap
    /// flag mean the same thing here as on macOS.
    pub fn with_schemas(mut self, schemas: Vec<AppFormSchema>) -> Self {
        self.schemas = schemas;
        self
    }

    pub fn start_session(&mut self, session_id: impl Into<String>, app: &str) {
        let id = session_id.into();
        self.session_id = Some(id.clone());
        self.inner.start_session(id, app);
    }

    pub fn end_session(&mut self, app: &str) {
        self.session_id = None;
        self.inner.end_session(app);
    }

    pub fn ingest(&mut self, obs: SimObservation) {
        self.inner.ingest(obs);
    }

    fn next_id(&mut self, kind: &str) -> String {
        self.seq += 1;
        format!("win-{kind}-{}", self.seq)
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Observe the foreground window once: its UI tree, its fields, and its pixels.
    pub fn poll_once(&mut self) -> PollOutcome {
        let mut out = PollOutcome::default();
        let ts = Self::now_ms();

        // --- UI tree ---------------------------------------------------------------
        //
        // One walk per poll. The first version called `foreground_snapshot()` a second time
        // just to label the frame event's `source_app`, which doubled the cost of the most
        // expensive thing in the loop *and* could disagree with itself: the user may have
        // switched windows between the two walks, so the frame would be attributed to an app
        // whose pixels it does not contain — and `source_app` is what every app-scoped grant
        // is checked against.
        let walk: Option<WalkOutcome> = with_uia(|client| match client {
            Err(e) => {
                out.warnings.push(format!("UI Automation unavailable: {e}"));
                None
            }
            Ok(client) => match client.foreground_snapshot() {
                Err(e) => {
                    out.warnings.push(format!("UI tree walk failed: {e}"));
                    None
                }
                Ok(w) => Some(w),
            },
        });

        let mut ax_text: Option<String> = None;
        let mut source_app: Option<String> = None;

        if let Some(walk) = walk {
            source_app = Some(walk.snapshot.source_app.clone());
            let flat = guard_vision::uitree::flatten_text(&walk.snapshot);
            if !flat.is_empty() {
                ax_text = Some(flat);
            }
            let mut ev = guard_vision::uitree::snapshot_to_event(
                &walk.snapshot,
                PLATFORM,
                self.next_id("ui"),
                ts,
                self.session_id.clone(),
            );
            // The walk's own completeness travels with the observation. Without it a truncated
            // tree and a small window look identical downstream.
            for (k, v) in walk.integrity_metadata() {
                ev.metadata.insert(k, v);
            }
            for w in &walk.truncated {
                out.warnings
                    .push(format!("UI tree truncated at the {w} cap"));
            }

            // Emit the tree only when the screen changed. A poller that re-emits an identical
            // tree twice a second turns `UI-REVALIDATE` into noise and fills the audit log
            // with a still screen.
            let text_now = ev.metadata.get("ui_text").cloned().unwrap_or_default();
            let changed = self.last_ui_text.as_deref() != Some(text_now.as_str());
            if changed {
                self.last_ui_text = Some(text_now);
                out.events.push(ev);
            }

            // FormFills follow the tree: emitting them from an unchanged screen would re-report
            // the same filled field twice a second, and the form-minimization probe *counts*
            // optional fields — a duplicate is not redundant there, it inflates the score.
            if changed {
                let prefix = self.next_id("ff");
                out.events
                    .extend(guard_vision::uitree::form_fills_from_snapshot(
                        &walk.snapshot,
                        PLATFORM,
                        &prefix,
                        ts,
                        self.session_id.clone(),
                        &self.schemas,
                    ));
            }
        }

        // --- pixels ----------------------------------------------------------------
        match crate::capture::capture_foreground() {
            Err(e) => out.warnings.push(format!("frame capture failed: {e}")),
            Ok(frame) => {
                self.frame_seq = self.frame_seq.wrapping_add(1);
                let mut stats = frame.to_stats(ts);
                // Pair the tree with the pixels so the AX↔screen cross-validation has both
                // sides. Windows now has an OCR of its own — `Windows.Media.Ocr`, which ships
                // with the OS — so `OVL-009` / `OVL-010` actually run here.
                stats.ax_text = ax_text;

                // The A1 sanitization loop: read the frame when a subliminal band trips, so a
                // payload hidden in low-contrast pixels surfaces as `ui_text` and meets the
                // ordinary injection rules; and periodically, so the viewtree comparison has
                // an input even on frames that tripped nothing. Both the trigger and the
                // contrast are the shared policy, not this adapter's opinion.
                if guard_vision::ocr::should_ocr(
                    self.frame_seq,
                    stats.subliminal_ratio,
                    stats.subliminal_ratio_wide,
                ) {
                    match crate::ocr::read_text(&frame.px, frame.width, frame.height) {
                        Ok(text) => stats.ocr_text = text,
                        // A failed read leaves `ocr_text` absent, which makes the viewtree
                        // check not run. Reported, because "did not run" and "found nothing"
                        // are different and only one of them is reassuring.
                        Err(e) => out.warnings.push(format!("OCR failed: {e}")),
                    }
                }
                let analysis = analyze_frame(&stats);
                let mut metadata: HashMap<String, String> = analysis.metadata.clone();
                if let Some(f) = self.consistency.check(&stats) {
                    metadata.insert("frame_consistency".into(), f.evidence.clone());
                    let marker = f.kind.marker().to_string();
                    let ui = metadata.entry("ui_text".into()).or_default();
                    if !ui.is_empty() {
                        ui.push(' ');
                    }
                    ui.push_str(&marker);
                }
                // Only when there is a finding. `analyze_frame` always returns capture
                // dimensions in metadata, so a bare `!metadata.is_empty()` was true for every
                // frame and emitted a ScreenFrame event twice a second forever.
                if !analysis.findings.is_empty() {
                    let id = self.next_id("frame");
                    out.events.push(GuardEvent {
                        event_id: id,
                        timestamp_ms: ts,
                        platform: PLATFORM.into(),
                        event_type: EventType::ScreenFrame,
                        // The app the tree walk named, or nothing. Never a guess: an invented
                        // `source_app` would satisfy an app-scoped grant that was never given,
                        // and `app_in_grant` treats an empty observed name as covered by
                        // nothing — which is the safe reading.
                        source_app: source_app.clone().unwrap_or_default(),
                        agent_context_id: self.session_id.clone(),
                        metadata,
                    });
                }
            }
        }

        if let (Some(first), false) = (out.events.first_mut(), out.warnings.is_empty()) {
            first
                .metadata
                .insert("adapter_warnings".into(), out.warnings.join("; "));
        }
        out
    }

    pub fn drain(&mut self) -> Result<Vec<GuardEvent>> {
        let mut out = self.inner.drain()?;
        out.extend(self.pending.drain(..));
        Ok(out)
    }
}

impl PlatformAdapter for NativeWinAdapter {
    fn platform_id(&self) -> &'static str {
        "windows-native"
    }

    fn poll_events(&mut self) -> Result<Vec<GuardEvent>> {
        let mut out = self.drain()?;
        out.extend(self.poll_once().events);
        Ok(out)
    }
}

/// `NativeWinAdapter` must be `Send`, or the desktop shell cannot hold it.
///
/// The shell stores it in `Mutex<Option<NativeWinAdapter>>` in Tauri's managed state and polls
/// it from a spawned thread; `manage` requires `Send + Sync + 'static`, and `Mutex<T>` is `Sync`
/// only when `T: Send`. A compile-time assertion rather than a runtime test, because the
/// failure it guards is a build error **on Windows only** — the Linux and macOS jobs compile
/// the shell with the `#[cfg(windows)]` observer field absent and would stay green while the
/// Windows build was broken. If a COM interface is ever put back into a field, this stops
/// compiling here, in the crate that owns the mistake.
const _: () = {
    const fn assert_send<T: Send>() {}
    let _ = assert_send::<NativeWinAdapter>;
};
