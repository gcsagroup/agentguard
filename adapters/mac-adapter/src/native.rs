//! macOS-facing wrapper around the shared simulation observation model.
//! Native AX / screen-capture permission probes; AX snapshot ingest via `ax_tree`.

use crate::ax_tree::{
    flatten_text, form_fills_from_snapshot, snapshot_to_event_with_viewport, AxSnapshot,
};
use crate::screencapture::{analyze_frame, FrameConsistency, FrameStats};
use anyhow::Result;
use guard_overlay::Viewport;
use guard_privacy::{load_form_schemas, AppFormSchema};
use guard_schema::{EventType, GuardEvent};
use serde::Serialize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use win_adapter::{PlatformAdapter, SimObservation, WinAdapter};

#[derive(Debug, Clone, Serialize)]
pub struct MacCapabilities {
    pub simulation: bool,
    /// Process is trusted for Accessibility APIs.
    pub accessibility: bool,
    /// Screen Recording preflight (CGPreflightScreenCaptureAccess).
    pub screen_capture: bool,
}

pub fn mac_capabilities() -> MacCapabilities {
    MacCapabilities {
        simulation: true,
        accessibility: permissions::accessibility_granted(),
        screen_capture: permissions::screen_capture_granted(),
    }
}

#[derive(Debug, Default)]
pub struct MacAdapter {
    inner: WinAdapter,
    ax_seq: u64,
    form_schemas: Vec<AppFormSchema>,
    viewport: Option<Viewport>,
    frame_consistency: FrameConsistency,
    /// Text of the most recent accessibility snapshot, used to cross-validate
    /// the next captured frame (AgentScan Viewtree Interference).
    last_ax_text: Option<String>,
    last_ax_ms: i64,
    /// AXObserver 推送的合并器(E3):把"变了就抓"和"兜底轮询"合成一个"现在该不该抓"的判定。
    ax_coalescer: crate::ax_push::PushCoalescer,
    /// 最近一次核对 observer 是否仍绑定当前前台应用的时间。
    ax_observer_refresh_ms: Option<i64>,
}

/// How stale an AX snapshot may be and still be compared against a frame.
/// Beyond this the two views legitimately describe different screens.
pub const VIEWTREE_PAIRING_WINDOW_MS: i64 = 3_000;

impl MacAdapter {
    pub fn new() -> Self {
        Self {
            form_schemas: default_form_schemas(),
            ..Default::default()
        }
    }

    pub fn with_form_schemas(mut self, schemas: Vec<AppFormSchema>) -> Self {
        self.form_schemas = schemas;
        self
    }

    pub fn set_viewport(&mut self, viewport: Option<Viewport>) {
        self.viewport = viewport;
    }

    pub fn start_session(&mut self, session_id: impl Into<String>, app: &str) {
        self.inner.start_session(session_id, app);
    }

    /// Open a session declaring the task (Aura §4.4), so the plan library can select a ceiling.
    pub fn start_task_session(
        &mut self,
        session_id: impl Into<String>,
        app: &str,
        task: &guard_schema::TaskDeclaration,
    ) {
        self.inner.start_task_session(session_id, app, task);
    }

    pub fn end_session(&mut self, app: &str) {
        self.inner.end_session(app);
    }

    pub fn ingest(&mut self, obs: SimObservation) {
        self.inner.ingest(obs);
    }

    /// Convert an accessibility snapshot into GuardEvents:
    /// UiTreeDelta (+ overlay / edge-zone markers) and FormFill for filled editables.
    pub fn ingest_ax_snapshot(&mut self, snapshot: AxSnapshot) {
        self.ax_seq += 1;
        let event_id = format!("mac-ax-{}", self.ax_seq);
        let ts = now_ms();
        let session = self.inner.session_id().map(str::to_string);
        self.last_ax_text = Some(flatten_text(&snapshot));
        self.last_ax_ms = ts;
        let tree = snapshot_to_event_with_viewport(
            &snapshot,
            &event_id,
            ts,
            session.clone(),
            self.viewport.as_ref(),
        );
        self.inner.push_raw(tree);
        for fill in form_fills_from_snapshot(&snapshot, &event_id, ts, session, &self.form_schemas)
        {
            self.inner.push_raw(fill);
        }
    }

    /// Ingest ScreenCaptureKit-style frame stats (simulation or coarse analysis).
    ///
    /// When a recent AX snapshot is available it rides along as `ax_text` so
    /// `analyze_frame` can cross-validate tree text against rendered text.
    pub fn ingest_capture_frame(&mut self, mut stats: FrameStats, source_app: &str) {
        self.ax_seq += 1;
        if stats.ax_text.is_none() {
            if let Some(ax) = self.pairable_ax_text(stats.timestamp_ms) {
                stats.ax_text = Some(ax);
            }
        }
        let mut analysis = analyze_frame(&stats);
        // A4 countermeasure: rapid double-capture consistency check.
        if let Some(finding) = self.frame_consistency.check(&stats) {
            let marker = finding.kind.marker().to_string();
            if !analysis.ui_text.is_empty() {
                analysis.ui_text.push(' ');
            }
            analysis.ui_text.push_str(&marker);
            analysis
                .metadata
                .insert("ui_text".into(), analysis.ui_text.clone());
            analysis.findings.push(finding);
        }
        let event = GuardEvent {
            event_id: format!("mac-cap-{}", self.ax_seq),
            timestamp_ms: stats.timestamp_ms,
            platform: "macos".into(),
            event_type: EventType::UiTreeDelta,
            source_app: source_app.into(),
            agent_context_id: self.inner.session_id().map(str::to_string),
            metadata: analysis.metadata,
        };
        self.inner.push_raw(event);
    }

    /// The last AX text, if it is fresh enough to describe the same screen as a
    /// frame at `frame_ms`. Frame timestamps come from the capture clock, so a
    /// zero/unset frame timestamp is treated as "now" and always pairs.
    fn pairable_ax_text(&self, frame_ms: i64) -> Option<String> {
        let ax = self.last_ax_text.as_ref()?;
        if ax.trim().is_empty() {
            return None;
        }
        if frame_ms <= 0 || self.last_ax_ms <= 0 {
            return Some(ax.clone());
        }
        let dt = (frame_ms - self.last_ax_ms).abs();
        (dt <= VIEWTREE_PAIRING_WINDOW_MS).then(|| ax.clone())
    }

    /// Drain native SCK bridge frames (if streaming) into GuardEvents.
    pub fn poll_sck_frames(&mut self, source_app: &str) -> usize {
        let frames = crate::sck_native::drain_sck_frames();
        let n = frames.len();
        for stats in frames {
            self.ingest_capture_frame(stats, source_app);
        }
        n
    }

    /// 开始接收 AXObserver 推送(E3)。驱动循环在会话开始时调一次;返回 `Err` 说明推送不可用
    /// (非 macOS、桥失败),此时应退回纯兜底轮询——而不是以为推送在工作。
    pub fn start_ax_push(&mut self) -> Result<(), String> {
        self.ax_observer_refresh_ms = None;
        crate::ax_native::start_ax_observer()
    }

    /// 停止接收 AXObserver 推送(会话结束时调)。
    pub fn stop_ax_push(&mut self) {
        crate::ax_native::stop_ax_observer();
        self.ax_observer_refresh_ms = None;
    }

    /// 驱动循环每 tick 调一次:把自上次以来的 AXObserver 通知喂进合并器,若合并器判定"该抓",
    /// 就抓一次实时 AX 快照并入队。返回是否真的抓了(供调用方决定要不要顺带抓一帧像素配对)。
    ///
    /// 这就是"实时化"的落点:一次树变化通常在 `DEBOUNCE_MS` 内被抓到,而不是最坏等一整个轮询
    /// 周期;持续变化至少每 `MAX_LATENCY_MS` 抓一次;完全没有推送时,退化成 `FALLBACK_FLOOR_MS`
    /// 的兜底轮询——推送那条命断了也不会漏抓。
    pub fn maybe_capture_ax(&mut self, now_ms: i64) -> Result<bool, String> {
        // 前台应用可能切换。每 500ms 让原生桥核对一次 PID；同 PID 是廉价 no-op，
        // 变化时才重绑 AXObserver。这样不会把 observer 永久留在启用时的那个应用上。
        let refresh_due = self
            .ax_observer_refresh_ms
            .map(|last| now_ms.saturating_sub(last) >= 500)
            .unwrap_or(true);
        if refresh_due {
            // 注册失败时仍保留 3s 兜底捕获；真正的权限/捕获错误会由 capture_live_ax 返回。
            let _ = crate::ax_native::start_ax_observer();
            self.ax_observer_refresh_ms = Some(now_ms);
        }
        if crate::ax_native::take_ax_notifications() > 0 {
            self.ax_coalescer.note(now_ms);
        }
        if !self.ax_coalescer.due(now_ms) {
            return Ok(false);
        }
        let r = self.capture_live_ax();
        // 抓过就 mark(无论快照成功与否):失败也不该让合并器把这次"该抓"一直挂着空转;
        // 下一次变化或兜底周期会再触发。
        self.ax_coalescer.mark_captured(now_ms);
        r.map(|_| true)
    }

    /// Live AXUIElement capture of the frontmost app into the adapter queue.
    pub fn capture_live_ax(&mut self) -> Result<(), String> {
        let snap = crate::ax_native::live_ax_snapshot()?;
        if let Some(b) = snap.root.bounds.as_ref() {
            if b.width > 0.0 && b.height > 0.0 {
                self.viewport = Some(guard_overlay::Viewport {
                    width: b.width.max(800.0),
                    height: b.height.max(600.0),
                    edge_margin: 24.0,
                });
            }
        }
        self.ingest_ax_snapshot(snap);
        Ok(())
    }

    pub fn has_session(&self) -> bool {
        self.inner.has_session()
    }

    pub fn drain(&mut self) -> Result<Vec<GuardEvent>> {
        let mut events = self.inner.drain()?;
        for e in &mut events {
            e.platform = "macos".into();
        }
        Ok(events)
    }
}

impl PlatformAdapter for MacAdapter {
    fn platform_id(&self) -> &'static str {
        "macos"
    }

    fn poll_events(&mut self) -> Result<Vec<GuardEvent>> {
        self.drain()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn default_form_schemas() -> Vec<AppFormSchema> {
    let candidates = [
        PathBuf::from("policies/forms"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policies/forms"),
    ];
    for dir in candidates {
        let loaded = load_form_schemas(&dir);
        if !loaded.is_empty() {
            return loaded;
        }
    }
    Vec::new()
}

pub mod permissions {
    //! TCC / Accessibility probes.

    pub fn accessibility_granted() -> bool {
        #[cfg(target_os = "macos")]
        {
            native::ax_is_process_trusted()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Best-effort prompt: on macOS this re-checks trust; UI should deep-link
    /// users to System Settings → Privacy → Accessibility when false.
    pub fn request_accessibility_prompt() -> bool {
        accessibility_granted()
    }

    pub fn screen_capture_granted() -> bool {
        #[cfg(target_os = "macos")]
        {
            native::cg_preflight_screen_capture()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    pub fn request_screen_capture() -> bool {
        #[cfg(target_os = "macos")]
        {
            native::cg_request_screen_capture()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    #[cfg(target_os = "macos")]
    mod native {
        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXIsProcessTrusted() -> u8;
        }

        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGPreflightScreenCaptureAccess() -> u8;
            fn CGRequestScreenCaptureAccess() -> u8;
        }

        pub fn ax_is_process_trusted() -> bool {
            unsafe { AXIsProcessTrusted() != 0 }
        }

        pub fn cg_preflight_screen_capture() -> bool {
            unsafe { CGPreflightScreenCaptureAccess() != 0 }
        }

        pub fn cg_request_screen_capture() -> bool {
            unsafe { CGRequestScreenCaptureAccess() != 0 }
        }
    }
}
