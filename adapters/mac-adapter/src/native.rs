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

use crate::ObserverGeneration;

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

/// 一次 AX 抓取尝试的结果(驱动循环据此决定心跳、配对像素帧)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxCapture {
    /// 合并器判定这一拍不该抓(推送没来、兜底周期没到)。
    NotDue,
    /// 抓到了别人的窗口并已入队。
    Captured,
    /// 前台是 AgentGuard 自己,跳过、不入队。观察器是活的。
    SkippedSelf,
}

impl AxCapture {
    /// 观察器这一拍真的看了一眼(抓到或确认是自己)——壳子据此更新心跳。
    pub fn observed(self) -> bool {
        matches!(self, AxCapture::Captured | AxCapture::SkippedSelf)
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
    /// 原生 AXObserver 当前绑定的桌面观察代际。
    ax_observer_generation: Option<ObserverGeneration>,
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
        self.reset_observation_generation();
        self.inner.start_session(session_id, app);
    }

    /// Open a session declaring the task (Aura §4.4), so the plan library can select a ceiling.
    pub fn start_task_session(
        &mut self,
        session_id: impl Into<String>,
        app: &str,
        task: &guard_schema::TaskDeclaration,
    ) {
        self.reset_observation_generation();
        self.inner.start_task_session(session_id, app, task);
    }

    pub fn end_session(&mut self, app: &str) {
        self.inner.end_session(app);
        self.reset_observation_generation();
    }

    pub fn ingest(&mut self, obs: SimObservation) {
        self.inner.ingest(obs);
    }

    fn reset_observation_generation(&mut self) {
        self.last_ax_text = None;
        self.last_ax_ms = 0;
        self.frame_consistency = FrameConsistency;
        self.ax_coalescer = crate::ax_push::PushCoalescer::new();
        self.ax_observer_refresh_ms = None;
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
    /// frame at `frame_ms`. Both timestamps must be validated Unix wall-clock
    /// values; zero/negative input is unknown and must not bypass freshness.
    fn pairable_ax_text(&self, frame_ms: i64) -> Option<String> {
        let ax = self.last_ax_text.as_ref()?;
        if ax.trim().is_empty() {
            return None;
        }
        if frame_ms <= 0 || self.last_ax_ms <= 0 {
            return None;
        }
        let dt = (frame_ms - self.last_ax_ms).abs();
        (dt <= VIEWTREE_PAIRING_WINDOW_MS).then(|| ax.clone())
    }

    /// Drain native SCK bridge frames (if streaming) into GuardEvents.
    pub fn poll_sck_frames(&mut self, source_app: &str) -> usize {
        let frames = crate::sck_native::drain_sck_frames();
        self.ingest_sck_frames(frames, source_app)
    }

    /// 只取指定观察代际的 SCK 帧；旧 callback 即使迟到也不会进入新会话。
    pub fn poll_sck_frames_generation(
        &mut self,
        generation: ObserverGeneration,
        source_app: &str,
    ) -> usize {
        let frames = crate::sck_native::drain_sck_frames_generation(generation.get());
        self.ingest_sck_frames(frames, source_app)
    }

    fn ingest_sck_frames(&mut self, frames: Vec<FrameStats>, source_app: &str) -> usize {
        let n = frames.len();
        for stats in frames {
            self.ingest_capture_frame(stats, source_app);
        }
        n
    }

    /// 只初始化当前 AX 观察代际的 Rust 状态。原生 observer 注册必须在调用方释放
    /// `AppState.adapter` 后执行，不能把可能阻塞的 AX IPC 带进共享锁。
    pub fn begin_ax_push(&mut self, generation: ObserverGeneration) {
        self.ax_coalescer = crate::ax_push::PushCoalescer::new();
        self.ax_observer_refresh_ms = None;
        self.ax_observer_generation = Some(generation);
    }

    /// 只结束匹配代际的 Rust 状态。返回 true 时调用方才应在锁外卸载原生 observer。
    pub fn finish_ax_push(&mut self, generation: ObserverGeneration) -> bool {
        if self.ax_observer_generation != Some(generation) {
            return false;
        }
        self.ax_observer_refresh_ms = None;
        self.ax_observer_generation = None;
        self.ax_coalescer = crate::ax_push::PushCoalescer::new();
        true
    }

    /// 是否该重新核对 AXObserver 的前台 PID。这里只读 Rust 时钟状态，不调用系统 API。
    pub fn ax_observer_refresh_due(
        &self,
        generation: ObserverGeneration,
        now_ms: i64,
    ) -> Result<bool, String> {
        if self.ax_observer_generation != Some(generation) {
            return Err(format!("stale AX observer generation {generation}"));
        }
        Ok(self
            .ax_observer_refresh_ms
            .map(|last| now_ms.saturating_sub(last) >= 500)
            .unwrap_or(true))
    }

    /// 记录一次已完成的原生 observer 核对（成功与否都节流 500ms，避免失败热循环）。
    pub fn note_ax_observer_refreshed(
        &mut self,
        generation: ObserverGeneration,
        now_ms: i64,
    ) -> Result<(), String> {
        if self.ax_observer_generation != Some(generation) {
            return Err(format!("stale AX observer generation {generation}"));
        }
        self.ax_observer_refresh_ms = Some(now_ms);
        Ok(())
    }

    /// 把锁外取得的通知计数喂给合并器，只回答这一拍是否应抓快照。
    pub fn ax_capture_due(
        &mut self,
        generation: ObserverGeneration,
        now_ms: i64,
        notifications: u64,
    ) -> Result<bool, String> {
        if self.ax_observer_generation != Some(generation) {
            return Err(format!("stale AX observer generation {generation}"));
        }
        if notifications > 0 {
            self.ax_coalescer.note(now_ms);
        }
        Ok(self.ax_coalescer.due(now_ms))
    }

    /// 提交锁外取得的快照；代际校验和 `mark_captured` 与入队在同一个短临界区完成。
    pub fn apply_ax_snapshot(
        &mut self,
        generation: ObserverGeneration,
        now_ms: i64,
        snap: AxSnapshot,
    ) -> Result<AxCapture, String> {
        if self.ax_observer_generation != Some(generation) {
            return Err(format!("stale AX observer generation {generation}"));
        }
        self.ax_coalescer.mark_captured(now_ms);
        Ok(self.ingest_live_ax_snapshot(snap))
    }

    /// 一次性手动抓取的锁内提交面。调用方负责先在锁外完成 AXUIElement 快照。
    pub fn ingest_live_ax_snapshot(&mut self, snap: AxSnapshot) -> AxCapture {
        if snap.is_self_observation() {
            return AxCapture::SkippedSelf;
        }
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
        AxCapture::Captured
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

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    fn adapter_with_ax(timestamp_ms: i64) -> MacAdapter {
        MacAdapter {
            last_ax_text: Some("Confirm Payment".into()),
            last_ax_ms: timestamp_ms,
            ..MacAdapter::new()
        }
    }

    #[test]
    fn ax_text_pairs_only_with_a_nearby_wall_clock_frame() {
        let base = 1_788_546_177_000;
        let adapter = adapter_with_ax(base);
        assert_eq!(
            adapter.pairable_ax_text(base + VIEWTREE_PAIRING_WINDOW_MS),
            Some("Confirm Payment".into())
        );
        assert_eq!(
            adapter.pairable_ax_text(base + VIEWTREE_PAIRING_WINDOW_MS + 1),
            None
        );
    }

    #[test]
    fn unknown_or_media_clock_timestamp_never_pairs_as_fresh() {
        let adapter = adapter_with_ax(1_788_546_177_000);
        assert_eq!(adapter.pairable_ax_text(0), None);
        assert_eq!(adapter.pairable_ax_text(-1), None);
        assert_eq!(adapter.pairable_ax_text(294_365_480), None);
    }
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

    /// 仅在用户点击授权入口时请求系统提示；普通状态轮询不触发授权。
    pub fn request_accessibility_prompt() -> bool {
        #[cfg(target_os = "macos")]
        {
            native::ax_request_permission()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
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

        extern "C" {
            fn agentguard_ax_request_permission() -> std::os::raw::c_int;
        }

        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGPreflightScreenCaptureAccess() -> u8;
            fn CGRequestScreenCaptureAccess() -> u8;
        }

        pub fn ax_is_process_trusted() -> bool {
            unsafe { AXIsProcessTrusted() != 0 }
        }

        pub fn ax_request_permission() -> bool {
            unsafe { agentguard_ax_request_permission() == 0 }
        }

        pub fn cg_preflight_screen_capture() -> bool {
            unsafe { CGPreflightScreenCaptureAccess() != 0 }
        }

        pub fn cg_request_screen_capture() -> bool {
            unsafe { CGRequestScreenCaptureAccess() != 0 }
        }
    }
}
