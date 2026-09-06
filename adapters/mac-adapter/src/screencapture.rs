//! ScreenCaptureKit attach points.
//!
//! The frame *analysis* is not here — it is in [`guard_vision::frame`], shared with every
//! other platform that can capture pixels. What is genuinely macOS lives below: starting
//! and stopping an SCK stream, and saying honestly whether this build can.
//!
//! The module still re-exports the shared types under their historical paths
//! (`mac_adapter::screencapture::FrameStats`) so that callers did not have to move when
//! the analysis did.

pub use guard_vision::frame::{
    analyze_frame, demo_transparent_overlay_frame, markers_as_ui_text, simulate_frame_from_regions,
    CaptureFrameMeta, FrameAnalysis, FrameConsistency, FrameStats, CONSISTENCY_LUMA_JUMP,
    CONSISTENCY_WINDOW_MS,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
pub fn screencapturekit_available() -> bool {
    true
}

#[cfg(not(target_os = "macos"))]
pub fn screencapturekit_available() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSessionInfo {
    pub native: bool,
    pub message: String,
}

/// Start ScreenCaptureKit stream via native bridge (macOS), or no-op sim elsewhere.
pub fn start_capture_session() -> Result<CaptureSessionInfo> {
    start_capture_session_with(crate::sck_native::sck_start)
}

/// Start a stream bound to a desktop observer generation.
pub fn start_capture_session_generation(generation: u64) -> Result<CaptureSessionInfo> {
    start_capture_session_with(|| crate::sck_native::sck_start_generation(generation))
}

fn start_capture_session_with(
    start: impl FnOnce() -> Result<(), String>,
) -> Result<CaptureSessionInfo> {
    if !screencapturekit_available() {
        anyhow::bail!("ScreenCaptureKit only available on macOS");
    }
    match start() {
        Ok(()) => Ok(CaptureSessionInfo {
            native: true,
            message: "ScreenCaptureKit stream started (stats-only callbacks)".into(),
        }),
        Err(e) => {
            // Soft-fail: callers can still use sim-capture / inject paths.
            Ok(CaptureSessionInfo {
                native: false,
                message: format!("native SCK unavailable ({e}); use sim-capture"),
            })
        }
    }
}

pub fn stop_capture_session() -> Result<CaptureSessionInfo> {
    stop_capture_session_with(crate::sck_native::sck_stop)
}

/// Stop only the matching desktop observer generation.
pub fn stop_capture_session_generation(generation: u64) -> Result<CaptureSessionInfo> {
    stop_capture_session_with(|| crate::sck_native::sck_stop_generation(generation))
}

fn stop_capture_session_with(
    stop: impl FnOnce() -> Result<(), String>,
) -> Result<CaptureSessionInfo> {
    stop().map_err(anyhow::Error::msg)?;
    Ok(CaptureSessionInfo {
        native: false,
        message: "capture stopped".into(),
    })
}
