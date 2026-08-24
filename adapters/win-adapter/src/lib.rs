//! Windows adapter: a real UI Automation walker and frame capture on Windows, offline
//! scenario replay everywhere.
//!
//! The pixel and tree *analysis* is not here — it lives in `guard-vision`, shared with the
//! macOS adapter, so that one implementation of the subliminal bands, the frame digest and
//! the editable-field vocabulary serves both platforms. This crate's job is Win32: get the
//! tree, get the pixels, and say honestly when it could not.

pub mod control_types;
mod sim;

#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod native;
#[cfg(windows)]
pub mod ocr;
pub mod probe;
#[cfg(windows)]
pub mod uia;

pub use sim::{SimObservation, WinAdapter};

#[cfg(windows)]
pub use native::{uia_status, NativeWinAdapter, PollOutcome, PLATFORM};

#[cfg(windows)]
pub use capture::{capture_foreground, capture_window, Frame, GRAPHICS_CAPTURE_NOTE, MAX_PIXELS};
#[cfg(windows)]
pub use ocr::{max_image_dimension, ocr_status, read_text, OCR_TIMEOUT};
#[cfg(windows)]
pub use uia::{UiaClient, WalkOutcome, MAX_CHILDREN, MAX_DEPTH, MAX_NODES};

pub use control_types::control_type_name_raw;
pub use probe::{capabilities, AdapterCapabilities, Capability};

use anyhow::Result;
use guard_schema::GuardEvent;

/// Platform adapter trait (mirrors the architecture doc).
pub trait PlatformAdapter {
    fn platform_id(&self) -> &'static str;
    fn poll_events(&mut self) -> Result<Vec<GuardEvent>>;
}

impl PlatformAdapter for WinAdapter {
    fn platform_id(&self) -> &'static str {
        "windows"
    }

    fn poll_events(&mut self) -> Result<Vec<GuardEvent>> {
        self.drain()
    }
}
