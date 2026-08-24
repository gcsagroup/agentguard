//! Runtime capability probes.
//!
//! # What was wrong with the old answer
//!
//! `capabilities()` used to report `uia_native: cfg!(windows)` and
//! `graphics_capture: cfg!(windows)`. That is a **compile flag**: it says "this binary was
//! built for Windows", and it answered `true` on a machine where the UIA client cannot be
//! created and no window can be captured. A capability report that cannot fail is not a
//! report; the desktop shell rendered it as a green tick and the coverage matrix inherited
//! the claim.
//!
//! A probe here actually tries the thing and keeps the error string. That makes the failure
//! legible instead of impossible — the same distinction `Face.error` draws on Android
//! between an absent appearance and a clean one.

use serde::{Deserialize, Serialize};

/// One capability, and why it is unavailable when it is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub available: bool,
    /// Empty when available. Never empty when not.
    pub detail: String,
}

impl std::fmt::Display for Capability {
    /// Prints the verdict *with* its reason, always. A bare `false` is how the previous
    /// version of this report read as a considered answer instead of a compile flag.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.available)
        } else {
            write!(f, "{} ({})", self.available, self.detail)
        }
    }
}

impl Capability {
    pub fn yes(detail: impl Into<String>) -> Self {
        Self {
            available: true,
            detail: detail.into(),
        }
    }
    pub fn no(detail: impl Into<String>) -> Self {
        Self {
            available: false,
            detail: detail.into(),
        }
    }
}

/// Probed capabilities of this host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdapterCapabilities {
    /// Offline scenario replay. True everywhere, and never a substitute for the others.
    pub simulation: bool,
    /// A UI Automation client could be created and the foreground window walked.
    pub uia_native: Capability,
    /// A frame could actually be copied out of the foreground window.
    pub frame_capture: Capability,
    /// Kept for compatibility with the old field name. Always unavailable: the capture path
    /// is GDI, and saying otherwise would claim the composed-desktop coverage GDI lacks.
    pub graphics_capture: Capability,
    /// Whether text can be read off a frame.
    ///
    /// Its own row because its absence has a specific consequence: without OCR the AX↔screen
    /// cross-validation (`OVL-009` / `OVL-010`) does not run, and the A1 sanitization loop
    /// cannot surface a subliminal payload as `ui_text`. A host with no language pack loses
    /// two published surfaces, and that should be visible rather than inferred.
    pub ocr: Capability,
}

impl AdapterCapabilities {
    /// True when this host can observe anything at all beyond replaying fixtures.
    pub fn can_observe(&self) -> bool {
        self.uia_native.available || self.frame_capture.available
    }
}

#[cfg(windows)]
pub fn capabilities() -> AdapterCapabilities {
    // Through the adapter's thread-local client, not a second one of our own. Creating a
    // separate client here would call `CoInitializeEx` again on this thread and leave the probe
    // reporting on an object nothing else uses — so a probe could succeed while the observer's
    // own client was failing, which is the one thing a probe must not do.
    let uia = match crate::native::uia_status() {
        Ok(()) => Capability::yes("UI Automation client created on this thread"),
        Err(e) => Capability::no(e),
    };
    let frame = match crate::capture::capture_foreground() {
        Ok(f) => Capability::yes(format!(
            "captured {}x{} from the foreground window",
            f.width, f.height
        )),
        Err(e) => Capability::no(e),
    };
    let ocr = match crate::ocr::ocr_status() {
        Ok(detail) => Capability::yes(detail),
        Err(e) => Capability::no(e),
    };
    AdapterCapabilities {
        simulation: true,
        uia_native: uia,
        frame_capture: frame,
        graphics_capture: Capability::no(
            "capture path is GDI BitBlt, not Windows.Graphics.Capture",
        ),
        ocr,
    }
}

#[cfg(not(windows))]
pub fn capabilities() -> AdapterCapabilities {
    // Not "false because the flag says so" — false with the reason, so a report copied off
    // a Linux CI runner cannot be mistaken for a report about a Windows host.
    let reason = format!(
        "this binary targets {}, not Windows; UI Automation and window capture are Win32 APIs",
        std::env::consts::OS
    );
    AdapterCapabilities {
        simulation: true,
        uia_native: Capability::no(reason.clone()),
        frame_capture: Capability::no(reason.clone()),
        graphics_capture: Capability::no(reason.clone()),
        ocr: Capability::no(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_windows_host_reports_no_observation_and_says_why() {
        // The bug this pins: `uia_native: cfg!(windows)` was a compile flag rendered as a
        // capability. On any host that cannot observe, the report must be unavailable AND
        // carry a reason, because an empty reason is what let the old version look fine.
        let c = capabilities();
        assert!(c.simulation, "replay is always possible");
        #[cfg(not(windows))]
        {
            assert!(!c.can_observe());
            assert!(!c.uia_native.available);
            assert!(
                !c.uia_native.detail.is_empty(),
                "an unavailable capability must say why; silence is how the old flag passed"
            );
            assert!(!c.frame_capture.detail.is_empty());
            assert!(!c.ocr.available);
            assert!(!c.ocr.detail.is_empty());
        }
    }

    #[test]
    fn graphics_capture_is_never_claimed() {
        // GDI does not see the composed desktop. Reporting Graphics Capture as available
        // would claim coverage of a phishing window drawn by another process, which this
        // path does not have.
        assert!(!capabilities().graphics_capture.available);
        assert!(!capabilities().graphics_capture.detail.is_empty());
    }
}
