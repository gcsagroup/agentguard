//! FFI bindings to the Objective-C ScreenCaptureKit bridge.
//!
//! On non-macOS targets this module provides stubs. Frame pixels are never
//! retained — only coarse [`crate::FrameStats`] are queued for the adapter.

use crate::screencapture::FrameStats;
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::ffi::CStr;
use std::sync::{Mutex, OnceLock};

static FRAME_QUEUE: OnceLock<Mutex<VecDeque<FrameStats>>> = OnceLock::new();

fn queue() -> &'static Mutex<VecDeque<FrameStats>> {
    FRAME_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(8)))
}

// Every code here is returned by the ObjC bridge and matched in `map_status`, which
// only exists on macOS — so off macOS the whole set reads as unused. Allow the lint
// there rather than everywhere, so a code that really does go stale on macOS is still
// reported.
#[repr(C)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct SckStatus;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl SckStatus {
    pub const OK: i32 = 0;
    pub const UNSUPPORTED: i32 = 1;
    pub const DENIED: i32 = 2;
    pub const BUSY: i32 = 3;
    pub const ERROR: i32 = 4;
    pub const NOT_STREAMING: i32 = 5;
}

/// Layout version of [`AgFrameStats`]; must match `AG_FRAME_STATS_ABI` in
/// `native/include/agentguard_sck.h`.
// Only read by the macOS callback; the layout test still exercises it elsewhere.
#[allow(dead_code)]
pub const FRAME_STATS_ABI: u32 = 2;

/// Mirror of the C `agentguard_frame_stats` struct.
///
/// The bridge passes stats by pointer rather than as a long positional argument
/// list, so adding a heuristic no longer means editing a 9-argument signature in
/// three places. Field order and the explicit `reserved0` padding keep this
/// layout byte-identical to the C struct (checked by `abi_layout_matches_c`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // constructed by the ObjC bridge (macOS) and the layout test
pub struct AgFrameStats {
    pub abi_version: u32,
    pub width: u32,
    pub height: u32,
    pub reserved0: u32,
    pub timestamp_ms: i64,
    pub mean_luma: f32,
    pub low_opacity_ratio: f32,
    pub subliminal_ratio: f32,
    pub subliminal_ratio_wide: f32,
    pub lsb_flip_rate: f32,
    pub chroma_lsb_flip_rate: f32,
    pub ocr_text: *const std::os::raw::c_char,
    pub frame_digest: *const std::os::raw::c_char,
}

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    pub type FrameCb =
        Option<unsafe extern "C" fn(stats: *const super::AgFrameStats, userdata: *mut c_void)>;

    extern "C" {
        pub fn agentguard_sck_probe() -> c_int;
        pub fn agentguard_sck_start(cb: FrameCb, userdata: *mut c_void) -> c_int;
        pub fn agentguard_sck_stop() -> c_int;
        pub fn agentguard_sck_last_error() -> *const c_char;
        pub fn agentguard_sck_string_free(s: *mut c_char);
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn on_frame(raw: *const AgFrameStats, _userdata: *mut std::os::raw::c_void) {
    if raw.is_null() {
        return;
    }
    let s = &*raw;
    // A newer bridge could hand us a longer struct; reading only the fields this
    // build knows about is safe, but an *older* bridge is not. On mismatch we
    // still release `ocr_text` — the ABI contract is that the first 16 bytes and
    // the `ocr_text` slot never move, precisely so this cleanup stays valid.
    if s.abi_version != FRAME_STATS_ABI {
        // Only the ABI-pinned prefix and `ocr_text` are safe to touch here; new
        // fields may not exist in an older bridge's struct.
        if !s.ocr_text.is_null() {
            ffi::agentguard_sck_string_free(s.ocr_text as *mut _);
        }
        return;
    }
    let take = |p: *const std::os::raw::c_char| -> Option<String> {
        if p.is_null() {
            return None;
        }
        let text = CStr::from_ptr(p).to_string_lossy().into_owned();
        ffi::agentguard_sck_string_free(p as *mut _);
        Some(text)
    };
    let ocr = take(s.ocr_text);
    let frame_digest = take(s.frame_digest);
    let stats = FrameStats {
        width: s.width,
        height: s.height,
        timestamp_ms: s.timestamp_ms,
        mean_luma: s.mean_luma,
        low_opacity_ratio: s.low_opacity_ratio,
        subliminal_ratio: s.subliminal_ratio,
        subliminal_ratio_wide: s.subliminal_ratio_wide,
        lsb_flip_rate: s.lsb_flip_rate,
        chroma_lsb_flip_rate: s.chroma_lsb_flip_rate,
        frame_digest,
        ocr_text: ocr,
        ax_text: None,
        regions: Vec::new(),
    };
    if let Ok(mut q) = queue().lock() {
        if q.len() >= 16 {
            q.pop_front();
        }
        q.push_back(stats);
    }
}

/// Probe ScreenCaptureKit + Screen Recording TCC.
pub fn sck_probe() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_sck_probe() };
        map_status(code)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("ScreenCaptureKit only available on macOS".into())
    }
}

/// Start native capture stream (low FPS). Frames land in [`drain_sck_frames`].
pub fn sck_start() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_sck_start(Some(on_frame), std::ptr::null_mut()) };
        map_status(code)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("ScreenCaptureKit only available on macOS".into())
    }
}

pub fn sck_stop() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_sck_stop() };
        if code == SckStatus::NOT_STREAMING {
            return Ok(());
        }
        map_status(code)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

pub fn drain_sck_frames() -> Vec<FrameStats> {
    queue()
        .lock()
        .map(|mut q| q.drain(..).collect())
        .unwrap_or_default()
}

// Reached only from `map_status`, which is macOS-only.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn last_error() -> String {
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let p = ffi::agentguard_sck_last_error();
            if p.is_null() {
                return String::new();
            }
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

#[cfg(target_os = "macos")]
fn map_status(code: i32) -> Result<(), String> {
    match code {
        SckStatus::OK => Ok(()),
        SckStatus::UNSUPPORTED => Err(format!("unsupported: {}", last_error())),
        SckStatus::DENIED => Err(format!("screen recording denied: {}", last_error())),
        SckStatus::BUSY => Err(format!("busy: {}", last_error())),
        SckStatus::NOT_STREAMING => Err("not streaming".into()),
        SckStatus::ERROR => Err(format!("sck error: {}", last_error())),
        other => Err(format!("sck error ({other}): {}", last_error())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C struct is 64 bytes with `ocr_text` at 48 and `frame_digest` at 56 on
    /// every 64-bit Apple target; a mismatch here means the ObjC bridge and this
    /// mirror have drifted, which would silently garble frame stats at runtime.
    #[test]
    fn abi_layout_matches_c() {
        assert_eq!(std::mem::size_of::<AgFrameStats>(), 64);
        assert_eq!(std::mem::align_of::<AgFrameStats>(), 8);
        let s = AgFrameStats {
            abi_version: FRAME_STATS_ABI,
            width: 0,
            height: 0,
            reserved0: 0,
            timestamp_ms: 0,
            mean_luma: 0.0,
            low_opacity_ratio: 0.0,
            subliminal_ratio: 0.0,
            subliminal_ratio_wide: 0.0,
            lsb_flip_rate: 0.0,
            chroma_lsb_flip_rate: 0.0,
            ocr_text: std::ptr::null(),
            frame_digest: std::ptr::null(),
        };
        let base = &s as *const AgFrameStats as usize;
        assert_eq!(&s.timestamp_ms as *const i64 as usize - base, 16);
        assert_eq!(&s.mean_luma as *const f32 as usize - base, 24);
        assert_eq!(&s.chroma_lsb_flip_rate as *const f32 as usize - base, 44);
        assert_eq!(
            &s.ocr_text as *const *const std::os::raw::c_char as usize - base,
            48
        );
        assert_eq!(
            &s.frame_digest as *const *const std::os::raw::c_char as usize - base,
            56
        );
    }
}
