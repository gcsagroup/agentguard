//! FFI bindings to the Objective-C ScreenCaptureKit bridge.
//!
//! On non-macOS targets this module provides stubs. Frame pixels are never
//! retained — only coarse [`crate::FrameStats`] are queued for the adapter.

use crate::screencapture::FrameStats;
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::ffi::CStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct QueuedFrame {
    generation: u64,
    stats: FrameStats,
}

static FRAME_QUEUE: OnceLock<Mutex<VecDeque<QueuedFrame>>> = OnceLock::new();
static ACTIVE_GENERATION: AtomicU64 = AtomicU64::new(0);
static NEXT_STANDALONE_GENERATION: AtomicU64 = AtomicU64::new(0);

const CAPTURE_CLOCK_SKEW_LIMIT_MS: i64 = 3_000;

fn queue() -> &'static Mutex<VecDeque<QueuedFrame>> {
    FRAME_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(8)))
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// Older native bridges supplied media PTS rather than Unix time. Validate at
/// the FFI trust boundary so a stale bridge cannot silently disable AX↔frame
/// pairing. Rust is entered only after native pixel analysis and optional OCR,
/// so its clock must never replace the capture timestamp: doing that could pair
/// an old, slow frame with a new AX tree. Implausible values become unknown (0)
/// and are rejected by the pairing layer.
fn validated_capture_timestamp(source_ms: i64, processing_completed_ms: i64) -> i64 {
    if source_ms > 0
        && processing_completed_ms > 0
        && source_ms.abs_diff(processing_completed_ms) <= CAPTURE_CLOCK_SKEW_LIMIT_MS as u64
    {
        source_ms
    } else {
        0
    }
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
    pub const TIMEOUT: i32 = 6;
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
        pub fn agentguard_sck_start(cb: FrameCb, userdata: *mut c_void, generation: u64) -> c_int;
        pub fn agentguard_sck_stop(generation: u64) -> c_int;
        pub fn agentguard_sck_last_error_copy() -> *mut c_char;
        pub fn agentguard_sck_string_free(s: *mut c_char);
        #[cfg(test)]
        pub fn agentguard_sck_singleflight_state_self_test() -> c_int;
        #[cfg(test)]
        pub fn agentguard_sck_busy_reason_state_self_test() -> c_int;
        #[cfg(test)]
        pub fn agentguard_sck_frame_digest_rgba(
            pixels: *const u8,
            width: usize,
            height: usize,
            bytes_per_row: usize,
            bgra: c_int,
        ) -> *mut c_char;
        #[cfg(test)]
        pub fn agentguard_sck_band_ratios_rgba(
            pixels: *const u8,
            width: usize,
            height: usize,
            bytes_per_row: usize,
            bgra: c_int,
            strong_out: *mut f32,
            wide_out: *mut f32,
        ) -> c_int;
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn on_frame(raw: *const AgFrameStats, userdata: *mut std::os::raw::c_void) {
    if raw.is_null() {
        return;
    }
    let generation = userdata as usize as u64;
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
    // stop/start 前已经进入 OCR 的旧 callback 可能很晚才跨进 Rust。代际不匹配时仍释放
    // callback 转交的字符串，但绝不把它塞进继任会话的进程级队列。
    if generation == 0 || ACTIVE_GENERATION.load(Ordering::SeqCst) != generation {
        if !s.ocr_text.is_null() {
            ffi::agentguard_sck_string_free(s.ocr_text as *mut _);
        }
        if !s.frame_digest.is_null() {
            ffi::agentguard_sck_string_free(s.frame_digest as *mut _);
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
    let processing_completed_ms = unix_now_ms();
    let stats = FrameStats {
        width: s.width,
        height: s.height,
        timestamp_ms: validated_capture_timestamp(s.timestamp_ms, processing_completed_ms),
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
        // 取消可发生在 OCR/复制字符串和拿队列锁之间；入队前再验一次。
        if ACTIVE_GENERATION.load(Ordering::SeqCst) != generation {
            return;
        }
        if q.len() >= 16 {
            q.pop_front();
        }
        q.push_back(QueuedFrame { generation, stats });
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
    let generation = next_standalone_generation();
    sck_start_generation(generation)
}

/// Start a native stream owned by an explicit desktop-observer generation.
pub fn sck_start_generation(generation: u64) -> Result<(), String> {
    if generation == 0 {
        return Err("SCK generation must be non-zero".into());
    }
    ACTIVE_GENERATION
        .compare_exchange(0, generation, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|active| format!("SCK generation {active} is already active"))?;
    clear_frame_queue();
    #[cfg(target_os = "macos")]
    {
        let userdata = generation as usize as *mut std::os::raw::c_void;
        let code = unsafe { ffi::agentguard_sck_start(Some(on_frame), userdata, generation) };
        let result = map_status(code);
        if result.is_err() {
            let _ = ACTIVE_GENERATION.compare_exchange(
                generation,
                0,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            clear_frame_queue();
        }
        result
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ =
            ACTIVE_GENERATION.compare_exchange(generation, 0, Ordering::SeqCst, Ordering::SeqCst);
        Err("ScreenCaptureKit only available on macOS".into())
    }
}

pub fn sck_stop() -> Result<(), String> {
    let generation = ACTIVE_GENERATION.load(Ordering::SeqCst);
    if generation == 0 {
        return Ok(());
    }
    sck_stop_generation(generation)
}

/// Stop only the matching stream generation. A stale stop is an idempotent no-op.
pub fn sck_stop_generation(generation: u64) -> Result<(), String> {
    if ACTIVE_GENERATION
        .compare_exchange(generation, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(());
    }
    clear_frame_queue();
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_sck_stop(generation) };
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
    let generation = ACTIVE_GENERATION.load(Ordering::SeqCst);
    drain_sck_frames_generation(generation)
}

/// Drain frames only for the requested active generation; stale entries are discarded.
pub fn drain_sck_frames_generation(generation: u64) -> Vec<FrameStats> {
    if generation == 0 || ACTIVE_GENERATION.load(Ordering::SeqCst) != generation {
        return Vec::new();
    }
    queue()
        .lock()
        .map(|mut q| {
            q.drain(..)
                .filter_map(|frame| (frame.generation == generation).then_some(frame.stats))
                .collect()
        })
        .unwrap_or_default()
}

fn clear_frame_queue() {
    if let Ok(mut queue) = queue().lock() {
        queue.clear();
    }
}

fn next_standalone_generation() -> u64 {
    loop {
        let generation = NEXT_STANDALONE_GENERATION
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        if generation != 0 {
            return generation;
        }
    }
}

// Reached only from `map_status`, which is macOS-only.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn last_error() -> String {
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let p = ffi::agentguard_sck_last_error_copy();
            if p.is_null() {
                return String::new();
            }
            let error = CStr::from_ptr(p).to_string_lossy().into_owned();
            ffi::agentguard_sck_string_free(p);
            error
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
        SckStatus::TIMEOUT => Err(format!("SCK timeout: {}", last_error())),
        SckStatus::ERROR => Err(format!("sck error: {}", last_error())),
        other => Err(format!("sck error ({other}): {}", last_error())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_timestamp_keeps_a_nearby_unix_wall_clock() {
        assert_eq!(
            validated_capture_timestamp(1_788_546_177_000, 1_788_546_177_420),
            1_788_546_177_000
        );
    }

    #[test]
    fn capture_timestamp_rejects_media_pts_and_unknown_values() {
        let completed = 1_788_546_177_000;
        assert_eq!(validated_capture_timestamp(294_365_480, completed), 0);
        assert_eq!(validated_capture_timestamp(0, completed), 0);
        assert_eq!(validated_capture_timestamp(-1, completed), 0);
        assert_eq!(validated_capture_timestamp(completed - 3_001, completed), 0);
    }

    /// ScreenCaptureKit owns the asynchronous completion, so a synchronous
    /// timeout cannot be tested deterministically without injecting Apple
    /// framework behavior. Keep a source-level contract test beside the FFI:
    /// it prevents the native token from being cleared at the deadline and
    /// requires matching-generation cleanup before a successor can start.
    #[test]
    fn native_start_timeout_is_single_flight_until_late_cleanup() {
        let bridge = include_str!("../native/AgentGuardSCK.m");
        assert!(
            bridge.contains("static pthread_mutex_t gSckStateLock")
                && bridge.contains("static uint64_t gSckStartInflight = 0"),
            "native SCK state needs an independent, mutex-protected operation token"
        );
        assert!(
            bridge.contains("ag_sck_claim_slot(generation, gStream != nil")
                && bridge.contains("return AG_SCK_BUSY;"),
            "a second native start must be rejected while start/cleanup is pending"
        );

        let busy_branch = bridge
            .split("// Claim the native slot only after permission probing")
            .nth(1)
            .and_then(|tail| tail.split("__block int result").next())
            .expect("native BUSY diagnostic section");
        let copy_reason = busy_branch
            .find("busyReason = ag_sck_busy_reason_copy(gSckBlockedReason)")
            .expect("copy permanent-or-temporary BUSY reason while state is locked");
        let unlock_state = busy_branch[copy_reason..]
            .find("pthread_mutex_unlock(&gSckStateLock)")
            .map(|offset| copy_reason + offset)
            .expect("release state lock before publishing diagnostic");
        let publish_error = busy_branch
            .find("ag_set_error(busyReason)")
            .expect("publish copied BUSY diagnostic");
        assert!(
            copy_reason < unlock_state && unlock_state < publish_error,
            "BUSY reason must be owned before state unlock and error lock acquisition"
        );

        let reason_helper = bridge
            .split("static NSString *ag_sck_busy_reason_copy")
            .nth(1)
            .and_then(|tail| tail.split("static BOOL ag_sck_claim_slot").next())
            .expect("BUSY reason ownership helper");
        assert!(
            reason_helper.contains("blocked_reason ?: kAgSckBusyInProgress")
                && reason_helper.contains(" copy]"),
            "permanent failure reason must take priority; temporary inflight uses generic BUSY"
        );

        let deadline = bridge
            .split("// A success completion may have committed")
            .nth(1)
            .and_then(|tail| tail.split("return AG_SCK_TIMEOUT;").next())
            .expect("native start deadline section");
        assert!(
            deadline.contains("ag_sck_cancel_slot(generation"),
            "deadline must revoke the timed-out generation's commit eligibility"
        );
        assert!(
            !deadline.contains("gSckStartInflight = 0")
                && !deadline.contains("ag_sck_retire_start(generation)"),
            "deadline must retain the native slot until Apple's completion/cleanup"
        );

        let cancel = bridge
            .split("static void ag_sck_cancel_slot")
            .nth(1)
            .and_then(|tail| tail.split("static BOOL ag_sck_retire_slot").next())
            .expect("deadline cancellation helper");
        assert!(
            cancel.contains("if (*inflight == generation)")
                && cancel.contains("atomic_compare_exchange_strong(active_generation"),
            "cancellation must use a matching-generation atomic CAS"
        );
        assert!(
            !cancel.contains("*inflight = 0"),
            "cancellation must not release single-flight ownership"
        );

        let late_success = bridge
            .split("// Do not release gSckStartInflight here")
            .nth(1)
            .and_then(|tail| tail.split("dispatch_semaphore_signal(sem);").next())
            .expect("late successful-start cleanup section");
        assert!(
            late_success.contains("stopCaptureWithCompletionHandler")
                && late_success.contains("if (stopErr == nil)")
                && late_success.contains("ag_sck_complete_cleanup_slot(")
                && late_success.contains("gSckBlockedReason = [failureReason copy]")
                && late_success.contains("restart required before capture can be retried"),
            "a stale stream may retire only after confirmed stop; stop failure must remain restart-required"
        );
        assert!(
            !late_success.contains("ag_sck_retire_start(generation)"),
            "late cleanup must not unconditionally retire after a failed stop"
        );

        let normal_stop = bridge
            .split("static int ag_sck_stop_impl")
            .nth(1)
            .and_then(|tail| tail.split("int agentguard_sck_stop").next())
            .expect("normal stop section");
        assert!(
            normal_stop.contains("if (error == nil)")
                && normal_stop.contains("ag_sck_complete_cleanup_slot(")
                && normal_stop.contains("gStream = stream;")
                && normal_stop.contains("gOutput = output;")
                && normal_stop.contains("restart required before capture can be retried"),
            "normal stop errors must retain ownership and stay fail-closed too"
        );

        let retire = bridge
            .split("static BOOL ag_sck_retire_start")
            .nth(1)
            .and_then(|tail| tail.split("static BOOL ag_sck_start_is_current").next())
            .expect("matching-generation retirement helper");
        assert!(
            retire.contains("ag_sck_retire_slot(")
                && retire.contains("&gSckStartInflight")
                && retire.contains("&gSckGeneration"),
            "old completions may retire only their own native token"
        );
        assert!(
            !retire.contains("ag_set_error"),
            "state-lock helpers must not acquire the independent last-error lock"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_single_flight_transitions_execute_deterministically() {
        assert_eq!(
            unsafe { ffi::agentguard_sck_singleflight_state_self_test() },
            1,
            "cleanup failure must preserve g1/BUSY; cleanup success must permit g2; old g1 cleanup must not clear g2"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_busy_reason_prefers_restart_required_and_owns_the_copy() {
        assert_eq!(
            unsafe { ffi::agentguard_sck_busy_reason_state_self_test() },
            1,
            "permanent restart-required reason must survive source mutation; nil uses generic temporary BUSY"
        );
    }

    #[test]
    fn timeout_status_is_not_stop_specific() {
        let source = include_str!("sck_native.rs");
        assert!(source.contains("SckStatus::TIMEOUT => Err(format!(\"SCK timeout:"));
        assert!(!source.contains("SckStatus::TIMEOUT => Err(format!(\"stop timeout:"));
    }

    #[cfg(target_os = "macos")]
    fn native_digest(
        pixels: &[u8],
        width: usize,
        height: usize,
        bytes_per_row: usize,
        bgra: bool,
    ) -> String {
        unsafe {
            let raw = ffi::agentguard_sck_frame_digest_rgba(
                pixels.as_ptr(),
                width,
                height,
                bytes_per_row,
                i32::from(bgra),
            );
            assert!(!raw.is_null(), "native digest rejected a valid frame");
            let digest = CStr::from_ptr(raw).to_string_lossy().into_owned();
            ffi::agentguard_sck_string_free(raw);
            digest
        }
    }

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

    /// The live ScreenCaptureKit path is Objective-C while simulation, CLI and
    /// comparisons use Rust. Exact golden parity prevents a detector that passes
    /// unit tests but emits a different/legacy digest on a real Mac.
    #[cfg(target_os = "macos")]
    #[test]
    fn objective_c_digest_matches_rust_for_packed_and_padded_frames() {
        const WIDTH: usize = 320;
        const HEIGHT: usize = 180;
        let cases = [
            vec![200u8; WIDTH * HEIGHT * 4],
            {
                let mut frame = vec![210u8; WIDTH * HEIGHT * 4];
                for y in 45..90 {
                    for x in 0..WIDTH {
                        let offset = (y * WIDTH + x) * 4;
                        frame[offset..offset + 3].fill(20);
                    }
                }
                frame
            },
            {
                let mut frame = vec![235u8; WIDTH * HEIGHT * 4];
                for y in (0..HEIGHT).step_by(4) {
                    for x in 40..280 {
                        let offset = (y * WIDTH + x) * 4;
                        frame[offset..offset + 3].fill(30);
                    }
                }
                frame
            },
        ];
        for packed in cases {
            let expected = crate::framehash::digest_rgba(&packed, WIDTH, HEIGHT, false)
                .expect("rust digest")
                .to_hex();
            assert_eq!(
                native_digest(&packed, WIDTH, HEIGHT, WIDTH * 4, false),
                expected
            );

            const PADDING: usize = 32;
            let stride = WIDTH * 4 + PADDING;
            let mut padded = vec![0xA5u8; stride * HEIGHT];
            for y in 0..HEIGHT {
                padded[y * stride..y * stride + WIDTH * 4]
                    .copy_from_slice(&packed[y * WIDTH * 4..(y + 1) * WIDTH * 4]);
            }
            let expected_padded =
                crate::framehash::digest_rgba_stride(&padded, WIDTH, HEIGHT, stride, false)
                    .expect("rust padded digest")
                    .to_hex();
            assert_eq!(
                native_digest(&padded, WIDTH, HEIGHT, stride, false),
                expected_padded
            );
        }
    }

    /// Non-divisible dimensions are the boundary case that used to make both
    /// implementations silently omit the rightmost column and bottom row.
    #[cfg(target_os = "macos")]
    #[test]
    fn objective_c_digest_matches_rust_and_covers_odd_frame_edges() {
        const WIDTH: usize = 321;
        const HEIGHT: usize = 181;
        let mut packed = vec![220u8; WIDTH * HEIGHT * 4];
        for x in 0..WIDTH {
            packed[((HEIGHT - 1) * WIDTH + x) * 4..][..3].fill(0);
        }
        for y in 0..HEIGHT {
            packed[(y * WIDTH + WIDTH - 1) * 4..][..3].fill(0);
        }

        let expected = crate::framehash::digest_rgba(&packed, WIDTH, HEIGHT, false)
            .expect("rust digest")
            .to_hex();
        assert_eq!(
            native_digest(&packed, WIDTH, HEIGHT, WIDTH * 4, false),
            expected
        );

        const PADDING: usize = 28;
        let stride = WIDTH * 4 + PADDING;
        let mut padded = vec![0xA5u8; stride * HEIGHT];
        for y in 0..HEIGHT {
            padded[y * stride..y * stride + WIDTH * 4]
                .copy_from_slice(&packed[y * WIDTH * 4..(y + 1) * WIDTH * 4]);
        }
        let expected_padded =
            crate::framehash::digest_rgba_stride(&padded, WIDTH, HEIGHT, stride, false)
                .expect("rust padded digest")
                .to_hex();
        assert_eq!(
            native_digest(&padded, WIDTH, HEIGHT, stride, false),
            expected_padded
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn objective_c_subliminal_ratios_match_rust_distribution() {
        const WIDTH: usize = 320;
        const HEIGHT: usize = 180;
        for alpha in [0.0f32, 0.04, 0.15, 1.0] {
            let mut frame = vec![255u8; WIDTH * HEIGHT * 4];
            let dim = ((1.0 - alpha) * 255.0) as u8;
            for y in 45..135 {
                if (y / 2) % 2 == 0 {
                    continue;
                }
                for x in 20..300 {
                    let offset = (y * WIDTH + x) * 4;
                    frame[offset..offset + 3].fill(dim);
                }
            }
            let expected = crate::subliminal::band_ratios(&frame, WIDTH, HEIGHT, false);
            let mut strong = -1.0f32;
            let mut wide = -1.0f32;
            let ok = unsafe {
                ffi::agentguard_sck_band_ratios_rgba(
                    frame.as_ptr(),
                    WIDTH,
                    HEIGHT,
                    WIDTH * 4,
                    0,
                    &mut strong,
                    &mut wide,
                )
            };
            assert_eq!(ok, 1);
            assert!(
                (strong - expected.0).abs() <= f32::EPSILON
                    && (wide - expected.1).abs() <= f32::EPSILON,
                "alpha={alpha}: native=({strong},{wide}) rust={expected:?}"
            );
        }
    }
}
