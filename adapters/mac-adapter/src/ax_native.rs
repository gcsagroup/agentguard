//! FFI bindings to the Objective-C Accessibility (AXUIElement) bridge.

use crate::ax_tree::AxSnapshot;
// 只有 macOS 上的那两处 `CStr::from_ptr` 用到它，所以在别的平台上它是未使用的。
//
// 这一行原来是裸的 `use std::ffi::CStr;`，被一次 `cargo clippy --fix` 删掉了 ——
// 在 Linux 上它确实"未使用"，而 clippy 只看当前目标平台。结果是一个**只在 macOS 上
// 出现**的编译失败，从 Linux 完全看不见。和之前 `NativeWinAdapter` 不是 `Send`
// 那次是同一形状：跨平台 crate 的自动修复只对它能编译的那个平台负责。
//
// 加上 cfg 之后两边都对：macOS 上是需要的导入，别的平台上根本不存在。
#[cfg(target_os = "macos")]
use std::ffi::CStr;

// The AX bridge only exists on macOS, so off macOS nothing calls into this status
// surface and every item below reads as dead. It is not: these are the codes the
// Objective-C side returns, and the real macOS build uses all of them. Allowing the
// lint only off macOS keeps the check honest where it can actually find rot.
#[repr(C)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct AxStatus;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl AxStatus {
    pub const OK: i32 = 0;
    pub const DENIED: i32 = 1;
    pub const ERROR: i32 = 2;
    pub const UNSUPPORTED: i32 = 3;
}

#[cfg(target_os = "macos")]
mod ffi {
    use std::os::raw::{c_char, c_int};

    extern "C" {
        pub fn agentguard_ax_probe() -> c_int;
        pub fn agentguard_ax_frontmost_json(out_json: *mut *mut c_char) -> c_int;
        pub fn agentguard_ax_string_free(s: *mut c_char);
        pub fn agentguard_ax_last_error() -> *const c_char;
        // AXObserver 推送(E3)。start 注册前台应用的树变化通知;take 取走并清零自上次以来
        // 收到的通知计数(轮询这个计数比把 Rust 回调传过 FFI 简单也更安全——和 SCK 的
        // drain_sck_frames 同一个"由内核/系统线程累积、Rust 定时取走"的模式)。
        pub fn agentguard_ax_observe_start() -> c_int;
        pub fn agentguard_ax_observe_take() -> u64;
        pub fn agentguard_ax_observe_stop();
    }
}

/// 开始接收前台应用的 AXObserver 树变化通知(E3)。
///
/// fail 语义与其余 AX 一致:非 macOS 或桥不可用返回 `Err`。调用方(驱动循环)据此决定是继续
/// 靠推送+合并器,还是退回纯兜底轮询——**不**静默假装推送在工作。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn start_ax_observer() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_ax_observe_start() };
        if code == AxStatus::OK {
            Ok(())
        } else {
            Err(format!(
                "AXObserver start failed: {} ({code})",
                last_error()
            ))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Accessibility bridge only available on macOS".into())
    }
}

/// 取走并清零自上次调用以来累积的 AXObserver 通知计数。非 macOS 恒为 0。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn take_ax_notifications() -> u64 {
    #[cfg(target_os = "macos")]
    {
        unsafe { ffi::agentguard_ax_observe_take() }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// 停止接收(卸载 observer)。非 macOS 是空操作。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn stop_ax_observer() {
    #[cfg(target_os = "macos")]
    {
        unsafe { ffi::agentguard_ax_observe_stop() }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn last_error() -> String {
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let p = ffi::agentguard_ax_last_error();
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn map_status(code: i32) -> Result<(), String> {
    match code {
        x if x == AxStatus::OK => Ok(()),
        x if x == AxStatus::DENIED => Err(format!("ax denied: {}", last_error())),
        x if x == AxStatus::UNSUPPORTED => Err(format!("ax unsupported: {}", last_error())),
        x if x == AxStatus::ERROR => Err(format!("ax error: {}", last_error())),
        _ => Err(format!("ax error ({code}): {}", last_error())),
    }
}

/// Probe Accessibility TCC (`AXIsProcessTrusted`).
pub fn ax_probe() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let code = unsafe { ffi::agentguard_ax_probe() };
        map_status(code)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Accessibility bridge only available on macOS".into())
    }
}

/// Capture the frontmost app's AX tree as [`AxSnapshot`].
pub fn live_ax_snapshot() -> Result<AxSnapshot, String> {
    #[cfg(target_os = "macos")]
    {
        let mut ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { ffi::agentguard_ax_frontmost_json(&mut ptr) };
        if code != AxStatus::OK {
            if !ptr.is_null() {
                unsafe { ffi::agentguard_ax_string_free(ptr) };
            }
            return map_status(code).map(|_| unreachable!());
        }
        if ptr.is_null() {
            return Err("ax returned null JSON".into());
        }
        let json = unsafe {
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ffi::agentguard_ax_string_free(ptr);
            s
        };
        AxSnapshot::from_sim_json(&json).map_err(|e| format!("parse live AX JSON: {e}"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Accessibility bridge only available on macOS".into())
    }
}
