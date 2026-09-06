[简体中文](macos实时观测.md) | [繁體中文](macos实时观测.zh-TW.md) | [English](macos实时观测.en.md)

# Real-Time macOS Observation (E3)

> Status: **Implemented (tree-signal push + coalescer + generation cancel/drain); pixels are still sampled; an old 2026-09-01 ad-hoc candidate has local wiring smoke, while the latest universal `.app` is not revalidated**.
> This changes macOS UI-tree observation from fixed polling to “capture when it changes,” narrowing the limitation
> that this is not real-time monitoring and actions occurring between polls may be missed.

## Problem: gaps between polls

The macOS UI tree was previously captured as an AXUIElement snapshot every 2.5 seconds. Something that appears
between two polls and disappears before the next one—such as a briefly displayed confirmation dialog or a quick
autofill action—could fall entirely within the gap and remain invisible to the guard.

## Approach: AXObserver push + pure coalescer + fallback polling

The design has three layers, each with a distinct responsibility and explicit boundary:

1. **AXObserver push** (`native/AgentGuardAX.m`, with FFI in `ax_native.rs`). It registers for tree-change
   notifications from the foreground application (value changes, focus changes, window creation/destruction, and
   title changes). A signal is pushed **when the change occurs**, instead of waiting for the next polling point.
   The callback does only one thing: under a short lock, validate its registration generation and increment that
   generation's notification counter. It is kept as thin as possible.

2. **Pure coalescer** (`ax_push.rs`, `PushCoalescer`). Capturing once for every notification is not viable—one input
   action can emit dozens of `kAXValueChangedNotification` events, and capturing each one could saturate the CPU
   (a guard that makes the system lag is just as likely to be disabled as one that misses events). Push signals
   therefore enter the coalescer first:
   - **Debounce** `DEBOUNCE_MS` (150ms): after a notification, wait for a short quiet period before capturing so a
     burst is merged into one capture of a stable tree.
   - **Maximum latency** `MAX_LATENCY_MS` (800ms): if notifications continue indefinitely and no quiet period
     arrives, force a capture so the delay from “changed” to “captured” has an upper bound.

3. **Fallback polling** `FALLBACK_FLOOR_MS` (3s). When push is available, this is only a safety net for missed
   events; when push is **unavailable** (observer registration fails or the platform is not macOS), it degrades to
   polling semantics. **Adding push does not remove the polling lifeline**—a disconnected observer does not make
   the guard blind.

Result: a tree change is normally captured within 150ms (instead of waiting up to an entire 2.5-second cycle),
continuous changes are captured at least once every 800ms, and a capture occurs at least once every 3 seconds when
push is entirely unavailable.

## Driver usage

```rust
let generation = lifecycle.begin_if_drained()?;
adapter.start_ax_push(generation)?;    // Bind the observer to a non-reusable generation
loop {
    let now = now_ms();
    let captured = adapter.maybe_capture_ax(generation, now)?;
    // When captured==true, a pixel frame can also be captured for pairing
    sleep(tick);
}
lifecycle.cancel(generation);          // Async/UI path only cancels; it does not block
lifecycle.wait(generation, timeout);   // Bounded drain on a blocking worker
adapter.stop_ax_push(generation);      // A stale stop cannot stop the successor
```

`maybe_capture_ax` combines “read notification count → feed coalescer → decide whether to capture → capture → mark”
into one operation. The driver only needs to call it on a timer.

## Two explicit boundaries

**1. Pixel capture is still sampled.** AXObserver is a **tree** signal, not a **frame** signal. E3 narrows the gap
in **tree** observation, not pixel observation. Pixel analysis (steganography and frame digests) is still sampled
every 1.5 seconds. A change that exists only in pixels and does not change the AX tree (for example, a pasted image)
has the same gap as before. Making pixel capture event-driven would be separate work using ScreenCaptureKit content-
change callbacks; it has not been done.

**2. Local wiring is validated; release-grade timing is not.** Six unit tests cover debounce, maximum latency,
fallback, clearing after capture, and cold start. Five lifecycle tests cover 1,000 start/end/start cycles, startup
failure, worker panic, stop timeout, and queued stale callbacks. Those tests establish the controller boundary; they
do not replace a callback-storm and system-queue drain test with real AX/SCK TCC grants. A desktop-shell test also
pins startup, driving, shutdown, and the main-RunLoop connection. On 2026-09-01, the local ad-hoc candidate was launched with both AX and Capture TCC status
true. Enabling real-time AX observation displayed `AXObserver push on`; changing the UI tree then produced
`live AX ingested · 1 decision(s)`, after which observation was disabled and the session ended. This proves only that the
Objective-C callback and product driver were connected for that candidate on that Mac; it is not evidence for the current universal candidate. It is **not** a real-device latency-distribution
benchmark for the 150ms/800ms targets, nor does it replace fresh-install, upgrade, foreground-app-switching, or
long-duration acceptance after Developer ID signing and notarization.

In short: this is **faster, with a bounded gap**, not **gap-free**.
