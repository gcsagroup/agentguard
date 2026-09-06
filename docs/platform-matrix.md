# Platform capability matrix

Written from code, and every row is checked by something. The previous version of this file was
a hand-maintained grid of ticks, and it overstated in three places: Android's Critical Confirm
row said "✅ (notif)" while `POST_NOTIFICATIONS` was declared and never requested at runtime, so
on API 33+ it was never granted; the iOS row described policy code that does not exist; and both
Windows rows claimed capabilities behind an adapter with no Win32 code in it at all.

The lesson is the same one `guard-cli coverage` exists for: a table nothing verifies drifts, and
it drifts optimistic. So this file now says which job or test backs each claim. A curated subset of
the rows here is additionally **machine-verified** by `guard-cli capability-claims` — each such
claim is pinned to a test that must exist and prose that must still appear in this file (see
[主张与测试映射.md](./主张与测试映射.md); rows not yet pinned are listed there as residual).

## What each platform can actually observe

| | **macOS** | **Windows** | **Android** | **Chromium** | **iOS** |
|---|---|---|---|---|---|
| **Observation source** | `AXUIElement` walker + ScreenCaptureKit (Obj-C bridges) | UI Automation tree walk + GDI `BitBlt` | AccessibilityService + `PackageManager` + window list | MV3 content script | Safari Web Extension MV3 content script + native handler |
| **Event kinds produced** | see [capability-matrix.md](./capability-matrix.md) — extracted from source, regenerated under `cargo test` (this row used to be hand-typed and drifted) | ″ | ″ | ″ | ″ |
| **Pixel analysis** | ✅ subliminal bands, chroma+luma stego, frame digest, Vision OCR | ✅ same code (`guard-vision`), OCR via `Windows.Media.Ocr` | ❌ an accessibility service cannot read pixels | ❌ | ❌ |
| **Session scope (Aura §4.4)** | ✅ | ✅ | ✅ | ❌ no session concept | ❌ |
| **App attestation (§3.5)** | ❌ no signing digest collected | ❌ | ✅ `PackageManager` signer SHA-256 | ❌ | ❌ |
| **Display identity / lookalike (§3.6)** | ❌ | ❌ | ✅ label + icon dHash | ❌ | ❌ |
| **Overlay detection** | ✅ pixels + AX regions | 🟡 window's own rendering only — see note 1 | 🟡 window list, draw-over-other-apps only — see note 2 | ✅ DOM opacity/geometry | ❌ |
| **Environment survey (A5/A6)** | ❌ | ❌ | ✅ a11y services, broadcast sinks, log readers | ❌ | ❌ |
| **Critical-node confirmation** | 🟡 post-observation risk confirmation; does not reverse the external action — see note 3 | 🟡 post-observation risk confirmation; does not reverse the external action — see note 3 | 🟡 notification **after** the event — see note 3 | 🟡 block-only DOM pre-execution gate + static DNR; no page approval — see note 4 | 🟡 block-only for covered DOM events; native `disabled` is the only release state |
| **Auto-poller** | 1.5 s frames; tree now **AXObserver push** + ≤3 s 兜底 — see note 5 | 2.5 s, tied to the session | event-driven | event-driven | — |
| **Runtime capability probe** | ✅ TCC preflight | ✅ real probe with a reason string | ✅ a11y-enabled + notification permission | — | 🟡 App Group/Keychain entitlement access fails closed; real-device state remains an acceptance item |
| **Compiled in CI** | ✅ `macos-shell` job | ✅ `windows` job | ✅ `android` job | ✅ Node/static gate plus real Chromium E2E | ✅ XcodeGen/Xcode build plus Swift and extension contract tests |
| **Tests** | see [capability-matrix.md](./capability-matrix.md) — static counts per crate / adapter / shell / extension / companion, regenerated under `cargo test` | ″ | ″ | ″ | ″ |

**Legend:** ✅ works · 🟡 works with a stated limit · ❌ absent

The **Chromium** column covers both Chrome and **Edge** from one MV3 ZIP; those are the only browsers in
the first GA. `manifest.firefox.json` is retained as an unshipped source prototype: Firefox is not packaged,
submitted, or accepted for this GA. **Safari** is a separate Xcode-wrapped product path. Per-browser breakdown is in
[跨浏览器.md](./跨浏览器.md).

Real-device acceptance checklists (the last mile CI cannot cover) live per platform:
[macOS](./acceptance-macos.md), [Windows](./acceptance-windows.md), [iOS](./acceptance-ios.md), and
[Chrome/Edge](./acceptance-chrome.md). The RC gate models Chrome and Edge as two independent structured kinds,
and models iOS signing, real-device Safari, and TestFlight independently. The Firefox document is an explicit
exclusion notice, not a PASS path.

### Note 1 — Windows overlay coverage is narrower than macOS

The capture path is GDI `BitBlt` on the target window's device context, which reads *that
window's* rendering. A phishing window drawn over it by **another process** is not in those
pixels unless it is itself the foreground window. `Windows.Graphics.Capture` samples the composed
desktop and would close the gap; it was not chosen because it is async WinRT with a D3D11 device
and a frame pool, several hundred lines whose failure modes this repository's CI cannot exercise.
The trade is recorded in `win_adapter::capture::GRAPHICS_CAPTURE_NOTE`, next to the code that
makes it.

Windows does now read screen text, with `Windows.Media.Ocr` — the OCR that ships with the OS,
offline, with simplified and traditional Chinese installed by default — so `OVL-009` / `OVL-010`
run there and the A1 sanitization loop closes. The **trigger and the contrast are shared** with
the macOS path (`guard_vision::ocr`), because a per-platform copy of "when to read" and "how much
contrast" is how one platform ends up quietly reading less than the other.

The remaining condition: a host with no recognizer language pack has no OCR, and then those two
rules do not run. The capability report says so with a reason rather than leaving it to be
inferred.

### Note 2 — the Android window survey does not catch a phishing Activity

`WindowSurvey` reads `getWindows()` and reports a window covering the active one. A fake payment
sheet launched as a normal Activity *becomes* the active window, so it is the baseline the scan
takes and skips. What this covers is the draw-over-other-apps overlay. (A)I Sees A3 (UI spoofing)
is covered, where it is covered at all, by app identity — `APP-LOOKALIKE` and the
signing-certificate pin — not by window geometry.

A window covering less than 55 % of the active window is not reported either, because a keyboard,
an autofill dropdown and a toast all legitimately sit on top. That is a deliberate false-negative.

### Note 3 — desktop and Android confirmations are post-hoc, not external-action gates

The relay now **reads** the engine's answer (it was fire-and-forget, so a `Block` with
`require_confirm` reached nothing), and a `require_confirm` verdict raises a high-importance
notification naming the engine's rule. That is a real improvement over a local heuristic guess
with no connection to the verdict.

The companion observes an accessibility event that has **already happened**; there is no point at
which it holds the action and waits. The macOS and Windows observers have the same boundary for an
external application: their shell can pause AgentGuard's current session and future observation,
but cannot undo or prove prevention of the already-observed external action. Their audit export must
therefore say `effect=observed_only` and `external_action_blocked=false`. Only the covered Chromium
DOM/DNR path in note 4 is a pre-execution block.

### Note 4 — Chromium is block-only in the first GA

The isolated content script synchronously intercepts covered payment clicks and privacy-trap submits before the
page handler runs. It observes open Shadow DOM and declared frames from `document_start`. The ordinary-page notice
only explains that the action was blocked and exposes one Close control; it cannot approve or replay anything.
A page that removes, hides, clicks, or imitates that notice therefore gains no authorization capability.

A separate, default-enabled static `declarativeNetRequest` ruleset blocks non-GET/HEAD payment-shaped
fetch/XHR/beacon/form traffic for the covered URL and resource-type shapes. DNR has no page approval or one-shot
exception. It is a deliberately bounded heuristic rather than a universal payment firewall: renamed endpoints,
encrypted body-only semantics, unsupported schemes or browser-native actions remain outside its claim. The GA
manifests omit `nativeMessaging`; repository Native Host and Firefox files are prototypes outside this browser
release contract. See [浏览器执行前阻断.md](./浏览器执行前阻断.md) and [acceptance-chrome.md](./acceptance-chrome.md).

### Note 5 — macOS tree observation is push-driven, with polling kept as a floor (E3)

The tree used to be a fixed 2.5 s poll, so a change that appeared and vanished between two polls
could fall entirely in the gap — the "not real-time monitoring" boundary. E3 registers an
**AXObserver** (`native/AgentGuardAX.m`, FFI in `ax_native.rs`) that pushes a notification when the
frontmost app's tree changes; a change now triggers a capture within `DEBOUNCE_MS` (150 ms) instead
of waiting up to a full poll period. A pure coalescer (`ax_push.rs`) debounces bursts and caps the
change-to-capture latency at `MAX_LATENCY_MS` (800 ms) so a continuously-animating UI still gets
captured. Polling is **not** removed — it stays as a `FALLBACK_FLOOR_MS` (3 s) floor, so a failed
observer registration or a missed notification degrades to the old poll rather than to blindness.

Two honesty limits: **pixel capture stays sampled** (1.5 s frames) — AXObserver is a tree signal, not
a frame signal, so this shrinks the *tree* gap, not the pixel gap; and the coalescer is unit-tested
here (`ax_push::tests`), but the AXObserver registration and the Objective-C callback are compiled
only on macOS (`check-macos-cfg` rewrites the Rust half to Linux to type-check it) and **not verified
on a real device**. This is "faster, with a bounded gap", not "zero gap".

## iOS

iOS now has a formal XcodeGen project with a container app, embedded Safari Web Extension,
`WebShieldCore`, App Group/Keychain entitlements, privacy manifest, local atomic JSONL audit,
Swift unit/UI tests, and extension-contract tests. The limited SKU observes only authorized
HTTP(S) Safari frames and blocks covered DOM clicks/submissions; it does not observe other apps,
system UI, pixels, closed shadow roots, or direct scripted network calls, and it is not wired to
the Rust engine. Unsigned simulator/device builds and simulator launch evidence exist, but Apple
Distribution signing, real-device Safari enablement/permissions, upgrade/uninstall, and TestFlight
remain external RC blockers. See [ios-limited-sku.md](./ios-limited-sku.md) and
[acceptance-ios.md](./acceptance-ios.md).

## What backs each column

| Job | Runs | What would break it |
|---|---|---|
| `test` (macOS + Ubuntu) | `cargo test --workspace`, eval, coverage, scoreboard | any engine or shared-analysis regression |
| `windows` | workspace tests, `cargo build -p win-adapter`, `clippy -D warnings`, shell tests | the UI Automation walk or GDI capture failing to compile — the only job that compiles them. Its first run found an adapter that was not `Send`, which is a build error **on Windows only** and which the Linux and macOS jobs cannot see. |
| `macos-shell` | `cargo build -p mac-adapter`, shell tests, signing-script parse | the Objective-C bridges failing to build against the macOS SDK |
| `android` | `:app:testDebugUnitTest`, `:app:assembleDebug`, APK artifact | the Kotlin failing to compile, a unit test failing, or the APK failing to package |
| `ios` | XcodeGen consistency, unsigned simulator/device Release builds, Swift tests, extension Node contracts | the app/extension/core project, resources, privacy manifest, or limited Safari gate failing to build or test |
| `frontend` | `make check-shells` | a syntax error in either shell's JS or in any `.sh` |

Locally: `make check` for the engine, then `make check-windows`, `make check-android` and
`make check-shell-apps` — separate targets because each needs a toolchain the others do not.
