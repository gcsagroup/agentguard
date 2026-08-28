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
| **Observation source** | `AXUIElement` walker + ScreenCaptureKit (Obj-C bridges) | UI Automation tree walk + GDI `BitBlt` | AccessibilityService + `PackageManager` + window list | MV3 content script | none |
| **Event kinds produced** | 4 — `UiTreeDelta`, `FormFill`, `ScreenFrame`, session | 3 — `UiTreeDelta`, `FormFill`, `ScreenFrame` | 8 — `ui_text`, `form_fill`, `env_survey`, `overlay_marker`, `permission_request`, `network_meta`, `session_start`, `session_end` | 2 — `ui_text`, `form_fill` | 0 |
| **Pixel analysis** | ✅ subliminal bands, chroma+luma stego, frame digest, Vision OCR | ✅ same code (`guard-vision`), OCR via `Windows.Media.Ocr` | ❌ an accessibility service cannot read pixels | ❌ | ❌ |
| **Session scope (Aura §4.4)** | ✅ | ✅ | ✅ | ❌ no session concept | ❌ |
| **App attestation (§3.5)** | ❌ no signing digest collected | ❌ | ✅ `PackageManager` signer SHA-256 | ❌ | ❌ |
| **Display identity / lookalike (§3.6)** | ❌ | ❌ | ✅ label + icon dHash | ❌ | ❌ |
| **Overlay detection** | ✅ pixels + AX regions | 🟡 window's own rendering only — see note 1 | 🟡 window list, draw-over-other-apps only — see note 2 | ✅ DOM opacity/geometry | ❌ |
| **Environment survey (A5/A6)** | ❌ | ❌ | ✅ a11y services, broadcast sinks, log readers | ❌ | ❌ |
| **Critical-node confirmation** | ✅ blocking modal in the shell | ✅ blocking modal in the shell | 🟡 notification **after** the event — see note 3 | 🟡 in-page 执行前拦截(付款/陷阱提交)+ host 事后通知 — see note 4 | ❌ |
| **Auto-poller** | 1.5 s frames / 2.5 s tree | 2.5 s, tied to the session | event-driven | event-driven | — |
| **Runtime capability probe** | ✅ TCC preflight | ✅ real probe with a reason string | ✅ a11y-enabled + notification permission | — | — |
| **Compiled in CI** | ✅ `macos-shell` job | ✅ `windows` job | ✅ `android` job | 🟡 syntax only (`frontend` job) | ❌ nothing to compile |
| **Tests** | 3 packaging | 2 packaging + 5 adapter | 24 unit | 0 | 0 |

**Legend:** ✅ works · 🟡 works with a stated limit · ❌ absent

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

### Note 3 — Android confirmation is post-hoc, not a gate

The relay now **reads** the engine's answer (it was fire-and-forget, so a `Block` with
`require_confirm` reached nothing), and a `require_confirm` verdict raises a high-importance
notification naming the engine's rule. That is a real improvement over a local heuristic guess
with no connection to the verdict.

It is still not the desktop's gate. The companion observes an accessibility event that has
**already happened**; there is no point at which it holds the action and waits. On the desktop the
modal blocks before the action proceeds. Calling both "Critical Confirm ✅" is what the previous
version of this table did.

### Note 4 — Chromium confirmation is an extension notification, not a gate (was: nothing)

This cell used to read "via the desktop shell", which was false twice over: the extension talks to
the standalone `guard-nm-host` binary, **not** the Tauri desktop shell (the two processes never
communicate), and `background.js` received the host's verdict and only `console.debug`'d it — the
`paused` / `require_confirm` / `decisions` were discarded, so the "Critical Confirm" the store
listing advertised never fired.

Now `guard-nm-host` returns a structured `notify` list (Critical / Block / confirm-worthy decisions,
each with rule id, action, severity, and a `log_safe`'d message), and `background.js` raises a
`chrome.notifications` entry per item plus a paused badge. This is the same shape as Android
(note 3): the host observes a DOM event that has **already happened** over async native messaging,
so there is nothing to hold and wait on — it is observe-and-notify, not the desktop's blocking gate.
A true interactive approve-then-proceed would need the content script to intercept the action
*before* it happens, which is a different capability (interception, not observation).

**E2 built that in-page half.** The host-notify path above is unchanged (it is still observe-and-notify
over async native messaging), but the content script now also runs a **synchronous** capturing gate:
a `submit` / payment-CTA `click` is `preventDefault()`'d *before* it fires, and only replayed after a
local "允许一次" confirmation (`content.js`, decision logic in `guard-gate.js`). It covers the page's
own DOM actions (payment CTAs, privacy-trap PII submits); it does **not** cover a script that calls
`fetch()` directly (no DOM event — that is what the `declarativeNetRequest` block-host rules are for),
cross-origin iframes, or any native-app action. So the cell is "🟡 in-page 执行前拦截 + host 事后通知":
the block is real but its reach is the page, not the machine. See [浏览器执行前阻断.md](./浏览器执行前阻断.md);
decision logic pinned by `guard-gate.js`'s node tests, host-notify still pinned by
`critical判决产生notify供扩展弹通知`.

## iOS

A 40-line SwiftUI snippet and a README. No Xcode project, no engine link, not connected to
anything. iOS cannot run an accessibility companion the way Android can; the intended shape is
Safari/WebView shielding plus MDM policy distribution, and none of it is built. Do not claim
parity.

## What backs each column

| Job | Runs | What would break it |
|---|---|---|
| `test` (macOS + Ubuntu) | `cargo test --workspace`, eval, coverage, scoreboard | any engine or shared-analysis regression |
| `windows` | workspace tests, `cargo build -p win-adapter`, `clippy -D warnings`, shell tests | the UI Automation walk or GDI capture failing to compile — the only job that compiles them. Its first run found an adapter that was not `Send`, which is a build error **on Windows only** and which the Linux and macOS jobs cannot see. |
| `macos-shell` | `cargo build -p mac-adapter`, shell tests, signing-script parse | the Objective-C bridges failing to build against the macOS SDK |
| `android` | `:app:testDebugUnitTest`, `:app:assembleDebug`, APK artifact | the Kotlin failing to compile, a unit test failing, or the APK failing to package |
| `frontend` | `make check-shells` | a syntax error in either shell's JS or in any `.sh` |

Locally: `make check` for the engine, then `make check-windows`, `make check-android` and
`make check-shell-apps` — separate targets because each needs a toolchain the others do not.
