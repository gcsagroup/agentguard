[简体中文](desktop-guide.md) | [繁體中文](desktop-guide.zh-TW.md) | [English](desktop-guide.en.md)

# Desktop guide (macOS / Windows)

This document answers four questions: **what this is, how to turn it on, how to know it is actually
working, and what it cannot do.** It is the long form of the “How to use it” card inside the desktop
app — the card is the three-step summary, this is the full version.

Real-device feedback is why it exists: the app's main window used to offer one “Start session” button
and one line reading `27 rules · intel 2026.07.30 · AX=false · Capture=false · SCK=idle`, with no
explanation of any of it.

## What this is

AgentGuard **does not operate anything for you.** It watches what an AI agent — in the browser, on
the desktop — does on this machine, holds a high-risk action **before it happens**, raises a
confirmation you must answer, and writes every verdict into a local audit trail.

It is **not** an antivirus, a firewall, a general sandbox, or zero-gap real-time monitoring: the
desktop observation paths include sampling and polling, and something inside a gap can be missed.
The full boundary list is in the [README](../README.en.md) under “Boundaries you must understand”.

## 1. Permissions (macOS only)

macOS needs two system permissions. Each one you skip removes one observation path:

| Permission | What it grants | Without it |
|---|---|---|
| Accessibility | Reading **window content**: control text, form fields, button titles | No interface text, so every form and payment-button rule is inert |
| Screen Recording | Reading **screen pixels**: transparent overlays, steganographic pixels, on-screen text (OCR) | No pixels, so every overlay and stego rule is inert |

With neither granted the app states **“Protection coverage: Simulation”** — only simulated events and
the browser-extension path do anything. That is not an error message; it is the app refusing to
pretend it is protecting you.

The two buttons in step 1 open System Settings directly on the right page, so you do not have to
find a four-level path yourself.

> **Known issue with unsigned builds.** If AgentGuard is missing from that list entirely, or the
> switch does not stick and reverts after a restart: that is what an **ad-hoc / unsigned build** does
> — macOS keys both grants to the signing identity, and an unstable identity cannot hold a grant.
> Only a properly signed build (Developer ID + notarization) holds them. This repository has not
> completed signing and notarization; see [release-evidence.en.md](release-evidence.en.md).

Windows needs no permission grant: reading window contents (UI Automation), capturing the screen
(GDI) and reading on-screen text (Windows.Media.Ocr) are not gated the way macOS gates them. What
varies is whether each is available **on this machine** — the app's “Live observation” card names all
three with the reason each one is or is not.

## 2. Start protecting

Press “**Start protecting**”. That does three things:

1. **Opens one session.** The session is the audit and policy boundary: every verdict is filed under
   it, and an exported report is exported per session.
2. **Starts the observers you granted.** On macOS, Accessibility starts window-content observation
   (AXObserver push plus fallback polling) and Screen Recording starts capture; on Windows
   observation starts with the session. **Stopping protection stops them** — there is no “ended but
   still collecting”.
3. **Applies a task cap (optional).** Picking a task in the dropdown caps what the session may do:
   pick “Book a hotel” and a transfer inside that session is held. Leaving it blank means no cap.

The status light and the “what is being watched” line are **derived from facts**, not from whether
you pressed a button:

| Light | Meaning |
|---|---|
| Not protecting | No session. |
| Permission required | A session is open but no observer can run (on macOS, neither permission granted). |
| Protection incomplete | A session is open but observers are not running, or the heartbeat is stale, or the audit trail is not writable — **this never shows green**. |
| Protecting | Session plus running observers plus a fresh heartbeat plus a writable audit trail, all four at once. |
| Confirmation required | A high-risk action is held, waiting for your answer. |
| Paused | The engine paused this session after a previous denial; press “Resume”. |

## 3. What happens when something risky shows up

A high-risk action — a payment, a transfer, a privacy-trap form, an injection inside a transparent
overlay — raises a confirmation you **must** answer:

- “**Not now**” (“Deny and pause” on Windows): the action is held. This is where focus lands by default.
- “**Allow once**”: that one action goes through. It is not a standing grant.
- **Two minutes with no answer** counts as a refusal and writes a Timeout receipt — it neither
  disappears quietly nor defaults to allowing.
- Keyboard: Tab cycles inside the dialog only, Esc equals “Not now”; screen-reader users hear an
  announcement.

Every verdict (allow, alert, block) enters the local audit trail: hash-chained, signable per entry.
The visible entry points are the “Activity timeline” at the bottom of the window and “Export summary”.

### To see it work right now: the self-test

The “**Self-test: simulate one payment block**” button in step 3 feeds the engine a **locally
constructed fake event**: the confirmation really appears and the timeline really gains a verdict. It
does **not** pay anything, does **not** touch the network, and is **not observation** — it proves the
rule fires and the confirmation reaches you, not that this machine is being watched.

## Nothing is happening — check in this order

1. **Light says “Not protecting”** → you have not pressed “Start protecting”.
2. **Light says “Permission required”, or the banner says “Protection coverage: Simulation”** → go
   back to step 1. If the app is missing from the System Settings list, see the unsigned-build note above.
3. **Light says “Protection incomplete”** → the reasons are listed under it (observers not running /
   stale heartbeat / audit not writable); act on that line.
4. **Light says “Protecting” but the timeline stays empty** → that is normal: no suspicious action
   means no verdict. Use the **self-test** to confirm the chain is live.
5. **You want proof the observers are moving** → expand “Developer panel (demos & diagnostics)”: the
   raw state line (`AX=… · Capture=… · SCK=…`), a single-observation button and the raw verdict log
   are there. The main window deliberately does not show them.

## For developers: running the shell on Linux

You do not need a Mac to verify the frontend ↔ real-backend layer: `make shell-run-linux` (needs Xvfb,
xdotool and webkit2gtk-4.1) compiles the shell, runs it headless, clicks through
Start protecting → self-test → Not now → Stop protecting, and leaves five screenshots.
**It does not replace a real device**: on Linux the TCC grants, AXObserver push and ScreenCaptureKit
capture are all stubs (`mac_capabilities()` always returns false), and Tauri renders through WebKitGTK
rather than WKWebView. The script's header states exactly what it does and does not prove — the first
such run caught a raw-terminology leak the Playwright stub harness could not see.

## What it cannot do (honestly)

- **It cannot hold what does not pass through it.** The desktop confirmation covers actions the
  engine can see; a direct system-API call, or an action completed inside an observation gap, is not held.
- **It is not zero-gap.** Pixel capture is sampled; macOS tree observation has push signals but still
  falls back to polling.
- **The browser is separate.** In-page payment and form interception is done synchronously on the page
  by the Chromium extension (only if you installed it); the native-messaging path is **asynchronous**
  and can only notify after the fact — it cannot undo an action that already happened.
- **Android notifies after the event.** The companion cannot stop an action a third-party app has
  already performed.
- **Real-device acceptance is not finished.** Signing, notarization and the per-platform checklists
  are tracked in [release-evidence.en.md](release-evidence.en.md) and `docs/acceptance-*.md`; the
  current release decision is **No-Go**.

## Related documents

- [capability-matrix.en.md](capability-matrix.en.md) — what each platform **actually emits**, test counts, versions (generated from source)
- [acceptance-macos.en.md](acceptance-macos.en.md) / [acceptance-windows.en.md](acceptance-windows.en.md) — real-device checklists
- [acceptance-chrome.en.md](acceptance-chrome.en.md) — the browser-extension path
- [privacy-policy.en.md](privacy-policy.en.md) — where the data stays
