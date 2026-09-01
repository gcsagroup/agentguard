[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# Real-Device Acceptance Runbook (for Automation Agents / computer-use)

This runbook turns the three acceptance checklists (`acceptance-firefox.md` / `acceptance-macos.md` /
`acceptance-windows.md`) from human-readable checklists into executable procedures. It gives the
**preparation, exact action, observable criterion, and evidence to capture** for every case, followed by
**how to record the results and update the dashboard**. The executor can be Codex, computer-use, or another
agent capable of driving real browsers and desktops.

> The expected result for each case is defined by the three `acceptance-*.md` files. This runbook adds how
> to cause the event and how to determine whether it succeeded.

---

## 0. Scope and Honest Preconditions (Read First)

- **The browser-extension path (Firefox / Chrome / Edge) is fully executable and assessable**, and this
  repository provides test fixtures (`eval/acceptance-fixtures/`), so F1–F8 are turnkey.
- **The desktop shells have native observation paths wired in:** macOS uses AXUIElement, ScreenCaptureKit,
  and Vision OCR; Windows uses UI Automation, GDI `BitBlt`, and `Windows.Media.Ocr`. However, “the code is
  wired” does not mean “it works on this real device.” Assess each case from runtime capability, operating-
  system permissions, actual event/frame/OCR output, and retained evidence. Therefore:
  - If native observation is available on the target device and produces the expected evidence, record `PASS (native)`.
  - If only a shell simulation injection proves the rule hit, record only `PASS (sim)`. It does not replace native observation, real-device acceptance, or release evidence.
  - If permission is not granted, a system component is missing, or the capability is unavailable, record `BLOCKED (specific reason)` and retain the capability report.
  The report must preserve this distinction. If the result cannot be determined, report `BLOCKED`; that is
  more valuable than a false PASS.

- **Do not make a real payment and do not send requests to real payment or transfer endpoints.** Fixture
  fetches go only to fake local same-origin paths. The test asks whether the request is blocked **before it
  is sent**, not whether the request itself succeeds.
- **An acceptance report is not release evidence.** Even if every executable case passes, signing,
  notarization/store review, release-artifact identity, strict gates, and target-platform coverage must
  still be satisfied separately.

---

## 1. Common One-Time Prerequisites

Run the following at the repository root, `/root/ag` (or the path to your clone):

```bash
# Toolchain: Rust (a version recent enough for the edition) and Node ≥ 18
cargo --version && node --version

# 1) Build the native-messaging host (the browser extension connects to it)
cargo build -p guard-nm-host           # Output: target/debug/guard-nm-host

# 2) Package the extension (default for Chrome/Edge; --firefox for Firefox)
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip
apps/extension-chromium/scripts/package-store.sh --firefox       # dist/agentguard-extension-firefox.zip

# 3) Offline gates (must all be green first; necessary but not sufficient for real-device acceptance)
make capability-claims && make check-extension-gate && make coverage
```

Start the test-fixture server (fetch cases require same-origin path resolution and cannot use file://):

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# Fixture index: http://localhost:8000/
```

Prepare an evidence directory:

```bash
mkdir -p /tmp/ag-evidence/{firefox,windows,macos}
```

---

## 2. Platform A: Browser Extension (Firefox / Chrome / Edge)

### A.1 Installation

**Firefox (≥128)**
1. Install the native-messaging host: `apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev`
2. Open `about:debugging#/runtime/this-firefox` → “Load Temporary Add-on” → choose
   `apps/extension-chromium/manifest.firefox.json` (or extract `dist/agentguard-extension-firefox.zip`
   and choose its `manifest.json`).
3. Record the assigned extension ID (expected: `agentguard@agentguard.dev`).

**Chrome / Edge**
1. Open `chrome://extensions` (or `edge://extensions`) → enable “Developer mode” → “Load unpacked” → choose
   `apps/extension-chromium/` (or the extracted dist directory). Copy the generated extension ID.
2. Install the host with `install-host.sh <extension-id>` (for Edge, use `--browser edge <extension-id>`).

After installation, **restart the browser once** so content scripts (including guard-page.js with
`world:"MAIN"`) are injected into new tabs.

### A.2 Execute F1–F8

For each case, **open DevTools first** (Console + Network panels), perform the action, and capture the
evidence specified by the criterion.

| Case | Page / Action | Observable PASS Criterion | Evidence |
|---|---|---|---|
| **F1** Hidden injection | Open `http://localhost:8000/injection.html`; click the extension icon and inspect “Recent” in the popup | The popup's recent list contains `invisible_injection`/`prompt_injection`; if the host is installed, host stderr / audit contains the corresponding event | Popup screenshot |
| **F2** Pre-execution payment CTA gate | Open `payment-cta.html` and click “Confirm Payment” | AgentGuard opens a confirmation layer **before** the action (with a human-readable title such as “This step makes a payment”); choose **“Not now”** → the page does **not** show “Payment confirmed”; repeat and choose **“Allow once”** → only then does it appear | Two screenshots (canceled / allowed states) |
| **F3** Trap + PII submission gate | Open `trap-pii.html` and click “Submit” | A confirmation layer appears; **“Not now”** → the URL is unchanged and has no `?phone=`; **“Allow once”** → the URL contains `?phone=13800000000` | Two screenshots with the URL bar visible |
| **F4** Payment-shaped fetch gate | Open `fetch-gate.html` and click “POST /pay/checkout” | A confirmation layer appears; **“Not now”** → the Network panel has **no** `/pay/checkout` request and the log says it was denied/not sent; **“Allow once”** → the request appears (404/501 is acceptable) | Network-panel screenshot in the canceled state |
| **F5** Do not gate read-only methods | On the same page, click “GET /pay/status” and “POST /api/search” | No confirmation layer appears; the requests are sent directly and appear in Network | Network-panel screenshot |
| **F6** Hard-block a malicious domain at the network layer | The engine must classify `evil.example` as malicious (the bundled baseline includes it). With the host path, construct a browser event whose url is `https://evil.example/x` (or visit `http://evil.example/` directly in the address bar), then access the host again in a **new request** | declarativeNetRequest blocks the host at the network layer (Network shows blocked / net::ERR_BLOCKED_BY_CLIENT); the popup block list contains `evil.example · Malicious domain`, with `INTEL-DOMAIN` provenance | Popup-list screenshot + Network screenshot |
| **F7** Native-messaging handshake | Ensure the host is installed and trigger any finding (F1–F3) | The host accepts the caller (it does not refuse startup because of origin validation, and stderr has no "refuse origin"); the verdict enters the signed audit database (the database pointed to by `AGENTGUARD_AUDIT_DB` has a new row) | Host stderr screenshot / audit row |
| **F8** DNR quota | After triggering several F6-style blocks, run `chrome.declarativeNetRequest.getDynamicRules().then(r=>console.log(r.length))` in the DevTools console | The rule count is ≤ the browser's dynamic-rule quota and rule installation produces no error | Console-output screenshot |

> **F6 note:** the browser extension currently reports `ui_text` events. The malicious-domain verdict
> (`INTEL-DOMAIN`) applies to **any event with a url**, so the host path can trigger it. If your environment
> does not return a malicious-domain verdict from the host, record `BLOCKED (no host verdict)`. Out-of-scope
> enforcement (`SCOPE-HOST`/E9 local allow-list gate) requires the session to declare `scope.hosts`. The browser
> path does not do so by default; record `N/A` unless you explicitly configured a task session with `scope.hosts`.

---

## 3. Platform B: Windows Desktop Shell (W1–W7)

### B.1 Build and Run

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # Start the tray shell (dev)
```

For the native-messaging host (when testing the W7 browser path), write `com.agentguard.native.json` to
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`; set `path` to
`target\debug\guard-nm-host.exe` and put the extension origin in `allowed_origins`.

### B.2 Execute Each Case

Use W1–W7 in `acceptance-windows.md` as the criteria. **For every case, record the runtime capability and
permission state first, then distinguish simulation from native observation** using capability indicators
in the tray/logs and actual event/frame/OCR output:

- **Verdict-path case (W1 blocking modal):** use shell simulation injection to trigger `CRIT-001` (payment
  text). PASS criterion: a **blocking modal** appears and choosing “Not now, pause task” does not allow the
  action. Record `PASS (sim)`, or `PASS (native)` when the native path produced the event.
- **Native-observation cases (W2 UIA tree / W3 GDI frame + steganography / W4 Windows.Media.Ocr screen
  reading / W5 overlay):** native UIA / GDI / OCR is wired into the shell, but it must be assessed from
  capability and actual output on the target Windows device. If capability is unavailable or a permission /
  language pack is missing, record `BLOCKED (specific reason)`. When available:
  - W3 requires an image containing steganography. Generate one with `make frame-digest-demo` or the
    guard-vision steganography encoder, display it in the target window, and verify that it is captured.
  - W4 requires an image with payment text that exists only in pixels. Generate or capture a bitmap saying
    "Complete purchase" in the same way and display it.
  - When a recognition language pack is missing, OCR does not run. The shell must provide a capability
    report **with a reason** (which is itself W6's PASS criterion).
- **W6 capability probe:** open the shell's capability panel/log and confirm the availability status plus a
  reason string for UIA / capture / OCR.
- **W7 native messaging:** same as F7, except the host is registered through the Windows registry.

---

## 4. Platform C: macOS Desktop Shell

```bash
cd apps/desktop-macos
npm install
npm run tauri dev
```

The macOS shell has AXUIElement, ScreenCaptureKit, and Vision OCR wired in. First grant and verify
Accessibility / Screen Recording permissions on the target device, then assess native-observation cases
from the capability report, real AX events, captured frames, and OCR output. If permission is not granted
or capability is unavailable, record `BLOCKED (specific reason)`. If only **simulated threat injection**
validates the verdict path, record `PASS (sim)`; it cannot replace `PASS (native)`. See the acceptance-case
table in `acceptance-macos.md`. Install the host with `install-host.sh --browser chrome <id>` (see the script
for the macOS path).

---

## 5. Record Results → Update the Dashboard

For each case:

1. **Fill the checklist table:** in the case row of the corresponding
   `docs/acceptance-{firefox,windows,macos}.md`, enter `PASS` / `PASS (sim)` / `FAIL` /
   `BLOCKED (reason)` in the Actual column, and put the relative evidence-file path in Evidence (for example,
   `/tmp/ag-evidence/firefox/F2-cancel.png`, or a repository-relative path after copying the file into the
   repository). The dashboard derives `X/N` progress from these two nonempty columns.

2. **Archive the evidence:** place screenshots / logs in the evidence directory and optionally export the
   evidence variables recognized by the gate:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=/tmp/ag-evidence/firefox
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS=/tmp/ag-evidence/windows
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=/tmp/ag-evidence/macos
   ```

3. **Recalculate the gate + dashboard:**
   ```bash
   make dashboard                        # Regenerate docs/status-dashboard.html from the completed tables
   bash scripts/release-gate.sh --strict # Strict mode turns an "unvalidated" item green only when its evidence variable is set
   ```

4. **Produce the report:** fill out `docs/acceptance-report-template.md` with PASS/FAIL/BLOCKED, evidence,
   notes, and environment information for every case, then return it with the evidence directory.

---

## 6. Quick Result Criteria (What Counts as PASS)

- **Pre-execution gates (F2/F3/F4):** the action is intercepted **before it occurs**, a confirmation layer
  appears, and “Not now” actually prevents the action (no navigation / no request / no handler side effect).
  A notification while the action proceeds normally is **FAIL**; that is post-action notification, not a
  pre-execution gate.
- **Network-layer hard block (F6):** the Network panel shows the target-host request as blocked, not 200.
- **Observation cases (F1 / W2, and so on):** the corresponding finding / event appears and the normal
  control content does **not** produce a false positive.
- Whenever the result cannot be determined or the environment is not connected, record `BLOCKED` with a
  reason. **Do not guess PASS.** The checklist is valuable precisely because it distinguishes “validated”
  from “it looks like it should work.”
