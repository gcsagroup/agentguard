[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# Real-Device Acceptance Runbook (for Automation Agents / computer-use)

This runbook turns the three acceptance checklists (`acceptance-firefox.md` / `acceptance-macos.md` /
`acceptance-windows.md`) from human-readable checklists into executable procedures and adds the Android
companion's signed-envelope real-device path. It gives the **preparation, exact action, observable criterion,
and evidence to capture** for every case, followed by **how to record results and produce structured evidence**.
The executor can be Codex, computer-use, or another agent capable of driving real browsers, desktops, and devices.

> The three `acceptance-*.md` files define browser, macOS, and Windows expectations. For Android, use section 5
> of this runbook together with the companion README.

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

Prepare an evidence work directory inside the repository. Keep it as local material outside the candidate
commit, redact sensitive data, and do not accidentally commit raw screenshots, account data, or device identifiers:

```bash
mkdir -p evidence/{firefox,windows,macos,android}
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

### A.3 Chrome / Edge: run the real-browser E2E first, then do C6–C8

The Chromium twins of F1–F5 have machine criteria: `make e2e-extension` loads the extension unpacked into a real
Chromium and asserts 20 things against the same fixture pages (payment click held before the handler runs, replayed
exactly once after "Allow once", page-issued fetch held before a byte reaches the server, read-only methods not gated,
popup without raw terms, …). It ends with `AGENTGUARD_E2E_EXTENSION=PASS` and writes `eval/e2e-extension/out/report.json`
plus two screenshots; copy those three files into `evidence/chrome/`. The Chrome twins of F6–F8 (C6–C8: native
messaging / DNR) are still done by hand on real Chrome/Edge per [acceptance-chrome.en.md](acceptance-chrome.en.md) — the
E2E installs no host. Firefox has no equivalent automation (Playwright cannot load Firefox extensions); F1–F8 stay manual.

---

## 3. Platform B: Windows Desktop Shell (W1–W10)

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

Use W1–W10 in `acceptance-windows.md` as the criteria. **For every case, record the runtime capability and
permission state first, then distinguish simulation from native observation** using capability indicators
in the tray/logs and actual event/frame/OCR output:

- **Verdict-path case (W1 blocking modal):** use shell simulation injection to trigger `CRIT-001` (payment
  text). PASS criterion: a **blocking modal** appears and choosing “Not now, pause task” does not allow the
  action. Record `PASS (sim)`, or `PASS (native)` when the native path produced the event.
- **Native-observation cases (W2 UIA tree / W3 GDI frame + steganography / W4 Windows.Media.Ocr screen
  reading / W5 overlay):** native UIA / GDI / OCR is wired into the shell, but it must be assessed from
  capability and actual output on the target Windows device. If capability is unavailable or a permission /
  language pack is missing, record `BLOCKED (specific reason)`. When available:
  - **Fixtures:** `make acceptance-fixtures` writes them to `eval/acceptance-fixtures/generated/` (deterministic;
    `MANIFEST.json` carries sha256s; `crates/guard-vision/tests/验收固件.rs` proves on every `cargo test` that these
    fixtures **do trigger** the rules they claim and that the control image yields zero findings; the HTML fixtures are
    additionally rendered in the container's Chromium and fed through the detectors).
  - W3: show `w3-stego-luma.png` (expect OVL-008) and `w3-stego-chroma.png` (expect OVL-011) full-screen; then show
    `w3-control-clean.png`, which must **not** fire — this step rules out "every image fires".
  - W4: open `w4-pixel-only-payment.html` in Edge/Chrome — the payment text is drawn only into canvas pixels and is absent
    from the UIA tree; once OCR reads it, expect OVL-009. Missing language pack → `BLOCKED (ocr language pack missing)`.
  - W5: open `w5-self-drawn-overlay.html` (the page draws its own 3 % opacity instruction text, which GDI captures;
    delete `#sub` in DevTools for the control) or show `w5-self-drawn-overlay.png` full-screen; expect OVL-006.
  - When a recognition language pack is missing, OCR does not run. The shell must provide a capability
    report **with a reason** (which is itself W6's PASS criterion).
- **W6 capability probe:** open the shell's capability panel/log and confirm the availability status plus a
  reason string for UIA / capture / OCR.
- **W7 native messaging:** same as F7, except the host is registered through the Windows registry
  (`native-host\install-host.ps1 <extension-id>` writes registry key + manifest + allowed-origin in one go).
- **W8–W10 trace check / no observation after end / state consistency:** launch the shell for the whole session with
  `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl` (the shell appends session_start/end,
  confirm_enqueued/shown/resolved/expired, every observation tick and every state change as JSONL); afterwards run
  `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <audit db>`. Six checks: session
  counts agree; every receipt lands on the record that was **shown** and approve/deny match (the shape of report P0-5);
  expired confirmations produce timeout receipts; no observation after session end; every “Protecting” state is backed by a
  heartbeat ≤10 s old; an expired confirmation never yields an approve receipt. Any FAIL exits 1 and fails W8.

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

Cases 15–17 are judged from the **acceptance trace**: launch the shell for the whole session with
`AGENTGUARD_ACCEPTANCE_TRACE=evidence/macos/trace.jsonl` (`AGENTGUARD_ACCEPTANCE_TRACE=… npm run tauri dev`); after
cases 1–14, 16 and 17 run `target/release/guard-cli acceptance-trace-check --trace evidence/macos/trace.jsonl --audit-db <audit db>`
and save the whole output as `evidence/macos/15-trace-check.txt`. It cross-checks the trace against the audit database
with six checks (see the Windows W8 note); only a printed `AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS` makes 15 PASS.
16 (no observation after end) and 17 (status light matches reality) additionally need screenshots and the tail of
`audit-report`. Pixel cases (overlay/steganography in 5/5b) may reuse the fixtures from `make acceptance-fixtures` — same
`guard-vision`.

---

## 5. Platform D: Android Companion

Follow the [Android companion README](../apps/android-companion/README.en.md) to build and install the candidate.
On a real device, enable notifications and the AccessibilityService, then connect to the desktop local API with
`adb reverse tcp:8788 tcp:8788`. Register the P-256 public key shown by the device in
`policies/adapter-registry.yaml`, restart the desktop API, and trigger at least one real accessibility event with
a clearly defined expected verdict.

PASS requires evidence that the event came from the target physical device, the desktop verified the signed HTTP
body envelope with the registered public key, the engine returned the expected verdict, and the device received
the corresponding risk result. A debug build, JVM unit test, relay with an unregistered key, or offline-only JSON
replay does not replace this real-device E2E. Record `BLOCKED (specific reason)` if any link cannot be determined.

**Follow the script:** `scripts/acceptance/android-e2e.sh` (needs adb + an authorized real device + python3) turns the
paragraph above into machine criteria — it installs the APK, grants the notification permission, enables the
accessibility service, sets up `adb reverse`, starts the desktop API with a one-off token, writes the P-256 public key you
paste from the app into `evidence/android/adapter-registry.yaml`, opens the payment fixture page in the phone browser and
then checks: A1 (install / permissions / foreground notification id 1001), A2 (desktop `/v1/status`
`adapter_ingress.verified` increases and `rejected` does not — `/v1/events` now writes each body's signature outcome into
the response, the status snapshot and stderr; previously A2 had no readable desktop-side evidence at all), A3 (a
`platform=android` `CRIT-*` verdict appears in the audit), A4 (the device's `last_risk_json` carries the same rule_id and the
engine notification id 1005 is present), L (after `am crash` the process returns, `session_active` stays true, the
foreground notification is restored, accessibility stays enabled — report P0-3), S (no plaintext `relay_token` in prefs,
`relay_token_enc` present; `files/events` ≤ 50 MiB — report P1-6). Every step prints PASS / FAIL / BLOCKED(reason),
evidence lands in `evidence/android/`, and the last line is `AGENTGUARD_ANDROID_E2E=PASS|FAIL|BLOCKED device=real|emulator` —
`device=emulator` can only ever be recorded as `PASS (sim)`. Only three things need a human: pasting the public key,
entering URL + token in the app and enabling forwarding, tapping "Start guard session" (private key and token live in the
Keystore; adb cannot reach them by design). The script's verdicts still have to be transcribed into the report template —
`manual-acceptance android` reads only that report.

---

## 6. Record Results → Produce Structured Evidence

For each case:

1. **Complete a separate report:** copy `docs/acceptance-report-template.en.md` to the corresponding
   `evidence/<platform>/report.md`. Record `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (reason)` and a
   repository-relative evidence path for every case. As a strict-gate artifact, Firefox F1–F8, Windows W1–W10,
   Android A1–A4, and macOS 1, 2, 3, 4, 5, 5b, 5c, and 6–17 must each appear exactly once. Column two must be
   exactly `PASS (native)`, and column three must identify an existing repository-relative nonempty regular file under the
   matching `evidence/<platform>/` directory. Every case must use a unique evidence path. It cannot reference the report
   itself or the current evidence JSON source file, contain a symbolic-link path, or resolve outside the repository.
   Paths use only `/`; every component must match portable ASCII `[A-Za-z0-9._-]+` and contain no whitespace or shell
   glob/expansion character. `PASS (sim)`, FAIL, BLOCKED, N/A, missing or duplicate cases, reused paths, and missing
   referenced files are not real-device PASS.

2. **Freeze the candidate commit:** if the status dashboard needs to show progress, first update the checklists,
   run `make dashboard`, commit those changes, and then rerun acceptance from the new `HEAD`. Before opening the
   gate, the index and every non-ignored file must be clean. Do not change code or version-controlled documentation
   while it runs. Any `HEAD` or non-ignored drift still present at the end makes the start/end snapshots differ and
   fails the run; these snapshots do not defend against a concurrent adversary that makes and then restores a
   transient change. The ignored `evidence/` workspace may continue to receive evidence files.

3. **Generate and complete the JSON:** the template is deliberately invalid until filled. Replace `command`,
   `timestamp`, `output`, `exit_code`, and the acceptance-closure SHA-256 with measured values. The top-level `signer` for
   acceptance evidence must remain `null`; do not pass `--expected-signer` during verification. At verification time,
   `timestamp` must be between 30 days in the past and 10 minutes in the future and must not predate the HEAD
   commit time, with a 10-minute clock-skew allowance. `command` must be the successfully executed single segment
   `guard-cli manual-acceptance <platform> <checklist> <artifact.path> --repo-root .` (after the build below, the actual command is
   `target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root .`). Both the report body
   and the JSON `output` must contain an entire line equal to the exact
   `AGENTGUARD_ACCEPTANCE_FIREFOX=PASS`, `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`,
   `AGENTGUARD_ACCEPTANCE_MACOS=PASS`, or `AGENTGUARD_ACCEPTANCE_ANDROID=PASS` marker, and only after every
   required native case passes. Acceptance artifacts are limited to regular `.md` files under the corresponding
   `evidence/<platform>/` directory. `artifact.sha256` uses `agentguard-acceptance-closure-sha256-v1` and binds the
   report bytes plus every unique per-case reference's relative path, length, and content in path order. It remains
   unsigned self-attestation and cannot prove that a screenshot or log came from the claimed device.
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md \
     evidence/firefox/report.md --repo-root .
   # Sole success output: AGENTGUARD_ACCEPTANCE_FIREFOX=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/firefox/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_firefox --commit "$commit" > evidence/firefox/evidence.json

   # Put the exact manual-acceptance command, marker, and closure digest above into JSON, then verify
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_firefox --file evidence/firefox/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **Pass the JSON to the strict gate.** The environment variable points to the JSON file, not a directory:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=evidence/firefox/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   Repeat for Windows, macOS, and Android with the corresponding kind, directory, and environment variable. See
   [Structured Release Evidence](release-evidence.en.md) for every field and all eight variables. A directory,
   untouched template, old-commit report, or arbitrary keyword-bearing file is rejected.
   After the strict gate passes, archive the local evidence read-only in a controlled location. Do not push raw
   evidence containing sensitive information to GitHub by default.

---

## 7. Quick Result Criteria (What Counts as PASS)

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
