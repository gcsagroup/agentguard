[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# Real-Device Acceptance Runbook (for Automation Agents / computer-use)

This runbook turns the Chrome / Edge, macOS, Windows, and iOS acceptance checklists from human-readable checklists into executable procedures and adds the Android
companion's signed-envelope real-device path. It gives the **preparation, exact action, observable criterion,
and evidence to capture** for every case, followed by **how to record results and produce structured evidence**.
The executor can be Codex, computer-use, or another agent capable of driving real browsers, desktops, and devices.

> Browser expectations come from `acceptance-chrome.en.md`; `acceptance-firefox.en.md` is only a first-GA exclusion notice. Use the platform-specific lists for macOS and Windows, section 5 plus the companion README for Android, and section 6 plus `acceptance-ios.en.md` for iOS.

---

## 0. Scope and Honest Preconditions (Read First)

- **First-GA browser scope is only the Chromium package shared by Chrome and Edge.** The repository provides fixtures and 39 Chromium E2E assertions; release Chrome and Edge still require separate manual evidence bound to the candidate ZIP. Firefox is source-only prototype material and cannot receive a release PASS.
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
# Toolchain: repository-pinned Rust 1.95.0 and Node >= 18. The wrapper prevents a Homebrew rustc child.
make bootstrap-rust
./scripts/bootstrap-rust.sh -- cargo -Vv
./scripts/bootstrap-rust.sh -- rustc -vV
node --version

# 1) Package the first-GA browser extension (shared by Chrome / Edge; no Native Messaging)
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip

# 2) Offline gates (must all be green first; necessary but not sufficient for real-device acceptance)
./scripts/bootstrap-rust.sh -- make capability-claims check-extension-gate coverage

# 3) Scope guard: must exit 64 and create no Firefox package
apps/extension-chromium/scripts/package-store.sh --firefox
```

Start the test-fixture server (fetch cases require same-origin path resolution and cannot use file://):

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# Fixture index: http://localhost:8000/
```

Prepare an evidence work directory inside the repository. Keep it as local material outside the candidate
commit, redact sensitive data, and do not accidentally commit raw screenshots, account data, or device identifiers:

```bash
mkdir -p evidence/{chrome,edge,windows,macos,android,ios,ios-testflight}
```

---

## 2. Platform A: Browser Extension (First GA: Chrome / Edge)

### A.1 Automation

Run `make e2e-extension` first. It executes 39 machine assertions in a test Chromium, covering block-only DOM behavior, open Shadow DOM, static-DNR positive and negative cases, legacy page messages, upgrade cleanup, mutation storms, and the popup. Preserve `eval/e2e-extension/out/report.json` and its actual Chromium version.

### A.2 Release Chrome / Edge

1. Compute the store-candidate ZIP SHA-256; Chrome and Edge must use the same file.
2. Load its unpacked content in clean Chrome and Edge profiles. Do not install a Native host; the GA manifest has no such permission.
3. Restart the browser, confirm isolated scripts load in new tabs, `payment_shape_block` is enabled, and no Native control appears in the popup.
4. Execute B1–B5 in [the Chromium checklist](acceptance-chrome.en.md), covering clean install, representative blocks and negative controls, in-place upgrade, disable/uninstall, and rollback. Store Chrome evidence in `evidence/chrome/` and Edge evidence in `evidence/edge/`; do not reuse evidence between them.
5. Decide Chrome and Edge separately. An indeterminate row is `BLOCKED`; test-Chromium PASS cannot replace it.

### A.3 Firefox

Firefox is outside the first GA. Do not load `manifest.firefox.json`, install a Firefox Native host, or create a Firefox PASS. `package-store.sh --firefox` must exit 64 and create no package; see the [Firefox exclusion notice](acceptance-firefox.en.md).

---

## 3. Platform B: Windows Desktop Shell (first-ga-v1)

### B.1 Build and Run

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # Start the tray shell (dev)
```

The first-GA browser package does not install Native Messaging. Windows `first-ga-v1` requires W1–W6/W8–W11; W7 is a non-GA/legacy prototype row excluded from the gate and must not be made to pass by adding permission back to the GA package.

### B.2 Execute Each Case

Use the required `first-ga-v1` cases in `acceptance-windows.en.md` as the criteria, and include the exact report line
`AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`. **For every case, record the runtime capability and
permission state first, then distinguish simulation from native observation** using capability indicators
in the tray/logs and actual event/frame/OCR output:

- **Verdict-path case (W1 post-observation risk confirmation):** use shell simulation injection to trigger
  `CRIT-001` (payment text). PASS criterion: a **post-observation risk confirmation** appears and clearly
  states that the external action was already observed and cannot be reversed. Choosing “Not now, pause task”
  pauses this session and future observation only. Audit evidence must record `effect=observed_only` and
  `external_action_blocked=false`; it must not claim that the original action was prevented. Record
  `PASS (sim)`, or `PASS (native)` when the native path produced the event.
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
- **W7 native messaging:** retain only as a non-GA/legacy optional record, preferably `N/A (non-GA)`. The structured gate neither requires nor counts it and does not bind its evidence.
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
table in `acceptance-macos.md`. The first-GA Chromium package does not install a Native host.

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
then checks: A1 (install / permissions / ordinary ongoing session notification id 1001), A2 (desktop `/v1/status`
`adapter_ingress.verified` increases and `rejected` does not — `/v1/events` now writes each body's signature outcome into
the response, the status snapshot and stderr; previously A2 had no readable desktop-side evidence at all), A3 (a
`platform=android` `CRIT-*` verdict appears in the audit), A4 (the device's `last_risk_json` carries the same rule_id and the
engine notification id 1005 is present), L (after `am crash` and an explicit app relaunch, the process returns,
`session_requested` is false, the old session notification is not restored, accessibility stays enabled, and the user
must explicitly start a new session — report P0-3), S (no plaintext `relay_token` in prefs,
`relay_token_enc` present; `files/events` ≤ 50 MiB — report P1-6), T (targetSdk 36 behaviour regression — report P2-2:
the installed APK's targetSdk is read from the device's `dumpsys package`; PASS only on a device running API 35+ with A1–A4
and L all passing; a device below API 35 can only be BLOCKED — a pass on Android 14 must not impersonate one on 15/16).
Every step prints PASS / FAIL / BLOCKED(reason),
evidence lands in `evidence/android/`, and the last line is `AGENTGUARD_ANDROID_E2E=PASS|FAIL|BLOCKED device=real|emulator` —
`device=emulator` can only ever be recorded as `PASS (sim)`. Only three things need a human: pasting the public key,
entering URL + token in the app and enabling forwarding, tapping "Start guard session" (private key and token live in the
Keystore; adb cannot reach them by design). The script's verdicts still have to be transcribed into the report template —
`manual-acceptance android` reads only that report.

---

## 6. Platform E: iOS Safari WebShield

Create a Release archive from the same frozen commit and sign the app plus its embedded Safari Web Extension with Apple Distribution. Produce separate `ios_codesign` evidence for that signed artifact. Then follow [iOS real-device and TestFlight acceptance](acceptance-ios.en.md): complete I1–I6 on physical iPhone/iPad devices and upload that same archive to TestFlight for TF1–TF3. An unsigned device build, Simulator, Xcode Analyze, or Swift/Node tests are development evidence only and cannot replace any strict gate.

Keep the I1–I6 report and per-case files only under `evidence/ios/`, and TF1–TF3 only under `evidence/ios-testflight/`; do not reuse either report's case evidence for the other. If signing, App Group/Keychain entitlements, physical-device Safari enablement, website permission, upgrade, or TestFlight identity cannot be verified, record `BLOCKED (specific reason)` and do not produce a PASS marker.

---

## 7. Record Results → Produce Structured Evidence

For each case:

1. **Complete a separate report:** copy `docs/acceptance-report-template.en.md` to the corresponding
   `evidence/<platform>/report.md`. Record `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (reason)` and a
   repository-relative evidence path for every case. As a strict-gate artifact, Windows `first-ga-v1` W1–W6/W8–W11,
   Android A1–A4, macOS 1, 2, 3, 4, 5, 5b, 5c, and 6–18, iOS I1–I6, TestFlight TF1–TF3, and B1–B5 separately for
   Chrome and Edge must each appear exactly once. Column two must be
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
   `guard-cli manual-acceptance <platform> <checklist> <artifact.path> --repo-root .`. Both the report body
   and the JSON `output` must contain an entire line equal to the exact
   marker for the matching kind: `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`, `AGENTGUARD_ACCEPTANCE_MACOS=PASS`,
   `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`, `AGENTGUARD_ACCEPTANCE_IOS=PASS`,
   `AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS`, `AGENTGUARD_ACCEPTANCE_CHROME=PASS`, or
   `AGENTGUARD_ACCEPTANCE_EDGE=PASS`, and only after every required native case for that kind passes. Acceptance artifacts are limited to regular `.md` files under the corresponding
   `evidence/<platform>/` directory. `artifact.sha256` uses `agentguard-acceptance-closure-sha256-v1` and binds the
   report bytes plus every unique per-case reference's relative path, length, and content in path order. It remains
   unsigned self-attestation and cannot prove that a screenshot or log came from the claimed device.
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
     evidence/macos/report.md --repo-root .
   # Sole success output: AGENTGUARD_ACCEPTANCE_MACOS=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/macos/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_macos --commit "$commit" > evidence/macos/evidence.json

   # Put the exact manual-acceptance command, marker, and closure digest above into JSON, then verify
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_macos --file evidence/macos/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **Pass the JSON to the strict gate.** The environment variable points to the JSON file, not a directory:
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=evidence/macos/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   Repeat for every other platform with its corresponding kind, directory, and environment variable; Chrome and Edge, and iOS and TestFlight, remain independent. The legacy Firefox kind is not read by the strict gate. See
   [Structured Release Evidence](release-evidence.en.md) for every field and all twelve variables. A directory,
   untouched template, old-commit report, or arbitrary keyword-bearing file is rejected.
   After the strict gate passes, archive the local evidence read-only in a controlled location. Do not push raw
   evidence containing sensitive information to GitHub by default.

---

## 8. Quick Result Criteria (What Counts as PASS)

- **Browser DOM block (B3):** the action is stopped **before it occurs**. The information notice has only Close, and closing it still causes no navigation, request, or handler side effect. Any in-page release or replay is **FAIL**.
- **Network-layer hard block (F6):** the Network panel shows the target-host request as blocked, not 200.
- **Observation cases (F1 / W2, and so on):** the corresponding finding / event appears and the normal
  control content does **not** produce a false positive.
- Whenever the result cannot be determined or the environment is not connected, record `BLOCKED` with a
  reason. **Do not guess PASS.** The checklist is valuable precisely because it distinguishes “validated”
  from “it looks like it should work.”
