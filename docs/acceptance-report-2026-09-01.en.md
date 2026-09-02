[简体中文](acceptance-report-2026-09-01.md) | [繁體中文](acceptance-report-2026-09-01.zh-TW.md) | [English](acceptance-report-2026-09-01.en.md)

# AgentGuard Real-Device Acceptance Report (2026-09-01)

> Conclusion: automation, packaging, and a limited macOS native smoke test advanced the current integration candidate, but release-grade browser, Windows, macOS, and Android end-to-end acceptance has not been completed against one immutable commit. Production release remains **No-Go**.

This report follows the [real-device acceptance runbook](acceptance-runbook.en.md) and the [report template](acceptance-report-template.en.md). Every unexecuted or insufficiently evidenced case is recorded as `BLOCKED`; no result is guessed as PASS.

## 1. Source and Evidence Boundary

This report distinguishes two evidence layers that must not be combined:

1. **2026-08-31 real-device / cross-platform baseline:** exact commit `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`, documented in `/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`. It contains the Windows 11, macOS, Android-emulator, temporary iOS-harness, and limited Chromium results collected for that commit.
2. **2026-09-01 current integration candidate:** first-parent release baseline `a7956314fba8340e905353448a53bb1f24f7083c`, merged feature baseline `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`, plus the fixes, D branding, and trilingual documentation recorded here. Its immutable identity is the `main` commit that contains this report.

The `bd7bb2f` real-device results are therefore historical baseline evidence only. They **do not transfer as PASS results** to the current integration candidate. The current run's console output was not archived in a standalone evidence bundle; its command results are integration-verification records, not independently reproducible release evidence.

## 2. Environment

| Item | Value |
|---|---|
| Execution date | 2026-09-01 (Asia/Shanghai) |
| Executor | Codex automation; Browser and Computer Use assisted local flow and macOS smoke checks |
| Current host | macOS 26.6.2 (Build 25G83), Apple Silicon arm64 |
| 2026-08-31 baseline | `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` |
| Current integration candidate | First parent `a7956314fba8340e905353448a53bb1f24f7083c` + feature baseline `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` + the integration recorded here; final identity is the `main` commit containing this report |
| Rust | `rustc 1.97.1`, `cargo 1.97.1` (`rustup stable`) |
| Node / npm | Node `v25.2.1`, npm `11.6.2` |
| Browsers present | Chrome `152.0.7977.65`, Firefox `153.0.1`; Edge not installed |
| All offline gates green | **No, in release terms:** 13/13 automated soft-gate checks passed and offline acceptance was 104/104, but 8 evidence / real-device checks remain unverified and the strict release gate is not satisfied |
| Toolchain note | The default Homebrew Rust 1.91.1 failed because of an LLVM dynamic-library mismatch; the same validation passed with `rustup stable`. This is recorded as an environment issue, not a product PASS or FAIL. |

## 3. Current-Candidate Automation, Build, and Packaging Results

| Scope | Command / operation | Result | Evidence level and boundary |
|---|---|---|---|
| Release soft gate | `bash scripts/release-gate.sh` | 13/13 automated checks passed, 0 failed, 8 unverified | Current console result; soft mode is not strict release approval |
| Offline acceptance | `make acceptance` | 104/104 | Offline scenarios only; not platform E2E |
| Extension gate | `node apps/extension-chromium/scripts/gate.test.mjs` | 20/20 | Pure logic and source invariants; no installed browser extension |
| click→submit wiring | `node apps/extension-chromium/scripts/content-event.test.mjs` | 2/2 | Minimal DOM event chain proves one approval prompts/submits once and does not leak; not real-browser E2E |
| Cross-browser manifests | `node apps/extension-chromium/scripts/manifests.test.mjs` | 8/8 | Structural consistency only; does not prove Firefox or Chrome runtime behavior |
| Extension localization | `node apps/extension-chromium/scripts/strings.test.mjs` | 8/8 | Three-language dictionary completeness; not real-browser UI evidence |
| macOS adapter | `rustup run stable cargo test -p mac-adapter` | 10/10 | Coalescer and bridge-structure automation |
| macOS Tauri | `rustup run stable cargo test --manifest-path apps/desktop-macos/src-tauri/Cargo.toml` | 7/7 | Packaging, product wiring, and legacy plaintext audit-store migration tests; not third-party-app E2E |
| Windows Tauri | `rustup run stable cargo test --manifest-path apps/desktop-windows/src-tauri/Cargo.toml --no-run` | Compiled successfully | no-run compilation on macOS; no Windows executable was launched |
| macOS release build | `apps/desktop-macos/scripts/build-release.sh` | Build succeeded; `codesign --verify --deep --strict` passed | Ad-hoc only: `TeamIdentifier=not set`; `spctl` rejected it; not notarized or distributable |
| Coverage matrix | Current generated `eval/coverage-matrix.md` | 30 surfaces: 13 covered, 16 partial, 1 uncovered; 107 claimed attack scenarios plus 35 benign controls | Repository-generated coverage evidence; it does not replace device acceptance |

### 3.1 Extension Artifact Recheck

The first package review found stale generated ZIPs: the Firefox archive still used `background.service_worker`, and the archived `background.js` / `content.js` hashes differed from the working tree. Those artifacts were not accepted.

After the packaging script was fixed to replace outputs atomically, the delivery archives were rebuilt and rechecked at 16:39 (Asia/Shanghai):

| Artifact | SHA-256 | Recheck |
|---|---|---|
| `/Users/lazy/Projects/agent-guard/_push/agentguard-extension.zip` | `443e141834de89587fc0daf7a5470e2edee8a15b6e18c9d3db2368396dea2f51` | 27 files including the D icon assets; `unzip -t` passed; archived `background.js` and `content.js` match the current source |
| `/Users/lazy/Projects/agent-guard/_push/agentguard-extension-firefox.zip` | `f9309f118ad0c22d0d86b2e4c657141f93a505fcdbdfc032756d215c1c934bb6` | 27 files including the D icon assets; `unzip -t` passed; files match current source; manifest version `1.0.0.1` sets `background.scripts = ["background.js"]` and `background.type = "module"` |

This proves delivery-package consistency only. Neither archive was installed and exercised for F1–F8 in this run.

### 3.2 macOS Artifact and Limited Native Smoke

- Current local executable SHA-256: `30425194afe8d4679b74d95e8b1fd2459e3d0f04e050cbe62b037de8fb5cbb11`.
- App D-icon SHA-256: `9a7732ab9cc79ff50341b5d205f1b03755698315d07f75b9713847780a598a10`.
- Signing state: `Signature=adhoc`, `TeamIdentifier=not set`; strict `codesign` verification passed, while Gatekeeper `spctl` assessment rejected the app.
- The launch path retained an existing plaintext audit database and selected a sibling SQLCipher database, avoiding the previous encrypted-open startup crash without overwriting the legacy file.
- On the physical Mac, the current ad-hoc app was launched through Computer Use. The UI reported Accessibility `true` and Capture `true`; AX push was enabled and reported `live AX ingested · 1 decision`. Observation was then disabled and the guard session ended.

That last sequence is a **limited native startup/capability/ingestion smoke test**. It has no standalone console/screenshot archive, does not identify which checklist scenario produced the decision, and does not establish timing, SCK/OCR output, pre-side-effect blocking, or audit closure. It is therefore recorded as supplemental evidence, not as a checklist PASS or release evidence.

## 4. Browser Extension (Chrome / Firefox / Edge)

The current archives were not installed with their Native Messaging host during this run. No current-candidate DevTools Network capture, popup finding, signed audit row, or DNR dynamic-rule evidence was archived. Edge is not installed.

| Case | Chrome 152 | Firefox 153 | Edge | Evidence and notes |
|---|---|---|---|---|
| F1 Hidden injection | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | Scanner logic has automated coverage; no finding was observed in an installed-extension popup |
| F2 Pre-execution payment CTA gate | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | Gate tests passed; the real cancel/allow side-effect timeline was not rerun |
| F3 Trap + PII submission gate | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | `requestSubmit` and one-shot approval have a simulated DOM event-chain test; real URL/submission behavior was not rerun |
| F4 Payment-shaped fetch gate | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | Classification logic is tested; no real Network evidence shows zero request after denial |
| F5 Read-only methods are not gated | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | GET/HEAD and ordinary-POST controls are tested; no browser Network evidence |
| F6 Malicious-domain network hard block | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (edge-not-installed)` | DNR construction, block list, and provenance are tested; no `ERR_BLOCKED_BY_CLIENT` capture |
| F7 Native-messaging handshake | `BLOCKED (native-host-not-installed)` | `BLOCKED (gecko-id-not-tested)` | `BLOCKED (edge-not-installed)` | No current host installation or signed audit row |
| F8 DNR quota | `BLOCKED (quota-not-measured)` | `BLOCKED (firefox-quota-not-measured)` | `BLOCKED (edge-not-installed)` | Pure logic bounds the list; actual browser quota was not measured |

The Firefox `background.scripts` correction passed the 8/8 manifest checks and is present in the rebuilt delivery ZIP, but the Firefox event page has not yet been started on real Firefox.

## 5. Windows Desktop Shell

The `bd7bb2f` baseline crashed on real Windows 11 Pro build 26200 before the main window appeared because of `RPC_E_CHANGED_MODE`, and the same baseline exposed Windows verbatim-path defects. The current candidate completed only a Tauri no-run compile and was not transferred back to a Windows device. The old failure cannot prove that the current candidate still fails, but it equally cannot be treated as fixed.

| Case | Current-candidate result | Evidence | Notes |
|---|---|---|---|
| W1 Blocking modal | `BLOCKED (current-candidate-not-run-on-Windows)` | 2026-08-31 outer report covers `bd7bb2f` only | Current candidate never displayed a Windows main window |
| W2 UIA tree capture | `BLOCKED (no-current-UIA-evidence)` | Same historical report only | no-run compilation produces no `UiTreeDelta` |
| W3 GDI frame capture + steganography | `BLOCKED (no-current-GDI-evidence)` | Same historical report only | No current frame or rule-hit evidence |
| W4 Windows.Media.Ocr screen reading | `BLOCKED (no-current-OCR-evidence)` | Same historical report only | No current language-pack, capability, or recognition output |
| W5 Overlay | `BLOCKED (no-current-overlay-evidence)` | Same historical report only | No target window was exercised |
| W6 Capability probe | `BLOCKED (no-current-capability-report)` | Same historical report only | No current UIA/GDI/OCR availability and reason strings |
| W7 Native messaging | `BLOCKED (native-host-not-tested-on-Windows)` | Same historical report only | No registry manifest, host handshake, or signed audit row |

## 6. macOS Desktop Shell

The current candidate passed mac-adapter 10/10, Tauri 7/7, the ad-hoc release build, and the limited native smoke described in section 3.2. AXObserver is wired into product start/stop and the 50ms driver path. However, the run did not archive per-case screenshots/logs, exercise the full set of real third-party-app events, capture SCK/OCR evidence, or close and verify a signed audit trail. The following checklist therefore does not inherit simulated results from the `bd7bb2f` baseline and does not convert the one-decision smoke into a scenario PASS.

| Case | Current-candidate result | Evidence | Notes |
|---|---|---|---|
| 1 Payment confirmation | `BLOCKED (current-native-E2E-not-run)` | `bd7bb2f` baseline has simulation only | No proof that a real-page event is controlled before its side effect |
| 2 Transfer confirmation | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No real transfer text triggered |
| 3 Optional PII | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No identified FM/TR event |
| 4 Trap form | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No identified trap event |
| 5 Transparent overlay | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No AX/SCK overlay comparison |
| 5b Rounded invisible zone | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | `[AG_INVISIBLE_ZONE]` was not exercised |
| 5c Pre-execution UI change | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No retained two-frame / two-AX-change evidence |
| 6 Intelligence injection | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No real third-party-app injection text |
| 7 Malicious domain | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No real navigation chain |
| 8 Netmon exfiltration | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No current netmon flow |
| 9 Browser malicious URL | `BLOCKED (extension-host-not-installed)` | No current standalone archive | Chrome extension and desktop ingest were not integrated live |
| 10 Session pause | `BLOCKED (current-session-E2E-not-run)` | `bd7bb2f` simulation produced a historical short chain | Current deny → next event → session isolation was not retested |
| 11 SCK probe | `BLOCKED (case-evidence-not-archived)` | UI reported Capture `true` in the limited smoke | No retained `sck-probe`, captured-frame, or OCR output |
| 12 AX probe | `BLOCKED (case-evidence-not-archived)` | UI reported Accessibility `true` in the limited smoke | No retained standalone probe output |
| 13 Native AX | `BLOCKED (insufficient-case-evidence)` | Limited smoke reported AX push on and one ingested decision | Wiring is alive, but event identity, expected FM/TR verdict, latency, and foreground switching were not evidenced |
| 14 UI revalidation | `BLOCKED (current-native-E2E-not-run)` | No current standalone archive | No real consecutive UI change and confirmation result |

## 7. Supplemental Android and iOS Status

The source template does not include detailed Android or iOS tables, so this report records their release boundaries separately.

| Platform | 2026-08-31 baseline | Current integration candidate | Conclusion |
|---|---|---|---|
| Android | `bd7bb2f` completed Debug/Release JVM 31/31, Debug APK installation, and foreground-service start/stop on an Android 16 emulator; Accessibility was disabled, so this was not protection E2E | No physical-device or emulator rerun for the current candidate | `BLOCKED (current-Android-E2E-and-release-signing-missing)` |
| iOS | `bd7bb2f` had only a temporary SwiftUI harness 1/1; the repository did not contain a complete Xcode product project | No current-candidate iOS product or archive was produced | **No-Go**; a temporary harness is not a product |

## 8. Latest Fixes That Still Require Full Real-Device Retesting

| Item | Current source correction | Current verification | Missing evidence |
|---|---|---|---|
| Firefox background entry point | Replaced Chromium `service_worker` semantics with a Firefox `background.scripts` event page | Manifest 8/8; rebuilt Firefox delivery archive matches current source | Real Firefox startup, event-page lifecycle, and F1–F8 |
| Block-list provenance | Pruning, persistence, removal, and popup reads retain the originating `rule_id` | Gate 20/20 | Real DNR installation, worker recovery, and popup provenance |
| Allow-once form replay | Uses `requestSubmit(e.submitter)` to retain validation, `formaction`, `formmethod`, name, and value; click→submit shares one approval token | Gate 20/20 source invariant + content-event 2/2 event chain | Real Chrome/Firefox cancel, allow, and one-shot replay |
| macOS AXObserver product wiring | Desktop starts, drives, coalesces, and stops the observer through the product path | mac-adapter 10/10, Tauri 7/7, release build, plus limited one-decision native smoke | Archived real callback identity, 150ms/800ms timing, foreground switching, full scenario verdicts, and session-end proof |

These are material corrections relative to the 2026-08-31 baseline. Source changes, automated tests, package identity, and a limited smoke test still do not constitute full platform acceptance.

One **unresolved security boundary** also remains: the `window.postMessage` decision/scope channel between MAIN world
and the isolated world is page-observable and forgeable, and the delivered `scope_hosts` list is visible to the page.
E2.1/E9 are therefore best-effort interlocks for cooperative pages, not enforcement against a hostile page. Before
release, the channel must be authenticated without exposing the full list, or the corresponding product claims narrowed.

## 9. Summary

| Surface | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| Browser (Chrome + Firefox + Edge, F1–F8) | 0 | 0 | 0 | 24 | 0 |
| Windows (W1–W7) | 0 | 0 | 0 | 7 | 0 |
| macOS (16 checklist rows) | 0 | 0 | 0 | 16 | 0 |
| Android current-candidate platform gate | 0 | 0 | 0 | 1 | 0 |

This table counts only the **current uncommitted integration candidate's** real-device checklist. Automated passes are reported separately in section 3; historical `bd7bb2f` PASS/FAIL results are not included.

**Overall conclusion: automation and local integration may continue, but production release remains No-Go.**

### Why the Current Candidate Has No Recorded FAIL Cases

No current-candidate real-device case is marked FAIL because the cases were not executed to a conclusive, independently evidenced state; the runbook therefore requires `BLOCKED`. This is not an all-platform pass. The `bd7bb2f` Windows startup failure remains in the historical report and can be closed or reconfirmed only by retesting the final candidate.

### Eight Strict Release Checks Remain Unverified

1. macOS Developer ID signing;
2. macOS notarization and staple;
3. Windows Authenticode signing;
4. Android release signing with a non-debug key;
5. macOS full real-device end-to-end acceptance;
6. Android physical-device end-to-end acceptance with Accessibility enabled;
7. Firefox 128+ F1–F8 real-device acceptance;
8. Windows W1–W7 real-device acceptance.

In addition, the current-candidate Chrome and Edge extension flows, Native Host installation/removal, store-package identity, and upgrade/rollback behavior lack release evidence.

## 10. Retest Conditions Before Release Reassessment

1. Commit the integration candidate as an immutable SHA, leave the worktree clean, rebuild the macOS app and both extension archives from that SHA, and bind artifact hashes to it.
2. Archive every automation command, exit code, toolchain identity, and artifact hash; have the strict gate consume structured evidence bound to the current commit.
3. Install the final packages and Native Host on real Chrome, Firefox, and Edge; execute F1–F8 and archive popup, Network, DNR, and signed-audit evidence.
4. Build and launch the final commit on real Windows with the standard toolchain; complete W1–W7, signed installer, upgrade, and uninstall checks.
5. On macOS, grant the final app Accessibility and Screen Recording, execute cases 1–14, measure AXObserver timing, retain SCK/OCR and session-end evidence, and verify the signed audit; then complete Developer ID signing, notarization, and staple.
6. On a physical Android device, enable AgentGuard AccessibilityService and complete observation → verdict → human confirmation → signed envelope/audit, including release signing, permission revocation, upgrade, and uninstall checks.

Only evidence bound to the same final commit and corresponding release artifacts can support a new Go/No-Go decision.

## 11. Evidence Index

- 2026-08-31 cross-platform baseline report: `/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`
- Run instructions: [real-device acceptance runbook](acceptance-runbook.en.md)
- Report structure: [real-device acceptance report template](acceptance-report-template.en.md)
- Repository status snapshot: [status dashboard](status-dashboard.html) (regenerate after the final commit)
- Current macOS ad-hoc app: `apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app`
- Rebuilt Chrome delivery ZIP: `/Users/lazy/Projects/agent-guard/_push/agentguard-extension.zip`
- Rebuilt Firefox delivery ZIP: `/Users/lazy/Projects/agent-guard/_push/agentguard-extension-firefox.zip`

> This report records a pre-commit acceptance state. It does not independently constitute release evidence; signing, notarization/store review, artifact identity, strict-gate evidence, and platform coverage must be verified separately.
