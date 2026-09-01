[简体中文](acceptance-report-windows-2026-09-02.md) | [繁體中文](acceptance-report-windows-2026-09-02.zh-TW.md) | [English](acceptance-report-windows-2026-09-02.en.md)

# AgentGuard Windows Real-Device Supplemental Acceptance Report (2026-09-02)

> Conclusion: final candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0` passed automation, the Release build, startup, idle operation, two observation rounds, and real blocking-modal smoke checks in a Windows 11 environment. No new application-crash event was recorded during the final test. However, the complete W1–W7 release scenarios, Authenticode signing, and install / upgrade / uninstall validation remain incomplete. Production release remains **No-Go**.

This is the Windows supplement to the [2026-09-01 overall acceptance report](acceptance-report-2026-09-01.en.md). It follows the [Windows real-device checklist](acceptance-windows.en.md), [real-device acceptance runbook](acceptance-runbook.en.md), and [report template](acceptance-report-template.en.md). It is not a strict artifact under `evidence/windows/`; a case without its own evidence file is not guessed as `PASS (native)`.

## 1. Candidate and Evidence Boundary

Four code identities were retested in sequence. Their results do not transfer between candidates:

| Candidate | Result | Boundary |
|---|---|---|
| `e9648eb86a8e82d83cd3c144de874565712e2c5f` | Automation and the Release build passed; interactive startup failed with exit code 101 before the main window appeared, and stderr reported `OleInitialize failed! Result was: RPC_E_CHANGED_MODE` | Proves a main-thread COM apartment conflict in the old candidate; green automation did not prove that the desktop executable could start |
| `f9bcecd` | The executable progressed after the COM startup conflict was removed, then failed with `0xC0000005`; Windows Event 1000 RVA `0x4b4a7c` symbolized to the `OcrEngine TryCreate` / `FactoryCache` path | This candidate failed and does not transfer a PASS to the final candidate |
| `ea9cb1a` | Idle startup was stable; `0xC0000005` recurred on frame 8 of the first observation round | Proves that idle survival alone was insufficient to close the OCR / observation-chain crash |
| `89dadf960a558d35dc3c6c557eadbc19d3a162d0` | Automation, Clippy, the Release build, interactive startup, and two observation-round smoke checks completed; the run added zero Event 1000 records | Final code candidate for this report; sections 6 and 7 retain the release boundary |

The 5/5 gate test on `e9648eb` covered the structured release-evidence validator's test suite. It was not a successful strict release gate and did not establish W1–W7 real-device acceptance.

## 2. Environment and Remote-Access Boundary

| Item | Value |
|---|---|
| Execution date | 2026-09-02 (Asia/Shanghai) |
| Operating system | Windows 11 Pro, build 26200 |
| Rust | `rustc 1.98.0`, `cargo 1.98.0`; target `x86_64-pc-windows-msvc` |
| Final code candidate | `89dadf960a558d35dc3c6c557eadbc19d3a162d0` |
| Automation channel | WinRM over HTTPS 5986 using NTLM |
| Interactive channel | Windows graphical desktop session for real-window, button, modal, and lifecycle checks |
| CI | GitHub Actions run [33551495621](https://github.com/gcsagroup/agentguard/actions/runs/33551495621) was fully green for `89dadf9` |

The service certificate on 5986 was self-signed, and its SAN did not match the connection target. Certificate verification was disabled client-side only for this controlled test. Port 5985 was unreachable. This was sufficient for the diagnostic run but **does not establish production-trusted TLS**. The report intentionally omits the host address, account, and password.

## 3. Automation and Build Results

### 3.1 Old candidate `e9648eb`

| Scope | Result | Notes |
|---|---|---|
| Structured release-evidence gate tests | 5/5 PASS | Test suite passed; this was not a strict release-gate PASS |
| Root workspace | 901 passed / 2 ignored | `cargo +stable test --workspace --locked` |
| `win-adapter` all-target build | PASS | Native Windows toolchain |
| `win-adapter` Clippy with `-D warnings` | PASS | No warnings were admitted |
| Windows desktop tests | 2/2 PASS | Those automated tests did not cover real-window startup |
| Release EXE | Build PASS | 14,341,632 bytes; SHA-256 `11389F7F6CBA1815C836CC14A93FC5B03A2B2B064E86E220829625153888F20E`; Authenticode `NotSigned` |
| Interactive startup | **FAIL** | Exit code 101; `RPC_E_CHANGED_MODE`; no main window |

### 3.2 Final candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0`

| Scope | Result | Notes |
|---|---|---|
| Windows desktop tests | 5/5 PASS | Includes startup-thread and observation-chain regression coverage |
| Windows desktop Clippy with `-D warnings` | PASS | Executed with the current Windows toolchain |
| Release build | PASS | Windows MSVC Release artifact |
| GitHub Actions | Fully green | Run `33551495621`, bound to `89dadf9` |

Final Release executable:

| Item | Value |
|---|---|
| File | `desktop-windows.exe` |
| Size | 14,343,168 bytes |
| SHA-256 | `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119` |
| Authenticode | `NotSigned` |

The hash identifies only the locally built artifact from this run. Because Authenticode is `NotSigned`, this is not a signed Windows installation artifact suitable for external release.

## 4. Final-Candidate Interactive Smoke Test

| Step | Observed result | Decision boundary |
|---|---|---|
| Idle after startup | The main window remained stable for more than 30 seconds | Supports a W0 startup smoke check; does not establish W1–W7 |
| Refresh capabilities twice | Both refreshes remained stable and displayed capability state | Proves that the positive display path runs; no capability-failure branch was exercised |
| First `Start` round | Observation ran for more than 30 seconds; a real blocking modal appeared with `Accessibility-tree text not rendered on screen`, rule `OVL-010`; Deny was selected | Proves that the current product chain can display a real blocking modal; this was not W1's payment-CTA scenario |
| Lifecycle transition | `End` → `Resume` → `Start` entered the second round while the UI and process remained stable | Supports a two-round session-lifecycle smoke check |
| Second `Start` round | Observation again ran for more than 30 seconds; the same type of `OVL-010` blocking modal appeared; Deny was selected | The second UIA / GDI / OCR / decision round did not reproduce the earlier crash |
| Close | The app was closed through its normal UI; the test window added zero Windows Event 1000 records | No application-crash event was observed |

stderr contained only the warning that the Release build was made without SQLCipher. The batch helper's exit-code file was empty because `echo 0>` had ambiguous redirection parsing. This report therefore records only the normal UI close and zero new Event 1000 records; it **does not claim a process exit code of 0**.

The supported scope is W0 startup, positive capability display, the UIA / GDI / OCR product chain, the blocking modal, and two session-lifecycle rounds. It does not replace the exact W1–W7 scenarios below.

## 5. Formal W1–W7 Checklist Results

| Case | Result | Observation available from this run | Missing release-grade evidence |
|---|---|---|---|
| W1 Blocking modal (payment CTA) | `BLOCKED (payment-CTA-not-executed)` | A real `OVL-010` modal appeared and was denied in both rounds | No `Confirm Payment` / `确认支付` case in an ordinary third-party app, and no proof of zero payment side effect after cancellation |
| W2 UIA tree capture | `BLOCKED (form-FM-TR-case-not-executed)` | The observation chain and Accessibility-tree decision path ran stably | No archived `UiTreeDelta` from a real third-party form and no FM/TR verdict for optional PII |
| W3 GDI frame capture + steganography | `BLOCKED (third-party-steganography-not-executed)` | Two observation rounds did not reproduce the frame-8 crash | No chroma / luma steganography sample in a third-party application, archived frame, or rule hit |
| W4 Windows.Media.Ocr screen reading | `BLOCKED (third-party-pixel-OCR-not-executed)` | The final candidate's UIA / GDI / OCR chain ran continuously with zero new Event 1000 records in both rounds | No payment text rendered only in third-party-app pixels, and no archived language-pack state, recognition output, or resulting verdict |
| W5 Overlay boundary | `BLOCKED (overlay-boundary-not-executed)` | None | No comparison between a target window's self-drawn overlay and an overlay drawn by another process under Windows' narrower capture boundary |
| W6 Capability probe | `BLOCKED (capability-failure-branch-not-executed)` | Two refreshes displayed the positive capability state | UIA / capture / OCR unavailable states, reason strings, and fail-closed behavior were not exercised independently |
| W7 Native messaging | `BLOCKED (native-messaging-not-installed)` | None | No registry manifest, Chrome / Edge origin handshake, host verdict, or signed audit row |

| Surface | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| Formal Windows checklist (W1–W7) | 0 | 0 | 0 | 7 | 0 |

Zero FAIL here means only that the final candidate recorded no failure for a W1–W7 case that was executed to a conclusive state. All seven cases remain `BLOCKED`; this must not be interpreted as Windows acceptance.

## 6. Open Release Gates

The following items were not executed or lack release-grade evidence:

1. W1 pre-execution blocking of a payment CTA and zero side effect after denial;
2. W2 real third-party form, `UiTreeDelta`, and FM/TR evidence;
3. W3 / W4 third-party-application pixel steganography and OCR scenarios;
4. W5 Windows overlay-capture boundary;
5. W6 capability-unavailable / failure-reason branches;
6. W7 Native Messaging registration, origin handshake, verdict, and signed audit;
7. An Authenticode-signed installer plus install, upgrade, rollback, and uninstall validation;
8. Unique, non-empty, current-commit-bound evidence under `evidence/windows/` for every W1–W7 row, as required by the strict template.

## 7. Overall Conclusion

`89dadf960a558d35dc3c6c557eadbc19d3a162d0` did not reproduce the earlier COM / OCR crashes on the same startup and observation path in this run, and both lifecycle smoke rounds remained stable. CI was also fully green for that candidate. This advances the Windows state from “the program cannot start” to “real-product smoke flow is operable.” However, W1–W7 still stand at 0/7 formal PASS results, the Release EXE is unsigned, and install / upgrade / uninstall acceptance is missing. **The production-release decision remains No-Go**.

The next acceptance run should build a signed installer from the same immutable commit, execute W1–W7 individually in ordinary third-party applications and real Chrome / Edge, archive one independent evidence item per case under `evidence/windows/`, and then run the strict gate.
