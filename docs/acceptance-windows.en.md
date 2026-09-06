[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows Real-Device Acceptance Checklist (first-ga-v1)

This document covers pre-release manual acceptance testing of the AgentGuard desktop shell on a
**real Windows device**. The required `first-ga-v1` cases are W1–W6 and W8–W11; W7 remains only as a
non-GA/legacy optional Native Messaging record and is not counted toward acceptance. The `windows` CI job now covers the Windows
workspace, `win-adapter`, desktop tests, and a real-window startup smoke, but it does not drive real
UI Automation / GDI / OCR interactions and cannot replace per-case manual evidence for `first-ga-v1`.

> A fully green checklist is necessary but not sufficient for release. It does not replace Authenticode
> signing, installer identity, evidence for the other platforms, or the complete release gate.

> **Automated prerequisite gate:** first run `make acceptance` and `cargo test --workspace` at the repository
> root. On Windows, also build `win-adapter`, run Clippy with `-D warnings`, and run desktop tests, desktop
> Clippy, and the Release build. CI's window-startup smoke confirms that the process does not exit immediately
> and creates a native window. A green result is necessary but not sufficient: it does not prove the required `first-ga-v1` interactions.

## Current Execution Status (2026-09-02)

- Candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0` completed desktop tests 5/5, desktop Clippy with `-D warnings`, and a Release build on Windows 11 build 26200. GitHub Actions run `33551495621` was fully green.
- The Release EXE has SHA-256 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119` and Authenticode status `NotSigned`.
- During independent RDP interaction testing, the window remained idle for more than 30 seconds and continued refreshing. Two sessions each ran for more than 30 seconds across OCR cycles; UIA/GDI/OCR all reported available; a real `OVL-010` post-observation risk modal fired; and a second End/Resume/Start cycle remained stable after pausing. No new Event 1000 appeared.
- This run is **partial real-device acceptance**. Payment CTA, third-party form and pixel OCR, steganography, overlay-boundary, and capability-failure scenarios were not executed as required by `first-ga-v1`, so the table below remains unmarked. WinRM automation is prerequisite-gate evidence only; this run also has separate RDP interaction evidence. See the [supplemental report](acceptance-report-windows-2026-09-02.en.md).

## Prerequisites

- [ ] The AgentGuard Windows desktop shell is installed and running
- [ ] The rule set is `crates/guard-schema/rules/p0_rules.yaml` (or an equivalent path in the release package)
- [ ] The threat-intelligence bundle is loaded
- [ ] The strict report contains the exact line `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`.
- [ ] Do not install a Native Messaging host for this checklist; the first-GA browser package has no such permission. W7 is retained only for a separately accepted legacy prototype.

## Acceptance Cases

Run every case manually on **real Windows** and retain evidence (screenshots / event logs).

| # | Steps | Expected | Actual | Evidence |
|---|-------|----------|--------|----------|
| W1 | In an ordinary application, open a window containing a payment CTA ("Confirm Payment / 确认支付") | The shell opens a **post-observation risk confirmation** and states that the action was already observed and cannot be reversed. “Not now” pauses this session and future observation only. Audit evidence must say `effect=observed_only` and `external_action_blocked=false`; it must not claim the original action was prevented | | |
| W2 | UI Automation observation: switch to a window containing a form | The engine receives `UiTreeDelta` (the tree was traversed); nonessential PII in the form triggers an FM/TR verdict | | |
| W3 | GDI `BitBlt` pixel capture + steganography. Fixtures: `make acceptance-fixtures` → show `eval/acceptance-fixtures/generated/w3-stego-luma.png` and `w3-stego-chroma.png` full-screen (the control `w3-control-clean.png` must stay silent) | An image containing chroma/luma steganography appears in the target window → `guard-vision` captures it (the same `guard-vision` stack used on macOS) | | |
| W4 | `Windows.Media.Ocr` screen reading. Fixture: open `generated/w4-pixel-only-payment.html` in Edge/Chrome (payment text lives only in canvas pixels, not in the UIA tree) | Payment text that exists only in pixels → OCR extracts it → `OVL-009/010` fires. Install the matching recognition language pack before strict acceptance. If it is absent, record this case as BLOCKED; the shell must still report the capability with a reason, but the row cannot say `PASS (native)` | | |
| W5 | overlay coverage (the note 1 limitation). Fixture: `generated/w5-self-drawn-overlay.html` (the page draws its own 3 % overlay; delete `#sub` in DevTools for the control) or `w5-self-drawn-overlay.png` full-screen | Suspicious content **drawn by the target window itself** is captured; a phishing window drawn over it by **another process** is **not** present in the pixels captured by GDI (an accurate narrow-coverage limitation, not a bug) | | |
| W6 | Runtime capability probe | The shell reports whether UI Automation / capture / OCR are available, each with a reason string (rather than silently assuming availability) | | |
| W7 (non-GA / legacy optional) | Browser extension → native-messaging host | Identifier and prototype semantics are retained only; this does not count toward `first-ga-v1`, and the GA manifest must never regain `nativeMessaging` merely to make it pass | N/A (non-GA) | |
| W8 | **Acceptance trace check:** launch the shell for the whole session with `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl`; after W1–W6, W9 and W10 run `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <audit db>` | All six checks `PASS`; the full line `AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS` is printed; any FAIL fails this case | | |
| W9 | **No observation after end** (report item 3): click “End session”, wait ≥60 s, switch through a few windows | Last audit row is `SESSION-END` with zero observation rows after it; no tick with `events>0` after the end in the trace; status light “Stopped” | | |
| W10 | **Status light matches reality** (report P0-3): screenshot “Protecting” mid-session; restart the shell with `AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia`, start a session, screenshot; remove the variable, screenshot again | “Protecting” → “Protection incomplete” (`required_capability_unavailable`; reason names UIA) → “Protecting”; trace-check #5 passes. A real `E_ACCESSDENIED` is tested separately and must read “Permission required”. | | |
| W11 | **“Start protecting” is enough on its own** (real-device feedback): launch the app fresh → **do not expand the developer panel** → press “Start protecting” | Within 10 s the light reads “Protecting” and the main line reads “Watching this machine…”; each of the three “Live observation” capability rows includes its probed value and reason. After “Stop protecting” the light returns to “Not protecting” and the line to “Not watching anything yet”. Capture the two screenshots (protecting / after stopping), the three capability rows, and the developer panel's separate raw diagnostic line. | | |

> The supplemental report's risk modal, capability status, and OCR cycles are adjacent evidence for W1/W3/W4/W6, but the payment CTA, effect semantics, steganography, third-party pixel-only text, and capability-failure scenarios specified by those rows were not executed. They therefore cannot be recorded as `PASS (native)`.
> Also, the `OVL-010` modal seen in both rounds of that report fired while AgentGuard's **own window** was in the foreground (demo-button text in a collapsed panel: in the tree, not in the pixels). It proves the chain runs; it was not a detection. The observer now skips its own process, and `OVL-010` requires the unrendered text to have instruction shape. Re-test with a third-party window in the foreground.

> **How to execute W6**: on a healthy machine the capability-failure branches cannot be triggered naturally. Before launching the shell set
> `AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia` (optionally `frame`, `ocr`, comma-separated, e.g. `uia,frame`) and verify item by item:
> the capability row shows "unavailable" with a reason containing `forced unavailable for acceptance`; with `uia,frame` both forced off the
> status pill reads "Protection incomplete" and the observation loop does not start (fail-closed to simulation); with only `ocr` forced off the
> W4 cross-validation does not run and the UI says so. The switch can only turn available into unavailable, never the reverse — it lets the
> tester see what breakage looks like; it cannot let an incapable machine pose as capable.

> The table above is only an execution record and cannot be used unchanged as a strict artifact. A strict-gate report
> must use the [central real-device acceptance report template](acceptance-report-template.en.md), preserve `ID | Result | Evidence`
> as its first three columns, and transcribe the required `first-ga-v1` W1–W6/W8–W11 results and evidence into it.

## Which “Pending Validation” Item in platform-matrix Each Case Covers

- W1 → the desktop observer's post-observation confirmation and `observed_only` effect semantics work on real hardware; pre-execution blocking is verified separately at the Chromium/Gateway boundary
- W2 → "Observation source: UI Automation tree walk" obtains a tree on real hardware
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" captures a frame and reads screen text on real hardware
- W5 → note 1 (Windows overlay coverage is narrower than macOS) matches real-device behavior
- W6 → "Runtime capability probe ✅ real probe with a reason string" supplies a reason string on real hardware
- W7 → non-GA/legacy registry registration for the native-messaging host + origin handshake; excluded from `first-ga-v1`

## Sign-off

- Tester: ____________  Version / commit: ____________  Date: ____________
- After all required `first-ga-v1` cases pass, save the completed report as a repository-relative regular file such as
  `evidence/windows/report.md`, then actually validate it, compute its closure digest, and complete JSON with the
  commands below. JSON `output` must use the exact success marker `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`, and the
  evidence must bind the full current commit and `agentguard-acceptance-closure-sha256-v1`. The report must contain
  the exact line `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`. W1–W6 and W8–W11 must each appear
  in exactly one report row with result `PASS (native)`. The evidence column must identify a unique existing nonempty
  repository-relative regular file under `evidence/windows/`; it cannot be the report itself or the current evidence
  JSON source file, traverse a symbolic link, or resolve outside the repository. Paths use only `/`; every component
  must match `[A-Za-z0-9._-]+` with no whitespace or shell glob/expansion character. The closure binds the report and
  every unique reference's path, length, and content, but remains unsigned self-attestation and cannot prove provenance.
  ```bash
  mkdir -p evidence/windows
  commit="$(git rev-parse HEAD)"
  commit_time="$(git show -s --format=%ct HEAD)"
  cargo build --release -p guard-cli
  target/release/guard-cli manual-acceptance windows docs/acceptance-windows.md \
    evidence/windows/report.md --repo-root .
  # Sole success output: AGENTGUARD_ACCEPTANCE_WINDOWS=PASS
  cargo run -p guard-cli -- evidence-digest \
    --repo-root . --path evidence/windows/report.md
  cargo run -p guard-cli -- evidence-template --kind acceptance_windows \
    --commit "$commit" > evidence/windows/evidence.json
  # Put the exact manual-acceptance command, marker, and closure digest into JSON, then verify
  cargo run -p guard-cli -- evidence-verify --kind acceptance_windows \
    --file evidence/windows/evidence.json --commit "$commit" \
    --commit-time "$commit_time" --repo-root .
  ```
- Then export the **JSON file** path as `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS`. A directory, untouched template,
  or file containing only a `PASS` keyword is not evidence. See
  [Structured Release Evidence](release-evidence.en.md).
