[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows Real-Device Acceptance Checklist (Launch Readiness)

This document covers pre-release manual acceptance testing of the AgentGuard desktop shell on a
**real Windows device** and defines the remaining W1–W7 work. The `windows` CI job now covers the Windows
workspace, `win-adapter`, desktop tests, and a real-window startup smoke, but it does not drive real
UI Automation / GDI / OCR interactions and cannot replace per-case manual evidence for W1–W7.

> A fully green checklist is necessary but not sufficient for release. It does not replace Authenticode
> signing, installer identity, evidence for the other platforms, or the complete release gate.

> **Automated prerequisite gate:** first run `make acceptance` and `cargo test --workspace` at the repository
> root. On Windows, also build `win-adapter`, run Clippy with `-D warnings`, and run desktop tests, desktop
> Clippy, and the Release build. CI's window-startup smoke confirms that the process does not exit immediately
> and creates a native window. A green result is necessary but not sufficient: it does not prove W1–W7 interactions.

## Current Execution Status (2026-09-02)

- Candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0` completed desktop tests 5/5, desktop Clippy with `-D warnings`, and a Release build on Windows 11 build 26200. GitHub Actions run `33551495621` was fully green.
- The Release EXE has SHA-256 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119` and Authenticode status `NotSigned`.
- During independent RDP interaction testing, the window remained idle for more than 30 seconds and continued refreshing. Two sessions each ran for more than 30 seconds across OCR cycles; UIA/GDI/OCR all reported available; a real `OVL-010` blocking modal fired; and a second End/Resume/Start cycle remained stable after rejection. No new Event 1000 appeared.
- This run is **partial real-device acceptance**. Payment CTA, third-party form and pixel OCR, steganography, overlay-boundary, capability-failure, and Native Messaging scenarios were not executed as specified by W1–W7, so the table below remains unmarked. WinRM automation is prerequisite-gate evidence only; this run also has separate RDP interaction evidence. See the [supplemental report](acceptance-report-windows-2026-09-02.en.md).

## Prerequisites

- [ ] The AgentGuard Windows desktop shell is installed and running
- [ ] The rule set is `crates/guard-schema/rules/p0_rules.yaml` (or an equivalent path in the release package)
- [ ] The threat-intelligence bundle is loaded
- [ ] If testing the browser-extension path: perform the Windows equivalent of `install-host.sh` (write the
      native-messaging host manifest to
      `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`, with `path` pointing to
      `guard-nm-host.exe`)—see the “Native messaging” notes in platform-matrix

## Acceptance Cases

Run every case manually on **real Windows** and retain evidence (screenshots / event logs).

| # | Steps | Expected | Actual | Evidence |
|---|-------|----------|--------|----------|
| W1 | In an ordinary application, open a window containing a payment CTA ("Confirm Payment / 确认支付") | The shell opens a **blocking modal** (Critical Confirm); canceling prevents the action. This is the real interactive confirmation available only on Windows/macOS | | |
| W2 | UI Automation observation: switch to a window containing a form | The engine receives `UiTreeDelta` (the tree was traversed); nonessential PII in the form triggers an FM/TR verdict | | |
| W3 | GDI `BitBlt` pixel capture + steganography | An image containing chroma/luma steganography appears in the target window → `guard-vision` captures it (the same `guard-vision` stack used on macOS) | | |
| W4 | `Windows.Media.Ocr` screen reading | Payment text that exists only in pixels → OCR extracts it → `OVL-009/010` fires. Install the matching recognition language pack before strict acceptance. If it is absent, record this case as BLOCKED; the shell must still report the capability with a reason, but the row cannot say `PASS (native)` | | |
| W5 | overlay coverage (the note 1 limitation) | Suspicious content **drawn by the target window itself** is captured; a phishing window drawn over it by **another process** is **not** present in the pixels captured by GDI (an accurate narrow-coverage limitation, not a bug) | | |
| W6 | Runtime capability probe | The shell reports whether UI Automation / capture / OCR are available, each with a reason string (rather than silently assuming availability) | | |
| W7 | Browser extension → native-messaging host | Chrome/Edge extension events are decided by the registry-registered `guard-nm-host.exe` and enter the signed audit trail; the host's origin validation matches. This is required for strict Windows candidate acceptance | | |

> The supplemental report's blocking modal, capability status, and OCR cycles are adjacent evidence for W1/W3/W4/W6, but the payment CTA, steganography, third-party pixel-only text, and capability-failure scenarios specified by those rows were not executed. They therefore cannot be recorded as `PASS (native)`.

> The table above is only an execution record and cannot be used unchanged as a strict artifact. A strict-gate report
> must use the [central real-device acceptance report template](acceptance-report-template.en.md), preserve `ID | Result | Evidence`
> as its first three columns, and transcribe the W1–W7 results and evidence into it.

## Which “Pending Validation” Item in platform-matrix Each Case Covers

- W1 → "Critical-node confirmation ✅ blocking modal in the shell" (Windows column) works on real hardware
- W2 → "Observation source: UI Automation tree walk" obtains a tree on real hardware
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" captures a frame and reads screen text on real hardware
- W5 → note 1 (Windows overlay coverage is narrower than macOS) matches real-device behavior
- W6 → "Runtime capability probe ✅ real probe with a reason string" supplies a reason string on real hardware
- W7 → Windows registry registration for the native-messaging host + origin handshake

## Sign-off

- Tester: ____________  Version / commit: ____________  Date: ____________
- After all required cases pass, save the completed report as a repository-relative regular file such as
  `evidence/windows/report.md`, then actually validate it, compute its closure digest, and complete JSON with the
  commands below. JSON `output` must use the exact success marker `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`, and the
  evidence must bind the full current commit and `agentguard-acceptance-closure-sha256-v1`. W1–W7 must each appear
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
