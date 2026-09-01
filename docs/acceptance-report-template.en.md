[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# Real-Device Acceptance Report (Template)

> The executor fills out this report. Use one row per case: `PASS` / `PASS (sim)` / `FAIL` /
> `BLOCKED (reason)` + evidence path + notes. Follow the quick criteria in section 6 of
> `acceptance-runbook.md`. **If the result cannot be determined, enter `BLOCKED` with a reason; do not guess PASS.**
> `PASS (sim)` proves only the simulated verdict path. It does not replace `PASS (native)`, real-device
> observation evidence, or release evidence.

## Environment

| Item | Value |
|---|---|
| Execution date |  |
| Executor (agent / person) |  |
| Operating system + version |  |
| Repository commit (`git rev-parse HEAD`) |  |
| Rust version (`cargo --version`) |  |
| Node version (`node --version`) |  |
| All offline gates green (`make capability-claims check-extension-gate coverage`) | ☐ Yes ☐ No |

## Browser Extension (Firefox / Chrome / Edge)

Browser + version: __________　Extension ID: __________　Native host installed: ☐ Yes ☐ No

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| F1 Hidden injection |  |  |  |
| F2 Pre-execution payment CTA gate |  |  |  |
| F3 Trap + PII submission gate |  |  |  |
| F4 Payment-shaped fetch gate |  |  |  |
| F5 Read-only methods are not gated |  |  |  |
| F6 Malicious-domain hard block at the network layer |  |  |  |
| F7 Native-messaging handshake |  |  |  |
| F8 DNR quota |  |  |  |

## Windows Desktop Shell

Windows version: __________　Shell mode: ☐ Simulation ☐ Native available ☐ Native wired but permission / capability unavailable

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| W1 Blocking modal (verdict path) |  |  |  |
| W2 UIA tree capture |  |  |  |
| W3 GDI frame capture + steganography |  |  |  |
| W4 Windows.Media.Ocr screen reading |  |  |  |
| W5 overlay |  |  |  |
| W6 Capability probe (with reason string) |  |  |  |
| W7 Native messaging |  |  |  |

## macOS Desktop Shell

macOS version: __________　Shell mode: ☐ Simulation ☐ Native available ☐ Native wired but permission / capability unavailable

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| (Copy each case from the `acceptance-macos.md` case table) |  |  |  |

## Summary

| Surface | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| Browser |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |

**Overall conclusion (one sentence):**

**For each FAIL case (if any), record: observed behavior / expected behavior / evidence / initial cause assessment:**

**For each BLOCKED case, record the reason** (for example, `permission-denied` / `capability-unavailable` /
`no host verdict` / missing language pack / host not connected in the environment):

> This report records the results of this acceptance run and does not independently constitute release evidence.
> Signing, notarization/store review, release-artifact identity, strict gates, and platform coverage must be verified separately.
