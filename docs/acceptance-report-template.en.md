[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# Real-Device Acceptance Report (Template)

> The executor fills out this report. Use one row per case: `PASS (native)` / `PASS (sim)` / `FAIL` /
> `BLOCKED (reason)` + evidence path + notes. Follow the quick criteria in section 7 of
> `acceptance-runbook.en.md`. **If the result cannot be determined, enter `BLOCKED` with a reason; do not guess PASS.**
> `PASS (sim)` proves only the simulated verdict path. It does not replace `PASS (native)`, real-device
> observation evidence, or release evidence.
> When used as a strict-gate artifact, every required ID must appear in exactly one Markdown table row. The
> second column must be exactly `PASS (native)`, and the third must identify an existing repository-relative
> nonempty regular file under the matching `evidence/<platform>/` directory, and every case must use a unique path.
> It cannot be the report itself or the current evidence JSON source file, traverse a symbolic link, or resolve outside
> the repository. Paths use only `/`; every component must match portable ASCII `[A-Za-z0-9._-]+` and contain no
> whitespace or shell glob/expansion character. Missing or duplicate cases, reused paths, missing referenced files,
> `PASS (sim)`, FAIL, BLOCKED, and N/A are rejected.

## Environment

| Item | Value |
|---|---|
| Execution date |  |
| Executor (agent / person) |  |
| Operating system + version |  |
| Repository commit (`git rev-parse HEAD`) |  |
| Commit time (`git show -s --format=%ct HEAD`) |  |
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
| 1 Payment confirmation |  |  |  |
| 2 Transfer confirmation |  |  |  |
| 3 Optional PII |  |  |  |
| 4 Trap form |  |  |  |
| 5 Transparent overlay |  |  |  |
| 5b Rounded-corner invisible zone |  |  |  |
| 5c Pre-execution UI change |  |  |  |
| 6 Intel injection |  |  |  |
| 7 Malicious domain |  |  |  |
| 8 Netmon exfiltration |  |  |  |
| 9 Browser malicious URL |  |  |  |
| 10 Session pause |  |  |  |
| 11 SCK probe |  |  |  |
| 12 AX probe |  |  |  |
| 13 Real-device AX |  |  |  |
| 14 UI revalidation |  |  |  |

## Android Companion

Android device + version: __________　Candidate version: __________　AccessibilityService: ☐ Enabled ☐ Unavailable

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| A1 Physical-device install, notification, and accessibility-permission lifecycle |  |  |  |
| A2 Device P-256 public key registered; desktop verifies the real HTTP body signature |  |  |  |
| A3 A real accessibility event reaches the engine and receives the expected verdict |  |  |  |
| A4 The verdict returns to the device and produces the corresponding risk result |  |  |  |

## Summary

| Surface | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| Browser |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |
| Android |  |  |  |  |  |

**Overall conclusion (one sentence):**

**For each FAIL case (if any), record: observed behavior / expected behavior / evidence / initial cause assessment:**

**For each BLOCKED case, record the reason** (for example, `permission-denied` / `capability-unavailable` /
`no host verdict` / missing language pack / host not connected in the environment):

**Structured-evidence platform marker** (only after every required native case for that platform passes, replace
`<PLATFORM>` with the platform name and change the result to `PASS`; otherwise leave the placeholder intact):

```text
AGENTGUARD_ACCEPTANCE_<PLATFORM>=<RESULT>
```

> This report records the results of this acceptance run and does not independently constitute release evidence.
> Signing, notarization/store review, release-artifact identity, strict gates, and platform coverage must be verified separately.
> When used as a structured-evidence artifact, save the report as a regular `.md` file under `evidence/<platform>/`.
> `artifact.sha256` is `agentguard-acceptance-closure-sha256-v1`, binding the report bytes plus every unique per-case
> reference's path, length, and content. Do not commit it into the candidate commit it binds. This closure remains
> unsigned self-attestation and cannot prove the provenance of screenshots, logs, or device data.
