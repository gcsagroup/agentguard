[简体中文](acceptance-report-template.md) | [繁體中文](acceptance-report-template.zh-TW.md) | [English](acceptance-report-template.en.md)

# Real-Device Acceptance Report (Template)

> The executor fills out this report. Use one row per case: `PASS (native)` / `PASS (sim)` / `FAIL` /
> `BLOCKED (reason)` + evidence path + notes. Follow the quick criteria in section 8 of
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
> These structured rules apply to the macOS, Android, iOS, iOS TestFlight, Windows, Chrome, and Edge kinds read by the strict gate. Chrome and Edge require separate reports; Firefox remains a first-GA exclusion only. Windows `first-ga-v1` requires only W1–W6/W8–W11; W7 is a legacy optional row excluded from the gate.

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

## First-GA Browser Extension (Chrome / Edge)

Browser + stable version: __________　Extension ID: __________　Candidate ZIP SHA-256: __________

> Complete this section separately for Chrome and Edge with the same ZIP. Put the Chrome report under `evidence/chrome/` with `AGENTGUARD_ACCEPTANCE_CHROME=PASS`, and the Edge report under `evidence/edge/` with `AGENTGUARD_ACCEPTANCE_EDGE=PASS`. Firefox is a source prototype only; `acceptance-firefox.en.md` is an exclusion notice and cannot produce Firefox PASS. Do not install a Native Host.

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| B1 Same-ZIP identity/version and no `nativeMessaging` permission |  |  |  |
| B2 Clean install: icon/i18n/popup correct, Native UI hidden, static rules enabled |  |  |  |
| B3 Representative DOM/DNR positive and negative cases: block-only, Close only, no authorization or replay |  |  |  |
| B4 Upgrade from prior public version: legacy pause/dynamic rules/badge cleared, no new permission |  |  |  |
| B5 Disable, restart, uninstall, and rollback are predictable with no page-authorization residue |  |  |  |

## Windows Desktop Shell

Windows version: __________　Shell mode: ☐ Simulation ☐ Native available ☐ Native wired but permission / capability unavailable

`AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| W1 Post-observation risk confirmation (`observed_only`; does not undo the external action) |  |  |  |
| W2 UIA tree capture |  |  |  |
| W3 GDI frame capture + steganography |  |  |  |
| W4 Windows.Media.Ocr screen reading |  |  |  |
| W5 overlay |  |  |  |
| W6 Capability probe (with reason string) |  |  |  |
| W7 Native messaging (non-GA / legacy optional; excluded from gate) | N/A (non-GA) |  |  |
| W8 Acceptance trace check |  |  |  |
| W9 No observation after end |  |  |  |
| W10 Status light matches reality |  |  |  |
| W11 “Start protecting” independently starts observation (not proof that external actions are blocked) |  |  |  |

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
| 15 Acceptance trace check |  |  |  |
| 16 No observation after end |  |  |  |
| 17 Status light matches reality |  |  |  |
| 18 “Start protecting” is enough on its own |  |  |  |

## Android Companion

Android device + version: __________　Candidate version: __________　AccessibilityService: ☐ Enabled ☐ Unavailable

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| A1 Physical-device install, notification, and accessibility-permission lifecycle |  |  |  |
| A2 Device P-256 public key registered; desktop verifies the real HTTP body signature |  |  |  |
| A3 A real accessibility event reaches the engine and receives the expected verdict |  |  |  |
| A4 The verdict returns to the device and produces the corresponding risk result |  |  |  |

## iOS Safari WebShield (Real Device)

iOS/iPadOS version: __________　Signed candidate version/build: __________　Safari Extension: ☐ Enabled ☐ Unavailable

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| I1 Real-iPhone install, extension enablement, and identity check |  |  |  |
| I2 Real-iPad install, extension enablement, and layout |  |  |  |
| I3 Benign pass and pre-execution block for supported risky actions |  |  |  |
| I4 Force-quit, reboot, and N-1 upgrade state |  |  |  |
| I5 Audit, rule synchronization, and data deletion |  |  |  |
| I6 VoiceOver, Dynamic Type, and keyboard |  |  |  |

## iOS TestFlight

App Store Connect build: __________　TestFlight install device: __________

| Case | Result | Evidence (path) | Notes |
|---|---|---|---|
| TF1 Processing completes and identity matches the signed candidate |  |  |  |
| TF2 Fresh-install from TestFlight and enable the embedded extension |  |  |  |
| TF3 Upgrade from the prior build and repeat core positive/negative cases |  |  |  |

## Summary

| Surface | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---|---|---|---|---|
| Browser |  |  |  |  |  |
| Windows |  |  |  |  |  |
| macOS |  |  |  |  |  |
| Android |  |  |  |  |  |
| iOS |  |  |  |  |  |
| iOS TestFlight |  |  |  |  |  |

**Overall conclusion (one sentence):**

**For each FAIL case (if any), record: observed behavior / expected behavior / evidence / initial cause assessment:**

**For each BLOCKED case, record the reason** (for example, `permission-denied` / `capability-unavailable` /
`no host verdict` / missing language pack / host not connected in the environment):

**Structured-evidence platform marker** (only after every required native case for that platform passes, replace
`<PLATFORM>` with the platform name and change the result to `PASS`; otherwise leave the placeholder intact):

```text
AGENTGUARD_ACCEPTANCE_<PLATFORM>=<RESULT>
```

> Chrome/Edge, iOS, and iOS TestFlight each require their exact marker and evidence directory. One platform or channel report cannot stand in for another.

> This report records the results of this acceptance run and does not independently constitute release evidence.
> Signing, notarization/store review, release-artifact identity, strict gates, and platform coverage must be verified separately.
> When used as a structured-evidence artifact, save the report as a regular `.md` file under `evidence/<platform>/`.
> `artifact.sha256` is `agentguard-acceptance-closure-sha256-v1`, binding the report bytes plus every unique per-case
> reference's path, length, and content. Do not commit it into the candidate commit it binds. This closure remains
> unsigned self-attestation and cannot prove the provenance of screenshots, logs, or device data.
