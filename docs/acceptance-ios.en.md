[简体中文](acceptance-ios.md) | [繁體中文](acceptance-ios.zh-TW.md) | [English](acceptance-ios.en.md)

# iOS Safari WebShield Device and TestFlight Acceptance

This document defines iOS release evidence for the first GA. Simulator builds, unsigned device builds, and Xcode Analyze are development gates only and do not replace this checklist. The formal candidate must be Apple Distribution signed, and the app, Safari Web Extension, build number, and TestFlight build must identify the same candidate.

## Preconditions

- Produce a Release archive from the final candidate commit. The app and extension use the same Apple Team, the correct App Group, and production provisioning profiles.
- Cover real iPhone and iPad hardware across the current and minimum supported systems. Do not commit test-account or device identifiers.
- Put I1–I6 reports under `evidence/ios/` and TF1–TF3 reports under `evidence/ios-testflight/`. Every case uses a distinct nonempty evidence file.

## Safari Web Extension device cases

| # | Step | Pass criterion |
|---|---|---|
| I1 | Install the signed candidate on a real iPhone and enable the extension in Safari | App and extension launch; version, build, and Team ID match the candidate; disabling the extension is reported as unprotected |
| I2 | Repeat install, enable, and disable on a real iPad | The iPad layout is usable, app and extension state agree, and Simulator evidence is not substituted |
| I3 | Open benign pages and declared payment/trap fixtures | Benign actions are not falsely blocked; supported risky actions are blocked before execution; there is no in-page allow-once or automatic replay |
| I4 | Force-quit the app/Safari, reboot, and upgrade N-1 to the candidate | Extension state, rule version, and audit state are predictable; upgrade adds no permission and does not silently re-enable a user-disabled capability |
| I5 | Inspect local audit, rule synchronization, and Delete Data | App/extension data agree; sensitive content avoids unnecessary logs; deletion follows the documented, verifiable contract |
| I6 | Use VoiceOver, Dynamic Type, and keyboard/external keyboard through onboarding, status, and risk notices | Controls are named, focus order works, text is not clipped, and risk/unprotected states do not rely on color alone |

After I1–I6 all pass, the report contains an exact line:

```text
AGENTGUARD_ACCEPTANCE_IOS=PASS
```

## TestFlight cases

| # | Step | Pass criterion |
|---|---|---|
| TF1 | Upload the same archive and wait for App Store Connect processing | TestFlight bundle ID, marketing version, and build number match the signed candidate; no binary was substituted |
| TF2 | Fresh-install from TestFlight on real hardware | Source, version, and build are verifiable; the app launches and Safari can find and enable the embedded extension |
| TF3 | Upgrade from the previous TestFlight build and repeat I3's core positive/negative cases | User data and extension state follow the migration contract; risky/benign behavior remains correct; no launch crash or disconnect occurs |

After TF1–TF3 all pass, the separate report contains an exact line:

```text
AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS
```

## Structured validation

```bash
guard-cli manual-acceptance ios docs/acceptance-ios.md evidence/ios/report.md --repo-root .
guard-cli manual-acceptance ios-testflight docs/acceptance-ios.md evidence/ios-testflight/report.md --repo-root .
```

These commands validate report structure, per-case references, and the evidence closure only. The result remains unsigned local self-attestation and cannot prove that a screenshot came from the claimed device. Release owners must still verify App Store Connect, signing identity, and the final candidate.
