# AgentGuard macOS Store Listing Draft

[简体中文](STORE.md) | [繁體中文](STORE.zh-TW.md) | [English](STORE.en.md)

> This is copy only. Signing, notarization, real-device acceptance, legal review of the privacy policy, and a public support address are incomplete. Do not submit it as-is.

## Name and short description

- **Name:** AgentGuard for Mac
- **Description:** Observe AI-agent sessions locally, record risk decisions, and provide critical-action confirmation on cooperative paths.

## Features

- Observe UI, window, and screen features locally through AXUIElement and ScreenCaptureKit.
- Run local rules for excessive disclosure, prompt injection, suspicious overlays, and critical actions.
- Write events, rules, and human decisions to a locally signed audit chain.
- Optionally load signature-verified threat intelligence and enterprise policies.

## Boundaries that must accompany the listing

- AgentGuard provides out-of-band observation and cooperative deterrence. It is not a general sandbox, DLP, EDR, or unavoidable real-time interceptor.
- Only actions routed through the AgentGuard gateway can wait for confirmation before execution. Direct execution bypasses it.
- Observation is polling-based; actions between samples may be missed.
- Coverage decreases without Accessibility or Screen Recording permission, and the app must show that state.

## Privacy and permissions

- Screen and accessibility data is processed locally by default; raw frames are not uploaded by default.
- Accessibility reads UI trees; Screen Recording supports visual-feature detection.
- No advertising tracker or crash-telemetry SDK is enabled by default.
- See the technical disclosure draft in [`../../docs/privacy-policy.en.md`](../../docs/privacy-policy.en.md).

## Blocks before store submission

- [ ] Developer ID or App Store signing verified
- [ ] Notarization and staple verified
- [ ] Representative device permissions, close/recovery, and first-launch flows accepted
- [ ] Valid support address and final privacy policy supplied
- [ ] Update channel, bundle ID, and distribution channel aligned
