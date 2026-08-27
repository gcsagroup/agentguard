# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

This is the AgentGuard Tauri 2 menu-bar client. It uses AXUIElement, ScreenCaptureKit, and the local rules engine to observe protected sessions and provide status, audit, and cooperative Critical Confirm flows.

## Run locally

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

The user must grant Accessibility and Screen Recording permissions. When either permission is missing, the client must show degraded coverage rather than presenting simulation or partial observation as full protection.

## Capability boundaries

- Native AXUIElement and ScreenCaptureKit bridges are implemented. Observation is polling-based, not real-time interception.
- Only actions routed through the cooperative gateway can wait for confirmation before execution; direct execution bypasses that gateway.
- A debug build, automated test, or successful launch is not proof of Developer ID signing, notarization, or real-device end-to-end acceptance.
- The default configuration does not enable the updater. Replace the public-key and endpoint placeholders before enabling it.

## Verification and release

```bash
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

See [`../../docs/macos-release.md`](../../docs/macos-release.md) and [`../../docs/RELEASE-1.0.0-rc.1.en.md`](../../docs/RELEASE-1.0.0-rc.1.en.md) for release steps and outstanding evidence.
