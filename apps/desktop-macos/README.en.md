# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

This is the AgentGuard Tauri 2 menu-bar client. It uses AXUIElement, ScreenCaptureKit, and the local rules engine to observe protected sessions and provide status, audit, and cooperative Critical Confirm flows.

## Run locally

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

Desktop observation requires user-granted Accessibility; Screen Recording is optional. Missing required permission or unavailable encrypted storage prevents starting. Simulation and partial observation are not full protection.

See the [desktop guide](../../docs/desktop-guide.en.md) for the five-page workspace and four settings tabs. Active protection provides browser setup, MCP configuration and authenticated local gateway confirmations without changing client settings automatically. See the [remediation note](../../docs/remediation-publication-2026-09-06.en.md).

## Capability boundaries

- AXUIElement tree changes use AXObserver push with a three-second fallback. ScreenCaptureKit pixels remain sampled every 1.5 seconds, so this is not gap-free real-time interception.
- Only actions routed through the cooperative gateway can wait for confirmation before execution; direct execution bypasses that gateway.
- A debug build, automated test, or successful launch is not proof of Developer ID signing, notarization, or real-device end-to-end acceptance.
- The default configuration does not enable the updater. Replace the public-key and endpoint placeholders before enabling it.

## Verification and release

```bash
../../scripts/bootstrap-rust.sh --install
../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
node --check src/main.js
AGENTGUARD_ALLOW_ADHOC=1 ./scripts/build-release.sh  # local smoke only
```

A Release build must explicitly enable `audit-sqlcipher`; omitting the feature is a compile-time
failure. The release script always uses `--no-default-features --features audit-sqlcipher --locked`
and no longer offers a plaintext Release override.
The production script defaults to a universal Apple Silicon + Intel `.app`, loads security resources from the
bundle, and stores the audit passphrase and signing seed separately in Keychain. A distributable build requires
a Developer ID, expected Team ID, and `notarytool` Keychain profile. Ad-hoc signing is local-smoke only and proves
neither stable TCC identity nor Gatekeeper/notarization.

See [`../../docs/macos-release.md`](../../docs/macos-release.md) and [`../../docs/RELEASE-1.0.0-rc.1.en.md`](../../docs/RELEASE-1.0.0-rc.1.en.md) for release steps and outstanding evidence.
