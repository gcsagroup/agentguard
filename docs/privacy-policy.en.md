# AgentGuard Privacy Notice Draft

[简体中文](privacy-policy.md) | [繁體中文](privacy-policy.zh-TW.md) | [English](privacy-policy.en.md)

- **Last updated:** 2026-08-28
- **Product version:** 1.0.0-rc.1
- **Applies to:** macOS, Windows, the Android companion, the Chromium extension, the Native Messaging host, the CLI, and the local API

> This is a technical disclosure draft shipped with the source. It is not a legally reviewed privacy policy. Before public distribution, add the real operator, contact details, applicable jurisdictions, and retention terms.

## Summary

AgentGuard processes observations locally by default. It has no default cloud account, telemetry, or vendor upload service. A user or organization may configure threat-intelligence downloads, policy sync, the Android relay, or the local API; the destination, transport security, and retention of those connections depend on the deployment.

| Data | Leaves the device by default? | Notes |
|---|---|---|
| UI / AX / UIA / Accessibility text | No | Used for local rules and may be written to the local audit trail |
| ScreenCaptureKit / GDI frames | No | Summaries or visual features are derived locally; raw pixels are not uploaded by default |
| Browser DOM signals | No | Kept in extension storage; sent to the local host only when Native Messaging is enabled |
| Audit database | No | Local SQLite, with optional SQLCipher |
| Threat intelligence and enterprise policy | Optional download | Accessed only after an operator configures an endpoint; release paths require signature verification |
| Android relay | Optional | The user may configure loopback, ADB reverse, or a LAN address |
| Crash telemetry and advertising tracking | No | The current source candidate includes no default telemetry or advertising SDK |

## Data processed locally

1. Accessibility trees, windows, and form text used to identify payments, excessive disclosure, injection, and suspicious interfaces.
2. Browser DOM signals used to detect hidden text, privacy traps, and high-risk action prompts.
3. Frames or frame summaries used for transparent-overlay, low-contrast, steganography, and frame-change checks.
4. Network-flow metadata such as host and approximate size; AgentGuard is not a full packet-capture tool.
5. Audit records such as event type, rule ID, decision, truncated explanation, and human confirmation result.
6. Android environment-survey results such as other broadcast receivers or accessibility services that may read input.

## Typical storage locations

- macOS: `~/Library/Application Support/agentguard/`
- Windows: local audit and configuration files under the application-data directory
- Android: JSONL envelopes, preferences, and Android Keystore keys in the app-private directory
- Chromium: extension-local storage; the Native Messaging host uses an operator-selected local audit database

Android adapter private keys in Android Keystore are designed to be non-exportable. The current file-backed audit-signing key is stored locally with `0600` permissions and remains exportable by an account or root process that can read that file. Public fixture keys in this repository are for tests and evaluation only and must not be used in production.

## Network behavior

- Core rule evaluation does not require internet access by default.
- Threat intelligence and enterprise policies are downloaded only after a user or organization configures an endpoint.
- The local API binds to loopback by default and requires a Bearer token. A LAN bind is allowed only with explicit `--allow-lan`. That exception may use plain HTTP, so the operator must provide a trusted network or additional transport protection.
- The Android relay is explicitly configured by the user; its payload and destination depend on that configuration.
- Chromium Native Messaging connects only to an installed local host and does not directly connect to an AgentGuard cloud service.

## Permissions and controls

- macOS: Accessibility and Screen Recording. Denial reduces coverage and must not be described as full protection.
- Windows: UI Automation, window, and screen observations depend on OS permissions and the target application.
- Android: Accessibility and a visible foreground-service notification. Risk notifications normally occur after the observed action; they are not a blocking confirmation gate.
- Users can end sessions, disable optional observation and relays, and delete local databases and reports.

## Current release status

This repository is a source release candidate. Signed installers, store data-safety declarations, legal review, real-device acceptance, and a public support channel are not complete.

## Contact

The source candidate does not yet provide a public privacy contact. A real, monitored contact owned by the operator must be added before public distribution.
