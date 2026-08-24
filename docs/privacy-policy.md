# AgentGuard Privacy Policy

**Last updated:** 2026-08-01  
**Product version:** 1.0.0-rc.1  
**Applies to:** macOS Menu Bar app, Chromium extension, local CLI / loopback API

AgentGuard is **local-first**. This document describes what the software does on your device. Replace the contact email before public distribution.

## Summary

| Data | Leaves device? | Notes |
|------|----------------|-------|
| UI / AX text used for rules | No (default) | Processed in-process; may be stored in local audit DB |
| ScreenCaptureKit frames | No | Sparse luma/opacity stats only; **pixels are not persisted** |
| Audit SQLite / SQLCipher DB | No | Under Application Support / APPDATA |
| Threat intel CDN fetch | Optional download | Signature-verified Ed25519 (or legacy sha256); you choose the URL |
| Billing / account | N/A in free launch | Not required for core guardian features |
| Crash telemetry | No (default) | Not shipped in RC |

## What we process on-device

1. **Accessibility / UI tree text** (when permission granted) to match high-risk patterns (payments, injection, traps).
2. **Browser DOM signals** via the Chromium extension (local). Optional Native Messaging to the desktop app is user-controlled.
3. **ScreenCaptureKit coarse stats** (when Screen Recording granted): width/height, mean luminance, low-opacity ratio. Overlay decisions prefer structured markers / AX when available.
4. **Network egress metadata** when provided by adapters/netmon helpers (host, rough size)—not full packet capture.
5. **Audit records**: event type, rule id, decision, truncated human message, optional user confirm choice.

## Storage locations (typical)

- macOS: `~/Library/Application Support/agentguard/`
  - `audit-macos.db` (plaintext or SQLCipher)
  - `audit.key` (SQLCipher passphrase file, mode 0600, when encryption enabled)
  - `audit-signing.key` (Ed25519 device key, mode 0600, plus `.pub`) — signs audit
    records so they are attributable and cannot be silently rewritten; never
    transmitted anywhere. See [audit-signing.md](./audit-signing.md)
  - `entitlement.json`, `device-cache.yaml`, `reports/`
- Extension: browser extension storage only as needed for settings; page content is not uploaded by AgentGuard servers (there are none by default).

## Network

- **Default offline** for decisioning.
- **Optional:** HTTPS GET of a threat-intel bundle / manifest you or your org configure. Bundles are verified before use in release builds; verification failure yields an empty intel set (fail-closed), not a silently trusted file.
- Local loopback API (`127.0.0.1` only) may expose status/audit to other local processes that present a Bearer token. Non-loopback binds are refused.

## Permissions (macOS)

| Permission | Why |
|------------|-----|
| Accessibility | Read UI trees of Agent / browser windows |
| Screen Recording | Optional SCK stats for overlay heuristics |

Denying a permission **reduces** coverage; the app should surface that state rather than claim full protection.

## Your controls

- Start / end guard sessions; approve or deny Critical Confirm prompts (release builds disable “auto-approve” unless you set an explicit env override).
- Export / delete local audit DB and reports.
- Disable ScreenCaptureKit / rely on simulation or extension-only paths.
- Choose not to configure any intel CDN.

## Children

Not directed at children under 13 (or local digital-age equivalent).

## Changes

Material changes will bump “Last updated” and the product release notes.

## Contact

`privacy@example.com` — **replace before public launch.**
