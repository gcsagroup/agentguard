# Chrome Web Store listing (draft)

## Name
AgentGuard Web Shield

## Summary
Detect prompt injection, optional PII overfill, privacy traps, and payment CTAs on pages used by AI agents. Local-first; optional Native Messaging to the AgentGuard desktop app.

## Description
AgentGuard Web Shield is a companion to the AgentGuard desktop guardian. It scans the active page for:

- Hidden / subliminal prompt-injection text
- Optional personal fields filled without need (FM)
- Privacy-trap widgets (TR)
- Payment and transfer confirmation CTAs

By default, findings stay on-device. When the desktop app is installed, you may forward events via Native Messaging for unified audit and Critical Confirm.

## Privacy
- No browsing history is uploaded to AgentGuard servers by default.
- Threat intel updates are signed (Ed25519) and optional.
- See `docs/privacy-policy.md`.

## Permissions justification
| Permission | Why |
|------------|-----|
| storage | Local finding buffer |
| nativeMessaging | Optional desktop bridge |
| activeTab / host | Content script probes on pages the user visits while an agent is active |

## Build
```bash
./scripts/package-store.sh
# upload dist/agentguard-extension.zip in Chrome Web Store developer dashboard
```
