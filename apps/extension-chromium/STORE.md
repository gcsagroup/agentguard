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

By default, findings stay on-device. When the AgentGuard native host is installed, you may forward events to it via Native Messaging. The host judges each event against the engine's rules, records a **signed, tamper-evident audit trail** (its own database — shareable with the desktop app by pointing both at the same `AGENTGUARD_AUDIT_DB`), and returns its verdict. On a **Critical** decision (payment/transfer/permanent-delete and the like) the extension raises a browser notification naming the rule — a notify-after-the-event alert, not a blocking approve-then-proceed gate (the host observes each event after it has already happened; only the desktop app has the blocking modal).

Separately, for actions taken **on the page itself** — submitting a payment/transfer confirmation, or submitting personal fields into a privacy-trap widget — the extension now also holds the action *before* it happens: it intercepts the submit/click synchronously and asks you to allow it once before letting it through. This in-page gate covers the page's own DOM actions only; it does not stop a script that talks to a payment API directly, nor anything outside the browser.

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
