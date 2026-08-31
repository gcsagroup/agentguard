# Chrome Web Store listing (draft)

## Name
AgentGuard Web Shield

## Summary
Stops risky steps by AI agents before they happen: payment clicks and privacy-trap
submissions are held for your approval, known malicious sites are blocked at the
network level, and hidden prompt-injection text is surfaced. Local-first.

## Description
AgentGuard Web Shield protects pages that AI agents use on your behalf.

**It blocks before, not after.** Three layers:

- **In-page approval gate** — a payment/transfer click, a form submitting personal
  info into a privacy-trap widget, or a payment-shaped `fetch`/XHR fired by page
  scripts is held *before it happens*. A plain-language dialog explains what the
  step does and what "Allow once" / "Not now" each mean. Keyboard and screen-reader
  accessible (alertdialog semantics, focus trap, Esc = not now), light and dark.
- **Network-level blocking** — hosts judged malicious (threat intelligence) or
  outside the current task's declared scope are blocked with
  `declarativeNetRequest` before the request leaves the browser. Every block is
  visible in the popup, explained in plain words, and can be undone.
- **Detection** — hidden / subliminal prompt-injection text, optional personal
  fields filled without need, privacy-trap widgets, payment CTAs.

**Made for people, not just engineers.** The popup leads with "Protecting this
page · Today: N found, M blocked"; every finding and block is described in plain
language (English, 简体中文, 繁體中文), with technical rule ids one tap away under
"Why?". A one-page onboarding opens on install, including a safe interactive demo
of the approval dialog.

**Optional desktop bridge.** With the AgentGuard native host installed, events are
also judged by the engine's rules and recorded in a **signed, tamper-evident audit
trail**. Host verdicts arrive asynchronously, so on that path a Critical decision
raises a notification after the fact — the *blocking* behaviour above lives in the
page gate and the network rules, which do not depend on the host.

**Honest limits.** The in-page gate covers the page's own DOM actions and wrapped
`fetch`/XHR; a script that grabbed `fetch` before us can bypass the wrapper
(network rules still apply). Nothing outside the browser is monitored by the
extension itself.

## Privacy
- Findings stay on-device by default; no browsing history is uploaded.
- Threat intel updates are signed (Ed25519) and optional.
- See `docs/privacy-policy.md`.

## Permissions justification
| Permission | Why |
|------------|-----|
| storage | Local finding buffer, language preference, block list persistence |
| nativeMessaging | Optional desktop bridge |
| activeTab / host | Content script probes and the pre-execution gate on pages the user visits while an agent is active |
| declarativeNetRequest | Block requests to judged-malicious / out-of-scope hosts before they leave the browser |
| notifications | Tell the user when the desktop engine judged a critical action (async path) |

## Build
```bash
./scripts/package-store.sh
# upload dist/agentguard-extension.zip in Chrome Web Store developer dashboard
```
