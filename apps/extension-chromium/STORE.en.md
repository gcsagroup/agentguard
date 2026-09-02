# Chrome Web Store Listing Draft

[简体中文](STORE.md) · [繁體中文](STORE.zh-TW.md) · English

> **Draft only; not submitted to or approved by the Chrome Web Store.** This copy is not evidence of publication, review, or real-browser acceptance.

## Name

AgentGuard Web Shield

## Summary

Hold payment, privacy-trap, and high-risk network actions before they happen, while surfacing hidden prompt injection on pages used by AI agents. Local-first.

## Description

AgentGuard Web Shield provides three limited layers for pages an AI agent uses on the user's behalf:

- **In-page approval gate:** payment or transfer clicks, personal-data submissions into a privacy trap, and payment-shaped `fetch`/XHR calls are held first and replayed only after **Allow once**.
- **Network block list:** browser DNR stops threat-intelligence matches and hosts outside an explicitly supplied task allowlist before requests leave. The popup shows each host, its reason, and an unblock control.
- **Page detection:** hidden / subliminal prompt-injection text, unnecessary personal-data fields, privacy traps, and high-risk CTA text.

Findings stay in the extension by default. With the optional `guard-nm-host`, matching events are evaluated by the local engine and can enter a signed, tamper-evident audit chain; the desktop app need not be running. Host verdicts are **asynchronous**: a Critical result raises a notification after the fact and cannot undo an action that already occurred. Pre-action control comes from the page gate and successfully installed DNR rules.

**Honest limits:** the page gate covers only main-frame DOM actions the extension can reach and `fetch`/XHR references that a page did not capture first. A clean iframe or earlier API reference can bypass it. DNR fails open if rules cannot be installed. The extension does not monitor native apps outside the browser.

## Privacy

- Browsing history is not uploaded to AgentGuard servers by default.
- Without an installed or enabled Native Messaging host, findings remain in the extension-local buffer.
- With the host enabled, matching events go to the user's local `guard-nm-host` process.
- The host audit database remains local by default. Audit signing and encryption require explicit user configuration and must not be assumed enabled.
- Threat intel updates are signed (Ed25519) and optional; production deployments must replace repository fixture keys.
- See the [privacy policy](../../docs/privacy-policy.en.md).

## Permission justification

- `storage`: stores settings and the local recent-findings buffer.
- `nativeMessaging`: optionally connects to the user-installed local `guard-nm-host`.
- `declarativeNetRequest`: blocks listed malicious or out-of-scope hosts before a request leaves.
- `notifications`: displays asynchronous high-risk engine verdicts.
- `activeTab`: supports extension interaction associated with the active tab.
- `http://*/*`, `https://*/*`: runs the content script and inspects the DOM on pages the user visits.

## Local-host security boundary

In addition to Chrome manifest `allowed_origins`, the host verifies the origin Chrome supplies through `argv[1]`. It refuses to start when no expected origin is configured or the values differ. The installer writes the extension origin to an `allowed-origin` file beside the binary.

## Package

```bash
./apps/extension-chromium/scripts/package-store.sh
```

The resulting ZIP does not contain the Native Messaging host. The extension package, host installation, and local audit configuration must be documented separately.

## Current release status

- Not submitted to the Chrome Web Store.
- No real-browser store install, upgrade, or permission-prompt acceptance record.
- The Native Messaging auto-installer currently supports macOS and Linux only; Windows requires manual manifest installation.
- Real store installation and end-to-end pre-action acceptance still require separate evidence for Chrome, Edge, and Firefox; Safari remains a design item.

See the [Chromium Extension README](README.en.md) for technical setup.
