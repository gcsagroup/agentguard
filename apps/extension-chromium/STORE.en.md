# Chrome Web Store Listing Draft

[简体中文](STORE.md) · [繁體中文](STORE.zh-TW.md) · English

> **Draft only; not submitted to or approved by the Chrome Web Store.** This copy is not evidence of publication, review, or real-browser acceptance.

## Name

AgentGuard Web Shield

## Summary

Find prompt injection, privacy traps, unnecessary personal data, and payment prompts on pages used by AI agents, with local records and alerts.

## Description

AgentGuard Web Shield checks HTTP/HTTPS pages the user visits for:

- hidden text and prompt-injection markers;
- unnecessary personal-data fields and privacy-trap widgets; and
- payment, transfer, and other high-risk CTA text.

Findings stay in the extension by default. After the user installs and enables the optional `guard-nm-host`, matching events go to that standalone local process. The host loads AgentGuard rules, evaluates events, and writes its own audit database; the desktop app does not need to be running.

When the host returns a High/Critical, Block, or confirmation-worthy result, the extension displays a browser notification and updates its badge. This is an **asynchronous notification**: it may appear before or after a user action, but the verdict is not synchronously bound to a specific action, so the extension cannot pause, undo, or prevent web actions. Engine pause state affects only subsequent event decisions.

## Privacy

- Browsing history is not uploaded to AgentGuard servers by default.
- Without an installed or enabled Native Messaging host, findings remain in the extension-local buffer.
- With the host enabled, matching events go to the user's local `guard-nm-host` process.
- The host audit database remains local by default. Audit signing and encryption require explicit user configuration and must not be assumed enabled.
- See the [privacy policy](../../docs/privacy-policy.en.md).

## Permission justification

- `storage`: stores settings and the local recent-findings buffer.
- `nativeMessaging`: optionally connects to the user-installed local `guard-nm-host`.
- `notifications`: displays high-risk verdicts after the event.
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
- Critical notifications are not pre-action confirmation or browser-action interception.

See the [Chromium Extension README](README.en.md) for technical setup.
