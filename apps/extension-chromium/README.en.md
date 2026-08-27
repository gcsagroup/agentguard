# AgentGuard Chromium Extension

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

This Manifest V3 extension checks browser pages for hidden or prompt-injection text, unnecessary personal-data fields, privacy-trap widgets, and payment or transfer CTA text. Findings stay in an extension-local buffer by default. An optional Native Messaging host can pass them to a local AgentGuard engine for evaluation.

> Capability boundary: the extension observes DOM changes and page content asynchronously. Critical or Block verdicts raise browser notifications and badges. A notification may appear before or after a user action, but the verdict is not synchronously bound to a specific action and cannot pause, undo, or prevent web actions.

## Load unpacked

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select `apps/extension-chromium`.
4. Record the extension ID assigned by Chrome; the Native Messaging installer needs it.

The extension ships `en`, `zh_CN`, and `zh_TW` UI resources and allows a popup-level language override.

## Package

From the repository root:

```bash
./apps/extension-chromium/scripts/package-store.sh
```

The default output is `apps/extension-chromium/dist/agentguard-extension.zip`. The script packages only extension files, not the Native Messaging host. Store review, privacy disclosure, and real-browser acceptance remain separate release gates.

## Optional standalone Native Messaging host

`guard-nm-host` is a standalone local process. It loads rules, evaluates events, and writes its own audit database; the AgentGuard desktop app does not need to be running. The host and desktop may use the same audit location when `AGENTGUARD_AUDIT_DB` is explicitly configured. Audit signing and encryption require `AGENTGUARD_AUDIT_SIGNING_KEY` and `AGENTGUARD_AUDIT_KEY`; neither should be assumed enabled by default.

Development install on macOS or Linux:

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
```

The installer:

- builds `guard-nm-host`;
- writes Chrome's Native Messaging manifest; and
- writes `chrome-extension://<EXTENSION_ID>/` to an `allowed-origin` file beside the host binary.

The helper currently supports macOS and Linux only. Windows requires manual Native Messaging manifest installation; this repository has no Windows installer.

### Caller identity fails closed

The Chrome manifest's `allowed_origins` constrains Chrome, but not another local process that directly executes the host. The host therefore reads the actual origin Chrome supplies in `argv[1]` and compares it byte-for-byte with:

1. `AGENTGUARD_ALLOWED_ORIGIN`; or
2. the `allowed-origin` file beside the binary.

If neither expected value exists, Chrome supplies no origin, or the values differ, the host refuses to start with exit code 2. This prevents an arbitrary local process from injecting a forged `source_app` into the audit path.

## Verdict and notification semantics

The extension converts local findings into browser events and sends them asynchronously to the host. High/Critical, Block, or `require_confirm` verdicts produce notifications, update the badge, and enter the recent-results buffer.

A "paused" response means the AgentGuard engine will refuse subsequent events. Host verdicts arrive asynchronously and are not bound to one specific web action. This path has no approve-then-proceed dialog and must not be described as browser-action interception.

When the host is missing, unregistered, or disabled, findings remain in the extension-local buffer but receive no engine verdict. The popup's native-relay toggle disables Native Messaging.

## Offline payload check

From the repository root:

```bash
cargo run -p guard-cli -- ingest-browser \
  --payload eval/fixtures/browser_extension_payload.json
```

## Privacy and limits

- Browsing history is not uploaded to AgentGuard servers by default.
- When Native Messaging is enabled, matching page findings go to the local host; local configuration determines its audit path and protections.
- The extension has `http://*/*` and `https://*/*` host permissions so its content script can run on pages the user visits.
- This is a DOM heuristic observer, not a network filter, browser sandbox, or unbypassable control.

See the [privacy policy](../../docs/privacy-policy.en.md) and [store-listing draft](STORE.en.md).
