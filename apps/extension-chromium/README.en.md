# AgentGuard Chromium Extension

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

This Manifest V3 extension checks pages for hidden or prompt-injection text, unnecessary personal-data fields, privacy traps, and payment or transfer actions. It synchronously holds matching clicks, submissions, and payment-shaped `fetch`/XHR calls in the page until the user decides. DNR rules can also stop judged-malicious or out-of-scope hosts before a request leaves the browser. Findings stay in an extension-local buffer by default; an optional Native Messaging host adds engine evaluation and audit records.

> Capability boundary: the in-page gate covers only main-frame DOM actions the extension can reach and `fetch`/XHR references that the page did not capture first. It is not an unbypassable browser sandbox. Native Messaging verdicts remain asynchronous and only notify or affect later state; pre-action control comes from the page gate and successfully installed DNR rules.

## Load unpacked

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select `apps/extension-chromium`.
4. Record the extension ID assigned by Chrome; the Native Messaging installer needs it.

Edge uses the same directory and package through `edge://extensions`. On Firefox 128+, open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select `manifest.firefox.json`. The Firefox port still requires real-browser acceptance.

The extension ships `en`, `zh_CN`, and `zh_TW` UI resources and allows a popup-level language override.

## Package

From the repository root:

```bash
./apps/extension-chromium/scripts/package-store.sh
./apps/extension-chromium/scripts/package-store.sh --firefox
```

The default command writes the Chrome/Edge package `agentguard-extension.zip`; `--firefox` writes `agentguard-extension-firefox.zip`. Neither package contains the Native Messaging host. Store review, privacy disclosure, and per-browser acceptance remain separate release gates.

## Optional standalone Native Messaging host

`guard-nm-host` is a standalone local process. It loads rules, evaluates events, and writes its own audit database; the AgentGuard desktop app does not need to be running. The host and desktop may use the same audit location when `AGENTGUARD_AUDIT_DB` is explicitly configured. Audit signing and encryption require `AGENTGUARD_AUDIT_SIGNING_KEY` and `AGENTGUARD_AUDIT_KEY`; neither should be assumed enabled by default.

Development install on macOS or Linux:

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
# Edge
./apps/extension-chromium/native-host/install-host.sh --browser edge <EXTENSION_ID>
# Firefox
./apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

The installer:

- builds `guard-nm-host`;
- writes Chrome's Native Messaging manifest; and
- writes `chrome-extension://<EXTENSION_ID>/` to an `allowed-origin` file beside the host binary.

The helper currently supports macOS and Linux only and writes the caller format required by the selected browser. Windows requires manual Native Messaging manifest installation; this repository has no Windows installer.

### Caller identity fails closed

The Chrome manifest's `allowed_origins` constrains Chrome, but not another local process that directly executes the host. The host therefore reads the actual origin Chrome supplies in `argv[1]` and compares it byte-for-byte with:

1. `AGENTGUARD_ALLOWED_ORIGIN`; or
2. the `allowed-origin` file beside the binary.

If neither expected value exists, Chrome supplies no origin, or the values differ, the host refuses to start with exit code 2. This prevents an arbitrary local process from injecting a forged `source_app` into the audit path.

## Pre-action gates, network rules, and asynchronous verdicts

The in-page gate evaluates payment CTAs, privacy-trap forms, and payment-shaped `fetch`/XHR calls in the capture path. It holds the action first and replays it only after **Allow once**. DNR rules derived from engine verdicts and the session allowlist block matching requests before they leave, with visible reasons and an unblock control in the popup.

Findings can also be sent asynchronously to the host. High/Critical, Block, or `require_confirm` verdicts produce notifications, update the badge, and enter the recent-results buffer. A "paused" response only means the engine refuses later events. This host path cannot undo an action that already occurred and must not be presented as the page gate's approve-then-proceed control.

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
- The page gate is a best-effort client control. A previously captured original `fetch`, a clean iframe, cross-frame actions, or native-app behavior can bypass it.
- DNR fails open when rules cannot be installed. Chrome, Edge, and Firefox still require separate real-browser acceptance; Safari remains a design item.

See the [privacy policy](../../docs/privacy-policy.en.md) and [store-listing draft](STORE.en.md).
