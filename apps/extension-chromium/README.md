# AgentGuard Chromium Extension

Detects:

- Hidden / prompt-injection text in the DOM
- Optional PII overfill
- Privacy-trap widgets
- Payment CTA text

## Load unpacked

1. `chrome://extensions` → Developer mode → Load unpacked
2. Select `apps/extension-chromium`
3. Copy the extension ID

## Native Messaging (optional)

```bash
cargo build -p guard-nm-host
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
```

The host is **fail-closed on caller identity**: it verifies the origin Chrome passes (`argv[1]`)
against an expected value and **refuses to start** if it has none. `install-host.sh` writes that
value to an `allowed-origin` file next to the host binary; you can also set
`AGENTGUARD_ALLOWED_ORIGIN`. Without either, any local process could speak the protocol and inject a
forged `source_app` into the signed audit — so an unconfigured host does not run.

Toggle “转发到桌面端” in the popup. Without a registered host, findings stay in the extension’s local buffer.

## Offline payload test

```bash
cargo run -p guard-cli -- ingest-browser \
  --payload eval/fixtures/browser_extension_payload.json
```
