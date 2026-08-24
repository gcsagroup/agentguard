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

Toggle “转发到桌面端” in the popup. Without a registered host, findings stay in the extension’s local buffer.

## Offline payload test

```bash
cargo run -p guard-cli -- ingest-browser \
  --payload eval/fixtures/browser_extension_payload.json
```
