# AgentGuard Windows

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

This is the AgentGuard Tauri 2 client for Windows. It connects Windows UI Automation, GDI window capture, and `Windows.Media.Ocr` to the local rules and audit layers.

## Run locally

```powershell
cd apps/desktop-windows
npm ci
npm run tauri dev
```

## Current status

- Native UIA, window-capture, and OCR code is implemented and compiled and tested in Windows CI.
- Representative Windows hardware, RDP, permission-change, and code-signing acceptance are not complete. A CI build is not production-release evidence.
- Observation polls at approximately 2.5 seconds and is not real-time monitoring. Critical Confirm constrains only operations that use a cooperative entry point.
- The system-tray, startup recovery, and notification lifecycle is not yet complete.

## Verification

```powershell
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

See [`../../docs/windows-observation.md`](../../docs/windows-observation.md) and [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md) for platform capabilities and limits.
