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

- Candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0` completed interactive RDP validation on Windows 11 build 26200: it stayed idle for more than 30 seconds, completed two observation sessions of more than 30 seconds each, reported UIA, GDI, and OCR as available, and actually triggered an `OVL-010` block.
- The 5/5 desktop tests, Clippy, Release build, and CI window-startup smoke test all passed.
- The candidate is unsigned, and the default Release build does not include SQLCipher. Install/upgrade/uninstall, permission-failure paths, Native Messaging, and the full W1–W7 suite remain unverified, so production release remains **No-Go**.
- Observation polls at approximately 2.5 seconds and is not real-time monitoring. Critical Confirm constrains only operations that use a cooperative entry point.
- The system-tray, startup-recovery, and notification lifecycles are not yet complete.

## Verification

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path src-tauri/Cargo.toml --release --locked
node --check src/main.js
```

Full Windows real-device supplement: [Simplified Chinese](../../docs/acceptance-report-windows-2026-09-02.md) | [Traditional Chinese](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md). See [`../../docs/windows-observation.md`](../../docs/windows-observation.md) and [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md) for platform capabilities and limits.
