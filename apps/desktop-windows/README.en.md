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

- Historical candidate `89dadf960a558d35dc3c6c557eadbc19d3a162d0` completed an interactive RDP smoke run on Windows 11 build 26200: it stayed idle for more than 30 seconds, completed two observation sessions of more than 30 seconds each, reported UIA, GDI, and OCR as available, and displayed an `OVL-010` post-observation risk confirmation. This records only an `effect=observed_only`, `external_action_blocked=false` observation path; it is neither current-candidate acceptance nor proof that an external action was blocked.
- The 5/5 desktop tests, Clippy, Release build, and CI window-startup smoke test all passed.
- The historical candidate is unsigned and did not include SQLCipher. Current source now makes a Release build without `audit-sqlcipher` fail at compile time, but a new secure Release, code signing, install/upgrade/uninstall, permission-failure paths, and the `first-ga-v1` W1–W6/W8–W11 cases still require Windows validation. Production release remains **No-Go**. W7 Native Messaging is a non-GA/legacy optional case and must not restore that permission to the first-GA browser package.
- Windows Release audit now requires both SQLCipher and a preflight-verified signer. The generated database passphrase and Ed25519 signing seed are stored only in separate current-user `agentguard-dpapi-v1` / `agentguard-signing-dpapi-v1` envelopes; this is not TPM-backed. Legacy plaintext DB/WAL/SHM, `audit.key`, and `audit-signing.key` files are preserved unchanged and block startup pending an explicit clear-or-migrate decision.
- The first GA does not publish Windows gateway `run_shell` or file side-effect tools: discovery omits them and forged calls fail before any side effect. This is a capability reduction that avoids the junction/reparse/hard-link TOCTOU path, not host-wide enforcement; direct execution outside the cooperative gateway remains out of scope.
- Observation polls at approximately 2.5 seconds and is not real-time monitoring. Critical Confirm constrains only operations that use a cooperative entry point.
- The system-tray, startup-recovery, and notification lifecycles are not yet complete.

## Verification

```powershell
bash ../../scripts/bootstrap-rust.sh --install
bash ../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
bash ../../scripts/bootstrap-rust.sh -- cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
node --check src/main.js
bash scripts/build-release.sh
```

`scripts/build-release.sh` runs `npm ci` and the Tauri build under repository-pinned Rust 1.95.0,
with `--no-default-features --features audit-sqlcipher --locked`. A direct `cargo build --release`
without that feature now fails by design. The resulting artifacts still require production code
signing and native acceptance.
Native acceptance must also cover current-user DPAPI binding for both envelopes, correct/wrong keys,
legacy plaintext keys being rejected unchanged, DB/WAL/SHM canaries, interrupted recovery, and upgrade/rollback. Cross-compilation and
SQLCipher tests on macOS do not replace that evidence.

Full Windows real-device supplement: [Simplified Chinese](../../docs/acceptance-report-windows-2026-09-02.md) | [Traditional Chinese](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md). See [`../../docs/windows-observation.md`](../../docs/windows-observation.md) and [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md) for platform capabilities and limits.
