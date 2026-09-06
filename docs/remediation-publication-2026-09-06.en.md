[简体中文](remediation-publication-2026-09-06.md) | [繁體中文](remediation-publication-2026-09-06.zh-TW.md) | [English](remediation-publication-2026-09-06.en.md)

# Cross-platform remediation source submission (2026-09-06)

This submission consolidates earlier cross-platform remediation, the macOS workspace and authenticated gateway confirmation. **It is a source-review candidate, not an installer release; production remains No-Go.** Private reports, screenshots, device identifiers, credentials, build output and test data are excluded.

## Changes and usage

- Shared engine/path validation, confirmation lifecycle, encrypted/signed audit recovery and structured release gates.
- Five-page macOS workspace, four settings tabs and setup guides. Accessibility is required; capture is optional. Gateway approval is separate from post-event desktop alerts and binds the process and current request. Expired, duplicate, mismatched or disconnected requests do not auto-approve.
- Windows observation/resource wiring, Android session/privacy state, a limited iOS Safari WebShield project and platform-specific tests and release boundaries.
- Independent Chrome/Edge block-only protection and static DNR; no in-page one-time approval, replay or GA Native Messaging. Firefox is source-only.

Follow the [desktop guide](desktop-guide.en.md). The app can probe its bundled gateway and generate configuration without editing your MCP client. Connect the running gateway's local port and current token in the app, review the request and deny or approve only that request. Tokens are not saved and connections do not automatically resume. Approval acceptance is not execution success; check the caller.

Write requests show the target and byte count, not full file contents. Verified calling-client identity and a unified gateway history page are not provided. This is cooperative protection, not an unavoidable system boundary.

## Verification

The final local arm64/SQLCipher/ad-hoc app was operated before publication integration: denial produced no file, approval wrote only afterward, and timeout/disconnection produced no file. The caller was a dedicated real stdio test client, not the user's actual MCP client. Permissions and signing evidence do not transfer to a rebuilt identity.

The isolated publication checkout reruns Rust workspace tests, macOS backend tests, 62 renderer checks, desktop dialogs, extension checks, Android Debug/Release unit tests and lint, and iOS Simulator/unsigned-build checks. The PR and commit-specific CI record actual results; static test counts are not pass counts.

```bash
./scripts/bootstrap-rust.sh -- cargo test --workspace --locked
make check-shells check-extension-gate
node eval/ui-preview/workspace.test.mjs
make shell-a11y
make check-android
make check-ios
```

Use the pinned Rust, Node 22, JDK 21 and platform SDKs. Playwright renderer checks explicitly stub the backend. Real gateway side-effect tests require a built `agentguard-mcp`, `AGENTGUARD_GATEWAY_TEST_BIN`, and the macOS backend `gateway_confirm` filter with `--include-ignored`. CI includes both types.

Actual-client integration, continuous observation under the final signed identity, signing/notarization, real-device Safari/TestFlight, installation/upgrade/rollback and channel acceptance remain open. Unsigned device builds are not device execution; historical Windows interaction is not current-candidate qualification. See [release evidence](release-evidence.en.md).
