[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="assets/brand/agentguard-logo.png" alt="AgentGuard logo" width="160">
</p>

# AgentGuard

AgentGuard is a local-first observation and audit system for third-party GUI agents. It analyzes screens, accessibility trees, forms, deep links, tool calls, and egress metadata, then produces auditable risk decisions.

> **Current status: `1.0.0-rc.1` is a source release candidate, not a production installer release.**
> This repository does not yet contain the code-signing, notarization, store-publication, or real-device end-to-end acceptance evidence required for this release. The production release decision remains **No-Go**.

## What it can do

- Collect available interface or event signals on macOS, Windows, Android, and Chromium paths.
- Detect prompt injection, transparent or invisible content, UI-tree and screen divergence, privacy over-disclosure, suspicious deep links, and critical actions.
- Store local audit records with a hash chain and optional signatures; support signed threat intelligence and optional SQLCipher.
- Execute, deny, or hold for human confirmation when an agent voluntarily routes a tool call through the MCP gateway.
- On Chrome / Edge pages supported by the first GA, block matching payment controls and trap forms before execution, with no in-page release; enable static DNR hard blocks for requests that match the declared payment keywords, HTTP(S), non-GET/HEAD methods, and resource types.
- On Linux, use `guard-jail` to provide a narrow kernel-enforced filesystem boundary for processes that AgentGuard launches itself; when a task explicitly declares `scope.net`, Landlock can also constrain TCP connect and bind ports.
- Use `guard-trust` to give six inbound surfaces a shared fail-closed trust vocabulary, and map the current 36 user-facing capability claims to concrete tests and a generated status dashboard.

## Boundaries you must understand

- **It is not zero-gap real-time monitoring.** macOS AX tree changes now use AXObserver push signals, coalescing, and fallback polling; pixel capture and other desktop paths still include sampling or polling, so actions within gaps may be missed.
- **Most controls are cooperative.** An agent that bypasses the gateway and executes directly cannot be stopped by that gateway.
- **It is not a general sandbox, EDR, firewall, or DLP.** Linux `guard-jail` constrains only processes it launches. Its network-port ceiling is opt-in and refuses to launch when declared but not enforceable by the selected backend.
- **Browser controls have explicit scope.** Risky DOM actions are block-only with no in-page release. The page notice is only a page-influenceable information layer; a user who insists on continuing must disable or remove protection from the browser's extension-management page and independently repeat the action. Static DNR does not inspect bodies or cover custom aliases and other undeclared surfaces, and Native Messaging is disabled in the GA manifest. Android high-risk notices remain post-event.
- The first-GA browser package supports Chrome / Edge only. Firefox remains a source prototype and is neither packaged nor an acceptance gate. iOS WebShield/Safari Extension is a separate Xcode/Swift limited SKU in the first-release product scope, not a future option. An older ad-hoc macOS candidate passed local checks, and historical Windows candidate `89dadf9` has partial evidence, but neither makes the current candidate distributable. Current signing/notarization, install/upgrade/uninstall, and real-device evidence remain open. iOS builds and has unsigned Simulator evidence, but is not wired to the Rust engine; production signing, real-device Safari, and TestFlight remain open.
- **What each platform actually observes is defined by the generated [docs/capability-matrix.en.md](docs/capability-matrix.en.md).** "Analyzes deep links" above is an engine capability (the offline corpus and adapter format carry `deeplink` events); no shipped observer on any platform emits a deep-link event on a real device today — Android reports deep-link-shaped strings in on-screen text only.

The current RC is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. It should not be presented as a mandatory security control for consumers or regulated environments.

## Quick start

~~~bash
make bootstrap-rust
./scripts/bootstrap-rust.sh -- cargo test --workspace
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- eval --scenarios eval/scenarios
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- coverage
./scripts/bootstrap-rust.sh -- make capability-claims
./scripts/bootstrap-rust.sh -- make check-extension-gate
./scripts/bootstrap-rust.sh -- make acceptance
./scripts/bootstrap-rust.sh -- make check
~~~

macOS development shell:

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

**After installation:** see the [desktop guide](docs/desktop-guide.en.md). macOS includes a five-page workspace, four settings tabs, browser setup and gateway confirmation. Accessibility is required; capture is optional. Self-test verifies a simulated alert, not prevention of an external action.

Connect a gateway's current port and token to review, deny or approve only its current request. Expiry and disconnection never automatically approve. This does not verify a specific MCP client integration. See the [remediation and verification note](docs/remediation-publication-2026-09-06.en.md).

## Documentation

- [Documentation portal](docs/README.en.md)
- [Desktop guide](docs/desktop-guide.en.md)
- [Mail-client and webmail protection design (not implemented)](docs/mail-protection-design.en.md)
- [1.0.0-rc.1 release notes](docs/RELEASE-1.0.0-rc.1.en.md)
- [Changelog](CHANGELOG.en.md)
- [Scope and non-goals](docs/scope-and-non-goals.md)
- [Platform capability matrix](docs/platform-matrix.md)
- [Inbound trust](docs/入站信任.en.md)
- [Capability claim-to-test mapping](docs/主张与测试映射.en.md)
- [Browser pre-execution gates](docs/浏览器执行前阻断.en.md)
- [Real-device acceptance runbook](docs/acceptance-runbook.en.md)
- [Structured release evidence](docs/release-evidence.en.md)
- [GA release-closure gate](docs/ga-release-gate.en.md)
- [Historical release-gate design note](docs/release-security.md)
- [Generated attack-surface coverage matrix](eval/coverage-matrix.md)

The key technical and acceptance documents added in this update are available in Simplified Chinese, Traditional Chinese, and English. Other deep technical documents remain in their original languages. The portal labels language, purpose, and status so designs, offline tests, and historical reviews are not mistaken for current real-device or release evidence.

## Repository layout

~~~text
crates/    Rust engine, rules, audit, evaluation, and tools
adapters/  macOS, Windows, Android, and browser adapters
apps/      Desktop apps, Chromium extension, Android companion, and limited iOS Safari WebShield
docs/      Product boundaries, architecture, release, security, and research documents
eval/      Scenarios, fixtures, coverage claims, and generated reports
~~~

## License

[Apache License 2.0](LICENSE)
