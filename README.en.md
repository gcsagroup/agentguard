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
- Within supported browser pages, provide limited pre-execution confirmation gates for payment controls, trap forms, and payment-shaped fetch/XHR requests; install DNR network rules for known-malicious or session-out-of-scope hosts, with blocklist management and rule provenance.
- On Linux, use `guard-jail` to provide a narrow kernel-enforced filesystem boundary for processes that AgentGuard launches itself; when a task explicitly declares `scope.net`, Landlock can also constrain TCP connect and bind ports.
- Use `guard-trust` to give six inbound surfaces a shared fail-closed trust vocabulary, and map the current 20 user-facing capability claims to concrete tests and a generated status dashboard.

## Boundaries you must understand

- **It is not zero-gap real-time monitoring.** macOS AX tree changes now use AXObserver push signals, coalescing, and fallback polling; pixel capture and other desktop paths still include sampling or polling, so actions within gaps may be missed.
- **Most controls are cooperative.** An agent that bypasses the gateway and executes directly cannot be stopped by that gateway.
- **It is not a general sandbox, EDR, firewall, or DLP.** Linux `guard-jail` constrains only processes it launches. Its network-port ceiling is opt-in and refuses to launch when declared but not enforceable by the selected backend.
- **Browser controls have explicit scope.** Page gates and DNR can block pre-execution for the vectors they cover, but a malicious page can bypass the page gate and DNR installation fails open. Native Messaging decisions remain asynchronous and cannot retroactively stop the event that triggered them. Android high-risk notices remain post-event.
- The Firefox port and Edge compatibility path exist, but real-browser end-to-end acceptance is still missing; Safari is design-only. The current macOS ad-hoc candidate has passed local startup, TCC probing, and an AXObserver push-flow check, but fresh-install and upgrade acceptance after signing/notarization remain open. Windows candidate `89dadf9` now has partial evidence from real Windows 11 for startup, continuous observation, and the blocking modal, but the W1–W7 checklist, a signed installer, and fresh-install/upgrade/uninstall coverage remain open. iOS remains a limited scaffold not wired to the engine.

The current RC is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. It should not be presented as a mandatory security control for consumers or regulated environments.

## Quick start

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
make acceptance
make check
~~~

macOS development shell:

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

## Documentation

- [Documentation portal](docs/README.en.md)
- [1.0.0-rc.1 release notes](docs/RELEASE-1.0.0-rc.1.en.md)
- [Changelog](CHANGELOG.en.md)
- [Scope and non-goals](docs/scope-and-non-goals.md)
- [Platform capability matrix](docs/platform-matrix.md)
- [Inbound trust](docs/入站信任.en.md)
- [Capability claim-to-test mapping](docs/主张与测试映射.en.md)
- [Browser pre-execution gates](docs/浏览器执行前阻断.en.md)
- [Real-device acceptance runbook](docs/acceptance-runbook.en.md)
- [Structured release evidence](docs/release-evidence.en.md)
- [Historical release-gate design note](docs/release-security.md)
- [Generated attack-surface coverage matrix](eval/coverage-matrix.md)

The key technical and acceptance documents added in this update are available in Simplified Chinese, Traditional Chinese, and English. Other deep technical documents remain in their original languages. The portal labels language, purpose, and status so designs, offline tests, and historical reviews are not mistaken for current real-device or release evidence.

## Repository layout

~~~text
crates/    Rust engine, rules, audit, evaluation, and tools
adapters/  macOS, Windows, Android, and browser adapters
apps/      Desktop apps, Chromium extension, Android companion, and iOS scaffold
docs/      Product boundaries, architecture, release, security, and research documents
eval/      Scenarios, fixtures, coverage claims, and generated reports
~~~

## License

[Apache License 2.0](LICENSE)
