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
- On Linux, use `guard-jail` to provide a narrow kernel-enforced filesystem boundary for processes that AgentGuard launches itself.

## Boundaries you must understand

- **It is not real-time monitoring.** Desktop observation includes polling, so actions between polls may be missed.
- **Most controls are cooperative.** An agent that bypasses the gateway and executes directly cannot be stopped by that gateway.
- **It is not a general sandbox, EDR, firewall, or DLP.** Linux `guard-jail` is the only narrow boundary that does not depend on cooperation from the constrained party.
- **Android and Chromium high-risk notices happen after the event; they are not pre-execution blocks.**
- Native Windows observation is implemented and covered by CI, but has no real-device end-to-end acceptance evidence. iOS remains a limited scaffold that is not wired to the engine.

The current RC is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. It should not be presented as a mandatory security control for consumers or regulated environments.

## Quick start

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
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
- [Release security and evidence gate](docs/release-security.md)
- [Generated attack-surface coverage matrix](eval/coverage-matrix.md)

Deep technical documents remain in their original languages. The portal identifies their language, purpose, and status so historical review records are not mistaken for the current release decision.

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
