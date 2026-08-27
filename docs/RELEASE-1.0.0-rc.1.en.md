[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

Release date: 2026-08-28

> **This is a source release candidate, not a production installer release.**
> Code signing, notarization, store publication, and real-device end-to-end acceptance are not complete. The production release decision remains **No-Go**.

## Positioning

This candidate is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. AgentGuard primarily provides out-of-band observation, risk decisions, and accountable audit records. The tool gateway is a bypassable cooperative control, while Linux `guard-jail` provides one narrow kernel-enforced filesystem boundary.

## Highlights

- A cross-platform Rust rule engine with OP, TR, and FM privacy scoring, task plans, and capability-scope decisions.
- macOS observation through AXUIElement, ScreenCaptureKit, and Vision OCR.
- Windows UI Automation, GDI capture, and Windows.Media.Ocr implementation; real-device acceptance is still missing.
- An Android AccessibilityService companion, environment survey, and Android Keystore P-256 adapter signatures.
- A Chromium MV3 extension, Native Messaging host, and post-event high-risk notifications.
- A cooperative MCP tool gateway and Linux `guard-jail` filesystem constraints.
- Hash-chained audit records, optional per-record signatures and SQLCipher, Ed25519 threat intelligence, a local API, signed policy sync, and authenticated billing webhooks.
- Reproducible offline evaluation, an attack-surface coverage matrix, preflight checks, and a release-evidence gate.

## Security hardening

- Release paths reject `sha256:` integrity digests when authenticity requires a threat-intelligence signature.
- Native Messaging caller identity is fail-closed by default.
- Sensitive filesystem targets cannot be approved through a confirmation prompt. Gateway filesystem operations reach independent engine decisions; verifiable audit records require the host to attach an audit store and signer.
- Path normalization, symbolic-link handling, macOS volume aliases, root mount namespaces, audit-witness inclusion, and frontend injection/CSP issues were hardened.
- Key files are created with restricted permissions, and unsafe permissions or symbolic-link paths are rejected.

## Verification baseline

The repository records the following baseline for this candidate:

- 130 offline scenario files;
- 104 acceptance checks;
- 30 published attack surfaces: 13 covered, 16 partial, and 1 uncovered.

These figures are the checked-in repository baseline, **not proof that this publication run has revalidated them**. Before publishing the current commit, rerun:

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make check
make release-gate
~~~

A production release must also satisfy the strict gate with code-signing, notarization, and real-device evidence. Passing the soft gate cannot replace that evidence.

## Explicitly incomplete

- Properly signed macOS, Windows, and Android installers.
- macOS notarization and stapling.
- Real-device end-to-end acceptance on macOS, Windows, and Android.
- Production publication to the App Store, Chrome Web Store, or Google Play.
- Kernel-level jails on macOS and Windows.
- A mandatory network-egress proxy.
- A complete iOS project wired to the engine.

Android and Chromium high-risk notices occur after the event, not before execution. Apart from Linux `guard-jail`, most controls depend on the agent voluntarily routing through AgentGuard and must not be described as unbypassable protection.

## Related documentation

- [Documentation portal](README.en.md)
- [Changelog](../CHANGELOG.en.md)
- [Release security and evidence gate](release-security.md)
- [Platform capability matrix](platform-matrix.md)
- [Generated attack-surface coverage matrix](../eval/coverage-matrix.md)
