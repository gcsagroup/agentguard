[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

Release date: 2026-08-28

> **This is a source release candidate, not a production installer release.**
> Code signing, notarization, store publication, and real-device end-to-end acceptance are not complete. The production release decision remains **No-Go**.

These notes include subsequent source updates on the candidate branch. The version remains `1.0.0-rc.1`; no new installer has been produced or published as a result.

## Positioning

This candidate is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. AgentGuard primarily provides out-of-band observation, risk decisions, and accountable audit records. The tool gateway is a bypassable cooperative control; browser page gates and DNR provide pre-execution control over limited vectors; and Linux `guard-jail` provides a narrow kernel boundary for processes it launches itself.

## Highlights

- A cross-platform Rust rule engine with OP, TR, and FM privacy scoring, task plans, and capability-scope decisions. `guard-trust` gives six inbound surfaces a shared fail-closed trust vocabulary and inventory check.
- macOS observation through AXUIElement, ScreenCaptureKit, and Vision OCR. AX-tree changes now use AXObserver push signals, coalescing, and fallback polling; pixel capture remains sampled.
- Windows UI Automation, GDI capture, and Windows.Media.Ocr implementation; real-device acceptance is still missing.
- An Android AccessibilityService companion, environment survey, and Android Keystore P-256 adapter signatures.
- A Chromium MV3 extension, Native Messaging host, consumerized trilingual UI, payment/trap/fetch-XHR page gates, and DNR blocking of malicious or out-of-scope hosts with management and rule provenance.
- A Firefox port and packaging scaffold, an Edge compatibility path, and an explicit Safari design boundary. These browser paths do not yet have real-environment end-to-end acceptance.
- A cooperative MCP tool gateway and Linux `guard-jail` filesystem constraints with an opt-in `scope.net` TCP-port ceiling.
- Hash-chained audit records, optional per-record signatures and SQLCipher, Ed25519 threat intelligence, a local API, signed policy sync, and authenticated billing webhooks.
- The bright D logo and cross-platform app icons; trilingual macOS, Windows, and Chromium interfaces with first-run onboarding, plain-language risks, an accessible confirmation layer, keyboard operation, and dark mode.
- Machine-checkable mappings for the current 20 user-facing capability claims, a generated status dashboard, reproducible offline evaluation, an attack-surface coverage matrix, preflight checks, and a release-evidence gate.
- Firefox, Windows, and macOS acceptance checklists, an executable real-device runbook, browser fixtures, and a report template. They define how acceptance must be run; they do not mean acceptance has completed.

## Security hardening

- Release paths reject `sha256:` integrity digests when authenticity requires a threat-intelligence signature.
- Native Messaging caller identity is fail-closed by default. Billing, policy sync, the local API, threat intelligence, adapter assertions, and Native Messaging follow one principle: unverified inbound data must not cross the trust boundary.
- Sensitive filesystem targets cannot be approved through a confirmation prompt. Gateway filesystem operations reach independent engine decisions; verifiable audit records require the host to attach an audit store and signer.
- Once declared, `scope.net` allows only listed TCP connect/bind ports. Empty lists deny all such operations, and an unenforceable backend refuses to launch rather than silently opening networking.
- Browser malicious-host entries persist across service-worker restarts, out-of-scope entries expire with the session, and the popup shows their triggering rules. DNR installation still fails open and does not claim a block that was not installed.
- Path normalization, symbolic-link handling, macOS volume aliases, root mount namespaces, audit-witness inclusion, and frontend injection/CSP issues were hardened.
- Key files are created with restricted permissions, and unsafe permissions or symbolic-link paths are rejected.

## Verification baseline

The repository contains offline scenarios, attack-surface coverage claims, and machine-checkable mappings from the current 20 capability claims to concrete tests. `docs/status-dashboard.html` is generated from capability claims, the release gate, and status data; it is not a hand-written conclusion.

Any generated figures and statuses are snapshots of the commit on which they were produced, **not proof that this publication run has revalidated them**. Before publishing the current commit, rerun:

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
make check-shells
make dashboard
make check
make release-gate
~~~

A production release must also satisfy the strict gate with code-signing, notarization, and real-device evidence. Passing the soft gate cannot replace that evidence.

## Explicitly incomplete

- Properly signed macOS, Windows, and Android installers.
- macOS notarization and stapling.
- The current macOS ad-hoc candidate has passed local startup, TCC probing, and an AXObserver push-flow check; fresh-install and upgrade acceptance after Developer ID signing/notarization remain open. Candidate real-device E2E is still missing on Windows and Android.
- Real-browser end-to-end acceptance on Chrome, Edge, and Firefox. Firefox DNR quotas and the Native Messaging gecko-id path still require calibration.
- Production publication to the App Store, Chrome Web Store, or Google Play.
- Kernel-level jails on macOS and Windows.
- A mandatory network-egress proxy.
- A Safari extension project and Swift Native Messaging handler; Safari is currently design-only.
- A complete iOS project wired to the engine.

Android high-risk notices occur after the event. Chromium page gates and DNR can control pre-execution behavior for the vectors they cover, but a malicious page can bypass the page gate, DNR installation fails open, and Native Messaging decisions remain asynchronous. macOS AX-tree changes have push signals, but pixel capture and fallback behavior retain sampling/polling boundaries. Apart from the narrow Linux `guard-jail` constraint on processes it launches, most controls depend on the agent or page passing through AgentGuard and must not be described as general or unbypassable protection.

## Related documentation

- [Documentation portal](README.en.md)
- [Changelog](../CHANGELOG.en.md)
- [Release security and evidence gate](release-security.md)
- [Platform capability matrix](platform-matrix.md)
- [Inbound trust](入站信任.en.md)
- [Capability claim-to-test mapping](主张与测试映射.en.md)
- [Browser pre-execution gates](浏览器执行前阻断.en.md)
- [Real-device acceptance runbook](acceptance-runbook.en.md)
- [2026-09-01 acceptance report](acceptance-report-2026-09-01.en.md)
- [Generated attack-surface coverage matrix](../eval/coverage-matrix.md)
