[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

Release date: 2026-08-28

> **This is a source release candidate, not a production installer release.**
> Code signing, notarization, store publication, and real-device end-to-end acceptance are not complete. The production release decision remains **No-Go**.

These notes include subsequent source updates on the candidate branch. The version remains `1.0.0-rc.1`; no new installer has been produced or published as a result.

> **`1.0.0-rc.1` is the version string written in the source tree, not something that has been released.** There is no matching git tag and no signed artifact in the repository; everything merged after the date above (the D brand scheme, the P0/P1/P2 remediation from the real-device report) lives in the source tree that carries this version string. These notes therefore describe "the current source carrying this version", not a frozen snapshot — they move with the source. Every figure of the form "what a platform observes, how many tests, how many capability claims, which version" is owned by the generated [docs/capability-matrix.en.md](capability-matrix.en.md); these notes no longer keep their own copy.

## Positioning

This candidate is intended for research and evaluation, development or staging, and controlled internal pilots with informed operators. AgentGuard primarily provides out-of-band observation, risk decisions, and accountable audit records. The tool gateway is a bypassable cooperative control; browser block-only DOM gates and static DNR provide pre-execution blocking over limited vectors; and Linux `guard-jail` provides a narrow kernel boundary for processes it launches itself.

## Highlights

- A cross-platform Rust rule engine with OP, TR, and FM privacy scoring, task plans, and capability-scope decisions. `guard-trust` gives six inbound surfaces a shared fail-closed trust vocabulary and inventory check.
- macOS observation through AXUIElement, ScreenCaptureKit, and Vision OCR. AX-tree changes now use AXObserver push signals, coalescing, and fallback polling; pixel capture remains sampled.
- Windows UI Automation, GDI capture, and Windows.Media.Ocr implementation; real-device acceptance is still missing.
- An Android AccessibilityService companion, environment survey, and Android Keystore P-256 adapter signatures.
- The first-GA browser scope is one shared Chrome/Edge Chromium MV3 ZIP: consumerized trilingual UI, block-only payment/trap DOM gates, and static DNR for explicit payment-shaped URLs. There is no in-page allow or replay, and the GA manifest has no Native Messaging permission.
- Firefox remains a source prototype only: it is not packaged, submitted, or used as a first-GA acceptance gate. Safari is a separate product path.
- A buildable Swift-first iOS Safari WebShield limited SKU with a container app, Safari Web Extension, shared Core, and automated tests. It is not wired to the Rust engine and does not replace release signing, real-device Safari, or TestFlight acceptance.
- A cooperative MCP tool gateway and Linux `guard-jail` filesystem constraints with an opt-in `scope.net` TCP-port ceiling.
- Hash-chained audit records, optional per-record signatures and SQLCipher, Ed25519 threat intelligence, a local API, signed policy sync, and authenticated billing webhooks.
- The bright D logo and cross-platform app icons; trilingual macOS, Windows, and Chromium interfaces with first-run onboarding, plain-language risks, accessible risk/block notices that reflect each path's actual enforcement boundary, keyboard operation, and dark mode.
- Machine-checkable mappings from user-facing capability claims to proving tests (count in [capability-matrix.en.md](capability-matrix.en.md)), a generated status dashboard, reproducible offline evaluation, an attack-surface coverage matrix, preflight checks, and a release-evidence gate.
- Chrome/Edge, Windows, macOS, and iOS acceptance checklists, a Firefox exclusion notice, an executable real-device runbook, browser fixtures, and a report template. They define how acceptance must be run; they do not mean formal candidate acceptance has completed.

## Security hardening

- Release paths reject `sha256:` integrity digests when authenticity requires a threat-intelligence signature.
- Caller identity in the repository Native Messaging prototype is fail-closed; the first-GA browser package does not request that permission. Billing, policy sync, the local API, threat intelligence, and adapter assertions follow one principle: unverified inbound data must not cross the trust boundary.
- Sensitive filesystem targets cannot be approved through a confirmation prompt. Gateway filesystem operations reach independent engine decisions; verifiable audit records require the host to attach an audit store and signer.
- Once declared, `scope.net` allows only listed TCP connect/bind ports. Empty lists deny all such operations, and an unenforceable backend refuses to launch rather than silently opening networking.
- The first-GA browser uses manifest static DNR rules for its explicitly supported payment requests. Upgrade clears legacy Native/dynamic-scope state; unavailable capability fails closed and the popup hides the unavailable entry.
- Path normalization, symbolic-link handling, macOS volume aliases, root mount namespaces, audit-witness inclusion, and frontend injection/CSP issues were hardened.
- Key files are created with restricted permissions, and unsafe permissions or symbolic-link paths are rejected.

## Verification baseline

The repository contains offline scenarios, attack-surface coverage claims, and machine-checkable mappings from capability claims to concrete tests (the current count, the events each platform actually emits and the static test counts are in the generated [capability-matrix.en.md](capability-matrix.en.md)). `docs/status-dashboard.html` is generated from capability claims, the release gate, and status data; it is not a hand-written conclusion.

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

A production release must also satisfy the strict gate with all twelve code-signing, notarization, and real-device evidence kinds. Passing the soft gate cannot replace that evidence. No complete set is currently bound to one frozen candidate, so the decision remains **No-Go**.

## Explicitly incomplete

- Properly signed macOS, Windows, Android, and iOS candidate artifacts.
- macOS notarization and stapling.
- An older ad-hoc macOS candidate passed local startup, TCC probing, and an AXObserver push-flow check, but the latest universal `.app` has not completed the full current rerun. Fresh-install, upgrade, and TCC acceptance after Developer ID signing/notarization also remain open. Current-candidate real-device E2E is still missing on Windows and Android.
- Chrome and Edge have not separately completed B1–B5 clean-profile installation, upgrade, rollback, and store evidence for the same formal candidate ZIP. Source-level real-Chromium E2E cannot replace these two independent strict gates. Firefox is outside first-GA scope.
- iOS has a buildable limited SKU and unsigned Simulator evidence, but no Apple Distribution candidate, I1–I6 real-device Safari Extension evidence, or TF1–TF3 TestFlight evidence. It is also not wired to the Rust engine.
- Production publication to the App Store / TestFlight, Chrome Web Store, or Google Play.
- Kernel-level jails on macOS and Windows.
- A mandatory network-egress proxy.
- iOS Rust-engine wiring and any cross-app/system observation beyond the limited SKU; the current Safari Extension covers only the documented web-DOM scope.

Android high-risk notices occur after the event. Chromium’s DOM gate covers declared frames, ordinary DOM, and open Shadow DOM; a page can remove the notice but cannot use that to authorize or replay an action. Closed Shadow DOM, browser-native actions, and unrecognized page shapes remain outside the claim. Static DNR covers only declared HTTP(S) methods, payment URL keywords, and resource types; it cannot infer business meaning from an encrypted body. macOS AX-tree changes have push signals, but pixel capture and fallback behavior retain sampling/polling boundaries. Apart from the narrow Linux `guard-jail` constraint on processes it launches, most controls depend on the agent or page passing through AgentGuard and must not be described as general or unbypassable protection.

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
