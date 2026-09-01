[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# Changelog

This file records notable AgentGuard changes. Versions follow Semantic Versioning.

## [Unreleased]

### Added

- Adopted the bright D brand direction with shared logo and app-icon masters; refreshed macOS, Windows, Android, and Chromium icons (including menu-bar, adaptive/themed, and notification assets); and added the unified mark to trilingual READMEs, documentation portals, conformance statement, and product headers.
- Added `guard-trust`, giving six inbound trust boundaries a shared constant-time comparison, `InboundOutcome` vocabulary, and inventory test while preserving protocol-appropriate cryptographic primitives and trust anchors.
- Added machine-checkable mappings for the current 20 user-facing capability claims and a dashboard generated from the claims, release gate, and status data. These verify that claim anchors and tests exist; they do not replace real-device acceptance.
- Added an opt-in `scope.net` ceiling to `guard-jail`: on Landlock ABI v4 (Linux kernel 6.7+), only explicitly listed TCP connect/bind ports are allowed. An undeclared ceiling leaves networking unconstrained; a declared but unenforceable ceiling refuses to launch.
- Added limited pre-execution browser confirmation gates for payment CTAs, trap forms, and payment-shaped fetch/XHR calls, plus DNR blocking of known-malicious and session-out-of-scope hosts with persistence/expiry semantics, blocklist management, and rule provenance.
- Added a separate Firefox manifest, packaging path, and Native Messaging host integration scaffold, plus Edge installation compatibility. Safari remains a design item requiring an Xcode wrapper and Swift handler.
- Added AXObserver push signals, 150 ms debounce, an 800 ms maximum latency, and 3 s fallback polling for macOS AX-tree observation. Pixel capture remains sampled.
- Consumerized the macOS, Windows, and Chromium interfaces in three languages, including first-run onboarding, plain-language risk copy, an accessible confirmation layer, keyboard focus handling, dark mode, notifications, and vocabulary-completeness checks.
- Added browser, Windows, and macOS real-device acceptance checklists, an executable runbook, browser fixtures, and a report template. The documents and fixtures define work still to be executed; they are not real-device evidence.

### Security

- Once declared, the network ceiling governs both TCP connect and bind. Empty port lists deny both, and non-Landlock backends cannot silently degrade to open networking.
- Malicious-host DNR entries persist across service-worker restarts, while out-of-scope hosts expire with the session. The popup can inspect, remove, and trace entries to `INTEL-DOMAIN` or `SCOPE-HOST`.

### Changed

- Chromium is no longer described broadly as “post-event only”: page gates and DNR provide pre-execution control for the vectors they cover. Native Messaging decisions remain asynchronous and cannot retroactively stop the triggering event, and both page gates and DNR retain explicit bypass/fail-open boundaries. Android remains post-event.
- Desktop observation is no longer described broadly as “polling only”: macOS AX-tree changes now have push signals. Pixel capture, other desktop paths, and fallback behavior still include sampling or polling, so this is not zero-gap real-time monitoring.

### Fixed

- Fixed Landlock attaching directory-only rights to single-file rules such as `/dev/null`, which made the entire ruleset fail with `EINVAL` before the child could start. Linux integration tests now start in an authorized directory and directly prove allowed reads/writes and genuine out-of-scope denials instead of passing because an unauthorized `/dev/null` redirect failed first.
- Made Windows drive and UNC prefixes compare semantically across normal and `\\?\` verbatim forms. Real `C:\Windows` and `C:\ProgramData` paths are sensitive again, while the fixed `\\?\` namespace marker is no longer mistaken for a wildcard.
- Replaced Windows workspace tests that still treated `/bin/*`, `/srv`, `/tmp`, and `/etc` as cross-platform fixtures. Gateway tests now use a controllable Rust child process for concurrent pipes, UTF-8 truncation, and exit codes; path, shell, and jail tests use genuine platform-specific absolute paths while retaining sensitive-directory and argument-injection coverage.
- Switched the Firefox MV3 package to its supported module `background.scripts` event page. Structural tests now pin the shared `background.js` entry across the Chromium service worker and Firefox event page.
- Preserved rule provenance when reading the blocklist, and replaced `form.submit()` in allow-once replay so constraint validation and submitter semantics are not bypassed; payment-button click→submit chains now share one approval token and no longer prompt twice.
- Wired macOS AXObserver into the desktop driver, attached it to the continuously running main RunLoop, and rebound it as the frontmost application changes; added a product-path wiring test.
- Prevented SQLCipher release builds from crashing on a legacy plaintext SQLite audit database: the original is retained unchanged and the encrypted store uses a separate sibling file.
- Changed extension packaging to build a fresh ZIP and atomically replace the target, preventing `zip` update mode from retaining stale code because of source timestamps.

### Known limitations

- The current macOS ad-hoc candidate has passed local startup, TCC probing, and an AXObserver push-flow check, but fresh-install and upgrade acceptance after Developer ID signing/notarization remain open. Chrome, Edge, Firefox, and Windows still lack candidate real-device E2E; Safari is design-only.
- Page gates cover only page vectors reachable by the installed extension. DNR installation fails open, and neither the Native Host nor Android notifications provide unbypassable pre-execution control.

## [1.0.0-rc.1] - 2026-08-28

> This is a source release candidate, not evidence that production installers are ready. Code signing, notarization, store publication, and real-device end-to-end acceptance are incomplete. The production release decision remains **No-Go**.

### Added

- A cross-platform Rust rule engine with OP, TR, and FM privacy scoring, task plans, and capability-scope decisions.
- macOS observation through AXUIElement, ScreenCaptureKit, and Vision OCR.
- Windows UI Automation, GDI capture, and Windows.Media.Ocr implementation.
- An Android AccessibilityService companion, environment survey, and Android Keystore P-256 adapter signatures.
- A Chromium MV3 extension, Native Messaging host, high-risk decision notifications, and pre-execution control over limited page vectors and blocklisted hosts.
- A cooperative MCP tool gateway and a kernel-enforced Linux `guard-jail` filesystem boundary.
- Ed25519 threat intelligence, hash-chained audit records, optional per-record signatures, and SQLCipher.
- A Bearer-protected local API, signed policy sync, and authenticated billing webhooks.
- Offline evaluation, a coverage matrix, preflight checks, and a release-evidence gate.
- Core README files, documentation portals, release notes, and changelogs in Simplified Chinese, Traditional Chinese, and English.

### Security

- Release paths reject `sha256:` integrity digests when threat-intelligence authenticity requires a signature.
- Native Messaging caller identity is fail-closed by default.
- Sensitive filesystem targets can no longer be approved through confirmation. Gateway filesystem operations reach independent engine decisions; verifiable audit records require the host to attach an audit store and signer.
- Path normalization, symbolic-link handling, macOS volume aliases, root mount namespaces, and read-scope handling were hardened.
- Audit-witness inclusion, session counts, key-file permissions, frontend DOM writes, and CSP were hardened.
- Policy sync and billing webhooks now verify signatures when crossing trust boundaries.

### Changed

- Documentation now distinguishes out-of-band observation, cooperative controls, and the Linux kernel-enforced boundary.
- Android confirmation remains a post-event notification. Chromium page gates and DNR provide pre-execution control only within their limited coverage; Native Messaging decisions remain asynchronous.
- Windows moved from a simulated scaffold to real UIA/GDI/OCR implementation while retaining the limitation that real-device acceptance is missing.
- `guard-ffi` is explicitly marked as an experimental component with no in-repository consumer.
- Release documentation no longer treats source, tests, builds, and production-installer evidence as the same state.

### Known limitations

- Apart from Linux `guard-jail`, most controls depend on the agent voluntarily routing through AgentGuard and can be bypassed.
- macOS AX-tree changes now have push signals, but pixel capture, other desktop observation, and fallback behavior still include sampling or polling and are not zero-gap real-time monitoring.
- Android cannot block before an action occurs. Chromium can do so only for vectors covered by its page gates and DNR, which does not support a claim of general or unbypassable control.
- Windows lacks real-device end-to-end acceptance. iOS is a limited scaffold without a complete project or engine wiring.
- Repository fixture keys must not be used in production and must be replaced before deployment.
- Signed and notarized installers and real-device acceptance evidence are missing, so the strict release gate cannot pass.

See the [1.0.0-rc.1 release notes](docs/RELEASE-1.0.0-rc.1.en.md) for the full scope and revalidation requirements.
