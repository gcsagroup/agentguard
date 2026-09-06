[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# Changelog

This file records notable AgentGuard changes. Versions follow Semantic Versioning.

## [Unreleased]

### Cross-platform remediation source integration (2026-09-06)

- Integrated shared-core, encrypted-audit and confirmation-lifecycle remediation with existing desktop, mobile and browser-extension changes. Added trilingual [submission notes](docs/remediation-publication-2026-09-06.en.md) stating validation scope and outstanding gates.
- Added workspace UI regressions and real MCP gateway file-side-effect tests to CI; aligned permission claims, proving-test mappings and generated capability matrices.
- At the maintainer's request, the source-review candidate was subsequently integrated into `main` using the repository's SSH identity, with remote and local branches consolidated. Local credentials, raw reports and build output are excluded. No installer release; production remains No-Go.

### macOS workspace and active-protection entry points (2026-09-06)

- Added authenticated local gateway confirmations with request-specific deny/review-before-approve, deadlines and disconnect handling. Tokens are transient, never saved or auto-reconnected; first answers win and expired/duplicate answers fail. Real temporary files verify no denial side effects and writes only after approval.
- Added overview, active protection, activity, four-tab settings, and help/diagnostics; language, appearance and next-session task preferences are stored locally.
- Separated required Accessibility from optional capture; exposed the actual app identity and permission feedback, and enforced required permission in the start command.
- Bundled the Chrome/Edge test extension, harmless fixture and platform MCP gateway. Setup performs a real handshake and generates token-free configuration without granting broad directory access.
- Acceptance builds have a separate fixed app name/identifier; ad-hoc rebuilds still require permission checks. Actual client integration and signed release acceptance remain incomplete. This is not a cross-platform UI or release-ready claim.
- Updated all three desktop guides and corrected misleading prevention claims and unauthenticated confirmation examples.

### Remediation of the real-device report (2026-08-31, plus the 2026-09-02 Windows supplement)

Handled item by item under the report's P0 / P1 / P2 numbering, each with red-green-mutation tests; the parts that can only happen on real devices, certificates or store accounts remain marked unverified — see [docs/release-evidence.en.md](docs/release-evidence.en.md).

- **P0-1 gate forgery**: twelve release-evidence kinds are now structurally validated (bound to the full commit, real command, exit code, criterion output and artifact identity). iOS Apple Distribution, iOS real-device, TestFlight, Chrome, and Edge add independent fail-closed gates; keyword-only files are refused.
- **Layered RC / GA gates**: `--strict` is fixed at 12 RC technical evidence kinds. `--ga` adds SBOM/license, privacy/store declarations, a 14-day Beta, dual RCs, five-party sign-off, six-channel smoke, and 5%→25%→100% rollout, for 19 kinds total. Firefox is excluded from the first GA; real GA closure material is currently missing, so the status remains No-Go.
- **P0-2 two CI root causes**: Windows extension-path fallback; a stale trailing argument in the Landlock `prctl` call.
- **P0-3 / P0-5 sessions and confirmations**: the confirm queue is keyed by `request_id` (race removed); observers really stop at session end; the protection state is derived by a state machine from "session + observer + heartbeat + writable audit" (active / degraded) instead of "a session is open, so we are guarding"; the Windows observer is bound to the session with a generation number and backs off into degraded on failure.
- **P0-4 machine-checkable real-device criteria**: the shells write JSONL under `AGENTGUARD_ACCEPTANCE_TRACE`; `guard-cli acceptance-trace-check` runs six checks against the audit database; macOS cases 15–17 and Windows W8–W10 plus the required-evidence lists are synchronised in three languages.
- **P1-1 / P1-2 / P1-3 extension**: Native Messaging forwarding is off by default and queues fail-closed until settings load; outbound and local URLs are minimised; a long-lived host connection with backoff, persisted pause state; per-connection nonce + monotonic seq reject replay and reordering.
- **P1-4 background Critical**: a pending confirmation brings the window forward and counts in the menu bar / title; two minutes without a decision is a refusal with a Timeout receipt; pending confirmations are persisted and receipted one by one after a restart. No system-level notifications yet.
- **P1-6 Android**: guard / relay state comes from a state machine; process restart fails closed and requires the user to start a new session instead of auto-resuming observation; an ordinary ongoing notification reflects only the currently bound session; the token lives in the Keystore and is never echoed; event JSONL rotates at 14 days / 20 files / 50 MiB / 5 MiB, with a clear button.
- **P1-7 Local API / webhook**: the audit database defaults to a private directory and refuses symlinks and shared-writable directories; request bodies capped at 256 KiB, `limit` at 1000; tokens masked; webhooks must carry `event_id / created_ms / version` — idempotent, ±10 minutes, monotonic version.
- **P1-8 / P1-9**: the CI signing step performs and verifies a real ad-hoc signature on a stand-in artifact; device policy is installed only after signature verification, only ever tightens, and unverified policy is displayed but not enforced.
- **Windows supplement**: the observer skips AgentGuard's own window by pid; OVL-010 requires unrendered text to look like an instruction; a W6 force-unavailable switch; W7 `install-host.ps1` (not yet executed on a real machine).
- **P2-1 coverage**: iMy `ask_user` enters the engine as a `user_query` event (USER-QUERY / PRIV-GUESS), closing the last uncovered surface; duplicate glyphs in the icon corpus fixed and the channel measurement re-derived.
- **P2-3 alert storms**: desktop observation dedupe (`event_dedup`, same content once per 30 s, a one-character change passes immediately) and the UI-REVALIDATE cross-source root cause fixed; extension finding dedupe, incremental scanning and a 1.5 s throttle, with a mutation-storm regression M1–M4 in the real-browser E2E.
- **P2-4 accessibility and localisation**: desktop dialog `alertdialog` + focus trap + Esc + focus restore + live region; Android TalkBack and other system services no longer count as "input observed"; Traditional Chinese resources corrected; launcher label localised.
- **P2-5 documentation drift**: a trilingual [docs/capability-matrix.en.md](docs/capability-matrix.en.md) generated from source (events each platform actually emits, static test counts, version strings), compared byte for byte under `cargo test`; Android copy no longer says it "observes deep links" (it reports deep-link-shaped strings in on-screen text; the code never emits `deeplink`); the iOS page now says what exists today versus the target; the release notes and this file no longer keep their own claim counts.
- **P2-6 reproducibility and supply chain**: `rust-toolchain.toml`, `.nvmrc`, Actions pinned to commit SHAs; both desktop-shell lockfiles pass cargo-deny separately under `deny.shells.toml` (per-crate MPL-2.0 exceptions pending legal review).
- **P2-7 commercial boundary**: enterprise features unlock only for a vendor-Ed25519-signed licence (expiry required, 7-day offline grace, signed revocation list); HMAC / webhook / fixture-signed entitlements show as demo and do not unlock.
- **Stage D cloud preparation**: a real-browser Chromium E2E (39 machine checks) with a trilingual `acceptance-chrome.en.md`; deterministic Windows W3–W5 fixtures with a rendering-contract test; an Android adb acceptance script; the Local API exposes the signature verdict for every signed body.

**Still unverified (needs your side)**: Developer ID signing and notarization, Authenticode, the Android release key, iOS Apple Distribution, and current-candidate strict evidence for macOS / Windows / Android / iOS / TestFlight / Chrome / Edge. Chrome and Edge each require B1–B5; Firefox is outside the first GA and cannot receive a release PASS.


### Added

- Adopted the bright D brand direction with shared logo and app-icon masters; refreshed macOS, Windows, Android, and Chromium icons (including menu-bar, adaptive/themed, and notification assets); and added the unified mark to trilingual READMEs, documentation portals, conformance statement, and product headers.
- Added `guard-trust`, giving six inbound trust boundaries a shared constant-time comparison, `InboundOutcome` vocabulary, and inventory test while preserving protocol-appropriate cryptographic primitives and trust anchors.
- Added machine-checkable mappings from user-facing capability claims to proving tests (current count in the generated [docs/capability-matrix.en.md](docs/capability-matrix.en.md)) and a dashboard generated from the claims, release gate, and status data. These verify that claim anchors and tests exist; they do not replace real-device acceptance.
- Added an opt-in `scope.net` ceiling to `guard-jail`: on Landlock ABI v4 (Linux kernel 6.7+), only explicitly listed TCP connect/bind ports are allowed. An undeclared ceiling leaves networking unconstrained; a declared but unenforceable ceiling refuses to launch.
- Added limited pre-execution browser confirmation gates for payment CTAs, trap forms, and payment-shaped fetch/XHR calls, plus DNR blocking of known-malicious and session-out-of-scope hosts with persistence/expiry semantics, blocklist management, and rule provenance.
- Firefox retains only a separate source-prototype manifest and Native Messaging host integration scaffold, plus Edge installation compatibility; the first GA does not package, submit, or accept Firefox. iOS Safari now has a buildable limited Swift project/SKU, while Apple Distribution signing, physical-device Safari Extension acceptance, TestFlight, and Rust-engine integration remain open.
- Added AXObserver push signals, 150 ms debounce, an 800 ms maximum latency, and 3 s fallback polling for macOS AX-tree observation. Pixel capture remains sampled.
- Consumerized the macOS, Windows, and Chromium interfaces in three languages, including first-run onboarding, plain-language risk copy, an accessible confirmation layer, keyboard focus handling, dark mode, notifications, and vocabulary-completeness checks.
- Added Chrome/Edge, Windows, macOS, Android, and iOS acceptance checklists, an executable runbook, browser fixtures, and a report template. The documents and fixtures define work still to be executed; they are not real-device evidence.
- Recorded historical partial real-device acceptance for Windows candidate `89dadf9`: desktop tests 5/5, Clippy with `-D warnings`, and the Release build passed on Windows 11 build 26200; the unsigned EXE has SHA-256 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`. Independent RDP interaction evidence covers two sessions of more than 30 seconds each, continuous observation, available UIA/GDI/OCR status, a real `OVL-010` post-observation risk confirmation, and stable second-session operation after rejection, with no new Event 1000. It does not prove that the external action was blocked and is not complete current `first-ga-v1` W1–W6/W8–W11 acceptance.
- The first-GA strict gate now has templates and verification for twelve structured release-evidence kinds. Evidence binds the full current commit, actual command, exit code, timestamp, criterion output, and artifact identity. Regular release files use standard SHA-256; macOS/iOS `.app` tree-v2 binds the complete bundle's paths, types, lengths, contents, and Unix `0111` executable-bit masks; acceptance closure-v1 binds the report bytes plus every unique per-case reference's path, length, and content. Five signing kinds bind `signer` to an externally supplied Apple Team ID or release-certificate SHA-256, while seven acceptance kinds fix it to `null`. The Firefox kind remains only for legacy/future format compatibility and is outside first-GA strict. Paths use portable-ASCII components and per-case references cannot be reused; untouched templates, empty or missing artifacts, self-references, symbolic links, and digest mismatches cannot pass. Tree-v2 does not bind other mode bits, xattrs, or ACLs and does not replace isolated-machine quarantine, Gatekeeper, and first-launch acceptance; an acceptance closure remains unsigned self-attestation that cannot prove screenshot provenance.

### Security

- Once declared, the network ceiling governs both TCP connect and bind. Empty port lists deny both, and non-Landlock backends cannot silently degrade to open networking.
- Malicious-host DNR entries persist across service-worker restarts, while out-of-scope hosts expire with the session. The popup can inspect, remove, and trace entries to `INTEL-DOMAIN` or `SCOPE-HOST`.
- The strict gate no longer accepts an arbitrary file containing a keyword. Signing and acceptance commands must use the verifier's complete fail-closed success chains, so a failing subcommand cannot be masked by later output. All five signing kinds must also retain tool output and the externally expected Team ID or certificate SHA-256, and the gate compares the same clean candidate commit before and after it runs. Structured JSON remains unsigned self-attestation: it addresses mistaken binding, operator mistakes, and some mechanical forgeries, not fabrication of every field by an attacker who controls the workspace.

### Changed

- Chromium is no longer described broadly as “post-event only”: page gates and DNR provide pre-execution control for the vectors they cover. Native Messaging decisions remain asynchronous and cannot retroactively stop the triggering event, and both page gates and DNR retain explicit bypass/fail-open boundaries. Android remains post-event.
- Desktop observation is no longer described broadly as “polling only”: macOS AX-tree changes now have push signals. Pixel capture, other desktop paths, and fallback behavior still include sampling or polling, so this is not zero-gap real-time monitoring.
- Windows CI now adds a real-window startup smoke after the existing workspace tests, adapter build/Clippy, and desktop tests; the candidate's GitHub Actions run `33551495621` was fully green. The smoke only catches an immediate window-startup exit and does not replace manual `first-ga-v1` W1–W6/W8–W11 interaction evidence.

### Fixed

- Fixed Landlock attaching directory-only rights to single-file rules such as `/dev/null`, which made the entire ruleset fail with `EINVAL` before the child could start. Linux integration tests now start in an authorized directory and directly prove allowed reads/writes and genuine out-of-scope denials instead of passing because an unauthorized `/dev/null` redirect failed first.
- Fixed the Landlock `prctl(PR_SET_NO_NEW_PRIVS)` call omitting the three trailing arguments that the kernel requires to be zero, which could return `EINVAL`. It now uses the complete five-argument syscall, selects the correct `prctl` syscall number on Linux x86_64 and aarch64, and preserves existing single-file access filtering.
- Fixed the aarch64 mount-namespace fallback using the x86_64 `getuid`/`getgid` syscall numbers. It now selects architecture-correct numbers and pins the fallback identity with real-syscall regression coverage.
- Fixed `guard-cli` overflowing the default Windows main-thread stack before entering a subcommand. The Windows entry point now runs the same CLI dispatch with an explicit 8 MiB stack. On Windows, release-gate argument tests resolve GitHub Runner's absolute `C:\shells\gitbash.exe` path and fall back to Git's default installation path on ordinary Windows; they then enter the repository through the native `current_dir` API and bind both the script's exit code 2 and its rejection text, so WSL, path, or CLI startup failures cannot masquerade as security rejections.
- Made Windows drive and UNC prefixes compare semantically across normal and `\\?\` verbatim forms. Real `C:\Windows` and `C:\ProgramData` paths are sensitive again, while the fixed `\\?\` namespace marker is no longer mistaken for a wildcard.
- Preserved component-aware Windows path normalization and the existing protection of home, `ProgramData`, and `Program Files (x86)`. No lossy global shape folding that would weaken those protections was adopted.
- Replaced Windows workspace tests that still treated `/bin/*`, `/srv`, `/tmp`, and `/etc` as cross-platform fixtures. Gateway tests now use a controllable Rust child process for concurrent pipes, UTF-8 truncation, and exit codes; path, shell, and jail tests use genuine platform-specific absolute paths while retaining sensitive-directory and argument-injection coverage.
- Fixed Windows desktop startup initializing UI Automation as MTA on the main thread before STA-dependent `OleInitialize`, which caused `RPC_E_CHANGED_MODE` and immediate exit. Startup capability probing now runs on a dedicated thread and caches the result, leaving the window main thread unmodified.
- Fixed a possible `0xC0000005` when the WinRT OCR `FactoryCache` was reused after a short-lived capability-probe thread exited. A process-lifetime `CoIncrementMTAUsage` cookie now keeps the COM MTA available, backed by cross-thread COM/OCR regression tests.
- Switched the Firefox MV3 source-prototype manifest to its supported module `background.scripts` event page. Structural tests pin the shared `background.js` entry across that prototype and the Chromium service worker, but the first GA does not produce a Firefox package.
- Preserved rule provenance when reading the blocklist, and replaced `form.submit()` in allow-once replay so constraint validation and submitter semantics are not bypassed; payment-button click→submit chains now share one approval token and no longer prompt twice.
- Wired macOS AXObserver into the desktop driver, attached it to the continuously running main RunLoop, and rebound it as the frontmost application changes; added a product-path wiring test.
- Made SQLCipher plus a working audit signer one fail-closed startup contract in both desktop Release shells. macOS stores the two secrets in Keychain; Windows uses distinct DPAPI envelope types. Legacy plaintext DB/WAL/SHM/key material is preserved and blocks startup instead of silently branching history to a sibling database.
- Bundled macOS rules, task plans, entitlement policy, signed threat intelligence and public key inside the `.app`, with Release loading only signed-bundle resources. Removed unjustified JIT, unsigned-executable-memory and disabled-library-validation entitlements; production signing pins the Team ID and notarization accepts only a Keychain profile.
- Changed extension packaging to build a fresh ZIP and atomically replace the target, preventing `zip` update mode from retaining stale code because of source timestamps.

### Known limitations

- The latest universal macOS `.app` still needs the full current checklist plus Developer ID/notarized clean-install, upgrade, and TCC acceptance. Chrome and Edge need separate clean-profile acceptance for the candidate ZIP; Firefox is outside the first GA. iOS has a compiled limited SKU and simulator evidence but no signed-device evidence. Windows still needs complete current-candidate `first-ga-v1` W1–W6/W8–W11 evidence.
- Page gates cover only page vectors reachable by the installed extension. DNR installation fails open, and neither the Native Host nor Android notifications provide unbypassable pre-execution control.
- Formal macOS/iOS Apple Team IDs and Windows/Android release-certificate SHA-256 values are not yet configured, so all five signing checks remain `UNVERIFIED`. Desktop Release now requires SQLCipher, but the Windows EXE is still `NotSigned`, and there is no production installer or fresh-install, upgrade, or uninstall evidence. Notarization, real-device, and rollback evidence remain incomplete; the production-release decision remains **No-Go**.

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
