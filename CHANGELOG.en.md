[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# Changelog

This file records notable AgentGuard changes. Versions follow Semantic Versioning.

## [Unreleased]

### AGD-030 platform APIs and native file grants (2026-09-16)

- Completed the API, signing, permission, compatibility and device inventory for four platforms, with nine follow-up tickets; current source and historical device evidence remain distinct. See the [platform report](docs/agd-030-platform-api-2026-09-16.zh.md).
- Four native workers signed with the existing organization certificate exercised file bookmarks. Access before activation and new opens after stopping were denied; granted reads/writes succeeded while outside paths and symlinks remained denied. Hard-link, open-descriptor and bookmark-replay limitations were measured and retained. Three invalid inputs and four tampered reports were rejected; 47 artifacts were independently checked.
- Fixed App 021 remains unchanged across 91 files. This API experiment is not an integrated native execution backend. Plan v0.63: 28 complete, one conditional, one in progress, two pending. Performance, Safari AX, deferred F13 and platform release gates remain open.

### Installation alert screenshot recheck (2026-09-16)

- Verified timestamps in fixed App 021, both retained permissions, and seven new low-contrast records classified as LogOnly. Five core, two desktop, and 133 frontend checks passed. Safari displayed the synthetic installation document, but the App's reading of its body remains unproven. No product changes or App rebuild; see the [recheck record](docs/timeline-observation-018-2026-09-16.zh.md).

### AGD-029 fraud research and simulated transaction (2026-09-16)

- Completed two fraud technique proposals, an independent review design, and a deepfake candidate assessment. The real protected Chromium simulation passed 15 checks; 51 audit rows agree with one correct local ledger entry. No deepfake model or real payment was executed. See the [record](docs/agd-029-fraud-review-2026-09-16.zh.md).
- Fixed macOS sandbox cleanup failing with `EPERM` when invoking setuid `ps`, and wait for normal cleanup before exiting. User and directory restrictions remain; four lifecycle checks and 30 browser regressions passed.
- All 91 files in fixed App 021 remain unchanged; these fixes belong to the external gateway source candidate. Plan v0.62: 27 complete, one conditional, one in progress, three pending. Performance, Safari AX, deferred F13, and release gates remain open.

### AGD-028 media preview and native approval (2026-09-16)

- Updated the fixed App in place to Ver 2.1 (021), with full extracted text, provenance, coverage limits and empty pages. Native approval, denial and reopening were verified; both system permissions remained granted. Independent checks cover 3 signed records and 48 audit rows; see the [acceptance record](docs/agd-028-native-media-2026-09-16.zh.md).
- Fixed a separate gateway false positive that treated compact serialized parameters as an oversized token. Text, source and explicit-injection checks and independent approval remain enforced. The fixed App was retested with the final gateway. Six-format regression, 1,530 workspace tests and 17/16/133 UI checks passed; initial failures and candidate boundaries are retained.
- AGD-028 is complete within its limited integration scope; audio/video has a separate 12–18 person-day estimate. Plan v0.61 has 26 complete, 1 conditional, 1 in progress and 4 pending tasks. The App's old packaged gateway was not replaced; AGD-027 performance, F13 and release gates remain open.

### AGD-028 installation-document false positive and model consumption (2026-09-16)

- A real flow found CRIT-005 refusing an ordinary installation document during persistence after successful OCR. Only the trusted memory entrypoint excludes the base installation-text rule; storage still needs independent approval. Execution, self-declared fields, explicit injection and additional policy constraints remain covered, with original failures retained.
- Two parsed images were stored and retrieved across processes for three local-model requests: the installation example and Traditional Chinese amount were correct, while the post-revocation request received no material. Independently verified four signatures and 76 audit rows, rejecting six evidence mutations. Six-format regression, seven memory-focused tests and 1,528 workspace tests passed; see the [record](docs/agd-028-document-model-2026-09-16.zh.md).
- Fixed App 020 was not rebuilt or renamed. This is script-mediated retrieval and model consumption, not autonomous tool selection or native acceptance. Plan v0.60 preserves task counts; AGD-027 performance, native integration and release remain unaccepted, with F13 deferred.

### AGD-028 Chinese OCR and persisted retrieval (2026-09-16)

- Image parsing now uses offline, hash-pinned PP-OCRv5 with bounded working and detection images. English spacing is reconciled only when all non-whitespace characters agree, within the shared 15-second deadline. Parser version 2 continues reading version 1 records without migration.
- All 13 frozen images, including the four original failures, met the original 5% character-error threshold. A stopped OCR child returned unknown and was reaped after about 15.09 seconds. The original 36 component cases, eight entrypoints, six-format gateway flow, two-process Chinese persistence/retrieval and new-candidate container faults passed. Peak memory still reached the limit; OOM and fixture failures remain in the [record](docs/agd-028-chinese-ocr-2026-09-16.zh.md).
- Workspace tests passed 1,525 cases, SQLCipher-feature document tests five, and strict Clippy passed. Chinese evidence independently verified three signatures and 53 audit rows; six report mutations were rejected. App 020 and its 91 files/signature are unchanged. Previous commit 76150f9 passed all 13 CI jobs. Plan v0.59 keeps existing task counts; model/native integration, AGD-027 performance and release remain unaccepted, with F13 deferred.

### AGD-028 parser faults and Chinese OCR evaluation (2026-09-16)

- Two real parser container faults produced dispatched/unknown outcomes with no memory writes. A paused container was removed at the original execution deadline after about 30.13 seconds; explicitly initiated subsequent imports succeeded. Empty PDFs were refused, partial PDFs retained blank-page coverage, and tested external relationships caused no observed side effects.
- Independently verified 5 signatures and 69 audit entries; seven report mutations were rejected. Four clear Chinese images had 11.36%–15.91% character error rates. Language, layout, and official accuracy-model comparisons all missed the original 5% threshold; failures are retained and the product image is unchanged. See the [verification record](docs/agd-028-document-faults-2026-09-16.zh.md).
- Previous commit 8a7a70d passed all 13 GitHub CI jobs. App 020 was not rebuilt and retains its fixed identity. Plan v0.58 remains at 25 complete, 1 conditionally complete, 2 in progress, and 4 pending; F13 remains deferred and release remains No-Go.

### AGD-028 isolated documents in controlled RAG (2026-09-16)

- Six formats now pass path authorization and a host-frozen byte snapshot before parsing in an offline container mounted with only that input. Independent approval binds text, provenance, parser, image and coverage gaps; native execution and client-supplied parsing claims cannot bypass this path.
- A separate material type retains original and extracted digests, extracted line numbers and component locations. Four real CLI processes covered legacy Markdown, denial, restart, revocation and restoration with the original proof. An independent injection document triggered INTEL-INJECT without a memory write.
- Independent verification checked 11 signatures and 218 audit rows; five report tampering cases were rejected. Workspace tests passed 1,524 cases, the gateway library 244, and memory regressions with the SQLCipher feature 21. Failed attempts remain documented in the [gateway record](docs/agd-028-media-rag-2026-09-16.zh.md).
- The macOS synthetic startup timeout in 9d9c833 CI remains recorded. Removed a reproduced reverse-DNS dependency from the loopback fixture without changing the eight-second limit. All 91 App 020 files and its signature remain unchanged. Plan v0.57 retains 25 complete, one conditional, two in progress and four pending; Chinese OCR, resource faults and native acceptance remain outstanding. Release stays No-Go.

### AGD-028 isolated parser component in progress (2026-09-16)

- Added offline PDF, DOCX, XLSX, PPTX, PNG and JPEG parsing with separate original-file and extracted-text digests and explicit coverage limits. Macros, formulas and external relationships are not executed; empty, missing-dependency, malformed and over-limit results do not imply safety.
- Built one fixed document runtime from the existing image using 12 hash-pinned packages and an offline build. Passed 36 component cases in a constrained container and eight real entrypoint cases. Retained the wheel-platform and pixel-limit classification failures.
- Controlled RAG approval, provenance/revocation and fixed-App integration remain pending, as do Chinese OCR, real crash/timeout and native acceptance. See the [component record](docs/agd-028-media-parser-2026-09-16.zh.md). Plan v0.56 retains 25 complete, one conditionally complete, two in progress and four pending tasks.
- AGD-027 now also records 36 owned-container lifecycles; its performance gate remains unmet. Index commit fcc33de passed all 13 GitHub CI jobs. App 020, the existing default image, deferred F13 and release No-Go are unchanged.

### Audit sequence indexes and upgrade compatibility (2026-09-16)

- Removed the full-history scan from each `MAX(seq)` append lookup: 2,048 records now require zero full-scan steps instead of 2,047. Historical signatures, receipts, sequence values and read-only behavior remain intact, including compatibility with databases lacking sequence columns.
- Three real CLI processes (old, indexed, old) passed 51 upgrade/rollback checks, retaining independent review after binary changes. Five real audit-fault scenarios passed another 51 checks. Workspace 1,518 tests, SQLCipher 119 tests and strict Clippy passed.
- The four original-budget runs passed only 4/6, 3/6, 4/6 and 4/6 budgets; performance remains unaccepted. Initial failures are retained. Fixed App 020 was not rebuilt; its timeline display and signature were rechecked. See the [diagnosis and evidence](docs/agd-027-m3-performance-2026-09-16.zh.md). Plan v0.55 retains 25 complete, one conditionally complete, one in progress and five pending tasks. F13 and release status are unchanged.

### AGD-027 joint acceptance in progress (2026-09-16)

- Added a real four-process crash/restart and principal key revocation workflow. Approved memory survives, unapproved content is not stored, the old key fails with valid new-session metadata, and the replacement key succeeds on the same message. Removed principals cannot receive new delegation.
- Independently checked 49 execution audit rows and 17 signature results; four altered evidence cases were rejected. The original 50 complete tasks passed. Fixed App 020, all 91 bundle files and its organization signature are unchanged; no rebuild.
- The 100 cycles, original 30-minute run (30 tasks and 121 heartbeats), 10 browser tasks, 100 browser cycles and F14 virtual-network recovery passed. Independent SQLite checks covered 1,225 browser and 33 F14 audit rows; six report mutations were rejected. Only 4/6 initial performance budgets passed, so joint acceptance remains incomplete. Principal key revocation requires stopping the old host and reloading configuration. See the [record](docs/agd-027-m3-joint-2026-09-16.zh.md); deferred F13 and release No-Go remain unchanged.

- Fixed intermittent macOS governance CI failures caused by accepted test sockets inheriting nonblocking mode. A split-body regression reproduced the failure before the fix; all 134 desktop and 23 repository tests now pass. The change is test-only; App 020 bytes and signature are unchanged.

### AGD-026 native memory and delegation governance (2026-09-16)

- Added source/version inspection, quarantine, revocation, historical restoration and branch stopping. Full previews and single-use approval bind the session and current version; restoration preserves provenance and restrictive labels. Completed external effects are not reversed.
- Fixed App Ver 2.1 (020) passed both native synthetic workflows, with 12 signatures and 48 execution audit rows independently verified. All 88 resources and both macOS permissions were preserved. Switching connections now clears the previous entry count.
- Workspace 1,515, desktop 133, governance UI 16 and SQLCipher-focused 16 tests passed; the new UI regression runs in CI. See the [acceptance record](docs/agd-026-memory-governance-2026-09-16.zh.md). Scope is an explicitly configured local CLI connection; the managed model form does not enable memory/delegation. AGD-027, deferred F13 and release remain unaccepted.

- Source commit `37ce7dc` passed all 13 GitHub CI jobs in run 35033338484, including governance UI regression and Windows window smoke testing.

### Tool registration, frozen packages, and change review (2026-09-15)

- Completed AGD-016: independent registration binds service, namespace, package identity, and manifest digests. Initial external observations require review; changes and revocations invalidate prior action approvals.
- Browser resources run from a frozen copy of verified bytes. Fixed lock ordering between revocation and HTTP dispatch; retained earlier failures.
- Passed 1,326 workspace tests, 122 desktop tests, and 71 live host checks, plus provenance/content regressions. Verified 62 unsigned audit rows. See the [registration record in Simplified Chinese](docs/agd-016-tool-registry-2026-09-15.zh.md). F13 remains deferred and untested; the 010 app is unchanged. AGD-017 is next.

- After the initial CI run, corrected the Windows concurrency fixture and upgraded rustls to 0.23.45 in all three lockfiles for RUSTSEC-2026-0285. Retained failed and repeated verification separately.
- Restricted browser-package runtime compilation to its supported platform while retaining tests on all platforms, fixing strict Linux Clippy.

### Raw, visible, and detection views (2026-09-14)

- Completed AGD-015 with captures from actual file reads/searches, DOM text nodes, and separate stdout/stderr streams. Each view has its own digest; private raw captures are excluded from model responses and audit records.
- Fixed missed detection across DOM node boundaries and the detection-byte limit for a truncated UTF-8 prefix. Retained failed runs; ordinary Unicode and research documents remain readable and cannot grant approval.
- Passed 1,310 workspace tests, 122 desktop tests, 43 Docker checks, 15 provenance regression checks, and 9 live browser tests. See the [content-view record in Simplified Chinese](docs/agd-015-content-views-2026-09-14.zh.md). F13 remains deferred and untested, the 010 app is unchanged, and AGD-016 is next.


### Durable provenance and live tool-output integration (2026-09-14)

- Completed AGD-014 with an exclusive provenance journal, restart recovery, parent-label validation, and shared action bindings across tools and the browser. Self-reported trust grants no authority; provenance failures stop subsequent actions.
- Passed 15 Docker checks, live Chromium integration, 1,302 workspace tests, and 122 desktop tests. AGD-015 raw-content and detection views are next. F13 remains deferred and untested; the 010 app is unchanged. See the [provenance record in Simplified Chinese](docs/agd-014-source-provenance-2026-09-14.zh.md).

### F13 deferral, F14 network recovery, and initial provenance work (2026-09-14)

- Deferred F13 at the user’s request without marking it passed. F14 passed on a Docker VM virtual link using native approvals in the exact 010 app, a live interface disconnect/reconnect, an unknown receipt, 25 seconds without retry, and one explicitly approved submission in a new session. Verified 33 audit rows and 90 unchanged app files.
- Started AGD-014 sensitivity inheritance, host observation, and redacted audit metadata. The three read paths are not connected yet, and AGD-014 is not complete. Original full M1 and release acceptance remain incomplete. See the [record in Simplified Chinese](docs/agd-f14-docker-network-2026-09-14.zh.md).

### Protected local agent and M0/M1 source integration (2026-09-14)

- Integrated local models, controlled workspace snapshots, command and full-diff approvals, host writeback, recovery copies, persistent audit, and dedicated browser sessions; retained read-only defaults and explicit data consent.
- Wait for HTTP completion while approval is pending. New form drafts can be edited without changing the frozen request body or its single-use approval. Refused, timed-out, and unknown actions are not automatically retried.
- Added the threat knowledge base, execution contracts, isolation and normal-task acceptance scripts, plus macOS observation and gateway usability fixes.
- Ver 1.0 (010) has frozen backend results of 60/60 tasks and a 30-minute run, plus separately verified native operations after recorded failures and explicit follow-ups: 3/3 host tests, one browser submission, and both F07 crash phases. This is not a single autonomous combined-task pass.
- See the [source integration record (Simplified Chinese)](docs/agentguard-source-merge-2026-09-14.zh.md) for merge checks and local log locations. F13 real sleep/wake and F14 non-loopback network recovery remain unverified: 12 tasks completed, 1 blocked, 19 not started; production release remains No-Go.
- Fixed Linux Clippy and scenario-registration gaps, premature browser-test rejections on page closure, unsupported Windows journal-lock test assumptions, and unnecessary waits while reading long macOS gateway output. Preserved initial CI failures and follow-up verification logs.
- Pinned knowledge-fixture line endings to LF so Windows checkout preserves registered digests. CI selects the self-contained gateway side-effect test explicitly; manual host-connection acceptance retains its separate prerequisites.

### Experimental webmail protection (2026-09-07)

- Added default-off independent mail settings, Gmail/Outlook candidate DOM checks for selected secrets, recipients, injected instructions and link mismatch in the Chrome/Edge extension. Attachment contents are not scanned; recognized attachment actions are conservatively blocked.
- Added unchanged-extension Chromium tests with synthetic mail and local receiver counts, including minimized records and explicit direct-API bypass checks. Real mailboxes and Edge remain unaccepted; no proxy or approval-based delivery is implemented. This is not a release or comprehensive-coverage claim.

### Combined mail protection design (2026-09-06)

- Added a trilingual [design proposal](docs/mail-protection-design.en.md) covering enterprise mail gateways, webmail and client integrations, permission and privacy boundaries, send-approval binding and mail-specific acceptance cases.
- This update completes only design and local interaction-preview checks. No mail proxy, real account connection or mail-route change is implemented; existing generic tests do not count as mail-protection acceptance.

### Cross-platform CI regression fixes (2026-09-06)

- Fixed capability-matrix output to UTF-8 and reproduced Windows cp1252 pipes in repository tests. Correctly scoped macOS-only adapter code without disabling strict compiler warnings.
- Replaced the stale webhook smoke input with runtime-generated temporary events. Real CLI cases cover acceptance, retries, stale/future timestamps, ordering, missing fields and refunds; the historical fixture and ten-minute replay window remain unchanged.
- Signing CI now verifies that the default release path rejects a missing identity, then explicitly opts into ad-hoc signing for its temporary stand-in. Distribution signing, notarization and release gates remain unchanged.
- Windows packaging assertions tolerate CRLF checkouts while still requiring DPAPI-backed production keys and rejecting plaintext signer fallback.
- Windows encrypted-audit CI explicitly verifies and uses the runner's preinstalled x64 MSVC OpenSSL headers, library and runtime; missing dependencies fail instead of skipping SQLCipher tests.

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
