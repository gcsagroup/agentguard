# Roadmap completion checklist

Generated against the 24-week plan. **Windows real-device UIA/Graphics Capture testing is explicitly deferred.**

Product version: **1.0.0-rc.1**

## Phase 1 — Foundation
- [x] Monorepo + crates
- [x] guard-privacy + MyPhoneBench mapping
- [x] P0 rules + audit + eval
- [x] Win adapter **simulation** + Tauri Dashboard
- [ ] Win **real** UIA/Capture validation — **DEFERRED**

## Phase 2 — Desktop GA
- [x] macOS Menu Bar + TCC + AX + SCK frame pipeline + capture/netmon UI inject
- [x] ScreenCaptureKit ObjC native bridge (`sck-probe` / `sck-start`, stats-only)
- [x] Menu Bar SCK start/stop/poll + **1.5s auto-poll** + tray actions
- [x] Overlay heuristics (`guard-overlay`)
- [x] Chromium extension + Native Messaging + Store package script
- [x] Threat Intel Ed25519 + CDN fetch
- [x] ≥20 eval scenarios + scoreboard
- [x] Network egress metadata (`guard-netmon` + CLI)
- [x] desktop-windows Phase 2 parity (entitlement / policy sync / netmon / intel reload)

## Phase 3 — Android + v1.0
- [x] android-adapter + companion app scaffold
- [x] Android eval scenarios
- [x] Pro entitlement + billing webhook apply
- [x] Local HTTP billing webhook receiver (`billing-webhook-serve`)
- [x] Play Store listing draft + release signingConfig
- [x] Platform matrix + iOS limited SKU scaffold

## Phase 4 — Productize
- [x] Aura-lite safe shell (`guard-shell`)
- [x] guard-ffi C ABI
- [x] Enterprise policy sync POC + desktop sync button
- [x] Eval methodology + CI scoreboard/leaderboard
- [x] Multi-agent privacy leaderboard (`eval/agents` + HTML)
- [x] Local billing entitlement + Stripe-like webhook JSON
- [x] Session summary report (`audit-report` + desktop 导出摘要)
- [x] Optional SQLCipher audit encryption (`--features sqlcipher`)
- [x] Expanded agent profiles (9 profiles, one shared probe suite)
- [x] Loopback local API with Bearer token (`api-serve`)
- [x] **1.0.0-rc.1** cut (`docs/RELEASE-1.0.0-rc.1.md`)
- [x] macOS acceptance gate (`make acceptance` + `docs/acceptance-macos.md`)
- [x] macOS release / notarize scaffolding (`docs/macos-release.md`)
- [x] Release security defaults (`docs/release-security.md`)
- [x] Privacy policy aligned with SCK / audit / intel / local API
- [x] Honest TCC coverage banner (sim / partial / full)
- [x] desktop-windows release security parity
- [x] Form schemas + AX→FormFill classify (paper-gap P0)
- [x] UI revalidate (pop-up/TOCTOU) + A2 invisible-zone heuristic
- [x] Android companion local risk + envelope jsonl sink
- [x] Live AXUIElement frontmost capture (`ax-probe` / `ax-snapshot` / Menu Bar)
- [x] Desktop UiTreeDelta → `process_with_revalidate`

## Iter 6 (paper-gap)
- [x] MyPhoneBench §2.4 TR normalized by trap population
- [x] MyPhoneBench §2.4 composite over evaluated dimensions only (`|D|`)
- [x] MyPhoneBench §2.5 `task_success` + real PQSR in eval / scoreboard / acceptance
- [x] (A)I Sees A7 shell-injection screening + argv construction (`guard-shell`)
- [x] AgentScan Viewtree Interference: AX↔OCR cross-validation (OVL-009 / OVL-010)
- [x] (A)I Sees A4 chroma stego detection (OVL-011)
- [x] (A)I Sees A1 wide opacity band (8–20 %)
- [x] (A)I Sees A2 display geometry (rounded corners + cutouts, OVL-012)
- [x] `eval` / `scoreboard` load the known-app registry (was a false FAIL)
- [x] Aura pillar iv: **signed** audit records — `audit-keygen` / `audit-verify
      --pubkey [--allow-unsigned] [--head-witness]`, `audit-migrate`, receipt
      `actor` + `audit_id`, `log_id`/`seq` binding, read-only verification,
      `user_decision`↔receipt cross-check, `AuditSigner` seam for Secure Enclave.
      See docs/audit-signing.md
- [ ] Hardware-backed `AuditSigner` (Secure Enclave / TPM) + external append-only
      anchor — a local key file cannot survive a compromised host, and truncation
      is only caught by the out-of-band head witness
- [x] (A)I Sees A5 / A6 Android channel monitors (`EnvironmentScanner`,
      `EventType::EnvironmentSurvey`, `ENV-A5` / `ENV-A6` / `ENV-INPUT-OBSERVED`)
      — see docs/android-env-survey.md
- [ ] A5 runtime-registered receivers (manifest receivers only today)
- [x] (A)I Sees A4 frame integrity: `framehash` grid digest + `OVL-013` + signed
      `frame_digest` + `guard-cli frame-digest` — see docs/frame-integrity.md
- [ ] On-demand double capture (the ~2 FPS stream cannot see a 50 ms TOCTOU window)
- [x] Verified per-surface coverage matrix (`make coverage`, 30 surfaces) +
      `kind: attack|benign` tagging + paired miss-rate / false-positive-rate
- [ ] Agent-in-the-loop ASR/TSR (needs real agents + sampling)
- [x] Every agent profile exercising a privacy dimension (shared probe suite; `make leaderboard` fails otherwise)
- [x] Aura §4.3.1 information-flow lattice: inheritance, No-Write-Down, HITL declassification (`docs/information-flow.md`; still `partial` — declared flows only)
- [x] Verified app identity by signing-certificate pinning, AgentScan §3.5 (`docs/app-identity.md`; still `partial` — Android only, digest trust sits in the adapter)
- [x] Aura pillar (i) agent identity: Ed25519 identity cards, session attestation with replay defence, card-level capability boundary, audit attribution (`docs/agent-identity.md`; still `partial` — session-level not per-action, no mutual attestation)
- [x] Aura §4.3.2 plan-trajectory alignment: executed-step state, scope/budget/order/completion conformance, drift latch + re-anchoring (`docs/trajectory-alignment.md`; still `partial` — no per-action justification against the instruction)
- [x] AgentScan §3.7 text anomalies: invisible characters (incl. the Unicode tag block), bidi overrides, Latin/Cyrillic homoglyphs, combining stacks, oversized tokens, published glitch tokens; `FW-TEXT-ANOMALY` + `on_text_anomaly` (`docs/text-anomalies.md`; still `partial` — the glitch-token list is a tripwire, not coverage, and an image of anomalous text is §3.6's problem — of which iteration 19 built the app-identity half, not the rendered-text half)
- [x] AgentScan §3.6 image forgery for app identity: confusable-folded display labels and a 64-bit icon difference hash compared against the registry's declared appearance, with the package's own entry excused **per channel** and only when its identity is verified; `APP-LOOKALIKE`, `APP-FACE-UNPROVEN`, `APP-FACE-UNREADABLE`, `guard-cli icon-dhash` (`docs/app-lookalike.md`; still `partial` — Android only and bounded by package visibility, exact clones only, the icon channel cannot intervene at a measured 6.6% false-match rate so the corpus reports a 1.1% attack-miss rate rather than 0.0%, containment and all but two typo shapes deliberately not matched, four-letter Latin names below the information floor, registry hashes are fixtures, Kotlin producer untested)
- [x] Identity channel from the companion actually reaching the engine: `signer_sha256` / `attest_error` / `app_label` / `icon_dhash` forwarded through an explicit allow-list on `AndroidEvent`, plus a source-scanning test that fails when the companion writes a key the adapter cannot receive. Fixes a defect that made §3.5 signer pinning **inert on every real device** for six iterations while the docs described it as shipped.
- [x] AgentScan §3.8 log hygiene: one redactor at every egress carrying observed text, a source-scanning test that fails when a sink forgets it, `READ_LOGS` holders reported as `ENV-LOG-READABLE`, and `Rule::event_types` so a page cannot forge an environment finding (`docs/log-hygiene.md`; still `partial` — no logcat monitoring, Kotlin untested on device, content markers still forgeable)
- [x] Aura pillar (ii) semantic firewall: checksum-verified structural entity recognition feeding the ingest label, origin-tagged isolation envelope with total escaping, `FW-BREAKOUT` for envelope/turn forgery, `agentguard isolate` / `scan-content` (`docs/semantic-firewall.md`; still `partial` — not NER, isolation advisory since the guard does not assemble the prompt, no adapter transmits field values, the label raise needs a `value_id` no adapter emits, and encoding evasions defeat recognition)

- [x] Aura §4.4 session-scoped least privilege: a per-session resource grant over apps, profile keys and destination hosts, with the ceiling in the operator's plan and the session's declaration able only to narrow it; `APP-NOT-IN-TASK`, `SCOPE-DATA`, `SCOPE-HOST`, `SCOPE-OVER-REQUEST`, and the grant recorded in the `SESSION-START` audit row (`docs/session-scope.md`; still `partial` — an unscoped profile has no ceiling, three dimensions rather than Aura's domains-plus-semantic-permissions, the request channel is unauthenticated, minimality is expressible but not provable, no time bound)
- [x] Closed a bypass in the mechanism above: the `task_apps` check lived in `with_transition_guard`, reachable from four event arms, so `ui_tree_delta` — the event every adapter emits most — had never been checked against the task's app set since iteration 3. Which event types the app grant judges is now an exhaustive match with a test that pins it.

## Deferred / external
- Windows real UIA + Graphics Capture on hardware/RDP
- Live payment provider endpoints (out of scope for free launch)
- Live Chrome Web Store / Play Console publication (packaging ready)
- Apple Developer ID signing / notarization (scripted; needs credentials)
- Android ↔ desktop confirm IPC
