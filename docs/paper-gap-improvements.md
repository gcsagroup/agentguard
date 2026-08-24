# Paper → product gap improvements (iter 2026-08)

Follow-up to the MyPhoneBench / (A)I Sees / AgentScan / Aura gap review.

Source papers (IDs resolved in iter 6):

| Short name | Paper | arXiv |
|---|---|---|
| MyPhoneBench / iMy | Do Phone-Use Agents Respect Your Privacy? | [2604.00986](https://arxiv.org/abs/2604.00986) |
| (A)I Sees | (A)I Sees What You Don’t: Exploiting New Attack Surfaces in Third-Party Mobile Agents | [2607.00333](https://arxiv.org/abs/2607.00333) |
| AgentScan | From Assistants to Adversaries: Exploring the Security Risks of Mobile LLM Agents | [2505.12981](https://arxiv.org/abs/2505.12981) |
| Aura | Blind Gods and Broken Screens: Architecting a Secure, Intent-Centric Mobile Agent OS | [2602.10915](https://arxiv.org/abs/2602.10915) |

Note: our internal `A1..A4` labels track (A)I Sees, but that paper defines
**A1–A7**. A5 (broadcast input interception) and A6 (credential sniffing) still
have no coverage; A7 is addressed in iter 6.

## Shipped (iter 6, 2026-08-10)

Full pre-iteration gap review: [paper-gap-iter6-review.md](./paper-gap-iter6-review.md).

### Scoring correctness — MyPhoneBench §2.4–2.5 parity was wrong

| Gap (paper) | Change |
|-----|--------|
| TR formula had no trap denominator | `score_trap_resistance` is now `max(0, 1 − \|violations\|/\|traps\|)` over traps **observed** (filled or not), per §2.4. One trap present and filled scores 0.0, not 0.65. Adapters/synthesizers report untouched traps as `value_filled=false` observations so the denominator exists; `TR_PENALTY_PER_TRAP` is gone |
| Composite averaged un-exercised dimensions as a free 1.0 | Dimensions are `Option<f32>`; `privacy(t) = (1/\|D\|) Σ_{d∈D} s_d` over reached dimensions only. `PrivacyScore.dimensions_evaluated` reports `\|D\|`; CLI / scoreboard / leaderboard print `n/a` at `\|D\| = 0` instead of a vacuous 1.000. A FM-only run used to report 0.917 for one violation, now 0.75 |
| PQSR was not computed; no `task_success` anywhere | `PrivacySession.task_success` (from `task_success` on `AgentSessionEnd`, or `Engine::set_task_success`); `qualifies(tau, task_success)` requires the outcome, with `privacy_only_passes(tau)` as the deliberately-differently-named privacy-half check. Eval scenarios take `task_success`, verification kind `privacy_qualified`, and reports carry `pqsr` / `pqsr_tau` / `pqsr_tasks` — `null` when no scenario declares an outcome rather than assuming success |
| Penalty constants attributed to the paper | `scoring.rs` and the mapping doc now state the magnitudes come from the reference `privacy_evaluator.py`; the paper only says penalties grow "progressively larger" |
| `dimension_gte` silently passed on unreached dimensions | Now fails: a threshold on something that never happened is not satisfied |

### (A)I Sees A7 — host-side command injection (20/20 on 4 of 5 agents)

| Gap (paper) | Change |
|-----|--------|
| `guard-shell` was a tool-name allowlist; an allowlisted tool with a poisoned operand passed | Injection screening runs **before** the allowlist: `;` `\|` backtick `<` `>` newline/CR/NUL and `$(` `${` `&&` `\|\|` `>>` `<<` `$NAME` → `Deny [SHELL-METACHAR]`. A bare `&` is rejected except in operands that really are `http(s)://` URLs for tools in the new `url_arg_tools` list, so query separators keep working. `ShellAction.args` is screened like `target`; `evaluate()` returns rule id + evidence; `SafeShell::argv()` / `shell_quote()` provide the paper’s actual remedy (parameterized construction) |

### AgentScan Viewtree Interference (8 of 9 agents — the broadest surface)

| Gap (paper) | Change |
|-----|--------|
| Frame OCR text was appended to `ui_text` but never compared against the AX tree | New `mac-adapter::viewtree`: token-set comparison with loose thresholds (≥ 4 comparable tokens per side, ≥ 3 one-sided tokens, > 50 % share) → `[AG_VIEWTREE_SCREEN_ONLY]` (`OVL-009`, alert: overlay drew without a11y nodes) and `[AG_VIEWTREE_TREE_ONLY]` (`OVL-010`, block+confirm: agent reads what the user cannot see). `MacAdapter` pairs the last AX snapshot with the next frame inside a 3 s window; the native bridge now also OCRs every 8th frame (~4 s at 2 FPS) so there is something to compare |

### Detectors aligned with the published attacks

| Gap (paper) | Change |
|-----|--------|
| A4 stego detector watched luma; the paper embeds in Cb/Cr **while preserving Y** | `stego::chroma_lsb_flip_rate` (BT.601, max of Cb/Cr) → `[AG_STEGO_CHROMA]` / `OVL-011`. Regression test builds a luminance-preserving chroma payload and asserts the luma detector misses it while the chroma detector catches it |
| A1 band topped out at 0.08 although §V-C shows extraction at 8–20 % opacity | Second band `[0.08, 0.22)` with its own higher ratio threshold (0.30 vs 0.10), since that range overlaps ordinary low-contrast UI. `subliminal::band_ratios` / `is_suspicious`; tests cover 8 % and 20 % |
| A2 had no device geometry | `guard_overlay::DisplayGeometry`: corner width `w(y) = R − √(R² − (R−y)²)` (R = 132 → w ≈ 78 at y = 12, matching §IV-B) + cutout rects → `[AG_MASKED_ZONE]` / `OVL-012`. Catches fully opaque, normal-sized, on-screen text that all three old heuristics passed |

### Incidental

- **Pre-existing CI bug fixed:** `guard-cli eval` / `scoreboard` never loaded
  `policies/known-apps.yaml`, so `deeplink_forgery_block` reported a false FAIL
  there while `acceptance-run` (which does load it) passed. Both now take
  `--known-apps`.
- The SCK frame callback takes a versioned `agentguard_frame_stats*` struct
  instead of a 9-argument positional signature that had already grown three
  times; a Rust-side layout test pins offsets against the C header.

New scenarios: `tr_trap_population`, `pqsr_task_failed`, `viewtree_screen_only`,
`viewtree_tree_only`, `stego_chroma_hint`, `masked_zone_corner`
(manifest 31/31, 52 scenarios total). The manifest now carries one qualifying
task and two non-qualifying ones, so the acceptance gate asserts a **mixed
PQSR = 1/3** — a gate that only ever saw 1.0 or 0.0 would not notice the metric
regressing to a constant.

**Not verifiable in this environment:** the ObjC changes in `AgentGuardSCK.m`
(wide band, chroma rate, periodic OCR, struct callback) compile only on macOS.
The Rust mirrors and thresholds are unit-tested; CI’s `macos-latest` job is the
first real compile.

## Shipped (iter 5, 2026-08-10)

| Gap (paper) | Change |
|-----|--------|
| A1 full sanitization loop ((A)I Sees Visual Input Sanitization) | When `subliminal_ratio` trips, `AgentGuardSCK.m` contrast-enhances the frame (CIColorControls 4×) and runs fast Vision OCR (`VNRecognizeTextRequest`); bounded text (≤24 lines × 80 chars) crosses FFI as `ocr_text` and rides `ui_text` in `analyze_frame`, so pixel-hidden injection payloads meet the regular rules (OVL-004 critical block). Detection → enhancement → extraction → rule match, closed loop; pixels still never leave the process |

New acceptance scenario: `inject_subliminal_ocr` (manifest 24/24).

## Shipped (iter 4, 2026-08-10)

| Gap (paper) | Change |
|-----|--------|
| A1/A4 steganography (residual of Visual Input Sanitization) | `mac-adapter::stego`: horizontal LSB flip rate over strided samples; > 0.35 → `StegoHint` finding (`[AG_STEGO_LSB]`, OVL-008 alert). Native `AgentGuardSCK.m` computes the same stat (new `lsb_flip_rate` callback field); Rust sim path + synthetic tests (flat/blocky/random-LSB) |
| Plan-trajectory alignment (Aura pillar iii, lite) | `AgentSessionStart` metadata `task_profile` binds the session goal; events carrying a conflicting `task_profile` → `TASK-DRIFT` alert (Allow→Alert upgrade, like the transition guard) |
| Android↔desktop IPC over Wi-Fi | `api-serve --allow-lan` opt-in permits non-loopback bind (bearer token still mandatory on all `/v1/*`; plain HTTP warning printed); companion MainActivity exposes editable Desktop API URL + token fields |

New acceptance scenarios: `stego_lsb_hint`, `task_drift_alert` (manifest 23/23).

## Shipped (iter 3, 2026-08-10)

| Gap (paper) | Change |
|-----|--------|
| A1 subliminal pixel injection ((A)I Sees Visual Input Sanitization, detection side) | `mac-adapter::subliminal`: 16×9 grid local-contrast analysis; cells in the subliminal band (0.008–0.08 luma) ≥ 10% → `SubliminalText` finding (`[AG_SUBLIMINAL_TEXT]`, OVL-007 block+confirm). Implemented natively in `AgentGuardSCK.m` (new `subliminal_ratio` callback stat) and in Rust for sim/tests; wired into `analyze_frame` |
| A3 per-task app whitelist ((A)I Sees Activity Monitoring) | `AgentSessionStart` metadata `task_apps` declares expected apps; off-list action targets → `APP-NOT-IN-TASK` **Block+confirm** (foreground-mismatch heuristic still applies when no whitelist declared) |
| Non-deniable user decisions (Aura pillar iv, follow-up) | `decision_receipts` chained table: every `set_user_decision` appends `receipt_hash(prev ‖ audit_id ‖ decision ‖ ts)`; `AuditStore::verify_receipts()`; `guard-cli audit-verify` reports both chains |
| AX auto-poll (macOS desktop) | `ax_auto_cmd(enable)` + 2.5s background poller (`ax_auto_poll` flag), tray menu toggle 「AX 自动轮询」, UI button, auto-stops on permission loss |
| Android → desktop IPC | `POST /v1/events` on the loopback API ingests companion envelopes straight into the Engine (bearer-authed); companion `RelayClient` POSTs fire-and-forget over `adb reverse tcp:8788 tcp:8788` (INTERNET permission, toggle in MainActivity) |

New acceptance scenarios: `inject_subliminal_pixel`, `task_allowlist_block` (manifest 21/21).

## Shipped (iter 2, 2026-08-10)

| Gap (paper) | Change |
|-----|--------|
| Non-deniable audit (Aura pillar iv) | `guard-audit::chain`: SHA-256 hash chain (`prev_hash`/`record_hash` columns, auto-migration + backfill), `AuditStore::verify_chain()`, CLI `audit-verify` (exit 1 on tamper) |
| Memory-use axis (MyPhoneBench 3rd capability) | `EventType::MemoryRead`; `PrivacySession` tracks saves/uses; `PrivacyScore.memory_use` reported separately from composite (per paper); `PRIV-MEM-READ` (unsaved key use) / `PRIV-MEM-USE` (wrong preference) decisions; eval `memory_use_gte` check; leaderboard `MemUse` column |
| Cross-app data pivoting (Aura pillar iii, taint-lite) | `PrivacySession::decide_and_record_form_fill` taints HIGH-tier keys per app; re-entering the same HIGH key in a different app → `PRIV-XAPP` alert |
| A3 UI spoofing (Activity Monitoring countermeasure) | Engine tracks `ProcessFocus`; FormFill/PermissionRequest/Deeplink from a non-foreground app → `APP-TRANSITION` alert (never overrides stronger decisions) |
| A4 screenshot tampering (double-capture consistency) | `screencapture::FrameConsistency`: mean-luma jump > 0.35 within 700ms → `[AG_SCREENSHOT_TAMPER]` finding (`OVL-003`), wired into `MacAdapter::ingest_capture_frame` |
| Deeplink / package forgery (AgentScan system layer) | `KnownAppsPolicy` (`policies/known-apps.yaml`): registered app + non-allowlisted URI → `DL-ALLOWLIST` block; custom scheme from unregistered app → `DL-UNKNOWN` alert |

New acceptance scenarios: `memory_pair_correct_use`, `memory_read_unsaved`,
`app_transition_hijack`, `xapp_taint_pivot`, `deeplink_forgery_block` (manifest 19/19).

## Shipped (iter 1)

| Gap | Change |
|-----|--------|
| Form-level FM/TR without explicit metadata | `guard-privacy::classify` + `policies/forms/*.yaml` |
| AX → FormFill | `mac-adapter::form_fills_from_snapshot` on every `ingest_ax_snapshot` |
| A2 invisible zone | `guard-overlay::detect_overlays_with_viewport` + `[AG_INVISIBLE_ZONE]` / `OVL-006` |
| Pop-up / TOCTOU | `Engine::revalidate_ui` / `process_with_revalidate` + `UI-REVALIDATE` |
| Android companion loop | form_fill emit + `EnvelopeSink` jsonl + `LocalRiskScanner` notifications |
| Live AXUIElement | `native/AgentGuardAX.m` → `live_ax_snapshot` / `capture_live_ax` |
| Desktop critical path | consecutive `UiTreeDelta` → revalidate + pending confirm |
| CLI / UI | `ax-probe`, `ax-snapshot`; Menu Bar「抓取前台 AX」 |

## Still open

Ranked in [paper-gap-iter6-review.md](./paper-gap-iter6-review.md); the headline items:

- **Aura pillar iv, remaining half.** Signing shipped in iter 7, but the key is a
  local file: a compromised host can re-sign, and log truncation is still
  undetectable. Needs a Secure Enclave / TPM `AuditSigner` implementation and an
  external append-only anchor.
- **Audit content scope** (Aura §4.4.6 logs "thoughts, actions, and screen
  states"): we log decisions + events, with no reasoning trace and no
  screen-state reference.
- **(A)I Sees A5 runtime receivers** — the iter-8 survey sees manifest-declared
  receivers only; an app registering at runtime is invisible. Needs a different
  signal entirely (or an authenticated input channel, which is the paper's fix).
- **AgentScan image forgery / glitch tokens / log leakage** — no coverage.
- **AgentScan package-name forgery** — *partial* since iter 13: identity is pinned
  to the signing certificate, but only the Android companion attests, so
  enforcement (`require_attestation`) is off by default. See
  [app-identity.md](./app-identity.md).
- **Aura taint lattice** — *shipped* in iter 12 (inheritance, No-Write-Down, HITL
  declassification); still `partial` because only declared flows are controlled and
  the tag is not cryptographically bound to the content. See
  [information-flow.md](./information-flow.md).
- **Aura per-action justification against the instruction** (§4.3.2's model call).
  Iter 14 shipped structural conformance to an operator-written plan
  ([trajectory-alignment.md](./trajectory-alignment.md)); judging whether an action
  *makes sense* given the user's request needs a model in the loop, and the plan is a
  step-kind grammar with no notion of which hotel or whose card.
- **Aura pillar ii** — no NER PII detection and no per-source context isolation.
- **Agent-in-the-loop evaluation** — a real ASR/TSR pair needs agents driven against
  the corpus with sampling, on real devices. Ours is a deterministic guard-behaviour
  corpus; the coverage matrix and the miss/false-positive pair are what it can
  honestly support.
- **Cross-session paired memory tasks** (MyPhoneBench's 50 A/B pairs).
- **Cryptographic binding of taint tags to content** (Aura §4.3.1 requires the tag
  stay bound "throughout its lifecycle"; ours is an in-process map).
- **macOS / Windows app attestation.** App identity by signing certificate is
  implemented for Android only (`docs/app-identity.md`); the desktop shells send no
  `package`, so every app there is Unregistered and falls back to name matching.
- **Per-action agent attestation and mutual attestation** (Aura pillar i / §4.4.6).
  Iter 15 shipped session-level agent identity ([agent-identity.md](./agent-identity.md)):
  an agent signs its session start and everything in that session is attributable to
  it. Signing every *event* needs an Ed25519 operation on the accessibility hot path,
  and the guard still does not prove itself to the agent.
- Windows real UIA (deferred)

## How to verify

```bash
cargo test --workspace
cargo run -p guard-cli -- audit-verify --audit-db <path>   # chain + receipts
make acceptance   # 31 scenarios
make leaderboard  # includes MemUse column

# Android → desktop relay (USB):
adb reverse tcp:8788 tcp:8788
guard-cli api-serve --bind 127.0.0.1:8788 ...   # token printed at startup
# Android → desktop relay (Wi-Fi, trusted LAN only):
guard-cli api-serve --bind 0.0.0.0:8788 --allow-lan ...
# companion app → toggle "Desktop relay: ON", paste URL + token
```

## Shipped (iter 10, 2026-08-10) — evaluation protocol

| Gap (paper) | Change |
|-----|--------|
| **No false-positive measurement at all.** The corpus was 100 % attacks, so a guard that blocked everything would have scored perfectly. This is the same class of blind spot as the earlier score inflation: the metric could not express the failure | Every scenario declares `kind: attack \| benign`, and `guard-cli eval` prints the **pair**: `attack miss rate: 0.0% (0/52) \| false positives: 0.0% (0/13)`. 8 new benign controls target the places over-triggering is cheapest — required-field fills, an app switch (the exact case the old mean-luma A4 detector fired on), a URL with `&` query separators, screen text sharing vocabulary with the payment rules, text near the injection keyword list, a clean env survey, correct memory reuse, a registered deeplink. New `no_intervention` verification with `ignore_rules` for interventions that are a contract choice rather than a detection |
| Tagging immediately found a real problem | Five scenarios sat in the attack set that were **compliant baselines** — a trap present and left alone, an optional field left blank, a bait chain declined. They reported an 8.8 % "miss rate" that was actually correct behaviour. Reclassified as `benign` with explicit `no_intervention` assertions; the real miss rate is 0/52 |
| **No per-surface coverage table** against the 11 AgentScan vectors / A1–A7 / Aura pillars / MyPhoneBench probes — the table a reviewer most wants | `eval/coverage/surfaces.yaml` → `make coverage` → [coverage-matrix.md](../eval/coverage-matrix.md): **29 surfaces, 13 covered, 10 partial, 6 uncovered**, each with the paper's own reported result beside our status |
| A hand-written matrix would rot and overstate | The matrix is **verified**, not just written. `guard-cli coverage` fails when a surface claims a rule that is not in the ruleset, claims a scenario that does not exist **or is currently failing**, is `covered` with no mechanism or no demonstration, is `partial`/`none` with no note saying what is missing, is `none` while claiming rules, or when an **attack** scenario in the corpus is claimed by no surface. It found 9 unclaimed scenarios on its first run. In CI and in `make check` |
| Repeated-trial ASR | **Deliberately not faked.** The runner is deterministic with no agent in the loop, so 20 trials would return the identical result and a "k/20" figure would be theatre. The docs say plainly that our miss rate is not the papers' ASR and why |

Paired metrics also appear in the scoreboard HTML/JSON and the acceptance report, with
the caveat printed next to them.

## Shipped (iter 9, 2026-08-10) — (A)I Sees A4 frame integrity

Full write-up: [frame-integrity.md](./frame-integrity.md).

| Gap (paper) | Change |
|-----|--------|
| The A4 detector compared **whole-frame mean luminance** with a 0.35 threshold, which the attack cannot reach: injecting a line of instruction text moves the frame mean by under a thousandth. A 0.35 jump only happens when the whole screen changes — so the detector fired on app switches and missed injections, exactly the wrong way round | `mac-adapter::framehash`: a structural **grid digest** (16×9 blocks, mean luma *and* Cb/Cr per block, quantised to 4 bits). Comparison distinguishes `Localized` (a few blocks changed, rest identical → `[AG_FRAME_REGION_TAMPER]` / `OVL-013` block+confirm) from `GlobalRepaint` (>35 % changed → an app switch, deliberately **not** reported). The regression test builds an injection, asserts the mean-luma jump is *below* 0.35 (the old detector would have been silent), then requires the new one to catch it |
| The window was 700 ms, 3× the paper's measured mean | 550 ms, covering the measured 50–500 ms with a small margin. Mean luma survives only as a documented fallback for digest-less frames, and its evidence string says so |
| Luma-only comparison is blind to the chroma-preserving A4 variant | The digest includes Cb/Cr per block, so a luminance-preserving edit still moves it |
| "Cryptographic integrity verification" (§VI) was absent | `frame_digest` goes into event metadata → `event_json` → the chain hash **and** the Ed25519 signature from iter 7. The guard attests *"at time T the screen looked like D"*, which makes a substitution provable rather than suspected. New `guard-cli frame-digest --raw … [--expect …]` is the host half: it reports `match`, `TAMPERED (localized): 14/144 blocks differ [...]`, or `DIFFERENT SCREEN`, exiting non-zero on mismatch. Raw pixels in, so no image-codec dependency |
| Resolution and encoding differences would make any pixel hash useless | Fixed grid (resolution independent — tested across a 4× scale difference) and 4-bit quantisation (absorbs ±1 encoding noise, tested) |

Limits stated in the doc: the ~2 FPS stream cannot see a tamper that opens and
closes inside 50 ms — the short end of the paper's range needs a deliberate
back-to-back double capture at the moment of use; a digest proves what the *guard*
saw, so detecting an actual substitution needs the host to hand over the frame the
agent consumed; a single changed block is dropped as noise; and this detects the
condition rather than preventing it (the paper's fix — never staging screenshots
through shared storage — lives in the agent framework).

New scenario: `frame_region_tamper` (manifest 36/36, 57 scenarios). Frame-stats
struct ABI bumped to 2 (`frame_digest` appended); `abi_layout_matches_c` pins the
new offsets (size 64).

## Shipped (iter 8, 2026-08-10) — (A)I Sees A5 / A6

Two attack classes at 20/20 in the paper with zero prior coverage. Details and
limits: [android-env-survey.md](./android-env-survey.md).

| Gap (paper) | Change |
|-----|--------|
| **A5 broadcast input interception** (§IV-C, 20/20 vs 3 of 5 agents): agent frameworks type text by broadcasting `ADB_INPUT_B64` / `ADB_INPUT_TEXT`; the broadcast is unprotected, so any app can register a receiver and read every keystroke with **no permission** | Companion `EnvironmentScanner` enumerates receivers for those actions via `queryBroadcastReceivers`, declared in the manifest `<queries>` block so the survey works on API 30+ without the Play-restricted `QUERY_ALL_PACKAGES`. Reported as `[AG_BROADCAST_INPUT_SINK]` → rule `ENV-A5`, **block + confirm** |
| **A6 credential sniffing** (§IV-C, 20/20 vs all 5): an enabled accessibility service receives `TYPE_VIEW_TEXT_CHANGED`, password fields in plaintext. AgentGuard *is* an accessibility consumer and never checked whether anything else was | Survey reads `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` (falling back to `AccessibilityManager`), minus our own package, and flags the subset whose `eventTypes` mask actually includes text changes. `[AG_FOREIGN_A11Y_SERVICE]` → `ENV-A6`, **alert** (a legitimate screen reader is on this list too) |
| Environment findings were one-shot notices with no consequence | New `EventType::EnvironmentSurvey` + `Engine::env_risk()` latch the state, because the risk is *standing*: a HIGH-tier fill while input is observed becomes `ENV-INPUT-OBSERVED` **block + confirm**. `with_env_guard` only strengthens — a trap fill stays `PRIV-TRAP`, LOW-tier data is not upgraded, and a later clean survey clears the latch so the guard does not stay pessimistic after the user disables the service |

### Bypasses / defects found in review, before shipping

An independent review (Kotlin cannot be compiled here) found problems that would
have made the feature useless or actively wrong. All fixed, with regression tests:

| Defect | Why it mattered | Fix |
|---|---|---|
| A failed scan returned empty lists, and the engine overwrote its latch on any survey | A broken lookup was indistinguishable from "nothing is listening" and could **clear a standing critical risk** — silent failure in exactly the wrong direction | Survey fields are `Option<Vec<String>>` (absent ≠ empty) plus a `scan_errors` list; the adapter sets `env_surveyed`, and only a *complete* survey may overwrite the latch. New `ENV-UNKNOWN` decision; `EnvRisk::is_clean()` requires `surveyed == true`, and never-surveyed reports unknown, not clean |
| The survey never reached the engine for a real session | It was emitted only from `onServiceConnected`, before any session exists, under a throwaway session id that `SessionState.start()` then replaced — so the real session's envelope contained no survey, and the relay is usually unconfigured that early | Re-emitted on the first event of each new session, on a background thread (it does binder + provider calls and file I/O on the thread that pumps accessibility events) |
| Self-exclusion used `startsWith(packageName)` | A sideloaded `com.agentguard.companion.evil` was silently dropped from both lists — precisely the socially-engineered install A6 describes | Exact package comparison via `ComponentName.unflattenFromString` |
| `with_env_guard` replaced any non-Block decision | A `PRIV-TRAP` alert became `ENV-INPUT-OBSERVED`, losing the more specific explanation of *which* field was the trap | High/Critical findings keep their rule id and are escalated to a confirmed block with the environment reason appended |
| One notification id and one "last risk" slot | The `high` A6 hit buried the `critical` A5 hit (both last-write-wins) | Distinct notification ids; critical recorded last |
| `textCapturingServices` computed but never transmitted | It is the signal separating "a screen reader is enabled" from "something is on the typed-text stream" — the exact refinement A6 needs | Plumbed through to the event, metadata and `EnvRisk` |
| **The module could not compile, and the relay could not connect** | Both pre-existing: Kotlin 2.0.0 with the pre-2.0 `composeOptions`/`kotlinCompilerExtensionVersion = 1.5.14` (which pins Kotlin 1.9.24), and a cleartext POST to `127.0.0.1` under a default-deny network security config (the implicit loopback exemption starts at API 37) whose failure `RelayClient` swallowed | Applied `org.jetbrains.kotlin.plugin.compose`, dropped `composeOptions`, added `res/xml/network_security_config.xml` scoped to loopback |

Honest limits, in the doc and in the code comments: `queryBroadcastReceivers`
returns **manifest-declared receivers only**, so an app that calls
`registerReceiver()` at runtime is invisible to this check; package visibility caps
the receiver list to packages matching the declared actions, so "clean" means
"nothing *visible* is listening"; presence on either list is not proof of malice;
and detection is not mitigation — the paper's fixes (authenticated input channels,
credential compartmentalisation) live in the agent framework, not in a guard
beside it.

New scenarios: `android_broadcast_input_sink`, `android_foreign_a11y_service`,
`android_high_tier_while_sniffed`, `android_env_survey_partial`
(manifest 35/35, 56 scenarios).

**Not verifiable in this environment:** the Kotlin changes need an Android SDK to
compile. Rust-side conversion, rules and the standing-risk composition are unit-
tested end to end through `ingest-android`.

## Shipped (iter 7, 2026-08-10) — Aura pillar iv, for real this time

| Gap (paper) | Change |
|-----|--------|
| “Non-deniable audit” was a **keyless** SHA-256 chain: tamper-evident against an editor who does not recompute it, and nothing more. Anyone with DB write access could edit a row, rehash the tail, and `audit-verify` reported `chain: OK` — no signer, so no attribution and nothing anyone could not deny (Aura §4.4.6 requires each action be *cryptographically attributed to its entity*) | `guard-audit::signing`: Ed25519 signature per record and per receipt **over the chain hash**, so editing row *N* invalidates *N* and every row after it. `key_id` is inside the signed payload (no re-presenting a signature under another key) and the two payload types are domain-separated. `AuditStore::with_signer`, `verify_record_signatures`, `verify_receipt_signatures`; new columns `record_sig` / `receipt_sig` / `signer_key_id`, plus `audit_meta` for the public key |
| Receipts conflated a **timeout** with a user decision | `decision_receipts.actor` (`user` for approve/deny, `system` for timeout) is part of the signed payload, so a signed timeout cannot be relabelled as an approval. `UserDecision::actor()` / `is_user_action()` |
| Nothing distinguished “verified” from “not signed at all” | `SignatureVerifyReport` separates `verified` / `unsigned` / `other_key`; `fully_covered()` requires all three to line up. **Signatures are never backfilled** — retro-signing pre-key rows would backdate an attestation, so they stay `unsigned` (hashes *are* backfilled, since a hash claims nothing about who saw the row) |
| `audit-verify` reported a clean bill of health on an unsigned DB | It now prints `signatures: NONE — … tamper-evident but not attributed`, warns when it falls back to the DB-embedded public key (an attacker who swaps the key swaps that copy too), and takes `--pubkey` / `--require-full-coverage` |
| CLI / servers / desktop had no way to sign | `audit-keygen` (Ed25519, secret 0600, public written alongside); every CLI path that writes audit rows picks the key up from `AGENTGUARD_AUDIT_SIGNING_KEY` or `policies/audit-signing.key` — **never creating one implicitly**, since silently signing with a key whose public half exists nowhere only *looks* like coverage; `api-serve --audit-signing-key`; both desktop shells generate and attach one on first run |

Honest limits, spelled out in [audit-signing.md](./audit-signing.md): a key on the
same disk raises the bar from "anyone who can write the file" to "anyone who can
write the file **and** read the key". That defeats remote write access, backup
tampering and casual edits — **not** a compromised host, which can simply re-sign.
Real non-repudiation needs a non-exportable key (Secure Enclave / TPM / StrongBox)
or an external append-only anchor; `AuditSigner` is the seam for the former.
Truncating the log tail remains locally undetectable by construction.

### Bypasses found in adversarial review, before shipping

An independent review of the first cut confirmed four ways to defeat it. All are
fixed and each has a regression test named after the attack:

| Bypass | Why it worked | Fix |
|---|---|---|
| Blank the `record_sig` column | `ok` only went false on a *failed* signature, so a missing one was a free pass. `--require-full-coverage` was off by default and absent from `make audit-verify` | Unsigned rows **fail**. Legacy rows need an explicit `--allow-unsigned`, which prints that they are not attributed |
| Blank `prev_hash`/`record_hash` | `open()` ran the chain backfill, so `audit-verify` recomputed and **persisted** a valid chain over forged content, then reported `chain: OK` — the tool repaired the log for the attacker | `audit-verify` opens read-only; empty hash is a mismatch; backfill moved to an explicit `audit-migrate` |
| Write `user_decision='approve'` directly | That column is excluded from the canonical content, so no hash and no signature covered it; `SessionReport`'s confirm counts read exactly that column | Every non-null `user_decision` must match the latest *valid signed* receipt; a decision with no receipt fails. `audit-report --pubkey` recomputes counts from receipts and `SessionReport.confirm_source` records the provenance |
| Re-sign everything with your own key | `other_key` rows were counted but did not fail | Foreign-key rows fail |

Also hardened while in there: `log_id` + `seq` in the signed payload (a signed row
cannot be transplanted into another log or reordered, and deleting a row from the
middle leaves a detectable gap), `audit_id` in the receipt payload, atomic 0600
key creation (`create_new` + `mode` instead of write-then-chmod, which left the
secret world-readable in between), `load_existing` on write paths so `api-serve`
stops silently generating a key, receipts refused for nonexistent records, and
`audit-export` now carries the hash/signature/position so the exported artifact is
actually verifiable.

Truncation and rollback remain undetectable from inside the log — any prefix of a
valid chain is a valid chain — so `--head-witness <path>` records
`{log_id, seq, count, last_record_hash}` outside the DB and fails when the head
goes backwards, the `log_id` changes, or the log is empty when the witness says it
had rows.

`make audit-signing-demo` (a CI step) runs all five tamper paths — re-hashed edit,
blanked signatures, blanked hashes, forged decision, truncated tail — and asserts
each verdict, including that verification leaves the database byte-identical.

## Native-bridge robustness fixes (iter 6 review pass)

An independent review of the macOS-only ObjC (which no test in this workspace can
compile) found three runtime defects that the struct/OCR changes made reachable:

- `gCallback` was re-read at the end of the sample handler after being tested at
  the top. `agentguard_sck_stop()` clears it from another thread without waiting
  for in-flight handlers, and periodic OCR now holds the handler for 100 ms+, so
  the window was wide enough to call a NULL function pointer. The callback and
  userdata are now snapshotted once at entry.
- The Rust callback returned early on an `abi_version` mismatch **before** freeing
  `ocr_text`. Unreachable today (both sides are 1), but it would leak on the first
  ABI bump — exactly when nobody is looking. The header now documents the
  contract that makes the cleanup valid: the first 16 bytes and the `ocr_text`
  slot never move.
- The sample handler ran on the *concurrent* global queue with a non-atomic
  `frame_seq` and a lazily-initialized `CIContext`. Now a private serial queue
  (so SCK drops overlapping frames rather than running two OCR passes at once),
  `_Atomic` counter, and `dispatch_once` for the context.

Verified by hand instead of by compiler: struct offsets 0/4/8/12/16/24/28/32/36/
40/44/48, size 56, align 8 — identical in the C header and the Rust mirror on both
Apple architectures, and pinned by `abi_layout_matches_c`.
