# Android environment survey (A5 / A6)

Two attack classes from “(A)I Sees What You Don’t” ([arXiv 2607.00333](https://arxiv.org/abs/2607.00333)
§IV-C) are about the *environment* an agent runs in rather than anything the agent
does. Both succeeded 20/20 in the paper, and until this iteration AgentGuard had
zero coverage of either.

| Attack | Mechanism | Paper result |
|---|---|---|
| **A5** broadcast input interception | Agent frameworks type text by broadcasting it (`ADB_INPUT_B64`, falling back to `ADB_INPUT_TEXT`) to an on-device keyboard helper. The broadcast is unprotected, so **any** app can register a receiver and read everything the agent types — no permission, no prompt | 20/20 vs Open-AutoGLM, MobA, Mobile-Agent-v3 (AppAgent/AppAgentX immune: direct `adb shell input`) |
| **A6** credential sniffing | An enabled accessibility service receives `TYPE_VIEW_TEXT_CHANGED` for every text change on screen, password fields in plaintext. Users get social-engineered into enabling one | 20/20 vs all five frameworks |

AgentGuard is well placed to notice A6 in particular: it *is* an accessibility
consumer, so it can say “something else is on this stream too”.

## Pipeline

```
EnvironmentScanner (companion)  →  env_survey envelope event
  → android-adapter  →  EventType::EnvironmentSurvey + [AG_*] markers
    → engine: ENV-A5 (block+confirm) / ENV-A6 (alert) / ENV-CLEAN
    → engine latches EnvRisk → later HIGH-tier fill upgrades to ENV-INPUT-OBSERVED
```

`EnvironmentScanner.scan()` collects:

- `broadcastInputReceivers` — `PackageManager.queryBroadcastReceivers` for each
  input action, minus our own package.
- `foreignA11yServices` — `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` (falling
  back to `AccessibilityManager.getEnabledAccessibilityServiceList`), minus ours.
  The settings string is preferred because it lists services the user has enabled
  even before the system binds them.
- `textCapturingServices` — the subset whose `eventTypes` mask includes
  `TYPE_VIEW_TEXT_CHANGED`, i.e. those that actually see typed text. Transmitted as
  its own field and surfaced in the summary, because it is what separates "a screen
  reader is enabled" from "something is on the typed-text stream".
- `scanErrors` — checks that could not be completed. **Non-empty means the result
  is partial**, and the engine then treats the survey as `ENV-UNKNOWN` rather than
  clean. This matters more than it looks: the first cut swallowed exceptions and
  returned empty lists, so a failed lookup was indistinguishable from "nothing is
  listening" and could *clear* a standing critical risk — a silent failure in
  exactly the wrong direction.

The survey is **emitted** by the accessibility service on `onServiceConnected` and
again on the first event of each new session — not once at install time, because
another service or receiver can appear at any moment. The per-session re-emission
matters: the connect-time survey lands before any session exists, under a
throwaway session id that `SessionState.start()` then replaces, so without it the
real session's envelope would contain no survey at all. It runs on a single
background thread, since it does binder + provider calls and file I/O on a thread
that otherwise pumps accessibility events. The app's refresh button re-reads the
survey for **display** only.

## Decisions

| Rule | Action | Why |
|---|---|---|
| `ENV-A5` | **Block + confirm** (critical) | Everything the agent types is being copied out by an app that needed no permission to do it. Proceeding is a decision the user should make explicitly |
| `ENV-A6` | **Alert** (high) | A legitimate screen reader is also on this list, so a hard block would be wrong. The user is told, and the block comes at the moment it matters |
| `ENV-INPUT-OBSERVED` | **Block + confirm** (critical) | Composition: a HIGH-tier field being filled *while* input is observed. Alerting once at survey time is not enough — the interesting moment is when the phone number or password is actually typed |
| `ENV-CLEAN` | LogOnly | A *complete* clean survey is reported too, so the engine can **clear** a latched risk instead of staying pessimistic after the user disables the offending service |
| `ENV-UNKNOWN` | Alert (low) | Survey incomplete, or none seen yet. Unknown is not clean: only a complete survey may clear a latch, and `EnvRisk::is_clean()` requires `surveyed == true` |

The environment risk is engine state (`Engine::env_risk()`), not a one-shot
notice, because the risk is standing: once another app is reading the input
stream, every later keystroke is compromised. `with_env_guard` only ever
strengthens a decision, and preserves attribution: a High/Critical finding keeps
its own rule id (a trap fill stays `PRIV-TRAP`) and is escalated to a confirmed
block with the environment reason appended, rather than being relabelled
`ENV-INPUT-OBSERVED` and losing the more specific explanation. LOW-tier data is
not upgraded at all, so the guard does not become a blanket block the moment any
other accessibility service exists.

## Limits — what a clean survey does and does not mean

Worth being blunt, because “Environment: clean” is easy to over-read:

- **Runtime-registered receivers are invisible.** `queryBroadcastReceivers` returns
  *manifest-declared* receivers only. An app that calls `registerReceiver()` while
  running will not appear. The paper's A5 uses a manifest receiver (an attacker
  wants persistence), but the runtime variant is not covered by this check at all.
- **Package visibility caps what we can see.** On API 30+ only packages matching a
  declared `<queries><intent>` are visible, which is why the manifest declares the
  two input actions explicitly. That is the narrow, Play-policy-friendly path;
  the alternative, `QUERY_ALL_PACKAGES`, is restricted and far broader than needed.
  A clean receiver list therefore means “nothing *visible* is listening”.
- **Presence is not proof of malice.** A screen reader, a password manager and a
  keyboard helper all legitimately appear on these lists. The survey reports; the
  user decides. That asymmetry is why A6 alerts and A5 blocks-with-confirm rather
  than denying outright — and note that a *legitimate* ADB-keyboard helper (the
  very component the agent types through) will trip `ENV-A5` and require one
  confirmation per session. That is arguably correct — the channel is unsafe by
  design, which is the paper's whole point — but an allowlist of declared input
  helpers is a reasonable future refinement.
- **This does not stop the attack.** It detects the condition. The paper's actual
  fixes are architectural — authenticated/encrypted input channels for A5 (§VI
  “Secure Text Input Channels”) and credential compartmentalisation for A6 (§VI
  “Memory Isolation”) — and both live in the agent framework, not in a guard
  running beside it.

## Try it

```bash
cargo run -p guard-cli -- ingest-android \
  --payload eval/fixtures/android_env_survey_hostile.json --confirm deny
# EnvironmentSurvey platform=android → Block [ENV-A5] paused=true

cargo run -p guard-cli -- ingest-android \
  --payload eval/fixtures/android_env_survey_clean.json --confirm deny
# EnvironmentSurvey platform=android → LogOnly [ENV-CLEAN] paused=false
```

```bash
cargo run -p guard-cli -- ingest-android \
  --payload eval/fixtures/android_env_survey_partial.json --confirm deny
# EnvironmentSurvey platform=android → Alert [ENV-UNKNOWN] paused=false
```

Scenarios: `android_broadcast_input_sink`, `android_foreign_a11y_service`,
`android_high_tier_while_sniffed`, `android_env_survey_partial` (all in the
acceptance manifest).

## Build prerequisites fixed alongside

Two pre-existing problems meant this feature could not have worked as shipped:

- The module could not compile at all. `build.gradle.kts` pins Kotlin **2.0.0**
  while `app/build.gradle.kts` still used
  `composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }`, which pins Kotlin
  1.9.24. Kotlin 2.0 requires the `org.jetbrains.kotlin.plugin.compose` plugin
  instead; that is now applied and the `composeOptions` block is gone.
- The relay POST to `http://127.0.0.1:8788` was blocked. From API 28 the default
  network security config denies cleartext, and the implicit loopback exemption
  only arrives in API 37; `RelayClient` wraps the failure in `runCatching`, so it
  failed silently. `res/xml/network_security_config.xml` now permits cleartext for
  loopback (and the emulator host `10.0.2.2`) only.
