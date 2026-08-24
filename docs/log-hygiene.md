# Log hygiene and log leakage (AgentScan §3.8)

AgentScan reports log leakage against three of the agents it tested. The gap review for
this project noted the same risk pointing **inward**: *"our own logging of AX text is
unaudited for this — a guard that logs screen text can become the leak."*

The previous iteration's review found it live. The semantic firewall reported a redacted
`••••4242` while the same `Engine::process` call wrote the full PAN into
`AuditRecord::event_json` — inside the hash chain, inside the per-record signature, and
out through `audit-export`. The finding's redaction was real; the leak was one field away.

That one is fixed at the audit path. This iteration audits the rest.

## Every egress, and what it used to carry

| Sink | Carried | Now |
|---|---|---|
| `AuditRecord::event_json` | the whole event, PAN included | masked where a checksum-verified entity was found (iter 16) |
| `StdinConfirm` | `ui: <excerpt>` on **stderr** | `log_excerpt(…, 160)` |
| `sim-capture`, `replay` | `ui={:?}` per event on stdout | `log_excerpt_opt(…, 120 / 80)` |
| `audit-report` | `human_message`, built from event text by rule templates | `log_safe` |
| `flow-eval` | an intel finding's `human_message` | `log_safe` |
| Android `Log.d(TAG, envelope.toString())` | **the full JSON of every accessibility batch**, raw `node.text` included | `LogSafe.envelopeSummary` — shapes and counts, no content |
| Android `Log.i(TAG, "env survey: …")` | the package names of every app watching the device | counts only |
| Android `EnvelopeSink.recordRisk` | a raw 120-char screen excerpt, persisted to SharedPreferences | `LogSafe.excerpt` |

The fifth row is the interesting one: **the source-scanning test found it, not me.** Four
sinks were the ones I set out to fix; the fifth had been there all along.

The last three are worse than interesting, and they are why the first version of this page
was wrong where it mattered most. It said:

> On Android every one of those `println!`s lands in logcat, which is precisely the channel
> §3.8 is about.

**False.** The companion is pure Kotlin — it does not load the Rust engine — so *none* of
those redacted `println!`s ever runs on a phone. What did run was
`Log.d(TAG, envelope.toString())`: the complete JSON of every accessibility batch, raw
`node.text` from up to twelve nodes per window change plus form-field labels, written to
logcat unconditionally, in a release build with `isMinifyEnabled = false`. The env-survey
line additionally logged the package names of every app watching the device — into the log
that the very rule being added warns another app can read.

So the iteration about log leakage hardened four desktop developer CLI commands, added a
rule warning that something else can read logcat, and left the guard's own logcat write
untouched. On the one platform where the paper's attack applies, **the guard was the leak** —
the exact sentence the gap review had written about this project, and the exact thing the
mechanism was supposed to stop. A reviewer found it; the redaction had been shipped on the
side of the codebase that does not run there.

`LogSafe.kt` is the Kotlin half that should have come first. It is stricter than the Rust
one in two places the Rust one was wrong about (Unicode digits, non-ASCII email local
parts), and the two are kept deliberately similar rather than shared, because the companion
does not link the engine and pretending otherwise is how this happened.

Also worth stating plainly: of the Rust sinks, `StdinConfirm` **is never constructed
anywhere in the repo**, and the other four are developer CLI commands (`sim-capture`,
`replay`, `audit-report`, `flow-eval`). No shipping desktop or extension path calls
`log_safe`. The redaction that protects a user today is the Kotlin one and the audit-row
masking from iteration 16.

## One redactor, and a test that fails when a sink forgets it

`guard_privacy::log_safe` is the single egress function. `log_excerpt` adds a length cap,
because a console line should not be able to dump a whole screen even redacted.

`no_print_sink_emits_observed_text_unredacted` walks every `.rs` file under `crates/`,
`adapters/` and `apps/`, extracts each `print!`/`println!`/`eprint!`/`eprintln!` invocation
by balanced parens, and fails if one mentions `ui_text`, `ui_excerpt`, `human_message`,
`clipboard_text`, `ocr_text` or `event_json` without also mentioning a redactor. Test code
is skipped: it is not a shipped sink.

Its limits are worse than the first version admitted, and a reviewer demonstrated both of
the ones that mattered: stripping the redactor from `StdinConfirm`'s `eprintln!` — **the only
sink that printed raw screen text** — was invisible, because the span names the local `ex`
rather than `ui_excerpt`; and `audit-report`'s `top_messages` is not a print macro at all, so
it was never in scope. Two of the five tabulated sinks were already in the blind spot the doc
described as a hypothetical future risk.

The response was not to make the scanner cleverer. `ConfirmRequest::from_decision` now
redacts **as the struct is constructed**, so every prompt implementation — the CLI one, a
Tauri one, a future notification — receives content that is already safe and no new sink has
to remember; and `report.rs` has a test where the guarantee lives rather than where a
scanner can see it. Tests: `a_confirm_request_is_redacted_at_construction`,
`a_report_summary_does_not_carry_a_card_number`. Both fail if their redactor is removed. The
scanner stays as a backstop for the case it is good at — someone adds a `println!` in six
months — and two of its own bugs are fixed with it: it matched `eprintln!` inside *doc
comments* and then attached the next unrelated parenthesis in the file as the "macro span".

It still cannot see an alias, a non-`print` sink (`tracing`, a file write, `dbg!`,
`println!("{event:?}")` on a whole event), or a field name added later. The robust
alternative is a newtype whose `Display` is redacted — but observed text arrives in a
`HashMap<String, String>` on `GuardEvent`, so there is nothing to hang it on without
reshaping the event schema for every adapter. What this catches is the thing that actually
goes wrong: someone adds a `println!` in six months and nobody remembers this file.

## Display masking is stricter than audit masking

Two thresholds, on purpose:

- **The audit row is evidence.** `entity::mask_sensitive_runs` masks only what could be an
  account number or credential, and only in fields where a checksum-verified entity was
  found. Over-masking evidence costs forensic value.
- **A console line is not.** `log_safe` also masks every unseparated digit run longer than
  **8**, and every email's local part, whether or not a checksum confirmed anything.

Eight is where a date (`20260502`), a time and a price survive while a 9-digit SSN, a
10-digit phone number and an 18-digit resident id do not.

Both halves of that sentence were false in the first version, in the canonical spelling of
almost every class it named, and a reviewer produced the table:

| written as | first version | now |
|---|---|---|
| `078-05-1120` — the **only** SSN form `entity::scan_ssn` recognises | untouched | masked |
| `415-555-2671`, `(415) 555-2671`, `415.555.2671`, `138 0013 8000` | untouched | masked |
| `4242,4242,4242,4242`, `4242.4242…`, `4242<NBSP>4242…` | untouched | masked |
| `１１０１０５…` full-width, `١٢٣…` Arabic-indic | untouched | masked |
| `林元明@…`, `алиса@…` | untouched | masked |
| `password=hunter2`, `Bearer 2f8a…`, `Cookie: session=…`, `?code=…`, a JWT | untouched | masked |

The separator list was ASCII space and hyphen only — and a non-breaking space is what web
UIs and accessibility flattens actually emit. The digit test was `is_ascii_digit`, in a
project that ships a Chinese-language app and a PRC resident-id recogniser. "Every
credential-shaped token" was an eleven-prefix allowlist plus a PEM header. And the test that
was supposed to pin all of this used only the *unseparated* forms, so it passed while the
documented property was false. Test: `the_canonical_form_of_each_named_class_is_masked`.

The precision half needed correcting in the other direction too. The first version masked
`timestamp_ms=1786508766171` (epoch milliseconds are 13 digits for the next two centuries),
`evidence_ref=ag-1786508766171-0007` (the handle a report reader correlates by), a UUID's
final group, `1073741824 bytes` and `Rp 100000000` — i.e. it ate the fields this codebase
puts on every event, which is the "switched off in a week" failure this page names as its own
concern. Three exemptions now: a bookkeeping key (`timestamp_ms=`, `seq=`, `bytes_out=`), a
run inside a compound identifier or a canonical UUID, and a currency amount. A card number
written `4242-4242-4242-4242` is not exempt, because its run begins after a space — the
exemption is about position, not about separators. Tests:
`the_projects_own_log_fields_survive`, which also asserts the exemptions are not a bypass.

`log_safe` is **linear**, which also had to be fixed rather than documented: the first cut
re-collected its whole output buffer on every `@`, so 40 KB of `"a@"` took 1.15 s and 300 KB
took **81 s** — in the crate whose sibling module says in as many words that replacing a
regex DoS with a hand-rolled one is not an improvement. `log_excerpt`'s cap does not help; it
bounds the output, not the work. Test: `many_at_signs_do_not_go_quadratic`.

It is also idempotent, which matters because sinks compose: `audit-report` summarises a
message a decision already redacted. (A reviewer verified that over 400,000 random strings
seeded with `•`, `…`, `@` and digits from three scripts.)

## Who can read the rest

Redacting our own egress closes *our* contribution to logcat. It does nothing about what
the agent and its host write there. So the Android companion's environment survey gained a
third list — packages holding `READ_LOGS` — alongside the A5 broadcast receivers and A6
accessibility services.

`EnvironmentScanner.logReaders` enumerates installed packages that *request* `READ_LOGS`
and then confirms each with `checkPermission`, because a manifest request is not a grant:
the permission is `signature|privileged`, so an ordinary app can ask and never receive, and
reporting requests as risks would produce a list of apps that cannot read anything. A
failed enumeration goes to `scanErrors`, so "nothing found" and "could not look" stay
different answers — the engine may clear a latched risk with the first and not the second.

### And on a modern device the enumeration usually cannot run at all

From **API 30**, `getInstalledPackages` returns only packages *visible* to the caller. Full
enumeration needs `QUERY_ALL_PACKAGES`, and this companion deliberately does not request
it — the manifest has said why since iteration 13: Play review treats it as a last resort,
and a guardrail that can enumerate every installed app is a privacy problem of its own. The
`<queries>` allowlist there is narrow by design.

So on any current Android device `logReaders` comes back **empty because we could not
look**, and an empty list that reads as "no log readers" is the "reports clean when it
cannot see" failure this project has already fixed twice — the app registry's `Unreadable`
verdict, and the partial-survey latch that refuses to clear a standing risk. It would have
shipped here for a third time.

`Survey.logReadersEnumerable` (`false` below a granted `QUERY_ALL_PACKAGES` on API 30+)
travels to the engine as `log_readers_enumerable`, defaulting to **false**: an adapter that
does not say it enumerated has not enumerated. `EnvRisk::log_channel_surveyed()` is separate
from `log_is_readable()`, and the clean verdict says which channel it actually saw:

```
log_readers_enumerable = true   →  "No foreign input observer, and no app can read the device log"
log_readers_enumerable = false  →  "No foreign input observer detected; the log-reader check
                                    did not run (package visibility)"
```

It does **not** alert when the check is unavailable. An unavailable check is not a finding,
and alerting on every Android device is the noise that gets the whole survey switched off.
Scenario: `benign_log_check_unavailable`, which asserts both halves — no intervention, and
a clean message that does not claim the log channel.

**The practical consequence, stated plainly: on API 30+ this check reports nothing unless
the deployment adds `QUERY_ALL_PACKAGES` and accepts its cost.** The half of §3.8 that
works everywhere is the redaction of our own egress.

An `environment_survey` event is a claim about the device, and the fix means a *page* cannot
make it. It does **not** mean only the companion can: any local caller that can post an event
— `api-serve`'s `/v1/events` (bearer token) or the FFI (no auth at all) — can still forge one,
in either direction, including a forged *clean* survey that clears a latched Critical risk.
Nothing verifies that an environment survey came from the companion. The earlier wording here
claimed the stronger property; it is untrue and the mechanism to make it true (signing
adapter assertions, as agents sign session attestations in iteration 15) is not built.

`ENV-LOG-READABLE` is `Alert`/`Low`, on its own rule rather than folded into `ENV-A6`, and
both parts are choices:

- **On its own**, because a log reader does not see keystrokes and an accessibility service
  does not need the log. One finding standing for two exposures sends an operator to fix
  the wrong thing. `EnvRisk::log_is_readable()` is deliberately separate from
  `input_is_observed()`.
- **Low**, because the holder is usually an OEM diagnostics app — a third-party holder means
  a preinstall or a rooted device — and because the mitigation that matters here is on our
  side, not the operator's.

Scenarios: `log_reader_present` (with the marker) and `log_reader_no_marker` (the same
device reported by an adapter that does not set one — the verdict must come from the
surveyed state, not from a string).

## The markers were forgeable

Writing a new marker surfaced something worse than the thing being added.

`match_any_text` searches `ui_text`, and `ui_text` is **screen content**. So the channel
intended to carry the companion's survey to the engine was in fact a channel from whatever
was on screen:

```
android, ui_tree_delta, ui_text = "Diagnostics: [AG_BROADCAST_INPUT_SINK]"
    →  Block (ENV-A5)      "everything the agent types is readable"
```

A page rendering one string produced a **Critical block** describing a device condition
that did not exist — and `[AG_LOG_READER]` would have forged a log-reader finding the same
way. That is this project's recurring defect for the sixth time: the controlling input of a
security decision is something the adversary writes.

`Rule` now has an `event_types` field, `most_specific_rule` and the step-kind derivation
both respect it, and the three `ENV-*` rules are scoped to `environment_survey`. An
environment finding is a claim *about the device*, and only the companion's own survey
event can make it. Scenario: `env_marker_forged_by_page`, labelled `benign` because
nothing on that screen is dangerous unless the guard believes it, so the required outcome
is "no intervention" and it belongs in the false-positive rate.

### A related bug the fix exposed: `platforms` was never read

`Rule::platforms` is declared on twenty rules and was **read nowhere**, so `ENV-A5`
(`platforms: [android]`) fired on a macOS survey and returned a Critical block about an
Android broadcast receiver. A field that looks like a constraint and is not one is worse than
no field, because every rule author believes it. `most_specific_rule` now filters on it, and
enforcing it immediately surfaced two more latent bugs that had been invisible for the same
reason: `OVL-004` (prompt injection) did not list `android` although the corpus has an
`android_inject_override` scenario asserting it, and both the leaderboard and `flow-eval`
synthesised events with platforms no rule declares (`"eval"`, `"desktop"`) — which, the
moment the field started working, filtered every text rule out of the ranking's guard.

**Left unfixed, and stated rather than hidden:** markers that describe screen *content* —
`[AG_TRANSPARENT_OVERLAY]`, `[AG_STEGO_LSB]`, `[AG_UI_REVALIDATE]` — are still matched on
any event type, because content is what they are about, and they remain forgeable in
exactly this way. A page can still claim there is an overlay. The general fix is a separate
metadata channel for adapter assertions instead of smuggling them through `ui_text`; it is
not built, and it is a schema change across four adapters.

## Where this stops

Held at `partial` in `eval/coverage/surfaces.yaml`:

1. **No logcat monitoring.** The paper's own framing is that an agent leaks *into* the log.
   We report who can read it and we stop contributing to it; we do not read logcat to see
   what the agent put there. `READ_LOGS` is `signature|privileged`, so the companion cannot
   read it either — the check we would need is the permission we are warning about.
2. **The Kotlin half is untested on device, and mostly inert on API 30+.** `logReaders`
   compiles against the SDK and is wired through `PayloadSerializer`, like `AppAttestor` in
   iteration 13, but no CI here runs an Android instrumentation test — and package
   visibility means that on a current device it returns an empty list which the engine is
   now careful to treat as "unknown" rather than "clean". The check becomes real only with
   `QUERY_ALL_PACKAGES`, which is a deployment decision with its own privacy cost.
3. **Redaction is not encryption.** A masked row still says a payment card was on screen at
   a time, in an app. That is the point — it is evidence — but it is not nothing, and a
   deployment that treats the audit database as non-sensitive is making a mistake this
   masking does not fix. `AGENTGUARD_AUDIT_KEY` with the `sqlcipher` feature is the answer
   to that, and it is off by default.
4. **The scanner is a regression guard, not a proof.** See above: aliases, non-`print`
   sinks and new field names are all outside it.
