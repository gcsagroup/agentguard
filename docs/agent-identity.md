# Agent identity (Aura pillar i, §4.1 / §4.4.6)

Aura pillar (i) wants an agent **registry**, identity cards and mutual attestation;
§4.4.6 wants each action cryptographically attributed to its entity — agent, user, or
third-party app.

Three of those were missing, and the gap was not obvious from the outside because two
adjacent things *were* built:

- Iteration 7 added per-record Ed25519 audit signing — with a **device** key. It
  attributes an action to the machine, not to the agent that took it.
- Iteration 13 verified third-party **app** identity by signing-certificate pinning.
  That is the app side of an interaction.

Nothing attested *which agent* was acting. Two agents on one device were
indistinguishable to the guard, and `agent_context_id` — the only agent-shaped field
on an event — was a string the agent chose.

## The mechanism in one sentence

An agent proves it holds the private key for a registered `agent_id` by signing its
session-start payload; everything in that session is then attributable to that agent,
and its identity card says what it is allowed to declare.

```
"AGENTGUARD-AGENT-SESSION-v2" ‖ len(agent_id) ‖ agent_id ‖ len(session_id) ‖ session_id
                             ‖ len(task_profile) ‖ task_profile ‖ len(nonce) ‖ nonce
```

Every field is there to stop a specific substitution, and leaving any out is not a
small simplification:

| Field | Without it |
|---|---|
| `agent_id` | one agent's signature is re-presentable as another's |
| `session_id` | one captured signature attests every future session |
| `task_profile` | an agent restricted to shopping signs once for a permitted task, then declares a transfer |
| `nonce` | the signature stays valid forever, so the same bytes reopen the session after an end event |

### Lengths, not a delimiter

v1 separated the fields with `0x1f` and its own test claimed that made concatenation
unambiguous. It did not: `0x1f` is a legal byte in a Rust `String`, so an agent id of
`a␟b` with session `c` produced exactly the bytes of the id `a` with session `b␟c`. The
test compared `"ab"+"c"` with `"a"+"bc"` — the case a delimiter *does* separate — and
read as proof of the case it never tried. A length prefix holds for every input rather
than for every input that avoids the delimiter. Test:
`a_field_containing_the_separator_cannot_forge_a_boundary`.

### The session id is the transport's, not the metadata's

`session_id` metadata is a fallback for adapters whose transport carries no session
field; when `agent_context_id` is present it is authoritative. The first cut preferred
the metadata field, which meant the signature bound a session id **nothing ever
compared against the session the events were actually tagged with** — so an agent could
sign for a session id of its own choosing and then act in any other. Scenario:
`agent_session_substitution`.

`agent_id` on its own authorises **nothing**. It is a claim; the signature is the only
evidence for it. That distinction is the entire mechanism — two earlier iterations
shipped a check whose controlling input was something the agent simply asserted (a
sink's clearance in iteration 12, a declassification's approval in the same one), and
both read as security controls while being instructions the attacker wrote.

## Verdicts

| Variant | Meaning | Consequence |
|---|---|---|
| `Verified` | signature checks out, nonce fresh, task on the card | attributable; session proceeds |
| `BadSignature` | claims a registered agent without its key | `AGENT-BAD-SIGNATURE`, critical block |
| `ReplayedNonce` | attestation seen before (or no nonce) | `AGENT-REPLAY`, critical block |
| `UnanchoredSession` | attestation presented for a session id that names nothing | `AGENT-SESSION-UNANCHORED`, critical block |
| `TaskNotPermitted` | verified, but the card does not list this task | `AGENT-TASK-NOT-PERMITTED`, critical block |
| `Unattested` | registered, no signature presented | `AGENT-UNATTESTED` — Low alert, or block under `require_attestation` |
| `NoKeyOnRecord` | registered with no key, so unverifiable | same; a registry gap, reported as one |
| `Unregistered` / `Anonymous` | nobody claimed, or nobody registered | silent unless `require_attestation` |

The first four are refused **whether or not** attestation is required: a forged,
replayed, unanchored or out-of-scope attestation is evidence *against* the claim, not an
absence of proof. An unanchored one is checked *before* the signature, so it cannot
consume a nonce.

### Freshness is checked after the signature

Deliberately, and it matters twice. A wrong signature is never reported as a replay
(the message would be misleading), and an attacker cannot burn a legitimate agent's
nonce by guessing it — an unverified attestation never reaches the freshness check.
Test: `a_forged_attestation_cannot_burn_a_nonce`.

An attestation with **no** nonce is treated as a replay rather than accepted, because
an eternally-valid signature is the thing the nonce exists to prevent.

### The nonce window is per agent

Consumed nonces live in one bounded FIFO window **per agent**, in a map keyed by the
card's id — so a collision between two agents' nonces is impossible by construction
rather than by the framing of a concatenated key, and one agent's churn cannot evict
another's. A single shared window turned its own bound into an attack: `NONCE_WINDOW`
(8192) cheap start/end cycles under any registered key — and the shipped fixture private
keys are in the repo — re-admitted every other agent's captured attestations. Test:
`one_agent_cannot_evict_another_agents_nonces`.

Total memory is bounded by `|registry| × NONCE_WINDOW`: an entry exists only for an
agent whose signature verified against a card the operator wrote.

### A session id must name a session

`AGENT-SESSION-UNANCHORED` refuses an attestation whose session id contains no
alphanumeric character, or any control character. The first cut refused only `""`,
which is the one value no attacker sends: `trim()` strips Unicode whitespace and nothing
else, so a zero-width space, a soft hyphen, a NUL, the old `0x1f` separator and a bare
`-` all produced a `Verified`, attributing session whose `agent_session_id` rendered
blank in the audit log. A positive rule ("must contain something") beats a denylist of
invisible characters, and every id a real host generates passes it. Tests:
`a_session_id_must_actually_name_a_session`, `an_invisible_session_id_is_not_an_anchor`.

### Anonymous and unregistered sessions are silent

This is the difference between a feature that ships and one that gets switched off.
Reporting "no agent claimed" per session made **28% of the benign corpus** a false
positive — every existing scenario, because no adapter sends an `agent_id`. "The host
never told us who is acting" is not the agent's fault, the same reasoning as the
trajectory's "nothing to align against is not drift".

A *registered* agent that could have proved itself and did not is still reported, at
`Low`: that gap is actionable, because the operator has a card for it, so the adapter
is what needs fixing.

## Identity lives exactly as long as the session

Resolved in the `agent_session_start` arm and nowhere else. A later event cannot
upgrade it, and a mid-run `agent_session_start` is already refused
(`SESSION-RESTART`, iteration 14) — so an agent cannot retry a failed attestation into
success, and cannot re-attest to launder a `TaskNotPermitted` verdict.

It is cleared at `agent_session_end`. The first cut did not clear it: that arm reset the
task allowlist, the task profile and the foreground app, and left `agent_identity`
latched — so the engine still reported `Verified` after the session had ended and went
on attributing later events, including a following *anonymous* session's, to an agent
that was gone. Test: `a_verified_identity_does_not_outlive_its_session`.

The consumed-nonce set is deliberately **not** cleared there. It is the replay defence,
and a session end is precisely when a captured attestation would be re-presented.

## Attribution is a column, and it is inside the hash

`AuditRecord::attributed_agent` is a typed column, written once when the record is
constructed and never updated, and `chain::canonical_content` covers it — so it is
hashed and signed like every other field. **Attribution that is not covered by the
chain is worse than none, because it reads as evidence.**

The first cut wrote `[agent: <id>]` into `human_message` instead, reasoning that
`canonical_content` forbids new fields. It does not: it forbids new *mutable* ones
(`user_decision` is excluded because `set_user_decision` writes it after the fact), and
an immutable field can be added and covered. Getting that wrong had a cost, because
`human_message` is built from event-controlled text in many rule arms
(`"Foreground app: {source_app}"`), so **any event could write its own attribution**:

```
source_app = "Evil [agent: claude-desktop]"    →  attributed = Some("claude-desktop")
```

…in an *anonymous* session, with no key material and no attested session, and hashed and
signed as authentic because `human_message` is inside the canonical content. First-match
parsing also let a forged marker substitute over a real one. A `[agent: …]` tag is still
appended for display, but only after `defuse_agent_tag` has rewritten any marker the
event supplied to `[claimed-agent: …]` — visible, because an event carrying that string
is itself worth seeing, and unmistakably unverified. Tests:
`an_event_cannot_write_its_own_attribution`, `an_event_cannot_forge_an_attribution`,
`attribution_is_covered_by_the_hash`.

Appending only when present keeps old databases verifiable: a record with no attribution
hashes to exactly what it hashed before the column existed
(`the_new_column_is_backwards_compatible_when_absent`), and the migration adds a
nullable column rather than a `NOT NULL DEFAULT ''` one, which would have re-hashed
every historical row into a broken chain — i.e. into something that reads as tampering.

The attribution is taken from the *verified* identity only. Writing `agent_context_id`
there would record the attacker's own claim as evidence. Test:
`audit_records_are_attributed_to_the_verified_agent`.

## Attribution is scoped to the attested session

An event is attributed only if it belongs to the session that was attested. An event
naming a **different** session is not, and is reported once per session as
`AGENT-SESSION-MISMATCH` at `Low` — in a correctly wired deployment it cannot happen, so
silently declining to attribute would hide a real misconfiguration. Latched, because the
alternative is one finding per event.

This matters because one `Engine` is conceptually one session's guard, and
`crates/guard-localapi` holds a single `Mutex<Engine>` for every `api-serve` caller.
Without the check, an event carrying `session=SOMEONE-ELSES-SESSION` was attributed to
whichever agent had most recently attested. Test:
`events_from_another_session_are_not_attributed`.

The same scoping applies to the **end** of the session, and it has to. Scoping only
attribution left the lifecycle open: one session-less `agent_session_end` on the shared
engine closed another caller's attested session — clearing its identity with *no*
finding, so everything after it was silently unattributed — and re-opened the door to a
session-less restart that resets the victim's plan and budgets without tripping
`SESSION-RESTART`. An attested session always has an anchored id, so an end event that
does not name it is refused (`AGENT-SESSION-MISMATCH`) and changes nothing. Sessions
that were never attested are untouched, which is every session a shipped adapter opens
today. Test: `a_foreign_end_cannot_close_an_attested_session`.

## Operator tools

```bash
# Make an agent an identity. The private half never touches the guard.
agentguard agent-keygen --agent-id my-bot [--key path]

# Sign a session attestation, to test an integration end to end.
agentguard agent-attest --agent-id my-bot --session-id s1 \
    --task-profile book_hotel --nonce n1 --secret <hex|path>
```

`agent-attest` takes the secret on the command line, so it is a development tool — a
real agent holds its key and signs in-process. It is also how the eval fixtures were
produced, which is worth knowing: running it against the fixture secret reproduces the
signature in `benign_agent_verified_session` byte for byte, so the corpus and the
signing path cannot drift apart silently.

## Where it is loaded

| Entry point | How |
|---|---|
| `api-serve` | `--agent-registry` (default `policies/agent-registry.yaml`) |
| native-messaging host | `AGENTGUARD_AGENT_REGISTRY`, else the repo default |
| FFI | loaded from the registry directory by `ag_engine_new_with_registry` |
| eval / scoreboard / coverage / acceptance / leaderboard | `with_repo_policies` |

All **five** eval entry points go through one helper, and `EvalRunner::new_engine` is
the single place an eval engine is assembled. The count in this table said four while
`leaderboard` built its own engine inside `score_agent` — so known-apps, task plans and
the agent registry reached `make eval` and never reached the ranking. Loading a policy
file in some entry points and not others has now happened three times in this project:
once making the release gate disagree with `make eval`, once leaving a whole mechanism
reachable only from the test harness, and once leaving a ranking scored by a different
guard than the corpus.

## A card that restricts nothing also switches off its plan

An empty `task_profiles` means "any", and "any" includes profiles the plan library has
never heard of. With `require_plan: false` that leaves the session `unplanned` — so a
card with no restrictions does not merely permit more, it *disables* the trajectory
check for whatever the agent then declares. The two gates have to agree twice over: the
card and the plan library match task names exactly, and a card that holds a key must
enumerate profiles the library knows. `claude-desktop` shipped with no restriction and
therefore with this hole; it now enumerates, and
`every_task_a_shipped_card_may_declare_has_a_plan` asserts the invariant for every
key-holding card in the shipped registry.

## The shipped keys are fixtures

`policies/agent-registry.yaml` pins keys derived from all-one-byte seeds (`0xa1…`,
`0xb2…`) so the eval corpus can present a genuinely valid signature deterministically.
Their private halves are in the test file. **A registry pinning a key whose private
half is public verifies a signature anybody can produce** — the registry says so in a
banner, and a test asserts the banner is there.

`require_attestation` is `false`, for the same reason as the app registry's: no shipped
adapter signs a session, so switching it on globally would refuse every session every
adapter opens. With it off, forged and replayed attestations are still refused; what
changes is whether an unsigned session may proceed.

That is an operator setting, and no test pins it. One did, and it was the wrong shape of
test: hardening a deployment would have broken `cargo test`. What is asserted instead is
the behaviour that must hold at *either* setting —
`a_forged_attestation_is_refused_whether_or_not_attestation_is_required`.

## What this is not

Held at `partial` in `eval/coverage/surfaces.yaml`:

1. **Only the session start is signed.** Signing every event would put an Ed25519
   operation on the accessibility hot path, and no adapter can do it today. So an
   attacker who can inject events into an already-attested session inherits its
   attribution. This is why §4.4.6's "attribute each *action*" is only half met:
   attribution is per session, not per action.
2. **No mutual attestation.** The agent proves itself to the guard; the guard does not
   prove itself to the agent, so an agent cannot distinguish a real guard from a shim
   that approves everything. Pillar (i) asks for both directions.
3. **The replay defence is in memory, per process, and bounded.** Restarting
   `api-serve` forgets every consumed nonce, and the native-messaging host — one
   process per message — never had them at all, so there the nonce buys nothing beyond
   what the session and task binding already buy. Each agent's window holds its most
   recent `NONCE_WINDOW` (8192) attestations and evicts FIFO, so an attestation older
   than that agent's last 8192 is re-admitted — by that agent's own churn only, not by
   anyone else's. A persisted nonce store is the fix; it is not built.
4. **An event carrying no session id of its own is attributed to whatever this engine
   attested.** Most adapters tag no session, and refusing to attribute those would
   leave the mechanism attributing almost nothing — so a mismatch is refused and an
   absence is accepted. Combined with the single shared `Mutex<Engine>` in `api-serve`,
   that means a caller who omits the session field can still land inside another
   caller's attribution. A per-session engine is the fix; it is not built.
5. **A signature proves an identity, not good behaviour.** A verified agent that
   misbehaves is a verified agent misbehaving — which is what the trajectory plans and
   the flow lattice are for.

Limits 1, 3 and 4 are all the same shape: the signature covers *opening* a session, and
everything after it is trusted because the session was opened by someone. That is the
honest boundary of a per-session attestation, and it is the reason this surface is held
at `partial` rather than `covered`.
