# Session-scoped least privilege (Aura §4.4)

Aura installs an **SA session token constrained to `S_max`** as a trust boundary. The problem it
removes is over-provisioning: an agent given the user's session inherits everything the user can
do, which the paper calls God Mode. This project's gap review had four lines for it, ending
*"no narrowing over domains + semantic permissions, so the paper's God Mode over-provisioning is
unmitigated."*

## What was actually missing

Iteration 14 shipped trajectory alignment: a task plan says which **step kinds** a task may take,
how many times, in what order, and which step ends it. That is a real constraint and it works. It
says nothing about which **resources** those steps may touch, and a probe of the shipped engine
showed what that cost:

```
task_profile=navigation_jump, then a ui_tree_delta from "OnlineBank"   → Allow
task_profile=book_hotel,      then form_fill id_number                → Allow
task_profile=book_hotel,      then form_fill social_security_number   → Allow
task_profile=book_hotel,      then form_fill medical_record_id        → Allow
```

A navigation task walked into a banking app and the guard said nothing, because "app switch" is a
permitted *kind*. A hotel booking filled a medical record id, because `disclose_high` is a
permitted *kind* and nothing enumerated which HIGH keys a hotel booking needs.

And the one dimension that did exist had no ceiling. `task_apps` arrives in
`agent_session_start` metadata — the agent declares its own app whitelist:

```
task_apps: "AMap,OnlineBank,Crypto Wallet"   → all three granted
```

An agent that picks its own ceiling has no ceiling.

## The shape of the fix

Three parts, and the middle one is the whole point.

**The ceiling comes from the plan.** `policies/task-plans.yaml` gains a `scope:` block per
profile, and that file is already explicit about why it is not the agent's to write: *"a plan the
agent wrote would authorise whatever the agent was about to do."*

```yaml
- task_profile: book_hotel
  allow: [app_switch, disclose_low, disclose_high, confirm_payment, network_egress, ...]
  max: { confirm_payment: 1, network_egress: 3, transfer_funds: 0, ... }
  scope:
    apps: ["Booking", "Meituan", "美团", "Stripe"]
    data_keys: ["name", "check_in", "check_out", "guest_count", "seat_preference",
                "phone_number", "email", "date_of_birth", "passport_number", "payment_info"]
    hosts: ["stripe.com", "booking.com", "meituan.com"]
```

**The session may only narrow.** `task_apps`, `task_data_keys` and `task_hosts` are a *request*.
The effective grant is the **intersection**:

| ceiling | request | grant |
|---|---|---|
| absent | absent | unconstrained — the check does not run |
| absent | `[A]` | **unconstrained** — the request is ignored, see below |
| `[A, B]` | absent | `[A, B]` — least privilege by default: the task's needs, not everything |
| `[A, B]` | `[A]` | `[A]` |
| `[A, B]` | `[A, X]` | `[A]`, and `X` is reported as an over-request |
| `[]` | anything | `[]` — an explicit "this task touches none" |

Widening is not refused-with-an-error, it is simply **not granted** — the intersection already
dropped it — and reported once as `SCOPE-OVER-REQUEST`, because an agent asking for more than its
task needs is a signal, and a silent intersection looks identical to a session that asked for
nothing.

Two properties do the work, and both are corrections to a first version that claimed them without
having them:

**The grant carries the *ceiling's* entries, never the request's.** The first version pushed the
matching request string into the grant, and the app dimension compares with a bidirectional
substring relation — so a request of `"a"` selected the ceiling entry `AMap`, was granted verbatim,
and then matched every app with an "a" in its name: `OnlineBank`, `Crypto Wallet`, `Signal`. A
request of `"NotBooking-Evil"` against a ceiling of `Booking` was granted verbatim and then
satisfied the *exact-match* HIGH-tier sink-clearance check — the precise forgery iteration 13
closed, reopened one layer up. Granting the ceiling's own entry makes the grant a subset of the
ceiling **by construction**, whatever the comparator does. A request may select from the ceiling; it
cannot contribute a string to it.

**A request without a ceiling is ignored, not installed.** "A session may always narrow itself"
sounds safe and is not: `task_apps` / `task_data_keys` / `task_hosts` arrive in event metadata, so
anything that can post to the local API could pin a session into a grant the operator never wrote —
every subsequent event a `require_confirm` block, and under `--confirm deny` (which is what
`guard-nm-host` and `make sim-*` use) a paused engine for the rest of the process. A denial of
service dressed as self-restraint. Narrowing is only meaningful inside a ceiling.

The one exception is `task_apps`, which has enforced `APP-NOT-IN-TASK` on its own since iteration 3
and keeps doing so — that behaviour is older than this mechanism, and its blast radius is already
shipped.

**The grant is written down.** Aura calls the token a trust boundary, and a boundary nobody can
see is not one, so the `SESSION-START` audit row carries it:

```
Agent session started — session grant [apps: granted: Booking, Meituan, 美团, Stripe;
  data keys: granted: name, check_in, check_out, guest_count, seat_preference, phone_number +4 more;
  hosts: granted: stripe.com, booking.com, meituan.com]
```

A session with no scope produces exactly the line it produced before: `Agent session started`.

The list is truncated at six for readability, and grants are **de-duplicated** — because with
request-derived grants an agent could repeat one entry seven times and push the rest past the
truncation, choosing what the signed record named. Ceiling-derived grants make that unreachable
anyway; de-duplicating makes it unreachable twice.

## The rules

| Rule | Fires when | Action |
|---|---|---|
| `APP-NOT-IN-TASK` | the acting app is outside the app grant | Block / Critical |
| `SCOPE-DATA` | a profile key (`profile_key`, `item_key`, or `value_id`'s `profile:` prefix) is outside the data grant | Block / High |
| `SCOPE-HOST` | an **egress** destination is outside the host grant | Block / High |
| `SCOPE-OVER-REQUEST` | the session asked for something the plan does not permit | Alert / Medium, once |

`APP-NOT-IN-TASK` is not new — it has existed since iteration 3 for the declared `task_apps` list.
What is new is that it now has a ceiling above it, and that it is reachable.

## Absent is not empty

Every dimension is `Option<Vec<String>>`, and the distinction carries weight:

- **absent** — this plan does not constrain that dimension. The check does not run, and a plan
  written before `scope:` existed behaves exactly as it did. This is the same default reasoning as
  `require_plan: false`: failing closed would deny every task an operator has not yet scoped, which
  in practice means the field never gets adopted.
- **empty** — an explicit statement that the task touches none of that resource. `hosts: []` means
  "this task never egresses", the same way `max: {network_egress: 0}` documents a prohibition
  rather than omitting it.

Collapsing the two would force a choice between breaking every existing plan and making an
explicit prohibition unwritable. It is the distinction `AndroidEvent.log_readers` already draws
between "not surveyed" and "surveyed and clean".

## Matching, per dimension

**Apps** — equality after trimming and case folding, plus containment in **one** direction: an
observed name that contains a granted entry is covered, so a grant for `Booking` still covers
`Booking.com` and `Booking – Hotels`. Deliberately *not* `apps_match`, whose two conveniences are
both wrong here: it returns `true` when either side is empty — and the shipped Android envelope path
produced `source_app: ""` verbatim for `{"app": ""}`, which satisfied every grant on every event
type and switched the Critical check off per event — and it matches substrings *bidirectionally*, so
a grant entry of `a` covered everything with an "a" in it. An empty observed name is never covered,
and the adapter no longer produces one.

The agent's own app is exempt by name. On desktop the frontmost app *is* the agent's window much of
the time, and `screen_frame` / `process_focus` / `ui_tree_delta` name it — so without the exemption,
`Claude` was Critical-blocked on its own events in every scoped session.

**Data keys** — read from whichever field the event type carries: `profile_key` on a form fill,
`item_key` on a memory write or read, and the `profile:<key>` prefix of `value_id` on a flow. Reading
only `profile_key` made this a form-fill-only check while its own doc comment condemned exactly that
("a grant enforced on one event type is a grant with a documented bypass") — a corpus census settles
it: `profile_key` appears on `form_fill` and nowhere else, in all 42 occurrences. So a
`preference_save` task persisted a passport number and saw only the generic "persist user
preference?" prompt. The test that was supposed to cover this passed by hand-injecting `profile_key`
alongside `item_key`, a shape neither adapter nor scenario produces.

Matching is exact, trimmed, case-folded. A profile key is an identifier, and iteration 15
established what a loose match on an identifier costs: `may_declare` was case-insensitive, so
declaring `ORDER_FOOD` passed the capability check while finding *no plan*, which switched the
trajectory check off for that session.

**Hosts** — the host itself, or a subdomain of it, **on the dot boundary**. A bare
`ends_with("stripe.com")` also accepts `secure-checkout-stripe.com`, a registerable domain with
nothing to do with Stripe, which would turn a host allow-list into a host allow-anything. Same
class as the `com.sankuai.meituan.evil` substring hole iteration 13 closed in the app registry,
arriving on a different axis. A destination the parser cannot name is **out** of scope, never in
it: a host the guard cannot identify is not one it can approve.

The authority also ends at a **backslash**, not only at `/`. WHATWG URL treats `\` as an authority
terminator for special schemes, so a browser fetching `https://evil.example\.stripe.com/x` goes to
**evil.example** — while a parser splitting only on `/` reads the host as `evil.example\.stripe.com`
and the dot-boundary check then accepts it as a subdomain of `stripe.com`. One character, in the
granting direction, past the primitive this section exists to defend.

**Only egress events are judged.** The first version read `url` from any event "because a `url` is a
network destination by construction" — and the browser adapter attaches `url` to every UI delta, so
a granted app *reading its own site* became a High `require_confirm` block: `Booking` on
`booking.com`, `Meituan` on `i.meituan.com`, `AMap` on `amap.com`. Observing a page is not sending
to it, which is the distinction `StepKind::Observe` already draws. A `network_flow`'s `url` is
judged; a `data_flow` is judged when it declares `sink_kind: network`; nothing else is.

Write the **domain**, not a list of its subdomains. `hosts: ["stripe.com"]` covers
`checkout.stripe.com` and `pay.stripe.com`; enumerating those instead looks tighter, means every
new endpoint needs a policy edit, and — as the corpus showed — makes the forgery case untestable,
because a phishing host cannot end with a subdomain it does not control.

## A bypass in the mechanism this extends

The pre-existing `task_apps` check lived inside `with_transition_guard`, and that helper is called
from exactly four event arms: `process_focus`, `deeplink`, `form_fill`, `permission_request`. So
**`ui_tree_delta` — the event every adapter emits most, the one that says what is on screen right
now — was never checked against the task's app set at all**, and neither were `screen_frame`,
`clipboard_change` or `network_flow`. A grant enforced on a subset of event types is a grant with a
bypass, and this one had been there since iteration 3.

The check now runs from `process`, on every event, and which event types it judges is an
**exhaustive match** rather than a deny-list:

- **judged** — an observed app is acting: `screen_frame`, `ui_tree_delta`, `process_focus`,
  `network_flow`, `clipboard_change`, `form_fill`, `deeplink`, `permission_request`.
- **exempt** — the agent is reporting about itself: `agent_session_start`/`end`, `data_derive`,
  `data_flow`, `declassify`, `memory_write`, `memory_read`, and `environment_survey` (which
  describes the device, not an action).

That exemption is not a convenience. On a `data_flow` the `source_app` is `Agent`; judging those
against a list of third-party apps blocked every flow in every scoped session, and three existing
tests failed exactly that way when the exemption was missing. The *resource* on those events is
covered by the data and host grants instead. `app_grant_classification_is_exhaustive` pins the
split, so adding an `EventType` is a decision someone has to make rather than a default someone
inherits.

## Where this stops

Held at `partial`.

1. **The ceiling is only as good as the plan, and an unscoped profile has none.** The shipped
   library scopes four profiles. A session naming any other profile — or a deployment that has not
   adopted the field — is unconstrained on all three dimensions. That default is deliberate and it
   is also the limit.

2. **A ceiling is a policy statement, and getting it wrong denies legitimate work rather than
   failing safe.** The first draft of the shipped scopes invented key names (`full_name`,
   `credit_card_number`) that this project's own `GuardContract` vocabulary does not use, and nine
   existing benign scenarios became Critical blocks — a ceiling in a vocabulary nobody speaks
   denies everything. A second error left Meituan out of `book_hotel`, which is wrong in a market
   where Meituan books hotels. Both were caught by the corpus; neither would have been caught by
   reading the code.

3. **Three dimensions, not "domains plus semantic permissions".** There is no scope over deeplink
   schemes, clipboard use, shell arguments, or which *fields within* a granted app may be written.
   A session granted `Booking` may write any field Booking exposes.

4. **The request channel is unauthenticated.** `task_apps` and friends arrive in event metadata, so
   anything that can post to the local API can send them. A request cannot *widen* a ceiling, which
   is the property that matters — but "narrowing is harmless" was too strong, and the first version
   of this document said it: a request on a dimension with **no** ceiling used to be installed as
   the grant, which turned a bogus request into a block storm and, under `--confirm deny`, a paused
   engine. Requests are now ignored where there is no ceiling. The residue is that a narrowing is
   not *attributable* to the agent unless the session is attested (§4.4 identity, iteration 15).

5. **Nothing enforces that the grant was minimal.** A plan may declare a wide scope and the guard
   cannot know the task did not need it. Least privilege is *expressible* here; it is not provable.

6. **Only some hosts can declare a task, and none of them do by default.** The mechanism was, at
   first, reachable from the eval harness alone: every adapter's `start_session` sent
   `metadata: HashMap::new()`, so no shipped event stream ever named a `task_profile` — four hosts
   loaded the plan library and none of them could select from it. That is now wired:
   `TaskDeclaration` is the one type that knows the metadata key names, `start_task_session` carries
   it, the Android envelope has `session_start` / `session_end` kinds, both desktop shells load the
   plan library and expose a task selector, and `guard-cli replay` loads it too (verified: a replayed
   `navigation_jump` session blocks a `ui_tree_delta` from `OnlineBank`).

   What is still true: **nothing declares a task unless a human or a host chooses to.** The default
   in every shell is `(unscoped)`. The browser native-messaging host has no session concept at all,
   so `guard-nm-host` cannot open a scoped session. And the two desktop shells could not be compiled
   in the environment this iteration was developed in — they are excluded from the workspace and need
   GTK/WebKit system libraries — so their changes are parse-checked (`rustfmt`) and read, not built or
   run. That is a weaker guarantee than the rest of this document rests on, and it is the same
   category as the companion's untested Kotlin.

7. **`scope:` is validated, but not against the contract's vocabulary.** The library refuses a blank
   entry (`apps: [""]` reads as the tightest grant and is the loosest, because an empty string once
   matched everything), a single-label host (`hosts: ["com"]` grants every `.com`, one deleted
   character from `booking.com`, and there is no public-suffix list here), a URL where a host belongs,
   and a `hosts:` grant on a task whose plan forbids egress — that last one caught a contradiction in
   two shipped plans. It does **not** check `data_keys` against `GuardContract`'s vocabulary, which is
   the error that turned nine benign scenarios into Critical blocks; the validator has no contract to
   check against, and only the corpus caught it.

8. **Time is not a dimension.** Aura's token is bounded; this grant lasts exactly as long as the
   session and has no expiry, no step budget of its own (the plan's `max` is the nearest thing),
   and no re-authorisation point.

## Verified by mutation, not assumed

Each mechanism was checked by breaking it and confirming the corpus notices:

| Mutation | Result |
|---|---|
| `narrow()` unions instead of intersecting | `scope_over_request_refused` fails |
| host matching by bare `ends_with` | `scope_host_suffix_forgery` fails |
| app grant judged on only the four old event arms | 2 scenarios fail |
| `passport_number` dropped from `book_hotel` | 3 scenarios fail — including the benign control |
| grant carries the request's string instead of the ceiling's | `a_one_character_request_cannot_widen_the_app_grant` fails |
| `url_host` splits on `/` only | `url_host_terminates_the_authority_on_a_backslash` fails |
| `app_in_grant` treats an empty observed name as covered | `an_unnamed_app_is_not_in_the_grant` fails |

The host mutation initially went **uncaught**, and that is worth recording: the first version of
`scope_host_suffix_forgery` used `checkout.stripe.com.collector.example`, which a bare `ends_with`
*also* rejects, so the scenario passed and would have passed against the broken implementation too.
The mutation run is what found it. A scenario that fails for the right reason is not the same as a
scenario that would fail for the wrong one.

## A corpus defect this iteration surfaced

Making the host check egress-only broke `scope_host_suffix_forgery`, which was the useful kind of
failure. The eval runner mapped scenario `event_type` strings to `EventType` with a `_ =>
EventType::UiTreeDelta` catch-all — and the corpus uses two names that were never in the match:
`network_meta` (two scenarios, including a host exfiltration case) and `deeplink_open` (one). Those
scenarios had been running as **UI deltas** for seventeen iterations, asserting verdicts about event
types the engine never saw.

The mapping now covers every `EventType` by name and an unrecognised one is a **load error**, not a
silent substitution. That immediately exposed a second thing: `book_hotel` and `order_food` both had
`max: {network_egress: 0}` *and* a `scope.hosts` list — a contradiction that had never fired because
no scenario ever produced a network event on those profiles. `TaskPlanLibrary::validate` now rejects
a host grant on a task that cannot egress, and both plans grant bounded egress instead.
