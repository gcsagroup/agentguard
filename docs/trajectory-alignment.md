# Plan-trajectory alignment (Aura §4.3.2)

Aura defines a trajectory `T = {(I_user, A₁…Aₜ)}` and requires every candidate
action be justified against **both** the original instruction and the steps already
executed, with a self-consistency drift pass and re-anchoring on failure.

What this codebase had was a string comparison. `TASK-DRIFT` fired when an event's
`task_profile` label differed from the session's — no trajectory state, no
per-action justification, and, the part that matters, **a drifting sequence that
keeps the same label was completely invisible**. An agent told to book a hotel could
confirm three payments, disclose a passport and persist the user's card, every event
labelled `book_hotel`, and nothing fired.

## What is here, and what is not

| Aura §4.3.2 | Here |
|---|---|
| Trajectory state `A₁…Aₜ` | ✅ `Trajectory` records every step |
| Justify against executed steps | ✅ scope / budget / order / completion |
| Justify against the instruction | ❌ — Aura's is a model call |
| Self-consistency drift pass | ~ cumulative `drift_score()` |
| Re-anchoring | ✅ via the confirm gate |

The missing row is the important one and is not a detail: Aura asks a model whether
an action *makes sense* given what the user asked. We cannot do that deterministically
offline, so what is here instead is **structural conformance to a plan an operator
wrote**. That catches the label-preserving drift the string comparison missed, needs
no model, and is a weaker claim — `eval/coverage/surfaces.yaml` keeps the surface at
`partial` and says why.

Concretely: the plan is a step-kind grammar, so it has no notion of *which* hotel or
*whose* card. An agent that books the wrong hotel conforms to `book_hotel` perfectly.

## The plan comes from policy

`policies/task-plans.yaml`. The agent may only *name* a task; what that task is
permitted to do is the operator's to say.

```yaml
plans:
  - task_profile: book_hotel
    goal: "Reserve a room and pay for it once"
    allow: [app_switch, disclose_low, disclose_high, request_permission, confirm_payment, recall_memory]
    max: { confirm_payment: 1, network_egress: 0, transfer_funds: 0, persist_memory: 0, run_shell: 0 }
    order: [disclose_low, confirm_payment]
    terminal: confirm_payment
```

A plan the *agent* supplied would authorise whatever the agent was about to do —
the same mistake as an earlier iteration letting an event assert its own sink
clearance, which read as a security control while being an instruction the attacker
wrote.

`TaskPlanLibrary::from_yaml_str` rejects a plan whose `order` or `terminal` names a
step the plan does not `allow`, or a `max` above zero for a disallowed kind. Those
are not stricter plans, they are unreachable clauses — and an unreachable clause
reads as protection while providing none. (`max: 0` on a disallowed kind is fine: it
documents the prohibition.)

## Step kinds: no adapter has to emit them

`Engine::step_kind_of` maps each event to a [`StepKind`] from what the adapters
**already send**: a filled `form_fill` becomes `disclose_low`/`disclose_high` by the
key's flow tier, `deeplink` becomes `app_switch`, `data_flow` with
`sink_kind: network` becomes `network_egress`.

Requiring adapters to emit a new `step_kind` field would have meant the mechanism did
nothing until every adapter shipped an update — exactly how the app attestor spent an
iteration as dead code while being documented as implemented.

**Critical actions are the exception, and they are declared on the rule** —
`step_kind: confirm_payment` on CRIT-001 in `p0_rules.yaml` — checked across *every*
rule whose pattern matches the text, with the most consequential kind winning.

The first cut keyed them on the **winning** rule's id, and that was the worst defect
in this iteration. Rule precedence is longest-matched-pattern, and CRIT-001 matches
only the four characters `确认支付`; appending `[AG_STEGO_LSB]` moved the win to an
overlay rule, so the payment fell through to `Observe` — uncounted, and the trajectory
then reported **perfect conformance** (`drift_score() == 0.0`) over two payments in a
one-payment task. The controlling input was attacker-authored screen text, i.e. the
exact adversary the overlay rules exist for. Scenario:
`plan_payment_hidden_by_marker`.

A consequence worth stating: a step kind no rule declares is invisible to a budget.
Payments are enforceable because the shipped rules carry the annotation; a deployment
that writes its own critical-action rule and omits it gets a plan that reads as a
constraint and counts nothing. A test asserts the shipped rules and plans agree
(`the_shipped_library_is_valid_and_covers_the_corpus_profiles`); nothing can check an
operator's.

Two more derivation details that carry weight:

- **A field the agent looked at and left blank is `Observe`, not a disclosure.**
  Counting it would put every form the agent merely rendered into the trajectory.
- **`agent_session_start`/`end` are not steps.** They are the anchor.

## A refused step is an attempt, not an execution

Judging and recording are separate: `judge_only` decides, and `process` commits once
the final verdict — including any confirm gate — is known. A step whose decision is
`Block` is recorded for the drift score and the latch but **charges no budget and does
not mark the task complete**.

Recording at judge time got both directions wrong. A payment the guard *blocked* in an
off-task app burned the task's one-payment budget, so the user's real payment
afterwards was reported as "this is #2". And a payment the **user denied** set
`terminal_reached`, after which every legitimate step was `PLAN-AFTER-COMPLETION`. On
approval, `process_gated` re-commits the step as executed — otherwise an approved
payment cost nothing and the same one-payment task could be confirmed indefinitely.

## A session cannot be restarted mid-run

Every piece of per-session state lives behind `agent_session_start`: the trajectory
(budgets, ordering, the drift latch), the app-identity pins, the task allowlist. So an
agent that simply re-sent the event got all of it back — refund the payment budget,
clear a drift latch, drop an impersonation verdict — or named a **more permissive
plan** and turned a refused disclosure into an allowed one. All four variants worked,
at a 100% miss rate.

A restart while a session is open is now `SESSION-RESTART` (block, confirm) and
nothing is cleared. A legitimate host closes the session first, which
`benign_plan_sequential_sessions` covers: two tasks in one process, each with its own
budget. Without that control, refusing every second session would break any
long-lived `api-serve` deployment.

## Every event reaches the trajectory

`with_drift_guard` runs once per event in `process`, not inside
`with_transition_guard` — that helper is reached from only three event arms, so the
trajectory would have missed every `data_flow`, `memory_write` and `memory_read`. **A
budget counted from a subset of the steps is worse than no budget, because it reads
as one.**

## Drift latches until a human re-anchors

Once a step is refused the trajectory is off-plan and stays off-plan:
`PLAN-UNANCHORED`, naming the *original* drift rather than the innocuous step in
front of it.

This is not strictness for its own sake. Twice already in this codebase a check fired
once and let the next identical attempt straight through — an impersonation verdict
and a declassification — so the attacker paid one prompt and proceeded. A drift
verdict has the same shape, so it gets the same treatment.

The door out is Aura's re-anchoring: approving a gated drift prompt *is* the user
being shown the step and accepting it, so `process_gated` calls
`reanchor_trajectory()` on `ApproveOnce`. The pending request is cleared at the start
of **every** `process` call, so it can only be consumed by the gate for the event that
armed it — it used to persist, and an Alert-mode drift (no prompt at all) armed a
re-anchor that the next unrelated gated approval, an injection warning say, then
consumed. The conforming prefix is kept, so **a spent
budget is not refunded** — a re-anchor after the one allowed payment does not buy a
second one. Denial and timeout clear the pending request rather than leaving it armed
for the next unrelated approval. Plain `process` never re-anchors.

## Defaults, and why they are permissive

Both defaults are set by what a new plan library can honestly support.

### The plan library must not reject its own tasks

`flow_tier_for_key` fails closed to `High` for any key outside `high_keys` *or*
`low_keys`, and `low_keys` shipped with three entries — so `destination`, the one
field a navigation task exists to fill, was a HIGH-tier disclosure that
`navigation_jump` forbids. Four of four ordinary flows tripped their own plans, and no
attack scenario would ever have noticed: a `false_positive_rate: 0.0` over a corpus
whose benign scenarios mostly declare no task profile measures nothing about this.

`low_keys` now covers the ordinary non-identifying task fields. Failing closed on
genuinely unknown keys is still right — an unrecognised field is likelier to be
sensitive than not — but "unknown" has to mean unknown, not "nobody listed the obvious
ones". `benign_plan_navigation_destination` is the control.

| Setting | Default | Why |
|---|---|---|
| `GuardContract::on_plan_drift` | `Alert` | A plan library is the easiest thing here to get wrong in the direction that costs users their work. An over-strict `order` clause stops a real booking mid-flow, and none of the attack scenarios would notice. Alerting first lets an operator see what their plans actually reject. |
| `TaskPlanLibrary::require_plan` | `false` | Failing closed blocks every profile nobody has written a plan for yet, which means the library never gets adopted. The one-time `PLAN-MISSING` report is the adoption path. |

`require_plan: true` is a real, tested code path
(`plan_missing_fails_closed`): a task nobody planned then has no permitted steps, so
naming an unfamiliar profile is not a way to escape alignment. A missing plan under
`require_plan` is a hard refusal regardless of `on_plan_drift` — that knob is about
how strict a *plan* is, not about whether one is required.

**Nothing to align against is not drift.** With no `agent_session_start`, or with no
library loaded, steps are recorded and not judged. `Trajectory`'s `unplanned` field
defaulting to `false` made every event outside a declared session produce
`PLAN-MISSING` — the host's omission reported as the agent's fault.

## Where it is loaded

| Entry point | How |
|---|---|
| `api-serve` | `--task-plans` (default `policies/task-plans.yaml`) |
| native-messaging host | `AGENTGUARD_TASK_PLANS`, else the repo default |
| FFI | loaded from the registry's directory by `ag_engine_new_with_registry` |
| eval / scoreboard / coverage / acceptance | `with_repo_policies` |

The eval entry points go through **one** helper. Three of them loaded the known-app
registry individually, and when the plan library was added it reached `eval` and
`scoreboard` but not `acceptance-run` — the release gate disagreeing with `make
eval`, which has happened here before for the same reason.

## The drift score

`Trajectory::drift_score()` is the fraction of non-observation steps that did not
conform — Aura's self-consistency pass in the only form a deterministic corpus can
support. It is `None`, not `0.0`, before any judged step has run: a score of zero
drift over zero steps is the same unearned number as a privacy composite over zero
dimensions, which this project has already had to correct once.

## Scenarios

| Scenario | Asserts |
|---|---|
| `plan_second_payment` | same label, same step kind, one time too many → the reason survives `CRIT-001`'s merge |
| `plan_out_of_order_payment` | same step kinds, wrong sequence |
| `plan_out_of_scope_shell` | a step the task does not involve at all |
| `plan_drift_latches` | an allowed step is still refused while off-plan |
| `plan_missing_fails_closed` | `require_plan: true` refuses an unplanned task |
| `plan_payment_hidden_by_marker` | a longer-matching rule cannot hide a payment step |
| `plan_session_restart_amnesty` | a mid-run restart cannot reset budgets or swap plans |
| `benign_plan_conforming_booking` | a complete ordinary booking is silent |
| `benign_plan_unplanned_profile` | unplanned ⇒ reported once, then unconstrained |
| `benign_plan_no_session_declared` | no session ⇒ nothing judged |
| `benign_plan_reanchor` | approval re-anchors and the run continues |
| `benign_plan_navigation_destination` | a task filling its own field is silent |
| `benign_plan_sequential_sessions` | two tasks in one process, each with its own budget |

`benign_plan_reanchor` first shipped **vacuous**: `confirm_mode: approve` turns every
block into an allow, so it passed unchanged with re-anchoring ripped out. It now
asserts on the decision message, and the discriminating test — approve the drift,
then evaluate the next step *ungated* — is
`guard-core::approving_a_drift_prompt_reanchors_the_trajectory`, because the YAML
harness applies `confirm_mode` to a whole scenario and cannot express the mix.

`decision_message_contains` searches every decision in a run, not just the last: a
merged-away reason lands on whichever event produced it, and checking only the final
event made the assertion pass or fail on where the scenario happened to stop.
