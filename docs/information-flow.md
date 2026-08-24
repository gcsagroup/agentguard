# Information-flow control (Aura §4.3.1)

`crates/guard-privacy/src/taint.rs` implements a two-axis label lattice; the
`data_derive` / `data_flow` / `declassify` events in `guard-core` enforce it.

This document is mostly a record of how the mechanism can be defeated and what
stops each attack, because the first implementation of this feature was defeated
by **six of eight** attacks an adversarial review threw at it. Every countermeasure
below has a named regression test in `crates/guard-core/src/lib.rs`.

## What is Aura's, and what is ours

Aura §4.3.1 defines memory as `M = ⟨Content, Tag_origin⟩` with
`Tag_origin ∈ {TAG_VERIFIED, TAG_TAINTED}` — an **integrity** tag and nothing
else. Its No-Write-Down rule is: *"if the agent attempts to retrieve a
`TAG_TAINTED` variable to populate a parameter of a Critical Node, the system
intercepts."*

| Concept | Whose | Rule id |
|---|---|---|
| Integrity tag, inheritance, memory ⟨Content, Tag_origin⟩, HITL declassification | Aura §4.3.1 | — |
| No-Write-Down: tainted content into a Critical Node | Aura §4.3.1 | `FLOW-NWD` |
| Confidentiality axis (`Public < Low < High`) | **ours** | — |
| Confidentiality rule: HIGH value into a lower-clearance sink | **ours** | `FLOW-CONF` |

An earlier revision of this code called the confidentiality rule "No-Write-Down"
and gave the paper's actual rule a different name. Anyone checking the code against
§4.3.1 would have concluded the wrong rule was implemented. The split above is why
`FLOW-CONF` carries its own name rather than borrowing the paper's.

## The lattice

```
Label = ⟨integrity, confidentiality⟩
integrity:        Tainted < Verified        join = min   (untrusted absorbs)
confidentiality:  Public < Low < High       join = max   (secret absorbs)
```

`join` is what makes inheritance transitive without walking the dependency graph:
a derived value's label already contains its parents' joins.

### The one invariant

**A label only ever moves up the lattice, except through `declassify`.**

`introduce` and `derive` *join* with any existing label for that id rather than
replacing it. Without this the carefully-guarded `declassify` is decoration,
because two cheaper paths moved a label down:

- `data_derive` with `value_id: profile:passport_number, parents: <public value>`
  overwrote the passport's HIGH label. The next flow to an arbitrary network host
  was **Allowed** — no block, no alert, no audit record, and it wiped the
  per-value `declassified` field on the way past.
- Re-filling the form that seeded a label reset it to `Verified`. The identical
  flow blocked, then went through one form fill later. In the benign direction it
  silently *revoked* an approved declassification when a second form asked for the
  same field.

Tests: `rederiving_an_existing_id_cannot_lower_its_label`,
`refilling_a_form_cannot_launder_taint`.

## Trust boundary: what the event stream may and may not say

The event stream is the agent's channel. Most rule inputs are *observations* —
`ui_text`, `source_app`, pixel digests — and taking them from the agent is fine,
because a lying agent only mislabels its own behaviour. Two inputs here were
*authorisations*, which is different:

| Metadata | Was | Now |
|---|---|---|
| `sink_clearance` | taken verbatim; `sink_clearance: high` on a network sink was Allowed outright | may only **lower** the ceiling the trust model computed |
| `approved` / `approved_by` on `declassify` | taken verbatim; the agent supplied its own approval and stripped the label | **ignored**. The request is always gated; `process()` never applies it |

A declassification is applied in exactly one place: `process_gated` on a real
`ConfirmResponse::ApproveOnce`, attributed to `ConfirmPrompt::approver()`. Hosts
with a signed-in account should override `approver()`; the default names the
channel (`local-confirm-prompt`) rather than inventing a person, because an audit
record naming someone who never typed anything is worse than one naming the
channel.

Tests: `event_cannot_raise_its_own_sink_clearance`,
`declassification_cannot_be_self_approved`, `confirm_gate_applies_a_declassification`,
`denied_declassification_is_discarded`,
`a_request_that_is_not_a_downgrade_never_reaches_the_user`.

## Sink clearance

`Sink::for_declared_flow` is the single place clearance is decided — it lives in
`guard-privacy` so the lattice's unit tests exercise the defaults the engine
actually ships. Previously three convenience constructors existed that only tests
called, while the engine built `Sink` literals with different parameters; the tests
passed on cases that never occurred, and the case that did occur (`app_field`
defaulting to `Low`) had no test at all. That is exactly where a hole was found.

| Sink kind | Ceiling |
|---|---|
| `network`, `clipboard` | `Public` — the clipboard is readable by every app, the network leaves the device |
| anything named in the session's `task_apps` | `High` |
| any other local sink | `Low` |

`critical_action` and `shell_arg` additionally require `Verified` integrity — these
are Aura's Critical Nodes.

The `task_apps` grant is an **exact, case-insensitive name match**, deliberately
not the substring match the transition guard uses: with `task_apps: "Booking"`, a
sink named `NotBooking-Evil` inherited `High` clearance and a passport number
flowed into it. Test: `task_app_clearance_is_not_a_substring_match`.

## Failing closed

Two defaults were changed to fail closed, both because failing open was silent:

- **A flow with no `value_id`** was its own `FLOW-NO-ID` Alert. Omitting the field
  was therefore the cheapest possible bypass of the entire lattice, and being a
  bespoke rule no deployment could tighten it. It is now the same
  `FlowVerdict::Unknown` claim as an unlabelled value, on the same
  `on_unlabelled_flow` knob, defaulting to block-until-approved. Only `data_flow`
  events are affected, so an adapter that emits no flows is untouched.
- **An unclassified profile key** was `Low`, because `tier_for_key` treats
  everything outside `high_keys` as `Low` — right for MyPhoneBench scoring, where
  an unlisted field is not evidence of over-collection. On the flow path it meant
  the default seven-entry `high_keys` list left `social_security_number`,
  `credit_card_number` and `medical_record_id` all `Low`, silently accepted by a
  `Low`-clearance sink. `flow_tier_for_key` fails closed to `High`: the cost of
  being wrong is a confirm prompt versus an unprompted disclosure.

Tests: `a_flow_with_no_value_id_fails_closed`,
`unclassified_profile_key_is_treated_as_high_on_the_flow_path`.

## Severity never masks severity

`PRIV-XAPP`'s upgrade to block was gated on the fill being *otherwise clean*
(`matches!(decision.action, Allow)`). That let the attacker pick the mask: make the
cross-app write **optional**, and `PRIV-FM`'s Alert suppressed the `PRIV-XAPP`
Block, so the HIGH-tier cross-app write went through. Decisions are now merged with
`worse_of`. Test: `priv_fm_cannot_mask_the_cross_app_block`.

## PRIV-XAPP is enforcement now, not a report

Cross-app pivoting is a confidentiality violation: HIGH-tier data collected for one
app being written into another. It was a hardcoded `Alert`, which tells the user
about a leak that already happened. It now routes through
`on_confidentiality_downgrade` (default: block until approved), so alert-only
remains available as a *policy choice* for a deployment that wants monitoring
without friction — rather than being a limitation baked into the code.

## What this still is not

Held at `partial` in `eval/coverage/surfaces.yaml`, for reasons that are structural:

1. **Only declared flows are controlled.** An agent that reads a value off the
   screen and retypes it from its own context window, emitting no `data_derive`, is
   invisible. This is flow control, not a sandbox — see
   [scope-and-non-goals.md](./scope-and-non-goals.md).
2. **The tag is not cryptographically bound to the content**, which Aura requires
   "throughout its lifecycle". Ours is an in-process map from memory key to value
   id. It survives a save/load round trip and nothing more; a host that writes to
   its own store without emitting the event, or restarts, loses the binding.
3. **Sink identity is a name, not an identity.** A malicious app registering the
   declared name inherits its clearance. This is the §3.5 / Aura pillar-i gap.
4. **`sink_kind` is still the event's word.** The clearance ceiling is no longer
   negotiable, but an agent that mislabels a network egress as an `app_field` gets
   the `app_field` ceiling. Closing this needs the adapter to classify the sink,
   not the policy.

## Scenarios

| Scenario | Asserts |
|---|---|
| `flow_derived_value_exfil` | inheritance: a summary built from the passport is itself HIGH → `FLOW-CONF` |
| `flow_memory_laundering` | write → `memory_read` → network keeps the label → `FLOW-CONF` |
| `flow_untrusted_drives_payment` | Aura's No-Write-Down: page text into a critical action → `FLOW-NWD` |
| `flow_declassify_self_approved` | agent-asserted `approved: true` is ignored; the flow behind it still blocks |
| `flow_declassify_not_a_downgrade` | a relabel dressed as a declassification is refused before any prompt |
| `xapp_taint_pivot` | cross-app pivot is blocked, not alerted |
| `benign_flow_within_task_app` | HIGH into a declared app is silent |
| `benign_flow_after_declassification` | the approved path actually works (via `confirm_mode: approve`) |
| `benign_derived_from_public_only` | inheritance is a join, not a blanket taint |

The three benign controls are not decoration: the first cut of the clearance
defaults over-blocked a guest name going into an ordinary form, and
`benign_derived_from_public_only` is what caught it.
