[简体中文](ga-evidence-template.md) | [繁體中文](ga-evidence-template.zh-TW.md) | [English](ga-evidence-template.en.md)

# GA evidence template (BLOCKED by default)

> This page is not release evidence. Every result is deliberately `BLOCKED`, and no valid success marker is supplied. An unchanged copy must fail. Change a case to `PASS (native)` only after real execution and externally verifiable records satisfy the [GA gate](ga-release-gate.en.md).

Each `report.md` uses this shape with unique, non-empty, redacted files:

```text
AGENTGUARD_GA_EVIDENCE_PROFILE=<BLOCKED until ga-v1 completed>
AGENTGUARD_GA_<KIND>=BLOCKED
HEAD=<full commit>
ARTIFACT_SET_SHA256=<64 lowercase hex>
OWNER=<accountable identity>
EXECUTED_AT=<RFC3339>
EXTERNAL_RECORD=<immutable external identifier>
```

```markdown
| Case | Result | Evidence | Notes |
|---|---|---|---|
| <ID> observed | BLOCKED | evidence/ga-<kind>/<unique-file> | <reason> |
```

The SBOM report has fixed references: `delivery.cdx.json` (SB1), `delivery.spdx.json` (SB2), `NOTICE-review.md` (SB3), and `scope-reconciliation.md` (SB4). Only a real reviewer may add `AGENTGUARD_NOTICE_REVIEW=APPROVED`. Scope may be marked `AGENTGUARD_DELIVERY_SBOM_SCOPE=COMPLETE` only after macOS, Windows, Android, iOS, Chrome, and Edge each have both `AGENTGUARD_DELIVERY_SCOPE_<PLATFORM>=INCLUDED` and `AGENTGUARD_DELIVERY_<PLATFORM>_SHA256=<64 lowercase hex>`. Those hashes bind the one frozen final package per platform in a repository-external `DELIVERY_ROOT`; generation refuses `.` or any repository subtree. `collect` does not copy the six binaries, so retain the original `DELIVERY_ROOT` in an external immutable artifact store.

Other reports/cases are `ga-privacy-store` PS1–PS6, `ga-beta-14d` BT1–BT4, `ga-dual-rc` RC1–RC2, `ga-channel-smoke` CS1–CS6, and `ga-rollout` RO5/RO25/RO100. Beta reserves unique RFC3339 `BETA_START`/`BETA_END` values; dual RC reserves full `RC1_COMMIT`/current `RC2_COMMIT`; rollout reserves RFC3339 `ROLLOUT_5_AT`/`25_AT`/`100_AT` values.

The five-party report uses `AGENTGUARD_GA_SIGNOFF_PROFILE=five-party-v1` and fixed files `release.md`, `qa.md`, `security.md`, `privacy-legal.md`, and `operations.md`. Each starts as:

```text
AGENTGUARD_GA_SIGNOFF_ROLE=<role>
AGENTGUARD_GA_SIGNOFF_DECISION=BLOCKED
AGENTGUARD_GA_SIGNOFF_IDENTITY=<external identity>
AGENTGUARD_GA_SIGNOFF_AT=<RFC3339>
AGENTGUARD_GA_SIGNOFF_ARTIFACT_SET_SHA256=<same hash in all five>
EXTERNAL_APPROVAL_RECORD=<ticket or detached signature>
```

The CLI binds file bytes; it does not authenticate identity. Keep a verifiable approval or controlled-ticket record outside the repository. Never include PII, store secrets, signing keys, cookies, or session tokens.
