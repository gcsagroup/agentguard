[简体中文](ga-beta-runbook.md) | [繁體中文](ga-beta-runbook.zh-TW.md) | [English](ga-beta-runbook.en.md)

# 14-day Beta runbook

## Entry

The RC technical gate has passed and the six-deliverable commit, version, build IDs, and hashes are frozen. Record cohort, consent/exit, data minimization, metric definitions, stop thresholds, and on-call owners. Exercise rollback, kill switches, [incident response](incident-response.en.md), and [support](support-runbook.en.md) first.

## Clock and daily review

Start at one RFC3339 UTC timestamp and observe one candidate series continuously for at least `14×24` hours. A security, privacy, or core-decision change, incompatible rebuild, Sev-0/1, or critical telemetry gap resets the clock. A documentation-only exception needs written Release and QA justification.

Daily review covers per-channel activity, install/update/launch, crash/hang, protection availability, false positives/negatives, confirmation queues, observation permissions, audit integrity, privacy signals, and support tickets. Redact PII and credentials; retain source data only in controlled systems under the retention policy.

## Stop and pass

Stop immediately for Sev-0/1, uncontrolled security/privacy impact, unavailable rollback, or missing critical telemetry. Passing requires Release and QA to review the complete window, confirm no open Sev-0/1 and all predeclared thresholds, and produce unique BT1–BT4 evidence. The CLI checks duration and evidence shape, not metric truth or human judgment.
