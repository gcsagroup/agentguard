[简体中文](rollout-runbook.md) | [繁體中文](rollout-runbook.zh-TW.md) | [English](rollout-runbook.en.md)

# 5% → 25% → 100% rollout runbook

Roll out one frozen artifact set. Each of the six channels has independent enable, pause, and rollback controls; one channel cannot borrow another's completion. Percentages, health thresholds, minimum observation periods, and decision owners are recorded before 5%.

1. **5%:** reconcile real-channel hashes; sample fresh install, upgrade, first launch, minimum protection, and rollback.
2. **25%:** enter only after a complete and observable 5% window with no stop event and Release+Operations approval; repeat health and support checks.
3. **100%:** enter only after a stable 25% stage while five-party approval remains valid. Full rollout does not end on-call, channel-availability, or incident monitoring.

Freeze and follow the [incident runbook](incident-response.en.md) for Sev-0/1, signing/update-chain failure, privacy breach, unavailable protection, metric gaps, or breached thresholds. RO5/RO25/RO100 each retain time, percentage, artifact set, health queries, incidents, support summary, decision owner, and rollback proof. The CLI checks ordering and candidate binding; controlled systems must establish real-world truth.
