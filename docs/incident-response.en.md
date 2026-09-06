[简体中文](incident-response.md) | [繁體中文](incident-response.zh-TW.md) | [English](incident-response.en.md)

# Production incident-response runbook

Sev-0 covers broad security/privacy harm, compromised supply chain/signing, or unstoppable incorrect high-risk action. Sev-1 covers multi-user loss of core protection/audit, broken update/rollback, or a scalable bypass. Sev-2 is localized degradation with a safe workaround; Sev-3 is minor and does not change protection semantics. Sev-0/1 stops rollout immediately.

Record UTC time, source, commit/artifact set, channel, and impact without credentials or raw PII. Appoint one Incident Commander plus technical, operations, security, privacy/legal, and communications owners. Pause channels and feature controls while preserving evidence. Mitigate or roll back only to verified artifacts with two-person review. Re-run affected RC, smoke, and regression gates; close only after timeline, cause, notifications, and actions are complete.

Recovery requires Incident Commander, Release, Security, and Operations approval, plus Privacy/Legal for personal data or store declarations. An interrupted Beta/rollout clock cannot be inherited, and an old `--ga` log cannot approve a new candidate.
