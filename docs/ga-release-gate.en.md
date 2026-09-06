[简体中文](ga-release-gate.md) | [繁體中文](ga-release-gate.zh-TW.md) | [English](ga-release-gate.en.md)

# GA release-closure gate

## Decision layers

`scripts/release-gate.sh --strict` is only the **RC technical gate**: automated checks, production preflight, candidate freezing, and 12 code-signing, notarization, and device-acceptance evidence kinds. Passing it only makes the candidate eligible for GA closure. It does not mean GA approval, store publication, or live availability.

`scripts/release-gate.sh --ga` includes those 12 RC kinds and requires seven GA closure kinds, 19 in total. Firefox is excluded from the first GA. The six channels are macOS, Windows, Android, iOS, Chrome, and Edge. A missing, stale, malformed, or wrong-HEAD item is **GA No-Go**.

## Seven GA evidence kinds

| Kind | Environment variable | Cases | Minimum real-world condition |
|---|---|---|---|
| `ga_sbom_license` | `AGENTGUARD_EVIDENCE_GA_SBOM_LICENSE` | SB1–SB4 | Final six-deliverable CycloneDX and SPDX inventories, human NOTICE review, and scope reconciliation |
| `ga_privacy_store` | `AGENTGUARD_EVIDENCE_GA_PRIVACY_STORE` | PS1–PS6 | Privacy, permissions, data handling, and store declarations match each of the six deliverables |
| `ga_beta_14d` | `AGENTGUARD_EVIDENCE_GA_BETA_14D` | BT1–BT4 | At least `14×24` continuous hours on one candidate series, with cohort, metrics, incidents, and rollback-drill records |
| `ga_dual_rc` | `AGENTGUARD_EVIDENCE_GA_DUAL_RC` | RC1–RC2 | Two distinct full Git commits each complete an independent candidate regression; RC2 is current HEAD |
| `ga_signoff` | `AGENTGUARD_EVIDENCE_GA_SIGNOFF` | SO1–SO5 | Distinct Release, QA, Security, Privacy/Legal, and Operations owners approve one artifact-set SHA-256 |
| `ga_channel_smoke` | `AGENTGUARD_EVIDENCE_GA_CHANNEL_SMOKE` | CS1–CS6 | Each real store/download channel completes download, install, first launch, and a minimum protection flow |
| `ga_rollout` | `AGENTGUARD_EVIDENCE_GA_ROLLOUT` | RO5/RO25/RO100 | Real rollout advances strictly through 5%, 25%, and 100%, with health and rollback decisions at each stage |

PS1–PS6 and CS1–CS6 map in order to macOS, Windows, Android, iOS, Chrome, and Edge. SO1–SO5 map to Release, QA, Security, Privacy/Legal, and Operations. SB1 is CycloneDX, SB2 SPDX, SB3 NOTICE review, and SB4 six-deliverable scope reconciliation. BT1–BT4 cover cohort/build binding, complete metrics, thresholds/incidents, and rollback/support drills.

## Machine-enforced contract

Each report lives at `evidence/ga-<kind>/report.md` and contains the exact line `AGENTGUARD_GA_EVIDENCE_PROFILE=ga-v1`. Every required case appears exactly once, its result is exactly `PASS (native)`, and it references a unique, non-empty, non-symlink repository-relative file under the matching lowercase directory. Simulated results, FAIL, BLOCKED, N/A, placeholders, and reused paths are rejected.

- Beta has unique RFC3339 start/end values at least 14 days apart; end cannot be later than the evidence JSON timestamp.
- Dual RC uses distinct 40-character lowercase commits and RC2 equals current HEAD. Content addressing does not replace controlled tags, immutable artifact storage, or external attestation.
- SBOM paths are fixed to `delivery.cdx.json`, `delivery.spdx.json`, `NOTICE-review.md`, and `scope-reconciliation.md`, with `artifact-set.sha256` implicitly included in the closure. Both inventories must be non-empty, and scope binds the one final-package SHA-256 for each of six platforms to that manifest.
- Sign-off paths are fixed to `release.md`, `qa.md`, `security.md`, `privacy-legal.md`, and `operations.md`. They require correct roles, `APPROVED`, five distinct identities, RFC3339 timestamps, and the same artifact-set SHA-256, bounded by the candidate and evidence times.
- Rollout `5_AT`, `25_AT`, and `100_AT` values strictly increase; 5% cannot predate the candidate and 100% cannot postdate the evidence JSON.

## Procedure

Run `scripts/release-gate.sh --strict` on a committed, clean candidate. Produce real records using the [GA evidence template](ga-evidence-template.en.md), [Beta runbook](ga-beta-runbook.en.md), [rollout runbook](rollout-runbook.en.md), [incident runbook](incident-response.en.md), and [support runbook](support-runbook.en.md). `scripts/ga-sbom-license.sh generate DELIVERY_ROOT` accepts only a repository-external root with exactly one frozen package per platform and an exact manifest; it rejects `.` and repository subtrees. Then `collect DELIVERY_ROOT CDX SPDX NOTICE SCOPE` atomically collects the review assets and manifest, not the six binaries. Retain the original `DELIVERY_ROOT` in an external immutable artifact store so later audits can recompute each SHA-256. Missing tooling, approval, scope, or any digest remains BLOCKED.

Run `guard-cli manual-acceptance <ga-platform> docs/ga-release-gate.md <report> --repo-root .` for each report, then bind the closure with `evidence-digest` and `evidence-verify`. Supply all 19 evidence JSON paths and run `scripts/release-gate.sh --ga`; archive the log, HEAD, artifact set, and evidence read-only.

## Evidence boundary

The JSON and Markdown records are unsigned local attestations. The CLI binds bytes, timestamps, commits, cases, and digests, but cannot authenticate approver identity or resist an operator who can forge every workspace file. Production closure therefore also needs externally verifiable store records, ticket identities, detached signatures, or trusted-runner attestations.

A passing `--ga` means only that the configured closure material passed this verification. It does not prove stores remain downloadable, clients remain online, or the system remains healthy afterward.
