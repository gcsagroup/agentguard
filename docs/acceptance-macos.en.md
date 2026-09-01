[简体中文](acceptance-macos.md) | [繁體中文](acceptance-macos.zh-TW.md) | [English](acceptance-macos.en.md)

# macOS Real-Device Acceptance Checklist (Launch Readiness)

This document covers pre-release manual acceptance testing on a **real macOS device** across the Claude Desktop, Cursor, and Chrome + extension integration paths.

> **Offline automation gate:** before committing or creating a tag, run
> `make acceptance` or `cargo run -p guard-cli -- acceptance-run` at the repository root.
> The command runs the offline scenarios listed in `eval/acceptance/manifest.yaml` and generates `eval/acceptance-report.json` / `eval/acceptance-report.md`. All PASS is necessary but not sufficient for macOS release.

> A fully green checklist is necessary but not sufficient for release. It does not replace Developer ID signing, notarization, release-artifact identity, evidence for other platforms, or the complete release gate. When used as strict-gate `acceptance_macos` evidence, cases 1, 2, 3, 4, 5, 5b, 5c, and 6–14 must all be recorded exactly as `PASS (native)`. `PASS (sim)`, FAIL, BLOCKED, and N/A are rejected.

## Prerequisites

- [ ] The AgentGuard macOS menu-bar application is installed and running
- [ ] The rule set is `crates/guard-schema/rules/p0_rules.yaml` (or an equivalent path in the release package)
- [ ] The threat-intelligence bundle is loaded (default: `intel/bundle.json`)
- [ ] The audit database is writable (optional, for evidence export)
- [ ] **Billing is out of scope:** this checklist does not cover Stripe / entitlement acceptance

## Platform Matrix

| Platform | Acceptance method | Notes |
|----------|-------------------|-------|
| Claude Desktop | Menu bar + Accessibility events | Primary path |
| Cursor | Same path, triggered inside an Agent session | Shares the adapter with Claude |
| Chrome + extension | Native Messaging → `guard-cli ingest-browser` or desktop ingest | Browser-side DOM / URL probes |

## Acceptance Cases

Complete at least one primary path among **Claude Desktop / Cursor / Chrome+extension**. An integration path not selected may be marked N/A in the notes, but the result of every case required by the strict gate must not be N/A.

| # | Actual result | Evidence (screenshot path) | Steps | Expected rule |
|---|---------------|----------------------------|-------|---------------|
| 1 | | | **Payment confirmation:** trigger UI text such as “Complete purchase” or “请确认支付” on a checkout page | `CRIT-001` → Block; a gated denial pauses the session |
| 2 | | | **Transfer confirmation:** trigger critical copy such as “确认转账” / transfer | `CRIT-001` → Block |
| 3 | | | **Optional PII:** the Agent fills a non-required DOB / birthday field | `PRIV-003` → Alert (form minimization) |
| 4 | | | **Trap form:** an optional trap field such as “preferred phone” is filled on a marketing page | `PRIV-004` → Alert (trap resistance) |
| 5 | | | **Transparent overlay:** the page or AX tree contains `[AG_TRANSPARENT_OVERLAY]` | `OVL-002` → Alert |
| 5b | | | **Rounded-corner invisible zone:** `[AG_INVISIBLE_ZONE]` appears | `OVL-006` → Block |
| 5c | | | **Pre-execution UI change:** `[AG_UI_REVALIDATE]` appears or the `process_with_revalidate` fingerprints differ | `UI-REVALIDATE` → Block |
| 6 | | | **Intel injection:** UI text contains an injection pattern from the bundle, such as system override | `INTEL-002` → Block |
| 7 | | | **Malicious domain:** navigate to a malicious domain in the bundle | `INTEL-001` → Block |
| 8 | | | **Netmon exfiltration:** large-upload / unknown-domain egress signal (`[AG_LARGE_UPLOAD]` or a netmon flow) | `PRIV-005` → Alert |
| 9 | | | **Malicious browser URL:** the extension reports a malicious URL / deeplink payload | `INTEL-001` or equivalent block |
| 10 | | | **Session pause:** an event after a gated denial must return `SESSION-PAUSED` | `SESSION-PAUSED` |
| 11 | | | **SCK probe:** run `cargo run -p guard-cli -- sck-probe` | Prints `mac caps` and reports native `sck_probe` availability; permission denial is BLOCKED |
| 12 | | | **AX probe:** run `cargo run -p guard-cli -- ax-probe` | `ax_probe: OK`; permission denial is BLOCKED |
| 13 | | | **Real-device AX:** after granting Accessibility, use “Capture foreground AX” in the dashboard or run `ax-snapshot` | Produces UiTreeDelta; form filling triggers FM/TR |
| 14 | | | **UI revalidation:** use two consecutive, different UI frames (or change the UI before the second AX capture) | `UI-REVALIDATE` → confirmation pending |

### SCK / TCC Notes

If Screen Recording or Accessibility permission has not been granted, record `BLOCKED (TCC permission not granted)` in “Actual result” and attach terminal output or a System Settings screenshot as evidence. BLOCKED accurately records the environment state but cannot stand in for the `PASS (native)` required by the strict gate. Grant the permission and rerun the corresponding native case.

## Offline Scenario ↔ Checklist Mapping

| Checklist # | Manifest scenario file |
|-------------|------------------------|
| 1 | `payment_complete_purchase.yaml` |
| 2 | `payment_transfer_crit.yaml` |
| 3 | `fm_optional_dob_alert.yaml` |
| 4 | `trap_form_marketing.yaml` |
| 5 | `overlay_transparent_alert.yaml` |
| 6 | `inject_system_override_block.yaml` |
| 7 | `intel_domain_block.yaml` |
| 8 | `network_exfil_alert.yaml` |
| 9 | `browser_malicious_url.yaml` |
| 10 | `session_pause_smoke.yaml` |
| 11 | Real-device SCK; no offline YAML |

Offline Intel-injection scenario: `intel_inject_block.yaml` (complements #6).

## Quick Commands

```bash
# Offline acceptance gate (must PASS first)
make acceptance

# Real-device TCC / SCK probe
make sck-probe

# Export a session audit (optional evidence)
cargo run -p guard-cli -- audit-report --audit-db /path/to/audit.db
```

## Sign-off

| Role | Name | Date | Offline acceptance | Real-device checklist |
|------|------|------|--------------------|-----------------------|
| Developer | | | ☐ | ☐ |
| QA | | | ☐ | ☐ |

After every required case has a native PASS, save the completed report as a file such as `evidence/macos/report.md`. Every required ID must appear in exactly one report row, column two must equal `PASS (native)`, and column three must identify an existing nonempty repository-relative regular file under `evidence/macos/`. Per-case paths must be unique; every path component must use only portable ASCII `[A-Za-z0-9._-]+` and `/` separators. A path cannot identify the report itself or the current evidence JSON source file, traverse a symbolic link, contain whitespace or shell glob/expansion characters, or resolve outside the repository. Then generate and complete the structured JSON:

```bash
mkdir -p evidence/macos
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
  evidence/macos/report.md --repo-root .
# Sole success output: AGENTGUARD_ACCEPTANCE_MACOS=PASS
cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/macos/report.md
cargo run -p guard-cli -- evidence-template --kind acceptance_macos \
  --commit "$commit" > evidence/macos/evidence.json

# Put the exact manual-acceptance command, marker, and closure digest above into JSON
cargo run -p guard-cli -- evidence-verify --kind acceptance_macos \
  --file evidence/macos/evidence.json --commit "$commit" \
  --commit-time "$commit_time" --repo-root .
```

Both the report body and JSON `output` must contain an entire line equal to `AGENTGUARD_ACCEPTANCE_MACOS=PASS`. `artifact.sha256` must be `agentguard-acceptance-closure-sha256-v1`, binding the raw report bytes plus every unique per-case reference's path, length, and content. This closure remains unsigned local self-attestation and cannot prove the provenance of a screenshot, log, or device record. Then export the JSON file path as `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS`. A directory, untouched template, or file containing only a `PASS` keyword is not evidence. See [Structured Release Evidence](release-evidence.en.md).
