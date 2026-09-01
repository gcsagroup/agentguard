[简体中文](acceptance-firefox.md) | [繁體中文](acceptance-firefox.zh-TW.md) | [English](acceptance-firefox.en.md)

# Firefox Extension Real-Device Acceptance Checklist (Launch Readiness)

This document covers pre-release manual acceptance testing of the extension on **real Firefox (≥128)**.
It corresponds to the Firefox items marked "scaffold implemented, real-device validation pending" in
`docs/跨浏览器.md`. **Those items count only after they have been exercised on real Firefox**; offline automation
and `node --check` cannot validate them.

> A fully green checklist is necessary but not sufficient for release. It does not replace store signing,
> release-artifact identity, evidence for the other platforms, or the complete release gate.

> **Offline prerequisite gate:** first run `make check-extension-gate` at the repository root (guard-gate logic
> plus structural consistency between the two manifests). A green result is necessary but not sufficient: it
> proves that Chrome and Firefox install the same content scripts and that the verdict logic is correct, but it
> does not prove that the extension actually blocks actions in real Firefox.

## Prerequisites

- [ ] Firefox version ≥ 128 (`world: "MAIN"` content scripts are supported starting with 128; the fetch gate does not load on earlier versions)
- [ ] Use `about:debugging` → “This Firefox” → “Load Temporary Add-on” to load `manifest.firefox.json`
      (or the zip produced by `package-store.sh --firefox`)
- [ ] Record the **gecko id** assigned to the temporary load (expected: `agentguard@agentguard.dev`)
- [ ] Install the native-messaging host with `install-host.sh --browser firefox agentguard@agentguard.dev`
- [ ] Use the rule set at `crates/guard-schema/rules/p0_rules.yaml`; load the intelligence bundle (the default baseline includes `evil.example`)

## Acceptance Cases

Run every case manually on **real Firefox** and retain evidence (screenshots / about:debugging console logs).

| # | Steps | Expected | Actual | Evidence |
|---|-------|----------|--------|----------|
| F1 | Open a test page containing hidden injected text (`[AG_INVISIBLE_TEXT]` / "ignore previous instructions") | The extension reports a finding (it appears in the popup's recent list) | | |
| F2 | Add a button whose label contains “确认支付/Confirm Payment” and click it | **Before execution**, AgentGuard opens a confirmation layer (“Allow once / Not now”); choosing “Not now” prevents the action | | |
| F3 | Submit a form that puts nonessential PII (a phone number) into a trap control | `preventDefault` blocks submission and a confirmation appears; canceling prevents submission | | |
| F4 | Run `fetch("/api/checkout",{method:"POST"})` from the page console | The fetch gate asks for confirmation; after denial, the Promise rejects and the request is **not sent** (no matching request in the Network panel) | | |
| F5 | Repeat F4 with `GET` | The request is **not** blocked (read-only methods should not have side effects) | | |
| F6 | Navigate to `https://evil.example/` (a malicious domain in the bundled intelligence) | The engine returns `INTEL-DOMAIN` Block → the host returns `block_hosts` → a DNR rule is installed → later requests to that host are blocked at the network layer (the Network panel shows blocked) | | |
| F7 | Observe the native-messaging round trip for F6 | The host accepts the caller (the gecko id matches the origin and `guard-nm-host` does not refuse to start because of the origin); the verdict enters the signed audit trail | | |
| F8 | Inspect the number of dynamic DNR rules | The number stays within Firefox's dynamic-rule quota (installing rules produces no error; truncate the list at the quota if necessary) | | |

## Which “Pending Validation” Item in docs/跨浏览器.md Each Case Covers

- F2/F3 → the DOM gate works in Firefox
- **F4/F5 → the `world:"MAIN"` fetch gate really loads and intercepts on FF≥128** (`跨浏览器.md` explicitly marks this as pending)
- F6 → the E5 engine-to-DNR bridge; F8 → DNR quota (`跨浏览器.md` marks the quota as “pending calibration”)
- F7 → **the caller identity received by the native host is a gecko id rather than a chrome-extension:// origin**
  (`跨浏览器.md` says “implemented from MDN guidance, not validated on real hardware”). This is fail-closed
  origin validation: if it fails, the host refuses to start, so it must be exercised on real Firefox.

## Quick Commands

```bash
# Offline gate (must PASS first)
make check-extension-gate

# Build the Firefox package
apps/extension-chromium/scripts/package-store.sh --firefox

# Install the Firefox native-messaging host (see manifest.firefox.json for the gecko id)
apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

## Sign-off

- Tester: ____________  Version / commit: ____________  Date: ____________
- After all cases PASS, export the evidence-directory path as `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`, then run
  `scripts/release-gate.sh --strict` to move this item from "unvalidated" to validated.
