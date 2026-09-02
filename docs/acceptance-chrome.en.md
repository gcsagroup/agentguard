[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium Extension Acceptance Checklist (Chrome / Edge)

This is the Chromium-side counterpart of the Firefox checklist ([acceptance-firefox.en.md](acceptance-firefox.en.md)).
Case numbers mirror Firefox (F1–F8) one-to-one because both browsers load the same content scripts; what differs is
**where the evidence comes from**:

- **C1–C5 (≙ F1–F5) are produced by a real-browser E2E run**: `make e2e-extension` loads `apps/extension-chromium`
  unpacked into a real Chromium (Playwright persistent context), drives the fixture pages in `eval/acceptance-fixtures/`
  with machine assertions, writes `eval/e2e-extension/out/report.json`, and ends with
  `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`. No human in the loop. It is deliberately **not** part of release-gate (it
  needs Playwright + Chromium, which the minimal container lacks); CI runs it as a separate job.
- **C6–C8 (≙ F6–F8) remain manual real-device cases**: native-messaging host, DNR rules, quota. The E2E does not
  install the host (`nativeEnabled` defaults to off and should stay off there); these only count on a real machine
  with `guard-nm-host` installed.

> A fully green checklist is necessary but not sufficient for release. It does not replace store signing,
> release-artifact identity, evidence for other platforms, or the complete release gate. It is **not yet** a strict-gate
> `EvidenceKind` — the extension evidence the strict gate accepts is Firefox F1–F8. Promoting Chrome requires adding a
> kind to `guard-cli evidence-verify` and bumping `EXPECTED_EVIDENCE` accordingly.

## What the E2E proves, and what it does not

Proven (re-proven on every run):

| # | Machine assertion | Firefox twin |
|---|-------------------|--------------|
| C1 | Hidden injection text → background `recent` contains `invisible_injection`; the stored URL is minimized and the title clamped (P1-1) | F1 |
| C2 | Payment-CTA click is held **synchronously**: page handler did not run, `role=alertdialog` appears, default focus on “Not now”, visible text has no raw machine terms; “Not now” → still not run; click again → “Allow once” → handler runs exactly once; each held click leaves one `prevented/payment_cta` entry | F2 |
| C3 | PII form submit under a trap label is held: URL unchanged; after “Allow once” the URL carries `?phone=…` (it really submitted) | F3 |
| C4 | Page-issued `POST /pay/checkout`: the local server **never received a byte** before the dialog; deny → page gets `AbortError`, server still nothing; allow → server receives it and the page sees 501 | F4 |
| C5 | `GET /pay/status` and `POST /api/search` are not gated and reach the server (no false positives) | F5 |
| CP | Popup: forwarding off by default (checkbox unchecked, copy says so), today line has counts, recent list has a “Blocked:” entry, visible text has no raw machine terms | — |

Not proven (honest boundary):

- It runs Playwright’s bundled Chromium in the container (version in report.json), not the user’s release Chrome/Edge.
- No Native Messaging host is installed; C6–C8 (F6–F8 twins) are not automated.
- Firefox: Playwright cannot load extensions into Firefox; real Firefox E2E stays **BLOCKED** (see the Firefox checklist).
- A page script that captured the original `fetch` before `document_start` bypasses the fetch gate — the boundary stated in the `guard-page.js` header; the E2E does not claim to cover it.

## Prerequisites (real-device C6–C8)

- [ ] Release Chrome or Edge; `chrome://extensions` → Developer mode → “Load unpacked” → `apps/extension-chromium`; note the extension ID
- [ ] Install the native-messaging host: macOS/Linux `native-host/install-host.sh --browser chrome <id>`; Windows
      `powershell -ExecutionPolicy Bypass -File native-host\install-host.ps1 -Browser chrome <id>` (`-Browser edge` for Edge)
- [ ] popup → Settings → enable “Desktop forwarding”; the link line should read “connected”
- [ ] Rule set is `crates/guard-schema/rules/p0_rules.yaml`; the intel bundle is loaded (the default baseline already contains `evil.example`)

## Acceptance cases

| # | Steps | Expected | Actual | Evidence |
|---|-------|----------|--------|----------|
| C1–C5 | `make e2e-extension` | Last line `AGENTGUARD_E2E_EXTENSION=PASS`, `all_pass: true` in `report.json`; copy `out/report.json`, `out/f2-payment-dialog.png`, `out/popup.png` into `evidence/chrome/` | | |
| C6 | Navigate to `https://evil.example/` (a malicious domain in the built-in intel) | Engine verdict `INTEL-DOMAIN` Block → host returns `block_hosts` → DNR rule installed → later requests to that host are blocked at the network layer (Network panel shows blocked) | | |
| C7 | Observe the native-messaging round trip of C6 | The host accepts the caller (`chrome-extension://<id>/` origin matches `allowed-origin`; `guard-nm-host` did not refuse to start), the verdict lands in the signed audit; the popup link line reads “connected · last success …” | | |
| C8 | Number of DNR dynamic rules | Within Chromium’s dynamic-rule quota (installing rules does not error; the list is truncated to the quota when necessary) | | |

## Quick commands

```bash
# Offline gate (must PASS first)
make check-extension-gate

# Real-browser E2E (C1–C5 + popup)
make e2e-extension
# → eval/e2e-extension/out/report.json, f2-payment-dialog.png, popup.png

# Build the Chrome package
apps/extension-chromium/scripts/package-store.sh
```
