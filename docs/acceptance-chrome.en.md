[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium Extension Acceptance Checklist (First GA: Chrome / Edge)

The first-GA browser product is one Chromium MV3 ZIP shared by Chrome and Edge. It is **block-only**: matching DOM actions and payment-shaped network requests are stopped, with no in-page “Allow once,” temporary exception, or action replay. The GA manifest does not request `nativeMessaging`, and the release ZIP does not carry a Native host. Firefox remains source-only prototype material and is outside this checklist, package, and first-GA gate.

Acceptance has two layers:

- `make e2e-extension` runs 39 machine assertions in a test Chromium and proves the blocking behavior of source and packaged content;
- the candidate ZIP must still be installed and exercised separately in release Chrome and release Edge, including upgrade and permission evidence.

Automation does not replace store signing, release browsers, candidate-ZIP identity, or other platform evidence. The strict gate requires separate structured acceptance evidence for Chrome and Edge; one Chromium test report cannot stand in for both release browsers.

## Automated acceptance

`make e2e-extension` installs the extension in a real Chromium persistent context, writes `eval/e2e-extension/out/report.json`, and prints one final marker: `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`. Its 39 cases are grouped below.

| Group | Machine assertion |
|---|---|
| D0 / D0b / D0c | Default static ruleset enabled; every DNR regex accepted by the browser; representative `POST /pay/checkout` selects a block |
| U1 | Upgrade to the no-Native GA clears legacy pause, host blocklist, dynamic DNR, and badge |
| F1 / F1b | Hidden injection reaches Recent; URL is minimized and title clamped instead of storing raw sensitive URLs |
| F2a–F2f / H0 / H1 / H5 | Normal, early-capture, and open-Shadow-DOM payment CTAs are stopped before page handlers; notice has only Close; page tampering cannot authorize or replay; every click is blocked and recorded again |
| F3a–F3d | Privacy-trap forms and payment actions in an ordinary child frame are stopped before navigation/POST; closing the notice does not submit |
| F4a–F4e / H2–H4 | fetch, XHR, sendBeacon, form, declared encodings, and operation queries are blocked by DNR before the server; legacy decision/scope messages and the removed 15-second timeout cannot release |
| F5a–F5d | GET, ordinary POST, body-only payment semantics, pay-prefixed ordinary words, and nested query text are not falsely blocked |
| M1–M4 | Mutation storms are deduplicated and throttled without losing a distinct later finding |
| P1–P4 | GA has no Native permission and hides unavailable controls; counters, Recent, and visible trilingual copy are correct |

Run:

```bash
make check-extension-gate
make e2e-extension
```

Success requires exit code 0, a final `AGENTGUARD_E2E_EXTENSION=PASS` line, `all_pass: true` in `report.json`, and exactly the 39 expected PASS records. Preserve the Chromium version in the report; never relabel it as release Chrome or Edge evidence.

## Manual candidate-ZIP acceptance in Chrome / Edge

Run separately in both release browsers using the same store-candidate ZIP. Do not install a Native host or enable any desktop-forwarding prototype.

| ID | Action | PASS criterion | Required evidence |
|---|---|---|---|
| B1 | Record ZIP SHA-256, manifest version, and release-browser version; unpack and load | Chrome and Edge use the same SHA-256; manifest lacks `nativeMessaging`; no unexpected permission prompt | Hash, versions, extension-details page |
| B2 | Install in a clean profile and open onboarding and popup | Icons, trilingual copy, and permission disclosure render correctly; no Native control is visible; `payment_shape_block` is enabled | Onboarding, popup, ruleset state |
| B3 | Repeat F2, H5, F3, F4a/F4c/F4d, and F5a/F5b/F5d against local fixtures | Payment/trap actions have no side effect; positive network cases make zero server requests; negatives arrive; notice has only Close and closing never executes | Page result, Network panel, server counts |
| B4 | Upgrade in place from the previous public version to the same candidate ZIP | No new Native permission; legacy pause, dynamic host rules, and badge are cleared; representative blocking covered by the 39 cases still works | Before/after permissions, storage/rules, popup |
| B5 | Disable, re-enable, uninstall, then exercise the documented rollback to the previous candidate | Browser state is predictable and no page-approval state remains; rollback is not recorded as a PASS for the current candidate | Operation log and final extension state |

If either browser is missing, any row is indeterminate, or evidence is not bound to the candidate ZIP, record `BLOCKED`; do not collapse the result into “Chromium passed.”

Make separate copies of the central report template under `evidence/chrome/` and `evidence/edge/`. B1–B5 must each be `PASS (native)` with distinct nonempty evidence files. B1 evidence records the shared candidate ZIP SHA-256. Then run:

```bash
guard-cli manual-acceptance chrome docs/acceptance-chrome.md evidence/chrome/report.md --repo-root .
guard-cli manual-acceptance edge docs/acceptance-chrome.md evidence/edge/report.md --repo-root .
```

The Chrome report contains the exact line `AGENTGUARD_ACCEPTANCE_CHROME=PASS`; the Edge report contains `AGENTGUARD_ACCEPTANCE_EDGE=PASS`. Passing structural validation remains unsigned local self-attestation and does not replace store review or production-download smoke.

## Explicit boundaries

- The DOM guarantee covers only HTTP(S) frames where the extension is actually injected and can observe a recognizable `click` / `submit` event. Direct `form.submit()`, uninjected special frames, custom pointer/keyboard pre-handlers, and native-app actions are outside it.
- Static DNR covers only the documented HTTP(S), non-GET/HEAD, payment keywords/encodings, query keys, and resource types. It does not inspect bodies or cover undeclared aliases, double encoding, WebSocket/WebTransport, or undeclared resource types.
- The page notice is a page-influenceable information layer, not an authorization surface. Continuing requires disabling or removing protection in the extension manager and independently repeating the action.
- Firefox and Safari prototypes, historical screenshots, and old acceptance reports are not first-GA Chrome / Edge evidence.

## Packaging

```bash
apps/extension-chromium/scripts/package-store.sh
unzip -t apps/extension-chromium/dist/agentguard-extension.zip
shasum -a 256 apps/extension-chromium/dist/agentguard-extension.zip
```

`package-store.sh --firefox` must fail without producing a Firefox ZIP. That is a scope guard, not Firefox acceptance.
