[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

# AgentGuard iOS WebShield

Status: **buildable Swift-first limited SKU; formal release remains No-Go.**

This directory now contains a formal XcodeGen definition, an iOS container app, a Safari Web
Extension, shared `WebShieldCore`, Swift unit/UI tests, and independent extension-script tests. It
does not bind the experimental Rust `guard-ffi`, and it is not evidence for signing, real-device
Safari, or TestFlight acceptance.

## IOS-01 through IOS-05

- **IOS-01 project:** `project.yml` generates app, Safari extension, static Core, and unit/UI test
  targets. The containing app embeds the extension through Embed App Extensions.
- **IOS-02 Safari gate:** an isolated-world Manifest V3 content script runs at `document_start` in
  every permitted matching HTTP(S) frame and registers capture listeners synchronously. `unknown`
  and `unavailable` fail closed for classified risky clicks/submissions; only a native-confirmed
  `disabled` state allows them through. When enabled, allow-once or cancel emits only a minimized event.
- **IOS-03 contract and storage:** native messaging accepts only version-1 allow-listed fields, with
  64 KiB/50-event limits; URLs are reduced to HTTP(S) origins. App Group UserDefaults stores consent
  and enablement. An atomic JSONL audit is coordinated by an actor and `NSFileCoordinator`, retaining
  at most 7 days or 500 records. Reads also physically remove expired lines within the same
  coordinated write transaction.
- **IOS-04 privacy and UI:** the app and extension include Simplified Chinese, Traditional Chinese,
  and English copy, enablement guidance, local-clear action, App Group/Keychain entitlements,
  PrivacyInfo, and icons.
- **IOS-05 tests:** Core behavior, unsigned capability boundaries, UI launch, and extension contracts
  are automated.

## Build

The generated `.xcodeproj` is excluded by this directory's `.gitignore` and is reproducible from
`project.yml`:

```bash
xcodegen generate --spec apps/ios-webshield/project.yml

xcodebuild \
  -project apps/ios-webshield/AgentGuardWebShield.xcodeproj \
  -scheme AgentGuardWebShield \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

Extension tests:

```bash
node --test apps/ios-webshield/Tests/ExtensionTests/*.test.cjs
```

## Data and message boundary

Page code sends only a contract version, random request ID, rule ID, fixed finding/action values,
time, and current URL. Swift validates every field again and reduces the URL to its origin before
storage. Raw DOM, input values, URL paths, queries, fragments, and page titles are neither stored nor
uploaded.

The audit file is in App Group `group.com.agentguard.webshield`. Both targets declare the same
Keychain access group. With code signing fully disabled, Keychain and App Group return entitlement
errors; the product stays disabled instead of silently using an unshared sandbox fallback.

## Provable Safari boundary

- `document_start` plus capture listeners narrows the registration window, but an isolated world is
  not guaranteed to precede every page-world script. The gate can cancel only cancelable DOM events
  it receives and cannot undo side effects completed earlier by page listeners.
- `all_frames` covers HTTP(S) frames that match the manifest and have site permission. It is not a
  claim about arbitrary `about:blank`/`srcdoc` frames, frames without permission, or pre-injection actions.
- Open Shadow DOM coverage is limited to roots found during the initial scan, DOM mutations, or an
  event's `composedPath()`. Closed shadow roots and script-direct network/API calls are not covered.
- While status is pending or native messaging is unavailable, only locally classified risky
  candidates are stopped and never auto-replayed; ordinary actions continue. A native-confirmed
  disabled state allows the action according to the user's explicit setting.

## Explicitly unsupported

- No MAIN world, `window.fetch`, or `XMLHttpRequest` patching.
- No long-lived `connectNative`, remote DNR intelligence, or upload endpoint.
- No monitoring of other apps, system UI, Accessibility, or screen contents.
- No claim of direct network-request coverage or Rust-engine policy parity.

## Local acceptance on 2026-09-05

- Xcode 26.6, iOS 26.5 Simulator SDK, XcodeGen 2.46.0.
- Generic Release simulator and device builds passed with `CODE_SIGNING_ALLOWED=NO`. The device bundle
  is unsigned; the simulator binary has only a linker ad-hoc signature, so neither is distribution-signing
  evidence. The app contains the Safari `.appex` and every declared resource; Release Analyze was clean.
- `WebShieldCoreTests`: 20/20 passed.
- `AgentGuardWebShieldUITests`: 2/2 passed.
- Safari extension Node contract/lifecycle tests: 18/18 passed.
- The container app was installed and launched on the existing iOS 26.5 “Aegis QA iPhone 17”
  simulator.

See [Acceptance/README.md](Acceptance/README.md) for the screenshot and environment record.

## Release blockers

The repository has no provisioning profile or developer-portal registration evidence for the App
Group/Keychain capabilities. Archive/signing, real-device Safari enablement and site permissions,
Private Browsing, upgrade/uninstall, and TestFlight remain unverified. The release decision stays
**No-Go** until Team, App IDs, profiles, and those acceptance gates are completed.
