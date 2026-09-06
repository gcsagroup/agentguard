[简体中文](ios-limited-sku.md) | [繁體中文](ios-limited-sku.zh-TW.md) | [English](ios-limited-sku.en.md)

# iOS limited SKU

> **Current status: buildable local candidate; formal release is No-Go.**
>
> The generated [capability matrix](capability-matrix.en.md) is authoritative for mechanical source
> facts. This page records product boundaries and external gates; simulator results are not promoted
> to device, signing, or App Store evidence.

## Implemented: IOS-01 through IOS-05

1. `apps/ios-webshield/project.yml` reproducibly generates an Xcode project with the containing app,
   Safari Web Extension, `WebShieldCore`, and unit/UI tests. The app embeds the extension.
2. An isolated-world Safari content script checks DOM clicks and form submissions, providing local
   cancel/allow-once gates for payment, prompt-injection, and sensitive-form risks.
3. `sendNativeMessage` reaches a versioned, allow-listed Swift contract. The native layer caps message
   size/count and reduces URLs to origins before local audit storage.
4. App Group UserDefaults stores consent and enablement. Atomic JSONL audit storage uses an actor,
   `NSFileCoordinator`, and retention limits. App and extension declare a shared Keychain group and
   contain no production credential.
5. The app provides trilingual enablement guidance, privacy boundary, activity list, and local-clear
   action. App and extension both include PrivacyInfo.

See the [iOS WebShield README](../apps/ios-webshield/README.en.md) for implementation and reproduction
commands.

## Boundaries that must not be broadened

- No monitoring of apps outside Safari, system UI, Accessibility, or screen contents.
- No MAIN world and no `fetch`/XHR interception; direct programmatic requests are outside this SKU.
- No Chromium `connectNative` port, remote DNR intelligence, or upload endpoint.
- Swift-first means platform bridge, state, and audit; it is not a rewrite or equivalent substitute
  for the Rust policy engine.
- This is cooperative in-page protection after Safari site permission, not an unavoidable boundary.

## Evidence obtained

On 2026-09-05 with Xcode 26.6 and the iOS 26.5 Simulator SDK: unsigned Release build, Analyze, and
complete strict-concurrency checking passed; the app product contains the Safari `.appex`; Swift Core
20/20, UI 2/2, and extension Node 18/18 passed; the container app was installed, launched, and visually
checked on an existing iOS 26.5 simulator.

With signing fully disabled, App Group and Keychain entitlements are unavailable. The UI reports the
failure and keeps protection off. This is intentional fail-closed behavior, not signing acceptance.

## Still required before release

- Confirm production bundle IDs, register same-Team App Group/Keychain capabilities, and generate
  profiles.
- Complete a signed Archive, entitlement readback, and App Store Connect validation.
- On representative devices, validate Safari enablement, site permissions, exactly-once allow/cancel,
  process restart, Private Browsing, all three languages, upgrade/uninstall, and local clear.
- Complete TestFlight install/upgrade and privacy-copy review.

Until every gate is complete, iOS may be called a **buildable limited candidate**, not released or
fully supported.
