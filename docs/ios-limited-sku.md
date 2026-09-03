# iOS limited SKU

> **Status: not a supported platform. Nothing below "What exists today" ships.**
> An earlier version of this page was headed "What we ship" and listed three capabilities; none of
> them exist in the repository (real-device report P2-5). The generated
> [capability-matrix.md](capability-matrix.md) is the reference for what each platform actually
> emits and whether an iOS project even exists — it is regenerated under `cargo test`, so this page
> cannot drift ahead of the code again without the build going red.

## What exists today

- One SwiftUI source fragment, `apps/ios-webshield/Sources/ContentView.swift` (~40 lines): a policy
  label and a button that runs a keyword check against a **hard-coded** sample string.
- No `.xcodeproj` / `.xcworkspace` / `Package.swift`, no Safari Web Extension target, no
  `WKWebView` wiring, no engine (`guard-ffi`) binding, no `guard-sync`, no entitlements, signing or
  tests. See [apps/ios-webshield/README.md](../apps/ios-webshield/README.md) for the honest inventory.

## Target scope (design only — none of this is implemented)

- Web / Safari session guidance aligned with the Chromium page-gate heuristics.
- Aura-lite `guard-shell` policy for first-party agent wrappers.
- Enterprise policy pull (`guard-sync`) via MDM / managed config — in production only
  `pull_policy_verified` (out-of-band organisation public key, Ed25519 detached signature), plain
  `http` refused; the unsigned `pull_policy` is for local development and does not authenticate.

## What this SKU will never claim

- System-wide Accessibility monitoring of other agent apps.
- Screen recording of arbitrary apps for overlay OCR.
- "Full AgentGuard companion" on iOS.

## What it would take to list iOS as supported

A reproducible Xcode project or Swift package; a `WKWebView` or Safari Web Extension target with a
message channel; trilingual UI, privacy disclosure, entitlements, signing and packaging; real wiring
to the policy/engine; unit, UI and real-device end-to-end acceptance; App Store capability,
permission and review conclusions. Until then, README, store copy and release notes must describe
iOS as a scaffold — the repository invariant that pins this page to the capability matrix is the
reminder.
