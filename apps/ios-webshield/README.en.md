# AgentGuard iOS WebShield (limited direction)

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

This directory currently contains one SwiftUI source snippet: `Sources/ContentView.swift`. It displays policy status and runs a simple keyword demo against a built-in sample string.

> This is not a directly buildable iOS app. The repository contains no `.xcodeproj`, `.xcworkspace`, Swift Package manifest, Safari Web Extension target, signing configuration, entitlements, or runnable iOS tests.

## What actually exists

- One SwiftUI `ContentView`.
- A `LocalHeuristics.scanDemoPage()` demonstration that processes fixed sample text only.
- No `WKWebView` wiring and no Safari Web Extension implementation.
- No connection to the Rust engine, `guard-sync`, Managed App Configuration, or an App Group.

This directory is therefore only a starting point for a limited iOS SKU. It is not evidence of web shielding, session isolation, or release capability.

## Local experiment

To view the snippet:

1. Create a new SwiftUI iOS App in Xcode, for example `AgentGuardWebShield`.
2. Copy `Sources/ContentView.swift` into that project and make it the initial view.
3. Select a development team and Bundle Identifier, then build for a simulator or device.

Those steps create a local Xcode project outside this repository. Do not interpret them as a reproducible iOS build supplied by the repository.

## Requirements for a deliverable component

At minimum, this still needs:

- a reproducible Xcode project or Swift Package structure;
- a defined `WKWebView` or Safari Web Extension target and message channel;
- trilingual UI, privacy disclosure, entitlements, signing, and packaging configuration;
- real wiring to AgentGuard policy and engine behavior;
- unit, UI, and physical-device end-to-end tests; and
- an App Store capability, permission, and review decision.

Current conclusion: **the source snippet is available for experimentation; an iOS product and release artifact do not yet exist.**
