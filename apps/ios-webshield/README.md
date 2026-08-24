# AgentGuard iOS WebShield (limited SKU)

iOS cannot run a full Accessibility companion. This package is a **WKWebView / Safari Web Extension style** scaffold for session-level shielding and Aura-lite policy checks.

## Scope
- In-app web agent sessions
- Local heuristic scans mirrored from Chromium Web Shield
- Policy pull via managed config / `guard-sync` JSON

## Open in Xcode
1. Create a new iOS App (SwiftUI) named `AgentGuardWebShield`
2. Replace `ContentView` with the snippet in `Sources/ContentView.swift`
3. Add App Group / Managed App Config later for enterprise policy

## Build note
This directory is **source documentation + Swift snippets**, not a full `.xcodeproj` (avoids binary project churn). Generate the Xcode project locally when ready to ship.
