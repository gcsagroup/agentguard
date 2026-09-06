# Google Play Listing Draft

[简体中文](PLAY_STORE.md) · [繁體中文](PLAY_STORE.zh-TW.md) · English

> **Release-preparation draft only; not submitted to Google Play.** Recheck this copy after obtaining a release-signed AAB, physical-device acceptance evidence, an Accessibility API declaration, and a completed Play Console Data safety form.

## App name

AgentGuard Companion

## Short description

Observe Android AI-agent sessions and notify users after payment, privacy, or UI risks are detected.

## Full description

After the user explicitly enables the Accessibility service and starts a guard session, AgentGuard Companion observes UI text, form fills, permission dialogs, and window overlays. It can identify payment or transfer prompts, privacy traps, unnecessary personal-data entry, suspicious deep-link strings appearing in on-screen text, and prompt-injection markers, then record events and display risk notifications on the device. It does not observe deep links themselves (an Accessibility service does not see intents); the events each platform actually emits are listed in the generated [docs/capability-matrix.en.md](../../docs/capability-matrix.en.md), and store copy must not claim beyond it.

The current Release build does not expose desktop relay. Debug builds retain relay wiring for development, but Relay v1 responses are unauthenticated and therefore cannot ship. The feature may re-enter release scope only after independent acceptance of response authentication and replay protection.

**Important boundary:** the Android companion observes and notifies after an event. It cannot pause, undo, or prevent a payment, transfer, or other action already performed by a third-party app, and it must not be described as a system-level interceptor.

## Current release blockers

- The current configuration is `compileSdk = 36` and `targetSdk = 36` (AGP 8.11.1; lint is clean with warnings treated as errors). Google Play requires API 36 from 2026-08-31, so the configuration now complies; see Google's [official target API requirements](https://support.google.com/googleplay/android-developer/answer/11926878).
- Android 16 emulator evidence covers enforced edge-to-edge, notification permission and status, Accessibility start/stop, runtime revocation, and fail-closed process death. **Android 15/16 physical-device and OEM regression testing remains open**; emulator evidence does not clear that release blocker.
- The repository contains no production upload keystore, verified release-signed AAB evidence, Play Console review result, or physical-device end-to-end acceptance record.
- The final Accessibility API declaration, Data safety form, and store assets have not been reviewed.

## Data safety draft

- Default processing: Accessibility events, app/window information, and risk results remain in the app-private directory.
- Uploaded to developer servers by default: none.
- Optional transfer: the current store candidate has no desktop relay; Debug development builds are not release artifacts.
- Sharing: no third-party sharing by default.
- Deletion: uninstalling removes app-private data; an in-product deletion flow and formal retention policy still need to be defined before release.

This describes the current code; it is not an approved or submitted Play Console declaration.

## Sensitive capability justification

### Accessibility service

The core feature requires `BIND_ACCESSIBILITY_SERVICE` to observe UI text and form changes during a guard session explicitly started by the user. The service detects payment, privacy, and injection risks but cannot reverse third-party actions.

### Package visibility

The manifest uses narrow `<queries>` entries for receivers matching `ADB_INPUT_B64` / `ADB_INPUT_TEXT` and queries launchable apps for lookalike checks. The project does not request `QUERY_ALL_PACKAGES`, but launcher visibility still has privacy implications and must be disclosed accurately during review.

### Notifications and Accessibility-service status

An active guard session uses an ordinary ongoing notification (the AccessibilityService owns the lifecycle; no `dataSync` foreground service is declared). Android 13 and newer also require user-granted notification permission. High-risk notifications are after-the-event alerts; if permission is denied, risks are still logged but the user may not receive a timely alert.

## Release-signing wiring

Never commit a keystore, passwords, or credential-bearing `gradle.properties`. Example:

```bash
keytool -genkeypair -v \
  -keystore /secure/path/agentguard-upload.jks \
  -alias agentguard \
  -keyalg RSA -keysize 2048 -validity 10000

export AGENTGUARD_STORE_FILE=/secure/path/agentguard-upload.jks
export AGENTGUARD_STORE_PASSWORD='<read-from-secure-credential-store>'
export AGENTGUARD_KEY_ALIAS=agentguard
export AGENTGUARD_KEY_PASSWORD='<read-from-secure-credential-store>'

cd apps/android-companion
./gradlew --no-daemon :app:bundleRelease
```

`signingConfigs.release` in `app/build.gradle.kts` reads those environment variables or Gradle properties with the same names. A successful build is not release proof: verify the certificate identity, exercise the permission lifecycle on physical devices, and complete Google Play review. Desktop relay is outside the current Release acceptance scope.

See the [Android Companion README](README.en.md) and [privacy policy](../../docs/privacy-policy.en.md) for more detail.
