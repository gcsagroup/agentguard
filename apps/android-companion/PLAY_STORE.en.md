# Google Play Listing Draft

[简体中文](PLAY_STORE.md) · [繁體中文](PLAY_STORE.zh-TW.md) · English

> **Release-preparation draft only; not submitted to Google Play.** Recheck this copy after obtaining a release-signed AAB, physical-device acceptance evidence, an Accessibility API declaration, and a completed Play Console Data safety form.

## App name

AgentGuard Companion

## Short description

Observe Android AI-agent sessions and notify users after payment, privacy, or UI risks are detected.

## Full description

After the user explicitly enables the Accessibility service and starts a guard session, AgentGuard Companion observes UI text, form fills, deep links, and window overlays. It can identify payment or transfer prompts, privacy traps, unnecessary personal-data entry, suspicious deep links, and prompt-injection markers, then record events and display risk notifications on the device.

Users may optionally relay events to a desktop AgentGuard local API they control. The relay uses a Bearer token, and the Android companion signs request bodies with an ECDSA P-256 key held by Android Keystore. The user must register the device public key with the desktop adapter registry.

**Important boundary:** the Android companion observes and notifies after an event. It cannot pause, undo, or prevent a payment, transfer, or other action already performed by a third-party app, and it must not be described as a system-level interceptor.

## Current release blockers

- The current configuration is `compileSdk = 34` and `targetSdk = 34`.
- As of 2026-08-28, ordinary mobile-app submissions and updates on Google Play must target at least API 35; the requirement rises to API 36 on 2026-08-31. The current build cannot be submitted as a compliant new app or update. See Google's [official target API requirements](https://support.google.com/googleplay/android-developer/answer/11926878).
- The repository contains no production upload keystore, verified release-signed AAB evidence, Play Console review result, or physical-device end-to-end acceptance record.
- The final Accessibility API declaration, Data safety form, and store assets have not been reviewed.

## Data safety draft

- Default processing: Accessibility events, app/window information, and risk results remain in the app-private directory.
- Uploaded to developer servers by default: none.
- Optional transfer: events are sent only after the user enables relay to a desktop API they configure.
- Sharing: no third-party sharing by default.
- Deletion: uninstalling removes app-private data; an in-product deletion flow and formal retention policy still need to be defined before release.

This describes the current code; it is not an approved or submitted Play Console declaration.

## Sensitive capability justification

### Accessibility service

The core feature requires `BIND_ACCESSIBILITY_SERVICE` to observe UI text and form changes during a guard session explicitly started by the user. The service detects payment, privacy, and injection risks but cannot reverse third-party actions.

### Package visibility

The manifest uses narrow `<queries>` entries for receivers matching `ADB_INPUT_B64` / `ADB_INPUT_TEXT` and queries launchable apps for lookalike checks. The project does not request `QUERY_ALL_PACKAGES`, but launcher visibility still has privacy implications and must be disclosed accurately during review.

### Notifications and foreground service

An active guard session uses an ongoing foreground-service notification. Android 13 and newer also require user-granted notification permission. High-risk notifications are after-the-event alerts; if permission is denied, risks are still logged but the user may not receive a timely alert.

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

`signingConfigs.release` in `app/build.gradle.kts` reads those environment variables or Gradle properties with the same names. A successful build is not release proof: verify the certificate identity, raise `targetSdk`, exercise permissions and relay on a physical device, and complete Google Play review.

See the [Android Companion README](README.en.md) and [privacy policy](../../docs/privacy-policy.en.md) for more detail.
