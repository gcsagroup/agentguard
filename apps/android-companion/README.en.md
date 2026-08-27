# AgentGuard Android Companion

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

The Android companion uses Kotlin, Jetpack Compose, and an `AccessibilityService` to observe UI events during a guard session. It runs local heuristics, writes JSONL event envelopes, and can optionally relay those envelopes to the desktop AgentGuard engine.

> Current status: the source, JVM unit tests, and Debug APK build path are available. There is no physical-device end-to-end acceptance record, release-signing evidence, or Google Play release. Notifications arrive after an event; they cannot pause, undo, or prevent an action already performed by a third-party app.

## What it does

- Observes text changes, UI text, deep links, permission dialogs, and window overlays.
- Detects payment/transfer text, privacy traps, unnecessary personal data, and prompt-injection markers.
- Surveys visible text-input broadcast receivers and other enabled accessibility services.
- Appends each session's envelopes to the private `files/events/session-<id>.jsonl` path.
- Optionally relays envelopes to a user-configured desktop local API and displays high-risk verdict notifications.
- Signs the exact HTTP body with a non-exportable ECDSA P-256 key held by Android Keystore.

## Build and test

Use JDK 21 (the version verified for this project) and an Android SDK containing API 34. Gradle requires at least JDK 17, but this project does not claim compatibility with every newer JDK; the default JDK 25 is known to fail. Open `apps/android-companion` in Android Studio, or run from the repository root:

```bash
cd apps/android-companion
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug
```

The Debug APK is written to:

```text
apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

## Run

```bash
adb install -r apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

On the device:

1. Grant notification permission on Android 13 and newer.
2. Open system Accessibility settings and enable AgentGuard Companion.
3. Return to the app and tap **Start guard session**. The foreground service displays an ongoing notification.
4. For desktop-engine verdicts, start the local API, copy the Bearer token printed by the CLI, then enter the endpoint and token in the app and enable relay.

Example USB debugging path:

```bash
# Desktop, from the repository root
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# Forward the phone's 127.0.0.1:8788 to the desktop
adb reverse tcp:8788 tcp:8788
```

The default relay endpoint is `http://127.0.0.1:8788/v1/events`. Wi-Fi/LAN mode requires an explicit `--allow-lan` flag, a non-loopback bind, and a strong Bearer token. Never expose the local API to a network without authentication.

Use Android Studio's Device File Explorer or `run-as` to read JSONL from the app-private directory. Each line is one envelope; save one line as a JSON file for offline replay:

```bash
cargo run -p guard-cli -- ingest-android --payload /path/to/one-envelope.json
```

## Adapter assertion signing

The app signs the exact UTF-8 HTTP body and carries assertion metadata in these request headers:

```text
X-AgentGuard-Adapter: android-companion
X-AgentGuard-Timestamp: <milliseconds>
X-AgentGuard-Signature: <DER signature as hex>
```

Android Keystore manages the key and does not expose its private material through the app API. Android 9 and newer first request StrongBox, then fall back to the device's available Keystore implementation. Do not claim universal hardware backing without device-specific evidence.

To wire the device key into the desktop verifier:

1. Enable desktop relay in the app, tap **Show adapter public key**, and copy the 130-character SEC1 hex public key beginning with `04`.
2. From the desktop repository root, generate a registry card:

   ```bash
   cargo run -p guard-cli -- adapter-card \
     --adapter-id android-companion \
     --platforms android \
     --public-key <130-character-hex-public-key>
   ```

3. Merge the output into `policies/adapter-registry.yaml` and restart the desktop API.

Without the registered public key, the desktop treats companion surveys as unsigned: they may add risk but cannot use a "clean environment" assertion to clear existing risk. This signature attributes the envelope to a holder of the device key; it does not prove that the app is unmodified and does not replace Play Integrity or device-integrity attestation.

## Environment-survey limits

`EnvironmentScanner` checks manifest-declared receivers matching `ADB_INPUT_B64` / `ADB_INPUT_TEXT` and other enabled accessibility services. Package visibility limits apply on Android 11 and newer. A "clean" result means no currently visible match was found, not that no listener exists on the device. See [Android environment survey](../../docs/android-env-survey.md).

## Incomplete and release boundaries

- No Rust engine or FFI runs on the phone; core verdicts depend on the optional desktop relay.
- Android high-risk prompts are after-the-event notifications, not pre-action confirmation dialogs.
- There is no instrumented test, physical-device permission-lifecycle test, or real-agent end-to-end record.
- There is no release-keystore signing evidence and no Google Play submission.
- The current `targetSdk = 34` does not meet Google Play's present requirement for new apps and updates; see the [Google Play draft](PLAY_STORE.en.md).

The cross-language signature format is fixed by `eval/fixtures/adapter_signature_vectors.json`; see [adapter assertion signing](../../docs/适配器断言签名.md) for the design.
