# AgentGuard Android Companion

[简体中文](README.md) · [繁體中文](README.zh-TW.md) · English

The Android companion uses Kotlin, Jetpack Compose, and an `AccessibilityService` to observe UI events during a guard session. It runs local heuristics and writes minimized JSONL event envelopes.

> Current status: the source, JVM unit tests, Debug APK, and API 36 emulator permission lifecycle have been verified. There is no physical-device end-to-end acceptance record, release-signing evidence, or Google Play release. Notifications arrive after an event; they cannot pause, undo, or prevent an action already performed by a third-party app. Relay v1 responses are unauthenticated, so Release builds force the desktop relay off; it remains available only in Debug builds for protocol development.

## What it does

- Observes text changes, UI text, permission dialogs, and window overlays (the events each platform actually emits are listed in the generated [docs/capability-matrix.en.md](../../docs/capability-matrix.en.md)).
- Detects payment/transfer text, privacy traps, unnecessary personal data, prompt-injection markers, and suspicious deep-link **strings** appearing in on-screen text (`intent://` and the like). It does not observe deep links themselves — an Accessibility service does not see intents.
- Surveys visible text-input broadcast receivers and other enabled accessibility services.
- Appends each session's envelopes to the private `files/events/session-<id>.jsonl` path.
- Debug builds can relay envelopes to a user-configured desktop API for protocol testing; Release builds force this path off until response authentication is complete.
- Signs the exact HTTP body with a non-exportable ECDSA P-256 key held by Android Keystore.

## Build and test

Use JDK 21 (the version verified for this project) and an Android SDK containing the API 36 platform and build-tools 36.0.0 (AGP 8.11). Gradle requires at least JDK 17, but this project does not claim compatibility with every newer JDK; the default JDK 25 is known to fail. Open `apps/android-companion` in Android Studio, or run from the repository root:

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
3. Return to the app and tap **Start guard session**. The AccessibilityService displays an ordinary ongoing status notification.
4. Only for Debug protocol testing, start the local API and enable relay. Release builds do not expose or enable that control.

Example USB debugging path:

```bash
# Desktop, from the repository root
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# Forward the phone's 127.0.0.1:8788 to the desktop
adb reverse tcp:8788 tcp:8788
```

The Debug relay endpoint defaults to `http://127.0.0.1:8788/v1/events`. This HTTP path is for local development only and must not be used as a release configuration. Never expose the local API to a network without authentication.

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

- No Rust engine or FFI runs on the phone; the current Release product provides local heuristics only, and desktop relay is outside the release scope.
- Android high-risk prompts are after-the-event notifications, not pre-action confirmation dialogs.
- There is no physical-device permission-lifecycle test or real-agent end-to-end record; API 36 emulator evidence does not replace a device run.
- There is no release-keystore signing evidence and no Google Play submission.
- `compileSdk / targetSdk = 36` meets Google Play's target-API requirement. Android 16 emulator evidence covers edge-to-edge, notification permission and status, Accessibility start/stop, runtime revocation, and fail-closed process death; **API 35+ physical-device and OEM regression testing remains open**. See the [Google Play draft](PLAY_STORE.en.md).

The cross-language signature format is fixed by `eval/fixtures/adapter_signature_vectors.json`; see [adapter assertion signing](../../docs/适配器断言签名.md) for the design.
