# Google Play listing (draft)

## App name
AgentGuard Companion

## Short description
Local-first AI agent guardian for Android — intercept risky actions and privacy overfill.

## Full description
AgentGuard Companion uses Accessibility (with explicit user consent) to observe AI agent sessions on your device. It detects payment confirmations, privacy traps, overlay markers, and suspicious deeplinks, and can pause high-risk actions until you confirm.

Data stays on-device by default. Optional signed threat-intel updates may be downloaded.

## Content rating
Privacy / Tools — declare Accessibility use clearly.

## Data safety
- Collected: none uploaded by default
- Shared: none
- Security practices: data encrypted in transit only if user enables sync (future)

## Release signing

Do **not** commit keystores. Local release:

```bash
# Generate once
keytool -genkey -v -keystore ~/agentguard-upload.jks -keyalg RSA -keysize 2048 -validity 10000 -alias agentguard

# gradle.properties (user home) or CI secrets:
AGENTGUARD_STORE_FILE=/path/to/agentguard-upload.jks
AGENTGUARD_STORE_PASSWORD=...
AGENTGUARD_KEY_ALIAS=agentguard
AGENTGUARD_KEY_PASSWORD=...

cd apps/android-companion
./gradlew assembleRelease
```

See `app/build.gradle.kts` `signingConfigs.release` (reads env / gradle properties).

## Sensitive API justification

**`<queries>` for `ADB_INPUT_B64` / `ADB_INPUT_TEXT`** — AgentGuard warns the user
when another installed app has registered a receiver for the text-input broadcast
that AI agent frameworks use to type on the device; such a receiver reads
everything the agent types and requires no permission to do so. Declaring these
two exact actions in `<queries>` limits visibility to packages that match them.
We deliberately do **not** request `QUERY_ALL_PACKAGES`, which would be far
broader than this feature needs.

**`BIND_ACCESSIBILITY_SERVICE`** — core function: the app observes on-screen text
and form fills to warn about risky agent actions. It additionally reads the list of
*other* enabled accessibility services (from `Settings.Secure`) purely to tell the
user that another service can also read their typed text, including passwords. No
accessibility data leaves the device except to the user's own desktop over a
loopback/LAN relay the user configures explicitly.
