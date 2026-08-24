# Verified app identity (AgentScan §3.5 / Aura pillar i)

AgentScan (arXiv 2505.12981) reports **package-name forgery succeeding against all
four** system-interacting agents it tested. The reason is not a missing check; it
is that the check has nothing to check. A package name is a string the attacker
picks, so an allow-list keyed on it grants privileges to whoever asks for them.

`policies/known-apps.yaml` had exactly that shape, and worse: it matched by
*substring*, on either the display name or the package. `com.sankuai.meituan.evil`
inherited Meituan's deeplink allow-list; so did an app that simply called itself
`Fake Meituan`.

An app's identity is now its **signing certificate**.

## The model

`KnownAppsPolicy::identify(package, attested_digests) -> AppIdentity`

| Variant | Meaning | Consequence |
|---|---|---|
| `Verified` | package matches exactly, an attested digest is accepted, **and** the presented display name agrees with the registry | may inherit the app's privileges |
| `NameMismatch` | verifiably app X, presenting itself as Y | `APP-NAME-MISMATCH`, critical block |
| `SignerMismatch` | package claims a registered app, signer does not match | `APP-SIGNER-MISMATCH`, critical block — this is the forgery, caught |
| `Unattested` | registered package, no digest supplied | `APP-UNATTESTED`, once per app; privilege withheld only under `require_attestation` |
| `NoSignerOnRecord` | registered package, entry lists no signers | same — a registry gap, reported as one |
| `Unregistered` | not in the registry | no privileges to inherit; stays quiet |

`identify` resolves **only** by package and signer. A presented display name is
checked *against* the registry (`identify_as`), never used to look anything up —
resolving by name is the attack.

Properties worth stating explicitly:

- **Packages match exactly** (case-insensitively). `com.sankuai.meituan.evil`,
  `evil.com.sankuai.meituan` and `com.sankuai.meitua` all resolve to
  `Unregistered`.
- **Digest comparison ignores formatting.** `keytool`, `apksigner` and `codesign`
  all print colon-separated hex; a policy file that pastes tool output works
  unchanged.
- **Any attested digest may match any accepted digest.** Multiple signers are
  normal — a multiply-signed APK, or a publisher mid key-rotation. Accepting only
  the first would fail a legitimate app, and the failure would look like an attack.
  They arrive in **one** comma-separated `signer_sha256`: an earlier split across
  `signer_sha256` plus `signer_sha256_all` let a *wrong* primary digest be
  whitewashed by an accepted alternate sitting in the other key.
- **A digest must be 64 hex characters.** Anything else is "no attestation", not a
  failed one. Without this any non-empty string was a usable digest — the engine's
  own test pinned `"aa11"` and it verified, and a policy file could pin 64 `z`s.

## Identity is keyed on the package, never the name

The first cut verified identity per (package, signer) and then **stored and consumed
it under the display name**. Any later event that set `source_app: Meituan` and
omitted `package` inherited the verified allow-list with no certificate at all —
`imeituan://pay/transfer?to=attacker` was allowed.

Identity now lives in a package-keyed map. A privilege lookup uses the attestation
on *that event*. Where only a name is available — a flow sink is a bare string —
the question is "has a verified package legitimately claimed this registry name this
session?" (`name_is_verified`), which only a `Verified` identity whose presented name
agreed with the registry can answer yes to.

Pins are cleared at `agent_session_start`. In a long-lived `api-serve` engine a
stale pin outlived both the session and the app.

## An impersonation verdict latches

A `SignerMismatch` or `NameMismatch` for a package holds for the rest of the
session. Without the latch the block fired once and the very next event for the same
package was allowed: the attacker paid one prompt and proceeded.

Conversely, a **missing** attestation never breaks a verified pin. Package-visibility
filtering on Android 11+ makes `getPackageInfo` throw for apps outside `<queries>`,
so a missing digest is a routine transient — and treating it as impersonation both
paused the session under `--confirm deny` and handed any app a denial-of-service
against a legitimate one: claim its package, omit the signer. A *changed* signer is
evidence and does break the pin (`APP-IDENTITY-CHANGED`).

## Enforcement is off by default, on purpose

`KnownAppsPolicy::require_attestation` is `false` in the shipped registry.

This is not timidity; it is what the adapters can deliver. Only the Android
companion reads a signing certificate from the OS. With enforcement on globally, a
registered app on any other platform would have its own deeplinks blocked and — in
the first cut — throw an `APP-UNATTESTED` alert on **every UI event**. Ordinary use
of Meituan produced a continuous alert stream and a broken app. A guard that cries
wolf on the normal path gets switched off, and then it protects nobody.

| | `require_attestation: false` (default) | `require_attestation: true` |
|---|---|---|
| Impersonation (`SignerMismatch`, `NameMismatch`) | blocked | blocked |
| Unattested registered app | falls back to the forgeable name match for its **own** allow-list | inherits nothing (`DL-UNVERIFIED`) |
| HIGH-tier flow clearance | denied unless verified | denied unless verified |
| Unattested report | once per app, log-only | once per app, alert |

The `APP-UNATTESTED` report is once per app per session either way, at `Low`
severity. Both modes are exercised by the corpus: `app_unattested_deeplink` and
`benign_registered_app_unattested` are the same traffic under the two settings.

Turn it on once every adapter in the deployment attests.

## What identity gates

Two privileges, both of which previously rested on a name:

1. **The deeplink allow-list.** Only a `Verified` app inherits its
   `deeplink_prefixes` on the strength of its identity. Under
   `require_attestation` an unverified claimant gets `DL-UNVERIFIED` (block) on a
   custom scheme; with enforcement off it is still held to that app's own allow-list
   by name, which is what the pre-signer registry did. Dropping that fallback
   silently downgraded `DL-ALLOWLIST` (High block) to `DL-UNKNOWN` (Medium alert)
   for every adapter that sends no attestation — i.e. every desktop and browser
   event.
2. **HIGH-tier sink clearance in the information-flow lattice.** This closes the
   gap [information-flow.md](./information-flow.md) left open at item 3: clearance
   for the user's passport number required only that the sink's *name* appear in
   the session's `task_apps`. It now requires the name **and** a verified identity.

## The identity finding never replaces the event's verdict

`resolve_app_identity` runs before the event's own handler and its finding is
**merged** by severity (`worse_of`), not returned instead. The first cut
short-circuited on it, so an `APP-UNATTESTED` *Alert* masked the `DL-UNVERIFIED`
*Block* it should have accompanied — the same lower-severity-masks-higher bug that
`PRIV-FM`/`PRIV-XAPP` had in iteration 12.

Because only one rule id can win per event, the loser's *reason* is appended to the
winner's message (`[identity: …]`) rather than dropped. `worse_of` uses a strict
comparison, so on a severity **tie** the identity finding vanished from the rule id,
the message and the audit record together — a forged package raising an unrelated
critical rule reported only that rule. Scenarios assert on the message via
`decision_message_contains`, which is what makes the difference observable.

## Where the digest comes from

This is the part that decides whether the mechanism is real.

| Platform | Source | Status |
|---|---|---|
| Android | `PackageManager.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES).signingInfo.apkContentsSigners` → SHA-256 | `AppAttestor.kt`, cached per package, attached to every event by `PayloadSerializer.baseEvent`, and — since iteration 19 — actually received by `AndroidEvent` (see below) |
| macOS | `SecCodeCopySigningInformation` / `codesign -dv --verbose=4` (Team ID, CDHash) | **not implemented** |
| Windows | Authenticode publisher (`WinVerifyTrust`) | **not implemented** |

`AppAttestor` was dead code for one iteration — nothing called it, while the docs
called it implemented. It is now installed by `GuardAccessibilityService.onServiceConnected`
and dropped on unbind.

**And then it was dead again, further down the pipe, for six iterations.** Installing the
attestor made `PayloadSerializer` write `signer_sha256` into the envelope JSON. The envelope
reaches the engine through `guard-localapi`, which parses it with
`android_adapter::AndroidEvent` — and that struct had no field for the key, so serde dropped
it. Every app on every real device resolved to `AppIdentity::Unattested` while this table said
the digest was "attached to every event". Fixed in iteration 19: identity keys are forwarded
through an explicit allow-list (not `#[serde(flatten)]` — anything can POST to the local API),
and `every_key_the_companion_sends_has_a_field_here` scans the companion's Kotlin and fails
when a key it writes has nothing to receive it. See
[app-lookalike.md](./app-lookalike.md#the-severed-channel-this-iteration-also-fixed).

The lesson is the one this project keeps relearning: a mechanism is implemented when it is
wired **end to end on a shipped path**, and an eval corpus that injects metadata directly
proves nothing about the wiring. Two dead-code findings on the same mechanism, in the same
direction, at two different boundaries. Results are cached per package because `attest` is a binder
call and the service emits an event on every screen change; a package's certificate
cannot change without a reinstall, which kills the app being observed.

`Unreadable` results are cached too: on Android 11+ an app outside the manifest's
`<queries>` list is *permanently* invisible, so retrying would be a failing binder
call per frame. The manifest lists each registry package explicitly rather than
requesting `QUERY_ALL_PACKAGES` — a guardrail that can enumerate every installed app
is a privacy problem of its own, and Play Store review treats that permission as a
last resort. A deployment that pins more apps must add them to `<queries>` too.

## Where it is loaded

The mechanism spent an iteration reachable from nothing but the eval harness: no
shipped entry point built an `Engine` with a registry, so `api-serve` — the server
the Android companion relays into — could not load one at all. Now:

| Entry point | How |
|---|---|
| `api-serve` | `--known-apps` (default `policies/known-apps.yaml`, loaded when it exists) |
| native-messaging host | `AGENTGUARD_KNOWN_APPS`, else the repo default; parse failure logs to stderr |
| FFI / desktop shells | `ag_engine_new_with_registry(rules, policy, known_apps)`; the old `ag_engine_new` still means *no* verification |
| eval / coverage / acceptance | `--known-apps` |

On Android the digest comes from the **OS**. The companion asks `PackageManager`
itself, and the agent cannot forge that answer. `apkContentsSigners` is used rather
than `signingCertificateHistory`: history includes keys the publisher has *rotated
away from*, which is precisely the key most likely to have leaked.

`AppAttestor.attest` returns a sealed `Signed` / `Unsigned` / `Unreadable` rather
than a nullable string, because from Android 11 (API 30) package-visibility
filtering makes `getPackageInfo` throw `NameNotFoundException` for apps the
companion cannot see — indistinguishable from "not installed" if it were swallowed.
`Unreadable` becomes `APP-UNATTESTED`, never `Verified` and never silently clean.

### The boundary that remains

**The digest is only as good as the adapter that produced it.** The Rust engine
reads `signer_sha256` off the event, so:

- an adapter that queries the OS (Android's `AppAttestor`) genuinely moves the
  trust boundary — the agent cannot forge a `PackageManager` answer;
- an adapter that forwards a digest the agent handed it gains **nothing at all**.
  It is worth exactly as much as the package name was.

This is why `agentscan-package-forgery` is `partial` rather than `covered` in the
coverage matrix, alongside the two platforms with no attestation at all.

## The shipped digests are fixtures

`policies/known-apps.yaml` contains obvious placeholder digests (repeated
nibbles), and says so in a banner. This is deliberate:

> A registry pinning a wrong digest is worse than no registry: it looks verified
> and verifies nothing.

Inventing plausible-looking digests for real publishers would be a fabrication that
*reads* as a security control. A test
(`policy.rs::repo_registry_is_internally_consistent`) asserts every shipped digest
stays an obvious fixture and that the banner is present, so pinning a real value is
a deliberate act that trips the test rather than a silent drift.

To pin real values:

```bash
# Android, from an APK
apksigner verify --print-certs app.apk | grep 'SHA-256 digest'
# Android, on device
adb shell pm list packages -f | grep <pkg>
# macOS
codesign -dv --verbose=4 /Applications/X.app
# Windows
Get-AuthenticodeSignature X.exe | Select-Object -Expand SignerCertificate
```

## What a signature does not prove

- **Not good behaviour.** Meituan signed by Meituan is still Meituan doing whatever
  Meituan does. Identity verification answers "is this who it claims to be", not
  "should it be trusted".
- **Not agent identity.** Aura pillar (i) also wants the *agent* attested, so an
  action can be cryptographically attributed to one of several agents on a device.
  Nothing here does that; two agents are indistinguishable to the guard. That, and
  mutual attestation between agent and guard, is what remains of pillar (i).
- **Nothing when no registry is loaded.** Without `--known-apps` there is no
  identity to verify, so `task_apps` clearance falls back to the name-only
  guarantee. That is a weaker configuration, tested
  (`no_registry_falls_back_to_the_name_only_guarantee`) rather than assumed.

## Scenarios

| Scenario | Asserts |
|---|---|
| `app_signer_mismatch` | the forgery itself → `APP-SIGNER-MISMATCH` |
| `app_identity_changed_midsession` | a verified app cannot swap identity → `APP-IDENTITY-CHANGED` |
| `app_unattested_deeplink` | no attestation → privilege withheld, reason in the message |
| `app_no_signer_on_record` | unverifiable registry entry is not a verified one |
| `flow_clearance_needs_verified_app` | HIGH-tier clearance needs identity, not a name |
| `deeplink_forgery_block` | a *verified* app still obeys its own allow-list |
| `benign_registered_deeplink` | the verified path works |
| `benign_flow_verified_task_app` | the verified flow path works |
| `benign_unregistered_app_web_link` | unregistered apps stay quiet |

The four benign controls exist because every check here could be "satisfied" by
refusing everything. Most apps on a device are unregistered; if identity checking
made all of them noisy, the registry would be switched off and the mechanism would
protect nobody.
