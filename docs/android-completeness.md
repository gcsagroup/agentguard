# The Android companion: what it emits, and what it still cannot do

## What was here before

The Kotlin was real — a working `AccessibilityService`, signer digests and icon hashes from
`PackageManager`, a genuine environment survey. But of the seven event kinds `PayloadSerializer`
could build, **three had callers**: `ui_text`, `form_fill`, `env_survey`. `overlay_marker`,
`deeplink`, `permission_request` and `network_meta` were functions nobody invoked, and
`session_start` / `session_end` did not exist in the Kotlin at all.

The effect was not that four features were missing. It was that the rules over those kinds were
**inert on the platform the papers demonstrate them on**, while the coverage matrix counted the
surfaces as covered because the desktop adapter could produce them.

Three more things were true and invisible:

- `POST_NOTIFICATIONS` was declared in the manifest and **never requested at runtime**, so on API
  33+ it was never granted — and notifications are the only channel by which a confirmation
  reaches the user on a phone. Declaring a permission is not holding it.
- `RelayClient.postAsync` drained `responseCode` and threw it away. The phone could report a
  payment sheet, the engine could decide `Block` with `require_confirm`, and nothing on the phone
  would ever know.
- There were **zero tests**. Not few — none. The Gradle wrapper was incomplete (no `gradlew`, no
  `gradle-wrapper.jar`), so there was no way to run any.

## What it emits now

Eight of the nine kinds, each from a real observation source.

| Kind | Source | Rules it feeds |
|---|---|---|
| `ui_text` | accessibility tree text | `OVL-004`, `INTEL-INJECT`, `FW-TEXT-ANOMALY`, `CRIT-*` |
| `form_fill` | `TYPE_VIEW_TEXT_CHANGED` + field classification | `PRIV-FM`, `PRIV-TRAP`, `FLOW-*` |
| `env_survey` | `PackageManager` + `AccessibilityManager` | `ENV-A5`, `ENV-A6`, `ENV-LOG-READABLE` |
| `session_start` / `session_end` | the app's own session control, naming the task | `SESSION-*`, `PLAN-*`, `SCOPE-*` |
| `overlay_marker` | `AccessibilityService.getWindows()` | `OVL-001`, `OVL-002` |
| `permission_request` | the system permission dialog's text | over-permissioning (MyPhoneBench OP) |
| `network_meta` | a host read from a browser's address bar | `INTEL-DOMAIN`, `SCOPE-HOST`, `FLOW-NWD` |

`deeplink` is the ninth and is **still not emitted**, deliberately: an `AccessibilityService` does
not see intents, and the only way to observe `ACTION_VIEW` is to register as a handler for it —
intercepting the user's links, a far larger intrusion than this project will make for one event
type. The function is kept because the desktop relay uses the same envelope format and does have a
source. It is documented at the function rather than left as an unexplained unused symbol, because
four unexplained unused symbols are what made this file's previous state look like seven working
kinds.

### Why `session_start` matters more than it looks

Naming the task is what selects the plan, and the plan is what carries the resource ceiling
(Aura §4.4). Without this kind the envelope had no way to say a session was starting, so the plan
library `guard-localapi` loads could never be selected from: loaded by the host, reachable by
nothing. Every phone session was unscoped.

## The three new sources, and what each cannot do

**`WindowSurvey`** reads `getWindows()` — window type, layer and bounds straight from the window
manager, so these are facts rather than inferences about text. It reports a non-focused window
covering ≥ 55 % of the active window, and any accessibility overlay this service did not create.

It does **not** catch a phishing Activity. A fake payment sheet launched as a normal Activity
*becomes* the active window, so it is the baseline the scan takes and skips. Nor does it report a
small covering window, because a keyboard, an autofill dropdown and a toast all legitimately sit on
top — a deliberate false negative. And an accessibility service cannot read pixels, so there is no
opacity here and no analogue of the desktop's `low_opacity_ratio`.

**`PermissionDialogReader`** parses the system dialog's text. It matches in English **and Chinese**
(simplified and traditional), which is not a nicety: the market this is built for shows these
dialogs in Chinese, and an English-only matcher would report a clean over-permissioning score on
every device it was actually deployed to — and a clean score reads as a well-behaved agent.

It checks denial words *before* allow words, because "Don't allow" contains "allow" and testing the
other order classifies every denial as a grant. It returns nothing for an unrecognised dialog
rather than a default, and it only trusts the system permission-controller packages — any app can
draw a dialog that *says* "allow access to your contacts", and accepting those would let a
malicious app fabricate permission events about other apps. The package name comes from
`AccessibilityEvent.getPackageName()`, which the system sets.

It always reports `necessity: unknown`. Whether a permission is necessary for the task is what the
task plan is for; guessing "optional" here would be the adapter quietly making the ruling the
engine exists to make.

**`UrlObserver`** extracts a host from address-bar text, and only for a known browser package. It
is **not traffic monitoring** — a host on screen is evidence the agent navigated somewhere, not
that bytes moved, and the emitted hint says so. It requires a dot and a non-numeric TLD so that
"version 2.0" and "Total: 99.00" do not become hosts; a fabricated host gets checked against the
session's host grant and could refuse an action the user asked for. It terminates the authority on
`\` as well as `/`, because WHATWG does and a matcher that does not reads
`https://good.example\@evil.example` as `good.example`.

## Confirmation is now connected, and is still not a gate

The relay reads the response. `/v1/events` returns `severity`, `require_confirm` and
`human_message` alongside the action (it returned only the action and rule id — so a client could
not implement confirmation at all), and a `require_confirm` verdict raises a high-importance
notification naming **the engine's rule**, not a local heuristic's guess. The two can disagree, and
the engine is the one holding the policy, the plan and the session scope.

But the companion observes an accessibility event that has **already happened**. There is no point
at which it holds the action and waits. On the desktop the modal blocks before the action proceeds;
here the user is told after. That is a real difference, and calling both "Critical Confirm ✅" is
what the old capability matrix did.

Every send now goes through one function, so whether the phone learns the verdict is a property of
the companion rather than of whichever call site you happen to read. Relay failures are recorded
and surfaced in the UI: a companion that looks connected and is not is worse than one that is
plainly offline.

## Tests, and the cross-language contract

24 JVM unit tests, where there were none. The load-bearing one is the dHash contract.

`AppFace.kt`'s header calls its difference hash **normative**: the Rust comparator in
`guard_schema::visual` and this Kotlin producer must agree bit for bit or every icon comparison is
noise — and the failure would have been silent and would have looked like good news, because an
icon channel that matches nothing reports no impersonation. Both sides now assert against
`eval/fixtures/icon_dhash_vectors.json` (12 non-degenerate vectors), so a drift fails a test in
both languages.

What is still **not** covered: `gridFrom`, which renders a `Drawable` through `Canvas` and
`Bitmap` — `Stub!` on the JVM. The rendering-to-grid step rests on a reading of the code; the
grid-to-bits step does not.

Also untested, because these are pure-JVM tests by choice: anything needing a device. There is no
instrumented test and no device run anywhere in this repository. The APK builds and packages in CI;
nobody has watched it observe a real agent.

## What is still missing

- **No `deeplink` source**, as above.
- **No blocking confirmation.**
- **No logcat monitoring.** `READ_LOGS` is `signature|privileged` — the check we would need is the
  permission we are warning about.
- **The relay is a development wiring.** `adb reverse tcp:8788` to the desktop loopback, over a
  bearer token. (发布阻塞项清理之后,那个令牌不再有硬编码默认值:`api-serve` 会拒绝启动在弱
  令牌上,不带 `--token` 时自己生成一个强的。中转本身仍然是开发接线,不是产品形态。)
- **No instrumented or on-device test.**
