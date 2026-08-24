# Cloned icons and display names (AgentScan §3.6)

AgentScan clones a target app's icon and name and reports **10/10 (100 %) on 3 agents** — the
highest success rate in the paper. This project's gap review had one line for it: *"Cloned
icon + name. No visual app-identity check exists."*

## Why it works, and why signer pinning does not stop it

An agent driving a GUI decides *which app it is in* by looking at the screen. Everything on
the screen is chosen by whoever wrote the app: the label is a string in a manifest, the icon is
a file in an APK. Neither is a claim about identity; both are what identity gets inferred from.

Iteration 13 bound app identity to the **signing certificate**, which defeats §3.5 —
an APK calling itself `com.sankuai.meituan` fails because it cannot produce Meituan's
certificate. §3.6 does not forge anything. The clone is honestly `com.evil.clone`, honestly
signed by whoever built it, registered under its own name. It simply *looks* like WeChat.

Against a probe of the shipped engine, before this iteration:

```
package com.evil.clone, source_app "WeChat"
  → APP-FOCUS   LogOnly   "Foreground app: WeChat"
  → DL-UNKNOWN  Alert     "Custom-scheme deeplink 'weixin://pay?amount=999'
                           from unregistered app 'WeChat'"
```

The guard printed the forged name as if it were the app's name.

## The one direction this is allowed to work in

> **A forged appearance may only ever raise suspicion. It may never grant trust.**

Matching a registered app's label or icon is never a reason to *believe* an app is that app.
That would be the mistake this project keeps finding in its own code — an attacker-supplied
value read as a security control — and it is why `identify_as` deliberately takes no display
name. Appearance is the **accusation**; the certificate is the **authority**.
`Appearance::resolve` can therefore return only `Consistent`, `Unprovable` or `Impersonation` —
never `Verified`.

Concretely, the finding is: *the appearance resolves to registered app R, and this package is
not R.*

What the package's own identity is, **and how that is known**, decides the verdict. The
provenance is load-bearing, and the first version of this code left it out: it read the own-name
from `AppIdentity::app_name()`, which is populated for `Unattested` as well as for `Verified`, so
a clone that *also* forged `package=com.tencent.mm` matched "its own" entry and came back clean.
Forging one more field downgraded a Critical block to a Low log line. `OwnIdentity` now carries
the provenance with the name.

| The package's own identity | Appearance resolves to | Verdict |
|---|---|---|
| unregistered | R | **impersonation** — the paper's attack |
| **verified** as S | R | **impersonation** — a properly-signed app wearing another's face |
| **verified** as R | R | consistent |
| **claimed** as R, unproven | R | **`APP-FACE-UNPROVEN`** — see below |
| **disproven** as R (signer mismatch) | R | silent; `APP-SIGNER-MISMATCH` already fired |
| disproven as R | S | **impersonation** of S |
| anything | nothing | consistent |

Row three is the row that makes this shippable. On Android 11+, package visibility makes
`getPackageInfo` throw for any package outside the companion's `<queries>` list, so "looks like
WeChat, is `com.tencent.mm`, signer unreadable" is a real state on a real device. Reporting that
as impersonation would make the genuine app un-runnable — exactly the failure mode
`APP-UNATTESTED` was carefully built to avoid.

Row four is what stops that from being a free pass. Where there is no attestation, an app
claiming `com.tencent.mm` and wearing WeChat's face is **indistinguishable** from WeChat: no
logic detects a perfect forgery without an authority. So the guard does the only honest thing —
it refuses to call it consistent. `APP-FACE-UNPROVEN` is `LogOnly`/`Low` by default (`Alert`
under `require_attestation: true`), once per package per session, and its message says in as many
words that this is *the absence of the evidence that would settle it*, not evidence of
impersonation. **The defence against a forged package name is §3.5 signer pinning; §3.6's
strength is bounded by whether that channel works.**

### Each channel is excused separately

The label channel is excused only by an own-entry **label** match, and the icon channel only by
an own-entry **icon** match. The first version short-circuited the whole resolution on either,
so a registered app presenting a cloned label plus its own icon came back `Consistent` — and so
did one presenting its own label plus a cloned icon. That is a silencing primitive an attacker
gets for free, and it contradicted the table above.

## Folding a label

`visual::fold_label` reduces a label to a comparison skeleton:

| Step | Effect |
|---|---|
| drop format characters | ZWSP/ZWJ/ZWNJ, soft hyphen, bidi controls, variation selectors, tag block |
| drop combining marks | `We\u{301}Chat` → `wechat` |
| narrow full-width | `ＷｅＣｈａｔ` → `wechat` |
| lowercase | before the tables, so uppercase Cyrillic А folds through а |
| map confusables | curated Cyrillic + Greek → Latin |
| reduce precomposed Latin | `Wéchat` → `wechat`, from the Unicode NFD decompositions |
| digit-leet | `0→o 1→l 3→e 5→s 7→t`, **only** where the digit has a letter on *both* sides |
| keep alphanumerics | spaces and punctuation vanish: `We-Chat` → `wechat` |

Two rules then compare skeletons: **exact** equality, or one of exactly two typo shapes — an
**adjacent transposition** (`Wechta`) or a **doubled letter** (`WeChatt`).

Both restrictions are the result of measurement, not caution.

**Not "within one edit".** A general one-edit rule admits roughly 470 neighbours of a six-letter
name, and against the shipped registry it made every one of these a Critical block with
`require_confirm`: `Stride` (Stride Health), `Strive`, `Stripes`, `Stripo`, `Strip` — all against
`Stripe` — plus `WebChat` against `WeChat` and `Elemi` against `Eleme`. Those are ordinary app
names. Substitution, arbitrary insertion and deletion are therefore not matches, and the cost is
stated: a deliberate one-letter typosquat such as `Wechet` is **not caught**.

**Not one letter neighbour for digit-leet.** The first version folded any digit with no digit
neighbour, which mangled `250 μsec` into `2soμsec`. The second required one letter neighbour,
which folded `Note 5` into `notes` — exactly equal to a registered `Notes` — and `Word 7` into
`wordt`, `Photo 3` into `photoe`. A trailing digit is a version or model number, and app names
carry those constantly. Requiring letters on *both* sides costs the leading-digit trick
(`0ffice` is no longer folded) and keeps `W3Chat`.

**Four-letter Latin names are not comparable at all.** `MIN_LABEL_WEIGHT` counts ASCII
alphanumerics as 1 and everything else as 3, and requires 5. That puts the registry's own `AMap`
out of reach of the label rule — French community-agriculture apps are named `AMAP`, and the
Serbian name `Амар` folds onto it through the Cyrillic table — while keeping two-character CJK
names comparable, which is the market this project is about.

`known-apps.yaml` refuses to load an entry that declares an appearance and has no **label** that
can produce a finding — an `icon_dhash` alone does not satisfy it, because icon evidence is advisory
and never blocks. The first version accepted an icon-only face, which left `AMap` passing the "no
usable face" net while having **no interventional protection at all** against the paper's exact
attack: a clone labelled `AMap` with `AMap`'s icon came back `LogOnly`. `AMap` is now protected by
its localised label `高德地图`, which clears the floor. An operator whose app has a short Latin name
and no localised alias must either add one or accept package-and-signer protection only — and now
has to say which, at load time.

### Greek is a confusable here and not in `anomaly.rs`

`guard_privacy::anomaly` refuses to treat Greek as a confusable: a lone Greek letter is
engineering notation (`Δtime`, `250 μsec`, `Ωmeter`) and flagging it produced findings on
ordinary screens. That argument does not transfer, and the difference is the **direction of
the inference**. There, a Greek letter *was itself* the finding. Here, folding can only produce
a finding by colliding with a name already in the registry: `Δtime` folds to `δtime` (δ is not in
the confusable table — this line said `dtime` for two iterations), matches nothing, and is silent. Folding aggressively is safe precisely because the registry is what
has to match.

## Hashing an icon

A 64-bit **difference hash**, and the algorithm is normative rather than descriptive, because
two producers that disagree by a bit pattern produce noise:

1. render the icon to a **9 × 8** grid, 8-bit greyscale, alpha composited onto **white**;
2. per row, compare each of the 8 adjacent column pairs — bit set when the **left** sample is
   strictly brighter;
3. row 0's leftmost comparison is the most significant bit;
4. serialise as 16 lowercase hex characters.

White, not black: a launcher icon is mostly transparent around its glyph, so compositing onto
transparent black makes the padding the darkest region — every icon then hashes as "bright
glyph on dark ground" and what distinguishes two icons becomes the shape of the alpha channel
rather than the artwork.

`guard-cli icon-dhash --raw <file> --width W --height H` computes one, taking raw packed
pixels rather than PNG — the same convention as `frame-digest`, so no image codec enters a
guard binary's dependency tree for a registry-authoring convenience.

**Degenerate hashes refuse to compare.** A flat or single-gradient icon hashes to nearly all
zeros or all ones, and two unrelated flat icons then sit at distance 0 and match perfectly.
Fewer than 8 set or fewer than 8 clear bits is refused — by the CLI, by the comparator, by the
Kotlin producer, and by `known-apps.yaml` at load.

### The icon channel cannot produce a finding, and here is the measurement

The first version of this document said "unrelated icons sit near 32 bits apart, so 6 is a wide
margin", and alerted at `High` on an icon-only match. **That claim was false.**

The replacement figures come from a test in the repo —
`visual::tests::the_icon_channel_false_match_rate_is_measured_not_assumed` — which generates its own
corpus of 30 glyphs in the dominant real style (one bold mark, dark on white, 192×192) and hashes
them through the shipped `IconHash::from_rgba`. That matters: the first version of this section
quoted a scratch program that was not part of the artifact, which for a fix about not shipping
unverified numbers was the wrong shape. Run `cargo test -p guard-schema the_icon_channel -- --nocapture`
to re-derive them.

| | |
|---|---|
| comparable glyphs | 28 of 30 (2 refused as degenerate) |
| unrelated pairs | 378 |
| maximum distance | **27**, not "near 32" |
| pairs within 4 bits (the shipped threshold) | 25 — **6.6 %** |
| pairs at distance **0** | 4 — an 8×8 grid cannot resolve the middle bar of an `E` |
| same icon, two producers | diverges by up to **4** bits |

Raising the information floor makes the *rate* worse, not better, because it removes the
low-structure icons that were far apart and keeps the structured ones that cluster. Widening the
hash to 256 bits was measured too and does not fix it. The same-icon and different-icon
distributions **overlap**; no threshold separates them.

The test asserts the conclusion rather than only printing it: it fails if unrelated glyphs stop
colliding at the shipped threshold, and it fails if the maximum unrelated distance reaches 32 — so
if the ground ever shifts, that is a failing test rather than a doc going quietly stale.

So: `ICON_MATCH_MAX_DISTANCE` is **4** — the tightest value that still admits the producer
divergence — and icon-only evidence is **advisory**: recorded in the signed audit record at
`LogOnly`/`Low`, never surfaced as an intervention. An operator interrupted one time in twenty
for nothing stops reading the alerts, and the next finding is the one that mattered. The icon is
a corroborator here, not a detector.

## The verdict

`APP-LOOKALIKE`, engine-emitted (not a YAML rule):

| Evidence | Action | Severity |
|---|---|---|
| label (exact or typo shape), with or without icon | **Block**, `require_confirm` | Critical |
| icon only | **LogOnly** | Low |

Two more rules alongside it:

- `APP-FACE-UNPROVEN` — `LogOnly`/`Low` (`Alert` under `require_attestation`), once per package
  per session. The appearance matches the package's own registered entry and the package never
  proved it owns that entry.
- `APP-FACE-UNREADABLE` — `LogOnly`/`Low`, once per package per session. The companion could not
  read the appearance at all (`face_error`, usually `NameNotFoundException`). Reported because
  "no finding" and "checked and clean" are different claims, and an inert mechanism that says
  nothing is indistinguishable from a working one — the same rule `log_readers_enumerable` and
  `scan_errors` already follow.

The impersonation verdict **latches** per package and re-reports on every subsequent event, so a
clone that shows its face once and then stops cannot retry — the hole iteration 15 found in the
signer check. The latch is cleared at `agent_session_start`, alongside `app_identities`, and that
was missing at first: a process-lifetime verdict in a long-lived `api-serve` engine meant one
envelope naming a package blocked it in every future session until restart, which anything local
could trigger through `POST /v1/events`, and no registry correction could clear it because the
latch is read before the registry is consulted. The message says "earlier in this session", and
now that is true.

## The severed channel this iteration also fixed

While wiring `app_label` and `icon_dhash` from the companion to the engine, the same wiring
turned out to be **missing for `signer_sha256`** — the input to the entire §3.5 defence.

`AppAttestor` computed the SHA-256 of each signing certificate. `PayloadSerializer` put it in
the envelope JSON. The envelope goes to `guard-localapi`, which parses it with
`android_adapter::AndroidEvent` — a struct that had **no field for it**, so serde dropped it.
Every app on every real device was therefore `AppIdentity::Unattested`, and signer pinning was
inert on the only platform that implements it, while `docs/app-identity.md` described it as
shipped.

Nothing in the corpus could catch this: eval scenarios write `signer_sha256` straight into
`metadata` and never cross the adapter boundary. This is the same shape as iteration 17's
worst defect — Kotlin computes it, Rust never receives it, the docs describe the intent — and
it is now guarded structurally rather than by attention:

- `AndroidEvent` forwards identity keys through an explicit **allow-list**, not
  `#[serde(flatten)]`. Anything can POST to `127.0.0.1:8788`, and a flatten would forward
  every key the poster invents — including the ENV markers iteration 17 showed a page can
  forge into a Critical block, and `agent_id`.
- `every_key_the_companion_sends_has_a_field_here` scans the companion's Kotlin for
  `obj.put("…")` / `out["…"]` literals and fails when any key has no field to receive it. Its
  file exclusions are an exclusion list with stated reasons, so a **new** companion file is
  scanned by default — iteration 17's print-sink scanner was an inclusion list and was blind
  to the two sinks that mattered. It also fails if it finds fewer than 20 keys, since a
  scanner that has stopped matching its target is a test that always passes.

Both were verified by mutation: dropping `icon_dhash` from the forwarding list fails the
passthrough test, and dropping it from the scanner's known-key set fails the scanner.

## Where this stops

Held at `partial`, and these limits are load-bearing.

1. **Android only.** The check runs only when an event carries a `package` — i.e. only where
   there is an OS-level identity channel to contradict the appearance with. macOS, Windows and
   the browser adapter send none, and there the check **does not run at all** rather than
   guessing. Guessing would be catastrophic in the ordinary direction: macOS reports the
   genuine WeChat's `localizedName` as "WeChat" and attests nothing, so an appearance-only rule
   would block the real app. When macOS attestation lands (`SecCodeCopySigningInformation`),
   the same check applies with `bundle_id`.

2. **Package visibility is the whole mechanism, and it nearly made this inert.** `AppFace` reads
   the label and icon from `PackageManager` **for the observed package** — and on Android 11+ a
   package outside the companion's `<queries>` list is *permanently* invisible. The companion
   listed only the six *registered* packages, which is exactly right for §3.5 ("is the app
   claiming to be WeChat really WeChat" only ever concerns a registered package) and exactly
   wrong for §3.6: the clone is by construction **not** registered. Both calls would have thrown
   `NameNotFoundException` for every clone, `AppFace` would have returned nulls forever, and
   `check_app_lookalike` would have returned `None` — the mechanism shipped and inert on the one
   platform it targets, which is this project's most-repeated defect.

   The manifest now carries a `MAIN`/`LAUNCHER` intent query, which makes every *launchable* app
   visible. The trade is stated rather than buried: that is enough to enumerate the user's
   launcher, which is a privacy cost. It is still narrower than `QUERY_ALL_PACKAGES` — services,
   providers and headless packages stay invisible — and it is not a restricted permission, so it
   needs no Play Store declaration. A clone must be launchable to be the app the agent opens.

   Remaining failures are **reported, not silent**: `AppFace.Face.error` becomes `face_error` on
   the wire and `APP-FACE-UNREADABLE` in the audit trail. None of this is verified on a device —
   there is no Android hardware in this repo's CI, so the claim rests on the documented API
   contract and on the companion's own code, which already says this about `AppAttestor`.

3. **The hash is a tripwire for exact clones.** A difference hash survives the rescaling and
   re-encoding an app store does. It does not survive a crop, a rotation, a hue shift beyond
   luma, or any deliberate perturbation. The paper's attack clones the icon *exactly*, which is
   what makes it detectable — an attacker who reads this shifts a few pixels and is past it.
   Same honest position as `anomaly::GLITCH_TOKENS`: a tripwire, not coverage.

4. **Containment is not a match.** An app whose folded label *contains* a registered name is
   not reported, because 企业微信 / "WeChat Work" is `com.tencent.wework` — a real, legitimate,
   different app — and so is every "… Lite", "… Business" and "… for Instagram" in an app
   store. The cost is stated rather than hidden: a clone named **`WeChat Pay`** is not caught
   by the label rule. It is caught by the icon rule if it cloned the icon, and otherwise not at
   all.

5. **The confusable table is curated, not UTS #39.** Cyrillic, Greek, precomposed Latin and
   digit-leet. Armenian, Cherokee, Coptic and the mathematical alphanumerics are absent, and an
   attacker who reads this list has a way past the label rule.

6. **The registry is fixtures.** The `icon_dhash` values in `policies/known-apps.yaml` are
   obvious repeated-nibble placeholders. This matters more than it does for the signer digests,
   because an `icon_dhash` entry is an **accusation template**: any app whose icon hashes
   within 4 bits and is not this app gets reported. A wrong signer digest fails closed; a wrong
   icon hash accuses an innocent app. `known-apps.yaml` refuses to load a malformed or
   degenerate one, and refuses to load two entries whose folded names would accuse each other.

7. **The Kotlin producer has no test.** `AppFace.hashGrid` reimplements the pinned algorithm
   because the companion does not load the Rust engine, and this repo has no JVM test target,
   so its agreement with `IconHash::from_grid_9x8` rests on a careful reading against a pinned
   spec. That is the shape of iteration 17's worst defect, named here rather than assumed away.

8. **Nothing here reads pixels off the screen.** The label and hash come from
   `PackageManager`, which is deliberate — a label scraped from the accessibility tree is
   chosen by whatever drew on top, so an overlay could dress an innocent app as WeChat and
   produce this finding against it. The consequence is that an app which renders a *fake
   chrome* inside itself — WeChat's title bar drawn in a WebView — is invisible to this check.
   That is the overlay family (`OVL-*`), not this one.

## False positives, measured on inputs that contain them

Iteration 18 shipped a "0.0 % false positives" figure measured on a corpus that contained no
emoji at all, in a module whose worst false positives were emoji. So the paired corpora here
are explicit:

- `no_ordinary_app_label_collides_with_the_shipped_registry` — **100+** real app labels, with the
  registry names **read from `policies/known-apps.yaml`** rather than hardcoded, so adding an app
  is covered automatically. The first version of this test hardcoded a copy and contained not one
  near-neighbour of any registry name, which meant the whole near-miss rule was covered by
  nothing. It now carries every false positive the review found: `Stride`, `Strive`, `Stripes`,
  `Stripo`, `Strip`, `WebChat`, `Elemi`, `AMAP`, `A Map`, `Амар`, `Note 5`, `Word 7`, `Photo 3`,
  `Line 7`, `Office 365` — alongside Tencent's own separate products, competitors one character
  away (微博 vs 微信, 微店, 美柚), payment apps where a false block costs most, and the character
  classes the fold touches (`Δ Notes`, `250 μsec Meter`, `Café Finder`, `Škoda Connect`,
  `1Password`).
- `ordinary_apps_are_not_lookalikes_against_the_shipped_registry` in `guard-core` — the same
  inputs through the **engine**, also against the shipped registry. Its first version used a
  two-app fixture, so four of its eight rows asserted nothing: "Office 365" cannot collide with a
  registry that has no entry it could collide with.
- `every_claimed_impersonation_shape_is_caught` — the recall half, because a rule that fires on
  nothing also scores 0.0 %. It also asserts the shapes that are **not** caught (`WeCh4t`,
  `Wechet`, `WebChat`, `WeChat Pay`), so a widening of the rule cannot happen without the docs
  being updated.
- `benign_lookalike_neighbouring_names` and `benign_lookalike_real_app_unattested` in the eval
  corpus, both load-bearing: making containment a match fails the first, and removing the
  own-entry guard fails the second. Verified by mutation, not assumed.

### And the miss rate moved

`lookalike_cloned_icon_only_001` is kept as an **attack** scenario that the guard does not
intervene on, so both corpora report a non-zero miss rate rather than 0.0 %: `guard-cli scoreboard`
over all 120 scenarios reports 1 miss of 87 attacks (**1.1 %**), and the 99-scenario release
manifest reports 1 of 69 (**1.4 %**). Two corpora, two denominators — worth keeping straight, since
an earlier draft of this paragraph quoted the first figure as if it were the gate's. The
release gate no longer asserts zero misses; it asserts that the set of missed attacks equals a
**named list with a stated reason for each**, and fails both when an undocumented miss appears
and when a listed one starts being caught. Zero was only ever true because no scenario described
an attack the guard knowingly does not stop.
