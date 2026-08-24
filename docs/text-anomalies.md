# Text anomalies and glitch tokens (AgentScan §3.7)

AgentScan tests glitch tokens against five agents and lists the class as **unresolved**.
This project's gap review had one sentence for it: *"No detection. A non-printable-run /
tokenizer-anomaly check on ingested `ui_text` is cheap."*

## The property being detected

Not "weird characters". The thing worth a finding is a **divergence between what a screen
renders and what an agent reads** — because every other check in this engine reasons about
the text as a string, and the user reasons about it as pixels. When those two disagree, the
disagreement is the evidence, whatever the payload says.

That makes this a third class alongside the semantic firewall's two:

| Check | Catches |
|---|---|
| `isolation::detect_breakout` | content claiming to be a different **speaker** |
| `entity::recognise` | content that **is** something sensitive |
| `anomaly::scan_anomalies` | content that **reads differently than it renders** |

## The six classes

This table is the **shipped** rule, after the corrections in the precision section below.
Its first version described the rule as designed rather than as shipped — it still listed the
soft hyphen, the whole tag block, the bidi isolates and a 256-character threshold after all
four had been removed or changed, which made the summary a reader consults first the one place
the disproved claims survived.

| Class | Rule | Why it is the attack |
|---|---|---|
| `invisible_text` | zero-width space, word joiner, BOM mid-string, invisible operators, Hangul/Braille fillers, variation selectors, and the Unicode **tag** block `U+E0000–E007F` — **not** ZWJ, **not** ZWNJ, **not** the soft hyphen, and **not** a tag run following `U+1F3F4` | the tag block is today's vehicle for invisible prompt injection: the label reads "Confirm booking" to a person and carries an instruction to the model. The exclusions are why the class can ship — see the table below |
| `bidi_override` | the two **overrides** `U+202D`/`U+202E` only | Trojan Source: the text renders in a different order than it reads. The isolates `U+2066–2069` are how ICU and Fluent wrap every interpolated value, and the plain marks `U+200E/200F` are ordinary in RTL interfaces |
| `homoglyph` | a **predominantly Latin** word containing **Cyrillic** | `p‑а‑yment` with a Cyrillic `а` renders identically and matches nothing, so a phrase rule does not fire and iteration 14's step-kind derivation does not see a payment. Greek is excluded: a lone Greek letter is engineering notation |
| `combining_stack` | 3+ stacked combining marks, in the generic diacritic blocks only | Zalgo-style stacking breaks tokenisation and rendering differently. See limit 4 below: the scripts cited to justify the threshold are not tested at all |
| `oversized_token` | one unbroken token > **2048** chars | a payload, not a word. 256 flagged real JWTs, presigned URLs and `data:` URLs |
| `glitch_token` | a published list | a string chosen for how a tokenizer mishandles it |

Findings carry a class and a **count**, never the matched text — the same rule as
`entity::Entity`, for the same reason: a finding's consumer is a hashed, signed audit record.

`FW-TEXT-ANOMALY` is `Alert`/**`Low`** under `on_text_anomaly`, latched once per class per
session. Reported rather than blocked
because this is evidence about the *screen*, not about an action: nothing here says the agent
is about to do something wrong, only that what it read is not what the user saw. The taint
lattice already refuses to let screen content authorise a critical action either way.

## Precision: what the first version fired on

The first version claimed precision and did not have it. A reviewer fed it real screens; every
row below was a finding, and each is ordinary content:

| Content | Was flagged as | Now |
|---|---|---|
| `👨‍👩‍👧`, `👩‍💻`, `🏳️‍🌈` — 15/15 ZWJ emoji tested | `invisible_text` (U+200D) | ZWJ removed from the class |
| `🏴󠁧󠁢󠁳󠁣󠁴󠁿` subdivision flags | `invisible_text ×6` — **they are tag sequences**, so "the tag block has no legitimate use" was wrong | a tag run following `U+1F3F4` is skipped |
| `می‌خواهم` — Persian ZWNJ is **grammatically required** | `invisible_text` | ZWNJ removed |
| `Ver­trags­be­din­gun­gen` — German `&shy;` | `invisible_text ×5` | soft hyphen removed |
| `Willkommen zurück, <FSI>Sara<PDI>!` — **ICU and Fluent wrap every interpolated value in FSI…PDI** | `bidi_override ×2` | narrowed to the two *overrides* `U+202D/202E` |
| a real 3-part JWT (261 ch), an AWS presigned URL (331), a `data:` URL (274–462) | `oversized_token` — the threshold's own comment called all three legitimate | 256 → **2048** |
| `Show Δtime column`, `250 μsec`, `Ωmeter` | `homoglyph` | Greek dropped; Cyrillic only |

Two multipliers made it worse than a per-string rate. `ui_text` is the **whole flattened
accessibility tree**, so one family emoji anywhere on the screen flagged the event; and there
was **no latch**, so forty identical UI deltas produced forty Alerts — the lesson this
codebase had already written down for `APP-UNATTESTED` and did not apply here. The finding is
now reported **once per class per session**, cleared at `agent_session_start`.

And the reported "0.0% false positives" was measured on a corpus containing **no emoji at
all**, no ZWNJ, no soft hyphen, no bidi isolate and no long token. A false-positive rate over
inputs that exclude the false-positive classes is not a measurement.
`benign_glitch_multilingual_ui` now carries every one of them, and re-admitting ZWJ to the
invisible class fails it.

## The rules that stayed dropped

A check that fires on ordinary screens is switched off in a week, and then protects nothing.
Each of these was tried and rejected:

- **Plain `U+200E`/`U+200F` are not flagged.** They appear in every Arabic and Hebrew
  interface. Only the two reordering *overrides* `U+202D`/`U+202E` are flagged — the
  *isolates* `U+2066`–`U+2069` were dropped too, because ICU and Mozilla Fluent wrap every
  interpolated value in FSI…PDI. (This bullet said "overrides *and isolates*" for one
  iteration after the isolates came out.)
- **Private-use characters are not flagged**, though they look suspicious: Material Icons and
  most icon fonts live there, so a run of them is a toolbar. Named here rather than left as
  an unexplained gap.
- **CJK is never a homoglyph finding.** Mixed-script text is normal — a Latin brand name
  inside a Chinese sentence is every second screen in this project's own corpus. The rule
  fires only on a predominantly Latin word carrying a Cyrillic or Greek letter, so pure
  Cyrillic or Greek prose is a *language*, not a finding.
- **Combining marks need a stack of three.** Vietnamese, Devanagari and Thai stack two
  routinely.

`benign_glitch_multilingual_ui` carries every one of those cases plus the renderer-required
characters above. It is load-bearing for the classes it contains — re-admitting ZWJ fails it —
but a corpus scenario cannot pin a *threshold*, and the first version claimed it did: it
advertised "a 256-char token at exactly the threshold" while containing no token longer than
64, so raising `MAX_TOKEN_CHARS` by one broke nothing. Both boundaries are now pinned by unit
tests instead (`the_oversized_token_boundary_is_pinned_both_ways`, `class_boundaries_are_pinned`),
in both directions, along with the combining threshold, the `latin >= 2` word rule and the
Greek exclusion. (The control's first draft also said 确认支付 and tripped `CRIT-001` — a
control that passes or fails for an unrelated reason is not a control, so the Chinese now says
"order confirmed".)

### A finding must not erase another one

`FW-TEXT-ANOMALY` was `Medium`, and `merge_keeping_reason` appended only the *extra*
decision's message — so when the anomaly won `worse_of` it replaced the primary verdict's rule
id **and** message. One zero-width character in a label was enough to make a latched
`APP-UNATTESTED`, `AGENT-SESSION-MISMATCH` or `ENV-LOG-READABLE` disappear, permanently,
because those latch once per session and never fire again. `FLOW-DERIVE` lost its whole taint
provenance line the same way, in the audit row too.

Two fixes, deliberately both: the severity is `Low` (a property of the *screen* must not
outrank a verdict about an *action*), and `merge_keeping_reason` now keeps **both** reasons
whichever wins. The second is the real one — it fixes the class, not this instance — and it is
the same bug that function was originally written to fix, in the opposite direction.

## Where this stops

Held at `partial`:

1. **The glitch-token list is a tripwire, not coverage.** A glitch token is a property of one
   tokenizer's training data — ` SolidGoldMagikarp` is famous because of what GPT-2's BPE did
   with it, and the equivalent for another model is a string nobody has published. An attacker
   who reads `GLITCH_TOKENS` picks something else. The paper calls this class unresolved, and
   a curated list of ten strings does not resolve it. What does not depend on knowing the
   model is the structural half.
2. **An image of anomalous text is invisible here.** Rendered text in a screenshot is
   §3.6 (image forgery). Iteration 19 built the app-identity half of that — a cloned label and
   icon, see [app-lookalike.md](./app-lookalike.md) — but not this half: anomalous text
   *drawn as pixels* is still unreadable to every check in this engine.
3. **Only observed *text* fields are scanned** — the same five keys as the semantic firewall,
   of which `ocr_text` is still reserved and unemitted.
4. **Combining-mark detection covers the wrong scripts for the reason given.** The threshold
   of 3 was justified by "Vietnamese, Devanagari and Thai stack one or two routinely" — but
   `is_combining` lists only the generic diacritic blocks, so Devanagari, Thai, Arabic and
   Hebrew marks are not tested at all and the threshold is irrelevant for every script named.
   The class works for `U+0300`-range stacking (Zalgo) and nothing else. Left as is rather
   than extended, because adding those blocks without a per-script threshold would flag
   ordinary Hindi and Arabic — and that trade needs its own iteration, not a one-line change.
5. **Homoglyphs are Cyrillic only.** Armenian, Cherokee and the mathematical
   alphanumerics contain confusables too; adding alphabets starts flagging ordinary
   multilingual text, so the line is drawn where the published confusable attacks are.
