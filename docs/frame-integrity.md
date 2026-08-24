# Frame integrity (A4 screenshot tampering)

(A)I Sees ([arXiv 2607.00333](https://arxiv.org/abs/2607.00333) §IV-C, attack A4)
tampers with a screenshot in the window between the moment it is captured and the
moment the agent reads it — measured at **50–500 ms, mean ≈ 210 ms** — and scored
19/20–20/20 against four of five agents surveyed. (MobA is immune because it
streams via `exec-out` and never touches shared storage.)

## What was wrong

The previous detector compared **whole-frame mean luminance** across two captures
and flagged a jump over **0.35**, inside a **700 ms** window.

That threshold is unreachable by the actual attack. Injecting text changes a small
fraction of the pixels, so the frame mean barely moves. `make frame-digest-demo`
measures it: a deliberately blatant injection — near-black stripes over 1.6 % of a
light frame — moves the mean by **0.036**, an order of magnitude below the 0.35
threshold, and a realistic line of small text is far below even that. A 0.35 mean
jump essentially only happens when the *whole screen* changes:
an app switch, a scroll, a video. The detector was tuned to fire on the one case
that is **not** an attack and to miss the case that is. The 700 ms window was also
3× the paper's measured mean, widening the interval in which a benign repaint could
be mistaken for an edit.

`localized_text_injection_is_detected_where_mean_luma_fails` asserts this
explicitly: it builds the injection, checks that the mean-luma jump is below 0.35
(i.e. the old detector would have said nothing), and then requires the new one to
catch it. `make frame-digest-demo` shows the same thing end to end, printing the
measured mean-luma jump next to the old threshold.

## What is implemented now

`mac-adapter::framehash` computes a **structural grid digest**: 16×9 blocks, 3×3
samples per block, mean luma **and** mean Cb/Cr per block, each quantised to 4 bits.
Comparison is block-by-block, and the verdict distinguishes three cases:

| Delta | Meaning |
|---|---|
| `Identical` | No block moved more than the tolerance (or exactly one did — noise floor) |
| `Localized { changed, total }` | A few blocks changed while the rest held still — the localized-edit signature a frame-wide average destroys. **This is the tamper signal** (`[AG_FRAME_REGION_TAMPER]` → `OVL-013`, block + confirm) |
| `GlobalRepaint { changed, total }` | More than 35 % of blocks changed: app switch, scroll, video. **Not** reported — reporting it is what the old detector did |

Three properties make it usable rather than merely sensitive:

- **Resolution independent.** A fixed grid, not a pixel hash, so the guard's
  640×360 capture and a full-resolution agent screenshot of the same screen produce
  comparable digests. Tested at a 4× scale difference.
- **Quantised.** 4 bits per channel per block, so re-encoding noise and sub-quantum
  drift do not flip a block. A cryptographic hash of raw pixels would be perfectly
  sensitive and perfectly useless — a blinking cursor would change it.
- **Chroma included.** The published A4 variant embeds in Cb/Cr *while preserving
  luminance*; a luma-only digest is blind to it by construction, the same mistake
  the original stego detector made.

The window is now **550 ms**, covering the paper's measured 50–500 ms with a small
margin instead of 700 ms. Mean luma survives only as a fallback for frames that
carry no digest (simulation, older bridge), and its evidence string says so.

## Integrity verification, not just consistency

The paper's own fix is architectural — a memory-only pipeline that never writes to
shared storage, plus cryptographic integrity verification — and that belongs in the
agent, not in a guard beside it. What a guard *can* do is make tampering provable:

`frame_digest` is written into event metadata, so it lands in the audit record's
`event_json`, which is covered by the chain hash **and** the Ed25519 signature from
[audit-signing.md](./audit-signing.md). The guard therefore attests: *at time T,
this device's screen looked like digest D*. If the screenshot the agent actually
consumed disagrees, that is provable after the fact rather than merely suspected.

The host side of that comparison:

```bash
# Guard's recorded digest comes from the audit record's frame_digest metadata.
D=$(guard-cli frame-digest --raw frame_clean.raw --width 320 --height 180)

# Same screen → agrees.
guard-cli frame-digest --raw frame_clean.raw --width 320 --height 180 --expect "$D"
# match: the frame agrees with the recorded digest

# A line of text injected in the TOCTOU window → localized mismatch, exit 1.
guard-cli frame-digest --raw frame_tampered.raw --width 320 --height 180 --expect "$D"
# TAMPERED (localized): 14/144 blocks differ [17, 18, 19, 20, 21, 22, ...]

# A different screen entirely → said plainly, not called an edit.
guard-cli frame-digest --raw frame_other.raw --width 320 --height 180 --expect "$D"
# DIFFERENT SCREEN: 144/144 blocks differ — this looks like a different screen
# entirely, not an edit of the same one
```

Input is raw packed 4-byte pixels: PNG/JPEG decoding is the caller's job, which
keeps an image-codec dependency out of the binary.

## Limits

- **The capture rate bounds detectability.** The stream runs at ~2 FPS (500 ms
  interval), so a tamper that opens and closes inside 50 ms can fall entirely
  between two captures. Catching the short end of the paper's range needs a
  deliberate back-to-back double capture at the moment of use, not a slow stream.
  Nothing here forces the agent to ask for that.
- **A digest proves what the guard saw, not what the agent read.** Without the
  agent's own copy of the screenshot to compare, this detects
  capture-to-capture inconsistency, not the actual substitution. The comparison
  above requires the host to cooperate by handing over the frame it consumed.
- **Block granularity.** 16×9 blocks over a 640×360 capture is 40×40 px per block.
  An injection confined to a single block sits at the noise floor and is dropped
  deliberately, because one changed block is where false positives live.
- **Not a mitigation.** As with the rest of the A-series coverage: this detects the
  condition. The fix — never staging screenshots through shared storage — lives in
  the agent framework.

## Native / Rust parity

The digest is computed twice: `framehash::digest_rgba` in Rust and
`ag_frame_digest` in `AgentGuardSCK.m`. They must agree byte for byte, since a
digest produced by one is compared against one produced by the other — same BT.601
coefficients, same 16×9×3×3 sampling, same 4-bit quantisation with `roundf`, same
`luma|cb|cr` hex layout. The frame-stats struct ABI is bumped to **2**
(`frame_digest` appended after `ocr_text`); `abi_layout_matches_c` pins the offsets
(0/4/8/12/16/24/…/48/56, size 64).
