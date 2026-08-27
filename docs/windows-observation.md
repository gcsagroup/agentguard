# Windows observation

## What was here before

`adapters/win-adapter` had no Win32 code. Its `Cargo.toml` declared no `windows` or
`uiautomation` dependency, `NativeWinAdapter` was a queue that accepted pre-normalized
observations behind a `// TODO(windows): replace with UIA element → FormFill / UiText mapping`,
and nothing in the repository constructed it. `capabilities()` reported
`uia_native: cfg!(windows)` — a *compile flag* rendered in the desktop shell as a green tick.
The only way to get an event into the Windows shell was to click one of its seven demo threat
buttons.

So every rule that reads a UI tree or a frame was inert on Windows, and the capability report
could not fail.

## What it does now

**`uia.rs`** — a real `IUIAutomation` walk of the foreground window, through the **control** view
(the raw view includes every layout container the framework created: triple the nodes, no extra
text a rule could match). Each element contributes a role, a name, a `ValuePattern` value, bounds
and an off-screen flag.

**`capture.rs`** — GDI `BitBlt` of the foreground window into a top-down 32-bit BGRA DIB, with
`CAPTUREBLT` so layered windows are included. That last flag matters: without it the very windows
this project exists to notice are excluded from the copy.

**`probe.rs`** — `capabilities()` now *tries the thing* and keeps the error string.

**`native.rs`** — `poll_once()` walks the tree, captures the pixels, and hands both to
`guard-vision`, the same analysis the macOS path calls.

## The analysis is shared, not reimplemented

`guard-vision` holds the subliminal contrast bands, the LSB and chroma flip rates, the frame
digest, the AX↔OCR cross-validation, and the UI-tree model. Windows contributes pixels and a
tree; it contributes no thresholds.

This is not tidiness. This project's worst recurring defect is a mechanism written twice: iteration
17 shipped a redactor that never ran on the platform that needed it, and `AppFace.kt` carries a
written warning that its dHash is "reimplemented rather than shared … the algorithm is
**normative**". Two copies of a threshold are two rules with one name, and the day they disagree
nobody can say which was meant.

The `platform` string is a parameter for the same reason. It was `"macos"` hardcoded in two places
inside what is now shared code; on a shared path that would have stamped every Windows event as
macOS, and the audit record would attribute an observation to an OS that never made it.

## Four things that were wrong on the first attempt

Each is written down because each is a shape that recurs, not a typo.

**1. Every control type classified as `edit`.** The mapping was a `match` over the `windows`
crate's `UIA_EditControlTypeId` constants. Those are lower-camel-case, so Rust treated each arm as
a **new binding** rather than a comparison: the first arm matched everything. Since `edit` is the
role `is_editable_role` matches, every node with a value would have produced a `FormFill` — a
form-minimization score built from the entire UI. `rustc` says exactly this, as a *warning*
("constant in pattern … should have an upper case name"), which is why `clippy -D warnings` on this
crate is a CI step and not a preference. The fix compares raw `i32`s, which also makes the mapping
testable on any host instead of only on the platform where testing is hardest.

**2. The adapter was not `Send`, so the shell could not build.** `UiaClient` held
`IUIAutomation` in a field. The shell stores the adapter in Tauri's managed state, which needs
`Send + Sync`, and a COM interface in the `windows` crate is a `NonNull<c_void>`, which is not
`Send`. The failure is a build error **on Windows only** — and the Linux and macOS jobs compile the
shell with the `#[cfg(windows)]` observer field absent, so every green run said nothing about it.

It would also have been unsound if it had compiled: `CoInitializeEx` initialises COM for *the
calling thread*, so constructing on the main thread and polling from the poller thread uses an
interface across apartments without marshalling. In practice that returns `RPC_E_WRONG_THREAD`
sometimes and works sometimes, which is the worst available outcome. The client is now
thread-local; the adapter carries plain data; and a `const` assertion in `native.rs` fails the
build if a COM interface is ever put back into a field.

**3. A transparent-overlay finding on every single frame.** `BitBlt` into a 32-bit `BI_RGB` DIB
writes three channels and leaves the fourth at zero. Read as alpha, that is "every pixel fully
transparent": `low_opacity_ratio` comes out at 1.0, `analyze_frame`'s `> 0.15` test fires, and the
adapter reports a transparent overlay twice a second forever — from a byte nobody wrote.
`stats_from_pixels` now takes an explicit `AlphaChannel`, so a new capture path cannot be added
without answering the question, and `Padding` reports 0 rather than a number that looks like a
measurement.

**4. A `ScreenFrame` event per poll, and two tree walks per poll.** `analyze_frame` always returns
capture dimensions in metadata, so a `!metadata.is_empty()` guard was true every time. And
`last_source_app()` walked the tree a *second* time purely to label the frame — doubling the cost
of the most expensive thing in the loop, and able to disagree with itself if the user switched
windows between the two walks. `source_app` is what every app-scoped grant is checked against.

## Bounds, and why they are reported

A UIA tree for a browser window can hold tens of thousands of elements and each property read is a
cross-process COM call, so an unbounded walk is not slow, it is a hang. The walk is capped at depth
12, 1500 nodes, 120 siblings per level and 512 characters per value — and every cap that bites is
**counted and reported** in `ui_tree_truncated`, with per-element read failures in
`ui_tree_read_errors`. A tree that stopped early and a tree that ended are different claims. Same
reasoning as `log_readers_enumerable` on Android: silence about a check that did not run reads as
a clean result.

An oversized frame (above 16 MPix) is **refused rather than downscaled**. Box averaging preserves
local contrast well enough for the subliminal bands but destroys the LSB plane completely, so
`lsb_flip_rate` over a resampled frame is a number about the resampler — still in range, still
indistinguishable from a real measurement.

## What Windows still does not have

- **No composed-desktop capture**, so an overlay drawn by another process is invisible unless it is
  the foreground window. See `GRAPHICS_CAPTURE_NOTE`.
- ~~**No OCR**~~ **OCR now works** via `Windows.Media.Ocr` (the OS's built-in OCR — offline, no
  model files; `win-adapter/src/ocr.rs`, wired in `native.rs`, gated on the `Media_Ocr` feature).
  `ocr_text` is set and `OVL-009` / `OVL-010` run, sharing the trigger/contrast with macOS
  (`guard_vision::ocr`). This was the one place this doc said "no OCR"; it is stale — see
  `platform-matrix.md`.
- **No app attestation.** Nothing collects a signing digest on Windows, so `APP-SIGNER-MISMATCH`
  and `APP-LOOKALIKE` have no input there.
- **No opacity or font size from the tree.** UIA exposes neither, and inventing one would be worse
  than reporting none: `regions_from_snapshot` defaults an absent opacity to fully opaque, so a
  guess would either fabricate an overlay finding or mask a real one.
- **Never run on real hardware by anyone.** The code compiles for `x86_64-pc-windows-msvc` and CI
  builds and tests it on `windows-latest`. Neither is the same as having watched it observe a real
  agent. Nothing in this repository has done that.
