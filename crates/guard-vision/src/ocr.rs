//! The OCR *policy*, shared; the OCR *engine*, not.
//!
//! # What is shared and why
//!
//! macOS reads text with Vision, Windows with `Windows.Media.Ocr`. Those cannot be shared —
//! they are different frameworks. But everything around them can be, and everything around
//! them is where the decisions live:
//!
//! - **when** to run OCR at all ([`should_ocr`]),
//! - **what the frame looks like** when it is read ([`CONTRAST`], [`BRIGHTNESS`],
//!   [`enhance_contrast`]),
//! - **how much** of the result travels ([`MAX_LINES`], [`MAX_LINE_CHARS`], [`join_lines`]).
//!
//! Left per-platform, those three drift, and the symptom is not a crash. It is one platform
//! reading a subliminal payload and the other not — a *quieter* guard on one OS, which looks
//! like a cleaner screen.
//!
//! # This is deliberately not a bit-exact contract, unlike the icon hash
//!
//! `IconHash` has two implementations that must agree **bit for bit**, because two hashes are
//! compared as numbers: one bit of disagreement and every comparison is noise, so
//! `eval/fixtures/icon_dhash_vectors.json` pins both sides.
//!
//! OCR is different in kind. Its output feeds `viewtree::cross_validate`, which compares
//! **token sets** — so "Confirm payment" read by Vision and by Windows OCR only have to agree
//! on words, not on bytes. Core Image's `CIColorControls` also operates in a linear working
//! space while [`enhance_contrast`] works on sRGB bytes, so bit-exactness is not achievable
//! here even in principle. Saying so is the point: a shared constant is not the same promise
//! as a shared algorithm, and this module makes the weaker promise on purpose.

/// Contrast multiplier applied before reading text.
///
/// The (A)I Sees A1 payload is text at 0.8–20 % opacity: legible to a VLM, invisible to a
/// person, and invisible to OCR too until the contrast is pushed. 4.0 is what the macOS path
/// uses, so it is what this one uses.
pub const CONTRAST: f32 = 4.0;

/// Brightness offset applied with [`CONTRAST`], in 0..1 units.
pub const BRIGHTNESS: f32 = 0.15;

/// Most lines carried out of one frame.
pub const MAX_LINES: usize = 24;

/// Most characters carried out of one line.
pub const MAX_LINE_CHARS: usize = 80;

/// Separator between lines, so a reader can tell a line break from a space.
pub const LINE_JOIN: &str = " | ";

/// Run OCR every Nth frame even when nothing looks subliminal.
///
/// The periodic read is not for A1 — it is so that `viewtree::cross_validate` (AgentScan's
/// Viewtree Interference, the broadest surface in the papers) has a screen-side input at all.
/// Without it that check only ever runs on frames that already tripped a subliminal band.
pub const OCR_EVERY_N_FRAMES: u64 = 8;

/// Whether this frame should be read.
///
/// Over-triggering is the safe direction: an extra OCR costs time, a missed one costs the
/// finding. The engine still decides what the text means.
pub fn should_ocr(frame_seq: u64, subliminal_strong: f32, subliminal_wide: f32) -> bool {
    if crate::subliminal::is_suspicious(subliminal_strong, subliminal_wide) {
        return true;
    }
    OCR_EVERY_N_FRAMES != 0 && frame_seq.is_multiple_of(OCR_EVERY_N_FRAMES)
}

/// Apply [`CONTRAST`] and [`BRIGHTNESS`] to a BGRA/RGBA buffer, in place-equivalent form.
///
/// `out = clamp((in - 0.5) * CONTRAST + 0.5 + BRIGHTNESS)`, per colour channel, on sRGB bytes.
/// Alpha is copied untouched: an OCR engine wants the colour channels, and rewriting alpha
/// would change what "transparent" means to whatever consumes the buffer next.
///
/// Returns a new buffer rather than mutating: the caller's pixels are also the input to the
/// frame digest and the stego detectors, and enhancing them in place would make those
/// measurements describe the enhancement instead of the screen.
pub fn enhance_contrast(px: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(px.len());
    // Precompute the 256-entry curve: this runs over millions of samples per frame, and the
    // transform depends only on the input byte.
    let curve: [u8; 256] = {
        let mut c = [0u8; 256];
        for (i, slot) in c.iter_mut().enumerate() {
            let v = i as f32 / 255.0;
            let boosted = (v - 0.5) * CONTRAST + 0.5 + BRIGHTNESS;
            *slot = (boosted.clamp(0.0, 1.0) * 255.0).round() as u8;
        }
        c
    };
    for chunk in px.chunks(4) {
        if chunk.len() < 4 {
            // A trailing partial pixel is copied rather than dropped, so the buffer length is
            // preserved and a caller that reasons about stride is not silently wrong.
            out.extend_from_slice(chunk);
            break;
        }
        out.push(curve[chunk[0] as usize]);
        out.push(curve[chunk[1] as usize]);
        out.push(curve[chunk[2] as usize]);
        out.push(chunk[3]);
    }
    out
}

/// Shape recognised lines into the single string that rides in `ocr_text`.
///
/// `None` when nothing was recognised. That is not the same as an empty string: an absent
/// `ocr_text` means the check did not run, and `analyze_frame` skips the viewtree comparison
/// entirely rather than comparing the AX tree against "".
pub fn join_lines<I, S>(lines: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut kept: Vec<String> = Vec::new();
    for line in lines {
        if kept.len() >= MAX_LINES {
            break;
        }
        let t = line.as_ref().trim();
        if t.is_empty() {
            continue;
        }
        // Truncate on character boundaries, never bytes: these lines are routinely Chinese,
        // and a mid-codepoint cut produces invalid UTF-8 that would then be compared against
        // the AX tree's valid text and match nothing.
        kept.push(if t.chars().count() > MAX_LINE_CHARS {
            t.chars().take(MAX_LINE_CHARS).collect()
        } else {
            t.to_string()
        });
    }
    if kept.is_empty() {
        None
    } else {
        Some(kept.join(LINE_JOIN))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_pushes_a_subliminal_band_into_legible_range() {
        // The A1 payload's whole property is that it sits just off the background. Text at 3 %
        // above a mid-grey ground is what the paper renders and what OCR cannot read; after the
        // boost the same pair has to be far apart, or the sanitization loop reads nothing and
        // the finding never surfaces as ui_text for OVL-004.
        let ground = 128u8;
        let payload = 136u8; // ~3 % contrast
        let px = vec![ground, ground, ground, 255, payload, payload, payload, 255];
        let out = enhance_contrast(&px);
        let a = out[0] as i32;
        let b = out[4] as i32;
        assert!(
            (b - a).abs() >= 24,
            "an 8-level difference must open up under {CONTRAST}x contrast, got {a} vs {b}"
        );
    }

    #[test]
    fn enhancement_preserves_length_and_alpha() {
        let px = vec![10, 20, 30, 77, 200, 210, 220, 3];
        let out = enhance_contrast(&px);
        assert_eq!(out.len(), px.len());
        assert_eq!(out[3], 77, "alpha must be copied, not transformed");
        assert_eq!(out[7], 3);
    }

    #[test]
    fn a_partial_trailing_pixel_is_preserved_rather_than_dropped() {
        // A caller that computed a stride and hands over a buffer whose length is not a
        // multiple of four should get a buffer of the same length back, or its next
        // calculation is off by the remainder.
        let px = vec![1, 2, 3, 4, 5, 6];
        assert_eq!(enhance_contrast(&px).len(), 6);
    }

    #[test]
    fn nothing_recognised_is_none_and_not_an_empty_string() {
        // An absent `ocr_text` means the check did not run, and `analyze_frame` then skips the
        // viewtree comparison. `Some("")` would make it compare the AX tree against nothing
        // and report a divergence for every screen.
        assert_eq!(join_lines(Vec::<String>::new()), None);
        assert_eq!(join_lines(vec!["", "   ", "\t"]), None);
    }

    #[test]
    fn lines_and_characters_are_both_capped_on_character_boundaries() {
        let long: String = "确认支付".repeat(40); // 160 chars
        let joined = join_lines(vec![long]).expect("one line");
        assert_eq!(joined.chars().count(), MAX_LINE_CHARS);
        // and it is still valid UTF-8 describing whole characters
        assert!(joined.starts_with("确认支付"));

        let many: Vec<String> = (0..MAX_LINES * 3).map(|i| format!("line{i}")).collect();
        let joined = join_lines(many).expect("lines");
        assert_eq!(joined.split(LINE_JOIN).count(), MAX_LINES);
    }

    #[test]
    fn ocr_runs_on_a_subliminal_trip_and_otherwise_periodically() {
        // A frame that trips a band is read whatever its sequence number.
        assert!(should_ocr(3, 0.30, 0.0));
        // A clean frame is read only on the cadence.
        assert!(should_ocr(0, 0.0, 0.0));
        assert!(should_ocr(OCR_EVERY_N_FRAMES, 0.0, 0.0));
        assert!(!should_ocr(1, 0.0, 0.0));
        assert!(!should_ocr(OCR_EVERY_N_FRAMES - 1, 0.0, 0.0));
    }

    /// The macOS bridge is Objective-C and cannot call this module, so its copies of these
    /// constants are asserted against it here.
    ///
    /// Same pattern as `every_key_the_companion_sends_has_a_field_here` for the Kotlin
    /// companion: where a second language must hold the same number, a test reads the other
    /// language's source rather than trusting a comment. Drift here would mean one platform
    /// enhancing the frame more than the other and reading a payload the other misses.
    #[test]
    fn the_macos_bridge_uses_the_shared_ocr_policy() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../adapters/mac-adapter/native/AgentGuardSCK.m");
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            // The bridge is part of this repository; if it is gone the test should say so
            // rather than pass silently.
            Err(e) => panic!("read {}: {e}", path.display()),
        };
        for (needle, what) in [
            ("#define AG_OCR_EVERY_N_FRAMES 8", "OCR cadence"),
            ("kCIInputContrastKey", "contrast filter"),
            ("@(4.0) forKey:kCIInputContrastKey", "contrast value"),
            ("@(0.15) forKey:kCIInputBrightnessKey", "brightness value"),
            ("lines.count >= 24", "line cap"),
            ("(NSUInteger)80", "per-line character cap"),
            ("componentsJoinedByString:@\" | \"", "line separator"),
        ] {
            assert!(
                src.contains(needle),
                "the macOS bridge no longer matches the shared {what}: expected to find \
                 {needle:?}. Either the bridge drifted or this module's constant changed \
                 without the bridge following."
            );
        }
        // And the constants here are the ones the strings above encode.
        assert_eq!(OCR_EVERY_N_FRAMES, 8);
        assert_eq!(CONTRAST, 4.0);
        assert_eq!(BRIGHTNESS, 0.15);
        assert_eq!(MAX_LINES, 24);
        assert_eq!(MAX_LINE_CHARS, 80);
        assert_eq!(LINE_JOIN, " | ");
    }
}
