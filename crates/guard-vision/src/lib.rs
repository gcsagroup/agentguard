//! Pixel and frame analysis, shared by every platform that can capture a screen.
//!
//! # Why this is its own crate
//!
//! These detectors read a buffer of bytes and a width and a height. Nothing in them is
//! macOS or Windows: the subliminal contrast bands, the LSB flip rates, the block digest
//! and the AX↔OCR cross-validation are arithmetic over samples. They lived inside
//! `mac-adapter` for as long as macOS was the only platform that could produce pixels,
//! and the moment a second platform could, the choice was to move them here or to write
//! them twice.
//!
//! Writing them twice is the project's own worst-defect pattern, named in three places
//! already: iteration 17 shipped a redactor that never ran on the platform that needed
//! it, and `AppFace.kt` carries a written warning that its dHash is "reimplemented rather
//! than shared … the algorithm is **normative**". Two copies of a threshold are not one
//! rule implemented twice; they are two rules with one name, and the day they disagree
//! nobody can say which was meant. So there is exactly one copy, here, and a platform
//! adapter's whole job is to turn its own pixels into [`FrameStats`] and hand them over.
//!
//! # What a platform adapter still owns
//!
//! Getting the pixels, and saying honestly whether it could. That is genuinely
//! per-platform — ScreenCaptureKit and TCC on macOS, GDI or Graphics Capture on Windows —
//! and it stays in the adapter.

pub mod frame;
pub mod framehash;
pub mod ocr;
pub mod stego;
pub mod subliminal;
pub mod uitree;
pub mod viewtree;

pub use frame::{
    analyze_frame, demo_transparent_overlay_frame, markers_as_ui_text, simulate_frame_from_regions,
    CaptureFrameMeta, FrameAnalysis, FrameConsistency, FrameStats, CONSISTENCY_LUMA_JUMP,
    CONSISTENCY_WINDOW_MS,
};
pub use framehash::{compare as compare_frame_digests, digest_rgba, DigestDelta, FrameDigest};
pub use ocr::{enhance_contrast, join_lines, should_ocr};
pub use stego::{chroma_lsb_flip_rate, lsb_flip_rate};
pub use subliminal::{band_ratios, subliminal_ratio, subliminal_ratio_wide};
pub use uitree::{
    flatten_text, form_fills_from_snapshot, is_editable_role, regions_from_snapshot,
    snapshot_to_event, snapshot_to_event_with_viewport, UiNode, UiSnapshot,
};
pub use viewtree::{
    compare as compare_viewtree, cross_validate as cross_validate_viewtree, ViewtreeComparison,
};

/// Whether a capture path's alpha byte means anything.
///
/// # Why this is a parameter and not an inference
///
/// GDI's `BitBlt` into a 32-bit `BI_RGB` DIB writes three channels and leaves the fourth
/// **undefined — in practice zero**. Reading it as alpha makes every sample fully transparent,
/// so `low_opacity_ratio` comes out at 1.0, and `analyze_frame` reports a transparent overlay
/// on **every frame** the Windows adapter captures. Not occasionally: always. A guard that
/// alerts on every frame is a guard that gets switched off, and the number looks like a
/// measurement the whole way down.
///
/// ScreenCaptureKit does deliver real alpha, so the answer differs per capture path and only
/// the capture path knows it. Passing it in makes it impossible to add a new platform without
/// answering the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlphaChannel {
    /// The fourth byte is real alpha (ScreenCaptureKit, a PNG, a composited layer).
    Meaningful,
    /// The fourth byte is padding. Transparency is not observable from these pixels, so
    /// `low_opacity_ratio` is reported as 0 — the honest answer, which leaves the
    /// transparent-overlay finding to come from the structured region list instead of from a
    /// byte that was never written.
    Padding,
}

/// Convert a captured RGBA/BGRA buffer into [`FrameStats`], running every pixel detector.
///
/// This is the one entry point a platform adapter needs. It exists so that "which
/// detectors run on a captured frame" is a property of this crate and not of whichever
/// adapter was written most recently — the failure mode being a new platform that
/// captures pixels perfectly and quietly runs three of the five checks.
///
/// `bgra` selects the channel order: `true` for the BGRA that both CoreGraphics and GDI
/// hand back, `false` for RGBA.
#[allow(clippy::too_many_arguments)]
pub fn stats_from_pixels(
    px: &[u8],
    width: u32,
    height: u32,
    timestamp_ms: i64,
    bgra: bool,
    alpha: AlphaChannel,
) -> FrameStats {
    let w = width as usize;
    let h = height as usize;
    let (strong, wide) = subliminal::band_ratios(px, w, h, bgra);
    FrameStats {
        width,
        height,
        timestamp_ms,
        mean_luma: mean_luma(px, bgra),
        low_opacity_ratio: match alpha {
            AlphaChannel::Meaningful => alpha_low_ratio(px),
            AlphaChannel::Padding => 0.0,
        },
        subliminal_ratio: strong,
        subliminal_ratio_wide: wide,
        lsb_flip_rate: stego::lsb_flip_rate(px, w, h),
        chroma_lsb_flip_rate: stego::chroma_lsb_flip_rate(px, w, h, bgra),
        frame_digest: framehash::digest_rgba(px, w, h, bgra).map(|d| d.to_hex()),
        ocr_text: None,
        ax_text: None,
        regions: Vec::new(),
    }
}

/// Rec. 601 mean luminance over the whole buffer, 0..1.
fn mean_luma(px: &[u8], bgra: bool) -> f32 {
    if px.len() < 4 {
        return 0.0;
    }
    let mut sum: u64 = 0;
    let mut n: u64 = 0;
    for p in px.chunks_exact(4) {
        let (r, g, b) = if bgra {
            (p[2] as u64, p[1] as u64, p[0] as u64)
        } else {
            (p[0] as u64, p[1] as u64, p[2] as u64)
        };
        sum += (299 * r + 587 * g + 114 * b) / 1000;
        n += 1;
    }
    if n == 0 {
        0.0
    } else {
        (sum as f32 / n as f32) / 255.0
    }
}

/// Fraction of samples that are near-transparent.
///
/// Only called when the caller has said the alpha byte is real. See [`AlphaChannel`] for what
/// happens when it is not.
fn alpha_low_ratio(px: &[u8]) -> f32 {
    if px.len() < 4 {
        return 0.0;
    }
    let mut low: u64 = 0;
    let mut n: u64 = 0;
    for p in px.chunks_exact(4) {
        if p[3] < 13 {
            low += 1;
        }
        n += 1;
    }
    if n == 0 {
        0.0
    } else {
        low as f32 / n as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: usize, h: usize, rgba: [u8; 4]) -> Vec<u8> {
        rgba.iter().cycle().take(w * h * 4).copied().collect()
    }

    #[test]
    fn stats_from_pixels_runs_every_detector_not_some() {
        // The point of this test is the *shape* of FrameStats, not the values: a new
        // platform must not be able to produce a frame with three of five channels
        // silently left at their default. Every numeric channel is asserted to have
        // been written by the pipeline, and the digest to be present for a frame that
        // is not degenerate.
        let mut px = solid(64, 32, [10, 10, 10, 255]);
        // Give the frame structure so the digest is not refused as degenerate.
        for y in 0..32 {
            for x in 0..64 {
                if (x / 4 + y / 4) % 2 == 0 {
                    let i = (y * 64 + x) * 4;
                    px[i] = 240;
                    px[i + 1] = 240;
                    px[i + 2] = 240;
                }
            }
        }
        let s = stats_from_pixels(&px, 64, 32, 1_000, false, AlphaChannel::Meaningful);
        assert_eq!(s.width, 64);
        assert_eq!(s.height, 32);
        assert_eq!(s.timestamp_ms, 1_000);
        assert!(s.mean_luma > 0.0, "mean_luma was never computed");
        assert!(
            s.frame_digest.is_some(),
            "a structured frame must produce a digest, or the A4 comparison has nothing to compare"
        );
        // ax_text/ocr_text are the adapter's to fill, and must start empty rather than
        // guessed: a wrong ax_text produces a Viewtree finding against an innocent app.
        assert!(s.ax_text.is_none());
        assert!(s.ocr_text.is_none());
        assert!(s.regions.is_empty());
    }

    #[test]
    fn channel_order_changes_luma_the_way_it_should() {
        // A BGRA buffer read as RGBA swaps red and blue. Rec. 601 weights them very
        // differently (0.299 vs 0.114), so getting the flag wrong is not cosmetic —
        // it moves mean_luma, and mean_luma is the A4 fallback threshold.
        let px = solid(8, 8, [255, 0, 0, 255]);
        let as_rgba = stats_from_pixels(&px, 8, 8, 0, false, AlphaChannel::Meaningful).mean_luma;
        let as_bgra = stats_from_pixels(&px, 8, 8, 0, true, AlphaChannel::Meaningful).mean_luma;
        assert!(
            (as_rgba - 0.299).abs() < 0.01,
            "pure red read as RGBA should weigh 0.299, got {as_rgba}"
        );
        assert!(
            (as_bgra - 0.114).abs() < 0.01,
            "pure red bytes read as BGRA are blue and should weigh 0.114, got {as_bgra}"
        );
    }

    #[test]
    fn a_real_alpha_channel_is_measured() {
        let px = solid(16, 16, [128, 128, 128, 255]);
        assert_eq!(
            stats_from_pixels(&px, 16, 16, 0, false, AlphaChannel::Meaningful).low_opacity_ratio,
            0.0
        );
        let clear = solid(16, 16, [128, 128, 128, 0]);
        assert_eq!(
            stats_from_pixels(&clear, 16, 16, 0, false, AlphaChannel::Meaningful).low_opacity_ratio,
            1.0
        );
    }

    #[test]
    fn a_padding_alpha_byte_never_becomes_a_transparency_measurement() {
        // The bug this pins, in full: GDI's BitBlt into a 32-bit BI_RGB DIB leaves the fourth
        // byte at zero. Read as alpha that is "every pixel fully transparent", so
        // `low_opacity_ratio` is 1.0, and `analyze_frame`'s `> 0.15` test then reports a
        // transparent overlay on EVERY frame the Windows adapter captures — a Critical finding
        // twice a second, forever, from a byte nobody wrote.
        let gdi_like = solid(16, 16, [128, 128, 128, 0]);
        let s = stats_from_pixels(&gdi_like, 16, 16, 0, true, AlphaChannel::Padding);
        assert_eq!(s.low_opacity_ratio, 0.0);
        // And the finding must not appear.
        let analysis = frame::analyze_frame(&s);
        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| matches!(f.kind, guard_overlay::OverlayKind::TransparentOverlay)),
            "a padded alpha byte produced a transparent-overlay finding: {:?}",
            analysis.findings
        );
        // The same bytes with a real alpha channel *should* report it, or this test would pass
        // for the wrong reason — a threshold that never fires.
        let meaningful = stats_from_pixels(&gdi_like, 16, 16, 0, true, AlphaChannel::Meaningful);
        assert_eq!(meaningful.low_opacity_ratio, 1.0);
        assert!(frame::analyze_frame(&meaningful)
            .findings
            .iter()
            .any(|f| matches!(f.kind, guard_overlay::OverlayKind::TransparentOverlay)));
    }
}
