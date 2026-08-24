//! A1 subliminal-injection detection (the "(A)I Sees What You Don't"
//! Visual Input Sanitization countermeasure, implemented on the detection side).
//!
//! Subliminal text is alpha-blended at a few percent opacity: invisible to the
//! user, legible to a VLM. On a coarse grid we measure per-cell luma contrast;
//! benign UI is either flat (contrast ≈ 0) or high-contrast text, while
//! subliminal payloads land in a narrow low-contrast band. The fraction of
//! cells in that band is `subliminal_ratio`.
//!
//! Pixels are analyzed in place and never retained.

/// Analysis grid: 16×9 cells.
pub const GRID_COLS: usize = 16;
pub const GRID_ROWS: usize = 9;

/// Per-cell contrast (max-min luma, 0..1) below which a cell is just flat fill.
pub const BAND_MIN: f32 = 0.008;
/// Top of the **strong** band: below this, low-contrast text is essentially
/// invisible to a human, so a small fraction of such cells is already alarming.
pub const BAND_MAX: f32 = 0.08;

/// Top of the **wide** band. (A)I Sees §V-C tested overlay opacity at 2, 5, 8,
/// 10 and 20 %, and VLMs extracted the payload 18/20–20/20 at *every* level, so
/// stopping at 0.08 left the paper's upper half undetected. Cells between
/// `BAND_MAX` and here are still faint but overlap ordinary low-contrast UI
/// (dark-mode panels, subtle borders), so they need a much larger share of the
/// grid before they count — hence a separate ratio.
pub const BAND_MAX_WIDE: f32 = 0.22;

/// Fraction of strong-band cells that raises a finding.
pub const SUSPICION_THRESHOLD: f32 = 0.10;

/// Fraction of wide-band cells that raises a finding on its own.
pub const WIDE_SUSPICION_THRESHOLD: f32 = 0.30;

/// Samples per cell axis (3×3 = 9 samples per cell).
const CELL_SAMPLES: usize = 3;

fn luma(r: u8, g: u8, b: u8) -> f32 {
    (0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32) / 255.0
}

/// Fraction of grid cells whose local contrast lands in the strong subliminal
/// band. `px` is tightly packed 4-byte pixels, `bgra` selects channel order.
pub fn subliminal_ratio(px: &[u8], width: usize, height: usize, bgra: bool) -> f32 {
    band_ratios(px, width, height, bgra).0
}

/// Fraction of cells in the wide band `[BAND_MAX, BAND_MAX_WIDE)` — the
/// 8–20 % opacity range from (A)I Sees §V-C.
pub fn subliminal_ratio_wide(px: &[u8], width: usize, height: usize, bgra: bool) -> f32 {
    band_ratios(px, width, height, bgra).1
}

/// Whether either band trips its threshold.
pub fn is_suspicious(strong: f32, wide: f32) -> bool {
    strong > SUSPICION_THRESHOLD || wide > WIDE_SUSPICION_THRESHOLD
}

/// `(strong_band_ratio, wide_band_ratio)` over the analysis grid.
pub fn band_ratios(px: &[u8], width: usize, height: usize, bgra: bool) -> (f32, f32) {
    if width < GRID_COLS || height < GRID_ROWS || px.len() < width * height * 4 {
        return (0.0, 0.0);
    }
    let cell_w = width / GRID_COLS;
    let cell_h = height / GRID_ROWS;
    let mut subliminal = 0usize;
    let mut wide = 0usize;
    for cy in 0..GRID_ROWS {
        for cx in 0..GRID_COLS {
            let mut lo = f32::MAX;
            let mut hi = f32::MIN;
            for sy in 0..CELL_SAMPLES {
                for sx in 0..CELL_SAMPLES {
                    let x = cx * cell_w + (sx * cell_w) / CELL_SAMPLES;
                    let y = cy * cell_h + (sy * cell_h) / CELL_SAMPLES;
                    let o = (y * width + x) * 4;
                    let l = if bgra {
                        luma(px[o + 2], px[o + 1], px[o])
                    } else {
                        luma(px[o], px[o + 1], px[o + 2])
                    };
                    lo = lo.min(l);
                    hi = hi.max(l);
                }
            }
            let contrast = hi - lo;
            if (BAND_MIN..BAND_MAX).contains(&contrast) {
                subliminal += 1;
            } else if (BAND_MAX..BAND_MAX_WIDE).contains(&contrast) {
                wide += 1;
            }
        }
    }
    let cells = (GRID_COLS * GRID_ROWS) as f32;
    (subliminal as f32 / cells, wide as f32 / cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = 160;
    const H: usize = 90;

    fn solid(l: u8) -> Vec<u8> {
        vec![l; W * H * 4]
    }

    /// Paint glyph-like stripes (2px on / 2px off) dimmed toward black at
    /// `alpha` over the white background, inside a wide band. Stripe structure
    /// matters: subliminal detection needs both background and dimmed pixels
    /// inside the same cell.
    fn with_glyph_stripes(base: &mut [u8], alpha: f32, y0: usize, y1: usize) {
        let dim = ((1.0 - alpha) * 255.0) as u8;
        for y in y0..y1 {
            if (y / 2) % 2 == 0 {
                continue; // gap row between glyph strokes
            }
            for x in 10..150 {
                let o = (y * W + x) * 4;
                for c in 0..3 {
                    base[o + c] = dim;
                }
            }
        }
    }

    #[test]
    fn flat_screen_has_zero_subliminal() {
        let buf = solid(255);
        assert_eq!(subliminal_ratio(&buf, W, H, false), 0.0);
    }

    #[test]
    fn high_contrast_text_is_not_subliminal() {
        let mut buf = solid(255);
        with_glyph_stripes(&mut buf, 1.0, 30, 60); // opaque black text
        assert!(subliminal_ratio(&buf, W, H, false) < SUSPICION_THRESHOLD);
    }

    #[test]
    fn low_contrast_injection_is_flagged() {
        let mut buf = solid(255);
        with_glyph_stripes(&mut buf, 0.04, 30, 60); // ~4% alpha: invisible to humans
        let r = subliminal_ratio(&buf, W, H, false);
        assert!(
            r >= SUSPICION_THRESHOLD,
            "expected subliminal band detection, ratio={r}"
        );
    }

    /// (A)I Sees §V-C: payloads remain VLM-legible at 20 % opacity, where the
    /// strong band no longer fires. The wide band must cover that case.
    #[test]
    fn twenty_percent_opacity_is_caught_by_the_wide_band() {
        let mut buf = solid(255);
        with_glyph_stripes(&mut buf, 0.20, 20, 70);
        let (strong, wide) = band_ratios(&buf, W, H, false);
        assert!(
            strong <= SUSPICION_THRESHOLD,
            "20% opacity is above the strong band by construction, got {strong}"
        );
        assert!(
            wide > WIDE_SUSPICION_THRESHOLD,
            "wide band should catch 20% opacity, got {wide}"
        );
        assert!(is_suspicious(strong, wide));
    }

    #[test]
    fn eight_percent_opacity_is_caught() {
        let mut buf = solid(255);
        with_glyph_stripes(&mut buf, 0.08, 20, 70);
        let (strong, wide) = band_ratios(&buf, W, H, false);
        assert!(is_suspicious(strong, wide), "strong={strong} wide={wide}");
    }

    /// False-positive control for the wide band. Dark-mode UI is genuinely
    /// low-contrast and overlaps [BAND_MAX, BAND_MAX_WIDE), which is exactly why
    /// the wide band needs a much larger share of the grid (0.30) than the strong
    /// band (0.10) before it fires. A panel of subtle borders on a dark background
    /// must not read as an injected payload.
    #[test]
    fn dark_mode_panel_is_not_subliminal() {
        // Dark background with faint separators: contrast around 0.10–0.15, i.e.
        // inside the wide band, but only over part of the screen.
        let mut buf = solid(28);
        for y in 0..H {
            // A separator line every 12 rows, slightly lighter than the panel.
            if y % 12 != 0 {
                continue;
            }
            for x in 0..(W / 3) {
                let o = (y * W + x) * 4;
                for c in 0..3 {
                    buf[o + c] = 58;
                }
            }
        }
        let (strong, wide) = band_ratios(&buf, W, H, false);
        assert!(
            !is_suspicious(strong, wide),
            "dark-mode panel must not trip either band: strong={strong} wide={wide}"
        );
    }

    #[test]
    fn flat_and_opaque_screens_are_not_suspicious() {
        let flat = solid(255);
        let (s0, w0) = band_ratios(&flat, W, H, false);
        assert!(!is_suspicious(s0, w0), "flat: strong={s0} wide={w0}");
        let mut opaque = solid(255);
        with_glyph_stripes(&mut opaque, 1.0, 30, 60);
        let (s1, w1) = band_ratios(&opaque, W, H, false);
        assert!(!is_suspicious(s1, w1), "opaque text: strong={s1} wide={w1}");
    }

    #[test]
    fn bgra_order_equivalent() {
        let mut rgba = solid(200);
        with_glyph_stripes(&mut rgba, 0.05, 30, 50);
        // Convert RGBA→BGRA.
        let mut bgra = rgba.clone();
        for px in bgra.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
        let a = subliminal_ratio(&rgba, W, H, false);
        let b = subliminal_ratio(&bgra, W, H, true);
        assert!((a - b).abs() < 1e-6);
    }
}
