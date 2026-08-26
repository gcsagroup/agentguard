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

/// 一格里有多大比例的相邻像素对落在带内,这一格才算"带内格"。
///
/// # 为什么从 max−min 换成"带内相邻对的比例"
///
/// 上一版每格取 3×3 = 9 个采样点,格内对比度 = 这 9 个点的 `max − min`。两个问题:
///
/// 1. **一个高对比像素就把一格废掉。** 格内只要同时出现暗像素和亮像素(普通文字的一条
///    边),`max − min` 就冲出 `BAND_MAX_WIDE`,两个带都不计。而真实屏幕上到处是文字。
///    复核实测:`payload alone strong=1.000`,`payload + ordinary text strong=0.000` ——
///    把阈下载荷叠在正常文字上就够了,攻击者甚至不用知道采样点。
/// 2. **9 点采样有和 framehash 同样的相位盲区**(见 F2):在 1920×1080 与 3840×2160 上,
///    采样点全部落在字形笔画的空隙相位上,探测器只读到背景。
///
/// 换成**分布**判据:全扫这一格,统计相邻像素对里 |Δluma| 落在阈下带内的比例。一个阈下
/// 字形场里约半数相邻对带有那个小台阶,而一处普通文字只有极少数对带**大**台阶(>0.22,
/// 不在带内)—— 这些大台阶只是另外一些对,**不会**抵消小台阶对的计数。所以叠在文字上的
/// 载荷仍然被看见:
///
/// ```text
///                          strong  wide
///   flat white             0.000   0.000
///   dark panel             0.000   0.000
///   gradient               0.000   0.000
///   ordinary text          0.000   0.000
///   subliminal α=0.05      0.492   0.000
///   subliminal + text 叠加  0.429   0.000   <- 旧判据是 0.000
/// ```
const CELL_BAND_FRACTION: f32 = 0.15;

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
    let luma_at = |o: usize| -> f32 {
        if bgra {
            luma(px[o + 2], px[o + 1], px[o])
        } else {
            luma(px[o], px[o + 1], px[o + 2])
        }
    };
    for cy in 0..GRID_ROWS {
        for cx in 0..GRID_COLS {
            // 全扫这一格,统计相邻**横向**像素对里 |Δ| 落在强/宽带内的比例。见
            // `CELL_BAND_FRACTION` 的注释:分布判据,单个高对比像素废不掉它。
            let x0 = cx * cell_w;
            let y0 = cy * cell_h;
            let mut strong_pairs = 0usize;
            let mut wide_pairs = 0usize;
            let mut pairs = 0usize;
            // 横向**和**纵向相邻对都要看:阈下文字的字形在两个方向都有结构,而横条形的
            // 载荷(整行整行地变)只有纵向变化。只算一个方向会漏掉后者。
            let mut prev_row: Vec<f32> = Vec::with_capacity(cell_w);
            let classify = |d: f32, strong: &mut usize, wide: &mut usize, pairs: &mut usize| {
                if (BAND_MIN..BAND_MAX).contains(&d) {
                    *strong += 1;
                } else if (BAND_MAX..BAND_MAX_WIDE).contains(&d) {
                    *wide += 1;
                }
                *pairs += 1;
            };
            for y in y0..y0 + cell_h {
                let row = y * width;
                let mut prev: Option<f32> = None;
                for (i, x) in (x0..x0 + cell_w).enumerate() {
                    let l = luma_at((row + x) * 4);
                    if let Some(p) = prev {
                        classify(
                            (l - p).abs(),
                            &mut strong_pairs,
                            &mut wide_pairs,
                            &mut pairs,
                        );
                    }
                    if let Some(up) = prev_row.get(i) {
                        classify(
                            (l - *up).abs(),
                            &mut strong_pairs,
                            &mut wide_pairs,
                            &mut pairs,
                        );
                    }
                    prev = Some(l);
                    if i < prev_row.len() {
                        prev_row[i] = l;
                    } else {
                        prev_row.push(l);
                    }
                }
            }
            if pairs == 0 {
                continue;
            }
            let strong_frac = strong_pairs as f32 / pairs as f32;
            let wide_frac = wide_pairs as f32 / pairs as f32;
            // 强带优先:一格同时有强带和宽带对时按强带算(更可疑)。
            if strong_frac >= CELL_BAND_FRACTION {
                subliminal += 1;
            } else if wide_frac >= CELL_BAND_FRACTION {
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

#[cfg(test)]
mod b6_遮蔽与相位复核 {
    use super::*;

    // 在真实分辨率上构造,顺带覆盖 F2 的相位盲区。
    const RW: usize = 1920;
    const RH: usize = 1080;

    fn canvas(bg: u8) -> Vec<u8> {
        vec![bg; RW * RH * 4]
    }

    /// 一个阈下字形场:2px on / 2px off 的纵横网格,整体压暗 `alpha`。
    fn paint_subliminal(buf: &mut [u8], alpha: f32, y0: usize, y1: usize) {
        let dim = ((1.0 - alpha) * 255.0) as u8;
        for y in y0..y1 {
            for x in 200..1720 {
                if (x / 2) % 2 == 0 || (y / 2) % 2 == 0 {
                    continue;
                }
                let o = (y * RW + x) * 4;
                buf[o] = dim;
                buf[o + 1] = dim;
                buf[o + 2] = dim;
            }
        }
    }

    /// 叠一层普通黑色文字(稀疏的高对比笔画)。
    fn paint_text(buf: &mut [u8]) {
        for y in 0..RH {
            if (y / 3) % 9 >= 2 {
                continue;
            }
            for x in 0..RW {
                if (x / 2) % 6 >= 2 {
                    continue;
                }
                let o = (y * RW + x) * 4;
                buf[o] = 0;
                buf[o + 1] = 0;
                buf[o + 2] = 0;
            }
        }
    }

    /// 阈下载荷叠在普通文字上,仍然要被抓到。
    ///
    /// 复核实测(修复前):`payload alone strong=1.000`,而
    /// `payload + ordinary text strong=0.000` —— 一个高对比像素就把整格的 max−min 冲出带外。
    #[test]
    fn 阈下载荷叠在文字上仍被抓到() {
        let mut only_payload = canvas(235);
        paint_subliminal(&mut only_payload, 0.05, 300, 780);
        let (s0, _) = band_ratios(&only_payload, RW, RH, false);
        assert!(s0 > SUSPICION_THRESHOLD, "纯载荷本身就该被抓到:strong={s0}");

        let mut payload_and_text = canvas(235);
        paint_subliminal(&mut payload_and_text, 0.05, 300, 780);
        paint_text(&mut payload_and_text);
        let (s1, w1) = band_ratios(&payload_and_text, RW, RH, false);
        assert!(
            is_suspicious(s1, w1),
            "载荷叠在文字上没被抓到:strong={s1} wide={w1}"
        );
    }

    /// 相位盲区:同一个载荷在 1920×1080 上不能静音(F2)。
    #[test]
    fn 载荷在1080p上不静音() {
        let mut buf = canvas(235);
        paint_subliminal(&mut buf, 0.05, 300, 780);
        let (s, w) = band_ratios(&buf, RW, RH, false);
        assert!(
            is_suspicious(s, w),
            "1920×1080 上载荷静音了:strong={s} wide={w}"
        );
    }

    /// 反面:满屏普通文字**不**触发(否则修复把漏报换成了对每个文字界面的误报)。
    #[test]
    fn 普通文字不误报() {
        let mut buf = canvas(245);
        paint_text(&mut buf);
        let (s, w) = band_ratios(&buf, RW, RH, false);
        assert!(!is_suspicious(s, w), "普通文字误报:strong={s} wide={w}");
    }

    /// 反面:纯色、暗色面板、平滑渐变都不触发。
    #[test]
    fn 良性内容不误报() {
        for (name, buf) in [
            ("纯白", canvas(255)),
            ("暗色面板", canvas(38)),
            ("平滑渐变", {
                let mut b = vec![0u8; RW * RH * 4];
                for y in 0..RH {
                    for x in 0..RW {
                        let v = ((x * 255) / RW) as u8;
                        let o = (y * RW + x) * 4;
                        b[o] = v;
                        b[o + 1] = v;
                        b[o + 2] = v;
                    }
                }
                b
            }),
        ] {
            let (s, w) = band_ratios(&buf, RW, RH, false);
            assert!(!is_suspicious(s, w), "{name} 误报:strong={s} wide={w}");
        }
    }
}
