//! Per-frame structural digest for screenshot-integrity checks.
//!
//! ## Why mean luma was not enough
//!
//! (A)I Sees (arXiv 2607.00333 §IV-C, attack A4) tampers with a screenshot in the
//! TOCTOU window between the moment it is captured and the moment the agent reads
//! it — measured at 50–500 ms, mean ≈ 210 ms. Earlier iterations detected this by
//! comparing whole-frame **mean luminance** across two captures and flagging a jump
//! over 0.35.
//!
//! That threshold is nearly unreachable by the actual attack. Injecting a line of
//! instruction text changes a handful of pixels out of hundreds of thousands, so
//! the frame mean moves by well under a thousandth — a 0.35 mean jump essentially
//! only happens when the whole screen changes, i.e. on a legitimate app switch.
//! The detector was tuned to catch exactly the case that is *not* an attack.
//!
//! ## What this does instead
//!
//! A grid digest: split the frame into [`GRID_COLS`]×[`GRID_ROWS`] blocks and
//! quantise each block's mean luma and mean chroma. Then compare digests
//! block-by-block. A localized injection lights up a few blocks strongly while the
//! rest stay identical — the signature that a frame-wide average destroys.
//!
//! Three properties matter for this to be usable:
//!
//! * **Resolution independent.** The digest is a fixed grid, not a pixel hash, so a
//!   640×360 guard capture and a full-resolution agent screenshot of the same
//!   screen produce comparable digests.
//! * **Quantised.** 4 bits per channel per block, so JPEG/PNG re-encoding noise and
//!   sub-quantum drift do not flip a block. A cryptographic hash of raw pixels
//!   would be perfectly sensitive and perfectly useless — a blinking cursor would
//!   change it.
//! * **Chroma included.** The published A4 variant embeds in Cb/Cr while preserving
//!   luminance; a luma-only digest is blind to it by construction, exactly like the
//!   old stego detector was.
//!
//! The digest is recorded in event metadata, which means it lands inside the signed
//! audit record: the guard attests "at time T the screen looked like this". If the
//! screenshot the agent actually consumed disagrees, that is provable after the
//! fact rather than merely suspected.

/// Digest grid. 16×9 matches the subliminal analysis grid and the common aspect
/// ratio, so blocks stay roughly square.
pub const GRID_COLS: usize = 16;
pub const GRID_ROWS: usize = 9;

/// Samples per block axis (3×3 = 9 samples per block, per channel).
const BLOCK_SAMPLES: usize = 3;

/// Quantisation levels per channel (4 bits).
const LEVELS: u8 = 16;

/// A block whose quantised luma or chroma moved by more than this many levels is
/// "changed". One level ≈ 6 % of range, so this tolerates encoding noise while
/// catching text drawn over a background.
pub const BLOCK_CHANGE_LEVELS: u8 = 2;

/// Fraction of blocks that may change before the frame counts as a *global*
/// repaint (app switch, scroll, video) rather than a localized edit.
pub const GLOBAL_CHANGE_RATIO: f32 = 0.35;

/// Minimum changed blocks for a localized-tamper finding. One block is noise; a
/// line of injected text covers several.
pub const MIN_LOCALIZED_BLOCKS: usize = 2;

/// Grid digest of one frame: `(luma, cb, cr)` quantised per block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameDigest {
    pub luma: Vec<u8>,
    pub cb: Vec<u8>,
    pub cr: Vec<u8>,
}

fn quantise(v: f32) -> u8 {
    let q = (v.clamp(0.0, 1.0) * (LEVELS - 1) as f32).round();
    q as u8
}

/// Compute the digest from tightly packed 4-byte pixels.
///
/// `bgra` selects channel order. Pixels are read in place and never retained.
pub fn digest_rgba(px: &[u8], width: usize, height: usize, bgra: bool) -> Option<FrameDigest> {
    if width < GRID_COLS || height < GRID_ROWS || px.len() < width * height * 4 {
        return None;
    }
    let cell_w = width / GRID_COLS;
    let cell_h = height / GRID_ROWS;
    let n = GRID_COLS * GRID_ROWS;
    let mut luma = Vec::with_capacity(n);
    let mut cb = Vec::with_capacity(n);
    let mut cr = Vec::with_capacity(n);
    for gy in 0..GRID_ROWS {
        for gx in 0..GRID_COLS {
            let mut sy_sum = 0.0f32;
            let mut cb_sum = 0.0f32;
            let mut cr_sum = 0.0f32;
            let mut count = 0.0f32;
            for sy in 0..BLOCK_SAMPLES {
                for sx in 0..BLOCK_SAMPLES {
                    let x = gx * cell_w + (sx * cell_w) / BLOCK_SAMPLES;
                    let y = gy * cell_h + (sy * cell_h) / BLOCK_SAMPLES;
                    let o = (y * width + x) * 4;
                    let (r, g, b) = if bgra {
                        (px[o + 2] as f32, px[o + 1] as f32, px[o] as f32)
                    } else {
                        (px[o] as f32, px[o + 1] as f32, px[o + 2] as f32)
                    };
                    // BT.601, matching `stego::chroma_at` so the two agree.
                    sy_sum += (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
                    cb_sum += (128.0 - 0.168_736 * r - 0.331_264 * g + 0.5 * b) / 255.0;
                    cr_sum += (128.0 + 0.5 * r - 0.418_688 * g - 0.081_312 * b) / 255.0;
                    count += 1.0;
                }
            }
            luma.push(quantise(sy_sum / count));
            cb.push(quantise(cb_sum / count));
            cr.push(quantise(cr_sum / count));
        }
    }
    Some(FrameDigest { luma, cb, cr })
}

impl FrameDigest {
    /// Hex encoding: `luma|cb|cr`, one hex nibble per block.
    pub fn to_hex(&self) -> String {
        fn enc(v: &[u8]) -> String {
            v.iter()
                .map(|b| std::char::from_digit(*b as u32, 16).unwrap_or('0'))
                .collect()
        }
        format!("{}|{}|{}", enc(&self.luma), enc(&self.cb), enc(&self.cr))
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let mut parts = s.split('|');
        let expect = GRID_COLS * GRID_ROWS;
        let dec = |t: Option<&str>| -> Option<Vec<u8>> {
            let t = t?;
            if t.len() != expect {
                return None;
            }
            t.chars()
                .map(|c| c.to_digit(16).map(|d| d as u8))
                .collect::<Option<Vec<u8>>>()
        };
        let luma = dec(parts.next())?;
        let cb = dec(parts.next())?;
        let cr = dec(parts.next())?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self { luma, cb, cr })
    }

    /// Indices of blocks that differ from `other` by more than the tolerance.
    pub fn changed_blocks(&self, other: &FrameDigest) -> Vec<usize> {
        let mut out = Vec::new();
        for i in 0..self.luma.len().min(other.luma.len()) {
            let d = |a: &[u8], b: &[u8]| a[i].abs_diff(b[i]);
            if d(&self.luma, &other.luma) > BLOCK_CHANGE_LEVELS
                || d(&self.cb, &other.cb) > BLOCK_CHANGE_LEVELS
                || d(&self.cr, &other.cr) > BLOCK_CHANGE_LEVELS
            {
                out.push(i);
            }
        }
        out
    }

    pub fn blocks(&self) -> usize {
        self.luma.len()
    }
}

/// How two digests of the same screen differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestDelta {
    /// Byte-identical grid.
    Identical,
    /// A few blocks changed while the rest held still — the localized-edit
    /// signature that a frame-wide mean average destroys.
    Localized { changed: Vec<usize>, total: usize },
    /// Most of the frame changed: an app switch, a scroll, a video. Not a tamper
    /// signal, and treating it as one is how the old threshold got its direction
    /// backwards.
    GlobalRepaint { changed: usize, total: usize },
}

pub fn compare(prev: &FrameDigest, next: &FrameDigest) -> DigestDelta {
    let changed = prev.changed_blocks(next);
    let total = prev.blocks().min(next.blocks());
    if changed.is_empty() {
        return DigestDelta::Identical;
    }
    if total > 0 && changed.len() as f32 / total as f32 > GLOBAL_CHANGE_RATIO {
        return DigestDelta::GlobalRepaint {
            changed: changed.len(),
            total,
        };
    }
    if changed.len() >= MIN_LOCALIZED_BLOCKS {
        return DigestDelta::Localized { changed, total };
    }
    // A single block: below the noise floor.
    DigestDelta::Identical
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = 320;
    const H: usize = 180;

    fn solid(v: u8) -> Vec<u8> {
        let mut buf = vec![255u8; W * H * 4];
        for px in buf.chunks_exact_mut(4) {
            px[0] = v;
            px[1] = v;
            px[2] = v;
        }
        buf
    }

    /// Draw dark text-like rows into a horizontal band, as an injected
    /// instruction would.
    fn inject_text(buf: &mut [u8], y0: usize, y1: usize, x0: usize, x1: usize) {
        for y in y0..y1 {
            if (y / 2) % 2 == 0 {
                continue;
            }
            for x in x0..x1 {
                let o = (y * W + x) * 4;
                buf[o] = 10;
                buf[o + 1] = 10;
                buf[o + 2] = 10;
            }
        }
    }

    #[test]
    fn identical_frames_are_identical() {
        let a = digest_rgba(&solid(200), W, H, false).unwrap();
        let b = digest_rgba(&solid(200), W, H, false).unwrap();
        assert_eq!(a, b);
        assert_eq!(compare(&a, &b), DigestDelta::Identical);
    }

    /// The case the mean-luma detector could not see: a line of injected text.
    #[test]
    fn localized_text_injection_is_detected_where_mean_luma_fails() {
        let base = solid(200);
        let mut tampered = base.clone();
        inject_text(&mut tampered, 20, 40, 20, 300);

        // Whole-frame mean luma barely moves — the old 0.35 threshold needs a
        // change ~100x larger than this attack produces.
        let mean = |buf: &[u8]| -> f32 {
            let mut s = 0.0;
            for px in buf.chunks_exact(4) {
                s += (0.299 * px[0] as f32 + 0.587 * px[1] as f32 + 0.114 * px[2] as f32) / 255.0;
            }
            s / (W * H) as f32
        };
        let luma_jump = (mean(&base) - mean(&tampered)).abs();
        assert!(
            luma_jump < 0.35,
            "mean-luma jump {luma_jump} would have been caught; pick a subtler injection"
        );

        let a = digest_rgba(&base, W, H, false).unwrap();
        let b = digest_rgba(&tampered, W, H, false).unwrap();
        match compare(&a, &b) {
            DigestDelta::Localized { changed, total } => {
                assert!(changed.len() >= MIN_LOCALIZED_BLOCKS, "changed={changed:?}");
                assert!(
                    (changed.len() as f32 / total as f32) <= GLOBAL_CHANGE_RATIO,
                    "should look localized, not global"
                );
            }
            other => panic!("expected Localized, got {other:?}"),
        }
    }

    /// Chroma-only tamper: luminance preserved, so a luma digest cannot see it.
    #[test]
    fn chroma_only_change_is_detected() {
        let base = solid(120);
        let mut tampered = base.clone();
        for y in 30..60 {
            for x in 30..200 {
                let o = (y * W + x) * 4;
                // Push blue up and red down so BT.601 luma stays put.
                tampered[o] = 40; // R
                tampered[o + 2] = 210; // B
            }
        }
        let a = digest_rgba(&base, W, H, false).unwrap();
        let b = digest_rgba(&tampered, W, H, false).unwrap();
        assert_ne!(a.cb, b.cb, "chroma plane must move");
        assert!(matches!(
            compare(&a, &b),
            DigestDelta::Localized { .. } | DigestDelta::GlobalRepaint { .. }
        ));
    }

    /// A full repaint is reported as such, not as a tamper.
    #[test]
    fn app_switch_is_a_global_repaint_not_a_tamper() {
        let a = digest_rgba(&solid(230), W, H, false).unwrap();
        let b = digest_rgba(&solid(30), W, H, false).unwrap();
        match compare(&a, &b) {
            DigestDelta::GlobalRepaint { changed, total } => {
                assert!(changed as f32 / total as f32 > GLOBAL_CHANGE_RATIO);
            }
            other => panic!("expected GlobalRepaint, got {other:?}"),
        }
    }

    /// Quantisation tolerates small encoding noise, so a re-encoded copy of the
    /// same screen does not read as tampered.
    #[test]
    fn quantisation_absorbs_encoding_noise() {
        let base = solid(150);
        let mut noisy = base.clone();
        let mut s: u64 = 0x1234_5678_9abc_def0;
        for px in noisy.chunks_exact_mut(4) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let jitter = (s % 3) as i32 - 1; // ±1
            for ch in px.iter_mut().take(3) {
                *ch = (*ch as i32 + jitter).clamp(0, 255) as u8;
            }
        }
        let a = digest_rgba(&base, W, H, false).unwrap();
        let b = digest_rgba(&noisy, W, H, false).unwrap();
        assert_eq!(compare(&a, &b), DigestDelta::Identical);
    }

    /// The digest is a fixed grid, so the same screen at a different resolution
    /// still compares.
    #[test]
    fn digest_is_resolution_independent() {
        // Same content, two resolutions: a flat field with a dark band.
        fn build(w: usize, h: usize) -> Vec<u8> {
            let mut buf = vec![255u8; w * h * 4];
            for px in buf.chunks_exact_mut(4) {
                px[0] = 200;
                px[1] = 200;
                px[2] = 200;
            }
            for y in (h / 4)..(h / 2) {
                for x in 0..w {
                    let o = (y * w + x) * 4;
                    buf[o] = 20;
                    buf[o + 1] = 20;
                    buf[o + 2] = 20;
                }
            }
            buf
        }
        let small = digest_rgba(&build(320, 180), 320, 180, false).unwrap();
        let large = digest_rgba(&build(1280, 720), 1280, 720, false).unwrap();
        assert_eq!(
            compare(&small, &large),
            DigestDelta::Identical,
            "same screen at 4x scale must match"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = digest_rgba(&solid(100), W, H, false).unwrap();
        let hex = d.to_hex();
        assert_eq!(hex.len(), GRID_COLS * GRID_ROWS * 3 + 2);
        assert_eq!(FrameDigest::from_hex(&hex), Some(d));
        assert!(FrameDigest::from_hex("garbage").is_none());
        assert!(FrameDigest::from_hex("aa|bb|cc").is_none());
    }

    #[test]
    fn bgra_and_rgba_orders_agree() {
        let rgba = {
            let mut b = solid(180);
            inject_text(&mut b, 50, 70, 10, 200);
            b
        };
        let mut bgra = rgba.clone();
        for px in bgra.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
        let a = digest_rgba(&rgba, W, H, false).unwrap();
        let b = digest_rgba(&bgra, W, H, true).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn frames_too_small_have_no_digest() {
        assert!(digest_rgba(&solid(10)[..64], 4, 4, false).is_none());
    }
}
