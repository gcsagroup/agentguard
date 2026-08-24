//! A1/A4 steganography-lite detection.
//!
//! LSB steganography embeds payload bits into pixel least-significant bits,
//! which decorrelates neighboring pixels: in natural (especially flat) UI
//! imagery adjacent LSBs match far more often than chance, while stego
//! payloads push the horizontal LSB flip rate toward ~0.5.
//!
//! We sample rows on a stride and measure the flip rate; pixels are analyzed
//! in place and never retained. This is a heuristic *hint* (alert, not block)
//! — high-entropy screenshots (video, noise) can trip it.

/// Fraction of sampled horizontal neighbor pairs whose LSB differs above which
/// the frame is suspicious (chance = 0.5; smooth natural UI ≈ 0).
pub const STEGO_FLIP_THRESHOLD: f32 = 0.35;

/// Horizontal sampling stride in pixels (keeps cost flat for large frames).
const STRIDE_X: usize = 7;
/// Vertical stride between sampled rows.
const STRIDE_Y: usize = 11;

/// LSB flip rate over sampled horizontal neighbor pairs (0..1).
/// Uses the green channel (stego tools typically embed across all channels
/// identically; one channel is representative and cheapest).
/// `px` is tightly packed 4-byte pixels.
pub fn lsb_flip_rate(px: &[u8], width: usize, height: usize) -> f32 {
    if width < STRIDE_X * 2 || height < STRIDE_Y * 2 || px.len() < width * height * 4 {
        return 0.0;
    }
    let mut flips = 0usize;
    let mut pairs = 0usize;
    let mut y = 0;
    while y < height {
        let row = y * width * 4;
        let mut x = 0;
        while x + STRIDE_X < width {
            let a = px[row + x * 4 + 1] & 1;
            let b = px[row + (x + STRIDE_X) * 4 + 1] & 1;
            flips += (a ^ b) as usize;
            pairs += 1;
            x += STRIDE_X;
        }
        y += STRIDE_Y;
    }
    if pairs == 0 {
        return 0.0;
    }
    flips as f32 / pairs as f32
}

/// Chrominance LSB flip rate (max over Cb and Cr).
///
/// (A)I Sees (arXiv 2607.00333 §IV-C, attack A4) embeds payloads "in Cb or Cr
/// **while preserving Y**". The luma detector above is blind to that by
/// construction: it reads the green channel, which barely moves when only
/// chroma LSBs change. So we convert sampled pixels to YCbCr and measure the
/// same neighbour-flip statistic on the chroma planes.
///
/// `bgra` selects channel order; pixels are analyzed in place, never retained.
pub fn chroma_lsb_flip_rate(px: &[u8], width: usize, height: usize, bgra: bool) -> f32 {
    if width < STRIDE_X * 2 || height < STRIDE_Y * 2 || px.len() < width * height * 4 {
        return 0.0;
    }
    let mut cb_flips = 0usize;
    let mut cr_flips = 0usize;
    let mut pairs = 0usize;
    let mut y = 0;
    while y < height {
        let row = y * width * 4;
        let mut x = 0;
        while x + STRIDE_X < width {
            let a = chroma_at(px, row + x * 4, bgra);
            let b = chroma_at(px, row + (x + STRIDE_X) * 4, bgra);
            cb_flips += ((a.0 ^ b.0) & 1) as usize;
            cr_flips += ((a.1 ^ b.1) & 1) as usize;
            pairs += 1;
            x += STRIDE_X;
        }
        y += STRIDE_Y;
    }
    if pairs == 0 {
        return 0.0;
    }
    let cb = cb_flips as f32 / pairs as f32;
    let cr = cr_flips as f32 / pairs as f32;
    cb.max(cr)
}

/// BT.601 Cb/Cr for one pixel, rounded to 8-bit like a real YCbCr conversion.
fn chroma_at(px: &[u8], offset: usize, bgra: bool) -> (u8, u8) {
    let (r, g, b) = if bgra {
        (px[offset + 2], px[offset + 1], px[offset])
    } else {
        (px[offset], px[offset + 1], px[offset + 2])
    };
    let (r, g, b) = (r as f32, g as f32, b as f32);
    let cb = 128.0 - 0.168_736 * r - 0.331_264 * g + 0.5 * b;
    let cr = 128.0 + 0.5 * r - 0.418_688 * g - 0.081_312 * b;
    (
        cb.round().clamp(0.0, 255.0) as u8,
        cr.round().clamp(0.0, 255.0) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = 160;
    const H: usize = 90;

    fn solid(v: u8) -> Vec<u8> {
        vec![v; W * H * 4]
    }

    /// xorshift64 for deterministic pseudo-random LSBs.
    fn random_lsbs() -> Vec<u8> {
        let mut buf = solid(200);
        let mut s: u64 = 0x9E3779B97F4A7C15;
        for px in buf.chunks_exact_mut(4) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            // Even base value, random LSB on green.
            px[1] = 200 | (s as u8 & 1);
        }
        buf
    }

    #[test]
    fn flat_image_has_no_lsb_flips() {
        let buf = solid(128);
        assert_eq!(lsb_flip_rate(&buf, W, H), 0.0);
    }

    #[test]
    fn blocky_ui_stays_below_threshold() {
        // UI-like image: large flat blocks (toolbars/panels). Only the rare
        // pairs straddling a block boundary can flip.
        let mut buf = solid(0);
        for y in 0..H {
            for x in 0..W {
                let o = (y * W + x) * 4;
                let v = if (x / 40) % 2 == 0 { 100u8 } else { 101u8 };
                buf[o] = v;
                buf[o + 1] = v;
                buf[o + 2] = v;
            }
        }
        let r = lsb_flip_rate(&buf, W, H);
        assert!(r < STEGO_FLIP_THRESHOLD, "blocky UI flip rate {r}");
    }

    #[test]
    fn randomized_lsb_payload_is_flagged() {
        let buf = random_lsbs();
        let r = lsb_flip_rate(&buf, W, H);
        assert!(r > STEGO_FLIP_THRESHOLD, "stego-like flip rate {r}");
    }

    /// Luminance-preserving chroma stego: perturb R and B in opposite
    /// directions so BT.601 luma stays put while Cb/Cr LSBs randomize.
    /// This is (A)I Sees A4 as published.
    fn luma_preserving_chroma_payload() -> Vec<u8> {
        let mut buf = solid(120);
        let mut s: u64 = 0x2545F4914F6CDD1D;
        for px in buf.chunks_exact_mut(4) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let bit = (s & 1) as i32;
            // BGRA: shift blue up and red down by luma-compensating amounts.
            let db = bit * 6;
            let dr = -(bit * 6) * 114 / 299; // keeps 0.299R + 0.114B ~ constant
            px[0] = (120 + db).clamp(0, 255) as u8; // B
            px[1] = 120; // G untouched
            px[2] = (120 + dr).clamp(0, 255) as u8; // R
        }
        buf
    }

    #[test]
    fn chroma_payload_is_invisible_to_the_luma_detector() {
        let buf = luma_preserving_chroma_payload();
        let luma = lsb_flip_rate(&buf, W, H);
        assert!(
            luma < STEGO_FLIP_THRESHOLD,
            "green-channel detector should miss chroma stego, got {luma}"
        );
        let chroma = chroma_lsb_flip_rate(&buf, W, H, true);
        assert!(
            chroma > STEGO_FLIP_THRESHOLD,
            "chroma detector should catch it, got {chroma}"
        );
    }

    #[test]
    fn flat_and_blocky_images_have_low_chroma_flip_rate() {
        assert_eq!(chroma_lsb_flip_rate(&solid(128), W, H, true), 0.0);
        let mut buf = solid(0);
        for y in 0..H {
            for x in 0..W {
                let o = (y * W + x) * 4;
                let v = if (x / 40) % 2 == 0 { 100u8 } else { 101u8 };
                buf[o] = v;
                buf[o + 1] = v;
                buf[o + 2] = v;
            }
        }
        let r = chroma_lsb_flip_rate(&buf, W, H, true);
        assert!(r < STEGO_FLIP_THRESHOLD, "blocky UI chroma flip rate {r}");
    }
}
