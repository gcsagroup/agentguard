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

/// 判据阈值。两条路的指标见下方长注释。
pub const STEGO_FLIP_THRESHOLD: f32 = 0.35;

/// 扫描的最小高度。**每一行都扫**(不再按固定行间距采样)。
///
/// 上一版按 `STRIDE_Y = 11` 采样行(只看第 0、11、22… 行)—— 这和它已经修掉的**水平**固定
/// 跨步是同一个洞的垂直版:攻击者把 LSB 载荷只嵌到 `y % 11 != 0` 的行(约 91% 容量),每个
/// 被采样行都干净,翻转率归零、OVL-008/011 静默(第七轮复核发现 8)。既然行内已经每个相邻对
/// 都看,行也全看:2 FPS 下全扫一帧(约 1600×900)只是毫秒级,没有理由留一个可对齐的靶子。
const MIN_SCAN_HEIGHT: usize = 2;

// # 为什么两条路的指标都换掉了
//
// 上一版都是"比较 `(x, x+7)` 这一对固定跨步像素的最低位"。一次独立复核给出两个方向都错的
// 结论。
//
// ## 一、可以被精确归零
//
// `STRIDE_X = 7` 是公开常量。把每第 7 列的 LSB 钉住,所有被采样的对就永远相同:
//
// ```text
// naive   LSB payload: flip_rate=0.5004 flagged=true
// aligned LSB payload: flip_rate=0.0000 flagged=false
// payload capacity kept: 85.7% (1233900 of 1440000 pixels)
// naive   chroma payload: rate=0.5065 flagged=true
// aligned chroma payload: rate=0.0000 flagged=false
// ```
//
// **精确归零**,载荷容量保留 85.7%,嵌入端只需改三行。OVL-008 与 OVL-011 同时失效。
//
// ## 二、在普通内容上误报
//
// 平滑斜坡的 LSB 就是斜坡的奇偶性;固定 7 像素跨步正好采到它(1600×900,阈值 0.35):
//
// ```text
// horizontal 8-bit gradient  luma=0.8860 FLAGGED
// dithered gradient          luma=0.5788 FLAGGED
// photo with film grain      luma=0.4932 FLAGGED
// ```
//
// 一张渐变壁纸或一个视频窗口 → 每帧一条 Medium alert(OVL-008),而本 crate 自己在
// `AlphaChannel` 的注释里就写着"a guard that alerts on every frame is a guard that gets
// switched off"。两条合起来:这个探测器的信噪比是**反的**。
//
// ## 亮度那一路换成什么
//
// 关键不是"最低位会不会变",而是"最低位是不是**独立于**高位"。平滑渐变的最低位是一个缓慢
// 变化量的奇偶性,和次低位有固定关系;真正的 LSB 隐写把最低位换成密文,与次低位无关。
// 指标改成 `max(0, bit0翻转率 − bit1翻转率)`,行内**相邻**像素对:
//
// ```text
//                        bit0    bit1    差值   判据(>0.35)
// 纯色                   0.000   0.000   0.000   干净
// 8bit 平滑渐变          0.159   0.079   0.079   干净   <- 旧指标 0.886 误报
// LSB 隐写(渐变底)      0.495   0.079   0.416   隐写
// 照片颗粒噪声           0.507   0.500   0.008   干净   <- 旧指标 0.493 误报
// 抖动渐变               0.455   0.455   0.000   干净   <- 旧指标 0.579 误报
// ```
//
// 要绕过它,攻击者必须把次低位的翻转率也拉到和最低位一样 —— 那是 ±2 级的可见噪声。
//
// **一条如实的局限**:载体本身就是高熵内容(照片、视频)时 bit0 与 bit1 都接近 0.5,
// 差值接近 0,这种情形下的 LSB 隐写检测不出来。上一版也检测不出来 —— 它只是把所有高熵内容
// 一律标记,于是"检测到隐写"和"对噪声误报"在输出上不可区分。现在这条局限是显式的。
//
// ## 色度那一路换成什么
//
// 已发表的 A4 色度变体是"保持亮度不变地在 Cb/Cr 里嵌入",实测形状是 B 抬 ±6、R 压 ∓2
// 抵消亮度 —— 那改动的是好几个比特,所以 LSB 统计漏得掉。而"色度有边缘、亮度没有"是这类
// 载荷的**结构性**签名:自然图像和界面里色度边缘总是和亮度边缘同处一地。
//
// ```text
//                        判据    (>0.35 = 隐写)
//   纯色灰                0.000   干净
//   保亮度色度载荷(±6)     0.507   隐写      <- 已发表的那个形状
//   色度 LSB 载荷(±1)     0.495   隐写
//   彩色渐变(色相变化)     0.159   干净
//   照片噪声              0.081   干净
//   红字反锯齿边缘         0.000   干净      <- 边缘稀疏,占比上不来
//   彩色抖动              0.347   干净      <- 贴着线,见 MIN_CHROMA_DELTA
// ```

/// LSB flip rate over sampled horizontal neighbor pairs (0..1).
/// Uses the green channel (stego tools typically embed across all channels
/// identically; one channel is representative and cheapest).
/// `px` is tightly packed 4-byte pixels.
pub fn lsb_flip_rate(px: &[u8], width: usize, height: usize) -> f32 {
    if width < 4 || height < MIN_SCAN_HEIGHT || px.len() < width * height * 4 {
        return 0.0;
    }
    let mut b0 = 0usize;
    let mut b1 = 0usize;
    let mut pairs = 0usize;
    for y in 0..height {
        let row = y * width * 4;
        for x in 0..width - 1 {
            let a = px[row + x * 4 + 1];
            let b = px[row + (x + 1) * 4 + 1];
            b0 += ((a ^ b) & 1) as usize;
            b1 += (((a >> 1) ^ (b >> 1)) & 1) as usize;
            pairs += 1;
        }
    }
    if pairs == 0 {
        return 0.0;
    }
    let r0 = b0 as f32 / pairs as f32;
    let r1 = b1 as f32 / pairs as f32;
    (r0 - r1).max(0.0)
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
    if width < 4 || height < MIN_SCAN_HEIGHT || px.len() < width * height * 4 {
        return 0.0;
    }
    // 判据:**色度变了而亮度没变**的相邻对占比。理由见文件上方长注释的"色度那一路"。
    //
    // `MIN_CHROMA_DELTA` 取 0.45 是为了连 ±1 的色度 LSB 也算上(一个 ±1 的蓝通道变化给出
    // ΔCb = 0.5);`MAX_LUMA_DELTA` 取 0.5 排除掉逐通道独立的抖动 —— 绿通道 ±1 就让亮度动
    // 0.587,而保亮度载荷按定义不会。彩色抖动落在 0.347,紧贴阈值:它和色度 LSB 隐写在这个
    // 统计量上本来就几乎不可分,区别只有"抖动也会让亮度动"这么多。这是这两种内容的物理
    // 差别,不是调参没调好。
    const MIN_CHROMA_DELTA: f32 = 0.45;
    const MAX_LUMA_DELTA: f32 = 0.5;
    let mut hits = 0usize;
    let mut pairs = 0usize;
    for y in 0..height {
        let row = y * width * 4;
        for x in 0..width - 1 {
            let rgb = |o: usize| -> (f32, f32, f32) {
                if bgra {
                    (px[o + 2] as f32, px[o + 1] as f32, px[o] as f32)
                } else {
                    (px[o] as f32, px[o + 1] as f32, px[o + 2] as f32)
                }
            };
            let (r1, g1, b1) = rgb(row + x * 4);
            let (r2, g2, b2) = rgb(row + (x + 1) * 4);
            let y1 = 0.299 * r1 + 0.587 * g1 + 0.114 * b1;
            let y2 = 0.299 * r2 + 0.587 * g2 + 0.114 * b2;
            let cb1 = -0.168_736 * r1 - 0.331_264 * g1 + 0.5 * b1;
            let cb2 = -0.168_736 * r2 - 0.331_264 * g2 + 0.5 * b2;
            let cr1 = 0.5 * r1 - 0.418_688 * g1 - 0.081_312 * b1;
            let cr2 = 0.5 * r2 - 0.418_688 * g2 - 0.081_312 * b2;
            let dc = (cb1 - cb2).abs().max((cr1 - cr2).abs());
            if dc >= MIN_CHROMA_DELTA && (y1 - y2).abs() < MAX_LUMA_DELTA {
                hits += 1;
            }
            pairs += 1;
        }
    }
    if pairs == 0 {
        return 0.0;
    }
    hits as f32 / pairs as f32
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

#[cfg(test)]
mod b6_隐写判据复核 {
    use super::*;

    const RW: usize = 1600;
    const RH: usize = 900;

    fn frame(mut f: impl FnMut(usize, usize) -> (u8, u8, u8)) -> Vec<u8> {
        let mut buf = vec![255u8; RW * RH * 4];
        for y in 0..RH {
            for x in 0..RW {
                let (r, g, b) = f(x, y);
                let o = (y * RW + x) * 4;
                // BGRA
                buf[o] = b;
                buf[o + 1] = g;
                buf[o + 2] = r;
            }
        }
        buf
    }

    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut s = seed;
        move || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            s >> 33
        }
    }

    /// 普通内容不能触发隐写告警。
    ///
    /// 旧判据比较 `(x, x+7)` 的最低位,而平滑斜坡的最低位就是斜坡的奇偶性 —— 固定 7 像素
    /// 跨步正好采到它。复核实测(1600×900,阈值 0.35):
    ///
    /// ```text
    /// horizontal 8-bit gradient  luma=0.8860 FLAGGED
    /// dithered gradient          luma=0.5788 FLAGGED
    /// photo with film grain      luma=0.4932 FLAGGED
    /// ```
    ///
    /// 一张渐变壁纸或一个视频窗口 → 每帧一条 Medium alert(OVL-008),而本 crate 自己在
    /// `AlphaChannel` 的注释里就写着"a guard that alerts on every frame is a guard that
    /// gets switched off"。
    #[test]
    fn 普通内容不触发隐写告警() {
        let mut r = rng(7);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("纯色", frame(|_, _| (200, 200, 200))),
            (
                "8bit 水平渐变",
                frame(|x, _| {
                    let v = ((x * 255) / RW) as u8;
                    (v, v, v)
                }),
            ),
            (
                "抖动渐变",
                frame(|x, _| {
                    let v = ((x * 255) / RW) as i32 + (r() % 3) as i32 - 1;
                    let v = v.clamp(0, 255) as u8;
                    (v, v, v)
                }),
            ),
            (
                "照片颗粒噪声",
                frame(|_, _| {
                    let v = (128 + (r() % 13) as i32 - 6).clamp(0, 255) as u8;
                    (v, v, v)
                }),
            ),
            (
                "反锯齿文字",
                frame(|x, y| {
                    let on = (y / 3) % 7 < 2 && (x / 2) % 5 < 3;
                    let v = if on { 40 } else { 245 };
                    (v, v, v)
                }),
            ),
            (
                "彩色渐变",
                frame(|x, _| {
                    let v = ((x * 255) / RW) as u8;
                    (v, 100, 255 - v)
                }),
            ),
        ];
        for (name, buf) in &cases {
            let luma = lsb_flip_rate(buf, RW, RH);
            let chroma = chroma_lsb_flip_rate(buf, RW, RH, true);
            assert!(
                luma < STEGO_FLIP_THRESHOLD,
                "{name}: 亮度判据误报 {luma:.4}"
            );
            assert!(
                chroma < STEGO_FLIP_THRESHOLD,
                "{name}: 色度判据误报 {chroma:.4}"
            );
        }
    }

    /// 对齐到任何固定跨步都不能把判据归零。
    ///
    /// 旧实现只比较 `(x, x+7)`,而 `STRIDE_X = 7` 是公开常量。把每第 7 列的 LSB 钉住,
    /// 所有被采样的对就永远相同:**精确 0.0000**,载荷容量保留 85.7%,嵌入端改三行。
    /// 这条测试遍历一批跨步 —— 攻击者可以对齐其中任何一个,判据都必须仍然报警。
    #[test]
    fn 对齐到固定跨步不能归零() {
        for stride in [2usize, 3, 5, 7, 11, 13, 16] {
            let mut r = rng(stride as u64 * 31);
            // 在灰底上做 LSB 隐写,但把每第 `stride` 列的 LSB 钉成固定值。
            let buf = frame(|x, _| {
                let bit = if x % stride == 0 { 0 } else { (r() & 1) as u8 };
                let v = (180 & 0xFE) | bit;
                (v, v, v)
            });
            let luma = lsb_flip_rate(&buf, RW, RH);
            assert!(
                luma > STEGO_FLIP_THRESHOLD,
                "对齐到跨步 {stride} 之后亮度判据只剩 {luma:.4} —— 被归零了"
            );
        }
    }

    /// **垂直方向**的同一个洞:载荷只嵌在 `y % stride != 0` 的行(避开旧的 STRIDE_Y=11
    /// 采样行),旧实现每个被采样行都干净、翻转率**精确归零**。现在每一行都扫,这条对齐
    /// evasion被堵(第七轮复核发现 8)。
    ///
    /// 用 stride ∈ {7,11,13}:避开这些采样行仍保留 ≥85% 的行做载荷,翻转率远在阈值之上。
    /// **一条如实的密度下限**:全扫堵的是「对齐到采样行」这种几乎不损容量的 evasion;若攻击者
    /// 肯把 ≥30% 的行留成干净灰底(stride=2、3),平均翻转率会被稀释到阈值下 —— 但那要付出
    /// 大量容量,且和文件上方那条「高熵载体检测不出」是同一类速率检测器的固有局限,不是可
    /// 对齐的固定靶子。
    #[test]
    fn 避开采样行的隐写仍被抓到() {
        for stride in [7usize, 11, 13] {
            let mut r = rng(stride as u64 * 71 + 5);
            // 只在 `y % stride != 0` 的行做 LSB 隐写;被跳过的行是干净灰底。
            let buf = frame(|_, y| {
                if y % stride == 0 {
                    (180, 180, 180) // 旧采样行:干净
                } else {
                    let bit = (r() & 1) as u8;
                    let v = (180 & 0xFE) | bit;
                    (v, v, v)
                }
            });
            let luma = lsb_flip_rate(&buf, RW, RH);
            assert!(
                luma > STEGO_FLIP_THRESHOLD,
                "载荷避开 {stride} 的采样行后亮度判据只剩 {luma:.4} —— 垂直方向被归零了"
            );
        }
    }

    /// 已发表的保亮度色度载荷仍然被抓到。
    ///
    /// 这是 A4 色度变体的实际形状:B 抬 ±6、R 压 ∓2 抵消亮度。它改动好几个比特,所以按
    /// LSB 统计会漏 —— 色度那一路因此用的是"色度有边缘而亮度没有"这个结构性签名。
    #[test]
    fn 保亮度色度载荷被抓到() {
        let mut r = rng(99);
        let buf = frame(|_, _| {
            let bit = (r() & 1) as i32;
            let b = (120 + bit * 6).clamp(0, 255) as u8;
            let rr = (120 - (bit * 6 * 114) / 299).clamp(0, 255) as u8;
            (rr, 120, b)
        });
        let luma = lsb_flip_rate(&buf, RW, RH);
        let chroma = chroma_lsb_flip_rate(&buf, RW, RH, true);
        assert!(
            luma < STEGO_FLIP_THRESHOLD,
            "亮度判据不该看见保亮度载荷(那是色度那一路的活):{luma:.4}"
        );
        assert!(
            chroma > STEGO_FLIP_THRESHOLD,
            "已发表的保亮度色度载荷没有被抓到:{chroma:.4}"
        );
    }

    /// 真正的 LSB 隐写仍然被抓到 —— 否则上面那些"不误报"是把功能关掉换来的。
    #[test]
    fn 真正的lsb隐写仍然被抓到() {
        let mut r = rng(4242);
        // 渐变底上的 LSB 隐写:底噪是平滑的,最低位是密文。
        let buf = frame(|x, _| {
            let base = (((x * 255) / RW) as u8) & 0xFE;
            let v = base | (r() & 1) as u8;
            (v, v, v)
        });
        let luma = lsb_flip_rate(&buf, RW, RH);
        assert!(
            luma > STEGO_FLIP_THRESHOLD,
            "渐变底上的 LSB 隐写没有被抓到:{luma:.4}"
        );
    }
}
