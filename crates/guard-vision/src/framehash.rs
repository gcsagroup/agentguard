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

// # 为什么这里从"每块 9 个点"改成了"块内全扫 + 两个平面"
//
// 上一版是 `BLOCK_SAMPLES = 3`,每块取 3×3 = 9 个**精确像素点**。在 1920×1080 上,整帧
// 一共只读 48 个 x 坐标 × 27 个 y 坐标 = **1296 个像素,占全帧 0.0625%**。落在采样点之间
// 的任何绘制对摘要完全不可见 —— 而"屏幕没变"正是这个摘要要证明的事。
//
// 一次独立复核跑出的三个结果:
//
// ```text
// (1) 在 1920×1080 浅色帧上涂满 303,264 个纯黑像素(全帧 14.6%,一整屏横幅文字):
//       digest base = digest tampered,逐字节相同。
//     mean_luma 只移动 0.1348,低于 0.35 的兜底阈值,所以兜底也静音。
//
// (2) 连采样点都不用知道:相邻采样行之间最大有 39 个连续行从不被读,
//     一条 39 行高、1920 像素宽的全宽黑条(74,880 像素)同样 Identical。
//
// (3) 最坏的一格是相位对齐。采样行是 gy*(h/9) + {0, (h/9)/3, 2(h/9)/3},
//     h=1080 时全部 ≡ 0 (mod 40),h=2160 时 ≡ 0 (mod 80)。字形笔画节距为 4 行
//     (2px 笔画 + 2px 间隔,即普通小字)时,每个采样点都落在同一相位的空隙行上:
//       320x180   changed=14  tamper      <- scripts/frame-digest-demo.sh 跑的尺寸
//      1920x1080  changed= 0  SILENT
//      3840x2160  changed= 0  SILENT
//     也就是探测器在它自己的演示尺寸上有效,在用户的屏幕上无效。
// ```
//
// ## 为什么单靠块内均值也不够
//
// 复核建议改成块均值。改完之后本文件原有的两条测试立刻变红,而它们是对的:一条 2 像素
// 高的文字笔画落在 120 像素高的块里,只占 1.6% 面积,均值移动远小于一个量化级(6.25%)。
// 均值是**相位无关**的,但它按定义会稀释细笔画 —— 这是均值这个统计量的信息论下限,不是
// 实现问题。
//
// 所以两个平面一起记,一次全帧扫描同时算出来:
//
// * `luma` / `cb` / `cr` —— 块内**均值**。相位无关,负责"这块整体变了"(背景色改变、
//   大面积覆盖)。
// * `detail` —— 块内**水平相邻像素亮度差的均值**(边缘能量)。一条细笔画在均值里被稀释
//   到看不见,但它带来的边缘能量非常高:纯色背景的 detail 接近 0,一行文字把它推到几个
//   量化级。这一路负责"这块里多了/少了东西",而且因为**每个像素都被读到**,它同样是
//   相位无关的。
//
// 两个平面各自用同一套量化和同一个 `BLOCK_CHANGE_LEVELS` 容差,任一超限即算该块变化。
// 代价是一次全帧线性 pass(1920×1080 约 200 万像素,几毫秒),和已有的 `mean_luma` /
// `alpha_low_ratio` 同量级 —— 而上一版为了省这一次 pass,把探测器的有效性换掉了。

/// 算作一次"边缘"的最小相邻亮度差。
///
/// # 为什么 detail 记的是边缘**个数**而不是边缘**能量**
///
/// 第一版这里用的是相邻像素亮度差的**均值**。它不行,而且不行的方式很有教育意义:
///
/// ```text
/// 信号:120×120 块里一条 2 像素黑条  -> 均值 |Δ| ≈ 0.0072
/// 噪声:同一块上 ±2/255 的编码噪声   -> 均值 |Δ| ≈ 0.0050
/// ```
///
/// **同一个数量级。** 于是任何放大倍数要么让信号低于容差(漏),要么让噪声高于容差
/// (整帧 144 块全报变化 —— 这是 `quantisation_absorbs_encoding_noise` 实际打出来的结果)。
/// 均值这个统计量分不开"几个大跳变"和"很多小跳变",而这正好是"文字"和"噪声"的区别。
///
/// 改成**跨过阈值的边缘对占比**之后两者相差约 30 倍:编码噪声的 |Δ| 约 0.008,一个字形
/// 笔画的 |Δ| 约 0.86。阈值 0.25 把它们干净分开,而且顺带解决了另一个复核发现的误报:
/// 一张平滑渐变的每相邻像素差是 1/255,一个边缘都不算,detail 保持 0 —— 而按能量算的话
/// 渐变会被当成高熵内容。
const EDGE_THRESHOLD: f32 = 0.25;

/// 边缘占比到量化级的映射系数,配 `sqrt` 使用。
///
/// # 为什么是 sqrt 而不是线性放大
///
/// 要同时满足两头。一块 120×120 的区域有 28,680 个相邻对:
///
/// ```text
///                              占比       线性×32     sqrt(5x)
///   细条两次跳变              0.00837      4.02 级     3.07 级
///   细条一次跳变(压在块边界)  0.00418      2.01 级     2.17 级
///   密集文字(10% 的对跨阈)   0.10000     15.00 级    10.61 级   <- 线性在这里饱和
///   编码噪声(跨阈数为 0)     0.00000      0.00 级     0.00 级
/// ```
///
/// 线性放大要让"压在块边界的细条"过容差,就必须让密集文字饱和到 15 —— 而饱和意味着一块
/// 已有文字的区域上再叠一条注入,detail 不动。sqrt 把两头都留在量程内:最小信号 2.17 级
/// (过 `DETAIL_CHANGE_LEVELS` = 1),密集文字 10.6 级(还有 4 级余量能继续升)。
///
/// 系数 5 是按"压在块边界的细条必须 ≥ 2 级"倒推的:sqrt(0.00418·K)·15 ≥ 2 → K ≥ 4.25。
///
/// 注意噪声那一行:因为 detail 记的是**跨过 `EDGE_THRESHOLD` 的边缘个数**,编码噪声的
/// 跨阈数恒为 0,所以放大倍数**完全不影响**噪声抑制。这正是从"边缘能量均值"换成
/// "跨阈边缘计数"换来的性质 —— 前者噪声与信号同量级,调什么倍数都两头不讨好。
const DETAIL_SCALE: f32 = 5.0;

/// Quantisation levels per channel (4 bits).
const LEVELS: u8 = 16;

/// A block whose quantised luma or chroma moved by more than this many levels is
/// "changed". One level ≈ 6 % of range, so this tolerates encoding noise while
/// catching text drawn over a background.
pub const BLOCK_CHANGE_LEVELS: u8 = 2;

/// `detail` 平面的容差,比亮度那一档更紧。
///
/// 亮度用 2 级是为了容忍编码噪声。detail 是边缘能量,它在纯色区域**恒为 0**,所以噪声底
/// 噪比亮度低得多;而它要检测的信号本身很小 —— 一条 2 像素黑条正好压在块边界上时,两个块
/// 各只分到一行,边缘能量只有满值的一半(约 1.7 级)。容差 2 会把这种情形放过,而"注入正好
/// 落在网格线上"不是攻击者需要避开的巧合,是 1/60 的自然概率。
pub const DETAIL_CHANGE_LEVELS: u8 = 1;

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
    /// 块内跨阈边缘对的占比。均值平面看不见细笔画,这一路能 —— 见 `EDGE_THRESHOLD`。
    pub detail: Vec<u8>,
    /// 这个摘要**真的带**细节平面吗,还是只是解析一个三平面摘要时补的零?
    ///
    /// # 为什么必须能区分
    ///
    /// macOS 的采集路径上,摘要不是由这个函数算的 —— 它由 `AgentGuardSCK.m` 里的手写孪生
    /// 实现 `ag_frame_digest` 算出来、以字符串形式跨 FFI 传过来。那一侧仍然是**每块 9 个
    /// 采样点、三个平面**,也就是这一轮修掉的相位盲区在 macOS 上**依然存在**。
    ///
    /// 如果不区分,一个三平面摘要会被当成"detail 恰好全为 0"的四平面摘要。两个都来自 ObjC
    /// 的摘要相互比较时不会误报(两边都是 0),但那正是危险的地方:**一切看起来正常,而
    /// 这一路完全没有信息**。这个字段让消费者能说出"这个摘要来自一个没有细节平面的实现",
    /// 而不是默默地按零比较。
    ///
    /// `docs/frame-integrity.md` 要求两侧"必须逐字节一致",而仓库里**没有任何测试钉住这
    /// 一点**(对比 icon dHash 有向量 fixture)。移植 ObjC 那一侧需要 macOS + Xcode,
    /// 这个环境里做不到,所以留下的是:一个能被检测到的标志、一份向量 fixture(见
    /// `eval/fixtures/frame_digest_vectors.json`)、以及运行时一条明确的警告。
    pub has_detail: bool,
}

fn quantise(v: f32) -> u8 {
    let q = (v.clamp(0.0, 1.0) * (LEVELS - 1) as f32).round();
    q as u8
}

/// Compute the digest from tightly packed 4-byte pixels.
///
/// `bgra` selects channel order. Pixels are read in place and never retained.
pub fn digest_rgba(px: &[u8], width: usize, height: usize, bgra: bool) -> Option<FrameDigest> {
    digest_rgba_stride(px, width, height, width * 4, bgra)
}

/// 带行跨距(`bytes_per_row`)的版本。
///
/// # 为什么必须有这个参数
///
/// ObjC 那一侧的孪生实现 `ag_frame_digest(base, width, height, bytesPerRow, bgra)` **有**
/// 这个参数并按 `base + yy*bytesPerRow + x*4` 取址;Rust 侧只按 `(y*width + x)*4` 取址,
/// 而 `docs/frame-integrity.md` 明确要求两者"必须逐字节一致"。IOSurface 的常规布局是行按
/// 64 字节对齐,例如 1000×600 的 `bytesPerRow = 4032`(而 `width*4 = 4000`),复核实测:
///
/// ```text
/// objc (stride aware) = 0123456789abbcde0123456789abbcde…
/// rust (packed only)  = 89a5663456789abc567899abb8976744…
/// changed blocks 109 of 144
/// ```
///
/// 通过现有适配器不可达(win-adapter 的 `Frame` 保证无填充,mac 走 ObjC 实现),但
/// `guard-cli frame-digest --raw` 这条文档化的操作员流程一旦 dump 一个 IOSurface 就会
/// 命中,而且**没有任何测试钉住这两个实现一致** —— 不像 icon dHash 有向量 fixture。
pub fn digest_rgba_stride(
    px: &[u8],
    width: usize,
    height: usize,
    bytes_per_row: usize,
    bgra: bool,
) -> Option<FrameDigest> {
    if width < GRID_COLS || height < GRID_ROWS || bytes_per_row < width * 4 {
        return None;
    }
    if px.len() < (height - 1) * bytes_per_row + width * 4 {
        return None;
    }
    // 行内偏移按像素算,所以跨距必须是 4 的倍数;不是的话按紧凑处理并拒绝。
    if !bytes_per_row.is_multiple_of(4) {
        return None;
    }
    let stride_px = bytes_per_row / 4;
    let cell_w = width / GRID_COLS;
    let cell_h = height / GRID_ROWS;
    let n = GRID_COLS * GRID_ROWS;
    let mut luma = Vec::with_capacity(n);
    let mut cb = Vec::with_capacity(n);
    let mut cr = Vec::with_capacity(n);
    let mut detail = Vec::with_capacity(n);
    // 复用的"上一行亮度"缓冲。在块循环外分配,所以整个摘要只有一次分配。
    let mut prev_row: Vec<f32> = Vec::with_capacity(cell_w);
    for gy in 0..GRID_ROWS {
        for gx in 0..GRID_COLS {
            let mut sy_sum = 0.0f32;
            let mut cb_sum = 0.0f32;
            let mut cr_sum = 0.0f32;
            let mut edge_sum = 0.0f32;
            let mut count = 0.0f32;
            let mut edge_count = 0.0f32;
            // 全帧扫描:块内**每一个**像素都读。这是让相位对齐失效的那个性质 ——
            // 不存在"从不被读的行"。
            let y0 = gy * cell_h;
            let x0 = gx * cell_w;
            // 边缘计数要同时算**水平**和**垂直**方向。
            //
            // 只算水平的话,一条全宽的横向黑条跨阈边缘数恰好为 **0** —— 那一行里每个像素都
            // 一样黑,行内没有任何跳变。而一条全宽横条正是复核用来演示相位盲区的形状
            // (39 行高、1920 像素宽),所以只算一个方向等于把这条测试留在原地。
            // 垂直梯度看的是"这一行和上一行差多少",横条在它进入和离开的两行上各贡献一次
            // 满幅跳变。文字两个方向都有。
            // 垂直梯度要**跨过块的上边界**。
            //
            // 不跨的话,落在块第一行的笔画只产生一次跳变而不是两次(它上面没有行可比),
            // 边缘数减半、正好掉到容差以下。复核那条"遍历每个行偏移"的测试里,120 个偏移
            // 中恰好剩下 0、118、119 三个静音 —— 就是块的上下边界。而"注入正好落在网格线上"
            // 不是攻击者需要避开的巧合,是 1/60 的自然概率。
            prev_row.clear();
            if y0 > 0 {
                let above = (y0 - 1) * stride_px;
                for x in x0..x0 + cell_w {
                    let o = (above + x) * 4;
                    let (r, g, b) = if bgra {
                        (px[o + 2] as f32, px[o + 1] as f32, px[o] as f32)
                    } else {
                        (px[o] as f32, px[o + 1] as f32, px[o + 2] as f32)
                    };
                    prev_row.push((0.299 * r + 0.587 * g + 0.114 * b) / 255.0);
                }
            }
            for y in y0..y0 + cell_h {
                let row = y * stride_px;
                let mut prev_luma: Option<f32> = None;
                for (i, x) in (x0..x0 + cell_w).enumerate() {
                    let o = (row + x) * 4;
                    let (r, g, b) = if bgra {
                        (px[o + 2] as f32, px[o + 1] as f32, px[o] as f32)
                    } else {
                        (px[o] as f32, px[o + 1] as f32, px[o + 2] as f32)
                    };
                    // BT.601, matching `stego::chroma_at` so the two agree.
                    let l = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
                    sy_sum += l;
                    cb_sum += (128.0 - 0.168_736 * r - 0.331_264 * g + 0.5 * b) / 255.0;
                    cr_sum += (128.0 + 0.5 * r - 0.418_688 * g - 0.081_312 * b) / 255.0;
                    count += 1.0;
                    if let Some(pl) = prev_luma {
                        if (l - pl).abs() > EDGE_THRESHOLD {
                            edge_sum += 1.0;
                        }
                        edge_count += 1.0;
                    }
                    if let Some(up) = prev_row.get(i) {
                        if (l - *up).abs() > EDGE_THRESHOLD {
                            edge_sum += 1.0;
                        }
                        edge_count += 1.0;
                    }
                    prev_luma = Some(l);
                    if i < prev_row.len() {
                        prev_row[i] = l;
                    } else {
                        prev_row.push(l);
                    }
                }
            }
            if count == 0.0 {
                count = 1.0;
            }
            if edge_count == 0.0 {
                edge_count = 1.0;
            }
            luma.push(quantise(sy_sum / count));
            cb.push(quantise(cb_sum / count));
            cr.push(quantise(cr_sum / count));
            // 跨阈边缘对的占比,经 sqrt 映射后量化。见 `EDGE_THRESHOLD` / `DETAIL_SCALE`。
            detail.push(quantise(((edge_sum / edge_count) * DETAIL_SCALE).sqrt()));
        }
    }
    Some(FrameDigest {
        luma,
        cb,
        cr,
        detail,
        has_detail: true,
    })
}

impl FrameDigest {
    /// Hex encoding: `luma|cb|cr`, one hex nibble per block.
    pub fn to_hex(&self) -> String {
        fn enc(v: &[u8]) -> String {
            v.iter()
                .map(|b| std::char::from_digit(*b as u32, 16).unwrap_or('0'))
                .collect()
        }
        format!(
            "{}|{}|{}|{}",
            enc(&self.luma),
            enc(&self.cb),
            enc(&self.cr),
            enc(&self.detail)
        )
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
        // `detail` 是这一轮新增的第四个平面。三平面的摘要仍然解析得出,但**必须能被认出来**
        // 是三平面的 —— 见 `has_detail`。
        let (detail, has_detail) = match parts.next() {
            Some(t) => (dec(Some(t))?, true),
            None => (vec![0u8; expect], false),
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            luma,
            cb,
            cr,
            detail,
            has_detail,
        })
    }

    /// Indices of blocks that differ from `other` by more than the tolerance.
    pub fn changed_blocks(&self, other: &FrameDigest) -> Vec<usize> {
        // 上界取**六个**平面长度的最小值。
        //
        // 以前用 `self.luma.len().min(other.luma.len())` 做上界却去索引 cb/cr,而三个字段
        // 都是 `pub` —— 任何消费者手搓一个 `FrameDigest { luma: vec![0;144], cb: vec![], .. }`
        // 就能让这里越界 panic。`from_hex` 构造不出这种形状,`digest_rgba` 也不会,所以
        // 当时不可达;但"不可达"依赖于所有构造点都正确,而字段是公开的。
        let n = [
            self.luma.len(),
            self.cb.len(),
            self.cr.len(),
            self.detail.len(),
            other.luma.len(),
            other.cb.len(),
            other.cr.len(),
            other.detail.len(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        let mut out = Vec::new();
        for i in 0..n {
            let d = |a: &[u8], b: &[u8]| a[i].abs_diff(b[i]);
            if d(&self.luma, &other.luma) > BLOCK_CHANGE_LEVELS
                || d(&self.cb, &other.cb) > BLOCK_CHANGE_LEVELS
                || d(&self.cr, &other.cr) > BLOCK_CHANGE_LEVELS
                || d(&self.detail, &other.detail) > DETAIL_CHANGE_LEVELS
            {
                out.push(i);
            }
        }
        out
    }

    /// 变化块,但**先减掉全局偏移**再判 —— 用来识别藏在一次均匀全局变化下的局部编辑。
    ///
    /// # 为什么需要它
    ///
    /// `compare` 的连通分量分析能抓住与大块动画**空间分离**的注入。但攻击者不必空间分离:
    /// 给整帧叠一个**均匀**的亮度/色度偏移(每块都偏移 > `BLOCK_CHANGE_LEVELS`,约 12.5%,
    /// 一次淡入/主题切换的量),`changed_blocks` 就会报**所有**块都变了 → 并成一个连通分量 →
    /// 没有次要簇 → `changed/total > 0.35` → `GlobalRepaint` → `None`,注入被整个吞掉
    /// (第七轮复核发现 9)。
    ///
    /// 这里对每个平面估计一个**全局偏移**(所有块 signed delta 的中位数,对少数注入块稳健),
    /// 减掉它,再看**残差**是否超容差。一个均匀色调偏移减完残差≈0(那些块不再算变化);而注入
    /// 块偏离这个全局偏移,减完仍在。detail(边缘能量)不随均匀色调偏移走,所以仍用绝对差。
    pub fn changed_blocks_residual(&self, other: &FrameDigest) -> Vec<usize> {
        let n = [
            self.luma.len(),
            self.cb.len(),
            self.cr.len(),
            self.detail.len(),
            other.luma.len(),
            other.cb.len(),
            other.cr.len(),
            other.detail.len(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if n == 0 {
            return Vec::new();
        }
        // 每个平面所有块的 signed delta,取中位数当全局偏移。
        let median = |plane_self: &[u8], plane_other: &[u8]| -> i32 {
            let mut deltas: Vec<i32> = (0..n)
                .map(|i| plane_other[i] as i32 - plane_self[i] as i32)
                .collect();
            deltas.sort_unstable();
            deltas[n / 2]
        };
        let off_luma = median(&self.luma, &other.luma);
        let off_cb = median(&self.cb, &other.cb);
        let off_cr = median(&self.cr, &other.cr);
        let tol = BLOCK_CHANGE_LEVELS as i32;
        let mut out = Vec::new();
        for i in 0..n {
            let resid =
                |ps: &[u8], po: &[u8], off: i32| (po[i] as i32 - ps[i] as i32 - off).unsigned_abs();
            if resid(&self.luma, &other.luma, off_luma) > tol as u32
                || resid(&self.cb, &other.cb, off_cb) > tol as u32
                || resid(&self.cr, &other.cr, off_cr) > tol as u32
                || self.detail[i].abs_diff(other.detail[i]) > DETAIL_CHANGE_LEVELS
            {
                out.push(i);
            }
        }
        out
    }

    /// 只比较**均值**平面,给两幅分辨率不同的画面用。
    ///
    /// # 为什么 detail 平面不能跨分辨率比
    ///
    /// 边缘能量按定义不是尺度无关的:同一条 1 像素的笔画在 4 倍放大后变成一段 4 像素的
    /// 渐变,相邻像素差降到四分之一。这不是实现缺陷,是"相邻像素差"这个统计量的性质。
    ///
    /// 而这恰好暴露了文档里一条更大的问题。`docs/frame-integrity.md` 说"守卫的 640×360
    /// 采集和一张全分辨率截图产生**可比**的摘要,已在 4 倍尺度差下验证",但那条验证用的是
    /// **网格对齐的平坦色带** —— 点采样唯一能存活的形状。复核用一页小号深色文字实测原生
    /// 1920×1080 与它自己降采样到 640×360 的版本:
    ///
    /// ```text
    /// changed 27 of 144 blocks;  guard-cli frame-digest --expect 会在一张
    /// **诚实的**帧上打印 TAMPERED (localized): 27/144 并 exit 1
    /// ```
    ///
    /// 也就是说跨分辨率可比性对**任何有细节的内容**本来就不成立,只对平坦色块成立。
    /// 实时路径不受影响(`FrameConsistency::check` 有 `prev.width != stats.width` 的守卫),
    /// 受影响的是那条文档化的操作员核验流程。
    ///
    /// 所以这里把两件事分开:同分辨率比较用 `changed_blocks`(四个平面,能看见细笔画);
    /// 跨分辨率比较用这个(三个均值平面,只能看见大面积变化),而且调用方必须知道自己
    /// 在做后者 —— 文档也据此改写。
    pub fn changed_blocks_cross_scale(&self, other: &FrameDigest) -> Vec<usize> {
        let n = [
            self.luma.len(),
            self.cb.len(),
            self.cr.len(),
            other.luma.len(),
            other.cb.len(),
            other.cr.len(),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        let mut out = Vec::new();
        for i in 0..n {
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

    // 先做连通分量分析,**再**看全局占比 —— 顺序反过来正是这个探测器能被一段全屏动画关掉的
    // 原因。
    //
    // 旧逻辑:changed/total > 0.35 就直接返回 `GlobalRepaint`,而 `FrameConsistency` 把它
    // 映射成 `None`(无 finding)。于是攻击者只要与注入**同时**重绘 ≥36% 的网格,注入就消失:
    //
    // ```text
    // injection alone                 -> Some(FrameRegionTamper)
    // animation over 4/9 grid rows(44%)-> GlobalRepaint -> None    <- 注入被一起吞掉
    // ```
    //
    // 覆盖 4/9 网格行(屏高 44%,一条视频、一个 banner、一个滚动列表)即可 —— 任何网页都能
    // 按需做到。而这在语义上是错的:一次**真正**的全局重绘(切应用、滚动)会改动**几乎整个**
    // 画面;44% 改动意味着 56% 静止,那不是全局重绘,是"一大块动 + 可能另有一小簇动"。
    //
    // 所以:把变化块按网格 4-邻接切成连通分量。最大的那个分量是"大块变化"(动画/视频/滚动)。
    // **除它之外**任何一个达到 `MIN_LOCALIZED_BLOCKS` 的分量,都是一处与大块**分离**的局部
    // 编辑 —— 报出来,和全局占比无关。用户读字的地方和视频窗口是两个位置,注入落在前者、
    // 动画落在后者,于是是两个分量,抓得到。
    let components = connected_components(&changed);
    if let Some((_, largest_idx)) = components
        .iter()
        .enumerate()
        .map(|(i, c)| (c.len(), i))
        .max()
    {
        let secondary: Vec<usize> = components
            .iter()
            .enumerate()
            .filter(|(i, c)| *i != largest_idx && c.len() >= MIN_LOCALIZED_BLOCKS)
            .flat_map(|(_, c)| c.iter().copied())
            .collect();
        if !secondary.is_empty() {
            let mut blocks = secondary;
            blocks.sort_unstable();
            return DigestDelta::Localized {
                changed: blocks,
                total,
            };
        }
    }

    // 没有分离的次要簇。剩下的是"要么一大块连续变化,要么一个小局部编辑"。
    if total > 0 && changed.len() as f32 / total as f32 > GLOBAL_CHANGE_RATIO {
        // 下结论 GlobalRepaint 之前:减掉全局偏移看残差。攻击者可以给整帧叠一个**均匀**的
        // 亮度/色度偏移,让每块都算"变了"、从而把注入藏进 GlobalRepaint→None。均匀偏移减完
        // 残差≈0,而注入块偏离这个偏移、减完仍在。若残差里剩下一个**小于全局比例**的局部簇,
        // 那就是藏在全局变化下的局部编辑 —— 报 Localized(第七轮复核发现 9)。
        // 一次**真正**的全局重绘(内容各处不同)减完偏移残差仍然铺满整屏,ratio 超阈值,
        // 不会被这里改判;而一次纯均匀偏移(如 app 切到另一个纯色屏)残差≈0、无簇,照旧
        // GlobalRepaint。
        let residual = prev.changed_blocks_residual(next);
        let cluster: Vec<usize> = connected_components(&residual)
            .into_iter()
            .filter(|c| c.len() >= MIN_LOCALIZED_BLOCKS)
            .flatten()
            .collect();
        if !cluster.is_empty() && (cluster.len() as f32 / total as f32) <= GLOBAL_CHANGE_RATIO {
            let mut blocks = cluster;
            blocks.sort_unstable();
            return DigestDelta::Localized {
                changed: blocks,
                total,
            };
        }
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

/// 把变化块索引按 16×9 网格的 4-邻接切成连通分量。
///
/// 只用于 `compare`。块索引是 `row * GRID_COLS + col`。
fn connected_components(changed: &[usize]) -> Vec<Vec<usize>> {
    use std::collections::BTreeSet;
    let set: BTreeSet<usize> = changed.iter().copied().collect();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut out = Vec::new();
    for &start in &set {
        if seen.contains(&start) {
            continue;
        }
        let mut stack = vec![start];
        let mut comp = Vec::new();
        while let Some(b) = stack.pop() {
            if !seen.insert(b) {
                continue;
            }
            comp.push(b);
            let (r, c) = (b / GRID_COLS, b % GRID_COLS);
            let mut neigh = Vec::new();
            if r > 0 {
                neigh.push(b - GRID_COLS);
            }
            if r + 1 < GRID_ROWS {
                neigh.push(b + GRID_COLS);
            }
            if c > 0 {
                neigh.push(b - 1);
            }
            if c + 1 < GRID_COLS {
                neigh.push(b + 1);
            }
            for n in neigh {
                if set.contains(&n) && !seen.contains(&n) {
                    stack.push(n);
                }
            }
        }
        out.push(comp);
    }
    out
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

    /// 注入 + **均匀全局色调偏移**:攻击者给整帧叠一个均匀亮度偏移,让每块都算"变了",
    /// 想把注入藏进 GlobalRepaint→None。减掉全局偏移后注入块仍偏离 → 必须判 Localized
    /// (第七轮复核发现 9)。
    #[test]
    fn 注入叠加均匀全局偏移仍判局部() {
        let base = solid(100);
        let mut tampered = solid(148); // 均匀 +48 全局偏移
        inject_text(&mut tampered, 20, 40, 20, 300); // 注入落在一个横带
        let a = digest_rgba(&base, W, H, false).unwrap();
        let b = digest_rgba(&tampered, W, H, false).unwrap();
        match compare(&a, &b) {
            DigestDelta::Localized { .. } => {}
            other => panic!("注入被均匀全局偏移藏住了,得到 {other:?}"),
        }
    }

    /// 对照:**纯**均匀全局偏移(无注入)不能被误判成局部篡改 —— 它是 GlobalRepaint。
    /// 守住上一条修复的误报侧:减掉偏移后残差≈0、无局部簇,照旧全局重绘。
    #[test]
    fn 纯均匀全局偏移仍是全局重绘() {
        let a = digest_rgba(&solid(100), W, H, false).unwrap();
        let b = digest_rgba(&solid(148), W, H, false).unwrap();
        match compare(&a, &b) {
            DigestDelta::GlobalRepaint { .. } => {}
            other => panic!("纯均匀偏移不该判成局部篡改,得到 {other:?}"),
        }
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

    /// 尺度无关性只对**均值**平面成立,而且只对平坦内容成立。
    ///
    /// 这条测试原来断言 `compare(&small, &large) == Identical`,用的是网格对齐的平坦色带 ——
    /// 点采样唯一能存活的形状。两个问题:
    ///
    /// 1. `detail` 平面按定义不是尺度无关的(同一条 1 像素笔画在 4 倍放大后是 4 像素渐变,
    ///    相邻差降到四分之一、跨不过阈值),所以跨尺度必须走 `changed_blocks_cross_scale`;
    /// 2. 更要紧的是,复核用一页**小号文字**实测原生 1920×1080 与它自己降采样到 640×360 的
    ///    版本:**27/144 块不同**。也就是说跨分辨率可比性对任何有细节的内容本来就不成立,
    ///    只对平坦色块成立 —— 而 `docs/frame-integrity.md` 把它写成了一条无条件的性质,
    ///    于是 `guard-cli frame-digest --expect` 会在一张**诚实的**帧上打印 TAMPERED 并 exit 1。
    ///
    /// 所以这条测试现在断言的是那条**真的**性质:平坦内容 + 均值平面 + 显式的跨尺度入口。
    /// 实时路径不受影响 —— `FrameConsistency::check` 本来就有 `prev.width != stats.width` 的守卫。
    #[test]
    fn 平坦内容的尺度无关性只在均值平面上成立() {
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
        assert!(
            small.changed_blocks_cross_scale(&large).is_empty(),
            "平坦色带在 4 倍尺度差下,均值平面应当一致:{:?}",
            small.changed_blocks_cross_scale(&large)
        );
    }

    /// 跨尺度比较**只**用均值平面 —— 而且这一点必须是显式的。
    ///
    /// `detail` 平面按定义不是尺度无关的(见 `changed_blocks_cross_scale`),所以跨分辨率
    /// 走那个入口。这条测试同时钉住:同一入口在**同**分辨率下仍然要看见细笔画,否则
    /// "跨尺度"会变成一条绕过整个 detail 平面的旁路。
    #[test]
    fn 跨尺度比较只用均值平面() {
        let small = digest_rgba(&solid(120), W, H, false).unwrap();
        let mut big_px = vec![120u8; (W * 4) * (H * 4) * 4];
        // 在放大版本上画一条细线:均值几乎不动,detail 动。
        for x in 0..W * 4 {
            let o = ((H * 2) * (W * 4) + x) * 4;
            big_px[o] = 0;
            big_px[o + 1] = 0;
            big_px[o + 2] = 0;
        }
        let big = digest_rgba(&big_px, W * 4, H * 4, false).unwrap();
        assert!(
            small.changed_blocks_cross_scale(&big).is_empty(),
            "跨尺度比较不应该因为 detail 平面的尺度差而报变化"
        );
        // 同分辨率下,同一条细线必须被看见 —— 否则 detail 平面白加。
        let same_scale_base =
            digest_rgba(&vec![120u8; (W * 4) * (H * 4) * 4], W * 4, H * 4, false).unwrap();
        assert!(
            !same_scale_base.changed_blocks(&big).is_empty(),
            "同分辨率下一条细线没有被看见"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = digest_rgba(&solid(100), W, H, false).unwrap();
        let hex = d.to_hex();
        const PLANES: usize = 4; // luma | cb | cr | detail
        assert_eq!(hex.len(), GRID_COLS * GRID_ROWS * PLANES + (PLANES - 1));
        assert_eq!(FrameDigest::from_hex(&hex), Some(d));
        assert!(FrameDigest::from_hex("garbage").is_none());
        assert!(FrameDigest::from_hex("aa|bb|cc").is_none());
    }

    /// 三平面的旧摘要仍然解析得出,`detail` 视为全 0。
    ///
    /// 一条已经落进签名审计的旧摘要不能因为格式加了一个平面就变成"无法解析" —— 那会把
    /// 一次格式演进变成一次历史不可读。
    #[test]
    fn 三平面的旧摘要仍然可解析() {
        let n = GRID_COLS * GRID_ROWS;
        let old = format!("{}|{}|{}", "8".repeat(n), "8".repeat(n), "8".repeat(n));
        let d = FrameDigest::from_hex(&old).expect("旧格式必须仍然解析得出");
        assert_eq!(d.luma.len(), n);
        assert_eq!(d.detail, vec![0u8; n], "缺失的 detail 平面应当补零");
    }

    /// 采样不能有相位盲区:一条细黑条落在**任何**一行上都必须被看见。
    ///
    /// 上一版每块只取 3×3 = 9 个精确像素点,相邻采样行之间最多有 39 个连续行从不被读。
    /// 复核实测:1920×1080 上一条 39 行高的全宽黑条(74,880 像素)得到 `Identical`;
    /// 而 `scripts/frame-digest-demo.sh` 那个"证明探测器有效"的注入在 1920×1080 和
    /// 3840×2160 上同样静音,只在它自己跑的 320×180 上有效。
    ///
    /// 这条测试遍历一个块内的**每一个**行偏移,任何一个静音就是失败。
    #[test]
    fn 细黑条在任何行偏移上都被看见() {
        // 用一个真实分辨率:1080 高 = 每块 120 行,正好是相位对齐最坏的那一档。
        const RW: usize = 1920;
        const RH: usize = 1080;
        let base = vec![220u8; RW * RH * 4];
        let d0 = digest_rgba(&base, RW, RH, false).unwrap();
        let cell_h = RH / GRID_ROWS;
        let mut silent = Vec::new();
        for off in 0..cell_h {
            let mut f = base.clone();
            // 一条 2 像素高的全宽黑条 —— 一行小字的笔画高度。
            for y in off..(off + 2).min(RH) {
                for x in 0..RW {
                    let o = (y * RW + x) * 4;
                    f[o] = 0;
                    f[o + 1] = 0;
                    f[o + 2] = 0;
                }
            }
            let d1 = digest_rgba(&f, RW, RH, false).unwrap();
            if d0.changed_blocks(&d1).is_empty() {
                silent.push(off);
            }
        }
        assert!(
            silent.is_empty(),
            "{} / {} 个行偏移上一条 2 像素黑条完全静音(相位盲区):{:?}",
            silent.len(),
            cell_h,
            &silent[..silent.len().min(12)]
        );
    }

    /// 大面积覆盖当然也要被看见 —— 复核那个 303,264 像素的例子。
    #[test]
    fn 大面积覆盖被看见() {
        const RW: usize = 1920;
        const RH: usize = 1080;
        let base = vec![235u8; RW * RH * 4];
        let d0 = digest_rgba(&base, RW, RH, false).unwrap();
        let mut f = base.clone();
        // 14.6% 的像素涂黑,分布在一整屏横幅文字的形状上(每 7 行画 2 行)。
        let mut painted = 0usize;
        for y in 0..RH {
            if y % 7 >= 2 {
                continue;
            }
            for x in 0..RW {
                let o = (y * RW + x) * 4;
                f[o] = 0;
                f[o + 1] = 0;
                f[o + 2] = 0;
                painted += 1;
            }
        }
        assert!(
            painted > 300_000,
            "夹具应当涂满 30 万以上像素,实际 {painted}"
        );
        let d1 = digest_rgba(&f, RW, RH, false).unwrap();
        assert!(
            !d0.changed_blocks(&d1).is_empty(),
            "涂满 {painted} 个像素(全帧 {:.1}%)的摘要逐字节相同",
            painted as f32 / (RW * RH) as f32 * 100.0
        );
    }

    /// 行跨距必须被尊重 —— ObjC 那侧的孪生实现有这个参数,Rust 侧以前没有。
    #[test]
    fn 行跨距被尊重() {
        // 1000×600,行按 64 字节对齐 => 4032 而不是 4000。
        const W2: usize = 1000;
        const H2: usize = 600;
        const STRIDE: usize = 4032;
        let mut padded = vec![0u8; STRIDE * H2];
        let mut packed = vec![0u8; W2 * H2 * 4];
        for y in 0..H2 {
            for x in 0..W2 {
                let v = ((x / 37 + y / 41) % 2) as u8 * 200 + 20;
                for (buf, stride) in [(&mut padded, STRIDE), (&mut packed, W2 * 4)] {
                    let o = y * stride + x * 4;
                    buf[o] = v;
                    buf[o + 1] = v;
                    buf[o + 2] = v;
                    buf[o + 3] = 255;
                }
            }
        }
        let a = digest_rgba_stride(&padded, W2, H2, STRIDE, false).unwrap();
        let b = digest_rgba_stride(&packed, W2, H2, W2 * 4, false).unwrap();
        assert_eq!(
            a.to_hex(),
            b.to_hex(),
            "同一幅画面在带填充与紧凑布局下摘要不同 —— 跨距没有被尊重"
        );
        // 而按紧凑读一个带填充的缓冲必须**不**等于正确结果,否则这条测试没有意义。
        let wrong = digest_rgba(&padded, W2, H2, false).unwrap();
        assert_ne!(
            wrong.to_hex(),
            a.to_hex(),
            "夹具没有真的产生跨距差异,这条测试证明不了什么"
        );
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

#[cfg(test)]
mod b6_采样结构复核 {
    use super::*;

    /// 项目自己的演示注入,必须在**每一个**常见分辨率上都被看见。
    ///
    /// `scripts/frame-digest-demo.sh` 那个注入被 `docs/frame-integrity.md` 当作"证明新探测器
    /// 能看见旧的看不见的东西"。复核把它按比例放到七个分辨率:
    ///
    /// ```text
    ///      320x180   changed=14  tamper      <- demo 自己跑的尺寸
    ///      640x360   changed=14  tamper
    ///     1280x720   changed=14  tamper
    ///     1440x900   changed=14  tamper
    ///    1920x1080   changed= 0  SILENT      <- 最常见的桌面分辨率
    ///    2560x1440   changed=14  tamper
    ///    3840x2160   changed= 0  SILENT
    /// ```
    ///
    /// 静音的两档不是巧合:采样行是 `gy*(h/9) + {0, (h/9)/3, 2(h/9)/3}`,h=1080 时全部
    /// ≡ 0 (mod 40),h=2160 时 ≡ 0 (mod 80),而笔画节距为 4 行时每个采样点都落在同一相位的
    /// 空隙行上。也就是探测器在它自己的演示尺寸上有效,在用户的屏幕上无效。
    #[test]
    fn 演示注入在每个常见分辨率上都被看见() {
        // 复刻 demo 的注入形状:节距 4 行的笔画(2 行画、2 行空),横跨画面中部。
        fn inject(w: usize, h: usize) -> (Vec<u8>, Vec<u8>) {
            let base = vec![235u8; w * h * 4];
            let mut t = base.clone();
            let y0 = h / 3;
            let rows = (h / 12).max(8);
            for k in 0..rows {
                let y = y0 + k * 4;
                if y + 1 >= h {
                    break;
                }
                for dy in 0..2 {
                    for x in (w / 8)..(w * 7 / 8) {
                        let o = ((y + dy) * w + x) * 4;
                        t[o] = 30;
                        t[o + 1] = 30;
                        t[o + 2] = 30;
                    }
                }
            }
            (base, t)
        }
        let mut silent = Vec::new();
        for (w, h) in [
            (320usize, 180usize),
            (640, 360),
            (1280, 720),
            (1440, 900),
            (1920, 1080),
            (2560, 1440),
            (3840, 2160),
        ] {
            let (base, tampered) = inject(w, h);
            let a = digest_rgba(&base, w, h, false).unwrap();
            let b = digest_rgba(&tampered, w, h, false).unwrap();
            if a.changed_blocks(&b).is_empty() {
                silent.push(format!("{w}x{h}"));
            }
        }
        assert!(
            silent.is_empty(),
            "演示注入在这些分辨率上完全静音:{silent:?} —— 探测器只在它自己的演示尺寸上有效"
        );
    }

    /// 编码噪声不能让整帧报变化 —— 这一条是 detail 平面设计的另一端。
    ///
    /// 第一版用"边缘能量均值",而 ±2/255 的编码噪声与一条 2 像素笔画在这个统计量上是同一
    /// 量级(0.0050 vs 0.0072),于是任何倍数要么漏掉信号、要么让 144 块全报变化。换成
    /// "跨过阈值的边缘个数"之后两者相差约 30 倍。
    #[test]
    fn 编码噪声不产生变化() {
        const RW: usize = 1920;
        const RH: usize = 1080;
        let base = vec![200u8; RW * RH * 4];
        let mut noisy = base.clone();
        let mut st = 12345u64;
        for px in noisy.chunks_exact_mut(4) {
            st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
            let n = ((st >> 33) % 5) as i32 - 2; // ±2
            for c in px.iter_mut().take(3) {
                *c = (*c as i32 + n).clamp(0, 255) as u8;
            }
        }
        let a = digest_rgba(&base, RW, RH, false).unwrap();
        let b = digest_rgba(&noisy, RW, RH, false).unwrap();
        let changed = a.changed_blocks(&b);
        assert!(
            changed.is_empty(),
            "±2/255 的编码噪声让 {} / {} 块报变化",
            changed.len(),
            a.blocks()
        );
    }

    /// 平滑渐变不能被当成变化 —— 这是复核在 stego 那边找到的同类误报,在这里预先钉住。
    #[test]
    fn 平滑渐变不产生变化() {
        const RW: usize = 1600;
        const RH: usize = 900;
        let mut a_px = vec![0u8; RW * RH * 4];
        let mut b_px = vec![0u8; RW * RH * 4];
        for y in 0..RH {
            for x in 0..RW {
                let v = ((x * 255) / RW) as u8;
                for (buf, shift) in [(&mut a_px, 0u8), (&mut b_px, 1u8)] {
                    let o = (y * RW + x) * 4;
                    // b 比 a 整体亮 1 —— 一次重编码级别的差异。
                    let w = v.saturating_add(shift);
                    buf[o] = w;
                    buf[o + 1] = w;
                    buf[o + 2] = w;
                    buf[o + 3] = 255;
                }
            }
        }
        let a = digest_rgba(&a_px, RW, RH, false).unwrap();
        let b = digest_rgba(&b_px, RW, RH, false).unwrap();
        assert!(
            a.changed_blocks(&b).is_empty(),
            "平滑渐变差 1 级灰度就报变化:{:?}",
            a.changed_blocks(&b)
        );
    }

    /// 采样代价仍然是一次线性 pass 的量级,而且随像素数**线性**增长。
    ///
    /// 从"每块 9 点"变成"全帧扫描"确实提高了成本 —— 这跑在无障碍热路径上,所以要量。
    /// release 构建下 1080p 单帧约 5ms(2 FPS 采集的预算是 500ms),debug 下约 56ms;
    /// 这条测试只在 release 下断言绝对上限,两种构建下都断言"4 倍像素 → 不超过 6 倍时间",
    /// 也就是要抓的是**意外变成二次**,不是常数因子。
    #[test]
    fn 全帧扫描仍然够快() {
        const RW: usize = 1920;
        const RH: usize = 1080;
        let time_one = |w: usize, h: usize| {
            let px = vec![180u8; w * h * 4];
            let t = std::time::Instant::now();
            for _ in 0..3 {
                let _ = digest_rgba(&px, w, h, false).unwrap();
            }
            t.elapsed() / 3
        };
        let small = time_one(RW / 2, RH / 2);
        let full = time_one(RW, RH);
        // 4 倍像素 -> 不超过 6 倍时间。二次增长会是 16 倍。
        assert!(
            full.as_nanos() <= small.as_nanos().saturating_mul(6).max(1_000_000),
            "540p {small:?} -> 1080p {full:?}:像素翻 4 倍而时间超过 6 倍,增长不是线性的"
        );
        #[cfg(not(debug_assertions))]
        assert!(
            full < std::time::Duration::from_millis(30),
            "release 下 1080p 单帧摘要耗时 {full:?}"
        );
    }
}

#[cfg(test)]
mod b6_跨语言摘要向量 {
    use super::*;

    /// 摘要的跨语言向量,以及为什么这个文件必须存在。
    ///
    /// `docs/frame-integrity.md` 要求 Rust 的 `digest_rgba` 与 `AgentGuardSCK.m` 的
    /// `ag_frame_digest` **逐字节一致**。仓库里**没有任何测试钉住这一点** —— 对比 icon dHash
    /// 有 `eval/fixtures/icon_dhash_vectors.json`、OCR 常量有一条会去 grep `.m` 的测试。
    ///
    /// 而这一轮把 Rust 侧改了(块内全扫 + 第四个平面 + 尊重行跨距),ObjC 侧**没动** ——
    /// 因为改它需要 macOS 和 Xcode 来编译和验证,这个环境里做不到。所以现在两侧确定不一致:
    /// ObjC 发的是三平面、9 点采样。
    ///
    /// 这条测试做两件事:
    ///
    /// 1. 把 Rust 侧的输出**钉住**,这样它不会在无人注意时再漂一次;
    /// 2. 把向量写进 `eval/fixtures/frame_digest_vectors.json`,给移植 ObjC 那一侧的人一个
    ///    明确的目标 —— 移植完成之后,同一份向量应当由一条编译 `.m` 的测试消费。
    ///
    /// 在那之前,`FrameDigest::has_detail` 让运行时能认出三平面摘要,而 `FrameConsistency`
    /// 会把这个事实写进证据字符串。
    #[test]
    fn 摘要向量与已记录的值一致() {
        // 三个确定性的合成帧,覆盖三种形状。
        let cases: Vec<(&str, usize, usize, Vec<u8>)> = vec![
            ("solid_200", 320, 180, vec![200u8; 320 * 180 * 4]),
            ("bands", 320, 180, {
                let mut b = vec![210u8; 320 * 180 * 4];
                for y in 45..90 {
                    for x in 0..320 {
                        let o = (y * 320 + x) * 4;
                        b[o] = 20;
                        b[o + 1] = 20;
                        b[o + 2] = 20;
                    }
                }
                b
            }),
            ("thin_stripes", 320, 180, {
                let mut b = vec![235u8; 320 * 180 * 4];
                for y in (0..180).step_by(4) {
                    for x in 40..280 {
                        let o = (y * 320 + x) * 4;
                        b[o] = 30;
                        b[o + 1] = 30;
                        b[o + 2] = 30;
                    }
                }
                b
            }),
        ];

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../eval/fixtures/frame_digest_vectors.json");
        let mut lines = Vec::new();
        for (name, w, h, px) in &cases {
            let d = digest_rgba(px, *w, *h, false).expect("digest");
            assert!(d.has_detail, "本实现产出的摘要必须带细节平面");
            lines.push(format!(
                "    {{\"name\": \"{name}\", \"width\": {w}, \"height\": {h}, \"bgra\": false, \"digest\": \"{}\"}}",
                d.to_hex()
            ));
        }
        let doc = format!(
            "{{\n  \"note\": \"Rust digest_rgba 的输出。移植 AgentGuardSCK.m 的 ag_frame_digest 之后,那一侧必须逐字节复现这些值。见 crates/guard-vision/src/framehash.rs::b6_跨语言摘要向量。\",\n  \"planes\": \"luma|cb|cr|detail\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
            lines.join(",\n")
        );

        match std::fs::read_to_string(&path) {
            Ok(existing) if existing == doc => {}
            Ok(_) => panic!(
                "摘要输出与 {} 里记录的向量不一致。\n\
                 如果这是一次**有意**的算法改动,更新那个文件,并且**同时**移植 \
                 AgentGuardSCK.m 的 ag_frame_digest —— 否则 macOS 采集路径会与 Rust 侧分家。\n\
                 当前输出:\n{doc}",
                path.display()
            ),
            Err(_) => {
                // 首次生成。
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&path, &doc).expect("写向量文件");
            }
        }
    }
}

#[cfg(test)]
mod b6_全屏动画不能关掉局部探测 {
    use super::*;

    // 直接在块索引上构造 digest delta,不必渲染像素 —— 我们要测的是 `compare` 的分簇逻辑。
    fn digest_from_changed(changed: &[usize]) -> (FrameDigest, FrameDigest) {
        let n = GRID_COLS * GRID_ROWS;
        let a = FrameDigest {
            luma: vec![8u8; n],
            cb: vec![8u8; n],
            cr: vec![8u8; n],
            detail: vec![0u8; n],
            has_detail: true,
        };
        let mut b = a.clone();
        for &i in changed {
            b.luma[i] = 0; // 远超 BLOCK_CHANGE_LEVELS
        }
        (a, b)
    }

    /// 一段全屏动画不能把与它**分离**的注入一起吞掉。
    ///
    /// 复核实测(修复前):覆盖 4/9 网格行 = 64 块(44%),`compare` 返回 GlobalRepaint,
    /// `FrameConsistency` 映射成 None,同时注入的 2 块被一起吞掉。
    #[test]
    fn 动画加分离注入仍报局部() {
        // 动画:前 4 行(0..64),连续一大块。
        let mut changed: Vec<usize> = (0..4 * GRID_COLS).collect();
        // 注入:第 8 行第 2、3 列 —— 与动画分离的一小簇。
        let inj = [8 * GRID_COLS + 2, 8 * GRID_COLS + 3];
        changed.extend_from_slice(&inj);

        let (a, b) = digest_from_changed(&changed);
        match compare(&a, &b) {
            DigestDelta::Localized {
                changed: blocks, ..
            } => {
                // 报的应当是**注入那一簇**,不是整块动画。
                assert!(
                    inj.iter().all(|i| blocks.contains(i)),
                    "注入块没有被报出来:{blocks:?}"
                );
                assert!(
                    blocks.len() < 10,
                    "报出来的块太多,说明把动画也算进去了:{}",
                    blocks.len()
                );
            }
            other => panic!("动画 + 分离注入应当报 Localized,得到 {other:?}"),
        }
    }

    /// 反面:一整块真正的全屏重绘(几乎所有块都变)仍然是 GlobalRepaint,不误报。
    #[test]
    fn 真正的全屏重绘不误报() {
        let changed: Vec<usize> = (0..GRID_COLS * GRID_ROWS).collect(); // 全变
        let (a, b) = digest_from_changed(&changed);
        assert!(
            matches!(compare(&a, &b), DigestDelta::GlobalRepaint { .. }),
            "整帧改变应当是 GlobalRepaint"
        );
    }

    /// 反面:一大块连续动画、**没有**分离注入,仍然是 GlobalRepaint(是视频,不是篡改)。
    #[test]
    fn 纯动画没有注入仍是全局重绘() {
        let changed: Vec<usize> = (0..5 * GRID_COLS).collect(); // 前 5 行连续,56%
        let (a, b) = digest_from_changed(&changed);
        assert!(
            matches!(compare(&a, &b), DigestDelta::GlobalRepaint { .. }),
            "一大块连续动画没有分离簇时应当是 GlobalRepaint"
        );
    }

    /// 两处分离的注入,即使总数很小,也都要被报出来。
    #[test]
    fn 两处分离注入都被报() {
        let changed = vec![
            0,
            1, // 左上角一簇
            8 * GRID_COLS + 14,
            8 * GRID_COLS + 15, // 右下角一簇
        ];
        let (a, b) = digest_from_changed(&changed);
        match compare(&a, &b) {
            DigestDelta::Localized {
                changed: blocks, ..
            } => {
                // 最大分量之外的另一簇必须出现。这里两簇同大,任一被当作"最大",另一必被报。
                assert!(blocks.len() >= 2, "至少一簇应当被报:{blocks:?}");
            }
            other => panic!("两处分离注入应当报 Localized,得到 {other:?}"),
        }
    }
}
