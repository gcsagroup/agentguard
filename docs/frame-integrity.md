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

- **分辨率无关 —— 只对均值平面,而且只对平坦内容。** 这一条原来写的是"守卫的 640×360
  采集和一张全分辨率截图产生可比的摘要,已在 4 倍尺度差下验证"。**那是假的。** 那条验证
  用的是网格对齐的平坦色带 —— 点采样唯一能存活的形状。一次独立复核用一页小号深色文字
  实测原生 1920×1080 与它自己降采样到 640×360:**27/144 块不同**,于是
  `guard-cli frame-digest --expect` 会在一张**诚实的**帧上打印
  `TAMPERED (localized): 27/144 blocks differ` 并 exit 1。

  现在跨分辨率比较必须显式走 `changed_blocks_cross_scale`(只用亮度/Cb/Cr 三个**均值**
  平面),而且这条性质只对平坦内容成立。`detail` 平面按定义不是尺度无关的 —— 同一条 1 像素
  笔画在 4 倍放大后是一段 4 像素渐变,相邻像素差降到四分之一、跨不过边缘阈值。
  **实时路径不受影响**:`FrameConsistency::check` 本来就有 `prev.width != stats.width`
  的守卫,所以这一条只打中那条文档化的事后核验流程。
- **Quantised.** 4 bits per channel per block, so re-encoding noise and sub-quantum
  drift do not flip a block. A cryptographic hash of raw pixels would be perfectly
  sensitive and perfectly useless — a blinking cursor would change it.
- **含色度,但摘要这一路对细微色度改动迟钝。** 已发表的 A4 变体在保持亮度的前提下嵌入
  Cb/Cr,所以只看亮度的摘要按构造是瞎的 —— 这一句仍然成立。但 4 bit 量化加 2 级容差之后,
  这个摘要对**细微**的色度改动同样迟钝:一次保亮度的 B+80 / R−31(肉眼明显偏蓝的区域)
  都不算块变化,而复核用本 crate 自己的 A4 fixture 实测摘要判决为 `Identical`。

  真正抓这类载荷的是 `stego::chroma_lsb_flip_rate`(判据是"色度有边缘而亮度没有"),
  摘要这一路是纵深而不是主防线。原来那句"a luma-only digest is blind to it by
  construction"读起来像"所以这个摘要不瞎",而它在这个量级上也是瞎的。
- **采样:块内全部像素,不是 9 个点。** 上一版每块取 3×3 = 9 个精确像素点 —— 1920×1080 上
  整帧只读 1296 个像素(0.0625%)。复核在浅色帧上涂满 303,264 个纯黑像素(全帧 14.6%),
  摘要**逐字节相同**;而 `scripts/frame-digest-demo.sh` 那个被本文档当作"证明新探测器有效"
  的注入,在 1920×1080 和 3840×2160 上**完全静音**(采样行的相位与字形笔画节距对齐)。
  详见 `framehash.rs` 顶部的长注释,包括为什么单靠块均值也不够、以及 `detail` 平面为什么
  记的是跨阈边缘**个数**而不是边缘**能量**。

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

---

## 一条我修不了的:macOS 采集路径上的摘要不是这个实现算的

`AgentGuardSCK.m` 里有一个手写的孪生实现 `ag_frame_digest`,macOS 上的 `frame_digest`
字符串**由它**算出来、跨 FFI 传进 Rust。本文档要求两侧"必须逐字节一致",而仓库里
**没有任何测试钉住这一点**(对比 icon dHash 有向量 fixture、OCR 常量有一条会去 grep `.m`
的测试)。

第六轮把 Rust 侧改了三处:块内全扫代替 9 点采样、新增 `detail` 平面、尊重行跨距。
**ObjC 侧没有动** —— 改它需要 macOS 和 Xcode 来编译和验证,而那不在这个环境的能力范围内。
所以现在的真实状态是:

| 路径 | 摘要来自 | 相位盲区 | 细节平面 |
|---|---|---|---|
| macOS(ScreenCaptureKit) | `AgentGuardSCK.m`,9 点采样,3 平面 | **仍然存在** | 无 |
| `guard-cli frame-digest`、模拟、测试 | Rust `digest_rgba`,全扫,4 平面 | 已修 | 有 |

也就是说 1920×1080 与 3840×2160 上那个"本项目自己的 A4 样本完全静音"的问题,**在 macOS
上依然存在**。

### 在移植完成之前留下了什么

1. **`FrameDigest::has_detail`** —— 三平面摘要能被认出来,不会被当成"detail 恰好全为 0"的
   四平面摘要。两个都来自 ObjC 的摘要相互比较不会误报,而那正是危险的地方:一切看起来正常
   而这一路没有信息。
2. **`FrameConsistency` 的证据字符串**会写明"摘要来自没有细节平面的实现(macOS ObjC 孪生),
   细笔画注入在这条路上检测不到"。运维读到的"未检出篡改"因此含义不同,必须让他们看得见。
3. **`eval/fixtures/frame_digest_vectors.json`** —— Rust 侧对三个确定性合成帧的输出。
   移植 ObjC 那一侧之后,同一份向量应当由一条编译 `.m` 的测试消费;在那之前它至少把 Rust
   侧钉住,不会再无人注意地漂一次。

### 移植时要注意的四点

* 行方向**每一行**都要读(不是按步长跳),这是相位无关性的来源;
* 垂直梯度要跨过块的**上**边界(用 `y0-1` 那一行做种子),否则块边界上的笔画只剩一次跳变、
  掉到容差以下;
* `detail` 是**跨过 `EDGE_THRESHOLD` 的边缘对个数**占比,再过 `sqrt(x * DETAIL_SCALE)`
  —— 不是边缘能量的均值(那个统计量和编码噪声同量级,试过,144 块全报变化);
* `detail` 的容差是 `DETAIL_CHANGE_LEVELS = 1`,比亮度那一档紧。
