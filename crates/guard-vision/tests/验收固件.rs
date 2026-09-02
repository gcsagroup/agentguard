//! 真机验收固件(scripts/acceptance/make-fixtures.py)必须**真的会触发**它声称的规则。
//!
//! Windows 补充报告(2026-09-02)把 W3/W4/W5 记为"未按规定场景执行"——验收者手里没有已知会触发
//! 的素材。固件脚本补上了素材;这条测试补上的是**素材与探测器之间的契约**:每次 `cargo test`
//! 都真的跑脚本、真的把 PNG 逐字节读回、真的过 `stats_from_pixels` + `analyze_frame`,断言:
//!
//!   * `w3-stego-luma.png`      → StegoHint(OVL-008),且**不**误报色度;
//!   * `w3-stego-chroma.png`    → ChromaStegoHint(OVL-011),且**不**误报亮度(保亮度载荷的定义);
//!   * `w5-self-drawn-overlay.png` → SubliminalText(OVL-006),且无隐写误报;
//!   * `w3-control-clean.png`   → **零** finding —— 对照图。没有它,"固件会触发"和"这个探测器逢图必报"
//!     在输出上不可区分;
//!   * `w4-pixel-only-payment.html` 里 canvas 画的那几行,当作 OCR 结果、DOM 文案当作 UIA 树,
//!     `cross_validate` 报 ScreenTextNotInTree(OVL-009)。真机上 OCR 是 Windows.Media.Ocr,这里
//!     验的是"假如 OCR 把它读出来了,规则这一侧会响"。OCR 本身读不读得出仍是真机 W4 的事。
//!
//! PNG 解码器是这里自己的 60 行:固件用 zlib **存储块**(level 0)+ 过滤器 0 写出,所以不需要
//! inflate 依赖。它只认这种形状——这是刻意的:固件格式是仓库自己定的,别的 PNG 不归它管。
//!
//! 需要 `python3`(Makefile 的 dashboard 目标早已依赖它)。没有就**失败**并说明,不静默跳过——
//! 一条跳过的验收契约和没有这条契约看起来一样绿。

use std::path::{Path, PathBuf};
use std::process::Command;

use guard_overlay::OverlayKind;
use guard_vision::frame::analyze_frame;
use guard_vision::{stats_from_pixels, AlphaChannel};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap()
}

/// 跑一次脚本,固件落到临时目录。1280×720 是脚本默认;这里用小一号(640×360)让测试快,
/// 探测器的判据都是比例、与尺寸无关(脚本的字号/行距也按高度缩放)。
/// `AGENTGUARD_FIXTURE_SIZE=1280x720 cargo test …` 可以按真机默认尺寸复核一遍。
fn generate(dir: &Path) {
    let script = repo_root().join("scripts/acceptance/make-fixtures.py");
    let out = Command::new("python3")
        .arg(&script)
        .arg("--out")
        .arg(dir)
        .arg("--size")
        .arg(std::env::var("AGENTGUARD_FIXTURE_SIZE").unwrap_or_else(|_| "640x360".into()))
        .output()
        .expect("python3 不可用:验收固件脚本需要它(Makefile 的 dashboard 目标同样依赖 python3)");
    assert!(
        out.status.success(),
        "make-fixtures.py 失败:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// 最小 PNG 读回:签名 → 块 → IHDR(8-bit RGBA,非交错)→ IDAT 拼接 → zlib 存储块 → 每行去掉
// 过滤器字节(必须是 0)。校验 CRC 与 Adler-32:证明写出的是**合法** PNG,不只是我们自己读得懂。
// ---------------------------------------------------------------------------
struct Png {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// zlib 流,只接受存储块(BTYPE=00)。
fn inflate_stored(z: &[u8]) -> Vec<u8> {
    assert!(z.len() >= 6, "zlib stream too short");
    assert_eq!(z[0] & 0x0F, 8, "zlib CM must be deflate");
    assert_eq!(
        (z[0] as u16 * 256 + z[1] as u16) % 31,
        0,
        "zlib header check"
    );
    let mut i = 2;
    let mut out = Vec::new();
    loop {
        let hdr = z[i];
        i += 1;
        let bfinal = hdr & 1;
        let btype = (hdr >> 1) & 3;
        assert_eq!(
            btype, 0,
            "固件 PNG 必须用存储块(zlib level 0);见 make-fixtures.py"
        );
        let len = u16::from_le_bytes([z[i], z[i + 1]]) as usize;
        let nlen = u16::from_le_bytes([z[i + 2], z[i + 3]]) as usize;
        assert_eq!(len, !nlen & 0xFFFF, "stored block LEN/NLEN mismatch");
        i += 4;
        out.extend_from_slice(&z[i..i + len]);
        i += len;
        if bfinal == 1 {
            break;
        }
    }
    let adler = be32(&z[i..i + 4]);
    assert_eq!(adler, adler32(&out), "zlib Adler-32 mismatch");
    out
}

fn read_png(path: &Path) -> Png {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "PNG signature");
    let mut i = 8;
    let (mut width, mut height) = (0u32, 0u32);
    let mut idat = Vec::new();
    let mut saw_iend = false;
    while i + 12 <= bytes.len() {
        let len = be32(&bytes[i..]) as usize;
        let tag = &bytes[i + 4..i + 8];
        let body = &bytes[i + 8..i + 8 + len];
        let crc = be32(&bytes[i + 8 + len..]);
        assert_eq!(
            crc,
            crc32(&bytes[i + 4..i + 8 + len]),
            "chunk CRC ({})",
            String::from_utf8_lossy(tag)
        );
        match tag {
            b"IHDR" => {
                width = be32(&body[0..]);
                height = be32(&body[4..]);
                assert_eq!(body[8], 8, "bit depth 8");
                assert_eq!(body[9], 6, "color type RGBA");
                assert_eq!(body[12], 0, "non-interlaced");
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => saw_iend = true,
            _ => {}
        }
        i += 12 + len;
    }
    assert!(saw_iend, "IEND missing");
    let raw = inflate_stored(&idat);
    let stride = width as usize * 4;
    assert_eq!(
        raw.len(),
        (stride + 1) * height as usize,
        "raw scanline size"
    );
    let mut rgba = Vec::with_capacity(stride * height as usize);
    for row in raw.chunks_exact(stride + 1) {
        assert_eq!(row[0], 0, "filter type must be 0 (None)");
        rgba.extend_from_slice(&row[1..]);
    }
    Png {
        width,
        height,
        rgba,
    }
}

/// GDI/CoreGraphics 路径:BGRA、alpha 是填充。固件是 RGBA,所以 bgra=false;alpha 用 Padding
/// 模拟真机(GDI 抓的第四字节没有意义)——像素探测器的结论不依赖 alpha。
fn kinds_of(png: &Png) -> Vec<OverlayKind> {
    let stats = stats_from_pixels(
        &png.rgba,
        png.width,
        png.height,
        1_000,
        false,
        AlphaChannel::Padding,
    );
    // `--nocapture` 时能看到每张图的原始指标与阈值的距离(贴线的固件是坏固件)。
    eprintln!(
        "  {}x{} luma_lsb={:.3} chroma_lsb={:.3} (thr {:.2})  subliminal={:.3} (thr {:.2}) wide={:.3}",
        png.width,
        png.height,
        stats.lsb_flip_rate,
        stats.chroma_lsb_flip_rate,
        guard_vision::stego::STEGO_FLIP_THRESHOLD,
        stats.subliminal_ratio,
        guard_vision::subliminal::SUSPICION_THRESHOLD,
        stats.subliminal_ratio_wide
    );
    analyze_frame(&stats)
        .findings
        .into_iter()
        .map(|f| f.kind)
        .collect()
}

#[test]
fn 固件触发其声称的规则_对照图零finding() {
    let dir = tempfile::tempdir().unwrap();
    generate(dir.path());

    let control = read_png(&dir.path().join("w3-control-clean.png"));
    assert!(control.width >= 320 && control.height >= 180);
    let k = kinds_of(&control);
    assert!(k.is_empty(), "对照图不该有任何 finding,得到 {k:?}");

    let luma = read_png(&dir.path().join("w3-stego-luma.png"));
    let k = kinds_of(&luma);
    assert!(
        k.contains(&OverlayKind::StegoHint),
        "W3 亮度隐写应报 StegoHint,得到 {k:?}"
    );
    assert!(
        !k.contains(&OverlayKind::ChromaStegoHint),
        "绿通道 ±1 会动亮度,不该被当成保亮度色度载荷:{k:?}"
    );
    assert!(
        !k.contains(&OverlayKind::SubliminalText),
        "LSB 噪声不是阈下文字:{k:?}"
    );

    let chroma = read_png(&dir.path().join("w3-stego-chroma.png"));
    let k = kinds_of(&chroma);
    assert!(
        k.contains(&OverlayKind::ChromaStegoHint),
        "W3 色度隐写应报 ChromaStegoHint,得到 {k:?}"
    );
    assert!(
        !k.contains(&OverlayKind::StegoHint),
        "保亮度载荷不动绿通道 LSB,亮度那一路应保持安静:{k:?}"
    );

    let sub = read_png(&dir.path().join("w5-self-drawn-overlay.png"));
    let k = kinds_of(&sub);
    assert!(
        k.contains(&OverlayKind::SubliminalText),
        "W5 自绘 3% 覆盖应报 SubliminalText,得到 {k:?}"
    );
    assert!(
        !k.contains(&OverlayKind::StegoHint) && !k.contains(&OverlayKind::ChromaStegoHint),
        "阈下文字不是隐写:{k:?}"
    );

    // 同一份 MANIFEST 记录了 sha256:固件是确定性的——同尺寸再生成一次,字节相同。
    let m1 = std::fs::read_to_string(dir.path().join("MANIFEST.json")).unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    generate(dir2.path());
    let m2 = std::fs::read_to_string(dir2.path().join("MANIFEST.json")).unwrap();
    assert_eq!(m1, m2, "固件必须逐字节确定(报告引用的 sha256 才有意义)");
}

/// W4:canvas 上的付款文本当 OCR 结果、DOM 文案当 UIA 树 → OVL-009。
#[test]
fn w4固件的像素文本对树文本触发_ovl009() {
    let dir = tempfile::tempdir().unwrap();
    generate(dir.path());
    let html = std::fs::read_to_string(dir.path().join("w4-pixel-only-payment.html")).unwrap();
    // 从固件里抠出两份文本,而不是在测试里再抄一遍——抄一遍就成了"测试和自己一致"。
    let lines_start = html.find("const lines = ").expect("canvas lines") + "const lines = ".len();
    let lines_end = html[lines_start..].find(";\n").unwrap() + lines_start;
    let lines: Vec<String> = serde_json::from_str(&html[lines_start..lines_end]).unwrap();
    assert!(lines.len() >= 3);
    let note_start = html.find("<div id=\"note\">").unwrap() + "<div id=\"note\">".len();
    let note_end = html[note_start..].find("</div>").unwrap() + note_start;
    let dom_text = &html[note_start..note_end];
    for l in &lines {
        assert!(
            !html
                .replace(&html[lines_start..lines_end], "")
                .contains(l.as_str()),
            "付款文本 {l:?} 不能出现在 DOM 里,否则 UIA 就看得见"
        );
    }
    // 屏幕 = OCR 读到的一切(DOM 那一行 + canvas 几行);树 = 只有 DOM 那一行。
    let mut screen: Vec<&str> = vec![dom_text];
    screen.extend(lines.iter().map(String::as_str));
    let ocr = guard_vision::ocr::join_lines(screen).unwrap();
    let findings = guard_vision::viewtree::cross_validate(dom_text, &ocr);
    let kinds: Vec<OverlayKind> = findings.iter().map(|f| f.kind).collect();
    assert!(
        kinds.contains(&OverlayKind::ScreenTextNotInTree),
        "W4 应报 ScreenTextNotInTree(OVL-009),得到 {kinds:?}"
    );
    assert!(
        !kinds.contains(&OverlayKind::TreeTextNotOnScreen),
        "树里的都在屏幕上,不该反向报:{kinds:?}"
    );
}

/// HTML 固件经 Chromium **真渲染**后的像素也要触发(scripts/acceptance/render-fixtures.mjs 的产物)。
///
/// 默认 ignore:它需要 Playwright 渲染出来的截图,最小容器里没有。`make acceptance-fixtures` 生成 +
/// 渲染 + 用 `--ignored 渲染` 跑这一条。ignore 的理由字符串会被 cargo 打印出来 —— 这是可见的跳过,
/// 不是静默的。
///
/// 第一版 W5 页面(44px 粗体)在这里得到 subliminal=0.000:大字只有边缘有小台阶。改成 16px 常规
/// 段落后 0.49 @720p / 0.69 @1080p。没有这条,那个错会一直活到真机上,然后被记成探测器的锅。
#[test]
#[ignore = "needs Chromium-rendered fixtures: make acceptance-fixtures (sets AGENTGUARD_RENDERED_FIXTURES)"]
fn 渲染后的html固件触发其声称的规则() {
    let dir = PathBuf::from(std::env::var("AGENTGUARD_RENDERED_FIXTURES").expect(
        "AGENTGUARD_RENDERED_FIXTURES=<dir> (node scripts/acceptance/render-fixtures.mjs)",
    ));
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".png") {
            continue;
        }
        eprintln!("{name}");
        let k = kinds_of(&read_png(&p));
        if name.starts_with("w5-overlay-") {
            assert!(
                k.contains(&OverlayKind::SubliminalText),
                "{name}: 自绘 3% 覆盖渲染后应报 SubliminalText,得到 {k:?}"
            );
            assert!(
                !k.contains(&OverlayKind::StegoHint) && !k.contains(&OverlayKind::ChromaStegoHint),
                "{name}: 反锯齿文字不是隐写:{k:?}"
            );
        } else if name.starts_with("w5-control-") {
            assert!(
                k.is_empty(),
                "{name}: 去掉覆盖的对照页不该有 finding,得到 {k:?}"
            );
        } else if name.starts_with("w4-canvas-") {
            assert!(
                k.is_empty(),
                "{name}: W4 的判据在 OCR 交叉校验,像素探测器应保持安静,得到 {k:?}"
            );
        } else {
            panic!("unexpected rendered fixture {name}");
        }
        seen += 1;
    }
    assert!(
        seen >= 6,
        "expected ≥6 rendered shots (2 viewports × overlay/control/w4), saw {seen}"
    );
}
