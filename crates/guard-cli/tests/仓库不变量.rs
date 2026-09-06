//! 仓库级不变量:那些不属于任何一个 crate、但一旦回退就没人会发现的东西。
//!
//! 为什么放在 `cargo test` 里而不是一个 shell 脚本里:`make check-shells` 只跑
//! `node --check`,也就是只验语法。一个语法完全正确的 `innerHTML = \`...\`` 它一句
//! 话都不会说。而这几条恰恰都是"语法没问题、语义是洞"的形状。

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()))
}

/// 读取 PNG 的 IHDR。这里不需要引入图像解码依赖，只盯住品牌资产最容易回退的
/// 三件事：像素尺寸、8 位色深，以及是否带 Alpha 通道。
fn png_信息(rel: &str) -> (u32, u32, u8, u8) {
    let p = root().join(rel);
    let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()));
    assert!(bytes.len() >= 26, "{} 不是完整 PNG", p.display());
    assert_eq!(
        &bytes[..8],
        b"\x89PNG\r\n\x1a\n",
        "{} 不是 PNG",
        p.display()
    );
    assert_eq!(&bytes[12..16], b"IHDR", "{} 缺少首个 IHDR", p.display());
    let width = u32::from_be_bytes(bytes[16..20].try_into().expect("PNG 宽度字段"));
    let height = u32::from_be_bytes(bytes[20..24].try_into().expect("PNG 高度字段"));
    (width, height, bytes[24], bytes[25])
}

/// 剥掉行内注释,但**不要**被字符串里的 `//` 骗到。
///
/// 上一版是 `line.split("//").next()`,于是
/// `const doc = "https://…"; el.innerHTML = x;` 里那个 `//` 把整行切掉,
/// sink 检测直接失效。一次独立复核用这一条打穿了它。
fn 去掉行内注释(line: &str) -> String {
    let b: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut 引号: Option<char> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match 引号 {
            Some(q) => {
                out.push(c);
                if c == '\\' {
                    // 转义:把下一个字符一起吃掉。
                    if i + 1 < b.len() {
                        out.push(b[i + 1]);
                        i += 2;
                        continue;
                    }
                } else if c == q {
                    引号 = None;
                }
            }
            None => {
                if c == '"' || c == '\'' || c == '`' {
                    引号 = Some(c);
                    out.push(c);
                } else if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
                    break;
                } else {
                    out.push(c);
                }
            }
        }
        i += 1;
    }
    out
}

/// 递归收集一个目录下的前端源文件。
///
/// 上一版用的是非递归 `read_dir`,而两个 Tauri 外壳的 `frontendDist` 是 `../src` ——
/// 也就是说 `src/views/panel.js` 会**打进应用**,却既不被这条检查看到,
/// 也不被 `make check-shells`(glob `src/*.js`)语法检查。
fn 前端源文件(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            前端源文件(&p, out);
        } else {
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, "js" | "mjs" | "cjs" | "ts" | "jsx" | "tsx" | "html") {
                out.push(p);
            }
        }
    }
}

/// 前端不允许出现任何把字符串当成标记或代码解释的写法。
///
/// 审计行里的 `human_message` / `source_app` 有一部分是**受监控方能影响**的
/// (窗口标题、URL、表单标签)。以前那一行是模板字符串塞进 innerHTML,于是一个把
/// 窗口标题改成 `<img src=x onerror=...>` 的 agent 能在守卫自己的界面里执行脚本。
///
/// # 这条测试被复核打回过**两次**
///
/// 第一版:写死四个文件、`if !exists { continue }` 会静默空转、只禁 `innerHTML`。
///
/// 第二版(也就是上一版)仍然漏掉 12 种绕法里的 11 种:
///   - 行里任何位置出现 `//`(比如一个 URL 字面量)就把整行切掉;
///   - `read_dir` 不递归,而 `frontendDist` 是整个 `src/`,子目录里的文件会**打进应用**;
///   - 只认 `.js/.html/.mjs`,漏 `.ts/.cjs/.jsx/.tsx`;
///   - `setAttribute("onclick", …)` —— 这一条被上一版自己的文档注释点名说"已经修好了",
///     而实际没有:`INLINE_HANDLERS` 里每一项都带尾部 `=`,只匹配 HTML 属性语法,
///     永远匹配不到这个 JS API。
///
/// # 它挡不住什么(说清楚,不假装)
///
/// 这是一个**文本 lint**,不是 JS 解析器。已知挡不住:
///
///   - `el["inner" + "HTML"] = x` —— 拼出来的属性名(下面有一条很窄的规则能抓到
///     这个具体形态,但换个拼法就绕过了);
///   - `setTimeout(某个变量, 0)`,而那个变量恰好装着字符串 —— 不做类型推导分不出
///     它和函数引用。
///
/// 也就是说:它挡的是**手滑和顺手的写法**,挡不住有人刻意绕。这不是可以补全的 ——
/// 补全需要真的解析 + 类型信息。写在这里是为了别让人误以为有了这条测试就不用
/// review 前端改动了。CSP 是第二道,正是为这类残余存在的。
#[test]
#[allow(non_snake_case)]
fn 前端不出现把字符串当代码的写法() {
    // 每一条都是一个真的注入 sink。
    const SINKS: &[(&str, &str)] = &[
        ("innerHTML", "把字符串当 HTML 解析"),
        ("outerHTML", "同上"),
        ("insertAdjacentHTML", "同上"),
        ("document.write", "同上"),
        ("createContextualFragment", "同上"),
        ("srcdoc", "把字符串当一整个文档"),
        ("eval(", "把字符串当代码"),
        ("Function(", "new Function 和裸 Function 都算"),
        ("dangerouslySetInnerHTML", "同上"),
        ("cssText", "把字符串当 CSS 解析"),
        ("insertRule", "同上"),
        ("javascript:", "URL 形式的代码执行"),
    ];
    // `setAttribute` 用来装事件处理器 / URL 属性。整个 API 都不许用在前端 ——
    // 这些页面没有一处需要它,所以一律禁掉比逐个白名单更可靠。
    const 危险API: &[(&str, &str)] = &[
        (
            "setAttribute",
            "可以用来装 on* 事件处理器或 javascript: URL;这些页面不需要它",
        ),
        (".href =", "可能被赋成 javascript: URL"),
        (".src =", "同上"),
    ];
    // `setTimeout` / `setInterval` 只有**第一个参数是字符串**时才是代码执行 sink。
    // 一刀切禁掉整个 API 会在 `setTimeout(runScan, 400)` 上误报 —— 而误报的代价是
    // 有人把检查关掉。所以只认紧跟着引号的那种形态。
    const 定时器: &[&str] = &["setTimeout(", "setInterval("];
    // HTML 里的内联事件处理器属性。
    const 内联属性: &[&str] = &[
        "onclick=",
        "onerror=",
        "onload=",
        "onmouseover=",
        "onfocus=",
        "onsubmit=",
    ];

    let mut 文件 = Vec::new();
    for dir in [
        "apps/desktop-macos/src",
        "apps/desktop-windows/src",
        "apps/extension-chromium",
    ] {
        let d = root().join(dir);
        assert!(
            d.is_dir(),
            "前端目录不见了:{dir} —— 目录一改名,这条检查就静默失效"
        );
        前端源文件(&d, &mut 文件);
    }
    // **精确相等**,不是下限。下限会让"新增一个文件"买到"静默删掉一个文件"的额度 ——
    // release-gate 的计数刚因为同一个原因从 `-lt` 改成 `-ne`。
    // 新增前端文件时要一起改这个数,而那一改会出现在 diff 里,于是有人会看一眼
    // 那个新文件有没有 sink。
    // 已检查新增 workspace、三语词表和 gateway-confirmation；外部正文仅写 textContent。
    const 前端文件数: usize = 22;
    assert_eq!(
        文件.len(),
        前端文件数,
        "前端文件数变了(现在 {})。新增文件请一起改这个常量 —— 那一改的意义是\
         「有人看过这个新文件里有没有注入 sink」。少了则说明结构变了,这条检查可能在空转。\n{:?}",
        文件.len(),
        文件
            .iter()
            .map(|p| p.strip_prefix(root()).unwrap().display().to_string())
            .collect::<Vec<_>>()
    );

    let mut 违规 = Vec::new();
    for path in &文件 {
        let text = std::fs::read_to_string(path).unwrap();
        let rel = path.strip_prefix(root()).unwrap().display().to_string();
        let 是html = path.extension().and_then(|e| e.to_str()) == Some("html");
        for (i, line) in text.lines().enumerate() {
            let code = if 是html {
                line.to_string()
            } else {
                去掉行内注释(line)
            };
            for (sink, why) in SINKS {
                if code.contains(sink) {
                    违规.push(format!("{rel}:{}: {sink}({why}) — {}", i + 1, line.trim()));
                }
            }
            if !是html {
                for (api, why) in 危险API {
                    if code.contains(api) {
                        违规.push(format!("{rel}:{}: {api}({why}) — {}", i + 1, line.trim()));
                    }
                }
                // 拼出来的属性名:`el["inner" + "HTML"] = x`。很窄,只抓这个形态。
                if code.contains("[\"") && code.contains('+') && code.contains("] =") {
                    违规.push(format!(
                        "{rel}:{}: 用拼接出来的属性名赋值 —— 请直接写属性名,\
                         这种写法唯一的用途是绕过检查 — {}",
                        i + 1,
                        line.trim()
                    ));
                }
                for t in 定时器 {
                    if let Some(pos) = code.find(t) {
                        let 之后 = code[pos + t.len()..].trim_start();
                        if 之后.starts_with(['"', '\'', '`']) {
                            违规.push(format!(
                                "{rel}:{}: {t} 的第一个参数是字符串 —— 那是代码执行 — {}",
                                i + 1,
                                line.trim()
                            ));
                        }
                    }
                }
            }
            let lower = code.to_lowercase();
            for h in 内联属性 {
                if lower.contains(h) {
                    违规.push(format!("{rel}:{}: 内联事件处理器 {h}", i + 1));
                }
            }
        }
    }
    assert!(
        违规.is_empty(),
        "前端出现了把字符串当标记/代码解释的写法(共扫描 {} 个文件)。\n\
         用 textContent 或建 DOM 节点 —— 这些字符串里有受监控方能影响的文本:\n{}",
        文件.len(),
        违规.join("\n")
    );
}

/// 两个 Tauri 外壳都必须配限制性 CSP。/// 两个 Tauri 外壳都必须配限制性 CSP。
///
/// # 这条测试被复核打回过一次
///
/// 上一版用 `csp.contains("script-src 'self'")` 当"脚本来源只有 self"。那是**前缀
/// 匹配**,于是 `script-src 'self' https://cdn.jsdelivr.net` 一路绿灯 —— 而它的注释
/// 写的正是"有人往 script-src 里加一个 CDN 域名"。同一版里还有一条
/// `!csp.contains("http://") || csp.contains("http://ipc.localhost")`,
/// 两个配置都含 `http://ipc.localhost`(IPC 必需),所以右边恒真,那条断言**永远
/// 不可能失败**。
///
/// 现在把 CSP **解析成指令表**再逐条比对来源集合。
fn parse_csp(csp: &str) -> std::collections::HashMap<String, Vec<String>> {
    csp.split(';')
        .filter_map(|d| {
            let mut it = d.split_whitespace();
            let name = it.next()?.to_ascii_lowercase();
            Some((name, it.map(|s| s.to_string()).collect()))
        })
        .collect()
}

#[test]
fn 两个外壳都配了限制性csp() {
    // 每条指令的来源集合必须**恰好**是这些。多一个域名就是多一条攻击面。
    let 期望: &[(&str, &[&str])] = &[
        ("default-src", &["'none'"]),
        ("script-src", &["'self'"]),
        ("style-src", &["'self'"]),
        ("font-src", &["'self'"]),
        ("object-src", &["'none'"]),
        ("base-uri", &["'none'"]),
        ("form-action", &["'none'"]),
        ("frame-ancestors", &["'none'"]),
        ("img-src", &["'self'", "data:"]),
        ("connect-src", &["ipc:", "http://ipc.localhost"]),
    ];
    for app in ["desktop-macos", "desktop-windows"] {
        let conf = read(&format!("apps/{app}/src-tauri/tauri.conf.json"));
        let v: serde_json::Value =
            serde_json::from_str(&conf).expect("tauri.conf.json 不是合法 JSON");
        let raw = &v["app"]["security"]["csp"];
        assert!(
            raw.is_string(),
            "{app} 的 csp 是 {raw} —— null 意思是不设 CSP"
        );
        let csp = raw.as_str().unwrap();
        let 实际 = parse_csp(csp);

        for (指令, 想要) in 期望 {
            let got = 实际
                .get(*指令)
                .unwrap_or_else(|| panic!("{app} 的 CSP 缺指令 `{指令}`:{csp}"));
            let mut a: Vec<&str> = got.iter().map(String::as_str).collect();
            let mut b: Vec<&str> = 想要.to_vec();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(
                a, b,
                "{app} 的 `{指令}` 来源集合变了(多一个域名就是多一条攻击面):{csp}"
            );
        }
        // 不允许出现期望表之外的指令 —— 新指令要么该进表,要么不该存在。
        for 指令 in 实际.keys() {
            assert!(
                期望.iter().any(|(n, _)| n == 指令),
                "{app} 的 CSP 多了一条没人审过的指令 `{指令}`:{csp}"
            );
        }
        // 任何 unsafe-* 都不行(上面的集合比对已经能拦住,这条是留给人读的)。
        assert!(!csp.contains("unsafe-"), "{app} 的 CSP 带 unsafe-*:{csp}");
    }

    // 页面里不许出现内联 <style>(大小写都算)。
    //
    // 写在 tauri.conf.json 里的是 `style-src 'self'`,而内联 <style> 之所以还能渲染,
    // 是因为 Tauri 构建时注入 nonce、运行时把 `'nonce-<随机>'` 追加进 style-src ——
    // 也就是**实际生效的 CSP 和写的那份不一样**。读配置的人会得出相反结论。
    //
    // 范围包括扩展的 popup.html:上一版只看 `apps/{app}/src/index.html`。
    let mut 扫到 = 0usize;
    for f in [
        "apps/desktop-macos/src/index.html",
        "apps/desktop-windows/src/index.html",
        "apps/extension-chromium/popup.html",
    ] {
        let p = root().join(f);
        assert!(p.is_file(), "{f} 不见了 —— 文件一改名这条检查就静默失效");
        扫到 += 1;
        let html = read(f).to_lowercase();
        assert!(
            !html.contains("<style"),
            "{f} 里有内联 <style> —— 搬去外部样式表,否则写的 CSP 和生效的不一致"
        );
    }
    assert_eq!(扫到, 3, "内联样式检查的文件数变了");
}

/// 品牌母版是所有平台图标的来源。全幅 App 图标必须无透明边缘；可复用标志、
/// 菜单栏模板和网页资源则必须带 Alpha，不能在深色界面上露出白方块。
#[test]
fn 品牌母版的尺寸与透明通道固定() {
    for (path, width, height, color_type) in [
        ("assets/brand/agentguard-app-icon-1024.png", 1024, 1024, 2),
        (
            "assets/brand/agentguard-app-icon-transparent-1024.png",
            1024,
            1024,
            6,
        ),
        ("assets/brand/agentguard-logo.png", 512, 512, 6),
        ("assets/brand/agentguard-mark-blue.png", 512, 512, 6),
        ("assets/brand/agentguard-mark-white.png", 512, 512, 6),
        ("assets/brand/agentguard-tray-template.png", 44, 44, 6),
    ] {
        assert_eq!(
            png_信息(path),
            (width, height, 8, color_type),
            "{path} 的 PNG 规格回退"
        );
    }
}

/// 桌面端打包 PNG、网页标志和 macOS 菜单栏模板必须来自同一套 D 方案资产。
#[test]
fn 桌面品牌资源与菜单栏接线完整() {
    let white_master = std::fs::read(root().join("assets/brand/agentguard-mark-white.png"))
        .expect("读不到白色品牌母版");
    for platform in ["desktop-macos", "desktop-windows"] {
        for (name, size) in [
            ("32x32.png", 32),
            ("128x128.png", 128),
            ("128x128@2x.png", 256),
        ] {
            let path = format!("apps/{platform}/src-tauri/icons/{name}");
            assert_eq!(png_信息(&path), (size, size, 8, 6), "{path} 规格错误");
        }

        let frontend = format!("apps/{platform}/src/index.html");
        assert!(
            read(&frontend).contains("assets/agentguard-mark-white.png"),
            "{frontend} 没有引用品牌标志"
        );
        assert_eq!(
            png_信息(&format!(
                "apps/{platform}/src/assets/agentguard-mark-white.png"
            )),
            (512, 512, 8, 6),
            "{platform} 前端品牌标志规格错误"
        );
        let packaged = std::fs::read(root().join(format!(
            "apps/{platform}/src/assets/agentguard-mark-white.png"
        )))
        .unwrap_or_else(|e| panic!("读不到 {platform} 品牌标志：{e}"));
        assert_eq!(
            packaged.as_slice(),
            white_master.as_slice(),
            "{platform} 前端品牌标志与母版漂移"
        );
    }

    for name in [
        "32x32.png",
        "128x128.png",
        "128x128@2x.png",
        "icon.icns",
        "icon.ico",
    ] {
        let mac = std::fs::read(root().join(format!("apps/desktop-macos/src-tauri/icons/{name}")))
            .unwrap_or_else(|e| panic!("读不到 macOS {name}：{e}"));
        let windows =
            std::fs::read(root().join(format!("apps/desktop-windows/src-tauri/icons/{name}")))
                .unwrap_or_else(|e| panic!("读不到 Windows {name}：{e}"));
        assert_eq!(
            mac, windows,
            "macOS 与 Windows 的 {name} 已从同一品牌母版漂移"
        );
    }

    let tray_source = std::fs::read(root().join("assets/brand/agentguard-tray-template.png"))
        .expect("读不到菜单栏品牌母版");
    let tray_packaged =
        std::fs::read(root().join("apps/desktop-macos/src-tauri/icons/tray-template.png"))
            .expect("读不到 macOS 打包菜单栏图标");
    assert_eq!(tray_packaged, tray_source, "macOS 菜单栏图标与品牌母版漂移");

    let mac = read("apps/desktop-macos/src-tauri/src/lib.rs");
    assert!(mac.contains("include_bytes!(\"../icons/tray-template.png\")"));
    assert!(mac.contains(".icon_as_template(true)"));
}

/// Chromium Manifest、真实 PNG 和商店打包清单必须同时覆盖 16/32/48/128。
#[test]
fn chromium_品牌图标与打包清单一致() {
    let manifest: serde_json::Value =
        serde_json::from_str(&read("apps/extension-chromium/manifest.json"))
            .expect("Chromium manifest 必须是有效 JSON");
    for size in [16, 32, 48, 128] {
        let path = format!("icons/icon{size}.png");
        assert_eq!(manifest["icons"][size.to_string()], path);
        assert_eq!(
            png_信息(&format!("apps/extension-chromium/{path}")),
            (size, size, 8, 6),
            "Chromium {size}px 图标规格错误"
        );
    }
    for size in [16, 32] {
        assert_eq!(
            manifest["action"]["default_icon"][size.to_string()],
            format!("icons/icon{size}.png")
        );
    }

    let script = read("apps/extension-chromium/scripts/package-store.sh");
    assert!(
        !script.contains("Placeholder"),
        "正式包不能静默生成占位图标"
    );
    assert!(script.contains("for size in 16 32 48 128"));
    assert!(script.contains("assets/agentguard-mark-white.png"));

    let white_master = std::fs::read(root().join("assets/brand/agentguard-mark-white.png"))
        .expect("读不到白色品牌母版");
    let extension_mark =
        std::fs::read(root().join("apps/extension-chromium/assets/agentguard-mark-white.png"))
            .expect("读不到 Chromium 品牌标志");
    assert_eq!(
        extension_mark.as_slice(),
        white_master.as_slice(),
        "Chromium 品牌标志与母版漂移"
    );
}

/// 三语入口必须展示同一个品牌标志，不能只更新其中一种语言。
#[test]
fn 三语文档都展示品牌标志() {
    for path in ["README.md", "README.zh-TW.md", "README.en.md"] {
        assert!(
            read(path).contains("assets/brand/agentguard-logo.png"),
            "{path} 没有展示品牌标志"
        );
    }
    for path in [
        "docs/README.md",
        "docs/README.zh-TW.md",
        "docs/README.en.md",
    ] {
        assert!(
            read(path).contains("../assets/brand/agentguard-logo.png"),
            "{path} 没有展示品牌标志"
        );
    }
}

/// 扩展 popup 引用的每个本地文件都必须在打包脚本里。
///
/// 打包脚本用的是**显式文件清单**(`cp $ROOT/popup.js ...`),不是通配。所以把内联
/// `<style>` 搬成 `popup.css` 的那一刻,商店包里就少了一个文件 ——
/// 装出来的扩展没有样式,而所有测试都是绿的。
///
/// 这不是假想:上面那条"不许内联 style"的修复第一次做完时,`popup.css` 确实没进
/// 打包清单。**一个显式清单必须有东西盯着它和引用保持同步。**
#[test]
fn 扩展引用的本地文件都在打包清单里() {
    let html = read("apps/extension-chromium/popup.html");
    let script = read("apps/extension-chromium/scripts/package-store.sh");
    let mut 引用 = Vec::new();
    for attr in ["href=\"", "src=\""] {
        let mut rest = html.as_str();
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            let Some(j) = rest.find('"') else { break };
            let v = &rest[..j];
            // 只管本地相对路径。
            if !v.starts_with("http") && !v.starts_with("//") && !v.is_empty() {
                引用.push(v.to_string());
            }
            rest = &rest[j..];
        }
    }
    assert!(
        !引用.is_empty(),
        "popup.html 里一个本地引用都没解析出来 —— 这条检查可能已经在空转"
    );
    let mut 缺的 = Vec::new();
    for f in &引用 {
        let 文件 = f.trim_start_matches("./");
        if !root().join("apps/extension-chromium").join(文件).exists() {
            缺的.push(format!("{f}(文件本身不存在)"));
        } else if !script.contains(文件) {
            缺的.push(format!("{f}(存在,但打包脚本没 cp 它)"));
        }
    }
    assert!(
        缺的.is_empty(),
        "popup.html 引用了这些文件,但它们进不了商店包 —— 装出来的扩展会缺东西:\n  {}",
        缺的.join("\n  ")
    );
}

/// README 的宣传口径不能和自己的边界文档矛盾。
///
/// 项目自己的上线评估文档明确写着不能称为"实时"、"沙箱"、"DLP"、"不可绕过";
/// README 却写着"实时拦截"。对一个安全产品来说这不只是文案问题 —— 它是
/// 读者据以判断风险的那句话。
///
/// 这条测试盯的是几个具体的词。它挡不住所有夸大,但它挡住了**已经发生过**的那次。
#[test]
fn readme不使用被自己文档否掉的词() {
    let readme = read("README.md");
    let 禁用词 = [
        (
            "实时拦截",
            "上线评估文档说了不能称为实时:轮询之间的事看不见",
        ),
        ("实时阻断", "同上"),
        ("沙箱隔离", "上线评估文档说了不能称为沙箱"),
        ("不可绕过", "工具网关是合作式的,agent 直接 exec 就绕过了"),
        (
            "零信任",
            "适配器断言仍可被本机持令牌方伪造(方向受限,但不是零信任)",
        ),
    ];
    let mut 命中 = Vec::new();
    for (词, 为什么) in 禁用词 {
        if readme.contains(词) {
            命中.push(format!("  「{词}」—— {为什么}"));
        }
    }
    assert!(
        命中.is_empty(),
        "README 用了自己的边界文档否掉的词:\n{}\n\
         (docs/上线评估.md 是那份边界文档。宣传口径要么改,要么先把能力做到。)",
        命中.join("\n")
    );
}

/// CI 的 `run:` 命令(注释已剥离),和每个 step / job 的 `continue-on-error` 值。
///
/// 上一版这两条检查是在**原始文本**上做 `contains`。复核用一串变异把它打穿了:
/// 一个被注释掉的 `# run: make check-shells` 满足了"CI 覆盖了这个 target";
/// `continue-on-error:  true`(两个空格)躲过了"没有被吞掉的退出码";
/// `|| :`、`|| exit 0`、`continue-on-error: True` 全都躲过了。
///
/// 一个字面子串比对,被一个空格打败 —— 那不是检查,是巧合。所以现在**解析 YAML**。
struct Ci {
    /// 每条 `run:` 的内容(多行的已经拼好)。
    runs: Vec<String>,
    /// (位置描述, continue-on-error 的原始值)
    coe: Vec<(String, serde_yaml::Value)>,
}

fn parse_ci() -> Ci {
    let raw = read(".github/workflows/ci.yml");
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).expect("ci.yml 不是合法 YAML");
    let mut out = Ci {
        runs: Vec::new(),
        coe: Vec::new(),
    };
    let jobs = doc
        .get("jobs")
        .and_then(|j| j.as_mapping())
        .expect("ci.yml 里没有 jobs");
    for (jname, job) in jobs {
        let jn = jname.as_str().unwrap_or("?").to_string();
        if let Some(v) = job.get("continue-on-error") {
            out.coe.push((format!("job {jn}"), v.clone()));
        }
        let steps = job.get("steps").and_then(|s| s.as_sequence());
        for (i, st) in steps.into_iter().flatten().enumerate() {
            if let Some(v) = st.get("continue-on-error") {
                out.coe.push((format!("job {jn} step {i}"), v.clone()));
            }
            if let Some(r) = st.get("run").and_then(|r| r.as_str()) {
                out.runs.push(r.to_string());
            }
            // `uses:` 也算 —— cargo-deny-action 就是这么跑的。
            if let Some(u) = st.get("uses").and_then(|u| u.as_str()) {
                out.runs.push(format!("uses:{u}"));
            }
        }
    }
    assert!(
        out.runs.len() >= 15,
        "只从 ci.yml 解析出 {} 条命令,像是结构变了 —— 这条检查可能已经在空转",
        out.runs.len()
    );
    out
}

/// `make check` 里的每个 target,CI 里都要有东西在跑它。
///
/// # 为什么需要这条
///
/// 一条只在本地跑的门禁,是靠人记得的门禁。`cargo fmt --check` 和 workspace 级的
/// `cargo clippy` 两条都曾不在 CI 里,结果 68 个文件漂出规范,其中还藏着一条被旧折行
/// 遮住的 clippy 错误。
///
/// # 这条测试被复核打回过一次
///
/// 上一版在原始文本上 `contains("make X")`,于是把 `run: make check-shells` 换成
/// `# 先临时停掉:run: make check-shells` 再加一行 `run: echo skipped`,测试照样绿 ——
/// 那条前端/脚本解析门禁从 CI 里消失了,而"防止门禁只在本地跑"的测试没看见。
///
/// 等效物白名单也是个洞:`("check-newgate", "")` 让 `contains("")` 恒真,
/// `("check-newgate", "run")` 也一样 —— 随便一个短字符串就能把一个 target 蒙过去。
#[test]
fn ci覆盖make_check的每个target() {
    let makefile = read("Makefile");
    let ci = parse_ci();

    // 先把 `check:` 那一行的续行拼起来。上一版只读一行,遇到 `\` 续行时会把反斜杠
    // 当成一个 target 名报出来,而续行之后那几个真 target 从来没被检查过。
    let mut check_line = String::new();
    let mut 收集 = false;
    for line in makefile.lines() {
        if line.starts_with("check:") {
            收集 = true;
            check_line.push_str(line.trim_start_matches("check:"));
        } else if 收集 {
            check_line.push(' ');
            check_line.push_str(line);
        }
        if 收集 {
            if check_line.trim_end().ends_with('\\') {
                check_line = check_line.trim_end().trim_end_matches('\\').to_string();
                continue;
            }
            break;
        }
    }
    assert!(!check_line.is_empty(), "Makefile 里找不到 `check:`");
    let targets: Vec<&str> = check_line.split_whitespace().collect();

    // target 名必须长得像 target 名。这条挡住"反斜杠被当成 target"那类解析事故。
    for t in &targets {
        assert!(
            t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
            "`check:` 里解析出一个不像 target 的词 `{t}` —— 解析坏了,别往白名单里加它"
        );
    }
    assert!(
        targets.len() >= 10,
        "`check:` 只依赖 {} 个 target,像是被删空了:{check_line}",
        targets.len()
    );

    // **`make check` 自己必须还包含这些门禁。**上一版只验 "CI ⊇ make check",
    // 于是把 `check:` 删成 `test eval coverage` 之后所有测试照样绿。
    for 必须 in [
        "check-fmt",
        "check-clippy",
        "check-supply-chain",
        "test",
        "eval",
        "coverage",
        "check-shells",
        "check-macos-paths",
        "preflight",
    ] {
        assert!(
            targets.contains(&必须),
            "`make check` 里少了 `{必须}` —— 本地门禁被掏空了"
        );
    }

    // 某些 target 在 CI 里是用等效命令跑的。等效字符串必须**足够具体**:
    // 至少 12 个字符且含空格,否则 `("x", "run")` 这种就能蒙过去。
    let 等效物: &[(&str, &str)] = &[
        ("test", "cargo test --workspace"),
        ("check-fmt", "cargo fmt --all --check"),
        ("check-clippy", "cargo clippy --workspace --all-targets"),
        ("check-supply-chain", "uses:EmbarkStudios/cargo-deny-action"),
        ("eval", "eval --scenarios eval/scenarios"),
        ("scoreboard", "guard-cli -- scoreboard"),
        ("leaderboard", "guard-cli -- leaderboard"),
        ("sim-capture", "guard-cli -- sim-capture"),
    ];
    for (name, cmd) in 等效物 {
        assert!(
            cmd.len() >= 12 && (cmd.contains(' ') || cmd.starts_with("uses:")),
            "等效物 `{name}` 的字符串 `{cmd}` 太笼统 —— 那等于给自己开一个口子"
        );
    }

    let mut 缺的 = Vec::new();
    for t in &targets {
        // 只在**解析出来的命令**里找,不在原始文本里找 —— 注释掉的行不算。
        let 直接 = ci.runs.iter().any(|r| {
            r.split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| w == ["make", *t])
        });
        let 等效 = 等效物
            .iter()
            .find(|(name, _)| name == t)
            .map(|(_, cmd)| ci.runs.iter().any(|r| r.contains(cmd)))
            .unwrap_or(false);
        if !直接 && !等效 {
            缺的.push(*t);
        }
    }
    assert!(
        缺的.is_empty(),
        "这些 `make check` 的 target 在 CI 里没有对应的步骤:{:?}\n\
         只在本地跑的门禁是靠人记得的门禁。要么加进 ci.yml,要么在「等效物」表里\n\
         说清它在 CI 里对应哪条**具体**命令(至少 12 字符且含空格)。",
        缺的
    );
}

/// CI 里不允许用任何方式吞掉门禁的退出码。
///
/// # 这条测试被复核打穿过
///
/// 上一版是 `code.contains("|| true") || code.contains("continue-on-error: true")`。
/// 13 种吞法里它只抓到 3 种。躲过去的包括:`|| :`、`|| exit 0`、
/// `|| echo "known failure"`、`set +e`、`if cmd; then true; fi`、
/// `continue-on-error: True`、`continue-on-error: ${{ true }}`,
/// 以及 **`continue-on-error:  true`(两个空格)** —— 一个字面子串比对,被一个空格打败。
/// 还有一种更难看的:`echo "gate #1"; make preflight || true` 里那个 `#`
/// 会让它自己的注释剥离把 `|| true` 切掉。
///
/// 所以现在读的是**解析出来的 YAML 值**,而不是文本。
#[test]
fn ci里没有被吞掉的退出码() {
    let ci = parse_ci();
    let mut 违规 = Vec::new();

    // continue-on-error:只要不是字面的 false 就算。这样 True / "true" /
    // `${{ ... }}` 表达式 / 任意空白都躲不过。
    for (位置, v) in &ci.coe {
        let 是false = matches!(v, serde_yaml::Value::Bool(false));
        if !是false {
            违规.push(format!(
                "{位置}: continue-on-error: {v:?} —— 只有字面 false 才算不吞"
            ));
        }
    }

    // run: 里的吞法。在**每一行**上单独看,而且不做 `#` 剥离 ——
    // YAML 的 `run:` 块里 `#` 是 shell 注释,剥它反而会切掉后面的 `|| true`。
    let 吞法: &[(&str, &str)] = &[
        ("|| true", "直接吞"),
        ("|| :", ": 就是 true"),
        ("|| exit 0", "显式以 0 退出"),
        ("|| echo", "用 echo 把失败变成成功"),
        ("set +e", "关掉 errexit"),
        ("|| /bin/true", "同 || true"),
    ];
    for r in &ci.runs {
        for line in r.lines() {
            let l = line.trim();
            if l.starts_with('#') {
                continue;
            }
            for (pat, why) in 吞法 {
                if l.contains(pat) {
                    违规.push(format!("run 里 `{l}` —— {why}"));
                }
            }
        }
    }
    assert!(
        违规.is_empty(),
        "CI 里有步骤在吞掉自己的退出码:\n  {}\n\
         一个不会让构建变红的检查,和一个不存在的检查没有区别。\n\
         只是想打印一份报告的话,把它和真正的门禁拆成两步。",
        违规.join("\n  ")
    );
}

/// Makefile 的门禁配方前面不许加 `-`(忽略退出码)。
///
/// 这是那个"原始罪"发生的地方:`preflight` 那一行曾经是 `-cargo run ...`,
/// 一个前缀减号把退出码吞掉,于是**新出现**的 FAIL 也不拦任何人。
/// 上面那条 CI 检查的文档注释点名了这件事,却只扫 ci.yml —— 一次独立复核指出,
/// 历史故障发生的那个文件本身没人看着。
#[test]
fn makefile的门禁配方不忽略退出码() {
    let makefile = read("Makefile");
    // `make check` 依赖的那些,以及 check 自己。
    let 门禁 = [
        "check",
        "check-fmt",
        "check-clippy",
        "check-supply-chain",
        "test",
        "eval",
        "coverage",
        "check-shells",
        "check-macos-paths",
        "check-macos-cfg",
        "check-macos-path-semantics",
        "preflight",
        "check-msrv",
    ];
    let mut 当前: Option<String> = None;
    let mut 违规 = Vec::new();
    for line in makefile.lines() {
        // 目标行:行首非空白且含 `:`。
        if !line.starts_with([' ', '\t']) && line.contains(':') && !line.starts_with('#') {
            当前 = line.split(':').next().map(|s| s.trim().to_string());
            continue;
        }
        // 配方行:以 tab 开头。
        if let Some(t) = &当前 {
            if line.starts_with('\t') && 门禁.contains(&t.as_str()) {
                let body = line.trim_start_matches('\t');
                if body.starts_with('-') {
                    违规.push(format!("{t}: {}", body.trim()));
                }
            }
        }
    }
    assert!(
        违规.is_empty(),
        "这些门禁配方前面带 `-`,make 会忽略它们的退出码:\n  {}\n\
         `preflight` 那一行曾经就是这样,于是一个新出现的 FAIL 谁都拦不住。",
        违规.join("\n  ")
    );
}

/// preflight 源码里**能发出**的每个结论 id 都要被钉住。
///
/// # 为什么基线本身不够
///
/// 基线只能钉**当前会触发**的结论。一次独立复核证明了后果:把
/// `check_adapter_registry` 里整个 `adapter.keys.publicly_known` 分支删掉 ——
/// 那是"注册表钉了一把私钥公开的适配器密钥"的检查,也就是"任何本机进程都能伪造
/// 一份干净的环境调查" ——
///
/// ```text
/// make preflight            → preflight 基线一致(15 条结论)   exit 0
/// cargo test -p guard-cli   → all green
/// ```
///
/// 全绿。因为那个分支现在不触发,基线里没有它,删掉它基线也不变。
/// **也就是说:恰恰是"将来会抓住回归"的那些代码,可以随便删。**
///
/// 所以这条测试钉的是**源码里的 id 集合**,不是运行时的结论集合。删一个分支,
/// 集合就变,测试就红。
#[test]
fn preflight能发出的结论id集合被钉住() {
    let src = read("crates/guard-cli/src/preflight.rs");
    // 只扫产品代码:测试模块里也有 `Finding::` 调用。
    let 产品段 = src
        .split("#[cfg(test)]")
        .next()
        .expect("preflight.rs 结构变了");

    let mut ids: Vec<String> = Vec::new();
    for ctor in [
        "Finding::pass(",
        "Finding::info(",
        "Finding::warn(",
        "Finding::fail(",
    ] {
        let mut rest = 产品段;
        while let Some(i) = rest.find(ctor) {
            rest = &rest[i + ctor.len()..];
            // 第一个参数是 id 字面量,可能带换行和缩进。
            let head = rest.trim_start();
            if let Some(stripped) = head.strip_prefix('"') {
                if let Some(j) = stripped.find('"') {
                    ids.push(stripped[..j].to_string());
                }
            }
        }
    }
    ids.sort();
    ids.dedup();

    // 这份清单是**手写的**,改它必须是一次有意的动作,而那一改会出现在 diff 里。
    // 删一个检查分支 → 这里少一个 id → 测试红,而且报的是"少了哪一个"。
    let 期望: &[&str] = &[
        "adapter.keys.absent",
        "adapter.keys.partial",
        "adapter.keys.present",
        "adapter.keys.publicly_known",
        "adapter.platforms.unpinned",
        "adapter.registry.absent",
        "adapter.registry.invalid",
        "adapters.asymmetric_trust",
        "agent.attestation.optional",
        "agent.attestation.required",
        "agent.keys.absent",
        "agent.keys.private",
        "agent.keys.publicly_known",
        "agent.registry.absent",
        "agent.registry.invalid",
        "api.token.empty",
        "api.token.generated",
        "api.token.strong",
        "api.token.weak",
        "apps.registry.absent",
        "apps.registry.invalid",
        "apps.signers.absent",
        "apps.signers.present",
        "audit.key.missing",
        "audit.signed",
        "audit.unsigned",
        "gateway.cooperative",
        "intel.absent",
        "intel.secret.absent",
        "intel.secret.present",
        "intel.secret.unignored",
        "intel.unverified",
        "intel.verified",
        "jail.backend",
        "jail.unavailable",
        "license.pubkey.configured",
        "license.pubkey.fixture",
        "license.pubkey.invalid",
        "license.secret.absent",
        "license.secret.present",
        "license.secret.unignored",
        "plans.absent",
        "plans.invalid",
        "plans.loaded",
        "plans.paths.absent",
        "plans.paths.declared",
        "rules.invalid",
        "rules.loaded",
        "rules.missing",
    ];
    let 期望集: std::collections::BTreeSet<&str> = 期望.iter().copied().collect();
    let 实际集: std::collections::BTreeSet<&str> = ids.iter().map(String::as_str).collect();

    let 少的: Vec<&&str> = 期望集.difference(&实际集).collect();
    let 多的: Vec<&&str> = 实际集.difference(&期望集).collect();
    assert!(
        少的.is_empty(),
        "preflight 源码里少了这些结论 id:{:?}\n\
         删掉一个检查分支就是这个形状 —— 而基线看不见它,因为它本来就不触发。\n\
         如果确实是有意删的,把它从这份清单里去掉,那一改会在评审里被看到。",
        少的
    );
    assert!(
        多的.is_empty(),
        "preflight 源码里多了这些结论 id:{:?}\n\
         新增检查是好事 —— 把它们加进这份清单,并且跑 `make preflight-baseline`。",
        多的
    );
}

/// 提交进仓库的那份基线里,**恰好一条 FAIL**,而且是已知的那一条。
///
/// 一次独立复核指出:`--write-baseline` 的更新流程唯一的把关是"有人读 diff",
/// 而 `ENV_DEPENDENT_PREFIXES` 那张表**有**一条单元测试盯着(所以放宽它必须改测试)。
/// 基线里"有几条 FAIL、是哪几条"这个更重要的不变量,反倒没有任何东西盯着。
///
/// 现在盯上了:多一条 FAIL 就是新出现的部署故障被顺手接受了。
#[test]
fn 提交的基线里只有一条已知的fail() {
    let base = read("policies/preflight-baseline.txt");
    let fails: Vec<&str> = base
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("FAIL "))
        .collect();
    assert_eq!(
        fails.len(),
        1,
        "提交的基线里有 {} 条 FAIL,期望恰好 1 条:\n  {}\n\
         多出来的那条意味着有人跑了 `make preflight-baseline` 把一个新故障接受掉了。",
        fails.len(),
        fails.join("\n  ")
    );
    assert!(
        fails[0].starts_with("FAIL agent.keys.publicly_known"),
        "基线里那条 FAIL 变了:{}\n\
         唯一**刻意保留**的 FAIL 是 agent.keys.publicly_known(仓库钉的是夹具密钥)。",
        fails[0]
    );
}

/// 中继那三个 HTTP 头的名字,Kotlin 侧和 Rust 侧必须一致。
///
/// 它们以前在两边各写一遍字面量,而**两侧都没有任何测试钉住**。改掉一侧的一个字母,
/// 生产静默退化成 `Unsigned` —— 也就是"签名静默地永远验不过"那个失败形状,
/// 而全部测试是绿的。跨语言向量整套机制就是为了防这件事,却漏掉了头名本身。
/// 一次独立对抗性复核指出来的。
#[test]
fn 中继头名两侧一致() {
    let rust = read("crates/guard-schema/src/adapter.rs");
    let kotlin =
        read("apps/android-companion/app/src/main/java/com/agentguard/companion/RelayClient.kt");
    let mut 对上的 = 0usize;
    for 常量 in [
        "ADAPTER_HEADER_ID",
        "ADAPTER_HEADER_TIMESTAMP",
        "ADAPTER_HEADER_SIGNATURE",
    ] {
        // 从 Rust 常量定义里取出那个字符串值。
        let needle = format!("pub const {常量}: &str = \"");
        let i = rust
            .find(&needle)
            .unwrap_or_else(|| panic!("guard-schema 里找不到常量 {常量}"));
        let rest = &rust[i + needle.len()..];
        let name = &rest[..rest.find('"').expect("常量定义没闭合")];
        assert!(
            name.starts_with("X-AgentGuard-"),
            "{常量} 的值看起来不像一个头名:{name}"
        );
        assert!(
            kotlin.contains(&format!("\"{name}\"")),
            "Kotlin 的 RelayClient 里没有发送头 `{name}` —— 两侧的头名漂开了,\
             而那的表现是「签名静默地永远验不过」"
        );
        对上的 += 1;
    }
    assert_eq!(对上的, 3, "对上的头名数量不对");
}

/// 发布版本不能再出现「核心是 RC、各客户端仍是 0.1.0」的漂移。
///
/// Chromium 的 `version` 只能用数字段，所以它用 `1.0.0.1`，并通过
/// `version_name` 保留对外版本 `1.0.0-rc.1`。Android 的 versionCode 同理单独编码。
#[test]
fn 发布版本元数据一致() {
    const VERSION: &str = "1.0.0-rc.1";

    for path in [
        "Cargo.toml",
        "apps/desktop-macos/package.json",
        "apps/desktop-macos/package-lock.json",
        "apps/desktop-macos/src-tauri/Cargo.toml",
        "apps/desktop-macos/src-tauri/Cargo.lock",
        "apps/desktop-macos/src-tauri/tauri.conf.json",
        "apps/desktop-windows/package.json",
        "apps/desktop-windows/package-lock.json",
        "apps/desktop-windows/src-tauri/Cargo.toml",
        "apps/desktop-windows/src-tauri/Cargo.lock",
        "apps/desktop-windows/src-tauri/tauri.conf.json",
    ] {
        assert!(
            read(path).contains(VERSION),
            "{path} 没有对齐发布版本 {VERSION}"
        );
    }

    let android = read("apps/android-companion/app/build.gradle.kts");
    assert!(android.contains("versionCode = 1000001"));
    assert!(android.contains(&format!("versionName = \"{VERSION}\"")));

    let chromium: serde_json::Value =
        serde_json::from_str(&read("apps/extension-chromium/manifest.json"))
            .expect("Chromium manifest 必须是有效 JSON");
    assert_eq!(chromium["version"], "1.0.0.1");
    assert_eq!(chromium["version_name"], VERSION);

    let firefox: serde_json::Value =
        serde_json::from_str(&read("apps/extension-chromium/manifest.firefox.json"))
            .expect("Firefox manifest 必须是有效 JSON");
    assert_eq!(firefox["version"], "1.0.0.1");
}

/// 能力矩阵(docs/capability-matrix{,.en,.zh-TW}.md)是 `scripts/gen-capability-matrix.py` 从源码
/// 生成的:各端真正发出的事件种类、静态测试数、版本字符串。真机报告 P2-5 列的漂移(Android 文案
/// 说观察 deeplink 而代码从未发出、发布说明写 20 条声明而实际 38、iOS 列着"我们交付")都是手写
/// 数字过期。这条以 `--check` 重新生成并逐字比对——改了代码没跑 `make capability-matrix` 就红。
///
/// 需要 python3(dashboard 与验收固件早已依赖它);没有就失败并说明,不静默跳过。
#[test]
fn 能力矩阵是从源码生成的_与仓库逐字一致() {
    // 强制复现 Windows 的非 UTF-8 控制台，不能等到该平台 CI 才发现打印失败。
    for encoding in ["utf-8", "cp1252"] {
        let out = std::process::Command::new("python3")
            .arg(root().join("scripts/gen-capability-matrix.py"))
            .arg("--check")
            .env("PYTHONIOENCODING", encoding)
            .output()
            .expect(
                "python3 不可用:能力矩阵脚本需要它(Makefile 的 dashboard 目标同样依赖 python3)",
            );
        assert!(
            out.status.success(),
            "能力矩阵检查失败({encoding}),跑 `make capability-matrix` 核对:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8(out.stdout)
            .expect("脚本输出必须是 UTF-8")
            .contains("与源码一致"));
    }
    // 生成物三语成组,且每份都自称生成物(手改的人先看到这句)。
    for rel in [
        "docs/capability-matrix.md",
        "docs/capability-matrix.zh-TW.md",
        "docs/capability-matrix.en.md",
    ] {
        let text = read(rel);
        assert!(
            text.contains("scripts/gen-capability-matrix.py"),
            "{rel} 必须声明自己由 scripts/gen-capability-matrix.py 生成"
        );
    }
    // 手写文档里引用矩阵而不是自己写数字:这几份以前各写了一套过期的数。
    for rel in [
        "docs/RELEASE-1.0.0-rc.1.md",
        "docs/RELEASE-1.0.0-rc.1.zh-TW.md",
        "docs/RELEASE-1.0.0-rc.1.en.md",
        "apps/android-companion/PLAY_STORE.md",
        "apps/android-companion/PLAY_STORE.zh-TW.md",
        "apps/android-companion/PLAY_STORE.en.md",
        "docs/ios-limited-sku.md",
        "docs/android-completeness.md",
        "docs/platform-matrix.md",
        "README.md",
        "README.zh-TW.md",
        "README.en.md",
    ] {
        assert!(
            read(rel).contains("capability-matrix"),
            "{rel} 应指向生成的能力矩阵(docs/capability-matrix*.md),而不是自己维护一套会过期的数字"
        );
    }
}

/// GitHub 入口、变更记录、核心发布说明和每个组件 README 必须成组三语存在。
///
/// 深层研究与审计材料保留原始语言，由三语文档门户标注；这里盯的是用户会直接
/// 进入的公开材料，防止以后只更新其中一种语言或误删一版。
#[test]
fn 公开文档三语成组() {
    let groups: &[&[&str]] = &[
        &["README.md", "README.zh-TW.md", "README.en.md"],
        &["CHANGELOG.md", "CHANGELOG.zh-TW.md", "CHANGELOG.en.md"],
        &[
            "docs/README.md",
            "docs/README.zh-TW.md",
            "docs/README.en.md",
        ],
        &[
            "docs/RELEASE-1.0.0-rc.1.md",
            "docs/RELEASE-1.0.0-rc.1.zh-TW.md",
            "docs/RELEASE-1.0.0-rc.1.en.md",
        ],
        &[
            "docs/release-evidence.md",
            "docs/release-evidence.zh-TW.md",
            "docs/release-evidence.en.md",
        ],
        &[
            "docs/capability-matrix.md",
            "docs/capability-matrix.zh-TW.md",
            "docs/capability-matrix.en.md",
        ],
        &[
            "docs/desktop-guide.md",
            "docs/desktop-guide.zh-TW.md",
            "docs/desktop-guide.en.md",
        ],
        &[
            "docs/privacy-policy.md",
            "docs/privacy-policy.zh-TW.md",
            "docs/privacy-policy.en.md",
        ],
        &[
            "docs/acceptance-firefox.md",
            "docs/acceptance-firefox.zh-TW.md",
            "docs/acceptance-firefox.en.md",
        ],
        &[
            "docs/acceptance-windows.md",
            "docs/acceptance-windows.zh-TW.md",
            "docs/acceptance-windows.en.md",
        ],
        &[
            "docs/acceptance-macos.md",
            "docs/acceptance-macos.zh-TW.md",
            "docs/acceptance-macos.en.md",
        ],
        &[
            "docs/acceptance-runbook.md",
            "docs/acceptance-runbook.zh-TW.md",
            "docs/acceptance-runbook.en.md",
        ],
        &[
            "docs/acceptance-report-template.md",
            "docs/acceptance-report-template.zh-TW.md",
            "docs/acceptance-report-template.en.md",
        ],
        &[
            "docs/macos实时观测.md",
            "docs/macos实时观测.zh-TW.md",
            "docs/macos实时观测.en.md",
        ],
        &[
            "docs/主张与测试映射.md",
            "docs/主张与测试映射.zh-TW.md",
            "docs/主张与测试映射.en.md",
        ],
        &[
            "docs/入站信任.md",
            "docs/入站信任.zh-TW.md",
            "docs/入站信任.en.md",
        ],
        &[
            "docs/浏览器执行前阻断.md",
            "docs/浏览器执行前阻断.zh-TW.md",
            "docs/浏览器执行前阻断.en.md",
        ],
        &[
            "docs/消费者化界面.md",
            "docs/消费者化界面.zh-TW.md",
            "docs/消费者化界面.en.md",
        ],
        &[
            "docs/跨浏览器.md",
            "docs/跨浏览器.zh-TW.md",
            "docs/跨浏览器.en.md",
        ],
        &[
            "apps/desktop-macos/README.md",
            "apps/desktop-macos/README.zh-TW.md",
            "apps/desktop-macos/README.en.md",
        ],
        &[
            "apps/desktop-windows/README.md",
            "apps/desktop-windows/README.zh-TW.md",
            "apps/desktop-windows/README.en.md",
        ],
        &[
            "apps/android-companion/README.md",
            "apps/android-companion/README.zh-TW.md",
            "apps/android-companion/README.en.md",
        ],
        &[
            "apps/extension-chromium/README.md",
            "apps/extension-chromium/README.zh-TW.md",
            "apps/extension-chromium/README.en.md",
        ],
        &[
            "apps/ios-webshield/README.md",
            "apps/ios-webshield/README.zh-TW.md",
            "apps/ios-webshield/README.en.md",
        ],
        &[
            "intel/README.md",
            "intel/README.zh-TW.md",
            "intel/README.en.md",
        ],
    ];

    for group in groups {
        for path in *group {
            assert!(root().join(path).is_file(), "三语文档缺少:{path}");
        }
    }

    for path in [
        "README.md",
        "README.zh-TW.md",
        "README.en.md",
        "CHANGELOG.md",
        "CHANGELOG.zh-TW.md",
        "CHANGELOG.en.md",
    ] {
        assert!(
            read(path).contains("1.0.0-rc.1"),
            "{path} 没有标明当前发布候选版本"
        );
    }
}

/// release-gate 的证据检查必须走结构化校验(guard-cli evidence-verify),
/// 不许退回"grep 关键词"。
///
/// 真机测试(报告 P0-1)用六个指向 release-gate.sh 自身的环境变量拿到了
/// "17/17 PASS,退出 0"——因为当时的证据检查是「普通文件 + 非空 + 含关键词」,
/// 而关键词就写在同一个脚本里。修复把校验挪进了 evidence.rs(纯函数,六种伪造
/// 姿势各有反向测试)。这条不变量盯住脚本侧:哪天有人图省事把 grep 加回去,
/// 或者把 evidence-verify 调用删掉,这里会红。
#[test]
fn 发布门禁的证据检查走结构化校验而不是关键词() {
    let gate = read("scripts/release-gate.sh");
    assert!(
        gate.contains("evidence-verify"),
        "release-gate.sh 不再调用 evidence-verify —— 证据检查退化了"
    );
    assert!(
        !gate.contains(r#"grep -qi -- "$expect""#),
        "release-gate.sh 又出现了关键词式证据检查 —— 这正是报告 P0-1 击穿的形态"
    );
    // 严格模式必须登记一道**无 baseline** 的 preflight 门(生产姿态零 FAIL)。两条修复线
    // 给它起了不同的名字("production preflight" / "生产部署自检"),合流取 canonical 的;
    // 这里盯的是形态:strict 分支里再跑一次裸 `guard-cli -- preflight`,而不是名字。
    let strict_blocks: Vec<&str> = gate
        .split("if [ \"$STRICT\" -eq 1 ]; then")
        .skip(1)
        .filter_map(|rest| rest.split("\nfi").next())
        .collect();
    assert!(
        !strict_blocks.is_empty(),
        "release-gate.sh 丢了 STRICT 分支"
    );
    assert!(
        strict_blocks.iter().any(|b| b.contains("gate ")
            && (b.contains("guard-cli -- preflight") || b.contains("guard-cli preflight"))),
        "release-gate.sh 的严格模式不再跑无 baseline 的 preflight 门(生产姿态零 FAIL)"
    );
}

// ---------------------------------------------------------------------------
// 构建可复现与供应链范围(真机报告 P2-6)
// ---------------------------------------------------------------------------

/// 从 TOML 文本里抠出一个 `[section]` 到下一个 `[`… 段头之间的正文,去掉注释行与空行。
/// 不引 toml 解析库:这里比的是**逐字**一致,解析后再比会把注释差异吞掉——而注释里写着理由。
fn toml_section(text: &str, header: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            inside = t == header;
            continue;
        }
        if inside && !t.is_empty() && !t.starts_with('#') {
            // 行尾注释不参与比较:两边对同一条目的解释允许不同,条目本身不允许。
            let code = t.split(" #").next().unwrap_or(t).trim_end();
            out.push(code.to_string());
        }
    }
    out
}

/// deny.shells.toml 是根 deny.toml 的抄件加显式差异。共享的三段——许可放行表、架构禁用表、
/// 来源——必须逐字一致,否则壳子那份会静默漂成一套更松的策略。差异段(`[graph].targets`、
/// `[advisories].ignore`、`[licenses].exceptions`)每一条必须带理由。
#[test]
fn 两份deny配置的共享策略段逐字一致() {
    let root_cfg = read("deny.toml");
    let shells = read("deny.shells.toml");
    for section in ["[bans]", "[sources]"] {
        assert_eq!(
            toml_section(&root_cfg, section),
            toml_section(&shells, section),
            "deny.shells.toml 的 {section} 与 deny.toml 不一致 —— 壳子的供应链策略漂了"
        );
    }
    // [licenses]:根文件没有 exceptions;壳子多的必须**只是** exceptions,allow 表一致。
    let root_lic: Vec<String> = toml_section(&root_cfg, "[licenses]");
    let shell_lic: Vec<String> = toml_section(&shells, "[licenses]");
    let mut shell_without_exceptions = Vec::new();
    let mut skipping = false;
    for l in &shell_lic {
        if l.starts_with("exceptions = [") {
            skipping = true;
            continue;
        }
        if skipping {
            if l == "]" {
                skipping = false;
            }
            continue;
        }
        shell_without_exceptions.push(l.clone());
    }
    assert_eq!(
        root_lic, shell_without_exceptions,
        "deny.shells.toml 的 [licenses] 除 exceptions 外必须与 deny.toml 一致(不许把 MPL 塞进 allow)"
    );
    assert!(
        !shell_without_exceptions.iter().any(|l| l.contains("MPL")),
        "MPL 只能作为逐 crate 例外出现,不能进 allow 表"
    );
    assert!(
        shell_lic
            .iter()
            .any(|l| l.starts_with("{ name = ") && l.contains("\"MPL-2.0\"")),
        "壳子配置应当以逐 crate exceptions 的形式记录 MPL 依赖(它们确实存在于 Tauri 的树里)"
    );
    // 差异段每条都要有 reason / 文件头有撤销条件。
    let ignores: Vec<&str> = shells
        .lines()
        .filter(|l| l.trim_start().starts_with("{ id = \"RUSTSEC"))
        .collect();
    assert!(
        !ignores.is_empty(),
        "壳子配置的 advisories.ignore 空了?那就该删掉这一节而不是留个空表"
    );
    for l in &ignores {
        assert!(
            l.contains("reason = \""),
            "advisories.ignore 条目缺理由:{l}"
        );
    }
    assert!(
        shells.contains("待法务确认"),
        "MPL 例外必须标明是待法务确认,不是结论"
    );
    assert!(
        toml_section(&root_cfg, "[advisories]")
            .iter()
            .any(|l| l == "ignore = []"),
        "根 deny.toml 的 advisories.ignore 必须保持为空——例外只许出现在壳子那份里并写明理由"
    );
    // Makefile 与 CI 真的对两棵壳子树跑了它。
    let mk = read("Makefile");
    let ci = read(".github/workflows/ci.yml");
    for m in [
        "apps/desktop-macos/src-tauri/Cargo.toml",
        "apps/desktop-windows/src-tauri/Cargo.toml",
    ] {
        assert!(
            mk.contains(&format!(
                "--config deny.shells.toml --manifest-path {m} check"
            )),
            "Makefile check-supply-chain 没有对 {m} 跑 cargo deny"
        );
        assert!(
            ci.contains(&format!("manifest-path: {m}")),
            "CI 没有对 {m} 跑 cargo deny"
        );
    }
}

/// 每个 `uses:` 都钉在 40 位 commit SHA 上,尾注写 tag。浮动 tag 让流水线的一半代码可被第三方随时替换。
#[test]
fn ci的每个action都钉在commit_sha上() {
    let ci = read(".github/workflows/ci.yml");
    let mut seen = 0;
    for (n, line) in ci.lines().enumerate() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("uses: ") else {
            continue;
        };
        if t.starts_with("- uses: ") {
            continue; // handled below via the "- uses:" form
        }
        seen += 1;
        check_pinned(rest, n + 1);
    }
    for (n, line) in ci.lines().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("- uses: ") {
            seen += 1;
            check_pinned(rest, n + 1);
        }
    }
    assert!(
        seen >= 10,
        "ci.yml 里只找到 {seen} 个 uses:?文件结构变了,这条检查可能在空转"
    );
}

fn check_pinned(spec: &str, line_no: usize) {
    let (action, tail) = spec
        .split_once('@')
        .unwrap_or_else(|| panic!("ci.yml:{line_no}: `uses: {spec}` 没有 @ref"));
    let sha = tail.split_whitespace().next().unwrap_or("");
    assert!(
        sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "ci.yml:{line_no}: {action}@{sha} 不是 40 位 commit SHA —— 浮动 tag 让这条流水线的代码由第三方随时可换(P2-6)"
    );
    assert!(
        tail.contains('#'),
        "ci.yml:{line_no}: {action} 钉了 SHA 但没有尾注说明对应的 tag/分支,下次升级没人知道它是什么"
    );
}

/// 工具链与前端运行时都钉了版本;MSRV job 不会被发布工具链的钉子静默带走。
#[test]
fn 工具链与node版本已钉且msrv_job不受发布钉子影响() {
    let tc = read("rust-toolchain.toml");
    let channel = tc
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = \""))
        .map(|r| r.trim_end_matches('"'))
        .expect("rust-toolchain.toml 缺 channel");
    assert!(
        channel.split('.').count() == 3 && channel.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "rust-toolchain.toml 的 channel 必须是具体版本(x.y.z),不是 {channel:?}——\"stable\" 每六周换一次,不是钉子"
    );
    assert!(
        tc.contains("\"rustfmt\"") && tc.contains("\"clippy\""),
        "钉的工具链要带 rustfmt 与 clippy,否则门禁第一步就装不出来"
    );
    let msrv = read("Cargo.toml")
        .lines()
        .find_map(|l| l.trim().strip_prefix("rust-version = \""))
        .map(|r| r.trim_end_matches('"').to_string())
        .expect("Cargo.toml 缺 rust-version");
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains(&format!("RUSTUP_TOOLCHAIN: '{msrv}'")),
        "CI 的 MSRV job 必须用 RUSTUP_TOOLCHAIN={msrv} 压过 rust-toolchain.toml,否则它在发布工具链上跑而名字还叫 MSRV"
    );
    let nvmrc = read(".nvmrc");
    let node_major = nvmrc.trim();
    assert!(!node_major.is_empty());
    assert!(
        ci.contains(&format!("node-version: '{node_major}'")),
        ".nvmrc({node_major})与 CI 的 node-version 不一致"
    );
    // 发布构建脚本:严格按 lock 装依赖,失败即停,不再 `npm install … || true`。
    let build: String = read("apps/desktop-macos/scripts/build-release.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(build.contains("npm ci"), "build-release.sh 不再用 npm ci");
    assert!(
        !build.contains("npm install"),
        "build-release.sh 又出现了 npm install(|| true 吞掉失败后拿旧 node_modules 打包,是 P2-6 点名的形态)"
    );
    // 壳子 Cargo.toml 与根 workspace 一致的三行。
    for m in [
        "apps/desktop-macos/src-tauri/Cargo.toml",
        "apps/desktop-windows/src-tauri/Cargo.toml",
    ] {
        let t = read(m);
        for needle in [
            "license = \"Apache-2.0\"",
            "publish = false",
            &format!("rust-version = \"{msrv}\""),
        ] {
            assert!(t.contains(needle), "{m} 缺 {needle}");
        }
    }
}

/// 每个 Makefile 目标都在 .PHONY 里:一个同名文件出现在仓库根就会让那条目标静默不跑。
#[test]
fn makefile的每个目标都在phony里() {
    let mk = read("Makefile");
    let phony: std::collections::BTreeSet<&str> = mk
        .lines()
        .find(|l| l.starts_with(".PHONY:"))
        .expect("Makefile 没有 .PHONY 行")
        .split_whitespace()
        .skip(1)
        .collect();
    let mut missing = Vec::new();
    for line in mk.lines() {
        if line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            if let Some((name, rest)) = line.split_once(':') {
                let name = name.trim();
                // `MSRV := 1.87` 是变量赋值,不是目标。
                if rest.starts_with('=')
                    || name.contains(' ')
                    || name.contains('=')
                    || name.contains('$')
                {
                    continue;
                }
                if !phony.contains(name) {
                    missing.push(name.to_string());
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "这些 Makefile 目标不在 .PHONY 里:{missing:?}(sim-mac / check-shell-apps 曾漏掉——报告 P2-6)"
    );
}

// ---------------------------------------------------------------------------
// Android 伴生应用的本地化(真机报告 P2-4:launcher 标签英文、繁中资源夹里有简体文案)
// ---------------------------------------------------------------------------

fn android_strings(rel: &str) -> std::collections::BTreeMap<String, String> {
    let xml = read(rel);
    let mut out = std::collections::BTreeMap::new();
    for line in xml.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("<string name=\"") else {
            continue;
        };
        let Some((name, rest)) = rest.split_once("\">") else {
            continue;
        };
        let Some((value, _)) = rest.rsplit_once("</string>") else {
            continue;
        };
        out.insert(name.to_string(), value.to_string());
    }
    out
}

/// 三个 strings.xml 键集合一致;繁中资源夹里没有简体字形;launcher 标签走资源(随语言)。
#[test]
fn android三语词表键一致且繁中无简体字形且launcher标签本地化() {
    let base = "apps/android-companion/app/src/main/res";
    let en = android_strings(&format!("{base}/values/strings.xml"));
    let cn = android_strings(&format!("{base}/values-zh-rCN/strings.xml"));
    let tw = android_strings(&format!("{base}/values-zh-rTW/strings.xml"));
    assert!(en.len() > 20, "英文词表只有 {} 条?解析可能坏了", en.len());
    let en_keys: Vec<&String> = en.keys().collect();
    assert_eq!(
        en_keys,
        cn.keys().collect::<Vec<_>>(),
        "values-zh-rCN 的键与 values 不一致"
    );
    assert_eq!(
        en_keys,
        tw.keys().collect::<Vec<_>>(),
        "values-zh-rTW 的键与 values 不一致"
    );
    // 一批**只在简体里出现**的字形(繁体对应字不同)。不是完整表,是这个词表里最容易漏的那些;
    // 报告点名的两条(显示适配器公钥 / 把它填到…)就是靠 显/适/钥/这/应/签 抓到的。
    const SIMPLIFIED_ONLY: &str = "显适钥这们个为让请设权记录应开关启务护连该态绿线际证择继续传输络监测问题级别导页认备网执确暂结运种电邮账处获键统计视询图检说术数库软钮击时间闭没转败验况动阅读载复错断卫签发响联点";
    let mut leaks = Vec::new();
    for (k, v) in &tw {
        let bad: String = v.chars().filter(|c| SIMPLIFIED_ONLY.contains(*c)).collect();
        if !bad.is_empty() {
            leaks.push(format!("{k}: [{bad}] {v}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "values-zh-rTW 里有简体字形(繁中用户看到的是简体文案):\n{}",
        leaks.join("\n")
    );
    // 简体词表反过来不该出现明显的繁体专用字形(对称检查,防止两份贴反)。
    const TRADITIONAL_ONLY: &str = "顯適鑰這們個為讓請設權記錄應開關啟務護連該態綠線際證擇繼續傳輸絡監測問題級別導頁認備網執確暫結運種電郵賬處獲鍵統計視詢圖檢說術數庫軟鈕擊時間閉沒轉敗驗況動閱讀載復錯斷衛簽發響聯點";
    let mut leaks = Vec::new();
    for (k, v) in &cn {
        let bad: String = v
            .chars()
            .filter(|c| TRADITIONAL_ONLY.contains(*c))
            .collect();
        if !bad.is_empty() {
            leaks.push(format!("{k}: [{bad}] {v}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "values-zh-rCN 里有繁体字形:\n{}",
        leaks.join("\n")
    );
    // launcher 标签必须是资源引用,否则桌面图标下的名字永远是英文。
    let manifest = read("apps/android-companion/app/src/main/AndroidManifest.xml");
    let label_lines: Vec<&str> = manifest
        .lines()
        .filter(|l| l.contains("android:label="))
        .collect();
    assert!(
        !label_lines.is_empty(),
        "AndroidManifest.xml 里没有 android:label"
    );
    for l in label_lines {
        assert!(
            l.contains("android:label=\"@string/"),
            "android:label 必须引用 @string/ 资源(随语言),不能写死英文:{}",
            l.trim()
        );
    }
    assert!(
        en.contains_key("app_title") && !tw["app_title"].is_empty(),
        "app_title 三语都要有"
    );
}
