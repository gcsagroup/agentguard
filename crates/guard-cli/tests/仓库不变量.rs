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
    const 前端文件数: usize = 10;
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
