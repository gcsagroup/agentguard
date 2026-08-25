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

/// 前端不允许出现任何把字符串当成标记或代码解释的写法。
///
/// 审计行里的 `human_message` / `source_app` 有一部分是**受监控方能影响**的
/// (窗口标题、URL、表单标签)。以前那一行是模板字符串塞进 innerHTML,于是一个把
/// 窗口标题改成 `<img src=x onerror=...>` 的 agent 能在守卫自己的界面里执行脚本。
///
/// # 这条测试自己被复核过一轮
///
/// 第一版有三个毛病,而它们正是这条测试要防的那类毛病:
///
///   1. **文件清单是写死的四个**,漏掉了两个 `i18n.js`(里面有 `applyTranslations()`
///      在遍历 `[data-i18n]` 赋 `textContent` —— 下一个"加点富文本"的人最可能动的
///      就是那里)、`background.js` 和三个 HTML。
///   2. **`if !p.exists() { continue; }`** —— 文件一改名,这条检查对它就静默失效了。
///      `make check-shells` 为同一个失效方式专门放了一个 `n < 3` 的数量下限,
///      这条测试没有。
///   3. **只禁 `innerHTML` 这一个词**。`insertAdjacentHTML`、`outerHTML`、
///      `document.write`、`eval`、`new Function`、`setAttribute('onclick', ...)`、
///      `srcdoc`、`createContextualFragment` 全都放行。
///
/// 现在改成**扫目录**、有数量下限、禁一整类 sink。
#[test]
#[allow(non_snake_case)]
fn 前端不出现把字符串当代码的写法() {
    // 每一条都是一个真的注入 sink。加东西进来要说清它为什么算。
    const SINKS: &[(&str, &str)] = &[
        ("innerHTML", "把字符串当 HTML 解析"),
        ("outerHTML", "同上"),
        ("insertAdjacentHTML", "同上"),
        ("document.write", "同上"),
        ("createContextualFragment", "同上"),
        ("srcdoc", "把字符串当一整个文档"),
        ("eval(", "把字符串当代码"),
        ("new Function", "同上"),
        ("dangerouslySetInnerHTML", "同上"),
        (".cssText", "把字符串当 CSS 解析"),
        ("insertRule", "同上"),
    ];
    // 内联事件处理器属性。单独一类,因为它们是 `on` + 事件名的形状。
    const INLINE_HANDLERS: &[&str] = &[
        "onclick=",
        "onerror=",
        "onload=",
        "onmouseover=",
        "onfocus=",
    ];

    let 前端目录 = [
        "apps/desktop-macos/src",
        "apps/desktop-windows/src",
        "apps/extension-chromium",
    ];
    let mut 扫到的 = 0usize;
    let mut 违规 = Vec::new();
    for dir in 前端目录 {
        let d = root().join(dir);
        assert!(
            d.is_dir(),
            "前端目录不见了:{dir} —— 目录一改名,这条检查就静默失效"
        );
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "html" | "mjs") {
                continue;
            }
            扫到的 += 1;
            let text = std::fs::read_to_string(&path).unwrap();
            let rel = path.strip_prefix(root()).unwrap().display().to_string();
            for (i, line) in text.lines().enumerate() {
                // 去掉注释:注释里提到这些词是允许的(下面这些注释本身就提到了)。
                let code = line.split("//").next().unwrap_or("");
                for (sink, why) in SINKS {
                    if code.contains(sink) {
                        违规.push(format!("{rel}:{}: {sink}({why}) — {}", i + 1, line.trim()));
                    }
                }
                let lower = code.to_lowercase();
                for h in INLINE_HANDLERS {
                    if lower.contains(h) {
                        违规.push(format!("{rel}:{}: 内联事件处理器 {h}", i + 1));
                    }
                }
            }
        }
    }
    // 数量下限:目录改名 / 文件搬走时这条检查不能静默变成空转。
    // `make check-shells` 为同一个失效方式放了 `n < 3`;这条测试以前没有。
    assert!(
        扫到的 >= 9,
        "只扫到 {扫到的} 个前端文件,像是目录结构变了 —— 这条检查可能已经在空转"
    );
    assert!(
        违规.is_empty(),
        "前端出现了把字符串当标记/代码解释的写法(共扫描 {扫到的} 个文件)。\n\
         用 textContent 或建 DOM 节点 —— 这些字符串里有受监控方能影响的文本:\n{}",
        违规.join("\n")
    );
}

/// 两个 Tauri 外壳都必须配限制性 CSP。/// 两个 Tauri 外壳都必须配限制性 CSP。
///
/// `"csp": null` 是 Tauri 的默认,意思是**不设** CSP。它和 innerHTML 那条是两道
/// 独立的防线:任何一道都可能被将来某次改动绕过,所以两道都要在。
///
/// 这条测试原来只该有 macOS 一个 —— 上一次评审只报了 macOS。Windows 那份
/// 是同一个洞,一起在这里钉住。
#[test]
fn 两个外壳都配了限制性csp() {
    for app in ["desktop-macos", "desktop-windows"] {
        let conf = read(&format!("apps/{app}/src-tauri/tauri.conf.json"));
        let v: serde_json::Value =
            serde_json::from_str(&conf).expect("tauri.conf.json 不是合法 JSON");
        let csp = &v["app"]["security"]["csp"];
        assert!(
            csp.is_string(),
            "{app} 的 csp 是 {csp} —— null 意思是不设 CSP"
        );
        let csp = csp.as_str().unwrap();
        for 必须有 in ["default-src 'none'", "object-src 'none'", "base-uri 'none'"] {
            assert!(csp.contains(必须有), "{app} 的 CSP 缺 `{必须有}`:{csp}");
        }
        assert!(
            !csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"),
            "{app} 的 CSP 带 unsafe-*,等于把这道防线让开:{csp}"
        );
        // 几个具体指令要钉住。不钉的话,有人往 script-src 里加一个 CDN 域名,
        // 上面那些断言全都还是绿的。
        for 必须 in ["script-src 'self'", "style-src 'self'"] {
            assert!(csp.contains(必须), "{app} 的 CSP 里 `{必须}` 变了:{csp}");
        }
        assert!(
            !csp.contains("http://") || csp.contains("http://ipc.localhost"),
            "{app} 的 CSP 里出现了 ipc.localhost 之外的 http:// 来源:{csp}"
        );
    }

    // 页面里不许再出现内联 <style>。
    //
    // 写在 tauri.conf.json 里的是 `style-src 'self'`(没有 'unsafe-inline'),而内联
    // <style> 之所以仍能渲染,是因为 Tauri 构建时注入 nonce、运行时把
    // `'nonce-<随机>'` 追加进 style-src —— 也就是**实际生效的 CSP 和写的那份不一样**。
    // 后果是审计问题:读配置的人会得出"内联样式被挡住"的错误结论。
    // 这一条是一次独立复核指出来的。
    for app in ["desktop-macos", "desktop-windows"] {
        let html = read(&format!("apps/{app}/src/index.html"));
        assert!(
            !html.contains("<style"),
            "{app}/src/index.html 里有内联 <style> —— 搬去 styles.css,\
             否则写在配置里的 CSP 和实际生效的那份不一致"
        );
    }
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

/// `make check` 里的每个 target,CI 里都要有东西在跑它。
///
/// # 为什么需要这条
///
/// 一条只在本地跑的门禁,是靠人记得的门禁。这不是假想:`cargo fmt --check` 和
/// workspace 级的 `cargo clippy` 两条都**不在** CI 里(clippy 只覆盖
/// win-adapter),结果是 68 个文件漂出 rustfmt 规范,而其中还藏着一条 clippy 错误 ——
/// 那一行的旧折行让它一直没被报出来。
///
/// 一次性把两边接上很容易;**保持**接上才是难的。所以这条测试比对的是两个清单,
/// 而不是某几条具体的命令。
///
/// # 它查什么、不查什么
///
/// 查:`make check` 依赖的每个 target 名,在 CI 里能不能找到(直接 `make <target>`,
/// 或者一条等效的命令)。
/// 不查:CI 跑得对不对、在哪个平台跑。那些看得见的差别由别的东西负责。
#[test]
fn ci覆盖make_check的每个target() {
    let makefile = read("Makefile");
    let ci = read(".github/workflows/ci.yml");

    let check_line = makefile
        .lines()
        .find(|l| l.starts_with("check:"))
        .expect("Makefile 里找不到 `check:` 这条规则");
    let targets: Vec<&str> = check_line
        .trim_start_matches("check:")
        .split_whitespace()
        .collect();
    assert!(
        targets.len() >= 5,
        "`check:` 只依赖 {} 个 target,像是被删空了:{check_line}",
        targets.len()
    );

    // 某些 target 在 CI 里是用等效命令跑的,而不是 `make <target>`。
    // 这张表是**白名单**,每一条都要说清等效物是什么 —— 否则它就变成一个
    // "忘了接 CI 就往这里加一行"的口子。
    let 等效物: &[(&str, &str)] = &[
        // `make test` == `cargo test --workspace`
        ("test", "cargo test --workspace"),
        // `make check-fmt` == `cargo fmt --all --check`
        ("check-fmt", "cargo fmt --all --check"),
        // `make check-clippy` == workspace clippy(CI 的 lint job)
        ("check-clippy", "cargo clippy --workspace --all-targets"),
        // `make check-supply-chain` == CI 里的 cargo-deny-action。
        // 用 action 而不是 `make`,是因为它自带公告库缓存;本地那条 target 走
        // 已装好的 cargo-deny。两边读的是同一份 deny.toml,所以配置不会分叉。
        ("check-supply-chain", "cargo-deny-action"),
        // `make eval` == 直接跑 eval 子命令
        ("eval", "eval --scenarios eval/scenarios"),
        // scoreboard / leaderboard / sim-capture 在 CI 里是分步跑的
        ("scoreboard", "scoreboard"),
        ("leaderboard", "leaderboard"),
        ("sim-capture", "sim-capture"),
    ];

    let mut 缺的 = Vec::new();
    for t in &targets {
        let 直接 = ci.contains(&format!("make {t}"));
        let 等效 = 等效物
            .iter()
            .find(|(name, _)| name == t)
            .map(|(_, cmd)| ci.contains(cmd))
            .unwrap_or(false);
        if !直接 && !等效 {
            缺的.push(*t);
        }
    }
    assert!(
        缺的.is_empty(),
        "这些 `make check` 的 target 在 CI 里没有对应的步骤:{:?}\n\
         只在本地跑的门禁是靠人记得的门禁。要么把它加进 .github/workflows/ci.yml,\n\
         要么在本测试的「等效物」表里说清它在 CI 里对应哪条命令。",
        缺的
    );
}

/// CI 里不允许再用 `|| true` 之类的方式吞掉门禁的退出码。
///
/// preflight 那一步以前就是 `cargo run ... preflight || true`,和 Makefile 里那个
/// 前缀减号同一个毛病:报告照打,但**新出现**的 FAIL 不拦任何人。
///
/// 允许的例外要写在 CI 里紧邻那一行的注释里,并且加进下面这张表 —— 目的是让
/// "吞掉一个失败"这件事必须改测试,于是它会出现在 diff 里被人看见。
#[test]
fn ci里没有被吞掉的退出码() {
    let ci = read(".github/workflows/ci.yml");
    let mut 违规 = Vec::new();
    for (i, line) in ci.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("");
        if code.contains("|| true") || code.contains("continue-on-error: true") {
            违规.push(format!("{}: {}", i + 1, line.trim()));
        }
    }
    assert!(
        违规.is_empty(),
        "CI 里有步骤在吞掉自己的退出码:\n{}\n\
         一个不会让构建变红的检查,和一个不存在的检查没有区别。\n\
         如果确实需要(比如只是打印一份报告),把它和真正的门禁拆成两步。",
        违规.join("\n")
    );
}
