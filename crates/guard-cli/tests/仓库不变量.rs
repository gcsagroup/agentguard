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

/// 前端不允许再出现 `innerHTML =` 赋值。
///
/// 审计行里的 `human_message` / `source_app` 有一部分是**受监控方能影响**的
/// (窗口标题、URL、表单标签)。以前那一行是模板字符串塞进 innerHTML,于是一个把
/// 窗口标题改成 `<img src=x onerror=...>` 的 agent 能在守卫自己的界面里执行脚本。
///
/// 这条测试盯的是**那一类写法**,不是那一行代码 —— 修好一处但下次又写回来的话,
/// 只有类级别的检查拦得住。
#[test]
#[allow(non_snake_case)]
fn 前端不再出现innerHTML赋值() {
    let files = [
        "apps/desktop-macos/src/main.js",
        "apps/desktop-windows/src/main.js",
        "apps/extension-chromium/content.js",
        "apps/extension-chromium/popup.js",
    ];
    let mut 违规 = Vec::new();
    for f in files {
        let p = root().join(f);
        if !p.exists() {
            continue;
        }
        for (i, line) in read(f).lines().enumerate() {
            // 只看赋值,不看注释里提到这个词。
            let code = line.split("//").next().unwrap_or("");
            if code.contains("innerHTML") && code.contains('=') && !code.contains("==") {
                违规.push(format!("{f}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        违规.is_empty(),
        "前端又出现了 innerHTML 赋值。用 textContent 或建 DOM 节点 —— \
         这些字符串里有受监控方能影响的文本:\n{}",
        违规.join("\n")
    );
}

/// 两个 Tauri 外壳都必须配限制性 CSP。
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
