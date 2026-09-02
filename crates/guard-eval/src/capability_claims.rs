//! 面向用户的**能力声明** → 兑现代码 + 证明测试,对着仓库核对(X-2)。
//!
//! `coverage.rs` 把**学术攻击面**映射到规则和场景,并拒绝无依据的声称。这个模块把同一条
//! 纪律扩到**商店文案 / 平台能力矩阵 / 端点表**这些**面向用户**的声明上:每一条声明都要挂
//!
//! * 它印在哪份用户可见的文档里(`source.doc` + 一段必须出现在那份文档里的锚文本);
//! * 由哪段代码兑现(`mechanism`,描述性);
//! * 由哪条(些)测试证明它**真的会触发**(`proven_by`:测试函数名 + 所在源文件)。
//!
//! # 被机器核对的是什么(以及**不是**什么)
//!
//! [`verify`] 核对两件硬事实,任一不成立就是错误(不是警告):
//!
//! 1. **声明真的印在那份文档里。** `source.anchor` 必须作为子串出现在 `source.doc` 里。
//!    这挡住"映射表声称我们宣传了 X,而文档里根本没有 X"——反过来,文档改了措辞、把某条
//!    能力删了,而映射表没跟上,也会红。
//! 2. **每条证明测试真的存在。** 证明测试的签名必须出现在它声明的源文件里——Rust 是 `fn <名>(`,
//!    JS/TS(浏览器扩展的 node 测试)是 `test("<名>"`(按扩展名自动选,见 `test_needle`)。删掉 /
//!    改名一条证明测试而不更新映射,就红——和 `coverage.rs`、X-1 的入站面清册同一招。
//!
//! `mechanism`(哪段代码兑现)是**描述性**的,和 `coverage.rs` 的 `mechanism` 一样**不**被
//! 机器核对——把它也做成"符号必须存在"会给一层假精确(符号改名不代表能力没了)。真正钉住
//! "能力还在"的是那条**测试**是否还在、是否还绿。
//!
//! # 边界(如实)
//!
//! 这张表是**人工维护**的:它**不能**自动发现"你又加了一条对用户的承诺却没测"(那需要从
//! 文档里做自然语言抽取,超出范围)。它能保证的是:**已登记**的声明,其证明测试不会被后续
//! 改动悄悄摘掉,其文案不会在文档里被悄悄改没。新加一条用户声明时,把它登进
//! `eval/capability-claims.yaml` 并配一条证明测试——否则这张表覆盖不到它,这条边界是显式的。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 声明印在哪份用户可见文档里,以及一段必须出现在其中的锚文本。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSource {
    /// 相对仓库根的文档路径(如 `docs/platform-matrix.md`)。
    pub doc: String,
    /// 必须作为子串出现在 `doc` 里的锚文本。选一段**具体到这条能力**的措辞,别选泛词。
    pub anchor: String,
}

/// 一条证明该声明"真的会触发"的测试。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingTest {
    /// 测试名(可含中文)。核对方式见 `test_needle`:Rust 找 `fn <test>(`,JS 找 `test("<test>"`。
    pub test: String,
    /// 相对仓库根的源文件路径。
    pub file: String,
}

/// 一条面向用户的能力声明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaim {
    pub id: String,
    /// 人读的一句话声明(通常就是文档里那句话的转述)。
    pub claim: String,
    /// 归属的能力域 / 平台(仅分组展示用,如 `android`、`audit`、`shell`)。
    #[serde(default)]
    pub area: String,
    pub source: ClaimSource,
    /// 由哪段代码兑现——描述性,不被机器核对(见模块文档)。
    #[serde(default)]
    pub mechanism: String,
    /// 证明它会触发的测试。**至少一条**,否则是无依据声称。
    #[serde(default)]
    pub proven_by: Vec<ProvingTest>,
    /// 可选:这条声明有什么已知限制 / 未覆盖的方面(如实)。
    #[serde(default)]
    pub note: String,
}

/// 能力声明注册表。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsRegistry {
    #[serde(default)]
    pub version: u32,
    pub claims: Vec<CapabilityClaim>,
}

impl ClaimsRegistry {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read capability claims {}", path.as_ref().display()))?;
        serde_yaml::from_str(&raw).context("parse capability claims YAML")
    }
}

/// 按源文件类型选"这条测试存在"的匹配串。
///
/// Rust 测试是 `fn <名>(`;JS/TS(node 测试用 `apps/extension-chromium/scripts/*.mjs` 那套
/// `test("<名>", …)` 的形态)是 `test("<名>"`。两种都精确到**具名**那条测试的签名,所以删/改名
/// 任一条仍然会红——不退化成"文件里随便有这个串就算"的弱匹配。
fn test_needle(file: &str, test: &str) -> String {
    let is_js = file.ends_with(".mjs") || file.ends_with(".js") || file.ends_with(".ts");
    if is_js {
        format!("test(\"{test}\"")
    } else {
        format!("fn {test}(")
    }
}

/// 核对时发现的一个问题。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProblem {
    pub claim: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsReport {
    pub total_claims: usize,
    /// 证明测试的去重总数(一条测试可能证明多条声明)。
    pub distinct_tests: usize,
    pub problems: Vec<ClaimProblem>,
}

impl ClaimsReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// 对着仓库核对每一条声明。
///
/// `read_file(rel_path)` 返回该相对路径的文件内容,读不到(不存在)返回 `None`。把文件读取
/// 抽成闭包是为了让单测能喂一张假文件表,而 CLI / 集成测试喂真实文件系统。
pub fn verify(
    registry: &ClaimsRegistry,
    read_file: impl Fn(&str) -> Option<String>,
) -> ClaimsReport {
    let mut problems = Vec::new();
    let mut distinct_tests = std::collections::BTreeSet::new();

    // id 不能重复,否则一条登记能冒充覆盖两条。
    let mut seen_ids = std::collections::BTreeSet::new();
    for c in &registry.claims {
        if !seen_ids.insert(c.id.clone()) {
            problems.push(ClaimProblem {
                claim: c.id.clone(),
                detail: format!("duplicate claim id '{}'", c.id),
            });
        }
    }

    for c in &registry.claims {
        // 1. 声明真的印在那份文档里。
        match read_file(&c.source.doc) {
            None => problems.push(ClaimProblem {
                claim: c.id.clone(),
                detail: format!("source doc '{}' does not exist", c.source.doc),
            }),
            Some(content) => {
                if !content.contains(&c.source.anchor) {
                    problems.push(ClaimProblem {
                        claim: c.id.clone(),
                        detail: format!(
                            "anchor text not found in '{}' — the doc no longer makes this claim \
                             (or the wording changed): {:?}",
                            c.source.doc, c.source.anchor
                        ),
                    });
                }
            }
        }

        // 2. 至少要有一条证明测试(反空洞)。
        if c.proven_by.is_empty() {
            problems.push(ClaimProblem {
                claim: c.id.clone(),
                detail: "no proving test — an unbacked user-facing claim".into(),
            });
        }

        // 3. 每条证明测试真的存在。
        for pt in &c.proven_by {
            distinct_tests.insert((pt.file.clone(), pt.test.clone()));
            match read_file(&pt.file) {
                None => problems.push(ClaimProblem {
                    claim: c.id.clone(),
                    detail: format!("proving-test file '{}' does not exist", pt.file),
                }),
                Some(content) => {
                    if !content.contains(&test_needle(&pt.file, &pt.test)) {
                        problems.push(ClaimProblem {
                            claim: c.id.clone(),
                            detail: format!(
                                "proving test `{}` not found in '{}' — deleted, renamed, or the \
                                 map is stale?",
                                pt.test, pt.file
                            ),
                        });
                    }
                }
            }
        }
    }

    ClaimsReport {
        total_claims: registry.claims.len(),
        distinct_tests: distinct_tests.len(),
        problems,
    }
}

/// 把注册表渲染成 Markdown,按 `area` 分组。
pub fn to_markdown(registry: &ClaimsRegistry, report: &ClaimsReport) -> String {
    let mut md = String::new();
    md.push_str("# 面向用户的能力声明 → 兑现代码 + 证明测试\n\n");
    md.push_str(
        "由 `guard-cli capability-claims` 生成。每条声明的**锚文本**都被核对确实印在所列文档里,\
         每条**证明测试**都被核对确实存在——任一不成立,命令失败。`mechanism` 是描述性的,不被\
         机器核对;钉住\"能力还在\"的是那条测试。\n\n",
    );
    md.push_str(&format!(
        "**{} 条声明,{} 条去重证明测试。**\n\n",
        report.total_claims, report.distinct_tests
    ));

    let mut areas: Vec<&str> = registry.claims.iter().map(|c| c.area.as_str()).collect();
    areas.sort_unstable();
    areas.dedup();
    for area in areas {
        let claims: Vec<&CapabilityClaim> =
            registry.claims.iter().filter(|c| c.area == area).collect();
        if claims.is_empty() {
            continue;
        }
        md.push_str(&format!(
            "## {}\n\n",
            if area.is_empty() { "(未分组)" } else { area }
        ));
        md.push_str("| 声明 | 印在 | 兑现 | 证明测试 |\n");
        md.push_str("|---|---|---|---|\n");
        for c in &claims {
            let tests = c
                .proven_by
                .iter()
                .map(|t| format!("`{}`", t.test))
                .collect::<Vec<_>>()
                .join("<br/>");
            md.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                escape(&c.claim),
                escape(&c.source.doc),
                escape(&c.mechanism),
                tests
            ));
        }
        md.push('\n');
        let noted: Vec<&&CapabilityClaim> = claims
            .iter()
            .filter(|c| !c.note.trim().is_empty())
            .collect();
        if !noted.is_empty() {
            md.push_str("说明:\n\n");
            for c in noted {
                md.push_str(&format!(
                    "- **{}**:{}\n",
                    escape(&c.claim),
                    c.note.trim().replace('\n', " ")
                ));
            }
            md.push('\n');
        }
    }

    if !report.problems.is_empty() {
        md.push_str("## 核对问题\n\n");
        for p in &report.problems {
            md.push_str(&format!("- `{}`: {}\n", p.claim, p.detail));
        }
        md.push('\n');
    }
    while md.ends_with("\n\n") {
        md.pop();
    }
    md
}

fn escape(s: &str) -> String {
    s.trim().replace('\n', " ").replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn reg(yaml: &str) -> ClaimsRegistry {
        serde_yaml::from_str(yaml).expect("parse")
    }

    /// 一张假文件表,键是相对路径,值是内容。
    fn files(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |p: &str| map.get(p).cloned()
    }

    const BASE: &str = r#"
version: 1
claims:
  - id: c1
    claim: We detect X
    area: demo
    source: { doc: docs/store.md, anchor: "we detect X" }
    mechanism: the x module
    proven_by:
      - { test: x_is_detected, file: crates/x/src/lib.rs }
"#;

    #[test]
    fn 依据齐全的声明通过() {
        let r = verify(
            &reg(BASE),
            files(&[
                ("docs/store.md", "blah blah we detect X here"),
                (
                    "crates/x/src/lib.rs",
                    "    fn x_is_detected() { assert!(true) }",
                ),
            ]),
        );
        assert!(r.ok(), "{r:?}");
        assert_eq!(r.total_claims, 1);
        assert_eq!(r.distinct_tests, 1);
    }

    #[test]
    fn 锚文本不在文档里是错误() {
        let r = verify(
            &reg(BASE),
            files(&[
                ("docs/store.md", "this doc says nothing of the sort"),
                ("crates/x/src/lib.rs", "    fn x_is_detected() {}"),
            ]),
        );
        assert!(!r.ok());
        assert!(
            r.problems
                .iter()
                .any(|p| p.detail.contains("anchor text not found")),
            "{r:?}"
        );
    }

    #[test]
    fn 证明测试不存在是错误() {
        let r = verify(
            &reg(BASE),
            files(&[
                ("docs/store.md", "we detect X"),
                ("crates/x/src/lib.rs", "    fn something_else() {}"),
            ]),
        );
        assert!(!r.ok());
        assert!(
            r.problems.iter().any(|p| p.detail.contains("not found in")),
            "{r:?}"
        );
    }

    #[test]
    fn 源文档不存在是错误() {
        let r = verify(
            &reg(BASE),
            files(&[("crates/x/src/lib.rs", "    fn x_is_detected() {}")]),
        );
        assert!(!r.ok());
        assert!(
            r.problems
                .iter()
                .any(|p| p.detail.contains("does not exist")),
            "{r:?}"
        );
    }

    #[test]
    fn 没有证明测试是无依据声称() {
        let y = r#"
version: 1
claims:
  - id: c1
    claim: We detect X
    source: { doc: docs/store.md, anchor: "we detect X" }
"#;
        let r = verify(&reg(y), files(&[("docs/store.md", "we detect X")]));
        assert!(!r.ok());
        assert!(
            r.problems.iter().any(|p| p.detail.contains("unbacked")),
            "{r:?}"
        );
    }

    #[test]
    fn 重复id是错误() {
        let y = r#"
version: 1
claims:
  - id: dup
    claim: A
    source: { doc: d, anchor: a }
    proven_by: [{ test: t, file: f }]
  - id: dup
    claim: B
    source: { doc: d, anchor: a }
    proven_by: [{ test: t, file: f }]
"#;
        let r = verify(&reg(y), files(&[("d", "a"), ("f", "fn t() {}")]));
        assert!(!r.ok());
        assert!(
            r.problems.iter().any(|p| p.detail.contains("duplicate")),
            "{r:?}"
        );
    }

    #[test]
    fn js证明测试按test签名匹配() {
        // 一条 JS 证明测试:needle 是 `test("名"`,不是 `fn 名(`。
        let y = r#"
version: 1
claims:
  - id: js1
    claim: browser gate
    source: { doc: docs/x.md, anchor: "gate" }
    proven_by:
      - { test: 付款CTA拦下, file: apps/ext/scripts/gate.test.mjs }
"#;
        let ok = verify(
            &reg(y),
            files(&[
                ("docs/x.md", "the gate"),
                (
                    "apps/ext/scripts/gate.test.mjs",
                    "test(\"付款CTA拦下\", () => {})",
                ),
            ]),
        );
        assert!(ok.ok(), "{ok:?}");
        // 改名(fn 风格 needle 不会误命中 JS)→ 红。
        let bad = verify(
            &reg(y),
            files(&[
                ("docs/x.md", "the gate"),
                ("apps/ext/scripts/gate.test.mjs", "fn 付款CTA拦下() {}"),
            ]),
        );
        assert!(!bad.ok(), "JS 文件里 fn 形态不该算命中 test 名");
    }

    #[test]
    fn markdown_列出声明与测试() {
        let r = verify(
            &reg(BASE),
            files(&[
                ("docs/store.md", "we detect X"),
                ("crates/x/src/lib.rs", "fn x_is_detected() {}"),
            ]),
        );
        let md = to_markdown(&reg(BASE), &r);
        assert!(md.contains("We detect X"));
        assert!(md.contains("x_is_detected"));
        assert!(md.contains("demo"));
        assert!(md.ends_with('\n'));
        assert!(!md.ends_with("\n\n"));
    }
}
