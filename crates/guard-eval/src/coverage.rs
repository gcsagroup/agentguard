//! Published-attack-surface coverage matrix, verified against the repo.
//!
//! Every paper in the bibliography reports a per-surface vulnerability rate, and
//! the most useful thing an OSS guard can publish is the matching table: which of
//! those surfaces it covers, which it does not, and where its mechanism is weaker
//! than the attack.
//!
//! The important word is **verified**. A hand-maintained matrix drifts from the
//! code within an iteration or two and then quietly overstates coverage — the same
//! failure mode as the score-inflation bugs and the "non-deniable" audit claim.
//! So [`verify`] checks each claim against the repository:
//!
//! * every `rules:` id must exist in the ruleset;
//! * every `scenarios:` file must exist **and pass**;
//! * a `covered` surface must name at least one mechanism and one scenario
//!   (or be explicitly exempted with `note` explaining why, like the host-side
//!   shell gate that is not on the event pipeline);
//! * every **attack** scenario in the corpus must be referenced by some surface, so
//!   an attack scenario cannot be added without deciding which published surface it
//!   demonstrates. Benign scenarios are corpus-level false-positive controls rather
//!   than surfaces, and are counted separately instead of being force-fitted into
//!   the matrix.
//!
//! Unbacked claims are errors, not warnings.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// Mechanism exists and a scenario exercises it.
    Covered,
    /// Mechanism exists but is weaker than the paper's attack, or a proxy for it.
    Partial,
    /// No coverage.
    None,
}

impl CoverageStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Partial => "partial",
            Self::None => "none",
        }
    }

    fn badge(self) -> &'static str {
        match self {
            Self::Covered => "✅ covered",
            Self::Partial => "◐ partial",
            Self::None => "✗ none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperRef {
    pub title: String,
    pub arxiv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Surface {
    pub id: String,
    pub paper: String,
    #[serde(default)]
    pub section: String,
    pub name: String,
    #[serde(default)]
    pub paper_result: String,
    pub status: CoverageStatus,
    #[serde(default)]
    pub mechanism: String,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub scenarios: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrix {
    #[serde(default)]
    pub version: u32,
    pub papers: BTreeMap<String, PaperRef>,
    pub surfaces: Vec<Surface>,
}

impl CoverageMatrix {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read coverage matrix {}", path.as_ref().display()))?;
        serde_yaml::from_str(&raw).context("parse coverage matrix YAML")
    }

    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for s in &self.surfaces {
            *out.entry(s.status.label()).or_default() += 1;
        }
        out
    }
}

/// One problem found while verifying the matrix against the repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageProblem {
    pub surface: String,
    pub detail: String,
}

/// 引擎在代码里发出、而不在 YAML 规则集里的 rule id。
///
/// 覆盖矩阵必须能点名它们。这不是"规则集之外的东西",而是策略表面的另一半 —— 它们的判据
/// 是打分或状态机而不是文本匹配,所以实现在代码里。
///
/// 而 `known_rule_ids` 以前只从 YAML 建,于是矩阵为了通过"这条规则存在"的检查,只能去声称
/// YAML 里那两条同义但**不可能触发**的 `PRIV-001` / `PRIV-003`(它们唯一的匹配谓词是
/// `match_field_categories`,而那个字段在整个仓库里没有任何读者)。也就是矩阵被格式逼着
/// 说了假话。
pub const ENGINE_EMITTED_RULE_IDS: &[&str] = &[
    "PRIV-OP",
    "PRIV-FM",
    "PRIV-TRAP",
    "PRIV-MEM-READ",
    "PRIV-MEM-USE",
    "PRIV-XAPP",
    "FLOW-CONF",
    "FLOW-DERIVE",
    "FLOW-DERIVE-ABUSE",
    "FLOW-DECLASSIFY-REQUEST",
    "FLOW-UNLABELLED",
    "FW-BREAKOUT",
    "FW-TEXT-ANOMALY",
    "SESSION-START",
    "SESSION-END",
    "SESSION-PAUSED",
    "PLAN-MISSING",
    "PLAN-OUT-OF-ORDER",
    "PLAN-OVER-BUDGET",
    "TASK-DRIFT",
    "ADAPTER-REPLAY",
    "APP-UNATTESTED",
    "APP-TRANSITION",
    "APP-NOT-IN-TASK",
    "APP-FOCUS",
    "APP-LOOKALIKE",
    "APP-IDENTITY-CHANGED",
    "APP-SIGNER-MISMATCH",
    "AGENT-KEY-PUBLICLY-KNOWN",
    "ALLOW",
];

/// What the verifier knows about one scenario in the corpus.
#[derive(Debug, Clone)]
pub struct ScenarioFacts {
    pub passed: bool,
    /// False for benign false-positive controls, which are not attack surfaces.
    pub is_attack: bool,
    /// 这条场景是**误报对照**吗(kind: benign)。
    ///
    /// 和 `is_attack` 分开列,因为 `ContractGate` 两者都不是:一个契约闸门既不是攻击面
    /// (它永远会 block,不检验检测能力),也不是误报对照(它**应当** intervene)。
    /// `benign_controls` 计数如果只用 `!is_attack`,就会把契约闸门错当成误报对照。
    pub is_benign: bool,
    /// 这条场景实际发出的判决里出现过的 rule id。
    ///
    /// # 为什么"覆盖"必须包含这个
    ///
    /// `verify` 以前只检查两件事:声称的 rule id **存在于规则集里**,以及声称的场景
    /// **通过**。它从不检查那条场景是否**命中**那条规则 —— 而"覆盖一条规则"的意思正是后者。
    ///
    /// 复核实测:27 条规则里 4 条从未被语料库命中,而**四条都被 surface 声称**,其中两条
    /// 还标着 `covered`:
    ///
    /// ```text
    /// ruleset rules: 27; hit by corpus: 23; NEVER hit: 4
    ///   CRIT-003  claimed by [('aura-critical-node', 'covered')]
    ///   CRIT-005  claimed by [('aura-critical-node', 'covered')]
    ///   PRIV-001  claimed by [('aisees-a3','partial'), ('myphonebench-fm','covered')]
    ///   PRIV-003  claimed by [('aura-ii-semantic-firewall','partial'), ('myphonebench-op','covered')]
    ///
    /// 5 / 30 surfaces 声称了自己场景从未命中的规则。
    /// ```
    ///
    /// 而 PRIV-001 / PRIV-003 比"未被演练"更糟:它们唯一的匹配谓词是
    /// `match_field_categories`,而那个字段在整个仓库里**没有任何读者** —— 它们不可能触发。
    pub rule_hits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub total_surfaces: usize,
    pub covered: usize,
    pub partial: usize,
    pub uncovered: usize,
    /// Scenarios named by at least one surface.
    pub scenarios_referenced: usize,
    /// **Attack** scenarios that no surface claims. An unclaimed attack scenario
    /// means a test exists without a decision about what published surface it
    /// demonstrates.
    pub scenarios_unreferenced: Vec<String>,
    /// Benign false-positive controls in the corpus. Not surfaces, counted here so
    /// the ratio is visible: an attack-only corpus cannot measure over-blocking.
    pub benign_controls: usize,
    pub problems: Vec<CoverageProblem>,
}

impl CoverageReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.scenarios_unreferenced.is_empty()
    }
}

/// Verify every claim in the matrix against the ruleset and the scenario corpus.
pub fn verify(
    matrix: &CoverageMatrix,
    known_rule_ids: &BTreeSet<String>,
    scenarios: &BTreeMap<String, ScenarioFacts>,
) -> CoverageReport {
    let mut problems = Vec::new();
    let mut referenced: BTreeSet<String> = BTreeSet::new();

    for s in &matrix.surfaces {
        if !matrix.papers.contains_key(&s.paper) {
            problems.push(CoverageProblem {
                surface: s.id.clone(),
                detail: format!("unknown paper key '{}'", s.paper),
            });
        }
        for rule in &s.rules {
            if !known_rule_ids.contains(rule) {
                problems.push(CoverageProblem {
                    surface: s.id.clone(),
                    detail: format!("claims rule '{rule}' which is not in the ruleset"),
                });
            }
        }
        for scenario in &s.scenarios {
            referenced.insert(scenario.clone());
            match scenarios.get(scenario) {
                None => problems.push(CoverageProblem {
                    surface: s.id.clone(),
                    detail: format!("claims scenario '{scenario}' which does not exist"),
                }),
                Some(f) if !f.passed => problems.push(CoverageProblem {
                    surface: s.id.clone(),
                    detail: format!("claims scenario '{scenario}' which is currently FAILING"),
                }),
                Some(_) => {}
            }
        }
        // 声称的规则里,至少要有一条被自己的某条场景**真的命中**。
        //
        // 这是"覆盖"这个词的实际含义。没有这一条,一个 surface 可以声称一条从不触发(甚至
        // **不可能**触发)的规则,而门禁全绿 —— 复核在 30 个 surface 里找到 5 个这样的。
        if !s.rules.is_empty() && !s.scenarios.is_empty() {
            let hits: std::collections::BTreeSet<&str> = s
                .scenarios
                .iter()
                .filter_map(|sc| scenarios.get(sc))
                .flat_map(|f| f.rule_hits.iter().map(String::as_str))
                .collect();
            // **逐条**规则检查,不是"至少命中一条"。
            //
            // 用 `any` 的话,一个声称 CRIT-001..005 的 surface 只要 CRIT-001 触发就通过 ——
            // 而复核实测 CRIT-003 和 CRIT-005 在 127 条场景里**一次都没触发过**,却被同一个
            // surface 标成 `covered`。矩阵把规则列成"这个 surface 覆盖了什么",所以每一条都
            // 得有依据。
            let unhit: Vec<&String> = s
                .rules
                .iter()
                .filter(|r| !hits.contains(r.as_str()))
                .collect();
            if !unhit.is_empty() {
                problems.push(CoverageProblem {
                    surface: s.id.clone(),
                    detail: format!(
                        "claims rule(s) {unhit:?} that none of its scenarios ever emits \
                         (they emit {hits:?}) — a coverage claim means the rule fired, not that \
                         it exists in the ruleset"
                    ),
                });
            }
        }
        match s.status {
            CoverageStatus::Covered => {
                if s.mechanism.trim().is_empty() {
                    problems.push(CoverageProblem {
                        surface: s.id.clone(),
                        detail: "status 'covered' with no mechanism named".into(),
                    });
                }
                // A covered surface needs a demonstration. The only acceptable
                // exception is a mechanism that is not on the event pipeline at
                // all, which must say so in `note`.
                if s.scenarios.is_empty() && s.note.trim().is_empty() {
                    problems.push(CoverageProblem {
                        surface: s.id.clone(),
                        detail: "status 'covered' with no scenario and no note explaining why"
                            .into(),
                    });
                }
            }
            CoverageStatus::Partial | CoverageStatus::None => {
                if s.note.trim().is_empty() {
                    problems.push(CoverageProblem {
                        surface: s.id.clone(),
                        detail: format!(
                            "status '{}' must carry a note saying what is missing",
                            s.status.label()
                        ),
                    });
                }
                if matches!(s.status, CoverageStatus::None)
                    && (!s.rules.is_empty() || !s.scenarios.is_empty())
                {
                    problems.push(CoverageProblem {
                        surface: s.id.clone(),
                        detail: "status 'none' but rules/scenarios are claimed".into(),
                    });
                }
            }
        }
    }

    let unreferenced: Vec<String> = scenarios
        .iter()
        .filter(|(k, f)| f.is_attack && !referenced.contains(*k))
        .map(|(k, _)| k.clone())
        .collect();
    let benign_controls = scenarios.values().filter(|f| f.is_benign).count();

    let counts = matrix.counts();
    CoverageReport {
        total_surfaces: matrix.surfaces.len(),
        covered: counts.get("covered").copied().unwrap_or(0),
        partial: counts.get("partial").copied().unwrap_or(0),
        uncovered: counts.get("none").copied().unwrap_or(0),
        scenarios_referenced: referenced.len(),
        scenarios_unreferenced: unreferenced,
        benign_controls,
        problems,
    }
}

/// Render the matrix as Markdown, grouped by paper.
pub fn to_markdown(matrix: &CoverageMatrix, report: &CoverageReport) -> String {
    let mut md = String::new();
    md.push_str("# Published attack surfaces → AgentGuard coverage\n\n");
    md.push_str(
        "Generated by `guard-cli coverage`. Every rule id and scenario named here is \
         verified to exist, and every scenario is verified to pass — an unbacked claim \
         fails the command.\n\n",
    );
    md.push_str(&format!(
        "**{} surfaces: {} covered, {} partial, {} uncovered.** {} attack scenarios are \
         claimed by a surface, alongside {} benign false-positive controls.\n\n",
        report.total_surfaces,
        report.covered,
        report.partial,
        report.uncovered,
        report.scenarios_referenced,
        report.benign_controls,
    ));
    md.push_str(
        "`partial` means the mechanism exists but is weaker than the published attack, or \
         is a proxy for it; the note says how. Our own numbers are never the papers' \
         numbers — see [eval-methodology.md](./eval-methodology.md) for why the \
         attack-miss-rate we report is not the papers' ASR.\n\n",
    );

    for (key, paper) in &matrix.papers {
        let surfaces: Vec<&Surface> = matrix.surfaces.iter().filter(|s| &s.paper == key).collect();
        if surfaces.is_empty() {
            continue;
        }
        md.push_str(&format!(
            "## {} ([arXiv {}](https://arxiv.org/abs/{}))\n\n",
            paper.title, paper.arxiv, paper.arxiv
        ));
        md.push_str("| Surface | Paper result | Status | Mechanism | Rules | Scenarios |\n");
        md.push_str("|---|---|---|---|---|---|\n");
        for s in &surfaces {
            md.push_str(&format!(
                "| **{}**{} | {} | {} | {} | {} | {} |\n",
                escape(&s.name),
                if s.section.is_empty() {
                    String::new()
                } else {
                    format!("<br/><sub>§{}</sub>", escape(&s.section))
                },
                escape(&s.paper_result),
                s.status.badge(),
                escape(&s.mechanism),
                if s.rules.is_empty() {
                    "—".into()
                } else {
                    s.rules
                        .iter()
                        .map(|r| format!("`{r}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if s.scenarios.is_empty() {
                    "—".into()
                } else {
                    s.scenarios.len().to_string()
                },
            ));
        }
        md.push('\n');
        let noted: Vec<&&Surface> = surfaces
            .iter()
            .filter(|s| !s.note.trim().is_empty())
            .collect();
        if !noted.is_empty() {
            md.push_str("Notes:\n\n");
            for s in noted {
                md.push_str(&format!(
                    "- **{}** ({}): {}\n",
                    escape(&s.name),
                    s.status.label(),
                    s.note.trim().replace('\n', " ")
                ));
            }
            md.push('\n');
        }
    }

    if !report.problems.is_empty() {
        md.push_str("## Verification problems\n\n");
        for p in &report.problems {
            md.push_str(&format!("- `{}`: {}\n", p.surface, p.detail));
        }
        md.push('\n');
    }
    if !report.scenarios_unreferenced.is_empty() {
        md.push_str("## Attack scenarios claimed by no surface\n\n");
        for s in &report.scenarios_unreferenced {
            md.push_str(&format!("- `{s}`\n"));
        }
        md.push('\n');
    }
    md
}

fn escape(s: &str) -> String {
    s.trim().replace('\n', " ").replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matrix(yaml: &str) -> CoverageMatrix {
        serde_yaml::from_str(yaml).expect("parse")
    }

    fn rules(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn scenarios(pairs: &[(&str, bool)]) -> BTreeMap<String, ScenarioFacts> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    ScenarioFacts {
                        passed: *v,
                        is_attack: true,
                        is_benign: false,
                        rule_hits: vec!["R-1".to_string()],
                    },
                )
            })
            .collect()
    }

    fn benign(name: &str) -> (String, ScenarioFacts) {
        (
            name.to_string(),
            ScenarioFacts {
                passed: true,
                is_attack: false,
                is_benign: true,
                rule_hits: vec!["R-1".to_string()],
            },
        )
    }

    const BASE: &str = r#"
version: 1
papers:
  p1:
    title: Paper One
    arxiv: "1234.5678"
surfaces:
  - id: s1
    paper: p1
    name: Something
    status: covered
    mechanism: a module
    rules: [R-1]
    scenarios: [scen_a]
"#;

    #[test]
    fn a_fully_backed_claim_verifies() {
        let m = matrix(BASE);
        let r = verify(&m, &rules(&["R-1"]), &scenarios(&[("scen_a", true)]));
        assert!(r.ok(), "{r:?}");
        assert_eq!(r.covered, 1);
    }

    #[test]
    fn a_rule_that_does_not_exist_is_an_error() {
        let m = matrix(BASE);
        let r = verify(&m, &rules(&["OTHER"]), &scenarios(&[("scen_a", true)]));
        assert!(!r.ok());
        assert!(r.problems[0].detail.contains("not in the ruleset"), "{r:?}");
    }

    #[test]
    fn a_scenario_that_does_not_exist_is_an_error() {
        let m = matrix(BASE);
        let r = verify(&m, &rules(&["R-1"]), &scenarios(&[("other", true)]));
        assert!(!r.ok());
        assert!(
            r.problems
                .iter()
                .any(|p| p.detail.contains("does not exist")),
            "{r:?}"
        );
    }

    /// The point of verification: a claim backed by a *failing* scenario is not
    /// coverage.
    #[test]
    fn a_failing_scenario_invalidates_the_claim() {
        let m = matrix(BASE);
        let r = verify(&m, &rules(&["R-1"]), &scenarios(&[("scen_a", false)]));
        assert!(!r.ok());
        assert!(
            r.problems.iter().any(|p| p.detail.contains("FAILING")),
            "{r:?}"
        );
    }

    #[test]
    fn covered_without_a_demonstration_is_an_error() {
        let m = matrix(
            r#"
version: 1
papers: {p1: {title: P, arxiv: "1"}}
surfaces:
  - id: s1
    paper: p1
    name: X
    status: covered
    mechanism: a module
"#,
        );
        let r = verify(&m, &rules(&[]), &scenarios(&[]));
        assert!(!r.ok());
        assert!(
            r.problems
                .iter()
                .any(|p| p.detail.contains("no scenario and no note")),
            "{r:?}"
        );
    }

    /// A mechanism that is not on the event pipeline (the host-side shell gate) may
    /// be `covered` with no scenario, provided it says why.
    #[test]
    fn covered_with_a_note_instead_of_a_scenario_is_allowed() {
        let m = matrix(
            r#"
version: 1
papers: {p1: {title: P, arxiv: "1"}}
surfaces:
  - id: s1
    paper: p1
    name: X
    status: covered
    mechanism: a host-side gate
    note: not on the event pipeline, unit-tested in its own crate
"#,
        );
        let r = verify(&m, &rules(&[]), &scenarios(&[]));
        assert!(r.ok(), "{r:?}");
    }

    #[test]
    fn partial_and_none_must_explain_themselves() {
        for status in ["partial", "none"] {
            let m = matrix(&format!(
                r#"
version: 1
papers: {{p1: {{title: P, arxiv: "1"}}}}
surfaces:
  - id: s1
    paper: p1
    name: X
    status: {status}
"#
            ));
            let r = verify(&m, &rules(&[]), &scenarios(&[]));
            assert!(!r.ok(), "{status} without a note must fail");
            assert!(
                r.problems
                    .iter()
                    .any(|p| p.detail.contains("must carry a note")),
                "{r:?}"
            );
        }
    }

    /// "No coverage" and "here are the rules that cover it" cannot both be true.
    #[test]
    fn none_with_claimed_rules_is_contradictory() {
        let m = matrix(
            r#"
version: 1
papers: {p1: {title: P, arxiv: "1"}}
surfaces:
  - id: s1
    paper: p1
    name: X
    status: none
    note: nothing yet
    rules: [R-1]
"#,
        );
        let r = verify(&m, &rules(&["R-1"]), &scenarios(&[]));
        assert!(!r.ok());
        assert!(
            r.problems
                .iter()
                .any(|p| p.detail.contains("rules/scenarios are claimed")),
            "{r:?}"
        );
    }

    /// An unclaimed *attack* scenario is a gap in the matrix, not a free pass: it
    /// means a test was added without deciding which published surface it shows.
    #[test]
    fn unreferenced_attack_scenarios_are_reported() {
        let m = matrix(BASE);
        let r = verify(
            &m,
            &rules(&["R-1"]),
            &scenarios(&[("scen_a", true), ("orphan", true)]),
        );
        assert!(!r.ok());
        assert_eq!(r.scenarios_unreferenced, vec!["orphan".to_string()]);
    }

    /// Benign controls are not surfaces. Forcing them into the matrix would be
    /// bookkeeping theatre, so they are counted separately and do not fail the run.
    #[test]
    fn benign_controls_are_counted_not_demanded() {
        let m = matrix(BASE);
        let mut s = scenarios(&[("scen_a", true)]);
        s.extend([benign("benign_one"), benign("benign_two")]);
        let r = verify(&m, &rules(&["R-1"]), &s);
        assert!(r.ok(), "{r:?}");
        assert_eq!(r.benign_controls, 2);
        assert!(r.scenarios_unreferenced.is_empty());
    }

    #[test]
    fn unknown_paper_key_is_an_error() {
        let m = matrix(
            r#"
version: 1
papers: {p1: {title: P, arxiv: "1"}}
surfaces:
  - id: s1
    paper: nope
    name: X
    status: none
    note: n/a
"#,
        );
        let r = verify(&m, &rules(&[]), &scenarios(&[]));
        assert!(r
            .problems
            .iter()
            .any(|p| p.detail.contains("unknown paper")));
    }

    #[test]
    fn markdown_names_every_surface_and_its_status() {
        let m = matrix(BASE);
        let r = verify(&m, &rules(&["R-1"]), &scenarios(&[("scen_a", true)]));
        let md = to_markdown(&m, &r);
        assert!(md.contains("Paper One"));
        assert!(md.contains("Something"));
        assert!(md.contains("covered"));
        assert!(md.contains("1234.5678"));
    }
}
