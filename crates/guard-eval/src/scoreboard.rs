//! Eval scoreboard JSON + static HTML export.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runner::{EvalReport, ScenarioResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardEntry {
    pub scenario_id: String,
    pub passed: bool,
    pub rule_hits: Vec<String>,
    pub decisions: Vec<String>,
    pub privacy_composite: Option<f32>,
    /// `|D|` — OP/TR/FM dimensions the scenario actually exercised.
    pub dimensions_evaluated: u8,
    pub task_success: Option<bool>,
    pub privacy_qualified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardReport {
    pub generated_at: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    /// MyPhoneBench PQSR(τ) over scenarios declaring a task outcome.
    pub pqsr: Option<f32>,
    pub pqsr_tau: f32,
    pub pqsr_tasks: usize,
    /// Tasks excluded from `pqsr` because they reached `|D| = 0`. Reported so a
    /// shrinking denominator cannot masquerade as a rising score.
    pub pqsr_unmeasured: usize,
    /// Paired coverage/utility metrics. Reported together on purpose: either alone
    /// makes a useless guard look perfect.
    pub attacks: usize,
    pub attack_misses: usize,
    pub attack_miss_rate: Option<f32>,
    pub benign: usize,
    pub benign_interventions: usize,
    pub false_positive_rate: Option<f32>,
    pub results: Vec<ScoreboardEntry>,
}

impl ScoreboardReport {
    pub fn from_eval(report: &EvalReport) -> Self {
        Self {
            generated_at: unix_timestamp(),
            total: report.total,
            passed: report.passed,
            failed: report.failed,
            pqsr: report.pqsr,
            pqsr_tau: report.pqsr_tau,
            pqsr_tasks: report.pqsr_tasks,
            pqsr_unmeasured: report.pqsr_unmeasured,
            attacks: report.attacks,
            attack_misses: report.attack_misses,
            attack_miss_rate: report.attack_miss_rate(),
            benign: report.benign,
            benign_interventions: report.benign_interventions,
            false_positive_rate: report.false_positive_rate(),
            results: report
                .results
                .iter()
                .map(ScoreboardEntry::from_scenario_result)
                .collect(),
        }
    }
}

impl ScoreboardEntry {
    pub fn from_scenario_result(r: &ScenarioResult) -> Self {
        Self {
            scenario_id: r.scenario_id.clone(),
            passed: r.passed,
            rule_hits: extract_rule_hits(&r.decisions),
            decisions: r.decisions.clone(),
            privacy_composite: r.privacy_composite,
            dimensions_evaluated: r.dimensions_evaluated,
            task_success: r.task_success,
            privacy_qualified: r.privacy_qualified,
        }
    }
}

fn extract_rule_hits(decisions: &[String]) -> Vec<String> {
    let mut hits = Vec::new();
    for d in decisions {
        if let Some((rule, _)) = d.split_once(':') {
            if !hits.contains(&rule.to_string()) {
                hits.push(rule.to_string());
            }
        }
    }
    hits
}

pub fn write_scoreboard_json(report: &ScoreboardReport, path: impl AsRef<Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path.as_ref(), json)
        .with_context(|| format!("write scoreboard JSON to {}", path.as_ref().display()))?;
    Ok(())
}

pub fn write_scoreboard_html(report: &ScoreboardReport, path: impl AsRef<Path>) -> Result<()> {
    let mut rows = String::new();
    for e in &report.results {
        let status = if e.passed { "PASS" } else { "FAIL" };
        let status_class = if e.passed { "pass" } else { "fail" };
        let rules = e.rule_hits.join(", ");
        let composite = match (e.privacy_composite, e.dimensions_evaluated) {
            (_, 0) => "n/a".into(),
            (Some(c), d) => format!("{c:.3} (|D|={d})"),
            (None, _) => "—".into(),
        };
        let qualified = match e.privacy_qualified {
            Some(true) => "yes",
            Some(false) => "no",
            None => "—",
        };
        rows.push_str(&format!(
            r#"    <tr class="{status_class}">
      <td>{scenario_id}</td>
      <td class="status">{status}</td>
      <td>{rules}</td>
      <td>{composite}</td>
      <td>{qualified}</td>
    </tr>
"#,
            scenario_id = html_escape(&e.scenario_id),
            status = status,
            status_class = status_class,
            rules = html_escape(&rules),
            composite = html_escape(&composite),
            qualified = qualified,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard Eval Scoreboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1117; color: #e6e6e6; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
    .meta {{ color: #9aa0a6; margin-bottom: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 960px; }}
    th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #2a2f3a; }}
    th {{ color: #9aa0a6; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }}
    tr.pass .status {{ color: #3ddc84; }}
    tr.fail .status {{ color: #ff6b6b; font-weight: 600; }}
    .summary {{ margin-bottom: 1rem; }}
    .summary span {{ margin-right: 1.5rem; }}
  </style>
</head>
<body>
  <h1>AgentGuard Eval Scoreboard</h1>
  <p class="meta">Generated {generated_at}</p>
  <div class="summary">
    <span>Total: <strong>{total}</strong></span>
    <span>Passed: <strong>{passed}</strong></span>
    <span>Failed: <strong>{failed}</strong></span>
    <span>PQSR(&tau;={pqsr_tau:.2}): <strong>{pqsr}</strong> over {pqsr_tasks} task(s); {pqsr_unmeasured} excluded (|D|=0)</span>
    <span>Attack miss rate: <strong>{miss_rate}</strong> ({attack_misses}/{attacks})</span>
    <span>False positives: <strong>{fp_rate}</strong> ({benign_interventions}/{benign})</span>
  </div>
  <p class="meta">Miss rate is not the papers' ASR — deterministic corpus, no agent
  in the loop. It is reported next to the false-positive rate because either number
  alone makes a useless guard look perfect.</p>
  <table>
    <thead>
      <tr>
        <th>Scenario</th>
        <th>Status</th>
        <th>Rule hits</th>
        <th>Privacy composite</th>
        <th>Privacy-qualified</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
</body>
</html>
"#,
        generated_at = html_escape(&report.generated_at),
        total = report.total,
        passed = report.passed,
        failed = report.failed,
        pqsr_tau = report.pqsr_tau,
        pqsr = report
            .pqsr
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "n/a".into()),
        pqsr_tasks = report.pqsr_tasks,
        pqsr_unmeasured = report.pqsr_unmeasured,
        miss_rate = report
            .attack_miss_rate
            .map(|v| format!("{:.1}%", v * 100.0))
            .unwrap_or_else(|| "n/a".into()),
        attack_misses = report.attack_misses,
        attacks = report.attacks,
        fp_rate = report
            .false_positive_rate
            .map(|v| format!("{:.1}%", v * 100.0))
            .unwrap_or_else(|| "n/a".into()),
        benign_interventions = report.benign_interventions,
        benign = report.benign,
        rows = rows,
    );

    std::fs::write(path.as_ref(), html)
        .with_context(|| format!("write scoreboard HTML to {}", path.as_ref().display()))?;
    Ok(())
}

fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
