//! 执行记录的只读投影。先核对完整快照，再关联同一动作的判决、开始与终态。
//! 资料关联不能反推攻击发生；哈希链一致也不等于独立签名归属或防管理员换库。
use anyhow::{bail, ensure, Context, Result};
use guard_audit::{AuditStore, VerifiedAuditSnapshot};
use guard_schema::{Sha256Digest, SourceEntryPoint, SourceSensitivity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub rule_id: String,
    pub layer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source_id_sha256: Sha256Digest,
    pub sensitivity: SourceSensitivity,
    pub status: String,
    pub entry: Option<SourceEntryPoint>,
    pub content_sha256: Option<Sha256Digest>,
    pub parser_version_sha256: Option<Sha256Digest>,
    #[serde(default)]
    pub parent_source_ids_sha256: Vec<Sha256Digest>,
    pub reason_sha256: Option<Sha256Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePackage {
    pub binding_sha256: Sha256Digest,
    pub content_sha256: Sha256Digest,
    pub sequence: u64,
    pub security_floor: u64,
    pub instruction_authority: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    schema: String,
    action_sha256: Sha256Digest,
    request_id_sha256: Sha256Digest,
    policy_version_sha256: Sha256Digest,
    tool_identity_sha256: Sha256Digest,
    target_sha256: Sha256Digest,
    parameters_sha256: Sha256Digest,
    approval_id_sha256: Option<Sha256Digest>,
    outcome: String,
    output_sha256: Option<Sha256Digest>,
    output_truncated: Option<bool>,
    dispatched: Option<bool>,
    side_effects: String,
    source_metadata_version: Option<u16>,
    #[serde(default)]
    sources: Vec<Source>,
    source_coverage: Option<String>,
    rule_package: Option<RulePackage>,
    decision: Option<String>,
    #[serde(default)]
    findings: Vec<Finding>,
    recovery: Option<String>,
}

impl Summary {
    fn validate(&self) -> Result<()> {
        ensure!(self.schema == "gateway_execution_v1", "执行证据结构不支持");
        ensure!(
            self.sources.len() <= 256 && self.findings.len() <= 256,
            "证据集合超限"
        );
        match self.source_metadata_version {
            None => ensure!(
                self.sources.is_empty() && self.source_coverage.is_none(),
                "旧来源字段矛盾"
            ),
            Some(1) => {
                ensure!(
                    self.source_coverage.as_deref()
                        == Some(if self.sources.is_empty() {
                            "missing"
                        } else {
                            "attached"
                        }),
                    "来源覆盖与条目不一致"
                );
                let mut ids = BTreeSet::new();
                for source in &self.sources {
                    ensure!(ids.insert(source.source_id_sha256.as_str()), "重复来源");
                    ensure!(source.parent_source_ids_sha256.len() <= 256, "来源父级超限");
                    match source.status.as_str() {
                        "observed" => ensure!(
                            source.entry.is_some()
                                && source.content_sha256.is_some()
                                && source.parser_version_sha256.is_some()
                                && source.reason_sha256.is_none(),
                            "已观察来源缺少证据"
                        ),
                        "unknown" => ensure!(
                            source.entry.is_none()
                                && source.content_sha256.is_none()
                                && source.parser_version_sha256.is_none()
                                && source.parent_source_ids_sha256.is_empty()
                                && source.reason_sha256.is_some(),
                            "未知来源不能冒充已观察"
                        ),
                        _ => bail!("来源状态不支持"),
                    }
                }
            }
            _ => bail!("来源版本不支持"),
        }
        if let Some(package) = &self.rule_package {
            ensure!(
                package.instruction_authority == "none",
                "规则资料不能授予执行权限"
            );
        }
        for finding in &self.findings {
            let id = &finding.rule_id;
            ensure!(
                id.strip_prefix("sha256:")
                    .is_some_and(|hash| Sha256Digest::new(hash).is_ok())
                    || (!id.is_empty()
                        && id.len() <= 64
                        && id.bytes().all(|b| b.is_ascii_uppercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'-' | b'_'))),
                "规则标识格式无效"
            );
            ensure!(
                ["path", "engine", "signed-rule-package", "unknown"]
                    .contains(&finding.layer.as_str()),
                "规则层不支持"
            );
        }
        Ok(())
    }

    fn binding(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        for name in [
            "approval_id_sha256",
            "outcome",
            "output_sha256",
            "output_truncated",
            "dispatched",
            "side_effects",
            "decision",
            "findings",
            "recovery",
        ] {
            value.as_object_mut().unwrap().remove(name);
        }
        Ok(value)
    }
}

#[derive(Clone, Serialize)]
pub struct Stage {
    pub sequence: usize,
    pub timestamp_ms: i64,
    pub kind: String,
    pub outcome: String,
    pub dispatched: Option<bool>,
    pub side_effects: String,
    pub approval_id_sha256: Option<Sha256Digest>,
}

#[derive(Serialize)]
pub struct ExecutionAction {
    pub id_sha256: String,
    pub session_sha256: String,
    pub action_sha256: Sha256Digest,
    pub request_id_sha256: Sha256Digest,
    pub policy_version_sha256: Sha256Digest,
    pub tool_identity_sha256: Sha256Digest,
    pub target_sha256: Sha256Digest,
    pub parameters_sha256: Sha256Digest,
    pub classification: &'static str,
    pub state: String,
    pub stages: Vec<Stage>,
    pub findings: Vec<Finding>,
    pub sources: Vec<Source>,
    pub rule_package: Option<RulePackage>,
}

#[derive(Serialize)]
pub struct ExecutionLogView {
    pub integrity: &'static str,
    pub signature_attribution: &'static str,
    pub records_verified: usize,
    pub other_records: usize,
    pub head_sha256: String,
    pub actions: Vec<ExecutionAction>,
}

struct Collected {
    action: ExecutionAction,
    binding: Value,
    decision: Option<Summary>,
    started: Option<Summary>,
    finished: Option<Summary>,
    last_sequence: usize,
}

pub fn read_execution_log(path: &Path, passphrase: Option<&str>) -> Result<ExecutionLogView> {
    let store = AuditStore::open_read_only_with_key(path, passphrase)?;
    project_execution_log(&store.verified_snapshot()?)
}

pub fn project_execution_log(snapshot: &VerifiedAuditSnapshot) -> Result<ExecutionLogView> {
    let mut actions: BTreeMap<String, Collected> = BTreeMap::new();
    let mut other_records = 0;
    for (sequence, row) in snapshot.records().iter().enumerate() {
        let suffix = match row.event_type.as_str() {
            "GatewayDecision" => "/decision",
            "GatewayExecutionStarted" => "",
            "GatewayExecutionFinished" => "/result",
            _ => {
                other_records += 1;
                continue;
            }
        };
        ensure!(
            row.platform == "gateway"
                && row.source_app == "agentguard-mcp"
                && row.timestamp_ms >= 0,
            "执行记录宿主元数据不匹配"
        );
        ensure!(row.rule_id == "GATEWAY-EXECUTION", "执行记录标识不匹配");
        let id = row
            .id
            .strip_suffix(suffix)
            .context("执行记录阶段后缀不匹配")?;
        Sha256Digest::new(id)?;
        let session = row
            .agent_session_id
            .as_deref()
            .context("执行记录缺少会话")?;
        Sha256Digest::new(session)?;
        let summary: Summary =
            serde_json::from_str(&row.event_json).context("执行记录正文不支持")?;
        summary.validate()?;
        let binding = summary.binding()?;
        let item = actions.entry(id.into()).or_insert_with(|| Collected {
            action: ExecutionAction {
                id_sha256: id.into(),
                session_sha256: session.into(),
                action_sha256: summary.action_sha256.clone(),
                request_id_sha256: summary.request_id_sha256.clone(),
                policy_version_sha256: summary.policy_version_sha256.clone(),
                tool_identity_sha256: summary.tool_identity_sha256.clone(),
                target_sha256: summary.target_sha256.clone(),
                parameters_sha256: summary.parameters_sha256.clone(),
                classification: "unknown",
                state: "unknown".into(),
                stages: vec![],
                findings: vec![],
                sources: summary.sources.clone(),
                rule_package: summary.rule_package.clone(),
            },
            binding: binding.clone(),
            decision: None,
            started: None,
            finished: None,
            last_sequence: sequence,
        });
        ensure!(
            item.binding == binding && item.action.session_sha256 == session,
            "同一动作的阶段绑定不一致"
        );
        ensure!(item.finished.is_none(), "终态之后又出现同一动作记录");
        match suffix {
            "/decision" => {
                ensure!(
                    item.decision.is_none() && item.started.is_none(),
                    "判决重复或发生于开始之后"
                );
                ensure!(
                    summary.outcome == "decision"
                        && summary.decision.as_deref() == Some(row.action.as_str())
                        && ["execute", "refuse", "needs_confirmation"]
                            .contains(&row.action.as_str()),
                    "判决分类不一致"
                );
                ensure!(
                    summary.dispatched == Some(false)
                        && summary.side_effects == "not_dispatched"
                        && summary.output_sha256.is_none()
                        && summary.output_truncated.is_none()
                        && summary.approval_id_sha256.is_none()
                        && summary.recovery.is_none(),
                    "判决不能充当执行回执"
                );
                item.action.findings = summary.findings.clone();
                item.decision = Some(summary.clone());
            }
            "" => {
                ensure!(
                    item.started.is_none()
                        && row.action == "started"
                        && summary.outcome == "started"
                        && summary.dispatched.is_none()
                        && summary.side_effects == "unknown"
                        && summary.output_sha256.is_none()
                        && summary.output_truncated.is_none()
                        && summary.recovery.is_none(),
                    "开始记录矛盾或重复"
                );
                ensure!(
                    item.decision
                        .as_ref()
                        .is_none_or(|d| d.decision.as_deref() != Some("refuse")),
                    "拒绝之后不能开始同一动作"
                );
                item.started = Some(summary.clone());
            }
            _ => {
                ensure!(
                    row.action == summary.outcome
                        && [
                            "success",
                            "refused",
                            "cancelled",
                            "timed_out",
                            "failed",
                            "unknown"
                        ]
                        .contains(&row.action.as_str()),
                    "终态分类不支持"
                );
                if let Some(started) = &item.started {
                    ensure!(
                        started.approval_id_sha256 == summary.approval_id_sha256,
                        "开始与终态批准绑定不一致"
                    );
                }
                if summary.recovery.is_some() {
                    ensure!(
                        summary.recovery.as_deref()
                            == Some("process_restarted_without_terminal_receipt")
                            && summary.outcome == "unknown"
                            && summary.dispatched.is_none()
                            && summary.side_effects == "unknown"
                            && item.started.is_some()
                            && summary.output_sha256.is_none()
                            && summary.output_truncated.is_none(),
                        "恢复记录不能编造终态"
                    );
                } else {
                    let dispatched = summary.dispatched.context("终态缺少派发状态")?;
                    ensure!(
                        summary.side_effects
                            == if dispatched {
                                "unknown"
                            } else {
                                "not_dispatched"
                            },
                        "派发与副作用声明矛盾"
                    );
                    ensure!(
                        !dispatched || item.started.is_some(),
                        "已派发终态缺少开始记录"
                    );
                    ensure!(
                        summary.outcome != "refused" || !dispatched,
                        "已派发动作不能声称拒绝执行"
                    );
                    ensure!(
                        summary.outcome != "success" || dispatched,
                        "未派发动作不能声称成功"
                    );
                    ensure!(
                        summary.output_sha256.is_some() == summary.output_truncated.is_some()
                            && (!dispatched || summary.output_sha256.is_some()),
                        "输出回执不完整"
                    );
                }
                item.finished = Some(summary.clone());
            }
        }
        if suffix != "/decision" {
            ensure!(
                summary.decision.is_none() && summary.findings.is_empty(),
                "执行阶段不能夹带新判决"
            );
        }
        item.last_sequence = sequence;
        item.action.stages.push(Stage {
            sequence: sequence + 1,
            timestamp_ms: row.timestamp_ms,
            kind: row.event_type.clone(),
            outcome: row.action.clone(),
            dispatched: summary.dispatched,
            side_effects: summary.side_effects.clone(),
            approval_id_sha256: summary.approval_id_sha256,
        });
    }
    let mut ordered: Vec<_> = actions.into_values().collect();
    ordered.sort_by_key(|item| std::cmp::Reverse(item.last_sequence));
    let actions = ordered
        .into_iter()
        .map(|mut item| {
            let (classification, state) =
                if item.decision.is_none() && item.started.is_none() {
                    ("unknown", "terminal_without_prior")
                } else if let Some(terminal) = item.finished {
                    match (terminal.outcome.as_str(), terminal.dispatched) {
                        ("refused", Some(false)) => ("blocked", "refused_before_dispatch"),
                        ("success", Some(true)) => ("record", "tool_returned_effects_unknown"),
                        ("cancelled" | "timed_out" | "failed", Some(false)) => {
                            ("record", "ended_without_dispatch")
                        }
                        _ => ("unknown", "effects_unknown"),
                    }
                } else if item.started.is_some() {
                    ("unknown", "started_without_terminal")
                } else if item.decision.as_ref().is_some_and(|d| {
                    !d.findings.is_empty() || d.decision.as_deref() != Some("execute")
                }) {
                    ("alert", "decision_without_terminal")
                } else {
                    ("unknown", "decision_without_terminal")
                };
            item.action.classification = classification;
            item.action.state = state.into();
            item.action
        })
        .collect();
    Ok(ExecutionLogView {
        integrity: "hash_chain_verified",
        signature_attribution: "not_verified",
        records_verified: snapshot.records().len(),
        other_records,
        head_sha256: snapshot.head_sha256().into(),
        actions,
    })
}

#[cfg(all(test, unix))]
mod tests;
