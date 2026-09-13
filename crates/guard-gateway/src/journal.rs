//! 网关执行日志：先落盘再发出动作，崩溃后的未完成记录转为未知，绝不自动重试。
//! 仅保存宿主生成ID、固定枚举与内容摘要，不保存命令正文、路径、输出或批准凭据。
use crate::gate::Outcome;
use crate::ExecOutput;
use anyhow::{bail, Context, Result};
use guard_audit::{AuditRecord, AuditStore};
use guard_schema::{ActionSnapshot, ExecutionOutcome, SourceObservation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::fs::File;
use std::path::Path;

pub struct ExecutionJournal {
    store: AuditStore,
    _lock: File,
    healthy: Cell<bool>,
    recovered_unknown: usize,
}

impl Drop for ExecutionJournal {
    fn drop(&mut self) {
        // 其他线程可能正处于 fork→exec 窗口。只 close 会让临时继承的fd延长flock；
        // 宿主结束写入时显式解锁，使重启不依赖另一个子进程何时完成exec。
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn audit_rule_id(id: &str) -> String {
    // 精确匹配内置标识，不能让自定义规则借用 SHELL- 等前缀将正文写入日志。
    let builtin = matches!(
        id,
        "ALLOW"
            | "GATEWAY-ENGINE-ERROR"
            | "AGENT-SESSION-MISMATCH"
            | "SHELL-METACHAR"
            | "SHELL-DENIED-ACTION"
            | "SHELL-DENIED-TARGET"
            | "SHELL-CONFIRM"
            | "SHELL-ALLOWLIST"
            | "SHELL-UNKNOWN-TOOL"
            | "SHELL-PATH-SENSITIVE"
            | "SHELL-PATH-UNPROVABLE"
            | "SHELL-PATH-UNSCOPED"
            | "SHELL-PATH-OUTSIDE"
            | "FS-NO-PATH"
            | "FS-UNPROVABLE"
            | "FS-SENSITIVE"
            | "FS-UNSCOPED"
            | "FS-OUTSIDE"
            | "SCOPE-DATA"
            | "SCOPE-HOST"
            | "SCOPE-OVER-REQUEST"
            | "SESSION-PAUSED"
            | "SESSION-RESTART"
            | "SESSION-START"
            | "SESSION-END"
            | "PLAN-MISSING"
            | "TASK-DRIFT"
            | "INTEL-INJECT"
            | "INTEL-DOMAIN"
            | "FLOW-UNKNOWN"
            | "FLOW-NO-ID"
            | "FLOW-DERIVE-ABUSE"
            | "FLOW-DERIVE"
            | "FLOW-DECLASSIFY-BAD"
            | "FLOW-DECLASSIFY-REQUEST"
    ) || include_str!("../../guard-schema/rules/p0_rules.yaml")
        .lines()
        .any(|line| line.trim_start().strip_prefix("- id: ") == Some(id));
    let bounded = !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if builtin && bounded {
        id.into()
    } else {
        format!("sha256:{}", sha256(id.as_bytes()))
    }
}

impl ExecutionJournal {
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path.parent().context("审计数据库缺少父目录")?;
        std::fs::create_dir_all(parent)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let lock = options.open(path.with_extension("gateway-lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("此网关审计日志已有写入者，拒绝并发恢复");
            }
        }
        #[cfg(not(unix))]
        bail!("当前网关执行日志锁尚未验证该宿主平台");
        let store = AuditStore::open_runtime(path, None)?;
        let chain = store.verify_chain()?;
        if !chain.ok {
            bail!("审计链校验失败，禁止继续执行");
        }
        let mut journal = Self {
            store,
            _lock: lock,
            healthy: Cell::new(true),
            recovered_unknown: 0,
        };
        let unfinished = journal.store.unfinished_gateway_actions()?;
        for record in unfinished {
            let mut summary: Value =
                serde_json::from_str(&record.event_json).context("未完成执行记录格式无效")?;
            summary["outcome"] = json!("unknown");
            summary["recovery"] = json!("process_restarted_without_terminal_receipt");
            summary["side_effects"] = json!("unknown");
            let recovered = AuditRecord {
                id: format!("{}/result", record.id),
                timestamp_ms: now_ms(),
                event_type: "GatewayExecutionFinished".into(),
                action: "unknown".into(),
                human_message: "进程重启后未找到执行终态，结果未知，未自动重试".into(),
                event_json: serde_json::to_string(&summary)?,
                ..record
            };
            journal.append(&recovered)?;
            journal.recovered_unknown += 1;
        }
        Ok(journal)
    }

    pub fn status(&self) -> Value {
        json!({"persistent":true, "healthy":self.healthy.get(), "recovered_unknown":self.recovered_unknown,
            "contents":"ids_and_digests_only", "automatic_retry":false})
    }

    /// 判决在批准等待之前持久化；正文与自定义规则标识不能进入审计原文。
    pub fn decided(&self, action: &ActionSnapshot, outcome: &Outcome) -> Result<()> {
        let classification = match outcome {
            Outcome::Execute { .. } => "execute",
            Outcome::Refuse { .. } => "refuse",
            Outcome::NeedsConfirmation { .. } => "needs_confirmation",
        };
        let findings: Vec<_> = outcome.findings().iter().map(|finding| {
            json!({"rule_id": audit_rule_id(&finding.rule_id),
                "layer":match finding.layer.as_str() { "path" => "path", "engine" => "engine", _ => "unknown" }})
        }).collect();
        let mut record = self.record(action, None, None, None)?;
        let mut summary: Value = serde_json::from_str(&record.event_json)?;
        summary["outcome"] = json!("decision");
        summary["decision"] = json!(classification);
        summary["findings"] = json!(findings);
        summary["dispatched"] = json!(false);
        summary["side_effects"] = json!("not_dispatched");
        record.id.push_str("/decision");
        record.event_type = "GatewayDecision".into();
        record.action = classification.into();
        record.human_message = "工具网关判决；仅保存分类与规则标识，尚未执行".into();
        record.event_json = serde_json::to_string(&summary)?;
        self.append(&record)
    }

    /// 获得执行资格后必须先提交开始记录；恢复时只检查真实开始记录。
    pub fn started(&self, action: &ActionSnapshot, approval_id: Option<&str>) -> Result<()> {
        self.append(&self.record(action, approval_id, None, None)?)
    }

    /// 无论成功、拒绝还是中止都记录终态；输出只保留摘要。
    pub fn finished(
        &self,
        action: &ActionSnapshot,
        approval_id: Option<&str>,
        outcome: ExecutionOutcome,
        output: Option<&ExecOutput>,
    ) -> Result<()> {
        self.append(&self.record(action, approval_id, Some(outcome), output)?)
    }

    fn append(&self, record: &AuditRecord) -> Result<()> {
        if !self.healthy.get() {
            bail!("审计写入已失败，禁止新动作");
        }
        if let Err(error) = self.store.append(record) {
            self.healthy.set(false);
            return Err(error).context("执行审计不能持久化，禁止继续执行");
        }
        Ok(())
    }

    fn record(
        &self,
        action: &ActionSnapshot,
        approval_id: Option<&str>,
        outcome: Option<ExecutionOutcome>,
        output: Option<&ExecOutput>,
    ) -> Result<AuditRecord> {
        let spec = action.spec();
        // 标识符虽然已经过schema校验，日志仍不接受任意外部字符串伪装成宿主ID。
        let action_hash = sha256(&action.canonical_bytes());
        let state = outcome
            .map(|s| serde_json::to_value(s).unwrap())
            .unwrap_or(json!("started"));
        // 保留来源绑定与限制；父 ID、解析器及未知原因可能带任意文本，仍只落摘要。
        let sources: Vec<Value> = spec
            .sources
            .iter()
            .map(|source| {
                let mut value = json!({
                    "source_id_sha256": sha256(source.source_id.as_str().as_bytes()),
                    "sensitivity": source.sensitivity,
                });
                match &source.observation {
                    SourceObservation::Observed {
                        entry,
                        content_sha256,
                        parser_version,
                        parent_source_ids,
                    } => {
                        value["status"] = json!("observed");
                        value["entry"] = json!(entry);
                        value["content_sha256"] = json!(content_sha256);
                        value["parser_version_sha256"] = json!(sha256(parser_version.as_bytes()));
                        value["parent_source_ids_sha256"] = json!(parent_source_ids
                            .iter()
                            .map(|id| sha256(id.as_str().as_bytes()))
                            .collect::<Vec<_>>());
                    }
                    SourceObservation::Unknown { reason } => {
                        value["status"] = json!("unknown");
                        value["reason_sha256"] = json!(sha256(reason.as_bytes()));
                    }
                }
                value
            })
            .collect();
        let summary = json!({"schema":"gateway_execution_v1", "action_sha256":action_hash,
            "source_metadata_version":1, "sources":sources,
            "source_coverage":if spec.sources.is_empty() { "missing" } else { "attached" },
            "request_id_sha256":sha256(spec.request_id.as_str().as_bytes()),
            "policy_version_sha256":sha256(spec.policy_version.as_str().as_bytes()),
            "tool_identity_sha256":sha256(&serde_json::to_vec(&spec.tool)?),
            "target_sha256":sha256(spec.target.as_bytes()),
            "parameters_sha256":sha256(&serde_json::to_vec(&spec.parameters)?),
            "approval_id_sha256":approval_id.map(|id|sha256(id.as_bytes())),
            "outcome":state,
            "output_sha256":output.map(|o|sha256(o.detail.as_bytes())),
            "output_truncated":output.map(|o|o.truncated),
            "dispatched":if outcome.is_some() { Some(output.is_some_and(|o|o.dispatched)) } else { None },
            // 命令退出码不能证明所有业务副作用；实际快照差异/业务核对单独验收。
            "side_effects": if outcome.is_some() && !output.is_some_and(|o|o.dispatched) { "not_dispatched" } else { "unknown" }});
        Ok(AuditRecord {
            id: if outcome.is_some() {
                format!("{}/result", sha256(spec.action_id.as_str().as_bytes()))
            } else {
                sha256(spec.action_id.as_str().as_bytes())
            },
            timestamp_ms: now_ms(),
            platform: "gateway".into(),
            event_type: if outcome.is_some() {
                "GatewayExecutionFinished"
            } else {
                "GatewayExecutionStarted"
            }
            .into(),
            source_app: "agentguard-mcp".into(),
            agent_session_id: Some(sha256(spec.session_id.as_str().as_bytes())),
            rule_id: "GATEWAY-EXECUTION".into(),
            severity: "Info".into(),
            action: state.as_str().unwrap().into(),
            human_message: "工具网关执行回执；正文仅保存摘要".into(),
            evidence_ref: None,
            user_decision: None,
            event_json: serde_json::to_string(&summary)?,
            attributed_agent: None,
        })
    }
}

#[cfg(all(test, not(unix)))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn 未验证日志锁的平台拒绝创建可执行审计会话() {
        let directory = std::env::temp_dir().join(format!(
            "ag-journal-unsupported-{}",
            crate::browser_bridge::token()
        ));
        let database = directory.join("audit.db");
        let error = match ExecutionJournal::open(&database) {
            Ok(_) => panic!("未验证平台不得打开可执行审计日志"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "当前网关执行日志锁尚未验证该宿主平台");
        assert!(!database.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use guard_schema::{ActionSpec, ToolIdentity, ValidatedId, EXECUTION_CONTRACT_VERSION};
    use rand::RngCore;

    fn temp_dir() -> std::path::PathBuf {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let root = std::env::temp_dir().join(format!("agd-journal-{}", sha256(&bytes)));
        std::fs::create_dir(&root).unwrap();
        root
    }
    fn action() -> ActionSnapshot {
        let id = |s| ValidatedId::new(s).unwrap();
        ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("host-session-1"),
            action_id: id("host-action-1"),
            request_id: id("host-request-1"),
            policy_version: id("host-policy-1"),
            tool: ToolIdentity {
                service: "gateway".into(),
                name: "write_file".into(),
                version: "1".into(),
            },
            target: "/private/workspace/secret-path.txt".into(),
            parameters: json!({"contents":"AGD_PRIVATE_CONTENT_MUST_NOT_PERSIST"}),
            issued_at_ms: now_ms(),
            expires_at_ms: now_ms() + 60_000,
            nonce: "a9".repeat(16),
            sources: vec![],
        })
        .unwrap()
    }

    #[test]
    fn 来源约束跨日志重开保留且正文和来源描述不落盘() {
        use guard_schema::{SourceEntryPoint, SourceSensitivity};
        let root = temp_dir();
        let path = root.join("audit.db");
        let mut collector = crate::provenance::SourceCollector::default();
        let source = collector
            .observe(
                b"PRIVATE_SOURCE_BODY",
                SourceEntryPoint::FileRead,
                "PRIVATE_PARSER_VERSION",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let source_id = source.source_id.clone();
        let mut spec = action().spec().clone();
        spec.sources = vec![source];
        let snapshot = ActionSnapshot::new(spec).unwrap();
        {
            let journal = ExecutionJournal::open(&path).unwrap();
            journal.started(&snapshot, None).unwrap();
        }
        // 未完成动作重启转未知，来源敏感度与内容摘要仍绑定原动作。
        let reopened = ExecutionJournal::open(&path).unwrap();
        assert_eq!(reopened.recovered_unknown, 1);
        let rows = reopened.store.list_recent(10).unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert!(!row.event_json.contains("PRIVATE_SOURCE_BODY"));
            assert!(!row.event_json.contains("PRIVATE_PARSER_VERSION"));
            assert!(!row.event_json.contains(source_id.as_str()));
            let value: Value = serde_json::from_str(&row.event_json).unwrap();
            assert_eq!(value["sources"][0]["sensitivity"], "sensitive");
            assert_eq!(value["sources"][0]["entry"], "file_read");
            assert_eq!(
                value["sources"][0]["content_sha256"],
                sha256(b"PRIVATE_SOURCE_BODY")
            );
            assert_eq!(value["source_coverage"], "attached");
        }
        assert!(reopened.store.verify_chain().unwrap().ok);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 执行前后记录持久且正文凭据均不落盘() {
        let root = temp_dir();
        let path = root.join("audit.db");
        let journal = ExecutionJournal::open(&path).unwrap();
        let action = action();
        journal
            .started(&action, Some("PRIVATE_APPROVAL_ID"))
            .unwrap();
        journal
            .finished(
                &action,
                Some("PRIVATE_APPROVAL_ID"),
                ExecutionOutcome::Success,
                Some(&ExecOutput::ok("AGD_PRIVATE_OUTPUT")),
            )
            .unwrap();
        assert!(journal
            .store
            .unfinished_gateway_actions()
            .unwrap()
            .is_empty());
        assert!(journal.store.verify_chain().unwrap().ok);
        let text = journal.store.export_jsonl(20).unwrap();
        for secret in [
            "PRIVATE_APPROVAL_ID",
            "AGD_PRIVATE_CONTENT_MUST_NOT_PERSIST",
            "AGD_PRIVATE_OUTPUT",
            "secret-path.txt",
            &"a9".repeat(16),
        ] {
            assert!(!text.contains(secret), "审计泄漏敏感正文：{secret}");
        }
        drop(journal);
        let reopened = ExecutionJournal::open(&path).unwrap();
        assert_eq!(reopened.recovered_unknown, 0);
        assert_eq!(reopened.store.list_recent(20).unwrap().len(), 2);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 判决保留真实规则标识但不保存理由原文和未知字段() {
        let root = temp_dir();
        let path = root.join("audit.db");
        let journal = ExecutionJournal::open(&path).unwrap();
        let action = action();
        journal
            .decided(
                &action,
                &Outcome::Refuse {
                    findings: vec![
                        crate::gate::Finding {
                            rule_id: "SHELL-PATH-SENSITIVE".into(),
                            layer: "path".into(),
                            severity: "AGD_PRIVATE_SEVERITY".into(),
                            message: "AGD_PRIVATE_REASON".into(),
                        },
                        crate::gate::Finding {
                            rule_id: "AGD_PRIVATE_CUSTOM_RULE_ID".into(),
                            layer: "AGD_PRIVATE_LAYER".into(),
                            severity: "high".into(),
                            message: "AGD_PRIVATE_REASON_2".into(),
                        },
                        crate::gate::Finding {
                            rule_id: "SHELL-/private/secret-path.txt".into(),
                            layer: "engine".into(),
                            severity: "high".into(),
                            message: "AGD_PRIVATE_REASON_3".into(),
                        },
                        crate::gate::Finding {
                            rule_id: "SHELL-AGD_PRIVATE_SECRET".into(),
                            layer: "path".into(),
                            severity: "high".into(),
                            message: "AGD_PRIVATE_REASON_4".into(),
                        },
                        crate::gate::Finding {
                            rule_id: "CRIT-001".into(),
                            layer: "engine".into(),
                            severity: "critical".into(),
                            message: "AGD_PRIVATE_REASON_5".into(),
                        },
                    ],
                },
            )
            .unwrap();
        let rows = journal.store.list_recent(20).unwrap();
        assert_eq!(rows.len(), 1);
        let record = &rows[0];
        assert_eq!(
            record.id,
            format!(
                "{}/decision",
                sha256(action.spec().action_id.as_str().as_bytes())
            )
        );
        assert_eq!(record.event_type, "GatewayDecision");
        let summary: Value = serde_json::from_str(&record.event_json).unwrap();
        assert_eq!(summary["decision"], "refuse");
        assert_eq!(summary["outcome"], "decision");
        assert_eq!(summary["dispatched"], false);
        assert_eq!(summary["side_effects"], "not_dispatched");
        assert_eq!(summary["findings"][0]["rule_id"], "SHELL-PATH-SENSITIVE");
        assert_eq!(summary["findings"][0]["layer"], "path");
        assert_eq!(
            summary["findings"][1]["rule_id"],
            format!("sha256:{}", sha256(b"AGD_PRIVATE_CUSTOM_RULE_ID"))
        );
        assert_eq!(summary["findings"][1]["layer"], "unknown");
        assert_eq!(
            summary["findings"][2]["rule_id"],
            format!("sha256:{}", sha256(b"SHELL-/private/secret-path.txt"))
        );
        assert_eq!(
            summary["findings"][3]["rule_id"],
            format!("sha256:{}", sha256(b"SHELL-AGD_PRIVATE_SECRET"))
        );
        assert_eq!(summary["findings"][4]["rule_id"], "CRIT-001");
        let exported = journal.store.export_jsonl(20).unwrap();
        for private in ["AGD_PRIVATE", "secret-path.txt", &"a9".repeat(16)] {
            assert!(!exported.contains(private), "判决日志泄漏：{private}");
        }
        assert!(journal.store.verify_chain().unwrap().ok);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 等待批准时重启不视为执行开始且不恢复批准() {
        let root = temp_dir();
        let path = root.join("audit.db");
        let journal = ExecutionJournal::open(&path).unwrap();
        journal
            .decided(&action(), &Outcome::NeedsConfirmation { findings: vec![] })
            .unwrap();
        assert!(journal
            .store
            .unfinished_gateway_actions()
            .unwrap()
            .is_empty());
        drop(journal);
        let reopened = ExecutionJournal::open(&path).unwrap();
        assert_eq!(reopened.recovered_unknown, 0);
        let records = reopened.store.list_recent(20).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "GatewayDecision");
        assert_eq!(records[0].action, "needs_confirmation");
        assert_eq!(reopened.status()["automatic_retry"], false);
        assert!(reopened.store.verify_chain().unwrap().ok);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 重启只将未完成动作记为未知且不会重复恢复() {
        let root = temp_dir();
        let path = root.join("audit.db");
        let journal = ExecutionJournal::open(&path).unwrap();
        journal.started(&action(), None).unwrap();
        drop(journal);
        let reopened = ExecutionJournal::open(&path).unwrap();
        assert_eq!(reopened.recovered_unknown, 1);
        let terminal = reopened.store.list_recent(1).unwrap().remove(0);
        assert_eq!(terminal.action, "unknown");
        assert!(terminal.human_message.contains("未自动重试"));
        assert!(reopened
            .store
            .unfinished_gateway_actions()
            .unwrap()
            .is_empty());
        assert!(reopened.store.verify_chain().unwrap().ok);
        drop(reopened);
        let again = ExecutionJournal::open(&path).unwrap();
        assert_eq!(again.recovered_unknown, 0);
        assert_eq!(again.store.list_recent(20).unwrap().len(), 2);
        drop(again);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 存活写入者不能被另一个进程恢复() {
        let root = temp_dir();
        let path = root.join("audit.db");
        let first = ExecutionJournal::open(&path).unwrap();
        assert!(ExecutionJournal::open(&path).is_err());
        drop(first);
        let second = ExecutionJournal::open(&path).unwrap();
        drop(second);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 审计写入失败后锁存故障() {
        let root = temp_dir();
        let path = root.join("audit.db");
        drop(AuditStore::open(&path).unwrap());
        let journal = ExecutionJournal {
            store: AuditStore::open_read_only(&path).unwrap(),
            _lock: File::create(root.join("test-lock")).unwrap(),
            healthy: Cell::new(true),
            recovered_unknown: 0,
        };
        assert!(journal.started(&action(), None).is_err());
        assert!(!journal.healthy.get());
        assert!(journal.started(&action(), None).is_err());
        assert_eq!(journal.store.list_recent(20).unwrap().len(), 0);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }
}
