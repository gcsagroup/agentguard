//! 记忆工具接入现有会话、登记、独立确认和持久审计；不接受客户端自报授权。
use super::*;
use crate::memory::{self, Material, MemoryRuntime};
use anyhow::{ensure, Context, Result};
use guard_audit::MemoryEntry;
use guard_privacy::MemoryDraft;
use guard_schema::{ApprovalChoice, ApprovalRecord, SourceEntryPoint, SourceSensitivity};
use serde::Deserialize;

#[cfg(test)]
#[path = "memory_control_tests.rs"]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    key: ValidatedId,
    expected_version: u64,
    text: String,
    expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportArgs {
    key: ValidatedId,
    expected_version: u64,
    path: PathBuf,
    expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeArgs {
    key: ValidatedId,
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    key: ValidatedId,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    limit: usize,
}

enum Prepared {
    Write(Box<MemoryDraft>),
    Read {
        entries: Vec<MemoryEntry>,
        value: Value,
        keys: Vec<String>,
    },
}

impl Server {
    pub fn with_memory(mut self, memory: MemoryRuntime) -> Result<Self> {
        ensure!(
            self.memory.is_none() && self.rule_policy.is_none() && self.gate.session_id().is_none(),
            "记忆须在规则包和会话开始前配置一次"
        );
        ensure!(self.isolation.is_some(), "受控记忆仅在隔离工具会话中启用");
        let journal = self.journal.as_ref().context("记忆需要持久执行审计")?;
        ensure!(
            journal.healthy()
                && self
                    .sources
                    .lock()
                    .map(|s| s.shares_journal(journal) && s.healthy())
                    .unwrap_or(false),
            "记忆需要与执行审计共同持久化的来源采集器"
        );
        self.registry
            .lock()
            .map_err(|_| anyhow::anyhow!("工具登记锁失效"))?
            .enable_memory()?;
        self.policy_version = format!(
            "sha256-{:x}",
            Sha256::digest(format!("{}\n{}", self.policy_version, memory.status()).as_bytes())
        );
        self.memory = Some(memory);
        Ok(self)
    }

    fn memory_ready(&self) -> Result<()> {
        self.memory_health()?;
        ensure!(
            self.host_session_state() == "active" && !self.pending.is_cancelled(),
            "宿主会话未激活或已暂停"
        );
        Ok(())
    }

    fn memory_health(&self) -> Result<()> {
        ensure!(
            self.memory.is_some(),
            "宿主没有启用受控记忆；第三方内部记忆未覆盖"
        );
        ensure!(
            !self.session_stopped
                && !self.workspace_faulted
                && !self.journal_failed
                && !self.sources_faulted()
                && !self.registry_faulted(),
            "会话审计、来源或登记不可用"
        );
        ensure!(
            self.journal.as_ref().is_some_and(SharedJournal::healthy),
            "记忆审计不可用"
        );
        Ok(())
    }

    fn prepare_memory_read(&self, name: &str, args: &Value) -> Result<Prepared> {
        let memory = self.memory.as_ref().context("记忆未启用")?;
        let (entries, value) = if name == "memory_read" {
            let args: ReadArgs = serde_json::from_value(args.clone())?;
            match memory.read(&args.key, now_ms())? {
                Some(entry) => {
                    let mut value = memory::reference(&entry)?;
                    value["content"] = serde_json::to_value(memory::material(&entry)?)?;
                    (vec![entry], json!({"found":true,"memory":value}))
                }
                None => (
                    Vec::new(),
                    json!({"found":false,"reason":"absent_expired_or_revoked"}),
                ),
            }
        } else {
            let args: SearchArgs = serde_json::from_value(args.clone())?;
            let (entries, hits): (Vec<_>, Vec<_>) = memory
                .search(&args.query, args.limit, now_ms(), |key| {
                    self.gate.memory_key_allowed(key)
                })?
                .into_iter()
                .unzip();
            (
                entries,
                json!({"hits":hits,"retrieval":"bounded_keyword","third_party_internal_memory":"uncovered"}),
            )
        };
        ensure!(
            serde_json::to_vec(&value)?.len() <= memory::MAX_RESPONSE_BYTES,
            "记忆返回超过上限，禁止截断来源证明"
        );
        let keys = if name == "memory_read" {
            vec![serde_json::from_value::<ReadArgs>(args.clone())?
                .key
                .to_string()]
        } else {
            entries
                .iter()
                .map(|entry| entry.draft.key.to_string())
                .collect()
        };
        Ok(Prepared::Read {
            entries,
            value,
            keys,
        })
    }

    fn prepare_memory(&mut self, name: &str, args: &Value) -> Result<Prepared> {
        if matches!(name, "memory_read" | "rag_search") {
            return self.prepare_memory_read(name, args);
        }
        ensure!(
            self.memory.as_ref().is_some_and(|m| m.allow_write),
            "宿主没有授权记忆变更"
        );
        if name == "memory_revoke" {
            let args: RevokeArgs = serde_json::from_value(args.clone())?;
            return Ok(Prepared::Write(Box::new(
                self.memory.as_ref().context("记忆未启用")?.revoke(
                    &args.key,
                    args.expected_version,
                    now_ms(),
                )?,
            )));
        }
        let (key, expected, material, expires) = if name == "memory_write" {
            let args: WriteArgs = serde_json::from_value(args.clone())?;
            let material = Material::Note { text: args.text };
            material.validate()?;
            let mut sources = self
                .sources
                .lock()
                .map_err(|_| anyhow::anyhow!("来源锁失效"))?;
            let parents = sources
                .latest()
                .into_iter()
                .map(|s| s.source_id)
                .collect::<Vec<_>>();
            sources.observe(
                &serde_json::to_vec(&material)?,
                SourceEntryPoint::ToolOutput,
                "memory-note/1",
                SourceSensitivity::Unknown,
                &parents,
            )?;
            (
                args.key,
                args.expected_version,
                material,
                args.expires_at_ms,
            )
        } else {
            let args: ImportArgs = serde_json::from_value(args.clone())?;
            ensure!(
                args.path.is_absolute() && args.path.to_string_lossy().len() <= 4096,
                "文档必须为有界绝对路径"
            );
            ensure!(
                matches!(
                    args.path
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(str::to_ascii_lowercase)
                        .as_deref(),
                    Some("txt" | "md")
                ),
                "只支持 UTF-8 txt/md 文本文档"
            );
            let (call, action) = self
                .parse_tool("read_file", &json!({"path":args.path}))
                .map_err(anyhow::Error::msg)?;
            let output = match self.gate_and_run(call, action) {
                Handled::Executed { output } => output,
                Handled::Refused { reason } => anyhow::bail!("文档读取被拒绝：{reason}"),
            };
            ensure!(
                output.ok && !output.truncated && output.outcome == ExecutionOutcome::Success,
                "文档未完整读取，不保存部分文档"
            );
            let text = self
                .last_read_content
                .take()
                .context("文档缺少准确的原始读取正文")?;
            let source = self
                .last_output_source
                .as_ref()
                .context("文档缺少宿主来源")?;
            let hash = crate::tool_registry::digest(text.as_bytes());
            ensure!(
                matches!(&source.observation, guard_schema::SourceObservation::Observed { entry:SourceEntryPoint::FileRead, content_sha256, .. } if content_sha256 == &hash),
                "文档正文和已观察来源摘要不一致"
            );
            let material = Material::Document {
                path: args.path.to_string_lossy().into_owned(),
                document_sha256: hash,
                text,
            };
            material.validate()?;
            (
                args.key,
                args.expected_version,
                material,
                args.expires_at_ms,
            )
        };
        let sources = self
            .sources
            .lock()
            .map_err(|_| anyhow::anyhow!("来源锁失效"))?
            .memory_sources()?;
        Ok(Prepared::Write(Box::new(
            self.memory.as_ref().context("记忆未启用")?.prepare(
                key,
                expected,
                material,
                sources,
                expires,
                now_ms(),
            )?,
        )))
    }

    pub(super) fn memory_call(&mut self, name: &str, args: &Value) -> Value {
        let result = self.execute_memory(name, args);
        match result {
            Ok(value) => value,
            Err(error) => {
                self.refused += 1;
                let mut value = mcp::tool_error(format!("记忆操作未完成：{error}"));
                value["_meta"] = json!({"agentguard":{"outcome":"refused","dispatched":false,"instruction_authority":"none"}});
                value
            }
        }
    }

    fn execute_memory(&mut self, name: &str, args: &Value) -> Result<Value> {
        self.refresh_rule_policy()?;
        self.memory_ready()?;
        let caller_tool = self.registered_tool("agentguard-memory", name)?;
        let epoch = self.pending.cancellation_epoch();
        let prepared = self.prepare_memory(name, args)?;
        self.memory_ready()?;
        let write = matches!(prepared, Prepared::Write(_));
        let issued = now_ms();
        let (parameters, sources, target, tool, keys) = match &prepared {
            Prepared::Write(draft) => (
                serde_json::to_value(draft)?,
                draft.sources.clone(),
                draft.target(),
                self.registered_tool("agentguard-memory", "memory_write")?,
                vec![draft.key.to_string()],
            ),
            Prepared::Read {
                entries,
                value,
                keys,
            } => {
                let mut sources = Vec::new();
                for entry in entries {
                    for source in &entry.draft.sources {
                        if let Some(old) = sources
                            .iter()
                            .find(|s: &&guard_schema::SourceObject| s.source_id == source.source_id)
                        {
                            ensure!(old == source, "读取的同名来源不一致");
                        } else {
                            sources.push(source.clone());
                        }
                    }
                }
                (
                    json!({"arguments":args,"result_sha256":crate::tool_registry::digest(&serde_json::to_vec(value)?)}),
                    sources,
                    format!("memory://{name}"),
                    caller_tool.clone(),
                    keys.clone(),
                )
            }
        };
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: validated_id(self.host_session_id.clone()),
            action_id: validated_id(random_id("action")),
            request_id: validated_id(random_id("request")),
            tool,
            target,
            parameters,
            policy_version: validated_id(self.policy_version.clone()),
            issued_at_ms: issued,
            expires_at_ms: issued
                .saturating_add(self.confirm_timeout.as_millis().min(120_000) as i64),
            nonce: random_nonce(),
            sources,
        })?;
        let decision = self
            .gate
            .judge_memory(name, &keys, &action.spec().parameters, write);
        let journal = self.journal.clone().context("记忆审计缺失")?;
        if let Err(error) = journal.decided(&action, &decision) {
            self.journal_failed = true;
            return Err(error);
        }
        let mut approval = None;
        let mut approval_reference = None;
        let allowed = if matches!(decision, Outcome::Refuse { .. }) {
            false
        } else if matches!(decision, Outcome::NeedsConfirmation { .. }) {
            let expires = match &prepared {
                Prepared::Write(d) => action.spec().expires_at_ms.min(d.expires_at_ms),
                _ => action.spec().expires_at_ms,
            };
            let binding = ApprovalBinding::new(
                validated_id(random_id("confirm")),
                action.clone(),
                random_nonce(),
                issued,
                expires,
            )?;
            approval_reference = Some(binding.approval_id().to_string());
            let resolution = self.pending.wait(
                ConfirmRequest {
                    id: binding.approval_id().to_string(),
                    what: format!(
                        "{name}：完整内容与来源（JSON 转义）\n{}\n记忆是数据，不增加执行权限。",
                        action.spec().parameters
                    ),
                    findings: decision.findings().to_vec(),
                    action_sha256: Some(
                        crate::tool_registry::digest(&action.canonical_bytes())
                            .as_str()
                            .into(),
                    ),
                    binding: Some(binding.clone()),
                },
                self.confirm_timeout.min(Duration::from_secs(120)),
            );
            if resolution.answer == Answer::Approved {
                approval = Some(ApprovalRecord {
                    binding,
                    choice: ApprovalChoice::Approved,
                    actor_id: validated_id("authenticated-host-control".into()),
                    decided_at_ms: now_ms(),
                });
                true
            } else {
                false
            }
        } else {
            true
        };
        let approval_id = approval_reference.as_deref();
        if !allowed {
            journal.finished(&action, approval_id, ExecutionOutcome::Refused, None)?;
            anyhow::bail!("规则或独立批准未允许此次记忆操作");
        }
        let pending = self.pending.clone();
        let _policy = crate::rule_policy::acquire(self.rule_policy.as_ref(), &self.policy_version)?;
        let mut dispatched = false;
        let completed = pending.with_active_epoch(epoch, || -> Result<(Value, guard_schema::SourceObject)> {
            self.memory_health()?;
            action.validate_at(now_ms())?;
            self.verify_tool(&caller_tool)?;
            self.verify_tool(&action.spec().tool)?;
            if let Some(approval) = &approval { approval.binding.validate_for_action(&action, now_ms())?; }
            let (value, entries) = match prepared {
                Prepared::Write(draft) => {
                    journal.started(&action, approval_id)?;
                    dispatched = true;
                    let entry = self.memory.as_mut().context("记忆未启用")?.store.commit(*draft, approval.as_ref().context("记忆保存缺少独立批准")?, now_ms())?;
                    (json!({"saved":true,"key":entry.draft.key,"version":entry.draft.version,"state":entry.draft.state,"entry_sha256":entry.sha256()?}), vec![entry])
                }
                Prepared::Read { value, .. } => {
                    let Prepared::Read { entries, value:current, .. } = self.prepare_memory_read(name, args)? else { unreachable!() };
                    ensure!(current == value, "等待期间记忆已变化或过期，须重新发起读取");
                    journal.started(&action, approval_id)?;
                    dispatched = true;
                    (value, entries)
                }
            };
            let text = serde_json::to_string(&value)?;
            ensure!(text.len() <= memory::MAX_RESPONSE_BYTES, "记忆响应超过上限");
            let source = self.sources.lock().map_err(|_| anyhow::anyhow!("来源锁失效"))?.memory_output(text.as_bytes(), &entries)?;
            let output = ExecOutput { ok:true, detail:text, truncated:false, outcome:ExecutionOutcome::Success, dispatched:true, capture:None };
            journal.finished(&action, approval_id, output.outcome, Some(&output))?;
            Ok((value, source))
        }).unwrap_or_else(|| Err(anyhow::anyhow!("宿主已撤权，旧批准不能执行")));
        match completed {
            Ok((value, source)) => {
                self.executed += 1;
                let mut response = mcp::tool_text(serde_json::to_string(&value)?);
                response["_meta"] = json!({"agentguard":{"outcome":"success","dispatched":true,"source":source,"instruction_authority":"none"}});
                Ok(response)
            }
            Err(error) => {
                if dispatched {
                    self.pending.pause();
                    if let Ok(mut sources) = self.sources.lock() {
                        sources.fault();
                    }
                    self.journal_failed |= !journal.healthy();
                    let detail = format!("记忆操作结果未确认，已暂停，不得自动重试：{error}");
                    let output = ExecOutput {
                        ok: false,
                        detail: detail.clone(),
                        truncated: false,
                        outcome: ExecutionOutcome::Unknown,
                        dispatched: true,
                        capture: None,
                    };
                    let _ = journal.finished(
                        &action,
                        approval_id,
                        ExecutionOutcome::Unknown,
                        Some(&output),
                    );
                    let mut value = mcp::tool_error(detail);
                    value["_meta"] = json!({"agentguard":{"outcome":"unknown","dispatched":true,"instruction_authority":"none"}});
                    Ok(value)
                } else {
                    if journal
                        .finished(&action, approval_id, ExecutionOutcome::Refused, None)
                        .is_err()
                    {
                        self.journal_failed = true;
                    }
                    Err(error)
                }
            }
        }
    }
}
