//! 只供已认证操作者查看来源及复核版本；不注册为模型工具。
use super::*;
use crate::operator::{failure, OperatorReply, MAX_REVIEW_BYTES};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListBody {
    session_id: ValidatedId,
    #[serde(default)]
    after_key: Option<ValidatedId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryBody {
    session_id: ValidatedId,
    key: ValidatedId,
    #[serde(default)]
    after_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewBody {
    session_id: ValidatedId,
    operation: String,
    key: ValidatedId,
    expected_version: u64,
    source_version: Option<u64>,
    expires_at_ms: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    session_id: ValidatedId,
    review_id: ValidatedId,
    review_sha256: String,
    review_nonce: String,
}

fn history_row(entry: &MemoryEntry, now: i64, content: bool) -> Result<Value> {
    let mut row = memory::reference(entry)?;
    row["state"] = json!(entry.draft.state);
    row["created_at_ms"] = json!(entry.draft.created_at_ms);
    row["committed_at_ms"] = json!(entry.committed_at_ms);
    row["expired"] = json!(entry.draft.expires_at_ms <= now);
    row["approval"] = serde_json::to_value(&entry.approval)?;
    if content {
        row["content"] = serde_json::to_value(memory::material(entry)?)?;
    }
    Ok(row)
}

impl Server {
    fn governance_session(&self, session: &ValidatedId) -> Result<()> {
        self.memory_health()?;
        ensure!(
            session.as_str() == self.host_session_id,
            "记忆治理属于旧宿主会话"
        );
        ensure!(
            self.memory.as_ref().is_some_and(|m| m.allow_read),
            "宿主未授权查看记忆"
        );
        Ok(())
    }

    pub(in crate::server) fn memory_governance(
        &mut self,
        route: &str,
        body: Value,
        instance_id: &str,
        epoch: u64,
    ) -> OperatorReply {
        let result = (|| -> Result<Value> {
            let value = match route {
                "/memory/list" => {
                    let body: ListBody = serde_json::from_value(body)?;
                    self.governance_session(&body.session_id)?;
                    let memory = self.memory.as_ref().context("记忆未启用")?;
                    let latest = memory.latest(now_ms())?;
                    let mut rest = latest.iter().filter(|(key, _)| {
                        body.after_key
                            .as_ref()
                            .is_none_or(|after| key.as_str() > after.as_str())
                    });
                    let page = rest.by_ref().take(16).collect::<Vec<_>>();
                    let next = if rest.next().is_some() {
                        page.last().map(|(key, _)| *key)
                    } else {
                        None
                    };
                    json!({"memory":memory.status(),"total_keys":latest.len(),"next_key":next,
                        "entries":page.iter().map(|(_, entry)|history_row(entry, now_ms(), false)).collect::<Result<Vec<_>>>()?,
                        "last_result":self.last_memory_result})
                }
                "/memory/history" => {
                    let body: HistoryBody = serde_json::from_value(body)?;
                    self.governance_session(&body.session_id)?;
                    let history = self
                        .memory
                        .as_ref()
                        .context("记忆未启用")?
                        .store
                        .history()?;
                    let history = history
                        .iter()
                        .filter(|e| e.draft.key == body.key)
                        .collect::<Vec<_>>();
                    ensure!(!history.is_empty(), "记忆不存在");
                    let current = history.last().context("记忆不存在")?;
                    let mut rest = history
                        .iter()
                        .filter(|e| e.draft.version > body.after_version);
                    let page = rest.by_ref().take(8).collect::<Vec<_>>();
                    let next = if rest.next().is_some() {
                        page.last().map(|e| e.draft.version)
                    } else {
                        None
                    };
                    json!({"key":body.key,"current_version":current.draft.version,"total_versions":history.len(),
                        "next_version":next,"versions":page.iter().map(|e|history_row(e, now_ms(), true)).collect::<Result<Vec<_>>>()?})
                }
                "/memory/preview" => {
                    // 新预览开始即使旧预览失效；错误不能留下可误用的旧批准。
                    self.memory_review = None;
                    let body: PreviewBody = serde_json::from_value(body)?;
                    self.governance_session(&body.session_id)?;
                    ensure!(
                        epoch == self.pending.cancellation_epoch(),
                        "记忆复核请求已经撤销"
                    );
                    let name = match body.operation.as_str() {
                        "quarantine" => "memory_quarantine",
                        "revoke" => "memory_revoke",
                        "restore" => "memory_restore",
                        _ => anyhow::bail!("不支持此记忆治理操作"),
                    };
                    let mut args = json!({"key":body.key,"expected_version":body.expected_version});
                    if name == "memory_restore" {
                        args["source_version"] =
                            json!(body.source_version.context("须明确选择恢复版本")?);
                        args["expires_at_ms"] =
                            json!(body.expires_at_ms.context("须明确新的有效期限")?);
                    } else {
                        ensure!(
                            body.source_version.is_none() && body.expires_at_ms.is_none(),
                            "隔离或撤销不接受恢复参数"
                        );
                    }
                    let proposal = self.prepare_memory_action(name, &args)?;
                    let Prepared::Write(draft) = &proposal.prepared else {
                        anyhow::bail!("治理操作必须生成新版本")
                    };
                    let decision = self.gate.judge_memory(
                        name,
                        &proposal.keys,
                        &proposal.action.spec().parameters,
                        true,
                    );
                    ensure!(
                        !matches!(decision, Outcome::Refuse { .. }),
                        "当前策略拒绝此记忆治理操作"
                    );
                    let issued = proposal.action.spec().issued_at_ms;
                    let binding = ApprovalBinding::new(
                        validated_id(random_id("memory-review")),
                        proposal.action.clone(),
                        random_nonce(),
                        issued,
                        proposal
                            .action
                            .spec()
                            .expires_at_ms
                            .min(draft.expires_at_ms),
                    )?;
                    let digest = crate::tool_registry::digest(&proposal.action.canonical_bytes())
                        .as_str()
                        .to_owned();
                    let value = json!({"review_id":binding.approval_id(),"review_nonce":binding.nonce(),
                        "review_sha256":digest,"operation":body.operation,"expires_at_ms":binding.expires_at_ms(),
                        "action":proposal.action,"draft":draft,"instruction_authority":"none",
                        "completed_effects":"not_reverted"});
                    ensure!(
                        serde_json::to_vec(&value)?.len() <= MAX_REVIEW_BYTES,
                        "记忆复核内容超过完整展示上限"
                    );
                    self.memory_review = Some(MemoryReview {
                        name: name.into(),
                        args,
                        proposal,
                        binding,
                        digest,
                    });
                    value
                }
                "/memory/apply" | "/memory/discard" => {
                    let body: ApplyBody = serde_json::from_value(body)?;
                    self.governance_session(&body.session_id)?;
                    let review = self
                        .memory_review
                        .take()
                        .context("记忆复核已消费、未生成或已失效")?;
                    ensure!(
                        body.review_id == *review.binding.approval_id()
                            && body.review_sha256 == review.digest
                            && body.review_nonce == review.binding.nonce()
                            && epoch == review.proposal.epoch
                            && epoch == self.pending.cancellation_epoch(),
                        "记忆复核身份或批准代次不匹配"
                    );
                    review
                        .binding
                        .validate_for_action(&review.proposal.action, now_ms())?;
                    if route == "/memory/discard" {
                        json!({"discarded":true,"review_id":body.review_id})
                    } else {
                        let Prepared::Write(draft) = &review.proposal.prepared else {
                            anyhow::bail!("复核不是记忆变更")
                        };
                        let current = self
                            .memory
                            .as_ref()
                            .context("记忆未启用")?
                            .latest(now_ms())?
                            .remove(draft.key.as_str())
                            .context("记忆已不存在")?;
                        ensure!(
                            current.draft.version.checked_add(1) == Some(draft.version)
                                && draft.previous_sha256 == Some(current.sha256()?),
                            "复核后记忆已变化，必须重新预览"
                        );
                        let approval = ApprovalRecord {
                            binding: review.binding,
                            choice: ApprovalChoice::Approved,
                            actor_id: validated_id("authenticated-host-control".into()),
                            decided_at_ms: now_ms(),
                        };
                        let result = self.run_memory_action(
                            &review.name,
                            &review.args,
                            review.proposal,
                            Some(approval),
                        )?;
                        let value = json!({"review_id":body.review_id,"execution":result,"completed_effects":"not_reverted"});
                        self.last_memory_result = Some(value.clone());
                        value
                    }
                }
                _ => anyhow::bail!("不支持此记忆治理请求"),
            };
            let envelope = json!({"service":"agentguard-mcp","governance_protocol":1,"instance_id":instance_id,
                "session_id":self.host_session_id,"data":value});
            ensure!(
                serde_json::to_vec(&envelope)?.len() <= MAX_REVIEW_BYTES,
                "记忆治理响应超过完整展示上限"
            );
            Ok(envelope)
        })();
        match result {
            Ok(value) => (200, value),
            Err(error) => failure("MEMORY_GOVERNANCE_REFUSED", &error.to_string(), 409),
        }
    }
}
