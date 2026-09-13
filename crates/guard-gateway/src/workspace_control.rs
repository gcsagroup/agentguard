//! 宿主持有的工作区复核。此模块不注册 MCP 方法，客户端只能请求容器内工具。
use super::*;
use crate::operator::{
    failure, OperatorCommand, OperatorReply, MAX_REVIEW_BYTES, WORKSPACE_PROTOCOL,
};
use crate::writeback::{ApplyOutcome, Preview};

pub(super) struct PendingWorkspaceReview {
    workspace_id: String,
    binding: ApprovalBinding,
    digest: String,
    preview: Preview,
    cancellation_epoch: u64,
}

impl Server {
    /// 独立人工批准不覆盖原有硬拒绝。脚本在副本中新建的敏感文件也必须重新过路径策略。
    pub(super) fn writeback_denial(&self, preview: &Preview) -> Option<crate::gate::Finding> {
        for change in &preview.changes {
            let deleting = matches!(change.kind, crate::writeback::ChangeKind::Delete);
            let action = ShellAction {
                tool: if deleting {
                    "run_terminal"
                } else {
                    "write_file"
                }
                .into(),
                action: deleting.then(|| "rm".into()),
                target: Some(
                    preview
                        .workspace_root
                        .join(&change.path)
                        .to_string_lossy()
                        .into_owned(),
                ),
                args: vec![],
            };
            let verdict = self.gate.shell().evaluate(&action);
            if verdict.decision == guard_shell::ShellDecision::Deny {
                return Some(crate::gate::Finding {
                    rule_id: verdict.rule_id,
                    layer: "path".into(),
                    severity: "high".into(),
                    message: format!("宿主回写目标被硬拒绝：{}", verdict.detail),
                });
            }
        }
        None
    }

    pub fn host_session_state(&self) -> &'static str {
        if self.workspace_faulted
            || self.journal_failed
            || self.browser_faulted()
            || self.sources_faulted()
        {
            "failed"
        } else if self.pending.is_closed() {
            "stopped"
        } else if self.pending.is_paused() {
            "paused"
        } else if self.session_stopped {
            "stopped"
        } else {
            "active"
        }
    }

    pub fn operator_status(&self, instance_id: &str) -> Value {
        let review = self.workspace_review.as_ref().filter(|review| {
            review.binding.expires_at_ms() > now_ms()
                && review.binding.action().spec().session_id.as_str() == self.host_session_id
                && !self.pending.is_closed()
                && !self.workspace_faulted
                && !self.journal_failed
                && !self.sources_faulted()
                && review.cancellation_epoch == self.pending.cancellation_epoch()
        });
        json!({"service":"agentguard-mcp", "workspace_protocol":WORKSPACE_PROTOCOL,
            "instance_id":instance_id, "session_id":self.host_session_id,
            "task_profile":self.host_profile, "session_state":self.host_session_state(), "busy":false,
            "required_mcp_session_binding":self.require_session_binding,
            "coverage":self.isolation.as_ref().map(DockerExecutor::status)
                .unwrap_or_else(|| json!({"mode":"native_cooperative","client_enforcement":"cooperative"})),
            "workspaces":self.isolation.as_ref().map(DockerExecutor::workspaces).unwrap_or(json!([])),
            "pending_review":review.map(|r| json!({"review_id":r.binding.approval_id(),
                "review_sha256":r.digest,"expires_at_ms":r.binding.expires_at_ms(),"workspace_id":r.workspace_id})),
            "last_result":self.last_workspace_result,
            "browser":self.browser.as_ref().map(|b|b.host().status()),
            "audit":self.journal.as_ref().map(ExecutionJournal::status).unwrap_or(json!({"persistent":false})),
            "source_provenance":self.sources.lock().map(|sources| sources.status()).unwrap_or_else(|_| json!({"healthy":false})),
        })
    }

    pub fn handle_operator(
        &mut self,
        command: OperatorCommand,
        instance_id: &str,
    ) -> OperatorReply {
        self.handle_operator_at(command, instance_id, self.pending.cancellation_epoch())
    }

    pub fn handle_operator_at(
        &mut self,
        command: OperatorCommand,
        instance_id: &str,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        match command {
            OperatorCommand::Preview { workspace_id } => {
                self.workspace_preview(workspace_id, instance_id, cancellation_epoch)
            }
            OperatorCommand::Apply {
                review_id,
                review_sha256,
                review_nonce,
            } => self.workspace_apply(
                &review_id,
                &review_sha256,
                &review_nonce,
                instance_id,
                cancellation_epoch,
            ),
            OperatorCommand::Discard {
                review_id,
                review_sha256,
                review_nonce,
            } => self.workspace_discard(
                &review_id,
                &review_sha256,
                &review_nonce,
                instance_id,
                cancellation_epoch,
            ),
            OperatorCommand::Pause => {
                self.host_transition("pause", instance_id, cancellation_epoch)
            }
            OperatorCommand::Resume => {
                self.host_transition("resume", instance_id, cancellation_epoch)
            }
            OperatorCommand::Stop => self.host_transition("stop", instance_id, cancellation_epoch),
        }
    }

    fn host_action(
        &self,
        name: &str,
        target: String,
        parameters: Value,
    ) -> anyhow::Result<ActionSnapshot> {
        let issued_at_ms = now_ms();
        // 同一配置控制复核有效期，避免等待超时被一个更长的回写窗口悄悄延长。
        let lifetime = self.confirm_timeout.as_millis().min(i64::MAX as u128) as i64;
        Ok(ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: validated_id(self.host_session_id.clone()),
            action_id: validated_id(random_id("host-action")),
            request_id: validated_id(random_id("host-request")),
            policy_version: validated_id(self.policy_version.clone()),
            tool: ToolIdentity {
                service: "agentguard-host-control".into(),
                name: name.into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            target,
            parameters,
            issued_at_ms,
            expires_at_ms: issued_at_ms.saturating_add(lifetime.max(1)),
            nonce: random_nonce(),
            sources: self
                .sources
                .lock()
                .map_err(|_| anyhow::anyhow!("来源锁已失效"))?
                .action_sources()?,
        })?)
    }

    fn writable_state(&self) -> Result<(), OperatorReply> {
        if self.journal_failed
            || self.workspace_faulted
            || self.browser_faulted()
            || self.sources_faulted()
        {
            return Err(failure(
                "WORKSPACE_FAILED",
                "上次审计或回写结果需要核实，当前会话禁止新动作",
                409,
            ));
        }
        if self.pending.is_closed() || (self.session_stopped && !self.pending.is_paused()) {
            return Err(failure(
                "WORKSPACE_STALE",
                "会话已结束；旧结果不能在停止后获得新的执行授权",
                409,
            ));
        }
        if self.isolation.is_none() || self.journal.is_none() {
            return Err(failure(
                "WORKSPACE_UNAVAILABLE",
                "回写需要真实隔离工作区与持久执行审计",
                409,
            ));
        }
        Ok(())
    }

    fn workspace_preview(
        &mut self,
        workspace_id: String,
        instance_id: &str,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        if let Err(reply) = self.writable_state() {
            return reply;
        }
        if cancellation_epoch != self.pending.cancellation_epoch() {
            return failure(
                "WORKSPACE_STALE",
                "预览请求之后已有新的暂停或停止；未创建批准",
                409,
            );
        }
        self.workspace_review = None;
        let preview = match self
            .isolation
            .as_mut()
            .unwrap()
            .preview_workspace(&workspace_id)
        {
            Ok(preview) => preview,
            Err(error) => {
                return failure(
                    "WORKSPACE_UNAVAILABLE",
                    &format!("不能生成可批准差异：{error:#}"),
                    409,
                )
            }
        };
        let recovery = guard_schema::paths::dealias_platform_volumes(&preview.recovery_directory);
        if self
            .gate
            .shell()
            .workspace()
            .read_grants()
            .iter()
            .chain(self.gate.shell().workspace().write_grants())
            .any(|grant| recovery.starts_with(grant))
        {
            return failure(
                "WORKSPACE_UNAVAILABLE",
                "恢复原件目录落入了任务授权范围，拒绝提供回写",
                409,
            );
        }
        let action = match self.host_action(
            "workspace_apply",
            preview.workspace_root.to_string_lossy().into_owned(),
            json!({"workspace_id":workspace_id,"preview":preview}),
        ) {
            Ok(action) => action,
            Err(error) => {
                return failure(
                    "WORKSPACE_ARGUMENTS",
                    &format!("差异不能构成完整动作：{error}"),
                    400,
                )
            }
        };
        let expires_at_ms = action.spec().expires_at_ms;
        let binding = match ApprovalBinding::new(
            validated_id(random_id("workspace-review")),
            action,
            random_nonce(),
            now_ms(),
            expires_at_ms,
        ) {
            Ok(binding) => binding,
            Err(_) => return failure("WORKSPACE_STALE", "差异复核期限无效，请重新预览", 409),
        };
        let digest = format!("{:x}", Sha256::digest(binding.action().canonical_bytes()));
        let response = json!({"service":"agentguard-mcp","workspace_protocol":WORKSPACE_PROTOCOL,
            "instance_id":instance_id,"session_id":self.host_session_id,"workspace_id":workspace_id,
            "review_id":binding.approval_id(),"review_sha256":digest,"review_nonce":binding.nonce(),
            "expires_at_ms":binding.expires_at_ms(),"preview":preview,"binding":binding});
        if response.to_string().len() > MAX_REVIEW_BYTES {
            return failure(
                "WORKSPACE_UNAVAILABLE",
                "完整差异超过 4 MiB 展示上限；请拆分任务，不能截断后批准",
                413,
            );
        }
        let outcome = if let Some(finding) = self.writeback_denial(&preview) {
            Outcome::Refuse {
                findings: vec![finding],
            }
        } else {
            Outcome::NeedsConfirmation {
                findings: vec![crate::gate::Finding {
                    rule_id: "SHELL-CONFIRM".into(),
                    layer: "path".into(),
                    severity: "high".into(),
                    message: "宿主回写需要独立操作者核对完整差异".into(),
                }],
            }
        };
        if let Err(error) = self
            .journal
            .as_ref()
            .unwrap()
            .decided(binding.action(), &outcome)
        {
            self.journal_failed = true;
            return failure(
                "WORKSPACE_FAILED",
                &format!("无法保存复核决策，未创建可用批准：{error}"),
                500,
            );
        }
        if let Outcome::Refuse { findings } = outcome {
            return failure("WORKSPACE_DENIED", &findings[0].message, 409);
        }
        if self.pending.is_closed() || cancellation_epoch != self.pending.cancellation_epoch() {
            return failure("WORKSPACE_STALE", "预览期间会话已撤权；未创建可用批准", 409);
        }
        self.workspace_review = Some(PendingWorkspaceReview {
            workspace_id,
            binding,
            digest,
            preview,
            cancellation_epoch,
        });
        (200, response)
    }

    fn workspace_apply(
        &mut self,
        id: &str,
        digest: &str,
        nonce: &str,
        instance_id: &str,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        if let Err(reply) = self.writable_state() {
            return reply;
        }
        if !self.workspace_review_matches(id, digest, nonce, cancellation_epoch) {
            return failure(
                "WORKSPACE_STALE",
                "差异已过期、已使用、绑定不一致或会话已撤权；未回写",
                409,
            );
        }
        let review = self.workspace_review.take().unwrap();
        let pending = self.pending.clone();
        if let Some(finding) = self.writeback_denial(&review.preview) {
            if let Err(error) = self.journal.as_ref().unwrap().finished(
                review.binding.action(),
                Some(id),
                ExecutionOutcome::Refused,
                None,
            ) {
                self.journal_failed = true;
                return failure(
                    "WORKSPACE_FAILED",
                    &format!("回写已拒绝但回执保存失败：{error}"),
                    500,
                );
            }
            return failure("WORKSPACE_DENIED", &finding.message, 409);
        }
        self.perform_workspace_apply(review, id, instance_id, pending, cancellation_epoch)
    }

    fn workspace_review_matches(
        &self,
        id: &str,
        digest: &str,
        nonce: &str,
        cancellation_epoch: u64,
    ) -> bool {
        !self.pending.is_closed()
            && cancellation_epoch == self.pending.cancellation_epoch()
            && self.workspace_review.as_ref().is_some_and(|review| {
                review.binding.approval_id().as_str() == id
                    && review.digest == digest
                    && review.binding.nonce() == nonce
                    && review.binding.action().spec().session_id.as_str() == self.host_session_id
                    && review.cancellation_epoch == cancellation_epoch
                    && review
                        .binding
                        .validate_for_action(review.binding.action(), now_ms())
                        .is_ok()
            })
    }

    fn workspace_discard(
        &mut self,
        id: &str,
        digest: &str,
        nonce: &str,
        instance_id: &str,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        if let Err(reply) = self.writable_state() {
            return reply;
        }
        if !self.workspace_review_matches(id, digest, nonce, cancellation_epoch) {
            return failure("WORKSPACE_STALE", "本次差异已失效或绑定不一致", 409);
        }
        let review = self.workspace_review.take().unwrap();
        if let Err(error) = self.journal.as_ref().unwrap().finished(
            review.binding.action(),
            Some(id),
            ExecutionOutcome::Refused,
            None,
        ) {
            self.journal_failed = true;
            return failure(
                "WORKSPACE_FAILED",
                &format!("差异已放弃，但回执保存失败：{error}"),
                500,
            );
        }
        (200, self.operator_status(instance_id))
    }

    fn perform_workspace_apply(
        &mut self,
        review: PendingWorkspaceReview,
        id: &str,
        instance_id: &str,
        pending: PendingConfirm,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        if review.preview.changes.is_empty() {
            return failure("WORKSPACE_STALE", "没有需要回写的文件变化", 409);
        }
        if let Err(error) = self
            .journal
            .as_ref()
            .unwrap()
            .started(review.binding.action(), Some(id))
        {
            self.journal_failed = true;
            return failure(
                "WORKSPACE_FAILED",
                &format!("回写前审计不能持久保存，未回写：{error}"),
                500,
            );
        }
        // 主线程独占执行器。外层批准单次消费，内部还会重验快照和宿主基线。
        let report = match self.isolation.as_mut().unwrap().apply_workspace(
            &review.workspace_id,
            &review.preview.digest,
            &|| pending.is_closed() || pending.cancellation_epoch() != cancellation_epoch,
        ) {
            Ok(report) => report,
            Err(error) => {
                let output = ExecOutput::err(format!("回写未进入引擎：{error:#}"))
                    .with_state(ExecutionOutcome::Failed, false);
                if self
                    .journal
                    .as_ref()
                    .unwrap()
                    .finished(
                        review.binding.action(),
                        Some(id),
                        output.outcome,
                        Some(&output),
                    )
                    .is_err()
                {
                    self.journal_failed = true;
                }
                return failure("WORKSPACE_FAILED", &output.detail, 409);
            }
        };
        let outcome = match report.outcome {
            ApplyOutcome::Applied => ExecutionOutcome::Success,
            ApplyOutcome::Conflict => ExecutionOutcome::Failed,
            ApplyOutcome::Partial | ApplyOutcome::Unknown => {
                self.workspace_faulted = true;
                self.pending.pause();
                ExecutionOutcome::Unknown
            }
        };
        let detail = serde_json::to_string(&report).expect("固定回写回执可序列化");
        let output = ExecOutput {
            ok: outcome == ExecutionOutcome::Success,
            detail,
            truncated: false,
            outcome,
            dispatched: true,
        };
        self.last_workspace_result = Some(report.clone());
        if let Err(error) = self.journal.as_ref().unwrap().finished(
            review.binding.action(),
            Some(id),
            outcome,
            Some(&output),
        ) {
            self.journal_failed = true;
            self.pending.pause();
            // 实际逐文件结果仍保留给操作者核对，但持久终态未知，不能返回整体成功。
            let mut unknown = report;
            unknown.outcome = ApplyOutcome::Unknown;
            unknown.detail =
                format!("文件操作已返回但回执无法持久保存，结果未知，不自动重试：{error}");
            self.last_workspace_result = Some(unknown.clone());
            return (
                200,
                json!({"service":"agentguard-mcp","workspace_protocol":WORKSPACE_PROTOCOL,
                "instance_id":instance_id,"session_id":self.host_session_id,"result":unknown}),
            );
        }
        (
            200,
            json!({"service":"agentguard-mcp","workspace_protocol":WORKSPACE_PROTOCOL,
            "instance_id":instance_id,"session_id":self.host_session_id,"result":report}),
        )
    }

    fn host_transition(
        &mut self,
        kind: &str,
        instance_id: &str,
        cancellation_epoch: u64,
    ) -> OperatorReply {
        if kind == "resume"
            && (self.journal_failed
                || self.sources_faulted()
                || self.browser_faulted()
                || self.workspace_faulted
                || self.pending.is_closed()
                || !self.pending.is_paused())
        {
            return failure(
                "WORKSPACE_STALE",
                "只有仍连接且无未知结果的暂停会话可以恢复；停止或断连需要重新启动网关",
                409,
            );
        }
        self.workspace_review = None;
        // 撤权不依赖审计可写；即使存储故障，暂停和停止仍须立即生效。
        if kind == "pause" {
            self.pending.pause();
            self.session_stopped = true;
        }
        if kind == "stop" {
            self.pending.close();
            self.session_stopped = true;
        }
        let action = match self.host_action(
            &format!("session_{kind}"),
            self.host_session_id.clone(),
            json!({"task_profile":self.host_profile}),
        ) {
            Ok(action) => action,
            Err(error) => {
                return failure(
                    "WORKSPACE_FAILED",
                    &format!("不能记录会话状态变更：{error}"),
                    500,
                )
            }
        };
        if let Some(journal) = &self.journal {
            if let Err(error) = journal
                .decided(&action, &Outcome::Execute { findings: vec![] })
                .and_then(|_| journal.started(&action, None))
            {
                self.journal_failed = true;
                return failure(
                    "WORKSPACE_FAILED",
                    &format!("状态变更审计失败，恢复未执行；暂停/停止撤权仍有效：{error}"),
                    500,
                );
            }
        }
        let transition = if kind == "resume" {
            if !self.pending.resume_from_host(cancellation_epoch) {
                Err(anyhow::anyhow!("连接不能恢复，或恢复请求之后已有新的撤权"))
            } else {
                let profile = self.host_profile.clone();
                self.start_host_session(profile.as_deref()).map(|_| {
                    self.require_session_binding = true;
                })
            }
        } else if self.gate.session_id().is_some() {
            self.gate.end_session().map(|_| ())
        } else {
            Ok(())
        };
        let output = match transition {
            Ok(()) => ExecOutput::ok(format!("宿主会话状态已变更：{kind}")),
            Err(error) => {
                self.pending.pause();
                self.session_stopped = true;
                ExecOutput::err(format!("宿主会话状态变更失败：{error}"))
            }
        };
        if let Some(journal) = &self.journal {
            if let Err(error) = journal.finished(&action, None, output.outcome, Some(&output)) {
                self.journal_failed = true;
                self.pending.pause();
                return failure(
                    "WORKSPACE_FAILED",
                    &format!("状态已改变但回执无法保存；已暂停后续动作：{error}"),
                    500,
                );
            }
        }
        if !output.ok {
            return failure("WORKSPACE_STALE", &output.detail, 409);
        }
        (200, self.operator_status(instance_id))
    }
}
