//! 委托入口只把经认证的文件操作交给原有执行管线，不能替代批准或变成 shell 权限。
use super::*;
use crate::delegation::DelegationAuthority;
use anyhow::{ensure, Context, Result};
use guard_schema::delegation::{DelegationCommand, DelegationEnvelope, DELEGATION_MAX_BYTES};
use guard_schema::{SourceEntryPoint, SourceSensitivity};

impl Server {
    pub fn delegation_operator(&self) -> Option<crate::delegation_governance::DelegationOperator> {
        self.delegation
            .as_ref()
            .zip(self.journal.as_ref())
            .map(|(authority, journal)| {
                crate::delegation_governance::DelegationOperator::new(
                    authority.budget.clone(),
                    journal.clone(),
                    self.pending.clone(),
                )
            })
    }
    pub fn with_delegation(mut self, authority: DelegationAuthority) -> Result<Self> {
        ensure!(
            self.delegation.is_none()
                && self.rule_policy.is_none()
                && self.gate.session_id().is_none(),
            "委托必须在规则包与会话启动前配置一次"
        );
        ensure!(self.isolation.is_some(), "委托文件执行必须使用隔离后端");
        let journal = self.journal.as_ref().context("委托必须接入持久审计")?;
        ensure!(
            journal.healthy()
                && self
                    .sources
                    .lock()
                    .map(|s| s.healthy() && s.shares_journal(journal))
                    .unwrap_or(false),
            "委托审计与来源必须共同持久化"
        );
        self.registry
            .lock()
            .map_err(|_| anyhow::anyhow!("工具登记锁失效"))?
            .enable_delegation()?;
        self.delegation = Some(authority);
        Ok(self)
    }
    fn delegation_ready(&self) -> Result<()> {
        ensure!(
            self.delegation.is_some()
                && self.host_session_state() == "active"
                && !self.pending.is_cancelled()
                && !self.session_stopped
                && !self.journal_failed
                && !self.workspace_faulted
                && !self.sources_faulted()
                && !self.registry_faulted()
                && self.journal.as_ref().is_some_and(SharedJournal::healthy),
            "委托会话、审计、来源或工具登记不可用"
        );
        Ok(())
    }
    pub(super) fn delegation_call(&mut self, id: Value, args: &Value) -> Value {
        // 控制错误也必须有界；过长 ID 不回显，避免它占满所有剩余输出额度。
        if !(id.is_string() || id.is_i64() || id.is_u64())
            || serde_json::to_vec(&id).map_or(true, |v| v.len() > 128)
        {
            return mcp::error(
                Value::Null,
                mcp::code::REFUSED,
                "委托请求 ID 无效或过长",
                None,
            );
        }
        let value = match self.execute_delegation(args) {
            Ok(value) => value,
            Err(error) => {
                self.refused += 1;
                if self.journal.as_ref().is_some_and(|j| !j.healthy()) {
                    self.journal_failed = true;
                    self.pending.pause();
                }
                let detail = error.to_string().chars().take(120).collect::<String>();
                let mut value = mcp::tool_error(format!("委托操作未完成：{detail}"));
                value["_meta"] = json!({"agentguard":{"outcome":"refused","dispatched":false,"instruction_authority":"none"}});
                value
            }
        };
        let mut full = mcp::result(id.clone(), value);
        let Some(permit) = self.active_budget.take() else {
            return full;
        };
        let limit = permit.output_limit();
        let ticket = permit.ticket();
        let dispatched = full
            .pointer("/result/_meta/agentguard/dispatched")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let outcome = full
            .pointer("/result/_meta/agentguard/outcome")
            .cloned()
            .unwrap_or(json!("refused"));
        let hidden = |reason: &str, outcome: Value| {
            let mut value = mcp::tool_error(
                "委托正文因预算或撤销未公开；已派发动作可能已完成，请核对回执，勿自动重试",
            );
            value["_meta"] = json!({"agentguard":{"outcome":outcome,"dispatched":dispatched,
                "budget_output_hidden":true,"budget_reason":reason,"instruction_authority":"none"}});
            mcp::result(id.clone(), value)
        };
        if full
            .pointer("/result/_meta/agentguard/delegation/message/expires_at_ms")
            .and_then(Value::as_i64)
            .is_some_and(|expires| now_ms() >= expires)
        {
            full = hidden("message_expired", outcome.clone());
        } else if permit.check(std::time::Instant::now()).is_err() {
            full = hidden("expired_or_revoked", outcome.clone());
        } else if serde_json::to_vec(&full).map_or(true, |v| v.len() as u64 > limit) {
            full = hidden("output_limit", outcome.clone());
        }
        let mut bytes = serde_json::to_vec(&full).expect("MCP 值可序列化");
        // reserve_at_least 保留 1 KiB；固定控制回执和有界 ID 必须容纳在其中。
        assert!(bytes.len() as u64 <= limit);
        let mut audit_failed = true;
        let _ = permit.finish_recorded(bytes.len() as u64, std::time::Instant::now(), |settled| {
            if !settled {
                full = hidden("expired_revoked_or_unconfirmed", outcome);
                bytes = serde_json::to_vec(&full).expect("固定控制回执可序列化");
            }
            let body = json!({"ticket":ticket,"output_limit":limit,"response_bytes":bytes.len(),
                "response_sha256":format!("{:x}",Sha256::digest(&bytes)),
                "charge_mode":if settled {"encoded_response"} else {"full_reservation"},
                "output_hidden":full.pointer("/result/_meta/agentguard/budget_output_hidden").and_then(Value::as_bool).unwrap_or(false),
                "dispatched":dispatched,"publication":"prepared_not_delivery_acknowledged"});
            let recorded = self.journal.as_ref().context("委托审计缺失")
                .and_then(|j| j.delegation_budget_event(&self.host_session_id, "finished", body));
            audit_failed = recorded.is_err();
            recorded
        });
        if audit_failed {
            self.journal_failed = true;
            self.pending.pause();
            if let Some(tree) = self
                .delegation
                .as_ref()
                .and_then(|a| a.budget.current(&self.host_session_id).ok())
            {
                let _ = tree.close();
            }
            full = hidden("audit_unconfirmed", json!("unknown"));
        }
        full
    }
    fn execute_delegation(&mut self, args: &Value) -> Result<Value> {
        self.refresh_rule_policy()?;
        self.delegation_ready()?;
        ensure!(self.active_budget.is_none(), "不能覆盖已有预算许可");
        ensure!(
            serde_json::to_vec(args)?.len() <= DELEGATION_MAX_BYTES,
            "委托消息过大"
        );
        let envelope: DelegationEnvelope = serde_json::from_value(args.clone())?;
        let caller = self.registered_tool("agentguard-delegation", "delegation_send")?;
        self.verify_tool(&caller)?;
        let authority = self.delegation.as_ref().context("委托未启用")?;
        let verified = authority.authenticate(envelope, &self.host_session_id, now_ms())?;
        let child = authority.child(&verified, now_ms())?;
        let limits = authority.budgets.clone();
        let tree = authority.budget.current(&self.host_session_id)?;
        let receipt = verified.receipt();
        self.active_budget = Some(tree.reserve_at_least(
            verified.grant.grant.grant_id.as_str(),
            512 * 1024,
            1024,
            std::time::Instant::now(),
        )?);
        let journal = self.journal.as_ref().context("委托审计缺失")?.clone();
        let permit = self.active_budget.as_ref().context("预算许可缺失")?;
        journal.delegation_budget_event(&self.host_session_id, "reserved", json!({
            "grant_id":verified.grant.grant.grant_id,"ticket":permit.ticket(),"output_limit":permit.output_limit(),
            "state":tree.status(std::time::Instant::now())?}))?;
        {
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
                &verified.envelope.command.binding_bytes()?,
                SourceEntryPoint::ToolOutput,
                "delegation-message/1",
                SourceSensitivity::Unknown,
                &parents,
            )?;
        }
        // 单个 Server 串行处理 MCP；独立宿主暂停仍能在原执行管线中撤销等待和派发。
        self.delegation_ready()?;
        if let Some(grant) = &child {
            let permit = self.active_budget.as_mut().context("预算许可缺失")?;
            permit.mark_started(std::time::Instant::now())?;
            let granted_limits = permit.create_child(
                grant.grant.grant_id.as_str(),
                &limits,
                std::time::Instant::now(),
            )?;
            journal.delegation_budget_event(&self.host_session_id, "child", json!({
                "grant_id":grant.grant.grant_id,"parent_grant_id":verified.grant.grant.grant_id,"limits":granted_limits}))?;
        }
        journal.delegation_message(&verified, child.as_ref(), None)?;
        self.delegation.as_mut().context("委托未启用")?.consume(
            &verified,
            child.clone(),
            now_ms(),
        )?;
        if let Some(grant) = child {
            let mut response = mcp::tool_text(serde_json::to_string(
                &json!({"delegated":true,"grant":grant}),
            )?);
            response["_meta"] = json!({"agentguard":{"outcome":"success","dispatched":false,"delegation":receipt,"instruction_authority":"none"}});
            return Ok(response);
        }
        let (name, arguments) = match &verified.envelope.command {
            DelegationCommand::ReadFile { path } => ("read_file", json!({"path":path})),
            DelegationCommand::WriteFile { path, contents } => {
                ("write_file", json!({"path":path,"contents":contents}))
            }
            DelegationCommand::DeleteFile { path } => ("delete_file", json!({"path":path})),
            DelegationCommand::Delegate { .. } => unreachable!("委托已返回授权"),
        };
        let (call, action) = self
            .parse_tool(name, &arguments)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            self.active_delegation.is_none(),
            "不能覆盖正在执行的委托绑定"
        );
        self.active_delegation = Some(verified);
        let handled = self.gate_and_run(call, action);
        self.active_delegation = None;
        let (mut response, outcome, dispatched) = match handled {
            Handled::Executed { output } => {
                let mut text = output.detail;
                if output.truncated {
                    text.push_str("\n[输出已截断]");
                }
                (
                    if output.ok {
                        mcp::tool_text(text)
                    } else {
                        mcp::tool_error(text)
                    },
                    output.outcome,
                    output.dispatched,
                )
            }
            Handled::Refused { reason } => {
                (mcp::tool_error(reason), self.last_refused_outcome, false)
            }
        };
        response["_meta"] = json!({"agentguard":{"outcome":outcome,"dispatched":dispatched,"delegation":receipt,
            "source":self.last_output_source,"instruction_authority":"none"}});
        Ok(response)
    }
}
