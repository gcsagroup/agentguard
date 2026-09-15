//! 委托入口只把经认证的文件操作交给原有执行管线，不能替代批准或变成 shell 权限。
use super::*;
use crate::delegation::DelegationAuthority;
use anyhow::{ensure, Context, Result};
use guard_schema::delegation::{DelegationCommand, DelegationEnvelope, DELEGATION_MAX_BYTES};
use guard_schema::{SourceEntryPoint, SourceSensitivity};

impl Server {
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
    pub(super) fn delegation_call(&mut self, args: &Value) -> Value {
        match self.execute_delegation(args) {
            Ok(value) => value,
            Err(error) => {
                self.refused += 1;
                if self.journal.as_ref().is_some_and(|j| !j.healthy()) {
                    self.journal_failed = true;
                    self.pending.pause();
                }
                let mut value = mcp::tool_error(format!("委托操作未完成：{error}"));
                value["_meta"] = json!({"agentguard":{"outcome":"refused","dispatched":false,"instruction_authority":"none"}});
                value
            }
        }
    }
    fn execute_delegation(&mut self, args: &Value) -> Result<Value> {
        self.refresh_rule_policy()?;
        self.delegation_ready()?;
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
        let receipt = verified.receipt();
        let journal = self.journal.as_ref().context("委托审计缺失")?.clone();
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
