//! 远程服务的生产动作：独立批准覆盖初始化和网络发送，未结束日志由既有执行恢复记未知。
use super::proxy_control::{refusal, ProxyCompletion};
use super::*;
use crate::mcp_permission::DispatchPermit;
use crate::mcp_remote::{RemoteClient, RemoteError};
use crate::mcp_remote_service::RemoteService;
use crate::mcp_stdio::Reply;
use anyhow::{ensure, Result};
use std::time::Instant;

impl Server {
    pub(super) fn remote_proxy_call(&mut self, index: usize, alias: &str, args: &Value) -> Value {
        let proxy = &self.remote_proxies[index];
        let original = proxy.original_name(alias).expect("已匹配远程工具");
        let Some(journal) = self.journal.as_ref() else {
            return refusal("远程服务缺少持久执行审计");
        };
        let mut host = RemoteHost {
            gate: &mut self.gate,
            pending: &self.pending,
            registry: &self.registry,
            sources: &self.sources,
            journal,
            journal_failed: &mut self.journal_failed,
            confirm_timeout: self.confirm_timeout,
            session: &self.host_session_id,
            policy: &self.policy_version,
            rule_policy: self.rule_policy.as_ref(),
        };
        let result = host
            .invoke(proxy, original, args)
            .unwrap_or_else(|e| refusal(&format!("远程工具未获准派发：{e}")));
        if result.pointer("/_meta/agentguard/dispatched") == Some(&json!(true)) {
            self.executed += 1;
        } else {
            self.refused += 1;
        }
        result
    }
}
struct RemoteHost<'a> {
    gate: &'a mut Gate,
    pending: &'a PendingConfirm,
    registry: &'a crate::tool_registry::SharedRegistry,
    sources: &'a SharedSources,
    journal: &'a ExecutionJournal,
    journal_failed: &'a mut bool,
    confirm_timeout: Duration,
    session: &'a str,
    policy: &'a str,
    rule_policy: Option<&'a crate::rule_policy::RuntimePolicy>,
}
impl RemoteHost<'_> {
    fn invoke(&mut self, proxy: &RemoteService, name: &str, args: &Value) -> Result<Value> {
        proxy.validate_input(name, args)?;
        let mut client = proxy.client()?;
        let tool = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("登记锁失效"))?
            .identity(&proxy.manifest.service_id, name)?;
        ensure!(
            tool.registration.as_ref().is_some_and(|r| r.manifest_sha256
                == crate::tool_registry::digest(&proxy.manifest.canonical_bytes())),
            "远程清单认可已失效，需要重新观测实际服务"
        );
        let epoch = self.pending.cancellation_epoch();
        let issued = now_ms();
        let timeout = self.confirm_timeout.min(Duration::from_secs(120));
        let expires = issued.saturating_add(timeout.as_millis() as i64);
        let receipt = proxy.receipt();
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: validated_id(self.session.into()),
            action_id: validated_id(random_id("action")),
            request_id: validated_id(random_id("request")),
            tool,
            target: format!("mcp__{}__{name}", proxy.manifest.namespace),
            parameters: json!({"arguments":args,"remote":receipt,"rule_package":self.rule_policy.map(|p| p.receipt(self.policy)).transpose()?}),
            policy_version: validated_id(self.policy.into()),
            issued_at_ms: issued,
            expires_at_ms: expires,
            nonce: random_nonce(),
            sources: self
                .sources
                .lock()
                .map_err(|_| anyhow::anyhow!("来源锁失效"))?
                .action_sources()?,
        })?;
        let decision = self
            .gate
            .judge_remote(&action.spec().target, proxy.endpoint(), args);
        if self.journal.decided(&action, &decision).is_err() {
            *self.journal_failed = true;
            anyhow::bail!("远程动作判决不能持久保存");
        }
        let mut output = ExecOutput {
            ok: false,
            detail: String::new(),
            truncated: false,
            outcome: ExecutionOutcome::Refused,
            dispatched: false,
            capture: None,
        };
        let mut result = refusal("远程动作被规则拒绝");
        let mut approval_id = None;
        let mut _policy_lease = None;
        if !matches!(decision, Outcome::Refuse { .. }) {
            let approval = ApprovalBinding::new(
                validated_id(random_id("confirm")),
                action.clone(),
                random_nonce(),
                issued,
                expires,
            )?;
            approval_id = Some(approval.approval_id().to_string());
            let hash = crate::tool_registry::digest(&action.canonical_bytes());
            let resolution=self.pending.wait(ConfirmRequest{id:approval.approval_id().to_string(),
                what:format!("向远程服务发送并调用 {}\n目标：{}\n参数（JSON 转义）：{}\n连接身份：{}\n动作 SHA-256：{}\n批准包括远程初始化及调用；参数将发送到该服务。远端可能产生外部副作用，断连或暂停不能保证远端动作停止，未知结果不得自动重发。",action.spec().target,proxy.endpoint(),args,receipt,hash.as_str()),
                findings:decision.findings().to_vec(),binding:Some(approval.clone()),action_sha256:Some(hash.as_str().into())},timeout);
            if resolution.answer == Answer::Approved {
                match crate::rule_policy::acquire(self.rule_policy, self.policy) {
                    Ok(lease) => _policy_lease = lease,
                    Err(error) => {
                        return ProxyCompletion {
                            pending: self.pending,
                            sources: self.sources,
                            journal: self.journal,
                            journal_failed: self.journal_failed,
                        }
                        .finish(
                            &action,
                            approval_id.as_deref(),
                            output,
                            refusal(&format!("规则包已变化，未发送远程请求：{error}")),
                            "remote",
                            receipt,
                        )
                    }
                }
                let permit = DispatchPermit {
                    pending: self.pending.clone(),
                    epoch,
                    registry: self.registry.clone(),
                    action: action.clone(),
                    approval,
                };
                match permit.with(|| self.journal.started(&action, approval_id.as_deref())) {
                    Some(Ok(())) => {
                        client.set_dispatch_guard(Box::new(permit.clone()))?;
                        let remote_result = self.exchange(
                            proxy,
                            name,
                            args,
                            &mut client,
                            &permit,
                            &mut output.dispatched,
                        );
                        match remote_result {
                            Ok(downstream) => {
                                output.ok = downstream.get("isError").and_then(Value::as_bool)
                                    != Some(true);
                                output.outcome = if output.ok {
                                    ExecutionOutcome::Success
                                } else {
                                    ExecutionOutcome::Failed
                                };
                                result = downstream;
                            }
                            Err(error) => {
                                output.outcome = if output.dispatched {
                                    ExecutionOutcome::Unknown
                                } else {
                                    ExecutionOutcome::Refused
                                };
                                if output.dispatched {
                                    self.pending.pause();
                                    result=mcp::tool_error(format!("远程动作终态未知，会话已暂停；远端可能继续执行，不自动重试：{error}"));
                                } else {
                                    result = refusal(&format!("远程请求未发送：{error}"));
                                }
                            }
                        }
                    }
                    Some(Err(_)) => {
                        *self.journal_failed = true;
                        result = refusal("开始审计不能持久保存，未建立远程连接");
                    }
                    None => {
                        output.outcome = ExecutionOutcome::Cancelled;
                        result = refusal("派发前许可已撤销，未建立远程连接");
                    }
                }
            } else {
                output.outcome = match resolution.source {
                    "timeout" => ExecutionOutcome::TimedOut,
                    "paused" | "disconnected" => ExecutionOutcome::Cancelled,
                    _ => ExecutionOutcome::Refused,
                };
                result = refusal(&format!("远程动作未获批准：{}", resolution.source));
            }
        }
        client.close();
        ProxyCompletion {
            pending: self.pending,
            sources: self.sources,
            journal: self.journal,
            journal_failed: self.journal_failed,
        }
        .finish(
            &action,
            approval_id.as_deref(),
            output,
            result,
            "remote",
            receipt,
        )
    }
    fn exchange(
        &self,
        proxy: &RemoteService,
        name: &str,
        args: &Value,
        client: &mut RemoteClient,
        permit: &DispatchPermit,
        dispatched: &mut bool,
    ) -> Result<Value> {
        let end = Instant::now() + Duration::from_secs(30);
        let left = || end.saturating_duration_since(Instant::now());
        let init = track(
            client.initialize(left(), &|| permit.cancelled()),
            dispatched,
        )?;
        let list = track(
            client.list_tools(left(), &|| permit.cancelled()),
            dispatched,
        )?;
        let current = proxy.current_manifest(init, list)?;
        if current.canonical_bytes() != proxy.manifest.canonical_bytes() {
            self.registry
                .lock()
                .map_err(|_| anyhow::anyhow!("登记锁失效"))?
                .observe(current)?;
            anyhow::bail!("运行清单发生变化，旧认可已撤销，未发送工具调用；初始化可能已有副作用");
        }
        match track(
            client.call_tool(name, args.clone(), left(), &|| permit.cancelled()),
            dispatched,
        )? {
            Reply::Result(value) => {
                proxy.validate_output(name, &value)?;
                Ok(value)
            }
            Reply::Error(value) => Ok(
                json!({"content":[{"type":"text","text":serde_json::to_string(&value)?}],"isError":true}),
            ),
        }
    }
}
fn track<T>(result: std::result::Result<T, RemoteError>, dispatched: &mut bool) -> Result<T> {
    match result {
        Ok(value) => {
            *dispatched = true;
            Ok(value)
        }
        Err(error) => {
            *dispatched |= error.dispatched;
            Err(error.into())
        }
    }
}
