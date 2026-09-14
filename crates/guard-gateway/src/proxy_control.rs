//! 产品入口的单次 MCP 执行：批准覆盖进程初始化及调用，容器退出后才返回主循环。
use super::*;
use crate::mcp_permission::DispatchPermit;
use crate::mcp_proxy::{ProxyConfig, ProxyService};
use crate::mcp_recovery::RecoveryLog;
use crate::mcp_service::ServiceWorkspace;
use crate::mcp_stdio::Reply;
use anyhow::{ensure, Context, Result};
use std::path::Path;
use std::time::Instant;

impl Server {
    pub fn with_mcp_services(mut self, config: ProxyConfig, recovery_path: &Path) -> Result<Self> {
        ensure!(
            config.version == 1 && !config.services.is_empty() && config.services.len() <= 4,
            "服务配置版本或数量无效"
        );
        ensure!(self.proxies.is_empty(), "不能重复配置服务");
        ensure!(
            self.journal.as_ref().is_some_and(ExecutionJournal::healthy),
            "第三方服务需要持久执行审计"
        );
        let isolation = self
            .isolation
            .as_ref()
            .context("第三方服务需要隔离工作区")?;
        let image = isolation.status()["image"]
            .as_str()
            .context("隔离镜像身份缺失")?
            .to_owned();
        // 先完成旧容器恢复，再启动任何新发现进程；恢复失败时整个配置拒绝启用。
        self.proxy_recovery = Some(RecoveryLog::open(recovery_path)?);
        let mut ids = std::collections::HashSet::new();
        let mut namespaces = std::collections::HashSet::new();
        for service in config.services {
            ensure!(
                ids.insert(service.service_id.clone())
                    && namespaces.insert(service.namespace.clone()),
                "服务标识或命名空间重复"
            );
            let proxy = ProxyService::discover(
                service,
                &image,
                isolation,
                &self.registry,
                self.proxy_recovery.as_mut().expect("已打开恢复索引"),
            )?;
            self.registry
                .lock()
                .map_err(|_| anyhow::anyhow!("登记锁失效"))?
                .attach_proxy(&proxy.manifest)?;
            self.proxies.push(proxy);
        }
        Ok(self)
    }
    pub(super) fn proxy_call(&mut self, name: &str, args: &Value) -> Value {
        if self.host_session_state() != "active" {
            return refusal("宿主会话未激活，第三方服务未启动");
        }
        let Some((proxy, original)) = self
            .proxies
            .iter()
            .find_map(|p| p.original_name(name).map(|n| (p, n)))
        else {
            return refusal("第三方工具没有实际配置来源，未执行");
        };
        let Some(isolation) = self.isolation.as_ref() else {
            return refusal("隔离工作区不可用");
        };
        let Some(journal) = self.journal.as_ref() else {
            return refusal("执行审计不可用");
        };
        let Some(recovery) = self.proxy_recovery.as_mut() else {
            return refusal("服务恢复索引不可用");
        };
        let mut host = ProxyHost {
            gate: &mut self.gate,
            pending: &self.pending,
            registry: &self.registry,
            sources: &self.sources,
            journal,
            recovery,
            journal_failed: &mut self.journal_failed,
            isolation,
            confirm_timeout: self.confirm_timeout,
            session: &self.host_session_id,
            policy: &self.policy_version,
        };
        let result = match host.invoke(proxy, original, args) {
            Ok(result) => result,
            Err(error) => refusal(&format!("第三方服务未获准启动：{error}")),
        };
        if result.pointer("/_meta/agentguard/dispatched") == Some(&json!(true)) {
            self.executed += 1;
        } else {
            self.refused += 1;
        }
        result
    }
}
fn refusal(message: &str) -> Value {
    let mut result = mcp::tool_error(message);
    result["_meta"] = json!({"agentguard":{"outcome":"refused","dispatched":false,"instruction_authority":"none"}});
    result
}
struct ProxyHost<'a> {
    gate: &'a mut Gate,
    pending: &'a PendingConfirm,
    registry: &'a crate::tool_registry::SharedRegistry,
    sources: &'a SharedSources,
    journal: &'a ExecutionJournal,
    recovery: &'a mut RecoveryLog,
    journal_failed: &'a mut bool,
    isolation: &'a DockerExecutor,
    confirm_timeout: Duration,
    session: &'a str,
    policy: &'a str,
}
impl ProxyHost<'_> {
    fn invoke(&mut self, proxy: &ProxyService, name: &str, args: &Value) -> Result<Value> {
        ensure!(proxy.service.healthy(), "服务清理状态未知");
        proxy.validate_input(name, args)?;
        let tool = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("登记锁失效"))?
            .identity(&proxy.manifest.service_id, name)?;
        ensure!(
            tool.registration.as_ref().is_some_and(|r| r.manifest_sha256
                == crate::tool_registry::digest(&proxy.manifest.canonical_bytes())),
            "登记已改变，需要重新配置实际服务"
        );
        let epoch = self.pending.cancellation_epoch();
        let prepared = proxy
            .service
            .prepare(&proxy.arguments, ServiceWorkspace::Snapshot(self.isolation))?;
        let receipt = prepared.receipt().clone();
        let container_name = prepared.container_name().to_owned();
        let issued = now_ms();
        let expires = issued.saturating_add(self.confirm_timeout.as_millis().min(120_000) as i64);
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: validated_id(self.session.into()),
            action_id: validated_id(random_id("action")),
            request_id: validated_id(random_id("request")),
            tool,
            target: format!("mcp__{}__{name}", proxy.manifest.namespace),
            parameters: json!({"arguments":args,"process":receipt,"container_name":container_name,
                "execution_backend":self.isolation.status()}),
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
        let decision = self.gate.judge_proxy(&action.spec().target, args);
        if self.journal.decided(&action, &decision).is_err() {
            *self.journal_failed = true;
            anyhow::bail!("判决审计不能持久保存");
        }
        let mut output = ExecOutput {
            ok: false,
            detail: String::new(),
            truncated: false,
            outcome: ExecutionOutcome::Refused,
            dispatched: false,
            capture: None,
        };
        let mut approval_id = None;
        let mut result = refusal("动作被规则拒绝");
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
            let resolution=self.pending.wait(ConfirmRequest{
                id:approval.approval_id().to_string(),
                what:format!("启动第三方服务并调用 {}\n参数（JSON 转义）：{}\n授权范围：{}\n包 SHA-256：{}\n运行 SHA-256：{}\n动作 SHA-256：{}\n服务初始化和调用均可修改授权副本；原目录须另行预览并批准回写。",action.spec().target,args,
                    self.isolation.workspaces(),receipt.package_sha256.as_str(),receipt.execution_sha256.as_str(),hash.as_str()),
                findings:decision.findings().to_vec(),binding:Some(approval.clone()),action_sha256:Some(hash.as_str().to_owned()),
            },self.confirm_timeout.min(Duration::from_secs(120)));
            if resolution.answer == Answer::Approved {
                let permit = DispatchPermit {
                    pending: self.pending.clone(),
                    epoch,
                    registry: self.registry.clone(),
                    action: action.clone(),
                    approval,
                };
                let mut recovery_started = false;
                let launch = permit.with(|| -> Result<_> {
                    self.recovery.starting(&prepared)?;
                    recovery_started = true;
                    self.journal.started(&action, approval_id.as_deref())?;
                    // launch 的包复核在许可锁之外完成，实际系统调用仍在锁内。
                    Ok(())
                });
                match launch {
                    Some(Ok(())) => {
                        let launched = prepared.launch_with(|spawn| {
                            permit
                                .with(|| {
                                    output.dispatched = true;
                                    spawn()
                                })
                                .context("实际启动前许可已撤销")?
                        });
                        match launched {
                            Ok(mut process) => {
                                let call = (|| -> Result<Value> {
                                    process
                                        .client()
                                        .set_dispatch_guard(Box::new(permit.clone()))?;
                                    let deadline = Instant::now() + Duration::from_secs(30);
                                    let init = process.client().initialize(
                                        deadline.saturating_duration_since(Instant::now()),
                                        &|| permit.cancelled(),
                                    )?;
                                    let listing = process.client().list_tools(
                                        deadline.saturating_duration_since(Instant::now()),
                                        &|| permit.cancelled(),
                                    )?;
                                    let current = guard_schema::ToolServiceManifest::from_mcp(
                                        proxy.registration.service_id.clone(),
                                        proxy.registration.namespace.clone(),
                                        proxy.manifest.package.clone(),
                                        receipt.execution_sha256.clone(),
                                        init,
                                        listing,
                                    )?;
                                    if current.canonical_bytes() != proxy.manifest.canonical_bytes()
                                    {
                                        self.registry
                                            .lock()
                                            .map_err(|_| anyhow::anyhow!("登记锁失效"))?
                                            .observe(current)?;
                                        anyhow::bail!("实际运行清单已改变，未发送工具调用；初始化可能已有副作用");
                                    }
                                    let reply = process.client().call_tool(
                                        name,
                                        args.clone(),
                                        deadline.saturating_duration_since(Instant::now()),
                                        &|| permit.cancelled(),
                                    )?;
                                    match reply {
                                        Reply::Result(result) => {
                                            proxy.validate_output(name, &result)?;
                                            Ok(result)
                                        }
                                        Reply::Error(error) => Ok(
                                            json!({"content":[{"type":"text","text":serde_json::to_string(&error)?}],"isError":true}),
                                        ),
                                    }
                                })();
                                let shutdown = process.close();
                                match call {
                                    Ok(downstream) if shutdown.container_removed => {
                                        output.ok =
                                            downstream.get("isError").and_then(Value::as_bool)
                                                != Some(true);
                                        output.outcome = if output.ok {
                                            ExecutionOutcome::Success
                                        } else {
                                            ExecutionOutcome::Failed
                                        };
                                        result = downstream;
                                    }
                                    Err(error) => {
                                        output.outcome = ExecutionOutcome::Unknown;
                                        result=mcp::tool_error(format!("服务已启动，但无法确认动作终态；结果未知，不自动重试：{error}"));
                                    }
                                    _ => {
                                        output.outcome = ExecutionOutcome::Unknown;
                                        result = mcp::tool_error(
                                            "服务已返回，但容器清理未知，禁止后续执行",
                                        );
                                    }
                                }
                                if shutdown.container_removed
                                    && self.recovery.removed(&container_name, &receipt).is_err()
                                {
                                    *self.journal_failed = true;
                                    output.ok = false;
                                    output.outcome = ExecutionOutcome::Unknown;
                                    result = mcp::tool_error(
                                        "容器已清理，但恢复终态无法持久保存，已禁止后续动作",
                                    );
                                }
                            }
                            Err(error) => {
                                output.outcome = if output.dispatched {
                                    ExecutionOutcome::Unknown
                                } else {
                                    ExecutionOutcome::Cancelled
                                };
                                result = mcp::tool_error(format!(
                                    "服务未取得有效运行通道；不得自动重试：{error}"
                                ));
                                if proxy.service.healthy()
                                    && self.recovery.removed(&container_name, &receipt).is_err()
                                {
                                    *self.journal_failed = true;
                                }
                            }
                        }
                    }
                    Some(Err(_)) => {
                        *self.journal_failed = true;
                        result = refusal("开始审计或恢复索引写入失败，未启动服务");
                        if recovery_started {
                            let _ = self.recovery.removed(&container_name, &receipt);
                        }
                    }
                    None => {
                        output.outcome = ExecutionOutcome::Cancelled;
                        result = refusal("启动前许可已撤销，未执行");
                    }
                }
            } else {
                output.outcome = match resolution.source {
                    "timeout" => ExecutionOutcome::TimedOut,
                    "paused" | "disconnected" => ExecutionOutcome::Cancelled,
                    _ => ExecutionOutcome::Refused,
                };
                result = refusal(&format!("服务启动未获批准：{}", resolution.source));
            }
        }
        // 整个下游 JSON（含结构化内容和元数据）先进入来源检测，再添加宿主回执。
        output.detail = serde_json::to_string(&result)?;
        let source = if output.dispatched {
            let captured = self
                .sources
                .lock()
                .map_err(|_| anyhow::anyhow!("来源锁失效"))
                .and_then(|mut sources| {
                    sources.captured_output(
                        &crate::content::RawCapture::single(
                            guard_schema::ContentViewOrigin::ToolText,
                            output.detail.as_bytes(),
                            true,
                        ),
                        &output.detail,
                        guard_schema::SourceEntryPoint::ToolOutput,
                        true,
                    )
                });
            match captured {
                Ok(source) => Some(source),
                Err(_) => {
                    self.pending.pause();
                    output.ok = false;
                    output.outcome = ExecutionOutcome::Unknown;
                    result =
                        mcp::tool_error("服务已启动，但返回来源无法持久保存；结果未知，会话已暂停");
                    None
                }
            }
        } else {
            None
        };
        if !*self.journal_failed
            && self
                .journal
                .finished(
                    &action,
                    approval_id.as_deref(),
                    output.outcome,
                    Some(&output),
                )
                .is_err()
        {
            *self.journal_failed = true;
            output.ok = false;
            output.outcome = ExecutionOutcome::Unknown;
            result = mcp::tool_error("执行终态不能持久保存，结果未知，已禁止后续动作");
        }
        let metadata = result
            .as_object_mut()
            .context("工具返回不是对象")?
            .remove("_meta");
        result["_meta"] = json!({"agentguard":{"outcome":output.outcome,"dispatched":output.dispatched,
            "process":receipt,"action_sha256":crate::tool_registry::digest(&action.canonical_bytes()),
            "source":source,"instruction_authority":"none","downstream_metadata":metadata}});
        Ok(result)
    }
}
