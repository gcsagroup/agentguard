//! 把协议、判决、执行接起来。
//!
//! 这个文件是网关的全部行为，所以它是唯一一处能看清"判决怎么变成不执行"的地方。

use crate::confirm::{Answer, ConfirmRequest, PendingConfirm};
use crate::exec::{ExecOutput, ToolCall};
use crate::gate::{Gate, Outcome, ENFORCEMENT};
use crate::mcp;
use guard_shell::ShellAction;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

pub struct Server {
    gate: Gate,
    pending: PendingConfirm,
    confirm_timeout: Duration,
    /// 已执行/已拒绝的计数，`gateway/stats` 用。
    executed: u64,
    refused: u64,
}

/// 一次调用走完之后发生了什么。测试断言的是这个，而不是 JSON 文本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    Executed { output: ExecOutput },
    Refused { reason: String },
}

impl Server {
    pub fn new(gate: Gate, pending: PendingConfirm, confirm_timeout: Duration) -> Self {
        Self {
            gate,
            pending,
            confirm_timeout,
            executed: 0,
            refused: 0,
        }
    }

    pub fn pending(&self) -> PendingConfirm {
        self.pending.clone()
    }

    pub fn gate_mut(&mut self) -> &mut Gate {
        &mut self.gate
    }

    /// 工具清单。
    pub fn tools() -> Vec<Value> {
        let path_prop = json!({ "type": "string", "description": "绝对路径，或 ~/ 开头" });
        vec![
            mcp::tool(
                "run_shell",
                "执行一条命令。以参数向量执行，不经过 shell：不做变量展开、不做通配符展开、\
                 不解释 `;` `|` 等元字符。被拒绝时不会执行。",
                json!({
                    "type": "object",
                    "properties": {
                        "argv": {
                            "type": "array", "items": { "type": "string" },
                            "description": "argv[0] 是可执行文件名。不要传 `sh -c \"...\"`——那会把\
                                            守卫刚挡下的 shell 解释又请回来。"
                        },
                        "cwd": { "type": "string", "description": "工作目录，可选" }
                    },
                    "required": ["argv"]
                }),
            ),
            mcp::tool(
                "read_file",
                "读一个文件。凭据目录（~/.ssh、~/.aws 等）会被拒绝，即使只是读。",
                json!({ "type": "object", "properties": { "path": path_prop.clone() }, "required": ["path"] }),
            ),
            mcp::tool(
                "write_file",
                "写一个文件。落在会话 paths 天花板之外会被拒绝。",
                json!({
                    "type": "object",
                    "properties": { "path": path_prop.clone(), "contents": { "type": "string" } },
                    "required": ["path", "contents"]
                }),
            ),
            mcp::tool(
                "delete_file",
                "删除一个文件。不递归——递归删除请走 run_shell，那条路上的路径判决更完整。",
                json!({ "type": "object", "properties": { "path": path_prop }, "required": ["path"] }),
            ),
            mcp::tool(
                "start_session",
                "开一个受守卫的会话并声明任务。任务名选中计划，计划带着资源与路径天花板。\
                 不开会话也能调工具，但那时没有天花板，写和删只能证明不了包含关系。",
                json!({
                    "type": "object",
                    "properties": { "task_profile": { "type": "string", "description": "如 book_hotel" } }
                }),
            ),
            mcp::tool(
                "end_session",
                "结束当前会话。",
                json!({ "type": "object", "properties": {} }),
            ),
        ]
    }

    /// 处理一条请求，返回要发回去的 JSON（通知返回 `None`）。
    pub fn handle(&mut self, req: mcp::Request) -> Option<Value> {
        // 通知没有 id，不回响应。
        let id = req.id.clone()?;

        let out = match req.method.as_str() {
            "initialize" => mcp::result(
                id,
                mcp::initialize_result("agentguard-mcp", env!("CARGO_PKG_VERSION")),
            ),
            "tools/list" => mcp::result(id, json!({ "tools": Self::tools() })),
            "tools/call" => self.handle_tool_call(id, &req.params),
            "ping" => mcp::result(id, json!({})),
            // 网关自己的状态，方便宿主 UI 展示，也让"这是协作式"这句话有个可查询的出处。
            "gateway/stats" => mcp::result(
                id,
                json!({
                    "enforcement": ENFORCEMENT,
                    "executed": self.executed,
                    "refused": self.refused,
                    "session_id": self.gate.session_id(),
                    "rules_loaded": self.gate.engine_status().rules_loaded,
                    "policy_id": self.gate.shell().policy_id(),
                }),
            ),
            other => mcp::error(
                id,
                mcp::code::METHOD_NOT_FOUND,
                format!("未知方法 {other}"),
                None,
            ),
        };
        Some(out)
    }

    fn handle_tool_call(&mut self, id: Value, params: &Value) -> Value {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = params.get("arguments").cloned().unwrap_or(json!({}));

        match name {
            "start_session" => {
                let profile = args.get("task_profile").and_then(Value::as_str);
                let sid = format!("mcp-session-{}", self.executed + self.refused + 1);
                match self.gate.start_session(&sid, profile) {
                    Ok(d) => mcp::result(
                        id,
                        mcp::tool_text(format!(
                            "会话已开始 {sid}（任务 {}）：{:?} [{}]",
                            profile.unwrap_or("未声明"),
                            d.action,
                            d.rule_id
                        )),
                    ),
                    Err(e) => mcp::error(
                        id,
                        mcp::code::INTERNAL_ERROR,
                        format!("开会话失败：{e}"),
                        None,
                    ),
                }
            }
            "end_session" => match self.gate.end_session() {
                Ok(d) => mcp::result(id, mcp::tool_text(format!("会话已结束：[{}]", d.rule_id))),
                Err(e) => mcp::error(
                    id,
                    mcp::code::INTERNAL_ERROR,
                    format!("结束会话失败：{e}"),
                    None,
                ),
            },
            "run_shell" | "read_file" | "write_file" | "delete_file" => {
                match self.parse_tool(name, &args) {
                    Err(why) => mcp::result(id, mcp::tool_error(format!("参数不合法：{why}"))),
                    Ok((call, action)) => {
                        let handled = self.gate_and_run(call, action);
                        match handled {
                            Handled::Executed { output } => {
                                let mut text = output.detail;
                                if output.truncated {
                                    text.push_str("\n[输出已截断]");
                                }
                                if output.ok {
                                    mcp::result(id, mcp::tool_text(text))
                                } else {
                                    // 工具自己失败（文件不存在之类）也走 isError，但要和"被守卫
                                    // 拒绝"区分开，否则智能体会把一次 ENOENT 当成策略问题。
                                    mcp::result(
                                        id,
                                        mcp::tool_error(format!(
                                            "工具执行失败（不是守卫拒绝）：{text}"
                                        )),
                                    )
                                }
                            }
                            Handled::Refused { reason } => mcp::result(id, mcp::tool_error(reason)),
                        }
                    }
                }
            }
            other => mcp::result(id, mcp::tool_error(format!("未知工具 {other}"))),
        }
    }

    /// 判、按需确认、只有在通过时才执行。
    ///
    /// **公开出来是为了能被直接测试。** 测试可以在这里断言"返回了 Refused"**并且**"文件确实还在"——
    /// 只断言前者，就还是那种"机制存在、被直接测过、什么都没接上"的缺陷。
    pub fn gate_and_run(&mut self, call: ToolCall, action: ShellAction) -> Handled {
        let outcome = self.gate.judge(&action);
        let findings = outcome.findings().to_vec();
        let render = |fs: &[crate::gate::Finding]| {
            fs.iter()
                .map(|f| format!("[{}/{}] {}", f.layer, f.rule_id, f.message))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let approved = match outcome {
            Outcome::Refuse { .. } => false,
            Outcome::Execute { .. } => true,
            Outcome::NeedsConfirmation { .. } => {
                let res = self.pending.wait(
                    ConfirmRequest {
                        id: format!("confirm-{}", self.executed + self.refused + 1),
                        what: call.describe(),
                        findings: findings.clone(),
                    },
                    self.confirm_timeout,
                );
                if res.answer == Answer::Denied {
                    self.refused += 1;
                    return Handled::Refused {
                        reason: format!(
                            "已拒绝（{}）。强制力：{ENFORCEMENT}。\n{}\n\n未执行：{}",
                            if res.source == "timeout" {
                                "等待确认超时——超时按拒绝处理，因为一个等不到答案就放行的闸门，\
                                 被攻击的方法就是等"
                            } else {
                                "使用者拒绝"
                            },
                            render(&findings),
                            call.describe()
                        ),
                    };
                }
                true
            }
        };

        if !approved {
            self.refused += 1;
            return Handled::Refused {
                reason: format!(
                    "已拒绝。强制力：{ENFORCEMENT}。\n{}\n\n未执行：{}\n\n\
                     这是一个判决，不是故障——重试不会改变结果。请改成一个落在授权范围内的动作。",
                    render(&findings),
                    call.describe()
                ),
            };
        }

        self.executed += 1;
        let output = call.execute();
        // Alert 的判据要跟着结果回去，让智能体自己看到——告警的语义是"这值得知道"，
        // 把它藏起来就只剩下日志里的一行。
        let alerts: Vec<_> = findings
            .iter()
            .filter(|f| matches!(f.severity.as_str(), "high" | "critical" | "medium"))
            .cloned()
            .collect();
        if alerts.is_empty() {
            return Handled::Executed { output };
        }
        Handled::Executed {
            output: ExecOutput {
                ok: output.ok,
                detail: format!(
                    "{}\n\n--- 守卫发现（已执行）---\n{}",
                    output.detail,
                    render(&alerts)
                ),
                truncated: output.truncated,
            },
        }
    }

    /// 把 MCP 参数变成 (要执行的东西, 要判的动作)。
    ///
    /// 两者分开构造，是因为判决看的是**命令的形状**（动词、标志、路径操作数），而执行看的是
    /// 结构化的调用。用同一个结构去做两件事，就得在其中一边做字符串还原，而还原是引入分歧的
    /// 地方——判的和执行的必须是同一件事。
    fn parse_tool(&self, name: &str, args: &Value) -> Result<(ToolCall, ShellAction), String> {
        let get_path = |key: &str| -> Result<PathBuf, String> {
            args.get(key)
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .ok_or_else(|| format!("缺少字符串参数 {key}"))
        };
        match name {
            "run_shell" => {
                let argv: Vec<String> = args
                    .get("argv")
                    .and_then(Value::as_array)
                    .ok_or("缺少数组参数 argv")?
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default().to_string())
                    .collect();
                if argv.is_empty() || argv[0].trim().is_empty() {
                    return Err("argv 为空".into());
                }
                let cwd = args.get("cwd").and_then(Value::as_str).map(PathBuf::from);
                // argv[0] 是要跑的程序，其余是操作数——路径判决要看的就是这些操作数。
                let action = ShellAction {
                    tool: "run_terminal".into(),
                    action: Some(argv[0].clone()),
                    target: argv.get(1).cloned(),
                    args: argv.iter().skip(2).cloned().collect(),
                };
                Ok((ToolCall::RunShell { argv, cwd }, action))
            }
            "read_file" => {
                let path = get_path("path")?;
                Ok((
                    ToolCall::ReadFile { path: path.clone() },
                    ShellAction {
                        tool: "read_file".into(),
                        action: None,
                        target: Some(path.to_string_lossy().into_owned()),
                        args: vec![],
                    },
                ))
            }
            "write_file" => {
                let path = get_path("path")?;
                let contents = args
                    .get("contents")
                    .and_then(Value::as_str)
                    .ok_or("缺少字符串参数 contents")?
                    .to_string();
                Ok((
                    ToolCall::WriteFile {
                        path: path.clone(),
                        contents,
                    },
                    ShellAction {
                        tool: "write_file".into(),
                        action: None,
                        target: Some(path.to_string_lossy().into_owned()),
                        args: vec![],
                    },
                ))
            }
            "delete_file" => {
                let path = get_path("path")?;
                Ok((
                    ToolCall::DeleteFile { path: path.clone() },
                    ShellAction {
                        tool: "run_terminal".into(),
                        action: Some("rm".into()),
                        target: Some(path.to_string_lossy().into_owned()),
                        args: vec![],
                    },
                ))
            }
            other => Err(format!("未知工具 {other}")),
        }
    }
}
