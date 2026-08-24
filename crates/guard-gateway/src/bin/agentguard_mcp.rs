//! `agentguard-mcp`：把 AgentGuard 当成 MCP 服务器跑起来。
//!
//! # 用法
//!
//! ```text
//! agentguard-mcp --rules crates/guard-schema/rules/p0_rules.yaml \
//!                --shell-policy crates/guard-shell/policies/default.yaml \
//!                --plans policies/task-plans.yaml \
//!                --confirm-port 8790
//! ```
//!
//! 然后在智能体的 MCP 配置里把它作为一个 stdio server 加上。智能体调
//! `agentguard.run_shell` 而不是自己的 shell，于是被拒绝的调用**不会执行**。
//!
//! # 确认怎么答
//!
//! `require_confirm` 的调用会挂住。答案从环回 HTTP 进来：
//!
//! ```text
//! curl -s localhost:8790/pending          # 看当前待确认的是什么
//! curl -XPOST localhost:8790/approve      # 批准
//! curl -XPOST localhost:8790/deny         # 拒绝
//! ```
//!
//! 超时（默认 120 秒）按**拒绝**处理。这不是保守设定，是唯一正确的方向：一个等不到答案就
//! 放行的闸门，被攻击的方法就是等，而等待是免费的。
//!
//! # 强制力
//!
//! **协作式。** 绕过本网关直接执行是可行的，所以它在运行不等于这台机器受到了内核级保护。

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use guard_gateway::{Gate, PendingConfirm, Server};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> anyhow::Result<()> {
    let rules = arg("--rules").unwrap_or_else(|| "crates/guard-schema/rules/p0_rules.yaml".into());
    let shell_policy =
        arg("--shell-policy").unwrap_or_else(|| "crates/guard-shell/policies/default.yaml".into());
    let plans = arg("--plans");
    let task = arg("--task");
    let confirm_port: u16 = arg("--confirm-port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(8790);
    let confirm_timeout = Duration::from_secs(
        arg("--confirm-timeout-secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(120),
    );

    // stderr 用来说人话。stdout 是 MCP 通道，往里写任何非协议内容都会破坏它 ——
    // 这是 stdio 传输最容易犯的错，所以整个程序里只有一处 println!。
    eprintln!(
        "agentguard-mcp 启动：强制力 = {}",
        guard_gateway::ENFORCEMENT
    );
    eprintln!("  规则      {rules}");
    eprintln!("  shell策略 {shell_policy}");

    let mut shell = guard_shell::SafeShell::from_path(&shell_policy)?;
    if let Some(plans_path) = &plans {
        let library =
            guard_schema::TaskPlanLibrary::from_yaml_str(&std::fs::read_to_string(plans_path)?)?;
        let profile = task.as_deref().unwrap_or_default();
        match library.plan_for(profile) {
            None => eprintln!(
                "  警告：计划库里没有 '{profile}'，本次没有 paths 天花板 —— \
                 只有无条件敏感目标会被拒"
            ),
            Some(plan) => {
                let p = plan.scope.paths.clone().unwrap_or_default();
                let (s2, rejected) =
                    shell.with_workspace(p.read.unwrap_or_default(), p.write.unwrap_or_default());
                shell = s2;
                for r in &rejected {
                    eprintln!("  警告：丢弃了一条路径授权 {r}");
                }
                eprintln!(
                    "  路径天花板 read={:?} write={:?}",
                    shell.workspace().read_grants(),
                    shell.workspace().write_grants()
                );
            }
        }
    } else {
        eprintln!("  警告：没给 --plans，因此没有 paths 天花板；写和删只能判成「证明不了」");
    }

    let engine = guard_core::Engine::from_paths(PathBuf::from(&rules), None::<PathBuf>)?;
    let pending = PendingConfirm::new();
    let mut server = Server::new(Gate::new(shell, engine), pending.clone(), confirm_timeout);

    // 确认用的环回接口。只绑 127.0.0.1 —— 一个能远程批准动作的端口，就是把闸门送给网络。
    let addr = format!("127.0.0.1:{confirm_port}");
    match tiny_http::Server::http(&addr) {
        Err(e) => {
            eprintln!("  警告：确认接口起不来（{e}）；require_confirm 只能等超时，也就是拒绝")
        }
        Ok(http) => {
            eprintln!("  确认接口 http://{addr}  (GET /pending, POST /approve, POST /deny)");
            let p = pending.clone();
            std::thread::spawn(move || {
                for req in http.incoming_requests() {
                    let (status, body) = match (req.method().as_str(), req.url()) {
                        ("GET", "/pending") => match p.peek() {
                            Some(c) => (200, serde_json::to_string(&c).unwrap_or_default()),
                            None => (200, "null".to_string()),
                        },
                        ("POST", "/approve") => {
                            let ok = p.answer(guard_gateway::Answer::Approved);
                            (if ok { 200 } else { 409 }, format!("{{\"answered\":{ok}}}"))
                        }
                        ("POST", "/deny") => {
                            let ok = p.answer(guard_gateway::Answer::Denied);
                            (if ok { 200 } else { 409 }, format!("{{\"answered\":{ok}}}"))
                        }
                        _ => (404, "{\"error\":\"not found\"}".to_string()),
                    };
                    let header = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json"[..],
                    )
                    .expect("静态 header");
                    let _ = req.respond(
                        tiny_http::Response::from_string(body)
                            .with_status_code(status)
                            .with_header(header),
                    );
                }
            });
        }
    }

    // MCP 主循环：一行一个 JSON。
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<guard_gateway::mcp::Request>(&line) {
            Ok(req) => server.handle(req),
            // 解析失败也要回一个规范的错误。静默丢弃会让对端一直等，而"一直等"在这条通道上
            // 和"被拒绝"长得不一样，却同样让智能体停住。
            Err(e) => Some(guard_gateway::mcp::error(
                serde_json::Value::Null,
                guard_gateway::mcp::code::PARSE_ERROR,
                format!("JSON 解析失败：{e}"),
                None,
            )),
        };
        if let Some(v) = response {
            writeln!(stdout, "{v}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
