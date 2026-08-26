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

/// 启动时生成的确认令牌。128 位 OS 随机,十六进制。
///
/// 只打到 stderr。操作员看得到(Chrome/终端日志),浏览器里的页面看不到 —— 这正是
/// `Origin` 检查之外还需要它的原因:页面能发出请求,但发不出这个头的正确值。
fn new_confirm_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn header_value<'a>(req: &'a tiny_http::Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// `None` = 放行;`Some(reason)` = 拒绝。
///
/// 常数时间比较不是这里的重点(令牌是 128 位随机、进程生命周期内有效、且每次失败都不
/// 透露任何状态),但顺带做了,免得以后有人把它当成可以计时的东西。
fn reject_confirm_request(req: &tiny_http::Request, token: &str) -> Option<&'static str> {
    // 跨站标记:一个由页面发起的请求会带上其中之一。本地 UI 和 curl 不会。
    if let Some(site) = header_value(req, "Sec-Fetch-Site") {
        if site != "same-origin" && site != "none" {
            return Some("cross-site request refused");
        }
    }
    if header_value(req, "Origin").is_some() {
        return Some("requests carrying Origin are refused");
    }
    let Some(auth) = header_value(req, "Authorization") else {
        return Some("missing Authorization: Bearer <token>");
    };
    let Some(got) = auth.strip_prefix("Bearer ") else {
        return Some("Authorization must be a Bearer token");
    };
    let (got, want) = (got.trim().as_bytes(), token.as_bytes());
    let equal =
        got.len() == want.len() && got.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !equal {
        return Some("bad confirm token");
    }
    None
}

/// 从 `{"id":"confirm-3"}` 里取出 id。取不到就是取不到 —— 不回落到"当前那个"。
fn confirm_id_from_body(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("id")?
        .as_str()
        .map(str::to_string)
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn respond_json(req: tiny_http::Request, status: u16, body: &str) {
    let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("静态 header");
    let _ = req.respond(
        tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(header),
    );
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

    // 确认用的环回接口。
    //
    // 只绑 127.0.0.1 挡的是**网络**,挡不住**浏览器里的页面** —— 而页面正是本产品的威胁
    // 模型主体。旧版本只匹配 method + url:一个隐藏的自动提交 HTML form 就能发出逐字节
    // 合法的 `POST /approve`(简单请求,不触发预检),复核实测批准掉了一次 delete_file,
    // 文件真的被删了;`GET /pending` 也无凭据可读,泄漏待确认命令的全文和判据。
    //
    // 三道门,一起加:
    //   1. 启动时生成的 bearer 令牌,只打到 stderr(操作员看得到,页面看不到);
    //   2. 拒绝任何带跨站标记的请求(`Origin` / `Sec-Fetch-Site: cross-site`);
    //   3. 批准必须带上 `/pending` 给出的 `id`(见 `PendingConfirm::answer_id`)。
    // 令牌是主防线;2 和 3 是纵深 —— 就算令牌泄漏,跨站请求仍然被拒,而拿不到当前 id 的
    // 批准也落不到任何请求上。
    let confirm_token = new_confirm_token();
    let addr = format!("127.0.0.1:{confirm_port}");
    match tiny_http::Server::http(&addr) {
        Err(e) => {
            eprintln!("  警告：确认接口起不来（{e}）；require_confirm 只能等超时，也就是拒绝")
        }
        Ok(http) => {
            eprintln!("  确认接口 http://{addr}  (GET /pending, POST /approve, POST /deny)");
            eprintln!("  确认令牌 {confirm_token}");
            eprintln!("    每个请求都要带 Authorization: Bearer <令牌>；");
            eprintln!(
                "    批准/拒绝的 body 要带 /pending 给出的 id，例如 {{\"id\":\"confirm-1\"}}"
            );
            let p = pending.clone();
            let token = confirm_token.clone();
            std::thread::spawn(move || {
                for mut req in http.incoming_requests() {
                    // 先鉴权,再看路由。任何一条没通过的,连"现在有没有待确认"都不透露。
                    if let Some(why) = reject_confirm_request(&req, &token) {
                        respond_json(req, 403, &format!("{{\"error\":{}}}", json_str(why)));
                        continue;
                    }
                    let mut body = String::new();
                    if req.method().as_str() == "POST" {
                        use std::io::Read;
                        let _ = req.as_reader().take(4096).read_to_string(&mut body);
                    }
                    let (status, body) = match (req.method().as_str(), req.url()) {
                        ("GET", "/pending") => match p.peek() {
                            Some(c) => (200, serde_json::to_string(&c).unwrap_or_default()),
                            None => (200, "null".to_string()),
                        },
                        ("POST", "/approve") | ("POST", "/deny") => {
                            let ans = if req.url() == "/approve" {
                                guard_gateway::Answer::Approved
                            } else {
                                guard_gateway::Answer::Denied
                            };
                            match confirm_id_from_body(&body) {
                                None => (
                                    400,
                                    "{\"error\":\"body must be {\\\"id\\\":\\\"<confirm id from /pending>\\\"}\"}"
                                        .to_string(),
                                ),
                                Some(id) => {
                                    let ok = p.answer_id(&id, ans);
                                    (
                                        if ok { 200 } else { 409 },
                                        format!("{{\"answered\":{ok}}}"),
                                    )
                                }
                            }
                        }
                        _ => (404, "{\"error\":\"not found\"}".to_string()),
                    };
                    respond_json(req, status, &body);
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
