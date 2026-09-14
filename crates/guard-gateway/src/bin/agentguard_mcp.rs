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
//! GET /status 或 /pending：必须带 Authorization: Bearer <本次进程令牌>
//! POST /approve 或 /deny：同样认证，并回传当前 id、动作摘要与单次批准随机值
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
use sha2::{Digest, Sha256};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// 启动时生成的确认令牌。128 位 OS 随机,十六进制。
///
/// 隔离模式只写独立宿主连接文件；原生兼容模式才使用 stderr。
fn new_confirm_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `None` = 放行;`Some(reason)` = 拒绝。
///
/// 常数时间比较不是这里的重点(令牌是 128 位随机、进程生命周期内有效、且每次失败都不
/// 透露任何状态),但顺带做了,免得以后有人把它当成可以计时的东西。
fn reject_confirm_request(
    req: &guard_gateway::control_http::ControlRequest,
    token: &str,
) -> Option<&'static str> {
    // 跨站标记:一个由页面发起的请求会带上其中之一。本地 UI 和 curl 不会。
    if let Some(site) = req.header("Sec-Fetch-Site") {
        if site != "same-origin" && site != "none" {
            return Some("cross-site request refused");
        }
    }
    if req.header("Origin").is_some() {
        return Some("requests carrying Origin are refused");
    }
    let Some(auth) = req.header("Authorization") else {
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

fn main() -> anyhow::Result<()> {
    let rules = arg("--rules").unwrap_or_else(|| "crates/guard-schema/rules/p0_rules.yaml".into());
    let shell_policy =
        arg("--shell-policy").unwrap_or_else(|| "crates/guard-shell/policies/default.yaml".into());
    let plans = arg("--plans");
    let task = arg("--task");
    let isolation_image = arg("--isolation-image");
    let audit_path = arg("--audit-db").map(PathBuf::from);
    let control_path = arg("--control-file").map(PathBuf::from);
    let browser_runtime = arg("--browser-runtime").map(PathBuf::from);
    let browser_node = arg("--browser-node").map(PathBuf::from);
    let browser_playwright = arg("--browser-playwright").map(PathBuf::from);
    let browser_browsers = arg("--browser-browsers").map(PathBuf::from);
    let browser_audit = arg("--browser-audit-db").map(PathBuf::from);
    let browser_file = arg("--browser-file").map(PathBuf::from);
    let cli_args = std::env::args().collect::<Vec<_>>();
    let browser_origins = cli_args
        .windows(2)
        .filter(|pair| pair[0] == "--browser-origin")
        .map(|pair| pair[1].clone())
        .collect::<Vec<_>>();
    let browser_enabled = browser_runtime.is_some();
    if browser_enabled != browser_node.is_some()
        || browser_enabled != browser_playwright.is_some()
        || browser_enabled != browser_browsers.is_some()
        || browser_enabled != browser_audit.is_some()
        || browser_enabled != browser_file.is_some()
        || browser_enabled == browser_origins.is_empty()
        || (browser_enabled && (control_path.is_none() || audit_path.is_none()))
    {
        anyhow::bail!("浏览器需要完整 --browser-runtime、--browser-node、--browser-playwright、--browser-browsers、--browser-audit-db、--browser-file、--browser-origin 及宿主控制和审计参数");
    }
    if browser_file.as_ref().is_some_and(|p| {
        Some(p) == control_path.as_ref()
            || Some(p) == audit_path.as_ref()
            || Some(p) == browser_audit.as_ref()
    }) || browser_audit
        .as_ref()
        .is_some_and(|p| Some(p) == audit_path.as_ref() || Some(p) == control_path.as_ref())
    {
        anyhow::bail!("浏览器执行连接文件、批准文件及两个审计数据库必须独立");
    }
    if isolation_image.is_some() && audit_path.is_none() {
        anyhow::bail!("隔离试点必须指定独立 --audit-db；执行开始与实际结果需要持久保存");
    }
    if isolation_image.is_some() && control_path.is_none() {
        anyhow::bail!("隔离试点必须指定独立 --control-file；批准凭据不能发送到客户端日志");
    }
    if control_path.is_some() && isolation_image.is_none() {
        anyhow::bail!("独立控制连接文件仅支持隔离工具模式；原生脚本不能保证批准凭据与任务隔离");
    }
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

    // 同一份启动字节既用于解析，也用于策略摘要；正常编辑策略文件不能造成归属错配。
    let rules_text = std::fs::read_to_string(&rules)?;
    let shell_text = std::fs::read_to_string(&shell_policy)?;
    let plans_text = plans.as_ref().map(std::fs::read_to_string).transpose()?;
    let mut shell =
        guard_shell::SafeShell::from_policy(guard_shell::ShellPolicy::from_yaml_str(&shell_text)?);
    let mut task_library = None;
    if let Some(plans_text) = &plans_text {
        let library = guard_schema::TaskPlanLibrary::from_yaml_str(plans_text)?;
        let profile = task.as_deref().unwrap_or_default();
        match library.plan_for(profile) {
            None => {
                anyhow::bail!("计划库里没有宿主选择的任务 '{profile}'，拒绝启动无授权范围的会话")
            }
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
        task_library = Some(library);
    } else {
        eprintln!("  警告：没给 --plans，因此没有 paths 天花板；写和删只能判成「证明不了」");
    }

    let source_path = audit_path.as_ref().or(browser_audit.as_ref()).map(|path| {
        let mut name = path.as_os_str().to_os_string();
        name.push(".sources.db");
        std::path::PathBuf::from(name)
    });
    let registry_path = audit_path.as_ref().or(browser_audit.as_ref()).map(|path| {
        let mut name = path.as_os_str().to_os_string();
        name.push(".tools.db");
        std::path::PathBuf::from(name)
    });
    for path in [
        &audit_path,
        &control_path,
        &browser_audit,
        &browser_file,
        &source_path,
        &registry_path,
    ]
    .into_iter()
    .flatten()
    {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("审计与控制文件必须使用绝对路径且不包含 ..");
        }
        let mut ancestor = path.as_path();
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| anyhow::anyhow!("审计路径缺少有效父目录"))?;
        }
        let resolved = ancestor.canonicalize()?.join(path.strip_prefix(ancestor)?);
        let resolved = guard_schema::paths::dealias_platform_volumes(&resolved);
        let lexical = guard_schema::paths::dealias_platform_volumes(path);
        if shell
            .workspace()
            .read_grants()
            .iter()
            .chain(shell.workspace().write_grants())
            .any(|grant| resolved.starts_with(grant) || lexical.starts_with(grant))
        {
            anyhow::bail!("审计与控制文件必须位于任务授权目录之外，不能复制到工具工作区");
        }
    }
    let journal = audit_path
        .as_deref()
        .map(guard_gateway::journal::ExecutionJournal::open)
        .transpose()?;
    let sources = std::sync::Arc::new(std::sync::Mutex::new(match source_path {
        Some(path) => guard_gateway::provenance::SourceCollector::open(&path)?,
        None => guard_gateway::provenance::SourceCollector::default(),
    }));
    let registry = std::sync::Arc::new(std::sync::Mutex::new(match registry_path {
        Some(path) => guard_gateway::tool_registry::ToolRegistry::open(&path)?,
        None => guard_gateway::tool_registry::ToolRegistry::default(),
    }));
    let isolation = isolation_image
        .map(|image| {
            guard_gateway::isolation::DockerExecutor::new(
                image,
                &shell
                    .workspace()
                    .read_grants()
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
                &shell
                    .workspace()
                    .write_grants()
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            )
        })
        .transpose()?;
    if let Some(executor) = &isolation {
        eprintln!("  隔离工具后端 {}", executor.status());
        eprintln!("  文件变化仅保留在工作区副本；客户端其他工具未纳入隔离，宿主原目录不会自动回写");
    }
    let mut policy_hash = Sha256::new();
    for text in [
        Some(rules_text.as_str()),
        Some(shell_text.as_str()),
        plans_text.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let bytes = text.as_bytes();
        policy_hash.update((bytes.len() as u64).to_be_bytes());
        policy_hash.update(bytes);
    }
    if browser_enabled {
        policy_hash.update(b"agentguard-browser-host-http-v1");
        let mut origins = browser_origins.clone();
        origins.sort();
        for origin in origins {
            policy_hash.update((origin.len() as u64).to_be_bytes());
            policy_hash.update(origin.as_bytes());
        }
    }
    let policy_version = format!("sha256-{:x}", policy_hash.finalize());
    let mut engine = guard_core::Engine::new(
        guard_schema::RuleSet::from_yaml_str(&rules_text)?,
        guard_schema::GuardContract::default(),
    );
    if let Some(library) = task_library {
        // 路径判决与会话引擎必须使用同一份操作员计划。
        engine = engine.with_task_plans(library);
    }
    let pending = PendingConfirm::new();
    let mut server = Server::new(Gate::new(shell, engine), pending.clone(), confirm_timeout)
        .with_sources(sources)
        .with_registry(registry)?
        .with_policy_version(policy_version)?;
    if let Some(executor) = isolation {
        server = server.with_isolation(executor);
    }
    if let Some(journal) = journal {
        server = server.with_journal(journal);
    }

    // 确认用的环回接口。
    //
    // 只绑 127.0.0.1 挡的是**网络**,挡不住**浏览器里的页面** —— 而页面正是本产品的威胁
    // 模型主体。旧版本只匹配 method + url:一个隐藏的自动提交 HTML form 就能发出逐字节
    // 合法的 `POST /approve`(简单请求,不触发预检),复核实测批准掉了一次 delete_file,
    // 文件真的被删了;`GET /pending` 也无凭据可读,泄漏待确认命令的全文和判据。
    //
    // 三道门,一起加:
    //   1. 隔离模式令牌只写宿主连接文件；原生兼容模式仍由操作者读取 stderr。
    //   2. 拒绝任何带跨站标记的请求(`Origin` / `Sec-Fetch-Site: cross-site`);
    //   3. 批准须回传当前 id、完整动作摘要与独立批准随机值。
    // 令牌是主防线;2 和 3 是纵深 —— 就算令牌泄漏,跨站请求仍然被拒,而拿不到当前 id 的
    // 批准也落不到任何请求上。
    let confirm_token = new_confirm_token();
    let instance_id = new_confirm_token();
    let (operator, operator_requests) =
        guard_gateway::operator::OperatorEndpoint::new(pending.clone());
    let operator = operator.with_registry(server.registry());
    server.start_host_session(task.as_deref())?;
    operator.publish(server.operator_status(&instance_id));
    let mut _control_http = None;
    let mut _control_file = None;
    let mut _browser_file = None;
    match guard_gateway::control_http::ControlHttp::bind(
        confirm_port,
        guard_gateway::control_http::HttpLimits {
            max_body_bytes: 64 * 1024,
            max_response_bytes: 8 * 1024 * 1024,
            ..Default::default()
        },
    ) {
        Err(e) => {
            if control_path.is_some() {
                anyhow::bail!("独立确认接口无法启动，拒绝启用会话：{e}");
            }
            eprintln!("  警告：确认接口起不来（{e}）；require_confirm 只能等超时，也就是拒绝")
        }
        Ok(mut http) => {
            let actual_port = http.port();
            let browser_host = if browser_enabled {
                let browser_token = guard_gateway::browser_bridge::token();
                let (session, policy) = server.host_session_binding();
                let host = guard_gateway::browser_bridge::BrowserHost::new_with_registry(
                    browser_origins.clone(),
                    pending.clone(),
                    guard_gateway::journal::ExecutionJournal::open(
                        browser_audit.as_ref().expect("浏览器审计"),
                    )?,
                    session.into(),
                    policy.into(),
                    confirm_timeout,
                    browser_token.clone(),
                    actual_port,
                    server.sources(),
                    server.registry(),
                )?;
                _browser_file = Some(guard_gateway::control_file::ControlFile::create(
                    browser_file.as_ref().expect("浏览器连接"),
                    &serde_json::to_vec(
                        &serde_json::json!({"service":"agentguard-browser-host","browser_protocol":1,
                        "url":host.execution_url(),"token":browser_token,"instance_id":instance_id}),
                    )?,
                )?);
                Some(host)
            } else {
                None
            };
            let browser_actor_host = browser_host.clone();
            if let Some(path) = &control_path {
                let address = format!("http://{}", http.address());
                let port = http.port();
                _control_file = Some(guard_gateway::control_file::ControlFile::create(
                    path,
                    &serde_json::to_vec(&serde_json::json!({
                        "service":"agentguard-mcp", "confirm_protocol":2, "url":address, "port":port,
                        "token":confirm_token, "instance_id":instance_id
                    }))?,
                )?);
                eprintln!(
                    "  本机控制连接文件 {}（仅供操作者载入，进程退出后撤销）",
                    path.display()
                );
            }
            eprintln!(
                "  确认接口 http://{}  (GET /status, GET /pending, POST /approve, POST /deny)",
                http.address()
            );
            if control_path.is_none() {
                eprintln!("  确认令牌 {confirm_token}");
            }
            eprintln!("    每个请求都要带 Authorization: Bearer <令牌>；");
            eprintln!(
                "    批准/拒绝的 body 须带 /pending 的 id、action_sha256、binding.nonce（字段名 approval_nonce）"
            );
            let actor_operator = operator.clone();
            let actor_instance = instance_id.clone();
            let p = pending.clone();
            let token = confirm_token.clone();
            let instance_id = instance_id.clone();
            let operator = operator.clone();
            http.start(std::sync::Arc::new(move |req| {
                use guard_gateway::control_http::ControlResponse;
                if req.header("Host")!=Some(format!("127.0.0.1:{actual_port}").as_str()) {
                    return ControlResponse::json(403,serde_json::json!({"error":"bad host"}));
                }
                if let Some(why)=reject_confirm_request(&req,&token) {return ControlResponse::json(403,serde_json::json!({"error":why}));}
                if req.url().starts_with("/workspace/") || req.url().starts_with("/registry/") {let (status,body)=operator.serve_authenticated(&req);return ControlResponse::json(status,body);}
                if req.body().len()>4096 {return ControlResponse::json(413,serde_json::json!({"error":"confirmation body too large"}));}
                let body=match std::str::from_utf8(req.body()){Ok(body)=>body,Err(_)=>return ControlResponse::json(400,serde_json::json!({"error":"invalid UTF-8"}))};
                let (status,body)=match (req.method(),req.url()) {
                    ("GET","/status")=>{let snapshot=p.snapshot();(200,serde_json::json!({"service":"agentguard-mcp","confirm_protocol":2,
                        "instance_id":instance_id,"pending":snapshot.as_ref().map(|(request,_)|request),"remaining_ms":snapshot.map(|(_,remaining)|remaining)}))},
                    ("GET","/pending")=>(200,p.peek().map(|request|serde_json::to_value(request).expect("确认JSON")).unwrap_or(serde_json::Value::Null)),
                    ("POST","/approve")|("POST","/deny")=>{
                        let answer=if req.url()=="/approve"{guard_gateway::Answer::Approved}else{guard_gateway::Answer::Denied};
                        let parsed=serde_json::from_str::<serde_json::Value>(body).ok();
                        match confirm_id_from_body(body) {
                            None=>(400,serde_json::json!({"error":"body must include confirm id"})),
                            Some(id)=>{let digest=parsed.as_ref().and_then(|v|v.get("action_sha256")).and_then(|v|v.as_str());
                                let nonce=parsed.as_ref().and_then(|v|v.get("approval_nonce")).and_then(|v|v.as_str());
                                let ok=match (digest,nonce){(Some(digest),Some(nonce))=>p.answer_bound(&id,digest,nonce,answer),_=>false};
                                (if ok{200}else{409},serde_json::json!({"answered":ok}))}
                        }
                    },
                    _=>(404,serde_json::json!({"error":"not found"})),
                };
                ControlResponse::json(status,body)
            }))?;
            _control_http = Some(http);
            if let Some(host) = browser_actor_host {
                server =
                    server.with_browser(guard_gateway::browser_bridge::BrowserActor::spawn(
                        browser_node.as_ref().expect("浏览器Node"),
                        browser_runtime.as_ref().expect("浏览器入口"),
                        browser_file.as_ref().expect("浏览器连接"),
                        browser_playwright.as_ref().expect("Playwright包"),
                        browser_browsers.as_ref().expect("浏览器缓存"),
                        cli_args.iter().any(|arg| arg == "--browser-headless"),
                        host,
                        confirm_timeout,
                    )?)?;
                actor_operator.publish(server.operator_status(&actor_instance));
            }
        }
    }

    // 独立读取 stdio，等待人工确认或执行命令时也能立即感知客户端退出。
    // 消息长度和队列都有上限；队列满时结束会话，不能让输入线程堵住 EOF 通知。
    const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
    let (sender, receiver) = std::sync::mpsc::sync_channel::<(u64, String)>(8);
    let connection = pending.clone();
    let reader_operator = operator.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut raw = Vec::new();
            match std::io::Read::take(&mut input, (MAX_MESSAGE_BYTES + 1) as u64)
                .read_until(b'\n', &mut raw)
            {
                Ok(0) => break,
                Ok(_) if raw.len() > MAX_MESSAGE_BYTES => {
                    eprintln!("MCP 消息超过 1 MiB，已结束本次连接");
                    break;
                }
                Err(error) => {
                    eprintln!("读取 MCP 连接失败：{error}");
                    break;
                }
                Ok(_) => {}
            }
            let Ok(line) = String::from_utf8(raw) else {
                eprintln!("MCP 消息不是 UTF-8，已结束本次连接");
                break;
            };
            reader_operator.note_client_message();
            if sender.try_send((reader_operator.epoch(), line)).is_err() {
                eprintln!("MCP 输入队列不可用或已满，已结束本次连接");
                break;
            }
        }
        connection.close();
    });
    let mut stdout = std::io::stdout();
    loop {
        while let Ok(job) = operator_requests.try_recv() {
            if !job.begin() {
                job.finish(guard_gateway::operator::failure(
                    "WORKSPACE_STALE",
                    "操作者请求已过期，未执行",
                    409,
                ));
                continue;
            }
            let revocation = matches!(
                job.command,
                guard_gateway::operator::OperatorCommand::Pause
                    | guard_gateway::operator::OperatorCommand::Stop
            );
            if !revocation && job.epoch != operator.epoch() {
                job.finish(guard_gateway::operator::failure(
                    "WORKSPACE_STALE",
                    "操作者请求之后会话状态已改变，未执行",
                    409,
                ));
                continue;
            }
            operator.set_busy(true);
            let resume = matches!(
                job.command,
                guard_gateway::operator::OperatorCommand::Resume
            );
            let reply = server.handle_operator_at(
                job.command.clone(),
                &instance_id,
                job.cancellation_epoch,
            );
            if resume && reply.0 == 200 {
                operator.advance_epoch();
            }
            operator.publish(server.operator_status(&instance_id));
            job.finish(reply);
        }
        let (epoch, line) = match receiver.recv_timeout(Duration::from_millis(25)) {
            Ok(line) => line,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                operator.publish(server.operator_status(&instance_id));
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        operator.set_busy(true);
        let response = match serde_json::from_str::<guard_gateway::mcp::Request>(&line) {
            Ok(req) if epoch != operator.epoch() => req.id.map(|id| {
                guard_gateway::mcp::error(
                    id,
                    guard_gateway::mcp::code::INVALID_REQUEST,
                    "宿主已暂停、恢复或停止；旧排队请求已失效，未执行",
                    None,
                )
            }),
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
        operator.publish(server.operator_status(&instance_id));
        if let Some(v) = response {
            writeln!(stdout, "{v}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
