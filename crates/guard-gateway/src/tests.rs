//! A1 的验收测试。
//!
//! # 这里唯一重要的断言形态
//!
//! 每一条"被拒绝"的测试都断言**两件事**：返回了 `Refused`，**并且副作用确实没发生**——文件还在、
//! 或者文件没被创建。只断言前者是这个项目反复在自己身上抓到的那种缺陷：机制存在、被直接测试过、
//! 被描述成完整的，然后什么都没接上。一个返回了 `Refused` 却还是把文件删了的网关，会通过一个
//! 只看返回值的测试。

use super::*;
use crate::exec::ToolCall;
use crate::gate::Gate;
use crate::server::{Handled, Server};
use guard_shell::SafeShell;
use std::path::PathBuf;
use std::time::Duration;

/// 一个临时工作区，析构时清掉。
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("ag-gateway-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("建临时目录");
        // canonicalize：macOS 上 /var 是 /private/var 的符号链接，不解开的话工作区授权
        // 和归约后的路径永远对不上，测试会因为一个和被测逻辑无关的原因失败。
        Self(std::fs::canonicalize(&p).unwrap_or(p))
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml")
}

fn shell_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-shell/policies/default.yaml")
}

/// 一个装好路径天花板的网关，天花板就是那个临时目录。
fn server_for(tmp: &Tmp, timeout: Duration) -> Server {
    let ws = tmp.path().to_string_lossy().into_owned();
    let (shell, rejected) = SafeShell::from_path(shell_policy_path())
        .expect("shell 策略")
        .with_workspace(vec![ws.clone()], vec![ws]);
    assert!(rejected.is_empty(), "授权应当可归约：{rejected:?}");
    let engine = guard_core::Engine::from_paths(rules_path(), None::<PathBuf>).expect("规则");
    Server::new(Gate::new(shell, engine), PendingConfirm::new(), timeout)
}

fn write_call(path: &std::path::Path, contents: &str) -> (ToolCall, guard_shell::ShellAction) {
    (
        ToolCall::WriteFile {
            path: path.to_path_buf(),
            contents: contents.to_string(),
        },
        guard_shell::ShellAction {
            tool: "write_file".into(),
            action: None,
            target: Some(path.to_string_lossy().into_owned()),
            args: vec![],
        },
    )
}

fn delete_call(path: &std::path::Path) -> (ToolCall, guard_shell::ShellAction) {
    (
        ToolCall::DeleteFile {
            path: path.to_path_buf(),
        },
        guard_shell::ShellAction {
            tool: "run_terminal".into(),
            action: Some("rm".into()),
            target: Some(path.to_string_lossy().into_owned()),
            args: vec![],
        },
    )
}

/// 一个**天花板覆盖不到**的动作：没有路径操作数，所以事前授权对它无话可说，必须逐次确认。
///
/// 这个 helper 存在本身就是一条信息：确认路径需要刻意构造一个动作才能触发，因为落在已声明
/// 天花板内的写不再逐次问 —— 见 `Gate::ceiling_authorises`。
fn needs_confirm_call() -> (ToolCall, guard_shell::ShellAction) {
    (
        ToolCall::RunShell {
            argv: vec!["/bin/echo".into(), "hello".into()],
            cwd: None,
        },
        guard_shell::ShellAction {
            tool: "run_terminal".into(),
            action: Some("/bin/echo".into()),
            target: None,
            args: vec!["hello".into()],
        },
    )
}

// ---------------------------------------------------------------- 拒绝是真的没做

#[test]
fn 拒绝写系统目录时文件确实没被创建() {
    let tmp = Tmp::new("sys-write");
    // 走 /etc 下一个不存在的路径。真被执行了就会留下痕迹（或者至少 create_dir_all 会试）。
    let target = PathBuf::from("/etc/agentguard-should-never-exist.conf");
    assert!(!target.exists(), "前置条件：目标不该已经存在");

    let (call, action) = write_call(&target, "x");
    let handled = server_for(&tmp, Duration::from_millis(50)).gate_and_run(call, action);

    match handled {
        Handled::Refused { reason } => {
            assert!(reason.contains("SHELL-PATH-SENSITIVE"), "{reason}");
            assert!(
                reason.contains("cooperative"),
                "每条拒绝都要写明强制力等级：{reason}"
            );
        }
        other => panic!("应当被拒绝，实际 {other:?}"),
    }
    // 关键的一半：真的没写。
    assert!(
        !target.exists(),
        "被拒绝之后文件仍然被创建了 —— 判决没有变成不执行"
    );
}

#[test]
fn 拒绝删除授权外的文件时文件还在() {
    let tmp = Tmp::new("outside-del");
    // 在天花板**之外**造一个文件。
    let outside_dir = std::env::temp_dir().join(format!("ag-outside-{}", std::process::id()));
    std::fs::create_dir_all(&outside_dir).expect("建目录");
    let victim = outside_dir.join("keepme.txt");
    std::fs::write(&victim, b"important").expect("写文件");

    let (call, action) = delete_call(&victim);
    let handled = server_for(&tmp, Duration::from_millis(50)).gate_and_run(call, action);

    match handled {
        Handled::Refused { reason } => assert!(
            reason.contains("SHELL-PATH-OUTSIDE") || reason.contains("SHELL-PATH-SENSITIVE"),
            "{reason}"
        ),
        other => panic!("应当被拒绝，实际 {other:?}"),
    }
    assert!(
        victim.exists(),
        "被拒绝之后文件还是被删了 —— 判决没有变成不执行"
    );
    let _ = std::fs::remove_dir_all(&outside_dir);
}

#[test]
fn 读凭据被拒且没有内容漏回去() {
    let tmp = Tmp::new("cred-read");
    // 造一个假的 .ssh，路径形状是真的（组件里有 .ssh），内容是可识别的哨兵。
    let ssh = tmp.path().join(".ssh");
    std::fs::create_dir_all(&ssh).expect("建 .ssh");
    let key = ssh.join("id_rsa");
    std::fs::write(&key, b"SENTINEL-PRIVATE-KEY").expect("写假密钥");

    let (call, action) = (
        ToolCall::ReadFile { path: key.clone() },
        guard_shell::ShellAction {
            tool: "read_file".into(),
            action: None,
            target: Some(key.to_string_lossy().into_owned()),
            args: vec![],
        },
    );
    let handled = server_for(&tmp, Duration::from_millis(50)).gate_and_run(call, action);
    match handled {
        Handled::Refused { reason } => {
            assert!(reason.contains("SHELL-PATH-SENSITIVE"), "{reason}");
            // 拒绝的理由里不能夹带被拒内容。
            assert!(
                !reason.contains("SENTINEL-PRIVATE-KEY"),
                "拒绝信息把它本该保护的内容带出来了：{reason}"
            );
        }
        other => panic!("读凭据应当被拒，实际 {other:?}"),
    }
}

// ---------------------------------------------------------------- 放行是真的做了

#[test]
fn 授权内的写真的落盘了() {
    // 反面用例。没有这一条，上面那些 Refused 断言都可能只是"什么都不执行"。
    let tmp = Tmp::new("allowed-write");
    let target = tmp.path().join("notes.txt");
    let (call, action) = write_call(&target, "hello");
    let handled = server_for(&tmp, Duration::from_millis(50)).gate_and_run(call, action);
    match handled {
        Handled::Executed { output } => assert!(output.ok, "{output:?}"),
        other => panic!("授权内的写应当执行，实际 {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
}

#[test]
fn run_shell_走参数向量而不是走_shell() {
    // 如果最终还是交给 `sh -c`，那么 `guard-shell` 挡住 `;` 和 `|` 只是在减少攻击面而不是
    // 消除这一类攻击。这条测试证明元字符被当成**字面参数**传给了程序。
    let tmp = Tmp::new("argv");
    let marker = tmp.path().join("SHOULD-NOT-EXIST");
    let argv = vec![
        "/bin/echo".to_string(),
        format!("a; touch {}", marker.display()),
    ];
    let (call, action) = (
        ToolCall::RunShell {
            argv: argv.clone(),
            cwd: None,
        },
        guard_shell::ShellAction {
            tool: "run_terminal".into(),
            action: Some(argv[0].clone()),
            // 元字符会被 guard-shell 的 METACHAR 规则拦住，所以这里不把它放进被判的操作数里，
            // 而是直接验证执行层的行为——两件事分开测。
            target: None,
            args: vec![],
        },
    );
    let mut server = server_for(&tmp, Duration::from_secs(5));
    let pending = server.pending();
    // echo 没有路径操作数，所以天花板覆盖不到它，会挂起等确认。批准它。
    let waiter = std::thread::spawn(move || {
        for _ in 0..300 {
            if pending.peek().is_some() {
                return pending.answer(Answer::Approved);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });
    let handled = server.gate_and_run(call, action);
    assert!(waiter.join().expect("确认线程"), "确认请求始终没出现");
    match handled {
        Handled::Executed { output } => {
            assert!(
                output.detail.contains("; touch"),
                "参数应当被原样输出：{output:?}"
            );
        }
        other => panic!("echo 应当执行，实际 {other:?}"),
    }
    assert!(
        !marker.exists(),
        "`;` 被当成命令分隔符执行了 —— 说明走了 shell"
    );
}

// ---------------------------------------------------------------- 确认

#[test]
fn 确认超时按拒绝处理且理由里写明是超时() {
    // 整个网关唯一不能搞错方向的地方。一个"等不到答案就放行"的闸门，被攻击的方法就是等。
    let tmp = Tmp::new("timeout");
    let marker = tmp.path().join("timeout-marker");
    // 一条会在被执行时留下痕迹的命令，且没有路径操作数落在天花板里 —— 所以必须逐次确认。
    let argv = vec![
        "/usr/bin/touch".to_string(),
        marker.to_string_lossy().into_owned(),
    ];
    let (call, action) = (
        ToolCall::RunShell { argv, cwd: None },
        guard_shell::ShellAction {
            tool: "run_terminal".into(),
            action: Some("/usr/bin/touch".into()),
            target: None,
            args: vec![],
        },
    );
    let handled = server_for(&tmp, Duration::from_millis(60)).gate_and_run(call, action);
    match handled {
        Handled::Refused { reason } => assert!(reason.contains("超时"), "{reason}"),
        other => panic!("超时应当拒绝，实际 {other:?}"),
    }
    // 关键的一半：超时之后命令确实没跑。
    assert!(!marker.exists(), "超时之后命令还是执行了");
}

#[test]
fn 有人批准之后才执行() {
    let tmp = Tmp::new("approved");
    let mut server = server_for(&tmp, Duration::from_secs(5));
    let pending = server.pending();

    // 另一个线程扮演使用者：等到确认请求出现，看一眼，然后批准。
    let waiter = std::thread::spawn(move || {
        for _ in 0..200 {
            if let Some(req) = pending.peek() {
                assert!(req.what.contains("echo"), "确认请求要说清会做什么：{req:?}");
                assert!(pending.answer(Answer::Approved));
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });

    let (call, action) = needs_confirm_call();
    let handled = server.gate_and_run(call, action);
    assert!(waiter.join().expect("确认线程"), "确认请求始终没出现");
    match handled {
        Handled::Executed { output } => {
            assert!(output.ok, "{output:?}");
            assert!(output.detail.contains("hello"), "{output:?}");
        }
        other => panic!("批准之后应当执行，实际 {other:?}"),
    }
}

#[test]
fn 有人拒绝之后不执行() {
    let tmp = Tmp::new("denied");
    let mut server = server_for(&tmp, Duration::from_secs(5));
    let pending = server.pending();
    let waiter = std::thread::spawn(move || {
        for _ in 0..200 {
            if pending.peek().is_some() {
                return pending.answer(Answer::Denied);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });
    let (call, action) = needs_confirm_call();
    let handled = server.gate_and_run(call, action);
    assert!(waiter.join().expect("确认线程"));
    match handled {
        Handled::Refused { reason } => {
            assert!(reason.contains("使用者拒绝"), "要能和超时区分开：{reason}");
            assert!(!reason.contains("超时"), "{reason}");
        }
        other => panic!("应当被拒绝，实际 {other:?}"),
    }
}

#[test]
fn 没有待确认时的回答不会预先批准下一次调用() {
    // 否则"先答一个 yes"就成了绕过闸门的办法。
    let pending = PendingConfirm::new();
    assert!(!pending.answer(Answer::Approved), "空槽位不该接受回答");
    assert!(pending.peek().is_none());
}

// ---------------------------------------------------------------- 协议

#[test]
fn initialize_里写明了这是协作式() {
    let tmp = Tmp::new("proto");
    let mut server = server_for(&tmp, Duration::from_millis(50));
    let req: mcp::Request =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
            .expect("解析");
    let v = server.handle(req).expect("要有响应");
    let text = v.to_string();
    assert!(text.contains("cooperative"), "{text}");
    assert!(
        text.contains("interception-design"),
        "要指向那份说明区分的文档：{text}"
    );
}

#[test]
fn 通知不产生响应() {
    // 没有 id 的是通知。回一个响应会破坏 JSON-RPC 的对端状态机。
    let tmp = Tmp::new("notif");
    let mut server = server_for(&tmp, Duration::from_millis(50));
    let req: mcp::Request =
        serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .expect("解析");
    assert!(server.handle(req).is_none());
}

#[test]
fn 工具清单里每个工具都有名字描述和schema() {
    let tools = Server::tools();
    assert!(tools.len() >= 6, "工具数量 {}", tools.len());
    for t in &tools {
        assert!(
            t.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()),
            "{t}"
        );
        assert!(
            t.get("description")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.len() > 20),
            "描述太短，智能体读不出该不该用它：{t}"
        );
        assert!(
            t.get("inputSchema").and_then(|v| v.get("type")).is_some(),
            "{t}"
        );
    }
}

#[test]
fn 未知方法回_method_not_found_而不是静默() {
    let tmp = Tmp::new("unknown");
    let mut server = server_for(&tmp, Duration::from_millis(50));
    let req: mcp::Request =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"method":"nope/xyz"}"#).expect("解析");
    let v = server.handle(req).expect("要有响应");
    assert_eq!(v["error"]["code"], mcp::code::METHOD_NOT_FOUND);
}

#[test]
fn 被拒绝走的是工具级错误而不是传输级错误() {
    // MCP 里 `isError: true` 的正常结果让智能体看到原因并改做法；JSON-RPC 错误会被当成
    // 传输故障去重试，而重试一个判决只会得到同一个判决。
    let tmp = Tmp::new("tool-err");
    let mut server = server_for(&tmp, Duration::from_millis(50));
    let req: mcp::Request = serde_json::from_str(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":
            {"name":"write_file","arguments":{"path":"/etc/nope.conf","contents":"x"}}}"#,
    )
    .expect("解析");
    let v = server.handle(req).expect("要有响应");
    assert!(v.get("error").is_none(), "不该是 JSON-RPC 错误：{v}");
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.contains("SHELL-PATH-SENSITIVE"), "{text}");
    assert!(
        text.contains("重试不会改变结果"),
        "要告诉智能体这是判决不是故障：{text}"
    );
}

#[test]
fn stats_里报的强制力是协作式() {
    let tmp = Tmp::new("stats");
    let mut server = server_for(&tmp, Duration::from_millis(50));
    let req: mcp::Request =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":9,"method":"gateway/stats"}"#).expect("解析");
    let v = server.handle(req).expect("要有响应");
    assert_eq!(v["result"]["enforcement"], "cooperative");
}

// ------------------------------------------------- 天花板替代确认，及其三条不放松的边界
//
// 这是 A1 里唯一一处**放松**。这个项目的历史里，两次最严重的缺陷都是自作的放松
// （`task_apps` 重赋值让天花板里每个应用都成了 HIGH 内容的合法接收方；图标锁存把一个
// 确定的判决降级），所以这一段的每条边界都单独钉住。

#[test]
fn 落在已声明天花板内的写不再逐次确认() {
    // 人已经在 task-plans.yaml 里答过了 —— 这就是 Aura §4.4 会话令牌的模型：
    // 令牌带着事前批准的范围，范围内不再逐次问。
    let tmp = Tmp::new("ceiling-ok");
    let target = tmp.path().join("in-ceiling.txt");
    let (call, action) = write_call(&target, "x");
    // 超时设得极短：如果它去问了，就会超时被拒，测试就会失败。
    let handled = server_for(&tmp, Duration::from_millis(30)).gate_and_run(call, action);
    match handled {
        Handled::Executed { .. } => {}
        other => panic!("授权内的写不该逐次确认，实际 {other:?}"),
    }
    assert!(target.exists());
}

#[test]
fn 边界一_天花板没声明时照旧确认() {
    let tmp = Tmp::new("ceiling-undeclared");
    let target = tmp.path().join("x.txt");
    // 不装工作区。
    let shell = SafeShell::from_path(shell_policy_path()).expect("shell 策略");
    let engine = guard_core::Engine::from_paths(rules_path(), None::<PathBuf>).expect("规则");
    let mut server = Server::new(
        Gate::new(shell, engine),
        PendingConfirm::new(),
        Duration::from_millis(40),
    );
    let (call, action) = write_call(&target, "x");
    match server.gate_and_run(call, action) {
        // 没声明天花板时，路径层先给出 UNSCOPED 的 Ask，然后超时被拒。
        Handled::Refused { reason } => assert!(reason.contains("超时"), "{reason}"),
        other => panic!("没声明天花板不该直接执行，实际 {other:?}"),
    }
    assert!(!target.exists());
}

#[test]
fn 边界二_归约不了的操作数不算在里面() {
    // "证明不了"不是"在里面"。通配符可以展开到授权之外。
    let tmp = Tmp::new("ceiling-glob");
    let glob = tmp.path().join("*").to_string_lossy().into_owned();
    let (call, action) = (
        ToolCall::WriteFile {
            path: PathBuf::from(&glob),
            contents: "x".into(),
        },
        guard_shell::ShellAction {
            tool: "write_file".into(),
            action: None,
            target: Some(glob),
            args: vec![],
        },
    );
    match server_for(&tmp, Duration::from_millis(40)).gate_and_run(call, action) {
        Handled::Refused { reason } => assert!(
            reason.contains("超时") || reason.contains("UNPROVABLE"),
            "{reason}"
        ),
        other => panic!("通配符不该被天花板认领，实际 {other:?}"),
    }
}

#[test]
// 函数名照抄的是规则 id `SHELL-CONFIRM` 与判决动作 `Ask`，改成蛇形就对不上被测对象了。
#[allow(non_snake_case)]
fn 边界三_只对_SHELL_CONFIRM_生效不对路径类的_Ask_生效() {
    // `SHELL-PATH-UNPROVABLE` / `SHELL-PATH-UNSCOPED` 恰恰是"证明不了"，天花板不能替它们答。
    // 边界二已经覆盖了 UNPROVABLE 这一支；这里直接钉住判据本身，防止将来有人把条件放宽成
    // "任何 Ask 都能被天花板认领"。
    let tmp = Tmp::new("ceiling-ruleid");
    let ws = tmp.path().to_string_lossy().into_owned();
    let (shell, _) = SafeShell::from_path(shell_policy_path())
        .expect("shell 策略")
        .with_workspace(vec![ws.clone()], vec![ws]);
    // 空操作数 → UNPROVABLE，而且它在天花板里没有对应物。
    let v = shell.evaluate(&guard_shell::ShellAction {
        tool: "write_file".into(),
        action: None,
        target: Some("".into()),
        args: vec![],
    });
    assert_eq!(v.rule_id, "SHELL-PATH-UNPROVABLE", "{v:?}");
    assert_ne!(
        v.rule_id, "SHELL-CONFIRM",
        "如果这两个判据合流了，天花板就会替'证明不了'签字"
    );
}

#[test]
fn 天花板不认领没有路径操作数的命令() {
    // `git status`、`echo` 这类命令没有可以被事前授权覆盖的东西，所以照旧确认。
    // 这条防的是把 `claims.is_empty()` 当成"全部都在里面"（`all()` 对空集返回 true）。
    let tmp = Tmp::new("ceiling-nopath");
    let (call, action) = needs_confirm_call();
    match server_for(&tmp, Duration::from_millis(40)).gate_and_run(call, action) {
        Handled::Refused { reason } => assert!(reason.contains("超时"), "{reason}"),
        other => panic!("没有路径操作数的命令应当照旧确认，实际 {other:?}"),
    }
}

#[test]
fn 天花板不能替引擎的_require_confirm_签字() {
    // `CRIT-*`（付款、转账）是引擎判的 require_confirm，在 `judge` 里先于路径那道门返回，
    // 所以天花板永远碰不到它。这里用一条会触发关键动作的命令文本验证。
    let tmp = Tmp::new("ceiling-crit");
    let target = tmp.path().join("pay.txt");
    let (call, mut action) = write_call(&target, "x");
    // 让命令文本里带上引擎的关键动作标记：ui_text 会带上全部操作数。
    action.args.push("确认支付".into());
    let handled = server_for(&tmp, Duration::from_millis(40)).gate_and_run(call, action);
    match handled {
        Handled::Refused { reason } => {
            // 要么引擎直接 Block，要么挂起后超时 —— 两者都不是"天花板放行"。
            assert!(
                reason.contains("CRIT") || reason.contains("超时"),
                "{reason}"
            );
        }
        // 如果它执行了，说明天花板越过了引擎的确认要求。
        other => panic!("关键动作不该被天花板放行，实际 {other:?}"),
    }
}

// ------------------------------------------------- 引擎那道门到底贡献了什么
//
// 这一组是自查时写的。写 `judge()` 的注释时我说它"拿 PLAN-*/SCOPE-*/CRIT-*"，然后
// 「天花板不能替引擎的 require_confirm 签字」失败了 —— 因为 27 条 YAML 规则**全部**声明了
// `platforms`，而网关的 platform 是 `gateway`，不在任何一条的列表里。也就是说我注释里写的
// 三样东西，有一样根本没接上。
//
// 这正是本项目反复抓到的第二种缺陷形态：机制存在、被直接测过、被描述成完整的，然后没接上。
// 所以下面把"哪些真的到了网关"逐条钉住。

#[test]
fn 引擎自身的判据在网关路径上有效() {
    // PLAN-* / SCOPE-* / SESSION-* / FLOW-* 是 Rust 状态机的结论，不是 YAML 规则，所以不受
    // `platforms` 影响。这是引擎在网关这条路上真正贡献的部分。
    let tmp = Tmp::new("engine-verdicts");
    let mut server = server_for(&tmp, Duration::from_millis(30));
    // 开一个声明了任务的会话，引擎应当给出 SESSION-START 而不是"没规则可用"。
    let d = server
        .gate_mut()
        .start_session("s-1", Some("book_hotel"))
        .expect("开会话");
    assert!(
        d.rule_id.starts_with("SESSION") || d.rule_id.starts_with("PLAN"),
        "会话开始应当得到引擎自己的判据，实际 {d:?}"
    );
}

#[test]
// `CRIT` 照抄的是规则 id 前缀（CRIT-001..005），小写化后就不是那批规则的名字了。
#[allow(non_snake_case)]
fn CRIT_规则在网关路径上也要生效() {
    // 修法是给 CRIT-001..005 的 platforms 加上 `gateway`，而不是让网关谎报平台。
    // 谎报会把一条 Linux 上经网关发生的动作在审计里记成 macOS —— 和共享 uitree 时
    // 硬编码 "macos" 是同一种错误。
    let tmp = Tmp::new("crit-gateway");
    let target = tmp.path().join("pay.txt");
    let (call, mut action) = write_call(&target, "x");
    action.args.push("确认支付".into());
    let handled = server_for(&tmp, Duration::from_millis(40)).gate_and_run(call, action);
    match handled {
        Handled::Refused { reason } => assert!(
            reason.contains("CRIT-001") || reason.contains("超时"),
            "关键动作应当被拦或被挂起：{reason}"
        ),
        other => panic!("关键动作不该直接执行，实际 {other:?}"),
    }
    assert!(!target.exists(), "关键动作被执行了");
}

#[test]
fn 平台专属的规则刻意不扩到网关() {
    // `ENV-A5`（Android 的广播输入接收方）、`OVL-001`（透明浮层，需要像素）这些的语义本来就
    // 绑在平台上。给它们加 `gateway` 会让一条只有在 Android 上才有意义的规则对一条命令发言。
    //
    // 这条测试钉住的是"没有人图省事把 gateway 加到全部 27 条上"。
    let raw = std::fs::read_to_string(rules_path()).expect("读规则");
    let doc: serde_json::Value = serde_yaml::from_str(&raw).expect("解析规则");
    let rules = doc["rules"].as_array().expect("rules 数组");
    let with_gateway: Vec<&str> = rules
        .iter()
        .filter(|r| {
            r["platforms"]
                .as_array()
                .is_some_and(|ps| ps.iter().any(|p| p.as_str() == Some("gateway")))
        })
        .map(|r| r["id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        !with_gateway.is_empty(),
        "没有任何规则对网关生效 —— 引擎那道门是空的"
    );
    assert!(
        with_gateway.iter().all(|id| id.starts_with("CRIT-")),
        "只有 CRIT-* 该扩到网关，实际还有 {with_gateway:?}"
    );
    assert!(
        with_gateway.len() >= 5,
        "CRIT 系列应当全部扩到网关，实际 {with_gateway:?}"
    );
}
