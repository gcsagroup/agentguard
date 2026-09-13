#![cfg(unix)]
// 真实二进制、真实 stdio 和环回确认接口；全部目标只在本次临时目录。
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

struct Gateway {
    child: Child,
    output: Receiver<Value>,
    address: String,
    token: String,
    directory: PathBuf,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Gateway {
    fn start() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let directory =
            std::env::temp_dir().join(format!("agentguard-stdio-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let directory = directory.canonicalize().unwrap();
        let plans = directory.join("plans.yaml");
        std::fs::write(
            &plans,
            json!({ "plans": [{ "task_profile": "test", "allow": ["run_shell"],
            "scope": { "paths": { "read": [directory], "write": [directory] } } }] })
            .to_string(),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_agentguard-mcp"))
            .args([
                "--confirm-port",
                "0",
                "--confirm-timeout-secs",
                "30",
                "--rules",
            ])
            .arg(root.join("../guard-schema/rules/p0_rules.yaml"))
            .arg("--shell-policy")
            .arg(root.join("../guard-shell/policies/default.yaml"))
            .arg("--plans")
            .arg(plans)
            .args(["--task", "test"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (send, output) = channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str(&line) {
                    let _ = send.send(value);
                }
            }
        });
        let (send, logs) = channel();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = send.send(line);
            }
        });
        let mut gateway = Self {
            child,
            output,
            address: String::new(),
            token: String::new(),
            directory,
        };
        while gateway.token.is_empty() {
            let line = logs
                .recv_timeout(Duration::from_secs(10))
                .expect("确认接口启动超时");
            if let Some(value) = line.strip_prefix("  确认接口 http://") {
                gateway.address = value.split_whitespace().next().unwrap().to_string();
            }
            if let Some(value) = line.strip_prefix("  确认令牌 ") {
                gateway.token = value.to_string();
            }
        }
        gateway.send(1, "start_session", json!({ "task_profile": "test" }));
        assert_ne!(gateway.response()["result"]["isError"], true);
        gateway
    }
    fn send(&mut self, id: u64, tool: &str, arguments: Value) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{}", json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": arguments }
        })).unwrap();
    }
    fn response(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(5))
            .expect("MCP 响应超时")
    }
    fn http(&self, path: &str, body: Option<Value>) -> Value {
        let mut socket = TcpStream::connect(&self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let payload = body.as_ref().map(Value::to_string).unwrap_or_default();
        write!(socket, "{} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            if body.is_some() { "POST" } else { "GET" }, self.address, self.token, payload.len()).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
    }
    fn pending(&self) -> Value {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if let Ok(response) = self.output.try_recv() {
                panic!("等待确认前已返回：{response}");
            }
            let pending = self.http("/status", None)["pending"].clone();
            if !pending.is_null() {
                return pending;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("未进入人工确认");
    }
    fn exited(&mut self) {
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("客户端退出后网关没有按期结束");
    }
}

#[test]
fn 待确认期间客户端退出不再等待且命令未执行() {
    let mut gateway = Gateway::start();
    gateway.send(2, "run_shell", json!({ "argv": ["/bin/sleep", "10"] }));
    let _request = gateway.pending();
    gateway.child.stdin.take();
    let response = gateway.response();
    assert_eq!(response["result"]["isError"], true);
    assert!(response.to_string().contains("客户端连接已断开"));
    gateway.exited();
}

#[test]
fn 同一操作员计划在真实会话中允许范围内写读并拒绝越界() {
    let mut gateway = Gateway::start();
    let target = gateway.directory.join("draft.txt");
    gateway.send(
        2,
        "write_file",
        json!({ "path": target, "contents": "已授权草稿" }),
    );
    let response = gateway.response();
    assert_ne!(response["result"]["isError"], true, "{response}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "已授权草稿");
    gateway.send(3, "read_file", json!({ "path": target }));
    let response = gateway.response();
    assert_ne!(response["result"]["isError"], true, "{response}");
    assert!(response.to_string().contains("已授权草稿"));
    let outside = gateway.directory.with_extension("outside.txt");
    gateway.send(
        4,
        "write_file",
        json!({ "path": outside, "contents": "不得落地" }),
    );
    assert_eq!(gateway.response()["result"]["isError"], true);
    assert!(!outside.exists());
    gateway.child.stdin.take();
    gateway.exited();
}

#[test]
fn 已启动命令在客户端退出后停止() {
    let mut gateway = Gateway::start();
    gateway.send(2, "run_shell", json!({ "argv": ["/bin/sleep", "10"] }));
    let request = gateway.pending();
    assert_eq!(
        gateway.http(
            "/approve",
            Some(json!({
                "id": request["id"], "action_sha256": request["action_sha256"],
                "approval_nonce": request["binding"]["nonce"]
            }))
        )["answered"],
        true
    );
    let end = Instant::now() + Duration::from_secs(3);
    let mut command_pid = None;
    while Instant::now() < end {
        let output = Command::new("ps")
            .args(["-axo", "pid=,ppid="])
            .output()
            .unwrap();
        command_pid = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                (fields.len() == 2 && fields[1].parse::<u32>().ok() == Some(gateway.child.id()))
                    .then(|| fields[0].parse::<i32>().unwrap())
            });
        if command_pid.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let command_pid = command_pid.expect("测试命令没有实际启动");
    gateway.child.stdin.take();
    assert_eq!(gateway.response()["result"]["isError"], true);
    gateway.exited();
    assert_eq!(unsafe { libc::kill(command_pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn 客户端不能换计划或结束后自行刷新会话() {
    let mut gateway = Gateway::start();
    gateway.send(
        2,
        "start_session",
        json!({ "task_profile": "unrestricted" }),
    );
    let rejected = gateway.response();
    assert_eq!(rejected["result"]["isError"], true);
    let target = gateway.directory.join("same-scope.txt");
    gateway.send(
        3,
        "write_file",
        json!({ "path": target, "contents": "原授权仍有效" }),
    );
    assert_ne!(gateway.response()["result"]["isError"], true);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "原授权仍有效");
    gateway.send(4, "end_session", json!({}));
    assert_ne!(gateway.response()["result"]["isError"], true);
    gateway.send(5, "start_session", json!({ "task_profile": "test" }));
    assert_eq!(gateway.response()["result"]["isError"], true);
    let marker = gateway.directory.join("must-not-write.txt");
    gateway.send(
        6,
        "write_file",
        json!({ "path": marker, "contents": "不得落地" }),
    );
    assert_eq!(gateway.response()["result"]["isError"], true);
    assert!(!marker.exists());
}

#[test]
fn 工具参数自报批准被拒绝且不执行() {
    let mut gateway = Gateway::start();
    let target = gateway.directory.join("self-approved.txt");
    gateway.send(
        2,
        "write_file",
        json!({ "path": target, "contents": "不得落地", "approved": true }),
    );
    let response = gateway.response();
    assert_eq!(response["result"]["isError"], true);
    assert!(response.to_string().contains("不接受参数 approved"));
    assert!(!target.exists());
    gateway.send(3, "run_shell", json!({ "argv": ["/bin/echo", 123] }));
    assert_eq!(gateway.response()["result"]["isError"], true);
}

#[test]
fn 真实确认拒绝旧协议替换摘要及重复批准() {
    let mut gateway = Gateway::start();
    gateway.send(
        2,
        "run_shell",
        json!({ "argv": ["/bin/echo", "已绑定正文"] }),
    );
    let request = gateway.pending();
    assert!(request["binding"]["action"]["parameters"]["argv"].is_array());
    let legacy = gateway.http("/approve", Some(json!({ "id": request["id"] })));
    assert_ne!(legacy["answered"], true);
    let forged = gateway.http(
        "/approve",
        Some(json!({
            "id": request["id"], "action_sha256": "0".repeat(64),
            "approval_nonce": request["binding"]["nonce"]
        })),
    );
    assert_ne!(forged["answered"], true);
    let forged_nonce = gateway.http(
        "/approve",
        Some(json!({
            "id": request["id"], "action_sha256": request["action_sha256"],
            "approval_nonce": "0".repeat(64)
        })),
    );
    assert_ne!(forged_nonce["answered"], true);
    let body = json!({ "id": request["id"], "action_sha256": request["action_sha256"],
        "approval_nonce": request["binding"]["nonce"] });
    assert_eq!(
        gateway.http("/approve", Some(body.clone()))["answered"],
        true
    );
    assert_ne!(gateway.http("/approve", Some(body))["answered"], true);
    let response = gateway.response();
    assert_ne!(response["result"]["isError"], true, "{response}");
    assert!(response.to_string().contains("已绑定正文"));
    gateway.send(
        3,
        "run_shell",
        json!({ "argv": ["/bin/echo", "第二个动作"] }),
    );
    let second = gateway.pending();
    assert_ne!(request["id"], second["id"]);
    assert_ne!(
        request["binding"]["action"]["request_id"],
        second["binding"]["action"]["request_id"]
    );
    assert_ne!(
        gateway.http(
            "/approve",
            Some(json!({
                "id": request["id"], "action_sha256": request["action_sha256"],
                "approval_nonce": request["binding"]["nonce"]
            }))
        )["answered"],
        true
    );
    assert_eq!(
        gateway.http(
            "/deny",
            Some(json!({
                "id": second["id"], "action_sha256": second["action_sha256"],
                "approval_nonce": second["binding"]["nonce"]
            }))
        )["answered"],
        true
    );
    assert_eq!(gateway.response()["result"]["isError"], true);
}

#[test]
fn 过长或非法编码输入主动结束连接() {
    for bytes in [vec![b'x'; 1024 * 1024 + 1], vec![0xff, b'\n']] {
        let mut gateway = Gateway::start();
        let _ = gateway.child.stdin.as_mut().unwrap().write_all(&bytes);
        // 客户端仍持有 stdin；网关必须自行结束，不能依赖客户端补发 EOF。
        gateway.exited();
    }
}

#[test]
fn 待确认时输入队列满会取消请求并结束连接() {
    let mut gateway = Gateway::start();
    gateway.send(2, "run_shell", json!({ "argv": ["/bin/sleep", "10"] }));
    gateway.pending();
    let mut burst = Vec::new();
    for id in 10..19 {
        writeln!(
            &mut burst,
            "{}",
            json!({ "jsonrpc": "2.0", "id": id, "method": "initialize" })
        )
        .unwrap();
    }
    gateway
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&burst)
        .unwrap();
    let response = gateway.response();
    assert_eq!(response["id"], 2);
    assert_eq!(response["result"]["isError"], true);
    gateway.exited();
}

#[test]
fn 字面搜索可读源码但不能读取凭据或把查询变成命令() {
    let mut gateway = Gateway::start();
    let source = gateway.directory.join("source.txt");
    let marker = gateway.directory.join("must-not-execute.txt");
    let query = format!("$(touch {})", marker.display());
    std::fs::write(&source, format!("正常\n{query}\n")).unwrap();
    gateway.send(2, "search_file", json!({ "path": source, "query": query }));
    let response = gateway.response();
    assert_ne!(response["result"]["isError"], true, "{response}");
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .starts_with("2:$(touch "));
    assert!(!marker.exists());
    let credentials = gateway.directory.join(".ssh");
    std::fs::create_dir(&credentials).unwrap();
    let private = credentials.join("id_rsa");
    std::fs::write(&private, "PRIVATE-CANARY").unwrap();
    for (id, path) in [
        (3, private.clone()),
        (4, gateway.directory.join("link.txt")),
    ] {
        if id == 4 {
            std::os::unix::fs::symlink(&private, &path).unwrap();
        }
        gateway.send(
            id,
            "search_file",
            json!({ "path": path, "query": "CANARY" }),
        );
        let response = gateway.response();
        assert_eq!(response["result"]["isError"], true);
        assert!(!response.to_string().contains("PRIVATE-CANARY"));
    }
}

#[test]
fn 安装路径不是安装动作但真实安装参数仍拒绝() {
    let mut gateway = Gateway::start();
    let installation = gateway.directory.join("installation/bin");
    std::fs::create_dir_all(&installation).unwrap();
    let program = installation.join("echo");
    std::os::unix::fs::symlink("/bin/echo", &program).unwrap();
    // 目录授权可覆盖这个纯读命令的路径参数；程序位置不应被误判成安装动作。
    gateway.send(
        2,
        "run_shell",
        json!({ "argv": [program, gateway.directory] }),
    );
    let response = gateway.response();
    assert_ne!(response["result"]["isError"], true, "{response}");
    gateway.send(
        3,
        "run_shell",
        json!({ "argv": ["/bin/echo", "Install", gateway.directory] }),
    );
    let response = gateway.response();
    assert_eq!(response["result"]["isError"], true);
    assert!(response.to_string().contains("未执行"));
}
