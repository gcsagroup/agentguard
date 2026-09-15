use super::*;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Fixture {
    client: StdioClient,
    root: PathBuf,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("agd-stdio-{}", crate::browser_bridge::token()));
        std::fs::create_dir(&root).unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.env_clear();
        // macOS 的 /usr/bin/python3 是开发工具代理。保留调用方显式选择的 SDK，
        // 避免测试进程清空环境后误切到另一套尚未就绪的 Xcode；Linux 仍为空环境。
        #[cfg(target_os = "macos")]
        if let Some(directory) = std::env::var_os("DEVELOPER_DIR") {
            command.env("DEVELOPER_DIR", directory);
        }
        let mut child = command
            .args(["-I", "-u"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/mcp_stdio_server.py"
            ))
            .arg(mode)
            .arg(root.join("calls.jsonl"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // 此夹具测协议与故障语义。解释器启动独立限时，不能把尚未进入主循环
        // 的进程误判为不支持版本或协议超时；真实网关启动预算另有实机验收。
        let launched = Instant::now();
        let ready = root.join("calls.jsonl.ready");
        while !ready.is_file() {
            let exited = child.try_wait().unwrap();
            if exited.is_some() || launched.elapsed() >= Duration::from_secs(10) {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                std::fs::remove_dir_all(&root).unwrap();
                panic!(
                    "合成服务未就绪：mode={mode} elapsed={:?} status={} stderr={}",
                    launched.elapsed(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        eprintln!("合成服务就绪：mode={mode} elapsed={:?}", launched.elapsed());
        Self {
            client: StdioClient::attach(child).unwrap(),
            root,
        }
    }
    fn ready(mode: &str) -> Self {
        let mut fixture = Self::new(mode);
        fixture
            .client
            .initialize(Duration::from_secs(3), &|| false)
            .unwrap();
        fixture
            .client
            .list_tools(Duration::from_secs(3), &|| false)
            .unwrap();
        fixture
    }
    fn call(&mut self) -> Result<Reply, Failure> {
        self.client
            .call_tool("record", json!({}), Duration::from_millis(300), &|| false)
    }
    fn calls(&self) -> usize {
        std::fs::read_to_string(self.root.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("tools/call"))
            .count()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.client.close();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn 解释器延迟就绪后仍须遵守原协议响应期限() {
    let mut fixture = Fixture::ready("boot-delayed");
    assert!(fixture.call().is_ok());
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn 真实进程握手发现调用和正常退出() {
    let mut f = Fixture::new("normal");
    assert_eq!(
        f.client
            .list_tools(Duration::from_secs(1), &|| false)
            .unwrap_err()
            .kind,
        FailureKind::State
    );
    let init = f
        .client
        .initialize(Duration::from_secs(3), &|| false)
        .unwrap();
    assert_eq!(init["protocolVersion"], PROTOCOL_VERSION);
    let listed = f
        .client
        .list_tools(Duration::from_secs(3), &|| false)
        .unwrap();
    assert_eq!(listed["tools"][0]["title"], "保留原始字段");
    assert_eq!(listed["tools"][0]["annotations"]["readOnlyHint"], false);
    let Reply::Result(result) = f.call().unwrap() else {
        panic!("应返回结果");
    };
    assert_eq!(result["structuredContent"]["recorded"], true);
    assert_eq!(f.calls(), 1);
    assert!(f.client.close());
    assert!(!f.client.is_ready());
}

#[test]
fn 远端错误正文保持不可信响应且不冒充传输失败() {
    let mut f = Fixture::ready("rpc-error");
    let Reply::Error(error) = f.call().unwrap() else {
        panic!("应保留 RPC 错误");
    };
    assert_eq!(error["code"], -32602);
    assert_eq!(error["data"]["untrusted"], true);
    assert!(f.client.is_ready());
    assert_eq!(f.calls(), 1);
}

#[test]
fn 派发后故障保留未知边界并禁止再次调用() {
    for (mode, expected) in [
        ("timeout", FailureKind::Timeout),
        ("partial", FailureKind::Timeout),
        ("eof", FailureKind::Disconnected),
        ("stderr", FailureKind::Limit),
        ("oversize", FailureKind::Limit),
        ("utf8", FailureKind::Protocol),
        ("notification", FailureKind::Unsupported),
        ("server-request", FailureKind::Unsupported),
        ("duplicate-response", FailureKind::Protocol),
        ("wrong-id", FailureKind::Protocol),
        ("image", FailureKind::Unsupported),
        ("bad-result", FailureKind::Protocol),
    ] {
        let mut f = Fixture::ready(mode);
        let started = Instant::now();
        let failure = f.call().unwrap_err();
        assert_eq!(failure.kind, expected, "{mode}");
        assert!(failure.dispatched, "{mode}");
        assert!(!f.client.is_ready(), "{mode}");
        assert!(started.elapsed() < Duration::from_secs(2), "{mode}");
        assert_eq!(
            f.call().unwrap_err(),
            Failure {
                kind: FailureKind::State,
                dispatched: false
            }
        );
        assert_eq!(f.calls(), 1, "{mode} 不得重发");
        assert!(
            f.client.child.try_wait().unwrap().is_some(),
            "{mode} 子进程已回收"
        );
    }
}

#[test]
fn 初始化和清单拒绝不支持版本分页重名与数量超限() {
    let mut f = Fixture::new("version");
    assert_eq!(
        f.client
            .initialize(Duration::from_secs(3), &|| false)
            .unwrap_err(),
        Failure {
            kind: FailureKind::Unsupported,
            dispatched: true
        }
    );
    for (mode, expected) in [
        ("pagination", FailureKind::Unsupported),
        ("duplicate-tool", FailureKind::Protocol),
        ("many-tools", FailureKind::Limit),
    ] {
        let mut f = Fixture::new(mode);
        f.client
            .initialize(Duration::from_secs(3), &|| false)
            .unwrap();
        assert_eq!(
            f.client
                .list_tools(Duration::from_secs(3), &|| false)
                .unwrap_err()
                .kind,
            expected
        );
        assert!(!f.client.is_ready());
        assert_eq!(f.calls(), 0);
    }
}

#[test]
fn 参数与请求大小错误发生在派发前且不破坏有效通道() {
    let mut f = Fixture::ready("normal");
    for (name, args, timeout) in [
        ("unknown", json!({}), Duration::from_secs(1)),
        ("record", json!([]), Duration::from_secs(1)),
        (
            "record",
            json!({"text":"x".repeat(MAX_REQUEST_BYTES)}),
            Duration::from_secs(1),
        ),
        ("record", json!({}), Duration::ZERO),
        ("record", json!({}), Duration::from_secs(31)),
    ] {
        assert_eq!(
            f.client
                .call_tool(name, args, timeout, &|| false)
                .unwrap_err(),
            Failure {
                kind: FailureKind::Input,
                dispatched: false
            }
        );
    }
    assert_eq!(f.calls(), 0);
    assert!(f.client.is_ready());
    assert!(f.call().is_ok());
    assert_eq!(f.calls(), 1);
}

#[test]
fn 取消区分写入前与写入后并关闭通道() {
    let mut f = Fixture::new("normal");
    assert_eq!(
        f.client
            .initialize(Duration::from_secs(1), &|| true)
            .unwrap_err(),
        Failure {
            kind: FailureKind::Cancelled,
            dispatched: false
        }
    );
    assert!(!f.root.join("calls.jsonl").exists());
    let mut f = Fixture::ready("timeout");
    let start = Instant::now();
    let result = f
        .client
        .call_tool("record", json!({}), Duration::from_secs(3), &|| {
            start.elapsed() > Duration::from_millis(100)
        });
    assert_eq!(
        result.unwrap_err(),
        Failure {
            kind: FailureKind::Cancelled,
            dispatched: true
        }
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(f.calls(), 1);
}

#[test]
fn 对端不读输入时写入也受总时限约束() {
    let mut f = Fixture::ready("blocked-input");
    // 服务在下一次 read 前主动停止；填满管道，验证 send 不会阻塞在 write。
    let mut status = 0;
    let stopped = unsafe {
        libc::waitpid(
            f.client.child.id() as libc::pid_t,
            &mut status,
            libc::WUNTRACED,
        )
    };
    assert_eq!(stopped, f.client.child.id() as libc::pid_t);
    assert!(libc::WIFSTOPPED(status));
    let fill = [b' '; 4096];
    loop {
        match f.client.stdin.as_mut().unwrap().write(&fill) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            other => panic!("填充管道失败：{other:?}"),
        }
    }
    // 大块写入被拒绝并不表示小请求也放不下；继续耗尽不足一个块的余量。
    loop {
        match f.client.stdin.as_mut().unwrap().write(b" ") {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            other => panic!("填充剩余管道容量失败：{other:?}"),
        }
    }
    let start = Instant::now();
    let failure = f.call().unwrap_err();
    assert_eq!(
        failure,
        Failure {
            kind: FailureKind::Timeout,
            dispatched: false
        }
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(f.client.child.try_wait().unwrap().is_some());
}

#[test]
fn 严格响应解析拒绝歧义和错误身份() {
    for wire in [
        r#"{"jsonrpc":"2.0","id":1,"id":1,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{"x":{"a":1,"a":2}}}"#,
        r#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"result":[],"extra":1}"#,
        r#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}"#,
        r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        r#"{"jsonrpc":"2.0","id":1,"result":{}} {}"#,
    ] {
        assert_eq!(
            parse_response(wire.as_bytes(), 1).unwrap_err(),
            FailureKind::Protocol,
            "{wire}"
        );
    }
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"x":{}0{}}}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    assert_eq!(
        parse_response(deep.as_bytes(), 1).unwrap_err(),
        FailureKind::Protocol
    );
    assert!(parse_response(
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":[null,true,1,-2,0.5,\"z\"]}}",
        1
    )
    .is_ok());
}

// 显式运行的集成检查：官方 npm 包、镜像和输出目录由验收脚本准备。
// 启动参数只用于这个测试，不充当尚未接好的产品代理启动器或包绑定。
struct DockerFixture {
    binary: PathBuf,
    endpoint: String,
    name: String,
}
impl DockerFixture {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command.env_clear().env("DOCKER_HOST", &self.endpoint);
        command.args(args);
        command
    }
    fn output(&self, args: &[&str]) -> crate::ExecOutput {
        crate::exec::run_command_with_cancel(self.command(args), Duration::from_secs(10), &|| false)
    }
}
impl Drop for DockerFixture {
    fn drop(&mut self) {
        // 只清理本测试随机命名的单个容器；没有镜像/卷清理。
        let _ = self.output(&["rm", "--force", &self.name]);
    }
}

#[test]
#[ignore = "需要显式准备官方 Filesystem MCP 包、既有 Docker 镜像和自有输出目录"]
fn 官方服务在既有容器中经过新通道实际读写() {
    use sha2::{Digest, Sha256};
    let package = PathBuf::from(std::env::var("AGD_MCP_FS_PACKAGE").expect("AGD_MCP_FS_PACKAGE"))
        .canonicalize()
        .unwrap();
    let output = PathBuf::from(std::env::var("AGD_MCP_FS_OUTPUT").expect("AGD_MCP_FS_OUTPUT"));
    assert!(output.is_absolute());
    std::fs::create_dir(&output).unwrap();
    let work = output.join("workspace");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("input.txt"), "SYNTHETIC_MCP_INPUT\n").unwrap();
    let docker = DockerFixture {
        binary: PathBuf::from(std::env::var("AGD_MCP_DOCKER").expect("AGD_MCP_DOCKER")),
        endpoint: std::env::var("AGD_MCP_DOCKER_ENDPOINT").expect("AGD_MCP_DOCKER_ENDPOINT"),
        name: format!("agd-stdio-{}", crate::browser_bridge::token()),
    };
    assert!(docker.binary.is_absolute());
    let socket = docker
        .endpoint
        .strip_prefix("unix://")
        .expect("仅支持本地 Unix socket");
    assert!(std::path::Path::new(socket).is_absolute());
    assert!(
        docker
            .output(&["info", "--format", "{{.OSType}}"])
            .detail
            .trim()
            == "linux"
    );
    let image = std::env::var("AGD_MCP_IMAGE").expect("AGD_MCP_IMAGE");
    let digest = image.strip_prefix("sha256:").expect("必须钉住本地镜像摘要");
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(
        docker
            .output(&["image", "inspect", "--format", "{{.Id}}", &image])
            .detail
            .trim(),
        image
    );
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    assert_ne!(uid, 0);
    assert!(!package.to_str().unwrap().contains(','));
    assert!(!work.to_str().unwrap().contains(','));
    let mut command = docker.command(&[
        "run",
        "--pull=never",
        "--rm",
        "-i",
        "--name",
        &docker.name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=64",
        "--memory=256m",
        "--memory-swap=256m",
        "--cpus=1",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216",
        "--entrypoint=/usr/bin/env",
    ]);
    command.args([
        "--user",
        &format!("{uid}:{gid}"),
        "--mount",
        &format!("type=bind,src={},dst=/service,readonly", package.display()),
        "--mount",
        &format!("type=bind,src={},dst=/workspace", work.display()),
        "--workdir",
        "/workspace",
        &image,
        "-i",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/tmp",
        "TMPDIR=/tmp",
        "LANG=C.UTF-8",
        "/usr/local/bin/node",
        "/service/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
        "/workspace",
    ]);
    let mut client = StdioClient::attach(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
    .unwrap();
    let mut checks = Vec::new();
    let initialized = client
        .initialize(Duration::from_secs(15), &|| false)
        .unwrap();
    checks.push("实际协商 MCP 2025-06-18");
    let inspection = docker.output(&["inspect", &docker.name]);
    assert!(inspection.ok, "{}", inspection.detail);
    let inspected: Value = serde_json::from_str(&inspection.detail).unwrap();
    let container = &inspected[0];
    assert_eq!(container["HostConfig"]["NetworkMode"], "none");
    assert_eq!(container["HostConfig"]["ReadonlyRootfs"], true);
    assert_eq!(container["HostConfig"]["CapDrop"], json!(["ALL"]));
    assert_eq!(
        container["HostConfig"]["SecurityOpt"],
        json!(["no-new-privileges:true"])
    );
    assert_eq!(container["Config"]["User"], format!("{uid}:{gid}"));
    assert_eq!(container["HostConfig"]["PidsLimit"], 64);
    assert_eq!(container["HostConfig"]["Memory"], 256 * 1024 * 1024);
    assert_eq!(container["HostConfig"]["MemorySwap"], 256 * 1024 * 1024);
    assert_eq!(container["HostConfig"]["NanoCpus"], 1_000_000_000);
    let mounts: Vec<_> = container["Mounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["Type"] == "bind")
        .collect();
    assert_eq!(mounts.len(), 2);
    assert!(mounts
        .iter()
        .any(|m| m["Destination"] == "/service" && m["RW"] == false));
    assert!(mounts
        .iter()
        .any(|m| m["Destination"] == "/workspace" && m["RW"] == true));
    checks.push("从容器外核对镜像及网络挂载用户能力与资源限制");
    let listed = client
        .list_tools(Duration::from_secs(15), &|| false)
        .unwrap();
    assert_eq!(listed["tools"].as_array().unwrap().len(), 14);
    checks.push("实际发现 14 项工具并保留完整描述与元数据");
    let Reply::Result(read) = client
        .call_tool(
            "read_text_file",
            json!({"path":"/workspace/input.txt"}),
            Duration::from_secs(15),
            &|| false,
        )
        .unwrap()
    else {
        panic!("读取失败");
    };
    assert_eq!(read["content"][0]["text"], "SYNTHETIC_MCP_INPUT\n");
    checks.push("读取自有合成输入");
    let Reply::Result(write) = client
        .call_tool(
            "write_file",
            json!({"path":"/workspace/result.txt","content":"SYNTHETIC_MCP_RESULT\n"}),
            Duration::from_secs(15),
            &|| false,
        )
        .unwrap()
    else {
        panic!("写入失败");
    };
    assert_ne!(write["isError"], true);
    assert_eq!(
        std::fs::read_to_string(work.join("result.txt")).unwrap(),
        "SYNTHETIC_MCP_RESULT\n"
    );
    checks.push("实际写入并从容器外核对文件内容");
    let Reply::Result(denied) = client
        .call_tool(
            "read_text_file",
            json!({"path":"/etc/hostname"}),
            Duration::from_secs(15),
            &|| false,
        )
        .unwrap()
    else {
        panic!("预期工具错误结果");
    };
    assert_eq!(denied["isError"], true);
    checks.push("保留服务自身的路径拒绝结果");
    assert!(client.close());
    let remaining = docker.output(&["ps", "-aq", "--filter", &format!("name=^/{}$", docker.name)]);
    assert!(remaining.ok && remaining.detail.trim().is_empty());
    checks.push("stdin EOF 后正常退出且自有容器已删除");
    let binary_digest = format!(
        "{:x}",
        Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    let report = json!({"passed":true,"scope":"AGD-017 stdio 传输组件；尚未经过登记批准审计的产品代理", "checks":checks,
        "image":image,"test_binary_sha256":binary_digest, "initialization":initialized, "tool_listing":listed,
        "receipts":{"read":read,"write":write,"service_path_denial":denied},
        "container_configuration":container["HostConfig"],"container_removed":true});
    std::fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "7 项真实 Docker 检查通过；报告：{}",
        output.join("report.json").display()
    );
}

struct PausingGuard {
    pending: crate::PendingConfirm,
    epoch: u64,
    pause: bool,
}
impl DispatchGuard for PausingGuard {
    fn with_permission(
        &self,
        write: &mut dyn FnMut() -> io::Result<usize>,
    ) -> Option<io::Result<usize>> {
        if self.pause {
            self.pending.pause();
        }
        self.pending.with_active_epoch(self.epoch, write)
    }
}
#[test]
fn 取消检查之后首次实际写入之前撤权仍为零请求() {
    let mut f = Fixture::new("normal");
    let pending = crate::PendingConfirm::new();
    f.client
        .set_dispatch_guard(Box::new(PausingGuard {
            epoch: pending.cancellation_epoch(),
            pending,
            pause: true,
        }))
        .unwrap();
    let failure = f
        .client
        .initialize(Duration::from_secs(3), &|| false)
        .unwrap_err();
    assert_eq!(failure.kind, FailureKind::Cancelled);
    assert!(!failure.dispatched);
    assert!(!f.root.join("calls.jsonl").exists());
}
#[test]
fn 宿主暂停后旧通道不能派发且守卫不能被替换() {
    let mut f = Fixture::new("normal");
    let pending = crate::PendingConfirm::new();
    let epoch = pending.cancellation_epoch();
    f.client
        .set_dispatch_guard(Box::new(PausingGuard {
            epoch,
            pending: pending.clone(),
            pause: false,
        }))
        .unwrap();
    assert!(f
        .client
        .set_dispatch_guard(Box::new(PausingGuard {
            epoch,
            pending: pending.clone(),
            pause: false
        }))
        .is_err());
    f.client
        .initialize(Duration::from_secs(3), &|| false)
        .unwrap();
    f.client
        .list_tools(Duration::from_secs(3), &|| false)
        .unwrap();
    pending.pause();
    let failure = f.call().unwrap_err();
    assert_eq!(failure.kind, FailureKind::Cancelled);
    assert!(!failure.dispatched);
    assert_eq!(f.calls(), 0);
}
