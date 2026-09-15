//! 桌面持有的独立 MCP 进程。模型只接触工具结果，不能取得控制连接文件或子进程句柄。
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MESSAGE_LIMIT: usize = 1024 * 1024;
const POLL: Duration = Duration::from_millis(10);
// 隔离后端撤销正在运行的任务后，单次容器回收本身最多等待 10 秒。
const EXIT_GRACE: Duration = Duration::from_secs(12);
const EXIT_LIMIT: Duration = Duration::from_secs(14);
const CHILD_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// 只能由可信宿主根据封装资源和本次授权构造，不能反序列化模型或 WebView 提供的命令。
pub struct GatewayStartSpec {
    pub binary: PathBuf,
    pub rules: PathBuf,
    pub policy: PathBuf,
    pub plans: PathBuf,
    pub audit_path: PathBuf,
    pub control_path: PathBuf,
    pub workspace: PathBuf,
    pub task_profile: String,
    pub image: String,
    pub browser: Option<GatewayBrowserSpec>,
}

pub struct GatewayBrowserSpec {
    pub node: PathBuf,
    pub runtime: PathBuf,
    pub playwright: PathBuf,
    pub browsers: PathBuf,
    pub origins: Vec<String>,
    pub audit_path: PathBuf,
    pub control_path: PathBuf,
}

#[derive(Default)]
struct Completion {
    done: bool,
    exited: bool,
    forced: bool,
    error: Option<String>,
}

struct Shared {
    stdin: Mutex<Option<ChildStdin>>,
    closed: AtomicBool,
    expected_id: AtomicU64,
    completion: Mutex<Completion>,
    completed: Condvar,
}

impl Shared {
    fn close(&self, error: Option<&str>) {
        self.closed.store(true, Ordering::SeqCst);
        self.expected_id.store(0, Ordering::SeqCst);
        if let Some(error) = error {
            let mut completion = self.completion.lock().unwrap_or_else(|e| e.into_inner());
            completion.error.get_or_insert_with(|| error.to_owned());
        }
        // 每次非阻塞 write 仅短暂持锁；撤销不会等待一个写满的管道。
        self.stdin.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    fn error(&self) -> String {
        self.completion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .error
            .clone()
            .unwrap_or_else(|| "MANAGED_GATEWAY_STOPPED".into())
    }
}

/// 一次只允许一个 RPC；独立 HTTP 操作者通道仍可并行暂停或停止。
pub struct GatewayProcess {
    pid: u32,
    shared: Arc<Shared>,
    serial: Mutex<()>,
    responses: Mutex<mpsc::Receiver<Value>>,
    sequence: AtomicU64,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl GatewayProcess {
    pub fn start(spec: GatewayStartSpec) -> Result<Arc<Self>, String> {
        for path in [
            &spec.binary,
            &spec.rules,
            &spec.policy,
            &spec.plans,
            &spec.audit_path,
            &spec.control_path,
            &spec.workspace,
        ] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err("MANAGED_GATEWAY_PATH".into());
            }
        }
        let workspace = spec
            .workspace
            .canonicalize()
            .map_err(|_| "MANAGED_GATEWAY_WORKSPACE")?;
        if !workspace.is_dir() {
            return Err("MANAGED_GATEWAY_WORKSPACE".into());
        }
        if spec.task_profile.is_empty()
            || spec.task_profile.len() > 128
            || spec.task_profile.chars().any(char::is_control)
            || spec.image.is_empty()
            || spec.image.chars().any(char::is_control)
        {
            return Err("MANAGED_GATEWAY_ARGUMENTS".into());
        }
        let mut command = Command::new(spec.binary);
        command
            .arg("--rules")
            .arg(spec.rules)
            .arg("--shell-policy")
            .arg(spec.policy)
            .arg("--plans")
            .arg(&spec.plans)
            .arg("--task")
            .arg(spec.task_profile)
            .arg("--isolation-image")
            .arg(spec.image)
            .arg("--audit-db")
            .arg(spec.audit_path)
            .arg("--control-file")
            .arg(spec.control_path)
            .args(["--confirm-port", "0", "--confirm-timeout-secs", "120"])
            // SafeShell 对相对 argv 的证明与工具实际执行必须使用同一工作区根。
            .current_dir(workspace);
        if let Some(browser) = spec.browser {
            command
                .arg("--browser-runtime")
                .arg(browser.runtime)
                .arg("--browser-node")
                .arg(browser.node)
                .arg("--browser-playwright")
                .arg(browser.playwright)
                .arg("--browser-browsers")
                .arg(browser.browsers)
                .arg("--browser-audit-db")
                .arg(browser.audit_path)
                .arg("--browser-file")
                .arg(browser.control_path);
            for origin in browser.origins {
                command.arg("--browser-origin").arg(origin);
            }
        }
        Self::spawn(command, EXIT_GRACE)
    }

    fn spawn(mut command: Command, exit_grace: Duration) -> Result<Arc<Self>, String> {
        #[cfg(not(unix))]
        {
            let _ = (command, exit_grace);
            return Err("MANAGED_GATEWAY_UNSUPPORTED".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.env_clear().env("PATH", CHILD_PATH);
            if let Some(home) = std::env::var_os("HOME") {
                command.env("HOME", home);
            }
            command.env("TMPDIR", std::env::temp_dir());
            // Docker 从本用户当前 context 确定本地 socket；不继承代理、模型令牌或远程覆盖。
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0);
            let mut child = command.spawn().map_err(|_| "MANAGED_GATEWAY_START")?;
            let stdin = child.stdin.take().expect("已配置 stdin 管道");
            let stdout = child.stdout.take().expect("已配置 stdout 管道");
            if nonblocking(&stdin)
                .and_then(|_| nonblocking(&stdout))
                .is_err()
            {
                terminate_child(&mut child);
                let _ = child.wait();
                return Err("MANAGED_GATEWAY_PIPE".into());
            }
            let pid = child.id();
            let shared = Arc::new(Shared {
                stdin: Mutex::new(Some(stdin)),
                closed: AtomicBool::new(false),
                expected_id: AtomicU64::new(0),
                completion: Mutex::new(Completion::default()),
                completed: Condvar::new(),
            });
            let (sender, receiver) = mpsc::sync_channel(1);
            let worker_shared = Arc::clone(&shared);
            // 命名线程同时负责 stdout 与子进程收割，唯一消费者不会与确认 HTTP 争用。
            let child = ReapChild(child);
            let reader = thread::Builder::new()
                .name("agentguard-mcp-stdio".into())
                .spawn(move || supervise(child, stdout, sender, worker_shared, exit_grace))
                .map_err(|_| "MANAGED_GATEWAY_READER_START")?;
            Ok(Arc::new(Self {
                pid,
                shared,
                serial: Mutex::new(()),
                responses: Mutex::new(receiver),
                sequence: AtomicU64::new(1),
                reader: Mutex::new(Some(reader)),
            }))
        }
    }

    #[allow(dead_code)] // 保留只读诊断接口，真实进程验收也使用该身份。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn exited(&self) -> bool {
        self.shared
            .completion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .exited
    }

    #[allow(dead_code)] // 宿主关闭诊断与独立生命周期验收使用。
    pub fn reader_exited(&self) -> bool {
        self.shared
            .completion
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .done
    }

    /// 返回完整 JSON-RPC 响应，业务拒绝与工具 isError 由调用方解释；不自动重试。
    pub fn rpc(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        self.exchange(method, params, timeout, true)?
            .ok_or_else(|| "MANAGED_GATEWAY_PROTOCOL".into())
    }

    pub fn notify(&self, method: &str, params: Value, timeout: Duration) -> Result<(), String> {
        self.exchange(method, params, timeout, false).map(|_| ())
    }

    fn exchange(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        reply: bool,
    ) -> Result<Option<Value>, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("MANAGED_GATEWAY_TIMEOUT")?;
        let _serial = loop {
            if self.shared.closed.load(Ordering::SeqCst) {
                return Err(self.shared.error());
            }
            if Instant::now() >= deadline {
                // 尚未取得串行槽，不影响另一条正在执行的请求。
                return Err("MANAGED_GATEWAY_BUSY_TIMEOUT".into());
            }
            match self.serial.try_lock() {
                Ok(lock) => break lock,
                Err(TryLockError::WouldBlock) => thread::sleep(POLL),
                Err(TryLockError::Poisoned(_)) => {
                    self.shared.close(Some("MANAGED_GATEWAY_STATE"));
                    return Err(self.shared.error());
                }
            }
        };
        let id = self.sequence.fetch_add(1, Ordering::SeqCst);
        if method.is_empty() || method.len() > 128 || id == 0 {
            return Err("MANAGED_GATEWAY_ARGUMENTS".into());
        }
        let mut value = json!({"jsonrpc":"2.0", "method":method, "params":params});
        if reply {
            value["id"] = json!(id);
        }
        let mut bytes = serde_json::to_vec(&value).map_err(|_| "MANAGED_GATEWAY_ARGUMENTS")?;
        bytes.push(b'\n');
        if bytes.len() > MESSAGE_LIMIT {
            return Err("MANAGED_GATEWAY_INPUT_TOO_LARGE".into());
        }
        if reply {
            self.shared.expected_id.store(id, Ordering::SeqCst);
        }
        let mut written = 0;
        while written < bytes.len() {
            self.check_live(deadline)?;
            let result = {
                let mut slot = self.shared.stdin.lock().unwrap_or_else(|e| e.into_inner());
                let input = slot.as_mut().ok_or_else(|| self.shared.error())?;
                input.write(&bytes[written..])
            };
            match result {
                Ok(0) => {
                    self.shared.close(Some("MANAGED_GATEWAY_WRITE"));
                    return Err(self.shared.error());
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.shared.close(Some("MANAGED_GATEWAY_WRITE"));
                    return Err(self.shared.error());
                }
            }
        }
        if !reply {
            return Ok(None);
        }
        let receiver = self.responses.lock().map_err(|_| "MANAGED_GATEWAY_STATE")?;
        loop {
            self.check_live(deadline)?;
            match receiver
                .recv_timeout(POLL.min(deadline.saturating_duration_since(Instant::now())))
            {
                Ok(response) => {
                    if self.shared.closed.load(Ordering::SeqCst) {
                        return Err(self.shared.error());
                    }
                    return Ok(Some(response));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.shared.error()),
            }
        }
    }

    fn check_live(&self, deadline: Instant) -> Result<(), String> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(self.shared.error());
        }
        if Instant::now() >= deadline {
            self.shared.close(Some("MANAGED_GATEWAY_TIMEOUT"));
            return Err(self.shared.error());
        }
        Ok(())
    }

    /// 幂等撤销。先关闭 stdin，使网关自行取消并回收容器；超限才强杀自有进程组。
    /// 强杀只证明本机进程收割，不能冒充容器清理或已发生动作的终态。
    pub fn shutdown(&self) -> Result<(), String> {
        self.shared.close(None);
        let deadline = Instant::now() + EXIT_LIMIT;
        let mut completion = self
            .shared
            .completion
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        while !completion.done {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("MANAGED_GATEWAY_EXIT_UNKNOWN".into());
            }
            completion = self
                .shared
                .completed
                .wait_timeout(completion, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let forced = completion.forced;
        let exited = completion.exited;
        drop(completion);
        if let Some(reader) = self.reader.lock().unwrap_or_else(|e| e.into_inner()).take() {
            reader.join().map_err(|_| "MANAGED_GATEWAY_READER_FAILED")?;
        }
        if !exited {
            Err("MANAGED_GATEWAY_EXIT_UNKNOWN".into())
        } else if forced {
            Err("MANAGED_GATEWAY_FORCED_EXIT".into())
        } else {
            Ok(())
        }
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(unix)]
fn nonblocking<T: std::os::fd::AsRawFd>(pipe: &T) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn terminate_group(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        // 只向本模块创建的进程组发信号，不使用进程名匹配。
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL) == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn terminate_child(child: &mut Child) {
    terminate_group(child.id());
    let _ = child.kill();
}

// 线程创建失败时 Rust 会丢弃闭包；Child 自身的 Drop 不会终止进程，必须单独兜底。
struct ReapChild(Child);
impl Drop for ReapChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            terminate_child(&mut self.0);
            let _ = self.0.wait();
        }
    }
}

fn supervise(
    mut child: ReapChild,
    mut stdout: ChildStdout,
    sender: mpsc::SyncSender<Value>,
    shared: Arc<Shared>,
    exit_grace: Duration,
) {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut closing = None;
    let mut forced = false;
    let mut eof = false;
    loop {
        let mut read_progress = false;
        if shared.closed.load(Ordering::SeqCst) && closing.is_none() {
            closing = Some(Instant::now());
        }
        // 关闭期间继续排空，避免网关最后一条回执堵在管道而无法正常退出。
        if !eof {
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    if !shared.closed.load(Ordering::SeqCst) {
                        shared.close(Some("MANAGED_GATEWAY_EOF"));
                    }
                }
                Ok(count) if !shared.closed.load(Ordering::SeqCst) => {
                    read_progress = true;
                    for byte in &chunk[..count] {
                        bytes.push(*byte);
                        if bytes.len() > MESSAGE_LIMIT {
                            shared.close(Some("MANAGED_GATEWAY_OUTPUT_TOO_LARGE"));
                            bytes.clear();
                            break;
                        }
                        if *byte == b'\n' {
                            let valid = serde_json::from_slice::<Value>(&bytes).ok().filter(|v| {
                                let expected = shared.expected_id.load(Ordering::SeqCst);
                                expected != 0
                                    && v["jsonrpc"] == "2.0"
                                    && v["id"].as_u64() == Some(expected)
                                    && (v.get("result").is_some() ^ v.get("error").is_some())
                            });
                            bytes.clear();
                            match valid {
                                Some(value) => {
                                    shared.expected_id.store(0, Ordering::SeqCst);
                                    if sender.try_send(value).is_err() {
                                        shared.close(Some("MANAGED_GATEWAY_PROTOCOL"));
                                        break;
                                    }
                                }
                                None => {
                                    shared.close(Some("MANAGED_GATEWAY_PROTOCOL"));
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(_) => read_progress = true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    eof = true;
                    shared.close(Some("MANAGED_GATEWAY_READ"));
                }
            }
        }
        match child.0.try_wait() {
            Ok(Some(_)) => {
                // 父进程退出后同组后代仍可能持有 stdout；不把这种情形当成完整正常退出。
                forced |= terminate_group(child.0.id());
                shared.close(if shared.closed.load(Ordering::SeqCst) {
                    None
                } else {
                    Some("MANAGED_GATEWAY_EOF")
                });
                let mut completion = shared.completion.lock().unwrap_or_else(|e| e.into_inner());
                completion.exited = true;
                completion.forced = forced;
                completion.done = true;
                shared.completed.notify_all();
                return;
            }
            Err(_) => shared.close(Some("MANAGED_GATEWAY_WAIT")),
            Ok(None) => {}
        }
        if !forced && closing.is_some_and(|at| at.elapsed() >= exit_grace) {
            terminate_child(&mut child.0);
            forced = true;
        }
        // 有数据时继续排空；每 8 KiB 强制睡眠会让长回执在繁忙主机上先触发超时。
        // 每轮仍检查撤销与子进程状态，无数据时才等待，避免空转。
        if !read_progress {
            thread::sleep(POLL);
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) fn test_python() -> PathBuf {
    // 合成端点使用实际解释器；产品对子进程环境的过滤保持原样。
    #[cfg(target_os = "macos")]
    if let Some(directory) = std::env::var_os("DEVELOPER_DIR") {
        let python = PathBuf::from(directory).join("usr/bin/python3");
        if python.is_file() {
            return python;
        }
    }
    PathBuf::from("/usr/bin/python3")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(body: &str) -> (PathBuf, Arc<GatewayProcess>) {
        let root =
            std::env::temp_dir().join(format!("agd-managed-gateway-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let script = root.join("fixture.py");
        fs::write(&script, body).unwrap();
        let mut command = Command::new(test_python());
        command
            .arg("-I")
            .arg(&script)
            .current_dir(&root)
            .env("AGENTGUARD_TEST_SECRET", "仅测试使用的合成值")
            .env("OPENAI_API_KEY", "synthetic-do-not-inherit")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("DOCKER_HOST", "tcp://127.0.0.1:1");
        let gateway = GatewayProcess::spawn(command, Duration::from_millis(150)).unwrap();
        (root, gateway)
    }

    fn cleanup(root: PathBuf, gateway: Arc<GatewayProcess>) {
        let _ = gateway.shutdown();
        assert!(gateway.exited());
        assert!(gateway.reader_exited());
        assert_eq!(unsafe { libc::kill(gateway.pid() as libc::pid_t, 0) }, -1);
        drop(gateway);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 握手多轮与业务拒绝保持同一进程() {
        let (root, gateway) = fixture(
            "import sys,json,os\nfor line in sys.stdin:\n r=json.loads(line)\n if 'id' in r:\n  v={'jsonrpc':'2.0','id':r['id'],'error':{'code':-32602,'message':'fixture'}} if r['method']=='deny' else {'jsonrpc':'2.0','id':r['id'],'result':{'pid':os.getpid()}}\n  print(json.dumps(v),flush=True)\n",
        );
        let first = gateway
            .rpc("initialize", json!({}), Duration::from_secs(2))
            .unwrap();
        gateway
            .notify(
                "notifications/initialized",
                json!({}),
                Duration::from_secs(1),
            )
            .unwrap();
        let second = gateway
            .rpc("tools/list", json!({}), Duration::from_secs(2))
            .unwrap();
        assert_eq!(first["result"]["pid"], second["result"]["pid"]);
        assert_eq!(first["result"]["pid"], gateway.pid());
        assert_eq!(
            gateway
                .rpc("deny", json!({}), Duration::from_secs(2))
                .unwrap()["error"]["code"],
            -32602
        );
        assert!(!gateway.exited());
        assert!(gateway.shutdown().is_ok());
        assert!(gateway.shutdown().is_ok());
        cleanup(root, gateway);
    }

    #[test]
    fn 超时后实例不能复用且迟到响应不生效() {
        let (root, gateway) = fixture("import sys,time,json\nfor line in sys.stdin:\n r=json.loads(line)\n time.sleep(1)\n print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':'late'}),flush=True)\n");
        assert_eq!(
            gateway
                .rpc("slow", json!({}), Duration::from_millis(50))
                .unwrap_err(),
            "MANAGED_GATEWAY_TIMEOUT"
        );
        assert!(gateway
            .rpc("next", json!({}), Duration::from_secs(1))
            .is_err());
        assert_eq!(
            gateway.shutdown().unwrap_err(),
            "MANAGED_GATEWAY_FORCED_EXIT"
        );
        cleanup(root, gateway);
    }

    #[test]
    fn 并发调用各自获得对应回执且超长输入未发送() {
        let (root, gateway) = fixture("import sys,json,time\nfor line in sys.stdin:\n r=json.loads(line)\n time.sleep(0.02)\n print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':r['params']}),flush=True)\n");
        assert_eq!(
            gateway
                .rpc(
                    "too_large",
                    json!({"body":"x".repeat(MESSAGE_LIMIT)}),
                    Duration::from_secs(2)
                )
                .unwrap_err(),
            "MANAGED_GATEWAY_INPUT_TOO_LARGE"
        );
        let calls: Vec<_> = (0..4)
            .map(|index| {
                let caller = Arc::clone(&gateway);
                thread::spawn(move || {
                    let response = caller
                        .rpc("echo", json!({"index":index}), Duration::from_secs(2))
                        .unwrap();
                    assert_eq!(response["result"]["index"], index);
                })
            })
            .collect();
        for call in calls {
            call.join().unwrap();
        }
        cleanup(root, gateway);
    }

    #[test]
    fn 错误id与非协议输出终止实例() {
        for body in [
            "import sys,json\nfor line in sys.stdin:\n r=json.loads(line)\n print(json.dumps({'jsonrpc':'2.0','id':r['id']+1,'result':{}}),flush=True)\n",
            "import sys\nfor line in sys.stdin:\n print('非协议输出',flush=True)\n",
        ] {
            let (root, gateway) = fixture(body);
            assert_eq!(gateway.rpc("initialize", json!({}), Duration::from_secs(2)).unwrap_err(), "MANAGED_GATEWAY_PROTOCOL");
            cleanup(root, gateway);
        }
    }

    #[test]
    fn 超长输出与提前退出均明确失败() {
        for (body, expected) in [
            (
                "import sys\nfor line in sys.stdin:\n print('x'*1048577,flush=True)\n",
                "MANAGED_GATEWAY_OUTPUT_TOO_LARGE",
            ),
            ("import sys\nsys.stdin.readline()\n", "MANAGED_GATEWAY_EOF"),
        ] {
            let (root, gateway) = fixture(body);
            let error = gateway
                .rpc("initialize", json!({}), Duration::from_secs(3))
                .unwrap_err();
            assert!(
                error == expected
                    || (expected == "MANAGED_GATEWAY_EOF" && error == "MANAGED_GATEWAY_STOPPED"),
                "{error}"
            );
            cleanup(root, gateway);
        }
    }

    #[test]
    fn 关闭能打断待回执与写满的stdin() {
        for params in [json!({}), json!({"body":"x".repeat(512 * 1024)})] {
            let (root, gateway) = fixture("import time\ntime.sleep(60)\n");
            let caller = Arc::clone(&gateway);
            let rpc = thread::spawn(move || caller.rpc("waiting", params, Duration::from_secs(30)));
            thread::sleep(Duration::from_millis(40));
            let start = Instant::now();
            assert_eq!(
                gateway.shutdown().unwrap_err(),
                "MANAGED_GATEWAY_FORCED_EXIT"
            );
            assert!(rpc.join().unwrap().is_err());
            assert!(start.elapsed() < Duration::from_secs(2));
            cleanup(root, gateway);
        }
    }

    #[test]
    fn 子进程只继承允许的环境变量() {
        let (root, gateway) = fixture("import sys,json,os\nfor line in sys.stdin:\n r=json.loads(line)\n print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':sorted(os.environ)}),flush=True)\n");
        let result = gateway
            .rpc("env", json!({}), Duration::from_secs(2))
            .unwrap();
        let names = result["result"].as_array().unwrap();
        // macOS 的 /usr/bin/python3 启动器还会添加 CPATH 等自身变量；验证不继承宿主秘密。
        for forbidden in [
            "AGENTGUARD_TEST_SECRET",
            "OPENAI_API_KEY",
            "HTTPS_PROXY",
            "DOCKER_HOST",
        ] {
            assert!(
                !names.contains(&json!(forbidden)),
                "宿主环境变量被继承：{forbidden}"
            );
        }
        assert!(names.contains(&json!("PATH")));
        assert!(names.contains(&json!("HOME")));
        assert!(names.contains(&json!("TMPDIR")));
        cleanup(root, gateway);
    }

    #[test]
    fn 最后一个持有者释放后收割子进程() {
        let (root, gateway) = fixture("import sys\nfor line in sys.stdin: pass\n");
        let pid = gateway.pid();
        drop(gateway);
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 线程接管失败的句柄析构也收割进程() {
        use std::os::unix::process::CommandExt;
        let child = Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        drop(ReapChild(child));
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
    }

    #[test]
    fn 主进程提前退出不能遗留同组后台后代() {
        let (root, gateway) = fixture("import os,time\npid=os.fork()\nif pid:\n with open('orphan.pid','w') as f: f.write(str(pid))\n os._exit(0)\ntime.sleep(60)\n");
        assert!(gateway
            .rpc("initialize", json!({}), Duration::from_secs(2))
            .is_err());
        assert_eq!(
            gateway.shutdown().unwrap_err(),
            "MANAGED_GATEWAY_FORCED_EXIT"
        );
        let descendant = fs::read_to_string(root.join("orphan.pid")).unwrap();
        thread::sleep(Duration::from_millis(100));
        let status = Command::new("/bin/ps")
            .args(["-p", descendant.trim(), "-o", "stat="])
            .output()
            .unwrap();
        let status = String::from_utf8_lossy(&status.stdout);
        // 孤儿退出后由系统收割；Z 仅是退出记录，不能继续执行。
        assert!(
            status.trim().is_empty() || status.trim().starts_with('Z'),
            "同组后台进程仍在运行"
        );
        cleanup(root, gateway);
    }

    #[test]
    #[ignore = "需要显式指定真实候选和已存在的本地隔离镜像，实际运行 Docker"]
    fn 真实网关跨轮持有与连接关闭撤销控制文件() {
        use sha2::{Digest, Sha256};
        use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
        let binary = PathBuf::from(
            std::env::var_os("AGENTGUARD_MANAGED_GATEWAY_BINARY").expect("必须指定冻结网关候选"),
        );
        let image =
            std::env::var("AGENTGUARD_MANAGED_GATEWAY_IMAGE").expect("必须指定本地镜像摘要");
        let binary_sha256 = format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()));
        let root = std::env::temp_dir().join(format!("agd-managed-real-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("fixture.txt"),
            "真实握手夹具，宿主正文保持不变\n",
        )
        .unwrap();
        fs::write(workspace.join("relative_probe.py"), "from pathlib import Path\nassert Path('fixture.txt').is_file()\nprint('RELATIVE_WORKSPACE_OK')\n").unwrap();
        let plans = root.join("plans.json");
        fs::write(&plans, serde_json::to_vec(&json!({"plans":[{"task_profile":"managed-fixture", "allow":["run_shell"], "scope":{"paths":{"read":[workspace],"write":[workspace]}}}]})).unwrap()).unwrap();
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let control_path = root.join("control.json");
        let gateway = GatewayProcess::start(GatewayStartSpec {
            binary,
            rules: repository.join("crates/guard-schema/rules/p0_rules.yaml"),
            policy: repository.join("crates/guard-shell/policies/default.yaml"),
            plans,
            audit_path: root.join("audit.db"),
            control_path: control_path.clone(),
            workspace: workspace.clone(),
            task_profile: "managed-fixture".into(),
            image: image.clone(),
            browser: None,
        })
        .unwrap();
        let init = gateway.rpc("initialize", json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agentguard-managed-probe","version":"1"}}), Duration::from_secs(30)).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "agentguard-mcp");
        gateway
            .notify(
                "notifications/initialized",
                json!({}),
                Duration::from_secs(2),
            )
            .unwrap();
        let first = gateway
            .rpc("gateway/stats", json!({}), Duration::from_secs(3))
            .unwrap();
        assert_eq!(
            first["result"]["execution_backend"]["mode"],
            "isolated_workspace_snapshot"
        );
        assert_eq!(first["result"]["session_state"], "active");
        let snapshot = PathBuf::from(
            first["result"]["execution_backend"]["snapshot_root"]
                .as_str()
                .unwrap(),
        );
        // 合成控制凭据只留在测试进程内，证据仅保存端口、实例号与撤销结果。
        let control: Value = serde_json::from_slice(&fs::read(&control_path).unwrap()).unwrap();
        let port = control["port"].as_u64().unwrap() as u16;
        let mut http = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).unwrap();
        http.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(http, "GET /workspace/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", control["token"].as_str().unwrap()).unwrap();
        let mut response = String::new();
        http.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        thread::sleep(Duration::from_millis(150));
        gateway
            .rpc("ping", json!({}), Duration::from_secs(2))
            .unwrap();
        let second = gateway
            .rpc("gateway/stats", json!({}), Duration::from_secs(3))
            .unwrap();
        let relative = gateway.rpc("tools/call", json!({"name":"run_shell", "arguments":{"argv":["python3","relative_probe.py"],"cwd":workspace}, "_meta":{"agentguard_session_id":second["result"]["host_session_id"]}}), Duration::from_secs(30)).unwrap();
        assert_eq!(relative["result"]["isError"], false, "{relative}");
        assert!(relative["result"]["content"]
            .to_string()
            .contains("RELATIVE_WORKSPACE_OK"));
        assert_eq!(
            first["result"]["session_id"],
            second["result"]["session_id"]
        );
        assert!(control_path.is_file());
        assert!(!gateway.exited());
        gateway.shutdown().unwrap();
        assert!(gateway.exited());
        assert!(gateway.reader_exited());
        assert!(!control_path.exists());
        assert!(TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_millis(200)
        )
        .is_err());
        assert_eq!(
            fs::read_to_string(workspace.join("fixture.txt")).unwrap(),
            "真实握手夹具，宿主正文保持不变\n"
        );
        let mut report = json!({"passed":true,"binary_sha256":binary_sha256,"image":image,"pid":gateway.pid(),"session_id":first["result"]["session_id"],"same_session_across_rpc":true,"operator_http_200":true,"control_file_revoked":true,"listener_closed":true,"child_reaped":true,"reader_exited":true,"host_unchanged":true,"snapshot":snapshot});
        // 只删除该已关闭实例报告的自有快照，不扫描或清理其它任务目录。
        assert!(snapshot
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("agentguard-snapshot-"));
        assert_eq!(
            snapshot.parent().unwrap().canonicalize().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        fs::remove_dir_all(&snapshot).unwrap();
        assert!(!snapshot.exists());
        report["snapshot_removed"] = json!(true);
        report["relative_argv_workspace_verified"] = json!(true);
        drop(gateway);
        fs::remove_dir_all(root).unwrap();
        if let Some(path) = std::env::var_os("AGENTGUARD_MANAGED_GATEWAY_REPORT") {
            fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
    }
}
