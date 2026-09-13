//! 执行层：网关自己动手，所以它拒绝时是真的没做。
//!
//! # 只走 argv，绝不交给 shell
//!
//! 每一条命令都以参数向量的形式 `exec`，永远不经过 `sh -c`。这是论文里的 "Secure Command
//! Construction"（(A)I Sees §IV-C 的 A7 攻击就是宿主对 VLM 输出用了 `shell=True`），也是
//! `guard-shell` 的元字符检查存在的前提：如果最终还是交给 shell，那么挡住 `;` 和 `|` 只是
//! 在减少攻击面，而不是消除这一类攻击。
//!
//! 这里没有 `sh`、没有 `-c`、没有字符串拼接后再解析。有的只是 `Command::new(argv[0]).args(&argv[1..])`。
//!
//! # 每个工具都有一个"不执行也能回答"的形态
//!
//! [`ToolCall::describe`] 返回这次调用**会**做什么，不做。测试用它断言"拒绝之后确实什么都没发生"，
//! 而不是只断言"返回了一个错误对象"。后者是这个项目反复抓到的那种缺陷：机制存在、被直接测试过、
//! 被描述成完整的，然后什么都没接上。

use crate::content::{visible_prefix, CapturedStream, RawCapture};
use guard_schema::ContentViewOrigin;
use guard_schema::ExecutionOutcome;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// 单次执行的输出上限，防止一条 `cat` 把整个 MCP 通道塞满。
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// 执行的墙钟上限。超时**杀掉**子进程并报错，而不是无限等——一个卡住的工具调用会让整个
/// MCP 会话停在那里，而智能体只会看到"没有响应"。
pub const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Windows first-GA execution posture.
///
/// The current policy judges path *names*, while Win32 filesystem calls and
/// child processes reopen those names later. Without a handle-bound executor,
/// a junction/reparse/hard-link swap can change the object after approval. A
/// final-path recheck still leaves a new check/use window, so Windows disables
/// every side-effect tool before execution instead of claiming that gap closed.
pub const WINDOWS_FAIL_CLOSED_REASON: &str =
    "Windows 首个 GA 已禁用 gateway 副作用工具：当前实现不能把已批准路径绑定到同一文件句柄，\
     也不能约束子进程重新解析字符串路径；为避免 junction/reparse/hard-link TOCTOU，\
     本次调用在任何文件系统或进程副作用前失败关闭。直接绕过 gateway 仍在 cooperative 边界之外。";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutionMode {
    Native,
    WindowsFailClosed,
}

impl ExecutionMode {
    pub(crate) const fn host() -> Self {
        if cfg!(target_os = "windows") {
            Self::WindowsFailClosed
        } else {
            Self::Native
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Native => "enabled",
            Self::WindowsFailClosed => "disabled_fail_closed",
        }
    }
}

/// 网关掌管的工具。
///
/// 刻意窄：每一个都是"危险到值得由守卫来执行"的动作。读文件也在里面，因为凭据目录的读
/// 同样是 B0 会拒的事情。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolCall {
    RunShell {
        argv: Vec<String>,
        cwd: Option<PathBuf>,
    },
    ReadFile {
        path: PathBuf,
    },
    SearchFile {
        path: PathBuf,
        query: String,
    },
    WriteFile {
        path: PathBuf,
        contents: String,
    },
    DeleteFile {
        path: PathBuf,
    },
}

/// 执行结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    pub ok: bool,
    pub detail: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default = "unknown_outcome")]
    pub outcome: ExecutionOutcome,
    #[serde(default)]
    pub dispatched: bool,
    // 仅接收可信执行器的私有捕获；即使误序列化 ExecOutput，也不能把原字节发给模型。
    #[serde(default, skip_serializing)]
    pub(crate) capture: Option<RawCapture>,
}

fn unknown_outcome() -> ExecutionOutcome {
    ExecutionOutcome::Unknown
}

impl ToolCall {
    /// 这次调用**会**做什么。不执行。
    pub fn describe(&self) -> String {
        match self {
            ToolCall::RunShell { argv, cwd } => format!(
                "run {argv:?}{}",
                cwd.as_ref()
                    .map(|c| format!(" in {}", c.display()))
                    .unwrap_or_default()
            ),
            ToolCall::ReadFile { path } => format!("read {}", path.display()),
            ToolCall::SearchFile { path, query } => {
                format!("search {:?} in {}", query, path.display())
            }
            ToolCall::WriteFile { path, contents } => {
                format!("write {} bytes to {}", contents.len(), path.display())
            }
            ToolCall::DeleteFile { path } => format!("delete {}", path.display()),
        }
    }

    /// 真的做。**只应该在网关判了执行之后调用。**
    ///
    /// 这个函数自己不做任何判决，也不应该做：把判决混进执行里，就没法写一个"判了拒绝之后
    /// 文件确实还在"的测试了。
    pub fn execute(&self) -> ExecOutput {
        self.execute_with_mode(ExecutionMode::host())
    }

    pub(crate) fn platform_denial(&self, mode: ExecutionMode) -> Option<String> {
        match mode {
            ExecutionMode::Native => None,
            ExecutionMode::WindowsFailClosed => Some(format!(
                "{WINDOWS_FAIL_CLOSED_REASON}\n\n未执行：{}",
                self.describe()
            )),
        }
    }

    pub(crate) fn execute_with_mode(&self, mode: ExecutionMode) -> ExecOutput {
        self.execute_with_mode_and_cancel(mode, &|| false)
    }

    pub(crate) fn execute_with_mode_and_cancel(
        &self,
        mode: ExecutionMode,
        cancelled: &dyn Fn() -> bool,
    ) -> ExecOutput {
        if let Some(reason) = self.platform_denial(mode) {
            return ExecOutput::err(reason).with_state(ExecutionOutcome::Refused, false);
        }
        if cancelled() {
            return ExecOutput::err("客户端连接已断开，未开始执行")
                .with_state(ExecutionOutcome::Cancelled, false);
        }
        match self {
            ToolCall::RunShell { argv, cwd } => {
                run_argv_with_cancel(argv, cwd.as_deref(), EXEC_TIMEOUT, cancelled)
            }
            ToolCall::ReadFile { path } => {
                let read = read_regular(path, MAX_OUTPUT_BYTES);
                match read {
                    Err(e) => ExecOutput::err(format!("read {} 失败：{e}", path.display())),
                    Ok(bytes) => {
                        let mut detail = visible_prefix(&bytes, MAX_OUTPUT_BYTES);
                        let detail_truncated = truncate_detail(&mut detail);
                        let truncated = bytes.len() > MAX_OUTPUT_BYTES || detail_truncated;
                        ExecOutput {
                            capture: Some(RawCapture::single(
                                ContentViewOrigin::FileBytes,
                                &bytes,
                                bytes.len() <= MAX_OUTPUT_BYTES,
                            )),
                            ok: true,
                            outcome: ExecutionOutcome::Success,
                            dispatched: true,
                            detail,
                            truncated,
                        }
                    }
                }
            }
            ToolCall::SearchFile { path, query } => search_file(path, query),
            ToolCall::WriteFile { path, contents } => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        return ExecOutput::err(format!("建目录 {} 失败：{e}", parent.display()));
                    }
                }
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                let write = options.open(path).and_then(|mut file| {
                    use std::io::Write;
                    if !file.metadata()?.is_file() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "只写入普通文件，不写入管道或设备",
                        ));
                    }
                    // 先检查已打开对象，再截断；避免特殊文件阻塞或接收本次正文。
                    file.set_len(0)?;
                    file.write_all(contents.as_bytes())
                });
                match write {
                    Ok(()) => {
                        ExecOutput::ok(format!("写入 {} 字节到 {}", contents.len(), path.display()))
                    }
                    Err(e) => ExecOutput::err(format!("write {} 失败：{e}", path.display())),
                }
            }
            ToolCall::DeleteFile { path } => {
                // 只删单个文件，不递归。递归删除交给 `run_shell`，那条路径上 B0 的判决
                // 更完整（能看到 `-rf`、能看到通配符）。给一个"看起来温和"的递归删除入口，
                // 就是给一条绕过那些判决的近路。
                match std::fs::remove_file(path) {
                    Ok(()) => ExecOutput::ok(format!("已删除 {}", path.display())),
                    Err(e) => ExecOutput::err(format!("delete {} 失败：{e}", path.display())),
                }
            }
        }
    }
}

fn read_regular(path: &std::path::Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "只读取普通文件，不读取管道或设备",
        ));
    }
    let mut bytes = Vec::with_capacity(limit.min(MAX_OUTPUT_BYTES) + 1);
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// 单文件字面搜索。查询串从不经过 shell，也不作为动作或路径参数推断。
fn search_file(path: &std::path::Path, query: &str) -> ExecOutput {
    const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;
    if query.is_empty() || query.len() > 1024 || query.contains(['\r', '\n']) {
        return ExecOutput::err("query 必须是 1–1024 字节的单行字面文本");
    }
    let bytes = match read_regular(path, MAX_SCAN_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return ExecOutput::err(format!("search {} 失败：{error}", path.display())),
    };
    let mut truncated = bytes.len() > MAX_SCAN_BYTES;
    let text = visible_prefix(&bytes, MAX_SCAN_BYTES);
    let mut detail = String::new();
    let mut matches = 0;
    for (index, line) in text.lines().enumerate() {
        if !line.contains(query) {
            continue;
        }
        if matches == 200 || detail.len() >= MAX_OUTPUT_BYTES {
            truncated = true;
            break;
        }
        matches += 1;
        detail.push_str(&format!("{}:{line}\n", index + 1));
        if truncate_detail(&mut detail) {
            truncated = true;
            break;
        }
    }
    ExecOutput {
        capture: Some(RawCapture::single(
            ContentViewOrigin::FileBytes,
            &bytes,
            bytes.len() <= MAX_SCAN_BYTES,
        )),
        ok: true,
        outcome: ExecutionOutcome::Success,
        dispatched: true,
        detail,
        truncated,
    }
}

impl ExecOutput {
    pub(crate) fn ok(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            capture: Some(RawCapture::single(
                ContentViewOrigin::ToolText,
                detail.as_bytes(),
                true,
            )),
            ok: true,
            outcome: ExecutionOutcome::Success,
            dispatched: true,
            detail,
            truncated: false,
        }
    }
    pub(crate) fn err(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            capture: Some(RawCapture::single(
                ContentViewOrigin::ToolText,
                detail.as_bytes(),
                true,
            )),
            ok: false,
            outcome: ExecutionOutcome::Failed,
            dispatched: true,
            detail,
            truncated: false,
        }
    }

    pub(crate) fn with_state(mut self, outcome: ExecutionOutcome, dispatched: bool) -> Self {
        self.outcome = outcome;
        self.dispatched = dispatched;
        self
    }
}

/// 读到上限后继续排空管道，但不继续积累内存，避免将内存上限变成管道死锁。
#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
    incomplete: bool,
}

fn capture(mut reader: impl Read, deadline: Instant, limit: usize) -> Captured {
    let mut result = Captured::default();
    let mut chunk = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            result.incomplete = true;
            return result;
        }
        match reader.read(&mut chunk) {
            Ok(0) => return result,
            Ok(n) => {
                let take = n.min(limit.saturating_sub(result.bytes.len()));
                result.bytes.extend_from_slice(&chunk[..take]);
                result.truncated |= take < n;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                result.incomplete = true;
                return result;
            }
        }
    }
}

fn truncate_detail(detail: &mut String) -> bool {
    truncate_detail_to(detail, MAX_OUTPUT_BYTES)
}

fn truncate_detail_to(detail: &mut String, limit: usize) -> bool {
    if detail.len() <= limit {
        return false;
    }
    let mut cut = limit;
    while !detail.is_char_boundary(cut) {
        cut -= 1;
    }
    detail.truncate(cut);
    true
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // fd 由仍存活的 ChildStdout/ChildStderr 持有；这里只修改该管道的读取标志。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn stop_group(pid: u32) -> bool {
    // Command::process_group(0) 为本次命令单独建组，不给用户的终端进程组发信号。
    // 只清理未自行脱离进程组的后代；这不是系统沙箱。
    unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) == 0 }
}

#[cfg(test)]
fn run_argv(argv: &[String], cwd: Option<&std::path::Path>) -> ExecOutput {
    run_argv_with_timeout(argv, cwd, EXEC_TIMEOUT)
}

#[cfg(test)]
fn run_argv_with_timeout(
    argv: &[String],
    cwd: Option<&std::path::Path>,
    timeout: Duration,
) -> ExecOutput {
    run_argv_with_cancel(argv, cwd, timeout, &|| false)
}

fn run_argv_with_cancel(
    argv: &[String],
    cwd: Option<&std::path::Path>,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
) -> ExecOutput {
    let Some((program, rest)) = argv.split_first() else {
        return ExecOutput::err("argv 为空").with_state(ExecutionOutcome::Refused, false);
    };
    let mut cmd = Command::new(program);
    cmd.args(rest);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    run_command_with_cancel(cmd, timeout, cancelled)
}

/// 复用限时、取消和有界输出；容器生命周期由隔离后端另行清理。
pub(crate) fn run_command_with_cancel(
    cmd: Command,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
) -> ExecOutput {
    run_command_bounded(cmd, timeout, cancelled, MAX_OUTPUT_BYTES)
}

pub(crate) fn run_command_bounded(
    mut cmd: Command,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
    output_limit: usize,
) -> ExecOutput {
    let program = cmd.get_program().to_string_lossy().into_owned();
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ExecOutput::err(format!("启动 {program:?} 失败：{error}"))
                .with_state(ExecutionOutcome::Failed, false)
        }
    };
    let stdout = child.stdout.take().expect("stdout 已配置管道");
    let stderr = child.stderr.take().expect("stderr 已配置管道");
    #[cfg(unix)]
    if let Err(error) = nonblocking(&stdout).and_then(|_| nonblocking(&stderr)) {
        stop_group(child.id());
        let _ = child.kill();
        let _ = child.wait();
        return ExecOutput::err(format!(
            "无法建立限时输出读取：{error}；命令结果需核实，不自动重试"
        ))
        .with_state(ExecutionOutcome::Unknown, true);
    }
    let deadline = Instant::now() + timeout;
    let out_h = std::thread::spawn(move || capture(stdout, deadline, output_limit));
    let err_h = std::thread::spawn(move || capture(stderr, deadline, output_limit));
    let mut failed = None;
    let status = loop {
        if cancelled() {
            failed = Some((
                "客户端已断开，已停止本次命令；已发生的结果需核实，不自动重试".into(),
                ExecutionOutcome::Cancelled,
            ));
            break None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(error) => {
                failed = Some((
                    format!("等待子进程失败：{error}"),
                    ExecutionOutcome::Unknown,
                ));
                break None;
            }
            Ok(None) if Instant::now() >= deadline => {
                failed = Some((
                    format!("超过 {timeout:?} 未结束，已停止本次命令；结果未知，不自动重试"),
                    ExecutionOutcome::TimedOut,
                ));
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    #[cfg(unix)]
    let remaining_group = stop_group(child.id());
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // Unix 读取端非阻塞且有相同 deadline，后代继承管道也不能无限卡住 join。
    // Windows 的生产执行模式仍全部拒绝；不能把这条 Unix 边界声称为 Windows 支持。
    let stdout = out_h.join().unwrap_or_else(|_| Captured {
        incomplete: true,
        ..Default::default()
    });
    let stderr = err_h.join().unwrap_or_else(|_| Captured {
        incomplete: true,
        ..Default::default()
    });
    if let Some((reason, outcome)) = failed {
        return ExecOutput::err(reason).with_state(outcome, true);
    }
    #[cfg(unix)]
    if remaining_group {
        return ExecOutput::err("命令退出后仍有同组子进程，已清理；结果需核实，不自动重试")
            .with_state(ExecutionOutcome::Unknown, true);
    }
    if stdout.incomplete || stderr.incomplete {
        return ExecOutput::err("输出未能在期限内完整收集；结果需核实，不自动重试")
            .with_state(ExecutionOutcome::Unknown, true);
    }
    let mut detail = crate::content::visible_text(&stdout.bytes, stdout.truncated);
    if !stderr.bytes.is_empty() {
        detail.push_str("\n--- stderr ---\n");
        detail.push_str(&crate::content::visible_text(
            &stderr.bytes,
            stderr.truncated,
        ));
    }
    let detail_truncated = truncate_detail_to(&mut detail, output_limit);
    ExecOutput {
        capture: (output_limit == MAX_OUTPUT_BYTES).then(|| RawCapture {
            version: 1,
            streams: vec![
                CapturedStream::new(ContentViewOrigin::Stdout, &stdout.bytes, !stdout.truncated),
                CapturedStream::new(ContentViewOrigin::Stderr, &stderr.bytes, !stderr.truncated),
            ],
        }),
        ok: status.is_some_and(|status| status.success()),
        outcome: if status.is_some_and(|status| status.success()) {
            ExecutionOutcome::Success
        } else {
            ExecutionOutcome::Failed
        },
        dispatched: true,
        detail,
        truncated: stdout.truncated || stderr.truncated || detail_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 文件返回后被改写也不会重新读取路径来伪造原始摘要() {
        let root = tempfile_dir("same-read-capture");
        let path = root.join("input.txt");
        let original = "实际读取的中文正文 👩‍💻";
        std::fs::write(&path, original).unwrap();
        let mut output =
            ToolCall::ReadFile { path: path.clone() }.execute_with_mode(ExecutionMode::Native);
        assert!(output.ok);
        std::fs::write(&path, "工具已经返回后的另一个内容").unwrap();
        let capture = output.capture.take().unwrap();
        let mut sources = crate::provenance::SourceCollector::default();
        let source = sources
            .captured_output(
                &capture,
                &output.detail,
                guard_schema::SourceEntryPoint::FileRead,
                true,
            )
            .unwrap();
        let views = source.content_views.unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(
            views.raw[0].digest.sha256.as_str(),
            format!("{:x}", Sha256::digest(original.as_bytes()))
        );
        assert_eq!(output.detail, original);
        assert_ne!(std::fs::read_to_string(&path).unwrap(), output.detail);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_fail_closed_mode_blocks_every_side_effect_before_it_happens() {
        let dir = tempfile_dir("windows-fail-closed");
        let existing = dir.join("existing.txt");
        let missing = dir.join("missing.txt");
        std::fs::write(&existing, "secret-canary").unwrap();

        let calls = [
            ToolCall::ReadFile {
                path: existing.clone(),
            },
            ToolCall::SearchFile {
                path: existing.clone(),
                query: "secret".into(),
            },
            ToolCall::WriteFile {
                path: missing.clone(),
                contents: "must-not-land".into(),
            },
            ToolCall::DeleteFile {
                path: existing.clone(),
            },
            ToolCall::RunShell {
                argv: vec!["definitely-not-launched-by-agentguard".into()],
                cwd: Some(dir.clone()),
            },
        ];
        for call in calls {
            let output = call.execute_with_mode(ExecutionMode::WindowsFailClosed);
            assert!(!output.ok, "Windows fail-closed call executed: {call:?}");
            assert!(
                output.detail.contains("disabled_fail_closed")
                    || output.detail.contains("失败关闭"),
                "denial did not explain the Windows posture: {}",
                output.detail
            );
            assert!(
                !output.detail.contains("secret-canary"),
                "denied read leaked file content"
            );
        }
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "secret-canary");
        assert!(!missing.exists(), "denied write created its target");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn tempfile_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "agentguard-exec-{tag}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        path
    }

    /// 用当前测试二进制充当可控的子进程，避免测试本身依赖 `/bin/sh`、`printf` 或
    /// PowerShell。这样 Unix 和 Windows 跑的是同一条 `Command::new(argv[0]).args(...)`
    /// 执行路径，也能精确控制 stdout、stderr 和退出码。
    fn child(mode: &str, count: usize, exit_code: i32) -> ExecOutput {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let dir = std::env::temp_dir().join(format!(
            "agentguard-exec-test-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).expect("创建子进程测试目录");
        std::fs::write(dir.join("mode"), format!("{mode}\n{count}\n{exit_code}\n"))
            .expect("写子进程测试参数");

        let executable = std::env::current_exe().expect("取得当前测试二进制路径");
        let output = run_argv(
            &[
                executable.to_string_lossy().into_owned(),
                "--exact".to_string(),
                "exec::tests::可控子进程".to_string(),
                "--ignored".to_string(),
                "--nocapture".to_string(),
                "--quiet".to_string(),
            ],
            Some(&dir),
        );

        std::fs::remove_dir_all(&dir).expect("清理子进程测试目录");
        output
    }

    /// 只由 [`child`] 精确点名运行。直接跑 ignored tests 时没有 `mode` 文件，会正常返回，
    /// 不会用 `process::exit` 提前终止整组测试。
    #[test]
    #[ignore]
    fn 可控子进程() {
        use std::io::Write;

        let Ok(spec) = std::fs::read_to_string("mode") else {
            return;
        };
        let mut lines = spec.lines();
        let mode = lines.next().expect("缺少输出模式");
        let count = lines
            .next()
            .expect("缺少输出长度")
            .parse::<usize>()
            .expect("输出长度不是整数");
        let exit_code = lines
            .next()
            .expect("缺少退出码")
            .parse::<i32>()
            .expect("退出码不是整数");

        match mode {
            "stdout-ascii" => std::io::stdout()
                .lock()
                .write_all(&vec![b'a'; count])
                .expect("写 stdout"),
            "stderr-ascii" => std::io::stderr()
                .lock()
                .write_all(&vec![b'e'; count])
                .expect("写 stderr"),
            "stdout-utf8" => std::io::stdout()
                .lock()
                .write_all("中".repeat(count).as_bytes())
                .expect("写 UTF-8 stdout"),
            "mixed-boundary" => {
                std::io::stdout()
                    .lock()
                    .write_all(&vec![b'a'; count])
                    .expect("写边界 stdout");
                std::io::stderr()
                    .lock()
                    .write_all("中".repeat(10_000).as_bytes())
                    .expect("写边界 stderr");
            }
            "sleep-marker" => {
                std::fs::write("ready", "ready").expect("标记子进程已启动");
                std::thread::sleep(Duration::from_millis(count as u64));
                std::fs::write("finished", "不应在清理后继续执行").expect("写测试标记");
            }
            "spawn-holder" => {
                let holder = std::env::current_dir().unwrap().join("holder");
                std::fs::create_dir(&holder).unwrap();
                std::fs::write(holder.join("mode"), "sleep-marker\n1000\n0\n").unwrap();
                // 故意让父进程先退出，复现后代持有输出管道；被测执行器负责终止该进程组。
                #[allow(clippy::zombie_processes)]
                let _holder = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "exec::tests::可控子进程",
                        "--ignored",
                        "--nocapture",
                        "--quiet",
                    ])
                    .current_dir(&holder)
                    .spawn()
                    .expect("启动继承管道的后代");
                let deadline = Instant::now() + Duration::from_secs(2);
                while !holder.join("ready").exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(holder.join("ready").exists());
            }
            "none" => {}
            other => panic!("未知子进程测试模式：{other}"),
        }
        std::io::stdout().flush().expect("刷新 stdout");
        std::io::stderr().flush().expect("刷新 stderr");
        std::process::exit(exit_code);
    }

    /// 在非字符边界上截断输出**不能** panic。
    ///
    /// 复核实测:65519 字节 ASCII stdout + 16 字节 stderr 头 = 65535,stderr 首字符是
    /// 3 字节 UTF-8,于是第 65536 字节落在字符内部,`String::truncate` 断言失败:
    ///
    /// ```text
    /// panicked at exec.rs:188: assertion failed: self.is_char_boundary(new_len)
    /// exit=101
    /// ```
    ///
    /// 而网关的事件循环**就是** main,所以进程直接死,智能体连响应都收不到 —— 一次被
    /// 批准的 `run_shell` 就能把整个协作式网关关掉,不需要人参与。非 ASCII 的子进程输出
    /// 对本项目是常态(规则、日志、报错本身都是中文),这不是边角情况。
    ///
    /// 可控子进程先写 60,000 字节 ASCII，再向 stderr 写足量三字节字符。
    /// 连续改变三个 ASCII 长度，不管 Unix/Windows 的 libtest 标头和换行多长，
    /// 都会有一次让 64 KiB 上限落在 UTF-8 字符内部。
    #[test]
    fn 非字符边界上的截断不panic() {
        for n in 60_000usize..=60_002 {
            let o = child("mixed-boundary", n, 0);
            assert!(o.truncated, "n={n} 的混合输出应当触发截断");
            assert!(o.detail.len() <= MAX_OUTPUT_BYTES, "n={n} 截断后仍超过上限");
            // 真正的断言是"没 panic 到这里" —— 加一条内容检查,免得将来有人用
            // `detail.clear()` 让这条测试变成永远通过。
            assert!(o.detail.contains("aaaa"), "n={n} 输出内容不对");
        }
    }

    /// 截断必须落在字符边界上,而且切出来的仍然是合法 UTF-8。
    #[test]
    fn 截断结果是合法utf8() {
        let o = child("stdout-utf8", 40_000, 0);
        assert!(o.truncated, "40000 个三字节字符应当超过上限");
        assert!(o.detail.len() <= MAX_OUTPUT_BYTES);
        // String 本身保证 UTF-8;这里钉住的是"没有在中途丢字符导致内容为空"。
        assert!(o.detail.ends_with('中'), "截断切开了一个字符");
    }

    /// 输出超过管道容量时**不能**死锁到超时。
    ///
    /// 旧代码先在 `try_wait()` 上轮询等子进程退出,退出之后才 `wait_with_output()` 去读
    /// 管道。写满 64 KiB(Linux 默认管道容量)的子进程阻塞在 write 上、永不退出,于是必然
    /// 走到 30 秒 `EXEC_TIMEOUT`:
    ///
    /// ```text
    /// 60000 字节 -> ok=true  2.77ms
    /// 70000 字节 -> ok=false 30.008 秒  detail="超过 30s 未结束，已杀掉"
    /// ```
    ///
    /// 三个后果:一次**成功**的命令被错报成失败;`MAX_OUTPUT_BYTES` 这条上限在 stdout
    /// 这条路上根本到不了(死锁先发生);而执行是同步单线程的,所以一次调用把全部判决
    /// 停住 30 秒 —— 成本极低的拒绝服务。
    #[test]
    fn 输出超过管道容量不死锁() {
        let t = std::time::Instant::now();
        let o = child("stdout-ascii", 200_000, 0);
        let dt = t.elapsed();
        assert!(o.ok, "一次成功的命令被错报成失败:{}", o.detail);
        assert!(
            dt < std::time::Duration::from_secs(10),
            "耗时 {dt:?} —— 说明还在等超时,管道没有被并发排空"
        );
        assert!(o.truncated, "200000 字节应当触发截断");
        assert_eq!(
            o.detail.len(),
            MAX_OUTPUT_BYTES,
            "既然没死锁,就应该真的到达输出上限"
        );
    }

    /// stderr 也要被排空,否则只写 stderr 的命令同样死锁。
    #[test]
    fn stderr超过管道容量也不死锁() {
        let t = std::time::Instant::now();
        let o = child("stderr-ascii", 200_000, 0);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "stderr 没有被并发排空"
        );
        assert!(o.detail.contains("--- stderr ---"));
    }

    /// 退出码仍然如实反映 —— 并发读不能把失败读成成功。
    #[test]
    fn 退出码未被并发读改变() {
        assert!(child("none", 0, 0).ok);
        assert!(!child("none", 0, 1).ok);
        assert!(!child("stdout-ascii", 200_000, 3).ok);
    }
    #[test]
    fn 大输出在读取期间就限制缓存且仍完整排空() {
        let source = std::io::repeat(b'x').take((MAX_OUTPUT_BYTES * 128) as u64);
        let got = capture(
            source,
            Instant::now() + Duration::from_secs(5),
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(got.bytes.len(), MAX_OUTPUT_BYTES);
        assert!(got.truncated);
        assert!(!got.incomplete);
        assert!(got.bytes.iter().all(|byte| *byte == b'x'));
    }

    #[test]
    fn 大文件及无效字符读取仍受输出上限约束() {
        let dir = tempfile_dir("bounded-file");
        let path = dir.join("large.bin");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(256 * 1024 * 1024)
            .unwrap();
        let result =
            ToolCall::ReadFile { path: path.clone() }.execute_with_mode(ExecutionMode::Native);
        assert!(result.ok && result.truncated);
        assert_eq!(result.detail.len(), MAX_OUTPUT_BYTES);
        std::fs::write(&path, vec![0xff; MAX_OUTPUT_BYTES + 100]).unwrap();
        let result = ToolCall::ReadFile { path }.execute_with_mode(ExecutionMode::Native);
        assert!(result.ok && result.truncated);
        assert!(result.detail.len() <= MAX_OUTPUT_BYTES);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn 字面搜索只返回匹配行且有扫描和输出上限() {
        let dir = tempfile_dir("search-file");
        let path = dir.join("source.txt");
        std::fs::write(&path, "首行\nwrite_file || && $(literal)\n末行\n").unwrap();
        for query in ["write_file", "||", "&&", "$(literal)"] {
            let output = search_file(&path, query);
            assert!(output.ok && !output.truncated);
            assert_eq!(output.detail, "2:write_file || && $(literal)\n");
        }
        assert_eq!(search_file(&path, "不存在").detail, "");
        for query in ["", "两\n行", "两\r行", &"x".repeat(1025)] {
            assert!(!search_file(&path, query).ok);
        }
        std::fs::write(&path, "匹配\n".repeat(201)).unwrap();
        let output = search_file(&path, "匹配");
        assert!(output.ok && output.truncated);
        assert_eq!(output.detail.lines().count(), 200);
        std::fs::write(&path, "中".repeat(MAX_OUTPUT_BYTES)).unwrap();
        let output = search_file(&path, "中");
        assert!(output.truncated && output.detail.len() <= MAX_OUTPUT_BYTES);
        std::fs::File::create(&path)
            .unwrap()
            .set_len(8 * 1024 * 1024)
            .unwrap();
        let output = search_file(&path, "不在扫描范围");
        assert!(output.ok && output.truncated && output.detail.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 命名管道不会让文件读写工具无限阻塞() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile_dir("fifo");
        let path = dir.join("input.fifo");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        let result =
            ToolCall::ReadFile { path: path.clone() }.execute_with_mode(ExecutionMode::Native);
        assert!(!result.ok);
        assert!(result.detail.contains("普通文件"));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!search_file(&path, "不可阻塞").ok);
        let start = Instant::now();
        let result = ToolCall::WriteFile {
            path,
            contents: "不得发出".into(),
        }
        .execute_with_mode(ExecutionMode::Native);
        assert!(!result.ok);
        assert!(start.elapsed() < Duration::from_secs(2));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 命令退出后继承管道的后代被清理而非挂住网关() {
        let dir = tempfile_dir("inherited-pipe");
        std::fs::write(dir.join("mode"), "spawn-holder\n0\n0\n").unwrap();
        let argv = vec![
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            "--exact".into(),
            "exec::tests::可控子进程".into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--quiet".into(),
        ];
        let start = Instant::now();
        let output = run_argv_with_timeout(&argv, Some(&dir), Duration::from_secs(3));
        assert!(!output.ok, "遗留后台后代不能报告同步命令成功");
        assert!(output.detail.contains("同组子进程"));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(dir.join("holder/ready").exists());
        assert!(!dir.join("holder/finished").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn 超时结束命令且下一调用可继续完成() {
        let dir = tempfile_dir("deadline");
        std::fs::write(dir.join("mode"), "sleep-marker\n2000\n0\n").unwrap();
        let argv = vec![
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            "--exact".into(),
            "exec::tests::可控子进程".into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--quiet".into(),
        ];
        let start = Instant::now();
        let output = run_argv_with_timeout(&argv, Some(&dir), Duration::from_millis(250));
        assert!(!output.ok);
        assert!(output.detail.contains("超过"));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!dir.join("finished").exists());
        std::fs::remove_dir_all(dir).unwrap();
        assert!(child("stdout-ascii", 128, 0).ok);
    }
}
