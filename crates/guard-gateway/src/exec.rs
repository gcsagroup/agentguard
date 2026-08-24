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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

/// 单次执行的输出上限，防止一条 `cat` 把整个 MCP 通道塞满。
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// 执行的墙钟上限。超时**杀掉**子进程并报错，而不是无限等——一个卡住的工具调用会让整个
/// MCP 会话停在那里，而智能体只会看到"没有响应"。
pub const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
        match self {
            ToolCall::RunShell { argv, cwd } => run_argv(argv, cwd.as_deref()),
            ToolCall::ReadFile { path } => match std::fs::read(path) {
                Err(e) => ExecOutput::err(format!("read {} 失败：{e}", path.display())),
                Ok(bytes) => {
                    let truncated = bytes.len() > MAX_OUTPUT_BYTES;
                    let slice = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
                    ExecOutput {
                        ok: true,
                        detail: String::from_utf8_lossy(slice).into_owned(),
                        truncated,
                    }
                }
            },
            ToolCall::WriteFile { path, contents } => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        return ExecOutput::err(format!("建目录 {} 失败：{e}", parent.display()));
                    }
                }
                match std::fs::write(path, contents) {
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

impl ExecOutput {
    fn ok(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: detail.into(),
            truncated: false,
        }
    }
    fn err(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
            truncated: false,
        }
    }
}

fn run_argv(argv: &[String], cwd: Option<&std::path::Path>) -> ExecOutput {
    let Some((program, rest)) = argv.split_first() else {
        return ExecOutput::err("argv 为空");
    };
    let mut cmd = Command::new(program);
    cmd.args(rest);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    // stdin 关掉：一个等输入的子进程会挂住整个 MCP 会话，而智能体只看到没有响应。
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ExecOutput::err(format!("启动 {program:?} 失败：{e}")),
    };

    // 简单的超时轮询。没引 tokio，因为这个 crate 其余部分是同步的，为一个 wait 引入
    // 整个运行时会把依赖面扩大得不成比例。
    let deadline = std::time::Instant::now() + EXEC_TIMEOUT;
    loop {
        match child.try_wait() {
            Err(e) => return ExecOutput::err(format!("等待子进程失败：{e}")),
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ExecOutput::err(format!("超过 {EXEC_TIMEOUT:?} 未结束，已杀掉"));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return ExecOutput::err(format!("收集子进程输出失败：{e}")),
    };
    let mut detail = String::new();
    detail.push_str(&String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        detail.push_str("\n--- stderr ---\n");
        detail.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    let truncated = detail.len() > MAX_OUTPUT_BYTES;
    if truncated {
        detail.truncate(MAX_OUTPUT_BYTES);
    }
    ExecOutput {
        ok: out.status.success(),
        detail,
        truncated,
    }
}
