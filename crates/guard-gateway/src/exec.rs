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

    // 管道要**并发**排空,不能"先等退出再读"。
    //
    // 旧代码在 `try_wait()` 上轮询,只有子进程退出之后才 `wait_with_output()` 去读管道。
    // 但一个写满管道缓冲区(Linux 默认 64 KiB)的子进程会阻塞在 write 上、永远不退出,
    // 于是必然走到 30 秒超时被杀。两个后果都被实测出来:
    //
    //   * 60000 字节 stdout -> 2.7ms,ok=true;70000 字节 -> **30.008 秒**,ok=false,
    //     detail="超过 30s 未结束,已杀掉"。一次**成功**的命令被错报成超时失败。
    //   * `MAX_OUTPUT_BYTES`(那条"输出上限")在 stdout 这条路上根本到不了 —— 死锁先
    //     发生在 64 KiB。文档承诺的截断保护是空的。
    //   * 而且执行是同步单线程的,所以一次这样的调用把**全部**判决停住 30 秒。一次调用
    //     换 30 秒,成本极低。
    //
    // 两个读线程各自 `read_to_end`,主线程照旧轮询超时。读线程在子进程被杀、管道关闭后
    // 自然结束,所以超时路径也不会泄漏线程。
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let out_h = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stdout_pipe.as_mut() {
            let _ = std::io::Read::read_to_end(p, &mut buf);
        }
        buf
    });
    let err_h = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stderr_pipe.as_mut() {
            let _ = std::io::Read::read_to_end(p, &mut buf);
        }
        buf
    });

    let deadline = std::time::Instant::now() + EXEC_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Err(e) => return ExecOutput::err(format!("等待子进程失败：{e}")),
            Ok(Some(st)) => break st,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ExecOutput::err(format!("超过 {EXEC_TIMEOUT:?} 未结束，已杀掉"));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    };
    let stdout_bytes = out_h.join().unwrap_or_default();
    let stderr_bytes = err_h.join().unwrap_or_default();

    let mut detail = String::new();
    detail.push_str(&String::from_utf8_lossy(&stdout_bytes));
    if !stderr_bytes.is_empty() {
        detail.push_str("\n--- stderr ---\n");
        detail.push_str(&String::from_utf8_lossy(&stderr_bytes));
    }
    let truncated = detail.len() > MAX_OUTPUT_BYTES;
    if truncated {
        // `String::truncate` panics unless the new length is a char boundary, and this
        // string is built from `from_utf8_lossy` of arbitrary child-process output, so the
        // cap lands mid-character whenever the byte at the boundary is a continuation.
        // 65519 bytes of ASCII stdout plus the 16-byte stderr header puts the cut exactly
        // inside a multi-byte character, and the gateway's event loop *is* `main`: the
        // process died with exit 101 and the agent never even received a response. Non-ASCII
        // child output is the norm here — the rules, the logs and the error strings are all
        // Chinese. `ReadFile` already gets this right (slice bytes, then `from_utf8_lossy`);
        // this path did not.
        let mut cut = MAX_OUTPUT_BYTES;
        while cut > 0 && !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
    }
    ExecOutput {
        ok: status.success(),
        detail,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
