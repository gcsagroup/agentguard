//! B2 的验收测试：**内核**是否真的拒绝了越界写。
//!
//! # 为什么必须是集成测试
//!
//! 约束在 `pre_exec` 里落下，也就是在 `fork` 之后、`exec` 之前。要验证它，必须真的起一个进程
//! 并从**外面**看文件系统。单元测试做不到这件事，而"只断言 launch() 返回了 Ok"和这个项目
//! 反复抓到的那种缺陷是同一形状：机制存在、被直接测过、然后什么都没真的发生。
//!
//! 所以每条测试都从 jail 外面用 `Path::exists()` 核对结果。
//!
//! # 没有后端的机器上会跳过
//!
//! 跳过而不是假通过，并且**打印跳过的原因**。一个在 CI 上静默跳过的安全测试，和一个不存在
//! 的测试没有区别。

use std::path::{Path, PathBuf};
use std::process::Command;

const JAIL: &str = env!("CARGO_BIN_EXE_agentguard-jail");

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("ag-jail-it-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("out")).expect("建临时目录");
        Self(std::fs::canonicalize(&p).unwrap_or(p))
    }
    fn path(&self) -> &Path {
        &self.0
    }
    /// 一份把 `<tmp>` 设为可读、`<tmp>/out` 设为可写的计划库。
    fn plans(&self) -> PathBuf {
        let f = self.0.join("plans.yaml");
        std::fs::write(
            &f,
            format!(
                "require_plan: false\nplans:\n  - task_profile: jailed\n    goal: \"约束验证\"\n\
                 \x20   allow: [app_switch, run_shell]\n    max: {{run_shell: 9}}\n\
                 \x20   scope:\n      paths: {{read: [\"{ws}\"], write: [\"{ws}/out\"]}}\n",
                ws = self.0.display()
            ),
        )
        .expect("写计划库");
        f
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 这台机器有没有可用后端。没有就跳过，并说明原因。
fn backend_or_skip() -> bool {
    let out = Command::new(JAIL)
        .arg("--probe")
        .output()
        .expect("跑 --probe");
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("没有可用后端") {
        eprintln!("跳过：这台机器没有可用的约束后端。--probe 输出：\n{text}");
        return false;
    }
    true
}

/// 在约束下跑一条 sh 命令，返回退出码。
fn jailed_sh(tmp: &Tmp, script: &str) -> i32 {
    let out = Command::new(JAIL)
        .args(["--plans"])
        .arg(tmp.plans())
        .args(["--task", "jailed", "--", "/bin/sh", "-c", script])
        .output()
        .expect("起 jail");
    out.status.code().unwrap_or(-1)
}

#[test]
fn 授权内的写成功并且从_jail_外面可见() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("inside");
    let target = tmp.path().join("out/ok.txt");
    let code = jailed_sh(&tmp, &format!("echo inside > {}", target.display()));
    assert_eq!(code, 0, "授权内的写应当成功");
    // 从 jail 外面看。这一半才是重点：只看退出码的话，一个什么都没做的 jail 也能通过。
    assert_eq!(
        std::fs::read_to_string(&target)
            .expect("读回写入的文件")
            .trim(),
        "inside"
    );
}

#[test]
fn 写授权外被内核拒绝() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("outside");
    // 授权是 <tmp>/out，这里写 <tmp> 本身——只读。
    let escape = tmp.path().join("escape.txt");
    let code = jailed_sh(&tmp, &format!("echo x > {} 2>/dev/null", escape.display()));
    assert_ne!(code, 0, "越界写应当失败");
    assert!(!escape.exists(), "越界文件被创建了 —— 内核没有在拦");
}

#[test]
fn 写系统目录被内核拒绝() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("etc");
    let marker = "/etc/ag-jail-it-marker";
    let code = jailed_sh(&tmp, &format!("echo x > {marker} 2>/dev/null"));
    assert_ne!(code, 0, "写 /etc 应当失败");
    assert!(!Path::new(marker).exists(), "/etc 被写了");
}

#[test]
fn 删系统文件被内核拒绝() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("rm-etc");
    // /etc/hosts 一定存在，而且删掉它是一次真实的破坏。
    assert!(
        Path::new("/etc/hosts").exists(),
        "前置条件：/etc/hosts 应当存在"
    );
    let code = jailed_sh(&tmp, "rm -f /etc/hosts 2>/dev/null");
    assert_ne!(code, 0, "删 /etc/hosts 应当失败");
    assert!(
        Path::new("/etc/hosts").exists(),
        "/etc/hosts 被删了 —— 内核没有在拦"
    );
}

#[test]
fn 写家目录下的凭据目录被内核拒绝() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("ssh");
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("跳过：没有 HOME");
        return;
    };
    let marker = home.join(".ssh/ag-jail-it-marker");
    let code = jailed_sh(
        &tmp,
        &format!(
            "mkdir -p {} 2>/dev/null && echo k > {} 2>/dev/null",
            home.join(".ssh").display(),
            marker.display()
        ),
    );
    assert_ne!(code, 0, "写 ~/.ssh 应当失败");
    assert!(!marker.exists(), "~/.ssh 被写了");
}

#[test]
fn 读仍然是允许的() {
    // 反面用例。没有这一条，上面所有 assert_ne!(code, 0) 都可能只是"这个 jail 里什么都跑不起来"。
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("read");
    assert_eq!(
        jailed_sh(&tmp, "head -c 1 /etc/hosts > /dev/null"),
        0,
        "读 /etc/hosts 应当允许"
    );
    assert_eq!(jailed_sh(&tmp, "/bin/ls / > /dev/null"), 0, "ls / 应当能跑");
}

#[test]
fn 没有天花板时是整个文件系统只读而不是不约束() {
    if !backend_or_skip() {
        return;
    }
    let tmp = Tmp::new("noplan");
    // 不给 --plans。
    let marker = tmp.path().join("out/should-not-exist.txt");
    let out = Command::new(JAIL)
        .args(["--", "/bin/sh", "-c"])
        .arg(format!("echo x > {} 2>/dev/null", marker.display()))
        .output()
        .expect("起 jail");
    assert_ne!(out.status.code().unwrap_or(-1), 0, "没有天花板时应当是只读");
    assert!(!marker.exists(), "没有天花板时仍然能写 —— 默认方向反了");
}

#[test]
fn 矛盾的_profile_下一个进程都不会启动() {
    // 写授权落在 /etc 上：这不是配置疏忽，是把约束的意义抵消掉。必须拒绝启动，
    // 而不是"尽力执行"——部分生效的约束在使用者看来和完全生效没有区别。
    let tmp = Tmp::new("contradiction");
    let plans = tmp.path().join("bad.yaml");
    std::fs::write(
        &plans,
        "require_plan: false\nplans:\n  - task_profile: bad\n    goal: \"矛盾\"\n\
         \x20   allow: [app_switch]\n    scope:\n      paths: {write: [\"/etc\"]}\n",
    )
    .expect("写计划库");
    let marker = tmp.path().join("out/ran.txt");
    let out = Command::new(JAIL)
        .args(["--plans"])
        .arg(&plans)
        .args(["--task", "bad", "--", "/bin/sh", "-c"])
        .arg(format!("echo ran > {}", marker.display()))
        .output()
        .expect("起 jail");
    assert_ne!(
        out.status.code().unwrap_or(-1),
        0,
        "矛盾的 profile 应当拒绝启动"
    );
    assert!(
        !marker.exists(),
        "矛盾的 profile 下进程仍然跑了 —— 拒绝启动没有生效"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("矛盾") || err.contains("敏感"),
        "要说清为什么：{err}"
    );
}

#[test]
fn probe_对每个不可用的后端都给出理由() {
    let out = Command::new(JAIL)
        .arg("--probe")
        .output()
        .expect("跑 --probe");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines().filter(|l| l.contains("不可用")) {
        // 行尾必须有理由，否则"不可用"和"没检查"分不开。
        let after = line.split("不可用").nth(1).unwrap_or("").trim();
        assert!(!after.is_empty(), "不可用但没给理由：{line}");
    }
}
