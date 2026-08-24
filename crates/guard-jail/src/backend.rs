//! 后端：谁来执行这份 profile，以及在没人能执行时会发生什么。
//!
//! # 强度不是一回事，所以要排序
//!
//! | 后端 | 需要什么 | 强度 |
//! |---|---|---|
//! | Landlock | 内核 5.13+，且 `landlock_*` 系统调用没被上层 seccomp 挡掉 | 按进程、不改变文件系统视图、不需要任何特权 |
//! | mount namespace | user + mount namespace 可用 | 强，但改变进程看到的文件系统 |
//! | 无 | — | **拒绝启动** |
//!
//! # 最重要的一条：没有后端就不启动
//!
//! 这是整个 crate 唯一不能搞错方向的地方。一个"约束不了就不约束地跑"的 jail，比没有 jail
//! 更糟：使用者以为进程被关住了。所以 [`Backend::best_available`] 返回 `None` 时，
//! [`crate::launch`] 返回错误而**不启动任何进程**。
//!
//! 写这段时的环境本身就是这条规则的测试场：这个容器的内核是 6.18（Landlock 早就有了），但
//! `landlock_create_ruleset` 返回 `ENOSYS`，因为上层 seccomp 把它挡掉了。也就是说"内核版本
//! 够"和"这个机制可用"是两件事，只查版本号的探测会给出错的答案。

use serde::{Deserialize, Serialize};

/// 一个可用的约束后端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Landlock,
    MountNamespace,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Landlock => "landlock",
            Backend::MountNamespace => "mount_namespace",
        }
    }

    /// 强度排序，数字大的优先。
    ///
    /// Landlock 优先不是因为它更强，而是因为它**不改变进程看到的文件系统**。mount namespace
    /// 的约束一样硬，但被约束的进程会看到一个不同的挂载树，而那会以各种意想不到的方式影响
    /// 一个不知道自己在 namespace 里的程序。
    fn rank(self) -> u8 {
        match self {
            Backend::Landlock => 2,
            Backend::MountNamespace => 1,
        }
    }
}

/// 一次探测的结果，包含不可用的**理由**。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Availability {
    pub backend: Backend,
    pub available: bool,
    /// 可用时为空，不可用时**永不为空**。一个没有理由的"不可用"，和一个没做的检查在
    /// 返回值上无法区分。
    pub detail: String,
}

/// 探测这台机器上所有后端。
pub fn probe() -> Vec<Availability> {
    vec![probe_landlock(), probe_mount_namespace()]
}

/// 最强的可用后端，没有则 `None`。
pub fn best_available() -> Option<Backend> {
    probe()
        .into_iter()
        .filter(|a| a.available)
        .map(|a| a.backend)
        .max_by_key(|b| b.rank())
}

#[cfg(target_os = "linux")]
fn probe_landlock() -> Availability {
    // `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` 返回 ABI 版本号。
    // 这是官方推荐的探测方式，而且它探的是"这个调用现在能不能用"，不是内核版本号——
    // 后者会在这个容器里给出错的答案。
    const SYS_LANDLOCK_CREATE_RULESET: libc_syscall::Nr = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    let abi = unsafe {
        libc_syscall::syscall3(
            SYS_LANDLOCK_CREATE_RULESET,
            0,
            0,
            LANDLOCK_CREATE_RULESET_VERSION as isize,
        )
    };
    if abi > 0 {
        Availability {
            backend: Backend::Landlock,
            available: true,
            detail: format!("Landlock ABI v{abi}"),
        }
    } else {
        let err = -abi;
        Availability {
            backend: Backend::Landlock,
            available: false,
            detail: format!(
                "landlock_create_ruleset 返回 errno {err}（{}）",
                match err {
                    38 =>
                        "ENOSYS —— 内核没有 Landlock，或者上层 seccomp 把这个系统调用挡掉了。\
                           内核版本够不等于这个机制可用",
                    1 => "EPERM",
                    _ => "未知",
                }
            ),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_landlock() -> Availability {
    Availability {
        backend: Backend::Landlock,
        available: false,
        detail: format!("Landlock 是 Linux 机制，本机是 {}", std::env::consts::OS),
    }
}

#[cfg(target_os = "linux")]
fn probe_mount_namespace() -> Availability {
    // 真的建一个再销毁，而不是查 /proc/sys/user/max_user_namespaces。后者在容器里经常是
    // 非零而实际不可用。探测必须探"能不能做"，不是"看起来该能做"。
    match crate::mountns::can_unshare() {
        Ok(()) => Availability {
            backend: Backend::MountNamespace,
            available: true,
            detail: "user + mount namespace 可用".into(),
        },
        Err(e) => Availability {
            backend: Backend::MountNamespace,
            available: false,
            detail: format!("unshare(CLONE_NEWUSER|CLONE_NEWNS) 失败：{e}"),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_mount_namespace() -> Availability {
    Availability {
        backend: Backend::MountNamespace,
        available: false,
        detail: format!(
            "mount namespace 是 Linux 机制，本机是 {}",
            std::env::consts::OS
        ),
    }
}

/// 极小的 syscall 封装。
///
/// 不引 `libc` crate：这个 crate 只需要三四个 syscall 号，而引入 `libc` 会让一个安全边界
/// 组件多一个依赖面。用 `asm!` 直接发，代码短到可以逐行读。
#[cfg(target_os = "linux")]
pub(crate) mod libc_syscall {
    pub type Nr = i64;

    /// 三参数 syscall。返回值 < 0 时是 `-errno`。
    #[inline]
    pub unsafe fn syscall3(nr: Nr, a: isize, b: isize, c: isize) -> isize {
        let ret: isize;
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a, in("rsi") b, in("rdx") c,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!(
            "svc 0",
            in("x8") nr as isize,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c,
            options(nostack, preserves_flags)
        );
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 探测不能依赖"当前二进制是 agentguard-jail"。
    ///
    /// 这条测试就跑在一个**不是** agentguard-jail 的二进制里（cargo 的 lib test
    /// harness），所以它正好能钉住那个真 bug：`can_unshare` 曾经是
    /// `Command::new("/proc/self/exe").arg("--jail-probe-unshare")`，
    /// 从任何不认识这个参数的二进制调用时，子进程会以 clap 的用法错误退出，
    /// 于是探测报"不支持 mount namespace"。
    ///
    /// 那是一个假阴性,而且出现在 `agentguard preflight` 的安全报告里 ——
    /// 它会告诉运维"本机没有内核约束可用",而实际上有。
    ///
    /// 断言查的是**理由的形状**,而不是"可用"：这条测试必须在真的不支持
    /// namespace 的机器上也能过。一个真实的失败理由里有 errno；一个参数解析
    /// 错误里有 usage / unexpected argument。
    #[cfg(target_os = "linux")]
    #[test]
    fn 探测不依赖当前二进制是哪一个() {
        let a = probe_mount_namespace();
        if a.available {
            return; // 本机支持,而且这个二进制也探到了 —— 正是原来会失败的情况。
        }
        let d = a.detail.to_ascii_lowercase();
        assert!(
            d.contains("errno"),
            "不可用的理由应该是一个系统调用失败,实际是:{}",
            a.detail
        );
        for bad in ["unexpected argument", "usage:", "--help", "unrecognized"] {
            assert!(
                !d.contains(bad),
                "探测把子进程的命令行解析错误当成了「不支持」:{}",
                a.detail
            );
        }
    }

    #[test]
    fn 每个不可用的后端都必须给出理由() {
        // 一个没有理由的"不可用"，和一个没做的检查在返回值上无法区分。
        for a in probe() {
            if !a.available {
                assert!(
                    !a.detail.is_empty(),
                    "{:?} 报了不可用但没说为什么",
                    a.backend
                );
            }
        }
    }

    #[test]
    fn 探测的是能不能做而不是版本号() {
        // 写这段时的容器：内核 6.18，Landlock 早就有了，但系统调用返回 ENOSYS，因为上层
        // seccomp 挡掉了。这条测试钉住的是"理由里要能看出这个区别"。
        let landlock = probe()
            .into_iter()
            .find(|a| a.backend == Backend::Landlock)
            .expect("有 landlock 条目");
        if !landlock.available {
            assert!(
                landlock.detail.contains("errno") || landlock.detail.contains("Linux 机制"),
                "理由要能说清是哪一种不可用：{}",
                landlock.detail
            );
        }
    }

    #[test]
    fn landlock_比_mount_namespace_优先() {
        assert!(Backend::Landlock.rank() > Backend::MountNamespace.rank());
    }
}
