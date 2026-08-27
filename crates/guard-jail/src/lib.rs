//! 内核执行的进程约束：AgentGuard 当父进程，从 paths 天花板生成约束规则。
//!
//! # 这一层和网关的区别
//!
//! `docs/interception-design.md` §2 把这条区分写成不能含混的一条：
//!
//! * **协作式**（`guard-gateway`，A1）：智能体自愿把动作交给守卫。守卫能拒。**绕过去的智能体
//!   不受影响。**
//! * **内核执行**（这里，B2）：内核代为拒绝。智能体配不配合无关。
//!
//! 这是"AgentGuard 不是沙箱"这句话第一次不再完整成立的地方——但只在 Linux 上，只对
//! AgentGuard 自己启动的进程，而且只约束文件系统。
//!
//! # 最重要的一条：约束不了就不启动
//!
//! [`launch`] 在没有任何可用后端时返回错误，**不启动任何进程**。一个"约束不了就不约束地跑"
//! 的 jail 比没有 jail 更糟，因为使用者以为进程被关住了。
//!
//! 同理，一份自相矛盾的 profile（比如写授权落在 `/etc` 上）也拒绝启动，而不是"尽力执行"——
//! 部分生效的约束在使用者看来和完全生效没有区别。

pub mod backend;
pub mod profile;

#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod mountns;

pub use backend::{best_available, probe, Availability, Backend};
pub use profile::Profile;

use std::process::Command;

/// 启动一个被约束的进程。
#[derive(Debug)]
pub struct Launched {
    pub backend: Backend,
    pub child: std::process::Child,
}

/// 启动失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum JailError {
    #[error(
        "没有可用的约束后端，因此**不启动任何进程**：\n{0}\n\n\
             一个约束不了就不约束地跑的 jail 比没有 jail 更糟——使用者会以为进程被关住了。"
    )]
    NoBackend(String),
    #[error("profile 自相矛盾，拒绝启动（部分生效的约束和完全生效在使用者看来没有区别）：\n{0}")]
    Contradictory(String),
    #[error(
        "拒绝以 root(euid 0)运行 mount-namespace 后端:此时新 user namespace 里 0 映射到 0,\
         /dev 仍可写,`dd of=/dev/sdX` 能绕过整棵树的只读约束。\n\
         以非 root 运行,或(明确接受这个风险时)设 AGENTGUARD_JAIL_ALLOW_ROOT=1。见 docs/内核约束.md。"
    )]
    RootMountNamespace,
    #[error("启动子进程失败：{0}")]
    Spawn(#[from] std::io::Error),
    #[error("{0}")]
    Backend(String),
}

/// 读**有效** uid(`/proc/self/status` 的 `Uid:` 行第二列)。
///
/// 不用 syscall 号(那是按架构变的);`/proc` 在 Linux 上一定有。读不到返回 `None`,
/// 调用方按「不确定」处理(不拒绝 —— 拒绝要基于确知是 root)。
#[cfg(target_os = "linux")]
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: <real> <effective> <saved> <fs>
            return rest.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

/// mount-ns + root 是不安全组合(见 `RootMountNamespace`)。这个纯函数把判定单独拿出来
/// 便于测试:确知是 root、后端是 mount-ns、且没有明确放行时才拒。
#[cfg(target_os = "linux")]
fn refuse_root_mountns(backend: Backend, euid: Option<u32>, allow_root: bool) -> bool {
    matches!(backend, Backend::MountNamespace) && euid == Some(0) && !allow_root
}

/// 在约束下启动 `argv`。
///
/// `argv[0]` 是程序，其余是参数。约束在 `fork` 之后、`exec` 之前落下（`pre_exec`），所以
/// 父进程不受影响，而子进程从第一条指令起就已经被关住。
pub fn launch(profile: &Profile, argv: &[String]) -> Result<Launched, JailError> {
    if argv.is_empty() {
        return Err(JailError::Backend("argv 为空".into()));
    }
    let contradictions = profile.contradictions();
    if !contradictions.is_empty() {
        return Err(JailError::Contradictory(contradictions.join("\n")));
    }
    let Some(backend) = best_available() else {
        let why = probe()
            .into_iter()
            .map(|a| format!("  {}: {}", a.backend.as_str(), a.detail))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(JailError::NoBackend(why));
    };

    // mount-ns 作为 root 跑时 /dev 仍可写(内核执行的只读约束绕得过去)。默认拒这个组合;
    // 运维明确接受风险可设 AGENTGUARD_JAIL_ALLOW_ROOT=1(会打警告)。
    #[cfg(target_os = "linux")]
    {
        let allow_root = std::env::var_os("AGENTGUARD_JAIL_ALLOW_ROOT").is_some();
        if refuse_root_mountns(backend, effective_uid(), allow_root) {
            return Err(JailError::RootMountNamespace);
        }
        if allow_root && matches!(backend, Backend::MountNamespace) && effective_uid() == Some(0) {
            eprintln!(
                "agentguard-jail: 警告:AGENTGUARD_JAIL_ALLOW_ROOT 已设,以 root 跑 mount-ns —— \
                 /dev 仍可写,只读约束可被 dd 到块设备绕过。"
            );
        }
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let p = profile.clone();
        match backend {
            Backend::MountNamespace => {
                // SAFETY: `pre_exec` 在 fork 之后、exec 之前跑，此时子进程是单线程的，
                // 所以这里做的一切只影响子进程。里面只调 syscall 和写 /proc，不分配也不加锁。
                unsafe {
                    cmd.pre_exec(move || mountns::enter(&p).map_err(std::io::Error::other));
                }
            }
            Backend::Landlock => {
                // Landlock 后端:装上一个规则集,其中**包含读天花板**(mount-ns 后端给不了
                // 的那一层)。fail-closed —— `landlock::enter` 返回 Err 时 `pre_exec` 失败、
                // 子进程绝不 exec,不会退化成不约束地跑。见 `landlock.rs` 顶部:这段代码的
                // 系统调用路径在当前容器里跑不到(seccomp 挡了 landlock_*),所以安全逻辑抽进
                // 了可在本环境完整测试的纯函数 `build_rule_plan`。
                let prog = std::path::PathBuf::from(&argv[0]);
                // SAFETY: 同 mount-ns 分支 —— `pre_exec` 在 fork 之后、单线程,只做 syscall。
                unsafe {
                    cmd.pre_exec(move || landlock::enter(&p, &prog).map_err(std::io::Error::other));
                }
            }
        }
    }

    let child = cmd.spawn()?;
    Ok(Launched { backend, child })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 矛盾的_profile_拒绝启动而且不启动任何进程() {
        let (p, _) = Profile::from_ceiling(&[], &["/etc".into()]);
        let err = launch(&p, &["/bin/true".into()]).expect_err("应当拒绝");
        assert!(matches!(err, JailError::Contradictory(_)), "{err:?}");
    }

    #[test]
    fn 空_argv_是错误() {
        let (p, _) = Profile::from_ceiling(&[], &[]);
        assert!(launch(&p, &[]).is_err());
    }

    #[test]
    fn 没有后端时的错误信息要说清为什么不启动() {
        // 这条测试在**有**后端的机器上也要有意义，所以它检查的是错误类型的措辞而不是
        // 触发它——措辞是使用者唯一能读到的东西。
        let err = JailError::NoBackend("landlock: ENOSYS".into());
        let msg = err.to_string();
        assert!(msg.contains("不启动任何进程"), "{msg}");
        assert!(msg.contains("比没有 jail 更糟"), "{msg}");
    }

    /// mount-ns + root 默认被拒;非 root、Landlock、或明确放行时不拒。
    #[test]
    #[cfg(target_os = "linux")]
    fn root跑mountns默认被拒() {
        // 危险组合:root + mount-ns + 未放行 → 拒。
        assert!(refuse_root_mountns(Backend::MountNamespace, Some(0), false));
        // 明确放行 → 不拒(运维接受风险)。
        assert!(!refuse_root_mountns(Backend::MountNamespace, Some(0), true));
        // 非 root → 不拒(/dev 不可写,没有这个逃逸)。
        assert!(!refuse_root_mountns(
            Backend::MountNamespace,
            Some(1000),
            false
        ));
        // Landlock 后端即便 root 也不拒:它按路径约束,不靠 ns 里的 uid 映射。
        assert!(!refuse_root_mountns(Backend::Landlock, Some(0), false));
        // 读不到 uid(None)= 不确知是 root → 不拒(拒绝要基于确知)。
        assert!(!refuse_root_mountns(Backend::MountNamespace, None, false));
    }

    #[test]
    fn root_mountns_错误信息说清怎么办() {
        let msg = JailError::RootMountNamespace.to_string();
        assert!(msg.contains("/dev"), "{msg}");
        assert!(msg.contains("AGENTGUARD_JAIL_ALLOW_ROOT"), "{msg}");
    }
}
