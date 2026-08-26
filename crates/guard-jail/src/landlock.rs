//! Landlock 后端:一个按进程的、不改变文件系统视图的访问约束。
//!
//! # 这个后端以前只探测、不落地,于是读约束根本没被执行
//!
//! `docs/内核约束.md` 说 profile 的读列表"其余一律拒绝",而 `Profile::read` 的文档说"空表示
//! 什么都不能读"。**mount namespace 后端从头到尾不消费 `profile.read`** —— 它把整棵树变只读,
//! 但读**哪里**不受限。一次独立复核实测:在 mount-ns 后端下,`/etc/shadow`、`/root` 全都读得到。
//!
//! 能执行读天花板的正是 Landlock:它是一个 LSM,按路径**拒绝**访问,包括读。这个文件把它
//! 实现出来。
//!
//! # 我在这个环境里测不了它的落地,所以怎么保证它不是"看起来能跑"
//!
//! 这个容器的内核有 Landlock,但上层 seccomp 把 `landlock_*` 系统调用挡掉了(`probe_landlock`
//! 实测返回 ENOSYS)。也就是说**这段代码的系统调用路径在这里跑不到**。上一轮复核的一个教训
//! 正是"实现一个不足以支撑其主张的机制"—— 盲写一段没跑过的 unsafe 然后声称它约束住了,是同
//! 一个错误。
//!
//! 所以这里把两件事分开:
//!
//! * **安全相关的逻辑**(哪个路径拿到哪些权限:读授权只给读、写授权给写、`/root/.ssh` 这类
//!   既不在授权里又不是系统运行时路径的东西**什么都不给** = 被拒)全部放进 [`build_rule_plan`],
//!   一个纯函数,在**这个环境里**就能完整单元测试。
//! * **系统调用序列**([`enter`])尽可能薄,而且**fail-closed**:`create_ruleset` /
//!   `add_rule` / `restrict_self` 任何一步返回错误,`enter` 就返回 `Err`,于是 `launch` 的
//!   `pre_exec` 失败、子进程**绝不 exec**。一个装不上 Landlock 的机器不会退化成不约束地跑。
//!
//! # 这个读天花板覆盖什么、不覆盖什么(如实说明)
//!
//! 一个纯 profile 的规则集会让目标程序连自己都启动不了 —— 它读不到 `ld.so`、libc、`/usr`。
//! 所以 [`build_rule_plan`] 额外给一组**系统运行时根**(`/usr` `/lib` `/lib64` `/bin` `/sbin`
//! `/etc` `/proc` `/sys` `/dev` 以及目标二进制自己所在的目录)授予读+执行。
//!
//! 后果要说清楚:这是一个**用户数据**的读天花板,不是一个**全盘**读天花板。`/root/.ssh`、
//! 别的用户的家目录、声明之外的项目目录 —— 这些不在系统运行时根里,所以被拒。而 `/etc` 在
//! 系统运行时根里(程序常要读它),所以 `/etc` 下的东西仍可读。想要更严(连 `/etc` 也按需
//! 授予)需要知道目标程序到底要读哪些运行时文件,那是另一件事;在它之前,这一层提供的是
//! "读不到你声明范围之外的用户数据",而不是"读不到任何东西"。

use std::path::{Path, PathBuf};

use crate::profile::Profile;

// ---- Landlock ABI v1 访问权限位 ----
pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// 只读+可遍历+可执行 —— 给系统运行时根和读授权。
pub const READ_SET: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE;

/// 全部写/改/建 —— 给写授权(叠加 READ_SET,因为能写必然要能读)。
pub const WRITE_SET: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM;

/// ruleset 治理的全部权限。**不在**某条规则里被授予的,就被拒 —— 包括读。
pub const HANDLED_ALL: u64 = READ_SET | WRITE_SET;

/// 系统运行时根:目标程序要能启动、能动态链接,就必须能读这些。
///
/// 这组路径是"用户数据读天花板"和"全盘读天花板"的分界线,见模块头的说明。
pub const RUNTIME_ROOTS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev",
];

/// 规则集的落地计划:每条 = (路径, 允许的访问位)。
///
/// 纯数据,不碰内核。`enter` 把它翻译成 `landlock_add_rule` 调用,而这个函数本身在没有
/// Landlock 的机器上也能完整测试。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePlan {
    pub handled: u64,
    /// (路径, 访问位),按路径去重、排序,行为可复现。
    pub rules: Vec<(PathBuf, u64)>,
}

/// 从 profile 和目标二进制路径构造规则计划。
///
/// * 系统运行时根(存在的那些)→ `READ_SET`
/// * 目标二进制所在目录 → `READ_SET`(否则连它自己都 exec 不了)
/// * profile 读授权 → `READ_SET`
/// * profile 写授权 → `READ_SET | WRITE_SET`
///
/// 同一路径被多次授予时权限**按位或**合并。不在任何规则里的路径 = 被拒。
pub fn build_rule_plan(profile: &Profile, program: &Path) -> RulePlan {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<PathBuf, u64> = BTreeMap::new();
    let mut grant = |p: PathBuf, bits: u64| {
        *acc.entry(p).or_insert(0) |= bits;
    };

    for root in RUNTIME_ROOTS {
        grant(PathBuf::from(root), READ_SET);
    }
    // 目标二进制自己所在的目录。argv[0] 可能是相对路径或裸命令名;裸命令名(靠 PATH 找到)
    // 的情况这里给不出目录,那属于运行时根覆盖的范围(/usr/bin 等)。
    if let Some(dir) = program.parent() {
        if !dir.as_os_str().is_empty() {
            grant(dir.to_path_buf(), READ_SET);
        }
    }
    for r in profile.all_read() {
        grant(r.to_path_buf(), READ_SET);
    }
    for w in profile.all_write() {
        grant(w.to_path_buf(), READ_SET | WRITE_SET);
    }

    RulePlan {
        handled: HANDLED_ALL,
        rules: acc.into_iter().collect(),
    }
}

// ---- 系统调用落地。fail-closed。 ----

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::backend::libc_syscall::{syscall3, syscall4};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    const SYS_LANDLOCK_ADD_RULE: i64 = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
    const SYS_PRCTL: i64 = 157;

    const LANDLOCK_RULE_PATH_BENEATH: isize = 1;
    const PR_SET_NO_NEW_PRIVS: isize = 38;

    // `O_PATH | O_CLOEXEC | O_DIRECTORY` 不用:O_PATH 打开一个只用于命名的 fd,不需要对
    // 内容的读权限,正是 add_rule 想要的。
    const O_PATH: i32 = 0x0020_0000;
    const O_CLOEXEC: i32 = 0x0008_0000;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    /// 装上规则集并 `restrict_self`。任何一步失败都返回 `Err`(fail-closed)。
    ///
    /// 在 `pre_exec` 里跑:此时子进程单线程,只做 syscall,不分配不加锁。
    pub fn enter(plan: &RulePlan) -> Result<(), String> {
        let attr = RulesetAttr {
            handled_access_fs: plan.handled,
        };
        let rs_fd = unsafe {
            syscall3(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const RulesetAttr as isize,
                std::mem::size_of::<RulesetAttr>() as isize,
                0,
            )
        };
        if rs_fd < 0 {
            return Err(format!(
                "landlock_create_ruleset errno {}(这台机器上 Landlock 系统调用不可用;\
                 拒绝在不约束的情况下启动)",
                -rs_fd
            ));
        }
        let rs_fd = rs_fd as i32;

        for (path, bits) in &plan.rules {
            // 路径不存在就跳过 —— 不能对不存在的路径下规则。这只影响**授予**:少授予
            // 一条只会更严(那个路径反正被拒),不会放宽。写授权必须存在,那由上层保证
            // (mount-ns 后端会创建;这里不创建,因为 Landlock 不改变文件系统)。
            let file = match std::fs::OpenOptions::new()
                .custom_flags(O_PATH | O_CLOEXEC)
                .read(true)
                .open(path)
            {
                Ok(f) => f,
                Err(_) => continue,
            };
            let pb = PathBeneathAttr {
                allowed_access: *bits,
                parent_fd: file.as_raw_fd(),
            };
            let r = unsafe {
                syscall4(
                    SYS_LANDLOCK_ADD_RULE,
                    rs_fd as isize,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &pb as *const PathBeneathAttr as isize,
                    0,
                )
            };
            if r < 0 {
                return Err(format!(
                    "landlock_add_rule 对 {} errno {}",
                    path.display(),
                    -r
                ));
            }
        }

        // restrict_self 的前提:PR_SET_NO_NEW_PRIVS。它本身也该设。
        let r = unsafe { syscall3(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0) };
        if r < 0 {
            return Err(format!("prctl(PR_SET_NO_NEW_PRIVS) errno {}", -r));
        }
        let r = unsafe { syscall3(SYS_LANDLOCK_RESTRICT_SELF, rs_fd as isize, 0, 0) };
        if r < 0 {
            return Err(format!("landlock_restrict_self errno {}", -r));
        }
        Ok(())
    }
}

/// 装上 profile 的 Landlock 约束(含读天花板),然后**不再** exec 任何更宽松的东西。
///
/// fail-closed:约束装不上就返回 `Err`,`launch` 的 `pre_exec` 会因此失败、子进程绝不 exec。
#[cfg(target_os = "linux")]
pub fn enter(profile: &Profile, program: &Path) -> Result<(), String> {
    let plan = build_rule_plan(profile, program);
    sys::enter(&plan)
}

#[cfg(not(target_os = "linux"))]
pub fn enter(_profile: &Profile, _program: &Path) -> Result<(), String> {
    Err("Landlock 是 Linux 机制".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(read: &[&str], write: &[&str]) -> Profile {
        Profile {
            read: read.iter().map(PathBuf::from).collect(),
            write: write.iter().map(PathBuf::from).collect(),
            ..Default::default()
        }
    }

    fn bits_for(plan: &RulePlan, path: &str) -> Option<u64> {
        plan.rules
            .iter()
            .find(|(p, _)| p == Path::new(path))
            .map(|(_, b)| *b)
    }

    /// 读授权只拿到读权限,不拿到写。
    #[test]
    fn 读授权只读() {
        let p = profile(&["/data/in"], &[]);
        let plan = build_rule_plan(&p, Path::new("/usr/bin/python3"));
        let b = bits_for(&plan, "/data/in").expect("读授权应当有规则");
        assert_eq!(b, READ_SET, "读授权应当只有 READ_SET");
        assert_eq!(b & WRITE_SET, 0, "读授权不能带任何写位");
    }

    /// 写授权拿到读+写。
    #[test]
    fn 写授权可读可写() {
        let p = profile(&[], &["/data/out"]);
        let plan = build_rule_plan(&p, Path::new("/usr/bin/python3"));
        let b = bits_for(&plan, "/data/out").expect("写授权应当有规则");
        assert_eq!(b & WRITE_SET, WRITE_SET, "写授权应当有全部写位");
        assert_eq!(b & READ_SET, READ_SET, "写授权也要能读");
    }

    /// essential_write(进程私有临时目录)也必须可读可写。
    ///
    /// 这条单独测,因为 `all_read()` 链进了 `write` 却**没**链 `essential_write`——所以
    /// essential_write 的读位**只**能来自写授权那条 `READ_SET | WRITE_SET`。少了它,进程
    /// 写得进自己的临时目录却读不回来。这条测试把那个 `READ_SET |` 钉住(否则它是等价变异)。
    #[test]
    fn essential写授权也可读可写() {
        let p = Profile {
            essential_write: vec![PathBuf::from("/tmp/agentguard-XXXX")],
            ..Default::default()
        };
        let plan = build_rule_plan(&p, Path::new("/usr/bin/python3"));
        let b = bits_for(&plan, "/tmp/agentguard-XXXX").expect("essential_write 应当有规则");
        assert_eq!(b & WRITE_SET, WRITE_SET, "essential_write 应当有全部写位");
        assert_eq!(
            b & READ_SET,
            READ_SET,
            "essential_write 也要能读(否则读不回自己写的东西)"
        );
    }

    /// **读天花板**:声明之外、又不是系统运行时根的路径,拿不到任何规则 = 被拒。
    ///
    /// 这正是 mount-namespace 后端做不到、而这个后端存在的理由。
    #[test]
    fn 声明之外的用户数据没有规则() {
        let p = profile(&["/data/in"], &["/data/out"]);
        let plan = build_rule_plan(&p, Path::new("/usr/bin/python3"));
        for outside in ["/root/.ssh", "/home/other", "/data/secret", "/root"] {
            assert!(
                bits_for(&plan, outside).is_none(),
                "{outside} 拿到了规则 —— 读天花板漏了"
            );
        }
    }

    /// 系统运行时根拿到读权限,否则程序连自己都启动不了。
    #[test]
    fn 系统运行时根可读() {
        let plan = build_rule_plan(&profile(&[], &[]), Path::new("/usr/bin/python3"));
        for root in ["/usr", "/lib", "/etc", "/proc"] {
            let b = bits_for(&plan, root).unwrap_or_else(|| panic!("{root} 应当有读规则"));
            assert_eq!(b & ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE);
            assert_eq!(b & WRITE_SET, 0, "运行时根不该可写");
        }
    }

    /// 目标二进制所在目录可读(相对路径 / 显式路径的情况)。
    #[test]
    fn 目标二进制目录可读() {
        let plan = build_rule_plan(&profile(&[], &[]), Path::new("/opt/tool/bin/agent"));
        let b = bits_for(&plan, "/opt/tool/bin").expect("二进制目录应当有读规则");
        assert_eq!(b & ACCESS_FS_EXECUTE, ACCESS_FS_EXECUTE);
    }

    /// 同一路径既是运行时根又被写授权覆盖时,权限按位或合并(取更宽),不是覆盖成更窄。
    #[test]
    fn 权限按位或合并() {
        // /etc 既是运行时根(READ_SET),又假设被显式写授权。
        let p = profile(&[], &["/etc"]);
        let plan = build_rule_plan(&p, Path::new("/usr/bin/x"));
        let b = bits_for(&plan, "/etc").expect("规则");
        assert_eq!(b, READ_SET | WRITE_SET, "应当合并成读+写,而不是只剩一个");
    }

    /// handled 集合治理读**和**写 —— 只治理写的话,读天花板根本不存在。
    #[test]
    fn handled_治理读() {
        let plan = build_rule_plan(&profile(&[], &[]), Path::new("/usr/bin/x"));
        assert_eq!(plan.handled & ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE);
        assert_eq!(plan.handled & ACCESS_FS_READ_DIR, ACCESS_FS_READ_DIR);
        assert_eq!(plan.handled & ACCESS_FS_WRITE_FILE, ACCESS_FS_WRITE_FILE);
    }

    /// 计划是确定性的:同一 profile 每次产出逐字节相同的规则(排序去重)。
    #[test]
    fn 计划确定() {
        let p = profile(&["/b", "/a", "/b"], &["/c"]);
        let a = build_rule_plan(&p, Path::new("/usr/bin/x"));
        let b = build_rule_plan(&p, Path::new("/usr/bin/x"));
        assert_eq!(a, b);
        // 去重:/b 只出现一次。
        assert_eq!(
            a.rules.iter().filter(|(p, _)| p == Path::new("/b")).count(),
            1
        );
    }
}
