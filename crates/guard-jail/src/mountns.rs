//! mount namespace 后端：在一个私有挂载命名空间里把文件系统变成只读，再把写授权挂回来。
//!
//! # 为什么这个后端存在
//!
//! Landlock 更好——它不改变进程看到的文件系统。但"内核版本够"不等于"这个机制可用"：写这段
//! 代码的容器内核是 6.18，Landlock 早就有了，而 `landlock_create_ruleset` 返回 `ENOSYS`，
//! 因为上层 seccomp 把它挡掉了。一个只有 Landlock 后端的 jail 在这种环境里只能拒绝启动。
//!
//! mount namespace 的可用面宽得多，而且它的约束**一样是内核执行的**。
//!
//! # 步骤，以及每一步为什么不能省
//!
//! 1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` —— 新的 user ns 让后面的 mount 操作不需要真的
//!    root；新的 mount ns 让后面所有挂载改动只影响这个进程及其子进程。
//! 2. 写 `uid_map` / `gid_map` —— 不做的话进程在新 ns 里是 nobody，读不了自己的文件。
//!    写之前必须先写 `setgroups=deny`，否则内核拒绝写 gid_map。
//! 3. `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` —— 断开挂载传播。**不做这一步，
//!    后面的改动会传播回父命名空间**，也就是改了宿主的挂载表。
//! 4. 对每个只读目标做 bind + remount ro。
//! 5. 对每个写授权做 bind + remount rw —— 顺序必须在只读之后，否则被只读覆盖。
//!
//! # 这个后端的真实边界
//!
//! 它约束的是**文件系统**，不是网络、不是进程、不是 IPC。一个在这里被关住的进程仍然可以
//! 建立网络连接（那是 C 层的事）。而且它需要 user namespace 可用——很多加固过的宿主关掉了。

use std::io::Write;
use std::path::Path;

use crate::backend::libc_syscall::syscall3;

const CLONE_NEWNS: isize = 0x00020000;
const CLONE_NEWUSER: isize = 0x10000000;
const SYS_UNSHARE: i64 = 272;
const SYS_MOUNT: i64 = 165;

const MS_RDONLY: usize = 1;
const MS_REMOUNT: usize = 32;
const MS_BIND: usize = 4096;
const MS_REC: usize = 16384;
const MS_PRIVATE: usize = 1 << 18;

/// 五参数 syscall，mount 需要。
#[inline]
unsafe fn syscall5(nr: i64, a: isize, b: isize, c: isize, d: isize, e: isize) -> isize {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    std::arch::asm!(
        "syscall",
        inlateout("rax") nr as isize => ret,
        in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e,
        out("rcx") _, out("r11") _,
        options(nostack, preserves_flags)
    );
    #[cfg(target_arch = "aarch64")]
    std::arch::asm!(
        "svc 0",
        in("x8") nr as isize,
        inlateout("x0") a => ret,
        in("x1") b, in("x2") c, in("x3") d, in("x4") e,
        options(nostack, preserves_flags)
    );
    ret
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn mount_raw(source: Option<&str>, target: &str, flags: usize) -> Result<(), String> {
    let src = source.map(cstr);
    let tgt = cstr(target);
    let r = unsafe {
        syscall5(
            SYS_MOUNT,
            src.as_ref().map(|v| v.as_ptr() as isize).unwrap_or(0),
            tgt.as_ptr() as isize,
            0,
            flags as isize,
            0,
        )
    };
    if r < 0 {
        Err(format!(
            "mount({source:?} -> {target:?}, flags={flags:#x}) errno {}",
            -r
        ))
    } else {
        Ok(())
    }
}

fn unshare_raw(flags: isize) -> Result<(), String> {
    match unshare_errno(flags) {
        0 => Ok(()),
        e => Err(format!("unshare({flags:#x}) errno {e}")),
    }
}

/// 同一个系统调用，返回裸 errno（0 = 成功）。
///
/// 探测路径需要 errno 本身而不是一句话：它要把结果通过 `pre_exec` 的
/// `io::Error` 传回父进程，而那个通道只能带一个 errno。
fn unshare_errno(flags: isize) -> i32 {
    let r = unsafe { syscall3(SYS_UNSHARE, flags, 0, 0) };
    if r < 0 {
        (-r) as i32
    } else {
        0
    }
}

/// `pre_exec` 用来表示"unshare 成功了"的哨兵 errno。
///
/// 选 `ENOTNAM`(118)：它是一个只有 NetWare/named-pipe 相关代码才会产生的 errno，
/// 这条路径上不可能自然出现，所以它和真实失败不会混。
const PROBE_OK_SENTINEL: i32 = 118;

/// 探测：真的 unshare 一次再看结果。
///
/// 在**子进程**里做，因为 `unshare` 是不可逆的——在探测里改掉当前进程的命名空间，会让后面
/// 所有逻辑运行在一个和它以为的不同的环境里。
///
/// ## 为什么不再重新 exec 自己
///
/// 第一版是 `Command::new("/proc/self/exe").arg("--jail-probe-unshare")`，靠
/// `agentguard-jail` 的 `main` 认出这个参数、在子进程里 unshare、用退出码回答。
///
/// 那个写法有一个只在**别的**二进制里调用时才暴露的 bug：从 `guard-cli` 调用时，
/// 子进程是 `guard-cli`，它的 clap 解析器不认识 `--jail-probe-unshare`，于是以
/// 非零码退出——探测把它读成"这台机器不支持 mount namespace"。
///
/// 这是**假阴性**，而且是在一份安全报告里：`agentguard preflight` 会告诉运维
/// "本机没有内核约束可用"，而实际上有。缺陷形状是本项目反复出现的第二种——
/// 机制没有接到它被调用的那个入口上——只不过这次错的方向更糟：
/// 它让人以为自己**没有**保护，而不是以为自己有。
///
/// 现在的写法完全不依赖二进制是谁：`pre_exec` 在 fork 之后、exec 之前跑，
/// 它在子进程里 unshare，然后**故意**返回一个错误，于是 exec 永远不发生
/// （那个程序路径也就不需要存在）。std 会把这个 errno 从子进程通过管道送回父进程。
///   - 哨兵 errno ⇒ unshare 成功，后端可用。
///   - 其它 errno ⇒ unshare 失败，errno 就是原因。
pub fn can_unshare() -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    // 这个路径不需要存在：pre_exec 一定返回 Err，所以 exec 永远走不到。
    let mut cmd = std::process::Command::new("/nonexistent/agentguard-jail-probe");
    unsafe {
        cmd.pre_exec(|| {
            // 子进程里只做两件事：一个系统调用，和返回。不分配、不加锁——
            // fork 之后的子进程只能做 async-signal-safe 的事。
            let e = unshare_errno(CLONE_NEWUSER | CLONE_NEWNS);
            Err(std::io::Error::from_raw_os_error(if e == 0 {
                PROBE_OK_SENTINEL
            } else {
                e
            }))
        });
    }
    match cmd.spawn() {
        // spawn 成功是不可能的——pre_exec 一定失败。真出现了说明上面的假设不成立，
        // 那就宁可报不可用：把一个理解不了的结果当成"可用"，等于凭猜测放行。
        Ok(mut child) => {
            let _ = child.kill();
            let _ = child.wait();
            Err("探测子进程居然 exec 成功了；pre_exec 的假设不成立，不敢认为可用".into())
        }
        Err(e) => match e.raw_os_error() {
            Some(PROBE_OK_SENTINEL) => Ok(()),
            Some(errno) => Err(format!(
                "unshare(CLONE_NEWUSER|CLONE_NEWNS) errno {errno}（{e}）"
            )),
            None => Err(format!("无法起探测子进程：{e}")),
        },
    }
}

/// 在**当前进程**里进入约束。调用之后不可逆。
///
/// 只应该在 `fork`/`Command` 的子进程里调用，也就是在 `pre_exec` 里——在父进程里调用会把
/// 父进程自己关进去。
pub fn enter(profile: &crate::Profile) -> Result<(), String> {
    let dbg = std::env::var_os("AGENTGUARD_JAIL_DEBUG").is_some();
    macro_rules! step {
        ($name:expr, $e:expr) => {{
            let r = $e;
            if dbg {
                eprintln!("  jail step {}: {:?}", $name, r);
            }
            r?
        }};
    }
    // **在 unshare 之前**读 uid/gid。
    //
    // 这是写这个后端时的真 bug，值得留着：第一版在 unshare 之后才调 getuid，而进入一个还没有
    // 映射的 user namespace 之后，进程看到的自己是 overflow uid（65534/nobody）。于是它试图把
    // ns 内的 0 映射到 65534——一个它并不拥有的外部 uid——内核返回 EPERM。
    //
    // EPERM 读起来像"权限不够"，实际是"你问错了问题"。这类错误在一个用别的语言写的
    // 探针里不会出现，因为探针的写法不同；只有把顺序写对才行。
    let outer_uid = unsafe { syscall3(102, 0, 0, 0) }; // getuid
    let outer_gid = unsafe { syscall3(104, 0, 0, 0) }; // getgid

    step!("unshare", unshare_raw(CLONE_NEWUSER | CLONE_NEWNS));

    // uid/gid 映射。`setgroups=deny` 必须先写，否则内核拒绝写 gid_map。
    let uid = std::process::id();
    // `setgroups=deny` 必须在 gid_map 之前写成功，否则内核拒绝写 gid_map。
    // 第一版用 `let _ =` 忽略了它的失败，于是真正的原因会被后面 gid_map 的 EPERM 掩盖。
    step!(
        "setgroups=deny",
        std::fs::write("/proc/self/setgroups", b"deny")
            .map_err(|e| format!("写 /proc/self/setgroups 失败：{e}"))
    );
    // 把 ns 里的 0 映射到 ns 外的当前 uid。用真实 uid 而不是 0：让被约束的进程在
    // namespace 里也不是 root，少一层"万一逃出去了"的影响面。
    step!("uid_map", write_map("/proc/self/uid_map", outer_uid));
    step!("gid_map", write_map("/proc/self/gid_map", outer_gid));
    let _ = uid;

    // 断开挂载传播。不做这一步，后面的改动会改到宿主的挂载表。
    step!(
        "make-rprivate",
        mount_raw(Some("none"), "/", MS_REC | MS_PRIVATE)
    );

    // 整棵树变只读。
    step!("rbind /", mount_raw(Some("/"), "/", MS_BIND | MS_REC));
    step!(
        "remount ro",
        mount_raw(None, "/", MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY)
    );

    // 把写授权挂回可写。顺序必须在只读之后。
    for w in profile.all_write() {
        let p = w.to_string_lossy().into_owned();
        if !Path::new(&p).exists() {
            // 不存在的写授权不是错误（目标目录可能由被约束的进程自己建），但也不能忽略：
            // 建出来，否则 bind 会失败而整个约束就落不下去。
            std::fs::create_dir_all(&p).map_err(|e| format!("建写授权目录 {p} 失败：{e}"))?;
        }
        step!("bind rw", mount_raw(Some(&p), &p, MS_BIND | MS_REC));
        step!("remount rw", mount_raw(None, &p, MS_REMOUNT | MS_BIND));
    }
    Ok(())
}

fn write_map(path: &str, outer: isize) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("打开 {path} 失败：{e}"))?;
    // "0 <outer> 1"：ns 内的 0 对应 ns 外的 outer，长度 1。
    f.write_all(format!("0 {outer} 1").as_bytes())
        .map_err(|e| format!("写 {path} 失败：{e}"))
}
