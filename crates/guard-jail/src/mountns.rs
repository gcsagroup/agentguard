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
#[cfg(target_arch = "x86_64")]
const SYS_UNSHARE: i64 = 272;
#[cfg(target_arch = "x86_64")]
const SYS_MOUNT: i64 = 165;
#[cfg(target_arch = "x86_64")]
const SYS_PRCTL: i64 = 157;
#[cfg(target_arch = "aarch64")]
const SYS_UNSHARE: i64 = 97;
#[cfg(target_arch = "aarch64")]
const SYS_MOUNT: i64 = 40;
#[cfg(target_arch = "aarch64")]
const SYS_PRCTL: i64 = 167;

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

    // 整棵树变只读 —— **逐个挂载点**,不是一次。
    //
    // `mount(2)` 的 `MS_REMOUNT` **忽略** `MS_REC`。上一版是对 `/` 的单次
    // `MS_REMOUNT|MS_BIND|MS_REC|MS_RDONLY`,注释写着"整棵树变只读",而内核只把 `/` 这一个
    // 挂载变成了只读。任何**独立挂载**的目录都保持可写:生产上极常见的独立 `/home`、`/var`、
    // `/data`、tmpfs `/tmp`、bind mount、附加磁盘、NFS。
    //
    // 复核直接复刻了 `docs/内核约束.md` 表格里"写 ~/.ssh → EROFS → 未创建"那一行,只是把
    // 家目录放在独立挂载上:
    //
    // ```text
    // 覆盖私钥 ~/.ssh/id_rsa:        写成功
    // 新增后门 ~/.ssh/authorized_keys: 写成功
    // --- 从宿主核对 ---
    // id_rsa 现在: STOLEN-AND-REPLACED
    // authorized_keys: ssh-rsa ATTACKER
    // ```
    //
    // 九条集成测试没抓到它,是因为测试容器里 `/`、`/etc`、`/root`、`/tmp` 全在同一个挂载上
    // (`stat %D` 都是 `fe00`),唯一的子挂载是不去写的伪文件系统。换一台 `/home` 独立分区的
    // 普通主机,那条测试会直接失败。
    step!("rbind /", mount_raw(Some("/"), "/", MS_BIND | MS_REC));
    step!(
        "remount ro /",
        mount_raw(None, "/", MS_REMOUNT | MS_BIND | MS_RDONLY)
    );
    // 枚举 /proc/self/mountinfo 并逐个 remount。用 mountinfo 而不是
    // `mount_setattr(AT_RECURSIVE)`(那是 5.12+),这样在老内核上也成立。
    for mp in read_mount_points() {
        if mp == "/" {
            continue;
        }
        // 伪文件系统跳过:remount 它们既无意义又会失败,而失败会让整个约束落不下去。
        if mp.starts_with("/proc") || mp.starts_with("/sys") || mp.starts_with("/dev") {
            continue;
        }
        // 单个挂载点 remount 失败不致命(可能是不支持只读的文件系统),但要说出来 ——
        // 静默跳过就是"你以为只读的地方其实可写"。
        if let Err(e) = mount_raw(None, &mp, MS_REMOUNT | MS_BIND | MS_RDONLY) {
            eprintln!("agentguard-jail: 警告:{mp} 没能变成只读({e});该挂载点仍可写");
        }
    }

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

    // **最后一步**:锁掉挂载家族,让被约束的进程改不了上面这些约束。
    //
    // 顺序不能变 —— 过滤器一装上,`mount` 就返回 EPERM,包括我们自己的。所以它必须在所有
    // 挂载操作之后、`exec` 之前。这也是为什么它在 `pre_exec` 里而不是在父进程里。
    //
    // 装不上就**失败**。`step!` 会把错误传播出去,于是 `spawn()` 报错、子进程绝不 exec ——
    // 一个装不上过滤器的 jail 不该假装自己在强制。
    step!("mount lockdown", install_mount_lockdown());
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

/// 读 `/proc/self/mountinfo` 里的挂载点列表。
///
/// 只在 jail 内部、`unshare` 之后调用,所以看到的是这个命名空间自己的挂载表。
fn read_mount_points() -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        // mountinfo 第 5 个字段是挂载点;路径里的空格被转义成 \040。
        if let Some(f) = line.split_whitespace().nth(4) {
            out.push(f.replace("\\040", " "));
        }
    }
    // 去重。`mount --rbind / /` 之后每个挂载点在 mountinfo 里都出现两次,不去重的话每个
    // 警告会打两遍 —— 而一条重复的警告读起来像两个不同的问题。
    out.sort();
    out.dedup();
    // 由深到浅:先 remount 子挂载,再动父挂载,免得父只读之后子的 remount 被拒。
    out.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
    out
}

/// 装上一个 seccomp 过滤器,让被约束的进程**失去**改自己挂载的能力。
///
/// # 为什么没有它,这一层的强制力约等于一个约定
///
/// jail 里的进程在自己的 user namespace 里是 ns-root 且持有**全部** capability,而只读挂载
/// 没有被 lock。于是它用一次裸 `mount(MS_REMOUNT|MS_BIND, "/")` 就能把整棵树重新变成可写。
/// 复核实测,root 与非 root 启动都成立:
///
/// ```text
/// 约束:14 个可读、1 个可写
/// 已在 mount_namespace 后端下启动(内核执行)
///   运行身份 uid=0 euid=0
///   CapEff:    000001ffffffffff          <- ns 内全部 40 个 capability
///   raw remount / -> 0 errno 0          <- 撤销只读成功
///   写只读区 ws/ 成功 —— 只读被撤销
/// --- 外部核对(宿主) ---
/// NONROOT-UNDID-READONLY                 <- 写进了只读授权区,宿主可见
/// ```
///
/// 三行 Python 即可,不依赖任何挂载布局。而"对不配合的智能体有效"正是这一层区别于网关的
/// 全部卖点(`docs/内核约束.md`:"对不配合的智能体 有效")。
///
/// 顺带纠正一处误导:那份文档说"提权可以逃出去……约束的是进程,不是 root",读者会以为
/// "只要 agent 不是 root 就关得住"。**不需要任何提权** —— 被约束进程始终是它自己 userns 内
/// 的 root 并握有 `CAP_SYS_ADMIN`。
///
/// # 这个过滤器做什么
///
/// 拒掉整个挂载家族,以及"再开一个 user namespace 来重新获得能力"这条路:
/// `mount` / `umount2` / `pivot_root` / `move_mount` / `open_tree` / `fsopen` / `fsconfig` /
/// `fsmount` / `mount_setattr` / `unshare` / `setns`。
///
/// 返回 `Err` 时调用方必须**拒绝启动** —— 一个装不上过滤器的 jail 不该假装自己在强制。
#[cfg(target_arch = "x86_64")]
pub(crate) fn install_mount_lockdown() -> Result<(), String> {
    // seccomp_data: nr(u32 @0), arch(u32 @4)
    const AUDIT_ARCH: u32 = 0xc000_003e; // x86_64
    const BLOCKED: &[u32] = &[
        165, // mount
        166, // umount2
        155, // pivot_root
        272, // unshare
        308, // setns
        428, // open_tree
        429, // move_mount
        430, // fsopen
        431, // fsconfig
        432, // fsmount
        442, // mount_setattr
    ];
    install_seccomp(AUDIT_ARCH, BLOCKED)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn install_mount_lockdown() -> Result<(), String> {
    const AUDIT_ARCH: u32 = 0xc000_00b7; // aarch64
    const BLOCKED: &[u32] = &[
        40,  // mount
        39,  // umount2
        41,  // pivot_root
        97,  // unshare
        268, // setns
        428, // open_tree
        429, // move_mount
        430, // fsopen
        431, // fsconfig
        432, // fsmount
        442, // mount_setattr
    ];
    install_seccomp(AUDIT_ARCH, BLOCKED)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn install_mount_lockdown() -> Result<(), String> {
    Err("这个架构上没有实现挂载锁定;拒绝在不约束的情况下启动".into())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// 手写 cBPF。没有引 libseccomp —— 这个 crate 连 libc 都没引,而过滤器本身只有十几条指令。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn install_seccomp(audit_arch: u32, blocked: &[u32]) -> Result<(), String> {
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO_EPERM: u32 = 0x0005_0001; // SECCOMP_RET_ERRNO | EPERM
    const RET_ALLOW: u32 = 0x7fff_0000;
    const PR_SET_NO_NEW_PRIVS: isize = 38;
    const PR_SET_SECCOMP: isize = 22;
    const SECCOMP_MODE_FILTER: isize = 2;

    let m = blocked.len();
    let mut prog: Vec<SockFilter> = Vec::with_capacity(m + 6);
    // 0: 取 arch
    prog.push(SockFilter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    // 1: arch 对得上就跳过下一条(那是 KILL)
    prog.push(SockFilter {
        code: JEQ_K,
        jt: 1,
        jf: 0,
        k: audit_arch,
    });
    // 2: 架构不符 —— 杀掉。不是 EPERM:架构不符意味着我的系统调用号表对不上,
    //    而"用一张对不上的表放行"比拒绝危险得多。
    prog.push(SockFilter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: RET_KILL_PROCESS,
    });
    // 3: 取 syscall 号
    prog.push(SockFilter {
        code: LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    // 4..4+m: 每个被拒的号一条 JEQ,命中就跳到最后那条 EPERM
    for (k, nr) in blocked.iter().enumerate() {
        prog.push(SockFilter {
            code: JEQ_K,
            jt: (m - k) as u8,
            jf: 0,
            k: *nr,
        });
    }
    // 4+m: 都没命中 -> 放行
    prog.push(SockFilter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    });
    // 5+m: 命中 -> EPERM
    prog.push(SockFilter {
        code: RET_K,
        jt: 0,
        jf: 0,
        k: RET_ERRNO_EPERM,
    });

    // `PR_SET_NO_NEW_PRIVS` 是装非特权 seccomp 过滤器的前提,而且它本身也该设:
    // 它让 setuid 二进制不能再提权。
    let r = unsafe { syscall5(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r < 0 {
        return Err(format!("prctl(PR_SET_NO_NEW_PRIVS) errno {}", -r));
    }
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let r = unsafe {
        syscall5(
            SYS_PRCTL,
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &fprog as *const SockFprog as isize,
            0,
            0,
        )
    };
    if r < 0 {
        return Err(format!("prctl(PR_SET_SECCOMP, FILTER) errno {}", -r));
    }
    Ok(())
}

#[cfg(test)]
mod b6_挂载约束复核 {
    use super::*;

    /// 挂载点枚举必须去重且由深到浅。
    ///
    /// 顺序是判据的一部分:父挂载先变只读的话,子挂载的 remount 会被拒,于是"整棵树只读"
    /// 变成"只有最外层只读"。
    #[test]
    fn 挂载点枚举去重且由深到浅() {
        let mps = read_mount_points();
        if mps.is_empty() {
            return; // 没有 /proc 的环境
        }
        let mut sorted = mps.clone();
        sorted.sort();
        let mut dedup = sorted.clone();
        dedup.dedup();
        assert_eq!(sorted.len(), dedup.len(), "挂载点列表里有重复项:{mps:?}");
        let depths: Vec<usize> = mps.iter().map(|p| p.matches('/').count()).collect();
        assert!(
            depths.windows(2).all(|w| w[0] >= w[1]),
            "挂载点没有按由深到浅排序:{:?}",
            mps.iter().zip(&depths).collect::<Vec<_>>()
        );
    }

    /// seccomp 过滤器必须能装上 —— 装不上等于这一层没有强制力。
    ///
    /// 在**子进程**里测,因为过滤器一装上就不可撤销,会影响本进程后续所有测试。
    #[test]
    fn 挂载锁定能装上并且真的生效() {
        // 只在支持的架构上跑。
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let exe = std::env::current_exe().unwrap();
            let out = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "mountns::b6_挂载约束复核::子进程内验证挂载锁定",
                    "--nocapture",
                    "--include-ignored",
                ])
                .env("AG_JAIL_LOCKDOWN_CHILD", "1")
                .output()
                .expect("spawn self");
            let so = String::from_utf8_lossy(&out.stdout);
            assert!(
                so.contains("LOCKDOWN-OK"),
                "子进程没有报告锁定生效:\nstdout={so}\nstderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// 由上面那条在子进程里调用。装上过滤器,然后确认 `mount` 真的被拒。
    #[test]
    #[ignore]
    fn 子进程内验证挂载锁定() {
        if std::env::var("AG_JAIL_LOCKDOWN_CHILD").is_err() {
            return;
        }
        // 装之前 mount 应当因为**权限**而失败(EPERM,因为我们不在 userns 里),
        // 装之后应当同样是 EPERM —— 所以这条测试要区分的是"过滤器装上了"这件事本身。
        match install_mount_lockdown() {
            Ok(()) => {}
            Err(e) => {
                // 环境不允许装 seccomp(例如外层已有更严的过滤器)。如实报告,不假装成功。
                println!("LOCKDOWN-UNAVAILABLE: {e}");
                return;
            }
        }
        // 过滤器装上之后,unshare 必须是 EPERM。在没有过滤器时,一个非特权进程在允许
        // 非特权 userns 的内核上是**可以** unshare(CLONE_NEWUSER) 的,所以这一条能区分。
        let r = unsafe { syscall5(SYS_UNSHARE, CLONE_NEWUSER, 0, 0, 0, 0) };
        assert_eq!(r, -1, "过滤器装上之后 unshare 仍然成功(返回 {r})");
        println!("LOCKDOWN-OK");
    }
}
