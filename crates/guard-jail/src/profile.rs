//! 从 paths 天花板生成约束规则。
//!
//! # 为什么这一层是平台无关的
//!
//! 设计文档（`docs/interception-design.md` §9）把 B2 定为"Linux 优先，因为**生成 profile 的
//! 逻辑**才是值得做对的部分，而 Landlock 是最容易做对的地方"。这个模块就是那个逻辑，它和
//! 具体用哪个内核机制无关：输入是 `TaskScope.paths`，输出是一份"哪些路径可读、哪些可写、
//! 其余一律拒绝"的规则。
//!
//! Landlock、mount namespace、`sandbox-exec` 的 SBPL、Windows 的受限令牌，都消费同一份 profile。
//! 一份 profile 四个后端，而不是四份各写一遍——后者是这个项目反复抓到的那种缺陷的温床。
//!
//! # 三条从 `narrow()` 继承来的性质
//!
//! 天花板来自会话作用域已有的机制，所以这三条不是这里重新实现的：
//!
//! 1. **没声明就是只读。** 没有 write 授权 ⇒ 整个文件系统只读。不是"允许一切"。
//! 2. **grant 是交集，永不是并集。** 进程不能通过请求扩大自己的天花板。
//! 3. **越界请求会被记录**成 `SCOPE-OVER-REQUEST`。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 网络出口天花板:允许的 TCP 端口。空 `Vec` = 一个都不许(明确的"不给")。
///
/// 只有当 [`Profile::net`] 是 `Some` 时才被强制。语义与覆盖范围见 `guard_schema::TaskNet`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetCeiling {
    /// 允许发起出站连接的 TCP 端口。
    pub connect_tcp: Vec<u16>,
    /// 允许监听/绑定的 TCP 端口。
    pub bind_tcp: Vec<u16>,
}

impl NetCeiling {
    /// 从任务计划的 `scope.net` 构造。缺的一维当作空(那一维一个端口都不放行),因为
    /// 一旦声明了 `net` 整节,语义就是"只许列出的,其余拒"——缺一维不等于那一维放开。
    pub fn from_task_net(net: &guard_schema::TaskNet) -> Self {
        let mut connect_tcp = net.connect_tcp.clone().unwrap_or_default();
        let mut bind_tcp = net.bind_tcp.clone().unwrap_or_default();
        connect_tcp.sort_unstable();
        connect_tcp.dedup();
        bind_tcp.sort_unstable();
        bind_tcp.dedup();
        Self {
            connect_tcp,
            bind_tcp,
        }
    }
}

/// 一份约束规则。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// 可读的路径。空表示**什么都不能读**（除了下面 essential 里的）。
    pub read: Vec<PathBuf>,
    /// 可写的路径。空表示整个文件系统只读。
    pub write: Vec<PathBuf>,
    /// 无论天花板怎么写都必须可读的路径。
    ///
    /// 不给这些，被约束的进程连自己都起不来：动态链接器读不到 `libc`，`/proc/self` 打不开。
    /// 一个起不来的进程和一个被约束住的进程，在使用者看来是同一件事——都是"东西坏了"——
    /// 而这种坏法会让人把约束关掉。
    pub essential_read: Vec<PathBuf>,
    /// 无论天花板怎么写都必须可写的路径。只有临时目录，而且是进程私有的那个。
    pub essential_write: Vec<PathBuf>,
    /// 网络出口天花板。`None` = **不约束网络**(jail 只管文件系统,现状);`Some` = 内核强制
    /// "只许列出的 TCP 端口,其余拒"。**opt-in**:见 `guard_schema::TaskNet` 为什么默认不是拒网。
    #[serde(default)]
    pub net: Option<NetCeiling>,
}

/// 每个 Linux 进程都需要能读的最小集合。
///
/// 刻意**不**包含 `/home`、`/root`、`/etc/shadow`。`/etc` 整个在里面是因为动态链接器要读
/// `/etc/ld.so.cache`，NSS 要读 `/etc/nsswitch.conf`——但那是**读**，`/etc` 的写在 profile 里
/// 永远不会出现（`sensitive_target` 也会拦）。
const ESSENTIAL_READ: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/proc",
    "/sys/devices/system/cpu",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
];

impl Profile {
    /// 从天花板生成。
    ///
    /// 归约失败的条目被**丢弃并报告**，不当成通配——和 `Workspace::new` 同一条理由：一条
    /// 坏掉的授权如果被当成"匹配一切"，策略错误就变成了权限放大。
    pub fn from_ceiling(read: &[String], write: &[String]) -> (Self, Vec<String>) {
        let mut rejected = Vec::new();
        // 授权里不接受相对路径，理由和 B0 一样：它会随进程的工作目录改变含义。
        let ctx = guard_schema::paths::ResolveContext {
            home: guard_schema::paths::ResolveContext::current().home,
            cwd: None,
        };
        let mut norm = |items: &[String]| -> Vec<PathBuf> {
            let mut out = Vec::new();
            for raw in items {
                match guard_schema::paths::resolve(raw, ctx.clone()) {
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
                essential_read: ESSENTIAL_READ
                    .iter()
                    .map(PathBuf::from)
                    .filter(|p| p.exists())
                    .collect(),
                essential_write: Vec::new(),
                net: None,
            },
            rejected,
        )
    }

    /// 整个文件系统是否只读。
    pub fn is_read_only(&self) -> bool {
        self.write.is_empty() && self.essential_write.is_empty()
    }

    /// 所有可写路径，含 essential。
    pub fn all_write(&self) -> Vec<&Path> {
        self.write
            .iter()
            .chain(self.essential_write.iter())
            .map(|p| p.as_path())
            .collect()
    }

    /// 所有可读路径，含可写的（能写必然能读）和 essential。
    pub fn all_read(&self) -> Vec<&Path> {
        self.read
            .iter()
            .chain(self.write.iter())
            .chain(self.essential_read.iter())
            .map(|p| p.as_path())
            .collect()
    }

    /// profile 里有没有明显自相矛盾或危险的地方。
    ///
    /// 返回的每一条都是**拒绝启动**的理由。一份说不通的 profile 不该被"尽力执行"——
    /// 部分生效的约束在使用者看来和完全生效没有区别。
    pub fn contradictions(&self) -> Vec<String> {
        let mut out = Vec::new();
        for w in &self.write {
            // 写授权落在系统目录里：这不是配置疏忽，是把约束的意义抵消掉。
            if let Some(why) =
                guard_schema::paths::sensitive_target(w, guard_schema::paths::PathIntent::Write)
            {
                out.push(format!("写授权 {:?} 本身就是敏感目标：{why}", w.display()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_test_path(name: &str) -> String {
        if cfg!(target_os = "windows") {
            format!(r"C:\AgentGuard-Test\{name}")
        } else {
            format!("/srv/{name}")
        }
    }

    fn sensitive_system_dir() -> String {
        if cfg!(target_os = "windows") {
            r"C:\Windows".into()
        } else {
            "/etc".into()
        }
    }

    #[test]
    fn 没有写授权就是整个文件系统只读() {
        // 不是"允许一切"。这是从 narrow() 继承的方向。
        let (p, rejected) = Profile::from_ceiling(&[absolute_test_path("data")], &[]);
        assert!(rejected.is_empty(), "{rejected:?}");
        assert!(p.is_read_only());
        assert!(p.all_write().is_empty());
    }

    #[test]
    fn 能写必然能读() {
        let (p, rejected) = Profile::from_ceiling(&[], &[absolute_test_path("out")]);
        assert!(rejected.is_empty(), "{rejected:?}");
        let write = p.write.first().expect("应当保留写授权").clone();
        assert!(p.all_read().iter().any(|r| *r == write));
    }

    #[test]
    fn essential_read_里没有家目录也没有影子文件() {
        // 一个把 /home 放进 essential 的 profile 等于没有约束。
        let (p, _) = Profile::from_ceiling(&[], &[]);
        for e in &p.essential_read {
            let s = e.to_string_lossy();
            assert!(!s.starts_with("/home"), "essential 里出现了 {s}");
            assert!(!s.starts_with("/root"), "essential 里出现了 {s}");
            assert_ne!(s, "/", "essential 里出现了根目录");
        }
    }

    #[test]
    fn essential_write_默认为空() {
        // 默认不给任何写。要临时目录的进程应当由调用方显式加。
        let (p, _) = Profile::from_ceiling(&[], &[]);
        assert!(p.essential_write.is_empty());
    }

    #[test]
    fn 相对路径授权被拒绝而不是按当前目录归约() {
        let (p, rejected) = Profile::from_ceiling(&[], &["build/out".into()]);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert!(p.write.is_empty());
    }

    #[test]
    fn 通配符授权被拒绝() {
        let wildcard = if cfg!(target_os = "windows") {
            r"C:\AgentGuard-Test\*".into()
        } else {
            "/srv/*".into()
        };
        let (_, rejected) = Profile::from_ceiling(&[], &[wildcard]);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
    }

    #[test]
    fn 写授权落在系统目录上是拒绝启动的理由() {
        // 这不是配置疏忽，是把约束的意义抵消掉。
        let (p, rejected) = Profile::from_ceiling(&[], &[sensitive_system_dir()]);
        assert!(rejected.is_empty(), "{rejected:?}");
        let c = p.contradictions();
        assert!(!c.is_empty(), "写 /etc 应当被判为矛盾");
        assert!(c[0].contains("敏感"), "{c:?}");
    }

    #[test]
    fn 普通工作区不产生矛盾() {
        // 反面用例。没有这一条，上面那条可能只是"什么都判成矛盾"。
        let (p, rejected) = Profile::from_ceiling(&[], &[absolute_test_path("ordinary-workspace")]);
        assert!(rejected.is_empty(), "{rejected:?}");
        assert!(p.contradictions().is_empty(), "{:?}", p.contradictions());
    }

    #[test]
    fn from_ceiling_默认不约束网络() {
        // 现状不变:不碰 net 的 profile 网络维是 None(不管),不是"拒一切"。
        let (p, _) = Profile::from_ceiling(&["/data".into()], &[]);
        assert!(p.net.is_none());
    }

    #[test]
    fn 网络天花板去重并排序() {
        let net = guard_schema::TaskNet {
            connect_tcp: Some(vec![443, 80, 443]),
            bind_tcp: None,
        };
        let c = NetCeiling::from_task_net(&net);
        assert_eq!(c.connect_tcp, vec![80, 443], "应去重并排序");
        // 缺的 bind 维当作空:声明了 net 就是"只许列出的",缺一维不等于放开那一维。
        assert!(c.bind_tcp.is_empty(), "缺的一维必须是空(拒),不是放开");
    }
}
