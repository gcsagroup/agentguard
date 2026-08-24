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

    #[test]
    fn 没有写授权就是整个文件系统只读() {
        // 不是"允许一切"。这是从 narrow() 继承的方向。
        let (p, rejected) = Profile::from_ceiling(&["/srv/data".into()], &[]);
        assert!(rejected.is_empty(), "{rejected:?}");
        assert!(p.is_read_only());
        assert!(p.all_write().is_empty());
    }

    #[test]
    fn 能写必然能读() {
        let (p, _) = Profile::from_ceiling(&[], &["/srv/out".into()]);
        assert!(p.all_read().iter().any(|r| *r == Path::new("/srv/out")));
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
        let (_, rejected) = Profile::from_ceiling(&[], &["/srv/*".into()]);
        assert_eq!(rejected.len(), 1, "{rejected:?}");
    }

    #[test]
    fn 写授权落在系统目录上是拒绝启动的理由() {
        // 这不是配置疏忽，是把约束的意义抵消掉。
        let (p, _) = Profile::from_ceiling(&[], &["/etc".into()]);
        let c = p.contradictions();
        assert!(!c.is_empty(), "写 /etc 应当被判为矛盾");
        assert!(c[0].contains("敏感"), "{c:?}");
    }

    #[test]
    fn 普通工作区不产生矛盾() {
        // 反面用例。没有这一条，上面那条可能只是"什么都判成矛盾"。
        let (p, _) = Profile::from_ceiling(&[], &["/tmp/agentguard-work".into()]);
        assert!(p.contradictions().is_empty(), "{:?}", p.contradictions());
    }
}
