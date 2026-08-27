//! 入站信任的**共用词汇**,不是共用的控制流。
//!
//! 设计见 `docs/入站信任.md`。这个 crate 收口三样东西,每一样都是"统一策略、不统一机制"
//! 的一个具体落点:
//!
//! 1. [`constant_time_eq`] —— 全工作区**唯一**的常数时间比较。收益不只是去重:一处实现意味着
//!    它只被审一次、被测一次,不会有一处哪天被人"优化"成 `==` 而另一处没跟上。
//! 2. [`InboundOutcome`] / [`OnUnverified`] —— 把"验过 / 降级 / 拒绝"这套处置写成类型,让每个
//!    入站面在代码里能一眼看出它选了哪一类。
//! 3. [`INBOUND_FACES`] —— 六个已知入站面的显式清册,配一条测试把每个面的 fail-closed 回归
//!    测试钉住(删掉任一条 → 清册测试红)。
//!
//! 这个 crate **刻意零依赖**,好让本来不依赖任何 `guard-*` 的 `guard-billing` 也能用它而不被
//! 拖进传递依赖。

/// 常数时间比较两段字节是否相等。
///
/// 全工作区唯一实现。令牌 / HMAC / 摘要的相等比较都必须走这里,不给计时侧信道
/// (`docs/入站信任.md` §二·4)。
///
/// 长度不同**立即**返回 `false` —— 长度本身不是秘密(它从密文/签名的编码就能看出来),
/// 泄露它不构成侧信道;真正要防的是"逐字节比较到第几个才发现不同"这条时间差,所以等长时
/// 一定走完全程再判。
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 一条入站数据验证之后该怎么处置。选哪个由 `docs/入站信任.md` §二 的方向性规则决定,
/// 并在**该面**注明理由。
///
/// 这不是要把六个面重写成一个函数(它们的信任锚来源和失败处置各不相同,见设计 §四),
/// 而是给它们一个**共同的词汇**,让 review 时能一眼看出某个面选了哪一类、以及那个选择对不对。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundOutcome<T> {
    /// 验过,可用于任何方向的决定(放行 / 清风险 / 授予 / 改配置都可以)。
    Verified(T),
    /// 没验过,但接受它最坏只会把状态推向**更保守**(如"只能加风险、清不了风险的调查")。
    /// `why` 说清为什么这个方向是安全的。
    DegradedSafe { value: T, why: &'static str },
    /// 没验过且可能**放宽**行为 —— 拒绝。`String` 是给运维的下一步。
    Refused(String),
}

impl<T> InboundOutcome<T> {
    /// 这条结果是否可以用于**任何方向**的安全决定(含放宽方向)。
    /// 只有 [`Verified`](InboundOutcome::Verified) 为真 —— 降级结果只能用于收紧方向,
    /// 拒绝结果一个方向都不能用。
    #[must_use]
    pub fn usable_for_any_decision(&self) -> bool {
        matches!(self, InboundOutcome::Verified(_))
    }
}

/// 一个入站面在验证**失败**时的处置方向(`docs/入站信任.md` §二 的方向性规则)。
///
/// 这是每个面必须显式回答的一个问题:一份**验不过**的入站数据,是拒绝、还是降级接受?
/// 规则是:只有当接受它最坏只能把状态推向"更保守"时才可以降级;只要它可能放宽行为
/// (放行 / 清风险 / 授予 / 改配置)就必须拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnUnverified {
    /// 验不过就拒绝(拒启动 / 503 / 401 / 丢弃)。六个面里的五个属于这一类。
    Refuse,
    /// 验不过降级为"未验证"接受,因为它最坏只能收紧。只有 `/v1/events` 属于这一类。
    DegradeSafe,
}

/// 清册里的一个入站面。
#[derive(Debug, Clone, Copy)]
pub struct InboundFace {
    /// 人读的名字。
    pub name: &'static str,
    /// 验证原语(仅文档,不强求统一 —— 见设计 §四"不该统一")。
    pub primitive: &'static str,
    /// 验证失败时的处置方向。
    pub on_unverified: OnUnverified,
    /// 这个面的 fail-closed 回归测试所在源文件(相对本 crate 的 `CARGO_MANIFEST_DIR`)。
    pub test_file: &'static str,
    /// 那条 fail-closed 回归测试的函数名。清册测试会去 `test_file` 里找它;删掉它 → 红。
    pub failclosed_test: &'static str,
}

/// 六个已知入站面的显式清册(`docs/入站信任.md` §一/§五)。
///
/// **这条清单是人工维护的** —— 它不能自动发现"你新加了一个入站面"(那需要污点分析,超出范围)。
/// 它能做的是:一旦某个面被登记进来,它的 fail-closed 保证就被 [`清册每个面都有fail_closed测试`]
/// 钉住,不会被后续改动悄悄摘掉。加一个新入站面时,把它登进这里并配一条 fail-closed 测试。
pub const INBOUND_FACES: &[InboundFace] = &[
    InboundFace {
        name: "情报库 ThreatBundle",
        primitive: "Ed25519 over SHA-256",
        on_unverified: OnUnverified::Refuse,
        test_file: "../guard-intel/src/lib.rs",
        failclosed_test: "有公钥时拒绝未签名",
    },
    InboundFace {
        name: "计费 webhook POST /webhook/billing",
        primitive: "HMAC-SHA256",
        on_unverified: OnUnverified::Refuse,
        test_file: "../guard-billing/src/http.rs",
        failclosed_test: "签名验证拒绝伪造",
    },
    InboundFace {
        name: "设备策略 DevicePolicy 同步",
        primitive: "Ed25519 分离签名",
        on_unverified: OnUnverified::Refuse,
        test_file: "../guard-sync/src/lib.rs",
        failclosed_test: "明文http被拒",
    },
    InboundFace {
        name: "nm-host 调用者身份",
        primitive: "身份串比对",
        on_unverified: OnUnverified::Refuse,
        test_file: "../guard-nm-host/src/main.rs",
        failclosed_test: "调用方origin默认拒绝且要对上",
    },
    InboundFace {
        name: "localapi bearer 令牌 /v1/*",
        primitive: "共享密钥(constant_time_eq)",
        on_unverified: OnUnverified::Refuse,
        test_file: "../guard-localapi/src/lib.rs",
        failclosed_test: "弱令牌不让服务器起来",
    },
    InboundFace {
        name: "localapi /v1/events 适配器断言",
        primitive: "ECDSA-P256",
        on_unverified: OnUnverified::DegradeSafe,
        test_file: "../guard-localapi/src/lib.rs",
        failclosed_test: "端到端_伪造的干净调查清不掉锁存的风险",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 常数时间比较_等长相等() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn 常数时间比较_等长不等() {
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        // 差异在第一个字节也一样判 false(不是短路)。
        assert!(!constant_time_eq(b"Xbcdef", b"abcdef"));
    }

    #[test]
    fn 常数时间比较_长度不同一律不等() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn inbound_outcome_只有verified能用于任何决定() {
        let v: InboundOutcome<u8> = InboundOutcome::Verified(1);
        let d: InboundOutcome<u8> = InboundOutcome::DegradedSafe {
            value: 1,
            why: "只能加风险",
        };
        let r: InboundOutcome<u8> = InboundOutcome::Refused("配置公钥".into());
        assert!(v.usable_for_any_decision());
        assert!(!d.usable_for_any_decision());
        assert!(!r.usable_for_any_decision());
    }

    /// 清册的**方向性**自洽:五个面验不过就拒,恰好一个面(`/v1/events`)降级 —— 这正是
    /// 设计 §二 那条方向性规则的落点。如果哪天有人把某个"放宽行为"的面改成降级,这条会红。
    #[test]
    fn 清册方向性符合设计() {
        let degrade: Vec<_> = INBOUND_FACES
            .iter()
            .filter(|f| f.on_unverified == OnUnverified::DegradeSafe)
            .map(|f| f.name)
            .collect();
        assert_eq!(
            degrade,
            vec!["localapi /v1/events 适配器断言"],
            "只有 /v1/events 允许降级接受(它只能收紧);其余面必须拒绝。实际降级面:{degrade:?}"
        );
    }

    /// 清册里每个面都得(a)登记一条 fail-closed 回归测试名,(b)那条测试在它声明的源文件里
    /// **确实存在**。删掉任一面的 fail-closed 测试(或改名却不更新清册)→ 这条红。
    ///
    /// 这是 P2 那条 `端点表与实际路由一致`(doc↔code)在安全属性上的对应物:一条**读源码**的
    /// 一致性测试,把"某个面的 fail-closed 保证还在"钉死,而不是留给下一个改代码的人自觉。
    /// 它**不能**自动发现新入站面(那要污点分析);它保证的是已登记的面不被悄悄摘掉。
    #[test]
    fn 清册每个面都有fail_closed测试() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // 反空洞:清册必须正好六个面(设计 §一 数过的六个)。新增面而不更新这里 → 红,
        // 逼着加面的人回来登记。
        assert_eq!(
            INBOUND_FACES.len(),
            6,
            "入站面清册应为六个(见 docs/入站信任.md §一);变了就更新这里和文档"
        );

        // 名字不重复,否则一条登记能冒充覆盖两个面。
        let mut names: Vec<_> = INBOUND_FACES.iter().map(|f| f.name).collect();
        names.sort_unstable();
        let uniq = names.len();
        names.dedup();
        assert_eq!(uniq, names.len(), "入站面名字有重复");

        for face in INBOUND_FACES {
            let path = root.join(face.test_file);
            let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "读不到入站面「{}」的源文件 {}:{e}",
                    face.name,
                    path.display()
                )
            });
            // 找 `fn <名>(` —— Rust 测试函数的形状。函数被删或改名 → 找不到 → 红。
            let needle = format!("fn {}(", face.failclosed_test);
            assert!(
                src.contains(&needle),
                "入站面「{}」登记的 fail-closed 测试 `{}` 在 {} 里找不到了 —— \
                 是被删了、改名了、还是清册没跟上?",
                face.name,
                face.failclosed_test,
                face.test_file
            );
        }
    }
}
