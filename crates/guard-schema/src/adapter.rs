//! 适配器断言签名:让"适配器说的话"变成可验证的,而不是任凭本机进程伪造。
//!
//! # 这解决的是哪个洞
//!
//! 引擎的一部分输入不是它自己观察到的,而是**适配器告诉它的**:环境调查的结果、
//! 浮层标记、显示身份读取是否失败。这些字段是从事件的 metadata 里读的,而事件的入口
//! (`api-serve` 的 `/v1/events`、FFI)在这之前只有一道 bearer 令牌 —— FFI 连令牌都没有。
//!
//! 于是本机任何拿到令牌的进程都能伪造一份适配器断言。**伪造的方向里最坏的一个**是:
//! 伪造一份 `env_surveyed=true`、四张风险清单全空的环境调查,把一个已经锁存的
//! Critical 风险清掉。完整调查会**覆盖**锁存状态 —— 那是它存在的意义,也是这个洞的形状。
//!
//! # 为什么不是"所有事件都必须签名"
//!
//! 因为那会立刻把产品变成不可用的:已发布的适配器一个都不签,打开强制验签等于拒掉
//! 全部输入。而一个装上去就把东西拦死的守卫会被卸掉,那时保护是零。这是本项目反复
//! 撞到的教训 —— **把"更严"当成"更安全"本身就是一种失效模式**。
//!
//! # 真正的规则是非对称的
//!
//! > **未经验证的适配器断言只能增加风险,永远不能移除风险。**
//!
//! 这条规则不需要任何开关就默认安全:
//!
//!   - 伪造一份"有风险"的断言,攻击者只能给自己制造一次误报 —— 没有收益。
//!   - 伪造一份"干净"的断言,才是攻击;而它现在做不到,因为清除锁存需要一个验证过的签名。
//!   - 现存的不签名适配器照常工作,它们只是**不能清风险**了。
//!
//! 也就是说,这一层的强制力方向和其它层都不同:它不拦事件,它只决定这个事件的话
//! **算不算证据**。
//!
//! # 失败往哪边倒
//!
//! 签名验不过、时间窗口不对、注册表里没有这个适配器 —— 全部退化成"未签名",
//! 也就是今天的行为(可以加风险,不能清风险),而**不是**拒绝这个事件。
//!
//! 这是刻意的:适配器的时钟偏移、注册表还没配、旧版本适配器,都不该让守卫瞎掉。
//! 一个把输入拒光的守卫,和一个没装的守卫,效果一样。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::events::GuardEvent;

/// 携带签名的两个 metadata 字段。
///
/// 它们本身不进签名消息 —— 一个签名不能签自己。排除是按名字做的,而且是**这两个常量**,
/// 不是"任何看起来像签名的字段":后者会让签名的覆盖范围随字段命名习惯漂移。
pub const ADAPTER_ID_FIELD: &str = "adapter_id";
pub const ADAPTER_SIG_FIELD: &str = "adapter_sig";

/// 断言的新鲜度窗口(毫秒)。
///
/// 两分钟。选这个数是因为它要同时容忍两件事:适配器和守卫之间的时钟偏移,
/// 以及中继(`adb reverse`)的排队延迟。窗口太紧的后果不是"更安全"而是
/// "签名永远验不过",于是所有断言都退化成未签名 —— 机制静默失效。
///
/// 窗口之外不是拒绝,是"未签名"。见模块注释里的失败方向。
pub const FRESHNESS_WINDOW_MS: i64 = 120_000;

/// 每个适配器记住多少个已用过的 event_id。
///
/// 有界,而且是按适配器分的 —— 和 agent nonce 的窗口同一个理由:一个无界的集合
/// 是一条内存耗尽路径,而一个全局共享的集合让一个适配器能挤掉另一个的记录。
pub const REPLAY_WINDOW: usize = 4096;

/// 中继路径上那三个 HTTP 头的名字。
///
/// # 为什么要有常量
///
/// 这三个名字以前在 Kotlin(`RelayClient.kt`)和 Rust(`guard-localapi`)各写一遍
/// 字面量,**两侧都没有任何测试钉住它们**。改掉一侧的一个字母,生产会静默退化成
/// `Unsigned` —— 也就是"签名静默地永远验不过"那个失败形状,而全部测试是绿的。
///
/// 跨语言向量整套机制就是为了防这件事而存在的,却漏掉了头名本身。
/// 一次独立对抗性复核指出来的。Kotlin 侧那三个字面量由
/// `crates/guard-cli/tests/仓库不变量.rs` 对着这里比。
pub const ADAPTER_HEADER_ID: &str = "X-AgentGuard-Adapter";
pub const ADAPTER_HEADER_TIMESTAMP: &str = "X-AgentGuard-Timestamp";
pub const ADAPTER_HEADER_SIGNATURE: &str = "X-AgentGuard-Signature";

/// 一张适配器身份卡。
///
/// `deny_unknown_fields` 不是洁癖:没有它,`publickey:`(少一个下划线)会**干净地
/// 加载成一张没有公钥的卡** —— 运维以为这张卡在强制什么,实际上它什么都不强制,
/// 而 preflight 也只会说"这张卡没钉公钥"。一次独立对抗性复核指出来的。
///
/// 策略文件是信任输入的入口。在这里,一个打错的字段名和"故意不填"在语义上是
/// 两件完全不同的事,而 serde 默认把它们混成一件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCard {
    /// 适配器自称的 id。
    pub adapter_id: String,
    #[serde(default)]
    pub display_name: String,
    /// 公钥的十六进制。长度由 [`AdapterCard::key_algorithm`] 决定:
    /// Ed25519 是 64 位(32 字节),ECDSA P-256 是 130 位(65 字节 SEC1 未压缩)。
    ///
    /// 没有公钥的卡永远验不过。这被报成注册表的缺口,而不是"这个适配器不需要证明" ——
    /// 后者正是应用注册表在 `signers` 为空时犯过的错。
    #[serde(default)]
    pub public_key: Option<String>,
    /// 签名算法名。默认 `ed25519`(向后兼容已经写好的卡)。
    ///
    /// # 为什么是一个独立字段,而不是从公钥长度推
    ///
    /// 长度确实能区分这两种,所以"推"能跑。但那是**算法混淆**这一类漏洞的标准入口:
    /// 验证方按自己推出来的算法去验,而攻击者控制着那个用来推的字段。加载时会校验
    /// 声明和长度一致,不一致是**加载失败**,不是运行时惊喜。
    ///
    /// # 为什么需要第二种算法
    ///
    /// Android 伴生应用的 `minSdk = 26`,而 `java.security` 的 Ed25519 要 API 33。
    /// 要么在手机上自带一份 Ed25519 实现(在一个安全产品里手搓密码学),要么用
    /// 平台从 API 1 就有的 ECDSA P-256。后者还有一个更强的好处:走 Android Keystore
    /// 时私钥可以留在 TEE / StrongBox 里,**根本不出硬件** —— 比一个软件密钥文件强。
    ///
    /// 这个字段留在 guard-schema(不带任何 crypto 依赖)里是**字符串**,
    /// 由 `guard_audit::KeyAlgorithm::parse` 解析。schema crate 刻意不引密码库。
    #[serde(default = "default_key_algorithm")]
    pub key_algorithm: String,
    /// 这个适配器可以声称的平台。空表示"任意"。
    ///
    /// 存在的理由:Android 伴生应用没有理由发一个 `platform: macos` 的事件。
    /// 把它钉住,一把泄露的 Android 密钥就不能用来伪造 macOS 侧的断言。
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

fn default_key_algorithm() -> String {
    "ed25519".to_string()
}

impl AdapterCard {
    /// 这张卡钉的公钥是不是一把私钥公开的已知密钥。
    ///
    /// 和 agent 注册表共用同一张表:那张表管的是"本仓库发布出去的 Ed25519 公钥",
    /// 和它被用在哪一种身份上无关。一把假钥匙在这里同样不能证明任何事。
    pub fn publicly_known_key(&self) -> Option<&'static str> {
        self.public_key
            .as_deref()
            .and_then(crate::publicly_known_agent_key)
    }

    /// 这张卡可不可以声称这个平台。
    pub fn may_claim_platform(&self, platform: &str) -> bool {
        self.platforms.is_empty() || self.platforms.iter().any(|p| p == platform)
    }
}

/// 适配器注册表。
///
/// 刻意**没有** `require_signature` 这样的开关。理由在模块注释里:强制验签会把产品
/// 变成不可用,而真正需要的那条保证(未验证的断言不能清风险)不需要开关就成立。
/// 少一个开关就少一处可以被配置错的地方。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterRegistry {
    #[serde(default)]
    pub adapters: Vec<AdapterCard>,
}

impl AdapterRegistry {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, crate::PolicyError> {
        let reg: Self = serde_yaml::from_str(yaml)?;
        reg.validate()?;
        Ok(reg)
    }

    fn validate(&self) -> Result<(), crate::PolicyError> {
        let mut seen = std::collections::HashSet::new();
        for a in &self.adapters {
            if a.adapter_id.trim() != a.adapter_id || a.adapter_id.trim().is_empty() {
                return Err(crate::PolicyError::Invalid(format!(
                    "适配器 id {:?} 不能为空、也不能带首尾空白",
                    a.adapter_id
                )));
            }
            if !seen.insert(a.adapter_id.clone()) {
                return Err(crate::PolicyError::Invalid(format!(
                    "适配器 id '{}' 重复;查表会拿到哪一张卡取决于顺序",
                    a.adapter_id
                )));
            }
            // 算法名先认出来。不认识的算法名是**加载失败**,不是默默退回默认值 ——
            // 一张写错算法的卡按错的算法去验,正是算法混淆。
            let want_hex = match a.key_algorithm.trim().to_ascii_lowercase().as_str() {
                "ed25519" => 64,
                "ecdsa-p256" | "ecdsap256" | "p256" => 130,
                other => {
                    return Err(crate::PolicyError::Invalid(format!(
                        "'{}' 的 key_algorithm '{other}' 不认识;支持 ed25519 或 ecdsa-p256",
                        a.adapter_id
                    )))
                }
            };
            if let Some(k) = &a.public_key {
                let k = k.trim();
                if k.len() != want_hex || !k.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(crate::PolicyError::Invalid(format!(
                        "'{}' 声明的是 {},公钥应为 {want_hex} 位十六进制,实际 {} 位",
                        a.adapter_id,
                        a.key_algorithm.trim(),
                        k.len()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn card(&self, adapter_id: &str) -> Option<&AdapterCard> {
        let want = adapter_id.trim();
        self.adapters.iter().find(|a| a.adapter_id == want)
    }

    /// 所有钉了"假钥匙"的卡:`(adapter_id, 出处)`。给 `preflight` 用。
    pub fn publicly_known_key_cards(&self) -> Vec<(&str, &'static str)> {
        self.adapters
            .iter()
            .filter_map(|c| {
                c.publicly_known_key()
                    .map(|why| (c.adapter_id.as_str(), why))
            })
            .collect()
    }
}

/// 一次适配器断言的验证结论。
///
/// 只有 [`AdapterIdentity::Verified`] 让这个事件的话可以用在**移除风险**的方向上。
/// 其余每一种都等价于"未签名" —— 可以加风险,不能清风险。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterIdentity {
    /// 签名验过,平台对得上,时间新鲜,event_id 没被用过。
    Verified { adapter_id: String },
    /// 事件没带 `adapter_sig`。绝大多数事件都是这一种 —— 不是攻击。
    Unsigned,
    /// 带了签名但注册表里没有这个 id。
    Unregistered { adapter_id: String },
    /// 注册表里有卡但没有公钥,验证不可能。
    NoKeyOnRecord { adapter_id: String },
    /// 注册表钉的是一把私钥公开的密钥 —— 签名有效,但证明不了任何事。
    PubliclyKnownKey {
        adapter_id: String,
        provenance: String,
    },
    /// 签名不对。有人在冒充这个适配器。
    BadSignature { adapter_id: String },
    /// 这个适配器不允许声称这个平台。
    PlatformNotPermitted {
        adapter_id: String,
        platform: String,
    },
    /// 时间戳在新鲜度窗口之外(可能是重放,也可能只是时钟偏了)。
    Stale { adapter_id: String, skew_ms: i64 },
    /// 这个 `(adapter_id, event_id)` 已经出现过。一份被重放的断言。
    Replayed {
        adapter_id: String,
        event_id: String,
    },
    /// `event_id` 是空的或渲染出来是空白 —— 签名于是绑不住任何一个事件,
    /// 同一串字节对每一个"无名事件"都验得过。
    UnanchoredEvent { adapter_id: String },
}

impl AdapterIdentity {
    /// 这个事件的话能不能用在**移除风险**的方向上。
    ///
    /// 这是整个模块唯一对外要紧的谓词。它刻意只对一个变体为真:任何
    /// "我不确定"都必须落在保守的那一边。
    pub fn may_clear_risk(&self) -> bool {
        // 和 `may_grant_trust` 是**同一条规则**,只有一处定义。
        // 分成两个名字是为了让两处调用点各自读得通,而不是为了两套语义。
        self.may_grant_trust()
    }

    /// 这个适配器说的话,能不能**授予**信任。
    ///
    /// 只有 `Verified` 能。这一条同时管两件事,因为它们本来就是一件事:
    ///
    ///   - 能不能移除一个已锁存的环境风险(`may_clear_risk`);
    ///   - 它转发的应用签名摘要,能不能把一个应用判成 `Verified`。
    ///
    /// 第二条是后加的,而漏掉它曾经是一个洞:应用签名证书摘要是**公开**的,
    /// 从发布的应用里就能提出来 —— 它是标识符,不是秘密。于是"事件里带了正确的
    /// 摘要"这件事,任何拿到 API 令牌的调用方都做得到。那正是 AgentScan 那个包名
    /// 伪造,只换了一层:从"攻击者随便填一个包名"变成"攻击者填一个查得到的摘要"。
    ///
    /// 摘要有证明力的前提,是它由一个**已验证的适配器**送进来 —— 那种适配器是去问
    /// 操作系统的(Android `GET_SIGNING_CERTIFICATES`、macOS
    /// `SecCodeCopySigningInformation`),而 agent 伪造不了操作系统的回答。
    /// 一个转发 agent 递过来的摘要的适配器,什么都没证明。
    pub fn may_grant_trust(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// 证据**积极地反对**这个身份声明 —— 也就是有人在冒充。
    ///
    /// 和 `!may_clear_risk()` 不是一回事:`Unsigned` 不是冒充,它是常态。
    /// 区分这两者的意义在于,冒充值得报出来,而未签名不值得 ——
    /// 一个每个事件都报一次的告警等于没有告警。
    pub fn is_impersonation(&self) -> bool {
        matches!(
            self,
            Self::BadSignature { .. } | Self::PlatformNotPermitted { .. } | Self::Replayed { .. }
        )
    }

    pub fn adapter_id(&self) -> Option<&str> {
        match self {
            Self::Verified { adapter_id }
            | Self::Unregistered { adapter_id }
            | Self::NoKeyOnRecord { adapter_id }
            | Self::PubliclyKnownKey { adapter_id, .. }
            | Self::BadSignature { adapter_id }
            | Self::PlatformNotPermitted { adapter_id, .. }
            | Self::Stale { adapter_id, .. }
            | Self::Replayed { adapter_id, .. }
            | Self::UnanchoredEvent { adapter_id } => Some(adapter_id),
            Self::Unsigned => None,
        }
    }

    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "ADAPTER-VERIFIED",
            Self::Unsigned => "ADAPTER-UNSIGNED",
            Self::Unregistered { .. } => "ADAPTER-UNREGISTERED",
            Self::NoKeyOnRecord { .. } => "ADAPTER-NO-KEY",
            Self::PubliclyKnownKey { .. } => "ADAPTER-KEY-PUBLICLY-KNOWN",
            Self::BadSignature { .. } => "ADAPTER-BAD-SIGNATURE",
            Self::PlatformNotPermitted { .. } => "ADAPTER-PLATFORM-NOT-PERMITTED",
            Self::Stale { .. } => "ADAPTER-STALE",
            Self::Replayed { .. } => "ADAPTER-REPLAY",
            Self::UnanchoredEvent { .. } => "ADAPTER-EVENT-UNANCHORED",
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Self::Verified { adapter_id } => {
                format!("断言由 '{adapter_id}' 签名并验证通过")
            }
            Self::Unsigned => {
                "事件没有适配器签名,所以它的断言只能增加风险,不能移除风险".into()
            }
            Self::Unregistered { adapter_id } => format!(
                "'{adapter_id}' 不在适配器注册表里,无法验证它的断言"
            ),
            Self::NoKeyOnRecord { adapter_id } => format!(
                "'{adapter_id}' 在注册表里但没有公钥,验证不可能"
            ),
            Self::PubliclyKnownKey {
                adapter_id,
                provenance,
            } => format!(
                "'{adapter_id}' 的签名验过了,但注册表为它钉的公钥私钥半边是公开的({provenance}),任何人都能产生同一个签名。用 `agentguard adapter-keygen` 换一对新密钥。"
            ),
            Self::BadSignature { adapter_id } => format!(
                "事件自称来自 '{adapter_id}',但签名对不上它注册的公钥 —— 有人在冒充这个适配器"
            ),
            Self::PlatformNotPermitted {
                adapter_id,
                platform,
            } => format!(
                "'{adapter_id}' 的签名有效,但它的卡不允许它声称平台 '{platform}'"
            ),
            Self::Stale { adapter_id, skew_ms } => format!(
                "'{adapter_id}' 的断言时间戳偏离 {skew_ms}ms,超出 {FRESHNESS_WINDOW_MS}ms 的新鲜度窗口;可能是重放,也可能只是时钟偏了"
            ),
            Self::Replayed {
                adapter_id,
                event_id,
            } => format!(
                "'{adapter_id}' 为事件 '{event_id}' 出示的断言之前已经出现过;一份被捕获的断言正在被重放"
            ),
            Self::UnanchoredEvent { adapter_id } => format!(
                "'{adapter_id}' 为一个没有 id 的事件签名;那串字节绑不住任何具体事件,对每一个无名事件都验得过"
            ),
        }
    }
}

/// 一个 `event_id` 是否真的**指向**一个事件。
///
/// 和 [`crate::is_anchored_session_id`] 同一条规则、同一个理由:签名绑的是
/// `event_id`,一个渲染出来是空白的 id 绑不住任何东西 —— 同一串签名字节会对
/// 每一个带着同样"非 id"的事件验证通过。
pub fn is_anchored_event_id(event_id: &str) -> bool {
    crate::is_anchored_session_id(event_id)
}

/// 适配器断言要签的那串字节。
///
/// # 为什么签整个事件,而不是挑出"宽松方向"的那几个字段
///
/// 挑字段签更小、更好读,但它要求每加一个宽松方向的字段就同步改签名逻辑,
/// 而**漏掉一个就是一个静默的洞**。签整个事件之后,签名覆盖的是"这个事件的全部内容",
/// 于是以后无论哪个字段被判定为宽松方向,它都已经在签名里了。
///
/// # 规范化
///
/// metadata 是 `HashMap`,迭代顺序不确定,所以必须**按键排序**之后再进消息 ——
/// 否则同一个事件在签名方和验证方会算出不同的字节,签名时好时坏。
/// 有一条测试专门用不同的插入顺序构造同一个事件,断言字节一致。
///
/// 每一段都带 4 字节大端长度前缀,和 `session_attestation_message` 一样:
/// 没有分隔符,于是值里出现任何字符都不会造成歧义。
/// (一个用分隔符的方案里,`a=1\x1fb=2` 和 `a=1\x1fb` + `=2` 会撞在一起。)
///
/// `adapter_id` / `adapter_sig` 两个字段被排除 —— 一个签名不能签自己。
/// 进签名消息的那几个字段。
///
/// 用具名结构而不是八个位置参数,理由是**位置参数在这里是可以静默出错的**:
/// `platform` 和 `source_app` 都是 `&str`,调换顺序编译得过,表现是签名永远
/// 验不过 —— 而那看起来像"验签坏了",不像"参数写反了"。
#[derive(Debug, Clone, Copy)]
pub struct AssertionFields<'a> {
    pub adapter_id: &'a str,
    pub event_id: &'a str,
    pub timestamp_ms: i64,
    pub platform: &'a str,
    pub event_type: &'a str,
    pub source_app: &'a str,
    pub agent_context_id: &'a str,
}

pub fn adapter_assertion_message(
    f: AssertionFields<'_>,
    metadata: &HashMap<String, String>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"AGENTGUARD-ADAPTER-ASSERTION-v1");

    let ts = f.timestamp_ms.to_string();
    for f in [
        f.adapter_id,
        f.event_id,
        ts.as_str(),
        f.platform,
        f.event_type,
        f.source_app,
        f.agent_context_id,
    ] {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }

    let mut keys: Vec<&str> = metadata
        .keys()
        .map(String::as_str)
        .filter(|k| *k != ADAPTER_ID_FIELD && *k != ADAPTER_SIG_FIELD)
        .collect();
    keys.sort_unstable();

    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for k in keys {
        let v = metadata.get(k).map(String::as_str).unwrap_or("");
        out.extend_from_slice(&(k.len() as u32).to_be_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

/// 对适配器**实际发出的那串字节**签名 —— 中继路径用的就是这一个。
///
/// # 为什么中继路径不能用逐事件签名
///
/// 这不是偏好,是硬约束。Android 伴生应用通过 `adb reverse` 发的是一个信封 JSON;
/// 桌面侧的 `AndroidAdapter::convert_event` 重建 `GuardEvent` 时,`event_id` 用的是
/// **桌面自己的序号**(`and-{seq}`),`timestamp_ms` 用的是**桌面自己的时钟**。
/// 手机侧无从知道这两个值,所以它签不出一个能对上重建结果的签名 ——
/// 一个逐事件签名的设计在这条唯一的生产中继上会静默地永远验不过。
///
/// 所以签的是**线上那串字节**:适配器写了什么就签什么。这同时消掉了整个
/// "JSON 规范化"陷阱 —— 不需要对 JSON 排序、不需要约定空白,因为验证方拿到的
/// 就是同一串原始字节。
///
/// 签名和时间戳走 **HTTP 头**,不进 body。把签名塞进它自己要签的 JSON 里,
/// 就必须先规范化那个 JSON,而那是这个设计刻意绕开的东西。
///
/// `format_tag` 命名 body 的格式(比如 `"android-envelope"`)。它进签名是为了
/// 让一个格式的签名不能被当作另一个格式的 —— 同一串字节在两种解析器下含义不同。
pub fn adapter_body_message(
    adapter_id: &str,
    format_tag: &str,
    timestamp_ms: i64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 128);
    out.extend_from_slice(b"AGENTGUARD-ADAPTER-BODY-v1");
    let ts = timestamp_ms.to_string();
    for f in [adapter_id, format_tag, ts.as_str()] {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Android 信封的 `format_tag`,以及它允许声称的平台。
pub const ANDROID_ENVELOPE_FORMAT: &str = "android-envelope";

/// 从一个 [`GuardEvent`] 算出它的断言消息。
///
/// 签名方和验证方都走这一条,所以两边不可能对"要签什么"有分歧 ——
/// 这个项目栽过的坑里有一类就是同一份逻辑在两处各写了一遍
/// (`AppFace.kt` 的哈希至今还写着"重新实现而非共享")。
pub fn assertion_message_for(event: &GuardEvent, adapter_id: &str) -> Vec<u8> {
    adapter_assertion_message(
        AssertionFields {
            adapter_id,
            event_id: &event.event_id,
            timestamp_ms: event.timestamp_ms,
            platform: &event.platform,
            event_type: event.event_type.as_str(),
            source_app: &event.source_app,
            agent_context_id: event.agent_context_id.as_deref().unwrap_or(""),
        },
        &event.metadata,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventType;

    fn ev(meta: &[(&str, &str)]) -> GuardEvent {
        GuardEvent {
            event_id: "e1".into(),
            timestamp_ms: 1_700_000_000_000,
            platform: "android".into(),
            event_type: EventType::EnvironmentSurvey,
            source_app: "Companion".into(),
            agent_context_id: Some("s1".into()),
            metadata: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// 规范化必须和 `HashMap` 的迭代顺序无关。
    ///
    /// 没有这条测试,签名会**时好时坏**:同一个事件在签名方和验证方各自的
    /// HashMap 顺序下算出不同的字节。这种缺陷最坏的地方是它偶发 ——
    /// 单跑一次测试大概率是过的。所以这里放足够多的键(HashMap 在少量键时
    /// 顺序常常恰好一致),并且用两种截然不同的插入顺序。
    #[test]
    fn 规范化不依赖map顺序() {
        let pairs: Vec<(String, String)> = (0..24)
            .map(|i| (format!("k{i:02}"), format!("v{i}")))
            .collect();
        let forward: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut backward = forward.clone();
        backward.reverse();

        let a = assertion_message_for(&ev(&forward), "android-companion");
        let b = assertion_message_for(&ev(&backward), "android-companion");
        assert_eq!(a, b, "同一个事件,不同插入顺序,签名消息必须一致");
        assert!(a.len() > 100, "消息看起来太短,可能没把 metadata 放进去");
    }

    /// 签名字段本身不进消息 —— 一个签名不能签自己。
    #[test]
    fn 签名字段被排除在消息之外() {
        let bare = assertion_message_for(&ev(&[("env_surveyed", "true")]), "a");
        let signed = assertion_message_for(
            &ev(&[
                ("env_surveyed", "true"),
                (ADAPTER_ID_FIELD, "a"),
                (ADAPTER_SIG_FIELD, &"0".repeat(128)),
            ]),
            "a",
        );
        assert_eq!(bare, signed);
    }

    /// 长度前缀的意义:值里的内容不会跨字段"串味"。
    ///
    /// 用分隔符的方案在这里会撞:`k1="a"` + `k2="b"` 和 `k1="a<sep>k2b"` 会
    /// 产生同一串字节,于是一个签名可以被重新解读成另一组字段。
    #[test]
    fn 相邻字段不会串味() {
        let a = assertion_message_for(&ev(&[("k1", "a"), ("k2", "b")]), "x");
        let b = assertion_message_for(&ev(&[("k1", "ak2b")]), "x");
        assert_ne!(a, b);
        let c = assertion_message_for(&ev(&[("k1k2", "ab")]), "x");
        assert_ne!(a, c);
    }

    /// 每一个被绑定的字段改动都必须改变消息。
    ///
    /// 逐个字段测,而不是"改点什么看看变不变":漏掉一个字段就意味着一个有效签名
    /// 可以被搬到另一个事件上。`platform` 那一项尤其要紧 —— 它是平台冒充的入口。
    #[test]
    fn 每个绑定字段都进了消息() {
        let base = ev(&[("env_surveyed", "true")]);
        let msg = assertion_message_for(&base, "a");

        let mut e = base.clone();
        e.event_id = "e2".into();
        assert_ne!(assertion_message_for(&e, "a"), msg, "event_id 没进消息");

        let mut e = base.clone();
        e.timestamp_ms += 1;
        assert_ne!(assertion_message_for(&e, "a"), msg, "timestamp 没进消息");

        let mut e = base.clone();
        e.platform = "macos".into();
        assert_ne!(assertion_message_for(&e, "a"), msg, "platform 没进消息");

        let mut e = base.clone();
        e.event_type = EventType::UiTreeDelta;
        assert_ne!(assertion_message_for(&e, "a"), msg, "event_type 没进消息");

        let mut e = base.clone();
        e.source_app = "Other".into();
        assert_ne!(assertion_message_for(&e, "a"), msg, "source_app 没进消息");

        let mut e = base.clone();
        e.agent_context_id = Some("s2".into());
        assert_ne!(
            assertion_message_for(&e, "a"),
            msg,
            "agent_context_id 没进消息"
        );

        let mut e = base.clone();
        e.metadata
            .insert("foreign_a11y_services".into(), "evil".into());
        assert_ne!(assertion_message_for(&e, "a"), msg, "metadata 没进消息");

        assert_ne!(
            assertion_message_for(&base, "b"),
            msg,
            "adapter_id 没进消息"
        );
    }

    /// body 签名要绑定 format_tag:同一串字节在两种解析器下含义不同。
    #[test]
    fn body消息绑定格式标签() {
        let b = b"{}";
        let a = adapter_body_message("x", "android-envelope", 1, b);
        let c = adapter_body_message("x", "browser-batch", 1, b);
        assert_ne!(a, c);
    }

    /// body 的长度前缀让"body 的尾部"和"下一个字段"分得开。
    ///
    /// 没有它的话,`ts=1` + `body="2{}"` 和 `ts=12` + `body="{}"` 会算出同一串字节。
    #[test]
    fn body长度前缀防止边界歧义() {
        let a = adapter_body_message("x", "f", 1, b"2{}");
        let b = adapter_body_message("x", "f", 12, b"{}");
        assert_ne!(a, b);
    }

    /// `may_clear_risk` 只对 `Verified` 为真 —— 任何"我不确定"都落在保守一边。
    ///
    /// 逐个变体列出来,而不是只测两三个:以后新加一个变体,这条测试不会自动覆盖它,
    /// 但至少会在有人改动语义时炸掉。
    #[test]
    fn 只有verified能清风险() {
        let cases = [
            (
                AdapterIdentity::Verified {
                    adapter_id: "a".into(),
                },
                true,
            ),
            (AdapterIdentity::Unsigned, false),
            (
                AdapterIdentity::Unregistered {
                    adapter_id: "a".into(),
                },
                false,
            ),
            (
                AdapterIdentity::NoKeyOnRecord {
                    adapter_id: "a".into(),
                },
                false,
            ),
            (
                AdapterIdentity::PubliclyKnownKey {
                    adapter_id: "a".into(),
                    provenance: "x".into(),
                },
                false,
            ),
            (
                AdapterIdentity::BadSignature {
                    adapter_id: "a".into(),
                },
                false,
            ),
            (
                AdapterIdentity::PlatformNotPermitted {
                    adapter_id: "a".into(),
                    platform: "macos".into(),
                },
                false,
            ),
            (
                AdapterIdentity::Stale {
                    adapter_id: "a".into(),
                    skew_ms: 999_999,
                },
                false,
            ),
            (
                AdapterIdentity::Replayed {
                    adapter_id: "a".into(),
                    event_id: "e1".into(),
                },
                false,
            ),
            (
                AdapterIdentity::UnanchoredEvent {
                    adapter_id: "a".into(),
                },
                false,
            ),
        ];
        for (id, expect) in cases {
            assert_eq!(
                id.may_clear_risk(),
                expect,
                "{} 的 may_clear_risk 不对",
                id.rule_id()
            );
            // 每一种都必须有解释,而且不能是空的:一个没有理由的判决,
            // 运维只能猜。
            assert!(!id.explain().is_empty(), "{} 没有解释", id.rule_id());
        }
    }

    /// 未签名**不是**冒充。这两者混起来会让每一个事件都报一次告警,
    /// 而一个每次都响的告警等于没有告警。
    #[test]
    fn 未签名不算冒充() {
        assert!(!AdapterIdentity::Unsigned.is_impersonation());
        assert!(!AdapterIdentity::Unregistered {
            adapter_id: "a".into()
        }
        .is_impersonation());
        assert!(AdapterIdentity::BadSignature {
            adapter_id: "a".into()
        }
        .is_impersonation());
    }

    #[test]
    fn 平台钉住之后不能跨平台声称() {
        let card = AdapterCard {
            adapter_id: "android-companion".into(),
            display_name: String::new(),
            public_key: None,
            key_algorithm: default_key_algorithm(),
            platforms: vec!["android".into()],
            notes: String::new(),
        };
        assert!(card.may_claim_platform("android"));
        assert!(!card.may_claim_platform("macos"));

        let any = AdapterCard {
            platforms: vec![],
            ..card
        };
        assert!(any.may_claim_platform("macos"), "空清单表示任意");
    }

    /// 不认识的算法名是加载失败,不是默默退回 ed25519。
    #[test]
    fn 不认识的算法名让注册表加载失败() {
        let r = AdapterRegistry::from_yaml_str(
            "adapters:\n  - adapter_id: a\n    key_algorithm: rsa\n",
        );
        assert!(r.is_err(), "写错的算法名应该拦在加载,而不是运行时");
        let msg = format!("{:?}", r.err().unwrap());
        assert!(msg.contains("rsa"), "错误信息要点名那个算法:{msg}");
    }

    /// 声明的算法和公钥长度必须对得上,不对就加载失败。
    #[test]
    fn 算法和公钥长度不符时加载失败() {
        // 声明 p256 却给了一把 32 字节的钥匙。
        let r = AdapterRegistry::from_yaml_str(&format!(
            "adapters:\n  - adapter_id: a\n    key_algorithm: ecdsa-p256\n    public_key: \"{}\"\n",
            "ab".repeat(32)
        ));
        assert!(r.is_err());
        // 反过来也一样。
        let r = AdapterRegistry::from_yaml_str(&format!(
            "adapters:\n  - adapter_id: a\n    key_algorithm: ed25519\n    public_key: \"{}\"\n",
            "ab".repeat(65)
        ));
        assert!(r.is_err());
        // 对上了就过。
        let r = AdapterRegistry::from_yaml_str(&format!(
            "adapters:\n  - adapter_id: a\n    key_algorithm: ecdsa-p256\n    public_key: \"04{}\"\n",
            "ab".repeat(64)
        ));
        assert!(r.is_ok(), "{r:?}");
    }

    /// 没写 key_algorithm 的卡默认 ed25519 —— 已经写好的卡不能因为加了这个字段就坏掉。
    #[test]
    fn 没写算法的卡默认ed25519() {
        let r = AdapterRegistry::from_yaml_str(&format!(
            "adapters:\n  - adapter_id: a\n    public_key: \"{}\"\n",
            "ab".repeat(32)
        ))
        .unwrap();
        assert_eq!(r.card("a").unwrap().key_algorithm, "ed25519");
    }

    #[test]
    fn 注册表拒绝重复id和坏公钥() {
        assert!(AdapterRegistry::from_yaml_str(
            "adapters:\n  - adapter_id: a\n  - adapter_id: a\n"
        )
        .is_err());
        assert!(AdapterRegistry::from_yaml_str(
            "adapters:\n  - adapter_id: a\n    public_key: \"zz\"\n"
        )
        .is_err());
        assert!(AdapterRegistry::from_yaml_str("adapters:\n  - adapter_id: \" a\"\n").is_err());
        let ok = AdapterRegistry::from_yaml_str(&format!(
            "adapters:\n  - adapter_id: a\n    public_key: \"{}\"\n",
            "ab".repeat(32)
        ))
        .unwrap();
        assert_eq!(ok.card("a").unwrap().adapter_id, "a");
    }

    #[test]
    fn 空白event_id不算锚定() {
        assert!(is_anchored_event_id("e1"));
        assert!(!is_anchored_event_id(""));
        assert!(!is_anchored_event_id("   "));
        assert!(!is_anchored_event_id("\u{200b}"));
        assert!(!is_anchored_event_id("-"));
    }
}
