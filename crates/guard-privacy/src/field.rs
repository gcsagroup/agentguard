//! Field observation model replacing MyPhoneBench form_drafts SQLite reads.

use guard_schema::DataTier;
use serde::{Deserialize, Serialize};

/// Privacy probe layout types from MyPhoneBench methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeType {
    /// Bait chain: optional HIGH after required LOW → over-permissioning.
    OverPermissioning,
    /// Marketing / VIP widget re-asking known PII → trap resistance.
    TrapResistance,
    /// Optional personal field between required fields → form minimization.
    FormMinimization,
}

/// Necessity class for graduated over-permissioning penalties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldNecessity {
    Required,
    Plausible,
    Unnecessary,
    Forbidden,
}

/// Where the value an agent put into a field came from — MyPhoneBench iMy `ask_user`(§2.2)
/// 落到守卫这一侧的形状。
///
/// iMy 给智能体四个契约工具,第四个是 `ask_user`:缺一个个人信息值时**问用户**,而不是编。
/// 守卫看不见模型的内部,分不出"这个生日是用户说的"和"这个生日是模型编的"——只有宿主
/// (把引擎嵌进智能体运行时的那一方)知道。所以 provenance 是**宿主声明**的,和 `data_flow`
/// 的 `value_id` 标签同一个信任模型:守卫核对宿主说的话之间是否一致,不核对宿主有没有说谎。
///
/// 三个值:
/// * `user` —— 用户给的:回答了一次 `user_query`,或写在原始任务指令里;
/// * `memory` —— 从用户批准过的记忆里读的(`memory_write` 已批准 + `memory_read`);
/// * `generated` —— 模型自己产生的。HIGH 层键上这就是"编出来的个人信息",`PRIV-GUESS`。
///
/// **不知道就不要带**这个字段。一个从无障碍树 / DOM 抓填表的适配器没有 provenance 可声明,
/// 省略即可,判决与以前完全一样;不要为了"填个值"写 `generated`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSource {
    User,
    Memory,
    Generated,
}

impl ValueSource {
    /// 解析事件 metadata 里的 `value_source`。大小写不敏感;认不出的值是 `None`,不是猜一个。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" | "user_answer" | "task_input" => Some(Self::User),
            "memory" | "profile" => Some(Self::Memory),
            "generated" | "model" | "guess" | "guessed" => Some(Self::Generated),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Memory => "memory",
            Self::Generated => "generated",
        }
    }
}

/// 一次 `user_query`:智能体问了用户什么、结果如何。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClarificationEvent {
    /// 问的是哪个个人信息键(`profile_key`);宿主没给就是空串。
    pub key: String,
    pub outcome: ClarificationOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationOutcome {
    /// 问了,还没有回答(或宿主不报告回答)。
    Asked,
    /// 用户给了值。
    Answered,
    /// 用户拒绝提供。此后这个键上出现 `generated` 的填写,是"用户说不、智能体编了一个"——
    /// 比单纯的 guess 更该被点名。
    Declined,
}

impl ClarificationOutcome {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "answered" | "provided" => Self::Answered,
            "declined" | "refused" => Self::Declined,
            _ => Self::Asked,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asked => "asked",
            Self::Answered => "answered",
            Self::Declined => "declined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedField {
    pub field_id: String,
    pub label: String,
    pub profile_key: String,
    pub required: bool,
    pub tier: DataTier,
    pub probe_type: Option<ProbeType>,
    pub value_filled: bool,
    pub necessity: FieldNecessity,
    /// 宿主声明的取值来源(见 [`ValueSource`])。`None` = 宿主没说,判决不受影响。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_source: Option<ValueSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub item_key: String,
    pub tier: DataTier,
    /// Whether access was granted (or only attempted).
    pub granted: bool,
    pub necessity: FieldNecessity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFillEvent {
    pub field: ObservedField,
    /// True when the widget is a privacy trap (non-essential re-collection).
    pub is_trap: bool,
}

/// User-controlled memory save (MyPhoneBench iMy `save_profile` analogue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySaveEvent {
    pub key: String,
    /// True when the save was permitted by contract / confirmed by the user.
    pub approved: bool,
}

/// Later-session use of a saved preference (MyPhoneBench paired-task axis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUseEvent {
    pub key: String,
    /// Whether the used key matches what the later task actually needed
    /// (ground truth from paired evaluation), when known.
    pub correct: bool,
}

/// Taint marker: HIGH-tier data observed in `app` (Aura cross-app pivoting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintMark {
    pub profile_key: String,
    pub app: String,
}
