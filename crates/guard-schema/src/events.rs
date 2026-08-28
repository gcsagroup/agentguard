//! Unified GuardEvent / Decision types consumed by adapters and the core engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ScreenFrame,
    UiTreeDelta,
    ProcessFocus,
    NetworkFlow,
    ClipboardChange,
    AgentSessionStart,
    AgentSessionEnd,
    FormFill,
    Deeplink,
    PermissionRequest,
    MemoryWrite,
    /// Later-session read/use of a saved preference (MyPhoneBench memory axis).
    MemoryRead,
    /// Report on the *environment* the agent is running in rather than an action
    /// it took: other apps that can intercept its input or read its text.
    /// Covers (A)I Sees A5 (broadcast input interception) and A6 (credential
    /// sniffing via a foreign accessibility service).
    EnvironmentSurvey,
    /// The agent computed a new value from existing ones. Carries `value_id` and
    /// a comma-separated `parents`, and is what makes Aura's dependency
    /// inheritance possible: without it a derived value is untracked and
    /// launders whatever it was built from.
    DataDerive,
    /// 智能体要写一个文件（B1）。
    ///
    /// # 为什么这三个类型是分开的
    ///
    /// `docs/scope-and-non-goals.md` 的第一条理由就是"没有文件系统事件类型"，于是引擎
    /// 从来看不到文件操作，也就不可能对一次删除有意见。加上它们之后，路径判决第一次进入
    /// 规则引擎，也第一次进入**签名审计记录**——在这之前网关拒绝了一次删除，但那次拒绝
    /// 没有可归属的记录。
    ///
    /// 读**不**在这里。一次读的判决（凭据目录）仍然只发生在网关那一层：给读也造一个事件
    /// 类型会让每一次 `read_file` 都进审计，而审计记录是要签名和长期保存的，一个正常
    /// 工作负载会把它塞满，塞满之后没人看。这是刻意的取舍，不是遗漏。
    ///
    /// `path` 必须在 metadata 里，且必须是**已归约的绝对路径**。引擎会用
    /// `guard_schema::paths` 自己再判一次包含关系，而不是相信事件里带来的任何结论。
    FileWrite,
    /// 智能体要删一个文件或目录（B1）。
    FileDelete,
    /// 智能体要执行一个程序（B1）。
    ///
    /// `argv0` 在 metadata 里。这个类型存在的意义不是判 argv0 本身（那是 shell 策略的事），
    /// 而是让"这次会话执行了几次程序"能被计入计划预算（`PLAN-OVER-BUDGET` 的 `run_shell`）。
    ProcessExec,
    /// The agent is moving a value into a sink (an app field, a host, the
    /// clipboard, a shell argument, a critical action). Checked against the
    /// taint lattice: this is where No-Write-Down is enforced.
    DataFlow,
    /// A human lowered a value's label (Aura HITL declassification). The only
    /// downward move in the lattice, and always recorded.
    Declassify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvent {
    pub event_id: String,
    pub timestamp_ms: i64,
    pub platform: String,
    pub event_type: EventType,
    pub source_app: String,
    #[serde(default)]
    pub agent_context_id: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl EventType {
    /// 稳定的字符串名,和 serde 的 `rename_all = "snake_case"` 完全一致。
    ///
    /// 存在的理由:适配器断言的签名要绑定事件类型
    /// ([`crate::adapter::adapter_assertion_message`])。用 `serde_json` 序列化拿这个
    /// 名字也行,但那会让一个**签名消息**的内容依赖 serde 的实现细节;写出来更好读,
    /// 而且下面那条测试保证两者不会漂。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScreenFrame => "screen_frame",
            Self::UiTreeDelta => "ui_tree_delta",
            Self::ProcessFocus => "process_focus",
            Self::NetworkFlow => "network_flow",
            Self::ClipboardChange => "clipboard_change",
            Self::AgentSessionStart => "agent_session_start",
            Self::AgentSessionEnd => "agent_session_end",
            Self::FormFill => "form_fill",
            Self::Deeplink => "deeplink",
            Self::PermissionRequest => "permission_request",
            Self::MemoryWrite => "memory_write",
            Self::MemoryRead => "memory_read",
            Self::EnvironmentSurvey => "environment_survey",
            Self::DataDerive => "data_derive",
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::ProcessExec => "process_exec",
            Self::DataFlow => "data_flow",
            Self::Declassify => "declassify",
        }
    }
}

#[cfg(test)]
mod event_type_tests {
    use super::*;

    /// `as_str` 必须和 serde 给出的名字逐字一致。
    ///
    /// 没有这条测试,手写的名字和 serde 的名字可以静默分叉 —— 而它们分叉的后果是
    /// 一个跨进程的签名验不过,并且只在那一个事件类型上验不过。
    #[test]
    fn as_str_和_serde_一致() {
        for v in [
            EventType::ScreenFrame,
            EventType::UiTreeDelta,
            EventType::ProcessFocus,
            EventType::NetworkFlow,
            EventType::ClipboardChange,
            EventType::AgentSessionStart,
            EventType::AgentSessionEnd,
            EventType::FormFill,
            EventType::Deeplink,
            EventType::PermissionRequest,
            EventType::MemoryWrite,
            EventType::MemoryRead,
            EventType::EnvironmentSurvey,
            EventType::DataDerive,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::ProcessExec,
            EventType::DataFlow,
            EventType::Declassify,
        ] {
            let via_serde = serde_json::to_string(&v).unwrap();
            let via_serde = via_serde.trim_matches('"');
            assert_eq!(v.as_str(), via_serde, "{v:?} 的名字不一致");
        }
    }

    /// 每个名字都不一样 —— 否则两个事件类型会共用一个签名域。
    #[test]
    fn 名字互不相同() {
        let all = [
            EventType::ScreenFrame,
            EventType::UiTreeDelta,
            EventType::ProcessFocus,
            EventType::NetworkFlow,
            EventType::ClipboardChange,
            EventType::AgentSessionStart,
            EventType::AgentSessionEnd,
            EventType::FormFill,
            EventType::Deeplink,
            EventType::PermissionRequest,
            EventType::MemoryWrite,
            EventType::MemoryRead,
            EventType::EnvironmentSurvey,
            EventType::DataDerive,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::ProcessExec,
            EventType::DataFlow,
            EventType::Declassify,
        ];
        let mut names: Vec<&str> = all.iter().map(|v| v.as_str()).collect();
        names.sort_unstable();
        let n = names.len();
        names.dedup();
        assert_eq!(names.len(), n, "有重名的事件类型");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    Allow,
    Alert,
    Block,
    LogOnly,
}

/// 情报判定"这个主机是恶意域"时用的 rule_id。
pub const INTEL_DOMAIN_RULE_ID: &str = "INTEL-DOMAIN";
/// 恶意域判决 `human_message` 的前缀,后面紧跟被拦的主机名。
///
/// 这是一个**共享契约**:生产端(`guard-core` 发这条判决)和消费端(`guard-nm-host` 要把主机名
/// 抠出来喂给浏览器 DNR 名单,让"引擎判恶意 → 浏览器网络层硬拦"这条链接上)都引用它。措辞一改,
/// 两边一起改——编译期就能发现,不会一端悄悄改了措辞、另一端解析出空。
pub const MALICIOUS_DOMAIN_MSG_PREFIX: &str = "Malicious domain blocked: ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: DecisionAction,
    pub severity: Severity,
    pub rule_id: String,
    pub human_message: String,
    pub require_confirm: bool,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            action: DecisionAction::Allow,
            severity: Severity::Info,
            rule_id: "ALLOW".into(),
            human_message: "Allowed".into(),
            require_confirm: false,
        }
    }
}
