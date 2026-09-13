//! 受保护会话、不可变动作、批准绑定和执行回执的版本化契约。
//!
//! 本模块只检查数据形状、完整性和绑定关系，不认证用户、不授予权限、不实施隔离。
//! 可反序列化的会话、来源或批准记录均不能充当授权凭据；宿主必须独立取得授权范围、
//! 认证批准通道，并在执行前原子消费随机值、复核策略与实际目标。敏感参数的完整快照
//! 用于执行与确认，持久审计必须另外脱敏，不能直接保存 `canonical_bytes()`。

use crate::TaskScope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

pub const EXECUTION_CONTRACT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("执行契约字段 {field} 无效：{reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("执行契约尚未生效")]
    NotYetValid,
    #[error("执行契约已到期")]
    Expired,
    #[error("批准绑定与当前动作不一致")]
    BindingMismatch,
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ContractError {
    ContractError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn required_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid(field, "必须非空、无首尾空白且不含控制字符"));
    }
    Ok(())
}

fn validate_version(version: u16) -> Result<(), ContractError> {
    if version != EXECUTION_CONTRACT_VERSION {
        return Err(invalid("contract_version", "不支持此版本"));
    }
    Ok(())
}

fn validate_window(issued_at_ms: i64, expires_at_ms: i64) -> Result<(), ContractError> {
    if issued_at_ms < 0 || expires_at_ms <= issued_at_ms {
        return Err(invalid("expires_at_ms", "期限必须晚于非负的签发时间"));
    }
    Ok(())
}

fn validate_at(issued_at_ms: i64, expires_at_ms: i64, now_ms: i64) -> Result<(), ContractError> {
    if now_ms < issued_at_ms {
        return Err(ContractError::NotYetValid);
    }
    if now_ms >= expires_at_ms {
        return Err(ContractError::Expired);
    }
    Ok(())
}

fn lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_nonce(nonce: &str) -> Result<(), ContractError> {
    if !(32..=128).contains(&nonce.len()) || !nonce.len().is_multiple_of(2) || !lowercase_hex(nonce)
    {
        return Err(invalid("nonce", "须为 16～64 字节的小写十六进制随机值"));
    }
    // 长度与编码不能证明随机性；随机值必须由宿主安全随机源生成。
    Ok(())
}

/// 经格式校验的标识符；值本身不证明身份或授权。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedId(String);

impl ValidatedId {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        required_text("id", &value)?;
        if value.len() > 256 {
            return Err(invalid("id", "长度不能超过 256 字节"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ValidatedId {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ValidatedId> for String {
    fn from(value: ValidatedId) -> Self {
        value.0
    }
}

impl fmt::Display for ValidatedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 摘要仅检查编码；内容摘要必须由可信读取入口或执行器重新计算。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if value.len() != 64 || !lowercase_hex(&value) {
            return Err(invalid("sha256", "须为 64 个小写十六进制字符"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Active,
    Stopped,
    Closed,
}

/// 覆盖声明需要真实执行证据；反序列化为 `Isolated` 不会建立隔离环境。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementCoverage {
    ObservationOnly,
    GatewayControlled,
    Isolated,
    Unavailable,
}

/// 宿主持有的会话记录；`granted_scope` 必须来自控制面，不能采纳客户端自报范围。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContract {
    pub contract_version: u16,
    pub session_id: ValidatedId,
    pub principal_id: ValidatedId,
    pub policy_version: ValidatedId,
    pub granted_scope: TaskScope,
    pub coverage: EnforcementCoverage,
    pub state: SessionState,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl SessionContract {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_version(self.contract_version)?;
        validate_window(self.issued_at_ms, self.expires_at_ms)?;
        self.granted_scope
            .validate(self.session_id.as_str())
            .map_err(|error| invalid("granted_scope", error.to_string()))
    }

    /// 仅检查已持有会话的状态和时间，不将输入数据转换为授权会话。
    pub fn validate_active_at(&self, now_ms: i64) -> Result<(), ContractError> {
        self.validate()?;
        if self.state != SessionState::Active {
            return Err(invalid("state", "会话未处于活动状态"));
        }
        validate_at(self.issued_at_ms, self.expires_at_ms, now_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub service: String,
    pub name: String,
    pub version: String,
}

impl ToolIdentity {
    fn validate(&self) -> Result<(), ContractError> {
        required_text("tool.service", &self.service)?;
        required_text("tool.name", &self.name)?;
        required_text("tool.version", &self.version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEntryPoint {
    FileRead,
    BrowserRead,
    ToolOutput,
    UserInput,
}

/// 没有 `trusted: true` 字段；来源描述不得提升动作权限。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceObservation {
    Observed {
        entry: SourceEntryPoint,
        content_sha256: Sha256Digest,
        parser_version: String,
        parent_source_ids: Vec<ValidatedId>,
    },
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceObject {
    pub source_id: ValidatedId,
    pub observation: SourceObservation,
}

impl SourceObject {
    pub fn validate(&self) -> Result<(), ContractError> {
        match &self.observation {
            SourceObservation::Observed {
                parser_version,
                parent_source_ids,
                ..
            } => {
                required_text("source.parser_version", parser_version)?;
                let mut seen = HashSet::new();
                for parent in parent_source_ids {
                    if parent == &self.source_id || !seen.insert(parent) {
                        return Err(invalid("source.parent_source_ids", "父来源重复或指向自身"));
                    }
                }
                Ok(())
            }
            SourceObservation::Unknown { reason } => required_text("source.reason", reason),
        }
    }
}

/// 构造输入可修改；只有通过 `ActionSnapshot::new` 后的只读快照可用于绑定。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub contract_version: u16,
    pub session_id: ValidatedId,
    pub action_id: ValidatedId,
    pub request_id: ValidatedId,
    pub tool: ToolIdentity,
    /// 最终目标的展示值；路径句柄、重定向等执行时校验仍由执行器负责。
    pub target: String,
    /// 经工具解析后的完整参数对象，包括写入正文；禁止用字节数代替正文参与绑定。
    pub parameters: Value,
    pub policy_version: ValidatedId,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    /// 空表示尚未附带来源；不能解释为可信或无风险。
    pub sources: Vec<SourceObject>,
}

impl ActionSpec {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_version(self.contract_version)?;
        self.tool.validate()?;
        required_text("target", &self.target)?;
        if !self.parameters.is_object() {
            return Err(invalid("parameters", "须为经工具解析后的 JSON 对象"));
        }
        validate_window(self.issued_at_ms, self.expires_at_ms)?;
        validate_nonce(&self.nonce)?;
        let mut seen = HashSet::new();
        for source in &self.sources {
            source.validate()?;
            if !seen.insert(&source.source_id) {
                return Err(invalid("sources", "来源标识符重复"));
            }
        }
        Ok(())
    }
}

/// 不暴露可变引用；反序列化同样经过完整校验，不为缺失关键字段补默认值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ActionSpec", into = "ActionSpec")]
pub struct ActionSnapshot(ActionSpec);

impl ActionSnapshot {
    pub fn new(spec: ActionSpec) -> Result<Self, ContractError> {
        spec.validate()?;
        Ok(Self(spec))
    }

    pub fn spec(&self) -> &ActionSpec {
        &self.0
    }

    pub fn validate_at(&self, now_ms: i64) -> Result<(), ContractError> {
        validate_at(self.0.issued_at_ms, self.0.expires_at_ms, now_ms)
    }

    /// 固定版本域与递归排序的 JSON 字节，可由网关做 SHA-256；不是通用 RFC 8785 实现。
    /// 字符串、数组顺序和数字表示保持原样，不做可能改变工具行为的文本归一化。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn sort(value: Value) -> Value {
            match value {
                Value::Object(map) => {
                    let mut entries: Vec<_> = map.into_iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    Value::Object(
                        entries
                            .into_iter()
                            .map(|(key, value)| (key, sort(value)))
                            .collect(),
                    )
                }
                Value::Array(values) => Value::Array(values.into_iter().map(sort).collect()),
                other => other,
            }
        }
        let value = serde_json::to_value(&self.0).expect("动作契约仅包含可序列化的 JSON 类型");
        let mut bytes = b"agentguard.execution.action.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&sort(value)).expect("规范动作 JSON 可序列化"));
        bytes
    }
}

impl TryFrom<ActionSpec> for ActionSnapshot {
    type Error = ContractError;
    fn try_from(spec: ActionSpec) -> Result<Self, Self::Error> {
        Self::new(spec)
    }
}

impl From<ActionSnapshot> for ActionSpec {
    fn from(snapshot: ActionSnapshot) -> Self {
        snapshot.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalSpec {
    approval_id: ValidatedId,
    action: ActionSnapshot,
    nonce: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

/// 批准请求的完整绑定；持有此对象不代表批准已认证或已被单次消费。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ApprovalSpec", into = "ApprovalSpec")]
pub struct ApprovalBinding(ApprovalSpec);

impl ApprovalBinding {
    pub fn new(
        approval_id: ValidatedId,
        action: ActionSnapshot,
        nonce: String,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<Self, ContractError> {
        validate_nonce(&nonce)?;
        validate_window(issued_at_ms, expires_at_ms)?;
        if issued_at_ms < action.spec().issued_at_ms || expires_at_ms > action.spec().expires_at_ms
        {
            return Err(invalid(
                "approval.expires_at_ms",
                "批准期限不能超出动作期限",
            ));
        }
        Ok(Self(ApprovalSpec {
            approval_id,
            action,
            nonce,
            issued_at_ms,
            expires_at_ms,
        }))
    }

    pub fn action(&self) -> &ActionSnapshot {
        &self.0.action
    }

    pub fn approval_id(&self) -> &ValidatedId {
        &self.0.approval_id
    }

    pub fn nonce(&self) -> &str {
        &self.0.nonce
    }

    pub fn expires_at_ms(&self) -> i64 {
        self.0.expires_at_ms
    }

    /// 只验证绑定，不验证批准者身份，也不维护随机值已消费集合。
    pub fn validate_for_action(
        &self,
        action: &ActionSnapshot,
        now_ms: i64,
    ) -> Result<(), ContractError> {
        if self.action() != action {
            return Err(ContractError::BindingMismatch);
        }
        action.validate_at(now_ms)?;
        validate_at(self.0.issued_at_ms, self.0.expires_at_ms, now_ms)
    }
}

impl TryFrom<ApprovalSpec> for ApprovalBinding {
    type Error = ContractError;
    fn try_from(spec: ApprovalSpec) -> Result<Self, Self::Error> {
        Self::new(
            spec.approval_id,
            spec.action,
            spec.nonce,
            spec.issued_at_ms,
            spec.expires_at_ms,
        )
    }
}

impl From<ApprovalBinding> for ApprovalSpec {
    fn from(binding: ApprovalBinding) -> Self {
        binding.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChoice {
    Approved,
    Denied,
}

/// 控制面审计记录，不能作为客户端提交的执行通行证。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub binding: ApprovalBinding,
    pub choice: ApprovalChoice,
    pub actor_id: ValidatedId,
    pub decided_at_ms: i64,
}

impl ApprovalRecord {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.binding
            .validate_for_action(self.binding.action(), self.decided_at_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Success,
    Refused,
    Cancelled,
    TimedOut,
    /// 执行器或工具明确报错；结合是否发出区分启动失败与已有部分副作用。
    Failed,
    /// 无法确定终态或实际副作用；不得据此自动重试原动作。
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    NotDispatched,
    Dispatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectStatus {
    NoneObserved,
    Observed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub evidence_id: ValidatedId,
    pub location: String,
    pub sha256: Sha256Digest,
}

impl EvidenceReference {
    pub fn validate(&self) -> Result<(), ContractError> {
        required_text("evidence.location", &self.location)
    }
}

/// 回执将判决与实际执行分开；结果可信度取决于写入者和证据采集，不取决于 JSON 字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub contract_version: u16,
    pub session_id: ValidatedId,
    pub action_id: ValidatedId,
    pub approval_id: Option<ValidatedId>,
    pub outcome: ExecutionOutcome,
    pub dispatch_state: DispatchState,
    pub started_at_ms: Option<i64>,
    pub completed_at_ms: i64,
    pub side_effects: SideEffectStatus,
    pub detail: String,
    pub evidence: Vec<EvidenceReference>,
}

impl ExecutionReceipt {
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_version(self.contract_version)?;
        if self.completed_at_ms < 0 {
            return Err(invalid("completed_at_ms", "不能为负数"));
        }
        if let Some(started) = self.started_at_ms {
            if started < 0 || started > self.completed_at_ms {
                return Err(invalid("started_at_ms", "须在回执时间之前且非负"));
            }
        }
        match self.dispatch_state {
            DispatchState::NotDispatched => {
                if self.started_at_ms.is_some()
                    || self.side_effects != SideEffectStatus::NoneObserved
                {
                    return Err(invalid(
                        "dispatch_state",
                        "未发出动作不能有开始时间或副作用声明",
                    ));
                }
                if matches!(
                    self.outcome,
                    ExecutionOutcome::Success | ExecutionOutcome::Unknown
                ) {
                    return Err(invalid("outcome", "未发出动作不能记执行成功或结果未知"));
                }
            }
            DispatchState::Dispatched => {
                if self.started_at_ms.is_none() || self.outcome == ExecutionOutcome::Refused {
                    return Err(invalid(
                        "dispatch_state",
                        "已发出动作须有开始时间，且不能记作未执行拒绝",
                    ));
                }
            }
        }
        if self.outcome == ExecutionOutcome::Unknown
            && self.side_effects != SideEffectStatus::Unknown
        {
            return Err(invalid("side_effects", "结果未知时不能断言副作用已经核实"));
        }
        if self.detail.trim().is_empty() {
            return Err(invalid("detail", "回执说明不能为空"));
        }
        let mut seen = HashSet::new();
        for evidence in &self.evidence {
            evidence.validate()?;
            if !seen.insert(&evidence.evidence_id) {
                return Err(invalid("evidence", "证据标识符重复"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id(value: &str) -> ValidatedId {
        ValidatedId::new(value).unwrap()
    }

    fn action() -> ActionSnapshot {
        ActionSnapshot::new(ActionSpec {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("session-1"),
            action_id: id("action-1"),
            request_id: id("request-1"),
            tool: ToolIdentity {
                service: "gateway".into(),
                name: "write_file".into(),
                version: "1.0.0-rc.1".into(),
            },
            target: "/workspace/报告.txt".into(),
            parameters: json!({"path":"/workspace/报告.txt", "contents":"第一行\n第二行"}),
            policy_version: id("policy-1"),
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            nonce: "ab".repeat(16),
            sources: vec![SourceObject {
                source_id: id("source-1"),
                observation: SourceObservation::Unknown {
                    reason: "读取入口尚未接入".into(),
                },
            }],
        })
        .unwrap()
    }

    fn binding() -> ApprovalBinding {
        ApprovalBinding::new(id("approval-1"), action(), "cd".repeat(16), 1100, 1900).unwrap()
    }

    fn receipt(outcome: ExecutionOutcome) -> ExecutionReceipt {
        let dispatched = matches!(
            outcome,
            ExecutionOutcome::Success | ExecutionOutcome::Failed | ExecutionOutcome::Unknown
        );
        ExecutionReceipt {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("session-1"),
            action_id: id("action-1"),
            approval_id: None,
            outcome,
            dispatch_state: if dispatched {
                DispatchState::Dispatched
            } else {
                DispatchState::NotDispatched
            },
            started_at_ms: dispatched.then_some(1200),
            completed_at_ms: 1400,
            side_effects: if outcome == ExecutionOutcome::Unknown {
                SideEffectStatus::Unknown
            } else {
                SideEffectStatus::NoneObserved
            },
            detail: "代表性回执".into(),
            evidence: vec![],
        }
    }

    #[test]
    fn 动作与批准可往返且保留中文正文() {
        let snapshot = action();
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<ActionSnapshot>(&bytes).unwrap(),
            snapshot
        );
        assert!(String::from_utf8(snapshot.canonical_bytes())
            .unwrap()
            .contains("第一行\\n第二行"));
        let original = binding();
        assert_eq!(
            serde_json::from_value::<ApprovalBinding>(serde_json::to_value(&original).unwrap())
                .unwrap(),
            original
        );
    }

    #[test]
    fn 每个动作必需字段缺失均拒绝() {
        let full = serde_json::to_value(action()).unwrap();
        for key in full.as_object().unwrap().keys() {
            let mut incomplete = full.clone();
            incomplete.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<ActionSnapshot>(incomplete).is_err(),
                "缺少 {key} 应拒绝"
            );
        }
    }

    #[test]
    fn 每个批准必需字段缺失均拒绝() {
        let full = serde_json::to_value(binding()).unwrap();
        for key in full.as_object().unwrap().keys() {
            let mut incomplete = full.clone();
            incomplete.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<ApprovalBinding>(incomplete).is_err(),
                "缺少 {key} 应拒绝"
            );
        }
    }

    #[test]
    fn 畸形关键字段不能反序列化为快照() {
        for (field, value) in [
            ("session_id", json!("")),
            ("request_id", json!("\n伪造")),
            ("action_id", json!(" action")),
            ("policy_version", json!("")),
            ("contract_version", json!(2)),
            ("target", json!(" ")),
            ("parameters", Value::Null),
            ("parameters", json!([])),
            ("issued_at_ms", json!(-1)),
            ("expires_at_ms", json!(1000)),
            ("nonce", json!("12")),
            ("nonce", json!("CD".repeat(16))),
        ] {
            let mut value_json = serde_json::to_value(action()).unwrap();
            value_json[field] = value;
            assert!(
                serde_json::from_value::<ActionSnapshot>(value_json).is_err(),
                "{field} 畸形应拒绝"
            );
        }
        for field in ["service", "name", "version"] {
            let mut value = serde_json::to_value(action()).unwrap();
            value["tool"][field] = json!("");
            assert!(serde_json::from_value::<ActionSnapshot>(value).is_err());
        }
    }

    #[test]
    fn 自报批准或信任字段不能混入动作() {
        let mut value = serde_json::to_value(action()).unwrap();
        value["approved"] = json!(true);
        assert!(serde_json::from_value::<ActionSnapshot>(value).is_err());
        let mut value = serde_json::to_value(action()).unwrap();
        value["sources"][0]["trusted"] = json!(true);
        assert!(serde_json::from_value::<ActionSnapshot>(value).is_err());
    }

    #[test]
    fn 参数键顺序不影响绑定字节且数组顺序仍有意义() {
        let mut first = action().spec().clone();
        first.parameters = serde_json::from_str(r#"{"b":{"y":2,"x":1},"a":[1,2]}"#).unwrap();
        let mut second = first.clone();
        second.parameters = serde_json::from_str(r#"{"a":[1,2],"b":{"x":1,"y":2}}"#).unwrap();
        let first = ActionSnapshot::new(first).unwrap();
        assert_eq!(
            first.canonical_bytes(),
            ActionSnapshot::new(second.clone())
                .unwrap()
                .canonical_bytes()
        );
        second.parameters["a"] = json!([2, 1]);
        assert_ne!(
            first.canonical_bytes(),
            ActionSnapshot::new(second).unwrap().canonical_bytes()
        );
    }

    #[test]
    fn 任一绑定字段替换均需新批准() {
        let original = action();
        let full = serde_json::to_value(&original).unwrap();
        for (field, value) in [
            ("session_id", json!("session-2")),
            ("action_id", json!("action-2")),
            ("request_id", json!("request-2")),
            ("policy_version", json!("policy-2")),
            ("target", json!("/workspace/其他.txt")),
            (
                "parameters",
                json!({"path":"/workspace/报告.txt","contents":"另一段相同长度正文"}),
            ),
            ("nonce", json!("ef".repeat(16))),
            ("expires_at_ms", json!(2100)),
            ("issued_at_ms", json!(900)),
        ] {
            let mut changed = full.clone();
            changed[field] = value;
            let changed = serde_json::from_value::<ActionSnapshot>(changed).unwrap();
            assert_ne!(original.canonical_bytes(), changed.canonical_bytes());
            assert_eq!(
                binding().validate_for_action(&changed, 1200),
                Err(ContractError::BindingMismatch)
            );
        }
        for field in ["service", "name", "version"] {
            let mut changed = full.clone();
            changed["tool"][field] = json!("replacement");
            let changed = serde_json::from_value::<ActionSnapshot>(changed).unwrap();
            assert_eq!(
                binding().validate_for_action(&changed, 1200),
                Err(ContractError::BindingMismatch)
            );
        }
    }

    #[test]
    fn 同字节数正文替换也改变绑定() {
        let mut original = action().spec().clone();
        original.parameters = json!({"contents":"safe"});
        let mut changed = original.clone();
        changed.parameters = json!({"contents":"evil"});
        assert_ne!(
            ActionSnapshot::new(original).unwrap().canonical_bytes(),
            ActionSnapshot::new(changed).unwrap().canonical_bytes()
        );
    }

    #[test]
    fn 生效时刻和截止时刻均有明确边界() {
        assert_eq!(action().validate_at(999), Err(ContractError::NotYetValid));
        assert!(action().validate_at(1000).is_ok());
        assert_eq!(action().validate_at(2000), Err(ContractError::Expired));
        assert_eq!(
            binding().validate_for_action(&action(), 1099),
            Err(ContractError::NotYetValid)
        );
        assert!(binding().validate_for_action(&action(), 1100).is_ok());
        assert_eq!(
            binding().validate_for_action(&action(), 1900),
            Err(ContractError::Expired)
        );
    }

    #[test]
    fn 批准不能延长动作期限() {
        for (issued, expires) in [(900, 1900), (1100, 2100), (1200, 1200)] {
            assert!(ApprovalBinding::new(
                id("approval"),
                action(),
                "cd".repeat(16),
                issued,
                expires
            )
            .is_err());
        }
    }

    #[test]
    fn 来源缺失可表达而重复或伪造摘要被拒绝() {
        assert!(action().spec().sources[0].validate().is_ok());
        let mut spec = action().spec().clone();
        spec.sources.push(spec.sources[0].clone());
        assert!(ActionSnapshot::new(spec).is_err());
        for invalid in ["", "A".repeat(64).as_str(), "0".repeat(63).as_str()] {
            assert!(Sha256Digest::new(invalid).is_err());
        }
        let source = SourceObject {
            source_id: id("s"),
            observation: SourceObservation::Observed {
                entry: SourceEntryPoint::FileRead,
                content_sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
                parser_version: "text/1".into(),
                parent_source_ids: vec![id("s")],
            },
        };
        assert!(source.validate().is_err());
    }

    #[test]
    fn 六种结果均能表达且工具失败不等于拒绝() {
        for (outcome, name) in [
            (ExecutionOutcome::Success, "success"),
            (ExecutionOutcome::Refused, "refused"),
            (ExecutionOutcome::Cancelled, "cancelled"),
            (ExecutionOutcome::TimedOut, "timed_out"),
            (ExecutionOutcome::Failed, "failed"),
            (ExecutionOutcome::Unknown, "unknown"),
        ] {
            let receipt = receipt(outcome);
            receipt.validate().unwrap();
            let value = serde_json::to_value(&receipt).unwrap();
            assert_eq!(value["outcome"], name);
            assert_eq!(
                serde_json::from_value::<ExecutionReceipt>(value).unwrap(),
                receipt
            );
        }
    }

    #[test]
    fn 回执不能把已发出动作写成拒绝或把未知写成无副作用() {
        let mut invalid = receipt(ExecutionOutcome::Success);
        invalid.outcome = ExecutionOutcome::Refused;
        assert!(invalid.validate().is_err());
        let mut launch_failure = receipt(ExecutionOutcome::Refused);
        launch_failure.outcome = ExecutionOutcome::Failed;
        assert!(launch_failure.validate().is_ok());
        let mut invalid = receipt(ExecutionOutcome::Unknown);
        invalid.side_effects = SideEffectStatus::NoneObserved;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn 取消或超时后允许记录已发生的部分副作用() {
        for outcome in [ExecutionOutcome::Cancelled, ExecutionOutcome::TimedOut] {
            let mut partial = receipt(outcome);
            partial.dispatch_state = DispatchState::Dispatched;
            partial.started_at_ms = Some(1200);
            partial.side_effects = SideEffectStatus::Observed;
            partial.validate().unwrap();
        }
    }

    #[test]
    fn 会话复用范围校验并拒绝非活动或过期状态() {
        let mut session = SessionContract {
            contract_version: EXECUTION_CONTRACT_VERSION,
            session_id: id("session-1"),
            principal_id: id("operator-1"),
            policy_version: id("policy-1"),
            granted_scope: TaskScope::default(),
            coverage: EnforcementCoverage::GatewayControlled,
            state: SessionState::Active,
            issued_at_ms: 1000,
            expires_at_ms: 2000,
        };
        session.validate_active_at(1200).unwrap();
        session.state = SessionState::Stopped;
        assert!(session.validate_active_at(1200).is_err());
        session.state = SessionState::Active;
        assert_eq!(
            session.validate_active_at(2000),
            Err(ContractError::Expired)
        );
        session.granted_scope.apps = Some(vec!["".into()]);
        assert!(session.validate().is_err());
    }

    #[test]
    fn 批准审计字段不认证行为主体且仍须验证期限() {
        let mut record = ApprovalRecord {
            binding: binding(),
            choice: ApprovalChoice::Approved,
            actor_id: id("独立控制面操作员"),
            decided_at_ms: 1200,
        };
        record.validate().unwrap();
        record.decided_at_ms = 1900;
        assert_eq!(record.validate(), Err(ContractError::Expired));
    }

    #[test]
    fn 浏览器共享样例与rust动作和批准契约一致() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../apps/protected-browser/fixtures/action-contract-v1.json"
        ))
        .unwrap();
        let action: ActionSnapshot = serde_json::from_value(fixture["action"].clone()).unwrap();
        let approval: ApprovalBinding =
            serde_json::from_value(fixture["approval"].clone()).unwrap();
        assert_eq!(
            action.canonical_bytes(),
            fixture["expected_canonical_utf8"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        approval
            .validate_for_action(&action, 1_800_000_001_000)
            .unwrap();
        assert_eq!(serde_json::to_value(&action).unwrap(), fixture["action"]);
        let mut changed = action.spec().clone();
        changed.parameters["body"] = json!("替换后的正文");
        assert_eq!(
            approval.validate_for_action(&ActionSnapshot::new(changed).unwrap(), 1_800_000_001_000),
            Err(ContractError::BindingMismatch)
        );
    }
}
