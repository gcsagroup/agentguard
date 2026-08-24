//! MCP 的 stdio 传输与 JSON-RPC 2.0 编解码。
//!
//! # 为什么手写而不引 SDK
//!
//! 需要的协议面很小——`initialize`、`tools/list`、`tools/call`，加上通知的忽略——而这一层的
//! 每一个错误分支都必须**fail-closed**。引一个 SDK 意味着把"解析失败时会发生什么"交给别人
//! 的默认值，而这一层解析失败时的正确行为是拒绝，不是重试、不是忽略。
//!
//! # 行分隔 JSON，而不是 Content-Length 分帧
//!
//! MCP 的 stdio 传输是每行一个 JSON 对象。这里就按这个来：`BufRead::read_line` 收，
//! `println!` 发。没有 `Content-Length` 头（那是 LSP 的形状，MCP stdio 不用）。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// 本网关宣称实现的协议版本。
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// 一条进来的请求。
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    /// 通知没有 id。没有 id 的东西不回响应。
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 错误码。`-32000` 之后是留给应用的区段。
pub mod code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// 网关拒绝执行。**不是**协议错误，是一个应用级的"不行"。
    pub const REFUSED: i64 = -32001;
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// 成功响应。
pub fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// 错误响应。
pub fn error(id: Value, code: i64, message: impl Into<String>, data: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": ErrorObject { code, message: message.into(), data }
    })
}

/// `initialize` 的结果。
///
/// `instructions` 里写明这是**协作式**控制。理由不是礼貌：一个读到这段话的智能体（或者配置
/// 它的人）需要知道，绕过这个网关直接 spawn shell 是可行的，所以网关的存在不等于机器被保护了。
/// 本项目在自己的能力表里已经把"通知"和"阻断门"记成同一个勾一次。
pub fn initialize_result(server_name: &str, version: &str) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": server_name, "version": version },
        "instructions": concat!(
            "AgentGuard 工具网关。危险动作请调这里的工具，不要直接调 shell 或文件 API：",
            "网关是执行者，所以它能拒绝执行，而一个旁路观察器只能事后记录。\n\n",
            "强制力等级：cooperative（协作式）。绕过本网关直接执行是可行的，因此本网关在运行",
            "不等于这台机器受到了内核级保护。内核级约束是另一层（见 docs/interception-design.md）。\n\n",
            "被拒绝时，错误里会点名具体规则和理由。那是判决，不是故障，不要重试；",
            "改成一个落在授权范围内的动作。"
        )
    })
}

/// 一个工具的声明。
pub fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": schema })
}

/// `tools/call` 的成功内容。
pub fn tool_text(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ], "isError": false })
}

/// `tools/call` 的失败内容。
///
/// MCP 里工具层面的失败走 `isError: true` 的正常结果，而不是 JSON-RPC 错误——这样智能体能
/// 看到原因并改做法，而不是把它当成传输故障去重试。被拒绝正是这种情况：它是一个答案。
pub fn tool_error(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ], "isError": true })
}
