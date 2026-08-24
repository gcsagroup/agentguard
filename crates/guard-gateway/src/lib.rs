//! 协作式工具网关：智能体调它而不是调原始工具，于是判决可以变成拒绝执行。
//!
//! # 位置变了，判决逻辑没变
//!
//! 在这个 crate 之前，AgentGuard 是旁路观察器：它看到的每一样输入都描述一件**已经发生**的事，
//! 所以判决只能记下来或者告诉人。网关不改规则，改的是站的位置——它是那个**执行者**。
//!
//! 全部 92 条规则加上 B0 的路径模型，在这条路径上第一次变成能拒绝的东西。
//!
//! # 这是协作式，不是边界
//!
//! 一个直接 `std::process::Command` 的智能体完全绕过它。`docs/interception-design.md` §2 把这条
//! 区分写成不能含混的一条，本 crate 每一条响应、`initialize` 的 instructions、以及
//! `gateway/stats` 都带 `enforcement: "cooperative"`。
//!
//! 内核级约束是另一层（设计文档里的 B2/B3，`guard-jail`），还没做。

pub mod confirm;
pub mod exec;
pub mod gate;
pub mod mcp;
pub mod server;

pub use confirm::{Answer, ConfirmRequest, PendingConfirm};
pub use exec::{ExecOutput, ToolCall};
pub use gate::{Finding, Gate, Outcome, ENFORCEMENT};
pub use server::{Handled, Server};

#[cfg(test)]
mod tests;
