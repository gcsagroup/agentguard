# AGD-009 桌面确认协议 2 适配

日期：2026-09-09。范围：现有桌面网关确认页与 Rust 控制面；保留已有工作区、设置和接入向导。

## 已实现

- Rust 控制面只接受协议 2 的完整 `ApprovalBinding`，重新计算动作 SHA-256，校验批准编号、动作绑定及有效期；回答前重新读取并核对请求。
- HTTP 批准／拒绝提交 `id`、`action_sha256`、`approval_nonce`。批准随机值与连接令牌只保留在 Rust 控制面，不通过返回视图传给网页，更不进入 Agent 状态或持久化设置。
- 现有确认区显示会话、工具来源和版本、最终目标、策略版本、动作摘要、完整参数与写入正文；外部文字只按文本呈现。没有勾选核对、请求改变或已过期时不能批准。同编号但正文／目标／摘要改变也清除旧勾选。
- 保留三语显示；请求总响应超过 4 MiB 或描述超过 2 MiB 时拒绝整条请求并提示拆分，不截断正文后继续批准。上限独立于网关输入上限，不能声称所有 1 MiB 输入都必然可展示。

落点：[Rust 控制面](../apps/desktop-macos/src-tauri/src/gateway_confirm.rs)、[确认页面](../apps/desktop-macos/src/gateway-confirmation.js)、[显示词条](../apps/desktop-macos/src/workspace-i18n.js)。

## 验证与边界

桌面 Rust 确认模块 **5 项通过**，另 1 项真实网关集成用例已显式使用冻结二进制单独执行并通过：真实 MCP 请求经 Rust 确认控制面分别验证允许写入、拒绝零写入、批准超时零写入、断连零写入。网关候选 SHA-256：`73d6a0a986e008787a09f9b01b1d6084ad17ab705981b9e1fbd86f58d62882f8`。已通过字段绑定、摘要篡改、请求编号变化、期限、旧无绑定请求拒绝、WebView 不收到随机值、旧连接、HTTP 响应异常等检查。

最终复验使用保存的[独立候选](../.artifacts/development-run-2026-09-09/candidates/73d6a0a986e008787a09f9b01b1d6084ad17ab705981b9e1fbd86f58d62882f8/agentguard-mcp)，由 `AGENTGUARD_GATEWAY_TEST_BIN` 指定；构建与测试通过 `bootstrap-rust.sh` 固定 Rust 1.95.0 的 PATH、编译器及 sysroot。四条真实路径在该最终候选上再次通过，未重跑未变更的浏览器或界面检查。原始输出：[final-candidate-integration.log](../.artifacts/agd-desktop-confirm-v2-complete/final-candidate-integration.log)。

工作区真实 Chromium 渲染测试通过，覆盖完整正文和摘要、同编号内容变化、语言切换、超大请求拒绝、过期和失败回执；输出位于本次 `.artifacts/agd-desktop-confirm-v2-complete/`。该渲染测试使用明确的后端桩，不能当成真实网关或原生 App 已运行证据。

另通过 Computer Use 实际操作本地页面：从“主动防护”找到确认入口，连接后检查完整正文和目标，确认勾选前按钮不可用，勾选后只批准当前请求，回执明确提示执行结果仍需在客户端核实；检查了实际排版和 HTML 仅作为文字显示。临时服务和浏览器标签已关闭。

**本项不证明原生 App 的 TCC 权限、签名身份、自动接入、持久审计或完整 M1 已验收。** 真正部署仍需对准确 App 候选和实际客户端完成对应测试。
