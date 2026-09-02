[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

发布日期：2026-08-28

> **这是源码候选版，不是生产安装包发布。**
> 当前没有完成代码签名、公证、商店发布及真实设备端到端验收，生产发布判断仍为 **No-Go**。

本说明已同步候选分支的后续源码更新；版本仍是 `1.0.0-rc.1`，没有因此产生或发布新的安装包。

## 定位

本候选版面向研究与评测、开发或预发环境，以及知情运维控制下的内部试点。AgentGuard 的主要形态是旁路观测、风险判决与可追责审计；工具网关提供可绕过的合作式控制，浏览器页面门和 DNR 对有限向量提供执行前控制，Linux `guard-jail` 为其自己启动的进程提供窄范围的内核边界。

## 主要能力

- 跨平台 Rust 规则引擎，以及 OP、TR、FM 隐私评分、会话计划和能力范围判决；`guard-trust` 为六类入站面提供统一的 fail-closed 信任词汇与清册检查。
- macOS 的 AXUIElement、ScreenCaptureKit 与 Vision OCR 观测路径；AX 树变化新增 AXObserver 推送、合并与兜底轮询，像素仍为采样路径。
- Windows 的 UI Automation、GDI 抓帧和 Windows.Media.Ocr 实现；尚未完成真实设备验收。
- Android AccessibilityService 伴生应用、环境调查和 Android Keystore P-256 适配器签名。
- Chromium MV3 扩展、Native Messaging host、消费者化三语界面，以及付款/陷阱/fetch-XHR 页面门和恶意/越界主机 DNR 阻断；名单支持管理与规则溯源。
- Firefox 移植与打包骨架、Edge 兼容路径，以及 Safari 的设计边界；这些浏览器路径尚未完成真实环境端到端验收。
- 合作式 MCP 工具网关，以及 Linux `guard-jail` 文件系统约束和可选 `scope.net` TCP 端口天花板。
- 哈希链审计、可选逐条签名与 SQLCipher、Ed25519 威胁情报、本地 API、签名策略同步和已认证计费 webhook。
- D 亮色 Logo 与跨平台 App 图标；macOS、Windows 与 Chromium 的三语界面、首次引导、人话风险文案、无障碍确认层、键盘操作和深色模式。
- 当前 20 条用户能力声明到证明测试的机器映射、生成状态仪表盘、可复现离线评测、攻击面覆盖矩阵、预检与发布证据门禁。
- Firefox、Windows 与 macOS 验收清单、可执行真机手册、浏览器夹具和报告模板；它们定义验收方法，不代表验收已经完成。

## 安全加固

- 发布路径拒绝以 `sha256:` 完整性摘要冒充威胁情报真实性签名。
- Native Messaging 调用者身份默认 fail-closed；计费、策略、本地 API、威胁情报、适配器断言与 Native Messaging 统一遵循已验证入站才能进入信任边界的原则。
- 敏感文件系统目标不可通过人工确认放行；网关文件操作进入引擎独立判决，宿主接入审计存储与签名器后才写入可验证审计。
- `scope.net` 一经声明便只允许列出的 TCP connect/bind 端口；空表表示全部拒绝，后端无法强制时拒绝启动而不静默放开网络。
- 浏览器恶意主机名单跨 service worker 重启保留，越界主机随会话过期，并在 popup 中显示触发规则；DNR 安装失败仍会 fail-open，不伪造已经阻断的状态。
- 修复路径归约、符号链接、macOS 卷别名、root mount namespace、审计见证包含性和前端注入/CSP 等问题。
- 密钥文件采用受限权限创建，并拒绝不安全权限或符号链接路径。

## 验证基线

仓库包含离线场景、攻击面覆盖声明，以及当前 20 条能力声明到具体测试的机器可核对映射。`docs/status-dashboard.html` 从能力声明、发布门禁和状态数据生成，不是手写结论。

任何已生成数字和状态都是生成时提交的快照，**不是本次发布动作已经复验的证明**。在当前提交上发布前必须重新运行：

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
make check-shells
make dashboard
make check
make release-gate
~~~

正式发布还必须让严格门禁取得代码签名、公证与真实设备证据；软门禁通过不能替代这些证据。

## 明确未完成

- macOS、Windows 与 Android 的正式签名安装包。
- macOS 公证与 staple。
- macOS 已完成当前 ad-hoc 候选在本机的启动、TCC 探测与 AXObserver 推送流程检查；Developer ID 签名/公证后的全新安装与升级验收仍未完成。Windows 与 Android 的候选版真机 E2E 仍未完成。
- Chrome、Edge 与 Firefox 的真实浏览器端到端验收；Firefox 的 DNR 配额与 Native Messaging gecko-id 路径仍需校准。
- App Store、Chrome Web Store 与 Google Play 的正式发布。
- macOS 与 Windows 的内核级 jail。
- 网络出口强制代理。
- Safari 扩展工程与 Swift Native Messaging handler；目前只有设计。
- iOS 完整工程及引擎接线。

Android 的高风险提示发生在事件之后。Chromium 的页面门和 DNR 能在其覆盖的向量上执行前控制，但页面门可被恶意页面绕过，DNR 安装失败时 fail-open，Native Messaging 判决仍是异步的。macOS AX 树有推送，但像素捕获和兜底仍有采样/轮询边界。除 Linux `guard-jail` 对其所启动进程的窄约束外，大部分控制依赖 Agent 或页面经过 AgentGuard，不能描述为通用或不可绕过的防护。

## 相关文档

- [文档门户](README.md)
- [变更记录](../CHANGELOG.md)
- [发布安全与证据门禁](release-security.md)
- [平台能力矩阵](platform-matrix.md)
- [入站信任](入站信任.md)
- [主张与测试映射](主张与测试映射.md)
- [浏览器执行前阻断](浏览器执行前阻断.md)
- [真机验收执行手册](acceptance-runbook.md)
- [2026-09-01 验收报告](acceptance-report-2026-09-01.md)
- [生成的攻击面覆盖矩阵](../eval/coverage-matrix.md)
