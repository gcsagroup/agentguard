[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

发布日期：2026-08-28

> **这是源码候选版，不是生产安装包发布。**
> 当前没有完成代码签名、公证、商店发布及真实设备端到端验收，生产发布判断仍为 **No-Go**。

## 定位

本候选版面向研究与评测、开发或预发环境，以及知情运维控制下的内部试点。AgentGuard 的主要形态是旁路观测、风险判决与可追责审计；工具网关提供可绕过的合作式控制，Linux `guard-jail` 提供一个窄范围的内核文件系统边界。

## 主要能力

- 跨平台 Rust 规则引擎，以及 OP、TR、FM 隐私评分、会话计划和能力范围判决。
- macOS 的 AXUIElement、ScreenCaptureKit 与 Vision OCR 观测路径。
- Windows 的 UI Automation、GDI 抓帧和 Windows.Media.Ocr 实现；尚未完成真实设备验收。
- Android AccessibilityService 伴生应用、环境调查和 Android Keystore P-256 适配器签名。
- Chromium MV3 扩展、Native Messaging host 与高风险判决事后通知。
- 合作式 MCP 工具网关，以及 Linux `guard-jail` 文件系统约束。
- 哈希链审计、可选逐条签名与 SQLCipher、Ed25519 威胁情报、本地 API、签名策略同步和已认证计费 webhook。
- 可复现离线评测、攻击面覆盖矩阵、预检与发布证据门禁。

## 安全加固

- 发布路径拒绝以 `sha256:` 完整性摘要冒充威胁情报真实性签名。
- Native Messaging 调用者身份默认 fail-closed。
- 敏感文件系统目标不可通过人工确认放行；网关文件操作进入引擎独立判决，宿主接入审计存储与签名器后才写入可验证审计。
- 修复路径归约、符号链接、macOS 卷别名、root mount namespace、审计见证包含性和前端注入/CSP 等问题。
- 密钥文件采用受限权限创建，并拒绝不安全权限或符号链接路径。

## 验证基线

仓库在本候选版中记录了以下基线：

- 130 个离线场景文件；
- 104 项验收检查；
- 30 个已发布攻击面，其中 13 个 covered、16 个 partial、1 个 uncovered。

这些数字是提交前的仓库基线，**不是本次发布动作已经复验的证明**。在当前提交上发布前必须重新运行：

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make check
make release-gate
~~~

正式发布还必须让严格门禁取得代码签名、公证与真实设备证据；软门禁通过不能替代这些证据。

## 明确未完成

- macOS、Windows 与 Android 的正式签名安装包。
- macOS 公证与 staple。
- macOS、Windows 与 Android 的真实设备端到端验收。
- App Store、Chrome Web Store 与 Google Play 的正式发布。
- macOS 与 Windows 的内核级 jail。
- 网络出口强制代理。
- iOS 完整工程及引擎接线。

Android 与 Chromium 的高风险提示发生在事件之后，不是执行前阻断。除 Linux `guard-jail` 外，大部分控制依赖 Agent 主动经过 AgentGuard，不能描述为不可绕过的防护。

## 相关文档

- [文档门户](README.md)
- [变更记录](../CHANGELOG.md)
- [发布安全与证据门禁](release-security.md)
- [平台能力矩阵](platform-matrix.md)
- [生成的攻击面覆盖矩阵](../eval/coverage-matrix.md)
