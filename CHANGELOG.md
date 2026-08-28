[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 变更记录

本文件记录 AgentGuard 的重要变更。版本号遵循语义化版本。

## [未发布]

### Added

- 接入 D 亮色品牌方案：增加共享 Logo 与 App 图标母版；更新 macOS、Windows、Android 与 Chromium 图标（含菜单栏、Adaptive/主题及通知小图标）；并在三语 README、文档门户、符合性说明及各前端页眉展示统一品牌标志。

## [1.0.0-rc.1] - 2026-08-28

> 源码候选版，不代表生产安装包已具备发布条件。当前没有完成代码签名、公证、商店发布或真实设备端到端验收，生产发布判断仍为 **No-Go**。

### Added

- 跨平台 Rust 规则引擎、OP/TR/FM 隐私评分、会话计划与能力范围判决。
- macOS AXUIElement、ScreenCaptureKit 与 Vision OCR 观测路径。
- Windows UI Automation、GDI 抓帧和 Windows.Media.Ocr 实现。
- Android AccessibilityService 伴生应用、环境调查和 Android Keystore P-256 适配器签名。
- Chromium MV3 扩展、Native Messaging host 与高风险判决事后通知。
- 合作式 MCP 工具网关，以及 Linux 上由内核执行的 `guard-jail` 文件系统边界。
- Ed25519 威胁情报、哈希链审计、可选逐条签名与 SQLCipher。
- Bearer 保护的本地 API、签名策略同步和已认证计费 webhook。
- 离线评测、覆盖矩阵、预检和发布证据门禁。
- 简体中文、繁體中文与英文的核心 README、文档门户、发布说明和变更记录。

### Security

- 发布路径拒绝以 `sha256:` 完整性摘要冒充威胁情报真实性签名。
- Native Messaging 调用者身份默认 fail-closed。
- 敏感文件系统目标改为不可确认放行；网关文件操作进入引擎独立判决，宿主接入审计存储与签名器后才写入可验证审计。
- 修复路径归约、符号链接、macOS 卷别名、root mount namespace 与读取范围问题。
- 加固审计见证包含性、会话计数、密钥文件权限、前端 DOM 写入与 CSP。
- 让策略同步和计费 webhook 在跨越信任边界时验证签名。

### Changed

- 明确区分旁路观测、合作式控制和 Linux 内核执行边界。
- Android 与 Chromium 的确认统一描述为事件后的通知，不再描述为执行前阻断。
- Windows 状态从模拟脚手架更新为真实 UIA/GDI/OCR 实现，同时保留“尚未真机验收”的限制。
- `guard-ffi` 明确标记为仓库内没有消费者的实验组件。
- 发布文档不再把源码、测试、构建和正式安装包证据混为同一状态。

### Known limitations

- 除 Linux `guard-jail` 外，大部分控制依赖 Agent 主动经过 AgentGuard，可以绕过。
- 桌面观测包含轮询，不是实时监控。
- Android 与 Chromium 无法在动作发生前阻断。
- Windows 尚无真实设备端到端验收；iOS 只有有限脚手架，没有完整工程或引擎接线。
- 仓库夹具密钥不得用于生产，部署前必须替换。
- 尚无签名、公证安装包和真实设备验收证据，严格发布门禁不能通过。

完整范围与复验要求见 [1.0.0-rc.1 发布说明](docs/RELEASE-1.0.0-rc.1.md)。
