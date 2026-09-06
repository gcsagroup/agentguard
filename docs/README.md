[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="../assets/brand/agentguard-logo.png" alt="AgentGuard 标志" width="120">
</p>

# AgentGuard 文档门户

本门户是三语入口。当前三语覆盖根 README、本门户、`1.0.0-rc.1` 发布说明、CHANGELOG、隐私说明、各组件 README、主要商店文案，以及本轮维护的技术说明和验收文档；其余深层技术与审计文档继续保留原始语言，并在下方标明用途与状态。

> `1.0.0-rc.1` 是源码候选版。代码签名、公证、商店发布和真实设备端到端验收证据尚未完成，生产发布判断仍为 **No-Go**。

## 状态说明

- **核心入口**：本次维护的当前三语摘要。
- **技术参考**：描述实现或威胁模型，不等于生产发布证据。
- **需对齐**：含有历史数字、追加式更正或待替换字段，引用前应核对代码与生成报告。
- **草稿**：用于商店、隐私或发布准备，不能直接作为已发布材料。
- **历史/内部**：复核、计划或迭代记录，不代表当前产品承诺。
- **生成报告**：必须在当前提交上重新生成后才能作为证据。

## 核心三语入口

- [邮件联合防护设计（简体）](mail-protection-design.md) · [繁體](mail-protection-design.zh-TW.md) · [English](mail-protection-design.en.md) — 已实现默认关闭的实验性网页邮箱模块；代理仍为设计候选，真实邮箱尚未验收。
- [2026-09-06 整改源码提交说明（简体）](remediation-publication-2026-09-06.md) · [繁體](remediation-publication-2026-09-06.zh-TW.md) · [English](remediation-publication-2026-09-06.en.md) — 本轮范围、使用入口、验证与 No-Go 边界。

- [项目 README（简体）](../README.md) · [繁體](../README.zh-TW.md) · [English](../README.en.md)
- [1.0.0-rc.1 发布说明（简体）](RELEASE-1.0.0-rc.1.md) · [繁體](RELEASE-1.0.0-rc.1.zh-TW.md) · [English](RELEASE-1.0.0-rc.1.en.md)
- [2026-09-01 真机验收报告（简体）](acceptance-report-2026-09-01.md) · [繁體](acceptance-report-2026-09-01.zh-TW.md) · [English](acceptance-report-2026-09-01.en.md) — 历史快照，区分 `bd7bb2f` 与当时未提交的整合候选；不代表本次提交已完成真机验收，发布结论仍为 No-Go。
- [2026-09-02 Windows 部分真机验收报告（简体）](acceptance-report-windows-2026-09-02.md) · [繁體](acceptance-report-windows-2026-09-02.zh-TW.md) · [English](acceptance-report-windows-2026-09-02.en.md) — 候选 `89dadf9` 的自动化、Release 产物与独立 RDP 交互证据；W1–W11 未完整执行，生产发布仍为 No-Go。
- [CHANGELOG（简体）](../CHANGELOG.md) · [繁體](../CHANGELOG.zh-TW.md) · [English](../CHANGELOG.en.md)
- [隐私说明（简体）](privacy-policy.md) · [繁體](privacy-policy.zh-TW.md) · [English](privacy-policy.en.md)

## 本轮维护的三语技术与验收文档

- [入站信任（简体）](入站信任.md) · [繁體](入站信任.zh-TW.md) · [English](入站信任.en.md) — 六类入站面的统一信任原则、共用词汇与清册测试。
- [主张与测试映射（简体）](主张与测试映射.md) · [繁體](主张与测试映射.zh-TW.md) · [English](主张与测试映射.en.md) — 首批能力声明、证明测试与生成状态仪表盘；不替代真机证据。
- [浏览器执行前阻断（简体）](浏览器执行前阻断.md) · [繁體](浏览器执行前阻断.zh-TW.md) · [English](浏览器执行前阻断.en.md) — Chrome/Edge 的 block-only DOM 门、静态 DNR 精确支持面，以及无页面内授权/重放边界。
- [跨浏览器（简体）](跨浏览器.md) · [繁體](跨浏览器.zh-TW.md) · [English](跨浏览器.en.md) — 首个 GA 仅 Chrome/Edge；Firefox 为源码原型，Safari 为独立路径。
- [消费者化界面（简体）](消费者化界面.md) · [繁體](消费者化界面.zh-TW.md) · [English](消费者化界面.en.md) — 三语人话界面、首次引导、无障碍、键盘与深色模式。
- [macOS 实时观测（简体）](macos实时观测.md) · [繁體](macos实时观测.zh-TW.md) · [English](macos实时观测.en.md) — AXObserver 推送与合并；像素采样、兜底轮询和真机未验边界。
- [结构化发布证据（简体）](release-evidence.md) · [繁體](release-evidence.zh-TW.md) · [English](release-evidence.en.md) — `--strict` 的 12 类 RC 技术证据；通过不等于 GA。
- [GA 发布闭环门禁（简体）](ga-release-gate.md) · [繁體](ga-release-gate.zh-TW.md) · [English](ga-release-gate.en.md) — `--ga` 的 19 类证据、机器语义和 No-Go 边界。
- [GA 证据模板](ga-evidence-template.md) · [繁體](ga-evidence-template.zh-TW.md) · [English](ga-evidence-template.en.md) — 故意 BLOCKED，不能原样变成 PASS。
- [14 天 Beta](ga-beta-runbook.md) · [繁體](ga-beta-runbook.zh-TW.md) · [English](ga-beta-runbook.en.md) · [5→25→100 扩量](rollout-runbook.md) · [繁體](rollout-runbook.zh-TW.md) · [English](rollout-runbook.en.md)
- [事故响应](incident-response.md) · [繁體](incident-response.zh-TW.md) · [English](incident-response.en.md) · [上线支持](support-runbook.md) · [繁體](support-runbook.zh-TW.md) · [English](support-runbook.en.md)
- [真机验收执行手册（简体）](acceptance-runbook.md) · [繁體](acceptance-runbook.zh-TW.md) · [English](acceptance-runbook.en.md) — 可执行步骤与证据规范，不是已完成验收。
- [真机验收报告模板（简体）](acceptance-report-template.md) · [繁體](acceptance-report-template.zh-TW.md) · [English](acceptance-report-template.en.md) — 按平台记录 PASS、FAIL 与 BLOCKED。
- [Chromium 扩展验收清单（简体）](acceptance-chrome.md) · [繁體](acceptance-chrome.zh-TW.md) · [English](acceptance-chrome.en.md) — 39 项真 Chromium E2E + Chrome/Edge 正式候选 ZIP 的 B1–B5 人工发布证据；Chrome 与 Edge 是两个独立的严格门禁 kind。
- [iOS 真机与 TestFlight 验收（简体）](acceptance-ios.md) · [繁體](acceptance-ios.zh-TW.md) · [English](acceptance-ios.en.md) — I1–I6 真机 Safari Extension 与 TF1–TF3 TestFlight 是两个独立的严格门禁 kind。
- [Firefox 首个 GA 排除说明（简体）](acceptance-firefox.md) · [繁體](acceptance-firefox.zh-TW.md) · [English](acceptance-firefox.en.md) — 仅源码原型，不封装、不提交、不产生首个 GA PASS。
- [Windows 验收清单（简体）](acceptance-windows.md) · [繁體](acceptance-windows.zh-TW.md) · [English](acceptance-windows.en.md) — `first-ga-v1` 要求 UIA、GDI、OCR、能力探针等 W1–W6/W8–W11 真机项；W7 Native Messaging 仅为非 GA/遗留可选记录。
- [macOS 验收清单（简体）](acceptance-macos.md) · [繁體](acceptance-macos.zh-TW.md) · [English](acceptance-macos.en.md) — SCK、AX、TCC 与原生用例的严格 PASS/BLOCKED 边界。

## 发布、平台与运维

- [release-security.md](release-security.md) — 原始语言：中英混合；状态：历史发布门禁设计说明；当前结构化格式以三语《结构化发布证据》为准。
- [platform-matrix.md](platform-matrix.md) — 原始语言：英文为主；状态：平台能力参考，真机状态须结合发布说明。
- [status-dashboard.html](status-dashboard.html) — 从能力声明、门禁与状态数据生成；必须在当前提交上重生成，不能替代真机证据。
- [capability-matrix.md](capability-matrix.md) — 由 `scripts/gen-capability-matrix.py` 从源码生成的三语能力矩阵：各端真正发出的事件、静态测试数、版本字符串；`cargo test` 逐字核对，手写文档里的这些数字以它为准。
- [desktop-guide.md](desktop-guide.md) — 桌面端使用说明:怎么授权、怎么开始守护、状态灯各是什么意思、怎么用自检看到它工作、它做不到什么。应用内「怎么用」卡片的完整版。
- [macos-release.md](macos-release.md) — 原始语言：简体中文；状态：签名、公证与打包指南，不是已执行证明。
- [roadmap-status.md](roadmap-status.md) — 原始语言：英文为主；状态：需对齐，部分指标和“已完成”勾选是历史快照。
- [privacy-policy.md](privacy-policy.md) — 三语技术披露草稿；公开前仍需法务复核并补真实联系信息。
- [store-listing-cws.md](store-listing-cws.md) — 三语兼容入口，指向 Chromium 商店文案草稿。
- [store-listing-macos.md](store-listing-macos.md) — 三语兼容入口，指向 macOS 商店文案草稿。
- [i18n.md](i18n.md) — 原始语言：英文；状态：客户端国际化技术参考。
- [intro.html](intro.html) — 原始语言：简体中文与英文；状态：需对齐，历史指标必须重新验证，尚无繁体正文。

## 架构、适配器与运行接口

- [architecture.md](architecture.md) — 原始语言：中英混合；状态：技术参考。
- [android-completeness.md](android-completeness.md) — 原始语言：英文为主；状态：Android 能力与缺口参考。
- [android-env-survey.md](android-env-survey.md) — 原始语言：英文；状态：Android 环境调查技术参考。
- [windows-observation.md](windows-observation.md) — 原始语言：英文；状态：Windows 实现参考，已有启动、连续观测与事后风险确认的历史部分真机证据；它不证明外部动作被阻止，`first-ga-v1` W1–W6/W8–W11 端到端验收仍未完成。
- [ios-limited-sku.md](ios-limited-sku.md) — 三语受限 Safari WebShield 候选；工程与模拟器证据已具备，签名、真机 Safari 与 TestFlight 仍是发布门槛。
- [local-api.md](local-api.md) — 原始语言：中英混合；状态：本地 API 技术参考。
- [billing.md](billing.md) — 原始语言：中英混合；状态：计费与授权技术参考。
- [sck-bridge.md](sck-bridge.md) — 原始语言：英文为主；状态：ScreenCaptureKit 接线参考。
- [safe-shell.md](safe-shell.md) — 原始语言：中英混合；状态：合作式命令判决参考，不是通用沙箱。
- [interception-design.md](interception-design.md) — 原始语言：中英混合；状态：需对齐，正文同时保留设计前叙述与后续已实现状态。
- [scope-and-non-goals.md](scope-and-non-goals.md) — 原始语言：中英混合；状态：当前能力边界与非目标参考。

## 审计、身份与信息流

- [audit-signing.md](audit-signing.md) — 原始语言：中英混合；状态：签名审计技术参考。
- [audit-encryption.md](audit-encryption.md) — 原始语言：中英混合；状态：SQLCipher 技术参考。
- [agent-identity.md](agent-identity.md) — 原始语言：英文；状态：会话级 Agent 身份与限制参考。
- [app-identity.md](app-identity.md) — 原始语言：英文；状态：应用签名身份参考。
- [app-lookalike.md](app-lookalike.md) — 原始语言：英文为主；状态：应用外观仿冒检测参考。
- [information-flow.md](information-flow.md) — 原始语言：英文；状态：信息流标签与降级参考。
- [semantic-firewall.md](semantic-firewall.md) — 原始语言：英文；状态：结构化实体与上下文隔离参考。
- [session-scope.md](session-scope.md) — 原始语言：英文；状态：会话最小权限参考。
- [trajectory-alignment.md](trajectory-alignment.md) — 原始语言：英文；状态：计划与轨迹对齐参考。
- [log-hygiene.md](log-hygiene.md) — 原始语言：英文为主；状态：日志脱敏与边界参考。

## 视觉、文本与评测方法

- [frame-integrity.md](frame-integrity.md) — 原始语言：中英混合；状态：帧摘要与篡改检测参考。
- [text-anomalies.md](text-anomalies.md) — 原始语言：英文；状态：文本异常启发式参考。
- [eval-methodology.md](eval-methodology.md) — 原始语言：英文；状态：评测方法参考。
- [leaderboard-comparability.md](leaderboard-comparability.md) — 原始语言：英文；状态：排行榜可比性参考。
- [myphonebench-mapping.md](myphonebench-mapping.md) — 原始语言：英文为主；状态：研究映射参考。
- [paper-gap-improvements.md](paper-gap-improvements.md) — 原始语言：英文；状态：历史研究差距与改进记录。
- [paper-gap-iter6-review.md](paper-gap-iter6-review.md) — 原始语言：英文；状态：历史复核记录。
- [攻击面覆盖矩阵](../eval/coverage-matrix.md) — 原始语言：英文；状态：生成报告，发布前必须在当前提交上重新生成。

## 简体中文实现说明

- [路径模型.md](路径模型.md) — 状态：文件系统路径判决技术参考。
- [工具网关.md](工具网关.md) — 状态：合作式 MCP 网关技术参考。
- [内核约束.md](内核约束.md) — 状态：Linux `guard-jail` 与后端边界参考。
- [适配器断言签名.md](适配器断言签名.md) — 状态：适配器签名与不对称信任参考。

## 历史与内部材料

以下文件保留审计轨迹，但不能替代当前 README、发布说明或严格发布门禁：

- [上线评估.md](上线评估.md)、[发布阻塞项.md](发布阻塞项.md)
- [第五轮复核.md](第五轮复核.md)、[第六轮复核.md](第六轮复核.md)、[第七轮复核-文档与实现差距.md](第七轮复核-文档与实现差距.md)
- [开发计划-文档实现差距修复.md](开发计划-文档实现差距修复.md)、[第二类全做.md](第二类全做.md)

## 仓库外层入口

- [Threat Intel README（简体）](../intel/README.md) · [繁體](../intel/README.zh-TW.md) · [English](../intel/README.en.md)
- 组件 README：[macOS](../apps/desktop-macos/README.md)、[Windows](../apps/desktop-windows/README.md)、[Android](../apps/android-companion/README.md)、[Chromium](../apps/extension-chromium/README.md)、[iOS WebShield](../apps/ios-webshield/README.md)；每个入口均可切换简体、繁体和英文。
