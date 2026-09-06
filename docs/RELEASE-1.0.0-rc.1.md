[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

发布日期：2026-08-28

> **这是源码候选版，不是生产安装包发布。**
> 当前没有完成代码签名、公证、商店发布及真实设备端到端验收，生产发布判断仍为 **No-Go**。

本说明已同步候选分支的后续源码更新；版本仍是 `1.0.0-rc.1`，没有因此产生或发布新的安装包。

> **`1.0.0-rc.1` 是源码树里写的版本字符串，不是一个已发布的东西。** 仓库里没有对应的 git tag、没有签名产物；标注日期之后合入的内容（D 方案品牌、真机报告 P0/P1/P2 的整改）都在带着这个版本字符串的源码树里。所以本说明描述的是"当前带此版本号的源码"，不是某个冻结时刻的快照——它会随源码更新。凡是"哪一端观察什么、多少测试、多少条能力声明、什么版本"的数字，以源码生成的 [docs/capability-matrix.md](capability-matrix.md) 为准，本说明不再自己维护一套。

## 定位

本候选版面向研究与评测、开发或预发环境，以及知情运维控制下的内部试点。AgentGuard 的主要形态是旁路观测、风险判决与可追责审计；工具网关提供可绕过的合作式控制，浏览器 block-only DOM 门和静态 DNR 对有限向量提供执行前阻断，Linux `guard-jail` 为其自己启动的进程提供窄范围的内核边界。

## 主要能力

- 跨平台 Rust 规则引擎，以及 OP、TR、FM 隐私评分、会话计划和能力范围判决；`guard-trust` 为六类入站面提供统一的 fail-closed 信任词汇与清册检查。
- macOS 的 AXUIElement、ScreenCaptureKit 与 Vision OCR 观测路径；AX 树变化新增 AXObserver 推送、合并与兜底轮询，像素仍为采样路径。
- Windows 的 UI Automation、GDI 抓帧和 Windows.Media.Ocr 实现；尚未完成真实设备验收。
- Android AccessibilityService 伴生应用、环境调查和 Android Keystore P-256 适配器签名。
- 首个 GA 浏览器范围为 Chrome/Edge 共用的 Chromium MV3 ZIP：消费者化三语界面、付款/陷阱 block-only DOM 门，以及明确付款 URL 形状的静态 DNR 阻断；页面内没有允许或重放，GA manifest 没有 Native Messaging。
- Firefox 只保留源码原型，不封装、不提交、不作首个 GA 验收门；Safari 是独立产品路径。
- 可构建的 Swift-first iOS Safari WebShield 受限 SKU，包含容器 App、Safari Web Extension、共享 Core 与自动测试；它未接入 Rust 引擎，不能替代发布签名、真机 Safari 或 TestFlight 验收。
- 合作式 MCP 工具网关，以及 Linux `guard-jail` 文件系统约束和可选 `scope.net` TCP 端口天花板。
- 哈希链审计、可选逐条签名与 SQLCipher、Ed25519 威胁情报、本地 API、签名策略同步和已认证计费 webhook。
- D 亮色 Logo 与跨平台 App 图标；macOS、Windows 与 Chromium 的三语界面、首次引导、人话风险文案、按路径能力区分的无障碍风险／阻断提示、键盘操作和深色模式。
- 用户能力声明到证明测试的机器映射（条数见 [capability-matrix.md](capability-matrix.md)）、生成状态仪表盘、可复现离线评测、攻击面覆盖矩阵、预检与发布证据门禁。
- Chrome/Edge、Windows、macOS 与 iOS 验收清单、Firefox 排除说明、可执行真机手册、浏览器夹具和报告模板；它们定义验收方法，不代表正式候选已完成发布验收。

## 安全加固

- 发布路径拒绝以 `sha256:` 完整性摘要冒充威胁情报真实性签名。
- 仓库内 Native Messaging 原型的调用者身份默认 fail-closed；首个 GA 浏览器包不申请该权限。计费、策略、本地 API、威胁情报与适配器断言统一遵循已验证入站才能进入信任边界的原则。
- 敏感文件系统目标不可通过人工确认放行；网关文件操作进入引擎独立判决，宿主接入审计存储与签名器后才写入可验证审计。
- `scope.net` 一经声明便只允许列出的 TCP connect/bind 端口；空表表示全部拒绝，后端无法强制时拒绝启动而不静默放开网络。
- 浏览器首个 GA 以 manifest 静态 DNR 规则阻断明确支持的付款请求；升级时清除旧 Native/动态范围状态，权限不可用时 fail-closed，popup 隐藏不可用入口。
- 修复路径归约、符号链接、macOS 卷别名、root mount namespace、审计见证包含性和前端注入/CSP 等问题。
- 密钥文件采用受限权限创建，并拒绝不安全权限或符号链接路径。

## 验证基线

仓库包含离线场景、攻击面覆盖声明，以及能力声明到具体测试的机器可核对映射（当前条数、各端真正发出的事件与静态测试数见源码生成的 [capability-matrix.md](capability-matrix.md)）。`docs/status-dashboard.html` 从能力声明、发布门禁和状态数据生成，不是手写结论。

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

正式发布还必须让严格门禁取得十二类代码签名、公证与真实设备证据；软门禁通过不能替代这些证据。当前没有一套与同一冻结候选绑定且全部通过的十二类证据，因此结论仍为 **No-Go**。

## 明确未完成

- macOS、Windows、Android 与 iOS 的正式签名候选产物。
- macOS 公证与 staple。
- 旧 ad-hoc macOS 候选曾完成本机启动、TCC 探测与 AXObserver 推送流程检查，但本轮最新 universal `.app` 尚未完整复验；Developer ID 签名/公证后的全新安装、升级与 TCC 验收也未完成。Windows 与 Android 的当前候选真机 E2E 仍未完成。
- Chrome 与 Edge 尚未分别完成同一正式候选 ZIP 的 B1–B5 干净 profile 安装、升级、回滚与商店证据；源码层真实 Chromium E2E 不能替代这两个独立严格门禁。Firefox 不在首个 GA 范围内。
- iOS 已有可构建受限 SKU 与无签名模拟器证据，但缺 Apple Distribution 签名候选、I1–I6 真机 Safari Extension 与 TF1–TF3 TestFlight 证据；也未接入 Rust 引擎。
- App Store / TestFlight、Chrome Web Store 与 Google Play 的正式发布。
- macOS 与 Windows 的内核级 jail。
- 网络出口强制代理。
- iOS Rust 引擎接线与受限 SKU 之外的跨 App / 系统观测能力；现有 Safari Extension 只覆盖文档声明的网页 DOM 范围。

Android 的高风险提示发生在事件之后。Chromium DOM 门覆盖声明的 frame、普通 DOM 与 open Shadow DOM，页面可移除提示但不能借此授权或重放；closed Shadow DOM、浏览器原生动作与未识别页面形状不在声明内。静态 DNR 只覆盖声明的 HTTP(S) 方法、付款 URL 关键词与资源类型，不能从加密 body 猜出业务语义。macOS AX 树有推送，但像素捕获和兜底仍有采样/轮询边界。除 Linux `guard-jail` 对其所启动进程的窄约束外，大部分控制依赖 Agent 或页面经过 AgentGuard，不能描述为通用或不可绕过的防护。

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
