[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

<p align="center">
  <img src="assets/brand/agentguard-logo.png" alt="AgentGuard 标志" width="160">
</p>

# AgentGuard

AgentGuard 是面向第三方 GUI Agent 的本地优先安全观测与审计系统。它分析屏幕、无障碍树、表单、深链、工具调用和外传元数据，并给出可审计的风险判决。

> **当前状态：`1.0.0-rc.1` 是源码候选版，不是生产安装包发布。**
> 仓库尚未提供本次发布所需的代码签名、公证、商店发布及真实设备端到端验收证据，生产发布判断仍为 **No-Go**。

## 能做什么

- 在 macOS、Windows、Android 与 Chromium 路径上采集可用的界面或事件信号。
- 检测提示注入、透明或不可见内容、界面树与画面不一致、隐私过度披露、可疑深链和关键操作。
- 通过哈希链与可选签名保存本地审计记录；支持签名威胁情报与可选 SQLCipher。
- 在 Agent 主动经过 MCP 工具网关时，按判决执行、拒绝或等待人工确认。
- 在受支持的浏览器页面内，对付款按钮、陷阱表单与付款形状的 fetch/XHR 提供有限的执行前确认门；对已知恶意或越出会话范围的主机安装 DNR 网络规则，并提供名单管理和规则溯源。
- 在 Linux 上，通过 `guard-jail` 为其自己启动的进程提供窄范围的内核文件系统边界；任务显式声明 `scope.net` 时，还可在 Landlock 支持下限制 TCP 连接与监听端口。
- 用 `guard-trust` 统一六类入站面的 fail-closed 信任词汇，并把当前 20 条用户能力声明映射到具体测试与生成状态仪表盘。

## 必须理解的边界

- **不是零间隙实时监控。** macOS AX 树变化已有 AXObserver 推送、合并与兜底轮询；像素捕获及其他桌面路径仍包含采样或轮询，间隙内的动作可能看不到。
- **大部分控制是合作式的。** Agent 如果绕过网关直接执行命令，网关无法阻止。
- **不是通用沙箱、EDR、防火墙或 DLP。** Linux `guard-jail` 只约束它启动的进程；网络端口天花板是可选能力，声明后若所选后端无法强制会拒绝启动。
- **浏览器控制有明确范围。** 页面门与 DNR 可在它们覆盖的向量上执行前拦截，但页面门可被恶意页面绕过，DNR 安装失败时会 fail-open；Native Messaging 判决仍是异步的，不能追溯阻止触发它的动作。Android 高风险提示仍发生在事件之后。
- Firefox 移植与 Edge 兼容路径已具备，但尚无真实浏览器端到端验收；Safari 目前只有设计。当前 macOS ad-hoc 候选已在本机通过启动、TCC 探测和 AXObserver 推送流程检查，但尚未完成签名/公证后的全新安装与升级验收；Windows 仍缺候选版真机 E2E，iOS 仍是未接入引擎的有限脚手架。

适用对象是研究与评测、开发或预发环境，以及知情运维控制下的内部试点；不应把当前 RC 作为面向消费者或受监管环境的强制安全控制。

## 快速开始

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
make acceptance
make check
~~~

macOS 开发壳：

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

## 文档

- [文档门户](docs/README.md)
- [1.0.0-rc.1 发布说明](docs/RELEASE-1.0.0-rc.1.md)
- [变更记录](CHANGELOG.md)
- [范围与非目标](docs/scope-and-non-goals.md)
- [平台能力矩阵](docs/platform-matrix.md)
- [入站信任](docs/入站信任.md)
- [主张与测试映射](docs/主张与测试映射.md)
- [浏览器执行前阻断](docs/浏览器执行前阻断.md)
- [真机验收执行手册](docs/acceptance-runbook.md)
- [结构化发布证据](docs/release-evidence.md)
- [历史发布门禁设计说明](docs/release-security.md)
- [生成的攻击面覆盖矩阵](eval/coverage-matrix.md)

本轮新增的关键技术与验收文档提供简体中文、繁體中文和英文版本；其余深层文档仍保留原始语言。门户会标明语言、用途和状态，避免把设计、离线测试或历史复核记录当作当前真机与发布结论。

## 仓库结构

~~~text
crates/    Rust 引擎、规则、审计、评测与工具
adapters/  macOS、Windows、Android 与浏览器适配器
apps/      桌面端、Chromium 扩展、Android 伴生应用与 iOS 脚手架
docs/      产品边界、架构、发布、安全与研究文档
eval/      场景、夹具、覆盖声明与生成报告
~~~

## 许可证

[Apache License 2.0](LICENSE)
