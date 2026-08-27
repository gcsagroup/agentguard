[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

# AgentGuard

AgentGuard 是面向第三方 GUI Agent 的本地优先安全观测与审计系统。它分析屏幕、无障碍树、表单、深链、工具调用和外传元数据，并给出可审计的风险判决。

> **当前状态：`1.0.0-rc.1` 是源码候选版，不是生产安装包发布。**
> 仓库尚未提供本次发布所需的代码签名、公证、商店发布及真实设备端到端验收证据，生产发布判断仍为 **No-Go**。

## 能做什么

- 在 macOS、Windows、Android 与 Chromium 路径上采集可用的界面或事件信号。
- 检测提示注入、透明或不可见内容、界面树与画面不一致、隐私过度披露、可疑深链和关键操作。
- 通过哈希链与可选签名保存本地审计记录；支持签名威胁情报与可选 SQLCipher。
- 在 Agent 主动经过 MCP 工具网关时，按判决执行、拒绝或等待人工确认。
- 在 Linux 上，通过 `guard-jail` 为其自己启动的进程提供窄范围的内核文件系统边界。

## 必须理解的边界

- **不是实时监控。** 桌面观测包含轮询，轮询间隙内的动作可能看不到。
- **大部分控制是合作式的。** Agent 如果绕过网关直接执行命令，网关无法阻止。
- **不是通用沙箱、EDR、防火墙或 DLP。** Linux `guard-jail` 是唯一不依赖被约束方配合的窄边界。
- **Android 与 Chromium 的高风险提示发生在事件之后，不是执行前阻断。**
- Windows 原生观测代码已实现并进入 CI，但尚无真实设备端到端验收；iOS 仍是未接入引擎的有限脚手架。

适用对象是研究与评测、开发或预发环境，以及知情运维控制下的内部试点；不应把当前 RC 作为面向消费者或受监管环境的强制安全控制。

## 快速开始

~~~bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- coverage
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
- [发布安全与证据门禁](docs/release-security.md)
- [生成的攻击面覆盖矩阵](eval/coverage-matrix.md)

深层技术文档仍保留其原始语言；门户会标明语言、用途和状态，避免把历史复核记录当作当前发布结论。

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
