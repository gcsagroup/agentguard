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
- 在首个 GA 支持的 Chrome / Edge 页面内，对匹配的付款按钮和陷阱表单执行 block-only 的执行前阻断；对已声明付款关键词、HTTP(S)、非 GET/HEAD 与指定资源类型的请求启用静态 DNR 硬阻断。
- 在 Linux 上，通过 `guard-jail` 为其自己启动的进程提供窄范围的内核文件系统边界；任务显式声明 `scope.net` 时，还可在 Landlock 支持下限制 TCP 连接与监听端口。
- 用 `guard-trust` 统一六类入站面的 fail-closed 信任词汇，并把当前 36 条用户能力声明映射到具体测试与生成状态仪表盘。

## 必须理解的边界

- **不是零间隙实时监控。** macOS AX 树变化已有 AXObserver 推送、合并与兜底轮询；像素捕获及其他桌面路径仍包含采样或轮询，间隙内的动作可能看不到。
- **大部分控制是合作式的。** Agent 如果绕过网关直接执行命令，网关无法阻止。
- **不是通用沙箱、EDR、防火墙或 DLP。** Linux `guard-jail` 只约束它启动的进程；网络端口天花板是可选能力，声明后若所选后端无法强制会拒绝启动。
- **浏览器控制有明确范围。** DOM 风险动作只阻断，网页内没有放行；页面提示只是可被页面影响的信息层，用户若坚持继续只能从浏览器扩展管理页停用或移除保护后自行重做。静态 DNR 不检查 body，也不覆盖自定义别名或其他未声明表面；GA manifest 禁用 Native Messaging。Android 高风险提示仍发生在事件之后。
- 首个 GA 的浏览器包只支持共用 Chromium 包的 Chrome / Edge；Firefox 仅保留源码原型，不打包、不作为验收门。iOS WebShield/Safari Extension 是首发正式产品范围内的独立 Xcode/Swift 受限 SKU，不是未来可选项。旧 ad-hoc macOS 候选曾在本机通过启动、TCC 探测和 AXObserver 推送流程检查，但本轮最新 universal `.app` 尚未完成全量复验，签名/公证后的全新安装与升级验收也仍缺失。Windows 历史候选 `89dadf9` 已取得真实 Windows 11 上的启动、连续观测与风险确认界面部分证据，但当前安全构建、签名安装包及全新安装/升级/卸载仍待重新验收。iOS 已有可构建的受限 Safari WebShield App/扩展/Core 工程并通过无签名模拟器测试，但未接 Rust 引擎，生产签名、真机 Safari 与 TestFlight 仍未完成。
- **各端真正观察什么，以源码生成的 [docs/capability-matrix.md](docs/capability-matrix.md) 为准。** 上面"分析深链"说的是引擎能力（离线语料与适配器格式带 `deeplink` 事件）；目前没有任何一端的观察器在真机上发出深链事件——Android 只报界面文字里的深链字样。

适用对象是研究与评测、开发或预发环境，以及知情运维控制下的内部试点；不应把当前 RC 作为面向消费者或受监管环境的强制安全控制。

## 快速开始

~~~bash
# 一次性安装 rust-toolchain.toml 钉住的 1.95.0；不会改系统默认工具链。
make bootstrap-rust

# wrapper 同时固定 PATH、Cargo、rustc 与 sysroot，避免 Homebrew/rustup 混用。
./scripts/bootstrap-rust.sh -- cargo test --workspace
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- eval --scenarios eval/scenarios
./scripts/bootstrap-rust.sh -- cargo run -p guard-cli -- coverage
./scripts/bootstrap-rust.sh -- make capability-claims
./scripts/bootstrap-rust.sh -- make check-extension-gate
./scripts/bootstrap-rust.sh -- make acceptance
./scripts/bootstrap-rust.sh -- make check
~~~

macOS 开发壳：

~~~bash
cd apps/desktop-macos
npm install
npm run tauri dev
~~~

**装好之后怎么用**：见[桌面端使用说明](docs/desktop-guide.md)。macOS 提供五页工作区、四标签设置、浏览器安装向导及网关确认入口；辅助功能必需，录屏可选。自检只验证模拟风险提醒，不证明拦截了外部动作。

网关确认需连接当前进程的端口和令牌，可核对、拒绝或仅批准当前请求；过期和断连不自动放行。它不代表具体 MCP 客户端已接入。见[本次整改与验证说明](docs/remediation-publication-2026-09-06.md)。

## 文档

- [文档门户](docs/README.md)
- [桌面端使用说明](docs/desktop-guide.md)
- [1.0.0-rc.1 发布说明](docs/RELEASE-1.0.0-rc.1.md)
- [变更记录](CHANGELOG.md)
- [范围与非目标](docs/scope-and-non-goals.md)
- [平台能力矩阵](docs/platform-matrix.md)
- [入站信任](docs/入站信任.md)
- [主张与测试映射](docs/主张与测试映射.md)
- [浏览器执行前阻断](docs/浏览器执行前阻断.md)
- [真机验收执行手册](docs/acceptance-runbook.md)
- [结构化发布证据](docs/release-evidence.md)
- [GA 发布闭环门禁](docs/ga-release-gate.md)
- [历史发布门禁设计说明](docs/release-security.md)
- [生成的攻击面覆盖矩阵](eval/coverage-matrix.md)

本轮新增的关键技术与验收文档提供简体中文、繁體中文和英文版本；其余深层文档仍保留原始语言。门户会标明语言、用途和状态，避免把设计、离线测试或历史复核记录当作当前真机与发布结论。

## 仓库结构

~~~text
crates/    Rust 引擎、规则、审计、评测与工具
adapters/  macOS、Windows、Android 与浏览器适配器
apps/      桌面端、Chromium 扩展、Android 伴生应用与受限 iOS Safari WebShield
docs/      产品边界、架构、发布、安全与研究文档
eval/      场景、夹具、覆盖声明与生成报告
~~~

## 许可证

[Apache License 2.0](LICENSE)
