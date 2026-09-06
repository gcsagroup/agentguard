[简体中文](remediation-publication-2026-09-06.md) | [繁體中文](remediation-publication-2026-09-06.zh-TW.md) | [English](remediation-publication-2026-09-06.en.md)

# 跨平台整改源码提交说明（2026-09-06）

本次提交整理此前的跨平台整改及 macOS 新工作区、网关确认接线。**这是源码审查候选，不是安装包发布；生产仍为 No-Go。** 本地原始报告、截图、设备标识、凭据、构建输出和测试数据不随源码上传。

## 主要变化

- 共享引擎、路径判定、待确认生命周期、审计加密/签名/恢复及结构化发布门禁整改。
- macOS 五页工作区、四标签设置、安装向导、真实权限与存储状态；辅助功能必需，录屏可选。网关确认与桌面事后提醒分开，按进程和当前请求绑定，过期、重复、错号或断连不自动批准。
- Windows 观察与安全资源接线、Android 会话和隐私状态、受限 iOS Safari WebShield 工程及各自的测试/发布边界。
- Chrome / Edge 独立 block-only 扩展与静态 DNR；没有网页内允许一次、动作重放或 GA Native Messaging。Firefox 仅保留源码原型。

## 如何使用 macOS 新入口

先阅读[桌面说明](desktop-guide.md)。主动防护页可检查随包网关并生成配置；它不修改现有 MCP 客户端。当前网关启动后，从其本机日志取得本次令牌，在 App 中连接本机端口，再核对和回答待确认请求。令牌不保存，不自动重连。批准回执不是执行成功，最终结果在调用端核实。

写入请求显示目标与字节数，不展示完整文件正文；当前也没有经过验证的客户端来源身份或统一网关历史页。不要把这一通道解释为不可绕过的系统级保护。

## 验证与可复现入口

发布整合前的最终本地 arm64 / SQLCipher / ad-hoc App 已实际操作：拒绝后不产生文件，批准后才写入，超时与断开后未产生文件。这个结论只覆盖专用真实 stdio 测试客户端，不代表已接入用户的具体 MCP 客户端。原生 App 的权限与签名证据也不能转移到重新编译的另一个身份。

本次独立发布工作区重新运行 Rust workspace、macOS 后端、62 项工作区渲染检查、桌面弹层、扩展、Android Debug/Release 单测及 lint、iOS 模拟器和无签名构建检查。具体成功/失败以 PR 所列运行结果和该提交 CI 为准；不能拿源码静态测试计数当作实际通过数。

常用命令：

```bash
./scripts/bootstrap-rust.sh -- cargo test --workspace --locked
make check-shells check-extension-gate
node eval/ui-preview/workspace.test.mjs
make shell-a11y
make check-android
make check-ios
```

需使用仓库要求的 Rust、Node 22、JDK 21 与相应平台 SDK。Playwright 渲染检查明确使用后端桩；真正的网关文件副作用测试需要先构建 `agentguard-mcp`，设置 `AGENTGUARD_GATEWAY_TEST_BIN` 后显式运行 macOS 后端 `gateway_confirm` 的 `--include-ignored` 测试。CI 已接入这两类回归。

## 不随本次提交完成的事项

指定 MCP 客户端接入、最终签名身份下连续桌面观察、正式签名/公证、真机 Safari 与 TestFlight、各平台安装升级回滚及完整渠道验收仍是独立门槛。iOS 的无签名模拟器/设备构建不等于真实设备运行；Windows 的历史交互证据不等于当前版本验收。详见[发布证据](release-evidence.md)。
