# iOS 旧工具链编译修正与 CI 失败保留

日期：2026-09-17。基线 `8b55a0e9dae656cb4b430201c594d116fe40c278`，App／Extension 同步为 **1.0.0 (22)**，名称、Bundle ID、权限和存储格式不变。固定 macOS App 仍为 024，本批没有重建或重签。

## 失败原因与改动

基线 [CI 35149317349](https://github.com/gcsagroup/agentguard/actions/runs/35149317349) 最终 11 项成功、2 项失败。iOS 在 Xcode 16.4／iOS 18.5 SDK 编译时报告 `ContentView.swift:13: value of type 'some View' has no member 'scrollEdgeEffectHidden'`，尚未运行 Swift 测试。前批本机 Xcode 27 通过不能证明旧工具链兼容；该失败保留。

`if #available(iOS 26.0, *)` 只控制运行时分支，旧 SDK 没有对应声明。本次增加 `#if compiler(>=6.2)`，在标准 Xcode 内置工具链中隔离新 API：旧工具链编译相同页面内容，新工具链仍按系统版本选择滚动边缘效果。没有删除新版导航栏修正、改变最低 iOS 17 目标或降低测试要求。编译器版本判断与项目现有 Swift 5 语言模式分别处理，参考 [Swift 条件编译说明](https://docs.swift.org/swift-book/ReferenceManual/Statements.html)及 [Apple API 文档](https://developer.apple.com/documentation/swiftui/view/scrolledgeeffecthidden(_:for:))。

## 本机验证

使用原有 `Aegis QA iPhone 17`、iOS 26.5（23F77），Xcode 27.0（27A266a）、Swift 6.4 和 XcodeGen 2.46.0，运行 `bash scripts/check-ios.sh`：

- Node 26／26、Swift 26／26（Core 21、UI 5），零失败、零跳过。
- 严格 Release 模拟器、无签名设备构建及 Analyze 全部通过。
- 三语标准字号逐页全类别审计及 6 张原生截图已核对；说明可读、可滚动至隐私末尾，导航栏没有正文穿透。仍仅豁免禁用清除按钮的对比度，本次 3 条报告均留存，没有扩大例外。
- 6 个 App／Extension 产物均为构建 22，三份扩展各 7 项资源与源码相同。固定 macOS App 的 91 个文件及模式仍与 024 冻结包完全一致。
- 仓库约束 23／23 及 HTTP 控制入口定向 Clippy（`-D warnings`）通过。
- 模拟器核对为 `large`／`light` 后恢复关闭；没有清除设备或其它 App 数据。

本机只执行新版工具链分支。**旧 SDK 分支须以修正提交的 CI 结果证明**，不能从条件编译文字推断通过。最大字号完整审计此前的失败保留，本批不计 I6、真实 Safari、VoiceOver 或 TestFlight 验收。

## Windows 失败定位

同一基线的 Windows 作业在 `dropping_idle_or_unstarted_listener_releases_port_and_workers` 失败：销毁入口后，首次 TCP 连接探测仍成功；该文件 14 项通过、1 项失败。原日志没有区分未启动／已启动分支，也没有探测连接的两端地址，暂不能归因为监听泄漏或端口复用。

本次只为三处关闭断言补充阶段、目标及完整连接诊断；仍要求第一次探测失败，没有重试、放宽或吞掉成功连接。macOS 同组 16 项全部通过；Windows 少一项 Unix 专用测试。提取相同断言、保留一个真实回环监听器的受控反例按预期退出 101，阶段、目标、连接双方与 socket 信息齐全。这只验证诊断能报告失败，不冒充 Windows 根因复现或产品修复。

本批原始日志、截图、产物摘要和反例保存在 `.artifacts/ios-sdk-compatibility-2026-09-17/`；[公开索引](evidence/ios-sdk-compatibility-2026-09-17.json)记录哈希。此前 Windows 并发审计及 macOS 启动等待的间歇性根因也仍未关闭。计划仍为 28 完成／1 附条件／1 开发中／2 待开始，AGD-027 原性能预算、F13 暂缓及发布 No-Go 均保持。
