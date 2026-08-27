# AgentGuard iOS WebShield（受限方向）

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

本目录目前只有一个 SwiftUI 源码片段：`Sources/ContentView.swift`。它显示策略状态，并对内置示例字符串运行简单关键词演示。

> 这不是可直接构建的 iOS 应用：仓库中没有 `.xcodeproj`、`.xcworkspace`、Swift Package manifest、Safari Web Extension target、签名配置、entitlements 或可运行的 iOS 测试。

## 当前实际内容

- 一个 `ContentView` SwiftUI 视图。
- 一个只处理固定示例文本的 `LocalHeuristics.scanDemoPage()` 演示。
- 没有 `WKWebView` 接线，也没有 Safari Web Extension 实现。
- 没有连接 Rust 引擎、`guard-sync`、Managed App Configuration 或 App Group。

因此，本目录只能作为 iOS 受限 SKU 的设计起点，不能证明已具备网页守护、会话隔离或发布能力。

## 本地试验

如需查看该片段：

1. 在 Xcode 中新建一个 SwiftUI iOS App，例如 `AgentGuardWebShield`。
2. 将 `Sources/ContentView.swift` 复制到新工程并设为初始视图。
3. 选择开发团队与 Bundle Identifier，在模拟器或设备上构建。

这些步骤会在仓库之外生成本地 Xcode 工程；不要把它误认为仓库提供了可复现的 iOS 构建。

## 若要成为可交付组件

至少还需要：

- 可复现的 Xcode 工程或 Swift Package 结构；
- 明确的 `WKWebView` 或 Safari Web Extension target 与消息通道；
- 三语 UI、隐私披露、entitlements、签名和打包配置；
- 与 AgentGuard 策略/引擎的真实接线；
- 单元测试、UI 测试及真机端到端验收；
- App Store 能力、权限和审核结论。

当前结论：**源码片段可供试验，iOS 产品与发布物尚不存在。**
