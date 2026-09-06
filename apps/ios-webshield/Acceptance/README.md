# iOS 26.5 模拟器验收记录（2026-09-05）

本记录只证明当前源码在本机模拟器的构建、测试、安装和容器 App 启动，不证明签名、真机
Safari 扩展行为或 App Store 可发布。

## 环境

- Xcode 26.6（17F113）
- iOS Simulator SDK 26.5
- XcodeGen 2.46.0
- 设备：iPhone 17 / iOS 26.5 模拟器；机器专属名称和标识不公开。

## 结果

- 从 `project.yml` 生成工程：成功，存在 App、Safari Extension、WebShieldCore、unit/UI test
  五个 targets。
- Debug 测试构建、Release 通用模拟器和 Release 通用设备构建均以
  `CODE_SIGNING_ALLOWED=NO` 成功；设备包为未签名 arm64，模拟器包只有链接器 ad-hoc 签名，
  不能替代分发签名。
- Release Analyze：成功，无诊断输出。
- Swift Core：20/20 通过，包括读取物理清除、全过期空文件和 32 个独立 Store 并发不丢记录。
- Swift UI：2/2 通过。
- Safari 扩展 Node 合同/生命周期：18/18 通过，包括早期 capture、frame 独立注入、open
  Shadow DOM、四态、状态延迟/失败与迟到结果隔离。
- Release 模拟器产物经 `simctl install` / `simctl launch com.agentguard.webshield`：成功，并回读
  容器 App 已呈现“共享存储不可用”的预期关闭状态。
- `pluginkit` 识别 `com.agentguard.webshield.extension (1.0.0)`。

## 截图

启动截图保留在本地验收材料中，不随源码提交；本文不作为独立签名发布证据。

截图中的“共享存储不可用”是完全关闭代码签名后的预期结果：App Group/Keychain entitlement
没有有效签名便不可用，应用保持关闭。它不会退回普通沙盒存储来伪造成功。

## 未覆盖

- Team/App IDs、App Group、Keychain capability 和 provisioning profiles。
- 签名 Archive、entitlements 回读、App Store Connect/TestFlight。
- 真机 Safari 扩展开关、网站权限、Private Browsing、DOM 允许/取消端到端。
- isolated-world 与页面世界的真实监听顺序、closed shadow、缺少网站权限或非 HTTP(S) frame。
- App 与 Extension 两个真实进程同时维护 App Group 文件；单测验证的是独立 Store 实例及
  `NSFileCoordinator`/原子替换边界，真机跨进程压力仍待签名环境。
- 真机升级、卸载、进程回收和多 Safari profile 数据隔离。
