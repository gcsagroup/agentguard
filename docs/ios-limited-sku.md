[简体中文](ios-limited-sku.md) | [繁體中文](ios-limited-sku.zh-TW.md) | [English](ios-limited-sku.en.md)

# iOS 受限 SKU

> **当前状态：可构建的本地候选；正式发布 No-Go。**
>
> 源码机械事实以生成的 [能力矩阵](capability-matrix.md) 为准。本页描述产品边界和外部验收，
> 不把模拟器结果升级成真机、签名或 App Store 证据。

## 已实现：IOS-01～05

1. `apps/ios-webshield/project.yml` 可复现生成包含主 App、Safari Web Extension、
   `WebShieldCore`、unit/UI tests 的 Xcode 工程；主 App 嵌入扩展。
2. Safari 内容脚本只在 isolated world 检查 DOM 点击与表单提交，对付款、提示注入和敏感表单
   直接阻断匹配操作；提示只有关闭键，不提供“允许一次”或重放。
3. `sendNativeMessage` 接入版本化白名单 Swift 合同；原生层限制消息大小/条数，将 URL 缩减为
   origin 后才写入本地审计。
4. App Group UserDefaults 保存同意与开关；原子 JSONL 审计通过 actor、`NSFileCoordinator` 和
   保留上限协调。App/扩展声明共享 Keychain 组，不包含生产凭据。
5. 主 App 提供三语启用指引、隐私边界、活动列表和本地清除入口；App/扩展都包含
   PrivacyInfo。

实现和复现命令见 [iOS WebShield README](../apps/ios-webshield/README.md)。

## 永不扩大解释的边界

- 不监控 Safari 以外的 App、系统 UI、Accessibility 或屏幕。
- 不使用 MAIN world，也不拦截 `fetch`/XHR；程序化直接网络请求不是本版能力。
- 不使用 Chromium 的 `connectNative` 长连接、远程 DNR 情报或上传端点。
- Swift-first 指平台桥、状态和审计，不是重写或等价替代 Rust 策略引擎。
- 当前只支持 Safari 获得网站权限后的页面内合作式防护，不是不可绕过的安全边界。

## 已取得证据

2026-09-05 在 Xcode 26.6 / iOS 26.5 模拟器 SDK 上：无签名 Release build、Analyze 和完整严格并发
检查成功；主 App 产物包含 Safari `.appex`；Swift Core 20/20、UI 2/2、扩展 Node 18/18 通过；
容器 App 已在现有 iOS 26.5 模拟器安装、启动并截图检查。

完全关闭代码签名时 App Group 和 Keychain entitlement 不可用，UI 会明确报错并保持防护关闭；
这是预期的 fail-closed 行为，不是签名验收。

## 发布前仍需完成

- 确认生产 bundle IDs，注册同 Team 的 App Group 与 Keychain capabilities，并生成 profiles。
- 完成签名 Archive、entitlements 回读和 App Store Connect 校验。
- 在代表性真机 Safari 验收扩展启用、网站权限、关闭提示后仍阻断、普通操作不误拦、进程重启、Private
  Browsing、三语、升级/卸载及清除。
- 完成 TestFlight 安装/升级和隐私声明复核。

这些条件全部完成前，iOS 只能标为 **buildable limited candidate**，不能标为已发布或完整支持。

## 2026-09-17 阻断合同修正

上一轮 App 与 Extension 构建号同为 2，名称和 Bundle ID 保持。移除页面内的一次放行及重放，修正网页伪造提示属性绕过；新事件记为 `blocked`，旧 `allowed`／`cancelled` 保留原含义。新增四个扩展回归在旧代码全部失败，修正后 Node 22／22、Swift Core 21／21 和 UI 2／2 通过；Xcode 27 严格 Release 模拟器／无签名设备构建及 Analyze 通过。真实 Chromium DOM 夹具验证了三语提示和零风险请求，但原生状态是合成的，不能代替真机 Safari 或 TestFlight。详见[本轮记录](ios-block-only-2026-09-17.zh.md)。

## 2026-09-17 键盘提示修正（构建 3）

App 与 Extension 现为 1.0.0 (3)，名称和 Bundle ID 保持。风险提示关联三语标题和说明，Tab／Shift+Tab 留在关闭键；关闭或 Escape 返回此前仍连接的控件，重叠提示按层处理。没有新增放行或重放。四个新增回归在旧源码全部失败；修正后 Node 26／26、Swift 23／23、两种严格 Release 和 Analyze 通过，真实 Chromium DOM 的三语键盘操作无风险请求。原生桥为合成；真实 Safari、VoiceOver、动态字体与 TestFlight 未验收。前批 CI 另有 macOS 启动等待和 Windows 并发审计失败，仍待解决。 [记录](ios-dialog-accessibility-2026-09-17.zh.md)。
