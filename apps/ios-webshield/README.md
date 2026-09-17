[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

# AgentGuard iOS WebShield

状态：**可构建的 Swift-first 受限 SKU；正式发布仍为 No-Go。**

这里提供正式 XcodeGen 工程、iOS 容器 App、Safari Web Extension、共享
`WebShieldCore`、Swift 单元测试、UI 测试和独立扩展脚本测试。它不接入实验性的 Rust
`guard-ffi`，也不能替代签名、真机 Safari 或 TestFlight 验收。

## IOS-01～05 已实现

- **IOS-01 工程：**`project.yml` 生成 App、Safari 扩展、静态 Core、unit/UI test targets；主
  App 通过 `Embed App Extensions` 嵌入扩展。
- **IOS-02 Safari 门控：**Manifest V3 isolated-world 内容脚本以 `document_start` 注入所有获准的
  HTTP(S) frame，并同步注册 capture listener。`unknown`/`unavailable` 对已识别的危险点击或提交
  关闭失败，只有原生端明确返回 `disabled` 才放行；启用时阻断匹配操作并发送脱敏的 `blocked` 记录；提示只有关闭键，不授权或重放。
- **IOS-03 原生合同与存储：**Swift 原生消息只接受版本 1 白名单字段，限制为 64 KiB/50 个
  事件；URL 只保留 HTTP(S) origin。App Group UserDefaults 保存同意/开关，原子 JSON 审计由
  actor 与 `NSFileCoordinator` 协调的原子 JSONL，最多保留 7 天或 500 条；读取也会在同一个协调
  写事务内把过期行从磁盘物理清除。
- **IOS-04 隐私与界面：**App 和扩展均有简体、繁体、英文文案；包括启用指引、清除入口、
  App Group/Keychain entitlements、PrivacyInfo 与应用图标。
- **IOS-05 测试：**Swift Core、无签名边界、UI 启动和扩展契约均有自动测试。

## 构建

生成的 `.xcodeproj` 已在本目录 `.gitignore` 中排除；可由 `project.yml` 随时重建：

```bash
xcodegen generate --spec apps/ios-webshield/project.yml

xcodebuild \
  -project apps/ios-webshield/AgentGuardWebShield.xcodeproj \
  -scheme AgentGuardWebShield \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

扩展脚本测试：

```bash
node --test apps/ios-webshield/Tests/ExtensionTests/*.test.cjs
```

## 数据与消息边界

网页内容脚本只把以下字段交给原生扩展：合同版本、随机 request ID、规则 ID、固定 finding/action
枚举、时间和当前 URL。Swift 再次执行严格校验，并在落盘前把 URL 缩减到 origin。原始 DOM、
输入值、URL 路径、query、fragment 和页面标题既不落盘也不上传。

审计文件位于 App Group `group.com.agentguard.webshield`。两个 targets 还声明同一个
Keychain access group；完全关闭代码签名时 Keychain 与 App Group 会返回 entitlement 错误，产品
会保持关闭，不会退回普通沙盒目录伪装成功。

## Safari 可证明边界

- `document_start` 和 capture listener 缩短注册窗口，但 isolated-world 不保证早于页面世界的每一段
  脚本；门控只能取消它实际收到且可取消的 DOM 事件，不能撤销页面监听器更早完成的副作用。
- `all_frames` 覆盖获得网站权限且匹配 Manifest 的 HTTP(S) frame，不据此声称覆盖任意
  `about:blank`/`srcdoc` frame、缺少权限的 frame 或注入前动作。
- open Shadow DOM 仅覆盖初始扫描、DOM mutation 发现，或由事件 `composedPath()` 暴露的开放根；
  不覆盖 closed shadow，也不声称拦截脚本直接调用网络/API 的动作。
- 状态尚未返回或本机消息失败时，只阻止本地规则已判定为危险的候选，不自动重放；普通动作继续。
  原生端明确确认关闭防护时，危险候选按用户选择放行。

## 明确不支持

- 不使用 MAIN world，不修改 `window.fetch` 或 `XMLHttpRequest`。
- 不使用 `connectNative` 长连接、DNR 远程情报或任何上传端点。
- 不监控其他 App、系统 UI、Accessibility 或屏幕内容。
- 不声称覆盖脚本直接发送的网络请求，也不声称与 Rust 规则引擎等价。

## 2026-09-05 本地验收

- Xcode 26.6 / iOS 26.5 Simulator SDK / XcodeGen 2.46.0。
- Release 通用模拟器与通用设备构建均以 `CODE_SIGNING_ALLOWED=NO` 通过；设备包完全未签名，
  模拟器二进制只有链接器 ad-hoc 签名，二者都不是发布签名证据。主 App 内存在 Safari `.appex`
  及全部声明资源，Release Analyze 无诊断。
- `WebShieldCoreTests`：20/20 通过。
- `AgentGuardWebShieldUITests`：2/2 通过。
- Safari 扩展 Node 契约与生命周期：18/18 通过。
- 已在现有 iOS 26.5 “Aegis QA iPhone 17” 模拟器安装并启动容器 App。

截图和环境记录见 [Acceptance/README.md](Acceptance/README.md)。

## 发布阻断

仓库没有 provisioning profile，也没有 App Group/Keychain capability 的开发者后台注册证据；
因此 Archive、签名、真机 Safari 扩展启用、网站权限、Private Browsing、升级/卸载和 TestFlight
均未通过。配置 Team/App IDs/profiles 并完成这些验收前，发布结论仍是 **No-Go**。

## 2026-09-17 阻断合同修正

上一轮 App 与 Extension 构建号同为 2，名称和 Bundle ID 保持。移除页面内的一次放行及重放，修正网页伪造提示属性绕过；新事件记为 `blocked`，旧 `allowed`／`cancelled` 保留原含义。新增四个扩展回归在旧代码全部失败，修正后 Node 22／22、Swift Core 21／21 和 UI 2／2 通过；Xcode 27 严格 Release 模拟器／无签名设备构建及 Analyze 通过。真实 Chromium DOM 夹具验证了三语提示和零风险请求，但原生状态是合成的，不能代替真机 Safari 或 TestFlight。详见[本轮记录](../../docs/ios-block-only-2026-09-17.zh.md)。

## 2026-09-17 键盘提示修正（构建 3）

此前 App 与 Extension 为 1.0.0 (3)，名称和 Bundle ID 保持。风险提示关联三语标题和说明，Tab／Shift+Tab 留在关闭键；关闭或 Escape 返回此前仍连接的控件，重叠提示按层处理。没有新增放行或重放。四个新增回归在旧源码全部失败；修正后 Node 26／26、Swift 23／23、两种严格 Release 和 Analyze 通过，真实 Chromium DOM 的三语键盘操作无风险请求。原生桥为合成；真实 Safari、VoiceOver、动态字体与 TestFlight 未验收。前批 CI 另有 macOS 启动等待和 Windows 并发审计失败，仍待解决。 [记录](../../docs/ios-dialog-accessibility-2026-09-17.zh.md)。

## 原生文字对比度（2026-09-17）

此前 App／Extension 为 1.0.0 (13)，名称与 Bundle ID 保持。状态、说明和分组标题使用正文颜色；共享存储不可用时防护仍关闭。新增三语首屏对比度及滚动回归，开发门禁 Node 26／26、Swift 26／26、严格 Release 与 Analyze 通过。完整自动审计仍有动态字体、截断和后续页面报告，I6、真机 Safari 与 TestFlight 未通过；[证据与限制](../../docs/ios-native-contrast-2026-09-17.zh.md)。

## 旧工具链兼容（2026-09-17）

此前 App／Extension 为 1.0.0 (22)，沿用相同名称与标识。逐页布局与多行文字修正见[构建 21 记录](../../docs/ios-page-audit-2026-09-17.zh.md)；该提交在 CI 的 Xcode 16.4 因新 API 不存在而编译失败。构建 22 补充编译期隔离，本机完整门禁通过，准确提交 `b458ca5` 的 CI 已 13／13 成功；Xcode 16.4／iOS 18.5 的 Node 26／26、Swift 26／26、严格 Release 和 Analyze 通过。最大字号、真机 Safari、VoiceOver 与 TestFlight 尚未验收；见[修正与证据边界](../../docs/ios-sdk-compatibility-2026-09-17.zh.md)。

## 逐段覆盖与分阶段审计（2026-09-17）

此前 App／Extension 为 **1.0.0 (33)**，名称、标识和产品界面保持。重叠滚动核对正文逐段可见范围，当前字号对比度先检查，动态字体最后检查；全部类别仍被覆盖。遮挡报告只有在完整显示后的整屏复查通过才算解决，构建 31 的真实低对比度反例仍失败。主构建 Node 26／26、Swift 26／26、严格 Release、Analyze 与仓库 23／23 通过，32 的最大字号深色 2 通过／1 失败保留；33 将复查改为从初始页面定位，三语四种显示状态共 12 组全部通过，测试机恢复关闭。基线 `75c7f1b` CI 12 成功／1 失败，旧 SDK 修复待准确新提交复验；I6、正式签名、真实 Safari、VoiceOver 与 TestFlight 未完成。[证据与限制](../../docs/ios-visible-audit-2026-09-17.zh.md)。

## iOS 文字识别独立检查与旧系统失败定位（2026-09-17）

**1.0.0 (34)**。构建 34 将文字识别放在其它审计之前，保存阶段树、截图和报告类型；全部类别与未知报告失败条件保持。准确源码提交 bc0433d 的 CI 13／13 成功，iOS 18.5 的完整开发门禁通过；旧文字识别报告本次未再出现，构建 33 的真实失败保留。

本机 Node 26／26、Swift 26／26、严格 Release、Analyze、三语四状态 12 组及仓库 23／23 通过，测试机恢复关闭。产品界面与固定 macOS App 024 保持；I6、真机、签名与发布门槛未完成。 [记录](../../docs/ios-ci-audit-2026-09-17.zh.md)。
