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
  关闭失败，只有原生端明确返回 `disabled` 才放行；启用时允许一次或取消后仅发送脱敏事件。
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
