# Google Play 商品页草案

简体中文 · [繁體中文](PLAY_STORE.zh-TW.md) · [English](PLAY_STORE.en.md)

> **仅供发布准备，尚未提交 Google Play。** 文案必须在取得正式签名 AAB、真机验收、无障碍权限声明和 Play Console 数据安全表证据后再次复核。

## 应用名称

AgentGuard Companion

## 简短说明

在 Android 上观察 AI Agent 会话，并在发现支付、隐私和界面风险后发出本地提醒。

## 完整说明

AgentGuard Companion 在用户明确启用无障碍服务并开始守护会话后，观察界面文字、表单填写、权限对话框和窗口覆盖情况。它可以识别支付或转账提示、隐私陷阱、非必要个人信息填写、界面文字里出现的可疑深层链接字样和提示词注入标记，并在设备上记录事件与显示风险通知。它不观察深层链接本身（无障碍服务看不到 intent）；各端真正发出的事件以源码生成的 [docs/capability-matrix.md](../../docs/capability-matrix.md) 为准，商店文案不得超出它。

当前 Release 构建不提供桌面中继。开发用 Debug 构建保留了中继联调，但 Relay v1 的响应未认证，因此它不能进入商店版本；响应认证和重放防护通过独立安全验收后才可重新纳入发布范围。

**重要边界：** Android 伴生应用在事件发生后才观察并通知。它不能暂停、撤销或阻止第三方应用已经执行的支付、转账或其他操作，也不能描述为系统级拦截器。

## 当前发布阻塞项

- 当前配置为 `compileSdk = 36`、`targetSdk = 36`（AGP 8.11.1；lint 零告警且 warning 即 error）。Google Play 从 2026-08-31 起要求 API 36，配置层面已满足；参见 [Google Play 官方目标 API 要求](https://support.google.com/googleplay/android-developer/answer/11926878)。
- Android 16 模拟器已经覆盖强制边到边、通知权限与状态、无障碍启停、运行中撤权和进程死亡 fail-closed；**Android 15/16 真机与 OEM 回归仍未完成**，模拟器证据不能替代这一发布阻塞项。
- 仓库没有正式上传 keystore、正式签名 AAB 的验证记录、Play Console 审核结果或真机端到端验收。
- 尚未完成无障碍 API 使用声明、数据安全表和商店素材的最终审核。

## 数据安全草案

- 默认处理：无障碍事件、应用/窗口信息和风险结果保存在应用私有目录。
- 默认上传到开发者服务器：无。
- 可选传输：当前商店候选无桌面转发；Debug 开发构建不属于发布版本。
- 共享：默认不与第三方共享。
- 删除：卸载应用会删除应用私有数据；发布前仍需补充产品内删除流程和正式保留策略。

以上是代码现状说明，不是已经提交或获批的 Play Console 声明。

## 敏感能力说明

### 无障碍服务

核心功能需要 `BIND_ACCESSIBILITY_SERVICE`：在用户主动开始的守护会话中观察界面文字和表单变化，以发现支付、隐私与注入风险。服务不具备撤销第三方操作的能力。

### 包可见性

清单使用精确的 `<queries>` 项查找匹配 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的广播接收器，并查询可启动应用以执行相似应用检查。项目不请求 `QUERY_ALL_PACKAGES`，但启动器可见性仍涉及隐私，正式提交时必须如实解释。

### 通知与无障碍服务状态

活动守护会话使用普通常驻通知（生命周期由无障碍服务承担，不声明 `dataSync` 前台服务）；Android 13 及以上还需要用户授予通知权限。高风险通知是事后提醒，通知被拒绝时风险仍会写入日志，但用户可能看不到及时提示。

## 发布签名接线

不要把 keystore、密码或 `gradle.properties` 中的凭据提交到仓库。示例：

```bash
keytool -genkeypair -v \
  -keystore /secure/path/agentguard-upload.jks \
  -alias agentguard \
  -keyalg RSA -keysize 2048 -validity 10000

export AGENTGUARD_STORE_FILE=/secure/path/agentguard-upload.jks
export AGENTGUARD_STORE_PASSWORD='<从安全凭据存储读取>'
export AGENTGUARD_KEY_ALIAS=agentguard
export AGENTGUARD_KEY_PASSWORD='<从安全凭据存储读取>'

cd apps/android-companion
./gradlew --no-daemon :app:bundleRelease
```

`app/build.gradle.kts` 的 `signingConfigs.release` 会读取上述环境变量或同名 Gradle 属性。构建成功不等于可发布；还必须验证证书身份、在真机完成权限生命周期，并通过 Google Play 审核。桌面中继不属于当前 Release 验收范围。

更多技术说明见 [Android Companion README](README.md) 和 [隐私政策](../../docs/privacy-policy.md)。
