# Google Play 商品页草案

简体中文 · [繁體中文](PLAY_STORE.zh-TW.md) · [English](PLAY_STORE.en.md)

> **仅供发布准备，尚未提交 Google Play。** 文案必须在取得正式签名 AAB、真机验收、无障碍权限声明和 Play Console 数据安全表证据后再次复核。

## 应用名称

AgentGuard Companion

## 简短说明

在 Android 上观察 AI Agent 会话，并在发现支付、隐私和界面风险后发出本地提醒。

## 完整说明

AgentGuard Companion 在用户明确启用无障碍服务并开始守护会话后，观察界面文字、表单填写、深层链接和窗口覆盖情况。它可以识别支付或转账提示、隐私陷阱、非必要个人信息填写、可疑深层链接和提示词注入标记，并在设备上记录事件与显示风险通知。

用户可选择把事件转发到自己控制的桌面 AgentGuard 本地 API。中继使用 Bearer 令牌，Android 伴生应用还会使用 Android Keystore 中的 ECDSA P-256 密钥签署请求 body；设备公钥必须由用户登记到桌面适配器注册表。

**重要边界：** Android 伴生应用在事件发生后才观察并通知。它不能暂停、撤销或阻止第三方应用已经执行的支付、转账或其他操作，也不能描述为系统级拦截器。

## 当前发布阻塞项

- 当前配置为 `compileSdk = 34`、`targetSdk = 34`。
- 截至 2026-08-28，Google Play 对普通移动应用的新应用和更新要求至少 API 35；从 2026-08-31 起要求 API 36。当前构建不能作为合规的新应用或更新提交。参见 [Google Play 官方目标 API 要求](https://support.google.com/googleplay/android-developer/answer/11926878)。
- 仓库没有正式上传 keystore、正式签名 AAB 的验证记录、Play Console 审核结果或真机端到端验收。
- 尚未完成无障碍 API 使用声明、数据安全表和商店素材的最终审核。

## 数据安全草案

- 默认处理：无障碍事件、应用/窗口信息和风险结果保存在应用私有目录。
- 默认上传到开发者服务器：无。
- 可选传输：只有用户开启桌面转发后，事件才发送到用户配置的桌面 API。
- 共享：默认不与第三方共享。
- 删除：卸载应用会删除应用私有数据；发布前仍需补充产品内删除流程和正式保留策略。

以上是代码现状说明，不是已经提交或获批的 Play Console 声明。

## 敏感能力说明

### 无障碍服务

核心功能需要 `BIND_ACCESSIBILITY_SERVICE`：在用户主动开始的守护会话中观察界面文字和表单变化，以发现支付、隐私与注入风险。服务不具备撤销第三方操作的能力。

### 包可见性

清单使用精确的 `<queries>` 项查找匹配 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的广播接收器，并查询可启动应用以执行相似应用检查。项目不请求 `QUERY_ALL_PACKAGES`，但启动器可见性仍涉及隐私，正式提交时必须如实解释。

### 通知与前台服务

活动守护会话使用前台服务通知；Android 13 及以上还需要用户授予通知权限。高风险通知是事后提醒，通知被拒绝时风险仍会写入日志，但用户可能看不到及时提示。

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

`app/build.gradle.kts` 的 `signingConfigs.release` 会读取上述环境变量或同名 Gradle 属性。构建成功不等于可发布；还必须验证证书身份、升级 `targetSdk`、在真机完成权限与中继流程，并通过 Google Play 审核。

更多技术说明见 [Android Companion README](README.md) 和 [隐私政策](../../docs/privacy-policy.md)。
