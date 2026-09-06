# AgentGuard Android Companion

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

Android 伴生应用使用 Kotlin、Jetpack Compose 和 `AccessibilityService` 观察守护会话中的界面事件，执行本地启发式检查，并将最小化事件写成 JSONL。

> 当前状态：源码、JVM 单元测试、Debug APK 和 API 36 模拟器权限生命周期已验证；尚无真机端到端验收、正式发布签名证据或 Google Play 发布记录。通知是事件发生后的提醒，不能暂停、撤销或阻止第三方应用已经执行的操作。Relay v1 的响应未认证，因此 Release 构建会强制禁用桌面中继；它只保留在 Debug 构建中用于协议开发。

## 能做什么

- 观察文本变化、界面文本、权限对话框和窗口覆盖情况（各端真正发出的事件以源码生成的 [docs/capability-matrix.md](../../docs/capability-matrix.md) 为准）。
- 检测支付/转账文字、隐私陷阱、非必要个人信息、提示词注入标记，以及界面文字里出现的可疑深层链接**字样**（`intent://` 一类）。它不观察深层链接本身——无障碍服务看不到 intent。
- 调查可见的文本输入广播接收器及其他已启用的无障碍服务。
- 将每个会话的信封追加到应用私有目录 `files/events/session-<id>.jsonl`。
- Debug 构建可通过用户明确配置的 HTTP 中继联调桌面本地 API；Release 构建在响应认证完成前强制禁用该能力。
- 使用 Android Keystore 中不可导出的 ECDSA P-256 密钥为实际发送的 HTTP body 签名。

## 构建与测试

使用 JDK 21（本项目已验证）以及包含 API 36 平台与 36.0.0 build-tools 的 Android SDK（AGP 8.11）。Gradle 至少要求 JDK 17，但本项目不承诺任意更高版本都兼容；已知默认 JDK 25 会失败。可以在 Android Studio 中打开 `apps/android-companion`，或从仓库根目录运行：

```bash
cd apps/android-companion
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug
```

Debug APK 输出到：

```text
apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

## 运行

```bash
adb install -r apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

然后在设备上：

1. 在 Android 13 及以上版本授予通知权限。
2. 打开系统无障碍设置，启用 AgentGuard Companion。
3. 返回应用并点击“开始守护会话”。无障碍服务会显示普通常驻状态通知。
4. 仅在 Debug 协议联调时，可启动本地 API并开启转发；Release 构建不会显示或启用该入口。

USB 调试路径示例：

```bash
# 桌面端，在仓库根目录运行
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# 让手机的 127.0.0.1:8788 转到桌面
adb reverse tcp:8788 tcp:8788
```

Debug 构建的默认中继地址是 `http://127.0.0.1:8788/v1/events`。该 HTTP 路径只用于本机开发，不得作为发布配置；不要把本地 API 无认证暴露到网络。

可以通过 Android Studio Device File Explorer 或 `run-as` 读取应用私有目录中的 JSONL。每一行都是一个信封；将单行保存成 JSON 文件后可离线回放：

```bash
cargo run -p guard-cli -- ingest-android --payload /path/to/one-envelope.json
```

## 适配器签名接线

应用为实际发送的 UTF-8 HTTP body 签名，签名信息通过以下请求头传递：

```text
X-AgentGuard-Adapter: android-companion
X-AgentGuard-Timestamp: <毫秒时间戳>
X-AgentGuard-Signature: <DER 签名十六进制>
```

密钥由 Android Keystore 管理，私钥不可通过应用 API 导出；Android 9 及以上会优先请求 StrongBox，不可用时回退到设备提供的 Keystore 实现，因此不能在没有设备证明的情况下声称所有设备都由硬件托管。

接线步骤：

1. 开启应用中的桌面转发，点击“显示适配器公钥”，复制以 `04` 开头的 130 位 SEC1 十六进制公钥。
2. 在桌面仓库根目录生成注册卡：

   ```bash
   cargo run -p guard-cli -- adapter-card \
     --adapter-id android-companion \
     --platforms android \
     --public-key <130位十六进制公钥>
   ```

3. 将输出合并到 `policies/adapter-registry.yaml`，重启桌面 API。

未注册公钥时，桌面端把伴生应用的调查视为未签名：它可以增加风险，但不能用“环境干净”清除已存在的风险。该签名证明信封来自持有设备密钥的一方，不证明应用未被修改，也不替代 Play Integrity 或设备完整性证明。

## 环境调查的限制

`EnvironmentScanner` 会检查匹配 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的清单式广播接收器，以及其他已启用的无障碍服务。Android 11 及以上受包可见性限制；“干净”只表示没有发现当前可见的匹配项，不代表设备上绝对不存在监听者。详见 [Android 环境调查](../../docs/android-env-survey.md)。

## 未完成与发布边界

- 没有在手机上运行 Rust 引擎或 FFI；Release 版本当前只提供本地启发式检测，桌面中继尚未进入发布范围。
- Android 的高风险提示是事后通知，不是执行前确认框。
- 没有真机权限生命周期测试或真实 Agent 端到端记录；API 36 模拟器证据不能替代真机。
- 没有正式发布 keystore 签名证据，也未提交 Google Play 审核。
- `compileSdk / targetSdk = 36` 已满足 Google Play 的目标 API 要求；Android 16 模拟器已验证边到边、通知权限与状态、无障碍启停、运行中撤权及进程死亡 fail-closed，但 **API 35+ 真机/OEM 回归仍未完成**；见 [Google Play 草案](PLAY_STORE.md)。

跨语言签名格式由 `eval/fixtures/adapter_signature_vectors.json` 固定，设计细节见 [适配器断言签名](../../docs/适配器断言签名.md)。
