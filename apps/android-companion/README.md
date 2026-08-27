# AgentGuard Android Companion

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

Android 伴生应用使用 Kotlin、Jetpack Compose 和 `AccessibilityService` 观察守护会话中的界面事件，执行本地启发式检查，将事件写成 JSONL，并可选择转发给桌面端 AgentGuard 引擎。

> 当前状态：源码、JVM 单元测试和 Debug APK 构建路径可用；尚无真机端到端验收、正式发布签名证据或 Google Play 发布记录。通知是事件发生后的提醒，不能暂停、撤销或阻止第三方应用已经执行的操作。

## 能做什么

- 观察文本变化、界面文本、深层链接、权限对话框和窗口覆盖情况。
- 检测支付/转账文字、隐私陷阱、非必要个人信息和提示词注入标记。
- 调查可见的文本输入广播接收器及其他已启用的无障碍服务。
- 将每个会话的信封追加到应用私有目录 `files/events/session-<id>.jsonl`。
- 通过用户明确配置的 HTTP 中继把信封发到桌面本地 API，并显示引擎返回的高风险通知。
- 使用 Android Keystore 中不可导出的 ECDSA P-256 密钥为实际发送的 HTTP body 签名。

## 构建与测试

使用 JDK 21（本项目已验证）以及包含 API 34 的 Android SDK。Gradle 至少要求 JDK 17，但本项目不承诺任意更高版本都兼容；已知默认 JDK 25 会失败。可以在 Android Studio 中打开 `apps/android-companion`，或从仓库根目录运行：

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
3. 返回应用并点击“开始守护会话”。前台服务会显示持续通知。
4. 如需桌面引擎判决，先启动本地 API，复制终端输出的 Bearer 令牌，再在应用中填写地址和令牌并开启转发。

USB 调试路径示例：

```bash
# 桌面端，在仓库根目录运行
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# 让手机的 127.0.0.1:8788 转到桌面
adb reverse tcp:8788 tcp:8788
```

默认中继地址是 `http://127.0.0.1:8788/v1/events`。Wi-Fi/LAN 模式需要显式使用 `--allow-lan`、非回环绑定和强 Bearer 令牌；不要把本地 API 无认证暴露到网络。

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

- 没有在手机上运行 Rust 引擎或 FFI；核心判决依赖可选桌面中继。
- Android 的高风险提示是事后通知，不是执行前确认框。
- 没有 instrumented test、真机权限生命周期测试或真实 Agent 端到端记录。
- 没有正式发布 keystore 签名证据，也未提交 Google Play 审核。
- 当前 `targetSdk = 34` 不满足 Google Play 对新应用和更新的现行要求；见 [Google Play 草案](PLAY_STORE.md)。

跨语言签名格式由 `eval/fixtures/adapter_signature_vectors.json` 固定，设计细节见 [适配器断言签名](../../docs/适配器断言签名.md)。
