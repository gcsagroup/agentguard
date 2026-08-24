# AgentGuard Android Companion

Minimal Kotlin / Jetpack Compose app that observes Accessibility events, classifies form fills, writes JSONL envelopes for `android-adapter`, and raises **local risk notifications** (payment / trap / overlay markers).

## Build

Open `apps/android-companion` in Android Studio, or:

```bash
cd apps/android-companion
./gradlew :app:assembleDebug
```

## Environment survey ((A)I Sees A5 / A6)

`EnvironmentScanner` reports what **else** on the device can read the agent's
input: apps with a receiver registered for the `ADB_INPUT_B64` / `ADB_INPUT_TEXT`
text-input broadcast (A5) and enabled accessibility services other than ours (A6).
Both attacks scored 20/20 in the paper.

The manifest declares those two actions in a `<queries>` block — that is what makes
`queryBroadcastReceivers` work on API 30+ without the Play-restricted
`QUERY_ALL_PACKAGES`. Consequences worth knowing before trusting a clean result:
only **manifest-declared** receivers are visible (an app registering at runtime is
not), and only packages matching those declared actions are visible at all.

Full write-up and decision table: [`docs/android-env-survey.md`](../../docs/android-env-survey.md).

## Runtime loop (minimal)

1. Grant **Accessibility** for AgentGuard Companion.
2. Tap **Start guard session** (starts foreground service).
3. `GuardAccessibilityService`:
   - on connect / session start → `env_survey` event (see below)
   - `TYPE_VIEW_TEXT_CHANGED` → `form_fill` events (label heuristics / trap / FM)
   - window content → `ui_text` events
   - Appends envelopes to `filesDir/events/session-<id>.jsonl`
   - `LocalRiskScanner` → high-priority notification + prefs for UI
4. Pull envelopes for desktop eval:

```bash
adb shell "run-as com.agentguard.companion cat files/events/session-*.jsonl"
# or copy via Device File Explorer
cargo run -p guard-cli -- ingest-android --payload /path/to/envelope.json
```

(Exact CLI flag may be `android-ingest` / fixture path — see `guard-cli --help`.)

## Not yet

- On-device Rust engine / FFI
- Attestation of the app itself (Play Integrity): the Keystore key proves *this app on
  this device*, not *this app unmodified*
- Bidirectional confirm UI that pauses the third-party Agent
- Broadcast (A5) / credential stream policy (A6) beyond logging text changes

## 适配器签名(Adapter assertion signing)

伴生应用给每一次中继的信封签名,用一把**私钥不出硬件**的 ECDSA P-256 密钥
(Android Keystore,有 StrongBox 就用 StrongBox,否则 TEE)。签名走请求头:

```
X-AgentGuard-Adapter:   android-companion
X-AgentGuard-Timestamp: <毫秒>
X-AgentGuard-Signature: <DER 十六进制>
```

签的是 **HTTP body 的原始字节**,不是逐个事件。这不是偏好,是硬约束:桌面侧重建
`GuardEvent` 时用的是它自己的序号和时钟,手机无从知道那两个值,所以签不出一个能对上
重建结果的签名。签 body 同时绕开了整个 JSON 规范化问题 —— 验证方拿到的就是同一串字节。

### 接上桌面

公钥是**每台设备一把**,所以注册表里没法预填:

1. 应用里开启中继,点 **显示适配器公钥**,复制那 130 位十六进制。
2. 桌面上生成卡:
   ```bash
   agentguard adapter-card --adapter-id android-companion \
     --platforms android --public-key <那串十六进制>
   ```
3. 把输出粘到 `policies/adapter-registry.yaml`。

不做这一步的话它的调查算未签名:**可以加风险,不能清风险**。这是刻意的默认 ——
比假装验过要安全。

### 为什么是 P-256 而不是 Ed25519

桌面侧其它一切签名都是 Ed25519,这里不是,两个理由,第二个才是真正的理由:

1. `minSdk = 26`,`java.security` 的 Ed25519 要 API 33。在安全产品里自带一份手写的
   Ed25519,是拿密码学实现风险换算法一致性,不值得。
2. **P-256 能走 Keystore,私钥根本不出硬件。** 即便 App 的私有目录被读走,签名能力
   也拿不走。

所以卡上有一个显式的 `key_algorithm` 字段 —— 显式,不是从公钥长度猜的。

### 这把密钥证明什么、不证明什么

证明:这条断言真的来自这台设备上的这个伴生应用,于是桌面本机的其它进程伪造不出
"环境是干净的"。

不证明:这个应用本身没被改过。拿到 root 的攻击者可以让它用自己的密钥签一句假话。
这一层挡的是"桌面本机的其它进程",不是"这台手机已经失陷"。

### 跨语言测试

签名消息的构造在 Rust 和 Kotlin 各有一份实现,靠
`eval/fixtures/adapter_signature_vectors.json` 钉住不分叉 —— 两个方向都覆盖。
细节见 [docs/适配器断言签名.md](../../docs/适配器断言签名.md)。
