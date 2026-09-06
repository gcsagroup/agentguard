# AgentGuard macOS 发布指南

**版本：** 1.0.0-rc.1 · **应用：** `apps/desktop-macos`（Tauri 2 Menu Bar shell）

本文档描述 **Developer ID 直装分发** 的签名、公证、DMG 与可选自动更新脚手架。无需在仓库中存放真实 Apple 证书；CI/本地仅在具备凭据时执行签名步骤。

## 前置条件

| 项目 | 说明 |
|------|------|
| macOS 构建机 | `tauri build` 默认产出 `.app`；DMG 在签名/公证后再打包 |
| Xcode CLT | `xcode-select --install` |
| Rust + Node | 仓库钉住的 Rust 1.95.0（`../../scripts/bootstrap-rust.sh --install`）与锁定的 npm 依赖 |
| Apple Developer | **Developer ID Application** 证书（直装，非 Mac App Store） |
| 公证 | 已用 `notarytool store-credentials` 保存到登录钥匙串的 profile；脚本不接受命令行密码 |

## 配置文件

| 文件 | 用途 |
|------|------|
| `src-tauri/tauri.conf.json` | 默认开发/发布配置；`version` 与 workspace 对齐；`bundle.macOS.entitlements` → `./entitlements.plist` |
| `src-tauri/entitlements.plist` | 当前为空：WebKit 独立进程与静态原生桥不需要关闭 Library Validation、开放 JIT 或无签名可执行内存；ScreenCaptureKit 走 TCC |
| `src-tauri/tauri.release.conf.json` | **可选** JSON Merge Patch：启用 updater 产物与 `plugins.updater` 占位 endpoint |

`tauri.conf.json` 为纯 JSON，**不能写注释**。Entitlements 路径与 updater 说明见本文档及 `scripts/build-release.sh`。

### Entitlements 说明

当前直装版不声明 Hardened Runtime 逃生项。Tauri/Wry 使用系统 WebKit 进程，AgentGuard 的 Objective-C
桥静态链接，因此没有证据支持 `allow-jit`、`allow-unsigned-executable-memory` 或
`disable-library-validation`；这三项已由打包测试固定为不得出现。ScreenCaptureKit 依赖用户在
**系统设置 → 隐私与安全性 → 屏幕录制** 中授权；见 [`sck-bridge.md`](sck-bridge.md)。

若将来上架 **Mac App Store** 并启用 App Sandbox，需重新评估 entitlements（如 `com.apple.security.network.client`）及 SCK 在沙盒下的限制。

## 构建

```bash
cd apps/desktop-macos
chmod +x scripts/build-release.sh
../../scripts/bootstrap-rust.sh --install
AGENTGUARD_ALLOW_ADHOC=1 ./scripts/build-release.sh  # 仅本机 smoke，不可分发
```

发布脚本默认生成 `universal-apple-darwin`（Apple Silicon + Intel）并固定传入
`--no-default-features --features audit-sqlcipher --locked`。明文 SQLite 只允许
开发/调试；Release 未显式启用 `audit-sqlcipher` 会由 Rust `compile_error!` 直接拒绝，不存在明文
override。

发布包把规则、任务计划、授权策略、威胁情报 bundle 与验签公钥映射到
`Contents/Resources/agentguard/`。Release 只从签名 bundle 读取这些文件并在缺失、解析失败或情报验签失败时
拒绝启动；`AGENTGUARD_RULES` / `AGENTGUARD_INTEL*` 等路径覆盖仅在 Debug 生效。SQLCipher 口令与
Ed25519 审计种子分别存入当前用户 Keychain，审计库通过 `open_protected` 一次性要求“加密 + 可用签名器”。
遇到旧明文 DB/WAL/SHM 时保持字节不变并阻断，不会静默换到同级新库；上线前须对选定的备份、迁移或清空
流程做中断与回滚演练。

产物目录（成功时）：

```
apps/desktop-macos/src-tauri/target/universal-apple-darwin/release/bundle/macos/AgentGuard.app
```

`bundle.targets` 默认为 `["app"]`（避免本机 `bundle_dmg.sh` 偶发失败阻断发布编译）。需要 DMG 时：对已签名并 staple 的 `.app` 用 `hdiutil` / `create-dmg` 另打，或临时把 `targets` 改为 `["app", "dmg"]` 再构建。

最低系统版本：`12.3`（ScreenCaptureKit）。**默认构建不包含 updater 插件**，不访问网络，无需 pubkey。

### 可选：启用 updater 配置 overlay

1. 生成密钥对（一次性，私钥勿提交）：

   ```bash
   cargo tauri signer generate -w ~/.tauri/agentguard.key
   ```

2. 将 `tauri.release.conf.json` 中 `REPLACE_WITH_OUTPUT_OF_tauri_signer_generate` 替换为 **公钥 PEM 内容**（非文件路径）。

3. 在 `Cargo.toml` 增加 `tauri-plugin-updater`（可选 feature `updater`），并在 `lib.rs` 中 `init` 插件（见下方「Tauri Updater vs Sparkle」）。

4. 构建：

   ```bash
   AGENTGUARD_ENABLE_UPDATER=1 ./scripts/build-release.sh
   ```

Endpoint 占位符：

```
https://releases.example.com/agentguard/{{target}}/{{current_version}}
```

部署时将 `releases.example.com` 换为真实 CDN，并托管 Tauri 期望的更新清单与 `.tar.gz` 签名包。

## 代码签名（Codesign）

正式构建环境变量（勿写入 git）：

```bash
export AGENTGUARD_EXPECTED_TEAM_ID="XXXXXXXXXX"
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Org (${AGENTGUARD_EXPECTED_TEAM_ID})"
export NOTARYTOOL_PROFILE="AgentGuard-Notary"
./scripts/build-release.sh
```

Tauri 在 `APPLE_SIGNING_IDENTITY` 或 `tauri.conf.json > bundle.macOS.signingIdentity` 存在时会尝试签名；也可在 bundler 产出后手动签名：

```bash
APP="src-tauri/target/universal-apple-darwin/release/bundle/macos/AgentGuard.app"
codesign --force --options runtime \
  --entitlements src-tauri/entitlements.plist \
  --sign "$APPLE_SIGNING_IDENTITY" \
  "$APP"
codesign --verify --deep --strict --verbose=4 "$APP" && \
  codesign -dv --verbose=4 "$APP"
```

## 公证（Notarization）与 Staple

在仓库外创建 `AgentGuard-Notary` 钥匙串 profile；以下命令会安全提示输入 App-Specific Password，
不要把密码放进命令参数、仓库或日志：

```bash
xcrun notarytool store-credentials AgentGuard-Notary

DMG="src-tauri/target/universal-apple-darwin/release/bundle/dmg/AgentGuard_1.0.0-rc.1_universal.dmg"
xcrun notarytool submit "$DMG" \
  --wait \
  --keychain-profile AgentGuard-Notary && \
  xcrun stapler staple "$DMG" && \
  xcrun stapler validate "$DMG"
```

严格证据必须记录上述 Team ID、keychain profile、staple 与 validate 的完整 fail-closed 成功链。构建工具可以有其他认证配置，但不能用较弱或不同形状的命令冒充严格证据。

staple 与 validate 成功仍不能证明 quarantine、Gatekeeper 或首次启动行为；下载后的正式候选必须在隔离机上完成首次启动验收。

## Tauri Updater vs Sparkle

| 方案 | 适用 |
|------|------|
| **Tauri plugin-updater** | 直装 DMG/ZIP；与 Tauri bundler 签名产物一致；endpoint + Ed25519 pubkey |
| **Sparkle** | 已有 Sparkle 基础设施或非 Tauri 原生壳；需单独集成 |
| **Mac App Store** | 必须使用 App Store 更新，**不能**与 Sparkle/直装 updater 混用同一 bundle ID |

当前仓库 **默认不链接** `tauri-plugin-updater`，避免无 pubkey 时破坏 `cargo check`。启用步骤：

```toml
# Cargo.toml — 示例 feature
[features]
default = []
updater = ["dep:tauri-plugin-updater"]

[dependencies]
tauri-plugin-updater = { version = "2", optional = true }
```

```rust
// lib.rs — feature = "updater" 时
#[cfg(feature = "updater")]
tauri::Builder::default().plugin(tauri_plugin_updater::Builder::new().build())
```

## DMG 分发清单

发布前逐项确认：

- [ ] `tauri.conf.json` 版本号与 release notes 一致
- [ ] `entitlements.plist` 与实际上架渠道（直装 / MAS）匹配
- [ ] Developer ID 签名 + Hardened Runtime
- [ ] `codesign -dvv` 的 `TeamIdentifier` 与 `AGENTGUARD_EXPECTED_TEAM_ID` 一致
- [ ] `notarytool submit --keychain-profile AgentGuard-Notary` 成功 + `stapler staple` + `stapler validate`
- [ ] DMG 在干净 macOS VM 上双击安装、首次启动无恶意软件拦截
- [ ] TCC 文案与 [`store-listing-macos.md`](store-listing-macos.md) 隐私说明一致
- [ ] ScreenCaptureKit / 辅助功能权限引导可理解（Menu Bar onboarding）
- [ ] 更新通道（若启用 updater）：HTTPS endpoint、公钥轮换流程、回滚策略
- [ ] 附 SHA256 校验和与发布说明（GitHub Releases / 官网）

## 相关文档

- [`store-listing-macos.md`](store-listing-macos.md) — App Store / 直装商店文案草案
- [`sck-bridge.md`](sck-bridge.md) — ScreenCaptureKit 与隐私默认
- [`privacy-policy.md`](privacy-policy.md) — 隐私政策草案
- [`RELEASE-1.0.0-rc.1.md`](RELEASE-1.0.0-rc.1.md) — RC 范围与验证命令
