# AgentGuard macOS 发布指南

**版本：** 1.0.0-rc.1 · **应用：** `apps/desktop-macos`（Tauri 2 Menu Bar shell）

本文档描述 **Developer ID 直装分发** 的签名、公证、DMG 与可选自动更新脚手架。无需在仓库中存放真实 Apple 证书；CI/本地仅在具备凭据时执行签名步骤。

## 前置条件

| 项目 | 说明 |
|------|------|
| macOS 构建机 | `tauri build` 默认产出 `.app`；DMG 在签名/公证后再打包 |
| Xcode CLT | `xcode-select --install` |
| Rust + Node | 与仓库 `make check` 相同 toolchain |
| Apple Developer | **Developer ID Application** 证书（直装，非 Mac App Store） |
| 公证 | App Store Connect API Key 或 App-Specific Password + `notarytool` |

## 配置文件

| 文件 | 用途 |
|------|------|
| `src-tauri/tauri.conf.json` | 默认开发/发布配置；`version` 与 workspace 对齐；`bundle.macOS.entitlements` → `./entitlements.plist` |
| `src-tauri/entitlements.plist` | Hardened Runtime 权限（WebView JIT 等）；ScreenCaptureKit 走 TCC，无需额外 entitlement |
| `src-tauri/tauri.release.conf.json` | **可选** JSON Merge Patch：启用 updater 产物与 `plugins.updater` 占位 endpoint |

`tauri.conf.json` 为纯 JSON，**不能写注释**。Entitlements 路径与 updater 说明见本文档及 `scripts/build-release.sh`。

### Entitlements 说明

直装版（非 App Sandbox）典型项：

- `com.apple.security.cs.allow-jit` — Tauri/Wry WebView
- `com.apple.security.cs.allow-unsigned-executable-memory`
- `com.apple.security.cs.disable-library-validation`

ScreenCaptureKit 依赖用户在 **系统设置 → 隐私与安全性 → 屏幕录制** 中授权；见 [`sck-bridge.md`](sck-bridge.md)。

若将来上架 **Mac App Store** 并启用 App Sandbox，需重新评估 entitlements（如 `com.apple.security.network.client`）及 SCK 在沙盒下的限制。

## 构建

```bash
cd apps/desktop-macos
chmod +x scripts/build-release.sh
./scripts/build-release.sh
```

产物目录（成功时）：

```
apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app
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

环境变量占位（勿写入 git）：

```bash
export APPLE_ID="you@example.com"
export TEAM_ID="XXXXXXXXXX"
export APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Org (${TEAM_ID})"
```

Tauri 在 `APPLE_SIGNING_IDENTITY` 或 `tauri.conf.json > bundle.macOS.signingIdentity` 存在时会尝试签名；也可在 bundler 产出后手动签名：

```bash
APP="src-tauri/target/release/bundle/macos/AgentGuard.app"
codesign --force --options runtime \
  --entitlements src-tauri/entitlements.plist \
  --sign "$APPLE_SIGNING_IDENTITY" \
  "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
```

## 公证（Notarization）与 Staple

使用 App-Specific Password：

```bash
DMG="src-tauri/target/release/bundle/dmg/AgentGuard_1.0.0-rc.1_aarch64.dmg"
xcrun notarytool submit "$DMG" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" \
  --wait
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
```

或使用 API Key（推荐 CI）：设置 `APPLE_API_ISSUER`、`APPLE_API_KEY`、`APPLE_API_KEY_PATH`（见 [Tauri 环境变量](https://v2.tauri.app/reference/environment-variables/)）。

用户首次打开未 staple 的 app 可能触发 Gatekeeper；staple 后离线校验通过。

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
- [ ] `notarytool submit` 成功 + `stapler staple`
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
