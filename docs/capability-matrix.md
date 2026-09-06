[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)

# 能力矩阵(由源码生成)

本文件由 `scripts/gen-capability-matrix.py` 从源码提取生成,**不要手改**——`cargo test` 里的仓库不变量会重新生成并逐字比对,漂移即红。手写文档(README、商店文案、发布说明)里凡是涉及"哪一端观察什么、多少测试、什么版本"的数字,以本文件为准。它记录的是机械事实,不是产品承诺;一端"发出"某类事件只说明源码里有那条路径,真机上跑不跑得通由各 `acceptance-*.md` 回答。

## 各端真正发出的事件

引擎 `EventType`(guard-schema)共 20 种:`screen_frame`, `ui_tree_delta`, `process_focus`, `network_flow`, `clipboard_change`, `agent_session_start`, `agent_session_end`, `form_fill`, `deeplink`, `permission_request`, `memory_write`, `memory_read`, `environment_survey`, `data_derive`, `file_write`, `file_delete`, `process_exec`, `data_flow`, `declassify`, `user_query`。下表是**各端源码里真的构造 / 上报**的种类;不在表里的种类那一端就没有来源,不管文案怎么写。

| 端 | 发出 | 提取自 | 说明 |
|---|---|---|---|
| Android 伴生应用 | `env_survey`, `form_fill`, `network_meta`, `overlay_marker`, `permission_request`, `session_end`, `session_start`, `ui_text` | `PayloadSerializer.kt` 里被主代码调用的 `fun` | 定义了但**没有任何调用方**、因此从未发出:`deeplink`。`deeplink` 是刻意的——AccessibilityService 看不到 intent,要看就得注册成链接处理器,那是比一类事件大得多的侵入(见 docs/android-completeness.md)。界面文字里出现的 `intent://` 一类**字样**由本地扫描器按文本规则报,不是 deeplink 事件。 |
| Chrome / Edge 扩展 | — | GA manifest 的权限门;`background.js` 的宿主 `type:`;`content.js` 的 finding `kind:` | 内容脚本 finding 种类:`invisible_injection`, `optional_pii`, `payment_cta`, `privacy_trap`, `prompt_injection`。GA manifest 没有 `nativeMessaging`,所以实际发给宿主的 guard-schema 信封为 —;background.js 中保留的事件映射只是不可达原型。首个 GA 仅交付共用同一 Chromium 包的 Chrome / Edge。Firefox 只保留源码原型,不打包且不作为首个 GA 验收门。 |
| macOS 桌面壳 | `form_fill`, `ui_tree_delta` | `adapters/mac-adapter/src` 与其调用的 `guard_vision::uitree` 构造器里的 `event_type: EventType::*`(不含 sim.rs 仿真适配器与测试模块;壳子的演示按钮事件不算) | 树快照、从树里抠出的表单填写、像素帧;会话事件由壳子经引擎 API 发起,不在此计。macOS 的 ScreenCaptureKit 帧经 `ingest_capture_frame` 以带帧元数据的 `ui_tree_delta` 进引擎,所以那一行没有 `screen_frame`——这是实现事实,不是漏。 |
| Windows 桌面壳 | `form_fill`, `screen_frame`, `ui_tree_delta` | `adapters/win-adapter/src` 与其调用的 `guard_vision::uitree` 构造器里的 `event_type: EventType::*`(不含 sim.rs 仿真适配器与测试模块;壳子的演示按钮事件不算) | 树快照、从树里抠出的表单填写、像素帧;会话事件由壳子经引擎 API 发起,不在此计。macOS 的 ScreenCaptureKit 帧经 `ingest_capture_frame` 以带帧元数据的 `ui_tree_delta` 进引擎,所以那一行没有 `screen_frame`——这是实现事实,不是漏。 |
| iOS | (无 guard-schema 事件) | 可构建工程,或含 App / Safari 扩展 / Core / 测试 targets 的 `project.yml` | 存在正式 XcodeGen 工程定义、Safari Web Extension 与本地审计接线;它是 isolated-world DOM 点击/提交受限 SKU,未接 Rust 引擎,签名、真机 Safari 与 TestFlight 仍需外部验收。 |

## 测试数(静态计数)

数的是源码里写了多少条,不是一次运行跑了多少条(cfg / ignore / 参数化会让运行数不同)。

| 位置 | 条数 | 形态 |
|---|---:|---|
| crates/guard-audit | 102 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-billing | 18 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-cli | 93 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-core | 256 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-eval | 43 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-ffi | 1 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-gateway | 37 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-intel | 15 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-jail | 52 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-localapi | 17 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-netmon | 2 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-nm-host | 27 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-overlay | 10 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-privacy | 105 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-schema | 154 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-shell | 41 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-sync | 6 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-trust | 6 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-vision | 100 | Rust `#[test]` / `#[tokio::test]` |
| adapters/android-adapter | 14 | Rust `#[test]` / `#[tokio::test]` |
| adapters/browser-adapter | 1 | Rust `#[test]` / `#[tokio::test]` |
| adapters/mac-adapter | 30 | Rust `#[test]` / `#[tokio::test]` |
| adapters/win-adapter | 8 | Rust `#[test]` / `#[tokio::test]` |
| apps/desktop-macos/src-tauri | 43 | Rust `#[test]` / `#[tokio::test]` |
| apps/desktop-windows/src-tauri | 29 | Rust `#[test]` / `#[tokio::test]` |
| **Rust 合计** | **1210** | |
| apps/extension-chromium/scripts/*.test.mjs | 58 | node `test(` |
| apps/ios-webshield/Tests/ExtensionTests | 18 | Safari 扩展 node `test(` |
| eval/e2e-extension/run.mjs | 39 | 真浏览器 E2E 判据 `record(` |
| apps/android-companion/app/src/test | 60 | Kotlin JVM `@Test`(纯函数) |
| apps/android-companion/app/src/test(Robolectric) | 26 | Kotlin `@Test`,在 JVM 上跑真 Android 框架(事件路径 / Compose 界面) |
| apps/android-companion/app/src/androidTest | 0 | Kotlin instrumented `@Test`(需设备) |
| apps/ios-webshield | 22 | Swift `func test*(` |
| eval/scenarios | 134 | 离线评测场景(YAML) |
| eval/capability-claims.yaml | 36 | 用户能力声明(每条挂证明测试) |

## 版本字符串

只列源码里写的字符串。有没有 tag、有没有签名产物不在此表——那由 `scripts/release-gate.sh` 与 `guard-cli evidence-verify` 回答;截至本矩阵生成的源码,这些版本号都还没有对应的已发布产物。

| 项 | 值 |
|---|---|
| Rust workspace | `1.0.0-rc.1` |
| MSRV (rust-version) | `1.87` |
| rust-toolchain.toml | `1.95.0` |
| .nvmrc | `22` |
| apps/desktop-macos (tauri.conf.json) | `1.0.0-rc.1` |
| apps/desktop-windows (tauri.conf.json) | `1.0.0-rc.1` |
| apps/extension-chromium/manifest.json (Chrome / Edge GA) | `1.0.0.1` |
| apps/extension-chromium/manifest.firefox.json (source prototype; not GA) | `1.0.0.1` |
| Android versionName | `1.0.0-rc.1` |
| Android versionCode | `1000001` |
| Android minSdk | `26` |
| Android targetSdk | `36` |
| Android compileSdk | `36` |

重新生成:`make capability-matrix`;核对:`python3 scripts/gen-capability-matrix.py --check`。
