[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)

# 能力矩陣(由原始碼產生)

本檔由 `scripts/gen-capability-matrix.py` 從原始碼擷取產生,**不要手改**——`cargo test` 裡的倉庫不變量會重新產生並逐字比對,漂移即紅。手寫文件(README、商店文案、發佈說明)裡凡涉及「哪一端觀察什麼、多少測試、什麼版本」的數字,以本檔為準。它記錄的是機械事實,不是產品承諾;一端「發出」某類事件只說明原始碼裡有那條路徑,真機上跑不跑得通由各 `acceptance-*.md` 回答。

## 各端真正發出的事件

引擎 `EventType`(guard-schema)共 20 種:`screen_frame`, `ui_tree_delta`, `process_focus`, `network_flow`, `clipboard_change`, `agent_session_start`, `agent_session_end`, `form_fill`, `deeplink`, `permission_request`, `memory_write`, `memory_read`, `environment_survey`, `data_derive`, `file_write`, `file_delete`, `process_exec`, `data_flow`, `declassify`, `user_query`。下表是**各端原始碼裡真的建構 / 回報**的種類;不在表裡的種類那一端就沒有來源,不管文案怎麼寫。

| 端 | 發出 | 擷取自 | 說明 |
|---|---|---|---|
| Android 伴生應用 | `env_survey`, `form_fill`, `network_meta`, `overlay_marker`, `permission_request`, `session_end`, `session_start`, `ui_text` | `PayloadSerializer.kt` 裡被主程式碼呼叫的 `fun` | 定義了但**沒有任何呼叫方**、因此從未發出:`deeplink`。`deeplink` 是刻意的——AccessibilityService 看不到 intent,要看就得註冊成連結處理器,那是比一類事件大得多的侵入(見 docs/android-completeness.md)。介面文字裡出現的 `intent://` 一類**字樣**由本機掃描器按文字規則回報,不是 deeplink 事件。 |
| Chrome / Edge 擴充功能 | — | GA manifest 的權限門;`background.js` 的宿主 `type:`;`content.js` 的 finding `kind:` | 內容腳本 finding 種類:`invisible_injection`, `optional_pii`, `payment_cta`, `privacy_trap`, `prompt_injection`。GA manifest 沒有 `nativeMessaging`,所以實際傳給宿主的 guard-schema 信封為 —;background.js 中保留的事件對應只是不可達原型。首個 GA 僅交付共用同一 Chromium 套件的 Chrome / Edge。Firefox 只保留原始碼原型,不封裝且不作為首個 GA 驗收門。 |
| macOS 桌面殼 | `form_fill`, `ui_tree_delta` | `adapters/mac-adapter/src` 與其呼叫的 `guard_vision::uitree` 建構器裡的 `event_type: EventType::*`(不含 sim.rs 模擬適配器與測試模組;殼子的示範按鈕事件不算) | 樹快照、從樹裡摘出的表單填寫、像素幀;工作階段事件由殼子經引擎 API 發起,不在此計。macOS 的 ScreenCaptureKit 幀經 `ingest_capture_frame` 以帶幀中繼資料的 `ui_tree_delta` 進引擎,所以那一列沒有 `screen_frame`——這是實作事實,不是漏。 |
| Windows 桌面殼 | `form_fill`, `screen_frame`, `ui_tree_delta` | `adapters/win-adapter/src` 與其呼叫的 `guard_vision::uitree` 建構器裡的 `event_type: EventType::*`(不含 sim.rs 模擬適配器與測試模組;殼子的示範按鈕事件不算) | 樹快照、從樹裡摘出的表單填寫、像素幀;工作階段事件由殼子經引擎 API 發起,不在此計。macOS 的 ScreenCaptureKit 幀經 `ingest_capture_frame` 以帶幀中繼資料的 `ui_tree_delta` 進引擎,所以那一列沒有 `screen_frame`——這是實作事實,不是漏。 |
| iOS | (無 guard-schema 事件) | 可建置工程,或含 App / Safari 延伸功能 / Core / 測試 targets 的 `project.yml` | 已有正式 XcodeGen 工程定義、Safari Web Extension 與本機稽核接線;它是 isolated-world DOM 點擊/提交受限 SKU,未接 Rust 引擎,簽署、真機 Safari 與 TestFlight 仍需外部驗收。 |

## 測試數(靜態計數)

數的是原始碼裡寫了多少條,不是一次執行跑了多少條(cfg / ignore / 參數化會讓執行數不同)。

| 位置 | 條數 | 形態 |
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
| **Rust 合計** | **1210** | |
| apps/extension-chromium/scripts/*.test.mjs | 45 | node `test(` |
| apps/ios-webshield/Tests/ExtensionTests | 18 | Safari 延伸功能 node `test(` |
| eval/e2e-extension/run.mjs | 39 | 真瀏覽器 E2E 判據 `record(` |
| apps/android-companion/app/src/test | 60 | Kotlin JVM `@Test`(纯函数) |
| apps/android-companion/app/src/test(Robolectric) | 26 | Kotlin `@Test`,在 JVM 上跑真 Android 框架(事件路径 / Compose 界面) |
| apps/android-companion/app/src/androidTest | 0 | Kotlin instrumented `@Test`(需裝置) |
| apps/ios-webshield | 22 | Swift `func test*(` |
| eval/scenarios | 134 | 離線評測場景(YAML) |
| eval/capability-claims.yaml | 36 | 使用者能力聲明(每條掛證明測試) |

## 版本字串

只列原始碼裡寫的字串。有沒有 tag、有沒有簽名產物不在此表——那由 `scripts/release-gate.sh` 與 `guard-cli evidence-verify` 回答;截至本矩陣產生的原始碼,這些版本號都還沒有對應的已發佈產物。

| 項 | 值 |
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

重新產生:`make capability-matrix`;核對:`python3 scripts/gen-capability-matrix.py --check`。
