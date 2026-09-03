[简体中文](capability-matrix.md) | [繁體中文](capability-matrix.zh-TW.md) | [English](capability-matrix.en.md)

# 能力矩陣(由原始碼產生)

本檔由 `scripts/gen-capability-matrix.py` 從原始碼擷取產生,**不要手改**——`cargo test` 裡的倉庫不變量會重新產生並逐字比對,漂移即紅。手寫文件(README、商店文案、發佈說明)裡凡涉及「哪一端觀察什麼、多少測試、什麼版本」的數字,以本檔為準。它記錄的是機械事實,不是產品承諾;一端「發出」某類事件只說明原始碼裡有那條路徑,真機上跑不跑得通由各 `acceptance-*.md` 回答。

## 各端真正發出的事件

引擎 `EventType`(guard-schema)共 20 種:`screen_frame`, `ui_tree_delta`, `process_focus`, `network_flow`, `clipboard_change`, `agent_session_start`, `agent_session_end`, `form_fill`, `deeplink`, `permission_request`, `memory_write`, `memory_read`, `environment_survey`, `data_derive`, `file_write`, `file_delete`, `process_exec`, `data_flow`, `declassify`, `user_query`。下表是**各端原始碼裡真的建構 / 回報**的種類;不在表裡的種類那一端就沒有來源,不管文案怎麼寫。

| 端 | 發出 | 擷取自 | 說明 |
|---|---|---|---|
| Android 伴生應用 | `env_survey`, `form_fill`, `network_meta`, `overlay_marker`, `permission_request`, `session_end`, `session_start`, `ui_text` | `PayloadSerializer.kt` 裡被主程式碼呼叫的 `fun` | 定義了但**沒有任何呼叫方**、因此從未發出:`deeplink`。`deeplink` 是刻意的——AccessibilityService 看不到 intent,要看就得註冊成連結處理器,那是比一類事件大得多的侵入(見 docs/android-completeness.md)。介面文字裡出現的 `intent://` 一類**字樣**由本機掃描器按文字規則回報,不是 deeplink 事件。 |
| Chromium / Firefox 擴充功能 | `form_fill`, `ui_text` | `background.js` 推給宿主的 `type:`;`content.js` 的 finding `kind:` | 內容腳本 finding 種類:`invisible_injection`, `optional_pii`, `payment_cta`, `payment_request`, `privacy_trap`, `prompt_injection`。信封只有 `form_fill`, `ui_text`——付款/注入類 finding 折成 `ui_text`,表單類折成 `form_fill`;兩份 manifest 裝同一套內容腳本(結構測試釘住),所以 Firefox 與 Chromium 一列。 |
| macOS 桌面殼 | `form_fill`, `ui_tree_delta` | `adapters/mac-adapter/src` 與其呼叫的 `guard_vision::uitree` 建構器裡的 `event_type: EventType::*`(不含 sim.rs 模擬適配器與測試模組;殼子的示範按鈕事件不算) | 樹快照、從樹裡摘出的表單填寫、像素幀;工作階段事件由殼子經引擎 API 發起,不在此計。macOS 的 ScreenCaptureKit 幀經 `ingest_capture_frame` 以帶幀中繼資料的 `ui_tree_delta` 進引擎,所以那一列沒有 `screen_frame`——這是實作事實,不是漏。 |
| Windows 桌面殼 | `form_fill`, `screen_frame`, `ui_tree_delta` | `adapters/win-adapter/src` 與其呼叫的 `guard_vision::uitree` 建構器裡的 `event_type: EventType::*`(不含 sim.rs 模擬適配器與測試模組;殼子的示範按鈕事件不算) | 樹快照、從樹裡摘出的表單填寫、像素幀;工作階段事件由殼子經引擎 API 發起,不在此計。macOS 的 ScreenCaptureKit 幀經 `ingest_capture_frame` 以帶幀中繼資料的 `ui_tree_delta` 進引擎,所以那一列沒有 `screen_frame`——這是實作事實,不是漏。 |
| iOS | (無) | `apps/ios-webshield` 有無 `.xcodeproj` / `.xcworkspace` / `Package.swift` | 沒有可建置的工程,沒有接入引擎——今天只有一個 SwiftUI 原始碼片段。iOS **不是**已支援平台;docs/ios-limited-sku.md 寫的是目標,不是現狀。 |

## 測試數(靜態計數)

數的是原始碼裡寫了多少條,不是一次執行跑了多少條(cfg / ignore / 參數化會讓執行數不同)。

| 位置 | 條數 | 形態 |
|---|---:|---|
| crates/guard-audit | 67 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-billing | 18 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-cli | 81 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-core | 251 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-eval | 43 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-ffi | 1 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-gateway | 32 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-intel | 15 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-jail | 52 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-localapi | 17 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-netmon | 2 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-nm-host | 27 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-overlay | 10 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-privacy | 105 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-schema | 150 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-shell | 41 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-sync | 6 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-trust | 6 | Rust `#[test]` / `#[tokio::test]` |
| crates/guard-vision | 96 | Rust `#[test]` / `#[tokio::test]` |
| adapters/android-adapter | 14 | Rust `#[test]` / `#[tokio::test]` |
| adapters/browser-adapter | 1 | Rust `#[test]` / `#[tokio::test]` |
| adapters/mac-adapter | 10 | Rust `#[test]` / `#[tokio::test]` |
| adapters/win-adapter | 7 | Rust `#[test]` / `#[tokio::test]` |
| apps/desktop-macos/src-tauri | 11 | Rust `#[test]` / `#[tokio::test]` |
| apps/desktop-windows/src-tauri | 9 | Rust `#[test]` / `#[tokio::test]` |
| **Rust 合計** | **1072** | |
| apps/extension-chromium/scripts/*.test.mjs | 50 | node `test(` |
| eval/e2e-extension/run.mjs | 24 | 真瀏覽器 E2E 判據 `record(` |
| apps/android-companion/app/src/test | 48 | Kotlin JVM `@Test` |
| apps/android-companion/app/src/androidTest | 0 | Kotlin instrumented `@Test`(需裝置) |
| apps/ios-webshield | 0 | Swift `func test*(` |
| eval/scenarios | 134 | 離線評測場景(YAML) |
| eval/capability-claims.yaml | 39 | 使用者能力聲明(每條掛證明測試) |

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
| apps/extension-chromium/manifest.json | `1.0.0.1` |
| apps/extension-chromium/manifest.firefox.json | `1.0.0.1` |
| Android versionName | `1.0.0-rc.1` |
| Android versionCode | `1000001` |
| Android minSdk | `26` |
| Android targetSdk | `36` |
| Android compileSdk | `36` |

重新產生:`make capability-matrix`;核對:`python3 scripts/gen-capability-matrix.py --check`。
