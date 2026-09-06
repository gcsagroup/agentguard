# AgentGuard Android Companion

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

Android 伴生應用程式使用 Kotlin、Jetpack Compose 與 `AccessibilityService` 觀察守護工作階段中的介面事件，執行本機啟發式檢查，並將最小化事件寫成 JSONL。

> 目前狀態：原始碼、JVM 單元測試、Debug APK 與 API 36 模擬器權限生命週期已驗證；尚無實機端到端驗收、正式發布簽章證據或 Google Play 發布記錄。通知是在事件發生後提醒，不能暫停、撤銷或阻止第三方應用程式已經執行的操作。Relay v1 回應尚未驗證，因此 Release 建置會強制停用桌面中繼；該能力只保留於 Debug 建置供協定開發。

## 能做什麼

- 觀察文字變更、介面文字、權限對話框與視窗覆蓋情況（各端真正發出的事件以原始碼產生的 [docs/capability-matrix.zh-TW.md](../../docs/capability-matrix.zh-TW.md) 為準）。
- 偵測付款/轉帳文字、隱私陷阱、非必要個資、提示詞注入標記，以及介面文字裡出現的可疑深層連結**字樣**（`intent://` 一類）。它不觀察深層連結本身——輔助使用服務看不到 intent。
- 調查可見的文字輸入廣播接收器及其他已啟用的輔助使用服務。
- 將每個工作階段的信封附加到應用程式私有目錄 `files/events/session-<id>.jsonl`。
- Debug 建置可透過使用者明確設定的 HTTP 中繼聯調桌面本機 API；Release 建置在回應驗證完成前強制停用此能力。
- 使用 Android Keystore 中不可匯出的 ECDSA P-256 金鑰，為實際送出的 HTTP body 簽章。

## 建置與測試

使用 JDK 21（本專案已驗證）以及包含 API 36 平台與 36.0.0 build-tools 的 Android SDK（AGP 8.11）。Gradle 至少要求 JDK 17，但本專案不承諾任意更高版本都相容；已知預設 JDK 25 會失敗。可在 Android Studio 開啟 `apps/android-companion`，或從儲存庫根目錄執行：

```bash
cd apps/android-companion
./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug
```

Debug APK 輸出到：

```text
apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

## 執行

```bash
adb install -r apps/android-companion/app/build/outputs/apk/debug/app-debug.apk
```

接著在裝置上：

1. 在 Android 13 及以上版本授予通知權限。
2. 開啟系統輔助使用設定，啟用 AgentGuard Companion。
3. 返回應用程式並點選「開始守護工作階段」。輔助使用服務會顯示普通常駐狀態通知。
4. 僅在 Debug 協定聯調時，可啟動本機 API 並開啟轉送；Release 建置不會顯示或啟用此入口。

USB 除錯路徑範例：

```bash
# 桌面端，在儲存庫根目錄執行
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# 讓手機的 127.0.0.1:8788 轉到桌面
adb reverse tcp:8788 tcp:8788
```

Debug 建置的預設中繼位址是 `http://127.0.0.1:8788/v1/events`。此 HTTP 路徑僅供本機開發，不得作為發布設定；不要把本機 API 無驗證暴露到網路。

可透過 Android Studio Device File Explorer 或 `run-as` 讀取應用程式私有目錄中的 JSONL。每一行都是一個信封；將單行另存成 JSON 檔案後可離線重播：

```bash
cargo run -p guard-cli -- ingest-android --payload /path/to/one-envelope.json
```

## 介面卡簽章接線

應用程式為實際送出的 UTF-8 HTTP body 簽章，簽章資訊透過下列請求標頭傳遞：

```text
X-AgentGuard-Adapter: android-companion
X-AgentGuard-Timestamp: <毫秒時間戳>
X-AgentGuard-Signature: <DER 簽章十六進位>
```

金鑰由 Android Keystore 管理，私鑰無法透過應用程式 API 匯出；Android 9 及以上會優先要求 StrongBox，不可用時退回裝置提供的 Keystore 實作，因此在沒有裝置證據時，不能聲稱所有裝置都由硬體託管。

接線步驟：

1. 開啟應用程式中的桌面轉送，點選「顯示介面卡公開金鑰」，複製以 `04` 開頭的 130 位 SEC1 十六進位公開金鑰。
2. 在桌面儲存庫根目錄產生註冊卡：

   ```bash
   cargo run -p guard-cli -- adapter-card \
     --adapter-id android-companion \
     --platforms android \
     --public-key <130位十六進位公開金鑰>
   ```

3. 將輸出合併到 `policies/adapter-registry.yaml`，重新啟動桌面 API。

未註冊公開金鑰時，桌面端會把伴生應用程式的調查視為未簽章：它可以增加風險，但不能用「環境乾淨」清除既有風險。此簽章證明信封來自持有裝置金鑰的一方，不證明應用程式未被修改，也不取代 Play Integrity 或裝置完整性證明。

## 環境調查的限制

`EnvironmentScanner` 會檢查符合 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的清單式廣播接收器，以及其他已啟用的輔助使用服務。Android 11 及以上受套件可見性限制；「乾淨」只表示沒有發現目前可見的符合項目，不代表裝置上絕對不存在監聽者。詳見 [Android 環境調查](../../docs/android-env-survey.md)。

## 未完成與發布邊界

- 手機上沒有執行 Rust 引擎或 FFI；Release 版本目前只提供本機啟發式偵測，桌面中繼尚未納入發布範圍。
- Android 的高風險提示是事後通知，不是執行前確認框。
- 沒有實機權限生命週期測試或真實 Agent 端到端記錄；API 36 模擬器證據不能取代實機。
- 沒有正式發布 keystore 簽章證據，也未提交 Google Play 審核。
- `compileSdk / targetSdk = 36` 已符合 Google Play 的目標 API 要求；Android 16 模擬器已驗證邊到邊、通知權限與狀態、輔助使用啟停、執行中撤權及處理程序死亡 fail-closed，但 **API 35+ 實機/OEM 回歸仍未完成**；請參閱 [Google Play 草案](PLAY_STORE.zh-TW.md)。

跨語言簽章格式由 `eval/fixtures/adapter_signature_vectors.json` 固定，設計細節請參閱 [介面卡斷言簽章](../../docs/适配器断言签名.md)。
