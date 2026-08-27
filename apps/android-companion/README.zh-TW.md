# AgentGuard Android Companion

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

Android 伴生應用程式使用 Kotlin、Jetpack Compose 與 `AccessibilityService` 觀察守護工作階段中的介面事件，執行本機啟發式檢查，將事件寫成 JSONL，並可選擇轉送給桌面端 AgentGuard 引擎。

> 目前狀態：原始碼、JVM 單元測試與 Debug APK 建置路徑可用；尚無實機端到端驗收、正式發布簽章證據或 Google Play 發布記錄。通知是在事件發生後提醒，不能暫停、撤銷或阻止第三方應用程式已經執行的操作。

## 能做什麼

- 觀察文字變更、介面文字、深層連結、權限對話框與視窗覆蓋情況。
- 偵測付款/轉帳文字、隱私陷阱、非必要個資及提示詞注入標記。
- 調查可見的文字輸入廣播接收器及其他已啟用的輔助使用服務。
- 將每個工作階段的信封附加到應用程式私有目錄 `files/events/session-<id>.jsonl`。
- 透過使用者明確設定的 HTTP 中繼把信封送到桌面本機 API，並顯示引擎回傳的高風險通知。
- 使用 Android Keystore 中不可匯出的 ECDSA P-256 金鑰，為實際送出的 HTTP body 簽章。

## 建置與測試

使用 JDK 21（本專案已驗證）以及包含 API 34 的 Android SDK。Gradle 至少要求 JDK 17，但本專案不承諾任意更高版本都相容；已知預設 JDK 25 會失敗。可在 Android Studio 開啟 `apps/android-companion`，或從儲存庫根目錄執行：

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
3. 返回應用程式並點選「開始守護工作階段」。前景服務會顯示持續通知。
4. 如需桌面引擎判決，先啟動本機 API，複製終端輸出的 Bearer 權杖，再於應用程式填入位址與權杖並開啟轉送。

USB 除錯路徑範例：

```bash
# 桌面端，在儲存庫根目錄執行
cargo run -p guard-cli -- api-serve --bind 127.0.0.1:8788

# 讓手機的 127.0.0.1:8788 轉到桌面
adb reverse tcp:8788 tcp:8788
```

預設中繼位址是 `http://127.0.0.1:8788/v1/events`。Wi-Fi/LAN 模式需要明確使用 `--allow-lan`、非回環繫結與強 Bearer 權杖；不要把本機 API 無驗證暴露到網路。

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

- 手機上沒有執行 Rust 引擎或 FFI；核心判決依賴選用的桌面中繼。
- Android 的高風險提示是事後通知，不是執行前確認框。
- 沒有 instrumented test、實機權限生命週期測試或真實 Agent 端到端記錄。
- 沒有正式發布 keystore 簽章證據，也未提交 Google Play 審核。
- 目前 `targetSdk = 34` 不符合 Google Play 對新應用程式與更新的現行要求；請參閱 [Google Play 草案](PLAY_STORE.zh-TW.md)。

跨語言簽章格式由 `eval/fixtures/adapter_signature_vectors.json` 固定，設計細節請參閱 [介面卡斷言簽章](../../docs/适配器断言签名.md)。
