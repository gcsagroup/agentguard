# Google Play 商店頁面草稿

[简体中文](PLAY_STORE.md) · 繁體中文 · [English](PLAY_STORE.en.md)

> **僅供發布準備，尚未提交 Google Play。** 文案必須在取得正式簽章 AAB、實機驗收、輔助使用權限聲明與 Play Console 資料安全表證據後再次複核。

## 應用程式名稱

AgentGuard Companion

## 簡短說明

在 Android 上觀察 AI Agent 工作階段，並於發現付款、隱私與介面風險後發出本機提醒。

## 完整說明

AgentGuard Companion 在使用者明確啟用輔助使用服務並開始守護工作階段後，觀察介面文字、表單填寫、權限對話框與視窗覆蓋情況。它可以識別付款或轉帳提示、隱私陷阱、非必要個資填寫、介面文字裡出現的可疑深層連結字樣與提示詞注入標記，並在裝置上記錄事件與顯示風險通知。它不觀察深層連結本身（輔助使用服務看不到 intent）；各端真正發出的事件以原始碼產生的 [docs/capability-matrix.zh-TW.md](../../docs/capability-matrix.zh-TW.md) 為準，商店文案不得超出它。

目前 Release 建置不提供桌面中繼。開發用 Debug 建置保留中繼聯調，但 Relay v1 回應尚未驗證，因此不能進入商店版本；回應驗證與重放防護通過獨立安全驗收後，才可重新納入發布範圍。

**重要邊界：** Android 伴生應用程式在事件發生後才觀察並通知。它不能暫停、撤銷或阻止第三方應用程式已經執行的付款、轉帳或其他操作，也不能描述為系統級攔截器。

## 目前發布阻塞項

- 目前設定為 `compileSdk = 36`、`targetSdk = 36`（AGP 8.11.1；lint 零警告且 warning 即 error）。Google Play 自 2026-08-31 起要求 API 36，設定層面已符合；請參閱 [Google Play 官方目標 API 要求](https://support.google.com/googleplay/android-developer/answer/11926878)。
- Android 16 模擬器已覆蓋強制邊到邊、通知權限與狀態、輔助使用啟停、執行中撤權及處理程序死亡 fail-closed；**Android 15/16 實機與 OEM 回歸仍未完成**，模擬器證據不能取代此發布阻塞項。
- 儲存庫沒有正式上傳 keystore、正式簽章 AAB 的驗證記錄、Play Console 審核結果或實機端到端驗收。
- 尚未完成輔助使用 API 使用聲明、資料安全表與商店素材的最終審核。

## 資料安全草稿

- 預設處理：輔助使用事件、應用程式/視窗資訊與風險結果保存在應用程式私有目錄。
- 預設上傳到開發者伺服器：無。
- 選用傳輸：目前商店候選沒有桌面轉送；Debug 開發建置不屬於發布版本。
- 分享：預設不與第三方分享。
- 刪除：解除安裝會刪除應用程式私有資料；發布前仍需補充產品內刪除流程與正式保留政策。

以上是程式碼現況說明，不是已提交或獲准的 Play Console 聲明。

## 敏感能力說明

### 輔助使用服務

核心功能需要 `BIND_ACCESSIBILITY_SERVICE`：在使用者主動開始的守護工作階段中觀察介面文字與表單變更，以發現付款、隱私與注入風險。服務不具備撤銷第三方操作的能力。

### 套件可見性

清單使用精確的 `<queries>` 項目查找符合 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的廣播接收器，並查詢可啟動應用程式以執行相似應用程式檢查。專案不要求 `QUERY_ALL_PACKAGES`，但啟動器可見性仍涉及隱私，正式提交時必須如實說明。

### 通知與輔助使用服務狀態

使用中的守護工作階段使用普通常駐通知（生命週期由無障礙服務承擔，不宣告 `dataSync` 前景服務）；Android 13 及以上還需要使用者授予通知權限。高風險通知是事後提醒，通知被拒絕時風險仍會寫入日誌，但使用者可能看不到即時提示。

## 發布簽章接線

不要把 keystore、密碼或 `gradle.properties` 中的憑證提交到儲存庫。範例：

```bash
keytool -genkeypair -v \
  -keystore /secure/path/agentguard-upload.jks \
  -alias agentguard \
  -keyalg RSA -keysize 2048 -validity 10000

export AGENTGUARD_STORE_FILE=/secure/path/agentguard-upload.jks
export AGENTGUARD_STORE_PASSWORD='<從安全憑證儲存讀取>'
export AGENTGUARD_KEY_ALIAS=agentguard
export AGENTGUARD_KEY_PASSWORD='<從安全憑證儲存讀取>'

cd apps/android-companion
./gradlew --no-daemon :app:bundleRelease
```

`app/build.gradle.kts` 的 `signingConfigs.release` 會讀取上述環境變數或同名 Gradle 屬性。建置成功不等於可發布；仍須驗證憑證身分、在實機完成權限生命週期，並通過 Google Play 審核。桌面中繼不屬於目前 Release 驗收範圍。

更多技術說明請參閱 [Android Companion README](README.zh-TW.md) 與 [隱私權政策](../../docs/privacy-policy.zh-TW.md)。
