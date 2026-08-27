# Google Play 商店頁面草稿

[简体中文](PLAY_STORE.md) · 繁體中文 · [English](PLAY_STORE.en.md)

> **僅供發布準備，尚未提交 Google Play。** 文案必須在取得正式簽章 AAB、實機驗收、輔助使用權限聲明與 Play Console 資料安全表證據後再次複核。

## 應用程式名稱

AgentGuard Companion

## 簡短說明

在 Android 上觀察 AI Agent 工作階段，並於發現付款、隱私與介面風險後發出本機提醒。

## 完整說明

AgentGuard Companion 在使用者明確啟用輔助使用服務並開始守護工作階段後，觀察介面文字、表單填寫、深層連結與視窗覆蓋情況。它可以識別付款或轉帳提示、隱私陷阱、非必要個資填寫、可疑深層連結與提示詞注入標記，並在裝置上記錄事件與顯示風險通知。

使用者可選擇把事件轉送到自己控制的桌面 AgentGuard 本機 API。中繼使用 Bearer 權杖，Android 伴生應用程式也會使用 Android Keystore 中的 ECDSA P-256 金鑰簽署請求 body；裝置公開金鑰必須由使用者登記到桌面介面卡註冊表。

**重要邊界：** Android 伴生應用程式在事件發生後才觀察並通知。它不能暫停、撤銷或阻止第三方應用程式已經執行的付款、轉帳或其他操作，也不能描述為系統級攔截器。

## 目前發布阻塞項

- 目前設定為 `compileSdk = 34`、`targetSdk = 34`。
- 截至 2026-08-28，Google Play 對一般行動應用程式的新應用程式與更新要求至少 API 35；自 2026-08-31 起要求 API 36。目前建置不能作為合規的新應用程式或更新提交。請參閱 [Google Play 官方目標 API 要求](https://support.google.com/googleplay/android-developer/answer/11926878)。
- 儲存庫沒有正式上傳 keystore、正式簽章 AAB 的驗證記錄、Play Console 審核結果或實機端到端驗收。
- 尚未完成輔助使用 API 使用聲明、資料安全表與商店素材的最終審核。

## 資料安全草稿

- 預設處理：輔助使用事件、應用程式/視窗資訊與風險結果保存在應用程式私有目錄。
- 預設上傳到開發者伺服器：無。
- 選用傳輸：只有使用者開啟桌面轉送後，事件才會送到使用者設定的桌面 API。
- 分享：預設不與第三方分享。
- 刪除：解除安裝會刪除應用程式私有資料；發布前仍需補充產品內刪除流程與正式保留政策。

以上是程式碼現況說明，不是已提交或獲准的 Play Console 聲明。

## 敏感能力說明

### 輔助使用服務

核心功能需要 `BIND_ACCESSIBILITY_SERVICE`：在使用者主動開始的守護工作階段中觀察介面文字與表單變更，以發現付款、隱私與注入風險。服務不具備撤銷第三方操作的能力。

### 套件可見性

清單使用精確的 `<queries>` 項目查找符合 `ADB_INPUT_B64` / `ADB_INPUT_TEXT` 的廣播接收器，並查詢可啟動應用程式以執行相似應用程式檢查。專案不要求 `QUERY_ALL_PACKAGES`，但啟動器可見性仍涉及隱私，正式提交時必須如實說明。

### 通知與前景服務

使用中的守護工作階段使用前景服務通知；Android 13 及以上還需要使用者授予通知權限。高風險通知是事後提醒，通知被拒絕時風險仍會寫入日誌，但使用者可能看不到即時提示。

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

`app/build.gradle.kts` 的 `signingConfigs.release` 會讀取上述環境變數或同名 Gradle 屬性。建置成功不等於可發布；仍須驗證憑證身分、升級 `targetSdk`、在實機完成權限與中繼流程，並通過 Google Play 審核。

更多技術說明請參閱 [Android Companion README](README.zh-TW.md) 與 [隱私權政策](../../docs/privacy-policy.zh-TW.md)。
