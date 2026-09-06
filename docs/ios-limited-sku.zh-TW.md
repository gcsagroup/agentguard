[简体中文](ios-limited-sku.md) | [繁體中文](ios-limited-sku.zh-TW.md) | [English](ios-limited-sku.en.md)

# iOS 受限 SKU

> **目前狀態：可建置的本機候選；正式發佈 No-Go。**
>
> 原始碼機械事實以產生的 [能力矩陣](capability-matrix.zh-TW.md) 為準。本頁記錄產品邊界與
> 外部驗收，不把模擬器結果升級為真機、簽署或 App Store 證據。

## 已完成：IOS-01～05

1. `apps/ios-webshield/project.yml` 可重現產生含容器 App、Safari Web Extension、
   `WebShieldCore`、unit/UI tests 的 Xcode 工程；主 App 嵌入延伸功能。
2. Safari isolated-world 內容腳本只檢查 DOM 點擊與表單提交，對付款、提示注入與敏感表單
   提供本機「取消/僅允許一次」閘門。
3. `sendNativeMessage` 接入版本化白名單 Swift 合約；原生層限制訊息大小/數量，URL 縮減成
   origin 後才寫入本機稽核。
4. App Group UserDefaults 保存同意與開關；原子 JSONL 稽核透過 actor、`NSFileCoordinator` 與
   保留上限協調。App/延伸功能宣告共享 Keychain 群組，不含正式環境憑證。
5. 主 App 提供三語啟用指引、隱私邊界、活動清單與本機清除入口；App/延伸功能均含
   PrivacyInfo。

實作與重現命令見 [iOS WebShield README](../apps/ios-webshield/README.zh-TW.md)。

## 不得擴大解讀的邊界

- 不監控 Safari 以外的 App、系統 UI、Accessibility 或畫面。
- 不使用 MAIN world，也不攔截 `fetch`/XHR；程式直接發出的網路請求不在本版能力內。
- 不使用 Chromium `connectNative` 長連線、遠端 DNR 情報或上傳端點。
- Swift-first 指平台橋接、狀態與稽核，不是重寫或等價替代 Rust 策略引擎。
- 目前只是在 Safari 網站授權後的頁面內合作式防護，不是不可繞過的安全邊界。

## 已取得證據

2026-09-05 在 Xcode 26.6 / iOS 26.5 模擬器 SDK 上：無簽署 Release build、Analyze 與完整嚴格並行
檢查成功；主 App 產物含 Safari `.appex`；Swift Core 20/20、UI 2/2、延伸功能 Node 18/18 通過；
容器 App 已在現有 iOS 26.5 模擬器安裝、啟動並截圖檢查。

完全停用程式碼簽署時 App Group 與 Keychain entitlement 無法使用；UI 會明確報錯並保持防護
關閉。這是預期的 fail-closed 行為，不是簽署驗收。

## 發佈前仍需完成

- 確認正式 bundle IDs，註冊同 Team 的 App Group/Keychain capabilities 並產生 profiles。
- 完成簽署 Archive、entitlements 回讀與 App Store Connect 驗證。
- 在代表性真機 Safari 驗收延伸功能啟用、網站權限、允許/取消恰好一次、程序重啟、Private
  Browsing、三語、升級/解除安裝與清除。
- 完成 TestFlight 安裝/升級與隱私說明複核。

所有條件完成前，iOS 只能標示為 **buildable limited candidate**，不能標示為已發佈或完整支援。
