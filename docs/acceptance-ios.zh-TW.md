[简体中文](acceptance-ios.md) | [繁體中文](acceptance-ios.zh-TW.md) | [English](acceptance-ios.en.md)

# iOS Safari WebShield 真機與 TestFlight 驗收

本文件定義首個 GA 的 iOS 發佈證據。模擬器建置、未簽署裝置建置與 Xcode Analyze 只屬於開發閘門，不能取代本清單。正式候選必須先以 Apple Distribution 身分簽署，並讓 App、Safari Web Extension、build number 與 TestFlight 中的同一候選一致。

## 前置條件

- 使用最終候選提交產生的 Release archive；App 與 Extension 使用同一 Apple Team、正確 App Group 與正式環境 provisioning profile。
- 至少涵蓋目前與最低支援系統的真實 iPhone 和 iPad；測試帳號與裝置識別資訊不得寫入儲存庫。
- I1–I6 的報告放在 `evidence/ios/`；TF1–TF3 的報告放在 `evidence/ios-testflight/`。每個案例使用不同的非空證據檔案。

## Safari Web Extension 真機案例

| # | 步驟 | 通過判據 |
|---|---|---|
| I1 | 在真實 iPhone 安裝簽署候選，依引導在 Safari 開啟擴充功能 | App 與 Extension 可啟動；版本、build、Team ID 與候選一致；關閉擴充功能時 UI 明確顯示未受保護 |
| I2 | 在真實 iPad 重複安裝、啟用與關閉流程 | iPad 版面可用，擴充功能狀態與 App 一致，不把模擬器結果冒充真機 |
| I3 | 分別開啟良性頁面與聲明支援的付款/陷阱測試資料 | 良性動作不被誤擋；支援範圍內風險動作在執行前被阻擋；頁面內沒有「允許一次」或自動重播 |
| I4 | 強制結束 App/Safari、重新啟動裝置，並執行 N-1 → 目前候選升級 | 擴充功能開關、規則版本與稽核狀態可預期；升級不擴大權限，不靜默恢復使用者已關閉的能力 |
| I5 | 檢查本機稽核、規則同步與「刪除資料」 | App/Extension 資料一致；敏感內容不進入非必要記錄；刪除後依文件清除且可驗證 |
| I6 | 以 VoiceOver、動態字體與鍵盤/外接鍵盤走 onboarding、狀態與風險提示 | 控制項有名稱、焦點順序可用、文字不截斷，風險與未受保護狀態不只依賴顏色表達 |

I1–I6 全部通過後，報告須包含一整列：

```text
AGENTGUARD_ACCEPTANCE_IOS=PASS
```

## TestFlight 案例

| # | 步驟 | 通過判據 |
|---|---|---|
| TF1 | 上傳同一 archive 並等待 App Store Connect 處理完成 | TestFlight 顯示的 bundle ID、marketing version、build number 與簽署候選一致；沒有替換二進位檔 |
| TF2 | 從 TestFlight 在真實裝置全新安裝 | 安裝來源、版本與 build 可核對；App 啟動，Safari 可找到並啟用內嵌 Extension |
| TF3 | 從上一個 TestFlight build 升級至目前 build，重複 I3 核心正負例 | 使用者資料與擴充功能狀態依移轉合約保留；風險/良性行為仍正確；無啟動崩潰或失聯 |

TF1–TF3 全部通過後，獨立報告須包含一整列：

```text
AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS
```

## 結構化校驗

```bash
guard-cli manual-acceptance ios docs/acceptance-ios.md evidence/ios/report.md --repo-root .
guard-cli manual-acceptance ios-testflight docs/acceptance-ios.md evidence/ios-testflight/report.md --repo-root .
```

上述命令只校驗報告結構、逐項引用與證據閉包。它們是未簽署本機自證，不能證明螢幕截圖來自所稱裝置；發佈負責人仍須核對 App Store Connect、簽署身分與最終候選。
