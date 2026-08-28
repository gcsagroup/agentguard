[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 變更記錄

本文件記錄 AgentGuard 的重要變更。版本號遵循語意化版本。

## [未發佈]

### Added

- 接入 D 亮色品牌方案：新增共用 Logo 與 App 圖示母版；更新 macOS、Windows、Android 與 Chromium 圖示（含選單列、Adaptive/主題及通知小圖示）；並在三語 README、文件入口、符合性說明與各前端頁首顯示統一品牌標誌。

## [1.0.0-rc.1] - 2026-08-28

> 原始碼候選版，不代表正式環境安裝套件已具備發佈條件。目前尚未完成程式碼簽署、公證、商店發佈或真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

### Added

- 跨平台 Rust 規則引擎、OP/TR/FM 隱私評分、工作階段計畫與能力範圍判決。
- macOS AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑。
- Windows UI Automation、GDI 擷取與 Windows.Media.Ocr 實作。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- Chromium MV3 擴充功能、Native Messaging host 與高風險判決事後通知。
- 協作式 MCP 工具閘道，以及 Linux 上由核心執行的 `guard-jail` 檔案系統邊界。
- Ed25519 威脅情報、雜湊鏈稽核、選用逐筆簽章與 SQLCipher。
- Bearer 保護的本機 API、簽署策略同步與已驗證計費 webhook。
- 離線評測、覆蓋矩陣、預檢與發佈證據閘門。
- 簡體中文、繁體中文與英文的核心 README、文件入口、發佈說明和變更記錄。

### Security

- 發佈路徑拒絕以 `sha256:` 完整性摘要冒充威脅情報真實性簽章。
- Native Messaging 呼叫者身分預設 fail-closed。
- 敏感檔案系統目標改為不可確認放行；閘道檔案操作進入引擎獨立判決，宿主接入稽核儲存與簽章器後才寫入可驗證稽核。
- 修正路徑歸約、符號連結、macOS 磁碟區別名、root mount namespace 與讀取範圍問題。
- 強化稽核見證包含性、工作階段計數、金鑰檔案權限、前端 DOM 寫入與 CSP。
- 讓策略同步與計費 webhook 在跨越信任邊界時驗證簽章。

### Changed

- 明確區分旁路觀測、協作式控制與 Linux 核心執行邊界。
- Android 與 Chromium 的確認統一描述為事件後通知，不再描述為執行前阻擋。
- Windows 狀態從模擬骨架更新為真實 UIA/GDI/OCR 實作，同時保留“尚未真實裝置驗收”的限制。
- `guard-ffi` 明確標記為儲存庫內沒有使用者的實驗元件。
- 發佈文件不再把原始碼、測試、建置與正式安裝套件證據混為同一狀態。

### Known limitations

- 除 Linux `guard-jail` 外，大部分控制依賴 Agent 主動經過 AgentGuard，可以繞過。
- 桌面觀測包含輪詢，不是即時監控。
- Android 與 Chromium 無法在動作發生前阻擋。
- Windows 尚無真實裝置端對端驗收；iOS 只有有限骨架，沒有完整工程或引擎接線。
- 儲存庫測試金鑰不得用於正式環境，部署前必須替換。
- 尚無簽署、公證安裝套件與真實裝置驗收證據，嚴格發佈閘門不能通過。

完整範圍與複驗要求見 [1.0.0-rc.1 發佈說明](docs/RELEASE-1.0.0-rc.1.zh-TW.md)。
