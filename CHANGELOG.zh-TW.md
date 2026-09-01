[简体中文](CHANGELOG.md) | [繁體中文](CHANGELOG.zh-TW.md) | [English](CHANGELOG.en.md)

# 變更記錄

本文件記錄 AgentGuard 的重要變更。版本號遵循語意化版本。

## [未發佈]

### Added

- 接入 D 亮色品牌方案：新增共用 Logo 與 App 圖示母版；更新 macOS、Windows、Android 與 Chromium 圖示（含選單列、Adaptive/主題及通知小圖示）；並在三語 README、文件入口、符合性說明與各前端頁首顯示統一品牌標誌。
- 新增 `guard-trust`，以統一的常數時間比較、`InboundOutcome` 詞彙與入站面清冊測試約束六類入站信任邊界；各協定仍保留適合自身的密碼學原語與信任錨。
- 新增目前 20 條「使用者能力聲明 ↔ 證明測試」機器可核對映射，以及從能力聲明、發佈閘門與狀態資料產生的儀表板；它們證明聲明錨點與測試存在，不取代真實裝置驗收。
- `guard-jail` 新增選用 `scope.net` 網路天花板：在 Landlock ABI v4（Linux 核心 6.7+）上只允許明確列出的 TCP connect/bind 連接埠；未宣告時不約束網路，已宣告但無法強制時拒絕啟動。
- 瀏覽器擴充功能新增付款 CTA、陷阱表單及付款形狀 fetch/XHR 的有限執行前確認閘門；新增對已知惡意與超出工作階段範圍主機的 DNR 阻擋、持久化/到期語意、名單管理與規則溯源。
- 新增 Firefox 獨立 manifest、封裝與 Native Messaging host 接入骨架，並補 Edge 安裝相容；Safari 維持為需要 Xcode/Swift handler 的設計項。
- macOS AX 樹狀結構觀測新增 AXObserver 推送、150ms 去抖、800ms 延遲上限與 3s 兜底輪詢；像素擷取仍為取樣路徑。
- macOS、Windows 與 Chromium 介面完成三語消費者化改造，包括首次引導、易懂風險文案、無障礙確認層、鍵盤焦點、深色模式、通知及詞表完整性檢查。
- 新增瀏覽器、Windows 與 macOS 真實裝置驗收清單、可執行手冊、瀏覽器測試資料與報告範本；文件與測試資料是待執行流程，不表示已取得真實裝置證據。

### Security

- 網路天花板一經宣告便涵蓋 TCP connect 與 bind；空連接埠表表示全部拒絕，非 Landlock 後端不得靜默降級為網路開放。
- 惡意主機 DNR 名單跨 service worker 重啟保留，越界主機隨工作階段到期；popup 可檢視、解除並追溯至 `INTEL-DOMAIN` 或 `SCOPE-HOST`。

### Changed

- Chromium 不再籠統描述為「只能事後通知」：頁面閘門與 DNR 對其涵蓋的向量提供執行前控制；Native Messaging 判決仍為非同步，不能回溯阻止觸發事件，且頁面閘門/DNR 都有明確繞過與 fail-open 邊界。Android 仍為事件後提示。
- 桌面觀測不再籠統描述為「僅輪詢」：macOS AX 樹狀結構變化已有推送；像素擷取、其他桌面路徑與兜底仍包含取樣或輪詢，因此不是零間隙即時監控。

### Fixed

- Firefox MV3 套件改用其支援的模組化 `background.scripts` 事件頁；結構測試同時釘住 Chromium service worker 與 Firefox event page 的同一個 `background.js` 入口。
- 修正讀取阻擋名單時遺失規則溯源，以及「允許一次」使用 `form.submit()` 繞過表單驗證並遺失 submitter 語意的問題；付款按鈕的 click→submit 鏈現在共用一次性批准，不會重複顯示確認。
- 把 macOS AXObserver 真正接入桌面驅動，繫結持續運作的主 RunLoop，並隨最上層應用程式切換重新繫結；新增產品路徑接線測試。
- SQLCipher 發佈建置遇到舊明文 SQLite 稽核資料庫時不再啟動崩潰：原資料庫保持不變，新的加密資料庫使用獨立同層檔案。
- 擴充功能封裝改為先產生全新 ZIP 再原子取代，避免 `zip` 更新模式因來源檔案時間戳而保留舊程式碼。

### Known limitations

- 目前 macOS ad-hoc 候選已在本機完成啟動、TCC 探測與 AXObserver 推送流程檢查，但 Developer ID 簽署/公證後的全新安裝與升級路徑仍未驗收；Chrome、Edge、Firefox 與 Windows 仍缺候選版真機 E2E，Safari 只有設計。
- 頁面閘門能涵蓋的只是在已安裝擴充功能可觸及的頁面向量；DNR 規則安裝失敗時 fail-open，Native Host 與 Android 通知不能提供不可繞過的執行前控制。

## [1.0.0-rc.1] - 2026-08-28

> 原始碼候選版，不代表正式環境安裝套件已具備發佈條件。目前尚未完成程式碼簽署、公證、商店發佈或真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

### Added

- 跨平台 Rust 規則引擎、OP/TR/FM 隱私評分、工作階段計畫與能力範圍判決。
- macOS AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑。
- Windows UI Automation、GDI 擷取與 Windows.Media.Ocr 實作。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- Chromium MV3 擴充功能、Native Messaging host、高風險判決通知，以及對有限頁面向量與名單主機的執行前控制。
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
- Android 的確認仍是事件後通知；Chromium 的頁面閘門與 DNR 則在其有限涵蓋面內提供執行前控制，Native Messaging 判決仍為非同步。
- Windows 狀態從模擬骨架更新為真實 UIA/GDI/OCR 實作，同時保留“尚未真實裝置驗收”的限制。
- `guard-ffi` 明確標記為儲存庫內沒有使用者的實驗元件。
- 發佈文件不再把原始碼、測試、建置與正式安裝套件證據混為同一狀態。

### Known limitations

- 除 Linux `guard-jail` 外，大部分控制依賴 Agent 主動經過 AgentGuard，可以繞過。
- macOS AX 樹狀結構變化已有推送，但像素擷取、其他桌面觀測與兜底仍包含取樣或輪詢，不是零間隙即時監控。
- Android 無法在動作發生前阻擋；Chromium 只能在頁面閘門與 DNR 涵蓋的向量上執行前控制，不能據此聲稱通用或不可繞過。
- Windows 尚無真實裝置端對端驗收；iOS 只有有限骨架，沒有完整工程或引擎接線。
- 儲存庫測試金鑰不得用於正式環境，部署前必須替換。
- 尚無簽署、公證安裝套件與真實裝置驗收證據，嚴格發佈閘門不能通過。

完整範圍與複驗要求見 [1.0.0-rc.1 發佈說明](docs/RELEASE-1.0.0-rc.1.zh-TW.md)。
