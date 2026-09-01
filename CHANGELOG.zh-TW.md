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
- 記錄 Windows 候選 `89dadf9` 的部分真機驗收：Windows 11 build 26200 上桌面測試 5/5、Clippy `-D warnings` 與 Release 建置通過；未簽署 EXE 的 SHA-256 為 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`。獨立 RDP 互動證據涵蓋兩輪各超過 30 秒的啟動與連續觀測、UIA/GDI/OCR 可用狀態、真實 `OVL-010` 阻斷模態及拒絕後第二輪穩定性，且未出現新的 Event 1000；這不是 W1–W7 全量驗收。
- 新增八類結構化發佈證據範本與校驗：證據綁定目前完整提交號、實際命令、結束碼、時間、判據輸出與產物身分。普通發佈檔案使用標準 SHA-256；macOS `.app` 的 tree-v2 綁定整個 bundle 的路徑、類型、長度、內容及 Unix `0111` 可執行位元遮罩；驗收 closure-v1 則綁定報告 bytes 與每個唯一逐項引用的路徑、長度和內容。四類簽署證據還把 `signer` 綁定至閘門外部提供的 Apple Team ID 或發佈憑證 SHA-256，四類驗收證據固定為 `null`。路徑採用可攜式 ASCII 元件且逐項引用不得重複使用；未填寫範本、空產物、缺失檔案、自我引用、符號連結與摘要不符均不能通過。tree-v2 不綁定其他 mode、xattr／ACL，也不取代隔離機上的 quarantine、Gatekeeper 與首次啟動驗收；驗收 closure 仍是不能證明螢幕截圖來源的未簽署自證。

### Security

- 網路天花板一經宣告便涵蓋 TCP connect 與 bind；空連接埠表表示全部拒絕，非 Landlock 後端不得靜默降級為網路開放。
- 惡意主機 DNR 名單跨 service worker 重啟保留，越界主機隨工作階段到期；popup 可檢視、解除並追溯至 `INTEL-DOMAIN` 或 `SCOPE-HOST`。
- 嚴格閘門不再接受僅含關鍵字的任意檔案；簽署與驗收命令必須採用校驗器認可的完整 fail-closed 成功鏈，任何子命令失敗都不能被後續輸出掩蓋。四類簽署證據還須出現工具輸出與外部預期的 Team ID／憑證 SHA-256，並在執行前後核對同一個 clean 候選提交。結構化 JSON 仍是未簽署自證，只防誤綁定、誤操作與部分機械偽造，不防控制工作區的攻擊者偽造全部欄位。

### Changed

- Chromium 不再籠統描述為「只能事後通知」：頁面閘門與 DNR 對其涵蓋的向量提供執行前控制；Native Messaging 判決仍為非同步，不能回溯阻止觸發事件，且頁面閘門/DNR 都有明確繞過與 fail-open 邊界。Android 仍為事件後提示。
- 桌面觀測不再籠統描述為「僅輪詢」：macOS AX 樹狀結構變化已有推送；像素擷取、其他桌面路徑與兜底仍包含取樣或輪詢，因此不是零間隙即時監控。
- Windows CI 在既有工作區測試、介接器建置/Clippy 與桌面測試之後新增真實視窗啟動 smoke；候選對應的 GitHub Actions run `33551495621` 全綠。該 smoke 只防止視窗啟動後立即退出，不能取代 W1–W7 的人工互動證據。

### Fixed

- 修正 Landlock 將目錄專屬權限附加到 `/dev/null` 等單一檔案規則，導致整份規則集回傳 `EINVAL`、子行程未啟動的問題；Linux 整合測試現在從已授權目錄啟動，並直接驗證授權讀寫與真實越界拒絕，不再因未授權的 `/dev/null` 重新導向而假綠。
- 修正 Landlock 呼叫 `prctl(PR_SET_NO_NEW_PRIVS)` 時未明確傳入三個必須為零的尾端參數而可能收到 `EINVAL` 的問題；現在統一使用完整五參數系統呼叫，並依 Linux x86_64／aarch64 選擇正確的 `prctl` 系統呼叫號，同時保留現有單一檔案權限過濾。
- 修正 aarch64 的 mount-namespace 降級路徑誤用 x86_64 `getuid`／`getgid` 系統呼叫號的問題；現在依架構選擇正確編號，並以真實系統呼叫回歸測試固定回退身分。
- 修正 Windows 預設主執行緒堆疊不足時 `guard-cli` 會在進入子命令前溢出的問題；Windows 入口現在以明確的 8 MiB 堆疊執行同一 CLI 調度。發佈閘門參數測試在 Windows 上解析 GitHub Runner 的 `C:\shells\gitbash.exe` 絕對路徑，並為一般 Windows 回退到預設 Git 安裝路徑；測試再由原生 `current_dir` 進入儲存庫並綁定腳本自己的結束碼 2 與拒絕文字，WSL、路徑或 CLI 啟動失敗都不能再冒充安全拒絕。
- 修正 Windows `canonicalize` 產生的 `\\?\` verbatim 磁碟機／UNC 前綴與一般前綴不等價的問題；真實 `C:\Windows`、`C:\ProgramData` 路徑會重新命中敏感目標，固定的 `\\?\` 命名空間標記也不再被誤判為萬用字元。
- 保留 Windows 元件層級路徑歸約與現有 home、`ProgramData`、`Program Files (x86)` 敏感路徑保護；未採用會把不同路徑形狀全域折疊並造成保護降級的方案。
- 修正 Windows 工作區測試仍把 `/bin/*`、`/srv`、`/tmp` 與 `/etc` 當作跨平台測試資料的問題；閘道改用可控 Rust 子行程驗證並行管道、UTF-8 截斷與結束碼，路徑、Shell 與 jail 測試使用目標平台真實的絕對路徑，同時保留敏感目錄與參數注入覆蓋。
- 修正 Windows 桌面啟動時先在主執行緒以 MTA 初始化 UI Automation，隨後 `OleInitialize` 需要 STA 而觸發 `RPC_E_CHANGED_MODE` 並退出的問題；啟動能力探測現在使用專用執行緒並快取結果，視窗主執行緒不再被預先改為 MTA。
- 修正短命能力探測執行緒結束後重用 WinRT OCR `FactoryCache` 可能觸發 `0xC0000005` 的問題；處理程序期 `CoIncrementMTAUsage` cookie 維持 COM MTA 可用，並新增 COM/OCR 跨執行緒回歸測試。
- Firefox MV3 套件改用其支援的模組化 `background.scripts` 事件頁；結構測試同時釘住 Chromium service worker 與 Firefox event page 的同一個 `background.js` 入口。
- 修正讀取阻擋名單時遺失規則溯源，以及「允許一次」使用 `form.submit()` 繞過表單驗證並遺失 submitter 語意的問題；付款按鈕的 click→submit 鏈現在共用一次性批准，不會重複顯示確認。
- 把 macOS AXObserver 真正接入桌面驅動，繫結持續運作的主 RunLoop，並隨最上層應用程式切換重新繫結；新增產品路徑接線測試。
- SQLCipher 發佈建置遇到舊明文 SQLite 稽核資料庫時不再啟動崩潰：原資料庫保持不變，新的加密資料庫使用獨立同層檔案。
- 擴充功能封裝改為先產生全新 ZIP 再原子取代，避免 `zip` 更新模式因來源檔案時間戳而保留舊程式碼。

### Known limitations

- 目前 macOS ad-hoc 候選已在本機完成啟動、TCC 探測與 AXObserver 推送流程檢查，但 Developer ID 簽署/公證後的全新安裝與升級路徑仍未驗收；Chrome、Edge 與 Firefox 仍缺候選版真機 E2E，Safari 只有設計。Windows 只有啟動、連續觀測與阻斷模態的部分真機證據；付款 CTA、第三方表單與像素 OCR、隱寫、overlay 邊界、能力失敗分支與 Native Messaging 等 W1–W7 項目尚未完整執行。
- 頁面閘門能涵蓋的只是在已安裝擴充功能可觸及的頁面向量；DNR 規則安裝失敗時 fail-open，Native Host 與 Android 通知不能提供不可繞過的執行前控制。
- 目前尚未設定正式 Apple Team ID、Windows／Android 發佈憑證 SHA-256，四類簽署檢查維持 `UNVERIFIED`；Windows EXE 為 `NotSigned`，預設 Release 未啟用 SQLCipher，也沒有安裝套件及全新安裝、升級、解除安裝證據。公證、真實裝置與回復證據仍不完整；結構化證據閘門上線不改變正式環境發佈 **No-Go** 結論。

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
