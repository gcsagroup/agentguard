[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

發佈日期：2026-08-28

> **這是原始碼候選版，不是正式環境安裝套件。**
> 目前尚未完成程式碼簽署、公證、商店發佈與真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

本說明已同步候選分支的後續原始碼更新；版本仍是 `1.0.0-rc.1`，並未因此產生或發佈新的安裝套件。

> **`1.0.0-rc.1` 是原始碼樹裡寫的版本字串，不是一個已發佈的東西。** 儲存庫裡沒有對應的 git tag、沒有簽名產物；標註日期之後合入的內容（D 方案品牌、真機報告 P0/P1/P2 的整改）都在帶著這個版本字串的原始碼樹裡。所以本說明描述的是「目前帶此版本號的原始碼」，不是某個凍結時刻的快照——它會隨原始碼更新。凡是「哪一端觀察什麼、多少測試、多少條能力聲明、什麼版本」的數字，以原始碼產生的 [docs/capability-matrix.zh-TW.md](capability-matrix.zh-TW.md) 為準，本說明不再自己維護一套。

## 定位

本候選版面向研究與評測、開發或預備環境，以及知情維運控制下的內部試點。AgentGuard 的主要形態是旁路觀測、風險判決與可追責稽核；工具閘道提供可繞過的協作式控制，瀏覽器 block-only DOM 閘門與靜態 DNR 對有限向量提供執行前阻擋，Linux `guard-jail` 為其自行啟動的程序提供窄範圍核心邊界。

## 主要能力

- 跨平台 Rust 規則引擎，以及 OP、TR、FM 隱私評分、工作階段計畫與能力範圍判決；`guard-trust` 為六類入站面提供統一的 fail-closed 信任詞彙與清冊檢查。
- macOS 的 AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑；AX 樹狀結構變化新增 AXObserver 推送、合併與兜底輪詢，像素仍為取樣路徑。
- Windows 的 UI Automation、GDI 擷取與 Windows.Media.Ocr 實作；尚未完成真實裝置驗收。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- 首個 GA 瀏覽器範圍為 Chrome/Edge 共用的 Chromium MV3 ZIP：消費者化三語介面、付款／陷阱 block-only DOM 閘門，以及明確付款 URL 形狀的靜態 DNR 阻擋；頁面內沒有允許或重播，GA manifest 沒有 Native Messaging。
- Firefox 只保留原始碼原型，不封裝、不提交、不作首個 GA 驗收閘門；Safari 是獨立產品路徑。
- 可建置的 Swift-first iOS Safari WebShield 受限 SKU，包含容器 App、Safari Web Extension、共用 Core 與自動測試；它未接入 Rust 引擎，不能取代發佈簽章、真實裝置 Safari 或 TestFlight 驗收。
- 協作式 MCP 工具閘道，以及 Linux `guard-jail` 檔案系統約束與選用 `scope.net` TCP 連接埠天花板。
- 雜湊鏈稽核、選用逐筆簽章與 SQLCipher、Ed25519 威脅情報、本機 API、簽署策略同步和已驗證計費 webhook。
- D 亮色 Logo 與跨平台 App 圖示；macOS、Windows 與 Chromium 的三語介面、首次引導、易懂風險文案、依路徑能力區分的無障礙風險／阻擋提示、鍵盤操作與深色模式。
- 使用者能力聲明到證明測試的機器映射（條數見 [capability-matrix.zh-TW.md](capability-matrix.zh-TW.md)）、產生的狀態儀表板、可重現離線評測、攻擊面覆蓋矩陣、預檢與發佈證據閘門。
- Chrome/Edge、Windows、macOS 與 iOS 驗收清單、Firefox 排除說明、可執行真實裝置手冊、瀏覽器測試資料與報告範本；它們定義驗收方法，不表示正式候選已完成發佈驗收。

## 安全強化

- 發佈路徑拒絕以 `sha256:` 完整性摘要冒充威脅情報真實性簽章。
- 儲存庫內 Native Messaging 原型的呼叫者身分預設 fail-closed；首個 GA 瀏覽器套件不申請該權限。計費、策略、本機 API、威脅情報與介接器斷言統一遵循已驗證入站才能進入信任邊界的原則。
- 敏感檔案系統目標不可透過人工確認放行；閘道檔案操作進入引擎獨立判決，宿主接入稽核儲存與簽章器後才寫入可驗證稽核。
- `scope.net` 一經宣告便只允許列出的 TCP connect/bind 連接埠；空表表示全部拒絕，後端無法強制時拒絕啟動而不靜默開放網路。
- 瀏覽器首個 GA 以 manifest 靜態 DNR 規則阻擋明確支援的付款請求；升級時清除舊 Native／動態範圍狀態，權限不可用時 fail-closed，popup 隱藏不可用入口。
- 修正路徑歸約、符號連結、macOS 磁碟區別名、root mount namespace、稽核見證包含性與前端注入/CSP 等問題。
- 金鑰檔案以受限權限建立，並拒絕不安全權限或符號連結路徑。

## 驗證基線

儲存庫包含離線情境、攻擊面覆蓋聲明，以及能力聲明到具體測試的機器可核對映射（目前條數、各端真正發出的事件與靜態測試數見原始碼產生的 [capability-matrix.zh-TW.md](capability-matrix.zh-TW.md)）。`docs/status-dashboard.html` 從能力聲明、發佈閘門與狀態資料產生，不是手寫結論。

任何已產生數字與狀態都是產生時提交的快照，**不是本次發佈動作已經複驗的證明**。在目前提交上發佈前必須重新執行：

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make capability-claims
make check-extension-gate
make check-shells
make dashboard
make check
make release-gate
~~~

正式發佈還必須讓嚴格閘門取得十二類程式碼簽署、公證與真實裝置證據；軟閘門通過不能取代這些證據。目前沒有一套綁定同一凍結候選且全部通過的十二類證據，因此結論仍為 **No-Go**。

## 明確未完成

- macOS、Windows、Android 與 iOS 的正式簽署候選產物。
- macOS 公證與 staple。
- 舊 ad-hoc macOS 候選曾完成本機啟動、TCC 探測與 AXObserver 推送流程檢查，但本輪最新 universal `.app` 尚未完整複驗；Developer ID 簽署／公證後的全新安裝、升級與 TCC 驗收也未完成。Windows 與 Android 的目前候選真實裝置 E2E 仍未完成。
- Chrome 與 Edge 尚未分別完成同一正式候選 ZIP 的 B1–B5 乾淨 profile 安裝、升級、回復與商店證據；原始碼層真 Chromium E2E 不能取代這兩個獨立嚴格閘門。Firefox 不在首個 GA 範圍內。
- iOS 已有可建置受限 SKU 與未簽署模擬器證據，但缺 Apple Distribution 簽署候選、I1–I6 真實裝置 Safari Extension 與 TF1–TF3 TestFlight 證據；也未接入 Rust 引擎。
- App Store / TestFlight、Chrome Web Store 與 Google Play 的正式發佈。
- macOS 與 Windows 的核心層級 jail。
- 網路出口強制代理。
- iOS Rust 引擎接線與受限 SKU 之外的跨 App／系統觀測能力；現有 Safari Extension 只涵蓋文件聲明的網頁 DOM 範圍。

Android 的高風險提示發生在事件之後。Chromium DOM 閘門涵蓋宣告的 frame、普通 DOM 與 open Shadow DOM；頁面可移除提示，但不能藉此授權或重播。closed Shadow DOM、瀏覽器原生動作與未識別頁面形狀不在聲明內。靜態 DNR 只涵蓋宣告的 HTTP(S) 方法、付款 URL 關鍵詞與資源類型，不能從加密 body 猜出業務語意。macOS AX 樹狀結構有推送，但像素擷取與兜底仍有取樣/輪詢邊界。除 Linux `guard-jail` 對其所啟動程序的窄約束外，大部分控制依賴 Agent 或頁面經過 AgentGuard，不能描述為通用或不可繞過的防護。

## 相關文件

- [文件入口](README.zh-TW.md)
- [變更記錄](../CHANGELOG.zh-TW.md)
- [發佈安全與證據閘門](release-security.md)
- [平台能力矩陣](platform-matrix.md)
- [入站信任](入站信任.zh-TW.md)
- [主張與測試映射](主张与测试映射.zh-TW.md)
- [瀏覽器執行前阻擋](浏览器执行前阻断.zh-TW.md)
- [真實裝置驗收執行手冊](acceptance-runbook.zh-TW.md)
- [2026-09-01 驗收報告](acceptance-report-2026-09-01.zh-TW.md)
- [產生的攻擊面覆蓋矩陣](../eval/coverage-matrix.md)
