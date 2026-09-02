[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

發佈日期：2026-08-28

> **這是原始碼候選版，不是正式環境安裝套件。**
> 目前尚未完成程式碼簽署、公證、商店發佈與真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

本說明已同步候選分支的後續原始碼更新；版本仍是 `1.0.0-rc.1`，並未因此產生或發佈新的安裝套件。

## 定位

本候選版面向研究與評測、開發或預備環境，以及知情維運控制下的內部試點。AgentGuard 的主要形態是旁路觀測、風險判決與可追責稽核；工具閘道提供可繞過的協作式控制，瀏覽器頁面閘門與 DNR 對有限向量提供執行前控制，Linux `guard-jail` 為其自行啟動的程序提供窄範圍核心邊界。

## 主要能力

- 跨平台 Rust 規則引擎，以及 OP、TR、FM 隱私評分、工作階段計畫與能力範圍判決；`guard-trust` 為六類入站面提供統一的 fail-closed 信任詞彙與清冊檢查。
- macOS 的 AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑；AX 樹狀結構變化新增 AXObserver 推送、合併與兜底輪詢，像素仍為取樣路徑。
- Windows 的 UI Automation、GDI 擷取與 Windows.Media.Ocr 實作；尚未完成真實裝置驗收。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- Chromium MV3 擴充功能、Native Messaging host、消費者化三語介面，以及付款/陷阱/fetch-XHR 頁面閘門和惡意/越界主機 DNR 阻擋；名單支援管理與規則溯源。
- Firefox 移植與封裝骨架、Edge 相容路徑，以及 Safari 的設計邊界；這些瀏覽器路徑尚未完成真實環境端對端驗收。
- 協作式 MCP 工具閘道，以及 Linux `guard-jail` 檔案系統約束與選用 `scope.net` TCP 連接埠天花板。
- 雜湊鏈稽核、選用逐筆簽章與 SQLCipher、Ed25519 威脅情報、本機 API、簽署策略同步和已驗證計費 webhook。
- D 亮色 Logo 與跨平台 App 圖示；macOS、Windows 與 Chromium 的三語介面、首次引導、易懂風險文案、無障礙確認層、鍵盤操作與深色模式。
- 目前 20 條使用者能力聲明到證明測試的機器映射、產生的狀態儀表板、可重現離線評測、攻擊面覆蓋矩陣、預檢與發佈證據閘門。
- Firefox、Windows 與 macOS 驗收清單、可執行真實裝置手冊、瀏覽器測試資料與報告範本；它們定義驗收方法，不表示驗收已完成。

## 安全強化

- 發佈路徑拒絕以 `sha256:` 完整性摘要冒充威脅情報真實性簽章。
- Native Messaging 呼叫者身分預設 fail-closed；計費、策略、本機 API、威脅情報、介接器斷言與 Native Messaging 統一遵循已驗證入站才能進入信任邊界的原則。
- 敏感檔案系統目標不可透過人工確認放行；閘道檔案操作進入引擎獨立判決，宿主接入稽核儲存與簽章器後才寫入可驗證稽核。
- `scope.net` 一經宣告便只允許列出的 TCP connect/bind 連接埠；空表表示全部拒絕，後端無法強制時拒絕啟動而不靜默開放網路。
- 瀏覽器惡意主機名單跨 service worker 重啟保留，越界主機隨工作階段到期，並在 popup 中顯示觸發規則；DNR 安裝失敗仍會 fail-open，不偽造已經阻擋的狀態。
- 修正路徑歸約、符號連結、macOS 磁碟區別名、root mount namespace、稽核見證包含性與前端注入/CSP 等問題。
- 金鑰檔案以受限權限建立，並拒絕不安全權限或符號連結路徑。

## 驗證基線

儲存庫包含離線情境、攻擊面覆蓋聲明，以及目前 20 條能力聲明到具體測試的機器可核對映射。`docs/status-dashboard.html` 從能力聲明、發佈閘門與狀態資料產生，不是手寫結論。

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

正式發佈還必須讓嚴格閘門取得程式碼簽署、公證與真實裝置證據；軟閘門通過不能替代這些證據。

## 明確未完成

- macOS、Windows 與 Android 的正式簽署安裝套件。
- macOS 公證與 staple。
- macOS 已完成目前 ad-hoc 候選在本機的啟動、TCC 探測與 AXObserver 推送流程檢查；Developer ID 簽署/公證後的全新安裝與升級驗收仍未完成。Windows 與 Android 的候選版真機 E2E 仍未完成。
- Chrome、Edge 與 Firefox 的真實瀏覽器端對端驗收；Firefox 的 DNR 配額與 Native Messaging gecko-id 路徑仍需校準。
- App Store、Chrome Web Store 與 Google Play 的正式發佈。
- macOS 與 Windows 的核心層級 jail。
- 網路出口強制代理。
- Safari 擴充功能工程與 Swift Native Messaging handler；目前只有設計。
- iOS 完整工程及引擎接線。

Android 的高風險提示發生在事件之後。Chromium 的頁面閘門與 DNR 能在其涵蓋的向量上執行前控制，但頁面閘門可被惡意頁面繞過，DNR 安裝失敗時 fail-open，Native Messaging 判決仍為非同步。macOS AX 樹狀結構有推送，但像素擷取與兜底仍有取樣/輪詢邊界。除 Linux `guard-jail` 對其所啟動程序的窄約束外，大部分控制依賴 Agent 或頁面經過 AgentGuard，不能描述為通用或不可繞過的防護。

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
