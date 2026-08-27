[简体中文](RELEASE-1.0.0-rc.1.md) | [繁體中文](RELEASE-1.0.0-rc.1.zh-TW.md) | [English](RELEASE-1.0.0-rc.1.en.md)

# AgentGuard 1.0.0-rc.1

發佈日期：2026-08-28

> **這是原始碼候選版，不是正式環境安裝套件。**
> 目前尚未完成程式碼簽署、公證、商店發佈與真實裝置端對端驗收，正式環境發佈判斷仍為 **No-Go**。

## 定位

本候選版面向研究與評測、開發或預備環境，以及知情維運控制下的內部試點。AgentGuard 的主要形態是旁路觀測、風險判決與可追責稽核；工具閘道提供可繞過的協作式控制，Linux `guard-jail` 提供一個窄範圍的核心檔案系統邊界。

## 主要能力

- 跨平台 Rust 規則引擎，以及 OP、TR、FM 隱私評分、工作階段計畫與能力範圍判決。
- macOS 的 AXUIElement、ScreenCaptureKit 與 Vision OCR 觀測路徑。
- Windows 的 UI Automation、GDI 擷取與 Windows.Media.Ocr 實作；尚未完成真實裝置驗收。
- Android AccessibilityService 伴生應用程式、環境調查與 Android Keystore P-256 介接器簽章。
- Chromium MV3 擴充功能、Native Messaging host 與高風險判決事後通知。
- 協作式 MCP 工具閘道，以及 Linux `guard-jail` 檔案系統約束。
- 雜湊鏈稽核、選用逐筆簽章與 SQLCipher、Ed25519 威脅情報、本機 API、簽署策略同步和已驗證計費 webhook。
- 可重現離線評測、攻擊面覆蓋矩陣、預檢與發佈證據閘門。

## 安全強化

- 發佈路徑拒絕以 `sha256:` 完整性摘要冒充威脅情報真實性簽章。
- Native Messaging 呼叫者身分預設 fail-closed。
- 敏感檔案系統目標不可透過人工確認放行；閘道檔案操作進入引擎獨立判決，宿主接入稽核儲存與簽章器後才寫入可驗證稽核。
- 修正路徑歸約、符號連結、macOS 磁碟區別名、root mount namespace、稽核見證包含性與前端注入/CSP 等問題。
- 金鑰檔案以受限權限建立，並拒絕不安全權限或符號連結路徑。

## 驗證基線

儲存庫在本候選版中記錄了以下基線：

- 130 個離線情境檔案；
- 104 項驗收檢查；
- 30 個已發佈攻擊面，其中 13 個 covered、16 個 partial、1 個 uncovered。

這些數字是提交前的儲存庫基線，**不是本次發佈動作已經複驗的證明**。在目前提交上發佈前必須重新執行：

~~~bash
cargo run -p guard-cli -- eval --scenarios eval/scenarios
make acceptance
cargo run -p guard-cli -- coverage
make check
make release-gate
~~~

正式發佈還必須讓嚴格閘門取得程式碼簽署、公證與真實裝置證據；軟閘門通過不能替代這些證據。

## 明確未完成

- macOS、Windows 與 Android 的正式簽署安裝套件。
- macOS 公證與 staple。
- macOS、Windows 與 Android 的真實裝置端對端驗收。
- App Store、Chrome Web Store 與 Google Play 的正式發佈。
- macOS 與 Windows 的核心層級 jail。
- 網路出口強制代理。
- iOS 完整工程及引擎接線。

Android 與 Chromium 的高風險提示發生在事件之後，不是執行前阻擋。除 Linux `guard-jail` 外，大部分控制依賴 Agent 主動經過 AgentGuard，不能描述為不可繞過的防護。

## 相關文件

- [文件入口](README.zh-TW.md)
- [變更記錄](../CHANGELOG.zh-TW.md)
- [發佈安全與證據閘門](release-security.md)
- [平台能力矩陣](platform-matrix.md)
- [產生的攻擊面覆蓋矩陣](../eval/coverage-matrix.md)
