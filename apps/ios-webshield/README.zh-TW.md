# AgentGuard iOS WebShield（受限方向）

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

本目錄目前只有一個 SwiftUI 原始碼片段：`Sources/ContentView.swift`。它顯示策略狀態，並對內建範例字串執行簡單關鍵字示範。

> 這不是可直接建置的 iOS 應用程式：儲存庫中沒有 `.xcodeproj`、`.xcworkspace`、Swift Package manifest、Safari Web Extension target、簽章設定、entitlements 或可執行的 iOS 測試。

## 目前實際內容

- 一個 `ContentView` SwiftUI 視圖。
- 一個只處理固定範例文字的 `LocalHeuristics.scanDemoPage()` 示範。
- 沒有 `WKWebView` 接線，也沒有 Safari Web Extension 實作。
- 沒有連接 Rust 引擎、`guard-sync`、Managed App Configuration 或 App Group。

因此，本目錄只能作為 iOS 受限 SKU 的設計起點，不能證明已具備網頁守護、工作階段隔離或發布能力。

## 本機試驗

如需查看此片段：

1. 在 Xcode 中建立一個 SwiftUI iOS App，例如 `AgentGuardWebShield`。
2. 將 `Sources/ContentView.swift` 複製到新專案並設為初始視圖。
3. 選擇開發團隊與 Bundle Identifier，在模擬器或裝置上建置。

這些步驟會在儲存庫之外產生本機 Xcode 專案；不要把它誤認為儲存庫提供了可重現的 iOS 建置。

## 若要成為可交付元件

至少還需要：

- 可重現的 Xcode 專案或 Swift Package 結構；
- 明確的 `WKWebView` 或 Safari Web Extension target 與訊息通道；
- 三語 UI、隱私揭露、entitlements、簽章與封裝設定；
- 與 AgentGuard 策略/引擎的真實接線；
- 單元測試、UI 測試及實機端到端驗收；
- App Store 能力、權限與審核結論。

目前結論：**原始碼片段可供試驗，iOS 產品與發布物尚不存在。**
