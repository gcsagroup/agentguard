[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

# AgentGuard iOS WebShield

狀態：**可建置的 Swift-first 受限 SKU；正式發佈仍為 No-Go。**

本目錄已有正式 XcodeGen 定義、iOS 容器 App、Safari Web Extension、共享
`WebShieldCore`、Swift 單元/UI 測試及獨立延伸功能腳本測試。它沒有綁定實驗性的 Rust
`guard-ffi`，也不能作為簽署、真機 Safari 或 TestFlight 驗收證據。

## IOS-01～05 已完成

- **IOS-01 工程：**`project.yml` 產生 App、Safari 延伸功能、靜態 Core 與 unit/UI test
  targets；容器 App 透過 Embed App Extensions 嵌入延伸功能。
- **IOS-02 Safari 閘門：**Manifest V3 isolated-world 內容腳本以 `document_start` 注入所有獲准的
  HTTP(S) frame，並同步註冊 capture listener。`unknown`/`unavailable` 對已識別的危險點擊或提交
  關閉失敗，只有原生端明確回傳 `disabled` 才放行；啟用時僅允許一次或取消後只傳送最小化事件。
- **IOS-03 原生合約與儲存：**原生訊息只接受版本 1 白名單欄位，限制 64 KiB/50 個事件；URL
  只保留 HTTP(S) origin。App Group UserDefaults 保存同意/開關，原子 JSON 稽核由 actor 與
  `NSFileCoordinator` 協調的原子 JSONL，最多保留 7 天或 500 筆；讀取也會在同一個協調寫入
  交易內把過期列從磁碟實體清除。
- **IOS-04 隱私與介面：**App 與延伸功能都有簡體、繁體、英文文案，並含啟用指引、本機清除
  入口、App Group/Keychain entitlements、PrivacyInfo 與圖示。
- **IOS-05 測試：**Core 行為、無簽署能力邊界、UI 啟動與延伸功能合約均有自動測試。

## 建置

產生的 `.xcodeproj` 已由本目錄 `.gitignore` 排除，可從 `project.yml` 重建：

```bash
xcodegen generate --spec apps/ios-webshield/project.yml

xcodebuild \
  -project apps/ios-webshield/AgentGuardWebShield.xcodeproj \
  -scheme AgentGuardWebShield \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

延伸功能腳本測試：

```bash
node --test apps/ios-webshield/Tests/ExtensionTests/*.test.cjs
```

## 資料與訊息邊界

網頁內容腳本只把合約版本、隨機 request ID、規則 ID、固定 finding/action 列舉、時間和目前
URL 傳給原生延伸功能。Swift 再次嚴格驗證，落盤前把 URL 縮減為 origin。原始 DOM、輸入值、
URL 路徑、query、fragment 與頁面標題均不儲存或上傳。

稽核檔位於 App Group `group.com.agentguard.webshield`。兩個 targets 也宣告相同的 Keychain
access group；完全停用程式碼簽署時，Keychain 與 App Group 會回傳 entitlement 錯誤，產品會
保持關閉，不會退回普通沙盒目錄假裝成功。

## Safari 可證明邊界

- `document_start` 與 capture listener 縮短註冊窗口，但 isolated-world 不保證早於頁面世界的每段
  腳本；閘門只能取消它實際收到且可取消的 DOM 事件，不能撤銷頁面監聽器先前完成的副作用。
- `all_frames` 涵蓋取得網站權限且符合 Manifest 的 HTTP(S) frame，不據此聲稱涵蓋任意
  `about:blank`/`srcdoc` frame、缺少權限的 frame 或注入前動作。
- open Shadow DOM 僅涵蓋初始掃描、DOM mutation 發現，或由事件 `composedPath()` 暴露的開放根；
  不涵蓋 closed shadow，也不聲稱攔截腳本直接呼叫網路/API 的動作。
- 狀態尚未回傳或本機訊息失敗時，只阻止本機規則已判定為危險的候選且不自動重播；普通動作
  繼續。原生端明確確認關閉防護時，危險候選依使用者選擇放行。

## 明確不支援

- 不使用 MAIN world，不修改 `window.fetch` 或 `XMLHttpRequest`。
- 不使用 `connectNative` 長連線、DNR 遠端情報或任何上傳端點。
- 不監控其他 App、系統 UI、Accessibility 或畫面內容。
- 不聲稱涵蓋腳本直接發出的網路請求，也不聲稱與 Rust 規則引擎等價。

## 2026-09-05 本機驗收

- Xcode 26.6 / iOS 26.5 Simulator SDK / XcodeGen 2.46.0。
- Release 通用模擬器與通用裝置建置都以 `CODE_SIGNING_ALLOWED=NO` 通過；裝置套件完全未簽署，
  模擬器二進位只有 linker ad-hoc 簽署，兩者都不是發佈簽署證據。主 App 內存在 Safari `.appex`
  與全部宣告資源，Release Analyze 無診斷。
- `WebShieldCoreTests`：20/20 通過。
- `AgentGuardWebShieldUITests`：2/2 通過。
- Safari 延伸功能 Node 合約與生命週期：18/18 通過。
- 已在現有 iOS 26.5「Aegis QA iPhone 17」模擬器安裝並啟動容器 App。

截圖與環境記錄見 [Acceptance/README.md](Acceptance/README.md)。

## 發佈阻斷

倉庫沒有 provisioning profile，也沒有 App Group/Keychain capability 的開發者後台註冊證據；
Archive、簽署、真機 Safari 延伸功能啟用、網站權限、Private Browsing、升級/解除安裝與
TestFlight 都尚未驗證。設定 Team/App IDs/profiles 並完成上述驗收前，發佈仍是 **No-Go**。
