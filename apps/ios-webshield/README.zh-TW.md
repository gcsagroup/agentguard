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
  關閉失敗，只有原生端明確回傳 `disabled` 才放行；啟用時阻斷匹配操作並傳送最小化的 `blocked` 記錄；提示只有關閉鍵，不授權或重放。
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

## 2026-09-17 阻斷合約修正

上一輪 App 與 Extension 建置號同為 2，名稱與 Bundle ID 保持。移除頁面內的一次放行與重放，修正網頁偽造提示屬性繞過；新事件記為 `blocked`，舊 `allowed`／`cancelled` 保留原含義。新增四個擴充功能回歸在舊程式碼全部失敗，修正後 Node 22／22、Swift Core 21／21 與 UI 2／2 通過；Xcode 27 嚴格 Release 模擬器／無簽章裝置建置及 Analyze 通過。真實 Chromium DOM 測試頁驗證三語提示與零風險請求，但原生狀態為合成，不能替代真機 Safari 或 TestFlight。詳見[本輪記錄](../../docs/ios-block-only-2026-09-17.zh.md)。

## 2026-09-17 鍵盤提示修正（建置 3）

先前 App 與 Extension 為 1.0.0 (3)，名稱與 Bundle ID 保持。風險提示關聯三語標題與說明，Tab／Shift+Tab 留在關閉鍵；關閉或 Escape 返回此前仍連接的控制項，重疊提示按層處理。未新增放行或重放。四個新增回歸在舊原始碼全部失敗；修正後 Node 26／26、Swift 23／23、兩種嚴格 Release 與 Analyze 通過，真實 Chromium DOM 的三語鍵盤操作無風險請求。原生橋為合成；真實 Safari、VoiceOver、動態字體與 TestFlight 未驗收。前批 CI 另有 macOS 啟動等待與 Windows 並行稽核失敗，仍待解決。 [記錄](../../docs/ios-dialog-accessibility-2026-09-17.zh.md)。

## 原生文字對比度（2026-09-17）

先前 App／Extension 為 1.0.0 (13)，名稱與 Bundle ID 保持。狀態、說明與分組標題使用正文顏色；共享儲存不可用時防護仍關閉。新增三語首屏對比度與捲動回歸，開發門禁 Node 26／26、Swift 26／26、嚴格 Release 與 Analyze 通過。完整自動稽核仍有動態字體、截斷及後續頁面報告，I6、真機 Safari 與 TestFlight 未通過；[證據與限制](../../docs/ios-native-contrast-2026-09-17.zh.md)。

## 舊工具鏈相容（2026-09-17）

先前 App／Extension 為 1.0.0 (22)，沿用相同名稱與識別碼。逐頁版面與多行文字修正見[建置 21 記錄](../../docs/ios-page-audit-2026-09-17.zh.md)；該提交在 CI 的 Xcode 16.4 因新 API 不存在而編譯失敗。建置 22 補充編譯期隔離，本機完整門禁通過，準確提交 `b458ca5` 的 CI 已 13／13 成功；Xcode 16.4／iOS 18.5 的 Node 26／26、Swift 26／26、嚴格 Release 與 Analyze 通過。最大字體、真機 Safari、VoiceOver 與 TestFlight 尚未驗收；見[修正與證據邊界](../../docs/ios-sdk-compatibility-2026-09-17.zh.md)。

## 逐段覆蓋與分階段審計（2026-09-17）

先前 App／Extension 為 **1.0.0 (33)**，名稱、識別碼和產品介面保持。重疊捲動核對正文逐段可見範圍，目前字級對比度先檢查，動態字體最後檢查；全部類別仍被覆蓋。遮擋報告只有在完整顯示後的整屏複查通過才算解決，建置 31 的真實低對比度反例仍失敗。主構建 Node 26／26、Swift 26／26、嚴格 Release、Analyze 與儲存庫 23／23 通過，32 的最大字級深色 2 通過／1 失敗保留；33 將複查改為從初始頁面定位，三語四種顯示狀態共 12 組全部通過，測試機恢復關閉。基線 `75c7f1b` CI 12 成功／1 失敗，舊 SDK 修復待準確新提交複驗；I6、正式簽署、真實 Safari、VoiceOver 與 TestFlight 未完成。[證據與限制](../../docs/ios-visible-audit-2026-09-17.zh.md)。

## iOS 文字辨識獨立檢查與舊系統失敗定位（2026-09-17）

**1.0.0 (34)**。建置 34 將文字辨識放在其它審計之前，保存階段樹、截圖與報告類型；全部類別與未知報告失敗條件保持。準確原始碼提交 bc0433d 的 CI 13／13 成功，iOS 18.5 完整開發門檻通過；舊文字辨識報告本次未再出現，建置 33 的真實失敗保留。

本機 Node 26／26、Swift 26／26、嚴格 Release、Analyze、三語四狀態 12 組及儲存庫 23／23 通過，測試機恢復關閉。產品介面與固定 macOS App 024 保持；I6、真機、簽署與發布門檻未完成。 [記錄](../../docs/ios-ci-audit-2026-09-17.zh.md)。
