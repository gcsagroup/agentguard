[簡體中文](acceptance-report-2026-09-01.md) | [繁體中文](acceptance-report-2026-09-01.zh-TW.md) | [English](acceptance-report-2026-09-01.en.md)

# AgentGuard 真機驗收報告（2026-09-01）

> 結論：目前整合候選的自動化、套件一致性與 macOS 有限原生 smoke 均取得進展，但尚未在同一個不可變提交上完成瀏覽器、Windows、macOS 與 Android 的發佈級真機端到端驗收。生產發佈仍為 **No-Go**。

本報告依照 [真機驗收執行手冊](acceptance-runbook.zh-TW.md) 與 [報告範本](acceptance-report-template.zh-TW.md) 填寫。空白項目均已改為明確結果；無法從目前候選取得足夠證據的項目記為 `BLOCKED`，不猜測 PASS。

## 1. 原始碼與證據邊界

本報告同時引用兩層證據，兩者不能混用：

1. **2026-08-31 真機／跨平台基線**：精確提交 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`，詳情見外層報告 `/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`。它包含當時的 Windows 11、macOS、Android 模擬器、iOS 臨時 harness 與 Chromium 限定範圍實測。
2. **2026-09-01 目前整合候選**：以發佈基線 `a7956314fba8340e905353448a53bb1f24f7083c` 為第一父提交，合入功能基線 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4`，並包含本報告記錄的修復、D 品牌與三語文件。最終不可變身分以「包含本報告的 `main` 提交」為準。

因此，`bd7bb2f` 的真機結果只能作為歷史基線，**不能自動繼承為目前整合候選的 PASS**。本輪主控台及 Computer Use 結果沒有歸檔至獨立證據目錄；下文以命令、計數及操作觀察記錄，屬於整合驗證紀錄，不是可獨立複核的發佈證據。

## 2. 環境資訊

| 項目 | 值 |
|---|---|
| 執行日期 | 2026-09-01（Asia/Shanghai） |
| 執行者 | Codex 自動化；Browser／Computer Use 輔助實際流程檢查 |
| 目前宿主 | macOS 26.6.2（Build 25G83），Apple Silicon arm64 |
| 8 月 31 日真機基線 | `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` |
| 目前整合候選 | 第一父提交 `a7956314fba8340e905353448a53bb1f24f7083c` + 功能基線 `bd7bb2f96c21518f601ecdc49603b074bf4d97a4` + 本報告所列整合；最終身分見包含本報告的 `main` 提交 |
| Rust | `rustc 1.97.1`、`cargo 1.97.1`（`rustup stable`） |
| Node / npm | Node `v25.2.1`、npm `11.6.2` |
| 瀏覽器 | Chrome `152.0.7977.65`、Firefox `153.0.1`；Edge 未安裝 |
| 離線門禁是否全綠 | **否（發佈意義）**：自動門禁 13/13、離線 acceptance 104/104，但 8 項憑據／真機門禁未驗證，嚴格發佈門禁不通過 |
| 工具鏈備註 | 預設 Homebrew Rust 1.91.1 曾因 LLVM 動態函式庫不相容失敗；改用 `rustup stable` 後通過，按環境問題記錄，不算產品 PASS 或 FAIL |

## 3. 目前整合候選的自動化、建置與有限實測

| 範圍 | 命令／操作 | 結果 | 證據等級與邊界 |
|---|---|---|---|
| 發佈軟門禁 | `bash scripts/release-gate.sh` | 13/13 自動項目通過，0 fail，8 unverified | 本輪主控台，未獨立歸檔；soft 模式不是嚴格發佈通過 |
| 離線驗收 | `make acceptance` | 104/104 | 本輪主控台，未獨立歸檔；離線情境不是平台 E2E |
| 擴充功能 gate | `node apps/extension-chromium/scripts/gate.test.mjs` | 20/20 | 純邏輯與原始碼不變量，不會驅動真實擴充功能 |
| click→submit 接線 | `node apps/extension-chromium/scripts/content-event.test.mjs` | 2/2 | 最小 DOM 事件鏈證明一次批准只確認／送出一次且權杖不外洩；不等於真瀏覽器 E2E |
| 跨瀏覽器 manifest | `node apps/extension-chromium/scripts/manifests.test.mjs` | 8/8 | 結構一致性，不證明 Firefox／Chrome 實際執行 |
| 擴充功能三語詞表 | `node apps/extension-chromium/scripts/strings.test.mjs` | 8/8 | 詞表完整性，不證明 UI 真機表現 |
| macOS adapter | `rustup run stable cargo test -p mac-adapter` | 10/10 | AX 推送合併器與橋接結構自動化 |
| macOS Tauri | `rustup run stable cargo test --manifest-path apps/desktop-macos/src-tauri/Cargo.toml` | 7/7 | 包裝、產品接線與舊明文稽核資料庫遷移測試；不是權限／第三方 App E2E |
| Windows Tauri | `rustup run stable cargo test --manifest-path apps/desktop-windows/src-tauri/Cargo.toml --no-run` | 編譯完成 | 目前 macOS 宿主上的 no-run 編譯；未啟動 Windows EXE |
| macOS release build | `apps/desktop-macos/scripts/build-release.sh` | 建置成功；`codesign --verify --deep --strict` 通過 | 僅 ad-hoc：`TeamIdentifier=not set`；`spctl` 拒絕，未公證，不可分發 |
| 覆蓋矩陣 | 目前產生的 `eval/coverage-matrix.md` | 30 個攻擊面：13 covered、16 partial、1 uncovered；107 個已聲明攻擊情境及 35 個良性控制 | 儲存庫產生的覆蓋證據；不能取代真機驗收 |
| Chromium／Firefox 套件 | `package-store.sh`、`--firefox`、`unzip -t` | 兩份 ZIP 均有 27 個檔案、包含 D 圖示、可完整解壓，且目前套件內容與工作樹一致 | 套件一致性通過；不等於已在真瀏覽器安裝或完成 F1–F8 |
| macOS 有限原生 smoke | 透過 Computer Use 啟動目前 ad-hoc App、開始工作階段與 AX 即時觀測 | UI 顯示 AX／Capture `true`、AX push 已開、`live AX ingested · 1 decision(s)`；隨後已關閉觀測並結束工作階段 | 實際產品路徑 smoke，但沒有獨立截圖／主控台歸檔，也未觸發完整第三方 App 清單情境；不得列為清單 PASS |
| Browser UI 輔助流程 | Browser 工具檢查本機引導、確認層與 popup 流程 | 人工流程可操作 | 無截圖／主控台歸檔，且不是 MV3 擴充功能上下文；只作輔助檢查 |

目前 macOS App 可執行檔 SHA-256 為 `30425194afe8d4679b74d95e8b1fd2459e3d0f04e050cbe62b037de8fb5cbb11`；App 內 D 圖示 SHA-256 為 `9a7732ab9cc79ff50341b5d205f1b03755698315d07f75b9713847780a598a10`。這些值綁定目前本機 ad-hoc 產物，不等於 Developer ID、公證或最終提交產物身分。

目前啟動路徑會保留既有明文稽核資料庫，改用相鄰的 SQLCipher 資料庫，避免以加密金鑰開啟舊明文資料庫所造成的啟動崩潰，且不覆寫 legacy 檔案。

擴充功能套件初次複核曾發現陳舊內容：Firefox 套件仍使用 `service_worker`，`background.js`／`content.js` 也與工作樹不同。2026-09-01 16:39（Asia/Shanghai）重新打包後已再次複核：

| 套件 | SHA-256 | 複核結果 |
|---|---|---|
| `/Users/lazy/Projects/agent-guard/_push/agentguard-extension.zip` | `443e141834de89587fc0daf7a5470e2edee8a15b6e18c9d3db2368396dea2f51` | 27 個檔案，`unzip -t` 通過；套件 `background.js`／`content.js` 與工作樹雜湊一致 |
| `/Users/lazy/Projects/agent-guard/_push/agentguard-extension-firefox.zip` | `f9309f118ad0c22d0d86b2e4c657141f93a505fcdbdfc032756d215c1c934bb6` | 27 個檔案，`unzip -t` 通過；manifest 版本 `1.0.0.1`，並設為 `background.scripts = ["background.js"]`、`background.type = "module"`；套件 JS 與工作樹雜湊一致 |

這次重打包只關閉了「陳舊套件」問題；因尚未安裝至真 Chrome／Firefox，不能用來關閉任何 F1–F8 真機門禁。

## 4. 瀏覽器擴充功能（Chrome／Firefox／Edge）

目前環境沒有為整合候選安裝擴充功能或 Native Messaging host，也沒有歸檔 DevTools Network、popup、稽核資料庫或 DNR 動態規則證據。Chrome／Firefox ZIP 的完整性檢查不能取代 F1–F8；Edge 未安裝。

| 案例 | Chrome 152 | Firefox 153 | Edge | 證據與備註 |
|---|---|---|---|---|
| F1 隱藏注入 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | 掃描邏輯有自動測試；未在已安裝擴充功能的 popup 中觀察 finding |
| F2 付款 CTA 執行前攔截 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | gate 自動測試通過；真實取消／允許副作用時間線未複測 |
| F3 陷阱 + PII 送出攔截 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | `requestSubmit` 與單次批准有模擬 DOM 事件鏈測試；真實 URL／送出行為未複測 |
| F4 付款形狀 fetch／XHR 攔截 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | 分類邏輯有測試；無真實 Network「拒絕時零請求」證據 |
| F5 唯讀方法不攔截 | `BLOCKED (real-extension-not-run)` | `BLOCKED (real-firefox-not-run)` | `BLOCKED (edge-not-installed)` | GET／HEAD 與一般 POST 反例有測試；無真實瀏覽器 Network 證據 |
| F6 惡意網域網路層硬攔截 | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (no-live-DNR-evidence)` | `BLOCKED (edge-not-installed)` | DNR 建構、清單與 provenance 有測試；無 `ERR_BLOCKED_BY_CLIENT` 證據 |
| F7 原生訊息握手 | `BLOCKED (native-host-not-installed)` | `BLOCKED (gecko-id-not-tested)` | `BLOCKED (edge-not-installed)` | 目前候選未安裝 host，未產生簽章稽核列 |
| F8 DNR 配額 | `BLOCKED (quota-not-measured)` | `BLOCKED (firefox-quota-not-measured)` | `BLOCKED (edge-not-installed)` | 純邏輯有清單上限；瀏覽器實際動態規則配額未測 |

Firefox `background.scripts` 修復與重打包內容已通過 8/8 manifest 自動檢查及雜湊一致性複核，但尚未在真 Firefox 啟動 event page，因此不得據此宣告 Firefox 可發佈。

## 5. Windows 桌面殼程式

8 月 31 日 `bd7bb2f` 基線在 Windows 11 Pro build 26200 上真實啟動時，因 `RPC_E_CHANGED_MODE` 在主視窗出現前退出，並發現 Windows verbatim 路徑問題。目前整合候選只完成 Tauri no-run 編譯，沒有重新傳至 Windows 真機啟動；舊失敗不能直接斷言目前仍存在，但同樣不能視為已修復。

| 案例 | 目前候選結果 | 證據 | 備註 |
|---|---|---|---|
| W1 阻斷模態 | `BLOCKED (current-candidate-not-run-on-Windows)` | 8/31 外層報告只涵蓋 `bd7bb2f` | 目前候選未顯示 Windows 主視窗 |
| W2 UIA 取樹 | `BLOCKED (no-current-UIA-evidence)` | 同上 | no-run 編譯不會產生 UiTreeDelta |
| W3 GDI 擷取影格 + 隱寫 | `BLOCKED (no-current-GDI-evidence)` | 同上 | 無目前影格／規則證據 |
| W4 Windows.Media.Ocr 讀屏 | `BLOCKED (no-current-OCR-evidence)` | 同上 | 無語言套件／capability／辨識輸出 |
| W5 overlay | `BLOCKED (no-current-overlay-evidence)` | 同上 | 未執行目標視窗 |
| W6 能力探針 | `BLOCKED (no-current-capability-report)` | 同上 | 未取得目前 UIA／GDI／OCR 原因字串 |
| W7 原生訊息 | `BLOCKED (native-host-not-tested-on-Windows)` | 同上 | 未安裝登錄檔 manifest，未寫入簽章稽核 |

## 6. macOS 桌面殼程式

目前候選已完成 mac-adapter 10/10、Tauri 7/7、ad-hoc release build，以及一次有限原生產品路徑 smoke。這次 smoke 證明 App 能讀到目前 AX／Capture capability、啟動 AX push 並擷取一次 live AX 判決，之後也已關閉觀測並結束工作階段；但它沒有歸檔獨立證據，也沒有逐項觸發真實第三方 App 的付款、PII、overlay、惡意網域、SCK/OCR 或工作階段隔離情境。因此，下列完整真機清單仍不能繼承 8 月 31 日 `bd7bb2f` 的結果，也不能因單次 smoke 而標示 PASS。

| 案例 | 目前候選結果 | 證據 | 備註 |
|---|---|---|---|
| 1 支付確認 | `BLOCKED (current-native-E2E-not-run)` | 8/31 基線只有 `bd7bb2f` 模擬注入 | 未證明目前候選的真實頁面事件在副作用前受到控制 |
| 2 轉帳確認 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未觸發真實 transfer 文案 |
| 3 可選 PII | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未取得真實 FM／TR 事件 |
| 4 Trap 表單 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未取得真實 trap 事件 |
| 5 透明 overlay | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未取得 AX／SCK overlay 對照 |
| 5b 圓角不可見區 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未觸發 `[AG_INVISIBLE_ZONE]` |
| 5c 執行前 UI 變化 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未取得兩影格／兩次 AX 變化證據 |
| 6 Intel 注入 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未觸發真實第三方 App 注入文字 |
| 7 惡意網域 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未執行真實導覽鏈 |
| 8 Netmon 外洩 | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未產生目前 netmon flow |
| 9 瀏覽器惡意 URL | `BLOCKED (extension-host-not-installed)` | 無目前歸檔 | Chrome 擴充功能與桌面 ingest 未聯調 |
| 10 工作階段暫停 | `BLOCKED (current-session-E2E-not-run)` | 8/31 `bd7bb2f` 模擬曾形成短鏈 | 目前候選未複測 deny 後第二事件與工作階段隔離 |
| 11 SCK 探針 | `BLOCKED (case-evidence-not-archived)` | 有限 smoke 顯示 Capture `true`，但無獨立終端／截圖 | 未執行並歸檔手冊指定的 `sck-probe` 輸出與影格結果 |
| 12 AX 探針 | `BLOCKED (case-evidence-not-archived)` | 有限 smoke 顯示 AX `true`，但無獨立終端／截圖 | 未執行並歸檔手冊指定的 `ax-probe` 輸出 |
| 13 真機 AX | `BLOCKED (insufficient-case-evidence)` | 有限 smoke 觀察到 AX push 與 1 個 live decision | 尚缺可複核的 UiTreeDelta、規則、延遲、前台切換及表單 FM／TR 證據 |
| 14 UI revalidate | `BLOCKED (current-native-E2E-not-run)` | 無目前歸檔 | 未取得真實連續 UI 變化與確認結果 |

## 7. Android 與 iOS 補充狀態

範本沒有 Android／iOS 逐項表，本報告補充其發佈邊界：

| 平台 | 8 月 31 日基線 | 目前整合候選 | 結論 |
|---|---|---|---|
| Android | `bd7bb2f` 在 Android 16 模擬器完成 Debug／Release JVM 31/31、Debug APK 安裝及前台服務啟停；Accessibility 未啟用，不是防護 E2E | 本輪未在實體機或模擬器重跑目前候選 | `BLOCKED (current-Android-E2E-and-release-signing-missing)` |
| iOS | `bd7bb2f` 只有臨時 SwiftUI harness 1/1；儲存庫沒有完整 Xcode 產品工程 | 本輪未形成目前候選的 iOS 產品或 archive | **No-Go**；臨時 harness 不等於產品 |

## 8. 提交前已修復，但仍需真機複測的項目

| 項目 | 目前原始碼修復 | 目前自動化／有限 smoke | 仍缺的證據 |
|---|---|---|---|
| Firefox 背景入口 | 從 Chromium `service_worker` 語意改為 Firefox `background.scripts` event page | manifest 8/8；重打包 manifest 與工作樹一致 | 真 Firefox 啟動、event page 生命週期與 F1–F8 |
| blocklist provenance | 剪枝、持久化、解除與 popup 讀取保留 `rule_id` 來源 | gate 20/20 | 真 DNR 安裝、service worker 恢復與 popup 溯源 |
| 表單允許一次 | 使用 `requestSubmit(e.submitter)` 保留驗證、`formaction`／`formmethod`／`name`／`value`；click→submit 共用一次性批准 | gate 20/20 原始碼不變量 + content-event 2/2 事件鏈 | 真 Chrome／Firefox 的取消、允許與單次重播 |
| macOS AXObserver 產品接線 | 桌面端啟動、50ms 驅動、合併擷取、停用／退出卸載 observer，並依前台 PID 重新綁定 | mac-adapter 10/10、Tauri 7/7、release build；有限真機 smoke 觀察到 1 個 live decision | 可複核的真實回呼、150ms／800ms 時序、前台切換、完整清單與工作階段結束證據 |

上述四項是目前候選相對 8 月 31 日基線的重要變更，但「修好程式碼 + 自動化通過」不等於相應平台已經真機 PASS；macOS 單次有限 smoke 也不替代完整清單。

另有一項**尚未修復的安全邊界**：MAIN world 與隔離世界的 `window.postMessage` 決策／scope 通道可被
頁面觀察及偽造，且下發的 `scope_hosts` 會對頁面可見。因此 E2.1／E9 只能作為協作頁面上的盡力而為聯鎖，
不能描述為對抗惡意頁面的強制邊界；發佈前需設計經過認證且不暴露整表的通道，或收窄相應產品聲明。

## 9. 彙總

| 面向 | PASS | PASS (sim) | FAIL | BLOCKED | N/A |
|---|---:|---:|---:|---:|---:|
| 瀏覽器（Chrome + Firefox + Edge，F1–F8） | 0 | 0 | 0 | 24 | 0 |
| Windows（W1–W7） | 0 | 0 | 0 | 7 | 0 |
| macOS（清單 16 項） | 0 | 0 | 0 | 16 | 0 |
| Android 目前候選平台門禁 | 0 | 0 | 0 | 1 | 0 |

本表只統計**目前整合候選**的完整真機清單。自動化通過數及有限 smoke 另列於第 3 節；8 月 31 日 `bd7bb2f` 的歷史 PASS／FAIL 不併入目前統計。

**整體結論：自動化、套件一致性及 macOS 有限原生 smoke 可支持繼續整合，生產發佈仍為 No-Go。**

### 目前候選未標示 FAIL 的說明

目前候選沒有任何真機案例標示 FAIL，是因為這些案例尚未在目前候選上執行至可判定狀態，全部依手冊記為 `BLOCKED`；這絕不代表全平台通過。8 月 31 日 `bd7bb2f` 基線的 Windows 啟動失敗仍保留在外層報告中，必須以最終提交複測後才能關閉或重新判定 FAIL。

### 8 項嚴格發佈門禁仍未驗證

1. macOS Developer ID 程式碼簽章；
2. macOS 公證與 staple；
3. Windows Authenticode 簽章；
4. Android release 簽章（非 debug keystore）；
5. macOS 完整真機端到端驗收；
6. Android 啟用無障礙服務後的實體機端到端驗收；
7. Firefox 128+ 的 F1–F8 真機驗收；
8. Windows 的 W1–W7 真機驗收。

此外，Chrome 與 Edge 的目前候選真實擴充功能流程、擴充功能 Native Host 安裝／解除安裝、商店套件身分及升級／回復也沒有形成發佈證據。

## 10. 發佈前複測條件

1. 先把整合候選提交為不可變 SHA，確認工作樹乾淨，並以該 SHA 重新產生 macOS App、Chromium ZIP 與 Firefox ZIP；再次驗證套件內檔案雜湊與工作樹一致。
2. 歸檔每條自動化命令、退出碼、工具鏈與產物 SHA；由嚴格門禁讀取結構化且綁定目前提交的證據。
3. 在真實 Chrome、Firefox 與 Edge 安裝最終套件及 Native Host，逐項執行 F1–F8，歸檔 popup、Network、DNR 與簽章稽核證據。
4. 在真實 Windows 上以標準工具鏈建置並啟動最終提交，完成 W1–W7、簽章安裝套件及升級／解除安裝。
5. 在 macOS 以最終 App 完成清單 1–14、AXObserver 時序、前台切換、SCK／OCR、工作階段結束與稽核驗簽；再完成 Developer ID、公證與 staple。
6. 在 Android 實體機啟用 AgentGuard AccessibilityService，完成「觀察 → 判決 → 使用者確認 → 簽章信封／稽核」，並驗證 release 簽章、權限撤銷及升級／解除安裝。

只有上述證據綁定至同一個最終提交及相應發佈產物後，才能重新評估 Go／No-Go。

## 11. 證據索引

- 8 月 31 日跨平台基線報告：`/Users/lazy/Projects/agent-guard/AGENTGUARD-REAL-TEST-REPORT-2026-08-31.md`
- 本次執行依據：[真機驗收執行手冊](acceptance-runbook.zh-TW.md)
- 填寫結構依據：[真機驗收報告範本](acceptance-report-template.zh-TW.md)
- 儲存庫狀態快照：[狀態儀表板](status-dashboard.html)（最終提交後須重新產生）
- 目前 macOS ad-hoc App：`apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app`
- 目前 Chromium ZIP：`/Users/lazy/Projects/agent-guard/_push/agentguard-extension.zip`
- 目前 Firefox ZIP：`/Users/lazy/Projects/agent-guard/_push/agentguard-extension-firefox.zip`

> 本報告記錄提交前驗收狀態，不單獨構成發佈證明；簽章、公證／商店審核、發佈套件身分、嚴格門禁與平台覆蓋仍須另行核驗。
