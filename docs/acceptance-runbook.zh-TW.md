[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# 真機驗收執行手冊（供自動化 agent / computer-use 使用）

本手冊將 Chrome / Edge、macOS、Windows 與 iOS 驗收清單
從「供人閱讀的檢查表」補成「可以照著執行的操作步驟」，並補充 Android 伴生應用程式的簽署信封真實裝置路徑。
它提供每個案例的**準備、精確動作、可觀察判據、應擷取的證據**，以及最後**如何記錄結果並產生結構化證據**。
執行者可以是 Codex / computer-use 這類能驅動真實瀏覽器、桌面與裝置的 agent。

> 瀏覽器以 `acceptance-chrome.zh-TW.md` 為準；`acceptance-firefox.zh-TW.md` 只是首個 GA 排除說明。macOS 與 Windows 以各自清單為準，Android 以本手冊第 5 節與伴生應用程式 README 為準，iOS 以第 6 節及 `acceptance-ios.zh-TW.md` 為準。

---

## 0. 範圍與誠實前提（先讀）

- **首個 GA 的瀏覽器範圍只有 Chrome / Edge 共用的 Chromium 套件。** 儲存庫提供測試夾具與 39 條 Chromium E2E；正式 Chrome 與 Edge 仍須分別綁定候選 ZIP 做人工檢查。Firefox 僅為原始碼原型，不執行發佈驗收，也不產生 PASS。
- **桌面殼程式已接入原生觀測鏈路**：macOS 已接入 AXUIElement、ScreenCaptureKit 與 Vision OCR；
  Windows 已接入 UI Automation、GDI `BitBlt` 與 `Windows.Media.Ocr`。但「程式碼已接線」不等於
  「這台真機可用」：仍須依執行階段 capability、系統權限、實際事件/影格/OCR 輸出及證據逐項判定。這表示：
  - 原生觀測在目標真機上可用並產生預期證據 → 記為 `PASS (native)`。
  - 只使用殼程式的模擬注入驗證規則命中 → 只能記為 `PASS (sim)`，不能取代原生觀測、真機驗收或發佈證據。
  - 權限未授予、系統元件缺失或 capability 不可用 → 記為 `BLOCKED (具體原因)`，並保留能力報告。
  報告中必須呈現這項區分。無法判定就如實填寫 `BLOCKED`；這比虛假的 PASS 更有價值。

- **不要真的付款，也不要向真實支付/轉帳端點送出請求。** 夾具中的 fetch 全部送往本機同源假路徑，
  驗證的是「請求在送出**之前**是否被攔截」，不是請求本身。
- **驗收報告不是發佈證明。** 即使所有可執行案例 PASS，仍須另外滿足簽章、公證/商店審核、發佈套件身分、
  嚴格門禁與目標平台覆蓋要求。

---

## 1. 通用前置作業（一次性）

在儲存庫根目錄 `/root/ag`（或你的複製路徑）執行：

```bash
# 工具鏈：儲存庫釘住的 Rust 1.95.0、Node >= 18。wrapper 防止 Cargo 子程序誤用 Homebrew rustc。
make bootstrap-rust
./scripts/bootstrap-rust.sh -- cargo -Vv
./scripts/bootstrap-rust.sh -- rustc -vV
node --version

# 1) 封裝首個 GA 瀏覽器套件（Chrome / Edge 共用；無 Native Messaging）
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip

# 2) 離線門禁（必須先全綠，是真機驗收的必要非充分前提）
./scripts/bootstrap-rust.sh -- make capability-claims check-extension-gate coverage

# 3) 範圍保護：必須退出 64 且不產生 Firefox 套件
apps/extension-chromium/scripts/package-store.sh --firefox
```

啟動測試夾具伺服器（fetch 案例需要同源路徑解析，不能使用 file://）：

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# 夾具首頁：http://localhost:8000/
```

在儲存庫內準備證據工作目錄。它必須保持為候選提交之外的本機檔案；先移除敏感資訊，不要誤提交原始截圖、帳號或裝置識別資訊：

```bash
mkdir -p evidence/{chrome,edge,windows,macos,android,ios,ios-testflight}
```

---

## 2. 平台 A：瀏覽器擴充功能（首個 GA：Chrome / Edge）

### A.1 自動化

先執行 `make e2e-extension`。它在測試 Chromium 中完成 39 條機器判據，包括 block-only DOM、開放 Shadow DOM、靜態 DNR 正負例、舊頁面訊息、升級清理、變異風暴與 popup。必須保存 `eval/e2e-extension/out/report.json`，並保留報告中的真實 Chromium 版本。

### A.2 Chrome / Edge 正式版

1. 對待提交 ZIP 計算 SHA-256；Chrome 與 Edge 必須使用同一檔案。
2. 分別在全新 profile 的 `chrome://extensions` / `edge://extensions` 載入解壓內容。不要安裝 Native host；GA manifest 沒有該權限。
3. 重新啟動瀏覽器，確認 isolated 內容指令碼在新分頁注入，`payment_shape_block` 已啟用，popup 沒有 Native 控制。
4. 依 [Chromium 驗收清單](acceptance-chrome.zh-TW.md) 的 B1–B5 執行全新安裝、代表性阻擋與負向對照、原地升級、停用/解除安裝及回滾。Chrome 證據放在 `evidence/chrome/`，Edge 證據放在 `evidence/edge/`，不能互相重複使用。
5. Chrome 與 Edge 分開下結論；任何一列無法判定就寫 `BLOCKED`，測試 Chromium PASS 不能取代。

### A.3 Firefox

Firefox 不屬於首個 GA。不要載入 `manifest.firefox.json`、不要安裝 Firefox Native host、不要建立 Firefox PASS。`package-store.sh --firefox` 應退出 64 且不產生套件；詳見 [Firefox 排除說明](acceptance-firefox.zh-TW.md)。

---

## 3. 平台 B：Windows 桌面殼程式（first-ga-v1）

### B.1 建置與執行

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # 啟動系統匣殼程式（dev）
```

首個 GA 瀏覽器套件不安裝 Native Messaging。Windows `first-ga-v1` 必要項目是 W1–W6/W8–W11；W7 是不計入門禁的非 GA／舊版原型項目，不得為讓它 PASS 而向 GA Chromium 套件加回權限。

### B.2 逐項執行

判據以 `acceptance-windows.zh-TW.md` 的 `first-ga-v1` 必要項目為準，嚴格報告必須包含
`AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。**每一項都先記錄執行階段 capability 與權限狀態，再區分
「模擬」或「原生觀測」**（查看系統匣/日誌的能力標誌與實際事件/影格/OCR 輸出）：

- **判決鏈路類（W1 事後風險確認）**：使用殼程式的模擬注入觸發一次 `CRIT-001`（付款文案）。PASS 判據：彈出
  **事後風險確認**，明確說明外部動作已被觀察且無法撤銷；點「先不要，暫停任務」只暫停本次工作階段與後續觀測。
  稽核證據必須記錄 `effect=observed_only`、`external_action_blocked=false`，不得聲稱原動作未發生。
  記為 `PASS (sim)`，或在由原生觀測觸發時記為 `PASS (native)`。
- **原生觀測類（W2 UIA 取樹 / W3 GDI 擷取影格+隱寫 / W4 Windows.Media.Ocr 讀屏 / W5 overlay）**：
  原生 UIA / GDI / OCR 已接入殼程式，但必須在目標 Windows 真機上依 capability 和實際輸出判定。
  capability 不可用或權限/語言套件缺失 → `BLOCKED (具體原因)`。可用時：
  - **固件**：`make acceptance-fixtures` 產生到 `eval/acceptance-fixtures/generated/`（確定性，`MANIFEST.json`
    附 sha256；`crates/guard-vision/tests/验收固件.rs` 每次 `cargo test` 都在證明這些固件**真的觸發**它們聲稱的規則、
    對照圖零 finding；HTML 固件另在容器內的 Chromium 真渲染一遍再過探測器）。
  - W3：全螢幕顯示 `w3-stego-luma.png`（期望 OVL-008）與 `w3-stego-chroma.png`（期望 OVL-011）；再顯示
    `w3-control-clean.png`，**不得**觸發——這一步是防「逢圖必報」。
  - W4：Edge/Chrome 開啟 `w4-pixel-only-payment.html`——付款文字只畫在 canvas 像素中，UIA 樹沒有；OCR 讀出後
    期望 OVL-009。缺語言套件 → `BLOCKED (ocr language pack missing)`。
  - W5：開啟 `w5-self-drawn-overlay.html`（頁面自繪 3% 不透明度的指令文字，GDI 擷取得到；DevTools 刪除 `#sub`
    作對照）或全螢幕 `w5-self-drawn-overlay.png`；期望 OVL-006。
  - 缺辨識語言套件時 OCR 不執行，殼程式應提供**含原因**的能力報告（這本身就是 W6 的 PASS 判據）。
- **W6 能力探針**：開啟殼程式的能力面板/日誌，確認 UIA / 擷取 / OCR 各自「是否可用 + 原因字串」。
- **W7 原生訊息**：僅保留為非 GA／舊版可選記錄，建議寫 `N/A (non-GA)`；結構化門禁不要求、不計數、不綁定其證據。
- **W8–W10 trace 判據／結束後不擷取／狀態一致**：整場以 `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl`
  啟動殼程式（殼程式把 session_start/end、confirm_enqueued/shown/resolved/expired、每次觀測 tick、每次狀態變化附加成 JSONL）；
  跑完後執行 `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <稽核庫>`。六項：會話數一致、
  每張回執落在**展示過**的那筆紀錄上且允許／拒絕對得上（報告 P0-5 的形狀）、逾時回執為 timeout、會話結束後無觀測、
  「保護中」狀態有 ≤10 s 的心跳背書、過期確認不產生 approve 回執。任一 FAIL 結束碼 1，W8 即 FAIL。

---

## 4. 平台 C：macOS 桌面殼程式

```bash
cd apps/desktop-macos
npm install
npm run tauri dev
```

macOS 殼程式已接入 AXUIElement、ScreenCaptureKit 與 Vision OCR。先在目標真機授予並核驗 Accessibility /
Screen Recording 權限，再依 capability 報告、真實 AX 事件、擷取影格與 OCR 輸出判定原生觀測案例。
權限未授予或 capability 不可用時記為 `BLOCKED (具體原因)`；只用**模擬威脅注入**驗證判決鏈路時記為
`PASS (sim)`，不能取代 `PASS (native)`。案例清單見 `acceptance-macos.md` 的驗收案例表。首個 GA Chromium 套件不安裝 Native host。

案例 15–17 的判據來自**驗收 trace**：整場以 `AGENTGUARD_ACCEPTANCE_TRACE=evidence/macos/trace.jsonl` 啟動殼程式
（`AGENTGUARD_ACCEPTANCE_TRACE=… npm run tauri dev`），跑完 1–14、16、17 後執行
`target/release/guard-cli acceptance-trace-check --trace evidence/macos/trace.jsonl --audit-db <稽核庫>`，把整段輸出存為
`evidence/macos/15-trace-check.txt`。它對照 trace 與稽核庫做六項檢查（見 Windows W8 的說明），印出
`AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS` 才算 15 PASS；16（結束後不再擷取）與 17（狀態燈與事實一致）另附截圖與
`audit-report` 尾段。像素案例（5/5b 的 overlay、隱寫）可重用 `make acceptance-fixtures` 產生的固件——同一套 `guard-vision`。

---

## 5. 平台 D：Android 伴生應用程式

依 [Android 伴生應用程式 README](../apps/android-companion/README.zh-TW.md) 建置並安裝候選，在真實裝置上啟用通知與
AccessibilityService，透過 `adb reverse tcp:8788 tcp:8788` 連接桌面本機 API。把裝置顯示的 P-256 公鑰登錄到
`policies/adapter-registry.yaml`，重新啟動桌面 API 後觸發至少一個有明確預期判決的真實無障礙事件。

PASS 需要同時證明：事件來自目標真實裝置、HTTP body 的簽署信封由桌面端使用已登錄公鑰驗證成功、引擎判決符合預期，
且裝置收到對應風險結果。Debug 建置、JVM 單元測試、未登錄公鑰的中繼或只離線重播 JSON 都不能取代這條真實裝置 E2E；
任一環節無法判定時記為 `BLOCKED (具體原因)`。

**照著指令碼做**：`scripts/acceptance/android-e2e.sh`（需要 adb + 已授權的真機 + python3）把上面這段變成機器判據——
它安裝 APK、授予通知權限、啟用無障礙服務、`adb reverse`、以一次性令牌啟動桌面 API、把你從應用程式貼來的 P-256 公鑰寫成
`evidence/android/adapter-registry.yaml`、在手機瀏覽器開啟付款固件頁，然後核對：A1（安裝／授權／普通常駐工作階段通知 id 1001）、
A2（桌面 `/v1/status` 的 `adapter_ingress.verified` 增加且 `rejected` 不增加——`/v1/events` 現在把每份 body 的簽章結論
寫進回應、狀態與 stderr，以前這條在桌面側沒有任何可讀證據）、A3（稽核出現 `platform=android` 的 `CRIT-*` 判決）、
A4（裝置 prefs 的 `last_risk_json` 帶同一 rule_id 且引擎通知 id 1005 存在）、L（`am crash` 殺掉處理程序並明確重新開啟應用程式後處理程序回來、
`session_requested` 為 false、舊工作階段通知不復活、無障礙仍啟用且必須由使用者明確重開工作階段——報告 P0-3）、S（prefs 無明文 `relay_token`、有 `relay_token_enc`；
`files/events` ≤ 50 MiB——報告 P1-6）、T（targetSdk 36 行為回歸——報告 P2-2：從裝置 `dumpsys package` 讀已安裝 APK 的
targetSdk，裝置 API ≥ 35 且 A1–A4、L 全過才 PASS；API < 35 的裝置只能 BLOCKED——Android 14 上的通過不能冒充 15/16 的通過）。
每步印 PASS／FAIL／BLOCKED（原因），證據落 `evidence/android/`，最後一行
`AGENTGUARD_ANDROID_E2E=PASS|FAIL|BLOCKED device=real|emulator`——`device=emulator` 時只能記 `PASS (sim)`。
需要人做的只有三件事：貼公鑰、在應用程式填地址與令牌並開啟轉送、按「開始守護會話」（私鑰與令牌都在 Keystore，adb 碰不到，
這是設計使然）。指令碼的結論仍要由人轉錄進報告範本，`manual-acceptance android` 只認那份報告。

---

## 6. 平台 E：iOS Safari WebShield

先從同一凍結提交產生 Release archive，並以 Apple Distribution 身分簽署 App 與內嵌 Safari Web Extension；簽署產物須另外產生 `ios_codesign` 證據。接著嚴格依照 [iOS 真實裝置與 TestFlight 驗收](acceptance-ios.zh-TW.md) 在真實 iPhone/iPad 完成 I1–I6，並從同一 archive 上傳 TestFlight、完成 TF1–TF3。未簽署裝置建置、模擬器、Xcode Analyze 或 Swift/Node 單元測試只能作為開發證據，不能取代任何嚴格閘門。

I1–I6 的報告及逐項材料只放在 `evidence/ios/`，TF1–TF3 只放在 `evidence/ios-testflight/`；兩份報告與逐項證據不得互相重複使用。任何簽章、App Group/Keychain entitlement、真實裝置 Safari 開關、網站權限、升級或 TestFlight 身分無法核對時，記為 `BLOCKED (具體原因)`，不得產生 PASS marker。

---

## 7. 記錄結果 → 產生結構化證據

對每個案例：

1. **填寫獨立報告**：將 `docs/acceptance-report-template.zh-TW.md` 複製到對應
   `evidence/<平台>/report.md`，逐項寫入 `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` 與儲存庫相對
   證據路徑。作為嚴格閘門 artifact 時，Windows `first-ga-v1` 的 W1–W6/W8–W11、Android 的 A1–A4，以及
   macOS 的 1、2、3、4、5、5b、5c、6–18、iOS 的 I1–I6、TestFlight 的 TF1–TF3，以及 Chrome 與 Edge 各自的 B1–B5
   必須各自恰好一列；第二欄必須精確為 `PASS (native)`，
   第三欄必須指向對應 `evidence/<平台>/` 下真實存在的儲存庫相對非空普通檔案，且每個案例必須使用唯一證據路徑。引用不能是報告本身或目前證據 JSON 來源檔案，
   路徑不能包含符號連結或超出儲存庫；路徑只使用 `/`，每個元件必須符合可攜式 ASCII `[A-Za-z0-9._-]+`，不能包含空白或 shell glob／展開字元。
   `PASS (sim)`、FAIL、BLOCKED、N/A、缺失、重複、重複使用路徑或引用檔案不存在都不能冒充真實裝置 PASS。

2. **凍結候選提交**：如需讓狀態儀表板顯示進度，先更新清單並執行 `make dashboard`，提交這些變更，然後再從
   新的 `HEAD` 重跑驗收。開啟閘門前索引與所有非 ignored 檔案必須 clean；閘門執行期間不要修改程式碼或受版本控制的文件。
   結束時仍存在的 `HEAD` 或非 ignored 漂移會讓起訖快照不一致並失敗；起訖快照不防瞬時修改後還原的並行對手。
   ignored 的 `evidence/` 可繼續寫入。

3. **產生並填寫 JSON**：範本刻意不能直接通過。將 `command`、`timestamp`、`output`、`exit_code` 與驗收閉包
   SHA-256 換成實測值；驗收證據的頂層 `signer` 必須維持 `null`，複核時不要傳入 `--expected-signer`。
   `timestamp` 在校驗時須位於過去 30 天至未來 10 分鐘內，且不能早於 HEAD 提交時間
   （允許 10 分鐘時鐘誤差）。`command` 必須是實際成功執行的單段
   `guard-cli manual-acceptance <平台> <清單> <artifact.path> --repo-root .`。報告正文與 JSON `output`
   都必須有對應 kind 的一整行精確標記：`AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`、`AGENTGUARD_ACCEPTANCE_MACOS=PASS`、
   `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`、`AGENTGUARD_ACCEPTANCE_IOS=PASS`、`AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS`、
   `AGENTGUARD_ACCEPTANCE_CHROME=PASS` 或 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`；只有該 kind 全部必要原生案例 PASS 後才能寫入。驗收 artifact
   僅接受對應 `evidence/<平台>/` 下的 `.md` 普通檔案。`artifact.sha256` 使用
   `agentguard-acceptance-closure-sha256-v1`，綁定報告 bytes，以及依路徑排序的每個唯一逐項引用的相對路徑、長度與內容；
   它仍是未簽署自證，不能證明螢幕截圖或記錄來自其聲稱的裝置。
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
     evidence/macos/report.md --repo-root .
   # 成功時唯一輸出：AGENTGUARD_ACCEPTANCE_MACOS=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/macos/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_macos --commit "$commit" > evidence/macos/evidence.json

   # 將上面的精確 manual-acceptance 命令、marker 與 closure 摘要填入 JSON 後明確複核
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_macos --file evidence/macos/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **把 JSON 交給嚴格閘門**；環境變數指向 JSON 檔案，不能再指向目錄：
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=evidence/macos/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   其餘平台依相同步驟替換 kind、目錄與環境變數；Chrome 與 Edge、iOS 與 TestFlight 分別獨立。Firefox 遺留 kind 不被嚴格閘門讀取。欄位與十二類變數的完整說明見
   [結構化發佈證據](release-evidence.zh-TW.md)。目錄、未填寫範本、舊提交報告或只有關鍵字的任意檔案都會被拒絕。
   嚴格閘門通過後將本機證據唯讀封存到受控位置，不要把含敏感資訊的原始證據預設推送到 GitHub。

---

## 8. 判定小抄（什麼算 PASS）

- **瀏覽器 DOM 阻擋（B3）**：動作在**發生前**被阻擋；資訊提示只有關閉鍵，關閉後仍無導覽、請求或頁面處理常式副作用。出現網頁內放行或重播 = **FAIL**。
- **瀏覽器網路硬擋（B3）**：聲明範圍內請求在 Network 顯示 block、伺服器零請求；對應負向對照必須到達。
- **觀測類（W2 等）**：出現對應 finding / 事件，且**對照的正常內容不誤報**。
- 任何「我無法判斷/環境未接上」的情況：記為 `BLOCKED` 並寫明原因，**不要猜 PASS**。這份清單的價值在於
  它區分了「驗過了」和「看起來應該可以」。
