[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# 真機驗收執行手冊（供自動化 agent / computer-use 使用）

本手冊將三份驗收清單（`acceptance-firefox.md` / `acceptance-macos.md` / `acceptance-windows.md`）
從「供人閱讀的檢查表」補成「可以照著執行的操作步驟」，並補充 Android 伴生應用程式的簽署信封真實裝置路徑。
它提供每個案例的**準備、精確動作、可觀察判據、應擷取的證據**，以及最後**如何記錄結果並產生結構化證據**。
執行者可以是 Codex / computer-use 這類能驅動真實瀏覽器、桌面與裝置的 agent。

> 瀏覽器、macOS 與 Windows 的「預期」以三份 `acceptance-*.md` 為準；Android 以本手冊第 5 節與伴生應用程式 README 為準。

---

## 0. 範圍與誠實前提（先讀）

- **瀏覽器擴充功能路徑（Firefox / Chrome / Edge）可以完整執行與判定**，而且本儲存庫提供測試夾具
  （`eval/acceptance-fixtures/`），因此 F1–F8 是 turnkey 的。
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
# 工具鏈：Rust（edition 所需的較新版本即可）、Node ≥ 18
cargo --version && node --version

# 1) 建置原生訊息 host（瀏覽器擴充功能要連線至它）
cargo build -p guard-nm-host           # 產物：target/debug/guard-nm-host

# 2) 打包擴充功能（Chrome/Edge 使用預設；Firefox 使用 --firefox）
apps/extension-chromium/scripts/package-store.sh                 # dist/agentguard-extension.zip
apps/extension-chromium/scripts/package-store.sh --firefox       # dist/agentguard-extension-firefox.zip

# 3) 離線門禁（必須先全綠，是真機驗收的必要非充分前提）
make capability-claims && make check-extension-gate && make coverage
```

啟動測試夾具伺服器（fetch 案例需要同源路徑解析，不能使用 file://）：

```bash
cd eval/acceptance-fixtures && python3 -m http.server 8000
# 夾具首頁：http://localhost:8000/
```

在儲存庫內準備證據工作目錄。它必須保持為候選提交之外的本機檔案；先移除敏感資訊，不要誤提交原始截圖、帳號或裝置識別資訊：

```bash
mkdir -p evidence/{firefox,windows,macos,android}
```

---

## 2. 平台 A：瀏覽器擴充功能（Firefox / Chrome / Edge）

### A.1 安裝

**Firefox（≥128）**
1. 安裝原生訊息 host：`apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev`
2. `about:debugging#/runtime/this-firefox` →「暫時載入附加元件」→ 選擇 `apps/extension-chromium/manifest.firefox.json`
   （或解壓縮 `dist/agentguard-extension-firefox.zip` 後選擇其中的 `manifest.json`）。
3. 記下分配的擴充功能 ID（應為 `agentguard@agentguard.dev`）。

**Chrome / Edge**
1. `chrome://extensions`（或 `edge://extensions`）→ 開啟「開發人員模式」→「載入未封裝項目」→ 選擇
   `apps/extension-chromium/`（或解壓縮後的 dist 目錄）。複製產生的擴充功能 ID。
2. 安裝 host：`install-host.sh <extension-id>`（Edge 使用 `--browser edge <extension-id>`）。

安裝後**重新啟動瀏覽器一次**，確保內容指令碼（包含 `world:"MAIN"` 的 guard-page.js）注入新分頁。

### A.2 逐項執行（F1–F8）

每一項都先**開啟 DevTools**（Console + Network 面板），再執行操作，最後依「判據」擷取畫面。

| 案例 | 開啟 / 動作 | PASS 判據（可觀察） | 證據 |
|---|---|---|---|
| **F1** 隱藏注入 | 開啟 `http://localhost:8000/injection.html`；點擴充功能圖示查看 popup「最近」 | popup 最近清單出現一筆 `invisible_injection`/`prompt_injection`；若已安裝 host，host stderr / 稽核中有對應事件 | popup 螢幕截圖 |
| **F2** 付款 CTA 執行前攔截 | 開啟 `payment-cta.html`，點「Confirm Payment」 | 點擊後**先**彈出 AgentGuard 確認層（標題使用自然語言，例如「這一步要付款了」）；點**「先不要」**→ 頁面**不**顯示「已確認支付」；再次點擊並選**「允許這一次」**→ 此時才顯示 | 兩張螢幕截圖（取消狀態 / 允許狀態） |
| **F3** 陷阱+PII 送出攔截 | 開啟 `trap-pii.html`，點「提交」 | 彈出確認層；**「先不要」**→ URL 不變、沒有 `?phone=`；**「允許這一次」**→ URL 出現 `?phone=13800000000` | 兩張螢幕截圖（URL 列可見） |
| **F4** 付款形狀 fetch 攔截 | 開啟 `fetch-gate.html`，點「POST /pay/checkout」 | 彈出確認層；**「先不要」**→ Network 面板**沒有** `/pay/checkout` 請求、日誌顯示「被拒絕/未送出」；**「允許這一次」**→ 出現該請求（404/501 均可） | Network 面板螢幕截圖（取消狀態） |
| **F5** 唯讀方法不攔截 | 在同一頁點「GET /pay/status」和「POST /api/search」 | **不**彈出確認層；請求直接送出（Network 中出現） | Network 面板螢幕截圖 |
| **F6** 惡意網域網路層硬攔截 | 需要引擎將 `evil.example` 判為惡意網域（內建情報基線包含它）。若走 host：建構一次 url 為 `https://evil.example/x` 的瀏覽器事件（或直接在網址列造訪 `http://evil.example/`）後，再用**新請求**造訪該主機 | 該主機的請求被 declarativeNetRequest 在網路層 block（Network 面板顯示 blocked / net::ERR_BLOCKED_BY_CLIENT）；popup 攔截清單出現 `evil.example · 惡意網域`，溯源顯示 `INTEL-DOMAIN` | popup 清單螢幕截圖 + Network 螢幕截圖 |
| **F7** 原生訊息握手 | 確認 host 已安裝；觸發任意 finding（F1–F3） | host 接受呼叫端（未因 origin 驗證拒絕啟動；stderr 沒有 "refuse origin"）；判決進入簽章稽核庫（`AGENTGUARD_AUDIT_DB` 指向的資料庫有新資料列） | host stderr 螢幕截圖 / 稽核資料列 |
| **F8** DNR 配額 | 觸發數個 F6 類攔截後，在 DevTools 主控台執行 `chrome.declarativeNetRequest.getDynamicRules().then(r=>console.log(r.length))` | 規則數 ≤ 瀏覽器動態規則配額上限，安裝規則不報錯 | 主控台輸出螢幕截圖 |

> **F6 說明**：瀏覽器擴充功能目前回報的是 `ui_text` 事件；惡意網域判決（`INTEL-DOMAIN`）對**任何帶 url 的
> 事件**成立，因此走 host 路徑可以觸發。若你的環境未接上 host 的惡意網域判決回流，記為 `BLOCKED (no host verdict)`。
> 越界（`SCOPE-HOST`/E9 本機允許表門）需要工作階段宣告 `scope.hosts`——瀏覽器路徑預設沒有，記為 `N/A`，除非
> 你明確設定了帶 `scope.hosts` 的任務工作階段。

---

## 3. 平台 B：Windows 桌面殼程式（W1–W7）

### B.1 建置與執行

```bash
cd apps/desktop-windows
npm install
npm run tauri dev        # 啟動系統匣殼程式（dev）
```

原生訊息 host（若驗 W7 瀏覽器路徑）：將 `com.agentguard.native.json` 寫入登錄檔
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`，`path` 指向
`target\debug\guard-nm-host.exe`，`allowed_origins` 填入擴充功能 origin。

### B.2 逐項執行

判據以 `acceptance-windows.md` 的 W1–W7 為準。**每一項都先記錄執行階段 capability 與權限狀態，再區分
「模擬」或「原生觀測」**（查看系統匣/日誌的能力標誌與實際事件/影格/OCR 輸出）：

- **判決鏈路類（W1 阻斷模態）**：使用殼程式的模擬注入觸發一次 `CRIT-001`（付款文案）。PASS 判據：彈出
  **阻斷式模態**，點「先不要，暫停任務」後動作不放行。記為 `PASS (sim)`，或在由原生觀測觸發時記為 `PASS (native)`。
- **原生觀測類（W2 UIA 取樹 / W3 GDI 擷取影格+隱寫 / W4 Windows.Media.Ocr 讀屏 / W5 overlay）**：
  原生 UIA / GDI / OCR 已接入殼程式，但必須在目標 Windows 真機上依 capability 和實際輸出判定。
  capability 不可用或權限/語言套件缺失 → `BLOCKED (具體原因)`。可用時：
  - W3 需要一張含隱寫的影像——使用 `make frame-digest-demo` 或 guard-vision 的隱寫編碼器產生一張，
    顯示在目標視窗中，查看是否被擷取。
  - W4 需要一段「只存在於像素中」的付款文字影像——用相同方法產生/擷取一張寫著 "Complete purchase" 的點陣圖並顯示。
  - 缺辨識語言套件時 OCR 不執行，殼程式應提供**含原因**的能力報告（這本身就是 W6 的 PASS 判據）。
- **W6 能力探針**：開啟殼程式的能力面板/日誌，確認 UIA / 擷取 / OCR 各自「是否可用 + 原因字串」。
- **W7 原生訊息**：同 F7，只是 host 透過登錄檔登記。

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
`PASS (sim)`，不能取代 `PASS (native)`。案例清單見 `acceptance-macos.md` 的驗收案例表。host 安裝方法：
`install-host.sh --browser chrome <id>`（macOS 路徑見指令碼）。

---

## 5. 平台 D：Android 伴生應用程式

依 [Android 伴生應用程式 README](../apps/android-companion/README.zh-TW.md) 建置並安裝候選，在真實裝置上啟用通知與
AccessibilityService，透過 `adb reverse tcp:8788 tcp:8788` 連接桌面本機 API。把裝置顯示的 P-256 公鑰登錄到
`policies/adapter-registry.yaml`，重新啟動桌面 API 後觸發至少一個有明確預期判決的真實無障礙事件。

PASS 需要同時證明：事件來自目標真實裝置、HTTP body 的簽署信封由桌面端使用已登錄公鑰驗證成功、引擎判決符合預期，
且裝置收到對應風險結果。Debug 建置、JVM 單元測試、未登錄公鑰的中繼或只離線重播 JSON 都不能取代這條真實裝置 E2E；
任一環節無法判定時記為 `BLOCKED (具體原因)`。

---

## 6. 記錄結果 → 產生結構化證據

對每個案例：

1. **填寫獨立報告**：將 `docs/acceptance-report-template.zh-TW.md` 複製到對應
   `evidence/<平台>/report.md`，逐項寫入 `PASS (native)` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)` 與儲存庫相對
   證據路徑。作為嚴格閘門 artifact 時，Firefox 的 F1–F8、Windows 的 W1–W7、Android 的 A1–A4，以及
   macOS 的 1、2、3、4、5、5b、5c、6–14 必須各自恰好一列；第二欄必須精確為 `PASS (native)`，
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
   `guard-cli manual-acceptance <平台> <清單> <artifact.path> --repo-root .`（依下方建置後，實際命令為
   `target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root .`）。報告正文與 JSON `output`
   都必須有一整行精確標記 `AGENTGUARD_ACCEPTANCE_FIREFOX=PASS`、
   `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`、`AGENTGUARD_ACCEPTANCE_MACOS=PASS` 或
   `AGENTGUARD_ACCEPTANCE_ANDROID=PASS`，而且只有全部必要原生案例 PASS 後才能寫入該標記。驗收 artifact
   僅接受對應 `evidence/<平台>/` 下的 `.md` 普通檔案。`artifact.sha256` 使用
   `agentguard-acceptance-closure-sha256-v1`，綁定報告 bytes，以及依路徑排序的每個唯一逐項引用的相對路徑、長度與內容；
   它仍是未簽署自證，不能證明螢幕截圖或記錄來自其聲稱的裝置。
   ```bash
   commit="$(git rev-parse HEAD)"
   commit_time="$(git show -s --format=%ct HEAD)"

   cargo build --release -p guard-cli
   target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md \
     evidence/firefox/report.md --repo-root .
   # 成功時唯一輸出：AGENTGUARD_ACCEPTANCE_FIREFOX=PASS

   cargo run -p guard-cli -- evidence-digest \
     --repo-root . --path evidence/firefox/report.md

   cargo run -p guard-cli -- evidence-template \
     --kind acceptance_firefox --commit "$commit" > evidence/firefox/evidence.json

   # 將上面的精確 manual-acceptance 命令、marker 與 closure 摘要填入 JSON 後明確複核
   cargo run -p guard-cli -- evidence-verify \
     --kind acceptance_firefox --file evidence/firefox/evidence.json \
     --commit "$commit" --commit-time "$commit_time" --repo-root .
   ```

4. **把 JSON 交給嚴格閘門**；環境變數指向 JSON 檔案，不能再指向目錄：
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=evidence/firefox/evidence.json
   bash scripts/release-gate.sh --strict
   ```

   Windows、macOS 與 Android 依相同步驟替換 kind、目錄與環境變數。欄位與八類變數的完整說明見
   [結構化發佈證據](release-evidence.zh-TW.md)。目錄、未填寫範本、舊提交報告或只有關鍵字的任意檔案都會被拒絕。
   嚴格閘門通過後將本機證據唯讀封存到受控位置，不要把含敏感資訊的原始證據預設推送到 GitHub。

---

## 7. 判定小抄（什麼算 PASS）

- **執行前攔截類（F2/F3/F4）**：動作在**發生前**被攔截、出現確認層，且「先不要」確實阻止了動作
  （無導覽 / 無請求 / 無處理常式副作用）。只彈出通知但動作照常發生 = **FAIL**（那是事後通知，不是執行前攔截）。
- **網路層硬攔截（F6）**：目標主機的請求在 Network 面板顯示被 block，而不是 200。
- **觀測類（F1 / W2 等）**：出現對應 finding / 事件，且**對照的正常內容不誤報**。
- 任何「我無法判斷/環境未接上」的情況：記為 `BLOCKED` 並寫明原因，**不要猜 PASS**。這份清單的價值在於
  它區分了「驗過了」和「看起來應該可以」。
