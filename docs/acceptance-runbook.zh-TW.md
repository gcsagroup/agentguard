[简体中文](acceptance-runbook.md) | [繁體中文](acceptance-runbook.zh-TW.md) | [English](acceptance-runbook.en.md)

# 真機驗收執行手冊（供自動化 agent / computer-use 使用）

本手冊將三份驗收清單（`acceptance-firefox.md` / `acceptance-macos.md` / `acceptance-windows.md`）
從「供人閱讀的檢查表」補成「可以照著執行的操作步驟」：每個案例的**準備、精確動作、可觀察判據、應擷取的證據**，
以及最後**如何記錄結果並更新儀表板**。執行者可以是 Codex / computer-use 這類能驅動真實瀏覽器與桌面的
agent。

> 每個案例的「預期」以三份 `acceptance-*.md` 為準；本手冊補充的是「如何讓它發生、如何看出是否成功」。

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

準備證據目錄：

```bash
mkdir -p /tmp/ag-evidence/{firefox,windows,macos}
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

## 5. 記錄結果 → 更新儀表板

對每個案例：

1. **填寫清單表**：在對應 `docs/acceptance-{firefox,windows,macos}.md` 的案例列中，將「實測」欄填入
   `PASS` / `PASS (sim)` / `FAIL` / `BLOCKED (原因)`，並在「證據」欄填入證據檔案相對路徑
   （例如 `/tmp/ag-evidence/firefox/F2-cancel.png`，或複製到儲存庫某目錄後的相對路徑）。
   —— 儀表板正是依這兩欄非空來反映進度，並據此計算 `X/N`。

2. **封存證據**：將螢幕截圖 / 日誌放入證據目錄，並（選用）匯出至門禁辨識的證據變數：
   ```bash
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=/tmp/ag-evidence/firefox
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS=/tmp/ag-evidence/windows
   export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=/tmp/ag-evidence/macos
   ```

3. **重新計算門禁 + 儀表板**：
   ```bash
   make dashboard                        # 重新產生 docs/status-dashboard.html，進度條依填好的表更新
   bash scripts/release-gate.sh --strict # 嚴格模式：證據變數均已設定，對應「未驗證」項目才轉綠
   ```

4. **產出報告**：依 `docs/acceptance-report-template.md` 填寫一份報告（每一項 PASS/FAIL/BLOCKED + 證據 + 備註 +
   環境資訊），連同證據目錄一起交回。

---

## 6. 判定小抄（什麼算 PASS）

- **執行前攔截類（F2/F3/F4）**：動作在**發生前**被攔截、出現確認層，且「先不要」確實阻止了動作
  （無導覽 / 無請求 / 無處理常式副作用）。只彈出通知但動作照常發生 = **FAIL**（那是事後通知，不是執行前攔截）。
- **網路層硬攔截（F6）**：目標主機的請求在 Network 面板顯示被 block，而不是 200。
- **觀測類（F1 / W2 等）**：出現對應 finding / 事件，且**對照的正常內容不誤報**。
- 任何「我無法判斷/環境未接上」的情況：記為 `BLOCKED` 並寫明原因，**不要猜 PASS**。這份清單的價值在於
  它區分了「驗過了」和「看起來應該可以」。
