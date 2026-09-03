[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium 擴充功能驗收清單（Chrome / Edge）

本文件對應 Firefox 清單（[acceptance-firefox.zh-TW.md](acceptance-firefox.zh-TW.md)）的 Chromium 側。案例編號與 Firefox
**同名同義**（F1–F8），因為兩邊載入的是同一套內容腳本；不同的是**證據來源**：

- **C1–C5（對應 F1–F5）由真瀏覽器 E2E 自動產出**：`make e2e-extension` 把 `apps/extension-chromium` 原樣
  作為未封裝擴充功能載入真 Chromium（Playwright 持久化情境），對 `eval/acceptance-fixtures/` 的固件頁跑機器判據，
  結論落 `eval/e2e-extension/out/report.json`，最後一行 `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`。不需要人，
  也**不進 release-gate**（需要 Playwright + Chromium，最小容器沒有）；CI 單獨執行。
- **C6–C8（對應 F6–F8）仍是真機人工案例**：原生訊息 host、DNR 規則、配額——E2E 不安裝宿主
  （`nativeEnabled` 預設關閉，也應當關閉），這幾條只有在安裝了 `guard-nm-host` 的真機上才算數。

> 本清單全綠只是發佈的必要非充分條件；它不能取代商店簽署、發佈套件身分、其餘平台證據或完整發佈閘門。
> 它**目前不是**嚴格閘門的一種 `EvidenceKind`——嚴格閘門認的擴充功能證據是 Firefox 的 F1–F8。要把 Chrome 提為
> 閘門證據，需先在 `guard-cli evidence-verify` 加入 kind，並把 `EXPECTED_EVIDENCE` 對應加一。

## E2E 到底證明了什麼、沒證明什麼

證明了（每次執行都重新證明）：

| # | 判據（機器斷言） | 對應 Firefox |
|---|------------------|--------------|
| C1 | 隱藏注入文字 → background `recent` 出現 `invisible_injection`；落盤 URL 已最小化、標題已截斷（P1-1） | F1 |
| C2 | 付款 CTA 點擊被**同步**攔住：頁面處理器未執行、`role=alertdialog` 出現、預設焦點在「先不要」、可見文字無裸術語；「先不要」→ 仍未執行；再點 →「允許這一次」→ 處理器恰好執行一次；兩次攔截各留一筆 `prevented/payment_cta` | F2 |
| C3 | 陷阱語境下的 PII 表單提交被攔：URL 不變；允許一次後 URL 帶上 `?phone=…`（真的提交了） | F3 |
| C4 | 頁面直發 `POST /pay/checkout`：**本地伺服器一個位元組都沒收到**就彈了確認；拒絕 → 頁面拿到 `AbortError`、伺服器仍未收到；允許 → 伺服器收到、頁面拿到 501 | F4 |
| C5 | `GET /pay/status`、`POST /api/search` 不彈、直達伺服器（不誤攔） | F5 |
| CM | 告警風暴回歸（真機報告 P2-3，固件 `mutation-storm.html`）：頁面每 50 ms 改 DOM、每秒重渲染同一段隱藏注入、頁面上有個付款按鈕 → 5 秒只多**一條**「最近」（M1）；注入與按鈕各只報**一次**（M2）；後到的另一段注入仍會報、且只報一次（M3）；30 段突發全部計數但打包進 ≤4 條（M4，兩輪掃描 ≥1.5 s）。變異檢查：去掉去重 → M1–M4 紅，去掉節流 → M4 紅，指紋退回常量 marker → M3/M4 紅 | — |
| CP | popup：預設不轉送（開關未勾、文案說明）、今日計數行有數、最近列表有「已攔截：」條目、可見文字無裸術語 | — |

沒證明（如實邊界）：

- 跑的是容器裡 Playwright 自帶的 Chromium（版本見 report.json），不是使用者機器上的 Chrome/Edge 正式版。
- 不安裝 Native Messaging 宿主；F6/F7/F8 的等價案例（C6–C8）沒有自動化。
- Firefox：Playwright 不能向 Firefox 載入擴充功能，Firefox 真 E2E 仍 **BLOCKED**，見 Firefox 清單。
- 一段在 `document_start` 之前就抓走原始 `fetch` 參考的頁面腳本能繞過 fetch 門——這是 `guard-page.js` 檔頭寫明的邊界，E2E 不聲稱涵蓋它。
- CM 釘的是使用者可見的行為（不重複、不失聰、打包）。增量掃描（只掃新增子樹）與跳過自家彈層是**成本**最佳化，把它們關掉 CM 仍綠——E2E 不聲稱釘住它們。

## 前置條件（真機 C6–C8）

- [ ] Chrome 或 Edge 正式版；`chrome://extensions` → 開發人員模式 → 「載入未封裝項目」選 `apps/extension-chromium`，記下擴充功能 ID
- [ ] 安裝原生訊息 host：macOS/Linux `native-host/install-host.sh --browser chrome <id>`；Windows
      `powershell -ExecutionPolicy Bypass -File native-host\install-host.ps1 -Browser chrome <id>`（Edge 用 `-Browser edge`）
- [ ] popup → 設定 → 開啟「桌面轉送」；link 行應顯示「已連線」
- [ ] 規則集為 `crates/guard-schema/rules/p0_rules.yaml`；情報 bundle 已載入（預設基線即含 `evil.example`）

## 驗收案例

| # | 步驟 | 期望 | 實測 | 證據 |
|---|------|------|------|------|
| C1–C5, CM | `make e2e-extension` | 最後一行 `AGENTGUARD_E2E_EXTENSION=PASS`，`report.json` 中 `all_pass: true`（24 條）；把 `out/report.json`、`out/f2-payment-dialog.png`、`out/m-mutation-storm.png`、`out/popup.png` 複製到 `evidence/chrome/` | | |
| C6 | 導覽到 `https://evil.example/`（內建情報的惡意網域） | 引擎判 `INTEL-DOMAIN` Block → 宿主回 `block_hosts` → DNR 規則裝上 → 該主機後續請求在網路層被攔（Network 面板顯示 blocked） | | |
| C7 | 觀察 C6 的原生訊息往返 | 宿主接受呼叫方（`chrome-extension://<id>/` origin 對上 `allowed-origin`，`guard-nm-host` 未因 origin 拒絕啟動），判決進入簽章稽核；popup link 行顯示「已連線 · 上次成功 …」 | | |
| C8 | DNR 動態規則數量 | 未超過 Chromium 的動態規則配額（安裝規則不報錯；必要時按配額上限截斷名單） | | |

## 快速指令

```bash
# 離線閘門（必須先 PASS）
make check-extension-gate

# 真瀏覽器 E2E（C1–C5 + CM 風暴回歸 + popup）
make e2e-extension
# → eval/e2e-extension/out/report.json, f2-payment-dialog.png, m-mutation-storm.png, popup.png

# 出 Chrome 套件
apps/extension-chromium/scripts/package-store.sh
```
