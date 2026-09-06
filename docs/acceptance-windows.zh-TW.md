[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows 真機驗收清單（first-ga-v1）

本文件用於在**真實 Windows 裝置**上對 AgentGuard 桌面殼程式進行發佈前人工驗收。
`first-ga-v1` 的必要項目是 W1–W6 與 W8–W11；W7 只保留為非 GA／舊版 Native Messaging 可選記錄，不計入通過條件。
`windows` CI 作業目前已涵蓋 Windows 工作區、`win-adapter`、桌面測試與真實視窗啟動 smoke，但不會驅動
真實 UI Automation / GDI / OCR 互動，也不能取代 `first-ga-v1` 必要項目的逐項人工證據。

> 本清單全綠只是發佈的必要非充分條件；它不能取代 Authenticode 簽章、安裝套件身分、其餘平台證據或完整發佈門禁。

> **前置的自動化門禁**：先在儲存庫根目錄執行 `make acceptance` 與 `cargo test --workspace`；在 Windows 上還要建置
> `win-adapter`、以 `-D warnings` 執行 Clippy，並執行桌面測試、桌面 Clippy 與 Release 建置。CI 的視窗啟動
> smoke 會確認處理程序未立即退出且已建立原生視窗。全綠是必要非充分條件：它不證明 `first-ga-v1` 必要項目的真實互動結果。

## 目前執行狀態（2026-09-02）

- 候選 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在 Windows 11 build 26200 上完成桌面測試 5/5、桌面 Clippy `-D warnings` 與 Release 建置；GitHub Actions run `33551495621` 全綠。
- Release EXE 的 SHA-256 為 `47A420C6A5FA88C406C18DD7F8A189B6D21183143A2DA69578FA02C559AB5119`，Authenticode 狀態為 `NotSigned`。
- 獨立 RDP 互動測試中，視窗閒置超過 30 秒並持續更新；兩輪工作階段各跨過 OCR 週期執行超過 30 秒，UIA/GDI/OCR 均顯示可用，真實觸發 `OVL-010` 事後風險模態，選擇暫停後執行 End/Resume/Start 的第二輪仍穩定，且未出現新的 Event 1000。
- 本輪結論是**部分真機驗收**。付款 CTA、第三方表單與像素 OCR、隱寫、overlay 邊界與能力失敗分支未依 `first-ga-v1` 必要情境執行，因此下表不標記 PASS。WinRM 自動化只屬於前置門禁；本輪另有獨立 RDP 互動證據。詳見[補充報告](acceptance-report-windows-2026-09-02.zh-TW.md)。

## 前置條件

- [ ] AgentGuard Windows 桌面殼程式已安裝並執行
- [ ] 規則集為 `crates/guard-schema/rules/p0_rules.yaml`（或發佈套件內等價路徑）
- [ ] 威脅情報 bundle 已載入
- [ ] 嚴格報告包含整列 `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。
- [ ] 不為本清單安裝 Native Messaging host；首個 GA 瀏覽器套件不含該權限。W7 僅供未來單獨驗收舊版原型。

## 驗收案例

每一項都要在**真 Windows** 上手動走一遍，保留證據（螢幕截圖 / 事件日誌）。

| # | 步驟 | 預期 | 實測 | 證據 |
|---|------|------|------|------|
| W1 | 在一般應用程式中開啟含付款 CTA（"Confirm Payment / 確認支付"）的視窗 | 殼程式彈出**事後風險確認**，明確說明動作已被觀察、不能撤銷；點「先不要」只暫停本次工作階段與後續觀察。稽核須記錄 `effect=observed_only`、`external_action_blocked=false`，不得聲稱原動作未發生 | | |
| W2 | UI Automation 觀測：切換至一個含表單的視窗 | 引擎收到 `UiTreeDelta`（樹已走訪）；表單中的非必要 PII 觸發 FM/TR 判決 | | |
| W3 | GDI `BitBlt` 像素擷取 + 隱寫。固件：`make acceptance-fixtures` → 全螢幕顯示 `eval/acceptance-fixtures/generated/w3-stego-luma.png`、`w3-stego-chroma.png`（對照 `w3-control-clean.png` 不得觸發） | 一張含 chroma/luma 隱寫的影像出現在目標視窗 → `guard-vision` 擷取到（與 macOS 使用同一套 `guard-vision`） | | |
| W4 | `Windows.Media.Ocr` 讀屏。固件：以 Edge/Chrome 開啟 `generated/w4-pixel-only-payment.html`（付款文字只在 canvas 像素中，UIA 樹沒有） | 一段只存在於像素中的付款文字 → OCR 讀出 → `OVL-009/010` 觸發。嚴格驗收前必須安裝對應辨識語言套件；缺少時本項記為 BLOCKED，殼程式仍應提供含原因的能力報告，但不能寫成 `PASS (native)` | | |
| W5 | overlay 覆蓋（note 1 的限制）。固件：`generated/w5-self-drawn-overlay.html`（頁面自繪 3% 覆蓋；DevTools 刪除 `#sub` 作對照）或全螢幕顯示 `w5-self-drawn-overlay.png` | 目標視窗**自行繪製**的可疑覆蓋會被擷取；**另一個處理程序**繪製在其上的網路釣魚視窗**不會**出現在 GDI 擷取的像素中（如實反映較窄的覆蓋範圍，不是 bug） | | |
| W6 | 執行階段能力探針 | 殼程式報告 UI Automation / 擷取 / OCR 各自是否可用，並附原因字串（不是靜默假設可用） | | |
| W7（非 GA／舊版可選） | 瀏覽器擴充功能 → 原生訊息 host | 僅保留編號和原型驗收語意；不計入 `first-ga-v1` 門禁，不得為讓它 PASS 而給 GA manifest 加回 `nativeMessaging` | N/A (non-GA) | |
| W8 | **驗收 trace 判據**：整場以 `AGENTGUARD_ACCEPTANCE_TRACE=evidence\windows\trace.jsonl` 啟動殼程式；跑完 W1–W6 與 W9、W10 後執行 `guard-cli acceptance-trace-check --trace evidence/windows/trace.jsonl --audit-db <稽核庫>` | 六項全 `PASS`，印出整行 `AGENTGUARD_ACCEPTANCE_TRACE_CHECK=PASS`；任一 FAIL 本項即 FAIL | | |
| W9 | **結束後不再擷取**（報告第 3 條）：按「結束會話」，等 ≥60 s，再切換幾個視窗 | 稽核庫最後一筆是 `SESSION-END`，其後零觀察紀錄；trace 會話結束後無 `events>0` 的 tick；狀態燈「已停止」 | | |
| W10 | **狀態燈與事實一致**（報告 P0-3）：會話中截圖「保護中」；以 `AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia` 重啟殼程式並開啟會話截圖；移除變數再截圖 | 「保護中」→「守護不完整」（`required_capability_unavailable`，原因字串點名 UIA）→「保護中」；trace-check 第 5 項 PASS。真實 `E_ACCESSDENIED` 另測，必須顯示「需要授權」。 | | |
| W11 | **「開始守護」自己就夠了**（真機回饋)：全新啟動應用 → **不展開開發者面板** → 點「開始守護」 | ≤10 s 內狀態燈變「保護中」，主介面那行變成「正在看這台機器…」；「即時觀察」卡片裡三項能力都顯示實際探測值和原因。點「結束守護」後燈回「未在守護」、那行回「什麼都沒在看」。保存兩張截圖（守護中／結束後）、三項能力列，以及開發者面板中獨立的原始診斷列。 | | |

> 補充報告中的風險模態、能力狀態與 OCR 週期是 W1/W3/W4/W6 的相鄰證據，但沒有依各列規定的付款 CTA、效果語意、隱寫、第三方純像素文字或能力失敗情境執行，不能據此將這些列寫成 `PASS (native)`。
> 另外，補充報告裡兩輪都出現的 `OVL-010` 模態是在 AgentGuard **自己的視窗**為前景時彈出的（樹裡有折疊的示範按鈕文字、像素裡沒有），它證明鏈路能跑，不是一次偵測；此後觀察器跳過自身行程，且 `OVL-010` 要求未渲染的文字具指令形狀。複測時以第三方視窗為前景。

> **W6 執行方法**：一台一切正常的機器上，能力不可用分支無法自然觸發。啟動殼程式前設定
> `AGENTGUARD_FORCE_CAP_UNAVAILABLE=uia`（可選 `frame`、`ocr`，逗號分隔，例 `uia,frame`），逐項驗證：
> 介面能力列顯示「不可用」且原因字串含 `forced unavailable for acceptance`；`uia,frame` 同時強制關閉時
> 狀態燈為「守護不完整」、觀察迴圈不啟動（fail-closed 到模擬）；只強制 `ocr` 時 W4 的交叉驗證不執行且介面如實說明。
> 這個開關只能把可用改成不可用，不能反向——它讓驗收者看「壞了會怎樣」，不能讓一台沒能力的機器冒充有能力。

> 上表只用於逐項執行記錄，不能原樣作為 strict artifact。嚴格閘門報告必須使用[中央真實裝置驗收報告範本](acceptance-report-template.zh-TW.md)，
> 並維持 `ID | 結果 | 證據` 為前三欄，再將 `first-ga-v1` 必要項目 W1–W6/W8–W11 的結果與證據逐項轉錄進去。

## 這些案例分別驗證 platform-matrix 的哪一項「未驗證」

- W1 → 桌面觀察器的事後風險確認與 `observed_only` 效果語意在真機成立；真正執行前阻斷由 Chromium/Gateway 的獨立閘門驗證
- W2 → "Observation source: UI Automation tree walk" 在真機取得樹
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 在真機擷取到影格並讀到螢幕文字
- W5 → note 1（Windows overlay 比 macOS 窄）真機行為符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 在真機提供原因字串
- W7 → 非 GA／舊版原型的登錄檔登記 + origin 握手；不計入 `first-ga-v1`

## 簽署

- 驗收人：____________  版本 / commit：____________  日期：____________
- 全部 `first-ga-v1` 必要案例 PASS 後，將完成的報告儲存為儲存庫相對普通檔案（例如 `evidence/windows/report.md`），用
  下列命令實際校驗、計算閉包摘要並填寫 JSON。`output` 必須使用命令成功時列印的精確標記
  `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`，JSON 還須綁定目前完整 commit 與
  `agentguard-acceptance-closure-sha256-v1`。
  報告必須包含整列 `AGENTGUARD_WINDOWS_ACCEPTANCE_PROFILE=first-ga-v1`。W1–W6 與 W8–W11 必須各恰好一列，結果精確為 `PASS (native)`，證據欄須指向 `evidence/windows/` 下真實存在的
  儲存庫相對非空普通檔案；路徑不得重複使用，不能引用報告本身或目前證據 JSON 來源檔案，也不能經過符號連結或超出儲存庫。
  路徑只使用 `/`，每個元件須符合 `[A-Za-z0-9._-]+`，不能包含空白或 shell glob／展開字元。閉包綁定報告與每個唯一引用的路徑、長度與內容，
  但仍是未簽署自證，不能證明螢幕截圖或記錄的真實來源。
  ```bash
  mkdir -p evidence/windows
  commit="$(git rev-parse HEAD)"
  commit_time="$(git show -s --format=%ct HEAD)"
  cargo build --release -p guard-cli
  target/release/guard-cli manual-acceptance windows docs/acceptance-windows.md \
    evidence/windows/report.md --repo-root .
  # 成功時唯一輸出：AGENTGUARD_ACCEPTANCE_WINDOWS=PASS
  cargo run -p guard-cli -- evidence-digest \
    --repo-root . --path evidence/windows/report.md
  cargo run -p guard-cli -- evidence-template --kind acceptance_windows \
    --commit "$commit" > evidence/windows/evidence.json
  # 將精確 manual-acceptance 命令、marker 與 closure 摘要填入 JSON 後
  cargo run -p guard-cli -- evidence-verify --kind acceptance_windows \
    --file evidence/windows/evidence.json --commit "$commit" \
    --commit-time "$commit_time" --repo-root .
  ```
- 再把 **JSON 檔案**路徑匯出至 `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS`。目錄、未填寫範本或僅含 `PASS`
  關鍵字的檔案都不能作為證據。詳見[結構化發佈證據](release-evidence.zh-TW.md)。
