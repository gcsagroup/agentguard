[简体中文](acceptance-windows.md) | [繁體中文](acceptance-windows.zh-TW.md) | [English](acceptance-windows.en.md)

# Windows 真機驗收清單（Launch Readiness）

本文件用於在**真實 Windows 裝置**上對 AgentGuard 桌面殼程式進行發佈前人工驗收。它對應 platform-matrix
中 Windows 欄位那些「程式碼已進 CI，但真機端到端未驗證」的項目——只有在真 Windows 上跑過一次才算數；
`windows` CI 作業只編譯 `win-adapter`，不會驅動真實的 UI Automation / GDI / OCR。

> 本清單全綠只是發佈的必要非充分條件；它不能取代 Authenticode 簽章、安裝套件身分、其餘平台證據或完整發佈門禁。

> **前置的離線門禁**：先在儲存庫根目錄執行 `make acceptance`（離線情境），並在 Windows 上執行
> `cargo build -p win-adapter` + `clippy -D warnings`。全綠是必要非充分條件——它證明「Windows 專屬
> 程式碼路徑能編譯、判決邏輯正確」，不證明「真 Windows 上 UI Automation 確實取得樹、GDI 確實擷取到影格」。

## 前置條件

- [ ] AgentGuard Windows 桌面殼程式已安裝並執行（系統匣應用程式）
- [ ] 規則集為 `crates/guard-schema/rules/p0_rules.yaml`（或發佈套件內等價路徑）
- [ ] 威脅情報 bundle 已載入
- [ ] 若驗收瀏覽器擴充功能路徑：`install-host.sh` 的 Windows 等價操作（原生訊息 host manifest 寫入登錄檔
      `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.agentguard.native`，`path` 指向
      `guard-nm-host.exe`）——見 platform-matrix「原生訊息」說明

## 驗收案例

每一項都要在**真 Windows** 上手動走一遍，保留證據（螢幕截圖 / 事件日誌）。

| # | 步驟 | 預期 | 實測 | 證據 |
|---|------|------|------|------|
| W1 | 在一般應用程式中開啟含付款 CTA（"Confirm Payment / 確認支付"）的視窗 | 殼程式彈出**阻斷式模態**（Critical Confirm），點取消後動作不發生——這是 Windows/macOS 才有的真實互動確認 | | |
| W2 | UI Automation 觀測：切換至一個含表單的視窗 | 引擎收到 `UiTreeDelta`（樹已走訪）；表單中的非必要 PII 觸發 FM/TR 判決 | | |
| W3 | GDI `BitBlt` 像素擷取 + 隱寫 | 一張含 chroma/luma 隱寫的影像出現在目標視窗 → `guard-vision` 擷取到（與 macOS 使用同一套 `guard-vision`） | | |
| W4 | `Windows.Media.Ocr` 讀屏 | 一段只存在於像素中的付款文字 → OCR 讀出 → `OVL-009/010` 觸發。嚴格驗收前必須安裝對應辨識語言套件；缺少時本項記為 BLOCKED，殼程式仍應提供含原因的能力報告，但不能寫成 `PASS (native)` | | |
| W5 | overlay 覆蓋（note 1 的限制） | 目標視窗**自行繪製**的可疑覆蓋會被擷取；**另一個處理程序**繪製在其上的網路釣魚視窗**不會**出現在 GDI 擷取的像素中（如實反映較窄的覆蓋範圍，不是 bug） | | |
| W6 | 執行階段能力探針 | 殼程式報告 UI Automation / 擷取 / OCR 各自是否可用，並附原因字串（不是靜默假設可用） | | |
| W7 | 瀏覽器擴充功能 → 原生訊息 host | Chrome/Edge 擴充功能的事件透過登錄檔登記的 `guard-nm-host.exe` 判決並進入簽章稽核；host 的 origin 驗證相符。它是嚴格 Windows 候選驗收的必要項目 | | |

> 上表只用於逐項執行記錄，不能原樣作為 strict artifact。嚴格閘門報告必須使用[中央真實裝置驗收報告範本](acceptance-report-template.zh-TW.md)，
> 並維持 `ID | 結果 | 證據` 為前三欄，再將 W1–W7 的結果與證據逐項轉錄進去。

## 這些案例分別驗證 platform-matrix 的哪一項「未驗證」

- W1 → "Critical-node confirmation ✅ blocking modal in the shell"（Windows 欄）在真機成立
- W2 → "Observation source: UI Automation tree walk" 在真機取得樹
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 在真機擷取到影格並讀到螢幕文字
- W5 → note 1（Windows overlay 比 macOS 窄）真機行為符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 在真機提供原因字串
- W7 → 原生訊息 host 在 Windows 的登錄檔登記 + origin 握手

## 簽署

- 驗收人：____________  版本 / commit：____________  日期：____________
- 全部必要案例 PASS 後，將完成的報告儲存為儲存庫相對普通檔案（例如 `evidence/windows/report.md`），用
  下列命令實際校驗、計算閉包摘要並填寫 JSON。`output` 必須使用命令成功時列印的精確標記
  `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`，JSON 還須綁定目前完整 commit 與
  `agentguard-acceptance-closure-sha256-v1`。
  W1–W7 在報告中必須各恰好一列，結果精確為 `PASS (native)`，證據欄須指向 `evidence/windows/` 下真實存在的
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
