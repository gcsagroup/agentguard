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
| W4 | `Windows.Media.Ocr` 讀屏 | 一段只存在於像素中的付款文字 → OCR 讀出 → `OVL-009/010` 觸發（需已安裝辨識語言套件；若未安裝則不執行這兩項，殼程式應提供含原因的能力報告） | | |
| W5 | overlay 覆蓋（note 1 的限制） | 目標視窗**自行繪製**的可疑覆蓋會被擷取；**另一個處理程序**繪製在其上的網路釣魚視窗**不會**出現在 GDI 擷取的像素中（如實反映較窄的覆蓋範圍，不是 bug） | | |
| W6 | 執行階段能力探針 | 殼程式報告 UI Automation / 擷取 / OCR 各自是否可用，並附原因字串（不是靜默假設可用） | | |
| W7 | 瀏覽器擴充功能 → 原生訊息 host（選用） | Chrome/Edge 擴充功能的事件透過登錄檔登記的 `guard-nm-host.exe` 判決並進入簽章稽核；host 的 origin 驗證相符 | | |

## 這些案例分別驗證 platform-matrix 的哪一項「未驗證」

- W1 → "Critical-node confirmation ✅ blocking modal in the shell"（Windows 欄）在真機成立
- W2 → "Observation source: UI Automation tree walk" 在真機取得樹
- W3/W4 → "Pixel analysis ✅ same code, OCR via Windows.Media.Ocr" 在真機擷取到影格並讀到螢幕文字
- W5 → note 1（Windows overlay 比 macOS 窄）真機行為符合描述
- W6 → "Runtime capability probe ✅ real probe with a reason string" 在真機提供原因字串
- W7 → 原生訊息 host 在 Windows 的登錄檔登記 + origin 握手

## 簽署

- 驗收人：____________  版本 / commit：____________  日期：____________
- 全部案例 PASS 後，把證據目錄路徑匯出至 `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS`，再執行
  `scripts/release-gate.sh --strict`，讓這一項從「未驗證」轉為已驗證。
