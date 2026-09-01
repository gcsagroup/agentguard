[简体中文](acceptance-macos.md) | [繁體中文](acceptance-macos.zh-TW.md) | [English](acceptance-macos.en.md)

# macOS 真機驗收清單（Launch Readiness）

本文件用於在**真實 macOS 裝置**上進行發佈前人工驗收，涵蓋 Claude Desktop、Cursor 及 Chrome + 擴充功能三條接入路徑。

> **離線自動化閘門**：提交或建立 tag 前，先在儲存庫根目錄執行
> `make acceptance` 或 `cargo run -p guard-cli -- acceptance-run`。
> 此命令會執行 `eval/acceptance/manifest.yaml` 列出的離線情境，並產生 `eval/acceptance-report.json` / `eval/acceptance-report.md`。全部 PASS 是 macOS 發佈的必要非充分條件。

> 本清單全綠只是發佈的必要非充分條件，不能取代 Developer ID 簽署、公證、發佈套件身分、其他平台證據或完整發佈閘門。作為 `acceptance_macos` 嚴格閘門證據時，1、2、3、4、5、5b、5c 及 6–14 必須全部精確記錄為 `PASS (native)`；`PASS (sim)`、FAIL、BLOCKED 或 N/A 都不能通過。

## 前置條件

- [ ] AgentGuard macOS 選單列應用程式已安裝並啟動
- [ ] 規則集為 `crates/guard-schema/rules/p0_rules.yaml`（或發佈套件內的等價路徑）
- [ ] 威脅情報 bundle 已載入（預設為 `intel/bundle.json`）
- [ ] 稽核資料庫可寫入（選用，用於匯出證據）
- [ ] **不涉及計費**：本清單不包含 Stripe / entitlement 驗收

## 平台矩陣

| 平台 | 驗收方式 | 備註 |
|------|----------|------|
| Claude Desktop | 選單列 + Accessibility 事件 | 主要路徑 |
| Cursor | 相同方式，在 Agent 工作階段內觸發 | 與 Claude 共用 adapter |
| Chrome + 擴充功能 | Native Messaging → `guard-cli ingest-browser` 或桌面 ingest | 瀏覽器端 DOM / URL 探針 |

## 驗收案例

在 **Claude Desktop / Cursor / Chrome+擴充功能** 中至少選一條主要路徑完成；未選的接入路徑可在備註中標記 N/A，但嚴格閘門要求的每個案例結果本身都不能是 N/A。

| # | 實測結果 | 證據（螢幕截圖路徑） | 步驟 | 預期規則 |
|---|----------|----------------------|------|----------|
| 1 | | | **付款確認**：在結帳頁觸發「Complete purchase」或「請確認支付」類 UI 文字 | `CRIT-001` → Block；gated deny 時工作階段暫停 |
| 2 | | | **轉帳確認**：觸發「確認轉帳」/ transfer 類 critical 文案 | `CRIT-001` → Block |
| 3 | | | **選用 PII**：Agent 填寫非必填 DOB / 生日欄位 | `PRIV-003` → Alert（form minimization） |
| 4 | | | **Trap 表單**：行銷頁面的選用「優先電話」等 trap 欄位被填寫 | `PRIV-004` → Alert（trap resistance） |
| 5 | | | **透明 overlay**：頁面或 AX 樹出現 `[AG_TRANSPARENT_OVERLAY]` 標記 | `OVL-002` → Alert |
| 5b | | | **圓角不可見區**：出現 `[AG_INVISIBLE_ZONE]` | `OVL-006` → Block |
| 5c | | | **執行前 UI 變化**：出現 `[AG_UI_REVALIDATE]`，或 `process_with_revalidate` 指紋不一致 | `UI-REVALIDATE` → Block |
| 6 | | | **Intel 注入**：UI 文字包含 bundle 內的 injection 模式（例如 system override） | `INTEL-002` → Block |
| 7 | | | **惡意網域**：導覽至 bundle 內的惡意網域 | `INTEL-001` → Block |
| 8 | | | **Netmon 外洩**：大容量上傳 / 未知網域外連提示（`[AG_LARGE_UPLOAD]` 或 netmon flow） | `PRIV-005` → Alert |
| 9 | | | **瀏覽器惡意 URL**：擴充功能回報惡意 URL / deeplink payload | `INTEL-001` 或等價 block |
| 10 | | | **工作階段暫停**：gated deny 後的後續事件應回傳 `SESSION-PAUSED` | `SESSION-PAUSED` |
| 11 | | | **SCK 探針**：執行 `cargo run -p guard-cli -- sck-probe` | 列印 `mac caps` 且 `sck_probe` 原生可用；權限拒絕須記為 BLOCKED |
| 12 | | | **AX 探針**：執行 `cargo run -p guard-cli -- ax-probe` | `ax_probe: OK`；權限拒絕須記為 BLOCKED |
| 13 | | | **真機 AX**：授予 Accessibility 後，使用儀表板「擷取前景 AX」或 `ax-snapshot` | 產生 UiTreeDelta；填寫表單時觸發 FM/TR |
| 14 | | | **UI revalidate**：連續兩個不同 UI 影格（或第二次 AX 擷取時 UI 已改變） | `UI-REVALIDATE` → 待確認 |

### SCK / TCC 說明

Screen Recording 或 Accessibility 權限未授予時，必須在「實測結果」欄記為 `BLOCKED (TCC 未授權)`，並在證據欄附上終端輸出或系統設定螢幕截圖。BLOCKED 能如實說明環境狀態，但不能冒充嚴格閘門要求的 `PASS (native)`；補齊權限後須重新執行對應原生案例。

## 離線情境 ↔ 清單對應

| 清單 # | manifest 情境檔案 |
|--------|-------------------|
| 1 | `payment_complete_purchase.yaml` |
| 2 | `payment_transfer_crit.yaml` |
| 3 | `fm_optional_dob_alert.yaml` |
| 4 | `trap_form_marketing.yaml` |
| 5 | `overlay_transparent_alert.yaml` |
| 6 | `inject_system_override_block.yaml` |
| 7 | `intel_domain_block.yaml` |
| 8 | `network_exfil_alert.yaml` |
| 9 | `browser_malicious_url.yaml` |
| 10 | `session_pause_smoke.yaml` |
| 11 | （真機 SCK；離線沒有 YAML） |

Intel 注入離線情境：`intel_inject_block.yaml`（與 #6 互補）。

## 快速命令

```bash
# 離線 acceptance 閘門（必須先 PASS）
make acceptance

# 真機 TCC / SCK 探針
make sck-probe

# 匯出工作階段稽核（選用證據）
cargo run -p guard-cli -- audit-report --audit-db /path/to/audit.db
```

## 簽署

| 角色 | 姓名 | 日期 | 離線 acceptance | 真機清單 |
|------|------|------|-----------------|----------|
| 開發者 | | | ☐ | ☐ |
| QA | | | ☐ | ☐ |

全部必要案例取得原生 PASS 後，將完成的報告儲存為例如 `evidence/macos/report.md`。報告中每個必要 ID 必須恰好一列，第二欄精確為 `PASS (native)`，第三欄指向 `evidence/macos/` 下真實存在的儲存庫相對非空普通檔案；逐項路徑不得重複使用，且每個路徑元件只能使用可攜式 ASCII `[A-Za-z0-9._-]+` 並以 `/` 分隔。不能引用報告本身或目前證據 JSON 來源檔案，也不能經過符號連結、包含空白或 shell glob／展開字元，或超出儲存庫。接著產生並填寫結構化 JSON：

```bash
mkdir -p evidence/macos
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
  evidence/macos/report.md --repo-root .
# 成功時唯一輸出：AGENTGUARD_ACCEPTANCE_MACOS=PASS
cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/macos/report.md
cargo run -p guard-cli -- evidence-template --kind acceptance_macos \
  --commit "$commit" > evidence/macos/evidence.json

# 將上面的精確 manual-acceptance 命令、marker 與 closure 摘要填入 JSON 後
cargo run -p guard-cli -- evidence-verify --kind acceptance_macos \
  --file evidence/macos/evidence.json --commit "$commit" \
  --commit-time "$commit_time" --repo-root .
```

報告正文與 JSON `output` 都必須包含一整列 `AGENTGUARD_ACCEPTANCE_MACOS=PASS`；`artifact.sha256` 必須是 `agentguard-acceptance-closure-sha256-v1`，綁定報告原始 bytes 以及每個唯一逐項引用的路徑、長度與內容。該閉包仍是未簽署本機自證，不能證明螢幕截圖、記錄或裝置資料的真實來源。再把 JSON 檔案路徑匯出至 `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS`。目錄、未填寫範本或僅含 `PASS` 關鍵字的檔案都不是證據；詳見[結構化發佈證據](release-evidence.zh-TW.md)。
