[简体中文](ga-release-gate.md) | [繁體中文](ga-release-gate.zh-TW.md) | [English](ga-release-gate.en.md)

# GA 發佈閉環閘門

## 結論與層級

`scripts/release-gate.sh --strict` 只判定 **RC 技術候選**：自動檢查、生產 preflight、候選凍結，以及 12 類簽署／公證／裝置驗收證據。通過只代表候選可進入 GA 收口，不代表 GA 已核准、商店已上架或用戶端已在線。

`scripts/release-gate.sh --ga` 包含 RC 的 12 類，再要求下列 7 類 GA 閉環證據，共 19 類。首個 GA 不含 Firefox；六個渠道是 macOS、Windows、Android、iOS、Chrome 與 Edge。任一證據缺失、過期、未綁定目前 HEAD 或結構不符，結論都是 **GA No-Go**。

## 七類 GA 證據

| kind | 環境變數 | 必需案例 | 最低真實條件 |
|---|---|---|---|
| `ga_sbom_license` | `AGENTGUARD_EVIDENCE_GA_SBOM_LICENSE` | SB1–SB4 | 六端最終交付物的 CycloneDX、SPDX、NOTICE 人工審查與範圍對帳 |
| `ga_privacy_store` | `AGENTGUARD_EVIDENCE_GA_PRIVACY_STORE` | PS1–PS6 | 六端隱私、權限、資料處理與商店聲明和實物一致 |
| `ga_beta_14d` | `AGENTGUARD_EVIDENCE_GA_BETA_14D` | BT1–BT4 | 同一候選系列連續觀察至少 `14×24` 小時，保留群體、指標、事故及回滾演練 |
| `ga_dual_rc` | `AGENTGUARD_EVIDENCE_GA_DUAL_RC` | RC1–RC2 | 兩個不同完整 Git commit 各自完成獨立候選回歸；RC2 是目前 HEAD |
| `ga_signoff` | `AGENTGUARD_EVIDENCE_GA_SIGNOFF` | SO1–SO5 | Release、QA、Security、Privacy/Legal、Operations 五位不同負責人核准同一 artifact-set SHA-256 |
| `ga_channel_smoke` | `AGENTGUARD_EVIDENCE_GA_CHANNEL_SMOKE` | CS1–CS6 | 六個真實商店／下載渠道分別完成下載、安裝、首啟及最小保護流程 |
| `ga_rollout` | `AGENTGUARD_EVIDENCE_GA_ROLLOUT` | RO5/RO25/RO100 | 真實擴量依 5%→25%→100% 嚴格遞增，每階段有健康判定與回滾決策 |

案例順序：PS1–PS6 與 CS1–CS6 均依次為 macOS、Windows、Android、iOS、Chrome、Edge；SO1–SO5 依次為 Release、QA、Security、Privacy/Legal、Operations。SB1 是 CycloneDX、SB2 是 SPDX、SB3 是 NOTICE 審查、SB4 是六端範圍對帳。BT1–BT4 分別覆蓋群體/build、完整指標、穩定閾值/事故及回滾支援演練。

## 機器校驗合同

每份報告位於 `evidence/ga-<kind>/report.md`，並包含精確行 `AGENTGUARD_GA_EVIDENCE_PROFILE=ga-v1`。每個必需案例恰好一行，結果精確為 `PASS (native)`，證據是對應小寫目錄內唯一、非空、非符號連結的倉庫相對檔案。模擬結果、FAIL、BLOCKED、N/A、佔位值與重複路徑都會被拒絕。

- Beta 必須有唯一 RFC3339 `START`/`END`，間隔至少 14 天，結束不晚於證據 JSON。
- 雙 RC 必須是兩個不同的 40 位小寫 commit，RC2 等於目前 HEAD。內容定址不取代受控標籤、不可變產物庫或外部見證。
- SBOM 固定為 `delivery.cdx.json`、`delivery.spdx.json`、`NOTICE-review.md`、`scope-reconciliation.md`；兩份 JSON 需有非空套件，審查與範圍檔需有規定 marker。
- 五方材料固定為 `release.md`、`qa.md`、`security.md`、`privacy-legal.md`、`operations.md`，需要正確角色、`APPROVED`、五個不同身份、RFC3339 時間及相同 artifact-set SHA-256；簽署時間須綁定目前候選與證據時間。
- 擴量 `5_AT`/`25_AT`/`100_AT` 必須嚴格遞增；5% 不早於目前候選，100% 不晚於證據 JSON。

## 操作

先在 clean、已提交候選執行 `scripts/release-gate.sh --strict`。依 [GA 證據範本](ga-evidence-template.zh-TW.md)、[Beta 手冊](ga-beta-runbook.zh-TW.md)、[擴量手冊](rollout-runbook.zh-TW.md)、[事故手冊](incident-response.zh-TW.md) 及 [支援手冊](support-runbook.zh-TW.md) 產生真實材料。`scripts/ga-sbom-license.sh generate DELIVERY_ROOT` 只掃描倉庫外、六端各一凍結套件的交付根，拒絕 `.`；再用 `collect DELIVERY_ROOT CDX SPDX NOTICE SCOPE` 原子收集。`artifact-set.sha256` 也進入 SB4 閉包，並與範圍檔六個 SHA 精確對帳。`collect` 只收集清單與審查資產，不複製六個二進位套件；原 `DELIVERY_ROOT` 必須在外部不可變產物庫留存，以供日後重新計算 SHA-256。任一工具、審批、範圍或摘要缺失均 BLOCKED。

逐份執行 `guard-cli manual-acceptance <ga-platform> docs/ga-release-gate.md <report> --repo-root .`，再用 `evidence-digest` 與 `evidence-verify` 綁定閉包。最後透過 19 個環境變數執行 `scripts/release-gate.sh --ga`，並將日誌、HEAD、產物集及證據唯讀封存。

## 證據邊界

目前 JSON/Markdown 是未簽署的本機自證。CLI 能綁定位元組、時間、commit、案例與摘要，但不能證明審批身份真實，也不能對抗可同時偽造全部檔案的工作區控制者。生產必須另外保留可核對的商店記錄、工單身份、可驗簽簽署或受信執行器證明。

`--ga` 通過只表示配置的閉環材料在本次複核時通過；它不證明商店目前仍可下載、用戶端目前仍在線或系統之後持續健康。
