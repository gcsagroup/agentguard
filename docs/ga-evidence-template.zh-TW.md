[简体中文](ga-evidence-template.md) | [繁體中文](ga-evidence-template.zh-TW.md) | [English](ga-evidence-template.en.md)

# GA 證據範本（預設 BLOCKED）

> 本頁不是發佈證據。所有結果故意為 `BLOCKED`，marker 也不是成功值；原樣複製必須失敗。只有真實執行且外部記錄可核對時，才能依 [GA 閘門](ga-release-gate.zh-TW.md) 改為 `PASS (native)` 與精確成功 marker。

每份 `report.md` 使用以下形狀，並以唯一、非空、已脫敏的檔案替代佔位值：

```text
AGENTGUARD_GA_EVIDENCE_PROFILE=<BLOCKED until ga-v1 completed>
AGENTGUARD_GA_<KIND>=BLOCKED
HEAD=<full commit>
ARTIFACT_SET_SHA256=<64 lowercase hex>
OWNER=<accountable identity>
EXECUTED_AT=<RFC3339>
EXTERNAL_RECORD=<immutable external identifier>
```

```markdown
| 案例 | 結果 | 證據 | 備註 |
|---|---|---|---|
| <ID> 實測 | BLOCKED | evidence/ga-<kind>/<unique-file> | <reason> |
```

SBOM 報告固定引用 `delivery.cdx.json`（SB1）、`delivery.spdx.json`（SB2）、`NOTICE-review.md`（SB3）及 `scope-reconciliation.md`（SB4）。NOTICE 真實審查後才可寫入 `AGENTGUARD_NOTICE_REVIEW=APPROVED`；範圍檔只有在 macOS/Windows/Android/iOS/Chrome/Edge 均納入後，才可寫入 `AGENTGUARD_DELIVERY_SBOM_SCOPE=COMPLETE`、六行 `AGENTGUARD_DELIVERY_SCOPE_<PLATFORM>=INCLUDED` 及六行 `AGENTGUARD_DELIVERY_<PLATFORM>_SHA256=<64 lowercase hex>`。這些摘要必須綁定倉庫外凍結 `DELIVERY_ROOT` 中每端唯一最終套件；生成命令拒絕掃描 `.`。`collect` 不會複製六個套件，原 `DELIVERY_ROOT` 必須在外部不可變產物庫留存。

其他報告與案例：`ga-privacy-store` PS1–PS6、`ga-beta-14d` BT1–BT4、`ga-dual-rc` RC1–RC2、`ga-channel-smoke` CS1–CS6，以及 `ga-rollout` RO5/RO25/RO100。Beta 預留唯一 RFC3339 `BETA_START`/`BETA_END`；雙 RC 預留完整 `RC1_COMMIT`/目前 `RC2_COMMIT`；擴量預留 RFC3339 `ROLLOUT_5_AT`/`25_AT`/`100_AT`。

五方報告使用 `AGENTGUARD_GA_SIGNOFF_PROFILE=five-party-v1`，並固定引用 `release.md`、`qa.md`、`security.md`、`privacy-legal.md`、`operations.md`。單份材料預設：

```text
AGENTGUARD_GA_SIGNOFF_ROLE=<role>
AGENTGUARD_GA_SIGNOFF_DECISION=BLOCKED
AGENTGUARD_GA_SIGNOFF_IDENTITY=<external identity>
AGENTGUARD_GA_SIGNOFF_AT=<RFC3339>
AGENTGUARD_GA_SIGNOFF_ARTIFACT_SET_SHA256=<same hash in all five>
EXTERNAL_APPROVAL_RECORD=<ticket or detached signature>
```

CLI 只綁定檔案位元組，不證明身份真實；必須另存可驗簽或受控工單記錄。證據不得包含 PII、商店密鑰、簽署私鑰、cookie 或會話令牌。
