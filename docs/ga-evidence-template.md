[简体中文](ga-evidence-template.md) | [繁體中文](ga-evidence-template.zh-TW.md) | [English](ga-evidence-template.en.md)

# GA 证据模板（默认 BLOCKED）

> 本页不是发布证据。所有表格故意为 `BLOCKED`，marker 也不是成功值；原样复制必须校验失败。只有真实执行、外部记录可核对且本地材料完整时，才能逐项改为 `PASS (native)` 并写入《[GA 发布闭环门禁](ga-release-gate.md)》要求的精确成功 marker。

## 通用报告头

```text
AGENTGUARD_GA_EVIDENCE_PROFILE=<BLOCKED until ga-v1 checklist completed>
AGENTGUARD_GA_<KIND>=BLOCKED
HEAD=<full commit>
ARTIFACT_SET_SHA256=<64 lowercase hex>
OWNER=<accountable identity>
EXECUTED_AT=<RFC3339>
EXTERNAL_RECORD=<ticket/store/build/approval URI or immutable identifier>
```

每份 `report.md` 的用例表必须使用这个形状：

```markdown
| 用例 | 结果 | 证据 | 备注 |
|---|---|---|---|
| <ID> 实测 | BLOCKED | evidence/ga-<kind>/<unique-file> | <reason> |
```

## SBOM/许可证

报告：`evidence/ga-sbom-license/report.md`。固定路径：

- SB1 `evidence/ga-sbom-license/delivery.cdx.json`
- SB2 `evidence/ga-sbom-license/delivery.spdx.json`
- SB3 `evidence/ga-sbom-license/NOTICE-review.md`
- SB4 `evidence/ga-sbom-license/scope-reconciliation.md`

NOTICE 审查完成后才能由审查人写入 `AGENTGUARD_NOTICE_REVIEW=APPROVED`。范围对账完成后才能写入：

```text
AGENTGUARD_DELIVERY_SBOM_SCOPE=COMPLETE
AGENTGUARD_DELIVERY_SCOPE_MACOS=INCLUDED
AGENTGUARD_DELIVERY_SCOPE_WINDOWS=INCLUDED
AGENTGUARD_DELIVERY_SCOPE_ANDROID=INCLUDED
AGENTGUARD_DELIVERY_SCOPE_IOS=INCLUDED
AGENTGUARD_DELIVERY_SCOPE_CHROME=INCLUDED
AGENTGUARD_DELIVERY_SCOPE_EDGE=INCLUDED
AGENTGUARD_DELIVERY_MACOS_SHA256=<64 lowercase hex>
AGENTGUARD_DELIVERY_WINDOWS_SHA256=<64 lowercase hex>
AGENTGUARD_DELIVERY_ANDROID_SHA256=<64 lowercase hex>
AGENTGUARD_DELIVERY_IOS_SHA256=<64 lowercase hex>
AGENTGUARD_DELIVERY_CHROME_SHA256=<64 lowercase hex>
AGENTGUARD_DELIVERY_EDGE_SHA256=<64 lowercase hex>
```

六个 SHA-256 必须与仓库外冻结 `DELIVERY_ROOT/artifact-set.sha256` 里的六个最终包一致。`generate DELIVERY_ROOT` 拒绝扫描仓库或 `.`；`collect DELIVERY_ROOT ...` 会重算六个包并核对这六行后才原子收集清单和审查资产，但不会复制六个包。原 `DELIVERY_ROOT` 必须在外部不可变产物库中留存。

## 隐私/商店、Beta、双 RC、六渠道 smoke

- `evidence/ga-privacy-store/report.md`：PS1–PS6，依次 macOS/Windows/Android/iOS/Chrome/Edge。
- `evidence/ga-beta-14d/report.md`：BT1–BT4；报告头预留 `AGENTGUARD_GA_BETA_START=<RFC3339>` 和 `AGENTGUARD_GA_BETA_END=<RFC3339>`。
- `evidence/ga-dual-rc/report.md`：RC1–RC2；报告头预留 `AGENTGUARD_GA_RC1_COMMIT=<full sha>` 和 `AGENTGUARD_GA_RC2_COMMIT=<current full HEAD>`。
- `evidence/ga-channel-smoke/report.md`：CS1–CS6，依次 macOS/Windows/Android/iOS/Chrome/Edge。

每个用例必须引用独立非空文件；不要在证据中收录用户 PII、商店密钥、签名私钥或账号 cookie。

## 五方签字

报告：`evidence/ga-signoff/report.md`，完成后必须含 `AGENTGUARD_GA_SIGNOFF_PROFILE=five-party-v1`。五份固定材料分别是 `release.md`、`qa.md`、`security.md`、`privacy-legal.md`、`operations.md`，单份模板：

```text
AGENTGUARD_GA_SIGNOFF_ROLE=<release|qa|security|privacy-legal|operations>
AGENTGUARD_GA_SIGNOFF_DECISION=BLOCKED
AGENTGUARD_GA_SIGNOFF_IDENTITY=<non-placeholder external identity>
AGENTGUARD_GA_SIGNOFF_AT=<RFC3339>
AGENTGUARD_GA_SIGNOFF_ARTIFACT_SET_SHA256=<same 64 lowercase hex in all five files>
EXTERNAL_APPROVAL_RECORD=<immutable ticket or detached-signature reference>
```

CLI 只绑定这些文件的字节，不证明 `IDENTITY` 真实。生产归档必须同时保留仓库外的可验签审批/工单记录。

## 扩量

报告：`evidence/ga-rollout/report.md`，用例 RO5/RO25/RO100，报告头预留：

```text
AGENTGUARD_GA_ROLLOUT_5_AT=<RFC3339>
AGENTGUARD_GA_ROLLOUT_25_AT=<RFC3339>
AGENTGUARD_GA_ROLLOUT_100_AT=<RFC3339>
```

三个时间只能在对应扩量真实发生且阶段健康证据完整后填写。
