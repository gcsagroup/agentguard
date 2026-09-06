[简体中文](ga-release-gate.md) | [繁體中文](ga-release-gate.zh-TW.md) | [English](ga-release-gate.en.md)

# GA 发布闭环门禁

## 结论与层级

`scripts/release-gate.sh --strict` 只是 **RC 技术门禁**：自动检查、生产 preflight、候选冻结及 12 类签名/公证/真机验收证据。它通过只表示候选可进入 GA 收口，不表示 GA 已批准、商店已上架或用户端已在线。

`scripts/release-gate.sh --ga` 包含 RC 的 12 类证据，再要求下表 7 类 GA 闭环证据，共 19 类。Firefox 不在首个 GA 内；六个渠道是 macOS、Windows、Android、iOS、Chrome 和 Edge。任一证据缺失、过期、未绑定当前 HEAD 或结构校验失败，都是 **GA No-Go**。

## 七类 GA 证据

| kind | 环境变量 | 必需用例 | 最低真实条件 |
|---|---|---|---|
| `ga_sbom_license` | `AGENTGUARD_EVIDENCE_GA_SBOM_LICENSE` | SB1–SB4 | 六端最终交付物的 CycloneDX JSON、SPDX JSON、NOTICE 人工审查和范围对账 |
| `ga_privacy_store` | `AGENTGUARD_EVIDENCE_GA_PRIVACY_STORE` | PS1–PS6 | macOS/Windows/Android/iOS/Chrome/Edge 的隐私、权限、数据处理与商店声明和实物一致 |
| `ga_beta_14d` | `AGENTGUARD_EVIDENCE_GA_BETA_14D` | BT1–BT4 | 同一候选系列连续观察至少 `14×24` 小时，有群体、指标、事故和回滚演练记录 |
| `ga_dual_rc` | `AGENTGUARD_EVIDENCE_GA_DUAL_RC` | RC1–RC2 | 两个不同完整 Git commit 各自经过独立候选回归；RC2 必须是当前 HEAD |
| `ga_signoff` | `AGENTGUARD_EVIDENCE_GA_SIGNOFF` | SO1–SO5 | Release、QA、Security、Privacy/Legal、Operations 五个不同责任人审批同一 artifact-set SHA-256 |
| `ga_channel_smoke` | `AGENTGUARD_EVIDENCE_GA_CHANNEL_SMOKE` | CS1–CS6 | 六个真实商店/下载渠道分别完成下载、安装、首启和最小保护流程 |
| `ga_rollout` | `AGENTGUARD_EVIDENCE_GA_ROLLOUT` | RO5/RO25/RO100 | 真实扩量按 5%→25%→100% 严格递增，每阶段有健康判定和回滚决策 |

### 用例对应

- SB1 CycloneDX；SB2 SPDX；SB3 NOTICE/许可证审查；SB4 六端交付范围对账。
- PS1–PS6 依次是 macOS、Windows、Android、iOS、Chrome、Edge。
- BT1 群体与 build 绑定；BT2 完整日志/指标；BT3 稳定阈值与未解决事故；BT4 回滚、支持与事故演练。
- RC1 是第一个不可变候选的完整回归；RC2 是不同的当前 HEAD 候选的完整回归。
- SO1–SO5 依次是 Release、QA、Security、Privacy/Legal、Operations。
- CS1–CS6 依次是 macOS、Windows、Android、iOS、Chrome、Edge。
- RO5、RO25、RO100 是对应百分比的扩量事实和健康证据。

## 机器校验合同

七份报告必须位于 `evidence/ga-<kind>/report.md`，含精确行 `AGENTGUARD_GA_EVIDENCE_PROFILE=ga-v1`。每个必需用例必须恰好一行，结果列精确为 `PASS (native)`，证据列必须是对应小写 `evidence/` 目录下唯一、非空、非符号链接的仓库相对文件。`PASS (sim)`、FAIL、BLOCKED、N/A、占位符和重用路径均被拒绝。

额外机器约束：

- Beta 报告必须各含一个 `AGENTGUARD_GA_BETA_START=<RFC3339>` 和 `AGENTGUARD_GA_BETA_END=<RFC3339>`，间隔至少 14 天，结束不得晚于证据 JSON 时间。
- 双 RC 报告必须含不同的 40 位小写 `AGENTGUARD_GA_RC1_COMMIT`/`RC2_COMMIT`，且 RC2 等于门禁当前 HEAD。Git 内容寻址绑定不替代受控标签、产物仓库不可变策略或外部见证。
- SBOM 路径固定为 `delivery.cdx.json`、`delivery.spdx.json`、`NOTICE-review.md`、`scope-reconciliation.md` 和隐式纳入闭包的 `artifact-set.sha256`；JSON 必须分别含非空 CycloneDX `components` 和 SPDX `packages`，范围文件必须分别绑定清单中六端唯一最终包 SHA-256。
- 五方报告必须含 `AGENTGUARD_GA_SIGNOFF_PROFILE=five-party-v1`；五份固定路径的审批文件必须有正确角色、`APPROVED`、不同非占位身份、RFC3339 时间和相同 64 位 artifact-set SHA-256，且签字不早于当前候选、不晚于证据 JSON。
- 扩量报告必须各含一个 `AGENTGUARD_GA_ROLLOUT_5_AT`/`25_AT`/`100_AT`，时间严格递增；5% 不早于当前候选，100% 不晚于证据 JSON。

## 运行流程

1. 在已提交且 clean 的候选上运行 `scripts/release-gate.sh --strict`。
2. 按 [GA 证据模板](ga-evidence-template.md)、[Beta 手册](ga-beta-runbook.md)、[扩量手册](rollout-runbook.md)、[事故手册](incident-response.md) 和 [支持手册](support-runbook.md) 产生真实材料。`scripts/ga-sbom-license.sh generate DELIVERY_ROOT` 只扫描仓库外、含六端唯一冻结包与精确清单的交付根，并拒绝 `.`/仓库子目录。再用 `collect DELIVERY_ROOT CDX SPDX NOTICE SCOPE` 原子收集；工具、审批、范围或任一摘要缺失都会 BLOCKED。`collect` 只把清单与审查资产收进仓库，不复制六个二进制包；原 `DELIVERY_ROOT` 必须在外部不可变产物库中留存，供后续重新计算 SHA-256。
3. 对每份报告实际运行 `guard-cli manual-acceptance <ga-platform> docs/ga-release-gate.md <report> --repo-root .`，只有全部真实条件成立才把表格改为 `PASS (native)`。
4. 用 `guard-cli evidence-digest` 计算验收闭包摘要，完成 `guard-cli evidence-template --kind <kind>` 生成的故意失败 JSON，再用 `evidence-verify` 现场复核。
5. 通过环境变量传入 19 份 JSON，运行 `scripts/release-gate.sh --ga`；将日志、HEAD、产物集和证据只读归档。

## 证据边界

当前 JSON、Markdown 及关联文件是未签名的本地自证。CLI 能绑定字节、时间、当前 commit、用例集和产物摘要，但不能证明审批身份的真实性，也不能对抗能同时伪造全部文件的工作区控制者。生产必须在仓库外保留可核对的商店记录、工单/审批系统身份、可验签的签字或受信执行器证明。

`--ga` 通过只能表示“所配置的 GA 闭环材料在本次复核时通过”；它不证明商店当前仍可下载、用户端当前仍在线或系统之后仍持续健康。
