[简体中文](acceptance-macos.md) | [繁體中文](acceptance-macos.zh-TW.md) | [English](acceptance-macos.en.md)

# macOS 真机验收清单（Launch Readiness）

本文档用于 **真实 macOS 设备** 上的发布前人工验收。覆盖 Claude Desktop、Cursor、Chrome + 扩展三条接入路径。

> **离线自动化门禁**：在提交或打 tag 前，先在仓库根目录运行
> `make acceptance` 或 `cargo run -p guard-cli -- acceptance-run`。
> 该命令会执行 `eval/acceptance/manifest.yaml` 中列出的离线场景，并生成 `eval/acceptance-report.json` / `eval/acceptance-report.md`。全部 PASS 是 macOS 发布的必要（非充分）条件。

> 本清单全绿只是发布的必要非充分条件，不能替代 Developer ID 签名、公证、发布包身份、其他平台证据或完整发布门禁。作为 `acceptance_macos` 严格门禁证据时，1、2、3、4、5、5b、5c 与 6–14 必须全部精确记录为 `PASS (native)`；`PASS (sim)`、FAIL、BLOCKED 或 N/A 都不能通过。

## 前置条件

- [ ] AgentGuard macOS Menu Bar 应用已安装并启动
- [ ] 规则集为 `crates/guard-schema/rules/p0_rules.yaml`（或发布包内等价路径）
- [ ] 威胁情报 bundle 已加载（默认 `intel/bundle.json`）
- [ ] 审计库可写（可选，用于导出证据）
- [ ] **不涉及计费**：本清单不包含 Stripe / entitlement 验收

## 平台矩阵

| 平台 | 验收方式 | 备注 |
|------|----------|------|
| Claude Desktop | Menu Bar + Accessibility 事件 | 主路径 |
| Cursor | 同上，Agent 会话内触发 | 与 Claude 共用 adapter |
| Chrome + 扩展 | Native Messaging → `guard-cli ingest-browser` 或桌面 ingest | 浏览器侧 DOM / URL 探针 |

## 验收用例

在 **Claude Desktop / Cursor / Chrome+扩展** 中至少选一条主路径完成；未选的接入路径可在备注中标记 N/A，但严格门禁要求的每个用例结果本身都不能是 N/A。

| # | 实测结果 | 证据（截图路径） | 步骤 | 期望规则 |
|---|----------|------------------|------|----------|
| 1 | | | **支付确认**：在结账页触发「Complete purchase」或「请确认支付」类 UI 文本 | `CRIT-001` → Block；gated deny 时会话暂停 |
| 2 | | | **转账确认**：触发「确认转账」/ transfer 类 critical 文案 | `CRIT-001` → Block |
| 3 | | | **可选 PII**：Agent 填写非必填 DOB / 生日字段 | `PRIV-003` → Alert（form minimization） |
| 4 | | | **Trap 表单**：营销页可选「优先电话」等 trap 字段被填写 | `PRIV-004` → Alert（trap resistance） |
| 5 | | | **透明 overlay**：页面或 AX 树出现 `[AG_TRANSPARENT_OVERLAY]` 标记 | `OVL-002` → Alert |
| 5b | | | **圆角不可见区**：出现 `[AG_INVISIBLE_ZONE]` | `OVL-006` → Block |
| 5c | | | **执行前 UI 变化**：出现 `[AG_UI_REVALIDATE]` 或 `process_with_revalidate` 指纹不一致 | `UI-REVALIDATE` → Block |
| 6 | | | **Intel 注入**：UI 文本含 bundle 内 injection 模式（如 system override） | `INTEL-002` → Block |
| 7 | | | **恶意域名**：导航至 bundle 内恶意域名 | `INTEL-001` → Block |
| 8 | | | **Netmon 外泄**：大体积上传 / 未知域名外联提示（`[AG_LARGE_UPLOAD]` 或 netmon flow） | `PRIV-005` → Alert |
| 9 | | | **浏览器恶意 URL**：扩展上报恶意 URL / deeplink payload | `INTEL-001` 或等价 block |
| 10 | | | **会话暂停**：gated deny 后后续事件应 `SESSION-PAUSED` | `SESSION-PAUSED` |
| 11 | | | **SCK 探针**：运行 `cargo run -p guard-cli -- sck-probe` | 打印 `mac caps` 且 `sck_probe` 原生可用；权限拒绝须记为 BLOCKED |
| 12 | | | **AX 探针**：`cargo run -p guard-cli -- ax-probe` | `ax_probe: OK`；权限拒绝须记为 BLOCKED |
| 13 | | | **真机 AX**：授权辅助功能后，仪表盘「抓取前台 AX」或 `ax-snapshot` | 产出 UiTreeDelta；含填表时触发 FM/TR |
| 14 | | | **UI revalidate**：连续两次不同 UI 帧（或二次 AX 抓取时 UI 已变） | `UI-REVALIDATE` → 待确认 |

### SCK / TCC 说明

Screen Recording 或 Accessibility 权限未授予时，必须在「实测结果」列记为 `BLOCKED (TCC 未授权)`，并在证据列附上终端输出或系统设置截图。BLOCKED 能如实说明环境状态，但不能冒充严格门禁要求的 `PASS (native)`；补齐权限后须重新执行对应原生用例。

## 离线场景 ↔ 清单映射

| 清单 # | manifest 场景文件 |
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
| 11 | （真机 SCK；离线无 YAML） |

Intel 注入离线场景：`intel_inject_block.yaml`（与 #6 互补）。

## 快速命令

```bash
# 离线 acceptance 门禁（必须先 PASS）
make acceptance

# 真机 TCC / SCK 探针
make sck-probe

# 导出会话审计（可选证据）
cargo run -p guard-cli -- audit-report --audit-db /path/to/audit.db
```

## 签署

| 角色 | 姓名 | 日期 | 离线 acceptance | 真机清单 |
|------|------|------|-----------------|----------|
| 开发者 | | | ☐ | ☐ |
| QA | | | ☐ | ☐ |

全部必需用例取得原生 PASS 后，把完成的报告保存为例如 `evidence/macos/report.md`。报告中每个必需 ID 必须恰好一行，第二列精确为 `PASS (native)`，第三列指向 `evidence/macos/` 下真实存在的仓库相对非空普通文件；逐项路径不得复用，且每个路径组件只能使用可移植 ASCII `[A-Za-z0-9._-]+` 并以 `/` 分隔。不能引用报告自身或当前证据 JSON 源文件，也不能经过符号链接、包含空白或 shell glob/展开字符，或越出仓库。然后生成并填写结构化 JSON：

```bash
mkdir -p evidence/macos
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
  evidence/macos/report.md --repo-root .
# 成功时唯一输出：AGENTGUARD_ACCEPTANCE_MACOS=PASS
cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/macos/report.md
cargo run -p guard-cli -- evidence-template --kind acceptance_macos \
  --commit "$commit" > evidence/macos/evidence.json

# 将上面的精确 manual-acceptance 命令、marker 与 closure 摘要填入 JSON 后
cargo run -p guard-cli -- evidence-verify --kind acceptance_macos \
  --file evidence/macos/evidence.json --commit "$commit" \
  --commit-time "$commit_time" --repo-root .
```

报告正文与 JSON `output` 都必须包含一整行 `AGENTGUARD_ACCEPTANCE_MACOS=PASS`；`artifact.sha256` 必须是 `agentguard-acceptance-closure-sha256-v1`，绑定报告原始 bytes 以及每个唯一逐项引用的路径、长度与内容。该闭包仍是未签名本地自证，不能证明截图、日志或设备记录的真实来源。再把 JSON 文件路径导出到 `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS`。目录、未填写模板或仅含 `PASS` 关键词的文件都不是证据；详见[结构化发布证据](release-evidence.md)。
