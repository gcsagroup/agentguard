# macOS 真机验收清单（Launch Readiness）

本文档用于 **真实 macOS 设备** 上的发布前人工验收。覆盖 Claude Desktop、Cursor、Chrome + 扩展三条接入路径。

> **离线自动化门禁**：在提交或打 tag 前，先在仓库根目录运行  
> `make acceptance` 或 `cargo run -p guard-cli -- acceptance-run`  
> 该命令会执行 `eval/acceptance/manifest.yaml` 中列出的离线场景，并生成 `eval/acceptance-report.json` / `eval/acceptance-report.md`。全部 PASS 是 macOS 发布的必要（非充分）条件。

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

在 **Claude Desktop / Cursor / Chrome+扩展** 三列中至少选一条主路径完成；其余列可在备注中标记 N/A。

| # | 步骤 | 期望规则 | 实测结果 | 证据（截图路径） |
|---|------|----------|----------|------------------|
| 1 | **支付确认**：在结账页触发「Complete purchase」或「请确认支付」类 UI 文本 | `CRIT-001` → Block；gated deny 时会话暂停 | | |
| 2 | **转账确认**：触发「确认转账」/ transfer 类 critical 文案 | `CRIT-001` → Block | | |
| 3 | **可选 PII**：Agent 填写非必填 DOB / 生日字段 | `PRIV-003` → Alert（form minimization） | | |
| 4 | **Trap 表单**：营销页可选「优先电话」等 trap 字段被填写 | `PRIV-004` → Alert（trap resistance） | | |
| 5 | **透明 overlay**：页面或 AX 树出现 `[AG_TRANSPARENT_OVERLAY]` 标记 | `OVL-002` → Alert | | |
| 5b | **圆角不可见区**：出现 `[AG_INVISIBLE_ZONE]` | `OVL-006` → Block | | |
| 5c | **执行前 UI 变化**：出现 `[AG_UI_REVALIDATE]` 或 `process_with_revalidate` 指纹不一致 | `UI-REVALIDATE` → Block | | |
| 6 | **Intel 注入**：UI 文本含 bundle 内 injection 模式（如 system override） | `INTEL-002` → Block | | |
| 7 | **恶意域名**：导航至 bundle 内恶意域名 | `INTEL-001` → Block | | |
| 8 | **Netmon 外泄**：大体积上传 / 未知域名外联提示（`[AG_LARGE_UPLOAD]` 或 netmon flow） | `PRIV-005` → Alert | | |
| 9 | **浏览器恶意 URL**：扩展上报恶意 URL / deeplink payload | `INTEL-001` 或等价 block | | |
| 10 | **会话暂停**：gated deny 后后续事件应 `SESSION-PAUSED` | `SESSION-PAUSED` | | |
| 11 | **SCK 探针**：运行 `cargo run -p guard-cli -- sck-probe` | 打印 `mac caps`；`sck_probe` OK 或 **权限拒绝已记录** 均可 | | |
| 12 | **AX 探针**：`cargo run -p guard-cli -- ax-probe` | `ax_probe: OK` 或明确 denied | | |
| 13 | **真机 AX**：授权辅助功能后，仪表盘「抓取前台 AX」或 `ax-snapshot` | 产出 UiTreeDelta；含填表时触发 FM/TR | | |
| 14 | **UI revalidate**：连续两次不同 UI 帧（或二次 AX 抓取时 UI 已变） | `UI-REVALIDATE` → 待确认 | | |

### SCK / TCC 说明

Screen Recording 权限未授予时，`sck_probe` 可能报错——**不算验收失败**，但必须在「实测结果」列注明「TCC 未授权」并在证据列附上终端输出截图。

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
