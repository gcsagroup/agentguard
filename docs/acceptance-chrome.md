[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium 扩展验收清单（Chrome / Edge）

本文档对应 Firefox 清单（[acceptance-firefox.md](acceptance-firefox.md)）的 Chromium 侧。用例编号与 Firefox
**同名同义**（F1–F8），因为两边装的是同一套内容脚本；不同的是**证据来源**：

- **C1–C5（对应 F1–F5）由真浏览器 E2E 自动产出**：`make e2e-extension` 把 `apps/extension-chromium` 原样
  作为未打包扩展装进真 Chromium（Playwright 持久化上下文），对 `eval/acceptance-fixtures/` 的固件页跑机器判据，
  结论落 `eval/e2e-extension/out/report.json`，最后一行 `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`。它不需要人，
  也**不进 release-gate**（需要 Playwright + Chromium，最小容器里没有）；CI 单独跑。
- **C6–C8（对应 F6–F8）仍是真机人工用例**：原生消息 host、DNR 规则、配额——E2E 不装宿主
  （`nativeEnabled` 默认关闭，也应当关闭），这几条只有在装了 `guard-nm-host` 的真机上才算数。

> 本清单全绿只是发布的必要非充分条件；它不能替代商店签名、发布包身份、其余平台证据或完整发布门禁。
> 它**目前不是**严格门禁的一种 `EvidenceKind`——严格门禁认的扩展证据是 Firefox 的 F1–F8。要把 Chrome 提为
> 门禁证据，需要先在 `guard-cli evidence-verify` 里加 kind，并把 `EXPECTED_EVIDENCE` 对应加一。

## E2E 到底证明了什么、没证明什么

证明了（每次运行都重新证明）：

| # | 判据（机器断言） | 对应 Firefox |
|---|------------------|--------------|
| C1 | 隐藏注入文本 → background `recent` 出现 `invisible_injection`；落盘 URL 已最小化、标题已截断（P1-1） | F1 |
| C2 | 付款 CTA 点击被**同步**拦住：页面处理器未运行、`role=alertdialog` 出现、默认焦点在「先不要」、可见文本无裸术语；「先不要」→ 仍未运行；再点 →「允许这一次」→ 处理器恰好运行一次；两次拦截各留一条 `prevented/payment_cta` | F2 |
| C3 | 陷阱语境下的 PII 表单提交被拦：URL 不变；允许一次后 URL 带上 `?phone=…`（真的提交了） | F3 |
| C4 | 页面直发 `POST /pay/checkout`：**本地服务器一个字节都没收到**就弹了确认；拒绝 → 页面拿到 `AbortError`、服务器仍未收到；允许 → 服务器收到、页面拿到 501 | F4 |
| C5 | `GET /pay/status`、`POST /api/search` 不弹、直达服务器（不误拦） | F5 |
| CM | 告警风暴回归（真机报告 P2-3，固件 `mutation-storm.html`）：页面每 50 ms 改 DOM、每秒重渲染同一段隐藏注入、页面上有个付款按钮 → 5 秒只多**一条**「最近」（M1）；注入与按钮各只报**一次**（M2）；后到的另一段注入仍会报、且只报一次（M3）；30 段突发全部计数但打包进 ≤4 条（M4，两轮扫描 ≥1.5 s）。变异检查：去掉去重 → M1–M4 红，去掉节流 → M4 红，指纹退回常量 marker → M3/M4 红 | — |
| CP | popup：默认不转发（开关未勾、文案说明）、今日计数行有数、最近列表有「已拦截：」条目、可见文本无裸术语 | — |

没证明（如实边界）：

- 跑的是容器里 Playwright 自带的 Chromium（版本见 report.json），不是用户机器上的 Chrome/Edge 正式版。
- 不装 Native Messaging 宿主；F6/F7/F8 的等价用例（C6–C8）没有自动化。
- Firefox：Playwright 不能向 Firefox 装扩展，Firefox 真 E2E 仍 **BLOCKED**，见 Firefox 清单。
- 一段在 `document_start` 之前就抓走原始 `fetch` 引用的页面脚本能绕过 fetch 门——这是 `guard-page.js` 头注里写明的边界，E2E 不声称覆盖它。
- CM 钉的是用户可见的行为（不重复、不失聪、打包）。增量扫描（只扫新增子树）与跳过自家弹层是**成本**优化，把它们关掉 CM 仍绿——E2E 不声称钉住它们。

## 前置条件（真机 C6–C8）

- [ ] Chrome 或 Edge 正式版；`chrome://extensions` → 开发者模式 → 「加载已解压」选 `apps/extension-chromium`，记下扩展 ID
- [ ] 装原生消息 host：macOS/Linux `native-host/install-host.sh --browser chrome <id>`；Windows
      `powershell -ExecutionPolicy Bypass -File native-host\install-host.ps1 -Browser chrome <id>`（Edge 用 `-Browser edge`）
- [ ] popup → 设置 → 打开「桌面转发」；link 行应显示「已连接」
- [ ] 规则集为 `crates/guard-schema/rules/p0_rules.yaml`；情报 bundle 已加载（默认基线即含 `evil.example`）

## 验收用例

| # | 步骤 | 期望 | 实测 | 证据 |
|---|------|------|------|------|
| C1–C5, CM | `make e2e-extension` | 最后一行 `AGENTGUARD_E2E_EXTENSION=PASS`，`report.json` 里 `all_pass: true`（24 条）；把 `out/report.json`、`out/f2-payment-dialog.png`、`out/m-mutation-storm.png`、`out/popup.png` 复制到 `evidence/chrome/` | | |
| C6 | 导航到 `https://evil.example/`（内置情报的恶意域） | 引擎判 `INTEL-DOMAIN` Block → 宿主回 `block_hosts` → DNR 规则装上 → 该主机后续请求在网络层被拦（Network 面板显示 blocked） | | |
| C7 | 观察 C6 的原生消息往返 | 宿主接受调用方（`chrome-extension://<id>/` origin 对上 `allowed-origin`，`guard-nm-host` 未因 origin 拒启动），判决进签名审计；popup link 行显示「已连接 · 上次成功 …」 | | |
| C8 | DNR 动态规则数量 | 未超 Chromium 的动态规则配额（装规则不报错；必要时按配额上限截断名单） | | |

## 快速命令

```bash
# 离线门禁（必须先 PASS）
make check-extension-gate

# 真浏览器 E2E（C1–C5 + CM 风暴回归 + popup）
make e2e-extension
# → eval/e2e-extension/out/report.json, f2-payment-dialog.png, m-mutation-storm.png, popup.png

# 出 Chrome 包
apps/extension-chromium/scripts/package-store.sh
```
