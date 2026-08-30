# Firefox 扩展真机验收清单（Launch Readiness）

本文档用于在**真实 Firefox（≥128）**上对扩展做发布前人工验收。它对应 `docs/跨浏览器.md` 里
Firefox 那几条"骨架已做、真机未验证"的项——**这些只有在真 Firefox 上跑一遍才算数**,离线自动化
和 `node --check` 都验不到。

> **前置的离线门禁**:先在仓库根跑 `make check-extension-gate`(guard-gate 逻辑 + 两份 manifest
> 结构一致)。它全绿是必要非充分条件——它证明"Chrome 与 Firefox 装同一套内容脚本、判决逻辑正确",
> 不证明"在真 Firefox 里真的拦得住"。

## 前置条件

- [ ] Firefox 版本 ≥ 128(`world: "MAIN"` 内容脚本从 128 起支持——低于它 fetch 门不加载)
- [ ] 用 `about:debugging` → 「此 Firefox」→「临时载入附加组件」加载 `manifest.firefox.json`
      (或 `package-store.sh --firefox` 出的 zip)
- [ ] 记下临时加载分配的 **gecko id**(应为 `agentguard@agentguard.dev`)
- [ ] `install-host.sh --browser firefox agentguard@agentguard.dev` 装原生消息 host
- [ ] 规则集为 `crates/guard-schema/rules/p0_rules.yaml`;情报 bundle 已加载(默认基线即含 `evil.example`)

## 验收用例

每条都在**真 Firefox** 上手动走一遍,留证据(截图 / about:debugging 控制台日志)。

| # | 步骤 | 期望 | 实测 | 证据 |
|---|------|------|------|------|
| F1 | 打开含隐藏注入文本(`[AG_INVISIBLE_TEXT]` / "ignore previous instructions")的测试页 | 扩展上报 finding(popup 最近列表出现) | | |
| F2 | 页面上放一个文案含"确认支付/Confirm Payment"的按钮,点它 | **执行前**弹出 AgentGuard 确认层("允许这一次/先不要");点「先不要」 → 动作不发生 | | |
| F3 | 一个把非必要 PII(手机号)填进陷阱控件的表单,提交 | 提交被 `preventDefault` 拦住,弹确认;取消 → 不提交 | | |
| F4 | 页面脚本 `fetch("/api/checkout",{method:"POST"})`(在页面控制台执行) | fetch 门弹确认;拒绝 → Promise reject、请求**未发出**(Network 面板无该请求) | | |
| F5 | 同 F4 但用 `GET` | **不**拦(只读方法不该有副作用) | | |
| F6 | 导航到 `https://evil.example/`(内置情报的恶意域) | 引擎判 `INTEL-DOMAIN` Block → 宿主回 `block_hosts` → DNR 规则装上 → 该主机后续请求在网络层被拦(Network 面板显示 blocked) | | |
| F7 | 观察 F6 的原生消息往返 | 宿主接受调用方(gecko id 作为 origin 对上,`guard-nm-host` 未因 origin 拒启动),判决进签名审计 | | |
| F8 | DNR 动态规则数量 | 未超 Firefox 的动态规则配额(装规则不报错;必要时按配额上限截断名单) | | |

## 这些用例分别验证 docs/跨浏览器.md 的哪条"未验证"

- F2/F3 → DOM 门在 Firefox 成立
- **F4/F5 → `world:"MAIN"` 的 fetch 门在 FF≥128 真的加载并拦截**(跨浏览器.md 明确标为待验)
- F6 → E5 引擎→DNR 桥 + F8 DNR 配额(跨浏览器.md 标为"配额待校准")
- F7 → **native host 收到的调用方标识是 gecko id 而非 chrome-extension:// origin**(跨浏览器.md 标为
  "按 MDN 写、真机未验")——这条是 fail-closed 的 origin 校验,验不过宿主会拒启动,所以它必须真机走通

## 快速命令

```bash
# 离线门禁(必须先 PASS)
make check-extension-gate

# 出 Firefox 包
apps/extension-chromium/scripts/package-store.sh --firefox

# 装 Firefox 原生消息 host(gecko id 见 manifest.firefox.json)
apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

## 签署

- 验收人:____________  版本 / commit:____________  日期:____________
- 全部用例 PASS 后,把证据目录路径导出到 `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`,再跑
  `scripts/release-gate.sh --strict` 让这条从"未验证"转为已验证。
