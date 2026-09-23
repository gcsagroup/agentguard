# Chrome 正式版 B1–B5 手测记录（2026-09-22）

日期：2026-09-22。固定 macOS App 024 未重建。源码候选 ZIP 为 `apps/extension-chromium/dist/agentguard-extension.zip`，本轮 SHA-256 为 `cc85c0aeae77aa2b15c886729f53c052add4d45dfef7a52b06e3a32d72e5b0f5`，权限不含 `nativeMessaging`。

## 方法与边界

Chrome 153 已取消品牌包的 `--load-extension`。本轮在官方 `/Applications/Google Chrome.app`（`153.0.8010.52`）有头进程中，用 Playwright 的调试管道加上 `--enable-unsafe-extension-debugging`，再发 CDP `Extensions.loadUnpacked`，加载的是上述 ZIP 的解压目录，不是源码树，也不是 `chrome://extensions` 的目录选择器。这绑定当前候选包，仍不是商店安装、签名或 `AGENTGUARD_ACCEPTANCE_CHROME=PASS`。

本机没有 Microsoft Edge，Edge B1–B5 记 **BLOCKED**，不得复制 Chrome 结果。GitHub Release 仍空，上一公开版本未确认，B4 记 **N/A**。

## Chrome 结果

| ID | 状态 | 说明 |
|---|---|---|
| B1 | PASS | 正式 Chrome 153.0.8010.52 加载同一 ZIP；无 `nativeMessaging`。 |
| B2 | PASS | 空白资料：popup / onboarding 渲染；静态 `payment_shape_block` 启用；`#native-settings` 隐藏。 |
| B3 | PASS | 付款 CTA、开放 Shadow、隐私陷阱提交被拦住；`POST /pay/checkout`、beacon、form POST 未到服务器；`GET /pay/status`、`POST /api/search`、`POST /payroll` 到达。 |
| B4 | N/A | 无已确认的上一公开版本。 |
| B5 | PASS | 再启动后付款仍阻断；未加载扩展的空白资料无页面放行残留。 |

夹具为 `eval/acceptance-fixtures/` 的 `payment-cta.html`、`shadow-payment.html`、`trap-pii.html`、`fetch-gate.html`。截图在 `.artifacts/chrome-native-b15-2026-09-22/`。结构化摘要见[证据](evidence/chrome-native-b15-2026-09-22.json)。

## 明确未宣称

- 不是商店门禁 PASS，也不是测试 Chromium `make e2e-extension` 的替代声明。
- 未完成 Edge；未从上一公开版升级。
- 未把 Native Messaging 放进 GA manifest。
- 固定 App 024、完整 M1 与发布仍为 No-Go。
