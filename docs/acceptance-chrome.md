[简体中文](acceptance-chrome.md) | [繁體中文](acceptance-chrome.zh-TW.md) | [English](acceptance-chrome.en.md)

# Chromium 扩展验收清单（首个 GA：Chrome / Edge）

首个 GA 的浏览器产品只有一份 Chrome / Edge 共用的 Chromium MV3 ZIP。它是 **block-only**：匹配的 DOM 动作和付款形状网络请求被阻断，网页内没有“允许一次”、临时例外或动作重放。GA manifest 不申请 `nativeMessaging`，发布 ZIP 不携带 Native host。Firefox 仅保留源码原型，不进入本清单、发布包或首个 GA 门禁。

本清单分两层：

- `make e2e-extension` 在测试 Chromium 中跑 39 条机器判据，证明源码与打包内容的阻断行为；
- Chrome 和 Edge 正式版的候选 ZIP 仍须分别完成安装、升级、权限与代表性行为留证。

自动化通过不能替代商店签名、正式浏览器、候选 ZIP 身份或其他平台发布证据。严格门禁要求 Chrome 与 Edge 各自提交结构化验收证据；一份 Chromium 测试报告不能代替两个正式浏览器的独立结果。

## 自动化验收

`make e2e-extension` 把扩展装入真 Chromium 持久化上下文，输出 `eval/e2e-extension/out/report.json` 和唯一结论标记 `AGENTGUARD_E2E_EXTENSION=PASS|FAIL`。当前 39 条用例按能力分组如下：

| 组 | 机器判据 |
|---|---|
| D0 / D0b / D0c | 默认静态规则集启用；每条 DNR 正则被浏览器接受；代表性 `POST /pay/checkout` 命中 block |
| U1 | 升级到无 Native 的 GA 后清理旧暂停、旧 host blocklist、动态 DNR 与徽章 |
| F1 / F1b | 隐藏注入进入最近列表；URL 最小化、标题截断，不落盘原始敏感 URL |
| F2a–F2f / H0 / H1 / H5 | 普通、早期捕获和开放 Shadow DOM 付款 CTA 均在页面处理器前阻断；提示只有关闭键；页面篡改不能授权或重放；每次点击仍重新阻断并留痕 |
| F3a–F3d | 隐私陷阱表单与普通子 frame 付款动作在导航/POST 前阻断；关闭提示后仍不提交 |
| F4a–F4e / H2–H4 | fetch、XHR、sendBeacon、form、明确编码与操作查询由 DNR 在服务器前阻断；旧 decision/scope 消息和旧 15 秒超时不能放行 |
| F5a–F5d | GET、普通 POST、body-only 付款语义、付款前缀普通词和嵌套查询文字不误拦 |
| M1–M4 | DOM 变异风暴去重、节流、不同新 finding 不漏报 |
| P1–P4 | GA 无 Native 权限且隐藏不可用控件；计数、最近列表和三语可见文案正确 |

运行：

```bash
make check-extension-gate
make e2e-extension
```

成功必须同时满足：进程退出 0、最后一行是 `AGENTGUARD_E2E_EXTENSION=PASS`、`report.json` 的 `all_pass` 为 `true`，且报告恰好记录当前清单期望的 39 条 PASS。报告中的 Chromium 版本必须保留；不能把它改称 Chrome 或 Edge 正式版证据。

## Chrome / Edge 候选 ZIP 人工验收

两种正式浏览器分别执行，且必须使用同一份待提交 ZIP。不要安装 Native host，不要打开任何“桌面转发”原型。

| ID | 操作 | PASS 判据 | 必留证据 |
|---|---|---|---|
| B1 | 记录 ZIP SHA-256、manifest 版本、浏览器正式版版本；解压并加载 | Chrome 与 Edge 加载的是同一 SHA-256；manifest 权限不含 `nativeMessaging`；无意外权限提示 | 哈希、版本与扩展详情页 |
| B2 | 全新 profile 安装并打开引导页、popup | 图标、三语文案、权限说明正常；Native 控件不可见；静态 `payment_shape_block` 已启用 | 引导页、popup、规则集状态 |
| B3 | 在本地夹具重做 F2、H5、F3、F4a/F4c/F4d、F5a/F5b/F5d | 付款/陷阱动作没有副作用；网络正例服务器零请求；负例到达；提示只有关闭键，关闭后仍不执行 | 页面结果、Network 和服务器计数 |
| B4 | 从上一公开版本原位升级到同一候选 ZIP | 不新增 Native 权限；旧暂停、旧动态 host 规则与旧徽章不残留；39 条自动化覆盖的代表性阻断仍成立 | 升级前后权限、storage/规则、popup |
| B5 | 禁用、重新启用、卸载；按发布回滚方案恢复上一候选 | 浏览器状态可预测，无残留页面授权状态；回滚不会被记录成当前候选 PASS | 操作记录与最终扩展状态 |

任一浏览器缺失、任一项无法判定或证据未绑定候选 ZIP 时，记录 `BLOCKED`，不得合并成“Chromium 已通过”。

分别从中央模板复制一份报告，Chrome 放在 `evidence/chrome/`，Edge 放在 `evidence/edge/`。B1–B5 必须逐项为 `PASS (native)` 且引用不同的非空证据文件；B1 证据必须记录两端共用的候选 ZIP SHA-256。完成后运行：

```bash
guard-cli manual-acceptance chrome docs/acceptance-chrome.md evidence/chrome/report.md --repo-root .
guard-cli manual-acceptance edge docs/acceptance-chrome.md evidence/edge/report.md --repo-root .
```

Chrome 报告须包含整行 `AGENTGUARD_ACCEPTANCE_CHROME=PASS`，Edge 报告须包含整行 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`。结构校验通过仍是未签名本地自证，不替代商店审核与生产下载 smoke。

## 明确边界

- DOM 保证只覆盖扩展实际注入、能产生被监听 `click` / `submit` 事件且标签可识别的 HTTP(S) frame；直接 `form.submit()`、未注入的特殊 frame、pointer/keyboard 自定义前置逻辑和浏览器外原生动作不在保证内。
- 静态 DNR 只覆盖文档声明的 HTTP(S)、非 GET/HEAD、付款关键词/编码、查询键和资源类型；不检查 body，不覆盖未列别名、双重编码、WebSocket/WebTransport 或未列资源类型。
- 页面提示是网页可影响的信息层，不是授权面。用户若坚持继续，只能在扩展管理页停用或移除保护后自行重新操作。
- Firefox 与 Safari 的任何原型、历史截图或旧验收报告都不能作为 Chrome / Edge 首个 GA 证据。

## 打包

```bash
apps/extension-chromium/scripts/package-store.sh
unzip -t apps/extension-chromium/dist/agentguard-extension.zip
shasum -a 256 apps/extension-chromium/dist/agentguard-extension.zip
```

`package-store.sh --firefox` 必须失败且不产生 Firefox ZIP；这是范围保护，不是 Firefox 验收。
