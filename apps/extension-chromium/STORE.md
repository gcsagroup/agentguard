# Chrome Web Store 商品页草案

简体中文 · [繁體中文](STORE.zh-TW.md) · [English](STORE.en.md)

> **草案，尚未提交或通过 Chrome Web Store 审核。** 商店文案不能作为已发布、已审核或已完成真实浏览器验收的证据。首个 GA 仅面向 Chrome / Edge；Firefox 源码原型不打包，也不作为验收门。

## 名称

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的网页中，于执行前阻断匹配的付款或隐私陷阱 DOM 动作，并硬拦已声明付款路径上的非只读网络请求；同时提示隐藏提示词注入，本地优先。

## 说明

AgentGuard Web Shield 为 Chrome / Edge 页面提供三项边界明确的有限防护：

- **DOM 动作阻断**：浏览器从 `document_start` 向允许扩展进入的各个 HTTP(S) frame 注入内容脚本；其中的付款／转账点击和隐私陷阱个人信息提交会在执行前被同步阻断。页面内没有“允许一次”、继续或重放控件。
- **付款路径网络硬拦**：默认静态 DNR 在浏览器网络层阻断符合声明范围的 HTTP(S) 非 GET/HEAD 请求，覆盖浏览器归类为 `xmlhttprequest`、`ping`、`main_frame` 或 `sub_frame` 的请求。
- **页面检测**：发现隐藏或潜意识提示词注入文本、非必要个人信息字段、隐私陷阱和高风险按钮文字，并把结果留在扩展本地最近列表。

页面内警告只是信息层。网页可以删除、遮挡、仿冒或影响它，因此它不是授权 UI，页面里的任何点击都不能放行。用户若理解风险后仍要继续，只能先在浏览器自己的受信扩展管理界面（`chrome://extensions` 或 `edge://extensions`）停用或移除 AgentGuard，再自行重新发起操作；首个 GA 不提供临时例外。

静态 DNR 仅在以下条件同时成立时硬阻断：URL 为 HTTP(S)；方法不是 GET/HEAD；路径组件以 `pay`、`payment`、`checkout`、`charge`、`transfer`、`remit`、`purchase`、`orderconfirm` / `order-confirm` / `order_confirm` 或 `confirmorder` / `confirm-order` / `confirm_order` 开头并满足字符边界，或查询键 `op`、`action`、`operation` 的值明确等于这些标记；资源类型为上述四类。路径规则还明确覆盖核心标记逐字节百分号编码与 `%2F` 分隔符。它不检查请求 body，也不覆盖 body-only 付款意图、自定义别名、未明确列出的编码/混淆形式、任意查询键或值、WebSocket/WebTransport、GET/HEAD 或其他资源类型。

**如实限制**：DOM 阻断只覆盖浏览器实际注入内容脚本、且会产生可观察 click/submit 事件的 HTTP(S) frame；直接 `form.submit()`、未注入的页面/协议及不产生被监听事件的脚本路径不在该保证内。网页可影响信息提示的可见性或真实性，但不能借此生成放行状态。静态 DNR 与 DOM 阻断都是 block-only，没有网页内批准、scope 例外或一次性放行。扩展不监控浏览器之外的原生 App。

## 隐私

- 默认不向 AgentGuard 服务器上传浏览历史或发现结果。
- 匹配结果保存在扩展本地最近列表。
- 本地记录的 URL 会被最小化：去掉 userinfo、fragment 和全部 query，并把形似令牌的路径段替换为 `…`。这是启发式保护，短令牌或嵌在普通文字里的秘密可能无法识别。
- GA manifest 不申请 `nativeMessaging`，扩展不连接本机 host。仓库中保留的 Native host 源码与模板不是首个 GA 能力，也不随商店 ZIP 发布。
- 详见[隐私政策](../../docs/privacy-policy.md)。

## 权限说明

- `storage`：保存设置和最近发现的本地缓冲区。
- `declarativeNetRequest`：默认启用已声明付款路径的静态网络硬阻断。
- `notifications`：在 DOM 动作已被阻断后显示浏览器拥有的信息通知，不作为授权入口。
- `activeTab`：支持与当前标签页相关的扩展交互。
- `http://*/*`、`https://*/*`：在用户访问的 HTTP(S) 页面中运行内容脚本并检查 DOM。

`nativeMessaging` 明确不在 GA manifest 权限中；首个 GA 不声明 Native host 判决、动态主机名单或本机审计链能力。

## 打包

```bash
./apps/extension-chromium/scripts/package-store.sh
```

该命令生成 Chrome / Edge 共用 ZIP。发布脚本拒绝 `--firefox`，ZIP 不包含 Firefox manifest 或 Native Messaging host。

## 当前发布状态

- 未提交 Chrome Web Store 或 Microsoft Edge Add-ons 审核。
- Chrome / Edge 尚需分别完成商店候选的安装、升级、权限提示和执行前阻断真实浏览器留证。
- Firefox 仅保留源码原型，不打包、不提交、不作为首个 GA 验收门。
- Native Messaging 在 GA manifest 中彻底禁用；相关原型不构成发布能力。
- Safari 是独立产品线，不属于此扩展首个 GA。

技术说明见 [Chrome / Edge 扩展 README](README.md)。
