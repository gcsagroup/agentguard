# AgentGuard Chrome / Edge 扩展

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

这是首个 GA 的浏览器扩展实现，用于在 Chrome 和 Edge 页面中发现隐藏提示词注入、非必要个人信息字段、隐私陷阱以及付款/转账动作。匹配的高风险 DOM 点击或提交会在执行前被阻断；匹配付款路径的非 GET/HEAD 网络请求由默认启用的静态 DNR 在网络层硬阻断。

> 首个 GA 只支持 Chrome 和 Edge。Firefox 仅保留源码原型，不生成发布包，也不是首个 GA 的验收门；Safari 属于独立 Xcode/Swift 产品线。GA manifest 不包含 `nativeMessaging`，发布包不连接或携带 Native Messaging host。

## 加载未打包扩展

Chrome：

1. 打开 `chrome://extensions`。
2. 启用“开发者模式”。
3. 点击“加载已解压的扩展程序”，选择 `apps/extension-chromium`。

Edge 使用同一目录和同一个包，在 `edge://extensions` 中加载。扩展包含 `en`、`zh_CN`、`zh_TW` 三套界面资源，也支持在弹出页中覆盖系统语言。

Firefox 的 `manifest.firefox.json` 仅作为后续研发起点保留。首个 GA 不应把它临时加载、打包、提交商店或纳入验收结论。

## 打包

从仓库根目录运行：

```bash
./apps/extension-chromium/scripts/package-store.sh
```

输出 `apps/extension-chromium/dist/agentguard-extension.zip`，供 Chrome / Edge 共用。发布脚本拒绝 `--firefox`；ZIP 不包含 Native Messaging host，GA manifest 也不申请 `nativeMessaging` 权限。

## 执行前阻断

### 页面 DOM 动作

浏览器从 `document_start` 向它允许扩展进入的各个 HTTP(S) frame 注入 isolated content script；其中的付款/转账 CTA 与隐私陷阱个人信息提交会在捕获阶段同步阻断。扩展**不会在网页内提供“允许一次”、继续或重放动作的授权控件**。

页面内提示只是信息层：网页可以删除、遮挡、仿冒或影响它，所以它不是可信授权 UI，点击页面里的任何内容都不能改变阻断决定。如果用户理解风险后仍要继续，只能先进入浏览器自己的受信扩展管理界面（Chrome 的 `chrome://extensions` 或 Edge 的 `edge://extensions`），停用或移除 AgentGuard，再由用户自行重新发起原操作。首个 GA 不提供临时例外。

DOM 保护只覆盖浏览器实际注入内容脚本、且会产生可观察 click/submit 事件的 HTTP(S) frame；直接 `form.submit()`、未注入的页面/协议以及不产生被监听事件的脚本路径不在该保证内。网页能破坏的是信息提示的可见性或真实性，不能借此生成放行状态。

### 静态 DNR 网络硬阻断

静态规则集 `payment_shape_block` 仅在以下条件**同时**成立时阻断：

- URL 为 HTTP(S)；
- 方法不是 GET 或 HEAD；
- URL 路径组件以明确列出的付款标记开头并满足字符边界，或查询键 `op`、`action`、`operation` 的值明确等于这些标记：`pay`、`payment`、`checkout`、`charge`、`transfer`、`remit`、`purchase`、`orderconfirm` / `order-confirm` / `order_confirm`、`confirmorder` / `confirm-order` / `confirm_order`；路径规则还明确覆盖核心标记逐字节百分号编码与 `%2F` 分隔符；
- 浏览器把请求归类为 `xmlhttprequest`、`ping`、`main_frame` 或 `sub_frame`。

因此它覆盖声明范围内的 fetch/XHR、sendBeacon，以及顶层/子框架 form 导航。它不检查请求 body，也不覆盖只有 body 表示付款、站点自定义别名、未明确列出的编码/混淆形式、任意查询键或值、WebSocket/WebTransport、GET/HEAD 或未列出的资源类型。规则是 block-only：没有网页内批准、scope 例外或一次性网络放行。

完整边界见[浏览器执行前阻断](../../docs/浏览器执行前阻断.md)。

## 本地数据与权限

- 发现结果保存在扩展本地最近列表，不默认上传到 AgentGuard 服务器。
- URL 在进入最近列表前会去掉 userinfo、fragment 和全部 query，并把形似令牌的路径段替换为 `…`；该处理是启发式，不能保证识别所有秘密。
- 同一页里同一条发现只上报一次，页面不停变化不会刷屏；内容变化会形成新发现，扫描仍有节流与有界指纹集。
- `storage` 保存设置与最近发现；`declarativeNetRequest` 启用静态网络规则；`notifications` 在 DOM 动作已被阻断后提供浏览器拥有的信息提示；`activeTab` 支持当前标签页相关交互；HTTP(S) host 权限用于在用户访问的页面运行内容脚本。
- GA manifest 中没有 `nativeMessaging`；仓库里的 Native host 源码和模板不是首个 GA 能力，也不得作为商店文案或验收依据。

## 验证

```bash
make check-extension-gate
make e2e-extension
```

`check-extension-gate` 检查阻断逻辑、manifest、三语词条和 Chrome/Edge 打包边界。`e2e-extension` 把扩展装进 Chromium 测试环境，验证 DOM 动作不执行、旧 decision/scope 消息不能放行、静态 DNR 在请求到达服务器前阻断，以及 GET 和普通 POST 不误拦。离线和自动化通过仍不替代 Chrome / Edge 商店候选的真实浏览器安装、升级、权限提示和行为留证。

## 当前发布边界

- 首个 GA：Chrome / Edge，同一 Chromium ZIP，分别完成商店与真实浏览器验收。
- Firefox：源码原型保留；不打包、不提交、不作为首个 GA 验收门。
- Native Messaging：GA manifest 中彻底禁用；host 不随 ZIP 发布，相关原型不构成 GA 能力。
- Safari：独立产品线，不属于此扩展的首个 GA。

参见[隐私政策](../../docs/privacy-policy.md)、[商店文案草案](STORE.md)和[跨浏览器范围](../../docs/跨浏览器.md)。
