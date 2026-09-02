# Chrome Web Store 商品页草案

简体中文 · [繁體中文](STORE.zh-TW.md) · [English](STORE.en.md)

> **草案，尚未提交或通过 Chrome Web Store 审核。** 商店文案不能作为已发布、已审核或已完成真实浏览器验收的证据。

## 名称

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的网页中，于付款、隐私陷阱提交和高风险网络请求发生前提醒并等待确认，同时发现隐藏提示词注入；本地优先。

## 说明

AgentGuard Web Shield 为 AI Agent 代用户操作的页面提供三层有限防护：

- **页面内确认门**：付款/转账点击、向隐私陷阱提交个人信息，以及付款形状的 `fetch`/XHR 会先被暂停；用户选择“允许这一次”后才重放。
- **网络层名单阻断**：浏览器 DNR 会在请求发出前拦截已由威胁情报判定的恶意主机，以及当前任务明确允许表之外的主机；名单、原因与解除入口均可见。
- **页面检测**：发现隐藏/潜意识提示词注入文本、非必要个人信息字段、隐私陷阱和高风险按钮文字。

发现结果默认保存在扩展本地。用户安装并启用可选的 `guard-nm-host` 后，匹配事件会交给本地引擎判决并进入可签名的防篡改审计链；桌面 App 不必同时运行。host 判决是**异步路径**：Critical 结果只能在事件发生后发出通知，不能撤销已发生的操作；执行前控制来自页面门和成功安装的 DNR 规则。

**如实限制**：页面门只能覆盖主框架中扩展能接触到的 DOM 动作及未被页面提前保存原始引用的 `fetch`/XHR，可能被干净 iframe 或更早抓取的 API 引用绕过。DNR 安装失败时 fail-open。当前机制不能监控浏览器之外的原生 App。

## 隐私

- 默认不向 AgentGuard 服务器上传浏览历史。
- 未安装或关闭 Native Messaging host 时，发现保存在扩展本地缓冲区。
- 启用 host 后，匹配事件发送到用户本机的 `guard-nm-host`。
- host 的审计库默认是本地数据；审计签名和加密必须由用户显式配置，不能假定默认存在。
- 威胁情报更新使用 Ed25519 签名且为可选功能；生产部署必须替换仓库夹具密钥。
- 详见 [隐私政策](../../docs/privacy-policy.md)。

## 权限说明

- `storage`：保存开关和最近发现的本地缓冲区。
- `nativeMessaging`：可选地连接用户安装的本机 `guard-nm-host`。
- `declarativeNetRequest`：在请求发出前阻断名单中的恶意或越界主机。
- `notifications`：显示引擎返回的异步高风险通知。
- `activeTab`：支持与当前标签页相关的扩展交互。
- `http://*/*`、`https://*/*`：在用户访问的网页中运行内容脚本并检查 DOM。

## 本机 host 安全边界

host 除了依赖 Chrome manifest 的 `allowed_origins`，还会校验 Chrome 通过 `argv[1]` 提供的 origin。没有配置期望 origin 或值不匹配时拒绝启动；安装脚本会把扩展 origin 写到二进制旁的 `allowed-origin` 文件。

## 打包

```bash
./apps/extension-chromium/scripts/package-store.sh
```

生成的 ZIP 不包含 Native Messaging host。扩展包、host 安装方式和本地审计配置必须分别说明。

## 当前发布状态

- 未提交 Chrome Web Store 审核。
- 没有商店安装、升级或权限提示的真实浏览器验收记录。
- Native Messaging 自动安装脚本目前只支持 macOS 和 Linux；Windows 需手工安装 manifest。
- Chrome、Edge 和 Firefox 的真实商店安装及端到端执行前阻断仍需分别留证；Safari 仅有设计说明。

技术说明见 [Chromium Extension README](README.md)。
