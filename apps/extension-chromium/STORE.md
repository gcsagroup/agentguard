# Chrome Web Store 商品页草案

简体中文 · [繁體中文](STORE.zh-TW.md) · [English](STORE.en.md)

> **草案，尚未提交或通过 Chrome Web Store 审核。** 商店文案不能作为已发布、已审核或已完成真实浏览器验收的证据。

## 名称

AgentGuard Web Shield

## 摘要

在 AI Agent 使用的网页中发现提示词注入、隐私陷阱、非必要个人信息和支付提示，并在本地记录和提醒。

## 说明

AgentGuard Web Shield 在用户访问的 HTTP/HTTPS 页面中检查：

- 隐藏文字和提示词注入标记；
- 非必要个人信息字段和隐私陷阱控件；
- 支付、转账和其他高风险按钮文字。

发现结果默认保存在扩展本地。用户安装并启用可选的 `guard-nm-host` 后，扩展会把匹配事件发送给这个独立本地进程。host 自己加载 AgentGuard 规则、执行判决并写审计库，不要求桌面 App 正在运行。

host 返回 High/Critical、Block 或需要确认的结果时，扩展会显示浏览器通知并更新徽章。这是**异步通知**：通知可能在用户操作前或后出现，但判决不与具体操作同步绑定，扩展不能暂停、撤销或阻止网页操作。引擎的暂停状态只影响后续事件判决。

## 隐私

- 默认不向 AgentGuard 服务器上传浏览历史。
- 未安装或关闭 Native Messaging host 时，发现保存在扩展本地缓冲区。
- 启用 host 后，匹配事件发送到用户本机的 `guard-nm-host`。
- host 的审计库默认是本地数据；审计签名和加密必须由用户显式配置，不能假定默认存在。
- 详见 [隐私政策](../../docs/privacy-policy.md)。

## 权限说明

- `storage`：保存开关和最近发现的本地缓冲区。
- `nativeMessaging`：可选地连接用户安装的本机 `guard-nm-host`。
- `notifications`：显示引擎返回的高风险事后通知。
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
- Critical 通知不是执行前确认或网页操作拦截。

技术说明见 [Chromium Extension README](README.md)。
