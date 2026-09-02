# AgentGuard Chromium Extension

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

这是一个 Manifest V3 扩展，用于检查隐藏/提示词注入文本、非必要个人信息字段、隐私陷阱和支付/转账动作。它会在页面内同步拦住匹配的点击、提交及付款形状 `fetch`/XHR，等待用户选择；还可通过 DNR 在请求发出前阻止已判定的恶意或越界主机。发现结果默认保存在扩展本地缓冲区；安装可选 Native Messaging host 后，可把事件交给本地 AgentGuard 引擎判决和审计。

> 能力边界：页面门只能覆盖扩展能接触到的主框架 DOM 动作及未被页面提前保存原始引用的 `fetch`/XHR；它不是不可绕过的浏览器沙箱。Native Messaging 判决仍是异步路径，只能通知并影响后续状态；真正的执行前控制来自页面门与已成功安装的 DNR 规则。

## 加载未打包扩展

1. 打开 `chrome://extensions`。
2. 启用“开发者模式”。
3. 点击“加载已解压的扩展程序”，选择 `apps/extension-chromium`。
4. 记下 Chrome 分配的扩展 ID；安装 Native Messaging host 时需要它。

Edge 使用同一目录和包，在 `edge://extensions` 中加载。Firefox 128+ 在 `about:debugging#/runtime/this-firefox` 中选择“临时载入附加组件”，打开 `manifest.firefox.json`；Firefox 移植仍需真实浏览器验收。

扩展包含 `en`、`zh_CN`、`zh_TW` 三套界面资源，也支持在弹出页中覆盖系统语言。

## 打包

从仓库根目录运行：

```bash
./apps/extension-chromium/scripts/package-store.sh
./apps/extension-chromium/scripts/package-store.sh --firefox
```

默认输出 Chrome/Edge 包 `agentguard-extension.zip`；`--firefox` 输出 `agentguard-extension-firefox.zip`。脚本不包含 Native Messaging host；上传商店前仍需完成对应商店审核、隐私披露和真实浏览器验收。

## 可选的独立 Native Messaging host

`guard-nm-host` 是独立本地进程：它自己加载规则、执行判决并写审计库，不要求 AgentGuard 桌面 App 正在运行。若显式把 `AGENTGUARD_AUDIT_DB` 指向同一个数据库，host 与桌面端可以使用同一审计位置；审计签名和加密仍需分别配置 `AGENTGUARD_AUDIT_SIGNING_KEY` 与 `AGENTGUARD_AUDIT_KEY`，不能假定默认已启用。

macOS / Linux 开发安装：

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
# Edge
./apps/extension-chromium/native-host/install-host.sh --browser edge <EXTENSION_ID>
# Firefox
./apps/extension-chromium/native-host/install-host.sh --browser firefox agentguard@agentguard.dev
```

安装脚本会：

- 构建 `guard-nm-host`；
- 写入 Chrome Native Messaging manifest；
- 把 `chrome-extension://<EXTENSION_ID>/` 写到 host 二进制旁的 `allowed-origin`。

该辅助脚本目前只支持 macOS 和 Linux，并会按目标浏览器写入正确的允许调用方格式。Windows 需要手工安装 Native Messaging manifest，仓库没有自动安装器。

### 调用方身份默认拒绝

Chrome manifest 的 `allowed_origins` 只约束 Chrome 自己。host 还会读取 Chrome 通过 `argv[1]` 传入的实际 origin，并与以下期望值逐字比较：

1. `AGENTGUARD_ALLOWED_ORIGIN`；或
2. 二进制旁的 `allowed-origin` 文件。

两者都没有、Chrome 未提供 origin 或值不匹配时，host 以退出码 2 拒绝启动。这可以防止任意本地进程直接执行 host 并把伪造的 `source_app` 写入审计。

## 执行前门、网络规则与异步判决

页面门在捕获阶段对付款 CTA、隐私陷阱表单及付款形状 `fetch`/XHR 执行本地同步判断：先阻止动作，用户选择“允许这一次”后才重放。DNR 根据引擎返回的恶意主机以及会话允许表产生规则，在匹配请求发出前阻断，并在 popup 中提供原因和解除入口。

扩展也会把发现异步发送给 host。host 返回 High/Critical、Block 或 `require_confirm` 时会显示通知、更新徽章并写入最近结果；“暂停”只表示引擎会拒绝后续事件。该异步路径不能撤销已经发生的网页动作，也不能冒充页面门的 approve-then-proceed。

host 未安装、未注册或被关闭时，发现仍保存在扩展的本地缓冲区，但不会得到引擎判决。弹出页中的“转发到本机守护”开关可以关闭 Native Messaging。

## 离线载荷检查

从仓库根目录运行：

```bash
cargo run -p guard-cli -- ingest-browser \
  --payload eval/fixtures/browser_extension_payload.json
```

## 隐私与限制

- 默认不把浏览历史上传到 AgentGuard 服务器。
- 启用 Native Messaging 后，匹配的页面发现会发给本机 host；host 的审计存储位置和保护方式由本机配置决定。
- 扩展有 `http://*/*` 与 `https://*/*` host 权限，用于在用户访问的页面执行内容脚本。
- 页面门是尽力而为的客户端控制：提前保存的原始 `fetch`、干净 iframe、跨框架动作或原生应用行为可能绕过它。
- DNR 安装失败时会如实 fail-open；Chrome、Edge、Firefox 仍需分别完成真实浏览器验收，Safari 目前只有设计说明。

参见 [隐私政策](../../docs/privacy-policy.md) 和 [商店文案草案](STORE.md)。
