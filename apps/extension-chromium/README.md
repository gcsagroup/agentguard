# AgentGuard Chromium Extension

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

这是一个 Manifest V3 扩展，用于在浏览器页面中检查隐藏/提示词注入文本、非必要个人信息字段、隐私陷阱控件和支付/转账按钮文字。发现结果默认保存在扩展本地缓冲区；安装可选 Native Messaging host 后，可把事件交给本地 AgentGuard 引擎判决。

> 能力边界：扩展异步观察 DOM 变化和页面内容。Critical/Block 结果会触发浏览器通知和徽章；通知可能在用户操作前或后出现，但判决不与具体操作同步绑定，不能暂停、撤销或阻止网页操作。

## 加载未打包扩展

1. 打开 `chrome://extensions`。
2. 启用“开发者模式”。
3. 点击“加载已解压的扩展程序”，选择 `apps/extension-chromium`。
4. 记下 Chrome 分配的扩展 ID；安装 Native Messaging host 时需要它。

扩展包含 `en`、`zh_CN`、`zh_TW` 三套界面资源，也支持在弹出页中覆盖系统语言。

## 打包

从仓库根目录运行：

```bash
./apps/extension-chromium/scripts/package-store.sh
```

默认输出为 `apps/extension-chromium/dist/agentguard-extension.zip`。脚本只打包扩展文件，不包含 Native Messaging host；上传商店前仍需完成商店审核、隐私披露和实际浏览器验收。

## 可选的独立 Native Messaging host

`guard-nm-host` 是独立本地进程：它自己加载规则、执行判决并写审计库，不要求 AgentGuard 桌面 App 正在运行。若显式把 `AGENTGUARD_AUDIT_DB` 指向同一个数据库，host 与桌面端可以使用同一审计位置；审计签名和加密仍需分别配置 `AGENTGUARD_AUDIT_SIGNING_KEY` 与 `AGENTGUARD_AUDIT_KEY`，不能假定默认已启用。

macOS / Linux 开发安装：

```bash
./apps/extension-chromium/native-host/install-host.sh <EXTENSION_ID>
```

安装脚本会：

- 构建 `guard-nm-host`；
- 写入 Chrome Native Messaging manifest；
- 把 `chrome-extension://<EXTENSION_ID>/` 写到 host 二进制旁的 `allowed-origin`。

该辅助脚本目前只支持 macOS 和 Linux。Windows 需要手工安装 Native Messaging manifest，仓库没有自动安装器。

### 调用方身份默认拒绝

Chrome manifest 的 `allowed_origins` 只约束 Chrome 自己。host 还会读取 Chrome 通过 `argv[1]` 传入的实际 origin，并与以下期望值逐字比较：

1. `AGENTGUARD_ALLOWED_ORIGIN`；或
2. 二进制旁的 `allowed-origin` 文件。

两者都没有、Chrome 未提供 origin 或值不匹配时，host 以退出码 2 拒绝启动。这可以防止任意本地进程直接执行 host 并把伪造的 `source_app` 写入审计。

## 判决与通知语义

扩展把本地发现转换为浏览器事件并异步发送给 host。host 返回 High/Critical、Block 或 `require_confirm` 判决时，扩展显示通知、更新徽章并记录最近结果。

“暂停”只表示 AgentGuard 引擎内部会拒绝后续事件；host 判决异步到达且不绑定某一次网页操作。该路径没有 approve-then-proceed 对话框，不应描述为浏览器操作拦截。

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
- 这是 DOM 启发式观察器，不是网络过滤器、浏览器沙箱或不可绕过的防护。

参见 [隐私政策](../../docs/privacy-policy.md) 和 [商店文案草案](STORE.md)。
