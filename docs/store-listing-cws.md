# Chrome Web Store 上架文案草案

**扩展 ID：** （Manifest V3，`apps/extension-chromium`）  
**版本：** 与仓库 release tag 对齐 · **打包脚本：** `apps/extension-chromium/scripts/package-store.sh`

## 名称

**AgentGuard — AI Agent Safety**

## 简短描述（132 字符内）

在浏览器侧本地分析页面，配合 AgentGuard 桌面壳拦截可疑 AI 代理操作；默认不上传页面内容。

## 详细描述

AgentGuard Chromium 扩展是 AgentGuard 体系的 **浏览器适配层**：

- 在页面 DOM 侧 **本地** 运行规则与隐私探测（支付文案、表单最小化、注入标记等）
- 可选 **Native Messaging** 与桌面应用联动（用户显式安装 native host 后生效）
- 不默认将页面内容上传至厂商服务器

**打包上传：**

```bash
cd apps/extension-chromium
./scripts/package-store.sh
# 默认输出 dist/agentguard-extension.zip
```

脚本会 staging `manifest.json`、background/content/popup 与 icons；**不含** native host 二进制（单独文档说明企业部署）。

## 分类

生产力 / 开发者工具

## 权限 justification（CWS 表单）

| 权限 | 理由 |
|------|------|
| `storage` | 保存本地策略开关与会话状态 |
| `activeTab` / host access | 在当前标签页运行内容脚本做本地分析 |
| `nativeMessaging` | 可选连接用户本机 AgentGuard 桌面壳 |
| （按 manifest 实际项填写） | 与 `manifest.json` 保持一致 |

## 隐私实践 bullet（CWS）

- **本地优先分析**；无默认远程 exfiltration
- Native Messaging 仅连接用户安装的本地 host
- 不售卖用户数据；详见 [`privacy-policy.md`](privacy-policy.md)
- 单用途：AI 代理安全防护辅助

## 远程代码

- MV3 service worker；**无**远程加载可执行脚本（提交前复核 `manifest.json` CSP / wasm）

## 支持 / 隐私链接

- 隐私政策 URL：与 [`privacy-policy.md`](../privacy-policy.md) 公开页一致（占位）
- 支持邮箱：发布前填写

## 与桌面端关系

- macOS / Windows 桌面壳：**独立 SKU**，见 [`store-listing-macos.md`](store-listing-macos.md)
- 扩展 zip 通过 [`package-store.sh`](../apps/extension-chromium/scripts/package-store.sh) 生成；勿将密钥或 native host 打入 store zip

## 提交前检查

- [ ] `manifest.json` version 与 release notes
- [ ] icons 16/48/128 非占位图
- [ ] `./scripts/package-store.sh` 产出 zip 已通过 `unzip -l` 审查
- [ ] 权限声明与商店 justification 一致
- [ ] 无未披露的主机权限或 broad `<all_urls>`（若存在需说明）
