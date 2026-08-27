# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

这是 AgentGuard 的 Tauri 2 菜单栏客户端。它通过 AXUIElement、ScreenCaptureKit 与本地规则引擎观察受保护会话，并提供状态、审计和合作式 Critical Confirm。

## 本地运行

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

首次运行需要用户自行授予“辅助功能”和“屏幕录制”权限。缺少权限时客户端必须显示降级状态，不能把仿真或部分观测称为完整保护。

## 能力边界

- AXUIElement 与 ScreenCaptureKit 原生桥接已实现；观测采用轮询，不是实时拦截。
- 只有经过合作式网关的操作可以在执行前等待确认；直接执行可绕过网关。
- 调试构建、自动化测试或成功启动不代表已完成 Developer ID 签名、公证与真机端到端验收。
- 默认配置不启用 updater；启用前必须替换公钥与更新端点占位值。

## 验证与发布

```bash
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

发布步骤与未完成证据见 [`../../docs/macos-release.md`](../../docs/macos-release.md) 和 [`../../docs/RELEASE-1.0.0-rc.1.md`](../../docs/RELEASE-1.0.0-rc.1.md)。
