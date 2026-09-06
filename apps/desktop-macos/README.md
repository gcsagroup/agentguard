# AgentGuard macOS

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

这是 AgentGuard 的 Tauri 2 菜单栏客户端。它通过 AXUIElement、ScreenCaptureKit 与本地规则引擎观察受保护会话，并提供状态、审计和合作式 Critical Confirm。

## 本地运行

```bash
cd apps/desktop-macos
npm ci
npm run tauri dev
```

桌面观察需要用户自行授予“辅助功能”；“屏幕录制”为可选补充。加密记录和必需权限未就绪时不能开始，不能把仿真或部分观测称为完整保护。

五页工作区和四标签设置的使用步骤见[桌面说明](../../docs/desktop-guide.md)。主动防护页可安装/验证浏览器资源、生成 MCP 配置，并连接本机网关处理当前请求；不会自动修改客户端配置。见[本轮整改说明](../../docs/remediation-publication-2026-09-06.md)。

## 能力边界

- AXUIElement 树变化采用 AXObserver 推送并保留 3 秒兜底；ScreenCaptureKit 像素仍按 1.5 秒采样，因此不是零间隙实时拦截。
- 只有经过合作式网关的操作可以在执行前等待确认；直接执行可绕过网关。
- 调试构建、自动化测试或成功启动不代表已完成 Developer ID 签名、公证与真机端到端验收。
- 默认配置不启用 updater；启用前必须替换公钥与更新端点占位值。

## 验证与发布

```bash
../../scripts/bootstrap-rust.sh --install
../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
node --check src/main.js
AGENTGUARD_ALLOW_ADHOC=1 ./scripts/build-release.sh  # 仅本机 smoke
```

Release 必须显式启用 `audit-sqlcipher`；缺少该 feature 会在编译期失败。发布脚本固定使用
`--no-default-features --features audit-sqlcipher --locked`，不再提供明文 Release override。
正式脚本默认生成 Apple Silicon + Intel universal `.app`，从包内加载安全资源，并把审计加密口令与签名种子
分别存入 Keychain。可分发构建必须提供 Developer ID、预期 Team ID 与 `notarytool` Keychain profile；
ad-hoc 只用于本机 smoke，不代表 TCC 稳定、Gatekeeper 或公证通过。

发布步骤与未完成证据见 [`../../docs/macos-release.md`](../../docs/macos-release.md) 和 [`../../docs/RELEASE-1.0.0-rc.1.md`](../../docs/RELEASE-1.0.0-rc.1.md)。
