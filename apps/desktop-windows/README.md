# AgentGuard Windows

[简体中文](README.md) | [繁體中文](README.zh-TW.md) | [English](README.en.md)

这是 AgentGuard 的 Tauri 2 Windows 客户端。它接入 Windows UI Automation、GDI 窗口抓取和 `Windows.Media.Ocr`，把观测事件交给本地规则引擎与审计层。

## 本地运行

```powershell
cd apps/desktop-windows
npm ci
npm run tauri dev
```

## 当前状态

- 原生 UIA、窗口抓取和 OCR 代码已实现，并在 Windows CI 中编译与测试。
- 尚未完成代表性 Windows 真机、RDP、权限变化和代码签名验收，因此不能把 CI 构建称为正式发布证明。
- 观测采用约 2.5 秒轮询，不是实时监控；Critical Confirm 只约束经过合作式入口的操作。
- 当前没有完整的托盘、开机恢复与通知生命周期闭环。

## 验证

```powershell
cargo test --manifest-path src-tauri/Cargo.toml
node --check src/main.js
```

平台能力与限制见 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。
