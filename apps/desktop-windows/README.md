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

- 候选版 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 已在 Windows 11 build 26200 上完成 RDP 交互验证：空闲运行超过 30 秒，两轮会话各超过 30 秒；UIA、GDI 和 OCR 可用，并实际触发 `OVL-010` 阻断。
- 桌面测试 5/5、Clippy、Release 构建和 CI 窗口启动 smoke 均通过。
- 候选产物仍未签名，默认 Release 未包含 SQLCipher；安装/升级/卸载、权限失败分支、Native Messaging 和完整 W1–W7 仍未验证，生产发布结论仍为 **No-Go**。
- 观测采用约 2.5 秒轮询，不是实时监控；Critical Confirm 只约束经过合作式入口的操作。
- 当前没有完整的系统托盘、开机恢复与通知生命周期闭环。

## 验证

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path src-tauri/Cargo.toml --release --locked
node --check src/main.js
```

完整的 Windows 真机补充报告：[简体中文](../../docs/acceptance-report-windows-2026-09-02.md) | [繁體中文](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md)。平台能力与限制见 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。
