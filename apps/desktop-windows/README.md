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

- 历史候选 `89dadf960a558d35dc3c6c557eadbc19d3a162d0` 曾在 Windows 11 build 26200 上完成 RDP 交互 smoke：空闲运行超过 30 秒，两轮会话各超过 30 秒；UIA、GDI 和 OCR 可用，并显示 `OVL-010` 事后风险确认。该记录只证明 `effect=observed_only`、`external_action_blocked=false` 的观察路径，不是当前候选验收，也不证明外部动作被阻断。
- 桌面测试 5/5、Clippy、Release 构建和 CI 窗口启动 smoke 均通过。
- 历史候选产物仍未签名且未包含 SQLCipher。当前源码已改为“Release 缺 `audit-sqlcipher` 就编译失败”，但新的安全 Release、签名、安装/升级/卸载、权限失败分支和 `first-ga-v1` 的 W1–W6/W8–W11 仍待 Windows 真机验证，生产发布结论仍为 **No-Go**。W7 Native Messaging 是非 GA/遗留可选项，不得为它向首个 GA 浏览器包加回权限。
- Windows Release 的审计现在必须同时具备 SQLCipher 和预检可用的签名器。自动生成的数据库口令与 Ed25519 签名种子分别只以当前用户 `agentguard-dpapi-v1` / `agentguard-signing-dpapi-v1` envelope 落盘；这不是 TPM。旧明文数据库、WAL/SHM、`audit.key` 和 `audit-signing.key` 都不会自动改写；应用会保留原文件并阻断，等待明确选择清空或迁移。
- 首个 GA 不发布 Windows gateway 的 `run_shell` / 文件副作用工具：工具清单不声明，伪造调用也会在任何副作用前失败关闭。这是避免 junction/reparse/hard-link TOCTOU 的功能收窄，不是主机级保护；绕过合作式 gateway 的直接执行仍不受它约束。
- 观测采用约 2.5 秒轮询，不是实时监控；Critical Confirm 只约束经过合作式入口的操作。
- Release 的规则、情报及公钥、任务计划、表单规则和默认展示策略直接编入 EXE，安装后不依赖源码目录、当前目录或开发环境路径变量。情报加载仍必须验签，失败时拒绝启动，不退回默认内容。
- 当前没有完整的系统托盘、开机恢复与通知生命周期闭环。

## 验证

```powershell
bash ../../scripts/bootstrap-rust.sh --install
bash ../../scripts/bootstrap-rust.sh -- cargo test --manifest-path src-tauri/Cargo.toml --locked
bash ../../scripts/bootstrap-rust.sh -- cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
node --check src/main.js
bash scripts/build-release.sh
```

`scripts/build-release.sh` 通过仓库钉住的 Rust 1.95.0 执行 `npm ci` 和 Tauri 构建，并固定
`--no-default-features --features audit-sqlcipher --locked`。直接运行未带该 feature 的
`cargo build --release` 会按设计在编译期失败；脚本产物仍需正式代码签名和真机验收。
真机验收还必须覆盖两个 envelope 的 DPAPI 当前用户绑定、正确/错误密钥、旧明文签名种子原样阻断、
DB/WAL/SHM canary、
中断恢复与升级/回滚；macOS 上的交叉编译和 SQLCipher 单测不能替代这些证据。

完整的 Windows 真机补充报告：[简体中文](../../docs/acceptance-report-windows-2026-09-02.md) | [繁體中文](../../docs/acceptance-report-windows-2026-09-02.zh-TW.md) | [English](../../docs/acceptance-report-windows-2026-09-02.en.md)。平台能力与限制见 [`../../docs/windows-observation.md`](../../docs/windows-observation.md) 和 [`../../docs/platform-matrix.md`](../../docs/platform-matrix.md)。
