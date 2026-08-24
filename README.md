# AgentGuard

Agent 安全卫士：在**合作式**网关上拦停高危操作，检测隐私过度披露与屏幕感知攻击，本地审计。

> 口径先说清：这是**旁路观测 + 合作式拦停**，不是实时、不是沙箱、不是 DLP、可以被绕过。
> 观测靠轮询（macOS 1.5 秒帧 / 2.5 秒树，Windows 2.5 秒），两次轮询之间的事看不见；
> 网关拦的是**经过它**的调用，agent 直接 exec 就绕过了（唯一不合作的一层是 Linux 上的
> guard-jail）。完整边界见 [docs/上线评估.md](docs/上线评估.md)。

## 范围与非目标（先读这段）

AgentGuard 是 **GUI agent 的旁路观测器**：盯屏幕、无障碍树、表单填写、深链、外传元数据。

**它不是沙箱，不防主机文件系统破坏。** 它拦不住 `rm -rf /`、`find "$dir" -delete`（`$dir`
为空时）这类操作——引擎里没有文件系统事件类型，`guard-shell` 没有路径范围概念（"删项目目录"
和"删整个盘"得到完全相同的判定），而且 `propose()` 只返回一个枚举值，没有 seccomp / Landlock /
sandbox-exec / 任何强制层。需要这类防护请靠操作系统：容器、VM、`sandbox-exec`、Landlock，
让 agent 物理上看不见其余磁盘。

完整的非目标清单（含 EDR、防火墙、agent 身份、Windows 真机）见
[`docs/scope-and-non-goals.md`](docs/scope-and-non-goals.md)。

## 状态

除 **Windows 真机 UIA/Capture 测试** 外，路线图已收口。当前版本 **1.0.0-rc.1** — 详见 [`docs/RELEASE-1.0.0-rc.1.md`](docs/RELEASE-1.0.0-rc.1.md) 与 [`docs/roadmap-status.md`](docs/roadmap-status.md)。

## 快速开始

```bash
cargo test --workspace
cargo run -p guard-cli -- eval --scenarios eval/scenarios
cargo run -p guard-cli -- scoreboard
cargo run -p guard-cli -- leaderboard
make coverage         # 已发布攻击面覆盖矩阵（会校验声明，未兑现的声明直接失败）
cargo run -p guard-cli -- sim-capture --confirm deny
cargo run -p guard-cli -- sck-probe
cargo run -p guard-cli -- netmon-check --flow eval/fixtures/netmon_malicious_flow.json
cargo run -p guard-cli -- billing-webhook --file eval/fixtures/billing_webhook_purchase.json --store /tmp/ag-ent.json
make check
make test-sqlcipher   # optional encrypted audit store

# 审计签名（Aura pillar iv）：生成设备密钥 → 写入签名审计 → 用带外公钥校验
make audit-keygen
make audit-signing-demo   # 演示"重算哈希链的篡改"如何被签名抓住

cd apps/desktop-macos && npm install && npm run tauri dev
```

docs: [`docs/scope-and-non-goals.md`](docs/scope-and-non-goals.md) · [`docs/sck-bridge.md`](docs/sck-bridge.md) · [`docs/acceptance-macos.md`](docs/acceptance-macos.md) · [`docs/audit-signing.md`](docs/audit-signing.md) · [`docs/android-env-survey.md`](docs/android-env-survey.md) · [`docs/frame-integrity.md`](docs/frame-integrity.md) · [`eval/coverage-matrix.md`](eval/coverage-matrix.md) · [`docs/safe-shell.md`](docs/safe-shell.md) · [`docs/paper-gap-improvements.md`](docs/paper-gap-improvements.md) · [`docs/paper-gap-iter6-review.md`](docs/paper-gap-iter6-review.md)

```bash
make acceptance
cargo run -p guard-cli -- ax-probe
cargo run -p guard-cli -- sck-probe
```

## 结构

```
crates/    … overlay ffi shell sync netmon billing …
adapters/  win mac browser android
apps/      desktop-* extension-chromium android-companion ios-webshield
```

## License

Apache-2.0
