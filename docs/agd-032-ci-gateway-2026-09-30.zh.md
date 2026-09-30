# AGD-032：真实网关确认回归的 CI 失败与修正

日期：2026-09-30。候选起点 `7978d3ceeab6fb70dbf05995a09d3ffeb4831d81`。本记录只处理已失败的自动检查，不改变发布 No-Go 结论。

## 故障

9 月 23 日的两次 GitHub CI（[007caae](https://github.com/gcsagroup/agentguard/actions/runs/35868768044)、[7978d3c](https://github.com/gcsagroup/agentguard/actions/runs/35871166005)）均为 12 个作业成功、1 个作业失败。失败集中在 `macOS shell (native AX + SCK)` 的「真实网关确认的文件副作用回归」，桌面普通串行测试 139 项通过。CI 日志显示夹具在 `gateway_confirm.rs` 的 HTTP 状态断言失败；此前只报告了本地测试通过，漏追了远端失败。

新加的控制 HTTP 来源检查会在解析层以 400 拒绝 `Origin: https://example.com`。旧夹具把它与缺少令牌都要求为 403，混淆了“格式／来源拒绝”和“鉴权拒绝”。夹具还用了 `Host: localhost`，虽然解析层接受，网关业务层要求准确的 `127.0.0.1:<port>`，会提前拒绝，无法独立证明缺令牌路径。

## 修正与本机复验

夹具改为准确 Host，分别断言：缺令牌为 403；带正确令牌、跨站 Origin 为 400。两条都必须在待批准动作执行前拒绝；原有拒绝、批准、超时和断连后的文件读回断言保持。

使用仓库固定 Rust 工具链，先构建 `agentguard-mcp`，再按 CI 同一参数运行独立真实网关测试：`--no-default-features --features audit-sqlcipher --lib ... --include-ignored --exact`。本机结果 1 项通过、0 失败，约 4.26 秒；`cargo fmt --all --check` 与 `git diff --check` 通过。原始本机输出在 `.artifacts/source-integration-2026-09-23/ci-gateway-*-20260930.log`。远端仍需对修正提交重新跑 CI，不能以本机通过代替。

补跑软发布门禁时，本地 API 的 `/health` 测试撞上同机其他服务占用的固定 `127.0.0.1:18766`，实际读到对方的 404；原门禁为 12 通过／2 失败（全工作区与 MSRV，同一测试所致）。将五处本地 API 测试使用的固定端口改为临时空闲回环端口，不改生产服务；`guard-localapi --lib` 21 项通过。随后完整软门禁重新运行，自动检查 **14 通过／0 失败**，12 类 RC 证据仍未验证。两次门禁输出分别保留于 `.artifacts/source-integration-2026-09-23/release-gate-soft-20260930.log` 和 `release-gate-soft-20260930-portfix.log`。此处只消除了测试环境端口冲突，未宣称外部服务、正式验收或发布通过。

## 发布条件

2026-09-30 只读设备清点发现一台 Android 设备（Pixel 9 Pro Fold，API 37）处于 ADB `device`，另有一台已配对 iPhone 17（iOS 26.5）处于连接状态。此前“没有在线设备”不再是这两类设备的当前事实，但尚未在它们上面安装本次发布候选或执行 A1–A4、I1–I6、TestFlight 验收。当前 keychain 未列出 Developer ID Application 身份，发布证据环境变量为空；Windows、Chrome／Edge 正式候选、签名、公证、Beta 与发布审批仍需独立证据。F13 按用户要求暂缓，固定 macOS App 024 未重建。
