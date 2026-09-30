# AGD-032：真实网关确认回归的 CI 失败与修正

日期：2026-09-30。候选起点 `7978d3ceeab6fb70dbf05995a09d3ffeb4831d81`，修正提交 `63bdda5b5b2d516df3236af6a7bd43a90da95b35`。本记录只处理已失败的自动检查，不改变发布 No-Go 结论。

## 故障

9 月 23 日的两次 GitHub CI（[007caae](https://github.com/gcsagroup/agentguard/actions/runs/35868768044)、[7978d3c](https://github.com/gcsagroup/agentguard/actions/runs/35871166005)）均为 12 个作业成功、1 个作业失败。失败集中在 `macOS shell (native AX + SCK)` 的「真实网关确认的文件副作用回归」，桌面普通串行测试 139 项通过。CI 日志显示夹具在 `gateway_confirm.rs` 的 HTTP 状态断言失败；此前只报告了本地测试通过，漏追了远端失败。

新加的控制 HTTP 来源检查会在解析层以 400 拒绝 `Origin: https://example.com`。旧夹具把它与缺少令牌都要求为 403，混淆了“格式／来源拒绝”和“鉴权拒绝”。夹具还用了 `Host: localhost`，虽然解析层接受，网关业务层要求准确的 `127.0.0.1:<port>`，会提前拒绝，无法独立证明缺令牌路径。

## 修正与本机复验

夹具改为准确 Host，分别断言：缺令牌为 403；带正确令牌、跨站 Origin 为 400。两条都必须在待批准动作执行前拒绝；原有拒绝、批准、超时和断连后的文件读回断言保持。

使用仓库固定 Rust 工具链，先构建 `agentguard-mcp`，再按 CI 同一参数运行独立真实网关测试：`--no-default-features --features audit-sqlcipher --lib ... --include-ignored --exact`。本机结果 1 项通过、0 失败，约 4.26 秒；`cargo fmt --all --check` 与 `git diff --check` 通过。原始本机输出在 `.artifacts/source-integration-2026-09-23/ci-gateway-*-20260930.log`。

补跑软发布门禁时，本地 API 的 `/health` 测试撞上同机其他服务占用的固定 `127.0.0.1:18766`，实际读到对方的 404；原门禁为 12 通过／2 失败（全工作区与 MSRV，同一测试所致）。将五处本地 API 测试使用的固定端口改为临时空闲回环端口，不改生产服务；`guard-localapi --lib` 21 项通过。随后完整软门禁重新运行，自动检查 **14 通过／0 失败**，12 类 RC 证据仍未验证。两次门禁输出分别保留于 `.artifacts/source-integration-2026-09-23/release-gate-soft-20260930.log` 和 `release-gate-soft-20260930-portfix.log`。此处只消除了测试环境端口冲突，未宣称外部服务、正式验收或发布通过。

准确提交 `63bdda5` 已推送到 `origin/main`，GitHub [CI 36728067284](https://github.com/gcsagroup/agentguard/actions/runs/36728067284) 终态 **13／13 作业成功**；此前失败的 `macOS shell (native AX + SCK)` 也成功。此结果证明修正提交的自动检查通过，不替代固定 App 024 的新构建或原生验收。

## 发布条件

2026-09-30 只读设备清点发现一台 Android 设备（Pixel 9 Pro Fold，API 37）处于 ADB `device`，另有一台已配对 iPhone 17（iOS 26.5）处于连接状态。此前“没有在线设备”不再是这两类设备的当前事实，但尚未在它们上面安装本次发布候选或执行 A1–A4、I1–I6、TestFlight 验收。当前 keychain 未列出 Developer ID Application 身份，发布证据环境变量为空；Windows、Chrome／Edge 正式候选、签名、公证、Beta 与发布审批仍需独立证据。F13 按用户要求暂缓，固定 macOS App 024 未重建。

进一步只读核对：Pixel 上安装的是旧 `1.0.0-rc.1`／targetSdk 34；当前本地 Debug 包为 `1.1.0-dev.11`／targetSdk 36，两者签名证书摘要相同，但升级会改变该手机上的应用与已启用的无障碍服务，本轮未安装。旧已安装 APK 已拉取到本地可恢复区，未读取应用私有数据。iOS 本机没有发布 provisioning profile；Windows App 当前显示远端凭据超时（`0x1f07`），不能据此做 Windows 真机验收。

Chrome／Edge 共用 ZIP 已从当前源码在原输出路径重新打包，SHA-256 为 `46e0bfcf6639f9c0484f6e6bded710b394bc584e1800a442424f97d2680f0f4a`；24 个包文件与源码逐字节一致，manifest 为 `1.0.0.1`／`1.0.0-rc.1`，不含 `nativeMessaging`。此前本地 ZIP 已可恢复保留。原生 UI 读到 Chrome 正式版 `153.0.8010.53`，新建未登录的 `AgentGuard Chrome Acceptance` 资料（`Profile 1`），开发者模式开启；加载目录选择器可用，但因扩展请求全部 HTTP(S) 页面访问且安装本地来源扩展需要当时确认，尚未选定目录或安装。Edge App 当前版本 `153.0.4234.48`，其首次启动许可与 B1–B5 仍未处理。GitHub Release 列表为空，尚无可核实的本项目上一公开版本，B4 不能据此判 PASS。

2026-10-01 接续准备：本机 Android Gradle 首次受默认 Java 25 阻断；切到 Android Studio Java 21 后依赖仓库 TLS 握手失败，未生成新的本地 APK，旧 Debug APK 摘要保持 `c640a004…0cd85`。改从准确提交 `63bdda5` 的 CI 下载已通过 Android 作业的 Debug APK（SHA-256 `e6178cb91c9034c86dd0e26276df594757f4f6ec4ba6f1f572440e8fa644e1f4`），读回包名 `com.agentguard.companion`、`1.1.0-dev.11`、targetSdk 36。CI 默认 Debug 证书与手机上旧版不同，原包不能原位升级；另用本机既有 Debug 证书生成仅供开发验收的重签副本（SHA-256 `513ba48cb6c2ea8171ede269da40bfb4fae0d88ef330754d92a59fa9c2a3d3b5`）。其 122 个非签名文件与 CI APK 逐字节相同，签名证书摘要与旧已安装 APK 相同。此副本不是 CI 原字节或发布签名产物；是否在实体 Pixel 上更新仍待用户针对数据与无障碍服务影响确认，尚未安装。

文档提交 `4ea9bc1` 自动触发的 [CI 36744043849](https://github.com/gcsagroup/agentguard/actions/runs/36744043849) 为 **12／13 成功**，失败作业是 macOS 原生壳。桌面测试 138 通过、1 失败、11 忽略；失败用例“停止期间迟到成功回执保留完成事实但不复活任务”仍在原 8 秒期限内等不到首个模型请求。模型预检约 41 ms 完成，合成 Python 网关在模型起点约 6.119 秒后才进入脚本，到超时仍未记录 `imports_ready`。这一形状与[既有诊断](macos-ci-startup-2026-09-16.zh.md)相同；`63bdda5` 的 13／13 成功不能覆盖本次失败。本轮未改变测试期限或产品逻辑；GitHub 对失败作业的手动重跑返回仓库权限不足，失败日志保留于 `.artifacts/source-integration-2026-09-23/ci-4ea9bc1-failed.log`，间歇性启动问题保持未解决。

2026-10-01：后续隐私与 Android 网络配置提交中的 `3c4f895`、`cb34e6a` 各自远端 CI 为 13／13 成功；`ca77986` 的 [CI 36757219219](https://github.com/gcsagroup/agentguard/actions/runs/36757219219) 为 12／13，同一 macOS 桌面用例再次失败。失败日志中模型预检在 32 毫秒回复，Python 约 5.874 秒后进入，2.278 秒后完成导入，首个模型执行请求因合成夹具统一的 8 秒收件期限而超时；状态仍为 `starting`，并非 Android 网络配置触及 macOS 产品逻辑。日志保留于 `.artifacts/source-integration-2026-09-23/ci-ca77986-macos-shell.log`。

为把不同阶段分开验证，合成模型夹具现在先给网关初始化最多 15 秒，进入 `running` 后仍以原有 8 秒期限接收模型请求；停止、撤权、迟到回执的断言和产品运行时超时均未改。顺带修复本地桌面 crate 已存在的一处格式问题。本机钉住 Rust 1.95.0 的定向用例 1／1、完整桌面测试 139 通过／11 忽略、该 crate 格式与 clippy 检查均通过。修正提交 `e43e936` 的 [CI 36759324986](https://github.com/gcsagroup/agentguard/actions/runs/36759324986) 终态 **13／13 作业成功**，包含 macOS 桌面测试与真实网关确认回归。该次自动检查通过；先前间歇性故障的长期稳定性仍需后续运行观察，且不替代真实平台或发布证据。
