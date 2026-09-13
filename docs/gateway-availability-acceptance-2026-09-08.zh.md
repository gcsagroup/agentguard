# 工具网关可用性与断连处理验收

日期：2026-09-08。基线：`b53387e` 加本次未提交改动。环境：本机 macOS、Rust 1.95.0。未部署或发布。

## 结论

本轮修复了大输出累积内存、继承输出管道导致调用迟迟不结束、客户端退出后仍等待批准，以及会话路径授权未传入引擎的问题。真实网关进程已验证授权内写读、越界拒绝、待确认退出和运行中退出。结论限定于经过本机网关的受控执行，不代表系统级防护或长期可用率。

## 修复与验证

| 问题 | 当前行为 | 实测依据 |
| --- | --- | --- |
| 文件或命令输出先全部读取再截断 | 普通文件最多读取 64 KiB 加一个判定字节；命令输出持续排空，每个流缓存上限 64 KiB，最终正文同样限长 | 256 MiB 稀疏文件、无效 UTF-8、8 MiB 模拟流，以及真实子进程 stdout/stderr 超过管道容量 |
| 文件工具可能被命名管道挂住 | Unix 非阻塞打开并核对文件类型；只读写普通文件，写入前先核对再截断 | 本次临时 FIFO 的读、写均快速返回失败 |
| 父命令退出，后代仍持有输出管道 | 每次命令建立独立进程组；结束或超时时清理同组后代；Unix 输出收集有期限 | 真实测试后代已启动，父命令结束后清理，后代完成标记未出现 |
| 超时后无法继续工作 | 命令超时返回明确错误，不自动重试；下一条命令可正常完成 | 250 ms 测试期限终止命令后，下一条调用成功 |
| 等待人工确认时无法察觉 stdio EOF | 独立输入线程感知断连；关闭确认槽位，清除待确认和已回答状态；后续请求不可复用旧批准 | 真实 MCP 二进制挂起请求后关闭 stdin，及时拒绝并退出 |
| 客户端退出，已批准命令继续运行 | 执行期间检查连接状态，断连后终止本次命令及同组后代，返回需核实结果的错误 | 批准并确认 `/bin/sleep` 实际启动后关闭 stdin；子进程已消失 |
| 启动计划只传入路径检查，未传入会话引擎 | 两处加载同一份操作员计划；明确声明任务后，授权内写读成功，越界写入仍拒绝 | 真实进程读取临时计划、开启会话、写文件、读回正文、尝试越界写入；检查实际文件结果 |
| stdio 输入无界 | 单条消息最多 1 MiB，待处理队列最多 8 条；过长、非法 UTF-8 或队列满时结束连接 | 真实进程接收超过 1 MiB、非法编码和待确认期间九条排队请求；无须客户端先关闭 stdin 即主动退出 |

## 可复现命令

```bash
./scripts/bootstrap-rust.sh -- cargo test -p guard-gateway
./scripts/bootstrap-rust.sh -- cargo test -p guard-shell -p guard-core
./scripts/bootstrap-rust.sh -- cargo clippy -p guard-gateway --all-targets -- -D warnings
```

结果：网关 42 项单元测试、5 项真实进程集成测试通过；核心引擎和路径规则共 297 项测试通过；网关所有目标的 Clippy 检查通过。测试列表中 1 项 `ignored` 是由其他测试显式启动的可控子进程入口，不是跳过的产品验收项。

还按仓库 CI 的现有入口复验桌面确认模块：4 项测试通过，其中显式启用的真实网关测试检查拒绝、批准、超时、断连和实际文件副作用。使用刚构建的本机二进制；这证明桌面确认模块与本次网关兼容，不代表重新安装或签名 App 已验收。

```bash
AGENTGUARD_GATEWAY_TEST_BIN="$PWD/target/debug/agentguard-mcp" ./scripts/bootstrap-rust.sh -- cargo test --manifest-path apps/desktop-macos/src-tauri/Cargo.toml --locked --no-default-features --features audit-sqlcipher gateway_confirm -- --include-ignored
```

输出见 [桌面确认回归日志](../apps/protected-browser/out/desktop-gateway-test.log)。

真实 Codex 文件任务使用独立测试进程和临时目录，不修改全局配置：

```bash
./scripts/bootstrap-rust.sh -- cargo build -p guard-gateway --bin agentguard-mcp
AGENTGUARD_CODEX_BIN=/Applications/ChatGPT.app/Contents/Resources/codex AGENTGUARD_CODEX_HTTPS=1 node scripts/test-codex-gateway.mjs
```

脚本核对四次工具调用：开会话、读取测试标记、写入授权目录、越界写入被拒绝。最后直接检查文件正文和越界目标未创建，再清理本次临时目录。模型连接设置沿用 [真实客户端验收](protected-browser-session-acceptance-2026-09-07.md) 的单次 HTTPS 对照方式。

本次实际通过：Codex CLI 0.153.4，四次工具调用，约 41 秒。成功正文为 `已核对：AG-GATEWAY-INPUT-7391`，越界文件不存在。单次本机合成任务不代表 50 个真实工作任务的完成率。

## 剩余边界

- 已发生的写入、外部请求等结果不能通过断连撤销；提示核实，不自动重放。普通文件和网络文件系统的 I/O 仍没有操作系统强制截止保证。
- 进程组清理仅覆盖未主动脱离本次进程组的后代。主动 `setsid`、同用户恶意进程、客户端其他执行工具以及路径检查到文件打开之间的竞争仍需要独立身份或系统隔离。
- Windows 生产执行模式继续拒绝副作用工具；本次新增的真实进程测试仅在 Unix 上运行，本轮仅实际验证 macOS。
- 网关确认服务与客户端共同退出；这与浏览器的“用户持有独立会话、Agent 断连后保留页面”不同。尚未完成统一桌面会话、持久审计与崩溃恢复。

证据保存在本机 [网关测试日志](../apps/protected-browser/out/gateway-test.log)、[核心与路径测试日志](../apps/protected-browser/out/core-shell-test.log)、[Clippy 日志](../apps/protected-browser/out/gateway-clippy.log) 和 [真实客户端报告](../apps/protected-browser/out/codex-gateway-report.json)。这些本机产物不提交版本库。后续验收以 [产品推进方案](agent-safety-viability-plan.zh.md) 为准。
