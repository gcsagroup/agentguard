# Codex 日常代码操作验收

本目录的固定语料使用 AgentGuard 真实源码与文档。它衡量经过网关后的**操作可完成性**，不把 50 次操作称为 50 个完整编码任务。

## 无模型日常回归

```bash
./scripts/bootstrap-rust.sh -- cargo build --locked -p guard-gateway --bin agentguard-mcp
node scripts/test-gateway-normal-tasks.mjs
```

需要 Node.js 22、`rg` 和 Unix 的 `/bin/ls`。当前已实际验证 macOS；Linux CI 已配置，尚未在远端运行。

50 项操作包括：10 项文件读取、10 项字面代码搜索、10 项目录查看、8 项语法检查、2 项现有测试脚本、10 项带来源的草稿副本。每项先直接执行得到结果，再经过真实 MCP 网关执行，检查输出或实际文件。需要确认时，测试控制器只拒绝并记为 `confirmation_required`，不会自动批准。

写入仅发生在本次临时目录。越界写入负例单独验证，不混入正常操作成功率。模型账户、真人操作时间和公网服务不参与这组测试。

第一次运行把明确列举的源码保存到 `out/corpus/`；后续复用同一份内容，报告记录每个文件的 SHA-256。首次准备语料时不会复制账号密钥、整个工作区或历史产物。要测新版本语料，先保留旧 `out/` 的完整证据，再另建新的语料快照，不能把改变输入后的结果混称为同一批对照。

`out/before.json` 是 2026-09-08 修复前的本机记录：直接执行 50/50，保护内 36/50。`out/report.json` 保存当前结果和二进制摘要。默认搜索使用专门的 `search_file`；`--legacy-search` 可对照仍走通用 `rg` 命令时的行为，不能靠关闭通用命令检查提高完成率。

## 独立真实 Codex 任务

```bash
AGENTGUARD_CODEX_BIN=/Applications/ChatGPT.app/Contents/Resources/codex AGENTGUARD_CODEX_HTTPS=1 node scripts/test-codex-normal-work.mjs
```

运行五个独立客户端，分别查实现限制、检索特殊符号、修改文档副本、实际跑现有测试、修改代码副本并检查语法。验证程序检查最终文件和成功工具调用，不仅检查模型自述。结果保存在 `out/codex-work-report.json`。

这些任务已经授权修改临时副本，因此测试明确使用 Codex 的 `workspace-write` 沙箱，工作区仅为本次临时目录；其他原生工具、网络搜索和多 Agent 功能仍关闭。不修改用户全局配置，不关闭沙箱。真实工作中，客户端的任务写权限与网关计划应一致；客户端处于只读模式时，应明确停止写入，不借 MCP 绕过。

五个受控源码任务仍不足以代表真实用户的长期完成率；50 个完整日常任务及至少 95% 的目标仍需独立验收。当前内容和日志均保存在本机，`out/` 不提交版本库。
