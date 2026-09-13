# 独立受保护会话：可恢复性与真实客户端验收

日期：2026-09-07。基线：`b53387e` 加本模块未提交修改。本轮未部署、发布或修改全局客户端配置。

## 结论

受保护浏览器已支持用户持有会话、Agent 独立连接、断连暂停和保留页面重连。真实 Codex CLI 与独立控制页完成了批准、拒绝和再次连接；服务器只收到批准的正文一次。这是有限任务的工程可行性证据，尚未达到“日常高可用安全产品”的完整验收标准。

## 本轮改变

- 新增 `--serve` 会话模式，由用户启动并掌握人工控制页；独立 MCP relay 连接到已存在的会话。
- Agent 操作令牌与控制页批准令牌独立生成，使用不同端口；Agent 通道只接收五种受保护工具操作，没有批准接口。配置可从控制页复制，也写入本次私有临时目录的 `agent.toml`。
- 单客户端连接与独立心跳；正常退出立即取消未批准请求，意外断连后最长约 5 秒加检查间隔暂停网页 HTTP 请求。页面保留，重新连接不重放请求、不恢复旧批准。
- 服务崩溃时先终止使用本次随机目录的浏览器主进程，再清理资料，修复扩大并发测试时偶发的目录重建问题。
- 修复控制页错误令牌无法更正、断连后旧响应可能重新显示为已连接的问题。窄屏接入入口实际检查无横向溢出。

## 验证结果

日常回归命令：

```bash
node --test apps/protected-browser/tests.mjs apps/protected-browser/lifecycle.test.mjs apps/protected-browser/transport.test.mjs apps/protected-browser/bridge.test.mjs apps/protected-browser/control-recovery.test.mjs
```

**29 个实际场景全部通过，0 失败、0 跳过。** Node 输出 31 项通过，其中包括两个父测试项。覆盖原有请求确认和旁路测试，以及权限分离、连接独占、断连取消、背景请求暂停、同页重连、心跳过期、真实 relay 进程 SIGKILL、服务失联、错误令牌更正和控制页旧响应竞态。已更新 CI 命令，未运行远端 CI。

真实客户端联合验收：

```bash
node apps/protected-browser/codex-session-check.mjs
```

- Codex CLI 0.139.0 第一个进程完成页面读取、填写、一次点击；独立控制页自动化核对正文后批准，服务器收到对应正文一次。
- 第一个客户端退出后会话保持运行、页面保留。第二个 Codex 进程重新连接同一会话，使用原页面填写另一条正文并点击一次；独立控制页拒绝，服务器总提交仍为 1 次。
- 控制页自动化与 Agent 客户端是独立通道，批准令牌未提供给 Codex。这不是“真人用户已验收”的声明。
- 另通过 Computer Use 在可见控制页实际核对并批准“可见会话批准验收”这条本机测试备注，业务页面显示 `received: true, count: 1`；连接退出后界面明确显示 Agent 未连接、网页请求暂停、页面保留。

## 可用性问题与模型连接对照

默认模型连接首次联合测试因外部连接超时未完成，未记为成功。后续联合测试虽然通过，但两个客户端分别用时约 139 和 141 秒，均记录了 WebSocket 重试。单独将 CLI 从 0.139.0 换成应用内 0.153.4 仍遇到同类超时，因此不能归因于旧版 CLI 或宣称升级即修复。

0.153.4 日志明确记录 WebSocket 失败后回退 HTTPS。使用单次测试进程中的独立模型提供方配置、选择官方支持的 HTTPS 通道后，无控制页拒绝测试通过，耗时约 43 秒，没有记录重连错误。该对照支持本机连接方式存在可改善空间；单次数据不能证明长期稳定性或普遍性能提升，也不是安全执行器自身耗时。

随后以同一 HTTPS 方式完成批准/拒绝联合验收：两个客户端分别约 49 秒和 38 秒，均未记录重连，最终业务提交仍为 1 次。网关文件任务也已单独完成真实客户端验证，见 [9 月 8 日网关验收](gateway-availability-acceptance-2026-09-08.zh.md)。

可复现的测试选项（路径按本机实际安装位置调整）：

```bash
AGENTGUARD_CODEX_BIN=/Applications/ChatGPT.app/Contents/Resources/codex AGENTGUARD_CODEX_HTTPS=1 node apps/protected-browser/codex-client-check.mjs
AGENTGUARD_CODEX_BIN=/Applications/ChatGPT.app/Contents/Resources/codex AGENTGUARD_CODEX_HTTPS=1 node apps/protected-browser/codex-session-check.mjs
```

配置依据：[OpenAI 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)。测试不覆盖内置提供方、不改全局配置、不更换模型、不读取或复制账号密钥。

## 证据

- [完整本地测试输出](../apps/protected-browser/out/test.log)
- [连接与恢复机器报告](../apps/protected-browser/out/bridge-report.json)
- [崩溃清理报告](../apps/protected-browser/out/lifecycle-report.json)
- [真实 Codex 联合报告](../apps/protected-browser/out/codex-session-report.json)
- [默认连接的联合测试记录](../apps/protected-browser/out/codex-session-0.139.0-default.json)
- 首次外部超时记录原指向本地 `apps/protected-browser/out/codex-session-timeout-2026-09-07.json`；2026-09-14 整合时未找到该文件，保留此缺失说明，不将它作为可复核的通过证据。
- [0.153.4 默认连接超时记录](../apps/protected-browser/out/codex-client-0.153.4-timeout.json)
- [0.153.4 HTTPS 无控制页测试](../apps/protected-browser/out/codex-client-0.153.4-https.json)
- [控制页窄屏入口](../apps/protected-browser/out/control-session-mobile.png)
- [30 分钟持续测试报告](../apps/protected-browser/out/soak-report.json)

上述机器报告与截图保存在本机 `out/`，不提交版本库；只含合成任务数据，操作令牌在测试输出中脱敏，批准令牌不进入客户端报告。

## 9 月 8 日持续运行补充

本机持续运行 **30 分钟、100 次循环全部通过**，测试正常结束并关闭测试会话。50 次批准对应 50 次实际提交；40 次拒绝、10 次断连取消均没有提交。同一页面在每轮重新连接后保留，旧待确认项没有复用。

循环处理耗时中位数 417 ms、P95 464 ms、最大 815 ms。这个数值包含测试控制页自动批准/拒绝与本机页面处理，不包含轮次间人为安排的等待，也不包含模型调用或真人确认时间；它不是真实网站响应速度或独立连接恢复耗时。

结果覆盖本机合成页面和本次 30 分钟窗口，未覆盖系统休眠、长期网络故障或真实站点兼容性。不能据此宣称 99.9% 可用率，也不能用这 100 次循环充当 50 个真实正常工作任务的验收。

## 仍需完成

复杂真实站点正常任务的完成率与误拦截测量、系统休眠与更长时间故障验收、桌面工作区整合、持久审计，以及真正不可绕过的系统隔离。当前没有长期可用率、正式安装升级或跨平台全面验收结果。后续按 [产品推进方案](agent-safety-viability-plan.zh.md) 执行。
