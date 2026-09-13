# 受保护浏览器任务（本地试用）

现有独立模式用于验证专用浏览器请求控制，不接管用户现有浏览器。2026-09-10 新增了由 Rust 宿主管理的统一会话：实际 HTTP 转发、持久审计、网页工具回执与 macOS 专用进程出口限制，当前只支持明确授权的 IPv4 回环 HTTP 站点。启动条件、验证与剩余边界见[统一宿主接入](../../docs/agd-012-unified-host.zh.md)。原独立模式的实施范围见[方案](../../docs/protected-browser-plan.md)。

## 运行

当前 CLI 实现 macOS/Linux 生命周期，本机已验证 macOS；其他平台尚未验收。需要 Node 22、固定的 Playwright 1.56.0 和对应 Chromium；与现有扩展 E2E 使用同一运行时。

```bash
npm install -g playwright@1.56.0
npx playwright install chromium
node apps/protected-browser/cli.mjs --demo
```

启动后：

1. 在自己的普通浏览器打开终端显示的控制页；从终端给出的私有 `control.json` 文件读取本次令牌，填入控制页连接。不要让 Agent 读取该文件。
2. 专用浏览器自动打开无害测试站点。在备注框输入文字，点击“提交测试备注”。
3. 在独立控制页查看实际目标和正文；展开“查看绑定与实际请求头”可核对会话、工具版本、策略、动作摘要和捕获的请求头。拒绝时服务器不收到提交；勾选核对后批准，原始请求才发送。修改输入框不会改变已经捕获的正文；再次提交会产生新请求，必须重新确认。
4. 控制页关闭/断连后，未批准请求在最多 5 秒的心跳期限内失效。已经发出的请求无法撤回；HTTP 回应不代表业务成功。
5. 结束任务关闭专用浏览器；终端 Ctrl+C 退出服务并删除临时控制凭据。记录仅保留在内存。

首版所有非 GET/HEAD、带查询参数的请求均需确认，因此复杂生产站点可能不可用。授权站点无查询 GET/HEAD 自动通过，并不保证没有副作用。正文仅支持最多 16 KiB 的 UTF-8 JSON、表单编码或纯文本，文件上传/二进制、WebSocket、Service Worker 和自动重定向明确不支持。WebRTC、非 HTTP 出口与外部进程没有系统强制隔离。

扩展与执行器同时生效：现有扩展对付款/陷阱表单仍只阻断，不会被控制页批准绕过。扩展加载状态来自真实浏览器 worker，不代表 Native Messaging 已接通。

每次启动复制一份扩展快照，避免工作区后续修改改变正在运行的任务。1.56.0 的后台 Worker 请求观测使用其显式实验开关，升级 Playwright 必须重新验证原型方法注册与后台出口；不能仅靠 JavaScript 覆盖注册函数。请求转发会缓冲响应，长流和大响应尚未完成资源压力验收。

## 推荐：用户持有会话，Agent 可重新连接

```bash
node apps/protected-browser/cli.mjs --serve --demo
# 明确真实授权范围时：
# node apps/protected-browser/cli.mjs --serve --origin https://已授权站点
```

1. 用户在独立控制页输入本次控制令牌。展开“连接 Agent 客户端”可复制此次会话的 Codex 接入配置；终端同时输出 `agent.toml` 路径。配置只含 Agent 操作权限，不含批准令牌。不要把 `control.json` 交给 Agent。
2. 将接入配置放入你选定的客户端配置文件，让 Agent 导航到允许的站点。在无害演示中，站点地址列于控制页“允许的站点”。这里不会自动修改全局配置。
3. Agent 客户端只能独占连接本会话；另一客户端不能抢占。确认请求仍在独立控制页逐条核对。
4. 客户端正常退出立即取消未批准请求；进程崩溃或心跳丢失后，最长约 5 秒加定时检查间隔内暂停网页请求。浏览器和页面保留，重新连接可继续查看，但旧待确认项和旧批准不会恢复，脚本不自动重放操作。
5. 会话服务自身崩溃则关闭本次浏览器并清理资料，需要由用户新建会话。已发送但结果未知的业务不能自动补发。结束时点击“结束任务并关闭浏览器”，再在启动终端 Ctrl+C 关闭服务。

此模式把客户端和控制页的生命周期分开，改善连接恢复；不建立系统级隔离。接入配置仅在本次服务运行期间有效。手工演示和旧 `--mcp` 模式仍可使用，但 `--mcp` 的客户端退出会同时结束其浏览器。

浏览器现使用与 Rust `ActionSnapshot`／`ApprovalBinding` 相同的契约 1 动作格式。批准同时绑定本次会话、动作与请求编号、工具版本、完整目标／正文／已捕获请求头、策略范围、有效期及两个单次随机值。HTTP 回答必须携带 `id`、`action_sha256`、`approval_nonce` 与决定；旧 `digest` 请求被拒绝，不能恢复旧批准。请求头只捕获一次并用于实际发送；捕获后站点 Cookie 变化不会改写已经展示的请求。控制页可见完整绑定，Agent 状态和内存摘要记录不含批准随机值、请求头和正文。

上述 `--serve` 独立模式仍由浏览器服务自行创建会话，不继承统一宿主的执行和审计能力。2026-09-09 的格式适配记录保留在[契约验收](../../docs/agd-012-browser-contract-v1.zh.md)；新宿主模式的持久回执与生命周期见[统一宿主接入](../../docs/agd-012-unified-host.zh.md)。

## MCP 接入

使用下面的 stdio 服务配置，替换为本机实际绝对路径及**用户明确允许的站点**。不要加入控制令牌。MCP 仅提供状态、导航、读取、点击、填写，没有执行脚本或批准工具。

```json
{
  "mcpServers": {
    "agentguard-browser": {
      "command": "node",
      "args": ["/Users/lazy/Projects/agent-guard/apps/protected-browser/cli.mjs", "--mcp", "--origin", "https://example.com"]
    }
  }
}
```

Codex 使用 TOML 格式。下面是供人工审阅的配置示例；请把路径和站点替换为实际授权值，写入你选定的配置文件。交互使用保留客户端工具确认。

```toml
[mcp_servers.agentguard]
command = "node"
args = ["/Users/lazy/Projects/agent-guard/apps/protected-browser/cli.mjs", "--mcp", "--origin", "https://example.com"]
required = true
default_tools_approval_mode = "prompt"
```

非交互无害测试直接使用文末复现脚本；脚本仅对自己创建的本机站点预先允许工具调用，不要据此把真实站点一律设为自动批准。

客户端若还拥有其他浏览器、命令或文件工具，就可能绕过本服务，甚至读取本机控制凭据；首版没有对抗同用户恶意进程的能力。只适合知情的本地受控试用，不能显示“全机已保护”。本机 Codex CLI 的无控制页拒绝场景已实测；其他客户端及真实业务仍需分别验证。

## 自动验收

```bash
node --test apps/protected-browser/execution-contract.test.mjs apps/protected-browser/control-binding.test.mjs apps/protected-browser/tests.mjs apps/protected-browser/lifecycle.test.mjs apps/protected-browser/transport.test.mjs apps/protected-browser/bridge.test.mjs apps/protected-browser/control-recovery.test.mjs
```

测试启动真实 Chromium、原有扩展、本机业务服务器和独立控制页，以服务器收到的请求验证阻断。缺依赖或浏览器启动失败会失败，不以跳过冒充通过。输出与截图保存在 `apps/protected-browser/out/`，不含批准令牌和真实业务内容。测试不会访问真实付款或邮件服务。


## 崩溃保护与真实客户端复现

浏览器所有直接 HTTP(S) 请求强制进入拒绝代理，只有执行器检查后才通过独立通道转发；这样调试连接突然断开不会释放未批准请求。独立守护进程在 CLI 被强制结束后，先终止使用本次随机目录的浏览器主进程，再删除临时目录，避免浏览器重建已删除资料。此机制仍不是系统网络沙箱。

可选运行 `node apps/protected-browser/codex-client-check.mjs`，需要本机已登录 Codex CLI，会消耗一次模型调用。它使用临时工作目录、忽略用户配置并关闭其他工具，只向模型提供无害本地页面；不会修改用户全局配置。测试检查五个 MCP 工具实际成功、只点击一次、服务器零提交，失败非零退出。不会自动批准真实业务。

2026-09-07 本机 Codex CLI 0.139.0 已完成导航、读取验收标记、填写、单次点击和状态读取；无控制页连接时 POST 被拒绝，服务器收到 0 条提交。

此前工具调用返回 `user cancelled MCP tool call`。仅设置通用 `approval_policy="never"` 不足；在本次无害测试命令中增加 `mcp_servers.agentguard.default_tools_approval_mode="approve"` 后通过。这只预先允许客户端调用本次测试 MCP 工具，不能批准 AgentGuard 暂停的业务请求，也没有修改全局配置或关闭客户端沙箱。配置项见 [OpenAI 官方 MCP 文档](https://learn.chatgpt.com/docs/extend/mcp)。

新增 `node apps/protected-browser/codex-session-check.mjs` 验证用户持有会话模式：两个真实 Codex CLI 进程先后连接同一会话，独立控制页的浏览器自动化分别批准和拒绝，最终只有批准的正文到达服务器一次，两次客户端退出后页面均保留。该测试消耗两轮模型调用，单轮最多等待 4 分钟；不会自动重试业务请求。它不等同于真人用户验收或 Codex 桌面端验收。

测试默认使用 PATH 中的 `codex`；可用 `AGENTGUARD_CODEX_BIN=/本机已安装的/codex` 明确指定版本做对照，无须覆盖全局安装。模型连接耗时和人工确认时间不能算成卫士执行开销。

整体推进标准见 [Agent 安全卫士可行性与可用性方案](../../docs/agent-safety-viability-plan.zh.md)。

持续运行测试不调用模型，使用本机合成页面验证同一会话的批准、拒绝、断连和重连。默认运行 30 分钟、100 次循环，结果写入 `out/soak-report.json`；每十次循环用断连取消待确认请求。

```bash
node apps/protected-browser/soak-check.mjs --minutes 30 --cycles 100
```

Rust 工具网关的真实 Codex 文件任务命令与结果见 [网关可用性验收](../../docs/gateway-availability-acceptance-2026-09-08.zh.md)。浏览器循环和文件任务都是合成验收，不能替代真实工作任务完成率。

若本机模型 WebSocket 通道反复超时，可在无害验收命令前添加 `AGENTGUARD_CODEX_HTTPS=1`，让本次模型请求直接使用 HTTPS；这不改变浏览器请求的拦截策略。版本/连接对照和限定结论见 [独立会话验收](../../docs/protected-browser-session-acceptance-2026-09-07.md)。
