# AGD-017 远程传输与令牌边界

日期：2026-09-15。状态：远程传输组件已实现，真实 TLS 及独立 Node HTTPS 互通已验证。远程服务尚未接入生产 CLI 的登记、逐次批准、来源和持久执行日志；AGD-017 仍进行中，完整 32 项计划不变，F13 暂缓未验收。

## 已实现的行为

`guard_gateway::mcp_remote` 提供 `RemoteEndpoint`、`AccessToken` 和 `RemoteClient`。组件限定 MCP 2025-06-18 的 Streamable HTTP：初始化、initialized 通知、完整工具清单及文本工具调用，每个消息使用独立 HTTPS POST。请求声明同时接受 JSON 与 SSE，通知须返回空的 202 响应。

JSON 与 SSE 都使用原 stdio 的严格 JSON-RPC 校验，拒绝嵌套重复键、错误 id、批量消息及服务端请求。完整工具元数据保留给后续登记；内容与下游 `_meta` 在组件中仍是原始、不可信数据。输入和输出 Schema 的执行检查归现有代理层，本组件只核对名称、对象参数和基本结果结构。

SSE 处理 CR、LF、CRLF、UTF-8、分段 data、注释及 message 事件，完整响应事件到达即返回，不要求远端立即关闭连接。`id` 和 `retry` 不触发恢复或重发；分页、后台订阅、旧 HTTP+SSE 的 endpoint 事件、服务端请求、媒体／资源结果以及服务端会话均明确拒绝。遇到 `Mcp-Session-Id` 时停止该通道；不会接收会话标识后却省略后续必须的会话头。

HTTP 接受准确长度、有限 chunked 或关闭定界，不支持压缩、协议升级、chunk 扩展和 trailers。重复响应头、矛盾长度和分块、错误类型及截断均拒绝。请求上限 32 KiB，响应正文 128 KiB，头 16 KiB，总线字节 256 KiB；SSE 最多 64 个完成事件。单次 API 操作最多 30 秒，调用者可以用剩余时限覆盖整个握手／发现／调用流程。

## 网络与凭据

宿主必须提供准确 HTTPS URL、固定 IPv4 地址和专用 CA DER。实际连接直接使用该地址，TLS 按 URL 中的 DNS 名核验证书；组件不进行 DNS 解析、不读取系统代理、不跟随重定向。TLS 关闭 0-RTT 和会话恢复，不能在证书校验完成前发送授权头。

公网模式保守拒绝私网、回环、链路本地、共享地址、文档／基准网段、组播及保留地址。独立 `LoopbackTest` 模式只接受 `localhost` 与准确 `127.0.0.1`，不能放行其它私网目标。IPv6、IP 字面量 URL、用户信息、查询串、片段、编码路径及非规范端口写法当前不支持。固定地址由可信宿主维护，服务换地址需要更新配置，不能从服务正文自动获取。

令牌采用预配的 EdDSA `at+jwt`，可信公钥和 issuer 由宿主提供。验证签名、单一且准确的受众、主体、令牌标识、精确 scope 集合、签发／生效／到期时间；最长有效期一小时。当前范围为 `mcp:discover` 和 `mcp:call`，缺少、重复或额外范围均拒绝。每次实际写入前重新检查期限和当前操作范围。令牌内的 `jku` 等公钥来源、未知算法及重复声明不能替换宿主信任。

凭据只加入对应 TLS 请求的 Authorization 头，没有接受模型凭据或向另一资源透传的入口。令牌对象不实现日志调试或序列化；错误只含固定代码及派发标记。返回中的完整令牌直接回显及 Unicode 转义回显会被拒绝；这只是已验证的具体回显边界，不能证明可识别恶意服务对秘密的任意变换。

首批使用宿主预配令牌，不包含 OAuth 登录、自动元数据发现、动态注册、刷新或第三方身份提供者接入。401／403 直接结束通道，不按远端提示访问新的认证地址。这是有限测试服务配置，不宣称完整 OAuth 客户端兼容性。

## 派发与失败

原有 `DispatchGuard` 同时约束非阻塞 connect 和每次实际 TLS 写入；网络等待在锁外。调用者仍须先建立可信批准、开始审计，再安装相同撤权锁及取消回调。组件自身不产生批准，也不持久化动作。

任何 HTTP 请求字节可能发出后发生超时、断连、取消或协议错误，结果必须由产品层记为未知，不自动重试。发送初始化后通知失败也保留已派发。失败客户端不能重新初始化或继续调用。关闭客户端只关闭本地状态，不能证明远端动作已停止；远端副作用读回和网关崩溃后的未知记录仍需产品接线和实操。

## 验证

新增 7 项单元测试及 9 项真实 TCP/TLS 集成测试。集成测试覆盖正常 JSON、分块 SSE、保持连接的 SSE、重定向、错误 id、重复字段、截断、超限、压缩、令牌回显、证书名称不符、有状态服务、超时／取消、撤权锁及错误参数零新增请求。服务端独立验证签名和受众／范围／期限；证书错误测试确认零 HTTP 请求。

独立 Node HTTPS 验收使用另一套服务实现，JSON 与 SSE 各完成握手、通知、清单、实际 echo 调用，共 8 个经过服务端验签的请求，3 项检查通过。SSE 模式覆盖初始化和清单，除工具响应外也实际使用事件流。输出明确标记 `production_route=false`，下游自报可信仍保留为数据。

```sh
scripts/bootstrap-rust.sh -- cargo test -p guard-gateway --test mcp_remote
scripts/bootstrap-rust.sh -- cargo build -p guard-gateway --example mcp_remote_probe
node scripts/acceptance/agd-mcp-remote-transport.mjs \
  --out /绝对路径/全新输出目录 \
  --binary /绝对路径/target/debug/examples/mcp_remote_probe
```

最终全仓 60 组共 **1381 项通过、14 项忽略**；桌面 **122 项通过、9 项忽略**。严格 Clippy、格式、能力矩阵和三套依赖图检查通过。127 个既有保留文件、准确 010 App 的 90 个文件逐项相同，App 严格签名通过。

公开测试证书及私钥只供回环夹具使用，生产代码没有内置该信任根。记录及二进制摘要见[结构化证据](evidence/m2-remote-transport-2026-09-15.json)，原始日志保存在 `.artifacts/m2-remote-transport-2026-09-15/`。本次未构建或替换准确 Ver 1.0（010）App。

保留失败：`tls-01.log` 有 2 项通过、7 项失败。独立诊断 `tls-diagnostic.log` 记录服务夹具在零正文时收到 `WouldBlock`；macOS accept 继承监听器非阻塞标记，夹具误当断连。对接受的服务端 socket 显式使用限时阻塞流后，`tls-02.log` 9/9 通过，没有放宽客户端期限或 TLS 验证。`clippy-01.log` 为测试中未使用的导入，删除后严格检查通过。`probe-build.log` 为示例 cfg 多一个括号，修正后的独立互通通过。原始失败均保留。`node-01` 是全仓测试前的互通结果；全仓测试重新链接了默认 example 输出。之后标准构建并保存固定二进制，`node-02` 对该副本完成最终 3 项检查，不将两个摘要当成同一候选。

上一提交 `5b9fe620b91859d12bde8b6a388c84054fac1b8e` 的 [GitHub CI](https://github.com/gcsagroup/agentguard/actions/runs/34910384220) 已实查 **13/13 通过**，其中包括 MSRV 1.87；当前改动的 CI 单独核对。

下一步将远程服务配置与实际清单接入已有登记和逐次批准、绑定网络与令牌信任身份、接入来源及持久未知恢复，再完成本地与远程两类服务的产品联合验收。当前组件证据不能代替这些尚未完成的工作。

依据：[MCP 2025-06-18 传输协议](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)、[令牌受众与授权要求](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)。
