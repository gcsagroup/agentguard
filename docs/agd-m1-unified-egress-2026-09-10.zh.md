# M1 统一模型与浏览器出口接入

> 历史记录：本文只对应 candidate-01（App `9c01238a…`、网关 `5a598e5a…`）。当前候选已更新为 [Ver 1.0（006）](agd-m1-build-number-006-2026-09-11.zh.md)；下文的通过数、原生阻塞与交付归档保留为 001 当时状态，不作为 006 的验收结果。

日期：2026-09-10。状态：统一会话、任务出口和浏览器接入已完成限定入口的开发与实测；同一候选的后台联合验收通过部分门槛。**完整 M1 尚未通过，整个开发计划尚未完成。**准确 App 的原生流程、真实睡眠／唤醒和非回环系统断网恢复仍缺验收条件。计划累计 **11 项已完成、2 项阻塞、19 项待开始**，详见[开发计划](agentguard-development-plan-2026-09-09.zh.md)。

桌面本地任务现在要求用户先同意把本次任务、工作区读取结果及选启的浏览器内容发给选定本机模型。未勾选时不能启动；改变工作区、模型端口或浏览器范围后须重新勾选。模型列表探测只发送公开查询，启动后的模型请求使用独立持久日志、会话版本和有限目的地；取消会撤销旧授权，迟到的模型输出不能继续调用工具。

“受保护浏览器（可选）”入口提供环境检查和站点范围输入。当前仅支持精确的 `http://127.0.0.1:端口`，最多八个站点，不能把模型端口登记为浏览器站点。检测只使用宿主已有 Node、Playwright 1.56.0 和对应 Chromium；缺少依赖时明确拒绝启用，不在后台安装或下载。

浏览器由当前任务的宿主网关创建，共用会话、暂停和独立批准入口。浏览器工具只提供状态、导航、读取、点击和填写；每条实际 HTTP 请求先形成绑定目标和正文的批准，再由宿主发送。浏览器进程不能自己取出批准凭据，页面内容不能扩大范围。页面点击完成与服务端业务成功分别显示；请求已发出但结果不明时记录“未知”，不自动重发。

## 使用与覆盖范围

1. 在桌面“主动防护”选择工作区及只读或修改副本模式。
2. 选择本机模型。需要网页任务时展开浏览器入口，检查环境并填写明确站点。
3. 阅读并勾选模型数据授权，输入任务并启动。
4. 在独立确认区检查最终请求目标与正文，批准或拒绝；需要修改宿主文件时另行预览差异并批准回写。
5. 查看实际工具回执和业务结果。暂停会取消旧待执行动作；恢复后明确追加新任务。永久停止或关闭任务 App 会回收其网关和浏览器。

代码和命令仍在断网 Docker 工作区副本中运行。浏览器使用 macOS 进程沙箱限制原始网络出口和用户目录读取；浏览器的宿主代理仅支持上述精确回环 HTTP，不支持公网 HTTPS、DNS 目标、重定向、WebSocket 和后台 Worker。当前沙箱没有宣称隔离宿主用户目录以外的所有文件。系统解析及网页后台请求以实际探针的证据范围为准，不能把端口规则叫作域名隔离。

本机模型服务是用户选定的数据接收者；本产品限制发给该服务的请求，不限制该服务自身的文件和联网行为。敏感信息规则用于拒绝已识别的秘密格式，不承诺识别所有业务机密。第三方客户端自带的原生工具或未登记 MCP 服务不因此被纳入覆盖。

## 本轮固定候选

正式验证使用 [candidate-01 源码清单](../.artifacts/full-plan-2026-09-10/candidate-01/source-manifest.json)中的 932 个文件及其[原始归档](../.artifacts/full-plan-2026-09-10/candidate-01/source.tar.gz)。所有正式后台任务使用同一网关；旧候选的成功结果不加入本轮分母。

最终核对入口：[本轮验证总表](../.artifacts/full-plan-2026-09-10/final-validation-summary.json)、[最终交付源码清单](../.artifacts/full-plan-2026-09-10/delivery-02/source-manifest.json)及[最终源码归档](../.artifacts/full-plan-2026-09-10/delivery-02/source.tar.gz)。后者只整理测试和文档；产品代码与原候选相同。`delivery-01` 保留为末次独立文档复审前的副本。

- 网关 SHA-256：`5a598e5a9889f7576a93e5bfd155cb2f5dbaa8415b0576948be3fb3ba5bea115`。
- App 主程序 SHA-256：`9c01238ae7d70cc9ba70fe503cd7f96e3355504f43236e0718d07e972c588e78`。
- 准确入口：[AgentGuard Local Agent Test.app](../.artifacts/full-plan-2026-09-10/candidate-01/5a598e5a9889f7576a93e5bfd155cb2f5dbaa8415b0576948be3fb3ba5bea115/AgentGuard%20Local%20Agent%20Test.app)，包标识 `com.agentguard.desktop.macos.localagenttest`。完整 App 已另存，90 个包内文件及严格签名核对见[构建记录](../.artifacts/full-plan-2026-09-10/candidate-01/build-report.json)。组织签名严格验证通过，Gatekeeper 评估拒绝；未公证或发布。
- 三项真实模型测试只增加独立测试代码，其余 931 个文件与候选逐字相同；测试程序身份与回归结果见[模型及容器独立核对](../.artifacts/full-plan-2026-09-10/candidate-01/independent-model-and-container-verification.zh.md)。最终交付源码另存，测试与文档整理不会替换原候选归档。

## 同一候选的验证结果

| 范围 | 当前证据 | 边界 |
| --- | --- | --- |
| 桌面后端 | [117 项通过、7 项按条件忽略](../.artifacts/full-plan-2026-09-10/candidate-01/desktop-tests.log) | 从冻结源码执行；不把忽略项计入通过数 |
| 网关及审计 | [284 项通过、10 项按条件忽略](../.artifacts/full-plan-2026-09-10/candidate-01/gateway-audit-tests.log) | 包含撤权竞争、控制 HTTP、批准和持久回执 |
| 静态检查 | [桌面 Clippy](../.artifacts/full-plan-2026-09-10/candidate-01/desktop-clippy.log)、[网关 Clippy](../.artifacts/full-plan-2026-09-10/candidate-01/gateway-clippy.log)通过 | 既有 macOS 弃用告警保留，不是原生操作证据 |
| 桌面界面 | [124 项渲染与交互通过](../.artifacts/full-plan-2026-09-10/ui-03.log) | 使用后端桩；不能代替真实 App 或模型任务 |
| 正常完整任务 | [工作区 50/50](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/workspace-50/report.json)及[浏览器 10/10](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/browser-normal/summary.json)，联合 60/60 | 预声明的合成任务，实际文件／测试／服务端账本独立核对；批准由限定脚本执行，不代表 60 项原生人工操作 |
| 循环与断连 | [工作区 100/100](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/workspace-cycles-100/report.json)、[浏览器 100/100](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/browser-cycles-100/report.json) | 浏览器 50 批准、40 拒绝、10 断连，账本只有 50 次提交；循环不算不同完整任务 |
| 连续运行 | [30 分钟运行通过](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/soak-30min/report.json)，实测 1800.220 秒、30 个任务 | 连续存活会话每 15 秒实测，最大心跳间隔 15.763 秒；结束时本次容器零残留。真实故障任务单独计数，不把旧运行、睡眠时间或中断片段拼接入时长 |
| 文件与故障 | [78 项真实隔离检查](../.artifacts/full-plan-2026-09-10/candidate-01/source/eval/out/AGD-002/20260909T213921952Z-78342-gateway/report.json)、[13 组 50 项故障／安全负例](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/workspace-faults/report.json)通过 | 含进程退出、审计故障、过期批准、容器停止和宿主冲突；不能代替准确 App 崩溃、系统睡眠或系统断网 |
| 浏览器网络与崩溃 | [正式浏览器边界核对](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/browser-boundary-and-faults/summary.json)通过 | 实际系统解析正对照成功、受控进程拒绝；浏览器崩溃后旧批准失效、零迟到提交，新会话批准只提交一次 |
| 容器出口 | [Node/Python 及子进程 24 次网络尝试均拒绝](../.artifacts/full-plan-2026-09-10/candidate-01/independent-container-egress-02/report.json) | 七类接收计数增量为零，宿主合成凭据和控制入口不可见；IPv6 映射地址有正向校准，`::1` 仅证明容器回环 |
| 实际包内资源 | [包内浏览器完整任务](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/packaged-resources/summary.json)、[扩展阻断负例](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/packaged-resources/extension-negative/summary.json)通过 | 准确包内网关、浏览器和扩展实际启动；普通按钮处理一次，合成受保护按钮处理零次、待批准零、POST 零；未做真实支付或原生 GUI 操作 |
| 真实本地模型 | [35B 三项任务全部通过](../.artifacts/full-plan-2026-09-10/candidate-01/independent-model-and-container-verification.zh.md) | CSV 汇总 26980 分；实际失败后修复并通过三个测试；读取两页事实后提交备注一次并核账。三项不加入原 60 项分母 |
| 性能预算 | [六项预算均通过](../.artifacts/full-plan-2026-09-10/candidate-01/performance-verdict.json) | 固定 1 KiB、每路 30 次，普通网关 p95 2.10 ms、隔离网关 p95 275.01 ms；启动分别 9.46/370.98 ms，网关峰值内存 12.64/12.92 MiB。内存不含 VM、浏览器或模型 |
| 出口撤销竞态修复 | [同一两项测试：旧实现失败，修复后通过](../.artifacts/full-plan-2026-09-10/egress-revocation-regression/report.json)；[出口专项 42 项通过](../.artifacts/full-plan-2026-09-10/egress-revocation-01.log) | 撤销返回后不能新建连接或写入请求字节；撤销前已经发出的数据仍可能到达，结果按未知处理 |
| 最终文档一致性 | [仓库不变量 23/23](../.artifacts/full-plan-2026-09-10/repo-invariants-final.json)通过 | 初次发现三语能力矩阵过期，已重新生成；冻结候选的旧文档和失败日志保留，最终文档独立归档 |

开发阶段另有[真实 CLI 慢正文 7 项通过](../.artifacts/control-http-cli-20260909T211602Z/report.json)，使用旧候选 `c56518d3…`。该记录证明当时半包请求期间状态接口仍响应，只作开发对照，不加入当前候选验证或系统断网证据。

正式分母与门槛已经在[联合验收清单](agd-full-plan-acceptance-2026-09-10.zh.md)中固定：原 50 项工作区任务加 10 项浏览器任务、100 次工作区循环、至少连续 30 分钟运行，以及安全负例和准确 App 生命周期。历史候选和开发中的成功运行不拼入新候选分母。

真实模型浏览器最终一轮出现六次控件定位失败（五次填写、一次点击），模型随后恢复，实际业务只提交一次。失败工具回执与 182 行完整审计链均保留，34 组模型出口记录全部配对。当前读取接口仅返回可见正文，缺少控件信息，是已实测的可用性改进项。先前测试曾因空 Cookie 白名单、过严的“每步成功”断言，以及 `/var` 与 `/private/var` 路径别名而停止；后续固定测试分别纠正，原失败未删除。工作区 50 任务外层曾把新增日志误判为源码漂移，已按权威 932 文件清单补核，详见[循环与源码核对说明](../.artifacts/full-plan-2026-09-10/candidate-01/acceptance/egress-control-formal-acceptance-summary.json)。

## 尚未满足的门槛与接续条件

| 门槛 | 当前结论 | 接续所需条件 |
| --- | --- | --- |
| AGD-011／准确 App 流程 | 阻塞 | Mac 手动解锁后，操作上述准确 App，验证新模型授权与浏览器设置、真实确认／结果、暂停恢复、停止和关窗；旧 App 原生证据不能转移给当前版本 |
| AGD-013／F07 准确 App 崩溃 | 阻塞 | 在准确 App 的未批准／已开始阶段核对自有进程后实施，独立核对旧批准与实际副作用 |
| AGD-013／F13 系统睡眠唤醒 | 阻塞 | 可中断窗口、可靠唤醒恢复条件和系统事件记录；待批准场景跨越期限，唤醒后只允许显式新动作 |
| AGD-013／F14 系统断网恢复 | 阻塞 | 需要无生产数据的自有非回环测试服务及安全网络恢复路径。当前产品仅支持回环 HTTP，须先明确目标并扩展该受限入口，再冻结新候选验收；不能仅靠关闭 Wi-Fi 完成 |

上述缺失条件已向用户询问，尚未收到补充。若选择将 M1 改为离线／本机试点，必须由用户明确调整原门槛；本轮没有自行作此调整。依据原计划，AGD-013 未通过前不进入 M2，AGD-014～032 的 19 项仍待开始。已完成的后台验证和本机候选均保留，可从这些条件继续。

全部更改和验证都在本机进行，既有脏文件、历史候选和报告保留。本轮没有据此作出发布、公证或全平台通过的声明。
