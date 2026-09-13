# M1 浏览器 HTTP 等待修复与 Ver 1.0（009）验收

日期：2026-09-11。状态：**009 已冻结、构建并通过严格组织签名核验，但完整浏览器矩阵发现草稿编辑回归，正常流程未通过，进入 010 修复；尚未发布。** 008 原生实测中，文件交付通过，但浏览器在 HTTP 待确认期间仍继续运行并再次请求提交。重复请求未获批准且未到达站点；该失败见 [008 原生记录](agd-m1-confirm-expiry-008-2026-09-11.zh.md)，不以最终只有一条业务记录掩盖正常流程失败。

## 修改与原因

1. 桌面模型每次派发工具和进入下一轮推理前，从独立控制面检查当前会话的 HTTP 请求及回执。请求未结束就等待；拒绝、取消、超时和 HTTP 失败会停止本轮，未知结果禁止继续或恢复。普通测试失败仍可修复后重测。
2. 模型同步调用保留 Playwright 的点击处理收尾与导航信号等待；浏览器同时从读取请求头之前就跟踪已观测到的请求。桌面调用等待这些请求完成登记、批准和回执处理，再消费独立宿主回执。此前 `noWaitAfter` 跳过了输入收尾，单独增加请求跟踪仍会偶发提前返回，后续联合测试再次捕获并修正。此等待不证明业务成功，也不声称涵盖网页未来才触发的定时事件。
3. 网关发现已有 HTTP 请求未结束时，拒绝后续点击、填写和导航；状态查询与只读检查保留。每条 HTTP 请求仍独立绑定目标、正文、会话与一次批准；模型不能通过工具参数关闭桌面的等待要求。

旧网关缺少新增等待字段时，普通控制面仍可查看；开启本地模型浏览器任务则必须取得完整等待证据，不能把缺失当成零请求。固定打包入口继续使用 `AgentGuard Local Agent Test.app`；本次源码构建号递增为 `9`，基础发布版本仍为 `1.0.0-rc.1`。

## 失败保留与验证

| 检查 | 当前证据 |
| --- | --- |
| 原实现的模型调度问题 | [3 项原始失败](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/red-result.json)：等待期间继续推理、拒绝后继续工具、暂停前放过后续工具 |
| 原网关的再次点击 | [真实 Chromium 失败日志](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/red-real-browser.log)：008 网关仍允许再次点击；该请求未获批准 |
| 首次联合修复不足 | [实际登记时序失败](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/real-joint-01/report.json)：仅轮询控制面仍会在几毫秒窗口放过同批下一步，保留失败后加入浏览器请求跟踪 |
| 桌面源码回归 | [122 项通过，9 项显式忽略](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/desktop-all-tests-final.log)；包含批准、拒绝、503、超时、取消、未知以及暂停后的迟到结果 |
| 网关与审计源码回归 | [289 项通过，10 项显式忽略](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/gateway-audit-tests-rustup.log)。首次运行的三个失败由子进程选中损坏的 Homebrew Rust 引起；仅修正本次测试的工具链路径后通过，原日志保留 |
| 浏览器相关回归 | [最终 5 项通过](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/browser-related-input-fence.log)：真实 Chromium 请求控制、再次动作拒绝、断连及已有控件行为 |
| 点击处理收尾缺口 | [再次出现的联合失败](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/real-joint-audit-final/report.json)：已增加请求跟踪后仍提前进入同批只读步骤，因此保留失败并恢复模型调用的输入收尾等待 |
| 生产调度器与真实浏览器联合 | [修后连续 20 轮通过](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/fix-summary.json)：每轮待批准时后续工具和模型均未继续；批准后只提交一次；新一轮拒绝后停止，站点零新增请求。每轮三份审计分别为 3、23、10 条，均已逐事件验链。该测试使用可控模型和脚本批准，不计为真实模型或原生 App 任务 |

原审计采集只复制主 DB，曾遗漏仍在 WAL 中的模型事件；[失败记录](../.artifacts/full-plan-2026-09-10/browser-http-barrier-fix/joint-audit-verified/failure.json)保留。采集现先停止任务并关闭模型客户端，确认无 WAL 后做只读一致备份，将归档副本转为独立主文件，再核对表、事件数、内容摘要和完整哈希链。最初冻结的 `candidate-09-browser-http` 已标记不可用于验收，后续构建使用重新核验的 `candidate-09-browser-http-final`。

## 冻结候选与实际包

[重新冻结的源码](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/source-manifest.json)含 941 个文件；23 项仓库不变量通过。[构建记录](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/build-report.json)核对固定路径 App 的基础版本 `1.0.0-rc.1`、构建号 `9`、编译来源、90 个包文件及内嵌网关。旧 008 整包已逐文件核对并保留。

- 固定入口：`apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard Local Agent Test.app`。
- App 主程序 SHA-256：`5c02a63c6b104d64bf6945b9ef06460fb4a06f0c677145c986f0aca8da544ba0`。
- 网关 SHA-256：`83e67144c004965d6ac4170e2eb731bc0ac3849e4fb1567b78194294833ee3c5`。
- 严格签名核验通过，组织为 Global Cybersecurity Alliance Limited，Team ID `R3JK7R29AC`；这仍是本机内部候选，Gatekeeper 返回 3，未完成 Developer ID 公证或外发。

冻结源码已重新通过桌面回归 122 项、网关与审计回归 289 项；分别有 9、10 项显式忽略，不能算已执行。界面桩检查 124 项通过，目视核对总览、窄窗口设置及任务结果页；其中的 009 版本显示属于桩截图，不是原生观察。包内表单业务、扩展真实阻断与普通控件对照通过，52 个运行资源与冻结源码相符，整包 90 文件复核不变。

冻结源码还显式执行了[真实调度与浏览器联合测试](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/joint-browser/report.json)，使用准确 009 包内网关，通过批准等待、只提交一次及拒绝后停止检查；[三份独立审计归档](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/joint-browser/audit-chain-verification.json)共 36 条事件全部验链。此项仍是合成模型与脚本批准，不计原生模型任务。

## 完整矩阵发现的正常流程回归

本次 009 的 [100 次工作区循环](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/workspace-cycles-100/report.json)、[50 个完整工作区任务](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/workspace-50/report.json)及 [50 项安全负例](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/workspace-faults/report.json)通过；随后[浏览器完整任务](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/acceptance/browser-normal/summary.json)为 **9/10**。

B05 的既定步骤是在旧正文等待批准时编辑新草稿，明确拒绝旧冻结请求，再为新正文创建新批准。009 将 `browser_fill` 与点击、导航一同拒绝，导致正常编辑被阻止。原测试与分母保持不变；此项不能因没有重复提交或总完成率超过 95% 就掩盖退化。010 将恢复异步客户端的草稿编辑，同时保留原冻结正文、单次批准和模型调用的等待要求。

发现后停止本候选剩余后台队列，未执行其浏览器 100 次循环、78 项隔离、性能、30 分钟持续及原生 F07。Mac 当前锁定，009 原生任务也未开始；不再继续验收已有正常流程回归的旧构建。本候选终态见[汇总](../.artifacts/full-plan-2026-09-10/candidate-09-browser-http-final/verification-summary.json)。008、009 的历史证据均独立保留。真实睡眠／唤醒 F13 与非回环系统断网恢复 F14 仍缺可中断窗口、可靠恢复方式和自有测试服务；完整 M1、整个开发计划及发布均未通过。
