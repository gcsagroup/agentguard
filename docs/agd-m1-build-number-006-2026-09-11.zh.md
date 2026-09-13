# M1 本地构建号修复与 Ver 1.0（006）验收

本页保留 006 的历史验收；固定 App 入口随后更新，最新进展见 [008 期限修复与验收](agd-m1-confirm-expiry-008-2026-09-11.zh.md)。006 的准确整包归档位置保存在本页链接的构建报告中。

日期：2026-09-11。状态：**006 的版本一致性、界面、包内业务、AGD-011 原生桌面流程，以及 F07 两阶段崩溃重启均已通过。原预算限定的 Docker 虚拟机已运行场景，性能六项全部达标。** 后端沿用与 005 完全相同的网关字节；[005 验收记录](agd-m1-control-publication-005-2026-09-10.zh.md)和本次空闲后启动失败均保留。仍缺真实系统睡眠／唤醒及非回环断网恢复，完整 M1、整个开发计划和发布均未通过。

## 1. 修复范围

此前把 Mac 本地构建次数同时写入基础发布版本，使 005 的 `1.0.0-rc.5` 偏离仓库各平台共用的 `1.0.0-rc.1`，导致发布版本一致性检查失败。本次保留基础版本 `1.0.0-rc.1`，单独把 macOS 构建号升为 `6`，三种界面语言显示 **Ver 1.0（006）**。

修改只涉及 Mac 的 package、锁文件、Tauri 清单及界面版本文案。没有改变其他平台的版本，也没有修改检查规则。[修改前备份及摘要](../.artifacts/full-plan-2026-09-10/version-build-number-fix/change.json)与[版本修复后验证](../.artifacts/full-plan-2026-09-10/version-build-number-fix/verification.json)均保留；当前工作区 23 项仓库不变量检查通过，三语能力表生成后检查通过。

## 2. 验证方法与已发现的问题

普通 Cargo 运行曾复用带有旧冻结路径的测试产物，使测试实际读取 001 源码。该次结果已标为不能证明当前工作区。随后强制重新编译该测试目标，核对产物嵌入路径确实指向当前仓库，复现发布版本失败；修复六个版本文件后，用已核实路径的同一检查器运行，23 项全部通过。初次失败、缓存核对与修复后结果均保留，不清理或覆盖旧证据。

006 构建前已完成 005 的 1800.991 秒持续验收：30/30 项完整任务、121 次心跳通过，退出后本轮容器为零。已备份准确旧 App 和原生会话证据，随后只关闭空闲的本轮 App 与合成站点；该清理不计原生停止、关窗或崩溃验收。

## 3. 当前准确成果与新增验证

- 固定入口：[AgentGuard Local Agent Test.app](../apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard%20Local%20Agent%20Test.app)。实际包基础版本 `1.0.0-rc.1`、构建号 `6`，准确原生界面已看到 **Ver 1.0（006）**。
- App 主程序 SHA-256：`920692f5d7bfd3b432c198757a497585c9dbfe4f5453bb83270ce38c8200f7f6`。
- 网关 SHA-256：`ed546c77870c51fc71a53e04ebc6338b76b49707543b255c7b15e8fec442554d`。
- [937 文件源码清单](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/source-manifest.json)、[完整源码归档](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/source.tar.gz)、[构建与组织签名记录](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/build-report.json)。App 内核对到本次冻结源码路径，没有把旧 App 记为新构建。
- 组织签名严格验证通过；Gatekeeper 分发评估仍拒绝，未公证或发布。最终说明文档独立于构建时源码冻结点。

| 本次实际运行 | 结果与范围 |
| --- | --- |
| 仓库不变量 | [23/23 通过](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/repo-invariants-run.json)；强制编译冻结 006 检查器并核对嵌入源码路径，版本与能力表检查均通过 |
| 界面回归 | [124/124 通过](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/ui-workspace-run.log)；另人工检查总览、680px 设置和任务结果截图，版本文案清楚，无裁切。后端为明确测试桩，不称原生任务 |
| 准确包内表单业务 | [通过](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/packaged-resources/packaged-browser-report.json)；真实网关／浏览器完成 GET、POST 各一次，页面及收件端一致，未授权站点零请求，27 条审计验链通过 |
| 准确包内扩展正负对照 | [通过](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/packaged-resources/extension-negative/report.json)；普通控件正常，合成受保护控件未进入提交，服务端 POST 为零 |
| 整包身份 | [测试前](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/packaged-resources/bundle-before.json)／[测试后](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/packaged-resources/bundle-after.json) 90 文件一致，52 个浏览器／扩展文件与冻结源码对应，签名严格验证通过 |

包内业务的批准由脚本完成，所有自有进程及私有浏览器目录在该专项结束后清理；不算原生人工批准。[验证汇总](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/verification-summary.json)保留这些区分。

[字节对应核对](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/byte-equivalence.json)证明相对 005，产品只改变六个版本文件，网关及 52 个浏览器／扩展资源逐字节一致。因此 005 的 60 个联合任务、各 100 次循环、78 项隔离、50 项安全故障及 30 分钟记录仍是同一后端的证据；**没有将它们写成 006 新跑的任务，也没有把 005 原生 App 成果转记给 006**。005 的性能失败同样保留。

## 4. 本次准确 App 的原生操作

在短暂可操作窗口中，使用 Computer Use 从固定路径 App 选择新建中文项目、修改副本权限、35B 本地模型及合成浏览器站点。已实际核对模型数据授权前启动禁用，勾选后才启用；此任务未读取批准令牌来启动或批准。

模型自主完成六个工具步骤：读取两个文件、第一次命令确认原始三个失败、修复计算、第二次独立批准后重跑三个测试通过、创建 1252 字节中文报告。两个原生命令动作摘要分别为 `40c200a3…d8ad39`、`bed693c7…674d1e`。测试文件未变，修复后的 `discount.py` 为 94 字节。

原生已展开两个文件的修改前后正文，显示原件恢复目录和批次摘要；报告的原始失败、修复说明及三个最终结果已检查，独立核对文件摘要及实际测试。[回写前独立记录](../.artifacts/full-plan-2026-09-10/native-06/before-writeback-independent.json)证明宿主原始 82 字节文件及权限未变、宿主仍为三个失败、快照三个测试通过。新增报告 SHA-256 为 `b7436f412c6ad16cbbe2d221381daf265bd206ea9b2bde6041d0f728894f44fb`。

第一次回写批准前 Mac 锁屏。[到期后的只读状态](../.artifacts/full-plan-2026-09-10/native-06/after-preview-deadline.json)确认预览已清空、原件未变、会话空闲；该动作没有批准或回写。恢复可操作后重新生成预览，展开两份文件正文，核对摘要与权限，再通过原生复选框和确认按钮回写。新的动作摘要为 `ba6df367…9cc005`，与已到期的 `658b8126…10d6f` 分别留档。[回写后独立核对](../.artifacts/full-plan-2026-09-10/native-06/after-writeback-independent.json)证明宿主三个测试通过、测试文件未变、成果与预览一致，旧原件的 82 字节正文及 `0644` 权限完整保留。

随后在同一原生会话追加合成浏览器任务：读取保存期限和导出格式、打开表单、提交固定业务编号，再读取账本核对结果。五条实际 HTTP 请求均经过原生批准，服务端为四次 GET、一次 POST，账本仅有 `B10-native-20260911-v006` 这一项提交，内容为“保留30天，默认导出Markdown”。[独立业务核对](../.artifacts/full-plan-2026-09-10/native-06/browser-independent-result.json)同时保留四次 DOM 操作失败、两次未派发拒绝和模型自行恢复过程；没有将它们删除或写成全程无失败。浏览器任务没有改变项目文件。

生命周期也已逐项实际操作并独立核对：

- [暂停](../.artifacts/full-plan-2026-09-10/native-06/paused-native.json)后会话显示暂停；[恢复](../.artifacts/full-plan-2026-09-10/native-06/resumed-before-new-instruction.json)更换会话编号、授权版本升为 2，原目录和站点账本没有变化。随后明确追加“只读 discount.py”并点击继续，新会话的真实读取结果与修复文件摘要一致，见[恢复后的动作核对](../.artifacts/full-plan-2026-09-10/native-06/stop-owned-before.json)。
- [永久停止](../.artifacts/full-plan-2026-09-10/native-06/native-permanent-stop.json)后界面显示任务已永久停止；包括网关在内的 15 个自有后代退出，控制端口、两个控制文件及浏览器私有目录均清理，App 继续显示结果。
- 停止后实际点击“新建任务”，重新选择只读模式并关闭浏览器。新任务保留项目和模型选择，但清除数据发送授权，未重新勾选时不能启动。授权后完成两个文件的实际读取；[只读范围与结果](../.artifacts/full-plan-2026-09-10/native-06/readonly-before-close/report.json)确认挂载为只读、回写不可用，工具返回摘要与宿主文件一致。
- 直接点击原生关窗按钮后，[App 与本次网关均退出](../.artifacts/full-plan-2026-09-10/native-06/readonly-after-close/report.json)，控制端口与文件清理，原目录和站点账本保持不变。退出审计另有一组 `session_stop` 记录，未将它计入两次模型文件读取。

停止及关窗后工作区快照仍保留；本次验证的是撤权、自有进程、控制通道与浏览器私有目录的回收，未声称删除全部临时数据。旧原件恢复目录和验收证据也保留。

[最终原生核对报告](../.artifacts/full-plan-2026-09-10/native-06/native-final-verification/report.json)已从两次会话重新备份审计并逐条验链：主会话文件／控制审计 34 条、浏览器 85 条、模型出口 64 条；只读会话文件／控制审计 9 条、模型出口 6 条。两会话模型出口分别有 32、3 组开始及结束记录，全部配对。报告同时复核整包 90 文件不变及严格签名有效。验证脚本只读取本次合成文件、状态和审计；连接令牌不输出、不提供给模型，全部批准仍来自原生界面。

当天凌晨准备 F07 时，选择合成项目期间 Mac 再次锁屏。[当时的准备记录](../.artifacts/full-plan-2026-09-10/native-06/f07-readiness.json)确认尚未启动受保护任务或发送崩溃信号；[当时的代表性输入运行](../.artifacts/full-plan-2026-09-10/native-06/f07-probe-rehearsal.json)只证明探针有效。下午恢复可操作后，已另建证据目录并完成下述正式验收，保留凌晨未执行的历史状态。

## 5. F07：准确 App 两阶段崩溃与原生重启

从固定路径启动未改动的 006 App，分别创建待批准、运行中两个合成项目。探针先写开始标记，等待 24 秒，再写迟到标记。每个阶段只向已核实身份的 App 主进程发送一次 `SIGKILL`，没有手工终止其后代来制造清理通过；之后观察至少 27 秒，跨越探针的延迟时点，再原生重开 App 并核对新任务状态。

| 阶段 | 崩溃前事实 | 崩溃后与重启结果 |
| --- | --- | --- |
| 待批准 | 原生确认框出现，复选框未勾选；审计只有决策，开始标记不存在，无运行容器 | 11 个自有进程约 1.049 秒内退出；审计终态取消，没有开始执行。观察 27.788 秒无迟到标记，重启后任务表单为空、数据授权清空、启动禁用，旧批准未恢复 |
| 运行中 | 原生明确批准同一动作；容器正在运行，开始标记已产生，审计已有开始记录且无结束记录 | 12 个自有进程及本次容器约 1.203 秒内回收；审计终态取消。观察 27.811 秒仍无迟到标记，原生重启后要求重新配置和授权，旧动作未重放 |

[F07 总报告](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/f07-result.json)、[待批准阶段的重启核对](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/pending/after-restart.json)及[运行中阶段的重启核对](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/running/after-restart.json)同时证明：旧控制端口、控制文件和浏览器私有目录已回收，宿主项目文件未变，合成站点请求和提交均为零，审计链完整，整包 90 个文件摘要不变。阶段崩溃报告是在原生重开之前生成，重启结论以独立的 `after-restart.json` 和总报告为准。

输入调整也保留完整记录。第一次使用带项目内脚本路径的命令，原有工作区授权已足以允许执行，因而正常完成；它没有进入待批准阶段，不计作崩溃验收。[正常对照记录](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/pending-unexpected-completion/report.json)和[调整说明](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/probe-input-correction.json)均保留。随后改用同一探针的模块调用，按既有策略实际进入独立确认；[模块调用的代表性运行](../.artifacts/full-plan-2026-09-10/native-06-f07-20260911/module-rehearsal-result.json)通过。没有修改批准策略或探针内容。

## 6. 性能复验与空闲启动限制

下午原五个高 CPU 外部进程已经退出，未由本任务终止。先使用原冻结脚本正式复验：每路 30 次、三路共 90 次读取内容全部正确，隔离读取 p95 为 300.325ms，但隔离启动为 3055.003ms，超过 2000ms。[这次 5/6 的失败报告](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/performance-20260911-afternoon/result.json)完整保留，005 在高负载时的 654.145ms 读取失败也不改写。

随后固定做五次启动诊断，临时包装器只给真实 Docker 子命令计时，透传原参数、输出及退出码，没有改变隔离方式。首次完整启动为 2663.508ms，其中能力探针的 `docker run` 占 2044.710ms；后四次完整启动为 591.357～628.529ms，探针容器启动为 172.085～199.732ms。[分段记录](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/startup-diagnostic-20260911/result.json)含包装器自身开销，仅用于定位，不能替代正式性能结果。

在受限容器内只读核对 Linux 启动编号和运行时间：[07:26:20 UTC 的运行时间为 121.93 秒](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/startup-diagnostic-20260911/after-vm-identity.json)，推算虚拟机在首次慢启动期间重新启动。Docker 官方说明，[Resource Saver 会在空闲时停止 Linux 虚拟机，部分查询无需唤醒它，首次容器请求可能额外等待数秒](https://docs.docker.com/desktop/use-desktop/resource-saver/)。这与观测一致；本机具体节能配置未核实，不能把该配置或此前 3055.003ms 的每一段耗时写成已确认事实。

[原预算](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/performance-budget.json)引用的[冻结验收方案第 6.3 节](../.artifacts/full-plan-2026-09-10/candidate-01/source/docs/agd-full-plan-acceptance-2026-09-10.zh.md)在本轮之前就明确限定“Docker VM 已运行”。因此新增只读启动身份检查，确认该条件后，使用**未改动的冻结基准、原预算、准确网关和相同镜像**再正式运行一次；没有常驻保活容器，没有修改 Docker 设置，每个隔离动作仍新建并回收容器。基准前后 Linux 启动编号一致，运行时间从 174.33 秒持续增加至 184.47 秒。

| 原预算项 | 本次正式结果 | 原上限 |
| --- | --- | --- |
| 原生读取 p95 | 2.452ms | 10ms |
| 原生单次启动 | 9.323ms | 100ms |
| 原生网关采样内存峰值 | 12.750MiB | 32MiB |
| 隔离读取 p95 | 281.089ms | 500ms |
| 隔离单次启动 | 423.480ms | 2000ms |
| 隔离网关采样内存峰值 | 13.078MiB | 32MiB |

[正式复验报告](../.artifacts/full-plan-2026-09-10/candidate-06-build-number/acceptance/performance-20260911-verified-warm/result.json)六项达标，三路各 5 次预热和 30 次正式读取均正确，结束后无运行容器。每路只测一次启动，不能称启动 p95；网关采样内存也不代表容器或宿主总内存。此次通过覆盖原先声明的虚拟机已运行场景，**不承诺空闲唤醒也在两秒内，不证明高负载下读取始终达标**。本轮只增加验收和诊断记录，没有改产品代码或重打包。

## 7. 未完成条件

| 门槛 | 必需接续 |
| --- | --- |
| AGD-013／F13 | 明确可中断且可可靠唤醒的窗口，执行真实系统睡眠及恢复 |
| AGD-013／F14 | 明确无生产数据的自有非回环服务和网络恢复路径，再扩展受限入口、冻结候选并做真实系统断网恢复 |

当前浏览器仍只支持明确登记的回环 HTTP。原预算下的性能与 F07 已关闭；不能用这些结果、脚本回归或关闭本机服务替代 F13/F14 的真实系统验证。开发计划仍为 **12 项完成、1 项阻塞、19 项待开始**；AGD-011 已完成，AGD-013 仍阻塞，完整任务定义、依赖和验收分母保持不变。最终重开的准确 App 为未配置任务状态，没有自有网关或控制连接；合成站点和证据保留。Mac 后续再次锁屏，不影响已完成的 F07 记录。
