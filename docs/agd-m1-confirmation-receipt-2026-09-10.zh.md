# M1：批准完成后的工具回执

日期：2026-09-10。**批准回执修正、用户指定的组织签名和当前候选的本地模型原生专项均已完成。恢复后的同一原始指令，经单次批准后自动读取报告并准确总结。完整 M1 及发布仍未通过。**

## 实测发现

组织签名候选 `dca9757d…` 已完成真实隔离任务、原生回写与生命周期验证。恢复后，使用者在界面单次批准了无害 `echo` 命令，审计明确记录已派发并成功，但模型随后误称“等待您通过界面批准本次操作”，也未继续读取报告。

独立核对发现，网关回执在实际命令输出后继续附加执行前的 `SHELL-CONFIRM` 风险文案，其中仍写着 `requires user confirmation`。完整正文摘要与真实审计一致，见[原始候选独立核对](../.artifacts/m1-org-signing-2026-09-10/independent-09b-round02-approved-echo-corrected.json)。批准状态与执行前说明混在一起可能影响模型判断；仅凭这一次观测不能断言模型误答只有这一个原因。

## 修正范围与完成标准

仅修正已消费单次批准后的 `path/SHELL-CONFIRM` 回执文字：明确本请求的批准已经完成、确认要求已经满足，保留来源、规则与风险等级；其他风险正文不变。批准不能被表述为执行成功；未批准的请求仍拒绝，已批准但实际执行失败的请求仍返回失败。协议版本、隔离、批准绑定、结构化执行回执与界面结构保持现有语义。

验证包括网关专项及完整单元测试、当前网关隔离回归，再将新网关放入准确测试 App，用用户指定的 Global Cybersecurity Alliance Limited 证书重新签名，实际检查批准后是否能继续后续任务，并复核回写和生命周期。旧 `dca9757d…` App、原生截图及失败说明全部保留，不能作为新候选的原生通过证据。

## 冻结候选与验证

当前网关 SHA-256 为 `8e3408cc310a43ed926160c7f7e4e6989c39063b65099f45b3fa67522bcd741c`，使用仓库固定 Rust 1.95.0 构建。修改仅涉及网关回执渲染和对应测试，见[候选记录](../.artifacts/m1-confirmation-receipt-2026-09-10/candidate.json)与[准确差异](../.artifacts/m1-confirmation-receipt-2026-09-10/change.patch)。

当前 App 仍位于 `apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard Local Agent Test.app`，Bundle ID 为 `com.agentguard.desktop.macos.localagenttest`，主程序 SHA-256 为 `72634c3d353f295702e17fac18743f3468c39d04f0450c69557337c7b1c5a2b2`。仅更换网关资源并重签外层 App，没有重编译桌面后端或前端；本次变化限于主程序签名、网关和资源封印三个文件，见[签名与文件记录](../.artifacts/m1-confirmation-receipt-2026-09-10/signed-app-identity.json)。[完整 App 保留件](../.artifacts/m1-confirmation-receipt-2026-09-10/signed-app-preserved.json)已逐文件核对并通过严格签名检查。

| 检查 | 本候选结果 |
| --- | --- |
| 网关完整测试 | [141 通过、0 失败、9 默认忽略](../.artifacts/m1-confirmation-receipt-2026-09-10/gateway-all-tests.log)；新增 1 个测试实际覆盖批准后成功、批准后命令失败、人工拒绝三条 MCP 分支，不能把分支数再加到测试总数 |
| 格式与静态检查 | [rustfmt](../.artifacts/m1-confirmation-receipt-2026-09-10/rustfmt-check.log) 与[全目标 Clippy](../.artifacts/m1-confirmation-receipt-2026-09-10/gateway-clippy.log) 通过 |
| 真实隔离批准回执 | [3/3](../.artifacts/m1-confirmation-receipt-2026-09-10/validation-summary.json)：批准后实际成功为 `success/true`，批准后命令非零退出为 `failed/true`，拒绝为 `refused/false`；绑定不能重用，宿主未变，网关、控制文件与自有容器收尾已核对 |
| 同候选隔离回归 | [78/78](../.artifacts/m1-confirmation-receipt-2026-09-10/isolation-78/run-result.json)，固定镜像与原验收脚本，53.283 秒；候选与脚本前后摘要一致。该回归会剥离附加风险段比较业务输出，因此不单独证明新提示语义 |
| 仓库不变量 | [23/23](../.artifacts/m1-confirmation-receipt-2026-09-10/repo-invariants.log)，包含重新生成的三语能力矩阵 |
| 组织签名 | 使用 `Apple Distribution: Global Cybersecurity Alliance Limited (R3JK7R29AC)`；[严格签名检查](../.artifacts/m1-confirmation-receipt-2026-09-10/verify.log) 返回 0，[Gatekeeper 分发评估](../.artifacts/m1-confirmation-receipt-2026-09-10/gatekeeper.log) 返回 3、拒绝，未调整系统策略 |
| 当前 App 原生复验 | 准确 `72634c3d…` App 已完成修复重测、三次初始工具批准、两文件整批回写、暂停／恢复后的原句批准与自动读取、永久停止、新只读任务和直接关窗回收；见[原生记录](../.artifacts/m1-confirmation-receipt-2026-09-10/native/attempt-03/README.zh.md)与[独立汇总](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-summary.json)。前两次失败／中断保持原归属 |

桌面 Rust 97 项与 Chromium 118 项仍是此前冻结源码的验证结果，本次未重新运行或重复计数。原生任务采用新建的两文件项目，保留旧候选的已回写成果；恢复后的原始 `echo` 加读取指令保持同一轮，不预先拆成两个任务来绕过问题。

## 原生复验过程

第一次实例在原生批准初始 `echo` 后，模型已自动接续两次读取；随后原测试命令的确认因操作超过时限而被拒绝，实际未派发。该次实例明确失败并永久停止，宿主仍为原始两文件，网关、控制文件、端口和精确关联容器均已回收，见[超时核对](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-02-initial-timeout.json)和[停止收尾](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-03-timeout-stop-cleanup.json)。这次失败保留，不计为完整任务通过。

第二次实例使用完全相同的原任务、模型和项目，完成了七个实际模型工具步骤。三次原生批准分别对应初始 `echo`、原始测试与修复后重测；测试由三项失败变为三项通过，代码与中文报告正确，测试文件未改。独立核对确认副本三项测试通过、七项实际回执及批准绑定正确，且宿主仍为原始两文件，见[预览前独验](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-04-attempt02-before-preview.json)。

对话中断后再次检查时，旧 App 和网关已退出，当前 App 是新启动的空实例；没有发生回写，旧副本和审计保留。恢复已安装的 Docker Desktop 后，独立检查确认旧关联容器为零，见[中断状态核对](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-05-attempt02-interrupted.json)。未推断是谁关闭了 App，也未将此退出记作原生停止或关窗按钮通过。本机模型服务当时也未运行，随后重新打开既有 oMLX，并从原生模型界面加载同一既有 35B；[状态记录](../.artifacts/m1-confirmation-receipt-2026-09-10/model-service-resume-load.json)确认可用，没有下载模型或修改全局配置。

第三次实例仍从原始项目使用完全相同的任务，在同一候选上完成七个模型工具步骤；[新实例预览前独验](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-06-attempt03-before-preview.json)再次确认宿主未变与真实修复、重测结果。随后在原生界面展开两文件前后全文，勾选本批确认并批准回写。[回写独验](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-07-attempt03-writeback.json)确认宿主代码为 84 字节、`0644`，报告为 1481 字节、`0600`，均精确匹配本批预览；原测试文件未改，恢复原件与原始 72 字节代码及权限一致，宿主三项测试通过且测试未改变文件。

在同一实例原生暂停、恢复后，逐字追加旧候选触发问题时的原指令。初始七个步骤没有自动重放；新的 `echo AGENTGUARD_NATIVE_RESUME_OK` 仅批准一次，模型随后在同一轮自动读取 `VERIFICATION.md`，形成第八、九步，并准确总结百分比修复和三项测试由失败转为通过，见[恢复后真实界面](../.artifacts/m1-confirmation-receipt-2026-09-10/native/attempt-03/24-resume-answer.png)。[恢复独验](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-08-attempt03-resume.json)核对了逐字相同的指令、批准绑定、新回执完整摘要、真实读取正文及无文件变化。这次观测支持修正后的回执能被本次模型正确使用，但不能推出任意模型均不会误答。

原生永久停止后，[独立收尾](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-native-09-attempt03-stop-cleanup.json)确认网关、控制文件、精确端口和关联容器均已退出或撤销。随后新建只读任务，实际读取代码与报告，回写入口禁用，计划与策略没有写入或终端权限。未先暂停或停止，直接关闭该任务主窗口；[独立汇总](../.artifacts/m1-confirmation-receipt-2026-09-10/independent-summary.json)核对 App、网关、控制文件、端口和关联容器收尾，宿主保持已批准成果。本轮没有实际提交违规写入请求，不把只读界面状态计为该安全负例通过。

当前候选的源码基于此前 909 文件清单，仅追加组织签名与本记录两篇文档，共 911 个文件。既有文件变化为网关两文件及六份说明／生成文档；四份外部并行成果单独保留。最终逐文件摘要、权限与归档字节核对见[源码清单](../.artifacts/m1-confirmation-receipt-2026-09-10/final-manifest.json)，[源码归档](../.artifacts/m1-confirmation-receipt-2026-09-10/source-final.tar.gz)与[交付汇总](../.artifacts/m1-confirmation-receipt-2026-09-10/delivery-summary.json)分别保留。所有旧候选、失败记录和中间证据均保留。

本轮未提交、推送、部署、公证或修改 TCC。AGD-011 的本地入口专项已通过，整体仍等待 AGD-006 统一会话的必需前置；完整 M1 还缺浏览器统一、联网凭据及模型出口控制、真实系统故障和同一最终候选的联合验收。总状态见[开发计划](agentguard-development-plan-2026-09-09.zh.md)。
