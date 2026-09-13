# M1 批准期限一致性修复与 Ver 1.0（007）验收

日期：2026-09-11。状态：**007 已构建；源码回归、124 项界面测试及准确包内业务通过，冻结仓库检查为 22/23，生成文档的测试数量未同步。** 原生只核对过版本和总览，尚无 007 完整原生或系统故障通过结论。修正后接续 [008 验收](agd-m1-confirm-expiry-008-2026-09-11.zh.md)。[006 的完整证据](agd-m1-build-number-006-2026-09-11.zh.md)保持独立；完整 M1、整个开发计划和发布仍未通过。

## 1. 已复现的问题与修复

复核 F13 前的批准过期路径时发现，执行前已按批准的绝对期限拒绝失效授权，但等待队列的快照、剩余时间和终态只依据单调计时器。在批准期限先到、等待计时仍未到的情况下，会继续显示已经不能批准的请求，并延迟结束等待。

新增三个定向用例，旧实现全部失败：失效请求未隐藏、一秒批准显示接近三十秒剩余、等待未随批准期限及时结束。[修复前源码和身份](../.artifacts/full-plan-2026-09-10/confirm-expiry-fix/before.json)、[失败日志](../.artifacts/full-plan-2026-09-10/confirm-expiry-fix/before-tests.log)保留。该复现是两个期限不一致时的本地组件行为，尚不能声称已复现真实系统睡眠问题或未授权执行。

修复仅涉及确认槽位：读取、答复和等待共用两个期限的较短值；失效时清空请求及尚未消费的答案，返回超时拒绝；等待期间每至多 250ms 重新核对绝对期限。既有动作摘要、随机值、会话、执行前校验及单次批准规则继续保留。

| 已实际运行 | 结果 |
| --- | --- |
| 确认槽位回归 | [9/9 通过](../.artifacts/full-plan-2026-09-10/confirm-expiry-fix/after-confirm-tests.json)，包括三个先失败后通过的新用例及原有取消、暂停、旧恢复和重复答复检查 |
| 网关及审计回归 | [289 项通过、0 失败、10 项默认跳过](../.artifacts/full-plan-2026-09-10/confirm-expiry-fix/gateway-audit-regression.json)，跳过项不计通过；其中 8 项需要显式 Docker 工作区，另 2 项为辅助入口 |

使用仓库固定的 Rust 1.95.0，从当前工作区编译新测试目标；日志中的新增用例和源码路径对应本次修改，没有复用旧候选结果。三语本地构建文案和 macOS 构建号递增至 007；基础发布版本继续为 `1.0.0-rc.1`。

## 2. 本次构建与检查结果

已冻结 938 个源码文件并构建同一路径 App，见[构建报告](../.artifacts/full-plan-2026-09-10/candidate-07-confirm-expiry/build-report.json)。基础版本 `1.0.0-rc.1`、构建号 `7`，组织签名严格验证通过，Gatekeeper 分发评估仍拒绝。App 主程序 SHA-256 为 `4bfbb67a3022bc4318da6652b35e4c0c7f4fb2ccfeaac4e7a83e8455edf8fc13`，网关为 `0c4dcedf4dec245a45777a2305be36a40b2270b302a4e56e58e4f951fad002fb`。

[124 项界面回归](../.artifacts/full-plan-2026-09-10/candidate-07-confirm-expiry/acceptance/ui-workspace-run.json)、[包内实际表单业务](../.artifacts/full-plan-2026-09-10/candidate-07-confirm-expiry/acceptance/packaged-resources/packaged-browser-report.json)及[扩展阻断对照](../.artifacts/full-plan-2026-09-10/candidate-07-confirm-expiry/acceptance/packaged-resources/extension-negative/report.json)通过，测试后整包 90 文件与签名复核通过。包内批准来自脚本，不计原生人工批准。

强制编译冻结源码检查器并核对其实际源码路径后，[仓库检查为 22 项通过、1 项失败](../.artifacts/full-plan-2026-09-10/candidate-07-confirm-expiry/acceptance/repo-invariants-run.json)：新增三个期限测试后，三语能力表仍写网关测试 184 项、Rust 总数 1475 项，实际应为 187、1478。已在当前仓库重新生成三份文档，[差异记录](../.artifacts/full-plan-2026-09-10/confirm-expiry-fix/document-correction/result.json)只包含这两项数量变化；它们是源码中声明的测试数量，不代表实际通过数量。007 原冻结源码及失败日志保持不变，修正后的下一次 App 构建号递增为 008。

007 没有开始完整联合任务或持续验收，不将 005／006 的结果转记给它。

F13 的真实系统睡眠／唤醒，以及 F14 的非回环系统断网／恢复仍需要明确的可中断窗口、可靠恢复方式和自有目标服务。本次单元测试不替代这两项，也不提前进入依赖 M1 的后续任务。
