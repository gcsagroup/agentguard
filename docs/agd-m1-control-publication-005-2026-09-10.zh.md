# M1 控制文件发布修复与 Ver 1.0（005）验收

日期：2026-09-10～11。状态：**005 已构建，原生文件修复与回写、正式任务及隔离验证通过；隔离读取超出性能预算，完整 M1 和整个开发计划尚未完成。**30 分钟持续运行已完整通过。准确 App 的浏览器提交前再次锁屏，未批准 POST 已超时拒绝、服务端零提交；原生生命周期、真实睡眠／唤醒和非回环系统断网恢复仍未完成。[004 的真实原生成果与失败](agd-m1-native-004-2026-09-10.zh.md)保留为该版本记录，不转绑给 005。

## 1. 修复内容

004 的循环测试在第 29 次启动新会话时读到零长度控制文件并安全拒绝。代码先创建正式文件再写入，使“文件已存在”与“内容已完整”之间有短暂窗口。本次失败没有派发任务、没有改变宿主原件，完整记录见[现场核对](../.artifacts/full-plan-2026-09-10/control-publication-failure-and-fix.json)。

005 先把连接内容写入同目录下的私有随机临时文件并同步，再以系统的排他 rename 一次发布。正式路径只出现完整内容；不使用会短暂产生两个硬链接的发布方法，不覆盖已有文件。写入失败或目标被操作者占用时，仅清理本实例临时文件；退出时仍按设备和 inode 核对，只撤销本实例文件。读取方的权限、类型、长度和链接数检查保持原样。

四项真实文件系统测试通过，覆盖发布前不可见、发布后单链接、失败清理、并发占用不覆盖，以及既有权限和符号链接保护。见[专项测试日志](../.artifacts/full-plan-2026-09-10/control-publication-regression.log)。本轮实测宿主是 macOS；Linux 分支沿用项目已有的 `RENAME_NOREPLACE` 方式，本轮未取得独立 Linux 真机运行证明。

## 2. 当前成果身份

- 005 归档：[AgentGuard Local Agent Test.app](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/ed546c77870c51fc71a53e04ebc6338b76b49707543b255c7b15e8fec442554d/AgentGuard%20Local%20Agent%20Test.app)，显示 **Ver 1.0（005）**，包版本 `1.0.0-rc.5`、构建号 `5`。
- App 主程序 SHA-256：`fa53eb780e648f99daaa7c739ac227c0fc97926e71d98e221aa57778ddd451a6`。
- 网关 SHA-256：`ed546c77870c51fc71a53e04ebc6338b76b49707543b255c7b15e8fec442554d`。
- [934 文件源码清单](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/source-manifest.json)、[原始归档](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/source.tar.gz)及[构建、完整包和签名记录](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/build-report.json)。相对 004 只改控制文件实现及六处版本信息，共七个文件。
- 组织签名严格验证通过；Gatekeeper 分发评估仍为拒绝。未公证、发布或安装到新的应用路径。

001～004 源码、App、通过和失败记录均保留。最终说明文档独立于上述构建时源码冻结点。

## 3. 验证记录

已完成网关 204 项（9 项按条件忽略）、受影响浏览器 17 项、界面 124 项回归，均通过。浏览器第一次命令误写一个文件名，实际只执行 8 项；保留该日志，并另行正确执行完整 17 项。界面测试使用明确后端桩，不代表原生 App 操作。[测试汇总](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/verification-summary.json)记录各自日志和范围。

桌面后端完整串行运行 119 项通过、8 项按条件忽略；Clippy 全目标严格检查通过。此前默认并行运行有两项等待合成模型请求超时（117 项通过、2 项失败），两个失败用例分别单独运行均通过。测试逻辑和时限未变；现场存在其他项目高 CPU 进程，但尚未确认超时根因，不能把串行通过写成并发问题已修复。[超时核对](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/desktop-timeout-diagnosis.json)与初次失败日志保留。

准确网关另通过真实 Chromium 崩溃恢复和系统解析器边界两项专项。前者只覆盖浏览器子进程；后者包含 DNS、TCP／UDP 正负对照，均不能替代准确 App 崩溃或真实系统断网恢复。

正式联合验证使用冻结源码和准确网关。每阶段重新核对 934 文件及 App 身份，所有通过和失败均保留。

| 005 验证范围 | 实际结果与证据 |
| --- | --- |
| 工作区完整任务 | [50/50 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/workspace-50/report.json)；含真实输入、工具、批准、预览、回写和成果核对 |
| 浏览器完整任务 | [10/10 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/browser-normal-run.log)；与工作区合计 60 个预声明脚本化任务，不称 60 个模型自主任务 |
| 工作区循环 | [100/100 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/workspace-cycles-100/report.json)；004 首次循环 29 失败仍保留 |
| 浏览器循环 | [100/100 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/browser-cycles-100-run.log)；50 批准、40 拒绝、10 断连取消，后两类零提交 |
| 文件、链接、解释器、后代与故障隔离 | [78/78 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/isolation-78-run.log) |
| 安全故障 | [50/50 通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/workspace-faults/report.json)；不加入正常任务分母 |
| 准确包内网关、浏览器与扩展 | [表单业务通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/packaged-resources/packaged-browser-report.json)、[合成受保护控件阻断通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/packaged-resources/extension-negative/report.json)；真实进程、页面、收件和审计核对，普通控件正常。由脚本代行批准，不称原生人工操作 |
| 整包复核 | [前](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/packaged-resources/bundle-before.json)／[后](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/packaged-resources/bundle-after.json)全部 90 文件不变，52 个运行时／扩展文件与冻结源码对应，严格签名通过 |
| 持续运行 | [1800.991 秒、30/30 任务通过](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/soak-30min/report.json)，121 次心跳、最大间隔 15.778 秒，退出后本轮容器为零；001 的 1800.220 秒不计入本次 |

### 3.1 性能预算尚未通过

每路固定 1 KiB 文件、5 次预热、30 次正式读取，正文全部正确；启动只测每路一次，内存仅统计网关 PID 的采样峰值。预算在本次测量前沿用原门槛固定，没有事后放宽。[正式预算结果](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/performance-budget-result.json)：

| 指标 | 原生网关 | 隔离网关 | 预算 |
| --- | --- | --- | --- |
| 读取 p95 | 5.40ms | **654.15ms，未通过** | 分别 ≤10ms、≤500ms |
| 单次启动 | 15.99ms | 701.60ms | 分别 ≤100ms、≤2000ms |
| 网关 RSS 采样峰值 | 12.81MiB | 13.28MiB | 每路 ≤32MiB |

测量时宿主为 18 核，负载均值约 29.7～32.0，并存在多个高 CPU 进程，见[现场记录](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/performance-host-load.json)。为定位失败，在当前环境下用旧 001 二进制作独立对照，隔离读取 p95 同样达到 **672.33ms**；隔离执行器、辅助程序、调用路径与基准脚本四个源码文件在 001/005 间逐字相同。[对照身份及日志](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/performance-old-comparison.json)只用于诊断，不加入 005 分母。

另按同样隔离限制启动五次空容器，未挂载项目、未执行网关，实值为 220～520ms，中位数 444ms，见[分段诊断](../.artifacts/full-plan-2026-09-10/candidate-05-control-publication/acceptance/docker-startup-diagnosis.json)。这些证据表明当前问题并非仅限新版，容器启动有明显开销；**尚未证明 CPU 争用是唯一根因，也未证明新候选已恢复预算**。未停止其他项目或更改 Docker 配置；当前宿主运行条件不满足声明的隔离读取预算，M1 性能仍为未通过。

### 3.2 准确 005 的原生文件成果与锁屏中断

已实际操作固定 App 完成：选择独立中文路径、修改副本权限、35B 模型、准确本机站点，以及数据授权前启动禁用／授权后才启用。模型自主读取两个文件，第一次真实命令复现原始三个失败，修改 `discount.py` 后经第二次独立批准重跑，三个测试通过；测试文件未变，新增中文报告为 1349 字节。

原生展开两个文件修改前后全文，核对目录、恢复目录与批次后回写。独立核对证明[回写前宿主未变](../.artifacts/full-plan-2026-09-10/native-05/before-writeback-independent.json)，[回写后文件摘要、权限和三个测试均正确](../.artifacts/full-plan-2026-09-10/native-05/after-writeback-independent.json)，原 `discount.py` 的 82 字节及 0644 权限完整保留在恢复目录。原生预览中的既有文件回写权限为 0644，新增报告为 0600；副本文件的 0600 不误转作原件权限。

同会话浏览器已实际收到四条经原生批准的 GET：存储页、导出页两次、表单页。POST 待批准时 Mac 再次锁屏；没有通过 API 代为批准。[独立核对](../.artifacts/full-plan-2026-09-10/native-05/lock-timeout-independent.json)确认该 POST 只有判决及超时终态、`dispatched=false`，服务端 POST 和账本提交数均为 0。这证明本次未授权提交被阻止，**不代表浏览器正常任务完成**。

本轮原生审计已另作只读备份并逐行验证哈希链，见[超时后的三库核对](../.artifacts/full-plan-2026-09-10/native-05/after-post-deadline-audits/summary.json)。所有原生批准与回写均由 Computer Use 操作 App；后续只读状态和审计核对使用本测试生成的连接文件，不向模型提供令牌。最初清单的“不读取原生控制凭据”不能用来描述这一后续核对方法；证据明确保留实际方法。持续验收结束后，重新备份三库并核对会话空闲、无待批准、服务端零提交，随后仅向准确 App 和本轮合成站点发送 SIGTERM。所有自有后代、两个监听端口和浏览器私有目录均已退出／撤销，见[清理记录](../.artifacts/full-plan-2026-09-10/native-05/cleanup-before-build06.json)。这是构建前清理，不计原生永久停止、关窗或 F07 验收；005 完整 App 归档保留。

## 4. 原门槛与接续条件

计划仍为 **11 项完成、2 项阻塞、19 项待开始**，原 32 项定义和依赖保持不变。

| 项目 | 必需的下一步 |
| --- | --- |
| AGD-011 | Mac 再次解锁并保持可操作；在同一 005 完成浏览器正常提交核账、暂停恢复、永久停止、只读新任务及直接关窗。文件任务已通过，锁屏超时不替代正常浏览器成果 |
| AGD-013／性能 | 解决或明确隔离读取超预算的瓶颈，在可比较条件下复验；保留当前 654.15ms 的首次失败，不放宽原预算 |
| AGD-013／F07 | 准确 005 App 在待批准、已开始两个阶段各实测崩溃与重启，独立核对旧批准和迟到副作用 |
| AGD-013／F13 | 取得可中断且可可靠唤醒的窗口，执行真实系统睡眠并核对事件、过期批准及恢复行为 |
| AGD-013／F14 | 明确无生产数据的自有非回环服务及网络恢复路径，再扩展受限入口、冻结候选并做真实系统断网恢复 |

当前产品浏览器仍只允许明确登记的回环 HTTP。关闭 Wi-Fi 或关闭本机站点不能替代 F14；后台循环数量和子进程退出不能替代 F07/F13。原 M1 联合门槛未通过前，不开始依赖它的后续实现。

本地构建序号与基础发布版本混用的问题已另行发现，见[006 修复记录](agd-m1-build-number-006-2026-09-11.zh.md)。005 的原生通过和失败仍只对应此处准确历史候选。
