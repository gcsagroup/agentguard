# AgentGuard M0／M1 源码整合记录

日期：2026-09-14。范围：将 `codex/agentguard-m0-m1-20260909` 的已有成果整合到 `main` 并提交 `gcsagroup/agentguard`。基础提交为 `b53387ebb67ecdef56f1322e4e3628a5fc66977c`，远端默认分支为 `main`。

**源码交付不改变验收结论：12 项完成、1 项阻塞、19 项待开始；完整 M1 未通过，生产发布仍为 No-Go。** 本次不生成安装包或 GitHub Release。沿用已有本地 Ver 1.0（010）候选；合并检查中的测试二进制不作为新的 App 候选。

## 整合内容

- 本地模型数据授权、只读与修改副本模式、工作区隔离、参数与全文差异批准、宿主冲突检查、回写及恢复原件。
- 受保护浏览器统一会话、真实 HTTP 单次批准、持久回执、待批准期间草稿编辑及失败停止；暂停／恢复、永久停止、退出和关窗回收。
- 执行与审计契约、威胁知识库、正常任务和隔离验收脚本，以及之前尚未提交的 macOS 观察告警、Codex 配置和网关可用性修复。
- 三语 README、文档入口和 CHANGELOG；完整开发计划保持原 32 项任务定义和依赖。

本次开工前已保存 178 个待提交源码、测试及文档文件的独立副本、摘要和原始差异。只将明确列出的源码与文档纳入 Git。原始验收数据、候选包、工作区快照、会话审计及本地运行日志保留在原目录；另一任务的情报采集配置／候选数据保持独立。未清理历史工作树登记或删除开发分支。

## 验证及日志

合并检查使用仓库固定的 Rust 1.95.0 和 Node.js 22；命令、完整输出及退出码独立保存于本地 `.artifacts/github-merge-2026-09-14/`，失败记录保留。本轮实际结果如下：

| 检查 | 结果 | 本地日志 |
| --- | --- | --- |
| Rust 完整工作区回归 | 1,290 通过、0 失败、11 默认忽略 | `workspace-tests.log` |
| macOS 桌面回归 | 122 通过、0 失败、9 默认忽略 | `desktop-tests.log` |
| 真实浏览器与 MCP 回归 | 39 通过、0 跳过 | `browser-tests.log` |
| 桌面界面与三语检查 | 124 项通过，原生接入使用界面桩；已检查截图 | `ui-tests.log`、`ui/` |
| Rust 格式与严格 Clippy | 通过 | `fmt-after.log`、`clippy.log` |
| 前端、脚本语法及三语键 | 通过 | `shell-check.log` |
| 文档与计划一致性 | 32 项原定义不变，仓库链接有效；本地历史证据路径单列 | `documentation-check-after.json` |

首次格式检查发现 3 个文件不符合 rustfmt，修正后复查通过；只改变排版，不改运行逻辑，原失败留在 `fmt.log`。Clippy 的 Rust 警告门禁通过，macOS 原生编译仍报告一个既有废弃 API 警告，完整输出保留。文档检查发现一个旧超时报告链接对应文件缺失，已改为明确缺失说明，未伪造或补写旧结果。默认忽略的系统／外部环境测试不计为通过。

010 的既有验收包括冻结后台 60/60 完整任务、工作区与浏览器各 100 次循环、50 项安全负例、78 项隔离、8 项显式故障、原预算性能 6/6 和 30 分钟运行。原生逐项补验包含实际回写后宿主 3/3 测试、浏览器实际提交一次、生命周期及 F07 待批准／运行中崩溃重启。首轮失败、明确追加和跨会话补验均保留，不能表述为一次自主联合任务通过。这些历史结果不改写成本次合并重跑结果。

本地证据位置：

- `.artifacts/full-plan-2026-09-10/candidate-10-pending-draft/verification-summary.json`：010 候选矩阵汇总。
- `.artifacts/full-plan-2026-09-10/native-10/host-post-writeback-tests.log`：宿主回写后原测试日志。
- `.artifacts/full-plan-2026-09-10/native-10-browser-recovery/final-verification.json`：7 个已结束会话、18 份审计库共 235 条记录及冻结文件／签名核验。
- `.artifacts/github-merge-2026-09-14/`：本次源码备份、检查日志与 GitHub 远端回读。

上述原始证据属于本地归档，未作为公开仓库内容上传。历史验收文档中的 `.artifacts/`、`eval/out/`、`apps/protected-browser/out/` 等生成目录链接需在原工作区读取。此后 README、计划和合并格式修订不会覆盖既有冻结归档或报告摘要；本次源码差异另行记录。

## GitHub 首轮失败与修复

源码提交 [`1252b7e`](https://github.com/gcsagroup/agentguard/commit/1252b7e93df0812d193247e595f61ce60b1eac25) 已快进合并并推送 `main`，远端提交逐字回读一致。随后运行的 [GitHub CI 首轮](https://github.com/gcsagroup/agentguard/actions/runs/34772625471) 发现以下问题；原失败保留在该运行记录和本地 `ci-job-*.log`，不能用推送前的本地通过覆盖远端失败。

- Linux Clippy：macOS 专用的 `BufRead` 导入没有限定平台，Linux 扩展属性检查的循环总在第一项返回。已限定导入并改为判断是否存在禁止属性；Linux 仍拒绝所有扩展属性，macOS 仅保留既有系统来源属性例外。
- 场景覆盖矩阵：新增的低对比度标记与明确中文指令联合场景未登记。已补入现有攻击面并重新生成矩阵，112/112 个场景都有引用，不扩大覆盖等级。
- 浏览器停止／导航测试：关闭页面会使进行中的 `page.evaluate` 拒绝，测试迟挂错误处理引发未处理异常。已在创建请求时接住结果，随后核对仅为页面销毁异常，并保留服务器零提交、确认清空和浏览器关闭断言。
- Windows 执行日志：两项浏览器测试误以为未验证的日志锁平台可创建执行会话。Unix 保留完整审计与取消回归；非 Unix 新增明确拒绝且审计数据库未创建的断言，不启用未支持的平台执行能力。
- macOS 长输出：读取线程每读 8 KiB 都额外等待 10 毫秒，繁忙 CI 上可能先超时而未报告超长输出。改为有数据时继续读取，无数据时等待；每轮仍检查撤销及子进程状态，保持 1 MiB 限制与原超时门槛。

新增 Windows 断言后，仓库不变量检查要求重新生成三语能力矩阵，已同步静态测试计数；首次修正的布尔表达式也经 Clippy 简化后重新通过，过程日志全部保留。

修正后工作区 1,290 项、桌面 122 项、真实浏览器 39 项、场景评估 135/135 通过；覆盖登记 112/112，格式、Clippy 与三语能力矩阵检查通过。默认忽略项仍分别为 11 与 9。日志使用 `*-ci-fix*.log`，GitHub 最终状态单独保存在本地 `ci-latest.json`。网关读取修正只交付源码，未替换已有 010 安装候选，其原生验收证据仍只绑定旧冻结包。

## 第二轮 CI 的检出与用例选择修复

[第二轮 CI](https://github.com/gcsagroup/agentguard/actions/runs/34773140315) 中，Linux／macOS 工作区、Clippy 和完整浏览器 E2E 已通过，Windows 与 macOS 壳子继续执行后暴露了后续问题：

- Windows `core.autocrlf=true` 将 12 个知识库 JSON 夹具从 LF 转为 CRLF，破坏登记的原始字节摘要。已在 `.gitattributes` 只为这些夹具固定 LF。用实际 Git 检出复现原失败，再检出验证 12/12 字节和登记摘要一致；未修改夹具或放松摘要校验，知识库回归 11 项通过。记录为 `crlf-before.json`、`crlf-after.json` 和 `knowledge-tests-crlf-fix.log`。
- macOS 默认桌面回归和真实网关副作用用例均通过，但宽泛的 `--include-ignored` 同时启动了新增的人工宿主连接验收；CI 没有该连接文件，因此明确失败。默认单测仍完整执行，后续独立进程步骤改为精确选择原有的自建网关副作用用例，并要求输出恰好 1 项通过，避免用例改名后零测试假通过。需 `AGENTGUARD_WORKSPACE_CONTROL_FILE` 的人工宿主验收保留原显式条件，未计作 CI 通过。

本地已用刚构建的真实网关执行同一条精确用例：1 项通过；仓库不变量 23 项通过。日志为 `native-gateway-fixture-second-ci-fix.log` 和 `repository-invariants-second-ci-fix.log`。

## 剩余条件与入口

F13 尚缺可中断的真实睡眠／唤醒时段和可靠恢复方式。F14 尚缺不含生产数据的自有非回环测试服务，以及真实断网／恢复的时段和方法；当前受保护浏览器仅支持登记回环 HTTP。M1 未通过前不进入 M2。

- [完整开发计划](agentguard-development-plan-2026-09-09.zh.md)
- [010 修复与验收详情](agd-m1-pending-draft-010-2026-09-11.zh.md)
- [桌面使用说明](desktop-guide.md)
- [受保护浏览器本地试用](../apps/protected-browser/README.md)
- [GitHub main 的 CI 记录](https://github.com/gcsagroup/agentguard/actions/workflows/ci.yml?query=branch%3Amain)
