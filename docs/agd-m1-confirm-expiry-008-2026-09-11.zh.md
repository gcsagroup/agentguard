# M1 批准期限一致性修复与 Ver 1.0（008）验收

日期：2026-09-11。状态：**008 的后台联合验收通过；准确 App 的原生实测发现浏览器等待与回执处理缺口，完整正常流程未通过。** 原生两文件回写、宿主测试、批准后一次业务提交、明确继续后的只读核账、暂停／恢复及永久停止已有实际证据。浏览器 HTTP 等待期间模型仍继续调用工具，并再次请求提交，重复请求未获批准、未到达站点；该失败保留并进入修复。[007 记录](agd-m1-confirm-expiry-007-2026-09-11.zh.md)保留期限修复、三个原始失败用例、回归结果、构建身份及生成文档检查失败。

008 保留 007 的批准期限修复，更新三语能力表中的测试数量统计，并将本地构建号递增为 8；基础发布版本仍为 `1.0.0-rc.1`。新增三个测试所涉及的等待、快照和答复逻辑已在源码回归中验证；真实系统睡眠行为尚待 F13 实测。

## 当前成果与验证

- 固定入口：[AgentGuard Local Agent Test.app](../apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard%20Local%20Agent%20Test.app)，基础版本 `1.0.0-rc.1`、本地构建号 `8`。
- App 主程序 SHA-256：`92059e00b8985627bf266ec050946dcca957c1015aa9dfb9ff7431c20f2a4271`。
- 网关 SHA-256：`0c4dcedf4dec245a45777a2305be36a40b2270b302a4e56e58e4f951fad002fb`，与 007 相同，与 005／006 不同。
- [939 文件源码清单](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/source-manifest.json)、[构建与组织签名记录](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/build-report.json)。签名严格验证通过，Gatekeeper 分发评估仍拒绝，未公证或发布。

| 本次实际运行 | 结果与范围 |
| --- | --- |
| 冻结仓库检查 | [23/23 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/repo-invariants-run.json)。在 App 构建前强制编译本次检查器，核对其嵌入的 008 源码路径，939 个源码文件在检查前后保持一致 |
| 界面回归 | [124/124 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/ui-workspace-run.json)，后端为明确的桩，不称原生任务；另目视检查总览、680 像素设置页及失败结果页，构建号 008 可见，无明显遮挡或溢出 |
| 准确包内业务 | [表单业务通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/packaged-resources/packaged-browser-report.json)，[扩展阻断对照通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/packaged-resources/extension-negative/report.json)；批准来自脚本，服务端结果与审计独立核对 |
| 整包身份 | [测试前](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/packaged-resources/bundle-before.json)与[测试后](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/packaged-resources/bundle-after.json) 90 文件及签名一致；52 个浏览器／扩展文件与冻结源码对应 |
| 显式 Docker 工作区故障 | [8/8 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/operator-workspace/result.json)。单线程逐项使用真实 Docker 副本、宿主文件及 SQLite 事务故障；每份回执绑定本次确认源码摘要，结束后无运行容器。队列中间态由公开 Server 接口构造，不称原生界面操作 |
| 完整工作区任务 | [50/50 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/workspace-50/report.json)，包含实际隔离执行、独立差异审核、宿主回写与交付内容核验；使用脚本批准 |
| 浏览器完整任务 | [10/10 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/browser-normal/summary.json)，服务端与审计独立核对；使用脚本批准，不计为模型自主或原生桌面任务 |
| 循环与安全故障 | [工作区 100/100](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/workspace-cycles-100/report.json)、[浏览器 100/100](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/browser-cycles-100/report.json)、[安全故障 50/50](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/workspace-faults/report.json)；循环与故障不加到 60 个完整任务分母 |
| 隔离边界 | [78/78 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/isolation-78-run.json)，使用当前网关和冻结源码的文件、链接、子进程及故障检查 |
| 性能 | [原预算 6/6 通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/performance-20260911-verified-warm/result.json)。三路各 5 次预热及 30 次正式读取均正确；原生读取 p95 1.98ms、隔离读取 p95 248.92ms；两路启动分别 8.72ms／370.06ms，网关 RSS 采样峰值分别 12.75／13.08MiB |
| 30 分钟持续运行 | [实际 1801.17 秒通过](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/acceptance/soak-30min/report.json)，北京时间 16:33:28～17:03:29；30/30 个穿插任务通过，包含真实网关崩溃和超时恢复。122 次心跳保持同一监测实例与会话，最大间隔 15.21 秒；网关峰值 2、自有容器峰值 1，收尾无本次遗留容器。这里的 30 项与持续时长独立统计，不扩充原 60 个完整任务分母 |

上述联合运行均核对执行前后的 939 个冻结源码文件以及准确 App／网关摘要。[性能预算登记](../.artifacts/full-plan-2026-09-10/candidate-08-confirm-expiry/performance-budget-registration.json)沿用原六项预算，在本候选实测前完成登记；实测前后核实 Linux 启动身份不变、测量开始时无运行容器。性能结论只适用于原预算规定的 Docker VM 已运行条件，不涵盖空闲后的节能唤醒或高负载。005／006 的对应失败仍保留。

## 准确 008 App 原生实测

北京时间 22:23 起 Mac 已可操作，重新核对固定 App 的 90 文件、签名、939 文件冻结源码及版本号，并实际看到 `Ver 1.0 (008)`。使用已加载的本机 `Huihui-Qwen3.5-9B-abliterated-mlx-4bit`，原生选择合成中文项目、授权发送项目内容及本机浏览器站点；此前锁屏和未使用站点的[空账本退出记录](../.artifacts/full-plan-2026-09-10/native-08/site-stopped.json)仍保留。

- **文件交付通过。** 模型先运行失败测试、修复 `discount.py` 的百分比计算，再通过 3 项测试并新增 `VERIFICATION.md`。两次命令符合既有范围预授权，没有独立命令批准卡；不得记成两次原生批准。完整展开两文件预览、核对会话及动作摘要后原生批准回写，宿主文件与预览一致，测试文件未改，原件恢复副本摘要匹配；宿主 3/3 测试通过。见[回写结果](../.artifacts/full-plan-2026-09-10/native-08/writeback-result.json)。
- **浏览器正常流程未通过。** 首次导航因参数无法冻结而拒绝，0 请求；未保存原始模型参数，空 `page` 只是待证假设。明确给出新的仅含 URL 指令后，原生批准 GET 表单和一次 POST；站点收到的 55 字节正文与审核内容完全一致。但 POST 待批准期间模型继续调用 DOM 工具，随后再次点击提交。重复 POST 出现在原生待确认卡，未获批准且最终被拒绝，站点始终只有 1 条提交。不能把最终业务数量正确当作完整正常流程通过。
- **暂停、恢复和停止已有证据。** 暂停后保存三份审计；恢复生成新会话编号，未追加指令期间模型出口与浏览器审计均无新增，也没有站点请求。随后明确追加仅查询账本的指令，经原生批准 GET 后，模型实际读取账本并报告 1 条提交。永久停止后原生显示“任务已永久停止”；网关及浏览器后代、控制端口、控制文件和自有容器均已回收，交付文件未改变。见[原生收尾与失败核验](../.artifacts/full-plan-2026-09-10/native-08/after-permanent-stop/report.json)。
- **已定位修复范围。** 桌面模型流程把 DOM 的“操作已发起”作为下一轮模型输入时，异步 HTTP 尚未结束；同时只传工具正文，未将宿主 HTTP 回执作为继续条件，部分网络拒绝会外显为可继续的 DOM 失败。需要实际等待当前请求结束、保留拒绝／未知语义并防止待批准期间后续动作。此时尚未修改产品代码；F07 两阶段崩溃重启未执行，不能沿用 006 的结果。

本轮三次 HTTP 批准均经原生界面完成；服务端实际记录为 GET `/form`、POST `/notes`、GET `/ledger?id=B04-native-008` 各一次。22:47 已退出准确 App 并[正常停止本轮合成站点](../.artifacts/full-plan-2026-09-10/native-08/site-native-stopped.json)，账本与测试副本保留。该原生失败不抹去后台已通过的独立结果，也不将它们作为原生流程通过的替代证明。

所有实际运行、失败和清理事实独立留档，不把旧候选结果冒充本次重跑。真实睡眠／唤醒和非回环断网恢复仍需用户提供可中断窗口、恢复方式和自有目标服务；完整 M1、整个开发计划及发布保持未通过。


后续修复已转入 [009 浏览器等待修复与验收](agd-m1-browser-http-009-2026-09-11.zh.md)。008 的本次原生失败与部分交付保持原记录，不由后续测试改判。
