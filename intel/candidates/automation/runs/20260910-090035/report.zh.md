# AgentGuard 威胁情报定时采集：2026-09-10 上午轮

本轮部分完成：检查 14 个固定来源入口，记录 15 条线索，深入处理 4 条、合并转载 1 条、保留待研究 10 条。形成 4 个候选，其中专用归档只读策略通过离线验证，可进入审核；没有签名、发布或修改正式规则与产品源码。首次近 30 天采集尚未完整完成，因此不推进成功水位。

运行目录采用计划时间 09:00:35（北京时间），实际证据整理发生在当日 13 时段；最终完成时间记录在状态文件，不表示准点执行完成。

## 可审核成果与未通过项

| 候选 | 实际结果 | 后续工作与限制 |
| --- | --- | --- |
| IMPORT：外部归档只读检查 | 实际 guard-shell 加载候选策略，8/8 通过 | 仅用于用户明确选择的归档资料只读会话；真实网关工具路由及完整任务效果尚未验证 |
| UNICODE：隐藏字符与安全引用 | 3 个攻击输入被阻断；6 个正常输入中 4 个允许、1 个误阻断、1 个告警 | 本版不通过；全部样本保留，v2 需要可信读取上下文与实际动作分离，尚未实现 |
| TENANT：共享服务租户隔离 | 已整理控制要求与验证入口 | 缺少两个真实受控会话的服务读写验证，不属于已实现覆盖 |
| EGRESS：模拟声明与真实出口 | 已整理控制要求与验证入口 | 需在受控本地目标上验证实际出口与重定向，正文自称模拟不能构成授权 |

下载及审阅：[专用策略](archive-inspect.policy.yaml)、[候选清单](candidates.json)、[结果汇总](validation-summary.json)。策略用例包含 3 个执行工具拒绝、1 个未知原生解码工具要求确认、4 个正常读取允许；要求确认不能统计为直接拒绝。它不能作为普通代码工作的默认策略。

## 原始来源与证据边界

1. Microsoft 9 月 3 日介绍隐藏字符从提示注入扩展到钓鱼规避，提及 2 月 9 日起的钓鱼活动；这些活动不能直接视为在野 Agent 注入。正常旗帜和研究材料是必须保留的对照。[Microsoft 原文](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/)
2. Embrace The Red 8 月 26 日的研究涉及网页获取失败后检查归档、模型编写 Python 解码、从不可信目录加载同名模块。这里提取的是模块导入路径风险，文章的小样本结果不能外推为普遍攻击成功率。[研究原文](https://embracethered.com/blog/posts/2026/breaking-claude-code-opus-5-and-automode/)
3. Check Point 9 月 8 日披露的研究发生于 6 月，指出共享内部服务的可变状态可能形成跨账号通道；原文说明报告结束时服务已下线，不能声称当前仍可利用。[Check Point 原文](https://research.checkpoint.com/2026/the-shared-clipboard-inside-the-sandbox-cross-account-data-leakage-in-chatgpt/)
4. Anthropic 9 月 9 日重评四起评测环境误联网事件，独立调查仍待完成。本轮只提取范围授权与确定性出口控制要求，未独立复现厂商事件。[Anthropic 原文](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents)

[证据索引](evidence-index.json)记录本地核对摘要的 SHA-256，不能当作网页全文哈希。产品版本不明确时保留空值；转载不算独立证据。

## 实际验证

| 验证 | 结果 | 能证明的范围 |
| --- | --- | --- |
| guard-intel、guard-core、guard-schema 回归 | 451 通过，0 失败、0 忽略 | 本轮源码快照下相关已有回归 |
| guard-shell 回归 | 42 通过，0 失败、0 忽略 | 策略引擎已有回归 |
| 新归档只读策略 | 8/8 通过 | 实际引擎离线输入判决，未验证客户端强制执行 |
| 模块导入路径机制对照 | 6/6 通过 | 自建无害同名模块；Python 隔离参数能排除本次目录和环境变量污染，不是操作系统沙箱 |
| 昨日记忆写入确认控制复验 | 12/12 通过 | PRIV-004 引擎控制；真实记忆写入、跨会话存储与确认绑定仍未验证 |
| Unicode 新对照 | 7/9 通过，2 个正常样本未通过 | 保持正常输入必须允许的标准，告警不算正常通过 |

本轮使用已安装的 Rust 1.97.1 工具链和独立源码快照，命令在仓库根目录执行：

```sh
export RUSTC=/Users/lazy/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc
export RUSTDOC=/Users/lazy/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustdoc
export CARGO_TARGET_DIR="$PWD/target"
INTEL_RUN=.artifacts/intel-automation/20260910-090035
INTEL_CARGO=/Users/lazy/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/cargo
"$INTEL_CARGO" test --locked --offline --manifest-path "$INTEL_RUN/snapshot/Cargo.toml" -p guard-intel -p guard-core -p guard-schema
"$INTEL_CARGO" test --locked --offline --manifest-path "$INTEL_RUN/snapshot/Cargo.toml" -p guard-shell
"$INTEL_CARGO" run --locked --offline --manifest-path "$INTEL_RUN/harness/Cargo.toml" --bin archive_policy
"$INTEL_CARGO" run --locked --offline --manifest-path "$INTEL_RUN/harness/Cargo.toml" --bin agentguard-intel-run-20260910
"$INTEL_CARGO" run --locked --offline --manifest-path "$INTEL_RUN/harness/Cargo.toml" --bin unicode
python3 "$INTEL_RUN/module_shadow_check.py"
```

Unicode 命令实际退出码为 2，表示没有通过准入；其余最终验证命令成功。最初两次回归因快照缺少测试资料和 policies 文件失败，补齐快照后重跑通过，原始失败日志仍保留，不能归因为产品回归。

原始记录：[回归日志](../../../../../.artifacts/intel-automation/20260910-090035/regression.log)、[Shell 回归](../../../../../.artifacts/intel-automation/20260910-090035/shell-regression.log)、[归档策略判决](../../../../../.artifacts/intel-automation/20260910-090035/archive-policy-results.json)、[模块机制对照](../../../../../.artifacts/intel-automation/20260910-090035/module-shadow-results.json)、[Unicode 全部样本与判决](../../../../../.artifacts/intel-automation/20260910-090035/unicode-results.json)、[记忆控制复验](../../../../../.artifacts/intel-automation/20260910-090035/control-v2-results.json)、[源码及规则摘要](../../../../../.artifacts/intel-automation/20260910-090035/snapshot-hashes.json)。

## 持续改进与采集缺口

Unicode 的失败归因为缺少可信上下文及规则表达能力，不增加“研究”等关键词豁免，不删除原样本，不把告警降级算作阻断成功。v2 建议在读取时保存原文、可见视图及异常证据，在实际动作入口核对来源和授权；需可信执行器接入后，连同未参与设计的攻击改写、用户明确授权及研究引用样本一起复测。本轮没有获得支持离线修订过关的新能力，因此保存设计和依赖，未虚报 v2 实现。

昨日记忆候选的 v1 漏报和误报历史完整保留；v2 确认控制重新验证通过。本轮核对的网关/桌面入口未见真实 MemoryWrite 接入，AGD-021/022 仍是待验收的持久记忆与读写接入要求。新增中文期刊的记忆防御线索只核对摘要和接受信息，尚未重现指标，已加入后续研究。[中文期刊原文](https://www.joca.cn/CN/10.11772/j.issn.1001-9081.2026040438)

14 个来源均记录了入口检查结果，但多数来源尚未完成近 30 天分页枚举；PromptArmor 未取得可枚举文章列表，MCP 公告页面出现加载错误提示，ATLAS/OWASP 仍需版本核对。这些均不等于“无更新”。10 条线索在[研究队列](research-queue.json)中保留，包括尚需永久链接、披露日期或原项目修复版本核对的条目；新期刊来源保留为待评审来源。

后续轮次优先处理[持续改进队列](../../rework-queue.json)、[来源检查缺口](source-status.json)及初始回溯，依赖没有变化时不重复运行同一失败。下一次计划检查为北京时间 2026-09-10 21:00。所有候选仍未签名、未发布，真实产品覆盖尚不成立。
