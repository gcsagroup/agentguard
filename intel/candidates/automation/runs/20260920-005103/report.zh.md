# AgentGuard威胁情报与候选更新：20260920-005103

本次定时触发实际完成来源检查、去重、两个候选族整理、本地组件验证及相关回归；采集仍为部分完成。不是只读预检，也不代表全量来源及历史缺口恢复完成。

- 来源：12个每日入口，11个取得页面、Unit 42超时。PromptArmor页面可读但无法枚举文章。ATLAS/OWASP距9月17日检查不足7天，本次不重复获取，旧基线缺口保留。
- 线索：核查20条，8条重复、12条新待核验；累计索引43条、待研究31条。新线索来自[GitHub公告列表](https://github.com/advisories)、[arXiv近期列表](https://arxiv.org/list/cs.CR/recent)、[微软主页](https://www.microsoft.com/en-us/security/blog/)及双语搜索；原文未核验，版本和披露日期未知项留空。arXiv仅核对工具返回前10项，未称253条全部处理。
- 候选：EGRESS扩充本机验收；AUTH补充受众、范围与入站校验要求。未新增可执行检测器，未发布。原六族失败及依赖保留。
- 测试：真实EgressBroker 23/23，相关既有集成回归42/42。原14项保留，新增9项；两个拒绝监听器零连接，正常服务收到预期请求。认证七项待运行，不能算通过。
- 首轮问题：夹具枚举预期错误导致1项失败，保留证据后修正复测；回归初始筛选0项不计通过，改正确入口后42项实际通过。未降低安全预期。
- 完整性：908个快照文件与当前源码核对一致；上轮25个证据摘要一致，没有未收尾旧运行。外部材料共136787字节，小于单来源1 MiB和整轮30 MiB；保存的是浏览工具可见文本，非原始全文。

## 剩余工作与水位

仅Invariant与Embrace固定可见列表水位推进至本轮开始时间，正文修订检查不包含在内。全局成功水位仍为空；2026-08-11起初始缺口、中断期间及列表分页缺口全部保留。没有为9月17日晚至9月19日补造执行记录。Unit 42本次400 Timeout保留为采集故障，不等同平台拒绝或候选失败。

下轮先读改进队列与31条研究待办；在已登记入口检查变化，未登记正文/API/分页继续待核验；恢复Unit 42正常采集；只有原文、相关能力或接入变化才复测原失败。认证需要AGD-017真实入口，出口完整隔离需要AGD-008真实执行环境；详细接入点与验收场景见[改进记录](/Users/lazy/Projects/agent-guard/intel/candidates/automation/runs/20260920-005103/refinement.zh.md)。无授权线上遥测，不能提供真实线上误报率。

## 证据边界

公开研究：新12条仅列表或检索线索。离线/本机：本轮组件23项和回归42项通过。真实环境：第三方客户端、MCP OAuth、完整网络隔离及固定App未验收。签名发布：未签名、未发布。正式源码、知识库、生效bundle和历史文件未修改。

[来源状态](/Users/lazy/Projects/agent-guard/intel/candidates/automation/runs/20260920-005103/source-status.json) · [候选](/Users/lazy/Projects/agent-guard/intel/candidates/automation/runs/20260920-005103/candidates.json) · [测试汇总](/Users/lazy/Projects/agent-guard/intel/candidates/automation/runs/20260920-005103/validation-summary.json) · [命令和退出码](/Users/lazy/Projects/agent-guard/.artifacts/intel-automation/20260920-005103/commands.json) · [逐项结果](/Users/lazy/Projects/agent-guard/.artifacts/intel-automation/20260920-005103/egress-results.json)
