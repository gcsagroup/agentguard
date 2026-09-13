# AGD-004／005：威胁知识库首版交付与验收

日期：2026-09-09。范围：知识库数据、离线校验、版本解析和本地验收夹具。完整产品场景仍待各阶段接入验收。

## 已实现

1. [目录数据](../intel/knowledge/v0.1/catalog.json) 含原 18 个稳定 ATI 编号、7 个攻击阶段、7 条版本化迁移、6 条案例、3 条现有规则映射、12 个场景及 18 条逐手法覆盖记录。
2. [Rust 加载与校验](../crates/guard-intel/src/knowledge.rs) 拒绝未知字段、坏结构版本、重复 ID、悬空引用、重新赋义的冻结编号、冲突短号、缺失覆盖状态和无证据的通过声明。仓库校验检查规则锚点、夹具摘要、路径上跳与符号链接逃逸。
3. [本地夹具准备器](../intel/knowledge/prepare_fixture.py) 为每个场景建立独立临时工作区和正常输入；目录外访问场景同时生成 Python／Node 脚本及仅供测试的标记，凭据场景只使用不可用的假令牌。
4. `KnowledgeCatalog` 与现有 `ThreatBundle` 分离；知识库不改策略，不产生批准，不自动执行外部材料。

API 与后续维护方式见[知识库说明](../intel/knowledge/README.zh.md)。本版使用现有 serde、serde_json、sha2 等依赖，没有为知识库引入新依赖。

## 原始案例核对

| 案例 | 证据属性 | 核对边界 |
| --- | --- | --- |
| 香港约 2 亿港元深度伪造会议诈骗 | 公开真实事件 | [政府披露](https://www.info.gov.hk/gia/general/202406/26/P2024062600192.htm) 明确是预录会议，无实时互动；不强行映射 Agent 身份冒充，待诈骗候选分类评审 |
| Claude Code 滥用活动 | 公开真实事件 | [Anthropic 调查](https://www.anthropic.com/news/disrupting-AI-espionage)；厂商调查与归因，GCSA 未独立确认其全部行为；没有把模型生成结果视为全部成功 |
| Morris II | 公开研究 | [原论文](https://arxiv.org/abs/2403.02817)；实验传播，不是互联网蠕虫疫情 |
| MCP 工具投毒 | 公开研究 | [Invariant 原文](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)；特定客户端实验，不推断当前所有 MCP 客户端均易受攻击 |
| EchoLeak | 公开研究 | [原作者迁移至 Cato 的文章](https://www.catonetworks.com/blog/breaking-down-echoleak/)；旧 Aim 链接本次 403；迁移页日期与通常披露日有冲突，日期暂列未知；不把后续 arXiv 分析当成最初发现来源 |
| 推广性记忆投毒 | 观测到的尝试 | [Microsoft 研究](https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/)；存在真实投递，效果随平台与防护变化，尝试数不能等同成功数 |

上述来源于 2026-09-09 阅读。未访问攻击基础设施，未执行外部 PoC；未提供受影响版本和可复用 IOC 的地方保留未知说明。现有 18 手法外的合成身份诈骗只记案例，未提前占用 ATI 新编号。

## 验证结果与剩余工作

夹具准备器已对全部 12 个场景实际运行自测；确认普通 Unicode 字节保留、隐藏零宽字符保留、测试凭据仅为假值，以及无隔离 Python 脚本确实读写新建目录外标记。自测结束时清理自身临时目录。Node 夹具已生成，完整隔离对照交由执行后端验收。

`cargo test --locked -p guard-intel` 实测 **26 通过、0 失败、0 忽略**：15 项原有测试与 11 项新增集成测试。新增测试覆盖有效目录、历史冲突编号、数据错误、无证据通过声明、错误摘要、目录逃逸、规则锚点漂移、输入大小限制与正常文本保留。首次测试中，一个多错误输入的错误条数断言过窄；改为分别断言三个目标错误后通过。仅目录/夹具校验成功不更改场景的 `not_run`。

本版 **6 个案例已登记、12 个本地输入已准备，0 个完整产品场景获得新通过结论**。所有手法覆盖保持 `unknown` 或 `not_integrated`。剩余事项：将实际执行器、独立批准、持久审计、桌面和浏览器接入后，在冻结候选上逐项填写实际结果与证据；攻击链运行时视图、签名更新和外部标准映射仍属于后续任务。
