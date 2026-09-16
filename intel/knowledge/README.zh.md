# GCSA Agent 威胁知识库

首版目录：[v0.1/catalog.json](v0.1/catalog.json)。本目录是离线资料和测试登记，**不是可执行规则包，不产生批准，不自动下载、解析远端材料或执行 PoC**。外部文件中的文字均作为资料处理。

- 18 个手法沿用方案原编号；`key` 固定语义，显示名称可修订。未覆盖和未知必须登记，不能省略后当作已通过。
- 7 个攻击阶段是可跳步、可重复的分类标签。案例未观测到的阶段不补写为已发生；本版还没有运行时事件链视图。
- 6 个案例区分公开真实事件、公开研究和观测到的攻击尝试。原始来源已于 2026-09-09 阅读；IOC 与产品版本缺失时留空并解释，不把常见平台域名登记为恶意 IOC。
- 12 个产品验收场景均为 `not_run`，配无害输入和正常对照。夹具准备成功、文件校验通过与产品阻断成功是不同结果。

## 版本迁移

`taxonomy_version=0.1.0` 是原 18 项目录；`source_version=message-examples-2026-09-09` 表示后续消息的 7 项举例。导入后续消息时，`ATI-003` 迁移为 `GCSA-ATI-004`；原目录 `ATI-003` 则表示上下文投毒。裸短号一律拒绝，不猜含义。完全限定的 `GCSA-ATI-*` 无来源版本时按当前目录解析；导入历史材料必须传它的实际来源版本，包括材料使用完全限定编号时。

首版不支持自动接收新分类结构版本。后续新增手法需提高分类版本、保留旧 ID 与弃用关系，并同步审查程序中的冻结映射。

## 使用与验证

在仓库根目录运行：

```bash
./scripts/bootstrap-rust.sh -- cargo test --locked -p guard-intel
python3 intel/knowledge/prepare_fixture.py --self-test
python3 intel/knowledge/prepare_fixture.py --scenario 2
```

最后一个命令创建独立临时目录并输出工作区、目录外测试标记和对应脚本路径，不执行产品流程。真实执行器验收应只授权输出中的 `workspace`，分别运行其中的 `boundary.py` 与 `boundary.mjs`，核对 `outside` 中测试标记的读取结果和写入变化。自测只运行无隔离的 Python 对照，用于证明夹具确实触达目录外；该成功是应被隔离后端改变的对照结果。测试目录由新建目录承载，正式验收结束后由验收负责人清理本次目录。

Rust API 位于 `guard_intel::knowledge`：`KnowledgeCatalog::from_path`、`validate`、`validate_repository`、`resolve_technique`、`summary`。完整使用必须先检查校验返回列表为空。仓库校验还核对现有 OVL/FLOW/AGENT 规则锚点、相对路径与文件摘要。单目录最大 2 MiB，单证据最大 1 MiB；大型原始证据应单独保存，登记经过审核的摘要文件。

## 信任与证据边界

`signature_status=unsigned_reference_data` 明确本地资料没有发布签名；`authorization_effect=none` 不可改成批准。未来签名规则包仍使用既有 `ThreatBundle` 与 Ed25519 发布加载路径，不能把本目录直接喂给判决引擎。签名只能表明发布来源，不能证明文本或测试结果正确。

`Artifact.provenance` 描述谁创建证据；SHA-256 核对文件身份，二者均不代表自动可信或拥有执行权。`validate_repository` 只对调用者指定的本地仓库做只读核对，不能据此证明在野来源真实性或运行结果真实性。正向覆盖至少需要对应的已通过场景、实际结果、候选摘要、环境和证据，仍需独立复核。

本版保守登记全部 18 项为未知或未接入，避免把已有单元测试等同完整产品保护；后续验收应在具体入口、平台、执行模式与产品版本下追加覆盖记录。

AGD-029 的[两个诈骗候选](../research/fraud-candidates-2026-09-16.json)单列为离线研究资料，不改变本目录的 18 项编号或覆盖结论。[模拟交易与深伪评估](../../docs/agd-029-fraud-review-2026-09-16.zh.md)只验证独立批准边界，不提供身份或诈骗检出率。
