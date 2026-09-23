# Unicode候选持续改进

本轮核心变更涉及可信桌面被动观察入口对CRIT-005、OVL-007、OVL-009、OVL-010基础线索的处理。代码差异不等于Unicode误报修复，因此实际用同9份原文分别调用Engine::process与Engine::process_desktop_observation。

两个入口均7项通过、2项正常对照失败：论文引用被OVL-004阻断，标签研究标记被FW-TEXT-ANOMALY告警。共18次判决只代表9份独立样本；不是4种独立误报。原样本、预期、原文保持检查全部保留，通用入口结果与昨晚逐项相同。

v2仍需要可信来源视图与真实动作授权结合。接入点为crates/guard-core/src/lib.rs中的process_desktop_observation、check_text_anomaly及crates/guard-gateway/src/content.rs、gate.rs；要区分引用读取与请求执行，不能让正文自报研究用途成为放行依据。保留既有3项风险、合法旗帜、多语与2项失败对照，再加入真实资料读取完成、执行仍需授权、伪造来源不能放行的接入场景。当前策略字段不能完成这些关系，本轮不修改源码、不添加词语豁免、不降级预期，不创建无依据的新版本。

其他7项沿用上一轮具体改进记录。本轮未运行固定App，不把023/024的独立原生证据替换成这里的CLI快照结果；本轮回归通过也不等于第三方客户端完整覆盖。
