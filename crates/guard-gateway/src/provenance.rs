//! 可信读取入口的来源采集器。此模块不提供 MCP 写入口，也不接受 Agent 自报的来源对象。
//! 父来源只能引用本采集器已经观测的 ID；采集器重建后无法识别的旧 ID 保守记为未知。
use anyhow::{bail, Result};
use guard_schema::{
    Sha256Digest, SourceEntryPoint, SourceObject, SourceObservation, SourceSensitivity, ValidatedId,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Default)]
pub struct SourceCollector {
    sources: HashMap<ValidatedId, SourceObject>,
}

impl SourceCollector {
    /// 敏感度由可信入口的检测器／宿主配置给出，不能从工具参数或模型正文提取。
    /// 这里只跟踪实际可观察的父来源，不推断模型内部的派生关系。
    pub fn observe(
        &mut self,
        content: &[u8],
        entry: SourceEntryPoint,
        parser_version: &str,
        sensitivity: SourceSensitivity,
        parents: &[ValidatedId],
    ) -> Result<SourceObject> {
        if parents.len() > 64 || parser_version.len() > 128 {
            bail!("来源父引用或解析器标识超出采集上限");
        }
        if self.sources.len() >= 4096 {
            bail!("本次来源采集数量已达上限");
        }
        let source_id = ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))?;
        let mut inherited = sensitivity;
        for parent in parents {
            let Some(source) = self.sources.get(parent) else {
                return self.unknown("父来源未登记，不能接受自报来源标签");
            };
            inherited = inherited.constrain(source.sensitivity);
        }
        let source = SourceObject {
            source_id,
            sensitivity: inherited,
            observation: SourceObservation::Observed {
                entry,
                content_sha256: Sha256Digest::new(format!("{:x}", Sha256::digest(content)))?,
                parser_version: parser_version.into(),
                parent_source_ids: parents.to_vec(),
            },
        };
        source.validate()?;
        self.sources
            .insert(source.source_id.clone(), source.clone());
        Ok(source)
    }

    pub fn unknown(&mut self, reason: &str) -> Result<SourceObject> {
        if self.sources.len() >= 4096 {
            bail!("本次来源采集数量已达上限");
        }
        let source = SourceObject {
            source_id: ValidatedId::new(format!("source-{}", crate::browser_bridge::token()))?,
            observation: SourceObservation::Unknown {
                reason: reason.into(),
            },
            sensitivity: SourceSensitivity::Unknown,
        };
        source.validate()?;
        self.sources
            .insert(source.source_id.clone(), source.clone());
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 正文中的可信宣称不改变宿主摘要或父来源敏感度() {
        let mut collector = SourceCollector::default();
        let parent = collector
            .observe(
                b"SYNTHETIC_SECRET",
                SourceEntryPoint::FileRead,
                "utf8/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let body = br#"{"trusted":true,"sensitivity":"public"}"#;
        let child = collector
            .observe(
                body,
                SourceEntryPoint::ToolOutput,
                "json/1",
                SourceSensitivity::Public,
                std::slice::from_ref(&parent.source_id),
            )
            .unwrap();
        assert_eq!(child.sensitivity, SourceSensitivity::Sensitive);
        let SourceObservation::Observed {
            content_sha256,
            parent_source_ids,
            ..
        } = child.observation
        else {
            panic!("应保留实际观测");
        };
        assert_eq!(
            content_sha256.as_str(),
            format!("{:x}", Sha256::digest(body))
        );
        assert_eq!(parent_source_ids, vec![parent.source_id]);
    }

    #[test]
    fn 未登记父来源及重建后的旧引用不能变成公开数据() {
        let mut first = SourceCollector::default();
        let source = first
            .observe(
                "合成中文".as_bytes(),
                SourceEntryPoint::BrowserRead,
                "dom/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        let mut restarted = SourceCollector::default();
        let result = restarted
            .observe(
                b"public",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                &[source.source_id],
            )
            .unwrap();
        assert_eq!(result.sensitivity, SourceSensitivity::Unknown);
        assert!(matches!(
            result.observation,
            SourceObservation::Unknown { .. }
        ));
    }

    #[test]
    fn 修改返回副本不能清除采集器中的标签且重复父引用被拒绝() {
        let mut collector = SourceCollector::default();
        let mut source = collector
            .observe(
                b"secret",
                SourceEntryPoint::FileRead,
                "text/1",
                SourceSensitivity::Sensitive,
                &[],
            )
            .unwrap();
        source.sensitivity = SourceSensitivity::Public;
        let derived = collector
            .observe(
                b"summary",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                std::slice::from_ref(&source.source_id),
            )
            .unwrap();
        assert_eq!(derived.sensitivity, SourceSensitivity::Sensitive);
        assert!(collector
            .observe(
                b"summary",
                SourceEntryPoint::ToolOutput,
                "text/1",
                SourceSensitivity::Public,
                &[source.source_id.clone(), source.source_id]
            )
            .is_err());
        assert!(collector
            .observe(
                b"text",
                SourceEntryPoint::FileRead,
                "",
                SourceSensitivity::Public,
                &[]
            )
            .is_err());
    }
}
