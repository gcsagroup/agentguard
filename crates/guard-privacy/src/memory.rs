//! 持久记忆的数据约束；数据可反序列化不代表写入已经得到授权。

use crate::{Confidentiality, Integrity, Label};
use guard_schema::{
    Sha256Digest, SourceEntryPoint, SourceObject, SourceObservation, SourceSensitivity, ValidatedId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MEMORY_SCHEMA_VERSION: u16 = 1;
pub const MEMORY_CONTENT_MAX_BYTES: usize = 64 * 1024;
pub const MEMORY_SOURCES_MAX: usize = 64;
pub const MEMORY_DRAFT_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    Active,
    Quarantined,
    Revoked,
}

/// 宿主组织的完整草稿；来源和标签不得由客户端的可信声明替换。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDraft {
    pub schema_version: u16,
    pub scope_id: ValidatedId,
    pub key: ValidatedId,
    pub version: u64,
    pub previous_sha256: Option<Sha256Digest>,
    pub content: String,
    pub sources: Vec<SourceObject>,
    pub label: Label,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: MemoryState,
}

impl std::fmt::Debug for MemoryDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryDraft")
            .field("scope_id", &self.scope_id)
            .field("key", &self.key)
            .field("version", &self.version)
            .field("content_bytes", &self.content.len())
            .field("sources", &self.sources.len())
            .field("label", &self.label)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("记忆草稿无效：{0}")]
pub struct MemoryDraftError(pub &'static str);

impl MemoryDraft {
    pub fn validate(&self) -> Result<(), MemoryDraftError> {
        let reject = |reason| Err(MemoryDraftError(reason));
        if self.schema_version != MEMORY_SCHEMA_VERSION
            || self.version == 0
            || self.version > i64::MAX as u64
        {
            return reject("不支持的版本");
        }
        if (self.version == 1) != self.previous_sha256.is_none() {
            return reject("首版和后续版本的前驱摘要不一致");
        }
        if self.created_at_ms < 0 || self.expires_at_ms <= self.created_at_ms {
            return reject("有效期必须晚于非负的创建时间");
        }
        if self.content.len() > MEMORY_CONTENT_MAX_BYTES
            || self.sources.is_empty()
            || self.sources.len() > MEMORY_SOURCES_MAX
        {
            return reject("正文或来源数量超限，或没有来源");
        }
        let mut ids = HashSet::new();
        let mut floor = Label::user_instruction();
        for source in &self.sources {
            if source.validate().is_err() || !ids.insert(&source.source_id) {
                return reject("来源无效或标识重复");
            }
            let integrity = match &source.observation {
                SourceObservation::Observed {
                    entry: SourceEntryPoint::UserInput,
                    ..
                } => Integrity::Verified,
                _ => Integrity::Tainted,
            };
            let confidentiality = match source.sensitivity {
                SourceSensitivity::Public => Confidentiality::Public,
                SourceSensitivity::Internal => Confidentiality::Low,
                SourceSensitivity::Sensitive | SourceSensitivity::Unknown => Confidentiality::High,
            };
            floor = floor.join(Label::new(integrity, confidentiality));
        }
        if self.label.join(floor) != self.label {
            return reject("标签低于来源限制");
        }
        // 来源图必须自包含且无环；不能仅留下无法核对的父 ID。
        let mut complete = HashSet::new();
        while complete.len() < ids.len() {
            let before = complete.len();
            for source in &self.sources {
                let ready = match &source.observation {
                    SourceObservation::Observed {
                        parent_source_ids, ..
                    } => parent_source_ids.iter().all(|id| complete.contains(id)),
                    SourceObservation::Unknown { .. } => true,
                };
                if ready {
                    complete.insert(source.source_id.clone());
                }
            }
            if complete.len() == before {
                return reject("来源父引用缺失或存在循环");
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| MemoryDraftError("无法编码"))?
            .len()
            > MEMORY_DRAFT_MAX_BYTES
        {
            return reject("完整草稿超过上限");
        }
        Ok(())
    }

    pub fn validate_at(&self, now_ms: i64) -> Result<(), MemoryDraftError> {
        self.validate()?;
        if now_ms < self.created_at_ms || now_ms >= self.expires_at_ms {
            return Err(MemoryDraftError("尚未生效或已到期"));
        }
        Ok(())
    }

    /// 作用域和键在参数正文中独立绑定，此值只用于展示，不解释为文件路径。
    pub fn target(&self) -> String {
        format!("memory://{}/{}", self.scope_id, self.key)
    }

    pub fn preserves(&self, old: &Self) -> bool {
        self.scope_id == old.scope_id
            && self.key == old.key
            && self.label.join(old.label) == self.label
            && old
                .sources
                .iter()
                .all(|source| self.sources.contains(source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> MemoryDraft {
        MemoryDraft {
            schema_version: 1,
            scope_id: ValidatedId::new("项目").unwrap(),
            key: ValidatedId::new("偏好").unwrap(),
            version: 1,
            previous_sha256: None,
            content: "中文😀\n保留正文".into(),
            sources: vec![SourceObject {
                source_id: ValidatedId::new("unknown-1").unwrap(),
                observation: SourceObservation::Unknown {
                    reason: "not_observed".into(),
                },
                sensitivity: SourceSensitivity::Unknown,
                content_views: None,
            }],
            label: Label::new(Integrity::Tainted, Confidentiality::High),
            created_at_ms: 100,
            expires_at_ms: 200,
            state: MemoryState::Active,
        }
    }

    #[test]
    fn 正常中文和未知来源往返不丢标签() {
        let value = draft();
        value.validate_at(150).unwrap();
        let restored: MemoryDraft =
            serde_json::from_str(&serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(restored, value);
        assert!(!format!("{value:?}").contains("保留正文"));
    }

    #[test]
    fn 来源和历史限制不能降级() {
        let old = draft();
        let mut next = old.clone();
        next.label = Label::user_instruction();
        assert!(next.validate().is_err());
        assert!(!next.preserves(&old));
        next = old.clone();
        next.sources.clear();
        assert!(next.validate().is_err());
        assert!(!next.preserves(&old));
        next = old.clone();
        next.sources[0].source_id = ValidatedId::new("换掉来源").unwrap();
        assert!(!next.preserves(&old));
    }

    #[test]
    fn 期限版本正文和未知字段拒绝() {
        let value = draft();
        assert!(value.validate_at(99).is_err());
        assert!(value.validate_at(200).is_err());
        let mut v = value.clone();
        v.version = 2;
        assert!(v.validate().is_err());
        let mut v = value.clone();
        v.schema_version = 2;
        assert!(v.validate().is_err());
        let mut v = value.clone();
        v.content = "x".repeat(MEMORY_CONTENT_MAX_BYTES + 1);
        assert!(v.validate().is_err());
        let mut json = serde_json::to_value(&value).unwrap();
        json["trusted"] = true.into();
        assert!(serde_json::from_value::<MemoryDraft>(json).is_err());
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut().unwrap().remove("sources");
        assert!(serde_json::from_value::<MemoryDraft>(json).is_err());
    }

    #[test]
    fn 悬空来源循环和重复来源拒绝() {
        let mut value = draft();
        value.sources[0].observation = SourceObservation::Observed {
            entry: SourceEntryPoint::FileRead,
            content_sha256: Sha256Digest::new("ab".repeat(32)).unwrap(),
            parser_version: "utf8/1".into(),
            parent_source_ids: vec![ValidatedId::new("missing").unwrap()],
        };
        assert!(value.validate().is_err());
        let mut second = value.sources[0].clone();
        second.source_id = ValidatedId::new("missing").unwrap();
        if let SourceObservation::Observed {
            parent_source_ids, ..
        } = &mut second.observation
        {
            *parent_source_ids = vec![value.sources[0].source_id.clone()];
        }
        value.sources.push(second);
        assert!(value.validate().is_err());
        value = draft();
        value.sources.push(value.sources[0].clone());
        assert!(value.validate().is_err());
    }
}
