//! 工具清单的观测契约。格式有效和摘要一致都不代表工具已获得宿主认可。
use crate::{Sha256Digest, ValidatedId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub const MAX_TOOL_MANIFEST_BYTES: usize = 48 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("工具登记契约无效：{0}")]
pub struct ToolRegistryError(pub &'static str);

/// 身份只用于路由和登记，不允许空白、Unicode 混淆或路径成分。
pub fn valid_registry_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolExposure {
    Mcp,
    HostOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPackageIdentity {
    pub package_id: String,
    pub version: String,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub exposure: ToolExposure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolServiceManifest {
    pub registry_version: u16,
    pub service_id: String,
    pub namespace: String,
    pub service_version: String,
    pub package: ToolPackageIdentity,
    pub tools: Vec<RegisteredToolDescriptor>,
}

/// 名称空间、整份服务清单、单工具描述和本次登记代次均进入动作摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistrationBinding {
    pub namespace: String,
    pub manifest_sha256: Sha256Digest,
    pub descriptor_sha256: Sha256Digest,
    pub registration_id: ValidatedId,
}
impl ToolRegistrationBinding {
    pub fn validate(&self) -> Result<(), ToolRegistryError> {
        if !valid_registry_name(&self.namespace, 24)
            || self.namespace != self.namespace.to_ascii_lowercase()
        {
            return Err(ToolRegistryError("名称空间必须是小写 ASCII 标识"));
        }
        Ok(())
    }
}

fn bounded_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

fn bounded_schema(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes += 1;
    if depth > 16 || *nodes > 8192 {
        return false;
    }
    match value {
        Value::Object(map) => map
            .iter()
            .all(|(key, value)| key.len() <= 1024 && bounded_schema(value, depth + 1, nodes)),
        Value::Array(values) => values.iter().all(|v| bounded_schema(v, depth + 1, nodes)),
        Value::String(text) => text.len() <= 16 * 1024,
        _ => true,
    }
}

/// 固定域和递归键排序；描述、数组、Unicode 及数字表示不做语义规范化。
/// 这是登记对象的编码，不宣称实现通用 RFC 8785。
pub fn registry_canonical_bytes(domain: &str, value: Value) -> Vec<u8> {
    fn sort(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries = map.into_iter().collect::<Vec<_>>();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(entries.into_iter().map(|(k, v)| (k, sort(v))).collect())
            }
            Value::Array(values) => Value::Array(values.into_iter().map(sort).collect()),
            other => other,
        }
    }
    let mut result = format!("agentguard.tool-registry.{domain}.v1\0").into_bytes();
    result.extend(serde_json::to_vec(&sort(value)).expect("登记对象仅包含 JSON 类型"));
    result
}

impl RegisteredToolDescriptor {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        registry_canonical_bytes("descriptor", serde_json::to_value(self).expect("工具描述"))
    }
}

impl ToolServiceManifest {
    pub fn validate(&self) -> Result<(), ToolRegistryError> {
        if self.registry_version != 1
            || !valid_registry_name(&self.service_id, 64)
            || !valid_registry_name(&self.namespace, 24)
            || self.namespace != self.namespace.to_ascii_lowercase()
            || !bounded_version(&self.service_version)
            || !valid_registry_name(&self.package.package_id, 128)
            || !bounded_version(&self.package.version)
            || self.tools.is_empty()
            || self.tools.len() > 64
        {
            return Err(ToolRegistryError("服务、名称空间、包或版本字段无效"));
        }
        let mut names = HashSet::new();
        for tool in &self.tools {
            if !valid_registry_name(&tool.name, 32)
                || !names.insert(&tool.name)
                || tool.description.is_empty()
                || tool.description.len() > 4096
                || !tool.input_schema.is_object()
                || tool.input_schema["type"] != "object"
                || !bounded_schema(&tool.input_schema, 0, &mut 0)
                || serde_json::to_vec(&tool.input_schema)
                    .expect("Schema")
                    .len()
                    > 16 * 1024
            {
                return Err(ToolRegistryError("工具名重复、描述或 Schema 超出支持范围"));
            }
        }
        if serde_json::to_vec(self).expect("清单").len() > MAX_TOOL_MANIFEST_BYTES {
            return Err(ToolRegistryError("整份服务清单超过 48 KiB"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        // tools/list 的枚举顺序不改变服务内容；Schema 内数组仍保留原顺序。
        let mut manifest = self.clone();
        manifest.tools.sort_by(|a, b| a.name.cmp(&b.name));
        registry_canonical_bytes(
            "manifest",
            serde_json::to_value(manifest).expect("服务清单"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn manifest() -> ToolServiceManifest {
        ToolServiceManifest {
            registry_version: 1,
            service_id: "fixture-service".into(),
            namespace: "fixture".into(),
            service_version: "1.0".into(),
            package: ToolPackageIdentity {
                package_id: "fixture-package".into(),
                version: "1.0".into(),
                sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
            },
            tools: vec![RegisteredToolDescriptor {
                name: "read".into(),
                description: "普通中文研究 👩‍💻".into(),
                input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
                exposure: ToolExposure::Mcp,
            }],
        }
    }
    #[test]
    fn 名称空间混淆重名和超限清单被拒绝() {
        let original = manifest();
        original.validate().unwrap();
        for namespace in ["fixture/other", "FiXture", "fixt\u{200b}ure", ""] {
            let mut m = original.clone();
            m.namespace = namespace.into();
            assert!(m.validate().is_err());
        }
        let mut m = original.clone();
        m.tools.push(m.tools[0].clone());
        assert!(m.validate().is_err());
        let mut m = original.clone();
        m.tools[0].description = "x".repeat(4097);
        assert!(m.validate().is_err());
        let mut m = original;
        let mut deep = json!({});
        for _ in 0..17 {
            deep = json!({"child":deep});
        }
        m.tools[0].input_schema["properties"] = deep;
        assert!(m.validate().is_err());
    }
    #[test]
    fn 描述中的隐藏字节保留且自报认可字段无效() {
        let original = manifest();
        let mut changed = original.clone();
        changed.tools[0].description.push('\u{200b}');
        assert_ne!(original.canonical_bytes(), changed.canonical_bytes());
        for field in ["trusted", "approved", "allow"] {
            let mut value = serde_json::to_value(&original).unwrap();
            value[field] = json!(true);
            assert!(serde_json::from_value::<ToolServiceManifest>(value).is_err());
        }
    }
    #[test]
    fn 工具枚举顺序不改变摘要但参数数组次序保持() {
        let mut a = manifest();
        let mut second = a.tools[0].clone();
        second.name = "write".into();
        a.tools.push(second);
        let mut b = a.clone();
        b.tools.reverse();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        b.tools[0].input_schema["required"] = json!(["path", "contents"]);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(
            registry_canonical_bytes("fixture", json!({"中":1,"a":true})),
            b"agentguard.tool-registry.fixture.v1\0{\"a\":true,\"\xe4\xb8\xad\":1}"
        );
    }
}
