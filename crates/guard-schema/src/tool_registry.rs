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
    /// 下游完整原始定义；缺失与空值不互换，注解不授予权限。
    /// 旧内建清单不序列化此字段，保持其已有摘要与审计编码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServiceObservation {
    /// 宿主实际启动身份；可反序列化的值本身不是启动或授权证明。
    pub execution_sha256: Sha256Digest,
    pub initialization: Value,
    /// 完整 tools/list 响应去掉 tools 数组；工具原文在各描述的 mcp 字段。
    pub list_metadata: Value,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpServiceObservation>,
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
    pub fn from_mcp(value: Value) -> Result<Self, ToolRegistryError> {
        validate_mcp_tool(&value)?;
        Ok(Self {
            name: value["name"].as_str().expect("已验证名称").into(),
            description: value
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            input_schema: value["inputSchema"].clone(),
            exposure: ToolExposure::Mcp,
            mcp: Some(value),
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        registry_canonical_bytes("descriptor", serde_json::to_value(self).expect("工具描述"))
    }
}

impl ToolServiceManifest {
    /// 从完整握手及工具发现构造观测；调用者必须另行证明这些数据来自实际服务。
    pub fn from_mcp(
        service_id: String,
        namespace: String,
        package: ToolPackageIdentity,
        execution_sha256: Sha256Digest,
        initialization: Value,
        listing: Value,
    ) -> Result<Self, ToolRegistryError> {
        let service_version = initialization
            .pointer("/serverInfo/version")
            .and_then(Value::as_str)
            .ok_or(ToolRegistryError("MCP 服务版本缺失"))?
            .to_owned();
        let mut list_metadata = listing
            .as_object()
            .ok_or(ToolRegistryError("MCP 清单不是对象"))?
            .clone();
        let raw_tools = list_metadata
            .remove("tools")
            .ok_or(ToolRegistryError("MCP 清单缺少工具"))?;
        let tools = raw_tools
            .as_array()
            .ok_or(ToolRegistryError("MCP 工具清单不是数组"))?
            .iter()
            .cloned()
            .map(RegisteredToolDescriptor::from_mcp)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = Self {
            registry_version: 1,
            service_id,
            namespace,
            service_version,
            package,
            tools,
            mcp: Some(McpServiceObservation {
                execution_sha256,
                initialization,
                list_metadata: Value::Object(list_metadata),
            }),
        };
        manifest.validate()?;
        Ok(manifest)
    }

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
            if let Some(raw) = &tool.mcp {
                validate_mcp_tool(raw)?;
                if self.mcp.is_none()
                    || tool.exposure != ToolExposure::Mcp
                    || raw["name"].as_str() != Some(tool.name.as_str())
                    || raw.get("description").and_then(Value::as_str).unwrap_or("")
                        != tool.description
                    || raw["inputSchema"] != tool.input_schema
                {
                    return Err(ToolRegistryError("MCP 原始定义与登记字段不一致"));
                }
            } else if self.mcp.is_some() {
                return Err(ToolRegistryError("MCP 服务缺少完整工具定义"));
            }
            if !valid_registry_name(&tool.name, 32)
                || !names.insert(&tool.name)
                || (tool.description.is_empty() && tool.mcp.is_none())
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
        if let Some(mcp) = &self.mcp {
            let init = &mcp.initialization;
            if !init.is_object()
                || !bounded_schema(init, 0, &mut 0)
                || init["protocolVersion"] != "2025-06-18"
                || !init["capabilities"].is_object()
                || !init["capabilities"]["tools"].is_object()
                || !init["serverInfo"].is_object()
                || !init["serverInfo"]["name"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 256)
                || init["serverInfo"]["version"].as_str() != Some(self.service_version.as_str())
                || init["serverInfo"]
                    .get("title")
                    .is_some_and(|v| !v.is_string())
                || init.get("instructions").is_some_and(|v| !v.is_string())
                || init.get("_meta").is_some_and(|v| !v.is_object())
                || !mcp.list_metadata.is_object()
                || !bounded_schema(&mcp.list_metadata, 0, &mut 0)
                || mcp.list_metadata.get("tools").is_some()
                || mcp.list_metadata.get("nextCursor").is_some()
                || mcp
                    .list_metadata
                    .get("_meta")
                    .is_some_and(|v| !v.is_object())
            {
                return Err(ToolRegistryError("MCP 握手或完整清单元数据无效"));
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

fn validate_mcp_tool(value: &Value) -> Result<(), ToolRegistryError> {
    let Some(map) = value.as_object() else {
        return Err(ToolRegistryError("MCP 工具不是对象"));
    };
    // 当前 SDK 在旧协议下也返回 taskSupport=forbidden。只接受这一同步声明，
    // 完整进入摘要；需要任务或未知扩展的执行语义不能因丢弃字段而隐式启用。
    if map.keys().any(|key| {
        !matches!(
            key.as_str(),
            "name"
                | "description"
                | "inputSchema"
                | "outputSchema"
                | "title"
                | "annotations"
                | "_meta"
                | "execution"
        )
    }) || !value["name"]
        .as_str()
        .is_some_and(|name| valid_registry_name(name, 32))
        || map
            .get("description")
            .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 4096))
        || map
            .get("title")
            .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 4096))
        || !valid_mcp_schema(&value["inputSchema"])
        || map
            .get("outputSchema")
            .is_some_and(|v| !valid_mcp_schema(v))
        || map.get("_meta").is_some_and(|v| !v.is_object())
        || map
            .get("execution")
            .is_some_and(|v| v != &serde_json::json!({"taskSupport":"forbidden"}))
        || !bounded_schema(value, 0, &mut 0)
        || serde_json::to_vec(value).expect("工具 JSON").len() > 32 * 1024
    {
        return Err(ToolRegistryError("MCP 工具定义无效、超限或含不支持的字段"));
    }
    if let Some(annotations) = map.get("annotations") {
        let Some(fields) = annotations.as_object() else {
            return Err(ToolRegistryError("MCP 工具注解不是对象"));
        };
        for (key, v) in fields {
            let valid = match key.as_str() {
                "title" => v.as_str().is_some_and(|s| s.len() <= 4096),
                "readOnlyHint" | "destructiveHint" | "idempotentHint" | "openWorldHint" => {
                    v.is_boolean()
                }
                _ => false,
            };
            if !valid {
                return Err(ToolRegistryError("MCP 工具注解无效或不受支持"));
            }
        }
    }
    Ok(())
}

fn valid_mcp_schema(value: &Value) -> bool {
    value.is_object()
        && value["type"] == "object"
        && bounded_schema(value, 0, &mut 0)
        && serde_json::to_vec(value).expect("Schema").len() <= 16 * 1024
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
                mcp: None,
            }],
            mcp: None,
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

#[cfg(test)]
mod mcp_tests;
