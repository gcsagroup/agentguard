//! 有限本地 Node MCP 服务：实际发现、完整 Schema 检查及宿主配置。
use crate::isolation::DockerExecutor;
use crate::mcp_package::FrozenPackage;
pub use crate::mcp_remote_service::RemoteConfig;
use crate::mcp_service::{NodeService, ServiceRegistration};
use crate::tool_registry::SharedRegistry;
use anyhow::{ensure, Result};
use guard_schema::ToolServiceManifest;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub service_id: String,
    pub namespace: String,
    pub package_path: PathBuf,
    pub package_id: String,
    pub package_version: String,
    pub entrypoint: String,
    pub arguments: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub version: u16,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    #[serde(default)]
    pub remote_services: Vec<RemoteConfig>,
}

pub(crate) struct ProxyService {
    pub service: NodeService,
    pub registration: ServiceRegistration,
    pub arguments: Vec<String>,
    pub manifest: ToolServiceManifest,
    schemas: ToolSchemas,
}
impl ProxyService {
    pub fn discover(
        config: ServiceConfig,
        image: &str,
        snapshot: &DockerExecutor,
        registry: &SharedRegistry,
        recovery: &mut crate::mcp_recovery::RecoveryLog,
    ) -> Result<Self> {
        ensure!(
            config.package_path.is_absolute(),
            "服务包必须使用宿主绝对路径"
        );
        let package = Arc::new(FrozenPackage::freeze(&config.package_path)?);
        let service = NodeService::new(image.to_owned(), package, config.entrypoint)?;
        let registration = ServiceRegistration {
            service_id: config.service_id,
            namespace: config.namespace,
            package_id: config.package_id,
            package_version: config.package_version,
        };
        let observed =
            service.discover_tracked(&registration, &config.arguments, snapshot, recovery)?;
        let manifest = observed.manifest().clone();
        let schemas = ToolSchemas::compile(&manifest)?;
        registry
            .lock()
            .map_err(|_| anyhow::anyhow!("登记锁失效"))?
            .observe_discovery(&observed)?;
        Ok(Self {
            service,
            registration,
            arguments: config.arguments,
            manifest,
            schemas,
        })
    }
    pub fn original_name<'a>(&'a self, alias: &str) -> Option<&'a str> {
        self.manifest
            .tools
            .iter()
            .find(|t| format!("mcp__{}__{}", self.manifest.namespace, t.name) == alias)
            .map(|t| t.name.as_str())
    }
    pub fn validate_input(&self, name: &str, arguments: &Value) -> Result<()> {
        self.schemas.validate_input(name, arguments)
    }
    pub fn validate_output(&self, name: &str, result: &Value) -> Result<()> {
        self.schemas.validate_output(name, result)
    }
}

/// 本地与远程服务共用同一组完整 Schema 验证，传输方式不降低校验。
pub(crate) struct ToolSchemas(
    BTreeMap<String, (jsonschema::Validator, Option<jsonschema::Validator>)>,
);
impl ToolSchemas {
    pub fn compile(manifest: &ToolServiceManifest) -> Result<Self> {
        let mut schemas = BTreeMap::new();
        for tool in &manifest.tools {
            let input = compile_schema(&tool.input_schema)?;
            let output = tool
                .mcp
                .as_ref()
                .and_then(|v| v.get("outputSchema"))
                .map(compile_schema)
                .transpose()?;
            schemas.insert(tool.name.clone(), (input, output));
        }
        Ok(Self(schemas))
    }
    pub fn validate_input(&self, name: &str, arguments: &Value) -> Result<()> {
        ensure!(
            arguments.is_object() && serde_json::to_vec(arguments)?.len() <= 24 * 1024,
            "工具参数无效或过大"
        );
        bound_value(arguments, 0, &mut 0)?;
        ensure!(
            self.0
                .get(name)
                .is_some_and(|(input, _)| input.is_valid(arguments)),
            "工具参数不符合已登记 Schema"
        );
        Ok(())
    }
    pub fn validate_output(&self, name: &str, result: &Value) -> Result<()> {
        bound_value(result, 0, &mut 0)?;
        // 工具错误可以没有成功输出结构；成功响应声明了 outputSchema 就必须提供匹配内容。
        if result.get("isError").and_then(Value::as_bool) != Some(true) {
            if let Some((_, Some(schema))) = self.0.get(name) {
                ensure!(
                    result
                        .get("structuredContent")
                        .is_some_and(|v| schema.is_valid(v)),
                    "工具返回不符合已登记 outputSchema"
                );
            }
        }
        Ok(())
    }
}
struct NoRetrieval;
impl jsonschema::Retrieve for NoRetrieval {
    fn retrieve(
        &self,
        _: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("服务 Schema 不允许读取外部资源".into())
    }
}
fn bound_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(depth <= 16 && *nodes <= 4096, "JSON 结构超出有限代理范围");
    match value {
        Value::Object(m) => {
            for v in m.values() {
                bound_value(v, depth + 1, nodes)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                bound_value(v, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn check_schema_boundary(value: &Value) -> Result<()> {
    match value {
        Value::Object(m) => {
            // 首批执行器只接受内联非递归 Schema，明确拒绝而不是忽略引用或自定义词汇。
            // 此限制也作用于嵌入注解中的这些键，完整原清单仍保留供操作者复核。
            ensure!(
                !["$ref", "$dynamicRef", "$recursiveRef", "$vocabulary", "$id"]
                    .iter()
                    .any(|k| m.contains_key(*k)),
                "本地代理暂不执行含引用、资源身份或自定义词汇的 Schema"
            );
            if let Some(draft) = m.get("$schema") {
                ensure!(
                    draft.as_str().is_some_and(|s| matches!(
                        s,
                        "http://json-schema.org/draft-07/schema#"
                            | "https://json-schema.org/draft/2019-09/schema"
                            | "https://json-schema.org/draft/2020-12/schema"
                    )),
                    "Schema 方言未支持"
                );
            }
            for v in m.values() {
                check_schema_boundary(v)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                check_schema_boundary(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn compile_schema(schema: &Value) -> Result<jsonschema::Validator> {
    bound_value(schema, 0, &mut 0)?;
    ensure!(
        serde_json::to_vec(schema)?.len() <= 16 * 1024,
        "Schema 过大"
    );
    check_schema_boundary(schema)?;
    jsonschema::options()
        .with_retriever(NoRetrieval)
        .with_pattern_options(
            jsonschema::PatternOptions::fancy_regex()
                .backtrack_limit(10_000)
                .size_limit(256 * 1024)
                .dfa_size_limit(256 * 1024),
        )
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .build(schema)
        .map_err(|_| anyhow::anyhow!("工具 Schema 无效或超出支持范围"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn 标准校验执行嵌套结构边界与额外字段限制() {
        let schema=compile_schema(&json!({"type":"object","required":["items"],"additionalProperties":false,"properties":{"items":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":1,"maximum":3}},"additionalProperties":false}}}})).unwrap();
        assert!(schema.is_valid(&json!({"items":[{"n":2}]})));
        for value in [
            json!({}),
            json!({"items":[]}),
            json!({"items":[{"n":4}]}),
            json!({"items":[{"n":1},{"n":1}]}),
            json!({"items":[{"n":1,"extra":true}]}),
            json!({"items":[{"n":1}],"approved":true}),
        ] {
            assert!(!schema.is_valid(&value));
        }
    }
    #[test]
    fn 引用自定义方言及无效关键字不会被静默忽略() {
        for schema in [
            json!({"type":"object","$ref":"file:///etc/passwd"}),
            json!({"$ref":"http://127.0.0.1:1/schema"}),
            json!({"$ref":"#"}),
            json!({"$dynamicRef":"#x"}),
            json!({"$schema":"https://example.invalid/schema"}),
            json!({"$vocabulary":{"https://example.invalid/vocab":true}}),
            json!({"type":"object","required":17}),
            json!({"type":"string","format":"agentguard-unregistered-format"}),
            json!({"type":"string","pattern":"["}),
        ] {
            assert!(compile_schema(&schema).is_err(), "{schema}");
        }
    }
    #[test]
    fn 标准格式组合和正则限制真实生效() {
        let schema=compile_schema(&json!({"type":"object","properties":{"address":{"type":"string","format":"email"},"code":{"type":"string","pattern":"^[A-Z]{2}$"}},"required":["address","code"]})).unwrap();
        assert!(schema.is_valid(&json!({"address":"user@example.invalid","code":"AB"})));
        assert!(!schema.is_valid(&json!({"address":"not-an-email","code":"AB"})));
        assert!(!schema.is_valid(&json!({"address":"user@example.invalid","code":"too-long"})));
        let mut deep = json!(1);
        for _ in 0..17 {
            deep = json!([deep]);
        }
        assert!(bound_value(&deep, 0, &mut 0).is_err());
    }
}
