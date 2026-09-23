//! 知识库到 STIX 2.1 的本地导入／导出。
//!
//! 手法映射 attack-pattern，案例映射 report，IOC 映射 indicator 与可观察对象，
//! 缓解映射 course-of-action。GCSA 字段放在 `x-gcsa-*`。导入保留对象上的未知字段，
//! 引用对不上就拒绝，不静默丢掉。本模块不联网，也不授予任何执行权限。

use crate::knowledge::{KnowledgeCatalog, Observable};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const SPEC_VERSION: &str = "2.1";
const EXPORTED_AT: &str = "2026-09-22T00:00:00.000Z";
const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StixError {
    #[error("解析 STIX bundle 失败：{0}")]
    Parse(#[from] serde_json::Error),
    #[error("STIX bundle 超过 {MAX_BUNDLE_BYTES} 字节限制")]
    TooLarge,
    #[error("{0}")]
    Invalid(String),
}

/// 导入后的 bundle。对象顺序和未知字段按读入时保留。
#[derive(Debug, Clone)]
pub struct StixBundle {
    envelope: Map<String, Value>,
    objects: Vec<Map<String, Value>>,
}

impl StixBundle {
    pub fn to_value(&self) -> Value {
        let mut envelope = self.envelope.clone();
        envelope.insert(
            "objects".into(),
            Value::Array(self.objects.iter().cloned().map(Value::Object).collect()),
        );
        Value::Object(envelope)
    }

    pub fn technique_ids(&self) -> Vec<String> {
        self.extension_strings("attack-pattern", "x-gcsa-id")
    }

    pub fn case_ids(&self) -> Vec<String> {
        self.extension_strings("report", "x-gcsa-id")
    }

    pub fn observable_values(&self) -> Vec<String> {
        self.objects
            .iter()
            .filter(|object| object.get("type").and_then(Value::as_str) == Some("indicator"))
            .filter_map(|object| object.get("x-gcsa-observable"))
            .filter_map(|value| serde_json::from_value::<Observable>(value.clone()).ok())
            .map(|observable| observable.value)
            .collect()
    }

    pub fn mitigations(&self) -> Vec<(String, String)> {
        self.objects
            .iter()
            .filter(|object| object.get("type").and_then(Value::as_str) == Some("course-of-action"))
            .filter_map(|object| {
                let technique = object.get("x-gcsa-technique-id")?.as_str()?.to_owned();
                let text = object.get("x-gcsa-mitigation")?.as_str()?.to_owned();
                Some((technique, text))
            })
            .collect()
    }

    fn extension_strings(&self, stix_type: &str, key: &str) -> Vec<String> {
        self.objects
            .iter()
            .filter(|object| object.get("type").and_then(Value::as_str) == Some(stix_type))
            .filter_map(|object| object.get(key).and_then(Value::as_str).map(str::to_owned))
            .collect()
    }
}

/// 从已通过校验的知识库导出本地 bundle。目录不自洽时拒绝导出。
pub fn export_catalog(catalog: &KnowledgeCatalog) -> Result<StixBundle, StixError> {
    let issues = catalog.validate();
    if !issues.is_empty() {
        let detail = issues
            .iter()
            .map(|issue| format!("{}: {}", issue.location, issue.message))
            .collect::<Vec<_>>()
            .join("；");
        return Err(StixError::Invalid(format!("知识库校验未通过：{detail}")));
    }

    let mut objects = Vec::new();
    let mut technique_stix = Map::new();
    for technique in &catalog.techniques {
        let id = stix_id("attack-pattern", &technique.id);
        technique_stix.insert(technique.id.clone(), Value::String(id.clone()));
        let mut object = sdo("attack-pattern", &id);
        object.insert("name".into(), Value::String(technique.name.clone()));
        object.insert("x-gcsa-id".into(), Value::String(technique.id.clone()));
        object.insert(
            "x-gcsa-technique".into(),
            serde_json::to_value(technique).map_err(StixError::Parse)?,
        );
        let coverage: Vec<_> = catalog
            .coverage
            .iter()
            .filter(|item| item.technique_id == technique.id)
            .cloned()
            .collect();
        object.insert(
            "x-gcsa-coverage".into(),
            serde_json::to_value(coverage).map_err(StixError::Parse)?,
        );
        objects.push(object);

        for (index, mitigation) in technique.mitigations.iter().enumerate() {
            let coa_id = stix_id(
                "course-of-action",
                &format!("{}#{index}:{mitigation}", technique.id),
            );
            let mut course = sdo("course-of-action", &coa_id);
            course.insert("name".into(), Value::String(mitigation.clone()));
            course.insert(
                "x-gcsa-technique-id".into(),
                Value::String(technique.id.clone()),
            );
            course.insert(
                "x-gcsa-mitigation".into(),
                Value::String(mitigation.clone()),
            );
            objects.push(course);

            let mut link = sdo(
                "relationship",
                &stix_id("relationship", &format!("mitigates:{coa_id}:{id}")),
            );
            link.insert(
                "relationship_type".into(),
                Value::String("mitigates".into()),
            );
            link.insert("source_ref".into(), Value::String(coa_id));
            link.insert("target_ref".into(), Value::String(id.clone()));
            objects.push(link);
        }
    }

    for case in &catalog.cases {
        let mut refs = Vec::new();
        for technique_id in &case.technique_ids {
            let Some(stix) = technique_stix.get(technique_id).and_then(Value::as_str) else {
                return Err(StixError::Invalid(format!(
                    "案例 {} 引用了未导出的手法 {technique_id}",
                    case.id
                )));
            };
            refs.push(stix.to_owned());
        }
        for observable in &case.iocs {
            let (sco_type_name, _) = sco_type(&observable.kind);
            let sco_id = stix_id(sco_type_name, &observable.id);
            objects.push(sco_object(observable, &sco_id)?);
            refs.push(sco_id);
            let indicator_id = stix_id("indicator", &observable.id);
            objects.push(indicator_object(observable, &indicator_id)?);
            refs.push(indicator_id.clone());
            for technique_id in &case.technique_ids {
                let Some(target) = technique_stix.get(technique_id).and_then(Value::as_str) else {
                    return Err(StixError::Invalid(format!(
                        "案例 {} 引用了未导出的手法 {technique_id}",
                        case.id
                    )));
                };
                let target = target.to_owned();
                let mut link = sdo(
                    "relationship",
                    &stix_id(
                        "relationship",
                        &format!("indicates:{indicator_id}:{target}"),
                    ),
                );
                link.insert(
                    "relationship_type".into(),
                    Value::String("indicates".into()),
                );
                link.insert("source_ref".into(), Value::String(indicator_id.clone()));
                link.insert("target_ref".into(), Value::String(target));
                objects.push(link);
            }
        }
        if refs.is_empty() {
            let anchor_id = stix_id("x-gcsa-case-anchor", &case.id);
            let mut anchor = sdo("x-gcsa-case-anchor", &anchor_id);
            anchor.insert("x-gcsa-id".into(), Value::String(case.id.clone()));
            anchor.insert(
                "x-gcsa-unmapped-reason".into(),
                Value::String(case.unmapped_reason.clone().unwrap_or_default()),
            );
            objects.push(anchor);
            refs.push(anchor_id);
        }
        let report_id = stix_id("report", &case.id);
        let mut report = sdo("report", &report_id);
        report.insert("name".into(), Value::String(case.title.clone()));
        report.insert("published".into(), Value::String(EXPORTED_AT.into()));
        report.insert(
            "object_refs".into(),
            Value::Array(refs.into_iter().map(Value::String).collect()),
        );
        report.insert("x-gcsa-id".into(), Value::String(case.id.clone()));
        report.insert(
            "x-gcsa-case".into(),
            serde_json::to_value(case).map_err(StixError::Parse)?,
        );
        objects.push(report);
    }

    let mut envelope = Map::new();
    envelope.insert("type".into(), Value::String("bundle".into()));
    envelope.insert(
        "id".into(),
        Value::String(stix_id(
            "bundle",
            &format!("{}:{}", catalog.taxonomy_version, catalog.catalog_version),
        )),
    );
    envelope.insert("spec_version".into(), Value::String(SPEC_VERSION.into()));
    envelope.insert(
        "x-gcsa-authorization-effect".into(),
        Value::String("none".into()),
    );
    envelope.insert("x-gcsa-delivery".into(), Value::String("local-only".into()));
    Ok(StixBundle { envelope, objects })
}

pub fn export_catalog_json(catalog: &KnowledgeCatalog) -> Result<Vec<u8>, StixError> {
    let bytes = serde_json::to_vec_pretty(&export_catalog(catalog)?.to_value())?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(StixError::TooLarge);
    }
    Ok(bytes)
}

/// 读入 bundle。未知字段留在对象里；悬空引用直接拒绝。
pub fn import_bundle(bytes: &[u8]) -> Result<StixBundle, StixError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(StixError::TooLarge);
    }
    let value: Value = serde_json::from_slice(bytes)?;
    let mut envelope = value
        .as_object()
        .cloned()
        .ok_or_else(|| StixError::Invalid("bundle 必须是 JSON 对象".into()))?;
    if envelope.get("type").and_then(Value::as_str) != Some("bundle") {
        return Err(StixError::Invalid("type 必须是 bundle".into()));
    }
    require_stix_id(envelope.get("id"), "bundle")?;
    if let Some(version) = envelope.get("spec_version").and_then(Value::as_str) {
        if version != SPEC_VERSION {
            return Err(StixError::Invalid(format!(
                "只接受 STIX {SPEC_VERSION}，收到 {version}"
            )));
        }
    }
    let raw_objects = envelope
        .remove("objects")
        .ok_or_else(|| StixError::Invalid("缺少 objects".into()))?;
    let raw_objects = raw_objects
        .as_array()
        .ok_or_else(|| StixError::Invalid("objects 必须是数组".into()))?;
    let mut objects = Vec::with_capacity(raw_objects.len());
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for raw in raw_objects {
        let object = raw
            .as_object()
            .cloned()
            .ok_or_else(|| StixError::Invalid("对象必须是 JSON 对象".into()))?;
        let stix_type = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| StixError::Invalid("对象缺少 type".into()))?;
        let id = require_stix_id(object.get("id"), stix_type)?.to_owned();
        if !ids.insert(id.clone()) {
            return Err(StixError::Invalid(format!("重复的 STIX id：{id}")));
        }
        if let Some(version) = object.get("spec_version").and_then(Value::as_str) {
            if version != SPEC_VERSION {
                return Err(StixError::Invalid(format!(
                    "{id} 的 spec_version 不是 {SPEC_VERSION}"
                )));
            }
        }
        objects.push(object);
    }
    check_refs(&objects)?;
    Ok(StixBundle { envelope, objects })
}

fn check_refs(objects: &[Map<String, Value>]) -> Result<(), StixError> {
    let ids: BTreeSet<&str> = objects
        .iter()
        .filter_map(|object| object.get("id").and_then(Value::as_str))
        .collect();
    for object in objects {
        let owner = object.get("id").and_then(Value::as_str).unwrap_or("?");
        for (key, value) in object {
            if key.ends_with("_ref") {
                let target = value
                    .as_str()
                    .ok_or_else(|| StixError::Invalid(format!("{owner} 的 {key} 必须是字符串")))?;
                if !ids.contains(target) {
                    return Err(StixError::Invalid(format!(
                        "{owner} 的 {key} 指向不存在的 {target}"
                    )));
                }
            } else if key.ends_with("_refs") {
                let refs = value
                    .as_array()
                    .ok_or_else(|| StixError::Invalid(format!("{owner} 的 {key} 必须是数组")))?;
                if refs.is_empty() {
                    return Err(StixError::Invalid(format!("{owner} 的 {key} 为空")));
                }
                for reference in refs {
                    let target = reference.as_str().ok_or_else(|| {
                        StixError::Invalid(format!("{owner} 的 {key} 含非字符串"))
                    })?;
                    if !ids.contains(target) {
                        return Err(StixError::Invalid(format!(
                            "{owner} 的 {key} 指向不存在的 {target}"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn sco_object(observable: &Observable, id: &str) -> Result<Map<String, Value>, StixError> {
    let (stix_type, property) = sco_type(&observable.kind);
    let mut object = sdo(stix_type, id);
    if stix_type == "file" {
        let mut hashes = Map::new();
        hashes.insert("SHA-256".into(), Value::String(observable.value.clone()));
        object.insert("hashes".into(), Value::Object(hashes));
    } else {
        object.insert(property.into(), Value::String(observable.value.clone()));
    }
    object.insert(
        "x-gcsa-observable".into(),
        serde_json::to_value(observable).map_err(StixError::Parse)?,
    );
    Ok(object)
}

fn indicator_object(observable: &Observable, id: &str) -> Result<Map<String, Value>, StixError> {
    let (stix_type, property) = sco_type(&observable.kind);
    let pattern_key = if stix_type == "file" {
        "file:hashes.'SHA-256'".to_owned()
    } else {
        format!("{stix_type}:{property}")
    };
    let mut object = sdo("indicator", id);
    object.insert(
        "name".into(),
        Value::String(format!("{} {}", observable.kind, observable.id)),
    );
    object.insert(
        "pattern".into(),
        Value::String(format!(
            "[{pattern_key} = '{}']",
            stix_quote(&observable.value)
        )),
    );
    object.insert("pattern_type".into(), Value::String("stix".into()));
    object.insert("valid_from".into(), Value::String(EXPORTED_AT.into()));
    object.insert(
        "x-gcsa-observable".into(),
        serde_json::to_value(observable).map_err(StixError::Parse)?,
    );
    Ok(object)
}

fn sco_type(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "domain" | "domain-name" => ("domain-name", "value"),
        "url" => ("url", "value"),
        "ipv4" | "ipv4-addr" => ("ipv4-addr", "value"),
        "email" | "email-addr" => ("email-addr", "value"),
        "sha256" => ("file", "hashes"),
        _ => ("x-gcsa-observable", "value"),
    }
}

fn sdo(stix_type: &str, id: &str) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("type".into(), Value::String(stix_type.into()));
    object.insert("spec_version".into(), Value::String(SPEC_VERSION.into()));
    object.insert("id".into(), Value::String(id.into()));
    object.insert("created".into(), Value::String(EXPORTED_AT.into()));
    object.insert("modified".into(), Value::String(EXPORTED_AT.into()));
    object
}

fn require_stix_id<'a>(
    value: Option<&'a Value>,
    expected_type: &str,
) -> Result<&'a str, StixError> {
    let id = value
        .and_then(Value::as_str)
        .ok_or_else(|| StixError::Invalid(format!("{expected_type} 缺少 id")))?;
    let Some((kind, uuid)) = id.split_once("--") else {
        return Err(StixError::Invalid(format!("非法 STIX id：{id}")));
    };
    if kind != expected_type {
        return Err(StixError::Invalid(format!(
            "{id} 的类型前缀与 {expected_type} 不一致"
        )));
    }
    let parts: Vec<&str> = uuid.split('-').collect();
    let widths = [8, 4, 4, 4, 12];
    let uuid_ok = parts.len() == widths.len()
        && parts.iter().zip(widths).all(|(part, width)| {
            part.len() == width && part.chars().all(|c| c.is_ascii_hexdigit())
        });
    if !uuid_ok {
        return Err(StixError::Invalid(format!("非法 STIX id：{id}")));
    }
    Ok(id)
}

fn stix_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn stix_id(kind: &str, name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gcsa-stix-2.1:");
    hasher.update(kind.as_bytes());
    hasher.update(b":");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{kind}--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::Observable;
    use std::path::PathBuf;

    fn catalog_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../intel/knowledge/v0.1/catalog.json")
    }

    #[test]
    fn 目录往返保留手法案例缓解与扩展覆盖() {
        let catalog = KnowledgeCatalog::from_path(catalog_path()).expect("读取目录");
        let exported = export_catalog(&catalog).expect("导出");
        let bytes = serde_json::to_vec(&exported.to_value()).expect("序列化");
        let imported = import_bundle(&bytes).expect("导入");
        assert_eq!(imported.to_value(), exported.to_value());
        assert_eq!(imported.technique_ids().len(), catalog.techniques.len());
        assert_eq!(imported.case_ids().len(), catalog.cases.len());
        let expected: Vec<_> = catalog
            .techniques
            .iter()
            .flat_map(|technique| {
                technique
                    .mitigations
                    .iter()
                    .map(|text| (technique.id.clone(), text.clone()))
            })
            .collect();
        assert_eq!(imported.mitigations(), expected);
        assert_eq!(imported.to_value()["x-gcsa-authorization-effect"], "none");
    }

    #[test]
    fn ioc与未知字段往返且悬空引用被拒绝() {
        let mut catalog = KnowledgeCatalog::from_path(catalog_path()).expect("读取目录");
        let source = catalog.cases[0].sources[0].url.clone();
        catalog.cases[0].iocs.push(Observable {
            id: "IOC-ROUNDTRIP-1".into(),
            kind: "domain".into(),
            value: "evil.example".into(),
            purpose: "本地往返样例".into(),
            source_url: source,
            first_seen: None,
            last_seen: None,
            expires_at: None,
            revoked: false,
            sharing: "local-only".into(),
        });
        let mut value = export_catalog(&catalog).expect("导出").to_value();
        value["objects"][0]["x-partner-note"] = Value::String("keep".into());
        value["objects"][0]["foreign_field"] = serde_json::json!({"a": 1});
        let bytes = serde_json::to_vec(&value).expect("序列化");
        let imported = import_bundle(&bytes).expect("导入");
        assert_eq!(imported.to_value(), value);
        assert!(imported
            .observable_values()
            .iter()
            .any(|item| item == "evil.example"));

        value["objects"][0]["created_by_ref"] =
            Value::String("identity--00000000-0000-4000-8000-000000000099".into());
        let broken = serde_json::to_vec(&value).expect("序列化");
        let error = import_bundle(&broken).expect_err("悬空引用");
        assert!(error.to_string().contains("不存在"));
    }
}
