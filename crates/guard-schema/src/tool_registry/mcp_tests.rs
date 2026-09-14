use super::*;
use serde_json::json;

fn raw_tool() -> Value {
    json!({"name":"read","title":"中文研究 👩‍💻","description":"读取授权副本",
        "inputSchema":{"type":"object","properties":{"path":{"type":"string"}}},
        "outputSchema":{"type":"object","properties":{"text":{"type":"string"}}},
        "annotations":{"title":"备用名称","readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false},
        "execution":{"taskSupport":"forbidden"},
        "_meta":{"example.org/metadata":{"note":"原始\u{200b}文字","values":[1,2]}}})
}
fn observation(tool: Value) -> ToolServiceManifest {
    ToolServiceManifest::from_mcp("fixture-service".into(), "fixture".into(), ToolPackageIdentity {
        package_id:"fixture-package".into(), version:"1.0".into(), sha256:Sha256Digest::new("a".repeat(64)).unwrap(),
    }, Sha256Digest::new("b".repeat(64)).unwrap(),
        json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1.0"},"instructions":"服务原文只作数据"}),
        json!({"tools":[tool],"_meta":{"revision":"one"},"vendor_note":"结果扩展也保留"})).unwrap()
}

#[test]
fn 旧清单序列化和摘要编码保持不变() {
    let old = json!({"registry_version":1,"service_id":"fixture-service","namespace":"fixture","service_version":"1.0",
        "package":{"package_id":"fixture-package","version":"1.0","sha256":"a".repeat(64)},
        "tools":[{"name":"read","description":"旧工具","input_schema":{"type":"object"},"exposure":"mcp"}]});
    let manifest: ToolServiceManifest = serde_json::from_value(old.clone()).unwrap();
    manifest.validate().unwrap();
    assert_eq!(serde_json::to_value(&manifest).unwrap(), old);
    assert_eq!(
        manifest.canonical_bytes(),
        registry_canonical_bytes("manifest", old.clone())
    );
    assert_eq!(
        manifest.tools[0].canonical_bytes(),
        registry_canonical_bytes("descriptor", old["tools"][0].clone())
    );
}

#[test]
fn 原始元数据和可选描述的存在性完整保留() {
    let raw = raw_tool();
    let manifest = observation(raw.clone());
    assert_eq!(manifest.tools[0].mcp.as_ref(), Some(&raw));
    assert_eq!(
        manifest.mcp.as_ref().unwrap().list_metadata,
        json!({"_meta":{"revision":"one"},"vendor_note":"结果扩展也保留"})
    );
    let parsed: ToolServiceManifest =
        serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(manifest, parsed);
    let mut absent = raw;
    absent.as_object_mut().unwrap().remove("description");
    let no_description = observation(absent.clone());
    assert!(no_description.tools[0].description.is_empty());
    absent["description"] = json!("");
    let empty_description = observation(absent);
    assert_ne!(
        no_description.canonical_bytes(),
        empty_description.canonical_bytes()
    );
}

#[test]
fn 完整定义拒绝不支持字段无效注解与显式空值() {
    for (field, value) in [
        ("execution", json!({"taskSupport":"required"})),
        ("execution", json!({"taskSupport":"optional"})),
        (
            "execution",
            json!({"taskSupport":"forbidden","trusted":true}),
        ),
        ("execution", Value::Null),
        ("trusted", json!(true)),
        ("title", Value::Null),
        ("description", Value::Null),
        ("outputSchema", json!({"type":"string"})),
        ("_meta", json!([])),
        ("annotations", json!({"readOnlyHint":"true"})),
        ("annotations", json!({"trusted":true})),
    ] {
        let mut raw = raw_tool();
        raw[field] = value;
        assert!(RegisteredToolDescriptor::from_mcp(raw).is_err(), "{field}");
    }
    let mut raw = raw_tool();
    let mut deep = json!({});
    for _ in 0..17 {
        deep = json!({"nested":deep});
    }
    raw["_meta"] = deep;
    assert!(RegisteredToolDescriptor::from_mcp(raw).is_err());
    let mut raw = raw_tool();
    raw["title"] = json!("x".repeat(4097));
    assert!(RegisteredToolDescriptor::from_mcp(raw).is_err());
}

#[test]
fn 原始与索引字段不一致以及不完整发现均拒绝() {
    let manifest = observation(raw_tool());
    for change in 0..11 {
        let mut m = manifest.clone();
        match change {
            0 => m.tools[0].name = "other".into(),
            1 => m.tools[0].description = "替换".into(),
            2 => m.tools[0].input_schema["additionalProperties"] = json!(false),
            3 => m.tools[0].exposure = ToolExposure::HostOnly,
            4 => m.tools[0].mcp = None,
            5 => m.mcp = None,
            6 => m.mcp.as_mut().unwrap().initialization["protocolVersion"] = json!("2024-11-05"),
            7 => m.mcp.as_mut().unwrap().initialization["serverInfo"]["version"] = json!("2.0"),
            8 => m.mcp.as_mut().unwrap().list_metadata["nextCursor"] = Value::Null,
            9 => m.mcp.as_mut().unwrap().list_metadata["tools"] = json!([]),
            _ => m.mcp.as_mut().unwrap().initialization["capabilities"]["tools"] = Value::Null,
        }
        assert!(m.validate().is_err(), "{change}");
    }
}

#[test]
fn 元数据排序不改变内容但数组次序和隐藏字节改变摘要() {
    let a = observation(raw_tool());
    let mut b = a.clone();
    b.tools[0].mcp.as_mut().unwrap()["_meta"]["example.org/metadata"] =
        json!({"values":[1,2],"note":"原始\u{200b}文字"});
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    b.tools[0].mcp.as_mut().unwrap()["_meta"]["example.org/metadata"]["values"] = json!([2, 1]);
    assert_ne!(a.tools[0].canonical_bytes(), b.tools[0].canonical_bytes());
    let mut b = a.clone();
    b.tools[0].mcp.as_mut().unwrap()["title"] = json!("中文研究 👩‍💻\u{200b}");
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
}
