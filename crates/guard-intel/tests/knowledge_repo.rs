//! 校验知识库登记、版本迁移和无害夹具；不把数据校验计作产品阻断成功。
use guard_intel::knowledge::{
    CoverageState, KnowledgeCatalog, KnowledgeError, RunStatus, LEGACY_EXAMPLES_VERSION,
    MAX_CATALOG_BYTES,
};
use serde_json::Value;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn catalog() -> KnowledgeCatalog {
    KnowledgeCatalog::from_path(root().join("intel/knowledge/v0.1/catalog.json")).unwrap()
}

#[test]
fn 仓库目录引用及全部夹具摘要通过() {
    let catalog = catalog();
    let errors = catalog.validate_repository(root());
    assert!(errors.is_empty(), "{errors:#?}");
    let summary = catalog.summary();
    assert_eq!(
        (summary.techniques, summary.cases, summary.scenarios),
        (18, 6, 12)
    );
    assert_eq!(
        (
            summary.public_incidents,
            summary.public_research,
            summary.observed_attempts
        ),
        (2, 3, 1)
    );
    assert_eq!(summary.scenarios_not_run, 12);
    assert_eq!(summary.coverage_unknown_or_not_integrated, 18);
}

#[test]
fn 冲突短号只有明确来源版本才能迁移() {
    let catalog = catalog();
    assert!(catalog.resolve_technique("ATI-003", None).is_err());
    assert_eq!(
        catalog
            .resolve_technique("ATI-003", Some("0.1.0"))
            .unwrap()
            .key,
        "context_poisoning"
    );
    assert_eq!(
        catalog
            .resolve_technique("ATI-003", Some(LEGACY_EXAMPLES_VERSION))
            .unwrap()
            .key,
        "memory_poisoning"
    );
    assert_eq!(
        catalog
            .resolve_technique("GCSA-ATI-003", Some(LEGACY_EXAMPLES_VERSION))
            .unwrap()
            .id,
        "GCSA-ATI-004"
    );
    assert!(catalog
        .resolve_technique("ATI-003", Some("unversioned"))
        .is_err());
    assert!(catalog.resolve_technique("GCSA-ATI-019", None).is_err());
}

#[test]
fn 重复编号悬空引用和重新赋义必须拒绝() {
    let mut catalog = catalog();
    catalog.techniques[1].id = catalog.techniques[0].id.clone();
    catalog.techniques[2].key = "memory_poisoning".into();
    catalog.scenarios[0].case_ids.push("不存在的案例".into());
    catalog.scenarios[0].rule_ids.push("不存在的规则".into());
    catalog.techniques[0].stage_ids.push("不存在的阶段".into());
    let errors = catalog.validate();
    assert!(errors.iter().any(|e| e.message.contains("重复")));
    assert!(errors.iter().any(|e| e.message.contains("重新赋义")));
    for target in ["不存在的案例", "不存在的规则", "不存在的阶段"] {
        assert!(errors
            .iter()
            .any(|e| e.message == format!("悬空引用：{target}")));
    }
    assert!(catalog.resolve_technique("GCSA-ATI-001", None).is_err());
}

#[test]
fn 错误版本和冲突迁移不能导入() {
    let mut catalog = catalog();
    catalog.schema_version = "0.2.0".into();
    catalog.catalog_version = "01.2.3".into();
    catalog.techniques[0].version = "latest".into();
    catalog.migrations[2].target_id = "GCSA-ATI-003".into();
    catalog.migrations.push(catalog.migrations[2].clone());
    let errors = catalog.validate();
    assert!(errors.iter().any(|e| e.location == "schema_version"));
    assert!(errors.iter().any(|e| e.location == "catalog_version"));
    assert!(errors.iter().any(|e| e.message.contains("迁移目标")));
    assert!(errors.iter().any(|e| e.message.contains("冲突的迁移")));
}

#[test]
fn 未覆盖和未运行不能伪装成通过() {
    let mut catalog = catalog();
    catalog.coverage[0].status = CoverageState::SpecifiedEnvironmentPassed;
    catalog.scenarios[0].status = RunStatus::Passed;
    catalog.scenarios[1]
        .actual_effects
        .push("声称已阻止越界".into());
    catalog
        .coverage
        .retain(|c| c.technique_id != "GCSA-ATI-018");
    let errors = catalog.validate();
    assert!(errors.iter().any(|e| e.message.contains("已运行场景必须")));
    assert!(errors.iter().any(|e| e.message.contains("正向覆盖必须")));
    assert!(errors.iter().any(|e| e.message.contains("未运行或阻塞")));
    assert!(errors.iter().any(|e| e.message.contains("缺少产品覆盖")));
}

#[test]
fn 必需字段未知状态和授予权限字段一律拒绝() {
    let value = serde_json::to_value(catalog()).unwrap();
    for (path, replacement) in [
        (
            vec!["trust", "authorization_effect"],
            Value::String("allow".into()),
        ),
        (
            vec!["trust", "signature_status"],
            Value::String("verified".into()),
        ),
    ] {
        let mut corrupt = value.clone();
        corrupt[path[0]][path[1]] = replacement;
        assert!(KnowledgeCatalog::from_json(&serde_json::to_vec(&corrupt).unwrap()).is_err());
    }
    let mut corrupt = value.clone();
    corrupt["scenarios"][0]["status"] = "covered".into();
    assert!(KnowledgeCatalog::from_json(&serde_json::to_vec(&corrupt).unwrap()).is_err());
    let mut corrupt = value.clone();
    corrupt["techniques"][0]
        .as_object_mut()
        .unwrap()
        .remove("uncovered");
    assert!(KnowledgeCatalog::from_json(&serde_json::to_vec(&corrupt).unwrap()).is_err());
    let mut corrupt = value;
    corrupt["execute"] = "不应存在的自动执行字段".into();
    assert!(KnowledgeCatalog::from_json(&serde_json::to_vec(&corrupt).unwrap()).is_err());
}

#[test]
fn 缺原始来源和错误日期拒绝() {
    let mut catalog = catalog();
    catalog.cases[0].sources[0].primary = false;
    catalog.cases[1].sources[0].verified_on = "2026-02-30".into();
    catalog.cases[2].unknowns.clear();
    let errors = catalog.validate();
    assert!(errors.iter().any(|e| e.message.contains("原始来源")));
    assert!(errors.iter().any(|e| e.message.contains("核对日期")));
    assert!(errors.iter().any(|e| e.message.contains("未知说明")));
}

#[test]
fn 路径逃逸错误摘要和删除规则锚点拒绝() {
    let mut catalog = catalog();
    catalog.scenarios[0].fixtures[0].path = "../outside.json".into();
    catalog.scenarios[1].fixtures[0].sha256 = "0".repeat(64);
    catalog.rules[0].source_anchor = "OVL-004 不存在的锚点".into();
    let errors = catalog.validate_repository(root());
    assert!(errors
        .iter()
        .any(|e| e.message.contains("拒绝非仓库相对路径")));
    assert!(errors.iter().any(|e| e.message.contains("摘要不匹配")));
    assert!(errors.iter().any(|e| e.message.contains("锚点不存在")));
}

#[test]
#[cfg(unix)]
fn 指向仓库外的符号链接不能作为证据() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("data"), b"only fixture").unwrap();
    std::os::unix::fs::symlink(outside.path().join("data"), dir.path().join("escape")).unwrap();
    let mut catalog = catalog();
    catalog.scenarios[0].fixtures[0].path = "escape".into();
    let errors = catalog.validate_repository(dir.path());
    assert!(errors.iter().any(|e| e.message.contains("链接逃出仓库")));
}

#[test]
fn 超大目录不能被加载() {
    assert!(matches!(
        KnowledgeCatalog::from_json(&vec![b' '; MAX_CATALOG_BYTES + 1]),
        Err(KnowledgeError::TooLarge)
    ));
}

#[test]
fn 无害输入有正常对照并保留语言字符和测试凭据() {
    let catalog = catalog();
    for scenario in &catalog.scenarios {
        let bytes = std::fs::read(root().join(&scenario.fixtures[0].path)).unwrap();
        let fixture: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(fixture["kind"].is_string());
        assert!(!scenario.normal_task.is_empty());
        assert!(!scenario.expected_effects.is_empty());
        // JSON 读取与重新序列化应保留文本；该检查不是产品侧原文保留验收。
        let roundtrip: Value =
            serde_json::from_slice(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(fixture, roundtrip);
        match scenario.id.as_str() {
            "GCSA-AS-003" => {
                let text = fixture["text"].as_str().unwrap();
                assert!(
                    text.contains("العربية") && text.contains("עברית") && text.contains('\u{200d}')
                );
                assert!(text.contains("ignore previous instructions"));
            }
            "GCSA-AS-004" => assert!(fixture["parsed_hidden"]
                .as_str()
                .unwrap()
                .contains('\u{200b}')),
            "GCSA-AS-008" => assert!(fixture["canary"]
                .as_str()
                .unwrap()
                .starts_with("GCSA_FAKE_TOKEN_NOT_A_CREDENTIAL")),
            "GCSA-AS-011" => assert_eq!(fixture["hop_limit"], 1),
            _ => (),
        }
    }
}
