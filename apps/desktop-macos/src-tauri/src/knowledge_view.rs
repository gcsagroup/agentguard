//! 工作区的离线知识资料。固定内嵌来源，不接受前端路径，不加载规则或执行样本。
use guard_intel::knowledge::{KnowledgeCatalog, KnowledgeSummary};
use serde::Serialize;
use sha2::{Digest, Sha256};

const CATALOG: &[u8] = include_bytes!("../../../../intel/knowledge/v0.1/catalog.json");

#[derive(Serialize)]
pub(crate) struct KnowledgeView {
    source: &'static str,
    sha256: String,
    instruction_authority: &'static str,
    summary: KnowledgeSummary,
    catalog: KnowledgeCatalog,
}

fn read_view(bytes: &[u8]) -> Result<KnowledgeView, String> {
    let catalog = KnowledgeCatalog::from_json(bytes).map_err(|e| e.to_string())?;
    let issues = catalog.validate();
    if !issues.is_empty() {
        return Err(format!("知识库登记校验失败：{} 项", issues.len()));
    }
    Ok(KnowledgeView {
        source: "embedded_reference",
        sha256: format!("{:x}", Sha256::digest(bytes)),
        instruction_authority: "none",
        summary: catalog.summary(),
        catalog,
    })
}

#[tauri::command]
pub(crate) fn get_knowledge_catalog() -> Result<KnowledgeView, String> {
    read_view(CATALOG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 内嵌资料保留未验收状态与原始摘要() {
        let view = get_knowledge_catalog().unwrap();
        assert_eq!(view.summary.techniques, 18);
        assert_eq!(view.summary.scenarios_not_run, 12);
        assert_eq!(view.summary.coverage_unknown_or_not_integrated, 18);
        assert_eq!(view.instruction_authority, "none");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        assert!(view.catalog.validate_repository(root).is_empty());
        assert_eq!(view.sha256, format!("{:x}", Sha256::digest(CATALOG)));
    }

    #[test]
    fn 损坏引用与伪造授权声明不返回可展示目录() {
        let original: serde_json::Value = serde_json::from_slice(CATALOG).unwrap();
        let mut invalid = original.clone();
        invalid["techniques"][0]["stage_ids"][0] = "不存在的阶段".into();
        assert!(read_view(&serde_json::to_vec(&invalid).unwrap()).is_err());
        invalid = original;
        invalid["trust"]["authorization_effect"] = "allow".into();
        assert!(read_view(&serde_json::to_vec(&invalid).unwrap()).is_err());
        assert!(read_view(b"{").is_err());
    }

    #[test]
    #[ignore = "仅在显式指定的测试输出文件生成实际命令回执，不启动或替换 App"]
    fn 导出工作区知识命令回执() {
        let path = std::env::var_os("AGENTGUARD_KNOWLEDGE_FIXTURE").expect("测试输出路径");
        let bytes = serde_json::to_vec_pretty(&get_knowledge_catalog().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}
