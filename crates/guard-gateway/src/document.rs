//! 文档解析回执：原始文件、提取内容、解析器和运行时分别绑定，不授予指令权限。
use anyhow::{ensure, Result};
use guard_schema::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PARSER: &str = include_str!("document_parser.py");
pub(crate) const MAX_INPUT: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RECEIPT: usize = 128 * 1024;

pub(crate) fn format(path: &std::path::Path) -> Option<&'static str> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "pdf" => Some("pdf"),
        "docx" => Some("docx"),
        "xlsx" => Some("xlsx"),
        "pptx" => Some("pptx"),
        "png" => Some("png"),
        "jpg" | "jpeg" => Some("jpeg"),
        _ => None,
    }
}

pub(crate) fn parser_sha256() -> Sha256Digest {
    crate::tool_registry::digest(PARSER.as_bytes())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coverage {
    pub parsed_layers: Vec<String>,
    pub uncovered: Vec<String>,
    pub empty_units: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Segment {
    pub location: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSegment {
    location: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    parser_version: String,
    source_sha256: Sha256Digest,
    source_bytes: usize,
    format: String,
    instruction_authority: String,
    limits: BTreeMap<String, u64>,
    status: String,
    text: String,
    text_sha256: Sha256Digest,
    segments: Vec<ReceiptSegment>,
    metadata: BTreeMap<String, Value>,
    coverage: Coverage,
    dependencies: BTreeMap<String, String>,
}

/// 以正文范围保存部件出处，避免在受控记忆里重复保存整段正文。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParsedDocument {
    pub parser_version: String,
    pub parser_sha256: Sha256Digest,
    pub image_sha256: Sha256Digest,
    pub receipt_sha256: Sha256Digest,
    pub source_sha256: Sha256Digest,
    pub source_bytes: usize,
    pub format: String,
    pub status: String,
    pub text: String,
    pub text_sha256: Sha256Digest,
    pub segments: Vec<Segment>,
    pub metadata: BTreeMap<String, Value>,
    pub coverage: Coverage,
    pub dependencies: BTreeMap<String, String>,
    pub limits: BTreeMap<String, u64>,
    pub instruction_authority: String,
}

impl ParsedDocument {
    pub fn from_receipt(raw: &str, expected_format: &str, image: &str) -> Result<Self> {
        ensure!(raw.len() <= MAX_RECEIPT, "解析回执超限");
        let report: Receipt = serde_json::from_str(raw)?;
        ensure!(
            report.schema == "agentguard_document_v1",
            "解析回执版本无效"
        );
        ensure!(report.format == expected_format, "解析格式与请求不一致");
        let mut offset = 0;
        let mut segments = Vec::new();
        let mut text = String::new();
        for segment in report.segments {
            if !text.is_empty() {
                text.push('\n');
                offset += 1;
            }
            let end = offset + segment.text.len();
            segments.push(Segment {
                location: segment.location,
                start_byte: offset,
                end_byte: end,
            });
            text.push_str(&segment.text);
            offset = end;
        }
        ensure!(text == report.text, "部件正文和提取正文不一致");
        let document = Self {
            parser_version: report.parser_version,
            parser_sha256: parser_sha256(),
            image_sha256: Sha256Digest::new(
                image.strip_prefix("sha256:").unwrap_or("").to_string(),
            )?,
            receipt_sha256: crate::tool_registry::digest(raw.as_bytes()),
            source_sha256: report.source_sha256,
            source_bytes: report.source_bytes,
            format: report.format,
            status: report.status,
            text: report.text,
            text_sha256: report.text_sha256,
            segments,
            metadata: report.metadata,
            coverage: report.coverage,
            dependencies: report.dependencies,
            limits: report.limits,
            instruction_authority: report.instruction_authority,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.parser_version == "agentguard-document/1",
            "文档解析版本未支持"
        );
        // 历史记录绑定当时的源码摘要，不强制等于当前版本，避免升级破坏已签名历史。
        ensure!(
            matches!(
                self.format.as_str(),
                "pdf" | "docx" | "xlsx" | "pptx" | "png" | "jpeg"
            ),
            "文档格式未支持"
        );
        ensure!(
            matches!(self.status.as_str(), "parsed" | "partial")
                && self.instruction_authority == "none",
            "解析失败或声明了指令权限"
        );
        ensure!(
            self.source_bytes > 0 && self.source_bytes <= MAX_INPUT,
            "原始文档大小不合法"
        );
        ensure!(
            !self.text.trim().is_empty()
                && self.text.len() <= 32 * 1024
                && !self.text.contains('\0'),
            "解析正文为空、过大或编码不支持"
        );
        ensure!(
            self.text_sha256 == crate::tool_registry::digest(self.text.as_bytes()),
            "提取正文摘要不一致"
        );
        ensure!(
            !self.coverage.parsed_layers.is_empty() && !self.coverage.uncovered.is_empty(),
            "解析覆盖说明缺失"
        );
        ensure!(
            self.status == "partial" || self.coverage.empty_units.is_empty(),
            "空白单元未标为部分解析"
        );
        ensure!(
            serde_json::to_vec(&self.metadata)?.len() <= 4096
                && self
                    .metadata
                    .values()
                    .all(|v| v.is_string() || v.is_boolean() || v.is_number()),
            "文档元数据无效或超限"
        );
        ensure!(
            !self.dependencies.is_empty() && !self.limits.is_empty(),
            "解析依赖或限制缺失"
        );
        let mut offset = 0;
        ensure!(!self.segments.is_empty(), "文档缺少部件出处");
        for (index, segment) in self.segments.iter().enumerate() {
            if index > 0 {
                ensure!(
                    self.text.as_bytes().get(offset) == Some(&b'\n'),
                    "部件分隔不一致"
                );
                offset += 1;
            }
            ensure!(
                !segment.location.is_empty()
                    && segment.start_byte == offset
                    && segment.end_byte > offset
                    && segment.end_byte <= self.text.len()
                    && self.text.is_char_boundary(offset)
                    && self.text.is_char_boundary(segment.end_byte),
                "文档部件范围无效"
            );
            offset = segment.end_byte;
        }
        ensure!(offset == self.text.len(), "文档部件范围没有覆盖提取正文");
        ensure!(
            serde_json::to_vec(self)?.len() <= 60 * 1024,
            "解析记忆超限，不保存截断结果"
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn test_receipt() -> String {
    serde_json::json!({
        "schema":"agentguard_document_v1","parser_version":"agentguard-document/1",
        "source_sha256":"ab".repeat(32),"source_bytes":100,"format":"pdf",
        "instruction_authority":"none","limits":{"input_bytes":MAX_INPUT},"status":"parsed",
        "text":"蓝鹭资料\n项目代号 ALPHA","text_sha256":crate::tool_registry::digest("蓝鹭资料\n项目代号 ALPHA".as_bytes()),
        "segments":[{"location":"page:1","text":"蓝鹭资料"},{"location":"page:2","text":"项目代号 ALPHA"}],
        "metadata":{"title":"合成文档"},"coverage":{"parsed_layers":["pdf_text"],"uncovered":["图片未解析"],"empty_units":[]},
        "dependencies":{"pypdf":"6.18.1"}
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(raw: &str) -> Result<ParsedDocument> {
        ParsedDocument::from_receipt(raw, "pdf", &format!("sha256:{}", "cd".repeat(32)))
    }

    #[test]
    fn 原始提取及回执摘要分开绑定且部件范围保留中文边界() {
        let raw = test_receipt();
        let document = parse(&raw).unwrap();
        assert_ne!(document.source_sha256, document.text_sha256);
        assert_eq!(
            document.receipt_sha256,
            crate::tool_registry::digest(raw.as_bytes())
        );
        assert_eq!(
            &document.text[document.segments[1].start_byte..document.segments[1].end_byte],
            "项目代号 ALPHA"
        );
        assert_eq!(document.segments[1].location, "page:2");
        let reopened: ParsedDocument =
            serde_json::from_str(&serde_json::to_string(&document).unwrap()).unwrap();
        reopened.validate().unwrap();
        assert!(reopened == document);
    }

    #[test]
    fn 修改正文摘要格式权限分段或覆盖说明均拒绝() {
        for (pointer, value) in [
            ("/text", serde_json::json!("被替换正文")),
            ("/text_sha256", serde_json::json!("ef".repeat(32))),
            ("/format", serde_json::json!("docx")),
            ("/instruction_authority", serde_json::json!("trusted")),
            ("/status", serde_json::json!("malformed")),
            ("/segments/0/text", serde_json::json!("伪造部件")),
            ("/coverage/uncovered", serde_json::json!([])),
            ("/coverage/empty_units", serde_json::json!(["page:3"])),
            ("/source_bytes", serde_json::json!(MAX_INPUT + 1)),
        ] {
            let mut raw: Value = serde_json::from_str(&test_receipt()).unwrap();
            *raw.pointer_mut(pointer).unwrap() = value;
            assert!(parse(&raw.to_string()).is_err(), "{pointer}");
        }
    }

    #[test]
    fn 部分解析保留空白缺口但空正文不能进入记忆() {
        let mut raw: Value = serde_json::from_str(&test_receipt()).unwrap();
        raw["status"] = serde_json::json!("partial");
        raw["coverage"]["empty_units"] = serde_json::json!(["page:3"]);
        assert_eq!(
            parse(&raw.to_string()).unwrap().coverage.empty_units,
            ["page:3"]
        );
        raw["text"] = serde_json::json!("");
        raw["text_sha256"] = serde_json::json!(crate::tool_registry::digest(b""));
        raw["segments"] = serde_json::json!([]);
        assert!(parse(&raw.to_string()).is_err());
    }

    #[test]
    fn 历史文档保留原解析器身份而范围损坏不能读取() {
        let mut document = parse(&test_receipt()).unwrap();
        document.parser_sha256 = crate::tool_registry::digest("旧解析器".as_bytes());
        document.validate().unwrap();
        document.segments[0].end_byte = 1;
        assert!(document.validate().is_err());
    }
}
