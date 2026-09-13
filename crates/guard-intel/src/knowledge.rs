//! GCSA 威胁知识库：离线资料与验收证据，不参与执行授权或规则包加载。
//!
//! 摘要、来源 URL 和签名信任声明只能描述证据，不能授予权限。校验通过只代表登记
//! 数据自洽；来源真实性、测试结果真实性仍须独立审核，不能由一个字段自证。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path};
use thiserror::Error;

pub const KNOWLEDGE_SCHEMA_VERSION: &str = "0.1.0";
pub const TAXONOMY_VERSION: &str = "0.1.0";
pub const LEGACY_EXAMPLES_VERSION: &str = "message-examples-2026-09-09";
pub const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;

// v0.1 冻结的语义键；中文显示名称可修订，ID 不得分配给另一个语义键。
const TECHNIQUE_KEYS: [&str; 18] = [
    "indirect_prompt_injection",
    "hidden_multimodal_injection",
    "context_poisoning",
    "memory_poisoning",
    "tool_mcp_poisoning",
    "agent_goal_hijacking",
    "agent_impersonation",
    "agent_to_agent_injection",
    "agent_social_engineering",
    "agent_worm",
    "agent_supply_chain",
    "excessive_permission_abuse",
    "agent_credential_theft",
    "runtime_prompt_injection",
    "runtime_context_tampering",
    "safety_judge_manipulation",
    "rag_poisoning",
    "multi_agent_trust_abuse",
];
const LEGACY_TARGETS: [usize; 7] = [1, 2, 4, 7, 8, 10, 14];

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("读取知识库失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("解析知识库失败：{0}")]
    Parse(#[from] serde_json::Error),
    #[error("知识库超过 {MAX_CATALOG_BYTES} 字节限制")]
    TooLarge,
    #[error("手法引用无法解析：{0}")]
    Unresolved(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeCatalog {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub catalog_version: String,
    pub trust: KnowledgeTrust,
    pub stages: Vec<Stage>,
    pub techniques: Vec<Technique>,
    pub migrations: Vec<Migration>,
    pub cases: Vec<ThreatCase>,
    pub rules: Vec<RuleMapping>,
    pub scenarios: Vec<AcceptanceScenario>,
    pub coverage: Vec<ProductCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeTrust {
    pub signature_status: SignatureStatus,
    pub purpose: String,
    pub authorization_effect: AuthorizationEffect,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    UnsignedReferenceData,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationEffect {
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub id: String,
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Technique {
    pub id: String,
    pub key: String,
    pub version: String,
    pub name: String,
    pub definition: String,
    pub prerequisites: Vec<String>,
    pub entry_points: Vec<String>,
    pub stage_ids: Vec<String>,
    pub impact: String,
    pub platforms: Vec<String>,
    pub observable_signals: Vec<String>,
    pub mitigations: Vec<String>,
    pub uncovered: String,
    pub related_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub source_version: String,
    pub source_id: String,
    pub target_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseEvidence {
    PublicIncident,
    PublicResearch,
    ObservedAttempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub title: String,
    pub publisher: String,
    pub url: String,
    pub primary: bool,
    pub verified_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatCase {
    pub id: String,
    pub title: String,
    pub evidence: CaseEvidence,
    pub occurred_at: Option<String>,
    pub disclosed_at: Option<String>,
    pub technique_ids: Vec<String>,
    pub unmapped_reason: Option<String>,
    pub summary: String,
    pub evidence_boundary: String,
    pub affected_versions: Option<Vec<String>>,
    pub sources: Vec<EvidenceSource>,
    pub iocs: Vec<Observable>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observable {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub purpose: String,
    pub source_url: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub sharing: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMapping {
    pub id: String,
    pub technique_ids: Vec<String>,
    pub source_path: String,
    pub source_anchor: String,
    pub telemetry: Vec<String>,
    pub false_positive_conditions: Vec<String>,
    pub action: String,
    pub version: String,
    pub limitation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    NotRun,
    Passed,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScenario {
    pub id: String,
    pub title: String,
    pub technique_ids: Vec<String>,
    pub case_ids: Vec<String>,
    pub rule_ids: Vec<String>,
    pub environment: String,
    pub normal_task: String,
    pub adversarial_steps: Vec<String>,
    pub expected_effects: Vec<String>,
    pub actual_effects: Vec<String>,
    pub status: RunStatus,
    pub status_reason: String,
    pub candidate_sha256: Option<String>,
    pub fixtures: Vec<Artifact>,
    pub evidence: Vec<Artifact>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Unknown,
    NotIntegrated,
    Observable,
    OfflineRulePassed,
    ControlledRuntimeBlocked,
    SpecifiedEnvironmentPassed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductCoverage {
    pub id: String,
    pub technique_id: String,
    pub entry_point: String,
    pub platform: String,
    pub execution_mode: String,
    pub product_version: String,
    pub status: CoverageState,
    pub scenario_ids: Vec<String>,
    pub evidence: Vec<Artifact>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeIssue {
    pub location: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeSummary {
    pub taxonomy_version: String,
    pub techniques: usize,
    pub cases: usize,
    pub public_incidents: usize,
    pub public_research: usize,
    pub observed_attempts: usize,
    pub scenarios: usize,
    pub scenarios_not_run: usize,
    pub coverage_unknown_or_not_integrated: usize,
}

impl KnowledgeCatalog {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, KnowledgeError> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take((MAX_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, KnowledgeError> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(KnowledgeError::TooLarge);
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn summary(&self) -> KnowledgeSummary {
        KnowledgeSummary {
            taxonomy_version: self.taxonomy_version.clone(),
            techniques: self.techniques.len(),
            cases: self.cases.len(),
            public_incidents: self
                .cases
                .iter()
                .filter(|c| c.evidence == CaseEvidence::PublicIncident)
                .count(),
            public_research: self
                .cases
                .iter()
                .filter(|c| c.evidence == CaseEvidence::PublicResearch)
                .count(),
            observed_attempts: self
                .cases
                .iter()
                .filter(|c| c.evidence == CaseEvidence::ObservedAttempt)
                .count(),
            scenarios: self.scenarios.len(),
            scenarios_not_run: self
                .scenarios
                .iter()
                .filter(|s| s.status == RunStatus::NotRun)
                .count(),
            coverage_unknown_or_not_integrated: self
                .coverage
                .iter()
                .filter(|c| {
                    matches!(
                        c.status,
                        CoverageState::Unknown | CoverageState::NotIntegrated
                    )
                })
                .count(),
        }
    }

    /// 历史材料必须带来源版本；没有来源版本的 ATI 短号一律拒绝，避免 003 被错误重释。
    pub fn resolve_technique(
        &self,
        id: &str,
        source_version: Option<&str>,
    ) -> Result<&Technique, KnowledgeError> {
        if !self.validate().is_empty() {
            return Err(KnowledgeError::Unresolved("目录校验未通过".into()));
        }
        let target = match source_version {
            None if id.starts_with("GCSA-ATI-") => id.to_owned(),
            Some(TAXONOMY_VERSION) => {
                if id.starts_with("GCSA-ATI-") {
                    id.to_owned()
                } else if id.starts_with("ATI-") {
                    format!("GCSA-{id}")
                } else {
                    return Err(KnowledgeError::Unresolved(id.into()));
                }
            }
            Some(version) if version == LEGACY_EXAMPLES_VERSION => {
                let short = id.strip_prefix("GCSA-").unwrap_or(id);
                self.migrations
                    .iter()
                    .find(|m| m.source_version == version && m.source_id == short)
                    .map(|m| m.target_id.clone())
                    .ok_or_else(|| KnowledgeError::Unresolved(id.into()))?
            }
            _ => {
                return Err(KnowledgeError::Unresolved(format!(
                    "{id}；需要明确且支持的来源版本"
                )))
            }
        };
        self.techniques
            .iter()
            .find(|t| t.id == target)
            .ok_or(KnowledgeError::Unresolved(target))
    }

    /// 校验登记约束，不运行样本，不拉取来源，不更改产品策略。
    pub fn validate(&self) -> Vec<KnowledgeIssue> {
        let mut errors = Vec::new();
        if self.schema_version != KNOWLEDGE_SCHEMA_VERSION {
            issue(&mut errors, "schema_version", "不支持的结构版本");
        }
        if self.taxonomy_version != TAXONOMY_VERSION {
            issue(&mut errors, "taxonomy_version", "不支持的分类版本");
        }
        if !version_valid(&self.catalog_version) {
            issue(&mut errors, "catalog_version", "必须为三段数字版本");
        }
        required(&mut errors, "trust.purpose", &self.trust.purpose);
        let stages = ids(
            &mut errors,
            "stages",
            self.stages.iter().map(|x| x.id.as_str()),
        );
        let techniques = ids(
            &mut errors,
            "techniques",
            self.techniques.iter().map(|x| x.id.as_str()),
        );
        let cases = ids(
            &mut errors,
            "cases",
            self.cases.iter().map(|x| x.id.as_str()),
        );
        let rules = ids(
            &mut errors,
            "rules",
            self.rules.iter().map(|x| x.id.as_str()),
        );
        let scenarios = ids(
            &mut errors,
            "scenarios",
            self.scenarios.iter().map(|x| x.id.as_str()),
        );
        ids(
            &mut errors,
            "coverage",
            self.coverage.iter().map(|x| x.id.as_str()),
        );
        if self.techniques.len() != TECHNIQUE_KEYS.len() {
            issue(&mut errors, "techniques", "v0.1 必须保留全部 18 个手法");
        }
        for (index, key) in TECHNIQUE_KEYS.iter().enumerate() {
            let id = format!("GCSA-ATI-{:03}", index + 1);
            if !self.techniques.iter().any(|t| t.id == id && t.key == *key) {
                issue(&mut errors, &id, "缺失手法或冻结编号被重新赋义");
            }
        }
        for stage in &self.stages {
            required(&mut errors, &stage.id, &stage.name);
            required(&mut errors, &stage.id, &stage.definition);
        }
        for technique in &self.techniques {
            for text in [
                &technique.name,
                &technique.definition,
                &technique.impact,
                &technique.uncovered,
            ] {
                required(&mut errors, &technique.id, text);
            }
            if !version_valid(&technique.version) {
                issue(&mut errors, &technique.id, "手法版本错误");
            }
            for values in [
                &technique.prerequisites,
                &technique.entry_points,
                &technique.platforms,
                &technique.observable_signals,
                &technique.mitigations,
                &technique.stage_ids,
            ] {
                required_list(&mut errors, &technique.id, values);
            }
            references(&mut errors, &technique.id, &technique.stage_ids, &stages);
            references(
                &mut errors,
                &technique.id,
                &technique.related_ids,
                &techniques,
            );
        }
        let mut migration_keys = BTreeSet::new();
        for migration in &self.migrations {
            let key = format!("{}:{}", migration.source_version, migration.source_id);
            if !migration_keys.insert(key.clone()) {
                issue(&mut errors, &key, "重复或冲突的迁移短号");
            }
            references(
                &mut errors,
                &key,
                std::slice::from_ref(&migration.target_id),
                &techniques,
            );
            required(&mut errors, &key, &migration.reason);
            let expected = LEGACY_TARGETS
                .iter()
                .enumerate()
                .find(|(i, _)| migration.source_id == format!("ATI-{:03}", i + 1));
            if migration.source_version != LEGACY_EXAMPLES_VERSION
                || expected.is_none_or(|(_, target)| {
                    migration.target_id != format!("GCSA-ATI-{target:03}")
                })
            {
                issue(&mut errors, &key, "来源版本或迁移目标与已登记历史不符");
            }
        }
        if self.migrations.len() != LEGACY_TARGETS.len() {
            issue(&mut errors, "migrations", "必须保留全部 7 项历史迁移");
        }
        let mut observable_ids = BTreeSet::new();
        for case in &self.cases {
            for text in [&case.title, &case.summary, &case.evidence_boundary] {
                required(&mut errors, &case.id, text);
            }
            references(&mut errors, &case.id, &case.technique_ids, &techniques);
            if case.technique_ids.is_empty()
                && case
                    .unmapped_reason
                    .as_deref()
                    .is_none_or(|x| x.trim().is_empty())
            {
                issue(&mut errors, &case.id, "未映射手法必须说明原因");
            }
            if !case.sources.iter().any(|s| s.primary) {
                issue(&mut errors, &case.id, "案例需要至少一个原始来源");
            }
            for source in &case.sources {
                for text in [&source.title, &source.publisher] {
                    required(&mut errors, &case.id, text);
                }
                if !source.url.starts_with("https://")
                    || source.url.len() < 10
                    || !date_valid(&source.verified_on)
                {
                    issue(&mut errors, &case.id, "来源必须有 HTTPS 地址和核对日期");
                }
            }
            if (case.affected_versions.is_none()
                || case.iocs.is_empty()
                || case.occurred_at.is_none()
                || case.disclosed_at.is_none())
                && case.unknowns.is_empty()
            {
                issue(
                    &mut errors,
                    &case.id,
                    "缺失版本、IOC 或时间必须记录未知说明",
                );
            }
            for ioc in &case.iocs {
                if ioc.id.trim().is_empty() || !observable_ids.insert(ioc.id.clone()) {
                    issue(&mut errors, &case.id, "IOC 编号缺失或重复");
                }
                for text in [
                    &ioc.kind,
                    &ioc.value,
                    &ioc.purpose,
                    &ioc.source_url,
                    &ioc.sharing,
                ] {
                    required(&mut errors, &ioc.id, text);
                }
                if !case.sources.iter().any(|s| s.url == ioc.source_url) {
                    issue(&mut errors, &ioc.id, "IOC 来源未登记");
                }
            }
        }
        for rule in &self.rules {
            required_list(&mut errors, &rule.id, &rule.technique_ids);
            references(&mut errors, &rule.id, &rule.technique_ids, &techniques);
            for text in [
                &rule.action,
                &rule.limitation,
                &rule.source_path,
                &rule.source_anchor,
            ] {
                required(&mut errors, &rule.id, text);
            }
            if !rule.source_anchor.contains(&rule.id) {
                issue(&mut errors, &rule.id, "规则锚点必须含原有规则编号");
            }
            for values in [&rule.telemetry, &rule.false_positive_conditions] {
                required_list(&mut errors, &rule.id, values);
            }
            if !version_valid(&rule.version) {
                issue(&mut errors, &rule.id, "规则映射版本错误");
            }
        }
        for scenario in &self.scenarios {
            references(
                &mut errors,
                &scenario.id,
                &scenario.technique_ids,
                &techniques,
            );
            references(&mut errors, &scenario.id, &scenario.case_ids, &cases);
            references(&mut errors, &scenario.id, &scenario.rule_ids, &rules);
            for text in [
                &scenario.title,
                &scenario.environment,
                &scenario.normal_task,
                &scenario.status_reason,
            ] {
                required(&mut errors, &scenario.id, text);
            }
            required_list(&mut errors, &scenario.id, &scenario.expected_effects);
            if scenario.fixtures.is_empty() {
                issue(&mut errors, &scenario.id, "验收登记需要本地夹具");
            }
            if matches!(scenario.status, RunStatus::Passed | RunStatus::Failed) {
                if scenario.actual_effects.is_empty()
                    || scenario.evidence.is_empty()
                    || scenario
                        .candidate_sha256
                        .as_deref()
                        .is_none_or(|s| !sha_valid(s))
                {
                    issue(
                        &mut errors,
                        &scenario.id,
                        "已运行场景必须有实际副作用、候选摘要和证据",
                    );
                }
            } else if !scenario.actual_effects.is_empty()
                || !scenario.evidence.is_empty()
                || scenario.candidate_sha256.is_some()
            {
                issue(
                    &mut errors,
                    &scenario.id,
                    "未运行或阻塞场景不能填写运行成功证据",
                );
            }
            for artifact in scenario.fixtures.iter().chain(&scenario.evidence) {
                validate_artifact(&mut errors, &scenario.id, artifact);
            }
        }
        for coverage in &self.coverage {
            references(
                &mut errors,
                &coverage.id,
                std::slice::from_ref(&coverage.technique_id),
                &techniques,
            );
            references(
                &mut errors,
                &coverage.id,
                &coverage.scenario_ids,
                &scenarios,
            );
            for text in [
                &coverage.entry_point,
                &coverage.platform,
                &coverage.execution_mode,
                &coverage.product_version,
                &coverage.reason,
            ] {
                required(&mut errors, &coverage.id, text);
            }
            if !matches!(
                coverage.status,
                CoverageState::Unknown | CoverageState::NotIntegrated
            ) {
                if coverage.evidence.is_empty() || coverage.scenario_ids.is_empty() {
                    issue(&mut errors, &coverage.id, "正向覆盖必须引用场景及证据");
                }
                for id in &coverage.scenario_ids {
                    if !self.scenarios.iter().any(|s| {
                        &s.id == id
                            && s.status == RunStatus::Passed
                            && s.technique_ids.contains(&coverage.technique_id)
                    }) {
                        issue(
                            &mut errors,
                            &coverage.id,
                            "正向覆盖需要已通过且匹配手法的场景",
                        );
                    }
                }
            }
            for artifact in &coverage.evidence {
                validate_artifact(&mut errors, &coverage.id, artifact);
            }
        }
        for technique in &self.techniques {
            if !self.coverage.iter().any(|c| c.technique_id == technique.id) {
                issue(
                    &mut errors,
                    &technique.id,
                    "缺少产品覆盖状态，不能将遗漏当成已覆盖",
                );
            }
        }
        errors
    }

    /// 在指定仓库内核对规则锚点、夹具与证据摘要；拒绝绝对路径、上跳和链接逃逸。
    pub fn validate_repository(&self, repository_root: impl AsRef<Path>) -> Vec<KnowledgeIssue> {
        let root = repository_root.as_ref();
        let mut errors = self.validate();
        for rule in &self.rules {
            match read_artifact(root, &rule.source_path) {
                Ok(bytes) if String::from_utf8_lossy(&bytes).contains(&rule.source_anchor) => {}
                Ok(_) => issue(&mut errors, &rule.id, "规则引用的锚点不存在"),
                Err(error) => issue(&mut errors, &rule.id, &error),
            }
        }
        let artifacts = self
            .scenarios
            .iter()
            .flat_map(|s| s.fixtures.iter().chain(&s.evidence))
            .chain(self.coverage.iter().flat_map(|c| &c.evidence));
        for artifact in artifacts {
            match read_artifact(root, &artifact.path) {
                Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == artifact.sha256 => {}
                Ok(_) => issue(&mut errors, &artifact.path, "文件摘要不匹配"),
                Err(error) => issue(&mut errors, &artifact.path, &error),
            }
        }
        errors
    }
}

fn issue(errors: &mut Vec<KnowledgeIssue>, location: &str, message: &str) {
    errors.push(KnowledgeIssue {
        location: location.into(),
        message: message.into(),
    });
}
fn required(errors: &mut Vec<KnowledgeIssue>, location: &str, text: &str) {
    if text.trim().is_empty() {
        issue(errors, location, "必需文本不能为空");
    }
}
fn required_list(errors: &mut Vec<KnowledgeIssue>, location: &str, values: &[String]) {
    if values.is_empty() {
        issue(errors, location, "必需列表不能为空");
    }
    for value in values {
        required(errors, location, value);
    }
}
fn ids<'a>(
    errors: &mut Vec<KnowledgeIssue>,
    location: &str,
    values: impl Iterator<Item = &'a str>,
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || !set.insert(value.into()) {
            issue(errors, location, "编号为空或重复");
        }
    }
    set
}
fn references(
    errors: &mut Vec<KnowledgeIssue>,
    location: &str,
    values: &[String],
    targets: &BTreeSet<String>,
) {
    for value in values {
        if !targets.contains(value) {
            issue(errors, location, &format!("悬空引用：{value}"));
        }
    }
}
fn version_valid(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && (p.len() == 1 || !p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u32>().is_ok()
        })
}
fn date_valid(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        parts[0].parse::<u32>(),
        parts[1].parse::<u32>(),
        parts[2].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    year > 0 && day > 0 && day <= days
}
fn sha_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn relative_path_valid(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn validate_artifact(errors: &mut Vec<KnowledgeIssue>, location: &str, artifact: &Artifact) {
    if !relative_path_valid(&artifact.path) || !sha_valid(&artifact.sha256) {
        issue(errors, location, "证据必须有仓库内相对路径和 SHA-256");
    }
    required(errors, location, &artifact.provenance);
}
fn read_artifact(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    if !relative_path_valid(relative) {
        return Err("拒绝非仓库相对路径".into());
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err("文件不存在或链接逃出仓库".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err("单个证据超过 1 MiB，须登记受控摘要文件".into());
    }
    Ok(bytes)
}
