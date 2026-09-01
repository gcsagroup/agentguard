//! 结构化发布证据。
//!
//! 这里做的是一条可审计、可重复的发布门禁：证据必须绑定当前提交、检查种类、
//! 实际命令、退出码、时间、输出判据，以及仓库内现场复核过的产物或验收闭包摘要。
//! `.app` 的 tree-v2 绑定相对路径、类型、长度、内容与 Unix 可执行位掩码，但故意不绑定
//! xattr/ACL，也不声称覆盖完整运行语义；这些边界必须由隔离机首次启动验收补足。
//! 它能挡住空文件、错文件、旧提交、模板原样提交和随手伪造哈希；它不是签名协议，
//! 因而不声称能对抗一个愿意同时伪造全部字段和产物内容的攻击者。

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVIDENCE_SCHEMA: &str = "agentguard-release-evidence-v1";
const MAX_EVIDENCE_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_EVIDENCE_FUTURE_SECONDS: i64 = 10 * 60;
const TREE_DIGEST_DOMAIN: &[u8] = b"agentguard-tree-sha256-v2\0";
const ACCEPTANCE_DIGEST_DOMAIN: &[u8] = b"agentguard-acceptance-closure-sha256-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MacosCodesign,
    MacosNotarize,
    WindowsSign,
    AndroidSign,
    AcceptanceMacos,
    AcceptanceAndroid,
    AcceptanceFirefox,
    AcceptanceWindows,
}

impl EvidenceKind {
    pub const ALL: [Self; 8] = [
        Self::MacosCodesign,
        Self::MacosNotarize,
        Self::WindowsSign,
        Self::AndroidSign,
        Self::AcceptanceMacos,
        Self::AcceptanceAndroid,
        Self::AcceptanceFirefox,
        Self::AcceptanceWindows,
    ];

    fn required_tool(self) -> Option<&'static str> {
        match self {
            Self::MacosCodesign => Some("codesign"),
            Self::MacosNotarize => Some("notarytool"),
            Self::WindowsSign => Some("signtool"),
            Self::AndroidSign => Some("apksigner"),
            Self::AcceptanceMacos
            | Self::AcceptanceAndroid
            | Self::AcceptanceFirefox
            | Self::AcceptanceWindows => None,
        }
    }

    fn template_command(self) -> &'static str {
        match self {
            Self::MacosCodesign => "<the codesign verification command actually executed>",
            Self::MacosNotarize => "<the notarytool and stapler commands actually executed>",
            Self::WindowsSign => "<the signtool verification command actually executed>",
            Self::AndroidSign => "<the apksigner verification command actually executed>",
            Self::AcceptanceMacos => "guard-cli manual-acceptance macos docs/acceptance-macos.md <repo-relative report.md> --repo-root .",
            Self::AcceptanceAndroid => "guard-cli manual-acceptance android docs/acceptance-runbook.md <repo-relative report.md> --repo-root .",
            Self::AcceptanceFirefox => "guard-cli manual-acceptance firefox docs/acceptance-firefox.md <repo-relative report.md> --repo-root .",
            Self::AcceptanceWindows => "guard-cli manual-acceptance windows docs/acceptance-windows.md <repo-relative report.md> --repo-root .",
        }
    }

    fn template_output(self) -> &'static str {
        match self {
            Self::MacosCodesign => {
                "<codesign output containing both required verification messages>"
            }
            Self::MacosNotarize => {
                "<notarytool Accepted output plus successful stapler validation output>"
            }
            Self::WindowsSign => "<signtool Successfully verified output>",
            Self::AndroidSign => "<apksigner release-certificate output>",
            Self::AcceptanceMacos => "<output containing AGENTGUARD_ACCEPTANCE_MACOS=PASS>",
            Self::AcceptanceAndroid => "<output containing AGENTGUARD_ACCEPTANCE_ANDROID=PASS>",
            Self::AcceptanceFirefox => "<output containing AGENTGUARD_ACCEPTANCE_FIREFOX=PASS>",
            Self::AcceptanceWindows => "<output containing AGENTGUARD_ACCEPTANCE_WINDOWS=PASS>",
        }
    }

    fn acceptance_marker(self) -> Option<&'static str> {
        match self {
            Self::AcceptanceMacos => Some("AGENTGUARD_ACCEPTANCE_MACOS=PASS"),
            Self::AcceptanceAndroid => Some("AGENTGUARD_ACCEPTANCE_ANDROID=PASS"),
            Self::AcceptanceFirefox => Some("AGENTGUARD_ACCEPTANCE_FIREFOX=PASS"),
            Self::AcceptanceWindows => Some("AGENTGUARD_ACCEPTANCE_WINDOWS=PASS"),
            Self::MacosCodesign | Self::MacosNotarize | Self::WindowsSign | Self::AndroidSign => {
                None
            }
        }
    }

    fn acceptance_command(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::AcceptanceMacos => Some(("macos", "docs/acceptance-macos.md")),
            Self::AcceptanceAndroid => Some(("android", "docs/acceptance-runbook.md")),
            Self::AcceptanceFirefox => Some(("firefox", "docs/acceptance-firefox.md")),
            Self::AcceptanceWindows => Some(("windows", "docs/acceptance-windows.md")),
            Self::MacosCodesign | Self::MacosNotarize | Self::WindowsSign | Self::AndroidSign => {
                None
            }
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::MacosCodesign => "macos_codesign",
            Self::MacosNotarize => "macos_notarize",
            Self::WindowsSign => "windows_sign",
            Self::AndroidSign => "android_sign",
            Self::AcceptanceMacos => "acceptance_macos",
            Self::AcceptanceAndroid => "acceptance_android",
            Self::AcceptanceFirefox => "acceptance_firefox",
            Self::AcceptanceWindows => "acceptance_windows",
        };
        f.write_str(value)
    }
}

impl FromStr for EvidenceKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "macos_codesign" => Ok(Self::MacosCodesign),
            "macos_notarize" => Ok(Self::MacosNotarize),
            "windows_sign" => Ok(Self::WindowsSign),
            "android_sign" => Ok(Self::AndroidSign),
            "acceptance_macos" => Ok(Self::AcceptanceMacos),
            "acceptance_android" => Ok(Self::AcceptanceAndroid),
            "acceptance_firefox" => Ok(Self::AcceptanceFirefox),
            "acceptance_windows" => Ok(Self::AcceptanceWindows),
            other => Err(format!(
                "未知证据 kind {other:?};允许值:{}",
                Self::ALL
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    pub schema: String,
    pub kind: EvidenceKind,
    pub commit: String,
    pub command: String,
    pub exit_code: i32,
    pub timestamp: String,
    pub output: String,
    /// 发布签名者身份。macOS 为 Team ID，Windows/Android 为证书 SHA-256；验收类必须为 null。
    pub signer: Option<String>,
    pub artifact: ArtifactEvidence,
}

#[derive(Debug)]
pub struct EvidenceError(Vec<String>);

impl EvidenceError {
    fn new(errors: Vec<String>) -> Self {
        Self(errors)
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 发布脚本把这一行嵌进报告。任何输入里的控制字符都不能把一项错误伪装成
        // 多项输出，`|` 也不能撞上旧版脚本曾用过的字段分隔符。
        let line: String = self
            .0
            .join("; ")
            .chars()
            .map(|character| {
                if character.is_control() || character == '|' {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        f.write_str(&line)
    }
}

impl std::error::Error for EvidenceError {}

pub fn evidence_template(kind: EvidenceKind, commit: Option<&str>) -> ReleaseEvidence {
    let commit = commit
        .filter(|value| valid_full_commit(value))
        .unwrap_or("<full HEAD commit>")
        .to_string();
    ReleaseEvidence {
        schema: EVIDENCE_SCHEMA.to_string(),
        kind,
        commit,
        command: kind.template_command().to_string(),
        // 故意不是成功值。模板是一张待填写表，不是生成即通过的凭据。
        exit_code: -1,
        timestamp: "<RFC3339 timestamp>".to_string(),
        output: kind.template_output().to_string(),
        signer: kind
            .required_tool()
            .map(|_| "<expected signer identity>".to_string()),
        artifact: ArtifactEvidence {
            path: "<repo-relative regular file path>".to_string(),
            sha256: "<sha256 of artifact bytes>".to_string(),
        },
    }
}

pub fn read_evidence_file(path: &Path) -> Result<ReleaseEvidence, EvidenceError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| EvidenceError::new(vec![format!("证据文件 {path:?} 无法读取:{error}")]))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(EvidenceError::new(vec![format!(
            "证据文件 {path:?} 必须是普通文件且不能是符号链接"
        )]));
    }
    if metadata.len() > 1024 * 1024 {
        return Err(EvidenceError::new(vec![format!(
            "证据文件 {path:?} 超过 1 MiB 上限"
        )]));
    }
    let raw = std::fs::read_to_string(path).map_err(|error| {
        EvidenceError::new(vec![format!("证据文件 {path:?} 不是可读 UTF-8:{error}")])
    })?;
    serde_json::from_str(&raw)
        .map_err(|error| EvidenceError::new(vec![format!("证据 JSON 无效:{error}")]))
}

/// 发布证据里的路径会同时进入 JSON、命令记录和跨平台文档。只接受一个无需
/// shell 引号或展开的交集，避免字面路径与真实执行对象分离。
fn valid_portable_repo_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// 使用与门禁完全相同的算法计算普通文件 SHA-256 或 `.app` tree-v2 SHA-256。
pub fn artifact_digest(repo_root: &Path, artifact_path: &str) -> Result<String, EvidenceError> {
    let relative = Path::new(artifact_path);
    if !valid_portable_repo_relative_path(artifact_path) || relative.is_absolute() {
        return Err(EvidenceError::new(vec![
            "摘要路径必须是只用 / 分隔、每组件仅含 ASCII 字母数字、.、_ 或 - 的仓库相对路径；不允许空白或 shell 元字符"
                .to_string(),
        ]));
    }
    let root = std::fs::canonicalize(repo_root).map_err(|error| {
        EvidenceError::new(vec![format!("repo-root {repo_root:?} 无法解析:{error}")])
    })?;
    if !root.is_dir() {
        return Err(EvidenceError::new(vec!["repo-root 必须是目录".to_string()]));
    }
    let mut candidate = root.clone();
    for part in artifact_path.split('/') {
        candidate.push(part);
        let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
            EvidenceError::new(vec![format!(
                "摘要目标 {artifact_path:?} 不存在或无法读取:{error}"
            )])
        })?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::new(vec![format!(
                "摘要目标 {artifact_path:?} 的路径包含符号链接"
            )]));
        }
    }
    let candidate = std::fs::canonicalize(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!(
            "摘要目标 {artifact_path:?} 无法解析真实路径:{error}"
        )])
    })?;
    if !candidate.starts_with(&root) {
        return Err(EvidenceError::new(vec![format!(
            "摘要目标 {artifact_path:?} 的真实路径越出 repo-root"
        )]));
    }
    let metadata = std::fs::metadata(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!("摘要目标 {artifact_path:?} 无法读取:{error}")])
    })?;
    if metadata.is_file() && metadata.len() == 0 {
        return Err(EvidenceError::new(vec![format!(
            "摘要目标 {artifact_path:?} 不能为空文件"
        )]));
    }
    if metadata.is_dir() && !artifact_path.ends_with(".app") {
        return Err(EvidenceError::new(vec![
            "只有 .app bundle 目录可以计算 tree-v2 摘要".to_string(),
        ]));
    }
    if let Some(kind) = acceptance_kind_for_report_path(artifact_path) {
        return acceptance_closure_digest(&root, artifact_path, &candidate, kind, None);
    }
    sha256_path(&candidate)
}

/// 实际执行一份人工验收报告的结构与逐项证据检查，成功时返回唯一机器标记。
pub fn manual_acceptance(
    platform: &str,
    checklist: &str,
    report_path: &str,
    repo_root: &Path,
) -> Result<&'static str, EvidenceError> {
    let kind = match platform {
        "macos" => EvidenceKind::AcceptanceMacos,
        "android" => EvidenceKind::AcceptanceAndroid,
        "firefox" => EvidenceKind::AcceptanceFirefox,
        "windows" => EvidenceKind::AcceptanceWindows,
        other => {
            return Err(EvidenceError::new(vec![format!(
                "manual-acceptance 平台 {other:?} 无效；允许 macos/android/firefox/windows"
            )]))
        }
    };
    let Some((_, expected_checklist)) = kind.acceptance_command() else {
        unreachable!("上方只产生验收 kind")
    };
    if checklist != expected_checklist {
        return Err(EvidenceError::new(vec![format!(
            "{platform} 的 checklist 必须精确为 {expected_checklist},实际为 {checklist:?}"
        )]));
    }
    // 固定路径本身也必须对应仓库内真实、非空且无符号链接的普通文件；否则命令虽然
    // 带着 checklist 字样，却没有实际可复核的清单。
    artifact_digest(repo_root, checklist)?;
    if !artifact_shape_matches(kind, report_path) {
        return Err(EvidenceError::new(vec![format!(
            "{platform} 的报告必须位于对应小写 evidence/ 平台目录且为 .md 普通文件"
        )]));
    }
    // `artifact_digest` 对验收报告计算 closure digest；因此这里与最终门禁复用同一套
    // marker、case、唯一引用、路径与文件检查，而不是维护第二份“人工命令”逻辑。
    artifact_digest(repo_root, report_path)?;
    Ok(kind
        .acceptance_marker()
        .expect("上方只产生带 marker 的验收 kind"))
}

/// 校验不依赖文件系统的字段。调用方显式给出“当前时间”，时间边界也能精确测试。
pub fn validate_fields_at(
    evidence: &ReleaseEvidence,
    expected_kind: EvidenceKind,
    expected_commit: &str,
    expected_commit_time: i64,
    expected_signer: Option<&str>,
    now_unix: i64,
) -> Result<(), EvidenceError> {
    let mut errors = Vec::new();

    if evidence.schema != EVIDENCE_SCHEMA {
        errors.push(format!(
            "schema 必须是 {EVIDENCE_SCHEMA},实际为 {:?}",
            evidence.schema
        ));
    }
    if evidence.kind != expected_kind {
        errors.push(format!(
            "kind 不匹配:期望 {expected_kind},实际 {}",
            evidence.kind
        ));
    }
    if !valid_full_commit(expected_commit) {
        errors.push("门禁传入的 commit 不是完整 40 位 Git SHA-1".to_string());
    }
    if !valid_full_commit(&evidence.commit) || evidence.commit != expected_commit {
        errors.push(format!(
            "commit 必须精确绑定当前完整 HEAD {expected_commit},实际为 {:?}",
            evidence.commit
        ));
    }
    if expected_commit_time <= 0
        || expected_commit_time > now_unix.saturating_add(MAX_EVIDENCE_FUTURE_SECONDS)
    {
        errors.push("门禁传入的 HEAD commit time 无效或明显在未来".to_string());
    }
    validate_command(
        evidence.kind,
        &evidence.command,
        &evidence.artifact.path,
        &mut errors,
    );
    if evidence.exit_code != 0 {
        errors.push(format!("exit_code 必须为 0,实际为 {}", evidence.exit_code));
    }
    match parse_rfc3339(&evidence.timestamp) {
        None => errors.push(format!(
            "timestamp 不是有效 RFC3339 时间:{:?}",
            evidence.timestamp
        )),
        Some(timestamp) if timestamp < now_unix.saturating_sub(MAX_EVIDENCE_AGE_SECONDS) => {
            errors.push("timestamp 已超过 30 天有效窗口;旧报告不能作为本次发布证据".to_string())
        }
        Some(timestamp) if timestamp > now_unix.saturating_add(MAX_EVIDENCE_FUTURE_SECONDS) => {
            errors.push("timestamp 比当前系统时间早报超过 10 分钟;请先校准时钟".to_string())
        }
        Some(timestamp)
            if timestamp < expected_commit_time.saturating_sub(MAX_EVIDENCE_FUTURE_SECONDS) =>
        {
            errors.push(
                "timestamp 早于当前 HEAD 的提交时间;旧证据不能改 commit 字段后复用".to_string(),
            )
        }
        Some(_) => {}
    }
    validate_output(evidence.kind, &evidence.output, &mut errors);
    validate_signer(
        evidence.kind,
        evidence.signer.as_deref(),
        expected_signer,
        &evidence.command,
        &evidence.output,
        &mut errors,
    );
    if has_placeholder(&evidence.artifact.path) {
        errors.push("artifact.path 仍是空值或占位值".to_string());
    } else if !valid_portable_repo_relative_path(&evidence.artifact.path) {
        errors.push(
            "artifact.path 每个路径组件只能包含 ASCII 字母数字、.、_ 或 -；不允许空白、glob、变量展开或其他 shell 元字符"
                .to_string(),
        );
    }
    if !valid_sha256(&evidence.artifact.sha256) {
        errors.push("artifact.sha256 必须是 64 位小写十六进制 SHA-256".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(EvidenceError::new(errors))
    }
}

pub fn verify_evidence(
    evidence: &ReleaseEvidence,
    expected_kind: EvidenceKind,
    expected_commit: &str,
    expected_commit_time: i64,
    expected_signer: Option<&str>,
    repo_root: &Path,
    evidence_source: &Path,
) -> Result<PathBuf, EvidenceError> {
    verify_evidence_at(
        evidence,
        expected_kind,
        expected_commit,
        expected_commit_time,
        expected_signer,
        repo_root,
        Some(evidence_source),
        current_unix_time(),
    )
}

// `now_unix` 与可选 source 只由测试注入；保留与公开入口一一对应的参数，避免测试
// 另走一套验证路径。
#[allow(clippy::too_many_arguments)]
fn verify_evidence_at(
    evidence: &ReleaseEvidence,
    expected_kind: EvidenceKind,
    expected_commit: &str,
    expected_commit_time: i64,
    expected_signer: Option<&str>,
    repo_root: &Path,
    evidence_source: Option<&Path>,
    now_unix: i64,
) -> Result<PathBuf, EvidenceError> {
    validate_fields_at(
        evidence,
        expected_kind,
        expected_commit,
        expected_commit_time,
        expected_signer,
        now_unix,
    )?;
    verify_artifact(
        &evidence.artifact,
        expected_kind,
        repo_root,
        evidence_source,
    )
}

fn verify_artifact(
    artifact: &ArtifactEvidence,
    kind: EvidenceKind,
    repo_root: &Path,
    evidence_source: Option<&Path>,
) -> Result<PathBuf, EvidenceError> {
    let relative = Path::new(&artifact.path);
    if !valid_portable_repo_relative_path(&artifact.path) || relative.is_absolute() {
        return Err(EvidenceError::new(vec![
            "artifact.path 必须是只用 / 分隔、每组件仅含 ASCII 字母数字、.、_ 或 - 的仓库相对路径；不允许空白或 shell 元字符"
                .to_string(),
        ]));
    }
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => Some(part.to_owned()),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Option<Vec<_>>>();
    let Some(parts) = parts else {
        return Err(EvidenceError::new(vec![
            "artifact.path 不允许 .、..、根路径或盘符".to_string(),
        ]));
    };
    if parts.is_empty() {
        return Err(EvidenceError::new(vec![
            "artifact.path 不能为空".to_string()
        ]));
    }
    if !artifact_shape_matches(kind, &artifact.path) {
        return Err(EvidenceError::new(vec![format!(
            "artifact {:?} 不是 {kind} 可接受的产品或报告文件类型",
            artifact.path
        )]));
    }

    let root = std::fs::canonicalize(repo_root).map_err(|error| {
        EvidenceError::new(vec![format!("repo-root {repo_root:?} 无法解析:{error}")])
    })?;
    if !root.is_dir() {
        return Err(EvidenceError::new(vec!["repo-root 必须是目录".to_string()]));
    }
    let evidence_source = evidence_source
        .map(|path| {
            std::fs::canonicalize(path).map_err(|error| {
                EvidenceError::new(vec![format!(
                    "证据 JSON 源文件 {path:?} 无法解析真实路径:{error}"
                )])
            })
        })
        .transpose()?;

    let mut candidate = root.clone();
    for part in parts {
        candidate.push(part);
        let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
            EvidenceError::new(vec![format!(
                "artifact {:?} 不存在或无法读取:{error}",
                artifact.path
            )])
        })?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::new(vec![format!(
                "artifact {:?} 的路径包含符号链接",
                artifact.path
            )]));
        }
    }

    let metadata = std::fs::metadata(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!(
            "artifact {:?} 无法读取:{error}",
            artifact.path
        )])
    })?;
    let app_bundle = matches!(
        kind,
        EvidenceKind::MacosCodesign | EvidenceKind::MacosNotarize
    ) && artifact.path.ends_with(".app");
    if !metadata.is_file() && !(app_bundle && metadata.is_dir()) {
        return Err(EvidenceError::new(vec![format!(
            "artifact {:?} 必须是普通文件；只有 macOS .app 可使用目录",
            artifact.path
        )]));
    }
    if metadata.is_file() && metadata.len() == 0 {
        return Err(EvidenceError::new(vec![format!(
            "artifact {:?} 不能为空文件",
            artifact.path
        )]));
    }
    // Windows junction / reparse point 不一定表现成 Rust 的 symlink。最终再 canonicalize
    // 一次并核对 containment，避免它把看似仓库内的路径导向仓库外。
    let candidate = std::fs::canonicalize(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!(
            "artifact {:?} 无法解析真实路径:{error}",
            artifact.path
        )])
    })?;
    if !candidate.starts_with(&root) {
        return Err(EvidenceError::new(vec![format!(
            "artifact {:?} 的真实路径越出 repo-root",
            artifact.path
        )]));
    }
    if evidence_source.as_ref() == Some(&candidate) {
        return Err(EvidenceError::new(vec![format!(
            "artifact {:?} 不能引用证据 JSON 源文件自身",
            artifact.path
        )]));
    }
    if kind.acceptance_marker().is_some() && metadata.len() > 16 * 1024 * 1024 {
        return Err(EvidenceError::new(vec![format!(
            "验收报告 {:?} 超过 16 MiB 上限",
            artifact.path
        )]));
    }

    let actual = if kind.acceptance_marker().is_some() {
        acceptance_closure_digest(
            &root,
            &artifact.path,
            &candidate,
            kind,
            evidence_source.as_deref(),
        )?
    } else {
        sha256_path(&candidate)?
    };
    if actual != artifact.sha256 {
        return Err(EvidenceError::new(vec![format!(
            "artifact SHA-256 不匹配:声明 {},现场 {}",
            artifact.sha256, actual
        )]));
    }
    Ok(candidate)
}

fn acceptance_kind_for_report_path(path: &str) -> Option<EvidenceKind> {
    [
        EvidenceKind::AcceptanceMacos,
        EvidenceKind::AcceptanceAndroid,
        EvidenceKind::AcceptanceFirefox,
        EvidenceKind::AcceptanceWindows,
    ]
    .into_iter()
    .find(|kind| artifact_shape_matches(*kind, path))
}

fn acceptance_closure_digest(
    repo_root: &Path,
    report_path: &str,
    report_file: &Path,
    kind: EvidenceKind,
    evidence_source: Option<&Path>,
) -> Result<String, EvidenceError> {
    let report_bytes = std::fs::read(report_file).map_err(|error| {
        EvidenceError::new(vec![format!("验收报告 {report_path:?} 无法读取:{error}")])
    })?;
    if report_bytes.len() > 16 * 1024 * 1024 {
        return Err(EvidenceError::new(vec![format!(
            "验收报告 {report_path:?} 超过 16 MiB 上限"
        )]));
    }
    let report = std::str::from_utf8(&report_bytes).map_err(|error| {
        EvidenceError::new(vec![format!(
            "验收报告 {report_path:?} 不是可读 UTF-8:{error}"
        )])
    })?;
    let marker = kind.acceptance_marker().ok_or_else(|| {
        EvidenceError::new(vec!["内部错误：签名 kind 进入验收闭包摘要".to_string()])
    })?;
    if !has_marker_line(report, marker) {
        return Err(EvidenceError::new(vec![format!(
            "验收报告 {report_path:?} 缺少固定成功标记 {marker}"
        )]));
    }

    let mut references = Vec::new();
    for reference in parse_acceptance_report(kind, report)? {
        let canonical =
            verify_acceptance_reference(repo_root, report_path, &reference, evidence_source)?;
        let length = std::fs::metadata(&canonical)
            .map_err(|error| {
                EvidenceError::new(vec![format!("验收逐项证据 {reference:?} 无法读取:{error}")])
            })?
            .len();
        if length == 0 {
            return Err(EvidenceError::new(vec![format!(
                "验收逐项证据 {reference:?} 不能为空文件"
            )]));
        }
        references.push((reference, canonical, length));
    }
    references.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_DIGEST_DOMAIN);
    hasher.update((report_bytes.len() as u64).to_be_bytes());
    hasher.update(&report_bytes);
    for (relative, canonical, length) in references {
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(length.to_be_bytes());
        sha256_file_into(&canonical, &mut hasher)?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn artifact_shape_matches(kind: EvidenceKind, path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let release_location = lower.starts_with("evidence/")
        || lower.starts_with("dist/")
        || lower.starts_with("target/release/")
        || (lower.starts_with("apps/")
            && (lower.contains("/dist/")
                || lower.contains("/target/release/")
                || lower.contains("/build/outputs/")));
    match kind {
        EvidenceKind::MacosCodesign => {
            release_location && (lower.ends_with(".dmg") || path.ends_with(".app"))
        }
        EvidenceKind::MacosNotarize => {
            release_location
                && (lower.ends_with(".dmg") || lower.ends_with(".pkg") || path.ends_with(".app"))
        }
        EvidenceKind::WindowsSign => {
            release_location
                && (lower.ends_with(".exe") || lower.ends_with(".msi") || lower.ends_with(".msix"))
        }
        EvidenceKind::AndroidSign => release_location && lower.ends_with(".apk"),
        EvidenceKind::AcceptanceMacos => acceptance_report_shape(path, "evidence/macos/"),
        EvidenceKind::AcceptanceAndroid => acceptance_report_shape(path, "evidence/android/"),
        EvidenceKind::AcceptanceFirefox => acceptance_report_shape(path, "evidence/firefox/"),
        EvidenceKind::AcceptanceWindows => acceptance_report_shape(path, "evidence/windows/"),
    }
}

fn acceptance_report_shape(path: &str, prefix: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.starts_with(prefix) && lower.ends_with(".md")
}

fn parse_acceptance_report(kind: EvidenceKind, report: &str) -> Result<Vec<String>, EvidenceError> {
    let (required, evidence_prefix): (&[&str], &str) = match kind {
        EvidenceKind::AcceptanceMacos => (
            &[
                "1", "2", "3", "4", "5", "5b", "5c", "6", "7", "8", "9", "10", "11", "12", "13",
                "14",
            ],
            "evidence/macos/",
        ),
        EvidenceKind::AcceptanceAndroid => (&["A1", "A2", "A3", "A4"], "evidence/android/"),
        EvidenceKind::AcceptanceFirefox => (
            &["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"],
            "evidence/firefox/",
        ),
        EvidenceKind::AcceptanceWindows => (
            &["W1", "W2", "W3", "W4", "W5", "W6", "W7"],
            "evidence/windows/",
        ),
        EvidenceKind::MacosCodesign
        | EvidenceKind::MacosNotarize
        | EvidenceKind::WindowsSign
        | EvidenceKind::AndroidSign => return Ok(Vec::new()),
    };

    let mut seen = Vec::new();
    let mut references = Vec::new();
    let mut errors = Vec::new();
    for line in report.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
            continue;
        }
        let cells: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() < 3 {
            continue;
        }
        let case_id = cells[0].split_whitespace().next().unwrap_or_default();
        if !required.contains(&case_id) {
            continue;
        }
        if seen.contains(&case_id) {
            errors.push(format!("验收用例 {case_id} 重复"));
            continue;
        }
        seen.push(case_id);
        if cells[1] != "PASS (native)" {
            errors.push(format!(
                "验收用例 {case_id} 的结果必须精确为 PASS (native),实际为 {:?}",
                cells[1]
            ));
        }
        if !valid_acceptance_evidence_reference(cells[2], evidence_prefix) {
            errors.push(format!(
                "验收用例 {case_id} 的证据列必须填写对应平台的仓库相对 evidence/ 路径"
            ));
        } else if references.iter().any(|reference| reference == cells[2]) {
            errors.push(format!(
                "验收用例 {case_id} 复用了其他用例的证据路径 {:?};逐项证据路径必须唯一",
                cells[2]
            ));
        } else {
            references.push(cells[2].to_string());
        }
    }
    for case_id in required {
        if !seen.contains(case_id) {
            errors.push(format!("验收报告缺少必需用例 {case_id}"));
        }
    }

    if errors.is_empty() {
        Ok(references)
    } else {
        Err(EvidenceError::new(errors))
    }
}

fn valid_acceptance_evidence_reference(value: &str, platform_prefix: &str) -> bool {
    let trimmed = value.trim();
    !has_placeholder(trimmed)
        && !trimmed.eq_ignore_ascii_case("n/a")
        && trimmed.starts_with(platform_prefix)
        && valid_portable_repo_relative_path(trimmed)
}

fn verify_acceptance_reference(
    repo_root: &Path,
    report_path: &str,
    reference: &str,
    evidence_source: Option<&Path>,
) -> Result<PathBuf, EvidenceError> {
    if reference == report_path {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 不能引用报告自身"
        )]));
    }
    let mut candidate = repo_root.to_path_buf();
    for part in reference.split('/') {
        candidate.push(part);
        let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
            EvidenceError::new(vec![format!(
                "验收逐项证据 {reference:?} 不存在或无法读取:{error}"
            )])
        })?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::new(vec![format!(
                "验收逐项证据 {reference:?} 的路径包含符号链接"
            )]));
        }
    }
    let metadata = std::fs::metadata(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!("验收逐项证据 {reference:?} 无法读取:{error}")])
    })?;
    if !metadata.is_file() {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 必须是普通文件"
        )]));
    }
    if metadata.len() == 0 {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 不能为空文件"
        )]));
    }
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
        EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 无法解析真实路径:{error}"
        )])
    })?;
    if !canonical.starts_with(repo_root) {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 的真实路径越出 repo-root"
        )]));
    }
    let report = std::fs::canonicalize(repo_root.join(report_path)).map_err(|error| {
        EvidenceError::new(vec![format!(
            "验收报告 {report_path:?} 无法解析真实路径:{error}"
        )])
    })?;
    if canonical == report {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 不能引用报告自身"
        )]));
    }
    if evidence_source == Some(canonical.as_path()) {
        return Err(EvidenceError::new(vec![format!(
            "验收逐项证据 {reference:?} 不能引用证据 JSON 源文件自身"
        )]));
    }
    Ok(canonical)
}

fn sha256_file_into(path: &Path, hasher: &mut Sha256) -> Result<(), EvidenceError> {
    let mut file = File::open(path)
        .map_err(|error| EvidenceError::new(vec![format!("artifact {path:?} 无法打开:{error}")]))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            EvidenceError::new(vec![format!("artifact {path:?} 读取失败:{error}")])
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, EvidenceError> {
    let mut hasher = Sha256::new();
    sha256_file_into(path, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_path(path: &Path) -> Result<String, EvidenceError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| EvidenceError::new(vec![format!("artifact {path:?} 无法读取:{error}")]))?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::new(vec![format!(
            "artifact {path:?} 不能是符号链接"
        )]));
    }
    if metadata.is_file() {
        return sha256_file(path);
    }
    if !metadata.is_dir() {
        return Err(EvidenceError::new(vec![format!(
            "artifact {path:?} 不是普通文件或目录"
        )]));
    }

    let mut entries = Vec::new();
    collect_tree_entries(path, path, &mut entries)?;
    if !entries
        .iter()
        .any(|entry| entry.kind == b'F' && entry.length > 0)
    {
        return Err(EvidenceError::new(vec![format!(
            "macOS .app bundle {path:?} 必须至少包含一个非空普通文件"
        )]));
    }
    entries.sort_by(|left, right| left.relative.as_bytes().cmp(right.relative.as_bytes()));

    let mut hasher = Sha256::new();
    hasher.update(TREE_DIGEST_DOMAIN);
    // 根目录名不属于 bundle 内部身份，但根目录的可遍历性属于。v2 绑定 root 与
    // 每个条目的 Unix executable bits；xattrs 仍刻意不进入可移植摘要。
    hasher.update(unix_executable_mask(&metadata).to_be_bytes());
    for entry in entries {
        hasher.update([entry.kind]);
        hasher.update((entry.relative.len() as u64).to_be_bytes());
        hasher.update(entry.relative.as_bytes());
        hasher.update(entry.length.to_be_bytes());
        hasher.update(entry.executable_mask.to_be_bytes());
        if entry.kind == b'F' {
            sha256_file_into(&entry.absolute, &mut hasher)?;
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct TreeEntry {
    relative: String,
    absolute: PathBuf,
    kind: u8,
    length: u64,
    executable_mask: u32,
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<TreeEntry>,
) -> Result<(), EvidenceError> {
    let children = std::fs::read_dir(directory).map_err(|error| {
        EvidenceError::new(vec![format!(
            "macOS .app bundle 目录 {directory:?} 无法读取:{error}"
        )])
    })?;
    for child in children {
        let child = child.map_err(|error| {
            EvidenceError::new(vec![format!("macOS .app bundle 目录项无法读取:{error}")])
        })?;
        let absolute = child.path();
        let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| {
            EvidenceError::new(vec![format!(
                "macOS .app bundle 项 {absolute:?} 无法读取:{error}"
            )])
        })?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::new(vec![format!(
                "macOS .app bundle 项 {absolute:?} 不能是符号链接"
            )]));
        }
        let relative = absolute.strip_prefix(root).map_err(|_| {
            EvidenceError::new(vec!["macOS .app bundle 遍历越出根目录".to_string()])
        })?;
        let relative = relative
            .to_str()
            .ok_or_else(|| {
                EvidenceError::new(vec![
                    "macOS .app bundle 路径必须是有效 UTF-8,才能稳定计算 tree hash".to_string(),
                ])
            })?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if metadata.is_dir() {
            entries.push(TreeEntry {
                relative,
                absolute: absolute.clone(),
                kind: b'D',
                length: 0,
                executable_mask: unix_executable_mask(&metadata),
            });
            collect_tree_entries(root, &absolute, entries)?;
        } else if metadata.is_file() {
            entries.push(TreeEntry {
                relative,
                absolute,
                kind: b'F',
                length: metadata.len(),
                executable_mask: unix_executable_mask(&metadata),
            });
        } else {
            return Err(EvidenceError::new(vec![format!(
                "macOS .app bundle 项 {absolute:?} 必须是普通文件或目录"
            )]));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_executable_mask(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;

    metadata.mode() & 0o111
}

#[cfg(not(unix))]
fn unix_executable_mask(_metadata: &std::fs::Metadata) -> u32 {
    // `.app` 发布证据应在 macOS/Unix 上生成和复核。保留该分支只为让 CLI 在
    // Windows 编译；没有 POSIX mode 的文件系统不能声称观测到了可执行位。
    0
}

fn validate_command(
    kind: EvidenceKind,
    command: &str,
    artifact_path: &str,
    errors: &mut Vec<String>,
) {
    if has_placeholder(command) || command.len() < 8 || command.chars().any(char::is_control) {
        errors.push("command 必须是已实际执行的单行非占位命令".to_string());
        return;
    }
    if has_command_comment_syntax(command) {
        errors.push("command 不允许 shell、PowerShell 或 batch 注释".to_string());
        return;
    }
    if let Err(error) = validate_command_flow(kind, command, artifact_path) {
        errors.push(error);
        return;
    }

    let executable = command
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(['\'', '"'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        executable.as_str(),
        "echo" | "printf" | "true" | "false" | ":"
    ) {
        errors.push(format!("command 不能用 {executable:?} 代替真实检查命令"));
    }

    if !has_placeholder(artifact_path) && !command.contains(artifact_path) {
        errors.push("command 必须包含同一个 artifact.path,证明检查针对的就是该产物".to_string());
    }

    if let Some(tool) = kind.required_tool() {
        if !has_command_tool(command, tool) {
            errors.push(format!("{kind} 的 command 必须实际调用 {tool}"));
        }
    }
    match kind {
        EvidenceKind::MacosCodesign => {
            let segments = direct_tool_segments(command, "codesign");
            let verify = segments.iter().position(|segment| {
                segment_has_shape(
                    segment,
                    &["--verify", "--deep", "--strict", "--verbose=4"],
                    artifact_path,
                )
            });
            let identity = segments.iter().position(|segment| {
                segment_has_shape(segment, &["-dv", "--verbose=4"], artifact_path)
            });
            if segments.len() < 2 || verify.is_none() || identity.is_none() || verify == identity {
                errors.push(
                    "macos_codesign 必须在两个独立命令段分别执行 codesign --verify --deep --strict --verbose=4 和 codesign -dv --verbose=4,且都绑定 artifact.path"
                        .to_string(),
                );
            }
        }
        EvidenceKind::MacosNotarize => {
            validate_notary_command(command, artifact_path, errors);
        }
        EvidenceKind::WindowsSign => {
            if !direct_tool_segments(command, "signtool")
                .iter()
                .any(|segment| segment_has_shape(segment, &["verify", "/pa", "/v"], artifact_path))
            {
                errors.push(
                    "windows_sign 必须在 signtool 命令段执行 verify /pa /v 并绑定 artifact.path"
                        .to_string(),
                );
            }
            let signature = command_segments(command).iter().any(|segment| {
                invokes_or_assigns_tool(segment, "Get-AuthenticodeSignature")
                    && segment_has_exact_token(segment, artifact_path)
            });
            let command_lower = command.to_ascii_lowercase();
            let fingerprint = direct_tool_segments(command, "Write-Output")
                .iter()
                .any(|segment| {
                    let lower = segment.to_ascii_lowercase();
                    lower.contains("certificatesha256=")
                })
                && command_lower.contains("getcerthashstring(");
            if !signature || !fingerprint {
                errors.push(
                    "windows_sign 必须用 Get-AuthenticodeSignature 绑定 artifact.path，并由 Write-Output 在同一实际流程中调用 GetCertHashString('SHA256') 输出 CertificateSHA256="
                        .to_string(),
                );
            }
        }
        EvidenceKind::AndroidSign => {
            if !direct_tool_segments(command, "apksigner")
                .iter()
                .any(|segment| {
                    segment_has_shape(segment, &["verify", "--print-certs"], artifact_path)
                })
            {
                errors.push(
                    "android_sign 必须在 apksigner 命令段执行 verify --print-certs 并绑定 artifact.path"
                        .to_string(),
                );
            }
        }
        EvidenceKind::AcceptanceMacos
        | EvidenceKind::AcceptanceAndroid
        | EvidenceKind::AcceptanceFirefox
        | EvidenceKind::AcceptanceWindows => {
            if let Some((platform, checklist)) = kind.acceptance_command() {
                if !direct_tool_segments(command, "guard-cli")
                    .iter()
                    .any(|segment| {
                        segment_has_shape(
                            segment,
                            &["manual-acceptance", platform, checklist, "--repo-root", "."],
                            artifact_path,
                        )
                    })
                {
                    errors.push(format!(
                        "{kind} 必须直接调用 guard-cli manual-acceptance {platform} {checklist} artifact.path --repo-root ."
                    ));
                }
            }
        }
    }
}

/// 发布证据只接受少量可明确解释的命令形状。
///
/// 仅仅把命令按 `;` / `&` / `|` 切段还不够：`verify || true; printf PASS`
/// 会让失败的真实检查得到成功退出码和伪造输出。这里先拒绝会改变执行对象或吞掉
/// 失败的 shell 语法，再把每类证据收紧到项目文档给出的成功链。Windows 使用的
/// PowerShell 流程需要分号，但每个可能失败的步骤后面都有固定的显式退出检查。
fn validate_command_flow(
    kind: EvidenceKind,
    command: &str,
    artifact_path: &str,
) -> Result<(), String> {
    if command.contains('|') {
        return Err("command 不允许管道或 ||；检查失败不能被后续命令吞掉".to_string());
    }
    if command.contains("$(") || command.contains('`') {
        return Err("command 不允许命令替换 `$(` 或反引号".to_string());
    }
    if command.contains(['<', '>']) {
        return Err("command 不允许输入输出重定向或进程替换".to_string());
    }
    if !ampersands_are_success_connectors(command) {
        return Err("command 只允许成对的 && 成功连接，不允许单个 & 或畸形连接符".to_string());
    }

    match kind {
        EvidenceKind::MacosCodesign => validate_codesign_flow(command, artifact_path),
        EvidenceKind::MacosNotarize => validate_notary_flow(command, artifact_path),
        EvidenceKind::WindowsSign => validate_windows_sign_flow(command, artifact_path),
        EvidenceKind::AndroidSign => validate_android_sign_flow(command, artifact_path),
        EvidenceKind::AcceptanceMacos
        | EvidenceKind::AcceptanceAndroid
        | EvidenceKind::AcceptanceFirefox
        | EvidenceKind::AcceptanceWindows => validate_acceptance_flow(kind, command, artifact_path),
    }
}

fn ampersands_are_success_connectors(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'&' {
            cursor += 1;
            continue;
        }
        if bytes.get(cursor + 1) != Some(&b'&') || bytes.get(cursor + 2) == Some(&b'&') {
            return false;
        }
        cursor += 2;
    }
    true
}

fn success_chain(command: &str) -> Result<Vec<&str>, String> {
    if command.contains(';') {
        return Err("非 PowerShell 发布检查只允许用 && 连接，不能使用分号".to_string());
    }
    let segments: Vec<&str> = command.split("&&").map(str::trim).collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err("command 含空命令段或畸形 && 连接".to_string());
    }
    Ok(segments)
}

fn direct_tool_args<'a>(segment: &'a str, tool: &str) -> Option<Vec<&'a str>> {
    let tokens: Vec<&str> = segment
        .split_whitespace()
        .map(cleaned_command_token)
        .filter(|token| !token.is_empty())
        .collect();
    let start = if tokens
        .first()
        .is_some_and(|token| command_token_is_tool(token, tool))
    {
        1
    } else if tokens.first().is_some_and(|token| {
        token
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("xcrun"))
    }) && tokens
        .get(1)
        .is_some_and(|token| command_token_is_tool(token, tool))
    {
        2
    } else {
        return None;
    };
    Some(tokens[start..].to_vec())
}

fn exact_tool_args(segment: &str, tool: &str, expected: &[&str]) -> bool {
    direct_tool_args(segment, tool).is_some_and(|actual| actual == expected)
}

fn validate_codesign_flow(command: &str, artifact_path: &str) -> Result<(), String> {
    let segments = success_chain(command)?;
    if segments.len() != 2
        || !exact_tool_args(
            segments[0],
            "codesign",
            &[
                "--verify",
                "--deep",
                "--strict",
                "--verbose=4",
                artifact_path,
            ],
        )
        || !exact_tool_args(
            segments[1],
            "codesign",
            &["-dv", "--verbose=4", artifact_path],
        )
    {
        return Err(
            "macos_codesign 只接受两段以 && 连接的精确检查：codesign --verify --deep --strict --verbose=4 ARTIFACT && codesign -dv --verbose=4 ARTIFACT"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_notary_flow(command: &str, artifact_path: &str) -> Result<(), String> {
    let segments = success_chain(command)?;
    let (staple_index, validate_index) = if artifact_path.ends_with(".app") {
        if segments.len() != 4 {
            return Err(
                ".app 公证只接受 ditto→notarytool→stapler staple→stapler validate 四段 && 成功链"
                    .to_string(),
            );
        }
        let Some(ditto_args) = direct_tool_args(segments[0], "ditto") else {
            return Err(
                ".app 公证命令顺序必须是 ditto→notarytool→stapler staple→stapler validate"
                    .to_string(),
            );
        };
        if ditto_args.len() != 5
            || ditto_args[0..3] != ["-c", "-k", "--keepParent"]
            || ditto_args[3] != artifact_path
            || !valid_command_zip_path(ditto_args[4])
        {
            return Err(
                ".app 公证的 ditto 段必须精确为 ditto -c -k --keepParent APP repo-relative.zip"
                    .to_string(),
            );
        }
        if !exact_notary_submit(segments[1], ditto_args[4]) {
            return Err("notarytool 必须直接 submit ditto 生成的同一 ZIP，并带 --wait、唯一 --team-id VALUE 与非占位 --keychain-profile PROFILE".to_string());
        }
        (2, 3)
    } else {
        if segments.len() != 3 || !exact_notary_submit(segments[0], artifact_path) {
            return Err(
                ".dmg/.pkg 的 notarytool 命令段必须是 submit ARTIFACT --wait --team-id VALUE --keychain-profile PROFILE，并以 && 连接 stapler staple→stapler validate"
                    .to_string(),
            );
        }
        (1, 2)
    };
    if !exact_tool_args(
        segments[staple_index],
        "stapler",
        &["staple", artifact_path],
    ) || !exact_tool_args(
        segments[validate_index],
        "stapler",
        &["validate", artifact_path],
    ) {
        return Err("stapler 必须依次精确执行 staple ARTIFACT 与 validate ARTIFACT".to_string());
    }
    Ok(())
}

fn exact_notary_submit(segment: &str, submitted_path: &str) -> bool {
    let Some(args) = direct_tool_args(segment, "notarytool") else {
        return false;
    };
    args.len() == 7
        && args[0] == "submit"
        && args[1] == submitted_path
        && args[2] == "--wait"
        && args[3] == "--team-id"
        && normalize_team_id(args[4]).is_some()
        && args[5] == "--keychain-profile"
        && valid_keychain_profile(args[6])
}

fn valid_keychain_profile(value: &str) -> bool {
    !has_placeholder(value)
        && !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_android_sign_flow(command: &str, artifact_path: &str) -> Result<(), String> {
    let segments = success_chain(command)?;
    if segments.len() != 1
        || !exact_tool_args(
            segments[0],
            "apksigner",
            &["verify", "--print-certs", artifact_path],
        )
    {
        return Err("android_sign 只接受单段 apksigner verify --print-certs ARTIFACT".to_string());
    }
    Ok(())
}

fn validate_acceptance_flow(
    kind: EvidenceKind,
    command: &str,
    artifact_path: &str,
) -> Result<(), String> {
    let segments = success_chain(command)?;
    let Some((platform, checklist)) = kind.acceptance_command() else {
        return Err("内部错误：签名 kind 进入验收命令校验".to_string());
    };
    if segments.len() != 1
        || !exact_tool_args(
            segments[0],
            "guard-cli",
            &[
                "manual-acceptance",
                platform,
                checklist,
                artifact_path,
                "--repo-root",
                ".",
            ],
        )
    {
        return Err(format!(
            "{kind} 只接受单段 guard-cli manual-acceptance {platform} {checklist} ARTIFACT --repo-root ."
        ));
    }
    Ok(())
}

fn validate_windows_sign_flow(command: &str, artifact_path: &str) -> Result<(), String> {
    if command.contains("&&") {
        return Err(
            "windows_sign 只接受带显式退出检查和 GetCertHashString 的固定 PowerShell 分号流程"
                .to_string(),
        );
    }
    let segments: Vec<&str> = command.split(';').map(str::trim).collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err("windows_sign 含空 PowerShell 命令段".to_string());
    }

    let bare = segments.len() == 5
        && exact_signtool_verify(segments[0], artifact_path)
        && exact_last_exit_guard(segments[1])
        && exact_authenticode_assignment(segments[2], artifact_path)
        && exact_authenticode_status_guard(segments[3])
        && compact_ascii_lower(segments[4])
            == "write-output('certificatesha256='+$signature.signercertificate.getcerthashstring('sha256'))";
    if bare {
        return Ok(());
    }

    let wrapped = segments.len() == 7
        && exact_powershell_sha256_prefix(segments[0])
        && exact_signtool_verify(segments[1], artifact_path)
        && exact_last_exit_guard(segments[2])
        && exact_authenticode_assignment(segments[3], artifact_path)
        && exact_authenticode_status_guard(segments[4])
        && compact_ascii_lower(segments[5])
            == "$fingerprint=$signature.signercertificate.getcerthashstring($algorithm)"
        && compact_ascii_lower(segments[6]) == "write-output('certificatesha256='+$fingerprint)\"";
    if wrapped {
        return Ok(());
    }

    Err(
        "windows_sign 必须是固定 PowerShell 流程：signtool verify 后检查 LASTEXITCODE，Get-AuthenticodeSignature 后检查 Valid/证书，再从该证书调用 GetCertHashString 计算并输出 SHA-256；不允许额外命令"
            .to_string(),
    )
}

fn exact_signtool_verify(segment: &str, artifact_path: &str) -> bool {
    exact_tool_args(segment, "signtool", &["verify", "/pa", "/v", artifact_path])
}

fn exact_last_exit_guard(segment: &str) -> bool {
    compact_ascii_lower(segment) == "if(-not$?-or$lastexitcode-ne0){exit1}"
}

fn exact_authenticode_assignment(segment: &str, artifact_path: &str) -> bool {
    let expected =
        format!("$signature=get-authenticodesignature{artifact_path}").to_ascii_lowercase();
    compact_ascii_lower(segment) == expected
}

fn exact_authenticode_status_guard(segment: &str) -> bool {
    compact_ascii_lower(segment)
        == "if($signature.status-ne'valid'-or-not$signature.signercertificate){exit1}"
}

fn exact_powershell_sha256_prefix(segment: &str) -> bool {
    compact_ascii_lower(segment) == "powershell-noprofile-command\"$algorithm='sha256'"
}

fn compact_ascii_lower(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn has_command_comment_syntax(command: &str) -> bool {
    command.contains('#')
        || command.split_whitespace().any(|token| {
            let token = cleaned_command_token(token);
            token.eq_ignore_ascii_case("rem") || token.starts_with("::")
        })
}

fn command_segments(command: &str) -> Vec<&str> {
    command
        // 这里故意 fail-closed，不尝试实现完整 shell 引号语法。单/双 `&`、
        // 单/双 `|` 与 `;` 都是命令边界，以免后一段的词元冒充前一段的参数。
        .split([';', '&', '|'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn direct_tool_segments<'a>(command: &'a str, tool: &str) -> Vec<&'a str> {
    command_segments(command)
        .into_iter()
        .filter(|segment| directly_invokes_tool(segment, tool))
        .collect()
}

fn directly_invokes_tool(segment: &str, tool: &str) -> bool {
    let tokens: Vec<&str> = segment
        .split_whitespace()
        .map(cleaned_command_token)
        .filter(|token| !token.is_empty())
        .collect();
    tokens
        .first()
        .is_some_and(|token| command_token_is_tool(token, tool))
        || (tokens.first().is_some_and(|token| {
            token
                .rsplit(['/', '\\'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("xcrun"))
        }) && tokens
            .get(1)
            .is_some_and(|token| command_token_is_tool(token, tool)))
}

fn invokes_or_assigns_tool(segment: &str, tool: &str) -> bool {
    if directly_invokes_tool(segment, tool) {
        return true;
    }
    let tokens: Vec<&str> = segment
        .split_whitespace()
        .map(cleaned_command_token)
        .filter(|token| !token.is_empty())
        .collect();
    tokens.first().is_some_and(|token| token.starts_with('$'))
        && tokens.get(1) == Some(&"=")
        && tokens
            .get(2)
            .is_some_and(|token| command_token_is_tool(token, tool))
}

fn command_token_is_tool(token: &str, tool: &str) -> bool {
    let candidate = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    candidate
        .strip_suffix(".exe")
        .unwrap_or(&candidate)
        .eq_ignore_ascii_case(tool)
}

fn validate_notary_command(command: &str, artifact_path: &str, errors: &mut Vec<String>) {
    let segments = command_segments(command);
    let indexed = |tool: &str| {
        segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| directly_invokes_tool(segment, tool))
            .collect::<Vec<_>>()
    };
    let notary = indexed("notarytool");
    let stapler = indexed("stapler");
    let staple = stapler
        .iter()
        .copied()
        .filter(|(_, segment)| segment_has_shape(segment, &["staple"], artifact_path))
        .collect::<Vec<_>>();
    let validate = stapler
        .iter()
        .copied()
        .filter(|(_, segment)| segment_has_shape(segment, &["validate"], artifact_path))
        .collect::<Vec<_>>();
    if notary.len() != 1 {
        errors.push("macos_notarize 必须恰好执行一次 notarytool".to_string());
    }
    if stapler.len() != 2 || staple.len() != 1 || validate.len() != 1 {
        errors.push(
            "macos_notarize 必须分别且各恰好执行一次 stapler staple 与 stapler validate，并绑定 artifact.path"
                .to_string(),
        );
    }

    if artifact_path.ends_with(".app") {
        let ditto = indexed("ditto");
        if ditto.len() != 1 {
            errors.push(".app 公证必须恰好执行一次 ditto 生成 ZIP".to_string());
            return;
        }
        let Some(zip) = extract_ditto_zip(ditto[0].1, artifact_path) else {
            errors.push(
                ".app 公证的 ditto 命令必须执行 -c -k --keepParent APP repo-relative.zip"
                    .to_string(),
            );
            return;
        };
        if notary.first().is_none_or(|(_, segment)| {
            !segment_has_shape(segment, &["submit", "--wait", "--team-id"], &zip)
        }) {
            errors.push(".app 公证的 notarytool submit 必须使用 ditto 生成的同一 ZIP".to_string());
        }
        if notary.len() == 1
            && staple.len() == 1
            && validate.len() == 1
            && !(ditto[0].0 < notary[0].0
                && notary[0].0 < staple[0].0
                && staple[0].0 < validate[0].0)
        {
            errors.push(
                ".app 公证命令顺序必须是 ditto→notarytool→stapler staple→stapler validate"
                    .to_string(),
            );
        }
    } else {
        if notary.first().is_none_or(|(_, segment)| {
            !segment_has_shape(segment, &["submit", "--wait", "--team-id"], artifact_path)
        }) {
            errors.push(
                "macos_notarize 必须在 notarytool 命令段执行 submit --wait --team-id 并绑定 artifact.path"
                    .to_string(),
            );
        }
        if notary.len() == 1
            && staple.len() == 1
            && validate.len() == 1
            && !(notary[0].0 < staple[0].0 && staple[0].0 < validate[0].0)
        {
            errors.push(
                "公证命令顺序必须是 notarytool submit→stapler staple→stapler validate".to_string(),
            );
        }
    }
}

fn extract_ditto_zip(segment: &str, artifact_path: &str) -> Option<String> {
    if !directly_invokes_tool(segment, "ditto")
        || !["-c", "-k", "--keepParent"]
            .iter()
            .all(|token| has_command_token(segment, token))
    {
        return None;
    }
    let tokens: Vec<&str> = segment
        .split_whitespace()
        .map(cleaned_command_token)
        .filter(|token| !token.is_empty())
        .collect();
    let artifact_index = tokens.iter().position(|token| *token == artifact_path)?;
    let zip = *tokens.get(artifact_index + 1)?;
    if artifact_index + 2 != tokens.len() || !valid_command_zip_path(zip) {
        return None;
    }
    Some(zip.to_string())
}

fn valid_command_zip_path(path: &str) -> bool {
    path.ends_with(".zip") && valid_portable_repo_relative_path(path)
}

fn segment_has_shape(segment: &str, required: &[&str], artifact_path: &str) -> bool {
    required
        .iter()
        .all(|token| has_command_token(segment, token))
        && segment_has_exact_token(segment, artifact_path)
}

fn segment_has_exact_token(segment: &str, expected: &str) -> bool {
    segment.match_indices(expected).any(|(index, value)| {
        let before = segment[..index].chars().next_back();
        let after = segment[index + value.len()..].chars().next();
        before.is_none_or(is_command_argument_boundary)
            && after.is_none_or(is_command_argument_boundary)
    })
}

fn is_command_argument_boundary(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '\'' | '"' | ';' | '&' | '|' | '(' | ')' | '[' | ']'
        )
}

fn has_command_tool(command: &str, tool: &str) -> bool {
    command_tool_count(command, tool) > 0
}

fn command_tool_count(command: &str, tool: &str) -> usize {
    command
        .split_whitespace()
        .filter(|token| {
            let candidate = cleaned_command_token(token)
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            candidate
                .strip_suffix(".exe")
                .unwrap_or(&candidate)
                .eq_ignore_ascii_case(tool)
        })
        .count()
}

fn has_command_token(command: &str, expected: &str) -> bool {
    command
        .split_whitespace()
        .any(|token| cleaned_command_token(token).eq_ignore_ascii_case(expected))
}

fn cleaned_command_token(token: &str) -> &str {
    token.trim_matches(['\'', '"', ';', '&', '|'])
}

fn command_flag_values<'a>(command: &'a str, flag: &str) -> Vec<&'a str> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| cleaned_command_token(token).eq_ignore_ascii_case(flag))
        .map(|(index, _)| {
            tokens
                .get(index + 1)
                .map(|token| cleaned_command_token(token))
                .unwrap_or_default()
        })
        .collect()
}

fn validate_output(kind: EvidenceKind, output: &str, errors: &mut Vec<String>) {
    if has_placeholder(output) {
        errors.push("output 必须是实际工具输出,不能是空值或占位值".to_string());
        return;
    }
    let lower = output.to_ascii_lowercase();
    let missing = match kind {
        EvidenceKind::MacosCodesign => {
            !(lower.contains("valid on disk")
                && lower.contains("satisfies its designated requirement"))
        }
        EvidenceKind::MacosNotarize => {
            let accepted = lower.contains("status: accepted")
                || lower.contains("\"status\": \"accepted\"")
                || lower.contains("\"status\":\"accepted\"");
            !(accepted && lower.contains("validate action worked"))
        }
        EvidenceKind::WindowsSign => !lower.contains("successfully verified"),
        EvidenceKind::AndroidSign => {
            !lower.contains("signer #1 certificate") || lower.contains("android debug")
        }
        EvidenceKind::AcceptanceMacos => {
            !has_marker_line(output, "AGENTGUARD_ACCEPTANCE_MACOS=PASS")
        }
        EvidenceKind::AcceptanceAndroid => {
            !has_marker_line(output, "AGENTGUARD_ACCEPTANCE_ANDROID=PASS")
        }
        EvidenceKind::AcceptanceFirefox => {
            !has_marker_line(output, "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS")
        }
        EvidenceKind::AcceptanceWindows => {
            !has_marker_line(output, "AGENTGUARD_ACCEPTANCE_WINDOWS=PASS")
        }
    };
    if missing {
        errors.push(format!("{kind} 的 output 不满足该类证据的成功判据"));
    }
}

fn validate_signer(
    kind: EvidenceKind,
    signer: Option<&str>,
    expected_signer: Option<&str>,
    command: &str,
    output: &str,
    errors: &mut Vec<String>,
) {
    if kind.required_tool().is_none() {
        if signer.is_some() || expected_signer.is_some() {
            errors.push("验收证据的 signer 必须为 null,也不能传 --expected-signer".to_string());
        }
        return;
    }
    let Some(signer) = signer else {
        errors.push("签名证据必须填写 signer".to_string());
        return;
    };
    let Some(expected) = expected_signer else {
        errors.push("签名证据缺少仓库外受控的 --expected-signer,不能判为已验证".to_string());
        return;
    };

    match kind {
        EvidenceKind::MacosCodesign | EvidenceKind::MacosNotarize => {
            let Some(actual) = normalize_team_id(signer) else {
                errors.push("macOS signer 必须是 10 位 Team ID".to_string());
                return;
            };
            let Some(expected) = normalize_team_id(expected) else {
                errors.push("--expected-signer 不是有效的 10 位 macOS Team ID".to_string());
                return;
            };
            if actual != expected {
                errors.push(format!("macOS signer 不匹配:期望 {expected},实际 {actual}"));
                return;
            }
            if kind == EvidenceKind::MacosCodesign {
                if !has_marker_line(output, &format!("TeamIdentifier={expected}")) {
                    errors.push("codesign output 未绑定预期 TeamIdentifier".to_string());
                }
            } else {
                let values = command_flag_values(command, "--team-id");
                if values.len() != 1 {
                    errors.push(
                        "notarytool command 必须恰好包含一个 --team-id 及其紧随值".to_string(),
                    );
                } else if normalize_team_id(values[0]).as_deref() != Some(expected.as_str()) {
                    errors
                        .push("notarytool command 的 --team-id 紧随值不是预期 Team ID".to_string());
                }
            }
        }
        EvidenceKind::WindowsSign | EvidenceKind::AndroidSign => {
            let Some(actual) = normalize_fingerprint(signer) else {
                errors.push("签名 signer 必须是 64 位证书 SHA-256".to_string());
                return;
            };
            let Some(expected) = normalize_fingerprint(expected) else {
                errors.push("--expected-signer 不是有效的 64 位证书 SHA-256".to_string());
                return;
            };
            if actual != expected {
                errors.push(format!("证书 SHA-256 不匹配:期望 {expected},实际 {actual}"));
                return;
            }
            let bound = if kind == EvidenceKind::WindowsSign {
                output_identity_matches(output, "CertificateSHA256=", &expected)
            } else {
                output_identity_matches(output, "Signer #1 certificate SHA-256 digest:", &expected)
            };
            if !bound {
                errors.push(format!("{kind} 的 output 未绑定预期证书 SHA-256"));
            }
        }
        EvidenceKind::AcceptanceMacos
        | EvidenceKind::AcceptanceAndroid
        | EvidenceKind::AcceptanceFirefox
        | EvidenceKind::AcceptanceWindows => unreachable!("上方已处理验收类"),
    }
}

fn normalize_team_id(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_uppercase();
    (normalized.len() == 10
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
    .then_some(normalized)
}

fn normalize_fingerprint(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .filter(|character| *character != ':' && !character.is_ascii_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn output_identity_matches(output: &str, prefix: &str, expected: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        line.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && normalize_fingerprint(&line[prefix.len()..]).as_deref() == Some(expected)
    })
}

fn has_marker_line(text: &str, marker: &str) -> bool {
    text.lines().any(|line| line.trim() == marker)
}

fn has_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || lower.contains("placeholder")
        || lower.contains("replace me")
        || lower.contains("todo")
        || trimmed.contains("待填写")
        || trimmed.contains("请替换")
}

fn valid_full_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_rfc3339(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if !value.is_ascii() || bytes.len() < 20 {
        return None;
    }
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let year = digits(bytes, 0, 4)?;
    let month = digits(bytes, 5, 7)?;
    let day = digits(bytes, 8, 10)?;
    let hour = digits(bytes, 11, 13)?;
    let minute = digits(bytes, 14, 16)?;
    let second = digits(bytes, 17, 19)?;
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return None;
        }
    }
    let offset_seconds = match bytes.get(cursor) {
        Some(b'Z') if cursor + 1 == bytes.len() => 0_i64,
        Some(b'+') | Some(b'-') => {
            if cursor + 6 != bytes.len() || bytes.get(cursor + 3) != Some(&b':') {
                return None;
            }
            let offset_hour = digits(bytes, cursor + 1, cursor + 3)?;
            let offset_minute = digits(bytes, cursor + 4, cursor + 6)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let seconds = i64::from(offset_hour * 60 * 60 + offset_minute * 60);
            if bytes[cursor] == b'+' {
                seconds
            } else {
                -seconds
            }
        }
        _ => return None,
    };
    let days = days_since_unix_epoch(year, month, day);
    let local_seconds = days * 24 * 60 * 60 + i64::from(hour * 60 * 60 + minute * 60 + second);
    Some(local_seconds - offset_seconds)
}

fn digits(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    let slice = bytes.get(start..end)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(slice).ok()?.parse().ok()
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn days_since_unix_epoch(year: u32, month: u32, day: u32) -> i64 {
    let mut days = 0_i64;
    if year >= 1970 {
        for candidate in 1970..year {
            days += i64::from(if is_leap_year(candidate) { 366 } else { 365 });
        }
    } else {
        for candidate in year..1970 {
            days -= i64::from(if is_leap_year(candidate) { 366 } else { 365 });
        }
    }
    for candidate in 1..month {
        days += i64::from(days_in_month(year, candidate));
    }
    days + i64::from(day - 1)
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100))
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const TEAM_ID: &str = "ABCDE12345";
    const CERT_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn fixed_now() -> i64 {
        parse_rfc3339("2026-09-01T12:34:56+08:00").unwrap()
    }

    fn fixed_commit_time() -> i64 {
        fixed_now() - 60
    }

    fn expected_signer(kind: EvidenceKind) -> Option<&'static str> {
        match kind {
            EvidenceKind::MacosCodesign | EvidenceKind::MacosNotarize => Some(TEAM_ID),
            EvidenceKind::WindowsSign | EvidenceKind::AndroidSign => Some(CERT_SHA256),
            EvidenceKind::AcceptanceMacos
            | EvidenceKind::AcceptanceAndroid
            | EvidenceKind::AcceptanceFirefox
            | EvidenceKind::AcceptanceWindows => None,
        }
    }

    fn verify_test(
        evidence: &ReleaseEvidence,
        kind: EvidenceKind,
        root: &Path,
    ) -> Result<PathBuf, EvidenceError> {
        verify_evidence_at(
            evidence,
            kind,
            COMMIT,
            fixed_commit_time(),
            expected_signer(kind),
            root,
            None,
            fixed_now(),
        )
    }

    fn acceptance_report(kind: EvidenceKind) -> String {
        let (marker, cases, platform) = match kind {
            EvidenceKind::AcceptanceMacos => (
                "AGENTGUARD_ACCEPTANCE_MACOS=PASS",
                vec![
                    "1", "2", "3", "4", "5", "5b", "5c", "6", "7", "8", "9", "10", "11", "12",
                    "13", "14",
                ],
                "macos",
            ),
            EvidenceKind::AcceptanceAndroid => (
                "AGENTGUARD_ACCEPTANCE_ANDROID=PASS",
                vec!["A1", "A2", "A3", "A4"],
                "android",
            ),
            EvidenceKind::AcceptanceFirefox => (
                "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS",
                vec!["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"],
                "firefox",
            ),
            EvidenceKind::AcceptanceWindows => (
                "AGENTGUARD_ACCEPTANCE_WINDOWS=PASS",
                vec!["W1", "W2", "W3", "W4", "W5", "W6", "W7"],
                "windows",
            ),
            _ => panic!("只给验收 kind 生成报告"),
        };
        let mut report = format!("{marker}\n\n| 用例 | 结果 | 证据 | 备注 |\n|---|---|---|---|\n");
        for case_id in cases {
            report.push_str(&format!(
                "| {case_id} 实测 | PASS (native) | evidence/{platform}/{case_id}.png | |\n"
            ));
        }
        report
    }

    fn write_acceptance_references(root: &Path, kind: EvidenceKind, report: &str) {
        for reference in parse_acceptance_report(kind, report).unwrap() {
            let path = root.join(reference);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"native device evidence").unwrap();
        }
    }

    fn valid_evidence(kind: EvidenceKind, path: &str, hash: &str) -> ReleaseEvidence {
        let (command, output) = match kind {
            EvidenceKind::MacosCodesign => (
                format!(
                    "codesign --verify --deep --strict --verbose=4 {path} && codesign -dv --verbose=4 {path}"
                ),
                format!(
                    "AgentGuard: valid on disk\nAgentGuard: satisfies its Designated Requirement\nTeamIdentifier={TEAM_ID}"
                ),
            ),
            EvidenceKind::MacosNotarize => (
                if path.ends_with(".app") {
                    format!(
                        "ditto -c -k --keepParent {path} dist/AgentGuard.zip && xcrun notarytool submit dist/AgentGuard.zip --wait --team-id {TEAM_ID} --keychain-profile AgentGuard-Notary && xcrun stapler staple {path} && xcrun stapler validate {path}"
                    )
                } else {
                    format!(
                        "xcrun notarytool submit {path} --wait --team-id {TEAM_ID} --keychain-profile AgentGuard-Notary && xcrun stapler staple {path} && xcrun stapler validate {path}"
                    )
                },
                "status: Accepted\nThe validate action worked!".to_string(),
            ),
            EvidenceKind::WindowsSign => (
                format!(
                    "signtool verify /pa /v {path}; if (-not $? -or $LASTEXITCODE -ne 0) {{ exit 1 }}; $signature = Get-AuthenticodeSignature {path}; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {{ exit 1 }}; Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))"
                ),
                format!("Successfully verified: {path}\nCertificateSHA256={CERT_SHA256}"),
            ),
            EvidenceKind::AndroidSign => (
                format!("apksigner verify --print-certs {path}"),
                format!(
                    "Signer #1 certificate DN: CN=AgentGuard Release\nSigner #1 certificate SHA-256 digest: {CERT_SHA256}"
                ),
            ),
            EvidenceKind::AcceptanceMacos => (
                format!(
                    "guard-cli manual-acceptance macos docs/acceptance-macos.md {path} --repo-root ."
                ),
                "AGENTGUARD_ACCEPTANCE_MACOS=PASS".to_string(),
            ),
            EvidenceKind::AcceptanceAndroid => (
                format!(
                    "guard-cli manual-acceptance android docs/acceptance-runbook.md {path} --repo-root ."
                ),
                "AGENTGUARD_ACCEPTANCE_ANDROID=PASS".to_string(),
            ),
            EvidenceKind::AcceptanceFirefox => (
                format!(
                    "guard-cli manual-acceptance firefox docs/acceptance-firefox.md {path} --repo-root ."
                ),
                "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS".to_string(),
            ),
            EvidenceKind::AcceptanceWindows => (
                format!(
                    "guard-cli manual-acceptance windows docs/acceptance-windows.md {path} --repo-root ."
                ),
                "AGENTGUARD_ACCEPTANCE_WINDOWS=PASS".to_string(),
            ),
        };
        ReleaseEvidence {
            schema: EVIDENCE_SCHEMA.to_string(),
            kind,
            commit: COMMIT.to_string(),
            command,
            exit_code: 0,
            timestamp: "2026-09-01T12:34:56+08:00".to_string(),
            output,
            signer: expected_signer(kind).map(str::to_string),
            artifact: ArtifactEvidence {
                path: path.to_string(),
                sha256: hash.to_string(),
            },
        }
    }

    #[test]
    fn 八种原样模板全部被拒绝() {
        for kind in EvidenceKind::ALL {
            let template = evidence_template(kind, Some(COMMIT));
            let error = validate_fields_at(
                &template,
                kind,
                COMMIT,
                fixed_commit_time(),
                expected_signer(kind),
                fixed_now(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("exit_code"), "{kind}: {error}");
        }
    }

    #[test]
    fn 有效证据会现场复核普通文件哈希() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("evidence/macos")).unwrap();
        let report = acceptance_report(EvidenceKind::AcceptanceMacos);
        write_acceptance_references(dir.path(), EvidenceKind::AcceptanceMacos, &report);
        fs::write(dir.path().join("evidence/macos/report.md"), &report).unwrap();
        let hash = artifact_digest(dir.path(), "evidence/macos/report.md").unwrap();
        let evidence = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &hash,
        );
        assert_eq!(
            verify_test(&evidence, EvidenceKind::AcceptanceMacos, dir.path()).unwrap(),
            dir.path()
                .canonicalize()
                .unwrap()
                .join("evidence/macos/report.md")
        );
    }

    #[test]
    fn 验收闭包摘要绑定逐项证据的内容和路径() {
        let dir = tempfile::tempdir().unwrap();
        let report_path = "evidence/firefox/report.md";
        let report = acceptance_report(EvidenceKind::AcceptanceFirefox);
        write_acceptance_references(dir.path(), EvidenceKind::AcceptanceFirefox, &report);
        fs::write(dir.path().join(report_path), &report).unwrap();
        let digest = artifact_digest(dir.path(), report_path).unwrap();
        let evidence = valid_evidence(EvidenceKind::AcceptanceFirefox, report_path, &digest);
        assert!(verify_test(&evidence, EvidenceKind::AcceptanceFirefox, dir.path()).is_ok());

        fs::write(
            dir.path().join("evidence/firefox/F1.png"),
            b"changed native evidence",
        )
        .unwrap();
        assert!(
            verify_test(&evidence, EvidenceKind::AcceptanceFirefox, dir.path())
                .unwrap_err()
                .to_string()
                .contains("SHA-256 不匹配")
        );

        fs::write(
            dir.path().join("evidence/firefox/F1.png"),
            b"native device evidence",
        )
        .unwrap();
        fs::rename(
            dir.path().join("evidence/firefox/F1.png"),
            dir.path().join("evidence/firefox/F1-renamed.png"),
        )
        .unwrap();
        let renamed_report =
            report.replace("evidence/firefox/F1.png", "evidence/firefox/F1-renamed.png");
        fs::write(dir.path().join(report_path), renamed_report).unwrap();
        assert!(
            verify_test(&evidence, EvidenceKind::AcceptanceFirefox, dir.path())
                .unwrap_err()
                .to_string()
                .contains("SHA-256 不匹配")
        );
    }

    #[test]
    fn app_bundle使用稳定tree_v2摘要并绑定整个目录和可执行位() {
        let dir = tempfile::tempdir().unwrap();
        for bundle in ["dist/First.app", "dist/Second.app"] {
            fs::create_dir_all(dir.path().join(bundle).join("Contents/MacOS")).unwrap();
            fs::create_dir_all(dir.path().join(bundle).join("Contents/Resources")).unwrap();
        }
        fs::write(
            dir.path().join("dist/First.app/Contents/MacOS/AgentGuard"),
            b"binary",
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("dist/First.app/Contents/Resources/config.json"),
            b"config",
        )
        .unwrap();
        // 以相反创建顺序生成同一棵树，摘要不能依赖 read_dir 返回顺序。
        fs::write(
            dir.path()
                .join("dist/Second.app/Contents/Resources/config.json"),
            b"config",
        )
        .unwrap();
        fs::write(
            dir.path().join("dist/Second.app/Contents/MacOS/AgentGuard"),
            b"binary",
        )
        .unwrap();

        #[cfg(unix)]
        for bundle in ["First", "Second"] {
            use std::os::unix::fs::PermissionsExt;

            let executable = dir
                .path()
                .join(format!("dist/{bundle}.app/Contents/MacOS/AgentGuard"));
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let first = artifact_digest(dir.path(), "dist/First.app").unwrap();
        let second = artifact_digest(dir.path(), "dist/Second.app").unwrap();
        assert_eq!(first, second, "bundle 根目录名不属于 tree 内部路径");

        let evidence = valid_evidence(EvidenceKind::MacosCodesign, "dist/First.app", &first);
        assert!(verify_test(&evidence, EvidenceKind::MacosCodesign, dir.path()).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = dir.path().join("dist/First.app/Contents/MacOS/AgentGuard");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o644)).unwrap();
            assert_ne!(
                first,
                artifact_digest(dir.path(), "dist/First.app").unwrap(),
                "755→644 必须改变 tree-v2 摘要"
            );
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                first,
                artifact_digest(dir.path(), "dist/First.app").unwrap(),
                "恢复可执行位后应恢复同一摘要"
            );
        }
        fs::write(
            dir.path()
                .join("dist/First.app/Contents/Resources/config.json"),
            b"changed",
        )
        .unwrap();
        let changed = artifact_digest(dir.path(), "dist/First.app").unwrap();
        assert_ne!(first, changed, "内容变化必须改变 tree 摘要");
        assert!(
            verify_test(&evidence, EvidenceKind::MacosCodesign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("SHA-256 不匹配")
        );

        fs::rename(
            dir.path()
                .join("dist/Second.app/Contents/Resources/config.json"),
            dir.path()
                .join("dist/Second.app/Contents/Resources/renamed.json"),
        )
        .unwrap();
        assert_ne!(
            second,
            artifact_digest(dir.path(), "dist/Second.app").unwrap(),
            "路径变化必须改变 tree 摘要"
        );
    }

    #[test]
    fn app_bundle拒绝空目录且内部mach_o不能冒充bundle() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dist/Empty.app")).unwrap();
        assert!(artifact_digest(dir.path(), "dist/Empty.app")
            .unwrap_err()
            .to_string()
            .contains("至少包含一个非空普通文件"));

        fs::create_dir_all(dir.path().join("dist/OnlyDirs.app/Contents/MacOS")).unwrap();
        assert!(artifact_digest(dir.path(), "dist/OnlyDirs.app")
            .unwrap_err()
            .to_string()
            .contains("至少包含一个非空普通文件"));

        fs::create_dir_all(dir.path().join("dist/OnlyEmpty.app/Contents/MacOS")).unwrap();
        fs::write(
            dir.path()
                .join("dist/OnlyEmpty.app/Contents/MacOS/AgentGuard"),
            b"",
        )
        .unwrap();
        assert!(artifact_digest(dir.path(), "dist/OnlyEmpty.app")
            .unwrap_err()
            .to_string()
            .contains("至少包含一个非空普通文件"));

        fs::create_dir_all(dir.path().join("dist/AgentGuard.app/Contents/MacOS")).unwrap();
        let executable = b"binary";
        fs::write(
            dir.path()
                .join("dist/AgentGuard.app/Contents/MacOS/AgentGuard"),
            executable,
        )
        .unwrap();
        let evidence = valid_evidence(
            EvidenceKind::MacosCodesign,
            "dist/AgentGuard.app/Contents/MacOS/AgentGuard",
            &format!("{:x}", Sha256::digest(executable)),
        );
        assert!(
            verify_test(&evidence, EvidenceKind::MacosCodesign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("文件类型")
        );
    }

    #[cfg(unix)]
    #[test]
    fn app_bundle拒绝符号链接和特殊文件() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dist/Linked.app/Contents")).unwrap();
        fs::write(dir.path().join("outside"), b"outside").unwrap();
        symlink(
            dir.path().join("outside"),
            dir.path().join("dist/Linked.app/Contents/link"),
        )
        .unwrap();
        assert!(artifact_digest(dir.path(), "dist/Linked.app")
            .unwrap_err()
            .to_string()
            .contains("符号链接"));

        fs::create_dir_all(dir.path().join("dist/Special.app/Contents")).unwrap();
        let _socket =
            UnixListener::bind(dir.path().join("dist/Special.app/Contents/socket")).unwrap();
        assert!(artifact_digest(dir.path(), "dist/Special.app")
            .unwrap_err()
            .to_string()
            .contains("普通文件或目录"));
    }

    #[test]
    fn 缺失产物和伪哈希都被拒绝() {
        let dir = tempfile::tempdir().unwrap();
        let missing = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/missing.md",
            &["0"; 64].concat(),
        );
        assert!(
            verify_test(&missing, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("不存在")
        );

        fs::create_dir_all(dir.path().join("evidence/macos")).unwrap();
        let report = acceptance_report(EvidenceKind::AcceptanceMacos);
        write_acceptance_references(dir.path(), EvidenceKind::AcceptanceMacos, &report);
        fs::write(dir.path().join("evidence/macos/report.md"), report).unwrap();
        let forged = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &["0"; 64].concat(),
        );
        assert!(
            verify_test(&forged, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("不匹配")
        );
    }

    #[test]
    fn 主产物和验收逐项证据都不能是空文件() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("evidence")).unwrap();
        fs::write(dir.path().join("evidence/AgentGuard.exe"), b"").unwrap();
        let empty_hash = format!("{:x}", Sha256::digest(b""));
        let artifact = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/AgentGuard.exe",
            &empty_hash,
        );
        assert!(
            verify_test(&artifact, EvidenceKind::WindowsSign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("不能为空文件")
        );

        fs::create_dir_all(dir.path().join("evidence/firefox")).unwrap();
        let report = acceptance_report(EvidenceKind::AcceptanceFirefox);
        write_acceptance_references(dir.path(), EvidenceKind::AcceptanceFirefox, &report);
        fs::write(dir.path().join("evidence/firefox/F1.png"), b"").unwrap();
        fs::write(dir.path().join("evidence/firefox/report.md"), &report).unwrap();
        let report_hash = format!("{:x}", Sha256::digest(report.as_bytes()));
        let acceptance = valid_evidence(
            EvidenceKind::AcceptanceFirefox,
            "evidence/firefox/report.md",
            &report_hash,
        );
        assert!(
            verify_test(&acceptance, EvidenceKind::AcceptanceFirefox, dir.path())
                .unwrap_err()
                .to_string()
                .contains("逐项证据 \"evidence/firefox/F1.png\" 不能为空")
        );
    }

    #[test]
    fn 验收逐项证据不能反指证据json源文件() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("evidence/firefox")).unwrap();
        let source_path = "evidence/firefox/source.json";
        let report = acceptance_report(EvidenceKind::AcceptanceFirefox).replacen(
            "evidence/firefox/F1.png",
            source_path,
            1,
        );
        write_acceptance_references(dir.path(), EvidenceKind::AcceptanceFirefox, &report);
        fs::write(dir.path().join("evidence/firefox/report.md"), &report).unwrap();
        let report_hash = format!("{:x}", Sha256::digest(report.as_bytes()));
        let evidence = valid_evidence(
            EvidenceKind::AcceptanceFirefox,
            "evidence/firefox/report.md",
            &report_hash,
        );
        fs::write(
            dir.path().join(source_path),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        let error = verify_evidence_at(
            &evidence,
            EvidenceKind::AcceptanceFirefox,
            COMMIT,
            fixed_commit_time(),
            None,
            dir.path(),
            Some(&dir.path().join(source_path)),
            fixed_now(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("JSON 源文件自身"));
    }

    #[test]
    fn 仓库外证据json源文件不影响仓内逐项证据() {
        let repo = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("release-evidence.json");
        fs::write(&source, b"external evidence source").unwrap();
        let report = acceptance_report(EvidenceKind::AcceptanceFirefox);
        write_acceptance_references(repo.path(), EvidenceKind::AcceptanceFirefox, &report);
        fs::write(repo.path().join("evidence/firefox/report.md"), &report).unwrap();
        let report_hash = artifact_digest(repo.path(), "evidence/firefox/report.md").unwrap();
        let evidence = valid_evidence(
            EvidenceKind::AcceptanceFirefox,
            "evidence/firefox/report.md",
            &report_hash,
        );
        assert!(verify_evidence_at(
            &evidence,
            EvidenceKind::AcceptanceFirefox,
            COMMIT,
            fixed_commit_time(),
            None,
            repo.path(),
            Some(&source),
            fixed_now(),
        )
        .is_ok());
    }

    #[test]
    fn 目录绝对路径和父目录都被拒绝() {
        let dir = tempfile::tempdir().unwrap();
        let hash = &["0"; 64].concat();
        for path in [
            ".",
            "../outside",
            "/tmp/outside",
            "C:\\outside",
            "evidence/macos/./report.md",
            "evidence//macos/report.md",
        ] {
            let evidence = valid_evidence(EvidenceKind::AcceptanceMacos, path, hash);
            assert!(
                verify_test(&evidence, EvidenceKind::AcceptanceMacos, dir.path()).is_err(),
                "path {path:?} 不应通过"
            );
        }
    }

    #[test]
    fn 发布路径统一拒绝glob变量展开和空白() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            "dist/*.dmg",
            "dist/?.dmg",
            "dist/[AgentGuard].dmg",
            "dist/{AgentGuard}.dmg",
            "dist/$ART.dmg",
            "dist/Agent Guard.dmg",
        ] {
            assert!(!valid_portable_repo_relative_path(path));
            assert!(
                artifact_digest(dir.path(), path)
                    .unwrap_err()
                    .to_string()
                    .contains("shell 元字符"),
                "摘要命令必须在触碰文件系统前拒绝不安全路径 {path:?}"
            );
        }

        let glob_artifact = valid_evidence(
            EvidenceKind::MacosCodesign,
            "dist/*.dmg",
            &["0"; 64].concat(),
        );
        assert!(
            verify_test(&glob_artifact, EvidenceKind::MacosCodesign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("shell 元字符")
        );

        for zip in ["dist/*.zip", "dist/$ZIP.zip", "dist/Agent Guard.zip"] {
            assert!(!valid_command_zip_path(zip));
        }
    }

    #[test]
    fn 错误产物类型和文档目录不能冒充产品或验收报告() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        fs::write(
            dir.path().join("docs/release-evidence.md"),
            b"AGENTGUARD_ACCEPTANCE_MACOS=PASS",
        )
        .unwrap();
        let docs_hash = format!("{:x}", Sha256::digest(b"AGENTGUARD_ACCEPTANCE_MACOS=PASS"));
        let docs = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "docs/release-evidence.md",
            &docs_hash,
        );
        assert!(
            verify_test(&docs, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("文件类型")
        );

        fs::create_dir_all(dir.path().join("Evidence/macos")).unwrap();
        fs::write(
            dir.path().join("Evidence/macos/report.md"),
            b"AGENTGUARD_ACCEPTANCE_MACOS=PASS",
        )
        .unwrap();
        let uppercase = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "Evidence/macos/report.md",
            &docs_hash,
        );
        assert!(
            verify_test(&uppercase, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("文件类型"),
            "Linux 上未被 /evidence/ ignore 的大小写变体不能通过"
        );

        fs::create_dir_all(dir.path().join("evidence")).unwrap();
        fs::write(dir.path().join("evidence/Cargo.toml"), b"package").unwrap();
        let cargo_hash = format!("{:x}", Sha256::digest(b"package"));
        let cargo = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/Cargo.toml",
            &cargo_hash,
        );
        assert!(verify_test(&cargo, EvidenceKind::WindowsSign, dir.path())
            .unwrap_err()
            .to_string()
            .contains("文件类型"));

        let release_bytes = b"signed release package";
        fs::write(dir.path().join("evidence/AgentGuard.pkg"), release_bytes).unwrap();
        fs::write(dir.path().join("evidence/AgentGuard.aab"), release_bytes).unwrap();
        let release_hash = format!("{:x}", Sha256::digest(release_bytes));

        let pkg_codesign = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.pkg",
            &release_hash,
        );
        assert!(
            verify_test(&pkg_codesign, EvidenceKind::MacosCodesign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("文件类型")
        );

        let pkg_notary = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.pkg",
            &release_hash,
        );
        assert!(
            verify_test(&pkg_notary, EvidenceKind::MacosNotarize, dir.path()).is_ok(),
            "flat .pkg 仍是 macOS 公证可接受产物"
        );

        let aab_apksigner = valid_evidence(
            EvidenceKind::AndroidSign,
            "evidence/AgentGuard.aab",
            &release_hash,
        );
        assert!(
            verify_test(&aab_apksigner, EvidenceKind::AndroidSign, dir.path())
                .unwrap_err()
                .to_string()
                .contains("文件类型")
        );
    }

    #[test]
    fn 验收报告本体缺少成功标记会失败() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("evidence/macos")).unwrap();
        fs::write(
            dir.path().join("evidence/macos/report.md"),
            b"AGENTGUARD_ACCEPTANCE_MACOS=PASSFAIL",
        )
        .unwrap();
        let hash = format!(
            "{:x}",
            Sha256::digest(b"AGENTGUARD_ACCEPTANCE_MACOS=PASSFAIL")
        );
        let evidence = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &hash,
        );
        assert!(
            verify_test(&evidence, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("缺少固定成功标记")
        );
    }

    #[test]
    fn 验收报告拒绝缺失重复仿真结果和空证据() {
        let kind = EvidenceKind::AcceptanceFirefox;

        let mut missing = acceptance_report(kind);
        missing = missing
            .lines()
            .filter(|line| !line.starts_with("| F8 "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_acceptance_report(kind, &missing)
            .unwrap_err()
            .to_string()
            .contains("缺少必需用例 F8"));

        let mut duplicate = acceptance_report(kind);
        duplicate.push_str("| F1 重复 | PASS (native) | evidence/firefox/F1-2.png | |\n");
        assert!(parse_acceptance_report(kind, &duplicate)
            .unwrap_err()
            .to_string()
            .contains("F1 重复"));

        let simulated = acceptance_report(kind).replacen("PASS (native)", "PASS (sim)", 1);
        assert!(parse_acceptance_report(kind, &simulated)
            .unwrap_err()
            .to_string()
            .contains("PASS (native)"));

        let empty_evidence =
            acceptance_report(kind).replacen("evidence/firefox/F1.png", "<待填写>", 1);
        assert!(parse_acceptance_report(kind, &empty_evidence)
            .unwrap_err()
            .to_string()
            .contains("证据列"));

        let reused =
            acceptance_report(kind).replace("evidence/firefox/F2.png", "evidence/firefox/F1.png");
        assert!(parse_acceptance_report(kind, &reused)
            .unwrap_err()
            .to_string()
            .contains("逐项证据路径必须唯一"));

        for invalid in [
            "evidence/windows/F1.png",
            "evidence/firefox/../windows/F1.png",
            "/tmp/F1.png",
            "evidence/firefox/*.png",
            "evidence/firefox/F?.png",
            "evidence/firefox/$CASE.png",
            "evidence/firefox/F 1.png",
        ] {
            let report = acceptance_report(kind).replacen("evidence/firefox/F1.png", invalid, 1);
            assert!(
                parse_acceptance_report(kind, &report)
                    .unwrap_err()
                    .to_string()
                    .contains("证据列"),
                "逐项证据路径 {invalid:?} 不应通过"
            );
        }
    }

    #[test]
    fn 验收证据命令必须绑定真实guard_cli子命令和固定repo_root() {
        let base = valid_evidence(
            EvidenceKind::AcceptanceFirefox,
            "evidence/firefox/report.md",
            &["0"; 64].concat(),
        );
        assert!(validate_fields_at(
            &base,
            EvidenceKind::AcceptanceFirefox,
            COMMIT,
            fixed_commit_time(),
            None,
            fixed_now(),
        )
        .is_ok());

        let mut direct_fake = base.clone();
        direct_fake.command = direct_fake.command.replacen("guard-cli ", "", 1);
        let mut missing_root = base.clone();
        missing_root.command = missing_root.command.replace(" --repo-root .", "");
        let mut wrong_root = base.clone();
        wrong_root.command = wrong_root
            .command
            .replace("--repo-root .", "--repo-root /tmp");
        let mut extra_argument = base;
        extra_argument.command.push_str(" --unexpected");

        for evidence in [direct_fake, missing_root, wrong_root, extra_argument] {
            assert!(
                validate_fields_at(
                    &evidence,
                    EvidenceKind::AcceptanceFirefox,
                    COMMIT,
                    fixed_commit_time(),
                    None,
                    fixed_now(),
                )
                .unwrap_err()
                .to_string()
                .contains("只接受单段 guard-cli manual-acceptance"),
                "验收命令必须是无多余参数的真实 guard-cli 固定形状：{evidence:?}"
            );
        }
    }

    #[test]
    fn 验收逐项证据必须真实存在且不能引用报告自身() {
        let dir = tempfile::tempdir().unwrap();
        let report_path = "evidence/firefox/report.md";
        fs::create_dir_all(dir.path().join("evidence/firefox")).unwrap();
        fs::write(
            dir.path().join(report_path),
            acceptance_report(EvidenceKind::AcceptanceFirefox),
        )
        .unwrap();
        fs::write(
            dir.path().join("evidence/firefox/F1.png"),
            b"native screenshot",
        )
        .unwrap();
        let root = dir.path().canonicalize().unwrap();

        verify_acceptance_reference(&root, report_path, "evidence/firefox/F1.png", None).unwrap();
        assert!(verify_acceptance_reference(
            &root,
            report_path,
            "evidence/firefox/missing.png",
            None,
        )
        .unwrap_err()
        .to_string()
        .contains("不存在"));
        assert!(
            verify_acceptance_reference(&root, report_path, report_path, None)
                .unwrap_err()
                .to_string()
                .contains("报告自身")
        );
    }

    #[cfg(unix)]
    #[test]
    fn 验收逐项证据拒绝符号链接() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let evidence_dir = dir.path().join("evidence/firefox");
        fs::create_dir_all(&evidence_dir).unwrap();
        fs::write(evidence_dir.join("report.md"), b"report").unwrap();
        fs::write(evidence_dir.join("real.png"), b"native screenshot").unwrap();
        symlink(evidence_dir.join("real.png"), evidence_dir.join("link.png")).unwrap();
        let error = verify_acceptance_reference(
            &dir.path().canonicalize().unwrap(),
            "evidence/firefox/report.md",
            "evidence/firefox/link.png",
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("符号链接"));
    }

    #[cfg(unix)]
    #[test]
    fn 任意路径组件为符号链接都会被拒绝() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("real/macos")).unwrap();
        let report = b"AGENTGUARD_ACCEPTANCE_MACOS=PASS";
        fs::write(dir.path().join("real/macos/report.md"), report).unwrap();
        fs::create_dir(dir.path().join("evidence")).unwrap();
        symlink(
            dir.path().join("real/macos"),
            dir.path().join("evidence/macos"),
        )
        .unwrap();
        let hash = format!("{:x}", Sha256::digest(report));
        let evidence = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &hash,
        );
        assert!(
            verify_test(&evidence, EvidenceKind::AcceptanceMacos, dir.path())
                .unwrap_err()
                .to_string()
                .contains("符号链接")
        );
    }

    #[test]
    fn 提交种类命令时间和输出都必须真实匹配() {
        let base = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        let mut cases = Vec::new();

        let mut wrong_commit = base.clone();
        wrong_commit.commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        cases.push((wrong_commit, EvidenceKind::MacosCodesign));

        let mut wrong_kind = base.clone();
        wrong_kind.kind = EvidenceKind::WindowsSign;
        cases.push((wrong_kind, EvidenceKind::MacosCodesign));

        let mut fake_command = base.clone();
        fake_command.command = "echo codesign --verify".to_string();
        cases.push((fake_command, EvidenceKind::MacosCodesign));

        let mut missing_tool = base.clone();
        missing_tool.command = "security verify evidence/AgentGuard.dmg".to_string();
        cases.push((missing_tool, EvidenceKind::MacosCodesign));

        let mut display_only = base.clone();
        display_only.command = "codesign -d evidence/AgentGuard.dmg".to_string();
        cases.push((display_only, EvidenceKind::MacosCodesign));

        let mut history = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        history.command = "xcrun notarytool history evidence/AgentGuard.dmg".to_string();
        cases.push((history, EvidenceKind::MacosNotarize));

        let mut sign_windows = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/AgentGuard.exe",
            &["0"; 64].concat(),
        );
        sign_windows.command = "signtool sign /v evidence/AgentGuard.exe".to_string();
        cases.push((sign_windows, EvidenceKind::WindowsSign));

        let mut sign_android = valid_evidence(
            EvidenceKind::AndroidSign,
            "evidence/AgentGuard.apk",
            &["0"; 64].concat(),
        );
        sign_android.command = "apksigner sign evidence/AgentGuard.apk".to_string();
        cases.push((sign_android, EvidenceKind::AndroidSign));

        let mut fake_acceptance = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &["0"; 64].concat(),
        );
        fake_acceptance.command = "not-a-real-test evidence/macos/report.md".to_string();
        cases.push((fake_acceptance, EvidenceKind::AcceptanceMacos));

        let mut marker_prefix = valid_evidence(
            EvidenceKind::AcceptanceMacos,
            "evidence/macos/report.md",
            &["0"; 64].concat(),
        );
        marker_prefix.output = "AGENTGUARD_ACCEPTANCE_MACOS=PASSFAIL".to_string();
        cases.push((marker_prefix, EvidenceKind::AcceptanceMacos));

        let mut invalid_time = base.clone();
        invalid_time.timestamp = "2026-02-30T25:00:00Z".to_string();
        cases.push((invalid_time, EvidenceKind::MacosCodesign));

        let mut fake_output = base.clone();
        fake_output.output = "<tool output>".to_string();
        cases.push((fake_output, EvidenceKind::MacosCodesign));

        for (evidence, expected_kind) in cases {
            assert!(
                validate_fields_at(
                    &evidence,
                    expected_kind,
                    COMMIT,
                    fixed_commit_time(),
                    expected_signer(expected_kind),
                    fixed_now()
                )
                .is_err(),
                "伪证字段不应通过:{evidence:?}"
            );
        }
    }

    #[test]
    fn 时间戳必须在当前时间前30天到未来10分钟窗口内() {
        let mut evidence = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        assert!(validate_fields_at(
            &evidence,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            expected_signer(EvidenceKind::MacosCodesign),
            fixed_now()
        )
        .is_ok());

        evidence.timestamp = "0001-01-01T00:00:00Z".to_string();
        assert!(validate_fields_at(
            &evidence,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            expected_signer(EvidenceKind::MacosCodesign),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("超过 30 天"));

        evidence.timestamp = "2026-09-01T04:45:57Z".to_string();
        assert!(validate_fields_at(
            &evidence,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            expected_signer(EvidenceKind::MacosCodesign),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("超过 10 分钟"));

        evidence.timestamp = "2026-09-01T04:23:55Z".to_string();
        assert!(validate_fields_at(
            &evidence,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            expected_signer(EvidenceKind::MacosCodesign),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("早于当前 HEAD"));
    }

    #[test]
    fn 签名者必须来自外部预期并同时绑定命令或输出() {
        let base = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        assert!(validate_fields_at(
            &base,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            None,
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("--expected-signer"));

        let mut wrong = base.clone();
        wrong.signer = Some("ZZZZZ99999".to_string());
        assert!(validate_fields_at(
            &wrong,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("signer 不匹配"));

        let mut unbound = base;
        unbound.output = unbound.output.replace(TEAM_ID, "ZZZZZ99999");
        assert!(validate_fields_at(
            &unbound,
            EvidenceKind::MacosCodesign,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("TeamIdentifier"));

        let mut wrong_fingerprint = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/AgentGuard.exe",
            &["0"; 64].concat(),
        );
        wrong_fingerprint.output = wrong_fingerprint
            .output
            .replace(CERT_SHA256, &"a".repeat(64));
        assert!(validate_fields_at(
            &wrong_fingerprint,
            EvidenceKind::WindowsSign,
            COMMIT,
            fixed_commit_time(),
            Some(CERT_SHA256),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("output 未绑定"));

        let mut windows_uppercase_exe = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/AgentGuard.exe",
            &["0"; 64].concat(),
        );
        windows_uppercase_exe.command =
            windows_uppercase_exe
                .command
                .replacen("signtool", "SIGNTOOL.EXE", 1);
        assert!(validate_fields_at(
            &windows_uppercase_exe,
            EvidenceKind::WindowsSign,
            COMMIT,
            fixed_commit_time(),
            Some(CERT_SHA256),
            fixed_now()
        )
        .is_ok());

        let mut acceptance = valid_evidence(
            EvidenceKind::AcceptanceAndroid,
            "evidence/android/report.md",
            &["0"; 64].concat(),
        );
        acceptance.signer = Some(TEAM_ID.to_string());
        assert!(validate_fields_at(
            &acceptance,
            EvidenceKind::AcceptanceAndroid,
            COMMIT,
            fixed_commit_time(),
            None,
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("必须为 null"));
    }

    #[test]
    fn 公证命令必须唯一绑定预期team_id并使用keychain_profile() {
        let base = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        assert!(validate_fields_at(
            &base,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .is_ok());

        let mut wrong_value_with_expected_comment = base.clone();
        wrong_value_with_expected_comment.command = wrong_value_with_expected_comment
            .command
            .replace(TEAM_ID, "ZZZZZ99999")
            + &format!(" # {TEAM_ID}");
        assert!(validate_fields_at(
            &wrong_value_with_expected_comment,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("不允许 shell、PowerShell 或 batch 注释"));

        let mut wrong_value = base.clone();
        wrong_value.command = wrong_value.command.replace(TEAM_ID, "ZZZZZ99999");
        assert!(validate_fields_at(
            &wrong_value,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("紧随值不是预期"));

        let mut missing_value = base.clone();
        missing_value.command = missing_value
            .command
            .replace(&format!("--team-id {TEAM_ID}"), "--team-id &&");
        assert!(validate_fields_at(
            &missing_value,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("紧随值不是预期"));

        let mut missing_profile = base.clone();
        missing_profile.command = missing_profile
            .command
            .replace(" --keychain-profile AgentGuard-Notary", "");
        assert!(validate_fields_at(
            &missing_profile,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("keychain-profile"));

        let mut plaintext_password = base.clone();
        plaintext_password.command = plaintext_password.command.replace(
            "--keychain-profile AgentGuard-Notary",
            "--apple-id qa@example.com --password exposed-secret",
        );
        assert!(validate_fields_at(
            &plaintext_password,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .is_err());

        let mut duplicate_profile = base.clone();
        duplicate_profile
            .command
            .push_str(" --keychain-profile Another-Profile");
        assert!(validate_fields_at(
            &duplicate_profile,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .is_err());

        let mut duplicate = base;
        duplicate.command.push_str(&format!(" --team-id {TEAM_ID}"));
        assert!(validate_fields_at(
            &duplicate,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("恰好包含一个"));
    }

    #[test]
    fn app公证绑定同一zip与有序的ditto_notary_stapler() {
        let base = valid_evidence(
            EvidenceKind::MacosNotarize,
            "dist/AgentGuard.app",
            &["0"; 64].concat(),
        );
        assert!(validate_fields_at(
            &base,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .is_ok());

        let mut validate_only = base.clone();
        validate_only.command = validate_only
            .command
            .replace("xcrun stapler staple dist/AgentGuard.app && ", "");
        assert!(validate_fields_at(
            &validate_only,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("stapler staple"));

        let mut wrong_zip = base.clone();
        wrong_zip.command = wrong_zip.command.replacen(
            "notarytool submit dist/AgentGuard.zip",
            "notarytool submit dist/Other.zip",
            1,
        );
        assert!(validate_fields_at(
            &wrong_zip,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("同一 ZIP"));

        let mut glob_zip = base.clone();
        glob_zip.command = glob_zip
            .command
            .replace("dist/AgentGuard.zip", "dist/*.zip");
        assert!(validate_fields_at(
            &glob_zip,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("repo-relative.zip"));

        let mut wrong_order = base.clone();
        wrong_order.command = format!(
            "xcrun stapler validate dist/AgentGuard.app && ditto -c -k --keepParent dist/AgentGuard.app dist/AgentGuard.zip && xcrun notarytool submit dist/AgentGuard.zip --wait --team-id {TEAM_ID} && xcrun stapler staple dist/AgentGuard.app"
        );
        assert!(validate_fields_at(
            &wrong_order,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("顺序必须"));

        let mut absolute_zip = base;
        absolute_zip.command = absolute_zip
            .command
            .replace("dist/AgentGuard.zip", "/tmp/AgentGuard.zip");
        assert!(validate_fields_at(
            &absolute_zip,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("repo-relative.zip"));
    }

    #[test]
    fn 命令注释和跨命令段参数不能冒充工具参数() {
        let base = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        for suffix in [
            " # --team-id ABCDE12345",
            " && REM --team-id ABCDE12345",
            " && :: --team-id ABCDE12345",
        ] {
            let mut commented = base.clone();
            commented.command = commented
                .command
                .replace(&format!(" --team-id {TEAM_ID}"), "")
                + suffix;
            assert!(
                validate_fields_at(
                    &commented,
                    EvidenceKind::MacosNotarize,
                    COMMIT,
                    fixed_commit_time(),
                    Some(TEAM_ID),
                    fixed_now()
                )
                .unwrap_err()
                .to_string()
                .contains("注释"),
                "注释形状 {suffix:?} 不应提供有效参数"
            );
        }

        let mut moved = base;
        moved.command = format!(
            "xcrun notarytool history evidence/AgentGuard.dmg && printf submit --wait --team-id {TEAM_ID} && xcrun stapler staple evidence/AgentGuard.dmg && xcrun stapler validate evidence/AgentGuard.dmg"
        );
        assert!(validate_fields_at(
            &moved,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("notarytool 命令段"));

        let mut single_ampersand = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        single_ampersand.command = format!(
            "xcrun notarytool history evidence/AgentGuard.dmg & printf submit --wait --team-id {TEAM_ID} & xcrun stapler staple evidence/AgentGuard.dmg & xcrun stapler validate evidence/AgentGuard.dmg"
        );
        assert!(validate_fields_at(
            &single_ampersand,
            EvidenceKind::MacosNotarize,
            COMMIT,
            fixed_commit_time(),
            Some(TEAM_ID),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("单个 &"));

        let mut windows = valid_evidence(
            EvidenceKind::WindowsSign,
            "dist/AgentGuard.exe",
            &["0"; 64].concat(),
        );
        windows.command = windows.command.replace(
            "Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))",
            "Write-Output ('CertificateSHA256=' + $signature.SignerCertificate) && printf SHA256",
        );
        assert!(validate_fields_at(
            &windows,
            EvidenceKind::WindowsSign,
            COMMIT,
            fixed_commit_time(),
            Some(CERT_SHA256),
            fixed_now()
        )
        .unwrap_err()
        .to_string()
        .contains("GetCertHashString"));
    }

    #[test]
    fn 失败吞噬命令替换参数填充和伪输出都不能通过() {
        let mut attacks = Vec::new();

        let mut codesign_masked = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        codesign_masked.command = concat!(
            "codesign --verify --deep --strict --verbose=4 evidence/AgentGuard.dmg || true; ",
            "codesign -dv --verbose=4 evidence/AgentGuard.dmg || true; ",
            "printf forged-success"
        )
        .to_string();
        attacks.push((codesign_masked, EvidenceKind::MacosCodesign));

        let mut codesign_substitution = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        codesign_substitution.command = concat!(
            "codesign --verify --deep --strict --verbose=4 \"$(: evidence/AgentGuard.dmg)\" && ",
            "codesign -dv --verbose=4 \"$(: evidence/AgentGuard.dmg)\""
        )
        .to_string();
        attacks.push((codesign_substitution, EvidenceKind::MacosCodesign));

        let mut codesign_extra = valid_evidence(
            EvidenceKind::MacosCodesign,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        codesign_extra.command.push_str(" && printf forged-success");
        attacks.push((codesign_extra, EvidenceKind::MacosCodesign));

        let mut notary_masked = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        notary_masked.command = format!(
            "xcrun notarytool submit evidence/AgentGuard.dmg --wait --team-id {TEAM_ID} || true; printf 'status: Accepted'; xcrun stapler staple evidence/AgentGuard.dmg || true; xcrun stapler validate evidence/AgentGuard.dmg || true"
        );
        attacks.push((notary_masked, EvidenceKind::MacosNotarize));

        let mut notary_stuffed = valid_evidence(
            EvidenceKind::MacosNotarize,
            "evidence/AgentGuard.dmg",
            &["0"; 64].concat(),
        );
        notary_stuffed.command = format!(
            "xcrun notarytool history submit evidence/AgentGuard.dmg --wait --team-id {TEAM_ID} && xcrun stapler staple evidence/AgentGuard.dmg && xcrun stapler validate evidence/AgentGuard.dmg"
        );
        attacks.push((notary_stuffed, EvidenceKind::MacosNotarize));

        let mut android_masked = valid_evidence(
            EvidenceKind::AndroidSign,
            "evidence/AgentGuard.apk",
            &["0"; 64].concat(),
        );
        android_masked.command = concat!(
            "apksigner verify --print-certs evidence/AgentGuard.apk || true; ",
            "printf 'Signer #1 certificate'"
        )
        .to_string();
        attacks.push((android_masked, EvidenceKind::AndroidSign));

        let mut android_stuffed = valid_evidence(
            EvidenceKind::AndroidSign,
            "evidence/AgentGuard.apk",
            &["0"; 64].concat(),
        );
        android_stuffed.command =
            "apksigner sign verify --print-certs evidence/AgentGuard.apk".to_string();
        attacks.push((android_stuffed, EvidenceKind::AndroidSign));

        let mut acceptance_masked = valid_evidence(
            EvidenceKind::AcceptanceFirefox,
            "evidence/firefox/report.md",
            &["0"; 64].concat(),
        );
        acceptance_masked.command = concat!(
            "guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root . || true; ",
            "printf AGENTGUARD_ACCEPTANCE_FIREFOX=PASS"
        )
        .to_string();
        attacks.push((acceptance_masked, EvidenceKind::AcceptanceFirefox));

        let mut windows_indirect = valid_evidence(
            EvidenceKind::WindowsSign,
            "evidence/AgentGuard.exe",
            &["0"; 64].concat(),
        );
        windows_indirect.command =
            windows_indirect
                .command
                .replacen("signtool", "cmd /c echo signtool", 1);
        attacks.push((windows_indirect, EvidenceKind::WindowsSign));

        for (evidence, kind) in attacks {
            assert!(
                validate_fields_at(
                    &evidence,
                    kind,
                    COMMIT,
                    fixed_commit_time(),
                    expected_signer(kind),
                    fixed_now(),
                )
                .is_err(),
                "失败吞噬、命令替换、参数填充或伪输出不应通过：{evidence:?}"
            );
        }
    }

    #[test]
    fn 固定powershell签名流程仍可通过命令校验() {
        let path = "dist/AgentGuard.exe";
        let mut evidence = valid_evidence(EvidenceKind::WindowsSign, path, &["0"; 64].concat());
        evidence.command = format!(
            "powershell -NoProfile -Command \"$algorithm = 'SHA256'; signtool verify /pa /v {path}; if (-not $? -or $LASTEXITCODE -ne 0) {{ exit 1 }}; $signature = Get-AuthenticodeSignature {path}; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {{ exit 1 }}; $fingerprint = $signature.SignerCertificate.GetCertHashString($algorithm); Write-Output ('CertificateSHA256=' + $fingerprint)\""
        );
        assert!(validate_fields_at(
            &evidence,
            EvidenceKind::WindowsSign,
            COMMIT,
            fixed_commit_time(),
            Some(CERT_SHA256),
            fixed_now(),
        )
        .is_ok());
    }

    #[test]
    fn windows签名拒绝旧last_exitcode守卫和缺失状态检查() {
        let path = "dist/AgentGuard.exe";
        let base = valid_evidence(EvidenceKind::WindowsSign, path, &["0"; 64].concat());

        let mut old_guard = base.clone();
        old_guard.command = old_guard.command.replace(
            "if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }",
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        );
        let mut missing_guard = base;
        missing_guard.command = missing_guard
            .command
            .replace("; if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }", "");

        for evidence in [old_guard, missing_guard] {
            assert!(
                validate_fields_at(
                    &evidence,
                    EvidenceKind::WindowsSign,
                    COMMIT,
                    fixed_commit_time(),
                    Some(CERT_SHA256),
                    fixed_now(),
                )
                .unwrap_err()
                .to_string()
                .contains("固定 PowerShell 流程"),
                "signtool 后必须同时检查 $? 与 LASTEXITCODE：{evidence:?}"
            );
        }
    }

    #[test]
    fn 错误文本始终只有一行且不含旧分隔符() {
        let error = EvidenceError::new(vec!["第一行\n第二行|伪字段".to_string()]);
        let rendered = error.to_string();
        assert!(!rendered.contains(['\r', '\n', '|']));
    }
}
