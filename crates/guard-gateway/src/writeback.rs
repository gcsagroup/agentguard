//! 单个授权根的小工作区回写。正文、基线和批准摘要由宿主内存持有。
//! 多文件提交不是事务；排他发布不会覆盖并发新建的路径，旧 inode 始终保留供恢复。
//! 已持有文件描述符的同用户写入及并发目录改名没有内核 CAS 保证，见同名设计报告。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MAX_FILE_BYTES: usize = 256 * 1024;
pub const MAX_PREVIEW_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_CHANGES: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileVersion {
    pub sha256: String,
    pub bytes: usize,
    pub mode: u32,
    pub text: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Create,
    Modify,
    Delete,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub kind: ChangeKind,
    pub before: Option<FileVersion>,
    pub after: Option<FileVersion>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preview {
    pub digest: String,
    pub workspace_root: PathBuf,
    pub recovery_directory: PathBuf,
    pub changes: Vec<FileChange>,
    pub total_body_bytes: usize,
    pub atomic: bool,
    pub limitations: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Applied,
    Conflict,
    Partial,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileApplyState {
    Applied,
    Conflict,
    NotApplied,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileApplyResult {
    pub path: String,
    pub state: FileApplyState,
    pub detail: String,
    pub recovery_file: Option<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyReport {
    pub outcome: ApplyOutcome,
    pub files: Vec<FileApplyResult>,
    pub recovery_directory: Option<PathBuf>,
    pub detail: String,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform {
    use super::*;
    use anyhow::{bail, Context, Result};
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{CStr, CString};
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};

    const MAX_BASELINE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_ENTRIES: usize = 20_000;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    struct Identity {
        device: u64,
        inode: u64,
    }
    impl Identity {
        fn of(meta: &Metadata) -> Self {
            Self {
                device: meta.dev(),
                inode: meta.ino(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    struct FileState {
        identity: Identity,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: (i64, i64),
        ctime: (i64, i64),
        sha256: String,
        #[serde(skip)]
        body: Vec<u8>,
    }
    impl FileState {
        fn same_content(&self, other: &Self) -> bool {
            self.sha256 == other.sha256 && self.body == other.body && self.mode == other.mode
        }
        fn same_moved_object(&self, other: &Self) -> bool {
            // rename 会改变 ctime；其余已观察到的内容与身份仍须相同。
            self.identity == other.identity
                && self.same_content(other)
                && self.uid == other.uid
                && self.gid == other.gid
                && self.mtime == other.mtime
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    struct DirectoryState {
        identity: Identity,
        mode: u32,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    struct LinkState {
        identity: Identity,
        target: Vec<u8>,
        mtime: (i64, i64),
        ctime: (i64, i64),
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    struct Tree {
        files: BTreeMap<String, FileState>,
        directories: BTreeMap<String, DirectoryState>,
        links: BTreeMap<String, LinkState>,
    }

    struct Root {
        path: PathBuf,
        directory: File,
        // 从 / 到授权根逐级保留身份；每次使用前重新打开校验，用户链接不被接受。
        ancestors: Vec<Identity>,
    }
    impl Root {
        fn open(path: &Path) -> Result<Self> {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            {
                bail!("回写根必须是没有点分量的绝对路径");
            }
            let physical = path.canonicalize().context("回写根不存在")?;
            if guard_schema::paths::dealias_platform_volumes(path)
                != guard_schema::paths::dealias_platform_volumes(&physical)
            {
                bail!("回写根或祖先包含用户符号链接");
            }
            let (directory, ancestors) = open_absolute(&physical)?;
            Ok(Self {
                path: physical,
                directory,
                ancestors,
            })
        }
        fn validate(&self) -> Result<()> {
            let (current, ancestors) = open_absolute(&self.path)?;
            if ancestors != self.ancestors
                || Identity::of(&current.metadata()?) != Identity::of(&self.directory.metadata()?)
            {
                bail!("授权根或祖先目录 inode 已改变");
            }
            Ok(())
        }
        fn stable_tree(&self) -> Result<Tree> {
            self.validate()?;
            let first = scan(&self.directory)?;
            let second = scan(&self.directory)?;
            self.validate()?;
            if first != second {
                bail!("工作区在读取清单时改变，拒绝使用不稳定基线");
            }
            Ok(first)
        }
        fn parent(&self, path: &str, expected: &Tree) -> Result<(File, CString)> {
            self.validate()?;
            let mut components = path.split('/').collect::<Vec<_>>();
            let name = components.pop().context("文件路径为空")?;
            let mut directory = open_at(&self.directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
            let mut relative = String::new();
            for component in components {
                if component.is_empty() || component == "." || component == ".." {
                    bail!("相对路径分量无效");
                }
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(component);
                directory = open_at(
                    &directory,
                    &CString::new(component)?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                let actual = DirectoryState {
                    identity: Identity::of(&directory.metadata()?),
                    mode: directory.metadata()?.mode() & 0o7777,
                };
                if expected.directories.get(&relative) != Some(&actual) {
                    bail!("文件父目录身份或模式已改变：{relative}");
                }
            }
            if name.is_empty() || name == "." || name == ".." {
                bail!("文件名无效");
            }
            Ok((directory, CString::new(name)?))
        }
    }

    /// 必须在复制快照之前采集；不接受由 Agent 或反序列化数据提供的起始清单。
    pub struct HostBaseline {
        root: Root,
        tree: Tree,
    }
    impl HostBaseline {
        pub fn capture(host_root: &Path) -> Result<Self> {
            let root = Root::open(host_root)?;
            let tree = root.stable_tree()?;
            for file in tree.files.values() {
                if file.uid != unsafe { libc::geteuid() } {
                    bail!("首版回写只支持当前宿主用户拥有的普通文件");
                }
            }
            Ok(Self { root, tree })
        }
    }

    impl FileVersion {
        fn of(file: &FileState, mode: u32) -> Self {
            let text = if file.body.contains(&0) {
                None
            } else {
                String::from_utf8(file.body.clone()).ok()
            };
            Self {
                sha256: file.sha256.clone(),
                bytes: file.body.len(),
                mode,
                text,
            }
        }
    }
    struct Pending {
        preview: Preview,
        snapshot: Tree,
    }
    pub struct WritebackEngine {
        baseline: HostBaseline,
        snapshot: Root,
        initial_snapshot: Tree,
        pending: Option<Pending>,
        consumed: bool,
    }
    impl WritebackEngine {
        /// 必须在首次工具执行前调用。快照可归一文件权限，正文、目录拓扑与链接必须吻合。
        pub fn attach(baseline: HostBaseline, snapshot_root: &Path) -> Result<Self> {
            if baseline.root.stable_tree()? != baseline.tree {
                bail!("宿主在复制快照期间改变");
            }
            let snapshot = Root::open(snapshot_root)?;
            if snapshot.path.starts_with(&baseline.root.path)
                || baseline.root.path.starts_with(&snapshot.path)
            {
                bail!("宿主根与快照根不能相互嵌套");
            }
            let initial_snapshot = snapshot.stable_tree()?;
            if initial_snapshot
                .directories
                .keys()
                .ne(baseline.tree.directories.keys())
                || initial_snapshot.links.keys().ne(baseline.tree.links.keys())
                || initial_snapshot.files.keys().ne(baseline.tree.files.keys())
            {
                bail!("起始快照对象清单与宿主基线不一致");
            }
            for (path, file) in &baseline.tree.files {
                if initial_snapshot.files[path].body != file.body {
                    bail!("起始快照正文不一致：{path}");
                }
            }
            for (path, link) in &baseline.tree.links {
                if initial_snapshot.links[path].target != link.target {
                    bail!("起始快照链接不一致：{path}");
                }
            }
            Ok(Self {
                baseline,
                snapshot,
                initial_snapshot,
                pending: None,
                consumed: false,
            })
        }

        pub fn preview(&mut self) -> Result<Preview> {
            self.pending = None;
            if self.consumed {
                bail!("此回写引擎已经使用，必须重新建立工作区基线");
            }
            if self.baseline.root.stable_tree()? != self.baseline.tree {
                bail!("宿主已被编辑，拒绝覆盖当前工作");
            }
            let current = self.snapshot.stable_tree()?;
            if current.directories != self.initial_snapshot.directories {
                bail!("首版回写不支持目录创建、删除、置换或模式变化");
            }
            if current.links != self.initial_snapshot.links {
                bail!("链接已改变，拒绝回写；不会跟随任何链接");
            }
            let paths = current
                .files
                .keys()
                .chain(self.initial_snapshot.files.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut changes = Vec::new();
            let mut total_body_bytes = 0usize;
            for path in paths {
                let before = self.baseline.tree.files.get(&path);
                let initial = self.initial_snapshot.files.get(&path);
                let after = current.files.get(&path);
                // 隔离副本初始 0600/0700 不是用户请求的 chmod，未变时保留宿主原模式。
                let after_mode = after.map(|file| match (initial, before) {
                    (Some(start), Some(host)) if start.mode == file.mode => host.mode,
                    _ => file.mode,
                });
                if let (Some(old), Some(new)) = (before, after) {
                    if old.body == new.body && Some(old.mode) == after_mode {
                        continue;
                    }
                }
                total_body_bytes = total_body_bytes
                    .checked_add(
                        before.map_or(0, |f| f.body.len()) + after.map_or(0, |f| f.body.len()),
                    )
                    .context("预览正文长度溢出")?;
                if total_body_bytes > MAX_PREVIEW_BODY_BYTES || changes.len() >= MAX_CHANGES {
                    bail!("预览超过 1 MiB 正文或 100 项变更；不能截断后批准");
                }
                changes.push(FileChange {
                    path,
                    kind: match (before, after) {
                        (None, Some(_)) => ChangeKind::Create,
                        (Some(_), None) => ChangeKind::Delete,
                        _ => ChangeKind::Modify,
                    },
                    before: before.map(|f| FileVersion::of(f, f.mode)),
                    after: after.map(|f| FileVersion::of(f, after_mode.expect("存在目标模式"))),
                });
            }
            let mut preview = Preview {
                digest: String::new(),
                workspace_root: self.baseline.root.path.clone(),
                recovery_directory: recovery_path(&self.baseline.root.path)?,
                changes,
                total_body_bytes,
                atomic: false,
                limitations: vec![
                    "多文件回写不是原子事务；原件保留在恢复目录，发生中断须逐项核对".into(),
                    "不提供针对同用户既有文件描述符、硬链接并发写入及目录主动改名的完全隔离".into(),
                    "首版仅支持现有目录中的普通文件；带扩展属性、ACL 或特殊权限的文件拒绝回写"
                        .into(),
                ],
            };
            preview.digest = hex_digest(&serde_json::to_vec(&(
                "agentguard-writeback-v1",
                &preview,
                &self.baseline.tree,
                &current,
            ))?);
            self.pending = Some(Pending {
                preview: preview.clone(),
                snapshot: current,
            });
            Ok(preview)
        }

        pub fn apply(&mut self, approved_digest: &str) -> ApplyReport {
            self.apply_with_cancel(approved_digest, &|| false)
        }

        pub fn apply_with_cancel(
            &mut self,
            approved_digest: &str,
            cancelled: &dyn Fn() -> bool,
        ) -> ApplyReport {
            let Some(pending) = self.pending.take() else {
                return conflict_report(Vec::new(), "缺少有效的未使用预览");
            };
            let files = pending
                .preview
                .changes
                .iter()
                .map(|change| FileApplyResult {
                    path: change.path.clone(),
                    state: FileApplyState::NotApplied,
                    detail: "尚未应用".into(),
                    recovery_file: None,
                })
                .collect();
            if self.consumed || approved_digest != pending.preview.digest {
                return conflict_report(files, "批准摘要不匹配或预览已经使用");
            }
            self.consumed = true;
            if cancelled() {
                self.consumed = false;
                return conflict_report(files, "已取消，尚未开始回写文件");
            }
            if let Err(error) = self.preflight(&pending) {
                self.consumed = false;
                return conflict_report(files, &format!("全批次预检冲突：{error:#}"));
            }
            if pending.preview.changes.is_empty() {
                self.consumed = false;
                return ApplyReport {
                    outcome: ApplyOutcome::Applied,
                    files,
                    recovery_directory: None,
                    detail: "没有需要回写的文件".into(),
                };
            }
            let mut report = ApplyReport {
                outcome: ApplyOutcome::Applied,
                files,
                recovery_directory: None,
                detail: "已逐项应用；保留旧原件，不代表多文件原子事务".into(),
            };
            let recovery = match Recovery::create(&self.baseline.root, &pending.preview) {
                Ok(value) => value,
                Err(error) => {
                    self.consumed = false;
                    let mut failure = conflict_report(
                        report.files,
                        &format!(
                            "不能建立私有恢复目录，原文件未动；预定目录可能已有准备文件：{error:#}"
                        ),
                    );
                    failure.recovery_directory = Some(pending.preview.recovery_directory.clone());
                    return failure;
                }
            };
            report.recovery_directory = Some(recovery.path.clone());
            // 先把本批全部待发布正文落到同一文件系统并同步；此阶段不碰任何原文件。
            if let Err(error) = self.stage(&pending, &recovery, cancelled) {
                report.outcome = ApplyOutcome::Conflict;
                report.detail = format!("准备回写内容失败，宿主原文件未改：{error:#}");
                if let Err(journal_error) = recovery.finish(&report) {
                    report
                        .detail
                        .push_str(&format!("；清单更新失败：{journal_error:#}"));
                }
                self.consumed = false;
                return report;
            }
            let mut expected_host = self.baseline.tree.clone();
            for (index, change) in pending.preview.changes.iter().enumerate() {
                #[cfg(test)]
                run_test_hook(index, "before_operation");
                match self.apply_one(
                    index,
                    change,
                    &pending,
                    &recovery,
                    &expected_host,
                    cancelled,
                ) {
                    Ok((old, resulting_file, retained_original)) => {
                        report.files[index].state = FileApplyState::Applied;
                        report.files[index].detail = "本文件已应用；原件未就地改写".into();
                        report.files[index].recovery_file = old;
                        if let Some(original) = retained_original {
                            account_for_rename(&mut expected_host, &original);
                        }
                        if let Some(file) = resulting_file {
                            expected_host.files.insert(change.path.clone(), file);
                        } else {
                            expected_host.files.remove(&change.path);
                        }
                        if let Err(error) = recovery.record_result(index, &report.files[index]) {
                            report.outcome = ApplyOutcome::Unknown;
                            report.detail =
                                format!("文件操作已发生但清单同步失败，须核对实际文件：{error:#}");
                            break;
                        }
                    }
                    Err(failure) => {
                        if let Some(restored) = &failure.restored_file {
                            if expected_host
                                .files
                                .get(&change.path)
                                .is_some_and(|before| before.same_moved_object(restored))
                            {
                                account_for_rename(&mut expected_host, restored);
                            }
                        }
                        report.files[index].state = if failure.unknown {
                            FileApplyState::Unknown
                        } else {
                            FileApplyState::Conflict
                        };
                        report.files[index].detail = failure.detail.clone();
                        report.files[index].recovery_file = failure.recovery_file;
                        report.outcome = if failure.unknown {
                            ApplyOutcome::Unknown
                        } else if report
                            .files
                            .iter()
                            .any(|f| f.state == FileApplyState::Applied)
                        {
                            ApplyOutcome::Partial
                        } else {
                            ApplyOutcome::Conflict
                        };
                        report.detail =
                            format!("回写已停止；没有对已完成项自动回滚：{}", failure.detail);
                        break;
                    }
                }
            }
            if report.outcome == ApplyOutcome::Applied {
                let verified = (|| -> Result<()> {
                    if self.snapshot.stable_tree()? != pending.snapshot {
                        bail!("批准的快照在回写期间改变");
                    }
                    if self.baseline.root.stable_tree()? != expected_host {
                        bail!("宿主最终内容与本批已确认结果不一致");
                    }
                    Ok(())
                })();
                if let Err(error) = verified {
                    report.outcome = ApplyOutcome::Unknown;
                    report.detail = format!("文件操作已发生，但最终一致性核对失败：{error:#}");
                }
            }
            if let Err(error) = recovery.finish(&report) {
                report.outcome = ApplyOutcome::Unknown;
                report
                    .detail
                    .push_str(&format!("；最终清单不能同步：{error:#}"));
            }
            if report.outcome == ApplyOutcome::Applied {
                self.baseline.tree = expected_host;
                self.initial_snapshot = pending.snapshot;
                self.consumed = false;
            } else if report.outcome == ApplyOutcome::Conflict {
                // 只吸收由已确认排他恢复产生的 ctime 变化，绝不把外部编辑当成新基线。
                if self
                    .baseline
                    .root
                    .stable_tree()
                    .is_ok_and(|current| current == expected_host)
                {
                    self.baseline.tree = expected_host;
                }
                self.consumed = false;
            }
            report
        }

        fn preflight(&self, pending: &Pending) -> Result<()> {
            if self.baseline.root.stable_tree()? != self.baseline.tree {
                bail!("宿主正文、模式、对象身份或清单已改变");
            }
            if self.snapshot.stable_tree()? != pending.snapshot {
                bail!("批准后快照发生变化");
            }
            for change in &pending.preview.changes {
                let (parent, name) = self
                    .baseline
                    .root
                    .parent(&change.path, &self.baseline.tree)?;
                verify_expected(&parent, &name, self.baseline.tree.files.get(&change.path))?;
            }
            Ok(())
        }
        fn stage(
            &self,
            pending: &Pending,
            recovery: &Recovery,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<()> {
            for (index, change) in pending.preview.changes.iter().enumerate() {
                cancellation_point(recovery, index, "before_staging", cancelled)?;
                if let Some(version) = &change.after {
                    let source = &pending.snapshot.files[&change.path];
                    let mut file = create_at(
                        &recovery.directory,
                        &CString::new(format!("new-{index}"))?,
                        0o600,
                    )?;
                    file.write_all(&source.body)?;
                    if let Some(before) = self.baseline.tree.files.get(&change.path) {
                        if unsafe { libc::fchown(file.as_raw_fd(), !0 as libc::uid_t, before.gid) }
                            != 0
                        {
                            return Err(std::io::Error::last_os_error().into());
                        }
                    }
                    if unsafe { libc::fchmod(file.as_raw_fd(), version.mode as libc::mode_t) } != 0
                    {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    file.sync_all()?;
                }
                recovery.transition(index, "staged")?;
            }
            recovery.directory.sync_all()?;
            Ok(())
        }

        fn apply_one(
            &self,
            index: usize,
            change: &FileChange,
            pending: &Pending,
            recovery: &Recovery,
            expected_host: &Tree,
            cancelled: &dyn Fn() -> bool,
        ) -> std::result::Result<OperationSuccess, OperationFailure> {
            let mut committed = false;
            let mut operation = || -> Result<OperationSuccess> {
                cancellation_point(recovery, index, "before_operation", cancelled)?;
                self.snapshot.validate()?;
                // 每项再次读快照版本。发布的字节始终来自批准时的内存，而非随后变化的路径。
                let (snapshot_parent, snapshot_name) =
                    self.snapshot.parent(&change.path, &pending.snapshot)?;
                verify_expected(
                    &snapshot_parent,
                    &snapshot_name,
                    pending.snapshot.files.get(&change.path),
                )?;
                let (parent, name) = self
                    .baseline
                    .root
                    .parent(&change.path, &self.baseline.tree)?;
                let original = expected_host.files.get(&change.path);
                verify_expected(&parent, &name, original)?;
                let old_name = CString::new(format!("old-{index}"))?;
                let new_name = CString::new(format!("new-{index}"))?;
                let staged = if let Some(version) = &change.after {
                    let staged = read_file(&recovery.directory, &new_name)?;
                    if staged.body != pending.snapshot.files[&change.path].body
                        || staged.mode != version.mode
                    {
                        bail!("待发布正文或模式已改变");
                    }
                    Some(staged)
                } else {
                    None
                };
                if original.is_none() {
                    recovery.transition(index, "before_publish")?;
                    #[cfg(test)]
                    run_test_hook(index, "before_publish");
                    cancellation_point(recovery, index, "before_publish", cancelled)?;
                    rename_exclusive(&recovery.directory, &new_name, &parent, &name)?;
                    committed = true;
                    #[cfg(test)]
                    run_test_hook(index, "after_publish");
                    parent.sync_all()?;
                    recovery.directory.sync_all()?;
                    self.baseline
                        .root
                        .parent(&change.path, &self.baseline.tree)?;
                    recovery.transition(index, "published")?;
                    return Ok((
                        None,
                        Some(verify_published(
                            &parent,
                            &name,
                            staged.as_ref().expect("创建必有正文"),
                        )?),
                        None,
                    ));
                }
                recovery.transition(index, "before_move_original")?;
                #[cfg(test)]
                run_test_hook(index, "before_move_original");
                cancellation_point(recovery, index, "before_move_original", cancelled)?;
                rename_exclusive(&parent, &name, &recovery.directory, &old_name)?;
                parent.sync_all()?;
                recovery.directory.sync_all()?;
                recovery.transition(index, "original_in_recovery")?;
                let old_path = recovery.path.join(format!("old-{index}"));
                let moved = read_file(&recovery.directory, &old_name)?;
                if !original.expect("已知原件").same_moved_object(&moved) {
                    bail!(
                        "取出的实际原件与批准基线不符，原件保存在 {}",
                        old_path.display()
                    );
                }
                self.baseline
                    .root
                    .parent(&change.path, &self.baseline.tree)?;
                if change.after.is_some() {
                    recovery.transition(index, "before_publish")?;
                    #[cfg(test)]
                    run_test_hook(index, "before_publish");
                    cancellation_point(recovery, index, "before_publish", cancelled)?;
                    rename_exclusive(&recovery.directory, &new_name, &parent, &name)?;
                }
                committed = true;
                #[cfg(test)]
                run_test_hook(index, "after_publish");
                parent.sync_all()?;
                recovery.directory.sync_all()?;
                self.baseline
                    .root
                    .parent(&change.path, &self.baseline.tree)?;
                recovery.transition(index, "published")?;
                let retained = read_file(&recovery.directory, &old_name)?;
                if !original.expect("已知原件").same_moved_object(&retained) {
                    bail!("保留原件在回写期间被并发写入");
                }
                Ok((
                    Some(old_path),
                    staged
                        .as_ref()
                        .map(|expected| verify_published(&parent, &name, expected))
                        .transpose()?,
                    Some(retained),
                ))
            };
            match operation() {
                Ok(value) => Ok(value),
                Err(error) => {
                    let old_path = recovery.path.join(format!("old-{index}"));
                    let old_name = CString::new(format!("old-{index}")).expect("内部名称无空字节");
                    let old_exists = match entry_stat(&recovery.directory, &old_name) {
                    Ok(value) => value.is_some(),
                    Err(stat_error) => return Err(OperationFailure { unknown: true, detail: format!("操作失败且无法核实恢复原件是否存在：{error:#}；核对失败：{stat_error:#}"), recovery_file: Some(old_path), restored_file: None }),
                };
                    if committed {
                        return Err(OperationFailure {
                            unknown: true,
                            detail: format!("文件操作已经发生，但后续同步或校验失败：{error:#}"),
                            recovery_file: old_exists.then_some(old_path),
                            restored_file: None,
                        });
                    }
                    if old_exists {
                        // 只向空缺原名排他恢复，绝不覆盖并发新建文件；恢复失败保留原件并记未知。
                        let mut restored_in_namespace = false;
                        let restored = self
                            .baseline
                            .root
                            .parent(&change.path, &self.baseline.tree)
                            .and_then(|(parent, name)| {
                                rename_exclusive(&recovery.directory, &old_name, &parent, &name)?;
                                restored_in_namespace = true;
                                parent.sync_all()?;
                                recovery.directory.sync_all()?;
                                read_file(&parent, &name)
                            });
                        match restored {
                        Ok(restored_file) => {
                            let journal = recovery.transition(index, "original_restored");
                            Err(OperationFailure { unknown: journal.is_err(), detail: format!("冲突，已排他恢复取出的原件：{error:#}{}", journal.err().map_or(String::new(), |e| format!("；恢复清单同步失败：{e:#}"))), recovery_file: None, restored_file: Some(Box::new(restored_file)) })
                        }
                        Err(restore_error) => Err(OperationFailure { unknown: true, detail: format!("冲突且恢复未确认；目录项已恢复={restored_in_namespace}，须核对原件与目标：{error:#}；恢复错误：{restore_error:#}"), recovery_file: (!restored_in_namespace).then_some(old_path), restored_file: None }),
                    }
                    } else {
                        Err(OperationFailure {
                            unknown: false,
                            detail: format!("未能应用：{error:#}"),
                            recovery_file: None,
                            restored_file: None,
                        })
                    }
                }
            }
        }
    }

    fn cancellation_point(
        recovery: &Recovery,
        index: usize,
        stage: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<()> {
        if cancelled() {
            recovery.transition(index, &format!("cancelled_{stage}"))?;
            bail!("用户已取消，在 {stage} 停止；不撤销已经完成的其它文件");
        }
        Ok(())
    }

    fn account_for_rename(tree: &mut Tree, moved: &FileState) {
        for file in tree.files.values_mut() {
            if file.identity == moved.identity {
                file.ctime = moved.ctime;
            }
        }
    }
    fn verify_published(parent: &File, name: &CStr, staged: &FileState) -> Result<FileState> {
        let published = read_file(parent, name)?;
        if !staged.same_moved_object(&published) {
            bail!("发布后的文件不再等于已批准正文、模式或新 inode");
        }
        Ok(published)
    }
    // 依次为恢复原件位置、发布后文件状态、已取出原件状态。
    type OperationSuccess = (Option<PathBuf>, Option<FileState>, Option<FileState>);
    struct OperationFailure {
        unknown: bool,
        detail: String,
        recovery_file: Option<PathBuf>,
        restored_file: Option<Box<FileState>>,
    }
    fn conflict_report(files: Vec<FileApplyResult>, detail: &str) -> ApplyReport {
        ApplyReport {
            outcome: ApplyOutcome::Conflict,
            files,
            recovery_directory: None,
            detail: detail.into(),
        }
    }
    struct Recovery {
        directory: File,
        path: PathBuf,
        manifest: RefCell<serde_json::Value>,
        sequence: Cell<u64>,
    }
    fn recovery_path(host: &Path) -> Result<PathBuf> {
        let parent = host.parent().context("不能为文件系统根建立回写恢复目录")?;
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        Ok(parent.join(format!(".agentguard-writeback-{}", hex_digest(&random))))
    }
    impl Recovery {
        fn create(root: &Root, preview: &Preview) -> Result<Self> {
            root.validate()?;
            let parent_path = root.path.parent().context("授权根没有父目录")?;
            if preview.recovery_directory.parent() != Some(parent_path) {
                bail!("恢复目录必须是宿主根的独立同级目录");
            }
            let (parent, ancestors) = open_absolute(parent_path)?;
            if ancestors != root.ancestors[..root.ancestors.len() - 1] {
                bail!("恢复目录的父对象改变");
            }
            if parent.metadata()?.dev() != root.directory.metadata()?.dev() {
                bail!("授权根与恢复目录不在同一文件系统，拒绝回写");
            }
            let c_name = CString::new(
                preview
                    .recovery_directory
                    .file_name()
                    .context("缺少恢复目录名")?
                    .as_bytes(),
            )?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let directory = open_at(&parent, &c_name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            if directory.metadata()?.dev() != root.directory.metadata()?.dev()
                || directory.metadata()?.mode() & 0o777 != 0o700
            {
                bail!("恢复目录文件系统或权限异常");
            }
            reject_extended_metadata(&directory)?;
            let manifest = serde_json::json!({"version":1,"preview_digest":preview.digest,"workspace_root":preview.workspace_root,"phase":"prepared","files":preview.changes.iter().enumerate().map(|(index,change)|serde_json::json!({"path":change.path,"kind":change.kind,"backup":change.before.as_ref().map(|_|format!("old-{index}")),"staged":change.after.as_ref().map(|_|format!("new-{index}")),"stage":"planned"})).collect::<Vec<_>>()});
            let recovery = Self {
                directory,
                path: preview.recovery_directory.clone(),
                manifest: RefCell::new(manifest),
                sequence: Cell::new(0),
            };
            recovery.persist()?;
            parent.sync_all()?;
            Ok(recovery)
        }
        fn transition(&self, index: usize, stage: &str) -> Result<()> {
            self.manifest.borrow_mut()["files"][index]["stage"] = stage.into();
            self.persist()
        }
        fn record_result(&self, index: usize, result: &FileApplyResult) -> Result<()> {
            self.manifest.borrow_mut()["files"][index]["result"] = serde_json::to_value(result)?;
            self.persist()
        }
        fn finish(&self, report: &ApplyReport) -> Result<()> {
            self.manifest.borrow_mut()["phase"] = "finished".into();
            self.manifest.borrow_mut()["report"] = serde_json::to_value(report)?;
            self.persist()
        }
        fn persist(&self) -> Result<()> {
            let sequence = self.sequence.get();
            self.sequence.set(sequence + 1);
            let name = CString::new(format!("manifest-next-{sequence}"))?;
            let mut file = create_at(&self.directory, &name, 0o600)?;
            file.write_all(&serde_json::to_vec_pretty(&*self.manifest.borrow())?)?;
            file.sync_all()?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    c"manifest.json".as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            self.directory.sync_all()?;
            Ok(())
        }
    }

    fn hex_digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    fn open_absolute(path: &Path) -> Result<(File, Vec<Identity>)> {
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut directory = unsafe { File::from_raw_fd(fd) };
        let mut ancestors = vec![Identity::of(&directory.metadata()?)];
        for component in path.components() {
            if let Component::Normal(name) = component {
                directory = open_at(
                    &directory,
                    &CString::new(name.as_bytes())?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                ancestors.push(Identity::of(&directory.metadata()?));
            }
        }
        Ok((directory, ancestors))
    }
    fn open_at(parent: &File, name: &CStr, flags: i32) -> Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn create_at(parent: &File, name: &CStr, mode: u32) -> Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn entry_stat(parent: &File, name: &CStr) -> Result<Option<libc::stat>> {
        let mut stat = std::mem::MaybeUninit::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error.into());
        }
        Ok(Some(unsafe { stat.assume_init() }))
    }
    fn read_file(parent: &File, name: &CStr) -> Result<FileState> {
        let mut file = open_at(parent, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let before = file.metadata()?;
        if !before.is_file() || before.mode() & 0o7000 != 0 {
            bail!("只允许没有特殊权限位的普通文件");
        }
        reject_extended_metadata(&file)?;
        if before.len() > MAX_FILE_BYTES as u64 {
            bail!("单文件超过 256 KiB，拒绝截断");
        }
        let mut body = Vec::new();
        (&mut file)
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        let after = file.metadata()?;
        if body.len() > MAX_FILE_BYTES
            || body.len() as u64 != before.len()
            || stamp(&before) != stamp(&after)
        {
            bail!("读取期间文件改变或超过限制");
        }
        Ok(FileState {
            identity: Identity::of(&after),
            mode: after.mode() & 0o7777,
            uid: after.uid(),
            gid: after.gid(),
            mtime: (after.mtime(), after.mtime_nsec()),
            ctime: (after.ctime(), after.ctime_nsec()),
            sha256: hex_digest(&body),
            body,
        })
    }
    fn reject_extended_metadata(file: &File) -> Result<()> {
        #[cfg(target_os = "macos")]
        let count = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
        #[cfg(target_os = "linux")]
        let count = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if count > 64 * 1024 {
            bail!("扩展属性名称列表超过限制");
        }
        if count > 0 {
            let mut names = vec![0u8; count as usize];
            #[cfg(target_os = "macos")]
            let length = unsafe {
                libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len(), 0)
            };
            #[cfg(target_os = "linux")]
            let length = unsafe {
                libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len())
            };
            if length < 0 || length as usize > names.len() {
                bail!("扩展属性列表在读取时改变");
            }
            names.truncate(length as usize);
            // macOS 自动生成的来源标记由系统重建；Linux 仍拒绝所有扩展属性。
            if names.split(|byte| *byte == 0).any(|name| {
                !(name.is_empty() || cfg!(target_os = "macos") && name == b"com.apple.provenance")
            }) {
                bail!("首版回写拒绝其它扩展属性或 ACL，避免替换时丢失安全元数据");
            }
        }
        #[cfg(target_os = "macos")]
        {
            // Darwin 的扩展 ACL 不属于 flistxattr；使用系统 acl.h 的三个原生入口检查。
            unsafe extern "C" {
                fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
                fn acl_get_entry(
                    acl: *mut libc::c_void,
                    entry_id: libc::c_int,
                    entry: *mut *mut libc::c_void,
                ) -> libc::c_int;
                fn acl_free(object: *mut libc::c_void) -> libc::c_int;
            }
            let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
            if acl.is_null() {
                // 在有效的已打开 fd 上，Darwin 对没有扩展 ACL 的对象返回 ENOENT。
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(error.into());
                }
            } else {
                let mut entry = std::ptr::null_mut();
                let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
                let error = std::io::Error::last_os_error();
                unsafe {
                    acl_free(acl);
                }
                if status == 0 {
                    bail!("首版回写拒绝扩展 ACL，避免原子替换丢失访问限制");
                }
                if error.raw_os_error() != Some(libc::EINVAL) {
                    return Err(error.into());
                }
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if unsafe { stat.assume_init() }.st_flags != 0 {
                bail!("首版回写拒绝带文件系统标志的对象");
            }
        }
        Ok(())
    }
    fn stamp(meta: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
        (
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mode(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
    }
    fn verify_expected(parent: &File, name: &CStr, expected: Option<&FileState>) -> Result<()> {
        match (expected, entry_stat(parent, name)?) {
            (None, None) => Ok(()),
            (Some(expected), Some(stat)) if stat.st_mode & libc::S_IFMT == libc::S_IFREG => {
                if read_file(parent, name)? == *expected {
                    Ok(())
                } else {
                    bail!("文件正文、模式或 inode 已改变")
                }
            }
            _ => bail!("文件不存在、类型改变或目标已被占用"),
        }
    }
    fn scan(root: &File) -> Result<Tree> {
        let mut tree = Tree {
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            links: BTreeMap::new(),
        };
        let mut bytes = 0;
        scan_directory(root, "", &mut tree, &mut bytes)?;
        Ok(tree)
    }
    fn scan_directory(
        directory: &File,
        relative: &str,
        tree: &mut Tree,
        bytes: &mut usize,
    ) -> Result<()> {
        let meta = directory.metadata()?;
        tree.directories.insert(
            relative.into(),
            DirectoryState {
                identity: Identity::of(&meta),
                mode: meta.mode() & 0o7777,
            },
        );
        for name in names(directory)? {
            if tree.files.len() + tree.directories.len() + tree.links.len() >= MAX_ENTRIES {
                bail!("起始清单超过 20000 个对象");
            }
            let display = name.to_str().context("首版回写仅支持 UTF-8 文件名")?;
            let path = if relative.is_empty() {
                display.into()
            } else {
                format!("{relative}/{display}")
            };
            let stat = entry_stat(directory, &name)?.context("枚举期间对象消失")?;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFREG => {
                    let file = read_file(directory, &name)?;
                    if file.identity.device != stat.st_dev as u64
                        || file.identity.inode != stat.st_ino as u64
                    {
                        bail!("枚举期间文件被置换");
                    }
                    *bytes += file.body.len();
                    if *bytes > MAX_BASELINE_BYTES {
                        bail!("起始清单正文超过 16 MiB");
                    }
                    tree.files.insert(path, file);
                }
                libc::S_IFDIR => {
                    let child = open_at(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    let identity = Identity::of(&child.metadata()?);
                    if identity.device != stat.st_dev as u64 || identity.inode != stat.st_ino as u64
                    {
                        bail!("枚举期间目录被置换");
                    }
                    scan_directory(&child, &path, tree, bytes)?;
                }
                libc::S_IFLNK => {
                    let mut target = vec![0u8; 16384];
                    let size = unsafe {
                        libc::readlinkat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            target.as_mut_ptr().cast(),
                            target.len(),
                        )
                    };
                    if size < 0 || size as usize == target.len() {
                        bail!("无法完整读取链接本身");
                    }
                    target.truncate(size as usize);
                    let after = entry_stat(directory, &name)?.context("链接消失")?;
                    if after.st_dev != stat.st_dev
                        || after.st_ino != stat.st_ino
                        || after.st_mode & libc::S_IFMT != libc::S_IFLNK
                    {
                        bail!("读取链接期间对象改变");
                    }
                    tree.links.insert(path, link_state(&after, target));
                }
                _ => bail!("工作区含管道、Socket、设备或其它特殊对象，回写不可用"),
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn link_state(stat: &libc::stat, target: Vec<u8>) -> LinkState {
        LinkState {
            identity: Identity {
                device: stat.st_dev as u64,
                inode: stat.st_ino,
            },
            target,
            mtime: (stat.st_mtime, stat.st_mtime_nsec),
            ctime: (stat.st_ctime, stat.st_ctime_nsec),
        }
    }
    #[cfg(target_os = "linux")]
    fn link_state(stat: &libc::stat, target: Vec<u8>) -> LinkState {
        LinkState {
            identity: Identity {
                device: stat.st_dev,
                inode: stat.st_ino,
            },
            target,
            mtime: (stat.st_mtime, stat.st_mtime_nsec),
            ctime: (stat.st_ctime, stat.st_ctime_nsec),
        }
    }
    fn names(directory: &File) -> Result<Vec<CString>> {
        let descriptor =
            open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?.into_raw_fd();
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            unsafe {
                libc::close(descriptor);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        let mut result = Vec::new();
        let error = loop {
            unsafe {
                *errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break unsafe { *errno_location() };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                result.push(name.to_owned());
            }
            if result.len() > MAX_ENTRIES {
                break libc::EFBIG;
            }
        };
        unsafe {
            libc::closedir(stream);
        }
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error).into());
        }
        result.sort();
        Ok(result)
    }
    #[cfg(target_os = "macos")]
    unsafe fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__error() }
    }
    #[cfg(target_os = "linux")]
    unsafe fn errno_location() -> *mut libc::c_int {
        unsafe { libc::__errno_location() }
    }
    fn rename_exclusive(
        source: &File,
        source_name: &CStr,
        target: &File,
        target_name: &CStr,
    ) -> Result<()> {
        #[cfg(target_os = "macos")]
        let status = unsafe {
            libc::renameatx_np(
                source.as_raw_fd(),
                source_name.as_ptr(),
                target.as_raw_fd(),
                target_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let status = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source.as_raw_fd(),
                source_name.as_ptr(),
                target.as_raw_fd(),
                target_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status != 0 {
            return Err(anyhow::Error::new(std::io::Error::last_os_error())
                .context("系统未能执行排他 rename；不会回退到可覆盖 rename"));
        }
        Ok(())
    }

    #[cfg(test)]
    type TestHook = Box<dyn FnMut(usize, &str)>;
    #[cfg(test)]
    thread_local! { static TEST_HOOK: std::cell::RefCell<Option<TestHook>> = std::cell::RefCell::new(None); }
    #[cfg(test)]
    fn run_test_hook(index: usize, stage: &str) {
        TEST_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(index, stage);
            }
        });
    }

    #[cfg(test)]
    mod tests {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/writeback/unit.rs"
        ));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;
    pub struct HostBaseline;
    pub struct WritebackEngine;
    impl HostBaseline {
        pub fn capture(_host_root: &std::path::Path) -> anyhow::Result<Self> {
            anyhow::bail!("当前宿主尚未实现安全回写，不能建立基线")
        }
    }
    impl WritebackEngine {
        pub fn attach(
            _baseline: HostBaseline,
            _snapshot_root: &std::path::Path,
        ) -> anyhow::Result<Self> {
            anyhow::bail!("当前宿主尚未实现安全回写")
        }
        pub fn preview(&mut self) -> anyhow::Result<Preview> {
            anyhow::bail!("当前宿主尚未实现安全回写，不能生成可批准预览")
        }
        pub fn apply(&mut self, digest: &str) -> ApplyReport {
            self.apply_with_cancel(digest, &|| false)
        }
        pub fn apply_with_cancel(
            &mut self,
            _digest: &str,
            _cancelled: &dyn Fn() -> bool,
        ) -> ApplyReport {
            ApplyReport {
                outcome: ApplyOutcome::Conflict,
                files: Vec::new(),
                recovery_directory: None,
                detail: "当前宿主尚未实现安全回写；没有执行文件操作".into(),
            }
        }
    }
}
pub use platform::{HostBaseline, WritebackEngine};
