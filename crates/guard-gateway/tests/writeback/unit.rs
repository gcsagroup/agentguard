use super::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;

struct Workspace {
    root: PathBuf,
    host: PathBuf,
    snapshot: PathBuf,
}
impl Workspace {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("agd-writeback-test-{}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let host = root.join("host");
        let snapshot = root.join("snapshot");
        fs::create_dir(&host).unwrap();
        fs::create_dir(&snapshot).unwrap();
        Self {
            root,
            host,
            snapshot,
        }
    }
    fn host_file(&self, name: &str, bytes: &[u8]) {
        let path = self.host.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn engine(&self) -> WritebackEngine {
        let baseline = HostBaseline::capture(&self.host).unwrap();
        copy_fixture(&self.host, &self.snapshot);
        WritebackEngine::attach(baseline, &self.snapshot).unwrap()
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn copy_fixture(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let name = target.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_symlink() {
            symlink(fs::read_link(entry.path()).unwrap(), name).unwrap();
        } else if kind.is_dir() {
            fs::create_dir(&name).unwrap();
            copy_fixture(&entry.path(), &name);
        } else {
            fs::copy(entry.path(), &name).unwrap();
            fs::set_permissions(name, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
struct Hook;
impl Hook {
    fn new(hook: impl FnMut(usize, &str) + 'static) -> Self {
        TEST_HOOK.with(|value| *value.borrow_mut() = Some(Box::new(hook)));
        Self
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        TEST_HOOK.with(|value| *value.borrow_mut() = None);
    }
}

#[test]
fn 创建修改删除和二进制预览保留完整内容与模式() {
    let work = Workspace::new();
    work.host_file("modify.txt", b"before");
    work.host_file("delete.txt", b"remove");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("modify.txt"), b"after\ncomplete").unwrap();
    fs::remove_file(work.snapshot.join("delete.txt")).unwrap();
    fs::write(work.snapshot.join("binary.bin"), [0, 255, 7]).unwrap();
    let preview = engine.preview().unwrap();
    assert_eq!(preview.changes.len(), 3);
    assert!(!preview.atomic);
    assert_eq!(preview.changes[0].after.as_ref().unwrap().text, None);
    assert_eq!(
        preview.changes[0].after.as_ref().unwrap().sha256,
        hex_digest(&[0, 255, 7])
    );
    let modified = &preview.changes[2];
    assert_eq!(
        modified.before.as_ref().unwrap().text.as_deref(),
        Some("before")
    );
    assert_eq!(
        modified.after.as_ref().unwrap().text.as_deref(),
        Some("after\ncomplete")
    );
    assert_eq!(modified.after.as_ref().unwrap().mode, 0o644);
    assert!(!preview.recovery_directory.starts_with(&work.host));
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Applied, "{report:?}");
    assert_eq!(
        fs::read(work.host.join("modify.txt")).unwrap(),
        b"after\ncomplete"
    );
    assert!(!work.host.join("delete.txt").exists());
    assert_eq!(fs::read(work.host.join("binary.bin")).unwrap(), [0, 255, 7]);
    let recovery = report.recovery_directory.unwrap();
    assert_eq!(fs::metadata(&recovery).unwrap().mode() & 0o777, 0o700);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(recovery.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["preview_digest"], preview.digest);
    assert_eq!(manifest["phase"], "finished");
    assert_eq!(manifest["report"]["outcome"], "applied");
    assert_eq!(
        fs::read(report.files[2].recovery_file.as_ref().unwrap()).unwrap(),
        b"before"
    );
}

#[test]
fn 完整成功后可继续第二轮且旧摘要不能重放() {
    let work = Workspace::new();
    work.host_file("a", b"one");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"two").unwrap();
    let first = engine.preview().unwrap();
    assert_eq!(engine.apply(&first.digest).outcome, ApplyOutcome::Applied);
    assert_eq!(engine.apply(&first.digest).outcome, ApplyOutcome::Conflict);
    fs::write(work.snapshot.join("a"), b"three").unwrap();
    let second = engine.preview().unwrap();
    assert_eq!(
        second.changes[0].before.as_ref().unwrap().text.as_deref(),
        Some("two")
    );
    assert_eq!(engine.apply(&second.digest).outcome, ApplyOutcome::Applied);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"three");
}

#[test]
fn 未变快照没有虚假的权限差异且空预览后仍可继续() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    let preview = engine.preview().unwrap();
    assert!(preview.changes.is_empty());
    assert_eq!(engine.apply(&preview.digest).outcome, ApplyOutcome::Applied);
    fs::write(work.snapshot.join("a"), b"next").unwrap();
    assert_eq!(engine.preview().unwrap().changes.len(), 1);
}

#[test]
fn 宿主编辑使整批预检失败且其它文件不变() {
    let work = Workspace::new();
    work.host_file("a", b"a");
    work.host_file("b", b"b");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"new-a").unwrap();
    fs::write(work.snapshot.join("b"), b"new-b").unwrap();
    let preview = engine.preview().unwrap();
    fs::write(work.host.join("b"), b"human").unwrap();
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Conflict);
    assert!(report.recovery_directory.is_none());
    assert!(report
        .files
        .iter()
        .all(|f| f.state == FileApplyState::NotApplied));
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"a");
    assert_eq!(fs::read(work.host.join("b")).unwrap(), b"human");
}

#[test]
fn 宿主同字节新inode仍冲突() {
    let work = Workspace::new();
    work.host_file("a", b"same");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"new").unwrap();
    let preview = engine.preview().unwrap();
    fs::rename(work.host.join("a"), work.root.join("old-inode")).unwrap();
    work.host_file("a", b"same");
    assert_eq!(
        engine.apply(&preview.digest).outcome,
        ApplyOutcome::Conflict
    );
}

#[test]
fn 宿主mode变化与批准后快照变化分别拒绝() {
    for snapshot_change in [false, true] {
        let work = Workspace::new();
        work.host_file("a", b"base");
        let mut engine = work.engine();
        fs::write(work.snapshot.join("a"), b"new").unwrap();
        let preview = engine.preview().unwrap();
        if snapshot_change {
            fs::write(work.snapshot.join("a"), b"changed-after-approval").unwrap();
        } else {
            fs::set_permissions(work.host.join("a"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            engine.apply(&preview.digest).outcome,
            ApplyOutcome::Conflict
        );
        assert_eq!(fs::read(work.host.join("a")).unwrap(), b"base");
    }
}

#[test]
fn 摘要不匹配不写文件() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"new").unwrap();
    engine.preview().unwrap();
    assert_eq!(engine.apply("wrong-digest").outcome, ApplyOutcome::Conflict);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"base");
}

#[test]
fn 授权根及内部父目录被置换时拒绝() {
    for replace_root in [false, true] {
        let work = Workspace::new();
        work.host_file("dir/a", b"base");
        let mut engine = work.engine();
        fs::write(work.snapshot.join("dir/a"), b"new").unwrap();
        let preview = engine.preview().unwrap();
        let victim = if replace_root {
            work.host.clone()
        } else {
            work.host.join("dir")
        };
        fs::rename(&victim, work.root.join("saved-directory")).unwrap();
        fs::create_dir(&victim).unwrap();
        assert_eq!(
            engine.apply(&preview.digest).outcome,
            ApplyOutcome::Conflict
        );
        assert_eq!(
            fs::read(work.root.join("saved-directory").join(if replace_root {
                "dir/a"
            } else {
                "a"
            }))
            .unwrap(),
            b"base"
        );
    }
}

#[test]
fn 已有链接不跟随且保持原样时不妨碍其它文件() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    fs::write(work.root.join("outside"), b"outside").unwrap();
    symlink("../outside", work.host.join("link")).unwrap();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"new").unwrap();
    let preview = engine.preview().unwrap();
    assert_eq!(preview.changes.len(), 1);
    assert_eq!(engine.apply(&preview.digest).outcome, ApplyOutcome::Applied);
    assert_eq!(fs::read(work.root.join("outside")).unwrap(), b"outside");
}

#[test]
fn 末级链接和父级链接变化都拒绝且不读写外部标记() {
    for parent_link in [false, true] {
        let work = Workspace::new();
        work.host_file("dir/a", b"base");
        fs::write(work.root.join("outside"), b"outside").unwrap();
        let mut engine = work.engine();
        if parent_link {
            fs::remove_dir_all(work.snapshot.join("dir")).unwrap();
            symlink(&work.root, work.snapshot.join("dir")).unwrap();
        } else {
            fs::remove_file(work.snapshot.join("dir/a")).unwrap();
            symlink(work.root.join("outside"), work.snapshot.join("dir/a")).unwrap();
        }
        assert!(engine.preview().is_err());
        assert_eq!(fs::read(work.root.join("outside")).unwrap(), b"outside");
    }
}

#[test]
fn 目录创建删除及类型变化拒绝() {
    for case in [0, 1, 2] {
        let work = Workspace::new();
        work.host_file("dir/a", b"base");
        let mut engine = work.engine();
        match case {
            0 => fs::create_dir(work.snapshot.join("new-dir")).unwrap(),
            1 => fs::remove_dir_all(work.snapshot.join("dir")).unwrap(),
            _ => {
                fs::remove_dir_all(work.snapshot.join("dir")).unwrap();
                fs::write(work.snapshot.join("dir"), b"changed-type").unwrap();
            }
        }
        assert!(engine.preview().is_err());
    }
}

#[test]
fn 特殊文件拒绝且不阻塞读取() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    let name = CString::new(work.snapshot.join("pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(engine.preview().is_err());
}

#[test]
fn 超过单文件正文总量或变更数量均明确失败() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("large"), vec![1; MAX_FILE_BYTES + 1]).unwrap();
    assert!(engine.preview().is_err());
    fs::remove_file(work.snapshot.join("large")).unwrap();
    for index in 0..5 {
        fs::write(
            work.snapshot.join(format!("large-{index}")),
            vec![1; MAX_FILE_BYTES],
        )
        .unwrap();
    }
    assert!(engine.preview().is_err());
    for index in 0..5 {
        fs::remove_file(work.snapshot.join(format!("large-{index}"))).unwrap();
    }
    for index in 0..101 {
        fs::write(work.snapshot.join(format!("empty-{index}")), []).unwrap();
    }
    assert!(engine.preview().is_err());
}

#[test]
fn 修改共享inode时原子替换不改变外部硬链接() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    fs::hard_link(work.host.join("a"), work.root.join("outside-hardlink")).unwrap();
    let mut engine = work.engine();
    let old_inode = fs::metadata(work.host.join("a")).unwrap().ino();
    fs::write(work.snapshot.join("a"), b"new").unwrap();
    let preview = engine.preview().unwrap();
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Applied, "{report:?}");
    assert_eq!(
        fs::read(work.root.join("outside-hardlink")).unwrap(),
        b"base"
    );
    assert_ne!(fs::metadata(work.host.join("a")).unwrap().ino(), old_inode);
    assert_eq!(
        fs::metadata(report.files[0].recovery_file.as_ref().unwrap())
            .unwrap()
            .ino(),
        old_inode
    );
}

#[test]
fn 同一工作区两个硬链接可依次替换而不误报工具自身ctime变化() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    fs::hard_link(work.host.join("a"), work.host.join("b")).unwrap();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"new-a").unwrap();
    fs::write(work.snapshot.join("b"), b"new-b").unwrap();
    let preview = engine.preview().unwrap();
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Applied, "{report:?}");
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"new-a");
    assert_eq!(fs::read(work.host.join("b")).unwrap(), b"new-b");
    assert!(engine.preview().unwrap().changes.is_empty());
}

#[test]
fn 发布后被并发修改不能吸收为已批准结果() {
    let work = Workspace::new();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"approved").unwrap();
    let preview = engine.preview().unwrap();
    let target = work.host.join("a");
    let _hook = Hook::new(move |_, stage| {
        if stage == "after_publish" {
            fs::write(&target, b"concurrent").unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Unknown);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"concurrent");
}

#[test]
fn 新建的排他发布不覆盖检查后并发创建() {
    let work = Workspace::new();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("new"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let target = work.host.join("new");
    let _hook = Hook::new(move |_, stage| {
        if stage == "before_publish" {
            fs::write(&target, b"concurrent").unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Conflict);
    assert_eq!(fs::read(work.host.join("new")).unwrap(), b"concurrent");
}

#[test]
fn 取出原件前发生同名置换可检出并恢复并发内容() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let target = work.host.join("a");
    let saved = work.root.join("concurrent-saved");
    let _hook = Hook::new(move |_, stage| {
        if stage == "before_move_original" {
            fs::rename(&target, &saved).unwrap();
            fs::write(&target, b"concurrent").unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Conflict, "{report:?}");
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"concurrent");
    assert_eq!(
        fs::read(work.root.join("concurrent-saved")).unwrap(),
        b"base"
    );
}

#[test]
fn 原件取出后目的路径被占用则保留两份并报告未知() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let target = work.host.join("a");
    let _hook = Hook::new(move |_, stage| {
        if stage == "before_publish" {
            fs::write(&target, b"concurrent").unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Unknown);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"concurrent");
    assert_eq!(
        fs::read(report.files[0].recovery_file.as_ref().unwrap()).unwrap(),
        b"base"
    );
}

#[test]
fn 多文件中途失败明确部分完成且不回滚先前文件() {
    let work = Workspace::new();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent-a").unwrap();
    fs::write(work.snapshot.join("b"), b"agent-b").unwrap();
    let preview = engine.preview().unwrap();
    let target = work.host.join("b");
    let _hook = Hook::new(move |index, stage| {
        if index == 1 && stage == "before_publish" {
            fs::write(&target, b"concurrent-b").unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Partial);
    assert_eq!(report.files[0].state, FileApplyState::Applied);
    assert_eq!(report.files[1].state, FileApplyState::Conflict);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"agent-a");
    assert_eq!(fs::read(work.host.join("b")).unwrap(), b"concurrent-b");
}

#[test]
fn 发布后根被移动报告未知而不声称零副作用() {
    let work = Workspace::new();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let root = work.host.clone();
    let moved = work.root.join("moved-host");
    let _hook = Hook::new(move |_, stage| {
        if stage == "after_publish" {
            fs::rename(&root, &moved).unwrap();
            fs::create_dir(&root).unwrap();
        }
    });
    let report = engine.apply(&preview.digest);
    assert_eq!(report.outcome, ApplyOutcome::Unknown);
    assert_eq!(fs::read(work.root.join("moved-host/a")).unwrap(), b"agent");
}

#[test]
fn 开始前取消没有文件副作用并可重新预览() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let report = engine.apply_with_cancel(&preview.digest, &|| true);
    assert_eq!(report.outcome, ApplyOutcome::Conflict);
    assert!(report.recovery_directory.is_none());
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"base");
    assert!(engine.preview().is_ok());
}

#[test]
fn 备份前取消保留原文件并在清单中记录阶段() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let _hook = Hook::new(move |_, stage| {
        if stage == "before_move_original" {
            signal.store(true, Ordering::SeqCst);
        }
    });
    let report = engine.apply_with_cancel(&preview.digest, &|| cancelled.load(Ordering::SeqCst));
    assert_eq!(report.outcome, ApplyOutcome::Conflict);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"base");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(report.recovery_directory.unwrap().join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["files"][0]["stage"],
        "cancelled_before_move_original"
    );
}

#[test]
fn 取出原件后取消会排他恢复而不应用新正文() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent").unwrap();
    let preview = engine.preview().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let _hook = Hook::new(move |_, stage| {
        if stage == "before_publish" {
            signal.store(true, Ordering::SeqCst);
        }
    });
    let report = engine.apply_with_cancel(&preview.digest, &|| cancelled.load(Ordering::SeqCst));
    assert_eq!(report.outcome, ApplyOutcome::Conflict, "{report:?}");
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"base");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(report.recovery_directory.unwrap().join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["files"][0]["stage"], "original_restored");
    assert!(
        engine.preview().is_ok(),
        "工具自身恢复导致的ctime变化不应阻断下一次预览"
    );
}

#[test]
fn 第二项取消明确部分完成并保留首项结果() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let work = Workspace::new();
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"agent-a").unwrap();
    fs::write(work.snapshot.join("b"), b"agent-b").unwrap();
    let preview = engine.preview().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let _hook = Hook::new(move |index, stage| {
        if index == 1 && stage == "before_operation" {
            signal.store(true, Ordering::SeqCst);
        }
    });
    let report = engine.apply_with_cancel(&preview.digest, &|| cancelled.load(Ordering::SeqCst));
    assert_eq!(report.outcome, ApplyOutcome::Partial);
    assert_eq!(fs::read(work.host.join("a")).unwrap(), b"agent-a");
    assert!(!work.host.join("b").exists());
    assert_eq!(report.files[0].state, FileApplyState::Applied);
}

#[test]
fn 额外扩展属性拒绝而系统来源属性不影响普通文件() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    assert!(HostBaseline::capture(&work.host).is_ok());
    let file = File::open(work.host.join("a")).unwrap();
    let value = b"AGD_SYNTHETIC_METADATA";
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"user.agd.fixture".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            0,
        )
    };
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"user.agd.fixture".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(status, 0);
    assert!(HostBaseline::capture(&work.host).is_err());
}

#[test]
fn 快照预检拒绝后可用新差异重新批准() {
    let work = Workspace::new();
    work.host_file("a", b"base");
    let mut engine = work.engine();
    fs::write(work.snapshot.join("a"), b"first").unwrap();
    let first = engine.preview().unwrap();
    fs::write(work.snapshot.join("a"), b"second").unwrap();
    assert_eq!(engine.apply(&first.digest).outcome, ApplyOutcome::Conflict);
    let second = engine.preview().unwrap();
    assert_eq!(
        second.changes[0].after.as_ref().unwrap().text.as_deref(),
        Some("second")
    );
    assert_eq!(engine.apply(&second.digest).outcome, ApplyOutcome::Applied);
}

#[test]
fn crash_worker() {
    let Ok(root) = std::env::var("AGD_WB_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    assert_eq!(
        fs::read(root.join("allow-crash-worker")).unwrap(),
        b"AGD_SYNTHETIC_CRASH_TEST"
    );
    let baseline = HostBaseline::capture(&root.join("host")).unwrap();
    let mut engine = WritebackEngine::attach(baseline, &root.join("snapshot")).unwrap();
    fs::write(root.join("snapshot/a"), b"approved").unwrap();
    let preview = engine.preview().unwrap();
    let _hook = Hook::new(|_, stage| {
        if stage == "before_publish" {
            unsafe {
                libc::raise(libc::SIGKILL);
            }
        }
    });
    engine.apply(&preview.digest);
    panic!("子进程应该已被强制终止");
}

#[test]
fn 崩溃后清单原件和已批准正文均可定位() {
    let work = Workspace::new();
    work.host_file("a", b"original");
    copy_fixture(&work.host, &work.snapshot);
    fs::write(
        work.root.join("allow-crash-worker"),
        b"AGD_SYNTHETIC_CRASH_TEST",
    )
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "writeback::platform::tests::crash_worker",
            "--nocapture",
        ])
        .env("AGD_WB_CRASH_ROOT", &work.root)
        .output()
        .unwrap();
    assert!(!output.status.success(), "{:?}", output);
    let recovery = fs::read_dir(&work.root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".agentguard-writeback-")
        })
        .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(recovery.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["files"][0]["stage"], "before_publish");
    assert_eq!(manifest["files"][0]["path"], "a");
    assert!(!work.host.join("a").exists());
    assert_eq!(fs::read(recovery.join("old-0")).unwrap(), b"original");
    assert_eq!(fs::read(recovery.join("new-0")).unwrap(), b"approved");
}
