use super::*;
use std::os::unix::ffi::OsStrExt;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "agd-package-test-{}",
            crate::browser_bridge::token()
        ));
        private_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
    fn source(&self) -> PathBuf {
        let path = self.0.join("source");
        private_dir(&path).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn 完整复制包内文件链接和空目录并绑定内容而非原路径() {
    let fixture = Fixture::new();
    let source = fixture.source();
    private_dir(&source.join("dist")).unwrap();
    private_dir(&source.join("empty")).unwrap();
    private_dir(&source.join("bin")).unwrap();
    fs::write(source.join("dist/main.js"), "console.log('原版');\n").unwrap();
    fs::write(source.join("package.json"), "{}\n").unwrap();
    std::os::unix::fs::symlink("../dist/main.js", source.join("bin/service")).unwrap();
    let frozen = FrozenPackage::freeze(&source).unwrap();
    assert_eq!(frozen.file_count(), 2);
    assert_eq!(frozen.entries.len(), 6);
    assert!(frozen.contains_entrypoint("dist/main.js"));
    for path in [
        "bin/service",
        "/dist/main.js",
        "../main.js",
        "dist/../package.json",
        "empty",
    ] {
        assert!(!frozen.contains_entrypoint(path), "{path}");
    }
    assert_eq!(
        fs::read_to_string(frozen.path().join("bin/service")).unwrap(),
        "console.log('原版');\n"
    );
    fs::write(source.join("dist/main.js"), "console.log('替换版');\n").unwrap();
    assert!(frozen.verify().is_ok());
    assert_eq!(
        fs::read_to_string(frozen.path().join("dist/main.js")).unwrap(),
        "console.log('原版');\n"
    );
    let replacement = FrozenPackage::freeze(&source).unwrap();
    assert_ne!(frozen.sha256(), replacement.sha256());
    let private = frozen.root.clone();
    drop(frozen);
    assert!(!private.exists());
}

#[test]
fn 摘要稳定且可执行位链接目标和空目录变化都能识别() {
    let fixture = Fixture::new();
    let first = fixture.source();
    fs::write(first.join("a.js"), b"A").unwrap();
    fs::write(first.join("b.js"), b"B").unwrap();
    std::os::unix::fs::symlink("a.js", first.join("launch")).unwrap();
    let a = FrozenPackage::freeze(&first).unwrap();
    let b = FrozenPackage::freeze(&first).unwrap();
    assert_eq!(a.sha256(), b.sha256());
    readonly(&first.join("a.js"), 0o700).unwrap();
    let exec = FrozenPackage::freeze(&first).unwrap();
    assert_ne!(exec.sha256(), a.sha256());
    fs::remove_file(first.join("launch")).unwrap();
    std::os::unix::fs::symlink("b.js", first.join("launch")).unwrap();
    let link = FrozenPackage::freeze(&first).unwrap();
    assert_ne!(exec.sha256(), link.sha256());
    private_dir(&first.join("new-empty")).unwrap();
    let directory = FrozenPackage::freeze(&first).unwrap();
    assert_ne!(directory.sha256(), link.sha256());
}

#[test]
fn 冻结副本的字节权限新增条目和链接变化均拒绝() {
    for change in ["bytes", "mode", "entry", "link"] {
        let fixture = Fixture::new();
        let source = fixture.source();
        fs::write(source.join("main.js"), "original").unwrap();
        std::os::unix::fs::symlink("main.js", source.join("launch")).unwrap();
        let frozen = FrozenPackage::freeze(&source).unwrap();
        let file = frozen.path().join("main.js");
        match change {
            "bytes" => {
                readonly(&file, 0o600).unwrap();
                fs::write(&file, "replaced").unwrap();
                readonly(&file, 0o400).unwrap();
            }
            "mode" => readonly(&file, 0o600).unwrap(),
            "entry" => {
                readonly(&frozen.path(), 0o700).unwrap();
                fs::write(frozen.path().join("extra.js"), "new").unwrap();
                readonly(&frozen.path(), 0o500).unwrap();
            }
            "link" => {
                readonly(&frozen.path(), 0o700).unwrap();
                fs::remove_file(frozen.path().join("launch")).unwrap();
                std::os::unix::fs::symlink("/etc/hostname", frozen.path().join("launch")).unwrap();
                readonly(&frozen.path(), 0o500).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(frozen.verify().is_err(), "{change}");
        let root = frozen.root.clone();
        drop(frozen);
        assert!(!root.exists(), "{change} 清理私有副本");
    }
}

#[test]
fn 拒绝包外链接悬空目录链接与链接链而不静默跳过() {
    for target in [
        "/etc/hostname",
        "../outside",
        "missing",
        "dir",
        "other",
        "file/../file",
    ] {
        let fixture = Fixture::new();
        let source = fixture.source();
        fs::write(source.join("file"), "synthetic").unwrap();
        private_dir(&source.join("dir")).unwrap();
        std::os::unix::fs::symlink("file", source.join("other")).unwrap();
        std::os::unix::fs::symlink(target, source.join("bad")).unwrap();
        assert!(FrozenPackage::freeze(&source).is_err(), "{target}");
    }
}

#[test]
fn 拒绝用户目录链接硬链接控制套接字和管道() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::write(source.join("main.js"), "synthetic").unwrap();
    let alias = fixture.0.join("alias");
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(FrozenPackage::freeze(&alias).is_err());
    fs::hard_link(source.join("main.js"), source.join("hard")).unwrap();
    assert!(FrozenPackage::freeze(&source).is_err());
    fs::remove_file(source.join("hard")).unwrap();
    // AF_UNIX 路径受长度限制，使用包根句柄下的短文件名建立 FIFO 即可覆盖特殊文件。
    let fifo = CString::new(source.join("control.pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(FrozenPackage::freeze(&source).is_err());
    fs::remove_file(source.join("control.pipe")).unwrap();
    assert!(FrozenPackage::freeze(&source).is_ok());
    // 用短的自有目录满足 macOS AF_UNIX 路径上限，实际覆盖控制 Socket。
    let socket_root = Path::new("/tmp").join(format!(
        "agd-pkg-socket-{}",
        &crate::browser_bridge::token()[..16]
    ));
    private_dir(&socket_root).unwrap();
    let socket_root = socket_root.canonicalize().unwrap();
    let socket = std::os::unix::net::UnixListener::bind(socket_root.join("control.sock")).unwrap();
    assert!(FrozenPackage::freeze(&socket_root).is_err());
    drop(socket);
    fs::remove_dir_all(socket_root).unwrap();
}

#[test]
fn 拒绝凭据路径及实际深度和大小超限() {
    let fixture = Fixture::new();
    let source = fixture.source();
    fs::write(source.join(".npmrc"), "SYNTHETIC_TOKEN").unwrap();
    assert!(FrozenPackage::freeze(&source).is_err());
    fs::remove_file(source.join(".npmrc")).unwrap();
    let huge = File::create(source.join("huge")).unwrap();
    huge.set_len(MAX_BYTES + 1).unwrap();
    assert!(FrozenPackage::freeze(&source).is_err());
    fs::remove_file(source.join("huge")).unwrap();
    let mut deep = source.clone();
    for _ in 0..=MAX_DEPTH {
        deep.push("d");
        private_dir(&deep).unwrap();
    }
    assert!(FrozenPackage::freeze(&source).is_err());
}
