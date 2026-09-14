//! 第三方服务包的完整字节副本。摘要只标识实际冻结内容，不授予认可或执行权限。
use anyhow::{bail, ensure, Context, Result};
use guard_schema::Sha256Digest;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::MetadataExt, fs::PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_ENTRIES: usize = 20_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_PATH: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Entry {
    Directory,
    File {
        bytes: u64,
        executable: bool,
        sha256: Sha256Digest,
    },
    Symlink {
        target: String,
    },
}

/// 私有冻结副本的所有者。生命周期覆盖实际容器，避免服务运行时包目录被提前清理。
pub struct FrozenPackage {
    root: PathBuf,
    entries: BTreeMap<String, Entry>,
    sha256: Sha256Digest,
    bytes: u64,
    retained: AtomicBool,
}
impl FrozenPackage {
    /// 只接受明确目录；不跟随宿主任意目录链接，不省略任何包内条目。
    pub fn freeze(source: &Path) -> Result<Self> {
        validate_root(source)?;
        let physical = source.canonicalize()?;
        ensure!(
            guard_schema::paths::dealias_platform_volumes(&physical)
                == guard_schema::paths::dealias_platform_volumes(source),
            "服务包根目录经过了未授权链接"
        );
        let directory = crate::isolation::open_absolute_dir(&physical)?;
        let root = std::env::temp_dir().join(format!(
            "agentguard-mcp-package-{}",
            crate::browser_bridge::token()
        ));
        private_dir(&root)?;
        let root = root.canonicalize()?;
        let mut package = Self {
            root,
            entries: BTreeMap::new(),
            sha256: crate::tool_registry::digest(&[]),
            bytes: 0,
            retained: AtomicBool::new(false),
        };
        let payload = package.path();
        private_dir(&payload)?;
        let mut scan = Scan::default();
        // 错误路径也由 package 的 Drop 清理；源目录始终只读。
        let result = scan.directory(&directory, Path::new(""), Some(&payload), false, 0);
        package.entries = scan.entries;
        package.bytes = scan.bytes;
        result?;
        validate_links(&package.entries)?;
        readonly(&payload, 0o500)?;
        package.sha256 = tree_digest(&package.entries)?;
        package.verify()?;
        Ok(package)
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
    pub fn file_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| matches!(e, Entry::File { .. }))
            .count()
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn manifest(&self) -> serde_json::Value {
        serde_json::json!({"version":1,"sha256":self.sha256,"bytes":self.bytes,"entries":self.entries})
    }
    pub(crate) fn path(&self) -> PathBuf {
        self.root.join("payload")
    }
    pub(crate) fn retain_for_recovery(&self) {
        self.retained.store(true, Ordering::SeqCst);
    }
    /// 容器清理未知时保留包；只供宿主记录和人工核查，不应传给模型。
    pub fn retained_path(&self) -> Option<&Path> {
        self.retained
            .load(Ordering::SeqCst)
            .then_some(self.root.as_path())
    }

    /// 正式入口必须是已冻结的普通文件，不能借入口链接或参数改变 Node 启动方式。
    pub fn contains_entrypoint(&self, path: &str) -> bool {
        valid_relative(Path::new(path))
            && matches!(self.entries.get(path), Some(Entry::File { .. }))
    }

    /// 启动前重新核对私有副本的全部字节、链接、可执行位及只读权限。
    pub fn verify(&self) -> Result<()> {
        let directory = crate::isolation::open_absolute_dir(&self.path())?;
        let mut scan = Scan::default();
        scan.directory(&directory, Path::new(""), None, true, 0)?;
        validate_links(&scan.entries)?;
        ensure!(
            scan.entries == self.entries
                && scan.bytes == self.bytes
                && tree_digest(&scan.entries)? == self.sha256,
            "冻结服务包已改变，不能沿用旧身份"
        );
        Ok(())
    }
}
impl Drop for FrozenPackage {
    fn drop(&mut self) {
        if self.retained.load(Ordering::SeqCst) {
            return;
        }
        // 仅操作本对象创建的随机私有目录；通过不跟随链接的目录句柄恢复删除权限。
        for (relative, entry) in &self.entries {
            if matches!(entry, Entry::Directory) {
                if let Ok(directory) =
                    crate::isolation::open_absolute_dir(&self.path().join(relative))
                {
                    let _ = directory.set_permissions(fs::Permissions::from_mode(0o700));
                }
            }
        }
        if let Ok(directory) = crate::isolation::open_absolute_dir(&self.path()) {
            let _ = directory.set_permissions(fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct Scan {
    entries: BTreeMap<String, Entry>,
    bytes: u64,
}
impl Scan {
    fn directory(
        &mut self,
        source: &File,
        relative: &Path,
        destination: Option<&Path>,
        verifying: bool,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "服务包目录深度超过 {MAX_DEPTH}");
        let before = source.metadata()?;
        ensure!(before.is_dir(), "服务包目录类型改变");
        if verifying {
            verify_mode(&before, 0o500)?;
        }
        let names = directory_names(source, MAX_ENTRIES.saturating_sub(self.entries.len()))?;
        for name in names {
            let name_text = name.to_str().context("服务包路径必须是 UTF-8")?;
            ensure!(
                !name_text.chars().any(char::is_control),
                "服务包路径含控制字符"
            );
            let child_path = relative.join(name_text);
            let key = child_path
                .to_str()
                .context("服务包路径必须是 UTF-8")?
                .to_owned();
            if let Some(reason) = guard_schema::paths::sensitive_target_with_home(
                &child_path,
                guard_schema::paths::PathIntent::Read,
                None,
            ) {
                bail!("服务包包含敏感路径：{reason}");
            }
            ensure!(
                key.len() <= MAX_PATH && self.entries.len() < MAX_ENTRIES,
                "服务包路径或条目数量超限"
            );
            ensure!(
                !matches!(
                    name_text,
                    ".ssh" | ".aws" | ".gnupg" | ".kube" | ".docker" | ".npmrc" | ".netrc" | ".env"
                ),
                "服务包包含凭据目录或配置"
            );
            let stat = stat_at(source, &name)?;
            let dest = destination.map(|p| p.join(name_text));
            let entry = match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let child = open_at(source, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    ensure!(
                        same_inode(&stat, &child.metadata()?),
                        "服务包目录在打开时被替换"
                    );
                    if let Some(dest) = &dest {
                        private_dir(dest)?;
                    }
                    // 先登记父目录，确保错误路径能恢复权限并完整清理。
                    self.entries.insert(key.clone(), Entry::Directory);
                    self.directory(&child, &child_path, dest.as_deref(), verifying, depth + 1)?;
                    if let Some(dest) = &dest {
                        readonly(dest, 0o500)?;
                    }
                    Entry::Directory
                }
                libc::S_IFREG => {
                    let mut input = open_at(source, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
                    let metadata = input.metadata()?;
                    ensure!(
                        metadata.is_file() && same_inode(&stat, &metadata),
                        "服务包文件在打开时被替换"
                    );
                    ensure!(metadata.nlink() == 1, "服务包不接受硬链接文件");
                    let executable = metadata.mode() & 0o111 != 0;
                    if verifying {
                        verify_mode(&metadata, if executable { 0o500 } else { 0o400 })?;
                    }
                    ensure!(
                        metadata.len() <= MAX_BYTES.saturating_sub(self.bytes),
                        "服务包总大小超过 512 MiB"
                    );
                    let mut output = match &dest {
                        Some(path) => Some(
                            fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(path)?,
                        ),
                        None => None,
                    };
                    let mut hash = Sha256::new();
                    let mut copied = 0u64;
                    // 缓冲区放堆上，深目录不能让每层递归保留 64 KiB 的栈帧。
                    let mut buffer = vec![0u8; 64 * 1024];
                    loop {
                        let n = input.read(&mut buffer)?;
                        if n == 0 {
                            break;
                        }
                        copied += n as u64;
                        ensure!(
                            copied <= metadata.len()
                                && copied <= MAX_BYTES.saturating_sub(self.bytes),
                            "服务包文件读取期间增长"
                        );
                        hash.update(&buffer[..n]);
                        if let Some(output) = &mut output {
                            output.write_all(&buffer[..n])?;
                        }
                    }
                    ensure!(
                        copied == metadata.len() && unchanged(&metadata, &input.metadata()?),
                        "服务包文件在冻结期间改变"
                    );
                    if let Some(output) = output {
                        output.set_permissions(fs::Permissions::from_mode(if executable {
                            0o500
                        } else {
                            0o400
                        }))?;
                    }
                    self.bytes += copied;
                    Entry::File {
                        bytes: copied,
                        executable,
                        sha256: Sha256Digest::new(format!("{:x}", hash.finalize()))?,
                    }
                }
                libc::S_IFLNK => {
                    let mut buffer = [0u8; MAX_PATH + 1];
                    let n = unsafe {
                        libc::readlinkat(
                            source.as_raw_fd(),
                            name.as_ptr(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                        )
                    };
                    ensure!(
                        n > 0 && (n as usize) < buffer.len(),
                        "服务包链接目标无效或超限"
                    );
                    let target = std::str::from_utf8(&buffer[..n as usize])?.to_owned();
                    ensure!(
                        !target.chars().any(char::is_control),
                        "服务包链接目标含控制字符"
                    );
                    let after = stat_at(source, &name)?;
                    ensure!(
                        stat.st_ino == after.st_ino
                            && stat.st_dev == after.st_dev
                            && stat.st_mode == after.st_mode
                            && stat.st_size == after.st_size,
                        "服务包链接在冻结期间改变"
                    );
                    if let Some(dest) = &dest {
                        std::os::unix::fs::symlink(&target, dest)?;
                    }
                    Entry::Symlink { target }
                }
                _ => bail!("服务包包含 Socket、设备或管道"),
            };
            // 目录重命名或同名替换不能把两个对象拼成一个登记身份。
            let after = stat_at(source, &name)?;
            ensure!(
                stat.st_ino == after.st_ino
                    && stat.st_dev == after.st_dev
                    && stat.st_mode == after.st_mode,
                "服务包条目在冻结期间被替换"
            );
            self.entries.insert(key, entry);
        }
        ensure!(
            unchanged(&before, &source.metadata()?),
            "服务包目录在冻结期间改变"
        );
        Ok(())
    }
}

fn verify_mode(metadata: &fs::Metadata, mode: u32) -> Result<()> {
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == mode,
        "冻结包所有者或只读权限改变"
    );
    Ok(())
}
fn same_inode(stat: &libc::stat, metadata: &fs::Metadata) -> bool {
    // macOS 的 dev_t 有符号，Linux 的设备号可能无符号；保留低 64 位再比较。
    stat.st_ino as u128 == u128::from(metadata.ino())
        && stat.st_dev as i128 as u64 == metadata.dev()
}
fn unchanged(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn tree_digest(entries: &BTreeMap<String, Entry>) -> Result<Sha256Digest> {
    Ok(crate::tool_registry::digest(
        &guard_schema::registry_canonical_bytes("mcp-package", serde_json::to_value(entries)?),
    ))
}
fn validate_links(entries: &BTreeMap<String, Entry>) -> Result<()> {
    for (name, entry) in entries {
        let Entry::Symlink { target } = entry else {
            continue;
        };
        let target = Path::new(target);
        ensure!(!target.is_absolute(), "服务包不接受绝对链接");
        let mut resolved = Path::new(name)
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        let mut parts = target.components().peekable();
        while let Some(part) = parts.next() {
            match part {
                Component::Normal(part) => resolved.push(part),
                Component::CurDir => {}
                Component::ParentDir => {
                    ensure!(resolved.pop(), "服务包链接越过包根目录");
                }
                _ => bail!("服务包链接目标无效"),
            }
            if parts.peek().is_some() && !resolved.as_os_str().is_empty() {
                ensure!(
                    matches!(
                        entries.get(resolved.to_str().context("包内路径必须是 UTF-8")?),
                        Some(Entry::Directory)
                    ),
                    "服务包链接中间路径不是普通目录"
                );
            }
        }
        let target_key = resolved.to_str().context("服务包链接目标必须是 UTF-8")?;
        ensure!(
            matches!(entries.get(target_key), Some(Entry::File { .. })),
            "首批仅接受指向包内普通文件的链接，拒绝悬空、目录和链接链"
        );
        let mut parent = resolved.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            ensure!(
                matches!(
                    entries.get(path.to_str().context("包内路径必须是 UTF-8")?),
                    Some(Entry::Directory)
                ),
                "服务包链接路径经过另一条链接"
            );
            parent = path.parent();
        }
    }
    Ok(())
}
fn valid_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path.as_os_str().len() <= MAX_PATH
        && path.components().all(|c| matches!(c, Component::Normal(_)))
        && path
            .to_str()
            .is_some_and(|s| !s.chars().any(char::is_control))
}
fn validate_root(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "服务包需要规范绝对路径"
    );
    ensure!(path.components().count() >= 3, "服务包根目录过宽");
    ensure!(
        path.to_str()
            .is_some_and(|s| !s.contains([',', '\n', '\r', '"']) && s.len() <= 4096),
        "服务包路径含不支持的字符或超限"
    );
    if let Some(reason) =
        guard_schema::paths::sensitive_target(path, guard_schema::paths::PathIntent::Read)
    {
        bail!("不能冻结敏感目录：{reason}");
    }
    if let Some(home) = std::env::var_os("HOME") {
        ensure!(
            !Path::new(&home).starts_with(path),
            "服务包不能包含整个宿主用户目录"
        );
    }
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn readonly(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn open_at(parent: &File, name: &CStr, flags: i32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn stat_at(parent: &File, name: &CStr) -> Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { stat.assume_init() })
}
struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn directory_names(directory: &File, remaining: usize) -> Result<Vec<CString>> {
    // 用独立 open file description，枚举不改变调用者目录句柄的位置。
    let file = open_at(directory, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    use std::os::fd::IntoRawFd;
    let fd = file.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = Directory(stream);
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        let errno = unsafe { libc::__error() };
        #[cfg(target_os = "linux")]
        let errno = unsafe { libc::__errno_location() };
        unsafe {
            *errno = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *errno } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        ensure!(names.len() < remaining, "服务包条目数量超过 {MAX_ENTRIES}");
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests;
