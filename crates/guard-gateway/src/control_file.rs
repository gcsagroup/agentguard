//! 独立控制连接文件。批准凭据只写操作者指定的宿主路径，不进入隔离工具stdio。
use anyhow::{bail, Context, Result};
use std::path::Path;

#[cfg(unix)]
pub struct ControlFile {
    parent: std::fs::File,
    name: std::ffi::CString,
    device: u64,
    inode: u64,
}
#[cfg(not(unix))]
pub struct ControlFile;

impl ControlFile {
    pub fn create(path: &Path, bytes: &[u8]) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path, bytes);
            bail!("当前连接文件保护尚未验证该宿主平台");
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            Self::create_with_writer(path, |file| {
                file.write_all(bytes).context("不能写入独立控制连接文件")?;
                file.sync_all().context("不能持久保存控制连接文件")
            })
        }
    }

    #[cfg(unix)]
    fn create_with_writer(
        path: &Path,
        write: impl FnOnce(&mut std::fs::File) -> Result<()>,
    ) -> Result<Self> {
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (path, write);
            bail!("当前宿主平台尚未验证控制连接文件的排他发布");
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use rand::RngCore;
            use std::os::{
                fd::{AsRawFd, FromRawFd},
                unix::{ffi::OsStrExt, fs::MetadataExt},
            };
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("控制连接文件必须使用绝对路径，且不能包含 ..");
            }
            let logical_parent = path.parent().context("控制文件缺少父目录")?;
            let physical_parent = logical_parent
                .canonicalize()
                .context("控制连接文件父目录不存在")?;
            if guard_schema::paths::dealias_platform_volumes(&physical_parent)
                != guard_schema::paths::dealias_platform_volumes(logical_parent)
            {
                bail!("控制连接文件父目录含用户符号链接，拒绝写入");
            }
            let parent = crate::isolation::open_absolute_dir(&physical_parent)?;
            let final_name =
                std::ffi::CString::new(path.file_name().context("控制文件缺少文件名")?.as_bytes())?;
            // 正式路径出现即代表内容完整。不能让读取方看到新建后尚未写完的空文件。
            let name = std::ffi::CString::new(format!(
                ".agentguard-control-{:016x}{:016x}",
                rand::rngs::OsRng.next_u64(),
                rand::rngs::OsRng.next_u64()
            ))?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("不能建立独立控制连接文件，已有文件不会被覆盖");
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            let mut guard = Self {
                parent,
                name,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            write(&mut file)?;
            // 排他 rename 同时保证正式文件没有中间内容、链接数不曾变成 2，且不覆盖旧文件。
            #[cfg(target_os = "macos")]
            let status = unsafe {
                libc::renameatx_np(
                    guard.parent.as_raw_fd(),
                    guard.name.as_ptr(),
                    guard.parent.as_raw_fd(),
                    final_name.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            let status = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    guard.parent.as_raw_fd(),
                    guard.name.as_ptr(),
                    guard.parent.as_raw_fd(),
                    final_name.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if status != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("不能排他发布控制连接文件，已有文件不会被覆盖");
            }
            guard.name = final_name;
            Ok(guard)
        }
    }
}

#[cfg(unix)]
impl Drop for ControlFile {
    // Unix 平台的 dev_t/ino_t 宽度不同；统一比较标准库 Metadata 返回的 u64。
    #[allow(clippy::unnecessary_cast)]
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            let info = unsafe { info.assume_init() };
            if info.st_dev as u64 == self.device && info.st_ino as u64 == self.inode {
                // 只撤销本实例创建的连接文件；替换后的文件属于操作者，不能顺手删除。
                unsafe {
                    libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::os::unix::fs::PermissionsExt;
    fn root() -> std::path::PathBuf {
        let name = rand::rngs::OsRng.next_u64();
        let path = std::env::temp_dir().join(format!("agd-control-{name}"));
        std::fs::create_dir(&path).unwrap();
        path.canonicalize().unwrap()
    }
    #[test]
    fn 文件仅本用户可读且正常退出撤销() {
        let root = root();
        let file = root.join("control.json");
        let guard = ControlFile::create(&file, b"test-only-token").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(ControlFile::create(&file, b"replacement").is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"test-only-token");
        drop(guard);
        assert!(!file.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn 父目录链接和已有文件拒绝且不删除替换文件() {
        let root = root();
        let original = root.join("original");
        std::fs::create_dir(&original).unwrap();
        std::os::unix::fs::symlink(&original, root.join("alias")).unwrap();
        assert!(ControlFile::create(&root.join("alias/control.json"), b"secret").is_err());
        let file = original.join("control.json");
        let guard = ControlFile::create(&file, b"old").unwrap();
        std::fs::rename(&file, original.join("operator-moved.json")).unwrap();
        std::fs::write(&file, b"operator replacement").unwrap();
        drop(guard);
        assert_eq!(std::fs::read(file).unwrap(), b"operator replacement");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 写入完成前正式路径不可见且发布后只有一个链接() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let root = root();
        let target = root.join("control.json");
        let guard = ControlFile::create_with_writer(&target, |file| {
            file.write_all(b"first-")?;
            assert!(!target.exists(), "读取方不能看到半写入的正式文件");
            file.write_all(b"complete")?;
            file.sync_all()?;
            assert!(!target.exists());
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first-complete");
        assert_eq!(std::fs::metadata(&target).unwrap().nlink(), 1);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        drop(guard);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn 写入失败或发布冲突只清理本次临时文件() {
        use std::io::Write;
        let root = root();
        let target = root.join("control.json");
        let failed = ControlFile::create_with_writer(&target, |file| {
            file.write_all(b"partial")?;
            bail!("合成写入故障")
        });
        assert!(failed.is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let conflict = ControlFile::create_with_writer(&target, |file| {
            file.write_all(b"candidate")?;
            file.sync_all()?;
            std::fs::write(&target, b"operator-owned")?;
            Ok(())
        });
        assert!(conflict.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"operator-owned");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
