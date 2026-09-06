//! 在任何 SQLite 打开之前复制加密容器，错误密钥只接触隔离副本。
//!
//! 不使用 immutable=1 忽略 WAL，不把普通只读 SQLite 连接误当作附属文件零写入保证。
//! 此模块只允许加密容器预检，不能用它制造明文历史库的临时磁盘副本。

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const SUFFIXES: [&str; 4] = ["", "-wal", "-shm", "-journal"];

pub(crate) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FileIdentity {
    pub bytes: u64,
    pub sha256: String,
}

fn read_file(path: &Path, mut target: Option<&mut File>) -> Result<Option<FileIdentity>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("无法检查审计文件"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("审计文件不是普通文件，保持原件不变");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("审计文件不能是重解析点，保持原件不变");
        }
    }
    let mut source = File::open(path).context("无法只读打开审计文件")?;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = source.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
        bytes += size as u64;
        if let Some(output) = &mut target {
            output.write_all(&buffer[..size])?;
        }
    }
    Ok(Some(FileIdentity {
        bytes,
        sha256: hex::encode(hash.finalize()),
    }))
}

pub(crate) fn identity(path: &Path) -> Result<Vec<Option<FileIdentity>>> {
    SUFFIXES
        .iter()
        .map(|suffix| read_file(&sidecar(path, suffix), None))
        .collect()
}

pub(crate) struct EncryptedSnapshot {
    _directory: tempfile::TempDir,
    pub path: PathBuf,
    source: PathBuf,
    before: Vec<Option<FileIdentity>>,
}

impl EncryptedSnapshot {
    pub fn capture(source: &Path) -> Result<Option<Self>> {
        let before = identity(source)?;
        if before[0].as_ref().is_none_or(|file| file.bytes == 0) {
            if before[1..].iter().flatten().any(|file| file.bytes > 0) {
                bail!("审计主文件缺失或为空但仍有恢复文件，请先恢复数据；没有创建新库");
            }
            return Ok(None);
        }
        let directory = tempfile::Builder::new()
            .prefix("agentguard-cipher-check-")
            .tempdir()?;
        let path = directory.path().join("audit.db");
        for (index, suffix) in SUFFIXES.iter().enumerate() {
            if before[index].is_none() {
                continue;
            }
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(sidecar(&path, suffix))?;
            let copied = read_file(&sidecar(source, suffix), Some(&mut file))?;
            if copied != before[index] {
                bail!("审计文件正在变化，预检已取消，请停止旧版本后重试");
            }
        }
        let snapshot = Self {
            _directory: directory,
            path,
            source: source.into(),
            before,
        };
        snapshot.verify_source()?;
        Ok(Some(snapshot))
    }

    pub fn verify_source(&self) -> Result<()> {
        if identity(&self.source)? != self.before {
            bail!("审计文件在预检期间发生变化，未打开原件写入，请重试");
        }
        Ok(())
    }
}
