//! Linux 容器执行试点：只挂工作区副本，宿主原目录从不自动回写。
//! 客户端仍是合作式接入；容器外的原生工具不属于此边界。

use crate::exec::{
    run_command_bounded, run_command_with_cancel, ExecOutput, ToolCall, EXEC_TIMEOUT,
    MAX_OUTPUT_BYTES,
};
use crate::writeback::{ApplyReport, HostBaseline, Preview, WritebackEngine};
use anyhow::{bail, Context, Result};
use guard_schema::ExecutionOutcome;
use rand::RngCore;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MAX_FILES: usize = 20_000;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const HELPER: &str = include_str!("isolation_helper.py");

struct Mount {
    source: PathBuf,
    target: PathBuf,
    host_target: PathBuf,
    writable: bool,
    aliases: Vec<PathBuf>,
    writeback: Option<WritebackEngine>,
    writeback_reason: Option<String>,
}

pub struct DockerExecutor {
    image: String,
    endpoint: String,
    snapshot_root: PathBuf,
    mounts: Vec<Mount>,
    uid: u32,
    gid: u32,
    degraded: AtomicBool,
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl DockerExecutor {
    /// 仅向受控服务启动器交付已建立的副本挂载；不暴露宿主原工作区挂载。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn service_mounts(
        &self,
        image: &str,
        endpoint: &str,
    ) -> Result<Vec<(PathBuf, PathBuf, bool)>> {
        if self.degraded.load(Ordering::SeqCst) || self.image != image || self.endpoint != endpoint
        {
            bail!("服务与工作区的隔离后端不一致或状态未知");
        }
        Ok(self
            .mounts
            .iter()
            .flat_map(|mount| {
                std::iter::once(&mount.target)
                    .chain(mount.aliases.iter())
                    .map(|target| (mount.source.clone(), target.clone(), mount.writable))
            })
            .collect())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn service_cleanup_unknown(&self) {
        self.degraded.store(true, Ordering::SeqCst);
    }

    /// 使用宿主已选定的授权目录。镜像必须在本地，并以不可变摘要指定。
    pub fn new(image: String, read: &[String], write: &[String]) -> Result<Self> {
        #[cfg(not(unix))]
        bail!("当前容器接入只支持经验证的 Unix 宿主");
        #[cfg(unix)]
        {
            let digest = image
                .strip_prefix("sha256:")
                .or_else(|| image.split_once("@sha256:").map(|(_, d)| d));
            if !digest.is_some_and(|d| {
                d.len() == 64
                    && d.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                bail!("隔离镜像必须使用 sha256 摘要，不能使用可变 tag");
            }
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            if uid == 0 {
                bail!("隔离试点不允许以宿主 root 启动");
            }
            let endpoint = verify_local_endpoint()?;
            let mut roots: Vec<(PathBuf, bool)> = Vec::new();
            for (grants, writable) in [(read, false), (write, true)] {
                for grant in grants {
                    let path = guard_schema::paths::dealias_platform_volumes(Path::new(grant));
                    validate_root(&path)?;
                    if let Some(existing) = roots.iter_mut().find(|(p, _)| p == &path) {
                        existing.1 |= writable;
                    } else {
                        roots.push((path, writable));
                    }
                }
            }
            if roots.is_empty() {
                bail!("隔离模式需要明确的工作区目录授权");
            }
            roots.sort_by_key(|(p, _)| p.components().count());
            // 重叠挂载会产生权限覆盖歧义，首批只支持彼此独立的目录。
            let mut unique: Vec<(PathBuf, bool)> = Vec::new();
            for (path, writable) in roots {
                if let Some((parent, parent_write)) =
                    unique.iter().find(|(p, _)| path.starts_with(p))
                {
                    if *parent_write == writable {
                        continue;
                    }
                    bail!(
                        "暂不支持读写权限不同的嵌套授权：{} / {}",
                        parent.display(),
                        path.display()
                    );
                }
                unique.push((path, writable));
            }
            let probe = run_command_with_cancel(
                endpoint_command(&endpoint, &["info", "--format", "{{.OSType}}"]),
                Duration::from_secs(10),
                &|| false,
            );
            if !probe.ok || probe.detail.trim() != "linux" {
                bail!("Linux 容器后端不可用：{}", probe.detail);
            }
            let inspect = run_command_with_cancel(
                endpoint_command(
                    &endpoint,
                    &["image", "inspect", "--format", "{{.Id}}", &image],
                ),
                Duration::from_secs(10),
                &|| false,
            );
            if !inspect.ok {
                bail!("本地缺少指定隔离镜像：{}", inspect.detail);
            }
            let immutable_image = inspect.detail.trim().to_string();
            if !immutable_image.starts_with("sha256:") {
                bail!("镜像摘要查询结果无效");
            }
            let snapshot_root =
                std::env::temp_dir().join(format!("agentguard-snapshot-{}", random_id()));
            create_private_dir(&snapshot_root)?;
            let result = (|| {
                let mut mounts = Vec::new();
                let mut budget = CopyBudget { files: 0, bytes: 0 };
                for (index, (target, writable)) in unique.into_iter().enumerate() {
                    let source = snapshot_root.join(format!("workspace-{index}"));
                    create_private_dir(&source)?;
                    // 策略把 macOS /private/var 等系统别名归一为 /var。只接受归一后
                    // 仍是同一授权根的物理目录；任意用户链接置换不能借此扩大授权。
                    let physical = target.canonicalize()?;
                    if guard_schema::paths::dealias_platform_volumes(&physical) != target {
                        bail!("工作区根在授权后已改变：{}", target.display());
                    }
                    let directory = open_absolute_dir(&physical)?;
                    // 基线必须早于复制；回写能力缺失不能把既有只读/快照执行降级成原生执行。
                    let baseline = if writable {
                        Some(HostBaseline::capture(&physical))
                    } else {
                        None
                    };
                    copy_tree(&directory, &source, &target, &mut budget)?;
                    let source = source.canonicalize()?;
                    let aliases = workspace_aliases(&target, &physical);
                    let (writeback, writeback_reason) = match baseline {
                        Some(Ok(baseline)) => match WritebackEngine::attach(baseline, &source) {
                            Ok(engine) => (Some(engine), None),
                            Err(error) => (None, Some(format!("无法建立回写基线：{error:#}"))),
                        },
                        Some(Err(error)) => (None, Some(format!("无法建立宿主基线：{error:#}"))),
                        None => (None, Some("只读授权不支持回写".into())),
                    };
                    mounts.push(Mount {
                        source,
                        target,
                        host_target: physical,
                        writable,
                        aliases,
                        writeback,
                        writeback_reason,
                    });
                }
                let executor = Self {
                    image: immutable_image,
                    endpoint,
                    snapshot_root: snapshot_root.clone(),
                    mounts,
                    uid,
                    gid,
                    degraded: AtomicBool::new(false),
                };
                // 真正启动同样限制的临时容器，缺 Python、非 Linux 或无 seccomp 均拒绝启用。
                let probe = executor.execute(&ToolCall::RunShell {
                    argv: vec!["/usr/bin/python3".into(), "-c".into(),
                        "import os; s=open('/proc/self/status').read(); assert os.getuid()!=0; assert 'NoNewPrivs:\\t1' in s and 'Seccomp:\\t2' in s; print('AGD_ISOLATION_READY')".into()],
                    cwd: None,
                }, &|| false);
                if !probe.ok || !probe.detail.contains("AGD_ISOLATION_READY") {
                    bail!("隔离能力探测未通过：{}", probe.detail);
                }
                Ok(executor)
            })();
            if result.is_err() {
                let _ = fs::remove_dir_all(&snapshot_root);
            }
            result
        }
    }

    pub fn status(&self) -> Value {
        json!({"mode":"isolated_workspace_snapshot", "image":self.image,
            "network":"none", "client_enforcement":"cooperative", "host_writeback":"operator_reviewed",
            "automatic_host_writeback":false,
            "healthy":!self.degraded.load(Ordering::SeqCst), "snapshot_root":self.snapshot_root, "workspace_mounts":self.mounts.iter().map(|m| json!({
                "snapshot":m.source,"target":m.target,"aliases":m.aliases,"writable":m.writable})).collect::<Vec<_>>(),
            "limits":{"pids":64,"memory_mb":256,"timeout_secs":30}})
    }

    pub fn workspaces(&self) -> Value {
        json!(self.mounts.iter().enumerate().map(|(index, mount)| json!({
            "workspace_id":format!("workspace-{index}"), "target":mount.host_target,
            "snapshot":mount.source, "writable":mount.writable,
            "writeback_available":mount.writeback.is_some() && !self.degraded.load(Ordering::SeqCst),
            "writeback_reason":mount.writeback_reason,
        })).collect::<Vec<_>>())
    }

    fn writeback_mut(&mut self, workspace_id: &str) -> Result<&mut WritebackEngine> {
        if self.degraded.load(Ordering::SeqCst) {
            bail!("隔离执行器状态未知，不能回写");
        }
        let index = workspace_id
            .strip_prefix("workspace-")
            .context("工作区编号无效")?
            .parse::<usize>()?;
        if workspace_id != format!("workspace-{index}") {
            bail!("工作区编号不是当前宿主生成的编号");
        }
        self.mounts
            .get_mut(index)
            .context("工作区不存在")?
            .writeback
            .as_mut()
            .context("此工作区没有可用回写基线")
    }

    pub fn preview_workspace(&mut self, workspace_id: &str) -> Result<Preview> {
        self.writeback_mut(workspace_id)?.preview()
    }

    pub fn apply_workspace(
        &mut self,
        workspace_id: &str,
        digest: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ApplyReport> {
        Ok(self
            .writeback_mut(workspace_id)?
            .apply_with_cancel(digest, cancelled))
    }

    pub fn execute(&self, call: &ToolCall, cancelled: &dyn Fn() -> bool) -> ExecOutput {
        self.execute_with_file_scope(call, cancelled, false)
    }

    pub(crate) fn execute_with_file_scope(
        &self,
        call: &ToolCall,
        cancelled: &dyn Fn() -> bool,
        strict_file_scope: bool,
    ) -> ExecOutput {
        if self.degraded.load(Ordering::SeqCst) {
            return ExecOutput::err("隔离后端状态未知，已禁止后续动作；须核实遗留容器并重建会话")
                .with_state(ExecutionOutcome::Refused, false);
        }
        if cancelled() {
            return ExecOutput::err("客户端已断开，未开始隔离执行")
                .with_state(ExecutionOutcome::Cancelled, false);
        }
        let request_root = self.snapshot_root.join(format!("request-{}", random_id()));
        let result = (|| -> Result<ExecOutput> {
            create_private_dir(&request_root)?;
            let mut request = serde_json::to_value(call)?;
            if strict_file_scope {
                request["__agentguard_single_link"] = json!(true);
            }
            fs::write(
                request_root.join("call.json"),
                serde_json::to_vec(&request)?,
            )?;
            fs::write(request_root.join("helper.py"), HELPER)?;
            let name = format!("agentguard-task-{}", random_id());
            // 名字仅由宿主生成，取消/超时不能只杀 Docker 客户端而遗留容器。
            let cleanup = ContainerCleanup {
                name: name.clone(),
                endpoint: self.endpoint.clone(),
            };
            let mut command = endpoint_command(
                &self.endpoint,
                &[
                    "run",
                    "--pull=never",
                    "--rm",
                    "--name",
                    &name,
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges:true",
                    "--pids-limit=64",
                    "--memory=256m",
                    "--memory-swap=256m",
                    "--cpus=1",
                    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=67108864",
                    "--entrypoint=/usr/bin/env",
                ],
            );
            command.args(["--user", &format!("{}:{}", self.uid, self.gid)]);
            for mount in &self.mounts {
                for target in std::iter::once(&mount.target).chain(mount.aliases.iter()) {
                    let option = format!(
                        "type=bind,src={},dst={}{}",
                        mount.source.display(),
                        target.display(),
                        if mount.writable { "" } else { ",readonly" }
                    );
                    command.args(["--mount", &option]);
                }
            }
            command.args([
                "--mount",
                &format!(
                    "type=bind,src={},dst=/run/agentguard-request,readonly",
                    request_root.display()
                ),
            ]);
            command.args([
                &self.image,
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "HOME=/tmp",
                "TMPDIR=/tmp",
                "LANG=C.UTF-8",
                "/usr/bin/timeout",
                "--signal=KILL",
                "30s",
                "/usr/bin/python3",
                "-I",
                "/run/agentguard-request/helper.py",
            ]);
            // 私有包络容纳 4 MiB 扫描字节的 base64 及转义正文；返回模型的正文仍为 64 KiB。
            let limit = if matches!(call, ToolCall::RunShell { .. }) {
                MAX_OUTPUT_BYTES
            } else {
                crate::content::MAX_CAPTURE_WIRE
            };
            let output = run_command_bounded(command, EXEC_TIMEOUT, cancelled, limit);
            // 正常退出后 --rm 已删除；失败或断连时此处仍清理整棵容器进程树。
            let removed = cleanup.remove();
            std::mem::forget(cleanup);
            if !removed {
                self.degraded.store(true, Ordering::SeqCst);
                return Ok(
                    ExecOutput::err("容器清理状态未知；停止新动作并人工核实，不自动重试")
                        .with_state(ExecutionOutcome::Unknown, true),
                );
            }
            if matches!(call, ToolCall::RunShell { .. }) {
                return Ok(output);
            }
            Ok(decode_file_reply(output))
        })();
        let _ = fs::remove_dir_all(request_root);
        result.unwrap_or_else(|e| {
            ExecOutput::err(format!("隔离执行准备失败：{e:#}"))
                .with_state(ExecutionOutcome::Failed, false)
        })
    }
}

fn decode_file_reply(output: ExecOutput) -> ExecOutput {
    // 私有包络可能包含整段原始捕获；错误、截断或子进程异常时也不能原样返回模型。
    let unknown = || {
        ExecOutput::err("隔离文件工具回执不完整或格式无效，实际结果未知，不自动重试")
            .with_state(ExecutionOutcome::Unknown, output.dispatched)
    };
    if output.truncated
        || !matches!(
            output.outcome,
            ExecutionOutcome::Success | ExecutionOutcome::Failed
        )
    {
        return unknown();
    }
    match serde_json::from_str::<ExecOutput>(&output.detail) {
        Ok(decoded) if decoded.detail.len() <= MAX_OUTPUT_BYTES && (!decoded.ok || output.ok) => {
            decoded
        }
        _ => unknown(),
    }
}

// Docker CLI 只获得连接本地引擎所需的最小环境，不把宿主令牌放入子进程环境。
fn base_command(args: &[&str]) -> Command {
    let mut cmd = Command::new("docker");
    cmd.env_clear();
    for name in [
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
    ] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.args(args);
    cmd
}

pub(crate) fn endpoint_command(endpoint: &str, args: &[&str]) -> Command {
    let mut command = base_command(args);
    command
        .env_remove("DOCKER_CONTEXT")
        .env("DOCKER_HOST", endpoint);
    command
}

pub(crate) fn verify_local_endpoint() -> Result<String> {
    // Docker 的显式 context 优先于 DOCKER_HOST；无覆盖时读取当前 context。
    let context = std::env::var("DOCKER_CONTEXT")
        .ok()
        .filter(|s| !s.is_empty());
    let endpoint = if context.is_none() {
        std::env::var("DOCKER_HOST").ok().filter(|s| !s.is_empty())
    } else {
        None
    };
    let endpoint = match endpoint {
        Some(endpoint) => endpoint,
        None => {
            let name = match context {
                Some(name) => name,
                None => {
                    let output = run_command_with_cancel(
                        base_command(&["context", "show"]),
                        Duration::from_secs(10),
                        &|| false,
                    );
                    if !output.ok {
                        bail!("无法读取当前 Docker context");
                    }
                    output.detail.trim().to_string()
                }
            };
            let mut command = base_command(&[
                "context",
                "inspect",
                &name,
                "--format",
                "{{.Endpoints.docker.Host}}",
            ]);
            command
                .env_remove("DOCKER_HOST")
                .env_remove("DOCKER_CONTEXT");
            let output = run_command_with_cancel(command, Duration::from_secs(10), &|| false);
            if !output.ok {
                bail!("无法确定 Docker 连接目标：{}", output.detail);
            }
            output.detail.trim().to_string()
        }
    };
    if !endpoint.starts_with("unix:///") {
        bail!("当前隔离试点只支持本地 Unix Socket，不支持远程 Docker：{endpoint}");
    }
    Ok(endpoint)
}

struct ContainerCleanup {
    name: String,
    endpoint: String,
}
impl ContainerCleanup {
    fn remove(&self) -> bool {
        let removed = run_command_with_cancel(
            endpoint_command(&self.endpoint, &["rm", "-f", &self.name]),
            Duration::from_secs(10),
            &|| false,
        );
        if removed.ok {
            return true;
        }
        // 只把明确不存在记为清理完成；daemon 故障是未知。
        removed.detail.contains("No such container")
    }
}
impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        self.remove();
    }
}

fn validate_root(path: &Path) -> Result<()> {
    if let Some(reason) =
        guard_schema::paths::sensitive_target(path, guard_schema::paths::PathIntent::Read)
    {
        bail!("不能把敏感宿主目录纳入隔离快照：{reason}");
    }
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("工作区必须是规范绝对目录：{}", path.display());
    }
    let s = path.to_str().context("工作区路径必须是 UTF-8")?;
    if s.contains([',', '\n', '\r', '"']) {
        bail!("工作区路径含不支持的挂载字符");
    }
    if path == Path::new("/")
        || [
            "/bin", "/sbin", "/etc", "/usr", "/proc", "/sys", "/dev", "/run", "/lib", "/lib64",
            "/root",
        ]
        .iter()
        .any(|reserved| path.starts_with(reserved))
    {
        bail!("不能将系统目录授权为工作区：{s}");
    }
    if [
        "/home",
        "/Users",
        "/tmp",
        "/var",
        "/private",
        "/private/tmp",
        "/private/var",
    ]
    .iter()
    .any(|p| path == Path::new(p))
    {
        bail!("工作区授权过宽：{s}");
    }
    if let Some(home) = std::env::var_os("HOME") {
        if Path::new(&home).starts_with(path) {
            bail!("工作区不能包含整个宿主用户目录");
        }
    }
    if path.components().any(|c| {
        [".ssh", ".aws", ".gnupg", ".kube", ".docker"]
            .iter()
            .any(|n| c.as_os_str() == *n)
    }) {
        bail!("凭据目录不能作为工作区");
    }
    Ok(())
}

fn workspace_aliases(target: &Path, physical: &Path) -> Vec<PathBuf> {
    let mut aliases = Vec::new();
    if physical != target {
        aliases.push(physical.to_path_buf());
    }
    #[cfg(target_os = "macos")]
    {
        let mut candidates =
            vec![Path::new("/System/Volumes/Data").join(target.strip_prefix("/").unwrap())];
        for root in ["/var", "/tmp"] {
            if target.starts_with(root) {
                let private = Path::new("/private").join(target.strip_prefix("/").unwrap());
                candidates.push(
                    Path::new("/System/Volumes/Data").join(private.strip_prefix("/").unwrap()),
                );
                candidates.push(private);
            }
        }
        for path in candidates {
            if path != target
                && !aliases.contains(&path)
                && guard_schema::paths::dealias_platform_volumes(&path) == target
            {
                aliases.push(path);
            }
        }
    }
    aliases
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
#[cfg(not(unix))]
fn create_private_dir(_: &Path) -> Result<()> {
    bail!("未支持的宿主")
}

#[cfg(unix)]
fn open_at(parent: &File, name: &std::ffi::CStr, flags: i32) -> Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
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
#[cfg(unix)]
pub(crate) fn open_absolute_dir(path: &Path) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let mut directory = File::open("/")?;
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            directory = open_at(
                &directory,
                &std::ffi::CString::new(name.as_bytes())?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
        }
    }
    Ok(directory)
}
struct CopyBudget {
    files: usize,
    bytes: u64,
}

#[cfg(unix)]
fn copy_tree(source: &File, target: &Path, original: &Path, budget: &mut CopyBudget) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    let copy_fd = unsafe { libc::dup(source.as_raw_fd()) };
    if copy_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(copy_fd) };
    if stream.is_null() {
        unsafe {
            libc::close(copy_fd);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = DirectoryStream(stream);
    loop {
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        // 凭据文件夹和控制 Socket 不进入快照；明确拒绝，不能静默漏掉项目文件。
        if matches!(
            name.to_bytes(),
            b".ssh" | b".aws" | b".gnupg" | b".kube" | b".docker"
        ) {
            bail!("工作区内含凭据目录，拒绝建立快照");
        }
        budget.files += 1;
        if budget.files > MAX_FILES {
            bail!("工作区超过 {MAX_FILES} 个对象");
        }
        let dest = target.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let original_child = original.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        if let Some(reason) = guard_schema::paths::sensitive_target(
            &original_child,
            guard_schema::paths::PathIntent::Read,
        ) {
            bail!("快照源包含敏感宿主文件，拒绝摄入：{reason}");
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                source.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let child = open_at(source, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                create_private_dir(&dest)?;
                copy_tree(&child, &dest, &original_child, budget)?;
            }
            libc::S_IFREG => {
                let mut input = open_at(source, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
                let metadata = input.metadata()?;
                if !metadata.is_file() {
                    bail!("快照过程中源文件类型改变");
                }
                if metadata.len() > MAX_SNAPSHOT_BYTES.saturating_sub(budget.bytes) {
                    bail!("工作区快照超过 512 MiB");
                }
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)?;
                use std::io::Read;
                let remaining = MAX_SNAPSHOT_BYTES.saturating_sub(budget.bytes);
                let written = std::io::copy(&mut (&mut input).take(remaining + 1), &mut output)?;
                budget.bytes += written;
                if written != metadata.len() || budget.bytes > MAX_SNAPSHOT_BYTES {
                    bail!("文件在快照期间改变或超过大小限制");
                }
                fs::set_permissions(
                    dest,
                    fs::Permissions::from_mode(0o600 | (metadata.permissions().mode() & 0o100)),
                )?;
            }
            libc::S_IFLNK => {
                let mut bytes = vec![0u8; 16_384];
                let length = unsafe {
                    libc::readlinkat(
                        source.as_raw_fd(),
                        name.as_ptr(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                if length < 0 || length as usize == bytes.len() {
                    bail!("无法安全复制链接");
                }
                std::os::unix::fs::symlink(
                    std::ffi::OsStr::from_bytes(&bytes[..length as usize]),
                    dest,
                )?;
            }
            _ => bail!("工作区含 Socket、设备或管道，拒绝建立快照"),
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn 文件执行器异常时私有捕获包络不得作为工具正文返回() {
        let wire = serde_json::json!({"ok":true,"detail":"公开回执","truncated":false,
            "outcome":"success","dispatched":true,"capture":{"version":1,"streams":[{
                "origin":"file_bytes","raw_base64":"U1lOVEhFVElDX1BSSVZBVEU=","complete":true}]}})
        .to_string();
        for (detail, truncated, outcome) in [
            (wire.clone(), false, ExecutionOutcome::Failed),
            (wire.clone(), true, ExecutionOutcome::Success),
            (format!("{wire}\nextra"), false, ExecutionOutcome::Success),
        ] {
            let mut outer = ExecOutput::ok(detail);
            outer.ok = outcome == ExecutionOutcome::Success;
            outer.outcome = outcome;
            outer.truncated = truncated;
            let decoded = decode_file_reply(outer);
            assert_eq!(decoded.outcome, ExecutionOutcome::Unknown);
            assert!(decoded.dispatched);
            assert!(
                !decoded.detail.contains("raw_base64") && !decoded.detail.contains("U1lOVEhFVElD")
            );
        }
        let outer = ExecOutput::err(
            serde_json::json!({"ok":false,"detail":"文件不存在",
            "truncated":false,"outcome":"failed","dispatched":true})
            .to_string(),
        );
        let decoded = decode_file_reply(outer);
        assert_eq!(decoded.outcome, ExecutionOutcome::Failed);
        assert_eq!(decoded.detail, "文件不存在");
    }
    fn temporary() -> PathBuf {
        // macOS 默认临时目录很长；Unix Socket 的路径上限比普通文件小。
        let root = Path::new("/tmp").join(format!("agd-snapshot-test-{}", random_id()));
        create_private_dir(&root).unwrap();
        root.canonicalize().unwrap()
    }

    #[test]
    fn 快照硬链接转为字节副本且不跟随符号链接() {
        let root = temporary();
        let source = root.join("source");
        let target = root.join("snapshot");
        create_private_dir(&source).unwrap();
        create_private_dir(&target).unwrap();
        let outside = root.join("outside.txt");
        fs::write(&outside, "original").unwrap();
        fs::hard_link(&outside, source.join("hardlink.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, source.join("symlink.txt")).unwrap();
        let mut budget = CopyBudget { files: 0, bytes: 0 };
        copy_tree(
            &open_absolute_dir(&source).unwrap(),
            &target,
            &source,
            &mut budget,
        )
        .unwrap();
        fs::write(target.join("hardlink.txt"), "snapshot only").unwrap();
        assert_eq!(fs::read_to_string(outside).unwrap(), "original");
        assert!(fs::symlink_metadata(target.join("symlink.txt"))
            .unwrap()
            .is_symlink());
        assert_eq!(budget.files, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 源目录被置换为用户链接后不能打开() {
        let root = temporary();
        let source = root.join("source");
        let outside = root.join("outside");
        create_private_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &source).unwrap();
        assert!(open_absolute_dir(&source).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 工作区含控制socket时拒绝复制() {
        let root = temporary();
        let source = root.join("source");
        let target = root.join("snapshot");
        create_private_dir(&source).unwrap();
        create_private_dir(&target).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(source.join("control.sock")).unwrap();
        let mut budget = CopyBudget { files: 0, bytes: 0 };
        assert!(copy_tree(
            &open_absolute_dir(&source).unwrap(),
            &target,
            &source,
            &mut budget
        )
        .is_err());
        drop(socket);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn 系统目录与挂载分隔符不能进入授权() {
        for input in [
            "/",
            "/etc/project",
            "/Users",
            "/tmp",
            "/work/path,readonly",
            "/work/../home",
        ] {
            assert!(validate_root(Path::new(input)).is_err(), "{input}");
        }
    }

    #[test]
    fn 快照摄入按原目录拒绝已知凭据而不是检查临时路径() {
        let root = temporary();
        let source = root.join("Library");
        let target = root.join("snapshot");
        create_private_dir(&source).unwrap();
        create_private_dir(&target).unwrap();
        create_private_dir(&source.join("Keychains")).unwrap();
        fs::write(source.join("Keychains/login.keychain-db"), "合成凭据").unwrap();
        assert!(validate_root(&source.join("Keychains")).is_err());
        let mut budget = CopyBudget { files: 0, bytes: 0 };
        assert!(copy_tree(
            &open_absolute_dir(&source).unwrap(),
            &target,
            &source,
            &mut budget
        )
        .is_err());
        assert!(!target.join("Keychains").exists());
        fs::remove_dir_all(source.join("Keychains")).unwrap();
        fs::write(source.join(".netrc"), "合成凭据").unwrap();
        assert!(copy_tree(
            &open_absolute_dir(&source).unwrap(),
            &target,
            &source,
            &mut budget
        )
        .is_err());
        assert!(!target.join(".netrc").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
