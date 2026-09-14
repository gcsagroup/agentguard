//! 第三方 Node MCP 服务的 Linux 容器启动器，复用已验证镜像及既有工作区副本。
//! 这里只建立执行边界；产品路由必须另行完成登记、授权、动作批准与审计。
use crate::exec::run_command_with_cancel;
use crate::isolation::{endpoint_command, verify_local_endpoint, DockerExecutor};
use crate::mcp_package::FrozenPackage;
use crate::mcp_stdio::StdioClient;
use anyhow::{bail, ensure, Context, Result};
use guard_schema::{Sha256Digest, ToolPackageIdentity, ToolServiceManifest};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const GATE: &str = include_str!("mcp_launch.py");
const PACKAGE_TARGET: &str = "/run/agentguard-mcp-package";
const HARDENING: &[&str] = &[
    "run",
    "--pull=never",
    "--rm",
    "-i",
    "--network=none",
    "--read-only",
    "--no-healthcheck",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=64",
    "--memory=256m",
    "--memory-swap=256m",
    "--cpus=1",
    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16777216",
    "--entrypoint=/usr/bin/env",
];

struct State {
    endpoint: String,
    healthy: AtomicBool,
    active: AtomicBool,
}

pub struct NodeService {
    package: Arc<FrozenPackage>,
    image: String,
    entrypoint: String,
    state: Arc<State>,
}

/// 宿主配置的登记名称与展示版本；包摘要始终从实际冻结字节计算。
pub struct ServiceRegistration {
    pub service_id: String,
    pub namespace: String,
    pub package_id: String,
    pub package_version: String,
}

/// 只由真实隔离发现产生，不提供反序列化或外部构造入口。
/// 发现已清理并不授予服务工作区权限，仍需独立登记和运行批准。
pub struct ServiceDiscovery {
    manifest: ToolServiceManifest,
    receipt: LaunchReceipt,
    container_name: String,
}
impl ServiceDiscovery {
    pub fn manifest(&self) -> &ToolServiceManifest {
        &self.manifest
    }
    pub fn receipt(&self) -> &LaunchReceipt {
        &self.receipt
    }
    pub fn container_name(&self) -> &str {
        &self.container_name
    }
}

/// 工作区权限来自宿主已有授权副本，不能从工具声明或 MCP 参数自行构造。
pub enum ServiceWorkspace<'a> {
    /// 工具发现只得到空的只读 /workspace；没有宿主工作区或凭据。
    Discovery,
    /// 上层完成服务授权后，复用隔离副本；不挂宿主原件、不自动回写。
    Snapshot(&'a DockerExecutor),
    /// 发现沿用授权副本的目标路径，但每个目标都只挂载空只读目录。
    DiscoveryFor(&'a DockerExecutor),
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchReceipt {
    pub session_id: String,
    pub package_sha256: Sha256Digest,
    pub execution_sha256: Sha256Digest,
    pub scope_sha256: Sha256Digest,
    pub image: String,
    pub discovery_only: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Shutdown {
    pub graceful_exit: bool,
    pub container_removed: bool,
}

pub struct ServiceProcess<'a> {
    client: StdioClient,
    state: Arc<State>,
    name: String,
    receipt: LaunchReceipt,
    _package: Arc<FrozenPackage>,
    workspace: Option<&'a DockerExecutor>,
    empty_root: Option<PathBuf>,
    shutdown: Option<Shutdown>,
}

impl NodeService {
    /// 只有空只读工作区。完整握手及清单共享总时限；关闭并核实容器后才交付观测。
    pub fn discover(
        &self,
        registration: &ServiceRegistration,
        arguments: &[String],
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ServiceDiscovery> {
        self.discover_in(
            registration,
            arguments,
            ServiceWorkspace::Discovery,
            timeout,
            cancelled,
            None,
        )
    }

    pub fn discover_for_snapshot(
        &self,
        registration: &ServiceRegistration,
        arguments: &[String],
        snapshot: &DockerExecutor,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ServiceDiscovery> {
        self.discover_in(
            registration,
            arguments,
            ServiceWorkspace::DiscoveryFor(snapshot),
            timeout,
            cancelled,
            None,
        )
    }

    pub(crate) fn discover_tracked(
        &self,
        registration: &ServiceRegistration,
        arguments: &[String],
        snapshot: &DockerExecutor,
        recovery: &mut crate::mcp_recovery::RecoveryLog,
    ) -> Result<ServiceDiscovery> {
        self.discover_in(
            registration,
            arguments,
            ServiceWorkspace::DiscoveryFor(snapshot),
            Duration::from_secs(30),
            &|| false,
            Some(recovery),
        )
    }

    fn discover_in(
        &self,
        registration: &ServiceRegistration,
        arguments: &[String],
        workspace: ServiceWorkspace<'_>,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        mut recovery: Option<&mut crate::mcp_recovery::RecoveryLog>,
    ) -> Result<ServiceDiscovery> {
        ensure!(
            !cancelled() && !timeout.is_zero() && timeout <= Duration::from_secs(30),
            "发现已取消或时限无效"
        );
        let deadline = Instant::now() + timeout;
        let prepared = self.prepare(arguments, workspace)?;
        let receipt = prepared.receipt().clone();
        let name = prepared.container_name().to_owned();
        if let Some(log) = recovery.as_mut() {
            log.starting(&prepared)?;
        }
        let launch = prepared.launch_with(|spawn| spawn());
        let mut process = match launch {
            Ok(process) => process,
            Err(error) => {
                if self.healthy() {
                    if let Some(log) = recovery.as_mut() {
                        log.removed(&name, &receipt)?;
                    }
                }
                return Err(error);
            }
        };
        let observed = (|| -> Result<ServiceDiscovery> {
            let initialization = process.client().initialize(
                deadline.saturating_duration_since(Instant::now()),
                cancelled,
            )?;
            let listing = process.client().list_tools(
                deadline.saturating_duration_since(Instant::now()),
                cancelled,
            )?;
            let manifest = ToolServiceManifest::from_mcp(
                registration.service_id.clone(),
                registration.namespace.clone(),
                ToolPackageIdentity {
                    package_id: registration.package_id.clone(),
                    version: registration.package_version.clone(),
                    sha256: self.package.sha256().clone(),
                },
                process.receipt().execution_sha256.clone(),
                initialization,
                listing,
            )?;
            Ok(ServiceDiscovery {
                manifest,
                receipt: process.receipt().clone(),
                container_name: process.name.clone(),
            })
        })();
        ensure!(
            process.close().container_removed,
            "发现服务清理未知，不能交付观测"
        );
        if let Some(log) = recovery.as_mut() {
            log.removed(&name, &receipt)?;
        }
        ensure!(!cancelled(), "发现已取消，不能交付观测");
        observed
    }

    pub fn new(image: String, package: Arc<FrozenPackage>, entrypoint: String) -> Result<Self> {
        ensure!(
            package.contains_entrypoint(&entrypoint),
            "服务入口必须是冻结包内的普通文件"
        );
        validate_image(&image)?;
        let endpoint = verify_local_endpoint()?;
        let output = run_command_with_cancel(
            endpoint_command(&endpoint, &["image", "inspect", &image]),
            Duration::from_secs(10),
            &|| false,
        );
        ensure!(output.ok && !output.truncated, "不能核实本地服务镜像");
        let inspected: Value = serde_json::from_str(&output.detail).context("镜像检查回执无效")?;
        let items = inspected.as_array().context("镜像检查回执不是数组")?;
        ensure!(
            items.len() == 1 && items[0]["Id"] == image,
            "镜像摘要不一致"
        );
        ensure!(items[0]["Os"] == "linux", "服务只支持 Linux 镜像");
        // 镜像声明的匿名卷会绕过本启动器的明确挂载清单，不能自动创建。
        ensure!(
            items[0]["Config"]
                .get("Volumes")
                .is_none_or(|v| v.is_null() || v.as_object().is_some_and(|v| v.is_empty())),
            "服务镜像声明了未支持的额外卷"
        );
        package.verify()?;
        Ok(Self {
            package,
            image,
            entrypoint,
            state: Arc::new(State {
                endpoint,
                healthy: AtomicBool::new(true),
                active: AtomicBool::new(false),
            }),
        })
    }

    /// 清单登记应使用这个实际运行身份，包含包、镜像、入口、参数和限制参数。
    pub fn execution_sha256(&self, arguments: &[String]) -> Result<Sha256Digest> {
        validate_arguments(arguments)?;
        let bytes = guard_schema::registry_canonical_bytes(
            "mcp-node-execution",
            json!({"package":self.package.sha256(),"image":self.image,
            "entrypoint":self.entrypoint,"arguments":arguments,"hardening":HARDENING,
            "package_target":PACKAGE_TARGET,"recovery_label":"com.agentguard.mcp-session","gate_sha256":crate::tool_registry::digest(GATE.as_bytes())}),
        );
        Ok(crate::tool_registry::digest(&bytes))
    }

    /// 同一个启动器只允许一个活动服务；发现与授权运行使用不同进程及会话标识。
    pub fn spawn<'a>(
        &self,
        arguments: &[String],
        workspace: ServiceWorkspace<'a>,
    ) -> Result<ServiceProcess<'a>> {
        self.prepare(arguments, workspace)?
            .launch_with(|spawn| spawn())
    }

    /// 预分配不可变运行身份并冻结挂载范围；准备期间没有下游进程。
    /// 借用工作区直至进程退出，阻止同一执行器在后台服务存活时预览或回写。
    pub fn prepare<'a>(
        &self,
        arguments: &[String],
        workspace: ServiceWorkspace<'a>,
    ) -> Result<PreparedService<'a>> {
        let execution_sha256 = self.execution_sha256(arguments)?;
        ensure!(
            self.state.healthy.load(Ordering::SeqCst),
            "服务清理状态未知，不能启动新会话"
        );
        ensure!(
            self.state
                .active
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "该服务已有活动会话"
        );
        let mut lease = LaunchLease {
            state: self.state.clone(),
            package: self.package.clone(),
            name: None,
            empty_root: None,
            workspace: None,
            handed_off: false,
        };
        ensure!(
            self.state.healthy.load(Ordering::SeqCst),
            "取得启动槽时服务清理状态已改变"
        );
        self.package.verify()?;
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        ensure!(uid != 0, "第三方服务不允许以宿主 root 启动");
        let (mounts, discovery_only) = match workspace {
            ServiceWorkspace::Discovery | ServiceWorkspace::DiscoveryFor(_) => {
                let targets = match workspace {
                    ServiceWorkspace::DiscoveryFor(snapshot) => snapshot
                        .service_mounts(&self.image, &self.state.endpoint)?
                        .into_iter()
                        .map(|(_, target, _)| target)
                        .collect(),
                    _ => vec![PathBuf::from("/workspace")],
                };
                use std::os::unix::fs::DirBuilderExt;
                let root = std::env::temp_dir().join(format!(
                    "agentguard-mcp-empty-{}",
                    crate::browser_bridge::token()
                ));
                std::fs::DirBuilder::new().mode(0o700).create(&root)?;
                lease.empty_root = Some(root.clone());
                (
                    targets
                        .into_iter()
                        .map(|target| Ok((root.canonicalize()?, target, false)))
                        .collect::<Result<Vec<_>>>()?,
                    true,
                )
            }
            ServiceWorkspace::Snapshot(snapshot) => {
                let mounts = snapshot.service_mounts(&self.image, &self.state.endpoint)?;
                lease.workspace = Some(snapshot);
                (mounts, false)
            }
        };
        let scope_sha256 = crate::tool_registry::digest(&guard_schema::registry_canonical_bytes(
            "mcp-node-scope",
            json!({"version":1,"discovery_only":discovery_only,"mounts":mounts,"uid":uid,"gid":gid}),
        ));
        let package_path = self.package.path().canonicalize()?;
        let mut command = endpoint_command(&self.state.endpoint, HARDENING);
        let name = format!("agentguard-mcp-{}", crate::browser_bridge::token());
        command.args([
            "--name",
            &name,
            "--user",
            &format!("{uid}:{gid}"),
            "--workdir",
            "/tmp",
        ]);
        command.args([
            "--mount",
            &mount_argument(&package_path, Path::new(PACKAGE_TARGET), false)?,
        ]);
        for (source, target, writable) in &mounts {
            ensure!(
                !target.starts_with(PACKAGE_TARGET)
                    && !Path::new(PACKAGE_TARGET).starts_with(target),
                "工作区与服务包挂载重叠"
            );
            crate::isolation::open_absolute_dir(source)?;
            command.args(["--mount", &mount_argument(source, target, *writable)?]);
        }
        let service_session = format!("mcp-session-{}", crate::browser_bridge::token());
        command.args([
            "--label",
            &format!("com.agentguard.mcp-session={service_session}"),
        ]);
        let runtime_entry = format!("{PACKAGE_TARGET}/{}", self.entrypoint);
        command.args([
            &self.image,
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "HOME=/tmp",
            "TMPDIR=/tmp",
            "LANG=C.UTF-8",
            "/usr/bin/python3",
            "-I",
            "-c",
            GATE,
            &uid.to_string(),
            &gid.to_string(),
            &runtime_entry,
        ]);
        command.args(arguments);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let receipt = LaunchReceipt {
            session_id: service_session,
            package_sha256: self.package.sha256().clone(),
            execution_sha256,
            scope_sha256,
            image: self.image.clone(),
            discovery_only,
        };
        Ok(PreparedService {
            command,
            lease,
            name,
            receipt,
        })
    }

    pub fn healthy(&self) -> bool {
        self.state.healthy.load(Ordering::SeqCst)
    }
}

/// 已准备的运行身份只能启动一次；丢弃未批准的准备不会创建容器。
pub struct PreparedService<'a> {
    command: Command,
    lease: LaunchLease<'a>,
    name: String,
    receipt: LaunchReceipt,
}
impl<'a> PreparedService<'a> {
    pub fn receipt(&self) -> &LaunchReceipt {
        &self.receipt
    }
    pub fn container_name(&self) -> &str {
        &self.name
    }

    /// 宿主把开始审计与实际 spawn 放入撤权共用锁；回调不能等待协议响应。
    pub fn launch_with(
        mut self,
        authorize: impl FnOnce(&mut dyn FnMut() -> Result<Child>) -> Result<Child>,
    ) -> Result<ServiceProcess<'a>> {
        self.lease.package.verify()?;
        ensure!(
            self.lease.state.healthy.load(Ordering::SeqCst),
            "服务清理状态已失效"
        );
        let mut attempted = false;
        let child = authorize(&mut || {
            ensure!(!attempted, "一次准备只能尝试启动一次");
            attempted = true;
            // 从这里开始，即使客户端 spawn 失败，也必须核实容器是否已创建。
            self.lease.name = Some(self.name.clone());
            self.command.spawn().context("无法启动受控 Docker 客户端")
        })?;
        let client = StdioClient::attach(child)?;
        let process = ServiceProcess {
            client,
            state: self.lease.state.clone(),
            name: self.name.clone(),
            receipt: self.receipt.clone(),
            _package: self.lease.package.clone(),
            workspace: self.lease.workspace.take(),
            empty_root: self.lease.empty_root.take(),
            shutdown: None,
        };
        self.lease.handed_off = true;
        Ok(process)
    }
}

impl ServiceProcess<'_> {
    pub fn client(&mut self) -> &mut StdioClient {
        &mut self.client
    }
    /// 启动回执不能代替协议握手、登记认可或一次动作的成功证据。
    pub fn receipt(&self) -> &LaunchReceipt {
        &self.receipt
    }
    pub fn close(&mut self) -> Shutdown {
        if let Some(result) = self.shutdown {
            return result;
        }
        let graceful_exit = self.client.close();
        let container_removed = remove_container(&self.state.endpoint, &self.name);
        if !container_removed {
            self._package.retain_for_recovery();
            self.state.healthy.store(false, Ordering::SeqCst);
            if let Some(workspace) = &self.workspace {
                workspace.service_cleanup_unknown();
            }
        }
        if container_removed {
            if let Some(root) = self.empty_root.take() {
                let _ = std::fs::remove_dir_all(root);
            }
        }
        self.state.active.store(false, Ordering::SeqCst);
        let result = Shutdown {
            graceful_exit,
            container_removed,
        };
        self.shutdown = Some(result);
        result
    }
}
impl Drop for ServiceProcess<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

// 构造失败也释放活动槽；已尝试启动时不能只杀管道客户端。
struct LaunchLease<'a> {
    state: Arc<State>,
    package: Arc<FrozenPackage>,
    name: Option<String>,
    empty_root: Option<PathBuf>,
    workspace: Option<&'a DockerExecutor>,
    handed_off: bool,
}
impl Drop for LaunchLease<'_> {
    fn drop(&mut self) {
        if self.handed_off {
            return;
        }
        let removed = self
            .name
            .as_ref()
            .is_none_or(|name| remove_container(&self.state.endpoint, name));
        if !removed {
            self.package.retain_for_recovery();
            self.state.healthy.store(false, Ordering::SeqCst);
            if let Some(workspace) = &self.workspace {
                workspace.service_cleanup_unknown();
            }
        } else if let Some(root) = &self.empty_root {
            let _ = std::fs::remove_dir_all(root);
        }
        self.state.active.store(false, Ordering::SeqCst);
    }
}
pub(crate) fn remove_container(endpoint: &str, name: &str) -> bool {
    let _removed = run_command_with_cancel(
        endpoint_command(endpoint, &["rm", "--force", name]),
        Duration::from_secs(10),
        &|| false,
    );
    // --rm 与显式删除可能并行；无论删除命令如何返回，都独立查询最终状态。
    // 只重复有界只读查询，不再次发送删除，也不重新派发服务请求。
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = run_command_with_cancel(
            endpoint_command(
                endpoint,
                &["ps", "-aq", "--filter", &format!("name=^/{name}$")],
            ),
            deadline.saturating_duration_since(Instant::now()),
            &|| false,
        );
        if !remaining.ok || remaining.truncated {
            return false;
        }
        if remaining.detail.trim().is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}
fn validate_arguments(arguments: &[String]) -> Result<()> {
    ensure!(
        arguments.len() <= 64 && arguments.iter().map(String::len).sum::<usize>() <= 8192,
        "服务启动参数超过上限"
    );
    ensure!(
        arguments.iter().all(|a| !a.chars().any(char::is_control)),
        "服务启动参数含控制字符"
    );
    Ok(())
}
fn validate_image(image: &str) -> Result<()> {
    let Some(digest) = image.strip_prefix("sha256:") else {
        bail!("服务镜像必须使用本地 sha256 摘要");
    };
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "服务镜像摘要无效"
    );
    Ok(())
}
fn mount_argument(source: &Path, target: &Path, writable: bool) -> Result<String> {
    for path in [source, target] {
        ensure!(
            path.is_absolute()
                && path
                    .to_str()
                    .is_some_and(|s| !s.contains([',', '\n', '\r', '"'])),
            "服务挂载路径无效"
        );
    }
    Ok(format!(
        "type=bind,src={},dst={}{}",
        source.display(),
        target.display(),
        if writable { "" } else { ",readonly" }
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod registration_tests;
