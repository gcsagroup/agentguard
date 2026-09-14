use super::*;
use crate::mcp_stdio::{FailureKind, Reply};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

const PROBE: &str = include_str!("../../tests/fixtures/mcp_isolation_probe.mjs");

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agd-service-test-{}",
            crate::browser_bridge::token()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn package(&self) -> Arc<FrozenPackage> {
        let path = self.0.join("package");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("index.mjs"), PROBE).unwrap();
        Arc::new(FrozenPackage::freeze(&path).unwrap())
    }
    fn isolated_identity(&self) -> NodeService {
        // 仅测试本地身份计算与派发前拒绝，不创建 Docker 连接。
        NodeService {
            package: self.package(),
            image: format!("sha256:{}", "a".repeat(64)),
            entrypoint: "index.mjs".into(),
            state: Arc::new(State {
                endpoint: "unix:///synthetic-missing/socket".into(),
                healthy: AtomicBool::new(true),
                active: AtomicBool::new(false),
            }),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn 运行身份绑定镜像入口参数和实际冻结包() {
    let fixture = Fixture::new();
    let mut service = fixture.isolated_identity();
    let args = vec!["/workspace".into()];
    let identity = service.execution_sha256(&args).unwrap();
    assert_eq!(identity, service.execution_sha256(&args).unwrap());
    assert_ne!(
        identity,
        service.execution_sha256(&["/other".into()]).unwrap()
    );
    service.entrypoint = "other.mjs".into();
    assert_ne!(identity, service.execution_sha256(&args).unwrap());
    service.entrypoint = "index.mjs".into();
    service.image = format!("sha256:{}", "b".repeat(64));
    assert_ne!(identity, service.execution_sha256(&args).unwrap());
    service.image = format!("sha256:{}", "a".repeat(64));
    let other = fixture.0.join("other");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("index.mjs"), "process.exit(0)").unwrap();
    service.package = Arc::new(FrozenPackage::freeze(&other).unwrap());
    assert_ne!(identity, service.execution_sha256(&args).unwrap());
}

#[test]
fn 无效镜像入口参数与挂载在创建进程前拒绝() {
    let fixture = Fixture::new();
    let service = fixture.isolated_identity();
    for image in [
        "latest".to_owned(),
        "sha256:abc".into(),
        format!("sha256:{}", "A".repeat(64)),
    ] {
        assert!(validate_image(&image).is_err());
    }
    assert!(NodeService::new(
        service.image.clone(),
        service.package.clone(),
        "../outside".into()
    )
    .is_err());
    assert!(validate_arguments(&vec!["x".into(); 65]).is_err());
    assert!(validate_arguments(&["x".repeat(8193)]).is_err());
    assert!(validate_arguments(&["bad\nvalue".into()]).is_err());
    for path in ["relative", "/tmp/a,b", "/tmp/a\n"] {
        assert!(mount_argument(Path::new(path), Path::new("/workspace"), false).is_err());
    }
}

#[test]
fn 故障与活动状态拒绝新会话且构造失败释放活动槽() {
    let fixture = Fixture::new();
    let service = fixture.isolated_identity();
    service.state.healthy.store(false, Ordering::SeqCst);
    assert!(service.spawn(&[], ServiceWorkspace::Discovery).is_err());
    assert!(!service.state.active.load(Ordering::SeqCst));
    service.state.healthy.store(true, Ordering::SeqCst);
    service.state.active.store(true, Ordering::SeqCst);
    assert!(service.spawn(&[], ServiceWorkspace::Discovery).is_err());
    assert!(service.state.active.load(Ordering::SeqCst));
    service.state.active.store(false, Ordering::SeqCst);
    let file = service.package.path().join("index.mjs");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, "replaced").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(service.spawn(&[], ServiceWorkspace::Discovery).is_err());
    assert!(!service.state.active.load(Ordering::SeqCst));
}

struct RescueContainer {
    endpoint: String,
    name: String,
}
impl Drop for RescueContainer {
    fn drop(&mut self) {
        remove_container(&self.endpoint, &self.name);
    }
}

fn docker_output(endpoint: &str, args: &[&str]) -> crate::ExecOutput {
    run_command_with_cancel(
        endpoint_command(endpoint, args),
        Duration::from_secs(10),
        &|| false,
    )
}
fn call(process: &mut ServiceProcess, name: &str, arguments: Value) -> Value {
    let Reply::Result(result) = process
        .client()
        .call_tool(name, arguments, Duration::from_secs(15), &|| false)
        .unwrap()
    else {
        panic!("预期 MCP 工具结果");
    };
    result
}
fn initialize(process: &mut ServiceProcess) -> Value {
    process
        .client()
        .initialize(Duration::from_secs(15), &|| false)
        .unwrap();
    process
        .client()
        .list_tools(Duration::from_secs(15), &|| false)
        .unwrap()
}

#[test]
#[ignore = "需要既有 Docker 镜像、官方 Filesystem 包和全新的自有输出目录"]
fn 生产启动器的官方服务隔离冻结内核拒绝和完整清理() {
    use sha2::{Digest, Sha256};
    let image = std::env::var("AGD_MCP_IMAGE").expect("AGD_MCP_IMAGE");
    let source_package =
        PathBuf::from(std::env::var("AGD_MCP_FS_PACKAGE").expect("AGD_MCP_FS_PACKAGE"))
            .canonicalize()
            .unwrap();
    let output =
        PathBuf::from(std::env::var("AGD_MCP_SERVICE_OUTPUT").expect("AGD_MCP_SERVICE_OUTPUT"));
    assert!(output.is_absolute());
    fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
    let output = output.canonicalize().unwrap();
    let frozen = Arc::new(FrozenPackage::freeze(&source_package).unwrap());
    fs::write(
        output.join("official-package-manifest.json"),
        serde_json::to_vec_pretty(&frozen.manifest()).unwrap(),
    )
    .unwrap();
    assert_eq!(frozen.file_count(), 4034);
    let official = NodeService::new(
        image.clone(),
        frozen.clone(),
        "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js".into(),
    )
    .unwrap();
    let endpoint = official.state.endpoint.clone();
    let mut checks = Vec::new();
    checks.push("官方包完整冻结 4034 文件和两条包内链接");
    let mut discovery = official
        .spawn(&["/workspace".into()], ServiceWorkspace::Discovery)
        .unwrap();
    let discovery_receipt = discovery.receipt().clone();
    let listing = initialize(&mut discovery);
    assert_eq!(listing["tools"].as_array().unwrap().len(), 14);
    assert!(official
        .spawn(&["/workspace".into()], ServiceWorkspace::Discovery)
        .is_err());
    checks.push("真实发现 14 项工具且同一启动器拒绝并发第二个会话");
    let inspect = docker_output(&endpoint, &["inspect", &discovery.name]);
    assert!(inspect.ok);
    let inspected: Value = serde_json::from_str(&inspect.detail).unwrap();
    assert_eq!(inspected[0]["HostConfig"]["NetworkMode"], "none");
    assert_eq!(inspected[0]["HostConfig"]["ReadonlyRootfs"], true);
    assert_eq!(inspected[0]["HostConfig"]["CapDrop"], json!(["ALL"]));
    assert!(inspected[0]["Mounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["Type"] == "bind")
        .all(|m| m["RW"] == false));
    assert_eq!(
        inspected[0]["Mounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["Type"] == "bind")
            .count(),
        2
    );
    checks.push("容器外核对发现阶段只读包加空工作区且禁网");
    let denied = call(
        &mut discovery,
        "write_file",
        json!({"path":"/workspace/denied.txt","content":"SYNTHETIC"}),
    );
    assert_eq!(denied["isError"], true);
    let empty = discovery.empty_root.clone().unwrap();
    assert!(!empty.join("denied.txt").exists());
    checks.push("发现阶段实际写入被只读挂载拒绝");
    let closed = discovery.close();
    assert!(closed.graceful_exit && closed.container_removed && !empty.exists());
    checks.push("发现会话正常退出且容器和空目录已清理");

    let work = output.join("workspace-source");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("input.txt"), "SYNTHETIC_INPUT\n").unwrap();
    let target = guard_schema::paths::dealias_platform_volumes(&work)
        .to_str()
        .unwrap()
        .to_owned();
    let snapshot = Arc::new(
        DockerExecutor::new(
            image.clone(),
            std::slice::from_ref(&target),
            std::slice::from_ref(&target),
        )
        .unwrap(),
    );
    let snapshot_view = snapshot.workspaces();
    let snapshot_path = PathBuf::from(snapshot_view[0]["snapshot"].as_str().unwrap());
    let mut running = official
        .spawn(
            std::slice::from_ref(&target),
            ServiceWorkspace::Snapshot(snapshot.clone()),
        )
        .unwrap();
    let running_receipt = running.receipt().clone();
    assert_ne!(discovery_receipt.session_id, running_receipt.session_id);
    assert_ne!(discovery_receipt.scope_sha256, running_receipt.scope_sha256);
    initialize(&mut running);
    assert_eq!(
        call(
            &mut running,
            "read_text_file",
            json!({"path":format!("{target}/input.txt")})
        )["content"][0]["text"],
        "SYNTHETIC_INPUT\n"
    );
    checks.push("新会话绑定授权副本范围并真实读取");
    let written = call(
        &mut running,
        "write_file",
        json!({"path":format!("{target}/result.txt"),"content":"SYNTHETIC_RESULT\n"}),
    );
    assert_ne!(written["isError"], true);
    assert_eq!(
        fs::read_to_string(snapshot_path.join("result.txt")).unwrap(),
        "SYNTHETIC_RESULT\n"
    );
    assert!(!work.join("result.txt").exists());
    assert_eq!(
        fs::read_to_string(work.join("input.txt")).unwrap(),
        "SYNTHETIC_INPUT\n"
    );
    checks.push("实际写入仅改变隔离副本，宿主原件没有自动回写");
    assert_eq!(
        call(
            &mut running,
            "read_text_file",
            json!({"path":"/etc/hostname"})
        )["isError"],
        true
    );
    checks.push("服务自身仍拒绝声明范围外路径");
    let closed = running.close();
    assert!(closed.graceful_exit && closed.container_removed);

    let probe_root = output.join("probe-package");
    fs::create_dir(&probe_root).unwrap();
    fs::write(probe_root.join("index.mjs"), PROBE).unwrap();
    let probe_package = Arc::new(FrozenPackage::freeze(&probe_root).unwrap());
    let mut probe =
        NodeService::new(image.clone(), probe_package.clone(), "index.mjs".into()).unwrap();
    let canary = output.join("outside-canary.txt");
    fs::write(&canary, "SYNTHETIC_NOT_MOUNTED\n").unwrap();
    let args = vec![target.clone(), canary.to_str().unwrap().into()];
    // 修改原始入口，实际服务仍必须从冻结字节启动。
    fs::write(
        probe_root.join("index.mjs"),
        "throw new Error('不得执行替换后的原件');",
    )
    .unwrap();
    let mut process = probe
        .spawn(&args, ServiceWorkspace::Snapshot(snapshot.clone()))
        .unwrap();
    initialize(&mut process);
    let result = call(&mut process, "probe", json!({}));
    let status: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(status["startupWrite"], true);
    assert!(snapshot_path.join("startup.txt").exists() && !work.join("startup.txt").exists());
    assert_eq!(status["outsideReadable"], false);
    assert_eq!(status["network"], "ENETUNREACH");
    assert_eq!(
        status["environmentKeys"],
        json!(["HOME", "LANG", "PATH", "TMPDIR"])
    );
    checks.push("原包替换不改变运行字节，启动期变更也仅发生于已授权副本");
    checks.push("真实服务无法读取未挂载金丝雀，环境清空且外连被内核拒绝");
    let failure = process
        .client()
        .call_tool("hang", json!({}), Duration::from_millis(800), &|| false)
        .unwrap_err();
    assert_eq!(failure.kind, FailureKind::Timeout);
    assert!(failure.dispatched);
    assert_eq!(
        fs::read_to_string(snapshot_path.join("calls.jsonl")).unwrap(),
        "ONE_CALL\n"
    );
    assert_eq!(
        process
            .client()
            .call_tool("hang", json!({}), Duration::from_secs(1), &|| false)
            .unwrap_err()
            .kind,
        FailureKind::State
    );
    assert!(snapshot_path.join("pulse.txt").exists());
    let closed = process.close();
    assert!(!closed.graceful_exit && closed.container_removed);
    let pulse = fs::read(snapshot_path.join("pulse.txt")).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(pulse, fs::read(snapshot_path.join("pulse.txt")).unwrap());
    checks.push("派发后超时不重试，关闭时删除整棵容器进程树，子进程心跳实际停止");
    drop(process);

    let mut process = probe
        .spawn(&args, ServiceWorkspace::Snapshot(snapshot.clone()))
        .unwrap();
    initialize(&mut process);
    let rescue = RescueContainer {
        endpoint: endpoint.clone(),
        name: process.name.clone(),
    };
    let unknown = Arc::new(State {
        endpoint: format!("unix://{}/missing-docker.sock", output.display()),
        healthy: AtomicBool::new(true),
        active: AtomicBool::new(true),
    });
    process.state = unknown.clone();
    probe.state = unknown;
    let closed = process.close();
    assert!(!closed.container_removed && !probe.healthy());
    assert!(probe_package.retained_path().is_some_and(Path::exists));
    assert_eq!(snapshot.status()["healthy"], false);
    let denied_write = snapshot.execute(
        &crate::ToolCall::WriteFile {
            path: PathBuf::from(&target).join("must-not-write.txt"),
            contents: "SYNTHETIC_REFUSED".into(),
        },
        &|| false,
    );
    assert!(!denied_write.ok && !denied_write.dispatched);
    assert!(!snapshot_path.join("must-not-write.txt").exists());
    assert!(probe
        .spawn(&args, ServiceWorkspace::Snapshot(snapshot.clone()))
        .is_err());
    assert!(remove_container(&rescue.endpoint, &rescue.name));
    checks.push("受控模拟清理连接丢失，启动器与共享副本均保持故障关闭；另行核实自有容器清理");

    // 去掉一项真实内核约束时，门禁必须在第三方脚本运行前退出。
    let mut kernel_denials = Vec::new();
    for mode in ["root", "no-new-privileges", "seccomp"] {
        let marker = output.join(format!("gate-{mode}"));
        fs::create_dir(&marker).unwrap();
        let name = format!("agentguard-mcp-negative-{}", crate::browser_bridge::token());
        let rescue = RescueContainer {
            endpoint: endpoint.clone(),
            name: name.clone(),
        };
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut command = endpoint_command(
            &endpoint,
            &[
                "run",
                "--pull=never",
                "--rm",
                "--name",
                &name,
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--pids-limit=64",
                "--memory=256m",
                "--entrypoint=/usr/bin/env",
            ],
        );
        if mode != "no-new-privileges" {
            command.arg("--security-opt=no-new-privileges:true");
        }
        if mode == "seccomp" {
            command.arg("--security-opt=seccomp=unconfined");
        }
        command.args([
            "--user",
            &if mode == "root" {
                "0:0".into()
            } else {
                format!("{uid}:{gid}")
            },
            "--mount",
            &mount_argument(&probe_package.path(), Path::new(PACKAGE_TARGET), false).unwrap(),
            "--mount",
            &mount_argument(&marker, Path::new("/workspace"), true).unwrap(),
            &image,
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "/usr/bin/python3",
            "-I",
            "-c",
            GATE,
            &uid.to_string(),
            &gid.to_string(),
            &format!("{PACKAGE_TARGET}/index.mjs"),
            "/workspace",
            "/missing-canary",
        ]);
        let denial = run_command_with_cancel(command, Duration::from_secs(10), &|| false);
        assert!(
            !denial.ok && denial.detail.contains("AgentGuard 服务启动约束未满足"),
            "{mode}: {}",
            denial.detail
        );
        assert!(!marker.join("startup.txt").exists());
        assert!(remove_container(&rescue.endpoint, &rescue.name));
        kernel_denials.push(mode);
    }
    checks.push("root、缺少禁止提权和 seccomp 未启用三种真实配置均在第三方代码前拒绝");
    let retained_package = probe_package.retained_path().unwrap().to_path_buf();
    drop(process);
    drop(probe);
    drop(probe_package);
    assert!(retained_package.exists());
    checks.push("清理曾未知的冻结包在所有所有者释放后仍保留供核查");
    assert_eq!(
        fs::read_to_string(canary).unwrap(),
        "SYNTHETIC_NOT_MOUNTED\n"
    );
    let report = json!({"passed":true,"checks":checks,"image":image,"official_frozen_package":frozen.sha256(),
        "discovery_receipt":discovery_receipt,"snapshot_receipt":running_receipt,"probe":status,"kernel_denials":kernel_denials,
        "workspace_source":work,"workspace_snapshot":snapshot_path,"original_workspace_unchanged":true,
        "retained_probe_package":retained_package,
        "test_binary_sha256":format!("{:x}",Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())),
        "scope":"生产隔离启动器与实际服务；产品登记批准审计和远程代理仍未接线"});
    fs::write(
        output.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "{} 项真实启动与隔离检查通过；报告：{}",
        checks.len(),
        output.join("report.json").display()
    );
}
