use super::tests::docker_output;
use super::*;
use std::fs;
use std::os::unix::fs::DirBuilderExt;

#[test]
#[ignore = "需要既有 Docker 镜像、官方包和全新 AGD_MCP_REGISTRATION_OUTPUT 目录"]
fn 官方服务完整发现登记持久恢复和运行身份变化() {
    let source = PathBuf::from(std::env::var("AGD_MCP_FS_PACKAGE").unwrap())
        .canonicalize()
        .unwrap();
    let output = PathBuf::from(std::env::var("AGD_MCP_REGISTRATION_OUTPUT").unwrap());
    assert!(output.is_absolute());
    fs::DirBuilder::new().mode(0o700).create(&output).unwrap();
    let output = output.canonicalize().unwrap();
    let image = std::env::var("AGD_MCP_IMAGE").unwrap();
    let package = Arc::new(FrozenPackage::freeze(&source).unwrap());
    let service = NodeService::new(
        image.clone(),
        package.clone(),
        "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js".into(),
    )
    .unwrap();
    let registration = ServiceRegistration {
        service_id: "official-filesystem".into(),
        namespace: "filesystem".into(),
        package_id: "modelcontextprotocol-filesystem".into(),
        package_version: "2026.8.31".into(),
    };
    let mut checks = Vec::new();
    let args = vec!["/workspace".into()];
    // 独立会话先保存未经登记转换的实际协议结果，再与生产发现产物逐项比较。
    let mut raw_process = service.spawn(&args, ServiceWorkspace::Discovery).unwrap();
    let raw_initialization = raw_process
        .client()
        .initialize(Duration::from_secs(15), &|| false)
        .unwrap();
    let raw_listing = raw_process
        .client()
        .list_tools(Duration::from_secs(15), &|| false)
        .unwrap();
    fs::write(
        output.join("raw-initialization.json"),
        serde_json::to_vec_pretty(&raw_initialization).unwrap(),
    )
    .unwrap();
    fs::write(
        output.join("raw-listing.json"),
        serde_json::to_vec_pretty(&raw_listing).unwrap(),
    )
    .unwrap();
    assert!(raw_process.close().container_removed);
    checks.push("独立空工作区会话保存完整原始握手与清单，并核实容器清理");
    let first = service
        .discover(&registration, &args, Duration::from_secs(30), &|| false)
        .unwrap();
    assert_eq!(first.manifest().tools.len(), 14);
    assert_eq!(
        first.manifest().mcp.as_ref().unwrap().initialization,
        raw_initialization
    );
    let mut metadata = raw_listing.as_object().unwrap().clone();
    let raw_tools = metadata.remove("tools").unwrap();
    assert_eq!(
        first.manifest().mcp.as_ref().unwrap().list_metadata,
        Value::Object(metadata)
    );
    for raw in raw_tools.as_array().unwrap() {
        let tool = first
            .manifest()
            .tools
            .iter()
            .find(|t| raw["name"] == t.name)
            .unwrap();
        assert_eq!(tool.mcp.as_ref().unwrap(), raw);
        assert_eq!(raw["execution"], json!({"taskSupport":"forbidden"}));
    }
    assert!(first.manifest().tools.iter().all(|t| t.mcp.is_some()));
    assert_eq!(first.manifest().package.sha256, *package.sha256());
    assert_eq!(
        first.manifest().mcp.as_ref().unwrap().execution_sha256,
        service.execution_sha256(&args).unwrap()
    );
    assert!(first.receipt().discovery_only);
    let removed = docker_output(
        &service.state.endpoint,
        &[
            "ps",
            "-aq",
            "--filter",
            &format!("name=^/{}$", first.container_name()),
        ],
    );
    assert!(removed.ok && removed.detail.trim().is_empty());
    checks.push("官方服务完整发现 14 个工具，实际包与运行摘要一致，精确容器已不存在");
    fs::write(
        output.join("first-manifest.json"),
        serde_json::to_vec_pretty(first.manifest()).unwrap(),
    )
    .unwrap();
    let db = output.join("registry.db");
    let mut registry = crate::tool_registry::ToolRegistry::open(&db).unwrap();
    registry.observe_discovery(&first).unwrap();
    assert!(registry
        .binding("official-filesystem", "read_text_file")
        .is_err());
    assert!(registry
        .published("official-filesystem")
        .unwrap()
        .is_empty());
    let review = registry.review("official-filesystem").unwrap();
    assert_eq!(
        review["manifest"],
        serde_json::to_value(first.manifest()).unwrap()
    );
    assert_eq!(review["dispatch_supported"], false);
    registry
        .decide(
            "official-filesystem",
            review["review_id"].as_str().unwrap(),
            review["review_nonce"].as_str().unwrap(),
            review["manifest_sha256"].as_str().unwrap(),
            true,
        )
        .unwrap();
    let binding = registry
        .binding("official-filesystem", "read_text_file")
        .unwrap();
    let published = registry.published("official-filesystem").unwrap();
    assert_eq!(published.len(), 14);
    for tool in &first.manifest().tools {
        let value = published
            .iter()
            .find(|p| p["name"] == format!("mcp__filesystem__{}", tool.name))
            .unwrap();
        for (key, original) in tool.mcp.as_ref().unwrap().as_object().unwrap() {
            if key == "name" {
                continue;
            }
            if key == "_meta" {
                assert_eq!(
                    &value["_meta"]["agentguard"]["downstream_metadata"],
                    original
                );
            } else {
                assert_eq!(&value[key], original, "{} {key}", tool.name);
            }
        }
    }
    checks.push("发现不自动认可，独立复核后 14 个公开别名完整保留元数据，仍不声明产品派发已开放");
    drop(registry);
    let mut registry = crate::tool_registry::ToolRegistry::open(&db).unwrap();
    assert!(registry
        .binding("official-filesystem", "read_text_file")
        .is_err());
    let second = service
        .discover(&registration, &args, Duration::from_secs(30), &|| false)
        .unwrap();
    assert_ne!(first.receipt().session_id, second.receipt().session_id);
    assert_eq!(
        first.manifest().canonical_bytes(),
        second.manifest().canonical_bytes()
    );
    registry.observe_discovery(&second).unwrap();
    assert_eq!(
        registry
            .binding("official-filesystem", "read_text_file")
            .unwrap(),
        binding
    );
    assert!(registry
        .decide(
            "official-filesystem",
            review["review_id"].as_str().unwrap(),
            review["review_nonce"].as_str().unwrap(),
            review["manifest_sha256"].as_str().unwrap(),
            true
        )
        .is_err());
    checks.push("重启仅凭摘要不能调用，真实新会话重新发现后恢复同一绑定，旧复核不可重放");
    let changed = service
        .discover(
            &registration,
            &["/workspace".into(), "/tmp".into()],
            Duration::from_secs(30),
            &|| false,
        )
        .unwrap();
    assert_ne!(
        first.receipt().execution_sha256,
        changed.receipt().execution_sha256
    );
    registry.observe_discovery(&changed).unwrap();
    assert!(registry
        .verify("official-filesystem", "read_text_file", &binding)
        .is_err());
    assert!(registry
        .published("official-filesystem")
        .unwrap()
        .is_empty());
    fs::write(
        output.join("changed-manifest.json"),
        serde_json::to_vec_pretty(changed.manifest()).unwrap(),
    )
    .unwrap();
    checks.push("实际启动参数改变运行身份，新发现使旧认可失效并撤下待复核工具");
    drop(registry);
    let store = guard_audit::AuditStore::open_read_only(&db).unwrap();
    assert!(store.verify_chain().unwrap().ok);
    let export = store.export_jsonl(20).unwrap();
    assert_eq!(store.tool_registrations(20).unwrap().len(), 3);
    for tool in &first.manifest().tools {
        if !tool.description.is_empty() {
            assert!(!export.contains(&tool.description));
        }
    }
    fs::write(output.join("audit.jsonl"), export).unwrap();
    checks.push("三条持久登记事件验链通过，日志未保存工具描述原文");
    for observed in [&first, &second, &changed] {
        let removed = docker_output(
            &service.state.endpoint,
            &[
                "ps",
                "-aq",
                "--filter",
                &format!("name=^/{}$", observed.container_name()),
            ],
        );
        assert!(removed.ok && removed.detail.trim().is_empty());
    }
    assert!(service.healthy() && !service.state.active.load(Ordering::SeqCst));
    checks.push("三个发现会话的容器分别核实已删除，没有活动启动槽");
    let probe_source = output.join("probe-package");
    fs::create_dir(&probe_source).unwrap();
    fs::write(
        probe_source.join("index.mjs"),
        include_str!("../../tests/fixtures/mcp_discovery_probe.mjs"),
    )
    .unwrap();
    let probe = NodeService::new(
        image.clone(),
        Arc::new(FrozenPackage::freeze(&probe_source).unwrap()),
        "index.mjs".into(),
    )
    .unwrap();
    let before = docker_output(
        &probe.state.endpoint,
        &["ps", "-aq", "--filter", "name=^/agentguard-mcp-"],
    );
    assert!(before.ok);
    for (mode, timeout) in [
        ("unsupported", Duration::from_secs(15)),
        ("timeout", Duration::from_secs(5)),
    ] {
        let failure = probe
            .discover(&registration, &[mode.into()], timeout, &|| false)
            .err()
            .expect("负例必须拒绝发现");
        fs::write(output.join(format!("negative-{mode}.json")), serde_json::to_vec_pretty(&json!({
            "error":failure.to_string(),"healthy":probe.healthy(),"active":probe.state.active.load(Ordering::SeqCst)
        })).unwrap()).unwrap();
        if mode == "unsupported" {
            assert!(
                failure
                    .downcast_ref::<guard_schema::ToolRegistryError>()
                    .is_some(),
                "{failure:#}"
            );
        } else {
            let failure = failure
                .downcast_ref::<crate::mcp_stdio::Failure>()
                .unwrap_or_else(|| panic!("预期实际传输超时，实际为：{failure:#}"));
            assert_eq!(failure.kind, crate::mcp_stdio::FailureKind::Timeout);
            assert!(failure.dispatched);
        }
        assert!(probe.healthy() && !probe.state.active.load(Ordering::SeqCst));
        let after = docker_output(
            &probe.state.endpoint,
            &["ps", "-aq", "--filter", "name=^/agentguard-mcp-"],
        );
        assert!(after.ok);
        assert_eq!(before.detail, after.detail);
    }
    checks.push("真实服务不支持的执行字段与发现超时均拒绝交付，容器集合未增加，启动槽释放");
    fs::write(output.join("report.json"),serde_json::to_vec_pretty(&json!({"passed":true,"checks":checks,"image":image,
        "package_sha256":package.sha256(),"first_manifest_sha256":crate::tool_registry::digest(&first.manifest().canonical_bytes()),
        "first_manifest_bytes":serde_json::to_vec(first.manifest()).unwrap().len(),"tools":14,"audit_rows":3,
        "receipts":[first.receipt(),second.receipt(),changed.receipt()],
        "test_binary_sha256":crate::tool_registry::digest(&fs::read(std::env::current_exe().unwrap()).unwrap())})).unwrap()).unwrap();
}
