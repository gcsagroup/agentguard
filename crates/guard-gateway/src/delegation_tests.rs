//! 使用随机宿主密钥验证认证器；真正 CLI、批准和隔离副作用另做实操。
use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
struct Fixture {
    root: PathBuf,
    authority: DelegationAuthority,
    a: FileDeviceKey,
    b: FileDeviceKey,
    c: FileDeviceKey,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(id("agd-delegation-test").as_str());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let work = root.join("work");
        fs::create_dir(&work).unwrap();
        let signing = FileDeviceKey::generate();
        let a = FileDeviceKey::generate();
        let b = FileDeviceKey::generate();
        let c = FileDeviceKey::generate();
        let signing_path = root.join("signing.hex");
        fs::write(&signing_path, signing.secret_hex()).unwrap();
        fs::set_permissions(&signing_path, fs::Permissions::from_mode(0o600)).unwrap();
        let permissions = DelegationPermissions {
            read_files: vec![
                work.join("a.txt").to_string_lossy().into(),
                work.join("b.txt").to_string_lossy().into(),
            ],
            write_files: vec![work.join("a.txt").to_string_lossy().into()],
            delete_files: vec![work.join("a.txt").to_string_lossy().into()],
            delegate_to: vec![
                ValidatedId::new("B").unwrap(),
                ValidatedId::new("C").unwrap(),
            ],
        };
        let mut limited = permissions.clone();
        limited.delete_files.clear();
        limited.read_files.truncate(1);
        limited.delegate_to.remove(0);
        let mut readonly = limited.clone();
        readonly.write_files.clear();
        readonly.delegate_to.clear();
        let principals = vec![
            ("A", &a, permissions),
            ("B", &b, limited),
            ("C", &c, readonly),
        ]
        .into_iter()
        .map(|(subject, key, permissions)| DelegationPrincipal {
            subject_id: ValidatedId::new(subject).unwrap(),
            public_key: key.verifying_key().to_hex(),
            permissions,
        })
        .collect();
        let config = DelegationConfig {
            version: 1,
            authority_id: ValidatedId::new("host").unwrap(),
            signing_key: signing_path,
            public_key: signing.verifying_key().to_hex(),
            root_subject_id: ValidatedId::new("A").unwrap(),
            target_id: ValidatedId::new("bounded-task").unwrap(),
            lifetime_ms: 60000,
            principals,
        };
        let (shell, rejected) = guard_shell::SafeShell::from_default_policy().with_workspace(
            vec![work.to_string_lossy().into_owned()],
            vec![work.to_string_lossy().into_owned()],
        );
        assert!(rejected.is_empty());
        let mut authority = config.open(shell.workspace()).unwrap();
        authority.start("host-session", 1000).unwrap();
        Self {
            root,
            authority,
            a,
            b,
            c,
        }
    }
    fn root_grant(&self) -> SignedDelegationGrant {
        self.authority.grants[self.authority.root.as_ref().unwrap()]
            .signed
            .clone()
    }
    fn command(&self) -> DelegationCommand {
        DelegationCommand::ReadFile {
            path: self.root.join("work/a.txt").to_string_lossy().into(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn message(
    grant: &SignedDelegationGrant,
    command: DelegationCommand,
    seq: u64,
    signer: &FileDeviceKey,
) -> DelegationEnvelope {
    let g = &grant.grant;
    let message = DelegationMessage {
        version: 1,
        host_session_id: g.host_session_id.clone(),
        session_id: g.session_id.clone(),
        grant_id: g.grant_id.clone(),
        grant_sha256: grant_digest(g).unwrap(),
        actor_id: g.subject_id.clone(),
        target_id: g.target_id.clone(),
        sequence: seq,
        issued_at_ms: 1010,
        expires_at_ms: 2000,
        operation_sha256: crate::tool_registry::digest(&command.binding_bytes().unwrap()),
    };
    let signature = signer
        .sign_message(&message.signing_bytes().unwrap())
        .unwrap();
    DelegationEnvelope {
        message,
        command,
        signature,
    }
}
fn resign(envelope: &mut DelegationEnvelope, key: &FileDeviceKey) {
    envelope.signature = key
        .sign_message(&envelope.message.signing_bytes().unwrap())
        .unwrap();
}

#[test]
fn 三层真实签名权限逐级取交集() {
    let mut f = Fixture::new();
    let root = f.root_grant();
    let command = DelegationCommand::Delegate {
        subject_id: ValidatedId::new("B").unwrap(),
        permissions: root.grant.permissions.clone(),
        expires_at_ms: 90000,
    };
    let verified = f
        .authority
        .authenticate(message(&root, command, 1, &f.a), "host-session", 1011)
        .unwrap();
    let b = f.authority.child(&verified, 1011).unwrap().unwrap();
    assert_eq!(
        b.grant.parent_session_id,
        Some(root.grant.session_id.clone())
    );
    assert_eq!(
        b.grant.parent_grant_sha256,
        Some(grant_digest(&root.grant).unwrap())
    );
    assert!(b.grant.permissions.delete_files.is_empty());
    assert_eq!(b.grant.permissions.read_files.len(), 1);
    assert_eq!(b.grant.expires_at_ms, root.grant.expires_at_ms);
    f.authority
        .consume(&verified, Some(b.clone()), 1011)
        .unwrap();
    let command = DelegationCommand::Delegate {
        subject_id: ValidatedId::new("C").unwrap(),
        permissions: root.grant.permissions.clone(),
        expires_at_ms: 90000,
    };
    let mut request = message(&b, command, 1, &f.b);
    request.message.issued_at_ms = 1012;
    resign(&mut request, &f.b);
    let verified = f
        .authority
        .authenticate(request, "host-session", 1012)
        .unwrap();
    let c = f.authority.child(&verified, 1012).unwrap().unwrap();
    assert!(
        c.grant.permissions.write_files.is_empty()
            && c.grant.permissions.delete_files.is_empty()
            && c.grant.permissions.delegate_to.is_empty()
    );
    f.authority
        .consume(&verified, Some(c.clone()), 1012)
        .unwrap();
    let mut request = message(&c, f.command(), 1, &f.c);
    request.message.issued_at_ms = 1013;
    resign(&mut request, &f.c);
    assert!(f
        .authority
        .authenticate(request, "host-session", 1013)
        .is_ok());
    let mut denied = message(
        &c,
        DelegationCommand::WriteFile {
            path: f.root.join("work/a.txt").to_string_lossy().into(),
            contents: "不应写入".into(),
        },
        1,
        &f.c,
    );
    denied.message.issued_at_ms = 1013;
    resign(&mut denied, &f.c);
    assert!(f
        .authority
        .authenticate(denied, "host-session", 1013)
        .is_err());
}

#[test]
fn 头部每个字段及操作正文都受签名约束() {
    let f = Fixture::new();
    let original = message(&f.root_grant(), f.command(), 1, &f.a);
    let value = serde_json::to_value(&original.message).unwrap();
    for field in value.as_object().unwrap().keys() {
        let mut changed = serde_json::to_value(&original).unwrap();
        let value = &mut changed["message"][field];
        if value.is_number() {
            *value = json!(value.as_u64().unwrap() + 1);
        } else {
            *value = json!(if field.ends_with("sha256") {
                "b".repeat(64)
            } else {
                "different".into()
            });
        }
        let parsed = serde_json::from_value(changed).unwrap();
        assert!(
            f.authority
                .authenticate(parsed, "host-session", 1011)
                .is_err(),
            "{field}"
        );
    }
    let mut changed = original.clone();
    changed.command = DelegationCommand::ReadFile {
        path: f.root.join("work/b.txt").to_string_lossy().into(),
    };
    assert!(f
        .authority
        .authenticate(changed, "host-session", 1011)
        .is_err());
    let mut forged = original;
    forged.signature =
        f.b.sign_message(&forged.message.signing_bytes().unwrap())
            .unwrap();
    assert!(f
        .authority
        .authenticate(forged, "host-session", 1011)
        .is_err());
}

#[test]
fn 重新签名也不能冒用其它主体会话目标或父授权() {
    let f = Fixture::new();
    let original = message(&f.root_grant(), f.command(), 1, &f.a);
    for field in [
        "host_session_id",
        "session_id",
        "actor_id",
        "target_id",
        "grant_id",
        "grant_sha256",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["message"][field] = json!(if field == "actor_id" {
            "B".into()
        } else if field.ends_with("sha256") {
            "a".repeat(64)
        } else {
            "other".into()
        });
        let mut changed: DelegationEnvelope = serde_json::from_value(value).unwrap();
        resign(&mut changed, if field == "actor_id" { &f.b } else { &f.a });
        assert!(
            f.authority
                .authenticate(changed, "host-session", 1011)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn 重放乱序和失效消息不推进有效序号() {
    let mut f = Fixture::new();
    let original = message(&f.root_grant(), f.command(), 1, &f.a);
    let mut future = original.clone();
    future.message.sequence = 2;
    resign(&mut future, &f.a);
    assert!(f
        .authority
        .authenticate(future, "host-session", 1011)
        .is_err());
    assert!(f
        .authority
        .authenticate(original.clone(), "host-session", 2000)
        .is_err());
    assert!(f
        .authority
        .authenticate(original.clone(), "host-session", 1009)
        .is_err());
    let verified = f
        .authority
        .authenticate(original.clone(), "host-session", 1011)
        .unwrap();
    f.authority.consume(&verified, None, 1011).unwrap();
    assert!(f
        .authority
        .authenticate(original.clone(), "host-session", 1012)
        .is_err());
    assert!(f.authority.consume(&verified, None, 1012).is_err());
    assert!(f
        .authority
        .revalidate(&verified, "host-session", 2000)
        .is_err());
    f.authority.start("new-host-session", 1015).unwrap();
    assert!(f
        .authority
        .authenticate(original, "new-host-session", 1015)
        .is_err());
    assert!(f
        .authority
        .revalidate(&verified, "new-host-session", 1015)
        .is_err());
}

#[test]
fn 伪造授权摘要与超期头部不能恢复被交集删掉的权限() {
    let f = Fixture::new();
    let mut grant = f.root_grant();
    grant
        .grant
        .permissions
        .read_files
        .push(f.root.join("work/z-private.txt").to_string_lossy().into());
    let changed = message(
        &grant,
        DelegationCommand::ReadFile {
            path: f.root.join("work/z-private.txt").to_string_lossy().into(),
        },
        1,
        &f.a,
    );
    assert!(f
        .authority
        .authenticate(changed, "host-session", 1011)
        .is_err());
    let mut changed = message(&f.root_grant(), f.command(), 1, &f.a);
    changed.message.expires_at_ms = 61001;
    resign(&mut changed, &f.a);
    assert!(f
        .authority
        .authenticate(changed, "host-session", 1011)
        .is_err());
}

#[test]
fn 拒绝弱公钥公开夹具密钥及含糊编码() {
    assert!(key(&format!("01{}", "00".repeat(31))).is_err());
    assert!(key("bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5").is_err());
    let generated = FileDeviceKey::generate().verifying_key().to_hex();
    assert!(key(&format!(" {generated}")).is_err());
    assert!(key(&generated.to_uppercase()).is_err());
    assert!(signature(&"FF".repeat(64)).is_err());
}

#[test]
#[ignore = "需显式提供已有 Docker 镜像；串行实测，不下载镜像"]
fn 委托实际隔离后端不能读取宿主私钥() {
    use crate::{isolation::DockerExecutor, ToolCall};
    let f = Fixture::new();
    let work = f.root.join("work");
    fs::write(work.join("a.txt"), "合成工作区可读\n").unwrap();
    for (name, key) in [("a", &f.a), ("b", &f.b), ("c", &f.c)] {
        let path = f.root.join(format!("{name}.hex"));
        fs::write(&path, key.secret_hex()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let image = std::env::var("AGD_DELEGATION_TEST_IMAGE").expect("显式指定已有镜像摘要");
    let roots = vec![work.to_string_lossy().into_owned()];
    let backend = DockerExecutor::new(image, &roots, &roots).unwrap();
    let read = |path: PathBuf| {
        backend.execute_with_file_scope(&ToolCall::ReadFile { path }, &|| false, true)
    };
    let ordinary = read(work.join("a.txt"));
    assert!(ordinary.ok && ordinary.dispatched, "{ordinary:?}");
    assert!(ordinary.detail.contains("合成工作区可读"));
    // 直接调用真实执行器，排除仅靠网关提前拒绝而未验证容器挂载的假阳性。
    for name in ["signing", "a", "b", "c"] {
        let path = f.root.join(format!("{name}.hex"));
        let secret = fs::read_to_string(&path).unwrap();
        let result = read(path);
        assert!(result.dispatched && !result.ok, "{result:?}");
        assert!(
            result.detail.contains("No such file or directory"),
            "{result:?}"
        );
        assert!(!result.detail.contains(&secret));
    }
    let request = read(PathBuf::from("/run/agentguard-request/call.json"));
    assert!(request.ok && request.dispatched, "{request:?}");
    let envelope: Value = serde_json::from_str(&request.detail).unwrap();
    assert_eq!(
        envelope,
        json!({"ReadFile":{"path":"/run/agentguard-request/call.json"},"__agentguard_single_link":true})
    );
    println!(
        "实际 Docker：普通文件可读，4 个宿主私钥路径均不可见；任务参数仅含本次文件请求和链接约束"
    );
}
