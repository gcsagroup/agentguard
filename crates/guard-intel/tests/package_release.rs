use guard_intel::{
    generate_keypair,
    knowledge::KnowledgeCatalog,
    package::{
        Compatibility, Operation, Package, PackageKind, Release, Rollout, RulePayload,
        SignedRelease, MAX_RELEASE_BYTES, MAX_UPDATE_LIFETIME_MS, PACKAGE_READER_VERSION,
    },
    ThreatBundle,
};
use guard_schema::RuleSet;
use serde_json::{json, Value};

fn release() -> Release {
    let payload = RulePayload {
        rules: RuleSet::from_yaml_str("version: '1.0'\nrules:\n - id: CRIT-001\n   name: 支付确认\n   severity: critical\n   action: block\n   match_any_text: [确认支付]\n").unwrap(),
        indicators: ThreatBundle::default(),
    };
    Release {
        schema_version: 1,
        stream: "agentguard.rules.stable".into(),
        kind: PackageKind::Rules,
        sequence: 1,
        security_epoch: 1,
        compatibility: Compatibility {
            min_reader: 1,
            max_reader: 2,
        },
        issued_at_ms: 1000,
        expires_at_ms: 2000,
        rollout: Rollout {
            basis_points: 10000,
            salt: "release-1".into(),
        },
        operation: Operation::Install {
            package: Package {
                kind: PackageKind::Rules,
                version: "1.0.0".into(),
                content: serde_json::to_value(payload).unwrap(),
            },
        },
    }
}
fn knowledge_release() -> Release {
    let catalog = KnowledgeCatalog::from_path(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../intel/knowledge/v0.1/catalog.json"
    ))
    .unwrap();
    let mut release = release();
    release.kind = PackageKind::Knowledge;
    release.stream = "agentguard.knowledge".into();
    release.operation = Operation::Install {
        package: Package {
            kind: PackageKind::Knowledge,
            version: catalog.catalog_version.clone(),
            content: serde_json::to_value(catalog).unwrap(),
        },
    };
    release
}
fn package_mut(release: &mut Release) -> &mut Package {
    match &mut release.operation {
        Operation::Install { package } => package,
        _ => panic!("夹具必须是安装包"),
    }
}

#[test]
fn 规则签名往返使用宿主公钥且取回相同规则() {
    let key = generate_keypair();
    let signed = SignedRelease::sign(release(), &key).unwrap();
    let bytes = serde_json::to_vec(&signed).unwrap();
    let verified = SignedRelease::from_bytes(&bytes)
        .unwrap()
        .verify(&key.public)
        .unwrap();
    assert_eq!(
        verified.rule_payload().unwrap().rules.rules[0].id,
        "CRIT-001"
    );
    assert_eq!(
        verified
            .rule_payload()
            .unwrap()
            .indicators
            .injection_patterns,
        ThreatBundle::default().injection_patterns
    );
    assert_eq!(verified.signed_bytes().unwrap(), bytes);
    assert_eq!(verified.release_sha256().len(), 64);
    assert_ne!(verified.release_sha256(), verified.signer_sha256());
    assert!(signed.verify(&generate_keypair().public).is_err());
}

#[test]
fn 验签知识包不能转换成可执行规则() {
    let key = generate_keypair();
    let verified = SignedRelease::sign(knowledge_release(), &key)
        .unwrap()
        .verify(&key.public)
        .unwrap();
    assert!(verified.rule_payload().is_err());
    let mut cross = knowledge_release();
    cross.kind = PackageKind::Rules;
    assert!(SignedRelease::sign(cross, &key).is_err());
    let mut cross = knowledge_release();
    cross.kind = PackageKind::Rules;
    package_mut(&mut cross).kind = PackageKind::Rules;
    assert!(SignedRelease::sign(cross, &key).is_err());
    let mut cross = release();
    cross.kind = PackageKind::Knowledge;
    package_mut(&mut cross).kind = PackageKind::Knowledge;
    assert!(SignedRelease::sign(cross, &key).is_err());
}

#[test]
fn 每个控制字段和正文均绑定签名() {
    let key = generate_keypair();
    let original = serde_json::to_value(SignedRelease::sign(release(), &key).unwrap()).unwrap();
    let changes = [
        ("/release/stream", json!("another-stream")),
        ("/release/sequence", json!(2)),
        ("/release/security_epoch", json!(2)),
        ("/release/compatibility/max_reader", json!(3)),
        ("/release/issued_at_ms", json!(999)),
        ("/release/expires_at_ms", json!(2001)),
        ("/release/rollout/basis_points", json!(5000)),
        ("/release/rollout/salt", json!("another-salt")),
        ("/release/operation/package/version", json!("1.0.1")),
        (
            "/release/operation/package/content/rules/rules/0/action",
            json!("alert"),
        ),
        (
            "/release/operation/package/content/indicators/malicious_domains",
            json!([]),
        ),
    ];
    for (pointer, value) in changes {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let parsed = SignedRelease::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(parsed.verify(&key.public).is_err(), "未绑定 {pointer}");
    }
}

#[test]
fn 摘要或未签名不能降级公钥验证() {
    let key = generate_keypair();
    for signature in [
        "".to_string(),
        format!("sha256:{}", "0".repeat(64)),
        "ed25519:invalid".into(),
    ] {
        let signed = SignedRelease {
            release: release(),
            signature,
        };
        assert!(signed.verify(&key.public).is_err());
    }
}

#[test]
fn 任何层级重复键未知字段和多消息均拒绝() {
    let key = generate_keypair();
    let signed = SignedRelease::sign(release(), &key).unwrap();
    let raw = serde_json::to_string(&signed).unwrap();
    for bad in [
        raw.replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":2", 1),
        raw.replacen(
            "\"action\":\"block\"",
            "\"action\":\"block\",\"action\":\"alert\"",
            1,
        ),
        raw.replacen("\"stream\":", "\"unknown\":0,\"stream\":", 1),
        raw.replacen("\"min_reader\":", "\"unknown\":0,\"min_reader\":", 1),
        raw.replacen("\"rules\":[", "\"unknown\":0,\"rules\":[", 1),
        raw.replacen(
            "\"malicious_domains\":[",
            "\"unknown\":0,\"malicious_domains\":[",
            1,
        ),
        raw.replacen(
            "\"name\":\"支付确认\"",
            "\"name\":\"支付确认\",\"unknown\":0",
            1,
        ),
        raw.replacen("\"sequence\":1", "\"sequence\":1.0", 1),
        format!("{raw} {{}}"),
    ] {
        assert_ne!(bad, raw, "负例确实改动输入");
        assert!(SignedRelease::from_bytes(bad.as_bytes()).is_err());
    }
}

#[test]
fn 对象键顺序和空白不改变签名而数组顺序会改变() {
    let key = generate_keypair();
    let signed = SignedRelease::sign(release(), &key).unwrap();
    let pretty = serde_json::to_vec_pretty(&signed).unwrap();
    let sorted = serde_json::to_vec(&serde_json::to_value(&signed).unwrap()).unwrap();
    let a = SignedRelease::from_bytes(&pretty)
        .unwrap()
        .verify(&key.public)
        .unwrap();
    let b = SignedRelease::from_bytes(&sorted)
        .unwrap()
        .verify(&key.public)
        .unwrap();
    assert_eq!(a.release_sha256(), b.release_sha256());
    let mut changed = serde_json::to_value(signed).unwrap();
    changed
        .pointer_mut("/release/operation/package/content/indicators/injection_patterns")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        SignedRelease::from_bytes(&serde_json::to_vec(&changed).unwrap())
            .unwrap()
            .verify(&key.public)
            .is_err()
    );
}

#[test]
fn 超限深层内容和无效控制数值拒绝() {
    assert!(SignedRelease::from_bytes(&vec![b' '; MAX_RELEASE_BYTES + 1]).is_err());
    assert!(SignedRelease::from_bytes(&[]).is_err());
    let deep = format!("{}0{}", "[".repeat(150), "]".repeat(150));
    assert!(SignedRelease::from_bytes(deep.as_bytes()).is_err());
    let key = generate_keypair();
    let cases = [
        ("/schema_version", json!(2)),
        ("/sequence", json!(0)),
        ("/sequence", json!(u64::MAX)),
        ("/security_epoch", json!(0)),
        ("/rollout/basis_points", json!(10001)),
        ("/compatibility/min_reader", json!(0)),
        ("/compatibility/min_reader", json!(3)),
    ];
    for (pointer, value) in cases {
        let mut raw = serde_json::to_value(release()).unwrap();
        *raw.pointer_mut(pointer).unwrap() = value;
        let changed: Release = serde_json::from_value(raw).unwrap();
        assert!(SignedRelease::sign(changed, &key).is_err(), "{pointer}");
    }
}

#[test]
fn 无效版本重复规则嵌套签名和遗漏字段均拒绝() {
    let key = generate_keypair();
    for version in ["1.0", "01.0.0", "1.0.0-beta", "1.0.4294967296", "1.0.-1"] {
        let mut changed = release();
        package_mut(&mut changed).version = version.into();
        assert!(SignedRelease::sign(changed, &key).is_err());
    }
    let mut duplicate = release();
    let content = &mut package_mut(&mut duplicate).content;
    let first = content["rules"]["rules"][0].clone();
    content["rules"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(first);
    assert!(SignedRelease::sign(duplicate, &key).is_err());
    let mut nested = release();
    package_mut(&mut nested).content["indicators"]["signature"] = json!("sha256:untrusted");
    assert!(SignedRelease::sign(nested, &key).is_err());
    let mut omitted = release();
    package_mut(&mut omitted).content["rules"]["rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("require_confirm");
    assert!(SignedRelease::sign(omitted, &key).is_err());
}

#[test]
fn 知识库正文失配和自报授权不能进入包() {
    let key = generate_keypair();
    let mut changed = knowledge_release();
    package_mut(&mut changed).content["trust"]["authorization_effect"] = json!("allow");
    assert!(SignedRelease::sign(changed, &key).is_err());
    let mut changed = knowledge_release();
    package_mut(&mut changed).version = "99.0.0".into();
    assert!(SignedRelease::sign(changed, &key).is_err());
    let mut changed = knowledge_release();
    package_mut(&mut changed).content["techniques"][0]["id"] = json!("forged-id");
    assert!(SignedRelease::sign(changed, &key).is_err());
}

#[test]
fn 兼容版本与有效期使用宿主输入而非包自报成功() {
    let r = release();
    assert!(r.check_update_context(1000, PACKAGE_READER_VERSION).is_ok());
    assert!(r.check_update_context(1999, 2).is_ok());
    for (time, reader) in [(999, 1), (2000, 1), (1500, 0), (1500, 3)] {
        assert!(r.check_update_context(time, reader).is_err());
    }
    let mut invalid = r;
    invalid.expires_at_ms = invalid.issued_at_ms + MAX_UPDATE_LIFETIME_MS + 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn 灰度稳定单调且零和全部范围准确() {
    let mut r = release();
    let mut selected = 0;
    for i in 0..2000 {
        let id = format!("host-device-{i}");
        r.rollout.basis_points = 0;
        assert!(!r.selected(&id).unwrap());
        r.rollout.basis_points = 10000;
        assert!(r.selected(&id).unwrap());
        r.rollout.basis_points = 2500;
        let quarter = r.selected(&id).unwrap();
        assert_eq!(quarter, r.selected(&id).unwrap());
        selected += usize::from(quarter);
        r.rollout.basis_points = 5000;
        assert!(!quarter || r.selected(&id).unwrap());
    }
    assert!((350..650).contains(&selected), "固定分桶结果 {selected}");
    assert!(r.selected("").is_err());
}

#[test]
fn 撤销恢复绑定摘要并强制覆盖所有分组() {
    let key = generate_keypair();
    let mut r = release();
    let digest = package_mut(&mut r).digest().unwrap();
    for operation in [
        Operation::Revoke {
            digests: vec![digest.clone()],
            reason: "撤销合成坏包".into(),
        },
        Operation::Recover {
            digest: digest.clone(),
            reason: "恢复合成已知良好包".into(),
        },
    ] {
        r.operation = operation;
        r.rollout.basis_points = 10000;
        let signed = SignedRelease::sign(r.clone(), &key).unwrap();
        assert!(signed.verify(&key.public).is_ok());
        r.rollout.basis_points = 9999;
        assert!(SignedRelease::sign(r.clone(), &key).is_err());
    }
    r.rollout.basis_points = 10000;
    r.operation = Operation::Revoke {
        digests: vec![digest.clone(), digest],
        reason: "重复".into(),
    };
    assert!(r.validate().is_err());
    r.operation = Operation::Recover {
        digest: "file:///other".into(),
        reason: "无效".into(),
    };
    assert!(r.validate().is_err());
}

#[test]
fn 包内容摘要不受推广序号影响但绑定类型和版本() {
    let mut r = release();
    let first = package_mut(&mut r).digest().unwrap();
    r.sequence += 1;
    r.rollout.basis_points = 5000;
    assert_eq!(first, package_mut(&mut r).digest().unwrap());
    package_mut(&mut r).version = "1.0.1".into();
    assert_ne!(first, package_mut(&mut r).digest().unwrap());
}

#[test]
fn 读取真实文件与内存验证保持一致() {
    let key = generate_keypair();
    let signed = SignedRelease::sign(release(), &key).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("release.json");
    std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    let from_file = SignedRelease::from_path(&path)
        .unwrap()
        .verify(&key.public)
        .unwrap();
    let expected = signed.verify(&key.public).unwrap();
    assert_eq!(from_file.release_sha256(), expected.release_sha256());
    let broken: Value = json!({"release":{},"signature":"ed25519:bad"});
    std::fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();
    assert!(SignedRelease::from_path(path).is_err());
}
