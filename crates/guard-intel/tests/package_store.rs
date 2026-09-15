use guard_intel::{
    generate_keypair,
    package::{
        store::{PackageStore, UpdateEffect},
        Compatibility, Operation, Package, PackageKind, Release, Rollout, RulePayload,
        SignedRelease,
    },
    KeyPair, ThreatBundle,
};
use guard_schema::RuleSet;
use serde_json::json;
use std::path::Path;

const STREAM: &str = "agentguard.rules.test";
fn release(sequence: u64, version: &str, epoch: u64) -> Release {
    Release {
        schema_version: 1, stream: STREAM.into(), kind: PackageKind::Rules, sequence, security_epoch: epoch,
        compatibility: Compatibility { min_reader: 1, max_reader: 1 }, issued_at_ms: 1000, expires_at_ms: 2000,
        rollout: Rollout { basis_points: 10000, salt: "fixed-rollout".into() },
        operation: Operation::Install { package: Package { kind: PackageKind::Rules, version: version.into(), content: serde_json::to_value(RulePayload {
            rules: RuleSet::from_yaml_str("version: '1.0'\nrules:\n - id: CRIT-001\n   name: 支付确认\n   severity: critical\n   action: block\n   match_any_text: [确认支付]\n").unwrap(),
            indicators: ThreatBundle::default(),
        }).unwrap() } },
    }
}
fn open(path: &Path, key: &KeyPair) -> PackageStore {
    PackageStore::open(
        path,
        key.public.clone(),
        STREAM,
        PackageKind::Rules,
        "host-device-1",
    )
    .unwrap()
}
fn apply(
    store: &mut PackageStore,
    key: &KeyPair,
    r: Release,
) -> guard_intel::package::store::UpdateReceipt {
    store
        .apply(SignedRelease::sign(r, key).unwrap(), 1500)
        .unwrap()
}
fn hash(r: &Release) -> String {
    match &r.operation {
        Operation::Install { package } => package.digest().unwrap(),
        _ => panic!("夹具必须是安装包"),
    }
}
fn control(sequence: u64, epoch: u64, operation: Operation) -> Release {
    Release {
        operation,
        ..release(sequence, "9.0.0", epoch)
    }
}

#[test]
fn 更新落盘重开与多连接读取保持相同有效包() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = generate_keypair();
    let mut first = open(&path, &key);
    let mut second = open(&path, &key);
    let r = release(1, "1.0.0", 1);
    let expected = hash(&r);
    let receipt = apply(&mut first, &key, r);
    assert_eq!(receipt.effect, UpdateEffect::Installed);
    assert_eq!(receipt.before_sha256, None);
    assert_eq!(receipt.after_sha256.as_deref(), Some(expected.as_str()));
    assert_eq!(
        second.status().unwrap().active_sha256.as_deref(),
        Some(expected.as_str())
    );
    drop(first);
    drop(second);
    let mut store = open(&path, &key);
    let status = store.status().unwrap();
    assert_eq!(status.last_sequence, 1);
    assert_eq!(status.verified_updates, 1);
    assert_eq!(status.instruction_authority, "none");
    assert_eq!(
        store.active_package().unwrap().unwrap().digest().unwrap(),
        expected
    );
}

#[test]
fn 旧包重复包和低安全代次不能覆盖当前状态() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    apply(&mut store, &key, release(5, "2.0.0", 2));
    let before = serde_json::to_value(store.status().unwrap()).unwrap();
    for r in [
        release(4, "3.0.0", 2),
        release(5, "2.0.0", 2),
        release(6, "1.0.0", 2),
        release(6, "3.0.0", 1),
    ] {
        assert!(store
            .apply(SignedRelease::sign(r, &key).unwrap(), 1500)
            .is_err());
        assert_eq!(
            serde_json::to_value(store.status().unwrap()).unwrap(),
            before
        );
    }
    drop(store);
    let mut store = open(&path, &key);
    assert_eq!(store.status().unwrap().last_sequence, 5);
}

#[test]
fn 灰度未选中保持旧包并拒绝旧推广重放() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let mut store = open(&dir.path().join("store.db"), &key);
    let first = release(1, "1.0.0", 1);
    let old = hash(&first);
    apply(&mut store, &key, first);
    let mut next = release(2, "2.0.0", 2);
    next.rollout.basis_points = 0;
    let receipt = apply(&mut store, &key, next.clone());
    assert_eq!(receipt.effect, UpdateEffect::OutsideRollout);
    assert_eq!(
        store.status().unwrap().active_sha256.as_deref(),
        Some(old.as_str())
    );
    assert_eq!(store.status().unwrap().security_floor, 1);
    assert!(store
        .apply(SignedRelease::sign(next.clone(), &key).unwrap(), 1500)
        .is_err());
    next.sequence = 3;
    next.rollout.basis_points = 10000;
    apply(&mut store, &key, next);
    assert_eq!(
        store.status().unwrap().active_version.as_deref(),
        Some("2.0.0")
    );
    assert_eq!(store.status().unwrap().security_floor, 2);
}

#[test]
fn 同版本不能换正文且同摘要不能伪造安全代次() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let mut store = open(&dir.path().join("store.db"), &key);
    apply(&mut store, &key, release(1, "1.0.0", 1));
    let mut changed = release(2, "1.0.0", 1);
    if let Operation::Install { package } = &mut changed.operation {
        package.content["indicators"]["malicious_domains"] = json!([]);
    }
    assert!(store
        .apply(SignedRelease::sign(changed, &key).unwrap(), 1500)
        .is_err());
    assert!(store
        .apply(
            SignedRelease::sign(release(2, "1.0.0", 2), &key).unwrap(),
            1500
        )
        .is_err());
    let mut changed = release(2, "1.0.0", 1);
    changed.compatibility.max_reader = 2;
    assert!(store
        .apply(SignedRelease::sign(changed, &key).unwrap(), 1500)
        .is_err());
    apply(&mut store, &key, release(2, "1.0.0", 1));
    assert_eq!(store.status().unwrap().last_sequence, 2);
}

#[test]
fn 兼容和时间失败不会消费序号或修改旧包() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let mut store = open(&dir.path().join("store.db"), &key);
    apply(&mut store, &key, release(1, "1.0.0", 1));
    let mut incompatible = release(2, "2.0.0", 2);
    incompatible.compatibility.min_reader = 2;
    incompatible.compatibility.max_reader = 3;
    assert!(store
        .apply(SignedRelease::sign(incompatible, &key).unwrap(), 1500)
        .is_err());
    for now in [999, 2000] {
        assert!(store
            .apply(
                SignedRelease::sign(release(2, "2.0.0", 2), &key).unwrap(),
                now
            )
            .is_err());
    }
    assert_eq!(store.status().unwrap().last_sequence, 1);
    apply(&mut store, &key, release(2, "2.0.0", 2));
    assert_eq!(
        store.status().unwrap().active_version.as_deref(),
        Some("2.0.0")
    );
}

#[test]
fn 撤销有效包清空激活且不能被新序号重新安装() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    let r = release(1, "1.0.0", 1);
    let h = hash(&r);
    apply(&mut store, &key, r);
    let receipt = apply(
        &mut store,
        &key,
        control(
            2,
            1,
            Operation::Revoke {
                digests: vec![h.clone()],
                reason: "测试撤销".into(),
            },
        ),
    );
    assert_eq!(receipt.effect, UpdateEffect::Revoked);
    assert!(store.active_package().unwrap().is_none());
    drop(store);
    let mut store = open(&path, &key);
    assert_eq!(store.status().unwrap().revoked, vec![h.clone()]);
    assert!(store
        .apply(
            SignedRelease::sign(release(3, "1.0.0", 1), &key).unwrap(),
            1500
        )
        .is_err());
    let recover = control(
        3,
        1,
        Operation::Recover {
            digest: h,
            reason: "不应恢复已撤销包".into(),
        },
    );
    assert!(store
        .apply(SignedRelease::sign(recover, &key).unwrap(), 1500)
        .is_err());
    assert!(store.active_package().unwrap().is_none());
}

#[test]
fn 受控恢复只接受准确的曾激活非撤销包并保留版本上限() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    let r = release(1, "1.0.0", 1);
    let first = hash(&r);
    apply(&mut store, &key, r);
    let next = release(2, "2.0.0", 1);
    let second = hash(&next);
    apply(&mut store, &key, next);
    apply(
        &mut store,
        &key,
        control(
            3,
            1,
            Operation::Revoke {
                digests: vec![second],
                reason: "测试新版撤销".into(),
            },
        ),
    );
    let receipt = apply(
        &mut store,
        &key,
        control(
            4,
            1,
            Operation::Recover {
                digest: first.clone(),
                reason: "测试独立恢复".into(),
            },
        ),
    );
    assert_eq!(receipt.effect, UpdateEffect::Recovered);
    assert_eq!(store.status().unwrap().active_sha256, Some(first));
    assert_eq!(
        store.status().unwrap().highest_installed_version.as_deref(),
        Some("2.0.0")
    );
    assert!(store
        .apply(
            SignedRelease::sign(release(5, "1.1.0", 1), &key).unwrap(),
            1500
        )
        .is_err());
    drop(store);
    let mut store = open(&path, &key);
    assert_eq!(
        store.status().unwrap().active_version.as_deref(),
        Some("1.0.0")
    );
    apply(&mut store, &key, release(5, "3.0.0", 2));
}

#[test]
fn 提高安全下限之后不能恢复旧代次或从未激活的灰度包() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let mut store = open(&dir.path().join("store.db"), &key);
    let old = release(1, "1.0.0", 1);
    let old_hash = hash(&old);
    apply(&mut store, &key, old);
    let mut skipped = release(2, "2.0.0", 2);
    let skipped_hash = hash(&skipped);
    skipped.rollout.basis_points = 0;
    apply(&mut store, &key, skipped);
    apply(&mut store, &key, release(3, "3.0.0", 2));
    for target in [old_hash, skipped_hash, "0".repeat(64)] {
        let recover = control(
            4,
            2,
            Operation::Recover {
                digest: target,
                reason: "无效恢复目标".into(),
            },
        );
        assert!(store
            .apply(SignedRelease::sign(recover, &key).unwrap(), 1500)
            .is_err());
    }
    assert_eq!(store.status().unwrap().last_sequence, 3);
    assert_eq!(
        store.status().unwrap().active_version.as_deref(),
        Some("3.0.0")
    );
}

#[test]
fn 开始就撤销未知摘要也会阻止未来安装() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let mut store = open(&dir.path().join("store.db"), &key);
    let denied = release(2, "1.0.0", 1);
    let h = hash(&denied);
    apply(
        &mut store,
        &key,
        control(
            1,
            1,
            Operation::Revoke {
                digests: vec![h],
                reason: "未安装即撤销".into(),
            },
        ),
    );
    assert!(store
        .apply(SignedRelease::sign(denied, &key).unwrap(), 1500)
        .is_err());
    assert!(store.active_package().unwrap().is_none());
}

#[test]
fn 数据库写入失败不留下半个更新或失去有效包() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    let first = release(1, "1.0.0", 1);
    let expected = hash(&first);
    apply(&mut store, &key, first);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER reject_package BEFORE INSERT ON package_updates BEGIN SELECT RAISE(ABORT,'synthetic disk write failure'); END;").unwrap();
    assert!(store
        .apply(
            SignedRelease::sign(release(2, "2.0.0", 2), &key).unwrap(),
            1500
        )
        .is_err());
    drop(store);
    let mut store = open(&path, &key);
    let status = store.status().unwrap();
    assert_eq!(status.last_sequence, 1);
    assert_eq!(status.active_sha256, Some(expected));
    db.execute_batch("DROP TRIGGER reject_package").unwrap();
    apply(&mut store, &key, release(2, "2.0.0", 2));
}

#[test]
fn 多写入者用事务读取最新序号而不是各自缓存() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut first = open(&path, &key);
    let mut second = open(&path, &key);
    apply(&mut first, &key, release(1, "1.0.0", 1));
    apply(&mut second, &key, release(3, "3.0.0", 1));
    assert!(first
        .apply(
            SignedRelease::sign(release(2, "2.0.0", 1), &key).unwrap(),
            1500
        )
        .is_err());
    assert_eq!(first.status().unwrap().last_sequence, 3);
    assert_eq!(first.active_package().unwrap().unwrap().version, "3.0.0");
}

#[test]
fn 仓库身份和签发信任根不能从更新或重开参数替换() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    apply(&mut store, &key, release(1, "1.0.0", 1));
    assert!(store
        .apply(
            SignedRelease::sign(release(2, "2.0.0", 1), &generate_keypair()).unwrap(),
            1500
        )
        .is_err());
    let mut cross = release(2, "2.0.0", 1);
    cross.stream = "other-stream".into();
    assert!(store
        .apply(SignedRelease::sign(cross, &key).unwrap(), 1500)
        .is_err());
    assert!(PackageStore::open(
        &path,
        generate_keypair().public,
        STREAM,
        PackageKind::Rules,
        "host-device-1"
    )
    .is_err());
    assert!(PackageStore::open(
        &path,
        key.public.clone(),
        "other",
        PackageKind::Rules,
        "host-device-1"
    )
    .is_err());
    assert!(PackageStore::open(
        &path,
        key.public.clone(),
        STREAM,
        PackageKind::Knowledge,
        "host-device-1"
    )
    .is_err());
    assert!(PackageStore::open(
        &path,
        key.public.clone(),
        STREAM,
        PackageKind::Rules,
        "model-chosen-device"
    )
    .is_err());
    assert_eq!(store.status().unwrap().last_sequence, 1);
}

#[test]
fn 磁盘签名正文或索引损坏时拒绝加载而不使用伪缓存() {
    for mutate in [
        "UPDATE package_updates SET sequence=2",
        "UPDATE package_updates SET release_sha256='forged'",
        "UPDATE package_updates SET signed_bytes=x'7b7d'",
        "UPDATE package_updates SET accepted_at_ms=999",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_keypair();
        let path = dir.path().join("store.db");
        let mut store = open(&path, &key);
        apply(&mut store, &key, release(1, "1.0.0", 1));
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(mutate).unwrap();
        assert!(store.status().is_err());
        assert!(store.active_package().is_err());
        assert!(PackageStore::open(
            &path,
            key.public,
            STREAM,
            PackageKind::Rules,
            "host-device-1"
        )
        .is_err());
    }
}

#[test]
fn 激活包持久读取不把已接受发布当成再次更新时间检查() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_keypair();
    let path = dir.path().join("store.db");
    let mut store = open(&path, &key);
    apply(&mut store, &key, release(1, "1.0.0", 1));
    drop(store);
    // 发布的接收时间为 1500；当前真实时钟早已超过 2000，不影响已经接受的版本。
    let mut store = open(&path, &key);
    assert_eq!(store.active_package().unwrap().unwrap().version, "1.0.0");
    assert!(store
        .apply(
            SignedRelease::sign(release(2, "2.0.0", 1), &key).unwrap(),
            2000
        )
        .is_err());
}

#[test]
fn 只打开已有仓库时不创建文件或修补空数据库() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.db");
    let key = generate_keypair();
    assert!(PackageStore::open_existing(
        &path,
        key.public.clone(),
        STREAM,
        PackageKind::Rules,
        "host-device-1"
    )
    .is_err());
    assert!(!path.exists());
    let db = rusqlite::Connection::open(&path).unwrap();
    assert!(PackageStore::open_existing(
        &path,
        key.public,
        STREAM,
        PackageKind::Rules,
        "host-device-1"
    )
    .is_err());
    let tables: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0);
}

#[test]
fn 真实并发更新最终保持最高序号() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.db");
    let key = generate_keypair();
    let mut initial = open(&path, &key);
    apply(&mut initial, &key, release(1, "1.0.0", 1));
    drop(initial);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = [(2, "2.0.0"), (3, "3.0.0")]
            .into_iter()
            .map(|(sequence, version)| {
                let path = &path;
                let key = &key;
                let barrier = &barrier;
                scope.spawn(move || {
                    let mut store = open(path, key);
                    let signed = SignedRelease::sign(release(sequence, version, 1), key).unwrap();
                    barrier.wait();
                    store.apply(signed, 1500).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(results[1]);
    let mut store = open(&path, &key);
    assert_eq!(store.status().unwrap().last_sequence, 3);
    assert_eq!(store.active_package().unwrap().unwrap().version, "3.0.0");
}
