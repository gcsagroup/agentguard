use guard_intel::{
    generate_keypair,
    package::{
        store::{PackageStore, RuntimeStore},
        Compatibility, Operation, Package, PackageKind, Release, Rollout, RulePayload,
        SignedRelease,
    },
    KeyPair, ThreatBundle,
};
use std::{path::Path, sync::mpsc, time::Duration};

fn release(sequence: u64) -> Release {
    Release {
        schema_version: 1, stream: "runtime-test".into(), kind: PackageKind::Rules, sequence,
        security_epoch: 1, compatibility: Compatibility { min_reader: 1, max_reader: 1 },
        issued_at_ms: 1000, expires_at_ms: 2000,
        rollout: Rollout { basis_points: 10000, salt: "host-test".into() },
        operation: Operation::Install { package: Package {
            kind: PackageKind::Rules, version: format!("1.0.{sequence}"),
            content: serde_json::to_value(RulePayload {
                rules: guard_schema::RuleSet::from_yaml_str("version: '1.0'\nrules:\n - id: PKG-TEST\n   name: 合成规则\n   severity: high\n   action: block\n   match_any_text: [仅用于测试的禁用标记]\n").unwrap(),
                indicators: ThreatBundle::default(),
            }).unwrap(),
        } },
    }
}
fn open(path: &Path, key: &KeyPair) -> PackageStore {
    PackageStore::open(
        path,
        key.public.clone(),
        "runtime-test",
        PackageKind::Rules,
        "host-1",
    )
    .unwrap()
}
fn apply(store: &mut PackageStore, key: &KeyPair, r: Release) {
    store
        .apply(SignedRelease::sign(r, key).unwrap(), 1500)
        .unwrap();
}

#[test]
fn 动作存续期间两种日志模式都禁止外部提交且最后释放后可以更新() {
    for mode in ["DELETE", "WAL"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let key = generate_keypair();
        let mut writer = open(&path, &key);
        apply(&mut writer, &key, release(1));
        let db = rusqlite::Connection::open(&path).unwrap();
        db.pragma_update(None, "journal_mode", mode).unwrap();
        db.busy_timeout(Duration::from_millis(50)).unwrap();
        let runtime = RuntimeStore::new(open(&path, &key)).unwrap();
        let snapshot = runtime.snapshot().unwrap();
        let first = runtime.acquire(snapshot.binding_sha256()).unwrap();
        let mut observer = PackageStore::open_existing(
            &path,
            key.public.clone(),
            "runtime-test",
            PackageKind::Rules,
            "host-1",
        )
        .unwrap();
        assert_eq!(
            observer.status().unwrap().last_sequence,
            1,
            "运行中独立状态查询不能争抢写锁"
        );
        let nested_runtime = runtime.clone();
        let binding = snapshot.binding_sha256().to_owned();
        let (send, receive) = mpsc::channel();
        let nested = std::thread::spawn(move || {
            send.send(nested_runtime.acquire(&binding).unwrap())
                .unwrap();
        });
        let second = receive
            .recv_timeout(Duration::from_secs(2))
            .expect("跨线程嵌套动作不能死锁");
        nested.join().unwrap();
        assert!(db.execute_batch("BEGIN IMMEDIATE").is_err(), "{mode}");
        drop(first);
        assert!(
            db.execute_batch("BEGIN IMMEDIATE").is_err(),
            "最后一个动作仍在运行 {mode}"
        );
        drop(second);
        apply(&mut writer, &key, release(2));
        assert!(runtime.acquire(snapshot.binding_sha256()).is_err());
        assert_eq!(runtime.snapshot().unwrap().status().last_sequence, 2);
        db.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
    }
}

#[test]
fn 等待批准不锁更新且恢复相同正文不能复活旧批准() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = generate_keypair();
    let mut writer = open(&path, &key);
    apply(&mut writer, &key, release(1));
    let runtime = RuntimeStore::new(open(&path, &key)).unwrap();
    let old = runtime.snapshot().unwrap();
    apply(&mut writer, &key, release(2));
    let mut recovery = release(3);
    recovery.operation = Operation::Recover {
        digest: old.package().unwrap().digest().unwrap(),
        reason: "已核对的合成恢复".into(),
    };
    apply(&mut writer, &key, recovery);
    let current = runtime.snapshot().unwrap();
    assert_eq!(
        old.package().unwrap().digest().unwrap(),
        current.package().unwrap().digest().unwrap()
    );
    assert_ne!(old.binding_sha256(), current.binding_sha256());
    assert!(runtime.acquire(old.binding_sha256()).is_err());
    assert!(runtime.acquire(current.binding_sha256()).is_ok());
}

#[test]
fn 空库撤销和错误代次均拒绝执行且失败不遗留事务() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = generate_keypair();
    let mut writer = open(&path, &key);
    let runtime = RuntimeStore::new(open(&path, &key)).unwrap();
    let empty = runtime.snapshot().unwrap();
    assert!(runtime.acquire(empty.binding_sha256()).is_err());
    apply(&mut writer, &key, release(1));
    assert!(runtime.acquire("伪造代次").is_err());
    let current = runtime.snapshot().unwrap();
    let lease = runtime.acquire(current.binding_sha256()).unwrap();
    assert!(runtime.acquire("其它嵌套代次").is_err());
    drop(lease);
    let mut revoke = release(2);
    revoke.operation = Operation::Revoke {
        digests: vec![current.package().unwrap().digest().unwrap()],
        reason: "合成撤销".into(),
    };
    apply(&mut writer, &key, revoke);
    assert!(runtime.acquire(current.binding_sha256()).is_err());
    let revoked = runtime.snapshot().unwrap();
    assert!(revoked.package().is_none());
    assert!(runtime.acquire(revoked.binding_sha256()).is_err());
    apply(&mut writer, &key, release(3));
}

#[test]
fn 失败更新保持有效执行策略且释放后仍重验签名流水() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = generate_keypair();
    let mut writer = open(&path, &key);
    apply(&mut writer, &key, release(1));
    let runtime = RuntimeStore::new(open(&path, &key)).unwrap();
    let before = runtime.snapshot().unwrap();
    assert!(writer
        .apply(
            SignedRelease::sign(release(2), &generate_keypair()).unwrap(),
            1500
        )
        .is_err());
    assert!(runtime.acquire(before.binding_sha256()).is_ok());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("UPDATE package_updates SET signed_bytes = x'00'", [])
        .unwrap();
    assert!(runtime.snapshot().is_err());
    assert!(runtime.acquire(before.binding_sha256()).is_err());
}
