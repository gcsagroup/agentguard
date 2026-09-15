use super::*;
use crate::FileDeviceKey;
use guard_privacy::{Confidentiality, Integrity, Label};
use guard_schema::{
    ActionSnapshot, ActionSpec, ApprovalBinding, SourceObject, SourceObservation,
    SourceSensitivity, ToolIdentity,
};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

fn id(value: &str) -> ValidatedId {
    ValidatedId::new(value).unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    witness: PathBuf,
    key: FileDeviceKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            db: dir.path().join("memory.db"),
            witness: dir.path().join("host-head.json"),
            _dir: dir,
            key: FileDeviceKey::generate(),
        }
    }
    fn create(&self) -> MemoryStore {
        MemoryStore::create(
            &self.db,
            &self.witness,
            id("项目"),
            Box::new(self.key.clone()),
            self.key.verifying_key(),
            None,
        )
        .unwrap()
    }
    fn open(&self) -> Result<MemoryStore> {
        MemoryStore::open(
            &self.db,
            &self.witness,
            id("项目"),
            Box::new(self.key.clone()),
            self.key.verifying_key(),
            None,
        )
    }
    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(&self.db)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn recover(&self) -> Result<MemoryRecovery> {
        MemoryStore::recover_anchor(
            &self.db,
            &self.witness,
            &id("项目"),
            &self.key.verifying_key(),
            None,
        )
    }
}

fn draft() -> MemoryDraft {
    MemoryDraft {
        schema_version: 1,
        scope_id: id("项目"),
        key: id("偏好"),
        version: 1,
        previous_sha256: None,
        content: "AGD_MEMORY_SYNTHETIC 中文😀\n来源不是执行指令。".into(),
        sources: vec![SourceObject {
            source_id: id("unknown-origin"),
            observation: SourceObservation::Unknown {
                reason: "not_observed".into(),
            },
            sensitivity: SourceSensitivity::Unknown,
            content_views: None,
        }],
        label: Label::new(Integrity::Tainted, Confidentiality::High),
        created_at_ms: 100,
        expires_at_ms: 1000,
        state: MemoryState::Active,
    }
}

fn approval(draft: &MemoryDraft, serial: u64) -> ApprovalRecord {
    let action = ActionSnapshot::new(ActionSpec {
        contract_version: 1,
        session_id: id("host-session"),
        action_id: id(&format!("action-{serial}")),
        request_id: id(&format!("request-{serial}")),
        tool: ToolIdentity {
            service: "agentguard-memory".into(),
            name: "memory_write".into(),
            version: "1".into(),
            registration: None,
        },
        target: draft.target(),
        parameters: serde_json::to_value(draft).unwrap(),
        policy_version: id("policy-v1"),
        issued_at_ms: draft.created_at_ms,
        expires_at_ms: draft.expires_at_ms,
        nonce: format!("{serial:032x}"),
        sources: draft.sources.clone(),
    })
    .unwrap();
    ApprovalRecord {
        binding: ApprovalBinding::new(
            id(&format!("approval-{serial}")),
            action,
            format!("{serial:032x}"),
            draft.created_at_ms,
            draft.expires_at_ms,
        )
        .unwrap(),
        choice: ApprovalChoice::Approved,
        actor_id: id("authenticated-host-operator"),
        decided_at_ms: draft.created_at_ms + 1,
    }
}

fn put(store: &mut MemoryStore, draft: MemoryDraft, serial: u64) -> MemoryEntry {
    let approved = approval(&draft, serial);
    let now = draft.created_at_ms + 2;
    store.commit(draft, &approved, now).unwrap()
}

fn next(entry: &MemoryEntry, state: MemoryState) -> MemoryDraft {
    let mut draft = entry.draft.clone();
    draft.version += 1;
    draft.previous_sha256 = Some(entry.sha256().unwrap());
    draft.created_at_ms += 10;
    draft.state = state;
    draft
}

#[test]
fn 完整版本跨关闭重开保持所有绑定() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let first = put(&mut store, draft(), 1);
    let mut second = next(&first, MemoryState::Active);
    second.content.push_str("\n第二版");
    let second = put(&mut store, second, 2);
    drop(store);
    let store = fixture.open().unwrap();
    assert_eq!(store.history().unwrap(), vec![first, second.clone()]);
    assert_eq!(store.get(&id("偏好"), 150).unwrap(), Some(second));
    assert!(store.get(&id("不存在"), 150).unwrap().is_none());
    assert!(store.get(&id("偏好"), 50).is_err());
}

#[test]
fn 最新过期隔离和撤销不回落旧版本() {
    for state in [
        MemoryState::Quarantined,
        MemoryState::Revoked,
        MemoryState::Active,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create();
        let first = put(&mut store, draft(), 1);
        let mut second = next(&first, state);
        second.expires_at_ms = 140;
        let second = put(&mut store, second, 2);
        drop(store);
        let mut store = fixture.open().unwrap();
        assert!(store.get(&id("偏好"), 150).unwrap().is_none());
        if state != MemoryState::Active {
            assert!(store.get(&id("偏好"), 130).unwrap().is_none());
        }
        let mut restored = next(&second, MemoryState::Active);
        restored.expires_at_ms = 2000;
        restored.label = Label::user_instruction();
        let permit = approval(&restored, 3);
        assert!(store.commit(restored, &permit, 123).is_err());
        let mut restored = next(&second, MemoryState::Active);
        restored.expires_at_ms = 2000;
        let saved = put(&mut store, restored, 4);
        assert_eq!(saved.draft.label, first.draft.label);
        assert_eq!(store.get(&id("偏好"), 160).unwrap(), Some(saved));
    }
}

#[test]
fn 批准拒绝过期替换正文或作用域不会写入() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let original = draft();
    let permit = approval(&original, 1);
    let mut denied = permit.clone();
    denied.choice = ApprovalChoice::Denied;
    assert!(store.commit(original.clone(), &denied, 102).is_err());
    assert!(store.commit(original.clone(), &permit, 1000).is_err());
    let mut replaced = original.clone();
    replaced.content.push_str("替换正文");
    assert!(store.commit(replaced, &permit, 102).is_err());
    let mut cross = original.clone();
    cross.scope_id = id("其他项目");
    let cross_permit = approval(&cross, 2);
    assert!(store.commit(cross, &cross_permit, 102).is_err());
    assert!(store.history().unwrap().is_empty());
    assert!(store.commit(original, &permit, 102).is_ok());
}

#[test]
fn 重启后批准随机值和旧版本不能重放() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let first = put(&mut store, draft(), 1);
    drop(store);
    let mut store = fixture.open().unwrap();
    let second = next(&first, MemoryState::Active);
    let reused = approval(&second, 1);
    assert!(store.commit(second.clone(), &reused, 112).is_err());
    let mut changed_key = draft();
    changed_key.key = id("另一个键");
    let reused = approval(&changed_key, 1);
    assert!(store.commit(changed_key, &reused, 112).is_err());
    let mut stale = second;
    stale.previous_sha256 = Some(Sha256Digest::new("00".repeat(32)).unwrap());
    let permit = approval(&stale, 2);
    assert!(store.commit(stale, &permit, 112).is_err());
    assert_eq!(store.history().unwrap(), vec![first]);
}

#[test]
fn 直接改正文或签名读取和重开都拒绝() {
    for sql in [
        "UPDATE audit_events SET event_json='{}' WHERE rowid=2",
        "UPDATE audit_events SET record_sig='' WHERE rowid=2",
        "UPDATE audit_events SET user_decision='approved' WHERE rowid=2",
        "UPDATE audit_meta SET value='forged-log' WHERE key='log_id'",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create();
        put(&mut store, draft(), 1);
        fixture.sql(sql);
        assert!(store.get(&id("偏好"), 150).is_err());
        drop(store);
        assert!(fixture.open().is_err());
        assert!(fixture.recover().is_err());
    }
}

#[test]
fn 重算完整哈希链不能伪造记忆() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let mut entry = put(&mut store, draft(), 1);
    drop(store);
    entry.draft.content = "FORGED_MEMORY".into();
    entry.content_sha256 = Sha256Digest::new(sha(entry.draft.content.as_bytes())).unwrap();
    let replacement = entry.record().unwrap();
    let db = rusqlite::Connection::open(&fixture.db).unwrap();
    let previous: String = db
        .query_row(
            "SELECT record_hash FROM audit_events WHERE rowid=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE audit_events SET id=?1,event_json=?2,record_hash=?3 WHERE rowid=2",
        rusqlite::params![
            replacement.id,
            replacement.event_json,
            crate::chain::chain_hash(&previous, &replacement)
        ],
    )
    .unwrap();
    drop(db);
    assert!(
        AuditStore::open_read_only_with_key(&fixture.db, None)
            .unwrap()
            .verify_chain()
            .unwrap()
            .ok
    );
    assert!(fixture.open().is_err());
    assert!(fixture.recover().is_err());
}

#[test]
fn 有效签名前缀删尾仍被外部见证拒绝() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let first = put(&mut store, draft(), 1);
    put(&mut store, next(&first, MemoryState::Revoked), 2);
    drop(store);
    fixture.sql("DELETE FROM audit_events WHERE rowid=3");
    let audit = AuditStore::open_read_only_with_key(&fixture.db, None).unwrap();
    assert!(audit
        .verify_record_signatures(&fixture.key.verifying_key())
        .unwrap()
        .fully_covered());
    drop(audit);
    assert!(fixture.open().is_err());
    assert!(fixture.recover().is_err());
}

#[test]
fn 跨库搬运和错误公钥不能取得记忆() {
    let a = Fixture::new();
    let mut store = a.create();
    put(&mut store, draft(), 1);
    drop(store);
    let b = Fixture::new();
    drop(b.create());
    fs::copy(&a.db, &b.db).unwrap();
    assert!(b.open().is_err());
    assert!(MemoryStore::open(
        &b.db,
        &b.witness,
        id("项目"),
        Box::new(a.key.clone()),
        a.key.verifying_key(),
        None
    )
    .is_err());
    assert!(MemoryStore::open(
        &a.db,
        &a.witness,
        id("其他项目"),
        Box::new(a.key.clone()),
        a.key.verifying_key(),
        None
    )
    .is_err());
    let wrong = FileDeviceKey::generate();
    assert!(MemoryStore::open(
        &a.db,
        &a.witness,
        id("项目"),
        Box::new(wrong.clone()),
        wrong.verifying_key(),
        None
    )
    .is_err());
}

#[test]
fn 并发写入者拒绝且正常释放后可重开() {
    let fixture = Fixture::new();
    let store = fixture.create();
    assert!(fixture.open().is_err());
    drop(store);
    assert!(fixture.open().is_ok());
}

#[test]
fn 符号链接硬链接宽松权限和缺见证拒绝() {
    let fixture = Fixture::new();
    drop(fixture.create());
    let saved = fixture.witness.with_extension("saved");
    fs::rename(&fixture.witness, &saved).unwrap();
    assert!(fixture.open().is_err());
    assert!(fixture.recover().is_err());
    symlink(&saved, &fixture.witness).unwrap();
    assert!(fixture.open().is_err());
    fs::remove_file(&fixture.witness).unwrap();
    fs::hard_link(&saved, &fixture.witness).unwrap();
    assert!(fixture.open().is_err());
    fs::remove_file(&fixture.witness).unwrap();
    fs::rename(&saved, &fixture.witness).unwrap();
    fs::set_permissions(&fixture.witness, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(fixture.open().is_err());
    let fresh = Fixture::new();
    let outside = fresh.db.with_extension("outside");
    symlink(&outside, crate::snapshot::sidecar(&fresh.db, "-wal")).unwrap();
    assert!(MemoryStore::create(
        &fresh.db,
        &fresh.witness,
        id("项目"),
        Box::new(fresh.key.clone()),
        fresh.key.verifying_key(),
        None
    )
    .is_err());
    assert!(!outside.exists() && !fresh.db.exists());
    let public = Fixture::new();
    fs::set_permissions(public._dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(MemoryStore::create(
        &public.db,
        &public.witness,
        id("项目"),
        Box::new(public.key.clone()),
        public.key.verifying_key(),
        None
    )
    .is_err());
    assert!(!public.db.exists());
}

#[test]
fn 句柄存活期间数据库路径被替换即停止() {
    let fixture = Fixture::new();
    let store = fixture.create();
    fs::rename(&fixture.db, fixture.db.with_extension("saved")).unwrap();
    File::create(&fixture.db).unwrap();
    assert!(store.history().is_err());
}

#[test]
fn 真实事务失败不留半条版本或消费批准() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    fixture.sql("CREATE TRIGGER fail_memory BEFORE INSERT ON audit_events WHEN NEW.event_type='MemoryVersionCommitted' BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END;");
    let d = draft();
    let permit = approval(&d, 1);
    assert!(store.commit(d.clone(), &permit, 102).is_err());
    assert!(store.history().unwrap().is_empty());
    fixture.sql("DROP TRIGGER fail_memory");
    assert!(store.commit(d, &permit, 102).is_ok());
}

#[derive(Debug)]
struct FaultSigner {
    key: FileDeviceKey,
    armed: Arc<AtomicBool>,
    witness: Option<PathBuf>,
}
impl AuditSigner for FaultSigner {
    fn key_id(&self) -> String {
        self.key.key_id()
    }
    fn public_hex(&self) -> Option<String> {
        self.key.public_hex()
    }
    fn sign_message(&self, value: &[u8]) -> Result<String> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if let Some(path) = &self.witness {
                fs::rename(path, path.with_extension("saved"))?;
                fs::create_dir(path)?;
            } else {
                anyhow::bail!("合成签名失败");
            }
        }
        self.key.sign_message(value)
    }
}

#[test]
fn 签名失败在数据库提交前回滚() {
    let fixture = Fixture::new();
    let armed = Arc::new(AtomicBool::new(false));
    let signer = FaultSigner {
        key: fixture.key.clone(),
        armed: armed.clone(),
        witness: None,
    };
    let mut store = MemoryStore::create(
        &fixture.db,
        &fixture.witness,
        id("项目"),
        Box::new(signer),
        fixture.key.verifying_key(),
        None,
    )
    .unwrap();
    armed.store(true, Ordering::SeqCst);
    let d = draft();
    assert!(store.commit(d.clone(), &approval(&d, 1), 102).is_err());
    assert!(store.history().unwrap().is_empty());
    drop(store);
    assert!(fixture.open().unwrap().history().unwrap().is_empty());
}

#[test]
fn 提交后见证写入失败须显式恢复且不重放() {
    let fixture = Fixture::new();
    let armed = Arc::new(AtomicBool::new(false));
    let signer = FaultSigner {
        key: fixture.key.clone(),
        armed: armed.clone(),
        witness: Some(fixture.witness.clone()),
    };
    let mut store = MemoryStore::create(
        &fixture.db,
        &fixture.witness,
        id("项目"),
        Box::new(signer),
        fixture.key.verifying_key(),
        None,
    )
    .unwrap();
    let d = draft();
    let permit = approval(&d, 1);
    armed.store(true, Ordering::SeqCst);
    assert!(store
        .commit(d.clone(), &permit, 102)
        .unwrap_err()
        .to_string()
        .contains("见证未确认"));
    assert!(store.get(&id("偏好"), 150).is_err());
    assert!(store.commit(d.clone(), &permit, 102).is_err());
    drop(store);
    fs::remove_dir(&fixture.witness).unwrap();
    fs::rename(fixture.witness.with_extension("saved"), &fixture.witness).unwrap();
    assert!(fixture.open().is_err());
    let recovered = fixture.recover().unwrap();
    assert_eq!(
        (
            recovered.old_count,
            recovered.recovered_count,
            recovered.replayed_writes
        ),
        (1, 2, 0)
    );
    let mut store = fixture.open().unwrap();
    assert_eq!(store.get(&id("偏好"), 150).unwrap().unwrap().draft, d);
    assert!(store.commit(d, &permit, 102).is_err());
    assert_eq!(store.history().unwrap().len(), 1);
}

#[test]
fn 恢复读取上限包括非正文列且不静默截断() {
    for sql in [
        "UPDATE audit_events SET human_message=replace(hex(zeroblob(9000000)),'0','x')",
        "UPDATE audit_meta SET value=hex(zeroblob(8193)) WHERE key='log_id'",
        "INSERT INTO decision_receipts (audit_id,decision,decided_at_ms,prev_hash,receipt_hash) VALUES ('memory/genesis','approved',1,'',hex(zeroblob(8193)))",
    ] {
        let fixture = Fixture::new();
        drop(fixture.create());
        fixture.sql(sql);
        assert!(fixture
            .open()
            .err()
            .unwrap()
            .to_string()
            .contains("恢复上限"));
    }
}

#[test]
fn 加密选项不能静默写明文() {
    let empty = Fixture::new();
    assert!(MemoryStore::create(
        &empty.db,
        &empty.witness,
        id("项目"),
        Box::new(empty.key.clone()),
        empty.key.verifying_key(),
        Some("")
    )
    .is_err());
    assert!(!empty.db.exists());
    drop(empty.create());
    assert!(MemoryStore::open(
        &empty.db,
        &empty.witness,
        id("项目"),
        Box::new(empty.key.clone()),
        empty.key.verifying_key(),
        Some("")
    )
    .is_err());
    assert!(MemoryStore::recover_anchor(
        &empty.db,
        &empty.witness,
        &id("项目"),
        &empty.key.verifying_key(),
        Some("")
    )
    .is_err());
    let fixture = Fixture::new();
    let result = MemoryStore::create(
        &fixture.db,
        &fixture.witness,
        id("项目"),
        Box::new(fixture.key.clone()),
        fixture.key.verifying_key(),
        Some("synthetic-memory-passphrase"),
    );
    if crate::sqlcipher_enabled() {
        let mut store = result.unwrap();
        put(&mut store, draft(), 1);
        drop(store);
        let bytes = fs::read(&fixture.db).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
        assert!(!bytes.windows(20).any(|v| v == b"AGD_MEMORY_SYNTHETIC "));
        assert!(MemoryStore::open(
            &fixture.db,
            &fixture.witness,
            id("项目"),
            Box::new(fixture.key.clone()),
            fixture.key.verifying_key(),
            Some("wrong")
        )
        .is_err());
        let store = MemoryStore::open(
            &fixture.db,
            &fixture.witness,
            id("项目"),
            Box::new(fixture.key.clone()),
            fixture.key.verifying_key(),
            Some("synthetic-memory-passphrase"),
        )
        .unwrap();
        assert_eq!(store.get(&id("偏好"), 150).unwrap().unwrap().draft, draft());
    } else {
        assert!(result.is_err());
        assert!(!fixture.db.exists());
    }
}

#[test]
#[ignore = "仅由跨进程父验收显式调用；需要已声明的合成目录和步骤"]
fn 跨进程合成子步骤() {
    let directory =
        PathBuf::from(std::env::var_os("AGD_MEMORY_CHILD_DIRECTORY").expect("缺少合成目录"));
    let phase = std::env::var("AGD_MEMORY_CHILD_PHASE").expect("缺少合成步骤");
    let key = FileDeviceKey::load_existing(directory.join("operator/signing.key")).unwrap();
    let public = AuditVerifyKey::from_path(directory.join("operator/public.hex")).unwrap();
    let database = directory.join("data/memory.db");
    let witness = directory.join("operator/head.json");
    let versions = if phase == "create" {
        let mut store =
            MemoryStore::create(&database, &witness, id("项目"), Box::new(key), public, None)
                .unwrap();
        put(&mut store, draft(), 1);
        assert_eq!(store.history().unwrap().len(), 1);
        1
    } else {
        let mut store =
            MemoryStore::open(&database, &witness, id("项目"), Box::new(key), public, None)
                .unwrap();
        match phase.as_str() {
            "read" => {
                let saved = store.get(&id("偏好"), 150).unwrap().unwrap();
                assert_eq!(saved.draft, draft());
                assert_eq!(saved.approval.approval_id, id("approval-1"));
                assert_eq!(
                    saved.content_sha256.as_str(),
                    sha(draft().content.as_bytes())
                );
                1
            }
            "revoke" => {
                let saved = store.get(&id("偏好"), 150).unwrap().unwrap();
                let next = next(&saved, MemoryState::Revoked);
                put(&mut store, next, 2);
                2
            }
            "read-revoked" => {
                assert!(store.get(&id("偏好"), 150).unwrap().is_none());
                let history = store.history().unwrap();
                assert_eq!(history.len(), 2);
                assert_eq!(history[0].draft, draft());
                assert_eq!(history[1].draft.state, MemoryState::Revoked);
                assert_eq!(history[1].draft.label, draft().label);
                2
            }
            _ => panic!("未知合成步骤"),
        }
    };
    println!(
        "AGD_MEMORY_STEP={}",
        serde_json::json!({"phase":phase,"pid":std::process::id(),"versions":versions})
    );
}

#[test]
fn 真实独立进程重启读取撤销并拒绝磁盘篡改() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = std::env::var_os("AGD_MEMORY_ACCEPTANCE_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("acceptance"));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["operator", "data"] {
        fs::create_dir(directory.join(name)).unwrap();
        fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = FileDeviceKey::load_or_create(directory.join("operator/signing.key")).unwrap();
    fs::write(
        directory.join("operator/public.hex"),
        key.verifying_key().to_hex(),
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap();
    let run = |phase: &str| {
        std::process::Command::new(&executable)
            .args([
                "--ignored",
                "--exact",
                "store::memory::tests::跨进程合成子步骤",
                "--nocapture",
            ])
            .env("AGD_MEMORY_CHILD_DIRECTORY", &directory)
            .env("AGD_MEMORY_CHILD_PHASE", phase)
            .output()
            .unwrap()
    };
    let mut steps = Vec::new();
    for phase in ["create", "read", "revoke", "read-revoked"] {
        let result = run(phase);
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert!(
            result.status.success(),
            "子步骤 {phase} 失败：{stdout}\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let record = stdout
            .lines()
            .find_map(|line| line.strip_prefix("AGD_MEMORY_STEP="))
            .expect("缺少实际子进程回执");
        let record: serde_json::Value = serde_json::from_str(record).unwrap();
        assert_eq!(record["phase"], phase);
        steps.push(record);
    }
    let pids: HashSet<_> = steps.iter().map(|v| v["pid"].as_u64().unwrap()).collect();
    assert_eq!(pids.len(), 4);
    let database = directory.join("data/memory.db");
    fs::copy(&database, directory.join("data/memory-pristine.db")).unwrap();
    let db = rusqlite::Connection::open(&database).unwrap();
    db.execute("UPDATE audit_events SET event_json=json_set(event_json,'$.draft.state','active') WHERE seq=3", []).unwrap();
    drop(db);
    let refused = run("read-revoked");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("记忆签名、顺序或正文被修改"));
    let result = serde_json::json!({"passed":true,"scope":"真实独立进程和磁盘；批准明确为宿主合成夹具，不冒充用户点击", "steps":steps,
        "tampered_revocation_refused":true,"test_executable":executable,"test_executable_sha256":sha(&fs::read(&executable).unwrap()),
        "pristine_database_sha256":sha(&fs::read(directory.join("data/memory-pristine.db")).unwrap()),
        "tampered_database_sha256":sha(&fs::read(&database).unwrap()),"public_key":key.verifying_key().to_hex()});
    fs::write(
        directory.join("report.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "{}",
        serde_json::json!({"passed":true,"report":directory.join("report.json"),"independent_processes":4})
    );
}
