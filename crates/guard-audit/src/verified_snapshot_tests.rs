use super::*;
fn record(id: &str) -> AuditRecord {
    AuditRecord {
        id: id.into(),
        timestamp_ms: 1,
        platform: "gateway".into(),
        event_type: "test".into(),
        source_app: "host".into(),
        agent_session_id: None,
        rule_id: "TEST".into(),
        severity: "Info".into(),
        action: "test".into(),
        human_message: String::new(),
        evidence_ref: None,
        user_decision: None,
        event_json: "{}".into(),
        attributed_agent: None,
    }
}
#[test]
fn 验证失败不返回记录也不重建链() {
    let store = AuditStore::open_in_memory().unwrap();
    store.append(&record("one")).unwrap();
    store
        .conn
        .execute("UPDATE audit_events SET event_json='changed'", [])
        .unwrap();
    assert!(store.verified_snapshot().is_err());
    assert!(!store.verify_chain().unwrap().ok);
    let body: String = store
        .conn
        .query_row("SELECT event_json FROM audit_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(body, "changed");
    // 错误分支也结束只读事务，不遗留数据库锁或替用户修复损坏。
    store
        .conn
        .execute("UPDATE audit_events SET event_json='{}'", [])
        .unwrap();
    assert_eq!(store.verified_snapshot().unwrap().records().len(), 1);
}
#[test]
fn 大记录和超量记录不能截断为通过() {
    let store = AuditStore::open_in_memory().unwrap();
    let mut huge = record("large");
    huge.event_json = "a".repeat(16 * 1024 * 1024);
    store.append(&huge).unwrap();
    assert!(store
        .verified_snapshot()
        .err()
        .unwrap()
        .to_string()
        .contains("超过"));
    let store = AuditStore::open_in_memory().unwrap();
    store.conn.execute("WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<8193) INSERT INTO audit_events(id,timestamp_ms) SELECT cast(n AS TEXT),1 FROM rows",[]).unwrap();
    assert!(store
        .verified_snapshot()
        .err()
        .unwrap()
        .to_string()
        .contains("超过"));
}
#[test]
fn 活动写入期间快照的记录数量和链头始终一致() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.db");
    let writer = AuditStore::open_with_key(&path, None).unwrap();
    writer.append(&record("0")).unwrap();
    drop(writer);
    let reader = AuditStore::open_read_only_with_key(&path, None).unwrap();
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writing = ready.clone();
    let thread = std::thread::spawn(move || {
        let writer = AuditStore::open_with_key(path, None).unwrap();
        writing.wait();
        for i in 1..=100 {
            writer.append(&record(&i.to_string())).unwrap();
        }
    });
    ready.wait();
    let mut previous = 0;
    for _ in 0..100 {
        let view = reader.verified_snapshot().unwrap();
        assert!(view.records().len() >= previous);
        previous = view.records().len();
        let mut head = crate::chain::GENESIS.to_string();
        for (i, row) in view.records().iter().enumerate() {
            assert_eq!(row.id, i.to_string());
            head = crate::chain::chain_hash(&head, row);
        }
        assert_eq!(head, view.head_sha256());
    }
    thread.join().unwrap();
    assert_eq!(reader.verified_snapshot().unwrap().records().len(), 101);
}
#[test]
fn 显式只读打开缺失数据库不会创建文件() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.db");
    assert!(AuditStore::open_read_only_with_key(&path, None).is_err());
    assert!(!path.exists());
}

#[test]
fn 来源迁移快照保留旧恢复容量而界面上限不变() {
    let store = AuditStore::open_in_memory().unwrap();
    let mut source = record("source");
    source.event_type = "GatewaySourceObserved".into();
    source.event_json = "a".repeat(16 * 1024 * 1024);
    store.append(&source).unwrap();
    assert!(store.verified_snapshot().is_err());
    let view = store.verified_source_snapshot().unwrap();
    assert_eq!(view.records().len(), 1);
    assert_eq!(view.records()[0].event_json, source.event_json);
    store.append(&record("unknown")).unwrap();
    assert!(
        store.verified_source_snapshot().is_err(),
        "不允许忽略其它事件"
    );
    let store = AuditStore::open_in_memory().unwrap();
    store.conn.execute("WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<4097) INSERT INTO audit_events(id,timestamp_ms,event_type) SELECT cast(n AS TEXT),1,'GatewaySourceObserved' FROM rows", []).unwrap();
    assert!(store
        .verified_source_snapshot()
        .err()
        .unwrap()
        .to_string()
        .contains("超限"));
}

#[test]
fn 批量最后记录失败时整批回滚且后续可重试() {
    let store = AuditStore::open_in_memory().unwrap();
    store.append(&record("existing")).unwrap();
    store.conn.execute_batch("CREATE TRIGGER fail_binding BEFORE INSERT ON audit_events WHEN NEW.id='binding' BEGIN SELECT RAISE(ABORT,'migration failure'); END;").unwrap();
    let batch = [record("source-1"), record("source-2"), record("binding")];
    assert!(store.append_batch(&batch).is_err());
    let view = store.verified_snapshot().unwrap();
    assert_eq!(view.records().len(), 1);
    assert_eq!(view.records()[0].id, "existing");
    store
        .conn
        .execute_batch("DROP TRIGGER fail_binding")
        .unwrap();
    store.append_batch(&batch).unwrap();
    assert_eq!(store.verified_snapshot().unwrap().records().len(), 4);
}
