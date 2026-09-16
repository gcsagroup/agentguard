//! 真实存储和网关库回归；这里的批准为显式宿主合成批准，CLI 认证另做实际验收。
use super::*;
use crate::provenance::SourceCollector;
use guard_audit::{FileDeviceKey, MemoryStore};
use guard_privacy::{Confidentiality, Integrity, Label};
use guard_schema::{GuardContract, RuleSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Instant;

struct Fixture {
    root: PathBuf,
    key: FileDeviceKey,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("agd-memory-gateway-{}", random_nonce()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("work")).unwrap();
        Self {
            root: root.canonicalize().unwrap(),
            key: FileDeviceKey::generate(),
        }
    }
    fn server(&self, write: bool) -> Server {
        self.server_with_scope(write, None)
    }
    fn server_with_scope(&self, write: bool, keys: Option<Vec<&str>>) -> Server {
        let db = self.root.join("memory.db");
        let witness = self.root.join("head.json");
        let scope = validated_id("test-memory-scope".into());
        let store = if db.exists() {
            MemoryStore::open(
                &db,
                &witness,
                scope.clone(),
                Box::new(self.key.clone()),
                self.key.verifying_key(),
                None,
            )
        } else {
            MemoryStore::create(
                &db,
                &witness,
                scope.clone(),
                Box::new(self.key.clone()),
                self.key.verifying_key(),
                None,
            )
        }
        .unwrap();
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guard-shell/policies/default.yaml");
        let (shell, rejected) = guard_shell::SafeShell::from_path(path)
            .unwrap()
            .with_workspace(
                vec![self.root.join("work").to_string_lossy().into_owned()],
                vec![],
            );
        assert!(rejected.is_empty());
        let mut engine = guard_core::Engine::new(
            RuleSet::from_yaml_str("version: '1.0'\nrules: []").unwrap(),
            GuardContract::default(),
        );
        if let Some(keys) = &keys {
            let plans = json!({"plans":[{"task_profile":"scoped-memory","goal":"条目范围回归",
                "allow":["persist_memory","recall_memory"],"scope":{"data_keys":keys}}]});
            engine = engine.with_task_plans(
                guard_schema::TaskPlanLibrary::from_yaml_str(&plans.to_string()).unwrap(),
            );
        }
        let journal =
            SharedJournal::from(ExecutionJournal::open(&self.root.join("audit.db")).unwrap());
        let sources = SourceCollector::open_with_execution_journal(
            &self.root.join("sources.db"),
            journal.clone(),
        )
        .unwrap();
        let mut server = Server::new(
            Gate::new(shell, engine),
            PendingConfirm::new(),
            Duration::from_secs(2),
        )
        .with_shared_journal(journal)
        .with_sources(Arc::new(Mutex::new(sources)));
        // 库测试明确采用本机文件读取；生产 with_memory 必须有隔离后端，另行验收。
        server.registry.lock().unwrap().enable_memory().unwrap();
        server.memory = Some(MemoryRuntime::new(store, scope, true, write).unwrap());
        server
            .start_host_session(keys.as_ref().map(|_| "scoped-memory"))
            .unwrap();
        server
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn call(server: &mut Server, name: &str, args: Value, answer: Option<Answer>) -> Value {
    let pending = server.pending.clone();
    let handle = answer.map(|answer| {
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(request) = pending.peek() {
                    assert!(pending.answer_bound(
                        &request.id,
                        request.action_sha256.as_deref().unwrap(),
                        request.binding.as_ref().unwrap().nonce(),
                        answer
                    ));
                    break;
                }
                assert!(Instant::now() < deadline, "没有出现预期的独立批准");
                thread::sleep(Duration::from_millis(5));
            }
        })
    });
    let request = serde_json::from_value(
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":name,"arguments":args,"_meta":{"agentguard_session_id":server.host_session_id}}}),
    )
    .unwrap();
    let result = server.handle(request).unwrap()["result"].clone();
    if let Some(handle) = handle {
        handle
            .join()
            .unwrap_or_else(|_| panic!("批准线程失败；真实回执：{result}"));
    }
    result
}

fn value(response: &Value) -> Value {
    assert_eq!(response["isError"], false, "{response}");
    serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap()
}
fn write(key: &str, version: u64, text: &str) -> Value {
    json!({"key":key,"expected_version":version,"text":text,"expires_at_ms":now_ms()+60_000})
}

fn govern(server: &mut Server, route: &str, mut body: Value) -> crate::operator::OperatorReply {
    if body.get("session_id").is_none() {
        body["session_id"] = json!(server.host_session_id);
    }
    server.handle_operator(
        crate::operator::OperatorCommand::Memory {
            route: route.into(),
            body,
        },
        "memory-host-test",
    )
}

fn review_body(view: &Value) -> Value {
    json!({"review_id":view["data"]["review_id"],"review_sha256":view["data"]["review_sha256"],
        "review_nonce":view["data"]["review_nonce"]})
}

#[test]
fn 宿主来源版本查看与完整预览后隔离恢复实际写入且批准不可重放() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    for (version, text) in [(0, "旧偏好"), (1, "新偏好")] {
        value(&call(
            &mut server,
            "memory_write",
            write("偏好", version, text),
            Some(Answer::Approved),
        ));
    }
    let before = server.memory.as_ref().unwrap().store.history().unwrap();
    let list = govern(&mut server, "/memory/list", json!({}));
    assert_eq!(list.0, 200, "{list:?}");
    assert_eq!(list.1["data"]["entries"][0]["version"], 2);
    assert_eq!(
        list.1["data"]["entries"][0]["sources"],
        json!(before[1].draft.sources)
    );
    let history = govern(&mut server, "/memory/history", json!({"key":"偏好"}));
    assert_eq!(history.0, 200);
    assert_eq!(
        history.1["data"]["versions"][0]["content"]["text"],
        "旧偏好"
    );
    let preview = govern(
        &mut server,
        "/memory/preview",
        json!({"operation":"quarantine","key":"偏好","expected_version":2}),
    );
    assert_eq!(preview.0, 200, "{preview:?}");
    assert_eq!(preview.1["data"]["draft"]["state"], "quarantined");
    assert_eq!(
        server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        2
    );
    let request = review_body(&preview.1);
    let applied = govern(&mut server, "/memory/apply", request.clone());
    assert_eq!(applied.0, 200, "{applied:?}");
    assert_eq!(value(&applied.1["data"]["execution"])["version"], 3);
    assert_eq!(govern(&mut server, "/memory/apply", request).0, 409);
    assert_eq!(
        value(&call(
            &mut server,
            "memory_read",
            json!({"key":"偏好"}),
            None
        ))["found"],
        false
    );
    drop(server);
    let mut server = fixture.server(true);
    let preview = govern(
        &mut server,
        "/memory/preview",
        json!({"operation":"restore","key":"偏好",
        "expected_version":3,"source_version":1,"expires_at_ms":now_ms()+90_000}),
    );
    assert_eq!(preview.0, 200, "{preview:?}");
    assert!(preview.1["data"]["draft"]["content"]
        .as_str()
        .unwrap()
        .contains("旧偏好"));
    let applied = govern(&mut server, "/memory/apply", review_body(&preview.1));
    assert_eq!(applied.0, 200, "{applied:?}");
    assert_eq!(value(&applied.1["data"]["execution"])["version"], 4);
    let after = server.memory.as_ref().unwrap().store.history().unwrap();
    assert_eq!(
        after[3].draft.label,
        before[1].draft.label.join(before[0].draft.label)
    );
    for source in &before[1].draft.sources {
        assert!(after[3].draft.sources.contains(source));
    }
    assert!(memory::material(&after[3]).unwrap() == memory::material(&before[0]).unwrap());
    assert!(server.pending.peek().is_none());
}

#[test]
fn 宿主治理拒绝篡改批准旧会话失效版本与新策略且丢弃不写入() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 0, "正文"),
        Some(Answer::Approved),
    ));
    assert_eq!(
        govern(
            &mut server,
            "/memory/list",
            json!({"session_id":"old-session"})
        )
        .0,
        409
    );
    assert_eq!(
        govern(&mut server, "/memory/list", json!({"trusted":true})).0,
        409
    );
    for scenario in ["nonce", "version", "policy", "discard", "pause", "expired"] {
        let current = server.memory.as_ref().unwrap().latest(now_ms()).unwrap()["偏好"]
            .draft
            .version;
        let preview = govern(
            &mut server,
            "/memory/preview",
            json!({"operation":"revoke","key":"偏好","expected_version":current}),
        );
        assert_eq!(preview.0, 200, "{preview:?}");
        let mut request = review_body(&preview.1);
        let policy = server.policy_version.clone();
        match scenario {
            "nonce" => request["review_nonce"] = json!("0".repeat(64)),
            "version" => {
                value(&call(
                    &mut server,
                    "memory_write",
                    write("偏好", current, "并发新版"),
                    Some(Answer::Approved),
                ));
            }
            "policy" => server.policy_version = "changed-policy".into(),
            "pause" => {
                server.pending.pause();
            }
            "expired" => {
                thread::sleep(Duration::from_millis(2050));
            }
            _ => {}
        }
        let count = server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len();
        let route = if scenario == "discard" {
            "/memory/discard"
        } else {
            "/memory/apply"
        };
        let result = govern(&mut server, route, request.clone());
        assert_eq!(
            result.0,
            if scenario == "discard" { 200 } else { 409 },
            "{scenario}: {result:?}"
        );
        assert_eq!(
            server
                .memory
                .as_ref()
                .unwrap()
                .store
                .history()
                .unwrap()
                .len(),
            count
        );
        assert_eq!(govern(&mut server, "/memory/apply", request).0, 409);
        server.policy_version = policy;
        if scenario == "pause" {
            assert!(server
                .pending
                .resume_from_host(server.pending.cancellation_epoch()));
        }
    }
}

#[test]
fn 宿主治理分页保留全部历史且模型没有管理读取工具() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    for i in 0..18 {
        value(&call(
            &mut server,
            "memory_write",
            write(&format!("entry-{i:02}"), 0, "偏好"),
            Some(Answer::Approved),
        ));
    }
    let first = govern(&mut server, "/memory/list", json!({}));
    assert_eq!(first.0, 200);
    assert_eq!(first.1["data"]["entries"].as_array().unwrap().len(), 16);
    let second = govern(
        &mut server,
        "/memory/list",
        json!({"after_key":first.1["data"]["next_key"]}),
    );
    assert_eq!(second.1["data"]["entries"].as_array().unwrap().len(), 2);
    assert!(second.1["data"]["next_key"].is_null());
    // 两类分页独立准备，不能为测试跨页而扩大单任务来源图的 64 项安全上限。
    drop(server);
    drop(fixture);
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    for version in 0..10 {
        value(&call(
            &mut server,
            "memory_write",
            write("entry-00", version, "历史"),
            Some(Answer::Approved),
        ));
    }
    let first = govern(&mut server, "/memory/history", json!({"key":"entry-00"}));
    assert_eq!(first.1["data"]["versions"].as_array().unwrap().len(), 8);
    let second = govern(
        &mut server,
        "/memory/history",
        json!({"key":"entry-00","after_version":first.1["data"]["next_version"]}),
    );
    assert_eq!(second.1["data"]["versions"].as_array().unwrap().len(), 2);
    for name in ["memory_list", "memory_history", "memory_apply"] {
        let response = call(&mut server, name, json!({}), None);
        assert_ne!(response["isError"], false);
    }
    server.memory.as_mut().unwrap().allow_read = false;
    assert_eq!(
        govern(&mut server, "/memory/history", json!({"key":"entry-00"})).0,
        409
    );
}

#[test]
fn 隔离跨重启不可读_恢复旧正文生成新版并保留新增来源() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 0, "旧正文"),
        Some(Answer::Approved),
    ));
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 1, "被修改的正文"),
        Some(Answer::Approved),
    ));
    let before = server.memory.as_ref().unwrap().store.history().unwrap();
    assert_ne!(before[0].draft.sources, before[1].draft.sources);
    assert_eq!(
        value(&call(
            &mut server,
            "memory_quarantine",
            json!({"key":"偏好","expected_version":2}),
            Some(Answer::Approved)
        ))["state"],
        "quarantined"
    );
    drop(server);
    let mut server = fixture.server(true);
    assert_eq!(
        value(&call(
            &mut server,
            "memory_read",
            json!({"key":"偏好"}),
            None
        ))["found"],
        false
    );
    let expires = now_ms() + 120_000;
    assert_eq!(
        value(&call(
            &mut server,
            "memory_restore",
            json!({"key":"偏好","expected_version":3,"source_version":1,"expires_at_ms":expires}),
            Some(Answer::Approved)
        ))["version"],
        4
    );
    let history = server.memory.as_ref().unwrap().store.history().unwrap();
    assert_eq!(history.len(), 4);
    let restored = &history[3].draft;
    assert_eq!(restored.content, before[0].draft.content);
    assert_eq!(restored.previous_sha256, Some(history[2].sha256().unwrap()));
    assert_eq!(restored.expires_at_ms, expires);
    assert!(restored.preserves(&before[0].draft) && restored.preserves(&history[2].draft));
    assert_eq!(
        restored.label,
        Label::new(Integrity::Tainted, Confidentiality::High)
    );
    drop(server);
    let mut server = fixture.server(true);
    let read = value(&call(
        &mut server,
        "memory_read",
        json!({"key":"偏好"}),
        None,
    ));
    assert_eq!(read["memory"]["content"]["text"], "旧正文");
    assert_eq!(read["memory"]["version"], 4);
    assert_eq!(read["memory"]["instruction_authority"], "none");
}

#[test]
fn 撤销文档恢复使用已批准历史快照而非当前路径内容() {
    let fixture = Fixture::new();
    let path = fixture.root.join("work/治理.md");
    fs::write(&path, "旧资料 青色基地").unwrap();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "rag_import",
        json!({"key":"文档","expected_version":0,"path":path,"expires_at_ms":now_ms()+60_000}),
        Some(Answer::Approved),
    ));
    value(&call(
        &mut server,
        "memory_revoke",
        json!({"key":"文档","expected_version":1}),
        Some(Answer::Approved),
    ));
    fs::remove_file(&path).unwrap();
    drop(server);
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_restore",
        json!({"key":"文档","expected_version":2,"source_version":1,"expires_at_ms":now_ms()+60_000}),
        Some(Answer::Approved),
    ));
    let hits = value(&call(
        &mut server,
        "rag_search",
        json!({"query":"青色","limit":4}),
        None,
    ));
    assert_eq!(hits["hits"][0]["document"]["text"], "旧资料 青色基地");
    assert_eq!(hits["hits"][0]["document"]["path"], json!(path));
    assert_eq!(hits["hits"][0]["version"], 3);
    assert_eq!(hits["hits"][0]["label"]["integrity"], "tainted");
}

#[test]
fn 治理拒绝无批准旧版本错误来源和自报可信且不写新记录() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 0, "仍是原文"),
        Some(Answer::Approved),
    ));
    let quarantine = json!({"key":"偏好","expected_version":1});
    assert_eq!(
        call(
            &mut server,
            "memory_quarantine",
            quarantine.clone(),
            Some(Answer::Denied)
        )["isError"],
        true
    );
    let restore = json!({"key":"偏好","expected_version":1,"source_version":1,"expires_at_ms":now_ms()+60_000});
    assert_eq!(
        call(
            &mut server,
            "memory_restore",
            restore.clone(),
            Some(Answer::Denied)
        )["isError"],
        true
    );
    for (field, bad) in [
        ("expected_version", json!(0)),
        ("source_version", json!(0)),
        ("source_version", json!(99)),
        ("key", json!("不存在")),
        ("expires_at_ms", json!(1)),
        ("expires_at_ms", json!(now_ms() + 31 * 24 * 60 * 60 * 1000)),
        ("trusted", json!(true)),
        ("approved", json!(true)),
    ] {
        let mut args = restore.clone();
        args[field] = bad;
        assert_eq!(
            call(&mut server, "memory_restore", args, None)["isError"],
            true
        );
        assert!(server.pending.peek().is_none());
    }
    assert_eq!(
        server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        1
    );
    value(&call(
        &mut server,
        "memory_quarantine",
        quarantine,
        Some(Answer::Approved),
    ));
    let invalid_source = json!({"key":"偏好","expected_version":2,"source_version":2,"expires_at_ms":now_ms()+60_000});
    assert_eq!(
        call(&mut server, "memory_restore", invalid_source, None)["isError"],
        true
    );
    assert_eq!(
        server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        2
    );
    drop(server);
    let mut readonly = fixture.server(false);
    for (name, args) in [
        (
            "memory_quarantine",
            json!({"key":"偏好","expected_version":2}),
        ),
        (
            "memory_restore",
            json!({"key":"偏好","expected_version":2,"source_version":1,"expires_at_ms":now_ms()+60_000}),
        ),
    ] {
        assert_eq!(call(&mut readonly, name, args, None)["isError"], true);
        assert!(readonly.pending.peek().is_none());
    }
    assert_eq!(
        readonly
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn 治理工具不能越过任务键范围或缺少会话绑定() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_write",
        write("秘密", 0, "不能恢复给其他任务"),
        Some(Answer::Approved),
    ));
    drop(server);
    let mut server = fixture.server_with_scope(true, Some(vec!["许可"]));
    for (name, args) in [
        (
            "memory_quarantine",
            json!({"key":"秘密","expected_version":1}),
        ),
        (
            "memory_restore",
            json!({"key":"秘密","expected_version":1,"source_version":1,"expires_at_ms":now_ms()+60_000}),
        ),
    ] {
        assert_eq!(call(&mut server, name, args.clone(), None)["isError"], true);
        let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap();
        assert_eq!(server.handle(request).unwrap()["result"]["isError"], true);
        assert!(server.pending.peek().is_none());
    }
    assert_eq!(
        server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn 批准后实际保存并跨重启读回来源标签和正文() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    assert_eq!(
        value(&call(
            &mut server,
            "memory_write",
            write("偏好", 0, "中文正文😀"),
            Some(Answer::Approved)
        ))["version"],
        1
    );
    let first = value(&call(
        &mut server,
        "memory_read",
        json!({"key":"偏好"}),
        None,
    ));
    assert_eq!(
        first["memory"]["content"],
        json!({"kind":"note","text":"中文正文😀"})
    );
    assert_eq!(first["memory"]["label"]["integrity"], "tainted");
    assert_eq!(first["memory"]["label"]["confidentiality"], "high");
    assert!(!first["memory"]["sources"].as_array().unwrap().is_empty());
    drop(server);
    let mut reopened = fixture.server(true);
    assert_eq!(
        value(&call(
            &mut reopened,
            "memory_read",
            json!({"key":"偏好"}),
            None
        )),
        first
    );
    let ancestors = reopened.sources.lock().unwrap().memory_sources().unwrap();
    for original in first["memory"]["sources"].as_array().unwrap() {
        assert!(ancestors
            .iter()
            .any(|s| serde_json::to_value(s).unwrap() == *original));
    }
}

#[test]
fn 拒绝自报授权错误版本和超期均不写入() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    assert_eq!(
        call(
            &mut server,
            "memory_write",
            write("偏好", 0, "不保存"),
            Some(Answer::Denied)
        )["isError"],
        true
    );
    let mut forged = write("偏好", 0, "伪造可信");
    forged["trusted"] = true.into();
    assert_eq!(
        call(&mut server, "memory_write", forged, None)["isError"],
        true
    );
    let mut expired = write("偏好", 0, "过期");
    expired["expires_at_ms"] = (now_ms() - 1).into();
    assert_eq!(
        call(&mut server, "memory_write", expired, None)["isError"],
        true
    );
    assert_eq!(
        call(
            &mut server,
            "memory_write",
            write("偏好", 1, "旧版本"),
            None
        )["isError"],
        true
    );
    assert!(server
        .memory
        .as_ref()
        .unwrap()
        .store
        .history()
        .unwrap()
        .is_empty());
}

#[test]
fn 撤销后新会话不回落旧版且不复用旧版本() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 0, "第一版"),
        Some(Answer::Approved),
    ));
    value(&call(
        &mut server,
        "memory_write",
        write("偏好", 1, "第二版"),
        Some(Answer::Approved),
    ));
    assert_eq!(
        call(
            &mut server,
            "memory_revoke",
            json!({"key":"偏好","expected_version":1}),
            None
        )["isError"],
        true
    );
    assert_eq!(
        value(&call(
            &mut server,
            "memory_revoke",
            json!({"key":"偏好","expected_version":2}),
            Some(Answer::Approved)
        ))["version"],
        3
    );
    drop(server);
    let mut server = fixture.server(true);
    assert_eq!(
        value(&call(
            &mut server,
            "memory_read",
            json!({"key":"偏好"}),
            None
        ))["found"],
        false
    );
    assert_eq!(
        server
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn 实际文本文件导入后检索保留快照出处行号并过滤撤销() {
    let fixture = Fixture::new();
    let path = fixture.root.join("work/知识.md");
    let text = "# 项目资料\n火星基地的颜色是青色。\n普通研究说明😀\n";
    fs::write(&path, text).unwrap();
    let mut server = fixture.server(true);
    value(&call(
        &mut server,
        "rag_import",
        json!({"key":"资料","expected_version":0,"path":path,"expires_at_ms":now_ms()+60_000}),
        Some(Answer::Approved),
    ));
    fs::write(&path, "宿主文件后来改变，不应替换已批准快照").unwrap();
    let result = value(&call(
        &mut server,
        "rag_search",
        json!({"query":"火星 青色","limit":4}),
        None,
    ));
    assert_eq!(result["hits"].as_array().unwrap().len(), 1);
    assert_eq!(result["hits"][0]["document"]["text"], text);
    assert_eq!(result["hits"][0]["document"]["start_line"], 1);
    assert_eq!(result["hits"][0]["document"]["end_line"], 3);
    assert_eq!(
        result["hits"][0]["document"]["document_sha256"],
        json!(crate::tool_registry::digest(text.as_bytes()))
    );
    value(&call(
        &mut server,
        "memory_revoke",
        json!({"key":"资料","expected_version":1}),
        Some(Answer::Approved),
    ));
    drop(server);
    let mut server = fixture.server(true);
    assert!(value(&call(
        &mut server,
        "rag_search",
        json!({"query":"火星","limit":4}),
        None
    ))["hits"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn 只读授权与旧会话不能触发保存或确认() {
    let fixture = Fixture::new();
    let mut server = fixture.server(false);
    assert_eq!(
        call(
            &mut server,
            "memory_write",
            write("偏好", 0, "没有写权限"),
            None
        )["isError"],
        true
    );
    let request = serde_json::from_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"memory_read","arguments":{"key":"偏好"},"_meta":{"agentguard_session_id":"old-session"}}})).unwrap();
    assert_eq!(server.handle(request).unwrap()["result"]["isError"], true);
    assert!(server.pending.peek().is_none());
    assert_eq!(
        server.memory_status()["third_party_internal_memory"],
        "uncovered"
    );
}

#[test]
fn 批准等待期间暂停不得落盘() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    let pending = server.pending.clone();
    let cancel = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while pending.peek().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let request = pending.peek().unwrap();
        pending.pause();
        assert!(!pending.answer_bound(
            &request.id,
            request.action_sha256.as_deref().unwrap(),
            request.binding.as_ref().unwrap().nonce(),
            Answer::Approved
        ));
    });
    assert_eq!(
        call(
            &mut server,
            "memory_write",
            write("偏好", 0, "已暂停"),
            None
        )["isError"],
        true
    );
    cancel.join().unwrap();
    assert!(server
        .memory
        .as_ref()
        .unwrap()
        .store
        .history()
        .unwrap()
        .is_empty());
}

#[test]
fn 见证失效返回未知并停止会话且审计不谎报未派发() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    let pending = server.pending.clone();
    let witness = fixture.root.join("head.json");
    let fault = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while pending.peek().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        fs::remove_file(witness).unwrap();
        let request = pending.peek().unwrap();
        assert!(pending.answer_bound(
            &request.id,
            request.action_sha256.as_deref().unwrap(),
            request.binding.as_ref().unwrap().nonce(),
            Answer::Approved
        ));
    });
    let result = call(
        &mut server,
        "memory_write",
        write("偏好", 0, "未确认"),
        None,
    );
    fault.join().unwrap();
    assert_eq!(result["_meta"]["agentguard"]["outcome"], "unknown");
    assert!(server.pending.is_paused());
    drop(server);
    let audit =
        guard_audit::AuditStore::open_read_only_with_key(fixture.root.join("audit.db"), None)
            .unwrap();
    let rows = audit.verified_snapshot().unwrap();
    let terminal = rows
        .records()
        .iter()
        .find(|r| r.event_type == "GatewayExecutionFinished")
        .unwrap();
    let body: Value = serde_json::from_str(&terminal.event_json).unwrap();
    assert_eq!(body["outcome"], "unknown");
    assert_eq!(body["dispatched"], true);
}

#[test]
fn 二进制导入禁止原生解析和客户端自报解析结果() {
    let fixture = Fixture::new();
    let mut server = fixture.server(true);
    let path = fixture.root.join("work/manual.pdf");
    fs::write(&path, b"%PDF-synthetic").unwrap();
    let args =
        json!({"key":"资料","expected_version":0,"path":path,"expires_at_ms":now_ms()+60_000});
    let response = call(&mut server, "rag_import", args.clone(), None);
    assert_eq!(response["isError"], true);
    assert!(response.to_string().contains("隔离后端"));
    for field in ["document", "parser_sha256", "format", "trusted"] {
        let mut forged = args.clone();
        forged[field] = json!("客户端声明");
        assert_eq!(
            call(&mut server, "rag_import", forged, None)["isError"],
            true
        );
    }
    assert!(server
        .parse_tool(
            "read_file",
            &json!({"path":path,"operation":"parse_document"})
        )
        .is_err());
    assert!(server.pending.peek().is_none());
    assert!(server
        .memory
        .as_ref()
        .unwrap()
        .store
        .history()
        .unwrap()
        .is_empty());
    let output = ToolCall::ParseDocument {
        path,
        format: "pdf".into(),
    }
    .execute();
    assert!(!output.ok && !output.dispatched);
}

#[test]
fn 超过文档限额和无效检索参数拒绝且不保存() {
    let fixture = Fixture::new();
    let path = fixture.root.join("work/large.md");
    fs::write(&path, "x".repeat(memory::MAX_TEXT_BYTES + 1)).unwrap();
    let mut server = fixture.server(true);
    assert_eq!(
        call(
            &mut server,
            "rag_import",
            json!({"key":"资料","expected_version":0,"path":path,"expires_at_ms":now_ms()+60_000}),
            None
        )["isError"],
        true
    );
    for args in [
        json!({"query":" ","limit":1}),
        json!({"query":"x","limit":5}),
        json!({"query":"x","limit":1,"trusted":true}),
    ] {
        assert_eq!(call(&mut server, "rag_search", args, None)["isError"], true);
    }
    assert!(server
        .memory
        .as_ref()
        .unwrap()
        .store
        .history()
        .unwrap()
        .is_empty());
}

#[test]
fn 只返回授权条目且越权直读与写入不会因工具名放行() {
    let fixture = Fixture::new();
    let path = fixture.root.join("work/notes.md");
    fs::write(&path, "# 资料\n共同检索词：蓝鹭\n").unwrap();
    let mut server = fixture.server(true);
    for key in ["a-private", "z-public"] {
        value(&call(
            &mut server,
            "rag_import",
            json!({"key":key,"expected_version":0,"path":path,"expires_at_ms":now_ms()+60_000}),
            Some(Answer::Approved),
        ));
    }
    drop(server);
    let mut scoped = fixture.server_with_scope(true, Some(vec!["z-public"]));
    let found = value(&call(
        &mut scoped,
        "rag_search",
        json!({"query":"蓝鹭","limit":1}),
        None,
    ));
    assert_eq!(found["hits"].as_array().unwrap().len(), 1);
    assert_eq!(found["hits"][0]["key"], "z-public");
    for key in ["a-private", "memory_read", "absent-private"] {
        assert_eq!(
            call(&mut scoped, "memory_read", json!({"key":key}), None)["isError"],
            true
        );
    }
    assert_eq!(
        call(
            &mut scoped,
            "memory_write",
            write("a-private", 1, "越权更新"),
            None
        )["isError"],
        true
    );
    assert_eq!(
        scoped
            .memory
            .as_ref()
            .unwrap()
            .store
            .history()
            .unwrap()
            .len(),
        2
    );
    drop(scoped);
    let mut empty = fixture.server_with_scope(false, Some(vec![]));
    let result = value(&call(
        &mut empty,
        "rag_search",
        json!({"query":"蓝鹭","limit":4}),
        None,
    ));
    assert!(result["hits"].as_array().unwrap().is_empty());
}
