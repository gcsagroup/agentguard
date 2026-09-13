//! 真实宿主控制与回写回归。默认不启动 Docker；显式指定本地镜像摘要后运行忽略项。
//! 本文件通过公开 Server 接口精确构造 HTTP 已撤权、队列尚未处理的并发中间态。
//! 只使用本测试创建的目录和短期容器；测试回执不保存批准随机值。

#![cfg(unix)]

use guard_audit::AuditStore;
use guard_gateway::operator::OperatorCommand;
use guard_gateway::{Gate, PendingConfirm, Server};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

const ORIGINAL: &str = "host baseline\n";
const REPLACEMENT: &str = "approved replacement\n";
const INSTANCE: &str = "independent-operator-review";

fn file_tree(root: &Path) -> Value {
    use std::os::unix::fs::PermissionsExt;
    fn visit(root: &Path, path: &Path, out: &mut Vec<Value>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let kind = if metadata.is_dir() {
            "directory"
        } else if metadata.is_file() {
            "file"
        } else {
            "link_or_special"
        };
        let mut row = json!({"path":path.strip_prefix(root).unwrap(),"kind":kind,"mode":metadata.permissions().mode() & 0o7777});
        if metadata.is_file() {
            let bytes = std::fs::read(path).unwrap();
            row["bytes"] = json!(bytes.len());
            row["sha256"] = json!(format!("{:x}", Sha256::digest(&bytes)));
        } else if metadata.file_type().is_symlink() {
            row["target"] = json!(std::fs::read_link(path).unwrap());
        }
        out.push(row);
        if metadata.is_dir() {
            let mut children = std::fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children {
                visit(root, &child, out);
            }
        }
    }
    let mut rows = vec![];
    visit(root, root, &mut rows);
    json!(rows)
}

struct Fixture {
    name: String,
    root: PathBuf,
    host: PathBuf,
    snapshot: PathBuf,
    audit: PathBuf,
    image: String,
    initial_tree: Value,
    pending: PendingConfirm,
    server: Server,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let image = std::env::var("AGD_OPERATOR_TEST_IMAGE")
            .expect("显式测试须提供 AGD_OPERATOR_TEST_IMAGE=sha256:<本地镜像摘要>");
        let root =
            std::env::temp_dir().join(format!("agd-operator-review-{}-{name}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let host = root.join("workspace");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("sample.txt"), ORIGINAL).unwrap();
        let initial_tree = file_tree(&host);
        let root_text = host.to_string_lossy().to_string();
        let executor = guard_gateway::isolation::DockerExecutor::new(
            image.clone(),
            std::slice::from_ref(&root_text),
            std::slice::from_ref(&root_text),
        )
        .unwrap();
        let workspaces = executor.workspaces();
        assert_eq!(workspaces[0]["writeback_available"], true);
        let snapshot = PathBuf::from(workspaces[0]["snapshot"].as_str().unwrap());
        std::fs::write(snapshot.join("sample.txt"), REPLACEMENT).unwrap();
        let (shell, rejected) = guard_shell::SafeShell::from_default_policy()
            .with_workspace([root_text.as_str()], [root_text.as_str()]);
        assert!(rejected.is_empty());
        let engine = guard_core::Engine::from_paths(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../guard-schema/rules/p0_rules.yaml"),
            None::<PathBuf>,
        )
        .unwrap();
        let pending = PendingConfirm::new();
        let audit = root.join("audit.db");
        let journal = guard_gateway::journal::ExecutionJournal::open(&audit).unwrap();
        let mut server = Server::new(
            Gate::new(shell, engine),
            pending.clone(),
            Duration::from_secs(120),
        )
        .with_isolation(executor)
        .with_journal(journal);
        server.start_host_session(None).unwrap();
        Self {
            name: name.into(),
            root,
            host,
            snapshot,
            audit,
            image,
            initial_tree,
            pending,
            server,
        }
    }

    fn preview(&mut self) -> Value {
        let reply = self.server.handle_operator(
            OperatorCommand::Preview {
                workspace_id: "workspace-0".into(),
            },
            INSTANCE,
        );
        assert_eq!(reply.0, 200, "预览失败：{:?}", reply);
        reply.1
    }

    fn command(review: &Value, discard: bool) -> OperatorCommand {
        let review_id = review["review_id"].as_str().unwrap().into();
        let review_sha256 = review["review_sha256"].as_str().unwrap().into();
        let review_nonce = review["review_nonce"].as_str().unwrap().into();
        if discard {
            OperatorCommand::Discard {
                review_id,
                review_sha256,
                review_nonce,
            }
        } else {
            OperatorCommand::Apply {
                review_id,
                review_sha256,
                review_nonce,
            }
        }
    }

    fn apply(&mut self, review: &Value, epoch: u64) -> (u16, Value) {
        self.server
            .handle_operator_at(Self::command(review, false), INSTANCE, epoch)
    }

    fn unchanged(&self) -> bool {
        file_tree(&self.host) == self.initial_tree
    }

    fn rows(&self) -> Vec<guard_audit::AuditRecord> {
        AuditStore::open_read_only(&self.audit)
            .unwrap()
            .list_recent(100)
            .unwrap()
    }

    fn fail_audit_event(&self, event_type: &str) {
        // 外部 SQLite 触发器制造真实事务失败，不把源码桩视为磁盘失败证据。
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg("import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"CREATE TRIGGER reject_test_event BEFORE INSERT ON audit_events WHEN NEW.event_type='\"+sys.argv[2]+\"' BEGIN SELECT RAISE(ABORT, 'AGD_OPERATOR_TEST_AUDIT_FAILURE'); END\"); c.commit()")
            .arg(&self.audit)
            .arg(event_type)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
    }

    fn record(&self, passed: bool, evidence: Value) {
        static BUILD: OnceLock<Value> = OnceLock::new();
        let build = BUILD.get_or_init(|| {
            let exe = std::env::current_exe().unwrap();
            let hash = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
            json!({"test_executable":exe,"test_executable_sha256":hash(&std::fs::read(&exe).unwrap()),
                "source_sha256":{
                    "operator.rs":hash(include_bytes!("../src/operator.rs")),
                    "workspace_control.rs":hash(include_bytes!("../src/workspace_control.rs")),
                    "confirm.rs":hash(include_bytes!("../src/confirm.rs")),
                    "writeback.rs":hash(include_bytes!("../src/writeback.rs")),
                    "workspace_control_test.rs":hash(include_bytes!("workspace_control.rs")),
                }})
        });
        let report = json!({"case":self.name,"passed":passed,"build":build,"image":self.image,
            "scope":"真实Server、Docker摄入快照、文件回写及SQLite；队列并发中间态由公开入口确定性构造",
            "fixture":self.root,"host":self.host,"snapshot":self.snapshot,
            "host_unchanged":self.unchanged(),"initial_host_tree":self.initial_tree,
            "actual_host_tree":file_tree(&self.host),"session_state":self.server.host_session_state(),
            "evidence":evidence});
        let output = std::env::var_os("AGD_OPERATOR_REPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.root.clone());
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(
            output.join(format!("{}.json", self.name)),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        assert!(passed, "{}", report);
    }
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 暂停前已经排队的回写不得吸收新撤权代次() {
    let mut f = Fixture::new("old-job-after-pause");
    let review = f.preview();
    let old = f.pending.cancellation_epoch();
    f.pending.pause();
    let reply = f.apply(&review, old);
    let hidden = f.server.operator_status(INSTANCE)["pending_review"].is_null();
    f.record(reply.0 == 409 && f.unchanged() && hidden, json!({"reply":reply,"old_epoch":old,"current_epoch":f.pending.cancellation_epoch(),"review_hidden":hidden}));
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 暂停后新提交不能复用暂停前的旧预览() {
    let mut f = Fixture::new("new-job-old-review-after-pause");
    let review = f.preview();
    f.pending.pause();
    let reply = f.apply(&review, f.pending.cancellation_epoch());
    f.record(reply.0 == 409 && f.unchanged(), json!({"reply":reply}));
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 暂停前旧预览请求不得重新生成可用批准() {
    let mut f = Fixture::new("old-preview-after-pause");
    let old = f.pending.cancellation_epoch();
    f.pending.pause();
    let reply = f.server.handle_operator_at(
        OperatorCommand::Preview {
            workspace_id: "workspace-0".into(),
        },
        INSTANCE,
        old,
    );
    let hidden = f.server.operator_status(INSTANCE)["pending_review"].is_null();
    f.record(
        reply.0 == 409 && f.unchanged() && hidden,
        json!({"reply":reply,"review_hidden":hidden}),
    );
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 连接关闭后旧回写和恢复均拒绝() {
    let mut f = Fixture::new("old-job-after-close");
    let review = f.preview();
    let old = f.pending.cancellation_epoch();
    f.pending.close();
    let reply = f.apply(&review, old);
    let resume = f.server.handle_operator(OperatorCommand::Resume, INSTANCE);
    f.record(
        reply.0 == 409 && resume.0 == 409 && f.unchanged(),
        json!({"reply":reply,"resume":resume}),
    );
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 敏感目标硬拒绝不会生成独立批准() {
    let mut f = Fixture::new("sensitive-target-denied");
    std::fs::write(f.snapshot.join(".netrc"), "敏感配置示例").unwrap();
    let reply = f.server.handle_operator(
        OperatorCommand::Preview {
            workspace_id: "workspace-0".into(),
        },
        INSTANCE,
    );
    let hidden = f.server.operator_status(INSTANCE)["pending_review"].is_null();
    let no_started = f
        .rows()
        .iter()
        .all(|row| row.event_type != "GatewayExecutionStarted");
    f.record(
        reply.0 == 409
            && reply.1["error"] == "WORKSPACE_DENIED"
            && hidden
            && no_started
            && f.unchanged()
            && !f.host.join(".netrc").exists(),
        json!({"reply":reply,"review_hidden":hidden,"no_started":no_started}),
    );
}

#[test]
#[ignore = "需要显式本地 Docker 镜像和真实工作区"]
fn 放弃差异必须绑定且单次消费并保留拒绝审计() {
    let mut f = Fixture::new("discard-bound-once");
    let review = f.preview();
    let mut wrong = review.clone();
    wrong["review_nonce"] = json!("0".repeat(64));
    let denied = f
        .server
        .handle_operator(Fixture::command(&wrong, true), INSTANCE);
    let kept =
        f.server.operator_status(INSTANCE)["pending_review"]["review_id"] == review["review_id"];
    let discard = f
        .server
        .handle_operator(Fixture::command(&review, true), INSTANCE);
    let replay = f.apply(&review, f.pending.cancellation_epoch());
    let rows = f.rows();
    let no_started = rows
        .iter()
        .all(|row| row.event_type != "GatewayExecutionStarted");
    let refused = rows
        .iter()
        .filter(|row| row.event_type == "GatewayExecutionFinished" && row.action == "refused")
        .count();
    let hidden = f.server.operator_status(INSTANCE)["pending_review"].is_null();
    let ok = denied.0 == 409
        && kept
        && discard.0 == 200
        && replay.0 == 409
        && no_started
        && refused == 1
        && hidden
        && f.unchanged();
    f.record(ok, json!({"wrong_binding_status":denied.0,"review_kept_on_wrong_binding":kept,"discard_status":discard.0,"replay_status":replay.0,"no_started":no_started,"refused_receipts":refused,"review_hidden":hidden}));
}

#[test]
#[ignore = "需要显式本地 Docker 镜像、Python SQLite 与真实工作区"]
fn 开始审计事务失败必须零回写并锁定会话() {
    let mut f = Fixture::new("audit-start-failure");
    let review = f.preview();
    f.fail_audit_event("GatewayExecutionStarted");
    let reply = f.apply(&review, f.pending.cancellation_epoch());
    let retry = f.apply(&review, f.pending.cancellation_epoch());
    let resume = f.server.handle_operator(OperatorCommand::Resume, INSTANCE);
    let no_started = f
        .rows()
        .iter()
        .all(|row| row.event_type != "GatewayExecutionStarted");
    f.record(reply.0 == 500 && retry.0 == 409 && resume.0 == 409 && f.server.host_session_state() == "failed" && no_started && f.unchanged(), json!({"reply":reply,"retry_status":retry.0,"resume_status":resume.0,"no_started":no_started}));
}

#[test]
#[ignore = "需要显式本地 Docker 镜像、Python SQLite 与真实工作区"]
fn 终态审计事务失败必须报告未知且禁止自动重放() {
    let mut f = Fixture::new("audit-finish-failure");
    let review = f.preview();
    f.fail_audit_event("GatewayExecutionFinished");
    let reply = f.apply(&review, f.pending.cancellation_epoch());
    let changed = std::fs::read_to_string(f.host.join("sample.txt")).unwrap() == REPLACEMENT;
    let retry = f.apply(&review, f.pending.cancellation_epoch());
    let resume = f.server.handle_operator(OperatorCommand::Resume, INSTANCE);
    let rows = f.rows();
    let started = rows
        .iter()
        .filter(|row| row.event_type == "GatewayExecutionStarted")
        .count();
    let terminal = rows
        .iter()
        .filter(|row| row.event_type == "GatewayExecutionFinished")
        .count();
    f.record(reply.0 == 200 && reply.1["result"]["outcome"] == "unknown" && changed && retry.0 == 409 && resume.0 == 409 && f.server.host_session_state() == "failed" && f.pending.is_paused() && started == 1 && terminal == 0, json!({"reply":reply,"host_has_authorized_result":changed,"retry_status":retry.0,"resume_status":resume.0,"started":started,"terminal":terminal}));
}
