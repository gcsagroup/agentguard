//! 当前网关的记忆与委托治理。连接令牌和一次性批准随机值始终留在 Rust。
use super::*;
use guard_privacy::{MemoryDraft, MemoryState};
use guard_schema::{ActionSnapshot, ValidatedId};
use serde_json::{json, Value};

#[derive(Clone, Default)]
pub(super) struct GovernanceState {
    epoch: u64,
    review: Option<MemoryReview>,
    delegation: Option<Value>,
}
impl GovernanceState {
    pub(super) fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.review = None;
        self.delegation = None;
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceRequest {
    MemoryList {
        after_key: Option<ValidatedId>,
    },
    MemoryHistory {
        key: ValidatedId,
        after_version: u64,
    },
    MemoryPreview {
        key: ValidatedId,
        expected_version: u64,
        change: MemoryChange,
        source_version: Option<u64>,
        expires_at_ms: Option<i64>,
    },
    MemoryApply {
        review_id: String,
        review_sha256: String,
    },
    MemoryDiscard {
        review_id: String,
        review_sha256: String,
    },
    DelegationStatus,
    DelegationRevoke {
        host_session_id: String,
        grant_id: String,
    },
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryChange {
    Quarantine,
    Revoke,
    Restore,
}

#[derive(Clone, Deserialize)]
struct MemoryReview {
    review_id: String,
    review_sha256: String,
    review_nonce: String,
    operation: MemoryChange,
    expires_at_ms: i64,
    action: ActionSnapshot,
    draft: MemoryDraft,
    instruction_authority: String,
    completed_effects: String,
}
impl MemoryReview {
    fn validate(&self, session: &str, now: i64) -> Result<(), String> {
        let action = self.action.spec();
        self.draft
            .validate_at(now)
            .map_err(|_| "GOVERNANCE_BINDING")?;
        let binding = ApprovalBinding::new(
            ValidatedId::new(self.review_id.clone()).map_err(|_| "GOVERNANCE_BINDING")?,
            self.action.clone(),
            self.review_nonce.clone(),
            action.issued_at_ms,
            self.expires_at_ms,
        )
        .map_err(|_| "GOVERNANCE_BINDING")?;
        binding
            .validate_for_action(&self.action, now)
            .map_err(|_| "GOVERNANCE_STALE")?;
        if action.session_id.as_str() != session
            || action.tool.service != "agentguard-memory"
            || action.tool.name != "memory_write"
            || action.target != self.draft.target()
            || action.parameters
                != serde_json::to_value(&self.draft).map_err(|_| "GOVERNANCE_BINDING")?
            || action.sources != self.draft.sources
            || self.review_sha256 != format!("{:x}", Sha256::digest(self.action.canonical_bytes()))
            || self.instruction_authority != "none"
            || self.completed_effects != "not_reverted"
            || self.expires_at_ms > self.draft.expires_at_ms
        {
            return Err("GOVERNANCE_BINDING".into());
        }
        let state = match self.operation {
            MemoryChange::Quarantine => MemoryState::Quarantined,
            MemoryChange::Revoke => MemoryState::Revoked,
            MemoryChange::Restore => MemoryState::Active,
        };
        if self.draft.state != state {
            return Err("GOVERNANCE_BINDING".into());
        }
        Ok(())
    }
    fn view(&self) -> Value {
        let action = self.action.spec();
        json!({"review_id":self.review_id,"review_sha256":self.review_sha256,
            "operation":self.operation,"expires_at_ms":self.expires_at_ms,"session_id":action.session_id,
            "target":action.target,"policy_version":action.policy_version,"draft":self.draft,
            "completed_effects":self.completed_effects,"instruction_authority":self.instruction_authority})
    }
}

fn request(
    connection: &Connection,
    method: &str,
    route: &str,
    body: &Value,
) -> Result<Value, String> {
    let encoded = if method == "GET" {
        String::new()
    } else {
        body.to_string()
    };
    let (code, bytes) = http_response(
        connection.port,
        &connection.token,
        method,
        route,
        &encoded,
        WORKSPACE_TIMEOUT,
    )?;
    if code != 200 {
        return Err(match code {
            403 => "GATEWAY_AUTH",
            409 => "GOVERNANCE_REFUSED",
            404 => "GOVERNANCE_UNAVAILABLE",
            _ => "GOVERNANCE_UNAVAILABLE",
        }
        .into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "GOVERNANCE_PROTOCOL".into())
}
fn memory_request(
    connection: &Connection,
    session: &str,
    route: &str,
    body: Value,
) -> Result<Value, String> {
    let remote = request(connection, "POST", route, &body)?;
    if remote["service"] != "agentguard-mcp"
        || remote["governance_protocol"] != 1
        || remote["instance_id"] != connection.instance_id
        || remote["session_id"] != session
        || !remote["data"].is_object()
    {
        return Err("GOVERNANCE_PROTOCOL".into());
    }
    Ok(remote["data"].clone())
}

fn validate_tree(data: &Value, session: &str) -> Result<(), String> {
    if data["host_session_id"] != session || !data["budget"]["closed"].is_boolean() {
        return Err("GOVERNANCE_PROTOCOL".into());
    }
    let nodes = data["budget"]["nodes"]
        .as_array()
        .ok_or("GOVERNANCE_PROTOCOL")?;
    let mut ids = std::collections::BTreeSet::new();
    for node in nodes {
        let id = node["grant_id"]
            .as_str()
            .filter(|id| safe_identifier(id))
            .ok_or("GOVERNANCE_PROTOCOL")?;
        if !ids.insert(id)
            || !node["revoked"].is_boolean()
            || [
                "used_calls",
                "used_output_bytes",
                "reserved_output_bytes",
                "remaining_calls",
                "remaining_output_bytes",
                "remaining_ms",
            ]
            .iter()
            .any(|key| node[key].as_u64().is_none())
        {
            return Err("GOVERNANCE_PROTOCOL".into());
        }
    }
    let mut visited = std::collections::BTreeSet::new();
    while visited.len() < nodes.len() {
        let before = visited.len();
        for node in nodes {
            if node["parent_grant_id"].is_null()
                || node["parent_grant_id"]
                    .as_str()
                    .is_some_and(|id| visited.contains(id))
            {
                visited.insert(node["grant_id"].as_str().unwrap());
            }
        }
        if visited.len() == before {
            return Err("GOVERNANCE_PROTOCOL".into());
        }
    }
    Ok(())
}

impl GatewayConfirm {
    fn governance_snapshot(&self, id: &str) -> Result<(Connection, u64), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let current = slot
            .as_mut()
            .filter(|c| c.id == id && c.supports_workspace)
            .ok_or("GOVERNANCE_UNAVAILABLE")?;
        current.governance.epoch = current.governance.epoch.wrapping_add(1);
        let snapshot = current.clone();
        // 即使本次网络请求失败，也不能重新提交上一次批准。
        current.governance.review = None;
        Ok((snapshot, current.governance.epoch))
    }
    fn governance_commit(
        &self,
        id: &str,
        epoch: u64,
        state: &GovernanceState,
    ) -> Result<(), String> {
        let mut slot = self.0.lock().map_err(|_| "GATEWAY_STATE")?;
        let current = slot
            .as_mut()
            .filter(|c| c.id == id && c.governance.epoch == epoch)
            .ok_or("GOVERNANCE_STALE")?;
        current.governance = state.clone();
        Ok(())
    }
    fn govern(&self, id: &str, command: GovernanceRequest) -> Result<Value, String> {
        let (mut connection, epoch) = self.governance_snapshot(id)?;
        let delegation = matches!(
            &command,
            GovernanceRequest::DelegationStatus | GovernanceRequest::DelegationRevoke { .. }
        );
        // 委托停止走独立控制面，不能排在正在等待批准的模型调用后面。
        let current = if delegation {
            status(&mut connection)?;
            None
        } else {
            Some(workspace_status(&mut connection)?)
        };
        let mut session = current
            .as_ref()
            .map(|s| s.session_id.clone())
            .unwrap_or_default();
        let active = current
            .as_ref()
            .is_some_and(|s| s.session_state == "active" && !s.busy);
        let previous = connection.governance.review.take();
        let apply = matches!(&command, GovernanceRequest::MemoryApply { .. });
        let result = match command {
            GovernanceRequest::MemoryList { after_key } => memory_request(
                &connection,
                &session,
                "/memory/list",
                json!({"session_id":session,"after_key":after_key}),
            )?,
            GovernanceRequest::MemoryHistory { key, after_version } => memory_request(
                &connection,
                &session,
                "/memory/history",
                json!({"session_id":session,"key":key,"after_version":after_version}),
            )?,
            GovernanceRequest::MemoryPreview {
                key,
                expected_version,
                change,
                source_version,
                expires_at_ms,
            } => {
                if !active {
                    return Err("GOVERNANCE_REFUSED".into());
                }
                let value = memory_request(
                    &connection,
                    &session,
                    "/memory/preview",
                    json!({"session_id":session,"key":key,"expected_version":expected_version,"operation":change,"source_version":source_version,"expires_at_ms":expires_at_ms}),
                )?;
                let review: MemoryReview =
                    serde_json::from_value(value).map_err(|_| "GOVERNANCE_PROTOCOL")?;
                review.validate(&session, now_ms()?)?;
                if review.operation != change
                    || review.draft.key != key
                    || expected_version.checked_add(1) != Some(review.draft.version)
                    || (change == MemoryChange::Restore
                        && Some(review.draft.expires_at_ms) != expires_at_ms)
                {
                    return Err("GOVERNANCE_BINDING".into());
                }
                let view = review.view();
                connection.governance.review = Some(review);
                view
            }
            GovernanceRequest::MemoryApply {
                review_id,
                review_sha256,
            }
            | GovernanceRequest::MemoryDiscard {
                review_id,
                review_sha256,
            } => {
                let review = previous
                    .filter(|r| r.review_id == review_id && r.review_sha256 == review_sha256)
                    .ok_or("GOVERNANCE_STALE")?;
                if !active {
                    return Err("GOVERNANCE_REFUSED".into());
                }
                review.validate(&session, now_ms()?)?;
                self.governance_commit(id, epoch, &connection.governance)?;
                let value = memory_request(&connection, &session, if apply { "/memory/apply" } else { "/memory/discard" },
                    json!({"session_id":session,"review_id":review.review_id,"review_sha256":review.review_sha256,"review_nonce":review.review_nonce}))
                    .map_err(|_| "GOVERNANCE_OUTCOME_UNKNOWN")?;
                if value["review_id"] != review.review_id
                    || (apply && value["completed_effects"] != "not_reverted")
                    || (!apply && value["discarded"] != true)
                {
                    return Err("GOVERNANCE_OUTCOME_UNKNOWN".into());
                }
                value
            }
            GovernanceRequest::DelegationStatus => {
                let value = request(&connection, "GET", "/delegation/status", &Value::Null)?;
                session = value["host_session_id"]
                    .as_str()
                    .filter(|s| safe_identifier(s))
                    .ok_or("GOVERNANCE_PROTOCOL")?
                    .to_owned();
                validate_tree(&value, &session)?;
                connection.governance.delegation = Some(value.clone());
                value
            }
            GovernanceRequest::DelegationRevoke {
                host_session_id,
                grant_id,
            } => {
                let displayed = connection
                    .governance
                    .delegation
                    .take()
                    .ok_or("GOVERNANCE_STALE")?;
                if displayed["host_session_id"] != host_session_id
                    || !displayed["budget"]["nodes"]
                        .as_array()
                        .is_some_and(|nodes| nodes.iter().any(|n| n["grant_id"] == grant_id))
                {
                    return Err("GOVERNANCE_STALE".into());
                }
                session = host_session_id.clone();
                self.governance_commit(id, epoch, &connection.governance)?;
                let value = request(
                    &connection,
                    "POST",
                    "/delegation/revoke",
                    &json!({"host_session_id":host_session_id,"grant_id":grant_id}),
                )
                .map_err(|_| "GOVERNANCE_OUTCOME_UNKNOWN")?;
                validate_tree(&value, &session).map_err(|_| "GOVERNANCE_OUTCOME_UNKNOWN")?;
                if value["grant_id"] != grant_id
                    || value["revoked"] != true
                    || value["completed_effects"] != "not_reverted"
                {
                    return Err("GOVERNANCE_OUTCOME_UNKNOWN".into());
                }
                connection.governance.delegation = Some(value.clone());
                value
            }
        };
        self.governance_commit(id, epoch, &connection.governance)
            .map_err(|e| {
                if apply || delegation {
                    "GOVERNANCE_OUTCOME_UNKNOWN".into()
                } else {
                    e
                }
            })?;
        Ok(json!({"session_id":session,"data":result}))
    }
}

#[tauri::command]
pub async fn govern_gateway(
    state: tauri::State<'_, GatewayConfirm>,
    connection_id: String,
    command: GovernanceRequest,
) -> Result<Value, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.govern(&connection_id, command))
        .await
        .map_err(|_| "GATEWAY_WORKER")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_privacy::{Confidentiality, Integrity, Label};
    use guard_schema::{
        ActionSpec, SourceObject, SourceObservation, SourceSensitivity, ToolIdentity,
    };
    use std::net::TcpListener;

    fn review() -> MemoryReview {
        let id = |s: &str| ValidatedId::new(s).unwrap();
        let now = now_ms().unwrap();
        let draft = MemoryDraft {
            schema_version: 1,
            scope_id: id("fixture"),
            key: id("note"),
            version: 2,
            previous_sha256: Some(guard_schema::Sha256Digest::new("f".repeat(64)).unwrap()),
            content: "{\"kind\":\"note\",\"text\":\"正文 <script>只显示文字</script>\"}".into(),
            sources: vec![SourceObject {
                source_id: id("source"),
                observation: SourceObservation::Unknown {
                    reason: "fixture".into(),
                },
                sensitivity: SourceSensitivity::Unknown,
                content_views: None,
            }],
            label: Label::new(Integrity::Tainted, Confidentiality::High),
            created_at_ms: now - 100,
            expires_at_ms: now + 60_000,
            state: MemoryState::Quarantined,
        };
        let action = ActionSnapshot::new(ActionSpec {
            contract_version: 1,
            session_id: id("session"),
            action_id: id("action"),
            request_id: id("request"),
            tool: ToolIdentity {
                registration: None,
                service: "agentguard-memory".into(),
                name: "memory_write".into(),
                version: "fixture".into(),
            },
            target: draft.target(),
            parameters: json!(draft),
            policy_version: id("policy"),
            issued_at_ms: now - 100,
            expires_at_ms: now + 30_000,
            nonce: "e".repeat(64),
            sources: draft.sources.clone(),
        })
        .unwrap();
        MemoryReview {
            review_id: "review".into(),
            review_sha256: format!("{:x}", Sha256::digest(action.canonical_bytes())),
            review_nonce: "d".repeat(64),
            operation: MemoryChange::Quarantine,
            expires_at_ms: now + 29_000,
            action,
            draft,
            instruction_authority: "none".into(),
            completed_effects: "not_reverted".into(),
        }
    }
    fn connection(port: u16) -> Connection {
        Connection {
            id: "connection".into(),
            port,
            token: "a".repeat(32),
            instance_id: "b".repeat(32),
            displayed: None,
            supports_workspace: true,
            workspace: None,
            review: None,
            workspace_epoch: 0,
            governance: GovernanceState::default(),
        }
    }
    fn memory_envelope(data: Value) -> Value {
        json!({"service":"agentguard-mcp","governance_protocol":1,"instance_id":"b".repeat(32),"session_id":"session","data":data})
    }
    fn workspace() -> Value {
        json!({"service":"agentguard-mcp","workspace_protocol":1,"instance_id":"b".repeat(32),"session_id":"session","task_profile":"fixture","session_state":"active","busy":false,"last_client_message_ms":0,"workspaces":[],"pending_review":null,"last_result":null})
    }
    fn wire(
        steps: Vec<(&'static str, Option<Value>)>,
    ) -> (GatewayConfirm, std::thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = GatewayConfirm::default();
        *state.0.lock().unwrap() = Some(connection(listener.local_addr().unwrap().port()));
        let worker = std::thread::spawn(move || {
            let mut bodies = vec![];
            for (path, response) in steps {
                let until = Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < until =>
                        {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(e) => panic!("未收到预期请求 {path}: {e}"),
                    }
                };
                // macOS 接收的连接继承监听器的非阻塞状态；读取超时不会改回阻塞。
                // HTTP 请求可能分段到达，连接必须等待余下正文而非立即 WouldBlock。
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut input = vec![];
                let body = loop {
                    let mut buffer = [0; 4096];
                    let n = socket.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    input.extend_from_slice(&buffer[..n]);
                    if let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&input[..end]).unwrap();
                        assert!(headers.lines().next().unwrap().contains(path));
                        assert!(
                            headers.contains(&format!("Authorization: Bearer {}", "a".repeat(32)))
                        );
                        let length: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if input.len() >= end + 4 + length {
                            break if length == 0 {
                                Value::Null
                            } else {
                                serde_json::from_slice(&input[end + 4..]).unwrap()
                            };
                        }
                    }
                };
                bodies.push(body);
                if let Some(response) = response {
                    let body = response.to_string();
                    write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                }
            }
            bodies
        });
        (state, worker)
    }

    #[test]
    fn 测试网关等待分段发送的请求正文() {
        let expected = json!({"text": "分段发送的中文正文"});
        let body = expected.to_string();
        let (manager, worker) = wire(vec![("POST /memory/list ", Some(json!({"ok": true})))]);
        let port = manager.0.lock().unwrap().as_ref().unwrap().port;
        let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        write!(
            socket,
            "POST /memory/list HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
            "a".repeat(32),
            body.len()
        )
        .unwrap();
        // 正文尚未送齐时，服务端应继续等待，不能关闭连接或提前返回响应。
        socket.write_all(&body.as_bytes()[..10]).unwrap();
        let error = socket.read(&mut [0; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        socket.write_all(&body.as_bytes()[10..]).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(worker.join().unwrap(), vec![expected]);
    }

    #[test]
    fn 记忆复核逐值绑定且网页视图不含批准随机值() {
        let original = review();
        original.validate("session", now_ms().unwrap()).unwrap();
        let view = original.view().to_string();
        assert!(view.contains("正文") && view.contains("tainted") && view.contains("source"));
        assert!(
            !view.contains(&original.review_nonce)
                && !view.contains(&original.action.spec().nonce)
                && !view.contains("review_nonce")
        );
        type Mutation = Box<dyn Fn(&mut MemoryReview)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|r| r.draft.content = "替换正文".into()),
            Box::new(|r| r.draft.sources.clear()),
            Box::new(|r| r.draft.label = Label::new(Integrity::Verified, Confidentiality::Public)),
            Box::new(|r| r.review_sha256 = "0".repeat(64)),
            Box::new(|r| r.review_nonce = "invalid".into()),
            Box::new(|r| r.operation = MemoryChange::Restore),
            Box::new(|r| r.completed_effects = "reverted".into()),
            Box::new(|r| r.expires_at_ms = 1),
        ];
        for mutate in mutations {
            let mut bad = original.clone();
            mutate(&mut bad);
            assert!(bad.validate("session", now_ms().unwrap()).is_err());
        }
        assert!(original.validate("new-session", now_ms().unwrap()).is_err());
    }

    #[test]
    fn 记忆批准回执丢失不能重试且暂停使迟到预览失效() {
        let r = review();
        let (manager, worker) = wire(vec![
            ("GET /workspace/status ", Some(workspace())),
            ("POST /memory/apply ", None),
        ]);
        manager
            .0
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .governance
            .review = Some(r.clone());
        let answer = manager.govern(
            "connection",
            GovernanceRequest::MemoryApply {
                review_id: r.review_id.clone(),
                review_sha256: r.review_sha256.clone(),
            },
        );
        assert_eq!(answer.unwrap_err(), "GOVERNANCE_OUTCOME_UNKNOWN");
        let requests = worker.join().unwrap();
        assert_eq!(requests[1]["review_nonce"], r.review_nonce);
        assert!(manager
            .0
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .governance
            .review
            .is_none());
        let (mut snapshot, epoch) = manager.governance_snapshot("connection").unwrap();
        snapshot.governance.review = Some(r);
        manager.workspace_snapshot("connection", true).unwrap();
        assert_eq!(
            manager
                .governance_commit("connection", epoch, &snapshot.governance)
                .unwrap_err(),
            "GOVERNANCE_STALE"
        );
        assert!(manager
            .0
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .governance
            .review
            .is_none());
    }

    fn tree() -> Value {
        let branch = |id, parent: Option<&str>| json!({"grant_id":id,"parent_grant_id":parent,"used_calls":0,"used_output_bytes":0,"reserved_output_bytes":0,"remaining_calls":2,"remaining_output_bytes":1024,"remaining_ms":5000,"revoked":false});
        json!({"host_session_id":"session","budget":{"closed":false,"nodes":[branch("root",None),branch("child",Some("root"))]}})
    }
    #[test]
    fn 委托停止不排入工作队列并绑定已展示的分支与会话() {
        let status = json!({"service":"agentguard-mcp","confirm_protocol":2,"instance_id":"b".repeat(32),"pending":null,"remaining_ms":0});
        let mut stopped = tree();
        stopped["grant_id"] = json!("root");
        stopped["revoked"] = json!(true);
        stopped["completed_effects"] = json!("not_reverted");
        for n in stopped["budget"]["nodes"].as_array_mut().unwrap() {
            n["revoked"] = json!(true);
        }
        let (manager, worker) = wire(vec![
            ("GET /status ", Some(status.clone())),
            ("GET /delegation/status ", Some(tree())),
            ("GET /status ", Some(status)),
            ("POST /delegation/revoke ", Some(stopped)),
        ]);
        manager
            .govern("connection", GovernanceRequest::DelegationStatus)
            .unwrap();
        let result = manager
            .govern(
                "connection",
                GovernanceRequest::DelegationRevoke {
                    host_session_id: "session".into(),
                    grant_id: "root".into(),
                },
            )
            .unwrap();
        assert_eq!(result["data"]["budget"]["nodes"][1]["revoked"], true);
        assert_eq!(
            worker.join().unwrap()[3],
            json!({"host_session_id":"session","grant_id":"root"})
        );
        for parent in ["missing", "child"] {
            let mut bad = tree();
            bad["budget"]["nodes"][0]["parent_grant_id"] = json!(parent);
            assert!(validate_tree(&bad, "session").is_err());
        }
        assert!(validate_tree(&tree(), "old-session").is_err());
    }

    #[test]
    fn 记忆响应不能替换连接实例会话或协议() {
        for field in [
            "instance_id",
            "session_id",
            "service",
            "governance_protocol",
        ] {
            let mut response = memory_envelope(json!({"entries":[]}));
            response[field] = json!("other");
            let (manager, worker) = wire(vec![
                ("GET /workspace/status ", Some(workspace())),
                ("POST /memory/list ", Some(response)),
            ]);
            assert_eq!(
                manager
                    .govern(
                        "connection",
                        GovernanceRequest::MemoryList { after_key: None }
                    )
                    .unwrap_err(),
                "GOVERNANCE_PROTOCOL"
            );
            worker.join().unwrap();
        }
    }
}
