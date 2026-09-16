//! 状态机故障注入用合成协议端点；真实模型验收另用显式忽略测试，不能混算。
use super::*;
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Instant;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agd-local-agent-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn workspace(&self) -> PathBuf {
        let path = self.0.join("合成 项目");
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn paths(&self, mode: &str) -> RuntimePaths {
        let binary = self.0.join("fixture-gateway.py");
        let source = GATEWAY_FIXTURE.replace("\"__MODE__\"", &serde_json::to_string(mode).unwrap());
        #[cfg(unix)]
        let source = source.replacen(
            "#!/usr/bin/python3",
            &format!("#!{}", crate::managed_gateway::test_python().display()),
            1,
        );
        std::fs::write(&binary, source).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let rules = self.0.join("rules.yaml");
        let policy = self.0.join("policy.yaml");
        std::fs::write(&rules, "合成规则\n").unwrap();
        std::fs::write(&policy, "合成策略\n").unwrap();
        let browser = mode.starts_with("browser-").then(|| {
            Arc::new(BrowserConfig {
                node: binary.clone(),
                runtime: binary.clone(),
                playwright: self.0.clone(),
                browsers: self.0.clone(),
                origins: vec!["http://127.0.0.1:32123".into()],
            })
        });
        RuntimePaths {
            binary,
            rules,
            policy,
            storage: self.0.join("private-state"),
            browser,
        }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ModelFixture {
    port: u16,
    requests: mpsc::Receiver<String>,
    replies: mpsc::SyncSender<Value>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    run: Mutex<Option<std::sync::Weak<AgentRun>>>,
    directory: Mutex<Option<PathBuf>>,
    progress: Arc<Mutex<Vec<(u128, &'static str)>>>,
    started_at_ms: u128,
}

impl ModelFixture {
    fn new() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let (request_tx, requests) = mpsc::channel();
        let (replies, reply_rx) = mpsc::sync_channel::<Value>(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let signal = stopped.clone();
        let progress = Arc::new(Mutex::new(Vec::new()));
        let observed = progress.clone();
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            while !signal.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                observed
                    .lock()
                    .unwrap()
                    .push((started.elapsed().as_millis(), "accepted"));
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let Some(request) = read_request(&mut stream, &signal) else {
                    observed
                        .lock()
                        .unwrap()
                        .push((started.elapsed().as_millis(), "incomplete_request"));
                    continue;
                };
                observed
                    .lock()
                    .unwrap()
                    .push((started.elapsed().as_millis(), "request_complete"));
                if request_tx.send(request).is_err() {
                    break;
                }
                let reply = loop {
                    if signal.load(Ordering::SeqCst) {
                        return;
                    }
                    match reply_rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(value) => break value,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => return,
                    }
                };
                let body = serde_json::to_vec(&reply).unwrap();
                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let written = stream
                    .write_all(header.as_bytes())
                    .and_then(|_| stream.write_all(&body))
                    .is_ok();
                observed.lock().unwrap().push((
                    started.elapsed().as_millis(),
                    if written {
                        "reply_written"
                    } else {
                        "reply_failed"
                    },
                ));
            }
        });
        Self {
            port,
            requests,
            replies,
            stopped,
            worker: Some(worker),
            run: Mutex::new(None),
            directory: Mutex::new(None),
            progress,
            started_at_ms,
        }
    }

    fn request(&self, path: &str) -> String {
        let request = self
            .requests
            .recv_timeout(Duration::from_secs(8))
            .unwrap_or_else(|error| {
                // 保留原 8 秒门槛。失败时给出实际阶段，不将网关启动失败混成模型超时。
                let state = self.run.try_lock().ok().and_then(|run| run.as_ref().and_then(std::sync::Weak::upgrade))
                    .map(|run| {
                        let view = run.state.try_lock().ok().map(|state| json!({"phase":state.view.phase,"error":state.view.error}));
                        json!({"view":view,"worker":run.worker.load(Ordering::SeqCst),"stopped":run.stopped.load(Ordering::SeqCst),"faulted":run.faulted.load(Ordering::SeqCst)})
                    });
                // 只输出合成端点的阶段与耗时，不输出请求正文、控制令牌或进程环境。
                let model_progress = self.progress.try_lock().ok().map(|items| items.clone());
                let gateway_progress = self.directory.try_lock().ok().and_then(|directory| {
                    let file = std::fs::File::open(directory.as_ref()?.join("fixture-progress.log")).ok()?;
                    let mut text = String::new();
                    file.take(8192).read_to_string(&mut text).ok()?;
                    Some(text)
                });
                panic!("合成模型未收到 {path}：{error:?}；状态：{state:?}；模型起点 Unix 毫秒：{}；模型阶段（相对毫秒）：{model_progress:?}；网关阶段（Unix 毫秒／相对毫秒）：{gateway_progress:?}", self.started_at_ms)
            });
        assert!(
            request.lines().next().unwrap().contains(path),
            "请求路径不符"
        );
        request
    }

    fn reply(&self, value: Value) {
        self.replies.send(value).unwrap();
    }

    fn loaded(&self) {
        self.request("/v1/models/status");
        self.reply(json!({"models":[{"id":"fixture-model","loaded":true,"model_type":"llm"}]}));
    }
}

impl Drop for ModelFixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream, stopped: &AtomicBool) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    loop {
        if stopped.load(Ordering::SeqCst)
            || Instant::now() >= deadline
            || bytes.len() > 2 * 1024 * 1024
        {
            return None;
        }
        let mut buffer = [0u8; 8192];
        match stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(_) => return None,
        }
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = std::str::from_utf8(&bytes[..at]).ok()?;
            let length = header
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() == at + 4 + length {
                return String::from_utf8(bytes).ok();
            }
        }
    }
}

fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !condition() {
        assert!(Instant::now() < deadline, "状态机应在 8 秒内完成有限操作");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn start_fixture(
    manager: &AgentManager,
    control: &GatewayConfirm,
    directory: &TestDirectory,
    model: &ModelFixture,
    mode: &str,
) -> Arc<AgentRun> {
    *model.directory.lock().unwrap() = Some(directory.0.clone());
    let view = manager
        .start(
            directory.paths(mode),
            control.clone(),
            directory.workspace().to_string_lossy().into_owned(),
            true,
            true,
            model.port,
            "fixture-model".into(),
            "读取合成项目并说明结果。".into(),
        )
        .unwrap();
    assert_eq!(view.phase, "starting");
    let run = manager.get(&view.run_id).unwrap();
    *model.run.lock().unwrap() = Some(Arc::downgrade(&run));
    run
}

#[test]
fn 启动期暂停不取消且停止后迟到预检不创建网关() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "normal");
    model.request("/v1/models/status");
    assert!(matches!(run.control("pause"), Err(code) if code == "LOCAL_AGENT_NOT_READY"));
    assert!(!run.cancelled.lock().unwrap().load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().phase, "starting");
    let stopping = Instant::now();
    run.control("stop").unwrap();
    assert_eq!(run.view().unwrap().phase, "stopped");
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert!(
        stopping.elapsed() < Duration::from_millis(750),
        "停止应取消尚未返回的模型预检"
    );
    model.reply(json!({"models":[{"id":"fixture-model","loaded":true,"model_type":"llm"}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert!(run.process.lock().unwrap().is_none());
    assert!(!control.connected());
    // 预检已发送，必须留下摘要审计；停止后不得生成网关配置或启动网关。
    let entries: Vec<_> = std::fs::read_dir(directory.0.join("private-state"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].join("model-egress.db").is_file());
    assert!(!entries[0].join("plans.json").exists());
    assert!(manager.external_connection(|| Ok(())).is_ok());
}

#[test]
fn 启动工具列表损坏会回收已创建网关() {
    failed_initialize_cleans("bad-tools", "LOCAL_AGENT_TOOLS");
}

#[test]
fn 固定回环模型和网关启动不依赖反向域名解析() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "dns-forbidden");
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"回环启动完成。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().answer, "回环启动完成。");
    run.control("stop").unwrap();
}

#[test]
fn 同一网关会话完成后可明确追加第二轮模型请求() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "normal");
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"第一轮合成结果。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let before = run.view().unwrap();
    assert_eq!(before.phase, "awaiting_review");
    manager
        .continue_task(&before.run_id, "第二轮：说明上一轮结果。".into())
        .unwrap();
    let second = model.request("/v1/chat/completions");
    assert!(second.contains("第一轮合成结果") && second.contains("第二轮"));
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"第二轮合成结果。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let after = run.view().unwrap();
    assert_eq!(after.phase, "awaiting_review");
    assert_eq!(before.session_id, after.session_id);
    assert_eq!(after.answer, "第二轮合成结果。");
    assert_eq!(run.epoch.load(Ordering::SeqCst), 1);
    run.control("stop").unwrap();
}

#[test]
fn 未授权模型数据出口在创建会话和预检前拒绝() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let result = manager.start(
        directory.paths("normal"),
        GatewayConfirm::default(),
        directory.workspace().to_string_lossy().into_owned(),
        true,
        false,
        model.port,
        "fixture-model".into(),
        "合成任务".into(),
    );
    assert!(matches!(result, Err(code) if code == "MODEL_DATA_AUTHORIZATION_REQUIRED"));
    assert!(!directory.0.join("private-state").exists());
    assert!(manager.poll().unwrap().is_none());
    assert!(model.requests.try_recv().is_err());
}

#[test]
fn 旧网关缺少结构化回执能力在模型执行前拒绝() {
    failed_initialize_cleans("old-receipt", "LOCAL_AGENT_GATEWAY_PROTOCOL");
}

#[test]
fn 导入后工作区状态损坏会清除控制连接() {
    failed_initialize_cleans("bad-workspace", "WORKSPACE_PROTOCOL");
}

fn failed_initialize_cleans(mode: &str, expected: &str) {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, mode);
    model.loaded();
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let view = run.view().unwrap();
    assert_eq!(view.phase, "failed");
    assert_eq!(view.error.as_deref(), Some(expected));
    assert!(view.connection.is_none() && !control.connected());
    let process = run
        .process
        .lock()
        .unwrap()
        .clone()
        .expect("故障发生于真实子进程创建后");
    assert_eq!(
        std::fs::read_to_string(directory.0.join("gateway-cwd.txt")).unwrap(),
        directory.workspace().to_string_lossy().as_ref(),
        "策略解析与隔离执行必须以同一授权工作区为当前目录"
    );
    assert!(process.exited() && process.reader_exited());
    run.control("stop").unwrap();
    assert!(manager.external_connection(|| Ok(())).is_ok());
}

#[test]
fn 晚到模型工具调用在暂停后丢弃且恢复换会话() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "normal");
    model.loaded();
    model.request("/v1/chat/completions");
    let before = run.view().unwrap().session_id;
    assert!(manager.external_connection(|| Ok(())).is_err());
    let paused = run.control("pause").unwrap().unwrap();
    assert_eq!(paused.session_state, "paused");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"late-call","type":"function","function":{"name":"write_file","arguments":json!({"path":directory.workspace().join("late.txt"),"contents":"晚到动作不得执行"}).to_string()}}]}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let view = run.view().unwrap();
    assert_eq!(view.phase, "paused");
    assert!(view.steps.is_empty() && view.answer.is_empty());
    assert!(!directory.0.join("tool-calls.jsonl").exists());
    assert!(!directory.workspace().join("late.txt").exists());
    let resumed = run.control("resume").unwrap().unwrap();
    assert_eq!(resumed.session_state, "active");
    assert_ne!(before, resumed.session_id);
    manager
        .continue_task(&view.run_id, "继续，但先说明当前状态。".into())
        .unwrap();
    let request = model.request("/v1/chat/completions");
    assert!(request.contains("继续，但先说明当前状态"));
    assert!(!request.contains("late-call"));
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"new-read","type":"function","function":{"name":"read_file","arguments":json!({"path":directory.workspace().join("sample.txt")}).to_string()}}]}}]}));
    let after_call = model.request("/v1/chat/completions");
    assert!(after_call.contains("合成工具已调用") && !after_call.contains("late-call"));
    let call_text = std::fs::read_to_string(directory.0.join("tool-calls.jsonl")).unwrap();
    let calls: Vec<Value> = call_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["params"]["name"], "read_file");
    assert_eq!(
        calls[0]["params"]["_meta"]["agentguard_session_id"],
        resumed.session_id
    );
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"已依据新的继续请求读取状态；未执行被暂停的动作。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().phase, "awaiting_review");
    run.control("stop").unwrap();
    let process = run.process.lock().unwrap().clone().unwrap();
    assert!(process.exited() && process.reader_exited() && !control.connected());
}

#[test]
fn 已有外部连接阻止启动本地会话() {
    let directory = TestDirectory::new();
    let endpoint = ModelFixture::new();
    let control = GatewayConfirm::default();
    let file = directory.0.join("external-connection.json");
    private_file(&file, &json!({"service":"agentguard-mcp","confirm_protocol":2,"url":format!("http://127.0.0.1:{}",endpoint.port),"port":endpoint.port,"instance_id":"b".repeat(32),"token":"a".repeat(32)})).unwrap();
    let cloned = control.clone();
    let importer = std::thread::spawn(move || cloned.import_file(&file));
    endpoint.request("/status");
    endpoint.reply(json!({"service":"agentguard-mcp","confirm_protocol":2,"instance_id":"b".repeat(32),"pending":null,"remaining_ms":0}));
    let connected = importer.join().unwrap().unwrap();
    let manager = AgentManager::default();
    let result = manager.start(
        directory.paths("normal"),
        control.clone(),
        directory.workspace().to_string_lossy().into_owned(),
        true,
        true,
        endpoint.port,
        "fixture-model".into(),
        "合成任务".into(),
    );
    assert!(matches!(result, Err(code) if code == "LOCAL_AGENT_BUSY"));
    assert!(manager.poll().unwrap().is_none());
    assert!(!directory.0.join("private-state").exists());
    control.disconnect(&connected.connection_id).unwrap();
}

#[test]
fn 模型省略cwd时可信宿主补上完整工作区() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "normal");
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"cwd-omitted","type":"function","function":{"name":"run_shell","arguments":json!({"argv":["pwd"]}).to_string()}}]}}]}));
    model.request("/v1/chat/completions");
    let log = std::fs::read_to_string(directory.0.join("tool-calls.jsonl")).unwrap();
    let calls: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0]["params"]["arguments"]["cwd"],
        directory.workspace().to_string_lossy().as_ref()
    );
    assert_eq!(calls[0]["params"]["arguments"]["argv"], json!(["pwd"]));
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"合成调用已结束。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().phase, "awaiting_review");
    run.control("stop").unwrap();
}

#[test]
fn 显式子目录cwd使整批模型调用在派发前拒绝() {
    let directory = TestDirectory::new();
    let subdirectory = directory.workspace().join("子目录");
    std::fs::create_dir(&subdirectory).unwrap();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "normal");
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[
        {"id":"first-valid","type":"function","function":{"name":"write_file","arguments":json!({"path":directory.workspace().join("must-not-write.txt"),"contents":"整批拒绝时不得先写"}).to_string()}},
        {"id":"second-invalid","type":"function","function":{"name":"run_shell","arguments":json!({"argv":["pwd"],"cwd":subdirectory}).to_string()}}
    ]}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let view = run.view().unwrap();
    assert_eq!(view.phase, "failed");
    assert_eq!(view.error.as_deref(), Some("LOCAL_AGENT_CWD_REQUIRED"));
    assert!(view.steps.is_empty());
    assert!(!directory.0.join("tool-calls.jsonl").exists());
    assert!(!directory.workspace().join("must-not-write.txt").exists());
    run.control("stop").unwrap();
}

#[test]
fn 字符串argv不能隐式拆分或让同批前序写入先执行() {
    for argv in ["python3 -B script.py", r#"["python3","-B","script.py"]"#] {
        let directory = TestDirectory::new();
        let model = ModelFixture::new();
        let manager = AgentManager::default();
        let control = GatewayConfirm::default();
        let run = start_fixture(&manager, &control, &directory, &model, "normal");
        model.loaded();
        model.request("/v1/chat/completions");
        model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[
            {"id":"valid-write","type":"function","function":{"name":"write_file","arguments":json!({"path":directory.workspace().join("must-not-write.txt"),"contents":"整批先校验"}).to_string()}},
            {"id":"invalid-argv","type":"function","function":{"name":"run_shell","arguments":json!({"argv":argv}).to_string()}}
        ]}}]}));
        wait_for(|| !run.worker.load(Ordering::SeqCst));
        let view = run.view().unwrap();
        assert_eq!(view.phase, "failed");
        assert_eq!(view.error.as_deref(), Some("LOCAL_AGENT_TOOL_ARGUMENTS"));
        assert!(view.steps.is_empty());
        assert!(!directory.0.join("tool-calls.jsonl").exists());
        assert!(!directory.workspace().join("must-not-write.txt").exists());
        run.control("stop").unwrap();
    }
}

#[test]
fn 暂停后旧工具返回未知结果不能恢复会话() {
    cancelled_tool_fault_is_sticky("late-unknown");
}

#[test]
fn 暂停后旧工具缺少执行回执不能恢复会话() {
    cancelled_tool_fault_is_sticky("late-missing");
}

#[test]
fn 暂停后迟到成功回执只更新步骤不恢复模型() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "late-success");
    start_gated_tool(&directory, &model);
    run.control("pause").unwrap();
    assert_eq!(run.view().unwrap().steps[0].state, "unknown");
    std::fs::write(directory.0.join("release-response"), "只放回原工具结果").unwrap();
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    let view = run.view().unwrap();
    assert_eq!(view.phase, "paused");
    assert_eq!(view.steps[0].state, "succeeded");
    assert!(view.answer.is_empty());
    assert!(
        model.requests.try_recv().is_err(),
        "旧成功回执不能触发下一轮模型"
    );
    assert!(!run
        .state
        .lock()
        .unwrap()
        .messages
        .iter()
        .any(|message| message["role"] == "tool"));
    run.control("stop").unwrap();
}

#[test]
fn 停止期间迟到成功回执保留完成事实但不复活任务() {
    stop_keeps_late_receipt("late-success-stop", "succeeded");
}

#[test]
fn 停止期间迟到未知回执保留未知错误且不复活任务() {
    stop_keeps_late_receipt("late-unknown-stop", "unknown");
}

fn start_gated_tool(directory: &TestDirectory, model: &ModelFixture) {
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"gated-call","type":"function","function":{"name":"write_file","arguments":json!({"path":directory.workspace().join("sample.txt"),"contents":"只等待合成回执"}).to_string()}}]}}]}));
    wait_for(|| directory.0.join("tool-started").exists());
}

fn stop_keeps_late_receipt(mode: &str, expected_step: &str) {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, mode);
    start_gated_tool(&directory, &model);
    let stopping = run.clone();
    let worker = std::thread::spawn(move || stopping.control("stop"));
    wait_for(|| directory.0.join("control-started").exists());
    assert!(run.stopped.load(Ordering::SeqCst));
    std::fs::write(
        directory.0.join("release-response"),
        "停止已撤权后才放回工具结果",
    )
    .unwrap();
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().steps[0].state, expected_step);
    std::fs::write(directory.0.join("release-control"), "允许停止收尾").unwrap();
    worker.join().unwrap().unwrap();
    let view = run.view().unwrap();
    assert_eq!(view.phase, "stopped");
    assert_eq!(view.steps[0].state, expected_step);
    assert!(view.answer.is_empty() && view.connection.is_none());
    assert!(model.requests.try_recv().is_err());
    if expected_step == "unknown" {
        assert_eq!(view.error.as_deref(), Some("LOCAL_AGENT_UNKNOWN"));
    }
    let process = run.process.lock().unwrap().clone().unwrap();
    assert!(process.exited() && process.reader_exited() && !control.connected());
}

fn cancelled_tool_fault_is_sticky(mode: &str) {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, mode);
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"started-call","type":"function","function":{"name":"write_file","arguments":json!({"path":directory.workspace().join("sample.txt"),"contents":"仅合成协议调用"}).to_string()}}]}}]}));
    wait_for(|| directory.0.join("tool-started").exists());
    run.control("pause").unwrap();
    assert_eq!(run.view().unwrap().phase, "paused");
    std::fs::write(directory.0.join("release-response"), "现在才返回旧执行结果").unwrap();
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert!(
        run.control("resume").is_err(),
        "旧动作结果无法确认，不能通过暂停恢复清除故障"
    );
    let id = run.view().unwrap().run_id;
    assert!(manager.continue_task(&id, "继续上一次任务".into()).is_err());
    run.control("stop").unwrap();
    let process = run.process.lock().unwrap().clone().unwrap();
    assert!(process.exited() && process.reader_exited() && !control.connected());
}

// 合成网关把点击和HTTP终态分开，检查生产模型循环是否真的等待控制面。
fn pending_browser_fixture_reply(model: &ModelFixture) {
    model.loaded();
    model.request("/v1/chat/completions");
    model.reply(json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{
        "role":"assistant","content":null,"tool_calls":[
            {"id":"click","type":"function","function":{"name":"browser_click","arguments":json!({"page":"fixture-page","selector":"#send"}).to_string()}},
            {"id":"read","type":"function","function":{"name":"browser_read","arguments":json!({"page":"fixture-page"}).to_string()}}
        ]}}]}));
}

#[test]
fn 浏览器网络待确认时同批后续工具和模型均等待() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "browser-pending");
    pending_browser_fixture_reply(&model);
    wait_for(|| directory.0.join("http-started").exists());
    assert!(
        model
            .requests
            .recv_timeout(Duration::from_millis(250))
            .is_err(),
        "HTTP待确认期间不能继续调用模型"
    );
    let calls = std::fs::read_to_string(directory.0.join("tool-calls.jsonl")).unwrap();
    assert_eq!(
        calls.lines().count(),
        1,
        "点击返回accepted不能允许同批后续工具越过HTTP等待"
    );
    std::fs::write(directory.0.join("release-http"), "success").unwrap();
    let request = model.request("/v1/chat/completions");
    assert!(
        request.contains("http_status") && request.contains("200"),
        "模型须收到可信HTTP回执，不能只得到DOM accepted"
    );
    model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"HTTP已返回，业务结果仍待核对。"}}]}));
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().phase, "awaiting_review");
    assert_eq!(
        std::fs::read_to_string(directory.0.join("tool-calls.jsonl"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    run.control("stop").unwrap();
}

#[test]
fn 浏览器网络拒绝或超时不能作为普通控件失败继续() {
    for outcome in ["refused", "timed_out", "cancelled", "failed", "unknown"] {
        let directory = TestDirectory::new();
        let model = ModelFixture::new();
        let manager = AgentManager::default();
        let control = GatewayConfirm::default();
        let run = start_fixture(&manager, &control, &directory, &model, "browser-pending");
        pending_browser_fixture_reply(&model);
        wait_for(|| directory.0.join("http-started").exists());
        std::fs::write(directory.0.join("release-http"), outcome).unwrap();
        wait_for(|| !run.worker.load(Ordering::SeqCst));
        let view = run.view().unwrap();
        assert_eq!(
            view.phase,
            if outcome == "unknown" {
                "failed"
            } else {
                "awaiting_review"
            }
        );
        assert_eq!(
            std::fs::read_to_string(directory.0.join("tool-calls.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert!(
            model.requests.try_recv().is_err(),
            "网络终态要求停止，不能继续模型或后半批工具"
        );
        if outcome == "unknown" {
            assert!(run.faulted.load(Ordering::SeqCst));
            assert!(run.control("resume").is_err());
        }
        run.control("stop").unwrap();
    }
}

#[test]
fn 浏览器网络等待可暂停且迟到成功不触发后续工具() {
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let run = start_fixture(&manager, &control, &directory, &model, "browser-pending");
    pending_browser_fixture_reply(&model);
    wait_for(|| directory.0.join("http-started").exists());
    run.control("pause").unwrap();
    std::fs::write(directory.0.join("release-http"), "success").unwrap();
    wait_for(|| !run.worker.load(Ordering::SeqCst));
    assert_eq!(run.view().unwrap().phase, "paused");
    assert_eq!(
        std::fs::read_to_string(directory.0.join("tool-calls.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(model.requests.try_recv().is_err());
    run.control("stop").unwrap();
}

const GATEWAY_FIXTURE: &str = r#"#!/usr/bin/python3
import os, time
root = os.path.dirname(os.path.realpath(__file__))
started = time.monotonic()
def progress(stage):
    with open(os.path.join(root,'fixture-progress.log'),'a') as output:
        output.write(str(time.time_ns()//1000000) + ' ' + str(round((time.monotonic()-started)*1000,3)) + ' ' + stage + '\n')
progress('python_entered')
import json, socket, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer
progress('imports_ready')
MODE = "__MODE__"
if MODE == 'dns-forbidden':
    def forbidden_lookup(*args): raise RuntimeError('固定回环夹具不得执行 DNS 查询')
    socket.getfqdn = forbidden_lookup
args = sys.argv[1:]
def flag(name): return args[args.index(name) + 1]
with open(os.path.join(root,'gateway-cwd.txt'),'w') as output: output.write(os.getcwd())
workspace = json.load(open(flag('--plans')))['plans'][0]['scope']['paths']['read'][0]
session = {'state': 'active', 'number': 1}
def identity(): return {'service':'agentguard-mcp','workspace_protocol':1,'instance_id':'b'*32,'session_id':'fixture-session-' + str(session['number'])}
def browser_progress():
    started = os.path.exists(os.path.join(root,'http-started'))
    terminal = os.path.join(root,'release-http')
    outcome = open(terminal).read() if started and os.path.exists(terminal) else None
    receipts = [{'request_id':'fixture-http','action_sha256':'c'*64,'session_id':identity()['session_id'],'epoch':0,'outcome':outcome,'dispatched':outcome in ['success','failed','unknown'],'http_status':200 if outcome == 'success' else 503 if outcome == 'failed' else None,'automatic_retry':False}] if outcome else []
    return {'service':'agentguard-browser-host','browser_protocol':1,'session_id':identity()['session_id'],'epoch':0,'state':'failed' if outcome == 'unknown' else session['state'],'pending_http_requests':int(started and not outcome),'receipts':receipts}
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        progress('http_get ' + self.path)
        if self.path == '/status': self.reply({'service':'agentguard-mcp','confirm_protocol':2,'instance_id':'b'*32,'pending':None,'remaining_ms':0})
        elif MODE == 'bad-workspace': self.reply({'invalid':'合成损坏状态'})
        else:
            result = identity(); result.update({'task_profile':'desktop-local-agent','session_state':session['state'],'busy':False,'last_client_message_ms':0,'workspaces':[{'workspace_id':'workspace-0','target':workspace,'snapshot':workspace,'writable':True,'writeback_available':True,'writeback_reason':None}],'pending_review':None,'last_result':None})
            if MODE.startswith('browser-'): result['browser'] = browser_progress()
            self.reply(result)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        action = self.path.rsplit('/',1)[-1]
        if action == 'resume': session['number'] += 1; session['state'] = 'active'
        elif action == 'pause': session['state'] = 'paused'
        elif action == 'stop': session['state'] = 'stopped'
        if action == 'stop' and MODE.endswith('-stop'):
            open(os.path.join(root,'control-started'),'w').close()
            deadline = time.monotonic() + 8
            while not os.path.exists(os.path.join(root,'release-control')) and time.monotonic() < deadline: time.sleep(0.01)
        self.reply(identity())
# 标准 HTTPServer.server_bind 会调用 getfqdn；固定回环协议夹具不需要 DNS。
class LoopbackHTTPServer(HTTPServer):
    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name = '127.0.0.1'
        self.server_port = self.server_address[1]
server = LoopbackHTTPServer(('127.0.0.1',0), Handler)
progress('http_bound')
port = server.server_address[1]
with open(os.open(flag('--control-file'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as output:
    json.dump({'service':'agentguard-mcp','confirm_protocol':2,'url':'http://127.0.0.1:'+str(port),'port':port,'instance_id':'b'*32,'token':'a'*32},output)
threading.Thread(target=server.serve_forever,daemon=True).start()
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request: continue
    method = request['method']
    progress('rpc ' + method)
    if method == 'initialize': result = {'serverInfo':{'name':'agentguard-mcp'},'capabilities':{'experimental':{} if MODE == 'old-receipt' else {'agentguardExecutionReceipt':1}}}
    elif method == 'gateway/stats': result = {'execution_backend':{'mode':'isolated_workspace_snapshot','network':'none'},'execution_journal':{'persistent':True,'healthy':True}}
    elif method == 'tools/list': result = {'tools': [] if MODE == 'bad-tools' else [{'name':name,'description':'合成工具','inputSchema':{'type':'object'}} for name in ['read_file','search_file','write_file','delete_file','run_shell'] + (['browser_status','browser_navigate','browser_read','browser_fill','browser_click'] if MODE.startswith('browser-') else [])]}
    elif method == 'tools/call':
        with open(os.path.join(root,'tool-calls.jsonl'),'a') as output: output.write(json.dumps(request)+'\n')
        if MODE.startswith('late-'):
            open(os.path.join(root,'tool-started'),'w').close()
            deadline = time.monotonic() + 8
            while not os.path.exists(os.path.join(root,'release-response')) and time.monotonic() < deadline: time.sleep(0.01)
        result = {'content':[{'type':'text','text':'合成工具已调用'}],'isError':False,'_meta':{'agentguard':{'outcome':'success','dispatched':True}}}
        if MODE.startswith('browser-') and request['params']['name'] == 'browser_click':
            open(os.path.join(root,'http-started'),'w').close()
            result['content'][0]['text'] = '{"accepted":true,"note":"HTTP仍在等待独立批准"}'
        if MODE.startswith('late-unknown'): result['isError'] = True; result['_meta']['agentguard']['outcome'] = 'unknown'
        elif MODE == 'late-missing': del result['_meta']
    else: result = {}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
server.server_close()
"#;

struct RealRun {
    directory: PathBuf,
    workspace: PathBuf,
    binary: PathBuf,
    manager: AgentManager,
    control: GatewayConfirm,
    run: Arc<AgentRun>,
    original: std::collections::BTreeMap<String, Vec<u8>>,
    started: Instant,
    source_hashes: Value,
    approvals: Mutex<Vec<Value>>,
}

impl RealRun {
    fn start(case: &str, inputs: &[(&str, &str)], task: &str) -> Self {
        Self::start_with_browser(case, inputs, task, None)
    }

    fn start_with_browser(
        case: &str,
        inputs: &[(&str, &str)],
        task: &str,
        browser: Option<Arc<BrowserConfig>>,
    ) -> Self {
        let output = PathBuf::from(
            std::env::var("AGENTGUARD_LOCAL_AGENT_OUT").expect("需显式指定本次输出根目录"),
        );
        assert!(output.is_absolute());
        std::fs::create_dir_all(&output).unwrap();
        let directory = output.canonicalize().unwrap().join(case);
        std::fs::create_dir(&directory).expect("每次验收使用新目录，不能覆盖旧证据");
        let workspace = directory.join("合成 项目");
        std::fs::create_dir(&workspace).unwrap();
        let original = inputs
            .iter()
            .map(|(name, contents)| {
                std::fs::write(workspace.join(name), contents).unwrap();
                (name.to_string(), contents.as_bytes().to_vec())
            })
            .collect();
        let binary = PathBuf::from(
            std::env::var("AGENTGUARD_LOCAL_AGENT_BINARY").expect("需显式指定本次网关候选"),
        );
        assert!(binary.is_absolute() && binary.is_file());
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf();
        use sha2::{Digest, Sha256};
        let mut source_hashes = serde_json::Map::new();
        for name in [
            "local_agent.rs",
            "local_model.rs",
            "managed_gateway.rs",
            "local_agent_tests.rs",
            "gateway_confirm.rs",
        ] {
            let bytes =
                std::fs::read(repo.join("apps/desktop-macos/src-tauri/src").join(name)).unwrap();
            source_hashes.insert(name.into(), json!(format!("{:x}", Sha256::digest(bytes))));
        }
        source_hashes.insert(
            "executed_test_binary".into(),
            json!(format!(
                "{:x}",
                Sha256::digest(std::fs::read(std::env::current_exe().unwrap()).unwrap())
            )),
        );
        let source_hashes = Value::Object(source_hashes);
        let writable = browser.is_none();
        let paths = RuntimePaths {
            browser,
            binary: binary.clone(),
            rules: repo.join("crates/guard-schema/rules/p0_rules.yaml"),
            policy: repo.join("crates/guard-shell/policies/default.yaml"),
            storage: directory.join("private-state"),
        };
        let model =
            std::env::var("AGENTGUARD_LOCAL_AGENT_MODEL").expect("需显式指定既有已加载模型");
        let port = std::env::var("AGENTGUARD_LOCAL_AGENT_PORT")
            .unwrap_or_else(|_| "8000".into())
            .parse()
            .unwrap();
        let manager = AgentManager::default();
        let control = GatewayConfirm::default();
        let started = Instant::now();
        let view = manager
            .start(
                paths,
                control.clone(),
                workspace.to_string_lossy().into_owned(),
                writable,
                true,
                port,
                model,
                task.into(),
            )
            .unwrap();
        let run = manager.get(&view.run_id).unwrap();
        private_file(&directory.join("input.json"), &json!({"scope":"真实本地模型通过生产 AgentManager 和隔离网关完成合成用户任务；仅对声明的本用例 unittest 命令模拟操作者批准；不执行 UI 目录选择或批准回写","task":task,"inputs":inputs,"initial_view":view,"source_hashes":source_hashes})).unwrap();
        Self {
            directory,
            workspace,
            binary,
            manager,
            control,
            run,
            original,
            started,
            source_hashes,
            approvals: Mutex::new(Vec::new()),
        }
    }

    fn answer_declared_test_action(&self) {
        let Ok(id) = self.run.connection_id() else {
            return;
        };
        let safe_view =
            serde_json::to_value(self.control.poll(&id).expect("真实操作者通道应可轮询")).unwrap();
        let pending = &safe_view["pending"];
        if pending.is_null() {
            return;
        }
        let action = &pending["action"];
        let parameters = &action["parameters"];
        let argv = &parameters["argv"];
        let test_path = self
            .workspace
            .join("test_discount.py")
            .to_string_lossy()
            .into_owned();
        let allowed = [
            json!(["python3", "-m", "unittest", "test_discount", "-v"]),
            json!(["python3", "-m", "unittest", "-v", "test_discount"]),
            json!(["python3", "-m", "unittest", "test_discount"]),
            json!(["python3", "-m", "unittest", "test_discount.py", "-v"]),
            json!(["python3", "-m", "unittest", "-v", "test_discount.py"]),
            json!(["python3", "-m", "unittest", "test_discount.py"]),
            json!(["python3", "test_discount.py"]),
            json!(["python3", "test_discount.py", "-v"]),
            json!(["python3", test_path]),
            json!(["python3", test_path, "-v"]),
        ];
        let browser_allowed = self.directory.file_name().unwrap() == "browser-note"
            && self
                .run
                .view()
                .unwrap()
                .browser_origins
                .first()
                .is_some_and(|origin| {
                    declared_browser_action(
                        action,
                        origin,
                        &self.run.view().unwrap().session_id,
                        &self.approvals.lock().unwrap(),
                    )
                });
        let matches = browser_allowed
            || self.directory.file_name().unwrap() == "bug-fix"
                && action["tool_service"] == "agentguard-gateway"
                && action["tool_name"] == "run_shell"
                && action["session_id"] == self.run.view().unwrap().session_id
                && parameters["cwd"] == self.workspace.to_string_lossy().as_ref()
                && parameters["execution_backend"]["mode"] == "isolated_workspace_snapshot"
                && allowed.contains(argv);
        if !matches {
            self.approvals.lock().unwrap().push(json!({"approved":false,"reason":"不属于本用例预声明命令或浏览器目标、正文及单次额度","safe_view":safe_view}));
            self.save_evidence(None, false);
            self.manager.shutdown();
            panic!("未声明的待批准动作，已停止测试且没有批准");
        }
        let request = pending["id"].as_str().unwrap();
        self.control
            .approve_test_action(&id, request)
            .expect("生产控制面应再次验证摘要、会话和期限");
        self.approvals.lock().unwrap().push(json!({"approved":true,"reason":if browser_allowed { "严格匹配本用例固定浏览器请求，且尚未批准过" } else { "严格匹配本用例标准库 unittest 命令和工作区" },"safe_view":safe_view}));
    }

    fn finish_turn(&self) -> PathBuf {
        let timeout = if self.run.view().unwrap().browser_origins.is_empty() {
            180
        } else {
            600
        };
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let mut last_steps = 0;
        while self.run.worker.load(Ordering::SeqCst) {
            self.answer_declared_test_action();
            let view = self.run.view().unwrap();
            if view.steps.len() != last_steps {
                last_steps = view.steps.len();
                println!(
                    "真实任务已请求 {} 个工具，当前状态 {}",
                    last_steps, view.phase
                );
            }
            if Instant::now() >= deadline {
                self.save_evidence(None, false);
                panic!("真实模型任务超过 {timeout} 秒，不能计为完成");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let view = self.run.view().unwrap();
        self.save_evidence(None, false);
        assert_eq!(
            view.phase, "awaiting_review",
            "实际状态 {:?}，错误 {:?}",
            view.phase, view.error
        );
        assert!(view.error.is_none());
        assert!(!view.answer.trim().is_empty());
        let status = self
            .control
            .workspace_poll(&self.run.connection_id().unwrap())
            .unwrap();
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["session_state"], "active");
        assert_eq!(value["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["workspaces"][0]["target"],
            self.workspace.to_string_lossy().as_ref()
        );
        let snapshot = PathBuf::from(value["workspaces"][0]["snapshot"].as_str().unwrap());
        assert!(snapshot.is_absolute() && snapshot != self.workspace && snapshot.is_dir());
        for (name, original) in &self.original {
            assert_eq!(
                &std::fs::read(self.workspace.join(name)).unwrap(),
                original,
                "模型只能改隔离副本"
            );
        }
        let actual_names: std::collections::BTreeSet<_> = std::fs::read_dir(&self.workspace)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(actual_names, self.original.keys().cloned().collect());
        self.save_evidence(Some(value), false);
        snapshot
    }

    fn save_evidence(&self, status: Option<Value>, verified: bool) {
        use sha2::{Digest, Sha256};
        let state = self.run.state.lock().unwrap();
        let process = self.run.process.lock().unwrap().clone();
        let report = json!({
            "scope":"真实模型决定工具调用并执行合成任务；宿主文件未回写。UI 选择与批准另行验收。",
            "verified":verified,"elapsed_ms":self.started.elapsed().as_millis(),
            "candidate":self.binary,"candidate_sha256":format!("{:x}",Sha256::digest(std::fs::read(&self.binary).unwrap())),
            "source_hashes":self.source_hashes,"operator_approvals":*self.approvals.lock().unwrap(),
            "view":state.view,"messages":state.messages,"tools":state.tools,"workspace_status":status,
            "process":process.map(|p|json!({"pid":p.pid(),"exited":p.exited(),"reader_exited":p.reader_exited()})),
        });
        // 本目录由本测试独占；阶段报告更新不会触及既有运行目录。
        std::fs::write(
            self.directory.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }

    fn verified_and_stop(&self, snapshot: &Path) {
        let status = serde_json::to_value(
            self.control
                .workspace_poll(&self.run.connection_id().unwrap())
                .unwrap(),
        )
        .unwrap();
        let artifacts = self.directory.join("verified-output");
        std::fs::create_dir(&artifacts).unwrap();
        for entry in std::fs::read_dir(snapshot).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), artifacts.join(entry.file_name())).unwrap();
            }
        }
        self.run.control("stop").unwrap();
        let process = self.run.process.lock().unwrap().clone().unwrap();
        assert!(process.exited() && process.reader_exited());
        assert!(!self.control.connected());
        self.save_evidence(Some(status), true);
    }
}

impl Drop for RealRun {
    fn drop(&mut self) {
        self.manager.shutdown();
    }
}

#[test]
#[ignore = "需显式授权使用既有本地模型及本次隔离网关候选，设置 AGENTGUARD_LOCAL_AGENT_* 环境变量"]
fn 真实模型编写脚本汇总中文订单并在隔离副本执行() {
    let run = RealRun::start("csv-summary", &[("orders.csv", "order_id,category,quantity,unit_price\nA01,办公,2,12.50\nA02,家居,3,7.20\nA03,办公,1,3.40\nA04,数码,2,99.90\nA05,家居,5,2.00\nA06,数码,1,10.00\n")],
        "请处理项目里的 orders.csv。读取实际数据后编写 analyze.py，使用 Python 标准库准确计算每行 quantity × unit_price，按 category 汇总，并实际运行脚本。脚本生成 summary.json，字段为 rows（行数）、total_cents（总金额整数分）、by_category_cents（类别到整数分的对象）；同时生成中文 report.md，包含类别金额和总金额表。不要安装依赖，不修改输入 CSV。最后说明实际运行结果。所有产物只写在项目根目录。请使用工具完成，不要只给代码示例。");
    let snapshot = run.finish_turn();
    let summary: Value =
        serde_json::from_slice(&std::fs::read(snapshot.join("summary.json")).unwrap()).unwrap();
    assert_eq!(
        summary,
        json!({"rows":6,"total_cents":26980,"by_category_cents":{"办公":2840,"家居":3160,"数码":20980}})
    );
    assert_eq!(
        std::fs::read(snapshot.join("orders.csv")).unwrap(),
        run.original["orders.csv"]
    );
    assert!(
        std::fs::metadata(snapshot.join("analyze.py"))
            .unwrap()
            .len()
            > 30
    );
    let report = std::fs::read_to_string(snapshot.join("report.md")).unwrap();
    for text in ["办公", "家居", "数码", "269.80"] {
        assert!(report.contains(text), "报告应包含 {text}");
    }
    let state = run.run.state.lock().unwrap();
    assert!(state
        .view
        .steps
        .iter()
        .any(|s| s.tool == "run_shell" && s.state == "succeeded"));
    assert!(
        state
            .messages
            .iter()
            .filter_map(|m| m["tool_calls"].as_array())
            .flatten()
            .any(|call| call["function"]["name"] == "run_shell"
                && call["function"]["arguments"]
                    .as_str()
                    .is_some_and(|args| args.contains("python3") && args.contains("analyze.py"))),
        "需要真实模型决定运行生成的脚本"
    );
    drop(state);
    run.verified_and_stop(&snapshot);
}

#[test]
#[ignore = "需显式授权使用既有本地模型及本次隔离网关候选，设置 AGENTGUARD_LOCAL_AGENT_* 环境变量"]
fn 真实模型先跑失败测试再修复并重跑通过() {
    let tests = "import unittest\nfrom discount import discounted_total\n\nclass DiscountTests(unittest.TestCase):\n    def test_large_total(self):\n        self.assertEqual(discounted_total([80, 120], 25), 150.0)\n    def test_decimal_prices(self):\n        self.assertEqual(discounted_total([12.5, 7.5], 10), 18.0)\n    def test_empty(self):\n        self.assertEqual(discounted_total([], 10), 0.0)\n\nif __name__ == '__main__':\n    unittest.main()\n";
    let run = RealRun::start("bug-fix", &[("discount.py", "def discounted_total(prices, percent):\n    return round(sum(prices) - percent, 2)\n"),("test_discount.py",tests)],
        "项目中的 discount.py 有百分比折扣计算错误，test_discount.py 已给出 3 个测试。请先读取文件并实际运行现有测试，确认失败；然后只修改 discount.py 修复问题，保留 discounted_total(prices, percent) 接口，不修改测试文件。完成后实际重新运行全部测试，报告原始失败和最终结果。使用 Python 标准库，不安装依赖。请用工具真实完成，不要只给修复建议。");
    let snapshot = run.finish_turn();
    assert_eq!(
        std::fs::read(snapshot.join("test_discount.py")).unwrap(),
        run.original["test_discount.py"]
    );
    assert_ne!(
        std::fs::read(snapshot.join("discount.py")).unwrap(),
        run.original["discount.py"]
    );
    let state = run.run.state.lock().unwrap();
    let failed = state
        .view
        .steps
        .iter()
        .position(|s| s.tool == "run_shell" && s.state == "failed")
        .expect("需要实际先看到失败测试");
    assert!(state
        .view
        .steps
        .iter()
        .skip(failed + 1)
        .any(|s| s.tool == "write_file" && s.state == "succeeded"));
    assert!(state
        .view
        .steps
        .iter()
        .skip(failed + 1)
        .any(|s| s.tool == "run_shell" && s.state == "succeeded"));
    let results: Vec<_> = state
        .messages
        .iter()
        .filter(|m| m["role"] == "tool")
        .filter_map(|m| m["content"].as_str())
        .collect();
    assert!(results
        .iter()
        .any(|text| text.contains("FAILED") && text.contains("failures=")));
    assert!(results
        .iter()
        .any(|text| text.contains("Ran 3 tests") && text.contains("OK")));
    drop(state);
    run.verified_and_stop(&snapshot);
}

const REAL_BROWSER_BODY: &str =
    r#"{"id":"REAL35B-note","note":"历史版本保留30天；默认导出Markdown。"}"#;
const REAL_BROWSER_GETS: [&str; 4] = ["/docs/storage", "/docs/export", "/form", "/ledger"];

fn declared_browser_action(
    action: &Value,
    origin: &str,
    session: &str,
    previous: &[Value],
) -> bool {
    let parameters = &action["parameters"];
    let target = action["target"].as_str().unwrap_or("");
    let read = parameters["method"] == "GET"
        && parameters["body"].is_null()
        && REAL_BROWSER_GETS
            .iter()
            .any(|path| target == format!("{origin}{path}"));
    let write = parameters["method"] == "POST"
        && target == format!("{origin}/notes")
        && parameters["body"] == REAL_BROWSER_BODY;
    let headers = parameters["headers"].as_object();
    let ordinary_headers = headers.is_some_and(|headers| {
        headers.keys().all(|name| {
            matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "content-length"
                    | "accept-encoding"
                    | "accept"
                    | "accept-language"
                    | "content-type"
                    | "cookie"
                    | "origin"
                    | "referer"
                    | "user-agent"
                    | "sec-ch-ua"
                    | "sec-ch-ua-mobile"
                    | "sec-ch-ua-platform"
                    | "sec-fetch-dest"
                    | "sec-fetch-mode"
                    | "sec-fetch-site"
                    | "sec-fetch-user"
                    | "upgrade-insecure-requests"
            )
        }) && headers.get("host").and_then(Value::as_str) == origin.strip_prefix("http://")
            && headers.get("cookie").is_none_or(|value| value == "")
            && headers.get("origin").is_none_or(|value| value == origin)
            && headers.get("referer").is_none_or(|value| {
                value.as_str().is_some_and(|url| {
                    REAL_BROWSER_GETS
                        .iter()
                        .any(|path| url == format!("{origin}{path}"))
                })
            })
    });
    action["tool_service"] == "agentguard-protected-browser"
        && action["tool_name"] == "http_request"
        && action["tool_version"] == "1"
        && action["session_id"] == session
        && ordinary_headers
        && (read || write)
        && !previous.iter().any(|approval| {
            approval["approved"] == true
                && approval["safe_view"]["pending"]["action"]["target"] == target
        })
}

#[test]
fn 浏览器真实验收只批准固定目标正文和一次请求() {
    let origin = "http://127.0.0.1:34567";
    let mut action = json!({"tool_service":"agentguard-protected-browser","tool_name":"http_request","tool_version":"1","session_id":"synthetic-session","target":format!("{origin}/notes"),"parameters":{"method":"POST","body":REAL_BROWSER_BODY,"headers":{"host":"127.0.0.1:34567","content-type":"application/json"}}});
    assert!(declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
    for (field, changed) in [
        ("target", json!(format!("{origin}/alternate"))),
        ("session_id", json!("old")),
        ("tool_name", json!("run_shell")),
    ] {
        let mut invalid = action.clone();
        invalid[field] = changed;
        assert!(!declared_browser_action(
            &invalid,
            origin,
            "synthetic-session",
            &[]
        ));
    }
    let previous = json!({"approved":true,"safe_view":{"pending":{"action":action}}});
    assert!(!declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[previous]
    ));
    action["parameters"]["body"] = json!("changed");
    assert!(!declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
    action["parameters"]["body"] = Value::Null;
    action["parameters"]["method"] = json!("GET");
    action["target"] = json!(format!("{origin}/docs/storage"));
    assert!(declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
    action["parameters"]["headers"]["authorization"] = json!("synthetic");
    assert!(!declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
    action["parameters"]["headers"]
        .as_object_mut()
        .unwrap()
        .remove("authorization");
    action["parameters"]["headers"]["cookie"] = json!("");
    assert!(declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
    action["parameters"]["headers"]["cookie"] = json!("synthetic-cookie");
    assert!(!declared_browser_action(
        &action,
        origin,
        "synthetic-session",
        &[]
    ));
}

struct RealBrowserSite {
    origin: String,
    ledger: Arc<Mutex<Vec<Value>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RealBrowserSite {
    fn new() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        listener.set_nonblocking(true).unwrap();
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let records = ledger.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let signal = stopped.clone();
        let worker = std::thread::spawn(move || {
            while !signal.load(Ordering::SeqCst) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let Some(request) = read_request(&mut stream, &signal) else {
                    continue;
                };
                let (head, body) = request.split_once("\r\n\r\n").unwrap();
                let mut first = head.lines().next().unwrap().split(' ');
                let method = first.next().unwrap();
                let path = first.next().unwrap();
                let mut ledger = records.lock().unwrap();
                use sha2::{Digest, Sha256};
                ledger.push(json!({"method":method,"path":path,"body":body,"body_sha256":format!("{:x}",Sha256::digest(body.as_bytes()))}));
                let count = ledger
                    .iter()
                    .filter(|row| {
                        row["method"] == "POST"
                            && row["path"] == "/notes"
                            && row["body"] == REAL_BROWSER_BODY
                    })
                    .count();
                let (status, content_type, content) = match (method, path) {
                    ("GET", "/docs/storage") => (200, "text/html; charset=utf-8", "<h1>星港笔记存储说明</h1><p>历史版本保留30天。</p>".to_string()),
                    ("GET", "/docs/export") => (200, "text/html; charset=utf-8", "<h1>星港笔记导出说明</h1><p>默认导出格式为Markdown。</p>".to_string()),
                    ("GET", "/form") => (200, "text/html; charset=utf-8", r#"<h1>真实模型合成备注</h1><form id="note-form"><label>业务编号<input id="business-id" value="REAL35B-note"></label><label>备注<input id="note"></label><button id="send">提交备注</button></form><output id="result">尚未提交</output><script>document.getElementById('note-form').addEventListener('submit',async e=>{e.preventDefault();try{const r=await fetch('/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:document.getElementById('business-id').value,note:document.getElementById('note').value})});const v=await r.json();document.getElementById('result').textContent='服务器回执：'+v.id+'；提交次数：'+v.count}catch{document.getElementById('result').textContent='结果未知，请只读核账'}})</script>"#.to_string()),
                    ("POST", "/notes") if body == REAL_BROWSER_BODY && count == 1 => (200, "application/json; charset=utf-8", json!({"id":"REAL35B-note","count":count}).to_string()),
                    ("GET", "/ledger") => (200, "text/html; charset=utf-8", format!("<h1>真实模型验收账本</h1><p>业务编号：REAL35B-note</p><p>提交次数：{count}</p><p>备注：{}</p>", if count == 1 { "历史版本保留30天；默认导出Markdown。" } else { "尚无已确认备注" })),
                    _ => (400, "text/plain; charset=utf-8", "未声明或重复请求".to_string()),
                };
                let content = if content_type.starts_with("text/html") {
                    format!("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>本机合成验收</title><link rel=\"icon\" href=\"data:,\"><body>{content}</body></html>")
                } else {
                    content
                };
                let header = format!("HTTP/1.1 {status} Result\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", content.len());
                let _ = stream
                    .write_all(header.as_bytes())
                    .and_then(|_| stream.write_all(content.as_bytes()));
            }
        });
        Self {
            origin,
            ledger,
            stopped,
            worker: Some(worker),
        }
    }
}

impl Drop for RealBrowserSite {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
#[ignore = "需显式指定网关摘要、输出目录及真实Chromium依赖；模型回复为可控夹具，不称真实模型或原生UI"]
fn 真实浏览器与桌面调度器共同等待异步请求终态() {
    use sha2::{Digest, Sha256};
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf();
    let binary = PathBuf::from(std::env::var("AGENTGUARD_LOCAL_AGENT_BINARY").unwrap());
    let expected = std::env::var("AGENTGUARD_LOCAL_AGENT_BINARY_SHA256").unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&binary).unwrap())),
        expected
    );
    let out = PathBuf::from(std::env::var("AGENTGUARD_BROWSER_BARRIER_OUT").unwrap());
    assert!(out.is_absolute());
    std::fs::create_dir(&out).expect("不得覆盖联合验收旧记录");
    let source = real_browser_source_hashes(&repo);
    let dependencies =
        crate::browser_setup::detect(&PathBuf::from(std::env::var_os("HOME").unwrap())).unwrap();
    let site = RealBrowserSite::new();
    let directory = TestDirectory::new();
    let model = ModelFixture::new();
    let manager = AgentManager::default();
    let control = GatewayConfirm::default();
    let view = manager
        .start(
            RuntimePaths {
                binary: binary.clone(),
                rules: repo.join("crates/guard-schema/rules/p0_rules.yaml"),
                policy: repo.join("crates/guard-shell/policies/default.yaml"),
                storage: directory.0.join("private-state"),
                browser: Some(Arc::new(BrowserConfig {
                    node: dependencies.node,
                    runtime: repo.join("apps/protected-browser/cli.mjs"),
                    playwright: dependencies.playwright,
                    browsers: dependencies.browsers,
                    origins: vec![site.origin.clone()],
                })),
            },
            control.clone(),
            directory.workspace().to_string_lossy().into_owned(),
            false,
            true,
            model.port,
            "fixture-model".into(),
            "只在自有页面测试一次提交及HTTP等待。".into(),
        )
        .unwrap();
    let run = manager.get(&view.run_id).unwrap();
    let mut approvals = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        model.loaded();
        model.request("/v1/chat/completions");
        let reply = |calls: Vec<Value>| json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":calls}}]});
        let call = |id: &str, name: &str, args: Value| json!({"id":id,"type":"function","function":{"name":name,"arguments":args.to_string()}});
        model.reply(reply(vec![call(
            "navigate",
            "browser_navigate",
            json!({"url":format!("{}/form",site.origin)}),
        )]));
        let pending = |control: &GatewayConfirm| {
            let mut found = None;
            wait_for(|| {
                let Ok(id) = run.connection_id() else {
                    return false;
                };
                let Ok(view) = control.poll(&id) else {
                    return false;
                };
                let value = serde_json::to_value(view).unwrap();
                if !value["pending"].is_null() {
                    found = Some((id, value));
                }
                found.is_some()
            });
            found.unwrap()
        };
        let (id, form) = pending(&control);
        assert_eq!(
            form["pending"]["action"]["target"],
            format!("{}/form", site.origin)
        );
        assert_eq!(form["pending"]["action"]["parameters"]["method"], "GET");
        control
            .approve_test_action(&id, form["pending"]["id"].as_str().unwrap())
            .unwrap();
        approvals.push(json!({"approved":true,"safe_view":form}));
        let request = model.request("/v1/chat/completions");
        let request: Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        let text = request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|m| m["role"] == "tool")
            .unwrap()["content"]
            .as_str()
            .unwrap();
        let state: Value = serde_json::from_str(text).unwrap();
        let page = state["pages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["url"] == format!("{}/form", site.origin))
            .unwrap()["id"]
            .clone();
        model.reply(reply(vec![
            call("fill", "browser_fill", json!({"page":page,"selector":"#note","value":"历史版本保留30天；默认导出Markdown。"})),
            call("click", "browser_click", json!({"page":page,"selector":"#send"})),
            call("read", "browser_read", json!({"page":page})),
        ]));
        let (id, post) = pending(&control);
        assert_eq!(
            post["pending"]["action"]["target"],
            format!("{}/notes", site.origin)
        );
        assert_eq!(post["pending"]["action"]["parameters"]["method"], "POST");
        assert_eq!(
            post["pending"]["action"]["parameters"]["body"],
            REAL_BROWSER_BODY
        );
        assert!(model
            .requests
            .recv_timeout(Duration::from_millis(350))
            .is_err());
        assert_eq!(
            run.view().unwrap().steps.len(),
            3,
            "真实HTTP待确认时同批只读步骤仍应等待"
        );
        assert_eq!(site.ledger.lock().unwrap().len(), 1, "未批准不能发送POST");
        control
            .approve_test_action(&id, post["pending"]["id"].as_str().unwrap())
            .unwrap();
        approvals.push(json!({"approved":true,"safe_view":post}));
        let request = model.request("/v1/chat/completions");
        assert!(request.contains("http_status") && request.contains("200"));
        assert_eq!(run.view().unwrap().steps.len(), 4);
        model.reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"合成模型已收到HTTP终态，测试端另核对实际账本。"}}]}));
        wait_for(|| !run.worker.load(Ordering::SeqCst));
        assert_eq!(run.view().unwrap().phase, "awaiting_review");
        let ledger = site.ledger.lock().unwrap();
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger[1]["method"], "POST");
        assert_eq!(ledger[1]["body"], REAL_BROWSER_BODY);
        drop(ledger);
        manager
            .continue_task(&view.run_id, "明确新一轮：测试HTTP拒绝后停止。".into())
            .unwrap();
        model.request("/v1/chat/completions");
        model.reply(reply(vec![
            call(
                "denied-navigate",
                "browser_navigate",
                json!({"url":format!("{}/docs/export",site.origin)}),
            ),
            call("must-not-read", "browser_read", json!({"page":page})),
        ]));
        let (id, denied) = pending(&control);
        assert_eq!(
            denied["pending"]["action"]["target"],
            format!("{}/docs/export", site.origin)
        );
        control
            .deny_test_action(&id, denied["pending"]["id"].as_str().unwrap())
            .unwrap();
        approvals.push(json!({"approved":false,"safe_view":denied}));
        wait_for(|| !run.worker.load(Ordering::SeqCst));
        let final_view = run.view().unwrap();
        assert_eq!(final_view.phase, "awaiting_review");
        assert_eq!(
            final_view.error.as_deref(),
            Some("LOCAL_AGENT_BROWSER_REFUSED")
        );
        assert_eq!(
            final_view.steps.len(),
            5,
            "HTTP拒绝不能当普通DOM失败继续后半批工具"
        );
        assert!(model.requests.try_recv().is_err());
        assert_eq!(
            site.ledger.lock().unwrap().len(),
            2,
            "拒绝的页面请求不能到达站点"
        );
    }));
    manager.shutdown();
    let process = run.process.lock().unwrap().clone().unwrap();
    let stopped = process.exited() && process.reader_exited() && !control.connected();
    assert!(stopped && !run.worker.load(Ordering::SeqCst));
    // 任务已停止，释放测试仍持有的模型客户端，使其审计WAL也完成落盘。
    drop(run.model_client.lock().unwrap().take());
    let mut audits = serde_json::Map::new();
    for entry in std::fs::read_dir(directory.0.join("private-state")).unwrap() {
        let session = entry.unwrap().path();
        for name in ["audit.db", "browser-audit.db", "model-egress.db"] {
            let source = session.join(name);
            if source.is_file() {
                // 只对已关闭且无WAL的日志使用immutable只读备份，不能忽略尚未合并的WAL。
                let copied = std::process::Command::new("/usr/bin/python3")
                    .args([
                        "-c",
                        r#"import json, os, sqlite3, sys
from pathlib import Path
src, dst = map(Path, sys.argv[1:])
stage = 'create_target'
try:
    fd = os.open(dst, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    stage = 'open_source'
    assert not src.with_name(src.name + '-wal').exists()
    assert not src.with_name(src.name + '-shm').exists()
    source = sqlite3.connect(src.as_uri() + '?mode=ro&immutable=1', uri=True)
    stage = 'read_source'
    source_count = source.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]
    stage = 'open_target'
    target = sqlite3.connect(dst)
    stage = 'check_target'
    target.execute('PRAGMA schema_version').fetchone()
    stage = 'backup'
    source.backup(target)
    stage = 'check_events'
    count = target.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]
    # 归档副本转为独立主文件，避免下次读取重新依赖WAL附属文件。
    assert target.execute('PRAGMA journal_mode=DELETE').fetchone()[0] == 'delete'
    target.close()
    source.close()
    assert count == source_count
    print(json.dumps({'source': str(src), 'target': str(dst), 'events': count}))
except Exception:
    import shutil
    diagnostic = dst.with_name(dst.name + '.failed-source')
    diagnostic.mkdir()
    state = []
    for suffix in ['', '-wal', '-shm', '-journal']:
        path = src.with_name(src.name + suffix)
        if path.exists():
            state.append({'name': path.name, 'mode': oct(path.stat().st_mode & 0o777), 'bytes': path.stat().st_size})
            shutil.copyfile(path, diagnostic / path.name)
    print(json.dumps({'failed_stage': stage, 'source': str(src), 'target': str(dst),
                      'source_exists': src.is_file(), 'parent_mode': oct(src.parent.stat().st_mode & 0o777),
                      'files': state}), file=sys.stderr)
    raise
"#,
                    ])
                    .arg(&source)
                    .arg(out.join(name))
                    .status()
                    .unwrap();
                assert!(copied.success(), "审计备份必须含实际表与事件");
                audits.insert(
                    name.into(),
                    json!(format!(
                        "{:x}",
                        Sha256::digest(std::fs::read(out.join(name)).unwrap())
                    )),
                );
            }
        }
    }
    let unchanged = source == real_browser_source_hashes(&repo)
        && format!("{:x}", Sha256::digest(std::fs::read(binary).unwrap())) == expected;
    private_file(&out.join("report.json"), &json!({"passed":result.is_ok() && stopped && unchanged,
        "scope":"生产AgentManager、真实网关、真实Chromium和站点；合成模型回复与脚本批准，不称原生UI或真实模型任务。",
        "gateway_sha256":expected,"source":source,"sources_unchanged":unchanged,"approvals":approvals,
        "requests":*site.ledger.lock().unwrap(),"final_view":run.view().unwrap(),"stopped":stopped,"audits":audits})).unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    assert!(stopped && unchanged);
}

fn real_browser_source_hashes(repo: &Path) -> Value {
    use sha2::{Digest, Sha256};
    let mut files = serde_json::Map::new();
    for path in [
        "apps/desktop-macos/src-tauri/src/local_agent.rs",
        "apps/desktop-macos/src-tauri/src/local_agent_tests.rs",
        "apps/desktop-macos/src-tauri/src/model_egress.rs",
        "apps/desktop-macos/src-tauri/src/local_model.rs",
        "apps/desktop-macos/src-tauri/src/managed_gateway.rs",
        "apps/desktop-macos/src-tauri/src/gateway_confirm.rs",
        "apps/desktop-macos/src-tauri/src/browser_setup.rs",
        "apps/protected-browser/cli.mjs",
        "apps/protected-browser/runtime.mjs",
        "apps/protected-browser/host-connection.mjs",
        "apps/protected-browser/mcp.mjs",
        "apps/protected-browser/tools.json",
        "apps/protected-browser/guardian.mjs",
        "apps/protected-browser/execution-contract.mjs",
        "apps/protected-browser/agent-bridge.mjs",
        "apps/protected-browser/demo.mjs",
        "crates/guard-gateway/src/browser_bridge.rs",
        "crates/guard-gateway/src/egress.rs",
        "crates/guard-gateway/src/control_http.rs",
        "crates/guard-schema/rules/p0_rules.yaml",
        "crates/guard-shell/policies/default.yaml",
    ] {
        files.insert(
            path.into(),
            json!(format!(
                "{:x}",
                Sha256::digest(std::fs::read(repo.join(path)).unwrap())
            )),
        );
    }
    Value::Object(files)
}

#[test]
#[ignore = "需冻结候选、已加载35B和真实浏览器依赖；设置AGENTGUARD_LOCAL_AGENT_*及BINARY_SHA256后显式运行"]
fn 真实模型浏览两页提取事实提交一次并只读核账() {
    use sha2::{Digest, Sha256};
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf();
    let source_before = real_browser_source_hashes(&repo);
    let expected =
        std::env::var("AGENTGUARD_LOCAL_AGENT_BINARY_SHA256").expect("必须声明冻结候选摘要");
    let binary = PathBuf::from(std::env::var("AGENTGUARD_LOCAL_AGENT_BINARY").unwrap());
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&binary).unwrap())),
        expected
    );
    let model = std::env::var("AGENTGUARD_LOCAL_AGENT_MODEL").unwrap();
    assert!(model.contains("35B"), "本用例明确检验既有35B模型");
    let home = PathBuf::from(std::env::var_os("HOME").expect("需要当前用户home以核实既有依赖"));
    let dependencies = crate::browser_setup::detect(&home).expect("必须使用真实依赖发现入口");
    let site = RealBrowserSite::new();
    let browser = Arc::new(BrowserConfig {
        node: dependencies.node,
        runtime: repo.join("apps/protected-browser/cli.mjs"),
        playwright: dependencies.playwright,
        browsers: dependencies.browsers,
        origins: vec![site.origin.clone()],
    });
    let scope = json!({"origins":browser.origins,"node":browser.node,"node_sha256":format!("{:x}",Sha256::digest(std::fs::read(&browser.node).unwrap())),"runtime":browser.runtime,"playwright":browser.playwright,"browsers":browser.browsers,"allowed_gets":REAL_BROWSER_GETS,"post_target":format!("{}/notes",site.origin),"post_body":REAL_BROWSER_BODY,"per_target_limit":1,"workspace_writable":false});
    let task = format!("请只用受保护浏览器完成这个本机任务，每个页面只导航一次。先分别打开 {0}/docs/storage 与 {0}/docs/export，并使用browser_read读取实际页面，提取历史版本保留天数及默认导出格式。然后打开 {0}/form，把业务编号保留为REAL35B-note，在备注字段填写由实际事实组成的句子，格式严格为：历史版本保留{{实际天数}}天；默认导出{{实际格式}}。不留空格，保留句末中文句号。点击提交一次，等操作者确认和页面实际回执；不得重复提交。最后打开 {0}/ledger 并使用browser_read只读核对该编号提交次数是否恰好一次，以及备注是否正确。最终报告两条事实和实际核账结果。不要运行命令，不改任何文件，不访问其他URL。", site.origin);
    let run = RealRun::start_with_browser("browser-note", &[], &task, Some(browser));
    private_file(&run.directory.join("browser-input.json"), &json!({"scope":scope,"source_root":repo,"source_before":source_before,"expected_candidate_sha256":expected,"native_ui_verified":false})).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let snapshot = run.finish_turn();
        let ledger = site.ledger.lock().unwrap().clone();
        assert_eq!(ledger.len(), 5, "四个固定GET和一次POST必须实际到达业务服务");
        for path in REAL_BROWSER_GETS {
            assert_eq!(
                ledger
                    .iter()
                    .filter(|row| row["method"] == "GET"
                        && row["path"] == path
                        && row["body"] == "")
                    .count(),
                1
            );
        }
        assert_eq!(
            ledger
                .iter()
                .filter(|row| row["method"] == "POST"
                    && row["path"] == "/notes"
                    && row["body"] == REAL_BROWSER_BODY)
                .count(),
            1
        );
        let state = run.run.state.lock().unwrap();
        // 普通控件定位失败可被模型纠正；完整任务以真实业务结果判定，保留所有失败步骤。
        // 未知、取消、仍执行中和非浏览器工具均不能计为任务完成。
        assert!(state.view.steps.iter().all(|step| {
            step.tool.starts_with("browser_")
                && (step.state == "succeeded"
                    || step.state == "failed"
                        && matches!(step.tool.as_str(), "browser_fill" | "browser_click"))
        }));
        assert!(
            state
                .view
                .steps
                .iter()
                .filter(|step| step.tool == "browser_read")
                .count()
                >= 4
        );
        assert!(state.view.answer.contains("30") && state.view.answer.contains("Markdown"));
        assert!(state
            .messages
            .iter()
            .filter(|message| message["role"] == "tool")
            .filter_map(|message| message["content"].as_str())
            .any(|text| text.contains("真实模型验收账本") && text.contains("提交次数：1")));
        drop(state);
        assert_eq!(source_before, real_browser_source_hashes(&repo));
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(&binary).unwrap())),
            expected
        );
        run.verified_and_stop(&snapshot);
    }));
    run.manager.shutdown();
    let recorded_steps = run.run.view().ok().map(|view| view.steps);
    private_file(&run.directory.join("browser-result.json"), &json!({"verified":result.is_ok(),"scope":scope,"requests":*site.ledger.lock().unwrap(),"recorded_model_steps":recorded_steps,"source_before":source_before,"source_after":real_browser_source_hashes(&repo),"candidate_sha256":format!("{:x}",Sha256::digest(std::fs::read(&binary).unwrap())),"native_ui_verified":false,"final_frozen_joint_acceptance":false})).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
