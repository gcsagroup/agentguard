//! 既有本地模型的有界客户端；不读取凭据、不使用代理、不跟随重定向。
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_TEXT: usize = 256 * 1024;

pub struct ModelToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

pub struct ModelReply {
    /// 仅保留标准assistant正文和已验证工具调用，不向历史传递reasoning字段。
    pub assistant: Value,
    pub content: String,
    pub calls: Vec<ModelToolCall>,
}

fn text_field(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn json_response(response: crate::model_egress::Response) -> Result<Value, String> {
    if response.status != 200 {
        return Err("MODEL_HTTP_STATUS".into());
    }
    response.body.ok_or_else(|| "MODEL_JSON".into())
}

/// oMLX有状态接口时只列已加载语言模型；标准接口仅返回ID，不替用户默认选择。
pub fn list_models(client: &crate::model_egress::ModelClient) -> Result<Vec<String>, String> {
    list_models_with_cancel(client, &AtomicBool::new(false))
}

pub fn list_models_with_cancel(
    client: &crate::model_egress::ModelClient,
    cancelled: &AtomicBool,
) -> Result<Vec<String>, String> {
    let response = client.request("/v1/models/status", None, cancelled)?;
    let status_available = response.status == 200;
    let value = if status_available {
        json_response(response)?
    } else if matches!(response.status, 404 | 405) {
        json_response(client.request("/v1/models", None, cancelled)?)?
    } else {
        return Err("MODEL_HTTP_STATUS".into());
    };
    let rows = value
        .get(if status_available { "models" } else { "data" })
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= 1024)
        .ok_or("MODEL_LIST_FORMAT")?;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        if status_available
            && (row.get("loaded").and_then(Value::as_bool) != Some(true)
                || !matches!(
                    row.get("model_type").and_then(Value::as_str),
                    Some("llm" | "vlm")
                ))
        {
            continue;
        }
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| text_field(id, 256))
            .ok_or("MODEL_LIST_FORMAT")?;
        if !seen.insert(id.to_string()) {
            return Err("MODEL_LIST_FORMAT".into());
        }
        result.push(id.to_string());
    }
    Ok(result)
}

fn parse_reply(value: Value) -> Result<ModelReply, String> {
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .ok_or("MODEL_REPLY_FORMAT")?;
    let choice = &choices[0];
    if choice.get("index").and_then(Value::as_u64) != Some(0) {
        return Err("MODEL_REPLY_FORMAT".into());
    }
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or("MODEL_REPLY_FORMAT")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant")
        || message.get("refusal").is_some_and(|value| !value.is_null())
    {
        return Err("MODEL_REPLY_FORMAT".into());
    }
    let content = match message.get("content") {
        Some(Value::String(text)) if text.len() <= MAX_TEXT && !text.contains('\0') => text.clone(),
        Some(Value::Null) | None => String::new(),
        _ => return Err("MODEL_TEXT_LIMIT".into()),
    };
    let rows = match message.get("tool_calls") {
        Some(Value::Array(rows)) if rows.len() <= 8 => rows.as_slice(),
        None | Some(Value::Null) => &[],
        _ => return Err("MODEL_TOOL_FORMAT".into()),
    };
    match choice.get("finish_reason").and_then(Value::as_str) {
        Some("tool_calls") if !rows.is_empty() => {}
        Some("stop") if rows.is_empty() && !content.trim().is_empty() => {}
        _ => return Err("MODEL_FINISH_REASON".into()),
    }
    let mut calls = Vec::new();
    let mut history_calls = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        if row.get("type").and_then(Value::as_str) != Some("function") {
            return Err("MODEL_TOOL_FORMAT".into());
        }
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| text_field(id, 256))
            .ok_or("MODEL_TOOL_FORMAT")?;
        if !seen.insert(id.to_string()) {
            return Err("MODEL_TOOL_FORMAT".into());
        }
        let function = row
            .get("function")
            .and_then(Value::as_object)
            .ok_or("MODEL_TOOL_FORMAT")?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| text_field(name, 128))
            .ok_or("MODEL_TOOL_FORMAT")?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .filter(|text| text.len() <= MAX_TEXT)
            .ok_or("MODEL_TOOL_FORMAT")?;
        let parsed: Value = serde_json::from_str(arguments).map_err(|_| "MODEL_TOOL_ARGUMENTS")?;
        if !parsed.is_object() {
            return Err("MODEL_TOOL_ARGUMENTS".into());
        }
        calls.push(ModelToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments: parsed,
        });
        history_calls.push(
            json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments}}),
        );
    }
    let mut assistant = json!({"role":"assistant","content":content});
    if !history_calls.is_empty() {
        assistant["tool_calls"] = Value::Array(history_calls);
    }
    Ok(ModelReply {
        assistant,
        content,
        calls,
    })
}

pub fn complete(
    client: &crate::model_egress::ModelClient,
    model: &str,
    messages: &[Value],
    tools: &[Value],
    cancelled: &AtomicBool,
) -> Result<ModelReply, String> {
    if !text_field(model, 256) || messages.is_empty() || messages.len() > 256 || tools.len() > 64 {
        return Err("MODEL_ARGUMENTS".into());
    }
    for message in messages {
        if !message.is_object()
            || !matches!(
                message.get("role").and_then(Value::as_str),
                Some("system" | "user" | "assistant" | "tool")
            )
            || message.get("content").is_some_and(|value| {
                !value.is_null()
                    && value
                        .as_str()
                        .is_none_or(|text| text.len() > MAX_TEXT || text.contains('\0'))
            })
        {
            return Err("MODEL_ARGUMENTS".into());
        }
    }
    let payload = json!({"model":model,"messages":messages,"tools":tools,"tool_choice":"auto",
        "stream":false,"temperature":0,"max_tokens":2048,"chat_template_kwargs":{"enable_thinking":false}});
    let response = client.request("/v1/chat/completions", Some(&payload), cancelled)?;
    let reply = parse_reply(json_response(response)?)?;
    if cancelled.load(Ordering::Acquire) {
        return Err("MODEL_CANCELLED".into());
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    struct TestClient {
        inner: crate::model_egress::ModelClient,
        root: std::path::PathBuf,
    }
    impl std::ops::Deref for TestClient {
        type Target = crate::model_egress::ModelClient;
        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
    impl Drop for TestClient {
        fn drop(&mut self) {
            self.inner.revoke();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn client(port: u16) -> TestClient {
        let root = std::env::temp_dir().join(format!("ag-model-egress-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).unwrap();
        let inner = crate::model_egress::ModelClient::open(
            port,
            &root.join("egress.db"),
            &uuid::Uuid::new_v4().to_string(),
            0,
            true,
            vec![],
        )
        .unwrap();
        TestClient { inner, root }
    }
    use std::sync::{mpsc, Arc};
    use std::thread;

    fn response(value: &Value) -> Vec<u8> {
        let body = serde_json::to_vec(value).unwrap();
        let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        bytes.extend(body);
        bytes
    }

    fn tool_reply() -> Value {
        json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
            "reasoning_content":"不得进入历史","reasoning":"不得进入历史",
            "tool_calls":[{"id":"call_sample","type":"function","function":{"name":"read_marker","arguments":"{\"name\":\"sample\"}"}}]}}]})
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            raw.extend_from_slice(&buffer[..count]);
            if let Some(at) = raw.windows(4).position(|part| part == b"\r\n\r\n") {
                let header = std::str::from_utf8(&raw[..at]).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if raw.len() == at + 4 + length {
                    return raw;
                }
            }
        }
    }

    fn server(bytes: Vec<u8>) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            for part in bytes.chunks(31) {
                if stream.write_all(part).is_err() {
                    break;
                }
            }
            request
        });
        (port, handle)
    }

    #[test]
    fn 真实tcp工具回复与请求固定字段() {
        let (port, server) = server(response(&tool_reply()));
        let result = complete(
            &client(port),
            "本机-model",
            &[json!({"role":"user","content":"合成任务"})],
            &[],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.calls[0].id, "call_sample");
        assert_eq!(result.calls[0].name, "read_marker");
        assert_eq!(result.calls[0].arguments, json!({"name":"sample"}));
        assert!(result.assistant.get("reasoning_content").is_none());
        assert!(result.assistant.get("reasoning").is_none());
        let request = server.join().unwrap();
        let boundary = request
            .windows(4)
            .position(|value| value == b"\r\n\r\n")
            .unwrap();
        let header = std::str::from_utf8(&request[..boundary]).unwrap();
        assert!(header.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(!header.to_lowercase().contains("authorization"));
        assert!(header.contains("Connection: close"));
        let value: Value = serde_json::from_slice(&request[boundary + 4..]).unwrap();
        assert_eq!(value["max_tokens"], 2048);
        assert_eq!(value["stream"], false);
        assert_eq!(value["temperature"], 0);
        assert_eq!(value["chat_template_kwargs"]["enable_thinking"], false);
    }

    #[test]
    fn 分块回复完整结束后才交付() {
        let body = serde_json::to_vec(&json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"合成完成"}}]})).unwrap();
        let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in body.chunks(13) {
            wire.extend(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend(part);
            wire.extend(b"\r\n");
        }
        wire.extend(b"0\r\n\r\n");
        let (port, server) = server(wire);
        let reply = complete(
            &client(port),
            "model",
            &[json!({"role":"user","content":"合成"})],
            &[],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(reply.content, "合成完成");
        assert!(reply.calls.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn 非标准工具结构整轮拒绝() {
        for scenario in 0..8 {
            let mut value = tool_reply();
            match scenario {
                0 => {
                    value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] =
                        json!("[]")
                }
                1 => {
                    value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] =
                        json!("{broken")
                }
                2 => value["choices"][0]["message"]["tool_calls"][0]["type"] = json!("computer"),
                3 => {
                    let call = value["choices"][0]["message"]["tool_calls"][0].clone();
                    value["choices"][0]["message"]["tool_calls"] = json!([call, call]);
                }
                4 => value["choices"][0]["finish_reason"] = json!("length"),
                5 => value["choices"][0]["finish_reason"] = json!("stop"),
                6 => value["choices"][0]["message"]["role"] = json!("user"),
                _ => {
                    let mut calls = Vec::new();
                    for n in 0..9 {
                        let mut call = value["choices"][0]["message"]["tool_calls"][0].clone();
                        call["id"] = json!(format!("call_{n}"));
                        calls.push(call);
                    }
                    value["choices"][0]["message"]["tool_calls"] = json!(calls);
                }
            }
            assert!(parse_reply(value).is_err(), "场景{scenario}应整轮拒绝");
        }
    }

    #[test]
    fn 正文与工具参数超限拒绝() {
        let mut value = tool_reply();
        value["choices"][0]["message"]["content"] = json!("x".repeat(MAX_TEXT + 1));
        assert_eq!(parse_reply(value).err().unwrap(), "MODEL_TEXT_LIMIT");
        let mut value = tool_reply();
        value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] =
            json!("x".repeat(MAX_TEXT + 1));
        assert!(parse_reply(value).is_err());
        assert!(parse_reply(json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":""}}]})).is_err());
    }

    #[test]
    fn 未返回完整头部时取消迅速生效() {
        for partial in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                if partial {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{").unwrap();
                }
                ready_tx.send(()).unwrap();
                let _ = done_rx.recv_timeout(Duration::from_secs(3));
            });
            let cancelled = Arc::new(AtomicBool::new(false));
            let cancel = cancelled.clone();
            let cancel_thread = thread::spawn(move || {
                ready_rx.recv().unwrap();
                thread::sleep(Duration::from_millis(50));
                cancel.store(true, Ordering::Release);
            });
            let started = Instant::now();
            let error = complete(
                &client(port),
                "model",
                &[json!({"role":"user","content":"合成"})],
                &[],
                &cancelled,
            )
            .err()
            .unwrap();
            assert_eq!(error, "MODEL_EXECUTION_UNCERTAIN");
            assert!(started.elapsed() < Duration::from_millis(750));
            done_tx.send(()).unwrap();
            server.join().unwrap();
            cancel_thread.join().unwrap();
        }
    }

    #[test]
    fn 列表只提供已加载语言模型且不选择默认项() {
        let (port, server) = server(response(&json!({"models":[
            {"id":"unloaded9b","loaded":false,"model_type":"llm"},
            {"id":"loaded35b","loaded":true,"model_type":"vlm"},
            {"id":"document","loaded":true,"model_type":"markitdown"}]})));
        assert_eq!(list_models(&client(port)).unwrap(), vec!["loaded35b"]);
        server.join().unwrap();
    }

    #[test]
    fn 普通兼容接口缺少状态端点时退回模型列表() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let request = read_request(&mut first);
            assert!(request.starts_with(b"GET /v1/models/status "));
            first
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            drop(first);
            let (mut second, _) = listener.accept().unwrap();
            let request = read_request(&mut second);
            assert!(request.starts_with(b"GET /v1/models "));
            second
                .write_all(&response(
                    &json!({"data":[{"id":"local-a"},{"id":"local-b"}]}),
                ))
                .unwrap();
        });
        assert_eq!(
            list_models(&client(port)).unwrap(),
            vec!["local-a", "local-b"]
        );
        server.join().unwrap();
    }

    #[test]
    fn 重定向和服务错误不带正文返回() {
        let (port, server) = server(b"HTTP/1.1 302 Found\r\nLocation: https://example.test/secret\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET".to_vec());
        let error = complete(
            &client(port),
            "model",
            &[json!({"role":"user","content":"合成"})],
            &[],
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert_eq!(error, "MODEL_HTTP_STATUS");
        assert!(!error.contains("SECRET"));
        server.join().unwrap();
    }

    #[test]
    fn 请求字符串和总量上限() {
        for model in ["", "bad\nmodel"] {
            assert_eq!(
                complete(
                    &client(1),
                    model,
                    &[json!({"role":"user","content":"合成"})],
                    &[],
                    &AtomicBool::new(false)
                )
                .err()
                .unwrap(),
                "MODEL_ARGUMENTS"
            );
        }
        let messages = vec![json!({"role":"user","content":"x".repeat(MAX_TEXT)}); 9];
        assert_eq!(
            complete(&client(1), "model", &messages, &[], &AtomicBool::new(false))
                .err()
                .unwrap(),
            "EGRESS_REQUEST_LIMIT"
        );
    }

    #[test]
    #[ignore = "仅显式指定本机已加载模型和独立证据目录时运行，不用于日常CI"]
    fn 本机已加载模型真实工具往返() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("AGENTGUARD_LOCAL_MODEL_PROBE_OUT").expect("必须指定新证据目录"),
        );
        let model =
            std::env::var("AGENTGUARD_LOCAL_MODEL_PROBE_ID").expect("必须指定完整已加载模型ID");
        assert!(directory.is_absolute());
        std::fs::create_dir(&directory).unwrap();
        let available = list_models(&client(8000)).unwrap();
        assert!(available.contains(&model));
        let tools = json!([{"type":"function","function":{"name":"read_synthetic_marker","description":"读取合成测试标记，不访问真实文件。",
            "parameters":{"type":"object","properties":{"marker_id":{"type":"string","enum":["sample"]}},"required":["marker_id"],"additionalProperties":false}}}]);
        let mut messages = vec![
            json!({"role":"system","content":"只做本机合成测试，必须实际调用提供的工具，不编造工具结果，不输出思考。"}),
            json!({"role":"user","content":"调用read_synthetic_marker读取marker_id=sample；收到工具结果后只输出marker正文。"}),
        ];
        let cancelled = AtomicBool::new(false);
        let started = Instant::now();
        let first = complete(
            &client(8000),
            &model,
            &messages,
            tools.as_array().unwrap(),
            &cancelled,
        )
        .unwrap();
        let first_ms = started.elapsed().as_millis();
        assert_eq!(first.calls.len(), 1);
        assert_eq!(first.calls[0].name, "read_synthetic_marker");
        assert_eq!(first.calls[0].arguments, json!({"marker_id":"sample"}));
        let tool_id = first.calls[0].id.clone();
        let first_assistant = first.assistant.clone();
        messages.push(first.assistant);
        messages.push(json!({"role":"tool","tool_call_id":tool_id,"content":"{\"marker\":\"AGD_RUST_LOCAL_MODEL_9462\"}"}));
        let final_start = Instant::now();
        let final_reply = complete(
            &client(8000),
            &model,
            &messages,
            tools.as_array().unwrap(),
            &cancelled,
        )
        .unwrap();
        assert!(final_reply.calls.is_empty());
        assert_eq!(final_reply.content.trim(), "AGD_RUST_LOCAL_MODEL_9462");
        let report = json!({"suite":"生产Rust本地模型模块真实工具往返","passed":true,"model":model,"endpoint":"http://127.0.0.1:8000/v1/chat/completions",
            "authentication":"none","stream":false,"temperature":0,"max_tokens":2048,"enable_thinking":false,
            "first_ms":first_ms,"final_ms":final_start.elapsed().as_millis(),"total_ms":started.elapsed().as_millis(),
            "first_finish_reason_validated":"tool_calls","final_finish_reason_validated":"stop","first_assistant":first_assistant,
            "final_assistant":final_reply.assistant,"synthetic_messages":messages,"tools":tools,
            "scope":"真实本机模型工具调用往返；不代表桌面启动器或完整用户任务验收"});
        std::fs::write(
            directory.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!(
            "本地模型Rust工具往返通过，报告={}",
            directory.join("report.json").display()
        );
    }
}
