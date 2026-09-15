//! 单连接 HTTP/1.1 与 SSE 有界解码；不重定向、不解压、不升级协议。
use super::{error, RemoteError};
use crate::mcp_stdio::{parse_response, Reply, MAX_RESPONSE_BYTES};
use std::collections::BTreeMap;

const MAX_HEADERS: usize = 16 * 1024;
const MAX_WIRE: usize = 256 * 1024;
#[derive(Clone, Copy)]
enum Framing {
    Length(usize),
    Chunked,
    Eof,
}
pub(super) struct Head {
    pub status: u16,
    pub sse: bool,
    pub session: Option<String>,
    framing: Framing,
}
pub(super) struct Decoder {
    raw: Vec<u8>,
    pub head: Option<Head>,
    pub body: Vec<u8>,
    at: usize,
    chunk: Option<usize>,
    pub complete: bool,
}
impl Decoder {
    pub fn new() -> Self {
        Self {
            raw: Vec::new(),
            head: None,
            body: Vec::new(),
            at: 0,
            chunk: None,
            complete: false,
        }
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), RemoteError> {
        if self.raw.len().saturating_add(bytes.len()) > MAX_WIRE {
            return Err(error("MCP_REMOTE_RESPONSE_LIMIT"));
        }
        self.raw.extend_from_slice(bytes);
        if self.head.is_none() {
            let Some(end) = self.raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                if self.raw.len() > MAX_HEADERS {
                    return Err(error("MCP_REMOTE_HEADER_LIMIT"));
                }
                return Ok(());
            };
            if end + 4 > MAX_HEADERS {
                return Err(error("MCP_REMOTE_HEADER_LIMIT"));
            }
            self.head = Some(parse_head(&self.raw[..end])?);
            self.at = end + 4;
        }
        let mode = self.head.as_ref().unwrap().framing;
        match mode {
            Framing::Length(n) => {
                if self.raw.len() - self.at > n - self.body.len() {
                    return Err(error("MCP_REMOTE_HTTP"));
                }
                self.body.extend_from_slice(&self.raw[self.at..]);
                self.at = self.raw.len();
                self.complete = self.body.len() == n;
            }
            Framing::Eof => {
                self.body.extend_from_slice(&self.raw[self.at..]);
                self.at = self.raw.len();
            }
            Framing::Chunked => loop {
                if self.complete {
                    if self.at != self.raw.len() {
                        return Err(error("MCP_REMOTE_HTTP"));
                    }
                    break;
                }
                if self.chunk.is_none() {
                    let Some(end) = self.raw[self.at..].windows(2).position(|w| w == b"\r\n")
                    else {
                        if self.raw.len() - self.at > 8 {
                            return Err(error("MCP_REMOTE_CHUNK"));
                        }
                        break;
                    };
                    let text = &self.raw[self.at..self.at + end];
                    if text.is_empty() || text.len() > 8 || !text.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(error("MCP_REMOTE_CHUNK"));
                    }
                    let n = usize::from_str_radix(std::str::from_utf8(text).unwrap(), 16)
                        .map_err(|_| error("MCP_REMOTE_CHUNK"))?;
                    if n > MAX_RESPONSE_BYTES - self.body.len() {
                        return Err(error("MCP_REMOTE_RESPONSE_LIMIT"));
                    }
                    self.chunk = Some(n);
                    self.at += end + 2;
                }
                let n = self.chunk.unwrap();
                if self.raw.len() - self.at < n + 2 {
                    break;
                }
                if &self.raw[self.at + n..self.at + n + 2] != b"\r\n" {
                    return Err(error("MCP_REMOTE_CHUNK"));
                }
                self.body.extend_from_slice(&self.raw[self.at..self.at + n]);
                self.at += n + 2;
                self.chunk = None;
                // 首批不接受 chunk 扩展或 trailers，避免未登记的尾部头字段。
                if n == 0 {
                    self.complete = true;
                }
            },
        }
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(error("MCP_REMOTE_RESPONSE_LIMIT"));
        }
        Ok(())
    }
    pub fn eof(&mut self) -> Result<(), RemoteError> {
        if self
            .head
            .as_ref()
            .is_some_and(|h| matches!(h.framing, Framing::Eof))
        {
            self.complete = true;
        }
        if self.complete {
            Ok(())
        } else {
            Err(error("MCP_REMOTE_DISCONNECTED"))
        }
    }
}
fn parse_head(bytes: &[u8]) -> Result<Head, RemoteError> {
    let bad = || error("MCP_REMOTE_HTTP");
    let raw = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let mut lines = raw.split("\r\n");
    let mut first = lines.next().ok_or_else(bad)?.splitn(3, ' ');
    if first.next() != Some("HTTP/1.1") {
        return Err(bad());
    }
    let code = first.next().ok_or_else(bad)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let status = code.parse::<u16>().map_err(|_| bad())?;
    if first
        .next()
        .is_none_or(|v| v.bytes().any(|b| !(32..127).contains(&b)))
        || !(200..600).contains(&status)
    {
        return Err(bad());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or_else(bad)?;
        if k.is_empty()
            || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || v.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(bad());
        }
        // 有限客户端不需要可重复的响应头；重复字段统一拒绝，防止两种解释。
        if headers
            .insert(k.to_ascii_lowercase(), v.trim().to_owned())
            .is_some()
        {
            return Err(bad());
        }
    }
    if (300..400).contains(&status) {
        return Err(error("MCP_REMOTE_REDIRECT"));
    }
    if status == 401 || status == 403 {
        return Err(error("MCP_REMOTE_AUTH_REJECTED"));
    }
    if status != 200 && status != 202 && status != 204 && status != 405 {
        return Err(error("MCP_REMOTE_HTTP_STATUS"));
    }
    if headers.contains_key("upgrade")
        || headers
            .get("content-encoding")
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Err(error("MCP_REMOTE_UNSUPPORTED"));
    }
    let content = headers
        .get("content-type")
        .map(|v| v.split(';').next().unwrap().trim().to_ascii_lowercase());
    let sse = content.as_deref() == Some("text/event-stream");
    if status == 200 && !sse && content.as_deref() != Some("application/json") {
        return Err(error("MCP_REMOTE_CONTENT_TYPE"));
    }
    // 仅接受 UTF-8；未声明 charset 时协议也固定 UTF-8。
    if let Some(v) = headers.get("content-type") {
        if v.split(';')
            .skip(1)
            .any(|p| !p.trim().eq_ignore_ascii_case("charset=utf-8"))
        {
            return Err(error("MCP_REMOTE_CONTENT_TYPE"));
        }
    }
    let framing = match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(n), None) => {
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            let n = n.parse::<usize>().map_err(|_| bad())?;
            if n > MAX_RESPONSE_BYTES {
                return Err(error("MCP_REMOTE_RESPONSE_LIMIT"));
            }
            Framing::Length(n)
        }
        (None, Some(v)) if v.eq_ignore_ascii_case("chunked") => Framing::Chunked,
        (None, None) => {
            if status == 204 {
                Framing::Length(0)
            } else {
                Framing::Eof
            }
        }
        _ => return Err(bad()),
    };
    let session = headers.remove("mcp-session-id");
    if session.as_ref().is_some_and(|v| {
        v.is_empty() || v.len() > 256 || !v.bytes().all(|b| (0x21..=0x7e).contains(&b))
    }) {
        return Err(bad());
    }
    Ok(Head {
        status,
        sse,
        session,
        framing,
    })
}

/// 逐字节处理 CR、LF 和 CRLF；总正文另有 128 KiB 上限。只接收 message 事件。
pub(super) struct Sse {
    line: Vec<u8>,
    data: Vec<u8>,
    event: Option<String>,
    skip_lf: bool,
    first: bool,
    events: usize,
}
impl Sse {
    pub fn new() -> Self {
        Self {
            line: vec![],
            data: vec![],
            event: None,
            skip_lf: false,
            first: true,
            events: 0,
        }
    }
    pub fn feed(&mut self, bytes: &[u8], id: u64) -> Result<Option<Reply>, RemoteError> {
        let mut reply = None;
        for &b in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if b == b'\n' {
                    continue;
                }
            }
            if b == b'\r' || b == b'\n' {
                self.skip_lf = b == b'\r';
                if let Some(value) = self.line(id)? {
                    if reply.is_some() {
                        return Err(error("MCP_REMOTE_SSE_EXTRA"));
                    }
                    reply = Some(value);
                }
            } else {
                self.line.push(b);
            }
        }
        if reply.is_some()
            && (!self.line.is_empty() || !self.data.is_empty() || self.event.is_some())
        {
            return Err(error("MCP_REMOTE_SSE_EXTRA"));
        }
        Ok(reply)
    }
    fn line(&mut self, id: u64) -> Result<Option<Reply>, RemoteError> {
        let raw = std::mem::take(&mut self.line);
        let mut text = std::str::from_utf8(&raw).map_err(|_| error("MCP_REMOTE_SSE"))?;
        if self.first {
            text = text.strip_prefix('\u{feff}').unwrap_or(text);
            self.first = false;
        }
        if text.is_empty() {
            self.events += 1;
            if self.events > 64 {
                return Err(error("MCP_REMOTE_SSE_LIMIT"));
            }
            let event = self.event.take();
            if event
                .as_deref()
                .is_some_and(|s| !s.is_empty() && s != "message")
            {
                return Err(error("MCP_REMOTE_UNSUPPORTED"));
            }
            if self.data.is_empty() {
                return Ok(None);
            }
            self.data.pop();
            let reply = parse_response(&self.data, id).map_err(|_| error("MCP_REMOTE_PROTOCOL"))?;
            self.data.clear();
            return Ok(Some(reply));
        }
        if text.starts_with(':') {
            return Ok(None);
        }
        let (key, value) = text.split_once(':').unwrap_or((text, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match key {
            "data" => {
                self.data.extend_from_slice(value.as_bytes());
                self.data.push(b'\n');
            }
            "event" => self.event = Some(value.into()),
            // 不恢复、不重试；游标和服务器建议不授予新的 HTTP 请求权限。
            "id" if value.len() <= 256 && !value.contains('\0') => {}
            "retry"
                if !value.is_empty()
                    && value.len() <= 10
                    && value.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => return Err(error("MCP_REMOTE_UNSUPPORTED")),
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 分块字节碎片与长度边界均准确还原() {
        let raw=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        for width in [1, 2, 7, 4096] {
            let mut d = Decoder::new();
            for b in raw.chunks(width) {
                d.feed(b).unwrap();
            }
            assert!(d.complete);
            assert_eq!(d.body, b"abcde");
            d.eof().unwrap();
        }
    }
    #[test]
    fn 歧义头超限重定向和截断全部拒绝() {
        for headers in [
            "Content-Length: 0\r\nContent-Length: 1",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
            "Content-Encoding: gzip",
            "Mcp-Session-Id: ",
            "Content-Length: 999999999",
            "Upgrade: websocket",
            "content-type: text/plain",
        ] {
            let mut d = Decoder::new();
            assert!(d
                .feed(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{headers}\r\n\r\n"
                    )
                    .as_bytes()
                )
                .is_err());
        }
        let mut d = Decoder::new();
        assert_eq!(
            d.feed(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/secret\r\n\r\n")
                .unwrap_err()
                .code,
            "MCP_REMOTE_REDIRECT"
        );
        let mut d = Decoder::new();
        d.feed(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\nabc",
        )
        .unwrap();
        assert!(d.eof().is_err());
        let mut d = Decoder::new();
        assert!(d
            .feed(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\nab"
            )
            .is_err());
    }
    #[test]
    fn 事件流支持换行碎片但不执行服务端请求或重试提示() {
        for nl in ["\n", "\r", "\r\n"] {
            let wire=format!("\u{feff}: ping{nl}id: cursor{nl}retry: 10{nl}event: message{nl}data: {{\"jsonrpc\":\"2.0\",{nl}data: \"id\":1,\"result\":{{}}}}{nl}{nl}");
            let mut p = Sse::new();
            let mut result = None;
            for b in wire.as_bytes().chunks(1) {
                if let Some(v) = p.feed(b, 1).unwrap() {
                    result = Some(v);
                }
            }
            assert!(matches!(result, Some(Reply::Result(_))));
        }
        for text in [
            "event: endpoint\ndata: /new\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":1}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"x\":1,\"x\":2}}\n\n",
        ] {
            assert!(Sse::new().feed(text.as_bytes(), 1).is_err());
        }
    }
}
