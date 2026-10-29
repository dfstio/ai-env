//! `ai-env-relay-mcp` (§V-vm.3.7, V-R29 to V-R35): the stdio MCP server claude starts from the image's relay config.
//! JSON-RPC 2.0, one message per line; `initialize`, `ping`, `tools/list` and `tools/call` of the two tools,
//! `notifications/cancelled`. Each tool call is one request on a fresh connection to its chat's relay client, whose
//! socket it finds by its own ancestry ([`find_socket`]): it holds no token and touches no socket before a call.
//! Argument errors are tool results (`isError`), an unknown tool a JSON-RPC error (LD-V10); results are text content,
//! compact JSON (LD-V16). On stdin EOF it lets its calls finish; the binary drops them on SIGTERM (LD-V17).
use crate::dial::{local_ceiling, Failure, CATALOG_CEILING};
use crate::local::{socket_path, Answer, Body, Code, Request, SourceEntry, ANSWER_MAX, DEFAULT_MAX_BYTES, LOCAL_V, PARAMS_MAX};
use crate::peer::ANCESTRY_HOPS;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

/// The server's name (= `ai_env_cli::wire::relay::MCP_SERVER`).
pub const SERVER_NAME: &str = "ai-env-relay";
/// The protocol versions `initialize` echoes; any other is answered [`FALLBACK_VERSION`].
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
pub const FALLBACK_VERSION: &str = "2025-06-18";
/// Tool calls at once; the next is `busy`.
pub const MAX_IN_FLIGHT: usize = 8;
/// One message line; a longer one is drained and answered -32600.
pub const LINE_MAX: usize = 4 * 1024 * 1024;
/// `relay_call`'s largest `max_bytes`.
pub const MAX_BYTES: u64 = 262_144;

/// The tools' names (= `wire::relay::TOOL_CATALOG`, `TOOL_CALL`).
const TOOL_CATALOG: &str = "relay_catalog";
const TOOL_CALL: &str = "relay_call";
/// `relay_call`'s `deadline_ms` bound.
const DEADLINE_MS_MAX: u64 = 300_000;
/// The answer to a chat without a relay session (§V-vm.3.6's frozen words).
const NO_SESSION: &str = "this chat has no relay session (it was not started with one)";
/// Beyond the client's own ceiling, how long a call waits for its answer.
const MARGIN: Duration = Duration::from_secs(5);
/// Answer lines queued for stdout at most: past it the reader and the calls wait for the writer (claude reads on).
const OUT_QUEUE: usize = 64;

/// The writer task's queue: one answer line per message.
type Out = tokio::sync::mpsc::Sender<Vec<u8>>;

/// How the server finds its chat's relay client.
pub enum Discovery {
    /// `<dir>/<pid>.sock` for the first pid of its ancestry that has one.
    Ancestry { dir: PathBuf },
    /// This socket (tests; no discovery).
    Socket(PathBuf),
}

/// A requested version when it is one of [`PROTOCOL_VERSIONS`], else [`FALLBACK_VERSION`].
#[must_use]
pub fn negotiate(requested: Option<&str>) -> &'static str {
    PROTOCOL_VERSIONS.iter().find(|v| Some(**v) == requested).copied().unwrap_or(FALLBACK_VERSION)
}

/// `tools/list`'s result: the two tools (§V-vm.3.7, frozen).
#[must_use]
pub fn tools() -> Value {
    json!({"tools": [
        {
            "name": TOOL_CATALOG,
            "title": "Relay catalog",
            "description": "List the data sources this chat may read through the ai-env relay: each source's name, kind, description and availability, and its ops with their parameter JSON Schemas, limits and examples. Call it before relay_call.",
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "Only this source, by its exact name."}}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        },
        {
            "name": TOOL_CALL,
            "title": "Relay call",
            "description": "Call one op of a relay source and return its output (JSON, text or base64). params must match the op's params_schema from relay_catalog. The output is cut at max_bytes (default 65536); truncated says when it was.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "The source's name, as relay_catalog lists it."},
                    "op": {"type": "string", "description": "The op's name, as relay_catalog lists it."},
                    "params": {"type": "object", "description": "The op's parameters; they must match its params_schema."},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 262_144, "description": "Cut the output after this many bytes (default 65536)."},
                    "deadline_ms": {"type": "integer", "minimum": 1, "maximum": 300_000, "description": "Give up after this many milliseconds (default: the op's own)."}
                },
                "required": ["source", "op"],
                "additionalProperties": false
            },
            "annotations": {"openWorldHint": true}
        }
    ]})
}

/// `initialize`'s result.
fn initialize_result(requested: Option<&str>) -> Value {
    json!({
        "protocolVersion": negotiate(requested),
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
        "instructions": "Data sources the developer granted to this chat, behind the ai-env relay. Call relay_catalog first, then relay_call."
    })
}

/// The first `<dir>/<pid>.sock` that is a socket, for each pid from `start` up its ancestry (at most
/// [`ANCESTRY_HOPS`], stopping at pid ≤ 1).
#[must_use]
pub fn find_socket(dir: &Path, start: u32, parent: impl Fn(u32) -> Option<u32>) -> Option<PathBuf> {
    let mut pid = start;
    for _ in 0..ANCESTRY_HOPS {
        if pid <= 1 {
            return None;
        }
        let path = socket_path(dir, pid);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket()) {
            return Some(path);
        }
        pid = parent(pid)?;
    }
    None
}

/// A JSON-RPC answer: `result` or `error`.
#[derive(Serialize)]
struct Reply<'a> {
    jsonrpc: &'static str,
    id: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: &'static str,
}

fn ok_line(id: &Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&Reply { jsonrpc: "2.0", id, result: Some(result), error: None }).unwrap_or_default()
}

fn error_line(id: &Value, code: i32, message: &'static str) -> Vec<u8> {
    serde_json::to_vec(&Reply { jsonrpc: "2.0", id, result: None, error: Some(RpcError { code, message }) }).unwrap_or_default()
}

/// A tool's result: one text content, compact JSON.
fn tool_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

#[derive(Serialize)]
struct ErrorText<'a> {
    code: Code,
    message: &'a str,
}

/// `relay_catalog`'s error text.
#[derive(Serialize)]
struct CatalogError<'a> {
    error: ErrorText<'a>,
}

/// `relay_call`'s error text: the source and op it was asked, then the error.
#[derive(Serialize)]
struct CallError<'a> {
    source: Option<&'a str>,
    op: Option<&'a str>,
    error: ErrorText<'a>,
}

#[derive(Serialize)]
struct CatalogText {
    sources: Vec<SourceEntry>,
    truncated: bool,
}

#[derive(Serialize)]
struct CallText<'a> {
    source: &'a str,
    op: &'a str,
    request_id: String,
    content_type: String,
    truncated: bool,
    bytes: u64,
    limit: u64,
    #[serde(flatten)]
    body: Body,
}

/// One tool call, its arguments checked (V-R32).
enum Tool {
    Catalog { source: Option<String> },
    Call { source: String, op: String, params: Value, max_bytes: u64, deadline_ms: Option<u32> },
}

impl Tool {
    /// The tool's error text for this call (`source` and `op` first for `relay_call`).
    fn error_text(name: &str, args: Option<&serde_json::Map<String, Value>>, code: Code, message: &str) -> String {
        let error = ErrorText { code, message };
        let text = if name == TOOL_CALL {
            let field = |k: &str| args.and_then(|a| a.get(k)).and_then(Value::as_str);
            serde_json::to_string(&CallError { source: field("source"), op: field("op"), error })
        } else {
            serde_json::to_string(&CatalogError { error })
        };
        text.unwrap_or_default()
    }

    /// The arguments of `name` as a call, or a `bad_request` message.
    fn parse(name: &str, args: Option<&serde_json::Map<String, Value>>) -> Result<Tool, String> {
        let empty = serde_json::Map::new();
        let args = args.unwrap_or(&empty);
        let known: &[&str] = if name == TOOL_CALL { &["source", "op", "params", "max_bytes", "deadline_ms"] } else { &["source"] };
        if let Some(k) = args.keys().find(|k| !known.contains(&k.as_str())) {
            return Err(format!("unknown argument {}", serde_json::to_string(&k.chars().take(64).collect::<String>()).unwrap_or_default()));
        }
        let string = |k: &str| match args.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{k} must be a string")),
        };
        if name != TOOL_CALL {
            return Ok(Tool::Catalog { source: string("source")? });
        }
        let source = string("source")?.ok_or("source is missing")?;
        let op = string("op")?.ok_or("op is missing")?;
        let params = match args.get("params") {
            None => Value::Object(serde_json::Map::new()),
            Some(p @ Value::Object(_)) => p.clone(),
            Some(_) => return Err("params must be an object".to_string()),
        };
        let size = serde_json::to_vec(&params).map_or(usize::MAX, |v| v.len());
        if size > PARAMS_MAX {
            return Err(format!("params are {size} bytes (at most {PARAMS_MAX})"));
        }
        let int = |k: &str, max: u64| match args.get(k) {
            None => Ok(None),
            Some(v) => v.as_u64().filter(|n| (1..=max).contains(n)).map(Some).ok_or(format!("{k} must be an integer from 1 to {max}")),
        };
        let max_bytes = int("max_bytes", MAX_BYTES)?.unwrap_or(DEFAULT_MAX_BYTES);
        let deadline_ms = int("deadline_ms", DEADLINE_MS_MAX)?.map(|d| u32::try_from(d).unwrap_or(u32::MAX));
        Ok(Tool::Call { source, op, params, max_bytes, deadline_ms })
    }
}

/// One message line from stdin, or a line over [`LINE_MAX`] (drained).
enum Incoming {
    Line(Vec<u8>),
    TooLong,
}

/// The next line (its newline dropped); `None` at EOF.
async fn next_line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> std::io::Result<Option<Incoming>> {
    let mut buf = Vec::new();
    let mut too_long = false;
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(match (too_long, buf.is_empty()) {
                (true, _) => Some(Incoming::TooLong),
                (false, true) => None,
                (false, false) => Some(Incoming::Line(buf)),
            });
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if !too_long {
            let content = &available[..if done { take - 1 } else { take }];
            if buf.len() + content.len() > LINE_MAX {
                too_long = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(content);
            }
        }
        r.consume(take);
        if done {
            return Ok(Some(if too_long { Incoming::TooLong } else { Incoming::Line(buf) }));
        }
    }
}

/// The calls in flight, by their id's JSON text: dropping one's task closes its connection.
type InFlight = Arc<Mutex<HashMap<String, tokio::task::AbortHandle>>>;

/// The server over `input` and `output` (V-R29 to V-R35): one writer task behind a bounded queue, each tool call on
/// its own task; at `input`'s EOF the calls in flight finish, then it returns.
pub async fn run<R, W>(input: R, output: W, discovery: Discovery) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(OUT_QUEUE);
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(mut line) = rx.recv().await {
            line.push(b'\n');
            output.write_all(&line).await?;
            output.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let discovery = Arc::new(discovery);
    let in_flight: InFlight = Arc::new(Mutex::new(HashMap::new()));
    let mut calls = tokio::task::JoinSet::new();
    let mut reader = tokio::io::BufReader::new(input);
    while let Some(incoming) = next_line(&mut reader).await? {
        while calls.try_join_next().is_some() {}
        let line = match incoming {
            Incoming::TooLong => {
                let _ = tx.send(error_line(&Value::Null, -32600, "the message is over 4 MiB")).await;
                continue;
            }
            Incoming::Line(l) if l.iter().all(u8::is_ascii_whitespace) => continue,
            Incoming::Line(l) => l,
        };
        handle(&line, &tx, &discovery, &in_flight, &mut calls).await;
    }
    while calls.join_next().await.is_some() {}
    drop(tx);
    writer.await.map_err(std::io::Error::other)?
}

/// One message (V-R30 to V-R34).
async fn handle(line: &[u8], tx: &Out, discovery: &Arc<Discovery>, in_flight: &InFlight, calls: &mut tokio::task::JoinSet<()>) {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        let _ = tx.send(error_line(&Value::Null, -32700, "parse error")).await;
        return;
    };
    let Value::Object(m) = message else {
        let _ = tx.send(error_line(&Value::Null, -32600, "not a JSON-RPC 2.0 request")).await;
        return;
    };
    let id = m.get("id");
    let id_ok = id.is_none_or(|i| i.is_string() || i.is_number() || i.is_null());
    let method = m.get("method").and_then(Value::as_str);
    let (Some(method), true, true) = (method, id_ok, m.get("jsonrpc").and_then(Value::as_str) == Some("2.0")) else {
        let id = id.filter(|_| id_ok).unwrap_or(&Value::Null);
        let _ = tx.send(error_line(id, -32600, "not a JSON-RPC 2.0 request")).await;
        return;
    };
    let params = m.get("params");
    let Some(id) = id else {
        // A notification: never answered. A cancel closes its call's connection and no result is sent for it.
        if method == "notifications/cancelled" {
            if let Some(rid) = params.and_then(|p| p.get("requestId")) {
                let key = serde_json::to_string(rid).unwrap_or_default();
                if let Some(call) = in_flight.lock().unwrap_or_else(PoisonError::into_inner).remove(&key) {
                    call.abort();
                }
            }
        }
        return;
    };
    let answer = match method {
        "initialize" => {
            let requested = params.and_then(|p| p.get("protocolVersion")).and_then(Value::as_str);
            ok_line(id, initialize_result(requested))
        }
        "ping" => ok_line(id, json!({})),
        "tools/list" => ok_line(id, tools()),
        "tools/call" => match tools_call(id, params, tx, discovery, in_flight, calls) {
            Some(refusal) => refusal,
            None => return,
        },
        _ => error_line(id, -32601, "method not found"),
    };
    let _ = tx.send(answer).await;
}

/// `tools/call` (V-R32, V-R34): an unknown tool is -32602; bad arguments and a ninth call are tool errors, each
/// returned as its answer line; else the call runs on its own task (`None`), which answers it.
fn tools_call(id: &Value, params: Option<&Value>, tx: &Out, discovery: &Arc<Discovery>, in_flight: &InFlight, calls: &mut tokio::task::JoinSet<()>) -> Option<Vec<u8>> {
    let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str).filter(|n| [TOOL_CATALOG, TOOL_CALL].contains(n)) else {
        return Some(error_line(id, -32602, "unknown tool: this server has relay_catalog and relay_call"));
    };
    let args = match params.and_then(|p| p.get("arguments")) {
        None | Some(Value::Null) => None,
        Some(Value::Object(a)) => Some(a),
        Some(_) => return Some(ok_line(id, tool_result(Tool::error_text(name, None, Code::BadRequest, "arguments must be an object"), true))),
    };
    let tool = match Tool::parse(name, args) {
        Ok(t) => t,
        Err(why) => return Some(ok_line(id, tool_result(Tool::error_text(name, args, Code::BadRequest, &why), true))),
    };
    let key = serde_json::to_string(id).unwrap_or_default();
    // The call is registered under the same lock as it is spawned: a fast one cannot answer before it is.
    let mut flight = in_flight.lock().unwrap_or_else(PoisonError::into_inner);
    if flight.contains_key(&key) {
        return Some(error_line(id, -32600, "a call with this id is in flight"));
    }
    if flight.len() >= MAX_IN_FLIGHT {
        return Some(ok_line(id, tool_result(Tool::error_text(name, args, Code::Busy, &format!("{MAX_IN_FLIGHT} calls in flight")), true)));
    }
    let (id, tx, discovery, mine) = (id.clone(), tx.clone(), discovery.clone(), in_flight.clone());
    let task_key = key.clone();
    let handle = calls.spawn(async move {
        let (text, is_error) = call_tool(&discovery, tool).await;
        // A call cancelled meanwhile is no longer ours to answer.
        let still = mine.lock().unwrap_or_else(PoisonError::into_inner).remove(&task_key).is_some();
        if still {
            let _ = tx.send(ok_line(&id, tool_result(text, is_error))).await;
        }
    });
    flight.insert(key, handle);
    None
}

/// A tool call's text and whether it is an error.
async fn call_tool(discovery: &Discovery, tool: Tool) -> (String, bool) {
    match tool {
        Tool::Catalog { source } => {
            let request = Request::Catalog { v: LOCAL_V, source };
            match ask(discovery, &request, CATALOG_CEILING + MARGIN).await {
                Ok(Answer::Catalog { sources, truncated, .. }) => (serde_json::to_string(&CatalogText { sources, truncated }).unwrap_or_default(), false),
                Ok(Answer::Error { code, message, .. }) => (Tool::error_text(TOOL_CATALOG, None, code, &message), true),
                Ok(Answer::Result { .. }) => (Tool::error_text(TOOL_CATALOG, None, Code::Internal, "the relay client answered a catalog with a result"), true),
                Err(f) => (Tool::error_text(TOOL_CATALOG, None, f.code, &f.message), true),
            }
        }
        Tool::Call { source, op, params, max_bytes, deadline_ms } => {
            let ceiling = local_ceiling(deadline_ms.unwrap_or(0)) + MARGIN;
            let request = Request::Call { v: LOCAL_V, source: source.clone(), op: op.clone(), params, max_bytes: Some(max_bytes), deadline_ms };
            let error = |code: Code, message: &str| serde_json::to_string(&CallError { source: Some(&source), op: Some(&op), error: ErrorText { code, message } }).unwrap_or_default();
            match ask(discovery, &request, ceiling).await {
                Ok(Answer::Result { request_id, content_type, truncated, bytes, limit, body, .. }) => {
                    (serde_json::to_string(&CallText { source: &source, op: &op, request_id, content_type, truncated, bytes, limit, body }).unwrap_or_default(), false)
                }
                Ok(Answer::Error { code, message, .. }) => (error(code, &message), true),
                Ok(Answer::Catalog { .. }) => (error(Code::Internal, "the relay client answered a call with a catalog"), true),
                Err(f) => (error(f.code, &f.message), true),
            }
        }
    }
}

/// One request on a fresh connection to the discovered socket: the connect, the request line and its answer, all
/// within `ceiling` (V-R33, V-R35).
async fn ask(discovery: &Discovery, request: &Request, ceiling: Duration) -> Result<Answer, Failure> {
    let path = match discovery {
        Discovery::Socket(p) => p.clone(),
        Discovery::Ancestry { dir } => find_socket(dir, std::os::unix::process::parent_id(), crate::peer::parent_of).ok_or(Failure::new(Code::NoSession, NO_SESSION))?,
    };
    let unavailable = |what: &str, e: &std::io::Error| Failure::new(Code::Unavailable, format!("the chat's relay client {what}: {e}"));
    let mut line = serde_json::to_vec(request).map_err(|e| Failure::new(Code::Internal, format!("the request: {e}")))?;
    line.push(b'\n');
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| unavailable("cannot be reached", &e))?;
        stream.write_all(&line).await.map_err(|e| unavailable("took no request", &e))?;
        read_answer(&mut stream).await.map_err(|e| unavailable("ended the call", &e))
    };
    let answer = match tokio::time::timeout(ceiling, exchange).await {
        Err(_) => return Err(Failure::new(Code::DeadlineExceeded, format!("no answer from the relay client within {} s", ceiling.as_secs()))),
        Ok(r) => r?,
    };
    match answer {
        AnswerLine::Ended => Err(Failure::new(Code::Unavailable, "the chat's relay client ended the call without an answer")),
        AnswerLine::TooLong => Err(Failure::new(Code::Internal, format!("the relay client's answer is over {ANSWER_MAX} bytes"))),
        AnswerLine::Line(line) => serde_json::from_slice(&line).map_err(|_| Failure::new(Code::Internal, "the relay client's answer is not an answer line")),
    }
}

/// One answer line: read up to its newline (at most [`ANSWER_MAX`] bytes before it), whatever follows.
async fn read_answer(stream: &mut tokio::net::UnixStream) -> std::io::Result<AnswerLine> {
    let mut answer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(AnswerLine::Ended);
        }
        let from = answer.len();
        answer.extend_from_slice(&chunk[..n]);
        match answer[from..].iter().position(|b| *b == b'\n').map(|i| from + i) {
            Some(end) if end <= ANSWER_MAX => {
                answer.truncate(end);
                return Ok(AnswerLine::Line(answer));
            }
            Some(_) => return Ok(AnswerLine::TooLong),
            None if answer.len() > ANSWER_MAX => return Ok(AnswerLine::TooLong),
            None => {}
        }
    }
}

/// What a connection gave back for its request.
enum AnswerLine {
    /// The answer line, its newline dropped.
    Line(Vec<u8>),
    /// More than [`ANSWER_MAX`] bytes before a newline.
    TooLong,
    /// The connection ended before one.
    Ended,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A running server over in-memory pipes: write lines in, read lines out.
    struct Server {
        input: tokio::io::DuplexStream,
        output: tokio::io::Lines<tokio::io::BufReader<tokio::io::DuplexStream>>,
        done: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    impl Server {
        fn start(discovery: Discovery) -> Server {
            let (input, server_in) = tokio::io::duplex(1 << 20);
            let (server_out, output) = tokio::io::duplex(1 << 20);
            let done = tokio::spawn(run(server_in, server_out, discovery));
            Server { input, output: tokio::io::BufReader::new(output).lines(), done }
        }

        async fn send(&mut self, line: &str) {
            self.input.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        }

        async fn next(&mut self) -> Value {
            let line = tokio::time::timeout(Duration::from_secs(10), self.output.next_line()).await.expect("a line within 10 s").unwrap().expect("a line");
            serde_json::from_str(&line).unwrap()
        }

        /// No line within `wait`.
        async fn quiet(&mut self, wait: Duration) -> Option<String> {
            tokio::time::timeout(wait, self.output.next_line()).await.ok().and_then(|l| l.ok().flatten())
        }
    }

    fn call(id: u64, name: &str, args: Value) -> String {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}).to_string()
    }

    /// The text and `isError` of a tool result.
    fn text_of(reply: &Value) -> (Value, bool) {
        let r = &reply["result"];
        (serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap(), r["isError"].as_bool().unwrap())
    }

    /// A listener that accepts and holds every connection, answering none; each request line it read.
    struct Silent {
        _dir: tempfile::TempDir,
        path: PathBuf,
        conns: Arc<Mutex<Vec<tokio::net::UnixStream>>>,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Silent {
        fn start() -> Silent {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("1.sock");
            let l = crate::serve::test_listener(&path).unwrap();
            let conns = Arc::new(Mutex::new(Vec::new()));
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (c, a) = (conns.clone(), accepted.clone());
            tokio::spawn(async move {
                while let Ok((s, _)) = l.accept().await {
                    a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    c.lock().unwrap().push(s);
                }
            });
            Silent { _dir: dir, path, conns, accepted }
        }

        /// Whether connection `i` was closed by the server (EOF after its request line).
        async fn closed(&self, i: usize) -> bool {
            let mut s = self.conns.lock().unwrap().remove(i);
            let mut buf = Vec::new();
            let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
            matches!(r, Ok(Ok(_)))
        }
    }

    /// A listener that answers each connection's request line with `reply`, its bytes as they are, then closes it.
    fn answering(reply: Vec<u8>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1.sock");
        let l = crate::serve::test_listener(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut request = String::new();
                    let _ = tokio::io::BufReader::new(&mut s).read_line(&mut request).await;
                    let _ = s.write_all(&reply).await;
                });
            }
        });
        (dir, path)
    }

    /// The raw text of a tool result (its keys in the order they were written).
    fn raw_text(reply: &Value) -> String {
        reply["result"]["content"][0]["text"].as_str().unwrap().to_string()
    }

    /// Each of `PROTOCOL_VERSIONS` is echoed; `2099-01-01` and a missing version get `2025-06-18`; the result is
    /// §V-vm.3.7's otherwise.
    #[tokio::test]
    async fn initialize_negotiates_a_known_version_or_the_fallback() {
        let mut s = Server::start(Discovery::Socket(PathBuf::from("/nonexistent/relay.sock")));
        let mut id = 0;
        let mut ask = |v: Option<&str>| {
            id += 1;
            let params = v.map_or(json!({"capabilities": {}}), |v| json!({"protocolVersion": v, "capabilities": {}}));
            (id, json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": params}).to_string())
        };
        for (requested, want) in PROTOCOL_VERSIONS.iter().map(|v| (Some(*v), *v)).chain([(Some("2099-01-01"), "2025-06-18"), (None, "2025-06-18")]) {
            let (n, line) = ask(requested);
            s.send(&line).await;
            let reply = s.next().await;
            assert_eq!(reply["id"], json!(n));
            assert_eq!(reply["jsonrpc"], "2.0");
            let r = &reply["result"];
            assert_eq!(r["protocolVersion"], want, "{requested:?}");
            assert_eq!(r["capabilities"], json!({"tools": {"listChanged": false}}));
            assert_eq!(r["serverInfo"], json!({"name": "ai-env-relay", "version": env!("CARGO_PKG_VERSION")}));
            assert_eq!(r["instructions"], "Data sources the developer granted to this chat, behind the ai-env relay. Call relay_catalog first, then relay_call.");
            assert_eq!(r.as_object().unwrap().len(), 4, "{r}");
        }
        assert_eq!(negotiate(Some("2024-11-05")), "2024-11-05");
        assert_eq!(negotiate(Some("")), FALLBACK_VERSION);
    }

    /// `tools()` and the `tools/list` answer equal §V-vm.3.7's document, parsed.
    #[tokio::test]
    async fn tools_list_is_the_two_frozen_tools() {
        let frozen = r#"{"tools":[
 {"name":"relay_catalog","title":"Relay catalog","description":"List the data sources this chat may read through the ai-env relay: each source's name, kind, description and availability, and its ops with their parameter JSON Schemas, limits and examples. Call it before relay_call.","inputSchema":{"type":"object","properties":{"source":{"type":"string","description":"Only this source, by its exact name."}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}},
 {"name":"relay_call","title":"Relay call","description":"Call one op of a relay source and return its output (JSON, text or base64). params must match the op's params_schema from relay_catalog. The output is cut at max_bytes (default 65536); truncated says when it was.","inputSchema":{"type":"object","properties":{"source":{"type":"string","description":"The source's name, as relay_catalog lists it."},"op":{"type":"string","description":"The op's name, as relay_catalog lists it."},"params":{"type":"object","description":"The op's parameters; they must match its params_schema."},"max_bytes":{"type":"integer","minimum":1,"maximum":262144,"description":"Cut the output after this many bytes (default 65536)."},"deadline_ms":{"type":"integer","minimum":1,"maximum":300000,"description":"Give up after this many milliseconds (default: the op's own)."}},"required":["source","op"],"additionalProperties":false},"annotations":{"openWorldHint":true}}
]}"#;
        let frozen: Value = serde_json::from_str(frozen).unwrap();
        assert_eq!(tools(), frozen);
        let mut s = Server::start(Discovery::Socket(PathBuf::from("/nonexistent/relay.sock")));
        s.send(r#"{"jsonrpc":"2.0","id":"t","method":"tools/list"}"#).await;
        let reply = s.next().await;
        assert_eq!(reply["id"], "t");
        assert_eq!(reply["result"], frozen);
    }

    /// Not JSON: -32700, `id` null; `[1]`: -32600; `resources/list`: -32601; a `tools/call` of `relay_other`:
    /// -32602; a notification gets no line; `ping` gets `{}`; a `notifications/cancelled` for a call whose listener
    /// never answers closes that connection, and no line ever names its id; a line over 4 MiB is -32600.
    #[tokio::test]
    async fn json_rpc_errors_follow_the_spec() {
        let listener = Silent::start();
        let mut s = Server::start(Discovery::Socket(listener.path.clone()));
        s.send("{not json").await;
        let r = s.next().await;
        assert_eq!((r["error"]["code"].clone(), r["id"].clone()), (json!(-32700), Value::Null));
        s.send("[1]").await;
        let r = s.next().await;
        assert_eq!((r["error"]["code"].clone(), r["id"].clone()), (json!(-32600), Value::Null));
        s.send(r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#).await;
        let r = s.next().await;
        assert_eq!((r["error"]["code"].clone(), r["id"].clone()), (json!(-32601), json!(3)));
        s.send(&call(4, "relay_other", json!({}))).await;
        let r = s.next().await;
        assert_eq!((r["error"]["code"].clone(), r["id"].clone()), (json!(-32602), json!(4)));
        s.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).await;
        s.send(r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#).await;
        let r = s.next().await;
        assert_eq!((r["id"].clone(), r["result"].clone()), (json!(5), json!({})), "the notification got no line");
        s.send(r#"{"jsonrpc":"1.0","id":6,"method":"ping"}"#).await;
        assert_eq!(s.next().await["error"]["code"], -32600, "not 2.0");
        // A call the listener holds, then its cancel.
        s.send(&call(7, "relay_catalog", json!({}))).await;
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while listener.accepted.load(std::sync::atomic::Ordering::SeqCst) < 1 {
            assert!(std::time::Instant::now() < until, "the call never connected");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        s.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"user"}}"#).await;
        assert!(listener.closed(0).await, "the cancelled call's connection was closed");
        s.send(r#"{"jsonrpc":"2.0","id":8,"method":"ping"}"#).await;
        let r = s.next().await;
        assert_eq!(r["id"], 8, "no line for the cancelled call: {r}");
        assert_eq!(s.quiet(Duration::from_millis(300)).await, None);
        let long = format!("{{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\",\"params\":\"{}\"}}", "x".repeat(LINE_MAX));
        s.send(&long).await;
        let r = s.next().await;
        assert_eq!((r["error"]["code"].clone(), r["id"].clone()), (json!(-32600), Value::Null));
        s.send(r#"{"jsonrpc":"2.0","id":10,"method":"ping"}"#).await;
        assert_eq!(s.next().await["id"], 10, "read on after the long line");
        drop(s.input);
        assert!(s.done.await.unwrap().is_ok(), "EOF ends the server");
    }

    /// `relay_call` without `op`, with `params` `[]`, `max_bytes` 0 or 262 145, `deadline_ms` 300 001, an unknown
    /// argument: each a result with `isError` and `bad_request`, its text `source` and `op` (each `null` when it is
    /// not a string) and then `error` (§V-vm.3.7's order, as written); with eight calls held by the listener, a ninth
    /// is `isError` `busy` at once.
    #[tokio::test]
    async fn tool_argument_errors_are_tool_results() {
        let listener = Silent::start();
        let mut s = Server::start(Discovery::Socket(listener.path.clone()));
        let bad = [
            json!({"source": "echo"}),
            json!({"source": "echo", "op": "echo", "params": []}),
            json!({"source": "echo", "op": "echo", "max_bytes": 0}),
            json!({"source": "echo", "op": "echo", "max_bytes": 262_145}),
            json!({"source": "echo", "op": "echo", "deadline_ms": 300_001}),
            json!({"source": "echo", "op": "echo", "extra": 1}),
            json!({"source": 1, "op": "echo"}),
            json!({"source": "echo", "op": "echo", "params": {"x": "y".repeat(PARAMS_MAX)}}),
        ];
        for (i, args) in bad.iter().enumerate() {
            s.send(&call(i as u64, "relay_call", args.clone())).await;
            let r = s.next().await;
            let (text, is_error) = text_of(&r);
            assert!(is_error, "{args}: {r}");
            assert_eq!(text["error"]["code"], "bad_request", "{args}: {text}");
            let field = |k: &str| args.get(k).filter(|v| v.is_string()).map_or_else(|| "null".to_string(), Value::to_string);
            let head = format!("{{\"source\":{},\"op\":{},\"error\":{{\"code\":\"bad_request\",\"message\":", field("source"), field("op"));
            assert!(raw_text(&r).starts_with(&head), "{head} …: {}", raw_text(&r));
        }
        s.send(&call(50, "relay_catalog", json!({"source": "echo", "op": "x"}))).await;
        let (text, is_error) = text_of(&s.next().await);
        assert!(is_error && text["error"]["code"] == "bad_request" && text.get("source").is_none(), "{text}");
        assert_eq!(listener.accepted.load(std::sync::atomic::Ordering::SeqCst), 0, "no bad call reached the socket");
        for i in 100..108 {
            s.send(&call(i, "relay_call", json!({"source": "echo", "op": "echo"}))).await;
        }
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while listener.accepted.load(std::sync::atomic::Ordering::SeqCst) < 8 {
            assert!(std::time::Instant::now() < until, "eight calls connected");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        s.send(&call(108, "relay_call", json!({"source": "echo", "op": "echo"}))).await;
        let r = s.next().await;
        assert_eq!(r["id"], 108);
        let (_, is_error) = text_of(&r);
        assert!(is_error, "{r}");
        assert_eq!(raw_text(&r), r#"{"source":"echo","op":"echo","error":{"code":"busy","message":"8 calls in flight"}}"#);
        assert_eq!(listener.accepted.load(std::sync::atomic::Ordering::SeqCst), 8, "the ninth never connected");
    }

    /// An answer line within `ANSWER_MAX` is the call's result, its text `source`, `op`, then the answer's fields
    /// (§V-vm.3.7's order, as written); one over `ANSWER_MAX` is the tool's `internal` error. Control (the answer
    /// bound, V-R32).
    #[tokio::test]
    async fn an_answer_over_its_bound_is_internal() {
        let result = br#"{"kind":"result","v":1,"request_id":"0199a1b2-0000-7000-8000-00000000000a","content_type":"application/json","truncated":false,"bytes":7,"limit":65536,"json":{"x":1}}"#;
        let (_dir, path) = answering([result.as_slice(), b"\n"].concat());
        let mut s = Server::start(Discovery::Socket(path));
        s.send(&call(1, "relay_call", json!({"source": "echo", "op": "echo", "params": {"x": 1}}))).await;
        let r = s.next().await;
        assert_eq!(r["result"]["isError"], false, "{r}");
        assert_eq!(
            raw_text(&r),
            r#"{"source":"echo","op":"echo","request_id":"0199a1b2-0000-7000-8000-00000000000a","content_type":"application/json","truncated":false,"bytes":7,"limit":65536,"json":{"x":1}}"#
        );
        for (what, reply) in [("a line over the bound", [vec![b'x'; ANSWER_MAX + 1], b"\n".to_vec()].concat()), ("no newline within the bound", vec![b'x'; ANSWER_MAX + 1])] {
            let (_dir, path) = answering(reply);
            let mut s = Server::start(Discovery::Socket(path));
            s.send(&call(2, "relay_call", json!({"source": "echo", "op": "echo"}))).await;
            let r = s.next().await;
            assert_eq!(raw_text(&r), format!(r#"{{"source":"echo","op":"echo","error":{{"code":"internal","message":"the relay client's answer is over {ANSWER_MAX} bytes"}}}}"#), "{what}");
        }
    }

    /// With sockets planted for an ancestor and for a stranger, `find_socket` picks the ancestor's; with none on the
    /// chain, `None`; a file that is no socket is passed over.
    #[test]
    fn the_mcp_server_finds_its_sessions_socket_by_ancestry() {
        let dir = tempfile::tempdir().unwrap();
        // A socket file at `<pid>.sock` (what find_socket looks for is the file's type, not a listener).
        let bind = |pid: u32| std::os::unix::net::UnixDatagram::bind(socket_path(dir.path(), pid)).unwrap();
        // 500 (the MCP's parent) → 400 → 300 → 1; a stranger at 600.
        let chain: HashMap<u32, u32> = [(500, 400), (400, 300), (300, 1)].into_iter().collect();
        let parent = |p: u32| chain.get(&p).copied();
        assert_eq!(find_socket(dir.path(), 500, parent), None, "no socket yet");
        let _stranger = bind(600);
        assert_eq!(find_socket(dir.path(), 500, parent), None, "a stranger's socket is not this chat's");
        std::fs::write(socket_path(dir.path(), 400), "not a socket").unwrap();
        let _ancestor = bind(300);
        assert_eq!(find_socket(dir.path(), 500, parent), Some(socket_path(dir.path(), 300)));
        assert_eq!(find_socket(dir.path(), 1, parent), None, "init is nobody's chat");
        // Past 16 pids up the chain: not found.
        let long: HashMap<u32, u32> = (1000..1030).map(|p| (p, p + 1)).collect();
        let _far = bind(1016);
        assert_eq!(find_socket(dir.path(), 1000, |p| long.get(&p).copied()), None, "the 17th pid is past the walk");
        assert_eq!(find_socket(dir.path(), 1001, |p| long.get(&p).copied()), Some(socket_path(dir.path(), 1016)));
    }
}
