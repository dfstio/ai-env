//! The Mac's signing agent: its line protocol and its client (WM-R9, WM-R10). The agent itself is M's
//! (`ai-env relay agent`).
//!
//! One request per connection: the client writes one JSON object and `\n` (at most 4096 bytes with it),
//! the agent answers one JSON object and `\n` (at most 8192) and closes. Every object carries `"v":1`;
//! unknown fields and any other `v` are refused (the agent answers them `bad_request`).

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::keys::{Alg, PublicKey, SIGNATURE_LEN};

/// Names the agent's socket when set and not empty.
pub const AGENT_SOCKET_ENV: &str = "AI_ENV_RELAY_AGENT_SOCK";
/// The socket's file name under `<bridge root>/state/`.
pub const AGENT_SOCKET_FILE: &str = "relay-agent.sock";
/// The longest request line, its newline included.
pub const REQUEST_MAX: usize = 4096;
/// The longest response line, its newline included.
pub const RESPONSE_MAX: usize = 8192;
/// The connect budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// The whole exchange's budget.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The one protocol version.
const VERSION: u32 = 1;

/// WM-R10's path: the variable, else `$AI_ENV_BRIDGE_DIR/state/…`, else `$HOME/.config/ai-env/bridge/state/…`.
pub fn default_socket_path() -> Option<PathBuf> {
    let set = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    if let Some(path) = set(AGENT_SOCKET_ENV) {
        return Some(PathBuf::from(path));
    }
    if let Some(root) = set("AI_ENV_BRIDGE_DIR") {
        return Some(PathBuf::from(root).join("state").join(AGENT_SOCKET_FILE));
    }
    set("HOME").map(|home| PathBuf::from(home).join(".config/ai-env/bridge/state").join(AGENT_SOCKET_FILE))
}

/// One request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The agent's status.
    Status,
    /// Sign a worker's handshake transcript (built by the agent itself).
    SignWorkerAuth(SignRequest),
    /// Mint a VM session token.
    MintSession(MintRequest),
}

/// The fields the agent builds a transcript from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// The worker id.
    pub worker_id: String,
    /// The relay id.
    pub relay_id: String,
    /// The challenge's nonce.
    pub nonce: Vec<u8>,
    /// The algorithm.
    pub alg: crate::keys::Alg,
    /// The worker's key.
    pub public_key: crate::keys::PublicKey,
    /// `Hello.protocol`.
    pub protocol: u32,
}

/// What a token is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
    /// The VM.
    pub vm_id: String,
    /// The spawn's id.
    pub session_id: String,
    /// A resumed or moved chat's id.
    pub chat_id: Option<String>,
    /// The grant.
    pub grant_id: String,
    /// The latest expiry asked, unix seconds.
    pub exp: u64,
}

/// One answer. Its `Debug` shows a token's and a signature's length, never their bytes (WM-R55).
#[derive(Clone, PartialEq, Eq)]
pub enum Response {
    /// The agent's status.
    Status(AgentStatus),
    /// A transcript's signature.
    Signed {
        /// The 64-byte Ed25519 signature.
        signature: [u8; 64],
    },
    /// A minted token.
    Minted {
        /// The token.
        token: String,
        /// Its expiry, unix seconds.
        exp: u64,
    },
    /// A refusal.
    Refused {
        /// The refusal's code word.
        error: String,
        /// Its text.
        message: String,
    },
}

impl fmt::Debug for Response {
    /// `Minted { token: <n bytes>, exp: … }` and `Signed { signature: <64 bytes> }`: one `{:?}` of an answer
    /// never logs a live session token (WM-R55) or a signature (WM-R39).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Response::Status(s) => f.debug_tuple("Status").field(s).finish(),
            Response::Signed { signature } => f.debug_struct("Signed").field("signature", &format_args!("<{} bytes>", signature.len())).finish(),
            Response::Minted { token, exp } => f.debug_struct("Minted").field("token", &format_args!("<{} bytes>", token.len())).field("exp", exp).finish(),
            Response::Refused { error, message } => f.debug_struct("Refused").field("error", error).field("message", message).finish(),
        }
    }
}

/// The agent's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    /// Its pid.
    pub pid: u32,
    /// When it ends, unix seconds.
    pub until: u64,
    /// The worker id it signs for.
    pub worker_id: String,
    /// Its worker key.
    pub worker_key: crate::keys::PublicKey,
    /// Its session key.
    pub session_key: crate::keys::PublicKey,
    /// Signatures made.
    pub signed: u64,
    /// Tokens minted.
    pub minted: u64,
}

// The lines on the socket, field for field (WM-R9).

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusLine {
    v: u32,
    op: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignLine {
    v: u32,
    op: String,
    worker_id: String,
    relay_id: String,
    nonce: String,
    alg: String,
    public_key: String,
    protocol: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintLine {
    v: u32,
    op: String,
    vm_id: String,
    session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chat_id: Option<String>,
    grant_id: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusAnswer {
    v: u32,
    ok: bool,
    pid: u32,
    until: u64,
    worker_id: String,
    worker_key: String,
    session_key: String,
    signed: u64,
    minted: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAnswer {
    v: u32,
    ok: bool,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintedAnswer {
    v: u32,
    ok: bool,
    token: String,
    exp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusedAnswer {
    v: u32,
    ok: bool,
    error: String,
    message: String,
}

const OP_STATUS: &str = "status";
const OP_SIGN: &str = "sign_worker_auth";
const OP_MINT: &str = "mint_session";

/// `value` and `\n`.
fn line_of<T: Serialize>(value: &T) -> Vec<u8> {
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    line
}

/// One JSON object of at most `max` bytes with its newline, `"v":1`, and the field `key` a string; its
/// fields and that string.
fn object(line: &[u8], max: usize, what: &str, key: &str) -> Result<(serde_json::Value, String), AgentError> {
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.len() >= max {
        return Err(AgentError(format!("{what} of {} bytes, over {max}", body.len() + 1)));
    }
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| AgentError(format!("{what} is not one JSON object")))?;
    if value.get("v").and_then(serde_json::Value::as_u64) != Some(u64::from(VERSION)) {
        return Err(AgentError(format!("{what} is not version 1")));
    }
    let tag = match value.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        _ => return Err(AgentError(format!("{what} has no {key}"))),
    };
    Ok((value, tag))
}

fn typed<T: DeserializeOwned>(value: serde_json::Value, what: &str) -> Result<T, AgentError> {
    serde_json::from_value(value).map_err(|e| AgentError(format!("{what}: {e}")))
}

/// `b64` of exactly `len` bytes.
fn bytes_of(b64: &str, len: usize, what: &str) -> Result<Vec<u8>, AgentError> {
    match STANDARD.decode(b64) {
        Ok(bytes) if bytes.len() == len => Ok(bytes),
        _ => Err(AgentError(format!("{what} is not the base64 of {len} bytes"))),
    }
}

/// One JSON line.
pub fn encode_request(r: &Request) -> Vec<u8> {
    match r {
        Request::Status => line_of(&StatusLine { v: VERSION, op: OP_STATUS.into() }),
        Request::SignWorkerAuth(s) => line_of(&SignLine {
            v: VERSION,
            op: OP_SIGN.into(),
            worker_id: s.worker_id.clone(),
            relay_id: s.relay_id.clone(),
            nonce: STANDARD.encode(&s.nonce),
            alg: s.alg.as_str().into(),
            public_key: s.public_key.b64(),
            protocol: s.protocol,
        }),
        Request::MintSession(m) => line_of(&MintLine {
            v: VERSION,
            op: OP_MINT.into(),
            vm_id: m.vm_id.clone(),
            session_id: m.session_id.clone(),
            chat_id: m.chat_id.clone(),
            grant_id: m.grant_id.clone(),
            exp: m.exp,
        }),
    }
}

/// One JSON line back; unknown fields and any `v` but 1 refused.
pub fn decode_request(line: &[u8]) -> Result<Request, AgentError> {
    let (value, op) = object(line, REQUEST_MAX, "a request", "op")?;
    match op.as_str() {
        OP_STATUS => typed::<StatusLine>(value, "a status request").map(|_| Request::Status),
        OP_SIGN => {
            let s: SignLine = typed(value, "a sign_worker_auth request")?;
            let alg = Alg::parse(&s.alg).ok_or_else(|| AgentError(format!("alg {:?} is not ed25519", s.alg)))?;
            let nonce = bytes_of(&s.nonce, ai_env_source::wire::NONCE_LEN, "the nonce")?;
            let key = bytes_of(&s.public_key, crate::keys::PUBLIC_KEY_LEN, "the public key")?;
            let public_key = PublicKey::from_bytes(&key).map_err(|e| AgentError(e.to_string()))?;
            Ok(Request::SignWorkerAuth(SignRequest { worker_id: s.worker_id, relay_id: s.relay_id, nonce, alg, public_key, protocol: s.protocol }))
        }
        OP_MINT => {
            let m: MintLine = typed(value, "a mint_session request")?;
            Ok(Request::MintSession(MintRequest { vm_id: m.vm_id, session_id: m.session_id, chat_id: m.chat_id, grant_id: m.grant_id, exp: m.exp }))
        }
        other => Err(AgentError(format!("unknown op {other:?}"))),
    }
}

/// One JSON line.
pub fn encode_response(r: &Response) -> Vec<u8> {
    match r {
        Response::Status(s) => line_of(&StatusAnswer {
            v: VERSION,
            ok: true,
            pid: s.pid,
            until: s.until,
            worker_id: s.worker_id.clone(),
            worker_key: s.worker_key.text(),
            session_key: s.session_key.text(),
            signed: s.signed,
            minted: s.minted,
        }),
        Response::Signed { signature } => line_of(&SignedAnswer { v: VERSION, ok: true, signature: STANDARD.encode(signature) }),
        Response::Minted { token, exp } => line_of(&MintedAnswer { v: VERSION, ok: true, token: token.clone(), exp: *exp }),
        Response::Refused { error, message } => line_of(&RefusedAnswer { v: VERSION, ok: false, error: error.clone(), message: message.clone() }),
    }
}

/// One JSON line back.
pub fn decode_response(line: &[u8]) -> Result<Response, AgentError> {
    let (value, ok) = object(line, RESPONSE_MAX, "an answer", "ok")?;
    if ok != "true" {
        let r: RefusedAnswer = typed(value, "a refusal")?;
        return Ok(Response::Refused { error: r.error, message: r.message });
    }
    if value.get("signature").is_some() {
        let s: SignedAnswer = typed(value, "a signature")?;
        let bytes = bytes_of(&s.signature, SIGNATURE_LEN, "the signature")?;
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes);
        Ok(Response::Signed { signature })
    } else if value.get("token").is_some() {
        let m: MintedAnswer = typed(value, "a token")?;
        Ok(Response::Minted { token: m.token, exp: m.exp })
    } else {
        let s: StatusAnswer = typed(value, "a status")?;
        let key = |text: &str, what: &str| PublicKey::parse_text(text).map_err(|e| AgentError(format!("{what}: {e}")));
        Ok(Response::Status(AgentStatus {
            pid: s.pid,
            until: s.until,
            worker_key: key(&s.worker_key, "worker_key")?,
            session_key: key(&s.session_key, "session_key")?,
            worker_id: s.worker_id,
            signed: s.signed,
            minted: s.minted,
        }))
    }
}

/// One request over a new connection, within `budget` (the connect within `CONNECT_TIMEOUT` too).
pub async fn request(socket: &Path, req: &Request, budget: Duration) -> Result<Response, AgentError> {
    let shown = socket.display();
    let exchange = async {
        let connect = tokio::time::timeout(CONNECT_TIMEOUT.min(budget), tokio::net::UnixStream::connect(socket));
        let mut stream = match connect.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(AgentError(format!("relay agent at {shown}: {e}"))),
            Err(_) => return Err(AgentError(format!("relay agent at {shown}: no connection within {} ms", CONNECT_TIMEOUT.min(budget).as_millis()))),
        };
        stream.write_all(&encode_request(req)).await.map_err(|e| AgentError(format!("relay agent at {shown}: {e}")))?;
        let mut line = Vec::with_capacity(1024);
        let mut reader = BufReader::new(stream).take(RESPONSE_MAX as u64);
        reader.read_until(b'\n', &mut line).await.map_err(|e| AgentError(format!("relay agent at {shown}: {e}")))?;
        if line.last() != Some(&b'\n') {
            return Err(AgentError(format!("relay agent at {shown}: no whole answer line within {RESPONSE_MAX} bytes")));
        }
        decode_response(&line).map_err(|e| AgentError(format!("relay agent at {shown}: {e}")))
    };
    match tokio::time::timeout(budget, exchange).await {
        Ok(answer) => answer,
        Err(_) => Err(AgentError(format!("relay agent at {shown}: no answer within {} ms", budget.as_millis()))),
    }
}

/// The agent could not be reached, or its line did not parse; it names the socket, never a key. Phase 0
/// freezes the name; W chooses its variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AgentError(String);

impl AgentError {
    pub(crate) fn new(message: impl Into<String>) -> AgentError {
        AgentError(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    /// Set (to a `;`-joined list of `NAME=value`) only in the child process the env test re-executes.
    const CHILD: &str = "AI_ENV_WORKER_AGENT_ENV_CHILD";

    fn key(seed: u8) -> PublicKey {
        SigningKey::from_seed(&[seed; 32]).expect("seed").public_key()
    }

    fn requests() -> Vec<Request> {
        vec![
            Request::Status,
            Request::SignWorkerAuth(SignRequest {
                worker_id: "worker-a".into(),
                relay_id: "relay-test".into(),
                nonce: (0u8..32).collect(),
                alg: Alg::Ed25519,
                public_key: key(1),
                protocol: 1,
            }),
            Request::MintSession(MintRequest {
                vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
                session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
                chat_id: Some("0199a1b2-0000-4000-8000-000000000003".into()),
                grant_id: "default".into(),
                exp: 1_800_028_800,
            }),
            Request::MintSession(MintRequest {
                vm_id: "vm-0000".into(),
                session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
                chat_id: None,
                grant_id: "default".into(),
                exp: 1,
            }),
        ]
    }

    /// WM-T9.
    #[test]
    fn the_agent_protocol_round_trips_and_refuses_what_it_does_not_know() {
        for r in requests() {
            let line = encode_request(&r);
            assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1, "one line");
            assert_eq!(line.last(), Some(&b'\n'));
            assert_eq!(decode_request(&line), Ok(r));
        }
        let answers = vec![
            Response::Status(AgentStatus { pid: 42, until: 1_800_043_200, worker_id: "mac".into(), worker_key: key(1), session_key: key(7), signed: 1, minted: 2 }),
            Response::Signed { signature: [9u8; 64] },
            Response::Minted { token: "0199a1b2-0000-7000-8000-000000000001".into(), exp: 1_800_028_800 },
            Response::Refused { error: "wrong_worker".into(), message: "this agent signs for worker mac".into() },
        ];
        for r in answers {
            let line = encode_response(&r);
            assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1, "one line");
            assert_eq!(decode_response(&line), Ok(r));
        }
        // `Debug` shows a token's and a signature's length, never their bytes (WM-R55).
        let token = "0199a1b2-0000-7000-8000-000000000001";
        let shown = format!("{:?} {:?}", Response::Minted { token: token.into(), exp: 7 }, Response::Signed { signature: [9u8; 64] });
        assert_eq!(shown, "Minted { token: <36 bytes>, exp: 7 } Signed { signature: <64 bytes> }");
        assert!(!shown.contains(token));
        let status = String::from_utf8(encode_response(&Response::Status(AgentStatus {
            pid: 1,
            until: 2,
            worker_id: "mac".into(),
            worker_key: key(1),
            session_key: key(7),
            signed: 0,
            minted: 0,
        })))
        .expect("text");
        assert!(status.starts_with(r#"{"v":1,"ok":true,"pid":1,"until":2,"worker_id":"mac","worker_key":"ed25519:"#), "{status}");
        assert_eq!(String::from_utf8(encode_request(&Request::Status)).expect("text"), "{\"v\":1,\"op\":\"status\"}\n");

        let padded = format!("{{\"v\":1,\"op\":\"status\"}}{}\n", " ".repeat(REQUEST_MAX - 21));
        assert_eq!(padded.len(), 4097);
        assert!(decode_request(padded.as_bytes()).is_err(), "4097 bytes");
        let fits = format!("{{\"v\":1,\"op\":\"status\"}}{}\n", " ".repeat(REQUEST_MAX - 22));
        assert_eq!(decode_request(fits.as_bytes()), Ok(Request::Status), "4096 bytes");
        for bad in [
            r#"{"v":2,"op":"status"}"#.to_string(),
            r#"{"op":"status"}"#.to_string(),
            r#"{"v":1,"op":"shutdown"}"#.to_string(),
            r#"{"v":1,"op":"status","extra":true}"#.to_string(),
            String::from_utf8(encode_request(&requests()[1])).expect("text").replace(&STANDARD.encode((0u8..32).collect::<Vec<_>>()), &STANDARD.encode([0u8; 31])),
            String::from_utf8(encode_request(&requests()[1])).expect("text").replace(&key(1).b64(), &STANDARD.encode([0u8; 33])),
            String::from_utf8(encode_request(&requests()[1])).expect("text").replace("\"ed25519\"", "\"rsa\""),
            "not json".to_string(),
        ] {
            assert!(decode_request(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(decode_response(br#"{"v":1,"ok":true,"signature":"AAAA"}"#).is_err(), "a short signature");
        assert!(decode_response(br#"{"v":1,"ok":false,"error":"x","message":"y","extra":1}"#).is_err());
        assert!(decode_response(format!("{}\n", "x".repeat(RESPONSE_MAX)).as_bytes()).is_err());

        let home = "/tmp/ai-env-worker-home";
        let cases: [(&str, Option<String>); 5] = [
            (&format!("{AGENT_SOCKET_ENV}=/tmp/a.sock;AI_ENV_BRIDGE_DIR=/tmp/b;HOME={home}"), Some("/tmp/a.sock".into())),
            (&format!("{AGENT_SOCKET_ENV}=;AI_ENV_BRIDGE_DIR=/tmp/b;HOME={home}"), Some("/tmp/b/state/relay-agent.sock".into())),
            (&format!("AI_ENV_BRIDGE_DIR=;HOME={home}"), Some(format!("{home}/.config/ai-env/bridge/state/relay-agent.sock"))),
            (&format!("HOME={home}"), Some(format!("{home}/.config/ai-env/bridge/state/relay-agent.sock"))),
            ("", None),
        ];
        for (env, want) in cases {
            assert_eq!(socket_path_in_child(env), want.map(PathBuf::from), "env {env:?}");
        }
    }

    /// `default_socket_path()` as a child process of this test binary sees it, with only `env` set: no other
    /// test sees these variables.
    fn socket_path_in_child(env: &str) -> Option<PathBuf> {
        let exe = std::env::current_exe().expect("the test binary");
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["--exact", "agent::tests::default_socket_path_child", "--nocapture", "--test-threads=1"]).env_clear().env(CHILD, env);
        for pair in env.split(';').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').expect("NAME=value");
            cmd.env(name, value);
        }
        let out = cmd.output().expect("the child runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8(out.stdout).expect("text");
        // The harness prints the test's name on the same line, before the answer.
        let line = stdout.lines().find_map(|l| l.split_once("socket-path:").map(|(_, p)| p)).expect("the child's answer");
        (line != "none").then(|| PathBuf::from(line))
    }

    /// The child half of `socket_path_in_child` (nothing in the parent).
    #[test]
    fn default_socket_path_child() {
        if std::env::var_os(CHILD).is_some() {
            match default_socket_path() {
                Some(p) => println!("socket-path:{}", p.display()),
                None => println!("socket-path:none"),
            }
        }
    }

    #[tokio::test]
    async fn a_request_names_the_socket_and_keeps_its_budget() {
        let dir = tempfile::Builder::new().prefix("aew").tempdir_in("/tmp").expect("a temp dir");
        let path = dir.path().join("agent.sock");
        let e = request(&path, &Request::Status, IO_TIMEOUT).await.expect_err("no agent");
        assert!(e.to_string().contains(&path.display().to_string()), "{e}");

        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let serve = tokio::spawn(async move {
            // The first connection: one status answer. The second: never answers.
            let (stream, _) = listener.accept().await.expect("accept");
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).await.expect("a line");
            assert_eq!(decode_request(&line), Ok(Request::Status));
            let answer = Response::Status(AgentStatus { pid: 7, until: 9, worker_id: "mac".into(), worker_key: key(1), session_key: key(7), signed: 0, minted: 0 });
            reader.get_mut().write_all(&encode_response(&answer)).await.expect("answer");
            let (_silent, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        match request(&path, &Request::Status, IO_TIMEOUT).await.expect("an answer") {
            Response::Status(s) => assert_eq!((s.pid, s.worker_id.as_str(), s.worker_key), (7, "mac", key(1))),
            other => panic!("{other:?}"),
        }
        let started = std::time::Instant::now();
        let e = request(&path, &Request::Status, Duration::from_millis(300)).await.expect_err("silent");
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(e.to_string().contains("no answer within 300 ms"), "{e}");
        serve.abort();
    }
}
