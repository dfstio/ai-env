//! The socket protocol between `ai-env-relay-mcp` and `ai-env-relay-client` (§V-vm.3.6): one connection carries one
//! request line and one answer line, then closes. The types fix the keys and their order; a reader takes them in any
//! order. A body is exactly one of `json`, `text` and `b64` (V-R26). Codes are google.rpc.Code's words, plus the
//! local ones (`no_session`, `forbidden_peer`, `bad_request`, `busy`).
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Every request's and answer's `v`.
pub const LOCAL_V: u32 = 1;
/// The clients' sockets, `<leader pid>.sock` (= `ai_env_cli::wire::relay::SOCKET_DIR`; each side's test pins it).
pub const SOCKET_DIR: &str = "/run/ai-env/relay";
/// One request line: 64 KiB of params and 4 KiB.
pub const REQUEST_MAX: usize = 69_632;
/// One answer line.
pub const ANSWER_MAX: usize = 2_097_152;
/// A call's params, compact (P's `wire::PARAMS_MAX`, R-34's default).
pub const PARAMS_MAX: usize = 65_536;
/// A call's byte cap when its request names none.
pub const DEFAULT_MAX_BYTES: u64 = 65_536;
/// The largest byte cap the client asks of the relay (R may lower it, never raise it).
pub const MAX_BYTES_CAP: u64 = 1_048_576;
/// A catalog answer's line, sources dropped from the end until it fits (V-R22).
pub const CATALOG_MAX: usize = 262_144;
/// The largest `deadline_ms` a request may name.
pub const DEADLINE_CAP_MS: u32 = 300_000;

/// `<dir>/<leader>.sock`.
#[must_use]
pub fn socket_path(dir: &Path, leader: u32) -> PathBuf {
    dir.join(format!("{leader}.sock"))
}

/// One request line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// The catalog, or one source of it.
    Catalog {
        v: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// One op of one source.
    Call {
        v: u32,
        source: String,
        op: String,
        #[serde(default)]
        params: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deadline_ms: Option<u32>,
    },
}

/// One answer line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    Catalog {
        v: u32,
        sources: Vec<SourceEntry>,
        truncated: bool,
    },
    Result {
        v: u32,
        request_id: String,
        content_type: String,
        truncated: bool,
        bytes: u64,
        limit: u64,
        #[serde(flatten)]
        body: Body,
    },
    Error {
        v: u32,
        code: Code,
        message: String,
    },
}

impl Answer {
    /// An `error` answer.
    #[must_use]
    pub fn error(code: Code, message: impl Into<String>) -> Answer {
        Answer::Error { v: LOCAL_V, code, message: message.into() }
    }
}

/// A result's body (V-R26).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Body {
    /// The bytes parsed as JSON (a JSON content type).
    Json(serde_json::Value),
    /// UTF-8 text.
    Text(String),
    /// Anything else, standard base64.
    B64(String),
}

/// An error's code: the local words, then google.rpc.Code's (tonic::Code's numbering, but `OK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    /// The MCP server found no client socket for its chat.
    NoSession,
    /// The client refused the peer (V-R18).
    ForbiddenPeer,
    /// A request the client or the MCP server refuses (V-R19, V-R32).
    BadRequest,
    /// Eight connections or calls already.
    Busy,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl Code {
    /// The word on the wire and in the client's lines (`no_session`, `permission_denied`, …).
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Code::NoSession => "no_session",
            Code::ForbiddenPeer => "forbidden_peer",
            Code::BadRequest => "bad_request",
            Code::Busy => "busy",
            Code::Cancelled => "cancelled",
            Code::Unknown => "unknown",
            Code::InvalidArgument => "invalid_argument",
            Code::DeadlineExceeded => "deadline_exceeded",
            Code::NotFound => "not_found",
            Code::AlreadyExists => "already_exists",
            Code::PermissionDenied => "permission_denied",
            Code::ResourceExhausted => "resource_exhausted",
            Code::FailedPrecondition => "failed_precondition",
            Code::Aborted => "aborted",
            Code::OutOfRange => "out_of_range",
            Code::Unimplemented => "unimplemented",
            Code::Internal => "internal",
            Code::Unavailable => "unavailable",
            Code::DataLoss => "data_loss",
            Code::Unauthenticated => "unauthenticated",
        }
    }
}

/// google.rpc.Code (tonic::Code's numbering) → its local code; any other number → `Unknown` (0 too: an error never
/// carries OK).
#[must_use]
pub fn code_of_grpc(code: i32) -> Code {
    match code {
        1 => Code::Cancelled,
        3 => Code::InvalidArgument,
        4 => Code::DeadlineExceeded,
        5 => Code::NotFound,
        6 => Code::AlreadyExists,
        7 => Code::PermissionDenied,
        8 => Code::ResourceExhausted,
        9 => Code::FailedPrecondition,
        10 => Code::Aborted,
        11 => Code::OutOfRange,
        12 => Code::Unimplemented,
        13 => Code::Internal,
        14 => Code::Unavailable,
        15 => Code::DataLoss,
        16 => Code::Unauthenticated,
        _ => Code::Unknown,
    }
}

/// One source of the catalog (a `SourceStatus` with its descriptor, §V-vm.3.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    /// `unspecified|sql|http_api|grpc_api|logs|metrics|host_stats|other`.
    pub kind: String,
    pub env: String,
    /// `unspecified|public|internal|restricted`.
    pub sensitivity: String,
    pub available: bool,
    pub last_seen_unix_ms: i64,
    pub ops: Vec<OpEntry>,
}

/// One op of a source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpEntry {
    pub name: String,
    pub description: String,
    /// The schema parsed when its text parses, else the text as a JSON string.
    pub params_schema: serde_json::Value,
    /// `unspecified|json|text|stream`.
    pub output: String,
    pub read_only: bool,
    pub default_limits: LimitsEntry,
    pub max_limits: LimitsEntry,
    /// Each example parsed when it parses, else its text as a JSON string.
    pub examples: Vec<serde_json::Value>,
}

/// An op's limits; zeros when the descriptor names none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimitsEntry {
    pub max_bytes: u64,
    pub max_rows: u32,
    pub max_chunks: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// google.rpc.Code's 1 to 16 map to their words; 0 (an error never carries OK), 17 and -1 to `unknown`.
    #[test]
    fn grpc_codes_map_to_local_codes() {
        let words = [
            "cancelled",
            "unknown",
            "invalid_argument",
            "deadline_exceeded",
            "not_found",
            "already_exists",
            "permission_denied",
            "resource_exhausted",
            "failed_precondition",
            "aborted",
            "out_of_range",
            "unimplemented",
            "internal",
            "unavailable",
            "data_loss",
            "unauthenticated",
        ];
        for (n, word) in (1..=16).zip(words) {
            let code = code_of_grpc(n);
            assert_eq!(code.word(), word, "{n}");
            assert_eq!(serde_json::to_value(code).unwrap(), serde_json::Value::String(word.into()), "{n}: the wire's word is the line's");
            assert_eq!(n, tonic::Code::from_i32(n) as i32, "tonic's numbering");
        }
        for n in [0, 17, -1] {
            assert_eq!(code_of_grpc(n), Code::Unknown, "{n}");
        }
        for (code, word) in [(Code::NoSession, "no_session"), (Code::ForbiddenPeer, "forbidden_peer"), (Code::BadRequest, "bad_request"), (Code::Busy, "busy")] {
            assert_eq!(code.word(), word);
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{word}\""));
        }
    }

    /// §V-vm.3.6's lines: each written as the contract shows it and read back; a reader takes keys in any order.
    #[test]
    fn the_local_lines_are_the_contracts() {
        let catalog = Request::Catalog { v: 1, source: None };
        assert_eq!(serde_json::to_string(&catalog).unwrap(), r#"{"kind":"catalog","v":1}"#);
        let one = Request::Catalog { v: 1, source: Some("echo".into()) };
        assert_eq!(serde_json::to_string(&one).unwrap(), r#"{"kind":"catalog","v":1,"source":"echo"}"#);
        let call = Request::Call { v: 1, source: "echo".into(), op: "echo".into(), params: serde_json::json!({"x": 1}), max_bytes: Some(65_536), deadline_ms: Some(30_000) };
        let line = r#"{"kind":"call","v":1,"source":"echo","op":"echo","params":{"x":1},"max_bytes":65536,"deadline_ms":30000}"#;
        assert_eq!(serde_json::to_string(&call).unwrap(), line);
        assert_eq!(serde_json::from_str::<Request>(line).unwrap(), call);
        let reordered = r#"{"op":"echo","source":"echo","v":1,"kind":"call"}"#;
        assert_eq!(serde_json::from_str::<Request>(reordered).unwrap(), Request::Call { v: 1, source: "echo".into(), op: "echo".into(), params: serde_json::Value::Null, max_bytes: None, deadline_ms: None });
        let result = Answer::Result { v: 1, request_id: "0199a1b2-0000-7000-8000-00000000000a".into(), content_type: "application/json".into(), truncated: false, bytes: 7, limit: 65_536, body: Body::Json(serde_json::json!({"x": 1})) };
        let line = r#"{"kind":"result","v":1,"request_id":"0199a1b2-0000-7000-8000-00000000000a","content_type":"application/json","truncated":false,"bytes":7,"limit":65536,"json":{"x":1}}"#;
        assert_eq!(serde_json::to_string(&result).unwrap(), line);
        assert_eq!(serde_json::from_str::<Answer>(line).unwrap(), result);
        for body in [Body::Text("a\nb".into()), Body::B64("AAE=".into())] {
            let a = Answer::Result { v: 1, request_id: "r".into(), content_type: "text/plain".into(), truncated: true, bytes: 3, limit: 3, body };
            assert_eq!(serde_json::from_str::<Answer>(&serde_json::to_string(&a).unwrap()).unwrap(), a);
        }
        let refused = Answer::error(Code::ForbiddenPeer, "not a process of this session");
        let line = r#"{"kind":"error","v":1,"code":"forbidden_peer","message":"not a process of this session"}"#;
        assert_eq!(serde_json::to_string(&refused).unwrap(), line);
        assert_eq!(serde_json::from_str::<Answer>(line).unwrap(), refused);
        let entry = SourceEntry {
            name: "echo".into(),
            version: "0.1.0".into(),
            description: "Echo its parameters".into(),
            kind: "other".into(),
            env: "test".into(),
            sensitivity: "internal".into(),
            available: true,
            last_seen_unix_ms: 1_761_730_000_000,
            ops: vec![OpEntry {
                name: "echo".into(),
                description: "Return params".into(),
                params_schema: serde_json::json!({"type": "object"}),
                output: "json".into(),
                read_only: true,
                default_limits: LimitsEntry { max_bytes: 65_536, max_rows: 0, max_chunks: 0 },
                max_limits: LimitsEntry { max_bytes: 1_048_576, max_rows: 0, max_chunks: 0 },
                examples: vec![serde_json::json!({"x": 1})],
            }],
        };
        let answer = Answer::Catalog { v: 1, sources: vec![entry], truncated: false };
        let line = r#"{"kind":"catalog","v":1,"sources":[{"name":"echo","version":"0.1.0","description":"Echo its parameters","kind":"other","env":"test","sensitivity":"internal","available":true,"last_seen_unix_ms":1761730000000,"ops":[{"name":"echo","description":"Return params","params_schema":{"type":"object"},"output":"json","read_only":true,"default_limits":{"max_bytes":65536,"max_rows":0,"max_chunks":0},"max_limits":{"max_bytes":1048576,"max_rows":0,"max_chunks":0},"examples":[{"x":1}]}]}],"truncated":false}"#;
        assert_eq!(serde_json::to_string(&answer).unwrap(), line);
        assert_eq!(serde_json::from_str::<Answer>(line).unwrap(), answer);
        assert_eq!(socket_path(Path::new(SOCKET_DIR), 42), PathBuf::from("/run/ai-env/relay/42.sock"));
    }
}
