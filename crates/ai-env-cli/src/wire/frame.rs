//! Versioned frames on the `/agent` WebSocket (`{"v":1,"t":"<kind>",…}`), the
//! run-hook payload, and the `/health` document. One `Frame ⇄ Message`
//! conversion serves both the Mac client and the VM server.
use crate::wire::redact::Secret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

pub const WIRE_VERSION: u8 = 1;

/// uuidv7 text; validated by the shim in a later stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpawnId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePoint {
    pub spawn_id: SpawnId,
    pub from_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnStatus {
    pub spawn_id: SpawnId,
    pub pid: u32,
    pub alive: bool,
    pub last_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloErrCode {
    BadToken,
    Gap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Sig {
    Int,
    Term,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deliver {
    Fd,
    Env,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    HookResume,
    HookSuspend,
    HookTerminate,
    WipRef,
}

/// Every frame kind, tagged by `t`. `line` fields carry one raw NDJSON line
/// (without `\n`) opaque: the wire layer never parses or re-serialises it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    Hello {
        session_token: Secret<String>,
        client: ClientInfo,
        #[serde(default)]
        resume: Vec<ResumePoint>,
    },
    HelloOk {
        shim_version: String,
        claude_version: Option<String>,
        microvm_id: String,
        image_version: String,
        has_credentials: bool,
        boot_nonce: String,
        owner: String,
        spawns: Vec<SpawnStatus>,
        uptime_s: u64,
        run_hook_seen: bool,
    },
    HelloErr {
        code: HelloErrCode,
        message: String,
    },
    Spawn {
        spawn_id: SpawnId,
        argv: Vec<String>,
        cwd: String,
        env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        secrets: BTreeMap<String, Secret<String>>,
        deliver_secret: Deliver,
    },
    Spawned {
        spawn_id: SpawnId,
        pid: u32,
        pgid: u32,
        claude_version: String,
    },
    SpawnErr {
        spawn_id: SpawnId,
        code: String,
        message: String,
    },
    Stdin {
        spawn_id: SpawnId,
        seq: u64,
        line: String,
    },
    StdinEof {
        spawn_id: SpawnId,
    },
    Signal {
        spawn_id: SpawnId,
        sig: Sig,
        scope: Scope,
    },
    Ack {
        spawn_id: SpawnId,
        seq: u64,
    },
    Ping {
        ts: u64,
    },
    Pong {
        ts: u64,
    },
    Stdout {
        spawn_id: SpawnId,
        seq: u64,
        line: String,
    },
    Stderr {
        spawn_id: SpawnId,
        seq: u64,
        text: String,
        dropped: u64,
    },
    Exit {
        spawn_id: SpawnId,
        seq: u64,
        code: Option<i32>,
        signal: Option<i32>,
        stderr_dropped: u64,
    },
    Event {
        kind: EventKind,
        at: String,
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
        reference: Option<String>,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Serialize)]
struct EnvelopeOut<'a> {
    v: u8,
    #[serde(flatten)]
    frame: &'a Frame,
}

#[derive(Deserialize)]
struct EnvelopeIn {
    v: u8,
    #[serde(flatten)]
    frame: Frame,
}

#[derive(Debug)]
pub enum WireError {
    Json(serde_json::Error),
    Version(u8),
    BinaryFrame,
    NotData(&'static str),
    LineTooLong(usize),
    PayloadTooLarge(usize),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Json(e) => write!(f, "bad frame: {e}"),
            WireError::Version(v) => write!(f, "unsupported wire version {v}"),
            WireError::BinaryFrame => f.write_str("binary frames are not accepted on /agent"),
            WireError::NotData(k) => write!(f, "{k} frame carries no data"),
            WireError::LineTooLong(n) => write!(f, "line of {n} bytes exceeds the cap"),
            WireError::PayloadTooLarge(n) => write!(f, "run-hook payload of {n} bytes exceeds 4096"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<serde_json::Error> for WireError {
    fn from(e: serde_json::Error) -> Self {
        WireError::Json(e)
    }
}

impl Frame {
    /// The `t` tag.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Frame::Hello { .. } => "hello",
            Frame::HelloOk { .. } => "hello_ok",
            Frame::HelloErr { .. } => "hello_err",
            Frame::Spawn { .. } => "spawn",
            Frame::Spawned { .. } => "spawned",
            Frame::SpawnErr { .. } => "spawn_err",
            Frame::Stdin { .. } => "stdin",
            Frame::StdinEof { .. } => "stdin_eof",
            Frame::Signal { .. } => "signal",
            Frame::Ack { .. } => "ack",
            Frame::Ping { .. } => "ping",
            Frame::Pong { .. } => "pong",
            Frame::Stdout { .. } => "stdout",
            Frame::Stderr { .. } => "stderr",
            Frame::Exit { .. } => "exit",
            Frame::Event { .. } => "event",
            Frame::Error { .. } => "error",
        }
    }

    /// One JSON object with `v` first, then `t`, then the fields.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&EnvelopeOut { v: WIRE_VERSION, frame: self }).expect("frame types always serialise")
    }

    pub fn from_json(text: &str) -> Result<Frame, WireError> {
        let env: EnvelopeIn = serde_json::from_str(text)?;
        if env.v != WIRE_VERSION {
            return Err(WireError::Version(env.v));
        }
        Ok(env.frame)
    }

    /// The error frame sent when a stdio line exceeds the cap; the socket stays up.
    #[must_use]
    pub fn line_too_long(len: usize) -> Frame {
        Frame::Error { code: "line_too_long".into(), message: format!("line of {len} bytes exceeds the 4 MiB cap") }
    }
}

impl TryFrom<Message> for Frame {
    type Error = WireError;

    fn try_from(msg: Message) -> Result<Self, WireError> {
        match msg {
            Message::Text(t) => Frame::from_json(t.as_str()),
            Message::Binary(_) => Err(WireError::BinaryFrame),
            Message::Ping(_) => Err(WireError::NotData("ping")),
            Message::Pong(_) => Err(WireError::NotData("pong")),
            Message::Close(_) => Err(WireError::NotData("close")),
            Message::Frame(_) => Err(WireError::NotData("frame")),
        }
    }
}

impl From<&Frame> for Message {
    fn from(frame: &Frame) -> Message {
        Message::Text(Utf8Bytes::from(frame.to_json()))
    }
}

// ---- run-hook payload ---------------------------------------------------------

/// `hex(sha256(token))` — what rides `run_hook_payload` instead of the token.
#[must_use]
pub fn commitment_hex(token: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token))
}

/// The ≤4096-byte payload handed to the VM's `/run` hook: a commitment to the
/// session token plus ownership metadata. Never the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunHookPayload {
    pub v: u8,
    pub commit: String,
    pub owner: String,
    pub created: String,
}

impl RunHookPayload {
    pub const MAX_BYTES: usize = 4096;

    #[must_use]
    pub fn new(token: &Secret<String>, owner: &str, created_rfc3339: &str) -> Self {
        RunHookPayload {
            v: WIRE_VERSION,
            commit: commitment_hex(token.expose().as_bytes()),
            owner: owner.to_string(),
            created: created_rfc3339.to_string(),
        }
    }

    pub fn to_json(&self) -> Result<String, WireError> {
        let s = serde_json::to_string(self)?;
        if s.len() > Self::MAX_BYTES {
            return Err(WireError::PayloadTooLarge(s.len()));
        }
        Ok(s)
    }

    /// Constant-time check of a presented token against the commitment.
    #[must_use]
    pub fn matches(&self, token: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let Ok(want) = hex::decode(&self.commit) else {
            return false;
        };
        use sha2::{Digest, Sha256};
        let got = Sha256::digest(token);
        want.len() == got.len() && bool::from(want.as_slice().ct_eq(got.as_slice()))
    }
}

// ---- health -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
    Booting,
    Draining,
}

/// `GET /health` on the shim's app port (public summary; no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub status: HealthStatus,
    pub shim_version: String,
    pub claude_version: Option<String>,
    pub microvm_id: Option<String>,
    pub owner: Option<String>,
    pub created: Option<String>,
    pub boot_nonce: Option<String>,
    pub run_hook_seen: bool,
    pub uptime_s: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192";

    fn sid() -> SpawnId {
        SpawnId(SID.to_string())
    }

    fn every_variant() -> Vec<Frame> {
        vec![
            Frame::Hello {
                session_token: Secret::new("fake-session-token".into()),
                client: ClientInfo { name: "ai-env-claude".into(), version: "0.1.0".into(), host: "mike@mbp".into() },
                resume: vec![ResumePoint { spawn_id: sid(), from_seq: 42 }],
            },
            Frame::HelloOk {
                shim_version: "0.1.0".into(),
                claude_version: Some("2.1.278".into()),
                microvm_id: "mvm-1".into(),
                image_version: "3".into(),
                has_credentials: false,
                boot_nonce: "n".into(),
                owner: "mike@mbp".into(),
                spawns: vec![SpawnStatus { spawn_id: sid(), pid: 42, alive: true, last_seq: 7, exit: None }],
                uptime_s: 12,
                run_hook_seen: true,
            },
            Frame::HelloErr { code: HelloErrCode::BadToken, message: "no".into() },
            Frame::Spawn {
                spawn_id: sid(),
                argv: vec!["--output-format".into(), "stream-json".into()],
                cwd: "/Users/mike/Documents/DeFi/ai-env".into(),
                env: BTreeMap::from([("HOME".to_string(), "/Users/mike".to_string())]),
                secrets: BTreeMap::from([("CLAUDE_CODE_OAUTH_TOKEN".to_string(), Secret::new("tok".to_string()))]),
                deliver_secret: Deliver::Fd,
            },
            Frame::Spawned { spawn_id: sid(), pid: 42, pgid: 42, claude_version: "2.1.278".into() },
            Frame::SpawnErr { spawn_id: sid(), code: "exec".into(), message: "boom".into() },
            Frame::Stdin { spawn_id: sid(), seq: 1, line: "{\"type\":\"user\"}".into() },
            Frame::StdinEof { spawn_id: sid() },
            Frame::Signal { spawn_id: sid(), sig: Sig::Term, scope: Scope::Group },
            Frame::Ack { spawn_id: sid(), seq: 9 },
            Frame::Ping { ts: 1 },
            Frame::Pong { ts: 1 },
            Frame::Stdout { spawn_id: sid(), seq: 7, line: "{}".into() },
            Frame::Stderr { spawn_id: sid(), seq: 2, text: "warn".into(), dropped: 0 },
            Frame::Exit { spawn_id: sid(), seq: 8, code: Some(0), signal: None, stderr_dropped: 0 },
            Frame::Event { kind: EventKind::WipRef, at: "2026-09-19T08:00:00Z".into(), reference: Some("refs/wip/1".into()) },
            Frame::Error { code: "line_too_long".into(), message: "x".into() },
        ]
    }

    #[test]
    fn roundtrip_every_variant() {
        let all = every_variant();
        assert_eq!(all.len(), 17);
        for f in all {
            let json = f.to_json();
            assert!(json.starts_with("{\"v\":1,\"t\":\""), "{json}");
            assert!(json.contains(&format!("\"t\":\"{}\"", f.kind())), "{json}");
            let back = Frame::from_json(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(back, f);
        }
    }

    #[test]
    fn json_shape_hello() {
        let f = &every_variant()[0];
        assert_eq!(
            f.to_json(),
            format!("{{\"v\":1,\"t\":\"hello\",\"session_token\":\"fake-session-token\",\"client\":{{\"name\":\"ai-env-claude\",\"version\":\"0.1.0\",\"host\":\"mike@mbp\"}},\"resume\":[{{\"spawn_id\":\"{SID}\",\"from_seq\":42}}]}}")
        );
    }

    #[test]
    fn json_shape_stdout() {
        let f = Frame::Stdout {
            spawn_id: sid(),
            seq: 7,
            line: "{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"4be70170-9fbc-47cc-bdda-17290d02e122\"}".into(),
        };
        assert_eq!(
            f.to_json(),
            format!("{{\"v\":1,\"t\":\"stdout\",\"spawn_id\":\"{SID}\",\"seq\":7,\"line\":\"{{\\\"type\\\":\\\"system\\\",\\\"subtype\\\":\\\"init\\\",\\\"session_id\\\":\\\"4be70170-9fbc-47cc-bdda-17290d02e122\\\"}}\"}}")
        );
    }

    #[test]
    fn json_shape_exit() {
        let f = Frame::Exit { spawn_id: sid(), seq: 8, code: Some(0), signal: None, stderr_dropped: 0 };
        assert_eq!(f.to_json(), format!("{{\"v\":1,\"t\":\"exit\",\"spawn_id\":\"{SID}\",\"seq\":8,\"code\":0,\"signal\":null,\"stderr_dropped\":0}}"));
    }

    #[test]
    fn rejects_v2() {
        let e = Frame::from_json("{\"v\":2,\"t\":\"ping\",\"ts\":1}").unwrap_err();
        assert!(matches!(e, WireError::Version(2)), "{e}");
    }

    #[test]
    fn rejects_unknown_t() {
        assert!(matches!(Frame::from_json("{\"v\":1,\"t\":\"nope\"}"), Err(WireError::Json(_))));
    }

    #[test]
    fn ignores_unknown_fields() {
        let f = Frame::from_json("{\"v\":1,\"t\":\"ping\",\"ts\":5,\"extra\":true}").unwrap();
        assert_eq!(f, Frame::Ping { ts: 5 });
    }

    #[test]
    fn message_binary_rejected() {
        let r = Frame::try_from(Message::Binary(vec![1u8, 2].into()));
        assert!(matches!(r, Err(WireError::BinaryFrame)));
    }

    #[test]
    fn message_ping_not_data() {
        assert!(matches!(Frame::try_from(Message::Ping(vec![].into())), Err(WireError::NotData("ping"))));
        assert!(matches!(Frame::try_from(Message::Close(None)), Err(WireError::NotData("close"))));
    }

    #[test]
    fn message_text_roundtrip() {
        let f = Frame::Ack { spawn_id: sid(), seq: 3 };
        let m = Message::from(&f);
        assert!(m.is_text());
        assert_eq!(Frame::try_from(m).unwrap(), f);
    }

    #[test]
    fn run_hook_payload_shape() {
        let p = RunHookPayload::new(&Secret::new("test-token".into()), "mike@mbp", "2026-09-19T08:00:00Z");
        assert_eq!(
            p.to_json().unwrap(),
            // sha256("test-token") — public known-answer, not a credential.
            "{\"v\":1,\"commit\":\"4c5dc9b7708905f77f5e5d16316b5dfb425e68cb326dcd55a860e90a7707031e\",\"owner\":\"mike@mbp\",\"created\":\"2026-09-19T08:00:00Z\"}"
        );
        let back: RunHookPayload = serde_json::from_str(&p.to_json().unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn run_hook_payload_cap_4096() {
        let p = RunHookPayload::new(&Secret::new("t".into()), &"o".repeat(4100), "2026-09-19T08:00:00Z");
        assert!(matches!(p.to_json(), Err(WireError::PayloadTooLarge(_))));
    }

    #[test]
    fn commitment_matches_and_rejects() {
        let p = RunHookPayload::new(&Secret::new("test-token".into()), "o", "c");
        assert!(p.matches(b"test-token"));
        assert!(!p.matches(b"test-token2"));
        let bad = RunHookPayload { commit: "zz".into(), ..p };
        assert!(!bad.matches(b"test-token"));
    }

    #[test]
    fn health_roundtrip() {
        let h = Health {
            status: HealthStatus::Ok,
            shim_version: "0.1.0".into(),
            claude_version: None,
            microvm_id: None,
            owner: None,
            created: None,
            boot_nonce: None,
            run_hook_seen: false,
            uptime_s: 3,
        };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.starts_with("{\"status\":\"ok\",\"shim_version\":\"0.1.0\""), "{s}");
        assert_eq!(serde_json::from_str::<Health>(&s).unwrap(), h);
    }
}
