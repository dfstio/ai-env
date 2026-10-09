//! Wire v1 of the `/agent` WebSocket (`{"v":1,"t":"<kind>",…}`), the run-hook
//! payload, and the `/health` documents. One `Frame ⇄ Message` conversion
//! serves both the Mac client and the VM server.
//!
//! Stdio crosses as raw byte chunks of at most [`CHUNK_MAX`] bytes ([`Chunk`]:
//! `text` when valid UTF-8, else `b64`; `wire::chunk` splits and joins them):
//! no lines on the wire, so `vm exec` is byte-exact and a line of any length
//! crosses (`vm exec` writes the bytes as they come; S8's remote pump will
//! re-split at the CLI's 256 MiB). Flow control is a credit window per
//! direction (`ack` / `stdin_ack`); nothing is ever dropped but stderr beyond
//! its 2 MiB buffer (counted in `dropped`). Plan: S6 (D2, D3).
use crate::wire::redact::Secret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

pub const WIRE_VERSION: u8 = 1;

// ---- sizes, windows and timers (both ends) ---------------------------------------------

/// Largest raw stdio chunk (before text/b64 encoding). An encoded frame is at
/// most about 6 × this plus the envelope (JSON escaping of control bytes).
pub const CHUNK_MAX: usize = 64 * 1024;
/// tungstenite `max_message_size` and `max_frame_size` on both ends (a safety
/// net: no v1 frame comes near it). A larger message closes the socket with 1009.
pub const WS_MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// tungstenite `max_write_buffer_size` on both ends.
pub const WS_MAX_WRITE_BUFFER: usize = 32 * 1024 * 1024;
/// Largest non-data frame (a `spawn` with its argv and env).
pub const CONTROL_FRAME_MAX: usize = 4 * 1024 * 1024;
/// Largest argv of one `spawn`, all arguments together.
pub const ARGV_MAX_BYTES: usize = 1024 * 1024;
/// Most environment entries one `spawn` may set.
pub const ENV_MAX_ENTRIES: usize = 256;
/// Live spawns per VM.
pub const MAX_SPAWNS: usize = 8;
/// Sockets that have not completed `hello` at one time; the next upgrade gets 503 `busy`.
pub const MAX_UNAUTHENTICATED: usize = 8;
/// The `hello` must arrive this soon after the 101 (else Close 4408).
pub const HELLO_DEADLINE: Duration = Duration::from_secs(10);
/// stdout credit window per spawn: unacked bytes / unacked chunks.
pub const STDOUT_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
pub const STDOUT_WINDOW_CHUNKS: u64 = 20_000;
/// stderr buffer per spawn (drop-oldest beyond it).
pub const STDERR_BUFFER_BYTES: u64 = 2 * 1024 * 1024;
/// stdin credit window per spawn (unacked bytes the shim holds).
pub const STDIN_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
/// Both ends acknowledge at least this often (bytes or time, whichever first).
pub const ACK_EVERY_BYTES: u64 = 1024 * 1024;
pub const ACK_EVERY: Duration = Duration::from_millis(250);
/// The Mac's app-level `ping` and WebSocket Ping while a spawn is attached and unfinished.
pub const PING_EVERY: Duration = Duration::from_secs(20);
pub const WS_PING_EVERY: Duration = Duration::from_secs(30);
/// The Mac declares a socket dead after this long without any inbound frame.
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
/// `hello.idle_s`: the shim closes a socket after this long without any inbound frame.
pub const IDLE_DEFAULT_S: u32 = 90;
pub const IDLE_MIN_S: u32 = 30;
pub const IDLE_MAX_S: u32 = 3600;
/// Default `detach_grace_s`: a detached spawn lives this long before TERM.
pub const DETACH_GRACE_EXEC_S: u32 = 60;
pub const DETACH_GRACE_SESSION_S: u32 = 900;
/// The S2 D22 ladder, run by the shim after `detach {final: true}`: TERM, then KILL.
pub const LADDER_TERM_AFTER: Duration = Duration::from_millis(800);
pub const LADDER_KILL_AFTER: Duration = Duration::from_millis(1200);
/// After the leader of a spawn exits, its group gets TERM, then KILL this much later.
pub const GROUP_KILL_AFTER: Duration = Duration::from_secs(1);
/// Each frame send times out after this (both ends).
pub const SEND_TIMEOUT: Duration = Duration::from_secs(60);

// ---- capabilities (S7) ----------------------------------------------------------------

/// The capability a shim names in `hello_ok.caps` (and `/health`) when it
/// holds a delivered credential in its one-slot cache and spawns from it. The
/// Mac sends a `credential` frame, or a `spawn` naming one, only to a shim that
/// names this: an older shim would answer `credential` with `unknown_frame`
/// after the secret had crossed, and would run a credentialed spawn without it.
/// Rule for later changes: anything the receiver must act on is gated by a cap;
/// a field it may ignore is not.
pub const CAP_CREDENTIAL_CACHE: &str = "credential_cache";

/// Longest `credential.tag` (an opaque, non-secret seal id the Mac chooses:
/// `[A-Za-z0-9-]`).
pub const CREDENTIAL_TAG_MAX: usize = 64;

// ---- close codes ---------------------------------------------------------------------

pub const CLOSE_NORMAL: u16 = 1000;
/// Drain, suspend, terminate, idle.
pub const CLOSE_GOING_AWAY: u16 = 1001;
pub const CLOSE_PROTOCOL: u16 = 1008;
pub const CLOSE_TOO_BIG: u16 = 1009;
pub const CLOSE_INTERNAL: u16 = 1011;
/// `hello_err busy`.
pub const CLOSE_TRY_AGAIN: u16 = 1013;
/// `hello_err bad_token` / `no_commitment`.
pub const CLOSE_HELLO_REFUSED: u16 = 4403;
pub const CLOSE_HELLO_DEADLINE: u16 = 4408;
/// `hello_err version`.
pub const CLOSE_WIRE_VERSION: u16 = 4426;

// ---- field types ---------------------------------------------------------------------

/// uuid v7 text (the shim refuses anything else).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpawnId(pub String);

impl SpawnId {
    /// A fresh uuid v7.
    #[must_use]
    pub fn new_v7() -> SpawnId {
        SpawnId(uuid::Uuid::now_v7().to_string())
    }

    /// Is this the hyphenated lowercase form of a uuid v7?
    #[must_use]
    pub fn is_v7(&self) -> bool {
        uuid::Uuid::try_parse(&self.0).is_ok_and(|u| u.get_version_num() == 7 && u.hyphenated().to_string() == self.0)
    }
}

impl std::fmt::Display for SpawnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
    pub host: String,
}

/// One spawn a `hello` reattaches to. `from_seq` absent = the oldest stdout
/// chunk the shim retains; `err_from_seq` likewise for stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePoint {
    pub spawn_id: SpawnId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err_from_seq: Option<u64>,
}

/// How a spawn ended: `code` for a normal exit, `signal` for a kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

/// One spawn as `hello_ok` and `/health/detail` report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnStatus {
    pub spawn_id: SpawnId,
    /// The basename of argv[0].
    pub argv0: String,
    pub pid: u32,
    pub pgid: u32,
    pub alive: bool,
    /// Attached to a socket other than the one this status is sent on.
    pub attached: bool,
    /// The last stdout seq produced (0 = none yet).
    pub out_seq: u64,
    /// The oldest stdout seq still retained (out_seq + 1 when none is).
    pub out_from: u64,
    /// The last stderr seq produced.
    pub err_seq: u64,
    /// The highest stdin seq the shim holds (written or queued); the Mac resends above it.
    pub in_seq: u64,
    pub stdin_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeStatus {
    /// Replay follows from the asked seq.
    Ok,
    /// The asked seq is older than the oldest retained chunk.
    Gap,
    /// No such spawn (never existed, or released).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resumed {
    pub spawn_id: SpawnId,
    pub status: ResumeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloErrCode {
    /// The token does not match the `/run` commitment. Close 4403.
    BadToken,
    /// `/run` arrived without a payload (fail-closed): no hello can ever pass. Close 4403.
    NoCommitment,
    /// An unsupported wire version. Close 4426.
    Version,
    /// Too many sockets. Close 1013.
    Busy,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnErrCode {
    BadRequest,
    /// The spawn id was already used on this VM: spawn ids are single-use,
    /// live or released (a re-sent `spawn` never runs twice).
    Exists,
    /// [`MAX_SPAWNS`] reached.
    Limit,
    /// The working directory could not be created or entered.
    Cwd,
    /// The program does not exist (not on the child PATH, or ENOENT at exec).
    NotFound,
    /// The program exists but could not be started (not executable, a bad interpreter).
    Exec,
    Draining,
    /// `spawn.credential` names a credential the shim's cache does not hold
    /// (never delivered, or wiped by a suspend since) (S7).
    NoCredential,
    #[serde(other)]
    Other,
}

/// Why the shim refused a `credential` frame (S7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrCode {
    /// A malformed name, an empty, oversized or NUL-bearing value, a bad tag.
    BadRequest,
    /// The shim is stopping.
    Draining,
    /// A `/suspend` is under way or done: nothing is cached until `/resume`.
    Suspended,
    #[serde(other)]
    Other,
}

/// What the shim's credential cache shows (S7), in `hello_ok` and
/// `/health/detail`: the name and tag of the copy it holds — never the value —
/// when it was cached, and how many live spawns were handed a secret. Every
/// field is left out when empty, so an exchange without credentials is
/// byte-identical to S6's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_tag: Option<String>,
    /// RFC 3339 UTC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_at: Option<String>,
    /// Live spawns that were handed a secret (cached or one-shot): their
    /// memory, and any snapshot taken while they live, still holds it.
    #[serde(skip_serializing_if = "is_zero")]
    pub credential_holders: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A binary message; the socket stays up.
    BinaryRejected,
    /// Malformed JSON or a frame that breaks the schema; Close 1008 follows.
    BadFrame,
    /// An unknown `t`; ignored.
    UnknownFrame,
    /// A spawn frame for a spawn not attached to this socket.
    NotAttached,
    /// A newer socket attached this spawn.
    Superseded,
    /// More stdin than the window; Close 1008 follows.
    StdinOverflow,
    /// A stdin seq that skips ahead; Close 1008 follows.
    StdinGap,
    Draining,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Sig {
    Int,
    Term,
    Kill,
    Hup,
}

impl Sig {
    /// The Linux/macOS signal number.
    #[must_use]
    pub fn number(self) -> i32 {
        match self {
            Sig::Int => libc::SIGINT,
            Sig::Term => libc::SIGTERM,
            Sig::Kill => libc::SIGKILL,
            Sig::Hup => libc::SIGHUP,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Group,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deliver {
    /// A pipe on fd 3, and `<NAME>_FILE_DESCRIPTOR=3` in the child's environment.
    #[default]
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
    #[serde(other)]
    Other,
}

/// One raw stdio chunk: exactly one of `text` (valid UTF-8) or `b64`
/// (standard base64), at most [`CHUNK_MAX`] bytes decoded. Built and read by
/// `wire::chunk`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b64: Option<String>,
}

impl std::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.text, &self.b64) {
            (Some(t), None) => write!(f, "Chunk(text, {} bytes)", t.len()),
            (None, Some(b)) => write!(f, "Chunk(b64, {} chars)", b.len()),
            _ => f.write_str("Chunk(malformed)"),
        }
    }
}

/// Every frame kind, tagged by `t`. `Debug` is written by hand: kind, spawn
/// id, seq and sizes only — never data, argv beyond argv[0], environment
/// values, secrets or the session token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    /// Mac → VM, the first frame (within [`HELLO_DEADLINE`] of the 101).
    Hello {
        session_token: Secret<String>,
        client: ClientInfo,
        #[serde(default)]
        resume: Vec<ResumePoint>,
        /// [`IDLE_MIN_S`]..=[`IDLE_MAX_S`]; default [`IDLE_DEFAULT_S`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_s: Option<u32>,
    },
    HelloOk {
        wire: u8,
        shim_version: String,
        claude_version: Option<String>,
        microvm_id: Option<String>,
        image_version: Option<String>,
        boot_nonce: String,
        owner: Option<String>,
        /// The shim's cache holds a deliverable copy right now (S7; false after any suspend).
        has_credentials: bool,
        uptime_s: u64,
        run_hook_seen: bool,
        spawns: Vec<SpawnStatus>,
        /// One per `hello.resume` entry; replay follows for every `ok`.
        resumed: Vec<Resumed>,
        /// What this shim can do beyond wire v1's core ([`CAP_CREDENTIAL_CACHE`]); absent from an S6 shim.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        caps: Vec<String>,
        #[serde(flatten)]
        credential: CredentialView,
    },
    HelloErr {
        code: HelloErrCode,
        message: String,
    },
    /// Mac → VM: start a process (attached to this socket).
    Spawn {
        spawn_id: SpawnId,
        argv: Vec<String>,
        /// Absolute; created and entered as the agent uid; default `--home`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        secrets: BTreeMap<String, Secret<String>>,
        #[serde(default)]
        deliver_secret: Deliver,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detach_grace_s: Option<u32>,
        /// The name of a credential the shim's cache holds, delivered to this
        /// spawn per `deliver_secret` (S7). Never together with `secrets`. Only
        /// the name rides here, so a re-sent `spawn` that names the cached
        /// credential never carries its value (a `--credential-file` spawn
        /// carries its secret in `secrets`, re-sends included).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential: Option<String>,
    },
    Spawned {
        spawn_id: SpawnId,
        pid: u32,
        pgid: u32,
        /// Only when argv[0] is `claude`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claude_version: Option<String>,
    },
    SpawnErr {
        spawn_id: SpawnId,
        code: SpawnErrCode,
        message: String,
    },
    /// Mac → VM; `seq` from 1, deduped at or below the shim's `in_seq`.
    Stdin {
        spawn_id: SpawnId,
        seq: u64,
        #[serde(flatten)]
        data: Chunk,
    },
    /// Mac → VM: the pipe closes once stdin up to `seq` is written (0 = none was sent).
    StdinEof {
        spawn_id: SpawnId,
        seq: u64,
    },
    /// VM → Mac: stdin up to `seq` is written to the pipe (window credit).
    StdinAck {
        spawn_id: SpawnId,
        seq: u64,
    },
    Signal {
        spawn_id: SpawnId,
        sig: Sig,
        scope: Scope,
    },
    /// Mac → VM: a deliberate end of this attachment. `final: true` runs the
    /// D22 ladder at once (TERM +0.8 s, KILL +1.2 s); `false` starts the
    /// spawn's detach grace now. A socket that ends without it is a lost
    /// socket: the grace applies, whatever the stdin state.
    Detach {
        spawn_id: SpawnId,
        #[serde(rename = "final")]
        is_final: bool,
    },
    Stdout {
        spawn_id: SpawnId,
        seq: u64,
        #[serde(flatten)]
        data: Chunk,
    },
    Stderr {
        spawn_id: SpawnId,
        seq: u64,
        #[serde(flatten)]
        data: Chunk,
        /// Cumulative stderr bytes dropped so far (drop-oldest) before they
        /// were sent; a chunk that was sent is the Mac's to deliver or count.
        dropped: u64,
    },
    /// Mac → VM: stdout up to `seq` and stderr up to `err_seq` are consumed
    /// (trims the window); acking the exit's `seq` releases the spawn.
    Ack {
        spawn_id: SpawnId,
        seq: u64,
        err_seq: u64,
    },
    /// VM → Mac, after every earlier stdout and stderr chunk was sent:
    /// `seq` = the last stdout seq + 1.
    Exit {
        spawn_id: SpawnId,
        seq: u64,
        code: Option<i32>,
        signal: Option<i32>,
        stderr_dropped: u64,
        /// stdout bytes were left unread (an escaper held the pipe past the drain bound).
        #[serde(default)]
        stdout_truncated: bool,
    },
    /// Mac → VM; the shim never pings.
    Ping {
        ts: u64,
    },
    Pong {
        ts: u64,
    },
    Event {
        kind: EventKind,
        at: String,
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
        reference: Option<String>,
    },
    Error {
        code: ErrorCode,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        spawn_id: Option<SpawnId>,
    },
    /// Mac → VM (S7): put one credential in the shim's one-slot cache, for
    /// spawns that name it. Sent only to a shim with [`CAP_CREDENTIAL_CACHE`],
    /// on its own frame so it is never part of a `spawn` the session re-sends.
    Credential {
        name: String,
        secret: Secret<String>,
        /// An opaque, non-secret seal id, so the Mac can tell a cached copy of
        /// the token it holds now from one of a token it has since replaced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<String>,
    },
    /// VM → Mac: the `credential` is cached (`cached: true`), or a
    /// `credential_forget` dropped it (`false`).
    CredentialOk {
        name: String,
        cached: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<String>,
    },
    CredentialErr {
        name: String,
        code: CredentialErrCode,
        message: String,
    },
    /// Mac → VM: drop the cached credential (`name` absent: whatever is cached).
    CredentialForget {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = self.kind();
        match self {
            Frame::Hello { client, resume, idle_s, .. } => write!(f, "{kind}(client={} {}, resume={}, idle_s={idle_s:?})", client.name, client.version, resume.len()),
            Frame::HelloOk { wire, spawns, resumed, run_hook_seen, .. } => write!(f, "{kind}(wire={wire}, spawns={}, resumed={}, run_hook_seen={run_hook_seen})", spawns.len(), resumed.len()),
            Frame::HelloErr { code, .. } => write!(f, "{kind}({code:?})"),
            Frame::Spawn { spawn_id, argv, env, secrets, deliver_secret, credential, .. } => {
                let argv0 = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a)).unwrap_or("");
                write!(f, "{kind}({spawn_id}, argv0={argv0}, argc={}, env={}, secrets={}, deliver={deliver_secret:?}, credential={credential:?})", argv.len(), env.len(), secrets.len())
            }
            Frame::Spawned { spawn_id, pid, pgid, .. } => write!(f, "{kind}({spawn_id}, pid={pid}, pgid={pgid})"),
            Frame::SpawnErr { spawn_id, code, .. } => write!(f, "{kind}({spawn_id}, {code:?})"),
            Frame::Stdin { spawn_id, seq, data } | Frame::Stdout { spawn_id, seq, data } => write!(f, "{kind}({spawn_id}, seq={seq}, {data:?})"),
            Frame::Stderr { spawn_id, seq, data, dropped } => write!(f, "{kind}({spawn_id}, seq={seq}, {data:?}, dropped={dropped})"),
            Frame::StdinEof { spawn_id, seq } | Frame::StdinAck { spawn_id, seq } => write!(f, "{kind}({spawn_id}, seq={seq})"),
            Frame::Signal { spawn_id, sig, .. } => write!(f, "{kind}({spawn_id}, {sig:?})"),
            Frame::Detach { spawn_id, is_final } => write!(f, "{kind}({spawn_id}, final={is_final})"),
            Frame::Ack { spawn_id, seq, err_seq } => write!(f, "{kind}({spawn_id}, seq={seq}, err_seq={err_seq})"),
            Frame::Exit { spawn_id, seq, code, signal, stderr_dropped, stdout_truncated } => {
                write!(f, "{kind}({spawn_id}, seq={seq}, code={code:?}, signal={signal:?}, stderr_dropped={stderr_dropped}, stdout_truncated={stdout_truncated})")
            }
            Frame::Ping { ts } | Frame::Pong { ts } => write!(f, "{kind}({ts})"),
            Frame::Event { kind: k, .. } => write!(f, "{kind}({k:?})"),
            Frame::Error { code, spawn_id, .. } => write!(f, "{kind}({code:?}, spawn={})", spawn_id.as_ref().map_or("-", |s| s.0.as_str())),
            // The name and the length, never the value.
            Frame::Credential { name, secret, tag } => write!(f, "{kind}({name}, {} bytes, tag={tag:?})", secret.expose().len()),
            Frame::CredentialOk { name, cached, tag } => write!(f, "{kind}({name}, cached={cached}, tag={tag:?})"),
            Frame::CredentialErr { name, code, .. } => write!(f, "{kind}({name}, {code:?})"),
            Frame::CredentialForget { name } => write!(f, "{kind}({name:?})"),
        }
    }
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

/// Only the version and kind of a frame, read first so an unknown `t` and an
/// unknown `v` are told apart from malformed JSON.
#[derive(Deserialize)]
struct Peek {
    v: u8,
    t: String,
}

#[derive(Debug)]
pub enum WireError {
    Json(serde_json::Error),
    Version(u8),
    /// A well-formed v1 frame of a kind this build does not know (`error unknown_frame`; ignored).
    UnknownKind(String),
    BinaryFrame,
    NotData(&'static str),
    /// A chunk without exactly one of `text`/`b64`, bad base64, or larger than [`CHUNK_MAX`].
    BadChunk(&'static str),
    PayloadTooLarge(usize),
    /// A run-hook payload that parses as JSON but breaks the schema; the text
    /// names the field, never its value.
    BadPayload(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Json(e) => write!(f, "bad frame: {e}"),
            WireError::Version(v) => write!(f, "unsupported wire version {v}"),
            WireError::UnknownKind(t) => write!(f, "unknown frame kind {t:?}"),
            WireError::BinaryFrame => f.write_str("binary frames are not accepted on /agent"),
            WireError::NotData(k) => write!(f, "{k} frame carries no data"),
            WireError::BadChunk(why) => write!(f, "bad chunk: {why}"),
            WireError::PayloadTooLarge(n) => write!(f, "run-hook payload of {n} bytes exceeds 4096"),
            WireError::BadPayload(why) => write!(f, "bad run-hook payload: {why}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<serde_json::Error> for WireError {
    fn from(e: serde_json::Error) -> Self {
        WireError::Json(e)
    }
}

/// Every `t` this build knows.
pub const KINDS: [&str; 24] = [
    "hello", "hello_ok", "hello_err", "spawn", "spawned", "spawn_err", "stdin", "stdin_eof", "stdin_ack", "signal", "detach", "stdout", "stderr", "ack", "exit", "ping", "pong", "event", "error",
    "credential", "credential_ok", "credential_err", "credential_forget", "_",
];

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
            Frame::StdinAck { .. } => "stdin_ack",
            Frame::Signal { .. } => "signal",
            Frame::Detach { .. } => "detach",
            Frame::Stdout { .. } => "stdout",
            Frame::Stderr { .. } => "stderr",
            Frame::Ack { .. } => "ack",
            Frame::Exit { .. } => "exit",
            Frame::Ping { .. } => "ping",
            Frame::Pong { .. } => "pong",
            Frame::Event { .. } => "event",
            Frame::Error { .. } => "error",
            Frame::Credential { .. } => "credential",
            Frame::CredentialOk { .. } => "credential_ok",
            Frame::CredentialErr { .. } => "credential_err",
            Frame::CredentialForget { .. } => "credential_forget",
        }
    }

    /// The spawn a frame is about, if any.
    #[must_use]
    pub fn spawn_id(&self) -> Option<&SpawnId> {
        match self {
            Frame::Spawn { spawn_id, .. }
            | Frame::Spawned { spawn_id, .. }
            | Frame::SpawnErr { spawn_id, .. }
            | Frame::Stdin { spawn_id, .. }
            | Frame::StdinEof { spawn_id, .. }
            | Frame::StdinAck { spawn_id, .. }
            | Frame::Signal { spawn_id, .. }
            | Frame::Detach { spawn_id, .. }
            | Frame::Stdout { spawn_id, .. }
            | Frame::Stderr { spawn_id, .. }
            | Frame::Ack { spawn_id, .. }
            | Frame::Exit { spawn_id, .. } => Some(spawn_id),
            Frame::Error { spawn_id, .. } => spawn_id.as_ref(),
            _ => None,
        }
    }

    /// One JSON object with `v` first, then `t`, then the fields.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&EnvelopeOut { v: WIRE_VERSION, frame: self }).expect("frame types always serialise")
    }

    /// Parse one frame. A wrong `v` is [`WireError::Version`]; a known `v`
    /// with an unknown `t` is [`WireError::UnknownKind`]; anything else that
    /// does not parse is [`WireError::Json`].
    pub fn from_json(text: &str) -> Result<Frame, WireError> {
        match serde_json::from_str::<Peek>(text) {
            Ok(p) if p.v != WIRE_VERSION => return Err(WireError::Version(p.v)),
            Ok(p) if !KINDS.contains(&p.t.as_str()) || p.t == "_" => return Err(WireError::UnknownKind(p.t.chars().take(64).collect())),
            _ => {}
        }
        let env: EnvelopeIn = serde_json::from_str(text)?;
        if env.v != WIRE_VERSION {
            return Err(WireError::Version(env.v));
        }
        Ok(env.frame)
    }

    /// An `error` frame.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>, spawn_id: Option<SpawnId>) -> Frame {
        Frame::Error { code, message: message.into(), spawn_id }
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

/// The tungstenite configuration both ends use: [`WS_MAX_MESSAGE`] per
/// message and per frame, [`WS_MAX_WRITE_BUFFER`] of write buffer.
#[must_use]
pub fn ws_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE))
        .max_frame_size(Some(WS_MAX_MESSAGE))
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER)
}

// ---- run-hook payload ---------------------------------------------------------

/// `hex(sha256(token))` — what rides `run_hook_payload` instead of the token.
#[must_use]
pub fn commitment_hex(token: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token))
}

/// The ≤4096-byte payload handed to the VM's `/run` hook: a commitment to the
/// session token plus ownership metadata. Never the token itself. Unknown
/// fields are refused: a new field is a new `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunHookPayload {
    pub v: u8,
    pub commit: String,
    pub owner: String,
    pub created: String,
}

impl RunHookPayload {
    pub const MAX_BYTES: usize = 4096;
    /// Longest `owner` accepted (`user@host`, printable ASCII).
    pub const MAX_OWNER: usize = 256;

    /// Parse the `runHookPayload` string the platform hands to `/run`: at most
    /// [`Self::MAX_BYTES`] bytes, strict JSON, then [`Self::validate`].
    pub fn from_json(text: &str) -> Result<Self, WireError> {
        if text.len() > Self::MAX_BYTES {
            return Err(WireError::PayloadTooLarge(text.len()));
        }
        let p: RunHookPayload = serde_json::from_str(text)?;
        p.validate()?;
        Ok(p)
    }

    /// Schema checks the type system cannot express: `v` is the wire version,
    /// `commit` is 64 lowercase hex digits, `owner` is 1–256 printable ASCII
    /// characters without spaces, `created` is RFC 3339 UTC.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.v != WIRE_VERSION {
            return Err(WireError::BadPayload("v"));
        }
        if self.commit.len() != 64 || !self.commit.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(WireError::BadPayload("commit"));
        }
        if self.owner.is_empty() || self.owner.len() > Self::MAX_OWNER || !self.owner.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(WireError::BadPayload("owner"));
        }
        if crate::wire::time::parse_rfc3339_utc(&self.created).is_none() {
            return Err(WireError::BadPayload("created"));
        }
        Ok(())
    }

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
    /// The `/agent` wire version this shim speaks (S6 on); absent from an
    /// older image, whose `/agent` upgrade answers 404.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<u8>,
    /// As `hello_ok.caps` (S7), so this Mac can record what a VM's shim can do
    /// before any command needs it; absent from an older image. `vm run`
    /// reads no `/health`: a `/health` refresh (`vm health`, `vm warm`, `vm
    /// smoke`, `egress check`, the live probes) and `credential::cached_on_vm`'s
    /// `/health/detail` record the caps in the VM's row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

/// The last peer of one runtime hook, as the guard saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookPeerSeen {
    pub peer: String,
    /// `/proc/net/tcp` (`4`) or `tcp6` (`6`); `None` when no row was found.
    pub family: Option<u8>,
    pub uid: Option<u32>,
    pub inode: Option<u64>,
    /// `admitted` | `refused` | `logged` (the policy's decision).
    pub decision: String,
    pub at: String,
}

/// `/health/detail` lists at most this many listeners: every uid's but the
/// agent's first (the shim's own and the platform's, what a reader checks),
/// the agent's own last, since an agent can open thousands; the rest are
/// counted in `listeners_omitted`.
pub const LISTENERS_MAX: usize = 512;

/// One LISTEN socket of the VM's network namespace (`/proc/net/tcp` and `tcp6`, state `0A`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub addr: String,
    pub port: u16,
    pub uid: u32,
    pub inode: u64,
    /// The socket is one of the shim's own (its inode is among `/proc/self/fd`).
    pub own: bool,
}

/// A spawn as `/health/detail` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnDetail {
    #[serde(flatten)]
    pub status: SpawnStatus,
    /// RFC 3339 UTC.
    pub started_at: String,
    /// Seconds left of the detach grace (None while attached, or frozen while suspended).
    pub detach_left_s: Option<u64>,
    pub frozen: bool,
    /// A process of the spawn's group still exists (the shim's `kill(-pgid,
    /// 0)`; S7 D6, the child-gone check after a refused credential's stop):
    /// `alive` is the leader alone. Left out when false, so a detail without
    /// it reads as before; an older shim never says it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub group_alive: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// `GET /health/detail` (bearer only): what `/health` says plus the guard,
/// the sockets, the spawns and the listeners. No secret, no argv beyond argv[0].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthDetail {
    #[serde(flatten)]
    pub health: Health,
    /// `AWS_LAMBDA_MICROVM_IMAGE_VERSION` at worker start.
    pub image_version: Option<String>,
    /// `log` | `enforce` | `peer`.
    pub hook_source: String,
    /// `on` | `log` | `off`.
    pub agent_guard: String,
    /// Refusals by port (`9000`, `8080`, `9418`).
    pub refused_peers: BTreeMap<String, u64>,
    /// The last peer the guard let through, per runtime hook (`run`,
    /// `resume`, `suspend`, `terminate`): the platform's own hook client.
    pub hook_peers: BTreeMap<String, HookPeerSeen>,
    /// The last refused peer per runtime hook (an agent, or `/validate`'s
    /// self-test), kept apart so a refusal never hides the platform's record.
    #[serde(default)]
    pub hook_refusals: BTreeMap<String, HookPeerSeen>,
    pub sockets_open: u32,
    pub sockets_authenticated: u32,
    pub spawns: Vec<SpawnDetail>,
    pub has_credentials: bool,
    #[serde(flatten)]
    pub credential: CredentialView,
    /// The last clock report (`/run` or `/resume`), as logged.
    pub clock: Option<serde_json::Value>,
    /// At most [`LISTENERS_MAX`], the agent uid's own last.
    pub listeners: Vec<ListenerInfo>,
    /// The listeners past [`LISTENERS_MAX`], left out.
    #[serde(default)]
    pub listeners_omitted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192";

    fn sid() -> SpawnId {
        SpawnId(SID.to_string())
    }

    fn text(t: &str) -> Chunk {
        Chunk { text: Some(t.to_string()), b64: None }
    }

    fn status() -> SpawnStatus {
        SpawnStatus { spawn_id: sid(), argv0: "claude".into(), pid: 42, pgid: 42, alive: true, attached: false, out_seq: 7, out_from: 3, err_seq: 2, in_seq: 5, stdin_closed: false, exit: None }
    }

    fn every_variant() -> Vec<Frame> {
        vec![
            Frame::Hello {
                session_token: Secret::new("fake-session-token".into()),
                client: ClientInfo { name: "ai-env".into(), version: "0.1.0".into(), host: "mike@mbp".into() },
                resume: vec![ResumePoint { spawn_id: sid(), from_seq: Some(42), err_from_seq: None }],
                idle_s: Some(90),
            },
            Frame::HelloOk {
                wire: 1,
                shim_version: "0.1.0".into(),
                claude_version: Some("2.1.287".into()),
                microvm_id: Some("microvm-1".into()),
                image_version: Some("5.0".into()),
                boot_nonce: "n".into(),
                owner: Some("mike@mbp".into()),
                has_credentials: false,
                uptime_s: 12,
                run_hook_seen: true,
                spawns: vec![status()],
                resumed: vec![Resumed { spawn_id: sid(), status: ResumeStatus::Ok }],
                caps: vec![CAP_CREDENTIAL_CACHE.into()],
                credential: CredentialView { credential_name: Some("CLAUDE_CODE_OAUTH_TOKEN".into()), credential_tag: Some("seal-1".into()), credential_at: Some("2026-10-07T10:00:00Z".into()), credential_holders: 1 },
            },
            Frame::HelloErr { code: HelloErrCode::BadToken, message: "no".into() },
            Frame::Spawn {
                spawn_id: sid(),
                argv: vec!["claude".into(), "--version".into()],
                cwd: Some("/Users/mike/Documents/DeFi/ai-env".into()),
                env: BTreeMap::from([("LANG".to_string(), "C.UTF-8".to_string())]),
                secrets: BTreeMap::from([("CLAUDE_CODE_OAUTH_TOKEN".to_string(), Secret::new("dummy-secret-value".to_string()))]),
                deliver_secret: Deliver::Fd,
                detach_grace_s: Some(60),
                credential: None,
            },
            Frame::Spawned { spawn_id: sid(), pid: 42, pgid: 42, claude_version: Some("2.1.287".into()) },
            Frame::SpawnErr { spawn_id: sid(), code: SpawnErrCode::Exec, message: "boom".into() },
            Frame::Stdin { spawn_id: sid(), seq: 1, data: text("{\"type\":\"user\"}\n") },
            Frame::StdinEof { spawn_id: sid(), seq: 1 },
            Frame::StdinAck { spawn_id: sid(), seq: 1 },
            Frame::Signal { spawn_id: sid(), sig: Sig::Term, scope: Scope::Group },
            Frame::Detach { spawn_id: sid(), is_final: true },
            Frame::Stdout { spawn_id: sid(), seq: 7, data: Chunk { text: None, b64: Some("AP8=".into()) } },
            Frame::Stderr { spawn_id: sid(), seq: 2, data: text("warn\n"), dropped: 0 },
            Frame::Ack { spawn_id: sid(), seq: 9, err_seq: 2 },
            Frame::Exit { spawn_id: sid(), seq: 8, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false },
            Frame::Ping { ts: 1 },
            Frame::Pong { ts: 1 },
            Frame::Event { kind: EventKind::WipRef, at: "2026-09-19T08:00:00Z".into(), reference: Some("refs/wip/1".into()) },
            Frame::Error { code: ErrorCode::Superseded, message: "x".into(), spawn_id: Some(sid()) },
            Frame::Credential { name: "CLAUDE_CODE_OAUTH_TOKEN".into(), secret: Secret::new("dummy-credential-value".into()), tag: Some("seal-1".into()) },
            Frame::CredentialOk { name: "CLAUDE_CODE_OAUTH_TOKEN".into(), cached: true, tag: Some("seal-1".into()) },
            Frame::CredentialErr { name: "CLAUDE_CODE_OAUTH_TOKEN".into(), code: CredentialErrCode::Suspended, message: "suspended".into() },
            Frame::CredentialForget { name: None },
        ]
    }

    #[test]
    fn roundtrip_every_variant() {
        let all = every_variant();
        assert_eq!(all.len(), 23);
        let mut kinds: Vec<&str> = all.iter().map(Frame::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), 23, "one sample per kind");
        assert_eq!(KINDS.len(), 24, "every kind and the _ sentinel");
        for k in &kinds {
            assert!(KINDS.contains(k), "{k} is listed in KINDS");
        }
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
            format!("{{\"v\":1,\"t\":\"hello\",\"session_token\":\"fake-session-token\",\"client\":{{\"name\":\"ai-env\",\"version\":\"0.1.0\",\"host\":\"mike@mbp\"}},\"resume\":[{{\"spawn_id\":\"{SID}\",\"from_seq\":42}}],\"idle_s\":90}}")
        );
    }

    #[test]
    fn json_shape_chunks_are_flat() {
        let out = Frame::Stdout { spawn_id: sid(), seq: 7, data: text("hi\n") };
        assert_eq!(out.to_json(), format!("{{\"v\":1,\"t\":\"stdout\",\"spawn_id\":\"{SID}\",\"seq\":7,\"text\":\"hi\\n\"}}"));
        let bin = Frame::Stdout { spawn_id: sid(), seq: 8, data: Chunk { text: None, b64: Some("AP8=".into()) } };
        assert_eq!(bin.to_json(), format!("{{\"v\":1,\"t\":\"stdout\",\"spawn_id\":\"{SID}\",\"seq\":8,\"b64\":\"AP8=\"}}"));
        let err = Frame::Stderr { spawn_id: sid(), seq: 1, data: text("w"), dropped: 3 };
        assert_eq!(err.to_json(), format!("{{\"v\":1,\"t\":\"stderr\",\"spawn_id\":\"{SID}\",\"seq\":1,\"text\":\"w\",\"dropped\":3}}"));
    }

    #[test]
    fn json_shape_exit_detach_ack() {
        let f = Frame::Exit { spawn_id: sid(), seq: 8, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false };
        assert_eq!(f.to_json(), format!("{{\"v\":1,\"t\":\"exit\",\"spawn_id\":\"{SID}\",\"seq\":8,\"code\":0,\"signal\":null,\"stderr_dropped\":0,\"stdout_truncated\":false}}"));
        // An exit without stdout_truncated (an older shim) reads as false.
        let old = format!("{{\"v\":1,\"t\":\"exit\",\"spawn_id\":\"{SID}\",\"seq\":8,\"code\":null,\"signal\":9,\"stderr_dropped\":0}}");
        assert!(matches!(Frame::from_json(&old).unwrap(), Frame::Exit { stdout_truncated: false, signal: Some(9), .. }));
        assert_eq!(Frame::Detach { spawn_id: sid(), is_final: true }.to_json(), format!("{{\"v\":1,\"t\":\"detach\",\"spawn_id\":\"{SID}\",\"final\":true}}"));
        assert_eq!(Frame::Ack { spawn_id: sid(), seq: 3, err_seq: 1 }.to_json(), format!("{{\"v\":1,\"t\":\"ack\",\"spawn_id\":\"{SID}\",\"seq\":3,\"err_seq\":1}}"));
    }

    /// The S7 frames on the wire, and an S6 peer's frames still read the same:
    /// every new field is left out when empty, and an older shim's `hello_ok`
    /// and `/health` parse with no caps and an empty credential view.
    #[test]
    fn credential_frames_and_caps_are_additive() {
        assert_eq!(
            Frame::Credential { name: "X_TOKEN".into(), secret: Secret::new("v".into()), tag: Some("t-1".into()) }.to_json(),
            "{\"v\":1,\"t\":\"credential\",\"name\":\"X_TOKEN\",\"secret\":\"v\",\"tag\":\"t-1\"}"
        );
        assert_eq!(Frame::CredentialForget { name: None }.to_json(), "{\"v\":1,\"t\":\"credential_forget\"}");
        assert_eq!(Frame::CredentialOk { name: "X_TOKEN".into(), cached: false, tag: None }.to_json(), "{\"v\":1,\"t\":\"credential_ok\",\"name\":\"X_TOKEN\",\"cached\":false}");
        let err = Frame::from_json("{\"v\":1,\"t\":\"credential_err\",\"name\":\"X\",\"code\":\"from_the_future\",\"message\":\"m\"}").unwrap();
        assert!(matches!(err, Frame::CredentialErr { code: CredentialErrCode::Other, .. }));
        let no_cred = Frame::from_json(&format!("{{\"v\":1,\"t\":\"spawn_err\",\"spawn_id\":\"{SID}\",\"code\":\"no_credential\",\"message\":\"m\"}}")).unwrap();
        assert!(matches!(no_cred, Frame::SpawnErr { code: SpawnErrCode::NoCredential, .. }));
        // A spawn naming a credential carries the name only.
        let spawn = Frame::Spawn { spawn_id: sid(), argv: vec!["claude".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: Some("X_TOKEN".into()) };
        assert!(spawn.to_json().ends_with(",\"credential\":\"X_TOKEN\"}"), "{}", spawn.to_json());
        // An S6 shim's hello_ok: no caps, no view; and it serialises back without them.
        let s6 = "{\"v\":1,\"t\":\"hello_ok\",\"wire\":1,\"shim_version\":\"0.1.0\",\"claude_version\":null,\"microvm_id\":null,\"image_version\":null,\"boot_nonce\":\"n\",\"owner\":null,\"has_credentials\":false,\"uptime_s\":1,\"run_hook_seen\":true,\"spawns\":[],\"resumed\":[]}";
        let f = Frame::from_json(s6).unwrap();
        let Frame::HelloOk { caps, credential, .. } = &f else { panic!("hello_ok") };
        assert!(caps.is_empty() && *credential == CredentialView::default());
        assert_eq!(f.to_json(), s6, "byte-identical for an S6 peer");
        // /health: an older shim's document has no caps; a new one names them.
        let old: Health = serde_json::from_str("{\"status\":\"ok\",\"shim_version\":\"0.1.0\",\"claude_version\":null,\"microvm_id\":null,\"owner\":null,\"created\":null,\"boot_nonce\":null,\"run_hook_seen\":true,\"uptime_s\":3,\"wire\":1}").unwrap();
        assert!(old.caps.is_empty());
        let new = Health { caps: vec![CAP_CREDENTIAL_CACHE.into()], ..old };
        assert!(serde_json::to_string(&new).unwrap().ends_with(",\"caps\":[\"credential_cache\"]}"));
    }

    /// `/health/detail`'s `group_alive` (S7 D6) is additive: left out when
    /// false, so a detail without it is byte-identical to before, and an
    /// older shim's spawn (no field) reads as false.
    #[test]
    fn group_alive_is_additive() {
        let d = SpawnDetail { status: status(), started_at: "2026-10-08T08:00:00Z".into(), detach_left_s: None, frozen: false, group_alive: false };
        let before = format!("{},\"started_at\":\"2026-10-08T08:00:00Z\",\"detach_left_s\":null,\"frozen\":false}}", serde_json::to_string(&status()).unwrap().trim_end_matches('}'));
        assert_eq!(serde_json::to_string(&d).unwrap(), before, "no group_alive while false");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&before).unwrap(), d, "an older shim's spawn reads as false");
        let alive = SpawnDetail { group_alive: true, ..d };
        let json = serde_json::to_string(&alive).unwrap();
        assert!(json.ends_with(",\"frozen\":false,\"group_alive\":true}"), "{json}");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&json).unwrap(), alive);
    }

    #[test]
    fn rejects_v2_and_names_an_unknown_kind() {
        assert!(matches!(Frame::from_json("{\"v\":2,\"t\":\"ping\",\"ts\":1}").unwrap_err(), WireError::Version(2)));
        assert!(matches!(Frame::from_json("{\"v\":1,\"t\":\"nope\"}"), Err(WireError::UnknownKind(t)) if t == "nope"));
        assert!(matches!(Frame::from_json("{\"v\":1,\"t\":\"_\"}"), Err(WireError::UnknownKind(_))));
        assert!(matches!(Frame::from_json("not json"), Err(WireError::Json(_))));
        assert!(matches!(Frame::from_json("{\"v\":1,\"t\":\"ping\"}"), Err(WireError::Json(_))), "a known kind missing its fields is malformed");
    }

    #[test]
    fn ignores_unknown_fields_and_codes() {
        assert_eq!(Frame::from_json("{\"v\":1,\"t\":\"ping\",\"ts\":5,\"extra\":true}").unwrap(), Frame::Ping { ts: 5 });
        let f = Frame::from_json("{\"v\":1,\"t\":\"error\",\"code\":\"from_the_future\",\"message\":\"m\"}").unwrap();
        assert!(matches!(f, Frame::Error { code: ErrorCode::Other, spawn_id: None, .. }));
        let h = Frame::from_json("{\"v\":1,\"t\":\"hello_err\",\"code\":\"later\",\"message\":\"m\"}").unwrap();
        assert!(matches!(h, Frame::HelloErr { code: HelloErrCode::Other, .. }));
    }

    #[test]
    fn debug_never_shows_data_secrets_or_arguments() {
        for f in every_variant() {
            let d = format!("{f:?}");
            for secret in ["fake-session-token", "dummy-secret-value", "dummy-credential-value", "--version", "type", "AP8=", "warn", "C.UTF-8", "/Users/mike/Documents"] {
                assert!(!d.contains(secret), "{} leaks {secret:?}: {d}", f.kind());
            }
            assert!(d.starts_with(f.kind()), "{d}");
        }
        let spawn = format!("{:?}", every_variant()[3]);
        assert!(spawn.contains("argv0=claude") && spawn.contains("argc=2") && spawn.contains("secrets=1"), "{spawn}");
    }

    #[test]
    fn spawn_ids_are_uuid_v7() {
        assert!(SpawnId::new_v7().is_v7());
        assert!(sid().is_v7());
        for bad in ["", "not-a-uuid", "0192F1E0-2B7C-7C3A-9A1B-4D5E6F708192", "f47ac10b-58cc-4372-a567-0e02b2c3d479", "0192f1e02b7c7c3a9a1b4d5e6f708192"] {
            assert!(!SpawnId(bad.into()).is_v7(), "{bad}");
        }
    }

    /// The golden `vm exec -- cat` conversation both ends' tests replay
    /// (tests/fixtures/wire/exec-golden.jsonl): every line parses as v1 and
    /// serialises back byte-identically, and the stdout bytes equal the stdin
    /// bytes (chunk boundaries are the shim's; the bytes are not).
    #[test]
    fn golden_exec_conversation_round_trips() {
        let text = include_str!("../../tests/fixtures/wire/exec-golden.jsonl");
        let (mut stdin, mut stdout) = (Vec::new(), Vec::new());
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let dir = v["dir"].as_str().unwrap();
            assert!(matches!(dir, "mac" | "vm"), "{line}");
            // The frame's own text, in its original key order (`{"dir":…,"frame":<frame>}`).
            let raw = line.split_once(",\"frame\":").and_then(|(_, rest)| rest.strip_suffix('}')).unwrap_or_else(|| panic!("{line}"));
            let f = Frame::from_json(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(f.to_json(), raw, "byte-identical re-serialisation");
            match (dir, &f) {
                ("mac", Frame::Stdin { data, .. }) => stdin.extend(crate::wire::chunk::decode(data).unwrap()),
                ("vm", Frame::Stdout { data, .. }) => stdout.extend(crate::wire::chunk::decode(data).unwrap()),
                ("mac", Frame::Hello { .. } | Frame::Spawn { .. } | Frame::StdinEof { .. } | Frame::Ack { .. }) => {}
                ("vm", Frame::HelloOk { .. } | Frame::Spawned { .. } | Frame::StdinAck { .. } | Frame::Exit { .. }) => {}
                _ => panic!("{dir} does not send {}", f.kind()),
            }
        }
        assert_eq!(stdout, stdin);
        assert_eq!(stdin, b"hello\n\x00\xff\n");
    }

    /// The golden credentialed conversation (S7,
    /// tests/fixtures/wire/cred-golden.jsonl): a miss (the `credential` frame,
    /// then the spawn naming it), a hit (a `hello_ok` showing the cached seal,
    /// a spawn by name only), a second client's view while that spawn holds
    /// the token, and the cache's other answers (`credential_forget`,
    /// `no_credential`, `suspended`). Every line parses as v1 and serialises
    /// back byte-identically, each kind comes from the side that sends it,
    /// every S7 shape is there, and the stand-in secret (no token shape) rides
    /// only the `credential` frames: no spawn carries one, and no frame's
    /// `Debug` shows it. Messages name the line by its number in the file
    /// (from 1, as an editor counts), never print it.
    #[test]
    fn golden_credential_conversation_round_trips() {
        let text = include_str!("../../tests/fixtures/wire/cred-golden.jsonl");
        let mut frames = Vec::new();
        let mut secrets: Vec<String> = Vec::new();
        let (mut miss, mut held, mut forgot, mut no_credential, mut suspended) = (false, false, false, false, false);
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {n}: {e}"));
            let dir = v["dir"].as_str().unwrap_or_default().to_string();
            // The frame's own text, in its original key order (`{"dir":…,"frame":<frame>}`).
            let raw = line.split_once(",\"frame\":").and_then(|(_, rest)| rest.strip_suffix('}')).unwrap_or_else(|| panic!("line {n}: no frame"));
            let f = Frame::from_json(raw).unwrap_or_else(|e| panic!("line {n}: {e}"));
            assert!(f.to_json() == raw, "line {n} ({}): not byte-identical once re-serialised", f.kind());
            match (dir.as_str(), &f) {
                ("mac", Frame::Credential { secret, .. }) => secrets.push(secret.expose().clone()),
                ("mac", Frame::Spawn { secrets: inline, credential, .. }) => assert!(inline.is_empty() && credential.as_deref() == Some("CLAUDE_CODE_OAUTH_TOKEN"), "line {n}: a spawn names the credential, never carries it"),
                ("mac", Frame::Hello { .. } | Frame::StdinEof { .. } | Frame::Ack { .. } | Frame::CredentialForget { .. }) => {}
                ("vm", Frame::HelloOk { caps, has_credentials, credential, .. }) => {
                    assert!(caps.iter().any(|c| c == CAP_CREDENTIAL_CACHE), "line {n}: an S7 shim offers {CAP_CREDENTIAL_CACHE}");
                    miss |= !*has_credentials && *credential == CredentialView::default();
                    held |= *has_credentials && credential.credential_tag.is_some() && credential.credential_at.is_some() && credential.credential_holders > 0;
                }
                ("vm", Frame::CredentialOk { cached, .. }) => forgot |= !*cached,
                ("vm", Frame::SpawnErr { code, .. }) => no_credential |= *code == SpawnErrCode::NoCredential,
                ("vm", Frame::CredentialErr { code, .. }) => suspended |= *code == CredentialErrCode::Suspended,
                ("vm", Frame::Spawned { .. } | Frame::Stdout { .. } | Frame::Exit { .. }) => {}
                _ => panic!("line {n}: {dir} does not send {}", f.kind()),
            }
            frames.push(f);
        }
        assert!(miss && held && forgot && no_credential && suspended, "every S7 shape: miss {miss}, held {held}, forgot {forgot}, no_credential {no_credential}, suspended {suspended}");
        for kind in ["credential", "credential_ok", "credential_err", "credential_forget"] {
            assert!(frames.iter().any(|f| f.kind() == kind), "{kind} missing");
        }
        // One stand-in secret, with no token shape, in exactly the `credential` lines; no `Debug` shows it.
        let secret = secrets.first().expect("a credential frame");
        assert!(secrets.iter().all(|s| s == secret) && !secret.starts_with("sk-ant-"), "one stand-in of {} bytes, no token shape", secret.len());
        assert_eq!(text.lines().filter(|l| l.contains(secret.as_str())).count(), secrets.len(), "only the credential frames carry it");
        assert!(frames.iter().all(|f| !format!("{f:?}").contains(secret.as_str())), "a frame's Debug shows the secret");
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
        let f = Frame::Ack { spawn_id: sid(), seq: 3, err_seq: 0 };
        let m = Message::from(&f);
        assert!(m.is_text());
        assert_eq!(Frame::try_from(m).unwrap(), f);
    }

    #[test]
    fn signal_numbers() {
        assert_eq!(Sig::Int.number(), 2);
        assert_eq!(Sig::Kill.number(), 9);
        assert_eq!(Sig::Term.number(), 15);
        assert_eq!(Sig::Hup.number(), 1);
    }

    #[test]
    fn ws_config_caps() {
        let c = ws_config();
        assert_eq!(c.max_message_size, Some(WS_MAX_MESSAGE));
        assert_eq!(c.max_frame_size, Some(WS_MAX_MESSAGE));
        assert_eq!(c.max_write_buffer_size, WS_MAX_WRITE_BUFFER);
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
    fn from_json_accepts_a_valid_payload_and_names_the_bad_field() {
        let good = RunHookPayload::new(&Secret::new("test-token".into()), "mike@mbp", "2026-09-19T08:00:00Z");
        let text = good.to_json().unwrap();
        assert_eq!(RunHookPayload::from_json(&text).unwrap(), good);
        let cases: [(RunHookPayload, &str); 7] = [
            (RunHookPayload { v: 2, ..good.clone() }, "v"),
            (RunHookPayload { commit: "ab".repeat(31), ..good.clone() }, "commit"),
            (RunHookPayload { commit: "AB".repeat(32), ..good.clone() }, "commit"),
            (RunHookPayload { owner: String::new(), ..good.clone() }, "owner"),
            (RunHookPayload { owner: "mike @mbp".into(), ..good.clone() }, "owner"),
            (RunHookPayload { created: "yesterday".into(), ..good.clone() }, "created"),
            // A multi-byte character straddling byte 19 is refused, not a panic.
            (RunHookPayload { created: "2026-09-25T01:39:3\u{e9}Z".into(), ..good.clone() }, "created"),
        ];
        for (p, field) in cases {
            let e = RunHookPayload::from_json(&serde_json::to_string(&p).unwrap()).unwrap_err();
            assert!(matches!(e, WireError::BadPayload(f) if f == field), "{field}: {e}");
            assert!(!e.to_string().contains(&p.owner) || p.owner.is_empty(), "the value never appears: {e}");
        }
        let long = RunHookPayload { owner: "o".repeat(RunHookPayload::MAX_OWNER + 1), ..good.clone() };
        assert!(matches!(RunHookPayload::from_json(&serde_json::to_string(&long).unwrap()), Err(WireError::BadPayload("owner"))));
    }

    #[test]
    fn from_json_refuses_unknown_fields_non_json_and_oversize() {
        let good = RunHookPayload::new(&Secret::new("t".into()), "o", "2026-09-19T08:00:00Z").to_json().unwrap();
        let extra = good.replacen('{', "{\"x\":1,", 1);
        assert!(matches!(RunHookPayload::from_json(&extra), Err(WireError::Json(_))), "{extra}");
        assert!(matches!(RunHookPayload::from_json("not json"), Err(WireError::Json(_))));
        let padded = format!("{good}{}", " ".repeat(RunHookPayload::MAX_BYTES + 1 - good.len()));
        assert!(matches!(RunHookPayload::from_json(&padded), Err(WireError::PayloadTooLarge(n)) if n == RunHookPayload::MAX_BYTES + 1));
        let at_cap = format!("{good}{}", " ".repeat(RunHookPayload::MAX_BYTES - good.len()));
        assert!(RunHookPayload::from_json(&at_cap).is_ok(), "exactly 4096 bytes is accepted");
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
            wire: None,
            caps: vec![],
        };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.starts_with("{\"status\":\"ok\",\"shim_version\":\"0.1.0\""), "{s}");
        assert!(!s.contains("wire"), "an absent wire is not written (an older Mac reads the document unchanged): {s}");
        assert_eq!(serde_json::from_str::<Health>(&s).unwrap(), h);
        let v1 = Health { wire: Some(WIRE_VERSION), ..h };
        assert_eq!(serde_json::from_str::<Health>(&serde_json::to_string(&v1).unwrap()).unwrap(), v1);
    }
}
