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
//!
//! S10 (plans/s10-contracts.md §1) adds the park frames (`park`, `parked`,
//! `park_refused`, `unpark`), sent only on a socket whose shim names
//! [`CAP_PARK_V1`], and two reply fields a reader may ignore
//! (`SpawnDetail.parked`, `Health.mem_total_mib`).
//!
//! S11 (plans/s11-contracts.md §1) adds four caps, each named by a shim
//! once its served flag holds ([`CAP_CODEOUT_MANIFEST_V1`],
//! [`CAP_VIEW_PARENT_V1`], [`CAP_TRANSCRIPT_GZIP_V1`],
//! [`CAP_CLAUDE_STAGE_V1`]), a spawn's staged claudes (`spawn.claude`, sent
//! only behind `CAP_CLAUDE_STAGE_V1`), and two reply fields a reader may
//! ignore (`spawned.claude_sha256`, `HealthDetail.claude_cache`).
use crate::wire::redact::Secret;
use crate::wire::workspace::{ClaudeCacheView, ClaudeRef, WorkspaceView};
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
/// S10: the longest park grace a `park` may name (the 8 h wall plus one
/// hour). A parked spawn whose socket goes lives its park grace, not the
/// detach grace.
pub const PARK_GRACE_MAX_S: u32 = 32_400;
/// S10: a parked socket's idle timer, in place of `hello.idle_s`, until the
/// next inbound frame.
pub const PARKED_IDLE_MAX: Duration = Duration::from_secs(86_400);
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

/// The capability a shim names in `hello_ok.caps` and `/health` (S8, L5)
/// when it serves the workspace routes (`wire::workspace`): `GET`/`PUT
/// /seed` and `POST /codeout` on the code port, `GET /transcript` (S8's
/// `PUT` went at S9's S3 cut-over) and `GET /settings` on the app port. The Mac sends a workspace request only
/// to a shim that names it (an image-7.0 shim answers each with 404), and
/// SELECT_VM never reuses a VM whose recorded caps lack it. Wire stays v1:
/// caps are additive. A shim names it when it has a workspace helper to run
/// (`ShimState::caps`: the image's binary); one without answers the routes
/// with 404, as an older shim does.
pub const CAP_WORKSPACE_V1: &str = "workspace_v1";

/// The capability a shim names (S9, L5) when it serves git smart-HTTP on the
/// code port (`wire::workspace::GIT_INFO_REFS_ROUTE`,
/// `GIT_UPLOAD_PACK_ROUTE`): `box fetch --smart-http` checks it before any
/// request (exit 7 naming `make deploy`). Named by a shim that serves the
/// workspace routes, once its git routes are built (`shim::gitcgi::SERVED`).
pub const CAP_GIT_HTTP_V1: &str = "git_http_v1";

/// The capability a shim names (S9, M2) when it serves the transcript
/// store's transfers on the app port (`POST /transcript/push`, `POST
/// /transcript/pull`, `GET /transcript/view`, `POST /transcript/tail`) and
/// the extended `GET /transcript`: the Mac checks it before any of them, and
/// a remote session's SELECT_VM never reuses a VM whose recorded caps lack
/// it (`shim::s3xfer::SERVED`).
pub const CAP_TRANSCRIPT_S3_V1: &str = "transcript_s3_v1";

/// The capability a shim names (S10, M2) when it answers the park frames
/// (`park`, `unpark`) and parks spawns. The Mac sends `park` only on a
/// socket whose `hello_ok.caps` names it: on an older image a session never
/// parks (`park:off(no_cap)`). Named with or without a workspace helper,
/// once the shim's park is built (`shim::agent::PARK_SERVED`).
pub const CAP_PARK_V1: &str = "park_v1";

/// S11 (C.1): the shim answers a code-out that sets
/// `CodeoutRequest.manifest_when_empty` with its manifest line alone (200)
/// when nothing is new. Named with a helper, once `shim::code::MANIFEST_SERVED`.
pub const CAP_CODEOUT_MANIFEST_V1: &str = "codeout_manifest_v1";

/// S11 (C.2): the view answers `first_parent` when `ViewQuery.parent` asks.
/// Named with a helper, `shim::s3xfer::SERVED` and `VIEW_PARENT_SERVED`.
pub const CAP_VIEW_PARENT_V1: &str = "view_parent_v1";

/// S11 (L5): a pull may name gzip parts (`PullPart.encoding`), which the
/// shim's curl decodes. Named with a helper, `shim::s3xfer::SERVED` and `GZIP_SERVED`.
pub const CAP_TRANSCRIPT_GZIP_V1: &str = "transcript_gzip_v1";

/// S11 (A.3, A.4): the shim serves `POST /claude/stage`, `GET /claude/stage`
/// and `POST /claude/relay`, and runs a spawn's `claude` refs. Named, with
/// or without a helper, when `shim::claudebin::SERVED` holds and the cache
/// has a store (the shim is root, or runs with `--fs-root`).
pub const CAP_CLAUDE_STAGE_V1: &str = "claude_stage_v1";

/// The stage whose image first names `cap` (what `BridgeError::NoCapability`
/// and `remote::Failure::OldImage` say an older image predates):
/// `credential_cache` S7, `workspace_v1` S8, `git_http_v1` and
/// `transcript_s3_v1` S9, `park_v1` S10, `codeout_manifest_v1`,
/// `view_parent_v1`, `transcript_gzip_v1` and `claude_stage_v1` S11, any
/// other `this ai-env`.
#[must_use]
pub fn cap_stage(cap: &str) -> &'static str {
    match cap {
        CAP_CREDENTIAL_CACHE => "S7",
        CAP_WORKSPACE_V1 => "S8",
        CAP_GIT_HTTP_V1 | CAP_TRANSCRIPT_S3_V1 => "S9",
        CAP_PARK_V1 => "S10",
        CAP_CODEOUT_MANIFEST_V1 | CAP_VIEW_PARENT_V1 | CAP_TRANSCRIPT_GZIP_V1 | CAP_CLAUDE_STAGE_V1 => "S11",
        _ => "this ai-env",
    }
}

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

/// Why the shim did not park a spawn (S10, `park_refused.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkRefusal {
    /// CPU over `cpu_busy_ms` in a sample, or a non-leader process running (state R or D), within `min_quiet_s`.
    Busy,
    /// stdout or stdin I/O within `min_quiet_s`.
    Output,
    /// stdout or stdin not acked yet.
    Unacked,
    /// The spawn is not this socket's.
    NotAttached,
    /// Anything else: a grace or a window out of range, a shim that does not park (`PARK_SERVED` false).
    #[serde(other)]
    Other,
}

/// The wrapper that parked a spawn (S10): its pid and its start (unix
/// seconds), as `registry::process_identity` reads them on the Mac. No
/// secret: `/health/detail` reports it (`SpawnDetail.parked`), so a later
/// start on the VM can end a parked spawn whose wrapper is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkOwner {
    pub pid: u32,
    pub started: u64,
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
        /// S11 (A.4, L2): the staged claudes this spawn may run, in preference order (at most
        /// `wire::workspace::CLAUDE_REFS_MAX`): the shim runs the first its cache holds, else `--claude`. Sent only to a
        /// shim naming [`CAP_CLAUDE_STAGE_V1`]; left out when empty, so a spawn naming none is written as S10's.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        claude: Vec<ClaudeRef>,
    },
    Spawned {
        spawn_id: SpawnId,
        pid: u32,
        pgid: u32,
        /// The version of the claude that ran: S11, always when argv[0] is `claude` (the cached one's, else the image's probe).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claude_version: Option<String>,
        /// S11: the sha256 of the cached binary that ran; `None` when the image's claude ran or argv[0] is not `claude`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claude_sha256: Option<String>,
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
    /// Mac → VM (S10, [`CAP_PARK_V1`]): park the spawn this socket carries;
    /// the shim answers `parked` or `park_refused`. Every field of the four
    /// park frames is required: they are new, and sent only behind the cap.
    Park {
        spawn_id: SpawnId,
        /// The park grace: a parked spawn whose socket goes lives this long (1..=[`PARK_GRACE_MAX_S`]).
        grace_s: u32,
        /// The busy check's window (0..=3600): no sample over `cpu_busy_ms`, no running non-leader, no stdio within it.
        min_quiet_s: u32,
        /// CPU of the spawn's session per sample (`ACTIVITY_SAMPLE`) above which it is busy.
        cpu_busy_ms: u32,
        /// Hold the parked spawn's stdout in its window instead of sending it.
        hold_output: bool,
        /// The wrapper that parks it, reported back in `SpawnDetail.parked` for the reaper.
        owner: ParkOwner,
    },
    /// VM → Mac (S10): parked. The socket's idle timer is [`PARKED_IDLE_MAX`],
    /// and a lost socket starts the park grace. `quiet_s`: seconds since the
    /// spawn's last stdio; `procs`: its live processes but the leader.
    Parked { spawn_id: SpawnId, quiet_s: u32, procs: u32 },
    /// VM → Mac (S10): not parked, and what the busy check saw (`cpu_ms`:
    /// the busiest sample's CPU in the window).
    ParkRefused { spawn_id: SpawnId, reason: ParkRefusal, quiet_s: u32, procs: u32, cpu_ms: u64 },
    /// Mac → VM (S10): unpark. A `stdin`, `stdin_eof`, `signal`, `ack` or
    /// `detach` for the spawn, and a `hello` resuming it, unpark it too. No
    /// answer: the Mac sends a `ping` beside it and takes the `pong`, or a
    /// `stdin_ack`, as the socket's proof.
    Unpark { spawn_id: SpawnId },
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = self.kind();
        match self {
            Frame::Hello { client, resume, idle_s, .. } => write!(f, "{kind}(client={} {}, resume={}, idle_s={idle_s:?})", client.name, client.version, resume.len()),
            Frame::HelloOk { wire, spawns, resumed, run_hook_seen, .. } => write!(f, "{kind}(wire={wire}, spawns={}, resumed={}, run_hook_seen={run_hook_seen})", spawns.len(), resumed.len()),
            Frame::HelloErr { code, .. } => write!(f, "{kind}({code:?})"),
            Frame::Spawn { spawn_id, argv, env, secrets, deliver_secret, credential, claude, .. } => {
                let argv0 = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a)).unwrap_or("");
                write!(f, "{kind}({spawn_id}, argv0={argv0}, argc={}, env={}, secrets={}, deliver={deliver_secret:?}, credential={credential:?}, claude={})", argv.len(), env.len(), secrets.len(), claude.len())
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
            Frame::Park { spawn_id, grace_s, min_quiet_s, cpu_busy_ms, hold_output, owner } => write!(
                f,
                "{kind}({spawn_id}, grace_s={grace_s}, min_quiet_s={min_quiet_s}, cpu_busy_ms={cpu_busy_ms}, hold_output={hold_output}, owner_pid={}, owner_started={})",
                owner.pid, owner.started
            ),
            Frame::Parked { spawn_id, quiet_s, procs } => write!(f, "{kind}({spawn_id}, quiet_s={quiet_s}, procs={procs})"),
            Frame::ParkRefused { spawn_id, reason, quiet_s, procs, cpu_ms } => write!(f, "{kind}({spawn_id}, {reason:?}, quiet_s={quiet_s}, procs={procs}, cpu_ms={cpu_ms})"),
            Frame::Unpark { spawn_id } => write!(f, "{kind}({spawn_id})"),
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
pub const KINDS: [&str; 28] = [
    "hello", "hello_ok", "hello_err", "spawn", "spawned", "spawn_err", "stdin", "stdin_eof", "stdin_ack", "signal", "detach", "stdout", "stderr", "ack", "exit", "ping", "pong", "event", "error",
    "credential", "credential_ok", "credential_err", "credential_forget", "park", "parked", "park_refused", "unpark", "_",
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
            Frame::Park { .. } => "park",
            Frame::Parked { .. } => "parked",
            Frame::ParkRefused { .. } => "park_refused",
            Frame::Unpark { .. } => "unpark",
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
            | Frame::Exit { spawn_id, .. }
            | Frame::Park { spawn_id, .. }
            | Frame::Parked { spawn_id, .. }
            | Frame::ParkRefused { spawn_id, .. }
            | Frame::Unpark { spawn_id } => Some(spawn_id),
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
    /// S10: the guest's `MemTotal` in MiB (`/proc/meminfo`, read once at
    /// start). Absent from an older image, or where it cannot be read; the
    /// Mac records it in the VM's row where it records the caps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_total_mib: Option<u32>,
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
    /// S10: the wrapper that parked the spawn, while it is parked (its
    /// `park.owner`). The closing suspend counts a parked spawn of another
    /// chat as no live spawn, and a later start on the VM ends one whose
    /// owner is no live wrapper. Left out when not parked, so a detail
    /// without it reads, and is written, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked: Option<ParkOwner>,
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
    /// The S8 workspace (one per VM): its seed record, the operation holding
    /// it, the newest snapshot. Left out while the shim holds none (and by
    /// any older shim), so a detail without it reads, and is written, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceView>,
    /// S11: the VM's claude cache (`shim::claudebin`); left out by a shim without one (and by any older shim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_cache: Option<ClaudeCacheView>,
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
                claude: vec![ClaudeRef { version: "2.1.308".into(), sha256: "5a".repeat(32) }],
            },
            Frame::Spawned { spawn_id: sid(), pid: 42, pgid: 42, claude_version: Some("2.1.308".into()), claude_sha256: Some("5a".repeat(32)) },
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
            Frame::Park { spawn_id: sid(), grace_s: 30_600, min_quiet_s: 30, cpu_busy_ms: 500, hold_output: false, owner: owner() },
            Frame::Parked { spawn_id: sid(), quiet_s: 600, procs: 0 },
            Frame::ParkRefused { spawn_id: sid(), reason: ParkRefusal::Busy, quiet_s: 300, procs: 1, cpu_ms: 2350 },
            Frame::Unpark { spawn_id: sid() },
        ]
    }

    /// The park golden's wrapper (a pid and a start in October 2026).
    fn owner() -> ParkOwner {
        ParkOwner { pid: 51_234, started: 1_792_483_200 }
    }

    #[test]
    fn roundtrip_every_variant() {
        let all = every_variant();
        assert_eq!(all.len(), 27);
        let mut kinds: Vec<&str> = all.iter().map(Frame::kind).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), 27, "one sample per kind");
        assert_eq!(KINDS.len(), 28, "every kind and the _ sentinel");
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
        let spawn = Frame::Spawn { spawn_id: sid(), argv: vec!["claude".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: Some("X_TOKEN".into()), claude: Vec::new() };
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
        let d = SpawnDetail { status: status(), started_at: "2026-10-08T08:00:00Z".into(), detach_left_s: None, frozen: false, group_alive: false, parked: None };
        let before = format!("{},\"started_at\":\"2026-10-08T08:00:00Z\",\"detach_left_s\":null,\"frozen\":false}}", serde_json::to_string(&status()).unwrap().trim_end_matches('}'));
        assert_eq!(serde_json::to_string(&d).unwrap(), before, "no group_alive while false");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&before).unwrap(), d, "an older shim's spawn reads as false");
        let alive = SpawnDetail { group_alive: true, ..d };
        let json = serde_json::to_string(&alive).unwrap();
        assert!(json.ends_with(",\"frozen\":false,\"group_alive\":true}"), "{json}");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&json).unwrap(), alive);
    }

    /// S8 (C1): the workspace capability is new beside S7's, and
    /// `/health/detail`'s workspace is additive: a detail without it (an
    /// older shim's, or one with no workspace yet) reads as `None` and is
    /// written without it; one with it round-trips, the view last.
    #[test]
    fn the_workspace_cap_and_view_are_additive() {
        assert_eq!(CAP_WORKSPACE_V1, "workspace_v1");
        assert_ne!(CAP_WORKSPACE_V1, CAP_CREDENTIAL_CACHE);
        let d: HealthDetail = serde_json::from_value(serde_json::json!({
            "status": "ok", "shim_version": "0.1.0", "run_hook_seen": true, "uptime_s": 1, "caps": [CAP_CREDENTIAL_CACHE], "hook_source": "peer", "agent_guard": "on",
            "refused_peers": {}, "hook_peers": {}, "sockets_open": 0, "sockets_authenticated": 0, "spawns": [], "has_credentials": false, "listeners": [],
        }))
        .unwrap();
        assert_eq!(d.workspace, None, "an S7 detail");
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("workspace") && json.ends_with(",\"listeners_omitted\":0}"), "left out while none: {json}");
        assert_eq!(serde_json::from_str::<HealthDetail>(&json).unwrap(), d);
        let with = HealthDetail { workspace: Some(WorkspaceView { busy: Some("codeout".into()), helpers: 1, ..WorkspaceView::default() }), ..d };
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.ends_with(",\"listeners_omitted\":0,\"workspace\":{\"busy\":\"codeout\",\"helpers\":1}}"), "{json}");
        assert_eq!(serde_json::from_str::<HealthDetail>(&json).unwrap(), with);
    }

    /// S9 (L5, M2): two caps beside S7's and S8's, each named by the stage
    /// an older image predates; a health without them reads as before.
    #[test]
    fn the_s9_caps_are_additive_and_named_by_stage() {
        assert_eq!((CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1), ("git_http_v1", "transcript_s3_v1"));
        let caps = [CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1];
        assert_eq!(caps.iter().collect::<std::collections::BTreeSet<_>>().len(), caps.len(), "unique");
        assert_eq!(caps.map(cap_stage), ["S7", "S8", "S9", "S9"]);
        assert_eq!(cap_stage("workspace_v2"), "this ai-env");
        let old = Health { status: HealthStatus::Ok, shim_version: "0.1.0".into(), claude_version: None, microvm_id: None, owner: None, created: None, boot_nonce: None, run_hook_seen: true, uptime_s: 1, wire: Some(WIRE_VERSION), caps: vec![CAP_CREDENTIAL_CACHE.into(), CAP_WORKSPACE_V1.into()], mem_total_mib: None };
        let json = serde_json::to_string(&old).unwrap();
        let mut caps = serde_json::from_str::<Health>(&json).unwrap().caps;
        caps.extend([CAP_GIT_HTTP_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]);
        let new = Health { caps, ..old.clone() };
        assert_eq!(serde_json::from_str::<Health>(&serde_json::to_string(&new).unwrap()).unwrap(), new, "the wire stays v1: the caps are a list");
    }

    /// S10 (M2, L10): `park_v1` beside S7's to S9's caps, named by its
    /// stage. The four park frames are known kinds, before the sentinel;
    /// every field of theirs is required, and a reason from a later shim
    /// reads as `other`. The park's two limits are the plan's.
    #[test]
    fn the_s10_cap_is_additive_and_named_by_stage() {
        assert_eq!(CAP_PARK_V1, "park_v1");
        let caps = [CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1, CAP_PARK_V1];
        assert_eq!(caps.iter().collect::<std::collections::BTreeSet<_>>().len(), caps.len(), "unique");
        assert_eq!(caps.map(cap_stage), ["S7", "S8", "S9", "S9", "S10"]);
        assert_eq!(cap_stage("park_v2"), "this ai-env");
        assert_eq!(KINDS[KINDS.len() - 5..], ["park", "parked", "park_refused", "unpark", "_"]);
        let park = format!("{{\"v\":1,\"t\":\"park\",\"spawn_id\":\"{SID}\",\"grace_s\":30600,\"min_quiet_s\":30,\"cpu_busy_ms\":500,\"hold_output\":false,\"owner\":{{\"pid\":51234,\"started\":1792483200}}}}");
        let want = Frame::Park { spawn_id: sid(), grace_s: 30_600, min_quiet_s: 30, cpu_busy_ms: 500, hold_output: false, owner: owner() };
        assert_eq!((Frame::from_json(&park).unwrap(), want.to_json()), (want, park.clone()));
        for field in ["spawn_id", "grace_s", "min_quiet_s", "cpu_busy_ms", "hold_output", "owner"] {
            let mut v: serde_json::Value = serde_json::from_str(&park).unwrap();
            v.as_object_mut().unwrap().remove(field);
            assert!(matches!(Frame::from_json(&v.to_string()), Err(WireError::Json(_))), "a park without {field} is malformed");
        }
        let mut no_started: serde_json::Value = serde_json::from_str(&park).unwrap();
        no_started["owner"].as_object_mut().unwrap().remove("started");
        assert!(matches!(Frame::from_json(&no_started.to_string()), Err(WireError::Json(_))), "an owner without its start is malformed");
        for (t, fields) in [("parked", "\"quiet_s\":1"), ("park_refused", "\"reason\":\"busy\",\"quiet_s\":1,\"procs\":0")] {
            let short = format!("{{\"v\":1,\"t\":\"{t}\",\"spawn_id\":\"{SID}\",{fields}}}");
            assert!(matches!(Frame::from_json(&short), Err(WireError::Json(_))), "{t} without its last field is malformed");
        }
        let words = [ParkRefusal::Busy, ParkRefusal::Output, ParkRefusal::Unacked, ParkRefusal::NotAttached, ParkRefusal::Other].map(|r| serde_json::to_string(&r).unwrap());
        assert_eq!(words, ["\"busy\"", "\"output\"", "\"unacked\"", "\"not_attached\"", "\"other\""]);
        let later = format!("{{\"v\":1,\"t\":\"park_refused\",\"spawn_id\":\"{SID}\",\"reason\":\"from_the_future\",\"quiet_s\":0,\"procs\":0,\"cpu_ms\":0}}");
        assert!(matches!(Frame::from_json(&later).unwrap(), Frame::ParkRefused { reason: ParkRefusal::Other, .. }));
        assert_eq!((PARK_GRACE_MAX_S, PARKED_IDLE_MAX), (8 * 3600 + 3600, Duration::from_secs(24 * 3600)));
        const { assert!(PARK_GRACE_MAX_S > DETACH_GRACE_SESSION_S && PARKED_IDLE_MAX.as_secs() > IDLE_MAX_S as u64) };
    }

    /// The park frames' `Debug`: the kind, the spawn id and the numbers
    /// (a refusal's reason by its name), nothing else.
    #[test]
    fn park_frames_debug_shows_ids_and_numbers_only() {
        let all = every_variant();
        let park = &all[all.len() - 4..];
        let shown: Vec<String> = park.iter().map(|f| format!("{f:?}")).collect();
        assert_eq!(
            shown,
            [
                format!("park({SID}, grace_s=30600, min_quiet_s=30, cpu_busy_ms=500, hold_output=false, owner_pid=51234, owner_started=1792483200)"),
                format!("parked({SID}, quiet_s=600, procs=0)"),
                format!("park_refused({SID}, Busy, quiet_s=300, procs=1, cpu_ms=2350)"),
                format!("unpark({SID})"),
            ]
        );
        for f in park {
            assert_eq!(f.spawn_id(), Some(&sid()), "{} names its spawn", f.kind());
        }
    }

    /// S10's two reply fields (no cap: a reader may ignore them):
    /// `Health.mem_total_mib` and `SpawnDetail.parked` are left out when
    /// absent, so an older shim's document reads as `None` and is written
    /// back byte for byte; when set they come last, and `/health/detail`
    /// carries the memory in its flattened `Health`.
    #[test]
    fn the_s10_reply_fields_are_additive() {
        let older = "{\"status\":\"ok\",\"shim_version\":\"0.1.0\",\"claude_version\":null,\"microvm_id\":null,\"owner\":null,\"created\":null,\"boot_nonce\":null,\"run_hook_seen\":true,\"uptime_s\":3,\"wire\":1,\"caps\":[\"credential_cache\"]}";
        let h: Health = serde_json::from_str(older).unwrap();
        assert_eq!(h.mem_total_mib, None);
        assert_eq!(serde_json::to_string(&h).unwrap(), older, "byte-identical for an S9 reader");
        let with = Health { mem_total_mib: Some(2048), ..h };
        let json = serde_json::to_string(&with).unwrap();
        assert!(json.ends_with(",\"caps\":[\"credential_cache\"],\"mem_total_mib\":2048}"), "{json}");
        assert_eq!(serde_json::from_str::<Health>(&json).unwrap(), with);
        let d: HealthDetail = serde_json::from_value(serde_json::json!({
            "status": "ok", "shim_version": "0.1.0", "run_hook_seen": true, "uptime_s": 1, "mem_total_mib": 2048, "hook_source": "peer", "agent_guard": "on",
            "refused_peers": {}, "hook_peers": {}, "sockets_open": 0, "sockets_authenticated": 0, "spawns": [], "has_credentials": false, "listeners": [],
        }))
        .unwrap();
        assert_eq!(d.health.mem_total_mib, Some(2048), "the detail's flattened Health");
        let spawn = SpawnDetail { status: status(), started_at: "2026-10-20T08:00:00Z".into(), detach_left_s: None, frozen: true, group_alive: false, parked: None };
        let before = serde_json::to_string(&spawn).unwrap();
        assert!(!before.contains("parked") && before.ends_with(",\"frozen\":true}"), "left out while not parked: {before}");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&before).unwrap(), spawn);
        let parked = SpawnDetail { parked: Some(owner()), ..spawn };
        let json = serde_json::to_string(&parked).unwrap();
        assert!(json.ends_with(",\"frozen\":true,\"parked\":{\"pid\":51234,\"started\":1792483200}}"), "{json}");
        assert_eq!(serde_json::from_str::<SpawnDetail>(&json).unwrap(), parked);
    }

    /// S11 (index §1, A §11.3, C §X.1): four caps beside S7's to S10's, each
    /// named by its stage; the nine are unique; a later one names no stage;
    /// an S10 `Health` without them reads and is written as before.
    #[test]
    fn the_s11_caps_are_additive_and_named_by_stage() {
        let s11 = [CAP_CODEOUT_MANIFEST_V1, CAP_VIEW_PARENT_V1, CAP_TRANSCRIPT_GZIP_V1, CAP_CLAUDE_STAGE_V1];
        assert_eq!(s11, ["codeout_manifest_v1", "view_parent_v1", "transcript_gzip_v1", "claude_stage_v1"]);
        let all = [CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1, CAP_PARK_V1, CAP_CODEOUT_MANIFEST_V1, CAP_VIEW_PARENT_V1, CAP_TRANSCRIPT_GZIP_V1, CAP_CLAUDE_STAGE_V1];
        assert_eq!(all.iter().collect::<std::collections::BTreeSet<_>>().len(), 9, "unique");
        assert_eq!(all.map(cap_stage), ["S7", "S8", "S9", "S9", "S10", "S11", "S11", "S11", "S11"]);
        assert_eq!(cap_stage("codeout_manifest_v2"), "this ai-env");
        let s10 = "{\"status\":\"ok\",\"shim_version\":\"0.1.0\",\"claude_version\":\"2.1.305\",\"microvm_id\":null,\"owner\":null,\"created\":null,\"boot_nonce\":null,\"run_hook_seen\":true,\"uptime_s\":3,\"wire\":1,\"caps\":[\"credential_cache\",\"workspace_v1\",\"git_http_v1\",\"transcript_s3_v1\",\"park_v1\"]}";
        let h: Health = serde_json::from_str(s10).unwrap();
        assert!(s11.iter().all(|c| !h.caps.iter().any(|have| have == c)));
        assert_eq!(serde_json::to_string(&h).unwrap(), s10, "byte-identical for an S10 reader");
        let mut caps = h.caps.clone();
        caps.extend(s11.map(str::to_string));
        let new = Health { caps, ..h.clone() };
        assert_eq!(serde_json::from_str::<Health>(&serde_json::to_string(&new).unwrap()).unwrap(), new, "the wire stays v1: the caps are a list");
        assert_eq!(new.caps[..5], h.caps[..], "an S10 shim's list is a prefix of an S11 one's");
    }

    /// S11 (A §1.5): `spawn.claude` and `spawned.claude_sha256` are
    /// additive: an S10 `spawned` parses (both fields absent) and is written
    /// back byte for byte; a spawn naming no ref is written as S10's; set,
    /// each comes last and round-trips.
    #[test]
    fn the_s11_spawn_fields_are_additive() {
        let s10 = format!("{{\"v\":1,\"t\":\"spawned\",\"spawn_id\":\"{SID}\",\"pid\":42,\"pgid\":42,\"claude_version\":\"2.1.305\"}}");
        let f = Frame::from_json(&s10).unwrap();
        assert!(matches!(&f, Frame::Spawned { claude_version: Some(v), claude_sha256: None, .. } if v == "2.1.305"));
        assert_eq!(f.to_json(), s10, "byte-identical for an S10 Mac");
        let cached = Frame::Spawned { spawn_id: sid(), pid: 42, pgid: 42, claude_version: Some("2.1.308".into()), claude_sha256: Some("5a".repeat(32)) };
        assert!(cached.to_json().ends_with(&format!(",\"claude_version\":\"2.1.308\",\"claude_sha256\":\"{}\"}}", "5a".repeat(32))), "{}", cached.to_json());
        assert_eq!(Frame::from_json(&cached.to_json()).unwrap(), cached);
        let bare = Frame::Spawn { spawn_id: sid(), argv: vec!["claude".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(900), credential: None, claude: Vec::new() };
        let s10_spawn = format!("{{\"v\":1,\"t\":\"spawn\",\"spawn_id\":\"{SID}\",\"argv\":[\"claude\"],\"env\":{{}},\"deliver_secret\":\"fd\",\"detach_grace_s\":900}}");
        assert_eq!(bare.to_json(), s10_spawn, "no refs: S10's spawn");
        assert_eq!(Frame::from_json(&s10_spawn).unwrap(), bare);
        let refs = vec![ClaudeRef { version: "2.1.308".into(), sha256: "5a".repeat(32) }, ClaudeRef { version: "2.1.307".into(), sha256: "6b".repeat(32) }];
        let named = Frame::Spawn { spawn_id: sid(), argv: vec!["claude".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: Some(900), credential: None, claude: refs.clone() };
        let json = named.to_json();
        assert!(json.ends_with(&format!(",\"claude\":[{{\"version\":\"2.1.308\",\"sha256\":\"{}\"}},{{\"version\":\"2.1.307\",\"sha256\":\"{}\"}}]}}", "5a".repeat(32), "6b".repeat(32))), "{json}");
        assert!(matches!(Frame::from_json(&json).unwrap(), Frame::Spawn { claude, .. } if claude == refs));
    }

    /// S11 (A §1.5): a spawn's `Debug` counts its refs and never names a
    /// version or a sha256; a `spawned`'s is unchanged.
    #[test]
    fn spawn_debug_shows_the_ref_count_only() {
        let all = every_variant();
        let spawn = format!("{:?}", all[3]);
        assert!(spawn.ends_with(", claude=1)"), "{spawn}");
        assert!(!spawn.contains("2.1.308") && !spawn.contains(&"5a".repeat(32)), "{spawn}");
        let spawned = format!("{:?}", all[4]);
        assert_eq!(spawned, format!("spawned({SID}, pid=42, pgid=42)"));
        let Frame::Spawn { claude, .. } = &all[3] else { panic!("spawn") };
        let three = Frame::Spawn { claude: vec![claude[0].clone(); 3], spawn_id: sid(), argv: vec!["claude".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: None };
        assert!(format!("{three:?}").ends_with(", credential=None, claude=3)"), "{three:?}");
    }

    /// S8 changes neither earlier golden conversation: both files are pinned
    /// by their sha256 (public known-answers of the committed files, not
    /// credentials), so a change to the S6 or S7 wire would show here. S9's
    /// 38 codeport documents are pinned the same way, in
    /// `wire::workspace`'s `golden_codeport_documents_round_trip_byte_identically`.
    #[test]
    fn the_s6_and_s7_goldens_stay_byte_identical() {
        use sha2::{Digest, Sha256};
        let pinned: [(&str, &[u8], &str); 2] = [
            ("exec-golden.jsonl", include_bytes!("../../tests/fixtures/wire/exec-golden.jsonl"), "bc13c39eca1b9979eff83aba3347a8a9bd9b658425084d3b933d3cc16468dfab"),
            ("cred-golden.jsonl", include_bytes!("../../tests/fixtures/wire/cred-golden.jsonl"), "53dc8e29c4b27a354cc3927e0680159262ffd05670ef571caee856a1ab8e0ff6"),
        ];
        for (name, bytes, sha) in pinned {
            assert_eq!(hex::encode(Sha256::digest(bytes)), sha, "{name} changed");
        }
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

    /// The golden park conversation (S10, tests/fixtures/wire/park-golden.jsonl):
    /// a `hello_ok` naming `park_v1`; a spawn and a turn of stdio with its
    /// acks; a `park` refused by the busy check; a `park` answered `parked`;
    /// an `unpark` with a `ping` and its `pong`; stdin after it; a second
    /// `parked`; then a second socket's `hello` resuming the spawn (`ok`,
    /// which unparks), `stdin_eof` and the exit. Every line parses as v1 and
    /// serialises back byte-identically, each kind comes from the side that
    /// sends it, every S10 kind is there, and each names the one spawn. Both
    /// ends replay it (`tests/shim_local.rs`, `agent/session.rs`). Messages
    /// name the line by its number in the file.
    #[test]
    fn golden_park_conversation_round_trips() {
        let text = include_str!("../../tests/fixtures/wire/park-golden.jsonl");
        let mut frames: Vec<Frame> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {n}: {e}"));
            let dir = v["dir"].as_str().unwrap_or_default().to_string();
            // The frame's own text, in its original key order (`{"dir":…,"frame":<frame>}`).
            let raw = line.split_once(",\"frame\":").and_then(|(_, rest)| rest.strip_suffix('}')).unwrap_or_else(|| panic!("line {n}: no frame"));
            let f = Frame::from_json(raw).unwrap_or_else(|e| panic!("line {n}: {e}"));
            assert!(f.to_json() == raw, "line {n} ({}): not byte-identical once re-serialised", f.kind());
            match (dir.as_str(), &f) {
                ("mac", Frame::Hello { .. } | Frame::Spawn { .. } | Frame::Stdin { .. } | Frame::StdinEof { .. } | Frame::Ack { .. } | Frame::Ping { .. } | Frame::Park { .. } | Frame::Unpark { .. }) => {}
                ("vm", Frame::HelloOk { caps, .. }) => assert!(caps.iter().any(|c| c == CAP_PARK_V1), "line {n}: the shim names {CAP_PARK_V1}"),
                ("vm", Frame::Spawned { .. } | Frame::StdinAck { .. } | Frame::Stdout { .. } | Frame::Pong { .. } | Frame::Parked { .. } | Frame::ParkRefused { .. } | Frame::Exit { .. }) => {}
                _ => panic!("line {n}: {dir} does not send {}", f.kind()),
            }
            frames.push(f);
        }
        let park_kinds = ["park", "parked", "park_refused", "unpark"];
        for kind in park_kinds {
            assert!(frames.iter().any(|f| f.kind() == kind), "{kind} missing");
        }
        let id = frames.iter().find_map(|f| if let Frame::Spawn { spawn_id, .. } = f { Some(spawn_id.clone()) } else { None }).expect("a spawn");
        assert!(frames.iter().filter(|f| park_kinds.contains(&f.kind())).all(|f| f.spawn_id() == Some(&id)), "every park frame names the one spawn");
        assert!(frames.iter().any(|f| matches!(f, Frame::ParkRefused { reason: ParkRefusal::Busy, .. })), "a park refused by the busy check");
        assert_eq!(frames.iter().filter(|f| f.kind() == "parked").count(), 2, "parked twice");
        let at = frames.iter().position(|f| f.kind() == "unpark").expect("an unpark");
        assert!(matches!((&frames[at + 1], &frames[at + 2]), (Frame::Ping { ts: a }, Frame::Pong { ts: b }) if a == b), "an unpark goes with a ping, and its pong proves the socket");
        assert!(frames[at..].iter().any(|f| matches!(f, Frame::Stdin { .. })), "stdin after the unpark");
        let last = frames.iter().rposition(|f| f.kind() == "parked").expect("parked");
        let resumed = frames[last..].iter().position(|f| matches!(f, Frame::HelloOk { resumed, .. } if resumed.len() == 1 && resumed[0].spawn_id == id && resumed[0].status == ResumeStatus::Ok));
        let resumed = resumed.expect("a second socket's hello resumes the parked spawn") + last;
        assert!(frames[resumed..].iter().any(|f| matches!(f, Frame::StdinEof { .. })) && frames[resumed..].iter().any(|f| matches!(f, Frame::Exit { .. })), "stdin_eof and the exit after it");
    }

    /// The golden claude spawn (S11, tests/fixtures/wire/claude-golden.jsonl,
    /// LD-33): a `hello`; a `hello_ok` naming `claude_stage_v1`; a spawn
    /// naming two refs; its `spawned` naming the first ref's version and
    /// sha256; a stdout chunk and its ack; the exit. Every line parses as v1
    /// and serialises back byte-identically, each kind from the side that
    /// sends it.
    #[test]
    fn golden_claude_spawn_round_trips() {
        let text = include_str!("../../tests/fixtures/wire/claude-golden.jsonl");
        let mut frames: Vec<Frame> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("line {n}: {e}"));
            let dir = v["dir"].as_str().unwrap_or_default().to_string();
            let raw = line.split_once(",\"frame\":").and_then(|(_, rest)| rest.strip_suffix('}')).unwrap_or_else(|| panic!("line {n}: no frame"));
            let f = Frame::from_json(raw).unwrap_or_else(|e| panic!("line {n}: {e}"));
            assert!(f.to_json() == raw, "line {n} ({}): not byte-identical once re-serialised", f.kind());
            match (dir.as_str(), &f) {
                ("mac", Frame::Hello { .. } | Frame::Spawn { .. } | Frame::Ack { .. }) => {}
                ("vm", Frame::HelloOk { caps, .. }) => assert!(caps.iter().any(|c| c == CAP_CLAUDE_STAGE_V1), "line {n}: the shim names {CAP_CLAUDE_STAGE_V1}"),
                ("vm", Frame::Spawned { .. } | Frame::Stdout { .. } | Frame::Exit { .. }) => {}
                _ => panic!("line {n}: {dir} does not send {}", f.kind()),
            }
            frames.push(f);
        }
        assert_eq!(frames.iter().map(Frame::kind).collect::<Vec<_>>(), ["hello", "hello_ok", "spawn", "spawned", "stdout", "ack", "exit"]);
        let Frame::Spawn { claude, .. } = &frames[2] else { panic!("a spawn") };
        assert!(claude.len() == 2 && claude.len() <= crate::wire::workspace::CLAUDE_REFS_MAX && claude.iter().all(|r| r.check().is_ok()), "{claude:?}");
        let Frame::Spawned { claude_version, claude_sha256, .. } = &frames[3] else { panic!("spawned") };
        assert_eq!((claude_version.as_deref(), claude_sha256.as_deref()), (Some(claude[0].version.as_str()), Some(claude[0].sha256.as_str())), "the first ref ran");
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
            mem_total_mib: None,
        };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.starts_with("{\"status\":\"ok\",\"shim_version\":\"0.1.0\""), "{s}");
        assert!(!s.contains("wire"), "an absent wire is not written (an older Mac reads the document unchanged): {s}");
        assert_eq!(serde_json::from_str::<Health>(&s).unwrap(), h);
        let v1 = Health { wire: Some(WIRE_VERSION), ..h };
        assert_eq!(serde_json::from_str::<Health>(&serde_json::to_string(&v1).unwrap()).unwrap(), v1);
    }
}
