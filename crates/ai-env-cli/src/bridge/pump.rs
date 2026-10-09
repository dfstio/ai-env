//! The S2 NDJSON pump: with `AI_ENV_BRIDGE_MODE=local-child|local-scratch` a
//! stream-json session is no longer exec'd — the wrapper spawns the real
//! binary as a piped child and stands between it and the extension.
//!
//! What it does, per line:
//! * host stdin → child stdin, byte-for-byte, recorded by
//!   `bridge::hoststate` (initialize, state requests, pending ids,
//!   outstanding user lines);
//! * child stdout → host stdout, classified by `wire::claude`:
//!   `transcript_mirror` frames go to `bridge::mirror` and are NEVER
//!   forwarded; `oauth_token_refresh` / `host_auth_token_refresh` requests
//!   are answered locally with a null token and never forwarded (the
//!   extension would throw); a gen-1 resume-miss `result` is held until the
//!   child's exit decides between a seed retry (dropped) and propagation;
//!   everything else is forwarded or, after a respawn, rewritten/swallowed as
//!   `hoststate` decides;
//! * child stderr → the wrapper's stderr as a raw byte copy (never re-framed:
//!   the extension shows its last 2048 bytes on a non-zero exit).
//!
//! Concurrency (one current-thread tokio runtime, built only here): every
//! I/O direction is its own task behind a bounded channel — host stdin
//! reader, host stdout writer, child stdin writer, child stdout reader, child
//! stderr copy, child waiter/signaller. The supervisor never awaits a send:
//! it keeps a small queue per direction and offers the head through a
//! `reserve()` future inside its `select!`, and it stops reading a source
//! while the queue towards its sink is not empty. Backpressure therefore
//! propagates end to end (a stalled host stops the child's stdout, a child
//! that does not read stops the host's stdin), and neither stall can block
//! the other direction, the signals or the deadlines.
//!
//! The child is reached through a [`ChildLink`] (an input sender, a signal
//! sender, an event receiver): S2 builds it over a local process
//! ([`spawn_local`]); S8 builds the same link over the MicroVM WebSocket
//! (`RemoteLink`, moved there from S6 by its D5: `spawn_next` then needs an
//! async link seam, and a refused remote spawn a [`ChildEvent`] of its own,
//! never `Exit(None)`, so the [`EndReason`]s keep their meaning).
//!
//! Timing (plan D22): host stdin EOF → child stdin closed → SIGTERM at
//! +800 ms → SIGKILL at +1200 ms → hard stop at +1400 ms → exit ≤ 1500 ms;
//! SIGTERM to the wrapper → SIGTERM the child now → SIGKILL at +600 ms →
//! hard stop at +900 ms → exit ≤ 1000 ms. The queued lines' flush to the
//! host never outlives the hard stop. When the child ends on its own while
//! the host still reads, its remaining output is drained eagerly and the
//! host gets up to 5 s to take it. At the end the mirror is fsync'ed, the
//! registry row closed and a second census row (the start row + `end`,
//! `exit`, a note) appended before `process::exit`.
//!
//! Lines are split at the CLI's own limit (256 MiB, `CLI_LINE_BYTES`): a user
//! message with pasted images or a transcript entry holding them passes as
//! the CLI would take it (the agent transport carries byte chunks, S6).
//!
//! `local-scratch` logs its child in with the sealed setup-token (S7,
//! [`scratch_login`]): when `CLAUDE_CODE_OAUTH_TOKEN` is not in the
//! environment, `credentials/setup-token.env` is unsealed before the spawn
//! (one Touch ID, the countdown on stderr, `[creds].unseal_timeout_s` — but
//! never past T−10 s of Cursor's 60 s initialize window, which runs while the
//! child does not exist yet: [`scratch_unseal_budget`]) and handed to the
//! child on fd 3 — or in its environment only, with `[creds] deliver =
//! "env"` — never in argv or on disk; the wrapper's copy is dropped once no
//! child generation can need it. Anything that keeps the token from the
//! child (none sealed, a refused seal, a dismissed dialog, the deadline) is
//! one note line, and the child runs logged out: the session is never
//! blocked or failed for it. SIGINT (130), SIGTERM and SIGHUP (143) during
//! the wait close the dialog (age runs in its own process group) and end the
//! wrapper. Every piped invocation pays its own Touch ID: Cursor's config
//! probe, whose argv is a chat's, included.
//!
//! A debug-build lab knob, [`SYNTHETIC_OAUTH_KNOB`], probes the extension's
//! side of Tier B: once the session is initialized the pump sends the host one
//! `oauth_token_refresh` request of its own and records the class of the
//! answer in the end row (`synthetic_oauth:<class>`); the answer is never
//! forwarded to the child.
use crate::age_cmd::{AgeKill, AgeTool};
use crate::bridge::agent::credential::{read_rejection, tag_of};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::census::{self, CensusRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::hoststate::{ChildVerdict, HostState};
use crate::bridge::lab::{self, PumpKnobs};
use crate::bridge::logging::{self, LogOpts};
use crate::bridge::mirror::{self, MirrorCfg, Writer};
use crate::bridge::registry::{self, SessionRow};
use crate::bridge::route::Mode;
use crate::bridge::seed;
use crate::bridge::setup_token::{parse_token_env, sealed_text, SetupToken, TOKEN_VAR};
use crate::bridge::unseal::UnsealJob;
use crate::errors::CliError;
use crate::store::{validate_key_name, Keystore};
use crate::wire::argv::{self, Route, SanitiseOpts, SessionArgs};
use crate::wire::claude::{self, ChildFrame, HostFrame};
use crate::wire::frame::Deliver;
use crate::wire::ndjson::{encode_line, LineError, LineSplitter, CLI_LINE_BYTES};
use crate::wire::redact::{self, Secret};
use crate::wire::slug;
use crate::wire::time::unix_now_ms;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Capacity of every channel between the supervisor and an I/O task.
pub const CHANNEL_CAP: usize = 64;
/// After host stdin EOF (the child's stdin is closed at once): SIGTERM the child.
pub const EOF_TERM_AFTER: Duration = Duration::from_millis(800);
/// After host stdin EOF: SIGKILL the child.
pub const EOF_KILL_AFTER: Duration = Duration::from_millis(1200);
/// After SIGTERM to the wrapper (forwarded at once): SIGKILL the child.
pub const SIGTERM_KILL_AFTER: Duration = Duration::from_millis(600);
/// After the child's exit: how long its stdout/stderr may still drain.
pub const EXIT_DRAIN: Duration = Duration::from_millis(200);
/// A respawned child must answer the replayed requests within this.
pub const REPLAY_DEADLINE: Duration = Duration::from_secs(15);
/// At the end of a closing session: how long queued lines may take to reach the host.
pub const FLUSH_DEADLINE: Duration = Duration::from_millis(250);
/// When the child ended on its own and the host still reads: how long the
/// host may take to read the rest (a host EOF or SIGTERM shortens it).
pub const FLUSH_OPEN_DEADLINE: Duration = Duration::from_secs(5);
/// After host stdin EOF: finish no matter what (exit budget 1500 ms).
pub const EOF_HARD_STOP: Duration = Duration::from_millis(1400);
/// After SIGTERM to the wrapper: finish no matter what (exit budget 1000 ms).
pub const SIGTERM_HARD_STOP: Duration = Duration::from_millis(900);
/// Longest line the pump passes (the CLI's own stream-json limit).
pub const PUMP_LINE_CAP: usize = CLI_LINE_BYTES;
/// While closing, lines queued for a host that stopped reading beyond this
/// many are dropped (counted), so the child's exit is still observed.
pub const CLOSING_QUEUE_CAP: usize = 1024;
/// The environment variable that points the mirror writer elsewhere.
pub const MIRROR_ROOT_ENV: &str = "AI_ENV_BRIDGE_MIRROR_ROOT";
/// Removed from a scratch child's environment: it would re-point the scratch
/// child's secure storage at the host's keychain entry.
pub const SECURE_STORAGE_ENV: &str = "CLAUDE_SECURESTORAGE_CONFIG_DIR";
/// Names the child's token descriptor under fd delivery
/// (`<TOKEN_VAR>_FILE_DESCRIPTOR`, as the shim sets it in a VM).
pub const TOKEN_FD_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
/// The descriptor a `local-scratch` child reads the token from.
const TOKEN_FD: libc::c_int = 3;
/// `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS=<n>` (debug builds only): once the
/// session is initialized, send the extension one `oauth_token_refresh`
/// request and wait at most `n` ms for its answer (`10000` from Cursor). Its
/// value is not allowlisted in the census (the name holds `AUTH`): the
/// name shows in `env_names`, the answer's class in the end row.
pub const SYNTHETIC_OAUTH_KNOB: &str = "AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS";
/// `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` (debug builds only): the budget of
/// the `local-scratch` unseal in ms, in place of `[creds].unseal_timeout_s`
/// (whose range starts at 10 s), so a test reaches the deadline at once.
/// `bridge::lab::vm_knobs` reads the same knob as the budget of every unseal
/// a credentialed `vm` or `lab` command makes.
pub const UNSEAL_TIMEOUT_KNOB: &str = "AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS";
/// How often the wrapper looks for a signal while Touch ID is awaited.
const UNSEAL_POLL: Duration = Duration::from_millis(25);
/// A signal while Touch ID is awaited: how long after it the wrapper waits,
/// at most, for the decrypt to be over before it exits. The decrypt answers
/// only once it gave up before spawning `age`, or killed and reaped it: a stop
/// that came while `age` was being spawned, before the kill could reach its
/// group, would otherwise exit first and leave the dialog up with nobody to
/// close it (`AgeKill` kills such a child as it adopts it, which needs the
/// process alive). The answer normally takes tens of ms; the bound keeps the
/// stop within the 1 s a SIGTERM may take.
const STOP_SETTLE: Duration = Duration::from_millis(800);
/// Cursor closes the channel when `initialize` is not answered within this
/// much of the wrapper's spawn (v6 §3.1).
pub const INITIALIZE_WINDOW: Duration = Duration::from_secs(60);
/// The `local-scratch` unseal gives up this long before [`INITIALIZE_WINDOW`]
/// closes (v6 §2.8, "fail fast at T−10 s"), so a logged-out child still has
/// the rest to start and answer `initialize`.
pub const INIT_FAIL_FAST: Duration = Duration::from_secs(10);
/// How long after generation 1 of a `--resume` answered `initialize` the
/// token copy is kept for the seed retry. The CLI reports a resume miss
/// synchronously at startup, while its first `system/init` comes with the
/// first turn: holding the copy until that init would keep it for as long as
/// a resumed chat sits idle.
const RESUME_MISS_GRACE: Duration = Duration::from_secs(2);
/// The most of an error text the end row keeps from the extension's answer.
const SYNTHETIC_ERROR_CHARS: usize = 160;

const READ_CHUNK: usize = 64 * 1024;

/// A `_MS` lab knob's value: a positive number of milliseconds; unset, `0`
/// and anything unparseable are off (a lab knob never breaks a session).
#[must_use]
pub fn parse_ms_knob(value: Option<&str>) -> Option<Duration> {
    value.and_then(|v| v.trim().parse::<u64>().ok()).filter(|ms| *ms > 0).map(Duration::from_millis)
}

/// A `_MS` lab knob from the environment (debug builds only, as `bridge::lab`'s).
#[cfg(debug_assertions)]
fn ms_knob(name: &str) -> Option<Duration> {
    parse_ms_knob(std::env::var(name).ok().as_deref())
}

/// Release builds: every knob off, whatever the environment says.
#[cfg(not(debug_assertions))]
fn ms_knob(_name: &str) -> Option<Duration> {
    None
}

/// Everything `ai-env-claude` knew when it decided to pipe this invocation.
#[derive(Debug, Clone)]
pub struct Session {
    pub real_binary: PathBuf,
    /// The CLI arguments after argv[1], verbatim.
    pub args: Vec<String>,
    pub route: Route,
    pub session: SessionArgs,
    pub cwd: Option<PathBuf>,
    pub paths: Paths,
    /// Unused by the local modes; S8 reads the VM settings from it.
    pub cfg: Option<BridgeConfig>,
    pub mode: Mode,
    /// The census row already written for this invocation (the end row clones it).
    pub start_row: CensusRow,
}

/// How the child is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPlan {
    pub program: PathBuf,
    /// `argv::sanitise` with nothing stripped: the host's argv + one `--session-mirror`.
    pub argv: Vec<String>,
    pub env_set: Vec<(String, OsString)>,
    pub env_remove: Vec<String>,
    /// The child's `CLAUDE_CONFIG_DIR` (inherited for local-child).
    pub child_config_dir: PathBuf,
    /// `local-scratch`: the scratch config dir to create before the spawn.
    pub scratch: Option<PathBuf>,
    /// The `--resume=<uuid>` value, when it is a uuid.
    pub resume: Option<String>,
    /// The child's projects subdirectory for this cwd.
    pub slug: Option<String>,
    pub mirror: MirrorCfg,
}

/// `CLAUDE_CODE_PROJECT_DIR_NAME` when the CLI would honour it (only with
/// `CLAUDE_CONFIG_DIR` set), else the slug of the canonical cwd — the
/// directory under `<config dir>/projects` the child writes its transcript to.
#[must_use]
pub fn child_slug(cwd: Option<&Path>, config_dir_set: bool, override_name: Option<&str>) -> Option<String> {
    slug::override_dir_name(config_dir_set, override_name).or_else(|| cwd.and_then(|c| slug::project_dir_name(c).ok()))
}

/// `remote` | `local:<reason>` for the registry row.
#[must_use]
pub fn route_label(route: &Route) -> String {
    match route {
        Route::Remote(_) => "remote".to_string(),
        Route::Local(r) => format!("local:{}", r.name()),
    }
}

/// The child plan, from the session and an environment lookup (the wrapper's
/// own environment in production). Pure apart from `canonicalize` inside the
/// slug and mirror decisions; the scratch dir is only named here.
pub fn child_plan(sess: &Session, env: &dyn Fn(&str) -> Option<OsString>, fresh_id: &mut dyn FnMut() -> String) -> Result<ChildPlan, String> {
    let argv = argv::sanitise(&sess.args, SanitiseOpts { strip_add_dir: false, strip_debug: false }).map_err(|e| e.to_string())?;
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    let mac_config_dir = match nonempty("CLAUDE_CONFIG_DIR") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(nonempty("HOME").ok_or("HOME is not set")?).join(".claude"),
    };
    let resume = sess.session.resume.clone().filter(|r| registry::is_uuid(r));
    let override_name = env("CLAUDE_CODE_PROJECT_DIR_NAME").map(|v| v.to_string_lossy().into_owned());
    let mirror_root = nonempty(MIRROR_ROOT_ENV).map(PathBuf::from);
    let (child_config_dir, scratch, env_set, env_remove, config_dir_set) = match sess.mode {
        Mode::LocalScratch => {
            let name = resume.clone().unwrap_or_else(fresh_id);
            let dir = sess.paths.scratch().join(name);
            // The scratch child's login is the wrapper's to decide (S7): an inherited descriptor
            // number names nothing this wrapper set up, so only `spawn_local`'s fd delivery sets one.
            (dir.clone(), Some(dir.clone()), vec![("CLAUDE_CONFIG_DIR".to_string(), dir.into_os_string())], vec![SECURE_STORAGE_ENV.to_string(), TOKEN_FD_VAR.to_string()], true)
        }
        Mode::LocalChild => (mac_config_dir.clone(), None, Vec::new(), Vec::new(), nonempty("CLAUDE_CONFIG_DIR").is_some()),
        Mode::Passthrough | Mode::Remote => return Err(format!("mode {} does not pipe", sess.mode.name())),
    };
    let slug = child_slug(sess.cwd.as_deref(), config_dir_set, override_name.as_deref());
    let mirror = mirror::decide(matches!(sess.route, Route::Remote(_)), true, &child_config_dir, &mac_config_dir, mirror_root.as_deref());
    Ok(ChildPlan { program: sess.real_binary.clone(), argv, env_set, env_remove, child_config_dir, scratch, resume, slug, mirror })
}

/// Why the pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The child exited on its own.
    ChildExit,
    /// Host stdin closed; the child ended within the ladder (by itself or by our SIGTERM).
    EofTerm,
    /// Host stdin closed; the child needed SIGKILL.
    EofKill,
    /// The wrapper got SIGTERM/SIGINT.
    SigTerm,
    /// The host stopped reading stdout.
    HostGone,
    /// `AI_ENV_BRIDGE_LAB_EXIT=…:after-init`.
    LabExit,
    /// The child could not be spawned.
    SpawnFailed,
}

impl EndReason {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            EndReason::ChildExit => "child_exit",
            EndReason::EofTerm => "eof",
            EndReason::EofKill => "eof_kill",
            EndReason::SigTerm => "sigterm",
            EndReason::HostGone => "host_gone",
            EndReason::LabExit => "lab_exit",
            EndReason::SpawnFailed => "spawn_failed",
        }
    }
}

/// What the end row records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The wrapper's exit code; `None` only for the `IGNORE_EOF=2` row written at SIGTERM.
    pub code: Option<i32>,
    pub end: Option<EndReason>,
    pub child_pid: Option<u32>,
    pub respawns: u32,
    pub mirror_frames: u64,
    pub mirror_rejected: u64,
    pub dropped_lines: u64,
    pub oauth_answered: u64,
    pub init_latency_ms: Option<u64>,
    pub eof_to_sigterm_ms: Option<u64>,
    pub session_id: Option<String>,
    /// `local-scratch` only: how the child was logged in ([`ScratchLogin::word`]);
    /// `none` once the seed retry respawned it after the token copy was
    /// dropped, since that generation runs logged out.
    pub credential: Option<&'static str>,
    /// With [`SYNTHETIC_OAUTH_KNOB`]: the class of the extension's answer
    /// ([`synthetic_answer_class`]), `none` (no answer within the wait) or
    /// `unsent` (the session was never initialized).
    pub synthetic_oauth: Option<String>,
}

/// The census end row: a clone of `start` with `end`, `exit` and the note
/// extended by `end:<reason>; child_pid:<n>; respawns:<n>; mirror:<frames>/<rejected>;
/// dropped:<n>; oauth_refresh_answered:<n>` (+ `init_ms`, `eof_to_sigterm_ms` when known;
/// `credential:<fd|env|inherited|none>` for `local-scratch`; `synthetic_oauth:<class>`
/// with the lab knob).
#[must_use]
pub fn end_row(start: &CensusRow, out: &Outcome, now_ms: u64) -> CensusRow {
    let mut row = start.clone();
    row.end = Some(now_ms);
    row.exit = out.code;
    let mut parts = vec![
        format!("end:{}", out.end.map_or("unknown", EndReason::name)),
        format!("child_pid:{}", out.child_pid.map_or_else(|| "-".to_string(), |p| p.to_string())),
        format!("respawns:{}", out.respawns),
        format!("mirror:{}/{}", out.mirror_frames, out.mirror_rejected),
        format!("dropped:{}", out.dropped_lines),
        format!("oauth_refresh_answered:{}", out.oauth_answered),
    ];
    if let Some(ms) = out.init_latency_ms {
        parts.push(format!("init_ms:{ms}"));
    }
    if let Some(ms) = out.eof_to_sigterm_ms {
        parts.push(format!("eof_to_sigterm_ms:{ms}"));
    }
    if let Some(how) = out.credential {
        parts.push(format!("credential:{how}"));
    }
    if let Some(class) = &out.synthetic_oauth {
        parts.push(format!("synthetic_oauth:{class}"));
    }
    let tail = parts.join("; ");
    row.note = Some(match row.note.take() {
        Some(n) if !n.is_empty() => format!("{n}; {tail}"),
        _ => tail,
    });
    row
}

// ---- the child link ----------------------------------------------------------------------

/// A line (with its `\n`) or the end of the child's stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildInput {
    Line(Bytes),
    Eof,
}

/// A signal for the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Term,
    Kill,
}

/// What the child side reports.
#[derive(Debug)]
pub enum ChildEvent {
    /// One stdout line (without `\n`).
    Line(Bytes),
    /// A stdout line over the CLI's 256 MiB limit was dropped.
    TooLong(usize),
    StdoutEof,
    StderrEof,
    /// The child was reaped (`None`: waiting failed).
    Exit(Option<ExitStatus>),
}

/// The pump's handle on one child: the seam S8's `RemoteLink` reuses with a WebSocket behind it.
#[derive(Debug)]
pub struct ChildLink {
    pub pid: Option<u32>,
    pub input: mpsc::Sender<ChildInput>,
    pub signal: mpsc::UnboundedSender<Sig>,
    pub events: mpsc::Receiver<ChildEvent>,
}

/// Spawn `plan` as a local child with piped stdio and start its four tasks.
/// All three pipes are taken before the waiter owns the process
/// (`Child::wait` would otherwise close stdin), and signals are delivered by
/// the waiter itself, before it has reaped the child, so a signal can never
/// reach a recycled pid.
///
/// `credential` (`local-scratch`, S7): the token goes on fd 3 — a pipe that
/// already holds it, its write end closed, with [`TOKEN_FD_VAR`]`=3` — or, for
/// [`Deliver::Env`], into the child's environment only. Either way the other
/// variable is removed after the plan's own environment is applied, so an
/// inherited empty `CLAUDE_CODE_OAUTH_TOKEN` or a stale descriptor number can
/// never shadow what was delivered.
pub fn spawn_local(plan: &ChildPlan, credential: Option<(&SetupToken, Deliver)>) -> std::io::Result<ChildLink> {
    let mut cmd = tokio::process::Command::new(&plan.program);
    cmd.args(&plan.argv).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    for k in &plan.env_remove {
        cmd.env_remove(k);
    }
    // fd delivery: the pipe holds the value before the child exists.
    let pipe = match credential {
        Some((token, Deliver::Fd)) => Some(secret_pipe(token.expose().as_bytes())?),
        _ => None,
    };
    match credential {
        Some((_, Deliver::Fd)) => {
            cmd.env(TOKEN_FD_VAR, TOKEN_FD.to_string()).env_remove(TOKEN_VAR);
        }
        Some((token, Deliver::Env)) => {
            // std keeps its own (unzeroized) copy until `cmd` is dropped below, as in the shim.
            cmd.env(TOKEN_VAR, token.expose()).env_remove(TOKEN_FD_VAR);
        }
        None => {}
    }
    if let Some(fd) = pipe.as_ref().map(|p| p.as_raw_fd()) {
        // SAFETY: the closure runs in the forked child before exec and makes
        // only async-signal-safe calls (dup2/fcntl) on an integer prepared here.
        unsafe {
            cmd.pre_exec(move || onto_fd3(fd));
        }
    }
    let spawned = cmd.spawn();
    drop(cmd);
    // The parent's read end: the child has its own on fd 3.
    drop(pipe);
    let mut child = spawned?;
    let pid = child.id();
    let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
        return Err(std::io::Error::other("child pipes missing"));
    };
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAP);
    let (sig_tx, sig_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(CHANNEL_CAP);
    tokio::spawn(child_stdin_writer(stdin, in_rx));
    tokio::spawn(child_stdout_reader(stdout, ev_tx.clone()));
    tokio::spawn(child_stderr_copy(stderr, ev_tx.clone()));
    tokio::spawn(child_waiter(child, pid, sig_rx, ev_tx));
    Ok(ChildLink { pid, input: in_tx, signal: sig_tx, events: ev_rx })
}

/// A close-on-exec pipe already holding `value`, its write end closed: the
/// read end, for the child's fd 3 (the twin of the shim's, which this build
/// does not compile). A token is at most 4096 bytes and fits the pipe
/// buffer, so the write never waits for a reader.
fn secret_pipe(value: &[u8]) -> std::io::Result<OwnedFd> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `fds` is an array of two ints for pipe(2) to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and belong to nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        // SAFETY: a valid fd we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    std::io::Write::write_all(&mut std::fs::File::from(write), value)?;
    Ok(read)
}

/// In the forked child: `fd` onto [`TOKEN_FD`], without close-on-exec (a
/// pipe already there only loses the flag). Async-signal-safe.
fn onto_fd3(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain syscalls on integers.
    let rc = unsafe {
        if fd == TOKEN_FD {
            libc::fcntl(TOKEN_FD, libc::F_SETFD, 0)
        } else {
            libc::dup2(fd, TOKEN_FD)
        }
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn child_stdin_writer(mut stdin: tokio::process::ChildStdin, mut rx: mpsc::Receiver<ChildInput>) {
    while let Some(item) = rx.recv().await {
        match item {
            ChildInput::Line(line) => {
                if stdin.write_all(&line).await.is_err() {
                    break;
                }
            }
            ChildInput::Eof => break,
        }
    }
    // Dropping the handle closes the pipe: the child sees EOF.
}

async fn child_stdout_reader(mut out: tokio::process::ChildStdout, tx: mpsc::Sender<ChildEvent>) {
    let mut split = LineSplitter::with_cap(PUMP_LINE_CAP);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let n = match out.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        split.push(&buf[..n]);
        while let Some(r) = split.next_line() {
            if tx.send(line_event(r)).await.is_err() {
                return;
            }
        }
    }
    if let Some(r) = split.finish() {
        let _ = tx.send(line_event(r)).await;
    }
    let _ = tx.send(ChildEvent::StdoutEof).await;
}

fn line_event(r: Result<Bytes, LineError>) -> ChildEvent {
    match r {
        Ok(line) => ChildEvent::Line(line),
        Err(LineError::TooLong { dropped_bytes }) => ChildEvent::TooLong(dropped_bytes),
    }
}

async fn child_stderr_copy(mut err: tokio::process::ChildStderr, tx: mpsc::Sender<ChildEvent>) {
    let mut out = tokio::io::stderr();
    let _ = tokio::io::copy(&mut err, &mut out).await;
    let _ = out.flush().await;
    let _ = tx.send(ChildEvent::StderrEof).await;
}

async fn child_waiter(mut child: tokio::process::Child, pid: Option<u32>, mut sig: mpsc::UnboundedReceiver<Sig>, tx: mpsc::Sender<ChildEvent>) {
    let status = {
        let wait = child.wait();
        tokio::pin!(wait);
        let mut sig_open = true;
        loop {
            tokio::select! {
                biased;
                st = &mut wait => break st.ok(),
                s = sig.recv(), if sig_open => match s {
                    Some(s) => send_signal(pid, s),
                    None => sig_open = false,
                },
            }
        }
    };
    let _ = tx.send(ChildEvent::Exit(status)).await;
}

fn send_signal(pid: Option<u32>, sig: Sig) {
    let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 0) else { return };
    let signo = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
    };
    // SAFETY: kill(2) with a positive pid we spawned and have not reaped yet
    // (the waiter reaps only after this select arm cannot run any more).
    unsafe {
        libc::kill(pid, signo);
    }
}

// ---- host I/O tasks ------------------------------------------------------------------------

#[derive(Debug)]
enum HostIn {
    Line(Bytes),
    TooLong(usize),
    Eof,
}

async fn host_stdin_reader(tx: mpsc::Sender<HostIn>) {
    let mut input = tokio::io::stdin();
    let mut split = LineSplitter::with_cap(PUMP_LINE_CAP);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let n = match input.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        split.push(&buf[..n]);
        while let Some(r) = split.next_line() {
            let item = match r {
                Ok(line) => HostIn::Line(line),
                Err(LineError::TooLong { dropped_bytes }) => HostIn::TooLong(dropped_bytes),
            };
            if tx.send(item).await.is_err() {
                return;
            }
        }
    }
    if let Some(r) = split.finish() {
        let item = match r {
            Ok(line) => HostIn::Line(line),
            Err(LineError::TooLong { dropped_bytes }) => HostIn::TooLong(dropped_bytes),
        };
        let _ = tx.send(item).await;
    }
    let _ = tx.send(HostIn::Eof).await;
}

async fn host_stdout_writer(mut rx: mpsc::Receiver<Bytes>) {
    let mut out = tokio::io::stdout();
    while let Some(line) = rx.recv().await {
        if out.write_all(&line).await.is_err() {
            return;
        }
        if rx.is_empty() && out.flush().await.is_err() {
            return;
        }
    }
    let _ = out.flush().await;
}

async fn recv_opt<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<Option<T>> {
    match rx {
        Some(r) => Some(r.recv().await),
        None => std::future::pending().await,
    }
}

async fn reserve_opt<T>(tx: &Option<mpsc::Sender<T>>) -> Option<mpsc::Permit<'_, T>> {
    match tx {
        Some(t) => t.reserve().await.ok(),
        None => std::future::pending().await,
    }
}

/// What woke the supervisor. The `select!` arms only touch disjoint fields
/// (its futures stay alive while an arm runs); everything else happens on
/// this value afterwards.
#[derive(Debug)]
enum Wake {
    Signal,
    Deadline,
    Sent,
    HostOutClosed,
    ChildInClosed,
    Child(Option<ChildEvent>),
    Host(Option<HostIn>),
}

// ---- the supervisor ----------------------------------------------------------------------

/// The EOF/SIGTERM ladder in progress.
#[derive(Debug, Clone, Copy)]
struct Ladder {
    term_at: Option<Instant>,
    kill_at: Instant,
    /// Finish at this instant even if the child's exit was never observed.
    hard_stop: Instant,
    /// true: host stdin closed (a child that ends after our signal still ends with 0).
    host_initiated: bool,
    /// The ladder sent the child a signal (SIGTERM or SIGKILL).
    signalled: bool,
    killed: bool,
}

struct Pump {
    sess: Session,
    plan: ChildPlan,
    knobs: PumpKnobs,
    after_init: Option<(i32, String)>,
    state: HostState,
    mirror: Writer,
    gen: u32,
    // The current child, split so the select! can borrow the parts independently.
    child_events: Option<mpsc::Receiver<ChildEvent>>,
    child_input: Option<mpsc::Sender<ChildInput>>,
    child_signal: Option<mpsc::UnboundedSender<Sig>>,
    child_pid: Option<u32>,
    spawned_at: Instant,
    child_exit: Option<Option<ExitStatus>>,
    exit_seen_at: Option<Instant>,
    stdout_eof: bool,
    stderr_eof: bool,
    held_miss: Option<Bytes>,
    retries: u32,
    /// Host EOF or SIGTERM seen: never respawn after it.
    close_requested: bool,
    /// The first session id (the scratch dir is renamed after it).
    first_session_id: Option<String>,
    /// A registry row was written at least once.
    registered: bool,
    in_q: VecDeque<ChildInput>,
    out_q: VecDeque<Bytes>,
    host_open: bool,
    host_eof_at: Option<Instant>,
    host_gone: bool,
    ladder: Option<Ladder>,
    delay_until: Option<Instant>,
    replay_deadline: Option<Instant>,
    finish: Option<(i32, EndReason)>,
    /// Decided while the child still runs (the lab exit): applied once it is gone.
    finish_after_child: Option<(i32, EndReason)>,
    finish_deadline: Option<Instant>,
    lab_message: Option<String>,
    noise_done: bool,
    ignored_sigterm_row: bool,
    user_line_seen: bool,
    row: Option<SessionRow>,
    out: Outcome,
    audit_path: PathBuf,
    /// `local-scratch` (S7): the unsealed setup-token, held only until no
    /// child generation can need it ([`Pump::settle_credential`]).
    credential: Option<ChildCredential>,
    /// A `--resume`'s copy goes at this instant: [`RESUME_MISS_GRACE`] after
    /// generation 1 answered `initialize` — unless by then it reported a
    /// resume miss or exited: the copy then stays for the seed retry's
    /// respawn, which gets it, or until the session ends ([`Pump::on_deadline`]).
    credential_hold_until: Option<Instant>,
    /// The synthetic `oauth_token_refresh` probe ([`SYNTHETIC_OAUTH_KNOB`]).
    synthetic: Option<Synthetic>,
}

/// The synthetic `oauth_token_refresh` the pump sends the host itself
/// ([`SYNTHETIC_OAUTH_KNOB`]): sent once, after the first success answer to
/// the host's `initialize` that reaches it, whichever generation gave it (a
/// seed retry's comes rewritten to the host's id); the answer is classified
/// and never forwarded.
#[derive(Debug)]
struct Synthetic {
    /// How long the host has to answer.
    wait: Duration,
    /// The request id, once sent: an answer to it never reaches a child,
    /// however late it comes.
    id: Option<String>,
    sent_at: Option<Instant>,
    /// The answer's class, or `none` once the wait ran out.
    class: Option<String>,
}

impl Synthetic {
    /// The probe, nothing sent yet, when [`SYNTHETIC_OAUTH_KNOB`] is set.
    fn from_knob() -> Option<Synthetic> {
        ms_knob(SYNTHETIC_OAUTH_KNOB).map(|wait| Synthetic { wait, id: None, sent_at: None, class: None })
    }

    /// When the wait runs out, while no class is decided.
    fn deadline(&self) -> Option<Instant> {
        if self.class.is_some() {
            return None;
        }
        self.sent_at.map(|t| t + self.wait)
    }

    /// The end row's class: the decided one, `none` for a request still
    /// unanswered, `unsent` when the session was never initialized.
    fn census(&self) -> String {
        self.class.clone().unwrap_or_else(|| if self.id.is_some() { "none".into() } else { "unsent".into() })
    }
}

impl Pump {
    fn new(sess: Session, plan: ChildPlan, login: Option<ScratchLogin>) -> Pump {
        let audit_path = sess.paths.audit();
        let mirror = Writer::new(plan.mirror.clone());
        let word = login.as_ref().map(ScratchLogin::word);
        let credential = match login {
            Some(ScratchLogin::Sealed(c)) => Some(c),
            _ => None,
        };
        let synthetic = Synthetic::from_knob();
        Pump {
            knobs: lab::pump_knobs(),
            after_init: lab::exit_after_init(),
            state: HostState::new(),
            mirror,
            gen: 0,
            child_events: None,
            child_input: None,
            child_signal: None,
            child_pid: None,
            spawned_at: Instant::now(),
            child_exit: None,
            exit_seen_at: None,
            stdout_eof: false,
            stderr_eof: false,
            held_miss: None,
            retries: 0,
            close_requested: false,
            first_session_id: None,
            registered: false,
            in_q: VecDeque::new(),
            out_q: VecDeque::new(),
            host_open: true,
            host_eof_at: None,
            host_gone: false,
            ladder: None,
            delay_until: None,
            replay_deadline: None,
            finish: None,
            finish_after_child: None,
            finish_deadline: None,
            lab_message: None,
            noise_done: false,
            ignored_sigterm_row: false,
            user_line_seen: false,
            row: None,
            out: Outcome { credential: word, ..Outcome::default() },
            audit_path,
            credential,
            credential_hold_until: None,
            synthetic,
            sess,
            plan,
        }
    }

    fn audit(&self, event: &str, detail: &[(&str, String)]) {
        let row = AuditRow::new(event, self.out.session_id.as_deref(), audit::detail(detail));
        if let Err(e) = audit::append(&self.audit_path, &row) {
            tracing::warn!("audit {event}: {e}");
        }
    }

    /// Drop (zeroize) the setup-token once no child generation can need it:
    /// right after the spawn, unless the one seed retry of a `--resume` may
    /// still respawn — until the first init, [`RESUME_MISS_GRACE`] after
    /// generation 1 answered `initialize` ([`Pump::on_deadline`]) or that
    /// respawn — and always when the session is `finishing`. `why` is logged.
    fn settle_credential(&mut self, finishing: bool, why: &str) {
        if self.credential.is_some() && (finishing || !self.retry_possible()) {
            self.drop_credential(why);
        }
    }

    /// Drop (zeroize) the setup-token now, if it is still held. A token of a
    /// shape the scrubber's rules do not mask whole is masked while its handle
    /// lives (`parse_token` registered it) and no longer: the handle's drop
    /// ends that registration, so the scrubber keeps no plain copy of it for
    /// the rest of the session (as `vm exec`'s delivery forgets its masking
    /// when it drops the value). The wrapper's own lines (its log, audit and
    /// census rows, notes) never quote the token, and the child's output
    /// passes through verbatim, never scrubbed, either way.
    fn drop_credential(&mut self, why: &str) {
        self.credential_hold_until = None;
        if self.credential.take().is_some() {
            tracing::info!(gen = self.gen, "the setup-token copy was dropped ({why})");
        }
    }

    // -- the synthetic oauth_token_refresh (lab knob) -------------------------------------

    /// Send the host the synthetic `oauth_token_refresh` (once, with the knob).
    fn send_synthetic_oauth(&mut self) {
        let Some(s) = self.synthetic.as_mut().filter(|s| s.id.is_none()) else { return };
        let Ok(request) = RawValue::from_string(r#"{"subtype":"oauth_token_refresh"}"#.to_string()) else { return };
        let id = format!("ai-env-synthetic-{}", uuid::Uuid::now_v7());
        s.id = Some(id.clone());
        s.sent_at = Some(Instant::now());
        let wait_ms = s.wait.as_millis() as u64;
        self.forward(&claude::control_request_line(&id, &request));
        tracing::info!(id = %id, wait_ms, "synthetic oauth_token_refresh sent toward the extension");
    }

    /// Is `id` the synthetic request's?
    fn is_synthetic(&self, id: &str) -> bool {
        self.synthetic.as_ref().and_then(|s| s.id.as_deref()) == Some(id)
    }

    /// The host answered the synthetic request: classify it (once) and
    /// never forward it — no child asked.
    fn on_synthetic_answer(&mut self, line: &[u8]) {
        let Some(s) = self.synthetic.as_mut() else { return };
        let ms = s.sent_at.map_or(0, |t| t.elapsed().as_millis() as u64);
        if s.class.is_some() {
            tracing::info!(ms, "synthetic oauth_token_refresh: a late answer was dropped (never forwarded)");
            return;
        }
        let class = synthetic_answer_class(line);
        s.class = Some(class.clone());
        tracing::info!(class = %class, ms, "synthetic oauth_token_refresh answered (never forwarded)");
        self.audit("synthetic_oauth", &[("class", class), ("ms", ms.to_string())]);
    }

    /// Spawn the next child generation; `false` when the spawn failed (the
    /// finish is then already decided).
    fn spawn_next(&mut self) -> bool {
        self.gen += 1;
        self.state.begin_gen(self.gen);
        self.child_exit = None;
        self.exit_seen_at = None;
        self.stdout_eof = false;
        self.stderr_eof = false;
        if self.gen > 1 && self.credential.is_none() && matches!(self.out.credential, Some("fd" | "env")) {
            // A resume miss later than the grace: the seed retry still runs, logged out.
            tracing::warn!(gen = self.gen, "respawned without the setup-token: the copy was already dropped");
            say(&logged_out_note("the seed retry respawned the child after the setup-token copy was dropped"));
            // The end row says how the generation that serves the session was logged in.
            self.out.credential = Some("none");
        }
        match spawn_local(&self.plan, self.credential.as_ref().map(|c| (&c.token, c.deliver))) {
            Ok(link) => {
                tracing::info!(gen = self.gen, pid = link.pid, "child spawned");
                self.child_pid = link.pid;
                self.out.child_pid = link.pid;
                self.child_events = Some(link.events);
                self.child_input = Some(link.input);
                self.child_signal = Some(link.signal);
                self.spawned_at = Instant::now();
                if self.gen == 1 {
                    self.delay_until = self.knobs.delay_init.map(|d| self.spawned_at + d);
                }
                if let Some(c) = &self.credential {
                    let detail = [
                        ("to", "local-scratch".to_string()),
                        ("gen", self.gen.to_string()),
                        ("pid", link.pid.map_or_else(|| "-".to_string(), |p| p.to_string())),
                        ("name", TOKEN_VAR.to_string()),
                        ("tag", c.tag.clone()),
                        ("source", "setup-token".to_string()),
                        ("deliver", c.word().to_string()),
                    ];
                    self.audit("credential_deliver", &detail);
                }
                self.settle_credential(false, "the child started and no retry can respawn it");
                true
            }
            Err(e) => {
                eprintln!("ai-env-claude: cannot spawn {}: {e}", self.plan.program.display());
                tracing::warn!("spawn failed: {e}");
                self.child_events = None;
                self.child_input = None;
                self.child_signal = None;
                self.decide_finish(1, EndReason::SpawnFailed);
                false
            }
        }
    }

    fn signal_child(&self, sig: Sig) {
        if let Some(tx) = &self.child_signal {
            let _ = tx.send(sig);
        }
    }

    fn child_alive(&self) -> bool {
        self.child_events.is_some() && self.child_exit.is_none()
    }

    /// Decide the exit. The flush of queued lines may take up to 5 s while
    /// the host still reads and nothing asked us to close; 250 ms otherwise;
    /// never past a ladder's hard stop.
    fn decide_finish(&mut self, code: i32, end: EndReason) {
        if self.finish.is_some() {
            return;
        }
        // No child is spawned once the finish is decided.
        self.settle_credential(true, "the session is finishing");
        let now = Instant::now();
        self.finish = Some((code, end));
        let flush = if self.host_open && !self.close_requested && !self.host_gone { FLUSH_OPEN_DEADLINE } else { FLUSH_DEADLINE };
        let mut deadline = now + flush;
        if let Some(l) = &self.ladder {
            deadline = deadline.min(l.hard_stop);
        }
        self.finish_deadline = Some(deadline);
    }

    /// A close request (host EOF, SIGTERM) while finishing: flush briefly.
    fn shorten_finish(&mut self) {
        if let Some(d) = &mut self.finish_deadline {
            *d = (*d).min(Instant::now() + FLUSH_DEADLINE);
        }
    }

    fn forward(&mut self, line: &[u8]) {
        // Nobody reads a closed stdout: queueing would only stall the child side.
        if self.host_gone {
            return;
        }
        // Closing towards a host that stopped reading: keep observing the child, drop the excess.
        if self.ladder.is_some() && self.out_q.len() >= CLOSING_QUEUE_CAP {
            self.out.dropped_lines += 1;
            return;
        }
        self.out_q.push_back(encode_line(line));
    }

    /// The replay deadline (15 s, or the debug lab knob).
    fn replay_deadline_len(&self) -> Duration {
        self.knobs.replay_deadline.unwrap_or(REPLAY_DEADLINE)
    }

    // -- host → child --------------------------------------------------------------------

    fn on_host(&mut self, item: Option<HostIn>) {
        if self.finish.is_some() {
            // Finishing: host lines have nowhere to go; an EOF shortens the flush.
            if matches!(item, Some(HostIn::Eof) | None) {
                self.host_open = false;
                self.close_requested = true;
                self.shorten_finish();
            }
            return;
        }
        match item {
            Some(HostIn::Line(line)) => {
                let frame = claude::classify_host(&line);
                // The answer to the synthetic request is the pump's own: recorded, never forwarded.
                if let HostFrame::ControlResponse { request_id: Some(id) } = &frame {
                    if self.is_synthetic(id) {
                        self.on_synthetic_answer(&line);
                        return;
                    }
                }
                if let HostFrame::ControlRequest { request_id, subtype, .. } = &frame {
                    // The subtype and id only: request bodies can carry credentials.
                    tracing::debug!(subtype = subtype.as_deref().unwrap_or("-"), id = request_id.as_deref().unwrap_or("-"), "host control_request");
                }
                self.state.on_host_frame(&frame, &line);
                if matches!(frame, HostFrame::User { .. }) && !self.user_line_seen {
                    self.user_line_seen = true;
                    self.maybe_register();
                }
                self.in_q.push_back(ChildInput::Line(encode_line(&line)));
            }
            Some(HostIn::TooLong(n)) => {
                self.out.dropped_lines += 1;
                tracing::warn!("host line over the CLI's 256 MiB limit dropped ({n} bytes)");
            }
            Some(HostIn::Eof) | None => self.on_host_eof(),
        }
    }

    fn on_host_eof(&mut self) {
        if !self.host_open {
            return;
        }
        self.host_open = false;
        let now = Instant::now();
        self.host_eof_at = Some(now);
        tracing::info!(ms = now.duration_since(self.spawned_at).as_millis() as u64, "host stdin EOF");
        if self.knobs.ignore_eof >= 1 {
            tracing::info!("lab: host EOF ignored");
            return;
        }
        self.close_requested = true;
        if self.child_events.is_none() {
            self.decide_finish(0, EndReason::EofTerm);
            return;
        }
        if self.child_exit.is_some() {
            // The child already exited and is draining: its own exit decides (no respawn).
            return;
        }
        self.in_q.push_back(ChildInput::Eof);
        self.start_ladder(Some(now + EOF_TERM_AFTER), now + EOF_KILL_AFTER, now + EOF_HARD_STOP, true);
    }

    fn start_ladder(&mut self, term_at: Option<Instant>, kill_at: Instant, hard_stop: Instant, host_initiated: bool) {
        // A closing session is never held back by the init-delay knob.
        self.delay_until = None;
        match &mut self.ladder {
            Some(l) => {
                l.kill_at = l.kill_at.min(kill_at);
                l.hard_stop = l.hard_stop.min(hard_stop);
                if term_at.is_none() {
                    l.term_at = None;
                }
                l.host_initiated &= host_initiated;
            }
            None => self.ladder = Some(Ladder { term_at, kill_at, hard_stop, host_initiated, signalled: term_at.is_none(), killed: false }),
        }
    }

    fn on_sigterm(&mut self) {
        let now = Instant::now();
        if let Some(eof) = self.host_eof_at {
            self.out.eof_to_sigterm_ms = Some(now.duration_since(eof).as_millis() as u64);
        }
        tracing::info!(eof_to_sigterm_ms = self.out.eof_to_sigterm_ms, "SIGTERM");
        if self.knobs.ignore_eof >= 2 {
            if !self.ignored_sigterm_row {
                self.ignored_sigterm_row = true;
                tracing::info!("lab: SIGTERM ignored; end row written with exit null");
                let mut out = self.snapshot_outcome();
                out.code = None;
                out.end = Some(EndReason::SigTerm);
                self.write_end_row(&out);
            }
            return;
        }
        self.host_open = false;
        self.close_requested = true;
        if self.finish.is_some() {
            self.shorten_finish();
            return;
        }
        if self.child_events.is_none() {
            self.decide_finish(143, EndReason::SigTerm);
            return;
        }
        if self.child_exit.is_some() {
            // The child already exited and is draining: its own exit decides (no respawn).
            return;
        }
        self.signal_child(Sig::Term);
        self.start_ladder(None, now + SIGTERM_KILL_AFTER, now + SIGTERM_HARD_STOP, false);
    }

    // -- child → host --------------------------------------------------------------------

    fn on_child_event(&mut self, ev: Option<ChildEvent>) {
        match ev {
            Some(ChildEvent::Line(line)) => self.on_child_line(line),
            Some(ChildEvent::TooLong(n)) => {
                self.out.dropped_lines += 1;
                tracing::warn!("child line over the CLI's 256 MiB limit dropped ({n} bytes)");
            }
            Some(ChildEvent::StdoutEof) => self.stdout_eof = true,
            Some(ChildEvent::StderrEof) => self.stderr_eof = true,
            Some(ChildEvent::Exit(status)) => {
                tracing::info!(gen = self.gen, status = ?status, "child exited");
                self.child_exit = Some(status);
                self.exit_seen_at = Some(Instant::now());
            }
            None => {
                // Every task of this child ended.
                self.stdout_eof = true;
                self.stderr_eof = true;
                if self.child_exit.is_none() {
                    self.child_exit = Some(None);
                    self.exit_seen_at = Some(Instant::now());
                }
            }
        }
    }

    fn on_child_line(&mut self, line: Bytes) {
        let frame = claude::classify_child(&line);
        match &frame {
            ChildFrame::Mirror { file_path, entries } => {
                match self.mirror.append(file_path.as_deref(), entries) {
                    Ok(bytes) => tracing::debug!(bytes, "mirror frame appended"),
                    Err(e) => tracing::debug!(reject = ?e, "mirror frame not appended"),
                }
                return;
            }
            ChildFrame::ControlRequest { request_id, subtype } if matches!(subtype.as_deref(), Some("oauth_token_refresh" | "host_auth_token_refresh")) => {
                let sub = subtype.as_deref().unwrap_or_default().to_string();
                if let Some(id) = request_id {
                    let body = if sub == "oauth_token_refresh" { r#"{"accessToken":null}"# } else { r#"{"authToken":null}"# };
                    if let Ok(raw) = RawValue::from_string(body.to_string()) {
                        self.in_q.push_back(ChildInput::Line(encode_line(&claude::control_success_line(id, &raw))));
                    }
                }
                self.out.oauth_answered += 1;
                self.audit("oauth_refresh_answered", &[("subtype", sub.clone()), ("gen", self.gen.to_string())]);
                tracing::info!(subtype = %sub, "answered locally with a null token (never forwarded)");
                return;
            }
            _ => {}
        }
        if claude::is_resume_miss(&frame) && self.retry_possible() && self.held_miss.is_none() {
            tracing::info!("resume miss reported by generation {}; holding the result until the child exits", self.gen);
            self.held_miss = Some(line.clone());
            return;
        }
        // Generation 1's answer to the host's `initialize`: its latency, and the start of the token's grace.
        if let ChildFrame::ControlResponse { request_id: Some(id), .. } = &frame {
            if self.gen == 1 && self.out.init_latency_ms.is_none() && self.state.initialize_id() == Some(id.as_ref()) {
                self.out.init_latency_ms = Some(self.spawned_at.elapsed().as_millis() as u64);
                if self.credential.is_some() {
                    // Still held: a seed retry is possible. A resume miss comes at startup, so not for long.
                    self.credential_hold_until = Some(Instant::now() + RESUME_MISS_GRACE);
                }
            }
        }
        let init_before = self.state.inits_forwarded();
        let verdict = self.state.on_child_frame(&frame, &line);
        let forwarded = !matches!(verdict, ChildVerdict::Swallow(_));
        // The session is initialized once a success answer to the host's `initialize` reaches the host, from
        // whichever generation: when generation 1 missed the resume before answering, the seed retry's answer
        // to the replayed request is the one, rewritten to the host's id.
        let initialized = match &verdict {
            ChildVerdict::Forward => self.answers_initialize(&frame),
            ChildVerdict::Rewritten(b) => self.answers_initialize(&claude::classify_child(b)),
            ChildVerdict::Swallow(_) => false,
        };
        match verdict {
            ChildVerdict::Forward => self.forward(&line),
            ChildVerdict::Rewritten(b) => self.forward(&b),
            ChildVerdict::Swallow(why) => tracing::debug!(?why, "child frame swallowed"),
        }
        if initialized {
            // Queued behind the response, so the host's handshake is complete when it arrives.
            self.send_synthetic_oauth();
        }
        match &frame {
            ChildFrame::Init { session_id, cwd } => {
                if let Some(id) = session_id {
                    if self.out.session_id.as_deref() != Some(id.as_ref()) {
                        if self.out.session_id.is_some() {
                            // `/clear` starts a new session in the same process: close the old row.
                            tracing::info!(session = %id, "new session id in the same process");
                            self.close_row(None);
                            self.row = None;
                        } else {
                            tracing::info!(session = %id, cwd = ?cwd, "session id learned");
                        }
                        self.out.session_id = Some(id.to_string());
                        self.first_session_id.get_or_insert_with(|| id.to_string());
                    }
                }
                if init_before == 0 && self.state.inits_forwarded() == 1 {
                    self.after_first_init();
                    // The host saw an init: the seed retry, the last reason to keep the token, is over.
                    self.settle_credential(false, "the first init");
                }
                self.maybe_register();
            }
            ChildFrame::Result { .. } if forwarded => {
                if let Err(e) = self.mirror.sync_all() {
                    tracing::warn!("mirror fsync: {e}");
                }
                self.touch_registry();
            }
            _ => {}
        }
    }

    fn after_first_init(&mut self) {
        if self.knobs.stdout_noise && !self.noise_done {
            self.noise_done = true;
            tracing::info!("hello");
            eprintln!("ai-env-claude: hello");
        }
        if let Some((code, msg)) = self.after_init.take() {
            tracing::info!(code, "lab: exit after init");
            self.lab_message = Some(msg);
            self.host_open = false;
            self.signal_child(Sig::Term);
            let now = Instant::now();
            self.start_ladder(None, now + SIGTERM_KILL_AFTER, now + SIGTERM_HARD_STOP, false);
            self.finish_after_child = Some((code, EndReason::LabExit));
        }
    }

    /// Is `frame` a success answer to the host's `initialize`, under the host's own id?
    fn answers_initialize(&self, frame: &ChildFrame<'_>) -> bool {
        matches!(frame, ChildFrame::ControlResponse { request_id: Some(id), subtype: Some(s) } if s == "success" && self.state.initialize_id() == Some(id.as_ref()))
    }

    fn retry_possible(&self) -> bool {
        self.sess.mode == Mode::LocalScratch && self.gen == 1 && self.retries == 0 && self.plan.resume.is_some() && self.state.inits_forwarded() == 0
    }

    // -- registry ------------------------------------------------------------------------

    fn maybe_register(&mut self) {
        if self.row.is_some() || !self.user_line_seen || self.sess.session.no_session_persistence {
            return;
        }
        let Some(session_id) = self.out.session_id.clone().filter(|s| registry::is_uuid(s)) else { return };
        let now = registry::now_rfc3339();
        let row = SessionRow {
            v: registry::REGISTRY_SCHEMA_V,
            session_id: session_id.clone(),
            slug: self.plan.slug.clone(),
            cwd: self.sess.cwd.as_ref().map(|c| c.display().to_string()),
            transcript_rel: self.plan.slug.as_ref().map(|s| format!("{s}/{session_id}.jsonl")),
            created: now.clone(),
            last_seen: now,
            status: "active".to_string(),
            mode: self.sess.mode.name().to_string(),
            route: route_label(&self.sess.route),
            ext: self.sess.start_row.ext.clone(),
            pid: std::process::id(),
            child_pid: self.child_pid,
            exit: None,
            argv_hash: registry::argv_hash(&self.sess.start_row.argv),
            respawns: self.out.respawns,
            child_config_dir: Some(self.plan.child_config_dir.display().to_string()),
            mirror_root: std::env::var_os(MIRROR_ROOT_ENV).filter(|v| !v.is_empty()).map(|v| v.to_string_lossy().into_owned()),
            scratch_dir: self.plan.scratch.as_ref().map(|p| p.display().to_string()),
            host_state: self.state.snapshot(),
            ..SessionRow::default()
        };
        self.row = Some(row);
        self.registered = true;
        self.write_row();
    }

    fn touch_registry(&mut self) {
        if let Some(row) = &mut self.row {
            row.last_seen = registry::now_rfc3339();
            row.host_state = self.state.snapshot();
            row.child_pid = self.child_pid;
            row.respawns = self.out.respawns;
        }
        self.write_row();
    }

    /// Mark the current row closed (with the exit code, when known) and write it.
    fn close_row(&mut self, exit: Option<i32>) {
        if let Some(row) = &mut self.row {
            row.status = "closed".to_string();
            row.exit = exit;
            row.last_seen = registry::now_rfc3339();
            row.host_state = self.state.snapshot();
            row.respawns = self.out.respawns;
        }
        self.write_row();
    }

    fn write_row(&self) {
        if let Some(row) = &self.row {
            if let Err(e) = registry::write(&self.sess.paths, row) {
                tracing::warn!("registry: {e}");
            }
        }
    }

    // -- the child's end -------------------------------------------------------------------

    /// Called once the current child is gone and drained.
    fn on_child_gone(&mut self) {
        let status = self.child_exit.flatten();
        let code = status.and_then(|s| s.code());
        let signal = status.and_then(|s| s.signal());
        self.child_events = None;
        self.child_input = None;
        self.child_signal = None;
        self.in_q.clear();
        if let Some(held) = self.held_miss.take() {
            if code == Some(1) && self.retry_possible() && !self.close_requested && self.finish.is_none() && self.ladder.is_none() && self.respawn_after_miss() {
                return;
            }
            // No retry: the host gets the error result after all.
            let _ = self.state.on_child_frame(&claude::classify_child(&held), &held);
            self.forward(&held);
        }
        if let Some(fin) = self.finish_after_child.take() {
            self.decide_finish(fin.0, fin.1);
            return;
        }
        let (exit_code, end) = match (code, signal, self.ladder) {
            // The host closed: a child that ended after our signal (whatever its code, e.g. a
            // SIGTERM handler's 143) is a clean close; one that ended on its own keeps its code.
            (Some(c), _, Some(l)) if l.host_initiated => (if l.signalled { 0 } else { c }, if l.killed { EndReason::EofKill } else { EndReason::EofTerm }),
            (Some(c), _, Some(_)) => (c, EndReason::SigTerm),
            (Some(c), _, None) => (c, if self.host_gone { EndReason::HostGone } else { EndReason::ChildExit }),
            (None, Some(_), Some(l)) if l.host_initiated => (0, if l.killed { EndReason::EofKill } else { EndReason::EofTerm }),
            (None, Some(s), Some(_)) => (128 + s, EndReason::SigTerm),
            (None, Some(s), None) => (if self.host_gone { 0 } else { 128 + s }, if self.host_gone { EndReason::HostGone } else { EndReason::ChildExit }),
            (None, None, _) => (1, EndReason::ChildExit),
        };
        self.decide_finish(exit_code, end);
    }

    /// The seed retry: re-seed the scratch dir from the Mac's transcript and
    /// spawn generation 2 with the host state replayed. `false` when there
    /// was nothing to seed from (the miss then propagates).
    fn respawn_after_miss(&mut self) -> bool {
        self.retries += 1;
        let Some(resume) = self.plan.resume.clone() else { return false };
        let detail: Vec<(&str, String)> = match seed_from_mac(&self.sess, &self.plan, &resume, true) {
            SeedOutcome::Seeded(report) => vec![
                ("session_id", resume.clone()),
                ("source", report.source.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
                ("files", (u32::from(report.copied_jsonl) + report.subtree_files).to_string()),
                ("bytes", report.bytes.to_string()),
            ],
            // The scratch dir holds a LONGER transcript than the Mac's: never
            // overwritten; the one respawn still gets its chance.
            SeedOutcome::KeptNewer(path) => vec![("session_id", resume.clone()), ("source", path.display().to_string()), ("files", "0".to_string()), ("bytes", "0".to_string()), ("kept", "scratch copy".to_string())],
            SeedOutcome::NoSource => {
                tracing::warn!("resume miss for {resume}: no local transcript to seed from");
                self.audit("resume_seed_miss", &[("session_id", resume.clone()), ("reason", "no local transcript".to_string())]);
                return false;
            }
            SeedOutcome::Failed(reason) => {
                tracing::warn!("resume miss for {resume}: seeding failed: {reason}");
                self.audit("resume_seed_failed", &[("session_id", resume.clone()), ("reason", reason)]);
                return false;
            }
        };
        self.audit("resume_seed_retry", &detail);
        if !self.spawn_next() {
            return true;
        }
        self.out.respawns += 1;
        let mut fresh = || uuid::Uuid::now_v7().to_string();
        for line in self.state.replay_lines(&mut fresh) {
            self.in_q.push_back(ChildInput::Line(encode_line(&line)));
        }
        for line in self.state.fail_in_flight() {
            self.forward(&line);
        }
        if self.state.replaying() {
            self.replay_deadline = Some(Instant::now() + self.replay_deadline_len());
        }
        self.touch_registry();
        true
    }

    // -- deadlines -------------------------------------------------------------------------

    fn next_deadline(&self) -> Option<Instant> {
        let mut all: Vec<Instant> = Vec::new();
        if let Some(l) = &self.ladder {
            if self.child_alive() {
                all.extend(l.term_at);
                if !l.killed {
                    all.push(l.kill_at);
                } else if self.finish.is_none() {
                    all.push(l.hard_stop);
                }
            }
        }
        all.extend(self.delay_until);
        all.extend(self.replay_deadline);
        all.extend(self.credential_hold_until);
        all.extend(self.synthetic.as_ref().and_then(Synthetic::deadline));
        if self.finish.is_some() {
            all.extend(self.finish_deadline);
        }
        if self.child_exit.is_some() && self.child_events.is_some() {
            all.extend(self.exit_seen_at.map(|t| t + EXIT_DRAIN));
        }
        all.into_iter().min()
    }

    fn on_deadline(&mut self, now: Instant) {
        if let Some(mut l) = self.ladder {
            if self.child_alive() {
                if l.term_at.is_some_and(|t| now >= t) {
                    l.term_at = None;
                    l.signalled = true;
                    tracing::info!("ladder: SIGTERM child");
                    self.signal_child(Sig::Term);
                }
                if !l.killed && now >= l.kill_at {
                    l.killed = true;
                    l.signalled = true;
                    tracing::info!("ladder: SIGKILL child");
                    self.signal_child(Sig::Kill);
                } else if l.killed && now >= l.hard_stop && self.finish.is_none() {
                    // Killed, yet its exit is still queued behind lines the host does not read.
                    tracing::warn!("child killed but its exit was not observed; finishing");
                    let (code, end) = match self.finish_after_child.take() {
                        Some(f) => f,
                        None if l.host_initiated => (0, EndReason::EofKill),
                        None => (143, EndReason::SigTerm),
                    };
                    self.decide_finish(code, end);
                }
            }
            self.ladder = Some(l);
        }
        if self.delay_until.is_some_and(|t| now >= t) {
            self.delay_until = None;
        }
        if self.credential_hold_until.is_some_and(|t| now >= t) {
            self.credential_hold_until = None;
            // A miss already held, or a child already gone, settles at the respawn or the finish.
            if self.held_miss.is_none() && self.child_exit.is_none() {
                self.drop_credential("no resume miss within the grace after initialize");
            }
        }
        if let Some(s) = self.synthetic.as_mut().filter(|s| s.deadline().is_some_and(|t| now >= t)) {
            // The id stays known: a later answer is still never forwarded.
            s.class = Some("none".into());
            let wait_ms = s.wait.as_millis() as u64;
            tracing::info!(wait_ms, "synthetic oauth_token_refresh: no answer within the wait");
            self.audit("synthetic_oauth", &[("class", "none".to_string()), ("ms", wait_ms.to_string())]);
        }
        if self.replay_deadline.is_some_and(|t| now >= t) {
            self.replay_deadline = None;
            if self.state.replaying() {
                let errors = self.state.replay_expired();
                tracing::warn!("respawned child did not answer the replay within {:?}", self.replay_deadline_len());
                self.audit("replay_timeout", &[("failed", errors.len().to_string()), ("gen", self.gen.to_string())]);
                for e in errors {
                    self.forward(&e);
                }
            }
        }
    }

    /// The child is gone for good once it exited and its output drained (or
    /// the drain window closed).
    fn child_done(&self, now: Instant) -> bool {
        self.child_events.is_some()
            && self.child_exit.is_some()
            && ((self.stdout_eof && self.stderr_eof) || self.exit_seen_at.is_some_and(|t| now >= t + EXIT_DRAIN))
    }

    fn snapshot_outcome(&self) -> Outcome {
        let mut out = self.out.clone();
        out.mirror_frames = self.mirror.appended_frames;
        out.mirror_rejected = self.mirror.rejected;
        out.synthetic_oauth = self.synthetic.as_ref().map(Synthetic::census);
        out
    }

    fn write_end_row(&self, out: &Outcome) {
        let row = end_row(&self.sess.start_row, out, unix_now_ms());
        if let Err(e) = census::record(&self.sess.paths.census(), &row) {
            eprintln!("ai-env-claude: census: {e}");
        }
    }

    /// The loop. Returns the exit code once the finish is decided and the
    /// queued lines reached the host (or the flush deadline passed).
    async fn supervise(&mut self) -> i32 {
        let (host_tx, mut host_rx) = mpsc::channel::<HostIn>(CHANNEL_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
        tokio::spawn(host_stdin_reader(host_tx));
        let writer = tokio::spawn(host_stdout_writer(out_rx));
        let (mut sigterm, mut sigint) = match (
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
        ) {
            (Ok(t), Ok(i)) => (t, i),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("ai-env-claude: cannot install signal handlers: {e}");
                return 1;
            }
        };
        let out_tx = Some(out_tx);
        self.spawn_next();
        loop {
            let now = Instant::now();
            if self.child_done(now) {
                self.on_child_gone();
                continue;
            }
            if let Some((code, _)) = self.finish {
                let flushed = self.out_q.is_empty();
                if flushed || self.finish_deadline.is_some_and(|t| now >= t) {
                    drop(out_tx);
                    let remaining = self.finish_deadline.map_or(FLUSH_DEADLINE, |t| t.saturating_duration_since(Instant::now()));
                    if !remaining.is_zero() {
                        let _ = tokio::time::timeout(remaining, writer).await;
                    }
                    return code;
                }
            }
            let deadline = self.next_deadline().unwrap_or_else(|| now + Duration::from_secs(3600));
            // After the child's exit its remaining output is bounded (pipe + channel): drain it eagerly.
            // While closing, keep reading too (the excess is dropped in `forward`): the exit must be seen.
            let read_child = self.child_events.is_some() && (self.out_q.len() < 2 || self.child_exit.is_some() || self.ladder.is_some()) && self.delay_until.is_none();
            // Host lines during a replay queue behind the replayed ones (the CLI takes user
            // lines before it has answered initialize); an EOF is acted on at once. While
            // finishing, host lines are read only to notice an EOF.
            let read_host = self.host_open && (self.finish.is_some() || (self.child_input.is_some() && self.in_q.len() < 2));
            let write_out = !self.out_q.is_empty() && !self.host_gone;
            let write_in = !self.in_q.is_empty() && self.child_input.is_some();
            let wake = tokio::select! {
                biased;
                _ = sigterm.recv() => Wake::Signal,
                _ = sigint.recv() => Wake::Signal,
                () = tokio::time::sleep_until(deadline) => Wake::Deadline,
                permit = reserve_opt(&out_tx), if write_out => match permit {
                    Some(p) => {
                        if let Some(line) = self.out_q.pop_front() {
                            p.send(line);
                        }
                        Wake::Sent
                    }
                    None => Wake::HostOutClosed,
                },
                permit = reserve_opt(&self.child_input), if write_in => match permit {
                    Some(p) => {
                        if let Some(item) = self.in_q.pop_front() {
                            p.send(item);
                        }
                        Wake::Sent
                    }
                    None => Wake::ChildInClosed,
                },
                ev = recv_opt(&mut self.child_events), if read_child => Wake::Child(ev.flatten()),
                item = host_rx.recv(), if read_host => Wake::Host(item),
            };
            match wake {
                Wake::Signal => self.on_sigterm(),
                Wake::Deadline => self.on_deadline(Instant::now()),
                Wake::Sent => {}
                Wake::HostOutClosed => {
                    tracing::info!("host stdout closed");
                    self.host_gone = true;
                    self.out_q.clear();
                    self.on_host_gone();
                }
                Wake::ChildInClosed => {
                    // The child's stdin is closed (it exited or stopped reading): drop the rest.
                    self.in_q.clear();
                    self.child_input = None;
                }
                Wake::Child(ev) => self.on_child_event(ev),
                Wake::Host(item) => self.on_host(item),
            }
        }
    }

    fn on_host_gone(&mut self) {
        self.host_open = false;
        if self.child_alive() {
            let now = Instant::now();
            self.close_requested = true;
            self.in_q.push_back(ChildInput::Eof);
            self.start_ladder(Some(now + EOF_TERM_AFTER), now + EOF_KILL_AFTER, now + EOF_HARD_STOP, true);
        } else {
            self.close_requested = true;
            self.decide_finish(0, EndReason::HostGone);
            self.shorten_finish();
        }
    }
}

/// What seeding the scratch config dir from the Mac's transcript did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOutcome {
    /// Copied (the first candidate directory that had the transcript).
    Seeded(seed::SeedReport),
    /// The scratch copy was kept (never truncated — the scratch child may hold
    /// entries a mirror gap kept from the Mac copy).
    KeptNewer(PathBuf),
    /// No candidate directory holds `<uuid>.jsonl`.
    NoSource,
    /// Seeding failed (too large, unreadable, …).
    Failed(String),
}

/// Copy the Mac's transcript for `resume` into the plan's scratch config dir
/// (`local-scratch`): the first candidate directory that seeds wins. A
/// scratch copy longer than the Mac's is never overwritten; before the spawn
/// (`retry` false) an equally long one is kept too, while the seed retry
/// re-copies it (the child just reported it missing).
fn seed_from_mac(sess: &Session, plan: &ChildPlan, resume: &str, retry: bool) -> SeedOutcome {
    let (Some(scratch), Some(dst_slug), Some(mac)) = (plan.scratch.as_ref(), plan.slug.as_deref(), mirror::mac_config_dir()) else {
        return SeedOutcome::NoSource;
    };
    let mac_projects = mac.join("projects");
    let dst_projects = scratch.join("projects");
    let cwd_slug = sess.cwd.as_deref().and_then(|c| slug::project_dir_name(c).ok());
    let registry_slug = registry::read(&sess.paths, resume).ok().flatten().and_then(|r| r.slug);
    let slugs: Vec<&str> = cwd_slug.iter().chain(registry_slug.iter()).map(String::as_str).collect();
    let dst_file = dst_projects.join(dst_slug).join(format!("{resume}.jsonl"));
    let dst_len = std::fs::symlink_metadata(&dst_file).ok().filter(|m| m.file_type().is_file()).map(|m| m.len());
    let mut failure = None;
    for dir in seed::candidates(&mac_projects, &slugs, resume) {
        let src_len = std::fs::symlink_metadata(dir.join(format!("{resume}.jsonl"))).map(|m| m.len()).unwrap_or(0);
        if dst_len.is_some_and(|d| d > src_len || (d == src_len && !retry)) {
            tracing::info!(source = %dir.display(), "scratch transcript kept: it is at least as long as the Mac copy");
            return SeedOutcome::KeptNewer(dst_file);
        }
        match seed::seed_local(&dir, resume, &dst_projects, dst_slug) {
            Ok(report) if report.copied_jsonl => {
                tracing::info!(source = %dir.display(), files = report.subtree_files, bytes = report.bytes, "seeded the scratch config dir");
                return SeedOutcome::Seeded(report);
            }
            Ok(_) => tracing::debug!(source = %dir.display(), "candidate had no transcript"),
            Err(e) => {
                tracing::warn!(source = %dir.display(), "seed failed: {e}");
                failure = Some(e.to_string());
            }
        }
    }
    failure.map_or(SeedOutcome::NoSource, SeedOutcome::Failed)
}

/// A new `local-scratch` session's scratch dir is named by a fresh id (the
/// session id is only known after the spawn). Once the child is gone, rename
/// it to the session id, so `ai-env session forget <uuid>` finds it and a
/// later `--resume=<uuid>` reuses it. Never replaces an existing directory.
fn rename_scratch(plan: &ChildPlan, session_id: Option<&str>) -> Option<PathBuf> {
    let from = plan.scratch.as_ref()?;
    let id = session_id.filter(|s| registry::is_uuid(s))?;
    if from.file_name().is_some_and(|n| n == id) {
        return None;
    }
    let to = from.parent()?.join(id);
    if std::fs::symlink_metadata(&to).is_ok() {
        tracing::info!("scratch dir {} kept: {} exists", from.display(), to.display());
        return None;
    }
    match std::fs::rename(from, &to) {
        Ok(()) => {
            tracing::info!("scratch dir renamed to {}", to.display());
            Some(to)
        }
        Err(e) => {
            tracing::warn!("scratch dir {} not renamed: {e}", from.display());
            None
        }
    }
}

/// Create the scratch config dir (0700, parents included) for `local-scratch`
/// and mark it as ours (`.ai-env-owner` = this pid) so `ai-env session forget`
/// never deletes it under a live child.
fn prepare_scratch(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return Err(std::io::Error::other(format!("{} is not a directory", dir.display()))),
        Ok(_) => {}
        Err(_) => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?,
    }
    let owner = dir.join(registry::SCRATCH_OWNER_FILE);
    let _ = std::fs::remove_file(&owner);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&owner)?;
    std::io::Write::write_all(&mut f, std::process::id().to_string().as_bytes())
}

/// At teardown (the child is gone): a fresh-named scratch dir of an
/// invocation that never registered a session (a config probe, a login, a
/// suggestions query, a chat closed before its first message) is removed;
/// any other scratch dir loses its owner mark and a fresh-named one is
/// renamed to the first session id. Returns the dir's final path, if kept.
fn finish_scratch(plan: &ChildPlan, registered: bool, first_session_id: Option<&str>) -> Option<PathBuf> {
    let dir = plan.scratch.as_ref()?;
    let fresh = plan.resume.is_none();
    if fresh && !registered {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => match std::fs::remove_dir_all(dir) {
                Ok(()) => tracing::info!("scratch dir {} removed (no session was registered)", dir.display()),
                Err(e) => tracing::warn!("scratch dir {} not removed: {e}", dir.display()),
            },
            _ => {}
        }
        return None;
    }
    let _ = std::fs::remove_file(dir.join(registry::SCRATCH_OWNER_FILE));
    rename_scratch(plan, first_session_id).or_else(|| Some(dir.clone()))
}

// ---- local-scratch: the sealed setup-token (S7) ---------------------------------------------

/// The setup-token a `local-scratch` child is handed, and how.
#[derive(Debug)]
pub struct ChildCredential {
    token: SetupToken,
    deliver: Deliver,
    /// The seal id of the container it came from (audit rows only).
    tag: String,
}

impl ChildCredential {
    /// `fd` or `env`.
    fn word(&self) -> &'static str {
        match self.deliver {
            Deliver::Fd => "fd",
            Deliver::Env => "env",
        }
    }
}

/// How a `local-scratch` child logs in, decided once, before its first spawn.
#[derive(Debug)]
pub enum ScratchLogin {
    /// `CLAUDE_CODE_OAUTH_TOKEN` is in the wrapper's environment: the child
    /// inherits it, as before S7.
    Inherited,
    /// Unsealed for this session.
    Sealed(ChildCredential),
    /// The child runs logged out, and why (the reason in its note line).
    LoggedOut(String),
    /// A signal arrived while Touch ID was awaited: the dialog was closed and
    /// the wrapper exits with this code.
    Stopped(i32),
}

impl ScratchLogin {
    /// The end row's `credential:` word.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            ScratchLogin::Inherited => "inherited",
            ScratchLogin::Sealed(c) => c.word(),
            ScratchLogin::LoggedOut(_) | ScratchLogin::Stopped(_) => "none",
        }
    }
}

/// The one note line of a logged-out `local-scratch` child.
#[must_use]
pub fn logged_out_note(why: &str) -> String {
    format!("ai-env-claude: local-scratch without {TOKEN_VAR}: {why}, so the child is logged out")
}

/// The `local-scratch` unseal's budget and whether Cursor's initialize window
/// set it: `configured` (`[creds].unseal_timeout_s`, or the lab knob), but
/// never past T−10 s of [`INITIALIZE_WINDOW`], of which `used` is already
/// gone — the unseal runs before the child exists, so a longer wait lets the
/// window close on the session. `used` counts in whole seconds (a fraction
/// comes out of the 10 s margin), so the countdown says `50 s left`.
#[must_use]
pub fn scratch_unseal_budget(configured: Duration, used: Duration) -> (Duration, bool) {
    let room = INITIALIZE_WINDOW.saturating_sub(INIT_FAIL_FAST).saturating_sub(Duration::from_secs(used.as_secs()));
    if configured <= room {
        (configured, false)
    } else {
        (room, true)
    }
}

/// The wrapper's exit code after a signal during the unseal: 130 for Ctrl-C,
/// 143 for SIGTERM and SIGHUP, as `vm exec`'s unseal exits.
fn stop_code(sig: i32) -> i32 {
    if sig == libc::SIGINT {
        130
    } else {
        143
    }
}

/// How a `local-scratch` child logs in. A token in the environment wins.
/// Otherwise the sealed setup-token is unsealed — unless none is sealed,
/// `[creds]` does not validate, Anthropic refused this seal before (S7 D6:
/// never unsealed again, no Touch ID), or `state/creds.toml` cannot be read
/// (which seals were refused is then unknown: it fails closed, as `vm exec`
/// does) — with `[creds].key` from the keystore at `AI_ENV_DIR` (else
/// `~/.config/ai-env`), within `[creds].unseal_timeout_s` (or
/// [`UNSEAL_TIMEOUT_KNOB`]) capped by [`scratch_unseal_budget`] (`used`: how
/// much of the initialize window the wrapper spent before this call). The
/// refusal is checked, and the delivery audited, under the seal id of the
/// very bytes decrypted: the text one read of the sealed file returned (the
/// reads before that one only classify the file). Every
/// failure, a dismissed dialog and the deadline included, is a logged-out
/// child, never a failed session; the unseal is audited `credential_unseal`.
pub fn scratch_login(sess: &Session, env: &dyn Fn(&str) -> Option<OsString>, used: Duration) -> ScratchLogin {
    if env(TOKEN_VAR).is_some_and(|v| !v.is_empty()) {
        return ScratchLogin::Inherited;
    }
    let paths = &sess.paths;
    let path = paths.setup_token_env();
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return ScratchLogin::LoggedOut("no setup-token is sealed (`ai-env creds setup-token` seals one)".into()),
        AwsEnvState::NotSealed(why) => return ScratchLogin::LoggedOut(format!("{} {why}", path.display())),
    }
    let creds = sess.cfg.as_ref().map(|c| c.creds.clone()).unwrap_or_default();
    if let Err(e) = creds.validate() {
        return ScratchLogin::LoggedOut(one_line(&e.to_string()));
    }
    // One read (M38, as `vm exec`): the bytes whose seal id is checked against the refusals and audited at
    // the spawn are the ones decrypted, never a second read of a file sealed anew or restored meanwhile.
    let Ok(text) = sealed_text(&path, "seal it with `ai-env creds setup-token`") else {
        return ScratchLogin::LoggedOut(format!("{} cannot be read", path.display()));
    };
    let tag = tag_of(&text);
    // Fails closed, as `vm exec` does: a store that cannot be read may hold this seal's refusal.
    match read_rejection(paths, &tag) {
        Ok(None) => {}
        Ok(Some(r)) => {
            return ScratchLogin::LoggedOut(format!("the sealed setup-token was refused by Anthropic on {} ({}) and is not unsealed again (`claude setup-token`, then `ai-env creds setup-token`)", r.at, r.vm));
        }
        Err(e) => return ScratchLogin::LoggedOut(format!("{}: which tokens Anthropic refused is unknown and the sealed setup-token is not unsealed (repair that file, or remove it to forget every recorded refusal)", one_line(&e))),
    }
    let deliver = if creds.deliver == "env" { Deliver::Env } else { Deliver::Fd };
    let (budget, capped) = scratch_unseal_budget(ms_knob(UNSEAL_TIMEOUT_KNOB).unwrap_or_else(|| creds.unseal_budget()), used);
    if budget.is_zero() {
        return ScratchLogin::LoggedOut(format!("the sealed setup-token was not unsealed (no time was left for Touch ID inside Cursor's {} s initialize window)", INITIALIZE_WINDOW.as_secs()));
    }
    if capped {
        tracing::info!(budget_s = budget.as_secs(), "the Touch ID budget ends {} s before Cursor's initialize window", INIT_FAIL_FAST.as_secs());
    }
    let started = std::time::Instant::now();
    let unsealed = Keystore::resolve(env("AI_ENV_DIR").filter(|d| !d.is_empty()).map(PathBuf::from)).and_then(|store| unseal_for_child(&store, &creds.key, &text, budget));
    let elapsed = started.elapsed();
    let outcome = match &unsealed {
        Ok(Unsealed::Token(_)) => "ok".to_string(),
        Ok(Unsealed::Stopped(sig)) => format!("signal {sig}"),
        Err(e) => format!("exit {}", e.exit_code()),
    };
    let detail = [("for", "local-scratch".to_string()), ("source", "setup-token".to_string()), ("ms", elapsed.as_millis().to_string()), ("outcome", outcome)];
    if let Err(e) = audit::append(&paths.audit(), &AuditRow::new("credential_unseal", None, audit::detail(&detail))) {
        tracing::warn!("audit credential_unseal: {e}");
    }
    match unsealed {
        Ok(Unsealed::Token(token)) => {
            tracing::info!(ms = elapsed.as_millis() as u64, len = token.len(), "setup-token unsealed for the local-scratch child");
            ScratchLogin::Sealed(ChildCredential { token, deliver, tag })
        }
        Ok(Unsealed::Stopped(sig)) => ScratchLogin::Stopped(stop_code(sig)),
        Err(e) => {
            let why = match &e {
                CliError::Cancelled => "the Touch ID dialog was dismissed".to_string(),
                CliError::AuthUnavailable(_) if elapsed >= budget && capped => format!("no Touch ID within {}: Cursor's {} s initialize window allows no more", budget_text(budget), INITIALIZE_WINDOW.as_secs()),
                CliError::AuthUnavailable(_) if elapsed >= budget => format!("no Touch ID within {}", budget_text(budget)),
                other => one_line(&other.to_string()),
            };
            ScratchLogin::LoggedOut(format!("the sealed setup-token was not unsealed ({why})"))
        }
    }
}

/// `60 s`, or `1500 ms` for a budget that is not whole seconds (the lab knob).
fn budget_text(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// The first line of `text`, scrubbed and at most 300 characters: what a
/// note line carries of an error.
fn one_line(text: &str) -> String {
    redact::scrub(text.lines().next().unwrap_or_default()).chars().take(300).collect()
}

/// One line on stderr. A closed stderr is ignored, never a panic: the
/// countdown speaks from a thread of its own.
fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// What the wait for Touch ID ended with.
enum Unsealed {
    Token(SetupToken),
    /// This signal arrived; the decrypt was killed, its dialog with it.
    Stopped(i32),
}

/// One killable, timed unseal of the sealed `text` with `key` (one Touch ID):
/// the countdown on stderr as `ai-env-claude`, the deadline `budget`. Signals
/// are caught before `age` exists, so from its first instant the dialog has an
/// owner that closes it ([`UnsealSignals`]); the dialog is killed while the
/// handlers still hold any further signal ([`await_unseal`]), and the
/// plaintext never leaves zeroizing memory. How the wait ends is
/// [`unseal_outcome`]'s.
fn unseal_for_child(store: &Keystore, key: &str, text: &str, budget: Duration) -> crate::errors::Result<Unsealed> {
    validate_key_name(key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let cont = crate::container::read(text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(key), &cont)?;
    let age = Arc::new(AgeTool::probe()?);
    let mut signals = UnsealSignals::catch().map_err(|e| CliError::Msg(format!("cannot catch signals for the unseal: {e}")))?;
    let job = UnsealJob::start(age, store.identity_path(&name), cont.data, budget, "the setup token").with_prefix("ai-env-claude");
    let kill = job.kill_handle();
    let (tx, rx) = std::sync::mpsc::channel();
    // A thread that cannot start drops the job, and its Drop closes the dialog.
    std::thread::Builder::new()
        .name("unseal-wait".into())
        .spawn(move || {
            let _ = tx.send(job.wait(say));
        })
        .map_err(|e| CliError::Msg(format!("cannot wait for the unseal: {e}")))?;
    let answer = await_unseal(&|| signals.caught(), &kill, &rx);
    // The decrypt is over either way: an answer came, or its group was killed above.
    unseal_outcome(signals.restore(), answer)
}

/// The wait for Touch ID: the decrypt's answer (`rx`), or `None` once
/// `caught` reports a signal. A stop kills the decrypt's group, then waits —
/// at most [`STOP_SETTLE`] after the stop — for the answer, which comes only
/// once the decrypt is over: given up before it spawned `age`, or with its
/// child adopted, killed (the kill is marked first) and reaped. So a stop
/// that came while `age` was being spawned, when the kill could not reach its
/// group yet, never lets the wrapper exit with the dialog up. That answer,
/// a plaintext included, is dropped (zeroized): the stop wins.
fn await_unseal(caught: &dyn Fn() -> Option<i32>, kill: &AgeKill, rx: &std::sync::mpsc::Receiver<crate::errors::Result<Zeroizing<Vec<u8>>>>) -> Option<crate::errors::Result<Zeroizing<Vec<u8>>>> {
    use std::sync::mpsc::RecvTimeoutError;
    loop {
        if caught().is_some() {
            let settle = std::time::Instant::now() + STOP_SETTLE;
            kill.kill_group();
            let _ = rx.recv_timeout(settle.saturating_duration_since(std::time::Instant::now()));
            return None;
        }
        match rx.recv_timeout(UNSEAL_POLL) {
            Ok(done) => return Some(done),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Some(Err(CliError::Msg("the unseal ended without an answer".into()))),
        }
    }
}

/// How the wait for Touch ID ends: a signal recorded until the dispositions
/// were restored wins over any answer — a plaintext (dropped, so zeroized), a
/// dismissed dialog, the deadline — so a wrapper told to stop never spawns;
/// otherwise the answer decides.
fn unseal_outcome(caught: Option<i32>, answer: Option<crate::errors::Result<Zeroizing<Vec<u8>>>>) -> crate::errors::Result<Unsealed> {
    match (caught, answer) {
        (Some(sig), _) => Ok(Unsealed::Stopped(sig)),
        (None, Some(done)) => Ok(Unsealed::Token(parse_token_env(&done?)?)),
        (None, None) => Err(CliError::Msg("the unseal stopped without an answer".into())),
    }
}

/// The signal caught while Touch ID was awaited (0: none).
static UNSEAL_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Only records the signal: an atomic store is async-signal-safe.
extern "C" fn record_unseal_signal(sig: libc::c_int) {
    UNSEAL_SIGNAL.store(sig, Ordering::SeqCst);
}

/// SIGINT, SIGTERM and SIGHUP caught while this lives, their previous
/// dispositions restored when it drops. `age` runs in its own process group,
/// so a terminal's Ctrl-C never reaches it, and the extension signals the
/// wrapper alone: a wrapper ended by the default action during the wait would
/// leave the Touch ID dialog behind. A signal ignored when the wrapper started
/// stays ignored. SIGKILL cannot be caught: its dialog stays until answered,
/// and the plaintext then goes nowhere (age's stdout reader is gone).
struct UnsealSignals {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl UnsealSignals {
    fn catch() -> std::io::Result<UnsealSignals> {
        UNSEAL_SIGNAL.store(0, Ordering::SeqCst);
        let mut caught = UnsealSignals { previous: Vec::new() };
        let handler: extern "C" fn(libc::c_int) = record_unseal_signal;
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: sigaction(2) on zeroed (valid) structs; the handler only
            // stores to an atomic. On an error `caught` drops and restores
            // what was already replaced.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &raw mut old) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if old.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler as libc::sighandler_t;
                act.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&raw mut act.sa_mask);
                if libc::sigaction(sig, &raw const act, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                caught.previous.push((sig, old));
            }
        }
        Ok(caught)
    }

    /// The signal that arrived since [`Self::catch`], if any.
    fn caught(&self) -> Option<i32> {
        let sig = UNSEAL_SIGNAL.load(Ordering::SeqCst);
        (sig != 0).then_some(sig)
    }

    /// Put the previous dispositions back, then report the signal recorded up
    /// to that instant: one that came with the answer, or between the last
    /// look and here, is never lost. A later one takes its default course.
    fn restore(&mut self) -> Option<i32> {
        for (sig, old) in self.previous.drain(..).rev() {
            // SAFETY: restores a disposition sigaction(2) itself returned.
            unsafe { libc::sigaction(sig, &raw const old, std::ptr::null_mut()) };
        }
        self.caught()
    }
}

impl Drop for UnsealSignals {
    fn drop(&mut self) {
        // Idempotent: `restore` already emptied the list.
        self.restore();
    }
}

/// A signal ended the wrapper while Touch ID was awaited (the dialog is
/// closed): nothing was spawned. The scratch dir goes as an unregistered
/// invocation's does, the census gets its end row (`end:sigterm`, and with
/// [`SYNTHETIC_OAUTH_KNOB`] `synthetic_oauth:unsent`: the session was never
/// initialized), and the wrapper exits with `code`.
fn stop_before_spawn(sess: &Session, plan: &ChildPlan, code: i32) -> ! {
    say("ai-env-claude: stopped while waiting for Touch ID: the dialog was closed and nothing was started");
    tracing::info!(code, "stopped by a signal during the unseal");
    let _ = finish_scratch(plan, false, None);
    let synthetic_oauth = Synthetic::from_knob().as_ref().map(Synthetic::census);
    let out = Outcome { code: Some(code), end: Some(EndReason::SigTerm), credential: Some("none"), synthetic_oauth, ..Outcome::default() };
    if let Err(e) = census::record(&sess.paths.census(), &end_row(&sess.start_row, &out, unix_now_ms())) {
        say(&format!("ai-env-claude: census: {e}"));
    }
    std::process::exit(code)
}

// ---- the synthetic oauth_token_refresh's answer ---------------------------------------------

/// The class of the host's answer to the synthetic request, as the end row
/// records it: `token(len=<n>)` (a success with an `accessToken` string —
/// only its length is kept; the value is read into a zeroizing `Secret` and
/// dropped), `null` (`accessToken: null`), `absent` (a success without
/// one), `malformed` (an `accessToken` that is no string), `error(<text>)`
/// (the stock extension: `getOAuthToken callback is not provided.`), or
/// `other(<subtype>)`. Texts are scrubbed and bounded ([`note_text`]). The
/// line itself, in the pump's read buffers, is freed without zeroizing: the
/// leak S7 accepts for serde and transport buffers (a stock extension sends
/// no token at all).
#[must_use]
pub fn synthetic_answer_class(line: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Line<'a> {
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Answer<'a> {
        #[serde(default)]
        subtype: Option<String>,
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
        #[serde(borrow, default)]
        error: Option<&'a RawValue>,
    }
    let Some(answer) = serde_json::from_slice::<Line<'_>>(line).ok().and_then(|l| l.response).and_then(|r| serde_json::from_str::<Answer<'_>>(r.get()).ok()) else {
        return "other(unparseable)".into();
    };
    match answer.subtype.as_deref() {
        Some("success") => {
            let fields: BTreeMap<String, &RawValue> = answer.response.and_then(|r| serde_json::from_str(r.get()).ok()).unwrap_or_default();
            match fields.get("accessToken") {
                None => "absent".into(),
                Some(raw) if raw.get() == "null" => "null".into(),
                Some(raw) => match serde_json::from_str::<Secret<String>>(raw.get()) {
                    Ok(token) => format!("token(len={})", token.expose().len()),
                    Err(_) => "malformed".into(),
                },
            }
        }
        Some("error") => {
            let text = answer.error.and_then(|e| serde_json::from_str::<String>(e.get()).ok()).unwrap_or_default();
            format!("error({})", note_text(&text, SYNTHETIC_ERROR_CHARS))
        }
        other => format!("other({})", note_text(other.unwrap_or("-"), 32)),
    }
}

/// `text` fit for one `; `-separated note part: scrubbed, `;` made `,`,
/// control characters made spaces, at most `max` characters (`…` when cut).
fn note_text(text: &str, max: usize) -> String {
    let clean: String = redact::scrub(text).chars().map(|c| if c == ';' { ',' } else if c.is_control() { ' ' } else { c }).collect();
    if clean.chars().count() > max {
        format!("{}\u{2026}", clean.chars().take(max.saturating_sub(1)).collect::<String>())
    } else {
        clean
    }
}

/// Exec the real binary as S1 does (the pump could not start).
fn exec_unpiped(sess: &Session) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&sess.real_binary).args(&sess.args).exec();
    eprintln!("ai-env-claude: cannot exec {}: {err}", sess.real_binary.display());
    std::process::exit(1)
}

/// Pipe `sess` through the pump and exit with the child's code. Never returns.
///
/// Order: logging (the first production caller of `logging::init`; a
/// failure is one stderr line, never fatal) → register
/// `CLAUDE_CODE_OAUTH_TOKEN` as a secret → the child plan (on failure: one
/// stderr line and S1's exec) → the runtime (before any Touch ID, so a
/// runtime that cannot start never wastes one) → `local-scratch`: the
/// scratch dir, the child's login ([`scratch_login`]: the sealed token, or
/// one note line), the pre-spawn seed → the supervisor → mirror fsync →
/// registry row closed → census end row → the lab message → exit.
pub fn run(sess: Session) -> ! {
    let log_path = sess.paths.wrapper_log();
    if let Err(e) = logging::init(&LogOpts { path: log_path, rust_log: std::env::var("RUST_LOG").ok() }) {
        eprintln!("ai-env-claude: log: {e}");
    }
    if let Some(token) = std::env::var_os(TOKEN_VAR) {
        redact::register_secret(&token.to_string_lossy());
    }
    let env = |k: &str| std::env::var_os(k);
    let mut fresh = || uuid::Uuid::now_v7().to_string();
    let plan = match child_plan(&sess, &env, &mut fresh) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ai-env-claude: pump unavailable ({e}); running unpiped");
            tracing::warn!("pump unavailable: {e}");
            exec_unpiped(&sess)
        }
    };
    tracing::info!(mode = sess.mode.name(), argc = plan.argv.len(), resume = plan.resume.is_some(), scratch = plan.scratch.is_some(), "piping the session");
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ai-env-claude: cannot start the pump runtime ({e}); running unpiped");
            exec_unpiped(&sess)
        }
    };
    let mut login = None;
    if let Some(dir) = &plan.scratch {
        if let Err(e) = prepare_scratch(dir) {
            eprintln!("ai-env-claude: scratch dir {}: {e}; running unpiped", dir.display());
            exec_unpiped(&sess)
        }
        // Cursor's initialize window runs from the wrapper's spawn; the start row was stamped just after it.
        let used = Duration::from_millis(unix_now_ms().saturating_sub(sess.start_row.start));
        let decided = scratch_login(&sess, &env, used);
        tracing::info!(credential = decided.word(), "local-scratch login decided");
        match &decided {
            ScratchLogin::LoggedOut(why) => say(&logged_out_note(why)),
            ScratchLogin::Stopped(code) => stop_before_spawn(&sess, &plan, *code),
            ScratchLogin::Inherited | ScratchLogin::Sealed(_) => {}
        }
        login = Some(decided);
        if let Some(resume) = &plan.resume {
            match seed_from_mac(&sess, &plan, resume, false) {
                SeedOutcome::Seeded(_) => {}
                SeedOutcome::KeptNewer(p) => tracing::info!("resume: scratch transcript {} kept", p.display()),
                SeedOutcome::NoSource => tracing::info!("resume: no local transcript for {resume}"),
                SeedOutcome::Failed(e) => tracing::warn!("resume: seeding failed: {e}"),
            }
        }
    }
    if plan.slug.is_some() && plan.slug != sess.cwd.as_deref().and_then(|c| slug::project_dir_name(c).ok()) {
        tracing::warn!("the child's projects subdirectory differs from the picker's slug of the cwd (CLAUDE_CODE_PROJECT_DIR_NAME?)");
    }
    tracing::info!("{}", plan.mirror.reason);
    let mut pump = Pump::new(sess, plan, login);
    let code = rt.block_on(pump.supervise());
    // `process::exit` runs no destructor: the token, if one is still held, is zeroized here.
    pump.settle_credential(true, "the session ended");
    if let Err(e) = pump.mirror.sync_all() {
        tracing::warn!("mirror fsync: {e}");
    }
    let mut out = pump.snapshot_outcome();
    out.code = Some(code);
    out.end = pump.finish.map(|f| f.1);
    let scratch = finish_scratch(&pump.plan, pump.registered, pump.first_session_id.as_deref());
    if let (Some(row), Some(dir)) = (&mut pump.row, &scratch) {
        row.scratch_dir = Some(dir.display().to_string());
    }
    pump.close_row(Some(code));
    if !pump.ignored_sigterm_row {
        pump.write_end_row(&out);
    }
    tracing::info!(code, end = out.end.map_or("unknown", EndReason::name), "pump done");
    if let Some(msg) = pump.lab_message.take() {
        eprintln!("{msg}");
    }
    // Never drop the runtime: its blocking stdin reader would hold the exit.
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::credential::seal_tag;
    use crate::wire::argv::LocalReason;

    fn start_row() -> CensusRow {
        CensusRow {
            v: 1,
            ts: "2026-09-25T10:00:00Z".into(),
            start: 1_000,
            pid: 42,
            ppid: 1,
            ext: Some("2.1.282".into()),
            route: "local".into(),
            reason: "unconfigured".into(),
            argv: vec!["w".into(), "b".into(), "--output-format".into(), "stream-json".into()],
            cwd: Some("/x".into()),
            env_names: vec!["HOME".into()],
            env_selected: std::collections::BTreeMap::new(),
            note: Some("mode:local-child".into()),
            end: None,
            exit: None,
        }
    }

    fn session(mode: Mode, args: &[&str], root: &Path) -> Session {
        let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let route = argv::classify(&args);
        let session = match &route {
            Route::Remote(s) => s.clone(),
            Route::Local(_) => SessionArgs::default(),
        };
        let route = if matches!(route, Route::Remote(_)) { Route::Local(LocalReason::Unconfigured) } else { route };
        Session {
            real_binary: PathBuf::from("/bin/claude"),
            args,
            route,
            session,
            cwd: Some(root.to_path_buf()),
            paths: Paths::from_root_and_env(root.join("bridge"), None),
            cfg: None,
            mode,
            start_row: start_row(),
        }
    }

    fn env_of(pairs: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn end_row_clones_the_start_row_and_extends_the_note() {
        let out = Outcome {
            code: Some(3),
            end: Some(EndReason::LabExit),
            child_pid: Some(77),
            respawns: 1,
            mirror_frames: 2,
            mirror_rejected: 1,
            dropped_lines: 0,
            oauth_answered: 1,
            init_latency_ms: Some(120),
            eof_to_sigterm_ms: None,
            session_id: None,
            credential: None,
            synthetic_oauth: None,
        };
        let row = end_row(&start_row(), &out, 9_000);
        assert_eq!((row.end, row.exit, row.pid, row.start), (Some(9_000), Some(3), 42, 1_000), "paired with the start row on (pid, start)");
        assert_eq!(
            row.note.as_deref(),
            Some("mode:local-child; end:lab_exit; child_pid:77; respawns:1; mirror:2/1; dropped:0; oauth_refresh_answered:1; init_ms:120")
        );
        let mut bare = start_row();
        bare.note = None;
        let row = end_row(&bare, &Outcome { code: None, ..Outcome::default() }, 5);
        assert_eq!(row.exit, None);
        assert!(row.note.unwrap().starts_with("end:unknown; child_pid:-"));
        let json = serde_json::to_string(&end_row(&start_row(), &Outcome { code: None, ..Outcome::default() }, 5)).unwrap();
        assert!(json.contains("\"end\":5") && !json.contains("\"exit\""), "exit: null is omitted: {json}");
    }

    #[test]
    fn child_plan_local_child_keeps_argv_and_env() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalChild, &["--output-format", "stream-json", "--add-dir", "/o", "--debug", "--replay-user-messages"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "x".to_string()).unwrap();
        assert_eq!(plan.argv, vec!["--output-format", "stream-json", "--add-dir", "/o", "--debug", "--replay-user-messages", "--session-mirror"]);
        assert!(plan.env_set.is_empty() && plan.env_remove.is_empty());
        assert_eq!(plan.child_config_dir, d.path().join(".claude"));
        assert_eq!(plan.scratch, None);
        assert!(!plan.mirror.enabled, "{}", plan.mirror.reason);
        assert!(plan.mirror.reason.starts_with("mirror writer disabled:"), "{}", plan.mirror.reason);
        assert_eq!(plan.slug, slug::project_dir_name(d.path()).ok());
        // With a mirror root the writer is on.
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned()), (MIRROR_ROOT_ENV, d.path().join("m").into_os_string())]);
        assert!(child_plan(&sess, &env, &mut || "x".to_string()).unwrap().mirror.enabled);
    }

    #[test]
    fn child_plan_local_scratch_points_the_child_at_a_scratch_dir() {
        let d = tempfile::tempdir().unwrap();
        let uuid = "11111111-2222-4333-8444-555555555555";
        let resume = format!("--resume={uuid}");
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", &resume], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned()), ("CLAUDE_CODE_PROJECT_DIR_NAME", OsString::from("custom-dir"))]);
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        let scratch = d.path().join("bridge").join("state").join("scratch").join(uuid);
        assert_eq!(plan.scratch.as_deref(), Some(scratch.as_path()));
        assert_eq!(plan.env_set, vec![("CLAUDE_CONFIG_DIR".to_string(), scratch.clone().into_os_string())]);
        assert_eq!(plan.env_remove, vec![SECURE_STORAGE_ENV.to_string(), TOKEN_FD_VAR.to_string()], "no inherited keychain pointer, no inherited token descriptor");
        assert_eq!(plan.resume.as_deref(), Some(uuid));
        assert_eq!(plan.slug.as_deref(), Some("custom-dir"), "the override applies because CLAUDE_CONFIG_DIR is set for the child");
        assert!(plan.mirror.enabled, "a scratch child writes elsewhere: the writer mirrors into the Mac's projects dir");
        assert_eq!(plan.mirror.dest_root, d.path().join(".claude").join("projects"));
        // Without --resume the scratch dir gets a fresh name; a non-uuid resume is not trusted.
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", "--resume=../../etc"], d.path());
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        assert_eq!(plan.resume, None);
        assert!(plan.scratch.unwrap().ends_with("fresh"));
    }

    #[test]
    fn child_plan_refuses_non_pipe_modes_and_a_missing_home() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::Passthrough, &["--output-format", "stream-json"], d.path());
        assert!(child_plan(&sess, &env_of(vec![("HOME", OsString::from("/h"))]), &mut || "x".into()).is_err());
        let sess = session(Mode::LocalChild, &["--output-format", "stream-json"], d.path());
        assert!(child_plan(&sess, &env_of(vec![]), &mut || "x".into()).is_err(), "no HOME and no CLAUDE_CONFIG_DIR");
        let plan = child_plan(&sess, &env_of(vec![("CLAUDE_CONFIG_DIR", d.path().join("cfg").into_os_string())]), &mut || "x".into()).unwrap();
        assert_eq!(plan.child_config_dir, d.path().join("cfg"));
    }

    #[test]
    fn child_slug_prefers_a_valid_override_only_with_a_config_dir() {
        let d = tempfile::tempdir().unwrap();
        let cwd_slug = slug::project_dir_name(d.path()).ok();
        assert_eq!(child_slug(Some(d.path()), false, Some("custom")), cwd_slug, "ignored without CLAUDE_CONFIG_DIR");
        assert_eq!(child_slug(Some(d.path()), true, Some("custom")).as_deref(), Some("custom"));
        assert_eq!(child_slug(Some(d.path()), true, Some("bad/name")), cwd_slug, "an invalid override falls back");
        assert_eq!(child_slug(None, false, None), None);
    }

    #[test]
    fn scratch_dirs_are_renamed_to_the_session_id_once() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "01a0d961-56d6-72c3-8573-4acdf7f8ad65".to_string()).unwrap();
        let from = plan.scratch.clone().unwrap();
        prepare_scratch(&from).unwrap();
        std::fs::write(from.join("x"), "y").unwrap();
        let sid = "33333333-0000-4000-8000-000000000003";
        assert_eq!(rename_scratch(&plan, Some("not-a-uuid")), None);
        assert_eq!(rename_scratch(&plan, None), None);
        let to = rename_scratch(&plan, Some(sid)).unwrap();
        assert_eq!(to, from.parent().unwrap().join(sid));
        assert_eq!(std::fs::read_to_string(to.join("x")).unwrap(), "y");
        // An existing target is never replaced.
        prepare_scratch(&from).unwrap();
        assert_eq!(rename_scratch(&plan, Some(sid)), None);
        assert!(from.exists());
    }

    #[test]
    fn route_labels() {
        assert_eq!(route_label(&Route::Remote(SessionArgs::default())), "remote");
        assert_eq!(route_label(&Route::Local(LocalReason::OutsideRoots)), "local:outside_roots");
    }

    #[test]
    fn end_reason_names_are_stable() {
        let all = [
            (EndReason::ChildExit, "child_exit"),
            (EndReason::EofTerm, "eof"),
            (EndReason::EofKill, "eof_kill"),
            (EndReason::SigTerm, "sigterm"),
            (EndReason::HostGone, "host_gone"),
            (EndReason::LabExit, "lab_exit"),
            (EndReason::SpawnFailed, "spawn_failed"),
        ];
        for (r, n) in all {
            assert_eq!(r.name(), n);
        }
    }

    /// The end row carries how a scratch child logged in and the synthetic
    /// answer's class, after the S2 parts; without them it is unchanged.
    #[test]
    fn end_row_records_the_login_and_the_synthetic_answer() {
        let out = Outcome { code: Some(0), end: Some(EndReason::EofTerm), credential: Some("fd"), synthetic_oauth: Some("error(getOAuthToken callback is not provided.)".into()), ..Outcome::default() };
        let note = end_row(&start_row(), &out, 9_000).note.unwrap();
        assert!(note.ends_with("; oauth_refresh_answered:0; credential:fd; synthetic_oauth:error(getOAuthToken callback is not provided.)"), "{note}");
        let plain = end_row(&start_row(), &Outcome::default(), 9_000).note.unwrap();
        assert!(!plain.contains("credential:") && !plain.contains("synthetic_oauth:"), "{plain}");
    }

    /// The lab knobs' `_MS` values parse as the S2 knobs do: a positive number
    /// of milliseconds, anything else off.
    #[test]
    fn ms_knobs_parse_like_the_s2_knobs() {
        assert_eq!(parse_ms_knob(None), None);
        assert_eq!(parse_ms_knob(Some("300")), Some(Duration::from_millis(300)));
        assert_eq!(parse_ms_knob(Some(" 40 ")), Some(Duration::from_millis(40)));
        for off in ["0", "-5", "x", "", "1.5"] {
            assert_eq!(parse_ms_knob(Some(off)), None, "{off:?}");
        }
        assert_eq!(TOKEN_FD_VAR, format!("{TOKEN_VAR}_FILE_DESCRIPTOR"), "the shim's name for the slot");
        assert!(!census::CENSUS_VALUE_ALLOWLIST.contains(&SYNTHETIC_OAUTH_KNOB), "its name holds AUTH: never allowlisted");
    }

    /// Each class of the extension's answer, and never the token: a returned
    /// `accessToken` is recorded as present with its length only; error texts
    /// are scrubbed, bounded and kept to one note part.
    #[test]
    fn synthetic_answers_are_classified_without_their_token() {
        let answer = |inner: &str| format!(r#"{{"type":"control_response","response":{inner}}}"#).into_bytes();
        let token = format!("{}oat01-{}", "sk-ant-", "Tk4_".repeat(12));
        let with_token = answer(&format!(r#"{{"subtype":"success","request_id":"s1","response":{{"accessToken":"{token}"}}}}"#));
        let class = synthetic_answer_class(&with_token);
        assert_eq!(class, format!("token(len={})", token.len()));
        assert!(!class.contains(&token[7..]), "only the length is kept");
        let cases = [
            (r#"{"subtype":"success","request_id":"s1","response":{"accessToken":null}}"#, "null"),
            (r#"{"subtype":"success","request_id":"s1","response":{}}"#, "absent"),
            (r#"{"subtype":"success","request_id":"s1"}"#, "absent"),
            (r#"{"subtype":"success","request_id":"s1","response":{"accessToken":42}}"#, "malformed"),
            (r#"{"subtype":"error","request_id":"s1","error":"getOAuthToken callback is not provided."}"#, "error(getOAuthToken callback is not provided.)"),
            (r#"{"subtype":"error","request_id":"s1"}"#, "error()"),
            (r#"{"subtype":"cancelled","request_id":"s1"}"#, "other(cancelled)"),
            (r#"{"request_id":"s1"}"#, "other(-)"),
        ];
        for (inner, want) in cases {
            assert_eq!(synthetic_answer_class(&answer(inner)), want, "{inner}");
        }
        assert_eq!(synthetic_answer_class(b"not json"), "other(unparseable)");
        // One note part: `;` and control characters go, the text is bounded and scrubbed.
        let long = format!("a;b\nc {} {}", token, "z".repeat(400));
        let class = synthetic_answer_class(&answer(&format!(r#"{{"subtype":"error","request_id":"s1","error":{}}}"#, serde_json::to_string(&long).unwrap())));
        assert!(class.starts_with("error(a,b c sk-ant-[redacted:len=") && class.ends_with("\u{2026})"), "{} chars", class.len());
        assert!(!class.contains(&token[7..]) && !class.contains(';') && !class.contains('\n'));
        assert_eq!(class.chars().count(), "error()".len() + SYNTHETIC_ERROR_CHARS);
    }

    /// F12 (M46): a `local-scratch` token of a shape the scrubber's rules do
    /// not mask whole is masked while the wrapper holds it (its handle's
    /// registration, `parse_token`'s) and no longer once `drop_credential`
    /// let the copy go: the scrubber keeps no plain copy of it for the rest of
    /// a session that may run for hours (no holder is left to forget).
    #[test]
    fn an_unrecognised_scratch_tokens_masking_ends_with_the_wrappers_copy() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        let odd = format!("odd-shape-scratch-{}", "Q8".repeat(12));
        let masked = |v: &str| !redact::scrub(&format!("x {v} y")).contains(v);
        let token = crate::bridge::setup_token::parse_token(&odd).unwrap_or_else(|f| panic!("{}", f.message));
        let mut pump = Pump::new(sess, plan, Some(ScratchLogin::Sealed(ChildCredential { token, deliver: Deliver::Fd, tag: "seal".into() })));
        assert!(masked(&odd), "masked while the wrapper holds it");
        pump.drop_credential("the test");
        assert!(pump.credential.is_none(), "the copy is gone");
        assert!(!masked(&odd), "the scrubber still holds a copy after the wrapper dropped its own");
        assert!(!redact::forget_secret(&odd), "a holder of the registration is left");
    }

    /// F9: the `initialize` grace of a `--resume` drops the copy only while
    /// no resume miss is held and generation 1 still runs. A held miss, or a
    /// child already exited (its drain may still bring one), keeps it for
    /// the seed retry's respawn (or the finish); either way the grace fires
    /// once.
    #[test]
    fn the_initialize_grace_keeps_the_copy_for_a_held_miss_or_an_exited_child() {
        let d = tempfile::tempdir().unwrap();
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let grace_over = |held_miss: bool, exited: bool| {
            let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", "--resume=11111111-2222-4333-8444-5555aaaa5555"], d.path());
            let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
            assert!(plan.resume.is_some(), "a --resume, so a seed retry is possible");
            let token = crate::bridge::setup_token::parse_token(&format!("{}oat01-{}", "sk-ant-", "Gr9_".repeat(12))).unwrap_or_else(|f| panic!("{}", f.message));
            let mut pump = Pump::new(sess, plan, Some(ScratchLogin::Sealed(ChildCredential { token, deliver: Deliver::Fd, tag: "seal".into() })));
            pump.gen = 1;
            let now = Instant::now();
            pump.credential_hold_until = Some(now);
            if held_miss {
                pump.held_miss = Some(Bytes::from_static(br#"{"type":"result","subtype":"error_during_execution"}"#));
            }
            if exited {
                pump.child_exit = Some(None);
                pump.exit_seen_at = Some(now);
            }
            pump.on_deadline(now);
            assert!(pump.credential_hold_until.is_none(), "the grace fires once (miss {held_miss}, exited {exited})");
            pump.credential.is_some()
        };
        assert!(!grace_over(false, false), "no miss within the grace and the child running: the copy goes");
        assert!(grace_over(true, false), "a held miss: the copy is kept for the seed retry");
        assert!(grace_over(false, true), "a child already exited: kept until its drain settles");
        assert!(grace_over(true, true), "a held miss from an exited child: kept");
    }

    /// Before any unseal: a token in the environment wins; no sealed file, a
    /// file that is not a container, a `[creds]` that does not validate, a
    /// seal Anthropic refused, a `state/creds.toml` that cannot be read (M53:
    /// it may hold this seal's refusal; the note names the file) and an
    /// initialize window already spent each run the child logged out without
    /// asking for Touch ID; a key the keystore lacks fails before `age` is
    /// probed, and that unseal is audited.
    #[test]
    fn scratch_login_decides_without_touch_id_where_it_can() {
        let d = tempfile::tempdir().unwrap();
        let mut sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let keys = d.path().join("keys");
        let keys_os = keys.clone().into_os_string();
        let env = env_of(vec![("AI_ENV_DIR", keys_os.clone())]);
        let inherited = env_of(vec![(TOKEN_VAR, OsString::from("from-the-shell")), ("AI_ENV_DIR", keys_os.clone())]);
        let now = Duration::ZERO;
        assert!(matches!(scratch_login(&sess, &inherited, now), ScratchLogin::Inherited));
        let logged_out = |l: ScratchLogin| match l {
            ScratchLogin::LoggedOut(why) => why,
            other => panic!("{}", other.word()),
        };
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.starts_with("no setup-token is sealed"), "{why}");
        assert!(logged_out_note(&why).starts_with("ai-env-claude: local-scratch without CLAUDE_CODE_OAUTH_TOKEN: no setup-token is sealed"));
        // An empty variable is no token.
        let empty = env_of(vec![(TOKEN_VAR, OsString::new())]);
        assert!(logged_out(scratch_login(&sess, &empty, now)).starts_with("no setup-token is sealed"));
        let path = sess.paths.setup_token_env();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{TOKEN_VAR}=plain\n")).unwrap();
        assert!(logged_out(scratch_login(&sess, &env, now)).contains("is not an ai-env container"));
        std::fs::write(&path, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        sess.cfg = Some(BridgeConfig::parse("[creds]\ndeliver = \"smoke\"\n").unwrap());
        assert!(logged_out(scratch_login(&sess, &env, now)).contains("[creds].deliver"));
        sess.cfg = None;
        let tag = seal_tag(&path).unwrap();
        std::fs::create_dir_all(sess.paths.creds_state().parent().unwrap()).unwrap();
        std::fs::write(sess.paths.creds_state(), format!("[[rejected]]\ntag = \"{tag}\"\nat = \"2026-10-08T09:00:00Z\"\nvm = \"microvm-test\"\n")).unwrap();
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.contains("refused by Anthropic on 2026-10-08T09:00:00Z (microvm-test)"), "{why}");
        std::fs::write(sess.paths.creds_state(), "[[rejected]\n").unwrap();
        let why = logged_out(scratch_login(&sess, &env, now));
        let unreadable = format!("{} cannot be parsed (", sess.paths.creds_state().display());
        assert!(why.starts_with(&unreadable) && why.contains("which tokens Anthropic refused is unknown and the sealed setup-token is not unsealed"), "{why}");
        std::fs::remove_file(sess.paths.creds_state()).unwrap();
        // 50 s of the window already gone: nothing is left for Touch ID.
        let why = logged_out(scratch_login(&sess, &env, Duration::from_secs(50)));
        assert_eq!(why, "the sealed setup-token was not unsealed (no time was left for Touch ID inside Cursor's 60 s initialize window)");
        let audit = std::fs::read_to_string(sess.paths.audit()).unwrap_or_default();
        assert!(!audit.contains("credential_unseal"), "nothing was unsealed: {audit}");
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.starts_with("the sealed setup-token was not unsealed (key \"ai-env-bridge\" does not exist"), "{why}");
        let audit = std::fs::read_to_string(sess.paths.audit()).unwrap();
        assert!(audit.contains("\"event\":\"credential_unseal\"") && audit.contains("\"outcome\":\"exit 4\""), "{audit}");
        assert_eq!(budget_text(Duration::from_secs(60)), "60 s");
        assert_eq!(budget_text(Duration::from_millis(1500)), "1500 ms");
    }

    /// F11: the unseal decrypts the very text whose seal id was checked
    /// against the refusals, never a second read of `setup-token.env`. The
    /// `AI_ENV_DIR` lookup comes between the check and the unseal; there the
    /// file is removed: the unseal still goes on with the text already read,
    /// to the keystore, which lacks the key (so `age` is never probed). A
    /// second read would have failed on the missing file instead.
    #[test]
    fn the_unseal_decrypts_the_text_whose_seal_was_checked() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let keys = d.path().join("keys");
        let path = sess.paths.setup_token_env();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        let env = |k: &str| -> Option<OsString> {
            if k == "AI_ENV_DIR" {
                let _ = std::fs::remove_file(&path);
                return Some(keys.clone().into_os_string());
            }
            None
        };
        let why = match scratch_login(&sess, &env, Duration::ZERO) {
            ScratchLogin::LoggedOut(why) => why,
            other => panic!("{}", other.word()),
        };
        assert!(!path.exists(), "the file was removed between the check and the unseal");
        assert!(why.starts_with("the sealed setup-token was not unsealed (key \"ai-env-bridge\" does not exist"), "the file was read again: {why}");
    }

    /// The unseal ends T−10 s into Cursor's 60 s initialize window, so a
    /// logged-out child can still answer in time: the default
    /// `[creds].unseal_timeout_s` (60 s) and the range's top become 50 s, a
    /// shorter budget (the lab knob's included) is kept, time already used
    /// counts in whole seconds, and a spent window leaves nothing.
    #[test]
    fn the_unseal_budget_ends_ten_seconds_before_the_initialize_window() {
        let s = Duration::from_secs;
        let default = crate::bridge::config::CredsCfg::default().unseal_budget();
        assert_eq!(default, s(60), "the default [creds].unseal_timeout_s");
        assert_eq!(scratch_unseal_budget(default, Duration::ZERO), (s(50), true));
        assert_eq!(scratch_unseal_budget(default, Duration::from_millis(900)), (s(50), true), "under a second comes out of the margin");
        assert_eq!(scratch_unseal_budget(default, Duration::from_millis(3_200)), (s(47), true));
        assert_eq!(scratch_unseal_budget(s(600), Duration::ZERO), (s(50), true));
        assert_eq!(scratch_unseal_budget(s(30), Duration::from_millis(200)), (s(30), false));
        assert_eq!(scratch_unseal_budget(Duration::from_millis(1500), Duration::ZERO), (Duration::from_millis(1500), false));
        assert_eq!(scratch_unseal_budget(default, s(55)), (Duration::ZERO, true));
    }

    /// A signal recorded before the dispositions were restored ends the wait
    /// whatever the answer — a dismissed dialog included, so the wrapper never
    /// spawns after being told to stop; without one the answer decides. Ctrl-C
    /// exits 130, SIGTERM and SIGHUP 143.
    #[test]
    fn a_signal_wins_over_any_answer_of_the_unseal() {
        let stopped = |r: crate::errors::Result<Unsealed>| match r {
            Ok(Unsealed::Stopped(sig)) => sig,
            Ok(Unsealed::Token(_)) => panic!("a token, not a stop"),
            Err(e) => panic!("an error, not a stop: {e}"),
        };
        let plain = || Zeroizing::new(format!("{TOKEN_VAR}={}oat01-{}\n", "sk-ant-", "Sw1_".repeat(12)).into_bytes());
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGTERM), Some(Err(CliError::Cancelled)))), libc::SIGTERM, "a dismissed dialog and a SIGTERM: stop");
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGHUP), Some(Err(CliError::AuthUnavailable("deadline".into()))))), libc::SIGHUP);
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGINT), Some(Ok(plain())))), libc::SIGINT, "the plaintext is dropped");
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGINT), None)), libc::SIGINT);
        assert!(matches!(unseal_outcome(None, Some(Err(CliError::Cancelled))), Err(CliError::Cancelled)));
        match unseal_outcome(None, Some(Ok(plain()))) {
            Ok(Unsealed::Token(t)) => assert_eq!(t.len(), plain().len() - TOKEN_VAR.len() - 2, "the value, without its name and newline"),
            _ => panic!("no token from a good answer"),
        }
        assert!(unseal_outcome(None, None).is_err());
        assert_eq!((stop_code(libc::SIGINT), stop_code(libc::SIGTERM), stop_code(libc::SIGHUP)), (130, 143, 143), "as vm exec's unseal");
    }

    /// F21: a stop that comes while `age` is being spawned — the decrypt past
    /// its `cancelled()` check, its child not adopted yet, so `kill_group`
    /// finds nothing to signal — waits for the decrypt's answer, which comes
    /// once the child was adopted, killed (the kill was marked first) and
    /// reaped: the wrapper never goes on to exit with the dialog's process
    /// group alive. The decrypt here stands for `AgeKill`'s: its child is a
    /// `sleep` in a group of its own, adopted 100 ms after the stop.
    #[test]
    fn a_stop_while_age_is_spawned_waits_until_its_group_is_gone() {
        use std::os::unix::process::CommandExt as _;
        let kill = Arc::new(AgeKill::new());
        let (tx, rx) = std::sync::mpsc::channel();
        let (pid_tx, pid_rx) = std::sync::mpsc::channel();
        let decrypt = Arc::clone(&kill);
        let worker = std::thread::spawn(move || {
            let mut child = std::process::Command::new("/bin/sleep").arg("30").process_group(0).spawn().expect("spawn sleep");
            let pgid = i32::try_from(child.id()).unwrap();
            pid_tx.send(pgid).unwrap();
            // The stop comes first; the adoption 100 ms later.
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while !decrypt.cancelled() && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(100));
            // What `AgeKill::adopt` does to a cancelled decrypt's child (and, were it never cancelled, the cleanup).
            // SAFETY: killpg(2) on our own unreaped child's group.
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
            let _ = child.wait();
            let _ = tx.send(Err(CliError::Cancelled));
        });
        let pgid = pid_rx.recv().unwrap();
        let answer = await_unseal(&|| Some(libc::SIGTERM), &kill, &rx);
        // SAFETY: signal 0 only checks for existence.
        let alive = unsafe { libc::killpg(pgid, 0) } == 0;
        worker.join().unwrap();
        assert!(answer.is_none() && kill.cancelled(), "a stop wins, and marks the kill");
        assert!(!alive, "the wait for Touch ID ended on a stop while the decrypt's group was alive");
    }

    /// F21: the wait after a stop is bounded ([`STOP_SETTLE`]) for a decrypt
    /// that never answers; without a stop the answer decides, and a wait
    /// thread gone without one is an error, never a success.
    #[test]
    fn the_wait_after_a_stop_is_bounded_and_without_one_the_answer_decides() {
        let (tx, rx) = std::sync::mpsc::channel::<crate::errors::Result<Zeroizing<Vec<u8>>>>();
        let started = std::time::Instant::now();
        assert!(await_unseal(&|| Some(libc::SIGINT), &AgeKill::new(), &rx).is_none());
        let took = started.elapsed();
        assert!(took >= STOP_SETTLE - Duration::from_millis(20) && took < STOP_SETTLE + Duration::from_secs(2), "a stop waited {took:?} for a decrypt that never answers, not about {STOP_SETTLE:?}");
        tx.send(Err(CliError::Cancelled)).unwrap();
        assert!(matches!(await_unseal(&|| None, &AgeKill::new(), &rx), Some(Err(CliError::Cancelled))));
        drop(tx);
        assert!(matches!(await_unseal(&|| None, &AgeKill::new(), &rx), Some(Err(CliError::Msg(_)))), "no answer is no success");
    }

    /// The pipe fd delivery starts from: it holds the value and closes on exec.
    #[test]
    fn the_secret_pipe_holds_the_value_and_closes_on_exec() {
        let value = format!("pipe-dummy-{}", "p".repeat(24));
        let fd = secret_pipe(value.as_bytes()).unwrap();
        // SAFETY: F_GETFD on a valid fd we own.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC, "only the child's fd 3 survives exec");
        let mut got = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::from(fd), &mut got).unwrap();
        assert!(got == value, "the pipe held {} bytes, not the {} written", got.len(), value.len());
    }

    /// Everything a `sh -c` child wrote on stdout. Its lines and its exit come
    /// from different tasks, in no fixed order, so this reads until it has
    /// seen both the end of stdout and the exit, as the pump does.
    async fn child_stdout(mut link: ChildLink) -> Vec<u8> {
        drop(link.input);
        let mut out = Vec::new();
        let (mut eof, mut exited) = (false, false);
        while !(eof && exited) {
            match link.events.recv().await {
                Some(ChildEvent::Line(l)) => {
                    out.extend_from_slice(&l);
                    out.push(b'\n');
                }
                Some(ChildEvent::StdoutEof) => eof = true,
                Some(ChildEvent::Exit(_)) => exited = true,
                Some(_) => {}
                None => break,
            }
        }
        out
    }

    /// `spawn_local` hands the token on fd 3 with the descriptor variable and
    /// no token variable, or (env) in the environment with no descriptor
    /// variable — removing what the environment already held, an empty token
    /// variable and a stale descriptor number; without a credential the
    /// child's environment is the plan's, untouched.
    #[tokio::test]
    async fn spawn_local_delivers_on_fd_3_or_in_the_environment() {
        let token = crate::bridge::setup_token::parse_token(&format!("{}oat01-{}", "sk-ant-", "Fd3_".repeat(10))).unwrap();
        // `-unset` without a colon: an empty variable prints as empty, an absent one as `unset`.
        let script = "if [ \"${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR-}\" = 3 ]; then cat <&3; echo; fi; echo \"fd=${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR-unset}\"; echo \"env=${CLAUDE_CODE_OAUTH_TOKEN-unset}\"";
        let plan = ChildPlan {
            program: PathBuf::from("/bin/sh"),
            argv: vec!["-c".into(), script.into()],
            // What the child would otherwise inherit: an empty token variable and a stale descriptor.
            env_set: vec![(TOKEN_VAR.to_string(), OsString::new()), (TOKEN_FD_VAR.to_string(), OsString::from("7"))],
            env_remove: Vec::new(),
            child_config_dir: PathBuf::from("/nonexistent"),
            scratch: None,
            resume: None,
            slug: None,
            mirror: mirror::decide(false, false, Path::new("/nonexistent"), Path::new("/nonexistent"), None),
        };
        let out = child_stdout(spawn_local(&plan, Some((&token, Deliver::Fd))).unwrap()).await;
        let want = format!("{}\nfd=3\nenv=unset\n", token.expose());
        assert!(out == want.as_bytes(), "fd delivery: {} bytes, expected {}", out.len(), want.len());
        let out = child_stdout(spawn_local(&plan, Some((&token, Deliver::Env))).unwrap()).await;
        let want = format!("fd=unset\nenv={}\n", token.expose());
        assert!(out == want.as_bytes(), "env delivery: {} bytes, expected {}", out.len(), want.len());
        let out = child_stdout(spawn_local(&plan, None).unwrap()).await;
        assert_eq!(out, b"fd=7\nenv=\n");
    }
}
