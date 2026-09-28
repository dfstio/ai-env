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
//! ([`spawn_local`]); S6 builds the same link over the MicroVM WebSocket.
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
//! Lines are split at the CLI's own limit (256 MiB, `CLI_LINE_BYTES`), never
//! at the 4 MiB WebSocket cap: a user message with pasted images or a
//! transcript entry holding them passes as the CLI would take it.
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::census::{self, CensusRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::hoststate::{ChildVerdict, HostState};
use crate::bridge::lab::{self, PumpKnobs};
use crate::bridge::logging::{self, LogOpts};
use crate::bridge::mirror::{self, MirrorCfg, Writer};
use crate::bridge::registry::{self, SessionRow};
use crate::bridge::route::Mode;
use crate::bridge::seed;
use crate::wire::argv::{self, Route, SanitiseOpts, SessionArgs};
use crate::wire::claude::{self, ChildFrame, HostFrame};
use crate::wire::ndjson::{encode_line, LineError, LineSplitter, CLI_LINE_BYTES};
use crate::wire::redact;
use crate::wire::slug;
use crate::wire::time::unix_now_ms;
use bytes::Bytes;
use serde_json::value::RawValue;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

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

const READ_CHUNK: usize = 64 * 1024;

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
            (dir.clone(), Some(dir.clone()), vec![("CLAUDE_CONFIG_DIR".to_string(), dir.into_os_string())], vec![SECURE_STORAGE_ENV.to_string()], true)
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
}

/// The census end row: a clone of `start` with `end`, `exit` and the note
/// extended by `end:<reason>; child_pid:<n>; respawns:<n>; mirror:<frames>/<rejected>;
/// dropped:<n>; oauth_refresh_answered:<n>` (+ `init_ms`, `eof_to_sigterm_ms` when known).
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
    /// A stdout line over the 4 MiB cap was dropped.
    TooLong(usize),
    StdoutEof,
    StderrEof,
    /// The child was reaped (`None`: waiting failed).
    Exit(Option<ExitStatus>),
}

/// The pump's handle on one child: the seam S6 reuses with a WebSocket behind it.
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
pub fn spawn_local(plan: &ChildPlan) -> std::io::Result<ChildLink> {
    let mut cmd = tokio::process::Command::new(&plan.program);
    cmd.args(&plan.argv).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    for k in &plan.env_remove {
        cmd.env_remove(k);
    }
    let mut child = cmd.spawn()?;
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
}

impl Pump {
    fn new(sess: Session, plan: ChildPlan) -> Pump {
        let audit_path = sess.paths.audit();
        let mirror = Writer::new(plan.mirror.clone());
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
            out: Outcome::default(),
            audit_path,
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

    /// Spawn the next child generation; `false` when the spawn failed (the
    /// finish is then already decided).
    fn spawn_next(&mut self) -> bool {
        self.gen += 1;
        self.state.begin_gen(self.gen);
        self.child_exit = None;
        self.exit_seen_at = None;
        self.stdout_eof = false;
        self.stderr_eof = false;
        match spawn_local(&self.plan) {
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
                tracing::warn!("host line over the 4 MiB cap dropped ({n} bytes)");
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
                tracing::warn!("child line over the 4 MiB cap dropped ({n} bytes)");
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
        if let ChildFrame::ControlResponse { request_id: Some(id), .. } = &frame {
            if self.gen == 1 && self.out.init_latency_ms.is_none() && self.state.initialize_id() == Some(id.as_ref()) {
                self.out.init_latency_ms = Some(self.spawned_at.elapsed().as_millis() as u64);
            }
        }
        let init_before = self.state.inits_forwarded();
        let verdict = self.state.on_child_frame(&frame, &line);
        let forwarded = !matches!(verdict, ChildVerdict::Swallow(_));
        match verdict {
            ChildVerdict::Forward => self.forward(&line),
            ChildVerdict::Rewritten(b) => self.forward(&b),
            ChildVerdict::Swallow(why) => tracing::debug!(?why, "child frame swallowed"),
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
/// stderr line and S1's exec) → `local-scratch`: the scratch dir, a token
/// note, the pre-spawn seed → the runtime → the supervisor → mirror fsync →
/// registry row closed → census end row → the lab message → exit.
pub fn run(sess: Session) -> ! {
    let log_path = sess.paths.wrapper_log();
    if let Err(e) = logging::init(&LogOpts { path: log_path, rust_log: std::env::var("RUST_LOG").ok() }) {
        eprintln!("ai-env-claude: log: {e}");
    }
    if let Some(token) = std::env::var_os("CLAUDE_CODE_OAUTH_TOKEN") {
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
    if let Some(dir) = &plan.scratch {
        if let Err(e) = prepare_scratch(dir) {
            eprintln!("ai-env-claude: scratch dir {}: {e}; running unpiped", dir.display());
            exec_unpiped(&sess)
        }
        if std::env::var_os("CLAUDE_CODE_OAUTH_TOKEN").is_none() {
            eprintln!("ai-env-claude: local-scratch without CLAUDE_CODE_OAUTH_TOKEN: the child is logged out (S7 delivers the token)");
        }
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
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ai-env-claude: cannot start the pump runtime ({e}); running unpiped");
            exec_unpiped(&sess)
        }
    };
    let mut pump = Pump::new(sess, plan);
    let code = rt.block_on(pump.supervise());
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
        assert_eq!(plan.env_remove, vec![SECURE_STORAGE_ENV.to_string()]);
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
}
