//! The Mac end of the agent transport (plan S6): one `/agent` session per
//! spawn — dial, hello, the stdio windows, pings and dead detection,
//! reconnect and reattach, token re-mint and rotation, 429 backoff, the
//! keep-alive that stops the VM idling into suspend under a running command,
//! and the reaction to a suspended or terminated VM — under `vm exec`,
//! `vm attach` and `vm smoke --exec` (`exec`).
//!
//! `conn` is one socket (dial, hello, frames), `session` is [`run_spawn`]
//! (everything across sockets), `exec` is the CLI's stdin, stdout, stderr,
//! signals and exit status on top. They meet in the types below:
//!
//! - the consumer sends [`SpawnInput`]s (stdin chunks of at most
//!   `CHUNK_MAX`, then EOF) on a bounded channel, and signals and a
//!   deliberate detach on `control`, which a full stdin window never holds up;
//!   for `Start::Attach` the session takes stdin only once the first
//!   `hello_ok` gave the shim's numbering;
//! - the session sends [`SpawnEvent`]s on an unbounded channel, so it never
//!   waits on a slow consumer (a `| less` must not stall pongs) —
//!   deduplicated by seq across reconnects, in order. It holds at most the
//!   shim's stdout credit window, and `STDERR_BUFFER_BYTES` of stderr the
//!   consumer has not marked (newer stderr is dropped meanwhile and counted
//!   in `dropped`, as the shim drops its oldest);
//! - the consumer marks in [`Consumed`] the stdout and stderr seqs it has
//!   WRITTEN AND FLUSHED; the session acks only those (at least every
//!   `ACK_EVERY_BYTES` or `ACK_EVERY`), so a crash of the Mac never loses
//!   output the shim already trimmed;
//! - [`run_spawn`] returns when the remote exit was delivered (or the session
//!   gave up, or the VM refused the spawn: the error says why — exit 7/8 by
//!   `BridgeError`, and `vm exec` maps a refused spawn to 127, 126, 1 or 9).
use crate::bridge::api::{EndpointClient, MicrovmApi};
use crate::bridge::config::{Keepalive, Paths, Rotation, TransportCfg};
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::AgentDial;
use crate::bridge::vm::registry::VmRow;
use crate::wire::frame::{Sig, SpawnId};
use crate::wire::redact::Secret;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

pub mod conn;
pub mod exec;
pub mod session;

/// Timers and budgets of a session ([`RunPolicy::from_cfg`]; probes and
/// tests build their own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPolicy {
    /// App-level `ping` while a spawn is attached and unfinished (`PING_EVERY`).
    pub ping: Duration,
    /// WebSocket Ping (`WS_PING_EVERY`).
    pub ws_ping: Duration,
    /// No inbound frame for this long: the socket is dead (`DEAD_AFTER`).
    pub dead_after: Duration,
    /// Ack at least every this many consumed bytes / this often.
    pub ack_bytes: u64,
    pub ack_every: Duration,
    pub rotation: Rotation,
    pub keepalive: Keepalive,
    /// The keep-alive cadence under [`Keepalive::Http`] (max_idle / 3, at least 20 s).
    pub keepalive_every: Duration,
    /// After `event hook_suspend`: wait this long for the VM to be resumed by someone else.
    pub suspend_wait: Duration,
    /// Reconnect backoff: first step, cap, and when it resets: once the spawn
    /// was carried `stable_after` without a break (a rotation is none), and
    /// after a suspended VM runs again.
    /// `backoff_min` is also the session's second for the waits the server
    /// or the platform set: one second of `Retry-After`, the 60 s a resume or
    /// a boot may take, the 3 s between GetMicrovm polls of a suspended VM.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub stable_after: Duration,
    /// How long reconnecting may go on before the session gives up (exit 8).
    /// It restarts with the backoff: sockets lost within `stable_after` keep it running.
    pub reconnect_budget: Duration,
    /// How long 503 `not_run` is retried (the run hook's budget).
    pub not_run_budget: Duration,
    /// Endpoint token lifetime (minutes, ≤ 60); re-mint below `remint_below`
    /// (wall clock: Darwin's `Instant` stops during sleep); proactive rotation
    /// at expiry minus `rotate_before`.
    pub token_minutes: u16,
    pub remint_below: Duration,
    pub rotate_before: Duration,
    /// `hello.idle_s`.
    pub idle_s: Option<u32>,
}

impl RunPolicy {
    /// The policy of `vm exec` / `vm attach` for `row` under `[transport]`,
    /// every step scaled from 1 s to `backoff_ms` ms when the lab knob is set.
    #[must_use]
    pub fn from_cfg(cfg: &TransportCfg, row: &VmRow, backoff_ms: Option<u64>) -> RunPolicy {
        use crate::wire::frame::{ACK_EVERY, ACK_EVERY_BYTES, DEAD_AFTER, PING_EVERY, WS_PING_EVERY};
        let scale = |d: Duration| backoff_ms.map_or(d, |ms| Duration::from_millis((d.as_millis() as u64).saturating_mul(ms) / 1000).max(Duration::from_millis(1)));
        let max_idle = row.idle.map_or(300, |i| i.max_idle_s.max(60));
        RunPolicy {
            ping: scale(PING_EVERY),
            ws_ping: scale(WS_PING_EVERY),
            dead_after: scale(DEAD_AFTER),
            ack_bytes: ACK_EVERY_BYTES,
            ack_every: ACK_EVERY,
            rotation: cfg.rotation,
            keepalive: cfg.keepalive,
            keepalive_every: scale(Duration::from_secs(u64::from(max_idle / 3).max(20))),
            suspend_wait: scale(Duration::from_secs(u64::from(cfg.suspend_wait_s))),
            backoff_min: scale(Duration::from_secs(1)),
            backoff_max: scale(Duration::from_secs(60)),
            stable_after: scale(Duration::from_secs(30)),
            reconnect_budget: scale(Duration::from_secs(300)),
            not_run_budget: scale(Duration::from_secs(30)),
            token_minutes: 60,
            remint_below: Duration::from_secs(300),
            rotate_before: Duration::from_secs(600),
            idle_s: None,
        }
    }
}

/// The VM a session talks to, from its registry row.
#[derive(Debug, Clone)]
pub struct AgentTarget {
    pub vm_id: String,
    /// Bare host (`normalize_endpoint`).
    pub endpoint: String,
    /// The token whose commitment rode `/run`; registered with the scrubber.
    pub session_token: Secret<String>,
    /// A `vpc` row: spawns get `egress::proxy_env` (the CLI adds it).
    pub vpc: bool,
    /// A `vm run --shell` row: [`run_spawn`] refuses it before any mint or
    /// dial (exit 9; `vm exec` and `vm attach` before any call) until the
    /// platform shell's in-VM listener is shown unreachable from the agent
    /// (D1). in-vm-firewall clears it on its own `--shell` VM to measure
    /// that listener (lab only).
    pub shell: bool,
}

impl AgentTarget {
    /// The target of `row`: its endpoint (normalised) and session token
    /// (registered with the scrubber before anything can log it). Exit 8
    /// naming the row when it has neither (a VM `vm run` did not start).
    pub fn from_row(row: &VmRow) -> Result<AgentTarget, BridgeError> {
        let token = row.session_token.clone().filter(|t| !t.is_empty()).ok_or_else(|| BridgeError::Transport(format!("{} has no session token in its row (only VMs `ai-env vm run` started can run commands)", row.id)))?;
        crate::wire::redact::register_secret(&token);
        let endpoint = crate::bridge::api::normalize_endpoint(row.endpoint.as_deref().unwrap_or_default())?;
        Ok(AgentTarget { vm_id: row.id.clone(), endpoint, session_token: Secret::new(token), vpc: row.egress == "vpc", shell: row.shell })
    }
}

/// What to start. `Debug` shows argv[0]'s basename and counts, never the
/// arguments or environment values.
#[derive(Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub detach_grace_s: Option<u32>,
}

impl std::fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let argv0 = self.argv.first().map_or("", |a| a.rsplit('/').next().unwrap_or(a));
        write!(f, "SpawnSpec(argv0={argv0}, argc={}, env={}, cwd={}, detach_grace_s={:?})", self.argv.len(), self.env.len(), if self.cwd.is_some() { "set" } else { "default" }, self.detach_grace_s)
    }
}

/// A new spawn, or a reattach to a running one.
#[derive(Clone, PartialEq, Eq)]
pub enum Start {
    New(SpawnSpec),
    Attach { spawn_id: SpawnId, from_seq: Option<u64>, err_from_seq: Option<u64> },
}

impl std::fmt::Debug for Start {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Start::New(spec) => write!(f, "New({spec:?})"),
            Start::Attach { spawn_id, from_seq, err_from_seq } => write!(f, "Attach({spawn_id}, from_seq={from_seq:?}, err_from_seq={err_from_seq:?})"),
        }
    }
}

/// Consumer → session. `Stdin` and `StdinEof` go on `input` (in order);
/// `Signal` and `Detach` on `control`. `Debug` shows sizes, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub enum SpawnInput {
    /// At most `CHUNK_MAX` bytes.
    Stdin(Vec<u8>),
    StdinEof,
    /// Sent once the spawn runs on a socket (queued while reconnecting).
    Signal(Sig),
    /// A deliberate end of the attachment (`detach {final}`): the session
    /// sends it, closes the socket and returns `Err(Transport("detached …"))`;
    /// while disconnected it returns that at once (the shim's detach grace
    /// then ends the spawn). One whose send failed goes out on the next socket.
    Detach { is_final: bool },
}

impl std::fmt::Debug for SpawnInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnInput::Stdin(bytes) => write!(f, "Stdin({} bytes)", bytes.len()),
            SpawnInput::StdinEof => f.write_str("StdinEof"),
            SpawnInput::Signal(sig) => write!(f, "Signal({sig:?})"),
            SpawnInput::Detach { is_final } => write!(f, "Detach(final={is_final})"),
        }
    }
}

/// How the remote process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    /// stderr bytes dropped in all: by the shim, and by the session while the consumer lagged.
    pub stderr_dropped: u64,
    pub stdout_truncated: bool,
}

impl RemoteExit {
    /// The status `vm exec` exits with (S6 D8): the code verbatim, 128 + N for
    /// a signal, 1 when the shim reported neither.
    #[must_use]
    pub fn status(&self) -> i32 {
        match (self.code, self.signal) {
            (Some(c), _) => c,
            (None, Some(s)) => 128 + s,
            (None, None) => 1,
        }
    }
}

/// Session → consumer. `Debug` shows seqs and sizes, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub enum SpawnEvent {
    /// The spawn runs (after `spawned`, or after a reattach's `hello_ok`).
    Started { spawn_id: SpawnId, pid: u32, pgid: u32, claude_version: Option<String> },
    Stdout { seq: u64, bytes: Vec<u8> },
    /// `dropped`: the cumulative count of stderr bytes dropped, by the shim
    /// (drop-oldest) and by the session while `STDERR_BUFFER_BYTES` of stderr
    /// waited for the consumer's mark.
    Stderr { seq: u64, bytes: Vec<u8>, dropped: u64 },
    /// One line for the operator's stderr (reconnecting, reattached, rotated,
    /// suspended, …), without the `ai-env: ` prefix or a newline.
    Note(String),
    /// The session's link to the spawn, after its note: `false` once a socket
    /// was lost or the VM suspended under it (nothing reaches the VM until it
    /// is back), `true` once a new socket took it up again (reattached, or the
    /// `spawn` sent again when the VM did not hold it).
    Link(bool),
    Exit(RemoteExit),
}

impl std::fmt::Debug for SpawnEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnEvent::Started { spawn_id, pid, pgid, claude_version } => write!(f, "Started({spawn_id}, pid={pid}, pgid={pgid}, claude_version={claude_version:?})"),
            SpawnEvent::Stdout { seq, bytes } => write!(f, "Stdout(seq={seq}, {} bytes)", bytes.len()),
            SpawnEvent::Stderr { seq, bytes, dropped } => write!(f, "Stderr(seq={seq}, {} bytes, dropped={dropped})", bytes.len()),
            SpawnEvent::Note(text) => write!(f, "Note({text:?})"),
            SpawnEvent::Link(up) => write!(f, "Link({up})"),
            SpawnEvent::Exit(exit) => write!(f, "Exit({exit:?})"),
        }
    }
}

/// The seqs the consumer has written and flushed; the session acks from them.
#[derive(Debug, Default)]
pub struct Consumed {
    stdout: AtomicU64,
    stderr: AtomicU64,
    notify: Notify,
}

impl Consumed {
    /// stdout up to `seq` is written and flushed.
    pub fn stdout_done(&self, seq: u64) {
        self.stdout.fetch_max(seq, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// stderr up to `seq` is written and flushed.
    pub fn stderr_done(&self, seq: u64) {
        self.stderr.fetch_max(seq, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// (stdout, stderr) consumed so far.
    #[must_use]
    pub fn seqs(&self) -> (u64, u64) {
        (self.stdout.load(Ordering::SeqCst), self.stderr.load(Ordering::SeqCst))
    }

    /// Resolves after the next `*_done` (cancel-safe).
    pub async fn changed(&self) {
        self.notify.notified().await;
    }
}

/// The session's side of one spawn's channels.
pub struct SpawnIo {
    pub input: mpsc::Receiver<SpawnInput>,
    pub control: mpsc::UnboundedReceiver<SpawnInput>,
    pub events: mpsc::UnboundedSender<SpawnEvent>,
    pub consumed: Arc<Consumed>,
}

/// The consumer's side.
pub struct ConsumerIo {
    /// stdin: the session stops taking it while `STDIN_WINDOW_BYTES` are
    /// unacked (and, for `Start::Attach`, before the first `hello_ok`).
    pub input: mpsc::Sender<SpawnInput>,
    /// Signals and detach: always taken.
    pub control: mpsc::UnboundedSender<SpawnInput>,
    pub events: mpsc::UnboundedReceiver<SpawnEvent>,
    pub consumed: Arc<Consumed>,
}

/// A connected pair of channels (the input channel holds `input_slots` chunks).
#[must_use]
pub fn spawn_channels(input_slots: usize) -> (SpawnIo, ConsumerIo) {
    let (in_tx, in_rx) = mpsc::channel(input_slots.max(1));
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    let consumed = Arc::new(Consumed::default());
    (SpawnIo { input: in_rx, control: ctl_rx, events: ev_tx, consumed: consumed.clone() }, ConsumerIo { input: in_tx, control: ctl_tx, events: ev_rx, consumed })
}

/// How one spawn ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnOutcome {
    pub spawn_id: SpawnId,
    pub exit: RemoteExit,
}

/// Everything a session needs besides its channels.
pub struct AgentEnv<'a, A: MicrovmApi, E: EndpointClient> {
    pub api: &'a A,
    pub ep: &'a E,
    pub paths: &'a Paths,
    pub target: AgentTarget,
    pub policy: RunPolicy,
    pub dial: AgentDial,
}

/// Run one spawn over `/agent` until its exit is delivered (`session`): the
/// error says why it gave up (exit 7 or 8 through `BridgeError`) or why the
/// VM refused the spawn; a `--shell` row's target is refused before any
/// mint or dial (`Policy`, exit 9: see [`AgentTarget::shell`]).
pub async fn run_spawn<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, start: Start, io: SpawnIo) -> Result<SpawnOutcome, BridgeError> {
    session::run(env, start, io).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_exit_status_is_verbatim_or_128_plus_signal() {
        let e = |code, signal| RemoteExit { code, signal, stderr_dropped: 0, stdout_truncated: false }.status();
        assert_eq!(e(Some(0), None), 0);
        assert_eq!(e(Some(7), None), 7, "a remote 7 is passed through (documented ambiguity)");
        assert_eq!(e(None, Some(9)), 137);
        assert_eq!(e(None, Some(15)), 143);
        assert_eq!(e(None, None), 1);
    }

    /// `vm exec`'s policy acks at the wire's cadence: every `ACK_EVERY_BYTES`
    /// consumed or every `ACK_EVERY`, whatever the other timers (the lab
    /// knob scales those, never the acks).
    #[test]
    fn the_cli_policy_acks_every_mib_or_250_ms() {
        use crate::wire::frame::{ACK_EVERY, ACK_EVERY_BYTES};
        for knob in [None, Some(100)] {
            let p = RunPolicy::from_cfg(&TransportCfg::default(), &VmRow::default(), knob);
            assert_eq!((p.ack_bytes, p.ack_every), (ACK_EVERY_BYTES, ACK_EVERY), "knob {knob:?}");
        }
        assert_eq!((ACK_EVERY_BYTES, ACK_EVERY), (1024 * 1024, Duration::from_millis(250)), "plan D3: 1 MiB or 250 ms");
    }

    #[test]
    fn consumed_keeps_the_highest_seq() {
        let c = Consumed::default();
        c.stdout_done(5);
        c.stdout_done(3);
        c.stderr_done(2);
        assert_eq!(c.seqs(), (5, 2));
    }

    #[test]
    fn debug_shows_argv0_counts_and_sizes_never_arguments_env_values_or_bytes() {
        let spec = SpawnSpec {
            argv: vec!["/usr/local/bin/claude".into(), "--print".into(), "the private prompt".into()],
            cwd: Some("/home/agent/work".into()),
            env: BTreeMap::from([("LANG".to_string(), "private-env-value".to_string())]),
            detach_grace_s: Some(30),
        };
        let shown = [
            format!("{spec:?}"),
            format!("{:?}", Start::New(spec.clone())),
            format!("{:?}", SpawnInput::Stdin(b"private stdin".to_vec())),
            format!("{:?}", SpawnEvent::Stdout { seq: 3, bytes: b"private stdout".to_vec() }),
            format!("{:?}", SpawnEvent::Stderr { seq: 4, bytes: b"private stderr".to_vec(), dropped: 9 }),
        ]
        .join("\n");
        for leak in ["--print", "the private prompt", "private-env-value", "/home/agent/work", "private stdin", "private stdout", "private stderr"] {
            assert!(!shown.contains(leak), "{leak}: {shown}");
        }
        for kept in ["argv0=claude", "argc=3", "env=1", "Stdin(13 bytes)", "Stdout(seq=3, 14 bytes)", "Stderr(seq=4, 14 bytes, dropped=9)"] {
            assert!(shown.contains(kept), "{kept}: {shown}");
        }
    }
}
