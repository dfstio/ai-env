//! Everything across sockets for one spawn (plan S6): [`run`] mints a
//! `Port(8080)` token, dials, says `hello` (resuming the spawn it already
//! has), starts or reattaches the spawn, and serves it until the exit is
//! delivered, reconnecting as often as the reconnect rules allow. A
//! `--shell` row's target is refused first, before any mint or dial
//! (`Policy`, exit 9: the platform shell's in-VM listener is outside the
//! shim's guard, D1).
//!
//! - **Stdio.** stdin is chunked (`wire::chunk::Chunker`), numbered from 1
//!   (`Start::Attach`: after the shim's `in_seq`, so no input is taken
//!   before the first `hello_ok`) and kept until `stdin_ack`; the session
//!   stops taking input while `STDIN_WINDOW_BYTES` are unacked and never has
//!   more than that in flight; after a reattach everything above
//!   `hello_ok`'s `in_seq` is sent again. A frame leaves its queue (stdin,
//!   signals, the detach) only once its send succeeded. stdout and stderr
//!   are delivered once, in order, by seq (a replay's duplicates are dropped;
//!   a stdout seq that skips one is a protocol error); acks carry only what
//!   the consumer marked in `Consumed`, at least every `ack_bytes` or
//!   `ack_every`. Each socket has a reader task that never waits on the
//!   consumer. The events hold at most the shim's stdout window and
//!   `STDERR_BUFFER_BYTES` of stderr the consumer has not marked: newer
//!   stderr is dropped meanwhile and counted in `dropped`, as the shim drops
//!   its oldest.
//! - **Liveness.** While the spawn is attached and unfinished: an app `ping`
//!   every `ping`, a WebSocket Ping every `ws_ping`, and under
//!   `Keepalive::Http` a bearer-less `GET /health` every `keepalive_every`
//!   (failures only logged). No inbound message for `dead_after`, or a wall
//!   clock that ran `dead_after` ahead of `Instant` (a laptop sleep), loses
//!   the socket.
//! - **Reconnect.** Backoff `backoff_min`..`backoff_max` ×2 ±25 % (getrandom),
//!   reset once the spawn was carried `stable_after` without a break (a
//!   rotation's socket continues the old one's time), everything within
//!   `reconnect_budget`. A mint that fails (the network still waking) is a
//!   failed attempt like a refused dial, unless the VM is gone; past the
//!   budget its own error ends the session. 401/403: one re-mint, the second is
//!   `TokenRejected` (exit 7). 429: wait max(Retry-After, backoff), never
//!   re-mint, audit `endpoint_429`. 503 `not_run`: every `backoff_min` for
//!   `not_run_budget`, then `ShimUnavailable`; `draining`: `Terminated`.
//!   404: `NoAgent`. 502 or no connection asks GetMicrovm: gone →
//!   `VmNotFound`/`Terminated`; SUSPENDED without auto-resume → one
//!   ResumeMicrovm (a Conflict is a resume already under way) and up to 60 s
//!   for RUNNING; PENDING → up to 60 s; otherwise keep backing off.
//!   `SpawnInput::DropSocket` (S8 `session drop-transport`) ends a socket
//!   that carries the spawn as a lost one, reconnected by these rules.
//! - **Tokens.** Wall-clock expiry (Darwin's `Instant` stops during sleep):
//!   a fresh token before any dial with less than `remint_below` left, and on
//!   any tick (the keep-alive presents it; a failed mint there never ends a
//!   live socket). `Rotation::Proactive`: at expiry minus `rotate_before` a
//!   second socket with a fresh token says `hello` with the resume; from that
//!   hello on spawn frames wait for it, the old socket's `superseded` is
//!   ignored, and the old socket is closed 1000 after the new `hello_ok`. A
//!   hello without an answer is a lost socket (the shim may have moved the
//!   spawn already): reconnect with the resume. The second socket's dial
//!   follows the reconnect rules while the old one serves: a 429 waits its
//!   Retry-After (audited), the token is kept across attempts, a 401/403
//!   spends the one re-mint and a second stops rotating on that socket.
//!   `Rotation::Lazy`: no second socket; the next reconnect uses the fresh token.
//! - **Suspend.** After `event hook_suspend` the session never dials on its
//!   own: it polls GetMicrovm every 3 s and reattaches once RUNNING, or gives
//!   up after `suspend_wait` naming `ai-env vm resume` and `ai-env vm attach`
//!   (exit 8, `StayedSuspended`): `vm exec`, `vm attach`, and a wrapper
//!   session without a park control. A parking session parks instead (below).
//!   `event hook_terminate` is `Terminated`.
//! - **Park** (S10 §D, a wrapper session with a `park::ParkCtl`,
//!   [`super::run_spawn_parked`]). On a socket whose `hello_ok` names
//!   `park_v1`, with the spawn attached, no rotation in flight, nothing queued
//!   (stdin, a signal, a detach, EOF), everything delivered marked consumed
//!   and acked, the pump's verdict (`park::QuietState`) `Idle` or `Prompt`
//!   for the policy's `after`, the session's own stdio quiet as long, and the
//!   code-out trigger quiet, the session sends `park` and waits
//!   `answer_wait` for the answer (none: the socket is lost). Parked, it
//!   sends nothing on that socket: no ping, no WebSocket Ping, no keep-alive,
//!   no rotation, no re-mint, and its dead-socket and sleep checks are off.
//!   The next `park` waits `after` past the last one, refused or unanswered
//!   (`session_park_refused` at most once per `PARK_REFUSED_LOG_EVERY`), and
//!   a socket lost before its `park` was answered starts a new reconnect
//!   episode: a shim that never answers costs a reconnect per `after`.
//!   Input, or output on the open socket, unparks: `unpark` and a `ping`, the
//!   socket lost unless a `pong` or a `stdin_ack` comes within `probe`;
//!   input during the handshake waits for the answer and unparks right after
//!   `parked`. The parked socket's end (the shim or the endpoint closed it)
//!   leaves the spawn parked with no socket, and so does `event hook_suspend`
//!   once the spawn ran (no `suspend_wait`, no exit 8): the next input asks
//!   GetMicrovm (TERMINATED: `Terminated`), dials (the endpoint's
//!   auto-resume, or one ResumeMicrovm), resumes the spawn with `hello` and
//!   sends the queue; no Touch ID. A suspend of a spawn the shim had not
//!   parked (its detach grace runs again once the VM runs) also reattaches
//!   once GetMicrovm, asked from 3 s on, doubling to every 60 s, says
//!   RUNNING: idle, it is parked `suspended`; a turn at work, or a shim
//!   without `park_v1`, reports no park but its link down, as S9's suspend
//!   does, with no limit. The host's
//!   EOF ends a session parked with no socket at once (`parked_close`, exit
//!   0, no dial, no GetMicrovm): its claude stays on the VM for the next
//!   start there to reap. A signal waits for the next socket, a detach ends
//!   the session at once. Each step is a `SpawnEvent::Park` and an audit row
//!   (`session_park`, `session_unpark`, `session_park_refused`); without
//!   `park_v1` the session never parks, keeps the VM awake as S9's does, and
//!   says `Off { no_cap }` once.
//! - **End.** `exit` is delivered as `SpawnEvent::Exit`; once the consumer
//!   marked every chunk this session delivered (at most `dead_after`) the
//!   exit's seq is acked, which releases the spawn, and the socket is closed 1000.
//! - **Credential** (S7, [`super::Delivery`], for its own VM and a new spawn
//!   only, exit 9). On each `hello_ok` before the spawn goes out, the gate
//!   pass must still stand (else exit 9, nothing more sent: run the command
//!   again) and the shim must offer `credential_cache` (else exit 7: an
//!   older image). A cache holding the delivery's name and tag is a hit: the
//!   spawn just names it. On a miss the value goes out first in its own
//!   `credential` frame (the shim handles frames in order, so the `spawn`
//!   right behind it finds it cached); without a value in hand the session
//!   ends with `CredentialMissing` (exit 5) before any spawn, and nothing
//!   retries: the message says to run the command again, which unseals the
//!   token. `no_credential` (the cache emptied in between) delivers once
//!   more, a second is exit 8; never for a one-shot spawn (a protocol error),
//!   whose value never rides a cacheable frame. `credential_err suspended`
//!   is waited out as a suspend and delivered once more; a second, after the
//!   VM ran again, is exit 8 (its cache stays closed). The VM's row names it
//!   as a holder (`credential_at`) before the value leaves the Mac, and on
//!   every hit or running spawn seen if it does not yet; the audit row
//!   `credential_deliver` means acknowledged (`credential_ok`). The value is
//!   dropped once the spawn runs: at `spawned`, or on a reattach that finds
//!   it running (the shim never sends `spawned` again). A
//!   `--credential-file` delivery rides that one `spawn` inline instead
//!   (recorded at `spawned`), as S6's `spawn.secrets` did: a spawn sent again
//!   after a lost socket carries it again, to the same VM only, which starts
//!   an id at most once.
//! - **Records.** Audit rows `endpoint_429` (retry_after, waited_ms: the wait
//!   the 429 set; written at the 429, before that wait, so also when the 429
//!   ends the session or a detach cuts its wait short), `agent_reconnect`
//!   (reason, ms), `agent_rotate` (mode), `agent_remint` (reason);
//!   `SpawnEvent::Note` lines for the operator, each loss, reattach or spawn
//!   sent again followed by a `SpawnEvent::Link`; TRACE in `conn`.
use super::conn::{close_text, Activity, AgentConn, AgentReceiver, AgentSender, HelloOk, Trace, CLOSE_WAIT};
use super::credential::{record_holder, Held};
use super::{AgentEnv, Delivery, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnIo, SpawnOutcome, SpawnSpec, Start};
use crate::bridge::api::{AuthToken, EndpointClient, HealthReply, MicrovmApi, VmInfo, VmState, APP_PORT};
use crate::bridge::config::{Keepalive, Rotation};
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::DialError;
use crate::bridge::vm::cmd::audit_event;
use crate::bridge::vm::token::mint;
use crate::wire::chunk::{decode, raw_len, Chunker};
use crate::wire::frame::{
    Chunk, CredentialErrCode, Deliver, ErrorCode, EventKind, Frame, ResumePoint, ResumeStatus, Scope, Sig, SpawnErrCode, SpawnId, SpawnStatus, CAP_CREDENTIAL_CACHE, CLOSE_NORMAL, STDERR_BUFFER_BYTES, STDIN_WINDOW_BYTES,
};
use crate::wire::redact::{scrub, Secret};
use futures_util::future::BoxFuture;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
// S10 §D: the park.
use super::ParkReport;
use crate::bridge::park::{ParkCtl, Verdict, PARK_REFUSED_LOG_EVERY};
use crate::bridge::remote::audit_event::{SESSION_PARK, SESSION_PARK_REFUSED, SESSION_UNPARK};
use crate::wire::frame::{ParkRefusal, CAP_PARK_V1};

/// [`super::run_spawn`]'s body (see the module doc). `park` (S10 §D): a
/// wrapper session's park control ([`super::run_spawn_parked`]): with it the
/// session parks when idle and resumes a suspended VM at the next input;
/// without it, it runs as S9's.
pub async fn run<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, start: Start, io: SpawnIo, delivery: Option<Delivery>, park: Option<crate::bridge::park::ParkCtl>) -> Result<SpawnOutcome, BridgeError> {
    // D1, for every caller (`vm exec` and `vm attach` refuse such rows before any call too).
    if env.target.shell {
        return Err(BridgeError::Policy(format!(
            "{} was started with --shell: no command runs on it until the platform shell's in-VM listener, which the shim does not guard, is shown unreachable from the agent (ai-env lab run in-vm-firewall measures it); start a VM without --shell",
            env.target.vm_id
        )));
    }
    // S7, for every caller too: a delivery goes only to the VM its pass was minted for, with a new spawn.
    if let Some(d) = &delivery {
        d.check_target(&env.target.vm_id)?;
        if !matches!(start, Start::New(_)) {
            return Err(BridgeError::Policy("a credential goes only with a new spawn".into()));
        }
    }
    crate::wire::redact::register_secret(env.target.session_token.expose());
    let token = mint_token(env).await?;
    let mut session = Session {
        env,
        io,
        trace: Trace::from_env(env.paths),
        token,
        st: State::new(start),
        attached: false,
        paused: false,
        control_open: true,
        delivery,
        cred_retried: false,
        cred_suspended: false,
        claude: None,
        park: park.map(Parking::new),
    };
    session.run().await
}

/// How one socket's service ended.
enum End {
    /// The remote exit (its seq) was delivered.
    Exited(u64, RemoteExit),
    /// The socket is gone (why); reconnect.
    Lost(String),
    /// `event hook_suspend`: wait for RUNNING without dialing.
    Suspended,
    /// The consumer's `detach` went out.
    Detached,
    /// S10 §D: the spawn stays parked with no socket until the next input:
    /// the parked socket ended, or (`frozen`) the VM was suspended under the
    /// session (`event hook_suspend`). `watch`: the shim had not parked the
    /// spawn, whose detach grace runs again once the VM runs, so the VM
    /// RUNNING again is reattached too (GetMicrovm from 3 s on, doubling to
    /// every 60 s); `down`: no park was reported but the link down, and the
    /// reattach is a reconnect.
    Parked { frozen: bool, watch: bool, down: bool },
}

// ---- S10 §D: the park ------------------------------------------------------------------

/// Where a parking session's park stands on the socket that carries the spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Park {
    /// Not parked: the session keeps the VM awake as S9's does.
    No,
    /// `park` went out: its answer is awaited until `until`. `why` and
    /// `quiet_ms` are the park's; `woke` is the first input, or output, that
    /// came meanwhile: it waits for the answer, and unparks right after `parked`.
    Asking { until: Instant, why: &'static str, quiet_ms: u64, woke: Option<&'static str> },
    /// Parked: the socket stays open, and silent.
    Parked,
}

/// An unpark under way: since when, why (`session_unpark.by`), and the VM's
/// state then. Reported once a socket carries the spawn again.
#[derive(Debug, Clone, Copy)]
struct Unparking {
    since: Instant,
    by: &'static str,
    vm_state: &'static str,
}

/// A parking session's control ([`ParkCtl`]) and its bookkeeping.
struct Parking {
    ctl: ParkCtl,
    /// The last `hello_ok` named `park_v1`.
    served: bool,
    /// `ParkReport::Off` went out (once a session).
    off_said: bool,
    at: Park,
    /// When the session's own stdin, stdout or stderr last moved.
    last_io: Instant,
    /// No park before this: `after` past the last `park` sent, or past its refusal.
    not_before: Option<Instant>,
    /// When the last `session_park_refused` row went out.
    refused_logged: Option<Instant>,
    unparking: Option<Unparking>,
    /// The open socket's unpark probe: lost unless a `pong` or a `stdin_ack` comes by then.
    probe_until: Option<Instant>,
}

impl Parking {
    fn new(ctl: ParkCtl) -> Parking {
        Parking { ctl, served: false, off_said: false, at: Park::No, last_io: Instant::now(), not_before: None, refused_logged: None, unparking: None, probe_until: None }
    }
}

/// `session_unpark.vm_state` of a VM in `state` (a VM on its way back from a suspend counts as suspended).
fn vm_state_word(state: &VmState) -> &'static str {
    match state {
        VmState::Suspended | VmState::Pending => "suspended",
        VmState::Suspending => "suspending",
        _ => "running",
    }
}

/// `park_refused.reason`'s word (the census's and the audit's).
fn refusal_word(reason: ParkRefusal) -> &'static str {
    match reason {
        ParkRefusal::Busy => "busy",
        ParkRefusal::Output => "output",
        ParkRefusal::Unacked => "unacked",
        ParkRefusal::NotAttached => "not_attached",
        ParkRefusal::Other => "other",
    }
}

/// `d` in whole milliseconds.
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What a socket's reader task reports.
enum Inbound {
    /// Boxed: `hello_ok` makes a [`Frame`] large, the other variants are a `String`.
    Frame(Box<Frame>),
    /// The socket ended (the peer's Close, EOF, a read error): why.
    Ended(String),
    /// Input the wire forbids (binary, malformed, another version).
    Bad(String),
}

/// One socket in service: its sender, and a reader task whose frames queue
/// in `inbound` (bounded in practice by the shim's windows).
struct Link {
    n: u64,
    tx: AgentSender,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    reader: tokio::task::JoinHandle<()>,
    activity: Activity,
    /// The first send that failed: the socket is lost.
    broken: Option<String>,
}

impl Link {
    fn start(conn: AgentConn) -> Link {
        let (n, activity) = (conn.number(), conn.activity());
        let (tx, rx) = conn.split();
        let (sink, inbound) = mpsc::unbounded_channel();
        Link { n, tx, inbound, reader: tokio::spawn(read_all(rx, sink)), activity, broken: None }
    }

    /// Send `frame` unless an earlier send failed (a failure lands in
    /// `broken`); whether it went out.
    async fn send(&mut self, frame: &Frame) -> bool {
        if self.broken.is_none() {
            if let Err(e) = self.tx.send(frame).await {
                self.broken = Some(e.to_string());
            }
        }
        self.broken.is_none()
    }

    async fn ws_ping(&mut self) {
        if self.broken.is_none() {
            if let Err(e) = self.tx.ping().await {
                self.broken = Some(e.to_string());
            }
        }
    }

    /// Close with `code`, give the reader [`CLOSE_WAIT`] to see the peer's Close, then stop it.
    async fn close(mut self, code: u16) {
        self.tx.close(code).await;
        let _ = tokio::time::timeout(CLOSE_WAIT, &mut self.reader).await;
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// A socket's reader: every frame into `sink` until the socket ends. A
/// dropped `sink` (a replaced socket) stops only the forwarding: reading
/// goes on, so the close handshake completes.
async fn read_all(mut rx: AgentReceiver, sink: mpsc::UnboundedSender<Inbound>) {
    loop {
        let report = match rx.recv().await {
            Ok(Some(frame)) => {
                let _ = sink.send(Inbound::Frame(Box::new(frame)));
                continue;
            }
            Ok(None) => Inbound::Ended(format!("the socket closed{}", close_text(rx.close_frame().as_ref()))),
            Err(BridgeError::Protocol(m)) => Inbound::Bad(m),
            Err(BridgeError::Transport(m)) => Inbound::Ended(m),
            Err(e) => Inbound::Ended(e.to_string()),
        };
        let _ = sink.send(report);
        return;
    }
}

/// Where the spawn stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `Start::New` before any `spawn` went out.
    ToSpawn,
    /// `spawn` went out; a lost socket may or may not have started it.
    SpawnSent,
    Running,
}

/// One spawn's bookkeeping across sockets.
struct State {
    id: SpawnId,
    spec: Option<SpawnSpec>,
    phase: Phase,
    /// `spawn` went out again, on a socket whose resume the shim answered `unknown`.
    resent: bool,
    started: bool,
    /// The last stdout seq delivered; `out_known` once the stream's position
    /// is fixed (always for a new spawn; for `Start::Attach` without
    /// `from_seq`, at its first chunk).
    out: u64,
    out_known: bool,
    err: u64,
    err_known: bool,
    /// The last stdout and stderr seq this session handed to the consumer
    /// (0: none; the position `vm attach --from-seq` starts at is no delivery).
    delivered: (u64, u64),
    /// Delivered chunks not yet counted as consumed: (seq, bytes).
    out_lens: VecDeque<(u64, u64)>,
    err_lens: VecDeque<(u64, u64)>,
    /// Bytes consumed since the last ack.
    consumed_bytes: u64,
    /// stderr bytes delivered and not yet marked consumed, and the stderr
    /// bytes dropped while that stood at `STDERR_BUFFER_BYTES`.
    err_unconsumed: u64,
    err_dropped: u64,
    /// The last ack sent on this socket (stdout, stderr).
    acked: (u64, u64),
    chunker: Chunker,
    /// The stdin numbering is fixed: from 1 for a new spawn; for
    /// `Start::Attach` once the first `hello_ok` gave the shim's `in_seq`
    /// (input waits in its channel until then).
    in_base: bool,
    /// The last stdin seq assigned.
    next_in: u64,
    /// stdin not yet acked: (seq, chunk, bytes), seq order.
    pending: VecDeque<(u64, Chunk, u64)>,
    pending_bytes: u64,
    /// The highest seq sent on this socket, and the bytes of `pending` at or below it.
    sent_in: u64,
    inflight: u64,
    /// `stdin_eof`'s seq once the consumer closed stdin.
    eof: Option<u64>,
    eof_sent: bool,
    /// The remote's stdin is already closed (`vm attach` to such a spawn).
    remote_stdin_closed: bool,
    input_open: bool,
    signals: VecDeque<Sig>,
    detach: Option<bool>,
    detach_sent: bool,
}

impl State {
    fn new(start: Start) -> State {
        let base = |id: SpawnId, spec: Option<SpawnSpec>, phase: Phase| State {
            id,
            spec,
            phase,
            resent: false,
            started: false,
            out: 0,
            out_known: true,
            err: 0,
            err_known: true,
            delivered: (0, 0),
            out_lens: VecDeque::new(),
            err_lens: VecDeque::new(),
            consumed_bytes: 0,
            err_unconsumed: 0,
            err_dropped: 0,
            acked: (0, 0),
            chunker: Chunker::new(),
            in_base: true,
            next_in: 0,
            pending: VecDeque::new(),
            pending_bytes: 0,
            sent_in: 0,
            inflight: 0,
            eof: None,
            eof_sent: false,
            remote_stdin_closed: false,
            input_open: true,
            signals: VecDeque::new(),
            detach: None,
            detach_sent: false,
        };
        match start {
            // The caller's id when it named one (S8: the wrapper's remote spawn), else a fresh v7.
            Start::New(spec) => base(spec.id.clone().unwrap_or_else(SpawnId::new_v7), Some(spec), Phase::ToSpawn),
            Start::Attach { spawn_id, from_seq, err_from_seq } => State {
                out: from_seq.map_or(0, |s| s.saturating_sub(1)),
                out_known: from_seq.is_some(),
                err: err_from_seq.map_or(0, |s| s.saturating_sub(1)),
                err_known: err_from_seq.is_some(),
                in_base: false,
                ..base(spawn_id, None, Phase::Running)
            },
        }
    }

    /// The resume point of a `hello` (nothing before the first `spawn`).
    fn resume(&self) -> Vec<ResumePoint> {
        if self.phase == Phase::ToSpawn {
            return Vec::new();
        }
        vec![ResumePoint { spawn_id: self.id.clone(), from_seq: self.out_known.then_some(self.out + 1), err_from_seq: self.err_known.then_some(self.err + 1) }]
    }

    fn wants_input(&self) -> bool {
        self.input_open && self.in_base && self.pending_bytes < STDIN_WINDOW_BYTES
    }

    /// Queue one consumer input.
    fn take(&mut self, input: SpawnInput) {
        match input {
            SpawnInput::Stdin(bytes) if self.eof.is_none() && !self.remote_stdin_closed => {
                for chunk in self.chunker.push(&bytes) {
                    self.push(chunk);
                }
            }
            SpawnInput::Stdin(_) => {}
            SpawnInput::StdinEof => {
                if self.eof.is_none() {
                    if let Some(tail) = self.chunker.finish() {
                        self.push(tail);
                    }
                    self.eof = Some(self.next_in);
                }
            }
            SpawnInput::Signal(sig) => self.signals.push_back(sig),
            SpawnInput::Detach { is_final } => self.detach = Some(is_final),
            // Only `serve` drops a socket that carries the spawn: with none, nothing to drop.
            SpawnInput::DropSocket => {}
        }
    }

    fn push(&mut self, chunk: Chunk) {
        let len = raw_len(&chunk).unwrap_or(0) as u64;
        self.next_in += 1;
        self.pending.push_back((self.next_in, chunk, len));
        self.pending_bytes += len;
    }

    /// The next stdin chunk to send, if the shim's window has room for it.
    fn next_stdin(&self) -> Option<(u64, Chunk, u64)> {
        let at = self.pending.partition_point(|(seq, _, _)| *seq <= self.sent_in);
        let (seq, chunk, len) = self.pending.get(at)?;
        (self.inflight + len <= STDIN_WINDOW_BYTES).then(|| (*seq, chunk.clone(), *len))
    }

    fn stdin_acked(&mut self, seq: u64) {
        while self.pending.front().is_some_and(|(s, _, _)| *s <= seq) {
            let Some((s, _, len)) = self.pending.pop_front() else { break };
            self.pending_bytes -= len;
            if s <= self.sent_in {
                self.inflight -= len;
            }
        }
    }

    /// A socket that resumed the spawn: the shim holds stdin up to `in_seq`
    /// (anything above goes again), and knows nothing of this socket's acks.
    fn reattached(&mut self, status: Option<&SpawnStatus>) {
        let in_seq = status.map_or(0, |s| s.in_seq);
        // `vm attach`: this client's stdin continues the shim's numbering
        // (none of it was numbered before: `in_base` held the input back).
        self.next_in = self.next_in.max(in_seq);
        self.in_base = true;
        self.sent_in = in_seq;
        self.inflight = self.pending.iter().take_while(|(seq, _, _)| *seq <= in_seq).map(|(_, _, len)| len).sum();
        self.remote_stdin_closed = status.is_some_and(|s| s.stdin_closed);
        self.eof_sent = self.remote_stdin_closed;
        if self.remote_stdin_closed {
            self.pending.clear();
            self.pending_bytes = 0;
            self.inflight = 0;
        }
        self.acked = (0, 0);
    }

    /// Count what the consumer marked (`out`, `err` capped at what was delivered).
    fn count_consumed(&mut self, out: u64, err: u64) {
        while let Some(&(_, len)) = self.out_lens.front().filter(|(seq, _)| *seq <= out) {
            self.out_lens.pop_front();
            self.consumed_bytes += len;
        }
        while let Some(&(_, len)) = self.err_lens.front().filter(|(seq, _)| *seq <= err) {
            self.err_lens.pop_front();
            self.consumed_bytes += len;
            self.err_unconsumed -= len;
        }
    }
}

/// The waits of one reconnect episode (from a socket's loss, or the first dial).
struct Retry {
    since: Instant,
    step: Duration,
    /// The one re-mint after a 401/403 is spent (until a hello succeeds).
    reminted: bool,
    not_run_since: Option<Instant>,
    /// The one ResumeMicrovm is spent.
    resumed: bool,
    /// The last failure, and its Retry-After when it was a 429.
    last: String,
    throttled: Option<Option<u64>>,
    /// The last failure was a mint: past the budget its error ends the session.
    no_token: Option<BridgeError>,
}

impl Retry {
    fn new(p: &RunPolicy) -> Retry {
        Retry { since: Instant::now(), step: p.backoff_min, reminted: false, not_run_since: None, resumed: false, last: String::new(), throttled: None, no_token: None }
    }

    fn failed(&mut self, why: String) {
        self.last = why;
        self.throttled = None;
        self.no_token = None;
    }

    /// The next backoff: the step ±25 %; the step then doubles, up to `backoff_max`.
    fn next(&mut self, p: &RunPolicy) -> Duration {
        let wait = jittered(self.step);
        self.step = self.step.saturating_mul(2).min(p.backoff_max);
        wait
    }
}

/// `d` × [0.75, 1.25), from getrandom.
fn jittered(d: Duration) -> Duration {
    let r = getrandom::u32().unwrap_or(u32::MAX / 2);
    d.mul_f64(0.75 + 0.5 * f64::from(r) / (f64::from(u32::MAX) + 1.0))
}

/// What a proactive rotation brings: the new token, its socket, and that socket's `hello_ok`.
struct Rotated {
    token: AuthToken,
    conn: AgentConn,
    ok: HelloOk,
}

/// How one step of a proactive rotation ended.
enum RotationStep {
    /// The second socket is up (with its token): its `hello` comes next.
    Dialed(AuthToken, AgentConn),
    /// Its `hello_ok`: it takes over.
    Answered(Box<Rotated>),
    /// No new socket; the token it used, kept for the next attempt.
    Failed(Option<AuthToken>, RotationFailed),
}

/// Why a rotation attempt failed.
enum RotationFailed {
    Mint(String),
    Dial(DialError),
    /// `hello_err` on the new socket: the shim left the spawn where it was.
    Refused(String),
    /// The `hello` went out and no `hello_ok` came: the shim may have moved the spawn.
    Unanswered(String),
}

impl std::fmt::Display for RotationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationFailed::Mint(m) => write!(f, "mint: {m}"),
            RotationFailed::Dial(e) => write!(f, "dial: {e}"),
            RotationFailed::Refused(m) | RotationFailed::Unanswered(m) => write!(f, "hello: {m}"),
        }
    }
}

/// Proactive rotation on one socket: the step under way, when the next
/// attempt may start, the token kept for it, and the reconnect rules its
/// dials follow (backoff, the one re-mint after a 401/403).
struct Rotating<'a> {
    step: Option<BoxFuture<'a, RotationStep>>,
    after: Option<Instant>,
    /// A 429 or a failed connect never costs a fresh token.
    token: Option<AuthToken>,
    retry: Retry,
    /// The old socket heard `superseded` while the new one's `hello` was out.
    superseded: bool,
    /// A second 401/403: no more attempts on this socket (when it ends, the
    /// reconnect's own 401/403 rule applies).
    stopped: bool,
}

impl Rotating<'_> {
    fn new(p: &RunPolicy) -> Self {
        Rotating { step: None, after: None, token: None, retry: Retry::new(p), superseded: false, stopped: false }
    }

    /// An attempt may start now (once the token is within `rotate_before`).
    fn due(&self) -> bool {
        self.step.is_none() && !self.stopped && self.after.is_none_or(|t| Instant::now() >= t)
    }
}

struct Session<'e, 'a, A: MicrovmApi, E: EndpointClient> {
    env: &'e AgentEnv<'a, A, E>,
    io: SpawnIo,
    trace: Trace,
    token: AuthToken,
    st: State,
    /// The current socket carries the spawn (after `spawned`, or a `hello_ok` that resumed it).
    attached: bool,
    /// A rotation's `hello` is out (the shim may move the spawn to its
    /// socket any moment): spawn frames wait for the new socket.
    paused: bool,
    control_open: bool,
    /// The credential the new spawn gets (S7).
    delivery: Option<Delivery>,
    /// `no_credential` was answered by delivering again once.
    cred_retried: bool,
    /// `credential_err suspended` was waited out once: a second ends the session.
    cred_suspended: bool,
    /// The VM's claude, as the last `hello_ok` that named it said: `Started`
    /// carries it when `spawned` (or a reattach) names none (S8: the remote
    /// link compares it with `authwatch::AUTH_TIMERS`).
    claude: Option<String>,
    /// S10 §D: a wrapper session's park (none: S9's session, which never parks).
    park: Option<Parking>,
}

impl<'a, A: MicrovmApi, E: EndpointClient> Session<'_, 'a, A, E> {
    async fn run(&mut self) -> Result<SpawnOutcome, BridgeError> {
        let mut retry = Retry::new(&self.env.policy);
        let mut lost: Option<(Instant, String)> = None;
        loop {
            let mut link = self.connect(&mut retry).await?;
            // The stability clock: a rotation swaps the socket without a break, so it runs on.
            let carried = Instant::now();
            if let Some((at, why)) = lost.take() {
                let ms = at.elapsed().as_millis().to_string();
                // Still `SpawnSent`: the resume found no such spawn and `adopt` sent it again; nothing was reattached.
                if self.st.phase == Phase::SpawnSent {
                    self.note(format!("sent spawn {} again after {ms} ms (socket {}): the VM did not hold it", self.st.id, link.n));
                } else {
                    self.note(format!("reattached to spawn {} after {ms} ms (socket {})", self.st.id, link.n));
                }
                self.link(true);
                self.audit("agent_reconnect", &[("reason", why), ("ms", ms)]);
            }
            // S10: an unpark that had to dial is done once a socket carries the spawn again.
            self.unparked();
            match self.serve(&mut link).await? {
                End::Exited(seq, exit) => return Ok(self.finish(link, seq, exit).await),
                End::Detached => {
                    link.close(CLOSE_NORMAL).await;
                    return Err(BridgeError::Transport(format!("detached from spawn {}", self.st.id)));
                }
                End::Lost(why) => {
                    // S10: a socket lost to its park's handshake starts a new episode however short it lived
                    // (`send_park` spaces those losses by `after`); its dials still count against the budget.
                    let handshake = self.park.as_ref().is_some_and(|p| matches!(p.at, Park::Asking { .. }));
                    if handshake || carried.elapsed() >= self.env.policy.stable_after {
                        retry = Retry::new(&self.env.policy);
                    }
                    drop(link);
                    retry.failed(why.clone());
                    let wait = retry.next(&self.env.policy);
                    self.note(format!("lost the connection to {} ({why}); reconnecting", self.vm()));
                    self.link(false);
                    self.give_up_past(&mut retry, wait)?;
                    lost = Some((Instant::now(), why));
                    self.pause(wait).await?;
                }
                End::Suspended => {
                    link.close(CLOSE_NORMAL).await;
                    self.wait_resumed().await?;
                    retry = Retry::new(&self.env.policy);
                    lost = Some((Instant::now(), "suspended".into()));
                }
                End::Parked { frozen, watch, down } => {
                    link.close(CLOSE_NORMAL).await;
                    if let Some(outcome) = self.wait_parked(frozen, watch, down).await? {
                        return Ok(outcome);
                    }
                    retry = Retry::new(&self.env.policy);
                    // A suspend that reported no park took the link down: its reattach is a reconnect, as after S9's.
                    if down {
                        lost = Some((Instant::now(), "suspended".into()));
                    }
                }
            }
        }
    }

    // ---- connecting ---------------------------------------------------------------------

    /// Dial and `hello` until a socket carries the spawn (or the rules give up).
    async fn connect(&mut self, retry: &mut Retry) -> Result<Link, BridgeError> {
        let env = self.env;
        loop {
            // An expired token cannot dial: a mint that failed then (the
            // network still waking after a sleep) is a failed attempt.
            if let Some(e) = self.freshen().await?.filter(|_| self.token_left().is_zero()) {
                self.mint_failed(e, retry).await?;
                continue;
            }
            let token = self.token.value()?.clone();
            // A detach while the dial or the hello is under way ends the
            // session there: the spawn is never sent (signals are queued).
            let mut conn = match self.watching(AgentConn::open(&env.dial, &env.target.endpoint, &token)).await? {
                Ok(conn) => conn.with_trace(self.trace.clone()),
                Err(e) => {
                    self.dial_failed(e, retry).await?;
                    continue;
                }
            };
            let resume = self.st.resume();
            match self.watching(tokio::time::timeout(env.policy.dead_after, conn.hello(&env.target.session_token, resume, env.policy.idle_s))).await? {
                Ok(Ok(ok)) => {
                    retry.reminted = false;
                    retry.not_run_since = None;
                    let mut link = Link::start(conn);
                    // A rotation in flight when the last socket was lost died with it.
                    (self.attached, self.paused) = (false, false);
                    // S10: a hello that resumes the spawn unparks it on the shim; a park in flight died with its socket.
                    if let Some(p) = &mut self.park {
                        (p.at, p.probe_until) = (Park::No, None);
                    }
                    self.adopt(&ok, &mut link).await?;
                    match link.broken.take() {
                        None => return Ok(link),
                        Some(why) => retry.failed(why),
                    }
                }
                Ok(Err(BridgeError::HelloRefused { code, message })) if code == "busy" => retry.failed(format!("hello_err busy: {message}")),
                Ok(Err(BridgeError::Transport(m))) => retry.failed(m),
                Ok(Err(e)) => return Err(e),
                Err(_) => retry.failed(format!("no hello_ok within {}", secs(env.policy.dead_after))),
            }
            let wait = retry.next(&env.policy);
            self.give_up_past(retry, wait)?;
            self.pause(wait).await?;
        }
    }

    /// A refused or failed dial: wait, re-mint or give up, per the reconnect rules.
    async fn dial_failed(&mut self, e: DialError, retry: &mut Retry) -> Result<(), BridgeError> {
        let env = self.env;
        let p = &env.policy;
        tracing::info!("vm {}: /agent dial: {e}", self.vm());
        match e {
            DialError::TokenRejected { status, proxy_error } => {
                if retry.reminted {
                    return Err(BridgeError::TokenRejected { port: APP_PORT, status, proxy_error });
                }
                match self.remint("token_rejected").await {
                    Ok(()) => {
                        retry.reminted = true;
                        Ok(())
                    }
                    Err(e) => self.mint_failed(e, retry).await,
                }
            }
            DialError::Throttled { retry_after_s } => {
                let backoff = retry.next(p);
                let wait = retry_after_s.map_or(backoff, |s| units(p, s).max(backoff));
                // Audited before the budget and the wait: a 429 that ends the session, or whose wait a detach cuts short, has its row too.
                let retry_after = retry_after_s.map_or_else(|| "none".to_string(), |s| s.to_string());
                self.audit("endpoint_429", &[("retry_after", retry_after), ("waited_ms", wait.as_millis().to_string())]);
                retry.failed(e.to_string());
                retry.throttled = Some(retry_after_s);
                self.give_up_past(retry, wait)?;
                self.note(format!("the endpoint throttled /agent (HTTP 429); retrying in {}", secs(wait)));
                self.pause(wait).await
            }
            DialError::NotRun => {
                let since = *retry.not_run_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= p.not_run_budget {
                    return Err(BridgeError::ShimUnavailable(format!("{}: its /run hook has not returned after {} (HTTP 503 not_run)", self.vm(), secs(p.not_run_budget))));
                }
                retry.failed(e.to_string());
                self.pause(p.backoff_min).await
            }
            DialError::Draining => Err(BridgeError::Terminated(format!("{}: the shim is draining (the VM is terminating)", self.vm()))),
            DialError::NoAgent => Err(BridgeError::NoAgent(format!("{}: HTTP 404 on /agent", self.vm()))),
            DialError::Http { status, body } if status < 500 => Err(BridgeError::Http { status, body }),
            DialError::Tls(m) => Err(BridgeError::Endpoint(format!("TLS to {}: {m}", env.target.endpoint))),
            DialError::Handshake(m) => Err(BridgeError::Endpoint(format!("the /agent handshake with {} failed: {m}", env.target.endpoint))),
            DialError::Busy => {
                retry.failed(e.to_string());
                let wait = retry.next(p);
                self.give_up_past(retry, wait)?;
                self.pause(wait).await
            }
            DialError::Gateway { .. } | DialError::Connect(_) | DialError::Http { .. } => {
                retry.failed(e.to_string());
                if self.check_vm(retry).await? {
                    return Ok(());
                }
                let wait = retry.next(p);
                self.give_up_past(retry, wait)?;
                self.pause(wait).await
            }
        }
    }

    /// 502 or no connection: what GetMicrovm says. `Ok(true)`: the VM just
    /// became RUNNING (redial at once); `Ok(false)`: keep backing off.
    async fn check_vm(&mut self, retry: &mut Retry) -> Result<bool, BridgeError> {
        let vm = match self.env.api.get(self.vm()).await {
            Ok(vm) => vm,
            Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
            Err(e) => {
                tracing::warn!("vm {}: GetMicrovm after a failed dial: {e}", self.vm());
                return Ok(false);
            }
        };
        match vm.state {
            ref s if s.is_terminal() => Err(terminated(&vm)),
            VmState::Suspended | VmState::Suspending if auto_resume(&vm) => Ok(false),
            VmState::Pending | VmState::Suspended | VmState::Suspending => self.wait_running(retry).await.map(|()| true),
            _ => Ok(false),
        }
    }

    /// Up to 60 s for RUNNING; a SUSPENDED VM without auto-resume gets one
    /// ResumeMicrovm (a Conflict means a resume is already under way).
    async fn wait_running(&mut self, retry: &mut Retry) -> Result<(), BridgeError> {
        let limit = units(&self.env.policy, 60);
        let start = Instant::now();
        loop {
            let seen = match self.env.api.get(self.vm()).await {
                Ok(vm) => match vm.state {
                    VmState::Running => return Ok(()),
                    ref s if s.is_terminal() => return Err(terminated(&vm)),
                    VmState::Suspended if !auto_resume(&vm) && !retry.resumed => {
                        retry.resumed = true;
                        self.note(format!("{} is suspended without auto-resume: resuming it", self.vm()));
                        match self.env.api.resume(self.vm()).await {
                            Ok(()) | Err(BridgeError::Conflict(_)) => {}
                            Err(e) => return Err(e),
                        }
                        continue;
                    }
                    ref s => s.as_str().to_string(),
                },
                Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
                Err(e) => format!("unknown (GetMicrovm: {e})"),
            };
            if start.elapsed() >= limit {
                return Err(BridgeError::ShimUnavailable(format!("{} is still {seen} after {}", self.vm(), secs(limit))));
            }
            self.pause(self.env.policy.backoff_min).await?;
        }
    }

    /// Past the reconnect budget, the last failure's error.
    fn give_up_past(&self, retry: &mut Retry, wait: Duration) -> Result<(), BridgeError> {
        let spent = retry.since.elapsed();
        if spent + wait <= self.env.policy.reconnect_budget {
            return Ok(());
        }
        Err(match (retry.no_token.take(), retry.throttled) {
            (Some(e), _) => e,
            (None, Some(retry_after_s)) => BridgeError::EndpointThrottled { retry_after_s },
            (None, None) => BridgeError::ShimUnavailable(format!("{}: no lasting /agent connection for {} (last: {})", self.vm(), secs(spent), retry.last)),
        })
    }

    /// A mint that failed while reconnecting: a VM that is gone ends the
    /// session; anything else is a failed attempt like a refused dial.
    async fn mint_failed(&mut self, e: BridgeError, retry: &mut Retry) -> Result<(), BridgeError> {
        if gone(&e) {
            return Err(e);
        }
        retry.failed(format!("no endpoint token: {e}"));
        retry.no_token = Some(e);
        let wait = retry.next(&self.env.policy);
        self.give_up_past(retry, wait)?;
        self.pause(wait).await
    }

    /// After `event hook_suspend`: GetMicrovm every 3 s, never a dial, until RUNNING or `suspend_wait`.
    async fn wait_resumed(&mut self) -> Result<(), BridgeError> {
        let env = self.env;
        let id = env.target.vm_id.as_str();
        self.note(format!("{id} was suspended; not reconnecting until it runs again (up to {}; `ai-env vm resume {id}`)", secs(env.policy.suspend_wait)));
        self.link(false);
        let start = Instant::now();
        loop {
            self.pause(units(&env.policy, 3)).await?;
            match env.api.get(id).await {
                Ok(vm) if vm.state == VmState::Running => return Ok(()),
                Ok(vm) if vm.state.is_terminal() => return Err(terminated(&vm)),
                Ok(_) => {}
                Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
                Err(e) => tracing::warn!("vm {id}: GetMicrovm while suspended: {e}"),
            }
            if start.elapsed() >= env.policy.suspend_wait {
                return Err(BridgeError::StayedSuspended(format!(
                    "{id} stayed suspended for {}: resume it with `ai-env vm resume {id}`, then reattach with `ai-env vm attach {id} --spawn {}`",
                    secs(env.policy.suspend_wait),
                    self.st.id
                )));
            }
        }
    }

    /// S10 §D: parked with no socket (`frozen`: the VM was suspended under
    /// the session). Nothing goes out until input comes: a detach ends the
    /// session at once, a signal waits for the next socket, and the host's
    /// EOF ends it at once too (`parked_close`, exit 0: nothing dialed, no
    /// GetMicrovm; its claude stays on the VM for the next start there to
    /// reap, or its grace to end). A stdin chunk unparks: GetMicrovm (a VM
    /// gone is the session's `Terminated` or `VmNotFound`, which the pump
    /// moves), then `Ok(None)`: the caller dials (the endpoint's
    /// auto-resume, or one ResumeMicrovm), resumes the spawn with `hello`
    /// and sends the queue. No Touch ID: the runtime key is in memory, and
    /// claude keeps its token. An unpark that was under way as the VM was
    /// suspended, or stdin the shim never acknowledged, is input there
    /// already: the VM is resumed at once. With `watch` (a spawn the shim
    /// had not parked) GetMicrovm is asked meanwhile, never a dial: 3 s after
    /// the suspend, then twice as long each time up to 60 s (3, 9, 21, 45, 93
    /// s, then every 60 s: a chat left open after a suspend costs no poll
    /// every 3 s until its wall); the VM RUNNING again (someone resumed it) is
    /// `Ok(None)` too, well within the spawn's detach grace (900 s, which runs
    /// only once the VM runs), and a VM gone ends the session.
    /// With `down` no park was reported, so no unpark is either: the
    /// caller's reattach is a reconnect.
    async fn wait_parked(&mut self, frozen: bool, watch: bool, down: bool) -> Result<Option<SpawnOutcome>, BridgeError> {
        let there = self.park.as_ref().is_some_and(|p| p.unparking.is_some()) || !self.st.pending.is_empty();
        let id = self.vm().to_string();
        // The watch's GetMicrovm backs off: 3 units, doubling to 60.
        let (mut every, cap) = (units(&self.env.policy, 3), units(&self.env.policy, 60));
        let mut look = tokio::time::Instant::now() + every;
        let eof = loop {
            if self.st.eof.is_some() {
                break true;
            }
            if there {
                break false;
            }
            let input = tokio::select! {
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(input) => input,
                    None => {
                        self.control_open = false;
                        continue;
                    }
                },
                m = self.io.input.recv(), if self.st.wants_input() => match m {
                    Some(input) => input,
                    // The host's stdin ended: its EOF.
                    None => {
                        self.st.input_open = false;
                        SpawnInput::StdinEof
                    }
                },
                () = tokio::time::sleep_until(look), if watch => {
                    every = every.saturating_mul(2).min(cap);
                    look = tokio::time::Instant::now() + every;
                    match self.env.api.get(&id).await {
                        Ok(vm) if vm.state == VmState::Running => {
                            self.ran_again(&id, down);
                            return Ok(None);
                        }
                        Ok(vm) if vm.state.is_terminal() => return Err(terminated(&vm)),
                        Ok(_) => {}
                        Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
                        Err(e) => tracing::warn!("vm {id}: GetMicrovm while suspended: {e}"),
                    }
                    continue;
                },
                // Nothing more can come (stdin's window full, the control channel gone): the queue goes out.
                else => break false,
            };
            match input {
                SpawnInput::Detach { .. } => return Err(self.detached_while_disconnected()),
                // No socket to drop.
                SpawnInput::DropSocket => {}
                SpawnInput::Stdin(_) => {
                    self.st.take(input);
                    break false;
                }
                // A signal waits for the next socket; the EOF is judged at the loop's top.
                other => self.st.take(other),
            }
        };
        if eof {
            return Ok(Some(self.parked_close()));
        }
        let since = Instant::now();
        let vm_state = match self.env.api.get(&id).await {
            Ok(vm) if vm.state.is_terminal() => return Err(terminated(&vm)),
            Ok(vm) => vm_state_word(&vm.state),
            Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
            // The dial asks again, by the reconnect rules.
            Err(e) => {
                tracing::warn!("vm {id}: GetMicrovm before an unpark: {e}");
                if frozen {
                    "suspended"
                } else {
                    "running"
                }
            }
        };
        if down {
            self.note(format!("input for spawn {} while {id} is {vm_state}: reconnecting", self.st.id));
            return Ok(None);
        }
        let by = self.input_word();
        // An unpark under way keeps its start and its cause; the VM's state is the one now.
        let unparking = match self.park.as_ref().and_then(|p| p.unparking) {
            Some(u) => Unparking { vm_state, ..u },
            None => Unparking { since, by, vm_state },
        };
        if let Some(p) = &mut self.park {
            p.unparking = Some(unparking);
        }
        self.note(format!("unparking spawn {} ({}): {id} is {vm_state}", self.st.id, unparking.by));
        Ok(None)
    }

    /// With no socket, the VM runs again and no input came (someone resumed
    /// it): the spawn is reattached before its detach grace runs out. A park
    /// that was reported is unparked by it (`by` `other`, the VM `running`);
    /// with `down` the reattach is a reconnect.
    fn ran_again(&mut self, id: &str, down: bool) {
        self.note(format!("{id} runs again: reattaching spawn {}", self.st.id));
        if let Some(p) = self.park.as_mut().filter(|_| !down) {
            p.unparking = Some(Unparking { since: Instant::now(), by: "other", vm_state: "running" });
        }
    }

    /// The host's EOF while parked with no socket (S10 §3.3): the session
    /// ends at once, exit 0, nothing dialed. Its claude stays on the VM,
    /// frozen with it while it is suspended (parked under its owner when the
    /// shim had parked it), until the next start there reaps it or its grace
    /// ends.
    fn parked_close(&self) -> SpawnOutcome {
        self.note(format!("closed while parked: spawn {} stays on {} (the next start there reaps it, or its grace ends it)", self.st.id, self.vm()));
        SpawnOutcome { spawn_id: self.st.id.clone(), exit: RemoteExit { code: Some(0), signal: None, stderr_dropped: self.st.err_dropped, stdout_truncated: false }, parked_close: true }
    }

    /// A `hello_ok`: the spawn goes out (again), or what became of it.
    async fn adopt(&mut self, ok: &HelloOk, link: &mut Link) -> Result<(), BridgeError> {
        if ok.claude_version.is_some() {
            self.claude.clone_from(&ok.claude_version);
        }
        // S10: whether this shim parks; a parking session on one that does not says so once.
        if let Some(p) = &mut self.park {
            p.served = ok.caps.iter().any(|c| c == CAP_PARK_V1);
            if !p.served && !std::mem::replace(&mut p.off_said, true) {
                tracing::info!("vm {}: no {CAP_PARK_V1} in hello_ok: this session never parks", self.env.target.vm_id);
                let _ = self.io.events.send(SpawnEvent::Park(ParkReport::Off { why: "no_cap" }));
            }
        }
        if self.st.phase == Phase::ToSpawn {
            self.no_pending_detach()?;
            self.offer_credential(ok, link).await?;
            self.send_spawn(link).await;
            return Ok(());
        }
        let status = ok.resumed.iter().find(|r| r.spawn_id == self.st.id).map_or(ResumeStatus::Unknown, |r| r.status);
        match status {
            ResumeStatus::Ok => {
                let found = ok.spawns.iter().find(|s| s.spawn_id == self.st.id);
                // A resume point past the end of the stream (`vm attach --from-seq`):
                // the shim replays from its next chunk (`Cursor::resume`), and so
                // does the session — else it drops every chunk up to the point as a
                // duplicate, never acks one, and the shim's window fills. The status
                // is read after the attach, so chunks in between are duplicates, never a skip.
                if let Some(s) = found.filter(|s| self.st.out_known && self.st.out > s.out_seq) {
                    self.note(format!("stdout seq {} is past the end of spawn {}'s stdout (seq {}): showing it from seq {}", self.st.out + 1, self.st.id, s.out_seq, s.out_seq + 1));
                    self.st.out = s.out_seq;
                }
                self.st.reattached(found);
                self.st.phase = Phase::Running;
                self.attached = true;
                if !self.st.started {
                    let (pid, pgid) = found.map_or((0, 0), |s| (s.pid, s.pgid));
                    self.started(pid, pgid, self.claude.clone());
                    // `spawned` died with its socket (and maybe the `credential_ok`
                    // before it): the spawn runs, so the VM holds the credential.
                    if let Some(d) = &self.delivery {
                        record_holder(self.env.paths, self.vm(), d.tag(), Held::Seen);
                    }
                    self.spawn_has_its_copy();
                }
                self.flush(link).await;
                Ok(())
            }
            ResumeStatus::Gap => Err(BridgeError::Gap { spawn_id: self.st.id.0.clone(), from_seq: self.st.resume().first().and_then(|r| r.from_seq).unwrap_or(0) }),
            // The shim does not hold the spawn: its `spawn` never arrived, the
            // shim is still starting it, or it ran and was released once its
            // detach grace ran out while no socket carried it. Sent again, it
            // starts in the first case only: the shim refuses an id it holds or
            // already used (`spawn_err exists`, see `on_frame`), so it never runs twice.
            ResumeStatus::Unknown if self.st.phase == Phase::SpawnSent => {
                self.no_pending_detach()?;
                self.st.resent = true;
                self.offer_credential(ok, link).await?;
                self.send_spawn(link).await;
                Ok(())
            }
            ResumeStatus::Unknown => Err(BridgeError::SpawnGone(format!("spawn {} is not on {} (it ended, or its detach grace ran out while disconnected)", self.st.id, self.vm()))),
        }
    }

    /// Before a `spawn` that names the delivery's credential (or carries a
    /// one-shot value): the pass must still stand, then hit or miss on the
    /// cache `ok` describes; on a miss its own `credential` frame goes out
    /// first (see the module doc).
    async fn offer_credential(&mut self, ok: &HelloOk, link: &mut Link) -> Result<(), BridgeError> {
        let Some(d) = &self.delivery else { return Ok(()) };
        d.still_gated(crate::wire::time::unix_now(), self.st.resent)?;
        if d.one_shot() {
            return Ok(());
        }
        if !ok.caps.iter().any(|c| c == CAP_CREDENTIAL_CACHE) {
            return Err(BridgeError::Endpoint(format!(
                "{} runs a shim that cannot hold a credential (image version {}, no {CAP_CREDENTIAL_CACHE} capability): start a VM of the current image",
                self.vm(),
                ok.image_version.as_deref().unwrap_or("unknown")
            )));
        }
        let hit = ok.has_credentials && ok.credential.credential_name.as_deref() == Some(d.name()) && ok.credential.credential_tag.as_deref() == Some(d.tag());
        if hit {
            tracing::info!("vm {}: the VM holds credential {} (tag {}): not sent", self.vm(), d.name(), d.tag());
            // Its row names it, even if the delivery that put it there was never recorded.
            record_holder(self.env.paths, self.vm(), d.tag(), Held::Seen);
            // S8: the VM's copy served the spawn (the remote session's census says `cached`).
            d.report.note_held();
            return Ok(());
        }
        self.send_credential(link).await
    }

    /// The delivery's `credential` frame, or `CredentialMissing` without a value.
    async fn send_credential(&mut self, link: &mut Link) -> Result<(), BridgeError> {
        let vm = self.vm().to_string();
        let Some(d) = &self.delivery else { return Ok(()) };
        let Some(secret) = d.frame_secret() else {
            return Err(d.missing(&vm, "nothing was started; run the command again"));
        };
        let frame = Frame::Credential { name: d.name().to_string(), secret, tag: Some(d.tag().to_string()) };
        // Recorded before it leaves: an answer lost with the socket must not leave the VM unlisted.
        record_holder(self.env.paths, &vm, d.tag(), Held::Sent);
        d.report.note_sent();
        link.send(&frame).await;
        Ok(())
    }

    async fn send_spawn(&mut self, link: &mut Link) {
        let Some(spec) = &self.st.spec else { return };
        let (secrets, credential, deliver_secret) = match &self.delivery {
            Some(d) if d.one_shot() => (d.frame_secret().map(|v| BTreeMap::from([(d.name().to_string(), v)])).unwrap_or_default(), None, d.deliver()),
            Some(d) => (BTreeMap::new(), Some(d.name().to_string()), d.deliver()),
            None => (BTreeMap::<String, Secret<String>>::new(), None, Deliver::Fd),
        };
        // A one-shot value rides this spawn: recorded before it leaves, as a `credential` frame is.
        if let Some(d) = self.delivery.as_ref().filter(|_| !secrets.is_empty()) {
            record_holder(self.env.paths, self.vm(), d.tag(), Held::Sent);
        }
        let frame = Frame::Spawn {
            spawn_id: self.st.id.clone(),
            argv: spec.argv.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            secrets,
            deliver_secret,
            detach_grace_s: spec.detach_grace_s,
            credential,
        };
        link.send(&frame).await;
        self.st.phase = Phase::SpawnSent;
    }

    /// `credential_ok`, or a one-shot spawn that started: the VM acknowledged
    /// the credential, so the audit says so (its row named it before it left).
    fn credential_delivered(&self, source: &str) {
        if let Some(d) = &self.delivery {
            super::credential::record_delivery(self.env.paths, self.vm(), Some(&self.st.id.to_string()), d, source);
        }
    }

    /// The spawn runs (`spawned`, or a reattach that found it running), so it
    /// has its copy: a one-shot delivery is recorded as acknowledged, once
    /// (while it still holds its value), and ours is dropped (zeroized).
    fn spawn_has_its_copy(&mut self) {
        if self.delivery.as_ref().is_some_and(|d| d.one_shot() && d.holds_value()) {
            self.credential_delivered("file");
        }
        if let Some(d) = &mut self.delivery {
            d.drop_value();
        }
    }

    // ---- serving one socket ---------------------------------------------------------------

    async fn serve(&mut self, link: &mut Link) -> Result<End, BridgeError> {
        let p = self.env.policy.clone();
        let mut tick = tokio::time::interval(p.ack_every.min(p.ping).min(p.ws_ping).min(p.dead_after / 4).max(Duration::from_millis(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (mut pinged, mut ws_pinged) = (Instant::now(), Instant::now());
        let mut keepalive_at = Instant::now() + p.keepalive_every;
        let mut keepalive: Option<BoxFuture<'a, Result<HealthReply, BridgeError>>> = None;
        let mut rot = Rotating::new(&p);
        let mut remint_after: Option<Instant> = None;
        let mut clock = (Instant::now(), wall_now());
        loop {
            if let Some(why) = link.broken.take() {
                return Ok(End::Lost(why));
            }
            if self.st.detach_sent {
                return Ok(End::Detached);
            }
            tokio::select! {
                m = link.inbound.recv() => match m {
                    Some(Inbound::Frame(frame)) => {
                        if let Some(end) = self.on_frame(*frame, link, &mut rot.superseded).await? {
                            return Ok(end);
                        }
                    }
                    // S10: the parked socket's end is no loss: the spawn stays parked, with no socket.
                    Some(Inbound::Ended(why)) if self.parked_here() => return Ok(self.parked_socket_gone(link.n, &why)),
                    Some(Inbound::Ended(why)) => return Ok(End::Lost(why)),
                    Some(Inbound::Bad(m)) => return Err(BridgeError::Protocol(m)),
                    None if self.parked_here() => return Ok(self.parked_socket_gone(link.n, "the socket's reader stopped")),
                    None => return Ok(End::Lost("the socket's reader stopped".into())),
                },
                r = pending_or(&mut rot.step) => {
                    rot.step = None;
                    match r {
                        RotationStep::Dialed(token, conn) => {
                            // From this hello on the shim may move the spawn: spawn frames wait for the new socket.
                            self.paused = true;
                            rot.step = Some(self.rotation_hello(token, conn));
                        }
                        RotationStep::Answered(rotated) => {
                            self.rotated(link, *rotated).await?;
                            rot = Rotating::new(&p);
                        }
                        // The shim may hold the spawn for that socket now: only a reconnect with the resume finds it for sure.
                        RotationStep::Failed(token, RotationFailed::Unanswered(why)) => {
                            if let Some(token) = token {
                                self.token = token;
                            }
                            return Ok(End::Lost(format!("the token rotation's hello got no answer: {why}")));
                        }
                        // A refused hello moved nothing: that `superseded` was another client's.
                        RotationStep::Failed(..) if rot.superseded => return Err(BridgeError::Superseded(format!("spawn {} of {}", self.st.id, self.vm()))),
                        RotationStep::Failed(token, failed) => {
                            self.paused = false;
                            rot.token = token;
                            self.rotation_failed(&mut rot, &failed, link.n);
                            self.flush(link).await;
                        }
                    }
                },
                m = self.io.control.recv(), if self.control_open => match m {
                    // S10: a parked socket dropped leaves the spawn parked, with no socket.
                    Some(SpawnInput::DropSocket) if self.parked_here() => return Ok(self.parked_socket_gone(link.n, "dropped by session drop-transport")),
                    // S8 `session drop-transport`: this socket goes as a lost one would, the spawn stays.
                    Some(SpawnInput::DropSocket) if self.attached => return Ok(End::Lost("dropped by session drop-transport".into())),
                    Some(input) => self.on_input(input, link).await,
                    None => self.control_open = false,
                },
                m = self.io.input.recv(), if self.st.wants_input() => match m {
                    Some(input) => self.on_input(input, link).await,
                    None => self.st.input_open = false,
                },
                () = self.io.consumed.changed() => self.ack(link, false).await,
                r = pending_or(&mut keepalive) => {
                    keepalive = None;
                    match r {
                        Ok(reply) if reply.status == 200 => {}
                        Ok(reply) => tracing::info!("vm {}: keep-alive /health answered {}", self.vm(), reply.status),
                        Err(e) => tracing::info!("vm {}: keep-alive /health: {e}", self.vm()),
                    }
                },
                _ = tick.tick() => {
                    // S10: parked, the socket is silent by design: neither check below holds then, nor
                    // while an unpark's probe (a `pong` or a `stdin_ack` within `probe`) judges the socket.
                    let quiet = self.parked_here() || self.probing();
                    // A laptop sleep stops Instant but not the wall clock: the socket did not survive it.
                    let asleep = wall_now().saturating_sub(clock.1).saturating_sub(clock.0.elapsed());
                    clock = (Instant::now(), wall_now());
                    if asleep > p.dead_after && !quiet {
                        return Ok(End::Lost(format!("woke after {} asleep", secs(asleep))));
                    }
                    let idle = link.activity.idle();
                    if idle > p.dead_after && !quiet {
                        return Ok(End::Lost(format!("no frame for {}", secs(idle))));
                    }
                    // S10: no answer to the park, or to the unpark's ping: the socket counts as lost.
                    if let Some(why) = self.park_overdue() {
                        return Ok(End::Lost(why));
                    }
                    self.ack(link, true).await;
                    // S10: from the park's request on, nothing keeps the VM awake (no ping, no keep-alive, no rotation).
                    if self.attached && self.unparked_here() {
                        if pinged.elapsed() >= p.ping {
                            link.send(&Frame::Ping { ts: crate::wire::time::unix_now_ms() }).await;
                            pinged = Instant::now();
                        }
                        if ws_pinged.elapsed() >= p.ws_ping {
                            link.ws_ping().await;
                            ws_pinged = Instant::now();
                        }
                        if p.keepalive == Keepalive::Http && keepalive.is_none() && Instant::now() >= keepalive_at {
                            keepalive = Some(self.keepalive());
                            keepalive_at = Instant::now() + p.keepalive_every;
                        }
                        if p.rotation == Rotation::Proactive && rot.due() && self.token_left() <= p.rotate_before {
                            tracing::info!("vm {}: rotating the endpoint token (socket {})", self.vm(), link.n);
                            rot.step = Some(self.rotation_dial(rot.token.take()));
                            rot.after = None;
                        }
                    }
                    // S10: a park, once everything says the chat is quiet.
                    if let Some((why, quiet_ms)) = self.park_due(rot.step.is_some()) {
                        self.send_park(link, why, quiet_ms).await;
                    }
                    // A failed mint never ends a live socket: the next reconnect mints again. Parked, nothing is minted.
                    if rot.step.is_none() && !self.parked_here() && remint_after.is_none_or(|t| Instant::now() >= t) && self.freshen().await?.is_some() {
                        remint_after = Some(Instant::now() + p.backoff_max);
                    }
                }
            }
        }
    }

    // ---- S10 §D: the park on this socket --------------------------------------------------

    /// Parked on the socket that carries the spawn.
    fn parked_here(&self) -> bool {
        self.park.as_ref().is_some_and(|p| p.at == Park::Parked)
    }

    /// Neither parked nor asking to: the session keeps the VM awake (S9's behaviour).
    fn unparked_here(&self) -> bool {
        self.park.as_ref().is_none_or(|p| p.at == Park::No)
    }

    /// An unpark's probe runs on this socket.
    fn probing(&self) -> bool {
        self.park.as_ref().is_some_and(|p| p.probe_until.is_some())
    }

    /// No answer to the park within `answer_wait`, or neither a `pong` nor a
    /// `stdin_ack` within `probe` of an unpark: why the socket counts as lost.
    fn park_overdue(&self) -> Option<String> {
        let p = self.park.as_ref()?;
        let now = Instant::now();
        if let Park::Asking { until, .. } = p.at {
            if now >= until {
                return Some(format!("no answer to park within {}", secs(p.ctl.policy.answer_wait)));
            }
        }
        p.probe_until.filter(|t| now >= *t).map(|_| format!("no pong or stdin_ack within {} of the unpark", secs(p.ctl.policy.probe)))
    }

    /// Whether the session parks now (S10 §3.3), and why (`idle`, `prompt`)
    /// with the quiet before it: `park_v1` named and the spawn attached; no
    /// rotation in flight (`rotating`); nothing queued (stdin unacked, a
    /// signal, a detach, EOF); everything delivered marked consumed and
    /// acked; the pump's verdict `Idle` or `Prompt` since at least `after`;
    /// the session's own stdio as quiet; the code-out trigger quiet; and no
    /// back-off (`after` past the last park asked, or its refusal) or unpark
    /// under way.
    fn park_due(&self, rotating: bool) -> Option<(&'static str, u64)> {
        let p = self.park.as_ref()?;
        if !p.served || p.at != Park::No || p.probe_until.is_some() || p.unparking.is_some() || p.not_before.is_some_and(|t| Instant::now() < t) {
            return None;
        }
        let st = &self.st;
        if !self.attached || self.paused || rotating || st.phase != Phase::Running {
            return None;
        }
        if !st.pending.is_empty() || !st.signals.is_empty() || st.detach.is_some() || st.eof.is_some() {
            return None;
        }
        let (out, err) = self.io.consumed.seqs();
        if out < st.delivered.0 || err < st.delivered.1 || st.acked != (out.min(st.out), err.min(st.err)) {
            return None;
        }
        let q = *p.ctl.quiet.borrow();
        let why = match q.verdict {
            Verdict::Idle => "idle",
            Verdict::Prompt => "prompt",
            Verdict::Busy => return None,
        };
        let quiet = q.since.elapsed().min(p.last_io.elapsed());
        (quiet >= p.ctl.policy.after && p.ctl.trigger.quiet()).then_some((why, ms(quiet)))
    }

    /// `park` for the spawn, with the policy's terms and this wrapper as its
    /// owner; its answer is awaited. The next park waits `after` past this
    /// one whatever comes of it: a shim that never answers, or drops the
    /// socket on a `park`, costs one reconnect per `after`, never a loop
    /// through the reconnect budget (`run` starts a new reconnect episode at
    /// a socket lost to its park's handshake, however short it lived).
    async fn send_park(&mut self, link: &mut Link, why: &'static str, quiet_ms: u64) {
        let Some(p) = &mut self.park else { return };
        let pol = p.ctl.policy;
        let frame = Frame::Park { spawn_id: self.st.id.clone(), grace_s: pol.grace_s, min_quiet_s: pol.min_quiet_s, cpu_busy_ms: pol.cpu_busy_ms, hold_output: pol.hold_output, owner: p.ctl.owner };
        if link.send(&frame).await {
            tracing::info!("vm {}: asking to park spawn {} ({why}, quiet {quiet_ms} ms, socket {})", self.env.target.vm_id, self.st.id, link.n);
            let now = Instant::now();
            (p.at, p.not_before) = (Park::Asking { until: now + pol.answer_wait, why, quiet_ms, woke: None }, Some(now + pol.after));
        }
    }

    /// `parked`: no frame goes out on this socket until an unpark. Input that
    /// came during the handshake unparks at once.
    async fn on_parked(&mut self, link: &mut Link, quiet_s: u32, procs: u32) {
        let Some(Park::Asking { why, quiet_ms, woke, .. }) = self.park.as_ref().map(|p| p.at) else {
            tracing::info!(quiet_s, procs, "vm {}: a parked answer to no park: ignored", self.vm());
            return;
        };
        if let Some(p) = &mut self.park {
            p.at = Park::Parked;
        }
        self.parked(why, quiet_ms, &format!("socket {}, the shim's quiet {quiet_s} s, {procs} more processes", link.n));
        if let Some(by) = woke {
            self.unpark_open(link, by).await;
            self.flush(link).await;
        }
    }

    /// `park_refused`: tried again `after` later; what came meanwhile goes out.
    async fn on_park_refused(&mut self, link: &mut Link, reason: ParkRefusal, quiet_s: u32, procs: u32, cpu_ms: u64) {
        let word = refusal_word(reason);
        let Some(p) = self.park.as_mut().filter(|p| matches!(p.at, Park::Asking { .. })) else {
            tracing::info!(reason = word, "vm {}: a park_refused answer to no park: ignored", self.env.target.vm_id);
            return;
        };
        let now = Instant::now();
        p.at = Park::No;
        p.not_before = Some(now + p.ctl.policy.after);
        let log = p.refused_logged.is_none_or(|at| now.duration_since(at) >= PARK_REFUSED_LOG_EVERY);
        if log {
            p.refused_logged = Some(now);
        }
        tracing::info!("vm {}: the shim refused to park spawn {} ({word}: quiet {quiet_s} s, {procs} more processes, busiest sample {cpu_ms} ms)", self.env.target.vm_id, self.st.id);
        let _ = self.io.events.send(SpawnEvent::Park(ParkReport::Refused { reason: word }));
        if log {
            self.park_audit(SESSION_PARK_REFUSED, &[("reason", word.to_string()), ("procs", procs.to_string()), ("cpu_ms", cpu_ms.to_string())]);
        }
        self.flush(link).await;
    }

    /// The spawn parked (`why`: `idle`, `prompt`, `suspended`): its report, its row, a note.
    fn parked(&mut self, why: &'static str, quiet_ms: u64, detail: &str) {
        let _ = self.io.events.send(SpawnEvent::Park(ParkReport::Parked { why, quiet_ms }));
        self.park_audit(SESSION_PARK, &[("why", why.to_string()), ("quiet_ms", quiet_ms.to_string())]);
        self.note(format!("parked spawn {} ({why} for {}; {detail})", self.st.id, secs(Duration::from_millis(quiet_ms))));
    }

    /// The quiet before a park that came with a suspend (the pump's clock or the session's own, the shorter).
    fn quiet_ms(&self) -> u64 {
        self.park.as_ref().map_or(0, |p| ms(p.ctl.quiet.borrow().since.elapsed().min(p.last_io.elapsed())))
    }

    /// Input (`by`) or output while parked, or during the handshake: an
    /// unpark on the open socket, or one right after `parked`.
    async fn wake(&mut self, link: &mut Link, by: &'static str) {
        match self.park.as_ref().map(|p| p.at) {
            Some(Park::Parked) => self.unpark_open(link, by).await,
            Some(Park::Asking { .. }) => {
                if let Some(Park::Asking { woke, .. }) = self.park.as_mut().map(|p| &mut p.at) {
                    woke.get_or_insert(by);
                }
            }
            _ => {}
        }
    }

    /// `unpark` and a `ping` on the open socket: it carries the spawn again
    /// once a `pong` or a `stdin_ack` comes, within `probe` (else it is lost).
    async fn unpark_open(&mut self, link: &mut Link, by: &'static str) {
        let id = self.st.id.clone();
        if let Some(p) = &mut self.park {
            let now = Instant::now();
            (p.at, p.probe_until, p.unparking) = (Park::No, Some(now + p.ctl.policy.probe), Some(Unparking { since: now, by, vm_state: "running" }));
        }
        tracing::info!("vm {}: unparking spawn {id} ({by}) on socket {}", self.vm(), link.n);
        link.send(&Frame::Unpark { spawn_id: id }).await;
        link.send(&Frame::Ping { ts: crate::wire::time::unix_now_ms() }).await;
    }

    /// A `pong` or a `stdin_ack`: an unpark's probe is answered.
    fn probe_answered(&mut self) {
        if let Some(p) = self.park.as_mut().filter(|p| p.probe_until.is_some()) {
            p.probe_until = None;
            self.unparked();
        }
    }

    /// An unpark is done (a socket carries the spawn again): its report, its row, a note.
    fn unparked(&mut self) {
        let Some(u) = self.park.as_mut().and_then(|p| p.unparking.take()) else { return };
        let took = ms(u.since.elapsed());
        let _ = self.io.events.send(SpawnEvent::Park(ParkReport::Unparked { by: u.by, vm_state: u.vm_state, ms: took }));
        self.park_audit(SESSION_UNPARK, &[("by", u.by.to_string()), ("vm_state", u.vm_state.to_string()), ("ms", took.to_string())]);
        self.note(format!("unparked spawn {} ({}; the VM was {}) in {took} ms", self.st.id, u.by, u.vm_state));
    }

    /// The parked socket ended (the shim or the endpoint closed it, or a drop-transport): parked with no socket.
    fn parked_socket_gone(&self, n: u64, why: &str) -> End {
        self.note(format!("the parked socket {n} ended ({why}); spawn {} stays parked until the next input", self.st.id));
        End::Parked { frozen: false, watch: false, down: false }
    }

    /// `event hook_suspend`. A parking session whose spawn ran waits with no
    /// socket, never on `suspend_wait` and never exit 8; the next input
    /// resumes the VM. A spawn the shim holds parked lives its park grace,
    /// and input alone ends the wait. One it does not hold parked lives its
    /// detach grace once the VM runs again, so RUNNING again ends the wait
    /// too (`watch`): idle (`park_v1` named, the pump's verdict `Idle` or
    /// `Prompt`), it is parked `suspended`; a turn at work, or a shim without
    /// `park_v1`, reports no park but its link down (`down`), as S9's
    /// suspend does. An unpark under way stays one: its input is there
    /// already, and the next socket carries it. Before the spawn ran, and
    /// without a park control, the session waits for RUNNING (S9).
    fn on_hook_suspend(&mut self) -> End {
        let Some(p) = self.park.as_ref().filter(|_| self.st.started) else {
            return End::Suspended;
        };
        let watch = !self.parked_here() && p.unparking.is_none();
        let idle = p.served && p.ctl.quiet.borrow().verdict != Verdict::Busy;
        let down = watch && !idle;
        if watch && idle {
            let quiet_ms = self.quiet_ms();
            self.parked("suspended", quiet_ms, "the VM was suspended under it");
        }
        if let Some(p) = &mut self.park {
            (p.at, p.probe_until) = (Park::No, None);
        }
        let vm = self.vm();
        if down {
            self.note(format!("{vm} was suspended under spawn {}: not reconnecting until it runs again or input comes (`ai-env vm resume {vm}`)", self.st.id));
            self.link(false);
        } else {
            self.note(format!("{vm} was suspended: spawn {} stays parked until the next input{}", self.st.id, if watch { ", or until the VM runs again" } else { "" }));
        }
        End::Parked { frozen: true, watch, down }
    }

    /// The pump's last forwarded host kind (`session_unpark.by` for input).
    fn input_word(&self) -> &'static str {
        self.park.as_ref().and_then(|p| p.ctl.quiet.borrow().last_host).unwrap_or("other")
    }

    /// Input's `session_unpark.by` (`None`: none unparks).
    fn wake_word(&self, input: &SpawnInput) -> Option<&'static str> {
        match input {
            SpawnInput::Stdin(_) => Some(self.input_word()),
            SpawnInput::StdinEof => Some("eof"),
            SpawnInput::Signal(_) | SpawnInput::Detach { .. } => Some("signal"),
            SpawnInput::DropSocket => None,
        }
    }

    /// The session's own stdio moved (a park waits for `after` of quiet).
    fn moved(&mut self) {
        if let Some(p) = &mut self.park {
            p.last_io = Instant::now();
        }
    }

    /// A park row: the VM, the spawn, then `pairs` (§4.2).
    fn park_audit(&self, event: &str, pairs: &[(&str, String)]) {
        let mut all = vec![("vm", self.vm().to_string()), ("spawn", self.st.id.to_string())];
        all.extend(pairs.iter().cloned());
        audit_event(self.env.paths, event, &all);
    }

    /// One frame from the shim; `Some` when it ends this socket's service.
    /// While a rotation's hello is out (`paused`), `superseded` and
    /// `not_attached` are that hello's doing.
    async fn on_frame(&mut self, frame: Frame, link: &mut Link, superseded: &mut bool) -> Result<Option<End>, BridgeError> {
        if frame.spawn_id().is_some_and(|id| *id != self.st.id) {
            tracing::debug!("vm {}: ignoring {frame:?} (another spawn)", self.vm());
            return Ok(None);
        }
        match frame {
            Frame::Spawned { pid, pgid, claude_version, .. } => {
                self.st.phase = Phase::Running;
                self.attached = true;
                if !self.st.started {
                    let claude = claude_version.or_else(|| self.claude.clone());
                    self.started(pid, pgid, claude);
                }
                self.spawn_has_its_copy();
                self.flush(link).await;
            }
            Frame::CredentialOk { name, cached: true, .. } if self.delivery.as_ref().is_some_and(|d| d.name() == name) => self.credential_delivered("sealed"),
            Frame::CredentialOk { .. } => {}
            // A second refusal for a suspend after the VM ran again: its cache stays
            // closed (no `/resume` reached the shim), and waiting again would only
            // send the value again, without end.
            Frame::CredentialErr { code: CredentialErrCode::Suspended, .. } if self.cred_suspended => {
                let vm = self.vm();
                return Err(BridgeError::Transport(format!(
                    "{vm} refused the credential as suspending again after GetMicrovm said it runs: its shim's credential cache stays closed until a /resume reaches it, so nothing was started (`ai-env vm suspend {vm}`, then `ai-env vm resume {vm}`, reopens it; or start a new VM); run the command again"
                )));
            }
            // The cache closed for a suspend: the spawn behind it found nothing, and the reattach delivers once more.
            Frame::CredentialErr { code: CredentialErrCode::Suspended, .. } => {
                self.cred_suspended = true;
                return Ok(Some(End::Suspended));
            }
            Frame::CredentialErr { code: CredentialErrCode::Draining, .. } => return Err(BridgeError::Terminated(format!("{} is stopping: it accepts no credential", self.vm()))),
            Frame::CredentialErr { name, code, message } => {
                return Err(BridgeError::Protocol(format!("the shim refused credential {name} ({}): {}", wire_name(&code), scrub(&message))));
            }
            // The cache emptied between the delivery and the spawn (a suspend in
            // between). Never for a one-shot spawn, which names no credential: its
            // value never rides a frame the shim caches (that answer is a protocol error below).
            Frame::SpawnErr { code: SpawnErrCode::NoCredential, .. } if self.delivery.as_ref().is_some_and(|d| !d.one_shot()) => {
                if self.cred_retried {
                    return Err(BridgeError::Transport(format!("{} dropped the credential twice before spawn {} started: run the command again", self.vm(), self.st.id)));
                }
                self.cred_retried = true;
                if let Some(d) = &self.delivery {
                    d.still_gated(crate::wire::time::unix_now(), true)?;
                }
                self.send_credential(link).await?;
                self.send_spawn(link).await;
            }
            Frame::SpawnErr { spawn_id, code, message } => {
                // The re-sent spawn's id is taken: the first `spawn` reached the VM
                // before its socket was lost, and the shim never starts an id twice.
                if code == SpawnErrCode::Exists && self.st.resent {
                    let vm = self.vm();
                    return Err(BridgeError::Transport(format!(
                        "spawn {spawn_id} reached {vm} before the connection was lost: it ran, or still runs, without this client and was not started again (`ai-env vm attach {vm} --spawn {spawn_id}` reattaches to it while it runs)"
                    )));
                }
                // The command itself could not start (no program, not executable, no
                // working directory): the operator's to fix, not a lost VM.
                let refused = match code {
                    SpawnErrCode::NotFound => Some("not_found"),
                    SpawnErrCode::Exec => Some("exec"),
                    SpawnErrCode::Cwd => Some("cwd"),
                    // The VM runs its most commands already: a refusal, not a lost VM.
                    SpawnErrCode::Limit => Some("limit"),
                    _ => None,
                };
                if let Some(code) = refused {
                    return Err(BridgeError::SpawnRefused { code, message: scrub(&message).into_owned() });
                }
                return Err(BridgeError::Protocol(format!("the shim refused spawn {spawn_id} ({}): {}", wire_name(&code), scrub(&message))));
            }
            // S10: new output is the session's own stdio moving, and it unparks (`output`).
            Frame::Stdout { seq, data, .. } => {
                let before = self.st.out;
                self.deliver_out(seq, &data)?;
                if self.st.out != before {
                    self.moved();
                    self.wake(link, "output").await;
                }
            }
            Frame::Stderr { seq, data, dropped, .. } => {
                let before = self.st.err;
                self.deliver_err(seq, &data, dropped)?;
                if self.st.err != before {
                    self.moved();
                    self.wake(link, "output").await;
                }
            }
            Frame::StdinAck { seq, .. } => {
                self.st.stdin_acked(seq);
                // S10: a `stdin_ack` proves the socket after an unpark.
                self.probe_answered();
                self.flush(link).await;
            }
            Frame::Pong { .. } => self.probe_answered(),
            Frame::Exit { seq, code, signal, stderr_dropped, stdout_truncated, .. } => {
                if self.st.out_known && seq > self.st.out + 1 {
                    return Err(BridgeError::Protocol(format!("spawn {} exited at stdout seq {seq} but its stdout stopped at {}", self.st.id, self.st.out)));
                }
                let exit = RemoteExit { code, signal, stderr_dropped: stderr_dropped + self.st.err_dropped, stdout_truncated };
                let _ = self.io.events.send(SpawnEvent::Exit(exit));
                return Ok(Some(End::Exited(seq, exit)));
            }
            Frame::Event { kind: EventKind::HookSuspend, .. } => return Ok(Some(self.on_hook_suspend())),
            Frame::Event { kind: EventKind::HookTerminate, .. } => return Err(BridgeError::Terminated(format!("{} is terminating (event hook_terminate)", self.vm()))),
            Frame::Error { code: ErrorCode::Superseded, .. } if self.paused => *superseded = true,
            Frame::Error { code: ErrorCode::Superseded, .. } => return Err(BridgeError::Superseded(format!("spawn {} of {}", self.st.id, self.vm()))),
            Frame::Error { code: ErrorCode::NotAttached, .. } if self.paused => {}
            Frame::Error { code: ErrorCode::NotAttached, message, .. } => return Ok(Some(End::Lost(format!("the shim does not attach the spawn to this socket: {}", scrub(&message))))),
            Frame::Error { code: ErrorCode::Draining, .. } => return Err(BridgeError::Terminated(format!("{} is draining", self.vm()))),
            Frame::Error { code: ErrorCode::UnknownFrame | ErrorCode::Other, message, .. } => tracing::info!("vm {}: the shim reported: {}", self.vm(), scrub(&message)),
            Frame::Error { code, message, .. } => return Err(BridgeError::Protocol(format!("the shim reported {}: {}", wire_name(&code), scrub(&message)))),
            // S10 §D: the park's answers; outside a handshake they are logged and ignored.
            Frame::Parked { quiet_s, procs, .. } => self.on_parked(link, quiet_s, procs).await,
            Frame::ParkRefused { reason, quiet_s, procs, cpu_ms, .. } => self.on_park_refused(link, reason, quiet_s, procs, cpu_ms).await,
            other => tracing::debug!("vm {}: ignoring {other:?}", self.vm()),
        }
        Ok(None)
    }

    fn deliver_out(&mut self, seq: u64, data: &Chunk) -> Result<(), BridgeError> {
        let st = &mut self.st;
        if st.out_known && seq <= st.out {
            return Ok(());
        }
        if st.out_known && seq != st.out + 1 {
            return Err(BridgeError::Protocol(format!("stdout of spawn {} skipped from seq {} to {seq}", st.id, st.out)));
        }
        let bytes = decode(data).map_err(|e| BridgeError::Protocol(format!("stdout seq {seq} of spawn {}: {e}", st.id)))?;
        st.out = seq;
        st.out_known = true;
        st.delivered.0 = seq;
        st.out_lens.push_back((seq, bytes.len() as u64));
        let _ = self.io.events.send(SpawnEvent::Stdout { seq, bytes });
        Ok(())
    }

    /// stderr is drop-oldest on the shim: its seqs may skip (`dropped` counts
    /// the bytes). The shim sends it without credit, so the session bounds it
    /// too: while `STDERR_BUFFER_BYTES` of it wait for the consumer's mark,
    /// newer chunks are dropped and added to `dropped`.
    fn deliver_err(&mut self, seq: u64, data: &Chunk, dropped: u64) -> Result<(), BridgeError> {
        let (out_done, err_done) = self.io.consumed.seqs();
        let st = &mut self.st;
        if st.err_known && seq <= st.err {
            return Ok(());
        }
        let bytes = decode(data).map_err(|e| BridgeError::Protocol(format!("stderr seq {seq} of spawn {}: {e}", st.id)))?;
        st.err = seq;
        st.err_known = true;
        st.count_consumed(out_done.min(st.out), err_done.min(seq));
        let len = bytes.len() as u64;
        if st.err_unconsumed + len > STDERR_BUFFER_BYTES {
            st.err_dropped += len;
            return Ok(());
        }
        st.err_unconsumed += len;
        st.delivered.1 = seq;
        st.err_lens.push_back((seq, len));
        let _ = self.io.events.send(SpawnEvent::Stderr { seq, bytes, dropped: dropped + st.err_dropped });
        Ok(())
    }

    async fn on_input(&mut self, input: SpawnInput, link: &mut Link) {
        // S10: input unparks; during the park's handshake it waits for the answer.
        if let Some(by) = self.wake_word(&input) {
            self.wake(link, by).await;
        }
        self.st.take(input);
        self.flush(link).await;
    }

    /// The socket carries the spawn and may say so: not while a rotation's
    /// hello is out, and (S10) not from a park's request until an unpark.
    fn can_send(&self) -> bool {
        self.attached && !self.paused && self.unparked_here()
    }

    /// Everything that waits for a socket carrying the spawn: stdin within
    /// the shim's window, `stdin_eof`, signals, the ack, a detach. A frame
    /// leaves its queue only once its send succeeded: after a failure the
    /// rest waits for the next socket (the broken one is replaced at once).
    async fn flush(&mut self, link: &mut Link) {
        if !self.can_send() {
            return;
        }
        while let Some((seq, data, len)) = self.st.next_stdin() {
            if !link.send(&Frame::Stdin { spawn_id: self.st.id.clone(), seq, data }).await {
                return;
            }
            self.st.sent_in = seq;
            self.st.inflight += len;
            self.moved();
        }
        if let Some(seq) = self.st.eof.filter(|eof| !self.st.eof_sent && self.st.sent_in >= *eof) {
            if !link.send(&Frame::StdinEof { spawn_id: self.st.id.clone(), seq }).await {
                return;
            }
            self.st.eof_sent = true;
            self.moved();
        }
        while let Some(&sig) = self.st.signals.front() {
            if !link.send(&Frame::Signal { spawn_id: self.st.id.clone(), sig, scope: Scope::Group }).await {
                return;
            }
            self.st.signals.pop_front();
        }
        self.ack(link, true).await;
        if let Some(is_final) = self.st.detach {
            if link.send(&Frame::Detach { spawn_id: self.st.id.clone(), is_final }).await {
                self.st.detach = None;
                self.st.detach_sent = true;
            }
        }
    }

    /// Ack what the consumer marked: always on the timer, otherwise once
    /// `ack_bytes` were consumed since the last ack.
    async fn ack(&mut self, link: &mut Link, timer: bool) {
        let (out, err) = self.io.consumed.seqs();
        let (out, err) = (out.min(self.st.out), err.min(self.st.err));
        self.st.count_consumed(out, err);
        if !self.can_send() || (out, err) == self.st.acked || (!timer && self.st.consumed_bytes < self.env.policy.ack_bytes) {
            return;
        }
        link.send(&Frame::Ack { spawn_id: self.st.id.clone(), seq: out, err_seq: err }).await;
        self.st.acked = (out, err);
        self.st.consumed_bytes = 0;
    }

    /// The rotation's new socket said `hello_ok`: it takes over, the old one is closed 1000.
    async fn rotated(&mut self, link: &mut Link, rotated: Rotated) -> Result<(), BridgeError> {
        // stdin acks the old socket already read still count.
        while let Ok(m) = link.inbound.try_recv() {
            if let Inbound::Frame(f) = m {
                if let Frame::StdinAck { spawn_id, seq } = *f {
                    if spawn_id == self.st.id {
                        self.st.stdin_acked(seq);
                    }
                }
            }
        }
        let old = std::mem::replace(link, Link::start(rotated.conn));
        tokio::spawn(old.close(CLOSE_NORMAL));
        self.token = rotated.token;
        self.paused = false;
        self.attached = false;
        self.adopt(&rotated.ok, link).await?;
        self.audit("agent_rotate", &[("mode", "proactive".into())]);
        self.note(format!("rotated to a fresh endpoint token (socket {})", link.n));
        Ok(())
    }

    /// The exit was delivered: once the consumer marked every chunk this
    /// session delivered (at most `dead_after`), ack the exit's seq (the shim
    /// then releases the spawn); close 1000.
    async fn finish(&mut self, mut link: Link, exit_seq: u64, exit: RemoteExit) -> SpawnOutcome {
        let want = self.st.delivered;
        let (consumed, events) = (self.io.consumed.clone(), self.io.events.clone());
        let caught_up = tokio::time::timeout(self.env.policy.dead_after, async {
            loop {
                let (out, err) = consumed.seqs();
                if out >= want.0 && err >= want.1 {
                    return true;
                }
                tokio::select! {
                    () = consumed.changed() => {}
                    () = events.closed() => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        if caught_up {
            link.send(&Frame::Ack { spawn_id: self.st.id.clone(), seq: exit_seq, err_seq: self.st.err }).await;
        } else {
            tracing::info!("vm {}: spawn {} exited; the consumer did not confirm its output, so the exit stays unacked (the shim keeps it for its grace)", self.vm(), self.st.id);
        }
        link.close(CLOSE_NORMAL).await;
        SpawnOutcome { spawn_id: self.st.id.clone(), exit, parked_close: false }
    }

    // ---- waiting while disconnected -----------------------------------------------------

    /// Sleep `d`, still taking the consumer's input (queued for the next
    /// socket); a detach ends the session at once.
    async fn pause(&mut self, d: Duration) -> Result<(), BridgeError> {
        let until = tokio::time::Instant::now() + d;
        loop {
            let input = tokio::select! {
                () = tokio::time::sleep_until(until) => return Ok(()),
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(input) => input,
                    None => {
                        self.control_open = false;
                        continue;
                    }
                },
                m = self.io.input.recv(), if self.st.wants_input() => match m {
                    Some(input) => input,
                    None => {
                        self.st.input_open = false;
                        continue;
                    }
                },
            };
            if matches!(input, SpawnInput::Detach { .. }) {
                return Err(self.detached_while_disconnected());
            }
            self.st.take(input);
        }
    }

    /// `fut` (a dial, a hello) while the consumer's control channel is
    /// watched: a signal is queued for the spawn, a detach ends the session
    /// at once and `fut` is dropped (a spawn not sent yet is never sent).
    async fn watching<T>(&mut self, fut: impl std::future::Future<Output = T>) -> Result<T, BridgeError> {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                out = &mut fut => return Ok(out),
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(SpawnInput::Detach { .. }) => return Err(self.detached_while_disconnected()),
                    Some(input) => self.st.take(input),
                    None => self.control_open = false,
                },
            }
        }
    }

    /// Before a `spawn` goes out: the control inputs that arrived meanwhile;
    /// a detach among them (or one already taken) means it never goes out.
    fn no_pending_detach(&mut self) -> Result<(), BridgeError> {
        while self.control_open {
            match self.io.control.try_recv() {
                Ok(input) => self.st.take(input),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => self.control_open = false,
            }
        }
        match self.st.detach {
            Some(_) => Err(self.detached_while_disconnected()),
            None => Ok(()),
        }
    }

    fn detached_while_disconnected(&self) -> BridgeError {
        BridgeError::Transport(format!("detached from spawn {} while disconnected from {} (its detach grace ends it)", self.st.id, self.vm()))
    }

    // ---- tokens -------------------------------------------------------------------------

    /// What is left of the endpoint token, by the wall clock.
    fn token_left(&self) -> Duration {
        left(&self.token)
    }

    async fn remint(&mut self, why: &str) -> Result<(), BridgeError> {
        self.token = mint_token(self.env).await?;
        self.audit("agent_remint", &[("reason", why.to_string())]);
        Ok(())
    }

    /// A fresh token when less than `remint_below` is left. A failed mint
    /// keeps the current token and comes back as `Ok(Some(error))` (whether
    /// an expired token is the end is the caller's call); only a VM that is
    /// gone is `Err`.
    async fn freshen(&mut self) -> Result<Option<BridgeError>, BridgeError> {
        if self.token_left() >= self.env.policy.remint_below {
            return Ok(None);
        }
        match self.remint("expiring").await {
            Ok(()) => Ok(None),
            Err(e) if gone(&e) => Err(e),
            Err(e) => {
                tracing::warn!("vm {}: the endpoint token was not re-minted ({e}); {} left on the current one", self.vm(), secs(self.token_left()));
                Ok(Some(e))
            }
        }
    }

    /// The keep-alive: one bearer-less `GET /health` (bounded by its own cadence).
    fn keepalive(&self) -> BoxFuture<'a, Result<HealthReply, BridgeError>> {
        let (ep, endpoint, token, limit) = (self.env.ep, self.env.target.endpoint.clone(), self.token.clone(), self.env.policy.keepalive_every);
        Box::pin(async move {
            match tokio::time::timeout(limit, ep.get_health(&endpoint, &token, APP_PORT)).await {
                Ok(r) => r,
                Err(_) => Err(BridgeError::Endpoint(format!("no /health answer within {}", secs(limit)))),
            }
        })
    }

    /// A rotation's first step: `kept` (while it has `remint_below` left) or
    /// a fresh token, and a second socket. The old one serves meanwhile.
    fn rotation_dial(&self, kept: Option<AuthToken>) -> BoxFuture<'a, RotationStep> {
        let env = self.env;
        let (api, paths, dial, minutes, below) = (env.api, env.paths, env.dial, env.policy.token_minutes, env.policy.remint_below);
        let (vm, endpoint, trace) = (env.target.vm_id.clone(), env.target.endpoint.clone(), self.trace.clone());
        Box::pin(async move {
            let token = match kept.filter(|t| left(t) >= below) {
                Some(token) => token,
                None => match mint(api, paths, &vm, APP_PORT, minutes).await {
                    Ok(token) => token,
                    Err(e) => return RotationStep::Failed(None, RotationFailed::Mint(e.to_string())),
                },
            };
            let value = match token.value() {
                Ok(value) => value.clone(),
                Err(e) => return RotationStep::Failed(None, RotationFailed::Mint(e.to_string())),
            };
            match AgentConn::open(&dial, &endpoint, &value).await {
                Ok(conn) => RotationStep::Dialed(token, conn.with_trace(trace)),
                Err(e) => RotationStep::Failed(Some(token), RotationFailed::Dial(e)),
            }
        })
    }

    /// A rotation's second step: `hello` on the new socket, resuming from what was delivered by now.
    fn rotation_hello(&self, token: AuthToken, mut conn: AgentConn) -> BoxFuture<'a, RotationStep> {
        let env = self.env;
        let (session_token, resume, idle_s, wait) = (env.target.session_token.clone(), self.st.resume(), env.policy.idle_s, env.policy.dead_after);
        Box::pin(async move {
            let answer = tokio::time::timeout(wait, conn.hello(&session_token, resume, idle_s)).await;
            match answer {
                Ok(Ok(ok)) => RotationStep::Answered(Box::new(Rotated { token, conn, ok })),
                Ok(Err(e @ BridgeError::HelloRefused { .. })) => RotationStep::Failed(Some(token), RotationFailed::Refused(e.to_string())),
                Ok(Err(e)) => RotationStep::Failed(Some(token), RotationFailed::Unanswered(e.to_string())),
                Err(_) => RotationStep::Failed(Some(token), RotationFailed::Unanswered(format!("no hello_ok within {}", secs(wait)))),
            }
        })
    }

    /// A rotation attempt that left the spawn on socket `n`: when the next
    /// may start, by the reconnect rules. A 429 waits max(Retry-After,
    /// backoff) and is audited; a 401/403 spends the one re-mint, and a second
    /// stops rotating on this socket; anything else backs off.
    fn rotation_failed(&self, rot: &mut Rotating<'_>, failed: &RotationFailed, n: u64) {
        let p = &self.env.policy;
        tracing::warn!("vm {}: token rotation: {failed}", self.vm());
        let wait = match failed {
            RotationFailed::Dial(DialError::TokenRejected { .. }) if rot.retry.reminted => {
                rot.stopped = true;
                self.note(format!("the token rotation failed again with a fresh token ({failed}); staying on socket {n} until it ends"));
                return;
            }
            RotationFailed::Dial(DialError::TokenRejected { .. }) => {
                rot.retry.reminted = true;
                rot.token = None;
                rot.retry.next(p)
            }
            RotationFailed::Dial(DialError::Throttled { retry_after_s }) => {
                let backoff = rot.retry.next(p);
                let wait = retry_after_s.map_or(backoff, |s| units(p, s).max(backoff));
                let retry_after = retry_after_s.map_or_else(|| "none".to_string(), |s| s.to_string());
                self.audit("endpoint_429", &[("retry_after", retry_after), ("waited_ms", wait.as_millis().to_string())]);
                wait
            }
            _ => rot.retry.next(p),
        };
        self.note(format!("the token rotation failed ({failed}); staying on socket {n} and trying again in {}", secs(wait)));
        rot.after = Some(Instant::now() + wait);
    }

    // ---- records ------------------------------------------------------------------------

    fn vm(&self) -> &str {
        &self.env.target.vm_id
    }

    fn started(&mut self, pid: u32, pgid: u32, claude_version: Option<String>) {
        self.st.started = true;
        let _ = self.io.events.send(SpawnEvent::Started { spawn_id: self.st.id.clone(), pid, pgid, claude_version });
    }

    fn note(&self, text: String) {
        tracing::info!("vm {}: {text}", self.vm());
        let _ = self.io.events.send(SpawnEvent::Note(text));
    }

    /// [`SpawnEvent::Link`]: whether a signal or a `detach` can reach the VM now.
    fn link(&self, up: bool) {
        let _ = self.io.events.send(SpawnEvent::Link(up));
    }

    fn audit(&self, event: &str, pairs: &[(&str, String)]) {
        let mut all = vec![("id", self.vm().to_string()), ("spawn", self.st.id.to_string())];
        all.extend(pairs.iter().cloned());
        audit_event(self.env.paths, event, &all);
    }
}

/// A `Port(8080)` token for the session; a mint that failed because the VM
/// is gone says so (exit 8, not the mint's own exit 7).
async fn mint_token<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>) -> Result<AuthToken, BridgeError> {
    let id = &env.target.vm_id;
    match mint(env.api, env.paths, id, APP_PORT, env.policy.token_minutes).await {
        Ok(token) => Ok(token),
        Err(e @ BridgeError::VmNotFound(_)) => Err(e),
        Err(e) => match env.api.get(id).await {
            Ok(vm) if vm.state.is_terminal() => Err(terminated(&vm)),
            Err(gone @ BridgeError::VmNotFound(_)) => Err(gone),
            _ => Err(e),
        },
    }
}

/// What is left of `token`, by the wall clock.
fn left(token: &AuthToken) -> Duration {
    Duration::from_secs(token.expires_at_unix).saturating_sub(wall_now())
}

/// The wall clock, as time since the epoch (in tests it runs
/// `tests::WALL_AHEAD` ahead: a laptop sleep, which stops `Instant` only).
fn wall_now() -> Duration {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    #[cfg(test)]
    let now = now + tests::WALL_AHEAD.with(std::cell::Cell::get);
    now
}

/// A mint failure that means the VM is gone (`mint_token` asked GetMicrovm).
fn gone(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Terminated(_) | BridgeError::VmNotFound(_))
}

/// The output of the future in `slot`, or never while it is empty (a select arm that stays quiet).
async fn pending_or<T>(slot: &mut Option<BoxFuture<'_, T>>) -> T {
    match slot.as_mut() {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

fn auto_resume(vm: &VmInfo) -> bool {
    !vm.idle.is_some_and(|i| !i.auto_resume)
}

fn terminated(vm: &VmInfo) -> BridgeError {
    let reason = vm.state_reason.as_deref().map(|r| format!(" ({})", scrub(r))).unwrap_or_default();
    BridgeError::Terminated(format!("{} is {}{reason}", vm.id, vm.state.as_str()))
}

/// `n` of the policy's seconds (`backoff_min`; see `RunPolicy`).
fn units(p: &RunPolicy, n: u64) -> Duration {
    p.backoff_min.saturating_mul(u32::try_from(n).unwrap_or(u32::MAX))
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

/// The wire spelling of a code (`bad_request`, …).
fn wire_name<T: serde::Serialize>(code: &T) -> String {
    serde_json::to_value(code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::{run_spawn, spawn_channels, AgentTarget, Consumed, ConsumerIo};
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN, TOKEN_HEADER};
    use crate::bridge::config::Paths;
    use crate::bridge::transport::AgentDial;
    use crate::bridge::vm::registry::{RowStatus, VmRow};
    use crate::errors::CliError;
    use crate::wire::frame::{HelloErrCode, Resumed, ACK_EVERY_BYTES, CLOSE_GOING_AWAY, CLOSE_HELLO_REFUSED};
    use crate::wire::redact::Secret;
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;

    type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    const SESSION_TOKEN: &str = "test-session-token-0001";
    /// Every test ends within this.
    const LIMIT: Duration = Duration::from_secs(30);

    thread_local! {
        /// How far `wall_now` runs ahead of the real wall clock on this test's
        /// thread (a `#[tokio::test]` runs on one thread, so no other test sees it).
        pub(super) static WALL_AHEAD: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    }

    // ---- the fake endpoint ---------------------------------------------------------------

    /// A scripted answer to one upgrade.
    struct Refusal {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    }

    fn refusal(status: u16, headers: &[(&'static str, &str)], body: &str) -> Refusal {
        Refusal { status, headers: headers.iter().map(|(k, v)| (*k, (*v).to_string())).collect(), body: body.into() }
    }

    /// One upgrade as the endpoint saw it.
    #[derive(Debug, Clone)]
    struct Attempt {
        at: Instant,
        status: u16,
    }

    /// The tests' MicroVM endpoint on loopback (the knob dials it): the
    /// scripted refusals first, then the proxy's own token and state check
    /// (`FakeState::endpoint_check`, which also auto-resumes), then the
    /// upgrade, whose socket goes to the test.
    struct Endpoint {
        addr: SocketAddr,
        refusals: Arc<Mutex<VecDeque<Refusal>>>,
        attempts: Arc<Mutex<Vec<Attempt>>>,
        sockets: tokio::sync::Mutex<mpsc::UnboundedReceiver<Ws>>,
    }

    impl Endpoint {
        async fn start(api: Arc<FakeMicrovmApi>) -> Endpoint {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let refusals: Arc<Mutex<VecDeque<Refusal>>> = Arc::default();
            let attempts: Arc<Mutex<Vec<Attempt>>> = Arc::default();
            let (tx, rx) = mpsc::unbounded_channel();
            let (scripted, seen) = (refusals.clone(), attempts.clone());
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (scripted, seen, api, tx) = (scripted.clone(), seen.clone(), api.clone(), tx.clone());
                    tokio::spawn(async move {
                        // tungstenite's `Callback` fixes this signature.
                        #[allow(clippy::result_large_err)]
                        let check = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                            let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                            let refused = scripted.lock().unwrap().pop_front().or_else(|| {
                                let token = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new(header("x-aws-proxy-auth")))]), port: APP_PORT, expires_at_unix: 0 };
                                let proxy = api.state().endpoint_check(&header("host"), &token, header("x-aws-proxy-port").parse().unwrap_or(0));
                                proxy.err().map(|r| Refusal { status: r.status, headers: r.proxy_error.map(|e| vec![("x-aws-proxy-error", e)]).unwrap_or_default(), body: String::new() })
                            });
                            seen.lock().unwrap().push(Attempt { at: Instant::now(), status: refused.as_ref().map_or(101, |r| r.status) });
                            let Some(r) = refused else { return Ok(resp) };
                            let mut answer = http::Response::builder().status(r.status);
                            for (k, v) in r.headers {
                                answer = answer.header(k, v);
                            }
                            Err(answer.body(Some(r.body)).unwrap())
                        };
                        if let Ok(ws) = tokio_tungstenite::accept_hdr_async_with_config(tcp, check, Some(crate::wire::frame::ws_config())).await {
                            let _ = tx.send(ws);
                        }
                    });
                }
            });
            Endpoint { addr, refusals, attempts, sockets: tokio::sync::Mutex::new(rx) }
        }

        fn refuse(&self, r: Refusal) {
            self.refusals.lock().unwrap().push_back(r);
        }

        fn attempts(&self) -> Vec<Attempt> {
            self.attempts.lock().unwrap().clone()
        }

        /// The next upgraded socket.
        async fn next(&self) -> Ws {
            tokio::time::timeout(LIMIT, async { self.sockets.lock().await.recv().await }).await.expect("an upgrade in time").expect("the endpoint runs")
        }
    }

    /// A RUNNING fake VM, its endpoint and a state root.
    struct Rig {
        api: Arc<FakeMicrovmApi>,
        vm: VmInfo,
        endpoint: Endpoint,
        paths: Paths,
        _dir: tempfile::TempDir,
    }

    async fn rig(auto_resume: bool) -> Rig {
        let api = Arc::new(FakeMicrovmApi::new());
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "0192f1e0-0000-7000-8000-0000000000a1".into(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let endpoint = Endpoint::start(api.clone()).await;
        Rig { api, vm, endpoint, paths, _dir: dir }
    }

    impl Rig {
        fn env(&self, policy: RunPolicy) -> AgentEnv<'_, FakeMicrovmApi, FakeMicrovmApi> {
            AgentEnv {
                api: &self.api,
                ep: &self.api,
                paths: &self.paths,
                target: AgentTarget { vm_id: self.vm.id.clone(), endpoint: self.vm.endpoint.clone(), session_token: Secret::new(SESSION_TOKEN.into()), vpc: false, shell: false },
                policy,
                dial: AgentDial { local: Some(self.endpoint.addr) },
            }
        }

        fn calls(&self, f: impl Fn(&Call) -> bool) -> usize {
            self.api.calls().iter().filter(|c| f(c)).count()
        }

        fn audit(&self, event: &str) -> Vec<serde_json::Value> {
            crate::bridge::audit::read_rows(&self.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == event).collect()
        }
    }

    /// Small timers; pings and keep-alives off unless a test turns them on.
    fn policy() -> RunPolicy {
        RunPolicy {
            ping: Duration::from_secs(3600),
            ws_ping: Duration::from_secs(3600),
            dead_after: Duration::from_secs(5),
            ack_bytes: ACK_EVERY_BYTES,
            ack_every: Duration::from_millis(10),
            rotation: Rotation::Lazy,
            keepalive: Keepalive::Frames,
            keepalive_every: Duration::from_secs(3600),
            suspend_wait: Duration::from_secs(5),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            stable_after: Duration::from_secs(1),
            reconnect_budget: Duration::from_secs(5),
            not_run_budget: Duration::from_secs(2),
            token_minutes: 60,
            remint_below: Duration::from_secs(60),
            rotate_before: Duration::from_secs(120),
            idle_s: Some(90),
        }
    }

    fn cat_spec() -> SpawnSpec {
        SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: None, id: None }
    }

    fn lines(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("line-{i:03}\n").into_bytes()).collect()
    }

    // ---- the consumer --------------------------------------------------------------------

    /// What the consumer saw.
    #[derive(Debug, Default)]
    struct Seen {
        stdout: Vec<u8>,
        out_seqs: Vec<u64>,
        notes: Vec<String>,
        links: Vec<bool>,
        started: Option<(u32, u32)>,
        exit: Option<RemoteExit>,
    }

    impl Seen {
        /// One event, marked consumed as soon as it is "written".
        fn add(&mut self, ev: SpawnEvent, consumed: &Consumed) {
            match ev {
                SpawnEvent::Started { pid, pgid, .. } => self.started = Some((pid, pgid)),
                SpawnEvent::Stdout { seq, bytes } => {
                    self.out_seqs.push(seq);
                    self.stdout.extend(bytes);
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Stderr { seq, .. } => consumed.stderr_done(seq),
                SpawnEvent::Note(n) => self.notes.push(n),
                SpawnEvent::Link(up) => self.links.push(up),
                SpawnEvent::Exit(e) => self.exit = Some(e),
                // S10: no session here parks.
                SpawnEvent::Park(_) => {}
            }
        }
    }

    /// Feeds `input` (each a stdin chunk, `gap` apart, then EOF; `None`: no
    /// stdin, never closed) and reads every event until the session ends.
    async fn consume(c: ConsumerIo, input: Option<Vec<Vec<u8>>>, gap: Duration) -> Seen {
        let ConsumerIo { input: tx, control: _control, mut events, consumed } = c;
        // The sender comes back, so stdin stays open until the session ends.
        let feed = async move {
            for chunk in input.iter().flatten() {
                tokio::time::sleep(gap).await;
                let _ = tx.send(SpawnInput::Stdin(chunk.clone())).await;
            }
            if input.is_some() {
                let _ = tx.send(SpawnInput::StdinEof).await;
            }
            tx
        };
        let read = async {
            let mut seen = Seen::default();
            while let Some(ev) = events.recv().await {
                seen.add(ev, &consumed);
            }
            seen
        };
        tokio::join!(feed, read).1
    }

    // ---- a scripted shim -----------------------------------------------------------------

    /// The next frame (WebSocket Pings and Pongs and app pings skipped).
    async fn frame(ws: &mut Ws) -> Frame {
        loop {
            match tokio::time::timeout(LIMIT, ws.next()).await.expect("a frame in time").expect("open").expect("readable") {
                Message::Text(t) => match Frame::from_json(t.as_str()).unwrap() {
                    Frame::Ping { .. } => continue,
                    f => return f,
                },
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("{other:?}"),
            }
        }
    }

    async fn put(ws: &mut Ws, f: &Frame) {
        ws.send(Message::from(f)).await.unwrap();
    }

    fn hello_ok(spawns: Vec<SpawnStatus>, resumed: Vec<Resumed>) -> Frame {
        Frame::HelloOk {
            wire: 1,
            shim_version: "0.1.0".into(),
            claude_version: None,
            microvm_id: None,
            image_version: None,
            boot_nonce: "test-nonce".into(),
            owner: None,
            has_credentials: false,
            uptime_s: 1,
            run_hook_seen: true,
            spawns,
            resumed,
            caps: vec![],
            credential: Default::default(),
        }
    }

    fn status(id: &SpawnId, out_seq: u64, in_seq: u64) -> SpawnStatus {
        SpawnStatus { spawn_id: id.clone(), argv0: "cat".into(), pid: 4242, pgid: 4242, alive: true, attached: false, out_seq, out_from: 1, err_seq: 0, in_seq, stdin_closed: false, exit: None }
    }

    /// hello → hello_ok → spawn → spawned: the spawn's id.
    async fn start_spawn(ws: &mut Ws) -> SpawnId {
        assert!(matches!(frame(ws).await, Frame::Hello { .. }));
        put(ws, &hello_ok(vec![], vec![])).await;
        let Frame::Spawn { spawn_id, .. } = frame(ws).await else { panic!("no spawn") };
        put(ws, &Frame::Spawned { spawn_id: spawn_id.clone(), pid: 4242, pgid: 4242, claude_version: None }).await;
        spawn_id
    }

    fn exit0(id: &SpawnId, seq: u64) -> Frame {
        Frame::Exit { spawn_id: id.clone(), seq, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }
    }

    /// A one-minute token rotated 59 s before its expiry: within a second.
    fn rotation_policy() -> RunPolicy {
        RunPolicy { rotation: Rotation::Proactive, token_minutes: 1, rotate_before: Duration::from_secs(59), remint_below: Duration::from_secs(1), ..policy() }
    }

    /// A session as `run` builds it (a fresh token), before its first socket.
    async fn session<'e, 'a>(env: &'e AgentEnv<'a, FakeMicrovmApi, FakeMicrovmApi>, io: SpawnIo, start: Start) -> Session<'e, 'a, FakeMicrovmApi, FakeMicrovmApi> {
        let token = mint_token(env).await.unwrap();
        Session { env, io, trace: Trace::default(), token, st: State::new(start), attached: false, paused: false, control_open: true, delivery: None, cred_retried: false, cred_suspended: false, claude: None, park: None }
    }

    /// A socket to the rig's endpoint with the session's token, and the endpoint's end of it.
    async fn link_to(rig: &Rig, s: &Session<'_, '_, FakeMicrovmApi, FakeMicrovmApi>) -> (Link, Ws) {
        let (conn, ws) = tokio::join!(AgentConn::open(&s.env.dial, &s.env.target.endpoint, s.token.value().unwrap()), rig.endpoint.next());
        (Link::start(conn.unwrap()), ws)
    }

    // ---- a cat shim ----------------------------------------------------------------------

    /// How the cat shim misbehaves.
    #[derive(Debug, Default, Clone, Copy)]
    struct CatScript {
        /// Socket `n` is cut (no Close) when stdin seq `m` reaches it: that
        /// chunk and everything after it on that socket are lost.
        cut: Option<(usize, u64)>,
        /// A reattach replays stdout from seq 1 (the client drops what it has).
        replay_all: bool,
        /// Socket `n` acks stdin only up to seq `m` (it holds the rest unacked).
        ack_upto: Option<(usize, u64)>,
        /// Socket `n` goes silent after `spawned`: it reads and writes nothing more.
        silent: Option<usize>,
        /// Socket `n` never answers its hello.
        mute: Option<usize>,
        /// Socket `n` is cut at its first ping after the muted socket said hello.
        cut_on_ping: Option<usize>,
    }

    enum Action {
        Go,
        Cut,
        Silent,
    }

    /// A shim running one `cat`: stdin chunks come back as stdout chunks,
    /// `stdin_eof` exits 0; the newest socket that resumes the spawn gets it
    /// (the old one is told `superseded`) and all output.
    #[derive(Default)]
    struct Cat {
        script: CatScript,
        /// Runs once, when the cut happens.
        on_cut: Option<Box<dyn FnOnce() + Send>>,
        spawn: Option<SpawnId>,
        out: Vec<Chunk>,
        in_seq: u64,
        /// (socket, seq) of every stdin frame that arrived, duplicates included.
        stdin: Vec<(usize, u64)>,
        eof: Option<u64>,
        attached: usize,
        writers: Vec<mpsc::UnboundedSender<Message>>,
        hellos: Vec<(usize, Vec<ResumePoint>)>,
        muted: bool,
        closes: Vec<(usize, Option<u16>)>,
        detach: Option<bool>,
    }

    impl Cat {
        fn new(script: CatScript) -> Arc<Mutex<Cat>> {
            Arc::new(Mutex::new(Cat { script, ..Cat::default() }))
        }

        fn send(&self, n: usize, f: &Frame) {
            let _ = self.writers[n - 1].send(Message::from(f));
        }

        fn id(&self) -> SpawnId {
            self.spawn.clone().expect("spawned")
        }

        fn on_frame(&mut self, n: usize, frame: Frame) -> Action {
            match frame {
                Frame::Hello { session_token, resume, .. } => {
                    assert_eq!(session_token.expose(), SESSION_TOKEN);
                    self.hellos.push((n, resume.clone()));
                    if self.script.mute == Some(n) {
                        self.muted = true;
                        return Action::Go;
                    }
                    let mut resumed = Vec::new();
                    let mut replay = None;
                    for r in resume {
                        if Some(&r.spawn_id) == self.spawn.as_ref() {
                            if self.attached != 0 && self.attached != n {
                                self.send(self.attached, &Frame::error(ErrorCode::Superseded, "a newer socket attached", Some(r.spawn_id.clone())));
                            }
                            self.attached = n;
                            replay = Some(if self.script.replay_all { 1 } else { r.from_seq.unwrap_or(1) });
                            resumed.push(Resumed { spawn_id: r.spawn_id, status: ResumeStatus::Ok });
                        } else {
                            resumed.push(Resumed { spawn_id: r.spawn_id, status: ResumeStatus::Unknown });
                        }
                    }
                    let spawns = self.spawn.iter().map(|id| status(id, self.out.len() as u64, self.in_seq)).collect();
                    self.send(n, &hello_ok(spawns, resumed));
                    if let Some(from) = replay {
                        if self.in_seq > 0 {
                            self.send(n, &Frame::StdinAck { spawn_id: self.id(), seq: self.in_seq });
                        }
                        for seq in from..=self.out.len() as u64 {
                            self.send(n, &Frame::Stdout { spawn_id: self.id(), seq, data: self.out[seq as usize - 1].clone() });
                        }
                        self.maybe_exit();
                    }
                    Action::Go
                }
                Frame::Spawn { spawn_id, argv, .. } => {
                    assert_eq!(argv, vec!["cat".to_string()]);
                    self.spawn = Some(spawn_id.clone());
                    self.attached = n;
                    self.send(n, &Frame::Spawned { spawn_id, pid: 4242, pgid: 4242, claude_version: None });
                    if self.script.silent == Some(n) {
                        return Action::Silent;
                    }
                    Action::Go
                }
                Frame::Stdin { spawn_id, seq, data } => {
                    self.stdin.push((n, seq));
                    if self.script.cut.is_some_and(|(s, m)| s == n && seq >= m) {
                        if let Some(hook) = self.on_cut.take() {
                            hook();
                        }
                        return Action::Cut;
                    }
                    if self.attached != n {
                        self.send(n, &Frame::error(ErrorCode::NotAttached, "not attached here", Some(spawn_id)));
                        return Action::Go;
                    }
                    if seq <= self.in_seq {
                        return Action::Go;
                    }
                    assert_eq!(seq, self.in_seq + 1, "a stdin gap");
                    self.in_seq = seq;
                    self.out.push(data.clone());
                    if self.script.ack_upto.is_none_or(|(s, m)| s != n || seq <= m) {
                        self.send(n, &Frame::StdinAck { spawn_id: spawn_id.clone(), seq });
                    }
                    self.send(n, &Frame::Stdout { spawn_id, seq: self.out.len() as u64, data });
                    self.maybe_exit();
                    Action::Go
                }
                Frame::StdinEof { seq, .. } => {
                    self.eof = Some(seq);
                    self.maybe_exit();
                    Action::Go
                }
                Frame::Ping { ts } => {
                    if self.muted && self.script.cut_on_ping == Some(n) {
                        return Action::Cut;
                    }
                    self.send(n, &Frame::Pong { ts });
                    Action::Go
                }
                Frame::Detach { is_final, .. } => {
                    self.detach = Some(is_final);
                    Action::Go
                }
                Frame::Ack { .. } => Action::Go,
                other => panic!("the cat shim got {other:?}"),
            }
        }

        fn maybe_exit(&self) {
            if self.eof.is_some_and(|e| self.in_seq >= e) {
                self.send(self.attached, &Frame::Exit { spawn_id: self.id(), seq: self.out.len() as u64 + 1, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false });
            }
        }
    }

    /// One socket of the cat shim: a writer task fed by the model, and this reader.
    async fn cat_socket(ws: Ws, cat: Arc<Mutex<Cat>>) {
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let n = {
            let mut c = cat.lock().unwrap();
            c.writers.push(tx);
            c.writers.len()
        };
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if sink.send(m).await.is_err() {
                    return;
                }
            }
        });
        while let Some(Ok(msg)) = stream.next().await {
            let frame = match msg {
                Message::Text(t) => Frame::from_json(t.as_str()).unwrap(),
                Message::Close(f) => {
                    cat.lock().unwrap().closes.push((n, f.map(|f| u16::from(f.code))));
                    break;
                }
                _ => continue,
            };
            let action = cat.lock().unwrap().on_frame(n, frame);
            match action {
                Action::Go => {}
                Action::Cut => {
                    writer.abort();
                    return;
                }
                Action::Silent => std::future::pending::<()>().await,
            }
        }
    }

    /// `work` while the cat shim serves every socket the endpoint upgrades.
    async fn with_cat<T>(rig: &Rig, cat: &Arc<Mutex<Cat>>, work: impl std::future::Future<Output = T>) -> T {
        let serve = async {
            while let Some(ws) = rig.endpoint.sockets.lock().await.recv().await {
                tokio::spawn(cat_socket(ws, cat.clone()));
            }
        };
        tokio::select! {
            out = work => out,
            () = serve => unreachable!("the endpoint stopped"),
        }
    }

    /// A whole `cat` session: `input` in, the outcome and what the consumer saw out.
    async fn cat_session(rig: &Rig, cat: &Arc<Mutex<Cat>>, policy: RunPolicy, input: Vec<Vec<u8>>, gap: Duration) -> (Result<SpawnOutcome, BridgeError>, Seen) {
        let env = rig.env(policy);
        let (sio, cio) = spawn_channels(8);
        with_cat(rig, cat, async { tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, Some(input), gap)) }).await
    }

    async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(LIMIT, f).await.expect("the test ran past its limit")
    }

    // ---- the tests -----------------------------------------------------------------------

    /// tests/fixtures/wire/exec-golden.jsonl from both ends: the client's
    /// frames equal the golden Mac lines (between two VM lines in any order;
    /// the spawn id and the host substituted), and the golden VM lines bring
    /// the bytes and the exit.
    #[tokio::test]
    async fn the_golden_conversation_both_directions() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.target.session_token = Secret::new("golden-session-token".into());
            let (sio, cio) = spawn_channels(8);
            let golden_id = "0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192";
            let host = format!("\"host\":{}", serde_json::to_string(&crate::bridge::vm::owner()).unwrap());
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let mut id = String::new();
                let mut want: Vec<String> = Vec::new();
                let check = |want: &mut Vec<String>, got: Vec<String>| {
                    let mut got = got;
                    got.sort();
                    want.sort();
                    assert_eq!(&got, want);
                    want.clear();
                };
                for line in include_str!("../../../tests/fixtures/wire/exec-golden.jsonl").lines() {
                    let raw = line.split_once(",\"frame\":").and_then(|(_, f)| f.strip_suffix('}')).unwrap();
                    if line.starts_with("{\"dir\":\"mac\"") {
                        want.push(raw.to_string());
                        continue;
                    }
                    let mut got = Vec::new();
                    while got.len() < want.len() {
                        let Message::Text(t) = ws.next().await.unwrap().unwrap() else { continue };
                        if let Ok(Frame::Spawn { spawn_id, .. }) = Frame::from_json(t.as_str()) {
                            id = spawn_id.0;
                        }
                        let mut text = t.as_str().replace(&host, "\"host\":\"mike@mbp\"");
                        if !id.is_empty() {
                            text = text.replace(&id, golden_id);
                        }
                        got.push(text);
                    }
                    check(&mut want, got);
                    ws.send(Message::text(raw.replace(golden_id, &id))).await.unwrap();
                }
                let mut got = Vec::new();
                while got.len() < want.len() {
                    if let Message::Text(t) = ws.next().await.unwrap().unwrap() {
                        got.push(t.as_str().replace(&id, golden_id));
                    }
                }
                check(&mut want, got);
                assert!(matches!(ws.next().await, Some(Ok(Message::Close(Some(f)))) if f.code == CloseCode::from(CLOSE_NORMAL)), "closed 1000 after the final ack");
            };
            let consumer = async {
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                input.send(SpawnInput::Stdin(b"hello\n".to_vec())).await.unwrap();
                input.send(SpawnInput::Stdin(b"\x00\xff\n".to_vec())).await.unwrap();
                let mut seen = Seen::default();
                while let Some(ev) = events.recv().await {
                    match ev {
                        // Mark only once both chunks are in, after stdin's EOF (the golden order).
                        SpawnEvent::Stdout { seq, bytes } => {
                            seen.stdout.extend(bytes);
                            if seq == 2 {
                                input.send(SpawnInput::StdinEof).await.unwrap();
                                consumed.stdout_done(2);
                            }
                        }
                        other => seen.add(other, &consumed),
                    }
                }
                seen
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            let out = result.unwrap();
            assert_eq!((out.exit.status(), out.spawn_id.is_v7()), (0, true));
            assert_eq!(seen.stdout, b"hello\n\x00\xff\n");
            assert_eq!((seen.started, seen.exit.map(|e| e.code)), (Some((4242, 4242)), Some(Some(0))));
        })
        .await;
    }

    #[tokio::test]
    async fn a_cut_mid_stream_reattaches_resends_stdin_above_in_seq_and_dedupes_stdout() {
        bounded(async {
            let rig = rig(true).await;
            // Socket 1 holds stdin 1..8 but acks only 1..4: the resend starts above in_seq 8, not above the last ack.
            let cat = Cat::new(CatScript { cut: Some((1, 9)), replay_all: true, ack_upto: Some((1, 4)), ..CatScript::default() });
            let input = lines(30);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat(), "every byte once, in order");
            assert_eq!(seen.out_seqs, (1..=30).collect::<Vec<u64>>(), "no seq twice, none skipped");
            assert_eq!(seen.started, Some((4242, 4242)), "one spawn, one pid");
            let c = cat.lock().unwrap();
            let on_2: Vec<u64> = c.stdin.iter().filter(|(n, _)| *n == 2).map(|(_, s)| *s).collect();
            assert_eq!(on_2.first(), Some(&9), "the resend starts above in_seq 8: {on_2:?}");
            assert!(on_2.windows(2).all(|w| w[1] == w[0] + 1), "{on_2:?}");
            assert_eq!(c.hellos.len(), 2);
            assert!(c.hellos[1].1[0].from_seq.is_some_and(|f| (2..=9).contains(&f)), "{:?}", c.hellos[1].1);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection")) && seen.notes.iter().any(|n| n.starts_with("reattached to spawn")), "{:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "the link went down, then up");
            let rows = rig.audit("agent_reconnect");
            assert_eq!(rows.len(), 1);
            assert!(rows[0]["detail"]["ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()));
        })
        .await;
    }

    #[tokio::test]
    async fn token_rejected_twice_remints_once_then_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..2 {
                rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
            }
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::TokenRejected { port: 8080, status: 403, proxy_error: Some(p) } if p == "UNAUTHORIZED"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 2, "the first token and exactly one re-mint");
            assert_eq!(rig.endpoint.attempts().len(), 2);
            assert_eq!(rig.audit("agent_remint").len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_waits_its_retry_after_and_never_remints() {
        bounded(async {
            let rig = rig(true).await;
            rig.endpoint.refuse(refusal(429, &[("retry-after", "2")], ""));
            let mut p = policy();
            // One second of Retry-After is one backoff_min: 2 → 200 ms, the backoff alone ≤ 125 ms.
            p.backoff_min = Duration::from_millis(100);
            p.backoff_max = Duration::from_millis(400);
            let cat = Cat::new(CatScript::default());
            let (result, seen) = cat_session(&rig, &cat, p, lines(3), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, lines(3).concat());
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![429, 101]);
            assert!(a[1].at - a[0].at >= Duration::from_millis(200), "waited {:?}", a[1].at - a[0].at);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 1, "a 429 never re-mints");
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["detail"]["retry_after"], "2");
            assert!(rows[0]["detail"]["waited_ms"].as_str().unwrap().parse::<u64>().unwrap() >= 200);
            assert!(seen.notes.iter().any(|n| n.contains("HTTP 429")), "{:?}", seen.notes);
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_without_retry_after_backs_off_exponentially() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..3 {
                rig.endpoint.refuse(refusal(429, &[], ""));
            }
            let mut p = policy();
            p.backoff_min = Duration::from_millis(200);
            p.backoff_max = Duration::from_secs(4);
            let cat = Cat::new(CatScript::default());
            let (result, _) = cat_session(&rig, &cat, p, lines(2), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![429, 429, 429, 101]);
            // 200, 400, 800 ms, each ±25 %: the steps double. The third wait is at
            // least twice the first (its floor 600 ms, the first's ceiling 250 ms),
            // which no constant step is, jittered or not; 100 ms of slack for load.
            let gaps: Vec<Duration> = a.windows(2).map(|w| w[1].at - w[0].at).collect();
            assert!(gaps[0] >= Duration::from_millis(150) && gaps[0] < Duration::from_millis(600) && gaps[1] >= Duration::from_millis(300) && gaps[2] >= Duration::from_millis(600) && gaps[2] >= gaps[0] * 2, "{gaps:?}");
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 1, "a 429 never re-mints");
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 3);
            assert!(rows.iter().all(|r| r["detail"]["retry_after"] == "none"));
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_past_the_budget_is_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..100 {
                rig.endpoint.refuse(refusal(429, &[("retry-after", "1")], ""));
            }
            let mut p = policy();
            p.reconnect_budget = Duration::from_millis(300);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::EndpointThrottled { retry_after_s: Some(1) }), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        })
        .await;
    }

    /// The 429 that ends the session has its `endpoint_429` row: it is
    /// written as the 429 is classified, before the budget is checked.
    #[tokio::test]
    async fn a_429_past_the_budget_is_audited_before_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            // Retry-After 1000: 10 s at this policy, past its 5 s budget at once.
            rig.endpoint.refuse(refusal(429, &[("retry-after", "1000")], ""));
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::EndpointThrottled { retry_after_s: Some(1000) }), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![429]);
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!((rows[0]["detail"]["retry_after"].as_str(), rows[0]["detail"]["waited_ms"].as_str()), (Some("1000"), Some("10000")), "the wait it set");
        })
        .await;
    }

    /// A detach during a 429's wait ends the session there, and the 429 was audited already.
    #[tokio::test]
    async fn a_detach_during_a_429_wait_leaves_its_audit_row() {
        bounded(async {
            let rig = rig(true).await;
            // Retry-After 300: a 3 s wait at this policy, within its budget.
            rig.endpoint.refuse(refusal(429, &[("retry-after", "300")], ""));
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let consumer = async {
                let ConsumerIo { input: _input, control, mut events, consumed: _c } = cio;
                // The note comes as the wait starts.
                while let Some(ev) = events.recv().await {
                    if matches!(&ev, SpawnEvent::Note(n) if n.contains("HTTP 429")) {
                        control.send(SpawnInput::Detach { is_final: true }).unwrap();
                    }
                }
            };
            let started = Instant::now();
            let (result, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
            assert!(started.elapsed() < Duration::from_secs(2), "the detach cut the 3 s wait short: {:?}", started.elapsed());
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["detail"]["retry_after"], "300");
        })
        .await;
    }

    /// A detach while the dial or the hello is under way ends the session
    /// there (`watching`): at once — not after the dial's 60 s or the hello's
    /// `dead_after` — and no `spawn` goes out.
    #[tokio::test]
    async fn a_detach_during_the_dial_or_the_hello_ends_the_session_at_once() {
        bounded(async {
            let rig = rig(true).await;
            {
                // The dial: a loopback listener takes the connection and never answers the upgrade.
                let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut env = rig.env(policy());
                env.dial = AgentDial { local: Some(silent.local_addr().unwrap()) };
                let (sio, cio) = spawn_channels(8);
                let session = run_spawn(&env, Start::New(cat_spec()), sio);
                tokio::pin!(session);
                let _held = tokio::select! {
                    tcp = silent.accept() => tcp.unwrap(),
                    r = &mut session => panic!("the session ended before its dial: {:?}", r.err()),
                };
                cio.control.send(SpawnInput::Detach { is_final: true }).unwrap();
                let e = tokio::time::timeout(Duration::from_secs(2), &mut session).await.expect("the detach ended the dial at once").unwrap_err();
                assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
            }
            {
                // The hello: the endpoint upgrades; the shim reads the hello and never answers it.
                let env = rig.env(policy());
                let (sio, cio) = spawn_channels(8);
                let session = run_spawn(&env, Start::New(cat_spec()), sio);
                tokio::pin!(session);
                let mut ws = tokio::select! {
                    ws = rig.endpoint.next() => ws,
                    r = &mut session => panic!("the session ended before its hello: {:?}", r.err()),
                };
                let hello = tokio::select! {
                    f = frame(&mut ws) => f,
                    r = &mut session => panic!("the session ended before its hello: {:?}", r.err()),
                };
                assert!(matches!(hello, Frame::Hello { .. }), "{hello:?}");
                cio.control.send(SpawnInput::Detach { is_final: true }).unwrap();
                let e = tokio::time::timeout(Duration::from_secs(2), &mut session).await.expect("the detach ended the hello at once").unwrap_err();
                assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
                while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_millis(200), ws.next()).await {
                    if let Message::Text(t) = m {
                        assert!(!matches!(Frame::from_json(t.as_str()), Ok(Frame::Spawn { .. })), "a spawn went out after the detach");
                    }
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn not_run_is_retried_then_succeeds() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..2 {
                rig.endpoint.refuse(refusal(503, &[("retry-after", "1"), ("content-type", "application/json")], r#"{"status":"not_run"}"#));
            }
            let cat = Cat::new(CatScript::default());
            let (result, seen) = cat_session(&rig, &cat, policy(), lines(2), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, lines(2).concat());
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![503, 503, 101]);
        })
        .await;
    }

    #[tokio::test]
    async fn not_run_past_its_budget_is_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..200 {
                rig.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            }
            let mut p = policy();
            p.not_run_budget = Duration::from_millis(200);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("not_run")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// The VM is suspended under the session (no hook event seen) and has no
    /// auto-resume: the redial gets 502, GetMicrovm says SUSPENDED, one
    /// ResumeMicrovm, then the spawn is reattached.
    #[tokio::test]
    async fn gateway_with_a_suspended_vm_resumes_it_once_then_reattaches() {
        bounded(async {
            let rig = rig(false).await;
            let cat = Cat::new(CatScript { cut: Some((1, 5)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Suspended)));
            let input = lines(12);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 1, "exactly one ResumeMicrovm");
            let statuses: Vec<u16> = rig.endpoint.attempts().iter().map(|a| a.status).collect();
            assert!(statuses.contains(&502) && statuses.last() == Some(&101), "{statuses:?}");
            assert!(seen.notes.iter().any(|n| n.contains("resuming it")), "{:?}", seen.notes);
        })
        .await;
    }

    /// ResumeMicrovm answers Conflict (someone else is resuming it): fine; the VM turns RUNNING meanwhile.
    #[tokio::test]
    async fn a_resume_conflict_is_a_resume_under_way() {
        bounded(async {
            let rig = rig(false).await;
            rig.api.fail_on("resume", BridgeError::Conflict("resume already in progress".into()), false);
            let cat = Cat::new(CatScript { cut: Some((1, 4)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || {
                api.set_state(&id, VmState::Suspended);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    api.set_state(&id, VmState::Running);
                });
            }));
            let input = lines(8);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 1, "one resume, its Conflict tolerated");
        })
        .await;
    }

    #[tokio::test]
    async fn hook_suspend_never_redials_until_the_vm_runs_again() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                rig.api.set_state(&rig.vm.id, VmState::Suspended);
                put(&mut ws, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
                tokio::time::sleep(Duration::from_millis(400)).await;
                assert_eq!(rig.endpoint.attempts().len(), 1, "no dial while the VM is suspended");
                assert!(rig.calls(|c| matches!(c, Call::Get(_))) >= 3, "it polls GetMicrovm instead");
                assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "it never resumes the VM itself");
                rig.api.set_state(&rig.vm.id, VmState::Running);
                let mut ws = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) }]);
                put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 1, code: Some(3), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 3);
            assert!(seen.notes.iter().any(|n| n.contains("was suspended")), "{:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "down while suspended, up once reattached");
        })
        .await;
    }

    #[tokio::test]
    async fn hook_suspend_gives_up_after_suspend_wait_naming_resume_and_attach() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.suspend_wait = Duration::from_millis(200);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                rig.api.set_state(&rig.vm.id, VmState::Suspended);
                put(&mut ws, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
                id
            };
            let (result, _, id) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            let text = e.to_string();
            let vm = &rig.vm.id;
            assert!(text.contains(&format!("ai-env vm resume {vm}")) && text.contains(&format!("ai-env vm attach {vm} --spawn {id}")), "{text}");
            // S10: `vm exec`'s policy (no park control): `StayedSuspended`, the one loss the pump never moves.
            assert!(matches!(e, BridgeError::StayedSuspended(_)), "{e:?}");
            assert_eq!(crate::bridge::remote::link::LossCause::of(&e), crate::bridge::remote::link::LossCause::Suspended);
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(rig.endpoint.attempts().len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn hook_terminate_is_terminated() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                start_spawn(&mut ws).await;
                put(&mut ws, &Frame::Event { kind: EventKind::HookTerminate, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            // S10: `vm exec` exits 8 on it; a wrapper's pump moves the chat to a new VM (`VmGone`).
            assert_eq!(crate::bridge::remote::link::LossCause::of(&e), crate::bridge::remote::link::LossCause::VmGone);
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    #[tokio::test]
    async fn hello_err_bad_token_is_refused_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &Frame::HelloErr { code: HelloErrCode::BadToken, message: "the token does not match this VM".into() }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_HELLO_REFUSED), reason: "bad_token".into() })).await.unwrap();
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::HelloRefused { code, .. } if code == "bad_token"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(rig.endpoint.attempts().len(), 1, "a refused hello is never retried");
        })
        .await;
    }

    /// A `--shell` row's target gets no session, whoever the caller (D1):
    /// a new spawn and a reattach are refused before anything reaches the VM
    /// (no mint, no GetMicrovm, no dial) with a policy error (exit 9) naming
    /// the unguarded platform shell and in-vm-firewall.
    #[tokio::test]
    async fn a_shell_rows_target_is_refused_before_any_mint_or_dial() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.target.shell = true;
            let before = rig.api.calls().len();
            for start in [Start::New(cat_spec()), Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None }] {
                let (sio, cio) = spawn_channels(8);
                let (result, seen) = tokio::join!(run_spawn(&env, start, sio), consume(cio, None, Duration::ZERO));
                let e = result.unwrap_err();
                let says = format!("{} was started with --shell: no command runs on it until the platform shell's in-VM listener, which the shim does not guard, is shown unreachable from the agent (ai-env lab run in-vm-firewall measures it)", rig.vm.id);
                assert!(matches!(&e, BridgeError::Policy(m) if m.starts_with(&says)), "{e}");
                assert_eq!(CliError::from(e).exit_code(), 9);
                assert!(seen.notes.is_empty() && seen.started.is_none(), "{seen:?}");
            }
            assert_eq!(rig.api.calls().len(), before, "nothing reached the API: {:?}", rig.api.calls());
            assert!(rig.endpoint.attempts().is_empty(), "no dial: {:?}", rig.endpoint.attempts());
        })
        .await;
    }

    #[tokio::test]
    async fn a_silent_socket_is_dead_after_dead_after_and_replaced() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { silent: Some(1), ..CatScript::default() });
            let mut p = policy();
            p.ping = Duration::from_millis(50);
            p.ws_ping = Duration::from_millis(50);
            p.dead_after = Duration::from_millis(300);
            let input = lines(10);
            let (result, seen) = cat_session(&rig, &cat, p, input.clone(), Duration::from_millis(20)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert!(seen.notes.iter().any(|n| n.contains("no frame for")), "{:?}", seen.notes);
            assert_eq!(cat.lock().unwrap().hellos.len(), 2);
        })
        .await;
    }

    /// A one-minute token with rotation 59 s before its expiry: within a
    /// second a second socket says hello with the resume, the first is closed
    /// 1000, and the stream goes on without a byte lost or doubled.
    #[tokio::test]
    async fn proactive_rotation_moves_the_spawn_to_a_second_socket() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let input = lines(60);
            let (result, seen) = cat_session(&rig, &cat, rotation_policy(), input.clone(), Duration::from_millis(25)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat(), "no output lost or doubled");
            assert_eq!(seen.out_seqs, (1..=60).collect::<Vec<u64>>());
            let c = cat.lock().unwrap();
            assert!(c.hellos.len() >= 2, "a second socket said hello");
            assert!(c.hellos[1].1.first().is_some_and(|r| Some(&r.spawn_id) == c.spawn.as_ref()), "with the resume");
            assert!(c.closes.contains(&(1, Some(CLOSE_NORMAL))), "the first socket was closed 1000: {:?}", c.closes);
            drop(c);
            assert!(rig.audit("agent_rotate").iter().all(|r| r["detail"]["mode"] == "proactive") && !rig.audit("agent_rotate").is_empty());
            assert!(rig.calls(|c| matches!(c, Call::Token { minutes: 1, .. })) >= 2);
            assert!(rig.endpoint.attempts().iter().all(|a| a.status == 101));
            assert!(seen.notes.iter().any(|n| n.starts_with("rotated to a fresh endpoint token")), "{:?}", seen.notes);
        })
        .await;
    }

    /// The first socket is lost while the rotation's socket still waits for
    /// its hello_ok: the reconnect's socket carries the spawn at once (the
    /// stdin queued meanwhile goes out on it, before any further rotation).
    #[tokio::test]
    async fn a_socket_lost_during_a_rotation_reconnects_unpaused() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { mute: Some(2), cut_on_ping: Some(1), ..CatScript::default() });
            let mut p = rotation_policy();
            p.ping = Duration::from_millis(100);
            let input = lines(80);
            let (result, seen) = cat_session(&rig, &cat, p, input.clone(), Duration::from_millis(25)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            let c = cat.lock().unwrap();
            let sockets: Vec<usize> = c.hellos.iter().map(|(n, _)| *n).collect();
            assert!(c.muted && sockets.contains(&3), "the third socket took over: {sockets:?}");
            assert!(c.stdin.iter().any(|(n, _)| *n == 3), "stdin flowed on the reconnected socket: {:?}", c.stdin);
        })
        .await;
    }

    #[tokio::test]
    async fn acks_carry_only_what_the_consumer_marked() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (mark_tx, mut mark_rx) = mpsc::unbounded_channel::<u64>();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                for (seq, text) in [(1, "a"), (2, "b"), (3, "c")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                assert!(tokio::time::timeout(Duration::from_millis(150), frame(&mut ws)).await.is_err(), "nothing is acked before the consumer marks it");
                mark_tx.send(2).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 2, err_seq: 0 });
                mark_tx.send(3).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 3, err_seq: 0 });
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 4, data: Chunk { text: Some("d".into()), b64: None } }).await;
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 5, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                assert!(tokio::time::timeout(Duration::from_millis(150), frame(&mut ws)).await.is_err(), "the exit waits for the last chunk's mark");
                mark_tx.send(4).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 5, err_seq: 0 }, "the exit's seq releases the spawn");
            };
            let consumer = async {
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let mut out = Vec::new();
                loop {
                    tokio::select! {
                        ev = events.recv() => match ev {
                            Some(SpawnEvent::Stdout { bytes, .. }) => out.extend(bytes),
                            Some(_) => {}
                            None => return out,
                        },
                        Some(seq) = mark_rx.recv() => consumed.stdout_done(seq),
                    }
                }
            };
            let (result, out, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(out, b"abcd");
        })
        .await;
    }

    /// The byte cadence: once `ack_bytes` are consumed the ack goes out at
    /// once, without waiting for the timer (an hour away here; the tick's
    /// other bounds are 15 s, and its immediate first tick is long past).
    #[tokio::test]
    async fn consuming_ack_bytes_acks_at_once_without_the_timer() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.ack_bytes = 8;
            p.ack_every = Duration::from_secs(3600);
            p.dead_after = Duration::from_secs(60);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                // Past the interval's first tick (it fires at once): only the bytes can ack now.
                tokio::time::sleep(Duration::from_millis(200)).await;
                for (seq, text) in [(1, "abcd"), (2, "efgh")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                let ack = tokio::time::timeout(Duration::from_secs(2), frame(&mut ws)).await.expect("8 bytes consumed: acked at once, not at the next tick");
                assert_eq!(ack, Frame::Ack { spawn_id: id.clone(), seq: 2, err_seq: 0 }, "4 bytes alone are no ack");
                put(&mut ws, &exit0(&id, 3)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 3, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"abcdefgh");
        })
        .await;
    }

    /// The time cadence: what the consumer marked is acked within
    /// `ack_every` (10 ms here) however few bytes it is, not at the tick's
    /// other bounds (pings an hour away, dead_after / 4 = 15 s).
    #[tokio::test]
    async fn a_mark_below_ack_bytes_is_acked_within_ack_every() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.dead_after = Duration::from_secs(60);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("a".into()), b64: None } }).await;
                let ack = tokio::time::timeout(Duration::from_secs(2), frame(&mut ws)).await.expect("acked within ack_every, not at a 15 s tick");
                assert_eq!(ack, Frame::Ack { spawn_id: id.clone(), seq: 1, err_seq: 0 });
                put(&mut ws, &exit0(&id, 2)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 2, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"a");
        })
        .await;
    }

    #[tokio::test]
    async fn keep_alive_gets_health_while_the_spawn_runs() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let mut p = policy();
            p.keepalive = Keepalive::Http;
            p.keepalive_every = Duration::from_millis(30);
            let (result, _) = cat_session(&rig, &cat, p, lines(20), Duration::from_millis(10)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(rig.calls(|c| matches!(c, Call::Health { port: 8080, .. })) >= 2, "{:?}", rig.api.calls());
        })
        .await;
    }

    #[tokio::test]
    async fn a_detach_goes_out_and_ends_the_session() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let consumer = async {
                let ConsumerIo { input, control, mut events, consumed: _c } = cio;
                input.send(SpawnInput::Stdin(b"x\n".to_vec())).await.unwrap();
                while let Some(ev) = events.recv().await {
                    if matches!(ev, SpawnEvent::Stdout { .. }) {
                        control.send(SpawnInput::Detach { is_final: true }).unwrap();
                    }
                }
            };
            let (result, ()) = with_cat(&rig, &cat, async { tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer) }).await;
            let e = result.unwrap_err();
            assert!(e.to_string().contains("detached from spawn"), "{e}");
            assert_eq!(cat.lock().unwrap().detach, Some(true));
        })
        .await;
    }

    #[tokio::test]
    async fn no_connection_to_a_running_vm_gives_up_after_the_budget() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.dial = AgentDial { local: Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()) };
            env.policy.reconnect_budget = Duration::from_millis(300);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("connect")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert!(rig.calls(|c| matches!(c, Call::Get(_))) >= 2, "each failed dial asks GetMicrovm");
        })
        .await;
    }

    #[tokio::test]
    async fn a_terminated_vm_ends_the_reconnect() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { cut: Some((1, 3)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Terminated)));
            let (result, _) = cat_session(&rig, &cat, policy(), lines(5), Duration::from_millis(2)).await;
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            // S10: a wrapper's pump moves the chat to a new VM (`VmGone`); `vm exec` exits 8.
            assert_eq!(crate::bridge::remote::link::LossCause::of(&e), crate::bridge::remote::link::LossCause::VmGone);
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// A VM back in PENDING (502 from the proxy) gets 60 of the policy's seconds, then exit 8.
    #[tokio::test]
    async fn a_vm_that_stays_pending_is_given_up_on() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { cut: Some((1, 3)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Pending)));
            let started = Instant::now();
            let (result, _) = cat_session(&rig, &cat, policy(), lines(5), Duration::from_millis(2)).await;
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("still PENDING")), "{e}");
            assert!(started.elapsed() >= Duration::from_millis(600), "60 × backoff_min");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    #[tokio::test]
    async fn spawn_err_names_its_code() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("no spawn") };
                put(&mut ws, &Frame::SpawnErr { spawn_id, code: crate::wire::frame::SpawnErrCode::Cwd, message: "cannot create the working directory".into() }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::SpawnRefused { code: "cwd", message } if message.contains("working directory")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 1, "the command could not start: the operator's to fix, not a lost VM");
        })
        .await;
    }

    /// The codes the operator cannot act on stay protocol errors (exit 8).
    #[tokio::test]
    async fn spawn_err_of_the_shims_own_making_is_a_protocol_error() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("no spawn") };
                put(&mut ws, &Frame::SpawnErr { spawn_id, code: crate::wire::frame::SpawnErrCode::Exists, message: "the spawn id is in use".into() }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Protocol(m) if m.contains("(exists)")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// The socket is lost after `spawn` went out and before `spawned` came
    /// back, and the shim released the spawn meanwhile: the resume answers
    /// `unknown`, the spawn goes out again (the note says so, not "reattached"),
    /// and the shim refuses its used id (`spawn_err exists`). The session ends
    /// with exit 8 naming `vm attach` — it never waits for a second `spawned`,
    /// nor sends a third `spawn`.
    #[tokio::test]
    async fn a_resent_spawn_whose_id_the_shim_used_is_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws1).await, Frame::Hello { .. }));
                put(&mut ws1, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id: id, .. } = frame(&mut ws1).await else { panic!("no spawn") };
                // Cut (no Close) before `spawned`.
                drop(ws1);
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) }]);
                put(&mut ws2, &hello_ok(vec![], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws2).await else { panic!("the spawn did not go out again") };
                assert_eq!(spawn_id, id, "the same id");
                put(&mut ws2, &Frame::SpawnErr { spawn_id: id.clone(), code: SpawnErrCode::Exists, message: format!("spawn {id} was already started") }).await;
                while let Ok(Some(Ok(m))) = tokio::time::timeout(LIMIT, ws2.next()).await {
                    if let Message::Text(t) = m {
                        assert!(!matches!(Frame::from_json(t.as_str()), Ok(Frame::Spawn { .. })), "a third spawn");
                    }
                }
                id
            };
            let (result, seen, id) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            let vm = &rig.vm.id;
            let says = format!("spawn {id} reached {vm} before the connection was lost: it ran, or still runs, without this client and was not started again (`ai-env vm attach {vm} --spawn {id}` reattaches to it while it runs)");
            assert!(matches!(&e, BridgeError::Transport(m) if *m == says), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(seen.started, None, "the spawn never started for this client");
            assert_eq!(rig.endpoint.attempts().len(), 2, "no third socket");
            // Socket numbers are the process's (tests run side by side): any.
            let again = format!("sent spawn {id} again after ");
            assert!(seen.notes.iter().any(|n| n.starts_with(&again) && n.contains(" ms (socket ") && n.ends_with("): the VM did not hold it")), "{:?}", seen.notes);
            assert!(!seen.notes.iter().any(|n| n.starts_with("reattached")), "nothing was reattached: {:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "down at the loss, up once the spawn went out again");
            assert_eq!(rig.audit("agent_reconnect").len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn attach_continues_the_shims_stdin_numbering_and_replays_from_the_asked_seq() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None }]);
                put(&mut ws, &hello_ok(vec![status(&id, 6, 40)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                for (seq, text) in [(4, "old"), (5, "five"), (6, "six")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                // Acks of the replayed chunks may come first.
                let seq = loop {
                    match frame(&mut ws).await {
                        Frame::Stdin { seq, .. } => break seq,
                        Frame::Ack { .. } => {}
                        other => panic!("expected stdin, got {other:?}"),
                    }
                };
                assert_eq!(seq, 41, "a second client's stdin continues after the shim's in_seq");
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 7, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                loop {
                    if let Frame::Ack { seq: 7, .. } = frame(&mut ws).await {
                        break;
                    }
                }
            };
            let consumer = consume(cio, Some(vec![b"more\n".to_vec()]), Duration::ZERO);
            let start = Start::Attach { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, start, sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"fivesix", "nothing below the asked seq");
            assert_eq!(seen.started, Some((4242, 4242)));
        })
        .await;
    }

    /// `vm attach`: input typed while the first dial is retried waits for
    /// the first hello_ok, then continues the shim's numbering (after its
    /// in_seq 40), its EOF too; nothing is numbered from 1 and then taken for
    /// stdin the shim already holds.
    #[tokio::test]
    async fn attach_takes_input_only_once_the_first_hello_ok_fixed_its_numbering() {
        bounded(async {
            let rig = rig(true).await;
            rig.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            let mut p = policy();
            p.backoff_min = Duration::from_millis(300);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![status(&id, 0, 40)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                let Frame::Stdin { seq, data, .. } = frame(&mut ws).await else { panic!("the input typed during the retry never came") };
                assert_eq!((seq, decode(&data).unwrap()), (41, b"typed during the retry\n".to_vec()), "it continues after in_seq 40");
                assert_eq!(frame(&mut ws).await, Frame::StdinEof { spawn_id: id.clone(), seq: 41 });
                put(&mut ws, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 1, err_seq: 0 });
            };
            let start = Start::Attach { spawn_id: id.clone(), from_seq: None, err_from_seq: None };
            let consumer = consume(cio, Some(vec![b"typed during the retry\n".to_vec()]), Duration::ZERO);
            let (result, _, ()) = tokio::join!(run_spawn(&env, start, sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![503, 101]);
        })
        .await;
    }

    /// `vm attach --from-seq 5` to a spawn that exits at seq 5: nothing was
    /// delivered, so nothing waits for marks; the exit's seq is acked at once.
    #[tokio::test]
    async fn an_attach_that_delivered_nothing_acks_the_exit_at_once() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.dead_after = Duration::from_secs(3);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![status(&id, 4, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws, &exit0(&id, 5)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 5, err_seq: 0 }, "the exit's seq releases the spawn");
            };
            let started = Instant::now();
            let start = Start::Attach { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None };
            let (result, _, ()) = tokio::join!(run_spawn(&env, start, sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(started.elapsed() < Duration::from_secs(2), "it waited {:?} for marks of output it never delivered", started.elapsed());
        })
        .await;
    }

    /// A send that fails mid-flush leaves what is still queued (a signal, the
    /// detach) for the next socket, which sends it: nothing is popped into a
    /// dead link, and the detach is not taken for sent.
    #[tokio::test]
    async fn a_failed_send_keeps_the_signals_and_the_detach_for_the_next_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            (s.st.phase, s.attached) = (Phase::Running, true);
            let (mut dead, _ws1) = link_to(&rig, &s).await;
            // After its Close every send on it fails.
            dead.tx.close(CLOSE_NORMAL).await;
            s.st.take(SpawnInput::Stdin(b"a\n".to_vec()));
            s.st.take(SpawnInput::Signal(Sig::Int));
            s.st.take(SpawnInput::Detach { is_final: true });
            s.flush(&mut dead).await;
            assert!(dead.broken.is_some());
            assert_eq!((Vec::from(s.st.signals.clone()), s.st.detach, s.st.detach_sent), (vec![Sig::Int], Some(true), false), "nothing left its queue");
            let (mut live, mut ws2) = link_to(&rig, &s).await;
            s.st.reattached(None);
            s.flush(&mut live).await;
            let id = s.st.id.clone();
            assert!(matches!(frame(&mut ws2).await, Frame::Stdin { seq: 1, .. }));
            assert_eq!(frame(&mut ws2).await, Frame::Signal { spawn_id: id.clone(), sig: Sig::Int, scope: Scope::Group });
            assert_eq!(frame(&mut ws2).await, Frame::Detach { spawn_id: id, is_final: true });
            assert!(s.st.signals.is_empty() && s.st.detach.is_none() && s.st.detach_sent);
        })
        .await;
    }

    /// The rotation's socket dies after its hello reached the shim (which
    /// moved the spawn to it), and the old socket hears `superseded` only
    /// later: the session reconnects with the resume instead of staying on a
    /// socket that no longer carries the spawn.
    #[tokio::test]
    async fn a_rotation_hello_without_an_answer_reconnects() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = rotation_policy();
            // Another attempt from the first socket would come only after this.
            p.backoff_max = Duration::from_secs(5);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello on the rotation's socket") };
                assert_eq!(resume[0].spawn_id, id);
                drop(ws2);
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = ws1.send(Message::from(&Frame::error(ErrorCode::Superseded, "a newer connection attached this spawn", Some(id.clone())))).await;
                let mut ws3 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws3).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the reconnect resumes the spawn");
                put(&mut ws3, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws3, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws3).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("rotation")), "{:?}", seen.notes);
        })
        .await;
    }

    /// A rotation does not restart the stability clock: the spawn was carried
    /// without a break, so losing the rotation's socket within `stable_after`
    /// of it — with the session older than its reconnect budget — starts a
    /// fresh reconnect episode: the session redials and finishes.
    #[tokio::test]
    async fn a_loss_soon_after_a_rotation_still_redials() {
        bounded(async {
            let rig = rig(true).await;
            // The rotation comes 1–2 s in (58 s before the expiry of a token the
            // fake stamps in whole seconds), past the budget; the cut 300 ms after
            // it, when the spawn was carried past `stable_after` but the rotation's socket was not.
            let p = RunPolicy { rotate_before: Duration::from_secs(58), stable_after: Duration::from_millis(800), reconnect_budget: Duration::from_millis(900), ..rotation_policy() };
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello on the rotation's socket") };
                assert_eq!(resume[0].spawn_id, id);
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                // Cut, no Close.
                drop(ws2);
                let mut ws3 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws3).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                put(&mut ws3, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws3, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws3).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                ws1
            };
            let (result, seen, _ws1) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            let rotated = seen.notes.iter().position(|n| n.starts_with("rotated to a fresh endpoint token"));
            let lost = seen.notes.iter().position(|n| n.starts_with("lost the connection"));
            assert!(rotated.is_some_and(|r| lost.is_some_and(|l| r < l)), "rotated, then lost: {:?}", seen.notes);
            assert_eq!(rig.endpoint.attempts().len(), 3, "the redial was the third socket");
        })
        .await;
    }

    /// The other side of the stability clock: a socket lost within
    /// `stable_after` of taking the spawn starts no fresh reconnect episode,
    /// so the budget runs on from the first dial across every such socket;
    /// once it is spent the session gives up (exit 8) instead of redialing for ever.
    #[tokio::test]
    async fn sockets_lost_within_stable_after_spend_one_reconnect_budget() {
        bounded(async {
            let rig = rig(true).await;
            let p = RunPolicy { stable_after: Duration::from_secs(1), reconnect_budget: Duration::from_millis(500), backoff_max: Duration::from_millis(40), ..policy() };
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            // Each socket is cut (no Close) 20 ms after it took the spawn; the next one resumes it.
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                loop {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    drop(ws);
                    ws = rig.endpoint.next().await;
                    let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                }
            };
            let started = Instant::now();
            // A session that redials for ever never ends this.
            let session = async { tokio::join!(tokio::time::timeout(Duration::from_secs(5), run_spawn(&env, Start::New(cat_spec()), sio)), consume(cio, None, Duration::ZERO)) };
            let (result, seen) = tokio::select! {
                out = session => out,
                () = shim => unreachable!("the shim serves every socket"),
            };
            let e = result.expect("the session gave up once its reconnect budget was spent").unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("no lasting /agent connection")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            // The budget less the last wait (at most 1.25 × backoff_max).
            assert!(started.elapsed() >= Duration::from_millis(450), "it gave up before the budget was spent: {:?}", started.elapsed());
            let sockets = rig.endpoint.attempts().len();
            assert!(sockets >= 3, "the lost sockets were replaced within the budget: {sockets}");
            assert_eq!(seen.notes.iter().filter(|n| n.starts_with("reattached to spawn")).count(), sockets - 1, "{:?}", seen.notes);
        })
        .await;
    }

    /// The rotation's dials follow the reconnect rules: a 429 waits its
    /// Retry-After, is audited and keeps the token; a 403 spends the one
    /// re-mint; the third dial carries the spawn on.
    #[tokio::test]
    async fn rotation_dials_follow_the_429_and_403_rules() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = rotation_policy();
            // Retry-After 2 → 200 ms; the backoff alone stays below that.
            p.backoff_min = Duration::from_millis(100);
            p.backoff_max = Duration::from_millis(400);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                rig.endpoint.refuse(refusal(429, &[("retry-after", "2")], ""));
                rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws2).await, Frame::Hello { .. }));
                let mints = rig.calls(|c| matches!(c, Call::Token { .. }));
                put(&mut ws1, &Frame::error(ErrorCode::Superseded, "a newer connection attached this spawn", Some(id.clone()))).await;
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws2, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws2).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                (mints, ws1)
            };
            let (result, _, (mints, _ws1)) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(mints, 3, "the session's token, the rotation's (kept across the 429), the one re-mint after the 403");
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![101, 429, 403, 101]);
            assert!(a[2].at - a[1].at >= Duration::from_millis(200), "Retry-After 2 was kept: {:?}", a[2].at - a[1].at);
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["detail"]["retry_after"], "2");
            assert!(rows[0]["detail"]["waited_ms"].as_str().unwrap().parse::<u64>().unwrap() >= 200);
        })
        .await;
    }

    /// A second 401/403 on the rotation's dials stops rotating on that
    /// socket: the spawn carries on where it is.
    #[tokio::test]
    async fn a_rotation_refused_twice_stays_on_its_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(rotation_policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                for _ in 0..2 {
                    rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
                }
                let id = start_spawn(&mut ws1).await;
                while rig.endpoint.attempts().len() < 3 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                // Many backoffs long: no third dial comes.
                tokio::time::sleep(Duration::from_millis(500)).await;
                put(&mut ws1, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws1).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![101, 403, 403]);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 3, "the session's token, the rotation's, its one re-mint");
            assert!(seen.notes.iter().any(|n| n.contains("staying on socket")), "{:?}", seen.notes);
        })
        .await;
    }

    /// An expired token and a mint that fails (the network still waking
    /// after a sleep): a failed attempt within the reconnect budget, not the
    /// end of the session; past the budget the mint's own error ends it.
    #[tokio::test]
    async fn an_expired_token_whose_mint_fails_is_retried() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            s.token.expires_at_unix = 1;
            let offline = || BridgeError::Endpoint("the network is not up yet".into());
            rig.api.fail_on("token", offline(), false);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                std::future::pending::<()>().await;
            };
            let mut retry = Retry::new(&env.policy);
            let link = tokio::select! {
                link = s.connect(&mut retry) => link,
                () = shim => unreachable!(),
            };
            assert!(link.is_ok(), "{:?}", link.err());
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 3, "the session's token, the failed mint, the retried one");
            assert!(!s.token_left().is_zero());

            let mut env = rig.env(policy());
            env.policy.reconnect_budget = Duration::from_millis(200);
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            s.token.expires_at_unix = 1;
            for _ in 0..100 {
                rig.api.fail_on("token", offline(), false);
            }
            let e = s.connect(&mut Retry::new(&env.policy)).await.err().unwrap();
            assert!(matches!(&e, BridgeError::Endpoint(m) if m.contains("not up yet")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        })
        .await;
    }

    /// A re-mint that fails on a tick never ends a live socket, even with
    /// the token expired: it serves on (the next reconnect mints again).
    #[tokio::test]
    async fn a_failed_remint_never_ends_a_live_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            let (mut link, mut ws) = link_to(&rig, &s).await;
            (s.st.phase, s.attached) = (Phase::Running, true);
            s.token.expires_at_unix = 1;
            for _ in 0..100 {
                rig.api.fail_on("token", BridgeError::Endpoint("the network is not up yet".into()), false);
            }
            let id = s.st.id.clone();
            let shim = async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                put(&mut ws, &exit0(&id, 1)).await;
            };
            let (end, ()) = tokio::join!(s.serve(&mut link), shim);
            assert!(matches!(end, Ok(End::Exited(1, _))), "{:?}", end.err());
            assert!(rig.calls(|c| matches!(c, Call::Token { .. })) >= 3, "it kept trying: {:?}", rig.api.calls());
        })
        .await;
    }

    /// Token expiry is by the wall clock (Darwin's `Instant` stops while a
    /// laptop sleeps): a token the wall clock expired — two hours ahead of
    /// `Instant` here — is re-minted before the dial, never presented.
    #[tokio::test]
    async fn a_token_the_wall_clock_expired_is_reminted_before_the_dial() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            assert!(s.token_left() > Duration::from_secs(3000), "a fresh 60-minute token");
            WALL_AHEAD.with(|w| w.set(Duration::from_secs(2 * 3600)));
            let expired = s.token_left().is_zero();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                std::future::pending::<()>().await;
            };
            let mut retry = Retry::new(&env.policy);
            let link = tokio::select! {
                link = s.connect(&mut retry) => link,
                () = shim => unreachable!(),
            };
            WALL_AHEAD.with(|w| w.set(Duration::ZERO));
            assert!(expired, "the token is expired by the wall clock");
            assert!(link.is_ok(), "{:?}", link.err());
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 2, "the session's token and the re-mint the wall clock asked for");
            let rows = rig.audit("agent_remint");
            assert!(rows.len() == 1 && rows[0]["detail"]["reason"] == "expiring", "{rows:?}");
        })
        .await;
    }

    /// A laptop sleep (the wall clock ran past `dead_after` ahead of
    /// `Instant`) loses the socket at the next tick, though it still looks
    /// open: the session redials with the resume and finishes.
    #[tokio::test]
    async fn a_wall_clock_jump_past_dead_after_loses_the_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                // dead_after is 5 s; the next tick (every 10 ms) finds 6 s asleep.
                WALL_AHEAD.with(|w| w.set(Duration::from_secs(6)));
                let mut ws2 = tokio::time::timeout(Duration::from_secs(3), rig.endpoint.next()).await.expect("the jump lost the socket: a redial");
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws2, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws2).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                ws1
            };
            let (result, seen, _ws1) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("(woke after ") && n.contains(" asleep)")), "{:?}", seen.notes);
            assert_eq!(rig.endpoint.attempts().len(), 2);
        })
        .await;
    }

    /// A consumer that marks no stderr while the shim floods it: the session
    /// hands it at most STDERR_BUFFER_BYTES, drops the rest and says so in
    /// the next chunk's `dropped` and in the exit.
    #[tokio::test]
    async fn stderr_the_consumer_has_not_marked_stays_bounded() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let chunk = Chunk { text: Some("e".repeat(crate::wire::frame::CHUNK_MAX)), b64: None };
            let len = crate::wire::frame::CHUNK_MAX as u64;
            let (flood, kept) = (3 * STDERR_BUFFER_BYTES / len / 2, STDERR_BUFFER_BYTES / len);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                for seq in 1..=flood {
                    put(&mut ws, &Frame::Stderr { spawn_id: id.clone(), seq, data: chunk.clone(), dropped: 0 }).await;
                }
                // stdout after the flood: the consumer marks once it has it.
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("after\n".into()), b64: None } }).await;
                loop {
                    if let Frame::Ack { err_seq, .. } = frame(&mut ws).await {
                        if err_seq == kept {
                            break;
                        }
                    }
                }
                put(&mut ws, &Frame::Stderr { spawn_id: id.clone(), seq: flood + 1, data: Chunk { text: Some("late\n".into()), b64: None }, dropped: 0 }).await;
                put(&mut ws, &exit0(&id, 2)).await;
                loop {
                    if let Frame::Ack { seq: 2, .. } = frame(&mut ws).await {
                        break;
                    }
                }
            };
            let consumer = async {
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let (mut got, mut exit) = (Vec::new(), None);
                while let Some(ev) = events.recv().await {
                    match ev {
                        SpawnEvent::Stderr { seq, bytes, dropped } => got.push((seq, bytes.len() as u64, dropped)),
                        SpawnEvent::Stdout { seq, .. } => {
                            consumed.stderr_done(got.last().map_or(0, |g| g.0));
                            consumed.stdout_done(seq);
                        }
                        SpawnEvent::Exit(e) => {
                            exit = Some(e);
                            consumed.stderr_done(got.last().map_or(0, |g| g.0));
                        }
                        _ => {}
                    }
                }
                (got, exit)
            };
            let (result, (got, exit), ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            let lost = (flood - kept) * len;
            let seqs: Vec<u64> = got.iter().map(|g| g.0).collect();
            assert_eq!(seqs, (1..=kept).chain([flood + 1]).collect::<Vec<u64>>(), "the flood past the bound was dropped");
            assert_eq!(got.iter().take(kept as usize).map(|g| g.1).sum::<u64>(), STDERR_BUFFER_BYTES);
            assert_eq!(got.last().map(|g| g.2), Some(lost), "the next chunk counts the drop");
            assert_eq!(exit.map(|e| e.stderr_dropped), Some(lost));
        })
        .await;
    }

    #[test]
    fn stdin_never_puts_more_than_the_window_in_flight() {
        let mut st = State::new(Start::New(cat_spec()));
        let big = vec![b'a'; crate::wire::frame::CHUNK_MAX];
        let chunks = (STDIN_WINDOW_BYTES / big.len() as u64) + 3;
        for _ in 0..chunks {
            st.take(SpawnInput::Stdin(big.clone()));
        }
        assert!(!st.wants_input(), "input stops once a window is pending");
        let mut sent = 0;
        while let Some((seq, _, len)) = st.next_stdin() {
            st.sent_in = seq;
            st.inflight += len;
            sent += 1;
        }
        assert_eq!(st.inflight, STDIN_WINDOW_BYTES, "exactly the window in flight");
        assert_eq!(sent, STDIN_WINDOW_BYTES / big.len() as u64);
        st.stdin_acked(4);
        assert!(st.next_stdin().is_some(), "an ack frees room");
        assert!(st.wants_input(), "less than a window pending again");
        // A reattach that holds stdin up to 6: 7.. go again, 5 and 6 still count until acked.
        st.reattached(Some(&status(&st.id.clone(), 0, 6)));
        assert_eq!((st.sent_in, st.inflight), (6, 2 * big.len() as u64));
        assert_eq!(st.next_stdin().map(|(seq, _, _)| seq), Some(7));
    }

    #[test]
    fn stdin_eof_flushes_a_held_utf8_tail_and_later_stdin_is_dropped() {
        let mut st = State::new(Start::New(cat_spec()));
        st.take(SpawnInput::Stdin(vec![b'o', b'k', 0xe2, 0x82]));
        st.take(SpawnInput::StdinEof);
        st.take(SpawnInput::Stdin(b"late".to_vec()));
        let chunks: Vec<(u64, Chunk)> = st.pending.iter().map(|(seq, c, _)| (*seq, c.clone())).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (1, Chunk { text: Some("ok".into()), b64: None }));
        assert_eq!(chunks[1].1.b64.as_deref(), Some("4oI="), "the unfinished tail goes at EOF, as b64");
        assert_eq!(st.eof, Some(2));
    }

    /// S8: a spec that names its spawn id is started under it (the frame's
    /// `spawn_id` is the state's); one that does not gets a fresh v7 each time.
    #[test]
    fn a_spec_that_names_its_id_spawns_under_it() {
        let id = SpawnId::new_v7();
        let named = State::new(Start::New(SpawnSpec { id: Some(id.clone()), ..cat_spec() }));
        assert_eq!(named.id, id);
        assert_eq!(named.spec.as_ref().and_then(|s| s.id.clone()), Some(id), "the spec keeps it");
        let (a, b) = (State::new(Start::New(cat_spec())), State::new(Start::New(cat_spec())));
        assert!(a.id.is_v7() && b.id.is_v7() && a.id != b.id, "unnamed: a fresh v7 per spawn");
    }

    /// The same through a socket: the `spawn` frame the shim gets names the
    /// spec's id, and the session runs to its exit under it.
    #[tokio::test]
    async fn the_spawn_frame_carries_the_named_id() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let named = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                put(&mut ws, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 1, err_seq: 0 });
                id
            };
            let spec = SpawnSpec { id: Some(named.clone()), ..cat_spec() };
            let (result, _, id) = tokio::join!(run_spawn(&env, Start::New(spec), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(id, named);
        })
        .await;
    }

    #[test]
    fn resume_points_follow_what_was_delivered() {
        let mut st = State::new(Start::New(cat_spec()));
        assert!(st.resume().is_empty(), "nothing to resume before the first spawn");
        st.phase = Phase::SpawnSent;
        assert_eq!(st.resume()[0].from_seq, Some(1));
        st.out = 7;
        st.err = 2;
        assert_eq!((st.resume()[0].from_seq, st.resume()[0].err_from_seq), (Some(8), Some(3)));
        let attach = State::new(Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None });
        assert_eq!((attach.resume()[0].from_seq, attach.resume()[0].err_from_seq), (None, None), "the oldest retained");
    }

    #[test]
    fn jitter_stays_within_a_quarter() {
        for _ in 0..200 {
            let d = jittered(Duration::from_millis(1000));
            assert!(d >= Duration::from_millis(750) && d < Duration::from_millis(1250), "{d:?}");
        }
        let p = policy();
        let mut r = Retry::new(&p);
        let steps: Vec<Duration> = (0..6).map(|_| {
            r.next(&p);
            r.step
        }).collect();
        assert_eq!(steps.last(), Some(&p.backoff_max), "the step doubles up to backoff_max: {steps:?}");
    }

    // ---- S7: credential delivery ---------------------------------------------------------

    const CRED_NAME: &str = "CLAUDE_CODE_OAUTH_TOKEN";
    const CRED_TAG: &str = "seal0123456789ab";

    /// A stand-in credential, built at run time.
    fn cred_value() -> String {
        format!("dummy-credential-{}", "v".repeat(24))
    }

    /// The delivery's parts: the test credential, with `secret` in hand or not.
    fn parts(secret: Option<String>, one_shot: bool) -> super::super::DeliveryParts {
        super::super::DeliveryParts { name: CRED_NAME.into(), tag: CRED_TAG.into(), deliver: Deliver::Fd, secret: secret.map(Secret::new), one_shot }
    }

    /// A delivery to the rig's VM behind a fresh test pass.
    fn delivery(rig: &Rig, secret: Option<String>, one_shot: bool) -> super::super::Delivery {
        let now = crate::wire::time::unix_now();
        let pass = crate::bridge::egress::GatePass::for_tests(&rig.vm.id, now);
        super::super::Delivery::new(&pass, &rig.vm.id, now, parts(secret, one_shot)).unwrap()
    }

    /// A delivery of the test credential (`secret` in hand or not,
    /// `one_shot` or not), built 5 s into a pass minted `age_s` ago (it stood then).
    fn aged(rig: &Rig, age_s: u64, secret: Option<String>, one_shot: bool) -> super::super::Delivery {
        let now = crate::wire::time::unix_now();
        let pass = crate::bridge::egress::GatePass::for_tests(&rig.vm.id, now - age_s);
        super::super::Delivery::new(&pass, &rig.vm.id, now - age_s + 5, parts(secret, one_shot)).unwrap()
    }

    /// A `hello_ok` from an S7 shim whose cache holds `held` (name, tag), if anything.
    fn hello_ok_s7(held: Option<(&str, &str)>) -> Frame {
        hello_ok_s7_with(vec![], vec![], held)
    }

    /// [`hello_ok_s7`] with these spawns and answers to the resume.
    fn hello_ok_s7_with(spawns: Vec<SpawnStatus>, resumed: Vec<Resumed>, held: Option<(&str, &str)>) -> Frame {
        let Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, uptime_s, run_hook_seen, .. } = hello_ok(vec![], vec![]) else { unreachable!() };
        let credential = crate::wire::frame::CredentialView { credential_name: held.map(|h| h.0.to_string()), credential_tag: held.map(|h| h.1.to_string()), credential_at: held.map(|_| "2026-10-07T12:00:00Z".to_string()), credential_holders: 0 };
        Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials: held.is_some(), uptime_s, run_hook_seen, spawns, resumed, caps: vec![CAP_CREDENTIAL_CACHE.to_string()], credential }
    }

    /// A `hello_ok` frame as `adopt` takes it.
    fn ok_of(f: Frame) -> HelloOk {
        let Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, spawns, resumed, caps, credential } = f else { panic!("not a hello_ok") };
        HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, spawns, resumed, caps, credential }
    }

    /// A registry row for the rig's VM (the rig writes none; a holder is recorded in it).
    fn seed_row(rig: &Rig) {
        let row = VmRow { id: rig.vm.id.clone(), status: RowStatus::Running, client_token: "0192f1e0-0000-7000-8000-0000000000a1".into(), ..VmRow::default() };
        crate::bridge::vm::registry::write_row(&rig.paths, &row).unwrap();
    }

    /// The rig's VM's row as it is now.
    fn row_of(rig: &Rig) -> VmRow {
        crate::bridge::vm::registry::read_row(&rig.paths, &rig.vm.id).unwrap().unwrap()
    }

    /// The row as one whose holder record failed (or a delivery before S7's fix wave): no `credential_at`.
    fn unrecord(rig: &Rig) {
        crate::bridge::vm::registry::update_row(&rig.paths, &rig.vm.id, |r| r.credential_at = None).unwrap();
    }

    /// No file under the rig's root (the audit, the rows, the CLI log) holds the stand-in credential.
    fn assert_value_off_disk(rig: &Rig) {
        let value = cred_value();
        let (mut todo, mut leaks) = (vec![rig.paths.root.clone()], Vec::new());
        while let Some(dir) = todo.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                match e.file_type() {
                    Ok(t) if t.is_dir() => todo.push(e.path()),
                    Ok(t) if t.is_file() && std::fs::read(e.path()).is_ok_and(|b| b.windows(value.len()).any(|w| w == value.as_bytes())) => leaks.push(e.path()),
                    _ => {}
                }
            }
        }
        assert!(leaks.is_empty(), "{} files hold the value: {leaks:?}", leaks.len());
    }

    /// The spawn is answered `spawned`, then exits 0.
    async fn run_and_exit(ws: &mut Ws, id: &SpawnId) {
        put(ws, &Frame::Spawned { spawn_id: id.clone(), pid: 4242, pgid: 4242, claude_version: None }).await;
        put(ws, &exit0(id, 1)).await;
    }

    /// A miss: the value goes out in its own `credential` frame, then a
    /// `spawn` naming it with no secret of its own; `credential_ok` records
    /// the delivery in the audit.
    #[tokio::test]
    async fn a_cache_miss_sends_the_credential_then_the_spawn_naming_it() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let value = cred_value();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(None)).await;
                match frame(&mut ws).await {
                    Frame::Credential { name, secret, tag } => assert!(name == CRED_NAME && secret.expose() == &value && tag.as_deref() == Some(CRED_TAG), "{name} {tag:?}"),
                    other => panic!("the credential first, got {other:?}"),
                }
                let Frame::Spawn { spawn_id, secrets, credential, deliver_secret, .. } = frame(&mut ws).await else { panic!("no spawn") };
                assert!(secrets.is_empty() && credential.as_deref() == Some(CRED_NAME) && deliver_secret == Deliver::Fd, "{credential:?}");
                put(&mut ws, &Frame::CredentialOk { name: CRED_NAME.into(), cached: true, tag: Some(CRED_TAG.into()) }).await;
                run_and_exit(&mut ws, &spawn_id).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(value.clone()), false))), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.code, Some(0));
            let rows = rig.audit("credential_deliver");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!((rows[0]["detail"]["name"].as_str(), rows[0]["detail"]["tag"].as_str(), rows[0]["detail"]["source"].as_str()), (Some(CRED_NAME), Some(CRED_TAG), Some("sealed")));
            assert!(!rows[0].to_string().contains(&value));
        })
        .await;
    }

    /// A hit: the VM's cache holds this name and tag, so only the spawn goes
    /// out — with no value even in hand, and nothing recorded as delivered.
    /// The delivery's report says the VM held it (S8: the census's `cached`).
    #[tokio::test]
    async fn a_cache_hit_sends_only_the_spawn() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(Some((CRED_NAME, CRED_TAG)))).await;
                let Frame::Spawn { spawn_id, secrets, credential, .. } = frame(&mut ws).await else { panic!("the spawn alone") };
                assert!(secrets.is_empty() && credential.as_deref() == Some(CRED_NAME));
                run_and_exit(&mut ws, &spawn_id).await;
                ws
            };
            let d = delivery(&rig, None, false);
            let report = d.report();
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(d)), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.code, Some(0));
            assert!(rig.audit("credential_deliver").is_empty());
            assert!(report.held_by_vm(), "the VM's copy served the spawn");
        })
        .await;
    }

    /// Another tag in the cache (a token sealed since) is a miss; with no
    /// value in hand the session ends `CredentialMissing` (exit 5) before any
    /// spawn goes out, and its message tells the operator to run the command
    /// again (which unseals the token): nothing retries it.
    #[tokio::test]
    async fn a_predicted_hit_that_misses_ends_before_the_spawn() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(Some((CRED_NAME, "another-seal")))).await;
                // Nothing more: the socket closes without a spawn.
                let next = tokio::time::timeout(LIMIT, ws.next()).await.expect("the socket ends");
                assert!(!matches!(next, Some(Ok(Message::Text(_)))), "no frame after hello_ok: {next:?}");
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, None, false))), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::CredentialMissing(m) if m.contains(CRED_TAG)), "{e}");
            let cli = CliError::from(e);
            assert_eq!(cli.exit_code(), 5);
            assert!(cli.to_string().contains("nothing was started; run the command again, which unseals the token"), "{cli}");
        })
        .await;
    }

    /// An S6 shim (no `credential_cache`) gets no credential: exit 7 before
    /// any frame carries it.
    #[tokio::test]
    async fn a_shim_without_the_cache_gets_no_credential() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let value = cred_value();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let next = tokio::time::timeout(LIMIT, ws.next()).await.expect("the socket ends");
                assert!(!matches!(next, Some(Ok(Message::Text(_)))), "no frame after hello_ok: {next:?}");
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(value), false))), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(e.to_string().contains("cannot hold a credential"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        })
        .await;
    }

    /// `no_credential` (the cache emptied between the delivery and the
    /// spawn): delivered once more with the same spawn; a second is exit 8.
    #[tokio::test]
    async fn no_credential_delivers_once_more_then_gives_up() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(None)).await;
                let mut ids = Vec::new();
                for _ in 0..2 {
                    assert!(matches!(frame(&mut ws).await, Frame::Credential { .. }), "a credential first");
                    let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("then the spawn") };
                    put(&mut ws, &Frame::SpawnErr { spawn_id: spawn_id.clone(), code: SpawnErrCode::NoCredential, message: "no credential".into() }).await;
                    ids.push(spawn_id);
                }
                assert_eq!(ids[0], ids[1], "the same spawn, which never started");
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(cred_value()), false))), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(e.to_string().contains("dropped the credential twice"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// S8's census word: a hit, then `no_credential` (the cache emptied
    /// before the spawn started): the value goes out in its own `credential`
    /// frame before the same spawn again, so the delivery's report never says
    /// the VM held it (`credential:cached` only when nothing was sent).
    #[tokio::test]
    async fn no_credential_after_a_hit_sends_the_value_and_reports_it_sent() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(Some((CRED_NAME, CRED_TAG)))).await;
                let Frame::Spawn { spawn_id, credential, .. } = frame(&mut ws).await else { panic!("the spawn alone: a hit") };
                assert_eq!(credential.as_deref(), Some(CRED_NAME));
                put(&mut ws, &Frame::SpawnErr { spawn_id: spawn_id.clone(), code: SpawnErrCode::NoCredential, message: "no credential".into() }).await;
                assert!(matches!(frame(&mut ws).await, Frame::Credential { .. }), "the credential, delivered once more");
                let Frame::Spawn { spawn_id: again, .. } = frame(&mut ws).await else { panic!("then the spawn again") };
                assert_eq!(again, spawn_id, "the same spawn, which never started");
                run_and_exit(&mut ws, &spawn_id).await;
                ws
            };
            let d = delivery(&rig, Some(cred_value()), false);
            let report = d.report();
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(d)), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.code, Some(0));
            assert!(!report.held_by_vm(), "the value went out: the census keeps its source");
        })
        .await;
    }

    /// `--credential-file`: the value rides that one spawn inline (S6's
    /// path, any shim), never a `credential` frame. The VM's row names it as
    /// a holder before that spawn leaves the Mac (M1: unless `spawned` is
    /// lost, the only record of it, since no cache hit names it later), and
    /// the audit records the delivery when the spawn starts.
    #[tokio::test]
    async fn a_one_shot_credential_rides_its_spawn_inline() {
        bounded(async {
            let rig = rig(true).await;
            seed_row(&rig);
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let value = cred_value();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id, secrets, credential, .. } = frame(&mut ws).await else { panic!("the spawn alone") };
                assert!(credential.is_none() && secrets.len() == 1 && secrets.get(CRED_NAME).is_some_and(|v| v.expose() == &value));
                let row = row_of(&rig);
                assert_eq!((row.credential_at.is_some(), row.credential_tag.as_deref()), (true, Some(CRED_TAG)), "recorded before the value left");
                run_and_exit(&mut ws, &spawn_id).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(value.clone()), true))), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.code, Some(0));
            let rows = rig.audit("credential_deliver");
            assert_eq!((rows.len(), rows[0]["detail"]["source"].as_str()), (1, Some("file")));
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// A delivery gated for another VM, or with a reattach, never starts a session.
    #[tokio::test]
    async fn a_delivery_goes_only_to_its_own_vm_with_a_new_spawn() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let now = crate::wire::time::unix_now();
            let pass = crate::bridge::egress::GatePass::for_tests("microvm-other", now);
            let parts = || super::super::DeliveryParts { name: CRED_NAME.into(), tag: CRED_TAG.into(), deliver: Deliver::Fd, secret: Some(Secret::new(cred_value())), one_shot: false };
            let e = super::super::Delivery::new(&pass, &rig.vm.id, now, parts()).unwrap_err();
            assert_eq!(CliError::from(e).exit_code(), 9, "a pass for another VM");
            let stale = crate::bridge::egress::GatePass::for_tests(&rig.vm.id, now - crate::bridge::egress::GATE_PASS_MAX_AGE_S - 1);
            assert_eq!(CliError::from(super::super::Delivery::new(&stale, &rig.vm.id, now, parts()).unwrap_err()).exit_code(), 9, "a pass too old");
            let other = super::super::Delivery::new(&pass, "microvm-other", now, parts()).unwrap();
            let (sio, _cio) = spawn_channels(8);
            let e = super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(other)).await.unwrap_err();
            assert!(matches!(&e, BridgeError::Policy(m) if m.contains("microvm-other")), "{e}");
            let (sio, _cio) = spawn_channels(8);
            let attach = Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None };
            let e = super::super::run_spawn_with(&env, attach, sio, Some(delivery(&rig, Some(cred_value()), false))).await.unwrap_err();
            assert!(matches!(&e, BridgeError::Policy(m) if m.contains("new spawn")), "{e}");
            assert!(rig.endpoint.attempts().is_empty(), "nothing dialed");
        })
        .await;
    }

    // ---- S7 fix wave: delivery ----------------------------------------------------------

    /// M1: the VM's row names it as a holder before the value leaves the
    /// Mac, so a socket lost before `credential_ok` and `spawned` never
    /// leaves it unlisted; and the reattach that sees it hold the seal (the
    /// spawn found running, or a hit for the spawn sent again) fills a row
    /// that names no delivery (wiped here after the send, as a record that
    /// failed). Nothing was acknowledged: no `credential_deliver` row.
    #[tokio::test]
    async fn a_delivery_whose_answers_were_lost_still_lists_the_vm() {
        for resumed in [ResumeStatus::Ok, ResumeStatus::Unknown] {
            bounded(async {
                let rig = rig(true).await;
                seed_row(&rig);
                let env = rig.env(policy());
                let (sio, cio) = spawn_channels(8);
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    assert!(matches!(frame(&mut ws1).await, Frame::Hello { .. }));
                    put(&mut ws1, &hello_ok_s7(None)).await;
                    assert!(matches!(frame(&mut ws1).await, Frame::Credential { .. }), "the credential first");
                    let Frame::Spawn { spawn_id: id, .. } = frame(&mut ws1).await else { panic!("then the spawn") };
                    let row = row_of(&rig);
                    assert_eq!((row.credential_at.is_some(), row.credential_tag.as_deref()), (true, Some(CRED_TAG)), "recorded before the value left");
                    unrecord(&rig);
                    // Cut (no Close) before `credential_ok` and `spawned`.
                    drop(ws1);
                    let mut ws2 = rig.endpoint.next().await;
                    let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume.len(), 1, "the hello resumes the spawn");
                    let held = Some((CRED_NAME, CRED_TAG));
                    if resumed == ResumeStatus::Ok {
                        put(&mut ws2, &hello_ok_s7_with(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }], held)).await;
                        put(&mut ws2, &exit0(&id, 1)).await;
                    } else {
                        put(&mut ws2, &hello_ok_s7_with(vec![], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }], held)).await;
                        let Frame::Spawn { spawn_id, secrets, credential, .. } = frame(&mut ws2).await else { panic!("the spawn alone, again: a hit") };
                        assert!(spawn_id == id && secrets.is_empty() && credential.as_deref() == Some(CRED_NAME));
                        run_and_exit(&mut ws2, &id).await;
                    }
                    ws2
                };
                let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(cred_value()), false))), consume(cio, None, Duration::ZERO), shim);
                assert_eq!(result.unwrap().exit.code, Some(0), "{resumed:?}");
                let row = row_of(&rig);
                assert_eq!((row.credential_at.is_some(), row.credential_tag.as_deref()), (true, Some(CRED_TAG)), "named again on the reattach ({resumed:?})");
                assert!(rig.audit("credential_deliver").is_empty(), "nothing was acknowledged ({resumed:?})");
                assert_value_off_disk(&rig);
            })
            .await;
        }
    }

    /// M5, M32: the Mac's copy goes once the spawn runs: at `spawned`, and
    /// on a reattach that finds it running after `spawned` was lost with its
    /// socket (the shim never sends it again). A one-shot delivery is
    /// recorded there, once (`credential_deliver`, source file); the running
    /// spawn fills a row that names no delivery yet.
    #[tokio::test]
    async fn the_macs_copy_goes_once_the_spawn_runs_or_is_found_running() {
        bounded(async {
            let rig = rig(true).await;
            seed_row(&rig);
            let env = rig.env(policy());
            for (one_shot, found) in [(false, false), (true, false), (false, true), (true, true)] {
                let what = format!("one_shot={one_shot}, found={found}");
                let (sio, _cio) = spawn_channels(8);
                let mut s = session(&env, sio, Start::New(cat_spec())).await;
                s.delivery = Some(delivery(&rig, Some(cred_value()), one_shot));
                s.st.phase = Phase::SpawnSent;
                let (mut link, _ws) = link_to(&rig, &s).await;
                let id = s.st.id.clone();
                let spawned = || Frame::Spawned { spawn_id: id.clone(), pid: 4242, pgid: 4242, claude_version: None };
                let before = rig.audit("credential_deliver").len();
                if found {
                    unrecord(&rig);
                    let ok = ok_of(hello_ok_s7_with(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }], Some((CRED_NAME, CRED_TAG))));
                    s.adopt(&ok, &mut link).await.unwrap();
                    assert!(row_of(&rig).credential_at.is_some(), "the running spawn names the VM ({what})");
                } else {
                    s.on_frame(spawned(), &mut link, &mut false).await.unwrap();
                }
                assert!(s.st.phase == Phase::Running && s.st.started, "{what}");
                assert!(!s.delivery.as_ref().unwrap().holds_value(), "the value is dropped ({what})");
                let rows = rig.audit("credential_deliver");
                assert_eq!(rows.len() - before, usize::from(one_shot), "{what}");
                if one_shot {
                    assert_eq!(rows.last().unwrap()["detail"]["source"], "file", "{what}");
                }
                // A later `spawned` (or reattach) records nothing more.
                s.on_frame(spawned(), &mut link, &mut false).await.unwrap();
                assert_eq!(rig.audit("credential_deliver").len(), rows.len(), "{what}");
            }
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M6: neither the value nor a spawn naming the credential leaves the
    /// Mac on a gate pass older than its life (90 s): a VM that answers only
    /// once the pass aged (here a delivery built 5 s into a pass now 100 s
    /// old) gets no frame after `hello_ok`, from a session (a miss with the
    /// value in hand; a hit, whose spawn would name the cached copy; a
    /// one-shot spawn, which would carry the value inline) or from `vm
    /// warm`; exit 9, saying nothing was sent and to run the command again;
    /// the row names no holder.
    #[tokio::test]
    async fn a_pass_that_aged_before_the_vm_answered_sends_nothing() {
        bounded(async {
            let rig = rig(true).await;
            seed_row(&rig);
            let env = rig.env(policy());
            let r = &rig;
            let shim = move |held: Option<(&'static str, &'static str)>| async move {
                let mut ws = r.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(held)).await;
                let next = tokio::time::timeout(LIMIT, ws.next()).await.expect("the socket ends");
                assert!(!matches!(next, Some(Ok(Message::Text(_)))), "no frame after hello_ok (hit={})", held.is_some());
                ws
            };
            let refused = |e: BridgeError, what: &str| {
                assert!(matches!(&e, BridgeError::Policy(m) if m.contains("ready for it (a slow") && m.contains("so nothing was sent; run the command again")), "{what}: {e}");
                assert_eq!(CliError::from(e).exit_code(), 9, "{what}");
            };
            let value = || Some(cred_value());
            for (secret, one_shot, held) in [(value(), false, None), (None, false, Some((CRED_NAME, CRED_TAG))), (value(), true, None)] {
                let what = format!("value={}, one_shot={one_shot}, hit={}", secret.is_some(), held.is_some());
                let (sio, cio) = spawn_channels(8);
                let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(aged(&rig, 100, secret, one_shot))), consume(cio, None, Duration::ZERO), shim(held));
                refused(result.unwrap_err(), &what);
            }
            let (warmed, _ws) = tokio::join!(super::super::credential::deliver_only(&env, aged(&rig, 100, value(), false)), shim(None));
            refused(warmed.unwrap_err(), "vm warm");
            assert!(row_of(&rig).credential_at.is_none(), "nothing left the Mac");
            assert!(rig.audit("credential_deliver").is_empty());
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M6: nor after a reconnect once the pass aged (a lost socket, a
    /// suspend waited out): neither the spawn sent again for a resume
    /// answered `unknown` (after a miss, for a hit, or a one-shot spawn with
    /// its value inline) nor the redelivery `no_credential` asks for goes
    /// out: exit 9 each, nothing on the socket, and the message says that
    /// nothing MORE was sent (the first spawn went out: the VM may hold a copy).
    #[tokio::test]
    async fn a_pass_that_aged_while_reconnecting_sends_nothing_again() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let value = || Some(cred_value());
            let hit = Some((CRED_NAME, CRED_TAG));
            // (the spawn sent again, or `no_credential`'s redelivery; the value; one-shot; what the cache holds)
            for (resend, secret, one_shot, held) in [(true, value(), false, None), (true, None, false, hit), (true, value(), true, None), (false, value(), false, None)] {
                let what = format!("resend={resend}, value={}, one_shot={one_shot}, hit={}", secret.is_some(), held.is_some());
                let (sio, _cio) = spawn_channels(8);
                let mut s = session(&env, sio, Start::New(cat_spec())).await;
                s.delivery = Some(aged(&rig, 100, secret, one_shot));
                s.st.phase = Phase::SpawnSent;
                let (mut link, mut ws) = link_to(&rig, &s).await;
                let id = s.st.id.clone();
                let e = if resend {
                    let ok = ok_of(hello_ok_s7_with(vec![], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }], held));
                    s.adopt(&ok, &mut link).await.unwrap_err()
                } else {
                    let refused = Frame::SpawnErr { spawn_id: id.clone(), code: SpawnErrCode::NoCredential, message: "no credential".into() };
                    s.on_frame(refused, &mut link, &mut false).await.err().expect("refused")
                };
                assert!(matches!(&e, BridgeError::Policy(m) if m.contains("ready for it again") && m.contains("so nothing more was sent (the VM may still hold the copy it had") && !m.contains("nothing was sent")), "{what}: {e}");
                assert_eq!(CliError::from(e).exit_code(), 9, "{what}");
                drop(link);
                let next = tokio::time::timeout(LIMIT, ws.next()).await.expect("the socket ends");
                assert!(!matches!(next, Some(Ok(Message::Text(_)))), "nothing went out ({what})");
            }
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M6, the rule `prepare` gates again by (`fresh_enough`): a pass with at
    /// least half its life left is kept (no extra reads); one past half its
    /// life (an 89 s old pass) is not, nor is one that no longer stands (too
    /// old, another VM's, a clock that went backwards). That `prepare` itself
    /// gates again on it: the shim_bridge_local test
    /// `prepare_gates_again_once_its_pass_is_past_half_its_life`.
    #[test]
    fn fresh_enough_keeps_only_a_pass_with_half_its_life_left() {
        use crate::bridge::egress::{GatePass, GATE_PASS_MAX_AGE_S};
        let (fresh, now, vm) = (super::super::credential::fresh_enough, 1_000_000, "microvm-1");
        let aged = |age: u64| GatePass::for_tests(vm, now - age);
        for age in [0, 30, GATE_PASS_MAX_AGE_S / 2] {
            assert!(fresh(&aged(age), vm, now), "{age} s old: kept");
        }
        for age in [GATE_PASS_MAX_AGE_S / 2 + 1, 89, GATE_PASS_MAX_AGE_S, GATE_PASS_MAX_AGE_S + 1] {
            assert!(!fresh(&aged(age), vm, now), "{age} s old: gated again");
        }
        assert!(!fresh(&aged(0), "microvm-other", now), "another VM's pass");
        assert!(!fresh(&GatePass::for_tests(vm, now + 5), vm, now), "a clock that went backwards");
    }

    /// M13: `credential_err suspended` is waited out as a suspend and
    /// delivered once more; a second while GetMicrovm says RUNNING (the
    /// shim's cache stays closed: no `/resume` reached it) ends the session,
    /// exit 8, naming `vm resume` and another run: two deliveries, never a loop.
    #[tokio::test]
    async fn credential_err_suspended_again_while_the_vm_runs_ends_the_session() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let sent = std::sync::atomic::AtomicUsize::new(0);
            let shim = async {
                for n in 0..3 {
                    let mut ws = rig.endpoint.next().await;
                    assert!(n < 2, "a third socket: the value would go out again, without bound");
                    assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok_s7(None)).await;
                    assert!(matches!(frame(&mut ws).await, Frame::Credential { .. }), "a credential first");
                    sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("then the spawn") };
                    // What the shim answers while its cache is closed for a suspend.
                    put(&mut ws, &Frame::CredentialErr { name: CRED_NAME.into(), code: CredentialErrCode::Suspended, message: "closed for a suspend".into() }).await;
                    put(&mut ws, &Frame::SpawnErr { spawn_id, code: SpawnErrCode::NoCredential, message: "no credential".into() }).await;
                }
            };
            let session = async { tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(cred_value()), false))), consume(cio, None, Duration::ZERO)).0 };
            let result = tokio::select! {
                r = session => r,
                () = shim => unreachable!("the shim ran out of sockets"),
            };
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Transport(m) if m.contains("`ai-env vm resume ") && m.contains("run the command again")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(sent.load(std::sync::atomic::Ordering::SeqCst), 2, "delivered once more, then no more");
            assert_eq!(rig.endpoint.attempts().len(), 2);
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M40: a `no_credential` answer to a one-shot (`--credential-file`)
    /// spawn, which names no credential, is a protocol error (exit 8): its
    /// value never rides a `credential` frame, which the shim would cache.
    #[tokio::test]
    async fn no_credential_for_a_one_shot_spawn_never_sends_its_value_to_the_cache() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(None)).await;
                let Frame::Spawn { spawn_id, secrets, credential, .. } = frame(&mut ws).await else { panic!("the spawn alone") };
                assert!(credential.is_none() && secrets.len() == 1, "the value inline");
                put(&mut ws, &Frame::SpawnErr { spawn_id, code: SpawnErrCode::NoCredential, message: "no credential".into() }).await;
                let next = tokio::time::timeout(LIMIT, ws.next()).await.expect("the socket ends");
                assert!(!matches!(next, Some(Ok(Message::Text(_)))), "nothing more went out");
                ws
            };
            let (result, _, _ws) = tokio::join!(super::super::run_spawn_with(&env, Start::New(cat_spec()), sio, Some(delivery(&rig, Some(cred_value()), true))), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Protocol(m) if m.contains("no_credential")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert!(rig.audit("credential_deliver").is_empty());
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M39: `session::run` itself (whoever calls it) and `vm warm`'s
    /// delivery refuse a delivery gated for another VM, and the session one
    /// with a reattach, as `run_spawn_with` does: exit 9, nothing minted or dialed.
    #[tokio::test]
    async fn a_delivery_for_another_vm_reaches_no_session_and_no_warm_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let other = || {
                let now = crate::wire::time::unix_now();
                super::super::Delivery::new(&crate::bridge::egress::GatePass::for_tests("microvm-other", now), "microvm-other", now, parts(Some(cred_value()), false)).unwrap()
            };
            let (sio, _cio) = spawn_channels(8);
            let e = super::run(&env, Start::New(cat_spec()), sio, Some(other()), None).await.unwrap_err();
            assert!(matches!(&e, BridgeError::Policy(m) if m.contains("microvm-other")), "{e}");
            let (sio, _cio) = spawn_channels(8);
            let attach = Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None };
            let e = super::run(&env, attach, sio, Some(delivery(&rig, Some(cred_value()), false)), None).await.unwrap_err();
            assert!(matches!(&e, BridgeError::Policy(m) if m.contains("new spawn")), "{e}");
            let e = super::super::credential::deliver_only(&env, other()).await.unwrap_err();
            assert!(matches!(&e, BridgeError::Policy(m) if m.contains("microvm-other")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 9);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 0, "no token minted");
            assert!(rig.endpoint.attempts().is_empty(), "nothing dialed");
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M1: `vm warm` names the VM in its row before the value leaves, so an
    /// answer lost with the socket (exit 8) never leaves it unlisted, with
    /// no `credential_deliver` (nothing acknowledged); the next `vm warm`
    /// finds it held and fills a row that names no delivery (wiped here, as
    /// a record that failed).
    #[tokio::test]
    async fn warm_records_the_vm_before_the_value_leaves_and_on_a_hit() {
        bounded(async {
            let rig = rig(true).await;
            seed_row(&rig);
            let env = rig.env(policy());
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(None)).await;
                assert!(matches!(frame(&mut ws).await, Frame::Credential { .. }));
                // Cut before `credential_ok`.
            };
            let (r, ()) = tokio::join!(super::super::credential::deliver_only(&env, delivery(&rig, Some(cred_value()), false)), shim);
            assert_eq!(CliError::from(r.unwrap_err()).exit_code(), 8);
            let row = row_of(&rig);
            assert_eq!((row.credential_at.is_some(), row.credential_tag.as_deref()), (true, Some(CRED_TAG)));
            assert!(rig.audit("credential_deliver").is_empty(), "nothing was acknowledged");
            unrecord(&rig);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(Some((CRED_NAME, CRED_TAG)))).await;
                ws
            };
            let (r, _ws) = tokio::join!(super::super::credential::deliver_only(&env, delivery(&rig, None, false)), shim);
            assert_eq!(r.unwrap(), super::super::credential::Warmed::AlreadyHeld);
            assert!(row_of(&rig).credential_at.is_some(), "the hit names it again");
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// `vm warm` on a VM whose cache holds the credential's name under
    /// another seal (a token sealed since: a rotated token) misses, as the
    /// session's own hit check does: the value goes out in its own
    /// `credential` frame and the delivery is recorded, never `AlreadyHeld`
    /// on the name alone, which would leave the VM with the old token.
    #[tokio::test]
    async fn warm_delivers_when_the_cache_holds_another_seal() {
        bounded(async {
            let rig = rig(true).await;
            seed_row(&rig);
            let env = rig.env(policy());
            let value = cred_value();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(Some((CRED_NAME, "another-seal")))).await;
                match frame(&mut ws).await {
                    Frame::Credential { name, secret, tag } => assert!(name == CRED_NAME && secret.expose() == &value && tag.as_deref() == Some(CRED_TAG), "{name} {tag:?}"),
                    other => panic!("the credential, got {other:?}"),
                }
                put(&mut ws, &Frame::CredentialOk { name: CRED_NAME.into(), cached: true, tag: Some(CRED_TAG.into()) }).await;
                ws
            };
            let (r, _ws) = tokio::join!(super::super::credential::deliver_only(&env, delivery(&rig, Some(value.clone()), false)), shim);
            assert_eq!(r.unwrap(), super::super::credential::Warmed::Delivered);
            assert_eq!(rig.audit("credential_deliver").len(), 1);
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M44: `vm warm`'s socket waits out what the session waits out: 503
    /// `not_run`, a 429 (its Retry-After, audited `endpoint_429`), 503
    /// `busy` and `hello_err busy`, on one token; then it delivers. The
    /// Mac's copy is gone once the frame went out (M32).
    #[tokio::test]
    async fn warm_waits_out_not_run_a_429_and_busy_then_delivers() {
        bounded(async {
            let rig = rig(true).await;
            rig.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            rig.endpoint.refuse(refusal(429, &[("retry-after", "3")], ""));
            rig.endpoint.refuse(refusal(503, &[], r#"{"status":"busy"}"#));
            let env = rig.env(policy());
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &Frame::HelloErr { code: HelloErrCode::Busy, message: "too many sockets without a hello".into() }).await;
                drop(ws);
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok_s7(None)).await;
                assert!(matches!(frame(&mut ws).await, Frame::Credential { .. }));
                put(&mut ws, &Frame::CredentialOk { name: CRED_NAME.into(), cached: true, tag: Some(CRED_TAG.into()) }).await;
                ws
            };
            let mut d = delivery(&rig, Some(cred_value()), false);
            let (r, _ws) = tokio::join!(super::super::credential::warm(&env, &mut d), shim);
            assert_eq!(r.unwrap(), super::super::credential::Warmed::Delivered);
            assert!(!d.holds_value(), "the Mac keeps no copy once it went out");
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![503, 429, 503, 101, 101]);
            assert!(a[2].at - a[1].at >= Duration::from_millis(30), "the 429's Retry-After: {:?}", a[2].at - a[1].at);
            assert_eq!(rig.audit("endpoint_429").len(), 1);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 1, "one token throughout");
            assert_eq!(rig.audit("credential_deliver").len(), 1);
            assert_value_off_disk(&rig);
        })
        .await;
    }

    /// M44: and gives up as the session does: `not_run` past
    /// `not_run_budget` is exit 8, 429s past `reconnect_budget` exit 7.
    #[tokio::test]
    async fn warm_gives_up_past_its_budgets() {
        bounded(async {
            let not_run = rig(true).await;
            for _ in 0..200 {
                not_run.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            }
            let mut p = policy();
            p.not_run_budget = Duration::from_millis(200);
            let e = super::super::credential::deliver_only(&not_run.env(p), delivery(&not_run, Some(cred_value()), false)).await.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("not_run")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_value_off_disk(&not_run);
            let throttled = rig(true).await;
            for _ in 0..100 {
                throttled.endpoint.refuse(refusal(429, &[("retry-after", "1")], ""));
            }
            let mut p = policy();
            p.reconnect_budget = Duration::from_millis(300);
            let e = super::super::credential::deliver_only(&throttled.env(p), delivery(&throttled, Some(cred_value()), false)).await.unwrap_err();
            assert!(matches!(e, BridgeError::EndpointThrottled { retry_after_s: Some(1) }), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
            assert_value_off_disk(&throttled);
        })
        .await;
    }

    /// S10 §D, against the scripted shim: a parking session's handshake,
    /// what it sends while parked (nothing), its unparks on the open socket
    /// and after a redial, the suspend and the close while parked, the park
    /// golden, and `agent::stop_spawn`.
    mod p_tests {
        use super::*;
        use crate::bridge::agent::{run_spawn_parked, stop_spawn, ParkReport};
        use crate::bridge::codeout::{CodeoutCtx, CodeoutTrigger};
        use crate::bridge::config::BridgeConfig;
        use crate::bridge::park::{ParkCtl, ParkPolicy, QuietState, Verdict};
        use crate::wire::frame::{ParkOwner, ParkRefusal, CAP_PARK_V1};
        use tokio::sync::watch;

        /// The wrapper every `park` names here (the golden's).
        const OWNER: ParkOwner = ParkOwner { pid: 51_234, started: 1_792_483_200 };

        fn ms(n: u64) -> Duration {
            Duration::from_millis(n)
        }

        /// The park's terms here: the golden's grace, window, threshold and
        /// owner; a quiet of `after` ms; a 500 ms probe and a 2 s answer wait.
        fn terms(after: u64) -> ParkPolicy {
            ParkPolicy { after: ms(after), grace_s: 30_600, min_quiet_s: 30, cpu_busy_ms: 500, hold_output: false, probe: ms(500), answer_wait: Duration::from_secs(2) }
        }

        /// The test's side of a parking control: the pump's quiet, and the
        /// generation's code-out trigger (idle unless asked).
        struct Pump {
            quiet: watch::Sender<QuietState>,
            trigger: CodeoutTrigger,
            fetch_lock: std::path::PathBuf,
        }

        impl Pump {
            /// The pump forwarded a line: `verdict` from now on, `last_host` the last host frame's kind.
            fn line(&self, verdict: Verdict, last_host: Option<&'static str>) {
                self.quiet.send_replace(QuietState { verdict, since: tokio::time::Instant::now(), last_host });
            }
        }

        /// A parking control on `rig`'s VM under `policy`, idle since now.
        fn park_ctl(rig: &Rig, policy: ParkPolicy) -> (ParkCtl, Pump) {
            use crate::bridge::workspace::{Head, WorkspaceRef, WsKind};
            let (tx, rx) = watch::channel(QuietState { verdict: Verdict::Idle, since: tokio::time::Instant::now(), last_host: None });
            let ws = WorkspaceRef {
                cwd: "/nonexistent/park".into(),
                root: "/nonexistent/park".into(),
                vm_cwd: "/nonexistent/park".into(),
                vm_root: "/nonexistent/park".into(),
                slug: "-nonexistent-park".into(),
                kind: WsKind::Git { git_dir: "/nonexistent/park/.git".into(), common_dir: "/nonexistent/park/.git".into(), object_format: crate::wire::workspace::ObjectFormat::Sha1 },
                head: Head::Detached { sha: "a".repeat(40) },
                seed_branch: None,
            };
            let fetch_lock = rig.paths.workspace_fetch_lock(&ws.slug);
            let target = AgentTarget { vm_id: rig.vm.id.clone(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false };
            let (dp, tokens) = (Arc::new(crate::bridge::dataplane::Unreached), Arc::new(crate::bridge::dataplane::Unreached));
            let trigger = CodeoutTrigger::spawn(CodeoutCtx { api: rig.api.clone(), dp, tokens, paths: rig.paths.clone(), cfg: Arc::new(BridgeConfig::default()), target, ws, capture_settings: false, transcript: None });
            (ParkCtl { quiet: rx, trigger: trigger.watch(), policy, owner: OWNER }, Pump { quiet: tx, trigger, fetch_lock })
        }

        /// What a parking session told its consumer, as it came.
        #[derive(Debug, Default)]
        struct Told {
            stdout: Vec<u8>,
            notes: Vec<String>,
            links: Vec<bool>,
            parks: Vec<ParkReport>,
            exit: Option<RemoteExit>,
        }

        impl Told {
            /// The parks reported so far.
            fn parked(&self) -> usize {
                self.parks.iter().filter(|r| matches!(r, ParkReport::Parked { .. })).count()
            }
        }

        /// Every event into `told` until the session ends, stdout marked consumed as it comes.
        async fn consume_into(events: &mut mpsc::UnboundedReceiver<SpawnEvent>, consumed: &Consumed, told: &Mutex<Told>) {
            while let Some(ev) = events.recv().await {
                let mut t = told.lock().unwrap();
                match ev {
                    SpawnEvent::Stdout { seq, bytes } => {
                        t.stdout.extend(bytes);
                        consumed.stdout_done(seq);
                    }
                    SpawnEvent::Stderr { seq, .. } => consumed.stderr_done(seq),
                    SpawnEvent::Note(n) => t.notes.push(n),
                    SpawnEvent::Link(up) => t.links.push(up),
                    SpawnEvent::Park(r) => t.parks.push(r),
                    SpawnEvent::Exit(e) => t.exit = Some(e),
                    SpawnEvent::Started { .. } => {}
                }
            }
        }

        /// Until `f` holds of what the consumer was told (within `LIMIT`).
        async fn until(told: &Mutex<Told>, what: &str, f: impl Fn(&Told) -> bool) {
            let deadline = Instant::now() + LIMIT;
            while !f(&told.lock().unwrap()) {
                assert!(Instant::now() < deadline, "{what}: {:?}", told.lock().unwrap());
                tokio::time::sleep(ms(5)).await;
            }
        }

        /// The next text frame, app pings included (WebSocket Pings and Pongs skipped).
        async fn next_frame(ws: &mut Ws) -> Frame {
            loop {
                match tokio::time::timeout(LIMIT, ws.next()).await.expect("a frame in time").expect("open").expect("readable") {
                    Message::Text(t) => return Frame::from_json(t.as_str()).unwrap(),
                    Message::Ping(_) | Message::Pong(_) => continue,
                    other => panic!("{other:?}"),
                }
            }
        }

        /// The next frame that is no ack (acks of what the consumer marked may come any time).
        async fn next_but_acks(ws: &mut Ws) -> Frame {
            loop {
                match next_frame(ws).await {
                    Frame::Ack { .. } => continue,
                    f => return f,
                }
            }
        }

        /// Everything that reaches the shim within `d`: every frame and every WebSocket Ping or Pong.
        async fn arrivals_within(ws: &mut Ws, d: Duration) -> Vec<String> {
            let until = tokio::time::Instant::now() + d;
            let mut got = Vec::new();
            while let Ok(Some(m)) = tokio::time::timeout_at(until, ws.next()).await {
                got.push(match m {
                    Ok(Message::Text(t)) => t.as_str().to_string(),
                    Ok(other) => format!("{other:?}"),
                    Err(e) => format!("the socket failed: {e}"),
                });
            }
            got
        }

        /// A `hello_ok` of a shim that parks (and caches credentials), with these spawns and answers to the resume.
        fn hello_ok_parks(spawns: Vec<SpawnStatus>, resumed: Vec<Resumed>) -> Frame {
            let Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, credential, .. } = hello_ok(vec![], vec![]) else { unreachable!() };
            Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, spawns, resumed, caps: vec![CAP_CREDENTIAL_CACHE.to_string(), CAP_PARK_V1.to_string()], credential }
        }

        /// hello → hello_ok (a shim that parks) → spawn → spawned: the spawn's id.
        async fn start_parking(ws: &mut Ws) -> SpawnId {
            assert!(matches!(next_frame(ws).await, Frame::Hello { .. }));
            put(ws, &hello_ok_parks(vec![], vec![])).await;
            let Frame::Spawn { spawn_id, .. } = next_frame(ws).await else { panic!("no spawn") };
            put(ws, &Frame::Spawned { spawn_id: spawn_id.clone(), pid: 4242, pgid: 4242, claude_version: None }).await;
            spawn_id
        }

        /// The session's `park`, as these tests' terms make it.
        fn park(id: &SpawnId) -> Frame {
            Frame::Park { spawn_id: id.clone(), grace_s: 30_600, min_quiet_s: 30, cpu_busy_ms: 500, hold_output: false, owner: OWNER }
        }

        fn parked(id: &SpawnId) -> Frame {
            Frame::Parked { spawn_id: id.clone(), quiet_s: 1, procs: 0 }
        }

        /// The `ts` of an unpark's probe (`unpark`, then a `ping`), answered `pong`.
        async fn answer_unpark(ws: &mut Ws, id: &SpawnId) {
            assert_eq!(next_but_acks(ws).await, Frame::Unpark { spawn_id: id.clone() }, "an unpark first");
            let Frame::Ping { ts } = next_frame(ws).await else { panic!("a ping beside the unpark") };
            put(ws, &Frame::Pong { ts }).await;
        }

        /// stdin `seq` (`text`) is acked and echoed as stdout `seq`.
        async fn echo(ws: &mut Ws, id: &SpawnId, seq: u64, text: &str) {
            match next_but_acks(ws).await {
                Frame::Stdin { spawn_id, seq: got, data } => assert_eq!((spawn_id, got, decode(&data).unwrap()), (id.clone(), seq, text.as_bytes().to_vec())),
                other => panic!("stdin {seq}, got {other:?}"),
            }
            put(ws, &Frame::StdinAck { spawn_id: id.clone(), seq }).await;
            put(ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
        }

        /// The host's EOF (stdin seq `eof`) is answered with the exit (`exit_seq`), whose ack follows.
        async fn exit_on_eof(ws: &mut Ws, id: &SpawnId, eof: u64, exit_seq: u64) {
            assert_eq!(next_but_acks(ws).await, Frame::StdinEof { spawn_id: id.clone(), seq: eof });
            put(ws, &exit0(id, exit_seq)).await;
            loop {
                if let Frame::Ack { seq, .. } = next_frame(ws).await {
                    if seq == exit_seq {
                        break;
                    }
                }
            }
        }

        /// The platform's `/suspend` under the socket `ws`: the VM SUSPENDED,
        /// then `event hook_suspend` and Close 1001, as the shim sends them.
        async fn suspend_under(rig: &Rig, ws: &mut Ws) {
            rig.api.set_state(&rig.vm.id, VmState::Suspended);
            put(ws, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-20T12:00:00Z".into(), reference: None }).await;
            ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
        }

        /// The session's redial once someone resumed its VM: within 5 s (its
        /// GetMicrovm poll, 3 s doubling to 60 s, is 30 ms doubling to 600
        /// ms here), else the test fails then.
        async fn redialed(rig: &Rig) -> Ws {
            tokio::time::timeout(Duration::from_secs(5), rig.endpoint.next()).await.expect("a redial within the poll once the VM ran again")
        }

        /// The park golden's probe `ts` (the Mac's clock: the session's own is put in).
        const GOLDEN_TS: &str = "\"ts\":1792484100000";

        /// What the golden's reader heard of the session so far: the probe's `ts`, the last ack.
        #[derive(Default)]
        struct Heard {
            ts: Option<u64>,
            last_ack: Option<String>,
        }

        /// The session's frames up to the golden's next shim line (as many as
        /// `want` holds), as the golden spells them: its host (`host`, this
        /// Mac's, put back) and its probe `ts`. A reattach's ack of what the
        /// old socket acked (S6's, no golden line) is skipped.
        async fn golden_read(ws: &mut Ws, want: &[String], host: &str, heard: &mut Heard) -> Vec<String> {
            let mut got = Vec::new();
            while got.len() < want.len() {
                let Message::Text(t) = ws.next().await.unwrap().unwrap() else { continue };
                let mut text = t.as_str().replace(host, "\"host\":\"mike@mbp\"");
                match Frame::from_json(&text).unwrap() {
                    Frame::Ping { ts } => {
                        heard.ts = Some(ts);
                        text = text.replace(&format!("\"ts\":{ts}"), GOLDEN_TS);
                    }
                    Frame::Ack { .. } if heard.last_ack.as_deref() == Some(text.as_str()) && !want.contains(&text) => continue,
                    Frame::Ack { .. } => heard.last_ack = Some(text.clone()),
                    _ => {}
                }
                got.push(text);
            }
            got
        }

        /// tests/fixtures/wire/park-golden.jsonl from the Mac's end (as
        /// `the_golden_conversation_both_directions` replays the exec golden):
        /// the session's frames between two shim lines equal the golden's Mac
        /// lines (in any order; the host and the probe's `ts` put in), and the
        /// golden's shim lines bring its answers. The pump's verdict stays
        /// idle, so the session's own stdio times its parks: the first, `after`
        /// past the first turn's output, is refused (`busy`), the second
        /// `after` past the refusal is parked. The host's line then unparks
        /// it on the open socket (`unpark`, the probe's `ping`, the line); a
        /// third park follows its echo. The shim closes that parked socket;
        /// the host's next input redials (here a chunk that brings no stdin of
        /// its own, so the golden's next frame is the EOF that follows it: a
        /// bare EOF while parked with no socket would end the session, no
        /// dial): the second socket's `hello` resumes the spawn and carries
        /// the EOF; the exit's ack, then Close 1000. A reattach acks again what
        /// the old socket acked (S6): that ack is no golden line.
        #[tokio::test]
        async fn the_park_golden_replays_against_the_session() {
            bounded(async {
                let rig = rig(true).await;
                let mut env = rig.env(policy());
                env.target.session_token = Secret::new("golden-session-token".into());
                let (ctl, pump) = park_ctl(&rig, terms(150));
                let golden_id = "0192f1e0-2b7c-7c3a-9a1b-4d5e6f708196";
                let spec = SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(900), id: Some(SpawnId(golden_id.into())) };
                let host = format!("\"host\":{}", serde_json::to_string(&crate::bridge::vm::owner()).unwrap());
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                input.send(SpawnInput::Stdin(b"hello\n".to_vec())).await.unwrap();
                let shim = async {
                    let check = |want: &mut Vec<String>, got: Vec<String>| {
                        let mut got = got;
                        got.sort();
                        want.sort();
                        assert_eq!(&got, want);
                        want.clear();
                    };
                    let mut ws: Option<Ws> = None;
                    let (mut want, mut heard): (Vec<String>, Heard) = (Vec::new(), Heard::default());
                    for line in include_str!("../../../tests/fixtures/wire/park-golden.jsonl").lines() {
                        let raw = line.split_once(",\"frame\":").and_then(|(_, f)| f.strip_suffix('}')).unwrap();
                        if line.starts_with("{\"dir\":\"mac\"") {
                            want.push(raw.to_string());
                            continue;
                        }
                        if want.first().is_some_and(|w| w.contains("\"t\":\"unpark\"")) {
                            // The host's next line unparks the parked session.
                            until(&told, "the park after the refusal", |t| t.parked() == 1).await;
                            pump.line(Verdict::Idle, Some("user"));
                            input.send(SpawnInput::Stdin(b"again\n".to_vec())).await.unwrap();
                        }
                        if want.first().is_some_and(|w| w.contains("\"t\":\"hello\"")) {
                            if let Some(mut parked_socket) = ws.take() {
                                // The shim closes the parked socket; the host's next input redials.
                                until(&told, "the third park", |t| t.parked() == 2).await;
                                parked_socket.close(None).await.unwrap();
                                until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("stays parked until the next input"))).await;
                                input.send(SpawnInput::Stdin(Vec::new())).await.unwrap();
                            }
                            ws = Some(rig.endpoint.next().await);
                        }
                        if want.first().is_some_and(|w| w.contains("\"t\":\"stdin_eof\"")) {
                            input.send(SpawnInput::StdinEof).await.unwrap();
                        }
                        let w = ws.as_mut().expect("a socket");
                        let got = golden_read(w, &want, &host, &mut heard).await;
                        check(&mut want, got);
                        let answer = match heard.ts {
                            Some(sent) => raw.replace(GOLDEN_TS, &format!("\"ts\":{sent}")),
                            None => raw.to_string(),
                        };
                        w.send(Message::text(answer)).await.unwrap();
                    }
                    let w = ws.as_mut().expect("a socket");
                    let got = golden_read(w, &want, &host, &mut heard).await;
                    check(&mut want, got);
                    assert!(matches!(w.next().await, Some(Ok(Message::Close(Some(f)))) if f.code == CloseCode::from(CLOSE_NORMAL)), "closed 1000 after the final ack");
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(spec), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                let out = result.unwrap();
                assert_eq!((out.exit.status(), out.parked_close), (0, false));
                let t = told.lock().unwrap();
                assert_eq!(t.stdout, b"hello\nagain\n");
                let words: Vec<String> = t
                    .parks
                    .iter()
                    .map(|r| match r {
                        ParkReport::Parked { why, .. } => format!("parked:{why}"),
                        ParkReport::Refused { reason } => format!("refused:{reason}"),
                        ParkReport::Unparked { by, vm_state, .. } => format!("unparked:{by}:{vm_state}"),
                        ParkReport::Off { why } => format!("off:{why}"),
                    })
                    .collect();
                assert_eq!(words, ["refused:busy", "parked:idle", "unparked:user:running", "parked:idle", "unparked:user:running"]);
                assert!(t.links.is_empty(), "a park's socket going is no lost link: {:?}", t.links);
                drop(pump);
            })
            .await;
        }

        /// From the park's request on, a parking session sends nothing that
        /// would keep the VM awake: the park goes out once the chat was quiet
        /// for `after` (with the policy's terms and this wrapper as its
        /// owner); parked, a whole second passes with no frame (no `ping`), no
        /// WebSocket Ping, no keep-alive `GET /health`, no token minted and no
        /// redial, though pings, WebSocket Pings and keep-alives ran every
        /// 40 ms before it and the dead-socket check would fire at 300 ms. The
        /// host's EOF then unparks it on that socket (`by` `eof`).
        #[tokio::test]
        async fn parks_after_park_after_then_sends_no_ping_or_keep_alive() {
            bounded(async {
                let rig = rig(true).await;
                let p = RunPolicy { ping: ms(40), ws_ping: ms(40), keepalive: Keepalive::Http, keepalive_every: ms(40), dead_after: ms(300), ..policy() };
                let env = rig.env(p);
                let (ctl, _pump) = park_ctl(&rig, terms(400));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                // The session's quiet starts with it: no stdio moved since.
                let began = Instant::now();
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    let (mut pings, mut ws_pings) = (0, 0);
                    let asked = loop {
                        match tokio::time::timeout(LIMIT, ws.next()).await.unwrap().unwrap().unwrap() {
                            Message::Ping(_) => ws_pings += 1,
                            Message::Text(t) => match Frame::from_json(t.as_str()).unwrap() {
                                Frame::Ping { ts } => {
                                    pings += 1;
                                    put(&mut ws, &Frame::Pong { ts }).await;
                                }
                                f @ Frame::Park { .. } => break f,
                                Frame::Ack { .. } => {}
                                other => panic!("{other:?}"),
                            },
                            _ => {}
                        }
                    };
                    assert!(began.elapsed() >= ms(400), "the park waited for `after`: {:?}", began.elapsed());
                    assert!(pings >= 2 && ws_pings >= 2, "the session kept the VM awake until then: {pings} pings, {ws_pings} WebSocket Pings");
                    assert_eq!(asked, park(&id));
                    put(&mut ws, &parked(&id)).await;
                    // A keep-alive in flight at the park ends at once (the fake answers it).
                    tokio::time::sleep(ms(50)).await;
                    let (health, tokens) = (rig.calls(|c| matches!(c, Call::Health { .. })), rig.calls(|c| matches!(c, Call::Token { .. })));
                    assert!(health >= 2, "keep-alives ran before the park");
                    let heard = arrivals_within(&mut ws, Duration::from_secs(1)).await;
                    assert!(heard.is_empty(), "parked, nothing goes out: {heard:?}");
                    assert_eq!((rig.calls(|c| matches!(c, Call::Health { .. })), rig.calls(|c| matches!(c, Call::Token { .. }))), (health, tokens), "no keep-alive and no mint while parked");
                    assert_eq!(rig.endpoint.attempts().len(), 1, "no redial: the dead-socket check is off while parked");
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    answer_unpark(&mut ws, &id).await;
                    exit_on_eof(&mut ws, &id, 0, 1).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "idle", quiet_ms }, ParkReport::Unparked { by: "eof", vm_state: "running", .. }] if *quiet_ms >= 400), "{:?}", t.parks);
                let parks = rig.audit("session_park");
                assert_eq!(parks.len(), 1, "{parks:?}");
                assert_eq!((parks[0]["detail"]["vm"].as_str(), parks[0]["detail"]["why"].as_str()), (Some(rig.vm.id.as_str()), Some("idle")));
                assert!(parks[0]["detail"]["spawn"].as_str().is_some_and(|s| s.len() == 36) && parks[0]["detail"]["quiet_ms"].as_str().is_some_and(|q| q.parse::<u64>().unwrap() >= 400), "{parks:?}");
                let unparks = rig.audit("session_unpark");
                assert_eq!(unparks.len(), 1, "{unparks:?}");
                assert_eq!((unparks[0]["detail"]["by"].as_str(), unparks[0]["detail"]["vm_state"].as_str()), (Some("eof"), Some("running")));
                assert!(unparks[0]["detail"]["ms"].as_str().is_some_and(|m| m.parse::<u64>().is_ok()));
            })
            .await;
        }

        /// A refused park is tried again `after` past the refusal, each time
        /// (`busy`, then `output`, then parked): each refusal is a report, and
        /// one `session_park_refused` row stands for both (one per
        /// `PARK_REFUSED_LOG_EVERY`), with what the busy check saw. The exit
        /// that comes while parked ends the session as any exit does.
        #[tokio::test]
        async fn park_refused_backs_off() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let (ctl, _pump) = park_ctl(&rig, terms(150));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    let mut refused: Option<Instant> = None;
                    for (reason, procs, cpu_ms) in [(ParkRefusal::Busy, 1, 2350), (ParkRefusal::Output, 0, 0)] {
                        assert_eq!(next_but_acks(&mut ws).await, park(&id));
                        if let Some(at) = refused {
                            assert!(at.elapsed() >= ms(150), "tried again only `after` past the refusal: {:?}", at.elapsed());
                        }
                        put(&mut ws, &Frame::ParkRefused { spawn_id: id.clone(), reason, quiet_s: 3, procs, cpu_ms }).await;
                        refused = Some(Instant::now());
                    }
                    assert_eq!(next_but_acks(&mut ws).await, park(&id));
                    let waited = refused.map(|at| at.elapsed()).unwrap_or_default();
                    assert!(waited >= ms(150), "tried again only `after` past the refusal: {waited:?}");
                    put(&mut ws, &parked(&id)).await;
                    until(&told, "parked", |t| t.parked() == 1).await;
                    put(&mut ws, &exit0(&id, 1)).await;
                    assert_eq!(next_frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Refused { reason: "busy" }, ParkReport::Refused { reason: "output" }, ParkReport::Parked { why: "idle", .. }]), "{:?}", t.parks);
                let rows = rig.audit("session_park_refused");
                assert_eq!(rows.len(), 1, "one row per PARK_REFUSED_LOG_EVERY: {rows:?}");
                let d = &rows[0]["detail"];
                assert_eq!((d["vm"].as_str(), d["reason"].as_str(), d["procs"].as_str(), d["cpu_ms"].as_str()), (Some(rig.vm.id.as_str()), Some("busy"), Some("1"), Some("2350")));
            })
            .await;
        }

        /// A third of a second of a socket whose shim does not park: its
        /// pings answered, and nothing else but acks; how many came.
        async fn pings_only(ws: &mut Ws) -> usize {
            let until = tokio::time::Instant::now() + ms(350);
            let mut pings = 0;
            while let Ok(Some(m)) = tokio::time::timeout_at(until, ws.next()).await {
                let Ok(Message::Text(t)) = m else { continue };
                match Frame::from_json(t.as_str()).unwrap() {
                    Frame::Ping { ts } => {
                        pings += 1;
                        put(ws, &Frame::Pong { ts }).await;
                    }
                    Frame::Ack { .. } => {}
                    other => panic!("no park without park_v1: {other:?}"),
                }
            }
            pings
        }

        /// A shim without `park_v1` (an older image) gets no `park`: the
        /// session says `Off { no_cap }` once (not again after a reconnect)
        /// and keeps the VM awake as S9's does, pinging all along. A suspend
        /// under it is no park either: the link goes down, and the VM
        /// running again (resumed by someone else) is reattached within the
        /// GetMicrovm poll, past `suspend_wait` and with no exit 8.
        #[tokio::test]
        async fn no_cap_no_park() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { ping: ms(50), suspend_wait: ms(200), ..policy() });
                let (ctl, _pump) = park_ctl(&rig, terms(100));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_spawn(&mut ws).await;
                    assert!(pings_only(&mut ws).await >= 3, "pinged all along");
                    // A reconnect: the second hello_ok names no park_v1 either.
                    drop(ws);
                    let mut ws = rig.endpoint.next().await;
                    assert!(matches!(next_frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    assert!(pings_only(&mut ws).await >= 3, "pinged all along");
                    // A suspend: no park, the link down until the VM runs again.
                    suspend_under(&rig, &mut ws).await;
                    tokio::time::sleep(ms(400)).await;
                    assert_eq!(rig.endpoint.attempts().len(), 2, "no dial while the VM stays suspended");
                    rig.api.set_state(&rig.vm.id, VmState::Running);
                    let mut ws = redialed(&rig).await;
                    assert!(matches!(next_frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    assert!(pings_only(&mut ws).await >= 3, "pinged all along");
                    put(&mut ws, &exit0(&id, 1)).await;
                    loop {
                        if let Frame::Ack { seq: 1, .. } = next_frame(&mut ws).await {
                            break;
                        }
                    }
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert_eq!(t.parks, [ParkReport::Off { why: "no_cap" }], "once a session, and no park at the suspend");
                assert_eq!(t.links, [false, true, false, true], "the drop, then the suspend");
                assert!(rig.audit("session_park").is_empty());
                let reconnects = rig.audit("agent_reconnect");
                assert_eq!(reconnects.len(), 2, "{reconnects:?}");
                assert_eq!(reconnects[1]["detail"]["reason"], "suspended");
            })
            .await;
        }

        /// A chat parked at a permission prompt (the pump's verdict
        /// `Prompt`: a `can_use_tool` open, nothing else) parks `prompt`; the
        /// host's answer is the pump's last host frame, a `control_response`,
        /// and it unparks the session on its socket (`by` `control_response`)
        /// and reaches claude.
        #[tokio::test]
        async fn a_prompt_park_unparks_on_the_answer() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let (ctl, pump) = park_ctl(&rig, terms(150));
                pump.line(Verdict::Prompt, Some("user"));
                let answer = "{\"type\":\"control_response\",\"response\":{\"subtype\":\"success\",\"request_id\":\"perm-1-1\",\"response\":{\"behavior\":\"allow\"}}}\n";
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    assert_eq!(next_but_acks(&mut ws).await, park(&id));
                    put(&mut ws, &parked(&id)).await;
                    until(&told, "parked", |t| t.parked() == 1).await;
                    pump.line(Verdict::Busy, Some("control_response"));
                    input.send(SpawnInput::Stdin(answer.as_bytes().to_vec())).await.unwrap();
                    answer_unpark(&mut ws, &id).await;
                    echo(&mut ws, &id, 1, answer).await;
                    until(&told, "the answer's echo", |t| t.stdout == answer.as_bytes()).await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws, &id, 1, 2).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "prompt", .. }, ParkReport::Unparked { by: "control_response", vm_state: "running", .. }]), "{:?}", t.parks);
                assert_eq!(rig.audit("session_park")[0]["detail"]["why"], "prompt");
                assert_eq!(rig.audit("session_unpark")[0]["detail"]["by"], "control_response");
            })
            .await;
        }

        /// A laptop sleep while parked (the wall clock 6 s ahead of
        /// `Instant`, past a 300 ms `dead_after`, and no frame for longer
        /// than that) loses nothing: the parked socket is silent by design,
        /// so the session neither redials nor drops it, and the next input
        /// unparks on that same socket.
        #[tokio::test]
        async fn a_wall_clock_jump_while_parked_is_no_loss() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { dead_after: ms(300), ..policy() });
                let (ctl, pump) = park_ctl(&rig, terms(100));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    assert_eq!(next_but_acks(&mut ws).await, park(&id));
                    put(&mut ws, &parked(&id)).await;
                    until(&told, "parked", |t| t.parked() == 1).await;
                    WALL_AHEAD.with(|w| w.set(Duration::from_secs(6)));
                    let heard = arrivals_within(&mut ws, ms(800)).await;
                    assert!(heard.is_empty(), "{heard:?}");
                    assert_eq!(rig.endpoint.attempts().len(), 1, "no redial");
                    pump.line(Verdict::Busy, Some("user"));
                    input.send(SpawnInput::Stdin(b"after the sleep\n".to_vec())).await.unwrap();
                    answer_unpark(&mut ws, &id).await;
                    echo(&mut ws, &id, 1, "after the sleep\n").await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws, &id, 1, 2).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                WALL_AHEAD.with(|w| w.set(Duration::ZERO));
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert_eq!(t.stdout, b"after the sleep\n");
                assert!(matches!(&t.parks[..], [ParkReport::Parked { .. }, ParkReport::Unparked { by: "user", vm_state: "running", .. }]), "{:?}", t.parks);
                assert!(!t.notes.iter().any(|n| n.starts_with("lost the connection")) && t.links.is_empty(), "{:?} {:?}", t.notes, t.links);
                assert_eq!(rig.endpoint.attempts().len(), 1, "one socket throughout");
            })
            .await;
        }

        /// A parked socket that died silently is found by the unpark's probe:
        /// the input's `unpark`, `ping` and stdin go into it, neither a `pong`
        /// nor a `stdin_ack` comes within `probe` (500 ms), so the socket is
        /// lost; the reconnect resumes the spawn and sends its stdin again
        /// above the shim's `in_seq`; the unpark is reported once the new
        /// socket carries the spawn.
        #[tokio::test]
        async fn a_dead_parked_socket_is_caught_within_the_probe() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let (ctl, pump) = park_ctl(&rig, terms(100));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    let id = start_parking(&mut ws1).await;
                    assert_eq!(next_but_acks(&mut ws1).await, park(&id));
                    put(&mut ws1, &parked(&id)).await;
                    until(&told, "parked", |t| t.parked() == 1).await;
                    // From here on the first socket answers nothing.
                    pump.line(Verdict::Busy, Some("user"));
                    let typed = Instant::now();
                    input.send(SpawnInput::Stdin(b"x\n".to_vec())).await.unwrap();
                    let mut ws2 = rig.endpoint.next().await;
                    let waited = typed.elapsed();
                    assert!(waited >= ms(500) && waited < Duration::from_secs(5), "lost once the probe ran out: {waited:?}");
                    let Frame::Hello { resume, .. } = next_frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) }]);
                    put(&mut ws2, &hello_ok_parks(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    echo(&mut ws2, &id, 1, "x\n").await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws2, &id, 1, 2).await;
                    drop(ws1);
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert_eq!(t.stdout, b"x\n");
                assert!(t.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("no pong or stdin_ack within")), "{:?}", t.notes);
                assert_eq!(t.links, [false, true], "a lost socket, then the reattach");
                assert!(matches!(&t.parks[..], [ParkReport::Parked { .. }, ParkReport::Unparked { by: "user", ms, .. }] if *ms >= 500), "{:?}", t.parks);
            })
            .await;
        }

        /// Input that comes while the park's answer is awaited waits for it
        /// (no frame meanwhile); `parked` then unparks at once: `unpark`, the
        /// probe's `ping`, then the input.
        #[tokio::test]
        async fn input_during_the_handshake_unparks_right_after_parked() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let (ctl, pump) = park_ctl(&rig, terms(100));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    assert_eq!(next_but_acks(&mut ws).await, park(&id));
                    pump.line(Verdict::Busy, Some("user"));
                    input.send(SpawnInput::Stdin(b"meanwhile\n".to_vec())).await.unwrap();
                    let heard = arrivals_within(&mut ws, ms(200)).await;
                    assert!(heard.is_empty(), "the input waits for the answer: {heard:?}");
                    put(&mut ws, &parked(&id)).await;
                    answer_unpark(&mut ws, &id).await;
                    echo(&mut ws, &id, 1, "meanwhile\n").await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws, &id, 1, 2).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "idle", .. }, ParkReport::Unparked { by: "user", .. }]), "{:?}", t.parks);
            })
            .await;
        }

        /// No answer to a `park` within `answer_wait`: the socket counts as
        /// lost and the session reconnects with the resume (a hello that
        /// unparks a parked spawn on the shim). The next `park` waits
        /// `after` past the last one whatever came of it, here a second
        /// socket that drops on its `park` and a third that parks: a shim
        /// that never answers costs one reconnect per `after`, never a loop
        /// through the reconnect budget into a move: no socket here lives
        /// `stable_after`, and the budget is shorter than `after`, so only
        /// the new reconnect episode at each socket lost to its park's
        /// handshake keeps the session from giving up.
        #[tokio::test]
        async fn no_answer_to_a_park_loses_the_socket() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { stable_after: Duration::from_secs(5), reconnect_budget: ms(500), ..policy() });
                let (ctl, _pump) = park_ctl(&rig, ParkPolicy { answer_wait: ms(200), ..terms(600) });
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let resumed = |id: &SpawnId| hello_ok_parks(vec![status(id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }]);
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    let id = start_parking(&mut ws1).await;
                    assert_eq!(next_but_acks(&mut ws1).await, park(&id));
                    let asked = Instant::now();
                    let mut ws2 = tokio::time::timeout(Duration::from_secs(5), rig.endpoint.next()).await.expect("a reconnect after the unanswered park: the session gave up");
                    assert!(asked.elapsed() >= ms(190), "lost once answer_wait ran out: {:?}", asked.elapsed());
                    let Frame::Hello { resume, .. } = next_frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id, "the reconnect resumes the spawn");
                    put(&mut ws2, &resumed(&id)).await;
                    assert_eq!(next_but_acks(&mut ws2).await, park(&id));
                    assert!(asked.elapsed() >= ms(550), "the next park waited `after` past the unanswered one: {:?}", asked.elapsed());
                    let asked = Instant::now();
                    // This one drops the socket on its park.
                    drop(ws2);
                    let mut ws3 = tokio::time::timeout(Duration::from_secs(5), rig.endpoint.next()).await.expect("a reconnect after the dropped park: the session gave up");
                    assert!(matches!(next_frame(&mut ws3).await, Frame::Hello { .. }));
                    put(&mut ws3, &resumed(&id)).await;
                    assert_eq!(next_but_acks(&mut ws3).await, park(&id));
                    assert!(asked.elapsed() >= ms(550), "the next park waited `after` past the dropped one: {:?}", asked.elapsed());
                    put(&mut ws3, &parked(&id)).await;
                    until(&told, "parked", |t| t.parked() == 1).await;
                    put(&mut ws3, &exit0(&id, 1)).await;
                    loop {
                        if let Frame::Ack { seq: 1, .. } = next_frame(&mut ws3).await {
                            break;
                        }
                    }
                    drop(ws1);
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(t.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("no answer to park within")), "{:?}", t.notes);
                assert_eq!(t.links, [false, true, false, true], "two lost sockets, each reattached");
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "idle", .. }]), "only the third socket's park: {:?}", t.parks);
            })
            .await;
        }

        /// A park waits for the code-out trigger: while a fetch is asked
        /// for and held (here at the workspace's fetch lock) no `park` goes
        /// out however quiet the chat; once the fetch ended, it does.
        #[tokio::test]
        async fn a_park_waits_for_the_code_out_trigger() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let (ctl, pump) = park_ctl(&rig, terms(100));
                let held = crate::bridge::vm::lock::try_lock_exclusive(&pump.fetch_lock).unwrap().expect("the test holds the fetch lock");
                pump.trigger.request();
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let id = start_parking(&mut ws).await;
                    let heard: Vec<String> = arrivals_within(&mut ws, ms(500)).await.into_iter().filter(|f| f.contains("\"t\":\"park\"")).collect();
                    assert!(heard.is_empty(), "a fetch runs: no park {heard:?}");
                    drop(held);
                    assert_eq!(next_but_acks(&mut ws).await, park(&id), "the fetch ended: the park");
                    put(&mut ws, &parked(&id)).await;
                    put(&mut ws, &exit0(&id, 1)).await;
                    loop {
                        if let Frame::Ack { seq: 1, .. } = next_frame(&mut ws).await {
                            break;
                        }
                    }
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                assert_eq!(told.lock().unwrap().parked(), 1);
            })
            .await;
        }

        /// `event hook_suspend` under an idle parking session (not parked
        /// yet) parks it with no socket (`suspended`): no `suspend_wait`, no
        /// exit 8, no dial and no ResumeMicrovm, only GetMicrovm asked (the
        /// shim holds the spawn under its detach grace, not parked); the next
        /// input dials, the endpoint's auto-resume wakes the VM, and the
        /// spawn is resumed and gets the line (`vm_state` `suspended`).
        #[tokio::test]
        async fn hook_suspend_while_active_parks_with_no_socket() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { suspend_wait: ms(200), ..policy() });
                let (ctl, pump) = park_ctl(&rig, terms(60_000));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    let id = start_parking(&mut ws1).await;
                    rig.api.set_state(&rig.vm.id, VmState::Suspended);
                    put(&mut ws1, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-20T12:00:00Z".into(), reference: None }).await;
                    ws1.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
                    until(&told, "parked by the suspend", |t| t.parked() == 1).await;
                    let gets = rig.calls(|c| matches!(c, Call::Get(_)));
                    tokio::time::sleep(ms(500)).await;
                    assert_eq!(rig.endpoint.attempts().len(), 1, "no dial past suspend_wait");
                    assert!(rig.calls(|c| matches!(c, Call::Get(_))) > gets, "GetMicrovm watches for the VM running again");
                    assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "never resumed without input");
                    pump.line(Verdict::Busy, Some("user"));
                    input.send(SpawnInput::Stdin(b"wake\n".to_vec())).await.unwrap();
                    let mut ws2 = rig.endpoint.next().await;
                    let Frame::Hello { resume, .. } = next_frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id);
                    put(&mut ws2, &hello_ok_parks(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    echo(&mut ws2, &id, 1, "wake\n").await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws2, &id, 1, 2).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "suspended", .. }, ParkReport::Unparked { by: "user", vm_state: "suspended", .. }]), "{:?}", t.parks);
                assert!(t.links.is_empty(), "{:?}", t.links);
                assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "the endpoint's auto-resume woke it");
                assert_eq!(rig.api.state().vms[&rig.vm.id].state, VmState::Running);
            })
            .await;
        }

        /// The shim holds a spawn it never parked under its detach grace,
        /// which runs again once the VM runs. So when someone else resumes
        /// the VM of an idle session suspended before its park (no input
        /// here), the session reattaches within its GetMicrovm poll (3 s
        /// doubling to 60 s; 30 ms doubling to 600 ms here), past
        /// `suspend_wait` and with no exit 8, never resuming the VM itself;
        /// its `suspended` park is unparked (`by` `other`, the VM `running`).
        #[tokio::test]
        async fn an_idle_suspend_reattaches_once_the_vm_runs_again() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { suspend_wait: ms(200), ..policy() });
                let (ctl, _pump) = park_ctl(&rig, terms(60_000));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    let id = start_parking(&mut ws1).await;
                    suspend_under(&rig, &mut ws1).await;
                    until(&told, "parked by the suspend", |t| t.parked() == 1).await;
                    tokio::time::sleep(ms(400)).await;
                    assert_eq!(rig.endpoint.attempts().len(), 1, "no dial while the VM stays suspended");
                    rig.api.set_state(&rig.vm.id, VmState::Running);
                    let mut ws2 = redialed(&rig).await;
                    let Frame::Hello { resume, .. } = next_frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id);
                    put(&mut ws2, &hello_ok_parks(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    until(&told, "the unpark", |t| t.parks.len() == 2).await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws2, &id, 0, 1).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(matches!(&t.parks[..], [ParkReport::Parked { why: "suspended", .. }, ParkReport::Unparked { by: "other", vm_state: "running", .. }]), "{:?}", t.parks);
                assert!(t.links.is_empty(), "{:?}", t.links);
                assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "someone else resumed it");
                assert_eq!((rig.audit("session_park")[0]["detail"]["why"].as_str(), rig.audit("session_unpark")[0]["detail"]["by"].as_str()), (Some("suspended"), Some("other")));
            })
            .await;
        }

        /// A suspend mid-turn (the pump's verdict `Busy`: a line
        /// outstanding) is no park: the link goes down, as under S9's
        /// suspend, but with no `suspend_wait` and no exit 8. The poll backs
        /// off (3 s doubling to 60 s; 30 ms doubling to 600 ms here: a few
        /// GetMicrovm in 400 ms, never one every 30 ms). When someone else
        /// resumes the VM (no input), the session reattaches at its next
        /// poll, before the spawn's detach grace could run out: the link up
        /// again, an `agent_reconnect` (`suspended`), and the rest of the
        /// turn's output.
        #[tokio::test]
        async fn a_suspend_mid_turn_reattaches_once_the_vm_runs_again() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(RunPolicy { suspend_wait: ms(200), ..policy() });
                let (ctl, pump) = park_ctl(&rig, terms(100));
                pump.line(Verdict::Busy, Some("user"));
                let (sio, cio) = spawn_channels(8);
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                let told = Mutex::new(Told::default());
                let shim = async {
                    let mut ws1 = rig.endpoint.next().await;
                    let id = start_parking(&mut ws1).await;
                    suspend_under(&rig, &mut ws1).await;
                    until(&told, "the suspend's report", |t| !t.links.is_empty() || !t.parks.is_empty()).await;
                    {
                        let t = told.lock().unwrap();
                        assert!(t.links == [false] && t.parks.is_empty(), "the link down, no park: {:?} {:?}", t.links, t.parks);
                    }
                    let gets = rig.calls(|c| matches!(c, Call::Get(_)));
                    tokio::time::sleep(ms(400)).await;
                    assert_eq!(rig.endpoint.attempts().len(), 1, "no dial while the VM stays suspended");
                    let watched = rig.calls(|c| matches!(c, Call::Get(_))) - gets;
                    assert!(watched > 0, "GetMicrovm watches for the VM running again");
                    // At 30, 90 and 210 ms (then 450): at most a few, never one every 30 ms (about 13).
                    assert!(watched <= 5, "the watch's poll backs off: {watched} GetMicrovm in 400 ms");
                    rig.api.set_state(&rig.vm.id, VmState::Running);
                    let mut ws2 = redialed(&rig).await;
                    let Frame::Hello { resume, .. } = next_frame(&mut ws2).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id);
                    put(&mut ws2, &hello_ok_parks(vec![status(&id, 1, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    put(&mut ws2, &Frame::Stdout { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("the rest of the turn\n".into()), b64: None } }).await;
                    until(&told, "the turn's output", |t| t.stdout == b"the rest of the turn\n").await;
                    input.send(SpawnInput::StdinEof).await.unwrap();
                    exit_on_eof(&mut ws2, &id, 0, 2).await;
                };
                let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat_spec()), sio, None, ctl), consume_into(&mut events, &consumed, &told), shim);
                assert_eq!(result.unwrap().exit.status(), 0);
                let t = told.lock().unwrap();
                assert!(t.parks.is_empty(), "a turn at work is no park: {:?}", t.parks);
                assert_eq!(t.links, [false, true], "down while suspended, up once reattached");
                assert!(rig.audit("session_park").is_empty());
                let reconnects = rig.audit("agent_reconnect");
                assert_eq!(reconnects.len(), 1, "{reconnects:?}");
                assert_eq!(reconnects[0]["detail"]["reason"], "suspended");
                assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "someone else resumed it");
            })
            .await;
        }

        /// `stop_spawn` attaches with the resume (from the oldest output
        /// retained, which it drops), sends `signal TERM` to the group, and
        /// takes the spawn's `exit`, acked (the shim then releases it), for
        /// its end: `true`.
        #[tokio::test]
        async fn stop_spawn_attaches_signals_and_takes_the_exit() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let id = SpawnId::new_v7();
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    let Frame::Hello { resume, .. } = next_frame(&mut ws).await else { panic!("no hello") };
                    assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: None, err_from_seq: None }], "from the oldest retained");
                    put(&mut ws, &hello_ok(vec![status(&id, 2, 5)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    for seq in 1..=2 {
                        put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some("old\n".into()), b64: None } }).await;
                    }
                    assert_eq!(next_but_acks(&mut ws).await, Frame::Signal { spawn_id: id.clone(), sig: Sig::Term, scope: Scope::Group });
                    put(&mut ws, &exit0(&id, 3)).await;
                    loop {
                        if let Frame::Ack { seq: 3, .. } = next_frame(&mut ws).await {
                            break;
                        }
                    }
                };
                let (stopped, ()) = tokio::join!(stop_spawn(&env, &id, Duration::from_secs(3)), shim);
                assert!(stopped.unwrap(), "its exit came and was acked");
            })
            .await;
        }

        /// A spawn that ignores TERM gets KILL at half the bound and is
        /// gone at its exit (`true`); one that outlives the bound gets
        /// `detach{final}` (the shim's ladder ends it) and the answer is
        /// `false`, within the bound and the detach's close; a spawn the VM
        /// does not hold (`unknown`) is gone already (`true`).
        #[tokio::test]
        async fn stop_spawn_kills_at_half_its_bound_and_gives_up_at_it() {
            bounded(async {
                let rig = rig(true).await;
                let env = rig.env(policy());
                let id = SpawnId::new_v7();
                let within = ms(600);
                let began = Instant::now();
                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    assert!(matches!(next_frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    assert!(matches!(next_but_acks(&mut ws).await, Frame::Signal { sig: Sig::Term, .. }));
                    assert!(matches!(next_but_acks(&mut ws).await, Frame::Signal { sig: Sig::Kill, .. }));
                    assert!(began.elapsed() >= ms(300), "KILL at half the bound: {:?}", began.elapsed());
                    put(&mut ws, &exit0(&id, 1)).await;
                    loop {
                        if let Frame::Ack { seq: 1, .. } = next_frame(&mut ws).await {
                            break;
                        }
                    }
                };
                let (stopped, ()) = tokio::join!(stop_spawn(&env, &id, within), shim);
                assert!(stopped.unwrap(), "KILL ended it");

                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    assert!(matches!(next_frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                    let mut got = Vec::new();
                    loop {
                        match next_frame(&mut ws).await {
                            Frame::Detach { is_final, .. } => {
                                got.push(format!("detach final={is_final}"));
                                break;
                            }
                            Frame::Signal { sig, .. } => got.push(format!("{sig:?}")),
                            _ => {}
                        }
                    }
                    assert_eq!(got, ["Term", "Kill", "detach final=true"]);
                    ws
                };
                let t = Instant::now();
                let (stopped, _ws) = tokio::join!(stop_spawn(&env, &id, within), shim);
                assert!(!stopped.unwrap(), "no exit within the bound: not known gone");
                assert!(t.elapsed() < within + Duration::from_secs(3), "{:?}", t.elapsed());

                let shim = async {
                    let mut ws = rig.endpoint.next().await;
                    assert!(matches!(next_frame(&mut ws).await, Frame::Hello { .. }));
                    put(&mut ws, &hello_ok(vec![], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }])).await;
                    ws
                };
                let (stopped, _ws) = tokio::join!(stop_spawn(&env, &id, within), shim);
                assert!(stopped.unwrap(), "not on the VM: gone");
            })
            .await;
        }
    }
}
