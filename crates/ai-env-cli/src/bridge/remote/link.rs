//! The pump's link seam (S8 §2, contract C3) and its two factories. The pump
//! gets each child generation from a [`LinkFactory`]: [`LocalLinks`] spawns
//! the CLI on this Mac (`pump::spawn_local`, unchanged: `local-child`,
//! `local-scratch` and its S7 token delivery); [`RemoteLinks`] runs it in the
//! workspace's MicroVM. What a start is asked for ([`StartReq`]), each kind's
//! close ladder ([`CloseTimings`]), the payloads of the events a remote link
//! adds to `pump::ChildEvent` ([`RemoteStarted`], [`SpawnFailure`],
//! [`LinkLoss`]) and what the census and the registry take from it
//! ([`RemoteSnapshot`]) are frozen here.
//!
//! **A remote generation** is one task on the pump's `LocalSet`, started by
//! [`RemoteLinks`]' `start`, which returns the link at once:
//! - **pending**: it awaits the pre-spawn pipeline (`remote::pipeline::run`:
//!   the Touch ID, SELECT_VM, the workspace beside the gate and the token,
//!   the spawn handed to a session task). The link's first event is
//!   `Started` or `SpawnFailed`, so a pending start is a live child to the
//!   pump: its ladders run. A `Sig::Term` or `Sig::Kill` now drops the
//!   pipeline (the unseal's dialog dies with it) and reports a cancelled
//!   `SpawnFailed`;
//! - **the adapter**, once the pipeline handed over its session: the
//!   session's events become `ChildEvent`s (stdout chunks re-split into
//!   lines at the CLI's limit, each chunk marked consumed once its lines are
//!   handed over, never per line, so a line over the 8 MiB stdout window
//!   cannot stall it; stderr through its own bounded queue, raw, to the
//!   wrapper's stderr, dropped and counted when full; the VM's pid, notes and
//!   the link's state; the exit as both EOFs and a status, after the
//!   splitter's tail), the pump's input goes to the session in `CHUNK_MAX`
//!   pieces, and the pump's signals become frames: before `Started`
//!   `detach{final}` (the spawn then never goes out, or is ended by the
//!   shim's own ladder as it starts), after it `Sig::Term` is
//!   `Signal(Term)` plus `detach{final}` and `Sig::Kill` is `detach{final}`
//!   (L2). From `Started` to the exit, [`LinkFactory::drop_transport`] asks
//!   the session to drop its socket (`SpawnInput::DropSocket`): a loss it
//!   reattaches from by its reconnect rules (`Link(false)`, `Link(true)`).
//!   The session's end decides the last event: an error before
//!   `Started` is a `SpawnFailed` (`Failure::from_error`, at the spawn), one
//!   after it `Detached` when the wrapper sent the detach, else `Lost`. Until
//!   `Started` the pipeline's deadline holds (`PipelineEnd::started_by`):
//!   past it the start fails there (exit 8), detached. The first `Started`
//!   adds the census's `spawn` leg. The session runs as a task of its own,
//!   so a host that stops reading never stalls its pings. The S7 refusal
//!   watch reads the output ([`AuthWatch::for_session`]) and says `Rejected`.
//!
//! Nothing here awaits a send inside a `select!` arm: each direction keeps a
//! queue and offers its head through a `reserve()`, as the supervisor does,
//! so the two directions never block each other, the signals or the end.
use crate::bridge::agent::{spawn_channels, Consumed, ConsumerIo, DeliveryReport, RemoteExit, SpawnEvent, SpawnInput, SpawnIo, SpawnOutcome};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::authwatch::{AuthWatch, Stream as WatchStream, Verdict, AUTH_TIMERS, RETRY_LIMIT};
use crate::bridge::codeout::{CodeoutTrigger, FetchReport, BOX_REFS, CLOSE_WAIT};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::pump::{self, ChildEvent, ChildInput, ChildLink, ChildPlan, Sig, CHANNEL_CAP, EOF_HARD_STOP, EOF_KILL_AFTER, EOF_TERM_AFTER, PUMP_LINE_CAP, SIGTERM_HARD_STOP, SIGTERM_KILL_AFTER};
use crate::bridge::remote::pipeline::{self, PipelineEnd, SessionPlan};
use crate::bridge::remote::{audit_event, census_part, Failure, REMOTE_EOF_DETACH_AFTER_MS, REMOTE_HARD_STOP_MS};
use crate::bridge::setup_token::SetupToken;
use crate::errors::CliError;
use crate::wire::frame::{Deliver, Sig as WireSig, SpawnId, CHUNK_MAX};
use crate::wire::ndjson::LineSplitter;
use bytes::Bytes;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::os::unix::process::ExitStatusExt;
use std::pin::Pin;
use std::process::ExitStatus;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// While a remote start is pending, the pump keeps reading the host until
/// this many lines are queued for the child, or [`PENDING_IN_BYTES`] (plan
/// §2): a host EOF stays visible during a Touch ID or a cold boot, so the
/// close ladder holds. Past either it stops reading; the init deadline
/// bounds the wait. Both caps count the pump's own queue alone: the link's
/// input channel takes its `pump::CHANNEL_CAP` lines first, of any size, as
/// it does in every state (S8's TIMING-4, refuted: as designed).
pub const PENDING_IN_LINES: usize = 1024;
/// The bytes queued for the child that stop the pump's host reads during a
/// pending remote start: the pump's queue, the line that crosses the cap
/// kept whole, beside what the link's channel holds.
pub const PENDING_IN_BYTES: usize = 64 * 1024 * 1024;
/// The stdin pieces (each at most `CHUNK_MAX`) queued toward a remote
/// session; the session takes them while the shim's stdin window has room.
const INPUT_SLOTS: usize = 16;
/// The VM's stderr chunks queued for the wrapper's stderr: past this a chunk
/// is dropped (counted, and marked consumed so the session never waits on it).
pub const STDERR_QUEUE: usize = 64;
/// Before its last events (the exit's, or the end of the link) the adapter
/// gives the VM's stderr this long to reach the wrapper's, so the wrapper's
/// own final line comes after it.
pub const STDERR_DRAIN: Duration = Duration::from_millis(100);
/// The census end row's part naming the step a failed start stopped at
/// (`step:<StartStep::name>`), beside `remote::census_part`'s.
pub const STEP_PART: &str = "step";
/// The step a start cancelled while its pipeline ran is reported at: the
/// pipeline does not say how far it got, and P1, the Touch ID, is the step a
/// start waits on longest. A cancelled start's step is shown nowhere (no
/// census `step:` part, no line naming it).
const PENDING_STEP: StartStep = StartStep::TouchId;

/// Where the pump gets each child generation from. Object-safe: the pump
/// holds a `Box<dyn LinkFactory>`.
pub trait LinkFactory {
    /// Start generation `gen` (1, then 2 for a resume miss's retry) and
    /// return its link at once: never awaits. A local factory spawns the
    /// child here (an `Err` is a spawn that failed: exit 1,
    /// `EndReason::SpawnFailed`, as today). A remote one returns a link whose
    /// first event is `ChildEvent::Started` or `ChildEvent::SpawnFailed`
    /// while its pipeline (P1–P4) runs as a task on the pump's `LocalSet`
    /// (so it is called inside that `LocalSet`, as the pump's every start
    /// is): a pending start is a live child, so the close ladders run and a
    /// `Sig::Term` cancels it (dropping the pipeline before the spawn goes
    /// out, `detach{final}` after).
    fn start(&mut self, gen: u32, req: StartReq<'_>) -> std::io::Result<ChildLink>;

    /// Local or remote.
    fn kind(&self) -> LinkKind;

    /// The close ladder's rungs: [`CloseTimings::LOCAL`] or [`CloseTimings::REMOTE`].
    fn timings(&self) -> CloseTimings;

    /// The pump forwarded a `result` (after the mirror's fsync): a remote
    /// factory asks for a code-out (`codeout::CodeoutTrigger::request`,
    /// non-blocking and coalescing). A local one does nothing.
    fn on_result(&mut self) {}

    /// What the census end row and the registry row take from a remote link
    /// now; `None` for a local one.
    fn snapshot(&self) -> Option<RemoteSnapshot> {
        None
    }

    /// `ai-env session drop-transport` (T8.6): the wrapper got
    /// `registry::DROP_TRANSPORT_SIGNAL`. A remote factory closes its live
    /// link's socket from the wrapper's side, and the session reattaches
    /// (`ChildEvent::Link(false)`, then `Link(true)`), never an exit; a local
    /// one, or a remote one with no spawn running, does nothing.
    fn drop_transport(&mut self) {}

    /// The pump made `session_id` the session's (a `system/init` it adopted;
    /// S8 W8, added to C3): a remote factory hands it to its live code-out
    /// trigger (an init reaches the pump only after its generation's
    /// `Started`), so the settings' start capture and each turn's go to that
    /// session's quarantine (T8.7). A local one does nothing.
    fn session_adopted(&mut self, session_id: &str) {
        let _ = session_id;
    }

    /// The wrapper is about to exit (S8 W1, added to C3): the supervisor
    /// finished and the census end row is written. A remote factory waits,
    /// at most `budget` (what is left of the hard stop), for its live
    /// session to end (its `detach{final}` sent, the best-effort suspend the
    /// session task fires after it, L2) and for the code-out trigger's close
    /// (`codeout::CLOSE_WAIT`), which that suspend waits for (plan §11). A
    /// local one is done at once.
    fn close(&mut self, budget: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
        let _ = budget;
        Box::pin(std::future::ready(()))
    }
}

/// The local factory: each start is `pump::spawn_local` of the session's
/// child plan, with the S7 token when `local-scratch` holds one.
#[derive(Debug)]
pub struct LocalLinks {
    plan: ChildPlan,
}

impl LocalLinks {
    /// The factory of a `local-child` or `local-scratch` session's `plan`.
    #[must_use]
    pub fn new(plan: ChildPlan) -> LocalLinks {
        LocalLinks { plan }
    }
}

impl LinkFactory for LocalLinks {
    fn start(&mut self, _gen: u32, req: StartReq<'_>) -> std::io::Result<ChildLink> {
        pump::spawn_local(&self.plan, req.credential)
    }

    fn kind(&self) -> LinkKind {
        LinkKind::Local
    }

    fn timings(&self) -> CloseTimings {
        CloseTimings::LOCAL
    }
}

/// One generation's pre-spawn pipeline, as the remote factory runs it
/// (`remote::pipeline::run`): a refusal is the link's first event.
pub type PipelineRun = Pin<Box<dyn Future<Output = Result<PipelineEnd, SpawnFailure>>>>;

/// How the remote factory starts a generation's pipeline: `gen`, why, and
/// the session's side of the generation's channels.
pub type PipelineFn = Box<dyn FnMut(u32, StartWhy, SpawnIo) -> PipelineRun>;

/// The remote factory: each [`LinkFactory::start`] makes the generation's
/// channels (`agent::spawn_channels`) and runs, as a task on the pump's
/// `LocalSet`, `remote::pipeline::run` with the session's side, then the
/// adapter over the consumer's side (the module doc). The pipeline's `Err` is
/// the link's first event (`ChildEvent::SpawnFailed`); its `PipelineEnd`
/// gives the snapshot's VM and legs, the code-out trigger
/// [`LinkFactory::on_result`] asks, and the session task whose end maps to
/// `Lost` or `Detached` (a refusal before `Started`: `SpawnFailed` by
/// `Failure::from_error(StartStep::Spawn, …)`).
pub struct RemoteLinks {
    paths: Paths,
    pipeline: PipelineFn,
    shared: Rc<RefCell<Shared>>,
    /// The generations' tasks not known to have ended ([`LinkFactory::close`] awaits them).
    tasks: Vec<JoinHandle<()>>,
    /// P0's plan, whose tasks outlive a generation (the closing suspend, a
    /// snapshot a dropped start left: `SessionPlan::take_closing`), for
    /// [`LinkFactory::close`]; `None` with a test's own pipeline.
    plan: Option<Rc<SessionPlan>>,
}

impl RemoteLinks {
    /// The factory of one wrapper's remote session, on `plan` (P0's).
    #[must_use]
    pub fn new(plan: Rc<SessionPlan>) -> RemoteLinks {
        let paths = plan.paths.clone();
        let run = Rc::clone(&plan);
        let mut links = RemoteLinks::with_pipeline(paths, Box::new(move |gen, why, io| Box::pin(pipeline::run(Rc::clone(&run), gen, why, io))));
        links.plan = Some(plan);
        links
    }

    /// The factory with `pipeline` in place of `remote::pipeline::run`: the
    /// seam a test puts the pre-spawn steps aside with, handing the link a
    /// session of its own; `paths` for the audit rows and the VM rows the
    /// adapter reads.
    #[must_use]
    pub fn with_pipeline(paths: Paths, pipeline: PipelineFn) -> RemoteLinks {
        RemoteLinks { paths, pipeline, shared: Rc::new(RefCell::new(Shared::default())), tasks: Vec::new(), plan: None }
    }
}

impl LinkFactory for RemoteLinks {
    fn start(&mut self, gen: u32, req: StartReq<'_>) -> std::io::Result<ChildLink> {
        if req.credential.is_some() {
            // Never: a remote start's pipeline unseals and delivers its own (D1); a token here goes nowhere.
            tracing::warn!(gen, "a remote start was handed a token: not used");
        }
        let (io, consumer) = spawn_channels(INPUT_SLOTS);
        let (input, input_rx) = mpsc::channel(CHANNEL_CAP);
        let (signal, signal_rx) = mpsc::unbounded_channel();
        let (events_tx, events) = mpsc::channel(CHANNEL_CAP);
        // A retry once the host's `initialize` was answered comes after `init_ms`: its steps are no census legs.
        let counts_legs = !matches!(req.why, StartWhy::ResumeRetry { init_answered: true, .. });
        let run = (self.pipeline)(gen, req.why, io);
        let ends = PumpEnds { input: input_rx, signal: signal_rx, events: events_tx };
        self.tasks.retain(|t| !t.is_finished());
        self.tasks.push(tokio::task::spawn_local(generation(gen, run, counts_legs, ends, consumer, Rc::clone(&self.shared), self.paths.clone())));
        Ok(ChildLink { pid: None, input, signal, events })
    }

    fn kind(&self) -> LinkKind {
        LinkKind::Remote
    }

    fn timings(&self) -> CloseTimings {
        CloseTimings::REMOTE
    }

    fn on_result(&mut self) {
        let mut shared = self.shared.borrow_mut();
        shared.count_fetch();
        if let Some(trigger) = &shared.trigger {
            trigger.request();
        }
    }

    fn snapshot(&self) -> Option<RemoteSnapshot> {
        let mut shared = self.shared.borrow_mut();
        shared.count_fetch();
        let mut snap = shared.snap.clone();
        if shared.delivery.as_ref().is_some_and(DeliveryReport::held_by_vm) {
            // The VM's cache held the token and the session sent none: that copy served the CLI.
            snap.credential = Some(crate::bridge::agent::credential::CACHED);
        }
        Some(snap)
    }

    /// The running spawn's session drops its socket (`SpawnInput::DropSocket`)
    /// and reattaches by its reconnect rules; nothing while none runs.
    fn drop_transport(&mut self) {
        let shared = self.shared.borrow();
        match &shared.control {
            Some(control) if control.send(SpawnInput::DropSocket).is_ok() => tracing::info!("drop-transport: the remote session closes its socket and reattaches"),
            _ => tracing::info!("drop-transport: no remote spawn runs: nothing to drop"),
        }
    }

    /// The live generation's trigger captures the settings of `session_id` (T8.7).
    fn session_adopted(&mut self, session_id: &str) {
        if let Some(trigger) = &self.shared.borrow().trigger {
            trigger.set_session(session_id);
        }
    }

    fn close(&mut self, budget: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
        let tasks = std::mem::take(&mut self.tasks);
        let trigger = self.shared.borrow_mut().trigger.take();
        let plan = self.plan.clone();
        Box::pin(async move {
            let sessions = async {
                for task in tasks {
                    let _ = task.await;
                }
                // Once every session ended, what it left is known: L2's closing suspend (started as
                // its exit arrived, it fires once the trigger below is closed and done) and the WIP
                // snapshot of a start dropped during its Touch ID.
                for task in plan.map(|p| p.take_closing()).unwrap_or_default() {
                    let _ = task.await;
                }
            };
            let fetch = async {
                if let Some(trigger) = trigger {
                    let _ = trigger.close(CLOSE_WAIT).await;
                }
            };
            if tokio::time::timeout(budget, async { tokio::join!(sessions, fetch) }).await.is_err() {
                tracing::info!(budget_ms = budget.as_millis() as u64, "the remote session did not end within the close budget: left to the shim's ladder");
            }
        })
    }
}

/// What the remote factory and its generations share (all on the pump's
/// `LocalSet`; never borrowed across an await).
#[derive(Debug, Default)]
struct Shared {
    snap: RemoteSnapshot,
    /// The live generation's code-out trigger (its `PipelineEnd`'s).
    trigger: Option<CodeoutTrigger>,
    /// What became of the live generation's token (its `PipelineEnd`'s):
    /// the snapshot's credential word is `cached` while the VM's cache
    /// served it and nothing was sent.
    delivery: Option<DeliveryReport>,
    /// The last code-out report counted in `snap`'s fetch counts.
    counted: Option<FetchReport>,
    /// The running spawn's session control, from its `Started` to its exit
    /// or its session's end: where [`LinkFactory::drop_transport`] goes.
    control: Option<mpsc::UnboundedSender<SpawnInput>>,
}

impl Shared {
    /// Count the trigger's last report when it is one not counted yet (a
    /// fetch a later one replaced between two looks is not counted).
    fn count_fetch(&mut self) {
        let report = self.trigger.as_ref().and_then(CodeoutTrigger::last);
        self.count(report);
    }

    /// [`Shared::count_fetch`]'s rule over `report`, the trigger's last.
    fn count(&mut self, report: Option<FetchReport>) {
        let Some(report) = report else { return };
        if self.counted.as_ref() == Some(&report) {
            return;
        }
        self.snap.fetch_runs += 1;
        if report.ok {
            self.snap.fetch_ok += 1;
        }
        // Snapshots are named `refs/wip/<UTC time>-<n>`: the greatest is the newest.
        if let Some(wip) = report.promoted.keys().filter(|r| r.strip_prefix(BOX_REFS).is_some_and(|n| n.starts_with("wip/"))).max() {
            self.snap.last_wip_fetch = Some(wip.clone());
        }
        self.counted = Some(report);
    }
}

/// The pump's ends of one generation's link, as its task holds them.
struct PumpEnds {
    input: mpsc::Receiver<ChildInput>,
    signal: mpsc::UnboundedReceiver<Sig>,
    events: mpsc::Sender<ChildEvent>,
}

/// How a pending start ended.
enum Pending {
    /// A signal (`true`), or the pump let the link go (`false`).
    Stopped(bool),
    /// Boxed: a pipeline's end is many times a stop's size.
    Done(Box<Result<PipelineEnd, SpawnFailure>>),
}

/// One remote generation: the pending start, then the adapter (the module
/// doc). `counts_legs`: its steps lead to the session's `init_ms` and add to
/// the census's legs ([`add_leg`]): generation 1's, and a resume miss's
/// retry while the host's `initialize` is unanswered.
async fn generation(gen: u32, run: PipelineRun, counts_legs: bool, mut ends: PumpEnds, consumer: ConsumerIo, shared: Rc<RefCell<Shared>>, paths: Paths) {
    let mut run = run;
    let pending = tokio::select! {
        biased;
        s = ends.signal.recv() => Pending::Stopped(s.is_some()),
        r = &mut run => Pending::Done(Box::new(r)),
    };
    let end = match pending {
        Pending::Stopped(asked) => {
            // Dropped before the spawn went out: an unseal's age group, and its dialog, die with it.
            drop(run);
            tracing::info!(gen, "the remote start was stopped while its pipeline ran: nothing was started");
            if asked {
                let _ = ends.events.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(PENDING_STEP, None))).await;
            }
            return;
        }
        Pending::Done(done) => match *done {
            Err(failure) => {
                tracing::warn!(gen, step = failure.step.name(), code = failure.code, "the remote start failed");
                if failure.vm.is_some() {
                    shared.borrow_mut().snap.vm.clone_from(&failure.vm);
                }
                let _ = ends.events.send(ChildEvent::SpawnFailed(failure)).await;
                return;
            }
            Ok(end) => end,
        },
    };
    let PipelineEnd { vm, vm_how, legs, seed, transcript, seeded_head, credential, delivery, spawn_id, started_by, trigger, session } = end;
    let handed = tokio::time::Instant::now();
    tracing::info!(gen, vm = %vm, how = vm_how, spawn = %spawn_id, "the remote spawn went to its session");
    {
        let mut s = shared.borrow_mut();
        // A new spawn: nothing of the last one's (its pid, claude, marks, link, control) is this one's.
        s.snap.vm_pid = None;
        s.snap.claude = None;
        s.snap.auth_timers = None;
        s.snap.last_acked_seq = 0;
        s.snap.link_up = false;
        s.control = None;
        s.snap.credential = credential;
        s.delivery = delivery;
        s.snap.vm = Some(vm.clone());
        s.snap.vm_how = Some(vm_how);
        if counts_legs {
            // Generation 1's into none yet; a retry the host waits on adds its own: both lead to `init_ms`.
            for (leg, ms) in legs {
                add_leg(&mut s.snap.legs, leg, ms);
            }
        }
        s.snap.seed = Some(seed);
        s.snap.transcript = transcript;
        s.snap.seeded_head = seeded_head;
        s.snap.spawn = Some(spawn_id);
        if let Some(old) = s.trigger.replace(trigger) {
            // A replaced generation's trigger (the resume miss's first): closed in the background.
            tokio::task::spawn_local(async move {
                let _ = old.close(CLOSE_WAIT).await;
            });
        }
    }
    Adapter::new(gen, vm, paths, shared, ends, consumer).run(session, handed, started_by, counts_legs).await;
}

/// `ms` added to `leg` in `legs`, or `leg` appended (S8 phase 4): a resume
/// miss's retry adds its steps to generation 1's, whose order
/// (`remote::LEG_NAMES`) they keep.
fn add_leg(legs: &mut Vec<(&'static str, u64)>, leg: &'static str, ms: u64) {
    match legs.iter_mut().find(|(l, _)| *l == leg) {
        Some((_, total)) => *total = total.saturating_add(ms),
        None => legs.push((leg, ms)),
    }
}

/// What the adapter queues for the pump: an event, or the stdout seq to mark
/// consumed once every event before it was handed over.
#[derive(Debug)]
enum Out {
    Event(ChildEvent),
    Mark(u64),
}

/// One pump input on its way to the session, in `CHUNK_MAX` pieces.
#[derive(Debug)]
enum Staged {
    Line { bytes: Bytes, at: usize },
    Eof,
}

/// The next piece of `staged` for the session (what is left stays staged).
fn next_piece(staged: &mut Option<Staged>) -> Option<SpawnInput> {
    match staged.take()? {
        Staged::Eof => Some(SpawnInput::StdinEof),
        Staged::Line { bytes, at } => {
            let end = (at + CHUNK_MAX).min(bytes.len());
            let piece = SpawnInput::Stdin(bytes[at..end].to_vec());
            if end < bytes.len() {
                *staged = Some(Staged::Line { bytes, at: end });
            }
            Some(piece)
        }
    }
}

/// What woke the adapter (its `select!` arms touch disjoint fields; the rest
/// happens on this value afterwards, as in the supervisor).
enum Wake {
    Signal(Option<Sig>),
    /// The generation's deadline passed before `Started`.
    Deadline,
    Ended(Result<SpawnOutcome, BridgeError>),
    Delivered,
    PumpGone,
    Session(Option<SpawnEvent>),
    Input(Option<ChildInput>),
    Fed,
    SessionInputClosed,
}

/// The session's end as a result: a task that panicked or was aborted is a
/// transport failure.
fn joined(r: Result<Result<SpawnOutcome, BridgeError>, tokio::task::JoinError>) -> Result<SpawnOutcome, BridgeError> {
    r.unwrap_or_else(|e| Err(BridgeError::Transport(format!("the session task ended: {e}"))))
}

/// The status a remote exit is to the pump: the code (as a wait status), the
/// signal, or exit 1 when the shim reported neither (`RemoteExit::status`).
fn exit_status(exit: &RemoteExit) -> ExitStatus {
    match (exit.code, exit.signal) {
        (Some(code), _) => ExitStatus::from_raw((code & 0xff) << 8),
        (None, Some(sig)) => ExitStatus::from_raw(sig & 0x7f),
        (None, None) => ExitStatus::from_raw(1 << 8),
    }
}

/// The adapter between one remote generation's session and the pump (the module doc).
struct Adapter {
    gen: u32,
    vm: String,
    paths: Paths,
    shared: Rc<RefCell<Shared>>,
    // The pump's side.
    input: mpsc::Receiver<ChildInput>,
    input_open: bool,
    signal: mpsc::UnboundedReceiver<Sig>,
    signal_open: bool,
    events: mpsc::Sender<ChildEvent>,
    /// The pump dropped the link's events: what is queued for it goes nowhere.
    pump_gone: bool,
    // The session's side.
    to_session: mpsc::Sender<SpawnInput>,
    control: mpsc::UnboundedSender<SpawnInput>,
    from_session: mpsc::UnboundedReceiver<SpawnEvent>,
    session_open: bool,
    consumed: Arc<Consumed>,
    // In between.
    out: VecDeque<Out>,
    staged: Option<Staged>,
    eof_sent: bool,
    split: LineSplitter,
    /// stdout bytes pushed into the splitter since it was last asked for a line.
    unsplit: usize,
    stderr: Option<mpsc::Sender<(u64, Vec<u8>)>>,
    stderr_task: Option<JoinHandle<()>>,
    stderr_dropped: u64,
    watch: Option<AuthWatch>,
    rejected: bool,
    started: bool,
    /// A stop came before `Started` (the detach then cancels the start).
    stop_asked: bool,
    detach_sent: bool,
    exit: Option<RemoteExit>,
    /// When the pipeline handed the spawn over (the `spawn` leg runs from
    /// here to `Started`), and by when `Started` must come.
    handed: tokio::time::Instant,
    started_by: Option<tokio::time::Instant>,
    /// The `spawn` leg counts toward the census's legs (the generation's
    /// `counts_legs`).
    counts_legs: bool,
    /// The deadline passed before `Started`: the link reported its failure
    /// and detached; nothing the session says after it reaches the pump.
    gave_up: bool,
}

impl Adapter {
    fn new(gen: u32, vm: String, paths: Paths, shared: Rc<RefCell<Shared>>, ends: PumpEnds, consumer: ConsumerIo) -> Adapter {
        let PumpEnds { input, signal, events } = ends;
        let ConsumerIo { input: to_session, control, events: from_session, consumed } = consumer;
        let (stderr, stderr_rx) = mpsc::channel(STDERR_QUEUE);
        let stderr_task = tokio::task::spawn_local(stderr_copy(stderr_rx, Arc::clone(&consumed)));
        Adapter {
            gen,
            vm,
            paths,
            shared,
            input,
            input_open: true,
            signal,
            signal_open: true,
            events,
            pump_gone: false,
            to_session,
            control,
            from_session,
            session_open: true,
            consumed,
            out: VecDeque::new(),
            staged: None,
            eof_sent: false,
            split: LineSplitter::with_cap(PUMP_LINE_CAP),
            unsplit: 0,
            stderr: Some(stderr),
            stderr_task: Some(stderr_task),
            stderr_dropped: 0,
            watch: None,
            rejected: false,
            started: false,
            stop_asked: false,
            detach_sent: false,
            exit: None,
            handed: tokio::time::Instant::now(),
            started_by: None,
            counts_legs: true,
            gave_up: false,
        }
    }

    /// Run the generation from the hand-over (`handed`) to the session's
    /// end; `started_by`: the pipeline's deadline, held until `Started`;
    /// `counts_legs`: its `spawn` leg adds to the census's.
    async fn run(mut self, mut session: JoinHandle<Result<SpawnOutcome, BridgeError>>, handed: tokio::time::Instant, started_by: Option<tokio::time::Instant>, counts_legs: bool) {
        self.handed = handed;
        self.started_by = started_by;
        self.counts_legs = counts_legs;
        let mut ended: Option<Result<SpawnOutcome, BridgeError>> = None;
        loop {
            self.settle_out();
            if ended.is_some() && !self.session_open && (self.out.is_empty() || self.pump_gone) {
                break;
            }
            // Backpressure: the session's events wait in its channel (at most the shim's window) while two are queued here.
            let read_session = self.session_open && ended.is_none() && self.out.len() < 2;
            let deadline = self.started_by.filter(|_| !self.started && !self.stop_asked && !self.gave_up && ended.is_none());
            let wake = tokio::select! {
                biased;
                s = self.signal.recv(), if self.signal_open => Wake::Signal(s),
                () = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => Wake::Deadline,
                r = &mut session, if ended.is_none() => Wake::Ended(joined(r)),
                p = self.events.reserve(), if !self.out.is_empty() && !self.pump_gone => match p {
                    Ok(p) => {
                        match self.out.pop_front() {
                            Some(Out::Event(ev)) => p.send(ev),
                            Some(mark) => self.out.push_front(mark),
                            None => {}
                        }
                        Wake::Delivered
                    }
                    Err(_) => Wake::PumpGone,
                },
                ev = self.from_session.recv(), if read_session => Wake::Session(ev),
                item = self.input.recv(), if self.input_open && self.staged.is_none() => Wake::Input(item),
                p = self.to_session.reserve(), if self.staged.is_some() => match p {
                    Ok(p) => {
                        if let Some(piece) = next_piece(&mut self.staged) {
                            if matches!(piece, SpawnInput::StdinEof) {
                                self.eof_sent = true;
                            }
                            p.send(piece);
                        }
                        Wake::Fed
                    }
                    Err(_) => Wake::SessionInputClosed,
                },
                // Never: the session's end, or a queued event once it ended, is always awaited.
                else => Wake::PumpGone,
            };
            match wake {
                Wake::Signal(s) => self.on_signal(s),
                Wake::Deadline => self.give_up(),
                Wake::Ended(r) => {
                    match &r {
                        Ok(o) => tracing::info!(gen = self.gen, spawn = %o.spawn_id, "the remote session ended with its exit"),
                        Err(e) => tracing::info!(gen = self.gen, "the remote session ended: {e}"),
                    }
                    ended = Some(r);
                    // Every event the session sent is in its channel by now (its task's end follows each send).
                    while let Ok(ev) = self.from_session.try_recv() {
                        self.on_session(ev).await;
                    }
                    self.session_open = false;
                }
                Wake::Delivered | Wake::Fed => {}
                Wake::PumpGone => {
                    tracing::debug!(gen = self.gen, "the pump let the link's events go");
                    self.pump_gone = true;
                }
                Wake::Session(Some(ev)) => self.on_session(ev).await,
                Wake::Session(None) => self.session_open = false,
                Wake::Input(Some(ChildInput::Line(bytes))) => self.staged = Some(Staged::Line { bytes, at: 0 }),
                Wake::Input(Some(ChildInput::Eof)) => self.staged = Some(Staged::Eof),
                Wake::Input(None) => {
                    // The pump let the link's input go: the child's stdin ends, as a local child's pipe does.
                    self.input_open = false;
                    if !self.eof_sent {
                        self.staged = Some(Staged::Eof);
                    }
                }
                Wake::SessionInputClosed => {
                    self.staged = None;
                    self.input_open = false;
                }
            }
        }
        if let Some(r) = ended {
            self.finish(r).await;
        }
    }

    /// The pump's signal (L2): before `Started` any of them cancels the
    /// start (`detach{final}`); after it `Term` is `Signal(Term)` plus
    /// `detach{final}`, `Kill` the detach alone. A pump that let the link go
    /// leaves no spawn running behind it: the detach goes, unless the exit
    /// came already.
    fn on_signal(&mut self, s: Option<Sig>) {
        let Some(sig) = s else {
            self.signal_open = false;
            if self.exit.is_none() {
                self.stop_asked |= !self.started;
                self.detach();
            }
            return;
        };
        tracing::info!(gen = self.gen, ?sig, started = self.started, "a stop for the remote child");
        if !self.started {
            self.stop_asked = true;
        } else if sig == Sig::Term {
            let _ = self.control.send(SpawnInput::Signal(WireSig::Term));
        }
        self.detach();
    }

    /// `detach{final}`, once.
    fn detach(&mut self) {
        if !self.detach_sent {
            self.detach_sent = true;
            let _ = self.control.send(SpawnInput::Detach { is_final: true });
        }
    }

    /// The generation's deadline passed before `Started` (plan §3: P4 ends
    /// at `spawned`): the start failed at the spawn (exit 8, `Deadline`),
    /// audited as the pipeline audits its own deadline; `detach{final}` so
    /// the spawn never runs on (the session's `no_pending_detach`, or the
    /// shim's ladder as it starts). The session is left to end on its own.
    fn give_up(&mut self) {
        let step = StartStep::Spawn;
        let failure = Failure::Deadline { code: pipeline::deadline_code(step), step: step.name() };
        tracing::warn!(gen = self.gen, step = step.name(), "the remote spawn did not start by the deadline");
        self.audit_failure(StartStep::Deadline, &failure);
        self.push(ChildEvent::SpawnFailed(SpawnFailure::from_failure(StartStep::Deadline, &failure, Some(self.vm.clone()))));
        self.gave_up = true;
        self.detach();
    }

    /// The audit row of a start that failed after the pipeline handed it
    /// over (the pipeline audits its own, the pump P0's), in the pipeline's
    /// shape: one row per failed start.
    fn audit_failure(&self, step: StartStep, failure: &Failure) {
        let detail = [("gen", self.gen.to_string()), ("step", step.name().to_string()), ("code", failure.exit_code().to_string()), ("why", failure.word().to_string()), ("id", self.vm.clone())];
        if let Err(e) = audit::append(&self.paths.audit(), &AuditRow::new(audit_event::SESSION_REMOTE_FAILED, None, audit::detail(&detail))) {
            tracing::warn!("audit {}: {e}", audit_event::SESSION_REMOTE_FAILED);
        }
    }

    /// stdout seq `seq` is handed over (every event before it was).
    fn mark(&self, seq: u64) {
        self.consumed.stdout_done(seq);
        let mut s = self.shared.borrow_mut();
        s.snap.last_acked_seq = s.snap.last_acked_seq.max(seq);
    }

    /// The marks at the queue's head; with the pump gone, everything (its
    /// events go nowhere, and the session must not wait for their marks).
    fn settle_out(&mut self) {
        while let Some(front) = self.out.front() {
            match front {
                Out::Mark(seq) => {
                    let seq = *seq;
                    self.out.pop_front();
                    self.mark(seq);
                }
                Out::Event(_) if self.pump_gone => {
                    self.out.pop_front();
                }
                Out::Event(_) => break,
            }
        }
    }

    fn push(&mut self, ev: ChildEvent) {
        // Past the deadline the link's last event went: nothing follows it.
        if !self.gave_up {
            self.out.push_back(Out::Event(ev));
        }
    }

    /// Show the refusal watch what the CLI printed; its verdict, once, is `Rejected`.
    fn watch(&mut self, stream: WatchStream, bytes: &[u8]) {
        let Some(w) = &mut self.watch else { return };
        if w.feed(stream, bytes) == Verdict::Rejected && !self.rejected {
            self.rejected = true;
            let how = w.verdict_how().unwrap_or("text");
            tracing::warn!(gen = self.gen, how, "the delivered setup-token was refused (the VM's claude said so)");
            self.push(ChildEvent::Rejected { how });
        }
    }

    async fn on_session(&mut self, ev: SpawnEvent) {
        match ev {
            SpawnEvent::Started { spawn_id, pid, claude_version, .. } => self.on_started(spawn_id, pid, claude_version),
            SpawnEvent::Stdout { seq, bytes } => {
                self.unsplit += bytes.len();
                // Only a chunk with a newline can end a line (or one past the cap end the discard): the
                // splitter is asked for lines then, so a long line is not scanned again at every chunk.
                let ends_one = bytes.contains(&b'\n') || self.unsplit > PUMP_LINE_CAP;
                self.split.push(&bytes);
                if ends_one {
                    self.unsplit = 0;
                    while let Some(r) = self.split.next_line() {
                        self.push(pump::line_event(r));
                    }
                }
                self.watch(WatchStream::Stdout, &bytes);
                self.out.push_back(Out::Mark(seq));
            }
            SpawnEvent::Stderr { seq, bytes, .. } => {
                self.watch(WatchStream::Stderr, &bytes);
                let len = bytes.len() as u64;
                let refused = match &self.stderr {
                    Some(tx) => tx.try_send((seq, bytes)).is_err(),
                    None => true,
                };
                if refused {
                    // Full (the wrapper's stderr is not read fast enough): dropped and counted, never waited for.
                    self.stderr_dropped += len;
                    self.consumed.stderr_done(seq);
                }
            }
            // Before `Started` (a socket lost while the spawn was on its way) they stay off the
            // link, whose first event is `Started` or `SpawnFailed`: logged, and counted.
            SpawnEvent::Note(text) if !self.started => tracing::info!(gen = self.gen, "remote link: {text}"),
            SpawnEvent::Note(text) => self.push(ChildEvent::Note(text)),
            SpawnEvent::Link(up) => {
                {
                    let mut s = self.shared.borrow_mut();
                    s.snap.link_up = up;
                    if !up {
                        s.snap.link_drops += 1;
                    }
                }
                if self.started {
                    self.push(ChildEvent::Link(up));
                }
            }
            SpawnEvent::Exit(exit) => self.on_exit(exit).await,
        }
    }

    /// `spawned` (or the reattach that found the spawn running): the VM's
    /// pid and claude (the VM's row when the frame named none), compared
    /// with `AUTH_TIMERS` for the refusal watch.
    fn on_started(&mut self, spawn_id: SpawnId, pid: u32, claude_version: Option<String>) {
        if self.gave_up {
            return;
        }
        let first = !self.started;
        self.started = true;
        let claude = claude_version.or_else(|| crate::bridge::vm::registry::read_row(&self.paths, &self.vm).ok().flatten().and_then(|r| r.claude_version));
        let measured = claude.as_deref() == Some(AUTH_TIMERS.claude);
        self.watch = Some(AuthWatch::for_session(measured));
        let timers = if measured { "match".to_string() } else { format!("unmeasured({})", claude.as_deref().unwrap_or("unknown")) };
        tracing::info!(gen = self.gen, spawn = %spawn_id, vm_pid = pid, claude = claude.as_deref().unwrap_or("unknown"), auth_timers = %timers, "the remote spawn started");
        {
            let mut s = self.shared.borrow_mut();
            s.snap.spawn = Some(spawn_id.clone());
            s.snap.vm_pid = Some(pid);
            s.snap.claude.clone_from(&claude);
            s.snap.auth_timers = Some(timers);
            s.snap.link_up = true;
            s.control = Some(self.control.clone());
            if first && self.counts_legs {
                // The census's last leg: from the hand-over to `spawned` (a reattach's `Started` is no new one;
                // a retry's adds to generation 1's).
                add_leg(&mut s.snap.legs, "spawn", u64::try_from(self.handed.elapsed().as_millis()).unwrap_or(u64::MAX));
            }
        }
        if first && !measured {
            // Once per claude version on this Mac (S8 §12): the watch counts the retry rule only.
            pipeline::audit_auth_timers(&self.paths, claude.as_deref().unwrap_or("unknown"));
        }
        self.push(ChildEvent::Started(RemoteStarted { spawn_id, vm_pid: pid, claude_version: claude }));
    }

    /// This spawn leaves [`LinkFactory::drop_transport`]'s reach (its exit
    /// came, or its session ended); a later generation's control stays.
    fn release_control(&self) {
        let mut s = self.shared.borrow_mut();
        if s.control.as_ref().is_some_and(|c| c.same_channel(&self.control)) {
            s.control = None;
        }
    }

    /// The exit: the splitter's tail, the refusal watch's exit rule, stdout's
    /// EOF, the VM's stderr given [`STDERR_DRAIN`], stderr's EOF, the status.
    async fn on_exit(&mut self, exit: RemoteExit) {
        if self.exit.is_some() {
            return;
        }
        self.exit = Some(exit);
        self.release_control();
        if let Some(r) = self.split.finish() {
            self.push(pump::line_event(r));
        }
        if let Some(w) = self.watch.as_mut().filter(|_| !self.rejected) {
            if w.rejected_at_exit(exit.code) {
                self.rejected = true;
                let how = if w.retries() >= RETRY_LIMIT { "retries" } else { "text" };
                self.push(ChildEvent::Rejected { how });
            }
        }
        if exit.stderr_dropped > 0 || self.stderr_dropped > 0 {
            tracing::warn!(gen = self.gen, shim_and_session = exit.stderr_dropped, here = self.stderr_dropped, "bytes of the VM's stderr were dropped");
        }
        tracing::info!(gen = self.gen, code = ?exit.code, signal = ?exit.signal, "the remote child exited");
        self.push(ChildEvent::StdoutEof);
        self.drain_stderr().await;
        self.push(ChildEvent::StderrEof);
        self.push(ChildEvent::Exit(Some(exit_status(&exit))));
    }

    /// The VM's stderr queue closed and written out, within [`STDERR_DRAIN`].
    async fn drain_stderr(&mut self) {
        self.stderr = None;
        if let Some(task) = self.stderr_task.take() {
            let _ = tokio::time::timeout(STDERR_DRAIN, task).await;
        }
    }

    /// The session ended (`r`): the last event, then everything queued
    /// handed over (marked, with the pump gone).
    async fn finish(mut self, r: Result<SpawnOutcome, BridgeError>) {
        self.release_control();
        match r {
            // The exit's events are queued already; a session that ended without one (never) gets them here.
            Ok(outcome) => self.on_exit(outcome.exit).await,
            // Past the deadline the failure was reported (and audited) already.
            Err(_) if self.exit.is_some() || self.gave_up => {}
            Err(e) => {
                self.drain_stderr().await;
                let ev = if !self.started {
                    let failure = if self.stop_asked { SpawnFailure::stopped(StartStep::Spawn, Some(self.vm.clone())) } else { self.refused(e) };
                    ChildEvent::SpawnFailed(failure)
                } else if self.detach_sent {
                    ChildEvent::Detached
                } else {
                    let code = CliError::from(e).exit_code();
                    let loss = LinkLoss::from_failure(&Failure::LinkLost { vm: self.vm.clone() });
                    ChildEvent::Lost(LinkLoss { code: if code == 7 { 7 } else { loss.code }, ..loss })
                };
                tracing::info!(gen = self.gen, event = ev.kind(), "the remote link ended");
                self.push(ev);
            }
        }
        loop {
            self.settle_out();
            if self.out.is_empty() {
                break;
            }
            match self.events.reserve().await {
                Ok(p) => {
                    if let Some(Out::Event(ev)) = self.out.pop_front() {
                        p.send(ev);
                    }
                }
                Err(_) => self.pump_gone = true,
            }
        }
    }

    /// The session refused the spawn before `Started` (the shim's spawn
    /// limit, a refused hello, a VM gone): its failure, audited as the
    /// session's that never started (the pipeline audits its own).
    fn refused(&self, e: BridgeError) -> SpawnFailure {
        tracing::warn!(gen = self.gen, "the remote spawn was refused: {e}");
        let failure = Failure::from_error(StartStep::Spawn, e, Some(&self.vm));
        self.audit_failure(StartStep::Spawn, &failure);
        SpawnFailure::from_failure(StartStep::Spawn, &failure, Some(self.vm.clone()))
    }
}

/// The VM's stderr, raw, to the wrapper's (as a local child's is copied),
/// each chunk marked consumed once written (or once the write failed).
async fn stderr_copy(mut rx: mpsc::Receiver<(u64, Vec<u8>)>, consumed: Arc<Consumed>) {
    let mut err = tokio::io::stderr();
    let mut ok = true;
    while let Some((seq, bytes)) = rx.recv().await {
        if ok && (err.write_all(&bytes).await.is_err() || err.flush().await.is_err()) {
            ok = false;
        }
        consumed.stderr_done(seq);
    }
}

/// What a generation is started for.
#[derive(Debug)]
pub struct StartReq<'a> {
    pub why: StartWhy,
    /// `local-scratch` only (S7): the unsealed setup-token and how the child
    /// gets it (`pump::spawn_local`'s argument). A remote start carries none:
    /// its pipeline unseals and delivers on its own (D1).
    pub credential: Option<(&'a SetupToken, Deliver)>,
}

/// Why a generation starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartWhy {
    /// The session's first child.
    First,
    /// The resume miss's one retry: generation 1 reported `session_id`
    /// missing. Local: the scratch dir was re-seeded from the Mac. Remote:
    /// the pipeline restores the transcript first (S9: from S3), re-gates without a
    /// prompt and respawns on the same VM. `init_answered` (S8 phase 4,
    /// added to C3): generation 1 answered the host's `initialize` before
    /// its miss, so Cursor's 60 s window is over and a remote retry has a
    /// window of its own; while it is unanswered, the retry's answer is the
    /// host's first: its start keeps T0 + 50 s (`pipeline::run`), and its
    /// legs count toward the census's (they lead to `init_ms`).
    ResumeRetry { session_id: String, init_answered: bool },
}

/// Which kind of child a factory starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// A process on this Mac (`local-child`, `local-scratch`).
    Local,
    /// The CLI in the workspace's MicroVM, through the shim (`remote`).
    Remote,
}

impl LinkKind {
    /// Its word (logs, the census's mode note).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            LinkKind::Local => "local",
            LinkKind::Remote => "remote",
        }
    }
}

/// The rungs of the close ladder, from the host's EOF or from the
/// wrapper's SIGTERM. On a remote link `Sig::Term` is `Signal(Term)` plus
/// `detach{final}`, and `Sig::Kill` is `detach{final}`: the shim's own ladder
/// (TERM at +0.8 s, KILL at +1.2 s from its receipt) ends the CLI after the
/// wrapper is gone (L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseTimings {
    /// After host EOF (the child's stdin is closed at once): `Sig::Term`;
    /// `None`: never sent (a remote CLI exits by itself once its stdin ends).
    pub eof_term_after: Option<Duration>,
    /// After host EOF: `Sig::Kill`.
    pub eof_kill_after: Duration,
    /// After host EOF: finish whatever was seen.
    pub eof_hard_stop: Duration,
    /// After the wrapper's SIGTERM (`Sig::Term` at once): `Sig::Kill`.
    pub sigterm_kill_after: Duration,
    /// After the wrapper's SIGTERM: finish whatever was seen.
    pub sigterm_hard_stop: Duration,
}

impl CloseTimings {
    /// A local child: the S2 ladder, unchanged (EOF: TERM at +0.8 s, KILL at
    /// +1.2 s, the hard stop at +1.4 s; SIGTERM: KILL at +0.6 s, the hard
    /// stop at +0.9 s).
    pub const LOCAL: CloseTimings = CloseTimings { eof_term_after: Some(EOF_TERM_AFTER), eof_kill_after: EOF_KILL_AFTER, eof_hard_stop: EOF_HARD_STOP, sigterm_kill_after: SIGTERM_KILL_AFTER, sigterm_hard_stop: SIGTERM_HARD_STOP };

    /// A remote child (L2): no TERM from the Mac after EOF, the CLI's own exit
    /// awaited until `detach{final}` at `remote::REMOTE_EOF_DETACH_AFTER_MS`,
    /// the hard stop at `remote::REMOTE_HARD_STOP_MS`; the SIGTERM rungs as
    /// the local ones.
    pub const REMOTE: CloseTimings = CloseTimings {
        eof_term_after: None,
        eof_kill_after: Duration::from_millis(REMOTE_EOF_DETACH_AFTER_MS),
        eof_hard_stop: Duration::from_millis(REMOTE_HARD_STOP_MS),
        sigterm_kill_after: SIGTERM_KILL_AFTER,
        sigterm_hard_stop: SIGTERM_HARD_STOP,
    };

    /// The ladder of `kind`.
    #[must_use]
    pub fn of(kind: LinkKind) -> CloseTimings {
        match kind {
            LinkKind::Local => CloseTimings::LOCAL,
            LinkKind::Remote => CloseTimings::REMOTE,
        }
    }
}

/// `ChildEvent::Started`: the shim's `spawned`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStarted {
    pub spawn_id: SpawnId,
    /// The CLI's pid in the VM (the census's `vm_pid`; Cursor sees the wrapper's own).
    pub vm_pid: u32,
    /// The VM's claude, as the shim probed it (compared with `authwatch::AUTH_TIMERS`).
    pub claude_version: Option<String>,
}

/// The step a remote start reached (the census's `legs`, a deadline's step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartStep {
    /// P0: no AWS call, no Touch ID.
    Precheck,
    /// P1: the runtime key's unseal.
    TouchId,
    /// P2: SELECT_VM.
    SelectVm,
    /// P3: the workspace (with the transcript on a resume).
    Workspace,
    /// P3: the credential gate.
    Gate,
    /// P3: the token's delivery.
    Token,
    /// P4: the spawn.
    Spawn,
    /// T0 + `remote::INIT_DEADLINE` passed.
    Deadline,
}

impl StartStep {
    /// Every step, in pipeline order.
    pub const ALL: [StartStep; 8] = [StartStep::Precheck, StartStep::TouchId, StartStep::SelectVm, StartStep::Workspace, StartStep::Gate, StartStep::Token, StartStep::Spawn, StartStep::Deadline];

    /// Its word; a step that is a census leg has the leg's name (`remote::LEG_NAMES`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            StartStep::Precheck => "precheck",
            StartStep::TouchId => "touchid",
            StartStep::SelectVm => "select",
            StartStep::Workspace => "workspace",
            StartStep::Gate => "gate",
            StartStep::Token => "token",
            StartStep::Spawn => "spawn",
            StartStep::Deadline => "deadline",
        }
    }
}

/// `ChildEvent::SpawnFailed`: the remote start ended before `spawned`.
/// Never reported as `Exit(None)`, so `EndReason::SpawnFailed` keeps its
/// meaning and the exit code is the failure's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnFailure {
    /// The wrapper's exit code ([`Failure::exit_code`]).
    pub code: i32,
    /// The step the start stopped at.
    pub step: StartStep,
    /// The one line Cursor shows, after `ai-env-claude: ` ([`Failure::line`]);
    /// `None`: nothing to say.
    pub line: Option<String>,
    /// The host's EOF or a signal cancelled the start: the pump maps it to
    /// (0, `EndReason::EofTerm`) with no line after a host EOF, to (143,
    /// `EndReason::SigTerm`) and this line after a signal.
    pub cancelled: bool,
    /// The VM, once SELECT_VM chose one.
    pub vm: Option<String>,
}

impl SpawnFailure {
    /// `failure` at `step`: its exit code and its line.
    #[must_use]
    pub fn from_failure(step: StartStep, failure: &Failure, vm: Option<String>) -> SpawnFailure {
        SpawnFailure { code: failure.exit_code(), step, line: Some(failure.line()), cancelled: *failure == Failure::Stopped, vm }
    }

    /// A start cancelled at `step` ([`Failure::Stopped`]).
    #[must_use]
    pub fn stopped(step: StartStep, vm: Option<String>) -> SpawnFailure {
        SpawnFailure::from_failure(step, &Failure::Stopped, vm)
    }
}

/// `ChildEvent::Lost`: the spawn started, then `run_spawn_with` gave up on
/// the link (the VM gone, the reconnect budget spent): not an exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLoss {
    /// The wrapper's exit code (7 or 8).
    pub code: i32,
    /// The one line Cursor shows, after `ai-env-claude: `.
    pub line: String,
}

impl LinkLoss {
    /// `failure`'s code and line ([`Failure::LinkLost`] as a rule).
    #[must_use]
    pub fn from_failure(failure: &Failure) -> LinkLoss {
        LinkLoss { code: failure.exit_code(), line: failure.line() }
    }
}

/// What a remote link knows now, for the census end row (its parts:
/// [`RemoteSnapshot::census_parts`]) and the session's registry row
/// (`microvm_id`, `spawn_id`, `last_acked_seq`, `seeded_head`,
/// `last_wip_fetch`, `detached` while the link is down).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteSnapshot {
    /// The VM, once SELECT_VM chose it.
    pub vm: Option<String>,
    /// How it was chosen: one of `remote::VM_HOW_WORDS`.
    pub vm_how: Option<&'static str>,
    /// The spawn's id, known from `start` (`SpawnSpec.id`).
    pub spawn: Option<SpawnId>,
    /// From `spawned`: the CLI's pid in the VM and its version.
    pub vm_pid: Option<u32>,
    pub claude: Option<String>,
    /// Each pipeline step's ms, in `remote::LEG_NAMES` order (a step not
    /// reached is left out): the steps that lead to the session's
    /// `init_ms`, so a resume miss's retry the host still waits on adds its
    /// own to generation 1's, and one after the host's `initialize` was
    /// answered leaves them as they are.
    pub legs: Vec<(&'static str, u64)>,
    /// What the workspace step did (`workspace::EnsureOutcome::word`).
    pub seed: Option<&'static str>,
    /// What a resume's upload did (`workspace::TranscriptOutcome::word`).
    pub transcript: Option<&'static str>,
    /// Where the session's token came from (`PipelineEnd::credential`:
    /// `combined` or `setup-token` for one the wrapper unsealed, `cached`
    /// when it counted on the VM's copy), or `cached` when the session found
    /// the VM's cache holding it and sent none (S7's word for the VM's copy;
    /// `PipelineEnd::delivery`). A token goes to the VM only with claude's
    /// spawn, so a start that ended before it names its source though
    /// nothing was sent. The end row's S7 `credential:` part, which the pump
    /// prints among S2's parts (not one of [`RemoteSnapshot::census_parts`]).
    pub credential: Option<&'static str>,
    /// Code-out fetches that succeeded, and those run.
    pub fetch_ok: u32,
    pub fetch_runs: u32,
    /// The highest stdout seq the adapter handed to the pump (the
    /// registry's `last_acked_seq`, never below what the session acked).
    pub last_acked_seq: u64,
    /// A socket is attached now.
    pub link_up: bool,
    /// Sockets lost and reattached so far.
    pub link_drops: u32,
    /// The VM head the session started from, and the newest
    /// `refs/remotes/box/wip/*` a fetch brought.
    pub seeded_head: Option<String>,
    pub last_wip_fetch: Option<String>,
    /// `match`, or `unmeasured(<version>)`: the VM's claude against
    /// `authwatch::AUTH_TIMERS`.
    pub auth_timers: Option<String>,
}

impl RemoteSnapshot {
    /// The census parts a remote link owns, each `name:value`, in
    /// `remote::census_part::ALL`'s order: `vm`, `vm_how`, `spawn`, `vm_pid`,
    /// `claude` and `legs` (`legs:touchid=<ms>,select=<ms>,…`) when known,
    /// `seed` and `transcript` when they ran, `fetch:<ok>/<runs>` and
    /// `link_drops:<n>` always, `auth_timers` when compared. `close_ms`,
    /// `pid_rewrite` and `prewarm` are the pump's and the start row's.
    #[must_use]
    pub fn census_parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        let mut put = |name: &str, value: Option<String>| {
            if let Some(v) = value {
                parts.push(format!("{name}:{v}"));
            }
        };
        put(census_part::VM, self.vm.clone());
        put(census_part::VM_HOW, self.vm_how.map(str::to_string));
        put(census_part::SPAWN, self.spawn.as_ref().map(ToString::to_string));
        put(census_part::VM_PID, self.vm_pid.map(|p| p.to_string()));
        put(census_part::CLAUDE, self.claude.clone());
        put(census_part::LEGS, (!self.legs.is_empty()).then(|| self.legs.iter().map(|(leg, ms)| format!("{leg}={ms}")).collect::<Vec<_>>().join(",")));
        put(census_part::SEED, self.seed.map(str::to_string));
        put(census_part::TRANSCRIPT, self.transcript.map(str::to_string));
        put(census_part::FETCH, Some(format!("{}/{}", self.fetch_ok, self.fetch_runs)));
        put(census_part::LINK_DROPS, Some(self.link_drops.to_string()));
        put(census_part::AUTH_TIMERS, self.auth_timers.clone());
        parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::remote::{LEG_NAMES, VM_HOW_WORDS};

    /// The local ladder is the S2 one; the remote one sends no TERM after
    /// EOF, detaches at 1.2 s and stops at 1.4 s, its SIGTERM rungs the
    /// local ones, all within the close budget.
    #[test]
    fn the_close_timings_are_the_s2_ladder_and_l2s() {
        let ms = |d: Duration| d.as_millis() as u64;
        let l = CloseTimings::LOCAL;
        assert_eq!((l.eof_term_after.map(ms), ms(l.eof_kill_after), ms(l.eof_hard_stop), ms(l.sigterm_kill_after), ms(l.sigterm_hard_stop)), (Some(800), 1200, 1400, 600, 900));
        let r = CloseTimings::REMOTE;
        assert_eq!((r.eof_term_after, ms(r.eof_kill_after), ms(r.eof_hard_stop), ms(r.sigterm_kill_after), ms(r.sigterm_hard_stop)), (None, 1200, 1400, 600, 900));
        assert!(ms(r.eof_hard_stop) < crate::bridge::remote::CLOSE_BUDGET_MS);
        assert_eq!((CloseTimings::of(LinkKind::Local), CloseTimings::of(LinkKind::Remote)), (l, r));
        assert_eq!((LinkKind::Local.name(), LinkKind::Remote.name()), ("local", "remote"));
        assert_eq!((PENDING_IN_LINES, PENDING_IN_BYTES), (1024, 64 << 20), "plan §2's pending-start caps");
    }

    #[test]
    fn the_start_steps_that_are_legs_carry_the_legs_names() {
        let names = StartStep::ALL.map(StartStep::name);
        assert_eq!(names, ["precheck", "touchid", "select", "workspace", "gate", "token", "spawn", "deadline"]);
        let legs: Vec<&str> = names.iter().copied().filter(|n| LEG_NAMES.contains(n)).collect();
        assert_eq!(legs, LEG_NAMES, "every leg is a step, in order");
    }

    /// C5 meets C3: a failure's code and line become the event's; a stop is
    /// the one cancellation, exit 143.
    #[test]
    fn spawn_failures_and_link_losses_carry_the_failures_code_and_line() {
        let f = SpawnFailure::from_failure(StartStep::TouchId, &Failure::TouchIdCancelled, None);
        assert_eq!((f.code, f.step, f.cancelled), (3, StartStep::TouchId, false));
        assert_eq!(f.line.as_deref(), Some(Failure::TouchIdCancelled.line().as_str()));
        let s = SpawnFailure::stopped(StartStep::SelectVm, Some("microvm-1".into()));
        assert_eq!((s.code, s.cancelled, s.vm.as_deref()), (143, true, Some("microvm-1")));
        assert!(s.line.unwrap().starts_with("stopped before the session started"));
        let lost = LinkLoss::from_failure(&Failure::LinkLost { vm: "microvm-1".into() });
        assert_eq!(lost.code, 8);
        assert!(lost.line.contains("reopen the chat from the picker"), "{}", lost.line);
    }

    #[test]
    fn a_snapshot_renders_the_census_parts_it_owns() {
        assert_eq!(RemoteSnapshot::default().census_parts(), ["fetch:0/0", "link_drops:0"]);
        let spawn = SpawnId::new_v7();
        let full = RemoteSnapshot {
            vm: Some("microvm-1".into()),
            vm_how: Some(VM_HOW_WORDS[1]),
            spawn: Some(spawn.clone()),
            vm_pid: Some(4242),
            claude: Some("2.1.296".into()),
            legs: vec![("touchid", 1800), ("select", 2400), ("workspace", 900), ("gate", 300), ("spawn", 700)],
            seed: Some("up_to_date"),
            transcript: Some("uploaded"),
            fetch_ok: 2,
            fetch_runs: 3,
            link_drops: 1,
            auth_timers: Some("match".into()),
            ..RemoteSnapshot::default()
        };
        let want = [
            "vm:microvm-1".to_string(),
            "vm_how:reused".into(),
            format!("spawn:{spawn}"),
            "vm_pid:4242".into(),
            "claude:2.1.296".into(),
            "legs:touchid=1800,select=2400,workspace=900,gate=300,spawn=700".into(),
            "seed:up_to_date".into(),
            "transcript:uploaded".into(),
            "fetch:2/3".into(),
            "link_drops:1".into(),
            "auth_timers:match".into(),
        ];
        assert_eq!(full.census_parts(), want, "in census_part::ALL's order");
    }

    /// A scripted factory (the shape the pump's contract tests take): the
    /// trait is object-safe, a pending start is a link whose first event says
    /// how it ended, and its input and signals reach the far side.
    struct Scripted {
        fail: bool,
        far: Vec<(mpsc::Receiver<ChildInput>, mpsc::UnboundedReceiver<Sig>)>,
    }

    impl LinkFactory for Scripted {
        fn start(&mut self, gen: u32, req: StartReq<'_>) -> std::io::Result<ChildLink> {
            assert!(req.credential.is_none(), "a remote start carries no token");
            let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAP);
            let (sig_tx, sig_rx) = mpsc::unbounded_channel();
            let (ev_tx, ev_rx) = mpsc::channel(CHANNEL_CAP);
            let first = if self.fail {
                ChildEvent::SpawnFailed(SpawnFailure::from_failure(StartStep::Workspace, &Failure::Finding { finding: "untracked .env rule env-file-plaintext".into() }, Some("microvm-1".into())))
            } else {
                ChildEvent::Started(RemoteStarted { spawn_id: SpawnId::new_v7(), vm_pid: 4000 + gen, claude_version: Some(AUTH_TIMERS.claude.into()) })
            };
            ev_tx.try_send(first).map_err(|e| std::io::Error::other(e.to_string()))?;
            self.far.push((in_rx, sig_rx));
            Ok(ChildLink { pid: None, input: in_tx, signal: sig_tx, events: ev_rx })
        }

        fn kind(&self) -> LinkKind {
            LinkKind::Remote
        }

        fn timings(&self) -> CloseTimings {
            CloseTimings::REMOTE
        }
    }

    #[tokio::test]
    async fn a_pending_remote_start_is_a_link_whose_first_event_says_how_it_ended() {
        let mut links: Box<dyn LinkFactory> = Box::new(Scripted { fail: false, far: Vec::new() });
        assert_eq!((links.kind(), links.timings(), links.snapshot()), (LinkKind::Remote, CloseTimings::REMOTE, None));
        links.on_result();
        links.drop_transport();
        let mut link = links.start(1, StartReq { why: StartWhy::First, credential: None }).unwrap();
        assert!(matches!(link.events.recv().await, Some(ChildEvent::Started(RemoteStarted { vm_pid: 4001, .. }))));
        link.input.send(ChildInput::Eof).await.unwrap();
        link.signal.send(Sig::Term).unwrap();
        links.close(Duration::from_secs(1)).await;
        let mut failing = Scripted { fail: true, far: Vec::new() };
        let mut link = failing.start(2, StartReq { why: StartWhy::ResumeRetry { session_id: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), init_answered: false }, credential: None }).unwrap();
        match link.events.recv().await {
            Some(ChildEvent::SpawnFailed(f)) => assert_eq!((f.code, f.step, f.cancelled, f.vm.as_deref()), (9, StartStep::Workspace, false, Some("microvm-1"))),
            other => panic!("{other:?}"),
        }
        let (mut input, mut sig) = failing.far.pop().unwrap();
        drop(link);
        assert!(input.recv().await.is_none() && sig.recv().await.is_none(), "the far side sees the link go");
    }

    // ---- the remote factory and its adapter, over fake pipelines and sessions ----------------

    use crate::bridge::agent::AgentTarget;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::codeout::CodeoutCtx;
    use crate::bridge::config::BridgeConfig;
    use crate::bridge::dataplane::Unreached;
    use crate::wire::redact::Secret;
    use std::cell::Cell;

    /// Every wait's bound.
    const T: Duration = Duration::from_secs(10);

    fn on_local<F: Future>(f: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio::task::LocalSet::new().block_on(&rt, f)
    }

    /// A fake session: what the session task runs with the session's side
    /// of the generation's channels.
    type Script = Box<dyn FnOnce(SpawnIo) -> Pin<Box<dyn Future<Output = Result<SpawnOutcome, BridgeError>>>>>;

    /// One generation's fake pipeline.
    enum Gen {
        /// Refuses with this failure.
        Refuse(SpawnFailure),
        /// Never resolves; the flag is set once its future is dropped (an unseal's dialog dies with it).
        Hang(Rc<Cell<bool>>),
        /// After this long, hands over a session task running the script.
        Session(Duration, Script),
        /// Hands over at once a session task running the script, which must
        /// say `Started` within this long (`PipelineEnd::started_by`).
        Due(Duration, Script),
    }

    struct DropFlag(Rc<Cell<bool>>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// What `remote::pipeline::run` hands over: VM `microvm-1`, reused, the
    /// session task `session`, a code-out trigger (W4's, on a data plane no
    /// call reaches: each fetch fails).
    fn end_with(dir: &std::path::Path, session: JoinHandle<Result<SpawnOutcome, BridgeError>>) -> PipelineEnd {
        let paths = Paths::from_root_and_env(dir.join("bridge"), None);
        let target = AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false };
        let ctx = CodeoutCtx { api: Arc::new(FakeMicrovmApi::new()), dp: Arc::new(Unreached), tokens: Arc::new(Unreached), paths, cfg: Arc::new(BridgeConfig::default()), target, ws: SessionPlan::sample(dir).ws, capture_settings: false, transcript: None };
        PipelineEnd {
            vm: "microvm-1".into(),
            vm_how: "reused",
            legs: vec![("touchid", 10), ("select", 20), ("workspace", 30), ("gate", 5)],
            seed: "up_to_date",
            transcript: None,
            seeded_head: Some("a".repeat(40)),
            credential: Some("combined"),
            delivery: None,
            spawn_id: SpawnId::new_v7(),
            started_by: None,
            trigger: CodeoutTrigger::spawn(ctx),
            session,
        }
    }

    /// The remote factory over `gens`, one per start, in order.
    fn remote_links(dir: &std::path::Path, gens: Vec<Gen>) -> RemoteLinks {
        let mut gens = VecDeque::from(gens);
        let root = dir.to_path_buf();
        RemoteLinks::with_pipeline(
            Paths::from_root_and_env(dir.join("bridge"), None),
            Box::new(move |_gen, _why, io| {
                let root = root.clone();
                match gens.pop_front().expect("a generation was scripted") {
                    Gen::Refuse(f) => Box::pin(async move {
                        drop(io);
                        Err(f)
                    }),
                    Gen::Hang(dropped) => Box::pin(async move {
                        let _flag = DropFlag(dropped);
                        let _io = io;
                        std::future::pending::<Result<PipelineEnd, SpawnFailure>>().await
                    }),
                    Gen::Session(delay, script) => Box::pin(async move {
                        tokio::time::sleep(delay).await;
                        let session = tokio::task::spawn_local(script(io));
                        Ok(end_with(&root, session))
                    }),
                    Gen::Due(within, script) => Box::pin(async move {
                        let session = tokio::task::spawn_local(script(io));
                        Ok(PipelineEnd { started_by: Some(tokio::time::Instant::now() + within), ..end_with(&root, session) })
                    }),
                }
            }),
        )
    }

    fn start(links: &mut RemoteLinks) -> ChildLink {
        links.start(1, StartReq { why: StartWhy::First, credential: None }).unwrap()
    }

    async fn next(link: &mut ChildLink) -> Option<ChildEvent> {
        tokio::time::timeout(T, link.events.recv()).await.expect("an event within the bound")
    }

    /// Every event up to and with the link's last one (or its end).
    async fn to_the_end(link: &mut ChildLink) -> Vec<ChildEvent> {
        let mut all = Vec::new();
        while let Some(ev) = next(link).await {
            let last = matches!(ev, ChildEvent::Exit(_) | ChildEvent::SpawnFailed(_) | ChildEvent::Lost(_) | ChildEvent::Detached);
            all.push(ev);
            if last {
                break;
            }
        }
        all
    }

    fn lines_of(events: &[ChildEvent]) -> Vec<Vec<u8>> {
        events.iter().filter_map(|e| if let ChildEvent::Line(b) = e { Some(b.to_vec()) } else { None }).collect()
    }

    fn started_event(claude: Option<&str>) -> SpawnEvent {
        SpawnEvent::Started { spawn_id: SpawnId::new_v7(), pid: 4242, pgid: 4242, claude_version: claude.map(str::to_string) }
    }

    fn exited(code: Option<i32>, signal: Option<i32>) -> RemoteExit {
        RemoteExit { code, signal, stderr_dropped: 0, stdout_truncated: false }
    }

    /// As `session::finish`: the exit is acked (here: the session ends) once
    /// the consumer marked every stdout and stderr seq delivered.
    async fn wait_marked(io: &SpawnIo, out: u64, err: u64) -> Result<(), BridgeError> {
        let until = tokio::time::Instant::now() + T;
        loop {
            let (o, e) = io.consumed.seqs();
            if o >= out && e >= err {
                return Ok(());
            }
            if tokio::time::timeout_at(until, io.consumed.changed()).await.is_err() {
                return Err(BridgeError::Transport(format!("the consumer marked stdout {o} of {out}, stderr {e} of {err}")));
            }
        }
    }

    /// A session that starts, sends `chunks` of stdout (no window), exits
    /// `code` and ends once every chunk was marked.
    fn printing(chunks: Vec<Vec<u8>>, exit: RemoteExit) -> Script {
        Box::new(move |io: SpawnIo| {
            Box::pin(async move {
                let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                let n = chunks.len() as u64;
                for (i, bytes) in chunks.into_iter().enumerate() {
                    let _ = io.events.send(SpawnEvent::Stdout { seq: i as u64 + 1, bytes });
                }
                let _ = io.events.send(SpawnEvent::Exit(exit));
                wait_marked(&io, n, 0).await?;
                Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
            })
        })
    }

    /// A pipeline's refusal is the link's first and only event, as it came;
    /// the snapshot names the VM it reached.
    #[test]
    fn a_pipeline_refusal_is_the_links_first_and_only_event() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let failure = SpawnFailure::from_failure(StartStep::Workspace, &Failure::Finding { finding: "untracked .env: rule env-file-plaintext".into() }, Some("microvm-1".into()));
            let mut links = remote_links(d.path(), vec![Gen::Refuse(failure.clone())]);
            assert_eq!((links.kind(), links.timings()), (LinkKind::Remote, CloseTimings::REMOTE));
            let mut link = start(&mut links);
            assert_eq!(link.pid, None, "the VM's pid comes with Started");
            match next(&mut link).await {
                Some(ChildEvent::SpawnFailed(f)) => assert_eq!(f, failure),
                other => panic!("{other:?}"),
            }
            assert!(next(&mut link).await.is_none(), "nothing after it");
            assert_eq!(links.snapshot().and_then(|s| s.vm).as_deref(), Some("microvm-1"));
        });
    }

    /// M07 at the link: a stop while the pipeline runs drops it at once
    /// (the Touch ID dialog's process group dies with it) and the link says
    /// the start was cancelled (143); `Kill` does the same; a pump that let
    /// the link go drops it too, and hears nothing.
    #[test]
    fn a_stop_while_the_pipeline_runs_drops_it_and_reports_a_cancelled_start() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            for sig in [Some(Sig::Term), Some(Sig::Kill), None] {
                let dropped = Rc::new(Cell::new(false));
                let mut links = remote_links(d.path(), vec![Gen::Hang(Rc::clone(&dropped))]);
                let mut link = start(&mut links);
                tokio::time::sleep(Duration::from_millis(20)).await;
                assert!(!dropped.get(), "pending");
                let at = std::time::Instant::now();
                match sig {
                    Some(sig) => {
                        link.signal.send(sig).unwrap();
                        match next(&mut link).await {
                            Some(ChildEvent::SpawnFailed(f)) => assert_eq!((f.code, f.cancelled, f.vm), (143, true, None), "{sig:?}"),
                            other => panic!("{other:?}"),
                        }
                        assert!(next(&mut link).await.is_none());
                    }
                    None => {
                        drop(link);
                        links.close(T).await;
                    }
                }
                assert!(dropped.get(), "the pipeline was dropped ({sig:?})");
                assert!(at.elapsed() < Duration::from_millis(500), "{:?}", at.elapsed());
            }
        });
    }

    /// M06 at the link: a stop after the pipeline handed over its session,
    /// before `Started`, is `detach{final}` alone (the session then never
    /// sends the spawn, as `adopt`'s `no_pending_detach` does), and the
    /// session's end is a cancelled start, never a refusal. The session's
    /// notes and link state before `Started` stay off the link: its first
    /// event is still the start's end.
    #[test]
    fn a_stop_before_started_detaches_and_the_start_is_cancelled() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<SpawnInput>>> = Rc::default();
            let seen = Rc::clone(&got);
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(SpawnEvent::Note("lost the connection to microvm-1 (x); reconnecting".into()));
                    let _ = io.events.send(SpawnEvent::Link(false));
                    while let Some(input) = io.control.recv().await {
                        let detach = matches!(input, SpawnInput::Detach { is_final: true });
                        seen.borrow_mut().push(input);
                        if detach {
                            return Err(BridgeError::Transport("detached from spawn x while disconnected from microvm-1 (its detach grace ends it)".into()));
                        }
                    }
                    Err(BridgeError::Transport("no control".into()))
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            tokio::time::sleep(Duration::from_millis(30)).await;
            link.signal.send(Sig::Term).unwrap();
            match next(&mut link).await {
                Some(ChildEvent::SpawnFailed(f)) => assert_eq!((f.code, f.step, f.cancelled, f.vm.as_deref()), (143, StartStep::Spawn, true, Some("microvm-1"))),
                other => panic!("{other:?}"),
            }
            assert_eq!(*got.borrow(), [SpawnInput::Detach { is_final: true }], "the detach alone: no signal for a spawn that never ran");
            let audit = std::fs::read_to_string(Paths::from_root_and_env(d.path().join("bridge"), None).audit()).unwrap_or_default();
            assert!(!audit.contains("session_remote_failed"), "a cancelled start is no failure: {audit}");
        });
    }

    /// After `Started`, `Sig::Term` is `Signal(Term)` then `detach{final}`,
    /// and the session's end after the wrapper's detach is `Detached`; a
    /// `Kill` after it sends no second detach.
    #[test]
    fn a_stop_after_started_is_signal_term_then_detach_final() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<SpawnInput>>> = Rc::default();
            let seen = Rc::clone(&got);
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    while let Some(input) = io.control.recv().await {
                        let detach = matches!(input, SpawnInput::Detach { .. });
                        seen.borrow_mut().push(input);
                        if detach {
                            // As the session: the detach goes, the socket closes, the session ends.
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            while let Ok(more) = io.control.try_recv() {
                                seen.borrow_mut().push(more);
                            }
                            return Err(BridgeError::Transport("detached from spawn x".into()));
                        }
                    }
                    Err(BridgeError::Transport("no control".into()))
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(RemoteStarted { vm_pid: 4242, .. }))));
            link.signal.send(Sig::Term).unwrap();
            link.signal.send(Sig::Kill).unwrap();
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Detached)));
            assert_eq!(*got.borrow(), [SpawnInput::Signal(WireSig::Term), SpawnInput::Detach { is_final: true }]);
        });
    }

    /// The session's end after `Started`, the wrapper having detached
    /// nothing: the link is lost (8; 7 for an error of exit 7: a refused or
    /// throttled endpoint), with the loss's line; never an exit.
    #[test]
    fn a_session_error_after_started_is_a_lost_link() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            for (error, code) in [(BridgeError::Terminated("microvm-1 is TERMINATED".into()), 8), (BridgeError::EndpointThrottled { retry_after_s: None }, 7)] {
                let script: Script = Box::new(move |io: SpawnIo| {
                    Box::pin(async move {
                        let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                        let _ = io.events.send(SpawnEvent::Link(false));
                        Err(error)
                    })
                });
                let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
                let mut link = start(&mut links);
                let events = to_the_end(&mut link).await;
                assert!(matches!(events[..], [ChildEvent::Started(_), ChildEvent::Link(false), ChildEvent::Lost(_)]), "{events:?}");
                let ChildEvent::Lost(loss) = &events[2] else { unreachable!() };
                assert_eq!(loss.code, code);
                assert!(loss.line.contains("microvm-1") && loss.line.ends_with("reopen the chat from the picker"), "{}", loss.line);
            }
        });
    }

    /// A spawn the session saw refused before `Started` is a failed start
    /// by its error (`Failure::from_error` at the spawn: the shim's spawn
    /// limit is 9 naming the VM), audited as `session_remote_failed`.
    #[test]
    fn a_session_refusal_before_started_is_a_spawn_failure_by_its_error() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let script: Script = Box::new(|_io: SpawnIo| Box::pin(async { Err(BridgeError::SpawnRefused { code: "limit", message: "8 spawns are running (at most 8)".into() }) }));
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            match next(&mut link).await {
                Some(ChildEvent::SpawnFailed(f)) => {
                    assert_eq!((f.code, f.step, f.cancelled, f.vm.as_deref()), (9, StartStep::Spawn, false, Some("microvm-1")));
                    assert!(f.line.unwrap_or_default().starts_with("microvm-1 runs 8 commands already"));
                }
                other => panic!("{other:?}"),
            }
            let audit = std::fs::read_to_string(Paths::from_root_and_env(d.path().join("bridge"), None).audit()).unwrap();
            assert!(audit.contains("\"event\":\"session_remote_failed\"") && audit.contains("\"why\":\"spawn_limit\"") && audit.contains("\"step\":\"spawn\""), "{audit}");
        });
    }

    /// The exit: the splitter's tail as a last line, stdout's EOF, stderr's
    /// EOF, then the status: the code, the signal, or 1 when the shim
    /// reported neither.
    #[test]
    fn the_exit_ends_with_the_tail_both_eofs_and_its_status() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            for (exit, code, signal) in [(exited(Some(3), None), Some(3), None), (exited(None, Some(15)), None, Some(15)), (exited(None, None), Some(1), None)] {
                let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, printing(vec![b"a\nb".to_vec()], exit))]);
                let mut link = start(&mut links);
                let events = to_the_end(&mut link).await;
                let kinds: Vec<&str> = events.iter().map(ChildEvent::kind).collect();
                assert_eq!(kinds, ["started", "line", "line", "stdout_eof", "stderr_eof", "exit"], "{exit:?}");
                assert_eq!(lines_of(&events), [b"a".to_vec(), b"b".to_vec()]);
                let ChildEvent::Exit(Some(status)) = events[5] else { panic!("{:?}", events[5]) };
                assert_eq!((status.code(), status.signal()), (code, signal), "{exit:?}");
                assert!(next(&mut link).await.is_none(), "the session ended with its exit: nothing more");
            }
        });
    }

    /// The pump's input reaches the session in `CHUNK_MAX` pieces, its EOF
    /// as `stdin_eof` after them.
    #[test]
    fn input_lines_go_to_the_session_in_chunk_max_pieces_then_eof() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<Option<usize>>>> = Rc::default();
            let seen = Rc::clone(&got);
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    while let Some(input) = io.input.recv().await {
                        match input {
                            SpawnInput::Stdin(b) => seen.borrow_mut().push(Some(b.len())),
                            SpawnInput::StdinEof => {
                                seen.borrow_mut().push(None);
                                break;
                            }
                            other => panic!("{other:?}"),
                        }
                    }
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            let mut line = vec![b'x'; 150 * 1024];
            line.push(b'\n');
            link.input.send(ChildInput::Line(Bytes::from(line))).await.unwrap();
            link.input.send(ChildInput::Eof).await.unwrap();
            let events = to_the_end(&mut link).await;
            assert!(matches!(events.last(), Some(ChildEvent::Exit(_))), "{events:?}");
            assert_eq!(*got.borrow(), [Some(CHUNK_MAX), Some(CHUNK_MAX), Some(150 * 1024 + 1 - 2 * CHUNK_MAX), None]);
        });
    }

    /// M09: a line longer than the shim's 8 MiB stdout window passes whole:
    /// each chunk is marked consumed once its lines are handed over (a chunk
    /// that ends no line, at once), never per line, so the session's window
    /// keeps moving under a 20 MiB line. The session here sends only while
    /// fewer than 8 MiB are unmarked, and gives up if the marks stop.
    #[test]
    fn a_20_mib_line_passes_whole_within_the_8_mib_window() {
        const WINDOW: usize = 8 * 1024 * 1024;
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let script: Script = Box::new(|io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    let mut data = vec![b'x'; 20 * 1024 * 1024];
                    data.push(b'\n');
                    data.extend_from_slice(b"{\"type\":\"result\"}\n");
                    let mut lens: VecDeque<(u64, usize)> = VecDeque::new();
                    let mut seq = 0;
                    for chunk in data.chunks(CHUNK_MAX) {
                        loop {
                            let (marked, _) = io.consumed.seqs();
                            while lens.front().is_some_and(|(s, _)| *s <= marked) {
                                lens.pop_front();
                            }
                            if lens.iter().map(|(_, l)| l).sum::<usize>() + chunk.len() <= WINDOW {
                                break;
                            }
                            if tokio::time::timeout(Duration::from_secs(5), io.consumed.changed()).await.is_err() {
                                return Err(BridgeError::Transport("the stdout window never opened again".into()));
                            }
                        }
                        seq += 1;
                        lens.push_back((seq, chunk.len()));
                        let _ = io.events.send(SpawnEvent::Stdout { seq, bytes: chunk.to_vec() });
                    }
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    wait_marked(&io, seq, 0).await?;
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            let events = tokio::time::timeout(Duration::from_secs(60), to_the_end(&mut link)).await.expect("no stall");
            let lines = lines_of(&events);
            assert_eq!(lines.len(), 2, "{:?}", events.iter().map(ChildEvent::kind).collect::<Vec<_>>());
            assert!(lines[0].len() == 20 * 1024 * 1024 && lines[0].iter().all(|b| *b == b'x'), "the long line whole");
            assert_eq!(lines[1], b"{\"type\":\"result\"}");
            assert!(matches!(events.last(), Some(ChildEvent::Exit(Some(s))) if s.code() == Some(0)), "the session ended with its exit, every chunk marked");
            assert_eq!(links.snapshot().unwrap().last_acked_seq, (20 * 1024 * 1024 + 1 + 18_usize).div_ceil(CHUNK_MAX) as u64);
        });
    }

    /// The VM's stderr goes to the wrapper's through its own queue; every
    /// chunk is marked consumed (written, or dropped when the queue is
    /// full), so the session can end; nothing of it becomes a line.
    #[test]
    fn stderr_has_its_own_queue_and_every_chunk_is_marked() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let n = 3 * STDERR_QUEUE as u64;
            let script: Script = Box::new(move |io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    for seq in 1..=n {
                        // Empty chunks: the queue's work without filling the test's stderr.
                        let _ = io.events.send(SpawnEvent::Stderr { seq, bytes: Vec::new(), dropped: 0 });
                    }
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    wait_marked(&io, 0, n).await?;
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            let events = to_the_end(&mut link).await;
            let kinds: Vec<&str> = events.iter().map(ChildEvent::kind).collect();
            assert_eq!(kinds, ["started", "stdout_eof", "stderr_eof", "exit"]);
            assert!(matches!(events.last(), Some(ChildEvent::Exit(Some(s))) if s.code() == Some(0)), "the session ended: every stderr chunk was marked");
        });
    }

    /// S7 D6 inside the adapter: on the measured claude a result 401 is a
    /// verdict at once (`Rejected`, `text`), after the chunk's lines; on
    /// another claude only three retry 401s are (`retries`), or S7's exit
    /// rule at its exit (a result 401, then exit 1: `text`); the snapshot
    /// says which (`auth_timers`).
    #[test]
    fn the_refusal_watch_reads_the_vms_claude() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let refused = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,\"api_error_status\":401,\"result\":\"Failed to authenticate. API Error: 401 OAuth access token is invalid.\"}\n";
            let retry = "{\"type\":\"system\",\"subtype\":\"api_retry\",\"attempt\":1,\"error_status\":401,\"error\":\"authentication_failed\"}\n";
            for (claude, out, code, how, timers) in [
                (AUTH_TIMERS.claude, refused.to_string(), 143, Some("text"), "match".to_string()),
                ("2.1.297", refused.to_string(), 143, None, "unmeasured(2.1.297)".to_string()),
                ("2.1.297", retry.repeat(3), 143, Some("retries"), "unmeasured(2.1.297)".to_string()),
                ("2.1.297", refused.to_string(), 1, Some("text"), "unmeasured(2.1.297)".to_string()),
            ] {
                let claude = claude.to_string();
                let script: Script = Box::new(move |io: SpawnIo| {
                    Box::pin(async move {
                        let _ = io.events.send(started_event(Some(&claude)));
                        let _ = io.events.send(SpawnEvent::Stdout { seq: 1, bytes: out.into_bytes() });
                        wait_marked(&io, 1, 0).await?;
                        let exit = exited(Some(code), None);
                        let _ = io.events.send(SpawnEvent::Exit(exit));
                        Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                    })
                });
                let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
                let mut link = start(&mut links);
                let events = to_the_end(&mut link).await;
                let said: Vec<&str> = events.iter().filter_map(|e| if let ChildEvent::Rejected { how } = e { Some(*how) } else { None }).collect();
                assert_eq!(said, how.into_iter().collect::<Vec<_>>(), "{events:?}");
                if how.is_some() {
                    let at = events.iter().position(|e| matches!(e, ChildEvent::Rejected { .. })).unwrap();
                    assert!(matches!(events[at - 1], ChildEvent::Line(_)), "after the chunk's lines");
                }
                assert_eq!(links.snapshot().unwrap().auth_timers.as_deref(), Some(timers.as_str()));
            }
        });
    }

    /// The snapshot follows the generation: the pipeline's VM, choice, legs,
    /// seed and head; `Started`'s spawn, pid and claude, and the `spawn`
    /// leg; the last stdout seq handed over; the link's drops; `on_result`
    /// asks the trigger for a code-out (on a data plane no call reaches, a
    /// failed one: `fetch:0/1`). Notes and the link's state pass through as
    /// events.
    #[test]
    fn the_snapshot_follows_the_pipeline_the_spawn_and_the_marks() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
            let script: Script = Box::new(move |io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    let _ = io.events.send(SpawnEvent::Stdout { seq: 1, bytes: b"{\"type\":\"result\"}\n".to_vec() });
                    let _ = io.events.send(SpawnEvent::Note("lost the connection to microvm-1 (x); reconnecting".into()));
                    let _ = io.events.send(SpawnEvent::Link(false));
                    let _ = io.events.send(SpawnEvent::Link(true));
                    let _ = go_rx.await;
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            assert_eq!(links.snapshot(), Some(RemoteSnapshot::default()), "nothing known before a start");
            let mut link = start(&mut links);
            let mut kinds = Vec::new();
            while kinds.len() < 5 {
                kinds.push(next(&mut link).await.unwrap().kind());
            }
            assert_eq!(kinds, ["started", "line", "note", "link", "link"]);
            let snap = links.snapshot().unwrap();
            assert_eq!((snap.vm.as_deref(), snap.vm_how, snap.seed, snap.legs.len(), snap.credential), (Some("microvm-1"), Some("reused"), Some("up_to_date"), 5, Some("combined")));
            assert_eq!(snap.legs.last().map(|(leg, _)| *leg), Some("spawn"), "the link adds the last leg at `Started`: {:?}", snap.legs);
            assert_eq!((snap.vm_pid, snap.claude.as_deref(), snap.auth_timers.as_deref()), (Some(4242), Some(AUTH_TIMERS.claude), Some("match")));
            assert_eq!((snap.last_acked_seq, snap.link_up, snap.link_drops), (1, true, 1));
            assert_eq!(snap.seeded_head, Some("a".repeat(40)));
            assert!(snap.spawn.is_some());
            links.on_result();
            // The trigger fetches on a task of its own: its report comes
            // once that task ran (W4's trigger, not phase 0's stub).
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut snap = links.snapshot().unwrap();
            while snap.fetch_runs == 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(10)).await;
                snap = links.snapshot().unwrap();
            }
            assert_eq!((snap.fetch_ok, snap.fetch_runs), (0, 1), "{:?}", snap.census_parts());
            assert!(snap.census_parts().contains(&"fetch:0/1".to_string()));
            let _ = go_tx.send(());
            assert!(matches!(to_the_end(&mut link).await.last(), Some(ChildEvent::Exit(_))));
        });
    }

    /// The census's `credential:` word: where the delivered token came
    /// from, unless the session found the VM's cache holding it and sent
    /// none (`cached`, S7's word for the VM's copy); a token sent after all
    /// (a resent spawn's offer that missed the cache) is the source's again.
    #[test]
    fn the_credential_word_is_cached_when_the_vm_held_the_token_and_none_was_sent() {
        let d = tempfile::tempdir().unwrap();
        let links = RemoteLinks::with_pipeline(Paths::from_root_and_env(d.path().join("bridge"), None), Box::new(|_, _, _| Box::pin(std::future::pending::<Result<PipelineEnd, SpawnFailure>>())));
        let report = DeliveryReport::default();
        {
            let mut s = links.shared.borrow_mut();
            s.snap.credential = Some("combined");
            s.delivery = Some(report.clone());
        }
        let word = || links.snapshot().and_then(|s| s.credential);
        assert_eq!(word(), Some("combined"), "nothing offered yet: the source");
        report.note_held();
        assert_eq!(word(), Some("cached"), "the VM held it, nothing sent");
        report.note_sent();
        assert_eq!(word(), Some("combined"), "sent after all: the source");
        links.shared.borrow_mut().delivery = None;
        assert_eq!(word(), Some("combined"), "no report (a test's pipeline): the source");
    }

    /// The close waits for the live session's end (its detach out, the
    /// session task's best-effort suspend after it), within its budget.
    #[test]
    fn close_waits_for_the_session_within_its_budget() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            for (ends, budget) in [(true, Duration::from_secs(3)), (false, Duration::from_millis(300))] {
                let script: Script = Box::new(move |mut io: SpawnIo| {
                    Box::pin(async move {
                        let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                        let _ = io.control.recv().await;
                        if !ends {
                            std::future::pending::<()>().await;
                        }
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        Err(BridgeError::Transport("detached from spawn x".into()))
                    })
                });
                let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
                let mut link = start(&mut links);
                assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
                link.signal.send(Sig::Kill).unwrap();
                let at = std::time::Instant::now();
                drop(link);
                links.close(budget).await;
                let took = at.elapsed();
                if ends {
                    assert!(took >= Duration::from_millis(140) && took < Duration::from_secs(2), "waited {took:?} for the session's end");
                } else {
                    assert!(took >= Duration::from_millis(290) && took < Duration::from_secs(2), "bounded by the budget: {took:?}");
                }
            }
        });
    }

    /// The close waits, within its budget and after the sessions, for what
    /// the plan's generations left behind (`SessionPlan::take_closing`: L2's
    /// closing suspend, the WIP snapshot of a start dropped during its Touch
    /// ID); a task past the budget is left to the process's exit.
    #[test]
    fn close_waits_for_what_the_plan_left_within_its_budget() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let plan = Rc::new(SessionPlan::sample(d.path()));
            let done = Rc::new(Cell::new(false));
            let flag = Rc::clone(&done);
            plan.keep(tokio::task::spawn_local(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                flag.set(true);
            }));
            let mut links = remote_links(d.path(), Vec::new());
            links.plan = Some(Rc::clone(&plan));
            links.close(Duration::from_secs(3)).await;
            assert!(done.get(), "the close waited for the plan's task");
            plan.keep(tokio::task::spawn_local(std::future::pending::<()>()));
            let at = std::time::Instant::now();
            links.close(Duration::from_millis(200)).await;
            assert!(at.elapsed() < Duration::from_secs(2), "bounded by the budget: {:?}", at.elapsed());
        });
    }

    /// The pipeline's deadline holds until `Started` (plan §3: P4 ends at
    /// `spawned`): a spawn that has not started by it is the start's
    /// failure at the deadline (exit 8, the line naming the spawn), the
    /// link's first and only event, audited once; `detach{final}` goes to
    /// the session, and a `Started` that comes after it never reaches the pump.
    #[test]
    fn a_spawn_not_started_by_the_deadline_fails_with_8_and_is_detached() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<SpawnInput>>> = Rc::default();
            let seen = Rc::clone(&got);
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    // The hello hangs past the deadline; the detach comes, then a late `spawned`.
                    let input = io.control.recv().await;
                    seen.borrow_mut().extend(input);
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    Err(BridgeError::Transport("detached from spawn x while disconnected from microvm-1 (its detach grace ends it)".into()))
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Due(Duration::from_millis(50), script)]);
            let mut link = start(&mut links);
            let events = to_the_end(&mut link).await;
            match events.as_slice() {
                [ChildEvent::SpawnFailed(f)] => {
                    assert_eq!((f.code, f.step, f.cancelled, f.vm.as_deref()), (8, StartStep::Deadline, false, Some("microvm-1")));
                    assert_eq!(f.line.as_deref(), Some("did not start within Cursor's 60 s window (stuck at spawn): ai-env vm warm prepares the VM ahead"));
                }
                other => panic!("{other:?}"),
            }
            assert!(next(&mut link).await.is_none(), "nothing after the link's last event");
            assert_eq!(*got.borrow(), [SpawnInput::Detach { is_final: true }]);
            let audit = std::fs::read_to_string(Paths::from_root_and_env(d.path().join("bridge"), None).audit()).unwrap_or_default();
            assert_eq!(audit.matches("session_remote_failed").count(), 1, "{audit}");
            assert!(audit.contains("\"step\":\"deadline\"") && audit.contains("\"why\":\"deadline\"") && audit.contains("\"code\":\"8\"") && audit.contains("\"id\":\"microvm-1\""), "{audit}");
            assert_eq!(links.snapshot().unwrap().legs.len(), 4, "no spawn leg: the spawn never started");
        });
    }

    /// `Started` adds the `spawn` leg once per generation (a reattach's is no
    /// new one) and audits a claude `AUTH_TIMERS` did not measure as
    /// `auth_timers_unmeasured`, once per version on this Mac; the measured
    /// one never.
    #[test]
    fn started_adds_the_spawn_leg_and_audits_an_unmeasured_claude_once() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let script = |claude: &'static str| -> Script {
                Box::new(move |io: SpawnIo| {
                    Box::pin(async move {
                        let _ = io.events.send(started_event(Some(claude)));
                        // A reattach that found the spawn running says `Started` again.
                        let _ = io.events.send(started_event(Some(claude)));
                        let exit = exited(Some(0), None);
                        let _ = io.events.send(SpawnEvent::Exit(exit));
                        Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                    })
                })
            };
            let gens = vec![Gen::Session(Duration::ZERO, script("2.0.0")), Gen::Session(Duration::ZERO, script("2.0.0")), Gen::Session(Duration::ZERO, script(AUTH_TIMERS.claude))];
            let mut links = remote_links(d.path(), gens);
            for gen in 1..=3 {
                let mut link = links.start(gen, StartReq { why: StartWhy::First, credential: None }).unwrap();
                let _ = to_the_end(&mut link).await;
                let legs = links.snapshot().unwrap().legs;
                assert_eq!(legs.iter().map(|(leg, _)| *leg).collect::<Vec<_>>(), ["touchid", "select", "workspace", "gate", "spawn"], "{legs:?}");
            }
            let audit = std::fs::read_to_string(Paths::from_root_and_env(d.path().join("bridge"), None).audit()).unwrap_or_default();
            assert_eq!(audit.matches("auth_timers_unmeasured").count(), 1, "{audit}");
            assert!(audit.contains("\"claude\":\"2.0.0\""), "{audit}");
        });
    }

    /// A pump that lets a running spawn's link go leaves nothing running
    /// behind it: the adapter sends `detach{final}` (and `stdin_eof`).
    #[test]
    fn a_link_the_pump_lets_go_detaches_its_running_spawn() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<SpawnInput>>> = Rc::default();
            let seen = Rc::clone(&got);
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    if let Some(input) = io.control.recv().await {
                        seen.borrow_mut().push(input);
                    }
                    Err(BridgeError::Transport("detached from spawn x".into()))
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
            drop(link);
            links.close(T).await;
            assert_eq!(*got.borrow(), [SpawnInput::Detach { is_final: true }]);
        });
    }

    /// `drop_transport` (T8.6) reaches a running spawn's session, once, as
    /// `DropSocket` on its control (the session drops its socket and
    /// reattaches: `Link(false)`, `Link(true)`, never an end); before
    /// `Started` and after the exit nothing goes.
    #[test]
    fn drop_transport_reaches_the_running_spawns_session_only() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let got: Rc<RefCell<Vec<SpawnInput>>> = Rc::default();
            let seen = Rc::clone(&got);
            let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
            let script: Script = Box::new(move |mut io: SpawnIo| {
                Box::pin(async move {
                    let _ = start_rx.await;
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    // As the session: the drop is a lost socket, reattached.
                    if let Some(input) = io.control.recv().await {
                        seen.borrow_mut().push(input);
                    }
                    while let Ok(more) = io.control.try_recv() {
                        seen.borrow_mut().push(more);
                    }
                    let _ = io.events.send(SpawnEvent::Link(false));
                    let _ = io.events.send(SpawnEvent::Link(true));
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            links.drop_transport();
            let mut link = start(&mut links);
            tokio::time::sleep(Duration::from_millis(20)).await;
            links.drop_transport();
            assert!(links.shared.borrow().control.is_none(), "handed over, not started: nothing to drop");
            let _ = start_tx.send(());
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Started(_))));
            links.drop_transport();
            let events = to_the_end(&mut link).await;
            assert!(matches!(events[..], [ChildEvent::Link(false), ChildEvent::Link(true), ChildEvent::StdoutEof, ChildEvent::StderrEof, ChildEvent::Exit(_)]), "{events:?}");
            assert_eq!(*got.borrow(), [SpawnInput::DropSocket], "one drop, after Started only");
            assert!(links.shared.borrow().control.is_none(), "after the exit: nothing to drop");
            links.drop_transport();
            assert_eq!(links.snapshot().unwrap().link_drops, 1);
        });
    }

    /// S8 phase 4 (RESUME-3): the census's legs are the steps that lead to
    /// the session's `init_ms`. A resume miss's retry while the host still
    /// waits for its `initialize` answer adds its steps to generation 1's
    /// (the one Touch ID kept, the order kept); a retry after the host's
    /// answer leaves generation 1's as they are, its own coming after
    /// `init_ms`.
    #[test]
    fn a_retry_adds_its_legs_to_the_first_generations_while_the_host_waits() {
        for answered in [false, true] {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let root = d.path().to_path_buf();
                let mut links = RemoteLinks::with_pipeline(
                    Paths::from_root_and_env(d.path().join("bridge"), None),
                    Box::new(move |gen, _why, io| {
                        let root = root.clone();
                        Box::pin(async move {
                            // The retry's spawn takes 40 ms past its hand-over: a leg the census can tell apart.
                            let session = tokio::task::spawn_local(async move {
                                if gen == 2 {
                                    tokio::time::sleep(Duration::from_millis(40)).await;
                                }
                                printing(Vec::new(), exited(Some(i32::from(gen == 1)), None))(io).await
                            });
                            let end = end_with(&root, session);
                            // The retry's own steps, as `pipeline::retry` hands them over: no Touch ID (D1).
                            let legs = if gen == 1 { end.legs.clone() } else { vec![("select", 1), ("workspace", 2), ("gate", 3)] };
                            Ok(PipelineEnd { legs, ..end })
                        })
                    }),
                );
                let names = |legs: &[(&'static str, u64)]| legs.iter().map(|(leg, _)| *leg).collect::<Vec<_>>();
                let ms = |legs: &[(&'static str, u64)], name: &str| legs.iter().find(|(leg, _)| *leg == name).map_or(0, |(_, ms)| *ms);
                let mut link = start(&mut links);
                let _ = to_the_end(&mut link).await;
                let first = links.snapshot().unwrap().legs;
                assert_eq!(names(&first), LEG_NAMES, "{first:?}");
                let why = StartWhy::ResumeRetry { session_id: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), init_answered: answered };
                let mut link = links.start(2, StartReq { why, credential: None }).unwrap();
                let _ = to_the_end(&mut link).await;
                let legs = links.snapshot().unwrap().legs;
                assert_eq!(names(&legs), LEG_NAMES, "answered {answered}: {legs:?}");
                if answered {
                    assert_eq!(legs, first, "after the host's answer the retry's steps, its spawn too, are no legs");
                } else {
                    assert_eq!(["touchid", "select", "workspace", "gate"].map(|l| ms(&legs, l)), [10, 21, 32, 8], "{legs:?}");
                    assert!(ms(&legs, "spawn") >= ms(&first, "spawn") + 40, "the retry's spawn adds to the first's: {legs:?}");
                }
            });
        }
    }

    /// A second generation (the resume miss's retry) starts its snapshot
    /// afresh at its hand-over: none of the first spawn's pid, claude, link
    /// state or last stdout seq, so the row never pairs the second spawn
    /// with the first one's seq; then its own.
    #[test]
    fn a_second_generation_starts_its_snapshot_afresh() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let three = vec![b"a\n".to_vec(), b"b\n".to_vec(), b"c\n".to_vec()];
            let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
            let second: Script = Box::new(move |io: SpawnIo| {
                Box::pin(async move {
                    let _ = start_rx.await;
                    let _ = io.events.send(SpawnEvent::Started { spawn_id: SpawnId::new_v7(), pid: 5151, pgid: 5151, claude_version: Some("2.1.297".into()) });
                    let _ = io.events.send(SpawnEvent::Stdout { seq: 1, bytes: b"d\n".to_vec() });
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    wait_marked(&io, 1, 0).await?;
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, printing(three, exited(Some(1), None))), Gen::Session(Duration::ZERO, second)]);
            let mut link = start(&mut links);
            assert_eq!(lines_of(&to_the_end(&mut link).await).len(), 3);
            let first = links.snapshot().unwrap();
            assert_eq!((first.last_acked_seq, first.vm_pid, first.link_up), (3, Some(4242), true));
            let mut link = links.start(2, StartReq { why: StartWhy::ResumeRetry { session_id: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), init_answered: false }, credential: None }).unwrap();
            let until = std::time::Instant::now() + T;
            while links.snapshot().unwrap().spawn == first.spawn {
                assert!(std::time::Instant::now() < until, "generation 2 was never handed over");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let handed = links.snapshot().unwrap();
            assert_eq!((handed.last_acked_seq, handed.vm_pid, handed.claude, handed.auth_timers, handed.link_up), (0, None, None, None, false), "nothing of the first spawn's");
            let _ = start_tx.send(());
            assert_eq!(lines_of(&to_the_end(&mut link).await), [b"d".to_vec()]);
            let second = links.snapshot().unwrap();
            assert_eq!((second.last_acked_seq, second.vm_pid, second.claude.as_deref()), (1, Some(5151), Some("2.1.297")));
            assert_ne!(second.spawn, first.spawn);
        });
    }

    /// The stderr queue full (the copy task has not run yet: all the
    /// chunks come in one turn of the adapter, within tokio's budget of 128
    /// polls) drops a chunk, counts it and marks it at once, so the session,
    /// which ends only once every stderr seq is marked, still ends: the
    /// last chunks are dropped ones, whose marks nothing else gives.
    #[test]
    fn a_full_stderr_queue_drops_and_marks_and_the_session_still_ends() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let n = STDERR_QUEUE as u64 + 32;
            let marked: Rc<Cell<Option<bool>>> = Rc::default();
            let said = Rc::clone(&marked);
            let script: Script = Box::new(move |io: SpawnIo| {
                Box::pin(async move {
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    for seq in 1..=n {
                        // Empty chunks: the queue's work without filling the test's stderr.
                        let _ = io.events.send(SpawnEvent::Stderr { seq, bytes: Vec::new(), dropped: 0 });
                    }
                    let exit = exited(Some(0), None);
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    let r = tokio::time::timeout(Duration::from_secs(3), wait_marked(&io, 0, n)).await;
                    said.set(Some(matches!(r, Ok(Ok(())))));
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            let events = to_the_end(&mut link).await;
            assert!(matches!(events.last(), Some(ChildEvent::Exit(_))), "{events:?}");
            assert!(next(&mut link).await.is_none(), "the session ended, and the link with it");
            assert_eq!(marked.get(), Some(true), "every stderr seq was marked: the dropped ones at once");
        });
    }

    /// A code-out report is counted once however often it is looked at (W4's
    /// `last` keeps returning it); a new one counts again, `ok` when it
    /// succeeded, and the newest `box/wip/*` it promoted is the snapshot's
    /// `last_wip_fetch`.
    #[test]
    fn a_fetch_report_is_counted_once() {
        let mut shared = Shared::default();
        shared.count(None);
        let failed = FetchReport { at: "2026-10-12T10:00:00Z".into(), ok: false, note: Some("code-out: x".into()), ..FetchReport::default() };
        shared.count(Some(failed.clone()));
        shared.count(Some(failed));
        assert_eq!((shared.snap.fetch_ok, shared.snap.fetch_runs, shared.snap.last_wip_fetch.as_deref()), (0, 1, None));
        let wip = |n: &str| format!("{BOX_REFS}wip/{n}");
        let promoted = std::collections::BTreeMap::from([(wip("20261012T100100Z-1"), "a".repeat(40)), (wip("20261012T100200Z-2"), "b".repeat(40)), (format!("{BOX_REFS}main"), "c".repeat(40))]);
        let fetched = FetchReport { at: "2026-10-12T10:02:00Z".into(), ok: true, promoted, ..FetchReport::default() };
        shared.count(Some(fetched.clone()));
        shared.count(Some(fetched));
        assert_eq!((shared.snap.fetch_ok, shared.snap.fetch_runs), (1, 2));
        assert_eq!(shared.snap.last_wip_fetch, Some(wip("20261012T100200Z-2")));
    }

    /// The VM's stderr reaches the wrapper's before the link says it ended
    /// (`StderrEof`): a chunk queued just before the exit is written, its seq
    /// marked, by then, or `STDERR_DRAIN` (the wait's bound) has passed.
    #[test]
    fn the_vms_stderr_is_written_before_its_eof() {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let consumed: Rc<RefCell<Option<Arc<Consumed>>>> = Rc::default();
            let shared = Rc::clone(&consumed);
            let exit_at: Rc<Cell<Option<std::time::Instant>>> = Rc::default();
            let exit_sent = Rc::clone(&exit_at);
            let script: Script = Box::new(move |io: SpawnIo| {
                Box::pin(async move {
                    *shared.borrow_mut() = Some(Arc::clone(&io.consumed));
                    let _ = io.events.send(started_event(Some(AUTH_TIMERS.claude)));
                    // One byte, a newline: a write the copy task waits on (tokio's stderr writes on a blocking thread).
                    let _ = io.events.send(SpawnEvent::Stderr { seq: 1, bytes: b"\n".to_vec(), dropped: 0 });
                    let exit = exited(Some(0), None);
                    exit_sent.set(Some(std::time::Instant::now()));
                    let _ = io.events.send(SpawnEvent::Exit(exit));
                    wait_marked(&io, 0, 1).await?;
                    Ok(SpawnOutcome { spawn_id: SpawnId::new_v7(), exit })
                })
            });
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, script)]);
            let mut link = start(&mut links);
            loop {
                match next(&mut link).await {
                    Some(ChildEvent::StderrEof) => break,
                    Some(_) => {}
                    None => panic!("the link ended before its StderrEof"),
                }
            }
            let marked = consumed.borrow().as_ref().map(|c| c.seqs().1);
            let waited = exit_at.get().map(|t| t.elapsed());
            assert!(marked == Some(1) || waited >= Some(STDERR_DRAIN), "the VM's stderr chunk was written before its EOF (marked {marked:?}, {waited:?} after the exit)");
            assert!(matches!(next(&mut link).await, Some(ChildEvent::Exit(_))));
        });
    }

    /// The splitter over any chunking of the CLI's output: the lines come
    /// out byte for byte as the CLI printed them (a `\r` kept, an empty line
    /// kept, a long one whole, the 2.1.296 `rate_limit_event` line), the
    /// last without its newline after the exit.
    fn resplit(chunks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let d = tempfile::tempdir().unwrap();
        on_local(async {
            let mut links = remote_links(d.path(), vec![Gen::Session(Duration::ZERO, printing(chunks, exited(Some(0), None)))]);
            let mut link = start(&mut links);
            lines_of(&to_the_end(&mut link).await)
        })
    }

    fn cli_lines() -> Vec<Vec<u8>> {
        let rate = include_str!("../../../tests/fixtures/claude/valid-stream-json-2.1.296.jsonl").lines().find(|l| l.contains("rate_limit_event")).unwrap().as_bytes().to_vec();
        vec![
            br#"{"type":"system","subtype":"init","session_id":"s"}"#.to_vec(),
            rate,
            Vec::new(),
            br#"{"type":"assistant","message":{"content":[]}}"#.to_vec(),
            [&b"{\"type\":\"stream_event\",\"pad\":\""[..], &vec![b'p'; 70_000], b"\"}\r"].concat(),
            br#"{"type":"result","subtype":"success","is_error":false}"#.to_vec(),
            b"tail without a newline".to_vec(),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

        /// M09 at the splitter: any split points of the stdout stream give the CLI's lines.
        #[test]
        fn stdout_chunks_are_resplit_into_lines_at_the_cli_limit(cuts in proptest::collection::vec(0usize..80_000, 0..12)) {
            let lines = cli_lines();
            let stream = lines.join(&b'\n');
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (stream.len() + 1)).collect();
            points.sort_unstable();
            points.dedup();
            let mut chunks = Vec::new();
            let mut at = 0;
            for p in points.into_iter().chain([stream.len()]) {
                if p > at {
                    chunks.push(stream[at..p].to_vec());
                    at = p;
                }
            }
            proptest::prop_assert_eq!(resplit(chunks), lines);
        }
    }
}
