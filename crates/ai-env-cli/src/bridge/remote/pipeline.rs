//! The remote session's pre-spawn pipeline (S8 §3): P0 the prechecks (no
//! AWS, no Touch ID), P1 the Touch ID (D1: one per wrapper process), P2
//! SELECT_VM, P3 the workspace beside the gate and the token, P4 the spawn,
//! all of P1–P4 within `remote::INIT_DEADLINE` of the census start; a
//! failure is a `remote::Failure`. Built in S8 wave 1 (W2).
//!
//! S8 phase 0 froze the seam between this pipeline and the pump's remote
//! link (W1, `remote::link::RemoteLinks`): what P0 hands the link
//! ([`SessionPlan`], from [`precheck`]), the call the link makes for each
//! child generation ([`run`]), and what that call gives back
//! ([`PipelineEnd`], or the `SpawnFailure` the link reports).
//!
//! - **P0** ([`precheck`], before the pump supervises anything; no AWS call,
//!   no Touch ID), in this order, its first refusal the failure:
//!   bridge.toml for the remote path (that it loads, else exit 1 with its
//!   error's first line; `[wrapper]`, `[seed]`, `Ctx::for_wrapper`); the
//!   cwd; the VM's `Choice` (`AI_ENV_BRIDGE_VM` pinned and checked here; a
//!   `--resume`'s VM preferred, from its registry row; else the
//!   workspace's); `workspace::resolve` (D6: a workspace that is no git
//!   repository is exit 9 at once); the run plan (vpc egress,
//!   `workspace_v1` and S9's `transcript_s3_v1` required); the sealed token
//!   (`sealed_token_plan`) and the runtime key (`runtime_key_sealed`); the
//!   gate's local half (`provisional_gate`); the keystore; the VM's argv
//!   (`claude`, the host's arguments `argv::sanitise`d, no
//!   `--session-mirror`: S9 keeps a remote chat's transcript in S3, never on
//!   this Mac) and environment (`remote::env`, L4); the spawn frame within
//!   its cap; the workspace's `.active` lock, shared, for the process's life
//!   (one try: while a closing session holds it alone, generation 1's
//!   pending start waits for it, where the host's EOF and the signals reach
//!   the wait); S9's transcript sync (`s3::TranscriptSync`: `[transcript]`,
//!   the transcripts bucket, this Mac's projects directory), for every
//!   session that keeps a transcript or resumes one, else exit 1; last, S9's
//!   size refusals of a `--resume` (`transcript_too_large`): a chat begun
//!   here over what a reopen carries inline (`Failure::TranscriptTooLarge`),
//!   and one S3 holds whose committed parts are over what a reopen pulls
//!   inline while no VM P2 could take can hold them: no pin, and
//!   `[vm].reuse_per_workspace` off or no row of the workspace's VMs but
//!   terminated ones, so P2 starts a new VM (`Failure::TranscriptPullTooLarge`,
//!   R5-AWS-1). So a chat an earlier check refuses gets that check's exit
//!   and line (the gate's 9, say). T0 is the census start, the start row's
//!   time.
//! - **P1**: `credential::backend_for_session` (the runtime key, and the
//!   token with it when `combined.env` is current; `state/unseal.lock`, the
//!   countdown as `ai-env-claude`, the budget ending 1 s before T0 + 50 s:
//!   `credential::room_until`), with
//!   `workspace::prepare` (the WIP snapshot and the scans' warm-up, local)
//!   on a blocking thread beside it, whose handle the plan keeps
//!   ([`SessionPlan::take_closing`]: nothing cancels a blocking thread);
//!   first on that thread, when P3 will send a `--resume`'s copy on this Mac
//!   up inline (a chat begun here, an S8 mirror; never one S3 holds), that
//!   copy through the seed's tripwires
//!   (`workspace::transcript::scan_mac_copy`: a finding starts no VM).
//! - **P2**: `vm::run::select_vm_detailed` with the plan's `Choice` (a VM
//!   whose caps were never read gets one `/health`: a VM without
//!   `workspace_v1` or `transcript_s3_v1` is exit 7 naming `make deploy`).
//! - **P3**: `try_join!` of the workspace branch (`ensure_workspace`, then
//!   a `--resume`'s transcript restored from S3 with P0's sync,
//!   `workspace::transcript::restore`: kept when the VM holds the committed
//!   prefix, else pulled, at most `wire::s3::INLINE_MAX` in all within the
//!   deadline: more is `Failure::TranscriptPullTooLarge` before any pull,
//!   naming `ai-env session stage UUID --warm`, and the reuse switch first
//!   when it is off: [`pull_cap`]) and the credential branch
//!   (`credential::prepare_session`: the gate, then the token); the first
//!   error drops the other (a tripwire closes a pending token dialog). Then
//!   a re-gate without a prompt if the pass passed half its life.
//! - **P4**: the spawn (`SpawnSpec` with its id, the VM path as cwd, the
//!   proxy variables then the session's, `remote::session_grace`) handed to
//!   its session task on the pump's `LocalSet` (`agent::run_spawn_with` with
//!   `hello.idle_s` 90), the code-out trigger beside it (a `--resume`'s id
//!   named to it at once: the settings' start capture runs in its task, best
//!   effort, never inside the init deadline; a fresh session's comes with
//!   its first `system/init`, through the pump; after each fetch the same
//!   task syncs the session's transcript to S3 and rewrites its view on this
//!   Mac). When the exit
//!   arrives, the session task starts the closing suspend as a task of its
//!   own and ends (L2, best effort: only with `[vm].suspend_on_close`, no
//!   other holder of the workspace's `.active` lock and no live spawn on the
//!   VM; SuspendMicrovm fired, never waited for; all within
//!   `CLOSING_BOUND`); the pump waits for it after the census end row
//!   ([`SessionPlan::take_closing`]). The suspend goes out only once the
//!   generation's code-out trigger is done (`codeout::TriggerWatch`: the
//!   pump's close closed it, and its last fetch ended or was given up at
//!   `codeout::CLOSE_WAIT`; plan §11's order): no fetch of the session
//!   starts after it, and the last one ended or was given up before it (one
//!   given up with its request already on its way may still reach the VM
//!   after it, and wake it).
//!
//! A resume miss's retry ([`StartWhy::ResumeRetry`]) takes no Touch ID: it
//! respawns on generation 1's VM with generation 1's backend, after the
//! transcript's restore (no deadline of its own: any size, within the
//! generation's bound) and a gate without a prompt, the token from the
//! VM's cache, within T0 + 50 s while the host's `initialize` is unanswered
//! (its answer is the host's first), else within its own 60 s
//! ([`deadline_of`]).
//! Nothing here prints an `ai-env:` line: notes and warnings go to
//! the wrapper's log (`bridge::voice`); the one line Cursor sees is the
//! pump's, from the `Failure`. Audit rows: `vm_select`,
//! `session_remote_start`, `session_remote_failed` (P1–P4's; P0's is the
//! pump's), `vm_suspend` (by `close`), and `auth_timers_unmeasured` once per
//! claude version ([`audit_auth_timers`], for the link's `Started`).
use crate::bridge::agent::credential::{self, CredentialPlan, CredentialSupply};
use crate::bridge::agent::exec::{agent_env, spawn_env};
use crate::bridge::agent::{run_spawn_with, AgentTarget, Delivery, DeliveryParts, DeliveryReport, SpawnIo, SpawnOutcome, SpawnSpec, Start};
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState};
use crate::bridge::codeout::{CodeoutCtx, CodeoutTrigger, TriggerWatch};
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::dataplane::{DataPlane, HttpsEndpoint, MintingTokens, TokenSource};
use crate::bridge::errors::BridgeError;
use crate::bridge::lab::VmKnobs;
use crate::bridge::pump::Session;
use crate::bridge::remote::link::{Carried, MoveWhy, SpawnFailure, StartStep, StartWhy};
use crate::bridge::remote::{audit_event as event, session_grace, Failure, INIT_DEADLINE, MOVE_WINDOW, PIN_KNOB, TRANSCRIPT_KNOB};
use crate::bridge::vm::cmd::{audit_event, provisional_gate, retry_gate_terminate, sealed_token_plan, Backend, Ctx};
use crate::bridge::vm::lock::{try_lock_exclusive, try_lock_shared, FlockGuard};
use crate::bridge::vm::registry::{self as vm_registry, RowStatus, VmRow};
use crate::bridge::vm::run::{self, Choice, Egress, Poll, RunFlags, RunPlan, Selected};
use crate::bridge::workspace::{self, vm_capability, Capability, EnsureCtx, PreparedSeed, SeedLimits, SeedWant, WorkspaceRef};
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::argv::{self, SanitiseOpts};
use crate::wire::frame::{Deliver, Frame, SpawnId, ARGV_MAX_BYTES, CAP_WORKSPACE_V1, CONTROL_FRAME_MAX, IDLE_DEFAULT_S};
use crate::bridge::remote::link::{LossCause, MoveDone, MoveEndRow, MoveKind};
use crate::bridge::remote::{MOVE_OLD_VM_WAIT, MOVE_SYNC_BUDGET};
use crate::bridge::setup_token::SetupToken;
use crate::bridge::agent::{run_spawn_parked, ParkReport, SpawnEvent};
use crate::bridge::park::{ParkCtl, ParkPolicy, QuietState};
use crate::bridge::remote::link::{request_of, MigrateTrigger, MoveFailure, MoveReady};
use crate::bridge::remote::{move_hold_ping, CARRY_P2_MIN_LEFT, MOVE_HOLD, REAP_WAIT};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// The closing suspend's whole run, from the exit on (L2): its wait for the
/// code-out trigger, its read of the VM's spawns and its SuspendMicrovm, so
/// its exclusive hold of the workspace's `.active` (the verdict and that
/// request alone) never outlasts it. The pump's wait for it cuts it sooner
/// (what is left of the close budget, [`SessionPlan::take_closing`]).
const CLOSING_BOUND: Duration = Duration::from_millis(crate::bridge::remote::CLOSE_BUDGET_MS);

/// How long generation 1's start (P0 tries once: [`hold_active_at_start`])
/// and `vm warm` wait for the workspace's `.active` lock while a closing
/// session holds it alone (around its suspend verdict and its
/// SuspendMicrovm: within [`CLOSING_BOUND`], which this outlasts); past it
/// the session goes on without (a warning in the log).
pub(crate) const ACTIVE_WAIT: Duration = Duration::from_secs(2);

/// A resume miss's retry after generation 1 answered the host's
/// `initialize`: its own window from its start (Cursor's 60 s window is
/// over; s8-design-session §3.7). One the host still waits on keeps T0 +
/// 50 s ([`deadline_of`]).
const RETRY_WINDOW: Duration = Duration::from_secs(60);

/// What P0 decided for the whole session, shared (`Rc`, on the pump's
/// `LocalSet`) by every generation's [`run`]: built by [`precheck`] only;
/// the link only hands it on. `Debug` shows counts, never an argument or an
/// environment value.
pub struct SessionPlan {
    pub paths: Paths,
    pub cfg: BridgeConfig,
    /// The VM's argv: `claude`, the host's arguments `argv::sanitise`d by
    /// `[wrapper] strip_add_dir` and `strip_debug` (no `--session-mirror`).
    pub argv: Vec<String>,
    /// The spawn's environment before the proxy variables (L4, `remote::env`):
    /// the forwarded names and the wrapper's own.
    pub env: BTreeMap<String, String>,
    /// The workspace (`workspace::resolve`): its VM path is the spawn's cwd.
    pub ws: WorkspaceRef,
    /// The census start (T0): P1–P4 are over by [`SessionPlan::init_deadline`].
    pub t0: Instant,
    /// `--resume`'s session id, when it is a uuid (the transcript's restore, the VM preferred).
    pub resume: Option<String>,
    /// The code-out trigger captures the VM's settings into the session's
    /// quarantine (T8.7): never for `--no-session-persistence` (Cursor's
    /// prompt-suggestion queries), which no registry row keeps, so nothing
    /// would ever show or remove that quarantine.
    capture_settings: bool,
    /// The lab knobs (debug builds), read at P0.
    knobs: VmKnobs,
    /// SELECT_VM's plan: vpc egress, the workspace (its canonical cwd), the
    /// `Choice`, `workspace_v1` and `transcript_s3_v1` required.
    run: RunPlan,
    /// The sealed setup-token: its seal id and how it reaches the CLI.
    token: CredentialPlan,
    /// The keystore the unseal reads (`AI_ENV_DIR`).
    store: Keystore,
    /// T0 on the clock the unseal measures Cursor's window with.
    window_from: std::time::Instant,
    /// The workspace's `.active` lock, shared, for the process's life (P0's,
    /// else generation 1's start's: [`hold_active_at_start`]); the closing
    /// suspend lets it go to see whether it is alone, then holds it shared
    /// again (a resume miss's retry may still come).
    active: RefCell<Option<FlockGuard>>,
    /// What outlives a generation's start or session: P1's snapshot thread,
    /// the closing suspend ([`SessionPlan::take_closing`]).
    closing: RefCell<Vec<JoinHandle<()>>>,
    /// `AI_ENV_BRIDGE_LAB_TRANSCRIPT=skip` (debug builds, L8): generation 1
    /// restores no transcript, so a resume misses and the retry restores it.
    skip_transcript: bool,
    /// The Mac's projects root and the slugs a session's transcript is
    /// looked for under (the cwd's, the registry row's).
    mac_projects: Option<PathBuf>,
    slugs: Vec<String>,
    /// What the session's transcript syncs with (S9, built at P0:
    /// [`transcript_sync_of`]): the code-out trigger's step after each fetch
    /// ([`session_sync`]: never for `--no-session-persistence`) and a
    /// `--resume`'s restore. `None` only for a session that neither keeps a
    /// transcript nor resumes one.
    transcript_sync: Option<crate::bridge::s3::TranscriptSync>,
    /// What the latest generation that reached its spawn leaves for a resume
    /// miss's retry and a move (S10: `Held` until S9, generation 1's alone).
    current: RefCell<Option<Current>>,
    /// S10: every VM a generation of this session spawned its claude on, in
    /// order (each may hold that claude's `<sid>.jsonl`): a fresh chat's move
    /// avoids them all (`--session-id` refuses a session whose file exists).
    spawned_on: RefCell<Vec<String>>,
    /// The highest generation started (a retry's start keeps a closing
    /// suspend from freezing the VM under it).
    started: Cell<u32>,
    /// Where the session's token came from (`combined` or `setup-token`: the
    /// wrapper unsealed it; `cached`: it counted on the VM's copy), set once
    /// a generation's gate passed (P3), before its spawn:
    /// `PipelineEnd::credential`, the census end row's `credential:` part.
    /// The token goes to the VM only with claude's spawn (`cached` instead
    /// when the session found the VM holding it and sent none:
    /// `PipelineEnd::delivery`).
    credential: Cell<Option<&'static str>>,
    /// S10 §D: the pump's quiet, each generation's park control's (a
    /// receiver of `RemoteLinks::quiet`'s, handed by `RemoteLinks::new`).
    quiet: RefCell<Option<tokio::sync::watch::Receiver<QuietState>>>,
    /// S10 §D: this wrapper as every `park` names it, the reaper judges it
    /// (`registry::process_identity` of its own pid, read at P0); `None`:
    /// unreadable, so the session never parks (`park:off(no_owner)`).
    owner: Option<crate::wire::frame::ParkOwner>,
    /// S10 §2.7: a reopen's carry off its `--resume` row's VM (gone, or near
    /// its wall), decided at P0: generation 1 starts on another VM.
    carry: Option<Carried>,
    /// S10 §B: the VM a migration's phase A prepared, held for the switch
    /// (until `MOVE_HOLD`, a `GET /health` keeping it running meanwhile).
    prepared: RefCell<Option<PreparedVm>>,
    /// S10 §B: the task of the migration's latest phase A, as the link
    /// started it ([`SessionPlan::hold_phase_a`]): a loss's move that turns
    /// into a re-address in M1 aborts it ([`SessionPlan::abandon_phase_a`]),
    /// its Touch ID dialog with it, before the move asks its own.
    phase_a: RefCell<Option<tokio::task::AbortHandle>>,
    /// S10 §B: a migration's switch began: the old generation's closing
    /// suspend is held off (its VM's work is fetched and synced next).
    moving: Cell<bool>,
    /// S10 §B: the generation a switch left, from its spawn on the new VM to
    /// that spawn's `Started`: the old VM a moved CLI that never started
    /// falls back to (the pump's next `Migrate` start, with no VM prepared).
    left: RefCell<Option<Current>>,
}

/// S10 §B: a migration's prepared VM ([`prepare_move`]): its row (its caps
/// read) and info, how SELECT_VM took it, since when it is held, and whether
/// the switch took it (no release at `MOVE_HOLD` then).
#[derive(Debug, Clone)]
struct PreparedVm {
    row: VmRow,
    vm: VmInfo,
    how: &'static str,
    at: Instant,
    switching: bool,
}

/// S10: what a generation's pipeline leaves to run once its spawn started
/// (`PipelineEnd::after_started`, run by the link's adapter at the first
/// `Started` as a task the process drops at its exit): an old VM's end after
/// a migration or a reopen's carry, generation 1's gc reconcile.
pub struct AfterStarted(pub std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>);

impl std::fmt::Debug for AfterStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AfterStarted")
    }
}

/// The latest generation's VM, row, how it was taken, its seed's word and
/// seeded head (S10 §2.7, in place of S9's `Held`): rewritten by every
/// generation that reaches its spawn (generation 1's `onwards`, a resume
/// miss's `retry`, a move's `move_gen`), so a retry and a move start from the
/// VM the chat runs on now. The runtime key's backend, P1's, stays shared by
/// every generation: no AWS call asks a Touch ID (D1).
#[derive(Clone)]
struct Current {
    backend: Rc<Backend>,
    row: VmRow,
    vm: VmInfo,
    how: &'static str,
    seed: &'static str,
    seeded_head: Option<String>,
}

impl SessionPlan {
    /// T0 + `remote::INIT_DEADLINE`: the bound on P1–P4 (plan §3), a timeout
    /// past it naming the step.
    #[must_use]
    pub fn init_deadline(&self) -> Instant {
        self.t0 + INIT_DEADLINE
    }

    /// The tasks that outlive a generation's start or its session: the
    /// closing suspend (L2, started as the exit arrives, within
    /// `CLOSING_BOUND`) and P1's WIP snapshot (a blocking thread a dropped
    /// start cannot stop). The pump awaits them after the census end row,
    /// within what is left of its close budget, then exits: what the budget
    /// cuts ends with the process (the idle policy suspends the VM anyway).
    #[must_use]
    pub fn take_closing(&self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut *self.closing.borrow_mut())
    }

    /// `task` for [`SessionPlan::take_closing`] (the finished ones dropped).
    pub(crate) fn keep(&self, task: JoinHandle<()>) {
        let mut closing = self.closing.borrow_mut();
        closing.retain(|t| !t.is_finished());
        closing.push(task);
    }

    /// The `vm`/`lab` context the pipeline's calls take.
    fn ctx(&self) -> Ctx {
        Ctx { paths: self.paths.clone(), cfg: self.cfg.clone(), knobs: self.knobs.clone() }
    }

    /// The VM `AI_ENV_BRIDGE_VM` pins (P0's `Choice::Pin`), if any: that VM
    /// or nothing, so S10's moves never take another (`RemoteSnapshot.pinned`).
    #[must_use]
    pub fn pinned(&self) -> Option<&str> {
        match &self.run.choice {
            Choice::Pin(id) => Some(id),
            _ => None,
        }
    }

    /// S10 §D: the pump's quiet as `RemoteLinks::quiet` sends it, which each
    /// generation's park control reads.
    pub(crate) fn set_quiet(&self, quiet: tokio::sync::watch::Receiver<QuietState>) {
        *self.quiet.borrow_mut() = Some(quiet);
    }

    /// S10 §B: the switch takes the prepared VM (no release at `MOVE_HOLD`
    /// then) and holds the old generation's closing suspend off; `false`:
    /// none is prepared (never, or released). What an earlier switch left
    /// ([`SessionPlan::left`]) is no fallback of this one.
    pub(crate) fn begin_switch(&self) -> bool {
        match self.prepared.borrow_mut().as_mut() {
            Some(p) => {
                p.switching = true;
                self.moving.set(true);
                self.left.borrow_mut().take();
                true
            }
            None => false,
        }
    }

    /// S10 §B: a switch that runs no migration's generation (its old link was
    /// lost meanwhile) is over: its prepared VM let go, the closing suspend no
    /// longer held off.
    pub(crate) fn end_switch(&self) {
        self.moving.set(false);
        if self.prepared.borrow().as_ref().is_some_and(|p| p.switching) {
            self.prepared.borrow_mut().take();
        }
    }

    /// S10 §B: the migration is given up (a loss's move took the chat off the
    /// VM it was to leave, or the session closes): its prepared VM let go
    /// whatever its switch (its hold's pings end), no switch under way, and no
    /// VM a switch left kept.
    pub(crate) fn release_prepared(&self) {
        self.moving.set(false);
        self.prepared.borrow_mut().take();
        self.left.borrow_mut().take();
    }

    /// S10 §B: the task the link runs the migration's phase A in, kept for
    /// [`SessionPlan::abandon_phase_a`] (a later phase A's replaces it).
    pub(crate) fn hold_phase_a(&self, task: tokio::task::AbortHandle) {
        *self.phase_a.borrow_mut() = Some(task);
    }

    /// S10 §B, §14 (wave 1c: a loss's move ends a pending migration), from
    /// the pipeline's side: phase A's task aborted (dropped at the
    /// `LocalSet`'s next tick: its Touch ID dialog closes and its turn on
    /// `state/unseal.lock` is let go, so the move's own dialog opens at once),
    /// then its prepared VM let go ([`SessionPlan::release_prepared`]). M1
    /// calls it as a respawn turns into a re-address, before the move's
    /// Touch ID: one move, one Touch ID. The link's bookkeeping and the
    /// `abandoned` row follow once the move's pipeline returned. Aborting a
    /// phase A that already ended does nothing.
    pub(crate) fn abandon_phase_a(&self) {
        if let Some(task) = self.phase_a.borrow_mut().take() {
            task.abort();
        }
        self.release_prepared();
    }

    /// A plan for a workspace at `/w`, its paths under `root` (tests).
    #[cfg(test)]
    pub(crate) fn sample(root: &std::path::Path) -> SessionPlan {
        use crate::bridge::workspace::{Head, WsKind};
        use crate::wire::workspace::ObjectFormat;
        let ws = WorkspaceRef {
            cwd: "/w".into(),
            root: "/w".into(),
            vm_cwd: "/w".into(),
            vm_root: "/w".into(),
            slug: "-w".into(),
            kind: WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        };
        let cfg = BridgeConfig::default();
        let run = RunPlan {
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            want_version: "active".into(),
            max_duration_s: cfg.vm.max_duration_s,
            idle: crate::bridge::api::IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            egress: Egress::Vpc,
            egress_connectors: Vec::new(),
            ingress_connectors: Vec::new(),
            shell: false,
            execution_role_arn: None,
            workspace: Some(("/w".into(), "-w".into())),
            new: false,
            label: None,
            wait: true,
            max_concurrent: cfg.vm.max_concurrent,
            reuse: true,
            migrate_before_wall_s: cfg.vm.migrate_before_wall_s,
            purpose: "session",
            warnings: Vec::new(),
            memory_mib: cfg.vm.memory_mib,
            client_token: None,
            pad_payload_to: None,
            choice: Choice::Workspace,
            workspace_cap: true,
            transcript_cap: true,
            avoid: Vec::new(),
        };
        SessionPlan {
            paths: Paths::from_root_and_env(root.join("bridge"), None),
            argv: vec!["claude".into(), "--output-format".into(), "stream-json".into()],
            env: BTreeMap::from([("DISABLE_AUTOUPDATER".to_string(), "1".to_string())]),
            ws,
            t0: Instant::now(),
            resume: None,
            capture_settings: true,
            knobs: VmKnobs::default(),
            run,
            token: CredentialPlan { deliver: Deliver::Fd, file: None, tag: "0".repeat(16) },
            store: Keystore::resolve(Some(root.join("keys"))).expect("a keystore root"),
            window_from: std::time::Instant::now(),
            active: RefCell::new(None),
            closing: RefCell::new(Vec::new()),
            skip_transcript: false,
            mac_projects: None,
            slugs: Vec::new(),
            transcript_sync: None,
            current: RefCell::new(None),
            spawned_on: RefCell::new(Vec::new()),
            started: Cell::new(0),
            credential: Cell::new(None),
            quiet: RefCell::new(None),
            owner: None,
            carry: None,
            prepared: RefCell::new(None),
            phase_a: RefCell::new(None),
            moving: Cell::new(false),
            left: RefCell::new(None),
            cfg,
        }
    }
}

impl std::fmt::Debug for SessionPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionPlan(argc={}, env={}, vm_cwd={}, resume={})", self.argv.len(), self.env.len(), self.ws.vm_cwd, self.resume.is_some())
    }
}

/// What a generation's [`run`] hands the link once its spawn went to the
/// session task: what the census and the registry take from the pipeline
/// (`link::RemoteSnapshot`), the trigger `LinkFactory::on_result` asks, and
/// the session itself.
#[derive(Debug)]
pub struct PipelineEnd {
    /// The VM SELECT_VM chose, and how (one of `remote::VM_HOW_WORDS`).
    pub vm: String,
    pub vm_how: &'static str,
    /// Each step's ms, in `remote::LEG_NAMES` order.
    pub legs: Vec<(&'static str, u64)>,
    /// What the workspace step did (`workspace::EnsureOutcome::word`), and a
    /// resume's restore (`workspace::TranscriptOutcome::word`).
    pub seed: &'static str,
    pub transcript: Option<&'static str>,
    /// The head the VM's checkout started from (the registry's `seeded_head`).
    pub seeded_head: Option<String>,
    /// Where the session's token came from (`combined`, `setup-token` or
    /// `cached`: [`SessionPlan`]'s word once P3's gate passed); it goes to
    /// the VM only with the spawn. The census end row's S7 `credential:`
    /// part (S8 W1, added to C3).
    pub credential: Option<&'static str>,
    /// What became of that token in the session (S8 wave 3, added to C3):
    /// when it found the VM's cache holding it and sent none
    /// (`DeliveryReport::held_by_vm`), the census says `cached`, not where
    /// the unused token came from. `None`: no delivery (a test's pipeline).
    pub delivery: Option<DeliveryReport>,
    /// The spawn's id (`SpawnSpec.id`), known before `spawned`.
    pub spawn_id: SpawnId,
    /// When the spawn must have started: the generation's deadline (T0 +
    /// 50 s, or a retry's own 60 s once the host's `initialize` was
    /// answered: [`deadline_of`]), which P4 reaches only at `spawned` (plan
    /// §3), so the link holds it past the hand-over ([`run`] sets it);
    /// `None`: no bound (a test's own pipeline).
    pub started_by: Option<Instant>,
    /// The per-result code-out of this VM's workspace.
    pub trigger: CodeoutTrigger,
    /// The session task (`agent::run_spawn_with` on the pump's `LocalSet`).
    /// Its events reach the link through the consumer's side of the
    /// generation's channels; its end is the spawn's: `Ok` once the exit was
    /// delivered, `Err` why the session gave up (before `Started`, the link
    /// reports a `SpawnFailed`; after it, `Lost` or `Detached`).
    pub session: JoinHandle<Result<SpawnOutcome, BridgeError>>,
    /// S10 (§2.7): P0 to P4 carried a reopened chat off its `--resume` row's
    /// VM (near its wall, or gone); the link copies it into
    /// `RemoteSnapshot.carried`. `None` until S10 wave 1b (C) builds the carry.
    pub carried: Option<Carried>,
    /// S10: a move's generation, what it did before its spawn (the kind that
    /// ran, the cut, the Touch ID, the seed's source); the link copies it
    /// into `RemoteSnapshot.moved`. `None` for any other generation.
    pub moved: Option<MoveDone>,
    /// S10: what runs once the spawn started ([`AfterStarted`]); `None`: nothing.
    pub after_started: Option<AfterStarted>,
}

/// What the moved CLI resumes (S10 L2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cut {
    /// Plain `--resume=<sid>`: no outstanding line, or the view shows none of the outstanding uuids; each is sent again.
    None,
    /// `--resume=<sid> --resume-session-at=<leaf>`: the first outstanding uuid sits after `leaf`; it and the rest are sent again.
    At(String),
    /// `--session-id=<sid>` and no `--resume`: a fresh chat (`MoveWhy.fresh_chat`) with a session id and outstanding lines.
    /// Decided before M2, which then restores nothing and reads no view; every outstanding line is sent again.
    Fresh,
}

impl Cut {
    /// `none`, `at`, `fresh`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Cut::None => "none",
            Cut::At(_) => "at",
            Cut::Fresh => "fresh",
        }
    }
}

/// The cut known before M2: `Some(Cut::Fresh)` for a fresh chat with a session id and outstanding lines,
/// `Some(Cut::None)` with no outstanding line; `None`: M2 restores, then `cut_of` reads one view.
#[must_use]
pub fn cut_before(why: &MoveWhy) -> Option<Cut> {
    if why.outstanding.is_empty() {
        return Some(Cut::None);
    }
    // A fresh chat's transcript is the dead CLI's alone: restored, or found on its own VM, it would make
    // `--session-id` refuse the session (`Session ID <sid> is already in use.`), so nothing is restored.
    (why.fresh_chat && why.session_id.is_some()).then_some(Cut::Fresh)
}

/// The cut a move resumes at, from one view of the restored transcript, the
/// outstanding lines' uuids (in send order) and the last assistant frame
/// forwarded before a `result` (plans/s10-contracts.md §2.9), for a chat
/// that is not fresh. U, the first outstanding uuid, not in the view: the
/// dead CLI never wrote it, so `None` (every line is sent again). In it:
/// `At(L)`, L the leaf when the view lists it before U, else the view's
/// entry just before U (a collapsed reply carries its last assistant
/// entry's uuid). U first in the view with no leaf there: `None`, logged.
#[must_use]
pub fn cut_of(view: &crate::wire::view::TranscriptViewReply, outstanding: &[String], leaf: Option<&str>) -> Cut {
    let Some(first) = outstanding.first() else { return Cut::None };
    let Some(at) = view.entries.iter().position(|e| e.uuid == *first) else { return Cut::None };
    let listed = |uuid: &str| view.entries[..at].iter().any(|e| e.uuid == uuid);
    if let Some(leaf) = leaf.filter(|l| !l.is_empty() && listed(l)) {
        return Cut::At(leaf.to_string());
    }
    match at.checked_sub(1).map(|before| view.entries[before].uuid.as_str()).filter(|u| !u.is_empty()) {
        Some(before) => Cut::At(before.to_string()),
        None => {
            tracing::info!(at, "the cut: the first outstanding line opens the view and no leaf is listed: plain --resume");
            Cut::None
        }
    }
}

/// The resume flags a moved CLI's argv loses ([`move_argv`]): those that take
/// a value (`--flag value` or `--flag=value`), then those that take none.
const RESUME_VALUE_FLAGS: [&str; 5] = ["--resume", "-r", "--session-id", "--resume-session-at", "--resume-drops-turn"];
const RESUME_BARE_FLAGS: [&str; 4] = ["--continue", "-c", "--fork-session", "--reply-on-resume"];

/// The moved CLI's argv: P0's `argv` without its resume flags (before a bare
/// `--`, every form of `--resume`, `--continue`, `--session-id`,
/// `--fork-session`, `--resume-session-at`, `--resume-drops-turn`,
/// `--reply-on-resume`, `-r`, `-c`; a `--flag value` form takes the next
/// token only when it is no flag), then the cut's (`None`: `--resume=<sid>`;
/// `At(L)`: with `--resume-session-at=<L>`; `Fresh`: `--session-id=<sid>`
/// alone), before the `--`; with no session id, P0's argv unchanged.
/// `--resume-drops-turn` is never added. The value of another flag
/// (`wire::argv::takes_value`) is kept as it is, whatever it reads.
///
/// A fork no init has named yet ([`forks_session`]: P0's `--fork-session`
/// beside its own `--resume` of `session_id`, the cut `None`) keeps P0's
/// argv whole: the moved CLI forks that session again (M2 restored it), at
/// P0's own `--resume-session-at`, and its init then names the fork, which
/// the pump adopts; stripped, the moved CLI would go on in the session it
/// forked from. Once the fork's id is adopted, the move resumes it as any.
#[must_use]
pub fn move_argv(argv: &[String], session_id: Option<&str>, cut: &Cut) -> Vec<String> {
    let Some(sid) = session_id else { return argv.to_vec() };
    let end = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    if *cut == Cut::None && forks_session(&argv[..end], sid) {
        tracing::info!("the moved CLI forks its session again: P0's argv kept (no init has named the fork yet)");
        return argv.to_vec();
    }
    let mut out = Vec::with_capacity(argv.len() + 2);
    let mut i = 0;
    while i < end {
        let a = &argv[i];
        let (flag, inline) = match a.split_once('=') {
            Some((f, _)) if f.starts_with('-') => (f, true),
            _ => (a.as_str(), false),
        };
        if RESUME_VALUE_FLAGS.contains(&flag) {
            let valued = !inline && argv[..end].get(i + 1).is_some_and(|v| !v.starts_with('-'));
            i += if valued { 2 } else { 1 };
            continue;
        }
        if RESUME_BARE_FLAGS.contains(&flag) {
            i += 1;
            continue;
        }
        out.push(a.clone());
        if !inline && argv::takes_value(flag) {
            if let Some(value) = argv[..end].get(i + 1) {
                out.push(value.clone());
                i += 1;
            }
        }
        i += 1;
    }
    match cut {
        Cut::None => out.push(format!("--resume={sid}")),
        Cut::At(leaf) => out.extend([format!("--resume={sid}"), format!("--resume-session-at={leaf}")]),
        Cut::Fresh => out.push(format!("--session-id={sid}")),
    }
    out.extend(argv[end..].iter().cloned());
    out
}

/// Whether `argv` (P0's, before a bare `--`) forks `sid`: `--fork-session`,
/// and its own `--resume` or `-r` (the last one) names `sid`, each read as
/// [`move_argv`]'s loop reads them (`--resume X`, `--resume=X`, `-r X`,
/// `-r=X`; another flag's value is no flag, whatever it reads).
fn forks_session(argv: &[String], sid: &str) -> bool {
    let (mut fork, mut resumed) = (false, None);
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with('-') => (f, Some(v)),
            _ => (a.as_str(), None),
        };
        if RESUME_VALUE_FLAGS.contains(&flag) {
            let next = if inline.is_none() { argv.get(i + 1).filter(|v| !v.starts_with('-')) } else { None };
            if matches!(flag, "--resume" | "-r") {
                resumed = inline.or(next.map(String::as_str));
            }
            i += if next.is_some() { 2 } else { 1 };
            continue;
        }
        if flag == "--fork-session" {
            fork = true;
        } else if inline.is_none() && argv::takes_value(flag) && i + 1 < argv.len() {
            i += 1;
        }
        i += 1;
    }
    fork && resumed == Some(sid)
}

/// How a workspace is resolved (`workspace::resolve`; tests inject theirs).
type Resolver<'a> = &'a dyn Fn(&BridgeConfig, &Path, Option<&str>) -> Result<WorkspaceRef, BridgeError>;

/// P0, in the wrapper before the pump supervises anything (no AWS call, no
/// Touch ID), in this order: bridge.toml for the remote path and its
/// checks, the cwd, the VM's `Choice` ([`choice_of`]: `AI_ENV_BRIDGE_VM`'s
/// pin, the resumed session's VM preferred, or the workspace's),
/// `workspace::resolve` (D6), the run plan (vpc egress, the caps), the
/// sealed token's plan, the runtime key, the provisional gate, the keystore,
/// the VM's argv, its environment, the spawn frame's size, the shared lock
/// on the workspace's `.active` (one try, no wait), S9's transcript sync,
/// then S9's size refusals of a `--resume` ([`transcript_too_large`]). The
/// first refusal is the failure: a chat over a size cap that an earlier
/// check refuses gets that check's exit and line. `Err` is the failure the
/// wrapper exits with: the pump prints its line, writes the census end row
/// and the `session_remote_failed` audit row.
pub fn precheck(sess: &Session) -> Result<SessionPlan, Failure> {
    precheck_with(sess, &|k| std::env::var_os(k), &workspace::resolve)
}

/// [`precheck`] with the environment (`env`, the wrapper's own: Cursor's)
/// and the workspace's resolution given (tests).
pub(crate) fn precheck_with(sess: &Session, env: &dyn Fn(&str) -> Option<OsString>, resolve: Resolver<'_>) -> Result<SessionPlan, Failure> {
    let precheck = |e: BridgeError| match Failure::from_error(StartStep::Precheck, e, None) {
        // `Failure::Refused` says "refused before any Touch ID: " itself.
        Failure::Refused { what } => Failure::Refused { what: what.strip_prefix("refused: ").map_or_else(|| what.clone(), str::to_string) },
        f => f,
    };
    let config = |e: &dyn std::fmt::Display| Failure::Config { first_line: e.to_string() };
    // No config: the wrapper routed this session on a bridge.toml that does not load
    // (`route::decide_loaded`). The line is its error, read again: the first line only, no TOML snippet.
    let Some(cfg) = sess.cfg.as_ref() else {
        let first_line = match BridgeConfig::load(&sess.paths) {
            Err(e) => e.to_string().lines().next().unwrap_or_default().to_string(),
            Ok(_) => format!("{} could not be read", sess.paths.config.display()),
        };
        return Err(Failure::Config { first_line });
    };
    cfg.wrapper.validate().map_err(|e| config(&e))?;
    cfg.seed.validate().map_err(|e| config(&e))?;
    let ctx = Ctx::for_wrapper(&sess.paths, cfg).map_err(|e| config(&e))?;
    // S10 (§5): `for_wrapper`'s `VmCfg::validate` refused a bad continuity key already; its warnings go to the log.
    for warning in cfg.vm.validate_continuity().unwrap_or_default() {
        tracing::warn!("{warning}");
    }
    let Some(cwd) = sess.cwd.as_deref() else {
        return Err(Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: "the working directory is unknown".into() });
    };
    let resume = sess.session.resume.clone().filter(|r| crate::bridge::registry::is_uuid(r));
    // S10 §6.1: an offline `session migrate` moves this chat now (its row `migrating`, its command still running).
    if let Some(row) = resume.as_deref().and_then(|id| crate::bridge::registry::read(&sess.paths, id).ok().flatten()) {
        if let Some(pid) = crate::bridge::migrate::moving_pid(&row) {
            return Err(Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: format!("session {} is being moved to a new VM (pid {pid}): reopen it in a minute", row.session_id) });
        }
    }
    let mut choice = choice_of(&ctx, resume.as_deref(), env)?;
    // S10 §2.7: a `--resume` row's VM gone or near its wall: generation 1 starts on another (the old one avoided).
    let carry = carry_of(&ctx, &choice);
    if let Some(c) = &carry {
        tracing::info!(vm = %c.from_vm, left_s = ?c.left_s, "the reopen carries the chat off its VM");
        choice = Choice::Workspace;
    }
    let ws = resolve(cfg, cwd, None).map_err(precheck)?;
    let flags = RunFlags { workspace: Some(ws.cwd.clone()), egress: Some(Egress::Vpc), purpose: "session", wait: true, ..RunFlags::default() };
    let mut run = RunPlan::from_cfg(cfg, &flags).map_err(precheck)?;
    run.choice = choice;
    run.avoid = carry.iter().map(|c| c.from_vm.clone()).collect();
    run.workspace_cap = true;
    // S9: a VM without the transcript store is never reused (its chat lives in S3).
    run.transcript_cap = true;
    let token = sealed_token_plan(&ctx).map_err(|e| match e {
        CliError::AuthUnavailable(why) => Failure::NoToken { why },
        other => config(&other),
    })?;
    runtime_key_sealed(&ctx)?;
    provisional_gate(&ctx, &run).map_err(|e| precheck(BridgeError::Cli(e)))?;
    let store = Keystore::resolve(env("AI_ENV_DIR").filter(|d| !d.is_empty()).map(PathBuf::from)).map_err(|e| precheck(BridgeError::Cli(e)))?;
    let argv = vm_argv(cfg, &sess.args)?;
    let session_env = crate::bridge::remote::env::session_env(cfg, env).map_err(|what| Failure::Refused { what })?;
    spawn_frame_fits(&ctx, &argv, &ws, &session_env)?;
    // One try: P0 runs before the pump reads the host or listens for a stop, so a closing session's exclusive
    // hold is waited for in generation 1's pending start ([`hold_active_at_start`]), never here.
    let active = try_lock_shared(&sess.paths.workspace_active(&ws.slug)).map_err(precheck)?;
    let elapsed = Duration::from_millis(crate::wire::time::unix_now_ms().saturating_sub(sess.start_row.start));
    let mac_projects = mac_config_dir(env).map(|d| d.join("projects"));
    let registry_slug = resume.as_deref().and_then(|id| crate::bridge::registry::read(&sess.paths, id).ok().flatten()).and_then(|r| r.slug);
    let slugs: Vec<String> = std::iter::once(ws.slug.clone()).chain(registry_slug).collect();
    // S9: what the transcript syncs with, before any Touch ID: a session that keeps or resumes one never starts without it.
    let keeps = !sess.session.no_session_persistence || resume.is_some();
    let transcript_sync = transcript_sync_of(&sess.paths, cfg, &ctx.knobs, &ws, mac_projects.as_deref(), keeps).map_err(|e| config(&e))?;
    // S9: a chat begun on this Mac over what a reopen carries inline goes through `session stage` first, and one S3
    // holds that no VM P2 could take holds, over what a reopen pulls inline, through `session stage --warm` (no Touch ID).
    transcript_too_large(&sess.paths, mac_projects.as_deref(), &slugs, resume.as_deref(), &run)?;
    let skip_transcript = cfg!(debug_assertions) && env(TRANSCRIPT_KNOB).is_some_and(|v| v == "skip");
    tracing::info!(argc = argv.len(), env = session_env.len(), choice = run.choice.word(), resume = resume.is_some(), skip_transcript, "remote session planned");
    if let Some(c) = &carry {
        // S10 §2.7: the carry's `session_move`, at P0's choice (generation 1).
        let (kind, why) = carry_words(c);
        let mut pairs = vec![("session", resume.clone().unwrap_or_else(|| "-".to_string())), ("gen", "1".to_string()), ("kind", kind.word().to_string())];
        pairs.push(if c.left_s.is_some() { ("trigger", why.to_string()) } else { ("cause", why.to_string()) });
        pairs.extend([("from_vm", c.from_vm.clone()), ("outstanding", "0".to_string()), ("cancelled", "0".to_string())]);
        audit_event(&sess.paths, event::SESSION_MOVE, &pairs);
    }
    // S10 §D: this wrapper, as a park names it (the reaper of a later start judges it alive by it).
    let owner = crate::bridge::registry::process_identity(std::process::id()).map(|(_, started)| crate::wire::frame::ParkOwner { pid: std::process::id(), started });
    Ok(SessionPlan {
        paths: sess.paths.clone(),
        cfg: cfg.clone(),
        argv,
        env: session_env,
        ws,
        t0: Instant::now().checked_sub(elapsed).unwrap_or_else(Instant::now),
        resume,
        capture_settings: !sess.session.no_session_persistence,
        knobs: ctx.knobs,
        run,
        token,
        store,
        window_from: std::time::Instant::now().checked_sub(elapsed).unwrap_or_else(std::time::Instant::now),
        active: RefCell::new(active),
        closing: RefCell::new(Vec::new()),
        skip_transcript,
        mac_projects,
        slugs,
        transcript_sync,
        current: RefCell::new(None),
        spawned_on: RefCell::new(Vec::new()),
        started: Cell::new(0),
        credential: Cell::new(None),
        quiet: RefCell::new(None),
        owner,
        carry,
        prepared: RefCell::new(None),
        phase_a: RefCell::new(None),
        moving: Cell::new(false),
        left: RefCell::new(None),
    })
}

/// S10 §2.7: the carry a reopen makes off its `--resume` row's VM (P0's
/// `Choice::Prefer`, never a pin), from local state alone: that VM's row
/// terminated, or its wall passed (the platform ends a VM there: the wall's
/// re-address stands, migration on or off), is a re-address (`left_s`
/// none); with migration on (`VmCfg::migrate_margin`), a row with at most
/// the margin of its wall left is a migration (`left_s` what is left). A VM
/// with no row, or one that cannot be read, carries nothing: P2 judges it as
/// S9 does (a preferred VM it cannot reuse is passed over for the
/// workspace's).
fn carry_of(ctx: &Ctx, choice: &Choice) -> Option<Carried> {
    let Choice::Prefer(id) = choice else { return None };
    match vm_registry::read_row(&ctx.paths, id) {
        Ok(Some(row)) if row.status == RowStatus::Terminated => Some(Carried { from_vm: id.clone(), left_s: None }),
        Ok(Some(row)) => {
            let left = row.wall_left(crate::wire::time::unix_now())?;
            if left <= 0 {
                return Some(Carried { from_vm: id.clone(), left_s: None });
            }
            let margin = ctx.cfg.vm.migrate_margin()?;
            (left <= i64::from(margin)).then(|| Carried { from_vm: id.clone(), left_s: Some(left) })
        }
        Ok(None) => None,
        Err(e) => {
            tracing::info!(vm = %id, "the --resume row's VM cannot be read ({e}): no carry");
            None
        }
    }
}

/// A carry's kind and its why (§2.7, §4.2): off a VM near its wall a
/// migration (`reopen`, its trigger), off a gone one a re-address (`vm_gone`, its cause).
fn carry_words(c: &Carried) -> (MoveKind, &'static str) {
    if c.left_s.is_some() {
        (MoveKind::Migrate, "reopen")
    } else {
        (MoveKind::Readdress, LossCause::VmGone.word())
    }
}

/// A carry's `vms[]` why and `session_remote_start`'s (§6.1): `migrate:reopen` or `readdress:vm_gone`.
fn carry_why(c: &Carried) -> String {
    let (kind, why) = carry_words(c);
    format!("{}:{why}", kind.word())
}

/// P0's transcript sync (S9): what the code-out trigger syncs the session's
/// transcript with after each turn, and what a `--resume`'s restore pulls
/// with (`s3::TranscriptSync::for_workspace`: `[transcript].view_messages`
/// validated, the transcripts bucket state/infra.toml records, this Mac's
/// projects directory for the view), built once, before any Touch ID, for
/// every session that keeps a transcript or resumes one (`keeps`; `None`
/// for `--no-session-persistence` alone). With S8's mirror gone that sync is
/// all that takes a remote chat's transcript off its VM and its view to
/// Cursor's picker (the shim's tail push at `/suspend` and `/terminate`
/// needs the URL a sync hands it), so a session that cannot build it never
/// starts: the error names the key, `make infra-status WRITE=1` or the
/// missing projects directory, and P0 makes it exit 1.
fn transcript_sync_of(paths: &Paths, cfg: &BridgeConfig, knobs: &VmKnobs, ws: &WorkspaceRef, mac_projects: Option<&Path>, keeps: bool) -> Result<Option<crate::bridge::s3::TranscriptSync>, BridgeError> {
    if !keeps {
        return Ok(None);
    }
    let Some(projects) = mac_projects else {
        return Err(BridgeError::Config("neither CLAUDE_CONFIG_DIR nor HOME is set: the chat's view has nowhere to go".into()));
    };
    crate::bridge::s3::TranscriptSync::for_workspace(paths, cfg, knobs, ws, projects).map(Some)
}

/// P0's size refusals (S9), from local state only, before any Touch ID. A
/// `--resume` whose chat S3 does not hold (no manifest) and whose copy on
/// this Mac (the first of `seed::candidates`, never a view) is over
/// `wire::s3::INLINE_MAX` in all is `Failure::TranscriptTooLarge`, from the
/// files' sizes only: naming `ai-env session stage UUID --warm` for a chat
/// begun here, `ai-env session migrate-s9` and then that `--warm` for an S8
/// mirror (`s3::manifest::origin_of`). At or under the cap P3 sends it up
/// inline. One S3 holds (a manifest) goes to [`pull_too_large`].
fn transcript_too_large(paths: &Paths, mac_projects: Option<&Path>, slugs: &[String], resume: Option<&str>, run: &RunPlan) -> Result<(), Failure> {
    use crate::bridge::s3::manifest::{origin_of, read, ORIGIN_S8_MIRROR, ORIGIN_VM};
    let Some(id) = resume else { return Ok(()) };
    if let Some(m) = read(paths, id).ok().flatten() {
        return pull_too_large(paths, &m, run);
    }
    let Some(projects) = mac_projects else { return Ok(()) };
    let origin = origin_of(paths, id);
    if origin == Some(ORIGIN_VM) {
        return Ok(());
    }
    let refs: Vec<&str> = slugs.iter().map(String::as_str).collect();
    let Some(dir) = crate::bridge::seed::candidates(projects, &refs, id).into_iter().next() else { return Ok(()) };
    if crate::bridge::view::is_view_file(&dir.join(format!("{id}.jsonl"))) {
        return Ok(());
    }
    match crate::bridge::seed::transcript_files_capped(&dir, id, crate::wire::s3::INLINE_MAX) {
        Err(BridgeError::TranscriptTooLarge { session, bytes }) => Err(Failure::TranscriptTooLarge { session, bytes, s8_mirror: origin == Some(ORIGIN_S8_MIRROR) }),
        // Anything else is P3's to say (it reads the same files again).
        _ => Ok(()),
    }
}

/// P0's half of the reopen's pull cap (S9, R5-AWS-1): a chat S3 holds whose
/// committed parts alone (`m`'s, the least P3 would pull: a tail only adds)
/// are over `wire::s3::INLINE_MAX` is `Failure::TranscriptPullTooLarge`
/// when no VM P2 could take can hold them: no `AI_ENV_BRIDGE_VM` pin, and
/// P2 sure to start a new VM, which holds nothing: with
/// `[vm].reuse_per_workspace` off ([`reuse_off`]: the line asks for the
/// switch first, since `session stage --warm` would warm yet another VM),
/// or when no row of the workspace's VMs is anything but terminated. P3
/// would refuse the pull anyway, after the Touch ID and the VM's start.
/// Any other row (running, suspended, pending, unknown) may be a VM that
/// holds the committed prefix (`session stage --warm` restores it there),
/// as may a pinned VM: P3 decides, from the VM's stat and the tail S3
/// lists, which P0 cannot have without an AWS call. The rows are
/// SELECT_VM's own list (`vm_registry::list_rows`: a row it cannot read is
/// one P2 never takes); a registry that cannot be listed refuses nothing.
fn pull_too_large(paths: &Paths, m: &crate::bridge::s3::manifest::Manifest, run: &RunPlan) -> Result<(), Failure> {
    let bytes: u64 = m.parts.iter().map(|p| p.len).sum();
    if bytes <= crate::wire::s3::INLINE_MAX || matches!(run.choice, Choice::Pin(_)) {
        return Ok(());
    }
    let refused = |off: bool| Err(Failure::TranscriptPullTooLarge { session: m.session.clone(), bytes, reuse_off: off, pinned: None });
    if reuse_off(run) {
        return refused(true);
    }
    let Some((canonical, _)) = &run.workspace else { return Ok(()) };
    let key = run::workspace_key(canonical);
    let Ok(rows) = vm_registry::list_rows(paths) else { return Ok(()) };
    // S10 §2.7: a VM the reopen's carry leaves (near its wall) holds the chat for no start.
    if rows.iter().any(|r| r.workspace.as_deref() == Some(key.as_str()) && r.status != RowStatus::Terminated && !run.avoid.contains(&r.id)) {
        return Ok(());
    }
    refused(false)
}

/// Whether P2 starts a new VM for `run` whatever the rows say:
/// `[vm].reuse_per_workspace` off (SELECT_VM then reuses no VM, the resumed
/// session's included) and no pin (a pinned VM is taken whatever the switch
/// says).
fn reuse_off(run: &RunPlan) -> bool {
    !run.reuse && !matches!(run.choice, Choice::Pin(_))
}

/// P3's pull cap as Cursor sees it: with [`reuse_off`] the line asks for
/// the switch first, as P0's does (a last tail can take a chat past the cap
/// that P0 let through); S10 (F3b): a pinned VM that lacks the chat is
/// named, the line asking to unset the pin first (P0 leaves a pin to P3).
fn pull_cap(run: &RunPlan, mut f: Failed) -> Failed {
    if let Failure::TranscriptPullTooLarge { reuse_off: off, pinned, .. } = &mut f.failure {
        *off = reuse_off(run);
        if let Choice::Pin(vm) = &run.choice {
            *pinned = Some(vm.clone());
        }
    }
    f
}

/// The VM SELECT_VM takes (plan §1): `AI_ENV_BRIDGE_VM` pins one, checked
/// here, before any Touch ID: a VM id (else 2), a row (else 8), not
/// terminated (else 8), vpc egress and no `--shell` (else 9), an image with
/// `workspace_v1` and S9's `transcript_s3_v1` as last read (else 7, `make
/// deploy`). Else a `--resume`'s VM (its registry row's `microvm_id`) is
/// preferred; else the workspace's.
fn choice_of(ctx: &Ctx, resume: Option<&str>, env: &dyn Fn(&str) -> Option<OsString>) -> Result<Choice, Failure> {
    if let Some(raw) = env(PIN_KNOB).filter(|v| !v.is_empty()) {
        let id = raw.to_string_lossy().into_owned();
        if !vm_registry::is_vm_id(&id) {
            return Err(Failure::PinInvalid);
        }
        let row = vm_registry::read_row(&ctx.paths, &id).map_err(|e| Failure::from_error(StartStep::Precheck, e, None))?;
        let Some(row) = row.filter(|r| r.status != RowStatus::Terminated) else {
            return Err(Failure::PinGone { vm: id });
        };
        if row.egress != Egress::Vpc.as_str() || row.shell {
            let shell = if row.shell { " and --shell" } else { "" };
            return Err(Failure::Refused { what: format!("the pinned VM {id} ({PIN_KNOB}) runs {} egress{shell}: a session needs vpc egress without --shell; unset {PIN_KNOB}, or pin another", row.egress) });
        }
        if vm_capability(&row) == Capability::No {
            return Err(Failure::OldImage { vm: id, cap: CAP_WORKSPACE_V1 });
        }
        if workspace::vm_capability_of(&row, crate::wire::frame::CAP_TRANSCRIPT_S3_V1) == Capability::No {
            return Err(Failure::OldImage { vm: id, cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1 });
        }
        return Ok(Choice::Pin(id));
    }
    let preferred = resume.and_then(|id| crate::bridge::registry::read(&ctx.paths, id).ok().flatten()).and_then(|r| r.microvm_id).filter(|id| vm_registry::is_vm_id(id));
    Ok(preferred.map_or(Choice::Workspace, Choice::Prefer))
}

/// P0 in container mode, when an unseal will happen: the runtime key is
/// sealed (`credentials/aws.env`), else exit 5 naming `make runtime-key`.
fn runtime_key_sealed(ctx: &Ctx) -> Result<(), Failure> {
    let container = matches!(CredentialsSource::parse(&ctx.cfg.aws.credentials), Ok(CredentialsSource::Container));
    let unsealed = ctx.knobs.fake_api.is_none() || ctx.knobs.fake_api_unseal;
    if !container || !unsealed {
        return Ok(());
    }
    let path = ctx.paths.aws_env();
    match aws_env_state(&path) {
        AwsEnvState::Sealed => Ok(()),
        AwsEnvState::Absent => Err(Failure::NoRuntimeKey { why: format!("{} does not exist", path.display()) }),
        AwsEnvState::NotSealed(why) => Err(Failure::NoRuntimeKey { why: format!("{} {why}", path.display()) }),
    }
}

/// The VM's argv: `claude` (the shim runs its own), then the host's
/// arguments as `argv::sanitise` makes them (`--add-dir` and the debug flags
/// stripped as `[wrapper]` says; no `--session-mirror`: S9 keeps a remote
/// chat's transcript in S3, never on this Mac), within `ARGV_MAX_BYTES`
/// (else exit 9).
fn vm_argv(cfg: &BridgeConfig, args: &[String]) -> Result<Vec<String>, Failure> {
    let opts = SanitiseOpts { strip_add_dir: cfg.wrapper.strip_add_dir, strip_debug: cfg.wrapper.strip_debug, mirror: false };
    let sanitised = argv::sanitise(args, opts).map_err(|e| Failure::Refused { what: format!("the session's arguments: {e}") })?;
    let argv: Vec<String> = std::iter::once("claude".to_string()).chain(sanitised).collect();
    argv_fits(&argv)?;
    Ok(argv)
}

/// The VM's argv within `ARGV_MAX_BYTES` (P0's, and S10's moved one), else exit 9.
fn argv_fits(argv: &[String]) -> Result<(), Failure> {
    let size: usize = argv.iter().map(|a| a.len() + 1).sum();
    if size > ARGV_MAX_BYTES {
        return Err(Failure::Refused { what: format!("the session's arguments are {size} bytes (at most {ARGV_MAX_BYTES})") });
    }
    Ok(())
}

/// The spawn frame P4 sends (the proxy variables included, as the vpc row
/// gets them) fits `CONTROL_FRAME_MAX`, else exit 9: the shim would close
/// the socket on it.
fn spawn_frame_fits(ctx: &Ctx, argv: &[String], ws: &WorkspaceRef, env: &BTreeMap<String, String>) -> Result<(), Failure> {
    let vpc = VmRow { egress: Egress::Vpc.as_str().to_string(), ..VmRow::default() };
    let pairs: Vec<(String, String)> = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let frame = Frame::Spawn {
        spawn_id: SpawnId::new_v7(),
        argv: argv.to_vec(),
        cwd: Some(ws.vm_cwd.clone()),
        env: spawn_env(ctx, &vpc, &pairs),
        secrets: BTreeMap::new(),
        deliver_secret: Deliver::Fd,
        detach_grace_s: Some(u32::MAX),
        credential: None,
    };
    let size = frame.to_json().len();
    if size > CONTROL_FRAME_MAX {
        return Err(Failure::Refused { what: format!("the session's argv and environment make a {size}-byte spawn frame (at most {CONTROL_FRAME_MAX})") });
    }
    Ok(())
}

/// The Mac's config dir from `env` (`CLAUDE_CONFIG_DIR`, else `HOME/.claude`), as `mirror::mac_config_dir`.
fn mac_config_dir(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let set = |k: &str| env(k).filter(|v| !v.is_empty());
    set("CLAUDE_CONFIG_DIR").map(PathBuf::from).or_else(|| set("HOME").map(|h| PathBuf::from(h).join(".claude")))
}

/// P0's `.active` hold, when P0's one try found the workspace held alone (a
/// closing session, around its suspend verdict, within `CLOSING_BOUND`):
/// taken shared at the start of generation 1's pending start, before any
/// Touch ID (the lock order: `.active`, then `unseal.lock`), polled within
/// [`ACTIVE_WAIT`]. Being part of the pending start, the wait ends with it on
/// the host's EOF or a signal (S8 phase 4: P0 runs before the pump reads the
/// host or listens for a stop). Past the wait a warning, and the session
/// goes on without, as P0's own wait did.
async fn hold_active_at_start(plan: &SessionPlan) {
    if plan.active.borrow().is_some() {
        return;
    }
    let path = plan.paths.workspace_active(&plan.ws.slug);
    let until = Instant::now() + ACTIVE_WAIT;
    loop {
        match try_lock_shared(&path) {
            Ok(Some(guard)) => {
                *plan.active.borrow_mut() = Some(guard);
                return;
            }
            Ok(None) if Instant::now() < until => tokio::time::sleep(crate::bridge::vm::lock::POLL).await,
            Ok(None) => {
                crate::bridge::voice::warn(&format!("{} still held exclusively after {} ms: the session goes on without the workspace's .active lock", path.display(), ACTIVE_WAIT.as_millis()));
                return;
            }
            Err(e) => {
                crate::bridge::voice::warn(&format!("the workspace's .active lock: {e}; the session goes on without it"));
                return;
            }
        }
    }
}

// ---- P1 to P4 -----------------------------------------------------------------------------

/// A generation's failure: the step it stopped at, what Cursor is shown,
/// the VM once SELECT_VM chose one.
struct Failed {
    step: StartStep,
    failure: Failure,
    vm: Option<String>,
}

/// `e` at `step` as Cursor sees it (`Failure::from_error`), but a Touch ID
/// that ran out of time is its own kind (exit 5, naming its budget).
fn failed(step: StartStep, e: BridgeError, vm: Option<&str>) -> Failed {
    let failure = match &e {
        BridgeError::Cli(c) if crate::bridge::unseal::is_deadline(c) => Failure::TouchIdTimeout { secs: deadline_secs(c) },
        _ => Failure::from_error(step, e, vm),
    };
    Failed { step, failure, vm: vm.map(str::to_string) }
}

fn failed_cli(step: StartStep, e: CliError, vm: Option<&str>) -> Failed {
    failed(step, BridgeError::Cli(e), vm)
}

/// The seconds an unseal's deadline names (`no Touch ID within N s, …`).
fn deadline_secs(e: &CliError) -> u64 {
    e.to_string().strip_prefix("no Touch ID within ").and_then(|rest| rest.split(' ').next()).and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// The exit code of T0 + 50 s passing at `step`: 5 at the Touch ID, 8 at
/// the spawn (the VM did not answer), 7 at the others.
pub(crate) fn deadline_code(step: StartStep) -> i32 {
    match step {
        StartStep::TouchId => 5,
        StartStep::Spawn => 8,
        _ => 7,
    }
}

/// Where a generation is (the step a deadline names) and its VM.
#[derive(Default)]
struct Progress {
    step: Cell<Option<StartStep>>,
    vm: RefCell<Option<String>>,
    /// P3's two branches, each once done.
    workspace_done: Cell<bool>,
    gate_done: Cell<bool>,
    /// S10: a move's kind once M1 decided it (a `Respawn` may run as a
    /// `Readdress`), and whether it asked its Touch ID (`asked`) or took the
    /// VM's copy (`cached`): what its failure reports.
    kind: Cell<Option<MoveKind>>,
    touchid: Cell<Option<&'static str>>,
}

impl Progress {
    fn at(&self, step: StartStep) {
        self.step.set(Some(step));
    }

    /// The step a deadline names: the step reached, but in P3 the branch
    /// still running (the workspace when both are).
    fn stuck_at(&self) -> StartStep {
        match self.step.get().unwrap_or(StartStep::Precheck) {
            StartStep::Workspace if self.workspace_done.get() && !self.gate_done.get() => StartStep::Gate,
            other => other,
        }
    }
}

/// One child generation's P1–P4 (`gen` 1, or 2 for the resume miss's retry,
/// which restores the transcript first and respawns on the same VM), on the
/// pump's `LocalSet`: the Touch ID, SELECT_VM, the workspace beside the gate
/// and the token, then the spawn handed to its session task with `io`. All of
/// it within [`deadline_of`]: `plan.init_deadline()`, but a retry's start +
/// 60 s once the host's `initialize` was answered. `Err` is the link's first
/// event (`ChildEvent::SpawnFailed`): nothing was spawned; it is audited
/// `session_remote_failed`. Dropping the future cancels it (an unseal's
/// dialog closes with it). S10: a move's failure is the move's
/// (`Failure::Move`, of the kind that ran, the inner failure's exit), audited
/// `session_move_end` `failed`: its session had started, so never
/// `session_remote_failed`.
pub async fn run(plan: Rc<SessionPlan>, gen: u32, why: StartWhy, io: SpawnIo) -> Result<PipelineEnd, SpawnFailure> {
    plan.started.set(plan.started.get().max(gen));
    let begun = Instant::now();
    let deadline = deadline_of(&plan, &why);
    let progress = Progress::default();
    let failed = match tokio::time::timeout_at(deadline, generation(&plan, gen, &why, io, &progress, deadline)).await {
        Ok(Ok(end)) => return Ok(PipelineEnd { started_by: Some(deadline), ..end }),
        Ok(Err(f)) => f,
        Err(_) => {
            let step = progress.stuck_at();
            Failed { step: StartStep::Deadline, failure: Failure::Deadline { code: deadline_code(step), step: step.name() }, vm: progress.vm.borrow().clone() }
        }
    };
    if let StartWhy::Move(m) = &why {
        let kind = progress.kind.get().unwrap_or(m.kind);
        let failure = Failure::Move { kind, from_vm: m.from_vm.clone(), cause: m.cause, inner: Box::new(failed.failure) };
        let row = MoveEndRow { session: m.session_id.as_deref(), gen, kind: Some(kind), outcome: "failed", from_vm: &m.from_vm, to_vm: failed.vm.as_deref(), touchid: progress.touchid.get(), ms: ms(begun), step_code: Some((failed.step.name(), failure.exit_code())), request: request_of(m.trigger.as_ref()), ..MoveEndRow::default() };
        row.audit(&plan.paths);
        if kind == MoveKind::Migrate {
            // S10 §B: the switch failed, its fallback too: no prepared VM is held for it any more.
            plan.end_switch();
        }
        tracing::warn!(gen, step = failed.step.name(), code = failure.exit_code(), kind = kind.word(), "the move's start failed");
        return Err(SpawnFailure::from_failure(failed.step, &failure, failed.vm));
    }
    let mut pairs = vec![("gen", gen.to_string()), ("step", failed.step.name().to_string()), ("code", failed.failure.exit_code().to_string()), ("why", failed.failure.word().to_string())];
    if let Some(vm) = &failed.vm {
        pairs.push(("id", vm.clone()));
    }
    audit_event(&plan.paths, event::SESSION_REMOTE_FAILED, &pairs);
    if let Some(c) = plan.carry.as_ref().filter(|_| matches!(why, StartWhy::First)) {
        // S10 §2.7: a reopen's carry that never started, beside its `session_remote_failed`.
        let (kind, _) = carry_words(c);
        let row = MoveEndRow { session: plan.resume.as_deref(), gen, kind: Some(kind), outcome: "failed", from_vm: &c.from_vm, to_vm: failed.vm.as_deref(), touchid: Some("asked"), ms: ms(plan.t0), step_code: Some((failed.step.name(), failed.failure.exit_code())), ..MoveEndRow::default() };
        row.audit(&plan.paths);
    }
    tracing::warn!(gen, step = failed.step.name(), code = failed.failure.exit_code(), why = failed.failure.word(), "the remote start failed");
    Err(SpawnFailure::from_failure(failed.step, &failed.failure, failed.vm))
}

/// A generation's deadline (plan §3 item 6: the start fits Cursor's window
/// from T0): `plan.init_deadline()`, T0 + 50 s, for generation 1 and for a
/// resume miss's retry while the host's `initialize` is unanswered (the
/// retry's answer is then the host's first); a retry after generation 1
/// answered it has its own [`RETRY_WINDOW`] from now (s8-design-session
/// §3.7).
fn deadline_of(plan: &SessionPlan, why: &StartWhy) -> Instant {
    match why {
        StartWhy::ResumeRetry { init_answered: true, .. } => Instant::now() + RETRY_WINDOW,
        // S10: a move has its own window from its start, but one the host's `initialize` waits on keeps T0 + 50 s.
        StartWhy::Move(m) if m.init_answered => Instant::now() + MOVE_WINDOW,
        StartWhy::First | StartWhy::ResumeRetry { .. } | StartWhy::Move(_) => plan.init_deadline(),
    }
}

async fn generation(plan: &Rc<SessionPlan>, gen: u32, why: &StartWhy, io: SpawnIo, progress: &Progress, deadline: Instant) -> Result<PipelineEnd, Failed> {
    match why {
        StartWhy::First => {
            hold_active_at_start(plan).await;
            first(plan, gen, io, progress).await
        }
        // S10: a move starts from the generation the chat ran on (its VM, P1's backend).
        StartWhy::Move(m) => {
            let current = plan.current.borrow().clone();
            let Some(current) = current else {
                return Err(Failed { step: StartStep::Precheck, failure: Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: "the move has no generation to move from".into() }, vm: None });
            };
            let backend = Rc::clone(&current.backend);
            match &*backend {
                Backend::Sdk(api, ep) => move_gen(plan, gen, Arc::clone(api), Arc::clone(ep), current, m, io, progress, deadline).await,
                Backend::Fake(f) => move_gen(plan, gen, Arc::new(f.clone()), Arc::new(f.clone()), current, m, io, progress, deadline).await,
            }
        }
        StartWhy::ResumeRetry { session_id, .. } => {
            let current = plan.current.borrow().clone();
            let Some(current) = current else {
                return Err(Failed { step: StartStep::Precheck, failure: Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: "the resume's retry has no first generation to respawn on".into() }, vm: None });
            };
            let backend = Rc::clone(&current.backend);
            match &*backend {
                Backend::Sdk(api, ep) => retry(plan, gen, Arc::clone(api), Arc::clone(ep), current, session_id, io, progress).await,
                Backend::Fake(f) => retry(plan, gen, Arc::new(f.clone()), Arc::new(f.clone()), current, session_id, io, progress).await,
            }
        }
    }
}

/// Milliseconds since `t`.
fn ms(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Generation 1: P1 (the Touch ID; beside it a `--resume`'s transcript scan
/// when the session names no VM, then the WIP snapshot), then P2–P4 on the
/// backend it unsealed.
async fn first(plan: &Rc<SessionPlan>, gen: u32, io: SpawnIo, progress: &Progress) -> Result<PipelineEnd, Failed> {
    let ctx = plan.ctx();
    progress.at(StartStep::TouchId);
    let lim = SeedLimits::wrapper(&plan.cfg);
    let unseal = async {
        let t = Instant::now();
        let unsealed = credential::backend_for_session(&plan.store, &ctx, &plan.token, plan.window_from + INIT_DEADLINE).await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?;
        // Answered: what P1 may still wait for is the snapshot (a deadline names the workspace).
        progress.at(StartStep::Workspace);
        Ok::<_, Failed>((unsealed, ms(t)))
    };
    let (paths, cfg, ws) = (plan.paths.clone(), plan.cfg.clone(), plan.ws.clone());
    // A `--resume`'s transcript goes through the seed's tripwires here, before the seed's own scans: a finding starts no
    // VM and closes the dialog. Only a chat whose copy on this Mac P3 will send up inline is scanned, one begun on this
    // Mac or an S8 mirror (`s3::manifest::origin_of`); one S3 holds is never read on this Mac.
    let scan_wanted = |id: &str| p1_scans(crate::bridge::s3::manifest::origin_of(&plan.paths, id));
    let transcript = plan.resume.clone().zip(plan.mac_projects.clone()).filter(|(id, _)| scan_wanted(id)).map(|(id, root)| (id, root, plan.slugs.clone()));
    // S10 §2.7: a reopen carried off a gone VM seeds from that VM's last fetch (its box record), when this Mac holds it.
    let gone = plan.carry.as_ref().filter(|c| c.left_s.is_none()).map(|c| c.from_vm.clone());
    let (((backend, token), touch_ms), prepared) = unseal_beside(plan, unseal, move |cancel| {
        if let Some((id, root, slugs)) = &transcript {
            let slugs: Vec<&str> = slugs.iter().map(String::as_str).collect();
            workspace::transcript::scan_mac_copy(&paths, &cfg, &ws, root, &slugs, id)?;
        }
        match gone.map(|dead| workspace::carry_source(&paths, &ws, &dead)) {
            Some(workspace::CarrySource::Box { record, note }) => {
                if let Some(note) = note {
                    crate::bridge::voice::note(&note);
                }
                workspace::prepare_from_box(&paths, &cfg, &ws, &lim, &record)
            }
            Some(workspace::CarrySource::Mac { note }) => {
                if let Some(note) = note {
                    crate::bridge::voice::note(&note);
                }
                workspace::prepare_cancellable(&paths, &cfg, &ws, &lim, cancel)
            }
            None => workspace::prepare_cancellable(&paths, &cfg, &ws, &lim, cancel),
        }
    })
    .await?;
    let backend = Rc::new(backend);
    let legs = vec![("touchid", touch_ms)];
    match &*Rc::clone(&backend) {
        Backend::Sdk(api, ep) => onwards(plan, gen, &ctx, Arc::clone(api), Arc::clone(ep), backend, token, prepared, legs, io, progress).await,
        Backend::Fake(f) => onwards(plan, gen, &ctx, Arc::new(f.clone()), Arc::new(f.clone()), backend, token, prepared, legs, io, progress).await,
    }
}

/// Whether P1 scans a `--resume`'s copy on this Mac (S9): when P3 will send
/// that copy up inline, a chat begun here (`origin` none) or an S8 mirror
/// (`s8_mirror`), never one S3 holds (`vm`, `mac`), whichever VM the
/// session names.
fn p1_scans(origin: Option<&str>) -> bool {
    matches!(origin, None | Some(crate::bridge::s3::manifest::ORIGIN_S8_MIRROR))
}

/// P1's two halves at once (plan §3 item 2): `unseal`, the Touch ID, and
/// `prepare`, the WIP snapshot, on a blocking thread: neither waits for the
/// other, and the first error drops the unseal (its dialog closes). A
/// blocking thread cannot be dropped, so `prepare` gets a cancel flag, set
/// once P1 is over however it ended (a failure, or the start dropped: a
/// host EOF, a signal): the snapshot's git runs end and it returns at once.
/// The plan keeps its thread's handle ([`SessionPlan::take_closing`]), so
/// the pump waits for that end before the process exits; a snapshot nobody
/// takes any more is dropped on its thread.
async fn unseal_beside<T, S: Send + 'static>(plan: &SessionPlan, unseal: impl std::future::Future<Output = Result<T, Failed>>, prepare: impl FnOnce(Arc<AtomicBool>) -> Result<S, BridgeError> + Send + 'static) -> Result<(T, S), Failed> {
    /// Sets the snapshot's cancel flag when P1 is over (dropped with this future).
    struct Over(Arc<AtomicBool>);
    impl Drop for Over {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let _over = Over(Arc::clone(&cancel));
    let (tx, rx) = tokio::sync::oneshot::channel();
    plan.keep(tokio::task::spawn_blocking(move || {
        let _ = tx.send(prepare(cancel));
    }));
    let snapshot = async {
        match rx.await {
            Ok(prepared) => prepared.map_err(|e| failed(StartStep::Workspace, e, None)),
            Err(_) => Err(failed(StartStep::Workspace, BridgeError::Io(std::io::Error::other("the workspace's snapshot did not finish")), None)),
        }
    };
    tokio::try_join!(unseal, snapshot)
}

/// Generation 1's P2–P4 on `api` and `ep`.
#[allow(clippy::too_many_arguments)]
async fn onwards<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static>(
    plan: &Rc<SessionPlan>,
    gen: u32,
    ctx: &Ctx,
    api: Arc<A>,
    ep: Arc<E>,
    backend: Rc<Backend>,
    token: Option<(crate::bridge::setup_token::SetupToken, String)>,
    prepared: PreparedSeed,
    mut legs: Vec<(&'static str, u64)>,
    io: SpawnIo,
    progress: &Progress,
) -> Result<PipelineEnd, Failed> {
    // P2: SELECT_VM, the plan's Choice inside its own lock hold; S10 (§2.7) beside it, a reopen's carry off a VM near
    // its wall resumes that VM, fetches its work and syncs the chat there (`carry_leave`).
    progress.at(StartStep::SelectVm);
    let t = Instant::now();
    let select = async {
        match run::select_vm_detailed(&*api, &plan.paths, &plan.run, ctx.poll(Poll::RUNNING)).await {
            Ok(selected) => Ok(selected),
            Err(f) => {
                let f = retry_gate_terminate(ctx, &*api, f).await;
                Err(with_parked(&plan.paths, &plan.run, failed(StartStep::SelectVm, f.error, f.started.as_deref())))
            }
        }
    };
    let (selected, ()) = tokio::join!(select, carry_leave(plan, ctx, &api));
    let selected = selected?;
    let how = match (&plan.run.choice, &selected) {
        (Choice::Pin(_), _) => "pinned",
        (_, Selected::Started { .. }) => "started",
        (_, Selected::Reused { resumed: true, .. }) => "resumed",
        (_, Selected::Reused { .. }) => "reused",
    };
    let (row, vm) = (selected.row().clone(), selected.vm().clone());
    *progress.vm.borrow_mut() = Some(vm.id.clone());
    let at = Some(vm.id.as_str());
    let (row, caps) = workspace_caps(ctx, &*api, &*ep, row).await.map_err(|e| failed(StartStep::SelectVm, e, at))?;
    legs.push(("select", ms(t)));
    audit_event(&plan.paths, event::VM_SELECT, &[("id", vm.id.clone()), ("how", how.to_string()), ("choice", plan.run.choice.word().to_string()), ("ms", ms(t).to_string())]);
    // P3: the workspace beside the gate and the token.
    progress.at(StartStep::Workspace);
    let target = target_of(&row, &vm).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let (dp, tokens) = data_plane(ctx, &api, &vm.id, true).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let deadline = plan.init_deadline();
    let progress_log = |p: workspace::SeedProgress| tracing::info!("seed: {p:?}");
    let ectx = EnsureCtx { api: &*api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: Some(deadline), progress: &progress_log };
    let workspace_branch = async {
        let t = Instant::now();
        let (outcome, source) = match plan.carry.as_ref() {
            // S10 §2.7: off a VM near its wall, the carry seed of the record P2's fetch just wrote there.
            Some(c) if c.left_s.is_some() => carry_seed(&ectx, &c.from_vm).await.map_err(|e| failed(StartStep::Workspace, e, at))?,
            carry => {
                let (source, want) = (prepared.source(), if carry.is_some() { SeedWant::Carry } else { SeedWant::Auto });
                let outcome = workspace::ensure_workspace(&ectx, Some(prepared), want).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
                let source = if matches!(outcome, workspace::EnsureOutcome::Kept { .. }) { "kept" } else { source };
                (outcome, source)
            }
        };
        let transcript = match &plan.resume {
            Some(_) if plan.skip_transcript => {
                tracing::info!("{TRANSCRIPT_KNOB}=skip: no transcript is restored before the resume");
                None
            }
            Some(id) => Some(restore_transcript(plan, &ectx, id).await.map_err(|e| pull_cap(&plan.run, failed(StartStep::Workspace, e, at)))?),
            None => None,
        };
        progress.workspace_done.set(true);
        Ok::<_, Failed>((outcome, source, transcript, ms(t)))
    };
    let credential_branch = async {
        let t = Instant::now();
        let supply = CredentialSupply { store: &plan.store, token };
        let prepared = credential::prepare_session(ctx, &*api, &*ep, &row, &vm, &plan.token, supply, plan.window_from + INIT_DEADLINE).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
        progress.gate_done.set(true);
        Ok::<_, Failed>((prepared, ms(t)))
    };
    let ((outcome, source, transcript, workspace_ms), (mut prepared, gate_ms)) = tokio::try_join!(workspace_branch, credential_branch)?;
    legs.push(("workspace", workspace_ms));
    // P3b: a deadline from here names the gate.
    progress.at(StartStep::Gate);
    let t = Instant::now();
    credential::regate_if_stale(ctx, &*api, &row, &vm, &mut prepared).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    legs.push(("gate", gate_ms + ms(t)));
    plan.credential.set(Some(prepared.source));
    // S10 (D5, M6): what this chat or a dead wrapper left running on the VM is ended before the spawn.
    reap(plan, ctx, &*api, &*ep, &row, &vm, plan.resume.as_deref()).await?;
    let seed = outcome.word();
    let seeded_head = seeded_head(&outcome);
    let current = Current { backend, row: row.clone(), vm: vm.clone(), how, seed, seeded_head: seeded_head.clone() };
    // The code-out trigger's code-port tokens are the session's 5 minutes, never the seed's 15 (plan §10).
    let code_tokens = Arc::new(MintingTokens::new(Arc::clone(&api), &ctx.paths, &vm.id, false));
    let why = plan.carry.as_ref().map_or_else(|| "first".to_string(), carry_why);
    let spawning = Spawning { argv: plan.argv.clone(), session: plan.resume.clone(), why };
    let end = spawn(plan, gen, ctx, Arc::clone(&api), Arc::clone(&ep), dp, code_tokens, target, row, vm, prepared.delivery, io, progress, spawning).await?;
    *plan.current.borrow_mut() = Some(current);
    let transcript = transcript.map(|o| o.word());
    if let Some(c) = &plan.carry {
        // S10 §2.7: the carry's end, beside its `session_remote_start`.
        let (kind, _) = carry_words(c);
        let row = MoveEndRow { session: plan.resume.as_deref(), gen, kind: Some(kind), outcome: "done", from_vm: &c.from_vm, to_vm: Some(&end.vm), how: Some(how), seed: Some(source), transcript, cut: Some(Cut::None.word()), touchid: Some("asked"), ms: ms(plan.t0), ..MoveEndRow::default() };
        row.audit(&plan.paths);
    }
    // Once the spawn runs: generation 1's gc reconcile (L12), and the end of a VM a reopen carried the chat off near its wall.
    let leaving = plan.carry.as_ref().filter(|c| c.left_s.is_some()).map(|c| c.from_vm.clone());
    let after = {
        let (plan, ctx, to) = (Rc::clone(plan), plan.ctx(), end.vm.clone());
        async move {
            let gc = gc_reconcile(Arc::clone(&api), ctx.paths.clone(), plan.run.image_arn.clone());
            let retire = async {
                if let Some(from) = leaving {
                    retire_old_vm(&ctx, &*api, &*ep, &from, &to, plan.resume.as_deref()).await;
                }
            };
            tokio::join!(gc, retire);
        }
    };
    Ok(PipelineEnd {
        vm: end.vm,
        vm_how: how,
        legs,
        seed,
        transcript,
        seeded_head,
        credential: plan.credential.get(),
        delivery: Some(end.delivery),
        spawn_id: end.spawn_id,
        started_by: None,
        trigger: end.trigger,
        session: end.session,
        carried: plan.carry.clone(),
        moved: None,
        after_started: Some(AfterStarted(Box::pin(after))),
    })
}

/// The retry of a resume miss (plan §2): the latest generation's VM
/// (generation 1's), running again if a closing suspend raced it; the
/// transcript restored; the gate again with no prompt; the token from the
/// VM's cache (no value in hand: a VM that lost it is exit 5, never a second
/// Touch ID); the spawn with P0's argv.
#[allow(clippy::too_many_arguments)]
async fn retry<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static>(plan: &Rc<SessionPlan>, gen: u32, api: Arc<A>, ep: Arc<E>, current: Current, session_id: &str, io: SpawnIo, progress: &Progress) -> Result<PipelineEnd, Failed> {
    let ctx = plan.ctx();
    let mut legs = Vec::new();
    progress.at(StartStep::SelectVm);
    *progress.vm.borrow_mut() = Some(current.vm.id.clone());
    let at = Some(current.vm.id.as_str());
    let t = Instant::now();
    let vm = running(&*api, &current.vm.id, ctx.poll(Poll::RUNNING)).await.map_err(|e| failed(StartStep::SelectVm, e, at))?;
    legs.push(("select", ms(t)));
    progress.at(StartStep::Workspace);
    let t = Instant::now();
    let target = target_of(&current.row, &vm).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let (dp, tokens) = data_plane(&ctx, &api, &vm.id, false).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let caps = current.row.caps.clone().unwrap_or_default();
    let progress_log = |p: workspace::SeedProgress| tracing::info!("seed: {p:?}");
    let ectx = EnsureCtx { api: &*api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: None, progress: &progress_log };
    let transcript = restore_transcript(plan, &ectx, session_id).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
    legs.push(("workspace", ms(t)));
    progress.workspace_done.set(true);
    progress.at(StartStep::Gate);
    let t = Instant::now();
    let pass = credential::gate(&ctx.cfg, &ctx.paths, &*api, &current.row, &vm).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    let parts = DeliveryParts { name: crate::bridge::setup_token::TOKEN_VAR.to_string(), tag: plan.token.tag.clone(), deliver: plan.token.deliver, secret: None, one_shot: false };
    let delivery = Delivery::new(&pass, &vm.id, crate::wire::time::unix_now(), parts).map_err(|e| failed(StartStep::Gate, e, at))?;
    // This generation's token is the VM's own copy: the census says so, not generation 1's source.
    plan.credential.set(Some(credential::CACHED));
    legs.push(("gate", ms(t)));
    progress.gate_done.set(true);
    let spawning = Spawning { argv: plan.argv.clone(), session: plan.resume.clone(), why: "retry".to_string() };
    let end = spawn(plan, gen, &ctx, api, ep, dp, tokens, target, current.row.clone(), vm.clone(), delivery, io, progress, spawning).await?;
    let (how, seed, seeded_head) = (current.how, current.seed, current.seeded_head.clone());
    *plan.current.borrow_mut() = Some(Current { vm, ..current });
    Ok(PipelineEnd { vm: end.vm, vm_how: how, legs, seed, transcript: Some(transcript.word()), seeded_head, credential: plan.credential.get(), delivery: Some(end.delivery), spawn_id: end.spawn_id, started_by: None, trigger: end.trigger, session: end.session, carried: None, moved: None, after_started: None })
}

/// `id` RUNNING: as GetMicrovm finds it, waited for while PENDING, resumed
/// while SUSPENDING or SUSPENDED (a closing session's suspend may have
/// raced the retry); gone or going is exit 8.
async fn running<A: MicrovmApi>(api: &A, id: &str, poll: Poll) -> Result<VmInfo, BridgeError> {
    running_resumed(api, id, poll).await.map(|(vm, _)| vm)
}

/// [`running`], and whether it had to resume the VM (S10: a move's
/// respawn says `resumed`, else `reused`).
pub(crate) async fn running_resumed<A: MicrovmApi>(api: &A, id: &str, poll: Poll) -> Result<(VmInfo, bool), BridgeError> {
    let vm = api.get(id).await?;
    match vm.state {
        VmState::Running => Ok((vm, false)),
        VmState::Pending => run::wait_for_state(api, id, &VmState::Running, poll).await.map(|vm| (vm, false)),
        VmState::Suspending | VmState::Suspended => {
            if vm.state == VmState::Suspending {
                run::wait_for_state(api, id, &VmState::Suspended, poll).await?;
            }
            match api.resume(id).await {
                Ok(()) | Err(BridgeError::Conflict(_)) => {}
                Err(e) => return Err(e),
            }
            // S10 F9: a resumed VM is polled on the resumed ramp (200, 300, 500 ms first).
            run::wait_for_state(api, id, &VmState::Running, poll.resumed()).await.map(|vm| (vm, true))
        }
        _ => Err(BridgeError::Terminated(format!("{id} is {}", vm.state.as_str()))),
    }
}

/// The VM's caps for the workspace routes and S9's transcript store: its
/// row's, or, never read (`vm run` reads no `/health`), one `/health` that
/// records them. Without `workspace_v1` nothing is sent: exit 7 naming
/// `make deploy` (L5). Nor without `transcript_s3_v1` (S9): SELECT_VM skips
/// a reuse candidate and refuses a pin whose recorded caps lack it, and here
/// it refuses a VM it started, or a row whose caps were never read (an
/// image that predates the store but holds an egress pass: a publish that
/// failed after the S9 deploy, a rollback). A chat there would run with no
/// sync and no view, its transcript kept on a VM no session reuses.
pub(crate) async fn workspace_caps<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: VmRow) -> Result<(VmRow, Vec<String>), BridgeError> {
    let row = if vm_capability(&row) == Capability::Unknown {
        crate::bridge::vm::health::read_health(api, ep, &ctx.paths, &row.id, ctx.backoff()).await?;
        vm_registry::read_row(&ctx.paths, &row.id)?.unwrap_or(row)
    } else {
        row
    };
    if vm_capability(&row) != Capability::Yes {
        return Err(BridgeError::NoCapability { cap: CAP_WORKSPACE_V1, message: format!("{} (image version {}) does not serve the workspace routes", row.id, row.image_version) });
    }
    if workspace::vm_capability_of(&row, crate::wire::frame::CAP_TRANSCRIPT_S3_V1) != Capability::Yes {
        return Err(BridgeError::NoCapability { cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1, message: format!("{} (image version {}) does not serve the transcript store", row.id, row.image_version) });
    }
    let caps = row.caps.clone().unwrap_or_default();
    Ok((row, caps))
}

/// The session's target on `vm` (the endpoint GetMicrovm reported wins over the row's).
pub(crate) fn target_of(row: &VmRow, vm: &VmInfo) -> Result<AgentTarget, BridgeError> {
    let mut row = row.clone();
    if !vm.endpoint.is_empty() {
        row.endpoint = Some(vm.endpoint.clone());
    }
    AgentTarget::from_row(&row)
}

/// A `--resume`'s transcript into the VM (S9, plan §5): restored from S3
/// (`workspace::transcript::restore`: kept on the VM when it holds the
/// committed prefix, else pulled, at most `wire::s3::INLINE_MAX` under
/// generation 1's deadline and any size under the retry's none; a chat
/// begun on this Mac sent up inline first) into the projects dir the VM's
/// claude reads (the slug of the workspace's VM path: a session never
/// forwards the CLI's override,
/// `remote::env::PROJECT_DIR_NAME`), with P0's `TranscriptSync`
/// ([`SessionPlan::transcript_sync`], the view under its projects
/// directory). Every `--resume` has one: P0 refused, before any Touch ID, a
/// session that could not build it (exit 1).
async fn restore_transcript<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(plan: &SessionPlan, ectx: &EnsureCtx<'_, A, D, T>, session_id: &str) -> Result<workspace::TranscriptOutcome, BridgeError> {
    let slugs: Vec<&str> = plan.slugs.iter().map(String::as_str).collect();
    let Some(sync) = &plan.transcript_sync else {
        return Err(BridgeError::Config("internal: no transcript sync for a --resume (P0 builds one for every resume)".into()));
    };
    workspace::transcript::restore(ectx, sync, Some(sync.mac_projects.as_path()), &slugs, session_id, &crate::wire::view::build_view).await
}

/// The head the VM's checkout started from, as the workspace step found it.
fn seeded_head(outcome: &workspace::EnsureOutcome) -> Option<String> {
    use workspace::EnsureOutcome as O;
    match outcome {
        O::Seeded { head, .. } | O::Updated { head, .. } | O::UpToDate { head } => Some(head.clone()),
        O::Kept { vm_head, .. } => Some(vm_head.clone()),
    }
}

/// What [`spawn`] made.
struct Spawned {
    vm: String,
    spawn_id: SpawnId,
    trigger: CodeoutTrigger,
    session: JoinHandle<Result<SpawnOutcome, BridgeError>>,
    /// What becomes of the delivery's token in the session.
    delivery: DeliveryReport,
}

/// What a generation spawns (S10: its argv is its own): the CLI's argv,
/// the session id its code-out trigger is named at once (a `--resume`'s,
/// a move's), and the `vms[]` why `session_remote_start` records.
struct Spawning {
    argv: Vec<String>,
    session: Option<String>,
    why: String,
}

/// P4: the spawn (its id named now, the workspace's VM path as cwd, the
/// proxy variables then the session's, the session grace, `hello.idle_s`
/// 90) handed to its session task on the pump's `LocalSet`, the code-out
/// trigger beside it (its watch to the session task, for the closing
/// suspend); audited `session_remote_start` (S10: with its `why`).
#[allow(clippy::too_many_arguments)]
async fn spawn<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static, D: DataPlane + 'static, T: TokenSource + 'static>(
    plan: &Rc<SessionPlan>,
    gen: u32,
    ctx: &Ctx,
    api: Arc<A>,
    ep: Arc<E>,
    dp: Arc<D>,
    tokens: Arc<T>,
    target: AgentTarget,
    row: VmRow,
    vm: VmInfo,
    delivery: Delivery,
    io: SpawnIo,
    progress: &Progress,
    spawning: Spawning,
) -> Result<Spawned, Failed> {
    progress.at(StartStep::Spawn);
    let at = Some(vm.id.as_str());
    // What the session task builds again: refused here, before anything is spawned.
    agent_env(ctx, &*api, &*ep, &row, Some(&vm)).map_err(|e| failed_cli(StartStep::Spawn, e, at))?;
    let spawn_id = SpawnId::new_v7();
    let Spawning { argv, session: session_id, why } = spawning;
    let spec = spawn_spec(plan, ctx, &row, &spawn_id, argv);
    let transcript = session_sync(plan);
    let trigger = CodeoutTrigger::spawn(CodeoutCtx { api: Arc::clone(&api), dp, tokens, paths: plan.paths.clone(), cfg: Arc::new(plan.cfg.clone()), target, ws: plan.ws.clone(), capture_settings: plan.capture_settings, transcript });
    if let Some(id) = &session_id {
        // A resumed or moved session's id is known before its init: the settings' start capture runs beside the spawn (T8.7).
        trigger.set_session(id);
    }
    let id = vm.id.clone();
    let report = delivery.report();
    let session = tokio::task::spawn_local(session(Rc::clone(plan), gen, plan.ctx(), api, ep, row, vm, spec, io, delivery, trigger.watch()));
    {
        // S10: the VM may now hold this claude's transcript (a fresh chat's move avoids it).
        let mut spawned_on = plan.spawned_on.borrow_mut();
        if !spawned_on.contains(&id) {
            spawned_on.push(id.clone());
        }
    }
    audit_event(&plan.paths, event::SESSION_REMOTE_START, &[("id", id.clone()), ("spawn", spawn_id.to_string()), ("gen", gen.to_string()), ("why", why)]);
    tracing::info!(gen, vm = %id, spawn = %spawn_id, "the remote spawn went to its session");
    Ok(Spawned { vm: id, spawn_id, trigger, session, delivery: report })
}

/// What the code-out trigger syncs the session's transcript with (S9):
/// P0's `TranscriptSync` ([`SessionPlan::transcript_sync`]), never for
/// `--no-session-persistence`, which keeps no transcript. A session that
/// keeps one always has it: P0 refused it otherwise, since that sync is all
/// that takes the chat's transcript to S3 and its view to the picker.
fn session_sync(plan: &SessionPlan) -> Option<crate::bridge::s3::TranscriptSync> {
    plan.transcript_sync.clone().filter(|_| plan.capture_settings)
}

// ---- S10: a move's generation (plans/s10-contracts.md §2.7, §2.9) ----------------------------

/// S10 (§2.5): a select refused at `[vm].max_concurrent` names the VMs to
/// free ([`parked_vms`]); any other failure as it is.
fn with_parked(paths: &Paths, run: &RunPlan, mut f: Failed) -> Failed {
    if let Failure::MaxConcurrent { parked, .. } = &mut f.failure {
        *parked = parked_vms(paths, &run.image_arn);
    }
    f
}

/// The suspended VMs of `image_arn` that no open chat holds: rows recorded
/// suspended whose workspace's `.active` nobody holds (a closed chat's, a
/// parked one's whose wrapper is gone), ids only, in the rows' order. The
/// lock is taken and let go at once; a row of no workspace is never named.
fn parked_vms(paths: &Paths, image_arn: &str) -> Vec<String> {
    let Ok(rows) = vm_registry::list_rows(paths) else { return Vec::new() };
    let free = |slug: &str| matches!(try_lock_exclusive(&paths.workspace_active(slug)), Ok(Some(_)));
    rows.into_iter().filter(|r| r.status == RowStatus::Suspended && r.image_arn == image_arn && r.slug.as_deref().is_some_and(free)).map(|r| r.id).collect()
}

/// A duration of the move's budgets as the lab's backoff knob scales a poll's
/// (`AI_ENV_BRIDGE_LAB_BACKOFF_MS`: a second is that many ms).
fn scaled(ctx: &Ctx, d: Duration) -> Duration {
    Poll { step: d, budget: d, ramp: [Duration::ZERO; 3] }.scaled(ctx.knobs.backoff_ms).step
}

/// What M1 chose for a move: the kind that runs (a `Respawn` whose VM is not
/// running, whose gapped spawn did not stop, or of a fresh chat, runs as a
/// `Readdress`), the VM and its row (its caps read), how it was taken
/// (`started`, `reused`, `resumed`), and the token when M1 asked its Touch ID
/// (`touchid` `asked`; `cached`: the VM's cache holds the seal).
struct MoveVm {
    kind: MoveKind,
    row: VmRow,
    vm: VmInfo,
    how: &'static str,
    token: Option<(SetupToken, String)>,
    touchid: &'static str,
}

/// A move's generation (S10 §2.7), beside `retry`: M1 ([`move_vm`]: the
/// Touch ID, the old VM and the new one, at once); M2 (the carry seed
/// ([`carry_seed`]), the restore then the cut ([`view_cut`]), the gate with
/// the token's delivery (`credential::move_delivery`, which never unseals),
/// at once; then `regate_if_stale`); M3 (the spawn with [`move_argv`], its
/// code-out trigger named the session; the token dropped once the spawn
/// runs). A `Fresh` cut restores nothing and reads no view, decided before
/// M2 ([`cut_before`]); it drops the transcript's chain of tails past the
/// committed length once the old VM is TERMINATED (C2's R1 splice,
/// [`drop_fresh_chain`]). One move, at most one RunMicrovm (SELECT_VM's
/// client token covers its ambiguous retry). `until`: the move's deadline
/// (its `MOVE_WINDOW`, or T0 + 50 s while the host's `initialize` is
/// unanswered). M3 runs the reaper first ([`reap`]). A migration's switch
/// is [`switch_gen`].
#[allow(clippy::too_many_arguments)]
async fn move_gen<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static>(
    plan: &Rc<SessionPlan>,
    gen: u32,
    api: Arc<A>,
    ep: Arc<E>,
    current: Current,
    why: &MoveWhy,
    io: SpawnIo,
    progress: &Progress,
    until: Instant,
) -> Result<PipelineEnd, Failed> {
    if why.kind == MoveKind::Migrate {
        return switch_gen(plan, gen, api, ep, current, why, io, progress, until).await;
    }
    let ctx = plan.ctx();
    let t = Instant::now();
    // The credential's budgets end by the move's deadline, on the clock the unseal measures it with.
    let until_std = until.into_std();
    let unseal = || credential::unseal_for_move(&plan.store, &ctx, &plan.token, until_std);
    let MoveVm { kind, row, vm, how, token, touchid } = move_vm(plan, &ctx, &*api, &*ep, &current, why, gen, progress, unseal).await?;
    let mut legs = vec![("select", ms(t))];
    let at = Some(vm.id.as_str());
    // M2: the carry seed, the restore then the cut, the gate.
    progress.at(StartStep::Workspace);
    let t = Instant::now();
    let target = target_of(&row, &vm).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let (dp, tokens) = data_plane(&ctx, &api, &vm.id, kind == MoveKind::Readdress).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let caps = row.caps.clone().unwrap_or_default();
    let progress_log = |p: workspace::SeedProgress| tracing::info!("seed: {p:?}");
    // The seed within the move's window and the wrapper's inline cap; the restore with no deadline (no inline cap).
    let seeding = EnsureCtx { api: &*api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: Some(until), progress: &progress_log };
    let restoring = EnsureCtx { api: &*api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: None, progress: &progress_log };
    // With no session id there is nothing to restore and the argv is P0's: no cut.
    let early = if why.session_id.is_none() { Some(Cut::None) } else { cut_before(why) };
    let seed_branch = async {
        if kind == MoveKind::Respawn {
            // The same VM keeps its checkout (the dead CLI's own work in it): nothing is seeded.
            return Ok::<_, Failed>((current.seed, current.seeded_head.clone(), "kept"));
        }
        let (outcome, source) = carry_seed(&seeding, &current.vm.id).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
        Ok((outcome.word(), seeded_head(&outcome), source))
    };
    let transcript_branch = async {
        if let Some(sid) = why.session_id.as_deref().filter(|_| early == Some(Cut::Fresh)) {
            // M1 waited for the old VM's TERMINATED (its `/terminate` tail landed): the restarted file's chain starts anew.
            drop_fresh_chain(plan, &*api, &*dp, &*tokens, &target, sid, until).await;
        }
        let sid = why.session_id.as_deref().filter(|_| early != Some(Cut::Fresh));
        let Some(sid) = sid else { return Ok::<_, Failed>((None, early.clone().unwrap_or(Cut::None))) };
        let restored = restore_transcript(plan, &restoring, sid).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
        let cut = match early.clone() {
            Some(cut) => cut,
            None => view_cut(plan, &restoring, sid, why, until).await,
        };
        Ok((Some(restored), cut))
    };
    let workspace_branch = async {
        let both = tokio::try_join!(seed_branch, transcript_branch)?;
        progress.workspace_done.set(true);
        Ok::<_, Failed>(both)
    };
    let credential_branch = async {
        let prepared = credential::move_delivery(&ctx, &*api, &*ep, &row, &vm, &plan.token, token, until_std).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
        progress.gate_done.set(true);
        Ok::<_, Failed>(prepared)
    };
    let (((seed, seeded_head, source), (transcript, cut)), mut prepared) = tokio::try_join!(workspace_branch, credential_branch)?;
    legs.push(("workspace", ms(t)));
    progress.at(StartStep::Gate);
    let t = Instant::now();
    credential::regate_if_stale(&ctx, &*api, &row, &vm, &mut prepared).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    legs.push(("gate", ms(t)));
    plan.credential.set(Some(prepared.source));
    // M3: the reaper (D5), then the spawn with the moved argv, within P0's caps.
    reap(plan, &ctx, &*api, &*ep, &row, &vm, why.session_id.as_deref()).await?;
    let argv = move_argv(&plan.argv, why.session_id.as_deref(), &cut);
    argv_fits(&argv).and_then(|()| spawn_frame_fits(&ctx, &argv, &plan.ws, &plan.env)).map_err(|failure| Failed { step: StartStep::Spawn, failure, vm: at.map(str::to_string) })?;
    tracing::info!(gen, kind = kind.word(), vm = %vm.id, cut = cut.word(), touchid, seed = source, "the move spawns");
    let code_tokens = Arc::new(MintingTokens::new(Arc::clone(&api), &ctx.paths, &vm.id, false));
    let spawning = Spawning { argv, session: why.session_id.clone(), why: MoveWhy { kind, ..why.clone() }.vms_why() };
    let end = spawn(plan, gen, &ctx, api, ep, dp, code_tokens, target, row.clone(), vm.clone(), prepared.delivery, io, progress, spawning).await?;
    *plan.current.borrow_mut() = Some(Current { backend: current.backend, row, vm, how, seed, seeded_head: seeded_head.clone() });
    let moved = MoveDone { kind, cut: cut.word(), touchid, seed: source, stayed: false };
    Ok(PipelineEnd {
        vm: end.vm,
        vm_how: how,
        legs,
        seed,
        transcript: transcript.map(|o| o.word()),
        seeded_head,
        credential: plan.credential.get(),
        delivery: Some(end.delivery),
        spawn_id: end.spawn_id,
        started_by: None,
        trigger: end.trigger,
        session: end.session,
        carried: None,
        moved: Some(moved),
        after_started: None,
    })
}

/// M1 of a move (S10 §2.7, §2.8): the VM it runs on, and its Touch ID.
///
/// A `Respawn` takes the same VM, running again (resumed when a suspend
/// left it so: `Poll::RESUMED`); for a `Gap`, once `agent::stop_spawn` ended
/// the gapped spawn (two claudes never share the VM's transcript); the
/// token from the VM's cache when it holds the seal (`cached`), else one
/// Touch ID (`unseal`). A VM that is not running, a gapped spawn that did not
/// stop (`false` or an error), or a fresh chat's respawn (its VM holds the
/// dead CLI's own transcript, which `--session-id` refuses) moves as a
/// `Readdress`; the chat then leaves the VM, so a pending migration's phase
/// A is given up first ([`SessionPlan::abandon_phase_a`]: its dialog closed
/// before the move's own opens).
///
/// A `Readdress` (never for a pinned session: its VM or nothing) runs at once
/// the Touch ID (`unseal`: `credential::unseal_for_move`, never waiting for
/// the target VM to be known), the old VM's end by its cause (gone: its
/// TERMINATED waited for, at most `MOVE_OLD_VM_WAIT`, so `/terminate`'s tail
/// lands before the restore; a `Gap` that never ran as a respawn (a fresh
/// chat's): its gapped spawn stopped on the old VM when that VM runs
/// ([`stop_gapped`]: logged when it does not stop), so its claude never runs
/// the turn beside the new one; unreachable: when another live wrapper's
/// chat runs on the old VM, this chat's spawn stopped there and the VM kept
/// for it (no spawn known: kept too); else, or when the stop fails, a
/// best-effort `sync_before_terminate` within `MOVE_SYNC_BUDGET`,
/// `request_terminate` by `readdress`, then the same wait; the sync runs
/// for a kept VM too) and SELECT_VM (`Choice::Workspace`,
/// `RunPlan.avoid` the old VM, and for a fresh chat's `--session-id` every VM
/// this session spawned on, which may hold its `<sid>.jsonl`; for an
/// unreachable one, once its terminate answered, so it no longer counts
/// against `[vm].max_concurrent`), then the VM's caps. The first error ends
/// the others (a dismissed dialog, a refused select); audited `vm_select`
/// with the generation and the VMs avoided (comma-separated).
#[allow(clippy::too_many_arguments)]
async fn move_vm<A, E, U, Uf>(plan: &SessionPlan, ctx: &Ctx, api: &A, ep: &E, current: &Current, why: &MoveWhy, gen: u32, progress: &Progress, unseal: U) -> Result<MoveVm, Failed>
where
    A: MicrovmApi + crate::bridge::s3::S3Sign,
    E: EndpointClient,
    U: FnOnce() -> Uf,
    Uf: std::future::Future<Output = crate::errors::Result<(SetupToken, String)>>,
{
    let old = current.vm.id.clone();
    let mut kind = why.kind;
    // Whether the old VM is gone or going: its TERMINATED is waited for, so its `/terminate` tail lands.
    let mut gone = why.cause == Some(LossCause::VmGone);
    if kind == MoveKind::Respawn && cut_before(why) == Some(Cut::Fresh) {
        tracing::info!(vm = %old, "a fresh chat's respawn moves as a re-address: its VM holds the dead CLI's own transcript");
        kind = MoveKind::Readdress;
        // S10 §B: the chat leaves its VM: a pending migration ends now, its dialog before this move's own.
        plan.abandon_phase_a();
    }
    // A `Gap` that never runs as a respawn (a fresh chat's re-address): its spawn is stopped on the old VM below, so its
    // claude never runs the turn beside the new VM's. One whose stop failed in the respawn branch is not tried again.
    let stop_old = if kind == MoveKind::Readdress && why.cause == Some(LossCause::Gap) { why.from_spawn.clone() } else { None };
    let mut unseal = Some(unseal);
    if kind == MoveKind::Respawn {
        progress.kind.set(Some(kind));
        progress.at(StartStep::SelectVm);
        *progress.vm.borrow_mut() = Some(old.clone());
        let t = Instant::now();
        match running_resumed(api, &old, ctx.poll(Poll::RESUMED)).await {
            Ok((vm, resumed)) => {
                let stopped = match (why.cause, &why.from_spawn) {
                    (Some(LossCause::Gap), Some(spawn)) => stop_gapped(ctx, api, ep, &current.row, &vm, spawn).await,
                    _ => true,
                };
                if stopped {
                    let how = if resumed { "resumed" } else { "reused" };
                    audit_event(&plan.paths, event::VM_SELECT, &[("id", vm.id.clone()), ("how", how.to_string()), ("choice", "respawn".to_string()), ("ms", ms(t).to_string()), ("gen", gen.to_string())]);
                    let (token, touchid) = if credential::cached_on_vm(&ctx.paths, api, ep, &current.row, &vm, &plan.token.tag).await {
                        (None, credential::CACHED)
                    } else {
                        progress.at(StartStep::TouchId);
                        progress.touchid.set(Some("asked"));
                        let unseal = unseal.take().ok_or_else(|| failed(StartStep::TouchId, BridgeError::Config("internal: the move's Touch ID was asked twice".into()), None))?;
                        (Some(unseal().await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?), "asked")
                    };
                    progress.touchid.set(Some(touchid));
                    let row = vm_registry::read_row(&ctx.paths, &old).ok().flatten().unwrap_or_else(|| current.row.clone());
                    return Ok(MoveVm { kind, row, vm, how, token, touchid });
                }
                tracing::info!(vm = %old, "the gapped spawn did not stop: the respawn moves as a re-address");
            }
            Err(e) => {
                tracing::info!(vm = %old, "the VM is not running ({e}): the respawn moves as a re-address");
                gone = true;
            }
        }
        kind = MoveKind::Readdress;
        // S10 §B: the chat leaves its VM: a pending migration ends now, its dialog before this move's own.
        plan.abandon_phase_a();
    }
    progress.kind.set(Some(kind));
    if let Choice::Pin(id) = &plan.run.choice {
        // AI_ENV_BRIDGE_VM: that VM or nothing, never a new one.
        return Err(Failed { step: StartStep::SelectVm, failure: Failure::PinGone { vm: id.clone() }, vm: None });
    }
    let unreachable = why.cause == Some(LossCause::Unreachable);
    progress.at(StartStep::TouchId);
    progress.touchid.set(Some("asked"));
    let selected = Cell::new(false);
    let (asked_tx, asked_rx) = tokio::sync::oneshot::channel::<()>();
    let unseal = unseal.take().ok_or_else(|| failed(StartStep::TouchId, BridgeError::Config("internal: the move's Touch ID was asked twice".into()), None))?;
    let touch = async {
        let token = unseal().await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?;
        if !selected.get() {
            progress.at(StartStep::SelectVm);
        }
        Ok::<_, Failed>(token)
    };
    let old_vm = async {
        if unreachable {
            // Another live wrapper's chat on the old VM keeps it, once this chat's spawn there stopped (none known: kept
            // too); a stop that fails ends the VM as before, so two claudes never run one chat's turn.
            let kept = others_live_on(ctx, &old)
                && match &why.from_spawn {
                    None => true,
                    Some(spawn) => match api.get(&old).await {
                        Ok(vm) if vm.state == VmState::Running => stop_gapped(ctx, api, ep, &current.row, &vm, spawn).await,
                        _ => false,
                    },
                };
            // A VM kept is not terminated: SELECT_VM need not wait for it.
            let asked_tx = if kept {
                let _ = asked_tx.send(());
                None
            } else {
                Some(asked_tx)
            };
            // Best effort: what the endpoint never let the Mac sync, then the VM's end; SELECT_VM waits for its answer.
            let synced = tokio::time::timeout(scaled(ctx, MOVE_SYNC_BUDGET), crate::bridge::s3::commands::sync_before_terminate(ctx, api, &old)).await;
            match synced {
                Ok(warnings) => warnings.iter().for_each(|w| tracing::info!(vm = %old, "the move's sync of the old VM: {w}")),
                Err(_) => tracing::info!(vm = %old, "the move's sync of the old VM did not end within its budget"),
            }
            match asked_tx {
                None => tracing::info!(vm = %old, "the old VM keeps running: other chats live there (its wall ends it)"),
                Some(asked_tx) => {
                    match run::request_terminate(api, &ctx.paths, &old, "readdress").await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::warn!(vm = %old, "the old VM is terminating, its row not updated: {e}"),
                        Err(e) => tracing::warn!(vm = %old, "the old VM's terminate was not accepted: {e}"),
                    }
                    let _ = asked_tx.send(());
                    wait_terminated(ctx, api, &old).await;
                }
            }
        } else {
            drop(asked_tx);
            if let Some(spawn) = &stop_old {
                match api.get(&old).await {
                    Ok(vm) if vm.state == VmState::Running => {
                        if !stop_gapped(ctx, api, ep, &current.row, &vm, spawn).await {
                            tracing::warn!(vm = %old, spawn = %spawn, "the gapped spawn did not stop: it runs until its detach grace");
                        }
                    }
                    Ok(vm) => tracing::info!(vm = %old, state = vm.state.as_str(), "the gapped spawn's VM is not running: nothing stopped"),
                    Err(e) => tracing::info!(vm = %old, "the gapped spawn's VM: {e}"),
                }
            }
            if gone {
                wait_terminated(ctx, api, &old).await;
            }
        }
        Ok::<_, Failed>(())
    };
    // A fresh chat's `--session-id` needs a VM without its `<sid>.jsonl`: none this session ran a claude on.
    let avoid = if cut_before(why) == Some(Cut::Fresh) {
        let mut all = plan.spawned_on.borrow().clone();
        if !all.contains(&old) {
            all.push(old.clone());
        }
        all
    } else {
        vec![old.clone()]
    };
    let new_vm = async {
        if unreachable {
            let _ = asked_rx.await;
        }
        let t = Instant::now();
        let mut run = plan.run.clone();
        run.choice = Choice::Workspace;
        run.avoid.clone_from(&avoid);
        let selected_vm = match run::select_vm_detailed(api, &plan.paths, &run, ctx.poll(Poll::RUNNING)).await {
            Ok(s) => s,
            Err(f) => {
                let f = retry_gate_terminate(ctx, api, f).await;
                return Err(with_parked(&plan.paths, &run, failed(StartStep::SelectVm, f.error, f.started.as_deref())));
            }
        };
        let how = match &selected_vm {
            Selected::Started { .. } => "started",
            Selected::Reused { resumed: true, .. } => "resumed",
            Selected::Reused { .. } => "reused",
        };
        let (row, vm) = (selected_vm.row().clone(), selected_vm.vm().clone());
        *progress.vm.borrow_mut() = Some(vm.id.clone());
        let (row, _) = workspace_caps(ctx, api, ep, row).await.map_err(|e| failed(StartStep::SelectVm, e, Some(&vm.id)))?;
        audit_event(&plan.paths, event::VM_SELECT, &[("id", vm.id.clone()), ("how", how.to_string()), ("choice", run.choice.word().to_string()), ("ms", ms(t).to_string()), ("gen", gen.to_string()), ("avoid", avoid.join(","))]);
        selected.set(true);
        Ok::<_, Failed>((row, vm, how))
    };
    let (token, (), (row, vm, how)) = tokio::try_join!(touch, old_vm, new_vm)?;
    Ok(MoveVm { kind, row, vm, how, token: Some(token), touchid: "asked" })
}

/// M1's end of the chat's spawn on its old VM, running (`agent::stop_spawn`
/// within `STOP_SPAWN_WITHIN`): a `Gap`'s, or an unreachable chat's on a VM
/// other chats keep. `true` once it is gone; `false` or an error alike (a
/// respawn then takes a new VM, an unreachable VM is terminated).
async fn stop_gapped<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, spawn: &SpawnId) -> bool {
    let env = match agent_env(ctx, api, ep, row, Some(vm)) {
        Ok(env) => env,
        Err(e) => {
            tracing::info!(vm = %vm.id, "the gapped spawn cannot be reached: {e}");
            return false;
        }
    };
    match crate::bridge::agent::stop_spawn(&env, spawn, crate::bridge::agent::STOP_SPAWN_WITHIN).await {
        Ok(stopped) => stopped,
        Err(e) => {
            tracing::info!(vm = %vm.id, spawn = %spawn, "stopping the gapped spawn failed: {e}");
            false
        }
    }
}

/// Whether another live wrapper's chat runs on `vm` (an unreachable VM's
/// end in M1: a workspace's chats share VMs): a session row naming it, of
/// another process (by pid: this wrapper's own rows, a `/clear`'s earlier
/// one included, never count), not closed, its wrapper a live
/// `ai-env-claude` (`registry::confirm_wrapper`). Rows that cannot be read
/// count as none.
fn others_live_on(ctx: &Ctx, vm: &str) -> bool {
    crate::bridge::registry::list(&ctx.paths)
        .unwrap_or_default()
        .iter()
        .any(|r| r.microvm_id.as_deref() == Some(vm) && r.pid != std::process::id() && r.status != "closed" && crate::bridge::registry::confirm_wrapper(r, r.pid).is_ok())
}

/// M1's wait for a gone or going VM's TERMINATED (at most
/// `MOVE_OLD_VM_WAIT`), so its `/terminate` tail lands before the restore;
/// then its row says so (`platform`, unless it says terminated already).
/// Best effort: a wait that ends otherwise is logged.
async fn wait_terminated<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str) {
    let poll = Poll { step: Poll::SETTLE.step, budget: MOVE_OLD_VM_WAIT, ramp: [Duration::ZERO; 3] };
    match run::wait_for_state(api, id, &VmState::Terminated, ctx.poll(poll)).await {
        Ok(vm) => {
            let now = crate::wire::time::unix_now();
            let marked = vm_registry::update_row(&ctx.paths, id, |r| {
                if r.status != RowStatus::Terminated {
                    r.status = RowStatus::Terminated;
                    r.terminated_at = Some(vm.terminated_at_unix.and_then(|t| u64::try_from(t).ok()).unwrap_or(now));
                    r.terminated_by.get_or_insert_with(|| "platform".to_string());
                }
                r.state_seen = Some(vm.state.as_str().to_string());
                r.state_seen_at = Some(now);
            });
            if let Err(e) = marked {
                tracing::warn!(vm = id, "the old VM's row does not say terminated: {e}");
            }
        }
        Err(e) => tracing::info!(vm = id, "the old VM's TERMINATED was not seen within the move's wait: {e}"),
    }
}

/// M2's carry seed of a re-address (S10 L7, §6.3): the source
/// `workspace::carry_source` picks for the dead VM (its last fetch's record,
/// else this Mac's HEAD and WIP, each with its note) prepared off the
/// runtime's thread, then `ensure_workspace` with `SeedWant::Carry` (a
/// never-seeded VM a clone, a pristine one a replace, any other kept). The
/// outcome and the source's word (`box`, `mac`; `kept` when the VM kept its
/// checkout).
pub(crate) async fn carry_seed<A: MicrovmApi, D: DataPlane, T: TokenSource>(ectx: &EnsureCtx<'_, A, D, T>, dead: &str) -> Result<(workspace::EnsureOutcome, &'static str), BridgeError> {
    let (paths, cfg, ws, lim, dead) = (ectx.paths.clone(), ectx.cfg.clone(), ectx.ws.clone(), ectx.lim, dead.to_string());
    let prepared = workspace::blocking(move || match workspace::carry_source(&paths, &ws, &dead) {
        workspace::CarrySource::Mac { note } => {
            if let Some(note) = note {
                crate::bridge::voice::note(&note);
            }
            workspace::prepare(&paths, &cfg, &ws, &lim)
        }
        workspace::CarrySource::Box { record, note } => {
            if let Some(note) = note {
                crate::bridge::voice::note(&note);
            }
            workspace::prepare_from_box(&paths, &cfg, &ws, &lim, &record)
        }
    })
    .await??;
    let source = prepared.source();
    let outcome = workspace::ensure_workspace(ectx, Some(prepared), SeedWant::Carry).await?;
    let source = if matches!(outcome, workspace::EnsureOutcome::Kept { .. }) { "kept" } else { source };
    Ok((outcome, source))
}

/// M2's cut once the transcript is restored (S10 §2.9): one `GET
/// /transcript/view` of it on the moved VM (`VIEW_MESSAGES_DEFAULT`
/// messages, within the move's deadline), then [`cut_of`]. A view that
/// cannot be read, or one its check refuses, is `Cut::None` (every
/// outstanding line is sent again), logged.
async fn view_cut<A: MicrovmApi, D: DataPlane, T: TokenSource>(plan: &SessionPlan, ectx: &EnsureCtx<'_, A, D, T>, sid: &str, why: &MoveWhy, until: Instant) -> Cut {
    use crate::bridge::dataplane::{exchange, Exchange, Verdict};
    let Some(sync) = &plan.transcript_sync else { return Cut::None };
    let q = crate::wire::workspace::ViewQuery { rel: crate::bridge::s3::sync::main_rel(&sync.slug, sid), n: crate::wire::view::VIEW_MESSAGES_DEFAULT };
    let x = Exchange { api: ectx.api, tokens: ectx.tokens, vm_id: &ectx.target.vm_id, port: crate::wire::workspace::APP_PORT, cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1, route: "GET /transcript/view", deadline: Some(until), idempotent: true };
    let read = exchange(&x, |t| {
        let q = &q;
        async move { ectx.dp.transcript_view(ectx.target, &t, q).await }
    })
    .await;
    match read {
        Ok((reply, Verdict::Done)) => match reply.body {
            Some(view) if view.check(q.n).is_ok() => cut_of(&view, &why.outstanding, why.leaf.as_deref()),
            _ => {
                tracing::info!(session = sid, "the cut: the view is not one the Mac takes: plain --resume");
                Cut::None
            }
        },
        Ok((reply, _)) => {
            tracing::info!(session = sid, status = reply.status, "the cut: no view: plain --resume");
            Cut::None
        }
        Err(e) => {
            tracing::info!(session = sid, "the cut: the view was not read ({e}): plain --resume");
            Cut::None
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod c1_tests {
    use super::*;
    use crate::bridge::api::{AuthToken, Call, FakeMicrovmApi, FakeState, HealthDetailReply, HealthReply, IdleSpec, RunSpec, FAKE_IMAGE_ARN};
    use crate::wire::frame::{CAP_CREDENTIAL_CACHE, CAP_TRANSCRIPT_S3_V1};
    use crate::wire::view::{TranscriptViewReply, ViewEntry, ViewRole};

    /// The documentation account's made-up egress connector.
    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// A move of `kind` for `cause` off `from_vm`: the session [`SID`], its
    /// outstanding lines `outstanding`, the host's `initialize` answered.
    fn why(kind: MoveKind, cause: LossCause, from_vm: &str, outstanding: &[&str]) -> MoveWhy {
        MoveWhy { kind, cause: Some(cause), trigger: None, from_vm: from_vm.into(), from_spawn: None, session_id: Some(SID.into()), outstanding: strings(outstanding), leaf: None, fresh_chat: false, init_answered: true }
    }

    /// The moved argv by the cut, every resume flag of P0's gone (each form,
    /// before a bare `--` only), another flag's value kept whatever it
    /// reads, `--resume-drops-turn` never added; with no session id, P0's
    /// argv unchanged; a fork no init has named yet (P0's `--fork-session`
    /// beside its own `--resume` of the session, no cut) unchanged too. The
    /// cut's flags keep the argv within its cap only when there is room for
    /// them.
    #[test]
    fn move_argv_table() {
        let at = || Cut::At("L".into());
        let cases: [(&[&str], Cut, &[&str]); 8] = [
            (&["claude", "--output-format", "stream-json", "--resume", "old", "--verbose"], Cut::None, &["claude", "--output-format", "stream-json", "--verbose", "--resume=S"]),
            (&["claude", "--resume=old", "--model", "opus"], at(), &["claude", "--model", "opus", "--resume=S", "--resume-session-at=L"]),
            (&["claude", "-r", "old", "-c", "--continue", "--fork-session", "--reply-on-resume", "--verbose"], Cut::Fresh, &["claude", "--verbose", "--session-id=S"]),
            (&["claude", "--session-id", "X", "--resume-session-at=Y", "--resume-drops-turn", "2", "--session-id=Z"], Cut::None, &["claude", "--resume=S"]),
            // `--resume` with no value (a flag follows): only the flag goes.
            (&["claude", "--resume", "--verbose"], Cut::None, &["claude", "--verbose", "--resume=S"]),
            // Another flag's value stays, whatever it reads.
            (&["claude", "--model", "-r", "--append-system-prompt=--resume x"], Cut::None, &["claude", "--model", "-r", "--append-system-prompt=--resume x", "--resume=S"]),
            // After a bare `--` nothing is a flag: the cut goes before it.
            (&["claude", "--verbose", "--", "--resume", "x"], at(), &["claude", "--verbose", "--resume=S", "--resume-session-at=L", "--", "--resume", "x"]),
            (&["claude"], Cut::Fresh, &["claude", "--session-id=S"]),
        ];
        for (argv, cut, want) in cases {
            let got = move_argv(&strings(argv), Some("S"), &cut);
            assert_eq!(got, strings(want), "{argv:?} by {cut:?}");
            assert!(!got.iter().any(|a| a.starts_with("--resume-drops-turn")), "{got:?}");
            assert!(argv_fits(&got).is_ok());
            assert_eq!(move_argv(&strings(argv), None, &cut), strings(argv), "no session id: P0's argv");
        }
        assert_eq!((Cut::None.word(), at().word(), Cut::Fresh.word()), ("none", "at", "fresh"));
        // A fork no init has named yet (the session is P0's own `--resume`, with `--fork-session`, no cut): P0's argv
        // whole, so the moved CLI forks again at P0's own cut; once the fork's id is adopted, it is resumed as any.
        let fork = strings(&["claude", "--resume=S", "--fork-session", "--resume-session-at=M", "--verbose"]);
        assert_eq!(move_argv(&fork, Some("S"), &Cut::None), fork, "an unused fork: forked again");
        assert_eq!(move_argv(&fork, Some("F"), &Cut::None), strings(&["claude", "--verbose", "--resume=F"]), "the adopted fork resumed");
        assert_eq!(move_argv(&fork, Some("S"), &at()), strings(&["claude", "--verbose", "--resume=S", "--resume-session-at=L"]), "a cut: stripped");
        for p0 in [&["claude", "-r", "S", "--fork-session"][..], &["claude", "--fork-session", "--resume", "S"], &["claude", "-r=S", "--fork-session", "--", "x"]] {
            assert_eq!(move_argv(&strings(p0), Some("S"), &Cut::None), strings(p0), "{p0:?}");
        }
        // No fork, a fork of another session, a `--fork-session` that is another flag's value, or one after `--`: stripped.
        for p0 in [&["claude", "--resume", "S"][..], &["claude", "--resume=X", "--fork-session"], &["claude", "--resume=S", "--model", "--fork-session"], &["claude", "--resume", "S", "--", "--fork-session"]] {
            assert_ne!(move_argv(&strings(p0), Some("S"), &Cut::None), strings(p0), "{p0:?}");
        }
        // P0's argv at its cap: the cut's flags take it over, which M3 refuses (exit 9).
        // Each argument and its NUL: `claude`, `--model`, then the value's own NUL.
        let used = ("claude".len() + 1) + ("--model".len() + 1) + 1;
        let full = vec!["claude".to_string(), "--model".to_string(), "x".repeat(ARGV_MAX_BYTES - used)];
        assert!(argv_fits(&full).is_ok());
        let over = argv_fits(&move_argv(&full, Some(SID), &Cut::None)).unwrap_err();
        assert_eq!(over.exit_code(), 9);
    }

    /// The cut from one view (§2.9): the leaf when the view lists it before
    /// the first outstanding line, else the entry just before that line;
    /// `None` when the line is not in the view (the dead CLI never wrote
    /// it), opens the view with no leaf there, or nothing is outstanding.
    /// `cut_before` decides first: nothing outstanding is `None`, a fresh
    /// chat with a session id and outstanding lines `Fresh`; else the view.
    #[test]
    fn cut_of_table() {
        let entry = |role: ViewRole, uuid: &str| ViewEntry { role, uuid: uuid.into(), timestamp: "2026-10-20T10:00:00Z".into(), blocks: vec!["x".into()] };
        let view = TranscriptViewReply {
            v: crate::wire::view::VIEW_V,
            present: true,
            title: None,
            version: None,
            git_branch: None,
            entries: vec![entry(ViewRole::User, "u1"), entry(ViewRole::Assistant, "a1"), entry(ViewRole::User, "u2"), entry(ViewRole::Assistant, "a2"), entry(ViewRole::User, "u3")],
        };
        let at = |l: &str| Cut::At(l.into());
        let cases: [(&[&str], Option<&str>, Cut); 9] = [
            (&["u3"], Some("a1"), at("a1")),
            (&["u3"], None, at("a2")),
            (&["u3"], Some("zz"), at("a2")),
            (&["u3"], Some(""), at("a2")),
            // The leaf after the line: not where it resumes.
            (&["u2", "u3"], Some("a2"), at("a1")),
            (&["u4"], Some("a2"), Cut::None),
            (&["u1"], None, Cut::None),
            (&["u1"], Some("a1"), Cut::None),
            (&[], Some("a2"), Cut::None),
        ];
        for (outstanding, leaf, want) in cases {
            assert_eq!(cut_of(&view, &strings(outstanding), leaf), want, "{outstanding:?} at {leaf:?}");
        }
        let empty = TranscriptViewReply { present: false, entries: Vec::new(), ..view.clone() };
        assert_eq!(cut_of(&empty, &strings(&["u1"]), Some("a1")), Cut::None);
        let mut w = why(MoveKind::Readdress, LossCause::VmGone, "microvm-1", &[]);
        assert_eq!(cut_before(&w), Some(Cut::None), "nothing outstanding");
        w.fresh_chat = true;
        assert_eq!(cut_before(&w), Some(Cut::None), "nothing outstanding, even fresh");
        w.outstanding = strings(&["u1"]);
        assert_eq!(cut_before(&w), Some(Cut::Fresh), "a fresh chat's first turn");
        w.session_id = None;
        assert_eq!(cut_before(&w), None, "no session id: the view decides (and with none there is no cut)");
        w.session_id = Some(SID.into());
        w.fresh_chat = false;
        assert_eq!(cut_before(&w), None, "a chat that is not fresh: the view decides");
    }

    /// The move's own window once the host's `initialize` was answered
    /// (`MOVE_WINDOW` from its start), T0 + 50 s while it is not; a start
    /// past it fails as the move (`Failure::Move`, its kind, its cause, the
    /// deadline naming the step it was stuck at: here a respawn's VM never
    /// RUNNING again), audited `session_move_end` `failed`, never
    /// `session_remote_failed` (the session had started).
    #[tokio::test]
    async fn the_move_deadline() {
        assert_eq!(MOVE_WINDOW, Duration::from_secs(180));
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        let answered = why(MoveKind::Respawn, LossCause::SpawnGone, "microvm-1", &[]);
        let before = Instant::now();
        let own = deadline_of(&plan, &StartWhy::Move(answered.clone()));
        assert!(own >= before + MOVE_WINDOW && own <= Instant::now() + MOVE_WINDOW, "the move's own window");
        let waiting = MoveWhy { init_answered: false, ..answered.clone() };
        assert_eq!(deadline_of(&plan, &StartWhy::Move(waiting.clone())), plan.init_deadline(), "Cursor still waits: T0 + 50 s");
        // T0 + 50 s is 300 ms away, and the chat's VM stays PENDING (no auto-advance).
        plan.t0 = Instant::now().checked_sub(INIT_DEADLINE - Duration::from_millis(300)).expect("a clock past 50 s");
        let path = dir.path().join("fake.json");
        std::fs::write(&path, serde_json::to_string(&FakeState::new()).unwrap()).unwrap();
        let api = crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(&path).unwrap();
        let spec = run_spec(&crate::bridge::vm::run::new_session_token());
        let vm = api.with(|s| s.run(&spec)).unwrap();
        assert_eq!(vm.state, VmState::Pending);
        let row = VmRow { id: vm.id.clone(), status: RowStatus::Pending, client_token: spec.client_token.clone(), egress: "vpc".into(), ..VmRow::default() };
        *plan.current.borrow_mut() = Some(Current { backend: Rc::new(Backend::Fake(api)), row, vm: vm.clone(), how: "started", seed: "cloned", seeded_head: None });
        let paths = plan.paths.clone();
        let (io, _consumer) = crate::bridge::agent::spawn_channels(1);
        let start = Instant::now();
        let f = run(Rc::new(plan), 2, StartWhy::Move(MoveWhy { from_vm: vm.id.clone(), ..waiting }), io).await.expect_err("past its deadline");
        assert!(start.elapsed() < Duration::from_secs(5), "cut at the deadline: {:?}", start.elapsed());
        assert_eq!((f.code, f.step, f.vm.as_deref()), (7, StartStep::Deadline, Some(vm.id.as_str())));
        let line = f.line.unwrap_or_default();
        assert!(line.starts_with(&format!("the chat's claude on {} was lost (its spawn is gone); restarting it there failed: ", vm.id)) && line.ends_with("; reopen the chat from the picker"), "{line}");
        let rows = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap();
        let ends: Vec<_> = rows.iter().filter(|r| r["event"] == "session_move_end").collect();
        assert_eq!(ends.len(), 1, "{rows:?}");
        let d = &ends[0]["detail"];
        assert_eq!((d["outcome"].as_str(), d["kind"].as_str(), d["gen"].as_str(), d["step"].as_str(), d["code"].as_str()), (Some("failed"), Some("respawn"), Some("2"), Some("deadline"), Some("7")));
        assert!(!rows.iter().any(|r| r["event"] == "session_remote_failed"), "{rows:?}");
    }

    /// A vpc RunSpec of the fake's image for a VM whose session token is `token`.
    fn run_spec(token: &crate::wire::redact::Secret<String>) -> RunSpec {
        RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![CONNECTOR.into()],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: crate::bridge::vm::run::build_payload(token, "mike@mbp", "2026-10-20T08:00:00Z").unwrap(),
            client_token: uuid::Uuid::now_v7().to_string(),
        }
    }

    /// The fake API as a move meets it: a VM is RUNNING at its first look,
    /// and its `/health` names the workspace routes, the transcript store and
    /// the credential cache (an S9 image's).
    fn fake() -> FakeMicrovmApi {
        let api = FakeMicrovmApi::new();
        api.set_auto_advance(true);
        api.state().health_caps.extend([CAP_WORKSPACE_V1, CAP_TRANSCRIPT_S3_V1, CAP_CREDENTIAL_CACHE].map(str::to_string));
        api
    }

    /// `SessionPlan::sample` whose SELECT_VM can start a VM (its vpc
    /// connector set), its polls scaled to milliseconds.
    fn plan_in(dir: &Path) -> SessionPlan {
        let mut plan = SessionPlan::sample(dir);
        plan.run.egress_connectors = vec![CONNECTOR.into()];
        plan.knobs.backoff_ms = Some(1);
        plan
    }

    /// The chat's VM: running in the fake, its row written (vpc, its session token, its endpoint).
    async fn chat_vm(plan: &SessionPlan, api: &FakeMicrovmApi) -> (VmRow, VmInfo) {
        let token = crate::bridge::vm::run::new_session_token();
        let spec = run_spec(&token);
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let vm = api.get(&vm.id).await.unwrap();
        let row = VmRow { id: vm.id.clone(), status: RowStatus::Running, client_token: spec.client_token.clone(), session_token: Some(token.expose().clone()), endpoint: Some(vm.endpoint.clone()), egress: "vpc".into(), ..VmRow::default() };
        vm_registry::write_row(&plan.paths, &row).unwrap();
        (row, vm)
    }

    /// What the generation before the move left: `row` and `vm`, its
    /// backend a file fake that M1 never calls (M1 takes the API it is given).
    fn current_on(dir: &Path, row: VmRow, vm: VmInfo) -> Current {
        let path = dir.join("backend.json");
        std::fs::write(&path, serde_json::to_string(&FakeState::new()).unwrap()).unwrap();
        let backend = Backend::Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(&path).unwrap());
        Current { backend: Rc::new(backend), row, vm, how: "started", seed: "cloned", seeded_head: None }
    }

    /// A setup-token built at run time (no credential-shaped literal), sealed as `tag`.
    fn unsealed(tag: &str) -> (SetupToken, String) {
        (crate::bridge::setup_token::parse_token(&"t".repeat(40)).unwrap(), tag.to_string())
    }

    /// M1 with a counting stand-in for `credential::unseal_for_move`: what it
    /// chose, how many Touch IDs it asked, and how many RunMicrovm calls the
    /// fake had taken when the Touch ID was asked.
    async fn m1<E: EndpointClient>(plan: &SessionPlan, api: &FakeMicrovmApi, ep: &E, current: &Current, why: &MoveWhy) -> (Result<MoveVm, Failed>, usize, Option<usize>) {
        let asked = Cell::new(0);
        let runs_then = Cell::new(None);
        let tag = plan.token.tag.clone();
        let ctx = plan.ctx();
        let progress = Progress::default();
        let moved = move_vm(plan, &ctx, api, ep, current, why, 2, &progress, || {
            asked.set(asked.get() + 1);
            runs_then.set(Some(runs(api)));
            async move { Ok::<_, CliError>(unsealed(&tag)) }
        })
        .await;
        (moved, asked.get(), runs_then.get())
    }

    /// The RunMicrovm calls the fake took.
    fn runs(api: &FakeMicrovmApi) -> usize {
        api.calls().iter().filter(|c| matches!(c, Call::Run { .. })).count()
    }

    /// The `vm_select` audit rows' details.
    fn selects(plan: &SessionPlan) -> Vec<serde_json::Value> {
        crate::bridge::audit::read_rows(&plan.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == "vm_select").map(|r| r["detail"].clone()).collect()
    }

    /// A re-address off a terminated VM (`VmGone`): its TERMINATED is waited
    /// for (its row then says so, `platform`), never asked for (no
    /// TerminateMicrovm, no resume of it), beside one Touch ID and one
    /// SELECT_VM that avoids it: one RunMicrovm, a new VM, its caps read,
    /// `vm_select` with the generation and the VM avoided. A RunMicrovm whose
    /// answer is lost after it made the VM is retried under the same client
    /// token: still one VM.
    #[tokio::test]
    async fn a_readdress_waits_for_terminated_and_runs_once() {
        for ambiguous in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let api = fake();
            let (row, vm) = chat_vm(&plan, &api).await;
            let current = current_on(dir.path(), row, vm.clone());
            api.set_state(&vm.id, VmState::Terminating);
            if ambiguous {
                api.fail_on("run", BridgeError::Ambiguous { op: "run_microvm", message: "the answer was lost".into() }, true);
            }
            let before = (runs(&api), api.state().vms.len());
            let (moved, asked, _) = m1(&plan, &api, &api, &current, &why(MoveKind::Readdress, LossCause::VmGone, &vm.id, &[])).await;
            let moved = moved.unwrap_or_else(|f| panic!("M1: {:?}", f.failure));
            assert_ne!(moved.vm.id, vm.id, "a new VM");
            assert_eq!((moved.kind, moved.how, moved.touchid, moved.token.is_some(), asked), (MoveKind::Readdress, "started", "asked", true, 1));
            assert_eq!(api.state().vms.len() - before.1, 1, "one VM made");
            let tokens: Vec<String> = api.calls().iter().filter_map(|c| if let Call::Run { client_token } = c { Some(client_token.clone()) } else { None }).skip(before.0).collect();
            assert_eq!(tokens.len(), if ambiguous { 2 } else { 1 }, "{tokens:?}");
            assert!(tokens.iter().all(|t| *t == tokens[0]), "one client token");
            let old = vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("the old VM's row");
            assert_eq!((old.status, old.terminated_by.as_deref()), (RowStatus::Terminated, Some("platform")), "its TERMINATED waited for");
            assert_eq!(api.state().vms[&vm.id].state, VmState::Terminated);
            assert!(!api.calls().iter().any(|c| matches!(c, Call::Terminate(id) | Call::Resume(id) if *id == vm.id)), "{:?}", api.calls());
            assert!(moved.row.caps.as_deref().is_some_and(|c| c.iter().any(|c| c == CAP_WORKSPACE_V1)), "its caps read: {:?}", moved.row.caps);
            let s = selects(&plan);
            assert_eq!(s.len(), 1, "{s:?}");
            assert_eq!((s[0]["id"].as_str(), s[0]["how"].as_str(), s[0]["choice"].as_str(), s[0]["gen"].as_str(), s[0]["avoid"].as_str()), (Some(moved.vm.id.as_str()), Some("started"), Some("workspace"), Some("2"), Some(vm.id.as_str())));
        }
    }

    /// M1's order: a move to a new VM asks its one Touch ID at once, before
    /// any RunMicrovm (it never waits for the VM to be known). The stand-in
    /// counts the asks; `move_gen` hands M1 `credential::unseal_for_move`
    /// (`setup-token.env`), whose `credential_unseal` row
    /// `t10_1_a_terminated_vm_moves_once` checks end to end. Off an
    /// unreachable VM, SELECT_VM waits for its terminate's answer (by
    /// `readdress`); a respawn whose VM is gone moves as a re-address, its
    /// one Touch ID the re-address's.
    #[tokio::test]
    async fn a_new_vm_move_asks_one_setup_token_unseal() {
        for (kind, cause, state) in [(MoveKind::Readdress, LossCause::Unreachable, VmState::Running), (MoveKind::Respawn, LossCause::SpawnGone, VmState::Terminated)] {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let api = fake();
            let (row, vm) = chat_vm(&plan, &api).await;
            let current = current_on(dir.path(), row, vm.clone());
            api.set_state(&vm.id, state.clone());
            let before = runs(&api);
            let (moved, asked, runs_then) = m1(&plan, &api, &api, &current, &why(kind, cause, &vm.id, &["u1"])).await;
            let moved = moved.unwrap_or_else(|f| panic!("{kind:?}: {:?}", f.failure));
            assert_eq!((asked, runs_then), (1, Some(before)), "{kind:?}: one Touch ID, asked before any RunMicrovm");
            assert_eq!((moved.kind, moved.touchid, runs(&api) - before), (MoveKind::Readdress, "asked", 1), "{kind:?}");
            assert_ne!(moved.vm.id, vm.id);
            let calls = api.calls();
            let terminate = calls.iter().position(|c| matches!(c, Call::Terminate(id) if *id == vm.id));
            let old = vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("the old VM's row");
            if cause == LossCause::Unreachable {
                let run_at = calls.iter().rposition(|c| matches!(c, Call::Run { .. }));
                assert!(terminate.is_some() && terminate < run_at, "the terminate answered before SELECT_VM ran: {calls:?}");
                assert_eq!((old.status, old.terminated_by.as_deref()), (RowStatus::Terminated, Some("readdress")));
            } else {
                assert_eq!(terminate, None, "a gone VM is never terminated again");
            }
        }
    }

    /// Set when the stand-in task that holds it is dropped (aborted, or done).
    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// S10 §B, §14 (wave 1c: a loss's move ends a pending migration): a
    /// respawn that turns into a re-address in M1 (its VM gone, or a fresh
    /// chat's) gives a pending migration up before its own Touch ID: phase
    /// A's task aborted, so its dialog's turn on `state/unseal.lock` is let
    /// go and the move's dialog opens at once, and its prepared VM let go.
    /// One move, one Touch ID, no wait behind a dialog whose answer would be
    /// thrown away.
    #[tokio::test]
    async fn a_respawn_that_readdresses_gives_phase_a_up_before_its_touch_id() {
        for (case, fresh, state) in [("its VM gone", false, VmState::Terminated), ("a fresh chat", true, VmState::Running)] {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let api = fake();
            let (row, vm) = chat_vm(&plan, &api).await;
            let current = current_on(dir.path(), row.clone(), vm.clone());
            api.set_state(&vm.id, state);
            // Phase A's stand-in: its dialog's turn held until its task is dropped.
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = Dropped(Arc::clone(&dropped));
            let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
            let paths = plan.paths.clone();
            let phase_a = tokio::spawn(async move {
                let _flag = flag;
                let _turn = credential::unseal_lock(&paths, Duration::from_secs(5)).await.expect("phase A's turn");
                let _ = held_tx.send(());
                std::future::pending::<()>().await;
            });
            held_rx.await.expect("phase A holds its turn");
            plan.hold_phase_a(phase_a.abort_handle());
            *plan.prepared.borrow_mut() = Some(PreparedVm { row: row.clone(), vm: vm.clone(), how: "started", at: Instant::now(), switching: false });
            let asked = Cell::new(0);
            let tag = plan.token.tag.clone();
            let ctx = plan.ctx();
            let progress = Progress::default();
            let w = MoveWhy { fresh_chat: fresh, ..why(MoveKind::Respawn, LossCause::SpawnGone, &vm.id, &["u1"]) };
            let p = &plan;
            let moved = move_vm(&plan, &ctx, &api, &api, &current, &w, 2, &progress, || {
                asked.set(asked.get() + 1);
                async move {
                    assert!(p.prepared.borrow().is_none(), "{case}: the prepared VM let go before the move's Touch ID");
                    let turn = credential::unseal_lock(&p.paths, Duration::from_secs(1)).await;
                    assert!(turn.is_ok(), "{case}: phase A's dialog let its turn go: {:?}", turn.err());
                    Ok::<_, CliError>(unsealed(&tag))
                }
            })
            .await;
            let moved = moved.unwrap_or_else(|f| panic!("{case}: {:?}", f.failure));
            assert_eq!((moved.kind, moved.touchid, asked.get()), (MoveKind::Readdress, "asked", 1), "{case}: one move, one Touch ID");
            assert!(dropped.load(Ordering::SeqCst), "{case}: phase A's task dropped");
            assert!(phase_a.await.unwrap_err().is_cancelled(), "{case}: aborted");
        }
    }

    /// The fake's `/health/detail`, saying the VM's cache holds the seal
    /// `tag` (as the shim reports a delivered setup-token), when `tag` is
    /// given; the fake's own answer otherwise.
    struct Cache<'a> {
        fake: &'a FakeMicrovmApi,
        tag: Option<String>,
    }

    impl EndpointClient for Cache<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            if let (Some(d), Some(tag)) = (reply.detail.as_mut(), &self.tag) {
                d.has_credentials = true;
                d.credential.credential_name = Some(crate::bridge::setup_token::TOKEN_VAR.into());
                d.credential.credential_tag = Some(tag.clone());
            }
            Ok(reply)
        }
    }

    /// A respawn (`SpawnGone`) on the same running VM takes the token from
    /// the VM's cache when it holds the seal: no Touch ID, no new VM,
    /// `reused`, `vm_select` `respawn`. A VM a suspend left empty (here
    /// suspended: it is resumed) asks one.
    #[tokio::test]
    async fn a_same_vm_respawn_takes_the_cached_token() {
        for suspended in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let api = fake();
            let (row, vm) = chat_vm(&plan, &api).await;
            let current = current_on(dir.path(), row, vm.clone());
            if suspended {
                api.set_state(&vm.id, VmState::Suspended);
            }
            let ep = Cache { fake: &api, tag: (!suspended).then(|| plan.token.tag.clone()) };
            let before = runs(&api);
            let (moved, asked, _) = m1(&plan, &api, &ep, &current, &why(MoveKind::Respawn, LossCause::SpawnGone, &vm.id, &["u1"])).await;
            let moved = moved.unwrap_or_else(|f| panic!("suspended {suspended}: {:?}", f.failure));
            assert_eq!((moved.vm.id.as_str(), moved.kind, runs(&api) - before), (vm.id.as_str(), MoveKind::Respawn, 0), "the same VM");
            let want = if suspended { ("resumed", "asked", true, 1) } else { ("reused", credential::CACHED, false, 0) };
            assert_eq!((moved.how, moved.touchid, moved.token.is_some(), asked), want, "suspended {suspended}");
            assert_eq!(api.calls().iter().filter(|c| matches!(c, Call::Resume(id) if *id == vm.id)).count(), usize::from(suspended));
            let s = selects(&plan);
            assert_eq!((s.len(), s[0]["choice"].as_str(), s[0]["gen"].as_str()), (1, Some("respawn"), Some("2")), "{s:?}");
        }
    }

    /// A pinned session never moves to another VM: the pump starts no
    /// re-address of it (`SessionPlan::pinned`, in `RemoteSnapshot.pinned`),
    /// and M1 holds the rule too (a respawn whose pinned VM is no longer
    /// running): its pin or nothing (`PinGone`, exit 8), before any Touch ID.
    #[tokio::test]
    async fn a_pinned_session_is_never_readdressed() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = plan_in(dir.path());
        let api = fake();
        let (row, vm) = chat_vm(&plan, &api).await;
        assert_eq!(plan.pinned(), None);
        plan.run.choice = Choice::Pin(vm.id.clone());
        assert_eq!(plan.pinned(), Some(vm.id.as_str()));
        let current = current_on(dir.path(), row, vm.clone());
        api.set_state(&vm.id, VmState::Terminated);
        let (moved, asked, _) = m1(&plan, &api, &api, &current, &why(MoveKind::Readdress, LossCause::VmGone, &vm.id, &[])).await;
        let f = moved.err().expect("no move off a pin");
        assert_eq!((f.failure.exit_code(), asked, runs(&api)), (8, 0, 1), "{:?}", f.failure);
        assert!(matches!(f.failure, Failure::PinGone { .. }), "{:?}", f.failure);
    }

    /// A fresh chat's move (`Cut::Fresh`: `--session-id`) avoids every VM
    /// this session spawned its claude on (each may hold its `<sid>.jsonl`,
    /// which `--session-id` refuses), not only the one it left; any other
    /// move avoids that one alone (`vm_select`'s `avoid`).
    #[tokio::test]
    async fn a_fresh_chats_move_avoids_every_vm_it_ran_on() {
        for fresh in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let plan = plan_in(dir.path());
            let api = fake();
            let (row, vm) = chat_vm(&plan, &api).await;
            let current = current_on(dir.path(), row, vm.clone());
            api.set_state(&vm.id, VmState::Terminated);
            plan.spawned_on.borrow_mut().extend(["microvm-earlier01".to_string(), vm.id.clone()]);
            let w = MoveWhy { fresh_chat: fresh, ..why(MoveKind::Readdress, LossCause::VmGone, &vm.id, &["u1"]) };
            let (moved, asked, _) = m1(&plan, &api, &api, &current, &w).await;
            let moved = moved.unwrap_or_else(|f| panic!("fresh {fresh}: {:?}", f.failure));
            assert_eq!((moved.kind, asked), (MoveKind::Readdress, 1));
            let want = if fresh { format!("microvm-earlier01,{}", vm.id) } else { vm.id.clone() };
            assert_eq!(selects(&plan)[0]["avoid"].as_str(), Some(want.as_str()), "fresh {fresh}");
        }
    }

    /// S10 §2.5: a select refused at `[vm].max_concurrent` names the
    /// suspended VMs of the image no open chat holds (their workspace's
    /// `.active` free); one a chat holds, a running one, another image's, or
    /// one of no workspace is not named.
    #[test]
    fn a_refused_select_names_the_parked_vms() {
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let write = |id: &str, status: RowStatus, image: &str, slug: Option<&str>| {
            let row = VmRow { id: id.into(), status, client_token: uuid::Uuid::now_v7().to_string(), image_arn: image.into(), slug: slug.map(str::to_string), ..VmRow::default() };
            vm_registry::write_row(&plan.paths, &row).unwrap();
        };
        write("microvm-parked01", RowStatus::Suspended, FAKE_IMAGE_ARN, Some("-a"));
        write("microvm-held0001", RowStatus::Suspended, FAKE_IMAGE_ARN, Some("-b"));
        write("microvm-running1", RowStatus::Running, FAKE_IMAGE_ARN, Some("-c"));
        write("microvm-otherimg", RowStatus::Suspended, "arn:aws:lambda:eu-central-1:123456789012:microvm-image:other", Some("-d"));
        write("microvm-noslug01", RowStatus::Suspended, FAKE_IMAGE_ARN, None);
        std::fs::create_dir_all(plan.paths.workspace_active("-b").parent().unwrap()).unwrap();
        let _held = crate::bridge::vm::lock::lock_shared_blocking(&plan.paths.workspace_active("-b"), Duration::from_millis(100)).unwrap();
        assert_eq!(parked_vms(&plan.paths, FAKE_IMAGE_ARN), ["microvm-parked01"]);
        let refused = Failed { step: StartStep::SelectVm, failure: Failure::MaxConcurrent { running: 3, parked: Vec::new() }, vm: None };
        let named = with_parked(&plan.paths, &plan.run, refused);
        assert_eq!(named.failure, Failure::MaxConcurrent { running: 3, parked: vec!["microvm-parked01".into()] });
        let other = Failed { step: StartStep::SelectVm, failure: Failure::PinGone { vm: "microvm-x".into() }, vm: None };
        assert_eq!(with_parked(&plan.paths, &plan.run, other).failure, Failure::PinGone { vm: "microvm-x".into() });
    }

    /// F3b: P3's pull cap with a pinned VM that lacks the chat names the pin
    /// and asks to unset it first.
    #[test]
    fn the_pull_cap_names_a_pinned_vm_that_lacks_the_chat() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        let cap = |run: &RunPlan| {
            let f = Failed { step: StartStep::Workspace, failure: Failure::TranscriptPullTooLarge { session: SID.into(), bytes: 70 << 20, reuse_off: false, pinned: None }, vm: None };
            pull_cap(run, f).failure
        };
        assert_eq!(cap(&plan.run), Failure::TranscriptPullTooLarge { session: SID.into(), bytes: 70 << 20, reuse_off: false, pinned: None });
        plan.run.choice = Choice::Pin("microvm-pinned001".into());
        let pinned = cap(&plan.run);
        assert_eq!(pinned, Failure::TranscriptPullTooLarge { session: SID.into(), bytes: 70 << 20, reuse_off: false, pinned: Some("microvm-pinned001".into()) });
        let line = pinned.line();
        assert!(line.contains("and the pinned VM microvm-pinned001 lacks it: unset AI_ENV_BRIDGE_VM, run ai-env session stage"), "{line}");
        assert!(line.ends_with(&format!("ai-env session stage {SID} --warm, then reopen the chat")), "{line}");
        assert_eq!(pinned.exit_code(), 9);
    }

    /// The prepared VM's hold (S10 §B, §14; phase 4b FK-7): a GET /health of
    /// that VM every `move_hold_ping` of its `max_idle_s` (300 s: 100 ms at
    /// the unit plan's 1 ms a second), the first one an interval in, no other
    /// VM's; it ends at the wake after the switch took the VM, with no ping
    /// more, and at `MOVE_HOLD` it releases the VM without one.
    #[tokio::test]
    async fn the_prepared_vm_is_pinged_until_the_switch_or_its_hold() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let api = fake();
        let (_, other) = chat_vm(&plan, &api).await;
        let (row, vm) = chat_vm(&plan, &api).await;
        let pings = |endpoint: &str| api.calls().iter().filter(|c| matches!(c, Call::Health { endpoint: e, .. } if e == endpoint)).count();
        *plan.prepared.borrow_mut() = Some(PreparedVm { row: row.clone(), vm: vm.clone(), how: "started", at: Instant::now(), switching: false });
        // Wide: under the full matrix's load a 100 ms sleep can wake late.
        assert!(tokio::time::timeout(Duration::from_millis(1500), hold_on(&plan, &api, &api, &vm.id)).await.is_err(), "still holding");
        assert!(pings(&vm.endpoint) >= 2, "a ping every 100 ms: {:?}", api.calls());
        assert_eq!(pings(&other.endpoint), 0, "no other VM's");
        let switch = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            plan.prepared.borrow_mut().as_mut().expect("held").switching = true;
            pings(&vm.endpoint)
        };
        let ((), at_switch) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(hold_on(&plan, &api, &api, &vm.id), switch) }).await.expect("the hold ends at the wake after the switch took the VM");
        assert_eq!(pings(&vm.endpoint), at_switch, "no ping once the switch took it");
        assert!(plan.prepared.borrow().is_some(), "the switch keeps it");
        *plan.prepared.borrow_mut() = Some(PreparedVm { row, vm: vm.clone(), how: "started", at: Instant::now().checked_sub(MOVE_HOLD).expect("an uptime past MOVE_HOLD"), switching: false });
        let before = pings(&vm.endpoint);
        tokio::time::timeout(Duration::from_secs(10), hold_on(&plan, &api, &api, &vm.id)).await.expect("released at its first wake");
        assert!(plan.prepared.borrow().is_none(), "released at MOVE_HOLD");
        assert_eq!(pings(&vm.endpoint), before, "no ping at the release");
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod g4_tests {
    use super::*;
    use crate::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_MAC};

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const SLUG: &str = "-Users-mike-w";

    /// A bridge root and a projects directory under a tempdir.
    fn world() -> (tempfile::TempDir, Paths, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let projects = tmp.path().join("projects");
        (tmp, paths, projects)
    }

    /// `<projects>/<SLUG>/<SID>.jsonl` of `len` bytes (sparse: only its size is read), its first bytes `head`.
    fn chat(projects: &Path, len: u64, head: &[u8]) {
        let dir = projects.join(SLUG);
        std::fs::create_dir_all(&dir).unwrap();
        let f = std::fs::File::create(dir.join(format!("{SID}.jsonl"))).unwrap();
        std::io::Write::write_all(&mut &f, head).unwrap();
        f.set_len(len).unwrap();
    }

    /// The sample's run plan (the workspace `/w`, its choice), its paths under `paths`' parent.
    fn run_plan(paths: &Paths) -> RunPlan {
        SessionPlan::sample(paths.root.parent().expect("the bridge root's parent")).run
    }

    fn too_large(paths: &Paths, projects: &Path) -> Result<(), Failure> {
        transcript_too_large(paths, Some(projects), &[SLUG.to_string()], Some(SID), &run_plan(paths))
    }

    /// P0's refusal: a chat S3 does not hold whose copy here is over
    /// `INLINE_MAX` is `TranscriptTooLarge` before any Touch ID, naming
    /// `session stage` for a chat begun here and `session migrate-s9` for an
    /// S8 mirror; at or under the cap, with a manifest, a view in place or no
    /// `--resume` it passes (P3 sends it up inline, or restores it).
    #[test]
    fn transcript_too_large_names_the_way_before_any_touch_id() {
        let (_tmp, paths, projects) = world();
        let max = crate::wire::s3::INLINE_MAX;
        chat(&projects, max, b"{\"type\":\"user\"}\n");
        assert!(too_large(&paths, &projects).is_ok(), "at the cap: inline");
        chat(&projects, max + 1, b"{\"type\":\"user\"}\n");
        match too_large(&paths, &projects) {
            Err(Failure::TranscriptTooLarge { session, bytes, s8_mirror: false }) => assert_eq!((session.as_str(), bytes), (SID, max + 1)),
            other => panic!("expected TranscriptTooLarge for a Mac-begun chat, got {other:?}"),
        }
        assert!(transcript_too_large(&paths, Some(&projects), &[SLUG.to_string()], None, &run_plan(&paths)).is_ok(), "no --resume");
        // An S8 mirror (a remote row without transcript_home) names migrate-s9.
        let row = crate::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), ..crate::bridge::registry::SessionRow::default() };
        crate::bridge::registry::write(&paths, &row).unwrap();
        assert!(matches!(too_large(&paths, &projects), Err(Failure::TranscriptTooLarge { s8_mirror: true, .. })));
        // A VM-begun chat (transcript_home s3) is S3's to restore.
        let s3_row = crate::bridge::registry::SessionRow { transcript_home: Some(manifest::HOME_S3.into()), ..row };
        crate::bridge::registry::write(&paths, &s3_row).unwrap();
        assert!(too_large(&paths, &projects).is_ok());
        let _ = std::fs::remove_file(crate::bridge::registry::path_for(&paths, SID).unwrap());
        // A manifest: S3 holds it, whatever is here.
        let target = crate::bridge::s3::S3Target { bucket: crate::bridge::s3::LAB_BUCKET.into(), owner: crate::bridge::s3::LAB_OWNER.into(), endpoint: crate::bridge::s3::S3Endpoint::Aws };
        let mut m = Manifest::new(SID, &target, ORIGIN_MAC, &format!("{SLUG}/{SID}.jsonl"), "2026-10-17T10:15:30.000Z");
        m.parts.push(ManifestPart { key: format!("v1/{SID}/mac/{}", "a".repeat(64)), version_id: "fv1".into(), from: 0, len: 1, sha256: "a".repeat(64) });
        m.committed = 1;
        manifest::write(&paths, &m).unwrap();
        assert!(too_large(&paths, &projects).is_ok(), "staged already");
        std::fs::remove_file(paths.transcript_manifest(SID)).unwrap();
        assert!(too_large(&paths, &projects).is_err());
        // A view in place of the file is never a Mac copy.
        chat(&projects, max + 1, crate::wire::view::VIEW_MARK_PREFIX.as_bytes());
        assert!(too_large(&paths, &projects).is_ok(), "a view");
    }

    /// P1's scan of a `--resume`'s copy here: exactly the copies P3 sends
    /// up inline, a chat begun here and an S8 mirror (whichever VM the
    /// session names), never one S3 holds (`vm`, `mac` with a manifest).
    #[test]
    fn p1_scans_only_what_p3_sends_up_inline() {
        use crate::bridge::s3::manifest::{ORIGIN_S8_MIRROR, ORIGIN_VM};
        for (origin, want) in [(None, true), (Some(ORIGIN_S8_MIRROR), true), (Some(ORIGIN_VM), false), (Some(ORIGIN_MAC), false)] {
            assert_eq!(p1_scans(origin), want, "origin {origin:?}");
        }
    }
}

/// P4's spawn frame: `argv` (the plan's, or S10's moved one: `move_argv`);
/// the workspace's VM path as its cwd (the NFC form the seed wrote, never the
/// Mac's spelling: on the VM's disk an NFD path names another directory); the
/// proxy variables of `row`, then the session's; the session grace for
/// `row`'s idle policy (a reused VM's may be longer than `[vm].max_idle_s`);
/// `spawn_id`.
fn spawn_spec(plan: &SessionPlan, ctx: &Ctx, row: &VmRow, spawn_id: &SpawnId, argv: Vec<String>) -> SpawnSpec {
    let pairs: Vec<(String, String)> = plan.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let grace = session_grace(&plan.cfg, row.idle.map(|i| i.max_idle_s));
    SpawnSpec { argv, cwd: Some(plan.ws.vm_cwd.clone()), env: spawn_env(ctx, row, &pairs), detach_grace_s: Some(grace), id: Some(spawn_id.clone()) }
}

/// The session task: the spawn over `/agent` until its exit is delivered
/// (`agent::run_spawn_with`); its end is the spawn's, never later. Once the
/// exit arrived (and only then: a session that gave up starts nothing), the
/// closing suspend (L2, best effort) runs as a task of its own, kept by the
/// plan for the pump's last wait ([`SessionPlan::take_closing`]), after the
/// generation's code-out trigger (`trigger`) is done. S10 §D: with `[vm].park`
/// and this wrapper readable as a park's owner, the session parks when the
/// chat is quiet (`agent::run_spawn_parked`, [`park_ctl`]); else it keeps
/// S9's keep-alive and says why it never parks (`ParkReport::Off`:
/// `config`, `no_owner`). A close parked with no socket (`parked_close`)
/// fires no closing suspend: its claude stays parked, and reading the VM's
/// spawns would resume it (D5).
#[allow(clippy::too_many_arguments)]
async fn session<A: MicrovmApi + 'static, E: EndpointClient + 'static>(plan: Rc<SessionPlan>, gen: u32, ctx: Ctx, api: Arc<A>, ep: Arc<E>, row: VmRow, vm: VmInfo, spec: SpawnSpec, io: SpawnIo, delivery: Delivery, trigger: TriggerWatch) -> Result<SpawnOutcome, BridgeError> {
    let ended = {
        let mut env = agent_env(&ctx, &*api, &*ep, &row, Some(&vm)).map_err(BridgeError::Cli)?;
        env.policy.idle_s = Some(IDLE_DEFAULT_S);
        match park_ctl(&plan, &ctx, &row, trigger.clone()) {
            Ok(park) => run_spawn_parked(&env, Start::New(spec), io, Some(delivery), park).await,
            Err(why) => {
                let _ = io.events.send(SpawnEvent::Park(ParkReport::Off { why }));
                run_spawn_with(&env, Start::New(spec), io, Some(delivery)).await
            }
        }
    };
    match &ended {
        Ok(outcome) if outcome.parked_close => {
            if plan.cfg.vm.suspend_on_close {
                audit_suspend(&plan.paths, &vm.id, "skipped", Some(Skip::Parked.word()), Instant::now());
            }
            tracing::info!("closing: no suspend of {} (its claude stays parked; a read of its spawns would resume it)", vm.id);
        }
        Ok(_) => {
            let closing = Rc::clone(&plan);
            plan.keep(tokio::task::spawn_local(async move { suspend_on_close(&closing, gen, &ctx, &*api, &*ep, &row, &vm, &trigger).await }));
        }
        Err(_) => {}
    }
    ended
}

/// S10 §D: the park control of a session on `row`'s VM: the pump's quiet
/// (the plan's receiver of `RemoteLinks::quiet`; a plan no factory handed one
/// gets a quiet that stays as it began: idle), the generation's code-out
/// trigger, `ParkPolicy::from_cfg` (the lab's park knob over
/// `[vm].park_after_s`), and this wrapper as the park's owner. `Err` the word
/// of why the session never parks: `config` (`[vm].park` off) or `no_owner`
/// (`registry::process_identity` could not read this wrapper: no owner a
/// reaper could judge).
fn park_ctl(plan: &SessionPlan, ctx: &Ctx, row: &VmRow, trigger: TriggerWatch) -> Result<ParkCtl, &'static str> {
    if !plan.cfg.vm.park {
        return Err("config");
    }
    let owner = plan.owner.ok_or("no_owner")?;
    let quiet = plan.quiet.borrow().clone().unwrap_or_else(|| tokio::sync::watch::channel(QuietState { verdict: crate::bridge::park::Verdict::Idle, since: Instant::now(), last_host: None }).1);
    Ok(ParkCtl { quiet, trigger, policy: ParkPolicy::from_cfg(&plan.cfg, row, &ctx.knobs, crate::wire::time::unix_now()), owner })
}

/// Why a closing suspend was not fired (S10 D5): its `vm_suspend` row's
/// `why` ([`Skip::word`]) and its log line's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    /// `[vm].suspend_on_close` is off (no row).
    Off,
    /// The code-out trigger was not done within the bound (a fetch could still reach the VM).
    TriggerBusy,
    SpawnsUnread,
    SpawnAlive,
    Retrying,
    NotAlone,
    /// Closed parked with no socket: its claude stays parked.
    Parked,
    /// A migration's switch takes the VM's work next.
    Moving,
}

impl Skip {
    /// `vm_suspend`'s `why`.
    fn word(self) -> &'static str {
        match self {
            Skip::Off => "off",
            Skip::TriggerBusy => "trigger_busy",
            Skip::SpawnsUnread => "spawns_unread",
            Skip::SpawnAlive => "spawn_alive",
            Skip::Retrying => "retrying",
            Skip::NotAlone => "not_alone",
            Skip::Parked => "parked",
            Skip::Moving => "moving",
        }
    }

    /// The log line's words.
    fn text(self) -> &'static str {
        match self {
            Skip::Off => "suspend_on_close is off",
            Skip::TriggerBusy => "its code-out trigger was not done within the bound; the idle policy suspends it",
            Skip::SpawnsUnread => "the VM's spawns could not be read",
            Skip::SpawnAlive => "a spawn still lives on the VM",
            Skip::Retrying => "a retry respawns on the VM",
            Skip::NotAlone => "another session or vm warm of the workspace runs",
            Skip::Parked => "its claude stays parked",
            Skip::Moving => "a migration takes the VM's work next",
        }
    }
}

/// L2's best-effort suspend, as the session's exit arrived: the reason it is
/// not fired, or `Ok` to fire it. `enabled`: `[vm].suspend_on_close`;
/// `alone`: nobody else holds the workspace's `.active` lock (another
/// wrapper of the workspace, a `vm warm`); `live`: the VM's spawns alive
/// now (`None`: `/health/detail` could not be read; S10: a parked spawn of
/// another chat is none, [`Count::Suspend`]); `retrying`: a resume miss's
/// retry started a later generation on the VM.
fn suspend_verdict(enabled: bool, alone: bool, live: Option<usize>, retrying: bool) -> Result<(), Skip> {
    if !enabled {
        return Err(Skip::Off);
    }
    if !alone {
        return Err(Skip::NotAlone);
    }
    match live {
        None => Err(Skip::SpawnsUnread),
        Some(n) if n > 0 => Err(Skip::SpawnAlive),
        Some(_) if retrying => Err(Skip::Retrying),
        Some(_) => Ok(()),
    }
}

/// The closing suspend's `vm_suspend` row (S10 D5): `id`, `by` `close`,
/// `outcome` (`fired`, `conflict`, `failed`, `no_answer`, `skipped`), `why`
/// (a skip's, [`Skip::word`]), `ms` since the exit arrived (`from`).
fn audit_suspend(paths: &Paths, vm: &str, outcome: &str, why: Option<&str>, from: Instant) {
    let mut pairs = vec![("id", vm.to_string()), ("by", "close".to_string()), ("outcome", outcome.to_string())];
    if let Some(why) = why {
        pairs.push(("why", why.to_string()));
    }
    pairs.push(("ms", ms(from).to_string()));
    audit_event(paths, "vm_suspend", &pairs);
}

/// The closing suspend (L2), within [`CLOSING_BOUND`]: first the
/// generation's code-out trigger done (`trigger`, plan §11's order: the
/// pump's close closes it after the census end row, and its last fetch ends
/// or is given up at `codeout::CLOSE_WAIT`), since a fetch reaching the
/// endpoint after SuspendMicrovm would resume the VM at once; then the VM's
/// live spawns read, while this process still holds the workspace's
/// `.active` (no verdict but solitude left to ask: a VM that keeps running
/// needs no lock); then that hold let go and the workspace taken alone
/// without waiting (a session that started meanwhile holds it shared from
/// its P0, or from generation 1's start when P0 found it held alone
/// ([`hold_active_at_start`]), so nothing is fired under it); SuspendMicrovm
/// fired (never waited for) when [`suspend_verdict`] says so, audited
/// `vm_suspend` (by `close`), the VM's running row then saying suspended
/// (its credential cache is empty: S7 D3); then the hold made shared again
/// ([`hold_active_again`]): the process may go on (a resume miss's retry).
/// The exclusive hold covers only the verdict and that request, so a new
/// session's generation 1 start outwaits it ([`hold_active_at_start`],
/// [`ACTIVE_WAIT`]). Every miss is a log line: the idle policy
/// (`[vm].max_idle_s`) suspends the VM anyway. S10 (D5): every outcome is
/// audited `vm_suspend` with its time ([`audit_suspend`]; none while
/// `suspend_on_close` is off); a fetch the trigger's close gave up is waited
/// for to its end (`TriggerWatch::wait_done`: the close no longer aborts it,
/// so no SuspendMicrovm goes out while its request may reach the VM); a
/// parked spawn of another chat keeps no VM from it ([`Count::Suspend`]); a
/// migration's switch skips it (`SessionPlan::begin_switch`).
#[allow(clippy::too_many_arguments)]
async fn suspend_on_close<A: MicrovmApi, E: EndpointClient>(plan: &SessionPlan, gen: u32, ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, trigger: &TriggerWatch) {
    if !plan.cfg.vm.suspend_on_close {
        tracing::info!("closing: no suspend (suspend_on_close is off)");
        return;
    }
    let begun = Instant::now();
    let until = begun + CLOSING_BOUND;
    let skip = |why: Skip| {
        tracing::info!("closing: no suspend of {} ({})", vm.id, why.text());
        audit_suspend(&plan.paths, &vm.id, "skipped", Some(why.word()), begun);
    };
    if plan.moving.get() {
        return skip(Skip::Moving);
    }
    if tokio::time::timeout_at(until, trigger.wait_done()).await.is_err() {
        return skip(Skip::TriggerBusy);
    }
    tracing::info!("closing: the code-out trigger is done");
    let live = tokio::time::timeout_at(until, live_spawns(ctx, api, ep, row, vm, Count::Suspend)).await.unwrap_or(None);
    if let Err(why) = suspend_verdict(true, true, live, plan.started.get() > gen) {
        return skip(why);
    }
    drop(plan.active.borrow_mut().take());
    let alone = match try_lock_exclusive(&plan.paths.workspace_active(&plan.ws.slug)) {
        Ok(alone) => alone,
        Err(e) => {
            tracing::warn!("closing: the workspace's .active lock: {e}");
            None
        }
    };
    match suspend_verdict(true, alone.is_some(), live, plan.started.get() > gen) {
        Err(why) => skip(why),
        Ok(()) => match tokio::time::timeout_at(until, api.suspend(&vm.id)).await {
            Ok(r @ (Ok(()) | Err(BridgeError::Conflict(_)))) => {
                audit_suspend(&plan.paths, &vm.id, if r.is_ok() { "fired" } else { "conflict" }, None, begun);
                // Its `/suspend` hook empties the shim's credential cache (S7 D3; a Conflict: it was RUNNING no more):
                // the row stops saying running, which the prewarm's `token_held` reads. Its `credential_at` stays.
                if let Err(e) = vm_registry::update_row(&plan.paths, &vm.id, |r| {
                    if r.status == RowStatus::Running {
                        r.status = RowStatus::Suspended;
                    }
                }) {
                    tracing::warn!("closing: the row of {} still says running: {e}", vm.id);
                }
                tracing::info!("closing: suspended {} (not waited for)", vm.id);
            }
            Ok(Err(e)) => {
                tracing::warn!("closing: suspend of {}: {e}", vm.id);
                audit_suspend(&plan.paths, &vm.id, "failed", None, begun);
            }
            Err(_) => {
                tracing::warn!("closing: the suspend of {} had no answer within {} ms (the idle policy suspends it)", vm.id, CLOSING_BOUND.as_millis());
                audit_suspend(&plan.paths, &vm.id, "no_answer", None, begun);
            }
        },
    }
    // The exclusive hold made shared on its own descriptor; one that did not take is let go first.
    match alone.filter(|guard| guard.share().unwrap_or(false)) {
        Some(guard) => *plan.active.borrow_mut() = Some(guard),
        None => hold_active_again(plan).await,
    }
}

/// The plan's `.active` hold again, shared, after the closing suspend let it
/// go and did not keep it: at once while other sessions hold it shared,
/// polled while another closing session holds it alone (within its
/// [`CLOSING_BOUND`], under [`ACTIVE_WAIT`]); past that a log line, and the
/// process goes on without.
async fn hold_active_again(plan: &SessionPlan) {
    let path = plan.paths.workspace_active(&plan.ws.slug);
    let until = Instant::now() + ACTIVE_WAIT;
    loop {
        match try_lock_shared(&path) {
            Ok(Some(guard)) => {
                *plan.active.borrow_mut() = Some(guard);
                return;
            }
            Ok(None) if Instant::now() < until => tokio::time::sleep(crate::bridge::vm::lock::POLL).await,
            Ok(None) => {
                tracing::warn!("closing: {} still held exclusively after {} ms: the process goes on without the workspace's .active lock", path.display(), ACTIVE_WAIT.as_millis());
                return;
            }
            Err(e) => {
                tracing::warn!("closing: the workspace's .active lock: {e}; the process goes on without it");
                return;
            }
        }
    }
}

/// Which of a VM's spawns alive keep it (S10 D5, [`live_spawns`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    /// The closing suspend's: a parked spawn (another chat's: this one's
    /// exited) keeps no VM from its suspend, which is what it waits for.
    Suspend,
    /// An old VM's end after a move: a parked orphan (its owner no live
    /// wrapper) ends with it; any other spawn keeps it.
    Retire,
}

/// The VM's spawns alive now (`/health/detail` with the session's bearer)
/// that `count` keeps, `None` when it cannot be read.
async fn live_spawns<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, count: Count) -> Option<usize> {
    let detail = health_detail(ctx, api, ep, row, vm).await?;
    let keeps = |s: &crate::wire::frame::SpawnDetail| match count {
        Count::Suspend => s.parked.is_none(),
        Count::Retire => !s.parked.is_some_and(|owner| !owner_alive(owner)),
    };
    Some(detail.spawns.iter().filter(|s| (s.status.alive || s.group_alive) && keeps(s)).count())
}

/// The VM's `/health/detail` (with the session's bearer), `None` when it cannot be read.
async fn health_detail<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo) -> Option<crate::wire::frame::HealthDetail> {
    let target = target_of(row, vm).ok()?;
    let token = crate::bridge::vm::token::mint_internal(api, &ctx.paths, &vm.id).await.ok()?;
    let reply = ep.get_health_detail(&target.endpoint, &token, &target.session_token).await.ok()?;
    reply.detail.filter(|_| reply.status == 200)
}

/// S10 (D5, M6): is a park's owner a live wrapper? Its pid is an
/// `ai-env-claude` (`registry::WRAPPER_EXE`) started when the park says
/// (`registry::process_identity`); anything else (gone, unreadable, another
/// program, a later start: the pid reused) is no live wrapper.
fn owner_alive(owner: crate::wire::frame::ParkOwner) -> bool {
    crate::bridge::registry::process_identity(owner.pid).is_some_and(|(name, started)| name == crate::bridge::registry::WRAPPER_EXE && started == owner.started)
}

/// `auth_timers_unmeasured` (plan §12), once per claude version on this
/// Mac: the VM's claude (`claude`, as the link's `Started` names it, or
/// `unknown`) is not the version `authwatch::AUTH_TIMERS` measured, so the
/// session's refusal watch counts the retry rule only. For the remote
/// link's adapter, at `Started`; nothing for the measured version. The empty
/// marker `state/auth-timers/<version>`, created once, says the row was
/// written; a version that is no plain version string is audited every time.
pub fn audit_auth_timers(paths: &Paths, claude: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let measured = crate::bridge::authwatch::AUTH_TIMERS.claude;
    if claude == measured {
        return;
    }
    let plain = !claude.is_empty() && claude.len() <= 64 && !claude.starts_with('.') && claude.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'));
    if plain {
        let dir = paths.root.join("state").join("auth-timers");
        let marker = crate::bridge::registry::ensure_private_dir(&dir)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|()| std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir.join(claude)));
        match marker {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return,
            Err(e) => tracing::warn!("{}: no marker for claude {claude} ({e}): audited anyway", event::AUTH_TIMERS_UNMEASURED),
        }
    }
    audit_event(paths, event::AUTH_TIMERS_UNMEASURED, &[("claude", claude.to_string()), ("measured", measured.to_string())]);
}

// ---- the data plane ---------------------------------------------------------------------

/// The data plane of a session's VM and its endpoint tokens (plan §10),
/// which `vm warm` takes too: W4's client (`dataplane::HttpsEndpoint`: one
/// client per port, the lab's plain http under the agent-address knob) and
/// the VM's tokens (`dataplane::MintingTokens`: minted with `api`, the
/// caller's own API object, in memory only). `seeding`: the code port's
/// tokens outlast a first seed (`dataplane::TOKEN_MINUTES_SEED`). One client
/// serves the session's seed, its transcript and its code-out trigger (whose
/// tokens are a source of their own, never seeding).
pub(crate) fn data_plane<A: MicrovmApi + 'static>(ctx: &Ctx, api: &Arc<A>, vm_id: &str, seeding: bool) -> Result<(Arc<impl DataPlane + 'static>, Arc<impl TokenSource + 'static>), BridgeError> {
    let dp = HttpsEndpoint::new(&ctx.knobs)?;
    Ok((Arc::new(dp), Arc::new(MintingTokens::new(Arc::clone(api), &ctx.paths, vm_id, seeding))))
}

// ---- S10 wave 1c (C3): a migration (§B), a reopen's carry (§2.7), the reaper (D5) ------------

/// What a switch's fallback keeps of the move's window for itself (the old
/// VM's gate, and its Touch ID when that VM's cache lost the seal): the
/// switch's own steps end this much before it (S10 §B).
const SWITCH_FALLBACK: Duration = Duration::from_secs(30);

/// S10 §B, phase A of a migration, which `RemoteLinks::prepare_move` runs
/// as a task of its own while the old CLI serves: the move's Touch ID for
/// the setup token (`credential::unseal_for_move`, M1: asked at once) beside
/// SELECT_VM (`Choice::Workspace`, `RunPlan.avoid` the chat's VM; its caps
/// read; audited `vm_select` with the live generation and the VM avoided),
/// then the gate and the delivery (`credential::move_delivery` with that
/// token) and the token delivered with no spawn
/// (`credential::deliver_only`: the VM's cache holds it, the value is
/// dropped), all within `MOVE_WINDOW`. The VM is then the plan's prepared one
/// ([`SessionPlan::begin_switch`] takes it), held running ([`hold_prepared`])
/// until the switch or `MOVE_HOLD`. A pinned session never migrates (refused
/// before anything is asked). A failure's `again`: a dismissed or unanswered
/// Touch ID (M4: asked again after the next turn); anything else ends wall
/// migrations in this process.
pub async fn prepare_move(plan: Rc<SessionPlan>, trigger: MigrateTrigger) -> Result<MoveReady, MoveFailure> {
    let begun = Instant::now();
    if plan.pinned().is_some() {
        tracing::info!(trigger = trigger.word(), "a pinned session never migrates");
        return Err(MoveFailure { step: StartStep::Precheck, code: 9, word: "refused", again: false });
    }
    let current = plan.current.borrow().clone();
    let Some(current) = current else {
        return Err(MoveFailure { step: StartStep::Precheck, code: 1, word: "other", again: false });
    };
    let backend = Rc::clone(&current.backend);
    let ctx = plan.ctx();
    let until = begun + MOVE_WINDOW;
    let progress = Progress::default();
    let prepared = match &*backend {
        Backend::Sdk(api, ep) => tokio::time::timeout_at(until, prepare_on(&plan, &ctx, Arc::clone(api), Arc::clone(ep), &current, until, &progress)).await,
        Backend::Fake(f) => tokio::time::timeout_at(until, prepare_on(&plan, &ctx, Arc::new(f.clone()), Arc::new(f.clone()), &current, until, &progress)).await,
    };
    let failed = match prepared {
        Ok(Ok((row, vm, how))) => {
            let to_vm = vm.id.clone();
            tracing::info!(trigger = trigger.word(), vm = %to_vm, how, "a migration's VM is prepared");
            *plan.prepared.borrow_mut() = Some(PreparedVm { row, vm, how, at: Instant::now(), switching: false });
            tokio::task::spawn_local(hold_prepared(Rc::clone(&plan), backend, to_vm.clone()));
            return Ok(MoveReady { to_vm, how, ms: ms(begun) });
        }
        Ok(Err(f)) => f,
        Err(_) => {
            let step = progress.stuck_at();
            Failed { step: StartStep::Deadline, failure: Failure::Deadline { code: deadline_code(step), step: step.name() }, vm: progress.vm.borrow().clone() }
        }
    };
    tracing::warn!(trigger = trigger.word(), step = failed.step.name(), code = failed.failure.exit_code(), why = failed.failure.word(), "a migration's phase A failed: the chat stays on its VM");
    Err(move_failure(failed.step, &failed.failure))
}

/// A phase A failure as the pump hears it (`ChildEvent::MoveFailed`): its
/// step, exit, word, and whether the next turn asks again (M4: a dismissed
/// or unanswered Touch ID, a deadline met at it).
fn move_failure(step: StartStep, failure: &Failure) -> MoveFailure {
    let again = matches!(failure, Failure::TouchIdCancelled | Failure::TouchIdTimeout { .. } | Failure::Deadline { step: "touchid", .. });
    MoveFailure { step, code: failure.exit_code(), word: failure.word(), again }
}

/// [`prepare_move`]'s steps on `api` and `ep`: the Touch ID beside SELECT_VM,
/// then the gate, the delivery and the token sent to the VM's cache;
/// `progress` the step a deadline names.
async fn prepare_on<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static>(plan: &SessionPlan, ctx: &Ctx, api: Arc<A>, ep: Arc<E>, current: &Current, until: Instant, progress: &Progress) -> Result<(VmRow, VmInfo, &'static str), Failed> {
    let until_std = until.into_std();
    progress.at(StartStep::TouchId);
    let touch = async {
        let token = credential::unseal_for_move(&plan.store, ctx, &plan.token, until_std).await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?;
        progress.at(StartStep::SelectVm);
        Ok::<_, Failed>(token)
    };
    let select = async {
        let t = Instant::now();
        let mut run = plan.run.clone();
        run.choice = Choice::Workspace;
        run.avoid = vec![current.vm.id.clone()];
        let selected = match run::select_vm_detailed(&*api, &plan.paths, &run, ctx.poll(Poll::RUNNING)).await {
            Ok(selected) => selected,
            Err(f) => {
                let f = retry_gate_terminate(ctx, &*api, f).await;
                return Err(with_parked(&plan.paths, &run, failed(StartStep::SelectVm, f.error, f.started.as_deref())));
            }
        };
        let how = match &selected {
            Selected::Started { .. } => "started",
            Selected::Reused { resumed: true, .. } => "resumed",
            Selected::Reused { .. } => "reused",
        };
        let (row, vm) = (selected.row().clone(), selected.vm().clone());
        *progress.vm.borrow_mut() = Some(vm.id.clone());
        let (row, _) = workspace_caps(ctx, &*api, &*ep, row).await.map_err(|e| failed(StartStep::SelectVm, e, Some(&vm.id)))?;
        audit_event(&plan.paths, event::VM_SELECT, &[("id", vm.id.clone()), ("how", how.to_string()), ("choice", run.choice.word().to_string()), ("ms", ms(t).to_string()), ("gen", plan.started.get().to_string()), ("avoid", current.vm.id.clone())]);
        Ok::<_, Failed>((row, vm, how))
    };
    let (token, (row, vm, how)) = tokio::try_join!(touch, select)?;
    let at = Some(vm.id.as_str());
    progress.at(StartStep::Gate);
    let prepared = credential::move_delivery(ctx, &*api, &*ep, &row, &vm, &plan.token, Some(token), until_std).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    progress.at(StartStep::Token);
    let env = agent_env(ctx, &*api, &*ep, &row, Some(&vm)).map_err(|e| failed_cli(StartStep::Token, e, at))?;
    credential::deliver_only(&env, prepared.delivery).await.map_err(|e| failed(StartStep::Token, e, at))?;
    Ok((row, vm, how))
}

/// The prepared VM held for the switch (S10 §B, §14): a `GET /health` every
/// `move_hold_ping` of its `max_idle_s` (the lab's backoff knob scales it)
/// keeps it RUNNING, so the platform never suspends it, which would empty
/// its credential cache (S7 D3). It ends once the switch takes the VM, or
/// another phase A replaced it; at `MOVE_HOLD` it releases it (the VM keeps
/// running for the idle policy; the next due migration runs phase A again).
async fn hold_prepared(plan: Rc<SessionPlan>, backend: Rc<Backend>, vm_id: String) {
    match &*backend {
        Backend::Sdk(api, ep) => hold_on(&plan, &**api, &**ep, &vm_id).await,
        Backend::Fake(f) => hold_on(&plan, f, f, &vm_id).await,
    }
}

/// [`hold_prepared`] on `api` and `ep`.
async fn hold_on<A: MicrovmApi, E: EndpointClient>(plan: &SessionPlan, api: &A, ep: &E, vm_id: &str) {
    let ctx = plan.ctx();
    let (max_idle, since) = plan.prepared.borrow().as_ref().map_or((None, Instant::now()), |p| (p.row.idle.map(|i| i.max_idle_s), p.at));
    let every = scaled(&ctx, move_hold_ping(max_idle.unwrap_or(plan.cfg.vm.max_idle_s))).max(Duration::from_millis(10));
    let until = since + MOVE_HOLD;
    loop {
        tokio::time::sleep(every.min(until.saturating_duration_since(Instant::now()))).await;
        let held = matches!(plan.prepared.borrow().as_ref(), Some(p) if p.vm.id == vm_id && !p.switching);
        if !held {
            return;
        }
        if Instant::now() >= until {
            plan.prepared.borrow_mut().take();
            tracing::info!(vm = vm_id, "the migration's prepared VM was not switched to within its hold: released");
            return;
        }
        if let Err(e) = crate::bridge::vm::health::read_health(api, ep, &ctx.paths, vm_id, ctx.backoff()).await {
            tracing::info!(vm = vm_id, "the prepared VM's keep-alive /health: {e}");
        }
    }
}

/// What a switch's new VM got before its spawn ([`arrive_vm`]): the seed's
/// word, its head and where it came from (`box`, `mac`, `kept`), the
/// transcript's word.
struct Arrived {
    seed: &'static str,
    seeded_head: Option<String>,
    source: &'static str,
    transcript: Option<&'static str>,
}

/// Where a switch spawns ([`switch_vm`]): the prepared VM, or the old one it
/// fell back to, with its delivery (and `how` it was taken); a fallback's
/// `touchid`: `cached` (the old VM held the seal) or `asked` ([`stay_on`]).
enum SwitchTo {
    New { row: VmRow, vm: VmInfo, how: &'static str, arrived: Arrived, prepared: credential::Prepared },
    Stayed { row: VmRow, vm: VmInfo, how: &'static str, prepared: credential::Prepared, touchid: &'static str },
}

/// S10 §B, phase B of a migration (`move_gen`'s `Migrate`; the old CLI
/// stopped): the moved argv checked first (`--resume=<sid>` and no cut,
/// [`move_argv`] with `Cut::None`: the same on either VM, so one over P0's
/// caps fails the move before anything moves); [`switch_vm`] (the old VM's
/// work fetched and synced, then the carry seed and the restore beside a
/// fresh gate on the prepared VM, the reaper, or the fallback to the old
/// VM); then the spawn. The generation the switch left stays the plan's
/// ([`SessionPlan::left`]) until the new spawn's `Started`: a moved CLI the
/// new VM never started falls back to it with the pump's next `Migrate`
/// start, which finds no VM prepared ([`stay_on`] at once; the pump wrote its
/// `stayed`). After the new `Started`, the old VM's end ([`retire_old_vm`]);
/// none after a fallback.
#[allow(clippy::too_many_arguments)]
async fn switch_gen<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, E: EndpointClient + 'static>(
    plan: &Rc<SessionPlan>,
    gen: u32,
    api: Arc<A>,
    ep: Arc<E>,
    current: Current,
    why: &MoveWhy,
    io: SpawnIo,
    progress: &Progress,
    until: Instant,
) -> Result<PipelineEnd, Failed> {
    let ctx = plan.ctx();
    let t = Instant::now();
    progress.kind.set(Some(MoveKind::Migrate));
    progress.touchid.set(Some("asked"));
    let argv = move_argv(&plan.argv, why.session_id.as_deref(), &Cut::None);
    argv_fits(&argv).and_then(|()| spawn_frame_fits(&ctx, &argv, &plan.ws, &plan.env)).map_err(|failure| Failed { step: StartStep::Spawn, failure, vm: None })?;
    let (base, fallback) = switch_base(plan, current);
    let until_std = until.into_std();
    let sid = why.session_id.clone();
    let unseal = || credential::unseal_for_move(&plan.store, &ctx, &plan.token, until_std);
    let switched = if fallback {
        tracing::info!(gen, vm = %base.vm.id, "the switch's new VM never started the moved claude: it restarts on the VM it left");
        let stayed = stay_on(plan, &ctx, &*api, &*ep, &base, until_std, progress, unseal).await;
        plan.moving.set(false);
        let (row, vm, how, prepared, touchid) = stayed?;
        SwitchTo::Stayed { row, vm, how, prepared, touchid }
    } else {
        let leave = || async { leave_vm(&ctx, &plan.ws, plan.transcript_sync.as_ref(), &api, &base.row, &base.vm, sid.as_deref()).await.map_err(|e| failed(StartStep::Workspace, e, Some(&base.vm.id))) };
        let arrive = |row: VmRow, vm: VmInfo| arrive_vm(plan, &ctx, &api, row, vm, base.vm.id.clone(), sid.clone(), until);
        switch_vm(plan, &ctx, &*api, &*ep, &base, why, gen, until, progress, leave, arrive, unseal).await?
    };
    let (row, vm, how, seed, seeded_head, source, transcript, delivery, stayed, touchid) = match switched {
        SwitchTo::New { row, vm, how, arrived, prepared } => (row, vm, how, arrived.seed, arrived.seeded_head, arrived.source, arrived.transcript, prepared, false, "asked"),
        SwitchTo::Stayed { row, vm, how, prepared, touchid } => (row, vm, how, base.seed, base.seeded_head.clone(), "kept", None, prepared, true, touchid),
    };
    let legs = vec![("workspace", ms(t))];
    plan.credential.set(Some(delivery.source));
    let at = Some(vm.id.as_str());
    let target = target_of(&row, &vm).map_err(|e| failed(StartStep::Spawn, e, at))?;
    let (dp, _) = data_plane(&ctx, &api, &vm.id, false).map_err(|e| failed(StartStep::Spawn, e, at))?;
    let code_tokens = Arc::new(MintingTokens::new(Arc::clone(&api), &ctx.paths, &vm.id, false));
    tracing::info!(gen, vm = %vm.id, stayed, seed = source, "the switch spawns");
    let spawning = Spawning { argv, session: why.session_id.clone(), why: why.vms_why() };
    let end = spawn(plan, gen, &ctx, Arc::clone(&api), Arc::clone(&ep), dp, code_tokens, target, row.clone(), vm.clone(), delivery.delivery, io, progress, spawning).await?;
    let (left_id, backend) = (base.vm.id.clone(), Rc::clone(&base.backend));
    if !stayed {
        *plan.left.borrow_mut() = Some(base);
    }
    *plan.current.borrow_mut() = Some(Current { backend, row, vm, how, seed, seeded_head: seeded_head.clone() });
    let moved = MoveDone { kind: MoveKind::Migrate, cut: Cut::None.word(), touchid, seed: source, stayed };
    let after_started = (!stayed).then(|| {
        let (plan, ctx, to, sid) = (Rc::clone(plan), plan.ctx(), end.vm.clone(), why.session_id.clone());
        AfterStarted(Box::pin(async move {
            // The moved claude runs on its new VM: the VM it left is no fallback any more, and ends.
            plan.left.borrow_mut().take();
            retire_old_vm(&ctx, &*api, &*ep, &left_id, &to, sid.as_deref()).await;
        }))
    });
    Ok(PipelineEnd {
        vm: end.vm,
        vm_how: how,
        legs,
        seed,
        transcript,
        seeded_head,
        credential: plan.credential.get(),
        delivery: Some(end.delivery),
        spawn_id: end.spawn_id,
        started_by: None,
        trigger: end.trigger,
        session: end.session,
        carried: None,
        moved: Some(moved),
        after_started,
    })
}

/// The generation a `Migrate` start moves off, and whether it is the pump's
/// fallback (S10 §B): `current`; but with no VM prepared any more and a
/// generation a switch left kept ([`SessionPlan::left`], taken), the switch
/// to the new VM never started the moved CLI, and the chat restarts on the
/// VM it left (`true`).
fn switch_base(plan: &SessionPlan, current: Current) -> (Current, bool) {
    let left = if plan.prepared.borrow().is_none() { plan.left.borrow_mut().take() } else { None };
    match left {
        Some(left) => (left, true),
        None => (current, false),
    }
}

/// [`switch_gen`]'s decision, before any spawn (S10 §B, §2.8): the plan's
/// prepared VM taken (one that is the chat's own VM counts as none); what
/// its spawn needs of its row checked; `leave` (the old VM's work fetched
/// with its WIP and the session synced there: [`leave_vm`]); then `arrive`
/// (the carry seed beside the restore on the prepared VM: [`arrive_vm`])
/// beside `credential::move_delivery` with no token there (a fresh gate:
/// phase A's pass is long past; the seal phase A left in its cache; never an
/// unseal), then `regate_if_stale` and the reaper ([`reap`]), all ending
/// [`SWITCH_FALLBACK`] before `until`. Anything of it that fails (none
/// prepared, the fetch, the sync, the seed, the restore, the prepared VM's
/// cache without the seal, the gate, the reaper) falls back to a respawn on
/// the old VM, `base` ([`stay_on`]: running again, its cached seal, else the
/// move's second Touch ID, `unseal`), audited `session_move_end` `stayed`
/// with the step and code of what failed. The closing suspend is held off
/// no more either way.
#[allow(clippy::too_many_arguments)]
async fn switch_vm<A, E, L, Lf, R, Rf, U, Uf>(plan: &SessionPlan, ctx: &Ctx, api: &A, ep: &E, base: &Current, why: &MoveWhy, gen: u32, until: Instant, progress: &Progress, leave: L, arrive: R, unseal: U) -> Result<SwitchTo, Failed>
where
    A: MicrovmApi,
    E: EndpointClient,
    L: FnOnce() -> Lf,
    Lf: std::future::Future<Output = Result<(), Failed>>,
    R: FnOnce(VmRow, VmInfo) -> Rf,
    Rf: std::future::Future<Output = Result<Arrived, Failed>>,
    U: FnOnce() -> Uf,
    Uf: std::future::Future<Output = crate::errors::Result<(SetupToken, String)>>,
{
    let begun = Instant::now();
    let until_std = until.into_std();
    // A prepared VM the chat runs on already (a loss's move took it there) is none to switch to.
    let taken = plan.prepared.borrow_mut().take().filter(|p| p.vm.id != base.vm.id);
    let attempt = async {
        let Some(p) = taken else {
            return Err(Failed { step: StartStep::SelectVm, failure: Failure::Other { code: 1, step: StartStep::SelectVm.name(), first_line: "the switch found no prepared VM".into() }, vm: None });
        };
        progress.at(StartStep::Workspace);
        *progress.vm.borrow_mut() = Some(p.vm.id.clone());
        let at = Some(p.vm.id.as_str());
        // What the spawn there takes of its row (the endpoint, the session token), before anything moves.
        target_of(&p.row, &p.vm).map_err(|e| failed(StartStep::Spawn, e, at))?;
        leave().await?;
        let delivery = async {
            let prepared = credential::move_delivery(ctx, api, ep, &p.row, &p.vm, &plan.token, None, until_std).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
            progress.gate_done.set(true);
            Ok::<_, Failed>(prepared)
        };
        let (arrived, mut prepared) = tokio::try_join!(arrive(p.row.clone(), p.vm.clone()), delivery)?;
        progress.at(StartStep::Gate);
        credential::regate_if_stale(ctx, api, &p.row, &p.vm, &mut prepared).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
        reap(plan, ctx, api, ep, &p.row, &p.vm, why.session_id.as_deref()).await?;
        Ok((p, arrived, prepared))
    };
    let fell = match tokio::time::timeout_at(until.checked_sub(SWITCH_FALLBACK).unwrap_or(until), attempt).await {
        Ok(Ok((p, arrived, prepared))) => {
            plan.moving.set(false);
            return Ok(SwitchTo::New { row: p.row, vm: p.vm, how: p.how, arrived, prepared });
        }
        Ok(Err(f)) => f,
        Err(_) => {
            let step = progress.stuck_at();
            Failed { step: StartStep::Deadline, failure: Failure::Deadline { code: deadline_code(step), step: step.name() }, vm: progress.vm.borrow().clone() }
        }
    };
    tracing::warn!(gen, step = fell.step.name(), code = fell.failure.exit_code(), why = fell.failure.word(), vm = %base.vm.id, "the switch failed after the old CLI stopped: the chat respawns on its old VM");
    let stayed = stay_on(plan, ctx, api, ep, base, until_std, progress, unseal).await;
    plan.moving.set(false);
    let (row, vm, how, prepared, touchid) = stayed?;
    let row_ = MoveEndRow {
        session: why.session_id.as_deref(),
        gen,
        kind: Some(MoveKind::Migrate),
        outcome: "stayed",
        from_vm: &why.from_vm,
        to_vm: Some(&base.vm.id),
        how: Some(how),
        seed: Some("kept"),
        cut: Some(Cut::None.word()),
        touchid: Some(touchid),
        ms: ms(begun),
        step_code: Some((fell.step.name(), fell.failure.exit_code())),
        request: request_of(why.trigger.as_ref()),
        ..MoveEndRow::default()
    };
    row_.audit(&plan.paths);
    Ok(SwitchTo::Stayed { row, vm, how, prepared, touchid })
}

/// A switch's fallback (S10 §B), a respawn on the old VM `base` as M1's
/// (§2.8): that VM running again (resumed when a suspend raced it:
/// `Poll::RESUMED`); the seal its cache holds (`cached`), else, as every
/// `/suspend` and `/resume` empties that cache (S7 D3), the move's second
/// Touch ID (`unseal`: `credential::unseal_for_move`, `asked`), whose token
/// the delivery carries; then the gate (`credential::move_delivery`) and
/// `regate_if_stale`. Its `how` and its `touchid` word with it.
#[allow(clippy::too_many_arguments)]
async fn stay_on<A, E, U, Uf>(plan: &SessionPlan, ctx: &Ctx, api: &A, ep: &E, base: &Current, until_std: std::time::Instant, progress: &Progress, unseal: U) -> Result<(VmRow, VmInfo, &'static str, credential::Prepared, &'static str), Failed>
where
    A: MicrovmApi,
    E: EndpointClient,
    U: FnOnce() -> Uf,
    Uf: std::future::Future<Output = crate::errors::Result<(SetupToken, String)>>,
{
    let old = base.vm.id.as_str();
    let at = Some(old);
    progress.at(StartStep::SelectVm);
    *progress.vm.borrow_mut() = Some(old.to_string());
    let (vm, resumed) = running_resumed(api, old, ctx.poll(Poll::RESUMED)).await.map_err(|e| failed(StartStep::SelectVm, e, at))?;
    let row = vm_registry::read_row(&ctx.paths, old).ok().flatten().unwrap_or_else(|| base.row.clone());
    let (token, touchid) = if credential::cached_on_vm(&ctx.paths, api, ep, &row, &vm, &plan.token.tag).await {
        (None, credential::CACHED)
    } else {
        progress.at(StartStep::TouchId);
        progress.touchid.set(Some("asked"));
        (Some(unseal().await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?), "asked")
    };
    progress.at(StartStep::Gate);
    let mut prepared = credential::move_delivery(ctx, api, ep, &row, &vm, &plan.token, token, until_std).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    credential::regate_if_stale(ctx, api, &row, &vm, &mut prepared).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    Ok((row, vm, if resumed { "resumed" } else { "reused" }, prepared, touchid))
}

/// The work of a VM a chat leaves (S10 §B's switch, §2.7's carry): a
/// code-out with the VM's uncommitted work (`codeout::fetch`,
/// `FetchOpts::per_result`, under the workspace's fetch lock: its record is
/// the carry seed's source), then the session `sid`'s transcript synced to
/// S3 there (`sync_session`), so the next VM restores all of it.
pub(crate) async fn leave_vm<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static>(ctx: &Ctx, ws: &WorkspaceRef, sync: Option<&crate::bridge::s3::TranscriptSync>, api: &Arc<A>, row: &VmRow, vm: &VmInfo, sid: Option<&str>) -> Result<(), BridgeError> {
    let target = target_of(row, vm)?;
    let (dp, tokens) = data_plane(ctx, api, &vm.id, false)?;
    let cctx = CodeoutCtx { api: Arc::clone(api), dp: Arc::clone(&dp), tokens: Arc::clone(&tokens), paths: ctx.paths.clone(), cfg: Arc::new(ctx.cfg.clone()), target: target.clone(), ws: ws.clone(), capture_settings: false, transcript: None };
    let report = crate::bridge::codeout::fetch(&cctx, crate::bridge::codeout::FetchOpts::per_result(&ctx.cfg)).await?;
    tracing::info!(vm = %vm.id, promoted = report.promoted.len(), "the work of the VM the chat leaves was fetched");
    let (Some(sid), Some(sync)) = (sid, sync) else { return Ok(()) };
    let rules = crate::bridge::workspace::blobscan::ScanSet::load(&ctx.paths, &ctx.cfg, ws)?.rules;
    let sctx = crate::bridge::s3::sync::SyncCtx { api: &**api, dp: &*dp, tokens: &*tokens, paths: &ctx.paths, target: &target, sync, rules: &rules, deadline: None };
    let synced = sctx.sync_session(sid).await?;
    tracing::info!(vm = %vm.id, session = sid, outcome = synced.outcome(), committed = synced.committed, "the chat's transcript was synced off the VM it leaves");
    Ok(())
}

/// A switch's new VM before its spawn (S10 §B): the carry seed of the old
/// VM's fresh record ([`carry_seed`], within `until`) beside the session's
/// transcript restored from S3 (no deadline: any size).
#[allow(clippy::too_many_arguments)]
async fn arrive_vm<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static>(plan: &SessionPlan, ctx: &Ctx, api: &Arc<A>, row: VmRow, vm: VmInfo, old: String, sid: Option<String>, until: Instant) -> Result<Arrived, Failed> {
    let at = Some(vm.id.as_str());
    let target = target_of(&row, &vm).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let (dp, tokens) = data_plane(ctx, api, &vm.id, true).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let caps = row.caps.clone().unwrap_or_default();
    let progress_log = |p: workspace::SeedProgress| tracing::info!("seed: {p:?}");
    let seeding = EnsureCtx { api: &**api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: Some(until), progress: &progress_log };
    let restoring = EnsureCtx { api: &**api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: None, progress: &progress_log };
    let seed = async { carry_seed(&seeding, &old).await.map_err(|e| failed(StartStep::Workspace, e, at)) };
    let transcript = async {
        match &sid {
            Some(sid) => restore_transcript(plan, &restoring, sid).await.map(Some).map_err(|e| failed(StartStep::Workspace, e, at)),
            None => Ok(None),
        }
    };
    let ((outcome, source), transcript) = tokio::try_join!(seed, transcript)?;
    Ok(Arrived { seed: outcome.word(), seeded_head: seeded_head(&outcome), source, transcript: transcript.map(|t| t.word()) })
}

/// S10 §2.7, P2 of a reopen carried off a VM near its wall: beside SELECT_VM,
/// that VM running again (resumed: `Poll::RESUMED`), its work fetched and the
/// chat synced there ([`leave_vm`]), so P3's carry seed and restore take all
/// of it. Skipped with less than `CARRY_P2_MIN_LEFT` of T0 + 50 s left, and
/// given up with half of that left: the VM's last fetch record serves then.
/// Best effort: logged.
async fn carry_leave<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static>(plan: &SessionPlan, ctx: &Ctx, api: &Arc<A>) {
    let Some(c) = plan.carry.as_ref().filter(|c| c.left_s.is_some()) else { return };
    let deadline = plan.init_deadline();
    if deadline.saturating_duration_since(Instant::now()) < CARRY_P2_MIN_LEFT {
        tracing::info!(vm = %c.from_vm, "the carry: too little of Cursor's window is left to fetch the old VM: its last fetch record serves");
        return;
    }
    let work = async {
        let (vm, _) = running_resumed(&**api, &c.from_vm, ctx.poll(Poll::RESUMED)).await?;
        let row = vm_registry::read_row(&plan.paths, &c.from_vm)?.ok_or_else(|| BridgeError::Config(format!("{} has no row", c.from_vm)))?;
        leave_vm(ctx, &plan.ws, plan.transcript_sync.as_ref(), api, &row, &vm, plan.resume.as_deref()).await
    };
    match tokio::time::timeout_at(deadline.checked_sub(CARRY_P2_MIN_LEFT / 2).unwrap_or(deadline), work).await {
        Ok(Ok(())) => tracing::info!(vm = %c.from_vm, "the carry: the old VM's work fetched and the chat synced"),
        Ok(Err(e)) => tracing::info!(vm = %c.from_vm, "the carry: the old VM's work was not fetched ({e}): its last fetch record serves"),
        Err(_) => tracing::info!(vm = %c.from_vm, "the carry: the old VM's fetch did not end in time: its last fetch record serves"),
    }
}

/// S10 §B, §2.7: once the chat runs on `to`, the VM it left (`from`): its row
/// says `leaving_for` (no reuse takes it while its spawns are counted:
/// `run::reuse_candidate`); then, when no other chat's spawn lives there
/// ([`Count::Retire`]: a parked orphan ends with it), its chats synced
/// (`sync_before_terminate`; the moved chat `sid` no longer among them:
/// [`row_moved`]) and it terminated by `migrate`, not waited for. A VM kept
/// (another chat's spawn lives there, its spawns or row cannot be read, or
/// GetMicrovm fails) loses this retire's mark: it stays an ordinary
/// workspace VM, which a later select may reuse, and its wall ends it.
/// Best effort, logged. Never the VM the chat runs on (`from` = `to`:
/// nothing to do).
pub(crate) async fn retire_old_vm<A: MicrovmApi + crate::bridge::s3::S3Sign, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, from: &str, to: &str, sid: Option<&str>) {
    if from == to {
        tracing::warn!(vm = from, "the VM the chat left is the one it runs on: kept");
        return;
    }
    let now = crate::wire::time::unix_now();
    if let Err(e) = vm_registry::update_row(&ctx.paths, from, |r| {
        r.leaving_for = Some(to.to_string());
        r.leaving_since = Some(now);
    }) {
        tracing::warn!(vm = from, "the VM the chat left: its row does not say so: {e}");
    }
    // Only this retire's own mark goes (another one's, set while this one counted, stays).
    let unmark = || {
        let cleared = vm_registry::update_row(&ctx.paths, from, |r| {
            if r.leaving_for.as_deref() == Some(to) && r.leaving_since == Some(now) {
                r.leaving_for = None;
                r.leaving_since = None;
            }
        });
        if let Err(e) = cleared {
            tracing::warn!(vm = from, "the VM the chat left is kept, its row still says it is leaving: {e}");
        }
    };
    let Ok(Some(row)) = vm_registry::read_row(&ctx.paths, from) else {
        unmark();
        return;
    };
    let vm = match api.get(from).await {
        Ok(vm) if !vm.state.is_terminal() => vm,
        Ok(_) => return,
        Err(e) => {
            tracing::info!(vm = from, "the VM the chat left is kept (its wall ends it): {e}");
            unmark();
            return;
        }
    };
    match live_spawns(ctx, api, ep, &row, &vm, Count::Retire).await {
        Some(0) => {}
        Some(n) => {
            tracing::info!(vm = from, spawns = n, "the VM the chat left keeps running: other chats' spawns live there (its wall ends it)");
            unmark();
            return;
        }
        None => {
            tracing::info!(vm = from, "the VM the chat left is kept: its spawns could not be read (its wall ends it)");
            unmark();
            return;
        }
    }
    if let Some(sid) = sid {
        row_moved(&ctx.paths, sid, from, to);
    }
    for w in crate::bridge::s3::commands::sync_before_terminate(ctx, api, from).await {
        tracing::info!(vm = from, "{w}");
    }
    match run::terminate_and_record(api, &ctx.paths, from, "migrate", None).await {
        Ok(_) => tracing::info!(vm = from, to, "the VM the chat left was terminated"),
        Err(e) => tracing::warn!(vm = from, "the VM the chat left was not terminated: {e}"),
    }
}

/// The moved chat's session row, while it still names the VM the chat left
/// (`from`; a reopen's wrapper writes its own only at its first init): its
/// VM is `to` now, its spawn there not recorded yet. So the old VM's sync
/// before its end, which takes the rows naming it, leaves this chat alone:
/// its transcript went up from there just before the move, and that copy,
/// behind what the new VM may have committed since, would go up as a shrunk
/// base. Read and written with no await between: the pump writes its rows
/// on the same thread. Best effort, logged.
fn row_moved(paths: &Paths, sid: &str, from: &str, to: &str) {
    match crate::bridge::registry::read(paths, sid) {
        Ok(Some(mut row)) if row.microvm_id.as_deref() == Some(from) => {
            row.microvm_id = Some(to.to_string());
            row.spawn_id = None;
            row.last_acked_seq = None;
            if let Err(e) = crate::bridge::registry::write(paths, &row) {
                tracing::warn!(session = sid, vm = from, "the moved chat's row still names the VM it left: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::info!(session = sid, "the moved chat's row: {e}"),
    }
}

/// L12 (S10 §2.7): generation 1's gc reconcile, `GC_RECONCILE_AFTER` past its
/// `Started` (outside Cursor's window), with the session's backend
/// (`api`): local only, at most every `GC_RECONCILE_EVERY` across wrappers.
async fn gc_reconcile<A: MicrovmApi>(api: Arc<A>, paths: Paths, image_arn: String) {
    use crate::bridge::vm::gc::{reconcile_apply_local, GC_RECONCILE_AFTER, GC_RECONCILE_EVERY};
    tokio::time::sleep(GC_RECONCILE_AFTER).await;
    match reconcile_apply_local(&*api, &paths, &image_arn, Some(GC_RECONCILE_EVERY)).await {
        Ok(Some(r)) => tracing::info!(marked = r.marked, removed = r.removed, closed = r.closed, "gc reconcile at the session's start"),
        Ok(None) => tracing::debug!("gc reconcile: another ran within its interval, or runs now"),
        Err(e) => tracing::info!("gc reconcile at the session's start: {e}"),
    }
}

/// C2's R1 splice (S10): a fresh chat's move restarts its transcript
/// (`--session-id`), so its chain of tails past the committed length goes
/// (`SyncCtx::drop_chain`), once the old VM pushes no more (M1 waited for its
/// TERMINATED) and before the spawn; bounded by the move's `until`. Best
/// effort: an error is logged and the move goes on.
async fn drop_fresh_chain<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(plan: &SessionPlan, api: &A, dp: &D, tokens: &T, target: &AgentTarget, sid: &str, until: Instant) {
    let Some(sync) = &plan.transcript_sync else { return };
    let rules = match crate::bridge::workspace::blobscan::ScanSet::load(&plan.paths, &plan.cfg, &plan.ws) {
        Ok(set) => set.rules,
        Err(e) => {
            tracing::warn!(session = sid, "the fresh chat's chain of tails was not dropped (its tripwires do not load: {e})");
            return;
        }
    };
    let sctx = crate::bridge::s3::sync::SyncCtx { api, dp, tokens, paths: &plan.paths, target, sync, rules: &rules, deadline: None };
    match tokio::time::timeout_at(until, sctx.drop_chain(sid)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(session = sid, "the fresh chat's chain of tails was not dropped: {e}"),
        Err(_) => tracing::warn!(session = sid, "the fresh chat's chain of tails was not dropped within the move's window"),
    }
}

/// S10 (D5, M6): the reaper, before a spawn on `vm` (P4, a move's M3, a
/// switch): the VM's spawns read once (`/health/detail`; unreadable: nothing
/// is reaped, logged). A `leftover`: the spawn this chat's session row
/// (`sid`'s) names on this VM, its wrapper not this process and no live one
/// (`registry::confirm_wrapper` fails: a reused pid is a dead wrapper). An
/// `orphan`: a parked spawn whose owner is no live wrapper ([`owner_alive`]:
/// a chat closed parked with no socket, a wrapper that died parked,
/// registered or not). Each one alive gets `agent::stop_spawn` within
/// `REAP_WAIT`, each a `session_reap` row (`ended`, `failed`; `gone` for one
/// listed no longer alive). A leftover that does not stop fails the start
/// (exit 8): two claudes never share one transcript; an orphan that does not
/// stop is only audited.
async fn reap<A: MicrovmApi, E: EndpointClient>(plan: &SessionPlan, ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, sid: Option<&str>) -> Result<(), Failed> {
    let Some(detail) = health_detail(ctx, api, ep, row, vm).await else {
        tracing::info!(vm = %vm.id, "the reaper: the VM's spawns could not be read: nothing reaped");
        return Ok(());
    };
    let leftover = sid
        .and_then(|sid| crate::bridge::registry::read(&plan.paths, sid).ok().flatten())
        .filter(|r| r.microvm_id.as_deref() == Some(vm.id.as_str()) && r.pid != std::process::id() && crate::bridge::registry::confirm_wrapper(r, r.pid).is_err())
        .and_then(|r| r.spawn_id.map(|spawn| (spawn, r.pid)));
    for s in &detail.spawns {
        let id = s.status.spawn_id.to_string();
        let found = match (&leftover, s.parked) {
            (Some((spawn, pid)), _) if *spawn == id => Some(("leftover", *pid)),
            (_, Some(owner)) if !owner_alive(owner) => Some(("orphan", owner.pid)),
            _ => None,
        };
        let Some((why, pid)) = found else { continue };
        let t = Instant::now();
        let outcome = if s.status.alive || s.group_alive {
            let stopped = match agent_env(ctx, api, ep, row, Some(vm)) {
                Ok(env) => crate::bridge::agent::stop_spawn(&env, &s.status.spawn_id, REAP_WAIT).await.unwrap_or_else(|e| {
                    tracing::info!(vm = %vm.id, spawn = %id, "the reaper: {e}");
                    false
                }),
                Err(e) => {
                    tracing::info!(vm = %vm.id, spawn = %id, "the reaper cannot reach the VM: {e}");
                    false
                }
            };
            if stopped {
                "ended"
            } else {
                "failed"
            }
        } else {
            "gone"
        };
        tracing::info!(vm = %vm.id, spawn = %id, why, wrapper_pid = pid, outcome, "the reaper");
        audit_event(
            &plan.paths,
            event::SESSION_REAP,
            &[("session", sid.unwrap_or("-").to_string()), ("vm", vm.id.clone()), ("spawn", id.clone()), ("why", why.to_string()), ("wrapper_pid", pid.to_string()), ("outcome", outcome.to_string()), ("ms", ms(t).to_string())],
        );
        if why == "leftover" && outcome == "failed" {
            return Err(Failed { step: StartStep::Spawn, failure: Failure::Other { code: 8, step: StartStep::Spawn.name(), first_line: format!("this chat's claude from an earlier wrapper (spawn {id}) did not stop on {}", vm.id) }, vm: Some(vm.id.clone()) });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod c3_tests {
    use super::*;
    use crate::bridge::api::{AuthToken, Call, FakeMicrovmApi, HealthDetailReply, HealthReply, IdleSpec, RunSpec, FAKE_IMAGE_ARN};
    use crate::bridge::remote::link::MigrateTrigger;
    use crate::wire::frame::{ParkOwner, SpawnDetail, SpawnStatus, CAP_CREDENTIAL_CACHE, CAP_TRANSCRIPT_S3_V1};

    /// The documentation account's made-up egress connector.
    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    /// The fake image version's build (`FakeState::new`).
    const BUILD: i64 = 1_789_804_800;

    fn connector_doc() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/egress/lambda-core.get-network-connector.json")).unwrap()
    }

    /// A plan whose credential gate passes on the fake's vpc VMs (bridge.toml's
    /// image and connector, a passing `egress check` recorded an hour ago with
    /// the connector's facts and the fake's build, a `no-dns` dns-path
    /// verdict), its polls scaled to milliseconds; the fake API, its VMs
    /// RUNNING at their first look, its `/health` naming the workspace
    /// routes, the transcript store and the credential cache.
    fn gated(dir: &Path) -> (SessionPlan, FakeMicrovmApi) {
        use crate::bridge::egress::{normalize_connector, ConnectorFacts, EgressVerified, VerifiedRecord, DNS_NONE, DNS_RULE, EGRESS_RULE};
        let mut plan = SessionPlan::sample(dir);
        plan.cfg = BridgeConfig::parse(&format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\nimage_version = \"1.0\"\negress_connector_arn = \"{CONNECTOR}\"\n")).unwrap();
        plan.run.egress_connectors = vec![CONNECTOR.into()];
        plan.knobs.backoff_ms = Some(1);
        let now = crate::wire::time::unix_now();
        let record = VerifiedRecord {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            connector: normalize_connector(CONNECTOR),
            vm_id: "microvm-checked".into(),
            at: crate::wire::time::rfc3339_utc(now - 3600),
            dns: DNS_NONE.into(),
            dns_rule: DNS_RULE,
            egress_rule: EGRESS_RULE,
            connector_facts: ConnectorFacts::from_get(&connector_doc()).unwrap(),
            image_created_at: Some(BUILD),
            ..VerifiedRecord::default()
        };
        EgressVerified { records: vec![record], ..EgressVerified::default() }.save(&plan.paths).unwrap();
        std::fs::create_dir_all(plan.paths.probes().parent().unwrap()).unwrap();
        std::fs::write(plan.paths.probes(), format!("{}\n", serde_json::json!({ "probe": "dns-path", "verdict": DNS_NONE, "ts": crate::wire::time::rfc3339_utc(now - 7200) }))).unwrap();
        let api = FakeMicrovmApi::new();
        api.set_auto_advance(true);
        api.state().health_caps.extend([CAP_WORKSPACE_V1, CAP_TRANSCRIPT_S3_V1, CAP_CREDENTIAL_CACHE].map(str::to_string));
        api.set_connector(CONNECTOR, connector_doc());
        (plan, api)
    }

    /// A running vpc VM of the fake (the HTTP ingress, the connector, image
    /// 1.0), its row written as a passed gate's: its id, row and info.
    async fn vm_of(plan: &SessionPlan, api: &FakeMicrovmApi) -> (VmRow, VmInfo) {
        let token = crate::bridge::vm::run::new_session_token();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![crate::bridge::api::managed_connector_arn("HTTP_INGRESS")],
            egress_connectors: vec![CONNECTOR.into()],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: crate::bridge::vm::run::build_payload(&token, "mike@mbp", "2026-10-20T08:00:00Z").unwrap(),
            client_token: uuid::Uuid::now_v7().to_string(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let vm = api.get(&vm.id).await.unwrap();
        let row = VmRow {
            id: vm.id.clone(),
            status: RowStatus::Running,
            client_token: spec.client_token.clone(),
            session_token: Some(token.expose().clone()),
            endpoint: Some(vm.endpoint.clone()),
            egress: "vpc".into(),
            egress_gate: Some(crate::bridge::vm::registry::GATE_PASSED.to_string()),
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            caps: Some([CAP_WORKSPACE_V1, CAP_TRANSCRIPT_S3_V1, CAP_CREDENTIAL_CACHE].map(str::to_string).to_vec()),
            ..VmRow::default()
        };
        vm_registry::write_row(&plan.paths, &row).unwrap();
        (row, vm)
    }

    /// The fake's endpoint whose `/health/detail` says the VM's cache holds
    /// the seal `tag` for the endpoints in `holding`, nothing for the others.
    struct Cache<'a> {
        fake: &'a FakeMicrovmApi,
        tag: String,
        holding: Vec<String>,
    }

    impl EndpointClient for Cache<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            if let Some(d) = reply.detail.as_mut().filter(|_| self.holding.iter().any(|e| e == endpoint)) {
                d.has_credentials = true;
                d.credential.credential_name = Some(crate::bridge::setup_token::TOKEN_VAR.into());
                d.credential.credential_tag = Some(self.tag.clone());
            }
            Ok(reply)
        }
    }

    /// A migration's move, off `from`.
    fn migrating(from: &str) -> MoveWhy {
        MoveWhy { kind: MoveKind::Migrate, cause: None, trigger: Some(MigrateTrigger::Command { nonce: "nonce-1".into() }), from_vm: from.into(), from_spawn: None, session_id: Some(SID.into()), outstanding: Vec::new(), leaf: None, fresh_chat: false, init_answered: true }
    }

    /// What a switch's new VM gets in the tests: a seed and a restore that ran.
    fn arrived() -> Arrived {
        Arrived { seed: "seeded", seeded_head: Some("a".repeat(40)), source: "box", transcript: Some("restored") }
    }

    /// The chat's VM (the generation before the switch: `current`, its
    /// backend a file fake the switch never calls) and a prepared one, held
    /// in the plan as phase A leaves it, the switch begun.
    async fn switching(dir: &Path, plan: &SessionPlan, api: &FakeMicrovmApi) -> (Current, VmInfo) {
        let (row, vm) = vm_of(plan, api).await;
        let (p_row, p_vm) = vm_of(plan, api).await;
        let path = dir.join("backend.json");
        std::fs::write(&path, serde_json::to_string(&crate::bridge::api::FakeState::new()).unwrap()).unwrap();
        let backend = Backend::Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(&path).unwrap());
        *plan.prepared.borrow_mut() = Some(PreparedVm { row: p_row, vm: p_vm.clone(), how: "started", at: Instant::now(), switching: false });
        assert!(plan.begin_switch());
        assert!(plan.moving.get(), "the closing suspend is held off");
        (Current { backend: Rc::new(backend), row, vm, how: "reused", seed: "seeded", seeded_head: Some("a".repeat(40)) }, p_vm)
    }

    /// The audit rows of `event`.
    fn rows(plan: &SessionPlan, event: &str) -> Vec<serde_json::Value> {
        crate::bridge::audit::read_rows(&plan.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == event).collect()
    }

    /// A setup-token built at run time (no credential-shaped literal), sealed as `tag`.
    fn unsealed(tag: &str) -> (SetupToken, String) {
        (crate::bridge::setup_token::parse_token(&"t".repeat(40)).unwrap(), tag.to_string())
    }

    /// §B: anything that fails after the old CLI stopped falls back to a
    /// respawn on the old VM, never a failed move: the old VM's work not
    /// fetched (its data plane), the prepared VM's seed or restore failing,
    /// the prepared VM's cache without the seal (exit 5 there), a prepared
    /// VM that is the chat's own (a loss's move took the chat there: none to
    /// switch to). The old VM is gated again with its own cached seal, or,
    /// when its cache lost the seal too (a suspend or a resume emptied it),
    /// with the token of the move's second Touch ID (asked once, as a
    /// respawn's: §2.8); audited `session_move_end` `stayed` with the step
    /// and code of what failed, the Touch ID's word and `session migrate`'s
    /// nonce; the prepared VM is let go and the closing suspend no longer held
    /// off. The switch itself never unseals.
    #[tokio::test]
    async fn a_failed_switch_respawns_on_the_old_vm() {
        for case in ["leave", "arrive", "seal", "own", "both"] {
            let dir = tempfile::tempdir().unwrap();
            let (plan, api) = gated(dir.path());
            let (current, prepared) = switching(dir.path(), &plan, &api).await;
            if case == "own" {
                // The prepared VM is the one the chat runs on.
                plan.prepared.borrow_mut().as_mut().expect("prepared").vm = current.vm.clone();
            }
            let holding = match case {
                "seal" => vec![current.vm.endpoint.clone()],
                "both" => Vec::new(),
                _ => vec![current.vm.endpoint.clone(), prepared.endpoint.clone()],
            };
            let ep = Cache { fake: &api, tag: plan.token.tag.clone(), holding };
            let ctx = plan.ctx();
            let progress = Progress::default();
            let fetch_failed = || Failed { step: StartStep::Workspace, failure: Failure::Workspace { code: 7, first_line: "the old VM's code-out failed".into() }, vm: None };
            let leave = || async { if case == "leave" { Err(fetch_failed()) } else { Ok(()) } };
            let arrive = |_: VmRow, _: VmInfo| async { if case == "arrive" { Err(Failed { step: StartStep::Workspace, failure: Failure::Workspace { code: 9, first_line: "the carry seed was refused".into() }, vm: None }) } else { Ok(arrived()) } };
            let asked = Cell::new(0);
            let tag = plan.token.tag.clone();
            let unseal = || {
                asked.set(asked.get() + 1);
                async move { Ok::<_, CliError>(unsealed(&tag)) }
            };
            let until = Instant::now() + MOVE_WINDOW;
            let why = migrating(&current.vm.id);
            let switched = switch_vm(&plan, &ctx, &api, &ep, &current, &why, 2, until, &progress, leave, arrive, unseal).await;
            assert!(plan.prepared.borrow().is_none() && !plan.moving.get(), "{case}: the prepared VM let go, the closing suspend no longer held off");
            let Ok(SwitchTo::Stayed { row, vm, how, prepared: delivery, touchid }) = switched else { panic!("{case}: no fallback") };
            let (source, touch) = if case == "both" { ("setup-token", "asked") } else { (credential::CACHED, credential::CACHED) };
            assert_eq!((vm.id.as_str(), row.id.as_str(), how, delivery.source, touchid, asked.get()), (current.vm.id.as_str(), current.vm.id.as_str(), "reused", source, touch, usize::from(case == "both")), "{case}");
            let ends = rows(&plan, "session_move_end");
            assert_eq!(ends.len(), 1, "{case}: {ends:?}");
            let d = &ends[0]["detail"];
            let want = match case {
                "leave" => ("workspace", "7"),
                "arrive" => ("workspace", "9"),
                "own" => ("select", "1"),
                _ => ("gate", "5"),
            };
            assert_eq!(
                (d["outcome"].as_str(), d["kind"].as_str(), d["to_vm"].as_str(), d["step"].as_str(), d["code"].as_str(), d["touchid"].as_str(), d["request"].as_str()),
                (Some("stayed"), Some("migrate"), Some(current.vm.id.as_str()), Some(want.0), Some(want.1), Some(touch), Some("nonce-1")),
                "{case}"
            );
            let gated_on: Vec<String> = rows(&plan, "credential_gate").iter().filter_map(|r| r["detail"]["id"].as_str().map(str::to_string)).collect();
            assert!(gated_on.contains(&current.vm.id), "{case}: the old VM gated again: {gated_on:?}");
        }
    }

    /// §B: the generation a `Migrate` start moves off is the chat's own,
    /// unless no VM is prepared any more and a switch left one
    /// (`SessionPlan::left`): the pump's fallback after a switch whose new VM
    /// never started the moved CLI restarts the chat on the VM it left (taken,
    /// so once). A normal switch keeps what a switch left untouched.
    #[tokio::test]
    async fn a_switch_whose_new_vm_never_started_falls_back_to_the_vm_it_left() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, api) = gated(dir.path());
        let (left, prepared) = switching(dir.path(), &plan, &api).await;
        let on_new = Current { vm: prepared.clone(), ..left.clone() };
        *plan.left.borrow_mut() = Some(left.clone());
        let (base, fallback) = switch_base(&plan, on_new.clone());
        assert_eq!((base.vm.id.as_str(), fallback), (on_new.vm.id.as_str(), false), "a VM prepared: a switch, off the chat's own");
        assert!(plan.left.borrow().is_some(), "what a switch left stays");
        plan.prepared.borrow_mut().take();
        let (base, fallback) = switch_base(&plan, on_new.clone());
        assert_eq!((base.vm.id.as_str(), fallback), (left.vm.id.as_str(), true), "none prepared: the VM the switch left");
        assert!(plan.left.borrow().is_none(), "taken");
        let (base, fallback) = switch_base(&plan, on_new.clone());
        assert_eq!((base.vm.id.as_str(), fallback), (on_new.vm.id.as_str(), false), "once");
        plan.left.borrow_mut().replace(left);
        plan.release_prepared();
        assert!(plan.left.borrow().is_none() && plan.prepared.borrow().is_none() && !plan.moving.get(), "a migration given up keeps neither");
    }

    /// The `Gap` path (§2.7, M1): a respawn after a replay gap first stops
    /// the gapped spawn (`agent::stop_spawn`), so two claudes never share the
    /// VM's transcript. One that does not stop (here its VM's agent cannot be
    /// reached: an error, taken as `false`) moves the chat as a re-address: a
    /// new VM avoiding the old one, the move's one Touch ID asked, no
    /// respawn on the old VM. (A spawn that stops, `true`, needs a shim: the
    /// rig's open point.)
    #[tokio::test]
    async fn a_gap_whose_spawn_does_not_stop_moves_as_a_readdress() {
        let dir = tempfile::tempdir().unwrap();
        let (mut plan, api) = gated(dir.path());
        // The agent's dial goes to a loopback port nothing listens on: the stop fails at once, nothing leaves the Mac.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        plan.knobs.fake_api = Some(dir.path().join("fake.json"));
        plan.knobs.agent_addr = Some(closed.to_string());
        let (row, vm) = vm_of(&plan, &api).await;
        let path = dir.path().join("backend.json");
        std::fs::write(&path, serde_json::to_string(&crate::bridge::api::FakeState::new()).unwrap()).unwrap();
        let current = Current { backend: Rc::new(Backend::Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(&path).unwrap())), row, vm: vm.clone(), how: "started", seed: "cloned", seeded_head: None };
        let ep = Cache { fake: &api, tag: plan.token.tag.clone(), holding: vec![vm.endpoint.clone()] };
        let why = MoveWhy {
            kind: MoveKind::Respawn,
            cause: Some(LossCause::Gap),
            trigger: None,
            from_vm: vm.id.clone(),
            from_spawn: Some(crate::wire::frame::SpawnId::new_v7()),
            session_id: Some(SID.into()),
            outstanding: vec!["u1".into()],
            leaf: None,
            fresh_chat: false,
            init_answered: true,
        };
        let asked = Cell::new(0);
        let tag = plan.token.tag.clone();
        let ctx = plan.ctx();
        let progress = Progress::default();
        let t = std::time::Instant::now();
        let moved = move_vm(&plan, &ctx, &api, &ep, &current, &why, 2, &progress, || {
            asked.set(asked.get() + 1);
            async move { Ok::<_, CliError>(unsealed(&tag)) }
        })
        .await;
        let moved = moved.unwrap_or_else(|f| panic!("M1: {:?}", f.failure));
        assert!(t.elapsed() < crate::bridge::agent::STOP_SPAWN_WITHIN + Duration::from_secs(10), "the stop gave up within its bound: {:?}", t.elapsed());
        assert_ne!(moved.vm.id, vm.id, "a new VM");
        assert_eq!((moved.kind, moved.touchid, moved.token.is_some(), asked.get()), (MoveKind::Readdress, "asked", true, 1));
        let selects: Vec<serde_json::Value> = rows(&plan, "vm_select").into_iter().map(|r| r["detail"].clone()).collect();
        assert_eq!(selects.len(), 1, "{selects:?}");
        assert_eq!((selects[0]["id"].as_str(), selects[0]["choice"].as_str(), selects[0]["avoid"].as_str()), (Some(moved.vm.id.as_str()), Some("workspace"), Some(vm.id.as_str())), "never a respawn on the gapped VM");
    }

    /// Another chat of the workspace (its row names the VM it runs on).
    const OTHER: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

    /// A live process `registry::confirm_wrapper` and `owner_alive` take for
    /// a wrapper, as `tests/vm/gc.rs` makes one: `/bin/sleep` copied as
    /// `ai-env-claude` into `dir` (the judges read the executable's file name
    /// and its start; on macOS the copy is signed ad hoc, since a copied
    /// system binary is killed at its start). It only sleeps; killed and
    /// reaped on drop.
    struct LiveWrapper(std::process::Child);

    impl LiveWrapper {
        fn start(dir: &Path) -> LiveWrapper {
            let exe = dir.join(crate::bridge::registry::WRAPPER_EXE);
            std::fs::copy("/bin/sleep", &exe).unwrap();
            #[cfg(target_vendor = "apple")]
            {
                let signed = std::process::Command::new("/usr/bin/codesign").args(["--sign", "-", "--force"]).arg(&exe).output().unwrap();
                assert!(signed.status.success(), "codesign: {}", String::from_utf8_lossy(&signed.stderr));
            }
            LiveWrapper(std::process::Command::new(&exe).arg("30").stdin(std::process::Stdio::null()).spawn().unwrap())
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }

        /// The park owner it would name (`SpawnDetail.parked`): its pid and start.
        fn owner(&self) -> ParkOwner {
            let (name, started) = crate::bridge::registry::process_identity(self.pid()).expect("the stand-in's identity");
            assert_eq!(name, crate::bridge::registry::WRAPPER_EXE);
            ParkOwner { pid: self.pid(), started }
        }
    }

    impl Drop for LiveWrapper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A pid no process has now (a child that ran and was reaped).
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// A session row of `sid` on `vm`, its wrapper `pid`, written a minute
    /// from now (a live wrapper started before it is confirmed).
    fn chat_row(plan: &SessionPlan, sid: &str, vm: &str, pid: u32, spawn: Option<&SpawnId>) {
        let created = crate::wire::time::rfc3339_utc(crate::wire::time::unix_now() + 60);
        let row = crate::bridge::registry::SessionRow {
            session_id: sid.into(),
            status: "active".into(),
            mode: "remote".into(),
            route: "remote".into(),
            pid,
            created: created.clone(),
            last_seen: created,
            microvm_id: Some(vm.into()),
            spawn_id: spawn.map(ToString::to_string),
            ..crate::bridge::registry::SessionRow::default()
        };
        crate::bridge::registry::write(&plan.paths, &row).unwrap();
    }

    /// The fake's endpoint whose `/health/detail` lists `spawns`: the
    /// shim's live spawns, which the fake has no model of.
    struct Spawns<'a> {
        fake: &'a FakeMicrovmApi,
        spawns: Vec<SpawnDetail>,
    }

    impl EndpointClient for Spawns<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            if let Some(d) = reply.detail.as_mut() {
                d.spawns.clone_from(&self.spawns);
            }
            Ok(reply)
        }
    }

    /// A live spawn of `/health/detail`, parked by `parked` when given.
    fn live_spawn(id: &SpawnId, parked: Option<ParkOwner>) -> SpawnDetail {
        SpawnDetail {
            status: SpawnStatus { spawn_id: id.clone(), argv0: "claude".into(), pid: 4100, pgid: 4100, alive: true, attached: false, out_seq: 0, out_from: 1, err_seq: 0, in_seq: 0, stdin_closed: false, exit: None },
            started_at: "2026-10-20T08:00:00Z".into(),
            detach_left_s: Some(900),
            frozen: false,
            group_alive: true,
            parked,
        }
    }

    /// A plan of [`gated`] whose agent dials go to a loopback port nothing
    /// listens on (the fake API's lab knobs): every stop fails at once.
    fn unreachable_agents(dir: &Path) -> (SessionPlan, FakeMicrovmApi) {
        let (mut plan, api) = gated(dir);
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        plan.knobs.fake_api = Some(dir.join("fake.json"));
        plan.knobs.agent_addr = Some(closed.to_string());
        (plan, api)
    }

    /// The generation before the move: `row` and `vm`, its backend a file
    /// fake M1 never calls.
    fn current_of(dir: &Path, row: VmRow, vm: VmInfo) -> Current {
        let path = dir.join("backend.json");
        std::fs::write(&path, serde_json::to_string(&crate::bridge::api::FakeState::new()).unwrap()).unwrap();
        Current { backend: Rc::new(Backend::Fake(crate::bridge::vm::fake_file::FileFakeMicrovmApi::open(&path).unwrap())), row, vm, how: "started", seed: "cloned", seeded_head: None }
    }

    /// §2.7: a fresh chat's `Gap` moves as a re-address (its VM holds the
    /// dead CLI's own transcript), never through the respawn's stop; M1
    /// still stops the gapped spawn on the old VM, running, so its claude
    /// never runs the turn beside the new VM's. Here the old VM's agent is a
    /// loopback listener that accepts and closes: it is dialed (the stop
    /// fails, which is logged) and the move goes on to a new VM with its one
    /// Touch ID. A fresh chat's move off a gone VM (`VmGone`) dials nothing.
    #[tokio::test]
    async fn a_fresh_chats_gap_stops_the_gapped_spawn_on_the_old_vm() {
        for (cause, dialed) in [(LossCause::Gap, true), (LossCause::VmGone, false)] {
            let dir = tempfile::tempdir().unwrap();
            let (mut plan, api) = gated(dir.path());
            let agent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            plan.knobs.fake_api = Some(dir.path().join("fake.json"));
            plan.knobs.agent_addr = Some(agent.local_addr().unwrap().to_string());
            let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = Arc::clone(&dials);
            let listening = tokio::spawn(async move {
                while let Ok((socket, _)) = agent.accept().await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    drop(socket);
                }
            });
            let (row, vm) = vm_of(&plan, &api).await;
            if cause == LossCause::VmGone {
                api.set_state(&vm.id, VmState::Terminated);
            }
            let current = current_of(dir.path(), row, vm.clone());
            let ep = Cache { fake: &api, tag: plan.token.tag.clone(), holding: Vec::new() };
            let why = MoveWhy {
                kind: MoveKind::Readdress,
                cause: Some(cause),
                trigger: None,
                from_vm: vm.id.clone(),
                from_spawn: Some(SpawnId::new_v7()),
                session_id: Some(SID.into()),
                outstanding: vec!["u1".into()],
                leaf: None,
                fresh_chat: true,
                init_answered: true,
            };
            let asked = Cell::new(0);
            let tag = plan.token.tag.clone();
            let ctx = plan.ctx();
            let progress = Progress::default();
            let moved = move_vm(&plan, &ctx, &api, &ep, &current, &why, 2, &progress, || {
                asked.set(asked.get() + 1);
                async move { Ok::<_, CliError>(unsealed(&tag)) }
            })
            .await;
            let moved = moved.unwrap_or_else(|f| panic!("{cause:?}: {:?}", f.failure));
            assert_eq!((moved.kind, asked.get()), (MoveKind::Readdress, 1), "{cause:?}");
            assert_ne!(moved.vm.id, vm.id, "{cause:?}: a new VM");
            assert_eq!(dials.load(Ordering::SeqCst) > 0, dialed, "{cause:?}: the gapped spawn's stop on the old VM");
            listening.abort();
        }
    }

    /// §2.7: an unreachable VM another live wrapper's chat runs on (a
    /// workspace's chats share VMs) is kept: with no spawn of this chat
    /// known there, nothing to stop, and no TerminateMicrovm; the move
    /// still takes a new VM with its one Touch ID. When this chat's spawn
    /// there does not stop (here its agent cannot be reached), or no other
    /// live wrapper's row names the VM (a dead pid's, or this process's
    /// own), it is terminated as before (`readdress`), so two claudes never
    /// run one chat's turn.
    #[tokio::test]
    async fn an_unreachable_vm_other_chats_live_on_is_kept() {
        for case in ["a live other, no spawn known", "a live other, a stop that fails", "a dead other", "this process's own row"] {
            let dir = tempfile::tempdir().unwrap();
            let (plan, api) = unreachable_agents(dir.path());
            let (row, vm) = vm_of(&plan, &api).await;
            let wrapper = case.starts_with("a live").then(|| LiveWrapper::start(dir.path()));
            let pid = match (&wrapper, case) {
                (Some(w), _) => w.pid(),
                (None, "a dead other") => dead_pid(),
                (None, _) => std::process::id(),
            };
            chat_row(&plan, OTHER, &vm.id, pid, None);
            let current = current_of(dir.path(), row, vm.clone());
            let ep = Cache { fake: &api, tag: plan.token.tag.clone(), holding: Vec::new() };
            let why = MoveWhy {
                kind: MoveKind::Readdress,
                cause: Some(LossCause::Unreachable),
                trigger: None,
                from_vm: vm.id.clone(),
                from_spawn: (!case.ends_with("no spawn known")).then(SpawnId::new_v7),
                session_id: Some(SID.into()),
                outstanding: vec!["u1".into()],
                leaf: None,
                fresh_chat: false,
                init_answered: true,
            };
            let asked = Cell::new(0);
            let tag = plan.token.tag.clone();
            let ctx = plan.ctx();
            let progress = Progress::default();
            let moved = move_vm(&plan, &ctx, &api, &ep, &current, &why, 2, &progress, || {
                asked.set(asked.get() + 1);
                async move { Ok::<_, CliError>(unsealed(&tag)) }
            })
            .await;
            let moved = moved.unwrap_or_else(|f| panic!("{case}: {:?}", f.failure));
            assert_eq!((moved.kind, asked.get()), (MoveKind::Readdress, 1), "{case}");
            assert_ne!(moved.vm.id, vm.id, "{case}: a new VM");
            let kept = case == "a live other, no spawn known";
            let terminated = api.calls().iter().any(|c| matches!(c, Call::Terminate(id) if *id == vm.id));
            assert_eq!(terminated, !kept, "{case}: {:?}", api.calls());
            let old = vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("the old VM's row");
            if kept {
                assert_eq!((old.status, api.state().vms[&vm.id].state.clone()), (RowStatus::Running, VmState::Running), "{case}: kept for the other chat");
            } else {
                assert_eq!((old.status, old.terminated_by.as_deref()), (RowStatus::Terminated, Some("readdress")), "{case}");
            }
        }
    }

    /// D5 (M6): the reaper before a spawn on a VM. A `leftover` is the spawn
    /// this chat's session row names there while that row's wrapper is no
    /// live one (a dead pid): it is stopped, and one that does not stop
    /// (here its agent cannot be reached) fails the start (exit 8), audited
    /// `session_reap` `leftover` `failed`. The same row whose wrapper is a
    /// live `ai-env-claude` (the chat still runs from that wrapper) is no
    /// leftover: nothing is stopped or audited.
    #[tokio::test]
    async fn the_reaper_ends_a_dead_wrappers_leftover_never_a_live_ones() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, api) = unreachable_agents(dir.path());
        let (row, vm) = vm_of(&plan, &api).await;
        let spawn = SpawnId::new_v7();
        let ep = Spawns { fake: &api, spawns: vec![live_spawn(&spawn, None)] };
        let ctx = plan.ctx();
        let wrapper = LiveWrapper::start(dir.path());
        chat_row(&plan, SID, &vm.id, wrapper.pid(), Some(&spawn));
        reap(&plan, &ctx, &api, &ep, &row, &vm, Some(SID)).await.unwrap_or_else(|f| panic!("a live wrapper's spawn: {:?}", f.failure));
        assert!(rows(&plan, "session_reap").is_empty(), "a live wrapper's spawn is no leftover: {:?}", rows(&plan, "session_reap"));
        chat_row(&plan, SID, &vm.id, dead_pid(), Some(&spawn));
        let f = reap(&plan, &ctx, &api, &ep, &row, &vm, Some(SID)).await.expect_err("a leftover that does not stop fails the start");
        assert_eq!((f.step, f.failure.exit_code()), (StartStep::Spawn, 8));
        let reaped = rows(&plan, "session_reap");
        assert_eq!(reaped.len(), 1, "{reaped:?}");
        let d = &reaped[0]["detail"];
        assert_eq!((d["why"].as_str(), d["outcome"].as_str(), d["spawn"].as_str()), (Some("leftover"), Some("failed"), Some(spawn.to_string().as_str())));
    }

    /// D5 (M6): an `orphan` is a parked spawn whose owner is no live
    /// wrapper (a dead pid): stopped, and one that does not stop is only
    /// audited (`session_reap` `orphan` `failed`), the start goes on. A
    /// spawn a live wrapper parked (its chat idle, its wrapper open) is no
    /// orphan: nothing is stopped or audited.
    #[tokio::test]
    async fn the_reaper_ends_an_orphan_never_a_live_wrappers_park() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, api) = unreachable_agents(dir.path());
        let (row, vm) = vm_of(&plan, &api).await;
        let ctx = plan.ctx();
        let wrapper = LiveWrapper::start(dir.path());
        let parked = SpawnId::new_v7();
        let ep = Spawns { fake: &api, spawns: vec![live_spawn(&parked, Some(wrapper.owner()))] };
        reap(&plan, &ctx, &api, &ep, &row, &vm, None).await.unwrap_or_else(|f| panic!("{:?}", f.failure));
        assert!(rows(&plan, "session_reap").is_empty(), "a live wrapper's park is no orphan: {:?}", rows(&plan, "session_reap"));
        let orphan = SpawnId::new_v7();
        let ep = Spawns { fake: &api, spawns: vec![live_spawn(&orphan, Some(ParkOwner { pid: dead_pid(), started: 1 }))] };
        reap(&plan, &ctx, &api, &ep, &row, &vm, None).await.unwrap_or_else(|f| panic!("an orphan that does not stop is only audited: {:?}", f.failure));
        let reaped = rows(&plan, "session_reap");
        assert_eq!(reaped.len(), 1, "{reaped:?}");
        let d = &reaped[0]["detail"];
        assert_eq!((d["why"].as_str(), d["outcome"].as_str(), d["spawn"].as_str()), (Some("orphan"), Some("failed"), Some(orphan.to_string().as_str())));
    }

    /// §B, §2.7: the VM a migration left, once the chat runs on the new one.
    /// Another chat's spawn lives there (or its spawns cannot be read): it
    /// is kept, never synced or terminated, and loses the retire's mark
    /// (`leaving_for`): an ordinary workspace VM again, which a later select
    /// may reuse. No other spawn: terminated by `migrate`, the mark kept.
    #[tokio::test]
    async fn a_vm_another_chat_lives_on_is_kept_and_unmarked() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, api) = gated(dir.path());
        let (row, vm) = vm_of(&plan, &api).await;
        // The workspace's VM, its connector recorded, hours from its wall: one a select may reuse.
        let wall = crate::wire::time::unix_now() + 7200;
        vm_registry::write_row(&plan.paths, &VmRow { workspace: Some("/w".into()), wall_deadline: Some(wall), egress_connectors: vec![CONNECTOR.into()], ..row }).unwrap();
        let ctx = plan.ctx();
        let to = "microvm-new000001";
        let terminated = |api: &FakeMicrovmApi| api.calls().iter().any(|c| matches!(c, Call::Terminate(id) if *id == vm.id));
        for case in ["another chat's spawn lives there", "its spawns cannot be read"] {
            if case == "its spawns cannot be read" {
                api.fail_on("health_detail", BridgeError::Endpoint("no answer".into()), false);
            }
            let ep = Spawns { fake: &api, spawns: vec![live_spawn(&SpawnId::new_v7(), None)] };
            retire_old_vm(&ctx, &api, &ep, &vm.id, to, Some(SID)).await;
            assert!(!terminated(&api), "{case}: kept: {:?}", api.calls());
            let kept = vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("its row");
            assert_eq!((kept.status, kept.leaving_for, kept.leaving_since), (RowStatus::Running, None, None), "{case}: an ordinary workspace VM again");
        }
        // A later select that prefers it (the other chat's reopen) reuses it.
        let mut run = plan.run.clone();
        run.choice = Choice::Prefer(vm.id.clone());
        match run::select_vm_detailed(&api, &plan.paths, &run, ctx.poll(Poll::RUNNING)).await {
            Ok(selected @ Selected::Reused { .. }) => assert_eq!(selected.row().id, vm.id, "the VM kept"),
            Ok(_) => panic!("a new VM, not the one kept"),
            Err(f) => panic!("the select: {}", f.error),
        }
        let ep = Spawns { fake: &api, spawns: Vec::new() };
        retire_old_vm(&ctx, &api, &ep, &vm.id, to, Some(SID)).await;
        assert!(terminated(&api), "no other spawn: terminated");
        let gone = vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("its row");
        assert_eq!((gone.status, gone.terminated_by.as_deref(), gone.leaving_for.as_deref()), (RowStatus::Terminated, Some("migrate"), Some(to)));
    }

    /// C3: a pinned session (`AI_ENV_BRIDGE_VM`: its VM or nothing) never
    /// migrates: its phase A is refused before anything is asked or
    /// selected (`Precheck`, exit 9, `refused`, never asked again).
    #[tokio::test]
    async fn a_pinned_sessions_phase_a_is_refused_before_anything() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        plan.run.choice = Choice::Pin("microvm-pinned001".into());
        let paths = plan.paths.clone();
        let f = prepare_move(Rc::new(plan), MigrateTrigger::Command { nonce: "nonce-1".into() }).await.expect_err("a pinned session's phase A is refused");
        assert_eq!((f.step, f.code, f.word, f.again), (StartStep::Precheck, 9, "refused", false));
        assert!(crate::bridge::audit::read_rows(&paths.audit(), None).unwrap_or_default().is_empty(), "nothing asked, nothing selected");
    }

    /// §B, §2.8: the switch gates the prepared VM afresh (phase A's pass is
    /// long past its age) and takes the seal phase A left in its cache
    /// (`cached`); nothing is unsealed: no `credential_unseal`, whatever
    /// happens. The VM spawned is the prepared one, its seed and transcript
    /// the arrival's; the plan holds no prepared VM after it and the closing
    /// suspend is held off no more.
    #[tokio::test]
    async fn the_switch_regates_the_prepared_vm_and_never_unseals() {
        let dir = tempfile::tempdir().unwrap();
        let (plan, api) = gated(dir.path());
        let (current, prepared) = switching(dir.path(), &plan, &api).await;
        let ep = Cache { fake: &api, tag: plan.token.tag.clone(), holding: vec![current.vm.endpoint.clone(), prepared.endpoint.clone()] };
        let ctx = plan.ctx();
        let progress = Progress::default();
        let left = std::cell::Cell::new(false);
        let leave = || async {
            left.set(true);
            Ok(())
        };
        let arrive = |row: VmRow, vm: VmInfo| {
            assert_eq!(row.id, vm.id);
            async { Ok(arrived()) }
        };
        let began = crate::wire::time::unix_now();
        let why = migrating(&current.vm.id);
        let asked = Cell::new(0);
        let unseal = || {
            asked.set(asked.get() + 1);
            async { Err::<(SetupToken, String), _>(CliError::Msg("never asked".into())) }
        };
        let switched = switch_vm(&plan, &ctx, &api, &ep, &current, &why, 2, Instant::now() + MOVE_WINDOW, &progress, leave, arrive, unseal).await;
        assert_eq!(asked.get(), 0, "the switch never asks a Touch ID");
        let Ok(SwitchTo::New { row, vm, how, arrived, prepared: delivery }) = switched else { panic!("the switch fell back") };
        assert!(left.get(), "the old VM's work was taken first");
        assert_eq!((vm.id.as_str(), row.id.as_str(), how, arrived.source, arrived.transcript), (prepared.id.as_str(), prepared.id.as_str(), "started", "box", Some("restored")));
        assert_eq!(delivery.source, credential::CACHED, "the seal phase A left on the VM");
        assert!(delivery.gated_at() >= began, "a fresh gate: {} before the switch {began}", delivery.gated_at());
        let gates: Vec<String> = rows(&plan, "credential_gate").iter().filter(|r| r["detail"]["result"] == "passed").filter_map(|r| r["detail"]["id"].as_str().map(str::to_string)).collect();
        assert_eq!(gates, [prepared.id.as_str()], "the prepared VM gated, once, and no other");
        assert!(rows(&plan, "credential_unseal").is_empty(), "never an unseal");
        assert!(rows(&plan, "session_move_end").is_empty(), "the pump writes the switch's done, once its CLI resumed");
        assert!(plan.prepared.borrow().is_none() && !plan.moving.get());
    }

    /// §2.7: a reopen's carry off its `--resume` row's VM, from that row
    /// alone (P0, no AWS call): terminated, or past its wall (the platform
    /// ended it there), a re-address, migration on or off; within
    /// `migrate_before_wall_s` of its wall a migration with what is left, with
    /// migration on only; further from it, with no wall recorded or no row,
    /// none; never for another choice than the preferred VM.
    #[test]
    fn a_reopen_carries_off_a_vm_near_or_past_its_wall() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        let now = i64::try_from(crate::wire::time::unix_now()).unwrap();
        for (id, status, left) in [("microvm-gone00001", RowStatus::Terminated, Some(3000)), ("microvm-past00001", RowStatus::Suspended, Some(-5)), ("microvm-near00001", RowStatus::Suspended, Some(600)), ("microvm-far000001", RowStatus::Running, Some(5000)), ("microvm-nowall001", RowStatus::Running, None)] {
            let row = VmRow { id: id.into(), status, client_token: format!("ct-{id}"), wall_deadline: left.map(|l| u64::try_from(now + l).unwrap()), ..VmRow::default() };
            vm_registry::write_row(&plan.paths, &row).unwrap();
        }
        let carry = |plan: &SessionPlan, id: &str| carry_of(&plan.ctx(), &Choice::Prefer(id.into()));
        let gone = |id: &str| Some(Carried { from_vm: id.into(), left_s: None });
        assert_eq!(plan.cfg.vm.migrate_margin(), Some(1200), "the defaults migrate");
        assert_eq!(carry(&plan, "microvm-gone00001"), gone("microvm-gone00001"));
        assert_eq!(carry(&plan, "microvm-past00001"), gone("microvm-past00001"));
        let near = carry(&plan, "microvm-near00001").expect("a migration");
        assert!(near.from_vm == "microvm-near00001" && near.left_s.is_some_and(|l| (590..=600).contains(&l)), "{near:?}");
        for id in ["microvm-far000001", "microvm-nowall001", "microvm-norow0001"] {
            assert_eq!(carry(&plan, id), None, "{id}");
        }
        assert_eq!(carry_of(&plan.ctx(), &Choice::Workspace), None);
        assert_eq!(carry_of(&plan.ctx(), &Choice::Pin("microvm-gone00001".into())), None);
        plan.cfg.vm.migrate_before_wall_s = 0;
        assert_eq!(carry(&plan, "microvm-near00001"), None, "migration off: no carry near the wall");
        assert_eq!((carry(&plan, "microvm-gone00001"), carry(&plan, "microvm-past00001")), (gone("microvm-gone00001"), gone("microvm-past00001")), "the wall's re-address stands");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::AuthToken;
    use crate::bridge::census::CensusRow;
    use crate::bridge::route::Mode;
    use crate::bridge::vm::lock::lock_shared_blocking;
    use crate::bridge::workspace::{Head, WsKind};
    use crate::wire::argv::Route;
    use crate::wire::workspace::ObjectFormat;

    /// The documentation account's made-up egress connector.
    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    /// The chat's argv (extension 2.1.282), plus an `--add-dir`.
    const ARGS: [&str; 18] = [
        "--output-format",
        "stream-json",
        "--verbose",
        "--input-format",
        "stream-json",
        "--permission-prompt-tool",
        "stdio",
        "--setting-sources=user,project,local",
        "--permission-mode",
        "default",
        "--include-partial-messages",
        "--debug",
        "--debug-to-stderr",
        "--enable-auth-status",
        "--no-chrome",
        "--replay-user-messages",
        "--add-dir",
        "/Users/someone/elsewhere",
    ];

    /// A green world for P0, all local: bridge.toml (the fake image at 1.0,
    /// the connector, one root), a passing egress check for 1.0 and a no-dns
    /// row, the setup-token and the runtime key sealed (containers), the
    /// documentation account's transcripts bucket recorded (S9), a keystore
    /// dir, a workspace under the root.
    struct World {
        _dir: tempfile::TempDir,
        root: PathBuf,
        work: PathBuf,
        paths: Paths,
        text: String,
    }

    impl World {
        fn new(extra: &str) -> World {
            use crate::bridge::egress::{normalize_connector, EgressVerified, VerifiedRecord, DNS_NONE, DNS_RULE};
            let dir = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            let work = root.join("work");
            std::fs::create_dir_all(&work).unwrap();
            let paths = Paths::from_root_and_env(root.join("bridge"), None);
            let text = format!(
                "[aws]\nimage_arn = \"{}\"\nimage_version = \"1.0\"\negress_connector_arn = \"{CONNECTOR}\"\n[workspaces]\nroots = [{work:?}]\n{extra}",
                crate::bridge::api::FAKE_IMAGE_ARN
            );
            let at = crate::wire::time::rfc3339_utc(crate::wire::time::unix_now() - 60);
            let record = VerifiedRecord { image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(), image_version: "1.0".into(), connector: normalize_connector(CONNECTOR), at: at.clone(), dns: DNS_NONE.into(), dns_rule: DNS_RULE, egress_rule: crate::bridge::egress::EGRESS_RULE, ..VerifiedRecord::default() };
            EgressVerified { records: vec![record], ..EgressVerified::default() }.save(&paths).unwrap();
            std::fs::create_dir_all(paths.probes().parent().unwrap()).unwrap();
            std::fs::write(paths.probes(), format!("{}\n", serde_json::json!({ "probe": "dns-path", "verdict": DNS_NONE, "ts": at }))).unwrap();
            std::fs::create_dir_all(paths.credentials()).unwrap();
            // Containers of an age-shaped blob: what is sealed, never a value.
            let blob = |n: &str| format!("age-encryption.org/v1\n-> x {n}\n--- y\n");
            std::fs::write(paths.setup_token_env(), crate::container::write(blob("token").as_bytes())).unwrap();
            std::fs::write(paths.aws_env(), crate::container::write(blob("key").as_bytes())).unwrap();
            // What `make infra-status WRITE=1` records after the S9 deploy: the session's transcript sync resolves it.
            let state = crate::bridge::infra::InfraState {
                stack: "dev".into(),
                region: "eu-central-1".into(),
                account_id: Some("123456789012".into()),
                transcripts_bucket: Some("ai-env-transcripts-123456789012".into()),
                ..crate::bridge::infra::InfraState::default()
            };
            std::fs::create_dir_all(paths.infra_state().parent().unwrap()).unwrap();
            std::fs::write(paths.infra_state(), toml::to_string(&state).unwrap()).unwrap();
            std::fs::create_dir_all(root.join("keys")).unwrap();
            World { _dir: dir, root, work, paths, text }
        }

        fn session(&self, args: &[&str]) -> Session {
            let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
            let Route::Remote(session) = crate::wire::argv::classify(&args) else { panic!("not a session: {args:?}") };
            let start_row = CensusRow {
                v: 1,
                ts: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
                start: crate::wire::time::unix_now_ms(),
                pid: std::process::id(),
                ppid: 1,
                ext: None,
                route: "remote".into(),
                reason: "session".into(),
                argv: Vec::new(),
                cwd: None,
                env_names: Vec::new(),
                env_selected: BTreeMap::new(),
                note: None,
                end: None,
                exit: None,
            };
            Session {
                real_binary: "/nonexistent/claude".into(),
                args,
                route: Route::Remote(session.clone()),
                session,
                cwd: Some(self.work.clone()),
                paths: self.paths.clone(),
                cfg: Some(BridgeConfig::parse(&self.text).unwrap()),
                mode: Mode::Remote,
                start_row,
            }
        }

        /// Cursor's environment: HOME, the keystore, LANG, then `extra`.
        fn env(&self, extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
            let mut pairs: Vec<(String, OsString)> = vec![("HOME".into(), self.root.clone().into_os_string()), ("AI_ENV_DIR".into(), self.root.join("keys").into_os_string()), ("LANG".into(), "C.UTF-8".into())];
            pairs.extend(extra.iter().map(|(k, v)| ((*k).to_string(), OsString::from(v))));
            move |k: &str| pairs.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        }

        /// A VM row of the workspace (vpc, running, a session token), `edit`ed.
        fn vm_row(&self, id: &str, edit: impl FnOnce(&mut VmRow)) {
            let mut row = VmRow {
                id: id.into(),
                status: RowStatus::Running,
                client_token: uuid::Uuid::now_v7().to_string(),
                workspace: Some(self.work.display().to_string()),
                egress: "vpc".into(),
                session_token: Some("t".repeat(64)),
                ..VmRow::default()
            };
            edit(&mut row);
            vm_registry::write_row(&self.paths, &row).unwrap();
        }
    }

    /// `workspace::resolve` as W4 builds it would answer for a git repository.
    fn a_git_repo(_: &BridgeConfig, cwd: &Path, _: Option<&str>) -> Result<WorkspaceRef, BridgeError> {
        let cwd = std::fs::canonicalize(cwd)?;
        let vm = cwd.display().to_string();
        Ok(WorkspaceRef {
            root: cwd.clone(),
            vm_cwd: vm.clone(),
            vm_root: vm,
            slug: crate::wire::slug::project_dir_name(&cwd)?,
            kind: WsKind::Git { git_dir: cwd.join(".git"), common_dir: cwd.join(".git"), object_format: ObjectFormat::Sha1 },
            head: Head::Branch { name: "main".into(), sha: "b".repeat(40) },
            seed_branch: None,
            cwd,
        })
    }

    /// The prechecks pass in a green world: the VM's argv (`claude`, the
    /// debug flags and `--add-dir` gone, no `--session-mirror`: S9 keeps the
    /// transcript in S3), the environment (the allowlist and the wrapper's
    /// names), the workspace's choice and caps (S9's `transcript_s3_v1`
    /// too), T0, and the `.active` lock held for the plan's life.
    #[test]
    fn the_prechecks_plan_the_session_and_hold_the_workspace_active() {
        let w = World::new("");
        let sess = w.session(&ARGS);
        let plan = precheck_with(&sess, &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}: {}", f.word(), f.line()));
        assert_eq!(plan.argv.first().map(String::as_str), Some("claude"));
        for gone in ["--debug", "--debug-to-stderr", "--add-dir", "/Users/someone/elsewhere", "--session-mirror"] {
            assert!(!plan.argv.iter().any(|a| a == gone), "{gone} is stripped: {:?}", plan.argv);
        }
        assert!(plan.argv.iter().any(|a| a == "--replay-user-messages"), "the rest is kept");
        assert_eq!(plan.env.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!((plan.env.get("DISABLE_TELEMETRY").map(String::as_str), plan.env.get("DISABLE_ERROR_REPORTING").map(String::as_str)), (Some("1"), Some("1")));
        assert!(!plan.env.contains_key("HOME") && !plan.env.contains_key("AI_ENV_DIR"), "only the allowlist: {:?}", plan.env.keys());
        assert_eq!((plan.run.choice.clone(), plan.run.workspace_cap, plan.run.transcript_cap, plan.run.egress, plan.run.purpose), (Choice::Workspace, true, true, Egress::Vpc, "session"));
        assert_eq!(plan.run.workspace.as_ref().map(|(p, _)| p.clone()), Some(w.work.clone()));
        assert!(plan.init_deadline() > Instant::now() + Duration::from_secs(45) && plan.init_deadline() <= Instant::now() + INIT_DEADLINE);
        assert_eq!(plan.resume, None);
        let active = w.paths.workspace_active(&plan.ws.slug);
        assert!(try_lock_exclusive(&active).unwrap().is_none(), "the plan holds the workspace's .active");
        assert!(lock_shared_blocking(&active, Duration::from_millis(100)).is_ok(), "shared with every other session of the workspace");
        drop(plan);
        assert!(try_lock_exclusive(&active).unwrap().is_some(), "gone with the plan (the process)");
        let audit = crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap();
        assert!(audit.is_empty() && !w.paths.unseal_lock().exists(), "P0 wrote no audit row and asked for no Touch ID: {audit:?}");
    }

    /// Each P0 failure is its own kind, exit code and line, before any AWS
    /// call or Touch ID (P0 makes neither: no backend exists yet; nothing
    /// is audited but the gate's local refusal).
    #[test]
    fn each_precheck_failure_has_its_exit_and_its_line() {
        let refused_repo = |code: &'static str| move |_: &BridgeConfig, cwd: &Path, _: Option<&str>| -> Result<WorkspaceRef, BridgeError> {
            match code {
                workspace::code::NOT_A_GIT_REPO => Err(BridgeError::WorkspaceRefused { code, message: format!("{} is not in a git repository", cwd.display()) }),
                _ => Err(BridgeError::WorkspaceFailed { code, message: "a shallow repository: the seed cannot carry it".into() }),
            }
        };
        let check = |w: &World, env: &[(&str, &str)], resolve: Resolver<'_>| precheck_with(&w.session(&ARGS), &w.env(env), resolve).map(drop).unwrap_err();
        // D6: a workspace that is no git repository, exit 9 at once.
        let w = World::new("");
        let f = check(&w, &[], &refused_repo(workspace::code::NOT_A_GIT_REPO));
        assert_eq!((f.clone(), f.exit_code()), (Failure::NotGitRepo, 9));
        assert_eq!(f.line(), "not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally");
        let f = check(&w, &[], &refused_repo(workspace::code::UNSUPPORTED_REPO));
        assert_eq!((f.word(), f.exit_code()), ("workspace", 1), "{}", f.line());
        // bridge.toml: a [wrapper].mode nobody knows (the session fails closed), a [vm] out of range.
        for (extra, key) in [("[wrapper]\nmode = \"remotely\"\n", "[wrapper].mode"), ("[vm]\nmax_idle_s = 10\n", "[vm].max_idle_s")] {
            let f = check(&World::new(extra), &[], &a_git_repo);
            assert_eq!((f.word(), f.exit_code()), ("config", 1), "{extra}");
            assert!(f.line().contains(key) && f.line().ends_with("AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally"), "{}", f.line());
        }
        // The pin: not an id (2), no row or terminated (8), not vpc or --shell (9), an image without workspace_v1 or
        // S9's transcript_s3_v1 (7).
        let f = check(&w, &[(PIN_KNOB, "../etc/passwd")], &a_git_repo);
        assert_eq!((f.clone(), f.exit_code()), (Failure::PinInvalid, 2));
        let f = check(&w, &[(PIN_KNOB, "microvm-unknown01")], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("pin_gone", 8));
        w.vm_row("microvm-ended0001", |r| r.status = RowStatus::Terminated);
        assert_eq!(check(&w, &[(PIN_KNOB, "microvm-ended0001")], &a_git_repo).word(), "pin_gone");
        w.vm_row("microvm-open00001", |r| r.egress = "internet".into());
        w.vm_row("microvm-shell0001", |r| r.shell = true);
        for id in ["microvm-open00001", "microvm-shell0001"] {
            let f = check(&w, &[(PIN_KNOB, id)], &a_git_repo);
            assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{id}");
            assert!(f.line().contains(id) && f.line().contains(PIN_KNOB), "{}", f.line());
        }
        w.vm_row("microvm-image7001", |r| r.caps = Some(vec![crate::wire::frame::CAP_CREDENTIAL_CACHE.into()]));
        let f = check(&w, &[(PIN_KNOB, "microvm-image7001")], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("old_image", 7));
        assert!(f.line().contains("make deploy"), "{}", f.line());
        w.vm_row("microvm-image8001", |r| r.caps = Some(vec![crate::wire::frame::CAP_CREDENTIAL_CACHE.into(), CAP_WORKSPACE_V1.into()]));
        let f = check(&w, &[(PIN_KNOB, "microvm-image8001")], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("old_image", 7));
        assert!(f.line().contains("older than S9 (no transcript_s3_v1)") && f.line().contains("make deploy"), "{}", f.line());
        // A configured name the rules refuse: exit 9 naming it, never its value.
        let token = format!("{}-{}-{}", "sk", "ant", "z".repeat(30));
        let f = check(&World::new("[wrapper]\nenv_extra = [\"GITHUB_TOKEN\"]\n"), &[("GITHUB_TOKEN", &token)], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("refused", 9));
        assert!(f.line().contains("GITHUB_TOKEN") && !f.line().contains(&token), "{}", f.line());
        // No sealed token (5, naming creds setup-token), no runtime key (5, naming make runtime-key).
        let w = World::new("");
        std::fs::remove_file(w.paths.setup_token_env()).unwrap();
        let f = check(&w, &[], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("no_token", 5));
        assert!(f.line().ends_with(": run ai-env creds setup-token"), "{}", f.line());
        let w = World::new("");
        std::fs::remove_file(w.paths.aws_env()).unwrap();
        let f = check(&w, &[], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("no_runtime_key", 5));
        assert!(f.line().ends_with(": run make runtime-key"), "{}", f.line());
        // The gate's local half: no passing egress check for the image version (9).
        let w = World::new("");
        std::fs::remove_file(w.paths.root.join("state").join("egress-verified.toml")).ok();
        crate::bridge::egress::EgressVerified::default().save(&w.paths).unwrap();
        let f = check(&w, &[], &a_git_repo);
        assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{}", f.line());
        assert!(f.line().starts_with("refused before any Touch ID: no credential for a vpc VM of image version 1.0"), "{}", f.line());
        let audit = crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap();
        assert!(audit.iter().all(|r| r["event"] == "credential_gate" && r["detail"]["half"] == "local"), "only the gate's local refusal: {audit:?}");
        assert!(!w.paths.unseal_lock().exists(), "no Touch ID was asked for");
    }

    /// S9 round 5 (R2): part B's first step, S9 installed over S8's
    /// recorded egress pass, before the deploy and the new check. S8 wrote
    /// its record without `egress_rule`, so it loads as 0 (serde's default),
    /// and `state/infra.toml` records the active version: P0's provisional
    /// gate refuses every chat (exit 9, `egress_rule`, before any Touch ID).
    /// Cursor's one line keeps 160 characters of the refusal, so the reason
    /// comes right after the version, before the note on where the version
    /// came from: the line says why.
    #[test]
    fn p0_over_s8s_recorded_pass_says_why_in_cursors_line() {
        use crate::bridge::egress::EgressVerified;
        let mut w = World::new("");
        w.text = w.text.replace("image_version = \"1.0\"", "image_version = \"active\"");
        let s9 = std::fs::read_to_string(w.paths.egress_verified()).unwrap();
        let s8: String = s9.lines().filter(|l| !l.starts_with("egress_rule")).map(|l| format!("{l}\n")).collect();
        assert_ne!(s8, s9, "S9 writes the field; S8 did not");
        std::fs::write(w.paths.egress_verified(), s8).unwrap();
        assert_eq!(EgressVerified::load(&w.paths).unwrap().records[0].egress_rule, 0, "S8's record loads as rule 0");
        let state = crate::bridge::infra::InfraState {
            stack: "dev".into(),
            region: "eu-central-1".into(),
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            latest_active_image_version: Some("1.0".into()),
            account_id: Some("123456789012".into()),
            transcripts_bucket: Some("ai-env-transcripts-123456789012".into()),
            ..crate::bridge::infra::InfraState::default()
        };
        std::fs::write(w.paths.infra_state(), toml::to_string(&state).unwrap()).unwrap();
        let f = precheck_with(&w.session(&ARGS), &w.env(&[]), &a_git_repo).map(drop).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{}", f.line());
        let line = f.line();
        let why = "refused before any Touch ID: no credential for a vpc VM of image version 1.0: the recorded `ai-env egress check` passed by an earlier rule, before the transcript store's cases";
        assert!(line.starts_with(why) && line.ends_with('\u{2026}'), "the reason within the cut: {line}");
        let audit = crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap();
        let gate: Vec<_> = audit.iter().filter(|r| r["event"] == "credential_gate").map(|r| ["condition", "half", "image_version"].map(|k| r["detail"][k].as_str().unwrap_or_default().to_string())).collect();
        assert_eq!(gate, [["egress_rule", "local", "1.0"].map(str::to_string)], "{audit:?}");
        assert!(!w.paths.unseal_lock().exists(), "no Touch ID was asked for");
    }

    /// A session the wrapper routed on a bridge.toml that does not load (no
    /// `cfg`, `route::decide_loaded`) fails P0 with exit 1 and the load
    /// error's first line (no TOML snippet), then the kill switch; a file
    /// gone since the wrapper read it still fails closed.
    #[test]
    fn a_bridge_toml_that_does_not_load_fails_p0_with_its_first_line() {
        let w = World::new("");
        let mut sess = w.session(&ARGS);
        sess.cfg = None;
        std::fs::create_dir_all(&w.paths.root).unwrap();
        std::fs::write(&w.paths.config, format!("{}[vm]\nmax_idle = 300\n", w.text)).unwrap();
        let f = precheck_with(&sess, &w.env(&[]), &a_git_repo).map(drop).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("config", 1));
        let error = BridgeConfig::load(&w.paths).unwrap_err().to_string();
        assert_eq!(f.line(), format!("{}; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally", error.lines().next().unwrap_or_default()));
        assert!(f.line().starts_with("config: bridge.toml: TOML parse error at line ") && !f.line().contains("max_idle"), "{}", f.line());
        std::fs::remove_file(&w.paths.config).unwrap();
        let f = precheck_with(&sess, &w.env(&[]), &a_git_repo).map(drop).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("config", 1));
        assert!(f.line().ends_with("bridge.toml could not be read; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally"), "{}", f.line());
        assert!(crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap().is_empty() && !w.paths.unseal_lock().exists(), "nothing audited, no Touch ID");
    }

    /// The `Choice` P0 makes: the pin when set (a usable row), else a
    /// `--resume`'s VM from its registry row, else the workspace's.
    #[test]
    fn the_choice_is_the_pin_then_the_resumed_sessions_vm_then_the_workspaces() {
        let w = World::new("");
        w.vm_row("microvm-pinned001", |r| r.caps = Some(vec![CAP_WORKSPACE_V1.into(), crate::wire::frame::CAP_TRANSCRIPT_S3_V1.into()]));
        let plan = precheck_with(&w.session(&ARGS), &w.env(&[(PIN_KNOB, "microvm-pinned001")]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert_eq!(plan.run.choice, Choice::Pin("microvm-pinned001".into()));
        drop(plan);
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let row = crate::bridge::registry::SessionRow { session_id: sid.into(), microvm_id: Some("microvm-session01".into()), slug: Some("-elsewhere".into()), ..Default::default() };
        crate::bridge::registry::write(&w.paths, &row).unwrap();
        let args: Vec<&str> = ARGS.iter().copied().chain(["--resume", sid]).collect();
        let plan = precheck_with(&w.session(&args), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert_eq!((plan.run.choice.clone(), plan.resume.as_deref()), (Choice::Prefer("microvm-session01".into()), Some(sid)));
        assert_eq!(plan.slugs, [plan.ws.slug.clone(), "-elsewhere".into()], "the transcript is looked for under the cwd's slug, then the row's");
        assert_eq!(plan.mac_projects, Some(w.root.join(".claude").join("projects")));
        assert!(plan.argv.windows(2).any(|p| p == ["--resume", sid]), "the resume is the CLI's to do");
        drop(plan);
        let other = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
        let args: Vec<&str> = ARGS.iter().copied().chain(["--resume", other]).collect();
        assert_eq!(precheck_with(&w.session(&args), &w.env(&[]), &a_git_repo).unwrap().run.choice, Choice::Workspace, "no row: the workspace's");
    }

    /// S9 (review CUT-2): P0 builds the session's transcript sync, before any
    /// Touch ID, for every session that keeps a transcript or resumes one:
    /// the code-out trigger's sync after each turn and a `--resume`'s
    /// restore both take it. With the mirror gone a chat without it would
    /// reach neither S3 nor Cursor's picker, so such a session never starts:
    /// exit 1 naming `[transcript].view_messages` (which `BridgeConfig::parse`
    /// takes as it is), `make infra-status WRITE=1` (no transcripts bucket
    /// recorded) or the missing projects directory. `--no-session-persistence`
    /// alone keeps no transcript and needs none; resumed, it restores one.
    #[test]
    fn a_session_that_cannot_sync_its_transcript_never_starts() {
        let untouched = |w: &World| crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap().is_empty() && !w.paths.unseal_lock().exists();
        let refused = |w: &World, args: &[&str], env: &[(&str, &str)]| {
            let f = precheck_with(&w.session(args), &w.env(env), &a_git_repo).map(drop).unwrap_err();
            assert_eq!((f.word(), f.exit_code()), ("config", 1), "{}", f.line());
            assert!(f.line().ends_with("; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally"), "{}", f.line());
            assert!(untouched(w), "nothing audited, no Touch ID");
            f.line()
        };
        let w = World::new("[transcript]\nview_messages = 0\n");
        let line = refused(&w, &ARGS, &[]);
        assert!(line.starts_with("config: [transcript].view_messages = 0 is outside 1..="), "{line}");
        // Before the S9 deploy and `make infra-status WRITE=1`: no transcripts bucket recorded.
        let w = World::new("");
        std::fs::remove_file(w.paths.infra_state()).unwrap();
        let line = refused(&w, &ARGS, &[]);
        assert!(line.contains("infra.toml not found: make infra-status WRITE=1"), "{line}");
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let quiet: Vec<&str> = ARGS.iter().copied().chain(["--no-session-persistence"]).collect();
        let plan = precheck_with(&w.session(&quiet), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert!(plan.transcript_sync.is_none() && session_sync(&plan).is_none(), "a query that keeps no transcript needs no sync");
        drop(plan);
        let quiet_resume: Vec<&str> = quiet.iter().copied().chain(["--resume", sid]).collect();
        assert!(refused(&w, &quiet_resume, &[]).contains("make infra-status WRITE=1"), "resumed, it restores a transcript");
        // No projects directory for the view: neither CLAUDE_CONFIG_DIR nor HOME.
        let w = World::new("");
        assert!(refused(&w, &ARGS, &[("HOME", "")]).contains("neither CLAUDE_CONFIG_DIR nor HOME is set"));
        // A green world: the recorded bucket and its owner, the view under ~/.claude/projects.
        let plan = precheck_with(&w.session(&ARGS), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        let sync = session_sync(&plan).expect("the trigger's sync");
        assert_eq!((sync.target.bucket.as_str(), sync.target.owner.as_str()), ("ai-env-transcripts-123456789012", "123456789012"));
        assert_eq!((sync.mac_projects, sync.view_messages), (w.root.join(".claude").join("projects"), crate::wire::view::VIEW_MESSAGES_DEFAULT));
        drop(plan);
        let plan = precheck_with(&w.session(&quiet_resume), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert!(plan.transcript_sync.is_some() && session_sync(&plan).is_none(), "the restore's sync, none after each turn");
        drop(plan);
        assert!(untouched(&w), "nothing audited, no Touch ID");
    }

    /// S9 (review CUT-4): P0 itself refuses a `--resume` of a chat S3 does
    /// not hold whose copy on this Mac is over what a reopen carries inline
    /// (`wire::s3::INLINE_MAX`), before any Touch ID: exit 9 naming `ai-env
    /// session stage` for a chat begun here (it would otherwise fail at P3,
    /// after the Touch ID and a VM start). At the cap it passes: P3 sends it
    /// up inline.
    #[test]
    fn p0_refuses_an_unstaged_chat_over_what_a_reopen_carries_inline() {
        let w = World::new("");
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let dir = w.root.join(".claude").join("projects").join(crate::wire::slug::project_dir_name(&w.work).unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        // Sparse: P0 reads the files' sizes only.
        let chat = std::fs::File::create(dir.join(format!("{sid}.jsonl"))).unwrap();
        std::io::Write::write_all(&mut &chat, b"{\"type\":\"user\"}\n").unwrap();
        let max = crate::wire::s3::INLINE_MAX;
        chat.set_len(max + 1).unwrap();
        let resume = format!("--resume={sid}");
        let args: Vec<&str> = ARGS.iter().copied().chain([resume.as_str()]).collect();
        let f = precheck_with(&w.session(&args), &w.env(&[]), &a_git_repo).map(drop).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("transcript_too_large", 9), "{}", f.line());
        assert!(f.line().contains(&format!("run ai-env session stage {sid} --warm in a terminal")), "{}", f.line());
        assert!(crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap().is_empty() && !w.paths.unseal_lock().exists(), "nothing audited, no Touch ID");
        chat.set_len(max).unwrap();
        let plan = precheck_with(&w.session(&args), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert_eq!(plan.resume.as_deref(), Some(sid), "at the cap: P3 sends it up inline");
    }

    /// A manifest of `sid` under `w`'s bridge (a chat begun on a VM): S3
    /// holds parts of `lens` bytes (generation 1's base, then segments),
    /// committed their sum. Only the sizes are true: nothing is in any S3.
    fn manifest_in_s3(w: &World, sid: &str, lens: &[u64]) {
        use crate::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_VM};
        use crate::wire::s3::S3Key;
        let target = crate::bridge::s3::S3Target { bucket: crate::bridge::s3::LAB_BUCKET.into(), owner: crate::bridge::s3::LAB_OWNER.into(), endpoint: crate::bridge::s3::S3Endpoint::Aws };
        let mut m = Manifest::new(sid, &target, ORIGIN_VM, &format!("-w/{sid}.jsonl"), "2026-10-18T10:15:30.000Z");
        let mut from = 0;
        for (i, len) in lens.iter().enumerate() {
            let key = if i == 0 { S3Key::Base { session: sid.into(), gen: 1 } } else { S3Key::Segment { session: sid.into(), gen: 1, offset: from } };
            m.parts.push(ManifestPart { key: key.render(), version_id: format!("fv{}", i + 1), from, len: *len, sha256: "a".repeat(64) });
            from += len;
        }
        (m.gen, m.committed, m.fp) = (1, from, "b".repeat(64));
        manifest::write(&w.paths, &m).unwrap();
    }

    /// S9 R5-AWS-1, P0's half of the reopen's pull cap: a `--resume` of a
    /// chat S3 holds whose committed parts alone are over what a reopen
    /// pulls inline (`wire::s3::INLINE_MAX`) is refused before any Touch ID
    /// when no VM P2 could take can hold them: no pin, and no VM row of the
    /// workspace anything but terminated (one of another workspace is never
    /// P2's), or `[vm].reuse_per_workspace` off whatever the rows (P2 starts
    /// a new VM: the line asks for the switch first). Exit 9, the line
    /// naming `ai-env session stage UUID --warm`, nothing audited, no
    /// unseal. Parts at the cap, a row of the workspace that may be alive
    /// (running, suspended, pending, unknown: a VM `session stage --warm`
    /// restored it into) with reuse on, or a pin leave it to P3, which reads
    /// the VM's copy and the tail.
    #[test]
    fn p0_refuses_a_chat_in_s3_over_what_a_reopen_pulls_when_no_vm_can_hold_it() {
        let w = World::new("");
        let untouched = |w: &World| crate::bridge::audit::read_rows(&w.paths.audit(), None).unwrap().is_empty() && !w.paths.unseal_lock().exists();
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let max = crate::wire::s3::INLINE_MAX;
        let resume = format!("--resume={sid}");
        let args: Vec<&str> = ARGS.iter().copied().chain([resume.as_str()]).collect();
        let check = |env: &[(&str, &str)]| precheck_with(&w.session(&args), &w.env(env), &a_git_repo).map(drop);
        manifest_in_s3(&w, sid, &[70 << 20]);
        let f = check(&[]).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("transcript_pull_too_large", 9), "{}", f.line());
        assert_eq!(f.line(), format!("the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline: run ai-env session stage {sid} --warm in a terminal, then reopen the chat"));
        assert!(untouched(&w), "nothing audited, no Touch ID");
        // The parts in all, one past the cap; a VM of the workspace that ended, one of another workspace alive.
        manifest_in_s3(&w, sid, &[max - 10, 11]);
        w.vm_row("microvm-ended0001", |r| r.status = RowStatus::Terminated);
        w.vm_row("microvm-other0001", |r| r.workspace = Some("/Users/someone/elsewhere".into()));
        assert_eq!(check(&[]).unwrap_err().word(), "transcript_pull_too_large");
        // At the cap: P3 pulls it.
        manifest_in_s3(&w, sid, &[max - 10, 10]);
        check(&[]).unwrap_or_else(|f| panic!("at the cap: {}", f.line()));
        // A VM of the workspace that may hold it: P3 decides.
        manifest_in_s3(&w, sid, &[max + 1]);
        for status in [RowStatus::Running, RowStatus::Suspended, RowStatus::Pending, RowStatus::Unknown] {
            w.vm_row("microvm-alive0001", |r| r.status = status);
            check(&[]).unwrap_or_else(|f| panic!("{status:?}: {}", f.line()));
        }
        w.vm_row("microvm-alive0001", |r| r.status = RowStatus::Terminated);
        assert_eq!(check(&[]).unwrap_err().word(), "transcript_pull_too_large", "every row of the workspace ended");
        // A pinned VM may hold it.
        w.vm_row("microvm-pinned001", |r| {
            r.workspace = Some("/Users/someone/elsewhere".into());
            r.caps = Some(vec![CAP_WORKSPACE_V1.into(), crate::wire::frame::CAP_TRANSCRIPT_S3_V1.into()]);
        });
        check(&[(PIN_KNOB, "microvm-pinned001")]).unwrap_or_else(|f| panic!("pinned: {}", f.line()));
        assert!(untouched(&w), "nothing audited, no Touch ID");
        // Reuse off: P2 starts a new VM though one of the workspace runs, so the refusal is certain.
        let off = World::new("[vm]\nreuse_per_workspace = false\n");
        let check = |env: &[(&str, &str)]| precheck_with(&off.session(&args), &off.env(env), &a_git_repo).map(drop);
        manifest_in_s3(&off, sid, &[70 << 20]);
        off.vm_row("microvm-alive0001", |r| r.caps = Some(vec![CAP_WORKSPACE_V1.into(), crate::wire::frame::CAP_TRANSCRIPT_S3_V1.into()]));
        let f = check(&[]).unwrap_err();
        assert_eq!((f.word(), f.exit_code()), ("transcript_pull_too_large", 9), "{}", f.line());
        assert_eq!(f.line(), format!("the chat's transcript in S3 is 70.0 MiB, over the 64 MiB a reopen pulls inline, and [vm] reuse_per_workspace is off: set it to true, run ai-env session stage {sid} --warm in a terminal, then reopen the chat"));
        assert!(untouched(&off), "nothing audited, no Touch ID");
        // A pinned VM is taken whatever the switch says: P3 decides.
        check(&[(PIN_KNOB, "microvm-alive0001")]).unwrap_or_else(|f| panic!("pinned, reuse off: {}", f.line()));
        manifest_in_s3(&off, sid, &[max - 10, 10]);
        check(&[]).unwrap_or_else(|f| panic!("at the cap, reuse off: {}", f.line()));
        assert!(untouched(&off), "nothing audited, no Touch ID");
    }

    /// P0's order where it decides an outcome (the docs fixer's reading of
    /// [`precheck_with`]): the size refusals come last, so a reopen of a
    /// chat over a cap that an earlier check refuses gets that check's exit
    /// and line. Over S9's two caps (a chat S3 holds, over what a reopen
    /// pulls inline with no VM to hold it; a chat begun here, over what it
    /// carries inline), each in turn: the pin (`choice_of`, 2), the
    /// workspace (`resolve`, 9), the sealed token (5), the runtime key (5),
    /// the gate's local half (9: it wins over the size refusal), the VM's
    /// argv over its cap (9), a refused environment name (9), the transcript
    /// sync (1); with every one of them green, the size refusal.
    #[test]
    fn p0s_earlier_checks_win_over_its_size_refusals() {
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let resume = format!("--resume={sid}");
        let args: Vec<&str> = ARGS.iter().copied().chain([resume.as_str()]).collect();
        let token = format!("{}-{}-{}", "sk", "ant", "z".repeat(30));
        let not_a_repo = |_: &BridgeConfig, cwd: &Path, _: Option<&str>| -> Result<WorkspaceRef, BridgeError> { Err(BridgeError::WorkspaceRefused { code: workspace::code::NOT_A_GIT_REPO, message: format!("{} is not in a git repository", cwd.display()) }) };
        for in_s3 in [true, false] {
            let size_word = if in_s3 { "transcript_pull_too_large" } else { "transcript_too_large" };
            let big = |w: &World| {
                if in_s3 {
                    manifest_in_s3(w, sid, &[70 << 20]);
                } else {
                    let dir = w.root.join(".claude").join("projects").join(crate::wire::slug::project_dir_name(&w.work).unwrap());
                    std::fs::create_dir_all(&dir).unwrap();
                    let chat = std::fs::File::create(dir.join(format!("{sid}.jsonl"))).unwrap();
                    std::io::Write::write_all(&mut &chat, b"{\"type\":\"user\"}\n").unwrap();
                    chat.set_len(70 << 20).unwrap();
                }
            };
            let refusal = |extra: &str, env: &[(&str, &str)], resolve: Resolver<'_>, setup: &dyn Fn(&World)| {
                let w = World::new(extra);
                big(&w);
                setup(&w);
                let f = precheck_with(&w.session(&args), &w.env(env), resolve).map(drop).unwrap_err();
                assert!(!w.paths.unseal_lock().exists(), "no Touch ID was asked for");
                f
            };
            let none = |_: &World| {};
            let f = refusal("", &[(PIN_KNOB, "not a vm")], &a_git_repo, &none);
            assert_eq!((f.word(), f.exit_code()), ("pin_invalid", 2), "{size_word}");
            let f = refusal("", &[], &not_a_repo, &none);
            assert_eq!((f.word(), f.exit_code()), ("not_git_repo", 9), "{size_word}");
            let f = refusal("", &[], &a_git_repo, &|w| std::fs::remove_file(w.paths.setup_token_env()).unwrap());
            assert_eq!((f.word(), f.exit_code()), ("no_token", 5), "{size_word}");
            let f = refusal("", &[], &a_git_repo, &|w| std::fs::remove_file(w.paths.aws_env()).unwrap());
            assert_eq!((f.word(), f.exit_code()), ("no_runtime_key", 5), "{size_word}");
            let f = refusal("", &[], &a_git_repo, &|w| crate::bridge::egress::EgressVerified::default().save(&w.paths).unwrap());
            assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{size_word}: {}", f.line());
            assert!(f.line().starts_with("refused before any Touch ID: no credential for a vpc VM of image version 1.0"), "the gate's refusal wins over the size refusal: {}", f.line());
            let w = World::new("");
            big(&w);
            let huge = "x".repeat(ARGV_MAX_BYTES);
            let long: Vec<&str> = args.iter().copied().chain(["--append-system-prompt", huge.as_str()]).collect();
            let f = precheck_with(&w.session(&long), &w.env(&[]), &a_git_repo).map(drop).unwrap_err();
            assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{size_word}");
            assert!(f.line().contains("the session's arguments are"), "the VM's argv over its cap: {}", f.line());
            let f = refusal("[wrapper]\nenv_extra = [\"GITHUB_TOKEN\"]\n", &[("GITHUB_TOKEN", &token)], &a_git_repo, &none);
            assert_eq!((f.word(), f.exit_code()), ("refused", 9), "{size_word}");
            assert!(f.line().contains("GITHUB_TOKEN"), "{}", f.line());
            let f = refusal("", &[], &a_git_repo, &|w| std::fs::remove_file(w.paths.infra_state()).unwrap());
            assert_eq!((f.word(), f.exit_code()), ("config", 1), "{size_word}: {}", f.line());
            assert!(f.line().contains("make infra-status WRITE=1"), "{}", f.line());
            let f = refusal("", &[], &a_git_repo, &none);
            assert_eq!((f.word(), f.exit_code()), (size_word, 9), "{}", f.line());
        }
    }

    /// L2: the closing suspend fires only with `suspend_on_close`, alone on
    /// the workspace, with no live spawn on the VM and no retry under way.
    #[test]
    fn the_closing_suspend_needs_the_switch_solitude_and_no_live_spawn() {
        assert_eq!(suspend_verdict(true, true, Some(0), false), Ok(()));
        assert!(suspend_verdict(false, true, Some(0), false).is_err(), "suspend_on_close off");
        assert!(suspend_verdict(true, false, Some(0), false).is_err(), "another wrapper or vm warm holds .active");
        assert!(suspend_verdict(true, true, Some(1), false).is_err(), "a spawn lives (the config probe)");
        assert!(suspend_verdict(true, true, None, false).is_err(), "the spawns could not be read");
        assert!(suspend_verdict(true, true, Some(0), true).is_err(), "a retry respawns on the VM");
    }

    /// A running VM of the fake API for the closing suspend, its row
    /// written under `plan`'s paths (vpc, its session token, its endpoint).
    async fn closing_vm(plan: &SessionPlan, api: &crate::bridge::api::FakeMicrovmApi) -> (VmRow, VmInfo) {
        use crate::bridge::api::{IdleSpec, RunSpec, FAKE_IMAGE_ARN};
        let token = crate::bridge::vm::run::new_session_token();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: crate::bridge::vm::run::build_payload(&token, "mike@mbp", "2026-10-12T08:00:00Z").unwrap(),
            client_token: uuid::Uuid::now_v7().to_string(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let vm = api.get(&vm.id).await.unwrap();
        let row = VmRow { id: vm.id.clone(), status: RowStatus::Running, client_token: spec.client_token.clone(), session_token: Some(token.expose().clone()), endpoint: Some(vm.endpoint.clone()), egress: "vpc".into(), ..VmRow::default() };
        vm_registry::write_row(&plan.paths, &row).unwrap();
        (row, vm)
    }

    /// The SuspendMicrovm calls the fake API took.
    fn suspends(api: &crate::bridge::api::FakeMicrovmApi) -> usize {
        api.state().calls.iter().filter(|c| matches!(c, crate::bridge::api::Call::Suspend { .. })).count()
    }

    /// A code-out trigger of `plan`'s workspace on a data plane no call
    /// reaches: a fetch fails once it has the workspace's fetch lock (the
    /// workspace does not exist).
    fn trigger_of(plan: &SessionPlan) -> CodeoutTrigger {
        let target = AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: crate::wire::redact::Secret::new("t".into()), vpc: true, shell: false };
        let (api, dp, tokens) = (Arc::new(crate::bridge::api::FakeMicrovmApi::new()), Arc::new(crate::bridge::dataplane::Unreached), Arc::new(crate::bridge::dataplane::Unreached));
        CodeoutTrigger::spawn(CodeoutCtx { api, dp, tokens, paths: plan.paths.clone(), cfg: Arc::new(plan.cfg.clone()), target, ws: plan.ws.clone(), capture_settings: false, transcript: None })
    }

    /// The watch of a trigger closed with nothing run: done.
    async fn done_watch(plan: &SessionPlan) -> TriggerWatch {
        let trigger = trigger_of(plan);
        let watch = trigger.watch();
        let _ = trigger.close(crate::bridge::codeout::CLOSE_WAIT).await;
        watch
    }

    /// The closing suspend on the fake API: fired (not waited for) when this
    /// session was alone, kept when another holder of the workspace's
    /// `.active` lives, or a retry started. Whatever it decided, the plan
    /// holds its `.active` shared again afterwards: a resume miss's retry
    /// (generation 2, after generation 1's close) runs under it.
    #[tokio::test]
    async fn the_closing_suspend_fires_alone_and_keeps_the_vm_for_another_session() {
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let (row, vm) = closing_vm(&plan, &api).await;
        let ctx = plan.ctx();
        let done = done_watch(&plan).await;
        let active = plan.paths.workspace_active(&plan.ws.slug);
        // Another session of the workspace holds .active: nothing, and the plan's hold is back.
        *plan.active.borrow_mut() = Some(lock_shared_blocking(&active, Duration::from_millis(100)).unwrap());
        let other = lock_shared_blocking(&active, Duration::from_millis(100)).unwrap();
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &done).await;
        assert_eq!(suspends(&api), 0, "another session keeps the VM");
        drop(other);
        assert!(plan.active.borrow().is_some() && try_lock_exclusive(&active).unwrap().is_none(), "the plan holds its .active again");
        // Generation 1 closes while its retry runs: nothing, and the retry keeps the plan's hold.
        plan.started.set(2);
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &done).await;
        assert_eq!(suspends(&api), 0, "the retry keeps the VM");
        assert!(try_lock_exclusive(&active).unwrap().is_none(), "nobody takes the workspace alone under the retry");
        // Alone, nothing alive: fired once, audited; the hold is shared again.
        suspend_on_close(&plan, 2, &ctx, &api, &api, &row, &vm, &done).await;
        assert_eq!(suspends(&api), 1);
        let rows = crate::bridge::audit::read_rows(&plan.paths.audit(), None).unwrap();
        assert!(rows.iter().any(|r| r["event"] == "vm_suspend" && r["detail"]["by"] == "close" && r["detail"]["id"] == vm.id.as_str()), "{rows:?}");
        assert!(plan.active.borrow().is_some() && try_lock_exclusive(&active).unwrap().is_none(), "the closing hold, shared");
        assert!(lock_shared_blocking(&active, Duration::from_millis(100)).is_ok(), "shared with every other session");
        drop(plan.active.borrow_mut().take());
        assert!(try_lock_exclusive(&active).unwrap().is_some(), "the plan's was the only hold");
    }

    /// S7 D3: the `/suspend` hook empties the VM's credential cache, so a
    /// closing suspend that fired leaves the VM's row saying suspended (the
    /// prewarm's `token_held` reads it), its credential record kept (`creds
    /// status` lists the VM until it is terminated); one kept for another
    /// session leaves the row running.
    #[tokio::test]
    async fn the_closing_suspend_marks_the_row_suspended_and_keeps_its_credential_record() {
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let (row, vm) = closing_vm(&plan, &api).await;
        let seal = "seal0123456789ab";
        vm_registry::update_row(&plan.paths, &vm.id, |r| {
            r.credential_at = Some(1);
            r.credential_tag = Some(seal.into());
        })
        .unwrap();
        let ctx = plan.ctx();
        let done = done_watch(&plan).await;
        let active = plan.paths.workspace_active(&plan.ws.slug);
        *plan.active.borrow_mut() = Some(lock_shared_blocking(&active, Duration::from_millis(100)).unwrap());
        let row_now = || vm_registry::read_row(&plan.paths, &vm.id).unwrap().expect("the VM's row");
        let other = lock_shared_blocking(&active, Duration::from_millis(100)).unwrap();
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &done).await;
        assert_eq!((suspends(&api), row_now().status), (0, RowStatus::Running), "kept for another session");
        drop(other);
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &done).await;
        let after = row_now();
        assert_eq!((suspends(&api), after.status), (1, RowStatus::Suspended), "fired: its cache is empty");
        assert_eq!((after.credential_at, after.credential_tag.as_deref()), (Some(1), Some(seal)), "the VM may hold the token until it is terminated");
    }

    /// The fake API's endpoint whose `/health/detail` answers after
    /// `delay`, noting whether another session could take the workspace's
    /// `.active` shared (its P0) while the closing suspend read it.
    struct SlowDetail<'a> {
        fake: &'a crate::bridge::api::FakeMicrovmApi,
        delay: Duration,
        active: PathBuf,
        shared_meanwhile: std::sync::Mutex<Option<bool>>,
    }

    impl EndpointClient for SlowDetail<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<crate::bridge::api::HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<crate::bridge::api::HealthDetailReply, BridgeError> {
            let shared = try_lock_shared(&self.active).unwrap().is_some();
            *self.shared_meanwhile.lock().unwrap() = Some(shared);
            tokio::time::sleep(self.delay).await;
            self.fake.get_health_detail(endpoint, token, bearer).await
        }
    }

    /// L2's bound: the VM's spawns are read before the workspace is taken
    /// alone, so a session that starts meanwhile takes `.active` shared at
    /// once (its generation 1's start never waits on a closing read); a read
    /// that outlasts the closing's bound is a miss (nothing fired) and ends
    /// the close at that bound, which the wait of generation 1's start
    /// outlasts.
    #[tokio::test]
    async fn the_closing_suspend_reads_the_spawns_before_taking_the_workspace_alone_and_ends_within_its_bound() {
        const { assert!(CLOSING_BOUND.as_millis() < ACTIVE_WAIT.as_millis(), "generation 1's start outwaits a closing session's exclusive hold") };
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let (row, vm) = closing_vm(&plan, &api).await;
        let ctx = plan.ctx();
        let done = done_watch(&plan).await;
        let active = plan.paths.workspace_active(&plan.ws.slug);
        *plan.active.borrow_mut() = Some(lock_shared_blocking(&active, Duration::from_millis(100)).unwrap());
        let stuck = SlowDetail { fake: &api, delay: CLOSING_BOUND * 2, active: active.clone(), shared_meanwhile: std::sync::Mutex::new(None) };
        let t = std::time::Instant::now();
        suspend_on_close(&plan, 1, &ctx, &api, &stuck, &row, &vm, &done).await;
        let took = t.elapsed();
        assert!(took >= CLOSING_BOUND - Duration::from_millis(100) && took < CLOSING_BOUND + Duration::from_secs(1), "the close ends at its bound: {took:?}");
        assert_eq!(suspends(&api), 0, "spawns unread: nothing fired");
        assert_eq!(*stuck.shared_meanwhile.lock().unwrap(), Some(true), "another session's P0 took .active during the read");
        assert!(try_lock_exclusive(&active).unwrap().is_none(), "the plan kept its hold");
        let slow = SlowDetail { fake: &api, delay: Duration::from_millis(200), active: active.clone(), shared_meanwhile: std::sync::Mutex::new(None) };
        suspend_on_close(&plan, 1, &ctx, &api, &slow, &row, &vm, &done).await;
        assert_eq!(suspends(&api), 1, "read within the bound, alone: fired");
        assert_eq!(*slow.shared_meanwhile.lock().unwrap(), Some(true));
        assert!(plan.active.borrow().is_some(), "the hold, shared again");
    }

    /// The fake API's endpoint whose `/health/detail` also lists one more
    /// spawn: its leader alive, or dead with its group living on (S7 D6).
    struct LiveDetail<'a> {
        fake: &'a crate::bridge::api::FakeMicrovmApi,
        leader_alive: bool,
    }

    impl EndpointClient for LiveDetail<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<crate::bridge::api::HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<crate::bridge::api::HealthDetailReply, BridgeError> {
            use crate::wire::frame::{SpawnDetail, SpawnStatus};
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            let status = SpawnStatus {
                spawn_id: SpawnId::new_v7(),
                argv0: "claude".into(),
                pid: 4242,
                pgid: 4242,
                alive: self.leader_alive,
                attached: false,
                out_seq: 0,
                out_from: 1,
                err_seq: 0,
                in_seq: 0,
                stdin_closed: false,
                exit: None,
            };
            if let Some(d) = reply.detail.as_mut() {
                d.spawns.push(SpawnDetail { status, started_at: "2026-10-12T08:00:00Z".into(), detach_left_s: Some(900), frozen: false, group_alive: !self.leader_alive, parked: None });
            }
            Ok(reply)
        }
    }

    /// L2's second condition, the read itself (phase 4, FIDELITY-1): a spawn
    /// that holds no `.active` (a `vm exec`, a CLI detached in its grace)
    /// keeps the VM from a closing session alone on the workspace, whether
    /// its leader lives or only its group does; with none, the suspend fires.
    /// The rig reaches a live leader end to end (tests/remote_pump.rs), never
    /// a group that outlives its leader: the shim kills that within
    /// `GROUP_KILL_AFTER` (1 s).
    #[tokio::test]
    async fn the_closing_suspend_keeps_a_vm_with_a_live_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let (row, vm) = closing_vm(&plan, &api).await;
        let ctx = plan.ctx();
        let done = done_watch(&plan).await;
        let active = plan.paths.workspace_active(&plan.ws.slug);
        *plan.active.borrow_mut() = Some(lock_shared_blocking(&active, Duration::from_millis(100)).unwrap());
        for leader_alive in [true, false] {
            suspend_on_close(&plan, 1, &ctx, &api, &LiveDetail { fake: &api, leader_alive }, &row, &vm, &done).await;
            assert_eq!(suspends(&api), 0, "a spawn lives on the VM (its leader alive: {leader_alive}): no suspend");
            assert!(plan.active.borrow().is_some() && try_lock_exclusive(&active).unwrap().is_none(), "the plan keeps its hold");
        }
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &done).await;
        assert_eq!(suspends(&api), 1, "no other spawn: fired");
    }

    /// Plan §11's close order: the closing suspend goes out only once the
    /// generation's code-out trigger is done, so no fetch of the session
    /// starts after it and the last one ended or was given up before it.
    /// The trigger's fetch is held here (the test holds the workspace's
    /// fetch lock). Never closed, it is a miss at the closing's bound:
    /// nothing fired. S10 (D5): closed with the fetch running, the close
    /// gives the fetch up at `CLOSE_WAIT` but it runs on, and the suspend
    /// waits for its end: none within the closing's bound here, nothing
    /// fired (audited skipped, `trigger_busy`); the fetch let go as the close
    /// begins, it fires at the fetch's end.
    #[tokio::test]
    async fn the_closing_suspend_waits_for_the_code_out_trigger_within_its_bound() {
        use crate::bridge::codeout::CLOSE_WAIT;
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let ctx = plan.ctx();
        *plan.active.borrow_mut() = Some(lock_shared_blocking(&plan.paths.workspace_active(&plan.ws.slug), Duration::from_millis(100)).unwrap());
        let held = try_lock_exclusive(&plan.paths.workspace_fetch_lock(&plan.ws.slug)).unwrap().expect("the test holds the fetch lock");
        // Never closed, its fetch running: the bound passes, nothing fired.
        let (row, vm) = closing_vm(&plan, &api).await;
        let open = trigger_of(&plan);
        open.request();
        let t = std::time::Instant::now();
        suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &open.watch()).await;
        let took = t.elapsed();
        assert!(took >= CLOSING_BOUND - Duration::from_millis(100) && took < CLOSING_BOUND + Duration::from_secs(1), "a miss at the bound: {took:?}");
        assert_eq!(suspends(&api), 0, "a fetch could still reach the VM: nothing fired");
        drop(open);
        // S10 (D5): closed with its fetch running, the close gives the fetch up at its bound, but the fetch runs on
        // (no abort) and the suspend waits for its end, which never comes within the closing's bound here: nothing
        // fired, audited skipped (`trigger_busy`).
        let (row, vm) = closing_vm(&plan, &api).await;
        let trigger = trigger_of(&plan);
        trigger.request();
        let watch = trigger.watch();
        let close = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(suspends(&api), 0, "nothing while the trigger is open");
            let t = std::time::Instant::now();
            let report = trigger.close(CLOSE_WAIT).await;
            assert_eq!(suspends(&api), 0, "nothing while the abandoned fetch runs");
            (t.elapsed(), report)
        };
        let ((), (closing, report)) = tokio::join!(suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &watch), close);
        assert!(closing >= CLOSE_WAIT && report.is_none(), "the fetch given up at the close's bound: {closing:?} {report:?}");
        assert_eq!(suspends(&api), 0, "the abandoned fetch could still reach the VM: nothing fired");
        let rows = crate::bridge::audit::read_rows(&plan.paths.audit(), None).unwrap();
        assert!(rows.iter().any(|r| r["event"] == "vm_suspend" && r["detail"]["outcome"] == "skipped" && r["detail"]["why"] == "trigger_busy" && r["detail"]["id"] == vm.id.as_str()), "{rows:?}");
        // The fetch let go as the close begins: fired at its end, well before the close's bound.
        let (row, vm) = closing_vm(&plan, &api).await;
        let trigger = trigger_of(&plan);
        trigger.request();
        let watch = trigger.watch();
        let began = std::cell::Cell::new(None);
        let close = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            began.set(Some(std::time::Instant::now()));
            let release = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!(suspends(&api), 0, "nothing while the fetch runs");
                drop(held);
            };
            tokio::join!(trigger.close(CLOSE_WAIT * 10), release).0
        };
        let fired = async {
            suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &watch).await;
            std::time::Instant::now()
        };
        let (fired, report) = tokio::join!(fired, close);
        assert!(report.is_some_and(|r| !r.ok), "the fetch ended (its workspace does not exist)");
        assert_eq!(suspends(&api), 1, "fired at the fetch's end");
        let after = fired.duration_since(began.get().expect("the close began"));
        assert!(after < CLOSE_WAIT * 5, "at the fetch's end, not the close's bound: {after:?}");
    }

    /// P1 (the plan's mutant "seed and unseal sequential"): the Touch ID and
    /// the WIP snapshot run at once, each half here waiting for the other to
    /// have begun; the snapshot's thread is the plan's to wait for
    /// (`take_closing`). A snapshot that fails while the dialog is up ends
    /// P1 at once and drops the unseal (its dialog closes); a Touch ID that
    /// fails while the snapshot runs ends P1 and cancels the snapshot.
    #[tokio::test]
    async fn the_touch_id_and_the_snapshot_run_at_once_and_the_first_error_closes_the_dialog() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        let gone = || Failed { step: StartStep::TouchId, failure: Failure::Stopped, vm: None };
        let (asked, snapshotting) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let unseal = {
            let (asked, snapshotting) = (Arc::clone(&asked), Arc::clone(&snapshotting));
            async move {
                asked.store(true, SeqCst);
                let t = Instant::now();
                while !snapshotting.load(SeqCst) {
                    if t.elapsed() > Duration::from_secs(5) {
                        return Err(gone());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok("unsealed")
            }
        };
        let prepare = move |_cancel| {
            snapshotting.store(true, SeqCst);
            let t = std::time::Instant::now();
            while !asked.load(SeqCst) {
                if t.elapsed() > Duration::from_secs(5) {
                    return Err(BridgeError::Io(std::io::Error::other("the Touch ID never began")));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok("prepared")
        };
        let both = unseal_beside(&plan, unseal, prepare).await.unwrap_or_else(|f| panic!("{}: {}", f.failure.word(), f.failure.line()));
        assert_eq!(both, ("unsealed", "prepared"), "neither half waited for the other to end");
        let kept = plan.take_closing();
        assert_eq!(kept.len(), 1, "the snapshot's thread is the plan's");
        for task in kept {
            task.await.unwrap();
        }
        // The snapshot fails while the dialog waits: P1 ends with its failure and the unseal is dropped.
        struct Dialog(Arc<AtomicBool>);
        impl Drop for Dialog {
            fn drop(&mut self) {
                self.0.store(true, SeqCst);
            }
        }
        let closed = Arc::new(AtomicBool::new(false));
        let dialog = Dialog(Arc::clone(&closed));
        let pending = async move {
            let _dialog = dialog;
            std::future::pending::<Result<(), Failed>>().await
        };
        let ended = tokio::time::timeout(Duration::from_secs(5), unseal_beside(&plan, pending, |_| Err::<(), _>(BridgeError::Tripwire("README.md line 3: rule aws-key".into())))).await.expect("the snapshot's failure ends P1 at once");
        let f = ended.unwrap_err();
        assert_eq!((f.step, f.failure.word()), (StartStep::Workspace, "finding"));
        assert!(closed.load(SeqCst), "the unseal was dropped: its dialog closed");
        // The Touch ID fails while the snapshot runs: P1 ends with that failure, and the snapshot is told to
        // stop (its git runs end), so the pump's last wait sees its thread end.
        for task in plan.take_closing() {
            task.await.unwrap();
        }
        let told = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&told);
        let dismissed = async { Err::<(), _>(Failed { step: StartStep::TouchId, failure: Failure::TouchIdCancelled, vm: None }) };
        let snapshot = move |cancel: Arc<AtomicBool>| {
            let t = std::time::Instant::now();
            while !cancel.load(SeqCst) && t.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(10));
            }
            seen.store(cancel.load(SeqCst), SeqCst);
            Err::<(), _>(BridgeError::Io(std::io::Error::new(std::io::ErrorKind::Interrupted, "the seed's preparation was cancelled")))
        };
        let f = unseal_beside(&plan, dismissed, snapshot).await.unwrap_err();
        assert_eq!((f.step, f.failure.clone()), (StartStep::TouchId, Failure::TouchIdCancelled));
        let t = std::time::Instant::now();
        for task in plan.take_closing() {
            task.await.unwrap();
        }
        assert!(told.load(SeqCst) && t.elapsed() < Duration::from_secs(2), "the snapshot was told to stop: {:?}", t.elapsed());
    }

    /// `auth_timers_unmeasured` once per claude version (its marker), never
    /// for the version `AUTH_TIMERS` measured; a version that is no plain
    /// string is audited every time and names no marker file.
    #[test]
    fn auth_timers_unmeasured_is_audited_once_per_version() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().join("bridge"), None);
        let audited = || -> Vec<String> {
            let rows = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap_or_default();
            rows.iter().filter(|r| r["event"] == event::AUTH_TIMERS_UNMEASURED).map(|r| r["detail"]["claude"].as_str().unwrap_or_default().to_string()).collect()
        };
        audit_auth_timers(&paths, crate::bridge::authwatch::AUTH_TIMERS.claude);
        assert!(audited().is_empty(), "the measured version");
        for v in ["2.1.300", "2.1.300", "unknown", "2.1.300", "unknown"] {
            audit_auth_timers(&paths, v);
        }
        assert_eq!(audited(), ["2.1.300", "unknown"]);
        audit_auth_timers(&paths, "../x");
        audit_auth_timers(&paths, "../x");
        assert_eq!(audited().len(), 4, "no plain version: every time");
        assert!(!paths.root.join("state").join("x").exists(), "no marker outside its directory");
    }

    /// The retry's VM: running as it is, resumed after a suspend that raced
    /// it, refused (exit 8) once gone.
    #[tokio::test]
    async fn the_retry_takes_its_vm_running_again() {
        use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN};
        let api = FakeMicrovmApi::new();
        api.set_auto_advance(true);
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: uuid::Uuid::now_v7().to_string(),
        };
        let vm = api.run(&spec).await.unwrap();
        let poll = Poll::RUNNING.scaled(Some(1));
        assert_eq!(running(&api, &vm.id, poll).await.unwrap().state, VmState::Running);
        api.set_state(&vm.id, VmState::Suspended);
        assert_eq!(running(&api, &vm.id, poll).await.unwrap().state, VmState::Running);
        assert!(api.state().calls.iter().any(|c| matches!(c, Call::Resume { .. })), "resumed");
        api.set_state(&vm.id, VmState::Terminated);
        let e = running(&api, &vm.id, poll).await.unwrap_err();
        assert_eq!(CliError::from(e).exit_code(), 8);
    }

    /// S8 phase 4 (TIMING-3, RESUME-4; plan §3 item 6): every start the
    /// host's `initialize` waits on fits Cursor's window from T0: generation
    /// 1 and a resume miss's retry before that answer keep T0 + 50 s; only a
    /// retry after generation 1 answered has its own 60 s from its start.
    #[test]
    fn a_start_the_host_waits_on_keeps_the_init_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        plan.t0 = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
        let retry = |init_answered| StartWhy::ResumeRetry { session_id: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), init_answered };
        assert_eq!(deadline_of(&plan, &StartWhy::First), plan.init_deadline());
        assert_eq!(deadline_of(&plan, &retry(false)), plan.init_deadline(), "the retry's answer is the host's first: T0 + 50 s");
        let before = Instant::now();
        let own = deadline_of(&plan, &retry(true));
        assert!(own >= before + RETRY_WINDOW && own <= Instant::now() + RETRY_WINDOW, "after the host's answer: its own 60 s");
    }

    /// S8 phase 4 (TIMING-5): P0 never waits for the workspace's `.active`
    /// (it runs before the pump reads the host or listens for a stop): held
    /// alone by a closing session, P0 returns at once without it; generation
    /// 1's start takes it shared once let go (inside the pending start,
    /// which a host EOF or a signal drops), or goes on without it past
    /// [`ACTIVE_WAIT`].
    #[test]
    fn p0_tries_the_workspaces_active_once_and_the_start_waits_for_it() {
        let w = World::new("");
        let slug = crate::wire::slug::project_dir_name(&w.work).unwrap();
        let active = w.paths.workspace_active(&slug);
        let closing = try_lock_exclusive(&active).unwrap().expect("the test holds .active alone, as a closing session");
        let t = std::time::Instant::now();
        let plan = precheck_with(&w.session(&ARGS), &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}", f.line()));
        assert!(t.elapsed() < ACTIVE_WAIT / 2, "P0 waited {:?}", t.elapsed());
        assert!(plan.active.borrow().is_none(), "P0 found it held");
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let took = rt.block_on(async {
            let release = async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(closing);
            };
            let t = Instant::now();
            tokio::join!(hold_active_at_start(&plan), release);
            t.elapsed()
        });
        assert!(took < ACTIVE_WAIT && plan.active.borrow().is_some(), "taken once let go: {took:?}");
        assert!(try_lock_exclusive(&active).unwrap().is_none(), "the start holds it shared");
        // Never let go: past ACTIVE_WAIT the session goes on without it.
        drop(plan.active.borrow_mut().take());
        let held = try_lock_exclusive(&active).unwrap().expect("alone again");
        let t = std::time::Instant::now();
        rt.block_on(hold_active_at_start(&plan));
        assert!(plan.active.borrow().is_none() && t.elapsed() >= ACTIVE_WAIT, "{:?}", t.elapsed());
        drop(held);
    }

    /// A deadline names the step it was stuck at, with its exit code; P3's
    /// two branches name the one still running, its re-gate the gate. (P1's
    /// unseal moves the step to the workspace once answered: `first`.)
    #[test]
    fn a_deadline_names_the_step_it_was_stuck_at() {
        let p = Progress::default();
        assert_eq!(p.stuck_at(), StartStep::Precheck);
        p.at(StartStep::TouchId);
        assert_eq!((p.stuck_at(), deadline_code(p.stuck_at())), (StartStep::TouchId, 5));
        p.at(StartStep::SelectVm);
        assert_eq!(deadline_code(p.stuck_at()), 7);
        p.at(StartStep::Workspace);
        assert_eq!(p.stuck_at(), StartStep::Workspace, "both P3 branches running: the workspace");
        p.gate_done.set(true);
        assert_eq!(p.stuck_at(), StartStep::Workspace);
        p.gate_done.set(false);
        p.workspace_done.set(true);
        assert_eq!(p.stuck_at(), StartStep::Gate, "the gate or its token still running");
        p.gate_done.set(true);
        p.at(StartStep::Gate);
        assert_eq!((p.stuck_at(), deadline_code(p.stuck_at())), (StartStep::Gate, 7), "P3b's re-gate names the gate");
        p.at(StartStep::Spawn);
        assert_eq!(deadline_code(p.stuck_at()), 8);
        let f = Failure::Deadline { code: deadline_code(StartStep::TouchId), step: StartStep::TouchId.name() };
        assert_eq!((f.exit_code(), f.line()), (5, "did not start within Cursor's 60 s window (stuck at touchid): ai-env vm warm prepares the VM ahead".to_string()));
    }

    /// A Touch ID that ran out of time is `TouchIdTimeout` naming its
    /// budget (exit 5); a dismissed one `TouchIdCancelled` (3); the rest
    /// map by `Failure::from_error`.
    #[test]
    fn a_touch_id_deadline_is_its_own_failure() {
        let deadline = CliError::AuthUnavailable("no Touch ID within 47 s, so the runtime key stayed sealed (nothing was started; …)".into());
        assert!(crate::bridge::unseal::is_deadline(&deadline));
        let f = failed_cli(StartStep::TouchId, deadline, None);
        assert_eq!((f.failure.clone(), f.failure.exit_code()), (Failure::TouchIdTimeout { secs: 47 }, 5));
        assert!(f.failure.line().starts_with("no Touch ID within 47 s (Cursor's 60 s window)"), "{}", f.failure.line());
        assert_eq!(failed_cli(StartStep::Gate, CliError::Cancelled, Some("microvm-1")).failure, Failure::TouchIdCancelled);
        let gate = failed_cli(StartStep::Gate, CliError::Policy("no credential for microvm-1: its egress check is older than 14 days".into()), Some("microvm-1"));
        assert_eq!((gate.failure.word(), gate.failure.exit_code(), gate.vm.as_deref()), ("gate_refused", 9, Some("microvm-1")));
    }

    /// P4 spawns at the workspace's VM path, never at the Mac's spelling of
    /// it: a cwd macOS hands out in NFD (Й as И and U+0306) is spawned at
    /// its NFC form, the one the seed wrote. On the VM's disk the NFD path
    /// is another, empty directory; on APFS (the rig's VM) either spelling
    /// finds the seeded one, so only this test tells them apart.
    #[test]
    fn the_spawn_runs_at_the_vm_path_never_the_macs_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = SessionPlan::sample(dir.path());
        let nfd = "/w/\u{0418}\u{0306}\u{043e}\u{0433}\u{0430}";
        plan.ws.cwd = nfd.into();
        plan.ws.vm_cwd = crate::wire::workspace::vm_path_of(Path::new(nfd)).unwrap();
        assert_eq!(plan.ws.vm_cwd, "/w/\u{0419}\u{043e}\u{0433}\u{0430}", "the NFC form");
        let id = SpawnId::new_v7();
        let spec = spawn_spec(&plan, &plan.ctx(), &VmRow::default(), &id, plan.argv.clone());
        assert_eq!(spec.cwd.as_deref(), Some(plan.ws.vm_cwd.as_str()), "{spec:?}");
        assert_eq!((spec.id.as_ref(), spec.detach_grace_s), (Some(&id), Some(session_grace(&plan.cfg, None))));
        assert_eq!((&spec.argv, &spec.env), (&plan.argv, &plan.env), "the plan's argv and environment (no proxy for a row without vpc egress)");
    }

    /// v6 L8(c): the spawn's grace outlasts the idle-to-suspend of the VM it
    /// runs on, whose policy is its own: a VM reused with a longer idle than
    /// `[vm].max_idle_s` (`vm run --idle 3600`, or started before the config
    /// was lowered) gets max(900, 3600 + 90 + 60); a shorter one never goes
    /// under the config's.
    #[test]
    fn the_spawn_grace_covers_the_vms_own_idle() {
        use crate::bridge::vm::registry::IdleRow;
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        assert_eq!(plan.cfg.vm.max_idle_s, 300, "the sample's config");
        let grace = |max_idle_s: u32| {
            let row = VmRow { idle: Some(IdleRow { max_idle_s, suspended_s: 28_800, auto_resume: true }), ..VmRow::default() };
            spawn_spec(&plan, &plan.ctx(), &row, &SpawnId::new_v7(), plan.argv.clone()).detach_grace_s
        };
        assert_eq!(grace(3600), Some(3750));
        assert_eq!(grace(300), Some(900));
    }

    /// The phase-0 plan W1's link tests build stays a plan: `Debug` shows no value.
    #[test]
    fn the_sample_plan_shows_counts_only() {
        let dir = tempfile::tempdir().unwrap();
        let plan = SessionPlan::sample(dir.path());
        assert_eq!(plan.init_deadline() - plan.t0, Duration::from_secs(50));
        assert_eq!(format!("{plan:?}"), "SessionPlan(argc=3, env=1, vm_cwd=/w, resume=false)");
        assert_eq!(plan.credential.get(), None);
    }
}
