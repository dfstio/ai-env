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
//! - **P0** ([`precheck`], before the pump supervises anything): bridge.toml
//!   for the remote path (that it loads, else exit 1 with its error's first
//!   line; `Ctx::for_wrapper`, `[wrapper].mode`, `[seed]`);
//!   the VM's `Choice` (`AI_ENV_BRIDGE_VM` pinned and checked here, before
//!   any Touch ID; a `--resume`'s VM preferred, from its registry row; else
//!   the workspace's); `workspace::resolve` (D6: a workspace that is no git
//!   repository is exit 9 at once); the run plan (vpc egress, `workspace_v1`
//!   required); the sealed token and the runtime key; the gate's local half;
//!   the VM's argv (`claude`, the host's arguments `argv::sanitise`d, then
//!   `--session-mirror`) and environment (`remote::env`, L4), the spawn frame
//!   within its cap; the workspace's `.active` lock, shared, for the
//!   process's life (taken at once: while a closing session holds it alone,
//!   generation 1's pending start waits for it, where the host's EOF and the
//!   signals reach the wait); T0, the census start.
//! - **P1**: `credential::backend_for_session` (the runtime key, and the
//!   token with it when `combined.env` is current; `state/unseal.lock`, the
//!   countdown as `ai-env-claude`, the budget ending 1 s before T0 + 50 s:
//!   `credential::session_room`), with
//!   `workspace::prepare` (the WIP snapshot and the scans' warm-up, local)
//!   on a blocking thread beside it, whose handle the plan keeps
//!   ([`SessionPlan::take_closing`]: nothing cancels a blocking thread);
//!   first on that thread, when the session names no VM of its own (no
//!   registry row naming one, no pin), a `--resume`'s transcript through the
//!   seed's tripwires (`workspace::transcript::scan_mac_copy`: a finding
//!   starts no VM). A VM the session names may hold the chat already: P3's
//!   upload refuses a finding only in a file it would send.
//! - **P2**: `vm::run::select_vm_detailed` with the plan's `Choice` (a VM
//!   whose caps were never read gets one `/health`: a VM without
//!   `workspace_v1` is exit 7 naming `make deploy`).
//! - **P3**: `try_join!` of the workspace branch (`ensure_workspace`, then
//!   a `--resume`'s transcript) and the credential branch
//!   (`credential::prepare_session`: the gate, then the token); the first
//!   error drops the other (a tripwire closes a pending token dialog). Then
//!   a re-gate without a prompt if the pass passed half its life.
//! - **P4**: the spawn (`SpawnSpec` with its id, the VM path as cwd, the
//!   proxy variables then the session's, `remote::session_grace`) handed to
//!   its session task on the pump's `LocalSet` (`agent::run_spawn_with` with
//!   `hello.idle_s` 90), the code-out trigger beside it (a `--resume`'s id
//!   named to it at once: the settings' start capture runs in its task, best
//!   effort, never inside the init deadline; a fresh session's comes with
//!   its first `system/init`, through the pump). When the exit
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
//! transcript's upload and a gate without a prompt, the token from the VM's
//! cache, within T0 + 50 s while the host's `initialize` is unanswered (its
//! answer is the host's first), else within its own 60 s ([`deadline_of`]).
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
use crate::bridge::remote::link::{SpawnFailure, StartStep, StartWhy};
use crate::bridge::remote::{audit_event as event, session_grace, Failure, INIT_DEADLINE, PIN_KNOB, TRANSCRIPT_KNOB};
use crate::bridge::vm::cmd::{audit_event, provisional_gate, retry_gate_terminate, sealed_token_plan, Backend, Ctx};
use crate::bridge::vm::lock::{try_lock_exclusive, try_lock_shared, FlockGuard};
use crate::bridge::vm::registry::{self as vm_registry, RowStatus, VmRow};
use crate::bridge::vm::run::{self, Choice, Egress, Poll, RunFlags, RunPlan, Selected};
use crate::bridge::workspace::{self, vm_capability, Capability, EnsureCtx, PreparedSeed, SeedLimits, SeedWant, WorkspaceRef};
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::argv::{self, SanitiseOpts};
use crate::wire::frame::{Deliver, Frame, SpawnId, ARGV_MAX_BYTES, CAP_WORKSPACE_V1, CONTROL_FRAME_MAX, IDLE_DEFAULT_S};
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
    /// `[wrapper] strip_add_dir` and `strip_debug`, then `--session-mirror`.
    pub argv: Vec<String>,
    /// The spawn's environment before the proxy variables (L4, `remote::env`):
    /// the forwarded names and the wrapper's own.
    pub env: BTreeMap<String, String>,
    /// The workspace (`workspace::resolve`): its VM path is the spawn's cwd.
    pub ws: WorkspaceRef,
    /// The census start (T0): P1–P4 are over by [`SessionPlan::init_deadline`].
    pub t0: Instant,
    /// `--resume`'s session id, when it is a uuid (the transcript's upload, the VM preferred).
    pub resume: Option<String>,
    /// The code-out trigger captures the VM's settings into the session's
    /// quarantine (T8.7): never for `--no-session-persistence` (Cursor's
    /// prompt-suggestion queries), which no registry row keeps, so nothing
    /// would ever show or remove that quarantine.
    capture_settings: bool,
    /// The lab knobs (debug builds), read at P0.
    knobs: VmKnobs,
    /// SELECT_VM's plan: vpc egress, the workspace (its canonical cwd), the
    /// `Choice`, `workspace_v1` required.
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
    /// uploads no transcript, so a resume misses and the retry uploads it.
    skip_transcript: bool,
    /// The Mac's projects root and the slugs a session's transcript is
    /// looked for under (the cwd's, the registry row's).
    mac_projects: Option<PathBuf>,
    slugs: Vec<String>,
    /// What generation 1 leaves for a resume miss's retry.
    held: RefCell<Option<Held>>,
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
}

/// Generation 1's backend and VM, for the retry (no second Touch ID, D1).
#[derive(Clone)]
struct Held {
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
        };
        SessionPlan {
            paths: Paths::from_root_and_env(root.join("bridge"), None),
            argv: vec!["claude".into(), "--output-format".into(), "stream-json".into(), "--session-mirror".into()],
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
            held: RefCell::new(None),
            started: Cell::new(0),
            credential: Cell::new(None),
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
    /// resume's upload (`workspace::TranscriptOutcome::word`).
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
}

/// How a workspace is resolved (`workspace::resolve`; tests inject theirs).
type Resolver<'a> = &'a dyn Fn(&BridgeConfig, &Path, Option<&str>) -> Result<WorkspaceRef, BridgeError>;

/// P0, in the wrapper before the pump supervises anything (no AWS call, no
/// Touch ID): bridge.toml for the remote path, the run plan (vpc egress, the
/// `Choice`: `AI_ENV_BRIDGE_VM`'s pin, the resumed session's VM preferred, or
/// the workspace's), `workspace::resolve` (D6), the sealed token's plan, the
/// provisional gate, the VM's argv and environment, the shared lock on the
/// workspace's `.active` (one try, no wait). `Err` is the failure the
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
    let Some(cwd) = sess.cwd.as_deref() else {
        return Err(Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: "the working directory is unknown".into() });
    };
    let resume = sess.session.resume.clone().filter(|r| crate::bridge::registry::is_uuid(r));
    let choice = choice_of(&ctx, resume.as_deref(), env)?;
    let ws = resolve(cfg, cwd, None).map_err(precheck)?;
    let flags = RunFlags { workspace: Some(ws.cwd.clone()), egress: Some(Egress::Vpc), purpose: "session", wait: true, ..RunFlags::default() };
    let mut run = RunPlan::from_cfg(cfg, &flags).map_err(precheck)?;
    run.choice = choice;
    run.workspace_cap = true;
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
    let skip_transcript = cfg!(debug_assertions) && env(TRANSCRIPT_KNOB).is_some_and(|v| v == "skip");
    tracing::info!(argc = argv.len(), env = session_env.len(), choice = run.choice.word(), resume = resume.is_some(), skip_transcript, "remote session planned");
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
        held: RefCell::new(None),
        started: Cell::new(0),
        credential: Cell::new(None),
    })
}

/// The VM SELECT_VM takes (plan §1): `AI_ENV_BRIDGE_VM` pins one, checked
/// here, before any Touch ID: a VM id (else 2), a row (else 8), not
/// terminated (else 8), vpc egress and no `--shell` (else 9), an image with
/// `workspace_v1` as last read (else 7, `make deploy`). Else a `--resume`'s
/// VM (its registry row's `microvm_id`) is preferred; else the workspace's.
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
            return Err(Failure::OldImage { vm: id });
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
/// stripped as `[wrapper]` says, one `--session-mirror` last), within
/// `ARGV_MAX_BYTES` (else exit 9).
fn vm_argv(cfg: &BridgeConfig, args: &[String]) -> Result<Vec<String>, Failure> {
    let opts = SanitiseOpts { strip_add_dir: cfg.wrapper.strip_add_dir, strip_debug: cfg.wrapper.strip_debug };
    let sanitised = argv::sanitise(args, opts).map_err(|e| Failure::Refused { what: format!("the session's arguments: {e}") })?;
    let argv: Vec<String> = std::iter::once("claude".to_string()).chain(sanitised).collect();
    let size: usize = argv.iter().map(|a| a.len() + 1).sum();
    if size > ARGV_MAX_BYTES {
        return Err(Failure::Refused { what: format!("the session's arguments are {size} bytes (at most {ARGV_MAX_BYTES})") });
    }
    Ok(argv)
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
/// which uploads the transcript first and respawns on the same VM), on the
/// pump's `LocalSet`: the Touch ID, SELECT_VM, the workspace beside the gate
/// and the token, then the spawn handed to its session task with `io`. All of
/// it within [`deadline_of`]: `plan.init_deadline()`, but a retry's start +
/// 60 s once the host's `initialize` was answered. `Err` is the link's first
/// event (`ChildEvent::SpawnFailed`): nothing was spawned; it is audited
/// `session_remote_failed`. Dropping the future cancels it (an unseal's
/// dialog closes with it).
pub async fn run(plan: Rc<SessionPlan>, gen: u32, why: StartWhy, io: SpawnIo) -> Result<PipelineEnd, SpawnFailure> {
    plan.started.set(plan.started.get().max(gen));
    let deadline = deadline_of(&plan, &why);
    let progress = Progress::default();
    let failed = match tokio::time::timeout_at(deadline, generation(&plan, gen, &why, io, &progress)).await {
        Ok(Ok(end)) => return Ok(PipelineEnd { started_by: Some(deadline), ..end }),
        Ok(Err(f)) => f,
        Err(_) => {
            let step = progress.stuck_at();
            Failed { step: StartStep::Deadline, failure: Failure::Deadline { code: deadline_code(step), step: step.name() }, vm: progress.vm.borrow().clone() }
        }
    };
    let mut pairs = vec![("gen", gen.to_string()), ("step", failed.step.name().to_string()), ("code", failed.failure.exit_code().to_string()), ("why", failed.failure.word().to_string())];
    if let Some(vm) = &failed.vm {
        pairs.push(("id", vm.clone()));
    }
    audit_event(&plan.paths, event::SESSION_REMOTE_FAILED, &pairs);
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
        StartWhy::First | StartWhy::ResumeRetry { .. } => plan.init_deadline(),
    }
}

async fn generation(plan: &Rc<SessionPlan>, gen: u32, why: &StartWhy, io: SpawnIo, progress: &Progress) -> Result<PipelineEnd, Failed> {
    match why {
        StartWhy::First => {
            hold_active_at_start(plan).await;
            first(plan, gen, io, progress).await
        }
        StartWhy::ResumeRetry { session_id, .. } => {
            let held = plan.held.borrow().clone();
            let Some(held) = held else {
                return Err(Failed { step: StartStep::Precheck, failure: Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: "the resume's retry has no first generation to respawn on".into() }, vm: None });
            };
            let backend = Rc::clone(&held.backend);
            match &*backend {
                Backend::Sdk(api, ep) => retry(plan, gen, Arc::clone(api), Arc::clone(ep), held, session_id, io, progress).await,
                Backend::Fake(f) => retry(plan, gen, Arc::new(f.clone()), Arc::new(f.clone()), held, session_id, io, progress).await,
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
        let unsealed = credential::backend_for_session(&plan.store, &ctx, &plan.token, plan.window_from).await.map_err(|e| failed_cli(StartStep::TouchId, e, None))?;
        // Answered: what P1 may still wait for is the snapshot (a deadline names the workspace).
        progress.at(StartStep::Workspace);
        Ok::<_, Failed>((unsealed, ms(t)))
    };
    let (paths, cfg, ws) = (plan.paths.clone(), plan.cfg.clone(), plan.ws.clone());
    // A `--resume`'s transcript goes through the seed's tripwires here, before the seed's own scans: a finding starts no
    // VM and closes the dialog. Not when the session names its VM (its row's, a pin): that VM may hold the chat already
    // (what its tools printed, mirrored here), which is never sent again, so P3's upload decides (`upload_transcript`).
    let names_vm = matches!(plan.run.choice, Choice::Prefer(_) | Choice::Pin(_));
    let transcript = plan.resume.clone().zip(plan.mac_projects.clone()).filter(|_| !names_vm).map(|(id, root)| (id, root, plan.slugs.clone(), crate::wire::slug::slug_of(&plan.ws.vm_cwd)));
    let (((backend, token), touch_ms), prepared) = unseal_beside(plan, unseal, move |cancel| {
        if let Some((id, root, slugs, vm_slug)) = &transcript {
            let slugs: Vec<&str> = slugs.iter().map(String::as_str).collect();
            workspace::transcript::scan_mac_copy(&paths, &cfg, &ws, root, &slugs, id, vm_slug)?;
        }
        workspace::prepare_cancellable(&paths, &cfg, &ws, &lim, cancel)
    })
    .await?;
    let backend = Rc::new(backend);
    let legs = vec![("touchid", touch_ms)];
    match &*Rc::clone(&backend) {
        Backend::Sdk(api, ep) => onwards(plan, gen, &ctx, Arc::clone(api), Arc::clone(ep), backend, token, prepared, legs, io, progress).await,
        Backend::Fake(f) => onwards(plan, gen, &ctx, Arc::new(f.clone()), Arc::new(f.clone()), backend, token, prepared, legs, io, progress).await,
    }
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
async fn onwards<A: MicrovmApi + 'static, E: EndpointClient + 'static>(
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
    // P2: SELECT_VM, the plan's Choice inside its own lock hold.
    progress.at(StartStep::SelectVm);
    let t = Instant::now();
    let selected = match run::select_vm_detailed(&*api, &plan.paths, &plan.run, ctx.poll(Poll::RUNNING)).await {
        Ok(selected) => selected,
        Err(f) => {
            let f = retry_gate_terminate(ctx, &*api, f).await;
            return Err(failed(StartStep::SelectVm, f.error, f.started.as_deref()));
        }
    };
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
        let outcome = workspace::ensure_workspace(&ectx, Some(prepared), SeedWant::Auto).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
        let transcript = match &plan.resume {
            Some(_) if plan.skip_transcript => {
                tracing::info!("{TRANSCRIPT_KNOB}=skip: no transcript is uploaded before the resume");
                None
            }
            Some(id) => Some(upload_transcript(plan, &ectx, id).await.map_err(|e| failed(StartStep::Workspace, e, at))?),
            None => None,
        };
        progress.workspace_done.set(true);
        Ok::<_, Failed>((outcome, transcript, ms(t)))
    };
    let credential_branch = async {
        let t = Instant::now();
        let supply = CredentialSupply { store: &plan.store, token };
        let prepared = credential::prepare_session(ctx, &*api, &*ep, &row, &vm, &plan.token, supply, plan.window_from).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
        progress.gate_done.set(true);
        Ok::<_, Failed>((prepared, ms(t)))
    };
    let ((outcome, transcript, workspace_ms), (mut prepared, gate_ms)) = tokio::try_join!(workspace_branch, credential_branch)?;
    legs.push(("workspace", workspace_ms));
    // P3b: a deadline from here names the gate.
    progress.at(StartStep::Gate);
    let t = Instant::now();
    credential::regate_if_stale(ctx, &*api, &row, &vm, &mut prepared).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    legs.push(("gate", gate_ms + ms(t)));
    plan.credential.set(Some(prepared.source));
    let seed = outcome.word();
    let seeded_head = seeded_head(&outcome);
    let held = Held { backend, row: row.clone(), vm: vm.clone(), how, seed, seeded_head: seeded_head.clone() };
    // The code-out trigger's code-port tokens are the session's 5 minutes, never the seed's 15 (plan §10).
    let code_tokens = Arc::new(MintingTokens::new(Arc::clone(&api), &ctx.paths, &vm.id, false));
    let end = spawn(plan, gen, ctx, api, ep, dp, code_tokens, target, row, vm, prepared.delivery, io, progress).await?;
    *plan.held.borrow_mut() = Some(held);
    Ok(PipelineEnd { vm: end.vm, vm_how: how, legs, seed, transcript: transcript.map(|o| o.word()), seeded_head, credential: plan.credential.get(), delivery: Some(end.delivery), spawn_id: end.spawn_id, started_by: None, trigger: end.trigger, session: end.session })
}

/// The retry of a resume miss (plan §2): generation 1's VM, running again
/// if a closing suspend raced it; the transcript up; the gate again with no
/// prompt; the token from the VM's cache (no value in hand: a VM that lost
/// it is exit 5, never a second Touch ID); the spawn.
#[allow(clippy::too_many_arguments)]
async fn retry<A: MicrovmApi + 'static, E: EndpointClient + 'static>(plan: &Rc<SessionPlan>, gen: u32, api: Arc<A>, ep: Arc<E>, held: Held, session_id: &str, io: SpawnIo, progress: &Progress) -> Result<PipelineEnd, Failed> {
    let ctx = plan.ctx();
    let mut legs = Vec::new();
    progress.at(StartStep::SelectVm);
    *progress.vm.borrow_mut() = Some(held.vm.id.clone());
    let at = Some(held.vm.id.as_str());
    let t = Instant::now();
    let vm = running(&*api, &held.vm.id, ctx.poll(Poll::RUNNING)).await.map_err(|e| failed(StartStep::SelectVm, e, at))?;
    legs.push(("select", ms(t)));
    progress.at(StartStep::Workspace);
    let t = Instant::now();
    let target = target_of(&held.row, &vm).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let (dp, tokens) = data_plane(&ctx, &api, &vm.id, false).map_err(|e| failed(StartStep::Workspace, e, at))?;
    let caps = held.row.caps.clone().unwrap_or_default();
    let progress_log = |p: workspace::SeedProgress| tracing::info!("seed: {p:?}");
    let ectx = EnsureCtx { api: &*api, dp: &*dp, tokens: &*tokens, paths: &plan.paths, cfg: &plan.cfg, target: &target, caps: &caps, ws: &plan.ws, lim: SeedLimits::wrapper(&plan.cfg), deadline: None, progress: &progress_log };
    let transcript = upload_transcript(plan, &ectx, session_id).await.map_err(|e| failed(StartStep::Workspace, e, at))?;
    legs.push(("workspace", ms(t)));
    progress.workspace_done.set(true);
    progress.at(StartStep::Gate);
    let t = Instant::now();
    let pass = credential::gate(&ctx.cfg, &ctx.paths, &*api, &held.row, &vm).await.map_err(|e| failed_cli(StartStep::Gate, e, at))?;
    let parts = DeliveryParts { name: crate::bridge::setup_token::TOKEN_VAR.to_string(), tag: plan.token.tag.clone(), deliver: plan.token.deliver, secret: None, one_shot: false };
    let delivery = Delivery::new(&pass, &vm.id, crate::wire::time::unix_now(), parts).map_err(|e| failed(StartStep::Gate, e, at))?;
    // This generation's token is the VM's own copy: the census says so, not generation 1's source.
    plan.credential.set(Some(credential::CACHED));
    legs.push(("gate", ms(t)));
    progress.gate_done.set(true);
    let end = spawn(plan, gen, &ctx, api, ep, dp, tokens, target, held.row.clone(), vm, delivery, io, progress).await?;
    Ok(PipelineEnd { vm: end.vm, vm_how: held.how, legs, seed: held.seed, transcript: Some(transcript.word()), seeded_head: held.seeded_head.clone(), credential: plan.credential.get(), delivery: Some(end.delivery), spawn_id: end.spawn_id, started_by: None, trigger: end.trigger, session: end.session })
}

/// `id` RUNNING: as GetMicrovm finds it, waited for while PENDING, resumed
/// while SUSPENDING or SUSPENDED (a closing session's suspend may have
/// raced the retry); gone or going is exit 8.
async fn running<A: MicrovmApi>(api: &A, id: &str, poll: Poll) -> Result<VmInfo, BridgeError> {
    let vm = api.get(id).await?;
    match vm.state {
        VmState::Running => Ok(vm),
        VmState::Pending => run::wait_for_state(api, id, &VmState::Running, poll).await,
        VmState::Suspending | VmState::Suspended => {
            if vm.state == VmState::Suspending {
                run::wait_for_state(api, id, &VmState::Suspended, poll).await?;
            }
            match api.resume(id).await {
                Ok(()) | Err(BridgeError::Conflict(_)) => {}
                Err(e) => return Err(e),
            }
            run::wait_for_state(api, id, &VmState::Running, poll).await
        }
        _ => Err(BridgeError::Terminated(format!("{id} is {}", vm.state.as_str()))),
    }
}

/// The VM's caps for the workspace routes: its row's, or, never read (`vm
/// run` reads no `/health`), one `/health` that records them. Without
/// `workspace_v1` nothing is sent: exit 7 naming `make deploy` (L5).
async fn workspace_caps<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: VmRow) -> Result<(VmRow, Vec<String>), BridgeError> {
    let row = if vm_capability(&row) == Capability::Unknown {
        crate::bridge::vm::health::read_health(api, ep, &ctx.paths, &row.id, ctx.backoff()).await?;
        vm_registry::read_row(&ctx.paths, &row.id)?.unwrap_or(row)
    } else {
        row
    };
    if vm_capability(&row) != Capability::Yes {
        return Err(BridgeError::NoCapability { cap: CAP_WORKSPACE_V1, message: format!("{} (image version {}) does not serve the workspace routes", row.id, row.image_version) });
    }
    let caps = row.caps.clone().unwrap_or_default();
    Ok((row, caps))
}

/// The session's target on `vm` (the endpoint GetMicrovm reported wins over the row's).
fn target_of(row: &VmRow, vm: &VmInfo) -> Result<AgentTarget, BridgeError> {
    let mut row = row.clone();
    if !vm.endpoint.is_empty() {
        row.endpoint = Some(vm.endpoint.clone());
    }
    AgentTarget::from_row(&row)
}

/// A `--resume`'s transcript to the VM (plan §8): the Mac's mirror of the
/// session, to the projects dir the VM's claude reads (the slug of the
/// workspace's VM path: a session never forwards the CLI's override,
/// `remote::env::PROJECT_DIR_NAME`). No Mac config dir: nothing to send.
async fn upload_transcript<A: MicrovmApi, D: DataPlane, T: TokenSource>(plan: &SessionPlan, ectx: &EnsureCtx<'_, A, D, T>, session_id: &str) -> Result<workspace::TranscriptOutcome, BridgeError> {
    let Some(mac_projects) = &plan.mac_projects else {
        return Ok(workspace::TranscriptOutcome::NoMacCopy);
    };
    let vm_slug = crate::wire::slug::slug_of(&plan.ws.vm_cwd);
    let slugs: Vec<&str> = plan.slugs.iter().map(String::as_str).collect();
    workspace::ensure_transcript(ectx, mac_projects, &slugs, session_id, &vm_slug).await
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

/// P4: the spawn (its id named now, the workspace's VM path as cwd, the
/// proxy variables then the session's, the session grace, `hello.idle_s`
/// 90) handed to its session task on the pump's `LocalSet`, the code-out
/// trigger beside it (its watch to the session task, for the closing
/// suspend); audited `session_remote_start`.
#[allow(clippy::too_many_arguments)]
async fn spawn<A: MicrovmApi + 'static, E: EndpointClient + 'static, D: DataPlane + 'static, T: TokenSource + 'static>(
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
) -> Result<Spawned, Failed> {
    progress.at(StartStep::Spawn);
    let at = Some(vm.id.as_str());
    // What the session task builds again: refused here, before anything is spawned.
    agent_env(ctx, &*api, &*ep, &row, Some(&vm)).map_err(|e| failed_cli(StartStep::Spawn, e, at))?;
    let spawn_id = SpawnId::new_v7();
    let spec = spawn_spec(plan, ctx, &row, &spawn_id);
    let trigger = CodeoutTrigger::spawn(CodeoutCtx { api: Arc::clone(&api), dp, tokens, paths: plan.paths.clone(), cfg: Arc::new(plan.cfg.clone()), target, ws: plan.ws.clone(), capture_settings: plan.capture_settings });
    if let Some(id) = &plan.resume {
        // A resumed session's id is known before its init: the settings' start capture runs beside the spawn (T8.7).
        trigger.set_session(id);
    }
    let id = vm.id.clone();
    let report = delivery.report();
    let session = tokio::task::spawn_local(session(Rc::clone(plan), gen, plan.ctx(), api, ep, row, vm, spec, io, delivery, trigger.watch()));
    audit_event(&plan.paths, event::SESSION_REMOTE_START, &[("id", id.clone()), ("spawn", spawn_id.to_string()), ("gen", gen.to_string())]);
    tracing::info!(gen, vm = %id, spawn = %spawn_id, "the remote spawn went to its session");
    Ok(Spawned { vm: id, spawn_id, trigger, session, delivery: report })
}

/// P4's spawn frame: the plan's argv; the workspace's VM path as its cwd
/// (the NFC form the seed wrote, never the Mac's spelling: on the VM's disk
/// an NFD path names another directory); the proxy variables of `row`,
/// then the session's; the session grace for `row`'s idle policy (a reused
/// VM's may be longer than `[vm].max_idle_s`); `spawn_id`.
fn spawn_spec(plan: &SessionPlan, ctx: &Ctx, row: &VmRow, spawn_id: &SpawnId) -> SpawnSpec {
    let pairs: Vec<(String, String)> = plan.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let grace = session_grace(&plan.cfg, row.idle.map(|i| i.max_idle_s));
    SpawnSpec { argv: plan.argv.clone(), cwd: Some(plan.ws.vm_cwd.clone()), env: spawn_env(ctx, row, &pairs), detach_grace_s: Some(grace), id: Some(spawn_id.clone()) }
}

/// The session task: the spawn over `/agent` until its exit is delivered
/// (`agent::run_spawn_with`); its end is the spawn's, never later. Once the
/// exit arrived (and only then: a session that gave up starts nothing), the
/// closing suspend (L2, best effort) runs as a task of its own, kept by the
/// plan for the pump's last wait ([`SessionPlan::take_closing`]), after the
/// generation's code-out trigger (`trigger`) is done.
#[allow(clippy::too_many_arguments)]
async fn session<A: MicrovmApi + 'static, E: EndpointClient + 'static>(plan: Rc<SessionPlan>, gen: u32, ctx: Ctx, api: Arc<A>, ep: Arc<E>, row: VmRow, vm: VmInfo, spec: SpawnSpec, io: SpawnIo, delivery: Delivery, trigger: TriggerWatch) -> Result<SpawnOutcome, BridgeError> {
    let ended = {
        let mut env = agent_env(&ctx, &*api, &*ep, &row, Some(&vm)).map_err(BridgeError::Cli)?;
        env.policy.idle_s = Some(IDLE_DEFAULT_S);
        run_spawn_with(&env, Start::New(spec), io, Some(delivery)).await
    };
    if ended.is_ok() {
        let closing = Rc::clone(&plan);
        plan.keep(tokio::task::spawn_local(async move { suspend_on_close(&closing, gen, &ctx, &*api, &*ep, &row, &vm, &trigger).await }));
    }
    ended
}

/// L2's best-effort suspend, as the session's exit arrived: the reason it is
/// not fired, or `Ok` to fire it. `enabled`: `[vm].suspend_on_close`;
/// `alone`: nobody else holds the workspace's `.active` lock (another
/// wrapper of the workspace, a `vm warm`); `live`: the VM's spawns alive
/// now (`None`: `/health/detail` could not be read); `retrying`: a resume
/// miss's retry started a later generation on the VM.
fn suspend_verdict(enabled: bool, alone: bool, live: Option<usize>, retrying: bool) -> Result<(), &'static str> {
    if !enabled {
        return Err("suspend_on_close is off");
    }
    if !alone {
        return Err("another session or vm warm of the workspace runs");
    }
    match live {
        None => Err("the VM's spawns could not be read"),
        Some(n) if n > 0 => Err("a spawn still lives on the VM"),
        Some(_) if retrying => Err("a retry respawns on the VM"),
        Some(_) => Ok(()),
    }
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
/// (`[vm].max_idle_s`) suspends the VM anyway.
#[allow(clippy::too_many_arguments)]
async fn suspend_on_close<A: MicrovmApi, E: EndpointClient>(plan: &SessionPlan, gen: u32, ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo, trigger: &TriggerWatch) {
    if !plan.cfg.vm.suspend_on_close {
        tracing::info!("closing: no suspend (suspend_on_close is off)");
        return;
    }
    let until = Instant::now() + CLOSING_BOUND;
    if tokio::time::timeout_at(until, trigger.wait_done()).await.is_err() {
        tracing::info!("closing: no suspend of {} (its code-out trigger was not done within {} ms; the idle policy suspends it)", vm.id, CLOSING_BOUND.as_millis());
        return;
    }
    tracing::info!("closing: the code-out trigger is done");
    let live = tokio::time::timeout_at(until, live_spawns(ctx, api, ep, row, vm)).await.unwrap_or(None);
    if let Err(why) = suspend_verdict(true, true, live, plan.started.get() > gen) {
        tracing::info!("closing: no suspend of {} ({why})", vm.id);
        return;
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
        Err(why) => tracing::info!("closing: no suspend of {} ({why})", vm.id),
        Ok(()) => match tokio::time::timeout_at(until, api.suspend(&vm.id)).await {
            Ok(Ok(()) | Err(BridgeError::Conflict(_))) => {
                audit_event(&plan.paths, "vm_suspend", &[("id", vm.id.clone()), ("by", "close".to_string())]);
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
            Ok(Err(e)) => tracing::warn!("closing: suspend of {}: {e}", vm.id),
            Err(_) => tracing::warn!("closing: the suspend of {} had no answer within {} ms (the idle policy suspends it)", vm.id, CLOSING_BOUND.as_millis()),
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

/// The VM's spawns alive now (`/health/detail` with the session's bearer),
/// `None` when it cannot be read.
async fn live_spawns<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, row: &VmRow, vm: &VmInfo) -> Option<usize> {
    let target = target_of(row, vm).ok()?;
    let token = crate::bridge::vm::token::mint_internal(api, &ctx.paths, &vm.id).await.ok()?;
    let reply = ep.get_health_detail(&target.endpoint, &token, &target.session_token).await.ok()?;
    let detail = reply.detail.filter(|_| reply.status == 200)?;
    Some(detail.spawns.iter().filter(|s| s.status.alive || s.group_alive).count())
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
    /// row, the setup-token and the runtime key sealed (containers), a
    /// keystore dir, a workspace under the root.
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
            let record = VerifiedRecord { image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(), image_version: "1.0".into(), connector: normalize_connector(CONNECTOR), at: at.clone(), dns: DNS_NONE.into(), dns_rule: DNS_RULE, ..VerifiedRecord::default() };
            EgressVerified { records: vec![record], ..EgressVerified::default() }.save(&paths).unwrap();
            std::fs::create_dir_all(paths.probes().parent().unwrap()).unwrap();
            std::fs::write(paths.probes(), format!("{}\n", serde_json::json!({ "probe": "dns-path", "verdict": DNS_NONE, "ts": at }))).unwrap();
            std::fs::create_dir_all(paths.credentials()).unwrap();
            // Containers of an age-shaped blob: what is sealed, never a value.
            let blob = |n: &str| format!("age-encryption.org/v1\n-> x {n}\n--- y\n");
            std::fs::write(paths.setup_token_env(), crate::container::write(blob("token").as_bytes())).unwrap();
            std::fs::write(paths.aws_env(), crate::container::write(blob("key").as_bytes())).unwrap();
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
    /// debug flags and `--add-dir` gone, one `--session-mirror` last), the
    /// environment (the allowlist and the wrapper's names), the workspace's
    /// choice and caps, T0, and the `.active` lock held for the plan's life.
    #[test]
    fn the_prechecks_plan_the_session_and_hold_the_workspace_active() {
        let w = World::new("");
        let sess = w.session(&ARGS);
        let plan = precheck_with(&sess, &w.env(&[]), &a_git_repo).unwrap_or_else(|f| panic!("{}: {}", f.word(), f.line()));
        assert_eq!(plan.argv.first().map(String::as_str), Some("claude"));
        assert_eq!(plan.argv.last().map(String::as_str), Some("--session-mirror"));
        for gone in ["--debug", "--debug-to-stderr", "--add-dir", "/Users/someone/elsewhere"] {
            assert!(!plan.argv.iter().any(|a| a == gone), "{gone} is stripped: {:?}", plan.argv);
        }
        assert!(plan.argv.iter().any(|a| a == "--replay-user-messages"), "the rest is kept");
        assert_eq!(plan.env.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!((plan.env.get("DISABLE_TELEMETRY").map(String::as_str), plan.env.get("DISABLE_ERROR_REPORTING").map(String::as_str)), (Some("1"), Some("1")));
        assert!(!plan.env.contains_key("HOME") && !plan.env.contains_key("AI_ENV_DIR"), "only the allowlist: {:?}", plan.env.keys());
        assert_eq!((plan.run.choice.clone(), plan.run.workspace_cap, plan.run.egress, plan.run.purpose), (Choice::Workspace, true, Egress::Vpc, "session"));
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
        // The pin: not an id (2), no row or terminated (8), not vpc or --shell (9), an image without workspace_v1 (7).
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
        w.vm_row("microvm-pinned001", |r| r.caps = Some(vec![CAP_WORKSPACE_V1.into()]));
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
        CodeoutTrigger::spawn(CodeoutCtx { api, dp, tokens, paths: plan.paths.clone(), cfg: Arc::new(plan.cfg.clone()), target, ws: plan.ws.clone(), capture_settings: false })
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
                d.spawns.push(SpawnDetail { status, started_at: "2026-10-12T08:00:00Z".into(), detach_left_s: Some(900), frozen: false, group_alive: !self.leader_alive });
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
    /// nothing fired. Closed with the fetch running, the suspend waits
    /// through the close's `CLOSE_WAIT` and fires once the fetch is given
    /// up; the fetch let go as the close begins, it fires at the fetch's end.
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
        // Closed with its fetch running: fired once the close gave the fetch up, never before.
        let (row, vm) = closing_vm(&plan, &api).await;
        let trigger = trigger_of(&plan);
        trigger.request();
        let watch = trigger.watch();
        let close = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(suspends(&api), 0, "nothing while the trigger is open");
            let t = std::time::Instant::now();
            let report = trigger.close(CLOSE_WAIT).await;
            assert_eq!(suspends(&api), 0, "nothing until the close gave the fetch up");
            (t.elapsed(), report)
        };
        let ((), (closing, report)) = tokio::join!(suspend_on_close(&plan, 1, &ctx, &api, &api, &row, &vm, &watch), close);
        assert!(closing >= CLOSE_WAIT && report.is_none(), "the fetch given up at the close's bound: {closing:?} {report:?}");
        assert_eq!(suspends(&api), 1, "fired once the trigger was done");
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
                assert_eq!(suspends(&api), 1, "nothing while the fetch runs");
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
        assert_eq!(suspends(&api), 2, "fired at the fetch's end");
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
        let spec = spawn_spec(&plan, &plan.ctx(), &VmRow::default(), &id);
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
            spawn_spec(&plan, &plan.ctx(), &row, &SpawnId::new_v7()).detach_grace_s
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
        assert_eq!(format!("{plan:?}"), "SessionPlan(argc=4, env=1, vm_cwd=/w, resume=false)");
        assert_eq!(plan.credential.get(), None);
    }
}
