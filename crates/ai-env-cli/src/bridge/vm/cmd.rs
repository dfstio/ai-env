//! `ai-env vm …` and `ai-env lab …` (plan S4 §6): load and validate the
//! config, pick the backend — the real SDK client and HTTPS endpoint behind
//! the sealed runtime key (one Touch ID per command), or, in debug builds
//! with the lab knob, the file-backed fake — run one command on a
//! current-thread runtime, print and audit.
//!
//! Output: human lines on stdout, or one JSON document with `--json` (step
//! lines then go to stderr); diagnostics `ai-env: …` on stderr. No output
//! ever carries a session token; an endpoint token is printed only by
//! `vm token --reveal`, alone on stdout. Flags are validated before the
//! runtime key is unsealed, so a usage error never costs a Touch ID.
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::awscli;
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths, REGION};
use crate::bridge::egress::ExpectedEcho;
use crate::bridge::errors::BridgeError;
use crate::bridge::lab::{vm_knobs, VmKnobs};
use crate::bridge::probes;
use crate::bridge::transport::ShellAuth;
use crate::bridge::vm::fake_file::FileFakeMicrovmApi;
use crate::bridge::vm::registry::{self, RowStatus, VmRow};
use crate::bridge::vm::{client, gc, health, lab, owner, run, shell, token};
use crate::cli::{EgressArg, LabCmd, ShellAuthArg, VmCmd};
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::time::{rfc3339_utc, unix_now};
use std::time::Instant;

/// What every `vm`/`lab` command works from.
pub struct Ctx {
    pub paths: Paths,
    pub cfg: BridgeConfig,
    pub knobs: VmKnobs,
}

impl Ctx {
    /// `bridge.toml` must exist and pass the `vm` checks (`[vm]` ranges,
    /// the S5 egress keys, `[aws].credentials`); the lab knobs are read and, when active,
    /// announced; the CLI log is opened (best effort).
    pub fn load() -> Result<Ctx> {
        let paths = Paths::resolve()?;
        let cfg = BridgeConfig::load(&paths)?.ok_or_else(|| CliError::Msg(format!("{} not found: run `make infra-status WRITE=1` (it writes [aws])", paths.config.display())))?;
        cfg.vm.validate()?;
        cfg.aws.validate_egress()?;
        CredentialsSource::parse(&cfg.aws.credentials)?;
        let knobs = vm_knobs();
        announce(&knobs);
        let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
        Ok(Ctx { paths, cfg, knobs })
    }

    /// `[aws].image_arn`, or exit 1 naming the command that writes it.
    pub fn image_arn(&self) -> Result<String> {
        self.cfg.aws.image_arn.clone().ok_or_else(|| CliError::Msg(format!("[aws].image_arn is not set in {}: run `make infra-status WRITE=1`", self.paths.config.display())))
    }

    /// Stamped into every `--json` record: `fake` (the file-backed fake),
    /// `sdk+knobs` (the real service with a lab knob such as scaled polls),
    /// or `sdk` — the only value `make s4-smoke` accepts.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        if self.knobs.fake_api.is_some() {
            "fake"
        } else if !self.knobs.active().is_empty() {
            "sdk+knobs"
        } else {
            "sdk"
        }
    }

    fn poll(&self, p: run::Poll) -> run::Poll {
        p.scaled(self.knobs.backoff_ms)
    }

    fn backoff(&self) -> health::Backoff {
        health::Backoff::HEALTH.scaled(self.knobs.backoff_ms)
    }
}

fn announce(knobs: &VmKnobs) {
    let active = knobs.active();
    if !active.is_empty() {
        eprintln!("ai-env: LAB KNOBS ACTIVE ({}): not the real service (debug build)", active.join(", "));
    }
}

/// The control plane and the endpoint a command talks to.
pub enum Backend {
    Sdk(client::SdkMicrovmApi, health::HttpsEndpoint),
    Fake(FileFakeMicrovmApi),
}

/// Unseal the runtime key (one Touch ID) and connect — or open the fake.
pub async fn backend(store: &Keystore, ctx: &Ctx) -> Result<Backend> {
    if let Some(path) = &ctx.knobs.fake_api {
        if ctx.knobs.fake_api_unseal {
            let creds = client::runtime_credentials(store, &ctx.paths, &ctx.cfg)?;
            eprintln!("ai-env: {} (unsealed; the fake API does not use it)", creds.describe());
        }
        return Ok(Backend::Fake(FileFakeMicrovmApi::open(path)?));
    }
    let creds = client::runtime_credentials(store, &ctx.paths, &ctx.cfg)?;
    eprintln!("ai-env: {}", creds.describe());
    let api = client::connect(&creds).await;
    let ep = health::HttpsEndpoint::new()?;
    Ok(Backend::Sdk(api, ep))
}

/// Run `$body` with `$api`/`$ep` bound to the backend's control plane and
/// endpoint (the same object for the fake).
macro_rules! with_backend {
    ($b:expr, |$api:ident, $ep:ident| $body:expr) => {
        match $b {
            $crate::bridge::vm::cmd::Backend::Sdk(a, e) => {
                let ($api, $ep) = (a, e);
                $body
            }
            $crate::bridge::vm::cmd::Backend::Fake(f) => {
                let ($api, $ep) = (f, f);
                $body
            }
        }
    };
}
pub(crate) use with_backend;

/// The current-thread runtime every `vm`/`lab`/`egress check` command runs on.
pub(crate) fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| CliError::Msg(format!("cannot start the async runtime: {e}")))
}

/// One audit row (`actor=cli` first); a failure to write is a warning, never fatal.
pub fn audit_event(paths: &Paths, event: &str, pairs: &[(&str, String)]) {
    let mut d = audit::detail(pairs);
    d.insert("actor".into(), "cli".into());
    if let Err(e) = audit::append(&paths.audit(), &AuditRow::new(event, None, d)) {
        eprintln!("ai-env: warning: audit row {event} not written: {e}");
    }
}

fn json_out(v: &serde_json::Value) -> Result<()> {
    outln!("{}", serde_json::to_string_pretty(v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    Ok(())
}

/// `3m12s`, `1h04m`, `-` for negative.
#[must_use]
pub fn fmt_secs(secs: i64) -> String {
    if secs < 0 {
        return "-".into();
    }
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// The `vm list` WALL-LEFT cell: `-` for a VM that is gone or going (its
/// row's deadline still counts down, but nothing is left to run).
fn wall_left_cell(state: &str, row: Option<&registry::VmRow>, now: u64) -> String {
    let ended = matches!(state, "TERMINATED" | "TERMINATING") || row.is_some_and(|r| r.status == RowStatus::Terminated);
    if ended {
        return "-".into();
    }
    row.and_then(|r| r.wall_left(now)).map_or_else(|| "-".into(), fmt_secs)
}

fn ms_s(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

/// Refresh the row of `vm` (when there is one) from a `GetMicrovm` answer.
fn refresh_row(paths: &Paths, vm: &VmInfo) {
    let result = registry::update_row(paths, &vm.id, |row| {
        row.state_seen = Some(vm.state.as_str().to_string());
        row.state_seen_at = Some(unix_now());
        row.state_reason.clone_from(&vm.state_reason);
        if row.status != RowStatus::Terminated {
            row.status = run::status_of(&vm.state);
            if row.status == RowStatus::Terminated {
                row.terminated_at = vm.terminated_at_unix.and_then(|t| u64::try_from(t).ok()).or(Some(unix_now()));
                row.terminated_by.get_or_insert_with(|| "platform".into());
            }
        }
    });
    if let Err(e) = result {
        eprintln!("ai-env: warning: cannot update the row of {}: {e}", vm.id);
    }
}

fn warn_plan(plan: &run::RunPlan) {
    for w in &plan.warnings {
        eprintln!("ai-env: warning: {w}");
    }
}

fn gc_hint(items: std::result::Result<Vec<gc::GcItem>, BridgeError>) {
    if let Some(line) = items.ok().as_deref().and_then(gc::hint_line) {
        eprintln!("ai-env: {line}");
    }
}

// ---- `ai-env vm …` ------------------------------------------------------------------------

/// `ai-env vm …`.
pub fn main(store: &Keystore, cmd: VmCmd) -> Result<()> {
    let ctx = Ctx::load()?;
    // Everything that can be refused without AWS is refused before the Touch ID.
    let pre = Pre::check(&ctx, &cmd)?;
    let rt = runtime()?;
    let result = rt.block_on(async {
        let b = backend(store, &ctx).await?;
        with_backend!(&b, |api, ep| dispatch(&ctx, api, ep, cmd, pre).await)
    });
    // `vm shell` leaves a blocking stdin read on the pool after the remote
    // closed; dropping the runtime would wait for the next key press.
    rt.shutdown_background();
    result
}

/// What `main` validated before the backend existed.
enum Pre {
    None,
    Run(Box<run::RunPlan>),
    Gc(gc::GcOpts),
}

impl Pre {
    fn check(ctx: &Ctx, cmd: &VmCmd) -> Result<Pre> {
        Ok(match cmd {
            VmCmd::Run { image, version, max_duration, idle, suspended, no_auto_resume, egress, workspace, new, label, shell, no_execution_role, no_wait, .. } => {
                let flags = run::RunFlags {
                    image: image.clone(),
                    version: version.clone(),
                    max_duration_s: *max_duration,
                    idle_s: *idle,
                    suspended_s: *suspended,
                    no_auto_resume: *no_auto_resume,
                    egress: egress.map(EgressArg::egress),
                    workspace: workspace.clone(),
                    new: *new,
                    label: label.clone(),
                    shell: *shell,
                    no_execution_role: *no_execution_role,
                    wait: !*no_wait,
                    purpose: "operator",
                    imply_internet: false,
                    allow_out_of_range_idle: false,
                };
                if let Some(l) = label {
                    if l.chars().count() > 64 || l.chars().any(char::is_control) {
                        return Err(CliError::Usage("--label: at most 64 printable characters".into()));
                    }
                }
                Pre::Run(Box::new(run::RunPlan::from_cfg(&ctx.cfg, &flags)?))
            }
            VmCmd::Smoke { max_duration, no_execution_role, egress, .. } => {
                let mut plan = run::RunPlan::from_cfg(&ctx.cfg, &smoke_flags(*max_duration, *no_execution_role, egress.map(EgressArg::egress)))?;
                // The smoke's own client token: its failure paths terminate exactly this run's VM.
                plan.client_token = Some(uuid::Uuid::now_v7().to_string());
                Pre::Run(Box::new(plan))
            }
            VmCmd::Terminate { id: Some(id), all: false, yes, .. } => {
                if !registry::is_vm_id(id) {
                    return Err(CliError::Usage(format!("not a microvm id: {id:?}")));
                }
                let row = registry::read_row(&ctx.paths, id)?;
                if row.is_none() {
                    if !*yes {
                        return Err(CliError::Msg(format!("{id} has no row in state/vms (not started by this ai-env): add --yes to terminate it anyway")));
                    }
                    ctx.image_arn()?;
                }
                Pre::None
            }
            VmCmd::Token { port, .. } => {
                token::check_port(*port)?;
                Pre::None
            }
            VmCmd::Gc { yes, include_orphans, .. } => {
                let include_orphans = match include_orphans {
                    Some(a) => Some(gc::parse_age(a).map_err(|e| CliError::Usage(format!("--include-orphans: {e}")))?),
                    None => None,
                };
                Pre::Gc(gc::GcOpts { yes: *yes, include_orphans, probe_health: true })
            }
            VmCmd::Images { managed: false, .. } | VmCmd::List { .. } | VmCmd::Terminate { all: true, .. } => {
                ctx.image_arn()?;
                Pre::None
            }
            _ => Pre::None,
        })
    }
}

/// `vm smoke`: `--egress` as given; without it a configured connector means
/// `vpc`, else the (audited) internet egress.
fn smoke_flags(max_duration: u32, no_execution_role: bool, egress: Option<run::Egress>) -> run::RunFlags {
    run::RunFlags { max_duration_s: Some(max_duration), label: Some("smoke".into()), no_execution_role, egress, wait: true, purpose: "smoke", imply_internet: true, ..run::RunFlags::default() }
}

async fn dispatch<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, cmd: VmCmd, pre: Pre) -> Result<()> {
    match (cmd, pre) {
        (VmCmd::Images { json, managed }, _) => images(ctx, api, json, managed).await,
        (VmCmd::Run { json, .. }, Pre::Run(plan)) => run_cmd(ctx, api, &plan, json).await,
        (VmCmd::List { all, json }, _) => list(ctx, api, all, json).await,
        (VmCmd::Status { id, json }, _) => status(ctx, api, &id, json).await,
        (VmCmd::Health { id, json }, _) => health_cmd(ctx, api, ep, &id, json).await,
        (VmCmd::Token { id, port, minutes, reveal }, _) => token_cmd(ctx, api, &id, port, minutes, reveal).await,
        (VmCmd::Suspend { id, no_wait }, _) => suspend_resume(ctx, api, &id, true, no_wait).await,
        (VmCmd::Resume { id, no_wait }, _) => suspend_resume(ctx, api, &id, false, no_wait).await,
        (VmCmd::Terminate { id, all, yes, no_wait }, _) => terminate(ctx, api, ep, id.as_deref(), all, yes, no_wait).await,
        (VmCmd::Gc { json, .. }, Pre::Gc(opts)) => gc_cmd(ctx, api, ep, &opts, json).await,
        (VmCmd::Shell { id, minutes, auth }, _) => {
            let auth = match auth {
                ShellAuthArg::Header => ShellAuth::Header,
                ShellAuthArg::Subprotocol => ShellAuth::Subprotocol,
            };
            shell::shell(api, &id, minutes, auth).await?;
            Ok(())
        }
        (VmCmd::Smoke { keep, json, .. }, Pre::Run(plan)) => smoke(ctx, api, ep, &plan, keep, json).await,
        _ => Err(CliError::Msg("internal: command/validation mismatch".into())),
    }
}

async fn images<A: MicrovmApi>(ctx: &Ctx, api: &A, json: bool, managed: bool) -> Result<()> {
    if managed {
        let imgs = api.list_managed_images().await?;
        if json {
            return json_out(&serde_json::json!({ "backend": ctx.backend_name(), "managed": imgs.iter().map(|i| i.arn.clone()).collect::<Vec<_>>() }));
        }
        for i in &imgs {
            outln!("{}", i.arn);
        }
        return Ok(());
    }
    let arn = ctx.image_arn()?;
    let img = api.get_image(&arn).await?;
    let mut versions = api.list_image_versions(&arn).await?;
    versions.sort_by_key(|v| std::cmp::Reverse(crate::bridge::doctor::image_version_key(&v.version)));
    let selected = run::resolve_image_version(api, &arn, &ctx.cfg.aws.image_version).await;
    let chosen = selected.as_ref().ok().map(|(v, _)| v.version.clone());
    if let Ok((v, _)) = &selected {
        if let Some(w) = run::memory_warning(ctx.cfg.vm.memory_mib, v) {
            eprintln!("ai-env: warning: {w}");
        }
    }
    if json {
        return json_out(&serde_json::json!({
            "backend": ctx.backend_name(), "image": img, "versions": versions, "selected": chosen,
            "selected_error": selected.as_ref().err().map(ToString::to_string), "note": selected.as_ref().ok().and_then(|(_, n)| n.clone()),
        }));
    }
    outln!("image {}  {}  latest active {}  latest failed {}", img.name, img.state, img.latest_active.as_deref().unwrap_or("-"), img.latest_failed.as_deref().unwrap_or("-"));
    for v in &versions {
        let mark = if chosen.as_deref() == Some(v.version.as_str()) { "  ← vm run" } else { "" };
        let created = v.created_at_unix.and_then(|t| u64::try_from(t).ok()).map_or_else(|| "-".to_string(), rfc3339_utc);
        outln!("  {:<6} {:<11} {:<8} {:>5} MiB  {}{mark}", v.version, v.state, v.status, v.memory_mib.map_or_else(|| "?".into(), |m| m.to_string()), created);
    }
    match &selected {
        Ok((_, Some(note))) => eprintln!("ai-env: {note}"),
        Err(e) => eprintln!("ai-env: warning: [aws].image_version = {:?} does not resolve: {e}", ctx.cfg.aws.image_version),
        _ => {}
    }
    Ok(())
}

fn started_line(row: &VmRow, vm: &VmInfo, run_ms: u64, running_ms: u64) -> String {
    let idle = row.idle.map_or_else(|| "-".into(), |i| format!("{}/{}/{}", i.max_idle_s, i.suspended_s, if i.auto_resume { "auto" } else { "manual" }));
    let wall = row.wall_deadline.map_or_else(|| "-".into(), rfc3339_utc);
    format!(
        "{} {} in {}  endpoint {}  image {}:{}  wall {wall} ({} s)  idle {idle}  egress {}  ingress {}  row state/vms/{}.toml  (run_microvm {} ms)",
        vm.id,
        vm.state.as_str(),
        ms_s(running_ms),
        if vm.endpoint.is_empty() { "-" } else { &vm.endpoint },
        vm.image_arn.rsplit(':').next().unwrap_or(&vm.image_arn),
        vm.image_version,
        vm.max_duration_s,
        row.egress,
        if vm.ingress.is_empty() { "-".to_string() } else { vm.ingress.join(",") },
        vm.id,
        run_ms
    )
}

/// `vm run --egress vpc` (S5): RunMicrovm needs an ACTIVE connector. One
/// line from `state/infra.toml` (the live state `ai-env infra status`
/// records), never a failure: `Some((true, warning))` naming any state but
/// ACTIVE, `None` for ACTIVE, `Some((false, hint))` when no state is
/// recorded for the configured connector (no file, no `connector_state`, the
/// state of another connector, an unreadable file).
fn connector_state_line(paths: &Paths, configured: Option<&str>) -> Option<(bool, String)> {
    let hint = |why: String| Some((false, format!("connector state unknown ({why}): run `make infra-status WRITE=1` to record it (RunMicrovm needs an ACTIVE connector)")));
    let state = match crate::bridge::infra::read_infra_state(paths) {
        Ok(Some(s)) => s,
        Ok(None) => return hint("no state/infra.toml".into()),
        Err(e) => return hint(e.to_string()),
    };
    let norm = crate::bridge::egress::normalize_connector;
    if let (Some(recorded), Some(configured)) = (state.connector_arn.as_deref(), configured) {
        if norm(recorded) != norm(configured) {
            return hint(format!("state/infra.toml records the connector {recorded}, not [aws].egress_connector_arn"));
        }
    }
    match state.connector_state.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => hint("state/infra.toml has no connector_state".into()),
        Some(s) if s.eq_ignore_ascii_case("ACTIVE") => None,
        Some(s) => Some((true, format!("the egress connector is {s} (state/infra.toml): RunMicrovm needs an ACTIVE connector; make connector-status"))),
    }
}

/// `vm run`: a VM the S5 egress gate rejected but could not terminate gets
/// one more TerminateMicrovm (by `policy`; TERMINATED waited for, best
/// effort) before the command exits 9. Accepted, the failure says
/// terminated and names no VM to terminate; refused again, it is left as it
/// is (the row says `mismatch`: `ai-env vm gc --yes` terminates it).
async fn retry_gate_terminate<A: MicrovmApi>(ctx: &Ctx, api: &A, mut f: run::SelectFailure) -> run::SelectFailure {
    let alive = match &f.error {
        BridgeError::EgressMismatch(m) if !m.terminated => (**m).clone(),
        _ => return f,
    };
    match run::request_terminate(api, &ctx.paths, &alive.id, "policy").await {
        Ok(recorded) => {
            if let Err(e) = recorded {
                eprintln!("ai-env: warning: vm row {}: terminated, but the row was not updated: {e}", alive.id);
            }
            if let Err(e) = run::wait_for_state(api, &alive.id, &VmState::Terminated, ctx.poll(run::Poll::SETTLE)).await {
                eprintln!("ai-env: warning: {} not seen TERMINATED: {e}", alive.id);
            }
            eprintln!("ai-env: terminated {} on the second try", alive.id);
            f.error = BridgeError::egress_mismatch(&alive.id, alive.expected, alive.echoed, true);
            f.started = None;
        }
        Err(e) => eprintln!("ai-env: warning: terminating {} failed again: {e} (its row says egress mismatch: `ai-env vm gc --yes` terminates it)", alive.id),
    }
    f
}

async fn run_cmd<A: MicrovmApi>(ctx: &Ctx, api: &A, plan: &run::RunPlan, json: bool) -> Result<()> {
    warn_plan(plan);
    if plan.egress == run::Egress::Vpc {
        match connector_state_line(&ctx.paths, plan.egress_connectors.first().map(String::as_str)) {
            Some((true, w)) => eprintln!("ai-env: warning: {w}"),
            Some((false, h)) => eprintln!("ai-env: {h}"),
            None => {}
        }
    }
    let selected = match run::select_vm_detailed(api, &ctx.paths, plan, ctx.poll(run::Poll::RUNNING)).await {
        Ok(s) => Ok(s),
        Err(f) => Err(retry_gate_terminate(ctx, api, f).await),
    };
    let selected = selected.map_err(|f| {
        let hint = match (&f.started, &f.kept_pending) {
            (Some(id), _) => format!("{id} may still be running: ai-env vm terminate {id}"),
            (None, Some(p)) => format!("the pending row {} is kept: ai-env vm gc", p.stem()),
            (None, None) => String::new(),
        };
        let e: CliError = f.error.into();
        if hint.is_empty() {
            e
        } else {
            crate::bridge::creds::with_note(e, &hint)
        }
    })?;
    let (row, vm, reused, resumed, run_ms, running_ms) = match selected {
        run::Selected::Started { row, vm, run_ms, running_ms } => (row, vm, false, false, run_ms, running_ms),
        run::Selected::Reused { row, vm, resumed } => (row, vm, true, resumed, 0, 0),
    };
    if json {
        json_out(&serde_json::json!({
            "backend": ctx.backend_name(), "id": vm.id, "state": vm.state.as_str(), "endpoint": vm.endpoint, "image_version": vm.image_version,
            "reused": reused, "resumed": resumed, "run_ms": run_ms, "running_ms": running_ms, "ingress": vm.ingress, "egress": vm.egress, "row": registry::view(&row),
        }))?;
    } else if reused {
        let left = row.wall_left(unix_now()).map_or_else(|| "-".into(), fmt_secs);
        outln!("reusing {} ({}{}, wall left {left})", vm.id, vm.state.as_str(), if resumed { ", resumed" } else { "" });
    } else {
        outln!("{}", started_line(&row, &vm, run_ms, running_ms));
    }
    let items = gc::reconcile_local(api, &ctx.paths, &plan.image_arn).await;
    if ctx.cfg.vm.auto_gc {
        auto_gc(ctx, api, items.as_deref().unwrap_or_default(), &vm.id).await;
    } else {
        gc_hint(items);
    }
    Ok(())
}

/// `[vm].auto_gc = true` (plan S4 D17): after a `vm run`, terminate the
/// registry VMs whose wall passed or is under a minute away — never the VM
/// this run just started or reused, never an orphan, never another owner's.
async fn auto_gc<A: MicrovmApi>(ctx: &Ctx, api: &A, items: &[gc::GcItem], just_selected: &str) {
    for id in items.iter().filter(|i| i.class == gc::GcClass::RegistryExpired).filter_map(|i| i.id.as_deref()).filter(|id| *id != just_selected) {
        match run::terminate_and_record(api, &ctx.paths, id, "gc-expired", None).await {
            Ok(_) => eprintln!("ai-env: auto_gc: terminated {id} (its wall passed or is under a minute away)"),
            Err(e) => eprintln!("ai-env: auto_gc: could not terminate {id}: {e}"),
        }
    }
}

async fn list<A: MicrovmApi>(ctx: &Ctx, api: &A, all: bool, json: bool) -> Result<()> {
    let arn = ctx.image_arn()?;
    let listing = api.list(Some(&arn)).await?;
    let rows = registry::list_rows(&ctx.paths)?;
    let now = unix_now();
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for s in &listing {
        seen.insert(s.id.clone());
        let row = rows.iter().find(|r| r.id == s.id);
        if s.state == VmState::Terminated && !all {
            continue;
        }
        out.push((s.id.clone(), s.state.as_str().to_string(), s.started_at_unix.and_then(|t| u64::try_from(t).ok()), row.cloned(), if row.is_some() { "both" } else { "list" }));
    }
    for r in &rows {
        if r.is_pending_row() || seen.contains(&r.id) {
            if r.is_pending_row() {
                out.push((r.stem(), "PENDING-ROW".into(), None, Some(r.clone()), "row"));
            }
            continue;
        }
        if r.status == RowStatus::Terminated && !all {
            continue;
        }
        out.push((r.id.clone(), format!("({})", r.status.as_str()), r.started_at, Some(r.clone()), "row"));
    }
    if json {
        let items: Vec<serde_json::Value> = out
            .iter()
            .map(|(id, state, started, row, source)| serde_json::json!({ "id": id, "state": state, "started_at": started, "source": source, "row": row.as_ref().map(registry::view) }))
            .collect();
        return json_out(&serde_json::json!({ "backend": ctx.backend_name(), "vms": items }));
    }
    if out.is_empty() {
        outln!("no VMs{}", if all { "" } else { " (TERMINATED hidden; --all shows them)" });
    } else {
        outln!("{:<46} {:<12} {:>7} {:>9}  {:<24} SOURCE", "ID", "STATE", "AGE", "WALL-LEFT", "WHERE");
        for (id, state, started, row, source) in &out {
            let age = started.map_or_else(|| "-".into(), |t| fmt_secs(i64::try_from(now.saturating_sub(t)).unwrap_or(i64::MAX)));
            let left = wall_left_cell(state, row.as_ref(), now);
            let place = row.as_ref().and_then(|r| r.workspace.clone().or_else(|| r.label.clone())).unwrap_or_else(|| "-".into());
            outln!("{id:<46} {state:<12} {age:>7} {left:>9}  {place:<24} {source}");
        }
    }
    gc_hint(gc::reconcile_local(api, &ctx.paths, &arn).await);
    Ok(())
}

async fn status<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str, json: bool) -> Result<()> {
    let vm = api.get(id).await?;
    refresh_row(&ctx.paths, &vm);
    if json {
        let row = registry::read_row(&ctx.paths, id).ok().flatten();
        return json_out(&serde_json::json!({ "backend": ctx.backend_name(), "vm": vm, "row": row.as_ref().map(registry::view) }));
    }
    let started = vm.started_at_unix.and_then(|t| u64::try_from(t).ok());
    outln!("{}  {}{}", vm.id, vm.state.as_str(), vm.state_reason.as_deref().map(|r| format!(" ({r})")).unwrap_or_default());
    outln!("  endpoint   {}", if vm.endpoint.is_empty() { "-" } else { &vm.endpoint });
    outln!("  image      {} version {}", vm.image_arn, vm.image_version);
    outln!("  started    {}  max duration {} s", started.map_or_else(|| "-".into(), rfc3339_utc), vm.max_duration_s);
    outln!("  idle       {}", vm.idle.map_or_else(|| "(not echoed)".into(), |i| format!("max idle {} s, suspended {} s, auto-resume {}", i.max_idle_s, i.suspended_s, i.auto_resume)));
    outln!("  ingress    {}", if vm.ingress.is_empty() { "-".into() } else { vm.ingress.join(", ") });
    outln!("  egress     {}", if vm.egress.is_empty() { "-".into() } else { vm.egress.join(", ") });
    outln!("  role       {}", vm.execution_role_arn.as_deref().unwrap_or("-"));
    if let Some(t) = vm.terminated_at_unix.and_then(|t| u64::try_from(t).ok()) {
        outln!("  terminated {}", rfc3339_utc(t));
    }
    Ok(())
}

async fn health_cmd<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, id: &str, json: bool) -> Result<()> {
    let (h, stats) = health::read_health(api, ep, &ctx.paths, id, ctx.backoff()).await?;
    if stats.resumed_note {
        eprintln!("ai-env: note: {id} was SUSPENDED; this request resumed it");
    }
    if json {
        return json_out(&serde_json::json!({ "backend": ctx.backend_name(), "id": id, "health": h, "attempts": stats.attempts, "elapsed_ms": stats.elapsed_ms, "reminted": stats.reminted }));
    }
    outln!(
        "ok shim {} claude {} run_hook_seen {} owner {} created {} boot_nonce {} uptime {} s (HTTP 200, {} ms, {} attempt{})",
        h.shim_version,
        h.claude_version.as_deref().unwrap_or("-"),
        if h.run_hook_seen { "yes" } else { "no" },
        h.owner.as_deref().unwrap_or("-"),
        h.created.as_deref().unwrap_or("-"),
        h.boot_nonce.as_deref().unwrap_or("-"),
        h.uptime_s,
        stats.elapsed_ms,
        stats.attempts,
        if stats.attempts == 1 { "" } else { "s" }
    );
    Ok(())
}

async fn token_cmd<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str, port: u16, minutes: u16, reveal: bool) -> Result<()> {
    let tok = token::mint(api, &ctx.paths, id, port, minutes).await?;
    audit_event(&ctx.paths, "vm_token", &[("id", id.to_string()), ("port", port.to_string()), ("minutes", minutes.to_string()), ("revealed", reveal.to_string())]);
    if reveal {
        eprintln!("ai-env: warning: this token opens port {port} of {id} until {}; it is printed alone on stdout — do not paste it anywhere else", rfc3339_utc(tok.expires_at_unix));
        outln!("{}", tok.value()?.expose());
    } else {
        outln!("Port({port}) token for {id} expires {}; value hidden (--reveal prints it alone on stdout)", rfc3339_utc(tok.expires_at_unix));
    }
    Ok(())
}

async fn suspend_resume<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str, suspend: bool, no_wait: bool) -> Result<()> {
    let start = Instant::now();
    if suspend {
        api.suspend(id).await?;
    } else {
        api.resume(id).await?;
    }
    audit_event(&ctx.paths, if suspend { "vm_suspend" } else { "vm_resume" }, &[("id", id.to_string())]);
    let want = if suspend { VmState::Suspended } else { VmState::Running };
    if no_wait {
        outln!("{id}: {} requested", if suspend { "suspend" } else { "resume" });
        return Ok(());
    }
    let vm = run::wait_for_state(api, id, &want, ctx.poll(run::Poll::SETTLE)).await?;
    refresh_row(&ctx.paths, &vm);
    outln!("{id} {} in {}", vm.state.as_str(), ms_s(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)));
    Ok(())
}

async fn terminate<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, id: Option<&str>, all: bool, yes: bool, no_wait: bool) -> Result<()> {
    let wait = (!no_wait).then(|| ctx.poll(run::Poll::SETTLE));
    if all {
        let arn = ctx.image_arn()?;
        let items = gc::terminate_all_plan(api, ep, &ctx.paths, &arn).await?;
        for i in items.iter().filter(|i| i.action == gc::GcAction::Keep) {
            eprintln!("ai-env: skipping {} ({}: {})", i.id.as_deref().unwrap_or("-"), i.class.name(), i.detail);
        }
        let targets: Vec<String> = items.iter().filter(|i| i.action == gc::GcAction::Terminate).filter_map(|i| i.id.clone()).collect();
        if targets.is_empty() {
            outln!("nothing to terminate");
            return Ok(());
        }
        for t in &targets {
            outln!("{t}");
        }
        if !yes {
            return Err(CliError::Msg(format!("nothing terminated: add --yes to terminate these {} VM(s)", targets.len())));
        }
        // Every target is tried; the failures are named at the end.
        let mut failed = Vec::new();
        for t in &targets {
            let start = Instant::now();
            match run::terminate_and_record(api, &ctx.paths, t, "operator", wait).await {
                Ok(_) if wait.is_none() => outln!("{t} terminate requested"),
                Ok(_) => outln!("{t} terminated ({})", ms_s(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))),
                Err(e) => {
                    eprintln!("ai-env: {t}: {e}");
                    failed.push(t.clone());
                }
            }
        }
        if !failed.is_empty() {
            return Err(CliError::Aws(format!("{} of {} VM(s) not confirmed terminated: {}", failed.len(), targets.len(), failed.join(", "))));
        }
        return Ok(());
    }
    let id = id.ok_or_else(|| CliError::Usage("vm terminate needs an id or --all".into()))?;
    let row = registry::read_row(&ctx.paths, id)?;
    // A VM with a row is this ai-env's (whatever `--image` it ran); a row-less
    // one must run the configured image (Pre::check required --yes and the ARN).
    let own_image = row.as_ref().map(|r| r.image_arn.clone()).filter(|a| !a.is_empty()).or_else(|| ctx.cfg.aws.image_arn.clone());
    match api.get(id).await {
        Ok(vm) => match &own_image {
            Some(arn) if &vm.image_arn != arn => {
                return Err(BridgeError::Policy(format!("{id} runs image {}, not {arn}; this ai-env terminates only its own image's VMs", vm.image_arn)).into());
            }
            Some(_) => {}
            None => return Err(BridgeError::Policy(format!("{id}: no image to compare with ([aws].image_arn is not set and there is no row)")).into()),
        },
        Err(BridgeError::VmNotFound(_)) if row.is_some() => {}
        Err(e) => return Err(e.into()),
    }
    let start = Instant::now();
    let vm = run::terminate_and_record(api, &ctx.paths, id, "operator", wait).await?;
    if wait.is_none() {
        outln!("{id} terminate requested");
    } else {
        let state = vm.as_ref().map_or("TERMINATED", |v| v.state.as_str());
        outln!("{id} {state} ({})", ms_s(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)));
    }
    Ok(())
}

async fn gc_cmd<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, opts: &gc::GcOpts, json: bool) -> Result<()> {
    let arn = ctx.image_arn()?;
    let report = gc::gc(api, ep, &ctx.paths, &arn, opts).await?;
    for e in &report.errors {
        tracing::warn!("vm gc: {e}");
    }
    if json {
        let items: Vec<serde_json::Value> = report
            .items
            .iter()
            .map(|i| serde_json::json!({ "class": i.class.name(), "id": i.id, "stem": i.stem, "age_s": i.age_s, "detail": i.detail, "action": i.action.name() }))
            .collect();
        json_out(&serde_json::json!({
            "backend": ctx.backend_name(), "yes": opts.yes, "items": items, "terminated": report.terminated, "adopted": report.adopted,
            "removed": report.removed, "marked": report.marked, "errors": report.errors, "egress_mismatches": report.mismatches,
        }))?;
    } else {
        for i in &report.items {
            let who = i.id.clone().or_else(|| i.stem.clone()).unwrap_or_else(|| "-".into());
            let age = i.age_s.map_or_else(|| "-".into(), |a| fmt_secs(i64::try_from(a).unwrap_or(i64::MAX)));
            outln!("{:<16} {who:<46} {age:>7}  {} → {}", i.class.name(), i.detail, i.action.name());
        }
        let acted = report.terminated + report.adopted + report.removed + report.marked;
        // What `--yes` would act on, and your own orphans (only with --include-orphans AGE).
        let actionable = report.items.iter().filter(|i| matches!(i.class, gc::GcClass::RegistryExpired | gc::GcClass::RegistryGone | gc::GcClass::Adopt | gc::GcClass::PendingStale | gc::GcClass::TerminatedOld)).count();
        let orphans = report.items.iter().filter(|i| i.class == gc::GcClass::OrphanMine).count();
        if !opts.yes && actionable == 0 && orphans == 0 {
            outln!("nothing to terminate");
        } else if !opts.yes {
            outln!("dry run: {actionable} item(s) for --yes; {orphans} own orphan(s) for --yes --include-orphans AGE");
        } else if acted == 0 && report.errors.is_empty() {
            outln!("nothing to terminate");
        } else {
            outln!("terminated {}, adopted {}, marked terminated {}, removed {}", report.terminated, report.adopted, report.marked, report.removed);
        }
    }
    if report.errors.is_empty() {
        Ok(())
    } else {
        for e in &report.errors {
            eprintln!("ai-env: vm gc: {e}");
        }
        if report.mismatches > 0 {
            // A VM that failed the S5 egress gate is a policy finding (exit 9), whatever else failed.
            return Err(CliError::Policy(format!("vm gc: {} VM(s) failed the egress gate; {} action(s) failed", report.mismatches, report.errors.len())));
        }
        Err(CliError::Aws(format!("vm gc: {} action(s) failed", report.errors.len())))
    }
}

// ---- smoke ----------------------------------------------------------------------------------

/// The T4.1 budgets.
const RUNNING_BUDGET_MS: u64 = 10_000;
const HEALTH_BUDGET_MS: u64 = 5_000;
const TERMINATED_BUDGET_MS: u64 = 30_000;

struct Steps {
    json: bool,
}

impl Steps {
    fn say(&self, line: &str) -> Result<()> {
        if self.json {
            eprintln!("smoke: {line}");
        } else {
            outln!("smoke: {line}");
        }
        Ok(())
    }
}

fn ms_since(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn smoke<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: &run::RunPlan, keep: bool, json: bool) -> Result<()> {
    warn_plan(plan);
    let steps = Steps { json };
    let t0_unix = unix_now();
    steps.say(&format!(
        "image {} ({}), max duration {} s, idle {}/{}/{}, egress {}",
        plan.image_arn.rsplit(':').next().unwrap_or(&plan.image_arn),
        plan.want_version,
        plan.max_duration_s,
        plan.idle.max_idle_s,
        plan.idle.suspended_s,
        if plan.idle.auto_resume { "auto" } else { "manual" },
        plan.egress
    ))?;
    let flow = smoke_flow(ctx, api, ep, plan, &steps);
    let outcome = tokio::select! {
        r = flow => r,
        _ = tokio::signal::ctrl_c() => Err(SmokeFail { id: None, kept_pending: None, gate: false, error: CliError::Cancelled }),
    };
    // The rows this smoke may have written carry its own client token, never another run's.
    let own_token = plan.client_token.as_deref().unwrap_or_default();
    let (id, record) = match outcome {
        Ok(ok) => (ok.0, Some(ok.1)),
        Err(fail) => {
            // Terminate whatever this smoke started (plan S4 D26), then report the failure.
            let id = match (fail.id.clone(), &fail.kept_pending) {
                (Some(id), _) => Some((id, fail.gate)),
                (None, Some(pending)) => adopt(ctx, api, ep, pending, t0_unix).await,
                (None, None) => sweep_own(ctx, api, ep, own_token, t0_unix).await,
            };
            match id {
                // A VM that failed the S5 egress gate is never kept, --keep or not.
                Some((id, true)) => match run::terminate_and_record(api, &ctx.paths, &id, "policy", Some(ctx.poll(run::Poll::SETTLE))).await {
                    Ok(_) => eprintln!("smoke: terminated {id}: it failed the egress gate{}", if keep { " (--keep never keeps such a VM)" } else { "" }),
                    Err(e) => eprintln!("smoke: could not terminate {id}, which failed the egress gate: {e} — run: ai-env vm terminate {id} (or ai-env vm gc --yes)"),
                },
                Some((id, false)) if keep => eprintln!("smoke: --keep: {id} left running (ai-env vm terminate {id})"),
                Some((id, false)) => match run::terminate_and_record(api, &ctx.paths, &id, "smoke", Some(ctx.poll(run::Poll::SETTLE))).await {
                    Ok(_) => eprintln!("smoke: terminated {id} after the failure"),
                    Err(e) => eprintln!("smoke: could not terminate {id}: {e} — run: ai-env vm terminate {id}"),
                },
                None => {}
            }
            return Err(fail.error);
        }
    };
    let mut record = record.unwrap_or_default();
    if keep {
        steps.say(&format!("--keep: {id} left running (ai-env vm terminate {id})"))?;
    } else {
        let t = Instant::now();
        run::terminate_and_record(api, &ctx.paths, &id, "smoke", Some(ctx.poll(run::Poll::SETTLE))).await?;
        let ms = ms_since(t);
        steps.say(&format!("terminate → TERMINATED after {}", ms_s(ms)))?;
        record.insert("terminate_to_terminated_ms".into(), ms.into());
    }
    // The T4.1 budgets are wall-clock facts of the real service: with a lab
    // knob (the file fake, scaled polls) they are not judged.
    let judged = ctx.knobs.active().is_empty();
    let within = !judged
        || (record.get("run_to_running_ms").and_then(serde_json::Value::as_u64).is_some_and(|m| m <= RUNNING_BUDGET_MS)
            && record.get("running_to_health_ms").and_then(serde_json::Value::as_u64).is_some_and(|m| m <= HEALTH_BUDGET_MS)
            && record.get("terminate_to_terminated_ms").and_then(serde_json::Value::as_u64).is_none_or(|m| m <= TERMINATED_BUDGET_MS));
    record.insert("within_budget".into(), if judged { within.into() } else { serde_json::Value::Null });
    record.insert("ok".into(), within.into());
    let summary = format!(
        "run→RUNNING {}, RUNNING→/health {}, terminate→TERMINATED {}",
        record.get("run_to_running_ms").and_then(serde_json::Value::as_u64).map_or_else(|| "-".into(), ms_s),
        record.get("running_to_health_ms").and_then(serde_json::Value::as_u64).map_or_else(|| "-".into(), ms_s),
        record.get("terminate_to_terminated_ms").and_then(serde_json::Value::as_u64).map_or_else(|| "-".into(), ms_s)
    );
    if json {
        outln!("{}", serde_json::Value::Object(record).to_string());
    } else {
        outln!("smoke {}: {summary}", if within { "ok" } else { "OVER BUDGET" });
    }
    gc_hint(gc::reconcile_local(api, &ctx.paths, &plan.image_arn).await);
    if within {
        Ok(())
    } else {
        Err(CliError::Msg(format!("smoke over budget (RUNNING ≤ 10 s, /health ≤ 5 s, TERMINATED ≤ 30 s): {summary}")))
    }
}

/// Why the smoke flow stopped, and what it may have left running.
struct SmokeFail {
    /// The VM this smoke started (terminate it).
    id: Option<String>,
    /// The pending row kept after two ambiguous RunMicrovm failures (adopt, then terminate).
    kept_pending: Option<Box<VmRow>>,
    /// The VM failed the S5 egress gate: terminated (`policy`) whatever `--keep` says.
    gate: bool,
    error: CliError,
}

impl From<BridgeError> for SmokeFail {
    fn from(e: BridgeError) -> Self {
        SmokeFail { id: None, kept_pending: None, gate: false, error: e.into() }
    }
}

fn fail_with(id: &str) -> impl FnOnce(BridgeError) -> SmokeFail + '_ {
    move |e| SmokeFail { id: Some(id.to_string()), kept_pending: None, gate: false, error: e.into() }
}

/// run → RUNNING → /health, with every assertion of T4.1; returns the VM id
/// and the timing record (termination is the caller's). The RUNNING answer's
/// egress is asserted first, before any request reaches the VM: anything but
/// exactly what the egress requires goes through the gate's reject path
/// (audit `vm_egress_mismatch` via `run`, terminated by `policy`, exit 9).
async fn smoke_flow<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: &run::RunPlan, steps: &Steps) -> std::result::Result<(String, serde_json::Map<String, serde_json::Value>), SmokeFail> {
    let selected = run::select_vm_detailed(api, &ctx.paths, plan, ctx.poll(run::Poll::RUNNING)).await.map_err(|f| {
        let gate = matches!(f.error, BridgeError::EgressMismatch(_));
        SmokeFail { id: f.started, kept_pending: f.kept_pending, gate, error: f.error.into() }
    })?;
    let run::Selected::Started { row, vm, run_ms, running_ms } = selected else {
        return Err(SmokeFail { id: None, kept_pending: None, gate: false, error: CliError::Msg("smoke reused a VM (internal)".into()) });
    };
    let id = vm.id.clone();
    let say = |l: String| steps.say(&l).map_err(|e| SmokeFail { id: Some(id.clone()), kept_pending: None, gate: false, error: e });
    say(format!("run_microvm → {id} ({} ms); RUNNING after {}", run_ms, ms_s(running_ms)))?;
    // The S5 echo gate passed at RunMicrovm; the RUNNING answer must still echo exactly the same.
    let expected = ExpectedEcho::for_plan(plan.egress, &plan.egress_connectors);
    let egress_expected: Vec<String> = expected.as_ref().map(|e| e.connectors().to_vec()).unwrap_or_default();
    let egress_ok = expected.as_ref().is_some_and(|e| e.matches(&vm.egress, run::echo_alias(&ctx.paths, plan.egress, &plan.egress_connectors).as_ref()));
    let shown = |l: &[String]| if l.is_empty() { "(none echoed)".to_string() } else { l.join(", ") };
    say(format!("egress {} ({} egress: {})", shown(&vm.egress), plan.egress, if egress_ok { "exactly as required".to_string() } else { format!("NOT exactly {}", shown(&egress_expected)) }))?;
    if !egress_ok {
        let e = run::reject_echo(api, &ctx.paths, &id, expected.as_ref(), &vm.egress, "run", plan.purpose).await;
        let alive = matches!(&e, BridgeError::EgressMismatch(m) if !m.terminated);
        return Err(SmokeFail { id: alive.then(|| id.clone()), kept_pending: None, gate: true, error: e.into() });
    }
    let mut problems = Vec::new();
    if vm.max_duration_s != plan.max_duration_s as i32 {
        problems.push(format!("max duration echoed {} (sent {})", vm.max_duration_s, plan.max_duration_s));
    }
    match vm.idle {
        Some(i) if i == plan.idle => {}
        Some(i) => problems.push(format!("idle policy echoed {i:?} (sent {:?})", plan.idle)),
        None => problems.push("idle policy not echoed".into()),
    }
    let t = Instant::now();
    let (h, stats) = health::read_health(api, ep, &ctx.paths, &id, ctx.backoff()).await.map_err(fail_with(&id))?;
    let health_ms = ms_since(t);
    say(format!(
        "/health 200 after {} ({} attempt{}): claude {}, shim {}, owner {}, run_hook_seen {}",
        ms_s(health_ms),
        stats.attempts,
        if stats.attempts == 1 { "" } else { "s" },
        h.claude_version.as_deref().unwrap_or("-"),
        h.shim_version,
        h.owner.as_deref().unwrap_or("-"),
        if h.run_hook_seen { "yes" } else { "no" }
    ))?;
    if !h.run_hook_seen {
        problems.push("run_hook_seen is false".into());
    }
    if h.owner.as_deref() != Some(row.owner.as_str()) || row.owner != owner() {
        problems.push(format!("owner {:?} (expected {})", h.owner, owner()));
    }
    if h.created.as_deref() != Some(row.created.as_str()) {
        problems.push(format!("created {:?} (the payload said {})", h.created, row.created));
    }
    if h.boot_nonce.as_deref().is_none_or(str::is_empty) {
        problems.push("no boot_nonce".into());
    }
    if h.microvm_id.as_deref() != Some(id.as_str()) {
        problems.push(format!("microvm_id {:?} (expected {id})", h.microvm_id));
    }
    let expected_claude = crate::bridge::infra::read_infra_state(&ctx.paths).ok().flatten().and_then(|s| s.claude_version);
    match (&expected_claude, &h.claude_version) {
        (Some(want), Some(got)) if want != got => problems.push(format!("claude {got} (the image lock says {want})")),
        (_, None) => problems.push("/health reports no claude version (the /ready probe never succeeded)".into()),
        (None, Some(_)) => eprintln!("smoke: warning: state/infra.toml has no claude version to compare (make infra-status WRITE=1)"),
        _ => {}
    }
    say(format!("ingress {}", if vm.ingress.is_empty() { "(none echoed)".to_string() } else { vm.ingress.join(", ") }))?;
    if !problems.is_empty() {
        return Err(SmokeFail { id: Some(id.clone()), kept_pending: None, gate: false, error: CliError::Msg(format!("smoke assertions failed: {}", problems.join("; "))) });
    }
    let mut rec = serde_json::Map::new();
    rec.insert("backend".into(), ctx.backend_name().into());
    rec.insert("ts".into(), rfc3339_utc(unix_now()).into());
    rec.insert("id".into(), id.clone().into());
    rec.insert("image_version".into(), vm.image_version.clone().into());
    rec.insert("endpoint".into(), vm.endpoint.clone().into());
    rec.insert("owner".into(), row.owner.clone().into());
    rec.insert("created".into(), row.created.clone().into());
    rec.insert("max_duration_s".into(), vm.max_duration_s.into());
    rec.insert("idle".into(), serde_json::to_value(vm.idle).unwrap_or_default());
    rec.insert("ingress".into(), vm.ingress.clone().into());
    rec.insert("egress".into(), vm.egress.clone().into());
    rec.insert("egress_expected".into(), egress_expected.into());
    rec.insert("egress_ok".into(), egress_ok.into());
    rec.insert("execution_role".into(), vm.execution_role_arn.is_some().into());
    rec.insert("run_call_ms".into(), run_ms.into());
    rec.insert("run_to_running_ms".into(), running_ms.into());
    rec.insert("running_to_health_ms".into(), health_ms.into());
    rec.insert("health_attempts".into(), stats.attempts.into());
    rec.insert("health".into(), serde_json::to_value(&h).unwrap_or_default());
    Ok((id, rec))
}

/// The VM a kept pending row stands for, by the adoption sweep, and whether
/// it failed the S5 egress gate: `Adopted` is terminated by the caller, and
/// so is a VM the sweep's egress gate rejected but could not terminate (by
/// `policy`, `--keep` or not); `NoMatch` and `Unresolved` leave the row for
/// `ai-env vm gc` and never terminate anything (the VMs may be another
/// run's).
async fn adopt<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, pending: &VmRow, since_unix: u64) -> Option<(String, bool)> {
    match run::adopt_after_ambiguous_for(api, ep, &ctx.paths, pending, since_unix, ctx.poll(run::Poll::RUNNING), "smoke").await {
        Ok(run::Adoption::Adopted(id)) => {
            eprintln!("smoke: the ambiguous RunMicrovm started {id} (adopted)");
            Some((id, false))
        }
        Err(BridgeError::EgressMismatch(m)) if !m.terminated => {
            eprintln!("smoke: the ambiguous RunMicrovm started {}, which failed the egress gate and is not confirmed terminated", m.id);
            Some((m.id.clone(), true))
        }
        Err(e @ BridgeError::EgressMismatch(_)) => {
            eprintln!("smoke: the ambiguous RunMicrovm's VM failed the egress gate: {e}");
            None
        }
        Ok(run::Adoption::NoMatch) => {
            eprintln!("smoke: no VM of this run is visible; the pending row {} is kept for `ai-env vm gc`", pending.stem());
            None
        }
        Ok(run::Adoption::Unresolved(ids)) => {
            eprintln!("smoke: VMs that may be this run's could not be asked ({}); nothing terminated — run `ai-env vm gc` later", ids.join(", "));
            None
        }
        Err(e) => {
            eprintln!("smoke: the adoption sweep failed: {e}; run `ai-env vm gc`");
            None
        }
    }
}

/// After a failure without a VM id or kept row, and after Ctrl-C: the VM of
/// THIS smoke, found only through the rows carrying its own client token
/// (an id row → that VM, failed the egress gate when its row says
/// `mismatch`; a pending row → the adoption sweep). Another run's rows never
/// match, and a failure before the pending row was written (MaxConcurrent, a
/// busy lock) finds nothing.
async fn sweep_own<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, client_token: &str, since_unix: u64) -> Option<(String, bool)> {
    if client_token.is_empty() {
        return None;
    }
    let rows = registry::list_rows(&ctx.paths).ok()?;
    let mine: Vec<&VmRow> = rows.iter().filter(|r| r.client_token == client_token).collect();
    if let Some(r) = mine.iter().find(|r| !r.is_pending_row() && r.status != RowStatus::Terminated) {
        return Some((r.id.clone(), r.egress_gate.as_deref() == Some(registry::GATE_MISMATCH)));
    }
    match mine.iter().find(|r| r.is_pending_row()) {
        Some(p) => adopt(ctx, api, ep, p, since_unix).await,
        None => None,
    }
}

// ---- `ai-env lab …` -------------------------------------------------------------------------

/// `ai-env lab …`.
pub fn lab_main(store: &Keystore, cmd: LabCmd) -> Result<()> {
    match cmd {
        LabCmd::List { json } => probes::cmd_list(json),
        LabCmd::Show { probe, json } => probes::cmd_show(&probe, json),
        LabCmd::Run { probe, id, log, manual, note } => lab_run(store, &probe, id.as_deref(), log.as_deref(), manual.as_deref(), note),
    }
}

/// The log probes read at most this much of a `make logs` capture.
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

fn read_log(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    f.take(MAX_LOG_BYTES).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn with_note(derived: String, user: Option<&String>) -> Option<String> {
    Some(match user {
        Some(u) => format!("{derived}; {u}"),
        None => derived,
    })
}

fn lab_run(store: &Keystore, name: &str, id: Option<&str>, log: Option<&std::path::Path>, manual: Option<&str>, note: Option<String>) -> Result<()> {
    let spec = probes::spec(name).ok_or_else(|| CliError::Usage(format!("unknown probe {name:?} (ai-env lab list)")))?;
    if !matches!(spec.stage, "S4" | "S5") {
        return Err(CliError::Usage(format!("{name} is a {} probe, recorded by: {}", spec.stage, spec.recorded_by)));
    }
    let paths = Paths::resolve()?;
    let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
    // Refuse arguments a probe does not take before anything (a Touch ID, a VM) happens.
    let takes_log = matches!(name, "hooks-port" | "hooks-source-ip" | "runtime-env" | "disk-budget" | "snapshot-uniqueness" | "cloudtrail-payload");
    if log.is_some() && !takes_log {
        return Err(CliError::Usage(format!("{name} does not read a log (--log is for hooks-port, hooks-source-ip, runtime-env, disk-budget, snapshot-uniqueness and cloudtrail-payload)")));
    }
    if id.is_some() && !matches!(name, "cloudtrail-payload" | "connector-pending") {
        return Err(CliError::Usage(format!("{name} takes no positional argument (cloudtrail-payload takes a VM id, connector-pending a connector ARN)")));
    }
    if name == "connector-pending" && manual.is_none() {
        let Some(arn) = id else {
            return Err(CliError::Usage("connector-pending needs the ARN of a connector that is not ACTIVE yet (make connector-probe CONFIRM=create-probe-connector creates one and runs this)".into()));
        };
        if !crate::bridge::config::is_connector_arn(arn) {
            return Err(CliError::Usage(format!("connector-pending: {arn:?} is not arn:aws:lambda:{REGION}:<account>:network-connector:<name>[:<version>]")));
        }
    }
    if manual.is_some() && name == "dns-path" {
        // The credential gate trusts the newest dns-path row: only the live probe writes one
        // ([egress].accept_platform_dns is the recorded acceptance of a platform resolver).
        return Err(CliError::Usage("dns-path is recorded only by the live probe (accept a platform resolver with [egress].accept_platform_dns = true)".into()));
    }
    if let Some(v) = manual {
        if v.trim().is_empty() || v.len() > 200 || v.chars().any(char::is_control) {
            return Err(CliError::Usage("--manual: 1–200 printable characters".into()));
        }
        return probes::record(&paths, &probes::stamped(&paths, spec, v.trim(), Some(note.unwrap_or_else(|| "recorded by hand".into()))));
    }
    let log_probe = matches!(name, "hooks-port" | "hooks-source-ip" | "runtime-env" | "disk-budget");
    if log_probe || (name == "snapshot-uniqueness" && log.is_some()) {
        let Some(file) = log else {
            return Err(CliError::Usage(format!("{name} reads the runtime log: make logs SINCE=30m > FILE; ai-env lab run {name} --log FILE")));
        };
        if BridgeConfig::load(&paths).ok().flatten().is_some_and(|c| c.aws.execution_role_arn.is_none()) {
            eprintln!("ai-env: warning: [aws].execution_role_arn is not set: VMs started without it write no runtime logs");
        }
        let text = read_log(file)?;
        let src = format!("from {}", file.display());
        let verdict = match name {
            "hooks-port" => probes::verdict_hooks_port(&probes::parse_hook_lines(&text)),
            "hooks-source-ip" => probes::verdict_hooks_source(&probes::parse_hook_lines(&text)),
            "runtime-env" => probes::verdict_runtime_env(&probes::parse_run_reports(&text)),
            "disk-budget" => probes::verdict_disk_budget(&probes::parse_run_reports(&text)),
            _ => return snapshot_log_pass(&paths, spec, &text, &src, note.as_ref()),
        };
        let (v, derived) = verdict.map_err(|e| CliError::Msg(format!("{name}: {e}; nothing recorded")))?;
        return probes::record(&paths, &probes::stamped(&paths, spec, &v, with_note(format!("{derived} ({src})"), note.as_ref())));
    }
    if name == "cloudtrail-payload" {
        let id = id.ok_or_else(|| CliError::Usage("cloudtrail-payload needs the id of a VM this ai-env started".into()))?;
        return cloudtrail(&paths, spec, id, log, note.as_ref());
    }
    // The live probes: their own VMs, the runtime key.
    let ctx = Ctx::load()?;
    let rt = runtime()?;
    let outcome = rt.block_on(async {
        let b = backend(store, &ctx).await?;
        with_backend!(&b, |api, ep| lab::run_probe(&ctx, api, ep, name, id).await.map_err(CliError::from))
    })?;
    let mut row = probes::stamped(&ctx.paths, spec, &outcome.verdict, with_note(outcome.note, note.as_ref()));
    if outcome.claude.is_some() {
        row.claude = outcome.claude.clone();
        row.ext = outcome.claude;
    }
    row.shim = outcome.shim.or(row.shim);
    row.image_version = outcome.image_version.or(row.image_version);
    probes::record(&ctx.paths, &row)
}

fn snapshot_log_pass(paths: &Paths, spec: &probes::ProbeSpec, text: &str, src: &str, note: Option<&String>) -> Result<()> {
    // The newest row whose note names the live pass's VMs (a log pass keeps them too, so it can be re-run).
    let ids_of = |r: &serde_json::Value| -> Vec<String> {
        r.get("note").and_then(|n| n.as_str()).unwrap_or("").split_whitespace().find_map(|w| w.strip_prefix("ids=")).map(|l| l.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
    };
    let rows = crate::bridge::census::read_rows(&paths.probes(), None)?;
    let live = rows.iter().rev().filter(|r| r.get("probe").and_then(|p| p.as_str()) == Some(spec.name)).find(|r| ids_of(r).len() >= 2);
    let Some(live) = live else {
        return Err(CliError::Msg("run `ai-env lab run snapshot-uniqueness` first (the live pass records the two VM ids as ids=a,b)".into()));
    };
    let ids = ids_of(live);
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let verdict = live.get("verdict").and_then(|v| v.as_str()).unwrap_or("?").to_string();
    let (same, pairs) = probes::boot_ids(&probes::parse_run_reports(text), &id_refs).map_err(|e| CliError::Msg(format!("snapshot-uniqueness: {e}; nothing recorded")))?;
    probes::record(paths, &probes::stamped(paths, spec, &verdict, with_note(format!("ids={} boot_ids {same} across snapshot clones: {pairs} ({src})", ids.join(",")), note)))
}

/// A bound on `list-channels` pages (the CLI does not paginate that call).
const MAX_CHANNEL_PAGES: usize = 50;

/// Where RunMicrovm records of this account may be kept.
enum Keeper {
    /// A trail (its own, a multi-region trail homed elsewhere, or an organization trail): its S3 destination and,
    /// when it forwards to CloudWatch Logs, that log group's ARN and (Region, name).
    Trail { arn: String, bucket: String, prefix: String, log_group_arn: Option<String>, log_group: Option<(String, String)>, org: bool },
    /// A service-linked channel whose selectors take RunMicrovm or cannot be read (CloudWatch's CloudTrail ingestion,
    /// Security Lake, …).
    Channel(probes::ChannelView),
}

/// What the operator's CloudTrail shows from eu-central-1: trails and channels. Not visible from here: CloudTrail
/// Lake event data stores (not checked: Lake is closed to new customers since 31 May 2026, and organization stores
/// are invisible to member accounts), channels homed in other Regions, and organization-level CloudWatch or
/// Security Lake configuration.
struct DataEventCoverage {
    trails: usize,
    channels: usize,
    /// Event data stores seen as destinations of Lake integration channels (Lake is in use).
    stores_seen: Vec<String>,
    keepers: Vec<Keeper>,
    unreadable: Vec<String>,
}

/// Every channel ARN, following `NextToken`; a repeated token, too many pages or an entry without an ARN is an error.
fn list_channel_arns() -> std::result::Result<Vec<String>, String> {
    let (mut arns, mut seen, mut token) = (Vec::new(), std::collections::BTreeSet::new(), None::<String>);
    for _ in 0..MAX_CHANNEL_PAGES {
        let page = match &token {
            Some(t) => awscli::aws_json("cloudtrail", &["list-channels", "--next-token", t])?,
            None => awscli::aws_json("cloudtrail", &["list-channels"])?,
        };
        for c in page.get("Channels").and_then(|l| l.as_array()).map(Vec::as_slice).unwrap_or_default() {
            let arn = c.get("ChannelArn").and_then(|a| a.as_str()).ok_or_else(|| "aws cloudtrail list-channels: a channel without ChannelArn".to_string())?;
            arns.push(arn.to_string());
        }
        match page.get("NextToken").and_then(|t| t.as_str()).filter(|t| !t.is_empty()) {
            None => return Ok(arns),
            Some(t) if !seen.insert(t.to_string()) => return Err("aws cloudtrail list-channels: a repeated NextToken".into()),
            Some(t) => token = Some(t.to_string()),
        }
    }
    Err(format!("aws cloudtrail list-channels: more than {MAX_CHANNEL_PAGES} pages"))
}

fn microvm_data_event_coverage() -> std::result::Result<DataEventCoverage, String> {
    let mut cov = DataEventCoverage { trails: 0, channels: 0, stores_seen: Vec::new(), keepers: Vec::new(), unreadable: Vec::new() };
    let trails = awscli::aws_json("cloudtrail", &["describe-trails"])?;
    for t in trails.get("trailList").and_then(|l| l.as_array()).map(Vec::as_slice).unwrap_or_default() {
        let Some(arn) = t.get("TrailARN").and_then(|a| a.as_str()) else {
            cov.unreadable.push("a trail without TrailARN".into());
            continue;
        };
        cov.trails += 1;
        let s = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        match awscli::aws_json("cloudtrail", &["get-event-selectors", "--trail-name", arn]) {
            Ok(doc) if probes::selectors_log_microvm_data(&doc) => {
                let log_group_arn = t.get("CloudWatchLogsLogGroupArn").and_then(|v| v.as_str()).map(str::to_string);
                let log_group = log_group_arn.as_deref().and_then(probes::log_group_from_arn);
                let org = t.get("IsOrganizationTrail").and_then(serde_json::Value::as_bool) == Some(true);
                cov.keepers.push(Keeper::Trail { arn: arn.to_string(), bucket: s("S3BucketName"), prefix: s("S3KeyPrefix"), log_group_arn, log_group, org });
            }
            Ok(_) => {}
            Err(e) => cov.unreadable.push(format!("trail {arn} (home region {}): {e}", t.get("HomeRegion").and_then(|r| r.as_str()).unwrap_or("?"))),
        }
    }
    for arn in list_channel_arns()? {
        cov.channels += 1;
        match awscli::aws_json("cloudtrail", &["get-channel", "--channel", &arn]) {
            Ok(doc) => {
                let view = probes::channel_cover(&doc);
                match view.cover {
                    probes::ChannelCover::Logs | probes::ChannelCover::Maybe => cov.keepers.push(Keeper::Channel(view)),
                    probes::ChannelCover::External => cov.stores_seen.extend(view.destinations.iter().filter(|(t, _)| t == "EVENT_DATA_STORE").map(|(_, l)| l.clone())),
                    probes::ChannelCover::No => {}
                }
            }
            Err(e) => cov.unreadable.push(format!("channel {arn}: {e}")),
        }
    }
    Ok(cov)
}

/// The log classes `describe-log-groups --log-group-class` takes; only STANDARD supports `filter-log-events`.
const LOG_CLASSES: [&str; 3] = ["STANDARD", "INFREQUENT_ACCESS", "DELIVERY"];

/// CloudWatch Logs groups in eu-central-1 whose name contains `cloudtrail` (`aws/cloudtrail…` of CloudWatch's
/// ingestion, `/aws/cloudtrail…`, `aws-cloudtrail-logs-…` of the console's trails), with their log class. A
/// pattern query answers names only (no `logGroupClass`), so the class comes from one query per class; a name
/// none of them returned is of an `unknown` class.
fn cloudtrail_log_groups() -> std::result::Result<Vec<(String, String)>, String> {
    let names = |class: Option<&str>| -> std::result::Result<Vec<String>, String> {
        let mut args = vec!["describe-log-groups", "--log-group-name-pattern", "cloudtrail"];
        if let Some(c) = class {
            args.extend(["--log-group-class", c]);
        }
        let doc = awscli::aws_json("logs", &args)?;
        Ok(doc.get("logGroups").and_then(|l| l.as_array()).map(Vec::as_slice).unwrap_or_default().iter().filter_map(|g| g.get("logGroupName").and_then(|v| v.as_str()).map(str::to_string)).collect())
    };
    let mut out: Vec<(String, String)> = Vec::new();
    for class in LOG_CLASSES {
        out.extend(names(Some(class))?.into_iter().map(|n| (n, class.to_string())));
    }
    for n in names(None)? {
        if !out.iter().any(|(g, _)| *g == n) {
            out.push((n, "unknown".to_string()));
        }
    }
    Ok(out)
}

/// Where the search for the RunMicrovm record starts (ms, as `filter-log-events --start-time` takes it): 5 min
/// before the payload's `created` (written before RunMicrovm), else 15 min before the start, else the oldest a row
/// can be.
fn search_start_ms(row: &VmRow) -> u64 {
    let s = run::created_unix(row).map(|c| c.saturating_sub(300)).or_else(|| row.started_at.map(|t| t.saturating_sub(900))).unwrap_or_else(|| unix_now().saturating_sub(registry::TERMINATED_KEEP_S + 86_400));
    s * 1000
}

/// The UTC day (`YYYY-MM-DD`) of the VM's start, whose CloudTrail log folder holds its RunMicrovm; today when the
/// row has no start.
fn s3_day(row: &VmRow) -> String {
    rfc3339_utc(row.started_at.unwrap_or_else(unix_now))[..10].to_string()
}

/// One `filter-log-events` command per log group, each into its own file (a later empty group must not overwrite
/// a hit), then the probe over that file. Group names were checked to be shell-safe; the id is `[A-Za-z0-9-]`.
fn filter_command(group: &str, id: &str, n: usize, start_ms: u64) -> String {
    format!(
        "aws logs filter-log-events --region {REGION} --endpoint-url {} --log-group-name '{group}' --filter-pattern '\"{id}\"' --start-time {start_ms} --unmask --output json > ~/ct-{id}-{n}.json && ai-env lab run cloudtrail-payload {id} --log ~/ct-{id}-{n}.json",
        awscli::LOGS_URL
    )
}

/// How to get the RunMicrovm record of `id` out of each keeper, one line each. Never a command for another Region.
fn keeper_hints(keepers: &[Keeper], groups: &[(String, String)], id: &str, day: &str, start_ms: u64) -> Vec<String> {
    let mut n = 0;
    let mut out = Vec::new();
    for k in keepers {
        match k {
            Keeper::Trail { arn, bucket, prefix, log_group_arn, log_group, org } => {
                let prefix = if prefix.is_empty() { String::new() } else { format!("{prefix}/") };
                // An organization trail is owned by the management account: its bucket and log group are there.
                let owner_acct = arn.split(':').nth(4).unwrap_or("?");
                let owner = if *org { format!(" (an organization trail owned by account {owner_acct}: its files and log group are in that account)") } else { String::new() };
                // The S3 route is always printed: CloudTrail leaves events over 256 KB out of CloudWatch Logs, and the
                // group's retention may be shorter than the 7 days a row lives.
                out.push(format!(
                    "trail {arn} logs MicroVM data events to s3://{bucket}/{prefix}AWSLogs/{owner}: take the log file under …/CloudTrail/{REGION}/{}/ that holds {id} (zgrep -l {id}; delivered within ~15 min), gunzip it, then: ai-env lab run cloudtrail-payload {id} --log FILE",
                    day.replace('-', "/")
                ));
                match (log_group, log_group_arn) {
                    (Some((r, g)), _) if r == REGION => {
                        n += 1;
                        let run_as = if *org { format!(" (run it with credentials of account {owner_acct}, which owns the group)") } else { String::new() };
                        out.push(format!("trail {arn} also forwards to the CloudWatch Logs group {g}{run_as}: {}", filter_command(g, id, n, start_ms)));
                    }
                    (Some((r, g)), _) => out.push(format!("trail {arn} also forwards to the CloudWatch Logs group {g} in {r}, outside the {REGION} pin (no command)")),
                    (None, Some(raw)) => out.push(format!("trail {arn} also forwards to {raw}, which is not a log group name this probe prints")),
                    (None, None) => {}
                }
            }
            Keeper::Channel(v) if v.kind == "cloudwatch" => {
                if groups.is_empty() {
                    out.push(format!("channel {} (CloudWatch's CloudTrail ingestion) may keep RunMicrovm, but no CloudWatch Logs group with cloudtrail in its name was found in {REGION}: find its log group (CloudWatch → Log groups) and fetch the record with aws logs filter-log-events --unmask, then: ai-env lab run cloudtrail-payload {id} --log FILE", v.name));
                }
                for (g, class) in groups {
                    if !probes::is_safe_log_group_name(g) {
                        out.push(format!("channel {} (CloudWatch) may have written it to the log group {g:?}, a name this probe does not print into a command: fetch the record with aws logs filter-log-events --unmask, then --log FILE", v.name));
                    } else if class == "INFREQUENT_ACCESS" {
                        out.push(format!("channel {} (CloudWatch) may have written it to {g} (log class INFREQUENT_ACCESS: filter-log-events is not supported; search it with CloudWatch Logs Insights and record the verdict with --manual)", v.name));
                    } else if class != "STANDARD" {
                        out.push(format!("channel {} (CloudWatch) may have written it to {g} (log class {class}: not searchable with filter-log-events; record what it holds with --manual)", v.name));
                    } else {
                        n += 1;
                        out.push(format!("channel {} (CloudWatch) may have written it to {g}: {}", v.name, filter_command(g, id, n, start_ms)));
                    }
                }
            }
            Keeper::Channel(v) => {
                let why = if v.cover == probes::ChannelCover::Maybe { "its selectors cannot be read" } else { "its selectors take RunMicrovm" };
                let dests = v.destinations.iter().map(|(t, l)| format!("{t} {l}")).collect::<Vec<_>>().join(", ");
                out.push(format!("service-linked channel {} ({why}) delivers to {dests}: read the RunMicrovm record of {id} there, then record the verdict: ai-env lab run cloudtrail-payload {id} --manual VERDICT --note TEXT", v.name));
            }
        }
    }
    out
}

/// cloudtrail-payload (plan S4 §8, corrected in part B): RunMicrovm is a
/// CloudTrail data event, which event history never holds. With `--log FILE`
/// the payload verdict is read from the RunMicrovm records in FILE (a trail's
/// log file or `aws logs filter-log-events` output). Without it the probe
/// looks for a trail or a service-linked channel (CloudWatch's CloudTrail
/// ingestion, Security Lake, …) that takes the event: found → how to fetch
/// its record; none → it still cannot record `not-logged` itself (CloudTrail
/// Lake stores, channels homed elsewhere and organization-level configuration
/// are invisible from here), so it prints the `--manual` command to run once
/// the operator has confirmed there are none. Fails closed: never a verdict
/// for what it could not see.
fn cloudtrail(paths: &Paths, spec: &probes::ProbeSpec, id: &str, log: Option<&std::path::Path>, note: Option<&String>) -> Result<()> {
    let row = registry::read_row(paths, id)?.ok_or_else(|| CliError::Msg(format!("no row for {id} in state/vms (rows live 7 days after termination): the probe needs the client token and the session token of a VM this ai-env started")))?;
    if let Some(file) = log {
        let text = read_log(file)?;
        return match probes::verdict_cloudtrail(&text, id, &row.client_token, row.session_token.as_deref(), &row.commit) {
            Ok(Some((v, derived))) => probes::record(paths, &probes::stamped(paths, spec, &v, with_note(format!("{derived} (from {})", file.display()), note))),
            Ok(None) => Err(CliError::Msg(format!("no RunMicrovm record for {id} in {}; nothing recorded", file.display()))),
            Err(e) => Err(CliError::Msg(format!("cloudtrail-payload: {e}; nothing recorded"))),
        };
    }
    let cov = microvm_data_event_coverage().map_err(|e| CliError::Aws(format!("cloudtrail-payload: {e}; nothing recorded")))?;
    if !cov.unreadable.is_empty() {
        return Err(CliError::Aws(format!("cloudtrail-payload: could not read what {} logs; nothing recorded", cov.unreadable.join("; "))));
    }
    if !cov.keepers.is_empty() {
        let wants_groups = cov.keepers.iter().any(|k| matches!(k, Keeper::Channel(v) if v.kind == "cloudwatch"));
        let groups = if wants_groups { cloudtrail_log_groups().map_err(|e| CliError::Aws(format!("cloudtrail-payload: {e}; nothing recorded")))? } else { Vec::new() };
        let hints = keeper_hints(&cov.keepers, &groups, id, &s3_day(&row), search_start_ms(&row));
        return Err(CliError::Msg(format!("cloudtrail-payload: RunMicrovm records are not in event history; where they may be kept:\n  {}\nnothing recorded", hints.join("\n  "))));
    }
    let stores = if cov.stores_seen.is_empty() {
        String::new()
    } else {
        format!(" CloudTrail Lake is in use: integration channels deliver to the event data store(s) {} — check what they keep.", cov.stores_seen.join(", "))
    };
    let manual_note = format!(
        "RunMicrovm is a CloudTrail data event ({}), off by default; no trail ({} checked) and no channel ({} checked) in {REGION} takes it, and by hand no CloudTrail Lake event data store, no channel homed in another Region and no organization-level CloudWatch or Security Lake ingestion, so AWS keeps nothing of the run-hook payload",
        probes::MICROVM_DATA_RESOURCE, cov.trails, cov.channels
    );
    Err(CliError::Msg(format!(
        "cloudtrail-payload: no trail ({} checked, multi-region and organization trails included) and no channel ({} checked: CloudWatch's CloudTrail ingestion, Security Lake, …) in {REGION} takes RunMicrovm, a CloudTrail data event that is off by default.{stores} Not visible from here: CloudTrail Lake event data stores (not checked; organization stores are invisible to member accounts), channels homed in other Regions, and organization-level CloudWatch or Security Lake configuration. If there are none, record it: ai-env lab run cloudtrail-payload {id} --manual not-logged --note \"{manual_note}\"; nothing recorded",
        cov.trails, cov.channels
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_names_the_fake_the_knobs_and_the_real_service() {
        let ctx = |knobs: VmKnobs| Ctx { paths: Paths::from_root_and_env("/r".into(), None), cfg: BridgeConfig::default(), knobs };
        assert_eq!(ctx(VmKnobs::default()).backend_name(), "sdk");
        assert_eq!(ctx(crate::bridge::lab::parse_vm_knobs(None, None, Some("5"))).backend_name(), "sdk+knobs");
        assert_eq!(ctx(crate::bridge::lab::parse_vm_knobs(None, Some("1"), None)).backend_name(), "sdk+knobs");
        assert_eq!(ctx(crate::bridge::lab::parse_vm_knobs(Some("/f.json"), None, Some("5"))).backend_name(), "fake");
    }

    #[test]
    fn fmt_secs_shapes() {
        assert_eq!(fmt_secs(-1), "-");
        assert_eq!(fmt_secs(59), "59s");
        assert_eq!(fmt_secs(61), "1m01s");
        assert_eq!(fmt_secs(3_660), "1h01m");
    }

    #[test]
    fn search_start_falls_back_from_created_to_started_at_to_the_row_lifetime() {
        let created = registry::VmRow { created: "2026-09-30T13:06:43.060Z".into(), started_at: Some(1_790_000_000), ..Default::default() };
        assert_eq!(search_start_ms(&created), (run::created_unix(&created).unwrap() - 300) * 1000, "5 min before the payload's created");
        let started = registry::VmRow { created: "not a time".into(), started_at: Some(1_700_000_000), ..Default::default() };
        assert_eq!(search_start_ms(&started), (1_700_000_000 - 900) * 1000, "15 min before the start");
        assert_eq!(s3_day(&started), "2023-11-14", "the day of the start, not of the probe");
        let neither = registry::VmRow::default();
        let oldest = (unix_now() - registry::TERMINATED_KEEP_S - 86_400) * 1000;
        assert!(search_start_ms(&neither).abs_diff(oldest) < 5_000, "the oldest a row can be");
    }

    #[test]
    fn trail_hints_keep_the_s3_route_and_name_the_owner_of_an_organization_trail() {
        let trail = |org: bool, group: Option<(&str, &str)>| Keeper::Trail {
            arn: "arn:aws:cloudtrail:eu-central-1:123456789012:trail/t".into(),
            bucket: "b".into(),
            prefix: String::new(),
            log_group_arn: group.map(|(r, g)| format!("arn:aws:logs:{r}:123456789012:log-group:{g}:*")),
            log_group: group.map(|(r, g)| (r.to_string(), g.to_string())),
            org,
        };
        let hints = keeper_hints(&[trail(false, Some(("eu-central-1", "g1")))], &[], "microvm-x", "2026-09-30", 1_000);
        assert_eq!(hints.len(), 2, "{hints:?}");
        assert!(hints[0].contains("s3://b/AWSLogs/") && hints[0].contains("CloudTrail/eu-central-1/2026/09/30/"), "the day of the VM's start: {hints:?}");
        assert!(hints[1].contains("--log-group-name 'g1'") && hints[1].contains("--start-time 1000 ") && hints[1].contains("~/ct-microvm-x-1.json"), "{hints:?}");
        let org = keeper_hints(&[trail(true, Some(("eu-central-1", "g2")))], &[], "microvm-x", "2026-09-30", 1_000);
        assert!(org[0].contains("owned by account 123456789012") && org[1].contains("run it with credentials of account 123456789012"), "{org:?}");
        let far = keeper_hints(&[trail(false, Some(("us-east-1", "g3")))], &[], "microvm-x", "2026-09-30", 1_000);
        assert!(far[1].contains("g3 in us-east-1") && !far.iter().any(|h| h.contains("filter-log-events")), "{far:?}");
        assert_eq!(keeper_hints(&[trail(false, None)], &[], "microvm-x", "2026-09-30", 1_000).len(), 1, "S3 only");
    }

    #[test]
    fn wall_left_is_a_dash_once_the_vm_is_gone() {
        let live = registry::VmRow { status: RowStatus::Running, wall_deadline: Some(1_000), ..Default::default() };
        assert_eq!(wall_left_cell("RUNNING", Some(&live), 900), "1m40s");
        assert_eq!(wall_left_cell("TERMINATED", Some(&live), 900), "-", "listed TERMINATED while the row still counts down (live 30 Sep 2026)");
        assert_eq!(wall_left_cell("TERMINATING", Some(&live), 900), "-");
        let gone = registry::VmRow { status: RowStatus::Terminated, ..live.clone() };
        assert_eq!(wall_left_cell("(terminated)", Some(&gone), 900), "-");
        assert_eq!(wall_left_cell("RUNNING", None, 900), "-");
    }
}
