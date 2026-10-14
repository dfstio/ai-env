//! `GET /health` — the public summary the Mac polls after `run_microvm` — and
//! the state every listener shares: options, the claude probe, the `/run`
//! record, the booting/draining flags, (S6) the spawn manager, the agent
//! registry and what the peer guard saw, and (S8) the VM's one workspace.
//! `GET /health/detail` (bearer only) adds the guard, the sockets, the
//! spawns, the listeners and the workspace. The app router puts the peer
//! guard first, then the bearer (every path but `/health` and `/agent`),
//! and answers any other path 404 behind them.
//!
//! S8's app-port routes (`wire::workspace`), each run by the agent's helper
//! (`asagent`) and served only by a shim that has one (it then names
//! `CAP_WORKSPACE_V1`; without one they answer 404, as an older shim's do):
//! `GET /transcript?rel=` (a `TranscriptStat`), `PUT /transcript?rel=` (the
//! file, `Content-Length` required, at most `TRANSCRIPT_MAX`; one at a time)
//! and `GET /settings?path=` (a `SettingsCapture`).
use crate::shim::agent::AgentRegistry;
use crate::shim::asagent::{self, AgentCmd, WorkspaceSlot};
use crate::shim::hooks::HookSource;
use crate::shim::peer::AgentGuard;
use crate::shim::spawn::{SpawnManager, SpawnOpts};
use crate::shim::state::RunState;
use crate::shim::sys::{ClockMode, RealSys, SysOps};
use crate::wire::frame::{Health, HealthDetail, HealthStatus, HookPeerSeen, CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1, STDOUT_WINDOW_BYTES, WIRE_VERSION};
use crate::wire::workspace::{budget, refusal, transcript_rel_check, vm_path_check, PathQuery, RelQuery, SettingsCapture, TranscriptReply, TranscriptStat, WsRefusal, SETTINGS_ROUTE, TRANSCRIPT_MAX, TRANSCRIPT_ROUTE};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{any, get};
use axum::{Json, Router};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

/// The one budget for `claude --version`, wherever it runs: the readiness
/// probe, `/validate`, and the Dockerfile's gate (`timeout 30`).
pub const CLAUDE_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// PATH of the probe child (the environment is otherwise cleared).
const PROBE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Who the claude probe runs as. `None` = unchanged (the shim is not root:
/// native tests on the Mac).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeSpec {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl ProbeSpec {
    /// Drop to `uid:gid` only when we are root (PID 1 in the VM).
    #[must_use]
    pub fn for_agent(uid: u32, gid: u32) -> Self {
        if nix::unistd::geteuid().is_root() {
            ProbeSpec { uid: Some(uid), gid: Some(gid) }
        } else {
            ProbeSpec::default()
        }
    }
}

/// The `ai-env shim` options the handlers read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimOpts {
    pub hook_source: HookSource,
    /// The peer guard on the app and code ports (S6).
    pub agent_guard: AgentGuard,
    pub clock: ClockMode,
    pub delay_run: u64,
    /// Prefix for every path `/validate` checks (native tests).
    pub fs_root: Option<PathBuf>,
    pub home: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// stdout window per spawn (hidden `--agent-window-bytes`).
    pub window_bytes: u64,
    /// The program the agent's workspace helper runs as `<helper> shim-io
    /// <op>` (S8 §6; W3 starts it): the shim's own binary, resolved at
    /// startup, or the hidden `--helper`. `None` (an in-process test that
    /// names none): the workspace routes cannot start a helper.
    pub helper: Option<PathBuf>,
    /// The git the helper runs (hidden `--git`, default [`GIT_DEFAULT`]).
    pub git: PathBuf,
}

/// The image's git, the helper's unless `--git` names another.
pub const GIT_DEFAULT: &str = "/usr/bin/git";

impl Default for ShimOpts {
    fn default() -> Self {
        ShimOpts {
            hook_source: HookSource::Log,
            agent_guard: AgentGuard::Off,
            clock: ClockMode::Measure,
            delay_run: 0,
            fs_root: None,
            home: PathBuf::from("/Users/mike"),
            uid: 1000,
            gid: 1000,
            window_bytes: STDOUT_WINDOW_BYTES,
            helper: None,
            git: PathBuf::from(GIT_DEFAULT),
        }
    }
}

/// The ports the worker actually bound (`--*-port 0` picks a free one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundPorts {
    pub hooks: u16,
    pub app: u16,
    pub code: u16,
}

pub struct ShimState {
    started: Instant,
    claude: PathBuf,
    probe: ProbeSpec,
    /// The full `--version` line of the first SUCCESSFUL probe.
    claude_line: OnceCell<String>,
    bound: AtomicBool,
    draining: AtomicBool,
    pub run: RunState,
    pub opts: ShimOpts,
    pub sys: Arc<dyn SysOps>,
    /// Held while one `/validate` runs (single flight).
    pub validating: tokio::sync::Mutex<()>,
    /// The processes `/agent` started (S6).
    pub spawns: SpawnManager,
    /// The open `/agent` sockets (S6).
    pub agents: AgentRegistry,
    /// `AWS_LAMBDA_MICROVM_IMAGE_VERSION` at worker start (`None` outside a VM).
    pub image_version: Option<String>,
    /// The last peer the guard let through, per runtime hook.
    pub hook_peers: Mutex<BTreeMap<String, HookPeerSeen>>,
    /// The last refused peer, per runtime hook.
    pub hook_refusals: Mutex<BTreeMap<String, HookPeerSeen>>,
    /// Guard refusals by port.
    pub refused: Mutex<BTreeMap<String, u64>>,
    /// The last clock report (`/run`, `/resume`), as logged.
    pub last_clock: Mutex<Option<serde_json::Value>>,
    /// Set once by [`Self::set_ports`].
    pub ports: OnceLock<BoundPorts>,
    /// The VM's one workspace (S8): the last seed's record, the lock of seed,
    /// code-out and snapshot.
    pub workspace: WorkspaceSlot,
}

impl ShimState {
    /// Listeners already bound, default options, the real machine: what the
    /// S0 `/health` tests and the in-process router tests start from.
    #[must_use]
    pub fn new(claude: PathBuf) -> Self {
        let s = Self::with(claude, ShimOpts::default(), ProbeSpec::default(), Arc::new(RealSys));
        s.set_bound();
        s
    }

    /// The binary's state: `booting` until [`Self::set_bound`].
    #[must_use]
    pub fn with(claude: PathBuf, opts: ShimOpts, probe: ProbeSpec, sys: Arc<dyn SysOps>) -> Self {
        let spawns = SpawnManager::new(SpawnOpts {
            claude: claude.clone(),
            home: opts.home.clone(),
            uid: probe.uid,
            gid: probe.gid,
            agent_uid: opts.uid,
            window_bytes: opts.window_bytes,
            sweep: cfg!(target_os = "linux") && probe.uid.is_some(),
            fs_root: opts.fs_root.clone(),
        });
        ShimState {
            started: Instant::now(),
            claude,
            probe,
            claude_line: OnceCell::new(),
            bound: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            run: RunState::default(),
            opts,
            sys,
            validating: tokio::sync::Mutex::new(()),
            spawns,
            agents: AgentRegistry::new(),
            image_version: std::env::var("AWS_LAMBDA_MICROVM_IMAGE_VERSION").ok().filter(|v| !v.is_empty() && v.len() <= 32 && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.')),
            hook_peers: Mutex::new(BTreeMap::new()),
            hook_refusals: Mutex::new(BTreeMap::new()),
            refused: Mutex::new(BTreeMap::new()),
            last_clock: Mutex::new(None),
            ports: OnceLock::new(),
            workspace: WorkspaceSlot::default(),
        }
    }

    /// Record the ports the worker bound (once).
    pub fn set_ports(&self, ports: BoundPorts) {
        let _ = self.ports.set(ports);
    }

    pub fn set_bound(&self) {
        self.bound.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.bound.load(Ordering::SeqCst)
    }

    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// `path` (absolute, as in the VM) under `--fs-root` when set.
    #[must_use]
    pub fn at(&self, path: &Path) -> PathBuf {
        match &self.opts.fs_root {
            Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_path_buf(),
        }
    }

    /// Whether this shim serves the workspace routes (S8): it has a helper
    /// program to run them as the agent (the shim's own binary, or the
    /// hidden `--helper`). Without one it neither names
    /// [`CAP_WORKSPACE_V1`] nor serves them (404, as an older shim).
    #[must_use]
    pub fn serves_workspace(&self) -> bool {
        self.opts.helper.is_some()
    }

    /// What this shim can do beyond wire v1's core: `hello_ok.caps` and `/health`'s.
    #[must_use]
    pub fn caps(&self) -> Vec<String> {
        let mut caps = vec![CAP_CREDENTIAL_CACHE.to_string()];
        if self.serves_workspace() {
            caps.push(CAP_WORKSPACE_V1.to_string());
        }
        caps
    }

    /// `/ready`: the three listeners are bound and one probe succeeded.
    /// `Err` lists what is still awaited.
    pub fn ready(&self) -> Result<(), Vec<&'static str>> {
        let mut waiting = Vec::new();
        if !self.is_bound() {
            waiting.push("listeners");
        }
        if self.claude_line.get().is_none() {
            waiting.push("claude");
        }
        if waiting.is_empty() { Ok(()) } else { Err(waiting) }
    }

    /// The version token of the cached probe (`2.1.283` of
    /// `2.1.283 (Claude Code)`).
    #[must_use]
    pub fn claude_version(&self) -> Option<String> {
        self.claude_line.get().and_then(|l| l.split_whitespace().next()).map(str::to_string)
    }

    /// Probe once; cache the line on success. A failure (the binary is
    /// still being unpacked at boot, say) is NOT cached: the caller retries.
    pub async fn probe_once(&self) -> Result<String, String> {
        if let Some(line) = self.claude_line.get() {
            return Ok(line.clone());
        }
        let line = self.probe_fresh().await?;
        Ok(self.claude_line.get_or_init(|| async { line }).await.clone())
    }

    /// `<claude> --version` now, never cached: a cleared environment (a
    /// throwaway `HOME`, a fixed `PATH`), as `uid:gid` when root, stdin
    /// closed, killed after [`CLAUDE_PROBE_TIMEOUT`]. Returns the first
    /// stdout line. An EPERM from the chown or the dropped spawn names the
    /// capabilities the effective set lacks. Counted as a workspace helper
    /// while it runs (`SpawnManager::hold_helper`): the idle sweep a spawn's
    /// end starts never kills the probe, which runs as the agent too.
    pub async fn probe_fresh(&self) -> Result<String, String> {
        let _hold = self.spawns.hold_helper(true).await;
        let home = tempfile::Builder::new().prefix("ai-env-probe-").tempdir().map_err(|e| format!("probe HOME: {e}"))?;
        let dropping = self.probe.uid.is_some() || self.probe.gid.is_some();
        let hint = |e: &std::io::Error| if dropping { crate::shim::sys::eperm_hint(e, self.sys.cap_eff()) } else { String::new() };
        if dropping {
            std::os::unix::fs::chown(home.path(), self.probe.uid, self.probe.gid).map_err(|e| format!("probe HOME chown: {e}{}", hint(&e)))?;
        }
        let mut cmd = tokio::process::Command::new(&self.claude);
        cmd.arg("--version")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", PROBE_PATH)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Some(gid) = self.probe.gid {
            cmd.gid(gid);
        }
        if let Some(uid) = self.probe.uid {
            cmd.uid(uid);
        }
        let out = tokio::time::timeout(CLAUDE_PROBE_TIMEOUT, cmd.output())
            .await
            .map_err(|_| format!("timed out after {} s", CLAUDE_PROBE_TIMEOUT.as_secs()))?
            .map_err(|e| format!("cannot run {}: {e}{}", self.claude.display(), hint(&e)))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let first = err.lines().next().unwrap_or("").chars().take(200).collect::<String>();
            return Err(format!("{} (stderr: {})", out.status, crate::wire::redact::scrub(&first)));
        }
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .ok_or_else(|| "empty --version output".into())
    }

    pub async fn health(&self) -> Health {
        let run = self.run.view();
        let status = if self.is_draining() {
            HealthStatus::Draining
        } else if !self.is_bound() {
            HealthStatus::Booting
        } else {
            HealthStatus::Ok
        };
        let since = if run.seen { run.at.unwrap_or(self.started) } else { self.started };
        Health {
            status,
            shim_version: env!("CARGO_PKG_VERSION").to_string(),
            claude_version: self.claude_version(),
            microvm_id: run.microvm_id,
            owner: run.owner,
            created: run.created,
            boot_nonce: run.boot_nonce,
            run_hook_seen: run.seen,
            uptime_s: since.elapsed().as_secs(),
            wire: Some(WIRE_VERSION),
            caps: self.caps(),
        }
    }

    /// `GET /health/detail`: [`Self::health`] plus the guard's counters and
    /// last hook peers, the sockets, the spawns, the last clock report and
    /// the LISTEN inventory (read now, bounded: `peer::bounded`).
    pub async fn detail(&self) -> HealthDetail {
        let (open, authenticated) = self.agents.counts();
        let (listeners, listeners_omitted) = crate::shim::peer::bounded(crate::shim::peer::listeners(), self.opts.uid);
        HealthDetail {
            health: self.health().await,
            image_version: self.image_version.clone(),
            hook_source: self.opts.hook_source.name().to_string(),
            agent_guard: self.opts.agent_guard.name().to_string(),
            refused_peers: self.refused.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            hook_peers: self.hook_peers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            hook_refusals: self.hook_refusals.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            sockets_open: open,
            sockets_authenticated: authenticated,
            spawns: self.spawns.detail(),
            has_credentials: self.spawns.credential().has(),
            credential: self.spawns.credential_view(),
            clock: self.last_clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            listeners,
            listeners_omitted,
            workspace: self.serves_workspace().then(|| self.workspace.view(self.spawns.helpers())),
        }
    }
}

async fn health(State(state): State<Arc<ShimState>>) -> Json<Health> {
    Json(state.health().await)
}

async fn detail(State(state): State<Arc<ShimState>>) -> Json<HealthDetail> {
    Json(state.detail().await)
}

/// 405 for a method a route does not serve (axum adds `Allow`), after
/// draining the request body like every other refusal.
pub(crate) async fn method_not_allowed(req: Request) -> StatusCode {
    crate::shim::peer::drain(req).await;
    StatusCode::METHOD_NOT_ALLOWED
}

/// The app-port router (http1 only): the public `/health` and the `/agent`
/// upgrade (which checks its method itself, after the 503s), the bearer-only
/// `/health/detail`, and 404 for the rest. Serve it with
/// `into_make_service_with_connect_info::<peer::Peer>()`.
pub fn router(state: Arc<ShimState>) -> Router {
    let mut routes = Router::new()
        .route("/health", get(health).fallback(method_not_allowed))
        .route("/health/detail", get(detail).fallback(method_not_allowed))
        .route("/agent", any(crate::shim::agent::upgrade));
    if state.serves_workspace() {
        routes = routes
            .route(TRANSCRIPT_ROUTE, get(get_transcript).put(put_transcript).fallback(method_not_allowed))
            .route(SETTINGS_ROUTE, get(get_settings).fallback(method_not_allowed));
    }
    // The last layer runs first: the guard, then the bearer.
    routes
        .fallback(crate::shim::auth::not_implemented)
        .layer(from_fn_with_state(state.clone(), crate::shim::auth::app_bearer))
        .layer(from_fn_with_state(state.clone(), crate::shim::peer::guard))
        .with_state(state)
}

// ---- S8: the transcript and settings routes -------------------------------------------------

/// The agent's projects directory, where its claude keeps its transcripts
/// (`CLAUDE_CONFIG_DIR` is `<home>/.claude`: `spawn`).
fn projects(state: &ShimState) -> std::path::PathBuf {
    state.opts.home.join(".claude").join("projects")
}

/// `GET /transcript?rel=`: the VM's copy, as the agent's projects directory holds it.
async fn get_transcript(State(state): State<Arc<ShimState>>, req: Request) -> axum::response::Response {
    let (op, started) = ("transcript-stat", Instant::now());
    let q: RelQuery = match crate::shim::code::query(&req) {
        Ok(q) => q,
        Err(r) => return asagent::refuse(op, started, &r),
    };
    if let Err(e) = transcript_rel_check(&q.rel) {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the transcript's rel {e}")));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &asagent::AgentProcError::Draining.refusal(op));
    }
    let cmd = AgentCmd { op, args: vec![asagent::flag("projects", projects(&state)), asagent::flag("rel", &q.rel)], budget: budget::TRANSCRIPT, stdin: false, during_stop: false };
    let out = asagent::run_op::<TranscriptStat>(&state, cmd, None).await;
    asagent::respond(op, started, out, |_| 200)
}

/// `PUT /transcript?rel=`: the file (`Content-Length` required, at most
/// `TRANSCRIPT_MAX`), streamed to the helper, which writes it as the agent;
/// under the transcripts' own lock, as a task of its own
/// (`asagent::detached`: a client gone meanwhile never kills the helper
/// before it removed its temp file).
async fn put_transcript(State(state): State<Arc<ShimState>>, req: Request) -> axum::response::Response {
    let (op, started) = ("transcript-put", Instant::now());
    let q: RelQuery = match crate::shim::code::query(&req) {
        Ok(q) => q,
        Err(r) => return crate::shim::code::refuse_draining(op, started, req, &r).await,
    };
    if let Err(e) = transcript_rel_check(&q.rel) {
        return crate::shim::code::refuse_draining(op, started, req, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the transcript's rel {e}"))).await;
    }
    let len = match crate::shim::code::content_length(&req, TRANSCRIPT_MAX) {
        Ok(len) => len,
        Err(stop) => {
            crate::shim::peer::drain(req).await;
            return stop.respond(op, started);
        }
    };
    if state.is_draining() {
        return crate::shim::code::refuse_draining(op, started, req, &asagent::AgentProcError::Draining.refusal(op)).await;
    }
    asagent::detached(op, started, async move {
        let Ok(_one) = tokio::time::timeout(state.workspace.busy_wait(), state.workspace.transcripts.lock()).await else {
            return crate::shim::code::refuse_after_body(op, started, req, len, &asagent::busy(op, "another transcript upload is being written", state.workspace.busy_wait())).await;
        };
        let args = vec![asagent::flag("projects", projects(&state)), asagent::flag("rel", &q.rel), asagent::flag("len", len.to_string())];
        let cmd = AgentCmd { op, args, budget: budget::TRANSCRIPT + asagent::transfer(len), stdin: true, during_stop: false };
        let out = asagent::run_with_body::<TranscriptReply>(&state, cmd, req.into_body()).await;
        asagent::respond(op, started, out, |r| r.outcome.status())
    })
    .await
}

/// `GET /settings?path=`: the VM claude's settings for the workspace (T8.7).
async fn get_settings(State(state): State<Arc<ShimState>>, req: Request) -> axum::response::Response {
    let (op, started) = ("settings", Instant::now());
    let q: PathQuery = match crate::shim::code::query(&req) {
        Ok(q) => q,
        Err(r) => return asagent::refuse(op, started, &r),
    };
    if let Err(e) = vm_path_check(&q.path) {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the workspace path {e}")));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &asagent::AgentProcError::Draining.refusal(op));
    }
    let cmd = AgentCmd { op, args: vec![asagent::flag("path", &q.path)], budget: budget::SETTINGS, stdin: false, during_stop: false };
    let out = asagent::run_op::<SettingsCapture>(&state, cmd, None).await;
    asagent::respond(op, started, out, |_| 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A `claude` whose FIRST `--version` exits 1 (the marker file is created
    /// on that run) and which answers `2.1.283 (Claude Code)` on every later
    /// run — the VM-boot race the cache must survive.
    fn flaky_claude(dir: &Path) -> PathBuf {
        let marker = dir.join("probed");
        let script = dir.join("claude");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ -e '{m}' ]; then echo '2.1.283 (Claude Code)'; exit 0; fi\n: > '{m}'\necho 'first run fails' >&2\nexit 1\n",
                m = marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[tokio::test]
    async fn failed_probe_is_not_cached_and_success_is() {
        let dir = tempfile::tempdir().unwrap();
        let state = ShimState::new(flaky_claude(dir.path()));
        let e = state.probe_once().await.unwrap_err();
        assert!(e.contains("first run fails"), "{e}");
        assert_eq!(state.claude_version(), None, "a failure is not cached");
        assert_eq!(state.ready(), Err(vec!["claude"]));
        assert_eq!(state.probe_once().await.unwrap(), "2.1.283 (Claude Code)");
        std::fs::remove_file(dir.path().join("claude")).unwrap();
        assert_eq!(state.probe_once().await.unwrap(), "2.1.283 (Claude Code)", "cached: not probed again");
        assert_eq!(state.claude_version().as_deref(), Some("2.1.283"));
        assert_eq!(state.ready(), Ok(()));
        assert!(state.probe_fresh().await.is_err(), "a fresh probe is never served from the cache");
    }

    /// The probe runs as the agent, as a workspace helper does: while it
    /// runs it is counted as one, so a spawn's end never sweeps it away.
    #[tokio::test]
    async fn the_probe_holds_off_the_idle_sweep_while_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let (script, started) = (dir.path().join("claude"), dir.path().join("started"));
        std::fs::write(&script, format!("#!/bin/sh\n: > '{}'\nsleep 1\necho '2.1.283 (Claude Code)'\n", started.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = Arc::new(ShimState::new(script));
        assert_eq!(state.spawns.helpers(), 0);
        let probe = tokio::spawn({
            let state = Arc::clone(&state);
            async move { state.probe_fresh().await }
        });
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !started.exists() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(state.spawns.helpers(), 1, "the running probe is counted");
        assert_eq!(probe.await.unwrap().unwrap(), "2.1.283 (Claude Code)");
        assert_eq!(state.spawns.helpers(), 0, "and let go once it ended");
    }

    #[tokio::test]
    async fn the_probe_sees_a_cleared_environment() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("claude");
        // CARGO_MANIFEST_DIR is in every `cargo test` process's environment.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some(), "precondition: cargo sets it for tests");
        std::fs::write(&script, "#!/bin/sh\necho \"$HOME|$PATH|${CARGO_MANIFEST_DIR:-none}\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = ShimState::new(script);
        let line = state.probe_fresh().await.unwrap();
        let parts: Vec<&str> = line.split('|').collect();
        assert!(parts[0].contains("ai-env-probe-"), "throwaway HOME: {line}");
        assert!(!Path::new(parts[0]).exists(), "the throwaway HOME is removed: {line}");
        assert_eq!(parts[1], PROBE_PATH);
        assert_eq!(parts[2], "none", "the shim's environment does not reach claude");
    }

    #[tokio::test]
    async fn missing_claude_is_null_and_status_follows_the_flags() {
        let state = ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts::default(), ProbeSpec::default(), Arc::new(RealSys));
        assert_eq!(state.health().await.status, HealthStatus::Booting);
        assert_eq!(state.ready(), Err(vec!["listeners", "claude"]));
        assert!(state.probe_once().await.unwrap_err().contains("cannot run"));
        state.set_bound();
        let h = state.health().await;
        assert_eq!(h.status, HealthStatus::Ok, "a missing claude does not fail /health");
        assert_eq!(h.claude_version, None);
        state.set_draining();
        assert_eq!(state.health().await.status, HealthStatus::Draining);
    }

    /// D16: `uptime_s` counts from process start until `/run` has returned,
    /// then from `/run`; a replay does not restart the clock.
    #[tokio::test]
    async fn uptime_counts_from_run_once_it_ran() {
        use crate::shim::state::{Claim, RunRecord};
        let mut state = ShimState::with(PathBuf::from("c"), ShimOpts::default(), ProbeSpec::default(), Arc::new(RealSys));
        state.started = Instant::now().checked_sub(Duration::from_secs(100)).unwrap();
        assert!(state.health().await.uptime_s >= 100, "before /run: from process start");
        let at = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        let record = || RunRecord { microvm_id: None, payload: None, body_sha256: [1; 32], at, boot_nonce: "0".repeat(32) };
        assert_eq!(state.run.claim(&[1; 32], record), Claim::First);
        assert!(state.health().await.uptime_s >= 100, "claimed but not returned: still from process start");
        state.run.mark_seen();
        let u = state.health().await.uptime_s;
        assert!((10..100).contains(&u), "once /run ran: from /run ({u})");
        assert_eq!(state.run.claim(&[1; 32], || unreachable!("a replay stores nothing")), Claim::Replay);
        assert_eq!(state.run.claim(&[2; 32], || unreachable!("a conflict stores nothing")), Claim::Conflict);
        assert_eq!(state.run.view().at, Some(at), "neither a replay nor a conflict restarts the clock");
        assert!((10..100).contains(&state.health().await.uptime_s));
    }

    /// A machine whose only fact is its capability mask.
    struct Caps(u64);

    impl SysOps for Caps {
        fn now(&self) -> (u64, u128) {
            (1, 1)
        }
        fn rtc(&self) -> Option<u64> {
            None
        }
        fn kernel_random(&self) -> [u8; 32] {
            [0; 32]
        }
        fn mix(&self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn reseed(&self) -> Result<(), String> {
            Ok(())
        }
        fn cap_eff(&self) -> Option<u64> {
            Some(self.0)
        }
        fn set_clock(&self, _: u64) -> Result<(), String> {
            Err("never".into())
        }
    }

    /// Not root: a chown of the probe HOME to someone else fails with EPERM,
    /// as it does in a VM whose effective set lacks CAP_CHOWN.
    #[tokio::test]
    async fn a_refused_privilege_drop_names_the_missing_capabilities() {
        let euid = nix::unistd::geteuid().as_raw();
        if euid == 0 {
            eprintln!("root may chown to anyone: the EPERM path needs a non-root run");
            return;
        }
        let drop_to = ProbeSpec { uid: Some(euid + 1), gid: None };
        let lacking = ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts::default(), drop_to, Arc::new(Caps(0xa804_25fb & !1)));
        let e = lacking.probe_fresh().await.unwrap_err();
        assert!(e.starts_with("probe HOME chown: ") && e.ends_with("(the effective capabilities lack CAP_CHOWN)"), "{e}");
        let full = ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts::default(), drop_to, Arc::new(Caps(0xa804_25fb)));
        let e = full.probe_fresh().await.unwrap_err();
        assert!(e.starts_with("probe HOME chown: ") && !e.contains("capabilities"), "every drop cap present: no hint: {e}");
        let e = ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts::default(), ProbeSpec::default(), Arc::new(Caps(0))).probe_fresh().await.unwrap_err();
        assert!(e.starts_with("cannot run ") && !e.contains("capabilities"), "no drop, no hint: {e}");
    }

    #[test]
    fn fs_root_prefixes_absolute_paths() {
        let mut opts = ShimOpts::default();
        let plain = ShimState::with(PathBuf::from("c"), opts.clone(), ProbeSpec::default(), Arc::new(RealSys));
        assert_eq!(plain.at(Path::new("/etc/machine-id")), PathBuf::from("/etc/machine-id"));
        opts.fs_root = Some(PathBuf::from("/tmp/root"));
        let rooted = ShimState::with(PathBuf::from("c"), opts, ProbeSpec::default(), Arc::new(RealSys));
        assert_eq!(rooted.at(Path::new("/etc/machine-id")), PathBuf::from("/tmp/root/etc/machine-id"));
    }
}
