//! `ai-env shim` — the MicroVM image ENTRYPOINT (root, PID 1). Runs natively
//! on the Mac for tests.
//!
//! Two roles (see `init`): as PID 1, or with the hidden `--supervise`, the
//! process is a signal-forwarding, orphan-reaping init that spawns the same
//! binary as the worker; otherwise it is the worker. The worker binds three
//! listeners — hooks (`hooks`, 9000), app (`/health`, `/agent` and the
//! bearer-only `/health/detail`, 8080) and code (9418, bearer-only; its
//! routes arrive in S8/S9) — probes `claude --version` in the background
//! (`/ready` waits for it), and shuts down gracefully on SIGTERM/SIGINT/SIGQUIT
//! or when its init dies: the `/agent` sockets are closed and every spawn's
//! process group is stopped before the servers end.
//!
//! Every log line goes through `errln!`: stderr is whatever PID 1 was
//! given, and a reader that went away must not panic a hook (`eprintln!`
//! panics on EPIPE).

/// `eprintln!` that never panics: a failed write to stderr is dropped. The
/// shim's only log is stderr, and losing a line beats losing a hook response
/// or PID 1. Defined before the submodules so they all see it.
macro_rules! errln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        // One write per line: init and the worker share stderr, and a line
        // written in pieces interleaves with the other process's (a pipe
        // write up to PIPE_BUF is atomic). Errors are dropped, never panicked.
        let mut line = format!($($arg)*);
        line.push('\n');
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }};
}

pub mod agent;
pub mod auth;
pub mod code;
pub mod credential;
pub mod health;
pub mod hooks;
pub mod init;
pub mod peer;
pub mod replay;
pub mod spawn;
pub mod state;
pub mod sys;
pub mod validate;

use crate::errors::{CliError, Result};
use std::future::IntoFuture;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(clap::Args, Debug, Clone)]
pub struct ShimArgs {
    /// Application port: /health, /agent
    #[arg(long, default_value_t = 8080)]
    pub app_port: u16,
    /// Platform lifecycle hooks port
    #[arg(long, default_value_t = 9000)]
    pub hooks_port: u16,
    /// Code channel port: /seed, /bundle, git smart-HTTP
    #[arg(long, default_value_t = 9418)]
    pub code_port: u16,
    /// Path of the claude binary the shim spawns
    #[arg(long, value_name = "PATH")]
    pub claude: PathBuf,
    /// HOME of the agent user (mirrors the Mac)
    #[arg(long, default_value = "/Users/mike")]
    pub home: PathBuf,
    /// uid the agent runs as
    #[arg(long, default_value_t = 1000)]
    pub uid: u32,
    /// gid the agent runs as
    #[arg(long, default_value_t = 1000)]
    pub gid: u32,
    /// Delay the /run hook response by S seconds (probe; 0–25, the hook budget is 30)
    #[arg(long, value_name = "S", value_parser = clap::value_parser!(u64).range(0..=25))]
    pub delay_run: Option<u64>,
    /// Hook source policy: log every origin (default), refuse runtime hooks from this VM's addresses (enforce), or from local agent-uid sockets (peer; Linux)
    #[arg(long, value_enum, default_value_t = hooks::HookSource::Log)]
    pub hook_source: hooks::HookSource,
    /// Peer guard on the app and code ports (default: on as root on Linux, else off)
    #[arg(long, value_enum)]
    pub agent_guard: Option<peer::AgentGuard>,
    /// stdout window per spawn in bytes (tests)
    #[arg(long, value_name = "BYTES", hide = true, value_parser = clap::value_parser!(u64).range(1..))]
    pub agent_window_bytes: Option<u64>,
    /// Clock handling on /run and /resume: measure only (default) or step forward to the RTC
    #[arg(long, value_enum, default_value_t = sys::ClockMode::Measure)]
    pub clock: sys::ClockMode,
    /// Prefix for every path /validate checks (native tests)
    #[arg(long, value_name = "DIR", hide = true)]
    pub fs_root: Option<PathBuf>,
    /// Worker role: the init that spawned us (exit when it dies)
    #[arg(long, value_name = "PID", hide = true)]
    pub init_pid: Option<u32>,
    /// Run the init role although we are not PID 1 (tests)
    #[arg(long, hide = true)]
    pub supervise: bool,
    /// Init role: SIGKILL the worker this many seconds after a stop signal (tests)
    #[arg(long, value_name = "S", hide = true, default_value_t = init::KILL_AFTER_S, value_parser = clap::value_parser!(u32).range(1..))]
    pub kill_after_s: u32,
}

/// A TERM/INT/QUIT the worker received before its tokio handlers existed
/// (0 = none); `serve` stops right after binding when it is set.
static EARLY_STOP: AtomicI32 = AtomicI32::new(0);

/// Only records the signal (an atomic store is async-signal-safe). tokio's
/// handler chains to it once installed, so it may also fire later; it is
/// read once, when the stop task starts.
extern "C" fn early_stop(sig: libc::c_int) {
    EARLY_STOP.store(sig, Ordering::SeqCst);
}

/// The worker's dispositions before its mask is opened: the worker inherits
/// init's blocked mask (std keeps the parent's mask across spawn), so a
/// signal init forwarded while we were starting is pending and lands the
/// moment we unblock — under these dispositions, never the default action
/// (which would kill the worker and end PID 1). HUP/USR1/USR2 are ignored;
/// TERM/INT/QUIT are recorded for `serve`. tokio replaces all six in `serve`
/// before any child is spawned, so no child inherits the SIG_IGN.
fn worker_dispositions() -> Result<()> {
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    for (sig, handler) in [
        (Signal::SIGHUP, SigHandler::SigIgn),
        (Signal::SIGUSR1, SigHandler::SigIgn),
        (Signal::SIGUSR2, SigHandler::SigIgn),
        (Signal::SIGTERM, SigHandler::Handler(early_stop)),
        (Signal::SIGINT, SigHandler::Handler(early_stop)),
        (Signal::SIGQUIT, SigHandler::Handler(early_stop)),
    ] {
        // SAFETY: SIG_IGN, or a handler that only stores to an atomic.
        unsafe { sigaction(sig, &SigAction::new(handler, SaFlags::SA_RESTART, SigSet::empty())) }.map_err(|e| CliError::Msg(format!("cannot set the {sig} disposition: {e}")))?;
    }
    Ok(())
}

/// Dispatch on the role before any runtime exists.
pub fn run(args: ShimArgs) -> Result<()> {
    if args.init_pid.is_none() && (std::process::id() == 1 || args.supervise) {
        return init::run(args.kill_after_s);
    }
    worker_dispositions()?;
    init::unblock_all();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if args.init_pid.is_some() {
        // SIGTERM (graceful) when init dies; the ppid poll below covers the
        // race where it died before this call.
        let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Msg(format!("cannot start the shim runtime: {e}")))?;
    rt.block_on(serve(args))
}

async fn bind(port: u16, what: &str) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| CliError::Msg(format!("cannot bind {what} port {port}: {e}")))
}

/// The six signal streams the worker handles, registered before anything
/// else in `serve` (registration installs tokio's handler at once).
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    usr1: tokio::signal::unix::Signal,
    usr2: tokio::signal::unix::Signal,
}

impl Signals {
    fn register() -> Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        let reg = |k: SignalKind| signal(k).map_err(|e| CliError::Msg(format!("cannot install signal handlers: {e}")));
        Ok(Signals {
            term: reg(SignalKind::terminate())?,
            int: reg(SignalKind::interrupt())?,
            quit: reg(SignalKind::quit())?,
            hup: reg(SignalKind::hangup())?,
            usr1: reg(SignalKind::user_defined1())?,
            usr2: reg(SignalKind::user_defined2())?,
        })
    }
}

/// Peer mode and the agent guard read `/proc/net/tcp`: off Linux they are
/// refused at startup (fail closed), never silently off.
fn check_guard_host(hook_source: hooks::HookSource, guard: peer::AgentGuard) -> Result<()> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    if hook_source == hooks::HookSource::Peer {
        return Err(CliError::Usage("--hook-source peer needs Linux (/proc/net/tcp)".into()));
    }
    if guard == peer::AgentGuard::On {
        return Err(CliError::Usage("--agent-guard on needs Linux (/proc/net/tcp)".into()));
    }
    Ok(())
}

async fn serve(args: ShimArgs) -> Result<()> {
    // First, before binding or spawning anything: from here on a signal is
    // tokio's, and children get default dispositions back at exec.
    let signals = Signals::register()?;
    let agent_guard = args.agent_guard.unwrap_or_else(peer::AgentGuard::default_for_host);
    check_guard_host(args.hook_source, agent_guard)?;
    let opts = health::ShimOpts {
        hook_source: args.hook_source,
        agent_guard,
        clock: args.clock,
        delay_run: args.delay_run.unwrap_or(0),
        fs_root: args.fs_root.clone(),
        home: args.home.clone(),
        uid: args.uid,
        gid: args.gid,
        window_bytes: args.agent_window_bytes.unwrap_or(crate::wire::frame::STDOUT_WINDOW_BYTES),
    };
    let probe = health::ProbeSpec::for_agent(args.uid, args.gid);
    let state = Arc::new(health::ShimState::with(args.claude.clone(), opts, probe, Arc::new(sys::RealSys)));
    let hooks_l = bind(args.hooks_port, "hooks").await?;
    let app_l = bind(args.app_port, "app").await?;
    let code_l = bind(args.code_port, "code").await?;
    let v = env!("CARGO_PKG_VERSION");
    // One line per listener with the ACTUALLY bound address (`--*-port 0`
    // picks a free port): tests/shim_local.rs parses "<role> listening on ".
    errln!("ai-env: shim {v} hooks listening on {}", hooks_l.local_addr()?);
    errln!("ai-env: shim {v} app listening on {}", app_l.local_addr()?);
    errln!("ai-env: shim {v} code listening on {}", code_l.local_addr()?);
    errln!("ai-env: shim {v} hook-source {} agent-guard {}", args.hook_source.name(), agent_guard.name());
    state.set_ports(health::BoundPorts { hooks: hooks_l.local_addr()?.port(), app: app_l.local_addr()?.port(), code: code_l.local_addr()?.port() });
    state.set_bound();
    errln!("ai-env: shim worker pid {} (init {})", std::process::id(), args.init_pid.map_or("none".to_string(), |p| p.to_string()));
    errln!("ai-env: boot {}", serde_json::to_string(&sys::boot_report(state.sys.as_ref())).unwrap_or_default());

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(probe_until_ready(state.clone(), stop_rx.clone()));
    tokio::spawn(stop_on_signal_or_orphan(state.clone(), stop_tx, signals, args.init_pid));

    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    // Every router sees both ends of its connections (the peer guard).
    let hooks_srv = axum::serve(hooks_l, hooks::router(state.clone()).into_make_service_with_connect_info::<peer::Peer>())
        .with_graceful_shutdown(stopped(stop_rx.clone()));
    let app_srv = axum::serve(app_l, health::router(state.clone()).into_make_service_with_connect_info::<peer::Peer>()).with_graceful_shutdown(stopped(stop_rx.clone()));
    let code_srv = axum::serve(code_l, code::router(state.clone()).into_make_service_with_connect_info::<peer::Peer>()).with_graceful_shutdown(stopped(stop_rx));
    let (h, a, c) = tokio::join!(hooks_srv.into_future(), app_srv.into_future(), code_srv.into_future());
    for (what, r) in [("hooks", h), ("app", a), ("code", c)] {
        r.map_err(|e| CliError::Msg(format!("shim {what} server error: {e}")))?;
    }
    errln!("ai-env: shim stopped");
    Ok(())
}


/// Probe `claude --version` until it answers (1 s, 2 s, … 10 s apart), so
/// `/ready` can flip and the snapshot carries the cached version.
async fn probe_until_ready(state: Arc<health::ShimState>, stop: tokio::sync::watch::Receiver<bool>) {
    let mut wait = 1;
    loop {
        let t = Instant::now();
        match state.probe_once().await {
            Ok(line) => {
                errln!("ai-env: claude probe ok in {} ms: {line}", t.elapsed().as_millis());
                return;
            }
            Err(e) => errln!("ai-env: claude probe failed in {} ms: {e}; retry in {wait} s", t.elapsed().as_millis()),
        }
        if *stop.borrow() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(wait)).await;
        wait = (wait * 2).min(10);
    }
}

/// Graceful stop on SIGTERM/SIGINT/SIGQUIT (also one that arrived while the
/// worker was starting: [`EARLY_STOP`]), or when the init that spawned us is
/// gone (reparented: `getppid()` changed). HUP/USR1/USR2 are logged and
/// otherwise ignored (their default action would kill the worker). A signal
/// before `run` set the worker's dispositions is still blocked by the mask
/// inherited from init, so there is no window with the default action.
async fn stop_on_signal_or_orphan(state: Arc<health::ShimState>, stop: tokio::sync::watch::Sender<bool>, mut sig: Signals, init_pid: Option<u32>) {
    let early = EARLY_STOP.load(Ordering::SeqCst);
    let why = if early != 0 {
        format!("{} during startup", nix::sys::signal::Signal::try_from(early).map_or("a stop signal", |s| s.as_str()))
    } else {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = sig.term.recv() => break "SIGTERM".to_string(),
                _ = sig.int.recv() => break "SIGINT".to_string(),
                _ = sig.quit.recv() => break "SIGQUIT".to_string(),
                _ = sig.hup.recv() => errln!("ai-env: SIGHUP ignored"),
                _ = sig.usr1.recv() => errln!("ai-env: SIGUSR1 ignored"),
                _ = sig.usr2.recv() => errln!("ai-env: SIGUSR2 ignored"),
                _ = tick.tick() => {
                    if let Some(p) = init_pid {
                        if nix::unistd::getppid().as_raw().unsigned_abs() != p {
                            break "init is gone".to_string();
                        }
                    }
                }
            }
        }
    };
    errln!("ai-env: shim stopping ({why})");
    // First: the cached credential goes, and none is accepted from here on (S7).
    hooks::begin_stop(&state, "stop");
    // Upgraded sockets are not tracked by axum's graceful shutdown: close them,
    // then stop every spawn's process group, before the servers end.
    state.agents.close_all(crate::wire::frame::CLOSE_GOING_AWAY, "stopping").await;
    state.spawns.shutdown("stop").await;
    let _ = stop.send(true);
}
