//! S11 (B.5): `ai-env panel serve`, a local control panel on 127.0.0.1:
//! sessions, VMs, the audit, settings diffs and cost; suspend, resume,
//! migrate, terminate and refresh through the same library as the CLI (one
//! Touch ID each). Every request carries this run's bearer in its path.
//!
//! The lifecycle ([`cmd_serve`]): `--bind` checked before anything is read,
//! the actor set to `panel`, `[panel]` read, the listener bound on
//! [`BIND`] (never a parsed address) and checked loopback again, a fresh
//! bearer per run (never on disk, in argv or in a log), the URL printed once
//! on stdout, then a two-worker server ([`routes`]) beside one std worker
//! thread that runs one action at a time ([`actions`]); SIGINT, SIGTERM or
//! SIGHUP stop it: no new connection, every `events` stream ended
//! ([`sse`]), a running action waited for at most [`STOP_WAIT`], then exit 0.
//! Each request passes [`guard::judge`] and each response
//! [`guard::harden`]; pages are rendered by hand ([`html`]) from the models
//! the CLI's views share ([`model`]).
pub mod actions;
pub mod guard;
pub mod html;
pub mod model;
pub mod routes;
pub mod sse;

use crate::bridge::audit::{self, Actor, AuditRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::signals;
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::redact::Secret;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The only address.
pub const BIND: std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;
/// The only `--bind` accepted.
pub const BIND_TEXT: &str = "127.0.0.1";
/// Random bytes per run.
pub const BEARER_BYTES: usize = 32;
/// Its base64url length, no padding.
pub const BEARER_LEN: usize = 43;
/// A POST body's bytes.
pub const BODY_MAX: usize = 4096;
/// A POST's content type (parameters after `;` ignored).
pub const FORM_TYPE: &str = "application/x-www-form-urlencoded";
/// A nonce's life.
pub const NONCE_TTL: Duration = Duration::from_secs(300);
/// Nonces held; the oldest dropped.
pub const NONCES_MAX: usize = 64;
/// `events` streams at once.
pub const SSE_MAX: usize = 8;
/// A comment line on each stream.
pub const SSE_KEEPALIVE: Duration = Duration::from_secs(15);
/// The list pages' `<meta http-equiv="refresh">`.
pub const REFRESH_S: u32 = 30;
/// Rows `audit` shows before its live rows.
pub const AUDIT_PAGE_ROWS: usize = 200;
/// A running action's wait at stop.
pub const STOP_WAIT: Duration = Duration::from_secs(10);
/// The server runtime's workers.
pub const SERVER_THREADS: usize = 2;
/// Every response's `Content-Security-Policy`.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
/// Every response's headers.
pub const HEADERS: [(&str, &str); 6] = [
    ("content-security-policy", CSP),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("cache-control", "no-store"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// What the server's handlers and the worker share for the life of the process.
pub(crate) struct Shared {
    pub(crate) paths: Paths,
    /// The bound port (the `Host` and `Origin` checks name it).
    pub(crate) port: u16,
    pub(crate) bearer: Secret<String>,
    pub(crate) nonces: Mutex<actions::Nonces>,
    pub(crate) board: Mutex<actions::Board>,
    /// The worker's queue (one action at a time; `board` says whether one runs).
    pub(crate) jobs: Mutex<std::sync::mpsc::Sender<actions::Job>>,
    /// Each action's state as it changes, for the `events` streams.
    pub(crate) changes: tokio::sync::broadcast::Sender<actions::ActionView>,
    /// `events` streams open now.
    pub(crate) streams: AtomicUsize,
    /// `true` once the panel stops: every `events` stream ends.
    pub(crate) stopping: tokio::sync::watch::Receiver<bool>,
}

impl Shared {
    /// The nonces, whatever a panicked holder left.
    pub(crate) fn nonces(&self) -> std::sync::MutexGuard<'_, actions::Nonces> {
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The board, whatever a panicked holder left.
    pub(crate) fn board(&self) -> std::sync::MutexGuard<'_, actions::Board> {
        self.board.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Change action `id` on the board and tell the streams, the board held across the send (which never
    /// blocks): the streams see the changes in the board's order.
    pub(crate) fn update(&self, id: &str, change: impl FnOnce(&mut actions::ActionView)) {
        let mut board = self.board();
        if let Some(view) = board.update(id, change) {
            let _ = self.changes.send(view);
        }
    }
}

/// One line on stderr, never a panic (a closed terminal is no crash).
fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// A fresh bearer: [`BEARER_BYTES`] random bytes, base64url without padding ([`BEARER_LEN`] characters).
fn new_bearer() -> crate::errors::Result<Secret<String>> {
    use base64::Engine as _;
    let mut bytes = zeroize::Zeroizing::new([0u8; BEARER_BYTES]);
    getrandom::fill(&mut bytes[..]).map_err(|e| CliError::Msg(format!("panel serve: the random source failed: {e}")))?;
    let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..]);
    debug_assert_eq!(text.len(), BEARER_LEN);
    Ok(Secret::new(text))
}

/// `panel_serve {port, outcome}`; a failure to write is a warning, never fatal.
fn audit_serve(paths: &Paths, port: u16, outcome: &str) {
    let row = AuditRow::new(audit::event::PANEL_SERVE, None, audit::detail(&[("port", port.to_string()), ("outcome", outcome.to_string())]));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        say(&format!("ai-env: warning: audit row {} not written: {e}", audit::event::PANEL_SERVE));
    }
}

/// `ai-env panel serve [--port N] [--bind 127.0.0.1]`: serve the panel in the foreground until Ctrl-C (B §B5.3).
/// Exits: 2 a `--bind` other than 127.0.0.1; 9 `[panel]` not enabled, or a bound address that is no loopback;
/// 1 the port busy; 0 after a stop.
pub fn cmd_serve(store: &Keystore, port: Option<u16>, bind: Option<&str>) -> crate::errors::Result<()> {
    if let Some(b) = bind.filter(|b| *b != BIND_TEXT) {
        return Err(CliError::Usage(format!("panel serve: --bind {b}: the panel listens on 127.0.0.1 only")));
    }
    audit::set_actor(Actor::Panel);
    let paths = Paths::resolve()?;
    let panel = BridgeConfig::load(&paths)?.map(|c| c.panel).unwrap_or_default();
    if !panel.enabled {
        return Err(CliError::Policy(format!("panel serve is off: [panel] enabled = false in {}  <- set [panel] enabled = true in bridge.toml", paths.config.display())));
    }
    let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
    // Before any listener could replace them: a stop signal ignored at start stays ignored.
    signals::note_dispositions();
    let want = port.unwrap_or(panel.port);
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from((BIND, want))).map_err(|e| {
        let what = if e.kind() == std::io::ErrorKind::AddrInUse { "is in use" } else { "cannot be listened on" };
        CliError::Msg(format!("panel serve: 127.0.0.1:{want} {what} ({e})  <- --port N, or --port 0 for any free port"))
    })?;
    let addr = listener.local_addr().map_err(|e| CliError::Msg(format!("panel serve: the bound address: {e}")))?;
    if !addr.ip().is_loopback() {
        return Err(CliError::Policy(format!("panel serve: bound {addr}, not a loopback address: refused")));
    }
    listener.set_nonblocking(true).map_err(|e| CliError::Msg(format!("panel serve: {e}")))?;
    let port = addr.port();
    // The server's runtime and the stop listeners before the URL line: a stop from then on is the panel's own
    // (its `stopped` row, exit 0), never the signal's default action.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(SERVER_THREADS)
        .thread_name("ai-env-panel")
        .enable_all()
        .build()
        .map_err(|e| CliError::Msg(format!("panel serve: cannot start the async runtime: {e}")))?;
    let stops = rt.block_on(async { signals::Stops::take() })?;
    let bearer = new_bearer()?;
    crate::wire::redact::register_secret(bearer.expose());
    crate::outln!("panel: http://127.0.0.1:{port}/{}/", bearer.expose());
    say(&format!("panel: serving on 127.0.0.1:{port} until Ctrl-C (the URL holds this run's bearer: do not share it)"));
    audit_serve(&paths, port, "started");
    tracing::info!("panel: serving on 127.0.0.1:{port}");
    let (stop_tx, stopping) = tokio::sync::watch::channel(false);
    let (jobs, queue) = std::sync::mpsc::channel();
    let shared = Arc::new(Shared {
        paths: paths.clone(),
        port,
        bearer,
        nonces: Mutex::new(actions::Nonces::default()),
        board: Mutex::new(actions::Board::default()),
        jobs: Mutex::new(jobs),
        changes: tokio::sync::broadcast::channel(64).0,
        streams: AtomicUsize::new(0),
        stopping,
    });
    std::thread::scope(|s| {
        let worker = Arc::clone(&shared);
        let spawned = std::thread::Builder::new().name("ai-env-panel-worker".into()).spawn_scoped(s, move || actions::work(store, &worker, &queue));
        let served = match spawned {
            Ok(_) => serve(rt, stops, &shared, listener, &stop_tx),
            Err(e) => Err(CliError::Msg(format!("panel serve: cannot start the action worker: {e}"))),
        };
        if let Err(e) = &served {
            say(&format!("ai-env: panel: {e}"));
        }
        audit_serve(&paths, port, "stopped");
        tracing::info!("panel: stopped");
        // The scope would join the worker, which may still run an abandoned action (a live migrate waits up
        // to 300 s): the process ends here (an offline move's `migrating_pid` then names a gone process).
        std::process::exit(served.map_or_else(|e| e.exit_code(), |()| 0));
    })
}

/// The server on its own runtime (`rt`, whose `stops` listen since before the URL line) until a stop signal;
/// then no new connection, the streams ended, and at most [`STOP_WAIT`] for the open connections and a running
/// action.
fn serve(
    rt: tokio::runtime::Runtime,
    mut stops: signals::Stops,
    shared: &Arc<Shared>,
    listener: std::net::TcpListener,
    stop_tx: &tokio::sync::watch::Sender<bool>,
) -> crate::errors::Result<()> {
    use std::future::IntoFuture as _;
    let served = rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| CliError::Msg(format!("panel serve: {e}")))?;
        let mut stopping = stop_tx.subscribe();
        let server = axum::serve(listener, routes::router(Arc::clone(shared))).with_graceful_shutdown(async move {
            let _ = stopping.wait_for(|s| *s).await;
        });
        let mut server = std::pin::pin!(server.into_future());
        let failed = tokio::select! {
            ended = &mut server => Some(ended),
            stop = stops.next() => {
                tracing::info!("panel: {} received: stopping", stop.name());
                None
            }
        };
        let _ = stop_tx.send(true);
        if let Some(ended) = failed {
            return ended.map_err(|e| CliError::Msg(format!("the server ended: {e}")));
        }
        let deadline = tokio::time::Instant::now() + STOP_WAIT;
        let _ = tokio::time::timeout_at(deadline, &mut server).await;
        while shared.board().busy().is_some() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if let Some(running) = shared.board().busy() {
            tracing::warn!("panel: stopped while {} {} still ran (abandoned)", running.action, running.target);
            say(&format!("ai-env: panel: stopped while {} {} still ran: it is abandoned", running.action, running.target));
        }
        Ok(())
    });
    // A page's model still being read on a blocking thread is not waited for.
    rt.shutdown_timeout(Duration::from_millis(200));
    served
}
