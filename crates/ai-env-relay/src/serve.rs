//! `RelayApp`, `Deps`, `Clock`, the two servers, `run`, shutdown (R-1, R-2, R-5, R-15 to R-18, R-69 to R-71).
//!
//! Two faces, one service each (R-1): the public face serves `WorkerTunnel` only, the private face `Relay` only,
//! each on its own tonic server over the connections `admit` let through (R-2), each with its own HTTP/2 bounds
//! (R-5). `run` binds both, polls the live files, keeps the housekeeping going and speaks to systemd; the tests and
//! the lead's integration test serve in-process streams through `serve_public` and `serve_private` instead.
//!
//! Every public connection is watched from its accept to its close (R-2a): no `Open` within
//! `handshake_timeout_ms`, or its tunnel's end and a second's grace, and the watch cuts it, so it holds no
//! admission slot. The cut never reaches a live tunnel: it waits for the tunnel's end. A second `Open` on the
//! connection, which the face's one stream lets start only after the first stream's end, cuts it at once (R-6).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use ai_env_relay_proto::v1::relay_server::RelayServer;
use ai_env_relay_proto::v1::worker_tunnel_server::WorkerTunnelServer;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::calls::Outcome;
use crate::config::{ms, Config};
use crate::files::{Entries, Live, Loaded, Poll};
use crate::limits::{IpSlots, Sessions, TokenBucket};
use crate::lists::{WorkerEntry, Workers};
use crate::private::PrivateSvc;
use crate::registry::{holds_key, Registry, TunnelHandle};
use crate::reqlog::{RequestLog, StatusLine};
use crate::tls::{ConnUse, Conns, Face, PeerInfo, Peered};
use crate::tunnel::{close, TunnelSvc};
use crate::{files, notify, reqlog};

/// The HTTP/2 keepalive's timeout (R-5).
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// R-5, the private face: streams at once on one connection (a chat's eight calls and a list, with room to spare).
pub(crate) const PRIVATE_STREAMS: u32 = 16;
/// R-5, the private face: one request's header list (a token of at most 2048 bytes and its HTTP/2 and gRPC headers).
pub(crate) const PRIVATE_HEADER_LIST: u32 = 4096;
/// R-5, the public face: one request's header list.
pub(crate) const PUBLIC_HEADER_LIST: u32 = 16_384;
/// R-5, the private face: a request's decode and its handler, up to the response head (tonic's `Server::timeout`;
/// a started response stream is never cut). `enqueue_timeout_ms`, the handler's one wait, stays within half of it.
pub(crate) const PRIVATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// R-2a: after a tunnel's end, its connection's last frames have this long to leave before the cut.
const TUNNEL_END_GRACE: Duration = Duration::from_secs(1);
/// How long a stop waits for both servers (R-71).
const DRAIN: Duration = Duration::from_secs(5);
/// The session sweep's period (R-58).
const SWEEP: Duration = Duration::from_secs(60);

/// The relay's wall clock (tests use a manual one).
pub trait Clock: Send + Sync + 'static {
    /// Now.
    fn now(&self) -> SystemTime;
}

/// `SystemTime::now`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// What the relay is built with.
pub struct Deps {
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
    /// The request log's sink.
    pub sink: Arc<dyn reqlog::Sink>,
    /// The key of the params digest (R-63).
    pub params_key: [u8; 32],
    /// sd_notify.
    pub notifier: notify::Notifier,
}

impl Deps {
    /// SystemClock, the FileSink at `cfg.request_log`, 32 random bytes, `Notifier::from_env()`.
    pub fn production(cfg: &Config) -> Result<Deps, RelayError> {
        use aws_lc_rs::rand::SecureRandom;
        let sink = reqlog::FileSink::open(&cfg.request_log).map_err(|e| RelayError::Serve(format!("request log {}: {e}", cfg.request_log.display())))?;
        let mut params_key = [0u8; 32];
        aws_lc_rs::rand::SystemRandom::new().fill(&mut params_key).map_err(|_| RelayError::Serve("the system random generator failed".into()))?;
        Ok(Deps { clock: Arc::new(SystemClock), sink: Arc::new(sink), params_key, notifier: notify::Notifier::from_env() })
    }
}

/// Why the relay could not start or stopped.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The config was refused.
    #[error("config: {0}")]
    Config(String),
    /// A listener could not bind.
    #[error("bind {0}")]
    Bind(String),
    /// A server failed.
    #[error("serve: {0}")]
    Serve(String),
}

/// Everything the faces share.
pub(crate) struct RelayState {
    pub(crate) cfg: Config,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) log: Arc<RequestLog>,
    pub(crate) notifier: notify::Notifier,
    pub(crate) live: Live,
    pub(crate) registry: Registry,
    pub(crate) slots: IpSlots,
    /// The public face's connections, each watched from its accept to its close (R-2a, R-6).
    pub(crate) conns: Conns,
    pub(crate) sessions: Sessions,
    /// `calls_in_flight_max` (R-57).
    pub(crate) in_flight: Arc<Semaphore>,
    pub(crate) shutdown: CancellationToken,
    /// WorkerFrames with no known variant (P-R17).
    pub(crate) unknown_frames: AtomicU64,
    /// Chunks no call of their tunnel held (R-37).
    pub(crate) dropped_chunks: AtomicU64,
    /// Token faults to `relay.log`, at the request log's refusal rate (R-53, R-66).
    pub(crate) fault_log: Mutex<TokenBucket>,
    started: Instant,
    bound: Mutex<Option<(SocketAddr, SocketAddr)>>,
    housekeeping: AtomicBool,
}

impl RelayState {
    pub(crate) fn now(&self) -> SystemTime {
        self.clock.now()
    }

    pub(crate) fn now_unix(&self) -> u64 {
        self.now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }

    pub(crate) fn now_ms(&self) -> i64 {
        self.now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }

    pub(crate) fn max_stale(&self) -> Duration {
        Duration::from_secs(u64::from(self.cfg.limits.max_stale_s))
    }

    /// The age of a loaded file's last confirmed fetch, in seconds (0 when unknown).
    fn age_s<T>(&self, loaded: &Loaded<T>) -> u64 {
        loaded.fresh_at.and_then(|t| self.now().duration_since(t).ok()).map_or(0, |d| d.as_secs())
    }
}

/// The relay.
#[derive(Clone)]
pub struct RelayApp {
    state: Arc<RelayState>,
}

impl RelayApp {
    /// A relay of `cfg` and `deps`; it serves nothing yet.
    pub fn new(cfg: Config, deps: Deps) -> Result<RelayApp, RelayError> {
        cfg.validate().map_err(RelayError::Config)?;
        let l = &cfg.limits;
        let state = RelayState {
            log: Arc::new(RequestLog::new(deps.sink, deps.params_key, l.log_refusals_per_min)),
            clock: deps.clock,
            notifier: deps.notifier,
            live: Live::new(&cfg.live_dir),
            registry: Registry::new(),
            slots: IpSlots::new(l),
            conns: Conns::default(),
            sessions: Sessions::new(l),
            in_flight: Arc::new(Semaphore::new(l.calls_in_flight_max as usize)),
            shutdown: CancellationToken::new(),
            unknown_frames: AtomicU64::new(0),
            dropped_chunks: AtomicU64::new(0),
            fault_log: Mutex::new(TokenBucket::new(l.log_refusals_per_min, l.log_refusals_per_min, Instant::now())),
            started: Instant::now(),
            bound: Mutex::new(None),
            housekeeping: AtomicBool::new(false),
            cfg,
        };
        Ok(RelayApp { state: Arc::new(state) })
    }

    /// One poll of the live directory, with R-18's revocations and R-26's sweep; tests call it instead of waiting for
    /// the tick.
    pub fn poll_files(&self) -> [(&'static str, files::Poll); 4] {
        let st = &self.state;
        let now = st.now();
        let outcomes = st.live.poll(now, st.max_stale());
        for (file, outcome) in &outcomes {
            let Some(word) = outcome.word() else { continue };
            if let Poll::Refused(text) = outcome {
                // A field or an index, never a value (WM-R7): relay.log, not the request log.
                tracing::warn!(file = *file, "a live file was refused: {text}");
            }
            let (version, entries, age) = match *file {
                "workers" => described(st, &st.live.workers.loaded()),
                "token-signers" => described(st, &st.live.signers.loaded()),
                "grants" => described(st, &st.live.grants.loaded()),
                _ => described(st, &st.live.tls.loaded()),
            };
            let version = if matches!(outcome, Poll::Missing) { String::new() } else { version };
            st.log.reload(now, file, word, &version, entries, age);
        }
        self.apply_whitelist(now);
        outcomes
    }

    /// R-17 for every live tunnel against the workers file as it is now; then, the file loaded and fresh, R-18 and
    /// R-26's sweep (`revoke_and_sweep`).
    fn apply_whitelist(&self, now: SystemTime) {
        let st = &self.state;
        let tunnels = st.registry.live();
        let Some(loaded) = st.live.workers.loaded() else {
            for t in &tunnels {
                t.closer.close(close::STALE, "the whitelist is not loaded");
            }
            return;
        };
        if !files::is_fresh(loaded.fresh_at, now, st.max_stale()) {
            for t in &tunnels {
                t.closer.close(close::STALE, "the whitelist is stale");
            }
            return;
        }
        // With no tunnel live as well: the sweep reaches the offline entries of stopped workers.
        let swept = revoke_and_sweep(&st.registry, &loaded.value, &tunnels, st.now_unix());
        if swept > 0 {
            tracing::info!(sources = swept, "removed the sources the whitelist no longer allows");
        }
    }

    /// R-2: the face's admission, then TLS within the handshake budget; None closes the connection.
    pub async fn admit<IO>(&self, face: Face, io: IO, ip: IpAddr) -> Option<Peered<tokio_rustls::server::TlsStream<IO>>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let st = &self.state;
        let ip = ip.to_canonical();
        let refuse = |reason: &str| {
            st.log.peer(st.now(), face.word(), &ip.to_string(), reason);
            None
        };
        if st.shutdown.is_cancelled() {
            return refuse("shutting_down");
        }
        // Before any TLS byte: a refusal drops `io`, closing the connection without writing (R-2).
        let slot = match st.slots.admit(face, ip, Instant::now()) {
            Ok(slot) => slot,
            Err(r) => return refuse(r.word()),
        };
        if face == Face::Private && !st.cfg.private_peers.iter().any(|n| n.contains(&ip)) {
            return refuse("not_in_peers");
        }
        let Some(tls) = st.live.tls.loaded() else {
            return refuse("no_tls");
        };
        match crate::tls::accept(tls.value, io, ip, slot, ms(st.cfg.limits.tls_handshake_timeout_ms)).await {
            Ok(peered) => Some(peered),
            Err(reason) => refuse(reason),
        }
    }

    /// R-5's HTTP/2 settings both faces share.
    fn h2(&self) -> tonic::transport::Server {
        let l = &self.state.cfg.limits;
        let keepalive = (l.h2_keepalive_s > 0).then(|| Duration::from_secs(u64::from(l.h2_keepalive_s)));
        tonic::transport::Server::builder()
            .http2_keepalive_interval(keepalive)
            .http2_keepalive_timeout(Some(H2_KEEPALIVE_TIMEOUT))
            .initial_connection_window_size(Some(1 << 20))
            .initial_stream_window_size(Some(1 << 20))
            .http2_max_pending_accept_reset_streams(Some(16))
            .http2_max_local_error_reset_streams(Some(64))
    }

    /// R-5's public face: one stream at a time (R-6), a 16 KiB header list.
    fn public_server(&self) -> tonic::transport::Server {
        self.h2().max_concurrent_streams(Some(1)).http2_max_header_list_size(Some(PUBLIC_HEADER_LIST))
    }

    /// R-5's private face, its own builder: 16 streams a connection, a 4 KiB header list, and every request decoded
    /// and answered (its response head, or its status) within 10 s, so what a caller with no token pins is bounded
    /// (§R-relay.4's budget, unit 28) and held at most 10 s.
    fn private_server(&self) -> tonic::transport::Server {
        self.h2().max_concurrent_streams(Some(PRIVATE_STREAMS)).http2_max_header_list_size(Some(PRIVATE_HEADER_LIST)).timeout(PRIVATE_REQUEST_TIMEOUT)
    }

    /// Serves `WorkerTunnel` (R-5's settings) on `incoming` until `shutdown`, each connection watched (R-2a).
    pub async fn serve_public<S, IO, E>(&self, incoming: S) -> Result<(), RelayError>
    where
        S: tokio_stream::Stream<Item = Result<Peered<IO>, E>> + Send + 'static,
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        use tokio_stream::StreamExt as _;
        self.start_housekeeping();
        let svc = WorkerTunnelServer::new(TunnelSvc::new(Arc::clone(&self.state))).max_decoding_message_size(self.state.cfg.limits.catalog_max_bytes as usize);
        let state = Arc::clone(&self.state);
        // The watch starts before tonic sees the connection, so `open()` always finds it.
        let incoming = incoming.map(move |c| {
            c.map(|mut peered| {
                watch_public(&state, &mut peered);
                peered
            })
        });
        self.public_server()
            .serve_with_incoming_shutdown(svc, incoming, self.state.shutdown.clone().cancelled_owned())
            .await
            .map_err(|e| RelayError::Serve(e.to_string()))
    }

    /// Serves `Relay` on `incoming` until `shutdown` (R-5's private bounds).
    pub async fn serve_private<S, IO, E>(&self, incoming: S) -> Result<(), RelayError>
    where
        S: tokio_stream::Stream<Item = Result<Peered<IO>, E>> + Send + 'static,
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.start_housekeeping();
        let max = self.state.cfg.limits.params_max_bytes as usize + 16_384;
        let svc = RelayServer::new(PrivateSvc::new(Arc::clone(&self.state))).max_decoding_message_size(max);
        self.private_server()
            .serve_with_incoming_shutdown(svc, incoming, self.state.shutdown.clone().cancelled_owned())
            .await
            .map_err(|e| RelayError::Serve(e.to_string()))
    }

    /// The status line every `status_log_s` (R-67) and the session sweep every 60 s (R-58), from the first serve.
    fn start_housekeeping(&self) {
        if self.state.housekeeping.swap(true, Ordering::SeqCst) {
            return;
        }
        let app = self.clone();
        tokio::spawn(async move {
            let st = Arc::clone(&app.state);
            let every = Duration::from_secs(u64::from(st.cfg.limits.status_log_s));
            let mut status = tokio::time::interval_at(Instant::now() + every, every);
            let mut sweep = tokio::time::interval_at(Instant::now() + SWEEP, SWEEP);
            loop {
                tokio::select! {
                    _ = status.tick() => st.log.status(st.now(), &app.snapshot()),
                    _ = sweep.tick() => {
                        st.sessions.sweep(Instant::now());
                        st.slots.sweep(Instant::now());
                    }
                    () = st.shutdown.cancelled() => break,
                }
            }
        });
    }

    /// Production: binds both faces, admits every connection through `admit`, polls, sweeps, notifies (R-69 to R-71).
    pub async fn run(&self) -> Result<(), RelayError> {
        let st = Arc::clone(&self.state);
        self.poll_files();
        let bind = |addr: SocketAddr| async move { tokio::net::TcpListener::bind(addr).await.map_err(|e| RelayError::Bind(format!("{addr}: {e}"))) };
        let public = bind(st.cfg.public_addr).await?;
        let private = bind(st.cfg.private_addr).await?;
        let addrs = (public.local_addr().map_err(|e| RelayError::Bind(e.to_string()))?, private.local_addr().map_err(|e| RelayError::Bind(e.to_string()))?);
        *st.bound.lock().unwrap_or_else(PoisonError::into_inner) = Some(addrs);
        let (public_tx, public_rx) = mpsc::channel(64);
        let (private_tx, private_rx) = mpsc::channel(64);
        tokio::spawn(self.clone().accept_loop(Face::Public, public, public_tx));
        tokio::spawn(self.clone().accept_loop(Face::Private, private, private_tx));
        let servers = async {
            let (a, b) = tokio::join!(
                self.serve_public(tokio_stream::wrappers::ReceiverStream::new(public_rx)),
                self.serve_private(tokio_stream::wrappers::ReceiverStream::new(private_rx))
            );
            a.and(b)
        };
        tokio::pin!(servers);
        self.start_ticks();
        st.notifier.ready("tunnels=0");
        tracing::info!(public = %addrs.0, private = %addrs.1, "the relay is ready");
        tokio::select! {
            r = &mut servers => r,
            () = st.shutdown.cancelled() => {
                // R-71: at most five seconds for both servers, then out.
                if tokio::time::timeout(DRAIN, &mut servers).await.is_err() {
                    tracing::warn!("the servers did not drain within {} s", DRAIN.as_secs());
                }
                Ok(())
            }
        }
    }

    /// One face's accepts: each connection admitted in its own task, so a slow TLS client blocks no other.
    async fn accept_loop(self, face: Face, listener: tokio::net::TcpListener, tx: mpsc::Sender<Result<Peered<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>, std::io::Error>>) {
        let shutdown = self.state.shutdown.clone();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((tcp, peer)) => {
                        let _ = tcp.set_nodelay(true);
                        let (app, tx) = (self.clone(), tx.clone());
                        tokio::spawn(async move {
                            if let Some(peered) = app.admit(face, tcp, peer.ip()).await {
                                let _ = tx.send(Ok(peered)).await;
                            }
                        });
                    }
                    Err(e) => {
                        // Out of descriptors and the like: wait a moment rather than spin.
                        tracing::warn!(face = face.word(), "accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                () = shutdown.cancelled() => break,
            }
        }
    }

    /// The poll tick (R-15) and the watchdog (R-70).
    fn start_ticks(&self) {
        let app = self.clone();
        let st = Arc::clone(&self.state);
        tokio::spawn(async move {
            let every = ms(st.cfg.limits.files_poll_ms);
            let mut tick = tokio::time::interval_at(Instant::now() + every, every);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        app.poll_files();
                    }
                    () = st.shutdown.cancelled() => break,
                }
            }
        });
        let usec = std::env::var("WATCHDOG_USEC").ok();
        let pid = std::env::var("WATCHDOG_PID").ok();
        let Some(every) = notify::watchdog_interval(usec.as_deref(), pid.as_deref(), std::process::id()) else {
            return;
        };
        let st = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        // A probe of the registry first, taking each shard's lock briefly: a parked shard or
                        // runtime stops the pings, and systemd restarts the relay (R-70).
                        let live = st.registry.live();
                        let pending: usize = live.iter().map(|t| t.calls.len()).sum();
                        st.notifier.watchdog();
                        tracing::trace!(tunnels = live.len(), pending, "watchdog");
                    }
                    () = st.shutdown.cancelled() => break,
                }
            }
        });
    }

    /// The bound public and private addresses, once `run` bound them.
    pub fn bound(&self) -> Option<(SocketAddr, SocketAddr)> {
        *self.state.bound.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The public connections watched now (R-2a), each from the moment the face takes it to its cut or its end; for
    /// the tests.
    #[doc(hidden)]
    pub fn public_conns(&self) -> usize {
        self.state.conns.len()
    }

    /// Stops both servers (R-71): `STOPPING=1`, no more admissions, `Close{NORMAL}` to every tunnel, every pending
    /// call ended `Shutdown`; `run` then waits at most 5 s for the servers.
    pub fn shutdown(&self) {
        let st = &self.state;
        if st.shutdown.is_cancelled() {
            return;
        }
        st.notifier.stopping();
        for t in st.registry.live() {
            t.closer.close(close::NORMAL, "the relay is shutting down");
            t.calls.fail_all(Outcome::Shutdown);
        }
        st.shutdown.cancel();
    }

    /// The status line's values now (R-67).
    pub fn snapshot(&self) -> reqlog::StatusLine {
        let st = &self.state;
        let live = st.registry.live();
        let (sources_live, sources_offline) = st.registry.counts();
        let (workers_version, _, workers_age_s) = described(st, &st.live.workers.loaded());
        let (signers_version, _, signers_age_s) = described(st, &st.live.signers.loaded());
        let (grants_version, _, grants_age_s) = described(st, &st.live.grants.loaded());
        StatusLine {
            relay_version: crate::RELAY_VERSION.to_string(),
            protocol: ai_env_relay_proto::PROTOCOL,
            uptime_s: st.started.elapsed().as_secs(),
            tunnels: live.len() as u64,
            sources_live: sources_live as u64,
            sources_offline: sources_offline as u64,
            calls_in_flight: live.iter().map(|t| t.calls.len() as u64).sum(),
            sessions: st.sessions.len() as u64,
            workers_version,
            workers_age_s,
            signers_version,
            signers_age_s,
            grants_version,
            grants_age_s,
            tls_loaded: st.live.tls.loaded().is_some(),
            unknown_frames: st.unknown_frames.load(Ordering::SeqCst),
            log_dropped: reqlog::dropped(),
        }
    }
}

/// R-2a: registers a public connection and starts its watch, its `Open` deadline counted from its accept.
fn watch_public<IO>(st: &Arc<RelayState>, peered: &mut Peered<IO>) {
    let info = peered.info();
    let conn = st.conns.insert(info.conn_seq);
    peered.watch(&conn);
    let deadline = peered.accepted() + ms(st.cfg.limits.handshake_timeout_ms);
    tokio::spawn(watch(Arc::clone(st), conn, info, deadline));
}

/// R-2a: one public connection from its accept to its close. No `Open` by `deadline` (or the relay stops first):
/// the cut, and a peer line `open_timeout`. Else its tunnel's end (its task or its response stream, whichever goes
/// first), `TUNNEL_END_GRACE` for the last frames, then the cut. The connection's own end stops the watch.
async fn watch(st: Arc<RelayState>, conn: Arc<ConnUse>, info: PeerInfo, deadline: Instant) {
    let (gone, ended) = (conn.gone(), conn.ended());
    let expired = tokio::select! {
        () = tokio::time::sleep_until(deadline) => true,
        () = st.shutdown.cancelled() => true,
        () = ended.cancelled() => false,
        () = gone.cancelled() => false,
    };
    // `expire` loses to an `open()` that came first: then the tunnel lives, and the watch waits for its end.
    if expired && conn.expire() {
        if !st.shutdown.is_cancelled() {
            st.log.peer(st.now(), Face::Public.word(), &info.ip.to_string(), "open_timeout");
        }
    } else {
        tokio::select! {
            () = async {
                ended.cancelled().await;
                tokio::time::sleep(TUNNEL_END_GRACE).await;
            } => conn.cut(),
            () = gone.cancelled() => {}
        }
    }
    st.conns.remove(info.conn_seq);
}

/// A loaded file's version (16 hex), entries and age, or `""`, 0, 0.
fn described<T: Entries>(st: &RelayState, loaded: &Option<Loaded<T>>) -> (String, u64, u64) {
    match loaded {
        Some(l) => (format!("{:016x}", l.version), l.value.entries() as u64, st.age_s(l)),
        None => (String::new(), 0, 0),
    }
}

/// R-18 for each of `tunnels` (the live ones as the poll began) against `workers`, then R-26's sweep of every source
/// entry, live or offline, whose worker `workers` no longer allows. A tunnel the sweep cuts is closed as R-18 closes
/// it: R-18 has usually closed it already (the first Close stands), but a catalog installed after `tunnels` was
/// taken was never judged, and must not stay cut and open. Returns how many entries the sweep removed.
fn revoke_and_sweep(registry: &Registry, workers: &Workers, tunnels: &[TunnelHandle], now_unix: u64) -> usize {
    for t in tunnels {
        // Wider globs or a later `not_after` close nothing (R-18).
        let narrowed = |e: &WorkerEntry| registry.sources_of(&t.worker_id, t.conn_id).iter().any(|s| !e.allows_source(s));
        if let Some(reason) = revocation(workers, t, now_unix, narrowed) {
            t.closer.close(close::REVOKED, reason);
        }
    }
    let (swept, cut) = registry.sweep(workers, now_unix);
    for t in &cut {
        // The sweep cut one of its names, so with its pair in force the globs no longer allow that name.
        if let Some(reason) = revocation(workers, t, now_unix, |_| true) {
            t.closer.close(close::REVOKED, reason);
        }
    }
    swept
}

/// R-18's reason to close `t`: its pair (worker_id, key) gone, `revoked`; its entry lapsed, `expired`; `narrowed`
/// true of its entry, `sources narrowed`; else None.
fn revocation(workers: &Workers, t: &TunnelHandle, now_unix: u64, narrowed: impl FnOnce(&WorkerEntry) -> bool) -> Option<&'static str> {
    match workers.entry(&t.worker_id) {
        Some(e) if holds_key(e, &t.public_key) => {
            if workers.in_force(&t.worker_id, now_unix).is_none() {
                Some("expired")
            } else if narrowed(e) {
                Some("sources narrowed")
            } else {
                None
            }
        }
        _ => Some("revoked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{catalog, file, now, tunnel, whitelisted};

    /// R-18 then R-26's sweep (review finding 2). Tunnels the poll's snapshot missed (their catalogs landed after it):
    /// the one the sweep cuts is closed with R-18's reason, the one it leaves whole stays open. Tunnels of the
    /// snapshot: R-18 judges each by its pair, whatever it registered.
    #[test]
    fn a_tunnel_the_sweep_cuts_is_closed_as_r18_closes_it() {
        let a = whitelisted("worker-a", 1, &["example.*"]);
        let b = whitelisted("worker-b", 2, &["other.*"]);
        let narrowed = WorkerEntry { sources: vec!["example.alpha".into()], ..a.clone() };
        let rotated = whitelisted("worker-a", 3, &["example.*"]);
        let lapsed = WorkerEntry { not_after: "2026-10-01T23:59:59Z".into(), ..a.clone() };
        let cases = [
            (vec![narrowed, b.clone()], 1, "sources narrowed"),
            (vec![b.clone()], 2, "revoked"),
            (vec![rotated, b.clone()], 2, "revoked"),
            (vec![lapsed.clone(), b.clone()], 2, "expired"),
        ];
        for (entries, swept, reason) in cases {
            let reg = Registry::new();
            let ta = tunnel(&reg, "worker-a", 1);
            reg.install(ta.clone(), &a, catalog(&["example.alpha", "example.alpha.logs"]), 0).unwrap();
            let tb = tunnel(&reg, "worker-b", 2);
            reg.install(tb.clone(), &b, catalog(&["other.x"]), 0).unwrap();
            assert_eq!(revoke_and_sweep(&reg, &file(&entries), &[], now()), swept, "{reason}");
            assert_eq!(ta.closer.peek(), Some((close::REVOKED, reason.to_string())), "{reason}");
            assert_eq!(tb.closer.peek(), None, "{reason}: worker-b's tunnel, left whole, stays open");
        }

        for (entries, reason) in [(vec![b.clone()], Some("revoked")), (vec![lapsed, b.clone()], Some("expired")), (vec![a, b], None)] {
            let reg = Registry::new();
            let ta = tunnel(&reg, "worker-a", 1);
            assert_eq!(revoke_and_sweep(&reg, &file(&entries), std::slice::from_ref(&ta), now()), 0, "nothing registered to sweep");
            assert_eq!(ta.closer.peek(), reason.map(|r| (close::REVOKED, r.to_string())));
        }
    }
}
