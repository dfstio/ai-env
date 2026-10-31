//! `TunnelSvc` (`WorkerTunnel`), the close codes, the pinger, `TunnelStream` (R-6 to R-29).
//!
//! `open()` answers at once with the `Challenge` queued (R-7) and leaves the rest to one task per tunnel: the
//! handshake within one budget from the connection's TLS accept, the one its `Open` had (R-9 to R-13, F24), the
//! first catalog (R-12, R-20), then the frame loop: chunks routed through the tunnel's call table (R-37 to R-41),
//! later catalogs (R-28), pings and the liveness timer (R-29), and at the end the teardown (R-24). Everything that
//! awaits on behalf of the call table awaits here, on values cloned out of it (R-75). The tunnel's task and its
//! response stream each end their connection's one use (R-2a): the first of them to go starts the grace after which
//! `serve.rs`'s watch cuts the connection. A second `Open` on the connection cuts it at once (R-6).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ai_env_relay_proto::v1::worker_tunnel_server::WorkerTunnel;
use ai_env_relay_proto::v1::{relay_frame, worker_frame, AuthOk, AuthProof, Cancel, Challenge, Hello, Ping, RelayFrame, WorkerFrame};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::calls::{CallState, CallTable, Delivery, Handoff, Outcome};
use crate::config::ms;
use crate::handshake::{self, AuthFault, Authed, NONCE_LEN};
use crate::limits::TokenBucket;
use crate::registry::{Closer, TunnelHandle};
use crate::reqlog::TunnelFields;
use crate::serve::RelayState;
use crate::tls::{Metered, OpenRefused, PeerInfo, TunnelEnd};

/// `Close.code` (R-27): P's 0 to 4, then R's 5 and 6, one definition in ai-env-source's `wire` (review A-L2).
pub use ai_env_source::wire::close;

/// R-109: a tunnel's chunks for ids its table neither holds nor recently ended, a burst of 16 at 16 a minute.
const UNKNOWN_CHUNKS: u32 = 16;
/// R-110: a tunnel's catalogs from its AuthOk, a burst of 3 at 6 a minute.
const CATALOG_BURST: u32 = 3;
const CATALOGS_PER_MIN: u32 = 6;
/// R-108: the unanswered Pings a Pong may answer, the last eight: two minutes of Pings, since a worker's Pong queues
/// behind its chunks on a slow uplink. A ninth forgets the oldest.
const UNANSWERED_PINGS: usize = 8;
/// R-112: an eviction is charged to its session when its oldest buffered chunk waited this long unread.
const UNREAD_CHARGE: Duration = Duration::from_secs(1);

/// The public face's service.
pub struct TunnelSvc {
    state: Arc<RelayState>,
}

impl TunnelSvc {
    /// The service of the relay `state`.
    pub(crate) fn new(state: Arc<RelayState>) -> TunnelSvc {
        TunnelSvc { state }
    }
}

#[tonic::async_trait]
impl WorkerTunnel for TunnelSvc {
    type OpenStream = TunnelStream;

    async fn open(&self, request: tonic::Request<tonic::Streaming<WorkerFrame>>) -> Result<tonic::Response<TunnelStream>, tonic::Status> {
        let st = &self.state;
        // R-1: the peer comes from the connection; a request without one cannot have come through `admit`.
        let Some(peer) = request.extensions().get::<PeerInfo>().copied() else {
            return Err(tonic::Status::internal("no peer"));
        };
        if st.shutdown.is_cancelled() {
            return Err(tonic::Status::unavailable("the relay is shutting down"));
        }
        // R-6 and R-2a: the connection's first `Open`, within its deadline; a later one finds the connection cut.
        let conn = st.conns.get(peer.conn_seq).ok_or_else(closing)?;
        match conn.open() {
            Ok(()) => {}
            Err(OpenRefused::Second) => {
                // R-6: the face's one stream (R-5) let this start only after the first stream's end reached the
                // client, so the cut loses nothing of the first tunnel; this status never leaves.
                conn.cut();
                return Err(tonic::Status::failed_precondition("one tunnel per connection"));
            }
            Err(OpenRefused::Closing) => return Err(closing()),
        }
        let nonce = handshake::new_nonce();
        let (tx, rx) = mpsc::channel(st.cfg.limits.tunnel_queue as usize);
        let challenge = Challenge { nonce: nonce.to_vec(), relay_id: st.cfg.relay_id.clone(), protocol: ai_env_relay_proto::PROTOCOL };
        // A fresh queue of at least four frames: the Challenge always fits, before anything is read (R-7).
        let _ = tx.try_send(Ok(frame(relay_frame::Msg::Challenge(challenge))));
        let closer = Closer::new();
        // F24: the handshake's budget is the `Open`'s own, from the TLS accept; a late `Open` buys no fresh one.
        let tunnel = Tunnel { st: Arc::clone(st), peer, nonce, tx, closer: closer.clone(), opened: conn.accepted(), _end: TunnelEnd::new(&conn) };
        tokio::spawn(tunnel.run(request.into_inner()));
        Ok(tonic::Response::new(TunnelStream::new(rx, closer, TunnelEnd::new(&conn))))
    }
}

/// R-2a: an `Open` on a connection whose deadline passed, or whose cut is under way.
fn closing() -> tonic::Status {
    tonic::Status::unavailable("the connection is closing")
}

fn frame(msg: relay_frame::Msg) -> RelayFrame {
    RelayFrame { msg: Some(msg) }
}

/// The `Cancel` of one call (R-43, R-46).
pub(crate) fn cancel_frame(request_id: &str, reason: &str) -> RelayFrame {
    frame(relay_frame::Msg::Cancel(Cancel { request_id: request_id.to_string(), reason: reason.to_string() }))
}

/// The response stream: the queued frames, then the stored Close (R-27), then the end.
pub struct TunnelStream {
    rx: mpsc::Receiver<Result<RelayFrame, tonic::Status>>,
    closer: Closer,
    closed: Pin<Box<WaitForCancellationFutureOwned>>,
    done: bool,
    /// Dropped with the stream (hyper sent its end, or the worker reset it): the connection's grace starts (R-2a).
    _end: TunnelEnd,
}

impl TunnelStream {
    fn new(rx: mpsc::Receiver<Result<RelayFrame, tonic::Status>>, closer: Closer, end: TunnelEnd) -> TunnelStream {
        let closed = Box::pin(closer.token().cancelled_owned());
        TunnelStream { rx, closer, closed, done: false, _end: end }
    }

    /// A closed tunnel yields its stored Close, even with a full queue, then ends with status 0 (R-27).
    fn finish(&mut self) -> Poll<Option<Result<RelayFrame, tonic::Status>>> {
        self.done = true;
        Poll::Ready(self.closer.stored().map(|c| Ok(frame(relay_frame::Msg::Close(c)))))
    }
}

impl tokio_stream::Stream for TunnelStream {
    type Item = Result<RelayFrame, tonic::Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.closer.is_closed() {
            return self.finish();
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(item)) => {
                if item.is_err() {
                    self.done = true;
                }
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => self.finish(),
            Poll::Pending => match self.closed.as_mut().poll(cx) {
                Poll::Ready(()) => self.finish(),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// Sends `frame` from a spawned task that waits at most `within` (used by `CallStream`'s drop, R-43).
pub fn send_later(tx: tokio::sync::mpsc::Sender<Result<RelayFrame, tonic::Status>>, frame: RelayFrame, within: Duration) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
    rt.spawn(async move {
        let _ = tx.send_timeout(Ok(frame), within).await;
    });
}

/// Sends a `Cancel` now when the queue has room, else within `within` from a task (R-43, R-46).
fn send_cancel(tx: &mpsc::Sender<Result<RelayFrame, tonic::Status>>, request_id: &str, reason: &str, within: Duration) {
    if let Err(mpsc::error::TrySendError::Full(Ok(f))) = tx.try_send(Ok(cancel_frame(request_id, reason))) {
        send_later(tx.clone(), f, within);
    }
}

/// How the frame loop ended, for the close line (R-65).
enum End {
    Closed,
    Eof,
    Error,
}

/// One tunnel's task.
struct Tunnel {
    st: Arc<RelayState>,
    peer: PeerInfo,
    nonce: [u8; NONCE_LEN],
    tx: mpsc::Sender<Result<RelayFrame, tonic::Status>>,
    closer: Closer,
    /// The connection's TLS accept: R-9's budget counts from here (F24).
    opened: Instant,
    /// Dropped when the task ends, its teardown done: the connection's grace starts (R-2a), even when the worker
    /// never reads the stream's last frames.
    _end: TunnelEnd,
}

/// The next inbound frame before `budget`, as the handshake reads it (R-9).
async fn next_before(inbound: &mut tonic::Streaming<WorkerFrame>, budget: Instant, shutdown: &CancellationToken) -> Result<worker_frame::Msg, AuthFault> {
    tokio::select! {
        r = tokio::time::timeout_at(budget, inbound.message()) => match r {
            Err(_) => Err(AuthFault::Timeout),
            Ok(Ok(Some(WorkerFrame { msg: Some(m) }))) => Ok(m),
            // A frame with no known variant is a fault before auth (LD-R24).
            Ok(Ok(Some(WorkerFrame { msg: None }))) => Err(AuthFault::OutOfOrder),
            Ok(Ok(None)) => Err(AuthFault::Eof),
            // The client's reset of its own stream arrives as the `Ok(None)` above today (tonic 0.14 absorbs it); this
            // `Cancelled` arm only guards a future tonic that would not. Any other stream error (a frame that does not
            // decode, one over the size cap, a bad gRPC flag) is a frame out of shape, a fault (R-102).
            Ok(Err(status)) if status.code() == tonic::Code::Cancelled => Err(AuthFault::Eof),
            Ok(Err(_)) => Err(AuthFault::Malformed),
        },
        () = shutdown.cancelled() => Err(AuthFault::Eof),
    }
}

impl Tunnel {
    async fn run(self, mut inbound: tonic::Streaming<WorkerFrame>) {
        let st = Arc::clone(&self.st);
        let mut line = TunnelFields { peer: self.peer.ip.to_string(), phase: "auth", ..TunnelFields::default() };
        // `verify_proof` checked the key's length; a frame's bytes never reach a panic (R-73).
        let checked = self.handshake(&mut inbound, &mut line).await.and_then(|a| match <[u8; 32]>::try_from(a.hello.public_key.as_slice()) {
            Ok(key) => Ok((a, key)),
            Err(_) => Err(AuthFault::Malformed),
        });
        let (authed, public_key) = match checked {
            Ok(a) => a,
            Err(fault) => {
                line.outcome = "refused";
                line.reason = fault.word();
                st.log.tunnel(st.now(), &line);
                // R-102: every fault but the relay's own and the client's leaving counts toward its address's ban.
                if fault.is_fault() {
                    st.slots.fault(self.peer.ip, Instant::now());
                }
                let status = if st.shutdown.is_cancelled() && fault == AuthFault::Eof {
                    tonic::Status::unavailable("the relay is shutting down")
                } else {
                    tonic::Status::unauthenticated("authentication failed")
                };
                // R-11: one status, no frame after the Challenge; the queue holds the Challenge at most.
                let _ = self.tx.try_send(Err(status));
                return;
            }
        };
        let worker_id = authed.hello.worker_id.clone();
        if st.registry.tunnels() >= st.cfg.limits.tunnels_max as usize && !st.registry.holds(&worker_id) {
            line.outcome = "refused";
            line.reason = "too_many_tunnels";
            st.log.tunnel(st.now(), &line);
            let _ = self.tx.try_send(Err(tonic::Status::resource_exhausted("too many tunnels")));
            return;
        }
        let tunnel_id = uuid::Uuid::now_v7();
        let ok = AuthOk { tunnel_id: tunnel_id.to_string(), whitelist_version: authed.whitelist_version };
        let _ = self.tx.try_send(Ok(frame(relay_frame::Msg::AuthOk(ok))));
        // R-98: an authenticated tunnel exempts its address from bans until `ban_window_s` after its end.
        let _exempt = Exempt::new(&st, self.peer.ip);
        line.tunnel = tunnel_id.to_string();
        line.outcome = "ok";
        st.log.tunnel(st.now(), &line);
        let handle = TunnelHandle {
            conn_id: st.registry.next_conn_id(),
            tunnel_id,
            worker_id,
            public_key,
            sdk_version: authed.hello.sdk_version.clone(),
            tx: self.tx.clone(),
            calls: Arc::new(CallTable::new(st.cfg.limits.calls_per_tunnel as usize)),
            closer: self.closer.clone(),
            last_seen_ms: Arc::new(AtomicI64::new(st.now_ms())),
            since_unix: st.now_unix(),
            peer_ip: self.peer.ip.to_canonical(),
        };
        let authed_at = Instant::now();
        let (end, installed) = self.serve(&mut inbound, &handle, &authed).await;
        drop(inbound);

        // R-24: the registry first (only this conn_id's entries), then the calls, then the line.
        let close = self.closer.peek();
        if installed.is_some() {
            let revoked = close.as_ref().is_some_and(|(code, _)| *code == close::REVOKED);
            st.registry.remove(&handle.worker_id, handle.conn_id, st.now_ms(), revoked);
        }
        let outcome = if st.shutdown.is_cancelled() { Outcome::Shutdown } else { Outcome::WorkerGone };
        handle.calls.fail_all(outcome);
        self.closer.end();
        line.phase = "close";
        line.outcome = "closed";
        line.reason = match (&end, &close) {
            (End::Eof, None) => "eof",
            (End::Error, None) => "error",
            (_, Some((code, reason))) => close_word(*code, reason),
            (End::Closed, None) => "normal",
        };
        // R-65: the count it had, its last accepted catalog's (a newer tunnel may have repointed the names already).
        line.sources = installed.unwrap_or(0);
        line.duration_ms = u64::try_from(authed_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        st.log.tunnel(st.now(), &line);
    }

    /// R-9 to R-11: exactly `Hello` then `AuthProof` within one budget from the TLS accept (F24), then R-10's checks.
    async fn handshake(&self, inbound: &mut tonic::Streaming<WorkerFrame>, line: &mut TunnelFields) -> Result<Authed, AuthFault> {
        let st = &self.st;
        let budget = self.opened + ms(st.cfg.limits.handshake_timeout_ms);
        let hello: Hello = match next_before(inbound, budget, &st.shutdown).await? {
            worker_frame::Msg::Hello(h) => h,
            _ => return Err(AuthFault::OutOfOrder),
        };
        if ai_env_worker::globs::valid_id(&hello.worker_id) {
            line.worker = hello.worker_id.clone();
        }
        line.sdk = handshake::sdk_label(&hello.sdk_version);
        let proof: AuthProof = match next_before(inbound, budget, &st.shutdown).await? {
            worker_frame::Msg::AuthProof(p) => p,
            _ => return Err(AuthFault::OutOfOrder),
        };
        let loaded = handshake::whitelist(&st.live.workers, st.now(), st.max_stale())?;
        let entry = handshake::verify_proof(Some(&loaded.value), &st.cfg.relay_id, &self.nonce, &hello, &proof, st.now_unix())?;
        Ok(Authed { entry, hello, whitelist_version: loaded.version })
    }

    /// After AuthOk: the first catalog within its budget, then every frame until the tunnel ends. Returns how it
    /// ended and, once it was installed, how many sources its last accepted catalog registered.
    ///
    /// The inbound budget from the AuthOk (R-107): one frame token per decoded frame before anything acts on it, and
    /// the connection's bytes charged as they are read (`Metered`); either short closes `inbound rate`. It budgets what
    /// the worker sends unasked (LD-R53): a chunk of a live call takes no frame token and its `encoded_len()` goes back,
    /// since the call's caps bound it. A Pong must answer one of the last eight unanswered Pings (R-108); chunks of no
    /// call have a budget of their own (R-109), besides R-107's; every catalog takes a catalog token, and one identical
    /// to the last installed is a no-op (R-110).
    async fn serve(&self, inbound: &mut tonic::Streaming<WorkerFrame>, handle: &TunnelHandle, authed: &Authed) -> (End, Option<u64>) {
        use ai_env_relay_proto::prost::Message as _;
        let st = &self.st;
        let l = &st.cfg.limits;
        let closed = self.closer.token();
        let now = Instant::now();
        let mut frames = TokenBucket::new(l.tunnel_frames_per_min, l.tunnel_frames_per_min, now);
        let gone = st.conns.get(self.peer.conn_seq).map(|c| c.gone());
        let metered = Metered::install(self.peer.conn_seq, l.tunnel_bytes_per_min, now, gone);
        let over = metered.short();
        let mut unknown_chunks = TokenBucket::new(UNKNOWN_CHUNKS, UNKNOWN_CHUNKS, now);
        let mut catalogs = TokenBucket::new(CATALOG_BURST, CATALOGS_PER_MIN, now);
        // LD-R29: the last installed catalog's digest is the task's own.
        let mut installed_digest: Option<Vec<u8>> = None;
        let mut unanswered: VecDeque<u64> = VecDeque::with_capacity(UNANSWERED_PINGS + 1);
        let catalog_by = now + ms(l.catalog_timeout_ms);
        let dead_after = ms(l.ping_dead_ms);
        let mut installed: Option<u64> = None;
        let mut seq = 0u64;
        let mut ping = tokio::time::interval_at(now + ms(l.ping_interval_ms), ms(l.ping_interval_ms));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let silence = tokio::time::sleep(dead_after);
        tokio::pin!(silence);
        loop {
            tokio::select! {
                biased;
                () = closed.cancelled() => return (End::Closed, installed),
                () = st.shutdown.cancelled() => {
                    self.closer.close(close::NORMAL, "the relay is shutting down");
                    return (End::Closed, installed);
                }
                () = over.cancelled() => {
                    self.closer.close(close::PROTOCOL, "inbound rate");
                    return (End::Closed, installed);
                }
                () = tokio::time::sleep_until(catalog_by), if installed.is_none() => {
                    self.closer.close(close::PROTOCOL, &format!("no catalog within {} s", l.catalog_timeout_ms / 1000));
                    return (End::Closed, installed);
                }
                () = &mut silence, if installed.is_some() => {
                    self.closer.close(close::PING_TIMEOUT, &format!("no frame for {} s", l.ping_dead_ms / 1000));
                    return (End::Closed, installed);
                }
                _ = ping.tick(), if installed.is_some() => {
                    seq += 1;
                    // Offered, never waited for: a full queue skips this Ping (R-29); a queued one awaits its Pong.
                    if handle.tx.try_send(Ok(frame(relay_frame::Msg::Ping(Ping { seq })))).is_ok() {
                        unanswered.push_back(seq);
                        if unanswered.len() > UNANSWERED_PINGS {
                            unanswered.pop_front();
                        }
                    }
                }
                next = inbound.message() => {
                    let inbound_frame = match next {
                        Ok(Some(f)) => f,
                        Ok(None) => return (End::Eof, installed),
                        Err(_) => return (End::Error, installed),
                    };
                    // R-107: the frame's token before anything acts on it, a frame with no variant included; only a
                    // frame inside the budget is a sign of life. Short, the connection reads nothing more, as when
                    // its bytes run short, until R-2a's cut. LD-R53: a chunk of a call in the table as it is read was
                    // asked for: no token, and its decoded length back to the bytes (what that length does not count
                    // stays charged). Every other chunk, `Late` or `Unknown`, is charged like any frame.
                    let asked_for = matches!(&inbound_frame.msg, Some(worker_frame::Msg::Chunk(c)) if handle.calls.holds(&c.request_id));
                    if asked_for {
                        metered.refund(inbound_frame.encoded_len() as u64);
                    } else if !frames.take(Instant::now()) {
                        metered.stall();
                        self.closer.close(close::PROTOCOL, "inbound rate");
                        return (End::Closed, installed);
                    }
                    silence.as_mut().reset(Instant::now() + dead_after);
                    handle.last_seen_ms.store(st.now_ms(), Ordering::SeqCst);
                    match inbound_frame.msg {
                        Some(worker_frame::Msg::Catalog(c)) => {
                            if !catalogs.take(Instant::now()) {
                                self.closer.close(close::PROTOCOL, "catalog rate");
                                return (End::Closed, installed);
                            }
                            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &c.encode_to_vec()).as_ref().to_vec();
                            if installed_digest.as_deref() == Some(digest.as_slice()) {
                                // R-110: the catalog installed already: no validation, no registry lock, no line.
                                continue;
                            }
                            let entry = self.current_entry(authed);
                            let count = c.sources.len() as u64;
                            st.catalog_installs.fetch_add(1, Ordering::SeqCst);
                            match st.registry.install(handle.clone(), &entry, c.sources, st.now_ms()) {
                                Ok(superseded) => {
                                    if let Some(old) = superseded {
                                        old.closer.close(close::SUPERSEDED, "superseded by a newer tunnel");
                                    }
                                    if installed.is_none() {
                                        silence.as_mut().reset(Instant::now() + dead_after);
                                        ping.reset();
                                    }
                                    installed = Some(count);
                                    installed_digest = Some(digest);
                                }
                                Err(refusal) => {
                                    self.closer.close(close::CATALOG_REFUSED, &refusal.reason());
                                    return (End::Closed, installed);
                                }
                            }
                        }
                        Some(worker_frame::Msg::Chunk(c)) => {
                            if !self.deliver(handle, c, &mut unknown_chunks).await {
                                self.closer.close(close::PROTOCOL, "chunks of no call");
                                return (End::Closed, installed);
                            }
                        }
                        Some(worker_frame::Msg::Hello(_)) => {
                            self.closer.close(close::PROTOCOL, "unexpected hello after auth");
                            return (End::Closed, installed);
                        }
                        Some(worker_frame::Msg::AuthProof(_)) => {
                            self.closer.close(close::PROTOCOL, "unexpected auth_proof after auth");
                            return (End::Closed, installed);
                        }
                        Some(worker_frame::Msg::Pong(p)) => {
                            // R-108: a Pong answers one of the last eight unanswered Pings, or closes the tunnel.
                            match unanswered.iter().position(|s| *s == p.seq) {
                                Some(i) => {
                                    unanswered.remove(i);
                                }
                                None => {
                                    self.closer.close(close::PROTOCOL, "unexpected pong");
                                    return (End::Closed, installed);
                                }
                            }
                        }
                        // A newer SDK's frame: ignored and counted (P-R17, LD-R24).
                        None => {
                            st.unknown_frames.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    }

    /// The worker's entry as the current whitelist holds it (a later catalog is checked against today's globs),
    /// else the one it authenticated with.
    fn current_entry(&self, authed: &Authed) -> crate::lists::WorkerEntry {
        let id = &authed.entry.worker_id;
        self.st
            .live
            .workers
            .loaded()
            .and_then(|l| l.value.entry(id).cloned())
            .filter(|e| e.public_key == authed.entry.public_key)
            .unwrap_or_else(|| authed.entry.clone())
    }

    /// One chunk: routed synchronously by the call table, then handed to its caller's buffer without waiting (R-111).
    /// A buffer still full after one yield (which lets the caller's task drain it, since chunks decoded from one read
    /// arrive here with no await between them) evicts the call at once; a last chunk is kept by the call for its
    /// caller (R-42), and the reader moves on. False when a chunk of no call found the tunnel's budget for them empty
    /// (R-109): the tunnel closes.
    async fn deliver(&self, handle: &TunnelHandle, chunk: ai_env_relay_proto::v1::Chunk, unknown: &mut TokenBucket) -> bool {
        let l = &self.st.cfg.limits;
        let within = ms(l.enqueue_timeout_ms);
        let request_id = chunk.request_id.clone();
        match handle.calls.on_chunk(chunk) {
            Delivery::Forward { to, chunk, last, cancel, state } => {
                if let Some(reason) = cancel {
                    send_cancel(&handle.tx, &request_id, reason, within);
                }
                if let Handoff::Full(chunk) = state.hand(&to, chunk, Instant::now()) {
                    if last {
                        // R-42: the call keeps its last chunk, which its stream yields after the buffer; `to` keeps
                        // the queue open until it is kept.
                        state.keep_final(chunk);
                    } else {
                        tokio::task::yield_now().await;
                        if let Handoff::Full(_) = state.hand(&to, chunk, Instant::now()) {
                            self.evict(handle, &state, &request_id, within);
                        }
                    }
                }
                // `Gone`: the caller's stream went, and R-43 ran; nobody is left to read a last chunk.
            }
            Delivery::Fail { outcome, .. } => {
                if outcome == Outcome::Violation {
                    // R-39: the call ends, the tunnel stays, and the worker learns why.
                    send_cancel(&handle.tx, &request_id, ai_env_source::wire::cancel::PROTOCOL, within);
                }
            }
            // R-37, R-46: a worker's late chunks after a Cancel, dropped and counted, outside R-109's budget (R-107's
            // charged them, LD-R53).
            Delivery::Late => {
                self.st.dropped_chunks.fetch_add(1, Ordering::Relaxed);
            }
            Delivery::Unknown => {
                self.st.dropped_chunks.fetch_add(1, Ordering::Relaxed);
                return unknown.take(Instant::now());
            }
        }
        true
    }

    /// R-111, R-112: evicts a call whose caller is too slow, charging its session when the oldest chunk in its buffer
    /// waited there `UNREAD_CHARGE` or more (a worker's burst evicts a call at worst and never charges its session).
    fn evict(&self, handle: &TunnelHandle, state: &CallState, request_id: &str, within: Duration) {
        let now = Instant::now();
        let charged = state.oldest_buffered().is_some_and(|oldest| now.saturating_duration_since(oldest) >= UNREAD_CHARGE);
        if handle.calls.finish(request_id, Outcome::Evicted) {
            if charged {
                self.st.sessions.evicted(state.session_id(), now);
            }
            send_cancel(&handle.tx, request_id, ai_env_source::wire::cancel::CALLER_TOO_SLOW, within);
        }
    }
}

/// R-98: one authenticated tunnel of its address, from its AuthOk to its task's end (`IpSlots::authenticated`, then
/// `IpSlots::tunnel_ended` on drop, whatever ends the task).
struct Exempt {
    st: Arc<RelayState>,
    ip: std::net::IpAddr,
}

impl Exempt {
    fn new(st: &Arc<RelayState>, ip: std::net::IpAddr) -> Exempt {
        st.slots.authenticated(ip, Instant::now());
        Exempt { st: Arc::clone(st), ip }
    }
}

impl Drop for Exempt {
    fn drop(&mut self) {
        self.st.slots.tunnel_ended(self.ip, Instant::now());
    }
}

/// R-65's close reasons, from the stored Close.
fn close_word(code: u32, reason: &str) -> &'static str {
    match code {
        close::NORMAL => "normal",
        close::REVOKED => match reason {
            "expired" => "expired",
            "sources narrowed" => "narrowed",
            "peer revoked" => "peer_revoked",
            _ => "revoked",
        },
        close::SUPERSEDED => "superseded",
        close::PROTOCOL => match reason {
            "inbound rate" | "catalog rate" => "rate",
            _ => "protocol",
        },
        close::CATALOG_REFUSED => "catalog_refused",
        close::PING_TIMEOUT => "ping_timeout",
        close::STALE => "stale",
        _ => "error",
    }
}
