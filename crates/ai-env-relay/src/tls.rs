//! The relay's TLS (R-1 to R-3): the server config, `Peered`, `PeerInfo`, `Face`. Production builds a
//! `Peered` only here, in `RelayApp::admit` through `accept` (R-76).
//!
//! One `rustls::ServerConfig` from `tls.pem` serves both faces (R-3, R-3a): TLS 1.3 only on aws-lc-rs, ALPN `h2`,
//! no resumption and no early data, no client certificate. The relay's own graph has no rustls `tls12`, so its
//! release binary cannot speak TLS 1.2 at all (`make check-features`).
//!
//! A public connection's use (R-2a, R-6) is kept here too: `ConnUse` is its state from the accept to the close,
//! `Conns` finds it by `conn_seq` for `open()`, and the cut it carries ends the connection under hyper's feet.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::limits::{ConnSlot, TokenBucket};

/// Every connection's sequence number, process-unique (R-6 keys on it).
static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// One listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    /// 443, `WorkerTunnel`, the internet.
    Public,
    /// 7443, `Relay`, the VMs.
    Private,
}

impl Face {
    /// The peer line's `face`.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Face::Public => "public",
            Face::Private => "private",
        }
    }
}

/// A connection's peer, in every request's extensions (tonic's `ConnectInfo`).
#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    /// The peer's address.
    pub ip: std::net::IpAddr,
    /// The connection's sequence number.
    pub conn_seq: u64,
}

/// A byte stream with its peer and its connection slot.
pub struct Peered<IO> {
    io: IO,
    info: PeerInfo,
    /// Held for its drop: the connection's admission slot is released when the connection goes (R-2).
    #[allow(dead_code)]
    slot: Option<ConnSlot>,
    /// Its TLS accept (or `new`): R-2a's `Open` deadline and R-9's handshake budget count from here (F24).
    accepted: Instant,
    /// R-2a's cut, on the public face (`watch`): once it fires, reads end and writes fail, so hyper drops the
    /// connection and its slot with it.
    cut: Option<Cut>,
}

impl<IO> Peered<IO> {
    /// A stream from `ip` (public for the tests and the lead's integration test, which serve plaintext duplex
    /// streams in-process; production goes through `admit`).
    pub fn new(io: IO, ip: std::net::IpAddr) -> Peered<IO> {
        Peered { io, info: PeerInfo { ip, conn_seq: CONN_SEQ.fetch_add(1, Ordering::SeqCst) }, slot: None, accepted: Instant::now(), cut: None }
    }

    /// Its peer.
    pub fn info(&self) -> PeerInfo {
        self.info
    }

    /// When it was accepted.
    pub(crate) fn accepted(&self) -> Instant {
        self.accepted
    }

    /// R-2a: `conn`'s cut ends this stream; dropping the stream tells `conn` it is gone.
    pub(crate) fn watch(&mut self, conn: &ConnUse) {
        let (cut, gone) = (conn.cut.clone(), conn.gone.clone());
        self.cut = Some(Cut { read: Box::pin(cut.clone().cancelled_owned()), write: Box::pin(cut.cancelled_owned()), gone });
    }
}

/// R-2a's cut of one connection, as its stream sees it.
struct Cut {
    read: Pin<Box<WaitForCancellationFutureOwned>>,
    write: Pin<Box<WaitForCancellationFutureOwned>>,
    /// Cancelled when the stream is dropped: the connection's watch ends with it.
    gone: CancellationToken,
}

impl Drop for Cut {
    fn drop(&mut self) {
        self.gone.cancel();
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Peered<IO> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(cut) = self.cut.as_mut() {
            if cut.read.as_mut().poll(cx).is_ready() {
                // R-2a: the cut reads as the connection's end.
                return Poll::Ready(Ok(()));
            }
        }
        // R-107, LD-R60: a public connection charges its read budget with every decrypted byte it reads, every HTTP/2
        // frame included: from its accept the unauthenticated budget (`meter_unauthenticated`), from its AuthOk its
        // tunnel's. Short (its bytes, or its frames: `Metered::stall`), it reads nothing more, and R-2a's cut, whose read
        // has just registered this waker, ends the connection: at its deadline before an AuthOk, after a tunnel's close
        // once it had one.
        let meter = metered(self.info.conn_seq);
        let stalls = self.cut.is_some();
        if stalls && meter.as_ref().is_some_and(|m| m.short.is_cancelled()) {
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let read = Pin::new(&mut self.io).poll_read(cx, buf);
        if let (Some(m), Poll::Ready(Ok(()))) = (&meter, &read) {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 && !m.charge(n, Instant::now()) && stalls {
                buf.set_filled(before);
                return Poll::Pending;
            }
        }
        read
    }
}

impl<IO: AsyncWrite + Unpin> Peered<IO> {
    /// The cut, for a writer: it fails every write from then on, and wakes one waiting on a full socket.
    fn write_cut(&mut self, cx: &mut Context<'_>) -> bool {
        self.cut.as_mut().is_some_and(|cut| cut.write.as_mut().poll(cx).is_ready())
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Peered<IO> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.write_cut(cx) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_cut(cx) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_cut(cx) {
            // Nothing more reaches the peer: the stream's drop closes the socket.
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl<IO> tonic::transport::server::Connected for Peered<IO> {
    type ConnectInfo = PeerInfo;

    fn connect_info(&self) -> PeerInfo {
        self.info
    }
}

/// Where a public connection is in its one use (R-2a, R-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    /// Accepted, no `Open` yet.
    Waiting,
    /// Its `Open` came in time; the tunnel lives.
    Open,
    /// Its tunnel ended: the grace for the last frames, then the cut.
    Ended,
    /// Cut, or never to carry a tunnel.
    Cut,
}

/// Why `open()` refuses a connection's `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenRefused {
    /// R-6: the connection carried one already; `open()` closes the connection.
    Second,
    /// R-2a: its deadline passed, or the relay stops; the cut is under way.
    Closing,
}

/// One public connection, from its accept to its close (R-2a). Synchronous: the watch that awaits on it is
/// `serve.rs`'s, on tokens cloned out of it.
pub(crate) struct ConnUse {
    state: Mutex<Use>,
    /// Its TLS accept: the one handshake budget (`handshake_timeout_ms`) of its `Open`, `Hello` and `AuthProof`
    /// counts from here (R-2a, R-9, F24).
    accepted: Instant,
    /// Ends the connection (its stream's reads end, its writes fail).
    cut: CancellationToken,
    /// The connection's stream was dropped.
    gone: CancellationToken,
    /// Its tunnel ended: the tunnel's task or its response stream went, whichever first.
    ended: CancellationToken,
}

impl ConnUse {
    fn new(accepted: Instant) -> ConnUse {
        ConnUse { state: Mutex::new(Use::Waiting), accepted, cut: CancellationToken::new(), gone: CancellationToken::new(), ended: CancellationToken::new() }
    }

    /// Its TLS accept.
    pub(crate) fn accepted(&self) -> Instant {
        self.accepted
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Use> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// R-6, R-2a: the connection's first `Open`, before its deadline.
    pub(crate) fn open(&self) -> Result<(), OpenRefused> {
        let mut state = self.state();
        match *state {
            Use::Waiting => {
                *state = Use::Open;
                Ok(())
            }
            Use::Open | Use::Ended => Err(OpenRefused::Second),
            Use::Cut => Err(OpenRefused::Closing),
        }
    }

    /// Its tunnel ended (`TunnelEnd`'s drop; idempotent).
    fn end(&self) {
        {
            let mut state = self.state();
            if *state == Use::Open {
                *state = Use::Ended;
            }
        }
        self.ended.cancel();
    }

    /// The deadline, or the relay's stop, with no `Open`: true when this cut the connection.
    pub(crate) fn expire(&self) -> bool {
        {
            let mut state = self.state();
            if *state != Use::Waiting {
                return false;
            }
            *state = Use::Cut;
        }
        self.cut.cancel();
        true
    }

    /// Cuts the connection (its tunnel's grace is over).
    pub(crate) fn cut(&self) {
        *self.state() = Use::Cut;
        self.cut.cancel();
    }

    /// Cancelled when the connection's stream is dropped.
    pub(crate) fn gone(&self) -> CancellationToken {
        self.gone.clone()
    }

    /// Cancelled when its tunnel ended.
    pub(crate) fn ended(&self) -> CancellationToken {
        self.ended.clone()
    }
}

/// Ends its connection's tunnel when dropped (R-2a): the tunnel's task and its response stream each hold one, and
/// the first to go starts the connection's grace.
pub(crate) struct TunnelEnd(Arc<ConnUse>);

impl TunnelEnd {
    pub(crate) fn new(conn: &Arc<ConnUse>) -> TunnelEnd {
        TunnelEnd(Arc::clone(conn))
    }
}

impl Drop for TunnelEnd {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// The public face's connections by `conn_seq`, each entry from its watch's start to its end (R-2a).
#[derive(Default)]
pub(crate) struct Conns {
    map: Mutex<HashMap<u64, Arc<ConnUse>>>,
}

impl Conns {
    /// A new connection's use, accepted at `accepted`.
    pub(crate) fn insert(&self, conn_seq: u64, accepted: Instant) -> Arc<ConnUse> {
        let conn = Arc::new(ConnUse::new(accepted));
        self.map.lock().unwrap_or_else(PoisonError::into_inner).insert(conn_seq, Arc::clone(&conn));
        conn
    }

    /// A connection's use, while its watch runs.
    pub(crate) fn get(&self, conn_seq: u64) -> Option<Arc<ConnUse>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).get(&conn_seq).cloned()
    }

    /// Forgets a connection (its watch ended).
    pub(crate) fn remove(&self, conn_seq: u64) {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).remove(&conn_seq);
    }

    /// How many connections are watched now (`RelayApp::public_conns`).
    pub(crate) fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

/// R-103's and R-105's budgets of a private connection's watch.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrivateBudget {
    /// No request whose token verified within this of the TLS accept: `auth_timeout` (`handshake_timeout_ms`).
    pub(crate) token: Duration,
    /// Verified, no request pending, its last request's start or end this long ago: `idle` (`private_idle_s`).
    pub(crate) idle: Duration,
    /// A concluded call whose stream is not dropped this long after: `undrained` (`UNDRAINED_GRACE`).
    pub(crate) undrained: Duration,
    /// Faulted this long ago, so the last refusal's status can leave: `bad_tokens` (`TUNNEL_END_GRACE`).
    pub(crate) faulted: Duration,
}

/// What a private connection's watch reads (R-103, R-105).
struct PrivateState {
    /// A request's token verified.
    verified: bool,
    /// Requests pending: each from its handler's start to its answer, or to its call's conclusion (R-106).
    pending: u32,
    /// The last request's start or end.
    last: Instant,
    /// Tokens refused on this connection (R-105); a verified one resets nothing.
    refused: u32,
    /// When `refused` reached `private_faults_max`.
    faulted_at: Option<Instant>,
    /// The connection's call streams by id, each with when its call concluded; a stream leaves when it is dropped.
    streams: HashMap<u64, Option<Instant>>,
    next_stream: u64,
}

/// One private connection, from its TLS accept to its close (R-103, R-105). Synchronous: the watch that awaits on it
/// is `serve.rs`'s, woken through `changed` at each change of what it reads.
pub(crate) struct PrivateConn {
    state: Mutex<PrivateState>,
    /// Its TLS accept: the token deadline counts from here.
    accepted: Instant,
    /// Ends the connection (its stream's reads end, its writes fail), as R-2a's cut.
    cut: CancellationToken,
    /// The connection's stream was dropped.
    gone: CancellationToken,
    changed: tokio::sync::Notify,
}

impl PrivateConn {
    fn new(accepted: Instant) -> PrivateConn {
        let state = PrivateState { verified: false, pending: 0, last: accepted, refused: 0, faulted_at: None, streams: HashMap::new(), next_stream: 0 };
        PrivateConn { state: Mutex::new(state), accepted, cut: CancellationToken::new(), gone: CancellationToken::new(), changed: tokio::sync::Notify::new() }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PrivateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the watch (a permit is kept when it is not waiting, so no change is missed).
    fn touch(&self) {
        self.changed.notify_one();
    }

    /// R-105: the connection reached `private_faults_max`: its requests are refused before any token is verified.
    pub(crate) fn faulted(&self) -> bool {
        self.state().faulted_at.is_some()
    }

    /// R-103: a request's token verified: the token deadline is met.
    pub(crate) fn verified(&self) {
        let first = !std::mem::replace(&mut self.state().verified, true);
        if first {
            self.touch();
        }
    }

    /// R-105: a token refused (`Missing` or `Token`, never the relay's own `NotLoaded`); true when this refusal
    /// faulted the connection, at `max`.
    pub(crate) fn refused(&self, max: u32, now: Instant) -> bool {
        let mut s = self.state();
        s.refused = s.refused.saturating_add(1);
        if s.faulted_at.is_some() || s.refused < max {
            return false;
        }
        s.faulted_at = Some(now);
        drop(s);
        self.touch();
        true
    }

    /// R-103: a request started at `now`; it is pending until the guard goes (its answer, or its call's conclusion).
    pub(crate) fn request(self: &Arc<Self>, now: Instant) -> Pending {
        {
            let mut s = self.state();
            s.pending = s.pending.saturating_add(1);
            s.last = now;
        }
        self.touch();
        Pending { conn: Arc::clone(self) }
    }

    /// R-103: a call's stream on this connection, its call not concluded yet (`StreamMark::concluded` says when).
    pub(crate) fn stream(self: &Arc<Self>) -> StreamMark {
        let mut s = self.state();
        let id = s.next_stream;
        s.next_stream += 1;
        s.streams.insert(id, None);
        StreamMark { conn: Arc::clone(self), id }
    }

    /// R-103, R-105: the connection's next cut and its peer line's reason, or None while none is due. Before a
    /// verified token, the token deadline from the accept; after it, with no request pending, the idle cut from the
    /// last request; a concluded call's undrained stream, `undrained` after it; a faulted connection, `bad_tokens`.
    pub(crate) fn next_cut(&self, b: &PrivateBudget) -> Option<(Instant, &'static str)> {
        let s = self.state();
        let mut next: Option<(Instant, &'static str)> = None;
        let mut sooner = |at: Instant, reason: &'static str| {
            if next.is_none_or(|(t, _)| at < t) {
                next = Some((at, reason));
            }
        };
        if !s.verified {
            sooner(self.accepted + b.token, "auth_timeout");
        }
        if let Some(at) = s.faulted_at {
            sooner(at + b.faulted, "bad_tokens");
        }
        if s.verified && s.pending == 0 {
            sooner(s.last + b.idle, "idle");
        }
        if let Some(at) = s.streams.values().flatten().min() {
            sooner(*at + b.undrained, "undrained");
        }
        next
    }

    /// The watch's wake-up: a change of what `next_cut` reads.
    pub(crate) fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }

    /// Cuts the connection (R-2a's cut: reads end, writes fail).
    pub(crate) fn cut(&self) {
        self.cut.cancel();
    }

    /// Cancelled when the connection's stream is dropped.
    pub(crate) fn gone(&self) -> CancellationToken {
        self.gone.clone()
    }
}

/// R-103: one pending request of a private connection, from its handler's start to its answer (`ListSources`) or to
/// its call's conclusion (`Call`, R-106, held in the call's permits).
pub(crate) struct Pending {
    conn: Arc<PrivateConn>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        {
            let mut s = self.conn.state();
            s.pending = s.pending.saturating_sub(1);
            s.last = Instant::now();
        }
        self.conn.touch();
    }
}

/// R-103: one call's stream on its private connection. From its call's conclusion until the stream is dropped
/// (`drained`, or this mark's drop), the stream holds the connection to `UNDRAINED_GRACE`.
pub(crate) struct StreamMark {
    conn: Arc<PrivateConn>,
    id: u64,
}

impl StreamMark {
    /// The call concluded at `now` (the first conclusion counts).
    pub(crate) fn concluded(&self, now: Instant) {
        let changed = match self.conn.state().streams.get_mut(&self.id) {
            Some(at @ None) => {
                *at = Some(now);
                true
            }
            _ => false,
        };
        if changed {
            self.conn.touch();
        }
    }

    /// The stream was dropped (hyper handed its last frame on, or the client went).
    pub(crate) fn drained(&self) {
        let was = self.conn.state().streams.remove(&self.id).is_some();
        if was {
            self.conn.touch();
        }
    }
}

impl Drop for StreamMark {
    fn drop(&mut self) {
        self.drained();
    }
}

impl<IO> Peered<IO> {
    /// R-103: `conn`'s cut ends this private stream, as R-2a's ends a public one; dropping the stream tells `conn` it
    /// is gone.
    pub(crate) fn watch_private(&mut self, conn: &PrivateConn) {
        let (cut, gone) = (conn.cut.clone(), conn.gone.clone());
        self.cut = Some(Cut { read: Box::pin(cut.clone().cancelled_owned()), write: Box::pin(cut.cancelled_owned()), gone });
    }
}

/// The private face's connections by `conn_seq`, each from its watch's start to its end (R-103).
#[derive(Default)]
pub(crate) struct PrivateConns {
    map: Mutex<HashMap<u64, Arc<PrivateConn>>>,
}

impl PrivateConns {
    /// A new connection's state, accepted at `accepted`.
    pub(crate) fn insert(&self, conn_seq: u64, accepted: Instant) -> Arc<PrivateConn> {
        let conn = Arc::new(PrivateConn::new(accepted));
        self.map.lock().unwrap_or_else(PoisonError::into_inner).insert(conn_seq, Arc::clone(&conn));
        conn
    }

    /// A connection's state, while its watch runs.
    pub(crate) fn get(&self, conn_seq: u64) -> Option<Arc<PrivateConn>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).get(&conn_seq).cloned()
    }

    /// Forgets a connection (its watch ended).
    pub(crate) fn remove(&self, conn_seq: u64) {
        self.map.lock().unwrap_or_else(PoisonError::into_inner).remove(&conn_seq);
    }
}

/// R-107, LD-R60: one public connection's inbound bytes budget: its tunnel's from its AuthOk, the unauthenticated one
/// before that.
struct Meter {
    bucket: Mutex<TokenBucket>,
    /// Cancelled once the budget ran short: the connection reads nothing more, and a tunnel closes `inbound rate`. The
    /// connection's one token: a budget that replaces another keeps it (`Metered::install`).
    short: CancellationToken,
}

impl Meter {
    /// `per_min` bytes a minute, its burst the same.
    fn new(per_min: u32, now: Instant, short: CancellationToken) -> Arc<Meter> {
        Arc::new(Meter { bucket: Mutex::new(TokenBucket::new(per_min, per_min, now)), short })
    }

    /// Charges `n` bytes; false (and short from then on) when the budget lacks them.
    fn charge(&self, n: u64, now: Instant) -> bool {
        if self.short.is_cancelled() {
            return false;
        }
        if self.bucket.lock().unwrap_or_else(PoisonError::into_inner).take_n(n, now) {
            return true;
        }
        self.short.cancel();
        false
    }

    /// LD-R53: gives `n` bytes back, never above the burst; a budget that ran short stays short.
    fn refund(&self, n: u64) {
        self.bucket.lock().unwrap_or_else(PoisonError::into_inner).give_n(n);
    }
}

/// The public connections' budgets by their process-unique `conn_seq`: a `Peered` holds no handle of the tunnel its
/// connection carries, so `poll_read` finds its budget here.
static METERS: RwLock<BTreeMap<u64, Arc<Meter>>> = RwLock::new(BTreeMap::new());

fn metered(conn_seq: u64) -> Option<Arc<Meter>> {
    METERS.read().unwrap_or_else(PoisonError::into_inner).get(&conn_seq).cloned()
}

/// Whether the connection `conn_seq` has a read budget now (no entry outlives its connection); for the tests.
#[doc(hidden)]
pub fn is_metered(conn_seq: u64) -> bool {
    metered(conn_seq).is_some()
}

/// LD-R60: a public connection's read budget from its TLS accept until its `AuthOk`: `bytes` a minute, its burst the
/// same. Short, the connection reads nothing more, so a flood with no key stops there and meets its deadline's fault
/// (R-102). `Metered::install` replaces it at the `AuthOk`, and the connection's watch ends with `unmeter`. It counts
/// decrypted bytes: TLS records below them (one-byte records, padding, KeyUpdates) take time, not tokens, so for wire
/// bytes and decrypt CPU the bound stays R-2's and the deadline.
pub(crate) fn meter_unauthenticated(conn_seq: u64, bytes: u32, now: Instant) {
    METERS.write().unwrap_or_else(PoisonError::into_inner).insert(conn_seq, Meter::new(bytes, now, CancellationToken::new()));
}

/// R-107: a tunnel's bytes budget (`per_min` bytes a minute, its burst the same) on its connection `conn_seq`, from
/// the tunnel's `AuthOk`, where it replaces the unauthenticated one (LD-R60), until this guard goes; a budget that ran
/// short, or a tunnel whose frames budget did (`stall`), keeps its connection reading nothing until the connection is
/// `gone` (R-2a's cut follows the tunnel's end), so the bytes it dropped are never followed by others. An
/// unauthenticated budget that ran short passes that on: the tunnel's budget starts short, and the tunnel closes
/// `inbound rate`.
pub(crate) struct Metered {
    conn_seq: u64,
    meter: Arc<Meter>,
    gone: Option<CancellationToken>,
}

impl Metered {
    pub(crate) fn install(conn_seq: u64, per_min: u32, now: Instant, gone: Option<CancellationToken>) -> Metered {
        let mut meters = METERS.write().unwrap_or_else(PoisonError::into_inner);
        // The budget this replaces may have dropped bytes, or be about to in a read already under way.
        let short = meters.get(&conn_seq).map_or_else(CancellationToken::new, |replaced| replaced.short.clone());
        let meter = Meter::new(per_min, now, short);
        meters.insert(conn_seq, Arc::clone(&meter));
        drop(meters);
        Metered { conn_seq, meter, gone }
    }

    /// Cancelled once the budget ran short.
    pub(crate) fn short(&self) -> CancellationToken {
        self.meter.short.clone()
    }

    /// LD-R53: a live call's chunk, which the relay asked for: its `encoded_len()` goes back to the budget. What that
    /// length does not count (HTTP/2's frames, padding, unknown protobuf fields) stays charged.
    pub(crate) fn refund(&self, n: u64) {
        self.meter.refund(n);
    }

    /// R-107: the tunnel's frames budget ran short: from now on its connection reads nothing more until it is gone,
    /// as when its bytes run short (the tunnel closes `inbound rate`, and R-2a's cut follows its end).
    pub(crate) fn stall(&self) {
        self.meter.short.cancel();
    }
}

/// Forgets a connection's budget (its tunnel's end, or its watch's).
pub(crate) fn unmeter(conn_seq: u64) {
    METERS.write().unwrap_or_else(PoisonError::into_inner).remove(&conn_seq);
}

impl Drop for Metered {
    fn drop(&mut self) {
        let conn_seq = self.conn_seq;
        if self.meter.short.is_cancelled() {
            if let (Some(gone), Ok(rt)) = (self.gone.take(), tokio::runtime::Handle::try_current()) {
                rt.spawn(async move {
                    gone.cancelled().await;
                    unmeter(conn_seq);
                });
                return;
            }
        }
        unmeter(conn_seq);
    }
}

/// Why `accept` refused a connection (R-2, R-102): the peer line's `reason`, and whether it is a fault of the peer's
/// (on the public face: every `tls_timeout`, and a `tls_failed` once the client sent a byte; a connection its client
/// closes before sending any, a bare TCP probe, is none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TlsRefused {
    /// `tls_timeout` or `tls_failed`.
    pub(crate) reason: &'static str,
    /// The client sent a byte, or held its slot to the timeout.
    pub(crate) fault: bool,
}

/// R-2's last step: TLS on an admitted connection within `within`, its slot kept for the connection's life.
pub(crate) async fn accept<IO>(
    config: Arc<rustls::ServerConfig>,
    io: IO,
    ip: std::net::IpAddr,
    slot: ConnSlot,
    within: Duration,
) -> Result<Peered<tokio_rustls::server::TlsStream<IO>>, TlsRefused>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(within, handshake(config, io)).await {
        Err(_) => Err(TlsRefused { reason: "tls_timeout", fault: true }),
        Ok(Err(sent)) => Err(TlsRefused { reason: "tls_failed", fault: sent }),
        Ok(Ok(stream)) => {
            let conn_seq = CONN_SEQ.fetch_add(1, Ordering::SeqCst);
            Ok(Peered { io: stream, info: PeerInfo { ip, conn_seq }, slot: Some(slot), accepted: Instant::now(), cut: None })
        }
    }
}

/// TLS on `io` with `config` (R-102): its first byte is read alone, so a client that closes before sending any is
/// told from a failed handshake, `Err(false)` from `Err(true)`. rustls's `Acceptor` is then fed that byte and reads
/// the rest of the ClientHello, and the handshake runs on `config` as `TlsAcceptor::accept` runs it.
async fn handshake<IO>(config: Arc<rustls::ServerConfig>, mut io: IO) -> Result<tokio_rustls::server::TlsStream<IO>, bool>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut first = [0u8; 1];
    if !matches!(io.read(&mut first).await, Ok(1)) {
        return Err(false);
    }
    let mut acceptor = rustls::server::Acceptor::default();
    acceptor.read_tls(&mut &first[..]).map_err(|_| true)?;
    let start = tokio_rustls::LazyConfigAcceptor::new(acceptor, io).await.map_err(|_| true)?;
    start.into_stream(config).await.map_err(|_| true)
}

/// R-3: TLS 1.3 only, aws-lc-rs, ALPN h2, no resumption, no early data; refuses a key that does not match its leaf.
pub fn server_config(pem: &[u8]) -> Result<rustls::ServerConfig, String> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem).collect::<Result<_, _>>().map_err(|e| format!("tls.pem: a certificate does not parse ({e})"))?;
    if chain.is_empty() {
        return Err("tls.pem: no certificate".into());
    }
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|_| "tls.pem: no private key".to_string())?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("tls.pem: the key does not serve the chain ({e})"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit 29: a public connection carries one `Open`, before its deadline (R-6, R-2a). The first `open` passes and a
    /// second is `Second`, before and after the tunnel's end; the deadline then cuts nothing, while the end cuts the
    /// connection only through the watch (`cut`). With no `Open`, the deadline cuts, and a late `Open` is `Closing`.
    #[test]
    fn a_public_connection_carries_one_open_before_its_deadline() {
        let conns = Conns::default();
        let at = Instant::now();
        let used = conns.insert(7, at);
        assert!(Arc::ptr_eq(&used, &conns.get(7).unwrap()));
        assert_eq!(used.accepted(), at, "the accept, for the handshake budget (F24)");
        assert_eq!(conns.len(), 1);
        assert_eq!(used.open(), Ok(()));
        assert_eq!(used.open(), Err(OpenRefused::Second));
        assert!(!used.expire(), "an Open came in time: the deadline cuts nothing");
        assert!(!used.cut.is_cancelled() && !used.ended.is_cancelled());
        let (task, stream) = (TunnelEnd::new(&used), TunnelEnd::new(&used));
        drop(task);
        assert!(used.ended.is_cancelled(), "the first end starts the grace");
        assert!(!used.cut.is_cancelled(), "the watch cuts, after the grace");
        drop(stream);
        assert_eq!(used.open(), Err(OpenRefused::Second));
        used.cut();
        assert!(used.cut.is_cancelled());
        assert_eq!(used.open(), Err(OpenRefused::Closing));
        conns.remove(7);
        assert!(conns.get(7).is_none());
        assert_eq!(conns.len(), 0);

        let idle = conns.insert(8, at);
        assert!(idle.expire(), "no Open by the deadline: cut");
        assert!(idle.cut.is_cancelled());
        assert!(!idle.expire(), "once");
        assert_eq!(idle.open(), Err(OpenRefused::Closing));
    }

    /// LD-R53: what `Metered` gives back its `Meter` may charge again, up to the burst; a budget that ran short stays
    /// short, whatever comes back, so the bytes it dropped are never followed by others.
    #[test]
    fn a_meter_takes_back_up_to_its_burst_and_stays_short() {
        let t0 = Instant::now();
        let conn_seq = CONN_SEQ.fetch_add(1, Ordering::SeqCst);
        let guard = Metered::install(conn_seq, 1000, t0, None);
        let meter = metered(conn_seq).expect("installed");
        assert!(meter.charge(900, t0));
        guard.refund(600);
        assert!(meter.charge(700, t0), "the 100 left and the 600 back");
        guard.refund(5000);
        assert!(meter.charge(1000, t0), "back up to its burst");
        assert!(!guard.short().is_cancelled());
        assert!(!meter.charge(1, t0), "nothing above it");
        assert!(guard.short().is_cancelled());
        guard.refund(1000);
        assert!(!meter.charge(1, t0), "short stays short");
        drop(guard);
        assert!(metered(conn_seq).is_none(), "no gone token: forgotten with its tunnel");
    }

    /// Unit 52 (LD-R60, R-107): a budget refills at its `per_min`, and a connection has one `short` across its budgets:
    /// one that ran short leaves the tunnel's short, and so does a read that held it as the tunnel's replaced it, so the
    /// bytes it dropped are never followed by others. One not short leaves the tunnel's whole.
    #[test]
    fn a_connections_budgets_refill_and_share_their_short() {
        let t0 = Instant::now();
        let conn_seq = CONN_SEQ.fetch_add(1, Ordering::SeqCst);
        meter_unauthenticated(conn_seq, 60_000, t0);
        let first = metered(conn_seq).expect("metered");
        assert!(first.charge(60_000, t0), "its burst");
        let later = t0 + Duration::from_secs(1);
        assert!(first.charge(1000, later), "a second's refill");
        assert!(!first.charge(1, later), "and no more");
        let tunnel = Metered::install(conn_seq, 1_000_000, later, None);
        assert!(tunnel.short().is_cancelled(), "short before its replacement");
        drop(tunnel);
        assert!(metered(conn_seq).is_none());

        let conn_seq = CONN_SEQ.fetch_add(1, Ordering::SeqCst);
        meter_unauthenticated(conn_seq, 1000, t0);
        let held = metered(conn_seq).expect("metered");
        let tunnel = Metered::install(conn_seq, 1_000_000, t0, None);
        assert!(!tunnel.short().is_cancelled(), "a budget not short leaves the tunnel's whole");
        assert!(metered(conn_seq).expect("the tunnel's").charge(1_000_000, t0), "the tunnel's own burst");
        assert!(!tunnel.short().is_cancelled());
        assert!(!held.charge(1001, t0), "a read under way");
        assert!(tunnel.short().is_cancelled(), "short as it was replaced");
    }

    /// Unit 30 (paused): the cut, as hyper sees the connection: a waiting read wakes to the end, writes fail, and the
    /// stream's drop tells the watch it is gone.
    #[tokio::test(start_paused = true)]
    async fn the_cut_ends_a_watched_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(1024);
        let mut peered = Peered::new(server, "198.51.100.7".parse().unwrap());
        let conn = Arc::new(ConnUse::new(peered.accepted()));
        peered.watch(&conn);
        client.write_all(b"ab").await.unwrap();
        let mut two = [0u8; 2];
        peered.read_exact(&mut two).await.unwrap();
        peered.write_all(b"cd").await.unwrap();
        client.read_exact(&mut two).await.unwrap();
        assert_eq!(&two, b"cd");
        let reader = tokio::spawn(async move {
            let mut one = [0u8; 1];
            let n = peered.read(&mut one).await.unwrap();
            (n, peered)
        });
        tokio::task::yield_now().await;
        assert!(conn.expire());
        let (n, mut peered) = tokio::time::timeout(Duration::from_secs(5), reader).await.expect("the cut wakes a waiting read").unwrap();
        assert_eq!(n, 0, "a waiting read wakes to the end");
        assert_eq!(peered.write_all(b"x").await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(!conn.gone.is_cancelled());
        drop(peered);
        assert!(conn.gone.is_cancelled(), "the drop ends the watch");
    }
}
