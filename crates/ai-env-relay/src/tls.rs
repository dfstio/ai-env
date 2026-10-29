//! The relay's TLS (R-1 to R-3): the server config, `Peered`, `PeerInfo`, `Face`. Production builds a
//! `Peered` only here, in `RelayApp::admit` through `accept` (R-76).
//!
//! One `rustls::ServerConfig` from `tls.pem` serves both faces (R-3, R-3a): TLS 1.3 only on aws-lc-rs, ALPN `h2`,
//! no resumption and no early data, no client certificate. The relay's own graph has no rustls `tls12`, so its
//! release binary cannot speak TLS 1.2 at all (`make check-features`).
//!
//! A public connection's use (R-2a, R-6) is kept here too: `ConnUse` is its state from the accept to the close,
//! `Conns` finds it by `conn_seq` for `open()`, and the cut it carries ends the connection under hyper's feet.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::limits::ConnSlot;

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
    /// Its TLS accept (or `new`): R-2a's `Open` deadline counts from here.
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
        Pin::new(&mut self.io).poll_read(cx, buf)
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
    /// Ends the connection (its stream's reads end, its writes fail).
    cut: CancellationToken,
    /// The connection's stream was dropped.
    gone: CancellationToken,
    /// Its tunnel ended: the tunnel's task or its response stream went, whichever first.
    ended: CancellationToken,
}

impl ConnUse {
    fn new() -> ConnUse {
        ConnUse { state: Mutex::new(Use::Waiting), cut: CancellationToken::new(), gone: CancellationToken::new(), ended: CancellationToken::new() }
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
    /// A new connection's use.
    pub(crate) fn insert(&self, conn_seq: u64) -> Arc<ConnUse> {
        let conn = Arc::new(ConnUse::new());
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

/// R-2's last step: TLS on an admitted connection within `within`, its slot kept for the connection's life.
pub(crate) async fn accept<IO>(
    config: Arc<rustls::ServerConfig>,
    io: IO,
    ip: std::net::IpAddr,
    slot: ConnSlot,
    within: Duration,
) -> Result<Peered<tokio_rustls::server::TlsStream<IO>>, &'static str>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    match tokio::time::timeout(within, acceptor.accept(io)).await {
        Err(_) => Err("tls_timeout"),
        Ok(Err(_)) => Err("tls_failed"),
        Ok(Ok(stream)) => {
            let conn_seq = CONN_SEQ.fetch_add(1, Ordering::SeqCst);
            Ok(Peered { io: stream, info: PeerInfo { ip, conn_seq }, slot: Some(slot), accepted: Instant::now(), cut: None })
        }
    }
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
        let used = conns.insert(7);
        assert!(Arc::ptr_eq(&used, &conns.get(7).unwrap()));
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

        let idle = conns.insert(8);
        assert!(idle.expire(), "no Open by the deadline: cut");
        assert!(idle.cut.is_cancelled());
        assert!(!idle.expire(), "once");
        assert_eq!(idle.open(), Err(OpenRefused::Closing));
    }

    /// Unit 30 (paused): the cut, as hyper sees the connection: a waiting read wakes to the end, writes fail, and the
    /// stream's drop tells the watch it is gone.
    #[tokio::test(start_paused = true)]
    async fn the_cut_ends_a_watched_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(1024);
        let mut peered = Peered::new(server, "198.51.100.7".parse().unwrap());
        let conn = Arc::new(ConnUse::new());
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
