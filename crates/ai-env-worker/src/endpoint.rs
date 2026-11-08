//! The relay endpoint (WM-R11, WM-R12; R-120, R-121): TLS 1.3 under the pinned relay CA, over a pluggable byte
//! transport, with the worker's client certificate when it has one.
//!
//! The client configuration (WM-R11a, the v6 amendment to invariant 15, as the relay security plan amends it):
//! TLS 1.3 only, the aws-lc-rs provider, ALPN `h2`, and exactly the certificates of `ca_pem` as trust
//! anchors: no public or native root store, no custom verifier; a client certificate only when
//! `client_identity` was given, which rustls presents only when the relay asks (R-120). Proxy variables are
//! never read: the default dialer connects the address itself.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::{AlertDescription, ClientConfig, RootCertStore};
use rustls_pki_types::pem::{PemObject, SectionKind};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::globs::valid_relay_id;

/// The relay's port when the address names none.
const DEFAULT_PORT: u16 = 443;
/// What a PEM file holding a private key holds, whatever its kind (PKCS#8, SEC1, PKCS#1).
const KEY_MARK: &[u8] = b"PRIVATE KEY-----";

/// The byte stream TLS runs over. TCP to the endpoint by default; a test may dial `tokio::io::duplex`.
/// TLS 1.3 under the pinned CA always runs on top of what it returns: there is no plaintext path.
pub trait Dial: Send + Sync + 'static {
    /// One new byte stream.
    fn dial(&self) -> crate::BoxFuture<'static, std::io::Result<Box<dyn Io>>>;
}

/// A byte stream.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static> Io for T {}

/// Where and how a worker dials the relay.
#[derive(Clone)]
pub struct RelayEndpoint {
    /// The address's host (an IPv6 literal without its brackets) and port.
    host: String,
    port: u16,
    server_name: Option<ServerName<'static>>,
    /// `ca_pem`'s certificates: the only trust anchors.
    roots: Option<Arc<RootCertStore>>,
    /// `client_identity`'s certificate and key.
    identity: Option<Arc<ClientIdentity>>,
    /// Built of the two above once `ca_pem` was given.
    tls: Option<Arc<ClientConfig>>,
    expect_relay_id: Option<String>,
    dialer: Option<Arc<dyn Dial>>,
}

/// A worker's client certificate and its P-256 key (R-120): the key's PKCS#8 DER, zeroized when dropped.
struct ClientIdentity {
    cert: CertificateDer<'static>,
    key: Zeroizing<Vec<u8>>,
}

impl RelayEndpoint {
    /// `host:port`; port 443 when absent.
    pub fn new(addr: &str) -> Result<RelayEndpoint, EndpointError> {
        let bad = |why: &str| EndpointError(format!("relay address {addr:?}: {why}"));
        let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
            let (host, after) = rest.split_once(']').ok_or_else(|| bad("an IPv6 address without its ]"))?;
            match after {
                "" => (host, None),
                _ => (host, Some(after.strip_prefix(':').ok_or_else(|| bad("not [host]:port"))?)),
            }
        } else {
            match addr.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (addr, None),
            }
        };
        let port = match port {
            Some(p) => p.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| bad("the port is not 1 to 65535"))?,
            None => DEFAULT_PORT,
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        ServerName::try_from(host.to_string()).map_err(|_| bad("the host is neither a DNS name nor an IP address"))?;
        Ok(RelayEndpoint { host: host.to_string(), port, server_name: None, roots: None, identity: None, tls: None, expect_relay_id: None, dialer: None })
    }

    /// The only trust anchors: the certificates of this PEM (at least one; a private key is refused).
    /// Required: an endpoint without it is accepted by `build()`, but every dial fails as TLS.
    pub fn ca_pem(mut self, pem: &[u8]) -> Result<RelayEndpoint, EndpointError> {
        if holds_key(pem) {
            return Err(EndpointError("the relay CA file holds a private key: give it the CA's certificate alone (ai-env relay ca)".into()));
        }
        let mut roots = RootCertStore::empty();
        for section in <(SectionKind, Vec<u8>) as PemObject>::pem_slice_iter(pem) {
            let (kind, der) = section.map_err(|e| EndpointError(format!("the relay CA file is not PEM: {e}")))?;
            if kind == SectionKind::Certificate {
                roots.add(CertificateDer::from(der)).map_err(|e| EndpointError(format!("the relay CA file holds a certificate rustls refuses: {e}")))?;
            }
        }
        if roots.is_empty() {
            return Err(EndpointError("the relay CA file holds no certificate".into()));
        }
        self.roots = Some(Arc::new(roots));
        self.configure()?;
        Ok(self)
    }

    /// The worker's client certificate (R-120): `cert_pem` exactly one `CERTIFICATE` block and nothing else,
    /// `key_pem` exactly one `PRIVATE KEY` block (PKCS#8, P-256) whose public point is the certificate's.
    /// The configuration presents it whether `ca_pem` came before or after this; rustls sends it only when
    /// the relay asks, so a relay that asks for none still serves this endpoint (design D4).
    pub fn client_identity(mut self, cert_pem: &[u8], key_pem: &[u8]) -> Result<RelayEndpoint, EndpointError> {
        if holds_key(cert_pem) {
            return Err(EndpointError("the client certificate file holds a private key".into()));
        }
        let cert = one_block(cert_pem, "CERTIFICATE", "the client certificate file")?;
        let key = one_block(key_pem, "PRIVATE KEY", "the client key file")?;
        let point = crate::certs::client_point(&key).map_err(|_| EndpointError("the client key file holds no P-256 key (PKCS#8)".into()))?;
        let cert_point = crate::certs::certificate_point(&cert).map_err(|_| EndpointError("the client certificate file holds no certificate this worker reads".into()))?;
        if cert_point != point.bytes() {
            return Err(EndpointError("the client key does not match the client certificate".into()));
        }
        self.identity = Some(Arc::new(ClientIdentity { cert: CertificateDer::from(cert.to_vec()), key }));
        self.configure()?;
        Ok(self)
    }

    /// The client configuration of the trust anchors and the identity given so far (WM-R11, R-120): none until
    /// `ca_pem`; `with_client_auth_cert` with an identity, else `with_no_client_auth`.
    fn configure(&mut self) -> Result<(), EndpointError> {
        let Some(roots) = self.roots.clone() else {
            return Ok(());
        };
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| EndpointError(format!("TLS 1.3 with aws-lc-rs: {e}")))?
            .with_root_certificates(roots);
        let mut config = match &self.identity {
            Some(id) => {
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.to_vec()));
                builder.with_client_auth_cert(vec![id.cert.clone()], key).map_err(|e| EndpointError(format!("the client certificate and its key: {e}")))?
            }
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"h2".to_vec()];
        self.tls = Some(Arc::new(config));
        Ok(())
    }

    /// The name the relay's certificate is checked against (else the host of `addr`).
    pub fn server_name(mut self, name: &str) -> Result<RelayEndpoint, EndpointError> {
        let parsed = ServerName::try_from(name.to_string()).map_err(|_| EndpointError(format!("server name {name:?} is neither a DNS name nor an IP address")))?;
        self.server_name = Some(parsed);
        Ok(self)
    }

    /// The relay id the `Challenge` must carry.
    pub fn expect_relay_id(mut self, id: &str) -> Result<RelayEndpoint, EndpointError> {
        if !valid_relay_id(id) {
            return Err(EndpointError(format!("relay id {id:?} is not a name ({})", ai_env_source::names::NAME_RULE)));
        }
        self.expect_relay_id = Some(id.to_string());
        Ok(self)
    }

    /// Another byte transport under the TLS (tests).
    pub fn dialer(mut self, d: Arc<dyn Dial>) -> RelayEndpoint {
        self.dialer = Some(d);
        self
    }

    /// The name TLS verifies: `server_name`, else the host.
    fn verified_name(&self) -> Result<ServerName<'static>, Failure> {
        match &self.server_name {
            Some(name) => Ok(name.clone()),
            None => ServerName::try_from(self.host.clone()).map_err(|_| Failure::Tls(format!("{} is no server name", self.host))),
        }
    }

    /// tonic's origin, `http://<server name>:<port>` (LD-WM7): the connector is the only TLS, so an `https`
    /// origin would fail wherever a crate in the graph turns tonic's own TLS on.
    pub(crate) fn origin(&self) -> String {
        let name = match &self.server_name {
            Some(ServerName::DnsName(d)) => d.as_ref().to_string(),
            Some(ServerName::IpAddress(ip)) => std::net::IpAddr::from(*ip).to_string(),
            _ => self.host.clone(),
        };
        // An IPv6 address is bracketed in a URI's authority.
        let host = if name.contains(':') { format!("[{name}]") } else { name };
        format!("http://{host}:{}", self.port)
    }

    /// The relay id the `Challenge` must carry, if one was set.
    pub(crate) fn expected_relay_id(&self) -> Option<&str> {
        self.expect_relay_id.as_deref()
    }

    /// One new connection: the dial and the TLS 1.3 handshake together within `budget` (WM-R12). A handshake
    /// that failed on the relay's alert of a client certificate is R-121's words.
    pub(crate) async fn connect(&self, budget: Duration) -> Result<Connection, Failure> {
        let config = self.tls.clone().ok_or_else(|| Failure::Tls("no relay CA: RelayEndpoint::ca_pem was not given one".into()))?;
        let name = self.verified_name()?;
        let presented = self.identity.is_some();
        let attempt = async {
            let io: Box<dyn Io> = match &self.dialer {
                Some(d) => d.dial().await.map_err(|e| Failure::Dial(e.to_string()))?,
                None => {
                    let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await.map_err(|e| Failure::Dial(format!("{}:{}: {e}", self.host, self.port)))?;
                    tcp.set_nodelay(true).map_err(|e| Failure::Dial(e.to_string()))?;
                    Box::new(tcp)
                }
            };
            TlsConnector::from(config).connect(name, io).await.map_err(|e| Failure::Tls(alert_of(&e).and_then(|a| alert_words(a, presented)).unwrap_or_else(|| e.to_string())))
        };
        let stream = tokio::time::timeout(budget, attempt).await.map_err(|_| Failure::Timeout)??;
        Ok(Connection { stream, alert: RelayAlert::new(presented), heard: false, failed: None })
    }
}

/// Whether a PEM text holds a private key block of any kind.
fn holds_key(pem: &[u8]) -> bool {
    pem.windows(KEY_MARK.len()).any(|w| w == KEY_MARK)
}

/// The body of the one PEM block of `text`, which must be labelled `label` (`what` names the file).
fn one_block(text: &[u8], label: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, EndpointError> {
    let mut blocks = crate::keys::pem_blocks(text).map_err(|e| EndpointError(format!("{what} is not PEM: {e}")))?;
    match blocks.as_slice() {
        [(found, _)] if found == label => Ok(blocks.remove(0).1),
        [(found, _)] => Err(EndpointError(format!("{what} holds a {found} block, not a {label} block"))),
        [] => Err(EndpointError(format!("{what} holds no {label} block"))),
        more => Err(EndpointError(format!("{what} holds {} PEM blocks, not one {label} block", more.len()))),
    }
}

/// The alert of the rustls error inside an I/O error of tokio-rustls, when it is `AlertReceived`.
fn alert_of(e: &io::Error) -> Option<AlertDescription> {
    match e.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::AlertReceived(alert) => Some(*alert),
        _ => None,
    }
}

/// R-121's words for the relay's alert: it requires a client certificate, or it refused this worker's (its
/// seven alerts, and `DecryptError` on a connection that `presented` one: a certificate under a replaced CA of
/// the same name, since webpki finds the anchor by name and then the signature fails, R-131). Any other alert
/// keeps today's text: rustls's at connect, HTTP/2's or tonic's after it.
fn alert_words(alert: AlertDescription, presented: bool) -> Option<String> {
    match alert {
        AlertDescription::CertificateRequired => Some("the relay requires a client certificate".to_string()),
        AlertDescription::BadCertificate
        | AlertDescription::UnknownCA
        | AlertDescription::CertificateExpired
        | AlertDescription::CertificateRevoked
        | AlertDescription::CertificateUnknown
        | AlertDescription::UnsupportedCertificate
        | AlertDescription::AccessDenied => Some(format!("the relay refused this worker's client certificate ({alert:?})")),
        AlertDescription::DecryptError if presented => Some(format!("the relay refused this worker's client certificate ({alert:?})")),
        _ => None,
    }
}

/// One connection to the relay: its TLS stream, which keeps the alert of its first read error (R-121).
pub(crate) struct Connection {
    stream: TlsStream<Box<dyn Io>>,
    alert: RelayAlert,
    /// A byte of the relay's was read: it took this worker's certificate, so no alert of R-121 is left to come.
    heard: bool,
    /// A write that found the relay gone, its error held until the read has answered (`poll_out`).
    failed: Option<io::Error>,
}

impl Connection {
    /// What its first read error said, shared: HTTP/2 owns the connection once it is handed over.
    pub(crate) fn alert(&self) -> RelayAlert {
        self.alert.clone()
    }

    /// One read of the stream, its first error kept.
    fn poll_in(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.stream).poll_read(cx, buf);
        match &polled {
            Poll::Ready(Ok(())) => self.heard |= buf.filled().len() > before,
            Poll::Ready(Err(e)) => self.alert.first_read_error(e),
            Poll::Pending => {}
        }
        polled
    }

    /// One write or flush of the stream. The relay closes right after its alert, so the worker's next write can fail on that
    /// close with the alert still unread, and HTTP/2 flushes before it reads: it would end the connection on the
    /// write's error, and `check` would say `transport error`, not R-121's words. So while the relay has said nothing,
    /// a write that finds it gone reads what it left, and its error waits for that read's answer. A closed
    /// connection answers (its bytes, its end or its error) as soon as the reactor has seen the close, and the
    /// handshake's own budgets stand above this.
    fn poll_out<T>(&mut self, cx: &mut Context<'_>, write: impl FnOnce(Pin<&mut TlsStream<Box<dyn Io>>>, &mut Context<'_>) -> Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        let written = match self.failed.take() {
            Some(e) => Poll::Ready(Err(e)),
            None => write(Pin::new(&mut self.stream), cx),
        };
        match written {
            Poll::Ready(Err(e)) if !self.heard && self.alert.first.get().is_none() && relay_gone(&e) => {
                let mut left = [0u8; 64];
                if self.poll_in(cx, &mut ReadBuf::new(&mut left)).is_pending() {
                    self.failed = Some(e);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e))
            }
            other => other,
        }
    }
}

/// A write's error that says the relay closed this connection, so that its read side has an answer too.
fn relay_gone(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
}

impl AsyncRead for Connection {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_in(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_out(cx, |stream, cx| stream.poll_write(cx, buf))
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_out(cx, |stream, cx| stream.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_out(cx, |stream, cx| stream.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// The alert a connection's first read error carried, if it was one (R-121). TLS 1.3 reports the relay's
/// refusal of a client certificate after the client's Finished: `connect` has passed, and the first read
/// (HTTP/2's, under tonic, or `Connection::poll_out`'s after a write that found the relay gone) meets the alert, which
/// tonic's status would otherwise reduce to a transport error.
#[derive(Clone, Default)]
pub(crate) struct RelayAlert {
    first: Arc<OnceLock<Option<AlertDescription>>>,
    /// The connection's endpoint holds a client certificate.
    presented: bool,
}

impl RelayAlert {
    fn new(presented: bool) -> RelayAlert {
        RelayAlert { first: Arc::default(), presented }
    }

    /// The first read error is kept; any later one says nothing more.
    fn first_read_error(&self, e: &io::Error) {
        let _ = self.first.set(alert_of(e));
    }

    /// R-121's words, when the first read error was the relay's alert of a client certificate.
    pub(crate) fn words(&self) -> Option<String> {
        self.first.get().copied().flatten().and_then(|a| alert_words(a, self.presented))
    }

    /// The record of a connection whose first read error was the relay's `alert`, as tokio-rustls reports one
    /// (tests: `tunnel.rs`'s mapping of an end).
    #[cfg(test)]
    pub(crate) fn received(alert: AlertDescription) -> RelayAlert {
        let record = RelayAlert::default();
        record.first_read_error(&io::Error::new(io::ErrorKind::InvalidData, rustls::Error::AlertReceived(alert)));
        record
    }
}

/// Why `connect` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The byte stream: TCP, or the test's dialer.
    Dial(String),
    /// The TLS handshake (an unknown issuer, another name, a protocol version, R-121's alerts).
    Tls(String),
    /// The dial and the handshake took longer than `connect_timeout`.
    Timeout,
}

/// An endpoint refused (WM-R11). Phase 0 freezes the name; W chooses its variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EndpointError(String);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::certs;
    use crate::keys::SigningKey;
    use crate::signer::FileSigner;
    use crate::worker::{Tuning, Worker, WorkerError};

    const RELAY_NAME: &str = "ai-env-relay";

    #[test]
    fn addresses_parse_with_their_port_and_the_origin_is_http() {
        let e = RelayEndpoint::new("203.0.113.10:8443").expect("parses");
        assert_eq!((e.host.as_str(), e.port), ("203.0.113.10", 8443));
        assert_eq!(e.origin(), "http://203.0.113.10:8443");
        let e = RelayEndpoint::new("relay.example.com").expect("parses");
        assert_eq!((e.host.as_str(), e.port), ("relay.example.com", 443));
        let e = e.server_name(RELAY_NAME).expect("a name");
        assert_eq!(e.origin(), format!("http://{}:443", RELAY_NAME));
        let e = RelayEndpoint::new("[::1]:7443").expect("parses").server_name("10.42.0.20").expect("an IP");
        assert_eq!(e.origin(), "http://10.42.0.20:7443");
        assert_eq!(RelayEndpoint::new("[::1]").expect("parses").origin(), "http://[::1]:443");
        for bad in ["", ":443", "relay:", "relay:0", "relay:65536", "[::1", "[::1]x", "a b:1"] {
            assert!(RelayEndpoint::new(bad).is_err(), "{bad:?}");
        }
        let e = RelayEndpoint::new("relay.example.com").expect("parses");
        assert!(e.clone().expect_relay_id("Relay").is_err());
        assert!(e.clone().expect_relay_id("relay-test").is_ok());
        assert!(e.clone().server_name("not a name").is_err());
        assert!(e.clone().ca_pem(b"").is_err(), "no certificate");
        // A key-shaped block, built at run time (no key-shaped literal in the source).
        let key_block = crate::certs::pem(&["PRIVATE", "KEY"].join(" "), &[0u8; 48]);
        let refused = e.ca_pem(key_block.as_bytes()).err().expect("a key is refused");
        assert!(refused.to_string().contains("private key"), "{refused}");
    }

    /// The `PRIVATE KEY` label, built at run time.
    fn key_label() -> String {
        ["PRIVATE", "KEY"].join(" ")
    }

    /// A worker's client certificate (PEM) and its key (PEM) under `ca`, for an hour from now.
    fn client_pair(ca: &certs::Issued, now: u64) -> (String, String, Vec<u8>) {
        let key = certs::client_key().expect("a P-256 key");
        let point = certs::client_point(&key).expect("its point");
        let der = certs::client_leaf(ca, "worker-a", &point, now, now + 3600).expect("a client certificate");
        (certs::pem("CERTIFICATE", &der), certs::pem(&key_label(), &key), der)
    }

    /// A test relay: a TLS 1.3 server of rustls over a duplex, with the relay's leaf under `ca`, requiring a
    /// client certificate under `ca` or asking for none. Each connection answers `ping` with `pong` and says
    /// which client certificate it was shown; a failed handshake keeps its connection until the client leaves, so
    /// the client reads the alert (tokio-rustls writes it before the failure returns). The relay itself closes at
    /// once: `Closes` below has that case's writes, and WM-J4 the real thing over TCP.
    struct TestRelay {
        config: Arc<rustls::ServerConfig>,
        shown: tokio::sync::mpsc::UnboundedSender<Option<Vec<u8>>>,
    }

    impl TestRelay {
        fn start(ca: &certs::Issued, now: u64, require: bool) -> (Arc<TestRelay>, tokio::sync::mpsc::UnboundedReceiver<Option<Vec<u8>>>) {
            let leaf = certs::relay_leaf(ca, Ipv4Addr::new(192, 0, 2, 20), now).expect("the relay's leaf");
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&rustls::version::TLS13]).expect("TLS 1.3");
            let builder = if require {
                let mut roots = RootCertStore::empty();
                roots.add(CertificateDer::from(ca.cert_der.clone())).expect("the CA");
                builder.with_client_cert_verifier(rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().expect("a verifier"))
            } else {
                builder.with_no_client_auth()
            };
            let chain = vec![CertificateDer::from(leaf.cert_der.clone()), CertificateDer::from(ca.cert_der.clone())];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_pkcs8.to_vec()));
            let mut config = builder.with_single_cert(chain, key).expect("the relay's chain and key");
            config.alpn_protocols = vec![b"h2".to_vec()];
            let (shown, seen) = tokio::sync::mpsc::unbounded_channel();
            (Arc::new(TestRelay { config: Arc::new(config), shown }), seen)
        }
    }

    impl Dial for TestRelay {
        fn dial(&self) -> crate::BoxFuture<'static, io::Result<Box<dyn Io>>> {
            let (config, shown) = (self.config.clone(), self.shown.clone());
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut rest = [0u8; 1024];
                    match tokio_rustls::TlsAcceptor::from(config).accept(server).into_fallible().await {
                        Ok(mut tls) => {
                            let _ = shown.send(tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()));
                            let mut ping = [0u8; 4];
                            if tls.read_exact(&mut ping).await.is_ok() && &ping == b"ping" {
                                let _ = tls.write_all(b"pong").await;
                                let _ = tls.flush().await;
                            }
                            while matches!(tls.read(&mut rest).await, Ok(n) if n > 0) {}
                        }
                        Err((_, mut io)) => while matches!(io.read(&mut rest).await, Ok(n) if n > 0) {},
                    }
                });
                Ok(Box::new(client) as Box<dyn Io>)
            })
        }
    }

    /// `ping` over a new connection of `endpoint`: the answer, and what its first read error said.
    async fn exchange(endpoint: &RelayEndpoint) -> (Result<[u8; 4], String>, Option<RelayAlert>) {
        let mut conn = match endpoint.connect(Duration::from_secs(5)).await {
            Ok(conn) => conn,
            Err(f) => return (Err(format!("{f:?}")), None),
        };
        let alert = conn.alert();
        let mut pong = [0u8; 4];
        let answer = async {
            conn.write_all(b"ping").await?;
            conn.flush().await?;
            conn.read_exact(&mut pong).await.map(|_| pong)
        };
        (answer.await.map_err(|e| e.to_string()), Some(alert))
    }

    /// A worker of `endpoint` (seed 1's key, the testkit's echo source), for `check`.
    fn worker(endpoint: RelayEndpoint) -> Worker {
        let tuning = Tuning { connect_timeout: Duration::from_secs(5), handshake_timeout: Duration::from_secs(5), ..Tuning::default() };
        let signer = Arc::new(FileSigner::from_key(SigningKey::from_seed(&[1; 32]).expect("seed")));
        Worker::builder().worker_id("worker-a").relay(endpoint).signer(signer).source(Arc::new(ai_env_source::testkit::EchoSource::new())).tuning(tuning).build().expect("a worker")
    }

    /// What `ClosedWrites` does with a write.
    #[derive(Clone, Copy)]
    enum Writes {
        Pass,
        /// A full socket: rustls keeps the bytes for the next flush.
        Block,
        /// A socket the relay closed.
        Fail(io::ErrorKind),
    }

    type WritesNow = Arc<std::sync::Mutex<Writes>>;

    /// A stream of `TestRelay`'s whose writes do as `writes` says; its reads go on.
    struct ClosedWrites {
        io: Box<dyn Io>,
        writes: WritesNow,
    }

    impl AsyncRead for ClosedWrites {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ClosedWrites {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let writes = *this.writes.lock().expect("unpoisoned");
            match writes {
                Writes::Pass => Pin::new(&mut this.io).poll_write(cx, buf),
                Writes::Block => Poll::Pending,
                Writes::Fail(kind) => Poll::Ready(Err(kind.into())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    /// `TestRelay`'s dial, each stream a `ClosedWrites`.
    struct Closes {
        relay: Arc<TestRelay>,
        writes: WritesNow,
    }

    impl Dial for Closes {
        fn dial(&self) -> crate::BoxFuture<'static, io::Result<Box<dyn Io>>> {
            let (dialing, writes) = (self.relay.dial(), self.writes.clone());
            Box::pin(async move { Ok(Box::new(ClosedWrites { io: dialing.await?, writes }) as Box<dyn Io>) })
        }
    }

    /// R-121, beside WM-T56: the relay closes right after its alert, so a write can fail with that alert unread, and
    /// HTTP/2 flushes before it reads. While the relay has said nothing, a write or a flush that finds it gone reads what
    /// it left: its error waits for the alert still on its way, and takes one already there at once. A write's other
    /// errors, and any write once the relay was heard, are returned at once and read nothing. Single-threaded, so
    /// `connect` returns with the relay yet to read the worker's Finished.
    #[tokio::test]
    async fn a_write_that_finds_the_relay_gone_reads_its_alert() {
        use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut};
        use std::future::Future as _;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after 1970").as_secs();
        let ca = certs::relay_ca(now).expect("the relay CA");
        let ca_pem = certs::pem("CERTIFICATE", &ca.cert_der);
        let (requiring, _seen) = TestRelay::start(&ca, now, true);
        let (asking_none, _seen_none) = TestRelay::start(&ca, now, false);
        let writes: WritesNow = Arc::new(std::sync::Mutex::new(Writes::Pass));
        let endpoint = |relay: &Arc<TestRelay>| {
            let dialer: Arc<dyn Dial> = Arc::new(Closes { relay: relay.clone(), writes: writes.clone() });
            RelayEndpoint::new("203.0.113.10:443").expect("an address").server_name(RELAY_NAME).expect("a name").dialer(dialer).ca_pem(ca_pem.as_bytes()).expect("the CA")
        };
        let set = |now: Writes| *writes.lock().expect("unpoisoned") = now;
        let required = Some("the relay requires a client certificate".to_string());

        // Each way a socket says the relay is gone: the alert is on its way, so the first poll waits; then it reads.
        for kind in [BrokenPipe, ConnectionReset, ConnectionAborted] {
            set(Writes::Pass);
            let mut conn = endpoint(&requiring).connect(Duration::from_secs(5)).await.expect("TLS 1.3: the worker's handshake ends first");
            let alert = conn.alert();
            set(Writes::Fail(kind));
            let mut write = std::pin::pin!(conn.write_all(b"ping"));
            let first = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
            assert!(first.is_pending(), "{kind:?}: its error waits for the read's answer: {first:?}");
            assert_eq!(alert.words(), None, "{kind:?}: nothing read yet");
            assert_eq!(write.await.expect_err("the write failed").kind(), kind, "{kind:?}: the write's own error");
            assert_eq!(alert.words(), required, "{kind:?}: R-121's words");
        }

        // A flush the same way: a full socket kept the bytes in rustls, and the relay then closed it.
        set(Writes::Pass);
        let mut conn = endpoint(&requiring).connect(Duration::from_secs(5)).await.expect("the worker's handshake");
        let alert = conn.alert();
        set(Writes::Block);
        assert_eq!(conn.write(b"ping").await.expect("taken, not sent"), 4);
        set(Writes::Fail(BrokenPipe));
        let mut flush = std::pin::pin!(conn.flush());
        let first = std::future::poll_fn(|cx| Poll::Ready(flush.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "its error waits for the read's answer: {first:?}");
        assert_eq!(flush.await.expect_err("the flush failed").kind(), BrokenPipe);
        assert_eq!(alert.words(), required);

        // HTTP/2's vectored write, with the alert already there: no wait.
        set(Writes::Pass);
        let mut conn = endpoint(&requiring).connect(Duration::from_secs(5)).await.expect("the worker's handshake");
        let alert = conn.alert();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        set(Writes::Fail(BrokenPipe));
        let bufs = [io::IoSlice::new(b"ping")];
        let mut write = std::pin::pin!(conn.write_vectored(&bufs));
        let first = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        assert!(matches!(&first, Poll::Ready(Err(e)) if e.kind() == BrokenPipe), "at once: {first:?}");
        assert_eq!(alert.words(), required, "the alert read at once");

        // Another error of a write says nothing of the relay: no wait, no read.
        set(Writes::Pass);
        let mut conn = endpoint(&requiring).connect(Duration::from_secs(5)).await.expect("the worker's handshake");
        let alert = conn.alert();
        set(Writes::Fail(TimedOut));
        let mut write = std::pin::pin!(conn.write_all(b"ping"));
        let first = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        assert!(matches!(&first, Poll::Ready(Err(e)) if e.kind() == TimedOut), "at once: {first:?}");
        assert_eq!(alert.words(), None);

        // A relay that was heard took the certificate: its close is returned at once, and nothing is read for it.
        set(Writes::Pass);
        let mut conn = endpoint(&asking_none).connect(Duration::from_secs(5)).await.expect("the worker's handshake");
        let alert = conn.alert();
        conn.write_all(b"ping").await.expect("the write");
        conn.flush().await.expect("the flush");
        let mut pong = [0u8; 4];
        conn.read_exact(&mut pong).await.expect("the answer");
        assert_eq!(&pong, b"pong");
        set(Writes::Fail(BrokenPipe));
        let mut write = std::pin::pin!(conn.write_all(b"ping"));
        let first = std::future::poll_fn(|cx| Poll::Ready(write.as_mut().poll(cx))).await;
        assert!(matches!(&first, Poll::Ready(Err(e)) if e.kind() == BrokenPipe), "at once: {first:?}");
        assert_eq!(alert.first.get().copied(), None, "no read error, for no read");
    }

    fn presents(endpoint: &RelayEndpoint) -> bool {
        endpoint.tls.as_ref().expect("a configuration").client_auth_cert_resolver.has_certs()
    }

    /// WM-T56.
    #[tokio::test]
    async fn an_endpoint_presents_its_client_certificate_when_asked() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after 1970").as_secs();
        let ca = certs::relay_ca(now).expect("the relay CA");
        let ca_pem = certs::pem("CERTIFICATE", &ca.cert_der);
        let (cert_pem, key_pem, cert_der) = client_pair(&ca, now);
        let (requiring, mut seen) = TestRelay::start(&ca, now, true);
        let (asking_none, mut seen_none) = TestRelay::start(&ca, now, false);
        let base = |relay: &Arc<TestRelay>| {
            let dialer: Arc<dyn Dial> = relay.clone();
            RelayEndpoint::new("203.0.113.10:443").expect("an address").server_name(RELAY_NAME).expect("a name").dialer(dialer)
        };

        // With its identity, the handshake passes and the relay is shown the certificate.
        let with = base(&requiring).ca_pem(ca_pem.as_bytes()).expect("the CA").client_identity(cert_pem.as_bytes(), key_pem.as_bytes()).expect("an identity");
        assert!(presents(&with));
        assert_eq!(exchange(&with).await.0, Ok(*b"pong"));
        assert_eq!(seen.recv().await, Some(Some(cert_der.clone())), "the relay saw the worker's certificate");

        // `ca_pem` after `client_identity` gives the same configuration.
        let after = base(&requiring).client_identity(cert_pem.as_bytes(), key_pem.as_bytes()).expect("an identity").ca_pem(ca_pem.as_bytes()).expect("the CA");
        assert!(presents(&after));
        assert_eq!(exchange(&after).await.0, Ok(*b"pong"));
        assert_eq!(seen.recv().await, Some(Some(cert_der.clone())));
        let alone = base(&requiring).client_identity(cert_pem.as_bytes(), key_pem.as_bytes()).expect("an identity");
        assert!(alone.tls.is_none(), "no configuration before ca_pem");
        assert!(exchange(&alone).await.0.expect_err("no CA").contains("no relay CA"));

        // Without one, the relay's alert is R-121's words: on the connection's first read, and through check.
        let bare = base(&requiring).ca_pem(ca_pem.as_bytes()).expect("the CA");
        assert!(!presents(&bare));
        let (answer, alert) = exchange(&bare).await;
        assert!(answer.is_err(), "{answer:?}");
        let words = alert.expect("connected").words().expect("the relay's alert");
        assert_eq!(WorkerError::Tls(words).to_string(), "tls: the relay requires a client certificate");
        let refused = worker(bare.clone()).check().await.expect_err("refused at TLS");
        assert_eq!(refused, WorkerError::Tls("the relay requires a client certificate".into()));
        assert_eq!(refused.to_string(), "tls: the relay requires a client certificate");

        // A certificate past its not_after: the relay's refusal of it, by its alert.
        let key = certs::client_key().expect("a P-256 key");
        let lapsed = certs::client_leaf(&ca, "worker-a", &certs::client_point(&key).expect("its point"), now - 7200, now - 60).expect("a lapsed certificate");
        let lapsed = bare.clone().client_identity(certs::pem("CERTIFICATE", &lapsed).as_bytes(), certs::pem(&key_label(), &key).as_bytes()).expect("an identity");
        let refused = worker(lapsed).check().await.expect_err("refused at TLS");
        assert_eq!(refused.to_string(), "tls: the relay refused this worker's client certificate (CertificateExpired)");
        // One under another CA of the same name, as `tls init --force` leaves one (R-131): webpki finds the anchor
        // by its name, then the signature fails, so the relay's alert is `DecryptError`, one of R-121's on a
        // connection that presented a certificate.
        let other = certs::relay_ca(now).expect("another CA");
        let (other_cert, other_key, _) = client_pair(&other, now);
        let foreign = bare.clone().client_identity(other_cert.as_bytes(), other_key.as_bytes()).expect("an identity");
        let (answer, alert) = exchange(&foreign).await;
        assert!(answer.is_err(), "another CA's certificate: {answer:?}");
        assert_eq!(alert.expect("connected").first.get().copied().flatten(), Some(AlertDescription::DecryptError), "the relay's alert");
        let refused = worker(foreign).check().await.expect_err("another CA's certificate");
        assert_eq!(refused.to_string(), "tls: the relay refused this worker's client certificate (DecryptError)");

        // A relay that asks for none still serves an endpoint with an identity, and is shown no certificate.
        let to_none = base(&asking_none).ca_pem(ca_pem.as_bytes()).expect("the CA").client_identity(cert_pem.as_bytes(), key_pem.as_bytes()).expect("an identity");
        assert_eq!(exchange(&to_none).await.0, Ok(*b"pong"));
        assert_eq!(seen_none.recv().await, Some(None), "nothing presented unasked");

        // Refused identities.
        let e = RelayEndpoint::new("203.0.113.10:443").expect("an address");
        let refused = |cert: &str, key: &str| e.clone().client_identity(cert.as_bytes(), key.as_bytes()).err().expect("refused").to_string();
        assert_eq!(refused(&cert_pem, &other_key), "the client key does not match the client certificate");
        assert_eq!(refused(&format!("{cert_pem}{key_pem}"), &key_pem), "the client certificate file holds a private key");
        assert_eq!(refused(&format!("{cert_pem}{other_cert}"), &key_pem), "the client certificate file holds 2 PEM blocks, not one CERTIFICATE block");
        assert_eq!(refused("", &key_pem), "the client certificate file holds no CERTIFICATE block");
        assert_eq!(refused(&cert_pem, &cert_pem), "the client key file holds a CERTIFICATE block, not a PRIVATE KEY block");
        assert_eq!(refused(&cert_pem, &format!("{key_pem}{key_pem}")), "the client key file holds 2 PEM blocks, not one PRIVATE KEY block");
        let ed25519 = SigningKey::from_seed(&[3; 32]).expect("seed").to_pkcs8_pem().expect("PEM");
        assert_eq!(refused(&cert_pem, &ed25519), "the client key file holds no P-256 key (PKCS#8)");
        // The relay CA file still refuses a key.
        let with_key = format!("{ca_pem}{key_pem}");
        assert!(e.ca_pem(with_key.as_bytes()).err().expect("refused").to_string().contains("holds a private key"));
    }

    /// R-121's words alert by alert (beside WM-T56): `CertificateRequired` says the relay requires a client
    /// certificate, each of its seven refusals names the alert as rustls's Debug writes it, and any other alert
    /// has no words. A connection's first read error decides, and every copy of its record reads it.
    #[test]
    fn each_alert_of_a_client_certificate_has_r121s_words() {
        use AlertDescription as A;
        let alert_error = |alert: A| io::Error::new(io::ErrorKind::InvalidData, rustls::Error::AlertReceived(alert));
        let required = "the relay requires a client certificate";
        assert_eq!(alert_words(A::CertificateRequired, false).as_deref(), Some(required));
        assert_eq!(RelayAlert::received(A::CertificateRequired).words().as_deref(), Some(required));
        let refusals = [
            (A::BadCertificate, "BadCertificate"),
            (A::UnknownCA, "UnknownCA"),
            (A::CertificateExpired, "CertificateExpired"),
            (A::CertificateRevoked, "CertificateRevoked"),
            (A::CertificateUnknown, "CertificateUnknown"),
            (A::UnsupportedCertificate, "UnsupportedCertificate"),
            (A::AccessDenied, "AccessDenied"),
        ];
        for (alert, name) in refusals {
            let words = format!("the relay refused this worker's client certificate ({name})");
            assert_eq!(alert_words(alert, false).as_deref(), Some(words.as_str()), "{alert:?}");
            assert_eq!(RelayAlert::received(alert).words(), Some(words), "{alert:?} on the first read");
        }
        for other in [A::HandshakeFailure, A::DecodeError, A::IllegalParameter, A::InternalError, A::CloseNotify, A::ProtocolVersion, A::NoApplicationProtocol] {
            assert_eq!(alert_words(other, true), None, "{other:?}");
            assert_eq!(RelayAlert::received(other).words(), None, "{other:?}");
        }
        // `DecryptError` speaks of a certificate only on a connection that presented one (R-121, R-131).
        let words = "the relay refused this worker's client certificate (DecryptError)";
        assert_eq!(alert_words(A::DecryptError, true).as_deref(), Some(words));
        assert_eq!(alert_words(A::DecryptError, false), None);
        let record = RelayAlert::new(true);
        record.first_read_error(&alert_error(A::DecryptError));
        assert_eq!(record.words().as_deref(), Some(words));
        assert_eq!(RelayAlert::received(A::DecryptError).words(), None, "none presented");

        // A read error that is no alert of the relay's, then the alert: the first said nothing, so nothing.
        let record = RelayAlert::default();
        assert_eq!(record.words(), None, "no read error yet");
        record.first_read_error(&io::Error::new(io::ErrorKind::BrokenPipe, "the relay left"));
        record.first_read_error(&alert_error(A::CertificateRequired));
        assert_eq!(record.words(), None, "the first read error was no alert");
        let local = RelayAlert::default();
        local.first_read_error(&io::Error::new(io::ErrorKind::InvalidData, rustls::Error::DecryptError));
        assert_eq!(local.words(), None, "a failure of this side is no alert of the relay's");
        // The first alert stays; a copy taken before the read (the one `tunnel.rs` keeps) reads it too.
        let record = RelayAlert::default();
        let kept = record.clone();
        record.first_read_error(&alert_error(A::UnknownCA));
        record.first_read_error(&alert_error(A::CertificateRequired));
        assert_eq!(kept.words().as_deref(), Some("the relay refused this worker's client certificate (UnknownCA)"));
    }
}
