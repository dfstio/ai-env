//! The relay endpoint (WM-R11, WM-R12): TLS 1.3 under the pinned relay CA, over a pluggable byte transport.
//!
//! The client configuration (WM-R11a, the v6 amendment to invariant 15): TLS 1.3 only, the aws-lc-rs
//! provider, ALPN `h2`, and exactly the certificates of `ca_pem` as trust anchors: no public or native root
//! store, no custom verifier, no client auth. Proxy variables are never read: the default dialer connects
//! the address itself.

use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::{PemObject, SectionKind};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::globs::valid_relay_id;

/// The relay's port when the address names none.
const DEFAULT_PORT: u16 = 443;

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
    /// Built by `ca_pem`: the pinned CA's certificates are its only trust anchors.
    tls: Option<Arc<ClientConfig>>,
    expect_relay_id: Option<String>,
    dialer: Option<Arc<dyn Dial>>,
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
        Ok(RelayEndpoint { host: host.to_string(), port, server_name: None, tls: None, expect_relay_id: None, dialer: None })
    }

    /// The only trust anchors: the certificates of this PEM (at least one; a private key is refused).
    /// Required: an endpoint without it is accepted by `build()`, but every dial fails as TLS.
    pub fn ca_pem(mut self, pem: &[u8]) -> Result<RelayEndpoint, EndpointError> {
        let holds_key = pem.windows(b"PRIVATE KEY-----".len()).any(|w| w == b"PRIVATE KEY-----");
        if holds_key {
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
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| EndpointError(format!("TLS 1.3 with aws-lc-rs: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        self.tls = Some(Arc::new(config));
        Ok(self)
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

    /// One new connection: the dial and the TLS 1.3 handshake together within `budget` (WM-R12).
    pub(crate) async fn connect(&self, budget: Duration) -> Result<TlsStream<Box<dyn Io>>, Failure> {
        let config = self.tls.clone().ok_or_else(|| Failure::Tls("no relay CA: RelayEndpoint::ca_pem was not given one".into()))?;
        let name = self.verified_name()?;
        let attempt = async {
            let io: Box<dyn Io> = match &self.dialer {
                Some(d) => d.dial().await.map_err(|e| Failure::Dial(e.to_string()))?,
                None => {
                    let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await.map_err(|e| Failure::Dial(format!("{}:{}: {e}", self.host, self.port)))?;
                    tcp.set_nodelay(true).map_err(|e| Failure::Dial(e.to_string()))?;
                    Box::new(tcp)
                }
            };
            TlsConnector::from(config).connect(name, io).await.map_err(|e| Failure::Tls(e.to_string()))
        };
        tokio::time::timeout(budget, attempt).await.map_err(|_| Failure::Timeout)?
    }
}

/// Why `connect` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The byte stream: TCP, or the test's dialer.
    Dial(String),
    /// The TLS handshake (an unknown issuer, another name, a protocol version).
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
}
