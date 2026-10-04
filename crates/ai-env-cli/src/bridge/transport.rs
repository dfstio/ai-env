//! The WebSocket dials to a MicroVM endpoint: `/agent` (S6) and the platform
//! shell `/shell` (S4, experimental). Every dial goes through
//! `tls::ws_connector()` — this file and `tls.rs` are the only places allowed
//! to (`make lint` confines every `client_async` form here).
//!
//! `/agent` ([`dial_agent`]): a TCP connect to `<host>:443` that ignores the
//! proxy environment, then `client_async_tls_with_config(wss request, tcp,
//! Some(wire::frame::ws_config()), Some(tls::ws_connector()))`, under one 60 s
//! timeout (it covers the platform's auto-resume hold). The debug knob
//! ([`AgentDial::local`], S6 D4) connects to a loopback address instead and
//! runs the same call with a `ws://<endpoint host>/agent` URI
//! (tokio-tungstenite takes the plain path for `ws://` even with
//! `Connector::Rustls`); release builds never take it, whatever `local` says.
use crate::bridge::api::{normalize_endpoint, APP_PORT, SHELL_PORT};
use crate::bridge::errors::BridgeError;
use crate::bridge::tls;
use crate::wire::frame::ws_config;
use crate::wire::redact::{scrub, Secret};
use http::HeaderValue;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError};
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// One `/agent` socket.
pub type AgentSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The overall budget of one `/agent` dial (TCP, TLS, upgrade).
pub const AGENT_DIAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Most bytes of a refused upgrade's body a [`DialError::Http`] keeps (scrubbed).
pub const REFUSAL_BODY_MAX: usize = 512;

/// Where `/agent` is dialed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentDial {
    /// The debug knob's loopback address (S6 D4); always `None` in release builds.
    pub local: Option<SocketAddr>,
}

/// Why an `/agent` dial failed, by what the caller does about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// 401/403 from the proxy (`x-aws-proxy-error`): re-mint once, then exit 7.
    TokenRejected { status: u16, proxy_error: Option<String> },
    /// 429: wait max(Retry-After, backoff); never re-mint.
    Throttled { retry_after_s: Option<u64> },
    /// 502 (the app does not answer, or auto-resume failed): ask GetMicrovm.
    Gateway { proxy_error: Option<String> },
    /// 503 `not_run` from the shim: `/run` has not returned yet (retry ≤ 30 s).
    NotRun,
    /// 503 `draining` from the shim: the VM is terminating.
    Draining,
    /// 503 `busy` from the shim: too many sockets without a hello.
    Busy,
    /// 404: the image predates `/agent` (exit 7).
    NoAgent,
    /// Any other status.
    Http { status: u16, body: String },
    /// Connect, reset, timeout: transient.
    Connect(String),
    /// A TLS failure (verification, version): never retried.
    Tls(String),
    /// A 101 tungstenite refused (Connection, Accept, an unrequested
    /// subprotocol), or a request that cannot be built (an endpoint outside the pin).
    Handshake(String),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::TokenRejected { status, proxy_error } => write!(f, "token rejected: HTTP {status}{}", proxy_error.as_ref().map(|p| format!(" (x-aws-proxy-error: {p})")).unwrap_or_default()),
            DialError::Throttled { retry_after_s } => write!(f, "throttled: HTTP 429{}", retry_after_s.map(|s| format!(", Retry-After {s} s")).unwrap_or_default()),
            DialError::Gateway { proxy_error } => write!(f, "HTTP 502{}", proxy_error.as_ref().map(|p| format!(" (x-aws-proxy-error: {p})")).unwrap_or_default()),
            DialError::NotRun => f.write_str("HTTP 503 not_run: the VM's /run has not returned"),
            DialError::Draining => f.write_str("HTTP 503 draining: the VM is terminating"),
            DialError::Busy => f.write_str("HTTP 503 busy: too many sockets without a hello"),
            DialError::NoAgent => f.write_str("HTTP 404: no /agent (the image is older than S6)"),
            DialError::Http { status, body } => write!(f, "HTTP {status}: {body}"),
            DialError::Connect(m) => write!(f, "connect: {m}"),
            DialError::Tls(m) => write!(f, "tls: {m}"),
            DialError::Handshake(m) => write!(f, "handshake: {m}"),
        }
    }
}

/// Dial `wss://<endpoint>/agent` with the endpoint token for port 8080 (or
/// the knob's loopback address in plain `ws://`), classified for the
/// session's reconnect rules.
pub async fn dial_agent(dial: &AgentDial, endpoint: &str, token: &Secret<String>) -> Result<AgentSocket, DialError> {
    let auth = UpgradeAuth::Header { token: token.clone(), port: APP_PORT };
    let req = upgrade_request(dial, endpoint, &auth).map_err(|e| DialError::Handshake(e.to_string()))?;
    handshake(dial, req).await.map(|(ws, _)| ws).map_err(|e| classify(*e))
}

/// How probe e0 presents a token on an upgrade attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeAuth {
    /// No token at all.
    None,
    /// `x-aws-proxy-auth` with this token and `x-aws-proxy-port: <port>`.
    Header { token: Secret<String>, port: u16 },
    /// The documented subprotocol form for this token and port.
    Subprotocol { token: Secret<String>, port: u16 },
}

/// What one probe upgrade got: the status, the proxy's error header, the
/// HTTP version of the response (as tungstenite parsed it: it refuses
/// HTTP/1.0, so every answer it reads is `HTTP/1.1`), and the socket when it
/// was a 101 the client accepted.
pub struct UpgradeProbe {
    pub status: u16,
    pub proxy_error: Option<String>,
    pub version: String,
    pub socket: Option<AgentSocket>,
    /// A 101 the client refused (no subprotocol echoed, a bad `Sec-WebSocket-Accept`, …): why.
    pub refused: Option<String>,
}

/// One `/agent` upgrade attempt for probe e0, whatever its HTTP outcome. A
/// failure before any answer (connect, TLS, timeout) is `Endpoint` (exit 7).
pub async fn upgrade_probe(dial: &AgentDial, endpoint: &str, auth: UpgradeAuth) -> Result<UpgradeProbe, BridgeError> {
    let req = upgrade_request(dial, endpoint, &auth)?;
    let answer = |resp: &Response, socket: Option<AgentSocket>| UpgradeProbe {
        status: resp.status().as_u16(),
        proxy_error: resp.headers().get("x-aws-proxy-error").and_then(|v| v.to_str().ok()).map(|v| scrub(v.trim()).into_owned()),
        version: format!("{:?}", resp.version()),
        socket,
        refused: None,
    };
    let e = match handshake(dial, req).await {
        Ok((ws, resp)) => return Ok(answer(&resp, Some(ws))),
        Err(e) => *e,
    };
    match e {
        WsError::Http(resp) => Ok(answer(&resp, None)),
        // tungstenite checks the status first: these refusals were all of a 101.
        WsError::Protocol(
            p @ (ProtocolError::MissingUpgradeWebSocketHeader | ProtocolError::MissingConnectionUpgradeHeader | ProtocolError::SecWebSocketAcceptKeyMismatch | ProtocolError::SecWebSocketSubProtocolError(_)),
        ) => Ok(UpgradeProbe { status: 101, proxy_error: None, version: format!("{:?}", http::Version::HTTP_11), socket: None, refused: Some(p.to_string()) }),
        e => Err(BridgeError::Endpoint(format!("/agent upgrade on {endpoint}: {}", classify(e)))),
    }
}

/// The handshake request for `wss://{endpoint}/agent`: tungstenite's own
/// WebSocket headers plus the endpoint token in `x-aws-proxy-auth` and the
/// target port in `x-aws-proxy-port`. No `Sec-WebSocket-Protocol`: subprotocol
/// auth is the documented fallback for clients that cannot set headers. The
/// endpoint must pass `normalize_endpoint`.
pub fn agent_request(endpoint: &str, token: &Secret<String>, port: u16) -> Result<http::Request<()>, BridgeError> {
    request("wss", endpoint, &UpgradeAuth::Header { token: token.clone(), port })
}

/// The knob's loopback address, honoured in debug builds only.
#[cfg(debug_assertions)]
fn knob(dial: &AgentDial) -> Option<SocketAddr> {
    dial.local
}

/// Release builds: never a plain-text dial, whatever `local` says.
#[cfg(not(debug_assertions))]
fn knob(_dial: &AgentDial) -> Option<SocketAddr> {
    None
}

/// The request of one dial: `ws://` through the knob, `wss://` otherwise.
fn upgrade_request(dial: &AgentDial, endpoint: &str, auth: &UpgradeAuth) -> Result<http::Request<()>, BridgeError> {
    match knob(dial) {
        Some(addr) if !addr.ip().is_loopback() => Err(BridgeError::Policy(format!("refusing a plain-text /agent dial to {addr}: the knob takes loopback addresses only"))),
        Some(_) => request("ws", endpoint, auth),
        None => request("wss", endpoint, auth),
    }
}

/// `<scheme>://<host>/agent` with `auth` (a header value marked sensitive).
fn request(scheme: &str, endpoint: &str, auth: &UpgradeAuth) -> Result<http::Request<()>, BridgeError> {
    let host = normalize_endpoint(endpoint)?;
    let err = |e: &dyn std::fmt::Display| BridgeError::Transport(format!("cannot build /agent request: {e}"));
    let mut req = format!("{scheme}://{host}/agent").into_client_request().map_err(|e| err(&e))?;
    let headers = req.headers_mut();
    match auth {
        UpgradeAuth::None => {}
        UpgradeAuth::Header { token, port } => {
            let mut v = HeaderValue::from_str(token.expose()).map_err(|e| err(&e))?;
            v.set_sensitive(true);
            headers.insert("x-aws-proxy-auth", v);
            headers.insert("x-aws-proxy-port", HeaderValue::from(*port));
        }
        UpgradeAuth::Subprotocol { token, port } => {
            let mut v = HeaderValue::from_str(&format!("lambda-microvms.authentication.{}, lambda-microvms, lambda-microvms.port.{port}", token.expose())).map_err(|e| err(&e))?;
            v.set_sensitive(true);
            headers.insert("sec-websocket-protocol", v);
        }
    }
    Ok(req)
}

/// TCP to `<host>:443` (the proxy environment is never consulted) or to the
/// knob's address, then TLS (for `wss://`) and the upgrade with the wire's
/// size caps, all within [`AGENT_DIAL_TIMEOUT`]. The error is boxed: it is
/// large, and only failures carry it.
async fn handshake(dial: &AgentDial, req: http::Request<()>) -> Result<(AgentSocket, Response), Box<WsError>> {
    let run = async {
        let tcp = match knob(dial) {
            Some(addr) => tokio::net::TcpStream::connect(addr).await?,
            None => {
                let host = req.uri().host().unwrap_or_default().to_string();
                tokio::net::TcpStream::connect((host.as_str(), 443)).await?
            }
        };
        // Pings, pongs and acks are small: never hold them back for coalescing.
        let _ = tcp.set_nodelay(true);
        tokio_tungstenite::client_async_tls_with_config(req, tcp, Some(ws_config()), Some(tls::ws_connector())).await
    };
    match tokio::time::timeout(AGENT_DIAL_TIMEOUT, run).await {
        Ok(r) => r.map_err(Box::new),
        Err(_) => Err(Box::new(WsError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("no WebSocket upgrade within {} s", AGENT_DIAL_TIMEOUT.as_secs()))))),
    }
}

/// A failed handshake, by what the caller does about it.
fn classify(e: WsError) -> DialError {
    match e {
        WsError::Http(resp) => refused(&resp),
        WsError::Io(io) => match io.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
            Some(tls) => DialError::Tls(tls.to_string()),
            None => DialError::Connect(io.to_string()),
        },
        WsError::Tls(t) => DialError::Tls(t.to_string()),
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Protocol(ProtocolError::HandshakeIncomplete) => DialError::Connect("the connection closed during the upgrade".into()),
        other => DialError::Handshake(scrub(&other.to_string()).into_owned()),
    }
}

/// A non-101 answer to the upgrade.
fn refused(resp: &http::Response<Option<Vec<u8>>>) -> DialError {
    let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).map(|v| scrub(v.trim()).into_owned());
    let proxy_error = header("x-aws-proxy-error");
    let body = resp.body().as_deref().unwrap_or_default();
    let status = resp.status().as_u16();
    match status {
        401 | 403 => DialError::TokenRejected { status, proxy_error },
        429 => DialError::Throttled { retry_after_s: header("retry-after").and_then(|v| v.parse().ok()) },
        502 => DialError::Gateway { proxy_error },
        // The shim's own 503s say why in `{"status": …}`.
        503 => match serde_json::from_slice::<serde_json::Value>(body).ok().as_ref().and_then(|v| v.get("status")).and_then(serde_json::Value::as_str) {
            Some("not_run") => DialError::NotRun,
            Some("draining") => DialError::Draining,
            Some("busy") => DialError::Busy,
            _ => DialError::Http { status, body: refusal_text(proxy_error, body) },
        },
        404 => DialError::NoAgent,
        _ => DialError::Http { status, body: refusal_text(proxy_error, body) },
    }
}

/// `x-aws-proxy-error: <e>; <body>`, the body scrubbed whole, then cut at
/// [`REFUSAL_BODY_MAX`] bytes: a cut first would split a secret straddling
/// it, and the scrubber masks only whole values (tungstenite keeps no more
/// of a refused upgrade's body than its last read).
fn refusal_text(proxy_error: Option<String>, body: &[u8]) -> String {
    let mut body = scrub(String::from_utf8_lossy(body).trim()).into_owned();
    body.truncate(body.floor_char_boundary(REFUSAL_BODY_MAX));
    match proxy_error {
        Some(p) if body.is_empty() => format!("x-aws-proxy-error: {p}"),
        Some(p) => format!("x-aws-proxy-error: {p}; {body}"),
        None => body,
    }
}

/// How `vm shell` presents its token (plan S4 D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellAuth {
    /// `x-aws-proxy-auth` + `x-aws-proxy-port: 8022` headers (inferred from the
    /// proxy's header rules; the default).
    Header,
    /// The documented subprotocol form: `lambda-microvms.authentication.<token>`,
    /// `lambda-microvms`, `lambda-microvms.port.8022`. tungstenite refuses the
    /// handshake when the proxy echoes none of them.
    Subprotocol,
}

/// The handshake request for `wss://{endpoint}/shell` (the endpoint must pass
/// `normalize_endpoint`).
pub fn shell_request(endpoint: &str, token: &Secret<String>, auth: ShellAuth) -> Result<http::Request<()>, BridgeError> {
    let host = normalize_endpoint(endpoint)?;
    let err = |e: &dyn std::fmt::Display| BridgeError::Transport(format!("cannot build /shell request: {e}"));
    let mut req = format!("wss://{host}/shell").into_client_request().map_err(|e| err(&e))?;
    let headers = req.headers_mut();
    match auth {
        ShellAuth::Header => {
            let mut v = HeaderValue::from_str(token.expose()).map_err(|e| err(&e))?;
            v.set_sensitive(true);
            headers.insert("x-aws-proxy-auth", v);
            headers.insert("x-aws-proxy-port", HeaderValue::from(SHELL_PORT));
        }
        ShellAuth::Subprotocol => {
            let mut v = HeaderValue::from_str(&format!("lambda-microvms.authentication.{}, lambda-microvms, lambda-microvms.port.{SHELL_PORT}", token.expose())).map_err(|e| err(&e))?;
            v.set_sensitive(true);
            headers.insert("sec-websocket-protocol", v);
        }
    }
    Ok(req)
}

/// Dial the shell: TCP to `<host>:443` (no proxy environment consulted), then
/// TLS through `tls::ws_connector()` (TLS 1.3, Amazon roots) and the
/// WebSocket handshake. A refused handshake is exit 7 naming the HTTP status
/// (403: the token; 400/404: the VM was not started with `vm run --shell`).
pub async fn dial_shell(endpoint: &str, token: &Secret<String>, auth: ShellAuth) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, BridgeError> {
    let req = shell_request(endpoint, token, auth)?;
    let host = req.uri().host().unwrap_or_default().to_string();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), 443)).await.map_err(|e| BridgeError::Endpoint(format!("cannot connect to {host}:443: {e}")))?;
    match tokio_tungstenite::client_async_tls_with_config(req, tcp, None, Some(tls::ws_connector())).await {
        Ok((ws, _response)) => Ok(ws),
        Err(WsError::Http(resp)) => {
            let proxy = resp.headers().get("x-aws-proxy-error").and_then(|v| v.to_str().ok()).map(str::to_string);
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                return Err(BridgeError::TokenRejected { port: SHELL_PORT, status, proxy_error: proxy });
            }
            Err(BridgeError::Http { status, body: format!("the shell handshake was refused{} (is this VM running with `ai-env vm run --shell`?)", proxy.map(|p| format!(" (x-aws-proxy-error: {p})")).unwrap_or_default()) })
        }
        Err(WsError::Protocol(ProtocolError::SecWebSocketSubProtocolError(e))) => {
            Err(BridgeError::Endpoint(format!("the proxy did not accept the subprotocol form ({e}); use --auth header, or the console's Connect")))
        }
        Err(e) => Err(BridgeError::Endpoint(format!("shell handshake with {host}: {}", crate::wire::redact::scrub(&e.to_string())))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;

    const HOST: &str = "bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws";

    /// Every async test ends within 30 s.
    async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(30), f).await.expect("the test ran past its limit")
    }

    #[test]
    fn shell_request_header_form() {
        let req = shell_request(HOST, &Secret::new("tok".repeat(4)), ShellAuth::Header).unwrap();
        assert_eq!(req.uri().to_string(), format!("wss://{HOST}/shell"));
        let h = req.headers();
        assert_eq!(h.get("x-aws-proxy-port").unwrap(), "8022");
        assert!(h.get("x-aws-proxy-auth").unwrap().is_sensitive());
        assert!(h.get("sec-websocket-protocol").is_none());
    }

    #[test]
    fn shell_request_subprotocol_form_and_host_pin() {
        let req = shell_request(&format!("https://{HOST}/"), &Secret::new("tok".repeat(4)), ShellAuth::Subprotocol).unwrap();
        let p = req.headers().get("sec-websocket-protocol").unwrap();
        assert!(p.is_sensitive());
        assert_eq!(p.to_str().unwrap(), format!("lambda-microvms.authentication.{}, lambda-microvms, lambda-microvms.port.8022", "tok".repeat(4)));
        assert!(req.headers().get("x-aws-proxy-auth").is_none());
        assert!(shell_request("evil.example.com", &Secret::new("t".into()), ShellAuth::Header).is_err(), "only the pinned endpoint suffix");
    }

    #[test]
    fn request_has_ws_and_proxy_headers_and_hides_the_token() {
        let req = agent_request(&format!("https://{HOST}/"), &Secret::new("tok".into()), 8080).unwrap();
        assert_eq!(req.uri().to_string(), format!("wss://{HOST}/agent"));
        let h = req.headers();
        assert_eq!(h.get("host").unwrap(), HOST);
        assert_eq!(h.get("x-aws-proxy-port").unwrap(), "8080");
        assert!(h.get("x-aws-proxy-auth").unwrap().is_sensitive());
        assert!(!format!("{:?}", h.get("x-aws-proxy-auth").unwrap()).contains("tok"));
        assert!(h.get("sec-websocket-key").is_some());
        assert!(h.get("sec-websocket-protocol").is_none());
    }

    #[test]
    fn agent_request_pins_the_endpoint() {
        for bad in ["mvm-1.microvms.eu-central-1.on.aws", "evil.example.com", "http://x.lambda-microvm.eu-central-1.on.aws"] {
            assert!(matches!(agent_request(bad, &Secret::new("tok".into()), 8080), Err(BridgeError::Endpoint(_))), "{bad}");
        }
    }

    #[test]
    fn probe_requests_carry_exactly_their_auth() {
        let tok = || Secret::new("tok".repeat(4));
        let none = request("wss", HOST, &UpgradeAuth::None).unwrap();
        assert!(none.headers().get("x-aws-proxy-auth").is_none() && none.headers().get("sec-websocket-protocol").is_none());
        let other_port = request("wss", HOST, &UpgradeAuth::Header { token: tok(), port: 8081 }).unwrap();
        assert_eq!(other_port.headers().get("x-aws-proxy-port").unwrap(), "8081");
        let sub = request("wss", HOST, &UpgradeAuth::Subprotocol { token: tok(), port: 8080 }).unwrap();
        let p = sub.headers().get("sec-websocket-protocol").unwrap();
        assert!(p.is_sensitive());
        assert_eq!(p.to_str().unwrap(), format!("lambda-microvms.authentication.{}, lambda-microvms, lambda-microvms.port.8080", "tok".repeat(4)));
        assert!(sub.headers().get("x-aws-proxy-auth").is_none());
    }

    #[test]
    fn the_knob_takes_loopback_only_and_dials_plain_ws() {
        let local = |a: &str| AgentDial { local: Some(a.parse().unwrap()) };
        let req = upgrade_request(&local("127.0.0.1:18080"), HOST, &UpgradeAuth::None).unwrap();
        assert_eq!(req.uri().to_string(), format!("ws://{HOST}/agent"), "the endpoint host stays in the URI (and Host)");
        assert_eq!(upgrade_request(&AgentDial::default(), HOST, &UpgradeAuth::None).unwrap().uri().scheme_str(), Some("wss"));
        let e = upgrade_request(&local("10.0.0.5:18080"), HOST, &UpgradeAuth::None).unwrap_err();
        assert!(matches!(e, BridgeError::Policy(_)), "{e}");
    }

    fn answer(status: u16, headers: &[(&str, &str)], body: &[u8]) -> http::Response<Option<Vec<u8>>> {
        let mut b = http::Response::builder().status(status);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Some(body.to_vec())).unwrap()
    }

    #[test]
    fn refusals_by_status_and_body() {
        let proxy = Some("UNAUTHORIZED".to_string());
        assert_eq!(refused(&answer(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], b"")), DialError::TokenRejected { status: 403, proxy_error: proxy.clone() });
        assert_eq!(refused(&answer(401, &[], b"")), DialError::TokenRejected { status: 401, proxy_error: None });
        assert_eq!(refused(&answer(429, &[("retry-after", "2")], b"")), DialError::Throttled { retry_after_s: Some(2) });
        assert_eq!(refused(&answer(429, &[], b"")), DialError::Throttled { retry_after_s: None });
        assert_eq!(refused(&answer(429, &[("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")], b"")), DialError::Throttled { retry_after_s: None }, "a date is no number of seconds");
        assert_eq!(refused(&answer(502, &[("x-aws-proxy-error", "MICROVM_SUSPENDED")], b"")), DialError::Gateway { proxy_error: Some("MICROVM_SUSPENDED".into()) });
        assert_eq!(refused(&answer(503, &[("retry-after", "1")], br#"{"status":"not_run"}"#)), DialError::NotRun);
        assert_eq!(refused(&answer(503, &[], br#"{"status":"draining"}"#)), DialError::Draining);
        assert_eq!(refused(&answer(503, &[], br#"{"status":"busy"}"#)), DialError::Busy);
        assert_eq!(refused(&answer(503, &[], b"upstream down")), DialError::Http { status: 503, body: "upstream down".into() });
        assert_eq!(refused(&answer(404, &[], b"")), DialError::NoAgent);
        let long = refused(&answer(418, &[("x-aws-proxy-error", "TEAPOT")], &[b'x'; 2000]));
        let DialError::Http { status: 418, body } = long else { panic!("{long:?}") };
        assert_eq!(body, format!("x-aws-proxy-error: TEAPOT; {}", "x".repeat(REFUSAL_BODY_MAX)));
        // A registered value in a body never reaches the error text.
        let token = "refusal-body-secret-value-0001";
        crate::wire::redact::register_secret(token);
        let DialError::Http { body, .. } = refused(&answer(400, &[], format!("bad token {token}").as_bytes())) else { panic!() };
        assert!(!body.contains(token), "{body}");
    }

    /// The body is scrubbed before the cut: a secret straddling it leaves no
    /// prefix behind, and a cut never splits a character.
    #[test]
    fn a_refusal_body_is_scrubbed_before_it_is_cut() {
        let token = "refusal-straddling-secret-value-0123456789";
        crate::wire::redact::register_secret(token);
        let text = |body: &[u8]| match refused(&answer(400, &[], body)) {
            DialError::Http { body, .. } => body,
            other => panic!("{other:?}"),
        };
        let body = text(format!("{}{token}", "x".repeat(REFUSAL_BODY_MAX - 12)).as_bytes());
        assert!(!body.contains(&token[..8]) && body.len() <= REFUSAL_BODY_MAX, "{body}");
        // An `eyJ…` token is masked only whole (at least 200 chars): cut first, its head would show.
        let body = text(format!("{}eyJ{}", "y".repeat(400), "a".repeat(300)).as_bytes());
        assert!(!body.contains("aaaaaaaa"), "{body}");
        let body = text("é".repeat(REFUSAL_BODY_MAX).as_bytes());
        assert_eq!(body, "é".repeat(REFUSAL_BODY_MAX / 2));
    }

    #[test]
    fn transport_failures_by_kind() {
        let rustls_err = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        assert!(matches!(classify(WsError::Io(rustls_err)), DialError::Tls(m) if m.contains("UnknownIssuer")));
        assert!(matches!(classify(WsError::Tls(tokio_tungstenite::tungstenite::error::TlsError::InvalidDnsName)), DialError::Tls(_)));
        assert!(matches!(classify(WsError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))), DialError::Connect(_)));
        assert!(matches!(classify(WsError::Protocol(ProtocolError::HandshakeIncomplete)), DialError::Connect(_)));
        assert!(matches!(classify(WsError::Protocol(ProtocolError::SecWebSocketAcceptKeyMismatch)), DialError::Handshake(_)));
    }

    /// A loopback server that reads one request head and writes `reply`
    /// verbatim; the head it read comes back on the channel.
    async fn raw_server(reply: &'static [u8]) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                let _ = s.write_all(reply).await;
                let _ = s.shutdown().await;
            }
        });
        (addr, rx)
    }

    fn knob_at(addr: SocketAddr) -> AgentDial {
        AgentDial { local: Some(addr) }
    }

    #[tokio::test]
    async fn dial_agent_through_the_knob_upgrades_and_presents_the_token() {
        bounded(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                let keep = seen.clone();
                // tungstenite's `Callback` fixes this signature.
                #[allow(clippy::result_large_err)]
                let cb = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
                    let mut s = keep.lock().unwrap();
                    for name in ["host", "x-aws-proxy-auth", "x-aws-proxy-port"] {
                        s.push(req.headers().get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default());
                    }
                    Ok(resp)
                };
                let mut ws = tokio_tungstenite::accept_hdr_async(tcp, cb).await.unwrap();
                let msg = ws.next().await.unwrap().unwrap();
                ws.send(msg).await.unwrap();
                let got = seen.lock().unwrap().clone();
                got
            });
            let token = Secret::new("knob-test-token".to_string());
            let mut ws = dial_agent(&knob_at(addr), HOST, &token).await.unwrap();
            ws.send(Message::text("echo")).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("echo"));
            assert_eq!(server.await.unwrap(), vec![HOST.to_string(), "knob-test-token".to_string(), "8080".to_string()]);
        })
        .await;
    }

    #[tokio::test]
    async fn dial_agent_classifies_what_the_server_answers() {
        bounded(async {
            let cases: [(&'static [u8], DialError); 5] = [
                (b"HTTP/1.1 403 Forbidden\r\nx-aws-proxy-error: UNAUTHORIZED\r\ncontent-length: 0\r\n\r\n", DialError::TokenRejected { status: 403, proxy_error: Some("UNAUTHORIZED".into()) }),
                (b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 3\r\ncontent-length: 0\r\n\r\n", DialError::Throttled { retry_after_s: Some(3) }),
                (b"HTTP/1.1 503 Service Unavailable\r\nretry-after: 1\r\ncontent-type: application/json\r\ncontent-length: 20\r\n\r\n{\"status\":\"not_run\"}", DialError::NotRun),
                (b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n", DialError::NoAgent),
                (b"HTTP/1.1 418 I'm a teapot\r\ncontent-length: 5\r\n\r\nshort", DialError::Http { status: 418, body: "short".into() }),
            ];
            for (reply, want) in cases {
                let (addr, mut heads) = raw_server(reply).await;
                let got = dial_agent(&knob_at(addr), HOST, &Secret::new("classify-token".into())).await.err().unwrap();
                assert_eq!(got, want);
                let head = heads.recv().await.unwrap().to_ascii_lowercase();
                assert!(head.starts_with("get /agent http/1.1\r\n") && head.contains("x-aws-proxy-port: 8080"), "{head}");
            }
            let (addr, _) = raw_server(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: bogus\r\n\r\n").await;
            assert!(matches!(dial_agent(&knob_at(addr), HOST, &Secret::new("t".repeat(9))).await.err().unwrap(), DialError::Handshake(_)), "a bad Accept");
            let (addr, _) = raw_server(b"").await;
            assert!(matches!(dial_agent(&knob_at(addr), HOST, &Secret::new("t".repeat(9))).await.err().unwrap(), DialError::Connect(_)), "closed before any answer");
            let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
            assert!(matches!(dial_agent(&knob_at(closed), HOST, &Secret::new("t".repeat(9))).await.err().unwrap(), DialError::Connect(_)), "nothing listens");
        })
        .await;
    }

    #[tokio::test]
    async fn upgrade_probe_reports_status_version_and_socket() {
        bounded(async {
            let (addr, mut heads) = raw_server(b"HTTP/1.1 403 Forbidden\r\nx-aws-proxy-error: UNAUTHORIZED\r\ncontent-length: 0\r\n\r\n").await;
            let p = upgrade_probe(&knob_at(addr), HOST, UpgradeAuth::None).await.unwrap();
            assert_eq!((p.status, p.proxy_error.as_deref(), p.version.as_str(), p.socket.is_none(), p.refused.is_none()), (403, Some("UNAUTHORIZED"), "HTTP/1.1", true, true));
            let head = heads.recv().await.unwrap().to_ascii_lowercase();
            assert!(!head.contains("x-aws-proxy-auth") && !head.contains("sec-websocket-protocol"), "no token at all: {head}");

            // A plain WebSocket server: the header form gets a socket; the subprotocol
            // form gets a 101 that echoes no subprotocol, which the client refuses.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        if let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await {
                            while let Some(Ok(_)) = ws.next().await {}
                        }
                    });
                }
            });
            let tok = || Secret::new("probe-test-token".to_string());
            let p = upgrade_probe(&knob_at(addr), HOST, UpgradeAuth::Header { token: tok(), port: 8080 }).await.unwrap();
            assert_eq!((p.status, p.version.as_str(), p.socket.is_some()), (101, "HTTP/1.1", true));
            let p = upgrade_probe(&knob_at(addr), HOST, UpgradeAuth::Subprotocol { token: tok(), port: 8080 }).await.unwrap();
            assert_eq!((p.status, p.socket.is_none()), (101, true));
            assert!(p.refused.as_deref().is_some_and(|r| r.to_ascii_lowercase().contains("subprotocol")), "{:?}", p.refused);
            let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
            assert!(matches!(upgrade_probe(&knob_at(closed), HOST, UpgradeAuth::None).await, Err(BridgeError::Endpoint(_))));
        })
        .await;
    }
}
