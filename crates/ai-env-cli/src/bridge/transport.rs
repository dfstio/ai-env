//! The WebSocket dials to a MicroVM endpoint: the `/agent` request (S0; the
//! pump and reconnect logic arrive with the transport stage) and the
//! platform shell `/shell` (S4, experimental). Every dial goes through
//! `tls::ws_connector()` — this file and `tls.rs` are the only places allowed
//! to (`make lint`).
use crate::bridge::api::{normalize_endpoint, SHELL_PORT};
use crate::bridge::errors::BridgeError;
use crate::bridge::tls;
use crate::wire::redact::Secret;
use http::HeaderValue;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The handshake request for `wss://{endpoint}/agent`: tungstenite's own
/// WebSocket headers plus the endpoint token in `x-aws-proxy-auth` and the
/// target port in `x-aws-proxy-port`. No `Sec-WebSocket-Protocol`: subprotocol
/// auth is the documented fallback for clients that cannot set headers.
pub fn agent_request(endpoint: &str, token: &Secret<String>, port: u16) -> Result<http::Request<()>, BridgeError> {
    let err = |e: &dyn std::fmt::Display| BridgeError::Transport(format!("cannot build /agent request: {e}"));
    let mut req = format!("wss://{endpoint}/agent").into_client_request().map_err(|e| err(&e))?;
    let mut auth = HeaderValue::from_str(token.expose()).map_err(|e| err(&e))?;
    auth.set_sensitive(true);
    let headers = req.headers_mut();
    headers.insert("x-aws-proxy-auth", auth);
    headers.insert("x-aws-proxy-port", HeaderValue::from_str(&port.to_string()).map_err(|e| err(&e))?);
    Ok(req)
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
    use tokio_tungstenite::tungstenite::error::{Error as WsError, ProtocolError};
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

    const HOST: &str = "bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws";

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
        let req = agent_request("mvm-1.microvms.eu-central-1.on.aws", &Secret::new("tok".into()), 8080).unwrap();
        assert_eq!(req.uri().to_string(), "wss://mvm-1.microvms.eu-central-1.on.aws/agent");
        let h = req.headers();
        assert_eq!(h.get("host").unwrap(), "mvm-1.microvms.eu-central-1.on.aws");
        assert_eq!(h.get("x-aws-proxy-port").unwrap(), "8080");
        assert!(h.get("x-aws-proxy-auth").unwrap().is_sensitive());
        assert!(!format!("{:?}", h.get("x-aws-proxy-auth").unwrap()).contains("tok"));
        assert!(h.get("sec-websocket-key").is_some());
        assert!(h.get("sec-websocket-protocol").is_none());
    }
}
