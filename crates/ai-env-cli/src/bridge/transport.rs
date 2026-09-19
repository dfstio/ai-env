//! The `/agent` WebSocket dial (S0: request construction only; the pump and
//! reconnect logic arrive with the transport stage).
use crate::bridge::errors::BridgeError;
use crate::wire::redact::Secret;
use http::HeaderValue;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

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

#[cfg(test)]
mod tests {
    use super::*;

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
