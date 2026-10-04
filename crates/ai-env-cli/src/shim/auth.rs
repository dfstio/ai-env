//! The session bearer on the side channels (plan S6): `Authorization:
//! Bearer <session token>`, checked against the `/run` commitment with
//! `RunHookPayload::matches` (constant time). App port: every path but
//! `/health` and `/agent` (`/agent` authenticates in `hello`; both answer
//! 405 to other methods themselves); code port: every path. No commitment
//! (before `/run`, or after a fail-closed `/run`) → 401; a bad or missing
//! bearer → 401; with a valid bearer an unknown path answers 404 "not
//! implemented (S8/S9)". The peer guard runs first, so a local agent-uid
//! client gets 403 before any bearer check. Each of these answers reads the
//! request body first ([`drain`]): the client gets it, not a reset.
use crate::shim::health::ShimState;
use crate::shim::peer::drain;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

/// The app-port paths outside the bearer.
pub const PUBLIC_PATHS: [&str; 2] = ["/health", "/agent"];

/// Does `headers` carry the session bearer of this VM's `/run` commitment?
/// Exactly one `Authorization` header, scheme `Bearer` (any case), a
/// non-empty token whose sha256 is the commitment.
#[must_use]
pub fn bearer_ok(state: &ShimState, headers: &HeaderMap) -> bool {
    let Some(payload) = state.run.payload() else {
        return false;
    };
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let Some((scheme, token)) = value.to_str().ok().and_then(|v| v.split_once(' ')) else {
        return false;
    };
    let token = token.trim_matches(' ');
    scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && payload.matches(token.as_bytes())
}

/// 401 `unauthorized` (with `WWW-Authenticate: Bearer`), after draining the
/// request body (bounded), as every refusal does.
async fn unauthorized(req: Request) -> Response {
    drain(req).await;
    let mut res = (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"status": "unauthorized"}))).into_response();
    res.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    res
}

/// The app port's bearer layer: [`PUBLIC_PATHS`] pass, every other path needs the bearer.
pub async fn app_bearer(State(state): State<Arc<ShimState>>, req: Request, next: Next) -> Response {
    if PUBLIC_PATHS.contains(&req.uri().path()) || bearer_ok(&state, req.headers()) {
        next.run(req).await
    } else {
        unauthorized(req).await
    }
}

/// The code port's bearer layer: every path needs the bearer.
pub async fn code_bearer(State(state): State<Arc<ShimState>>, req: Request, next: Next) -> Response {
    if bearer_ok(&state, req.headers()) {
        next.run(req).await
    } else {
        unauthorized(req).await
    }
}

/// What both ports answer behind the bearer for a path no stage serves yet
/// (`PUT /seed`, a git push), after draining the request body (bounded), so
/// the client reads the 404 instead of a reset.
pub async fn not_implemented(req: Request) -> Response {
    drain(req).await;
    (StatusCode::NOT_FOUND, "ai-env: not implemented (S8/S9)\n").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::state::RunRecord;
    use crate::wire::frame::RunHookPayload;
    use crate::wire::redact::Secret;
    use std::path::PathBuf;
    use std::time::Instant;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(header::AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn state_after_run(token: Option<&str>) -> ShimState {
        let s = ShimState::new(PathBuf::from("/nonexistent/claude"));
        let payload = token.map(|t| RunHookPayload::new(&Secret::new(t.to_string()), "mike@mbp", "2026-10-03T08:00:00Z"));
        s.run.claim(&[1; 32], || RunRecord { microvm_id: None, payload, body_sha256: [1; 32], at: Instant::now(), boot_nonce: "0".repeat(32) });
        s
    }

    #[test]
    fn the_bearer_must_match_the_commitment() {
        let token = format!("bearer-test-{}", "t".repeat(20));
        let s = state_after_run(Some(&token));
        assert!(bearer_ok(&s, &headers(&[&format!("Bearer {token}")])));
        assert!(bearer_ok(&s, &headers(&[&format!("bearer {token}")])), "the scheme is case-insensitive");
        assert!(bearer_ok(&s, &headers(&[&format!("Bearer  {token} ")])), "extra spaces around the token");
        for bad in [format!("Bearer {token}x"), format!("Basic {token}"), token.clone(), "Bearer".into(), "Bearer ".into(), String::new()] {
            assert!(!bearer_ok(&s, &headers(&[&bad])), "{bad:?}");
        }
        assert!(!bearer_ok(&s, &HeaderMap::new()), "no header");
        assert!(!bearer_ok(&s, &headers(&[&format!("Bearer {token}"), &format!("Bearer {token}")])), "two headers are ambiguous");
    }

    #[test]
    fn no_commitment_admits_no_bearer() {
        let before = ShimState::new(PathBuf::from("/nonexistent/claude"));
        assert!(!bearer_ok(&before, &headers(&["Bearer anything"])), "before /run");
        let fail_closed = state_after_run(None);
        assert!(!bearer_ok(&fail_closed, &headers(&["Bearer anything"])), "after a fail-closed /run");
    }
}
