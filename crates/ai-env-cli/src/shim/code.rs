//! `--code-port` (9418): the code channel (`PUT /seed`, `GET /bundle`, git
//! smart-HTTP) arrives in S8/S9. S3 binds the port so the image's listener
//! set is final; S6 puts the peer guard and then the session bearer in front
//! of every path, and answers 404 behind them.
use crate::shim::health::ShimState;
use axum::middleware::from_fn_with_state;
use axum::Router;
use std::sync::Arc;

/// The code-port router. Serve it with `into_make_service_with_connect_info::<peer::Peer>()`.
pub fn router(state: Arc<ShimState>) -> Router {
    // The last layer runs first: the guard, then the bearer.
    Router::new()
        .fallback(crate::shim::auth::not_implemented)
        .layer(from_fn_with_state(state.clone(), crate::shim::auth::code_bearer))
        .layer(from_fn_with_state(state, crate::shim::peer::guard))
}
