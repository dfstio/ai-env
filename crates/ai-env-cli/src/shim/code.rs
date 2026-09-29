//! `--code-port` (9418): the code channel (`PUT /seed`, `GET /bundle`, git
//! smart-HTTP) arrives in S8/S9. S3 binds the port so the image's listener
//! set is final, and answers every request 404.
use axum::http::StatusCode;
use axum::Router;

pub fn router() -> Router {
    Router::new().fallback(|| async { (StatusCode::NOT_FOUND, "ai-env: the code channel is not implemented yet (S8/S9)\n") })
}
