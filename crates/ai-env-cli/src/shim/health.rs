//! `GET /health` — the public summary the Mac polls after `run_microvm`.
use crate::wire::frame::{Health, HealthStatus};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

pub struct ShimState {
    started: Instant,
    claude: PathBuf,
    claude_version: OnceCell<Option<String>>,
}

impl ShimState {
    #[must_use]
    pub fn new(claude: PathBuf) -> Self {
        ShimState { started: Instant::now(), claude, claude_version: OnceCell::new() }
    }

    /// `<claude> --version` once, with a 5 s timeout; `None` when it fails.
    async fn claude_version(&self) -> Option<String> {
        self.claude_version
            .get_or_init(|| async {
                let out = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::process::Command::new(&self.claude).arg("--version").output(),
                )
                .await
                .ok()?
                .ok()?;
                if !out.status.success() {
                    return None;
                }
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            })
            .await
            .clone()
    }

    pub async fn health(&self) -> Health {
        Health {
            status: HealthStatus::Ok,
            shim_version: env!("CARGO_PKG_VERSION").to_string(),
            claude_version: self.claude_version().await,
            microvm_id: None,
            owner: None,
            created: None,
            boot_nonce: None,
            run_hook_seen: false,
            uptime_s: self.started.elapsed().as_secs(),
        }
    }
}

async fn health(State(state): State<Arc<ShimState>>) -> Json<Health> {
    Json(state.health().await)
}

/// The app-port router (http1 only; `/agent` joins it in the transport stage).
pub fn router(state: Arc<ShimState>) -> Router {
    Router::new().route("/health", get(health)).with_state(state)
}
