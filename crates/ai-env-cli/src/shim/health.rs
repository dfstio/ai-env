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
    /// Filled by the first SUCCESSFUL `--version` probe; stays empty (and
    /// is probed again on the next `/health`) while claude fails to answer.
    claude_version: OnceCell<String>,
}

impl ShimState {
    #[must_use]
    pub fn new(claude: PathBuf) -> Self {
        ShimState { started: Instant::now(), claude, claude_version: OnceCell::new() }
    }

    /// `<claude> --version` with a 5 s timeout, cached once it succeeds. A
    /// probe that fails or times out (the binary is still being unpacked at
    /// VM boot, say) is NOT cached: `/health` reports `null` and the next poll
    /// probes again. The cached value is the first whitespace-separated token
    /// of stdout, so `2.1.278 (Claude Code)` is reported as `2.1.278`.
    async fn claude_version(&self) -> Option<String> {
        self.claude_version
            .get_or_try_init(|| async {
                let out = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::process::Command::new(&self.claude).arg("--version").kill_on_drop(true).output(),
                )
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                if !out.status.success() {
                    return Err(());
                }
                String::from_utf8_lossy(&out.stdout).split_whitespace().next().map(str::to_string).ok_or(())
            })
            .await
            .ok()
            .cloned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// A `claude` whose FIRST `--version` exits 1 (the marker file is created
    /// on that run) and which answers `2.1.278 (Claude Code)` on every later
    /// run — the VM-boot race the cache must survive.
    fn flaky_claude(dir: &Path) -> PathBuf {
        let marker = dir.join("probed");
        let script = dir.join("claude");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ -e '{m}' ]; then echo '2.1.278 (Claude Code)'; exit 0; fi\n: > '{m}'\nexit 1\n",
                m = marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[tokio::test]
    async fn failed_probe_is_retried_until_it_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let state = ShimState::new(flaky_claude(dir.path()));
        assert_eq!(state.health().await.claude_version, None, "first probe fails: null, not cached");
        assert_eq!(state.health().await.claude_version.as_deref(), Some("2.1.278"), "second probe succeeds");
        std::fs::remove_file(dir.path().join("claude")).unwrap();
        assert_eq!(state.health().await.claude_version.as_deref(), Some("2.1.278"), "cached: not probed again");
    }

    #[tokio::test]
    async fn missing_claude_is_null_every_time() {
        let state = ShimState::new(PathBuf::from("/nonexistent/claude"));
        assert_eq!(state.health().await.claude_version, None);
        assert_eq!(state.health().await.claude_version, None);
        assert_eq!(state.health().await.status, HealthStatus::Ok, "a missing claude does not fail /health");
    }
}
