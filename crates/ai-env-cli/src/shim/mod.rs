//! `ai-env shim` — the MicroVM image ENTRYPOINT (root, PID 1). S0 ships the
//! argument surface and the `/health` listener; hooks, the `/agent` socket and
//! the spawn manager arrive in later stages. Runs natively on the Mac for
//! tests.
pub mod health;

use crate::errors::{CliError, Result};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(clap::Args, Debug, Clone)]
pub struct ShimArgs {
    /// Application port: /health, /agent
    #[arg(long, default_value_t = 8080)]
    pub app_port: u16,
    /// Platform lifecycle hooks port
    #[arg(long, default_value_t = 9000)]
    pub hooks_port: u16,
    /// Code channel port: /seed, /bundle, git smart-HTTP
    #[arg(long, default_value_t = 9418)]
    pub code_port: u16,
    /// Path of the claude binary the shim spawns
    #[arg(long, value_name = "PATH")]
    pub claude: PathBuf,
    /// HOME of the agent user (mirrors the Mac)
    #[arg(long, default_value = "/Users/mike")]
    pub home: PathBuf,
    /// uid the agent runs as
    #[arg(long, default_value_t = 1000)]
    pub uid: u32,
    /// Echo mode for local transport tests
    #[arg(long)]
    pub echo: bool,
    /// Delay the /run hook response by S seconds (probe)
    #[arg(long, value_name = "S")]
    pub delay_run: Option<u64>,
}

/// Build the runtime and serve until SIGTERM/SIGINT.
pub fn run(args: ShimArgs) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Msg(format!("cannot start the shim runtime: {e}")))?;
    rt.block_on(serve(args))
}

async fn serve(args: ShimArgs) -> Result<()> {
    let state = Arc::new(health::ShimState::new(args.claude.clone()));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", args.app_port))
        .await
        .map_err(|e| CliError::Msg(format!("cannot bind app port {}: {e}", args.app_port)))?;
    eprintln!("ai-env: shim {} listening on {}", env!("CARGO_PKG_VERSION"), listener.local_addr()?);
    axum::serve(listener, health::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| CliError::Msg(format!("shim server error: {e}")))?;
    eprintln!("ai-env: shim stopped");
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
