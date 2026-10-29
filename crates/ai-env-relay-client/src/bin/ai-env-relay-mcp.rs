//! `ai-env-relay-mcp` (S13, plans/s13-contracts.md §V-vm): the stdio MCP server claude starts from the image's
//! `/etc/ai-env/relay-mcp.json`; stdin and stdout are the transport (`ai_env_relay_client::mcp`). It writes nothing
//! to stderr but one `ai-env-relay-mcp: <error>` line before an exit 1.
use ai_env_relay_client::mcp::{run, Discovery};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// ai-env's relay tools for claude (relay_catalog, relay_call), over stdio
#[derive(Parser)]
#[command(name = "ai-env-relay-mcp", version)]
struct Cli {
    /// Look for the chat's socket in this directory (tests)
    #[arg(long, value_name = "DIR", hide = true, conflicts_with = "socket")]
    socket_dir: Option<PathBuf>,
    /// Use this socket, with no discovery (tests)
    #[arg(long, value_name = "PATH", hide = true)]
    socket: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let discovery = match cli.socket {
        Some(path) => Discovery::Socket(path),
        None => Discovery::Ancestry { dir: cli.socket_dir.unwrap_or_else(|| PathBuf::from(ai_env_relay_client::local::SOCKET_DIR)) },
    };
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("ai-env-relay-mcp: cannot start the runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let code = rt.block_on(async {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ai-env-relay-mcp: cannot handle SIGTERM: {e}");
                return ExitCode::from(1);
            }
        };
        tokio::select! {
            r = run(tokio::io::stdin(), tokio::io::stdout(), discovery) => match r {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("ai-env-relay-mcp: {e}");
                    ExitCode::from(1)
                }
            },
            // LD-V17: the calls in flight are dropped (their connections close with them).
            _ = term.recv() => ExitCode::SUCCESS,
        }
    });
    // stdin's blocking read cannot be cancelled: never wait for it.
    rt.shutdown_background();
    code
}
