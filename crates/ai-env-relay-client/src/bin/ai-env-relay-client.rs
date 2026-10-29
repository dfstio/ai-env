//! `ai-env-relay-client` (S13, plans/s13-contracts.md §V-vm): the relay client the shim starts as ai-env-net for one
//! relay spawn, its session on fd 3 alone. One subcommand, `serve` (`ai_env_relay_client::serve`).
use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// ai-env's relay client in the VM: serves one chat's relay session on a Unix socket
#[derive(Parser)]
#[command(name = "ai-env-relay-client", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the session on fd 3 to the leader's processes at --socket, until SIGTERM or the leader is gone
    Serve(ai_env_relay_client::serve::ServeArgs),
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Serve(args) => ai_env_relay_client::serve::main_serve(args),
    }
}
