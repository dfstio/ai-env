//! `ai-env` — operator CLI on the Mac and, built with `--features shim`, the
//! VM image ENTRYPOINT. All behaviour lives in the `ai_env_cli` library.
use clap::Parser;

fn main() {
    let cli = ai_env_cli::cli::Cli::parse();
    ai_env_cli::errors::exit_on_error("ai-env", ai_env_cli::cli::run(cli));
}
