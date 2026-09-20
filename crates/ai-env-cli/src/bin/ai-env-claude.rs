//! `ai-env-claude` — Cursor's `claudeCode.claudeProcessWrapper` target,
//! exec'd as `<wrapper> <realBinary> <claude args…>`. `--version` is its only
//! other mode. In S0 every route execs the real binary locally, before any
//! tokio runtime, SDK or TLS object exists; the remote route is stubbed until
//! the pump and transport stages land. stderr lines are prefixed
//! `ai-env-claude:`; stdout belongs to Claude's stream-json.
use ai_env_cli::wire::argv::{self, ArgvError, Route};
use std::ffi::{OsStr, OsString};
use std::path::Path;

const USAGE: &str = "(usage: ai-env-claude <realBinary> <claude args…> | --version)";

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("ai-env-claude: {msg}");
    std::process::exit(code)
}

/// Replace this process with the real binary; the environment passes through
/// untouched (the extension's env is the contract for a local child). Generic
/// over the argument type so the kill switch can pass raw `OsString`s through.
fn exec_local<S: AsRef<OsStr>>(bin: &Path, args: &[S]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(bin).args(args).exec();
    fail(1, &format!("cannot exec {}: {err}", bin.display()))
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if argv.len() == 2 && matches!(argv[1].to_str(), Some("--version" | "-V")) {
        println!("ai-env-claude {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Kill switch: plain Cursor, no AWS, no runtime. Checked BEFORE the UTF-8
    // split so argv reaches the real binary byte-for-byte, non-UTF-8 included.
    if std::env::var_os("AI_ENV_BRIDGE_LOCAL").is_some_and(|v| v == "1") {
        match argv.get(1) {
            Some(real) => exec_local(Path::new(real), &argv[2..]),
            None => fail(2, &format!("{}  {USAGE}", ArgvError::MissingRealBinary)),
        }
    }
    let inv = match argv::split(&argv) {
        Ok(i) => i,
        Err(e) => fail(2, &format!("{e}  {USAGE}")),
    };
    match argv::classify(&inv.args) {
        Route::Local(_) => exec_local(&inv.real_binary, &inv.args),
        Route::Remote(_) => {
            eprintln!("ai-env-claude: remote route not implemented (S2/S6); running locally");
            exec_local(&inv.real_binary, &inv.args)
        }
    }
}
