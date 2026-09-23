//! `ai-env-claude` — Cursor's `claudeCode.claudeProcessWrapper` target,
//! exec'd as `<wrapper> <realBinary> <claude args…>`. `--version` is its only
//! other mode. In S1 every route execs the real binary locally with argv
//! verbatim (the remote route is a census label until the S2 pump), before
//! any tokio runtime, SDK or TLS object exists: this binary links only
//! `wire::argv`, `bridge::{route, census, lab, sibling, config}` and
//! `age_cmd`.
//!
//! The ORDER below is the invariant (plan §4 step 9): `--version` → kill
//! switch (raw exec, no census, no config read) → `argv::split` (exit 2 only
//! for a missing argv[1] or an argument that is not valid UTF-8 — Cursor's
//! argv comes from JS strings, so the latter never happens from the
//! extension; the kill switch execs raw bytes regardless) →
//! `route::load_for_wrapper` + `current_dir` → `route::decide` → notes
//! (`mcp add|remove`, missing cwd, lab knob, local fallback) → the binary
//! check, so the row can carry the fallback note → `census::record` (one
//! stderr line on failure, never blocking) → the lab exit knob (debug
//! builds) → exec. stderr lines are prefixed `ai-env-claude:` (the extension
//! shows the last 2 KiB of stderr only on a non-zero exit); stdout belongs to
//! Claude's stream-json.
use ai_env_cli::bridge::sibling::exists_exec;
use ai_env_cli::bridge::{census, lab, route};
use ai_env_cli::wire::argv::{self, ArgvError};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

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

/// `add` or `remove` when the invocation is `mcp add …` / `mcp remove …`:
/// the one subcommand whose effect (the Mac's `~/.claude.json`) a VM session
/// never sees, so it earns a stderr line and a census note.
fn mcp_verb(args: &[String]) -> Option<&str> {
    match args {
        [first, verb, ..] if first == "mcp" && (verb == "add" || verb == "remove") => Some(verb.as_str()),
        _ => None,
    }
}

/// The first executable `claude` in an ABSOLUTE entry of the PATH the
/// extension handed us — its login shell's PATH, taken literally: no Homebrew
/// directory appended, and an empty or relative entry (`.`, a trailing `:`)
/// never resolves to a file inside the workspace Cursor opened.
fn claude_on_path() -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    std::env::split_paths(&path_env).filter(|d| d.is_absolute()).map(|d| d.join("claude")).find(|p| exists_exec(p) == (true, true))
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if argv.len() == 2 && matches!(argv[1].to_str(), Some("--version" | "-V")) {
        println!("ai-env-claude {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Kill switch: plain Cursor, no AWS, no runtime, no census, no config
    // read. Checked BEFORE the UTF-8 split so argv reaches the real binary
    // byte-for-byte, non-UTF-8 included.
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
    let loaded = route::load_for_wrapper();
    let cwd = std::env::current_dir().ok();
    let route = route::decide(&inv.args, cwd.as_deref(), loaded.cfg.as_ref());

    // Notes for the census row, joined by "; ".
    let mut notes: Vec<String> = Vec::new();
    if let Some(n) = &loaded.note {
        notes.push(n.clone());
    }
    if let Some(verb) = mcp_verb(&inv.args) {
        eprintln!("ai-env-claude: mcp {verb} edits the Mac's ~/.claude.json; VM sessions see committed .mcp.json");
        notes.push(format!("mcp {verb} edits the Mac's ~/.claude.json"));
    }
    if cwd.is_none() {
        notes.push("cwd unavailable".to_string());
    }
    let knob = lab::exit_knob();
    if let Some((code, _)) = &knob {
        notes.push(format!("lab_exit:{code}"));
    }

    // The binary check comes before the census so the row carries the
    // fallback note; a failure is remembered and reported after the row.
    // A bare name (`claude`, no path separator) would be checked against the
    // cwd but exec'd through PATH: treat it as "not found" so the fallback
    // lookup decides, and the file checked is the file exec'd.
    let bare_name = inv.real_binary.components().count() == 1 && !inv.real_binary.is_absolute();
    let (exists, exec) = exists_exec(&inv.real_binary);
    let bin: Result<PathBuf, String> = if exists && exec && !bare_name {
        Ok(inv.real_binary.clone())
    } else {
        // "claude on PATH" means the PATH the extension handed us (its login
        // shell's), literally — no Homebrew directories appended, and only
        // absolute entries: an empty or `.` entry would resolve inside the
        // workspace Cursor opened.
        let fallback_allowed = loaded.cfg.as_ref().is_none_or(|c| c.wrapper.local_fallback);
        match fallback_allowed.then(claude_on_path).flatten() {
            Some(p) => {
                eprintln!("ai-env-claude: {} is not executable; using claude on PATH ({})", inv.real_binary.display(), p.display());
                notes.push(format!("local_fallback:{}", p.display()));
                Ok(p)
            }
            None => Err(format!("cannot exec {}: not executable (local_fallback off or no claude on PATH)", inv.real_binary.display())),
        }
    };

    // The census: one redacted row, never blocking the exec.
    let note = if notes.is_empty() { None } else { Some(notes.join("; ")) };
    match &loaded.paths {
        Some(paths) => {
            if let Err(e) = census::record(&paths.census(), &census::build_row(&argv, &route, cwd.as_deref(), note)) {
                eprintln!("ai-env-claude: census: {e}");
            }
        }
        None => eprintln!("ai-env-claude: census: HOME is not set"),
    }

    // Lab knob (debug builds only): raw message, no prefix, so Cursor's error
    // reads exactly `… exited with code 3. stderr: boom`.
    if let Some((code, msg)) = knob {
        eprintln!("{msg}");
        std::process::exit(code);
    }

    match bin {
        Ok(bin) => exec_local(&bin, &inv.args),
        Err(msg) => fail(1, &msg),
    }
}
