//! The invocation census: one redacted JSON line per wrapper invocation in
//! `<bridge root>/logs/census.jsonl` (dir 0700, file 0600, `O_NOFOLLOW`,
//! one `write` per row so concurrent wrappers never interleave). Names of
//! environment variables are always recorded; VALUES only for the
//! hard-coded allowlist below, and every recorded string passes
//! `wire::redact::scrub`. The census is the stage-S1 instrument: fixtures
//! under `tests/fixtures/argv/` are captured from it.
use crate::bridge::doctor::bundle_version;
use crate::bridge::errors::BridgeError;
use crate::bridge::logging::open_log_file;
use crate::wire::argv::Route;
use crate::wire::redact::scrub;
use crate::wire::time::{rfc3339_utc, unix_now_ms};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

pub const CENSUS_SCHEMA_V: u8 = 1;

/// A row larger than this is refused (never written piecemeal).
pub const MAX_ROW_BYTES: usize = 64 * 1024;

/// The only environment variables whose VALUE the census records; every name
/// here is a fingerprint of the launcher, never a credential (a unit test
/// keeps `TOKEN|KEY|SECRET|PASSWORD|AUTH|CREDENTIAL` out of this list).
/// Presence or absence of anything else (`CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH`,
/// `CLAUDECODE`, `NODE_OPTIONS`) is read from `env_names` — so is S7's
/// `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS`, kept out by that rule: what it
/// found is the end row's `synthetic_oauth:` part.
pub const CENSUS_VALUE_ALLOWLIST: [&str; 21] = [
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
    "MCP_CONNECTION_NONBLOCKING",
    "CLAUDE_CODE_ENABLE_TASKS",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_RESUME_INTERRUPTED_TURN",
    "CLAUDE_CODE_RESUME_INTERRUPTED_TURN_MAX_AGE_MS",
    "DEBUG",
    "DEBUG_CLAUDE_AGENT_SDK",
    "LANG",
    "TERM",
    "AI_ENV_BRIDGE_LAB_EXIT",
    // S2: the pump mode, the mirror root and the pump-stage lab knobs.
    "AI_ENV_BRIDGE_MODE",
    "AI_ENV_BRIDGE_MIRROR_ROOT",
    "AI_ENV_BRIDGE_LAB_IGNORE_EOF",
    "AI_ENV_BRIDGE_LAB_STDOUT_NOISE",
    "AI_ENV_BRIDGE_LAB_DELAY_INIT_MS",
    "AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS",
    // S7: the local-scratch unseal's budget (the row then explains a timeout note).
    "AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS",
    // S8: the remote session's transcript knob (`skip`, the forced resume miss: the row then explains a retry).
    "AI_ENV_BRIDGE_LAB_TRANSCRIPT",
];

/// One census line. `end`/`exit` are absent on the start row of every
/// invocation; the S2 pump appends a second row for a piped session (a clone
/// of the start row with `end`, `exit` and an extended `note`), paired on
/// `(pid, start)`. An exec'd invocation has only the start row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusRow {
    pub v: u8,
    /// RFC 3339 seconds, for humans.
    pub ts: String,
    /// Unix milliseconds, for measuring the extension's teardown gaps.
    pub start: u64,
    /// The wrapper, which becomes the claude process after exec.
    pub pid: u32,
    /// Cursor's extension host: groups rows per window.
    pub ppid: u32,
    /// Bundle version parsed from argv[1]'s path (`2.1.278`), if any.
    pub ext: Option<String>,
    /// `local` or `remote`.
    pub route: String,
    /// `LocalReason::name()` or `session`.
    pub reason: String,
    /// The full `args_os()` incl. argv[0] and argv[1], redacted.
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Sorted, deduplicated names — never values.
    pub env_names: Vec<String>,
    /// Values for `CENSUS_VALUE_ALLOWLIST` names only, each scrubbed.
    pub env_selected: BTreeMap<String, String>,
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
}

/// The row for one invocation, read from the clock, the process and the
/// environment: `argv` goes through [`redact_argv`], `ext` comes from
/// argv[1]'s path, `env_names` holds every variable name (sorted, deduped)
/// and `env_selected` the scrubbed values of the allowlisted names only.
/// `ts` and `start` come from the same clock read, so they never disagree.
#[must_use]
pub fn build_row(argv: &[OsString], route: &Route, cwd: Option<&Path>, note: Option<String>) -> CensusRow {
    let (route_name, reason) = match route {
        Route::Local(r) => ("local", r.name()),
        Route::Remote(_) => ("remote", "session".to_string()),
    };
    let lossy: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    let mut env_names: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
    env_names.sort();
    env_names.dedup();
    let env_selected = CENSUS_VALUE_ALLOWLIST
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|v| ((*name).to_string(), scrub(&v.to_string_lossy()).into_owned())))
        .collect();
    let start = unix_now_ms();
    CensusRow {
        v: CENSUS_SCHEMA_V,
        ts: rfc3339_utc(start / 1000),
        start,
        pid: std::process::id(),
        ppid: parent_pid(),
        ext: ext_version_from_real_binary(argv.get(1)),
        route: route_name.to_string(),
        reason,
        argv: redact_argv(&lossy),
        cwd: cwd.map(|p| scrub(&p.to_string_lossy()).into_owned()),
        env_names,
        env_selected,
        // Notes carry error texts and paths: scrubbed like every other string.
        note: note.map(|n| scrub(&n).into_owned()),
        end: None,
        exit: None,
    }
}

#[cfg(unix)]
fn parent_pid() -> u32 {
    // SAFETY: getppid(2) takes no arguments, touches no memory and cannot fail.
    let ppid = unsafe { libc::getppid() };
    u32::try_from(ppid).unwrap_or(0)
}

#[cfg(not(unix))]
fn parent_pid() -> u32 {
    0
}

/// What the next token is the value of (rules 1 and 3 of [`redact_argv`],
/// and S10 F7's thinking budget).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Nothing,
    Env,
    Header,
    McpConfig,
    ThinkingBudget,
}

/// The value of `--flag=value` when `tok` has that shape.
fn joined_value<'a>(tok: &'a str, flag: &str) -> Option<&'a str> {
    tok.strip_prefix(flag).and_then(|rest| rest.strip_prefix('='))
}

/// The redaction policy for a census `argv` (the full `args_os()`, so
/// argv[0] is the wrapper and argv[1] the real binary; both are paths and
/// only rule 4 touches them). Rules, in order over the remaining tokens:
///
/// 1. the token after `--env` (or `-e`, or the `--env=` form) becomes
///    `NAME=[redacted:len=N]`, `NAME` being the part before the first `=`
///    and `N` the byte length of the value (`[redacted:len=N]` for a token
///    without `=`); the token after `--header` (or `-H`, `--header=`) keeps
///    the header name before the first `:` and masks the rest as
///    `NAME: [redacted:len=N]` (`N` = the value without its leading blanks;
///    no `:` → the whole token is masked);
/// 2. after a bare `--` only the first positional (the MCP server name) is
///    kept and every remaining token becomes one `…` token — the
///    extension's own scrubber policy, because commands, arguments and
///    URLs may carry credentials;
/// 3. a `--mcp-config <json>` value (also `--mcp-config=<json>`) collapses
///    to `{"mcpServers":["name1","name2"]}` (sorted server names only), or
///    `[mcp-config:len=N]` when it does not parse as JSON;
/// 4. every token passes through `wire::redact::scrub` (`sk-ant-` tokens,
///    long `eyJ` tokens, registered values, key-shaped assignments). For a
///    token rules 1–3 rewrote, the user-supplied fragments (the env name,
///    the header name, the server names) are what gets scrubbed and the
///    placeholder is appended afterwards: scrubbing the finished token
///    would mask the placeholder a second time (`GITHUB_TOKEN=[…]` is
///    key-shaped) and lose the recorded length. Likewise the panel's
///    thinking budget (S10 F7): `--max-thinking-tokens=` with 1 to 7 digits
///    is a number, never a credential, so only its value is scrubbed (the
///    whole token is key-shaped, `token` being a key name, and would lose
///    the number); any other value of it is masked whole,
///    `--max-thinking-tokens=[redacted:len=N]` (`scrub` would stop at a `,`,
///    `}` or `"` and keep the rest), and an empty one is left as it is. The
///    token after `--max-thinking-tokens` (2.1.278's spelling, which the
///    router reads as its value too) follows the same rule, a bare `--` or
///    a flag of rules 1 and 3 (`--env`, `-e`, `--header`, `-H`,
///    `--mcp-config`) never being its value (those rules hold).
#[must_use]
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut pending = Pending::Nothing;
    for (i, tok) in argv.iter().enumerate() {
        if i < 2 {
            out.push(scrub(tok).into_owned());
            continue;
        }
        match pending {
            Pending::Env => out.push(mask_env(tok)),
            Pending::Header => out.push(mask_header(tok)),
            Pending::McpConfig => out.push(mask_mcp_config(tok)),
            Pending::ThinkingBudget if !matches!(tok.as_str(), "--" | "--env" | "-e" | "--header" | "-H" | "--mcp-config") => out.push(mask_thinking_budget(tok)),
            Pending::Nothing | Pending::ThinkingBudget => {
                if tok == "--" {
                    out.push("--".to_string());
                    let rest = &argv[i + 1..];
                    if let Some(name) = rest.first() {
                        out.push(scrub(name).into_owned());
                        if rest.len() > 1 {
                            out.push("\u{2026}".to_string());
                        }
                    }
                    break;
                }
                if let Some(v) = joined_value(tok, "--env") {
                    out.push(format!("--env={}", mask_env(v)));
                } else if let Some(v) = joined_value(tok, "--header") {
                    out.push(format!("--header={}", mask_header(v)));
                } else if let Some(v) = joined_value(tok, "--mcp-config") {
                    out.push(format!("--mcp-config={}", mask_mcp_config(v)));
                } else if let Some(v) = joined_value(tok, "--max-thinking-tokens") {
                    out.push(format!("--max-thinking-tokens={}", mask_thinking_budget(v)));
                } else {
                    pending = match tok.as_str() {
                        "--env" | "-e" => Pending::Env,
                        "--header" | "-H" => Pending::Header,
                        "--mcp-config" => Pending::McpConfig,
                        "--max-thinking-tokens" => Pending::ThinkingBudget,
                        _ => Pending::Nothing,
                    };
                    out.push(scrub(tok).into_owned());
                }
                continue;
            }
        }
        pending = Pending::Nothing;
    }
    out
}

/// A thinking budget as the extension writes it (`31999`): 1 to 7 ASCII
/// digits (S10 F7).
fn is_thinking_budget(value: &str) -> bool {
    (1..=7).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

/// A thinking budget's value in the census (S10 F7): 1 to 7 digits kept
/// (scrubbed only), an empty one left as it is, anything else
/// `[redacted:len=N]`.
fn mask_thinking_budget(value: &str) -> String {
    if value.is_empty() || is_thinking_budget(value) {
        scrub(value).into_owned()
    } else {
        format!("[redacted:len={}]", value.len())
    }
}

/// `NAME=value` → `NAME=[redacted:len=N]`; no `=` → `[redacted:len=N]`.
fn mask_env(tok: &str) -> String {
    match tok.split_once('=') {
        Some((name, value)) => format!("{}=[redacted:len={}]", scrub(name), value.len()),
        None => format!("[redacted:len={}]", tok.len()),
    }
}

/// `Name: value` → `Name: [redacted:len=N]`; no `:` → `[redacted:len=N]`.
fn mask_header(tok: &str) -> String {
    match tok.split_once(':') {
        Some((name, rest)) => format!("{}: [redacted:len={}]", scrub(name), rest.trim_start().len()),
        None => format!("[redacted:len={}]", tok.len()),
    }
}

/// An `--mcp-config` value → `{"mcpServers":[<sorted names>]}`, or
/// `[mcp-config:len=N]` when it is not JSON (a file path, say).
fn mask_mcp_config(value: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(value) {
        Ok(json) => {
            let mut names: Vec<String> = json
                .get("mcpServers")
                .and_then(serde_json::Value::as_object)
                .map(|servers| servers.keys().map(|k| scrub(k).into_owned()).collect())
                .unwrap_or_default();
            names.sort();
            serde_json::json!({ "mcpServers": names }).to_string()
        }
        Err(_) => format!("[mcp-config:len={}]", value.len()),
    }
}

/// The bundle version in the real binary's path
/// (`…/anthropic.claude-code-2.1.278-darwin-arm64/resources/native-binary/claude`
/// → `2.1.278`): the first path component `doctor::bundle_version` accepts.
/// `None` for a binary outside a bundle (`/opt/homebrew/bin/claude`).
#[must_use]
pub fn ext_version_from_real_binary(real: Option<&OsString>) -> Option<String> {
    Path::new(real?).components().find_map(|c| bundle_version(&c.as_os_str().to_string_lossy()))
}

/// Append one row as `<json>\n` with a single `write` on the file
/// `logging::open_log_file` opens (0700 dir, 0600 file, `O_APPEND`,
/// `O_NOFOLLOW`): `O_APPEND` makes one write atomic between appenders on a
/// regular file, so a short write is an error and never completed later —
/// a partial row must not be finished by a second write that could land
/// after another wrapper's row. A row over [`MAX_ROW_BYTES`] is refused
/// before the file is touched.
pub fn record(path: &Path, row: &CensusRow) -> Result<(), BridgeError> {
    let mut line = serde_json::to_vec(row).map_err(|e| BridgeError::Config(format!("census row: {e}")))?;
    line.push(b'\n');
    if line.len() > MAX_ROW_BYTES {
        return Err(BridgeError::Config(format!("census row too large: {} bytes", line.len())));
    }
    let mut file = open_log_file(path)?;
    let written = file.write(&line)?;
    if written != line.len() {
        return Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!("short census write: {written} of {} bytes", line.len()),
        )));
    }
    Ok(())
}

/// `path` opened for reading as the writer guards its file
/// (`logging::open_log_file`: `O_NOFOLLOW`, then a regular file on the
/// descriptor), and `O_NONBLOCK`: a symlink, a FIFO, a directory or any
/// other non-regular file is an error naming the path, never followed or
/// waited on. `None` when there is no file. [`read_rows`] and [`read_tail`]
/// open with it, so every reader of the census, the audit and the probe
/// rows does.
pub fn open_for_read(path: &Path) -> Result<Option<std::fs::File>, BridgeError> {
    use std::os::unix::fs::OpenOptionsExt;
    let opened = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(BridgeError::Config(format!("{} is a symlink; refusing to read it", path.display()))),
        Err(e) => return Err(BridgeError::Io(e)),
    };
    if !file.metadata()?.is_file() {
        return Err(BridgeError::Config(format!("{} is not a regular file", path.display())));
    }
    Ok(Some(file))
}

/// Every parseable row (oldest first), or the last `last` of them. A missing
/// file is an empty census; unparseable lines (one that is not UTF-8
/// included) are skipped, never fatal. Opened by [`open_for_read`].
pub fn read_rows(path: &Path, last: Option<usize>) -> Result<Vec<serde_json::Value>, BridgeError> {
    use std::io::Read;
    let Some(mut file) = open_for_read(path)? else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut rows: Vec<serde_json::Value> = bytes.split(|b| *b == b'\n').filter_map(|l| serde_json::from_slice(l).ok()).collect();
    if let Some(n) = last {
        let skip = rows.len().saturating_sub(n);
        rows.drain(..skip);
    }
    Ok(rows)
}

/// The parseable rows of the census's last `chunks` × [`MAX_ROW_BYTES`]
/// bytes (oldest first), for a reader that must not read the whole file (the
/// census is never rotated): it seeks back that far, plus one byte that says
/// whether a line starts there, and reads no further than the length it saw
/// first. A line the window cuts is dropped, so every row is whole, and the
/// last `chunks` rows are always among them (no row is longer than
/// [`MAX_ROW_BYTES`]). A missing file is an empty census; unparseable lines,
/// a partial last line among them, are skipped. Opened by [`open_for_read`]:
/// a symlink, a FIFO or any other non-regular file is an error naming the
/// path, never followed or waited on.
pub fn read_tail(path: &Path, chunks: usize) -> Result<Vec<serde_json::Value>, BridgeError> {
    use std::io::{Read, Seek, SeekFrom};
    let Some(mut file) = open_for_read(path)? else {
        return Ok(Vec::new());
    };
    let len = file.metadata()?.len();
    let window = u64::try_from(chunks).unwrap_or(u64::MAX).saturating_mul(MAX_ROW_BYTES as u64);
    let start = len.saturating_sub(window.saturating_add(1));
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.take(len - start).read_to_end(&mut buf)?;
    // From the start of the file every line is whole; else the first one is
    // whole only when the byte before the window ends a line.
    let whole = if start == 0 { &buf[..] } else { buf.iter().position(|b| *b == b'\n').map_or(&[][..], |i| &buf[i + 1..]) };
    Ok(whole.split(|b| *b == b'\n').filter_map(|l| serde_json::from_slice(l).ok()).collect())
}

/// What a row's `ext` is printed as when it is not in the shape the census
/// writes (a version): only the wrapper writes the census, but nothing
/// stops another hand.
pub const UNRECOGNISED_EXT: &str = "unrecognised";

/// One Cursor window whose extension host still runs, as the census shows
/// it ([`running_extensions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningExtension {
    /// The window's extension host: its rows' `ppid`.
    pub host: u32,
    /// The extension version its newest row names (`ext`); [`UNRECOGNISED_EXT`]
    /// when that value is not a version's shape (1 to 32 characters of
    /// `[0-9A-Za-z.+-]`).
    pub ext: String,
    /// When the host started (unix seconds), as the system says.
    pub started: u64,
    /// That newest row's `start` (unix ms).
    pub seen: u64,
}

/// The extension each Cursor window runs now, from the census `rows` (as
/// [`read_tail`] returns them): the rows grouped by `ppid`, the window's
/// extension host, and each host's newest row that names an extension (by
/// `start`; of equal ones the later in the file). A host counts while
/// `identity` (`registry::process_identity`: its executable's name and
/// when it started, unix seconds; `None` when it is gone) shows it started
/// no later than that row: a pid the system gave a later process never
/// counts, and a window keeps the extension it loaded until a reload starts
/// a new host. A row without `ppid`, `start` or `ext`, or whose `ppid` is
/// 0 or 1 (no window), is skipped. Sorted by when each host started, then
/// its pid.
#[must_use]
pub fn running_extensions(rows: &[serde_json::Value], identity: &dyn Fn(u32) -> Option<(String, u64)>) -> Vec<RunningExtension> {
    let mut newest: BTreeMap<u32, (u64, &str)> = BTreeMap::new();
    for row in rows {
        let host = row.get("ppid").and_then(serde_json::Value::as_u64).and_then(|p| u32::try_from(p).ok()).filter(|p| *p > 1);
        let (Some(host), Some(start), Some(ext)) = (host, row.get("start").and_then(serde_json::Value::as_u64), row.get("ext").and_then(serde_json::Value::as_str)) else {
            continue;
        };
        let seen = newest.entry(host).or_insert((start, ext));
        if start >= seen.0 {
            *seen = (start, ext);
        }
    }
    let shaped = |ext: &str| !ext.is_empty() && ext.len() <= 32 && ext.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-'));
    let mut out: Vec<RunningExtension> = newest
        .into_iter()
        .filter_map(|(host, (seen, ext))| {
            let (_, started) = identity(host)?;
            (started.saturating_mul(1000) <= seen).then(|| RunningExtension { host, ext: if shaped(ext) { ext.to_string() } else { UNRECOGNISED_EXT.to_string() }, started, seen })
        })
        .collect();
    out.sort_by_key(|w| (w.started, w.host));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::argv::classify;

    const WRAPPER: &str = "/Users/mike/.cargo/bin/ai-env-claude";
    const BUNDLED: &str = "/Users/mike/.cursor/extensions/anthropic.claude-code-2.1.278-darwin-arm64/resources/native-binary/claude";

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// The `argv` array of a fixture under `tests/fixtures/argv/`.
    fn fixture_argv(text: &str) -> Vec<String> {
        let j: serde_json::Value = serde_json::from_str(text).unwrap();
        j["argv"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    }

    fn row_with_note(note: &str) -> CensusRow {
        let argv: Vec<OsString> = [WRAPPER, BUNDLED, "auth", "status", "--json"].iter().map(OsString::from).collect();
        build_row(&argv, &classify(&v(&["auth", "status", "--json"])), Some(Path::new("/Users/mike/Documents/DeFi/ai-env")), Some(note.to_string()))
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn note_and_cwd_are_scrubbed() {
        let token = format!("{}oat01-{}", "sk-ant-", "Y".repeat(20));
        let argv = [OsString::from("w"), OsString::from("/b/claude"), OsString::from("--version")];
        let cwd = std::path::PathBuf::from(format!("/ws/{token}"));
        let row = build_row(&argv, &Route::Local(crate::wire::argv::LocalReason::Version), Some(&cwd), Some(format!("config: bridge.toml: bad {token}")));
        let masked = format!("sk-ant-[redacted:len={}]", token.len());
        assert_eq!(row.cwd.as_deref(), Some(format!("/ws/{masked}").as_str()));
        assert_eq!(row.note.as_deref(), Some(format!("config: bridge.toml: bad {masked}").as_str()));
        let line = serde_json::to_string(&row).unwrap();
        assert!(!line.contains(&token), "{line}");
    }

    #[test]
    fn allowlist_never_names_a_credential() {
        for name in CENSUS_VALUE_ALLOWLIST {
            let upper = name.to_ascii_uppercase();
            for word in ["TOKEN", "KEY", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL"] {
                assert!(!upper.contains(word), "{name} contains {word}");
            }
        }
    }

    #[test]
    fn mcp_add_stdio_masks_env_and_drops_the_tail() {
        let xs = "x".repeat(40);
        let api_key = format!("k-{}", "y".repeat(24));
        let argv = v(&[
            "w", "/b/claude", "mcp", "add", "--scope", "user", "--transport", "stdio",
            "--env", &format!("GITHUB_TOKEN={xs}"),
            "--", "github", "npx", "-y", "@x/server", "--api-key", &api_key,
        ]);
        let got = redact_argv(&argv);
        assert_eq!(got, v(&["w", "/b/claude", "mcp", "add", "--scope", "user", "--transport", "stdio", "--env", "GITHUB_TOKEN=[redacted:len=40]", "--", "github", "\u{2026}"]));
        let joined = got.join(" ");
        assert!(!joined.contains(&xs) && !joined.contains(&api_key), "{joined}");
        let fixture = fixture_argv(include_str!("../../tests/fixtures/argv/mcp_add.json"));
        assert_eq!(got[2..], fixture[..], "the fixture is the census-redacted form");
    }

    #[test]
    fn mcp_add_http_keeps_header_name_and_server_name_only() {
        let tok = format!("t-{}", "z".repeat(30));
        let header = format!("Authorization: Bearer {tok}");
        let argv = v(&["w", "/b/claude", "mcp", "add", "--scope", "user", "--transport", "http", "--header", &header, "--", "github", "https://mcp.example.test/sse?k=1"]);
        let got = redact_argv(&argv);
        let n = format!("Bearer {tok}").len();
        assert_eq!(got, v(&["w", "/b/claude", "mcp", "add", "--scope", "user", "--transport", "http", "--header", &format!("Authorization: [redacted:len={n}]"), "--", "github", "\u{2026}"]));
        assert!(!got.join(" ").contains(&tok));
    }

    #[test]
    fn env_and_header_alternate_forms() {
        let secret = "s".repeat(16);
        // `--env=K=V`, `-e K=V`, a value without `=`, `--header=`, `-H`, a header without `:`.
        let argv = v(&[
            "w", "/b/claude", "mcp", "add",
            &format!("--env=A={secret}"), "-e", &format!("B={secret}"), "--env", &secret,
            &format!("--header=X-Api: {secret}"), "-H", &secret,
            "--", "name",
        ]);
        let got = redact_argv(&argv);
        assert_eq!(got, v(&[
            "w", "/b/claude", "mcp", "add",
            "--env=A=[redacted:len=16]", "-e", "B=[redacted:len=16]", "--env", "[redacted:len=16]",
            "--header=X-Api: [redacted:len=16]", "-H", "[redacted:len=16]",
            "--", "name",
        ]));
        assert!(!got.join(" ").contains(&secret));
        // `mcp remove -- name`: nothing after the name, so no `…`.
        let remove = fixture_argv(include_str!("../../tests/fixtures/argv/mcp_remove.json"));
        let mut full = v(&["w", "/b/claude"]);
        full.extend(remove.iter().cloned());
        assert_eq!(redact_argv(&full)[2..], remove[..]);
        // A trailing `--env` with no value is left as it is.
        assert_eq!(redact_argv(&v(&["w", "/b/claude", "mcp", "add", "--env"])), v(&["w", "/b/claude", "mcp", "add", "--env"]));
    }

    #[test]
    fn mcp_config_collapses_to_sorted_server_names() {
        let cfg = r#"{"mcpServers":{"zeta":{"command":"npx","args":["-y","@x/y"]},"alpha":{"type":"http","url":"https://x.test/mcp?k=1"}}}"#;
        let spaced = redact_argv(&v(&["w", "/b/claude", "--output-format", "stream-json", "--mcp-config", cfg, "--verbose"]));
        assert_eq!(spaced, v(&["w", "/b/claude", "--output-format", "stream-json", "--mcp-config", r#"{"mcpServers":["alpha","zeta"]}"#, "--verbose"]));
        let joined = redact_argv(&v(&["w", "/b/claude", &format!("--mcp-config={cfg}"), "--verbose"]));
        assert_eq!(joined, v(&["w", "/b/claude", r#"--mcp-config={"mcpServers":["alpha","zeta"]}"#, "--verbose"]));
        let path = redact_argv(&v(&["w", "/b/claude", "--mcp-config", "/tmp/mcp.json"]));
        assert_eq!(path, v(&["w", "/b/claude", "--mcp-config", "[mcp-config:len=13]"]));
        let empty = redact_argv(&v(&["w", "/b/claude", "--mcp-config", "{}"]));
        assert_eq!(empty[3], r#"{"mcpServers":[]}"#);
        // The Chrome MCP session fixture collapses to the one bundled server.
        let chrome = fixture_argv(include_str!("../../tests/fixtures/argv/session_chrome_mcp.json"));
        let mut full = v(&[WRAPPER, BUNDLED]);
        full.extend(chrome.iter().cloned());
        let got = redact_argv(&full);
        let i = got.iter().position(|t| t == "--mcp-config").unwrap();
        assert_eq!(got[i + 1], r#"{"mcpServers":["claude-in-chrome"]}"#);
        assert_eq!(got.len(), full.len());
    }

    #[test]
    fn sk_ant_tokens_are_masked_anywhere() {
        let tok = format!("sk-ant-oat01-{}", "X".repeat(20));
        let got = redact_argv(&v(&[&format!("/w/{tok}"), "/b/claude", "--print", &tok, &format!("--resume={tok}")]));
        assert!(!got.join(" ").contains(&tok), "{got:?}");
        assert_eq!(got[3], "sk-ant-[redacted:len=33]");
        assert_eq!(got[0], "/w/sk-ant-[redacted:len=33]", "argv[0] gets rule 4 too");
        assert_eq!(got[4], "--resume=sk-ant-[redacted:len=33]");
    }

    /// S10 F7: the panel's thinking budget is a number, never a credential:
    /// a `--max-thinking-tokens=` of 1 to 7 digits is kept as written
    /// (`scrub` alone masks it, `token` being a key name); any other value is
    /// masked whole (a letter in it, a sign, 8 digits or more, a token, or a
    /// `,`, `}` or `"` that `scrub` would stop at, keeping what follows), an
    /// empty one is left as it is; the space-separated form (2.1.278's, the
    /// value the next token, as the router reads it) follows the same rule,
    /// and a bare `--` is never its value. The three session fixtures are
    /// the census's form of a 2.1.303 chat: their budget reads 31999, and
    /// the census writes them as they are.
    #[test]
    fn a_digits_only_thinking_budget_is_kept_and_anything_else_masked() {
        let one = |tok: &str| redact_argv(&v(&["w", "/b/claude", tok])).remove(2);
        for kept in ["--max-thinking-tokens=31999", "--max-thinking-tokens=0", "--max-thinking-tokens=1234567", "--max-thinking-tokens="] {
            assert_eq!(one(kept), kept);
        }
        let tok = format!("{}oat01-{}", "sk-ant-", "Q".repeat(20));
        for (given, want) in [
            ("--max-thinking-tokens=12a".to_string(), "--max-thinking-tokens=[redacted:len=3]".to_string()),
            ("--max-thinking-tokens=-1".to_string(), "--max-thinking-tokens=[redacted:len=2]".to_string()),
            ("--max-thinking-tokens=12345678".to_string(), "--max-thinking-tokens=[redacted:len=8]".to_string()),
            ("--max-thinking-tokens=３１９９９".to_string(), "--max-thinking-tokens=[redacted:len=15]".to_string()),
            (format!("--max-thinking-tokens={tok}"), format!("--max-thinking-tokens=[redacted:len={}]", tok.len())),
            ("--max-thinking-tokens==1".to_string(), "--max-thinking-tokens=[redacted:len=2]".to_string()),
            ("--max-thinking-tokens=1,2345678".to_string(), "--max-thinking-tokens=[redacted:len=9]".to_string()),
            ("--max-thinking-tokens=31999,--x=y".to_string(), "--max-thinking-tokens=[redacted:len=11]".to_string()),
            ("--max-thinking-tokens=1\"abc".to_string(), "--max-thinking-tokens=[redacted:len=5]".to_string()),
            ("--max-thinking-tokens=1}x".to_string(), "--max-thinking-tokens=[redacted:len=3]".to_string()),
        ] {
            assert_eq!(one(&given), want, "{given}");
        }
        assert_eq!(redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", "31999"]))[2..], v(&["--max-thinking-tokens", "31999"]), "2.1.278's spelling");
        for (given, want) in [
            ("12345678".to_string(), "[redacted:len=8]".to_string()),
            ("-1".to_string(), "[redacted:len=2]".to_string()),
            ("hunter2".to_string(), "[redacted:len=7]".to_string()),
            ("1,--x=y".to_string(), "[redacted:len=7]".to_string()),
            (tok.clone(), format!("[redacted:len={}]", tok.len())),
            ("1234567".to_string(), "1234567".to_string()),
            (String::new(), String::new()),
        ] {
            assert_eq!(redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", &given, "--verbose"]))[2..], v(&["--max-thinking-tokens", &want, "--verbose"]), "2.1.278's spelling: {given:?}");
        }
        assert_eq!(redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", "--", "github", "npx", "x"]))[2..], v(&["--max-thinking-tokens", "--", "github", "\u{2026}"]), "a bare -- is rule 2's, never the budget");
        assert_eq!(redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", "--env", "FOO=hunter2"]))[2..], v(&["--max-thinking-tokens", "--env", "FOO=[redacted:len=7]"]), "--env is rule 1's, never the budget");
        assert_eq!(redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", "-H", "X-Api-Key: abc123"]))[2..], v(&["--max-thinking-tokens", "-H", "X-Api-Key: [redacted:len=6]"]), "-H is rule 1's, never the budget");
        let mcp = r#"{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"hunter2"}}}}"#;
        for (flag, value) in [("--env", "FOO=hunter2"), ("-e", "FOO=hunter2"), ("--header", "X-Api-Key: abc123"), ("-H", "X-Api-Key: abc123"), ("--mcp-config", mcp)] {
            let after = redact_argv(&v(&["w", "/b/claude", "--max-thinking-tokens", flag, value]));
            assert_eq!(after[3..], redact_argv(&v(&["w", "/b/claude", flag, value]))[2..], "{flag} keeps its rule after --max-thinking-tokens");
            assert!(!after.iter().any(|t| t.contains("hunter2") || t.contains("abc123")), "{after:?}");
        }
        for (name, text) in [
            ("session", include_str!("../../tests/fixtures/argv/session.json")),
            ("session_multiroot", include_str!("../../tests/fixtures/argv/session_multiroot.json")),
            ("session_resume", include_str!("../../tests/fixtures/argv/session_resume.json")),
        ] {
            let args = fixture_argv(text);
            assert!(args.iter().any(|a| a == "--max-thinking-tokens=31999"), "{name}: {args:?}");
            let mut full = v(&[WRAPPER, BUNDLED]);
            full.extend(args.iter().cloned());
            assert_eq!(redact_argv(&full)[2..], args[..], "{name}");
        }
    }

    #[test]
    fn ext_version_from_bundle_path() {
        assert_eq!(ext_version_from_real_binary(Some(&OsString::from(BUNDLED))).as_deref(), Some("2.1.278"));
        assert_eq!(ext_version_from_real_binary(Some(&OsString::from("/opt/homebrew/bin/claude"))), None);
        assert_eq!(ext_version_from_real_binary(Some(&OsString::from("claude"))), None);
        assert_eq!(ext_version_from_real_binary(None), None);
    }

    #[test]
    fn build_row_on_the_session_fixture() {
        let args = fixture_argv(include_str!("../../tests/fixtures/argv/session.json"));
        let route = classify(&args);
        assert!(matches!(route, Route::Remote(_)));
        let mut argv: Vec<OsString> = vec![OsString::from(WRAPPER), OsString::from(BUNDLED)];
        argv.extend(args.iter().map(OsString::from));
        let cwd = Path::new("/Users/mike/Documents/DeFi/ai-env");
        let row = build_row(&argv, &route, Some(cwd), None);

        assert_eq!(row.v, CENSUS_SCHEMA_V);
        assert_eq!(row.route, "remote");
        assert_eq!(row.reason, "session");
        assert_eq!(row.ext.as_deref(), Some("2.1.278"));
        assert_eq!(row.pid, std::process::id());
        assert!(row.ppid > 0);
        assert_eq!(row.ts.len(), 20);
        assert!(row.ts.ends_with('Z'));
        let now = crate::wire::time::unix_now();
        assert!(row.start / 1000 <= now && row.start / 1000 + 5 >= now, "start {} vs now {now}", row.start);
        assert_eq!(row.ts, rfc3339_utc(row.start / 1000), "ts is derived from the same clock read as start");
        assert_eq!(row.argv[0], WRAPPER);
        assert_eq!(row.argv[1], BUNDLED);
        assert_eq!(row.argv[2..], args[..], "the row is the fixture, its thinking budget included (S10 F7)");
        assert_eq!(row.cwd.as_deref(), Some("/Users/mike/Documents/DeFi/ai-env"));
        assert!(row.note.is_none() && row.end.is_none() && row.exit.is_none());

        assert!(row.env_names.windows(2).all(|w| w[0] < w[1]), "sorted and deduplicated");
        assert!(row.env_names.iter().any(|n| n == "PATH"));
        for key in row.env_selected.keys() {
            assert!(CENSUS_VALUE_ALLOWLIST.contains(&key.as_str()), "{key} is not allowlisted");
        }
        for (name, value) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            let value = value.to_string_lossy().into_owned();
            if CENSUS_VALUE_ALLOWLIST.contains(&name.as_str()) {
                assert_eq!(row.env_selected.get(&name).map(String::as_str), Some(&*scrub(&value)), "{name} is allowlisted: its scrubbed value is recorded");
            } else {
                assert!(!row.env_selected.contains_key(&name), "{name} is not allowlisted but its value was recorded");
            }
            assert!(row.env_names.contains(&name), "{name} missing from env_names");
        }

        let json = serde_json::to_string(&row).unwrap();
        assert!(!json.contains("\"end\"") && !json.contains("\"exit\""), "{json}");
        let back: CensusRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn local_route_records_the_reason_name() {
        let row = row_with_note("hello");
        assert_eq!(row.route, "local");
        assert_eq!(row.reason, "subcommand:auth");
        assert_eq!(row.note.as_deref(), Some("hello"));
        let argv: Vec<OsString> = [WRAPPER, "/opt/homebrew/bin/claude"].iter().map(OsString::from).collect();
        let bare = build_row(&argv, &classify(&[]), None, None);
        assert_eq!(bare.reason, "no_args");
        assert_eq!(bare.ext, None);
        assert_eq!(bare.cwd, None);
    }

    #[test]
    fn record_appends_rows_with_private_modes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("logs").join("census.jsonl");
        assert_eq!(read_rows(&path, None).unwrap(), Vec::<serde_json::Value>::new(), "a missing file is an empty census");

        record(&path, &row_with_note("one")).unwrap();
        record(&path, &row_with_note("two")).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(mode_of(path.parent().unwrap()), 0o700);
            assert_eq!(mode_of(&path), 0o600);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
        assert!(!text.contains("\"end\"") && !text.contains("\"exit\""));

        let rows = read_rows(&path, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["note"], "one");
        assert_eq!(rows[1]["note"], "two");
        assert_eq!(rows[0]["v"], CENSUS_SCHEMA_V);
        let last = read_rows(&path, Some(1)).unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0]["note"], "two");
        assert_eq!(read_rows(&path, Some(0)).unwrap().len(), 0);
        assert_eq!(read_rows(&path, Some(9)).unwrap().len(), 2);

        // An oversized row is refused before the file is touched.
        let before = std::fs::read(&path).unwrap();
        let err = record(&path, &row_with_note(&"n".repeat(MAX_ROW_BYTES))).unwrap_err();
        assert!(err.to_string().contains("census row too large"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);

        // Unparseable lines are skipped, never fatal.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"not json\n{\"v\":\n").unwrap();
        drop(f);
        assert_eq!(read_rows(&path, None).unwrap().len(), 2);
    }

    #[test]
    fn record_never_creates_the_file_for_an_oversized_row() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("logs").join("census.jsonl");
        assert!(record(&path, &row_with_note(&"n".repeat(MAX_ROW_BYTES))).is_err());
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists(), "the 0700 dir is not created either");
    }

    /// One census line of exactly `bytes` bytes, its newline included: a
    /// row whose note pads it out.
    fn line_of(n: usize, bytes: usize) -> String {
        let head = format!("{{\"v\":1,\"n\":{n},\"note\":\"");
        format!("{head}{}\"}}\n", "x".repeat(bytes - head.len() - 3))
    }

    fn numbers(rows: &[serde_json::Value]) -> Vec<u64> {
        rows.iter().map(|r| r["n"].as_u64().unwrap()).collect()
    }

    /// The tail spans several chunks: the rows of the last `chunks` × 64 KiB
    /// come back whole and in order, a row the window cuts is dropped, a row
    /// before it never shows (the file is not read from its start), and a
    /// census shorter than the window comes back whole.
    #[test]
    fn read_tail_reads_the_last_chunks_only_and_keeps_whole_rows() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("census.jsonl");
        assert_eq!(read_tail(&path, 4).unwrap(), Vec::<serde_json::Value>::new(), "a missing file is an empty census");
        // Row 0, then 20 KiB rows: 2 × 64 KiB hold six of them and part of a seventh.
        let mut text = line_of(0, 100);
        for n in 1..=12 {
            text.push_str(&line_of(n, 20 * 1024));
        }
        std::fs::write(&path, &text).unwrap();
        assert_eq!(numbers(&read_tail(&path, 2).unwrap()), (7..=12).collect::<Vec<_>>(), "row 6 is cut by the window");
        assert_eq!(numbers(&read_tail(&path, 1).unwrap()), (10..=12).collect::<Vec<_>>());
        assert_eq!(numbers(&read_tail(&path, 4).unwrap()), (0..=12).collect::<Vec<_>>(), "the whole census fits in four chunks");
        assert_eq!(read_tail(&path, 0).unwrap(), Vec::<serde_json::Value>::new());
        // A window that starts exactly on a line keeps it: the byte before is its predecessor's newline.
        let exact = root.path().join("exact.jsonl");
        std::fs::write(&exact, format!("{}{}{}", line_of(0, 100), line_of(1, MAX_ROW_BYTES / 2), line_of(2, MAX_ROW_BYTES / 2))).unwrap();
        assert_eq!(numbers(&read_tail(&exact, 1).unwrap()), vec![1, 2]);
    }

    /// A partial last line (a row still being written, or a torn one) is
    /// skipped; an unterminated line that parses is a whole row.
    #[test]
    fn read_tail_skips_a_partial_last_line() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("census.jsonl");
        std::fs::write(&path, format!("{}{}{{\"v\":1,\"n\":3,\"no", line_of(1, 200), line_of(2, 200))).unwrap();
        assert_eq!(numbers(&read_tail(&path, 1).unwrap()), vec![1, 2]);
        std::fs::write(&path, format!("{}{{\"v\":1,\"n\":3}}", line_of(1, 200))).unwrap();
        assert_eq!(numbers(&read_tail(&path, 1).unwrap()), vec![1, 3]);
    }

    /// The tail is opened as the writer guards the file: a symlink in its
    /// place is refused, never followed; a FIFO or a directory is no regular
    /// file, refused at once (the FIFO's open never waits for a writer). Each
    /// error names the path.
    #[cfg(unix)]
    #[test]
    fn read_tail_refuses_a_symlink_a_fifo_or_a_directory() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real.jsonl");
        std::fs::write(&real, line_of(1, 200)).unwrap();
        assert_eq!(numbers(&read_tail(&real, 1).unwrap()), vec![1]);
        let link = root.path().join("census.jsonl");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_tail(&link, 1).unwrap_err().to_string(), format!("config: {} is a symlink; refusing to read it", link.display()));
        let fifo = root.path().join("fifo.jsonl");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // On a thread with a deadline: without O_NONBLOCK the open would wait for a writer forever.
        let (tx, rx) = std::sync::mpsc::channel();
        let at = fifo.clone();
        std::thread::spawn(move || tx.send(read_tail(&at, 1).map_err(|e| e.to_string())).unwrap());
        let got = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("opening a FIFO must not block");
        assert_eq!(got, Err(format!("config: {} is not a regular file", fifo.display())));
        assert_eq!(read_tail(root.path(), 1).unwrap_err().to_string(), format!("config: {} is not a regular file", root.path().display()));
    }

    /// Every reader of the census, the audit and the probe rows opens as the
    /// tail does ([`open_for_read`]): a symlink in the file's place is
    /// refused, never followed (its target untouched and unread); a FIFO or
    /// a directory is no regular file, refused at once (the FIFO's open
    /// never waits for a writer). Each error names the path; a missing file
    /// is still an empty census, and a line that is not UTF-8 is skipped
    /// like any unparseable one.
    #[cfg(unix)]
    #[test]
    fn read_rows_refuses_a_symlink_a_fifo_or_a_directory() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real.jsonl");
        let mut bytes = line_of(1, 200).into_bytes();
        bytes.extend_from_slice(b"\xff\xfe not utf-8\n");
        bytes.extend_from_slice(line_of(2, 200).as_bytes());
        std::fs::write(&real, &bytes).unwrap();
        assert_eq!(numbers(&read_rows(&real, None).unwrap()), vec![1, 2], "a line that is not UTF-8 is skipped, never fatal");
        assert_eq!(read_rows(&root.path().join("absent.jsonl"), None).unwrap(), Vec::<serde_json::Value>::new());
        let link = root.path().join("census.jsonl");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_rows(&link, None).unwrap_err().to_string(), format!("config: {} is a symlink; refusing to read it", link.display()));
        assert_eq!(crate::bridge::audit::read_rows(&link, Some(1)).unwrap_err().to_string(), format!("config: {} is a symlink; refusing to read it", link.display()), "the audit's reader too");
        let fifo = root.path().join("fifo.jsonl");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // On a thread with a deadline: without O_NONBLOCK the open would wait for a writer forever.
        let (tx, rx) = std::sync::mpsc::channel();
        let at = fifo.clone();
        std::thread::spawn(move || tx.send(read_rows(&at, None).map_err(|e| e.to_string())).unwrap());
        let got = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("opening a FIFO must not block");
        assert_eq!(got, Err(format!("config: {} is not a regular file", fifo.display())));
        assert_eq!(read_rows(root.path(), None).unwrap_err().to_string(), format!("config: {} is not a regular file", root.path().display()));
        assert!(matches!(open_for_read(&root.path().join("absent")), Ok(None)));
        assert!(open_for_read(&real).unwrap().is_some());
    }

    /// One census row of host `ppid` started at `start` (unix ms) naming `ext`.
    fn host_row(ppid: u64, start: u64, ext: Option<&str>) -> serde_json::Value {
        serde_json::json!({"v": 1, "start": start, "pid": 4242, "ppid": ppid, "ext": ext, "route": "remote", "reason": "session"})
    }

    /// The extension each live window runs: each host's newest row that
    /// names one, by `start` (an end row is its start row's clone, and an
    /// older row later in the file changes nothing); a dead host, and a pid
    /// the system gave a process that started after the host's newest row,
    /// never count; two live windows on two versions are both named, by
    /// when their hosts started. A row naming no extension, or of no window
    /// (`ppid` 0 or 1), is skipped; an `ext` of another shape is printed as
    /// unrecognised, never as written.
    #[test]
    fn running_extensions_take_each_live_hosts_newest_row() {
        let s = |secs: u64| secs * 1000;
        let rows = vec![
            // Host 100: dead.
            host_row(100, s(1_000), Some("2.1.290")),
            // Host 200: its pid now another process's, started after its newest row.
            host_row(200, s(1_000), Some("2.1.296")),
            // Host 300: its newest row naming an extension decides; a later one naming none changes nothing.
            host_row(300, s(2_000), Some("2.1.301")),
            host_row(300, s(3_000), Some("2.1.302")),
            host_row(300, s(3_500), None),
            // Host 400: a window still on 2.1.301; its older row comes later in the file, an end row too.
            host_row(400, s(2_500), Some("2.1.301")),
            host_row(400, s(1_500), Some("2.1.299")),
            {
                let mut end = host_row(400, s(2_500), Some("2.1.301"));
                end["end"] = serde_json::json!(s(2_600));
                end
            },
            // No window: launchd's child, a row with no ppid.
            host_row(1, s(4_000), Some("2.1.302")),
            serde_json::json!({"start": s(4_000), "ext": "2.1.302"}),
            // Host 500: a forged ext.
            host_row(500, s(4_000), Some("2.1.302\n  [ok ] forged")),
        ];
        let identity = |pid: u32| -> Option<(String, u64)> {
            match pid {
                200 => Some(("launchd-thing".into(), 1_500)),
                300 => Some(("Cursor Helper (Plugin)".into(), 1_900)),
                400 => Some(("Cursor Helper (Plugin)".into(), 1_200)),
                500 => Some(("Cursor Helper (Plugin)".into(), 3_999)),
                1 => Some(("launchd".into(), 0)),
                _ => None,
            }
        };
        let got = running_extensions(&rows, &identity);
        assert_eq!(
            got,
            vec![
                RunningExtension { host: 400, ext: "2.1.301".into(), started: 1_200, seen: s(2_500) },
                RunningExtension { host: 300, ext: "2.1.302".into(), started: 1_900, seen: s(3_000) },
                RunningExtension { host: 500, ext: UNRECOGNISED_EXT.into(), started: 3_999, seen: s(4_000) },
            ]
        );
        // A host that started in its newest row's second still counts; one a second later does not.
        assert_eq!(running_extensions(&[host_row(600, s(5_000) + 999, Some("2.1.302"))], &|_| Some((String::new(), 5_000))).len(), 1);
        assert!(running_extensions(&[host_row(600, s(5_000) + 999, Some("2.1.302"))], &|_| Some((String::new(), 5_001))).is_empty());
        assert!(running_extensions(&[], &identity).is_empty());
        // This process stands for a live host: its own start, read from the system, is before now.
        let me = std::process::id();
        let now_ms = crate::wire::time::unix_now_ms();
        let live = running_extensions(&[host_row(u64::from(me), now_ms, Some("2.1.302"))], &crate::bridge::registry::process_identity);
        assert_eq!(live.iter().map(|w| (w.host, w.ext.as_str())).collect::<Vec<_>>(), [(me, "2.1.302")]);
    }

    /// A row of exactly [`MAX_ROW_BYTES`] (the largest `record` writes) is
    /// whole in a one-chunk tail, and the row before it is not read.
    #[test]
    fn read_tail_keeps_a_64_kib_row() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("census.jsonl");
        let big = line_of(2, MAX_ROW_BYTES);
        assert_eq!(big.len(), MAX_ROW_BYTES);
        std::fs::write(&path, format!("{}{big}", line_of(1, 300))).unwrap();
        let rows = read_tail(&path, 1).unwrap();
        assert_eq!(numbers(&rows), vec![2]);
        assert_eq!(rows[0]["note"].as_str().map(str::len), Some(MAX_ROW_BYTES - "{\"v\":1,\"n\":2,\"note\":\"\"}\n".len()));
        assert_eq!(numbers(&read_tail(&path, 2).unwrap()), vec![1, 2]);
        // Its own census row: record writes it, the tail reads it back.
        let real = root.path().join("logs").join("census.jsonl");
        let mut row = row_with_note("");
        let pad = MAX_ROW_BYTES - serde_json::to_vec(&row).unwrap().len() - 1;
        row.note = Some("n".repeat(pad));
        record(&real, &row_with_note("before")).unwrap();
        record(&real, &row).unwrap();
        let back = read_tail(&real, 1).unwrap();
        assert_eq!(back.len(), 1, "the row before the 64 KiB one is outside the window");
        assert_eq!(serde_json::from_value::<CensusRow>(back[0].clone()).unwrap(), row);
    }
}
