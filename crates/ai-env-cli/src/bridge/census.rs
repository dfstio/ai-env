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
/// `CLAUDECODE`, `NODE_OPTIONS`) is read from `env_names`.
pub const CENSUS_VALUE_ALLOWLIST: [&str; 13] = [
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
];

/// One census line. `end`/`exit` stay absent until the S2 pump: the S1
/// wrapper execs the real binary, so nothing can write them.
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

/// What the next token is the value of (rules 1 and 3 of [`redact_argv`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Nothing,
    Env,
    Header,
    McpConfig,
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
///    key-shaped) and lose the recorded length.
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
            Pending::Nothing => {
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
                } else {
                    pending = match tok.as_str() {
                        "--env" | "-e" => Pending::Env,
                        "--header" | "-H" => Pending::Header,
                        "--mcp-config" => Pending::McpConfig,
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

/// Every parseable row (oldest first), or the last `last` of them. A missing
/// file is an empty census; unparseable lines are skipped, never fatal.
pub fn read_rows(path: &Path, last: Option<usize>) -> Result<Vec<serde_json::Value>, BridgeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(BridgeError::Io(e)),
    };
    let mut rows: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    if let Some(n) = last {
        let skip = rows.len().saturating_sub(n);
        rows.drain(..skip);
    }
    Ok(rows)
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
        assert_eq!(row.argv[2..], args[..], "nothing in a session argv needs redacting");
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
}
