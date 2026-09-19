//! The wrapper's argv router and sanitiser. Cursor's Claude extension spawns
//! `<wrapper> <realBinary> <flags…>`; the same wrapper serves chat sessions
//! (stream-json) and plain subcommands (`auth status --json`, `mcp add`, …).
//!
//! Facts this file encodes (verified against extension 2.1.278): `--resume=`
//! and `--setting-sources=` are `=`-joined; `--permission-mode M`,
//! `--mcp-config JSON`, `--tools …` and `--add-dir DIR` (repeated pairs) are
//! space-separated; the extension never emits `--debug-to-stderr` nor
//! `--replay-user-messages`, so neither is assumed here; `--session-mirror`
//! is a hidden CLI flag the wrapper appends itself.
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub real_binary: PathBuf,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvError {
    MissingRealBinary,
    NotUtf8(usize),
    Rejected(&'static str),
}

impl std::fmt::Display for ArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgvError::MissingRealBinary => f.write_str("missing <realBinary> argument"),
            ArgvError::NotUtf8(i) => write!(f, "argument {i} is not valid UTF-8"),
            ArgvError::Rejected(flag) => write!(f, "refusing to run with {flag}"),
        }
    }
}

/// `argv[0]` is the wrapper, `argv[1]` the real binary, the rest the CLI args.
pub fn split(argv: &[OsString]) -> Result<Invocation, ArgvError> {
    let real = argv.get(1).ok_or(ArgvError::MissingRealBinary)?;
    let mut args = Vec::with_capacity(argv.len().saturating_sub(2));
    for (i, a) in argv.iter().enumerate().skip(2) {
        args.push(a.to_str().ok_or(ArgvError::NotUtf8(i))?.to_string());
    }
    Ok(Invocation { real_binary: PathBuf::from(real), args })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReason {
    NoArgs,
    Version,
    Subcommand(String),
    ChromeMcp,
    Bare,
    NotStreamJson,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionArgs {
    pub resume: Option<String>,
    pub thinking_disabled: bool,
    pub add_dirs: Vec<String>,
    pub permission_mode: Option<String>,
    pub model: Option<String>,
    pub has_mcp_config: bool,
    pub setting_sources: Option<String>,
    pub continue_: bool,
    pub debug: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Local(LocalReason),
    Remote(SessionArgs),
}

/// Flags that consume the following token (unless written as `--flag=value`).
const VALUE_FLAGS: [&str; 27] = [
    "--output-format",
    "--input-format",
    "--permission-mode",
    "--permission-prompt-tool",
    "--mcp-config",
    "--tools",
    "--allowedTools",
    "--disallowedTools",
    "--add-dir",
    "--thinking",
    "--max-thinking-tokens",
    "--thinking-display",
    "--effort",
    "--max-turns",
    "--max-budget-usd",
    "--task-budget",
    "--model",
    "--fallback-model",
    "--agent",
    "--betas",
    "--json-schema",
    "--debug-file",
    "--plugin-dir",
    "--permission-prompts",
    "--resume",
    "--session-id",
    "--setting-sources",
];

#[must_use]
pub fn takes_value(flag: &str) -> bool {
    VALUE_FLAGS.contains(&flag)
}

/// Value of `--flag v` or `--flag=v`; flag handling stops at a bare `--`.
#[must_use]
pub fn value_of<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--" {
            return None;
        }
        if tok == flag {
            return args.get(i + 1).map(String::as_str);
        }
        if let Some(rest) = tok.strip_prefix(flag) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v);
            }
        }
        if takes_value(tok) {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn all_values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--" {
            break;
        }
        if tok == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.as_str());
            }
            i += 2;
            continue;
        }
        if let Some(v) = tok.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            out.push(v);
            i += 1;
            continue;
        }
        i += if takes_value(tok) { 2 } else { 1 };
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    for tok in args {
        if tok == "--" {
            return false;
        }
        if tok == flag {
            return true;
        }
    }
    false
}

fn is_debug_flag(tok: &str) -> bool {
    tok == "--debug" || tok.starts_with("--debug=") || tok == "--debug-file" || tok.starts_with("--debug-file=")
}

/// Decide where an invocation runs. Local reasons are checked in order.
#[must_use]
pub fn classify(args: &[String]) -> Route {
    let Some(first) = args.first() else {
        return Route::Local(LocalReason::NoArgs);
    };
    if matches!(first.as_str(), "--version" | "-v" | "-V") {
        return Route::Local(LocalReason::Version);
    }
    if !first.starts_with('-') {
        return Route::Local(LocalReason::Subcommand(first.clone()));
    }
    if has_flag(args, "--claude-in-chrome-mcp") {
        return Route::Local(LocalReason::ChromeMcp);
    }
    if has_flag(args, "--bare") {
        return Route::Local(LocalReason::Bare);
    }
    if value_of(args, "--output-format") != Some("stream-json") {
        return Route::Local(LocalReason::NotStreamJson);
    }
    Route::Remote(SessionArgs {
        resume: value_of(args, "--resume").map(str::to_string),
        thinking_disabled: value_of(args, "--thinking") == Some("disabled"),
        add_dirs: all_values(args, "--add-dir").into_iter().map(str::to_string).collect(),
        permission_mode: value_of(args, "--permission-mode").map(str::to_string),
        model: value_of(args, "--model").map(str::to_string),
        has_mcp_config: value_of(args, "--mcp-config").is_some(),
        setting_sources: value_of(args, "--setting-sources").map(str::to_string),
        continue_: has_flag(args, "--continue"),
        debug: args.iter().take_while(|t| t.as_str() != "--").any(|t| is_debug_flag(t)),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitiseOpts {
    pub strip_add_dir: bool,
    pub strip_debug: bool,
}

impl Default for SanitiseOpts {
    fn default() -> Self {
        SanitiseOpts { strip_add_dir: true, strip_debug: true }
    }
}

/// The argv sent to the remote child: `--bare` rejected; `--add-dir` pairs and
/// `--add-dir=` dropped; `--debug`/`--debug-file` dropped when `strip_debug`;
/// exactly one trailing `--session-mirror`; every other token, and every
/// value of a value-taking flag, copied byte-for-byte in order.
pub fn sanitise(args: &[String], opts: SanitiseOpts) -> Result<Vec<String>, ArgvError> {
    let mut out = Vec::with_capacity(args.len() + 1);
    let mut i = 0;
    let mut past_dd = false;
    while i < args.len() {
        let tok = args[i].as_str();
        if past_dd {
            out.push(tok.to_string());
            i += 1;
            continue;
        }
        if tok == "--" {
            past_dd = true;
            out.push(tok.to_string());
            i += 1;
            continue;
        }
        if tok == "--bare" {
            return Err(ArgvError::Rejected("--bare"));
        }
        if tok == "--session-mirror" {
            i += 1;
            continue;
        }
        if opts.strip_add_dir && tok == "--add-dir" {
            i += 2;
            continue;
        }
        if opts.strip_add_dir && tok.starts_with("--add-dir=") {
            i += 1;
            continue;
        }
        if opts.strip_debug && (tok == "--debug" || tok.starts_with("--debug=")) {
            i += 1;
            continue;
        }
        if opts.strip_debug && tok == "--debug-file" {
            i += 2;
            continue;
        }
        if opts.strip_debug && tok.starts_with("--debug-file=") {
            i += 1;
            continue;
        }
        if takes_value(tok) {
            out.push(tok.to_string());
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
            continue;
        }
        out.push(tok.to_string());
        i += 1;
    }
    out.push("--session-mirror".to_string());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct FixtureSession {
        resume: Option<String>,
        #[serde(default)]
        thinking_disabled: bool,
        #[serde(default)]
        add_dirs: Vec<String>,
        permission_mode: Option<String>,
        model: Option<String>,
        #[serde(default)]
        has_mcp_config: bool,
        setting_sources: Option<String>,
        #[serde(default, rename = "continue")]
        continue_: bool,
        #[serde(default)]
        debug: bool,
    }

    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        argv: Vec<String>,
        route: String,
        reason: Option<String>,
        session: Option<FixtureSession>,
        sanitised: Option<Vec<String>>,
        sanitise_error: Option<String>,
    }

    const FIXTURES: [&str; 10] = [
        include_str!("../../tests/fixtures/argv/session.json"),
        include_str!("../../tests/fixtures/argv/config_probe.json"),
        include_str!("../../tests/fixtures/argv/login_probe.json"),
        include_str!("../../tests/fixtures/argv/auth_status.json"),
        include_str!("../../tests/fixtures/argv/plugin_list.json"),
        include_str!("../../tests/fixtures/argv/mcp_add.json"),
        include_str!("../../tests/fixtures/argv/chrome_mcp.json"),
        include_str!("../../tests/fixtures/argv/version.json"),
        include_str!("../../tests/fixtures/argv/bare.json"),
        include_str!("../../tests/fixtures/argv/not_stream_json.json"),
    ];

    fn reason_name(r: &LocalReason) -> String {
        match r {
            LocalReason::NoArgs => "no_args".into(),
            LocalReason::Version => "version".into(),
            LocalReason::Subcommand(s) => format!("subcommand:{s}"),
            LocalReason::ChromeMcp => "chrome_mcp".into(),
            LocalReason::Bare => "bare".into(),
            LocalReason::NotStreamJson => "not_stream_json".into(),
        }
    }

    #[test]
    fn kat_fixtures() {
        for text in FIXTURES {
            let f: Fixture = serde_json::from_str(text).expect("fixture json");
            let route = classify(&f.argv);
            match (&route, f.route.as_str()) {
                (Route::Local(r), "local") => {
                    assert_eq!(Some(reason_name(r)), f.reason, "fixture {}", f.name);
                }
                (Route::Remote(s), "remote") => {
                    let e = f.session.as_ref().unwrap_or_else(|| panic!("fixture {} lacks session", f.name));
                    assert_eq!(s.resume, e.resume, "{}", f.name);
                    assert_eq!(s.thinking_disabled, e.thinking_disabled, "{}", f.name);
                    assert_eq!(s.add_dirs, e.add_dirs, "{}", f.name);
                    assert_eq!(s.permission_mode, e.permission_mode, "{}", f.name);
                    assert_eq!(s.model, e.model, "{}", f.name);
                    assert_eq!(s.has_mcp_config, e.has_mcp_config, "{}", f.name);
                    assert_eq!(s.setting_sources, e.setting_sources, "{}", f.name);
                    assert_eq!(s.continue_, e.continue_, "{}", f.name);
                    assert_eq!(s.debug, e.debug, "{}", f.name);
                }
                (r, want) => panic!("fixture {}: got {r:?}, want {want}", f.name),
            }
            let san = sanitise(&f.argv, SanitiseOpts::default());
            if let Some(want) = &f.sanitised {
                assert_eq!(san.as_ref().ok(), Some(want), "fixture {}", f.name);
            }
            if let Some(err) = &f.sanitise_error {
                assert_eq!(san, Err(ArgvError::Rejected("--bare")), "fixture {} expected {err}", f.name);
            }
        }
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn split_missing_real_binary() {
        assert_eq!(split(&[OsString::from("ai-env-claude")]), Err(ArgvError::MissingRealBinary));
        let inv = split(&[OsString::from("w"), OsString::from("/bin/claude"), OsString::from("--version")]).unwrap();
        assert_eq!(inv.real_binary, PathBuf::from("/bin/claude"));
        assert_eq!(inv.args, v(&["--version"]));
    }

    #[test]
    fn sanitise_strips_add_dir_eq_form() {
        let out = sanitise(&v(&["--output-format", "stream-json", "--add-dir=/x", "--add-dir", "/y", "-p"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["--output-format", "stream-json", "-p", "--session-mirror"]));
    }

    #[test]
    fn sanitise_strip_debug_variants() {
        let out = sanitise(&v(&["--debug", "--debug=api", "--debug-file", "/l", "--debug-file=/m", "-p"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["-p", "--session-mirror"]));
    }

    #[test]
    fn sanitise_keeps_debug_when_disabled() {
        let opts = SanitiseOpts { strip_add_dir: true, strip_debug: false };
        let out = sanitise(&v(&["--debug", "--debug-file", "/l"]), opts).unwrap();
        assert_eq!(out, v(&["--debug", "--debug-file", "/l", "--session-mirror"]));
    }

    #[test]
    fn sanitise_dedupes_session_mirror() {
        let out = sanitise(&v(&["--session-mirror", "-p", "--session-mirror"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["-p", "--session-mirror"]));
    }

    #[test]
    fn sanitise_passthrough_unexpected_debug_to_stderr() {
        let out = sanitise(&v(&["--debug-to-stderr", "--replay-user-messages"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["--debug-to-stderr", "--replay-user-messages", "--session-mirror"]));
    }

    #[test]
    fn sanitise_rejects_bare() {
        assert_eq!(sanitise(&v(&["--bare"]), SanitiseOpts::default()), Err(ArgvError::Rejected("--bare")));
    }

    #[test]
    fn value_of_stops_at_double_dash() {
        let a = v(&["--model", "m1", "--", "--model", "m2"]);
        assert_eq!(value_of(&a, "--model"), Some("m1"));
        let b = v(&["--", "--model", "m2"]);
        assert_eq!(value_of(&b, "--model"), None);
        assert_eq!(value_of(&v(&["--resume=abc"]), "--resume"), Some("abc"));
    }

    #[test]
    fn mcp_config_value_containing_add_dir_survives() {
        let json = "{\"mcpServers\":{\"x\":{\"args\":[\"--add-dir\",\"y\"]}}}";
        let out = sanitise(&v(&["--output-format", "stream-json", "--mcp-config", json, "--add-dir", "/z"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["--output-format", "stream-json", "--mcp-config", json, "--session-mirror"]));
    }

    fn token() -> impl Strategy<Value = Vec<String>> {
        prop_oneof![
            Just(v(&["--verbose"])),
            Just(v(&["--include-partial-messages"])),
            Just(v(&["--continue"])),
            Just(v(&["--output-format", "stream-json"])),
            Just(v(&["--permission-mode", "default"])),
            Just(v(&["--model", "claude-sonnet-4-5"])),
            Just(v(&["--resume=8f3c1b2e-4d5a-7b6c-9d8e-0f1a2b3c4d5e"])),
            Just(v(&["--add-dir", "/Users/mike/x"])),
            Just(v(&["--add-dir=/Users/mike/y"])),
            Just(v(&["--debug"])),
            Just(v(&["--debug-file", "/tmp/log"])),
            Just(v(&["--session-mirror"])),
            Just(v(&["--mcp-config", "{\"a\":\"--add-dir\"}"])),
            // Unknown boolean flags and `--k=v` forms: the extension's spawn
            // argv is flags only (messages arrive on stdin), never positionals.
            "--[a-z][a-z0-9-]{0,10}".prop_map(|s| vec![s]),
            "--[a-z]{2,6}=[A-Za-z0-9/.,:]{1,8}".prop_map(|s| vec![s]),
        ]
    }

    fn argv_strategy() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(token(), 0..24).prop_map(|parts| parts.into_iter().flatten().collect())
    }

    fn is_subsequence(needle: &[String], hay: &[String]) -> bool {
        let mut j = 0;
        for h in hay {
            if j < needle.len() && &needle[j] == h {
                j += 1;
            }
        }
        j == needle.len()
    }

    proptest! {
        #[test]
        fn prop_sanitise_idempotent(a in argv_strategy()) {
            let once = sanitise(&a, SanitiseOpts::default()).unwrap();
            let twice = sanitise(&once, SanitiseOpts::default()).unwrap();
            prop_assert_eq!(once, twice);
        }

        #[test]
        fn prop_single_trailing_session_mirror(a in argv_strategy()) {
            let out = sanitise(&a, SanitiseOpts::default()).unwrap();
            prop_assert_eq!(out.iter().filter(|t| t.as_str() == "--session-mirror").count(), 1);
            prop_assert_eq!(out.last().map(String::as_str), Some("--session-mirror"));
        }

        #[test]
        fn prop_order_preserving(a in argv_strategy()) {
            let mut out = sanitise(&a, SanitiseOpts::default()).unwrap();
            out.pop();
            prop_assert!(is_subsequence(&out, &a));
        }

        #[test]
        fn prop_mcp_config_value_intact(a in argv_strategy()) {
            let out = sanitise(&a, SanitiseOpts::default()).unwrap();
            let want = all_values(&a, "--mcp-config");
            let got = all_values(&out, "--mcp-config");
            prop_assert_eq!(got, want);
        }

        #[test]
        fn prop_no_add_dir_flag_remains(a in argv_strategy()) {
            let out = sanitise(&a, SanitiseOpts::default()).unwrap();
            prop_assert!(all_values(&out, "--add-dir").is_empty());
        }

        #[test]
        fn prop_route_stable_under_sanitise(a in argv_strategy()) {
            if let Route::Remote(s) = classify(&a) {
                let out = sanitise(&a, SanitiseOpts::default()).unwrap();
                match classify(&out) {
                    Route::Remote(t) => {
                        prop_assert_eq!(s.resume, t.resume);
                        prop_assert_eq!(s.thinking_disabled, t.thinking_disabled);
                        prop_assert_eq!(s.permission_mode, t.permission_mode);
                        prop_assert_eq!(s.model, t.model);
                    }
                    other => prop_assert!(false, "route changed: {:?}", other),
                }
            }
        }
    }
}
