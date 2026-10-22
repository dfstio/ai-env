//! The wrapper's argv router and sanitiser. Cursor's Claude extension spawns
//! `<wrapper> <realBinary> <flags…>`; the same wrapper serves chat sessions
//! (stream-json) and plain subcommands (`auth status --json`, `mcp add`, …).
//!
//! Facts this file encodes (verified against extension 2.1.278): `--resume=`
//! and `--setting-sources=` are `=`-joined; `--permission-mode M`,
//! `--mcp-config JSON`, `--tools …` and `--add-dir DIR` (repeated pairs) are
//! space-separated; every session and probe spawn ends with the fixed group
//! `--debug --debug-to-stderr --enable-auth-status --no-chrome
//! --replay-user-messages` (the extension's `extraArgs`), so `strip_debug`
//! drops `--debug-to-stderr` too while `--replay-user-messages` passes
//! through; `--session-mirror` is a hidden CLI flag the wrapper appends
//! itself. 2.1.301's SDK builder (2.1.303's too) joins each valued flag it
//! adds as `--flag=value` (`--permission-mode=M`, `--add-dir=DIR`,
//! `--thinking=disabled`, `--max-thinking-tokens=N`), all but `--mcp-config`
//! and `--managed-settings`; both spellings are read.
//! `tests/fixtures/argv/*.json` carry `FIXTURE_EXT_VERSION` (its doc names
//! the 8 that keep 2.1.278's argv; `KEPT_FIXTURES` the 4 of them the
//! extension makes no more). The 2.1.282 SDK builder
//! can also push `--managed-settings X`, `--plugin-dir-no-mcp X` and
//! `--channels X` (space-separated values, listed in `VALUE_FLAGS`) and
//! `--no-session-persistence` (a query whose transcript is never written —
//! the prompt-suggestions call; `SessionArgs::no_session_persistence`).
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

/// The extension version `tests/fixtures/argv/*.json` were captured from (a
/// kept fixture, [`KEPT_FIXTURES`], may carry an older one);
/// `ai-env doctor` warns when the installed bundle differs. S9's re-capture
/// (19 Oct 2026) took 9 of the 17 from 2.1.303's census; the other 8 keep
/// their 2.1.278 argv, tagged by hand: 2.1.303 makes `--version`, `--bare`,
/// `--output-format json` and a session's Chrome `--mcp-config` no more
/// ([`KEPT_FIXTURES`]), and `design-login`, `edit-permission-rules` and
/// `--claude-in-chrome-mcp` only in flows the capture skipped (part B's
/// Cursor checklist makes them).
pub const FIXTURE_EXT_VERSION: &str = "2.1.307";

/// Every fixture name under `tests/fixtures/argv/` (one source of truth:
/// the in-crate KAT includes exactly these, `tests/route.rs` checks the
/// directory holds exactly these).
pub const FIXTURE_NAMES: [&str; 17] = [
    "session",
    "session_resume",
    "session_multiroot",
    "session_chrome_mcp",
    "config_probe",
    "login_probe",
    "design_login",
    "auth_status",
    "plugin_list",
    "plugin_marketplace_list",
    "mcp_add",
    "mcp_remove",
    "edit_permission_rules",
    "chrome_mcp",
    "version",
    "bare",
    "not_stream_json",
];

/// The fixtures of shapes the extension makes no more (S10 F10), in
/// [`FIXTURE_NAMES`]' order: 2.1.303 starts no `--version`, no `--bare`, no
/// `--output-format json` and no session with Chrome's `--mcp-config`, so its
/// census holds no row of them. They keep their 2.1.278 argv (the router
/// still meets the shapes, from an older extension or a claude run by hand).
/// `make argv-fixtures` rewrites one only from a row of its shape (the
/// extension making it again) and otherwise reports it as kept, never as
/// missing; a kept fixture's `ext_version` may stay below
/// [`FIXTURE_EXT_VERSION`] when that moves on (never above it).
pub const KEPT_FIXTURES: [&str; 4] = ["session_chrome_mcp", "version", "bare", "not_stream_json"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalReason {
    NoArgs,
    Version,
    Subcommand(String),
    ChromeMcp,
    Bare,
    NotStreamJson,
    /// A stream-json session whose cwd is not under an approved workspace root
    /// (decided by `bridge::route`, never by `classify`).
    OutsideRoots,
    /// A stream-json session with no usable `bridge.toml` (absent or invalid).
    Unconfigured,
}

impl LocalReason {
    /// The census/fixture spelling of the reason (`subcommand:<word>` carries
    /// the first argv token).
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            LocalReason::NoArgs => "no_args".into(),
            LocalReason::Version => "version".into(),
            LocalReason::Subcommand(s) => format!("subcommand:{s}"),
            LocalReason::ChromeMcp => "chrome_mcp".into(),
            LocalReason::Bare => "bare".into(),
            LocalReason::NotStreamJson => "not_stream_json".into(),
            LocalReason::OutsideRoots => "outside_roots".into(),
            LocalReason::Unconfigured => "unconfigured".into(),
        }
    }
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
    /// `--no-session-persistence`: the CLI writes no transcript, so there is
    /// nothing to register, mirror or resume.
    pub no_session_persistence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Local(LocalReason),
    Remote(SessionArgs),
}

/// Flags that consume the following token (unless written as `--flag=value`).
const VALUE_FLAGS: [&str; 32] = [
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
    // S10's cut (a moved CLI resumes at a message); the second is never added, only stripped.
    "--resume-session-at",
    "--resume-drops-turn",
    "--setting-sources",
    "--managed-settings",
    "--plugin-dir-no-mcp",
    "--channels",
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
    tok == "--debug" || tok.starts_with("--debug=") || tok == "--debug-file" || tok.starts_with("--debug-file=") || tok == "--debug-to-stderr"
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
        no_session_persistence: has_flag(args, "--no-session-persistence"),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitiseOpts {
    pub strip_add_dir: bool,
    pub strip_debug: bool,
    /// Append the one `--session-mirror` (S9: a remote chat's transcript is
    /// kept in S3, so the remote route passes `false`: its child mirrors
    /// nothing to the Mac).
    pub mirror: bool,
}

impl Default for SanitiseOpts {
    fn default() -> Self {
        SanitiseOpts { strip_add_dir: true, strip_debug: true, mirror: true }
    }
}

/// The argv sent to the remote child: `--bare` rejected; `--add-dir` pairs and
/// `--add-dir=` dropped; `--debug`/`--debug-file` dropped when `strip_debug`;
/// every `--session-mirror` given dropped, and exactly one trailing
/// `--session-mirror` when `mirror`; every other token, and every value of a
/// value-taking flag, copied byte-for-byte in order.
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
        if opts.strip_debug && (tok == "--debug" || tok.starts_with("--debug=") || tok == "--debug-to-stderr") {
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
    if opts.mirror {
        out.push("--session-mirror".to_string());
    }
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
        #[serde(default)]
        no_session_persistence: bool,
    }

    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        ext_version: String,
        argv: Vec<String>,
        route: String,
        reason: Option<String>,
        session: Option<FixtureSession>,
        sanitised: Option<Vec<String>>,
        sanitise_error: Option<String>,
    }

    /// Same order as `FIXTURE_NAMES` (asserted by `fixture_names_are_the_index`).
    const FIXTURES: [&str; 17] = [
        include_str!("../../tests/fixtures/argv/session.json"),
        include_str!("../../tests/fixtures/argv/session_resume.json"),
        include_str!("../../tests/fixtures/argv/session_multiroot.json"),
        include_str!("../../tests/fixtures/argv/session_chrome_mcp.json"),
        include_str!("../../tests/fixtures/argv/config_probe.json"),
        include_str!("../../tests/fixtures/argv/login_probe.json"),
        include_str!("../../tests/fixtures/argv/design_login.json"),
        include_str!("../../tests/fixtures/argv/auth_status.json"),
        include_str!("../../tests/fixtures/argv/plugin_list.json"),
        include_str!("../../tests/fixtures/argv/plugin_marketplace_list.json"),
        include_str!("../../tests/fixtures/argv/mcp_add.json"),
        include_str!("../../tests/fixtures/argv/mcp_remove.json"),
        include_str!("../../tests/fixtures/argv/edit_permission_rules.json"),
        include_str!("../../tests/fixtures/argv/chrome_mcp.json"),
        include_str!("../../tests/fixtures/argv/version.json"),
        include_str!("../../tests/fixtures/argv/bare.json"),
        include_str!("../../tests/fixtures/argv/not_stream_json.json"),
    ];

    #[test]
    fn fixture_names_are_the_index() {
        assert_eq!(FIXTURES.len(), FIXTURE_NAMES.len());
        for (text, name) in FIXTURES.iter().zip(FIXTURE_NAMES) {
            let f: Fixture = serde_json::from_str(text).expect("fixture json");
            assert_eq!(f.name, name, "FIXTURES and FIXTURE_NAMES disagree at {name}");
        }
    }

    #[test]
    fn reason_names_are_stable() {
        let all = [
            (LocalReason::NoArgs, "no_args"),
            (LocalReason::Version, "version"),
            (LocalReason::Subcommand("auth".into()), "subcommand:auth"),
            (LocalReason::ChromeMcp, "chrome_mcp"),
            (LocalReason::Bare, "bare"),
            (LocalReason::NotStreamJson, "not_stream_json"),
            (LocalReason::OutsideRoots, "outside_roots"),
            (LocalReason::Unconfigured, "unconfigured"),
        ];
        for (r, want) in all {
            assert_eq!(r.name(), want);
        }
    }

    /// Whether a fixture's `ext_version` holds: `FIXTURE_EXT_VERSION` or an
    /// older N.N.N. A re-capture rewrites a fixture only from a row of its
    /// shape, and Cursor's extension stays fresh (Mike, 22 Oct 2026: S10's
    /// 2.1.307 capture remade 5 of the 17), so one no capture remade keeps
    /// the tag of its own; never a newer or a malformed one.
    fn tag_holds(_name: &str, ext_version: &str) -> bool {
        fn version(v: &str) -> Option<[u32; 3]> {
            let mut parts = v.split('.').map(|p| Some(p).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).and_then(|p| p.parse::<u32>().ok()));
            let out = [parts.next()??, parts.next()??, parts.next()??];
            parts.next().is_none().then_some(out)
        }
        version(ext_version).zip(version(FIXTURE_EXT_VERSION)).is_some_and(|(v, at)| v <= at)
    }

    #[test]
    fn kat_fixtures() {
        assert!(tag_holds("bare", "2.1.278") && tag_holds("session", "2.1.278") && !tag_holds("session", "99.0.0") && !tag_holds("session", "2.1"), "a fixture may keep an older tag, never a newer or a malformed one");
        for text in FIXTURES {
            let f: Fixture = serde_json::from_str(text).expect("fixture json");
            assert!(tag_holds(&f.name, &f.ext_version), "fixture {} is tagged with another extension version ({})", f.name, f.ext_version);
            let route = classify(&f.argv);
            match (&route, f.route.as_str()) {
                (Route::Local(r), "local") => {
                    assert_eq!(Some(r.name()), f.reason, "fixture {}", f.name);
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
                    assert_eq!(s.no_session_persistence, e.no_session_persistence, "{}", f.name);
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
        let opts = SanitiseOpts { strip_add_dir: true, strip_debug: false, mirror: true };
        let out = sanitise(&v(&["--debug", "--debug-file", "/l"]), opts).unwrap();
        assert_eq!(out, v(&["--debug", "--debug-file", "/l", "--session-mirror"]));
    }

    /// S9 (M2): a remote chat's child mirrors nothing once its transcript is
    /// kept in S3: without `mirror` no `--session-mirror` is left, not even
    /// one the host passed; the rest is sanitised as before.
    #[test]
    fn remote_has_no_session_mirror() {
        let opts = SanitiseOpts { mirror: false, ..SanitiseOpts::default() };
        let args = v(&["--output-format", "stream-json", "--session-mirror", "--add-dir", "/y", "--debug", "-p", "--session-mirror"]);
        let out = sanitise(&args, opts).unwrap();
        assert_eq!(out, v(&["--output-format", "stream-json", "-p"]));
        assert!(!out.iter().any(|a| a == "--session-mirror"));
        assert_eq!(sanitise(&args, SanitiseOpts::default()).unwrap().last().map(String::as_str), Some("--session-mirror"), "the default still mirrors");
        assert!(SanitiseOpts::default().mirror);
    }

    #[test]
    fn sanitise_dedupes_session_mirror() {
        let out = sanitise(&v(&["--session-mirror", "-p", "--session-mirror"]), SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["-p", "--session-mirror"]));
    }

    #[test]
    fn sanitise_strips_debug_to_stderr_and_keeps_the_rest_of_the_tail() {
        // The extension's fixed trailing group: only the two debug flags go.
        let tail = v(&["--debug", "--debug-to-stderr", "--enable-auth-status", "--no-chrome", "--replay-user-messages"]);
        let out = sanitise(&tail, SanitiseOpts::default()).unwrap();
        assert_eq!(out, v(&["--enable-auth-status", "--no-chrome", "--replay-user-messages", "--session-mirror"]));
        let kept = sanitise(&tail, SanitiseOpts { strip_add_dir: true, strip_debug: false, mirror: true }).unwrap();
        assert_eq!(kept.len(), tail.len() + 1, "strip_debug=false keeps every tail flag");
        assert!(matches!(classify(&v(&["--output-format", "stream-json", "--debug-to-stderr"])), Route::Remote(s) if s.debug), "--debug-to-stderr counts as a debug flag");
    }

    #[test]
    fn no_session_persistence_and_the_new_value_flags() {
        let a = v(&["--output-format", "stream-json", "--thinking", "disabled", "--model", "claude-haiku-4-5-20251001", "--no-session-persistence"]);
        assert!(matches!(classify(&a), Route::Remote(s) if s.no_session_persistence && s.thinking_disabled));
        assert!(matches!(classify(&v(&["--output-format", "stream-json"])), Route::Remote(s) if !s.no_session_persistence));
        // A space-separated value is never mistaken for a flag of its own.
        let b = v(&["--output-format", "stream-json", "--managed-settings", "--resume=x", "--channels", "--add-dir"]);
        assert!(matches!(classify(&b), Route::Remote(s) if s.resume.is_none() && s.add_dirs.is_empty()));
        assert_eq!(sanitise(&b, SanitiseOpts::default()).unwrap(), v(&["--output-format", "stream-json", "--managed-settings", "--resume=x", "--channels", "--add-dir", "--session-mirror"]));
        assert!(takes_value("--plugin-dir-no-mcp"));
    }

    /// Extension 2.1.303 (its SDK builder is 2.1.301's) joins each valued
    /// flag it adds as `--flag=value`, after the fixed
    /// `--output-format stream-json --verbose --input-format stream-json`;
    /// `--mcp-config`, `--managed-settings` and a valued `extraArgs` entry
    /// stay space-separated (joined when the value starts with `-`). A chat
    /// starts with the panel's thinking budget, `--max-thinking-tokens=31999`
    /// (thinking off, and the config probe: `--thinking=disabled`), and with
    /// no `--model` or `--effort`: the panel sends them after init.
    /// Every joined flag the router reads is read. The remote child keeps the
    /// budget byte for byte (the census too, S10 F7: the fixtures carry it)
    /// and loses `--add-dir=` and the debug flags.
    #[test]
    fn the_joined_forms_of_2_1_303() {
        let id = "123ce858-087d-4061-a4e0-dafc20958256";
        let resume = format!("--resume={id}");
        let chat = v(&["--output-format", "stream-json", "--verbose", "--input-format", "stream-json", "--max-thinking-tokens=31999", "--permission-prompt-tool=stdio", &resume, "--setting-sources=user,project,local", "--permission-mode=acceptEdits", "--include-partial-messages", "--add-dir=/Users/mike/other", "--debug", "--debug-to-stderr", "--enable-auth-status", "--no-chrome", "--replay-user-messages"]);
        let Route::Remote(s) = classify(&chat) else { panic!("not a session: {chat:?}") };
        assert_eq!((s.resume.as_deref(), s.permission_mode.as_deref(), s.setting_sources.as_deref()), (Some(id), Some("acceptEdits"), Some("user,project,local")));
        assert_eq!((s.add_dirs.clone(), s.model.as_deref(), s.thinking_disabled, s.debug), (v(&["/Users/mike/other"]), None, false, true));
        let remote = sanitise(&chat, SanitiseOpts { mirror: false, ..SanitiseOpts::default() }).unwrap();
        assert_eq!(remote, v(&["--output-format", "stream-json", "--verbose", "--input-format", "stream-json", "--max-thinking-tokens=31999", "--permission-prompt-tool=stdio", &resume, "--setting-sources=user,project,local", "--permission-mode=acceptEdits", "--include-partial-messages", "--enable-auth-status", "--no-chrome", "--replay-user-messages"]));
        // The probe's switch, and a model and an effort a launch may still name.
        let probe = v(&["--output-format", "stream-json", "--thinking=disabled", "--model=claude-opus-5-5", "--effort=high"]);
        let Route::Remote(p) = classify(&probe) else { panic!("not a session: {probe:?}") };
        assert_eq!((p.thinking_disabled, p.model.as_deref()), (true, Some("claude-opus-5-5")));
        assert_eq!(sanitise(&probe, SanitiseOpts::default()).unwrap(), probe.iter().cloned().chain(["--session-mirror".to_string()]).collect::<Vec<_>>());
        // 2.1.278's spelling keeps its value too.
        assert_eq!(sanitise(&v(&["--max-thinking-tokens", "31999", "-p"]), SanitiseOpts::default()).unwrap(), v(&["--max-thinking-tokens", "31999", "-p", "--session-mirror"]));
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
            Just(v(&["--debug-to-stderr"])),
            Just(v(&["--replay-user-messages"])),
            Just(v(&["--session-mirror"])),
            Just(v(&["--mcp-config", "{\"a\":\"--add-dir\"}"])),
            // 2.1.303's joined forms.
            Just(v(&["--permission-mode=default"])),
            Just(v(&["--thinking=disabled"])),
            Just(v(&["--max-thinking-tokens=31999"])),
            Just(v(&["--model=claude-sonnet-4-5"])),
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod n_tests {
    use super::*;

    /// The `argv` array of a fixture's text.
    fn argv_of(text: &str) -> Vec<String> {
        let j: serde_json::Value = serde_json::from_str(text).unwrap();
        j["argv"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    }

    /// S10 F10: the kept fixtures are four of the index, in its order, and
    /// their shapes are the ones extension 2.1.303 makes no more: `--version`,
    /// `--bare`, a non-stream-json run, and a session whose `--mcp-config`
    /// names Chrome's server.
    #[test]
    fn the_kept_fixtures_are_the_four_shapes_the_extension_makes_no_more() {
        let at: Vec<usize> = KEPT_FIXTURES.iter().map(|k| FIXTURE_NAMES.iter().position(|n| n == k).unwrap_or_else(|| panic!("{k} is no fixture"))).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "in FIXTURE_NAMES' order: {at:?}");
        assert_eq!(KEPT_FIXTURES, ["session_chrome_mcp", "version", "bare", "not_stream_json"]);
        assert_eq!(classify(&argv_of(include_str!("../../tests/fixtures/argv/version.json"))), Route::Local(LocalReason::Version));
        assert_eq!(classify(&argv_of(include_str!("../../tests/fixtures/argv/bare.json"))), Route::Local(LocalReason::Bare));
        assert_eq!(classify(&argv_of(include_str!("../../tests/fixtures/argv/not_stream_json.json"))), Route::Local(LocalReason::NotStreamJson));
        let chrome = argv_of(include_str!("../../tests/fixtures/argv/session_chrome_mcp.json"));
        assert!(matches!(classify(&chrome), Route::Remote(s) if s.has_mcp_config), "{chrome:?}");
        assert!(value_of(&chrome, "--mcp-config").is_some_and(|c| c.contains("claude-in-chrome")), "{chrome:?}");
    }
}
