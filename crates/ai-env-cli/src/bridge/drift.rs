//! S11 (C.4): doctor's drift rows, Mac-only and offline: the env names and
//! the flags each running Cursor window's extension starts chats with (the
//! census tail's session rows), and whether each newer extension's reader
//! still names the view's fields. Names and flags only, never a value.
use crate::bridge::agent::exec::{is_proxy_name, refused_name};
use crate::bridge::census::RunningExtension;
use crate::bridge::config::{Paths, WrapperCfg};
use crate::bridge::remote::env::{HOST_REFRESH_NAMES, NONESSENTIAL, PROJECT_DIR_NAME, WRAPPER_NAMES};
use crate::commands::{DoctorLine, Tag};
use crate::wire::argv::{flag_class, takes_value, FlagClass};
use crate::wire::redact::scrub;
use crate::wire::view::{VIEW_EXT_VERSION, VIEW_READER_STRINGS};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// The env name prefixes the env row judges.
pub const ENV_PREFIXES: [&str; 8] = ["CLAUDE_", "ANTHROPIC_", "MCP_", "DISABLE_", "ENABLE_", "MAX_", "BASH_", "OTEL_"];
/// Env names an extension sets that are reviewed and not forwarded: (name, why).
/// Part B's P0 doctor run (24 Oct 2026) gave the first list, from the 2.1.301 to
/// 2.1.303 windows' session rows; remote chats have run without each since S8.
/// S12 (R2): its two forwarding candidates, `CLAUDE_CODE_QUESTION_PREVIEW_FORMAT`
/// and `CLAUDE_CODE_SDK_READS_SESSION_STATE`, are forwarded by default now
/// (`WrapperCfg::default().env_forward`) and left the list: an explicit
/// `[wrapper] env_forward` that lacks them gets the `[!! ]` row for them.
pub const ENV_REVIEWED: &[(&str, &str)] = &[
    ("CLAUDE_CODE_CONFIG_PROBE", "marks the extension's config probe; remote probes have run without it since S8"),
    ("CLAUDE_CODE_EMIT_STARTUP_TIMING", "start-up timing for the extension's own log; nothing remote reads it"),
];
/// The most names or flags one row lists before ` (+<k> more)`.
pub const DRIFT_LIST_MAX: usize = 12;
/// The most of one `extension.js` the view row reads.
pub const VIEW_JS_MAX: u64 = 64 << 20;

/// `ext`'s session rows: the census rows whose `reason` is `session` and whose `ext` is `ext`. A row of any other
/// reason (a subcommand, a probe, a session outside the roots) is never judged.
fn session_rows<'a>(rows: &'a [Value], ext: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    rows.iter().filter(move |r| r.get("reason").and_then(Value::as_str) == Some("session") && r.get("ext").and_then(Value::as_str) == Some(ext))
}

/// A row's `env_names`: names only, the census never records a value there.
fn env_names_of(row: &Value) -> impl Iterator<Item = &str> {
    row.get("env_names").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
}

/// A name of one of [`ENV_PREFIXES`].
fn relevant(name: &str) -> bool {
    ENV_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether a remote session's environment already accounts for `name`: `[wrapper].env_forward` or `env_extra`
/// forwards it, the wrapper sets it itself (`remote::env`'s `WRAPPER_NAMES` and `NONESSENTIAL`), it is never
/// forwarded (`PROJECT_DIR_NAME`, a name `vm exec --env` refuses, a proxy variable, S12's refresh names), or
/// `reviewed` lists it.
///
/// `refused_name` refuses any name holding TOKEN, KEY, SECRET or PASSWORD, so CLI settings that are no credential
/// (`MAX_THINKING_TOKENS`, `CLAUDE_CODE_MAX_OUTPUT_TOKENS`, …) count as accounted here although a remote session
/// never carries them: [`refused_env_names`] names those (C5-R1, its own `[-  ]` row).
///
/// S12 (R2-6): a name of `remote::env::HOST_REFRESH_NAMES` is never forwarded either (`session_env` refuses it in
/// `[wrapper]`, R2-3), as `PROJECT_DIR_NAME` is not: an extension that sets one gets neither the `[!! ]` row nor the
/// refused row for it (`stock-ext-oauth` stays the detector of `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH`).
fn accounted(name: &str, wrapper: &WrapperCfg, reviewed: &[(&str, &str)]) -> bool {
    wrapper.env_forward.iter().chain(&wrapper.env_extra).any(|n| n.as_str() == name)
        || WRAPPER_NAMES.iter().any(|(n, _)| *n == name)
        || NONESSENTIAL.0 == name
        || PROJECT_DIR_NAME == name
        || refused_name(name).is_some()
        || is_proxy_name(name)
        || reviewed.iter().any(|(n, _)| *n == name)
        || HOST_REFRESH_NAMES.contains(&name)
}

/// The env names extension `ext`'s session rows carry, relevant (`ENV_PREFIXES`)
/// and neither forwarded nor reviewed (C.4.3), sorted.
#[must_use]
pub fn unreviewed_env_names(rows: &[Value], ext: &str, wrapper: &WrapperCfg) -> Vec<String> {
    unreviewed_of(rows, ext, wrapper, ENV_REVIEWED)
}

/// [`unreviewed_env_names`] with `reviewed` in place of [`ENV_REVIEWED`].
fn unreviewed_of(rows: &[Value], ext: &str, wrapper: &WrapperCfg, reviewed: &[(&str, &str)]) -> Vec<String> {
    let names: BTreeSet<&str> = session_rows(rows, ext).flat_map(env_names_of).filter(|n| relevant(n) && !accounted(n, wrapper, reviewed)).collect();
    names.into_iter().map(str::to_string).collect()
}

/// The env names of `ext`'s session rows with a relevant prefix (`ENV_PREFIXES`) that `vm exec --env` refuses
/// (`agent::exec::refused_name`: a credential's shape, the shim's own) and `ENV_REVIEWED` does not list, sorted
/// (C.4.2, C5-R1): a remote session never carries them, a setting that moved into such a name included.
#[must_use]
pub fn refused_env_names(rows: &[Value], ext: &str) -> Vec<String> {
    refused_of(rows, ext, ENV_REVIEWED)
}

/// [`refused_env_names`] with `reviewed` in place of [`ENV_REVIEWED`].
fn refused_of(rows: &[Value], ext: &str, reviewed: &[(&str, &str)]) -> Vec<String> {
    let names: BTreeSet<&str> = session_rows(rows, ext).flat_map(env_names_of).filter(|n| relevant(n) && refused_name(n).is_some() && !reviewed.iter().any(|(r, _)| r == n)).collect();
    names.into_iter().map(str::to_string).collect()
}

/// The `[wrapper].env_forward` names of a relevant prefix that none of `ext`'s session rows carries, sorted (so
/// `LANG` and `TERM` are never named). None when `ext` has no session row: a version that started no chat in the
/// census tail is no evidence that it stopped setting a name.
#[must_use]
pub fn forwarded_env_names_gone(rows: &[Value], ext: &str, wrapper: &WrapperCfg) -> Vec<String> {
    let mut sessions = session_rows(rows, ext).peekable();
    if sessions.peek().is_none() {
        return Vec::new();
    }
    let carried: BTreeSet<&str> = sessions.flat_map(env_names_of).collect();
    let gone: BTreeSet<&str> = wrapper.env_forward.iter().map(String::as_str).filter(|n| relevant(n) && !carried.contains(n)).collect();
    gone.into_iter().map(str::to_string).collect()
}

/// The `--flag` names a census row's `argv` passes, as the router reads them: from its third token (argv[0] and
/// argv[1] are the wrapper and the real binary) up to a bare `--`; a token starting with `--` and longer than 2 split
/// at its first `=`; the token after a `Value` flag in its spaced form skipped, as `takes_value` reads it. Short flags
/// (`-c`) and other tokens are never judged.
fn flags_of(row: &Value) -> Vec<&str> {
    // A token that is not a string keeps its place (an empty token), so the skips stay aligned.
    let argv: Vec<&str> = row.get("argv").and_then(Value::as_array).map(|a| a.iter().map(|t| t.as_str().unwrap_or_default()).collect()).unwrap_or_default();
    let mut out = Vec::new();
    let mut rest = argv.into_iter().skip(2);
    while let Some(tok) = rest.next() {
        if tok == "--" {
            break;
        }
        if tok.len() <= 2 || !tok.starts_with("--") {
            continue;
        }
        if let Some((name, _)) = tok.split_once('=') {
            out.push(name);
        } else {
            out.push(tok);
            if takes_value(tok) {
                rest.next();
            }
        }
    }
    out
}

/// The flags `ext`'s session rows pass that `flag_class` calls `Unknown`, sorted and unique.
#[must_use]
pub fn unknown_flags(rows: &[Value], ext: &str) -> Vec<String> {
    let flags: BTreeSet<&str> = session_rows(rows, ext).flat_map(flags_of).filter(|f| flag_class(f) == FlagClass::Unknown).collect();
    flags.into_iter().map(str::to_string).collect()
}

/// `items` (sorted by the caller), each scrubbed, joined by `, `: at most [`DRIFT_LIST_MAX`], then ` (+<k> more)`.
fn listed<S: AsRef<str>>(items: &[S]) -> String {
    let shown: Vec<String> = items.iter().take(DRIFT_LIST_MAX).map(|s| scrub(s.as_ref()).into_owned()).collect();
    match items.len().saturating_sub(DRIFT_LIST_MAX) {
        0 => shown.join(", "),
        more => format!("{} (+{more} more)", shown.join(", ")),
    }
}

/// Per running window's extension version (once each, by version): its env rows, then its flag row.
#[must_use]
pub fn env_and_flag_rows(rows: &[Value], running: &[RunningExtension], wrapper: &WrapperCfg) -> Vec<DoctorLine> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for v in running.iter().map(|w| w.ext.as_str()).filter(|v| seen.insert(*v)) {
        let unreviewed = unreviewed_env_names(rows, v, wrapper);
        if !unreviewed.is_empty() {
            out.push(DoctorLine::row(Tag::Warn, format!("extension {v} starts chats with env names neither forwarded nor reviewed: {}  <- [wrapper].env_extra, or ENV_REVIEWED", listed(&unreviewed))));
        }
        let gone = forwarded_env_names_gone(rows, v, wrapper);
        if !gone.is_empty() {
            out.push(DoctorLine::row(Tag::Skip, format!("extension {v} starts chats without {}, which [wrapper].env_forward forwards", listed(&gone))));
        }
        let refused = refused_env_names(rows, v);
        if !refused.is_empty() {
            out.push(DoctorLine::row(Tag::Skip, format!("extension {v} starts chats with {}, which a remote session never carries (vm exec refuses the name)", listed(&refused))));
        }
        let flags = unknown_flags(rows, v);
        if !flags.is_empty() {
            out.push(DoctorLine::row(
                Tag::Warn,
                format!("extension {v} passes flags the router does not classify: {}  <- VALUE_FLAGS or BOOL_FLAGS (src/wire/argv.rs), then make argv-fixtures EXT={v}", listed(&flags)),
            ));
        }
    }
    out
}

/// `v`'s N.N.N, compared numerically: a suffixed `2.1.310-beta` by its core, `2.1.310`, and a part past the third
/// ignored, as doctor's bundle pick reads a version; `None` for no version.
fn version_core(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| Some(p).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).and_then(|p| p.parse::<u64>().ok()));
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// Whether `hay` holds `needle` as bytes.
fn holds(hay: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };
    let mut at = 0;
    while let Some(p) = hay[at..].iter().position(|&b| b == first) {
        if hay[at + p + 1..].starts_with(rest) {
            return true;
        }
        at += p + 1;
    }
    false
}

/// The view rows of `versions` (each newer than `VIEW_EXT_VERSION`), `bundle_js` reading `<V>`'s `extension.js`.
/// A version at or below the pin, or none, has no row; each version is judged once.
#[must_use]
pub fn view_rows(versions: &[String], bundle_js: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Vec<DoctorLine> {
    let pin = version_core(VIEW_EXT_VERSION);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for v in versions {
        if !seen.insert(v.as_str()) || !version_core(v).zip(pin).is_some_and(|(v, pin)| v > pin) {
            continue;
        }
        out.push(match bundle_js(v) {
            Ok(js) => {
                let mut missing: Vec<&str> = VIEW_READER_STRINGS.iter().copied().filter(|s| !holds(&js, s.as_bytes())).collect();
                missing.sort_unstable();
                if missing.is_empty() {
                    DoctorLine::row(Tag::Ok, format!("view format: {v}'s reader still names the view's fields (pinned at {VIEW_EXT_VERSION})"))
                } else {
                    DoctorLine::row(Tag::Warn, format!("view format: {v}'s reader lacks: {}  <- re-check src/wire/view.rs", listed(&missing)))
                }
            }
            Err(why) => DoctorLine::row(Tag::Skip, format!("view format: {v}'s extension.js cannot be read ({})", scrub(&why))),
        });
    }
    out
}

/// `<ext_dir>/anthropic.claude-code-<V>-darwin-arm64/extension.js`, as the view row reads it: a regular file opened
/// `O_NOFOLLOW` and `O_NONBLOCK` (a symlink, a FIFO or a directory is refused, never followed or waited on), of at
/// most [`VIEW_JS_MAX`] bytes. `Err` says why in a few words, never the path.
fn read_extension_js(ext_dir: &Path, version: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if version.is_empty() || version.contains('/') {
        return Err("not a version".into());
    }
    let path = ext_dir.join(format!("anthropic.claude-code-{version}-darwin-arm64")).join("extension.js");
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "missing".to_string()
        } else if e.raw_os_error() == Some(libc::ELOOP) {
            "a symlink".to_string()
        } else {
            e.to_string()
        }
    })?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > VIEW_JS_MAX {
        return Err(format!("larger than {} MiB", VIEW_JS_MAX >> 20));
    }
    let mut js = Vec::new();
    file.take(VIEW_JS_MAX).read_to_end(&mut js).map_err(|e| e.to_string())?;
    Ok(js)
}

/// Doctor's call: the census tail (`census::read_tail(paths.census(), wrapper_status::CENSUS_TAIL_CHUNKS)`),
/// `census::running_extensions` with `registry::process_identity`, the installed bundle
/// (`doctor::pick_bundle(&doctor::installed_extension_names(ext_dir))`) and each running window's version;
/// then `env_and_flag_rows` and `view_rows`. No census or no root: no env or flag row.
#[must_use]
pub fn doctor_rows(paths: Option<&Paths>, ext_dir: &Path, wrapper: &WrapperCfg) -> Vec<DoctorLine> {
    use crate::bridge::{census, doctor, registry, wrapper_status};
    let rows = paths.and_then(|p| census::read_tail(&p.census(), wrapper_status::CENSUS_TAIL_CHUNKS).ok()).unwrap_or_default();
    let running = census::running_extensions(&rows, &registry::process_identity);
    let installed = doctor::pick_bundle(&doctor::installed_extension_names(ext_dir)).map(|(v, _)| v);
    let versions: Vec<String> = installed.into_iter().chain(running.iter().map(|w| w.ext.clone())).collect();
    let mut lines = env_and_flag_rows(&rows, &running, wrapper);
    lines.extend(view_rows(&versions, &|v| read_extension_js(ext_dir, v)));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXT: &str = "2.1.310";

    /// A census row as the wrapper writes one (`census::build_row`): argv[0] the wrapper, argv[1] the real binary.
    fn row(reason: &str, ext: &str, args: &[&str], env: &[&str]) -> Value {
        let argv: Vec<&str> = ["/Users/mike/.cargo/bin/ai-env-claude", "--argv1-is-never-judged"].into_iter().chain(args.iter().copied()).collect();
        let route = if reason == "session" { "remote" } else { "local" };
        json!({"v": 1, "ts": "2026-10-23T10:00:00Z", "start": 1_000, "pid": 4243, "ppid": 4242, "ext": ext, "route": route, "reason": reason, "argv": argv, "env_names": env})
    }

    fn session(args: &[&str], env: &[&str]) -> Value {
        row("session", EXT, args, env)
    }

    fn window(ext: &str) -> RunningExtension {
        RunningExtension { host: 4242, ext: ext.to_string(), started: 1, seen: 1_000 }
    }

    fn texts(lines: &[DoctorLine]) -> Vec<String> {
        lines
            .iter()
            .map(|l| match l {
                DoctorLine::Row { tag, text } => format!("{} {text}", tag.bracket()),
                DoctorLine::Plain(t) => t.clone(),
            })
            .collect()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// The default `[wrapper]`'s forwarded names, so a row carrying them has no gone row (S12: the extension's two
    /// as well, R2-1).
    fn forwarded() -> Vec<&'static str> {
        vec![
            "CLAUDE_CODE_ENTRYPOINT",
            "CLAUDE_AGENT_SDK_VERSION",
            "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
            "MCP_CONNECTION_NONBLOCKING",
            "CLAUDE_CODE_ENABLE_TASKS",
            "CLAUDE_CODE_QUESTION_PREVIEW_FORMAT",
            "CLAUDE_CODE_SDK_READS_SESSION_STATE",
        ]
    }

    /// A fake extensions directory: `<dir>/anthropic.claude-code-<V>-darwin-arm64/extension.js` holding `js`.
    fn bundle(dir: &Path, v: &str, js: &str) {
        let b = dir.join(format!("anthropic.claude-code-{v}-darwin-arm64"));
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("extension.js"), js).unwrap();
    }

    /// Every reader string, in the minified shapes a bundle holds them.
    fn every_string() -> String {
        VIEW_READER_STRINGS.iter().map(|s| format!("a.{s}=b;")).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn an_unreviewed_env_name_is_named_and_a_reviewed_one_is_not() {
        let w = WrapperCfg::default();
        let env: Vec<&str> = forwarded().into_iter().chain(["CLAUDE_CODE_NEW_THING", "OTEL_EXPORTER", "ANTHROPIC_BETA", "HOME", "PATH", "LANG", "SOME_OTHER", "CLAUDECODE"]).collect();
        let rows = vec![session(&["--verbose"], &env), session(&["--verbose"], &["MAX_THINKING", "CLAUDE_CODE_NEW_THING"])];
        // Relevant prefixes only (HOME, PATH, LANG, SOME_OTHER and CLAUDECODE are none), the union, sorted, once.
        assert_eq!(unreviewed_env_names(&rows, EXT, &w), s(&["ANTHROPIC_BETA", "CLAUDE_CODE_NEW_THING", "MAX_THINKING", "OTEL_EXPORTER"]));
        // A reviewed name is not named; nor is one `[wrapper].env_extra` adds.
        assert_eq!(unreviewed_of(&rows, EXT, &w, &[("CLAUDE_CODE_NEW_THING", "the extension's own, read by the CLI locally")]), s(&["ANTHROPIC_BETA", "MAX_THINKING", "OTEL_EXPORTER"]));
        let extra = WrapperCfg { env_extra: s(&["OTEL_EXPORTER"]), ..WrapperCfg::default() };
        assert_eq!(unreviewed_env_names(&rows, EXT, &extra), s(&["ANTHROPIC_BETA", "CLAUDE_CODE_NEW_THING", "MAX_THINKING"]));
        for &(name, why) in ENV_REVIEWED {
            assert!(!why.is_empty() && unreviewed_env_names(&[session(&[], &[name])], EXT, &w).is_empty(), "{name}");
        }
        // Another extension's rows count for nothing.
        assert!(unreviewed_env_names(&rows, "2.1.309", &w).is_empty());
        let lines = texts(&env_and_flag_rows(&rows, &[window(EXT)], &w));
        assert_eq!(lines, vec!["[!! ] extension 2.1.310 starts chats with env names neither forwarded nor reviewed: ANTHROPIC_BETA, CLAUDE_CODE_NEW_THING, MAX_THINKING, OTEL_EXPORTER  <- [wrapper].env_extra, or ENV_REVIEWED".to_string()]);
        // At most DRIFT_LIST_MAX names, then how many more.
        let many: Vec<String> = (0..DRIFT_LIST_MAX + 2).map(|i| format!("CLAUDE_X{i:02}")).collect();
        let many_rows = vec![session(&[], &forwarded().into_iter().chain(many.iter().map(String::as_str)).collect::<Vec<_>>())];
        let lines = texts(&env_and_flag_rows(&many_rows, &[window(EXT)], &w));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(&format!("{}, CLAUDE_X11 (+2 more)  <- ", many[..DRIFT_LIST_MAX - 1].join(", "))) && !lines[0].contains("CLAUDE_X12"), "{lines:?}");
    }

    #[test]
    fn forwarded_wrapper_and_refused_names_are_never_named() {
        let w = WrapperCfg::default();
        let mut env: Vec<&str> = forwarded();
        env.extend(WRAPPER_NAMES.iter().map(|(n, _)| *n));
        env.extend([NONESSENTIAL.0, PROJECT_DIR_NAME]);
        // Names `vm exec --env` refuses (a credential's shape, the shim's own) and the proxy variables.
        env.extend(["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "MCP_SECRET", "CLAUDE_CONFIG_DIR", "BASH_PASSWORD_FILE", "https_proxy", "NO_PROXY"]);
        assert!(env.iter().filter(|n| relevant(n)).count() >= 15, "the relevant ones are judged and dropped: {env:?}");
        let rows = vec![session(&["--verbose"], &env)];
        assert!(unreviewed_env_names(&rows, EXT, &w).is_empty(), "{:?}", unreviewed_env_names(&rows, EXT, &w));
        assert!(forwarded_env_names_gone(&rows, EXT, &w).is_empty());
        // The refused ones only in C5-R1's note (none of them reviewed yet).
        assert_eq!(
            texts(&env_and_flag_rows(&rows, &[window(EXT)], &w)),
            vec!["[-  ] extension 2.1.310 starts chats with ANTHROPIC_API_KEY, BASH_PASSWORD_FILE, CLAUDE_CODE_OAUTH_TOKEN, CLAUDE_CONFIG_DIR, MCP_SECRET, which a remote session never carries (vm exec refuses the name)".to_string()]
        );
        let clean: Vec<&str> = env.iter().copied().filter(|n| refused_name(n).is_none()).collect();
        assert!(env_and_flag_rows(&[session(&["--verbose"], &clean)], &[window(EXT)], &w).is_empty(), "a clean version shows nothing");
    }

    /// C5-R1: a relevant name `vm exec --env` refuses (a CLI setting shaped like a credential, the shim's own) is
    /// a note right after the gone row, sorted and listed under `DRIFT_LIST_MAX`; one `ENV_REVIEWED` lists is not.
    #[test]
    fn a_refused_settings_name_is_a_note_and_a_reviewed_one_is_not() {
        let w = WrapperCfg::default();
        let env: Vec<&str> = forwarded()
            .into_iter()
            .filter(|n| *n != "CLAUDE_CODE_ENABLE_TASKS")
            .chain(["MAX_THINKING_TOKENS", "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "CLAUDE_CODE_OAUTH_TOKEN", "GITHUB_TOKEN", "AWS_PROFILE", "NODE_OPTIONS"])
            .collect();
        let rows = vec![session(&["--verbose"], &env), session(&[], &["MAX_MCP_OUTPUT_TOKENS"])];
        // Relevant prefixes only (GITHUB_TOKEN, AWS_PROFILE and NODE_OPTIONS are none), the union, sorted.
        assert_eq!(refused_env_names(&rows, EXT), s(&["CLAUDE_CODE_MAX_OUTPUT_TOKENS", "CLAUDE_CODE_OAUTH_TOKEN", "MAX_MCP_OUTPUT_TOKENS", "MAX_THINKING_TOKENS"]));
        assert!(unreviewed_env_names(&rows, EXT, &w).is_empty(), "never the unreviewed row's");
        assert_eq!(refused_of(&rows, EXT, &[("CLAUDE_CODE_OAUTH_TOKEN", "the setup-token's name: ai-env delivers it")]), s(&["CLAUDE_CODE_MAX_OUTPUT_TOKENS", "MAX_MCP_OUTPUT_TOKENS", "MAX_THINKING_TOKENS"]));
        for &(name, _) in ENV_REVIEWED {
            assert!(refused_env_names(&[session(&[], &[name])], EXT).is_empty(), "{name}");
        }
        assert_eq!(
            texts(&env_and_flag_rows(&rows, &[window(EXT)], &w)),
            vec![
                "[-  ] extension 2.1.310 starts chats without CLAUDE_CODE_ENABLE_TASKS, which [wrapper].env_forward forwards".to_string(),
                "[-  ] extension 2.1.310 starts chats with CLAUDE_CODE_MAX_OUTPUT_TOKENS, CLAUDE_CODE_OAUTH_TOKEN, MAX_MCP_OUTPUT_TOKENS, MAX_THINKING_TOKENS, which a remote session never carries (vm exec refuses the name)".to_string(),
            ]
        );
        // Another extension's rows, or a row that is no session's, count for nothing.
        assert!(refused_env_names(&rows, "2.1.309").is_empty());
        assert!(refused_env_names(&[row("subcommand:mcp", EXT, &[], &["MAX_THINKING_TOKENS"])], EXT).is_empty());
        // At most DRIFT_LIST_MAX names, then how many more.
        let many: Vec<String> = (0..=DRIFT_LIST_MAX).map(|i| format!("CLAUDE_KEY_{i:02}")).collect();
        let lines = texts(&env_and_flag_rows(&[session(&[], &forwarded().into_iter().chain(many.iter().map(String::as_str)).collect::<Vec<_>>())], &[window(EXT)], &w));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(", CLAUDE_KEY_11 (+1 more), which a remote session never carries"), "{lines:?}");
    }

    #[test]
    fn a_forwarded_name_the_extension_no_longer_sets_is_a_note() {
        let w = WrapperCfg::default();
        assert!(w.env_forward.iter().any(|n| n == "LANG") && w.env_forward.iter().any(|n| n == "TERM"));
        // Neither LANG nor TERM (no relevant prefix) nor CLAUDE_CODE_ENABLE_TASKS.
        let without: Vec<&str> = forwarded().into_iter().filter(|n| *n != "CLAUDE_CODE_ENABLE_TASKS").collect();
        let rows = vec![session(&[], &without)];
        assert_eq!(forwarded_env_names_gone(&rows, EXT, &w), s(&["CLAUDE_CODE_ENABLE_TASKS"]));
        assert_eq!(texts(&env_and_flag_rows(&rows, &[window(EXT)], &w)), vec!["[-  ] extension 2.1.310 starts chats without CLAUDE_CODE_ENABLE_TASKS, which [wrapper].env_forward forwards".to_string()]);
        // One session row carrying it is enough.
        let both = vec![rows[0].clone(), session(&[], &["CLAUDE_CODE_ENABLE_TASKS"])];
        assert!(forwarded_env_names_gone(&both, EXT, &w).is_empty());
        // No session row of that version: no evidence, no note.
        assert!(forwarded_env_names_gone(&[row("subcommand:auth", EXT, &["auth", "status", "--json"], &[])], EXT, &w).is_empty());
        assert!(forwarded_env_names_gone(&rows, "2.1.309", &w).is_empty());
    }

    #[test]
    fn an_unknown_flag_is_named_in_either_form_never_past_a_bare_dashdash() {
        let w = WrapperCfg::default();
        let args = ["--output-format", "stream-json", "--verbose", "--new-flag", "--other-new=3", "-x", "--debug", "--", "--past-the-dashdash", "\u{2026}"];
        let rows = vec![session(&args, &forwarded()), session(&["--new-flag", "--max-thinking-tokens=31999", "--third-new=a=b"], &forwarded())];
        assert_eq!(unknown_flags(&rows, EXT), s(&["--new-flag", "--other-new", "--third-new"]), "argv[0] and argv[1] never; split at the first =; once each");
        assert_eq!(
            texts(&env_and_flag_rows(&rows, &[window(EXT)], &w)),
            vec!["[!! ] extension 2.1.310 passes flags the router does not classify: --new-flag, --other-new, --third-new  <- VALUE_FLAGS or BOOL_FLAGS (src/wire/argv.rs), then make argv-fixtures EXT=2.1.310".to_string()]
        );
        // Only a bare `--` ends the flags; the census's own redaction (`--`, the server name, `…`) is never judged.
        assert!(unknown_flags(&[session(&["--verbose", "--", "--new-flag"], &[])], EXT).is_empty());
        assert_eq!(unknown_flags(&[session(&["---", "--=x", "--verbose"], &[])], EXT), s(&["--", "---"]));
        // Non-string tokens keep their places; a row with no argv passes nothing.
        assert_eq!(unknown_flags(&[json!({"reason": "session", "ext": EXT, "argv": ["/w", "/b", "--model", 7, "--new-flag"]})], EXT), s(&["--new-flag"]));
        assert!(unknown_flags(&[json!({"reason": "session", "ext": EXT})], EXT).is_empty());
    }

    #[test]
    fn a_spaced_value_is_no_flag() {
        // Each `Value` flag's spaced value is skipped, even one shaped like a flag; the census's masked budget too.
        let args = ["--model", "--looks-like-a-flag", "--permission-mode", "default", "--max-thinking-tokens", "[redacted:len=5]", "--resume", "--another-value", "--mcp-config", "{\"mcpServers\":[\"x\"]}"];
        assert!(unknown_flags(&[session(&args, &[])], EXT).is_empty(), "{:?}", unknown_flags(&[session(&args, &[])], EXT));
        // A `Bool` or `Stripped` flag takes no value: the token after it is judged.
        assert_eq!(unknown_flags(&[session(&["--verbose", "--after-a-bool", "--debug", "--after-stripped"], &[])], EXT), s(&["--after-a-bool", "--after-stripped"]));
        // `=value` takes nothing from the next token.
        assert_eq!(unknown_flags(&[session(&["--model=opus", "--after-joined"], &[])], EXT), s(&["--after-joined"]));
        // An unknown flag's spaced value is no flag either (it does not start with --), and never shown.
        assert_eq!(unknown_flags(&[session(&["--new-secretish", "value-not-shown"], &[])], EXT), s(&["--new-secretish"]));
    }

    #[test]
    fn a_non_session_row_is_never_judged() {
        let w = WrapperCfg::default();
        let env = ["CLAUDE_CODE_NEW_THING"];
        let rows = vec![
            row("subcommand:mcp", EXT, &["mcp", "add", "--scope", "user", "--transport", "stdio", "--env", "GITHUB_TOKEN=[redacted:len=40]", "--", "github", "\u{2026}"], &env),
            row("subcommand:design-login", EXT, &["design-login", "--json", "--status"], &env),
            row("outside_roots", EXT, &["--output-format", "stream-json", "--new-flag"], &env),
            row("unconfigured", EXT, &["--output-format", "stream-json", "--new-flag"], &env),
            json!({"ext": EXT, "argv": ["/w", "/b", "--new-flag"], "env_names": env}),
            // A session row of another extension.
            row("session", "2.1.309", &["--new-flag"], &env),
        ];
        assert!(unknown_flags(&rows, EXT).is_empty());
        assert!(unreviewed_env_names(&rows, EXT, &w).is_empty());
        assert!(forwarded_env_names_gone(&rows, EXT, &w).is_empty());
        assert!(env_and_flag_rows(&rows, &[window(EXT)], &w).is_empty());
        // The same rows as a session's would be named.
        let as_session: Vec<Value> = rows.iter().map(|r| json!({"reason": "session", "ext": EXT, "argv": r["argv"], "env_names": r["env_names"]})).collect();
        assert_eq!(unknown_flags(&as_session, EXT), s(&["--env", "--json", "--new-flag", "--scope", "--status", "--transport"]));
    }

    #[test]
    fn no_running_window_no_env_or_flag_row() {
        let w = WrapperCfg::default();
        let rows = vec![session(&["--new-flag"], &["CLAUDE_CODE_NEW_THING"])];
        assert_eq!(env_and_flag_rows(&rows, &[window(EXT)], &w).len(), 3, "the control: an env row, a gone row, a flag row");
        assert!(env_and_flag_rows(&rows, &[], &w).is_empty());
        // Two windows on one version: its rows once; a window on another version: that version's rows only.
        assert_eq!(env_and_flag_rows(&rows, &[window(EXT), window(EXT)], &w).len(), 3);
        assert!(env_and_flag_rows(&rows, &[window("2.1.309")], &w).is_empty());
        // Doctor's call: no root, no census, or no window still running: no env or flag row.
        let ext_dir = tempfile::tempdir().unwrap();
        assert!(doctor_rows(None, ext_dir.path(), &w).is_empty());
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(root.path().to_path_buf(), None);
        assert!(doctor_rows(Some(&paths), ext_dir.path(), &w).is_empty(), "no census");
        std::fs::create_dir_all(paths.logs()).unwrap();
        let census = |host: u32| {
            let r = json!({"v": 1, "ts": "2026-10-23T10:00:00Z", "start": crate::wire::time::unix_now_ms(), "pid": 4243, "ppid": host, "ext": EXT, "route": "remote", "reason": "session",
                "argv": ["/w/ai-env-claude", "/b/claude", "--new-flag"], "env_names": ["CLAUDE_CODE_NEW_THING"]});
            std::fs::write(paths.census(), format!("{r}\n")).unwrap();
        };
        // A host no process holds (macOS pids stay below 100000).
        census(999_999);
        assert!(doctor_rows(Some(&paths), ext_dir.path(), &w).is_empty(), "the window is gone");
        // This test process as the window's live host: its rows, after which the view rows (none: no bundle).
        census(std::process::id());
        let lines = texts(&doctor_rows(Some(&paths), ext_dir.path(), &w));
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].starts_with("[!! ] extension 2.1.310 starts chats with env names neither forwarded nor reviewed: CLAUDE_CODE_NEW_THING  <- "), "{lines:?}");
        assert!(lines[1].starts_with("[-  ] extension 2.1.310 starts chats without CLAUDE_AGENT_SDK_VERSION, "), "{lines:?}");
        assert!(lines[2].starts_with("[!! ] extension 2.1.310 passes flags the router does not classify: --new-flag  <- "), "{lines:?}");
        assert_eq!(lines[3], "[-  ] view format: 2.1.310's extension.js cannot be read (missing)");
    }

    #[test]
    fn the_view_row_is_ok_with_every_reader_string_and_names_the_missing_ones() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "2.1.310", &every_string());
        // Without `"ai-title"` (its bare word stays, unquoted) and `teamName`.
        let lacking = every_string().replace("a.\"ai-title\"=b;", "ai-title").replace("teamName", "team");
        bundle(dir.path(), "2.1.311", &lacking);
        let read = |v: &str| read_extension_js(dir.path(), v);
        assert_eq!(
            texts(&view_rows(&s(&["2.1.310", "2.1.311"]), &read)),
            vec![
                "[ok ] view format: 2.1.310's reader still names the view's fields (pinned at 2.1.302)".to_string(),
                "[!! ] view format: 2.1.311's reader lacks: \"ai-title\", teamName  <- re-check src/wire/view.rs".to_string(),
            ]
        );
        // Doctor's call with no census: the installed bundle (the highest) alone.
        assert_eq!(texts(&doctor_rows(None, dir.path(), &WrapperCfg::default())), vec!["[!! ] view format: 2.1.311's reader lacks: \"ai-title\", teamName  <- re-check src/wire/view.rs".to_string()]);
        // Every string missing: at most DRIFT_LIST_MAX named.
        bundle(dir.path(), "2.1.312", "nothing here");
        let lines = texts(&view_rows(&s(&["2.1.312"]), &read));
        assert!(lines[0].ends_with(&format!(" (+{} more)  <- re-check src/wire/view.rs", VIEW_READER_STRINGS.len() - DRIFT_LIST_MAX)), "{lines:?}");
    }

    #[test]
    fn a_version_at_or_below_the_pin_has_no_view_row() {
        let never = |v: &str| -> Result<Vec<u8>, String> { panic!("{v}'s bundle is never read") };
        let low = s(&["2.1.302", "2.1.301", "2.0.999", "1.9.400", "2.1.302-beta", "2.1.302+b", "2.1.302.9", "unrecognised", "2.1", "2.1.x", ""]);
        assert!(view_rows(&low, &never).is_empty());
        // Newer, numerically (2.1.1000 is newer than 2.1.302), a suffixed one by its core; each version once.
        let ok = |_: &str| -> Result<Vec<u8>, String> { Ok(every_string().into_bytes()) };
        let lines = texts(&view_rows(&s(&["2.1.1000", "2.1.303-beta", "3.0.0", "2.1.1000", "2.1.302", "2.1.303.1"]), &ok));
        assert_eq!(
            lines.iter().map(|l| l.split('\'').next().unwrap_or_default()).collect::<Vec<_>>(),
            ["[ok ] view format: 2.1.1000", "[ok ] view format: 2.1.303-beta", "[ok ] view format: 3.0.0", "[ok ] view format: 2.1.303.1"]
        );
    }

    #[test]
    fn an_unreadable_bundle_is_a_note() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let at = |v: &str| p.join(format!("anthropic.claude-code-{v}-darwin-arm64"));
        // No extension.js; a symlink to a good one; a directory; a FIFO (never waited on); one over VIEW_JS_MAX.
        std::fs::create_dir_all(at("2.1.310")).unwrap();
        bundle(p, "2.1.400", &every_string());
        std::fs::create_dir_all(at("2.1.311")).unwrap();
        std::os::unix::fs::symlink(at("2.1.400").join("extension.js"), at("2.1.311").join("extension.js")).unwrap();
        std::fs::create_dir_all(at("2.1.312").join("extension.js")).unwrap();
        std::fs::create_dir_all(at("2.1.313")).unwrap();
        let fifo = std::ffi::CString::new(at("2.1.313").join("extension.js").to_string_lossy().into_owned()).unwrap();
        // SAFETY: mkfifo reads the NUL-terminated path `fifo` owns and nothing else.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::fs::create_dir_all(at("2.1.314")).unwrap();
        std::fs::File::create(at("2.1.314").join("extension.js")).unwrap().set_len(VIEW_JS_MAX + 1).unwrap();
        let read = |v: &str| read_extension_js(p, v);
        assert_eq!(
            texts(&view_rows(&s(&["2.1.309-gone", "2.1.310", "2.1.311", "2.1.312", "2.1.313", "2.1.314", "2.1.400"]), &read)),
            vec![
                "[-  ] view format: 2.1.309-gone's extension.js cannot be read (missing)".to_string(),
                "[-  ] view format: 2.1.310's extension.js cannot be read (missing)".to_string(),
                "[-  ] view format: 2.1.311's extension.js cannot be read (a symlink)".to_string(),
                "[-  ] view format: 2.1.312's extension.js cannot be read (not a regular file)".to_string(),
                "[-  ] view format: 2.1.313's extension.js cannot be read (not a regular file)".to_string(),
                "[-  ] view format: 2.1.314's extension.js cannot be read (larger than 64 MiB)".to_string(),
                "[ok ] view format: 2.1.400's reader still names the view's fields (pinned at 2.1.302)".to_string(),
            ]
        );
        // Any reader's error is the note's why.
        assert_eq!(texts(&view_rows(&s(&["2.1.310"]), &|_| Err("denied".to_string()))), vec!["[-  ] view format: 2.1.310's extension.js cannot be read (denied)".to_string()]);
        assert_eq!(read_extension_js(p, "../2.1.310"), Err("not a version".to_string()));
    }

    /// S12 (R2-6): a refresh name an extension sets (`remote::env::HOST_REFRESH_NAMES`, which `[wrapper]` refuses) is
    /// accounted: neither the `[!! ]` row's nor the refused row's (`refused_name` does not refuse it), so a 2.1.310
    /// window that sets both beside the forwarded names shows no env row at all.
    #[test]
    fn a_host_refresh_name_is_accounted_never_unreviewed() {
        let w = WrapperCfg::default();
        let env: Vec<&str> = forwarded().into_iter().chain(HOST_REFRESH_NAMES).collect();
        let rows = vec![session(&["--verbose"], &env)];
        assert!(unreviewed_env_names(&rows, EXT, &w).is_empty(), "{:?}", unreviewed_env_names(&rows, EXT, &w));
        assert!(refused_env_names(&rows, EXT).is_empty(), "{:?}", refused_env_names(&rows, EXT));
        assert_eq!(texts(&env_and_flag_rows(&rows, &[window(EXT)], &w)), Vec::<String>::new());
    }

    /// S12 (R2): `ENV_REVIEWED` keeps the two names no session forwards, and none of the default `env_forward`'s:
    /// a reviewed name that is also forwarded by default would hide a list that left it out (R2-2).
    #[test]
    fn no_reviewed_name_is_a_default_forwarded_one() {
        assert_eq!(ENV_REVIEWED.iter().map(|(n, _)| *n).collect::<Vec<_>>(), ["CLAUDE_CODE_CONFIG_PROBE", "CLAUDE_CODE_EMIT_STARTUP_TIMING"]);
        let forward = WrapperCfg::default().env_forward;
        for (name, _) in ENV_REVIEWED {
            assert!(!forward.iter().any(|n| n == name), "{name} is reviewed and forwarded by default");
        }
    }

    /// S12 (R2-6): a window on an extension older than the two names (2.1.300: its chats carry the five relevant
    /// names forwarded before S12) gets the existing gone row for the two, exactly, and nothing else.
    #[test]
    fn an_older_window_lacking_the_s12_names_gets_the_gone_note() {
        let w = WrapperCfg::default();
        let pre_s12 = ["CLAUDE_CODE_ENTRYPOINT", "CLAUDE_AGENT_SDK_VERSION", "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING", "MCP_CONNECTION_NONBLOCKING", "CLAUDE_CODE_ENABLE_TASKS"];
        let rows = vec![row("session", "2.1.300", &["--verbose"], &pre_s12)];
        assert_eq!(
            texts(&env_and_flag_rows(&rows, &[window("2.1.300")], &w)),
            vec!["[-  ] extension 2.1.300 starts chats without CLAUDE_CODE_QUESTION_PREVIEW_FORMAT, CLAUDE_CODE_SDK_READS_SESSION_STATE, which [wrapper].env_forward forwards".to_string()]
        );
    }
}
