//! `ai-env wrapper install` and `ai-env wrapper census` (plan §7 and §3
//! "Probes"). `install` points Cursor's `claudeCode.claudeProcessWrapper` at
//! the sibling `ai-env-claude` by splicing two string-valued keys into
//! `settings.json` textually — comments and key order survive — and a
//! round-trip check makes a bad splice impossible to write. `census` prints
//! `logs/census.jsonl` and, with `--record-probes`, derives the two S1
//! verdicts from the newest session row into `lab/probes.jsonl`.
use crate::bridge::census::read_rows;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::doctor::{cursor_settings_path, parse_settings, run_capture, version_token, PERMISSION_SETTING, WRAPPER_SETTING};
use crate::bridge::logging::open_log_file;
use crate::bridge::sibling::{exists_exec, require_sibling, INSTALL_HINT};
use crate::errors::{CliError, Result};
use crate::store::write_atomic;
use crate::wire::time::{rfc3339_utc, unix_now};
use crate::{bail, outln};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The values Cursor accepts for `claudeCode.initialPermissionMode`
/// (`manual` reaches the CLI as `--permission-mode default`).
pub const PERMISSION_MODES: [&str; 5] = ["default", "manual", "acceptEdits", "plan", "bypassPermissions"];

/// A wrapper path with one of these suffixes is handed to node by the
/// extension, with the arguments transposed: the wrapper must stay a native
/// extensionless binary.
const NODE_SUFFIXES: [&str; 5] = [".js", ".mjs", ".ts", ".tsx", ".jsx"];

/// The name of the environment variable whose absence from a session's
/// `env_names` is the `stock-ext-oauth` verdict.
const OAUTH_REFRESH_VAR: &str = "CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH";

/// The stage every probe recorded by this command is stamped with.
const PROBE_STAGE: &str = "S1";

/// One line of `lab/probes.jsonl`: a version-stamped verdict for one probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRow {
    /// `entrypoint` or `stock-ext-oauth`.
    pub probe: String,
    /// The stage that recorded the row (`S1`).
    pub stage: String,
    /// The extension bundle version of the session row the verdict came from.
    pub ext: Option<String>,
    /// `CLAUDE_AGENT_SDK_VERSION` of that session, when recorded.
    pub sdk: Option<String>,
    /// What was observed.
    pub verdict: String,
    /// What the stage expects; a row whose verdict differs is a failed probe.
    pub expected: String,
    /// RFC 3339 seconds, when the verdict was derived.
    pub ts: String,
}

// ---- probes ------------------------------------------------------------------------

/// The two S1 verdicts, derived from one census session row (pure):
/// `entrypoint` is `env_selected.CLAUDE_CODE_ENTRYPOINT` (`missing` when
/// absent; expected `claude-vscode`), `stock-ext-oauth` is `present` or
/// `absent` by whether `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH` appears in
/// `env_names` (expected `absent`). `ext` and `sdk` are copied from the row;
/// `ts` is now.
#[must_use]
pub fn probe_verdicts(row: &serde_json::Value) -> Vec<ProbeRow> {
    let text = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).map(str::to_string);
    let ext = text(row.get("ext"));
    let sdk = text(row.pointer("/env_selected/CLAUDE_AGENT_SDK_VERSION"));
    let ts = rfc3339_utc(unix_now());
    let entrypoint = text(row.pointer("/env_selected/CLAUDE_CODE_ENTRYPOINT")).unwrap_or_else(|| "missing".to_string());
    let has_oauth = row.get("env_names").and_then(|n| n.as_array()).is_some_and(|names| names.iter().any(|n| n.as_str() == Some(OAUTH_REFRESH_VAR)));
    vec![
        ProbeRow {
            probe: "entrypoint".to_string(),
            stage: PROBE_STAGE.to_string(),
            ext: ext.clone(),
            sdk: sdk.clone(),
            verdict: entrypoint,
            expected: "claude-vscode".to_string(),
            ts: ts.clone(),
        },
        ProbeRow {
            probe: "stock-ext-oauth".to_string(),
            stage: PROBE_STAGE.to_string(),
            ext,
            sdk,
            verdict: if has_oauth { "present" } else { "absent" }.to_string(),
            expected: "absent".to_string(),
            ts,
        },
    ]
}

/// A census row that went through the session classifier: `route` is
/// `remote`, or the reason is one of the two demoted session reasons.
fn is_session_row(row: &serde_json::Value) -> bool {
    let field = |k: &str| row.get(k).and_then(|v| v.as_str()).unwrap_or("");
    field("route") == "remote" || matches!(field("reason"), "outside_roots" | "unconfigured")
}

/// `--record-probes`: derive the verdicts from the newest session row, print
/// a diff against the last recorded row of each probe, append every row to
/// `lab/probes.jsonl` (one `write` each), and fail AFTER writing when any
/// verdict differs from its expectation.
fn record_probes(paths: &Paths, rows: &[serde_json::Value]) -> Result<()> {
    let Some(session) = rows.iter().rev().find(|r| is_session_row(r)) else {
        bail!("no session row in the census yet — open a Cursor chat with the wrapper installed");
    };
    let verdicts = probe_verdicts(session);
    let probes_path = paths.probes();
    let existing = read_rows(&probes_path, None)?;
    let mut file = open_log_file(&probes_path)?;
    let mut failed = Vec::new();
    for v in &verdicts {
        let previous = existing.iter().rev().find(|r| r.get("probe").and_then(|p| p.as_str()) == Some(v.probe.as_str()));
        if let Some(old) = previous.and_then(|r| r.get("verdict")).and_then(|o| o.as_str()) {
            if old != v.verdict {
                outln!("probe {}: {old} -> {}", v.probe, v.verdict);
            }
        }
        let mut line = serde_json::to_vec(v).map_err(|e| CliError::Msg(format!("probe row: {e}")))?;
        line.push(b'\n');
        let written = file.write(&line)?;
        if written != line.len() {
            bail!("short probe write: {written} of {} bytes to {}", line.len(), probes_path.display());
        }
        outln!("recorded {}={} (expected {})", v.probe, v.verdict, v.expected);
        if v.verdict != v.expected {
            failed.push(format!("{}={} (expected {})", v.probe, v.verdict, v.expected));
        }
    }
    if !failed.is_empty() {
        bail!("probe verdict differs from the expectation: {}", failed.join(", "));
    }
    Ok(())
}

// ---- census ------------------------------------------------------------------------

/// The text rendering of one census row: `ts route reason ext cwd argv[2..]`
/// (the argv tail joined by spaces, at most 120 characters, `…` when cut).
fn census_line(row: &serde_json::Value) -> String {
    let field = |k: &str| row.get(k).and_then(|v| v.as_str()).unwrap_or("-").to_string();
    let argv: Vec<&str> = row.get("argv").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|t| t.as_str()).collect()).unwrap_or_default();
    let tail = argv.iter().skip(2).copied().collect::<Vec<_>>().join(" ");
    let tail = if tail.chars().count() > 120 { format!("{}\u{2026}", tail.chars().take(119).collect::<String>()) } else { tail };
    format!("{}  {:<6} {:<24} {}  {}  {tail}", field("ts"), field("route"), field("reason"), field("ext"), field("cwd"))
}

/// `ai-env wrapper census [--last N] [--json] [--record-probes]`: print the
/// census (one text line or one raw JSON line per row; a missing file prints
/// `no census yet` and exits 0), then optionally record the probes from the
/// newest session row of the whole census (not just the last `N`).
pub fn census(last: Option<usize>, json: bool, record_probes_flag: bool) -> Result<()> {
    let paths = Paths::resolve().map_err(|e| CliError::Msg(e.to_string()))?;
    let path = paths.census();
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        outln!("no census yet at {}", path.display());
        return Ok(());
    }
    let rows = read_rows(&path, None)?;
    let shown = &rows[rows.len().saturating_sub(last.unwrap_or(rows.len()))..];
    for row in shown {
        if json {
            outln!("{row}");
        } else {
            outln!("{}", census_line(row));
        }
    }
    if record_probes_flag {
        record_probes(&paths, &rows)?;
    }
    Ok(())
}

// ---- settings.json splice --------------------------------------------------------------

/// The indentation of the first indented line: `"\t"` for a tab, four spaces
/// for four or more, else two spaces (the default when nothing is indented).
#[must_use]
pub fn detect_indent(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.len() == line.len() {
            continue;
        }
        let ws = &line[..line.len() - trimmed.len()];
        if ws.starts_with('\t') {
            return "\t".to_string();
        }
        return if ws.len() >= 4 { "    ".to_string() } else { "  ".to_string() };
    }
    "  ".to_string()
}

/// A significant token of a JSONC document, with its byte span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Open(u8),
    Close(u8),
    Comma,
    Colon,
    Str,
    Scalar,
}

#[derive(Debug, Clone, Copy)]
struct Token {
    tok: Tok,
    start: usize,
    end: usize,
}

/// Tokenise `text` outside strings and comments. Every boundary lands on an
/// ASCII byte, so byte offsets are always char boundaries.
fn tokenize(text: &str) -> std::result::Result<Vec<Token>, String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut j = i + 2;
                while j + 1 < b.len() && !(b[j] == b'*' && b[j + 1] == b'/') {
                    j += 1;
                }
                if j + 1 >= b.len() {
                    return Err(format!("unterminated block comment at byte {i}"));
                }
                i = j + 2;
            }
            b'"' => {
                let start = i;
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err(format!("unterminated string at byte {start}")),
                        Some(b'\\') => i += 2,
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(Token { tok: Tok::Str, start, end: i.min(b.len()) });
            }
            b'{' | b'[' => {
                out.push(Token { tok: Tok::Open(c), start: i, end: i + 1 });
                i += 1;
            }
            b'}' | b']' => {
                out.push(Token { tok: Tok::Close(c), start: i, end: i + 1 });
                i += 1;
            }
            b',' => {
                out.push(Token { tok: Tok::Comma, start: i, end: i + 1 });
                i += 1;
            }
            b':' => {
                out.push(Token { tok: Tok::Colon, start: i, end: i + 1 });
                i += 1;
            }
            _ => {
                let start = i;
                while i < b.len() {
                    let d = b[i];
                    let comment = d == b'/' && matches!(b.get(i + 1), Some(b'/') | Some(b'*'));
                    if matches!(d, b' ' | b'\t' | b'\r' | b'\n' | b',' | b'}' | b']' | b':' | b'"' | b'{' | b'[') || comment {
                        break;
                    }
                    i += 1;
                }
                if i == start {
                    return Err(format!("unexpected character at byte {start}"));
                }
                out.push(Token { tok: Tok::Scalar, start, end: i });
            }
        }
    }
    Ok(out)
}

/// One member of the top-level object: the key's string span and the value's span.
#[derive(Debug, Clone, Copy)]
struct Member {
    key_start: usize,
    key_end: usize,
    value_start: usize,
    value_end: usize,
}

/// The top-level object of a JSONC document as spans over the text.
#[derive(Debug)]
struct TopLevel {
    members: Vec<Member>,
    /// Byte offset of the final `}`.
    close: usize,
    /// The token just before the final `}`: the opening `{` (empty object),
    /// a trailing comma, or the last value's end — decides how a new member
    /// is joined.
    before_close: Token,
}

/// Index of the token closing the group opened at `open`.
fn matching_close(tokens: &[Token], open: usize) -> std::result::Result<usize, String> {
    let mut depth = 0usize;
    for (i, t) in tokens.iter().enumerate().skip(open) {
        match t.tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err(format!("unbalanced brackets from byte {}", tokens[open].start))
}

/// Parse the members of the top-level object; anything after its `}` is an error.
fn top_level(tokens: &[Token]) -> std::result::Result<TopLevel, String> {
    match tokens.first() {
        Some(Token { tok: Tok::Open(b'{'), .. }) => {}
        _ => return Err("the top-level value is not an object".to_string()),
    }
    let end = matching_close(tokens, 0)?;
    if end + 1 != tokens.len() {
        return Err("content after the top-level object".to_string());
    }
    let mut members = Vec::new();
    let mut i = 1;
    while i < end {
        let key = tokens[i];
        if key.tok != Tok::Str {
            return Err(format!("expected a key at byte {}", key.start));
        }
        match tokens.get(i + 1) {
            Some(Token { tok: Tok::Colon, .. }) => {}
            _ => return Err(format!("expected ':' after the key at byte {}", key.start)),
        }
        let value = tokens.get(i + 2).ok_or_else(|| format!("missing value for the key at byte {}", key.start))?;
        let value_last = match value.tok {
            Tok::Str | Tok::Scalar => i + 2,
            Tok::Open(_) => matching_close(tokens, i + 2)?,
            _ => return Err(format!("expected a value at byte {}", value.start)),
        };
        members.push(Member { key_start: key.start, key_end: key.end, value_start: value.start, value_end: tokens[value_last].end });
        i = value_last + 1;
        match tokens[i].tok {
            Tok::Comma => i += 1,
            Tok::Close(b'}') => {}
            _ => return Err(format!("expected ',' or '}}' at byte {}", tokens[i].start)),
        }
    }
    Ok(TopLevel { members, close: tokens[end].start, before_close: tokens[end - 1] })
}

/// Replace the value of the depth-1 string key `key` in place, or insert
/// `"key": "value"` before the final `}` with the detected indent.
fn upsert(text: &str, key: &str, value: &str) -> std::result::Result<String, String> {
    let tokens = tokenize(text)?;
    let top = top_level(&tokens)?;
    let literal = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let existing = top.members.iter().find(|m| serde_json::from_str::<String>(&text[m.key_start..m.key_end]).is_ok_and(|k| k == key));
    if let Some(m) = existing {
        return Ok(format!("{}{literal}{}", &text[..m.value_start], &text[m.value_end..]));
    }
    let key_literal = serde_json::to_string(key).map_err(|e| e.to_string())?;
    let indent = detect_indent(text);
    let close = top.close;
    // Everything before `}`, with a comma appended to the previous member
    // when the object is neither empty nor already trailing-comma'd. The comma
    // goes right after the value, never after a comment that may follow it.
    let mut head = match top.before_close.tok {
        Tok::Open(_) | Tok::Comma => text[..close].to_string(),
        _ => format!("{},{}", &text[..top.before_close.end], &text[top.before_close.end..close]),
    };
    // The whitespace on the `}` line is its own indentation: keep it in front of `}`.
    let brace_ws_len = head.len() - head.trim_end_matches([' ', '\t']).len();
    let brace_ws = head[head.len() - brace_ws_len..].to_string();
    head.truncate(head.len() - brace_ws_len);
    if !head.ends_with('\n') {
        head.push('\n');
    }
    let trailing_comma = if top.before_close.tok == Tok::Comma { "," } else { "" };
    Ok(format!("{head}{indent}{key_literal}: {literal}{trailing_comma}\n{brace_ws}{}", &text[close..]))
}

/// A JSONC-safe top-level upsert of string-valued keys: each existing key's
/// value is replaced in place, each missing key is inserted before the final
/// `}` (a comma is added to the previous member when needed; `{}`, `{\n}`, a
/// trailing comma and a missing final newline are handled), and nothing
/// outside the touched values changes — comments and order included. Then
/// the result is verified: `parse_settings(new)` must equal
/// `parse_settings(text)` with `entries` applied, else `Err` and the caller
/// writes nothing.
pub fn splice_settings(text: &str, entries: &[(&str, &str)]) -> std::result::Result<String, String> {
    let old = parse_settings(text).map_err(|e| format!("cannot parse the settings: {e}"))?;
    let mut expected = old;
    let obj = expected.as_object_mut().ok_or_else(|| "the top-level value is not an object".to_string())?;
    for (key, value) in entries {
        obj.insert((*key).to_string(), serde_json::Value::String((*value).to_string()));
    }
    let mut out = text.to_string();
    for (key, value) in entries {
        out = upsert(&out, key, value)?;
    }
    let got = parse_settings(&out).map_err(|e| format!("splice verification failed: the result does not parse: {e}"))?;
    if got != expected {
        return Err("splice verification failed: the result is not the old settings plus the new keys".to_string());
    }
    Ok(out)
}

// ---- install -------------------------------------------------------------------------

/// `(size, mtime)` of the settings file, the pair `--write` re-checks before
/// touching it; `None` when the file does not exist.
fn stamp(meta: Option<&std::fs::Metadata>) -> Option<(u64, Option<SystemTime>)> {
    meta.map(|m| (m.len(), m.modified().ok()))
}

/// The exact keys the command writes, as a JSON snippet for the manual path.
fn snippet(wrapper: &str, mode: &str) -> String {
    format!("{{\n  {}: {},\n  {}: {}\n}}", json_str(WRAPPER_SETTING), json_str(wrapper), json_str(PERMISSION_SETTING), json_str(mode))
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("{s:?}"))
}

/// The backup name next to `path`: `settings.json.<unix seconds>.ai-env.bak`.
fn backup_path(path: &Path, now: u64) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "settings.json".to_string());
    path.with_file_name(format!("{name}.{now}.ai-env.bak"))
}

/// `ai-env wrapper install [--write] [--permission-mode M]` (plan §7): find
/// and check the sibling wrapper, pick the permission mode, splice the two
/// keys into Cursor's `settings.json` (dry run unless `write`; a backup and
/// a size/mtime re-check guard the write) and print the guidance block.
pub fn install(write: bool, permission_mode: Option<String>) -> Result<()> {
    // 1. The sibling: absolute, not canonicalised (`<dir of ai-env>/ai-env-claude`).
    let (sibling, note) = require_sibling("ai-env-claude")?;
    if let Some(note) = note {
        outln!("note: {note}");
    }
    let sibling = if sibling.is_absolute() { sibling } else { std::env::current_dir()?.join(sibling) };
    let Some(wrapper) = sibling.to_str().map(str::to_string) else {
        bail!("{} is not valid UTF-8; settings.json cannot hold it", sibling.display());
    };
    if sibling.components().any(|c| c.as_os_str() == "target") {
        eprintln!("ai-env: warning: {wrapper} is under a build directory: cargo clean breaks Cursor; re-run ai-env wrapper install --write from the installed ai-env");
    }
    // 2. Executable, and never a node script.
    match exists_exec(&sibling) {
        (false, _) => bail!("{wrapper} does not exist"),
        (true, false) => bail!("{wrapper} is not executable"),
        (true, true) => {}
    }
    if NODE_SUFFIXES.iter().any(|s| wrapper.ends_with(s)) {
        bail!("{wrapper} ends in a JS/TS suffix: Cursor would run it under node (an extensionless native binary is required)");
    }
    // 3. Same version as this binary.
    let mine = env!("CARGO_PKG_VERSION");
    let banner = run_capture(&wrapper, &["--version"], Duration::from_secs(5)).map_err(|e| CliError::Msg(format!("ai-env-claude --version: {e}")))?;
    let Some(theirs) = version_token(&banner) else {
        bail!("ai-env-claude --version printed no version: {banner:?}");
    };
    if theirs != mine {
        bail!("version skew: ai-env {mine}, ai-env-claude {theirs}  <- {INSTALL_HINT}");
    }
    // 4. The permission mode: the flag, else `[wrapper].initial_permission_mode`, else `default`.
    let mode = match permission_mode {
        Some(m) => m,
        None => Paths::resolve()
            .ok()
            .and_then(|p| BridgeConfig::load(&p).ok().flatten())
            .map_or_else(|| "default".to_string(), |c| c.wrapper.initial_permission_mode),
    };
    if !PERMISSION_MODES.contains(&mode.as_str()) {
        return Err(CliError::Usage(format!("permission mode {mode:?} is not one of {}", PERMISSION_MODES.join(", "))));
    }
    // 5. The settings file: a symlink is refused, a missing file is `{}`.
    let path = cursor_settings_path();
    let snippet = snippet(&wrapper, &mode);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => {
            outln!("add these keys to {} by hand:", path.display());
            outln!("{snippet}");
            bail!("{} is a symlink — refusing to edit it", path.display());
        }
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("cannot stat {}: {e}", path.display()),
    };
    let before = stamp(meta.as_ref());
    let old_text = match &meta {
        Some(_) => std::fs::read_to_string(&path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?,
        None => "{}\n".to_string(),
    };
    // 6. It must parse (JSONC tolerated).
    let old = match parse_settings(&old_text) {
        Ok(v) => v,
        Err(e) => {
            outln!("add these keys to {} by hand:", path.display());
            outln!("{snippet}");
            bail!("cannot parse {}: {e}", path.display());
        }
    };
    // 7. The splice, verified inside `splice_settings`.
    let entries = [(WRAPPER_SETTING, wrapper.as_str()), (PERMISSION_SETTING, mode.as_str())];
    let new_text = match splice_settings(&old_text, &entries) {
        Ok(t) => t,
        Err(e) => {
            outln!("add these keys to {} by hand:", path.display());
            outln!("{snippet}");
            bail!("{}: {e}", path.display());
        }
    };
    // 8. Report; write only on request.
    outln!("wrapper:  {wrapper}");
    outln!("versions: ai-env {mine}, ai-env-claude {theirs}");
    outln!("settings: {}{}", path.display(), if meta.is_some() { "" } else { " (will be created)" });
    for (key, new) in &entries {
        let current = old.get(*key).and_then(|v| v.as_str());
        match current {
            Some(c) if c == *new => outln!("  {key}: {c:?} (unchanged)"),
            Some(c) => outln!("  {key}: {c:?} -> {new:?}"),
            None => outln!("  {key}: unset -> {new:?}"),
        }
    }
    if mode == "manual" {
        outln!("note: initialPermissionMode = manual reaches the CLI as --permission-mode default");
    }
    outln!("snippet:");
    outln!("{snippet}");
    if write {
        match commit_settings(&path, meta.as_ref(), before, &old_text, &new_text)? {
            Some(bak) => outln!("backup: {}", bak.display()),
            None => outln!("backup: none (no settings.json before)"),
        }
        outln!("wrote: {}", path.display());
    } else {
        outln!("dry run: nothing written; re-run with --write");
    }
    // 9. Always: what changes for Cursor and how to undo it.
    outln!();
    outln!("claudeCode.disableLoginPrompt is left alone (set it only once the bridge delivers credentials, S7).");
    outln!("Wrapped setups start in Manual mode: the extension now passes --permission-mode {mode} on every spawn (choose with --permission-mode).");
    outln!("Reload the Cursor window for the setting to take effect.");
    outln!("With a wrapper set the extension stops self-updating and stops following CLAUDE_CONFIG_DIR changes.");
    outln!("AI_ENV_BRIDGE_LOCAL=1 is the kill switch: the wrapper execs the bundled binary directly, without a census.");
    Ok(())
}

/// The write phase of `install --write`, separated so the guards are unit
/// testable: re-stat the file and refuse when its size or mtime moved since
/// `before` (Cursor rewrites the whole file on any settings change), copy the
/// old text to `settings.json.<unix seconds>.ai-env.bak` (never clobbering,
/// with the original file's mode), write the new text atomically and restore
/// the original mode (`write_atomic` leaves 0600). Returns the backup path,
/// `None` when there was no file before.
pub(crate) fn commit_settings(path: &Path, meta: Option<&std::fs::Metadata>, before: Option<(u64, Option<SystemTime>)>, old_text: &str, new_text: &str) -> Result<Option<PathBuf>> {
    let now_meta = match std::fs::symlink_metadata(path) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("cannot stat {}: {e}", path.display()),
    };
    if stamp(now_meta.as_ref()) != before {
        bail!("settings.json changed while editing; re-run");
    }
    let backup = match meta {
        Some(m) => {
            let bak = backup_path(path, unix_now());
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                opts.mode(m.permissions().mode() & 0o777);
            }
            let mut f = opts.open(&bak).map_err(|e| CliError::Msg(format!("cannot create backup {}: {e}", bak.display())))?;
            f.write_all(old_text.as_bytes())?;
            f.sync_all()?;
            drop(f);
            Some(bak)
        }
        None => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| CliError::Msg(format!("cannot create {}: {e}", dir.display())))?;
            }
            None
        }
    };
    write_atomic(path, new_text.as_bytes())?;
    if let Some(m) = meta {
        // write_atomic leaves 0600; Cursor's file is normally 0644.
        std::fs::set_permissions(path, m.permissions())?;
    }
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn commit_refuses_a_file_that_changed_underneath_and_copies_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{\n  \"a\": 1\n}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let before = stamp(Some(&meta));
        // Something (Cursor) rewrites the file between the read and the write.
        std::fs::write(&path, "{\n  \"a\": 1,\n  \"b\": 2\n}\n").unwrap();
        let err = commit_settings(&path, Some(&meta), before, "{\n  \"a\": 1\n}\n", "{\n  \"a\": 1,\n  \"x\": \"y\"\n}\n").unwrap_err();
        assert!(err.to_string().contains("changed while editing"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\n  \"a\": 1,\n  \"b\": 2\n}\n", "nothing written");
        assert!(std::fs::read_dir(dir.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".ai-env.bak")), "no backup");

        // The same call with a fresh stamp succeeds: backup with the original
        // mode, new text in place, mode restored.
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let before = stamp(Some(&meta));
        let old = std::fs::read_to_string(&path).unwrap();
        let bak = commit_settings(&path, Some(&meta), before, &old, "{\n  \"a\": 1,\n  \"b\": 2,\n  \"x\": \"y\"\n}\n").unwrap().expect("a backup");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), old);
        assert_eq!(std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777, 0o644, "the backup carries the original mode");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644, "the original mode is restored");
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"x\": \"y\""));

        // No file before: no backup, the parent is created.
        let fresh = dir.path().join("new").join("settings.json");
        assert_eq!(commit_settings(&fresh, None, None, "{}\n", "{\n  \"x\": \"y\"\n}\n").unwrap(), None);
        assert!(fresh.is_file());
    }

    /// The top-level keys in FILE order: serde's map is sorted, so the order
    /// has to be read from the text itself.
    fn keys(text: &str) -> Vec<String> {
        let tokens = tokenize(text).unwrap();
        top_level(&tokens).unwrap().members.iter().map(|m| serde_json::from_str::<String>(&text[m.key_start..m.key_end]).unwrap()).collect()
    }

    #[test]
    fn splice_into_an_empty_object() {
        let out = splice_settings("{}", &[("a.b", "x")]).unwrap();
        assert_eq!(out, "{\n  \"a.b\": \"x\"\n}");
        let out = splice_settings("{}\n", &[("a.b", "x"), ("c", "y")]).unwrap();
        assert_eq!(out, "{\n  \"a.b\": \"x\",\n  \"c\": \"y\"\n}\n");
        let out = splice_settings("{\n}\n", &[("a", "x")]).unwrap();
        assert_eq!(out, "{\n  \"a\": \"x\"\n}\n");
        assert_eq!(parse_settings(&out).unwrap()["a"], "x");
    }

    #[test]
    fn splice_plain_json_keeps_order_and_four_space_indent() {
        let src = "{\n    \"editor.tabSize\": 2,\n    \"nested\": {\"k\": [1, 2]},\n    \"z\": \"last\"\n}\n";
        assert_eq!(detect_indent(src), "    ");
        let out = splice_settings(src, &[(WRAPPER_SETTING, "/x/ai-env-claude"), (PERMISSION_SETTING, "default")]).unwrap();
        assert_eq!(
            out,
            "{\n    \"editor.tabSize\": 2,\n    \"nested\": {\"k\": [1, 2]},\n    \"z\": \"last\",\n    \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n    \"claudeCode.initialPermissionMode\": \"default\"\n}\n"
        );
        assert_eq!(keys(&out), vec!["editor.tabSize", "nested", "z", WRAPPER_SETTING, PERMISSION_SETTING]);
        // A missing final newline and a `}` right after the last value.
        let out = splice_settings("{\"a\": 1}", &[("b", "x")]).unwrap();
        assert_eq!(out, "{\"a\": 1,\n  \"b\": \"x\"\n}");
        // Indented closing brace keeps its indentation.
        let out = splice_settings("{\n  \"a\": 1\n  }", &[("b", "x")]).unwrap();
        assert_eq!(out, "{\n  \"a\": 1,\n  \"b\": \"x\"\n  }");
    }

    #[test]
    fn splice_jsonc_preserves_comments_order_and_trailing_comma() {
        let src = "{\n  // Cursor settings\n  \"editor.tabSize\": 2, /* block */\n  \"url\": \"http://x/y\", // a line comment with \"quotes\"\n  \"list\": [1, 2, ],\n}\n";
        let out = splice_settings(src, &[(WRAPPER_SETTING, "/x/ai-env-claude"), (PERMISSION_SETTING, "manual")]).unwrap();
        assert_eq!(
            out,
            "{\n  // Cursor settings\n  \"editor.tabSize\": 2, /* block */\n  \"url\": \"http://x/y\", // a line comment with \"quotes\"\n  \"list\": [1, 2, ],\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"manual\",\n}\n"
        );
        assert!(out.starts_with(&src[..src.len() - 3]), "everything before the final `}}` is byte-for-byte the original");
        let v = parse_settings(&out).unwrap();
        assert_eq!(v[WRAPPER_SETTING], "/x/ai-env-claude");
        assert_eq!(v[PERMISSION_SETTING], "manual");
        assert_eq!(keys(&out), vec!["editor.tabSize", "url", "list", WRAPPER_SETTING, PERMISSION_SETTING]);
        // A comment between the last value and `}`: the comma lands after the value, not after the comment.
        let out = splice_settings("{\n  \"a\": 1 // one\n}\n", &[("b", "x")]).unwrap();
        assert_eq!(out, "{\n  \"a\": 1, // one\n  \"b\": \"x\"\n}\n");
        let out = splice_settings("{\n  \"a\": 1\n  /* c */\n}\n", &[("b", "x")]).unwrap();
        assert_eq!(out, "{\n  \"a\": 1,\n  /* c */\n  \"b\": \"x\"\n}\n");
    }

    #[test]
    fn splice_replaces_an_existing_value_in_place() {
        let src = "{\n  \"a\": \"one\", // keep\n  \"claudeCode.claudeProcessWrapper\": \"/old/wrapper\", /* keep too */\n  \"z\": true\n}\n";
        let out = splice_settings(src, &[(WRAPPER_SETTING, "/new/ai-env-claude")]).unwrap();
        assert_eq!(out, "{\n  \"a\": \"one\", // keep\n  \"claudeCode.claudeProcessWrapper\": \"/new/ai-env-claude\", /* keep too */\n  \"z\": true\n}\n");
        // A non-string existing value (an object) is replaced whole.
        let out = splice_settings("{\"k\": {\"nested\": [1, {\"deep\": \"}\"}]}, \"z\": 1}", &[("k", "v")]).unwrap();
        assert_eq!(out, "{\"k\": \"v\", \"z\": 1}");
        // Values with characters that need escaping round-trip.
        let out = splice_settings("{}", &[("k", "a \"quoted\" \\ path")]).unwrap();
        assert_eq!(parse_settings(&out).unwrap()["k"], "a \"quoted\" \\ path");
        // An escaped key in the file still matches.
        let out = splice_settings("{\"a\\u002eb\": \"old\"}", &[("a.b", "new")]).unwrap();
        assert_eq!(out, "{\"a\\u002eb\": \"new\"}");
    }

    #[test]
    fn splice_is_not_confused_by_the_key_inside_strings_comments_or_nested_objects() {
        let src = "{\n  // \"claudeCode.claudeProcessWrapper\": \"in a comment\"\n  \"note\": \"\\\"claudeCode.claudeProcessWrapper\\\": in a string\",\n  \"nested\": { \"claudeCode.claudeProcessWrapper\": \"depth 2\" },\n  /* \"claudeCode.claudeProcessWrapper\": \"in a block\" */\n  \"list\": [\"claudeCode.claudeProcessWrapper\"]\n}\n";
        let out = splice_settings(src, &[(WRAPPER_SETTING, "/x/ai-env-claude")]).unwrap();
        // The comma lands right after the last value (`]`), before its newline.
        assert_eq!(out, format!("{}{}", &src[..src.len() - 3], ",\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\"\n}\n"));
        let v = parse_settings(&out).unwrap();
        assert_eq!(v["nested"][WRAPPER_SETTING], "depth 2");
        assert_eq!(v[WRAPPER_SETTING], "/x/ai-env-claude");
    }

    #[test]
    fn splice_refuses_when_verification_would_fail() {
        // Duplicate keys: the scanner rewrites the first, serde reads the last — the round trip catches it.
        let err = splice_settings("{\"a\": \"x\", \"a\": \"y\"}", &[("a", "new")]).unwrap_err();
        assert!(err.starts_with("splice verification failed"), "{err}");
        // The top-level object is not the whole document / not an object at all.
        assert!(splice_settings("{\"a\": 1} {}", &[("a", "x")]).is_err());
        assert!(splice_settings("[1, 2]", &[("a", "x")]).is_err());
        assert!(splice_settings("", &[("a", "x")]).is_err());
        assert!(splice_settings("{\"a\": }", &[("a", "x")]).is_err());
        // The scanner alone rejects the same shapes.
        assert!(top_level(&tokenize("{\"a\": 1} 2").unwrap()).unwrap_err().contains("after the top-level object"));
        assert!(top_level(&tokenize("[1]").unwrap()).unwrap_err().contains("not an object"));
        assert!(tokenize("{\"a\": \"unterminated}").is_err());
        assert!(tokenize("{ /* open").is_err());
    }

    #[test]
    fn detect_indent_cases() {
        assert_eq!(detect_indent("{}"), "  ");
        assert_eq!(detect_indent("{\n  \"a\": 1\n}"), "  ");
        assert_eq!(detect_indent("{\n    \"a\": 1\n}"), "    ");
        assert_eq!(detect_indent("{\n\t\"a\": 1\n}"), "\t");
        assert_eq!(detect_indent("{\n\n   \"a\": 1\n}"), "  ", "three spaces round down to two");
        assert_eq!(detect_indent("{\n        \"a\": 1\n}"), "    ", "eight spaces round down to four");
        assert_eq!(detect_indent("{\n   \n  \"a\": 1\n}"), "  ", "a whitespace-only line is skipped");
    }

    fn session_row(env_names: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "ts": "2026-09-23T08:00:00Z",
            "start": 1_790_150_400_000u64,
            "pid": 4242,
            "ppid": 4200,
            "ext": "2.1.278",
            "route": "remote",
            "reason": "session",
            "argv": ["/Users/mike/.cargo/bin/ai-env-claude", "/Users/mike/.cursor/extensions/anthropic.claude-code-2.1.278-darwin-arm64/resources/native-binary/claude", "--output-format", "stream-json"],
            "cwd": "/Users/mike/Documents/DeFi/ai-env",
            "env_names": env_names,
            "env_selected": {"CLAUDE_CODE_ENTRYPOINT": "claude-vscode", "CLAUDE_AGENT_SDK_VERSION": "0.3.278"},
            "note": null
        })
    }

    #[test]
    fn probe_verdicts_on_a_session_row() {
        let rows = probe_verdicts(&session_row(&["CLAUDE_AGENT_SDK_VERSION", "CLAUDE_CODE_ENTRYPOINT", "HOME", "PATH"]));
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].probe.as_str(), rows[0].verdict.as_str(), rows[0].expected.as_str()), ("entrypoint", "claude-vscode", "claude-vscode"));
        assert_eq!((rows[1].probe.as_str(), rows[1].verdict.as_str(), rows[1].expected.as_str()), ("stock-ext-oauth", "absent", "absent"));
        for r in &rows {
            assert_eq!(r.stage, "S1");
            assert_eq!(r.ext.as_deref(), Some("2.1.278"));
            assert_eq!(r.sdk.as_deref(), Some("0.3.278"));
            assert_eq!(r.ts.len(), 20);
            assert!(r.ts.ends_with('Z'));
            assert_eq!(r.verdict, r.expected, "{}", r.probe);
            let back: ProbeRow = serde_json::from_str(&serde_json::to_string(r).unwrap()).unwrap();
            assert_eq!(&back, r);
        }
        assert!(is_session_row(&session_row(&[])));
    }

    #[test]
    fn probe_verdicts_when_the_oauth_refresh_variable_is_present() {
        let rows = probe_verdicts(&session_row(&["CLAUDE_CODE_ENTRYPOINT", OAUTH_REFRESH_VAR, "PATH"]));
        assert_eq!(rows[1].verdict, "present");
        assert_ne!(rows[1].verdict, rows[1].expected);
        assert_eq!(rows[0].verdict, "claude-vscode");
        // A row without the entrypoint or the SDK version reads as missing.
        let bare = serde_json::json!({"route": "local", "reason": "unconfigured", "env_names": []});
        let rows = probe_verdicts(&bare);
        assert_eq!(rows[0].verdict, "missing");
        assert_eq!((rows[0].ext.as_deref(), rows[0].sdk.as_deref()), (None, None));
        assert_eq!(rows[1].verdict, "absent");
        assert!(is_session_row(&bare));
        assert!(!is_session_row(&serde_json::json!({"route": "local", "reason": "subcommand:auth"})));
    }

    #[test]
    fn census_line_shape_and_truncation() {
        let row = session_row(&[]);
        let line = census_line(&row);
        assert_eq!(line, "2026-09-23T08:00:00Z  remote session                  2.1.278  /Users/mike/Documents/DeFi/ai-env  --output-format stream-json");
        let mut long = row.clone();
        long["argv"] = serde_json::json!(["w", "b", "x".repeat(200)]);
        let line = census_line(&long);
        let tail = line.rsplit("  ").next().unwrap();
        assert_eq!(tail.chars().count(), 120);
        assert!(tail.ends_with('\u{2026}'));
        let none = census_line(&serde_json::json!({"route": "local"}));
        assert!(none.starts_with("-  local  -"), "{none}");
    }

    #[test]
    fn snippet_and_backup_name() {
        let s = snippet("/x/ai-env-claude", "default");
        assert_eq!(s, "{\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\"\n}");
        assert!(parse_settings(&s).is_ok());
        assert_eq!(backup_path(Path::new("/u/User/settings.json"), 17), PathBuf::from("/u/User/settings.json.17.ai-env.bak"));
        assert_eq!(PERMISSION_MODES.len(), 5);
        assert!(PERMISSION_MODES.contains(&"manual"));
    }
}
