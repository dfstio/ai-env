//! `ai-env wrapper install` and `ai-env wrapper census` (plan §7 and §3
//! "Probes"). `install` points Cursor's `claudeCode.claudeProcessWrapper` at
//! the sibling `ai-env-claude` by splicing two string-valued keys into
//! `settings.json` textually — comments and key order survive — and a
//! round-trip check makes a bad splice impossible to write. `census` prints
//! `logs/census.jsonl` and, with `--record-probes`, derives the two S1
//! verdicts from the newest session row (and S8's `init-wrapper` from the
//! remote end rows, once any exist) into `lab/probes.jsonl`.
//!
//! S8 (wave 2, W8): `install --mode` also writes `[wrapper] mode` into
//! bridge.toml (L1, [`install_mode`]); `settings-sync` promotes the safe
//! rules a session's VM added into the image's `claude/settings.json` and
//! the settings policy, scanned before and after (T8.7, [`settings_sync`],
//! [`splice_rules`]).
//!
//! `uninstall` takes the wrapper key out again ([`remove_settings`], the
//! splice's inverse, verified the same way), so what Cursor starts
//! afterwards is its bundled claude. `install` then splices the key in as
//! any missing key ([`splice_settings`], U4): on its own line just before
//! `initialPermissionMode` when that key starts its own line, else just
//! before the final `}`. Given the same two values, a key that sat as
//! install writes it (on its own line just before `initialPermissionMode`,
//! with that line's indent and line ending) comes back byte for byte; from
//! anywhere else it comes back where the splice puts it, the settings the
//! same.
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::census::read_rows;
use crate::bridge::config::{BridgeConfig, Paths, WrapperMode};
use crate::bridge::doctor::{cursor_settings_path, parse_settings, run_capture, strip_jsonc, version_token, PERMISSION_SETTING, WRAPPER_SETTING};
use crate::bridge::probes::{append_row, init_wrapper_verdict, Expectation};
use crate::bridge::sibling::{exists_exec, require_sibling, INSTALL_HINT};
use crate::bridge::wrapper_status::{shown_mode, CursorEnv};
use crate::errors::{CliError, Result};
use crate::store::write_atomic;
use crate::wire::redact::scrub;
use crate::wire::time::{rfc3339_utc, unix_now};
use crate::{bail, outln};
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

/// One line of `lab/probes.jsonl` (moved to `bridge::probes` in S4; re-exported
/// here for the S1 callers).
pub use crate::bridge::probes::ProbeRow;

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
    let row = |probe: &str, verdict: String, expected: &str| ProbeRow {
        ext: ext.clone(),
        sdk: sdk.clone(),
        ts: ts.clone(),
        ..ProbeRow::new(probe, PROBE_STAGE, &verdict, &Expectation::Exact(expected.to_string()))
    };
    vec![row("entrypoint", entrypoint, "claude-vscode"), row("stock-ext-oauth", if has_oauth { "present" } else { "absent" }.to_string(), "absent")]
}

/// The second half of `stock-ext-oauth` (S7): the class a piped session
/// recorded for the pump's synthetic `oauth_token_refresh` (the end row's
/// `synthetic_oauth:` part, with `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS`; the
/// stock extension answers `error(getOAuthToken callback is not provided.)`).
/// Only rows of extension version `ext` count — the verdicts' own `ext` —
/// so an answer the previous extension gave is never stamped with the new
/// version. The newest answer wins over a newer `none` or `unsent`: Cursor's
/// config probe may close before the extension answers.
fn synthetic_answer(rows: &[serde_json::Value], ext: Option<&str>) -> Option<String> {
    let classes: Vec<&str> = rows
        .iter()
        .rev()
        .filter(|r| r.get("ext").and_then(|e| e.as_str()) == ext)
        .filter_map(|r| r.get("note")?.as_str()?.split("; ").find_map(|p| p.strip_prefix("synthetic_oauth:")))
        .collect();
    classes.iter().find(|c| !matches!(**c, "none" | "unsent")).or_else(|| classes.first()).map(|c| (*c).to_string())
}

/// Put the synthetic answer, when the census holds one for the verdicts'
/// extension version, in the `stock-ext-oauth` row's note.
fn note_synthetic_answer(verdicts: &mut [ProbeRow], rows: &[serde_json::Value]) {
    let Some(row) = verdicts.iter_mut().find(|v| v.probe == "stock-ext-oauth") else { return };
    if let Some(class) = synthetic_answer(rows, row.ext.as_deref()) {
        row.note = Some(format!("the extension answered the synthetic oauth_token_refresh with {class}"));
    }
}

/// A census row that went through the session classifier: `route` is
/// `remote`, or the reason is one of the two demoted session reasons.
fn is_session_row(row: &serde_json::Value) -> bool {
    let field = |k: &str| row.get(k).and_then(|v| v.as_str()).unwrap_or("");
    field("route") == "remote" || matches!(field("reason"), "outside_roots" | "unconfigured")
}

/// `--record-probes`: derive the verdicts from the newest session row (and,
/// S7, the synthetic answer into `stock-ext-oauth`'s note; S8, the
/// `init-wrapper` row from the remote end rows, once any exist), print a
/// diff against the last recorded row of each probe, append every row to
/// `lab/probes.jsonl` (one `write` each), and fail AFTER writing when any
/// verdict differs from its expectation.
fn record_probes(paths: &Paths, rows: &[serde_json::Value]) -> Result<()> {
    let Some(session) = rows.iter().rev().find(|r| is_session_row(r)) else {
        bail!("no session row in the census yet — open a Cursor chat with the wrapper installed");
    };
    let mut verdicts = probe_verdicts(session);
    note_synthetic_answer(&mut verdicts, rows);
    verdicts.extend(init_wrapper_verdict(rows));
    let probes_path = paths.probes();
    let mut failed = Vec::new();
    for v in &verdicts {
        let holds = append_row(&probes_path, v)?;
        outln!("recorded {}={} (expected {})", v.probe, v.verdict, v.expected);
        if let Some(note) = &v.note {
            outln!("  {note}");
        }
        if !holds {
            failed.push(format!("{}={} (expected {})", v.probe, v.verdict, v.expected));
        }
    }
    if !failed.is_empty() {
        bail!("probe verdict differs from the expectation: {}", failed.join(", "));
    }
    Ok(())
}

// ---- census ------------------------------------------------------------------------

/// `text` with every control character escaped as Rust writes it (`\n`,
/// `\t`, `\u{1b}`): a census value another hand wrote never moves the
/// terminal's cursor, colours it or forges a line (S9).
fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { c.escape_debug().to_string() } else { c.to_string() }).collect()
}

/// The text rendering of one census row: `ts route reason ext cwd argv[2..]`
/// (the argv tail joined by spaces, at most 120 characters, `…` when cut).
/// The S2 pump's end row (it carries `end`) also shows `exit=<n> dur=<ms>ms`
/// before the argv tail (`exit=null` when the wrapper could not know it).
/// Every value goes through [`printable`] first, so no control character
/// reaches the terminal (S9).
fn census_line(row: &serde_json::Value) -> String {
    let field = |k: &str| printable(row.get(k).and_then(|v| v.as_str()).unwrap_or("-"));
    let argv: Vec<String> = row.get("argv").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|t| t.as_str()).map(printable).collect()).unwrap_or_default();
    let tail = argv.iter().skip(2).map(String::as_str).collect::<Vec<_>>().join(" ");
    let tail = if tail.chars().count() > 120 { format!("{}\u{2026}", tail.chars().take(119).collect::<String>()) } else { tail };
    let end = match row.get("end").and_then(serde_json::Value::as_u64) {
        Some(end) => {
            let exit = row.get("exit").and_then(serde_json::Value::as_i64).map_or_else(|| "null".to_string(), |c| c.to_string());
            let dur = row.get("start").and_then(serde_json::Value::as_u64).map_or_else(|| "?".to_string(), |s| end.saturating_sub(s).to_string());
            format!("exit={exit} dur={dur}ms  ")
        }
        None => String::new(),
    };
    format!("{}  {:<6} {:<24} {}  {}  {end}{tail}", field("ts"), field("route"), field("reason"), field("ext"), field("cwd"))
}

/// `ai-env wrapper census [--last N] [--json] [--record-probes]`: print the
/// census (one text line or one raw JSON line per row; a missing file prints
/// `no census yet` and exits 0), then optionally record the probes from the
/// whole census (not just the last `N`): the S1 ones from its newest session
/// row, `init-wrapper` from its remote end rows.
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
/// `"key": "value"`: on its own line just before the member `anchor` when
/// that starts its own line (its indent and its line's ending; U4), else
/// before the final `}` with the detected indent.
fn upsert(text: &str, key: &str, value: &str, anchor: Option<&str>) -> std::result::Result<String, String> {
    let tokens = tokenize(text)?;
    let top = top_level(&tokens)?;
    let literal = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let member = |name: &str| top.members.iter().find(|m| serde_json::from_str::<String>(&text[m.key_start..m.key_end]).is_ok_and(|k| k == name)).copied();
    if let Some(m) = member(key) {
        return Ok(format!("{}{literal}{}", &text[..m.value_start], &text[m.value_end..]));
    }
    let key_literal = serde_json::to_string(key).map_err(|e| e.to_string())?;
    if let Some(m) = anchor.and_then(member) {
        let line_start = text[..m.key_start].rfind('\n').map_or(0, |i| i + 1);
        let indent = &text[line_start..m.key_start];
        if indent.bytes().all(|c| c == b' ' || c == b'\t') {
            // The anchor line's own ending (the LF lines install adds to a CRLF file stay LF), else the one before it.
            let ending = text[m.key_start..].find('\n').map_or(line_start, |i| m.key_start + i + 1);
            let eol = if text[..ending].ends_with("\r\n") { "\r\n" } else { "\n" };
            return Ok(format!("{}{indent}{key_literal}: {literal},{eol}{}", &text[..line_start], &text[line_start..]));
        }
    }
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
/// value is replaced in place, each missing key is inserted just before the
/// first later entry the file already holds when that starts its own line
/// (U4: with the same values, `uninstall` then `install` gives back the same
/// bytes when the wrapper key sat on its own line just before
/// `initialPermissionMode`, the layout install writes; else the same
/// settings), else before
/// the final `}` (a comma is added to the previous member when needed; `{}`,
/// `{\n}`, a trailing comma and a missing final newline are handled), and
/// nothing outside the touched values changes — comments and order
/// included. Then the result is verified: `parse_settings(new)` must equal
/// `parse_settings(text)` with `entries` applied, else `Err` and the caller
/// writes nothing.
pub fn splice_settings(text: &str, entries: &[(&str, &str)]) -> std::result::Result<String, String> {
    let old = parse_settings(text).map_err(|e| format!("cannot parse the settings: {e}"))?;
    let mut expected = old.clone();
    let obj = expected.as_object_mut().ok_or_else(|| "the top-level value is not an object".to_string())?;
    for (key, value) in entries {
        obj.insert((*key).to_string(), serde_json::Value::String((*value).to_string()));
    }
    let mut out = text.to_string();
    for (i, (key, value)) in entries.iter().enumerate() {
        let anchor = entries[i + 1..].iter().map(|(k, _)| *k).find(|k| old.get(*k).is_some());
        out = upsert(&out, key, value, anchor)?;
    }
    let got = parse_settings(&out).map_err(|e| format!("splice verification failed: the result does not parse: {e}"))?;
    if got != expected {
        return Err("splice verification failed: the result is not the old settings plus the new keys".to_string());
    }
    Ok(out)
}

/// Take the first depth-1 member named `key` (escaped keys match) out of
/// `text`: the member and one comma, its own or, for the last member, the
/// one before it (only that comma byte: a comment after it stays). A member
/// alone on its line(s) goes with them, line ending included; one ending a
/// line behind something else takes the blanks before it. Comments outside
/// the member stay, ones inside it go with it. `None`: no such member.
fn remove_first(text: &str, key: &str) -> std::result::Result<Option<String>, String> {
    let tokens = tokenize(text)?;
    top_level(&tokens)?;
    let obj = object_at(&tokens, 0)?;
    let named = |i: usize| serde_json::from_str::<String>(&text[tokens[i].start..tokens[i].end]).is_ok_and(|k| k == key);
    let Some(j) = obj.members.iter().position(|&(k, _, _)| named(k)) else {
        return Ok(None);
    };
    let (k, _, last) = obj.members[j];
    let (b, blank) = (text.as_bytes(), |c: u8| c == b' ' || c == b'\t');
    let (key_at, value_end) = (tokens[k].start, tokens[last].end);
    let comma = (tokens[last + 1].tok == Tok::Comma).then_some(tokens[last + 1]);
    let before = (comma.is_none() && j > 0).then_some(tokens[k - 1]);
    let own_end = comma.map_or(value_end, |c| c.end);
    let ws_end = own_end + b[own_end..].iter().take_while(|&&c| blank(c)).count();
    let line_end = match &b[ws_end..] {
        [b'\n', ..] => Some(ws_end + 1),
        [b'\r', b'\n', ..] => Some(ws_end + 2),
        _ => None,
    };
    let line_start = text[..key_at].rfind('\n').map_or(0, |i| i + 1);
    let lead = key_at - b[line_start..key_at].iter().rev().take_while(|&&c| blank(c)).count();
    let (from, to) = match (line_end, before) {
        (Some(end), _) if lead == line_start => (line_start, end),
        // `"a": 1, "k": "v"` on one line: the comma before goes with it.
        (_, Some(c)) if b[c.end..key_at].iter().all(|&x| blank(x)) => (c.start, value_end),
        (Some(_), _) => (lead, ws_end),
        _ => (key_at, ws_end),
    };
    let head = match before {
        Some(c) if c.start < from => format!("{}{}", &text[..c.start], &text[c.end..from]),
        _ => text[..from].to_string(),
    };
    Ok(Some(format!("{head}{}", &text[to..])))
}

/// [`splice_settings`]' inverse, for `uninstall`: every depth-1 member
/// named in `keys` taken out, duplicates too ([`remove_first`] until none is
/// left), with how many went. Then verified: `parse_settings(new)` must
/// equal `parse_settings(text)` without `keys`, else `Err` and the caller
/// writes nothing.
pub fn remove_settings(text: &str, keys: &[&str]) -> std::result::Result<(String, usize), String> {
    let mut expected = parse_settings(text).map_err(|e| format!("cannot parse the settings: {e}"))?;
    let obj = expected.as_object_mut().ok_or_else(|| "the top-level value is not an object".to_string())?;
    for key in keys {
        obj.remove(*key);
    }
    let (mut out, mut removed) = (text.to_string(), 0);
    for key in keys {
        while let Some(next) = remove_first(&out, key)? {
            out = next;
            removed += 1;
        }
    }
    let got = parse_settings(&out).map_err(|e| format!("removal verification failed: the result does not parse: {e}"))?;
    if got != expected {
        return Err("removal verification failed: the result is not the old settings without the keys".to_string());
    }
    Ok((out, removed))
}

/// An object's members as token indices (`object_at`): each member's key,
/// its value's first token and its value's last; and the closing `}`.
struct Object {
    members: Vec<(usize, usize, usize)>,
    close: usize,
}

/// The object whose `{` is token `open`.
fn object_at(tokens: &[Token], open: usize) -> std::result::Result<Object, String> {
    let close = matching_close(tokens, open)?;
    let mut members = Vec::new();
    let mut i = open + 1;
    while i < close {
        if tokens[i].tok != Tok::Str {
            return Err(format!("expected a key at byte {}", tokens[i].start));
        }
        if tokens.get(i + 1).map(|t| t.tok) != Some(Tok::Colon) {
            return Err(format!("expected ':' after the key at byte {}", tokens[i].start));
        }
        let value = i + 2;
        let last = match tokens.get(value).map(|t| t.tok) {
            Some(Tok::Str | Tok::Scalar) => value,
            Some(Tok::Open(_)) => matching_close(tokens, value)?,
            _ => return Err(format!("missing value for the key at byte {}", tokens[i].start)),
        };
        members.push((i, value, last));
        i = last + 1;
        match tokens.get(i).map(|t| t.tok) {
            Some(Tok::Comma) => i += 1,
            Some(Tok::Close(b'}')) => {}
            _ => return Err(format!("expected ',' or '}}' after the value of the key at byte {}", tokens[value].start)),
        }
    }
    Ok(Object { members, close })
}

/// The leading whitespace of the line `at` is on.
fn line_indent(text: &str, at: usize) -> &str {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let line = &text[start..];
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

/// Insert `items` (rendered values or members) as the last entries of the
/// container whose brackets are tokens `open` and `close`, in its style: on
/// one line with its own separator when it holds no newline, else one item
/// per line, indented like its last item (an empty one: its closing line's
/// indent plus the document's unit). A trailing comma stays trailing.
fn insert_items(text: &str, tokens: &[Token], open: usize, close: usize, items: &[String]) -> std::result::Result<String, String> {
    let (inner_from, inner_to) = (tokens[open].end, tokens[close].start);
    let inner = &text[inner_from..inner_to];
    let before = tokens[close - 1];
    let empty = close == open + 1;
    if empty && !inner.trim().is_empty() {
        return Err(format!("a comment inside the empty list at byte {}; edit it by hand", tokens[open].start));
    }
    let (head, tail) = if !inner.contains('\n') {
        let sep = if inner.contains(", ") || text.contains(", ") { ", " } else { "," };
        let joined = items.join(sep);
        match (empty, before.tok) {
            (true, _) => (&text[..inner_from], format!("{joined}{}", &text[inner_to..])),
            (false, Tok::Comma) => (&text[..before.end], format!("{}{joined},{}", if sep == ", " { " " } else { "" }, &text[before.end..])),
            (false, _) => (&text[..before.end], format!("{sep}{joined}{}", &text[before.end..])),
        }
    } else {
        let close_indent = line_indent(text, tokens[close].start);
        let indent = if empty { format!("{close_indent}{}", detect_indent(text)) } else { line_indent(text, before.start).to_string() };
        let lines: String = items.iter().map(|i| format!("\n{indent}{i}")).collect::<Vec<_>>().join(",");
        match (empty, before.tok) {
            (true, _) => (&text[..inner_from], format!("{lines}\n{close_indent}{}", &text[inner_to..])),
            (false, Tok::Comma) => (&text[..before.end], format!("{lines},{}", &text[before.end..])),
            (false, _) => (&text[..before.end], format!(",{lines}{}", &text[before.end..])),
        }
    };
    Ok(format!("{head}{tail}"))
}

/// Append `entries` to `permissions.<kind>` (`allow`, `deny`, `ask`) of a
/// JSON(C) settings document, textually: key order, spacing and comments
/// survive. Into the list when it exists, else as a new `"<kind>": [...]`
/// member of `permissions`, else as a new `"permissions"` member of the
/// top-level object (`permissions` and the list each the last of their name,
/// as the CLI reads them). Then verified as [`splice_settings`] verifies:
/// the result must parse as the old document with exactly these entries
/// appended, else `Err` and the caller writes nothing (a `permissions` or a
/// list that is no object or list is refused).
pub fn splice_rules(text: &str, kind: &str, entries: &[String]) -> std::result::Result<String, String> {
    let old = parse_settings(text).map_err(|e| format!("cannot parse the settings: {e}"))?;
    let mut expected = old.clone();
    let perms = expected.as_object_mut().ok_or_else(|| "the top-level value is not an object".to_string())?.entry("permissions").or_insert_with(|| serde_json::json!({}));
    let list = perms.as_object_mut().ok_or_else(|| "permissions is not an object".to_string())?.entry(kind).or_insert_with(|| serde_json::json!([]));
    list.as_array_mut().ok_or_else(|| format!("permissions.{kind} is not a list"))?.extend(entries.iter().map(|e| serde_json::Value::String(e.clone())));
    let rendered: Vec<String> = entries.iter().map(|e| serde_json::to_string(e).map_err(|e| e.to_string())).collect::<std::result::Result<_, _>>()?;
    let tokens = tokenize(text)?;
    top_level(&tokens)?;
    let key_is = |i: usize, k: &str| serde_json::from_str::<String>(&text[tokens[i].start..tokens[i].end]).is_ok_and(|x| x == k);
    let colon = |within: &str| if within.contains(": ") { ": " } else { ":" };
    let top = object_at(&tokens, 0)?;
    let out = match top.members.iter().rev().find(|(k, _, _)| key_is(*k, "permissions")) {
        None => {
            let c = colon(text);
            let member = format!("\"permissions\"{c}{{\"{kind}\"{c}[{}]}}", rendered.join(","));
            insert_items(text, &tokens, 0, top.close, &[member])?
        }
        Some(&(_, value, _)) => {
            if tokens[value].tok != Tok::Open(b'{') {
                return Err("permissions is not an object".into());
            }
            let perms = object_at(&tokens, value)?;
            match perms.members.iter().rev().find(|(k, _, _)| key_is(*k, kind)) {
                None => {
                    let c = colon(&text[tokens[value].start..tokens[perms.close].end]);
                    let member = format!("{}{c}[{}]", serde_json::to_string(kind).map_err(|e| e.to_string())?, rendered.join(","));
                    insert_items(text, &tokens, value, perms.close, &[member])?
                }
                Some(&(_, list, last)) => {
                    if tokens[list].tok != Tok::Open(b'[') {
                        return Err(format!("permissions.{kind} is not a list"));
                    }
                    insert_items(text, &tokens, list, last, &rendered)?
                }
            }
        }
    };
    let got = parse_settings(&out).map_err(|e| format!("splice verification failed: the result does not parse: {e}"))?;
    if got != expected {
        return Err("splice verification failed: the result is not the old settings plus the new rules".to_string());
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
#[cfg(test)]
fn backup_path(path: &Path, now: u64) -> PathBuf {
    backup_path_n(path, now, 0)
}

/// The `n`-th backup name within one second: `<name>.<secs>.ai-env.bak`
/// for `n == 0`, else `<name>.<secs>-<n>.ai-env.bak`.
fn backup_path_n(path: &Path, now: u64, n: u32) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "settings.json".to_string());
    if n == 0 {
        path.with_file_name(format!("{name}.{now}.ai-env.bak"))
    } else {
        path.with_file_name(format!("{name}.{now}-{n}.ai-env.bak"))
    }
}

/// The value of `[wrapper] mode` in bridge.toml's text, when the key is set.
fn configured_mode(text: &str) -> Option<String> {
    let table: toml::Table = toml::from_str(text).ok()?;
    table.get("wrapper")?.get("mode")?.as_str().map(str::to_string)
}

/// The permission mode `install` writes without `--permission-mode`:
/// `[wrapper].initial_permission_mode` from bridge.toml, else `default`.
fn configured_permission_mode() -> String {
    Paths::resolve().ok().and_then(|p| BridgeConfig::load(&p).ok().flatten()).map_or_else(|| "default".to_string(), |c| c.wrapper.initial_permission_mode)
}

/// `uninstall`'s line on the mode the wrapper comes back in, and the exit
/// code every chat under the roots then fails closed with (`None`: it does
/// not), both as `ai-env wrapper status` weighs them
/// (`wrapper_status::row_effective_mode`): Cursor's variables (`env`, read
/// from the settings `uninstall` edits, as the extension hands them to every
/// spawn) first. The kill switch runs every chat on this Mac, whatever the
/// mode. A bridge root or bridge.toml other than this command's
/// (`AI_ENV_BRIDGE_DIR`, `AI_ENV_BRIDGE_CONFIG`) leaves the mode to a file
/// this command does not read: named, never claimed. Else bridge.toml's
/// `[wrapper] mode` as the wrapper reads it (`route::load_for_wrapper`,
/// `route::effective_mode_loaded`): the value as written (scrubbed and
/// capped as status shows it, `wrapper_status::shown_mode`), with the mode
/// it is taken as unless that is its own name (`unset: passthrough`,
/// `unreadable: remote`, `"x": remote`), under an `AI_ENV_BRIDGE_MODE` that
/// names a mode, which wins. In remote mode it fails closed as
/// `wrapper_status::fails_closed` says (a file that does not load or names
/// no mode, or fails a check of a remote session's start, with a root to
/// route on or roots it cannot read: without one no session goes remote);
/// never under the kill switch or another bridge root. No other variable's
/// name or value is ever printed.
fn wrapper_mode_report(env: &CursorEnv) -> (String, Option<i32>) {
    use crate::bridge::route::{effective_mode_loaded, load_for_wrapper, MODE_ENV};
    use crate::bridge::wrapper_status::{fails_closed, ENV_SETTING, LOCAL_ENV};
    let back = "ai-env wrapper install --write brings the wrapper back";
    if env.local == Some(true) {
        return (format!("bridge.toml is left alone: {back}, but the kill switch ({LOCAL_ENV}=1 in Cursor's {ENV_SETTING}) still runs every chat on this Mac."), None);
    }
    let loaded = load_for_wrapper();
    let elsewhere = env.elsewhere(loaded.paths.as_ref());
    let named = env.named_mode();
    if !elsewhere.is_empty() {
        let how = named.map_or_else(|| "in the mode the bridge.toml there names".to_string(), |m| format!("in {m} mode ({MODE_ENV} in Cursor's {ENV_SETTING})"));
        return (format!("bridge.toml is left alone, but the wrapper reads another bridge root ({} in Cursor's {ENV_SETTING}): {back}, {how}, for what Cursor starts after it (ai-env wrapper status shows the variables).", elsewhere.join(" and ")), None);
    }
    // The file's own mode for the report; the one the chats get, the variable's when it names one, for the rest.
    let file = effective_mode_loaded(None, &loaded).0;
    let mode = effective_mode_loaded(named, &loaded).0;
    let written = match &loaded.broken {
        Some(broken) => broken.mode.clone(),
        None => Some(loaded.paths.as_ref().and_then(|p| std::fs::read_to_string(&p.config).ok()).and_then(|t| configured_mode(&t))),
    };
    let report = match &written {
        Some(Some(w)) if w == file.name() => format!("[wrapper] mode = {}", shown_mode(w)),
        Some(Some(w)) => format!("[wrapper] mode = {}: {}", shown_mode(w), file.name()),
        Some(None) => format!("[wrapper] mode unset: {}", file.name()),
        None => format!("[wrapper] mode unreadable: {}", file.name()),
    };
    let how = named.map_or_else(|| "in that mode".to_string(), |m| format!("in {m} mode, which {MODE_ENV} in Cursor's {ENV_SETTING} sets over bridge.toml's"));
    (format!("bridge.toml is left alone ({report}): {back}, {how}, for what Cursor starts after it."), fails_closed(mode, &loaded).map(|c| c.code()))
}

/// `ai-env wrapper install … --mode M` (S8, L1): [`install`] (Cursor's two
/// keys), and `[wrapper] mode = "M"` spliced into bridge.toml
/// (`infra::splice_toml_table`: comments, order and every other table kept;
/// the result must parse as a bridge.toml), backup first. The splice is
/// checked before anything is written (a refusal names the first line of
/// its error, scrubbed: the rest quotes the file); without `--write`
/// neither file is written and the dry run says so. No bridge.toml:
/// passthrough is already the default, and remote mode needs one
/// (`[workspaces].roots`, `[aws]`): refused naming `make infra-status
/// WRITE=1`. `AI_ENV_BRIDGE_MODE` still overrides the key (tests), and
/// `AI_ENV_BRIDGE_LOCAL=1` stays the kill switch.
pub fn install_mode(write: bool, permission_mode: Option<String>, mode: WrapperMode) -> Result<()> {
    let paths = Paths::resolve()?;
    let path = paths.config.clone();
    let want = mode.name();
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => bail!("{} is a symlink — refusing to edit it; set [wrapper] mode = {want:?} by hand", path.display()),
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => bail!("cannot stat {}: {e}", path.display()),
    };
    if meta.is_none() && mode == WrapperMode::Remote {
        bail!("no bridge.toml at {}: remote mode needs one ([workspaces].roots, [aws]): make infra-status WRITE=1 writes it, then add the roots", path.display());
    }
    // The bridge.toml edit, checked before install writes anything.
    let planned = match &meta {
        Some(m) => {
            let old_text = std::fs::read_to_string(&path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?;
            // The refusal's first line, scrubbed: a bridge.toml error quotes the file (a snippet, a value).
            let new_text = crate::bridge::infra::splice_toml_table(&old_text, "wrapper", &[("mode", want.to_string())])
                .map_err(|e| CliError::Msg(format!("{}: {}; set [wrapper] mode = {want:?} by hand", path.display(), scrub(e.lines().next().unwrap_or_default()))))?;
            Some((m.clone(), stamp(Some(m)), old_text, new_text))
        }
        None => None,
    };
    install(write, permission_mode)?;
    outln!();
    let Some((m, before, old_text, new_text)) = planned else {
        outln!("bridge.toml: {} absent: [wrapper] mode is passthrough already (the default)", path.display());
        return Ok(());
    };
    outln!("bridge.toml: {}", path.display());
    match configured_mode(&old_text) {
        Some(c) if c == want => outln!("  [wrapper] mode: {c:?} (unchanged)"),
        Some(c) => outln!("  [wrapper] mode: {} -> {want:?}", shown_mode(&c)),
        None => outln!("  [wrapper] mode: unset (passthrough) -> {want:?}"),
    }
    if new_text == old_text {
        outln!("bridge.toml: nothing to write");
    } else if write {
        if let Some(bak) = commit_settings(&path, Some(&m), before, &old_text, &new_text)? {
            outln!("backup: {}", bak.display());
        }
        outln!("wrote: {}", path.display());
    } else {
        outln!("dry run: bridge.toml not written; re-run with --write");
    }
    match mode {
        WrapperMode::Remote => {
            let cfg = BridgeConfig::parse(&new_text)?;
            if cfg.roots().is_empty() {
                outln!("note: [workspaces].roots is empty: no chat runs in a MicroVM until a root is set");
            }
            outln!("Remote mode: a Cursor chat (stream-json) under [workspaces].roots runs in the workspace's MicroVM (a Touch ID per chat process); everything else runs on this Mac. Chats started from now on use the new mode; a window reload moves the chats already open, and restarts them. ai-env wrapper install --write --mode passthrough switches back.");
        }
        WrapperMode::Passthrough => outln!("Passthrough mode: every Cursor chat runs on this Mac (the wrapper execs the bundled claude). Chats started from now on use the new mode; a window reload moves the chats already open, and restarts them."),
    }
    Ok(())
}

// ---- settings-sync (S8 T8.7) ---------------------------------------------------------------

/// The image directory `settings-sync` writes into: `--image-dir`, else
/// `image/` at the top of the git repository the current directory is in;
/// it must hold `MANIFEST` and a regular `claude/settings.json`.
fn image_dir_of(given: Option<&Path>) -> Result<PathBuf> {
    let dir = match given {
        Some(d) => d.to_path_buf(),
        None => {
            let cwd = std::env::current_dir()?;
            let top = crate::gitrun::GitRun::mac(&cwd).output(["rev-parse", "--show-toplevel"]).map_err(|_| CliError::Msg(format!("{} is in no git repository: --image-dir DIR names the image directory", cwd.display())))?;
            PathBuf::from(String::from_utf8_lossy(&top).trim()).join("image")
        }
    };
    if !dir.join("MANIFEST").is_file() {
        bail!("{} holds no MANIFEST: not an image directory (--image-dir DIR)", dir.display());
    }
    match std::fs::symlink_metadata(dir.join("claude").join("settings.json")) {
        Ok(m) if m.file_type().is_file() => Ok(dir),
        Ok(_) => bail!("{}/claude/settings.json is not a regular file", dir.display()),
        Err(e) => bail!("{}/claude/settings.json: {e}", dir.display()),
    }
}

/// What `settings-sync` does with one rule the session added.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncVerdict {
    Promote,
    /// Already in the image's list.
    Present,
    /// Not named (`--rule`) and `--all-safe` not given.
    NotChosen,
    /// Never promoted, and why (`settings_capture::rule_refusal`).
    Refused(String),
}

/// The text of a file that may be absent (`None`), never read through a symlink.
fn read_optional(path: &Path) -> Result<Option<(String, u32)>> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => bail!("{} is a symlink: refusing to edit it", path.display()),
        Ok(m) => Ok(Some((std::fs::read_to_string(path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?, m.permissions().mode() & 0o777))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => bail!("cannot stat {}: {e}", path.display()),
    }
}

/// The scan `make image-stage-scan` runs, over `image` itself: the image
/// profile, the tripwires and the settings policy read from disk now.
fn image_findings(paths: &Paths, cfg: &BridgeConfig, image: &Path) -> Result<(Vec<crate::bridge::scan::Finding>, usize)> {
    let (rules, policy) = crate::bridge::scan::load_lists(Some((paths, &cfg.review)), None, None, true).map_err(CliError::Msg)?;
    crate::bridge::scan::scan_dir(image, crate::bridge::scan::Profile::Image, &rules, &policy).map_err(CliError::Msg)
}

/// One file `settings-sync --write` replaces: its text before (`None`:
/// absent), its text after, and the mode it keeps.
struct Replaced<'a> {
    path: &'a Path,
    old: Option<&'a str>,
    new: &'a str,
    mode: u32,
}

/// Write `files` in order, then run `scan` (the image-mode scan of the
/// image): every file written is put back as it was (one absent before is
/// removed) when a write fails, the scan cannot run, or it finds anything
/// (exit 9 naming each finding, never a value). The files scanned.
fn write_checked(files: &[Replaced<'_>], scan: impl FnOnce() -> Result<(Vec<crate::bridge::scan::Finding>, usize)>) -> Result<usize> {
    let restore = |written: &[Replaced<'_>]| -> Result<()> {
        for f in written.iter().rev() {
            match f.old {
                Some(text) => crate::bridge::infra::write_atomic_mode(f.path, text.as_bytes(), f.mode)?,
                None => {
                    let _ = std::fs::remove_file(f.path);
                }
            }
        }
        Ok(())
    };
    for (i, f) in files.iter().enumerate() {
        if let Err(e) = crate::bridge::infra::write_atomic_mode(f.path, f.new.as_bytes(), f.mode) {
            restore(&files[..i])?;
            return Err(e.into());
        }
    }
    let (found, scanned) = match scan() {
        Ok(found) => found,
        Err(e) => {
            restore(files)?;
            return Err(e);
        }
    };
    if !found.is_empty() {
        restore(files)?;
        let shown: Vec<String> = found.iter().map(|f| format!("{}:{}: {}", f.file, f.line, f.rule)).collect();
        return Err(CliError::Policy(format!("the image does not scan clean with the synced rules ({}): every file was put back", shown.join("; "))));
    }
    Ok(scanned)
}

/// A fresh `sync-<unix seconds>[-n]` directory (0700) in the session's
/// quarantine, for the files a write replaces.
fn backup_dir(paths: &Paths, session: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let base = crate::bridge::settings_capture::private_settings_dir(paths, session)?;
    let now = unix_now();
    for n in 0..10 {
        let dir = base.join(if n == 0 { format!("sync-{now}") } else { format!("sync-{now}-{n}") });
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => bail!("cannot create {}: {e}", dir.display()),
        }
    }
    bail!("cannot create a backup directory in {}", base.display())
}

/// `ai-env wrapper settings-sync SESSION [--rule R]… [--all-safe] [--write]
/// [--image-dir DIR]` (S8 T8.7): the rules the session's VMs added
/// (`session show --settings-diff`'s union: each VM's last capture against
/// the start, so a rule approved on a VM the session left is one too)
/// promoted into the image's `claude/settings.json` (spliced,
/// [`splice_rules`]) and, for each `allow`, an `allow <rule>` line in the
/// settings policy (`[review].settings_policy`), which the image scan
/// requires. A dry run by default: both changes printed, nothing written.
/// Never promoted (`settings_capture::rule_refusal`): a broad allow or
/// anything else the repo mode refuses (D8), a rule a tripwire matches or
/// with a secret shape; a `defaultMode` change never is either. `--rule R`
/// promotes R (exit 9 when it is never promoted, 1 when the session did
/// not add it), `--all-safe` every rule that passes. With `--write`: the
/// image must scan clean first (exit 9 otherwise); the replaced files are
/// kept in `quarantine/SESSION/settings/sync-*`, both files written, the
/// image-mode scan run again with the new policy, and both put back unless
/// it is clean (exit 9); then `make test-docker deploy` bakes them (deploy's
/// preflight P12 takes only a zip `make test-docker` stamped) and `ai-env
/// egress check --if-needed` checks the new image version (the credential
/// gate admits a version only with its own passing check).
pub fn settings_sync(session: &str, rules: &[String], all_safe: bool, write: bool, image_dir: Option<&Path>) -> Result<()> {
    use crate::bridge::settings_capture::{diff, read_captures, rule_refusal, shown_rule, tripwires};
    if !crate::bridge::registry::is_uuid(session) {
        return Err(CliError::Usage(format!("not a session id: {session}")));
    }
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    let trips = tripwires(&paths)?;
    let captures = read_captures(&paths, session)?;
    if captures.latest.is_none() && captures.left.is_empty() {
        bail!("session {session} has no capture after a result yet (quarantine/{session}/settings/latest.json): nothing to sync");
    }
    let d = diff(session, &captures);
    // What is printed comes from the shown diff (the VM writes the modes, the helper the times); the rules written from `d`.
    let shown = d.shown(&trips);
    let added = d.added_rules();
    for r in rules {
        if !added.iter().any(|a| &a.rule == r) {
            bail!("{} is not a rule session {session} added (ai-env session show {session} --settings-diff lists them)", shown_rule(r, &trips));
        }
    }
    let image = image_dir_of(image_dir)?;
    let settings_path = image.join("claude").join("settings.json");
    let Some((settings_text, settings_mode)) = read_optional(&settings_path)? else {
        bail!("{} is missing", settings_path.display());
    };
    let current = parse_settings(&settings_text).map_err(|e| CliError::Msg(format!("cannot parse {}: {e}", settings_path.display())))?;
    let present = |kind: &str, rule: &str| current.pointer(&format!("/permissions/{kind}")).and_then(serde_json::Value::as_array).is_some_and(|l| l.iter().any(|e| e.as_str() == Some(rule)));
    let verdicts: Vec<(&crate::bridge::settings_capture::AddedRule, SyncVerdict)> = added
        .iter()
        .map(|a| {
            let v = match rule_refusal(a.kind, &a.rule, &trips) {
                Some(why) => SyncVerdict::Refused(why),
                None if present(a.kind.name(), &a.rule) => SyncVerdict::Present,
                None if all_safe || rules.contains(&a.rule) => SyncVerdict::Promote,
                None => SyncVerdict::NotChosen,
            };
            (a, v)
        })
        .collect();
    let against: Vec<String> = shown.vms.iter().map(|v| v.vm.as_ref().map_or_else(|| v.at.clone(), |vm| format!("{vm} {}", v.at))).collect();
    outln!("session {session}: {} rule(s) its {} added ({} against {})", added.len(), if shown.vms.len() == 1 { "VM" } else { "VMs" }, shown.start, against.join(", "));
    // `SettingsDiff::shown` maps the union rule for rule, in order: what is printed is its words.
    for ((_, v), s) in verdicts.iter().zip(shown.added_rules()) {
        let what = match v {
            SyncVerdict::Promote => "promote".to_string(),
            SyncVerdict::Present => "already in the image".to_string(),
            SyncVerdict::NotChosen => "not chosen (--rule R or --all-safe)".to_string(),
            SyncVerdict::Refused(why) => format!("never promoted: {why}"),
        };
        outln!("  {} {}  ({})  {what}", s.kind.name(), s.rule, s.place());
    }
    for v in &shown.vms {
        for s in &v.scopes {
            if let Some(m) = &s.default_mode {
                let at = v.vm.as_ref().map_or_else(|| s.scope.name().to_string(), |vm| format!("{}; {vm}", s.scope.name()));
                outln!("  defaultMode {} -> {} ({at}): never promoted", m.from.as_deref().unwrap_or("unset"), m.to.as_deref().unwrap_or("unset"));
            }
        }
    }
    let refused: Vec<String> = verdicts.iter().filter(|(a, v)| rules.contains(&a.rule) && matches!(v, SyncVerdict::Refused(_))).map(|(a, _)| format!("{} {}", a.kind.name(), shown_rule(&a.rule, &trips))).collect();
    if !refused.is_empty() {
        return Err(CliError::Policy(format!("never promoted, so nothing was written: {}", refused.join("; "))));
    }
    let chosen: Vec<&crate::bridge::settings_capture::AddedRule> = verdicts.iter().filter(|(_, v)| *v == SyncVerdict::Promote).map(|(a, _)| *a).collect();
    if chosen.is_empty() {
        outln!("nothing to promote");
        return Ok(());
    }
    // Both changes: the image's settings and the policy's allow lines.
    let mut new_settings = settings_text.clone();
    for kind in crate::bridge::settings_capture::RuleKind::ALL {
        let entries: Vec<String> = chosen.iter().filter(|a| a.kind == kind).map(|a| a.rule.clone()).collect();
        if !entries.is_empty() {
            new_settings = splice_rules(&new_settings, kind.name(), &entries).map_err(|e| CliError::Msg(format!("{}: {e}; add the rules by hand", settings_path.display())))?;
        }
    }
    let policy_path = cfg.review.settings_policy_path(&paths);
    let old_policy = read_optional(&policy_path)?;
    let listed = crate::bridge::scan::parse_policy(old_policy.as_ref().map_or("", |(t, _)| t.as_str()), &policy_path.display().to_string()).map_err(CliError::Msg)?;
    let lines: Vec<String> = chosen.iter().filter(|a| a.kind == crate::bridge::settings_capture::RuleKind::Allow && !listed.contains(&a.rule)).map(|a| format!("allow {}", a.rule)).collect();
    outln!("{}:", settings_path.display());
    for a in &chosen {
        outln!("  + permissions.{} {}", a.kind.name(), serde_json::to_string(&shown_rule(&a.rule, &trips)).unwrap_or_default());
    }
    outln!("{}:", policy_path.display());
    if lines.is_empty() {
        outln!("  (no change: every allow is in it already)");
    }
    for l in &lines {
        outln!("  + {}", shown_rule(l, &trips));
    }
    if !write {
        outln!("dry run: nothing written; re-run with --write");
        return Ok(());
    }
    let (before, _) = image_findings(&paths, &cfg, &image)?;
    if !before.is_empty() {
        let shown: Vec<String> = before.iter().map(|f| format!("{}:{}: {}", f.file, f.line, f.rule)).collect();
        return Err(CliError::Policy(format!("{} does not scan clean before the sync ({}): fix it first (make image-stage-scan shows it); nothing was written", image.display(), shown.join("; "))));
    }
    let backups = backup_dir(&paths, session)?;
    crate::bridge::infra::write_atomic_mode(&backups.join("settings.json"), settings_text.as_bytes(), 0o600)?;
    if let Some((text, _)) = &old_policy {
        crate::bridge::infra::write_atomic_mode(&backups.join("settings-policy.txt"), text.as_bytes(), 0o600)?;
    }
    outln!("backup: {}", backups.display());
    let mut policy_text = old_policy.as_ref().map(|(t, _)| t.clone()).unwrap_or_default();
    if !policy_text.is_empty() && !policy_text.ends_with('\n') {
        policy_text.push('\n');
    }
    for l in &lines {
        policy_text.push_str(l);
        policy_text.push('\n');
    }
    let audit_row = |outcome: &str| {
        let row = AuditRow::new(crate::bridge::remote::audit_event::SETTINGS_SYNC, Some(session), audit::detail(&[("rules", chosen.len().to_string()), ("policy_lines", lines.len().to_string()), ("outcome", outcome.to_string())]));
        if let Err(e) = audit::append(&paths.audit(), &row) {
            tracing::warn!("audit row settings_sync not written: {e}");
        }
    };
    let mut replaced = vec![Replaced { path: &settings_path, old: Some(&settings_text), new: &new_settings, mode: settings_mode }];
    if !lines.is_empty() {
        replaced.push(Replaced { path: &policy_path, old: old_policy.as_ref().map(|(t, _)| t.as_str()), new: &policy_text, mode: old_policy.as_ref().map_or(0o600, |(_, m)| *m) });
    }
    let files = match write_checked(&replaced, || image_findings(&paths, &cfg, &image)) {
        Ok(files) => files,
        Err(e) => {
            audit_row("rolled_back");
            return Err(e);
        }
    };
    audit_row("written");
    for f in &replaced {
        outln!("wrote: {}", f.path.display());
    }
    outln!("scan: clean ({files} files)");
    outln!("next: make test-docker deploy (test-docker builds the zip and stamps it), then ai-env egress check --if-needed (a new image version needs its check before a credential goes in): a VM of the new image starts with these rules");
    Ok(())
}

/// `ai-env wrapper install [--write] [--permission-mode M]` (plan §7): find
/// and check the sibling wrapper, pick the permission mode, splice the two
/// keys into Cursor's `settings.json` (dry run unless `write`; a backup and
/// a size/mtime re-check guard the write; nothing is written when both keys
/// hold their values already) and print the guidance block. A permission
/// mode it refuses is named scrubbed and capped, as it may come from
/// bridge.toml.
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
    let mode = permission_mode.unwrap_or_else(configured_permission_mode);
    if !PERMISSION_MODES.contains(&mode.as_str()) {
        return Err(CliError::Usage(format!("permission mode {} is not one of {}", shown_mode(&mode), PERMISSION_MODES.join(", "))));
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
    if new_text == old_text {
        // Both keys hold their values already: no backup, no write, so the file keeps its mtime
        // (`ai-env wrapper status` weighs the census against its last change).
        outln!("settings: nothing to write");
    } else if write {
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
    outln!("claudeCode.disableLoginPrompt is left alone (set it only once S8 runs Cursor's sessions in MicroVMs with the delivered credential).");
    outln!("Wrapped setups start in Manual mode: the extension now passes --permission-mode {mode} on every spawn (choose with --permission-mode).");
    outln!("Cursor reads this setting each time it starts a process: chats it starts from now on use it; a chat already running keeps its process until it ends (a window reload restarts open chats through the wrapper).");
    outln!("With a wrapper set the extension stops following CLAUDE_CONFIG_DIR changes. Cursor still updates the extension and its bundled claude (turn off Auto Update for the Claude Code extension to keep a version); make claude-update brings the image to it.");
    outln!("AI_ENV_BRIDGE_LOCAL=1 is the kill switch: the wrapper execs the bundled binary directly, without a census.");
    Ok(())
}

/// A settings value as the reports show it: a string quoted, anything else
/// as its JSON.
fn shown(v: &serde_json::Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), |s| format!("{s:?}"))
}

/// `ai-env wrapper uninstall [--write]`: take `claudeCode.claudeProcessWrapper`
/// out of Cursor's `settings.json`, every top-level copy ([`remove_settings`]),
/// so what Cursor starts afterwards is its bundled claude. A dry run unless
/// `write`; the backup and the size/mtime re-check are `install`'s
/// ([`commit_settings`]). `initialPermissionMode`, bridge.toml, the census and
/// both binaries stay, and nothing here needs `ai-env-claude`, Touch ID or
/// AWS. A missing or empty file, or no wrapper key, is nothing to remove
/// (exit 0, no backup); a symlink or a file that does not parse is exit 1,
/// nothing written. Prints what Cursor does once the key is out (after a
/// dry run, what it would do after `--write`: until then a reload still
/// restarts the open chats through the wrapper), the mode the wrapper comes
/// back in as it reads bridge.toml under Cursor's variables, with a note
/// when every chat under the roots then fails closed
/// ([`wrapper_mode_report`]), and the `install` that undoes it (with
/// `--permission-mode` when the file's `initialPermissionMode` is not the
/// one `install` would pick, or `install` would refuse bridge.toml's). S9
/// (§6.4): before anything is written, and in the dry run, a warning on
/// stderr while remote chats keep only their view on this Mac
/// ([`views_warning`]): with the wrapper off, Cursor resumes an open one
/// here, from its view.
pub fn uninstall(write: bool) -> Result<()> {
    let projects = view_projects(&|name| std::env::var_os(name));
    let Some(old) = uninstall_settings(&cursor_settings_path(), projects.as_deref(), write, &mut |line| eprintln!("ai-env: warning: {line}"))? else {
        return Ok(());
    };
    let permission = old.get(PERMISSION_SETTING);
    let was = permission.map_or_else(|| "unset".to_string(), shown);
    outln!();
    let spawned = "(a new chat, a reopened or restored one, its config probe) runs its bundled claude on this Mac: no ai-env-claude, no census, no MicroVM, no Touch ID.";
    if write {
        outln!("Cursor reads {WRAPPER_SETTING} at every spawn: what it starts from now on {spawned}");
        outln!("A chat already running keeps the process it started with; a window reload restarts the restored chats without the wrapper.");
    } else {
        // Nothing changed yet: a reload now still restarts the open chats through the wrapper.
        outln!("With --write, Cursor reads {WRAPPER_SETTING} at every spawn: what it starts from then on {spawned}");
        outln!("A chat already running keeps the process it started with; after the write, a window reload restarts the restored chats without the wrapper.");
    }
    // Cursor's variables, as the extension hands them to every process it starts, the wrapper back too.
    let (report, closed) = wrapper_mode_report(&CursorEnv::of(&old));
    outln!("{report}");
    if let Some(code) = closed {
        outln!("note: with the wrapper back, every Cursor chat under bridge.toml's roots (every chat, when they cannot be read) exits {code} naming the error until bridge.toml is fixed (ai-env wrapper status shows it)");
    }
    // `install` rewrites initialPermissionMode too: the flag keeps today's when install would
    // pick another, and stands in for a bridge.toml value install refuses (exit 2).
    let picked = configured_permission_mode();
    let now = permission.and_then(|m| m.as_str()).filter(|m| PERMISSION_MODES.contains(m));
    match (now, PERMISSION_MODES.contains(&picked.as_str())) {
        (Some(m), true) if m == picked => outln!("undo: ai-env wrapper install --write"),
        (Some(m), _) => outln!("undo: ai-env wrapper install --write --permission-mode {m}"),
        (None, true) => {
            outln!("undo: ai-env wrapper install --write");
            outln!("note: install sets {PERMISSION_SETTING} to {picked:?} (now {was})");
        }
        (None, false) => {
            outln!("undo: ai-env wrapper install --write --permission-mode default");
            outln!("note: install refuses bridge.toml's [wrapper].initial_permission_mode = {}: the undo sets {PERMISSION_SETTING} to \"default\" (now {was})", shown_mode(&picked));
        }
    }
    Ok(())
}

/// `<projects>` as `wire::view::local_view_target` finds it (`env` reads the
/// environment): `$CLAUDE_CONFIG_DIR/projects`, else `$HOME/.claude/projects`,
/// an empty value counting as unset; `None` with neither.
fn view_projects(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    match nonempty("CLAUDE_CONFIG_DIR") {
        Some(dir) => Some(PathBuf::from(dir).join("projects")),
        None => Some(PathBuf::from(nonempty("HOME")?).join(".claude").join("projects")),
    }
}

/// The view files among `<projects>/*/*.jsonl` (`projects`): those whose
/// first `wire::view::VIEW_HEAD_READ` bytes `wire::view::is_view_head` takes.
/// Regular files only, opened as the census is (`census::open_for_read`:
/// never through a link, never waiting on a FIFO); one level of project
/// directories, a link to one followed as claude follows it.
fn count_views(projects: &Path) -> usize {
    use crate::wire::view::{is_view_head, VIEW_HEAD_READ};
    use std::io::Read;
    let Ok(dirs) = std::fs::read_dir(projects) else {
        return 0;
    };
    dirs.flatten()
        .filter(|d| d.path().is_dir())
        .filter_map(|d| std::fs::read_dir(d.path()).ok())
        .flat_map(|files| files.flatten())
        .filter(|f| f.path().extension().is_some_and(|e| e == "jsonl"))
        .filter(|f| {
            let Ok(Some(file)) = crate::bridge::census::open_for_read(&f.path()) else {
                return false;
            };
            let mut head = Vec::with_capacity(VIEW_HEAD_READ);
            file.take(VIEW_HEAD_READ as u64).read_to_end(&mut head).is_ok() && is_view_head(&head)
        })
        .count()
}

/// What `uninstall` warns of while views exist under `projects` (S9,
/// §6.4; [`count_views`]): a remote chat's transcript is kept in S3 and the
/// Mac holds only its view, which Cursor, with the wrapper off, resumes on
/// this Mac for any of those chats still open (a window reload respawns them
/// with `--resume`). `None` without a view; one line, §6.4's, for any count.
fn views_warning(projects: &Path) -> Option<String> {
    let at = projects.display();
    match count_views(projects) {
        0 => None,
        n => Some(format!("{n} remote chats keep only their view under {at}: with the wrapper off, Cursor resumes an open one on this Mac; close their tabs first")),
    }
}

/// [`uninstall`]'s edit of Cursor's settings file at `path`: the wrapper key
/// out (every top-level copy), what changes, then the write (`write`) or the
/// dry run's line, the views' warning ([`views_warning`] of `projects`) to
/// `warn` before either, so before anything is written. `Ok(None)` when
/// there is nothing to remove (no file, an empty one, no wrapper key);
/// else the settings as they were, for the report that follows. A symlink,
/// a file that does not parse or a removal that does not verify is exit 1,
/// nothing written.
fn uninstall_settings(path: &Path, projects: Option<&Path>, write: bool, warn: &mut dyn FnMut(&str)) -> Result<Option<serde_json::Value>> {
    let by_hand = format!("remove {} from {} by hand", json_str(WRAPPER_SETTING), path.display());
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            outln!("{by_hand}");
            bail!("{} is a symlink — refusing to edit it", path.display());
        }
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            outln!("settings: {} (absent)", path.display());
            outln!("  {WRAPPER_SETTING}: unset (nothing to remove)");
            return Ok(None);
        }
        Err(e) => bail!("cannot stat {}: {e}", path.display()),
    };
    let before = stamp(Some(&meta));
    let old_text = std::fs::read_to_string(path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?;
    let old = match parse_settings(&old_text) {
        Ok(v) => Some(v),
        Err(_) if strip_jsonc(&old_text).trim().is_empty() => None,
        Err(e) => {
            outln!("{by_hand}");
            bail!("cannot parse {}: {e}", path.display());
        }
    };
    let Some(wrapper) = old.as_ref().and_then(|v| v.get(WRAPPER_SETTING)) else {
        outln!("settings: {}", path.display());
        outln!("  {WRAPPER_SETTING}: unset (nothing to remove)");
        return Ok(None);
    };
    let (new_text, removed) = match remove_settings(&old_text, &[WRAPPER_SETTING]) {
        Ok(r) => r,
        Err(e) => {
            outln!("{by_hand}");
            bail!("{}: {e}", path.display());
        }
    };
    let permission = old.as_ref().and_then(|v| v.get(PERMISSION_SETTING));
    let was = permission.map_or_else(|| "unset".to_string(), shown);
    outln!("settings: {}", path.display());
    outln!("  {WRAPPER_SETTING}: {} -> unset", shown(wrapper));
    outln!("  {PERMISSION_SETTING}: {was} (left alone)");
    if removed > 1 {
        outln!("note: {WRAPPER_SETTING} was set {removed} times; every one is removed");
    }
    if wrapper.as_str().and_then(|w| Path::new(w).file_name()).is_none_or(|n| n != "ai-env-claude") {
        outln!("note: {} is not an ai-env-claude; removed all the same (the backup keeps it)", shown(wrapper));
    }
    // §6.4: the views, before anything is written (and in the dry run).
    if let Some(line) = projects.and_then(views_warning) {
        warn(&line);
    }
    if write {
        if let Some(bak) = commit_settings(path, Some(&meta), before, &old_text, &new_text)? {
            outln!("backup: {}", bak.display());
        }
        outln!("wrote: {}", path.display());
    } else {
        outln!("dry run: nothing written; re-run with --write");
    }
    Ok(old)
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
        let name = path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        bail!("{name} changed while editing; re-run");
    }
    let backup = match meta {
        Some(m) => {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                opts.mode(m.permissions().mode() & 0o777);
            }
            // Never clobber a backup: a second edit within the same second
            // gets `<name>.<secs>-<n>.ai-env.bak`.
            let now = unix_now();
            let mut n = 0u32;
            let (bak, mut f) = loop {
                let bak = backup_path_n(path, now, n);
                match opts.open(&bak) {
                    Ok(f) => break (bak, f),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 9 => n += 1,
                    Err(e) => return Err(CliError::Msg(format!("cannot create backup {}: {e}", bak.display()))),
                }
            };
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

    #[test]
    fn commit_twice_in_one_second_keeps_both_backups_and_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.toml");
        let texts = ["[aws]\n", "[aws]\nregion = \"eu-central-1\"\n", "[aws]\nregion = \"eu-central-1\"\nbudget_name = \"b\"\n"];
        std::fs::write(&path, texts[0]).unwrap();
        // Squat this second's and the next second's backup names: the commit
        // must pick a `-<n>` name and leave the squatters alone.
        let now = unix_now();
        let squatters = [backup_path(&path, now), backup_path(&path, now + 1)];
        for s in &squatters {
            std::fs::write(s, "squatter").unwrap();
        }
        let mut backups = Vec::new();
        for pair in texts.windows(2) {
            let meta = std::fs::symlink_metadata(&path).unwrap();
            backups.push(commit_settings(&path, Some(&meta), stamp(Some(&meta)), pair[0], pair[1]).unwrap().expect("a backup"));
        }
        assert_ne!(backups[0], backups[1], "no clobbering: {backups:?}");
        for b in &backups {
            assert!(!squatters.contains(b), "a numbered name next to the squatter: {b:?}");
            assert!(b.file_name().unwrap().to_string_lossy().ends_with("-1.ai-env.bak") || b.file_name().unwrap().to_string_lossy().ends_with("-2.ai-env.bak"), "{b:?}");
        }
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), texts[0]);
        assert_eq!(std::fs::read_to_string(&backups[1]).unwrap(), texts[1]);
        for s in &squatters {
            assert_eq!(std::fs::read_to_string(s).unwrap(), "squatter");
        }
        let meta = std::fs::symlink_metadata(&path).unwrap();
        std::fs::write(&path, "changed").unwrap();
        let err = commit_settings(&path, Some(&meta), stamp(Some(&meta)), texts[2], "x").unwrap_err();
        assert!(err.to_string().starts_with("bridge.toml changed while editing"), "{err}");
    }

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

    /// `uninstall`'s removal: the member and one comma (the last member's
    /// from before it, only the comma byte), its whole lines when it is
    /// alone on them; comments outside it, the trailing-comma style,
    /// indents, tabs and CRLF stay.
    #[test]
    fn remove_takes_the_member_and_one_comma() {
        for (src, want) in [
            // Four-space indent, between two members.
            ("{\n    \"a\": 1,\n    \"k\": \"v\",\n    \"z\": 2\n}\n", "{\n    \"a\": 1,\n    \"z\": 2\n}\n"),
            // The last member, no trailing comma: the comma before it goes.
            ("{\n  \"a\": 1,\n  \"k\": \"v\"\n}\n", "{\n  \"a\": 1\n}\n"),
            // CRLF with tabs, last and first.
            ("{\r\n\t\"a\": 1,\r\n\t\"k\": \"v\"\r\n}\r\n", "{\r\n\t\"a\": 1\r\n}\r\n"),
            ("{\r\n\t\"k\": \"v\",\r\n\t\"a\": 1\r\n}\r\n", "{\r\n\t\"a\": 1\r\n}\r\n"),
            // A comment after the previous comma stays: only the comma goes.
            ("{\n  \"a\": 1, // one\n  \"k\": \"v\"\n}\n", "{\n  \"a\": 1 // one\n}\n"),
            // A trailing comma stays trailing.
            ("{\n  \"a\": 1,\n  \"k\": \"v\",\n}\n", "{\n  \"a\": 1,\n}\n"),
            // A comment line before the member, a comment after its comma: both stay.
            ("{\n  \"a\": 1,\n  // mine\n  \"k\": \"v\",\n  \"z\": 2\n}\n", "{\n  \"a\": 1,\n  // mine\n  \"z\": 2\n}\n"),
            ("{\n  \"k\": \"v\", // why\n  \"z\": 2\n}\n", "{\n  // why\n  \"z\": 2\n}\n"),
            // A comment inside the member goes with it.
            ("{\n  \"k\": /* old */ \"v\",\n  \"z\": 2\n}\n", "{\n  \"z\": 2\n}\n"),
            // The only member.
            ("{\"k\": \"v\"}", "{}"),
            ("{ \"k\": \"v\" }", "{ }"),
            ("{\n  \"k\": \"v\"\n}\n", "{\n}\n"),
            ("{\n  \"k\": \"v\",\n}\n", "{\n}\n"),
            // One line: first, middle, last, compact.
            ("{\"k\": \"v\", \"a\": 1}", "{\"a\": 1}"),
            ("{\"a\": 1, \"k\": \"v\", \"z\": 2}", "{\"a\": 1, \"z\": 2}"),
            ("{ \"a\": 1, \"k\": \"v\" }", "{ \"a\": 1 }"),
            ("{\"a\":1,\"k\":\"v\"}", "{\"a\":1}"),
            // Behind another member on its line: the blanks before it go too.
            ("{\n  \"a\": 1, \"k\": \"v\",\n  \"z\": 2\n}\n", "{\n  \"a\": 1,\n  \"z\": 2\n}\n"),
            ("{\n  \"a\": 1, \"k\": \"v\"\n}\n", "{\n  \"a\": 1\n}\n"),
            // An object value over several lines: every one of them.
            ("{\n  \"k\": {\n    \"nested\": [1,\n      2]\n  },\n  \"z\": 2\n}\n", "{\n  \"z\": 2\n}\n"),
        ] {
            assert_eq!(remove_settings(src, &["k"]), Ok((want.to_string(), 1)), "{src:?}");
        }
    }

    /// Every top-level copy goes (serde and Cursor read the last one), an
    /// escaped key matches, the key nested, in a string or in a comment
    /// never does, and what does not parse is refused as the splice refuses it.
    #[test]
    fn remove_takes_every_copy_and_nothing_else() {
        let twice = "{\n  \"k\": \"v\",\n  \"a\": 1,\n  \"k\": \"w\"\n}\n";
        assert_eq!(remove_settings(twice, &["k"]), Ok(("{\n  \"a\": 1\n}\n".to_string(), 2)));
        let escaped = "{\"claudeCode\\u002eclaudeProcessWrapper\": \"/x/ai-env-claude\", \"a\": 1}";
        assert_eq!(remove_settings(escaped, &[WRAPPER_SETTING]), Ok(("{\"a\": 1}".to_string(), 1)));
        // splice_is_not_confused_by_the_key_inside_strings_comments_or_nested_objects' source.
        let src = "{\n  // \"claudeCode.claudeProcessWrapper\": \"in a comment\"\n  \"note\": \"\\\"claudeCode.claudeProcessWrapper\\\": in a string\",\n  \"nested\": { \"claudeCode.claudeProcessWrapper\": \"depth 2\" },\n  /* \"claudeCode.claudeProcessWrapper\": \"in a block\" */\n  \"list\": [\"claudeCode.claudeProcessWrapper\"]\n}\n";
        assert_eq!(remove_settings(src, &[WRAPPER_SETTING]), Ok((src.to_string(), 0)));
        assert_eq!(remove_settings("{}\n", &[WRAPPER_SETTING]), Ok(("{}\n".to_string(), 0)));
        for (text, why) in [
            ("{\"a\": }", "cannot parse the settings"),
            ("", "cannot parse the settings"),
            ("{\"a\": 1} {}", "cannot parse the settings"),
            ("[1, 2]", "the top-level value is not an object"),
            // Parses once the comment is stripped, but its tokens are no member list.
            ("{\"k\": tru/**/e}", "expected ',' or '}'"),
        ] {
            let e = remove_settings(text, &["k"]).unwrap_err();
            assert!(e.contains(why), "{text:?}: {e}");
        }
    }

    /// U4: `uninstall` then `install` gives back the same bytes when the
    /// wrapper key sat on its own line just before `initialPermissionMode`,
    /// as install writes it. With the key gone, the splice puts it back just
    /// before `initialPermissionMode` when that starts its own line (its
    /// indent and its line's ending), else before the final `}` as before; a
    /// key that sat anywhere else comes back there, the settings the same.
    #[test]
    fn remove_then_splice_gives_back_the_same_bytes() {
        let wrapper = "/x/ai-env-claude";
        for (src, mode) in [
            // The two splices above: plain JSON, JSONC with a trailing comma.
            ("{\n    \"editor.tabSize\": 2,\n    \"nested\": {\"k\": [1, 2]},\n    \"z\": \"last\",\n    \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n    \"claudeCode.initialPermissionMode\": \"default\"\n}\n", "default"),
            ("{\n  // Cursor settings\n  \"editor.tabSize\": 2, /* block */\n  \"url\": \"http://x/y\", // a line comment with \"quotes\"\n  \"list\": [1, 2, ],\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"manual\",\n}\n", "manual"),
            // A member after the mode; the wrapper first, no final newline; CRLF with tabs.
            ("{\n  \"a\": 1,\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"plan\",\n  \"z\": 2\n}\n", "plan"),
            ("{\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\",\n  \"a\": 1\n}", "default"),
            ("{\r\n\t\"a\": 1,\r\n\t\"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\r\n\t\"claudeCode.initialPermissionMode\": \"default\"\r\n}\r\n", "default"),
        ] {
            let (removed, n) = remove_settings(src, &[WRAPPER_SETTING]).unwrap();
            assert_eq!(n, 1, "{src:?}");
            assert_eq!(splice_settings(&removed, &[(WRAPPER_SETTING, wrapper), (PERMISSION_SETTING, mode)]).unwrap(), src, "{removed:?}");
        }
        // install's own lines in a CRLF file end in LF: the key comes back with the mode line's ending.
        for src in ["{\r\n  \"a\": 1\r\n}\r\n", "{\r\n\t\"a\": 1,\r\n}", "{}\r\n"] {
            let entries = [(WRAPPER_SETTING, wrapper), (PERMISSION_SETTING, "default")];
            let installed = splice_settings(src, &entries).unwrap();
            let (removed, _) = remove_settings(&installed, &[WRAPPER_SETTING]).unwrap();
            assert_eq!(splice_settings(&removed, &entries).unwrap(), installed, "{src:?}");
        }
        // The mode not on a line of its own: before the final `}`, as before.
        let (removed, _) = remove_settings("{\"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\", \"claudeCode.initialPermissionMode\": \"default\"}", &[WRAPPER_SETTING]).unwrap();
        assert_eq!(removed, "{\"claudeCode.initialPermissionMode\": \"default\"}");
        assert_eq!(splice_settings(&removed, &[(WRAPPER_SETTING, wrapper), (PERMISSION_SETTING, "default")]).unwrap(), "{\"claudeCode.initialPermissionMode\": \"default\",\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\"\n}");
        // Another layout (the key last, after the mode, as the install before U4 left a file whose mode
        // was set; the key with a comment after it): the key comes back before the mode, not where it was.
        for (src, back) in [
            (
                "{\n  \"editor.tabSize\": 2,\n  \"claudeCode.initialPermissionMode\": \"default\",\n  \"window.zoomLevel\": 1,\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\"\n}\n",
                "{\n  \"editor.tabSize\": 2,\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\",\n  \"window.zoomLevel\": 1\n}\n",
            ),
            (
                "{\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\", // ai-env\n  \"claudeCode.initialPermissionMode\": \"default\"\n}\n",
                "{\n  // ai-env\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\"\n}\n",
            ),
        ] {
            let (removed, _) = remove_settings(src, &[WRAPPER_SETTING]).unwrap();
            let again = splice_settings(&removed, &[(WRAPPER_SETTING, wrapper), (PERMISSION_SETTING, "default")]).unwrap();
            assert_eq!(again, back, "{src:?}");
            assert_eq!(parse_settings(&again).unwrap(), parse_settings(src).unwrap(), "the same settings: {src:?}");
        }
    }

    /// S8 T8.7: rules spliced into `permissions.<kind>` in the document's
    /// own style (the image's one-line file, a pretty one, JSONC's trailing
    /// comma), the list or `permissions` added when missing, every other
    /// byte kept; anything the splice cannot do faithfully refuses.
    #[test]
    fn splice_rules_appends_in_the_documents_style() {
        let rules = |r: &[&str]| -> Vec<String> { r.iter().map(|s| (*s).to_string()).collect() };
        let image = "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[]}}";
        let once = splice_rules(image, "allow", &rules(&["Bash(git status)", "Read"])).unwrap();
        assert_eq!(once, "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[\"Bash(git status)\",\"Read\"]}}");
        assert_eq!(splice_rules(&once, "allow", &rules(&["Edit(./src/**)"])).unwrap(), "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[\"Bash(git status)\",\"Read\",\"Edit(./src/**)\"]}}");
        assert_eq!(splice_rules(image, "deny", &rules(&["Bash(rm:*)"])).unwrap(), "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[],\"deny\":[\"Bash(rm:*)\"]}}");
        assert_eq!(splice_rules("{\"model\":\"x\"}", "ask", &rules(&["WebFetch"])).unwrap(), "{\"model\":\"x\",\"permissions\":{\"ask\":[\"WebFetch\"]}}");
        assert_eq!(splice_rules("{}", "allow", &rules(&["Read"])).unwrap(), "{\"permissions\":{\"allow\":[\"Read\"]}}");
        let pretty = "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read\"\n    ]\n  }\n}\n";
        assert_eq!(splice_rules(pretty, "allow", &rules(&["Bash(ls)", "Glob"])).unwrap(), "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read\",\n      \"Bash(ls)\",\n      \"Glob\"\n    ]\n  }\n}\n");
        let no_list = "{\n  \"permissions\": {\n    \"defaultMode\": \"default\"\n  }\n}\n";
        assert_eq!(splice_rules(no_list, "allow", &rules(&["Read"])).unwrap(), "{\n  \"permissions\": {\n    \"defaultMode\": \"default\",\n    \"allow\": [\"Read\"]\n  }\n}\n");
        let empty_pretty = "{\n  \"permissions\": {\n    \"allow\": [\n    ]\n  }\n}\n";
        assert_eq!(splice_rules(empty_pretty, "allow", &rules(&["Read"])).unwrap(), "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read\"\n    ]\n  }\n}\n");
        let jsonc = "{\n  // the VM's rules\n  \"permissions\": {\"allow\": [\"Read\", ]},\n}\n";
        let out = splice_rules(jsonc, "allow", &rules(&["Bash(ls)"])).unwrap();
        assert_eq!(out, "{\n  // the VM's rules\n  \"permissions\": {\"allow\": [\"Read\", \"Bash(ls)\", ]},\n}\n", "the trailing comma stays trailing, the space before ] too");
        // The last `permissions` is the one the CLI reads, and the one spliced.
        let twice = "{\"permissions\":{\"allow\":[]},\"permissions\":{\"allow\":[\"A\"]}}";
        assert_eq!(splice_rules(twice, "allow", &rules(&["B"])).unwrap(), "{\"permissions\":{\"allow\":[]},\"permissions\":{\"allow\":[\"A\",\"B\"]}}");
        // A value that needs escaping round-trips.
        let quoted = splice_rules(image, "allow", &rules(&["Bash(echo \"hi\" \\ there)"])).unwrap();
        assert_eq!(parse_settings(&quoted).unwrap()["permissions"]["allow"][0], "Bash(echo \"hi\" \\ there)");
        for (text, kind, why) in [
            ("{\"permissions\":[]}", "allow", "permissions is not an object"),
            ("{\"permissions\":{\"allow\":\"Read\"}}", "allow", "permissions.allow is not a list"),
            ("[1]", "allow", "not an object"),
            ("{\"permissions\":{\"allow\":[ /* none yet */ ]}}", "allow", "a comment inside the empty list"),
            ("{\"a\": }", "allow", "cannot parse"),
        ] {
            let e = splice_rules(text, kind, &rules(&["Read"])).unwrap_err();
            assert!(e.contains(why), "{text}: {e}");
        }
    }

    /// `settings-sync --write` puts every file back unless the image scans
    /// clean after it: a finding (exit 9, never a value), a scan that cannot
    /// run, a write that fails; a file absent before is removed again.
    #[test]
    fn write_checked_puts_every_file_back_unless_the_scan_is_clean() {
        use crate::bridge::scan::Finding;
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("settings.json"), d.path().join("policy.txt"));
        std::fs::write(&a, "old\n").unwrap();
        let files = [Replaced { path: &a, old: Some("old\n"), new: "new\n", mode: 0o644 }, Replaced { path: &b, old: None, new: "allow Read\n", mode: 0o600 }];
        let finding = || Ok((vec![Finding { file: "claude/settings.json".into(), line: 1, rule: "allow-not-in-policy".into() }], 7));
        let e = write_checked(&files, finding).unwrap_err();
        assert_eq!(e.exit_code(), 9);
        assert!(e.to_string().contains("claude/settings.json:1: allow-not-in-policy") && e.to_string().contains("put back"), "{e}");
        assert_eq!((std::fs::read_to_string(&a).unwrap(), b.exists()), ("old\n".to_string(), false));
        assert!(write_checked(&files, || Err(CliError::Msg("cannot scan".into()))).is_err());
        assert_eq!((std::fs::read_to_string(&a).unwrap(), b.exists()), ("old\n".to_string(), false));
        let blocked = [Replaced { path: &a, old: Some("old\n"), new: "new\n", mode: 0o644 }, Replaced { path: &d.path().join("missing").join("policy.txt"), old: None, new: "x", mode: 0o600 }];
        assert!(write_checked(&blocked, || Ok((Vec::new(), 1))).is_err());
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "old\n", "the first file is put back when the second cannot be written");
        assert_eq!(write_checked(&files, || Ok((Vec::new(), 7))).unwrap(), 7);
        assert_eq!((std::fs::read_to_string(&a).unwrap(), std::fs::read_to_string(&b).unwrap()), ("new\n".to_string(), "allow Read\n".to_string()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!((std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, std::fs::metadata(&b).unwrap().permissions().mode() & 0o777), (0o644, 0o600));
    }

    /// `install --mode`'s report reads the key as written: unset is passthrough.
    #[test]
    fn configured_mode_reads_the_key_as_written() {
        assert_eq!(configured_mode("[wrapper]\nmode = \"remote\" # S8\n"), Some("remote".into()));
        assert_eq!(configured_mode("[wrapper]\nstrip_debug = true\n"), None);
        assert_eq!(configured_mode(""), None);
        assert_eq!(configured_mode("not toml ="), None);
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

    /// The synthetic answer of the pump's lab knob lands in `stock-ext-oauth`'s
    /// note: the newest answer of the verdicts' extension version, never
    /// shadowed by a newer `none` or `unsent` (a config probe), never one an
    /// older extension gave, and no note when no session recorded one.
    #[test]
    fn the_synthetic_answer_goes_into_the_stock_ext_oauth_note() {
        let end_of = |ext: &str, note: &str| serde_json::json!({"ext": ext, "route": "local", "reason": "unconfigured", "end": 2, "note": note});
        // session_row's extension version.
        let end = |note: &str| end_of("2.1.278", note);
        let stock = "error(getOAuthToken callback is not provided.)";
        let rows = vec![
            end("mode:local-child; end:eof; synthetic_oauth:null"),
            end(&format!("mode:local-child; end:eof; synthetic_oauth:{stock}")),
            end("mode:local-child; end:eof; synthetic_oauth:none"),
            end("mode:local-child; end:eof; synthetic_oauth:unsent"),
            end("mode:local-child; end:eof"),
        ];
        let ext = Some("2.1.278");
        assert_eq!(synthetic_answer(&rows, ext).as_deref(), Some(stock));
        let mut verdicts = probe_verdicts(&session_row(&[]));
        note_synthetic_answer(&mut verdicts, &rows);
        assert_eq!(verdicts[0].note, None, "entrypoint is untouched");
        assert_eq!(verdicts[1].note.as_deref(), Some(format!("the extension answered the synthetic oauth_token_refresh with {stock}").as_str()));
        assert_eq!(verdicts[1].verdict, "absent", "the verdict is still the env names'");
        // Rows are oldest first: with only `none` (row 2) and `unsent` (row 3), the newest is `unsent`.
        assert_eq!(synthetic_answer(&rows[2..], ext).as_deref(), Some("unsent"), "only none or unsent: the newest");
        assert_eq!(synthetic_answer(&rows[4..], ext), None);
        let mut verdicts = probe_verdicts(&session_row(&[]));
        note_synthetic_answer(&mut verdicts, &rows[4..]);
        assert!(verdicts.iter().all(|v| v.note.is_none()));
        // An answer from another extension version, however new, is not this version's.
        let mut mixed = rows.clone();
        mixed.push(end_of("2.1.290", "mode:local-child; end:eof; synthetic_oauth:token(len=108)"));
        assert_eq!(synthetic_answer(&mixed, ext).as_deref(), Some(stock));
        let only_other = vec![end_of("2.1.270", &format!("mode:local-child; end:eof; synthetic_oauth:{stock}"))];
        let mut verdicts = probe_verdicts(&session_row(&[]));
        note_synthetic_answer(&mut verdicts, &only_other);
        assert!(verdicts.iter().all(|v| v.note.is_none()), "no note from an older extension's answer");
    }

    /// S8's `init-wrapper` row (plan L8) follows the two S1 rows once the
    /// census holds a remote end row: none for a census of local sessions;
    /// with only a cold row its verdict is a gap, recorded, and the command
    /// fails after writing it, naming it; with the newest cold and warm rows
    /// within their budgets it records `within-budget` and passes.
    #[test]
    fn record_probes_appends_the_init_wrapper_row_once_remote_end_rows_exist() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let recorded = || -> Vec<(String, String)> {
            let text = std::fs::read_to_string(paths.probes()).unwrap_or_default();
            text.lines().map(|l| serde_json::from_str::<ProbeRow>(l).unwrap()).map(|r| (r.probe, r.verdict)).collect()
        };
        let end_of = |pid: u32, note: &str| {
            let mut row = session_row(&[]);
            row["pid"] = serde_json::json!(pid);
            row["end"] = serde_json::json!(1_790_150_406_100u64);
            row["exit"] = serde_json::json!(0);
            row["note"] = serde_json::json!(note);
            row
        };
        let local = end_of(1, "mode:local-child; end:eof; child_pid:7; respawns:0; init_ms:900");
        record_probes(&paths, &[session_row(&[]), local.clone()]).unwrap();
        assert_eq!(recorded().iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(), ["entrypoint", "stock-ext-oauth"], "no remote end row: no init-wrapper row");
        let remote = |how: &str, ms: u64| format!("mode:remote; end:eof; init_ms:{ms}; vm:microvm-1; vm_how:{how}; legs:touchid=1800,select=2400,workspace=900,gate=300,spawn=700");
        let cold = end_of(2, &remote("started", 12_000));
        let err = record_probes(&paths, &[session_row(&[]), local.clone(), cold.clone()]).unwrap_err().to_string();
        assert!(err.contains("init-wrapper=gap:warm (expected within-budget)"), "{err}");
        assert_eq!(recorded()[2..], [("entrypoint".to_string(), "claude-vscode".to_string()), ("stock-ext-oauth".to_string(), "absent".to_string()), ("init-wrapper".to_string(), "gap:warm".to_string())], "written before it failed");
        let warm = end_of(3, &remote("reused", 3_000));
        record_probes(&paths, &[session_row(&[]), local, cold, warm]).unwrap();
        let rows: Vec<ProbeRow> = std::fs::read_to_string(paths.probes()).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let last = rows.last().unwrap();
        assert_eq!((last.probe.as_str(), last.stage.as_str(), last.verdict.as_str()), ("init-wrapper", "S8", "within-budget"));
        assert!(last.note.as_deref().is_some_and(|n| n.starts_with("cold 12000 ms (touchid 1800 ms; ") && n.contains("; warm 3000 ms (touchid 1800 ms; ")), "{last:?}");
        assert_eq!(init_wrapper_verdict(&[session_row(&[])]), None);
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
    fn census_line_shows_exit_and_duration_of_an_end_row() {
        let mut end = session_row(&[]);
        end["start"] = serde_json::json!(1_000_u64);
        end["end"] = serde_json::json!(6_123_u64);
        end["exit"] = serde_json::json!(0);
        assert_eq!(census_line(&end), "2026-09-23T08:00:00Z  remote session                  2.1.278  /Users/mike/Documents/DeFi/ai-env  exit=0 dur=5123ms  --output-format stream-json");
        end["exit"] = serde_json::Value::Null;
        assert!(census_line(&end).contains("exit=null dur=5123ms  --output-format"), "{}", census_line(&end));
        let start = session_row(&[]);
        assert!(!census_line(&start).contains("exit="), "a start row has no end fields");
    }

    /// S9: a census another hand wrote (a newline and a forged row, an
    /// escape sequence, a carriage return, a NUL, DEL, a C1 control) in any
    /// field the line prints, the argv tail included, never reaches the
    /// terminal as a control character: each is escaped as Rust writes it,
    /// and the line stays one line.
    #[test]
    fn census_line_never_prints_a_control_character() {
        let forged = "\n2026-09-23T08:00:00Z  remote session  forged";
        let row = serde_json::json!({
            "ts": format!("2026-09-23T08:00:00Z{forged}"),
            "route": "remote\u{1b}[2J",
            "reason": "session\r",
            "ext": "2.1.278\u{0}",
            "cwd": "/Users/mike/w\u{7f}\u{9b}31m",
            "argv": ["/w/ai-env-claude", "/b/claude\u{1b}]0;title\u{7}", "--output-format", "stream-json\u{1b}[1A", "\t--verbose"],
            "start": 1_000_u64,
            "end": 2_000_u64,
            "exit": 0,
        });
        let line = census_line(&row);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert_eq!(line.lines().count(), 1, "{line:?}");
        for want in ["2026-09-23T08:00:00Z\\n2026-09-23T08:00:00Z  remote session  forged", "remote\\u{1b}[2J", "session\\r", "2.1.278\\0", "/Users/mike/w\\u{7f}\\u{9b}31m", "stream-json\\u{1b}[1A \\t--verbose"] {
            assert!(line.contains(want), "{want:?} missing from {line:?}");
        }
        // A plain row prints as it did.
        assert_eq!(printable("2026-09-23T08:00:00Z /a b—ü"), "2026-09-23T08:00:00Z /a b—ü");
    }

    /// S9 (§6.4): while remote chats keep only their view under
    /// `<projects>` (a file whose first bytes are the view's mark), the
    /// dry run and `--write` both warn before anything is written (the
    /// settings file still holds the key when the warning goes out),
    /// counting each view once: a transcript, a symlink to a view, a view
    /// one directory too deep, a file that is not `.jsonl` or a FIFO is
    /// none. No view, or no `<projects>`, no warning.
    #[test]
    fn uninstall_warns_while_views_exist() {
        use crate::wire::view::VIEW_MARK_PREFIX;
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings.json");
        let projects = dir.path().join("projects");
        let slug = projects.join("-Users-mike-w");
        std::fs::create_dir_all(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b").join("subagents")).unwrap();
        let view = format!("{VIEW_MARK_PREFIX}\"type\":\"ai-title\",\"aiTitle\":\"t\",\"sessionId\":\"s\"}}\n");
        std::fs::write(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl"), &view).unwrap();
        std::fs::write(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c.jsonl"), "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"hi\"}}\n").unwrap();
        std::fs::write(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b").join("subagents").join("agent-a1.jsonl"), &view).unwrap();
        std::fs::write(slug.join("notes.txt"), &view).unwrap();
        std::os::unix::fs::symlink(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl"), slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d.jsonl")).unwrap();
        let fifo = std::ffi::CString::new(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e.jsonl").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let other = projects.join("-Users-mike-x");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60.jsonl"), &view).unwrap();
        let text = format!("{{\n  {}: \"/x/ai-env-claude\",\n  {}: \"default\"\n}}\n", json_str(WRAPPER_SETTING), json_str(PERMISSION_SETTING));
        let want = format!("2 remote chats keep only their view under {}: with the wrapper off, Cursor resumes an open one on this Mac; close their tabs first", projects.display());
        for write in [false, true] {
            std::fs::write(&settings, &text).unwrap();
            let mut warned = Vec::new();
            let old = uninstall_settings(&settings, Some(&projects), write, &mut |line| {
                assert_eq!(std::fs::read_to_string(&settings).unwrap(), text, "write {write}: the warning goes out before anything is written");
                warned.push(line.to_string());
            })
            .unwrap();
            assert_eq!(warned, std::slice::from_ref(&want), "write {write}");
            assert!(old.is_some_and(|v| v.get(WRAPPER_SETTING).is_some()), "write {write}: the settings as they were");
            assert_eq!(std::fs::read_to_string(&settings).unwrap() == text, !write, "write {write}: written only with --write");
        }
        // One view: §6.4's one line, with 1; no view, no <projects>, or nothing to remove: no warning.
        std::fs::remove_dir_all(&other).unwrap();
        assert_eq!(views_warning(&projects), Some(format!("1 remote chats keep only their view under {}: with the wrapper off, Cursor resumes an open one on this Mac; close their tabs first", projects.display())));
        std::fs::remove_file(slug.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl")).unwrap();
        assert_eq!(views_warning(&projects), None, "the transcript, the dangling link, the deep view, the text file and the FIFO count for nothing");
        assert_eq!(views_warning(&dir.path().join("absent")), None);
        std::fs::write(&settings, &text).unwrap();
        let mut warned = 0;
        assert!(uninstall_settings(&settings, None, false, &mut |_| warned += 1).unwrap().is_some());
        std::fs::write(&settings, "{}\n").unwrap();
        std::fs::write(other_view(&projects), &view).unwrap();
        assert!(uninstall_settings(&settings, Some(&projects), true, &mut |_| warned += 1).unwrap().is_none(), "no wrapper key: nothing to remove");
        assert_eq!(warned, 0);
        // `<projects>` as the kill switch finds it.
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| std::ffi::OsString::from(*v));
        assert_eq!(view_projects(&env(&[("HOME", "/h"), ("CLAUDE_CONFIG_DIR", "/c")])), Some(PathBuf::from("/c/projects")));
        assert_eq!(view_projects(&env(&[("HOME", "/h"), ("CLAUDE_CONFIG_DIR", "")])), Some(PathBuf::from("/h/.claude/projects")));
        assert_eq!(view_projects(&env(&[("HOME", "")])), None);
        assert_eq!(view_projects(&env(&[])), None);
    }

    /// A view file of its own project directory under `projects`.
    fn other_view(projects: &Path) -> PathBuf {
        let dir = projects.join("-Users-mike-y");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61.jsonl")
    }

    #[test]
    fn snippet_and_backup_name() {
        let s = snippet("/x/ai-env-claude", "default");
        assert_eq!(s, "{\n  \"claudeCode.claudeProcessWrapper\": \"/x/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\"\n}");
        assert!(parse_settings(&s).is_ok());
        assert_eq!(backup_path(Path::new("/u/User/settings.json"), 17), PathBuf::from("/u/User/settings.json.17.ai-env.bak"));
        assert_eq!(backup_path_n(Path::new("/b/bridge.toml"), 17, 2), PathBuf::from("/b/bridge.toml.17-2.ai-env.bak"));
        assert_eq!(PERMISSION_MODES.len(), 5);
        assert!(PERMISSION_MODES.contains(&"manual"));
    }
}
