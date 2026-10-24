//! The audit's reader (S11): the rows of `audit.jsonl` as the views read them
//! ([`Read`]), whole files ([`read_all`]), the lines past an offset
//! ([`since`]) and a follower that keeps reading a growing file
//! ([`Follower`]); then the filters, the text form and the two commands
//! `ai-env audit tail` and `ai-env audit grep`. A v1 row (S10's, no actor) is
//! read best effort; a v2 row as the registry says; an unknown event, or `v`
//! above 2, is shown raw and never read by cost.
//!
//! Phase 0 built the reading half (`Read`, `parse_line`, `read_all`,
//! `since`, the follower's offsets); S11 wave 1's B2 the rest.
use super::schema::{self, SessionFrom};
use crate::bridge::config::Paths;
use crate::wire::redact::scrub;
use crate::bridge::errors::BridgeError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How often a follower looks again.
pub const FOLLOW_POLL: Duration = Duration::from_millis(250);

/// One stored row as the views read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The stored line, without its newline.
    pub raw: String,
    pub v: u64,
    pub ts: String,
    /// `ts` as unix seconds (0 when unreadable).
    pub at: u64,
    pub event: String,
    /// The envelope's `session_id`, else the spec's detail key when it holds a uuid.
    pub session: Option<String>,
    pub pid: u32,
    /// `detail.actor` (`None` for a v1 row without one).
    pub actor: Option<String>,
    /// The values of the spec's `vm_keys`, in its order, `-` left out (the first one cost charges).
    pub vms: Vec<String>,
    pub detail: BTreeMap<String, String>,
    /// Registered and `v` at most 2: cost reads it; otherwise shown raw only.
    pub known: bool,
}

/// One line; `None` for a line that is no JSON object with `event` and `ts`.
#[must_use]
pub fn parse_line(line: &str) -> Option<Read> {
    let raw = line.trim_end_matches(['\n', '\r']);
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = value.as_object()?;
    let event = obj.get("event")?.as_str()?.to_string();
    let ts = obj.get("ts")?.as_str()?.to_string();
    let v = obj.get("v").and_then(serde_json::Value::as_u64).unwrap_or(0);
    let pid = obj.get("pid").and_then(serde_json::Value::as_u64).and_then(|p| u32::try_from(p).ok()).unwrap_or(0);
    let detail: BTreeMap<String, String> = obj
        .get("detail")
        .and_then(serde_json::Value::as_object)
        .map(|d| {
            d.iter()
                .map(|(k, v)| {
                    let v = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), v)
                })
                .collect()
        })
        .unwrap_or_default();
    let spec = schema::spec(&event);
    let envelope = obj.get("session_id").and_then(serde_json::Value::as_str).map(str::to_string);
    let session = envelope.or_else(|| match spec?.session {
        SessionFrom::Detail(key) => detail.get(key).filter(|s| crate::bridge::registry::is_uuid(s)).cloned(),
        SessionFrom::Envelope | SessionFrom::None => None,
    });
    let vms = spec.map_or_else(Vec::new, |s| s.vm_keys.iter().filter_map(|k| detail.get(*k)).filter(|v| !v.is_empty() && v.as_str() != "-").cloned().collect());
    Some(Read {
        raw: raw.to_string(),
        v,
        at: crate::wire::time::parse_rfc3339_utc(&ts).unwrap_or(0),
        ts,
        event,
        session,
        pid,
        actor: detail.get("actor").cloned(),
        vms,
        detail,
        known: spec.is_some() && v <= u64::from(super::AUDIT_SCHEMA_V),
    })
}

/// The parseable whole lines of `bytes` (a cut last line, with no newline, is skipped).
fn whole_lines(bytes: &[u8]) -> (Vec<Read>, usize) {
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let rows = bytes[..end].split(|b| *b == b'\n').filter(|l| !l.is_empty()).filter_map(|l| std::str::from_utf8(l).ok()).filter_map(parse_line).collect();
    (rows, end)
}

/// Every row in file order; a missing file is empty; unparseable lines and a cut last line are skipped.
/// Opened as every audit reader opens it (`census::open_for_read`: never a symlink or a FIFO).
pub fn read_all(path: &Path) -> Result<Vec<Read>, BridgeError> {
    use std::io::Read as _;
    let Some(mut file) = crate::bridge::census::open_for_read(path)? else {
        return Ok(Vec::new());
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(whole_lines(&bytes).0)
}

/// The whole lines past byte `from`, and where the next read starts (migrate.rs's `audit_since`, moved here);
/// a file that cannot be read is no rows and the same offset.
#[must_use]
pub fn since(path: &Path, from: u64) -> (Vec<Read>, u64) {
    use std::io::{Read as _, Seek as _};
    let Ok(Some(mut f)) = crate::bridge::census::open_for_read(path) else {
        return (Vec::new(), from);
    };
    if f.seek(std::io::SeekFrom::Start(from)).is_err() {
        return (Vec::new(), from);
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return (Vec::new(), from);
    }
    let (rows, end) = whole_lines(&buf);
    (rows, from + end as u64)
}

/// `<when>`: `<n>s`, `<n>m`, `<n>h`, `<n>d` before `now` (`gc::parse_age`), an RFC 3339 UTC time, or a UTC
/// date `YYYY-MM-DD` (its midnight). Anything else: `Err` naming the three forms.
pub fn parse_when(text: &str, now: u64) -> Result<u64, String> {
    let t = text.trim();
    let forms = || format!("{text:?} is no time: use an age (90s, 30m, 1h, 2d), an RFC 3339 UTC time (2026-10-22T10:00:00Z) or a UTC date (2026-10-22)");
    if t.len() == 10 && t.is_ascii() && t.as_bytes()[4] == b'-' && t.as_bytes()[7] == b'-' {
        return crate::wire::time::parse_rfc3339_utc(&format!("{t}T00:00:00Z")).ok_or_else(forms);
    }
    if let Some(at) = crate::wire::time::parse_rfc3339_utc(t) {
        return Ok(at);
    }
    let age = crate::bridge::vm::gc::parse_age(t).map_err(|_| forms())?;
    now.checked_sub(age.as_secs()).ok_or_else(|| format!("{text:?} reaches before 1970"))
}

/// `text` with every control character (C0, DEL, C1) as its `\u` escape: what reaches the terminal is never an
/// escape sequence, a carriage return or a line break (T8.7's rule for words a VM wrote). The views' text forms
/// (`audit tail|grep`, `cost`, `session list|show`) print through it.
#[must_use]
pub fn terminal_safe(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(text.chars().map(|c| if c.is_control() { format!("\\u{:04x}", u32::from(c)) } else { c.to_string() }).collect())
}

/// A stored line as `--json` prints it: the same JSON, with what a valid line can hold raw and a terminal would
/// act on made inert (DEL and C1 inside strings as their `\u` escapes, a CR or a tab between tokens a space).
/// The panel's `/audit?json=1` sends each line through it too (P-1: the same document as the CLI's).
pub(crate) fn json_line_safe(raw: &str) -> std::borrow::Cow<'_, str> {
    if !raw.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(raw);
    }
    std::borrow::Cow::Owned(raw.chars().map(|c| match c { '\r' | '\t' | '\n' => " ".to_string(), c if c.is_control() => format!("\\u{:04x}", u32::from(c)), c => c.to_string() }).collect())
}

/// One cell of the text form: scrubbed again on its own (as the writer scrubbed it), then a JSON string when it
/// holds a space, a quote, `=` or a control character, the control characters JSON leaves raw (DEL, C1) escaped
/// too.
fn shown(v: &str) -> String {
    let v = scrub(v);
    if !v.chars().any(|c| c.is_control() || matches!(c, ' ' | '"' | '=')) {
        return v.into_owned();
    }
    let quoted = serde_json::to_string(v.as_ref()).unwrap_or_else(|_| "\"?\"".to_string());
    terminal_safe(&quoted).into_owned()
}

/// The text form: `<ts> <actor> <event> <session8> <vm> <k>=<v>…`, every cell scrubbed again and shown inert
/// ([`shown`]); a raw row is its line, scrubbed and its control characters escaped.
#[must_use]
pub fn render(r: &Read) -> String {
    if !r.known {
        return terminal_safe(&scrub(&r.raw)).into_owned();
    }
    let spec = schema::spec(&r.event);
    // The keys the line's first five cells show already: the first VM's key, the session's detail key.
    let vm_key = spec.and_then(|s| s.vm_keys.iter().copied().find(|k| r.detail.get(*k).is_some_and(|v| !v.is_empty() && v != "-")));
    let session_key = match spec.map(|s| s.session) {
        Some(SessionFrom::Detail(key)) if r.session.is_some() && r.detail.get(key) == r.session.as_ref() => Some(key),
        _ => None,
    };
    // Every cell scrubbed again on its own, as the writer scrubbed it (a whole `k=v` line would read as one
    // assignment and lose the cells after a `…token=`).
    let mut line = format!(
        "{} {} {} {} {}",
        shown(&r.ts),
        shown(r.actor.as_deref().unwrap_or("-")),
        shown(&r.event),
        shown(r.session.as_deref().map_or("-", |s| s.get(..8).unwrap_or(s))),
        shown(r.vms.first().map_or("-", String::as_str))
    );
    for (k, v) in r.detail.iter().filter(|(k, _)| k.as_str() != "actor" && Some(k.as_str()) != vm_key && Some(k.as_str()) != session_key) {
        line.push_str(&format!(" {}={}", shown(k), shown(v)));
    }
    line
}

/// `--session`: the session, and its VMs within each generation's span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionScope {
    pub session: String,
    /// `(vm, from, to)` from the row's `vms[]` (`registry::VmEntry`): `to` `None` while it runs.
    pub spans: Vec<(String, u64, Option<u64>)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub session: Option<SessionScope>,
    pub vm: Option<String>,
    pub events: Vec<String>,
    pub actor: Option<String>,
    pub since: Option<u64>,
    pub wheres: Vec<(String, String)>,
}

impl Filter {
    /// The CLI's flags (exit 2: a `--session` that is no uuid, a `--vm` that is no VM id, a `--where`
    /// without `=`, an unreadable `--since`); a `--session` without a row is that session's own rows only.
    pub fn from_args(paths: &Paths, args: &crate::cli::AuditFilterArgs, now: u64) -> crate::errors::Result<Filter> {
        use crate::errors::CliError;
        let session = match &args.session {
            None => None,
            Some(s) if !crate::bridge::registry::is_uuid(s) => return Err(CliError::Usage(format!("--session {s:?}: not a session id"))),
            Some(s) => {
                let spans = crate::bridge::registry::read(paths, s)?.map(|row| crate::bridge::registry::generation_spans(&row)).unwrap_or_default();
                Some(SessionScope { session: s.clone(), spans })
            }
        };
        if let Some(vm) = args.vm.as_deref().filter(|v| !crate::bridge::vm::registry::is_vm_id(v)) {
            return Err(CliError::Usage(format!("--vm {vm:?}: not a microvm id")));
        }
        let since = match args.since.as_deref() {
            None => None,
            Some(text) => Some(parse_when(text, now).map_err(|e| CliError::Usage(format!("--since: {e}")))?),
        };
        let mut wheres = Vec::new();
        for w in &args.wheres {
            let Some((k, v)) = w.split_once('=') else {
                return Err(CliError::Usage(format!("--where {w:?}: expected K=V")));
            };
            wheres.push((k.to_string(), v.to_string()));
        }
        let actor = args.actor.map(|a| match a {
            crate::cli::ActorArg::Cli => "cli".to_string(),
            crate::cli::ActorArg::Wrapper => "wrapper".to_string(),
            crate::cli::ActorArg::Panel => "panel".to_string(),
        });
        let events = args.event.iter().map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect();
        Ok(Filter { session, vm: args.vm.clone(), events, actor, since, wheres })
    }

    /// Every given filter holds (AND); `--event` holds when the event is one of them.
    #[must_use]
    pub fn matches(&self, r: &Read) -> bool {
        if let Some(scope) = &self.session {
            let own = r.session.as_deref() == Some(scope.session.as_str());
            let now = crate::bridge::lab::now();
            let on_vm = scope.spans.iter().any(|(vm, from, to)| r.vms.contains(vm) && r.at >= *from && r.at <= to.unwrap_or(now));
            if !own && !on_vm {
                return false;
            }
        }
        if let Some(vm) = &self.vm {
            // A raw row (an unknown event) names no VM key: any detail value equal to the id counts.
            if !r.vms.contains(vm) && (r.known || !r.detail.values().any(|v| v == vm)) {
                return false;
            }
        }
        if !self.events.is_empty() && !self.events.contains(&r.event) {
            return false;
        }
        if self.actor.as_ref().is_some_and(|a| r.actor.as_ref() != Some(a)) {
            return false;
        }
        if self.since.is_some_and(|since| r.at < since) {
            return false;
        }
        self.wheres.iter().all(|(k, v)| r.detail.get(k) == Some(v))
    }
}

/// Follows a file by byte offset: whole lines only (a partial last line is held until its newline);
/// a file shorter than the offset (truncated) or another inode (replaced) restarts at offset 0.
#[derive(Debug)]
pub struct Follower {
    path: PathBuf,
    offset: u64,
    inode: Option<u64>,
    partial: Vec<u8>,
}

/// The inode and length of `path`, when it is a file.
fn stat(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().filter(std::fs::Metadata::is_file).map(|m| (m.ino(), m.len()))
}

impl Follower {
    /// From the file's end now (its length; 0 when missing).
    #[must_use]
    pub fn at_end(path: &Path) -> Follower {
        let st = stat(path);
        Follower { path: path.to_path_buf(), offset: st.map_or(0, |(_, len)| len), inode: st.map(|(ino, _)| ino), partial: Vec::new() }
    }

    /// From `offset`.
    #[must_use]
    pub fn from(path: &Path, offset: u64) -> Follower {
        Follower { path: path.to_path_buf(), offset, inode: stat(path).map(|(ino, _)| ino), partial: Vec::new() }
    }

    /// The rows written since the last call (unparseable whole lines skipped).
    pub fn poll(&mut self) -> Vec<Read> {
        use std::io::{Read as _, Seek as _};
        let Some((ino, len)) = stat(&self.path) else {
            return Vec::new();
        };
        if self.inode.is_some_and(|i| i != ino) || len < self.offset {
            // Replaced or truncated: the new file from its start.
            self.offset = 0;
            self.partial.clear();
        }
        self.inode = Some(ino);
        if len == self.offset {
            return Vec::new();
        }
        let Ok(Some(mut f)) = crate::bridge::census::open_for_read(&self.path) else {
            return Vec::new();
        };
        let mut buf = Vec::new();
        if f.seek(std::io::SeekFrom::Start(self.offset)).is_err() || f.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        self.offset += buf.len() as u64;
        self.partial.extend_from_slice(&buf);
        let (rows, end) = whole_lines(&self.partial);
        self.partial.drain(..end);
        rows
    }

    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Every row of `path` and where its last whole line ends (the follower's start); a missing file is none at 0.
fn read_all_to_end(path: &Path) -> Result<(Vec<Read>, u64), BridgeError> {
    use std::io::Read as _;
    let Some(mut file) = crate::bridge::census::open_for_read(path)? else {
        return Ok((Vec::new(), 0));
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (rows, end) = whole_lines(&bytes);
    Ok((rows, end as u64))
}

/// One row as the commands print it: its stored line with `--json` (as stored: its shape is the file's), else
/// [`render`].
fn print_row(r: &Read, json: bool) -> crate::errors::Result<()> {
    if json {
        crate::outln!("{}", json_line_safe(&r.raw));
    } else {
        crate::outln!("{}", render(r));
    }
    Ok(())
}

/// Set by SIGINT or SIGTERM while `audit tail -f` follows: the loop ends with exit 0.
static FOLLOW_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_follow_stop(_sig: libc::c_int) {
    FOLLOW_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Ctrl-C (and SIGTERM) end a follow with exit 0; a signal ignored at start stays ignored.
fn arm_follow_stop() {
    let handler: extern "C" fn(libc::c_int) = on_follow_stop;
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: sigaction(2) on zeroed (valid) structs; the handler only stores an atomic (async-signal-safe).
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &raw mut old) != 0 || old.sa_sigaction == libc::SIG_IGN {
                continue;
            }
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = handler as libc::sighandler_t;
            libc::sigemptyset(&raw mut act.sa_mask);
            libc::sigaction(sig, &raw const act, std::ptr::null_mut());
        }
    }
}

/// `ai-env audit tail` (B §B2.10): the last `n` matching rows, oldest first; with `follow`, then every new
/// matching row as it is written (Ctrl-C, SIGTERM or a closed pipe end it, exit 0).
pub fn cmd_tail(n: u32, follow: bool, filter: &crate::cli::AuditFilterArgs, json: bool) -> crate::errors::Result<()> {
    let paths = Paths::resolve()?;
    let filter = Filter::from_args(&paths, filter, crate::bridge::lab::now())?;
    let path = paths.audit();
    let (rows, end) = read_all_to_end(&path)?;
    let matched: Vec<&Read> = rows.iter().filter(|r| filter.matches(r)).collect();
    let skip = matched.len().saturating_sub(usize::try_from(n).unwrap_or(usize::MAX));
    for r in &matched[skip..] {
        print_row(r, json)?;
    }
    if !follow {
        return Ok(());
    }
    arm_follow_stop();
    let mut follower = Follower::from(&path, end);
    while !FOLLOW_STOP.load(std::sync::atomic::Ordering::SeqCst) {
        for r in follower.poll().iter().filter(|r| filter.matches(r)) {
            print_row(r, json)?;
        }
        std::thread::sleep(FOLLOW_POLL);
    }
    Ok(())
}

/// Whether `audit grep`'s `needle` (lower case already with `ignore_case`) is in `r`'s one-line form ([`render`]),
/// or in its full session id, which that line shows as its first 8 characters (B-CLI-1: the uuid `session list`
/// prints finds the session's rows).
fn grep_hit(r: &Read, needle: &str, ignore_case: bool) -> bool {
    let holds = |text: &str| if ignore_case { text.to_ascii_lowercase().contains(needle) } else { text.contains(needle) };
    holds(&render(r)) || r.session.as_deref().is_some_and(holds)
}

/// `ai-env audit grep` (B §B2.10): every matching row whose one-line form, or full session id, holds `pattern` (a
/// fixed string; `ignore_case`: ASCII case), in file order; exit 1 with no match and nothing printed.
pub fn cmd_grep(pattern: &str, ignore_case: bool, filter: &crate::cli::AuditFilterArgs, json: bool) -> crate::errors::Result<()> {
    let paths = Paths::resolve()?;
    let filter = Filter::from_args(&paths, filter, crate::bridge::lab::now())?;
    let rows = read_all(&paths.audit())?;
    let needle = if ignore_case { pattern.to_ascii_lowercase() } else { pattern.to_string() };
    let mut hits = 0usize;
    for r in rows.iter().filter(|r| filter.matches(r)) {
        if grep_hit(r, &needle, ignore_case) {
            hits += 1;
            print_row(r, json)?;
        }
    }
    if hits == 0 {
        return Err(crate::errors::CliError::Exit(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "11111111-2222-4333-8444-555555555555";

    /// A v2 row, a v1 row, an unknown event and a row of a later schema; then a cut last line.
    #[test]
    fn rows_parse_and_a_cut_line_is_skipped() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let lines = [
            format!(r#"{{"v":2,"ts":"2026-10-22T10:00:00Z","event":"transcript_pull","session_id":null,"pid":7,"detail":{{"actor":"wrapper","session":"{SID}","vm":"microvm-a","parts":"1","bytes":"2","outcome":"restored","ms":"3"}}}}"#),
            r#"{"v":1,"ts":"2026-10-22T10:00:01Z","event":"vm_suspend","session_id":null,"pid":8,"detail":{"id":"microvm-b"}}"#.to_string(),
            r#"{"v":2,"ts":"2026-10-22T10:00:02Z","event":"unheard_of","session_id":null,"pid":9,"detail":{"actor":"cli"}}"#.to_string(),
            r#"{"v":3,"ts":"2026-10-22T10:00:03Z","event":"vm_resume","session_id":null,"pid":9,"detail":{"actor":"cli","id":"microvm-b"}}"#.to_string(),
            "not json".to_string(),
            r#"{"v":2,"ts":"2026-10-22T10:00:04Z","event":"vm_res"#.to_string(),
        ];
        std::fs::write(&path, lines.join("\n")).unwrap();
        let rows = read_all(&path).unwrap();
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows[0].session.as_deref(), Some(SID), "the detail's uuid");
        assert_eq!((rows[0].actor.as_deref(), rows[0].vms.clone(), rows[0].known, rows[0].pid), (Some("wrapper"), vec!["microvm-a".to_string()], true, 7));
        assert_eq!(rows[0].at, crate::wire::time::parse_rfc3339_utc("2026-10-22T10:00:00Z").unwrap());
        assert_eq!((rows[1].v, rows[1].actor.clone(), rows[1].known), (1, None, true), "a v1 row is read best effort");
        assert!(!rows[2].known && !rows[3].known, "an unknown event and a later schema are shown raw only");
        assert_eq!(rows[3].raw, lines[3]);
        assert!(read_all(&d.path().join("none.jsonl")).unwrap().is_empty());
        let (all, end) = since(&path, 0);
        assert_eq!((all.len(), end), (4, (lines[..5].iter().map(|l| l.len() + 1).sum::<usize>()) as u64));
        let (tail, end2) = since(&path, end);
        assert!(tail.is_empty() && end2 == end, "the cut line waits for its newline");
        assert!(parse_line(r#"{"v":2,"event":"x"}"#).is_none(), "no ts");
        assert!(parse_line("[1]").is_none());
    }

    /// The follower reads whole lines only (a partial last line waits for its newline), and starts the file
    /// again from 0 once it is shorter than its offset (truncated) or another file (replaced).
    #[test]
    fn the_follower_holds_a_partial_line_and_restarts_on_truncation() {
        use std::io::Write as _;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let line = |n: u32| format!(r#"{{"v":2,"ts":"2026-10-22T10:00:0{n}Z","event":"vm_resume","session_id":null,"pid":{n},"detail":{{"actor":"cli","id":"microvm-a"}}}}"#);
        std::fs::write(&path, format!("{}\n", line(1))).unwrap();
        let mut f = Follower::at_end(&path);
        assert!(f.poll().is_empty(), "nothing new");
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let two = line(2);
        file.write_all(&two.as_bytes()[..20]).unwrap();
        assert!(f.poll().is_empty(), "a partial line is held");
        file.write_all(format!("{}\n{}\nnot json\n", &two[20..], line(3)).as_bytes()).unwrap();
        assert_eq!(f.poll().iter().map(|r| r.pid).collect::<Vec<_>>(), [2, 3], "the held line completed, then the next; junk skipped");
        assert_eq!(f.offset(), std::fs::metadata(&path).unwrap().len());
        std::fs::write(&path, format!("{}\n", line(4))).unwrap();
        assert_eq!(f.poll().iter().map(|r| r.pid).collect::<Vec<_>>(), [4], "truncated: from 0 again");
        let other = d.path().join("other.jsonl");
        std::fs::write(&other, format!("{}\n{}\n", line(5), line(6))).unwrap();
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(f.poll().iter().map(|r| r.pid).collect::<Vec<_>>(), [5, 6], "replaced: the new file from 0");
        std::fs::remove_file(&path).unwrap();
        assert!(f.poll().is_empty(), "gone: nothing");
    }

    fn fixture_paths() -> Paths {
        Paths::from_root_and_env(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/s11/bridge"), None)
    }

    /// The filters AND; `--session` also takes its VMs' rows inside each generation's span; bad flags are exit 2.
    #[test]
    fn filters_and_the_session_expansion() {
        use crate::cli::{ActorArg, AuditFilterArgs};
        let paths = fixture_paths();
        let rows = read_all(&paths.audit()).unwrap();
        let now = 1_792_713_600;
        let pick = |args: AuditFilterArgs| {
            let f = Filter::from_args(&paths, &args, now).unwrap();
            rows.iter().filter(|r| f.matches(r)).map(|r| (r.ts[11..19].to_string(), r.event.clone())).collect::<Vec<_>>()
        };
        let s1 = "11111111-1111-4111-8111-111111111111";
        let got = pick(AuditFilterArgs { session: Some(s1.into()), ..AuditFilterArgs::default() });
        let want = [
            ("09:00:00", "vm_select"),
            ("09:00:02", "session_remote_start"),
            ("09:20:00", "session_park"),
            ("10:00:00", "session_unpark"),
            ("10:20:00", "session_move"),
            ("10:21:00", "session_move_end"),
            ("10:21:05", "session_remote_start"),
            ("10:21:08", "session_remote_end"),
            ("11:00:00", "session_park"),
            ("13:00:00", "vm_observed"),
        ];
        assert_eq!(got, want.map(|(t, e)| (t.to_string(), e.to_string())), "its rows, and its VMs' inside each generation's span");
        let s2 = "22222222-2222-4222-8222-222222222222";
        assert_eq!(pick(AuditFilterArgs { session: Some(s2.into()), ..AuditFilterArgs::default() }).len(), 3, "a closed chat's span ends at its last_seen");
        let none = "44444444-4444-4444-8444-444444444444";
        assert!(pick(AuditFilterArgs { session: Some(none.into()), ..AuditFilterArgs::default() }).is_empty(), "no row: its own rows only");
        let b = "microvm-0be03000-0000-4000-8000-00000000000b";
        let on_b = pick(AuditFilterArgs { vm: Some(b.into()), event: vec!["session_park".into(), "vm_run".into()], actor: Some(ActorArg::Wrapper), ..AuditFilterArgs::default() });
        assert_eq!(on_b, [("10:20:30".to_string(), "vm_run".to_string()), ("11:00:00".to_string(), "session_park".to_string())]);
        let since = pick(AuditFilterArgs { since: Some("2026-10-22T12:00:00Z".into()), wheres: vec!["via=survey".into()], ..AuditFilterArgs::default() });
        assert_eq!(since, [("13:00:00".to_string(), "vm_observed".to_string())]);
        assert_eq!(pick(AuditFilterArgs { actor: Some(ActorArg::Panel), ..AuditFilterArgs::default() }).len(), 0);
        assert_eq!(pick(AuditFilterArgs { vm: Some("microvm-0a5fc800-0000-4000-8000-00000000000a".into()), ..AuditFilterArgs::default() }).len(), 12, "every row naming A, the move's end by its from_vm");
        for bad in [
            AuditFilterArgs { session: Some("not-a-uuid".into()), ..AuditFilterArgs::default() },
            AuditFilterArgs { vm: Some("../x".into()), ..AuditFilterArgs::default() },
            AuditFilterArgs { wheres: vec!["novalue".into()], ..AuditFilterArgs::default() },
            AuditFilterArgs { since: Some("yesterday".into()), ..AuditFilterArgs::default() },
        ] {
            let e = Filter::from_args(&paths, &bad, now).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad:?}: {e}");
        }
    }

    /// `<when>`: an age before now, an RFC 3339 UTC time, a UTC date's midnight; anything else names the forms.
    #[test]
    fn when_takes_ages_times_and_dates() {
        let now = 1_792_713_600;
        assert_eq!(parse_when("90s", now), Ok(now - 90));
        assert_eq!(parse_when("30m", now), Ok(now - 1800));
        assert_eq!(parse_when("1h", now), Ok(now - 3600));
        assert_eq!(parse_when("2d", now), Ok(now - 172_800));
        assert_eq!(parse_when("2026-10-22T10:00:00Z", now), Ok(1_792_663_200));
        assert_eq!(parse_when("2026-10-22", now), Ok(1_792_627_200));
        for bad in ["", "yesterday", "0s", "-1h", "2026-13-01", "2026-10-22T10:00:00+02:00", "10", "1w"] {
            let e = parse_when(bad, now).unwrap_err();
            assert!(e.contains("90s, 30m, 1h, 2d") && e.contains("RFC 3339") && e.contains("UTC date"), "{bad}: {e}");
        }
        assert!(parse_when("100000d", 10).is_err_and(|e| e.contains("reaches before 1970")), "before 1970");
    }

    /// The text form: ts, actor, event, the session's first 8, the first VM, then the other keys; a value holding
    /// a space, a quote or `=` is a JSON string; a raw row is its line; every cell scrubbed again.
    #[test]
    fn render_quotes_what_holds_a_space() {
        let r = parse_line(&format!(
            r#"{{"v":2,"ts":"2026-10-22T10:21:00Z","event":"session_move_end","session_id":"{SID}","pid":1,"detail":{{"actor":"wrapper","session":"{SID}","to_vm":"microvm-b","from_vm":"microvm-a","outcome":"done","step":"two words","why":"a=b","q":"say \"hi\"","empty":""}}}}"#
        ))
        .unwrap();
        assert_eq!(
            render(&r),
            r#"2026-10-22T10:21:00Z wrapper session_move_end 11111111 microvm-b empty= from_vm=microvm-a outcome=done q="say \"hi\"" step="two words" why="a=b""#
        );
        let v1 = parse_line(r#"{"v":1,"ts":"2026-10-22T08:00:00Z","event":"vm_suspend","session_id":null,"pid":1,"detail":{"id":"microvm-a","client_token":"0199eff0-0000-7000-8000-00000000000a","by":"cli"}}"#).unwrap();
        assert_eq!(render(&v1), "2026-10-22T08:00:00Z - vm_suspend - microvm-a by=cli client_token=0199eff0-0000-7000-8000-00000000000a", "a v1 row: no actor; a token-named key alone loses nothing else");
        let raw = r#"{"v":2,"ts":"2026-10-22T12:00:00Z","event":"panel_frobnicate","session_id":null,"pid":1,"detail":{"actor":"cli"}}"#;
        assert_eq!(render(&parse_line(raw).unwrap()), raw, "an unknown event: its line");
        let secret = parse_line(r#"{"v":2,"ts":"2026-10-22T12:00:00Z","event":"vm_suspend","session_id":null,"pid":1,"detail":{"actor":"cli","id":"microvm-a","why":"sk-ant-oat01-abcdefghijklmnop"}}"#).unwrap();
        assert!(!render(&secret).contains("abcdefghijklmnop") && render(&secret).contains("[redacted"), "{}", render(&secret));
        // A VM's words with control characters (ESC, CR, LF, DEL, C1's CSI) in a value, the actor and a key: inert.
        let vm_words = parse_line(
            r#"{"v":2,"ts":"2026-10-22T12:00:00Z","event":"settings_capture","session_id":null,"pid":1,"detail":{"actor":"x\u001b[2J","phase":"end","outcome":"failed","vm":"microvm-a","why":"x\u001b[8m\r\nforged\u007f\u009b31m","k\u000d":"1"}}"#,
        )
        .unwrap();
        let line = render(&vm_words);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert_eq!(line, r#"2026-10-22T12:00:00Z "x\u001b[2J" settings_capture - microvm-a "k\r"=1 outcome=failed phase=end why="x\u001b[8m\r\nforged\u007f\u009b31m""#);
        let raw = "{\"v\":2,\r\"ts\":\"2026-10-22T12:00:00Z\",\"event\":\"panel_x\",\"session_id\":null,\"pid\":1,\"detail\":{\"actor\":\"cli\",\"y\":\"a\u{7f}\u{9b}b\"}}";
        let unknown = parse_line(raw).unwrap();
        assert!(!render(&unknown).chars().any(char::is_control), "{:?}", render(&unknown));
        let safe = json_line_safe(&unknown.raw);
        assert!(!safe.chars().any(char::is_control) && serde_json::from_str::<serde_json::Value>(&safe).unwrap()["detail"]["y"] == "a\u{7f}\u{9b}b", "{safe:?}");
    }

    /// B-CLI-1: `audit grep` finds a session's rows by the full uuid `session list` prints, whether the row holds
    /// it in its detail (the line shows its first 8 characters and drops the key) or in its envelope; a pattern
    /// still matches the one-line form, ASCII case folded with `-i`.
    #[test]
    fn grep_finds_a_session_by_its_full_id() {
        let detail = parse_line(&format!(
            r#"{{"v":2,"ts":"2026-10-22T10:21:00Z","event":"session_move_end","session_id":"{SID}","pid":1,"detail":{{"actor":"wrapper","session":"{SID}","to_vm":"microvm-b","from_vm":"microvm-a","outcome":"done"}}}}"#
        ))
        .unwrap();
        let envelope = parse_line(&format!(r#"{{"v":2,"ts":"2026-10-22T10:22:00Z","event":"session_remote_end","session_id":"{SID}","pid":1,"detail":{{"actor":"wrapper","vm":"microvm-b","spawn":"s1","gen":"1","exit":"0","end":"exit","close_ms":"5","last_acked_seq":"9"}}}}"#)).unwrap();
        let other = parse_line(r#"{"v":2,"ts":"2026-10-22T10:23:00Z","event":"vm_suspend","session_id":null,"pid":1,"detail":{"actor":"cli","id":"microvm-b"}}"#).unwrap();
        for r in [&detail, &envelope] {
            assert!(!render(r).contains(SID), "the line shows 8 characters: {}", render(r));
            assert!(grep_hit(r, SID, false) && grep_hit(r, &SID.to_ascii_lowercase(), true), "{}", r.raw);
        }
        assert!(!grep_hit(&other, SID, false));
        assert!(grep_hit(&detail, "outcome=done", false) && grep_hit(&detail, "outcome=done", true) && !grep_hit(&detail, "OUTCOME=DONE", false));
        assert!(grep_hit(&detail, &"OUTCOME=DONE".to_ascii_lowercase(), true));
    }

    #[test]
    fn the_follower_starts_at_the_end_or_an_offset() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        assert_eq!(Follower::at_end(&path).offset(), 0, "a missing file");
        std::fs::write(&path, "12345\n").unwrap();
        assert_eq!(Follower::at_end(&path).offset(), 6);
        assert_eq!(Follower::from(&path, 3).offset(), 3);
    }
}
