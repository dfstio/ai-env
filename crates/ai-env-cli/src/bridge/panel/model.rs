//! Each page's model (B §B5.7), built from the library the CLI's views use
//! (`registry`, `vm::ops`, `audit::read`, `settings_capture`, `cost`), and
//! the document its `?json=1` answers: the same as its CLI twin's `--json`
//! where it has one. Every model is read from disk on a blocking thread and
//! never writes: the settings page never writes `diff.json`, the VMs page
//! makes no AWS call.
use super::actions::{Action, NO_TARGET};
use crate::bridge::audit::read::{self, Filter, Read};
use crate::bridge::config::Paths;
use crate::bridge::cost::Estimate;
use crate::bridge::registry::{self, ListExtra, SessionRow, SessionView};
use crate::bridge::settings_capture::{self, SettingsDiff};
use crate::bridge::vm::ops::{self, Survey};
use crate::bridge::vm::registry as vm_registry;
use crate::cli::AuditFilterArgs;
use crate::errors::CliError;
use serde::Serialize;

/// Why a page has no model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageErr {
    /// 400, with its fixed line (never the request's value).
    Bad(&'static str),
    /// 404, with its fixed line.
    NotFound(&'static str),
    /// 500, with the model's one line.
    Failed(String),
}

impl PageErr {
    /// The first line of a library error.
    pub(crate) fn failed(e: impl std::fmt::Display) -> PageErr {
        PageErr::Failed(e.to_string().lines().next().unwrap_or("failed").to_string())
    }
}

/// `/`: `session list`'s rows, newest first, and their S11 cells.
#[derive(Debug, Clone)]
pub struct Sessions {
    pub rows: Vec<SessionRow>,
    pub extras: Vec<ListExtra>,
    /// S12 (T): the search as asked (`?q=`, `None` when absent or empty), and how many rows there were before it.
    pub q: Option<String>,
    pub total: usize,
}

/// S12 (T): the 400 line of a `q` over `title::TITLE_MAX` characters.
pub const Q_TOO_LONG: &str = "bad request: a search of more than 200 characters";

/// `/`'s model: the rows `q` matches (`title::matches`, names and ids), newest first, and their S11 cells; its
/// document is `session list --title <q> --json`'s for a `q` no session id holds. A `q` over `title::TITLE_MAX`
/// characters is `PageErr::Bad(Q_TOO_LONG)`.
///
/// S12 (T, §T3 U5): a `q` of spaces alone is no search (`title::needle` finds nothing in it): every row, as
/// with none. The rows are filtered before their cost cells are read, so the audit is read for those alone.
pub fn sessions(paths: &Paths, now: u64, q: Option<&str>) -> Result<Sessions, PageErr> {
    if q.is_some_and(|q| q.chars().count() > crate::bridge::title::TITLE_MAX) {
        return Err(PageErr::Bad(Q_TOO_LONG));
    }
    let mut rows = registry::list(paths).map_err(PageErr::failed)?;
    let total = rows.len();
    if let Some(needle) = q.and_then(crate::bridge::title::needle) {
        rows.retain(|r| crate::bridge::title::matches(r, &needle, true));
    }
    let extras = registry::list_extras(paths, &rows, now).map_err(PageErr::failed)?;
    Ok(Sessions { rows, extras, q: q.filter(|q| !q.is_empty()).map(str::to_string), total })
}

/// `/session/<sid>`: `session show <sid> --json`'s view; 400 not a uuid, 404 no row.
pub fn session(paths: &Paths, sid: &str, now: u64) -> Result<SessionView, PageErr> {
    if !registry::is_uuid(sid) {
        return Err(PageErr::Bad("bad request: not a session id"));
    }
    registry::session_view(paths, sid, now).map_err(PageErr::failed)?.ok_or(PageErr::NotFound("not found: no such session row"))
}

/// `/vms`: the registry alone (`vm::ops::offline`, no AWS call); its document is `ops::survey_json`'s.
pub fn vms(paths: &Paths, now: u64) -> Result<Survey, PageErr> {
    ops::offline(paths, now, false).map_err(PageErr::failed)
}

/// `/audit` and `/events`' filters as `audit tail`'s flags: `event` (comma-separated), `session`, `vm`.
#[must_use]
pub fn audit_args(event: Option<&str>, session: Option<&str>, vm: Option<&str>) -> AuditFilterArgs {
    AuditFilterArgs {
        session: session.map(str::to_string),
        vm: vm.map(str::to_string),
        event: event.map(|e| e.split(',').filter(|e| !e.is_empty()).map(str::to_string).collect()).unwrap_or_default(),
        ..AuditFilterArgs::default()
    }
}

/// The filter of `args`, as `audit tail` builds it (a usage error is 400); no flag is every row.
pub fn filter_of(paths: &Paths, args: &AuditFilterArgs, now: u64) -> Result<Filter, PageErr> {
    if *args == AuditFilterArgs::default() {
        return Ok(Filter::default());
    }
    Filter::from_args(paths, args, now).map_err(|e| match e {
        CliError::Usage(_) => PageErr::Bad("bad request: a bad filter (event names, a session's uuid, a VM's id)"),
        e => PageErr::failed(e),
    })
}

/// `/audit`: the last [`super::AUDIT_PAGE_ROWS`] rows the filter takes, oldest first.
#[derive(Debug, Clone)]
pub struct AuditPage {
    pub args: AuditFilterArgs,
    pub rows: Vec<Read>,
}

/// `/audit`'s model; its document is `audit tail -n 200 … --json`'s (each row as stored, one per line).
pub fn audit(paths: &Paths, args: AuditFilterArgs, now: u64) -> Result<AuditPage, PageErr> {
    let filter = filter_of(paths, &args, now)?;
    let mut rows: Vec<Read> = read::read_all(&paths.audit()).map_err(PageErr::failed)?.into_iter().filter(|r| filter.matches(r)).collect();
    let cut = rows.len().saturating_sub(super::AUDIT_PAGE_ROWS);
    rows.drain(..cut);
    Ok(AuditPage { args, rows })
}

/// `/settings/<sid>`: the diff `session show <sid> --settings-diff` prints, never written.
#[derive(Debug, Clone)]
pub struct SettingsPage {
    pub sid: String,
    pub diff: SettingsDiff,
    /// The CLI's text lines (`settings_capture::diff_lines`).
    pub lines: Vec<String>,
}

/// `/settings/<sid>`'s model: 400 not a uuid, 404 no start capture.
pub fn settings(paths: &Paths, sid: &str) -> Result<SettingsPage, PageErr> {
    if !registry::is_uuid(sid) {
        return Err(PageErr::Bad("bad request: not a session id"));
    }
    let diff = settings_capture::diff_of(paths, sid)
        .map_err(|e| match e {
            CliError::Usage(_) => PageErr::Bad("bad request: not a session id"),
            e => PageErr::failed(e),
        })?
        .ok_or(PageErr::NotFound("not found: no settings captured for this session"))?;
    let lines = settings_capture::diff_lines(&diff);
    Ok(SettingsPage { sid: sid.to_string(), diff, lines })
}

/// `/cost?since=<when>`: the estimate from `<when>` (default `24h`) to now.
#[derive(Debug, Clone)]
pub struct CostPage {
    pub since: String,
    pub estimate: Estimate,
}

/// The default window of `/cost`.
pub const COST_SINCE: &str = "24h";

/// `/cost`'s model; its document is `cost --since <when> --json`'s; 400 a bad `<when>`.
pub fn cost(paths: &Paths, since: Option<&str>, now: u64) -> Result<CostPage, PageErr> {
    let since = since.unwrap_or(COST_SINCE).to_string();
    let from = read::parse_when(&since, now).map_err(|_| PageErr::Bad("bad request: since takes 90s, 30m, 1h, 2d, an RFC 3339 UTC time or a UTC date YYYY-MM-DD"))?;
    if from >= now {
        return Err(PageErr::Bad("bad request: since is not before now"));
    }
    let estimate = crate::bridge::cost::estimate_for(paths, from, now, false).map_err(PageErr::failed)?;
    Ok(CostPage { since, estimate })
}

/// `/confirm?action=<word>&target=<id>`: what will happen, its Touch IDs, its CLI twin, and (GET, never
/// HEAD) a fresh nonce for its form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Confirm {
    pub action: &'static str,
    pub target: String,
    pub twin: String,
    pub what: String,
    pub touch_ids: String,
    /// `vm-terminate`: the chats on the VM, which move to a new VM at their next message.
    pub chats: Vec<String>,
    pub nonce: Option<String>,
}

/// One Touch ID for the runtime key, asked by the action itself.
const ONE_TOUCH_ID: &str = "one Touch ID on this Mac (the runtime key), asked when the action runs";

/// `/confirm`'s model, its nonce not issued yet: 400 a bad target, 404 no such VM row or session row.
pub fn confirm(paths: &Paths, action: Action, target: &str) -> Result<Confirm, PageErr> {
    let mut chats = Vec::new();
    let (what, touch_ids) = match action {
        Action::VmSuspend | Action::VmResume | Action::VmTerminate => {
            if !vm_registry::is_vm_id(target) {
                return Err(PageErr::Bad("bad request: the target is no VM id"));
            }
            vm_registry::read_row(paths, target).map_err(PageErr::failed)?.ok_or(PageErr::NotFound("not found: no such VM row"))?;
            let what = match action {
                Action::VmSuspend => format!("Suspend {target}: SuspendMicrovm, then wait until it is SUSPENDED. A chat on it resumes it with its next message."),
                Action::VmResume => format!("Resume {target}: ResumeMicrovm, then wait until it is RUNNING."),
                _ => {
                    let ctx = crate::bridge::vm::cmd::Ctx::load().map_err(PageErr::failed)?;
                    ops::terminate_check(&ctx, target, false).map_err(|e| match e {
                        CliError::Usage(_) => PageErr::Bad("bad request: the target is no VM id"),
                        e => PageErr::failed(e),
                    })?;
                    chats = ops::chats_on(paths, target).map_err(PageErr::failed)?;
                    format!("Terminate {target}: the transcripts of its chats synced to S3 first, then TerminateMicrovm. Each chat on it moves to a new VM at its next message.")
                }
            };
            (what, ONE_TOUCH_ID.to_string())
        }
        Action::VmRefresh => {
            if target != NO_TARGET {
                return Err(PageErr::Bad("bad request: vm-refresh takes no target"));
            }
            ("Refresh from AWS: ListMicrovms joined with this Mac's VM rows, then the reconcile (vm list's survey); each row records the state it saw.".to_string(), ONE_TOUCH_ID.to_string())
        }
        Action::SessionMigrate => {
            if !registry::is_uuid(target) {
                return Err(PageErr::Bad("bad request: the target is no session id"));
            }
            let row = registry::read(paths, target).map_err(PageErr::failed)?.ok_or(PageErr::NotFound("not found: no such session row"))?;
            if row.mode != "remote" {
                return Err(PageErr::Bad("bad request: the session is no remote chat (it runs on this Mac)"));
            }
            let vm = row.microvm_id.clone().unwrap_or_else(|| "-".into());
            let live = row.status != "closed" && registry::pid_alive(row.pid) && registry::confirm_wrapper(&row, row.pid).is_ok();
            if live {
                (
                    format!("Move session {target} off {vm} to a new VM: its wrapper (pid {}) prepares the new VM now and switches at the chat's next quiet point; this waits up to {} s for its answer.", row.pid, crate::bridge::migrate::MIGRATE_WAIT.as_secs()),
                    "none here: the chat's wrapper asks its own Touch ID".to_string(),
                )
            } else {
                (format!("Move session {target} off {vm} to a new VM now: no wrapper serves the chat, so this moves it (the old VM resumed for its fetch, a new VM, then the old one terminated)."), ONE_TOUCH_ID.to_string())
            }
        }
    };
    Ok(Confirm { action: action.word(), target: target.to_string(), twin: action.twin(target), what, touch_ids, chats, nonce: None })
}

/// Pretty JSON, as the CLI prints its documents.
pub(crate) fn pretty<T: Serialize + ?Sized>(value: &T) -> Result<String, PageErr> {
    serde_json::to_string_pretty(value).map(|mut s| {
        s.push('\n');
        s
    }).map_err(|e| PageErr::Failed(format!("cannot render JSON: {e}")))
}

/// `/audit?json=1`: each row as stored, one per line, as `audit tail --json` prints it (P-1:
/// `read::json_line_safe`, so DEL and C1 inside a value reach a terminal reading the document inert).
#[must_use]
pub fn audit_ndjson(page: &AuditPage) -> String {
    page.rows.iter().map(|r| format!("{}\n", read::json_line_safe(&r.raw))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P-1: the document is the CLI's, line for line: a value holding DEL and a C1 CSI is sent with them as `\u`
    /// escapes (the same JSON value), never raw; a plain line goes as stored.
    #[test]
    fn the_audit_document_is_the_clis_with_controls_inert() {
        let lines = [
            r#"{"v":2,"ts":"2026-10-22T12:00:00Z","event":"vm_suspend","session_id":null,"pid":1,"detail":{"actor":"cli","id":"microvm-a"}}"#.to_string(),
            "{\"v\":2,\"ts\":\"2026-10-22T12:00:01Z\",\"event\":\"settings_capture\",\"session_id\":null,\"pid\":1,\"detail\":{\"actor\":\"cli\",\"phase\":\"end\",\"outcome\":\"failed\",\"vm\":\"microvm-a\",\"why\":\"x\u{7f}\u{9b}31m\"}}".to_string(),
        ];
        let rows: Vec<Read> = lines.iter().map(|l| read::parse_line(l).unwrap()).collect();
        let doc = audit_ndjson(&AuditPage { args: AuditFilterArgs::default(), rows });
        assert!(!doc.chars().any(|c| c.is_control() && c != '\n'), "{doc:?}");
        let sent: Vec<&str> = doc.lines().collect();
        assert_eq!(sent[0], lines[0], "a plain line as stored");
        assert_eq!(sent[1], read::json_line_safe(&lines[1]), "the CLI's line");
        let value: serde_json::Value = serde_json::from_str(sent[1]).unwrap();
        assert_eq!(value["detail"]["why"], "x\u{7f}\u{9b}31m", "the same value");
    }
}
