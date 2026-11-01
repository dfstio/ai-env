//! Each page's model (B §B5.7), built from the library the CLI's views use
//! (`registry`, `vm::ops`, `audit::read`, `settings_capture`, `cost`), and
//! the document its `?json=1` answers: the same as its CLI twin's `--json`
//! where it has one. Every model is read from disk on a blocking thread and
//! never writes: the settings page never writes `diff.json`, the VMs page
//! makes no AWS call. What a chat's relay access shows comes from
//! `[relay].offer`, `state/relay-access.json` and the agent's socket alone (R-151,
//! R-152): no AWS call, no Touch ID, and the relay remains the gate.
use super::actions::{relay_target, Action, NO_TARGET};
use crate::bridge::audit::read::{self, Filter, Read};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::cost::Estimate;
use crate::bridge::registry::{self, ListExtra, SessionRow, SessionView};
use crate::bridge::relay::params::{access_day, read_access_cache, AccessCache, ACCESS_DAYS_DEFAULT};
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

/// What the Sessions and session pages show of the chats' relay access (R-151, R-152).
#[derive(Debug, Clone, Default)]
pub struct AccessPanel {
    /// `[relay].offer`: a row per grant, in its order.
    pub offer: Vec<String>,
    /// Why `offer` is empty when `[relay]` does not validate (the first line of its error).
    pub problem: Option<String>,
    /// The list as a command last read it; `None`: none has yet.
    pub cache: Option<AccessCache>,
    /// The agent's pid and when it ends, when one answers: a chat spawned with none holds no token.
    pub agent: Option<(u32, u64)>,
    /// The page's clock: an entry lapsed by then holds nothing.
    pub now: u64,
}

impl AccessPanel {
    /// From disk and the agent's socket, each at most a second; a `bridge.toml` that does not load offers nothing.
    #[must_use]
    pub fn read(paths: &Paths, now: u64) -> AccessPanel {
        let relay = BridgeConfig::load(paths).ok().flatten().unwrap_or_default().relay;
        let problem = relay.validate().err().map(|e| e.to_string().lines().next().unwrap_or_default().to_string());
        let offer = if problem.is_some() { Vec::new() } else { relay.offer };
        let agent = crate::bridge::relay::ops::agent_status(paths).map(|s| (s.pid, s.until));
        AccessPanel { offer, problem, cache: read_access_cache(paths), agent, now }
    }

    /// The grants `chat` holds in force as the cache has it, and the entry's end.
    #[must_use]
    pub fn held(&self, chat: &str) -> Option<(&[String], &str)> {
        let entries = self.cache.as_ref().map_or(&[][..], |c| c.entries.as_slice());
        entries.iter().find(|a| a.chat == chat && self.now <= a.not_after_unix()).map(|a| (a.grants.as_slice(), a.not_after.as_str()))
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
    /// R-151: not in the document, which stays `session list --json`'s.
    pub access: AccessPanel,
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
    Ok(Sessions { rows, extras, q: q.filter(|q| !q.is_empty()).map(str::to_string), total, access: AccessPanel::read(paths, now) })
}

/// `/session/<sid>`'s model: its document is exactly `session show <sid> --json`'s view.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct SessionPage {
    pub view: SessionView,
    /// R-151: not in the document.
    #[serde(skip)]
    pub access: AccessPanel,
}

/// `/session/<sid>`: `session show <sid> --json`'s view; 400 not a uuid, 404 no row.
pub fn session(paths: &Paths, sid: &str, now: u64) -> Result<SessionPage, PageErr> {
    if !registry::is_uuid(sid) {
        return Err(PageErr::Bad("bad request: not a session id"));
    }
    let view = registry::session_view(paths, sid, now).map_err(PageErr::failed)?.ok_or(PageErr::NotFound("not found: no such session row"))?;
    Ok(SessionPage { view, access: AccessPanel::read(paths, now) })
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
    /// `vm-terminate`: the chats on the VM, which move to a new VM at their next message. `relay-allow`, `relay-remove`
    /// (R-151): the other chats on the chat's VM, whose processes could use its access.
    pub chats: Vec<String>,
    pub nonce: Option<String>,
}

/// One Touch ID for the runtime key, asked by the action itself.
const ONE_TOUCH_ID: &str = "one Touch ID on this Mac (the runtime key), asked when the action runs";
/// One Touch ID for the ops key, asked by the action's child, which alone holds it (R-151).
const ONE_OPS_TOUCH_ID: &str = "one Touch ID on this Mac (the ops key), asked when the action runs, by a child that keeps it no longer";

/// What a chat with no token hears on the confirm page: an approval reaches it from its next spawn (R-151).
fn token_note(row: &SessionRow) -> String {
    match row.relay.as_deref() {
        Some("minted") => String::new(),
        Some("off") => " This chat's latest spawn holds no session token (off): [relay].grant or its workspace's relay_grant names none, so it reaches the grant from the first spawn after one does.".to_string(),
        Some(word) => format!(" This chat's latest spawn holds no session token ({word}), so it reaches the grant from its next spawn: the session's Migrate makes one."),
        None => " This chat's row names no session token, so it reaches the grant from its next spawn: the session's Migrate makes one.".to_string(),
    }
}

/// What an allow does to the rest of a chat's entry, as the cache has it (R-150): an entry has one end for all its grants, so
/// a day that ends later stretches what it holds, and one that ends earlier gives way to the entry's. Nothing with no entry in force.
fn entry_note(paths: &Paths, chat: &str, now: u64) -> String {
    let panel = AccessPanel { cache: read_access_cache(paths), now, ..AccessPanel::default() };
    panel.held(chat).map_or_else(String::new, |(grants, end)| format!(" Its entry ends {} and holds {}: one end covers all its grants, the later of the two.", end.get(..10).unwrap_or(end), grants.join(",")))
}

/// `relay-allow`'s or `relay-remove`'s page: what will happen, and the other chats on its VM (R-151). A title is the
/// chat's own, so the session id always sits beside it. 400 a bad target, an allow or a chat with no access id on this Mac, a
/// chat with no access id, a grant `[relay].offer` does not name for an allow; 404 no row. A row now on this Mac that holds an
/// id can still be taken out of the list: a later remote `--resume` takes that id.
fn relay_confirm(paths: &Paths, action: Action, target: &str) -> Result<(String, Vec<String>), PageErr> {
    let bad = || PageErr::Bad("bad request: the target is no <session>_<grant>");
    let (sid, grant) = relay_target(target).ok_or_else(bad)?;
    if !registry::is_uuid(sid) || !ai_env_worker::globs::valid_id(grant) || grant.contains('.') {
        return Err(bad());
    }
    let row = registry::read(paths, sid).map_err(PageErr::failed)?.ok_or(PageErr::NotFound("not found: no such session row"))?;
    if row.mode != "remote" && (action == Action::RelayAllow || row.access().is_none()) {
        return Err(PageErr::Bad("bad request: the session is no remote chat (it runs on this Mac)"));
    }
    let Some(access) = row.access() else {
        return Err(PageErr::Bad("bad request: the chat has no access id: it last ran before this ai-env, so reopen it first"));
    };
    let named = crate::bridge::title::of_row(&row).map_or_else(String::new, |t| format!(" (\"{}\")", crate::bridge::title::inert(&t.text)));
    let what = if action == Action::RelayAllow {
        let relay = BridgeConfig::load(paths).map_err(PageErr::failed)?.unwrap_or_default().relay;
        relay.validate().map_err(PageErr::failed)?;
        if !relay.offer.iter().any(|g| g == grant) {
            return Err(PageErr::Bad("bad request: [relay].offer does not name this grant"));
        }
        // The clock the child's write will read, never the lab's.
        let now = crate::wire::time::unix_now();
        format!(
            "Allow session {sid}{named} grant {grant} until {}: chat {access} joins /ai-env/relay/access, and the relay applies it within about 70 s, with no change in the chat or its VM and no restart.{}{}",
            access_day(now, ACCESS_DAYS_DEFAULT),
            entry_note(paths, access, now),
            token_note(&row)
        )
    } else {
        format!("Take grant {grant} from session {sid}{named}: chat {access} leaves it in /ai-env/relay/access, and the relay refuses it within about 70 s; calls in flight finish.")
    };
    let mut chats = match row.microvm_id.as_deref() {
        Some(vm) => ops::chats_on(paths, vm).map_err(PageErr::failed)?,
        None => Vec::new(),
    };
    chats.retain(|c| c != sid);
    Ok((what, chats))
}

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
        Action::RelayAllow | Action::RelayRemove => {
            let (what, others) = relay_confirm(paths, action, target)?;
            chats = others;
            (what, ONE_OPS_TOUCH_ID.to_string())
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
