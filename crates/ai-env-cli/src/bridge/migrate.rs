//! `ai-env session migrate UUID [--json]` (S10 §C, plans/s10-contracts.md
//! §7.1): move a remote chat to a new VM now, before its VM's 8-hour wall.
//!
//! - Before any Touch ID: the id is a uuid (exit 2), the session has a row
//!   (exit 1) of a remote chat (exit 9: a chat on this Mac has no VM to move
//!   from) that records its VM (exit 1).
//! - A live wrapper serves the chat (a row that is not `closed`, its pid an
//!   `ai-env-claude` started before the row: `registry::confirm_wrapper`),
//!   and an S10 one (`v` 2 or more: SIGUSR1 would end an S9 wrapper, exit 1
//!   before any signal): the command writes the request
//!   `state/sessions/<sid>.migrate.json` (0600, `O_EXCL`, a stale one older
//!   than [`MIGRATE_REQUEST_FRESH`] removed first), sends
//!   `registry::MIGRATE_SIGNAL`, audits `session_migrate_request`, then
//!   waits at most [`MIGRATE_WAIT`] for the `session_move_end` carrying its
//!   nonce in `audit.jsonl`. The wrapper prepares the new VM at once (one
//!   Touch ID there) and switches at its next quiet point.
//! - No live wrapper: the command moves the chat itself (the row `migrating`
//!   with `migrating_pid` meanwhile): one Touch ID for the runtime key, the
//!   old VM fetched and synced (or its fetch record when it is gone), a new
//!   VM avoiding the old, the carry seed beside the restore, the row
//!   rewritten, the old VM terminated.
//! - Exits: 0 moved; 1 refused, abandoned or no answer within `MIGRATE_WAIT`;
//!   2 not a uuid; 3 or 5 the Touch ID; 7 AWS; 8 the wrapper exited before
//!   answering; 9 a local chat, or a policy refusal.
//!
//! Phase 0 declares the command; S10 wave 1b (C) builds it.
use crate::store::Keystore;
use std::time::Duration;
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::{self, SessionRow};
use crate::errors::CliError;
use crate::outln;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A live wrapper takes a `session migrate` request only this fresh; the
/// command removes an older one (a command killed before the wrapper took
/// it) before it writes its own.
pub const MIGRATE_REQUEST_FRESH: Duration = Duration::from_secs(60);
/// How long `session migrate` waits for the live wrapper's answer (its
/// `session_move_end` in `audit.jsonl`).
pub const MIGRATE_WAIT: Duration = Duration::from_secs(300);
/// How often the command reads `audit.jsonl` again while it waits.
const POLL: Duration = Duration::from_millis(200);

/// `state/sessions/<sid>.migrate.json` (§6.5): `session migrate`'s request to
/// the session's live wrapper, by its nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateRequest {
    pub v: u32,
    /// A uuid v7: the `request` of the `session_move_end` that answers it.
    pub nonce: String,
    /// RFC 3339 UTC.
    pub requested_at: String,
    /// The command's pid.
    pub by_pid: u32,
}

impl MigrateRequest {
    /// Asked within [`MIGRATE_REQUEST_FRESH`] of `now` (unix seconds); an unreadable time is stale.
    #[must_use]
    pub fn fresh(&self, now: u64) -> bool {
        crate::wire::time::parse_rfc3339_utc(&self.requested_at).is_some_and(|at| now.saturating_sub(at) < MIGRATE_REQUEST_FRESH.as_secs())
    }

    /// Its age in seconds at `now`.
    fn age_s(&self, now: u64) -> u64 {
        crate::wire::time::parse_rfc3339_utc(&self.requested_at).map_or(0, |at| now.saturating_sub(at))
    }
}

/// The request of session `sid`, read (never through a symlink) and removed,
/// whatever it holds (the wrapper takes it on `MIGRATE_SIGNAL`); `None` when
/// there is none. A file that does not parse is removed and an error.
pub(crate) fn take_request(paths: &Paths, sid: &str) -> Result<Option<MigrateRequest>, BridgeError> {
    let path = registry::path_for(paths, sid).map(|_| paths.session_migrate_request(sid))?;
    let Some(text) = registry::read_regular_file(&path)? else { return Ok(None) };
    registry::remove_if_present(&path)?;
    serde_json::from_str(&text).map(Some).map_err(|e| BridgeError::Config(format!("{}: {e}", path.display())))
}

/// The command's request to the live wrapper of `sid` (§6.5): a stale one
/// (a command killed before the wrapper took it) removed first; then
/// [`create_request`]. A fresh one is another command's (exit 1).
fn write_request(paths: &Paths, sid: &str, req: &MigrateRequest) -> crate::errors::Result<()> {
    let path = paths.session_migrate_request(sid);
    let now = crate::wire::time::unix_now();
    if let Some(text) = registry::read_regular_file(&path)? {
        match serde_json::from_str::<MigrateRequest>(&text) {
            Ok(other) if other.fresh(now) => {
                return Err(CliError::Msg(format!("a move of session {sid} was asked {} s ago (pid {}): wait for it", other.age_s(now), other.by_pid)));
            }
            _ => {
                registry::remove_if_present(&path)?;
            }
        }
    }
    registry::ensure_private_dir(&paths.sessions())?;
    create_request(&path, req)
}

/// `req` at `path`, created there (`O_EXCL` and `O_NOFOLLOW`, 0600) and
/// written whole. A file there already is an error, left as it is: another
/// command wrote its request between this one's check and its open, so two
/// commands racing never both think the wrapper took theirs.
fn create_request(path: &std::path::Path, req: &MigrateRequest) -> crate::errors::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).map_err(|e| CliError::Msg(format!("{}: {e}", path.display())))?;
    let text = serde_json::to_string(req).map_err(|e| CliError::Msg(format!("the request: {e}")))?;
    file.write_all(text.as_bytes()).and_then(|()| file.sync_all()).map_err(|e| CliError::Msg(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// `session_migrate_request` (§4.2): `session`, `nonce`, `how`, and the live wrapper's pid.
fn audit_request(paths: &Paths, sid: &str, nonce: &str, how: &str, wrapper_pid: Option<u32>) {
    let mut pairs = vec![("session", sid.to_string()), ("nonce", nonce.to_string()), ("how", how.to_string())];
    if let Some(pid) = wrapper_pid {
        pairs.push(("wrapper_pid", pid.to_string()));
    }
    let row = AuditRow::new(crate::bridge::remote::audit_event::SESSION_MIGRATE_REQUEST, Some(sid), audit::detail(&pairs));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        eprintln!("ai-env: warning: audit row {} not written: {e}", crate::bridge::remote::audit_event::SESSION_MIGRATE_REQUEST);
    }
}

/// What a move came to (S11, B.1: public for the panel): the CLI's `report` prints it, the panel renders it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Moved {
    pub outcome: String,
    /// `live` or `offline`.
    pub how: &'static str,
    pub from_vm: String,
    pub to_vm: Option<String>,
    pub ms: u64,
    /// The command's exit: 0, or the answer's `code` (3, 5, 7, 8, 9; else 1).
    pub code: i32,
    /// What failed, for the error line (none for `done`).
    pub why: Option<String>,
}

impl Moved {
    /// `report`'s line for `sid`: `session <sid>: moved from <old> to <new> (<how>)` when `code` is 0, else
    /// `session <sid>: <why>` (the line of the error `report` returns, its exit `code`).
    #[must_use]
    pub fn line(&self, sid: &str) -> String {
        if self.code == 0 {
            format!("session {sid}: moved from {} to {} ({})", self.from_vm, self.to_vm.as_deref().unwrap_or("-"), self.how)
        } else {
            format!("session {sid}: {}", self.why.as_deref().unwrap_or("the move failed"))
        }
    }
}

/// `ai-env session migrate UUID [--json]` (the module doc), as S10 wave 1c
/// (C3) builds it:
///
/// - The checks before any Touch ID ([`target`]) also refuse a chat that
///   another offline move moves now: its row's `migrating_pid` is that
///   command, still running ([`moving_pid`]), exit 1.
/// - Live: a fresh request of another command is exit 1 (`a move of
///   session <sid> was asked <n> s ago (pid <pid>): wait for it`); the
///   wrapper takes the request at its `MIGRATE_SIGNAL`
///   (`pump::Pump::on_migrate`); its answer's `code` is this command's exit
///   for `stayed` and `failed` (a Touch ID's 3 or 5, 7, 8, 9; else 1).
/// - Offline: the one Touch ID is the runtime key's alone
///   (`vm::cmd::backend`, as `session stage` unseals: the chat's next
///   wrapper delivers its own token); the old VM is resumed for its fetch
///   and the chat's sync there; the carry seed beside the restore has no
///   deadline; the old VM ends synced first.
/// - Output: `session <sid>: moved from <old> to <new> (<live|offline>)`;
///   `--json`: one document `{"session","outcome","how","from_vm","to_vm","ms","code"}`.
pub fn cmd_migrate(store: &Keystore, uuid: &str, json: bool) -> crate::errors::Result<()> {
    report(uuid, &migrate(store, uuid, &uuid::Uuid::now_v7().to_string())?, json)
}

/// `cmd_migrate`'s body without `report` (S11, B.1: the panel's too): the checks before any Touch ID, then the
/// live or the offline move with `nonce` as the request's (the live wrapper's `session_move_end` carries it as
/// `request`; the offline move audits it in `session_migrate_request`). `Ok` for every answered move, whatever its
/// outcome (`code` says it); `Err` for a refusal before the move and for an offline move's error.
pub fn migrate(store: &Keystore, uuid: &str, nonce: &str) -> crate::errors::Result<Moved> {
    if !registry::is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let paths = Paths::resolve()?;
    let row = target(&paths, uuid)?;
    let old = row.microvm_id.clone().unwrap_or_default();
    if live_wrapper(&row) {
        if row.v < 2 {
            return Err(CliError::Msg(format!("session {uuid}'s wrapper (pid {}) predates S10: close the chat and reopen it, then run ai-env session migrate again", row.pid)));
        }
        migrate_live(&paths, &row, &old, nonce)
    } else {
        migrate_offline(store, &paths, &row, &old, nonce)
    }
}

/// The checks before any Touch ID (the module doc): the row, of a remote
/// chat (else exit 9), its VM recorded, no offline move of it running.
fn target(paths: &Paths, uuid: &str) -> crate::errors::Result<SessionRow> {
    let Some(row) = registry::read(paths, uuid)? else {
        return Err(CliError::Msg(format!("no session {uuid}")));
    };
    if row.mode != "remote" {
        return Err(CliError::Policy(format!("session {uuid} runs on this Mac: there is no VM to move it from")));
    }
    if !row.microvm_id.as_deref().is_some_and(crate::bridge::vm::registry::is_vm_id) {
        return Err(CliError::Msg(format!("session {uuid} records no VM: there is none to move it from")));
    }
    if let Some(pid) = moving_pid(&row) {
        return Err(CliError::Msg(format!("session {uuid} is being moved to a new VM (pid {pid}): wait for it")));
    }
    Ok(row)
}

/// The executable an offline move runs as (`migrating_pid`'s).
const CLI_EXE: &str = "ai-env";

/// The pid of the offline `session migrate` that moves `row`'s chat now:
/// its `migrating_pid`, while that pid is still that command (P0's reopen
/// refuses the chat meanwhile, as this command does). A command killed
/// mid-move (SIGINT runs no destructor, so the row stays `migrating`)
/// leaves a pid the system may give another process: one that is no
/// [`CLI_EXE`], or started after the row was last written (the move stamps
/// `last_seen` as it takes the row), moves nothing.
#[must_use]
pub(crate) fn moving_pid(row: &SessionRow) -> Option<u32> {
    let pid = row.migrating_pid?;
    judge_moving(row, registry::process_identity(pid)).then_some(pid)
}

/// [`moving_pid`]'s verdict on what the system says of the pid
/// (`identity`: its executable's file name and start; `None`: gone or unreadable).
fn judge_moving(row: &SessionRow, identity: Option<(String, u64)>) -> bool {
    let Some((name, started)) = identity else { return false };
    let stamped = crate::wire::time::parse_rfc3339_utc(&row.last_seen);
    name == CLI_EXE && stamped.is_some_and(|at| started <= at)
}

/// A live wrapper serves the chat: its row is not closed and its pid is the
/// `ai-env-claude` that wrote it (`registry::confirm_wrapper`).
fn live_wrapper(row: &SessionRow) -> bool {
    row.status != "closed" && registry::pid_alive(row.pid) && registry::confirm_wrapper(row, row.pid).is_ok()
}

/// The live flow: the request, the signal, its audit row, then the
/// wrapper's answer (its `session_move_end` with the nonce) read off
/// `audit.jsonl` from where it ended when the request went, at most
/// [`MIGRATE_WAIT`]; the wrapper gone before it is exit 8.
fn migrate_live(paths: &Paths, row: &SessionRow, old: &str, nonce: &str) -> crate::errors::Result<Moved> {
    let sid = &row.session_id;
    let req = MigrateRequest { v: 1, nonce: nonce.to_string(), requested_at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), by_pid: std::process::id() };
    let started = std::time::Instant::now();
    let mut from = std::fs::metadata(paths.audit()).map_or(0, |m| m.len());
    write_request(paths, sid, &req)?;
    let pid = libc::pid_t::try_from(row.pid).map_err(|_| CliError::Msg(format!("pid {} is no process id", row.pid)))?;
    // SAFETY: kill(2) of a live process confirmed to be the session's S10 wrapper (row `v` 2), which handles it.
    if unsafe { libc::kill(pid, registry::MIGRATE_SIGNAL) } != 0 {
        let e = std::io::Error::last_os_error();
        let _ = registry::remove_if_present(&paths.session_migrate_request(sid));
        return Err(CliError::Msg(format!("session {sid}'s wrapper (pid {}) could not be signalled: {e}", row.pid)));
    }
    audit_request(paths, sid, nonce, "live", Some(row.pid));
    let until = started + MIGRATE_WAIT;
    // S11: the audit's own reader (`audit::read::since`), the answer the `session_move_end` whose `request` is the nonce.
    let answer_in = |rows: &[crate::bridge::audit::read::Read]| {
        rows.iter().find(|r| r.event == crate::bridge::remote::audit_event::SESSION_MOVE_END && r.detail.get("request").map(String::as_str) == Some(nonce)).map(|r| serde_json::to_value(&r.detail).unwrap_or_default())
    };
    loop {
        let (rows, next) = crate::bridge::audit::read::since(&paths.audit(), from);
        from = next;
        if let Some(detail) = answer_in(&rows) {
            return Ok(answered(&detail, old, started));
        }
        if !registry::pid_alive(row.pid) {
            // One more read: the wrapper may have answered as it ended.
            let (rows, _) = crate::bridge::audit::read::since(&paths.audit(), from);
            if let Some(detail) = answer_in(&rows) {
                return Ok(answered(&detail, old, started));
            }
            return Err(CliError::VmLost(format!("session {sid}'s wrapper (pid {}) exited before it answered the move", row.pid)));
        }
        if std::time::Instant::now() >= until {
            return Err(CliError::Msg(format!("session {sid}'s wrapper (pid {}) did not answer the move within {} s (it moves at the chat's next quiet point: run session migrate again later)", row.pid, MIGRATE_WAIT.as_secs())));
        }
        std::thread::sleep(POLL);
    }
}

/// The wrapper's answer (its `session_move_end`'s detail) as the command
/// reports it: `done` exit 0; `stayed` and `failed` the row's `code` (3, 5,
/// 7, 8, 9; else 1); `refused` and `abandoned` exit 1.
fn answered(d: &serde_json::Value, old: &str, started: std::time::Instant) -> Moved {
    let s = |k: &str| d[k].as_str().filter(|v| *v != "-").map(str::to_string);
    let outcome = s("outcome").unwrap_or_else(|| "failed".to_string());
    let code = match outcome.as_str() {
        "done" => 0,
        "stayed" | "failed" => s("code").and_then(|c| c.parse().ok()).filter(|c| matches!(c, 3 | 5 | 7 | 8 | 9)).unwrap_or(1),
        _ => 1,
    };
    let why = match outcome.as_str() {
        "done" => None,
        "refused" => Some("the wrapper refused the move: another move is under way, the chat closes, or its VM is pinned (AI_ENV_BRIDGE_VM)".to_string()),
        "abandoned" => Some(format!("the wrapper gave the move up before its switch (the new VM's hold ended with no quiet point, the chat's VM was lost and it moved anyway, or the chat closed): run session migrate again if the chat is still on {old}")),
        "stayed" => Some(format!("the chat stays on {old}: the move failed at {}", s("step").unwrap_or_else(|| "a step".to_string()))),
        _ => Some(format!("the move failed at {}", s("step").unwrap_or_else(|| "a step".to_string()))),
    };
    Moved { outcome, how: "live", from_vm: old.to_string(), to_vm: s("to_vm"), ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), code, why }
}

/// The command's line, or its document with `--json` (and its exit: the move's).
fn report(sid: &str, m: &Moved, json: bool) -> crate::errors::Result<()> {
    if json {
        let doc = serde_json::json!({ "session": sid, "outcome": m.outcome, "how": m.how, "from_vm": m.from_vm, "to_vm": m.to_vm, "ms": m.ms, "code": m.code });
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else if m.code == 0 {
        outln!("{}", m.line(sid));
    }
    if m.code == 0 {
        return Ok(());
    }
    let why = m.line(sid);
    Err(match m.code {
        3 => {
            eprintln!("ai-env: {why}");
            CliError::Cancelled
        }
        5 => CliError::AuthUnavailable(why),
        7 => CliError::Aws(why),
        8 => CliError::VmLost(why),
        9 => CliError::Policy(why),
        _ => CliError::Msg(why),
    })
}

/// The row held `migrating` with this process's pid (`migrating_pid`)
/// while an offline move runs, its `last_seen` now (so a later process
/// given that pid is told from this one: [`moving_pid`]); given back
/// (`closed`, no pid) when it ends, whatever its end: no wrapper serves the
/// chat, so the status the row had before (a killed move's `migrating`, a
/// dead wrapper's `active`) is stale. A row whose `migrating_pid` is no
/// longer this process's was taken over meanwhile (a wrapper registered
/// it): left as it is.
struct Migrating<'a> {
    paths: &'a Paths,
    sid: String,
}

impl<'a> Migrating<'a> {
    fn hold(paths: &'a Paths, row: &SessionRow) -> crate::errors::Result<Migrating<'a>> {
        let mut held = row.clone();
        held.status = "migrating".to_string();
        held.migrating_pid = Some(std::process::id());
        held.last_seen = registry::now_rfc3339();
        registry::write(paths, &held)?;
        Ok(Migrating { paths, sid: row.session_id.clone() })
    }
}

impl Drop for Migrating<'_> {
    fn drop(&mut self) {
        if let Ok(Some(mut row)) = registry::read(self.paths, &self.sid) {
            if row.migrating_pid != Some(std::process::id()) {
                return;
            }
            row.migrating_pid = None;
            row.status = "closed".to_string();
            if let Err(e) = registry::write(self.paths, &row) {
                eprintln!("ai-env: warning: session {}'s row still says migrating: {e}", self.sid);
            }
        }
    }
}

/// The offline flow (the module doc): one Touch ID (the runtime key alone),
/// the move, the row rewritten; its row `migrating` throughout.
fn migrate_offline(store: &Keystore, paths: &Paths, row: &SessionRow, old: &str, nonce: &str) -> crate::errors::Result<Moved> {
    use crate::bridge::vm::cmd::{backend, runtime, Backend, Ctx};
    let sid = &row.session_id;
    let ctx = Ctx::load()?;
    let cwd = row.cwd.as_deref().filter(|c| Path::new(c).is_absolute()).ok_or_else(|| CliError::Msg(format!("session {sid}'s row records no cwd: where it reopens is unknown")))?;
    let ws = crate::bridge::workspace::resolve(&ctx.cfg, Path::new(cwd), None)?;
    let projects = crate::bridge::mirror::mac_config_dir().map(|d| d.join("projects")).ok_or_else(|| CliError::Msg("neither CLAUDE_CONFIG_DIR nor HOME is set: the chat's view has nowhere to go".into()))?;
    let sync = crate::bridge::s3::TranscriptSync::for_workspace(&ctx.paths, &ctx.cfg, &ctx.knobs, &ws, &projects)?;
    let rt = runtime()?;
    let _held = Migrating::hold(paths, row)?;
    audit_request(paths, sid, nonce, "offline", None);
    let started = std::time::Instant::now();
    let to = rt.block_on(async {
        match backend(store, &ctx).await? {
            Backend::Sdk(api, ep) => offline_on(&ctx, &api, &*ep, row, old, &ws, &sync).await,
            Backend::Fake(f) => offline_on(&ctx, &std::sync::Arc::new(f.clone()), &f, row, old, &ws, &sync).await,
        }
    })?;
    Ok(Moved { outcome: "done".to_string(), how: "offline", from_vm: old.to_string(), to_vm: Some(to), ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), code: 0, why: None })
}

/// [`migrate_offline`]'s steps on `api` and `ep`; the new VM's id.
async fn offline_on<A, E>(ctx: &crate::bridge::vm::cmd::Ctx, api: &std::sync::Arc<A>, ep: &E, row: &SessionRow, old: &str, ws: &crate::bridge::workspace::WorkspaceRef, sync: &crate::bridge::s3::TranscriptSync) -> crate::errors::Result<String>
where
    A: crate::bridge::api::MicrovmApi + crate::bridge::s3::S3Sign + 'static,
    E: crate::bridge::api::EndpointClient,
{
    use crate::bridge::remote::pipeline::{carry_seed, data_plane, leave_vm, retire_old_vm, running_resumed, target_of, workspace_caps};
    use crate::bridge::vm::registry as vm_registry;
    use crate::bridge::vm::run::{self, Choice, Egress, Poll, RunFlags, RunPlan};
    use crate::bridge::workspace::{EnsureCtx, SeedLimits};
    let sid = row.session_id.as_str();
    // The old VM's work and the chat, fetched and synced there; a VM gone leaves its last fetch record.
    match api.get(old).await {
        Ok(vm) if !vm.state.is_terminal() => {
            let (vm, _) = running_resumed(&**api, old, ctx.poll(Poll::RESUMED)).await?;
            let vm_row = vm_registry::read_row(&ctx.paths, old)?.ok_or_else(|| CliError::Msg(format!("{old} has no row")))?;
            leave_vm(ctx, ws, Some(sync), api, &vm_row, &vm, Some(sid)).await?;
        }
        Ok(_) | Err(BridgeError::VmNotFound(_)) => crate::bridge::voice::note(&format!("{old} is gone: the chat moves with its last fetch's work")),
        Err(e) => return Err(e.into()),
    }
    // SELECT_VM: the workspace's VM, never the old one.
    let flags = RunFlags { workspace: Some(ws.cwd.clone()), egress: Some(Egress::Vpc), purpose: "session", wait: true, ..RunFlags::default() };
    let mut plan = RunPlan::from_cfg(&ctx.cfg, &flags)?;
    plan.choice = Choice::Workspace;
    plan.workspace_cap = true;
    plan.transcript_cap = true;
    plan.avoid = vec![old.to_string()];
    // S11 (L5): a gzip-staged chat is restored only on a VM that decodes it.
    plan.caps_required = crate::bridge::s3::manifest::caps_required(&ctx.paths, sid);
    let selected = run::select_vm_detailed(&**api, &ctx.paths, &plan, ctx.poll(Poll::RUNNING)).await.map_err(|f| f.error)?;
    let (vm_row, vm) = (selected.row().clone(), selected.vm().clone());
    let (vm_row, caps) = workspace_caps(ctx, &**api, ep, vm_row).await?;
    crate::bridge::vm::cmd::audit_event(&ctx.paths, crate::bridge::remote::audit_event::VM_SELECT, &[("id", vm.id.clone()), ("choice", "workspace".to_string()), ("avoid", old.to_string())]);
    // The carry seed beside the restore, with no deadline.
    let target = target_of(&vm_row, &vm)?;
    let (dp, tokens) = data_plane(ctx, api, &vm.id, true)?;
    let progress = |p: crate::bridge::workspace::SeedProgress| tracing::info!("seed: {p:?}");
    let ectx = EnsureCtx { api: &**api, dp: &*dp, tokens: &*tokens, paths: &ctx.paths, cfg: &ctx.cfg, target: &target, caps: &caps, ws, lim: SeedLimits::cli(&ctx.cfg, None), deadline: None, progress: &progress };
    let slugs: Vec<&str> = std::iter::once(ws.slug.as_str()).chain(row.slug.as_deref()).collect();
    let seed = async {
        let (outcome, source) = carry_seed(&ectx, old).await?;
        Ok::<_, BridgeError>((outcome, source))
    };
    let restore = crate::bridge::workspace::transcript::restore(&ectx, sync, Some(sync.mac_projects.as_path()), &slugs, sid, &crate::wire::view::build_view);
    let ((outcome, source), restored) = tokio::try_join!(seed, restore)?;
    tracing::info!(vm = %vm.id, seed = outcome.word(), source, transcript = restored.word(), "session migrate: the chat is on its new VM");
    // The row: its VM, and a `vms` entry for the move.
    let entry = registry::VmEntry { gen: 0, vm: vm.id.clone(), spawn: None, from: registry::now_rfc3339(), to: None, why: "migrate:command".to_string(), end: None, pid: std::process::id(), tag: None, account: None };
    if let Ok(Some(mut now)) = registry::read(&ctx.paths, sid) {
        now.microvm_id = Some(vm.id.clone());
        now.spawn_id = None;
        now.last_acked_seq = None;
        if let Ok(v) = toml::Value::try_from(&entry) {
            now.vms.push(v);
            let n = now.vms.len();
            if n > registry::VMS_KEPT {
                now.vms.drain(..n - registry::VMS_KEPT);
            }
        }
        registry::write(&ctx.paths, &now)?;
    }
    // The old VM ends, its chats synced first (unless another chat's spawn lives there).
    retire_old_vm(ctx, &**api, ep, old, &vm.id, Some(sid)).await;
    Ok(vm.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// The request file (§6.5): written 0600 with `O_EXCL`; a fresh one is
    /// another command's (refused naming its age and pid), a stale one
    /// removed first; the wrapper takes it whole (read, removed) and judges
    /// it fresh within `MIGRATE_REQUEST_FRESH`; the budgets are the contract's.
    #[test]
    fn the_request_file_is_exclusive_fresh_and_taken_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let now = crate::wire::time::unix_now();
        let req = |age: u64, by: u32| MigrateRequest { v: 1, nonce: uuid::Uuid::now_v7().to_string(), requested_at: crate::wire::time::rfc3339_utc(now - age), by_pid: by };
        let first = req(0, 4242);
        write_request(&paths, SID, &first).unwrap();
        let path = paths.session_migrate_request(SID);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let e = write_request(&paths, SID, &req(0, 4343)).unwrap_err();
        assert!(e.to_string().contains("was asked 0 s ago (pid 4242): wait for it"), "{e}");
        assert_eq!(take_request(&paths, SID).unwrap(), Some(first.clone()), "taken whole");
        assert!(!path.exists() && take_request(&paths, SID).unwrap().is_none(), "removed once taken");
        let stale = req(MIGRATE_REQUEST_FRESH.as_secs() + 5, 4444);
        write_request(&paths, SID, &stale).unwrap();
        assert!(!take_request(&paths, SID).unwrap().unwrap().fresh(now), "older than MIGRATE_REQUEST_FRESH");
        write_request(&paths, SID, &stale).unwrap();
        let mine = req(0, 4545);
        write_request(&paths, SID, &mine).unwrap();
        assert_eq!(take_request(&paths, SID).unwrap(), Some(mine), "a stale one is replaced");
        assert!(take_request(&paths, "not-a-uuid").is_err());
        assert_eq!((MIGRATE_REQUEST_FRESH, MIGRATE_WAIT), (Duration::from_secs(60), Duration::from_secs(300)));
        // Two commands racing: another's request written between this one's check and its open. The open is
        // exclusive: this one fails, naming the file, and the other's request stays whole.
        let theirs = req(0, 4646);
        std::fs::write(&path, serde_json::to_string(&theirs).unwrap()).unwrap();
        let e = create_request(&path, &req(0, 4747)).unwrap_err();
        assert!(e.to_string().contains(&path.display().to_string()), "{e}");
        assert_eq!(take_request(&paths, SID).unwrap(), Some(theirs), "the other command's request, untouched");
    }

    /// The wrapper's answer as the command reports it: `done` 0 with its new
    /// VM; `stayed` and `failed` the row's code (a Touch ID's 3 or 5, AWS 7,
    /// 8, policy 9; any other 1); `refused` and `abandoned` 1.
    #[test]
    fn the_wrappers_answer_maps_to_the_commands_exit() {
        let at = std::time::Instant::now();
        let row = |outcome: &str, code: Option<&str>| {
            let mut d = serde_json::json!({ "outcome": outcome, "to_vm": "microvm-new0000001", "step": "touchid" });
            if let Some(c) = code {
                d["code"] = serde_json::Value::from(c);
            }
            answered(&d, "microvm-old0000001", at)
        };
        let done = row("done", None);
        assert_eq!((done.code, done.to_vm.as_deref(), done.how, done.why), (0, Some("microvm-new0000001"), "live", None));
        for (code, want) in [("3", 3), ("5", 5), ("7", 7), ("8", 8), ("9", 9), ("2", 1)] {
            assert_eq!(row("stayed", Some(code)).code, want, "stayed {code}");
            assert_eq!(row("failed", Some(code)).code, want, "failed {code}");
        }
        for outcome in ["refused", "abandoned"] {
            let m = row(outcome, None);
            assert_eq!(m.code, 1, "{outcome}");
            assert!(m.why.is_some());
        }
    }

    /// A row's `migrating_pid` holds the chat only while it is the offline
    /// `session migrate` that stamped the row: an `ai-env` started at or
    /// before the row's `last_seen`. A pid gone (or unreadable), another
    /// program, or one started later (the system gave a killed command's pid
    /// to a new process) moves nothing; a row with no pid neither.
    #[test]
    fn a_migrating_pid_holds_the_chat_only_while_it_is_the_moving_command() {
        let stamped = 1_790_000_000;
        let row = SessionRow { session_id: SID.into(), last_seen: crate::wire::time::rfc3339_utc(stamped), migrating_pid: Some(4242), ..SessionRow::default() };
        assert!(judge_moving(&row, Some((CLI_EXE.to_string(), stamped - 3))), "the command that took the row");
        assert!(judge_moving(&row, Some((CLI_EXE.to_string(), stamped))), "started in the second it took it");
        assert!(!judge_moving(&row, Some((CLI_EXE.to_string(), stamped + 1))), "a later ai-env given the pid");
        assert!(!judge_moving(&row, Some(("zsh".to_string(), stamped - 3))), "another program");
        assert!(!judge_moving(&row, None), "gone");
        let unstamped = SessionRow { last_seen: String::new(), ..row.clone() };
        assert!(!judge_moving(&unstamped, Some((CLI_EXE.to_string(), 0))), "no stamp to judge by");
        assert_eq!(moving_pid(&SessionRow { migrating_pid: None, ..row.clone() }), None);
        // This test's own process is no `ai-env`: its pid in the row holds nothing.
        assert_eq!(moving_pid(&SessionRow { migrating_pid: Some(std::process::id()), last_seen: registry::now_rfc3339(), ..row }), None);
    }

    /// The offline move's hold: the row `migrating` with this process's pid
    /// meanwhile, given back `closed` with no pid whatever it said before (a
    /// killed move's `migrating` with its dead pid, a dead wrapper's
    /// `active`); a row a wrapper took over meanwhile (no `migrating_pid`
    /// of this process) stays the wrapper's.
    #[test]
    fn the_hold_gives_the_row_back_closed_unless_a_wrapper_took_it() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let me = std::process::id();
        let dead = i32::MAX as u32;
        let base = SessionRow { v: registry::REGISTRY_SCHEMA_V, session_id: SID.into(), status: "closed".into(), mode: "remote".into(), pid: dead, microvm_id: Some("microvm-old0000001".into()), ..SessionRow::default() };
        let read = || registry::read(&paths, SID).unwrap().expect("the row");
        for before in ["migrating", "active", "closed"] {
            let left = SessionRow { status: before.into(), migrating_pid: (before == "migrating").then_some(dead), ..base.clone() };
            registry::write(&paths, &left).unwrap();
            let held = Migrating::hold(&paths, &left).unwrap();
            let now = read();
            assert_eq!((now.status.as_str(), now.migrating_pid), ("migrating", Some(me)), "{before}: held");
            drop(held);
            let now = read();
            assert_eq!((now.status.as_str(), now.migrating_pid, now.microvm_id.as_deref()), ("closed", None, Some("microvm-old0000001")), "{before}: given back");
        }
        // A wrapper registered the row meanwhile (its own pid and status, no `migrating_pid`): the drop leaves it.
        let held = Migrating::hold(&paths, &base).unwrap();
        let wrapper = SessionRow { status: "active".into(), pid: me, migrating_pid: None, ..read() };
        registry::write(&paths, &wrapper).unwrap();
        drop(held);
        assert_eq!(read(), wrapper, "the wrapper's row stays");
    }
}
