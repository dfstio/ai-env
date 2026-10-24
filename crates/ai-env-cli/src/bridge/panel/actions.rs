//! The panel's actions (B §B5.8 to §B5.10): what each runs and its CLI twin,
//! the nonces a confirm page issues (single use, [`NONCE_TTL`], at most
//! [`NONCES_MAX`] held), the board of this run's actions (in memory only,
//! never written), and the worker: one std thread that runs one action at a
//! time, each as the CLI runs it (`Ctx::load`, its own current-thread
//! runtime, `vm::cmd::backend`: one Touch ID, dropped with the action).
use super::{Shared, NONCES_MAX, NONCE_TTL};
use crate::bridge::vm::cmd::{backend, runtime, with_backend, Ctx};
use crate::bridge::vm::ops;
use crate::errors::{CliError, Result};
use crate::store::Keystore;
use serde::Serialize;
use std::collections::VecDeque;

/// The target word of the one action with none (`vm-refresh`).
pub const NO_TARGET: &str = "-";

/// What the panel can do, each a CLI command ([`Action::twin`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    VmSuspend,
    VmResume,
    VmTerminate,
    VmRefresh,
    SessionMigrate,
}

impl Action {
    pub const ALL: [Action; 5] = [Action::VmSuspend, Action::VmResume, Action::VmTerminate, Action::VmRefresh, Action::SessionMigrate];

    /// `vm-suspend`, `vm-resume`, `vm-terminate`, `vm-refresh`, `session-migrate`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Action::VmSuspend => "vm-suspend",
            Action::VmResume => "vm-resume",
            Action::VmTerminate => "vm-terminate",
            Action::VmRefresh => "vm-refresh",
            Action::SessionMigrate => "session-migrate",
        }
    }

    /// The action a word names.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.word() == word)
    }

    /// The CLI command that does the same (shown on its pages).
    #[must_use]
    pub fn twin(self, target: &str) -> String {
        match self {
            Action::VmSuspend => format!("ai-env vm suspend {target}"),
            Action::VmResume => format!("ai-env vm resume {target}"),
            Action::VmTerminate => format!("ai-env vm terminate {target}"),
            Action::VmRefresh => "ai-env vm list".to_string(),
            Action::SessionMigrate => format!("ai-env session migrate {target}"),
        }
    }

    /// Its target is a VM id with a row (else a session id, or [`NO_TARGET`]).
    #[must_use]
    pub fn on_vm(self) -> bool {
        matches!(self, Action::VmSuspend | Action::VmResume | Action::VmTerminate)
    }
}

/// One issued nonce: bound to its action and target.
#[derive(Debug)]
struct Nonce {
    id: String,
    action: Action,
    target: String,
    /// Wall-clock seconds (`unix_now`): `Instant` stops while a Mac sleeps, so a confirm page left open over a
    /// sleep would outlive [`NONCE_TTL`].
    issued: u64,
    used: bool,
}

/// The nonces the confirm pages issued, oldest first.
#[derive(Debug, Default)]
pub struct Nonces {
    held: VecDeque<Nonce>,
}

impl Nonces {
    /// A fresh nonce (a uuid v7, also the action's id) for `action` on `target`; the oldest dropped past
    /// [`NONCES_MAX`].
    pub fn issue(&mut self, action: Action, target: &str, now: u64) -> String {
        let id = uuid::Uuid::now_v7().to_string();
        self.held.push_back(Nonce { id: id.clone(), action, target: target.to_string(), issued: now, used: false });
        while self.held.len() > NONCES_MAX {
            self.held.pop_front();
        }
        id
    }

    /// `id` was issued for `action` on `target`, is unused, and younger than [`NONCE_TTL`] at `now` (wall-clock
    /// seconds; a clock that moved back before its issue fails closed).
    #[must_use]
    pub fn valid(&self, id: &str, action: Action, target: &str, now: u64) -> bool {
        self.held.iter().any(|n| n.id == id && !n.used && n.action == action && n.target == target && n.issued <= now && now - n.issued < NONCE_TTL.as_secs())
    }

    /// `id` is used: never valid again.
    pub fn spend(&mut self, id: &str) {
        if let Some(n) = self.held.iter_mut().find(|n| n.id == id) {
            n.used = true;
        }
    }
}

/// One action as its page, its `?json=1` and the `events` streams show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionView {
    /// Its nonce.
    pub id: String,
    pub action: &'static str,
    pub target: String,
    /// `queued`, `running`, `done` or `failed`.
    pub state: &'static str,
    pub twin: String,
    /// The CLI's result line (its warnings first), or its error's line, once it ended.
    pub line: String,
    /// The CLI's exit code, once it ended.
    pub code: Option<i32>,
    /// When it was queued (RFC 3339 UTC); on its page, not in its documents.
    #[serde(skip)]
    pub since: String,
}

/// This run's actions, in the order they came (memory only).
#[derive(Debug, Default)]
pub struct Board {
    actions: Vec<ActionView>,
}

impl Board {
    /// The action queued or running, if any.
    #[must_use]
    pub fn busy(&self) -> Option<&ActionView> {
        self.actions.iter().find(|a| matches!(a.state, "queued" | "running"))
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&ActionView> {
        self.actions.iter().find(|a| a.id == id)
    }

    /// The last `n` actions, oldest first.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<ActionView> {
        self.actions[self.actions.len().saturating_sub(n)..].to_vec()
    }

    /// Change action `id`: what it now is.
    pub fn update(&mut self, id: &str, change: impl FnOnce(&mut ActionView)) -> Option<ActionView> {
        let a = self.actions.iter_mut().find(|a| a.id == id)?;
        change(a);
        Some(a.clone())
    }
}

/// One action for the worker: its nonce, what, on what.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub action: Action,
    pub target: String,
}

/// Why `POST actions` refused: its status and its one line.
pub(crate) type Refusal = (http::StatusCode, String);

/// `POST actions`' checks and its hand-off to the worker: the nonce issued for exactly this action and target,
/// unused and unexpired (403); no action queued or running (409, the nonce left unused); then the nonce spent,
/// the action on the board as `queued`, and the worker told.
pub(crate) fn submit(shared: &Shared, nonce: &str, action: Action, target: &str) -> std::result::Result<(), Refusal> {
    let mut nonces = shared.nonces();
    if !nonces.valid(nonce, action, target, crate::wire::time::unix_now()) {
        return Err((http::StatusCode::FORBIDDEN, "forbidden: no such nonce for this action and target, or it was used or expired (open its confirm page again)".into()));
    }
    let mut board = shared.board();
    if let Some(running) = board.busy() {
        return Err((http::StatusCode::CONFLICT, format!("an action is running: {} {} since {} (it has its own page)", running.action, running.target, running.since)));
    }
    let view = ActionView {
        id: nonce.to_string(),
        action: action.word(),
        target: target.to_string(),
        state: "queued",
        twin: action.twin(target),
        line: String::new(),
        code: None,
        since: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
    };
    board.actions.push(view.clone());
    let sent = shared.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).send(Job { id: nonce.to_string(), action, target: target.to_string() });
    if sent.is_err() {
        board.actions.pop();
        return Err((http::StatusCode::INTERNAL_SERVER_ERROR, "the action worker is gone".into()));
    }
    nonces.spend(nonce);
    // Sent with the board held (`send` never blocks): the worker's `running` reaches the streams after this.
    let _ = shared.changes.send(view);
    drop(board);
    drop(nonces);
    Ok(())
}

/// The worker: each job in turn, `running`, then `done` (exit 0) or `failed` with the CLI's line and exit code.
/// The state follows the result, never the code: an error the CLI exits 0 with (`BrokenPipe`, `Exit(0)`) is
/// `failed` with code 1. A panicking action is `failed` (101), and the worker goes on.
pub(crate) fn work(store: &Keystore, shared: &Shared, queue: &std::sync::mpsc::Receiver<Job>) {
    while let Ok(job) = queue.recv() {
        shared.update(&job.id, |a| a.state = "running");
        tracing::info!("panel: action {} {}: running", job.action.word(), job.target);
        let (state, line, code) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(store, &job))) {
            Ok(Ok(line)) => ("done", line, 0),
            Ok(Err((line, code))) => ("failed", line, if code == 0 { 1 } else { code }),
            Err(_) => ("failed", "the action panicked (logs/ai-env.log)".to_string(), 101),
        };
        tracing::info!("panel: action {} {}: {state} (exit {code})", job.action.word(), job.target);
        shared.update(&job.id, |a| {
            a.state = state;
            a.line = line;
            a.code = Some(code);
        });
    }
}

/// One action, as its CLI twin runs it: its result line, or its error's line and exit code.
fn run(store: &Keystore, job: &Job) -> std::result::Result<String, (String, i32)> {
    let failed = |e: CliError| (e.to_string(), e.exit_code());
    match job.action {
        Action::SessionMigrate => match crate::bridge::migrate::migrate(store, &job.target, &job.id) {
            Ok(m) if m.code == 0 => Ok(m.line(&job.target)),
            Ok(m) => Err((m.line(&job.target), m.code)),
            Err(e) => Err(failed(e)),
        },
        _ => vm_action(store, job).map_err(failed),
    }
}

/// A VM action: the context and its checks before any Touch ID, then the backend (one Touch ID) on a runtime
/// of the action's own, the `ops` call, the backend dropped.
fn vm_action(store: &Keystore, job: &Job) -> Result<String> {
    let ctx = Ctx::load()?;
    match job.action {
        Action::VmTerminate => ops::terminate_check(&ctx, &job.target, false)?,
        Action::VmRefresh => {
            ctx.image_arn()?;
        }
        _ => {}
    }
    let rt = runtime()?;
    let line = rt.block_on(async {
        let b = backend(store, &ctx).await?;
        with_backend!(&b, |api, _ep| match job.action {
            Action::VmSuspend => ops::suspend_resume(&ctx, api, &job.target, true, false).await.map(|t| t.line()),
            Action::VmResume => ops::suspend_resume(&ctx, api, &job.target, false, false).await.map(|t| t.line()),
            Action::VmTerminate => ops::terminate_one(&ctx, api, &job.target, false).await.map(|t| terminated_lines(&t)),
            Action::VmRefresh | Action::SessionMigrate => ops::survey(&ctx, api, false, true).await.map(|s| survey_lines(&s)),
        })
    });
    rt.shutdown_background();
    line
}

/// The one-id terminate's output: each warning (`warning: <w>`), then its last line.
fn terminated_lines(t: &ops::Terminated) -> String {
    t.warnings.iter().map(|w| format!("warning: {w}")).chain(std::iter::once(t.line())).collect::<Vec<_>>().join("\n")
}

/// The refresh's output: `vm list`'s stdout lines (`vm::cmd::list_lines`,
/// B §B5.8; the panel's survey never shows TERMINATED ones), then the
/// reconcile's hint.
fn survey_lines(s: &ops::Survey) -> String {
    let mut lines = crate::bridge::vm::cmd::list_lines(s, false);
    lines.extend(s.hint.clone());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_twins_and_nonces() {
        for a in Action::ALL {
            assert_eq!(Action::from_word(a.word()), Some(a));
        }
        assert_eq!(Action::from_word("vm-reboot"), None);
        assert_eq!(Action::VmSuspend.twin("microvm-x"), "ai-env vm suspend microvm-x");
        assert_eq!(Action::VmRefresh.twin(NO_TARGET), "ai-env vm list");
        let mut n = Nonces::default();
        let t0: u64 = 1_792_000_000;
        let ttl = NONCE_TTL.as_secs();
        let id = n.issue(Action::VmResume, "microvm-x", t0);
        assert!(n.valid(&id, Action::VmResume, "microvm-x", t0));
        assert!(!n.valid(&id, Action::VmSuspend, "microvm-x", t0), "another action");
        assert!(!n.valid(&id, Action::VmResume, "microvm-y", t0), "another target");
        assert!(!n.valid(&id, Action::VmResume, "microvm-x", t0 + ttl), "expired");
        assert!(n.valid(&id, Action::VmResume, "microvm-x", t0 + ttl - 1));
        assert!(!n.valid(&id, Action::VmResume, "microvm-x", t0 - 1), "a clock moved back fails closed");
        n.spend(&id);
        assert!(!n.valid(&id, Action::VmResume, "microvm-x", t0), "used");
        let first = n.issue(Action::VmRefresh, NO_TARGET, t0);
        for _ in 0..NONCES_MAX {
            n.issue(Action::VmRefresh, NO_TARGET, t0);
        }
        assert!(!n.valid(&first, Action::VmRefresh, NO_TARGET, t0), "the oldest dropped");
        assert_eq!(n.held.len(), NONCES_MAX);
    }
}
