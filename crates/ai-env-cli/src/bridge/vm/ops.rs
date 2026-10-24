//! The bodies of `vm list`, `vm suspend|resume` and the one-id
//! `vm terminate` (S11 B.1), returning what happened; `vm/cmd.rs` prints it,
//! the panel renders it. Phase 0 moved them out of `vm/cmd.rs` with no change
//! of output; S11 wave 1's B2 added the cost cells and `vm_observed`. `ops` never unseals
//! and never caches a backend: every caller builds its own
//! (`vm::cmd::backend`, one Touch ID).
use crate::bridge::api::{MicrovmApi, VmState};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::cmd::{refresh_row, Ctx};
use crate::bridge::vm::registry::{self, RowStatus, VmRow};
use crate::bridge::vm::{gc, run};
use crate::errors::{CliError, Result};
use serde::Serialize;
use std::time::Instant;

/// What `vm list`'s RUN and COST cells and its `--json` `cost` say of one VM (B2; `None` until then).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmCostCell {
    /// Over the VM's life up to `now`, at `cost::EUC1`.
    pub usd: f64,
    pub running_s: u64,
    pub suspended_s: u64,
    /// Some end in it was inferred.
    pub inferred: bool,
}

/// One line of `vm list`.
#[derive(Debug, Clone, PartialEq)]
pub struct SurveyItem {
    /// The VM id, or a pending row's stem.
    pub id: String,
    /// ListMicrovms' state, `PENDING-ROW`, or `(<row status>)` for a row the listing lacks.
    pub state: String,
    pub started_at: Option<u64>,
    /// `both`, `list` or `row`.
    pub source: &'static str,
    pub row: Option<VmRow>,
    pub cost: Option<VmCostCell>,
}

/// What `vm list` found, at `now` (`lab::now`).
#[derive(Debug, Clone, PartialEq)]
pub struct Survey {
    pub backend: &'static str,
    pub now: u64,
    pub items: Vec<SurveyItem>,
    /// The reconcile's hint line (`gc::hint_line`), when the survey ran it.
    pub hint: Option<String>,
}

/// ListMicrovms joined with `state/vms` (TERMINATED hidden without `all`); then, with `reconcile`,
/// `gc::reconcile_applied` (S10 L12) and its hint. B2: each listed VM's row gets `state_seen` and
/// `state_seen_at` from the listing, a changed recorded `state_seen` audits `vm_observed` (`via` `survey`), and
/// each item gets its cost cell. A row another process recorded a state in after the listing was asked for (a
/// wrapper's resume) keeps that newer state.
pub async fn survey<A: MicrovmApi>(ctx: &Ctx, api: &A, all: bool, reconcile: bool) -> Result<Survey> {
    let arn = ctx.image_arn()?;
    let before: std::collections::BTreeMap<String, Seen> = registry::list_rows(&ctx.paths)?.into_iter().filter(|r| !r.is_pending_row()).map(|r| (r.id, (r.state_seen, r.state_seen_at))).collect();
    let listing = api.list(Some(&arn)).await?;
    for s in &listing {
        if let Some(seen) = before.get(&s.id) {
            observe(&ctx.paths, &s.id, s.state.as_str(), Via::Survey, seen);
        }
    }
    let rows = registry::list_rows(&ctx.paths)?;
    let now = crate::bridge::lab::now();
    let mut items = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for s in &listing {
        seen.insert(s.id.clone());
        let row = rows.iter().find(|r| r.id == s.id);
        if s.state == VmState::Terminated && !all {
            continue;
        }
        items.push(SurveyItem {
            id: s.id.clone(),
            state: s.state.as_str().to_string(),
            started_at: s.started_at_unix.and_then(|t| u64::try_from(t).ok()),
            source: if row.is_some() { "both" } else { "list" },
            row: row.cloned(),
            cost: None,
        });
    }
    for r in &rows {
        if r.is_pending_row() || seen.contains(&r.id) {
            if r.is_pending_row() {
                items.push(SurveyItem { id: r.stem(), state: "PENDING-ROW".into(), started_at: None, source: "row", row: Some(r.clone()), cost: None });
            }
            continue;
        }
        if r.status == RowStatus::Terminated && !all {
            continue;
        }
        items.push(SurveyItem { id: r.id.clone(), state: format!("({})", r.status.as_str()), started_at: r.started_at, source: "row", row: Some(r.clone()), cost: None });
    }
    let hint = if reconcile { gc::reconcile_applied(api, &ctx.paths, &arn).await.ok().as_deref().and_then(gc::hint_line) } else { None };
    let mut survey = Survey { backend: ctx.backend_name(), now, items, hint };
    add_costs(&ctx.paths, &mut survey);
    Ok(survey)
}

/// Each item's cost cell, from one timeline of every VM's life to the survey's `now` (none when the audit
/// cannot be read: the listing stands without them).
fn add_costs(paths: &Paths, survey: &mut Survey) {
    let t = match crate::bridge::cost::timeline_for(paths, 0, survey.now) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("vm list: no cost cells: {e}");
            return;
        }
    };
    for item in &mut survey.items {
        item.cost = crate::bridge::cost::vm_cell(&t, &item.id);
    }
}

/// A row's recorded `(state_seen, state_seen_at)`.
type Seen = (Option<String>, Option<u64>);

/// A listing saw `id` in `state`: its row (not a terminated one: gc's clock reads its `state_seen_at`) records
/// it, and a change of a recorded `state_seen` is audited `vm_observed` (B §B2.7; a first observation is silent).
/// Under the rows lock, only while the row still records `asked` (what it held before the listing was asked
/// for): a state another process recorded meanwhile is newer than the listing's. Best effort: a row that cannot
/// be written is a warning.
pub(crate) fn observe(paths: &Paths, id: &str, state: &str, via: Via, asked: &Seen) {
    if !registry::is_vm_id(id) {
        return;
    }
    let mut was: Option<String> = None;
    let result = registry::update_row(paths, id, |row| {
        if row.status == RowStatus::Terminated || (row.state_seen.as_ref(), row.state_seen_at) != (asked.0.as_ref(), asked.1) {
            return;
        }
        was = row.state_seen.clone().filter(|w| w != state);
        row.state_seen = Some(state.to_string());
        row.state_seen_at = Some(crate::wire::time::unix_now());
    });
    match result {
        Ok(_) => {
            if let Some(w) = was {
                audit_observed(paths, id, &w, state, via);
            }
        }
        Err(e) => tracing::warn!("cannot record {id}'s state {state}: {e}"),
    }
}

/// The registry alone, no AWS call (the panel's `/vms`): each row as `vm list` would show it, its state the row's
/// `state_seen` (else `(<row status>)`), source `row`; a terminated row hidden without `all`. B2 adds the cost cells.
pub fn offline(paths: &Paths, now: u64, all: bool) -> Result<Survey> {
    let rows = registry::list_rows(paths)?;
    let mut items = Vec::new();
    for r in &rows {
        if r.is_pending_row() {
            items.push(SurveyItem { id: r.stem(), state: "PENDING-ROW".into(), started_at: None, source: "row", row: Some(r.clone()), cost: None });
            continue;
        }
        let state = r.state_seen.clone().unwrap_or_else(|| format!("({})", r.status.as_str()));
        if !all && (r.status == RowStatus::Terminated || state == VmState::Terminated.as_str()) {
            continue;
        }
        items.push(SurveyItem { id: r.id.clone(), state, started_at: r.started_at, source: "row", row: Some(r.clone()), cost: None });
    }
    let mut survey = Survey { backend: "registry", now, items, hint: None };
    add_costs(paths, &mut survey);
    Ok(survey)
}

/// `vm list --json`'s document: `{"backend", "vms": [{"id", "state", "started_at", "source", "row", "cost"}]}`,
/// `row` through `vm::registry::view` (never the session token), `cost` the cell or `null`.
#[must_use]
pub fn survey_json(s: &Survey) -> serde_json::Value {
    let items: Vec<serde_json::Value> = s
        .items
        .iter()
        .map(|i| {
            let cost = i.cost.as_ref().and_then(|c| serde_json::to_value(c).ok()).unwrap_or(serde_json::Value::Null);
            serde_json::json!({ "id": i.id, "state": i.state, "started_at": i.started_at, "source": i.source, "row": i.row.as_ref().map(registry::view), "cost": cost })
        })
        .collect();
    serde_json::json!({ "backend": s.backend, "vms": items })
}

/// `<s>.<tenths> s`.
fn ms_s(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What `vm suspend|resume` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Toggled {
    pub id: String,
    /// `suspend` or `resume`.
    pub action: &'static str,
    /// The state waited for (`SUSPENDED`, `RUNNING`); `None` with `no_wait`.
    pub state: Option<String>,
    pub ms: u64,
}

impl Toggled {
    /// The CLI's line, which `vm/cmd.rs` prints and the panel shows: `<vm>: suspend requested` (`resume`), or
    /// `<vm> SUSPENDED in <s> s`.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.state {
            None => format!("{}: {} requested", self.id, self.action),
            Some(state) => format!("{} {state} in {}", self.id, ms_s(self.ms)),
        }
    }
}

/// SuspendMicrovm or ResumeMicrovm, audited `vm_suspend` or `vm_resume` `{id}`, then (unless `no_wait`)
/// the wait for the state and the row refreshed (`vm::cmd::refresh_row`; B2: `vm_observed` with `via` `wait`).
pub async fn suspend_resume<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str, suspend: bool, no_wait: bool) -> Result<Toggled> {
    let start = Instant::now();
    if suspend {
        api.suspend(id).await?;
    } else {
        api.resume(id).await?;
    }
    crate::bridge::vm::cmd::audit_event(&ctx.paths, if suspend { crate::bridge::audit::event::VM_SUSPEND } else { crate::bridge::audit::event::VM_RESUME }, &[("id", id.to_string())]);
    let action = if suspend { "suspend" } else { "resume" };
    if no_wait {
        return Ok(Toggled { id: id.to_string(), action, state: None, ms: elapsed_ms(start) });
    }
    let want = if suspend { VmState::Suspended } else { VmState::Running };
    let vm = run::wait_for_state(api, id, &want, ctx.poll(run::Poll::SETTLE)).await?;
    refresh_row(&ctx.paths, &vm, Via::Wait);
    Ok(Toggled { id: id.to_string(), action, state: Some(vm.state.as_str().to_string()), ms: elapsed_ms(start) })
}

/// What `vm terminate <vm>` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Terminated {
    pub id: String,
    /// The state the wait saw (`TERMINATED`, …); `None` with `no_wait`.
    pub state: Option<String>,
    pub ms: u64,
    /// `sync_before_terminate`'s warnings, in order (the CLI prints each as `warning: <w>`).
    pub warnings: Vec<String>,
}

impl Terminated {
    /// The CLI's last line: `<vm> terminate requested`, or `<vm> <STATE> (<s> s)`.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.state {
            None => format!("{} terminate requested", self.id),
            Some(state) => format!("{} {state} ({})", self.id, ms_s(self.ms)),
        }
    }
}

/// The checks `Pre::check` makes before any Touch ID: not a VM id, exit 2; no row and not `yes`, exit 1 naming
/// `--yes`; no row, `[aws].image_arn` required.
pub fn terminate_check(ctx: &Ctx, id: &str, yes: bool) -> Result<()> {
    if !registry::is_vm_id(id) {
        return Err(CliError::Usage(format!("not a microvm id: {id:?}")));
    }
    let row = registry::read_row(&ctx.paths, id)?;
    if row.is_none() {
        if !yes {
            return Err(CliError::Msg(format!("{id} has no row in state/vms (not started by this ai-env): add --yes to terminate it anyway")));
        }
        ctx.image_arn()?;
    }
    Ok(())
}

/// The one-id terminate: the image check, the chat transcripts synced first, then
/// `run::terminate_and_record(…, "operator", …)`. A terminate that fails says the sync's warnings first (through
/// the voice), as the CLI always did.
pub async fn terminate_one<A: MicrovmApi + crate::bridge::s3::S3Sign>(ctx: &Ctx, api: &A, id: &str, no_wait: bool) -> Result<Terminated> {
    let wait = (!no_wait).then(|| ctx.poll(run::Poll::SETTLE));
    let row = registry::read_row(&ctx.paths, id)?;
    // A VM with a row is this ai-env's (whatever `--image` it ran); a row-less
    // one must run the configured image (terminate_check required --yes and the ARN).
    let own_image = row.as_ref().map(|r| r.image_arn.clone()).filter(|a| !a.is_empty()).or_else(|| ctx.cfg.aws.image_arn.clone());
    match api.get(id).await {
        Ok(vm) => match &own_image {
            Some(arn) if &vm.image_arn != arn => {
                return Err(BridgeError::Policy(format!("{id} runs image {}, not {arn}; this ai-env terminates only its own image's VMs", vm.image_arn)).into());
            }
            Some(_) => {}
            None => return Err(BridgeError::Policy(format!("{id}: no image to compare with ([aws].image_arn is not set and there is no row)")).into()),
        },
        Err(BridgeError::VmNotFound(_)) if row.is_some() => {}
        Err(e) => return Err(e.into()),
    }
    let start = Instant::now();
    // S9: a running VM's sessions' transcripts to S3 first (best effort; its tails go up at /terminate; a suspended one is not woken: its /suspend pushed them, once).
    let warnings = crate::bridge::s3::commands::sync_before_terminate(ctx, api, id).await;
    let vm = match run::terminate_and_record(api, &ctx.paths, id, "operator", wait).await {
        Ok(vm) => vm,
        Err(e) => {
            for w in &warnings {
                crate::bridge::voice::warn(w);
            }
            return Err(e.into());
        }
    };
    let state = wait.map(|_| vm.as_ref().map_or("TERMINATED", |v| v.state.as_str()).to_string());
    Ok(Terminated { id: id.to_string(), state, ms: elapsed_ms(start), warnings })
}

/// The session ids whose row names `id` as its VM and is not `closed` (the panel's terminate confirmation).
pub fn chats_on(paths: &Paths, id: &str) -> Result<Vec<String>> {
    Ok(crate::bridge::registry::list(paths)?.into_iter().filter(|r| r.microvm_id.as_deref() == Some(id) && r.status != "closed").map(|r| r.session_id).collect())
}

/// One `vm_observed` row (B §B2.7): a refresh changed the row's recorded `state_seen` `was` to `state`.
pub(crate) fn audit_observed(paths: &Paths, id: &str, was: &str, state: &str, via: Via) {
    crate::bridge::vm::cmd::audit_event(paths, crate::bridge::audit::event::VM_OBSERVED, &[("id", id.to_string()), ("state", state.to_string()), ("was", was.to_string()), ("via", via.word().to_string())]);
}

/// Which refresh saw it; its word is `vm_observed`'s `via`: `survey`, `status`, `wait`, `gc`, `reconcile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Survey,
    Status,
    Wait,
    Gc,
    Reconcile,
}

impl Via {
    /// `vm_observed`'s `via`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Via::Survey => "survey",
            Via::Status => "status",
            Via::Wait => "wait",
            Via::Gc => "gc",
            Via::Reconcile => "reconcile",
        }
    }
}
