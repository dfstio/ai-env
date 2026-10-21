//! Tag-free garbage collection (plan S4 D17, §7, step 7). The platform has
//! no tags, so ownership comes from two places: the registry
//! (`state/vms/*.toml`) and, for a VM without a row, its `/health` `owner` +
//! `created` (the run-hook payload the shim echoes). gc surveys
//! `ListMicrovms(image)` ∪ the rows, probes `/health` once for each row-less
//! RUNNING VM (never a SUSPENDED/SUSPENDING/PENDING one: a request would
//! resume it and bill), classifies every VM and row into the nine classes of
//! the §7 table ([`classify`], pure), and acts only with `--yes`. A dry run
//! writes nothing: no row, no audit line.
//!
//! With `--yes`, gc also finishes the S5 egress echo gate ([`regate`]): a
//! live VM whose row's verdict is not `passed` is judged again, or
//! terminated (`policy`), so a failed terminate or a crash between
//! RunMicrovm and the gate cannot leave a VM with the wrong egress behind.
//!
//! [`reconcile_local`] is the opportunistic survey (no probes, no action,
//! one hint line). S10's [`reconcile_apply_local`] acts on it locally (the
//! rows of VMs the platform ended, old terminated rows, the session rows a
//! dead wrapper left on a VM that is gone; never a terminate, never a Touch
//! ID): at a wrapper's start at most every [`GC_RECONCILE_EVERY`], and at
//! every `vm run|list|smoke` ([`reconcile_applied`], before their hint).
//! [`terminate_all_plan`] is the survey behind `vm terminate --all` (D29).
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState, VmSummary};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::owner;
use crate::bridge::vm::registry::{self, RowStatus, VmRow, GATE_MISMATCH, GATE_PASSED, PENDING_STALE_S, TERMINATED_KEEP_S};
use crate::bridge::vm::run::{adopt_pending, audit_event, created_unix, echo_passes, probe_health_once, reject_echo, request_terminate, row_gate, terminate_and_record, START_SKEW_S};
use crate::wire::time::unix_now;
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// A registry VM whose wall deadline is this close (or passed) is `registry:expired`.
pub const EXPIRY_MARGIN_S: u64 = 60;

/// The nine classes of the plan S4 §7 gc table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GcClass {
    /// A row, the VM non-terminal, `wall_deadline` > now + 60 s.
    RegistryLive,
    /// A row, the VM non-terminal, `wall_deadline` ≤ now + 60 s.
    RegistryExpired,
    /// A row not terminated whose VM is TERMINATED, or unlisted and `GetMicrovm` NotFound.
    RegistryGone,
    /// A pending row whose `owner` + `created` a row-less VM's `/health` answers.
    Adopt,
    /// A row-less RUNNING VM whose `/health` owner is this user@host.
    OrphanMine,
    /// A row-less VM of another owner.
    Foreign,
    /// A row-less SUSPENDED/SUSPENDING/PENDING VM, one whose `/health` failed
    /// (or was not asked) or named no owner/created yet, or a pending row of
    /// an image gc could not list.
    Unprobed,
    /// A pending row > 5 min old with no unprobed VM started around its
    /// `created`, or older than its max duration.
    PendingStale,
    /// A terminated row older than 7 days.
    TerminatedOld,
}

impl GcClass {
    /// Every class, in table order.
    pub const ALL: [GcClass; 9] = [
        GcClass::RegistryLive,
        GcClass::RegistryExpired,
        GcClass::RegistryGone,
        GcClass::Adopt,
        GcClass::OrphanMine,
        GcClass::Foreign,
        GcClass::Unprobed,
        GcClass::PendingStale,
        GcClass::TerminatedOld,
    ];

    /// The printed name (`registry:live`, …, `terminated-old`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            GcClass::RegistryLive => "registry:live",
            GcClass::RegistryExpired => "registry:expired",
            GcClass::RegistryGone => "registry:gone",
            GcClass::Adopt => "adopt",
            GcClass::OrphanMine => "orphan:mine",
            GcClass::Foreign => "foreign",
            GcClass::Unprobed => "unprobed",
            GcClass::PendingStale => "pending:stale",
            GcClass::TerminatedOld => "terminated-old",
        }
    }
}

impl Serialize for GcClass {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

/// What gc does (or, in a dry run, would only report) for one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GcAction {
    /// `--yes`: leave it.
    Keep,
    /// `--yes`: `TerminateMicrovm` and record it (`gc-expired` / `gc-orphan`).
    Terminate,
    /// `--yes`: the row becomes terminated (the VM is already gone).
    MarkTerminated,
    /// `--yes`: the pending row becomes `<id>.toml`.
    Adopt,
    /// `--yes`: the row file is removed.
    RemoveRow,
    /// A dry run: reported, nothing done.
    Report,
}

impl GcAction {
    /// The printed name (`keep`, `terminate`, `mark-terminated`, `adopt`, `remove-row`, `report`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            GcAction::Keep => "keep",
            GcAction::Terminate => "terminate",
            GcAction::MarkTerminated => "mark-terminated",
            GcAction::Adopt => "adopt",
            GcAction::RemoveRow => "remove-row",
            GcAction::Report => "report",
        }
    }
}

/// One classified VM or row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcItem {
    pub class: GcClass,
    /// The VM id (absent for a pending row nothing adopts).
    pub id: Option<String>,
    /// The row's file stem (`<id>` or `pending-<client_token>`), when a row is involved.
    pub stem: Option<String>,
    /// Seconds since the VM started (row: since `started_at`, else `created`;
    /// pending row: since `created`; terminated row: since `terminated_at`).
    pub age_s: Option<u64>,
    /// Human detail: wall left, owner, state, why stale.
    pub detail: String,
    pub action: GcAction,
}

/// `ai-env vm gc` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcOpts {
    /// `--yes`: act; without it nothing is written.
    pub yes: bool,
    /// `--include-orphans AGE` (with `--yes`): terminate own orphans at least this old.
    pub include_orphans: Option<Duration>,
    /// Probe `/health` of row-less RUNNING VMs (off for [`reconcile_local`]).
    pub probe_health: bool,
}

/// What a row-less RUNNING VM's `/health` (HTTP 200, for that VM's own
/// `microvm_id`) said about its owner.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthProbe {
    pub owner: Option<String>,
    pub created: Option<String>,
}

/// The outcome of [`gc`]: every item, and what `--yes` did.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct GcReport {
    pub items: Vec<GcItem>,
    pub terminated: usize,
    pub adopted: usize,
    pub removed: usize,
    pub marked: usize,
    /// One line per action that failed (the others still ran); empty on success.
    pub errors: Vec<String>,
    /// How many of `errors` are VMs that failed the S5 egress echo gate
    /// (`vm gc` then exits 9, not 7).
    pub mismatches: usize,
}

// ---- classify (pure) -------------------------------------------------------------------

fn action_for(class: GcClass, age_s: Option<u64>, opts: &GcOpts) -> GcAction {
    if !opts.yes {
        return GcAction::Report;
    }
    match class {
        GcClass::RegistryLive | GcClass::Foreign | GcClass::Unprobed => GcAction::Keep,
        GcClass::RegistryExpired => GcAction::Terminate,
        GcClass::RegistryGone => GcAction::MarkTerminated,
        GcClass::Adopt => GcAction::Adopt,
        GcClass::OrphanMine => match (opts.include_orphans, age_s) {
            (Some(min), Some(age)) if age >= min.as_secs() => GcAction::Terminate,
            _ => GcAction::Keep,
        },
        GcClass::PendingStale | GcClass::TerminatedOld => GcAction::RemoveRow,
    }
}

fn since(now: u64, t: Option<u64>) -> Option<u64> {
    t.map(|t| now.saturating_sub(t))
}

fn started(s: &VmSummary) -> Option<u64> {
    s.started_at_unix.and_then(|t| u64::try_from(t).ok())
}

/// Classify every VM and row per the plan S4 §7 table. `listing` is
/// `ListMicrovms(image)` plus, for every non-terminated id row the listing
/// missed, what `GetMicrovm` answered ([`gc`] adds those); an id row absent
/// from `listing` therefore means `GetMicrovm` said NotFound. `healths` holds
/// the successful `/health` answers of row-less RUNNING VMs (a row-less
/// RUNNING VM without one, or whose answer has no `owner` or no `created` —
/// the run hook was not delivered yet — is `unprobed`: never terminated,
/// never adopted, and it keeps pending rows of its image from going stale).
/// `me` is `vm::owner()`. Without `opts.yes` every action is `Report`; with
/// it the table's `--yes` column applies, `orphan:mine` terminating only with
/// `include_orphans` and an age at least that old. Items come in three
/// groups: id rows (in `rows` order), row-less VMs (in `listing` order),
/// pending rows. Every image is taken as surveyed; see [`classify_surveyed`].
#[must_use]
pub fn classify(listing: &[VmSummary], rows: &[VmRow], healths: &BTreeMap<String, HealthProbe>, now: u64, me: &str, opts: &GcOpts) -> Vec<GcItem> {
    classify_surveyed(listing, rows, healths, now, me, opts, &BTreeMap::new())
}

/// [`classify`], told which images could not be listed (`unsurveyed`: image
/// ARN → why). A pending row of such an image is never `pending:stale` for
/// want of a VM to adopt (its VM could exist unseen): it is reported as
/// `unprobed` instead (kept with `--yes`). A pending row older than its max
/// duration is stale whatever was surveyed (no VM outlives it).
#[must_use]
pub fn classify_surveyed(listing: &[VmSummary], rows: &[VmRow], healths: &BTreeMap<String, HealthProbe>, now: u64, me: &str, opts: &GcOpts, unsurveyed: &BTreeMap<String, String>) -> Vec<GcItem> {
    let mut items = Vec::new();
    let mut push = |class: GcClass, id: Option<String>, stem: Option<String>, age_s: Option<u64>, detail: String| {
        let action = action_for(class, age_s, opts);
        items.push(GcItem { class, id, stem, age_s, detail, action });
    };
    let listed: BTreeMap<&str, &VmSummary> = listing.iter().map(|s| (s.id.as_str(), s)).collect();
    let id_rows: Vec<&VmRow> = rows.iter().filter(|r| !r.is_pending_row()).collect();
    let row_ids: BTreeSet<&str> = id_rows.iter().map(|r| r.id.as_str()).collect();
    let pending: Vec<&VmRow> = rows.iter().filter(|r| r.is_pending_row()).collect();

    for row in &id_rows {
        let vm = listed.get(row.id.as_str()).copied();
        let age = since(now, row.started_at.or_else(|| created_unix(row)));
        match vm {
            Some(s) if !s.state.is_terminal() => {
                let deadline = row.wall_deadline.or_else(|| created_unix(row).map(|c| c.saturating_add(u64::from(row.max_duration_s))));
                let stale_row = if row.status == RowStatus::Terminated { " (the row says terminated)" } else { "" };
                let gate = gate_note(row);
                match deadline {
                    Some(d) if d <= now.saturating_add(EXPIRY_MARGIN_S) => {
                        let when = if d <= now { format!("wall passed {} s ago", now - d) } else { format!("wall in {} s", d - now) };
                        push(GcClass::RegistryExpired, Some(row.id.clone()), Some(row.stem()), age, format!("{} {when}{stale_row}{gate}", s.state.as_str()));
                    }
                    Some(d) => push(GcClass::RegistryLive, Some(row.id.clone()), Some(row.stem()), age, format!("{} wall left {} s{stale_row}{gate}", s.state.as_str(), d - now)),
                    None => push(GcClass::RegistryLive, Some(row.id.clone()), Some(row.stem()), age, format!("{} wall unknown{stale_row}{gate}", s.state.as_str())),
                }
            }
            _ if row.status == RowStatus::Terminated => {
                let at = row.terminated_at.or(row.state_seen_at).or_else(|| created_unix(row));
                if let Some(old) = since(now, at).filter(|a| *a > TERMINATED_KEEP_S) {
                    push(GcClass::TerminatedOld, Some(row.id.clone()), Some(row.stem()), Some(old), format!("terminated {} d ago", old / 86_400));
                }
            }
            Some(s) => push(GcClass::RegistryGone, Some(row.id.clone()), Some(row.stem()), age, format!("row {}, VM {}", row.status.as_str(), s.state.as_str())),
            None => push(GcClass::RegistryGone, Some(row.id.clone()), Some(row.stem()), age, format!("row {}, VM not listed and GetMicrovm: not found", row.status.as_str())),
        }
    }

    let mut adopted: BTreeSet<&str> = BTreeSet::new();
    // (image, start) of every row-less VM gc could not ask: each may be a pending row's VM.
    let mut unprobed_starts: Vec<(&str, Option<u64>)> = Vec::new();
    for s in listing.iter().filter(|s| !row_ids.contains(s.id.as_str()) && !s.state.is_terminal()) {
        let age = since(now, started(s));
        if s.state != VmState::Running {
            unprobed_starts.push((s.image_arn.as_str(), started(s)));
            let why = match s.state {
                VmState::Pending => "booting",
                VmState::Suspended | VmState::Suspending => "never probed: a request would resume it",
                _ => "state not probed",
            };
            push(GcClass::Unprobed, Some(s.id.clone()), None, age, format!("{} ({why})", s.state.as_str()));
            continue;
        }
        let Some(h) = healths.get(&s.id) else {
            unprobed_starts.push((s.image_arn.as_str(), started(s)));
            let why = if opts.probe_health { "/health failed" } else { "/health not probed" };
            push(GcClass::Unprobed, Some(s.id.clone()), None, age, format!("RUNNING ({why})"));
            continue;
        };
        // No owner or no created: the run hook has not reached the shim yet, so the VM cannot say whose it is.
        let (Some(owner), Some(created)) = (h.owner.as_deref(), h.created.as_deref()) else {
            unprobed_starts.push((s.image_arn.as_str(), started(s)));
            push(GcClass::Unprobed, Some(s.id.clone()), None, age, "RUNNING (/health has no owner or created yet: run hook not delivered)".to_string());
            continue;
        };
        let matched = pending.iter().find(|p| !adopted.contains(p.client_token.as_str()) && owner == p.owner && created == p.created);
        if let Some(p) = matched {
            adopted.insert(p.client_token.as_str());
            push(GcClass::Adopt, Some(s.id.clone()), Some(p.stem()), age, format!("/health owner {} created {} = {}", p.owner, p.created, p.stem()));
        } else if owner == me {
            push(GcClass::OrphanMine, Some(s.id.clone()), None, age, format!("owner {me}, no row"));
        } else {
            push(GcClass::Foreign, Some(s.id.clone()), None, age, format!("owner {owner}"));
        }
    }

    let same_image = |a: &str, b: &str| a.is_empty() || b.is_empty() || a == b;
    for p in pending.iter().filter(|p| !adopted.contains(p.client_token.as_str())) {
        let created = created_unix(p);
        let age = since(now, created);
        let (class, detail) = match (created, age) {
            (Some(c), Some(age)) => {
                if p.max_duration_s > 0 && age > u64::from(p.max_duration_s) {
                    (GcClass::PendingStale, Some(format!("pending {age} s, older than its max duration ({} s)", p.max_duration_s)))
                } else if age > PENDING_STALE_S {
                    if let Some(why) = unsurveyed.get(&p.image_arn) {
                        (GcClass::Unprobed, Some(format!("pending {age} s of image {}, which could not be listed ({why}): not judged stale", p.image_arn)))
                    } else {
                        let (lo, hi) = (c.saturating_sub(START_SKEW_S), c.saturating_add(PENDING_STALE_S));
                        let candidate = unprobed_starts.iter().any(|(image, t)| same_image(image, &p.image_arn) && t.is_none_or(|t| (lo..=hi).contains(&t)));
                        (GcClass::PendingStale, (!candidate).then(|| format!("pending {age} s, no VM to adopt")))
                    }
                } else {
                    (GcClass::PendingStale, None)
                }
            }
            _ => (GcClass::PendingStale, Some(format!("pending row with an unreadable created {:?}", p.created))),
        };
        if let Some(detail) = detail {
            push(class, None, Some(p.stem()), age, detail);
        }
    }
    items
}

/// A row that says terminated while its VM may still run, which `vm gc
/// --yes` terminates again ([`regate`]): one the S5 egress gate terminated
/// (`terminated_by = policy`), or one that ended before its gate passed.
fn terminate_again(row: &VmRow) -> bool {
    row.status == RowStatus::Terminated && (row.terminated_by.as_deref() == Some("policy") || row.egress_gate.as_deref() != Some(GATE_PASSED))
}

/// What the S5 egress verdict of a row whose VM is live adds to its detail:
/// nothing once `passed`; else what `vm gc --yes` does about it ([`regate`]).
fn gate_note(row: &VmRow) -> String {
    if row.status == RowStatus::Terminated {
        return if terminate_again(row) { "; --yes terminates it again".to_string() } else { String::new() };
    }
    match row.egress_gate.as_deref() {
        Some(GATE_PASSED) => String::new(),
        Some(GATE_MISMATCH) => "; egress gate mismatch: --yes terminates it".to_string(),
        Some(g) => format!("; egress gate {g}: --yes gates it again"),
        None => "; egress gate never ran (a row from before S5): --yes gates it".to_string(),
    }
}

// ---- survey ----------------------------------------------------------------------------

/// What [`survey_local`] saw.
struct Survey {
    /// Every image listed, plus `GetMicrovm` of the unlisted id rows.
    listing: Vec<VmSummary>,
    rows: Vec<VmRow>,
    /// Images of rows that could not be listed: ARN → why.
    unsurveyed: BTreeMap<String, String>,
}

/// `ListMicrovms(image)`, then `ListMicrovms` of every other image a pending
/// row, a non-terminated id row or a row to terminate again
/// ([`terminate_again`]) names (a crashed `vm run --image OTHER` must be
/// adoptable; a failure there is logged and the image recorded as
/// unsurveyed, never fatal), then `GetMicrovm` of every non-terminated id row
/// the listings missed (NotFound leaves it out: `registry:gone`), and every row.
async fn survey_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str) -> Result<Survey, BridgeError> {
    let mut listing = api.list(Some(image_arn)).await?;
    let rows = registry::list_rows(paths)?;
    let others: BTreeSet<&str> = rows.iter().filter(|r| r.is_pending_row() || r.status != RowStatus::Terminated || terminate_again(r)).map(|r| r.image_arn.as_str()).filter(|a| !a.is_empty() && *a != image_arn).collect();
    let mut unsurveyed = BTreeMap::new();
    for other in others {
        match api.list(Some(other)).await {
            Ok(more) => {
                let seen: BTreeSet<String> = listing.iter().map(|s| s.id.clone()).collect();
                listing.extend(more.into_iter().filter(|s| !seen.contains(&s.id)));
            }
            Err(e) => {
                tracing::warn!("gc: cannot list the VMs of image {other}: {e}");
                unsurveyed.insert(other.to_string(), e.to_string());
            }
        }
    }
    let listed: BTreeSet<String> = listing.iter().map(|s| s.id.clone()).collect();
    for row in rows.iter().filter(|r| !r.is_pending_row() && r.status != RowStatus::Terminated && !listed.contains(&r.id)) {
        match api.get(&row.id).await {
            Ok(vm) => listing.push(summary_of(&vm)),
            Err(BridgeError::VmNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Survey { listing, rows, unsurveyed })
}

fn summary_of(vm: &VmInfo) -> VmSummary {
    VmSummary { id: vm.id.clone(), state: vm.state.clone(), image_arn: vm.image_arn.clone(), image_version: vm.image_version.clone(), started_at_unix: vm.started_at_unix }
}

/// One `/health` per row-less RUNNING VM (no retry). Only an HTTP 200 whose
/// body names the probed VM (`microvm_id`, plan S4 D30) counts; anything
/// else — another status, a transport error, an answer for another or no
/// `microvm_id` — is logged and leaves the VM out (→ `unprobed`, never
/// `adopt` or `orphan:mine`). Returns the answers and each probed VM's
/// `GetMicrovm` (for adoption).
async fn probe_rowless<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, listing: &[VmSummary], rows: &[VmRow]) -> (BTreeMap<String, HealthProbe>, BTreeMap<String, VmInfo>) {
    let row_ids: BTreeSet<&str> = rows.iter().filter(|r| !r.is_pending_row()).map(|r| r.id.as_str()).collect();
    let mut healths = BTreeMap::new();
    let mut infos = BTreeMap::new();
    for s in listing.iter().filter(|s| s.state == VmState::Running && !row_ids.contains(s.id.as_str())) {
        match probe_health_once(api, ep, &s.id).await {
            Ok((vm, h)) => {
                healths.insert(s.id.clone(), HealthProbe { owner: h.owner, created: h.created });
                infos.insert(s.id.clone(), vm);
            }
            Err(e) => tracing::warn!("gc: {} not probed: {e}", s.id),
        }
    }
    (healths, infos)
}

// ---- the S5 egress gate, again ---------------------------------------------------------

/// The S5 egress echo gate again (`--yes`, before the table's actions), so a
/// VM whose gate never finished cannot outlive gc. For every row whose VM
/// `listing` shows non-terminal: a row to terminate again
/// ([`terminate_again`]: the gate terminated it, or it ended before its gate
/// passed) or one whose verdict is `mismatch` (its terminate failed) is
/// terminated (`policy`) whatever it echoes now; a row still `pending`
/// (`ai-env` died between RunMicrovm and the gate) or without a verdict (a
/// row from before S5) is judged on one `GetMicrovm` against its own row
/// ([`ExpectedEcho::for_row`](crate::bridge::egress::ExpectedEcho::for_row)):
/// a pass records `passed` and the echo; anything else is a mismatch
/// (`reject_echo`: verdict, terminate by `policy`, audit `vm_egress_mismatch`
/// via `gc`), counted in [`GcReport::mismatches`] and reported as an error. A
/// VM still PENDING without an echo, gone, or that `GetMicrovm` could not
/// answer for (an error) is left for the next gc. Returns the ids it
/// terminated (the table's own terminate skips them).
async fn regate<A: MicrovmApi>(api: &A, paths: &Paths, listing: &[VmSummary], rows: &[VmRow], report: &mut GcReport) -> BTreeSet<String> {
    let live: BTreeSet<&str> = listing.iter().filter(|s| !s.state.is_terminal()).map(|s| s.id.as_str()).collect();
    let mut done = BTreeSet::new();
    for row in rows.iter().filter(|r| !r.is_pending_row() && live.contains(r.id.as_str())) {
        let id = row.id.as_str();
        if terminate_again(row) || (row.status != RowStatus::Terminated && row.egress_gate.as_deref() == Some(GATE_MISMATCH)) {
            match request_terminate(api, paths, id, "policy").await {
                Ok(recorded) => {
                    if let Err(e) = recorded {
                        tracing::warn!("gc: vm row {id}: the policy termination not recorded: {e}");
                    }
                    report.terminated += 1;
                    done.insert(id.to_string());
                }
                Err(e) => {
                    // A VM known to have failed the gate is still running: a policy failure (exit 9), not only an AWS one.
                    report.mismatches += 1;
                    report.errors.push(format!("egress-gate {id} → terminate: {e}"));
                }
            }
            continue;
        }
        if row.status == RowStatus::Terminated || row.egress_gate.as_deref() == Some(GATE_PASSED) {
            continue;
        }
        let vm = match api.get(id).await {
            Ok(vm) if vm.state.is_terminal() => continue,
            // Still booting without an echo (a run's own gate may be waiting for it): the next gc judges it.
            Ok(vm) if vm.state == VmState::Pending && vm.egress.is_empty() => continue,
            Ok(vm) => vm,
            Err(BridgeError::VmNotFound(_)) => continue,
            Err(e) => {
                report.errors.push(format!("egress-gate {id} → get: {e}"));
                continue;
            }
        };
        let (expected, alias) = row_gate(paths, row);
        if echo_passes(expected.as_ref(), &vm.egress, alias.as_ref()) {
            let echo: Vec<String> = expected.as_ref().map(|e| e.connectors().to_vec()).unwrap_or_default();
            if let Err(e) = registry::update_row(paths, id, |r| {
                r.egress_connectors.clone_from(&echo);
                r.egress_gate = Some(GATE_PASSED.to_string());
            }) {
                report.errors.push(format!("egress-gate {id} → record passed: {e}"));
            }
            continue;
        }
        let error = reject_echo(api, paths, id, expected.as_ref(), &vm.egress, "gc", "gc").await;
        report.mismatches += 1;
        if matches!(&error, BridgeError::EgressMismatch(m) if m.terminated) {
            report.terminated += 1;
            done.insert(id.to_string());
        }
        report.errors.push(format!("egress-gate {id} → terminate: {error}"));
    }
    done
}

// ---- gc --------------------------------------------------------------------------------

/// `ai-env vm gc` (plan S4 D17): survey, probe `/health` of the row-less
/// RUNNING VMs when `opts.probe_health`, [`classify`], and — only with
/// `opts.yes` — act: `terminate` via [`terminate_and_record`] (`gc-expired` /
/// `gc-orphan`), `mark-terminated` rows of VMs that are gone, `adopt` pending
/// rows, `remove-row` stale pending and old terminated rows, then audit
/// `vm_gc` with the counts. First, with `opts.yes`, the S5 egress gate
/// again ([`regate`]: every live row whose gate did not pass). An adoption
/// whose VM fails the gate is never adopted: the VM is terminated (`policy`;
/// counted in `terminated` once confirmed) and the `EgressMismatch` is one of
/// [`GcReport::errors`] (and of [`GcReport::mismatches`]). A failed action is
/// recorded in [`GcReport::errors`] and the others still run. Without
/// `opts.yes` nothing is written.
pub async fn gc<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, image_arn: &str, opts: &GcOpts) -> Result<GcReport, BridgeError> {
    gc_syncing(api, ep, paths, image_arn, opts, |_| async { Vec::new() }).await
}

/// [`gc`] with `sync_first` run before each VM it terminates (S9: the VM's
/// sessions' transcripts to S3, `s3::commands::sync_before_terminate`), its
/// warnings recorded in [`GcReport::errors`]; never a refusal of the
/// termination.
pub async fn gc_syncing<A: MicrovmApi, E: EndpointClient, F, Fut>(api: &A, ep: &E, paths: &Paths, image_arn: &str, opts: &GcOpts, sync_first: F) -> Result<GcReport, BridgeError>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    let (healths, infos) = if opts.probe_health { probe_rowless(api, ep, &listing, &rows).await } else { Default::default() };
    let now = unix_now();
    let items = classify_surveyed(&listing, &rows, &healths, now, &owner(), opts, &unsurveyed);
    let mut report = GcReport { items, ..GcReport::default() };
    if !opts.yes {
        return Ok(report);
    }
    let regated = regate(api, paths, &listing, &rows, &mut report).await;
    let by_stem: BTreeMap<String, &VmRow> = rows.iter().map(|r| (r.stem(), r)).collect();
    let row_of = |item: &GcItem| item.stem.as_ref().and_then(|s| by_stem.get(s).copied());
    for item in report.items.clone() {
        let id = item.id.clone().unwrap_or_default();
        let outcome: Result<(), BridgeError> = match item.action {
            GcAction::Keep | GcAction::Report => continue,
            // The egress gate terminated it already.
            GcAction::Terminate if regated.contains(&id) => continue,
            GcAction::Terminate => {
                let by = if item.class == GcClass::OrphanMine { "gc-orphan" } else { "gc-expired" };
                report.errors.extend(sync_first(id.clone()).await);
                terminate_and_record(api, paths, &id, by, None).await.map(|_| report.terminated += 1)
            }
            GcAction::MarkTerminated => match row_of(&item) {
                Some(row) => mark_gone(paths, &row.id, now).map(|()| report.marked += 1),
                None => Err(BridgeError::Config(format!("gc: no row for {id}"))),
            },
            GcAction::Adopt => match (row_of(&item), infos.get(&id)) {
                (Some(pending), Some(vm)) => match adopt_pending(api, paths, pending, vm).await {
                    Ok(_) => {
                        report.adopted += 1;
                        Ok(())
                    }
                    // The S5 egress gate: never adopted; a VM it terminated counts as terminated.
                    Err(e) => {
                        if let BridgeError::EgressMismatch(m) = &e {
                            report.mismatches += 1;
                            report.terminated += usize::from(m.terminated);
                        }
                        Err(e)
                    }
                },
                _ => Err(BridgeError::Config(format!("gc: cannot adopt {id}: its pending row or GetMicrovm answer is missing"))),
            },
            GcAction::RemoveRow => match row_of(&item) {
                Some(row) => registry::remove_row(paths, row).map(|_| report.removed += 1),
                None => Err(BridgeError::Config(format!("gc: no row {}", item.stem.clone().unwrap_or_default()))),
            },
        };
        if let Err(e) = outcome {
            let what = item.id.clone().or_else(|| item.stem.clone()).unwrap_or_default();
            report.errors.push(format!("{} {what} → {}: {e}", item.class.name(), item.action.name()));
        }
    }
    let orphans = opts.include_orphans.map_or_else(|| "-".to_string(), |d| d.as_secs().to_string());
    audit_event(
        paths,
        "vm_gc",
        &[
            ("terminated", report.terminated.to_string()),
            ("adopted", report.adopted.to_string()),
            ("removed", report.removed.to_string()),
            ("marked", report.marked.to_string()),
            ("errors", report.errors.len().to_string()),
            ("include_orphans_s", orphans),
        ],
    );
    Ok(report)
}

/// The row of a VM the platform ended (`registry:gone`) says so: terminated
/// at `now`, `terminated_by` `platform` unless it names who (`vm gc --yes`,
/// and S10's reconcile, which terminates nothing). Under the rows lock: what
/// another process wrote meanwhile is kept.
fn mark_gone(paths: &Paths, id: &str, now: u64) -> Result<(), BridgeError> {
    registry::update_row(paths, id, |r| {
        r.status = RowStatus::Terminated;
        r.terminated_at.get_or_insert(now);
        r.terminated_by.get_or_insert_with(|| "platform".to_string());
        r.state_seen = Some(VmState::Terminated.as_str().to_string());
        r.state_seen_at = Some(now);
    })
    .and_then(|written| written.map(|_| ()).ok_or_else(|| BridgeError::Config(format!("gc: row {id} vanished"))))
}

/// The opportunistic reconcile of `vm run|list|smoke` (plan S4 D17): the
/// survey and [`classify`] without `/health` probes and without acting
/// (every action `Report`), for [`hint_line`].
pub async fn reconcile_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str) -> Result<Vec<GcItem>, BridgeError> {
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    Ok(classify_surveyed(&listing, &rows, &BTreeMap::new(), unix_now(), &owner(), &GcOpts::default(), &unsurveyed))
}

/// S10 (L12): `vm run|list|smoke`'s reconcile: [`reconcile_apply_local`]
/// whatever `state/gc.stamp` says, then the items it left, for
/// [`hint_line`]. While another process reconciles (or when the apply
/// failed, which is a log line), the survey alone ([`reconcile_local`]).
pub async fn reconcile_applied<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str) -> Result<Vec<GcItem>, BridgeError> {
    match apply_local(api, paths, image_arn, None).await {
        Ok(Some((_, items))) => Ok(items),
        Ok(None) => reconcile_local(api, paths, image_arn).await,
        Err(e) => {
            tracing::warn!("gc reconcile: {e}");
            reconcile_local(api, paths, image_arn).await
        }
    }
}

/// [`reconcile_apply_local`]'s body: the report, and every item it did not
/// act on (an action that failed is kept, logged).
async fn apply_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str, every: Option<Duration>) -> Result<Option<(ReconcileReport, Vec<GcItem>)>, BridgeError> {
    let started = std::time::Instant::now();
    let Some(_held) = crate::bridge::vm::lock::try_lock_exclusive(&paths.gc_lock())? else {
        tracing::debug!("gc reconcile: another process holds {}", paths.gc_lock().display());
        return Ok(None);
    };
    let now = unix_now();
    if let Some(age) = every.and_then(|every| read_stamp(paths).and_then(|at| now.checked_sub(at)).filter(|age| *age < every.as_secs())) {
        tracing::debug!("gc reconcile: the last one ran {age} s ago");
        return Ok(None);
    }
    // The attempt is stamped, not the success: a survey that fails (a throttled or unreachable API) waits its
    // interval too, so wrapper starts never pile ListMicrovms on an API that does not answer.
    write_stamp(paths, now);
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    let by_stem: BTreeMap<String, &VmRow> = rows.iter().map(|r| (r.stem(), r)).collect();
    let mut report = ReconcileReport::default();
    let mut left = Vec::new();
    for item in classify_surveyed(&listing, &rows, &BTreeMap::new(), now, &owner(), &GcOpts::default(), &unsurveyed) {
        let row = item.stem.as_ref().and_then(|s| by_stem.get(s).copied());
        let done = match (item.class, row) {
            (GcClass::RegistryGone, Some(row)) => mark_gone(paths, &row.id, now).map(|()| report.marked += 1),
            (GcClass::TerminatedOld, Some(row)) => registry::remove_row(paths, row).map(|_| report.removed += 1),
            _ => {
                left.push(item);
                continue;
            }
        };
        if let Err(e) = done {
            tracing::warn!("gc reconcile: {} {}: {e}", item.class.name(), item.id.as_deref().unwrap_or_default());
            left.push(item);
        }
    }
    report.closed = close_dead_sessions(api, paths, &listing, &|row| crate::bridge::registry::confirm_wrapper(row, row.pid).is_ok()).await;
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(marked = report.marked, removed = report.removed, closed = report.closed, ms, "gc reconcile");
    audit_event(
        paths,
        crate::bridge::remote::audit_event::VM_GC_RECONCILE,
        &[("marked", report.marked.to_string()), ("removed", report.removed.to_string()), ("closed", report.closed.to_string()), ("ms", ms.to_string())],
    );
    Ok(Some((report, left)))
}

/// Session rows a dead wrapper left open on a VM that is gone become
/// `closed` (S10 L12): a row is closed only when no live VM of the survey
/// is its VM and its VM row says terminated (with no row, GetMicrovm says
/// gone), its wrapper is dead (`wrapper_lives` says no: the reconcile's is
/// `registry::confirm_wrapper`) and no offline `session migrate` holds it;
/// and only if the row read again just before is the one judged (a wrapper
/// that took it meanwhile keeps it). What fails is a log line; the count is
/// what was closed.
async fn close_dead_sessions<A: MicrovmApi>(api: &A, paths: &Paths, listing: &[VmSummary], wrapper_lives: &(dyn Fn(&crate::bridge::registry::SessionRow) -> bool + Sync)) -> u32 {
    use crate::bridge::registry::pid_alive;
    let live: BTreeSet<&str> = listing.iter().filter(|s| !s.state.is_terminal()).map(|s| s.id.as_str()).collect();
    let sessions = match crate::bridge::registry::list(paths) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("gc reconcile: the session rows: {e}");
            return 0;
        }
    };
    let mut closed = 0;
    for row in sessions {
        let Some(vm) = row.microvm_id.as_deref().filter(|vm| row.status != "closed" && !live.contains(vm)) else { continue };
        if row.migrating_pid.is_some_and(pid_alive) || wrapper_lives(&row) || !vm_gone(api, paths, vm).await {
            continue;
        }
        match close_row(paths, &row) {
            Ok(true) => {
                tracing::info!("gc reconcile: session {} closed (its VM {vm} is gone, and its wrapper pid {} too)", row.session_id, row.pid);
                closed += 1;
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("gc reconcile: session {}: {e}", row.session_id),
        }
    }
    closed
}

/// Is `id`, which no live VM of the survey is, gone: its row terminated,
/// or (with no row) GetMicrovm says NotFound or terminal? Anything unsure is no.
async fn vm_gone<A: MicrovmApi>(api: &A, paths: &Paths, id: &str) -> bool {
    match registry::read_row(paths, id) {
        Ok(Some(row)) => row.status == RowStatus::Terminated,
        Ok(None) => match api.get(id).await {
            Ok(vm) => vm.state.is_terminal(),
            Err(e) => matches!(e, BridgeError::VmNotFound(_)),
        },
        Err(e) => {
            tracing::warn!("gc reconcile: vm row {id}: {e}");
            false
        }
    }
}

/// `seen` written again `closed`, when its file still holds the row judged
/// (the same wrapper, status, VM and creation); whether it was.
fn close_row(paths: &Paths, seen: &crate::bridge::registry::SessionRow) -> Result<bool, BridgeError> {
    let Some(mut row) = crate::bridge::registry::read(paths, &seen.session_id)? else { return Ok(false) };
    if (row.pid, &row.status, &row.microvm_id, &row.created) != (seen.pid, &seen.status, &seen.microvm_id, &seen.created) {
        return Ok(false);
    }
    row.status = "closed".into();
    crate::bridge::registry::write(paths, &row)?;
    Ok(true)
}

/// The last reconcile's unix seconds (`state/gc.stamp`); `None` without one,
/// or when it does not read as one.
fn read_stamp(paths: &Paths) -> Option<u64> {
    crate::bridge::registry::read_regular_file(&paths.gc_stamp()).ok().flatten()?.trim().parse().ok()
}

/// `state/gc.stamp` says `now` (0600, never through a symlink, and never
/// waiting on a FIFO put there: `O_NONBLOCK` makes its open fail at once,
/// while the lock is held); a failure is a log line.
fn write_stamp(paths: &Paths, now: u64) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = paths.gc_stamp();
    let written = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&path).and_then(|mut f| writeln!(f, "{now}"));
    if let Err(e) = written {
        tracing::warn!("gc reconcile: {} not written: {e}", path.display());
    }
}

/// S10 (L12): a wrapper's reconcile runs at most this often (`state/gc.stamp`).
pub const GC_RECONCILE_EVERY: Duration = Duration::from_secs(15 * 60);
/// S10 (L12): generation 1 starts its reconcile this long after its `Started`.
pub const GC_RECONCILE_AFTER: Duration = Duration::from_secs(10);

/// What [`reconcile_apply_local`] did (S10): rows it marked terminated (the
/// platform ended their VM), terminated rows it removed, session rows it
/// closed (their VM gone, their wrapper dead).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub marked: u32,
    pub removed: u32,
    pub closed: u32,
}

/// S10 (L12): [`reconcile_local`]'s survey and [`classify`] with no
/// `/health` probe, then acted on locally: a `registry:gone` row marked
/// terminated (`terminated_by` `platform`), a `terminated-old` row removed,
/// a session row whose VM is gone and whose wrapper is dead closed; never
/// a terminate, never a Touch ID. `None` when `state/gc.lock` is held or
/// `state/gc.stamp` is younger than `every` (`vm run`, `vm list` and `vm
/// smoke` pass `None`: always, [`reconcile_applied`]). Each one that starts
/// stamps `state/gc.stamp`, failed or not (an API that does not answer is
/// asked again only past `every`), and each one that ran writes its
/// `vm_gc_reconcile` row (the counts, its ms).
pub async fn reconcile_apply_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str, every: Option<Duration>) -> Result<Option<ReconcileReport>, BridgeError> {
    Ok(apply_local(api, paths, image_arn, every).await?.map(|(report, _)| report))
}

/// One line for `vm run|list|smoke` when gc has something to look at
/// (every class but `registry:live` and `foreign`), e.g.
/// `vm gc: 1 registry:expired, 2 unprobed (run \`ai-env vm gc\`)`; `None`
/// when there is nothing.
#[must_use]
pub fn hint_line(items: &[GcItem]) -> Option<String> {
    let mut counts: BTreeMap<GcClass, usize> = BTreeMap::new();
    for item in items.iter().filter(|i| !matches!(i.class, GcClass::RegistryLive | GcClass::Foreign)) {
        *counts.entry(item.class).or_default() += 1;
    }
    if counts.is_empty() {
        return None;
    }
    let parts: Vec<String> = counts.iter().map(|(c, n)| format!("{n} {}", c.name())).collect();
    Some(format!("vm gc: {} (run `ai-env vm gc`)", parts.join(", ")))
}

/// `ai-env vm terminate --all` (plan S4 D29): the gc survey with `/health`
/// probes, reduced to what `--all` may touch. Every VM with a registry row
/// that is not gone (`registry:live`, `registry:expired`), every row-less VM
/// whose `/health` owner is this user@host (`orphan:mine`, and `adopt` —
/// a crashed run of ours) gets action `Terminate`; `foreign` and `unprobed`
/// VMs are returned with `Keep` so the caller can say what it skips (a
/// foreign VM needs its id and `--yes`). Nothing is written.
pub async fn terminate_all_plan<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, image_arn: &str) -> Result<Vec<GcItem>, BridgeError> {
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    let (healths, _) = probe_rowless(api, ep, &listing, &rows).await;
    let opts = GcOpts { yes: true, include_orphans: Some(Duration::ZERO), probe_health: true };
    Ok(classify_surveyed(&listing, &rows, &healths, unix_now(), &owner(), &opts, &unsurveyed)
        .into_iter()
        .filter_map(|mut item| {
            item.action = match item.class {
                GcClass::RegistryLive | GcClass::RegistryExpired | GcClass::OrphanMine | GcClass::Adopt => GcAction::Terminate,
                GcClass::Foreign | GcClass::Unprobed if item.id.is_some() => GcAction::Keep,
                // Rows without a VM (a pending row of an unlisted image included): nothing to terminate.
                GcClass::Foreign | GcClass::Unprobed | GcClass::RegistryGone | GcClass::PendingStale | GcClass::TerminatedOld => return None,
            };
            Some(item)
        })
        .collect())
}

/// `--include-orphans AGE`: a positive number with a unit, `90s`, `30m`,
/// `1h` or `2d`.
pub fn parse_age(s: &str) -> Result<Duration, String> {
    let t = s.trim();
    let bad = || format!("age {s:?}: expected a positive number with a unit, such as 90s, 30m, 1h or 2d");
    if !t.is_ascii() || t.len() < 2 {
        return Err(bad());
    }
    let (num, unit) = t.split_at(t.len() - 1);
    let unit_s: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(bad()),
    };
    if !num.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = num.parse().map_err(|_| bad())?;
    match n.checked_mul(unit_s) {
        Some(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_parse_with_units_only() {
        assert_eq!(parse_age("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_age("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_age(" 1h "), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_age("2d"), Ok(Duration::from_secs(172_800)));
        for bad in ["", "h", "0h", "90", "1.5h", "-1h", "+1h", "1w", "1 h", "é1h", "1hé"] {
            assert!(parse_age(bad).is_err(), "{bad:?}");
        }
        // Too large for u64 seconds: refused, never wrapped.
        let huge = format!("{}d", "9".repeat(20));
        let overflow = format!("{}d", u64::MAX / 86_400 + 1);
        for bad in [huge, overflow] {
            assert!(parse_age(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_are_the_table_spellings() {
        let names: Vec<&str> = GcClass::ALL.iter().map(GcClass::name).collect();
        assert_eq!(names, ["registry:live", "registry:expired", "registry:gone", "adopt", "orphan:mine", "foreign", "unprobed", "pending:stale", "terminated-old"]);
        assert_eq!(serde_json::to_value(GcClass::OrphanMine).unwrap(), "orphan:mine");
        assert_eq!(serde_json::to_value(GcAction::MarkTerminated).unwrap(), GcAction::MarkTerminated.name());
    }

    fn row(id: &str, status: RowStatus) -> VmRow {
        VmRow { id: id.into(), status, client_token: "01926f2e-0000-7000-8000-000000000001".into(), created: "2026-09-29T10:00:00.000Z".into(), max_duration_s: 3600, ..VmRow::default() }
    }

    fn vm(id: &str, state: VmState, started: i64) -> VmSummary {
        VmSummary { id: id.into(), state, image_arn: "arn".into(), image_version: "1.0".into(), started_at_unix: Some(started) }
    }

    #[test]
    fn expiry_margin_and_actions() {
        let now = 1_790_000_000u64;
        let mut near = row("microvm-near", RowStatus::Running);
        near.wall_deadline = Some(now + EXPIRY_MARGIN_S);
        let mut far = row("microvm-far", RowStatus::Running);
        far.wall_deadline = Some(now + EXPIRY_MARGIN_S + 1);
        let listing = [vm("microvm-near", VmState::Running, 1), vm("microvm-far", VmState::Suspended, 1)];
        let yes = GcOpts { yes: true, ..GcOpts::default() };
        let items = classify(&listing, &[near, far], &BTreeMap::new(), now, "me@h", &yes);
        assert_eq!(items.iter().map(|i| (i.class, i.action)).collect::<Vec<_>>(), [(GcClass::RegistryExpired, GcAction::Terminate), (GcClass::RegistryLive, GcAction::Keep)]);
        let dry = classify(&listing, &[], &BTreeMap::new(), now, "me@h", &GcOpts::default());
        assert!(dry.iter().all(|i| i.class == GcClass::Unprobed && i.action == GcAction::Report), "{dry:?}");
    }

    #[test]
    fn orphans_terminate_only_past_the_age() {
        let now = 1_790_000_000u64;
        let listing = [vm("microvm-old", VmState::Running, (now - 7200) as i64), vm("microvm-new", VmState::Running, (now - 60) as i64)];
        let mine = HealthProbe { owner: Some("me@h".into()), created: Some("2026-09-29T10:00:00.000Z".into()) };
        let healths: BTreeMap<String, HealthProbe> = [("microvm-old".to_string(), mine.clone()), ("microvm-new".to_string(), mine)].into_iter().collect();
        let opts = GcOpts { yes: true, include_orphans: Some(Duration::from_secs(3600)), probe_health: true };
        let items = classify(&listing, &[], &healths, now, "me@h", &opts);
        assert_eq!(items.iter().map(|i| (i.class, i.action)).collect::<Vec<_>>(), [(GcClass::OrphanMine, GcAction::Terminate), (GcClass::OrphanMine, GcAction::Keep)]);
        let keep = classify(&listing, &[], &healths, now, "me@h", &GcOpts { yes: true, ..GcOpts::default() });
        assert!(keep.iter().all(|i| i.action == GcAction::Keep));
    }

    #[test]
    fn hint_names_only_actionable_classes() {
        let item = |class| GcItem { class, id: None, stem: None, age_s: None, detail: String::new(), action: GcAction::Report };
        assert_eq!(hint_line(&[item(GcClass::RegistryLive), item(GcClass::Foreign)]), None);
        assert_eq!(hint_line(&[item(GcClass::PendingStale), item(GcClass::RegistryExpired), item(GcClass::PendingStale)]).unwrap(), "vm gc: 1 registry:expired, 2 pending:stale (run `ai-env vm gc`)");
    }

    /// S9: `vm gc --yes` runs `sync_first` (the VM's sessions' transcripts to
    /// S3) right before each VM it terminates, and records its warnings in
    /// the report, never refusing the termination; a dry run syncs nothing.
    #[tokio::test]
    async fn gc_syncs_each_vm_it_terminates_first() {
        use crate::bridge::api::{FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, FAKE_IMAGE_ARN};
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let api = FakeMicrovmApi::new();
        let created = crate::wire::time::rfc3339_utc(unix_now());
        let payload = crate::bridge::vm::run::build_payload(&crate::bridge::vm::run::new_session_token(), &owner(), &created).unwrap();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: Vec::new(),
            egress_connectors: Vec::new(),
            idle: IdleSpec { max_idle_s: 300, suspended_s: 3600, auto_resume: true },
            max_duration_s: 3600,
            run_hook_payload: payload,
            client_token: uuid::Uuid::now_v7().to_string(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        // Its gate passed (the egress re-gate leaves it alone), its wall about to pass: `registry:expired`, terminated.
        let row = VmRow { id: vm.id.clone(), status: RowStatus::Running, client_token: spec.client_token.clone(), image_arn: FAKE_IMAGE_ARN.into(), created, wall_deadline: Some(unix_now() + 30), egress_gate: Some(GATE_PASSED.into()), ..VmRow::default() };
        registry::write_row(&paths, &row).unwrap();
        let synced = std::sync::Mutex::new(Vec::new());
        let sync_first = |id: String| {
            synced.lock().unwrap().push(id.clone());
            async move { vec![format!("{id}: the transcript of a session was not synced before it ends")] }
        };
        let dry = gc_syncing(&api, &api, &paths, FAKE_IMAGE_ARN, &GcOpts { yes: false, include_orphans: None, probe_health: false }, sync_first).await.unwrap();
        assert!(synced.lock().unwrap().is_empty() && dry.terminated == 0, "a dry run syncs nothing");
        let report = gc_syncing(&api, &api, &paths, FAKE_IMAGE_ARN, &GcOpts { yes: true, include_orphans: None, probe_health: false }, sync_first).await.unwrap();
        assert_eq!((synced.lock().unwrap().clone(), report.terminated), (vec![vm.id.clone()], 1));
        assert_eq!(report.errors, [format!("{}: the transcript of a session was not synced before it ends", vm.id)], "the warning recorded, the termination done");
        assert_eq!(registry::read_row(&paths, &vm.id).unwrap().unwrap().status, RowStatus::Terminated);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod p_tests {
    use super::*;
    use crate::bridge::api::{Call, FakeMicrovmApi};
    use crate::bridge::registry::{self as sessions, SessionRow};

    fn listed(id: &str, state: VmState) -> VmSummary {
        VmSummary { id: id.into(), state, image_arn: "arn".into(), image_version: "1.0".into(), started_at_unix: Some(1) }
    }

    /// Session row `n` of `vm` (none: a local session) in `status`, its wrapper `pid`.
    fn session(n: u64, status: &str, vm: Option<&str>, pid: u32) -> SessionRow {
        SessionRow { session_id: format!("0192f1e0-0000-7000-8000-{n:012x}"), status: status.into(), mode: "remote".into(), pid, created: sessions::now_rfc3339(), microvm_id: vm.map(str::to_string), ..SessionRow::default() }
    }

    /// A pid no process has now (a child that ran and was reaped).
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// S10 L12: the reconcile closes a session row only when its VM is gone
    /// (no live VM of the survey, and its row terminated, or with no row
    /// GetMicrovm's NotFound), its wrapper is dead and no offline `session
    /// migrate` holds it. A live wrapper's row (the judge says so of pid
    /// 4242 here), a live VM's, one whose VM row still says it runs (an
    /// image the survey did not list), a closed one, a local one and a
    /// migrating one stay as they were; GetMicrovm is asked only of the VM
    /// no row names.
    #[tokio::test]
    async fn only_a_dead_wrappers_row_on_a_gone_vm_is_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let api = FakeMicrovmApi::new();
        let dead = dead_pid();
        for (id, status) in [("microvm-gone", RowStatus::Terminated), ("microvm-live", RowStatus::Running), ("microvm-unseen", RowStatus::Running)] {
            registry::write_row(&paths, &VmRow { id: id.into(), status, client_token: "0192f1e0-0000-7000-8000-0000000000c1".into(), ..VmRow::default() }).unwrap();
        }
        let rows = [
            session(1, "active", Some("microvm-gone"), dead),
            session(2, "parked", Some("microvm-gone"), 4242),
            session(3, "detached", Some("microvm-live"), dead),
            session(4, "closed", Some("microvm-gone"), dead),
            session(5, "active", None, dead),
            SessionRow { migrating_pid: Some(std::process::id()), ..session(6, "migrating", Some("microvm-gone"), dead) },
            session(7, "active", Some("microvm-nowhere"), dead),
            session(8, "parked", Some("microvm-unseen"), dead),
        ];
        for r in &rows {
            sessions::write(&paths, r).unwrap();
        }
        let listing = [listed("microvm-live", VmState::Suspended), listed("microvm-gone", VmState::Terminated)];
        let closed = close_dead_sessions(&api, &paths, &listing, &|r| r.pid == 4242).await;
        let status: Vec<String> = rows.iter().map(|r| sessions::read(&paths, &r.session_id).unwrap().unwrap().status).collect();
        assert_eq!(status, ["closed", "parked", "detached", "closed", "active", "migrating", "closed", "parked"]);
        assert_eq!(closed, 2);
        assert_eq!(api.calls(), [Call::Get("microvm-nowhere".into())], "GetMicrovm only of the VM no row names");
        let kept = sessions::read(&paths, &rows[0].session_id).unwrap().unwrap();
        assert_eq!(kept, SessionRow { status: "closed".into(), ..rows[0].clone() }, "only its status changed");
    }

    /// The row closed is the row judged: one its wrapper wrote again
    /// meanwhile (another pid: a reopen) is left as that wrapper wrote it.
    #[test]
    fn a_row_written_again_meanwhile_is_not_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        let judged = session(1, "parked", Some("microvm-gone"), 77);
        let reopened = SessionRow { pid: 78, status: "active".into(), ..judged.clone() };
        sessions::write(&paths, &reopened).unwrap();
        assert!(!close_row(&paths, &judged).unwrap());
        assert_eq!(sessions::read(&paths, &judged.session_id).unwrap().unwrap(), reopened);
        assert!(close_row(&paths, &reopened).unwrap());
        assert_eq!(sessions::read(&paths, &judged.session_id).unwrap().unwrap().status, "closed");
        assert!(!close_row(&paths, &session(2, "active", Some("microvm-gone"), 77)).unwrap(), "no row: nothing to close");
    }

    /// `state/gc.stamp`: none until a reconcile wrote one, then its unix
    /// seconds, 0600; never read or written through a symlink, and a FIFO
    /// put in its place blocks neither (the reconcile holds `state/gc.lock`
    /// meanwhile).
    #[test]
    fn the_stamp_is_private_and_never_followed() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        std::fs::create_dir_all(paths.root.join("state")).unwrap();
        assert_eq!(read_stamp(&paths), None);
        write_stamp(&paths, 1_790_000_000);
        assert_eq!(read_stamp(&paths), Some(1_790_000_000));
        assert_eq!(std::fs::metadata(paths.gc_stamp()).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(paths.gc_stamp(), "not a number\n").unwrap();
        assert_eq!(read_stamp(&paths), None, "an unreadable stamp is none: the reconcile runs");
        std::fs::remove_file(paths.gc_stamp()).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, "1790000000\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, paths.gc_stamp()).unwrap();
        assert_eq!(read_stamp(&paths), None, "not read through a symlink");
        write_stamp(&paths, 5);
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "1790000000\n", "not written through a symlink");
        std::fs::remove_file(paths.gc_stamp()).unwrap();
        let fifo = std::ffi::CString::new(paths.gc_stamp().into_os_string().into_vec()).unwrap();
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(read_stamp(&paths), None, "a FIFO is no stamp");
        // In a thread of its own: a write that waited for the FIFO's reader would never come back.
        let (done, wrote) = std::sync::mpsc::channel();
        let stamp_paths = paths.clone();
        std::thread::spawn(move || {
            write_stamp(&stamp_paths, 5);
            let _ = done.send(());
        });
        assert!(wrote.recv_timeout(std::time::Duration::from_secs(5)).is_ok(), "writing the stamp waited on a FIFO");
        assert!(std::fs::symlink_metadata(paths.gc_stamp()).unwrap().file_type().is_fifo(), "left as it was");
    }
}
