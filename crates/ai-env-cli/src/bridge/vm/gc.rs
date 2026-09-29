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
//! [`reconcile_local`] is the opportunistic variant for `vm run|list|smoke`
//! (no probes, no action, one hint line); [`terminate_all_plan`] is the
//! survey behind `vm terminate --all` (D29).
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState, VmSummary};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::owner;
use crate::bridge::vm::registry::{self, RowStatus, VmRow, PENDING_STALE_S, TERMINATED_KEEP_S};
use crate::bridge::vm::run::{adopt_pending, audit_event, created_unix, probe_health_once, terminate_and_record, START_SKEW_S};
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
                match deadline {
                    Some(d) if d <= now.saturating_add(EXPIRY_MARGIN_S) => {
                        let when = if d <= now { format!("wall passed {} s ago", now - d) } else { format!("wall in {} s", d - now) };
                        push(GcClass::RegistryExpired, Some(row.id.clone()), Some(row.stem()), age, format!("{} {when}{stale_row}", s.state.as_str()));
                    }
                    Some(d) => push(GcClass::RegistryLive, Some(row.id.clone()), Some(row.stem()), age, format!("{} wall left {} s{stale_row}", s.state.as_str(), d - now)),
                    None => push(GcClass::RegistryLive, Some(row.id.clone()), Some(row.stem()), age, format!("{} wall unknown{stale_row}", s.state.as_str())),
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
/// row or a non-terminated id row names (a crashed `vm run --image OTHER`
/// must be adoptable; a failure there is logged and the image recorded as
/// unsurveyed, never fatal), then `GetMicrovm` of every non-terminated id row
/// the listings missed (NotFound leaves it out: `registry:gone`), and every row.
async fn survey_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str) -> Result<Survey, BridgeError> {
    let mut listing = api.list(Some(image_arn)).await?;
    let rows = registry::list_rows(paths)?;
    let others: BTreeSet<&str> = rows.iter().filter(|r| r.is_pending_row() || r.status != RowStatus::Terminated).map(|r| r.image_arn.as_str()).filter(|a| !a.is_empty() && *a != image_arn).collect();
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

// ---- gc --------------------------------------------------------------------------------

/// `ai-env vm gc` (plan S4 D17): survey, probe `/health` of the row-less
/// RUNNING VMs when `opts.probe_health`, [`classify`], and — only with
/// `opts.yes` — act: `terminate` via [`terminate_and_record`] (`gc-expired` /
/// `gc-orphan`), `mark-terminated` rows of VMs that are gone, `adopt` pending
/// rows, `remove-row` stale pending and old terminated rows, then audit
/// `vm_gc` with the counts. A failed action is recorded in
/// [`GcReport::errors`] and the others still run. Without `opts.yes` nothing
/// is written.
pub async fn gc<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, image_arn: &str, opts: &GcOpts) -> Result<GcReport, BridgeError> {
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    let (healths, infos) = if opts.probe_health { probe_rowless(api, ep, &listing, &rows).await } else { Default::default() };
    let now = unix_now();
    let items = classify_surveyed(&listing, &rows, &healths, now, &owner(), opts, &unsurveyed);
    let mut report = GcReport { items, ..GcReport::default() };
    if !opts.yes {
        return Ok(report);
    }
    let by_stem: BTreeMap<String, &VmRow> = rows.iter().map(|r| (r.stem(), r)).collect();
    let row_of = |item: &GcItem| item.stem.as_ref().and_then(|s| by_stem.get(s).copied());
    for item in report.items.clone() {
        let id = item.id.clone().unwrap_or_default();
        let outcome: Result<(), BridgeError> = match item.action {
            GcAction::Keep | GcAction::Report => continue,
            GcAction::Terminate => {
                let by = if item.class == GcClass::OrphanMine { "gc-orphan" } else { "gc-expired" };
                terminate_and_record(api, paths, &id, by, None).await.map(|_| report.terminated += 1)
            }
            GcAction::MarkTerminated => match row_of(&item) {
                // Under the rows lock: what another process wrote meanwhile is kept.
                Some(row) => registry::update_row(paths, &row.id, |r| {
                    r.status = RowStatus::Terminated;
                    r.terminated_at.get_or_insert(now);
                    r.terminated_by.get_or_insert_with(|| "platform".to_string());
                    r.state_seen = Some(VmState::Terminated.as_str().to_string());
                    r.state_seen_at = Some(now);
                })
                .and_then(|written| written.map(|_| report.marked += 1).ok_or_else(|| BridgeError::Config(format!("gc: row {id} vanished")))),
                None => Err(BridgeError::Config(format!("gc: no row for {id}"))),
            },
            GcAction::Adopt => match (row_of(&item), infos.get(&id)) {
                (Some(pending), Some(vm)) => adopt_pending(paths, pending, vm).map(|_| report.adopted += 1),
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

/// The opportunistic reconcile of `vm run|list|smoke` (plan S4 D17): the
/// survey and [`classify`] without `/health` probes and without acting
/// (every action `Report`), for [`hint_line`].
pub async fn reconcile_local<A: MicrovmApi>(api: &A, paths: &Paths, image_arn: &str) -> Result<Vec<GcItem>, BridgeError> {
    let Survey { listing, rows, unsurveyed } = survey_local(api, paths, image_arn).await?;
    Ok(classify_surveyed(&listing, &rows, &BTreeMap::new(), unix_now(), &owner(), &GcOpts::default(), &unsurveyed))
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
}
