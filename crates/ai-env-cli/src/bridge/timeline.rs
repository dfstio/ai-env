//! S11 (B.3): each VM's running and suspended stretches over a window,
//! rebuilt from the audit (`audit::read`), the VM rows and `[vm]`, with the
//! idle suspends the platform made inferred (the cost estimate's and the
//! views' input). Phase 0 declared it; S11 wave 1's B2 built it.
use crate::bridge::audit::read::Read;
use crate::bridge::audit::schema::{self, event, Effect, When};
use crate::bridge::vm::registry::{RowStatus, VmRow};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Running,
    Suspended,
}

/// One stretch of one VM, `[from, to)` in unix seconds, clipped to the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interval {
    pub phase: Phase,
    pub from: u64,
    pub to: u64,
    /// Its end was inferred (rule 1 or 3); then `low` and `high` bound it (rule 5), else both equal `to`.
    pub inferred: bool,
    pub low: u64,
    pub high: u64,
    /// The events that opened and closed it (`-` for an inferred end).
    pub opened_by: String,
    pub closed_by: String,
}

/// One VM over the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmTimeline {
    pub vm: String,
    pub memory_mib: u32,
    pub max_idle_s: u32,
    pub suspended_s: Option<u32>,
    pub max_duration_s: u32,
    pub intervals: Vec<Interval>,
    /// Counted inside the window (an inferred event at its inferred time).
    pub starts: u32,
    pub resumes: u32,
    pub suspends: u32,
    pub inferred_suspends: u32,
    pub inferred_resumes: u32,
    /// How it ended: `terminated (<by>)`, `wall`, `suspended_s`, or `None` while it lives.
    pub end: Option<String>,
    pub anomalies: u32,
}

/// The proxy's running stretches; `assumed`: no `proxy_start` or `proxy_stop` row before or in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxySpans {
    pub running: Vec<(u64, u64)>,
    pub assumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Timeline {
    pub since: u64,
    pub until: u64,
    pub vms: Vec<VmTimeline>,
    pub proxy: ProxySpans,
    /// VMs rows name with neither start evidence nor a VM row: listed, never priced.
    pub not_counted: Vec<String>,
    /// Rows shown raw only (unknown event, `v` above 2) that were skipped.
    pub skipped: u64,
}

/// The `[vm]` values for a VM whose `vm_run` lacks S11's keys and whose row lacks the echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmDefaults {
    pub memory_mib: u32,
    pub max_idle_s: u32,
    pub suspended_s: Option<u32>,
    pub max_duration_s: u32,
}

impl VmDefaults {
    #[must_use]
    pub fn from_cfg(cfg: &crate::bridge::config::VmCfg) -> VmDefaults {
        VmDefaults { memory_mib: cfg.memory_mib, max_idle_s: cfg.max_idle_s, suspended_s: cfg.suspended_s, max_duration_s: cfg.max_duration_s }
    }
}

/// The timeline of `[since, until)` from every row (read before `since` too: a state carries in; rows after
/// `until` too, so an inferred end may be capped by later evidence). Per VM (the first of a row's `vms`), its
/// rows in time order (file order for equal times) through the registry's effects (B §B3.2's rules).
#[must_use]
pub fn build(rows: &[Read], vm_rows: &[VmRow], defaults: VmDefaults, since: u64, until: u64) -> Timeline {
    let mut by_vm: BTreeMap<&str, Vec<(&Read, Vec<Effect>)>> = BTreeMap::new();
    let mut proxy: Vec<(u64, bool)> = Vec::new();
    let mut skipped = 0u64;
    let inside = |at: u64| at >= since && at < until;
    for r in rows {
        if !r.known {
            skipped += u64::from(inside(r.at));
            continue;
        }
        let effects = effects_of(r);
        if effects.contains(&Effect::ProxyStart) || effects.contains(&Effect::ProxyStop) {
            proxy.push((r.at, effects.contains(&Effect::ProxyStart)));
        }
        if let Some(vm) = r.vms.first() {
            by_vm.entry(vm.as_str()).or_default().push((r, effects));
        }
    }
    let row_of: BTreeMap<&str, &VmRow> = vm_rows.iter().filter(|r| !r.is_pending_row()).map(|r| (r.id.as_str(), r)).collect();
    let mut ids: BTreeSet<&str> = by_vm.keys().copied().collect();
    ids.extend(row_of.keys().copied());
    let mut vms = Vec::new();
    let mut not_counted = BTreeSet::new();
    for id in ids {
        let evs = by_vm.get(id).map_or(&[][..], Vec::as_slice);
        let row = row_of.get(id).copied();
        let has_start = evs.iter().any(|(_, e)| e.contains(&Effect::Start));
        if !has_start && row.is_none() {
            if evs.iter().any(|(r, _)| inside(r.at)) {
                not_counted.insert(id.to_string());
            }
            continue;
        }
        let mut m = Machine::new(id, params(evs, row, defaults), row);
        // At equal times (the sort is stable): the row's start, the audit's rows, then the row's end.
        let mut items: Vec<(u64, Item<'_>)> = Vec::new();
        if !has_start {
            let Some(at) = row.and_then(|r| r.started_at).or_else(|| evs.first().map(|(r, _)| r.at)) else { continue };
            items.push((at, Item::RowStart));
        }
        // Only rows with an effect step the machine: one with none (`egress_check`, `credential_gate`, …) is no
        // evidence, so it never caps an inferred suspend's range (rule 8).
        items.extend(evs.iter().filter(|(_, e)| !e.is_empty()).map(|(r, e)| (r.at, Item::Row(r, e))));
        if let Some(r) = row.filter(|r| r.status == RowStatus::Terminated) {
            if let Some(at) = r.terminated_at {
                items.push((at, Item::RowEnd(r.terminated_by.clone().unwrap_or_else(|| "platform".into()))));
            }
        }
        items.sort_by_key(|(at, _)| *at);
        let mut last_t = 0;
        for (at, item) in &items {
            m.advance(*at);
            match item {
                Item::RowStart => m.start(*at, "row"),
                Item::RowEnd(by) => m.terminate(*at, "row", &format!("terminated ({by})")),
                Item::Row(r, e) => m.on(r, e),
            }
            last_t = last_t.max(*at);
        }
        let end_t = until.max(last_t);
        m.advance(end_t);
        m.close_open(end_t);
        if let Some(t) = m.clip(since, until) {
            vms.push(t);
        }
    }
    vms.sort_by(|a, b| (a.intervals.first().map(|i| i.from), &a.vm).cmp(&(b.intervals.first().map(|i| i.from), &b.vm)));
    Timeline { since, until, vms, proxy: proxy_spans(&proxy, since, until), not_counted: not_counted.into_iter().collect(), skipped }
}

/// The effects of a row that apply to it (`When` against its detail).
#[must_use]
pub fn effects_of(r: &Read) -> Vec<Effect> {
    schema::spec(&r.event).map(|s| s.effects.iter().filter(|e| applies(e.when, &r.detail)).map(|e| e.effect).collect()).unwrap_or_default()
}

fn applies(when: When, d: &BTreeMap<String, String>) -> bool {
    match when {
        When::Always => true,
        When::Is { key, value } => d.get(key).is_some_and(|v| v == value),
        When::IsOrAbsent { key, value } => d.get(key).is_none_or(|v| v == value),
    }
}

/// Is `event` one that starts a VM (or the VM row's own start, `row`)? The views count such an opening as a start.
#[must_use]
pub fn is_start(event: &str) -> bool {
    event == "row" || schema::spec(event).is_some_and(|s| s.effects.iter().any(|e| e.effect == Effect::Start))
}

/// The proxy's running stretches inside `[since, until)` (rule 10).
fn proxy_spans(rows: &[(u64, bool)], since: u64, until: u64) -> ProxySpans {
    let mut rows = rows.to_vec();
    rows.sort_by_key(|(at, _)| *at);
    if !rows.iter().any(|(at, _)| *at < until) {
        return ProxySpans { running: if since < until { vec![(since, until)] } else { Vec::new() }, assumed: true };
    }
    // Its state at `since`: the last row before it; with none before, what the window's first row implies.
    let mut on = match rows.iter().rev().find(|(at, _)| *at < since) {
        Some((_, start)) => *start,
        None => rows.iter().find(|(at, _)| *at >= since && *at < until).is_some_and(|(_, start)| !start),
    };
    let mut from = since;
    let mut running = Vec::new();
    for (at, start) in rows.iter().filter(|(at, _)| *at >= since && *at < until) {
        if *start && !on {
            on = true;
            from = *at;
        } else if !*start && on {
            on = false;
            if *at > from {
                running.push((from, *at));
            }
        }
    }
    if on && until > from {
        running.push((from, until));
    }
    ProxySpans { running, assumed: false }
}

/// A VM's parameters (rule 1): its newest `vm_run` or `vm_adopt` row's, else its VM row's, else `[vm]`'s.
fn params(evs: &[(&Read, Vec<Effect>)], row: Option<&VmRow>, d: VmDefaults) -> VmDefaults {
    let run = evs.iter().rev().map(|(r, _)| *r).find(|r| r.event == event::VM_RUN || r.event == event::VM_ADOPT);
    let num = |k: &str| run.and_then(|r| r.detail.get(k)).and_then(|v| v.parse::<u32>().ok()).filter(|n| *n > 0);
    let idle = row.and_then(|r| r.idle.as_ref());
    VmDefaults {
        memory_mib: num("memory_mib").unwrap_or(d.memory_mib),
        max_idle_s: num("max_idle_s").or(idle.map(|i| i.max_idle_s).filter(|n| *n > 0)).unwrap_or(d.max_idle_s),
        suspended_s: num("suspended_s").or(idle.map(|i| i.suspended_s).filter(|n| *n > 0)).or(d.suspended_s),
        max_duration_s: num("max_duration_s").or(row.map(|r| r.max_duration_s).filter(|n| *n > 0)).unwrap_or(d.max_duration_s),
    }
}

/// `VmTimeline.end` for rule 3's end: an inference, which later evidence of life may revive.
const END_SUSPENDED_S: &str = "suspended_s";

/// Two rows of one transition (the review's B-COST-1): a resume or a suspend at most this long after the hard
/// evidence of the same kind that opened the stretch is that transition's second record, no anomaly (as rule 3
/// takes a repeated terminate): `reuse_row`'s `vm_reuse{resumed=true}` and the pipeline's `vm_select{how=resumed}`
/// for one resume; each chat's `session_park{why=suspended}`, and a `vm suspend` beside them, for one suspend.
const SAME_TRANSITION_S: u64 = 120;

/// One step of a VM's sequence.
enum Item<'a> {
    /// The VM row's start (no start row in the audit).
    RowStart,
    /// The VM row's end (`terminated_at`, `terminated_by`).
    RowEnd(String),
    Row(&'a Read, &'a [Effect]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Absent,
    Running,
    Suspended,
    Ended,
}

/// One VM's state machine over its rows (unclipped).
struct Machine {
    vm: String,
    p: VmDefaults,
    row_start: Option<u64>,
    row_wall: Option<u64>,
    wall: u64,
    st: St,
    from: u64,
    opened_by: String,
    /// The open stretch was opened by hard evidence of its own kind: a resume row (not inferred) for a running
    /// one, a suspend row for a suspended one ([`SAME_TRANSITION_S`]).
    opened_hard: bool,
    last: u64,
    spans: BTreeSet<String>,
    raw: Vec<Interval>,
    starts: Vec<u64>,
    resumes: Vec<u64>,
    suspends: Vec<u64>,
    inferred_suspends: Vec<u64>,
    inferred_resumes: Vec<u64>,
    anomalies: Vec<u64>,
    end: Option<String>,
    /// When it ended (`ended`).
    ended_at: u64,
    /// The open suspended stretch's latest start: its inferred suspend's `high`, else its start.
    susp_high: u64,
    /// Rule 3's latest end the platform could have made: `susp_high` + `suspended_s`.
    latest_end: u64,
}

impl Machine {
    fn new(vm: &str, p: VmDefaults, row: Option<&VmRow>) -> Machine {
        Machine {
            vm: vm.to_string(),
            p,
            row_start: row.and_then(|r| r.started_at),
            row_wall: row.and_then(|r| r.wall_deadline),
            wall: u64::MAX,
            st: St::Absent,
            from: 0,
            opened_by: String::new(),
            opened_hard: false,
            last: 0,
            spans: BTreeSet::new(),
            raw: Vec::new(),
            starts: Vec::new(),
            resumes: Vec::new(),
            suspends: Vec::new(),
            inferred_suspends: Vec::new(),
            inferred_resumes: Vec::new(),
            anomalies: Vec::new(),
            end: None,
            ended_at: 0,
            susp_high: 0,
            latest_end: 0,
        }
    }

    /// Close the open stretch at `to` (a zero-length one leaves no interval).
    fn close(&mut self, to: u64, inferred: bool, low: u64, high: u64, closed_by: &str) {
        let phase = if self.st == St::Suspended { Phase::Suspended } else { Phase::Running };
        if to > self.from {
            self.raw.push(Interval { phase, from: self.from, to, inferred, low, high, opened_by: self.opened_by.clone(), closed_by: closed_by.to_string() });
        }
    }

    fn open(&mut self, st: St, at: u64, by: &str) {
        self.st = st;
        self.from = at;
        self.opened_by = by.to_string();
        self.opened_hard = false;
        if st == St::Running {
            self.last = at;
        }
    }

    fn ended(&mut self, at: u64, inferred: bool, closed_by: &str, end: &str) {
        self.close(at, inferred, at, at, closed_by);
        self.st = St::Ended;
        self.spans.clear();
        self.end = Some(end.to_string());
        self.ended_at = at;
    }

    /// Rule 3's end is an inference. Hard evidence of life after it (a resume, an observed RUNNING, a span's
    /// opening), or other activity before the latest end the platform could have made, proves it wrong (most
    /// likely its suspend came later than rule 1 put it): the suspended stretch it closed reopens, so the
    /// evidence applies as on a suspended VM. Hard evidence after any end, and every revival, is an anomaly
    /// (rule 4); other activity after a hard end is none (a respawn's move names the VM it leaves). `true`:
    /// revived.
    fn revive(&mut self, at: u64, hard: bool) -> bool {
        if self.st != St::Ended {
            return false;
        }
        let revived = self.end.as_deref() == Some(END_SUSPENDED_S) && at < self.wall && (hard || at < self.latest_end);
        if hard || revived {
            self.anomalies.push(at);
        }
        if !revived {
            return false;
        }
        let end_at = self.ended_at;
        match self.raw.pop_if(|iv| iv.phase == Phase::Suspended && iv.to == end_at && iv.closed_by == "-") {
            Some(iv) => {
                self.from = iv.from;
                self.opened_by = iv.opened_by;
            }
            // A zero-length stretch left no interval: it reopens at the end.
            None => {
                self.from = end_at;
                self.opened_by = "-".to_string();
            }
        }
        self.st = St::Suspended;
        self.opened_hard = false;
        self.end = None;
        true
    }

    /// Whether a hard `kind` row at `at` is a second record of the transition that opened the open stretch
    /// ([`SAME_TRANSITION_S`]).
    fn same_transition(&self, kind: St, at: u64) -> bool {
        self.st == kind && self.opened_hard && at.saturating_sub(self.from) <= SAME_TRANSITION_S
    }

    /// What happened before `t` with no row saying so: rule 1's idle suspends, rule 3's end, the wall (rule 7).
    fn advance(&mut self, t: u64) {
        let idle = u64::from(self.p.max_idle_s);
        loop {
            if self.st == St::Running && self.spans.is_empty() {
                let at = self.last.saturating_add(idle);
                if at < t && at < self.wall {
                    // Rule 5: low at the last activity, high at the next evidence or twice the idle time.
                    let high = t.min(self.last.saturating_add(2 * idle)).min(self.wall);
                    self.close(at, true, self.last, high, "-");
                    self.open(St::Suspended, at, "-");
                    self.susp_high = high;
                    self.inferred_suspends.push(at);
                    continue;
                }
            }
            if self.st == St::Suspended {
                if let Some(s) = self.p.suspended_s {
                    let at = self.from.saturating_add(u64::from(s));
                    if at <= t && at < self.wall {
                        self.latest_end = self.susp_high.max(self.from).saturating_add(u64::from(s));
                        self.ended(at, true, "-", END_SUSPENDED_S);
                        return;
                    }
                }
            }
            if matches!(self.st, St::Running | St::Suspended) && self.wall <= t {
                let wall = self.wall;
                self.ended(wall, false, "wall", "wall");
            }
            return;
        }
    }

    fn start(&mut self, at: u64, by: &str) {
        if self.st != St::Absent {
            self.anomalies.push(at);
            return;
        }
        let at = if by == "row" { at } else { self.row_start.unwrap_or(at) };
        self.wall = self.row_wall.unwrap_or_else(|| at.saturating_add(u64::from(self.p.max_duration_s)));
        self.open(St::Running, at, by);
        self.starts.push(at);
    }

    fn resume(&mut self, at: u64, by: &str, inferred: bool) {
        match self.st {
            St::Suspended => {
                self.close(at, false, at, at, by);
                self.open(St::Running, at, by);
                self.opened_hard = !inferred;
                if inferred { self.inferred_resumes.push(at) } else { self.resumes.push(at) }
            }
            St::Running => {
                // The same resume's second row is none (B-COST-1); any other resume of a running VM is.
                if inferred || !self.same_transition(St::Running, at) {
                    self.anomalies.push(at);
                }
                self.last = self.last.max(at);
            }
            St::Ended => self.revive_and_resume(at, by, true, inferred),
            St::Absent => {}
        }
    }

    /// [`Machine::revive`], then the resume on the reopened stretch.
    fn revive_and_resume(&mut self, at: u64, by: &str, hard: bool, inferred: bool) {
        if self.revive(at, hard) {
            self.resume(at, by, inferred);
        }
    }

    fn suspend(&mut self, at: u64, by: &str) {
        match self.st {
            St::Running => {
                self.close(at, false, at, at, by);
                self.open(St::Suspended, at, by);
                self.opened_hard = true;
                self.susp_high = at;
                self.spans.clear();
                self.suspends.push(at);
            }
            // The same suspend's second row (each chat's park, a `vm suspend` beside them) is none (B-COST-1).
            St::Suspended if self.same_transition(St::Suspended, at) => {}
            // A suspend after an end (hard or inferred) is a contradiction, ignored.
            St::Suspended | St::Ended => self.anomalies.push(at),
            St::Absent => {}
        }
    }

    fn terminate(&mut self, at: u64, by: &str, end: &str) {
        if matches!(self.st, St::Running | St::Suspended) {
            self.ended(at, false, by, end);
        }
    }

    /// Rule 4: activity restarts the idle clock, or auto-resumes a suspended VM (inferred), or revives one rule 3
    /// ended (`revive`; `hard`: a span's opening). A closing span never resumes one: its socket closed because the
    /// VM suspended.
    fn activity(&mut self, at: u64, by: &str, closing: bool, hard: bool) {
        match self.st {
            St::Running => self.last = self.last.max(at),
            St::Suspended if !closing => self.resume(at, by, true),
            St::Ended if !closing => self.revive_and_resume(at, by, hard, true),
            _ => {}
        }
    }

    fn on(&mut self, r: &Read, effects: &[Effect]) {
        let (at, by) = (r.at, r.event.as_str());
        let span = r.detail.get("spawn").cloned().unwrap_or_default();
        if effects.contains(&Effect::Start) {
            self.start(at, by);
        }
        if effects.contains(&Effect::Resume) {
            self.resume(at, by, false);
        }
        if effects.contains(&Effect::Observed) {
            match r.detail.get("state").map(String::as_str) {
                Some("RUNNING") if matches!(self.st, St::Suspended | St::Ended) => self.resume(at, by, true),
                Some("SUSPENDING" | "SUSPENDED") if matches!(self.st, St::Running | St::Ended) => self.suspend(at, by),
                Some("TERMINATING" | "TERMINATED") => self.terminate(at, by, "terminated (observed)"),
                Some("RUNNING") if self.st == St::Absent => self.anomalies.push(at),
                _ => {}
            }
        }
        if effects.iter().any(|e| matches!(e, Effect::Activity | Effect::SpanOpen)) {
            self.activity(at, by, false, effects.contains(&Effect::SpanOpen));
        }
        if effects.contains(&Effect::SpanOpen) && self.st == St::Running {
            self.spans.insert(span.clone());
        }
        if effects.contains(&Effect::SpanClose) {
            self.activity(at, by, true, false);
            self.spans.remove(&span);
        }
        if effects.contains(&Effect::Suspend) {
            self.suspend(at, by);
        }
        if effects.contains(&Effect::Terminate) {
            let who = r.detail.get("by").cloned().unwrap_or_else(|| if r.event == event::VM_EGRESS_MISMATCH { "policy".into() } else { r.event.clone() });
            self.terminate(at, by, &format!("terminated ({who})"));
        }
    }

    /// The stretch still open at the end of the rows: to `at`, its end not inferred (the VM lives).
    fn close_open(&mut self, at: u64) {
        if matches!(self.st, St::Running | St::Suspended) {
            self.close(at, false, at, at, "-");
        }
    }

    /// The intervals clipped to `[since, until)` and the counts inside it; `None` when nothing falls in it.
    fn clip(self, since: u64, until: u64) -> Option<VmTimeline> {
        let inside = |at: &&u64| **at >= since && **at < until;
        let count = |v: &[u64]| u32::try_from(v.iter().filter(inside).count()).unwrap_or(u32::MAX);
        let intervals: Vec<Interval> = self
            .raw
            .iter()
            .filter_map(|iv| {
                let (from, to) = (iv.from.max(since), iv.to.min(until));
                // Inferred inside the window: some of its range (from its low end on) lies in it.
                (from < to).then(|| Interval { from, to, inferred: iv.inferred && iv.low < until, low: iv.low.clamp(from, until), high: iv.high.clamp(from, until), ..iv.clone() })
            })
            .collect();
        let t = VmTimeline {
            vm: self.vm,
            memory_mib: self.p.memory_mib,
            max_idle_s: self.p.max_idle_s,
            suspended_s: self.p.suspended_s,
            max_duration_s: self.p.max_duration_s,
            starts: count(&self.starts),
            resumes: count(&self.resumes),
            suspends: count(&self.suspends),
            inferred_suspends: count(&self.inferred_suspends),
            inferred_resumes: count(&self.inferred_resumes),
            // An end at or after the window's end is none inside it: the VM lived through it.
            end: self.end.filter(|_| self.ended_at < until),
            anomalies: count(&self.anomalies),
            intervals,
        };
        let any = !t.intervals.is_empty() || t.starts + t.resumes + t.suspends + t.inferred_suspends + t.inferred_resumes + t.anomalies > 0;
        any.then_some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::audit::read::{parse_line, read_all};
    use crate::bridge::config::Paths;

    /// 2026-10-22T00:00:00Z, the fixture's day.
    const DAY: u64 = 1_792_627_200;
    const A: &str = "microvm-0a5fc800-0000-4000-8000-00000000000a";
    const B: &str = "microvm-0be03000-0000-4000-8000-00000000000b";
    const X: &str = "microvm-0c000000-0000-4000-8000-00000000000c";

    fn at(h: u64, m: u64, s: u64) -> u64 {
        DAY + h * 3600 + m * 60 + s
    }

    fn defaults() -> VmDefaults {
        VmDefaults { memory_mib: 2048, max_idle_s: 300, suspended_s: None, max_duration_s: 28_800 }
    }

    /// A v2 row of `event` at `t` (unix seconds).
    fn row(t: u64, event: &str, detail: &[(&str, &str)]) -> Read {
        let mut d = serde_json::Map::new();
        d.insert("actor".into(), "cli".into());
        for (k, v) in detail {
            d.insert((*k).into(), (*v).into());
        }
        let line = serde_json::json!({ "v": 2, "ts": crate::wire::time::rfc3339_utc(t), "event": event, "session_id": null, "pid": 1, "detail": d }).to_string();
        parse_line(&line).unwrap()
    }

    fn fixture() -> (Vec<Read>, Vec<VmRow>) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/s11/bridge");
        let paths = Paths::from_root_and_env(root, None);
        (read_all(&paths.audit()).unwrap(), crate::bridge::vm::registry::list_rows(&paths).unwrap())
    }

    /// `(phase, from, to, inferred, low, high, opened_by, closed_by)`.
    type Shape<'a> = (Phase, u64, u64, bool, u64, u64, &'a str, &'a str);

    /// Each interval's [`Shape`].
    fn shape(v: &VmTimeline) -> Vec<Shape<'_>> {
        v.intervals.iter().map(|i| (i.phase, i.from, i.to, i.inferred, i.low, i.high, i.opened_by.as_str(), i.closed_by.as_str())).collect()
    }

    fn vm<'a>(t: &'a Timeline, id: &str) -> &'a VmTimeline {
        t.vms.iter().find(|v| v.vm == id).unwrap_or_else(|| panic!("{id} in {t:#?}"))
    }

    /// The fixture's day: A (an S10 `vm_run`, its parameters from its VM row) idles twice into an inferred
    /// suspend, auto-resumes on a `vm_select`, resumes on an unpark and ends terminated by the migrate; B (an S11
    /// `vm_run`) suspends with its park and ends after its `suspended_s`; the proxy ran 07:00 to 19:00.
    #[test]
    fn fixture_intervals_and_inferred_suspends() {
        use Phase::{Running, Suspended};
        let (rows, vm_rows) = fixture();
        let t = build(&rows, &vm_rows, defaults(), DAY, DAY + 86_400);
        assert_eq!(t.vms.iter().map(|v| v.vm.as_str()).collect::<Vec<_>>(), [A, B]);
        let a = vm(&t, A);
        assert_eq!(
            shape(a),
            [
                (Running, at(8, 0, 0), at(8, 35, 0), true, at(8, 30, 0), at(8, 40, 0), "vm_run", "-"),
                (Suspended, at(8, 35, 0), at(9, 0, 0), false, at(9, 0, 0), at(9, 0, 0), "-", "vm_select"),
                (Running, at(9, 0, 0), at(9, 25, 0), true, at(9, 20, 0), at(9, 30, 0), "vm_select", "-"),
                (Suspended, at(9, 25, 0), at(10, 0, 0), false, at(10, 0, 0), at(10, 0, 0), "-", "session_unpark"),
                (Running, at(10, 0, 0), at(10, 21, 10), false, at(10, 21, 10), at(10, 21, 10), "session_unpark", "vm_terminate"),
            ]
        );
        assert_eq!((a.starts, a.resumes, a.inferred_resumes, a.suspends, a.inferred_suspends, a.anomalies), (1, 1, 1, 0, 2, 0));
        assert_eq!((a.memory_mib, a.max_idle_s, a.suspended_s, a.max_duration_s), (2048, 300, Some(3600), 28_800), "an S10 vm_run: the VM row's echo");
        assert_eq!(a.end.as_deref(), Some("terminated (migrate)"));
        let b = vm(&t, B);
        assert_eq!(
            shape(b),
            [
                (Running, at(10, 20, 30), at(11, 0, 0), false, at(11, 0, 0), at(11, 0, 0), "vm_run", "session_park"),
                (Suspended, at(11, 0, 0), at(12, 0, 0), true, at(12, 0, 0), at(12, 0, 0), "session_park", "-"),
            ]
        );
        assert_eq!((b.starts, b.resumes, b.suspends, b.inferred_suspends, b.anomalies), (1, 0, 1, 0, 0), "the later vm_observed TERMINATED agrees");
        assert_eq!(b.end.as_deref(), Some("suspended_s"));
        assert_eq!(t.proxy, ProxySpans { running: vec![(at(7, 0, 0), at(19, 0, 0))], assumed: false });
        assert_eq!((t.skipped, t.not_counted.len()), (1, 0), "the unknown event is skipped");
        // Clipped to a window that cuts A's first inferred stretch: its range from its low end on.
        let part = build(&rows, &vm_rows, defaults(), at(8, 32, 0), at(9, 10, 0));
        assert_eq!(shape(vm(&part, A))[0], (Running, at(8, 32, 0), at(8, 35, 0), true, at(8, 32, 0), at(8, 40, 0), "vm_run", "-"));
        assert_eq!(vm(&part, A).starts, 0, "the start is before the window");
        assert!(part.vms.iter().all(|v| v.vm != B), "B starts after it");
    }

    /// Rule 2: activity on a VM held suspended is an inferred auto-resume; with no `suspended_s` a suspended VM
    /// lives to its wall (rule 7); with one, it ends there (rule 3).
    #[test]
    fn auto_resume_gaps_and_the_wall() {
        use Phase::{Running, Suspended};
        let t0 = at(1, 0, 0);
        let rows = [
            row(t0, "vm_run", &[("id", X), ("max_duration_s", "3600"), ("max_idle_s", "300"), ("suspended_s", "-")]),
            row(t0 + 100, "codeout_fetch", &[("vm", X), ("outcome", "fetched")]),
            row(t0 + 2000, "codeout_fetch", &[("vm", X), ("outcome", "fetched")]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 10_000);
        let x = vm(&t, X);
        assert_eq!(
            shape(x),
            [
                (Running, t0, t0 + 400, true, t0 + 100, t0 + 700, "vm_run", "-"),
                (Suspended, t0 + 400, t0 + 2000, false, t0 + 2000, t0 + 2000, "-", "codeout_fetch"),
                (Running, t0 + 2000, t0 + 2300, true, t0 + 2000, t0 + 2600, "codeout_fetch", "-"),
                (Suspended, t0 + 2300, t0 + 3600, false, t0 + 3600, t0 + 3600, "-", "wall"),
            ]
        );
        assert_eq!((x.inferred_suspends, x.inferred_resumes, x.suspended_s, x.end.as_deref()), (2, 1, None, Some("wall")));
        // A suspended_s of 600: the platform ends the VM 600 s into its suspend.
        let rows = [row(t0, "vm_run", &[("id", X), ("suspended_s", "600")]), row(t0 + 100, "vm_suspend", &[("id", X)])];
        let t = build(&rows, &[], defaults(), 0, t0 + 10_000);
        assert_eq!(shape(vm(&t, X))[1], (Suspended, t0 + 100, t0 + 700, true, t0 + 700, t0 + 700, "vm_suspend", "-"));
        assert_eq!(vm(&t, X).end.as_deref(), Some("suspended_s"));
        // The wall ends a running VM whatever holds it open.
        let rows = [row(t0, "vm_run", &[("id", X), ("max_duration_s", "1000")]), row(t0 + 10, "session_remote_start", &[("id", X), ("spawn", "s1"), ("gen", "1"), ("why", "first")])];
        let t = build(&rows, &[], defaults(), 0, t0 + 10_000);
        assert_eq!(shape(vm(&t, X)), [(Running, t0, t0 + 1000, false, t0 + 1000, t0 + 1000, "vm_run", "wall")]);
    }

    /// A second start, a resume of a running VM rule 1 does not explain and a suspend of a suspended one are
    /// anomalies, ignored (a suspend more than `SAME_TRANSITION_S` after the one that opened the stretch); a second
    /// terminate is none; an unknown event is skipped and a VM with neither start evidence nor a row is listed,
    /// never priced.
    #[test]
    fn contradictions_count_as_anomalies() {
        let t0 = at(2, 0, 0);
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            row(t0 + 10, "vm_adopt", &[("id", X)]),
            row(t0 + 20, "vm_resume", &[("id", X)]),
            row(t0 + 30, "vm_suspend", &[("id", X), ("by", "cli")]),
            row(t0 + 30 + SAME_TRANSITION_S + 10, "vm_suspend", &[("id", X), ("by", "cli")]),
            row(t0 + 200, "vm_suspend", &[("id", X), ("outcome", "skipped")]),
            row(t0 + 210, "vm_terminate", &[("id", X), ("by", "operator")]),
            row(t0 + 220, "vm_egress_mismatch", &[("id", X), ("terminated", "true")]),
            row(t0 + 230, "vm_observed", &[("id", X), ("state", "TERMINATED"), ("was", "SUSPENDED"), ("via", "survey")]),
            row(t0 + 240, "codeout_fetch", &[("vm", "microvm-elsewhere"), ("outcome", "fetched")]),
            row(t0 + 245, "not_an_event", &[("vm", X)]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 1000);
        let x = vm(&t, X);
        assert_eq!((x.anomalies, x.starts, x.resumes, x.suspends), (3, 1, 0, 1), "{x:#?}");
        assert_eq!(x.end.as_deref(), Some("terminated (operator)"));
        assert_eq!(x.intervals.last().map(|i| i.to), Some(t0 + 210));
        assert_eq!((t.not_counted.clone(), t.skipped), (vec!["microvm-elsewhere".to_string()], 1));
    }

    /// B-COST-1: two rows of one transition are one event. A wrapper's resume writes `vm_reuse{resumed=true}`,
    /// then the pipeline's `vm_select{how=resumed}`; each chat on a VM writes its own `session_park{why=suspended}`
    /// and a `vm suspend` adds its row beside them: one resume, one suspend, no anomaly. The same kind of row
    /// past `SAME_TRANSITION_S`, or a resume row after an inferred auto-resume, is still an anomaly.
    #[test]
    fn a_second_record_of_one_transition_is_no_anomaly() {
        use Phase::{Running, Suspended};
        let t0 = at(4, 0, 0);
        let start = |spawn: &'static str, t: u64| row(t, "session_remote_start", &[("id", X), ("spawn", spawn), ("gen", "1"), ("why", "first")]);
        let park = |spawn: &'static str, t: u64| row(t, "session_park", &[("vm", X), ("spawn", spawn), ("why", "suspended"), ("quiet_ms", "0")]);
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            start("s1", t0 + 10),
            start("s2", t0 + 20),
            park("s1", t0 + 500),
            park("s2", t0 + 501),
            row(t0 + 505, "vm_suspend", &[("id", X), ("by", "cli")]),
            row(t0 + 1000, "vm_reuse", &[("id", X), ("purpose", "session"), ("resumed", "true")]),
            row(t0 + 1002, "vm_select", &[("id", X), ("choice", "reuse"), ("how", "resumed")]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 1200);
        let x = vm(&t, X);
        assert_eq!((x.resumes, x.suspends, x.anomalies), (1, 1, 0), "{x:#?}");
        assert_eq!(
            shape(x),
            [
                (Running, t0, t0 + 500, false, t0 + 500, t0 + 500, "vm_run", "session_park"),
                (Suspended, t0 + 500, t0 + 1000, false, t0 + 1000, t0 + 1000, "session_park", "vm_reuse"),
                (Running, t0 + 1000, t0 + 1200, false, t0 + 1200, t0 + 1200, "vm_reuse", "-"),
            ]
        );
        // The control: a resume of the running VM well after its own, and a suspend well after the one that
        // suspended it, are anomalies; so is a resume row after an inferred auto-resume.
        let late = SAME_TRANSITION_S + 1;
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            row(t0 + 10, "vm_suspend", &[("id", X)]),
            row(t0 + 10 + late, "vm_suspend", &[("id", X)]),
            row(t0 + 1000, "vm_resume", &[("id", X)]),
            row(t0 + 1000 + late, "vm_resume", &[("id", X)]),
            row(t0 + 1200, "vm_suspend", &[("id", X)]),
            row(t0 + 3000, "codeout_fetch", &[("vm", X), ("outcome", "fetched")]),
            row(t0 + 3001, "vm_resume", &[("id", X)]),
        ];
        let x = vm(&build(&rows, &[], defaults(), 0, t0 + 3100), X).clone();
        assert_eq!((x.resumes, x.inferred_resumes, x.suspends, x.anomalies), (1, 1, 2, 3), "{x:#?}");
    }

    /// B-COST-4 (rule 8): a row with no effect (`egress_check`, `credential_gate`, …) is no evidence, so it never
    /// caps an inferred suspend's range: its high end stays the last activity + 2 × `max_idle_s`.
    #[test]
    fn a_row_without_an_effect_never_caps_an_inferred_range() {
        use Phase::{Running, Suspended};
        let t0 = at(5, 0, 0);
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            row(t0 + 310, "egress_check", &[("id", X), ("image_version", "12.0"), ("verdict", "ok")]),
            row(t0 + 320, "credential_gate", &[("id", X), ("result", "ok")]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 2000);
        assert_eq!(shape(vm(&t, X)), [(Running, t0, t0 + 300, true, t0, t0 + 600, "vm_run", "-"), (Suspended, t0 + 300, t0 + 2000, false, t0 + 2000, t0 + 2000, "-", "-")]);
    }

    /// B-COST-2 (rule 4): the next wrapper's reap of a dead wrapper's spawn closes that spawn's keep-alive span,
    /// so once the live chat parks the VM idles into its inferred suspend `max_idle_s` later, not to its wall.
    #[test]
    fn a_reaped_spawn_holds_nothing_open() {
        use Phase::{Running, Suspended};
        let t0 = at(6, 0, 0);
        let start = |spawn: &'static str, t: u64| row(t, "session_remote_start", &[("id", X), ("spawn", spawn), ("gen", "1"), ("why", "first")]);
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            start("s1", t0 + 10),
            row(t0 + 1000, "session_reap", &[("session", "01926f2e-0000-7000-8000-00000000000a"), ("vm", X), ("spawn", "s1"), ("why", "leftover"), ("wrapper_pid", "77"), ("outcome", "reaped"), ("ms", "3")]),
            start("s2", t0 + 1001),
            row(t0 + 1500, "session_park", &[("vm", X), ("spawn", "s2"), ("why", "idle"), ("quiet_ms", "300000")]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 5000);
        assert_eq!(
            shape(vm(&t, X)),
            [(Running, t0, t0 + 1800, true, t0 + 1500, t0 + 2100, "vm_run", "-"), (Suspended, t0 + 1800, t0 + 5000, false, t0 + 5000, t0 + 5000, "-", "-")]
        );
    }

    /// Rule 3's end is an inference: a hard resume after it (here before the latest end the inferred suspend's
    /// range allows) reopens the suspended stretch, the VM runs on and the contradiction is an anomaly; other
    /// activity revives it only before that latest end (a respawn's move off a VM the platform ended does not).
    /// After a hard end, a resume, a suspend, an observed state or a span's opening is an anomaly only, and other
    /// activity is none.
    #[test]
    fn an_inferred_end_revives_on_later_life() {
        use Phase::{Running, Suspended};
        let t0 = at(10, 0, 0);
        let run = || row(t0, "vm_run", &[("id", X), ("max_idle_s", "300"), ("suspended_s", "600")]);
        let fetch = |t: u64| row(t, "codeout_fetch", &[("vm", X), ("outcome", "fetched")]);
        let rows = [
            run(),
            fetch(t0 + 10),
            row(t0 + 960, "vm_resume", &[("id", X)]),
            row(t0 + 1020, "session_remote_start", &[("id", X), ("spawn", "s9"), ("gen", "1"), ("why", "first")]),
            row(at(12, 0, 0), "session_remote_end", &[("vm", X), ("spawn", "s9"), ("gen", "1")]),
        ];
        let t = build(&rows, &[], defaults(), DAY, DAY + 86_400);
        let x = vm(&t, X);
        assert_eq!(
            shape(x),
            [
                (Running, t0, t0 + 310, true, t0 + 10, t0 + 610, "vm_run", "-"),
                (Suspended, t0 + 310, t0 + 960, false, t0 + 960, t0 + 960, "-", "vm_resume"),
                (Running, t0 + 960, at(12, 5, 0), true, at(12, 0, 0), at(12, 10, 0), "vm_resume", "-"),
                (Suspended, at(12, 5, 0), at(12, 15, 0), true, at(12, 15, 0), at(12, 15, 0), "-", "-"),
            ]
        );
        assert_eq!((x.starts, x.resumes, x.inferred_resumes, x.inferred_suspends, x.anomalies, x.end.as_deref()), (1, 1, 0, 2, 1, Some("suspended_s")));
        // Activity before the latest end (10:10:10 + 600 s) revives it too, as an inferred auto-resume.
        let rows = [run(), fetch(t0 + 10), fetch(t0 + 960)];
        let x = vm(&build(&rows, &[], defaults(), DAY, DAY + 86_400), X).clone();
        assert_eq!(shape(&x)[1], (Suspended, t0 + 310, t0 + 960, false, t0 + 960, t0 + 960, "-", "codeout_fetch"));
        assert_eq!((x.inferred_resumes, x.anomalies), (1, 1));
        // A respawn's move off the VM an hour later: the platform ended it; no revival, no anomaly.
        let rows = [run(), fetch(t0 + 10), row(t0 + 3600, "session_move", &[("session", "-"), ("gen", "2"), ("kind", "respawn"), ("from_vm", X)])];
        let x = vm(&build(&rows, &[], defaults(), DAY, DAY + 86_400), X).clone();
        assert_eq!((x.intervals.last().map(|i| (i.phase, i.to)), x.anomalies, x.end.as_deref()), (Some((Suspended, t0 + 910)), 0, Some("suspended_s")));
        // After a hard end: evidence of life is an anomaly, ignored; a fetch is none.
        let rows = [
            run(),
            row(t0 + 100, "vm_terminate", &[("id", X), ("by", "operator")]),
            row(t0 + 200, "vm_resume", &[("id", X)]),
            row(t0 + 300, "session_remote_start", &[("id", X), ("spawn", "s1"), ("gen", "1"), ("why", "first")]),
            fetch(t0 + 400),
            row(t0 + 500, "vm_suspend", &[("id", X)]),
            row(t0 + 600, "vm_observed", &[("id", X), ("state", "SUSPENDED"), ("was", "TERMINATED"), ("via", "survey")]),
            row(t0 + 700, "vm_observed", &[("id", X), ("state", "RUNNING"), ("was", "SUSPENDED"), ("via", "survey")]),
        ];
        let x = vm(&build(&rows, &[], defaults(), DAY, DAY + 86_400), X).clone();
        assert_eq!(shape(&x), [(Running, t0, t0 + 100, false, t0 + 100, t0 + 100, "vm_run", "vm_terminate")]);
        assert_eq!((x.anomalies, x.resumes, x.end.as_deref()), (5, 0, Some("terminated (operator)")));
    }

    /// An open keep-alive span holds the VM running past `max_idle_s`; it idles only once every span closed; a
    /// suspend closes every open span, so a dead wrapper's span holds nothing after it.
    #[test]
    fn a_keep_alive_span_holds_the_vm_running() {
        use Phase::{Running, Suspended};
        let t0 = at(3, 0, 0);
        let start = |spawn: &'static str, t: u64| row(t, "session_remote_start", &[("id", X), ("spawn", spawn), ("gen", "1"), ("why", "first")]);
        let end = |spawn: &'static str, t: u64| row(t, "session_remote_end", &[("vm", X), ("spawn", spawn), ("gen", "1")]);
        let rows = [
            row(t0, "vm_run", &[("id", X)]),
            start("s1", t0 + 10),
            start("s2", t0 + 20),
            end("s1", t0 + 3000),
            end("s2", t0 + 5000),
            start("s3", t0 + 6000),
            row(t0 + 6100, "vm_suspend", &[("id", X)]),
            row(t0 + 7000, "transcript_push", &[("vm", X), ("session", "-")]),
        ];
        let t = build(&rows, &[], defaults(), 0, t0 + 9000);
        assert_eq!(
            shape(vm(&t, X)),
            [
                (Running, t0, t0 + 5300, true, t0 + 5000, t0 + 5600, "vm_run", "-"),
                (Suspended, t0 + 5300, t0 + 6000, false, t0 + 6000, t0 + 6000, "-", "session_remote_start"),
                (Running, t0 + 6000, t0 + 6100, false, t0 + 6100, t0 + 6100, "session_remote_start", "vm_suspend"),
                (Suspended, t0 + 6100, t0 + 7000, false, t0 + 7000, t0 + 7000, "vm_suspend", "transcript_push"),
                (Running, t0 + 7000, t0 + 7300, true, t0 + 7000, t0 + 7600, "transcript_push", "-"),
                (Suspended, t0 + 7300, t0 + 9000, false, t0 + 9000, t0 + 9000, "-", "-"),
            ]
        );
        // A span that closes on a suspended VM (its socket closed with the suspend) resumes nothing.
        let rows = [row(t0, "vm_run", &[("id", X)]), start("s1", t0 + 10), row(t0 + 100, "vm_suspend", &[("id", X)]), end("s1", t0 + 105)];
        let t = build(&rows, &[], defaults(), 0, t0 + 1000);
        assert_eq!(vm(&t, X).intervals.iter().map(|i| i.phase).collect::<Vec<_>>(), [Running, Suspended]);
    }
}
