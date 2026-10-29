//! S11 (B.3): what the MicroVMs and the egress proxy cost over a window,
//! estimated from the timeline (`timeline`) at one rate card ([`EUC1`]):
//! `ai-env cost`, `vm list`'s RUN and COST cells, the panel's cost page. No
//! AWS call. Phase 0 built the rates and declared the rest; S11 wave 1's B2
//! built it. S12 (C): the live tests' runs merged, labelled (`estimate_with`,
//! `bridge::testruns`; `--no-tests` leaves them out), and `--compare`'s
//! proxy verdict and billed rates (B Q4), evidence beside the exit's verdict.
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::timeline::{Phase, Timeline, VmDefaults, VmTimeline};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// One rate card: USD, `eu-central-1`. The Lambda rows are S10 B5 (d)'s, off the October bill
/// (plans/s10-measurements.md:386-396); the EC2 rows are plans/s5-plan.md:670's and the gp3 list
/// price, unverified until T11.1 calibrates them.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Rates {
    /// `EUC1 2026-10-23`.
    pub card: &'static str,
    pub vcpu_second: f64,
    pub gb_second: f64,
    pub snapshot_write_gb: f64,
    pub snapshot_read_gb: f64,
    pub snapshot_storage_gb_hour: f64,
    pub t4g_nano_hour: f64,
    pub public_ipv4_hour: f64,
    pub gp3_gb_month: f64,
}

pub const EUC1: Rates = Rates {
    card: "EUC1 2026-10-23",
    vcpu_second: 0.000034996,
    gb_second: 0.000004633,
    snapshot_write_gb: 0.004983147,
    snapshot_read_gb: 0.001978002,
    snapshot_storage_gb_hour: 0.0001322222,
    t4g_nano_hour: 0.0048,
    public_ipv4_hour: 0.005,
    gp3_gb_month: 0.0952,
};

/// The baseline's vCPUs (B5 (d): not the guest's 4).
pub const VCPUS: f64 = 1.0;
/// GB a suspend writes (T11.1 calibrates).
pub const SUSPEND_WRITE_GB: f64 = 2.0;
/// GB a resume reads (T11.1 calibrates).
pub const RESUME_READ_GB: f64 = 2.0;
/// GB a start reads from the image (unmeasured; 2.0 until T11.1).
pub const START_READ_GB: f64 = 2.0;
/// GB a suspended VM's snapshot holds.
pub const SUSPENDED_GB: f64 = 2.0;
/// The images' snapshot storage (3617 GB-hours over 1 to 23 Oct).
pub const IMAGE_SNAPSHOT_USD_PER_DAY: f64 = 0.021;
/// The proxy's gp3 volume (plans/s5-plan.md:124).
pub const PROXY_VOLUME_GB: f64 = 8.0;
/// AWS's per-GB-month proration.
pub const HOURS_PER_MONTH: f64 = 730.0;
/// T11.1's ±30 %.
pub const COMPARE_BAND: f64 = 0.30;

/// Cost Explorer's `USAGE_TYPE` of the MicroVMs' vCPU-seconds.
pub const USAGE_VCPU: &str = "EUC1-Lambda-MicroVM-vCPU-Second-ARM";
/// Their memory's GB-seconds.
pub const USAGE_MEMORY: &str = "EUC1-Lambda-MicroVM-Memory-GB-Second-ARM";
/// The GB a suspend's snapshot writes.
pub const USAGE_SNAPSHOT_WRITE: &str = "EUC1-Lambda-MicroVM-Snapshot-Write-GB";
/// The GB a start or a resume reads.
pub const USAGE_SNAPSHOT_READ: &str = "EUC1-Lambda-MicroVM-Snapshot-Read-GB";
/// The snapshots' GB-hours.
pub const USAGE_SNAPSHOT_STORAGE: &str = "EUC1-Lambda-MicroVM-Snapshot-Storage-GB-Hour";
/// The proxy instance's hours.
pub const USAGE_T4G_NANO: &str = "EUC1-BoxUsage:t4g.nano";
/// The proxy's public IPv4 hours.
pub const USAGE_IPV4: &str = "EUC1-PublicIPv4:InUseAddress";
/// The proxy volume's GB-months.
pub const USAGE_GP3: &str = "EUC1-EBS:VolumeUsage.gp3";

/// The five Lambda types: the MicroVM total T11.1 judges.
pub const MICROVM_USAGE: [&str; 5] = [USAGE_VCPU, USAGE_MEMORY, USAGE_SNAPSHOT_WRITE, USAGE_SNAPSHOT_READ, USAGE_SNAPSHOT_STORAGE];
/// The proxy's three usage types (B Q4): its instance hours, its public IPv4's and its gp3 volume's.
pub const PROXY_USAGE: [&str; 3] = [USAGE_T4G_NANO, USAGE_IPV4, USAGE_GP3];

/// One Cost Explorer line.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Line {
    pub usage_type: &'static str,
    /// `AWS Lambda` or `EC2`.
    pub service: &'static str,
    pub quantity: f64,
    pub unit: &'static str,
    pub usd: f64,
}

/// One VM's share.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmCost {
    pub id: String,
    pub running_s: u64,
    pub suspended_s: u64,
    pub starts: u32,
    pub resumes: u32,
    pub suspends: u32,
    pub inferred_suspends: u32,
    pub usd: f64,
    pub low_usd: f64,
    pub high_usd: f64,
    /// `-`, `<n> idle suspends inferred`, `terminated (<by>)`, … joined by `; `.
    pub note: String,
    /// S12 (C1): the live test whose run holds this VM (`state/test-runs`); `None` for this root's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<String>,
}

/// One UTC day of a `--by day` estimate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Day {
    /// `YYYY-MM-DD`.
    pub day: String,
    pub usd: f64,
    pub low_usd: f64,
    pub high_usd: f64,
    pub microvm_usd: f64,
    pub proxy_usd: f64,
    pub lines: Vec<Line>,
}

/// `ai-env cost --json`'s document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Estimate {
    /// 1.
    pub v: u32,
    /// RFC 3339 UTC.
    pub since: String,
    pub until: String,
    pub rates: &'static str,
    pub vms: Vec<VmCost>,
    pub lines: Vec<Line>,
    pub usd: f64,
    pub low_usd: f64,
    pub high_usd: f64,
    pub microvm_usd: f64,
    pub proxy_usd: f64,
    pub proxy_assumed: bool,
    pub not_counted: Vec<String>,
    /// S12 (C1): the runs (`state/test-runs/<name>`) whose VMs this estimate prices, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub test_runs: Vec<String>,
    /// S12 (C1): what those VMs cost: their `usd` summed; `None` when none is priced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests_usd: Option<f64>,
    /// S12 (C1): `--no-tests` only: the test VMs a merged estimate would have priced in the window and
    /// this one does not (a VM this root holds too is priced, so it is not left out).
    #[serde(skip_serializing_if = "is_zero")]
    pub tests_excluded: u32,
    /// S12 (C1): each run that could not be read, `<name>: <why>`; none of its VMs is priced or counted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub test_runs_unreadable: Vec<String>,
    pub anomalies: u32,
    /// `S3`, `CloudWatch`, `data transfer`.
    pub not_estimated: Vec<&'static str>,
    pub caveats: Vec<&'static str>,
    /// `--by day` only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Day>,
}

/// `serde`'s skip test for `tests_excluded`.
fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The estimate of `[since, until)` with the live tests' runs merged: `estimate_with(.., Tests::Merge)`.
/// `ai-env cost` and the panel's `/cost` (whose `?json=1` is `cost --json`'s document) read it.
pub fn estimate_for(paths: &Paths, since: u64, until: u64, by_day: bool) -> Result<Estimate, BridgeError> {
    estimate_with(paths, since, until, by_day, Tests::Merge)
}

/// The estimate of `[since, until)` from `paths`' audit, VM rows and `[vm]`, the runs under
/// `paths.test_runs()` merged or left out (§C2.3).
///
/// The root is read exactly as [`timeline_for`] reads it (an unreadable audit or `state/vms` is the
/// `Err`, exit 1), then the runs (`testruns::read_runs`, which never fails: a run it cannot read is
/// `test_runs_unreadable`, in both modes, and adds to no count). `Merge` (rule 1) builds one timeline
/// over the root's rows followed by each run's (runs by name), and each run's VM rows followed by the
/// root's, so `timeline::build`'s id map keeps the root's row of an id both hold (LD-C5); its test VMs
/// are labelled (rules 2 and 3, [`label_tests`]). `Exclude` (rule 4, `--no-tests`) prices the root
/// alone and counts in `tests_excluded` the VMs `build` puts in the window over the runs alone (the same
/// `[vm]`, LD-C6) that the root's own estimate does not price: a VM the root holds too (its `vm gc`
/// adopted or ended a test's leaked VM) is still priced, so it is not left out. No run holds a row
/// naming no VM, so the proxy's spans are the root's in both modes (rule 6). Read-only: it creates,
/// writes, chmods and locks nothing, asks no Touch ID and calls no AWS.
pub fn estimate_with(paths: &Paths, since: u64, until: u64, by_day: bool, tests: Tests) -> Result<Estimate, BridgeError> {
    let rows = crate::bridge::audit::read::read_all(&paths.audit())?;
    let vm_rows = crate::bridge::vm::registry::list_rows(paths)?;
    let defaults = VmDefaults::from_cfg(&crate::bridge::config::BridgeConfig::load(paths)?.map(|c| c.vm).unwrap_or_default());
    let (runs, unreadable) = crate::bridge::testruns::read_runs(paths);
    let run_rows = runs.iter().flat_map(|r| r.rows.iter().cloned());
    let run_vm_rows = runs.iter().flat_map(|r| r.vm_rows.iter().cloned());
    let mut est = match tests {
        Tests::Merge => {
            let rows: Vec<_> = rows.into_iter().chain(run_rows).collect();
            let vm_rows: Vec<_> = run_vm_rows.chain(vm_rows).collect();
            let mut est = estimate(&crate::bridge::timeline::build(&rows, &vm_rows, defaults, since, until), &EUC1, by_day);
            label_tests(&mut est, &runs);
            est
        }
        Tests::Exclude => {
            let mut est = estimate(&crate::bridge::timeline::build(&rows, &vm_rows, defaults, since, until), &EUC1, by_day);
            let alone = crate::bridge::timeline::build(&run_rows.collect::<Vec<_>>(), &run_vm_rows.collect::<Vec<_>>(), defaults, since, until);
            let left_out = alone.vms.iter().filter(|v| !est.vms.iter().any(|e| e.id == v.vm)).count();
            est.tests_excluded = u32::try_from(left_out).unwrap_or(u32::MAX);
            est
        }
    };
    est.test_runs_unreadable = unreadable;
    Ok(est)
}

/// §C2.3 rules 2 and 3: a VM is a test VM when a run's VM rows hold its id or a run's row charges it
/// (`Read.vms.first()`); the first run by name that names it labels it (LD-C5). Its `test` is that
/// run's test, and its note says so first: `live test <test>`, or `live test <test>; <note>`.
/// `test_runs` names the runs that label at least one VM, sorted; `tests_usd` is their VMs' `usd`
/// summed, `None` with none.
fn label_tests(est: &mut Estimate, runs: &[crate::bridge::testruns::TestRun]) {
    let mut labelling = std::collections::BTreeSet::new();
    let mut usd_sum: Option<f64> = None;
    for v in &mut est.vms {
        let names = |r: &&crate::bridge::testruns::TestRun| r.vm_rows.iter().any(|row| row.id == v.id) || r.rows.iter().any(|row| row.vms.first() == Some(&v.id));
        let Some(run) = runs.iter().find(names) else { continue };
        v.note = if v.note == "-" { format!("live test {}", run.test) } else { format!("live test {}; {}", run.test, v.note) };
        v.test = Some(run.test.clone());
        labelling.insert(run.name.clone());
        *usd_sum.get_or_insert(0.0) += v.usd;
    }
    est.test_runs = labelling.into_iter().collect();
    est.tests_usd = usd_sum.map(usd);
}

/// The timeline of `[since, until)` from `paths`' audit, its VM rows and `[vm]` (the views' one reading).
pub fn timeline_for(paths: &Paths, since: u64, until: u64) -> Result<Timeline, BridgeError> {
    let rows = crate::bridge::audit::read::read_all(&paths.audit())?;
    let vm_rows = crate::bridge::vm::registry::list_rows(paths)?;
    let defaults = VmDefaults::from_cfg(&crate::bridge::config::BridgeConfig::load(paths)?.map(|c| c.vm).unwrap_or_default());
    Ok(crate::bridge::timeline::build(&rows, &vm_rows, defaults, since, until))
}

/// Whether an estimate counts the live tests' VMs (S12 C1): each live test's guard keeps its audit rows
/// naming a VM and its stripped VM rows under the real root's `state/test-runs` (`bridge::testruns`);
/// `ai-env cost` and the panel merge them (`Merge`), `ai-env cost --no-tests` leaves them out (`Exclude`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tests {
    Merge,
    Exclude,
}

/// The caveats every estimate prints, in order.
pub const CAVEATS: [&str; 8] = [
    "idle suspends are inferred: a running stretch with no closing row ends max_idle_s after its last activity (the range puts it at that activity and at the next evidence)",
    "GB per snapshot operation assumed 2 (a suspend's write, a resume's read; a start's image read unmeasured): T11.1 calibrates them",
    "bursts above the baseline (1 vCPU and the image's memory) are billed while used and invisible here",
    "the images' snapshot storage is taken as a constant ($0.021 a day)",
    "VMs outside this registry (other owners, a deleted audit, a live test before S12 or one killed before its end) are not counted",
    "image builds during make deploy are not counted",
    "Cost Explorer's days are UTC, lag 24 to 48 h and round",
    "a sleeping Mac writes no rows: a parked chat's VM is priced by the idle rule, an unparked one's by its wrapper's reconnect, which measures the sleep (suspended max_idle_s after the lid closed); an unparked one that ended asleep left no reconnect and is priced as running to its wall, or to the platform's end once ai-env records it (the chat's next message, a reuse, vm status), and through the sleep until then",
];

/// What the estimate leaves out.
pub const NOT_ESTIMATED: [&str; 3] = ["S3", "CloudWatch", "data transfer"];

/// Which end of every inferred suspend an estimate prices (rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Point,
    Low,
    High,
}

/// A VM's seconds in `[a, b)` with every inferred running end at `which`'s bound (the suspended stretch after
/// it starts there too).
fn seconds(v: &VmTimeline, which: Which, a: u64, b: u64) -> (u64, u64) {
    let (mut running, mut suspended) = (0u64, 0u64);
    let mut moved: Option<(u64, u64)> = None;
    for iv in &v.intervals {
        let mut from = iv.from;
        if let Some((was, now)) = moved.take() {
            if was == iv.from {
                from = now;
            }
        }
        let mut to = iv.to;
        if iv.inferred && iv.phase == Phase::Running {
            to = match which {
                Which::Point => iv.to,
                Which::Low => iv.low,
                Which::High => iv.high,
            };
            moved = Some((iv.to, to));
        }
        let (from, to) = (from.max(a), to.min(b));
        if to > from {
            match iv.phase {
                Phase::Running => running += to - from,
                Phase::Suspended => suspended += to - from,
            }
        }
    }
    (running, suspended)
}

/// What a VM did in `[a, b)`: starts, resumes (inferred ones too) and suspends (inferred ones too), read off
/// its interval boundaries (one at the timeline's own `since` is a state carried in, never an event).
fn boundary_counts(v: &VmTimeline, since: u64, a: u64, b: u64) -> (u32, u32, u32) {
    let (mut starts, mut resumes, mut suspends) = (0u32, 0u32, 0u32);
    for iv in v.intervals.iter().filter(|iv| iv.from > since && iv.from >= a && iv.from < b) {
        match iv.phase {
            Phase::Running if crate::bridge::timeline::is_start(&iv.opened_by) => starts += 1,
            Phase::Running => resumes += 1,
            Phase::Suspended => suspends += 1,
        }
    }
    (starts, resumes, suspends)
}

/// One VM's quantities: running and suspended seconds, starts, resumes, suspends, its memory.
#[derive(Debug, Clone, Copy, Default)]
struct Use {
    running_s: u64,
    suspended_s: u64,
    starts: u32,
    resumes: u32,
    suspends: u32,
    memory_mib: u32,
}

impl Use {
    fn vcpu_s(&self) -> f64 {
        self.running_s as f64 * VCPUS
    }
    fn gb_s(&self) -> f64 {
        self.running_s as f64 * f64::from(self.memory_mib) / 1024.0
    }
    fn write_gb(&self) -> f64 {
        f64::from(self.suspends) * SUSPEND_WRITE_GB
    }
    fn read_gb(&self) -> f64 {
        f64::from(self.starts) * START_READ_GB + f64::from(self.resumes) * RESUME_READ_GB
    }
    fn storage_gb_h(&self) -> f64 {
        self.suspended_s as f64 / 3600.0 * SUSPENDED_GB
    }
    /// Its dollars: compute, snapshot write, read and storage.
    fn usd(&self, r: &Rates) -> f64 {
        self.vcpu_s() * r.vcpu_second + self.gb_s() * r.gb_second + self.write_gb() * r.snapshot_write_gb + self.read_gb() * r.snapshot_read_gb + self.storage_gb_h() * r.snapshot_storage_gb_hour
    }
}

/// A VM's use of `[a, b)` at `which` (counts off the boundaries when `a`/`b` cut the timeline's window, else its own).
fn use_of(t: &Timeline, v: &VmTimeline, which: Which, a: u64, b: u64) -> Use {
    let (running_s, suspended_s) = seconds(v, which, a, b);
    let window = (v.starts, v.resumes + v.inferred_resumes, v.suspends + v.inferred_suspends);
    let (starts, resumes, suspends) = if a == t.since && b == t.until {
        window
    } else if a == t.since {
        // The events at exactly the window's start, which no boundary shows, count on its first part.
        let (s, r, p) = boundary_counts(v, t.since, a, b);
        let (ws, wr, wp) = boundary_counts(v, t.since, t.since, t.until);
        (s + window.0.saturating_sub(ws), r + window.1.saturating_sub(wr), p + window.2.saturating_sub(wp))
    } else {
        boundary_counts(v, t.since, a, b)
    };
    Use { running_s, suspended_s, starts, resumes, suspends, memory_mib: v.memory_mib }
}

/// The proxy's running seconds in `[a, b)`.
fn proxy_s(t: &Timeline, a: u64, b: u64) -> u64 {
    t.proxy.running.iter().map(|(from, to)| (*to).min(b).saturating_sub((*from).max(a))).sum()
}

fn round(x: f64) -> f64 {
    usd(x)
}

/// The eight lines of `[a, b)`: the MicroVMs' five, then the proxy's three.
fn lines_of(t: &Timeline, rates: &Rates, a: u64, b: u64) -> Vec<Line> {
    let uses: Vec<Use> = t.vms.iter().map(|v| use_of(t, v, Which::Point, a, b)).collect();
    let sum = |f: &dyn Fn(&Use) -> f64| uses.iter().map(f).sum::<f64>();
    let days = b.saturating_sub(a) as f64 / 86_400.0;
    let hours = b.saturating_sub(a) as f64 / 3600.0;
    let proxy_h = proxy_s(t, a, b) as f64 / 3600.0;
    let image_gb_h = IMAGE_SNAPSHOT_USD_PER_DAY * days / rates.snapshot_storage_gb_hour;
    let line = |usage_type: &'static str, service: &'static str, quantity: f64, unit: &'static str, rate: f64| Line { usage_type, service, quantity: round(quantity), unit, usd: round(quantity * rate) };
    vec![
        line(USAGE_VCPU, "AWS Lambda", sum(&Use::vcpu_s), "vCPU-s", rates.vcpu_second),
        line(USAGE_MEMORY, "AWS Lambda", sum(&Use::gb_s), "GB-s", rates.gb_second),
        line(USAGE_SNAPSHOT_WRITE, "AWS Lambda", sum(&Use::write_gb), "GB", rates.snapshot_write_gb),
        line(USAGE_SNAPSHOT_READ, "AWS Lambda", sum(&Use::read_gb), "GB", rates.snapshot_read_gb),
        line(USAGE_SNAPSHOT_STORAGE, "AWS Lambda", sum(&Use::storage_gb_h) + image_gb_h, "GB-h", rates.snapshot_storage_gb_hour),
        line(USAGE_T4G_NANO, "EC2", proxy_h, "h", rates.t4g_nano_hour),
        line(USAGE_IPV4, "EC2", proxy_h, "h", rates.public_ipv4_hour),
        line(USAGE_GP3, "EC2", PROXY_VOLUME_GB * hours / HOURS_PER_MONTH, "GB-month", rates.gp3_gb_month),
    ]
}

/// The totals of `[a, b)`: (usd, low, high, MicroVM, proxy) and its lines.
fn totals(t: &Timeline, rates: &Rates, a: u64, b: u64) -> (f64, f64, f64, f64, f64, Vec<Line>) {
    let lines = lines_of(t, rates, a, b);
    let microvm: f64 = lines.iter().filter(|l| MICROVM_USAGE.contains(&l.usage_type)).map(|l| l.usd).sum();
    let proxy: f64 = lines.iter().filter(|l| !MICROVM_USAGE.contains(&l.usage_type)).map(|l| l.usd).sum();
    let delta = |which: Which| t.vms.iter().map(|v| use_of(t, v, which, a, b).usd(rates) - use_of(t, v, Which::Point, a, b).usd(rates)).sum::<f64>();
    let total = microvm + proxy;
    (round(total), round(total + delta(Which::Low)), round(total + delta(Which::High)), round(microvm), round(proxy), lines)
}

/// `fmt_secs`, `-` for none.
fn secs_cell(s: u64) -> String {
    if s == 0 {
        "-".into()
    } else {
        crate::bridge::vm::cmd::fmt_secs(i64::try_from(s).unwrap_or(i64::MAX))
    }
}

/// A VM's note: its inferred idle suspends and how it ended, `-` for nothing.
fn note_of(v: &VmTimeline) -> String {
    let mut parts = Vec::new();
    match v.inferred_suspends {
        0 => {}
        1 => parts.push("1 idle suspend inferred".to_string()),
        n => parts.push(format!("{n} idle suspends inferred")),
    }
    if v.inferred_resumes > 0 {
        parts.push(format!("{} auto-resume{} inferred", v.inferred_resumes, if v.inferred_resumes == 1 { "" } else { "s" }));
    }
    if let Some(end) = &v.end {
        parts.push(match end.as_str() {
            "wall" => "ended at its wall".to_string(),
            "suspended_s" => "ended suspended (suspended_s)".to_string(),
            other => other.to_string(),
        });
    }
    if v.anomalies > 0 {
        parts.push(format!("{} anomal{}", v.anomalies, if v.anomalies == 1 { "y" } else { "ies" }));
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join("; ")
    }
}

/// The same, from what is already read (S12: no run labelled, nothing left out).
#[must_use]
pub fn estimate(t: &Timeline, rates: &Rates, by_day: bool) -> Estimate {
    let (since, until) = (t.since, t.until);
    let vms: Vec<VmCost> = t
        .vms
        .iter()
        .map(|v| {
            let point = use_of(t, v, Which::Point, since, until);
            VmCost {
                id: v.vm.clone(),
                running_s: point.running_s,
                suspended_s: point.suspended_s,
                starts: point.starts,
                resumes: point.resumes,
                suspends: point.suspends,
                inferred_suspends: v.inferred_suspends,
                usd: round(point.usd(rates)),
                low_usd: round(use_of(t, v, Which::Low, since, until).usd(rates)),
                high_usd: round(use_of(t, v, Which::High, since, until).usd(rates)),
                note: note_of(v),
                test: None,
            }
        })
        .collect();
    let (total, low, high, microvm, proxy, lines) = totals(t, rates, since, until);
    let days = if by_day { days_of(t, rates) } else { Vec::new() };
    Estimate {
        v: 1,
        since: crate::wire::time::rfc3339_utc(since),
        until: crate::wire::time::rfc3339_utc(until),
        rates: rates.card,
        vms,
        lines,
        usd: total,
        low_usd: low,
        high_usd: high,
        microvm_usd: microvm,
        proxy_usd: proxy,
        proxy_assumed: t.proxy.assumed,
        not_counted: t.not_counted.clone(),
        // S12 (C1): `estimate_with` fills them.
        test_runs: Vec::new(),
        tests_usd: None,
        tests_excluded: 0,
        test_runs_unreadable: Vec::new(),
        anomalies: t.vms.iter().map(|v| v.anomalies).sum(),
        not_estimated: NOT_ESTIMATED.to_vec(),
        caveats: CAVEATS.to_vec(),
        days,
    }
}

/// The window split at UTC midnights; an event at exactly the window's start counts on its first day.
fn days_of(t: &Timeline, rates: &Rates) -> Vec<Day> {
    let mut days = Vec::new();
    let mut a = t.since;
    while a < t.until {
        let b = ((a / 86_400) + 1).saturating_mul(86_400).min(t.until);
        let (usd, low_usd, high_usd, microvm_usd, proxy_usd, lines) = totals(t, rates, a, b);
        days.push(Day { day: crate::wire::time::rfc3339_utc(a)[..10].to_string(), usd, low_usd, high_usd, microvm_usd, proxy_usd, lines });
        a = b;
    }
    days
}

/// One VM's cell over its life to `now` (`vm list`'s RUN and COST): `t` built from 0 to now.
#[must_use]
pub fn vm_cell(t: &Timeline, id: &str) -> Option<crate::bridge::vm::ops::VmCostCell> {
    let v = t.vms.iter().find(|v| v.vm == id)?;
    let u = use_of(t, v, Which::Point, t.since, t.until);
    Some(crate::bridge::vm::ops::VmCostCell { usd: round(u.usd(&EUC1)), running_s: u.running_s, suspended_s: u.suspended_s, inferred: v.intervals.iter().any(|i| i.inferred) })
}

/// A session's cost: its VMs over its generations' spans (`(vm, from, to)`), each span priced as a window.
#[must_use]
pub fn spans_cost(t: &Timeline, spans: &[(String, u64, u64)]) -> (f64, f64, f64, u64, u64) {
    let (mut point, mut low, mut high, mut running, mut suspended) = (0.0, 0.0, 0.0, 0u64, 0u64);
    for (vm, from, to) in spans {
        let Some(v) = t.vms.iter().find(|v| &v.vm == vm) else { continue };
        let u = use_of(t, v, Which::Point, *from, *to);
        point += u.usd(&EUC1);
        low += use_of(t, v, Which::Low, *from, *to).usd(&EUC1);
        high += use_of(t, v, Which::High, *from, *to).usd(&EUC1);
        running += u.running_s;
        suspended += u.suspended_s;
    }
    (round(point), round(low), round(high), running, suspended)
}

/// The baseline's dollars an hour of a running VM of `memory_mib` (`vm gc`'s line).
#[must_use]
pub fn usd_per_hour(memory_mib: u32) -> f64 {
    3600.0 * (VCPUS * EUC1.vcpu_second + f64::from(memory_mib) / 1024.0 * EUC1.gb_second)
}

/// Dollars rounded to 6 decimals (every `usd` field).
#[must_use]
pub fn usd(x: f64) -> f64 {
    (x * 1_000_000.0).round() / 1_000_000.0
}

/// `aws ce get-cost-and-usage` of the UTC days `start` (inclusive) to `end` (exclusive), as `cost` prints it.
#[must_use]
pub fn ce_command(start: &str, end: &str) -> String {
    format!("aws ce get-cost-and-usage --region us-east-1 --time-period Start={start},End={end} --granularity DAILY --metrics UnblendedCost UsageQuantity --group-by Type=DIMENSION,Key=USAGE_TYPE --output json > ce.json")
}

/// A Cost Explorer answer, read leniently: its window (UTC midnights), each usage type's summed
/// `UnblendedCost` and (S12) `UsageQuantity`, and the days whose figures are still `Estimated`.
#[derive(Debug, Clone, PartialEq)]
pub struct CeAnswer {
    pub start: u64,
    pub end: u64,
    pub by_type: BTreeMap<String, f64>,
    /// S12 (B Q4): each usage type's `UsageQuantity` summed over the kept days (the JSON's);
    /// empty for the console's CSV, which has none.
    pub quantity: BTreeMap<String, f64>,
    pub estimated: Vec<String>,
}

/// `YYYY-MM-DD` as its UTC midnight.
fn day_start(text: &str) -> Option<u64> {
    (text.len() == 10).then(|| crate::wire::time::parse_rfc3339_utc(&format!("{text}T00:00:00Z"))).flatten()
}

/// Parse `--compare`'s file (the JSON of `aws ce get-cost-and-usage … --group-by Type=DIMENSION,Key=USAGE_TYPE`,
/// or the console's Cost Explorer CSV); `Err` (exit 2) names the command that makes a usable one.
pub fn parse_compare(text: &str) -> Result<CeAnswer, String> {
    parse_compare_in(text, None)
}

/// [`parse_compare`], keeping only the days within `days` (UTC `[from, to)`, from `--since`/`--until`) when given:
/// one day of a longer file is compared alone.
pub fn parse_compare_in(text: &str, days: Option<(u64, u64)>) -> Result<CeAnswer, String> {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    if body.starts_with("\"Usage type\"") || body.starts_with("Usage type,") {
        return parse_console_csv(body, days);
    }
    let usage = || format!("not a Cost Explorer answer grouped by USAGE_TYPE with UnblendedCost (or the console's CSV of costs by usage type, daily); save one with\n  {}", ce_command("<YYYY-MM-DD>", "<YYYY-MM-DD>"));
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| usage())?;
    if v["GroupDefinitions"][0]["Key"].as_str() != Some("USAGE_TYPE") {
        return Err(usage());
    }
    let periods = v["ResultsByTime"].as_array().filter(|a| !a.is_empty()).ok_or_else(usage)?;
    let (mut start, mut end) = (u64::MAX, 0u64);
    let mut by_type: BTreeMap<String, f64> = BTreeMap::new();
    let mut quantity: BTreeMap<String, f64> = BTreeMap::new();
    let mut estimated = Vec::new();
    for p in periods {
        let from = p["TimePeriod"]["Start"].as_str().and_then(day_start).ok_or_else(usage)?;
        let to = p["TimePeriod"]["End"].as_str().and_then(day_start).ok_or_else(usage)?;
        if to <= from {
            return Err(usage());
        }
        if days.is_some_and(|(lo, hi)| from < lo || to > hi) {
            continue;
        }
        start = start.min(from);
        end = end.max(to);
        if p["Estimated"].as_bool() == Some(true) {
            estimated.push(crate::wire::time::rfc3339_utc(from)[..10].to_string());
        }
        for g in p["Groups"].as_array().map_or(&[][..], Vec::as_slice) {
            let key = g["Keys"][0].as_str().ok_or_else(usage)?;
            let amount = g["Metrics"]["UnblendedCost"]["Amount"].as_str().and_then(|a| a.parse::<f64>().ok()).filter(|a| a.is_finite()).ok_or_else(usage)?;
            *by_type.entry(key.to_string()).or_default() += amount;
            // S12 (B Q4, §C3.2 rule 1): the billed quantity, read as leniently: a group without one, or with one
            // that is no finite number, adds nothing and is no error.
            if let Some(q) = g["Metrics"]["UsageQuantity"]["Amount"].as_str().and_then(|q| q.parse::<f64>().ok()).filter(|q| q.is_finite()) {
                *quantity.entry(key.to_string()).or_default() += q;
            }
        }
    }
    if end == 0 {
        return Err(if days.is_some() { "the file has no day within --since/--until".to_string() } else { usage() });
    }
    Ok(CeAnswer { start, end, by_type, quantity, estimated })
}

/// One CSV line's fields (RFC 4180: quoted with `""` for a quote, or bare); `None` for a malformed line.
fn csv_fields(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    loop {
        let mut field = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') if chars.peek() == Some(&'"') => {
                        chars.next();
                        field.push('"');
                    }
                    Some('"') => break,
                    Some(c) => field.push(c),
                    None => return None,
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                field.push(c);
                chars.next();
            }
        }
        out.push(field);
        match chars.next() {
            Some(',') => {}
            None => return Some(out),
            Some(_) => return None,
        }
    }
}

/// The console's Cost Explorer CSV ("Download as CSV" of costs grouped by usage type, daily): a header
/// `"Usage type","<type>($)",…,"Total costs($)"`, a `"Usage type total"` row (skipped), then one row a UTC day
/// (`YYYY-MM-DD`), an empty cell for a type with no cost that day. The console marks no day estimated.
fn parse_console_csv(text: &str, days: Option<(u64, u64)>) -> Result<CeAnswer, String> {
    let usage = || "not the console's Cost Explorer CSV of costs grouped by usage type, daily (\"Usage type\" header, a row a day)".to_string();
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = csv_fields(lines.next().ok_or_else(usage)?).ok_or_else(usage)?;
    if header.len() < 2 || header[0] != "Usage type" {
        return Err(usage());
    }
    let types: Vec<Option<String>> = header[1..]
        .iter()
        .map(|h| {
            let t = h.strip_suffix("($)").unwrap_or(h).trim();
            (!t.is_empty() && t != "Total costs").then(|| t.to_string())
        })
        .collect();
    let (mut start, mut end) = (u64::MAX, 0u64);
    let mut by_type: BTreeMap<String, f64> = BTreeMap::new();
    for line in lines {
        let fields = csv_fields(line).ok_or_else(usage)?;
        let label = fields.first().map(String::as_str).unwrap_or_default();
        if label == "Usage type total" {
            continue;
        }
        let day = day_start(label).ok_or_else(usage)?;
        if days.is_some_and(|(lo, hi)| day < lo || day + 86_400 > hi) {
            continue;
        }
        start = start.min(day);
        end = end.max(day + 86_400);
        for (t, v) in types.iter().zip(fields.iter().skip(1)) {
            let (Some(t), v) = (t, v.trim()) else { continue };
            if v.is_empty() {
                continue;
            }
            let amount = v.parse::<f64>().ok().filter(|a| a.is_finite()).ok_or_else(usage)?;
            *by_type.entry(t.clone()).or_default() += amount;
        }
    }
    if end == 0 {
        return Err(if days.is_some() { "the CSV has no day within --since/--until".to_string() } else { usage() });
    }
    // The console's CSV holds costs only: no quantity, so no billed rate (§C3.4).
    Ok(CeAnswer { start, end, by_type, quantity: BTreeMap::new(), estimated: Vec::new() })
}

/// A verdict over some usage types at T11.1's band (S12: the proxy's).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Judged {
    /// The types judged, in `PROXY_USAGE`'s order: those the file holds.
    pub types: Vec<&'static str>,
    pub estimate_usd: f64,
    pub actual_usd: f64,
    /// `(estimate - actual) / actual` in percent, one decimal; `None` with no actual cost.
    pub off_pct: Option<f64>,
    pub pass: bool,
}

/// One priced type's card rate against the rate Cost Explorer billed (`UnblendedCost / UsageQuantity`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BilledRate {
    pub usage_type: &'static str,
    pub card: f64,
    pub billed: f64,
    pub quantity: f64,
}

/// The estimate against Cost Explorer: each usage type's pair, and the MicroVM total's verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Compared {
    /// `(usage type, estimate, actual)`: the estimate's lines, then the file's other types.
    pub lines: Vec<(String, f64, f64)>,
    pub estimate_usd: f64,
    pub actual_usd: f64,
    /// `(estimate - actual) / actual` in percent; `None` with no actual cost.
    pub off_pct: Option<f64>,
    pub pass: bool,
    /// S12 (B Q4): the proxy's verdict over the proxy types the file holds; `None` when it holds none.
    /// Evidence: never the exit.
    pub proxy: Option<Judged>,
    /// S12 (B Q4): the card rate against the billed one, for each of the estimate's eight types the
    /// file has a positive quantity of, in the lines' order.
    pub rates: Vec<BilledRate>,
}

/// T11.1's rule for a total: `(off_pct, pass)`, the percent off at one decimal (`None` with no actual
/// cost) and whether the estimate lies within ±`COMPARE_BAND` of the actual (a zero actual passes only a
/// zero estimate). The MicroVM total and the proxy's (§C3.2 rule 2) are judged alike.
fn judge(estimate: f64, actual: f64) -> (Option<f64>, bool) {
    let off_pct = (actual > 0.0).then(|| (estimate - actual) / actual * 100.0);
    let pass = if actual > 0.0 { (estimate - actual).abs() <= COMPARE_BAND * actual } else { estimate == 0.0 };
    (off_pct.map(|p| (p * 10.0).round() / 10.0), pass)
}

/// `<what>: estimate $<e>, Cost Explorer $<a>: <off>: within ±30 %` (or `outside ±30 %`).
fn verdict_line(what: &str, estimate: f64, actual: f64, off_pct: Option<f64>, pass: bool) -> String {
    let band = format!("±{:.0} %", COMPARE_BAND * 100.0);
    let off = off_pct.map_or_else(|| "no Cost Explorer figure to judge by".to_string(), |p| format!("{:.1} % off", p.abs()));
    format!("{what}: estimate ${estimate:.3}, Cost Explorer ${actual:.3}: {off}: {} {band}", if pass { "within" } else { "outside" })
}

/// The card's rate of `usage_type`, one of the estimate's eight lines; `None` for any other type.
fn card_rate(rates: &Rates, usage_type: &str) -> Option<f64> {
    Some(match usage_type {
        USAGE_VCPU => rates.vcpu_second,
        USAGE_MEMORY => rates.gb_second,
        USAGE_SNAPSHOT_WRITE => rates.snapshot_write_gb,
        USAGE_SNAPSHOT_READ => rates.snapshot_read_gb,
        USAGE_SNAPSHOT_STORAGE => rates.snapshot_storage_gb_hour,
        USAGE_T4G_NANO => rates.t4g_nano_hour,
        USAGE_IPV4 => rates.public_ipv4_hour,
        USAGE_GP3 => rates.gp3_gb_month,
        _ => return None,
    })
}

/// Judge `est` against `ce` (T11.1: the MicroVM total within ±`COMPARE_BAND`).
///
/// S12 (B Q4, §C3.2): beside it, the proxy's verdict over the `PROXY_USAGE` types the file holds, in
/// that order (none: `None`), the estimate's lines for them against the file's amounts, judged by the
/// same rule (LD-C8, §C3.2 rule 2); and, for each of the estimate's eight lines in order whose type the
/// file has a positive quantity of, the card's rate against the billed one, the file's amount divided by
/// its quantity (LD-C7, §C3.2 rule 3). Neither changes `pass`, the exit's (rule 4); nothing of it is
/// stored.
#[must_use]
pub fn compare(est: &Estimate, ce: &CeAnswer) -> Compared {
    let mut lines: Vec<(String, f64, f64)> = est.lines.iter().map(|l| (l.usage_type.to_string(), l.usd, round(ce.by_type.get(l.usage_type).copied().unwrap_or(0.0)))).collect();
    for (k, a) in &ce.by_type {
        if !lines.iter().any(|(t, _, _)| t == k) {
            lines.push((k.clone(), 0.0, round(*a)));
        }
    }
    let actual = round(MICROVM_USAGE.iter().map(|t| ce.by_type.get(*t).copied().unwrap_or(0.0)).sum());
    let estimate = est.microvm_usd;
    let (off_pct, pass) = judge(estimate, actual);
    let types: Vec<&'static str> = PROXY_USAGE.iter().copied().filter(|t| ce.by_type.contains_key(*t)).collect();
    let proxy = (!types.is_empty()).then(|| {
        let estimate_usd = round(est.lines.iter().filter(|l| types.contains(&l.usage_type)).map(|l| l.usd).sum());
        let actual_usd = round(types.iter().map(|t| ce.by_type.get(*t).copied().unwrap_or(0.0)).sum());
        let (off_pct, pass) = judge(estimate_usd, actual_usd);
        Judged { types: types.clone(), estimate_usd, actual_usd, off_pct, pass }
    });
    let rates = est
        .lines
        .iter()
        .filter_map(|l| {
            let quantity = ce.quantity.get(l.usage_type).copied().filter(|q| *q > 0.0)?;
            let card = card_rate(&EUC1, l.usage_type)?;
            Some(BilledRate { usage_type: l.usage_type, card, billed: ce.by_type.get(l.usage_type).copied().unwrap_or(0.0) / quantity, quantity })
        })
        .collect();
    Compared { lines, estimate_usd: estimate, actual_usd: actual, off_pct, pass, proxy, rates }
}

impl Judged {
    /// `<what>: estimate $<e>, Cost Explorer $<a>: <off>: within ±30 %` (or `outside ±30 %`), as
    /// `Compared::verdict` words the MicroVM total.
    #[must_use]
    pub fn verdict(&self, what: &str) -> String {
        verdict_line(what, self.estimate_usd, self.actual_usd, self.off_pct, self.pass)
    }
}

impl Compared {
    /// `--json`'s `compare`: S11's `lines` and `microvm`, then (S12, B Q4) `proxy` (`null` when the file
    /// holds no proxy type) and `rates` (empty for the console's CSV).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        let lines: Vec<serde_json::Value> = self.lines.iter().map(|(t, e, a)| serde_json::json!({ "usage_type": t, "estimate_usd": e, "actual_usd": a })).collect();
        serde_json::json!({
            "lines": lines,
            "microvm": { "estimate_usd": self.estimate_usd, "actual_usd": self.actual_usd, "off_pct": self.off_pct, "pass": self.pass },
            "proxy": self.proxy,
            "rates": self.rates,
        })
    }

    /// The verdict line.
    #[must_use]
    pub fn verdict(&self) -> String {
        verdict_line("MicroVM total", self.estimate_usd, self.actual_usd, self.off_pct, self.pass)
    }

    /// The proxy's line (§C3.3): its verdict, which is evidence and never the exit, or what the file
    /// lacks (B Q4 needs an export with the EC2 and VPC services).
    #[must_use]
    pub fn proxy_verdict(&self) -> String {
        match &self.proxy {
            Some(j) => format!("{} (evidence, not the exit)", j.verdict(&format!("proxy total ({})", j.types.join(", ")))),
            None => format!("proxy total: the file holds none of {} (export EC2-Instances, EC2-Other and VPC too)", PROXY_USAGE.join(", ")),
        }
    }

    /// One line per `BilledRate` (§C3.3): `rate <usage type>: card $<card>, billed $<billed> (<pct> %) over
    /// <quantity>`, the rates at 10 decimals, `<pct>` the billed rate's difference from the card's in
    /// percent with its sign and one decimal, the quantity at 3 decimals.
    #[must_use]
    pub fn rate_lines(&self) -> Vec<String> {
        self.rates
            .iter()
            .map(|r| format!("rate {}: card ${:.10}, billed ${:.10} ({:+.1} %) over {:.3}", r.usage_type, r.card, r.billed, (r.billed - r.card) / r.card * 100.0, r.quantity))
            .collect()
    }
}

/// The text form of `ai-env cost` (frozen by `tests/control.rs`' snapshot).
#[must_use]
pub fn render_text(est: &Estimate, t_since: u64, t_until: u64, hint: bool) -> Vec<String> {
    let mut out = Vec::new();
    let one_day = t_since.is_multiple_of(86_400) && t_until == t_since + 86_400;
    out.push(format!("window {} .. {}{}", est.since, est.until, if one_day { " (UTC day; Cost Explorer lags 24–48 h)" } else { "" }));
    if est.vms.is_empty() {
        out.push("no MicroVM ran in the window".to_string());
    } else {
        out.push(format!("{:<46} {:>7} {:>7} {:>6} {:>7} {:>8} {:>9}  NOTE", "VM", "RUN", "SUSP", "STARTS", "RESUMES", "SUSPENDS", "COST"));
        for v in &est.vms {
            out.push(format!("{:<46} {:>7} {:>7} {:>6} {:>7} {:>8} {:>9}  {}", v.id, secs_cell(v.running_s), secs_cell(v.suspended_s), v.starts, v.resumes, v.suspends, format!("${:.3}", v.usd), v.note));
        }
    }
    out.push(format!("{:<46} {:>22} {:>9}", "usage type", "quantity", "cost"));
    for l in &est.lines {
        out.push(format!("{:<46} {:>22} {:>9}", l.usage_type, format!("{:.3} {}", l.quantity, l.unit), format!("${:.3}", l.usd)));
    }
    out.push(format!("estimate ${:.3} (range ${:.3}–{:.3}); not counted: {}", est.usd, est.low_usd, est.high_usd, est.not_estimated.join(", ")));
    // S12 (C1, LD-C14): the live tests' share, each line only when it applies, so S11's text stays without runs.
    if let Some(usd) = est.tests_usd {
        let k = est.vms.iter().filter(|v| v.test.is_some()).count();
        out.push(format!("live tests: {k} VM(s) of {} run(s), ${usd:.3} of the estimate (--no-tests leaves them out)", est.test_runs.len()));
    }
    if est.tests_excluded > 0 {
        out.push(format!("live tests: {} VM(s) left out (--no-tests)", est.tests_excluded));
    }
    if !est.test_runs_unreadable.is_empty() {
        out.push(format!("test runs not read: {}", est.test_runs_unreadable.join("; ")));
    }
    for d in &est.days {
        out.push(format!("day {}  ${:.3} (range ${:.3}–{:.3})  MicroVM ${:.3}  proxy ${:.3}", d.day, d.usd, d.low_usd, d.high_usd, d.microvm_usd, d.proxy_usd));
    }
    if est.proxy_assumed {
        out.push("the proxy: no proxy_start or proxy_stop row, assumed running throughout".to_string());
    }
    if !est.not_counted.is_empty() {
        out.push(format!("not priced (no start row, no VM row): {}", est.not_counted.join(", ")));
    }
    if est.anomalies > 0 {
        out.push(format!("{} contradictory row(s) ignored (anomalies)", est.anomalies));
    }
    out.push("caveats:".to_string());
    out.extend(est.caveats.iter().map(|c| format!("  - {c}")));
    if hint {
        let start = crate::wire::time::rfc3339_utc(t_since - t_since % 86_400)[..10].to_string();
        let end = crate::wire::time::rfc3339_utc(t_until.div_ceil(86_400) * 86_400)[..10].to_string();
        out.push("Cost Explorer (ai-env never calls ce:): with an identity that may call ce:GetCostAndUsage, run".to_string());
        out.push(format!("  {}", ce_command(&start, &end)));
        out.push("then: ai-env cost --compare ce.json".to_string());
    }
    // VM ids are the audit's values: their control characters escaped.
    out.iter().map(|l| crate::bridge::audit::read::terminal_safe(l).into_owned()).collect()
}

/// The most of a `--compare` file read: a Cost Explorer answer of 14 months' days is a few MB.
const COMPARE_MAX_BYTES: u64 = 64 << 20;

/// `--compare`'s file: a regular file (a FIFO or a directory is refused, never waited on) of at most
/// [`COMPARE_MAX_BYTES`].
fn read_compare(file: &Path) -> Result<String, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(file).map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("not a regular file".to_string());
    }
    let mut text = String::new();
    f.take(COMPARE_MAX_BYTES + 1).read_to_string(&mut text).map_err(|e| e.to_string())?;
    if text.len() as u64 > COMPARE_MAX_BYTES {
        return Err(format!("larger than {} MiB: not a Cost Explorer answer", COMPARE_MAX_BYTES >> 20));
    }
    Ok(text)
}

/// `ai-env cost` (B §B3.4, §B3.5): no AWS call, no Touch ID. Exit 2 for an unreadable `<when>`, a window that
/// ends before it starts or an unusable `--compare` file; 1 for an unreadable audit or VM directory of the root, or a
/// comparison whose MicroVM total lies outside the band (whatever becomes of the output). A window reaching past now
/// ends now: what has not happened is not priced. S12 (C1): the live tests' runs are merged, labelled, unless `tests`
/// is `Exclude` (`--no-tests`); a run that cannot be read is named and never an exit, and neither is the proxy's
/// verdict (B Q4).
pub fn cmd_cost(since: Option<&str>, until: Option<&str>, by_day: bool, json: bool, compare_file: Option<&Path>, tests: Tests) -> crate::errors::Result<()> {
    use crate::errors::CliError;
    let paths = Paths::resolve()?;
    let now = crate::bridge::lab::now();
    let ce = match compare_file {
        None => None,
        Some(file) => {
            // With --compare, --since/--until narrow the file to their days (one day of a longer export).
            let narrow = if since.is_some() || until.is_some() {
                let lo = match since {
                    Some(s) => crate::bridge::audit::read::parse_when(s, now).map_err(|e| CliError::Usage(format!("--since: {e}")))?,
                    None => 0,
                };
                let hi = match until {
                    Some(u) => crate::bridge::audit::read::parse_when(u, now).map_err(|e| CliError::Usage(format!("--until: {e}")))?,
                    None => u64::MAX,
                };
                Some((lo, hi))
            } else {
                None
            };
            let text = read_compare(file).map_err(|e| CliError::Usage(format!("--compare {}: {e}", file.display())))?;
            Some(parse_compare_in(&text, narrow).map_err(|e| CliError::Usage(format!("--compare {}: {e}", file.display())))?)
        }
    };
    let (from, asked) = match &ce {
        Some(ce) => (ce.start, ce.end),
        None => {
            let from = crate::bridge::audit::read::parse_when(since.unwrap_or("24h"), now).map_err(|e| CliError::Usage(format!("--since: {e}")))?;
            let to = match until {
                Some(u) => crate::bridge::audit::read::parse_when(u, now).map_err(|e| CliError::Usage(format!("--until: {e}")))?,
                None => now,
            };
            (from, to)
        }
    };
    // `--until` tomorrow ("today so far"), or a Cost Explorer file whose last day is today's: the window ends now.
    let to = asked.min(now);
    if to <= from {
        let (to_s, from_s) = (crate::wire::time::rfc3339_utc(to), crate::wire::time::rfc3339_utc(from));
        let msg = if to < asked { format!("the window's start {from_s} is not before now ({to_s})") } else { format!("the window's end {to_s} is not after its start {from_s}") };
        return Err(CliError::Usage(msg));
    }
    let est = estimate_with(&paths, from, to, by_day, tests)?;
    let judged = ce.as_ref().map(|ce| compare(&est, ce));
    // The verdict is the exit even when the output fails (a reader that closed the pipe early is no pass).
    let printed = print_cost(&est, judged.as_ref(), ce.as_ref(), json, (from, to, to < asked));
    if judged.is_some_and(|j| !j.pass) {
        return Err(CliError::Exit(1));
    }
    printed
}

/// `cmd_cost`'s output: `--json`'s document, or the text and the comparison; `window`: `(from, to, capped at now)`.
fn print_cost(est: &Estimate, judged: Option<&Compared>, ce: Option<&CeAnswer>, json: bool, window: (u64, u64, bool)) -> crate::errors::Result<()> {
    use crate::errors::CliError;
    use crate::outln;
    let (from, to, capped) = window;
    if json {
        /// The estimate's keys in their order, then `compare` (with `--compare`).
        #[derive(Serialize)]
        struct Doc<'a> {
            #[serde(flatten)]
            est: &'a Estimate,
            #[serde(skip_serializing_if = "Option::is_none")]
            compare: Option<serde_json::Value>,
        }
        let doc = Doc { est, compare: judged.map(Compared::json) };
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        let mut lines = render_text(est, from, to, ce.is_none());
        if capped {
            if let Some(first) = lines.first_mut() {
                first.push_str(" (until capped at now)");
            }
        }
        for line in lines {
            outln!("{line}");
        }
        if let (Some(j), Some(ce)) = (judged, ce) {
            for day in &ce.estimated {
                outln!("{day}: Cost Explorer's figures are still estimated");
            }
            outln!("{:<46} {:>10} {:>10} {:>11}", "usage type", "estimate", "actual", "difference");
            for (t, e, a) in &j.lines {
                // The file's usage types: their control characters escaped.
                let t = crate::bridge::audit::read::terminal_safe(t);
                outln!("{t:<46} {:>10} {:>10} {:>11}", format!("${e:.3}"), format!("${a:.3}"), format!("{}${:.3}", if e < a { "-" } else { "+" }, (e - a).abs()));
            }
            outln!("{}", j.verdict());
            // S12 (B Q4): the proxy's verdict and the billed rates, evidence after the exit's verdict.
            outln!("{}", j.proxy_verdict());
            for line in j.rate_lines() {
                outln!("{line}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-22T00:00:00Z, the fixture's day.
    const DAY: u64 = 1_792_627_200;
    const A: &str = "microvm-0a5fc800-0000-4000-8000-00000000000a";
    const B: &str = "microvm-0be03000-0000-4000-8000-00000000000b";

    fn fixture() -> Paths {
        Paths::from_root_and_env(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/s11/bridge"), None)
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// S10 B5 (d): a baseline VM (1 vCPU, 2 GB) running an hour is $0.159.
    #[test]
    fn rates_are_s10_b5d() {
        let hour = 3600.0 * (VCPUS * EUC1.vcpu_second + 2.0 * EUC1.gb_second);
        assert_eq!((hour * 1000.0).round(), 159.0, "{hour}");
        assert!(close(usd(usd_per_hour(2048)), usd(hour)));
        assert!(close(usd(0.123_456_789), 0.123_457));
        assert_eq!(MICROVM_USAGE.len(), 5);
        assert!(MICROVM_USAGE.iter().all(|t| t.starts_with("EUC1-Lambda-MicroVM-")));
    }

    /// The fixture's day priced by hand: A 4870 s running and 3600 s suspended (1 start, 2 resumes, 2 inferred
    /// suspends), B 2370 s and 3600 s (1 start, 1 suspend), the proxy 12 h; the range moves A's two inferred
    /// suspends to their last activity (low) and to the next evidence or twice the idle time (high).
    #[test]
    fn fixture_estimate_and_range() {
        let est = estimate_for(&fixture(), DAY, DAY + 86_400, false).unwrap();
        let rate = EUC1.vcpu_second + 2.0 * EUC1.gb_second;
        let snap = |writes: f64, reads: f64, susp_s: f64| writes * 2.0 * EUC1.snapshot_write_gb + reads * 2.0 * EUC1.snapshot_read_gb + susp_s / 3600.0 * 2.0 * EUC1.snapshot_storage_gb_hour;
        let a = 4870.0 * rate + snap(2.0, 3.0, 3600.0);
        let a_low = 4270.0 * rate + snap(2.0, 3.0, 4200.0);
        let a_high = 5470.0 * rate + snap(2.0, 3.0, 3000.0);
        let b = 2370.0 * rate + snap(1.0, 1.0, 3600.0);
        let vms: Vec<(&str, u64, u64, u32, u32, u32, u32)> = est.vms.iter().map(|v| (v.id.as_str(), v.running_s, v.suspended_s, v.starts, v.resumes, v.suspends, v.inferred_suspends)).collect();
        assert_eq!(vms, [(A, 4870, 3600, 1, 2, 2, 2), (B, 2370, 3600, 1, 0, 1, 0)]);
        assert!(close(est.vms[0].usd, usd(a)) && close(est.vms[0].low_usd, usd(a_low)) && close(est.vms[0].high_usd, usd(a_high)), "{:?}", est.vms[0]);
        assert!(close(est.vms[1].usd, usd(b)) && close(est.vms[1].low_usd, usd(b)), "{:?}", est.vms[1]);
        assert_eq!(est.vms[0].note, "2 idle suspends inferred; 1 auto-resume inferred; terminated (migrate)");
        let proxy = 12.0 * (EUC1.t4g_nano_hour + EUC1.public_ipv4_hour) + PROXY_VOLUME_GB * 24.0 / HOURS_PER_MONTH * EUC1.gp3_gb_month;
        let microvm = a + b + IMAGE_SNAPSHOT_USD_PER_DAY;
        // The totals add the lines as printed (each rounded to 6 decimals): within a few millionths of the sums.
        let near = |x: f64, y: f64| (x - y).abs() < 5e-6;
        assert!(near(est.microvm_usd, microvm) && near(est.proxy_usd, proxy), "{} {}", est.microvm_usd, est.proxy_usd);
        assert!(near(est.usd, microvm + proxy) && near(est.low_usd, microvm + proxy + a_low - a) && near(est.high_usd, microvm + proxy + a_high - a), "{est:#?}");
        assert_eq!((est.usd, est.low_usd, est.high_usd), (0.530_348, 0.503_835, 0.556_861));
        let q: Vec<(&str, f64)> = est.lines.iter().map(|l| (l.usage_type, l.quantity)).collect();
        assert_eq!(q[..4], [(USAGE_VCPU, 7240.0), (USAGE_MEMORY, 14_480.0), (USAGE_SNAPSHOT_WRITE, 6.0), (USAGE_SNAPSHOT_READ, 8.0)]);
        assert_eq!(q[5..7], [(USAGE_T4G_NANO, 12.0), (USAGE_IPV4, 12.0)]);
        assert!(close(est.lines.iter().map(|l| l.usd).sum::<f64>(), est.usd) || (est.lines.iter().map(|l| l.usd).sum::<f64>() - est.usd).abs() < 1e-5);
        assert_eq!((est.proxy_assumed, est.anomalies, est.not_counted.len(), est.caveats.len(), est.not_estimated.clone()), (false, 0, 0, 8, vec!["S3", "CloudWatch", "data transfer"]));
        assert_eq!((est.since.as_str(), est.until.as_str(), est.rates), ("2026-10-22T00:00:00Z", "2026-10-23T00:00:00Z", "EUC1 2026-10-23"));
        // vm list's cell: B over its life to 11:30, its suspend's end beyond it, not inferred there.
        let t = timeline_for(&fixture(), 0, DAY + 11 * 3600 + 1800).unwrap();
        let cell = vm_cell(&t, B).unwrap();
        assert_eq!((cell.running_s, cell.suspended_s, cell.inferred), (2370, 1800, false));
        assert!(close(cell.usd, usd(2370.0 * rate + snap(1.0, 1.0, 1800.0))), "{cell:?}");
        assert!(vm_cell(&t, "microvm-none").is_none());
    }

    fn ce(groups: &[(&str, &str)], grouped_by: &str, estimated: bool) -> String {
        let groups: Vec<serde_json::Value> = groups.iter().map(|(k, a)| serde_json::json!({ "Keys": [k], "Metrics": { "UnblendedCost": { "Amount": a, "Unit": "USD" }, "UsageQuantity": { "Amount": "1", "Unit": "N/A" } } })).collect();
        serde_json::json!({
            "GroupDefinitions": [{ "Type": "DIMENSION", "Key": grouped_by }],
            "ResultsByTime": [{ "TimePeriod": { "Start": "2026-10-22", "End": "2026-10-23" }, "Total": {}, "Groups": groups, "Estimated": estimated }],
            "DimensionValueAttributes": []
        })
        .to_string()
    }

    /// `--compare`: the window is the file's; the MicroVM total passes within ±30 % of Cost Explorer's and fails
    /// outside; a file grouped otherwise or without UnblendedCost is refused naming the command.
    #[test]
    fn compare_judges_30_percent() {
        let file = ce(&[(USAGE_VCPU, "0.30"), (USAGE_MEMORY, "0.07"), ("EUC1-Requests-Tier1", "0.01")], "USAGE_TYPE", true);
        let answer = parse_compare(&file).unwrap();
        assert_eq!((answer.start, answer.end, answer.estimated.clone()), (DAY, DAY + 86_400, vec!["2026-10-22".to_string()]));
        let est = estimate_for(&fixture(), answer.start, answer.end, true).unwrap();
        let judged = compare(&est, &answer);
        assert!(close(judged.actual_usd, 0.37) && close(judged.estimate_usd, est.microvm_usd), "{judged:?}");
        assert!(judged.pass, "{} vs 0.37: {judged:?}", est.microvm_usd);
        assert!(judged.lines.iter().any(|(t, e, a)| t == "EUC1-Requests-Tier1" && *e == 0.0 && close(*a, 0.01)), "the file's other types are listed");
        assert!(judged.verdict().starts_with("MicroVM total: estimate $0.388, Cost Explorer $0.370: ") && judged.verdict().ends_with("% off: within ±30 %"), "{}", judged.verdict());
        let far = parse_compare(&ce(&[(USAGE_VCPU, "1.20")], "USAGE_TYPE", false)).unwrap();
        let judged = compare(&est, &far);
        assert!(!judged.pass && judged.verdict().ends_with("outside ±30 %"), "{judged:?}");
        assert_eq!(judged.json()["microvm"]["pass"], false);
        assert!(!compare(&est, &parse_compare(&ce(&[], "USAGE_TYPE", false)).unwrap()).pass, "no actual cost: nothing to judge by");
        for bad in [ce(&[(USAGE_VCPU, "0.3")], "SERVICE", false), r#"{"GroupDefinitions":[{"Key":"USAGE_TYPE"}],"ResultsByTime":[{"TimePeriod":{"Start":"2026-10-22","End":"2026-10-23"},"Groups":[{"Keys":["x"],"Metrics":{"BlendedCost":{"Amount":"1"}}}]}]}"#.to_string(), "[]".to_string()] {
            let e = parse_compare(&bad).unwrap_err();
            assert!(e.contains("aws ce get-cost-and-usage --region us-east-1"), "{e}");
        }
    }

    /// The console's CSV (S10 B5 (d)'s export, its figures): types summed over its days, the BOM and the
    /// totals row and column ignored; `--since`/`--until` keep one day; malformed files refused.
    #[test]
    fn the_console_csv_compares_by_usage_type_and_day() {
        let csv = "\u{feff}\"Usage type\",\"EUC1-Lambda-MicroVM-vCPU-Second-ARM($)\",\"EUC1-Lambda-MicroVM-Memory-GB-Second-ARM($)\",\"EUC1-USE1-AWS-Out-Bytes($)\",\"Total costs($)\"\n\
            \"Usage type total\",\"0.2913054441\",\"0.0766781932\",\"6.52e-8\",\"0.3679836373\"\n\
            \"2026-10-21\",\"0.0425060716\",\"0.0110915688\",\"0.0000000652\",\"0.0535976404\"\n\
            \"2026-10-22\",\"0.2487993725\",\"0.0655866244\",\"\",\"0.3143859969\"\n";
        let (d21, d22, d23) = (day_start("2026-10-21").unwrap(), day_start("2026-10-22").unwrap(), day_start("2026-10-23").unwrap());
        let all = parse_compare(csv).unwrap();
        assert_eq!((all.start, all.end), (d21, d23));
        assert!(close(all.by_type[USAGE_VCPU], 0.2913054441) && close(all.by_type[USAGE_MEMORY], 0.0766781932), "{all:?}");
        assert!(!all.by_type.contains_key("Total costs") && all.estimated.is_empty(), "{all:?}");
        let one = parse_compare_in(csv, Some((d22, d23))).unwrap();
        assert_eq!((one.start, one.end), (d22, d23));
        assert!(close(one.by_type[USAGE_VCPU], 0.2487993725) && !one.by_type.contains_key("EUC1-USE1-AWS-Out-Bytes"), "{one:?}");
        assert!(parse_compare_in(csv, Some((d23, d23 + 86_400))).unwrap_err().contains("no day within"));
        for bad in ["\"Usage type\",\"x($)\"\n\"not a day\",\"1\"\n", "\"Usage type\",\"x($)\"\n\"2026-10-22\",\"one\"\n", "\"Usage type\",\"x($)\"\n\"2026-10-22,\"1\"\n"] {
            assert!(parse_compare(bad).is_err(), "{bad}");
        }
        let json_one = parse_compare_in(&ce(&[(USAGE_VCPU, "0.30")], "USAGE_TYPE", false), Some((d22, d23))).unwrap();
        assert!(close(json_one.by_type[USAGE_VCPU], 0.30));
        assert!(parse_compare_in(&ce(&[(USAGE_VCPU, "0.30")], "USAGE_TYPE", false), Some((d21, d22))).is_err());
    }

    /// `--by day` splits the window at UTC midnights: each day priced alone, the days summing to the window.
    #[test]
    fn by_day_splits_at_utc_midnight() {
        let (since, until) = (DAY + 6 * 3600, DAY + 86_400 + 6 * 3600);
        let est = estimate_for(&fixture(), since, until, true).unwrap();
        let days: Vec<&str> = est.days.iter().map(|d| d.day.as_str()).collect();
        assert_eq!(days, ["2026-10-22", "2026-10-23"]);
        let sum = |f: &dyn Fn(&Day) -> f64| est.days.iter().map(f).sum::<f64>();
        assert!((sum(&|d| d.usd) - est.usd).abs() < 1e-5 && (sum(&|d| d.low_usd) - est.low_usd).abs() < 1e-5 && (sum(&|d| d.high_usd) - est.high_usd).abs() < 1e-5, "{est:#?}");
        let second = &est.days[1];
        assert!(close(second.microvm_usd, usd(IMAGE_SNAPSHOT_USD_PER_DAY * 0.25)), "6 h of image storage, no VM: {second:?}");
        assert!(close(second.proxy_usd, usd(PROXY_VOLUME_GB * 6.0 / HOURS_PER_MONTH * EUC1.gp3_gb_month)), "the volume only: {second:?}");
        let first = estimate_for(&fixture(), since, DAY + 86_400, false).unwrap();
        assert!(close(est.days[0].usd, first.usd) && est.days[0].lines == first.lines, "{:?} vs {:?}", est.days[0], first);
        assert!(estimate_for(&fixture(), since, until, false).unwrap().days.is_empty(), "no days without --by day");
    }

    // ---- S12 (C): the live tests' runs, B Q4 and the measured sleep (plans/s12-contracts.md §6) ----

    /// §C10.1's TV: a live test's VM of the fixture's day.
    const TV: &str = "microvm-0e570000-0000-4000-8000-00000000000e";

    /// A v2 audit line of `event` at `t`.
    fn audit_line(t: u64, event: &str, detail: &[(&str, &str)]) -> String {
        let mut d = serde_json::Map::new();
        d.insert("actor".into(), "cli".into());
        for (k, v) in detail {
            d.insert((*k).into(), (*v).into());
        }
        serde_json::json!({ "v": 2, "ts": crate::wire::time::rfc3339_utc(t), "event": event, "session_id": null, "pid": 5150, "detail": d }).to_string()
    }

    /// `from`'s tree copied to `to`.
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap().flatten() {
            let (src, dst) = (e.path(), to.join(e.file_name()));
            if e.file_type().unwrap().is_dir() {
                copy_tree(&src, &dst);
            } else {
                std::fs::copy(&src, &dst).unwrap();
            }
        }
    }

    /// §C10.1: TV's run, archived into `world` by the real writer (LD-C15) from a test root of its own: TV's
    /// `vm_run` at 12:00 (`max_idle_s` 300, `suspended_s` 3600), a `proxy_stop` at 12:00 (merged, it would cut
    /// the fixture's proxy hours from 12 to 5), its `vm_terminate` by `test` at 12:30, and TV's row with a
    /// session token and a commit made at run time.
    fn tv_run(world: &Paths) -> std::path::PathBuf {
        use crate::bridge::vm::registry::{write_row, IdleRow, RowStatus, VmRow};
        let t = tempfile::tempdir().unwrap();
        let test = Paths::from_root_and_env(t.path().to_path_buf(), None);
        let noon = DAY + 12 * 3600;
        let lines = [
            audit_line(noon, "vm_run", &[("id", TV), ("purpose", "test"), ("image_version", "13.0"), ("egress", "internet"), ("shell", "false"), ("client_token", "0199f0e5-0000-7000-8000-00000000000e"), ("max_duration_s", "3600"), ("max_idle_s", "300"), ("suspended_s", "3600"), ("memory_mib", "2048")]),
            audit_line(noon, "proxy_stop", &[("instance", "i-0test"), ("vpc_vms", "0")]),
            audit_line(noon + 1800, "vm_terminate", &[("id", TV), ("by", "test")]),
        ];
        std::fs::write(test.audit(), lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
        let nonce = uuid::Uuid::now_v7().simple().to_string();
        let row = VmRow {
            v: 1,
            status: RowStatus::Terminated,
            id: TV.into(),
            session_token: Some(format!("{}{nonce}", "ab".repeat(16))),
            commit: format!("{}{nonce}", "cd".repeat(16)),
            started_at: Some(noon),
            wall_deadline: Some(noon + 3600),
            max_duration_s: 3600,
            idle: Some(IdleRow { max_idle_s: 300, suspended_s: 3600, auto_resume: true }),
            terminated_at: Some(noon + 1800),
            terminated_by: Some("test".into()),
            ..VmRow::default()
        };
        write_row(&test, &row).unwrap();
        crate::bridge::testruns::archive(&test, world, "live_vm_lifecycle", DAY + 13 * 3600).unwrap().expect("TV's run")
    }

    /// S12 (C1, §C2.3): TV's run, archived into a copy of the fixture's root, merges into its day: A, B and
    /// TV, TV labelled with its test, the run and its dollars named, the proxy the root's (the run kept no
    /// `proxy_stop`); `--no-tests` is the root's estimate with TV counted; the views' timeline never sees it
    /// (M-C5, M-C6, M-C7). LD-C5, with ids in two places: a second run, later by name, holds TV's row again
    /// and copies of A's and B's rows whose times differ from the root's. The root's row wins (A and B
    /// priced as before, M-C25), the first run by name labels a VM (TV keeps its test, M-C26), and the
    /// second labels A and B; `--no-tests` still prices A and B, so only TV is left out (LD-C6 as amended,
    /// M-C29), and a run holding only a VM the root holds leaves nothing out.
    #[test]
    fn the_live_tests_runs_merge_labelled_and_no_tests_counts_them() {
        use crate::bridge::vm::registry::{list_rows, write_row, VmRow};
        let dir = tempfile::tempdir().unwrap();
        copy_tree(&fixture().root, dir.path());
        let world = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let run = tv_run(&world);
        let name = run.file_name().unwrap().to_string_lossy().into_owned();
        let base = estimate_for(&fixture(), DAY, DAY + 86_400, false).unwrap();
        let merged = estimate_with(&world, DAY, DAY + 86_400, false, Tests::Merge).unwrap();
        assert_eq!(merged, estimate_for(&world, DAY, DAY + 86_400, false).unwrap(), "estimate_for (the panel's) merges");
        assert_eq!(merged.vms.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(), [A, B, TV]);
        assert_eq!(merged.vms[..2], base.vms[..], "the root's own VMs as they were, unlabelled");
        let tv = &merged.vms[2];
        assert_eq!((tv.running_s, tv.suspended_s, tv.starts, tv.resumes, tv.suspends, tv.inferred_suspends), (300, 1500, 1, 0, 1, 1), "{tv:?}");
        assert_eq!((tv.test.as_deref(), tv.note.as_str(), tv.usd), (Some("live_vm_lifecycle"), "live test live_vm_lifecycle; 1 idle suspend inferred; terminated (test)", 0.027_311));
        assert_eq!((merged.test_runs.clone(), merged.tests_usd, merged.tests_excluded, merged.test_runs_unreadable.clone()), (vec![name.clone()], Some(0.027_311), 0, Vec::<String>::new()));
        assert!((merged.usd - (base.usd + tv.usd)).abs() < 1e-5, "{} vs {} + {}", merged.usd, base.usd, tv.usd);
        assert_eq!((merged.proxy_usd, merged.proxy_assumed), (base.proxy_usd, base.proxy_assumed), "the test's proxy_stop is never merged");
        // --no-tests: the root's own estimate, TV counted as left out.
        let mut want = base.clone();
        want.tests_excluded = 1;
        assert_eq!(estimate_with(&world, DAY, DAY + 86_400, false, Tests::Exclude).unwrap(), want);
        // The views read the root alone.
        let t = timeline_for(&world, DAY, DAY + 86_400).unwrap();
        assert!(t.vms.iter().all(|v| v.vm != TV) && !t.not_counted.iter().any(|v| v == TV), "{t:#?}");
        // A window the run's VM is not in: nothing labelled, nothing left out.
        let next = (DAY + 86_400, DAY + 2 * 86_400);
        let later = estimate_with(&world, next.0, next.1, false, Tests::Merge).unwrap();
        assert!(later.vms.iter().all(|v| v.test.is_none()) && later.test_runs.is_empty() && later.tests_usd.is_none(), "{later:?}");
        assert_eq!(estimate_with(&world, next.0, next.1, false, Tests::Exclude).unwrap().tests_excluded, 0);
        // LD-C5: a second run, later by name and with no audit row, holding TV's row again and stripped copies of A's row
        // ending an hour earlier and of B's starting an hour earlier (as a test's row of a VM the root's `vm gc` took).
        let roots = list_rows(&world).unwrap();
        let copy = |id: &str| roots.iter().find(|r| r.id == id).map(crate::bridge::testruns::strip).unwrap();
        let t2 = tempfile::tempdir().unwrap();
        let second = Paths::from_root_and_env(t2.path().to_path_buf(), None);
        let tv_row = list_rows(&Paths::from_root_and_env(run.clone(), None)).unwrap().remove(0);
        let a = VmRow { terminated_at: copy(A).terminated_at.map(|t| t - 3600), ..copy(A) };
        let b = VmRow { started_at: copy(B).started_at.map(|t| t - 3600), ..copy(B) };
        for row in [&tv_row, &a, &b] {
            write_row(&second, row).unwrap();
        }
        let run2 = crate::bridge::testruns::archive(&second, &world, "zz_second", DAY + 14 * 3600).unwrap().expect("the second run");
        let name2 = run2.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name < name2, "{name} sorts first");
        let both = estimate_with(&world, DAY, DAY + 86_400, false, Tests::Merge).unwrap();
        assert_eq!(both.vms.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(), [A, B, TV]);
        for (v, was) in both.vms[..2].iter().zip(&base.vms) {
            assert_eq!((v.running_s, v.suspended_s, v.usd, v.low_usd, v.high_usd), (was.running_s, was.suspended_s, was.usd, was.low_usd, was.high_usd), "{}: the root's row wins", v.id);
            assert_eq!((v.test.as_deref(), v.note.strip_prefix("live test zz_second; ")), (Some("zz_second"), Some(was.note.as_str())), "{}: labelled by the run holding its row", v.id);
        }
        assert_eq!(both.vms[2], merged.vms[2], "TV as before: the first run by name labels it");
        assert_eq!(both.test_runs, [name.clone(), name2]);
        assert!(both.tests_usd.is_some_and(|u| close(u, usd(base.vms[0].usd + base.vms[1].usd + tv.usd))), "{:?}", both.tests_usd);
        assert!(close(both.usd, merged.usd), "{} vs {}", both.usd, merged.usd);
        assert_eq!(estimate_with(&world, DAY, DAY + 86_400, false, Tests::Exclude).unwrap(), want, "the root prices A and B: TV alone is left out");
        // A run holding only a VM the root holds: --no-tests leaves nothing out.
        let d3 = tempfile::tempdir().unwrap();
        copy_tree(&fixture().root, d3.path());
        let only = Paths::from_root_and_env(d3.path().to_path_buf(), None);
        let t3 = tempfile::tempdir().unwrap();
        let third = Paths::from_root_and_env(t3.path().to_path_buf(), None);
        write_row(&third, &copy(A)).unwrap();
        crate::bridge::testruns::archive(&third, &only, "a_copy", DAY + 14 * 3600).unwrap().expect("A's copy's run");
        assert_eq!(estimate_with(&only, DAY, DAY + 86_400, false, Tests::Exclude).unwrap(), base);
    }

    /// One Cost Explorer group: `(usage type, UnblendedCost, UsageQuantity)`, the quantity left out when `None`.
    type Group<'a> = (&'a str, &'a str, Option<&'a str>);

    /// A Cost Explorer JSON of `days`, each `(start, end, groups)`.
    fn ce_days(days: &[(&str, &str, &[Group<'_>])]) -> String {
        let periods: Vec<serde_json::Value> = days
            .iter()
            .map(|(start, end, groups)| {
                let groups: Vec<serde_json::Value> = groups
                    .iter()
                    .map(|(k, a, q)| {
                        let mut metrics = serde_json::json!({ "UnblendedCost": { "Amount": a, "Unit": "USD" } });
                        if let Some(q) = q {
                            metrics["UsageQuantity"] = serde_json::json!({ "Amount": q, "Unit": "N/A" });
                        }
                        serde_json::json!({ "Keys": [k], "Metrics": metrics })
                    })
                    .collect();
                serde_json::json!({ "TimePeriod": { "Start": start, "End": end }, "Total": {}, "Groups": groups, "Estimated": false })
            })
            .collect();
        serde_json::json!({ "GroupDefinitions": [{ "Type": "DIMENSION", "Key": "USAGE_TYPE" }], "ResultsByTime": periods, "DimensionValueAttributes": [] }).to_string()
    }

    /// S12 (B Q4, §C3.2 rule 2): the proxy is judged over the proxy types the file holds, at the MicroVM
    /// total's band and rule; with none there is no verdict and the line says what to export; its verdict
    /// never decides `pass`; the console's CSV is judged too, with no rate (M-C19).
    #[test]
    fn compare_judges_the_proxy_over_the_ec2_lines_the_file_holds() {
        let est = estimate_for(&fixture(), DAY, DAY + 86_400, false).unwrap();
        let day = |groups: &[Group<'_>]| compare(&est, &parse_compare(&ce_days(&[("2026-10-22", "2026-10-23", groups)])).unwrap());
        let (vcpu, memory) = ((USAGE_VCPU, "0.30", None), (USAGE_MEMORY, "0.07", None));
        let all = day(&[vcpu, memory, (USAGE_T4G_NANO, "0.0576", None), (USAGE_IPV4, "0.06", None), (USAGE_GP3, "0.025", None)]);
        let proxy = all.proxy.clone().expect("judged");
        assert_eq!((proxy.types.clone(), proxy.estimate_usd, proxy.actual_usd, proxy.off_pct, proxy.pass), (PROXY_USAGE.to_vec(), 0.142_639, 0.1426, Some(0.0), true));
        assert_eq!(all.proxy_verdict(), "proxy total (EUC1-BoxUsage:t4g.nano, EUC1-PublicIPv4:InUseAddress, EUC1-EBS:VolumeUsage.gp3): estimate $0.143, Cost Explorer $0.143: 0.0 % off: within ±30 % (evidence, not the exit)");
        assert!(all.pass, "the MicroVM total: {all:?}");
        assert_eq!(all.json()["proxy"], serde_json::json!({ "types": PROXY_USAGE, "estimate_usd": 0.142_639, "actual_usd": 0.1426, "off_pct": 0.0, "pass": true }));
        assert_eq!(all.json()["rates"], serde_json::json!([]), "no quantity, no rate");
        // Two of the three, whatever the file's order: those two in PROXY_USAGE's, their lines' sum.
        let two = day(&[vcpu, (USAGE_GP3, "0.025", None), (USAGE_T4G_NANO, "0.0576", None)]);
        let proxy = two.proxy.clone().expect("judged");
        assert_eq!((proxy.types.clone(), proxy.estimate_usd, proxy.actual_usd), (vec![USAGE_T4G_NANO, USAGE_GP3], usd(0.0576 + 0.025_039), usd(0.0576 + 0.025)));
        // No EC2 line: no verdict, and the line names the export.
        let none = day(&[vcpu, memory]);
        assert_eq!(none.proxy, None);
        assert_eq!(none.proxy_verdict(), "proxy total: the file holds none of EUC1-BoxUsage:t4g.nano, EUC1-PublicIPv4:InUseAddress, EUC1-EBS:VolumeUsage.gp3 (export EC2-Instances, EC2-Other and VPC too)");
        assert_eq!(none.json()["proxy"], serde_json::Value::Null);
        // The proxy outside its band is evidence: `pass` stays the MicroVM total's, its line unchanged.
        let far = day(&[vcpu, memory, (USAGE_T4G_NANO, "1.00", None)]);
        assert!(far.pass && far.proxy.as_ref().is_some_and(|p| !p.pass && p.off_pct == Some(-94.2)), "{far:?}");
        assert_eq!(far.proxy_verdict(), "proxy total (EUC1-BoxUsage:t4g.nano): estimate $0.058, Cost Explorer $1.000: 94.2 % off: outside ±30 % (evidence, not the exit)");
        assert_eq!(far.verdict(), none.verdict());
        // The console's CSV: judged; it holds no quantity, so no rate.
        let csv = "\"Usage type\",\"EUC1-Lambda-MicroVM-vCPU-Second-ARM($)\",\"EUC1-BoxUsage:t4g.nano($)\",\"Total costs($)\"\n\"2026-10-22\",\"0.30\",\"0.0576\",\"0.3576\"\n";
        let console = compare(&est, &parse_compare(csv).unwrap());
        assert!(console.proxy.as_ref().is_some_and(|p| p.types == [USAGE_T4G_NANO] && p.pass && p.off_pct == Some(0.0)), "{console:?}");
        assert!(console.rates.is_empty(), "{console:?}");
    }

    /// S12 (B Q4, §C3.2 rules 1 and 3): each priced type the file has a positive quantity of gets the card's
    /// rate against the billed one, its cost over its quantity, both summed over the file's days, in the
    /// estimate's lines' order; a zero quantity, an unpriced type and an unusable quantity get none (M-C21).
    #[test]
    fn billed_rates_divide_the_cost_by_its_quantity() {
        let est = estimate_for(&fixture(), DAY, DAY + 86_400, false).unwrap();
        let file = ce_days(&[
            ("2026-10-22", "2026-10-23", &[(USAGE_T4G_NANO, "0.0576", Some("12")), (USAGE_VCPU, "0.1265", Some("3620")), (USAGE_GP3, "0.0125", Some("0")), ("EUC1-Requests-Tier1", "0.01", Some("1")), (USAGE_MEMORY, "0.03", Some("lots"))]),
            ("2026-10-23", "2026-10-24", &[(USAGE_VCPU, "0.1265", Some("3620")), (USAGE_T4G_NANO, "0.0576", Some("12")), (USAGE_GP3, "0.0125", None), (USAGE_MEMORY, "0.03", None)]),
        ]);
        let answer = parse_compare(&file).unwrap();
        let q: Vec<(&str, f64)> = answer.quantity.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        assert_eq!(q, [("EUC1-BoxUsage:t4g.nano", 24.0), ("EUC1-EBS:VolumeUsage.gp3", 0.0), ("EUC1-Lambda-MicroVM-vCPU-Second-ARM", 7240.0), ("EUC1-Requests-Tier1", 1.0)], "summed over both days; an unusable or missing quantity adds nothing");
        let judged = compare(&est, &answer);
        assert_eq!(judged.rates.iter().map(|r| r.usage_type).collect::<Vec<_>>(), [USAGE_VCPU, USAGE_T4G_NANO], "the lines' order; no rate for gp3's zero or an unpriced type");
        let (v, t) = (&judged.rates[0], &judged.rates[1]);
        assert_eq!((v.card, v.quantity, t.card, t.quantity), (EUC1.vcpu_second, 7240.0, EUC1.t4g_nano_hour, 24.0));
        assert!(close(v.billed, 0.2530 / 7240.0) && close(t.billed, 0.0048), "{judged:?}");
        assert_eq!(
            judged.rate_lines(),
            [
                "rate EUC1-Lambda-MicroVM-vCPU-Second-ARM: card $0.0000349960, billed $0.0000349448 (-0.1 %) over 7240.000",
                "rate EUC1-BoxUsage:t4g.nano: card $0.0048000000, billed $0.0048000000 (+0.0 %) over 24.000",
            ]
        );
        assert_eq!(judged.json()["rates"][1], serde_json::json!({ "usage_type": USAGE_T4G_NANO, "card": 0.0048, "billed": t.billed, "quantity": 24.0 }));
    }

    /// S12 (C3, §C4.3): a sleep measured by the wrapper's reconnect prices X suspended from `max_idle_s` after
    /// the lid closed (the point) within its range (the close and twice the idle time); S11 priced all
    /// 2200 s as running (M-C9, M-C16).
    #[test]
    fn a_measured_sleep_prices_the_vm_suspended_within_its_range() {
        const X: &str = "microvm-0c000000-0000-4000-8000-00000000000c";
        let t0 = DAY + 14 * 3600;
        let lines = [
            audit_line(t0, "vm_run", &[("id", X), ("purpose", "session"), ("image_version", "13.0"), ("egress", "internet"), ("shell", "false"), ("client_token", "0199f0e5-0000-7000-8000-0000000000c1"), ("max_idle_s", "300"), ("memory_mib", "2048")]),
            audit_line(t0 + 10, "session_remote_start", &[("id", X), ("spawn", "s1"), ("gen", "1"), ("why", "first")]),
            audit_line(t0 + 2003, "agent_reconnect", &[("id", X), ("spawn", "s1"), ("reason", "woke after 1800.0 s asleep"), ("ms", "2500")]),
            audit_line(t0 + 2100, "session_remote_end", &[("vm", X), ("spawn", "s1"), ("gen", "1"), ("exit", "0"), ("end", "close"), ("close_ms", "20"), ("last_acked_seq", "3")]),
            audit_line(t0 + 2200, "vm_terminate", &[("id", X), ("by", "operator")]),
        ];
        let rows: Vec<crate::bridge::audit::read::Read> = lines.iter().map(|l| crate::bridge::audit::read::parse_line(l).unwrap()).collect();
        let defaults = VmDefaults { memory_mib: 2048, max_idle_s: 300, suspended_s: None, max_duration_s: 28_800 };
        let t = crate::bridge::timeline::build(&rows, &[], defaults, t0, t0 + 3000);
        let est = estimate(&t, &EUC1, false);
        let v = &est.vms[0];
        let at = |which: Which| {
            let u = use_of(&t, &t.vms[0], which, t0, t0 + 3000);
            (u.running_s, u.suspended_s)
        };
        assert_eq!([(v.running_s, v.suspended_s), at(Which::Low), at(Which::High)], [(697, 1503), (397, 1803), (997, 1203)], "{:#?}", t.vms[0]);
        assert_eq!((v.starts, v.resumes, v.suspends, v.inferred_suspends), (1, 1, 1, 1));
        assert_eq!(v.note, "1 idle suspend inferred; 1 auto-resume inferred; terminated (operator)");
        // Use's formula (one start and one resume read, one suspend writes; 2 GB of memory).
        let priced = |running: f64, suspended: f64| {
            running * VCPUS * EUC1.vcpu_second + running * 2048.0 / 1024.0 * EUC1.gb_second + SUSPEND_WRITE_GB * EUC1.snapshot_write_gb + (START_READ_GB + RESUME_READ_GB) * EUC1.snapshot_read_gb + suspended / 3600.0 * SUSPENDED_GB * EUC1.snapshot_storage_gb_hour
        };
        assert!(close(v.usd, usd(priced(697.0, 1503.0))) && close(v.low_usd, usd(priced(397.0, 1803.0))) && close(v.high_usd, usd(priced(997.0, 1203.0))), "{v:?}");
    }
}
