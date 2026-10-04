//! Clock, entropy and boot facts for the hooks, behind [`SysOps`] so the hook
//! tests never touch the real clock or the kernel pool.
//!
//! A VM restored from the image snapshot keeps the snapshot's wall clock and
//! the snapshot's RNG state, identically in every clone. S3 v0 therefore
//! MEASURES the clock (guest time, the PL031 RTC, the payload's `created`)
//! and only steps it under `--clock forward`. Plan S6 D7: `--clock measure`
//! stays; S6's `clock-after-resume` probe measures the drift, and a
//! follow-up decides only beyond ±2 s. Entropy: `/run` mixes per-VM material
//! into `/dev/urandom` and attempts `RNDRESEEDCRNG` (needs CAP_SYS_ADMIN;
//! logged, never fatal); the boot nonce does not depend on either.
//!
//! The run report (plan S4 D19) is logged once after the first accepted
//! `/run` and once at `/terminate`: what the VM looks like from inside
//! (boot id, disk, PID 1's environment by NAME, zombies), for the
//! `runtime-env`, `disk-budget` and `snapshot-uniqueness` probes.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// A drift below this is left alone even under `--clock forward`.
pub const STEP_THRESHOLD_S: u64 = 2;

/// The PL031 RTC as the kernel exposes it: seconds since the epoch, readable
/// without any tool (the guest's `date` is the snapshot's).
pub const RTC_PATH: &str = "/sys/class/rtc/rtc0/since_epoch";

/// `_IO('R', 0x07)`: reseed the CRNG from the input pool (Linux ≥ 5.x; not in
/// the libc crate).
#[cfg(target_os = "linux")]
const RNDRESEEDCRNG: libc::c_ulong = 0x5207;

/// Capability bit numbers (linux/capability.h).
const CAP_CHOWN: u32 = 0;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_SYS_TIME: u32 = 25;

/// What dropping the claude probe (and later the agent) to `uid:gid` needs:
/// chown its HOME, then setgid and setuid in the child.
const DROP_CAPS: [(u32, &str); 3] = [(CAP_CHOWN, "CAP_CHOWN"), (CAP_SETGID, "CAP_SETGID"), (CAP_SETUID, "CAP_SETUID")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ClockMode {
    /// Log guest clock, RTC and drift; never step (S3 v0)
    Measure,
    /// Step the clock forward to the RTC (and the payload's `created`) when it lags by more than 2 s
    Forward,
}

/// The target a forward step would set, or `None`. Pure: `now` is the guest
/// wall clock, `rtc` the RTC, `lower_bound` the payload's `created` (the Mac
/// minted it, so the guest cannot be earlier). Never steps backwards; a lag
/// of at most [`STEP_THRESHOLD_S`] is left alone.
#[must_use]
pub fn decide_step(now: u64, rtc: Option<u64>, lower_bound: Option<u64>) -> Option<u64> {
    let target = rtc.unwrap_or(0).max(lower_bound.unwrap_or(0));
    (target > now.saturating_add(STEP_THRESHOLD_S)).then_some(target)
}

/// The per-boot nonce `/health` and `hello_ok` report: the first 16 bytes of
/// SHA-256 over fresh kernel bytes, the VM id, the `/run` body hash and both
/// clocks, as 32 lowercase hex digits. Distinct per clone even if the kernel
/// bytes were not (the VM id differs), and independent of the reseed.
#[must_use]
pub fn nonce_from(kernel: &[u8; 32], microvm_id: &str, body_sha256: &[u8; 32], now_ns: u128, rtc: Option<u64>) -> String {
    let mut h = Sha256::new();
    h.update(b"ai-env boot nonce v1\0");
    h.update(kernel);
    h.update((microvm_id.len() as u64).to_be_bytes());
    h.update(microvm_id.as_bytes());
    h.update(body_sha256);
    h.update(now_ns.to_be_bytes());
    h.update(rtc.unwrap_or(0).to_be_bytes());
    hex::encode(&h.finalize()[..16])
}

/// `CapEff:` of a `/proc/<pid>/status` text.
#[must_use]
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    let v = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?.trim();
    u64::from_str_radix(v, 16).ok()
}

#[must_use]
pub fn has_cap(cap_eff: u64, bit: u32) -> bool {
    cap_eff & (1u64 << bit) != 0
}

/// The capabilities the privilege drop needs that `cap_eff` lacks, by name.
#[must_use]
pub fn missing_drop_caps(cap_eff: u64) -> Vec<&'static str> {
    DROP_CAPS.iter().filter(|(bit, _)| !has_cap(cap_eff, *bit)).map(|(_, name)| *name).collect()
}

/// The suffix for a failed chown or spawn of the dropped probe: when the
/// error is EPERM and the effective set lacks a drop capability, name the
/// missing ones (the platform's default set is not documented; the boot
/// report carries `cap_eff`). Empty otherwise.
#[must_use]
pub fn eperm_hint(err: &std::io::Error, cap_eff: Option<u64>) -> String {
    let missing = match (err.raw_os_error(), cap_eff) {
        (Some(libc::EPERM), Some(c)) => missing_drop_caps(c),
        _ => Vec::new(),
    };
    if missing.is_empty() { String::new() } else { format!(" (the effective capabilities lack {})", missing.join(", ")) }
}

/// One `/run` or `/resume` clock measurement (logged as JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClockReport {
    pub hook: &'static str,
    pub mode: &'static str,
    pub guest_s: u64,
    pub rtc_s: Option<u64>,
    pub created_s: Option<u64>,
    /// `rtc - guest` in seconds (positive: the guest lags).
    pub drift_s: Option<i64>,
    /// CAP_SYS_TIME in the effective set (None off Linux).
    pub settable: Option<bool>,
    /// The forward step taken (`--clock forward` only), or why it failed.
    pub stepped_to: Option<u64>,
    pub step_error: Option<String>,
    /// CLOCK_MONOTONIC and CLOCK_BOOTTIME (Linux only) in ms: across a
    /// suspend, how far each jumped (the detach graces run on the first).
    pub monotonic_ms: Option<u64>,
    pub boottime_ms: Option<u64>,
}

/// What the kernel side of a hook needs. [`RealSys`] is the machine;
/// tests supply their own.
pub trait SysOps: Send + Sync {
    /// Wall clock: whole seconds and nanoseconds since the epoch.
    fn now(&self) -> (u64, u128);
    fn rtc(&self) -> Option<u64>;
    /// 32 fresh bytes from the kernel.
    fn kernel_random(&self) -> [u8; 32];
    /// Write `material` into `/dev/urandom` (mixed in, not credited).
    fn mix(&self, material: &[u8]) -> Result<(), String>;
    /// `RNDRESEEDCRNG` on `/dev/urandom`.
    fn reseed(&self) -> Result<(), String>;
    /// Effective capability mask (None off Linux).
    fn cap_eff(&self) -> Option<u64>;
    fn set_clock(&self, secs: u64) -> Result<(), String>;
    /// CLOCK_MONOTONIC in ms (a machine without one, or a fake, says None).
    fn monotonic_ms(&self) -> Option<u64> {
        None
    }
    /// CLOCK_BOOTTIME in ms (Linux; None elsewhere).
    fn boottime_ms(&self) -> Option<u64> {
        None
    }
}

/// Measure (and under `forward`, step) the clock; never fails.
pub fn clock_report(sys: &dyn SysOps, hook: &'static str, mode: ClockMode, created: Option<u64>) -> ClockReport {
    let (guest_s, _) = sys.now();
    let rtc_s = sys.rtc();
    let settable = sys.cap_eff().map(|c| has_cap(c, CAP_SYS_TIME));
    let drift_s = rtc_s.map(|r| i64::try_from(r).unwrap_or(i64::MAX).saturating_sub(i64::try_from(guest_s).unwrap_or(i64::MAX)));
    let mut report = ClockReport {
        hook,
        mode: match mode {
            ClockMode::Measure => "measure",
            ClockMode::Forward => "forward",
        },
        guest_s,
        rtc_s,
        created_s: created,
        drift_s,
        settable,
        stepped_to: None,
        step_error: None,
        monotonic_ms: sys.monotonic_ms(),
        boottime_ms: sys.boottime_ms(),
    };
    if mode == ClockMode::Forward {
        if let Some(target) = decide_step(guest_s, rtc_s, created) {
            match sys.set_clock(target) {
                Ok(()) => report.stepped_to = Some(target),
                Err(e) => report.step_error = Some(e),
            }
        }
    }
    report
}

/// Mix per-VM material into the pool and attempt a reseed; returns one log
/// line. Never fails the hook.
pub fn refresh_entropy(sys: &dyn SysOps, material: &[u8]) -> String {
    let mix = match sys.mix(material) {
        Ok(()) => "mixed".to_string(),
        Err(e) => format!("mix failed ({e})"),
    };
    let reseed = match sys.reseed() {
        Ok(()) => "reseeded".to_string(),
        Err(e) => format!("reseed failed ({e})"),
    };
    let admin = sys.cap_eff().map(|c| has_cap(c, CAP_SYS_ADMIN));
    format!("entropy: {mix}, {reseed}, cap_sys_admin={}", admin.map_or("n/a".into(), |b| b.to_string()))
}

/// The machine.
pub struct RealSys;

impl SysOps for RealSys {
    fn now(&self) -> (u64, u128) {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        (d.as_secs(), d.as_nanos())
    }

    fn rtc(&self) -> Option<u64> {
        std::fs::read_to_string(RTC_PATH).ok()?.trim().parse().ok()
    }

    fn kernel_random(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        // getrandom(2) cannot fail on Linux ≥ 3.17 once the pool is
        // initialised; a failure leaves zeros, and the nonce still mixes
        // in the VM id and clocks.
        let _ = getrandom::fill(&mut b);
        b
    }

    fn mix(&self, material: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).open("/dev/urandom").map_err(|e| e.to_string())?;
        f.write_all(material).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "linux")]
    fn reseed(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        let f = std::fs::OpenOptions::new().write(true).open("/dev/urandom").map_err(|e| e.to_string())?;
        // SAFETY: RNDRESEEDCRNG takes no argument; the fd is open for the
        // duration of the call.
        let rc = unsafe { libc::ioctl(f.as_raw_fd(), RNDRESEEDCRNG) };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
    }

    #[cfg(not(target_os = "linux"))]
    fn reseed(&self) -> Result<(), String> {
        Err("RNDRESEEDCRNG is Linux-only".into())
    }

    #[cfg(target_os = "linux")]
    fn cap_eff(&self) -> Option<u64> {
        parse_cap_eff(&std::fs::read_to_string("/proc/self/status").ok()?)
    }

    #[cfg(not(target_os = "linux"))]
    fn cap_eff(&self) -> Option<u64> {
        None
    }

    #[cfg(target_os = "linux")]
    fn set_clock(&self, secs: u64) -> Result<(), String> {
        let ts = libc::timespec { tv_sec: libc::time_t::try_from(secs).map_err(|e| e.to_string())?, tv_nsec: 0 };
        // SAFETY: a valid timespec on the stack; CLOCK_REALTIME.
        let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
        if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
    }

    #[cfg(not(target_os = "linux"))]
    fn set_clock(&self, _secs: u64) -> Result<(), String> {
        Err("stepping the clock is Linux-only".into())
    }

    fn monotonic_ms(&self) -> Option<u64> {
        clock_ms(libc::CLOCK_MONOTONIC)
    }

    #[cfg(target_os = "linux")]
    fn boottime_ms(&self) -> Option<u64> {
        clock_ms(libc::CLOCK_BOOTTIME)
    }
}

/// `clock_gettime(clock)` in whole milliseconds.
fn clock_ms(clock: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: a valid timespec on the stack; the clock id is a libc constant.
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    Some(u64::try_from(ts.tv_sec).ok()?.saturating_mul(1000).saturating_add(u64::try_from(ts.tv_nsec).ok()? / 1_000_000))
}

/// Facts logged once at startup (the build log and CloudWatch carry them):
/// who we are, what we may do, and what the VM looks like. Never a secret;
/// the machine id is reported as absent/empty/present only.
#[derive(Debug, Clone, Serialize)]
pub struct BootReport {
    pub pid: u32,
    pub ppid: u32,
    pub comm1: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub cap_eff: Option<String>,
    pub cap_sys_time: Option<bool>,
    pub cap_sys_admin: Option<bool>,
    /// The privilege drop's capabilities (the probe and the agent run as
    /// `--uid`/`--gid`): without them `/ready` never flips.
    pub cap_chown: Option<bool>,
    pub cap_setuid: Option<bool>,
    pub cap_setgid: Option<bool>,
    pub kernel: Option<String>,
    pub rtc0: Option<u64>,
    pub ptp0: bool,
    pub machine_id: &'static str,
    pub boot_id: Option<String>,
    pub guest_s: u64,
    pub nf_tables: NftEvidence,
}

/// The `/proc/kallsyms` names [`NftEvidence`] counts (plan S6, critic L6).
pub const NFT_SYMBOLS: [&str; 4] = ["nft_", "nf_tables", "xt_owner", "nft_meta"];

/// Whether this kernel has nf_tables (the D1-B fallback needs it), read
/// without any capability: symbol NAMES in `/proc/kallsyms` are readable
/// without CAP_SYSLOG (only the addresses read as zero), and `/proc/modules`
/// lists loaded modules. Built-in code shows in the first only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NftEvidence {
    /// How many symbol names contain each of [`NFT_SYMBOLS`] (`None`: unreadable).
    pub kallsyms: Option<BTreeMap<&'static str, usize>>,
    /// The `nf_*`, `nft_*`, `nfnetlink*`, `x_tables` and `xt_*` entries of `/proc/modules`, names only (`None`: unreadable).
    pub modules: Option<Vec<String>>,
}

/// Count the symbol names (the third field of each line) containing each of
/// [`NFT_SYMBOLS`].
#[must_use]
pub fn count_nft_symbols(lines: impl Iterator<Item = String>) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> = NFT_SYMBOLS.iter().map(|n| (*n, 0)).collect();
    for line in lines {
        let Some(name) = line.split_whitespace().nth(2) else { continue };
        for needle in NFT_SYMBOLS {
            if name.contains(needle) {
                *counts.entry(needle).or_default() += 1;
            }
        }
    }
    counts
}

/// The prefixes of netfilter's table modules (nf_tables, nf_conntrack,
/// nft_chain_nat, nfnetlink_queue, xt_owner); `x_tables` itself is matched
/// whole. A bare `nf` would take nfs, nfsd, nfit and nfc too.
const NF_MODULE_PREFIXES: [&str; 4] = ["nf_", "nft_", "nfnetlink", "xt_"];

/// The module names of a `/proc/modules` text that belong to netfilter's
/// tables: `nf_*`, `nft_*`, `nfnetlink*`, `x_tables` and `xt_*`.
#[must_use]
pub fn nf_modules(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| *n == "x_tables" || NF_MODULE_PREFIXES.iter().any(|p| n.starts_with(p)))
        .map(str::to_string)
        .collect()
}

/// [`NftEvidence`] from `<proc>/kallsyms` (streamed: it is megabytes) and `<proc>/modules`.
#[must_use]
pub fn nft_evidence(proc: &Path) -> NftEvidence {
    use std::io::BufRead;
    let kallsyms = std::fs::File::open(proc.join("kallsyms")).ok().map(|f| count_nft_symbols(std::io::BufReader::new(f).lines().map_while(std::result::Result::ok)));
    let modules = std::fs::read_to_string(proc.join("modules")).ok().map(|t| nf_modules(&t));
    NftEvidence { kallsyms, modules }
}

/// `(real, effective)` uid of a `/proc/<pid>/status` text.
#[must_use]
pub fn parse_uids(status: &str) -> Option<(u32, u32)> {
    let mut f = status.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace();
    Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
}

/// Is this `/proc/<pid>/status` text a process that still runs (not a
/// zombie: it holds nothing and cannot be killed) whose real and effective
/// uid are `uid`?
#[must_use]
pub fn is_running_as(status: &str, uid: u32) -> bool {
    let dead = status.lines().find_map(|l| l.strip_prefix("State:")).and_then(|v| v.trim_start().chars().next()).is_some_and(|c| c == 'Z' || c == 'X');
    !dead && parse_uids(status) == Some((uid, uid))
}

/// The pids under `proc` (numeric entries only) that [`is_running_as`]
/// `uid`, ascending; a process that exits meanwhile is skipped. The spawn
/// manager's idle sweep re-checks each one after opening a pidfd.
#[must_use]
pub fn pids_of_uid(proc: &Path, uid: u32) -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir(proc) else { return Vec::new() };
    let mut pids: Vec<u32> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str().filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())).and_then(|n| n.parse().ok()))
        .filter(|pid: &u32| std::fs::read_to_string(proc.join(pid.to_string()).join("status")).is_ok_and(|s| is_running_as(&s, uid)))
        .collect();
    pids.sort_unstable();
    pids
}

fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[must_use]
pub fn boot_report(sys: &dyn SysOps) -> BootReport {
    let cap = sys.cap_eff();
    let machine_id = match std::fs::read("/etc/machine-id") {
        Err(_) => "absent",
        Ok(b) if b.iter().all(u8::is_ascii_whitespace) => "empty",
        Ok(_) => "present",
    };
    BootReport {
        pid: std::process::id(),
        ppid: nix::unistd::getppid().as_raw().unsigned_abs(),
        comm1: read_trim("/proc/1/comm"),
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
        cap_eff: cap.map(|c| format!("{c:016x}")),
        cap_sys_time: cap.map(|c| has_cap(c, CAP_SYS_TIME)),
        cap_sys_admin: cap.map(|c| has_cap(c, CAP_SYS_ADMIN)),
        cap_chown: cap.map(|c| has_cap(c, CAP_CHOWN)),
        cap_setuid: cap.map(|c| has_cap(c, CAP_SETUID)),
        cap_setgid: cap.map(|c| has_cap(c, CAP_SETGID)),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        rtc0: sys.rtc(),
        ptp0: std::path::Path::new("/dev/ptp0").exists(),
        machine_id,
        boot_id: read_trim("/proc/sys/kernel/random/boot_id"),
        guest_s: sys.now().0,
        nf_tables: nft_evidence(Path::new("/proc")),
    }
}

// ---- run report (S4 D19) -----------------------------------------------------------

/// The PID 1 variables whose VALUES the run report shows; every other
/// variable is reported by name only.
pub const REPORT_ENV_VALUES: [&str; 6] = ["HOME", "PATH", "AWS_REGION", "AWS_LAMBDA_MICROVM_IMAGE_NAME", "AWS_LAMBDA_MICROVM_IMAGE_ARN", "AWS_LAMBDA_MICROVM_IMAGE_VERSION"];

/// Does `name` carry (or point at) AWS credentials? The run report lists
/// such names in `aws_credential_env` and never shows their values.
#[must_use]
pub fn is_aws_credential_name(name: &str) -> bool {
    matches!(name, "AWS_ACCESS_KEY_ID" | "AWS_SECRET_ACCESS_KEY" | "AWS_SESSION_TOKEN") || name.starts_with("AWS_CONTAINER_")
}

/// An environment as the run report shows it: names, a few allowlisted
/// values, and which credential variables exist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EnvSummary {
    /// Every variable name, sorted, without duplicates.
    pub names: Vec<String>,
    /// The values of the [`REPORT_ENV_VALUES`] that are set (the first
    /// occurrence wins, as for `getenv`); nothing else.
    pub values: BTreeMap<String, String>,
    /// The names [`is_aws_credential_name`] accepts, sorted: names only,
    /// never values.
    pub aws_credential_env: Vec<String>,
}

/// Parse a `/proc/<pid>/environ` image: NUL-separated `KEY=VALUE` entries.
/// An entry without `=` or with an empty name is skipped; bytes that are not
/// UTF-8 are replaced (lossy). Pure; never panics.
#[must_use]
pub fn parse_environ(bytes: &[u8]) -> EnvSummary {
    let mut s = EnvSummary::default();
    for entry in bytes.split(|&b| b == 0) {
        let Some(eq) = entry.iter().position(|&b| b == b'=') else { continue };
        if eq == 0 {
            continue;
        }
        let name = String::from_utf8_lossy(&entry[..eq]).into_owned();
        if REPORT_ENV_VALUES.contains(&name.as_str()) && !s.values.contains_key(&name) {
            s.values.insert(name.clone(), String::from_utf8_lossy(&entry[eq + 1..]).into_owned());
        }
        if is_aws_credential_name(&name) {
            s.aws_credential_env.push(name.clone());
        }
        s.names.push(name);
    }
    for v in [&mut s.names, &mut s.aws_credential_env] {
        v.sort();
        v.dedup();
    }
    s
}

/// How many of `stat_lines` (each the text of one `/proc/<pid>/stat`) are
/// zombies: the state field right after the `)` that closes `comm`. `comm`
/// may itself hold spaces and parentheses, so the LAST `)` is the one; a
/// line without one is not counted.
#[must_use]
pub fn count_zombies(stat_lines: &[&str]) -> usize {
    stat_lines.iter().filter(|l| l.rfind(')').and_then(|i| l[i + 1..].split_whitespace().next()) == Some("Z")).count()
}

/// What a Linux run report is built from, already read (each `None` when
/// its source was missing or unreadable). `Debug` is hand-written: `environ`
/// is PID 1's raw environment, credential values included, so it prints as
/// its length only (and `stat_lines` as a count).
#[derive(Clone, Copy)]
pub struct ReportFacts<'a> {
    /// `run` | `terminate`.
    pub hook: &'a str,
    /// The id of the accepted `/run` (`None` before one, or when its id was
    /// not safe to log).
    pub microvm_id: Option<&'a str>,
    /// `/proc/sys/kernel/random/boot_id` (identical in every clone of a
    /// snapshot: recorded, not relied on).
    pub boot_id: Option<&'a str>,
    /// `(total, used)` bytes of `/` (statvfs).
    pub disk: Option<(u64, u64)>,
    /// `/proc/1/environ`.
    pub environ: Option<&'a [u8]>,
    /// Every `/proc/<pid>/stat` that could be read.
    pub stat_lines: Option<&'a [&'a str]>,
    /// The shim's effective uid.
    pub uid: u32,
    /// The shim's effective gid.
    pub gid: u32,
}

impl std::fmt::Debug for ReportFacts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bytes of `environ`: they hold PID 1's credential values.
        let environ = self.environ.map(|e| format!("<{} bytes>", e.len()));
        let stats = self.stat_lines.map(|s| format!("<{} lines>", s.len()));
        f.debug_struct("ReportFacts")
            .field("hook", &self.hook)
            .field("microvm_id", &self.microvm_id)
            .field("boot_id", &self.boot_id)
            .field("disk", &self.disk)
            .field("environ", &format_args!("{}", environ.as_deref().unwrap_or("None")))
            .field("stat_lines", &format_args!("{}", stats.as_deref().unwrap_or("None")))
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .finish()
    }
}

/// The run report's JSON from [`ReportFacts`] (pure, so it is tested on every
/// platform): `hook`, `microvm_id`, `boot_id`, `disk_total_bytes`,
/// `disk_used_bytes`, `env` (`names`, `values`), `aws_credential_env`,
/// `zombies`, `uid`, `gid`; a missing source is `null`. No credential value
/// can reach it: `env.values` holds the [`REPORT_ENV_VALUES`] only.
#[must_use]
pub fn assemble_report(f: &ReportFacts<'_>) -> serde_json::Value {
    let env = f.environ.map(parse_environ);
    serde_json::json!({
        "hook": f.hook,
        "microvm_id": f.microvm_id,
        "boot_id": f.boot_id,
        "disk_total_bytes": f.disk.map(|d| d.0),
        "disk_used_bytes": f.disk.map(|d| d.1),
        "env": env.as_ref().map(|e| serde_json::json!({"names": e.names, "values": e.values})),
        "aws_credential_env": env.as_ref().map(|e| e.aws_credential_env.clone()),
        "zombies": f.stat_lines.map(count_zombies),
        "uid": f.uid,
        "gid": f.gid,
    })
}

/// `(total, used)` bytes of the filesystem holding `path`.
// `c_ulong` and `fsblkcnt_t` are u64 on 64-bit Linux (and `c_ulong` on the Mac).
#[allow(clippy::useless_conversion)]
fn disk_usage(path: &Path) -> Option<(u64, u64)> {
    let s = nix::sys::statvfs::statvfs(path).ok()?;
    let frag = u64::from(s.fragment_size());
    let (blocks, free) = (u64::from(s.blocks()), u64::from(s.blocks_free()));
    Some((blocks.saturating_mul(frag), blocks.saturating_sub(free).saturating_mul(frag)))
}

/// The text of every readable `<proc>/<pid>/stat` (a process that exits
/// meanwhile is skipped); `None` when `proc` cannot be listed.
fn proc_stat_lines(proc: &Path) -> Option<Vec<String>> {
    let rd = std::fs::read_dir(proc).ok()?;
    let pids = rd.flatten().filter(|e| e.file_name().to_str().is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())));
    Some(pids.filter_map(|e| std::fs::read(e.path().join("stat")).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).collect())
}

/// The Linux run report with every source under `root` (`/` on the machine;
/// a planted tree in the tests, so the paths below are exercised on every
/// platform): `proc/sys/kernel/random/boot_id`, `proc/1/environ`,
/// `proc/<pid>/stat`, statvfs of `root`, and the shim's own uid/gid.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_report(root: &Path, hook: &str, microvm_id: Option<&str>) -> serde_json::Value {
    let proc = root.join("proc");
    let boot_id = read_trim(proc.join("sys/kernel/random/boot_id"));
    let environ = std::fs::read(proc.join("1/environ")).ok();
    let stats = proc_stat_lines(&proc);
    let stat_refs: Option<Vec<&str>> = stats.as_ref().map(|v| v.iter().map(String::as_str).collect());
    assemble_report(&ReportFacts {
        hook,
        microvm_id,
        boot_id: boot_id.as_deref(),
        disk: disk_usage(root),
        environ: environ.as_deref(),
        stat_lines: stat_refs.as_deref(),
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    })
}

/// The run report for `hook` (`run` | `terminate`), read from this machine
/// (see [`assemble_report`]). Never fails: whatever cannot be read is `null`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn run_report(hook: &str, microvm_id: Option<&str>) -> serde_json::Value {
    read_report(Path::new("/"), hook, microvm_id)
}

/// The portable twin: `/proc` does not exist here, so the report says so
/// (native tests on the Mac still see one line per hook, with the id).
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn run_report(hook: &str, microvm_id: Option<&str>) -> serde_json::Value {
    serde_json::json!({"unsupported": true, "hook": hook, "microvm_id": microvm_id})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn decide_step_only_forward_and_beyond_the_threshold() {
        assert_eq!(decide_step(1000, None, None), None, "nothing to compare with");
        assert_eq!(decide_step(1000, Some(1002), None), None, "2 s lag is tolerated");
        assert_eq!(decide_step(1000, Some(1003), None), Some(1003));
        assert_eq!(decide_step(1000, Some(900), None), None, "never backwards");
        assert_eq!(decide_step(1000, Some(900), Some(1500)), Some(1500), "created is a lower bound");
        assert_eq!(decide_step(1000, Some(2000), Some(1500)), Some(2000), "the later of the two");
        assert_eq!(decide_step(1000, None, Some(1001)), None);
        assert_eq!(decide_step(u64::MAX, Some(u64::MAX), None), None, "no overflow");
    }

    #[test]
    fn nonce_is_32_hex_and_depends_on_every_input() {
        let base = nonce_from(&[1; 32], "mvm-1", &[2; 32], 5, Some(7));
        assert_eq!(base.len(), 32);
        assert!(base.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(base, nonce_from(&[1; 32], "mvm-1", &[2; 32], 5, Some(7)), "deterministic");
        for other in [
            nonce_from(&[9; 32], "mvm-1", &[2; 32], 5, Some(7)),
            nonce_from(&[1; 32], "mvm-2", &[2; 32], 5, Some(7)),
            nonce_from(&[1; 32], "mvm-1", &[3; 32], 5, Some(7)),
            nonce_from(&[1; 32], "mvm-1", &[2; 32], 6, Some(7)),
            nonce_from(&[1; 32], "mvm-1", &[2; 32], 5, None),
        ] {
            assert_ne!(other, base);
        }
    }

    #[test]
    fn cap_eff_parsing() {
        let docker = "Name:\tai-env\nCapInh:\t0000000000000000\nCapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\n";
        let c = parse_cap_eff(docker).unwrap();
        assert!(!has_cap(c, CAP_SYS_TIME), "Docker's default set lacks CAP_SYS_TIME");
        assert!(!has_cap(c, CAP_SYS_ADMIN));
        assert!(has_cap(parse_cap_eff("CapEff:\t000001ffffffffff\n").unwrap(), CAP_SYS_TIME));
        assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);
        assert_eq!(parse_cap_eff("Name:\tx\n"), None);
    }

    #[test]
    fn drop_caps_are_named_when_missing() {
        // Docker's default set has all three; `--cap-drop CHOWN --cap-drop SETUID --cap-drop SETGID` clears bits 0, 7, 6.
        assert_eq!(missing_drop_caps(0xa804_25fb), Vec::<&str>::new());
        assert_eq!(missing_drop_caps(0xa804_253a), vec!["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"]);
        assert_eq!(missing_drop_caps(0xa804_25fb & !1), vec!["CAP_CHOWN"]);
        assert_eq!(missing_drop_caps(0xa804_25fb & !(1 << 7)), vec!["CAP_SETUID"]);
        assert_eq!(missing_drop_caps(0xa804_25fb & !(1 << 6)), vec!["CAP_SETGID"]);
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        let hint = eperm_hint(&eperm, Some(0xa804_25fb & !1));
        assert_eq!(hint, " (the effective capabilities lack CAP_CHOWN)");
        assert_eq!(eperm_hint(&eperm, Some(0xa804_25fb)), "", "every drop cap present: the EPERM has another cause");
        assert_eq!(eperm_hint(&eperm, None), "", "no capability facts off Linux");
        assert_eq!(eperm_hint(&std::io::Error::from_raw_os_error(libc::ENOENT), Some(0)), "", "only EPERM");
        let report = serde_json::to_string(&boot_report(&Fake { cap: Some(0xa804_253a), ..fake(1, None) })).unwrap();
        assert!(report.contains("\"cap_chown\":false") && report.contains("\"cap_setuid\":false") && report.contains("\"cap_setgid\":false"), "{report}");
        let report = serde_json::to_string(&boot_report(&Fake { cap: Some(0xa804_25fb), ..fake(1, None) })).unwrap();
        assert!(report.contains("\"cap_chown\":true") && report.contains("\"cap_setuid\":true") && report.contains("\"cap_setgid\":true"), "{report}");
    }

    /// A machine whose clock is a variable and whose step is recorded.
    struct Fake {
        now: u64,
        rtc: Option<u64>,
        cap: Option<u64>,
        stepped: Mutex<Vec<u64>>,
        mixed: Mutex<Vec<u8>>,
        fail_set: bool,
    }

    impl SysOps for Fake {
        fn now(&self) -> (u64, u128) {
            (self.now, u128::from(self.now) * 1_000_000_000)
        }
        fn rtc(&self) -> Option<u64> {
            self.rtc
        }
        fn kernel_random(&self) -> [u8; 32] {
            [4; 32]
        }
        fn mix(&self, m: &[u8]) -> Result<(), String> {
            self.mixed.lock().unwrap().extend_from_slice(m);
            Ok(())
        }
        fn reseed(&self) -> Result<(), String> {
            Err("Operation not permitted (os error 1)".into())
        }
        fn cap_eff(&self) -> Option<u64> {
            self.cap
        }
        fn set_clock(&self, secs: u64) -> Result<(), String> {
            if self.fail_set {
                return Err("Operation not permitted (os error 1)".into());
            }
            self.stepped.lock().unwrap().push(secs);
            Ok(())
        }
    }

    fn fake(now: u64, rtc: Option<u64>) -> Fake {
        Fake { now, rtc, cap: Some(1 << CAP_SYS_TIME), stepped: Mutex::default(), mixed: Mutex::default(), fail_set: false }
    }

    #[test]
    fn measure_never_steps() {
        let f = fake(1000, Some(5000));
        let r = clock_report(&f, "run", ClockMode::Measure, Some(4000));
        assert_eq!(r.drift_s, Some(4000));
        assert_eq!(r.settable, Some(true));
        assert_eq!(r.stepped_to, None);
        assert!(f.stepped.lock().unwrap().is_empty(), "measure mode must not call set_clock");
    }

    #[test]
    fn forward_steps_once_to_the_later_bound_and_reports_failures() {
        let f = fake(1000, Some(5000));
        let r = clock_report(&f, "resume", ClockMode::Forward, Some(6000));
        assert_eq!(r.stepped_to, Some(6000));
        assert_eq!(*f.stepped.lock().unwrap(), vec![6000]);
        let g = fake(1000, Some(1001));
        assert_eq!(clock_report(&g, "resume", ClockMode::Forward, None).stepped_to, None, "within the threshold");
        let h = Fake { fail_set: true, ..fake(1000, Some(5000)) };
        let r = clock_report(&h, "run", ClockMode::Forward, None);
        assert_eq!(r.stepped_to, None);
        assert!(r.step_error.unwrap().contains("not permitted"));
        let serialised = serde_json::to_string(&clock_report(&fake(1, None), "run", ClockMode::Measure, None)).unwrap();
        assert!(serialised.contains("\"mode\":\"measure\"") && serialised.contains("\"rtc_s\":null"), "{serialised}");
    }

    #[test]
    fn entropy_refresh_never_fails_and_says_what_happened() {
        let f = fake(1, None);
        let line = refresh_entropy(&f, b"material");
        assert_eq!(*f.mixed.lock().unwrap(), b"material".to_vec());
        assert!(line.contains("mixed") && line.contains("reseed failed") && line.contains("cap_sys_admin=false"), "{line}");
        let g = Fake { cap: None, ..fake(1, None) };
        assert!(refresh_entropy(&g, b"").contains("cap_sys_admin=n/a"));
    }

    #[test]
    fn boot_report_serialises_without_secrets() {
        let r = boot_report(&RealSys);
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"pid\":") && s.contains("\"machine_id\":"), "{s}");
        assert!(["absent", "empty", "present"].contains(&r.machine_id));
    }

    /// Credential-shaped values, built at run time (no such literal in the tree).
    fn credential_values() -> [(&'static str, String); 5] {
        [
            ("AWS_ACCESS_KEY_ID", format!("{}{}", "AKIA", "Q".repeat(16))),
            ("AWS_SECRET_ACCESS_KEY", "s3Cr".repeat(10)),
            ("AWS_SESSION_TOKEN", format!("tok{}", "Zz9".repeat(30))),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", format!("auth{}", "Yy8".repeat(12))),
            ("AWS_CONTAINER_CREDENTIALS_FULL_URI", format!("http://169.254.170.23/v1/credentials?x={}", "Ww7".repeat(8))),
        ]
    }

    fn environ(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut b = Vec::new();
        for (k, v) in entries {
            b.extend_from_slice(format!("{k}={v}").as_bytes());
            b.push(0);
        }
        b
    }

    #[test]
    fn parse_environ_lists_credential_names_never_their_values() {
        let creds = credential_values();
        let mut entries: Vec<(&str, &str)> = vec![
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("HOME", "/root"),
            ("AWS_REGION", "eu-central-1"),
            ("AWS_LAMBDA_MICROVM_IMAGE_VERSION", "1.0"),
            ("AWS_LAMBDA_MICROVM_IMAGE_NAME", "ai-env-agent"),
            ("AWS_LAMBDA_MICROVM_IMAGE_ARN", "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent"),
            ("AWS_DEFAULT_REGION", "eu-west-3"),
            ("OTHER_SECRET", "not-an-allowlisted-value"),
        ];
        entries.extend(creds.iter().map(|(k, v)| (*k, v.as_str())));
        let s = parse_environ(&environ(&entries));
        assert_eq!(s.aws_credential_env, ["AWS_ACCESS_KEY_ID", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]);
        let mut all: Vec<&str> = entries.iter().map(|(k, _)| *k).collect();
        all.sort_unstable();
        assert_eq!(s.names, all, "every name, sorted");
        assert_eq!(s.values.keys().map(String::as_str).collect::<Vec<_>>(), {
            let mut want = REPORT_ENV_VALUES.to_vec();
            want.sort_unstable();
            want
        });
        assert_eq!(s.values["AWS_LAMBDA_MICROVM_IMAGE_VERSION"], "1.0");
        assert_eq!(s.values["HOME"], "/root");
        let json = serde_json::to_string(&s).unwrap();
        let report = assemble_report(&ReportFacts { environ: Some(&environ(&entries)), ..facts() }).to_string();
        for text in [&json, &report] {
            for (name, value) in &creds {
                assert!(text.contains(name), "{name} is listed: {text}");
                assert!(!text.contains(value.as_str()), "the value of {name} never appears: {text}");
            }
            assert!(!text.contains("not-an-allowlisted-value") && !text.contains("eu-west-3"), "only allowlisted values: {text}");
        }
    }

    #[test]
    fn parse_environ_edge_cases() {
        assert_eq!(parse_environ(b""), EnvSummary::default());
        assert_eq!(parse_environ(b"\0\0"), EnvSummary::default());
        let s = parse_environ(b"PATH=/a=b:/c\0NOEQUALS\0=hidden\0HOME=\0PATH=/second\0HOME=/later\0B=1\0A=2\0B=3");
        assert_eq!(s.names, ["A", "B", "HOME", "PATH"], "no-'=' and empty-name entries skipped, duplicates once, no trailing NUL needed");
        assert_eq!(s.values["PATH"], "/a=b:/c", "split at the first '=', the first occurrence wins");
        assert_eq!(s.values["HOME"], "", "an empty value is a value");
        assert!(s.aws_credential_env.is_empty());
        let s = parse_environ(b"AWS_REGION=eu-\xffcentral-1\0X\xfe=1\0");
        assert_eq!(s.values["AWS_REGION"], "eu-\u{fffd}central-1", "lossy, never a panic");
        assert!(s.names.contains(&"X\u{fffd}".to_string()), "{:?}", s.names);
        assert!(is_aws_credential_name("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"));
        assert!(!is_aws_credential_name("AWS_REGION") && !is_aws_credential_name("MY_AWS_ACCESS_KEY_ID") && !is_aws_credential_name("AWS_CONTAINER"));
    }

    #[test]
    fn zombies_are_read_after_the_last_parenthesis() {
        let lines = [
            "1 (ai-env) S 0 1 1 0 -1",
            "42 (sh) Z 1 42 42 0",
            "43 (kworker a b) Z 2 0 0",
            "44 (x) Z (y) S 1 44",
            "45 ((sd-pam)) Z 1 45",
            "46 (evil) R) Z 1 46",
            "47 ())) Z 1",
            "48 (Z) S 1",
            "49 (zombie) z 1",
            "50 (x)",
            "",
            "garbage without a paren Z",
        ];
        // 42, 43, 45, 46 and 47; 44's comm is "x) Z (y" (state S).
        assert_eq!(count_zombies(&lines), 5);
        assert_eq!(count_zombies(&[]), 0);
    }

    fn facts() -> ReportFacts<'static> {
        ReportFacts { hook: "run", microvm_id: None, boot_id: None, disk: None, environ: None, stat_lines: None, uid: 0, gid: 0 }
    }

    #[test]
    fn report_shape_with_and_without_sources() {
        let empty = assemble_report(&facts());
        for key in ["microvm_id", "boot_id", "disk_total_bytes", "disk_used_bytes", "env", "aws_credential_env", "zombies"] {
            assert!(empty[key].is_null(), "a missing source is null: {key} in {empty}");
        }
        assert_eq!((empty["hook"].as_str(), empty["uid"].as_u64(), empty["gid"].as_u64()), (Some("run"), Some(0), Some(0)));
        let env = environ(&[("HOME", "/root"), ("AWS_ACCESS_KEY_ID", "x")]);
        let stats = ["7 (a) Z 1", "8 (b) S 1"];
        let full = assemble_report(&ReportFacts {
            hook: "terminate",
            microvm_id: Some("microvm-00000000-0000-4000-8000-000000000001"),
            boot_id: Some("b1"),
            disk: Some((8 << 30, 1 << 29)),
            environ: Some(&env),
            stat_lines: Some(&stats),
            uid: 0,
            gid: 0,
        });
        assert_eq!(full["hook"], "terminate");
        assert_eq!(full["microvm_id"], "microvm-00000000-0000-4000-8000-000000000001");
        assert_eq!(full["boot_id"], "b1");
        assert_eq!((full["disk_total_bytes"].as_u64(), full["disk_used_bytes"].as_u64()), (Some(8 << 30), Some(1 << 29)));
        assert_eq!(full["env"]["names"], serde_json::json!(["AWS_ACCESS_KEY_ID", "HOME"]));
        assert_eq!(full["env"]["values"], serde_json::json!({"HOME": "/root"}));
        assert_eq!(full["aws_credential_env"], serde_json::json!(["AWS_ACCESS_KEY_ID"]));
        assert_eq!(full["zombies"], 1);
        assert!(!full.to_string().contains('\n'), "one log line");
    }

    #[test]
    fn report_facts_debug_never_shows_the_environment() {
        let creds = credential_values();
        let entries: Vec<(&str, &str)> = creds.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let env = environ(&entries);
        let stats = ["7 (a) Z 1"];
        let d = format!("{:?}", ReportFacts { environ: Some(&env), stat_lines: Some(&stats), ..facts() });
        assert!(d.contains(&format!("environ: <{} bytes>", env.len())) && d.contains("stat_lines: <1 lines>"), "{d}");
        for (name, value) in &creds {
            // A derived Debug prints the slice as decimal bytes: neither form may appear.
            let bytes = format!("{:?}", &value.as_bytes()[..6]);
            assert!(!d.contains(value.as_str()) && !d.contains(bytes.trim_matches(['[', ']'])), "{name}: {d}");
            assert!(!d.contains(name), "not even the names: {d}");
        }
        assert_eq!(format!("{:?}", facts()), "ReportFacts { hook: \"run\", microvm_id: None, boot_id: None, disk: None, environ: None, stat_lines: None, uid: 0, gid: 0 }");
    }

    /// A `/proc` as the Linux reader sees it, under a temp root: the paths
    /// the report reads are exercised on the Mac too (the portable twin
    /// never reads them).
    fn plant_proc(root: &std::path::Path, files: &[(&str, &[u8])]) {
        for (rel, bytes) in files {
            let p = root.join("proc").join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
    }

    #[test]
    fn read_report_reads_boot_id_pid1_environ_and_every_pid_stat() {
        let t = tempfile::tempdir().unwrap();
        let creds = credential_values();
        let pid1 = environ(&[("HOME", "/root"), ("AWS_REGION", "eu-central-1"), (creds[0].0, creds[0].1.as_str()), (creds[2].0, creds[2].1.as_str())]);
        let other = environ(&[("HOME", "/home/not-pid-1"), ("PID2_ONLY", "x")]);
        let boot = "3f2c9a1e-5b7d-4c8e-9f01-23456789abcd";
        plant_proc(
            t.path(),
            &[
                ("sys/kernel/random/boot_id", format!("{boot}\n").as_bytes()),
                ("1/environ", &pid1),
                ("1/stat", b"1 (ai-env) S 0 1 1 0 -1"),
                ("2/environ", &other),
                ("2/stat", b"2 (sh) Z 1 2 2 0"),
                ("37/stat", b"37 (my (odd) name) Z 1 37"),
                ("40/stat", b"40 (sleep) S 1 40"),
                ("self/stat", b"99 (self) Z 1"),
                ("sys/stat", b"98 (sys) Z 1"),
            ],
        );
        std::fs::create_dir_all(t.path().join("proc/41")).unwrap();
        let r = read_report(t.path(), "terminate", Some("microvm-00000000-0000-4000-8000-000000000007"));
        assert_eq!(r["hook"], "terminate");
        assert_eq!(r["microvm_id"], "microvm-00000000-0000-4000-8000-000000000007");
        assert_eq!(r["boot_id"], boot, "trimmed: {r}");
        assert_eq!(r["env"]["names"], serde_json::json!(["AWS_ACCESS_KEY_ID", "AWS_REGION", "AWS_SESSION_TOKEN", "HOME"]), "PID 1's environ, not another pid's: {r}");
        assert_eq!(r["env"]["values"], serde_json::json!({"AWS_REGION": "eu-central-1", "HOME": "/root"}));
        assert_eq!(r["aws_credential_env"], serde_json::json!(["AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"]));
        assert_eq!(r["zombies"], 2, "pids 2 and 37 (numeric dirs only; 41 has no stat): {r}");
        let (total, used) = (r["disk_total_bytes"].as_u64(), r["disk_used_bytes"].as_u64());
        assert!(total.is_some_and(|t| t > 0) && used.is_some_and(|u| Some(u) <= total), "statvfs of the root: {r}");
        assert_eq!((r["uid"].as_u64(), r["gid"].as_u64()), (Some(u64::from(nix::unistd::geteuid().as_raw())), Some(u64::from(nix::unistd::getegid().as_raw()))));
        let text = r.to_string();
        for (_, value) in &creds {
            assert!(!text.contains(value.as_str()), "{text}");
        }
        // Nothing planted: every /proc field is null, the disk still answers.
        let empty = tempfile::tempdir().unwrap();
        let r = read_report(empty.path(), "run", None);
        for key in ["microvm_id", "boot_id", "env", "aws_credential_env", "zombies"] {
            assert!(r[key].is_null(), "{key} in {r}");
        }
        assert!(r["disk_total_bytes"].as_u64().is_some_and(|t| t > 0), "{r}");
        // A /proc whose PID 1 environ is unreadable (a directory here) and an empty listing.
        std::fs::create_dir_all(empty.path().join("proc/1/environ")).unwrap();
        let r = read_report(empty.path(), "run", None);
        assert!(r["env"].is_null() && r["aws_credential_env"].is_null(), "{r}");
        assert_eq!(r["zombies"], 0, "a listable /proc without stats: {r}");
    }

    #[test]
    fn run_report_on_this_platform_never_panics() {
        let r = run_report("run", Some("microvm-x"));
        assert_eq!((r["hook"].as_str(), r["microvm_id"].as_str()), (Some("run"), Some("microvm-x")));
        if cfg!(target_os = "linux") {
            // Values, not key presence: `assemble_report` emits every key (null when unread).
            assert!(r["boot_id"].as_str().is_some_and(|b| b.len() == 36 && b.matches('-').count() == 4), "a uuid boot_id: {r}");
            assert!(r["zombies"].is_u64(), "/proc is listable: {r}");
            let (total, used) = (r["disk_total_bytes"].as_u64(), r["disk_used_bytes"].as_u64());
            assert!(total.is_some_and(|t| t > 0) && used.is_some_and(|u| Some(u) <= total), "statvfs(/) answers on Linux: {r}");
            let readable = std::fs::read("/proc/1/environ").is_ok();
            assert_eq!(r["env"].is_object(), readable, "env is PID 1's environ exactly when this uid may read it: {r}");
            assert_eq!(r["aws_credential_env"].is_array(), readable, "{r}");
            if readable {
                assert!(r["env"]["names"].as_array().is_some_and(|n| !n.is_empty()) && r["env"]["values"].is_object(), "{r}");
            }
            assert_eq!((r["uid"].as_u64(), r["gid"].as_u64()), (Some(u64::from(nix::unistd::geteuid().as_raw())), Some(u64::from(nix::unistd::getegid().as_raw()))), "{r}");
            assert!(r.get("unsupported").is_none(), "{r}");
        } else {
            assert_eq!(r["unsupported"], true, "{r}");
        }
        assert!(run_report("terminate", None)["microvm_id"].is_null());
    }

    #[test]
    fn clock_report_carries_monotonic_and_boottime() {
        let fake = serde_json::to_string(&clock_report(&fake(1, None), "resume", ClockMode::Measure, None)).unwrap();
        assert!(fake.contains("\"monotonic_ms\":null") && fake.contains("\"boottime_ms\":null"), "a fake has neither: {fake}");
        let r = clock_report(&RealSys, "resume", ClockMode::Measure, None);
        let first = r.monotonic_ms.expect("CLOCK_MONOTONIC on Linux and macOS");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = RealSys.monotonic_ms().unwrap();
        assert!(second >= first + 15, "{first} then {second}");
        assert_eq!(r.boottime_ms.is_some(), cfg!(target_os = "linux"), "CLOCK_BOOTTIME on Linux only: {r:?}");
        if let (Some(m), Some(b)) = (r.monotonic_ms, r.boottime_ms) {
            assert!(b + 1000 >= m, "boottime counts at least what monotonic does: {r:?}");
        }
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.starts_with("{\"hook\":\"resume\",\"mode\":\"measure\",\"guest_s\":") && json.contains("\"monotonic_ms\":"), "the old fields first, unchanged: {json}");
    }

    /// A `/proc/kallsyms` excerpt as uid 1000 reads it (kptr_restrict: zero
    /// addresses, names intact); the addresses are built here, not written out.
    fn kallsyms() -> String {
        let z = "0".repeat(16);
        ["T nft_do_chain", "t nft_meta_get_eval\t[nft_meta_bridge]", "T nf_tables_newrule", "t owner_mt\t[xt_owner]", "d xt_owner_mt_reg\t[xt_owner]", "T tcp_v4_connect", "T"].iter().map(|l| format!("{z} {l}\n")).collect()
    }

    /// A `/proc/modules` excerpt: netfilter's tables, and modules that only
    /// share their first letters (NFS, the NVDIMM driver, NFC).
    fn modules() -> String {
        let z = format!("0x{}", "0".repeat(16));
        ["nf_tables 307200 0 -", "nfsd 856064 0 -", "nft_chain_nat 16384 0 -", "nfs 413696 0 -", "nfs_acl 16384 1 nfsd,", "nfnetlink 20480 1 nf_tables,", "nfit 69632 0 -", "nfc 135168 0 -", "x_tables 53248 1 xt_owner,", "xt_owner 16384 0 -", "ip_tables 32768 0 -", "virtio_net 61440 0 -"].iter().map(|l| format!("{l} Live {z}\n")).collect()
    }

    #[test]
    fn nft_symbols_and_modules_are_counted_by_name() {
        let counts = count_nft_symbols(kallsyms().lines().map(str::to_string));
        assert_eq!(counts.get("nft_"), Some(&2), "nft_do_chain, nft_meta_get_eval: {counts:?}");
        assert_eq!(counts.get("nf_tables"), Some(&1), "{counts:?}");
        assert_eq!(counts.get("xt_owner"), Some(&1), "the symbol name, not the [module] tag: {counts:?}");
        assert_eq!(counts.get("nft_meta"), Some(&1), "{counts:?}");
        assert_eq!(count_nft_symbols(std::iter::empty()).values().sum::<usize>(), 0);
        assert_eq!(nf_modules(&modules()), ["nf_tables", "nft_chain_nat", "nfnetlink", "x_tables", "xt_owner"], "never nfs, nfsd, nfs_acl, nfit or nfc");
        assert!(nf_modules("").is_empty());
    }

    #[test]
    fn nft_evidence_reads_a_planted_proc_and_says_none_when_unreadable() {
        let t = tempfile::tempdir().unwrap();
        let (k, m) = (kallsyms(), modules());
        plant_proc(t.path(), &[("kallsyms", k.as_bytes()), ("modules", m.as_bytes())]);
        let e = nft_evidence(&t.path().join("proc"));
        assert_eq!(e.kallsyms.as_ref().and_then(|k| k.get("nf_tables")), Some(&1));
        assert_eq!(e.modules.as_deref().map(<[String]>::len), Some(5));
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.starts_with("{\"kallsyms\":{\"nf_tables\":1,\"nft_\":2,\"nft_meta\":1,\"xt_owner\":1},\"modules\":[\"nf_tables\""), "{json}");
        assert_eq!(nft_evidence(&t.path().join("absent")), NftEvidence { kallsyms: None, modules: None });
        let boot = serde_json::to_string(&boot_report(&RealSys)).unwrap();
        assert!(boot.starts_with("{\"pid\":") && boot.contains("\"nf_tables\":{\"kallsyms\":"), "{boot}");
        if !cfg!(target_os = "linux") {
            assert!(boot.contains("\"nf_tables\":{\"kallsyms\":null,\"modules\":null}"), "no /proc here: {boot}");
        }
    }

    #[test]
    fn uids_are_read_from_proc_status() {
        assert_eq!(parse_uids("Name:\tsleep\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"), Some((1000, 1000)));
        assert_eq!(parse_uids("Uid:\t1000\t0\t0\t0\n"), Some((1000, 0)));
        assert_eq!(parse_uids("Uid:\t1000\n"), None);
        assert_eq!(parse_uids("Name:\tx\n"), None);
        let t = tempfile::tempdir().unwrap();
        let status = |r: u32, e: u32| format!("Name:\tx\nState:\tS (sleeping)\nUid:\t{r}\t{e}\t{e}\t{e}\n");
        let (agent, root, setuid, other) = (status(1000, 1000), status(0, 0), status(1000, 0), status(1001, 1001));
        let zombie = agent.replace("S (sleeping)", "Z (zombie)");
        let no_state = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(is_running_as(&agent, 1000) && is_running_as(no_state, 1000) && !is_running_as(&zombie, 1000) && !is_running_as(&setuid, 1000));
        plant_proc(
            t.path(),
            &[
                ("42/status", agent.as_bytes()),
                ("7/status", agent.as_bytes()),
                ("1/status", root.as_bytes()),
                ("43/status", setuid.as_bytes()),
                ("44/status", other.as_bytes()),
                ("46/status", zombie.as_bytes()),
                ("self/status", agent.as_bytes()),
                ("+5/status", agent.as_bytes()),
            ],
        );
        std::fs::create_dir_all(t.path().join("proc/45")).unwrap();
        assert_eq!(pids_of_uid(&t.path().join("proc"), 1000), [7, 42], "real and effective, running (46 is a zombie), numeric entries only, ascending");
        assert_eq!(pids_of_uid(&t.path().join("proc"), 0), [1]);
        assert!(pids_of_uid(&t.path().join("absent"), 1000).is_empty());
    }
}
