//! Clock, entropy and boot facts for the hooks, behind [`SysOps`] so the hook
//! tests never touch the real clock or the kernel pool.
//!
//! A VM restored from the image snapshot keeps the snapshot's wall clock and
//! the snapshot's RNG state, identically in every clone. S3 v0 therefore
//! MEASURES the clock (guest time, the PL031 RTC, the payload's `created`)
//! and only steps it under `--clock forward`, which S6 enables once its
//! `clock-after-resume` probe has data. Entropy: `/run` mixes per-VM material
//! into `/dev/urandom` and attempts `RNDRESEEDCRNG` (needs CAP_SYS_ADMIN;
//! logged, never fatal); the boot nonce does not depend on either.
use serde::Serialize;
use sha2::{Digest, Sha256};

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
}

fn read_trim(path: &str) -> Option<String> {
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
    }
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
}
