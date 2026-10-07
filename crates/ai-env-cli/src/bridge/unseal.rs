//! One unseal with a deadline, a countdown and a way to give up (S7).
//!
//! Touch ID has no timeout of its own: `age -d` waits for the Secure Enclave,
//! and the Enclave waits for the person. Everything that unseals a container on
//! the way to a MicroVM therefore runs it as a job: the decrypt happens on its
//! own thread with the child in its own process group
//! ([`AgeTool::decrypt_to_bytes_killable`]), the caller is told how long it has
//! been waiting, and when the budget runs out the group is killed — which also
//! closes the dialog, since `age-plugin-se` is in it.
//!
//! Why a budget at all: S8's wrapper must answer Cursor within its initialize
//! window, and `vm exec` must not hang a terminal for ever. Exit codes follow
//! D8 and `errors.rs`: a dismissed dialog is 3 (cancelled), a budget that ran
//! out is 5 (auth unavailable, with `ai-env vm warm` as the way to pay the
//! Touch ID ahead of time), a missing plugin 5, the wrong key 4.
//!
//! Signals stay the caller's: `process_group(0)` means a terminal Ctrl-C no
//! longer reaches `age`, so whoever owns SIGINT calls [`UnsealJob::kill`].
use crate::age_cmd::{AgeKill, AgeTool};
use crate::errors::{CliError, Result};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The default budget for one unseal (`[creds].unseal_timeout_s`): long enough
/// to find the Mac, short enough that a forgotten dialog does not hold a
/// command for ever.
pub const DEFAULT_UNSEAL_TIMEOUT_S: u64 = 60;
/// The range `[creds].unseal_timeout_s` accepts.
pub const UNSEAL_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 10..=600;
/// The countdown says something at once, then every this many seconds.
const COUNTDOWN_EVERY_S: u64 = 10;
/// …and once more when this little is left, whatever the interval.
const COUNTDOWN_LAST_S: u64 = 5;

/// Should the countdown speak after `elapsed_s` of `budget_s`? At once, every
/// [`COUNTDOWN_EVERY_S`], and at [`COUNTDOWN_LAST_S`] left — never twice for
/// the same second, and never once the budget is spent (the deadline speaks
/// for itself).
#[must_use]
pub fn countdown_at(elapsed_s: u64, budget_s: u64) -> bool {
    if elapsed_s >= budget_s {
        return false;
    }
    let left = budget_s - elapsed_s;
    elapsed_s == 0 || elapsed_s.is_multiple_of(COUNTDOWN_EVERY_S) || left == COUNTDOWN_LAST_S
}

/// `waiting for Touch ID to unseal <what>, <n> s left`: what the countdown
/// prints, with the caller's prefix (`ai-env`, or `ai-env-claude` in S8).
#[must_use]
pub fn countdown_line(prefix: &str, what: &str, left_s: u64) -> String {
    format!("{prefix}: waiting for Touch ID to unseal {what}, {left_s} s left")
}

/// An unseal running on its own thread. Dropping it kills the decrypt, so no
/// abandoned dialog outlives the command that asked for it.
pub struct UnsealJob {
    rx: Receiver<Result<Zeroizing<Vec<u8>>>>,
    kill: Arc<AgeKill>,
    started: Instant,
    budget: Duration,
    what: String,
    /// Set once this job killed its own decrypt, so `Drop` does not run the
    /// TERM-then-KILL ladder a second time.
    killed: std::sync::atomic::AtomicBool,
    /// Who speaks in the countdown: `ai-env`, or `ai-env-claude` for S8's wrapper.
    prefix: &'static str,
}

impl UnsealJob {
    /// Start `age -d -i identity` on `ciphertext` in the background. Nothing is
    /// printed and nothing waits until [`Self::wait`].
    ///
    /// `what` names the container in the countdown and in the failure
    /// ("the setup token", "the runtime key"); it is never a value.
    pub fn start(age: Arc<AgeTool>, identity: PathBuf, ciphertext: Vec<u8>, budget: Duration, what: impl Into<String>) -> UnsealJob {
        let (tx, rx) = mpsc::channel();
        let kill = Arc::new(AgeKill::new());
        let worker = Arc::clone(&kill);
        let what = what.into();
        let name = format!("unseal {what}");
        let spawned = std::thread::Builder::new().name(name).spawn(move || {
            let out = age.decrypt_to_bytes_killable(&identity, &ciphertext, &worker);
            // The receiver is gone when the caller gave up; the plaintext is dropped (and zeroized) here.
            let _ = tx.send(out);
        });
        if let Err(e) = spawned {
            let (tx2, rx2) = mpsc::channel();
            let _ = tx2.send(Err(CliError::Msg(format!("cannot start the unseal thread: {e}"))));
            return UnsealJob { rx: rx2, kill, started: Instant::now(), budget, what, killed: std::sync::atomic::AtomicBool::new(false), prefix: "ai-env" };
        }
        UnsealJob { rx, kill, started: Instant::now(), budget, what, killed: std::sync::atomic::AtomicBool::new(false), prefix: "ai-env" }
    }

    /// Speak as `prefix` in the countdown (S8's wrapper passes `ai-env-claude`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: &'static str) -> UnsealJob {
        self.prefix = prefix;
        self
    }

    /// End the decrypt now, closing the Touch ID dialog with it. For the
    /// caller's own signal handling; [`Self::wait`] does it on the deadline and
    /// `Drop` on abandonment.
    pub fn kill(&self) {
        self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.kill.kill_group();
    }

    /// Is the decrypt still running?
    #[must_use]
    pub fn running(&self) -> bool {
        self.kill.running()
    }

    /// How long this job has been waiting.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Wait for the plaintext, calling `tick` with each countdown line
    /// ([`countdown_at`]). On the budget the group is killed and the failure is
    /// exit 5, naming `ai-env vm warm` as the way to pay the Touch ID ahead of
    /// time; a dismissed dialog is exit 3 and a wrong key exit 4, as
    /// `age_cmd::classify_failure` decides.
    pub fn wait(self, mut tick: impl FnMut(&str)) -> Result<Zeroizing<Vec<u8>>> {
        let budget_s = self.budget.as_secs().max(1);
        let mut said: Option<u64> = None;
        loop {
            let elapsed_s = self.started.elapsed().as_secs();
            // Never twice for the same second: a `recv_timeout` that returns a little early would otherwise
            // repeat a line.
            if said != Some(elapsed_s) && countdown_at(elapsed_s, budget_s) {
                said = Some(elapsed_s);
                tick(&countdown_line(self.prefix, &self.what, budget_s - elapsed_s));
            }
            let left = self.budget.checked_sub(self.started.elapsed()).unwrap_or_default();
            if left.is_zero() {
                // An answer that arrived just as the budget ran out is still an answer — asked for
                // BEFORE the kill, since afterwards every answer is the kill's own doing.
                if let Ok(done) = self.rx.try_recv() {
                    return done;
                }
                self.kill();
                return Err(CliError::AuthUnavailable(format!(
                    "no Touch ID within {budget_s} s, so {} was not unsealed and nothing was started (answer the dialog sooner, raise [creds].unseal_timeout_s, or run `ai-env vm warm <workspace>` to pay it ahead of time)",
                    self.what
                )));
            }
            match self.rx.recv_timeout(left.min(Duration::from_secs(1))) {
                Ok(done) => return done,
                Err(RecvTimeoutError::Timeout) => {}
                // The worker thread died without sending (a panic): never a silent success.
                Err(RecvTimeoutError::Disconnected) => {
                    self.kill();
                    return Err(CliError::Msg(format!("the unseal of {} ended without an answer", self.what)));
                }
            }
        }
    }
}

impl Drop for UnsealJob {
    fn drop(&mut self) {
        // An abandoned job must not leave a dialog on screen; a job that already killed its own decrypt
        // does not run the ladder again.
        if !self.killed.load(std::sync::atomic::Ordering::SeqCst) && self.kill.running() {
            self.kill.kill_group();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `AgeTool` aimed at the repo's fake age through a wrapper that carries
    /// `knobs` in its own environment. The knobs never touch this process's
    /// environment, so these tests run in parallel with every other.
    fn fake_age(dir: &std::path::Path, knobs: &[(&str, &str)]) -> Arc<AgeTool> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/age.sh");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mut script = String::from("#!/bin/sh\n");
        for (k, v) in knobs {
            assert!(!v.contains('\''), "a knob value with a quote would not survive the wrapper");
            script.push_str(&format!("{k}='{v}'\nexport {k}\n"));
        }
        // Through `sh`: the repo keeps the fake non-executable (each test harness chmods its own copy).
        script.push_str(&format!("exec /bin/sh {} \"$@\"\n", src.display()));
        let (age, keygen) = (bin.join("age"), bin.join("age-keygen"));
        for p in [&age, &keygen] {
            std::fs::write(p, &script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        Arc::new(AgeTool::for_tests(age, keygen, (1, 3, 2)))
    }

    /// What the fake age accepts as a sealed file: its own shape, not a value.
    fn sealed(age: &AgeTool, dir: &std::path::Path, plaintext: &[u8]) -> (PathBuf, Vec<u8>) {
        let recipients = dir.join("recipients.txt");
        std::fs::write(&recipients, "age1fake\n").unwrap();
        let ct = age.encrypt(&recipients, plaintext).unwrap();
        let identity = dir.join("identity.txt");
        std::fs::write(&identity, "AGE-PLUGIN-SE-FAKE\n").unwrap();
        (identity, ct)
    }

    #[test]
    fn the_countdown_speaks_at_the_start_every_ten_seconds_and_near_the_end() {
        let said: Vec<u64> = (0..60).filter(|e| countdown_at(*e, 60)).collect();
        assert_eq!(said, vec![0, 10, 20, 30, 40, 50, 55]);
        assert!(!countdown_at(60, 60) && !countdown_at(61, 60), "the deadline speaks for itself");
        // A short budget still says something at once, and the 5-s line never doubles the interval's.
        assert_eq!((0..10).filter(|e| countdown_at(*e, 10)).collect::<Vec<_>>(), vec![0, 5]);
        assert_eq!(countdown_line("ai-env", "the setup token", 25), "ai-env: waiting for Touch ID to unseal the setup token, 25 s left");
        assert!(countdown_line("ai-env-claude", "the runtime key", 5).starts_with("ai-env-claude: waiting for Touch ID"));
    }

    #[test]
    fn an_answered_unseal_returns_the_plaintext_and_says_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let age = fake_age(dir.path(), &[]);
        let (identity, ct) = sealed(&age, dir.path(), b"PLAINTEXT-OF-THE-TEST\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the test container");
        let mut lines = Vec::new();
        let out = job.wait(|l| lines.push(l.to_string())).unwrap();
        assert_eq!(&out[..], b"PLAINTEXT-OF-THE-TEST\n");
        assert_eq!(lines.len(), 1, "only the opening line for a prompt answered at once: {lines:?}");
        assert!(lines[0].starts_with("ai-env: ") && lines[0].contains("30 s left"), "{lines:?}");
        // S8's wrapper speaks as itself.
        let (identity, ct) = sealed(&age, dir.path(), b"AGAIN\n");
        let mut lines = Vec::new();
        UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the test container").with_prefix("ai-env-claude").wait(|l| lines.push(l.to_string())).unwrap();
        assert!(lines[0].starts_with("ai-env-claude: waiting for Touch ID"), "{lines:?}");
    }

    #[test]
    fn a_slow_prompt_counts_down_and_still_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let age = fake_age(dir.path(), &[("FAKE_AGE_DELAY_MS", "1200")]);
        let (identity, ct) = sealed(&age, dir.path(), b"SLOW\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(6), "the test container");
        let mut lines = Vec::new();
        let out = job.wait(|l| lines.push(l.to_string()));
        assert_eq!(&out.unwrap()[..], b"SLOW\n");
        assert!(lines.len() >= 2, "a prompt answered after a second counts down: {lines:?}");
        let left: Vec<&String> = lines.iter().collect();
        assert!(left[0].contains("6 s left"), "{lines:?}");
    }

    #[test]
    fn an_unanswered_prompt_hits_the_budget_exits_5_and_the_group_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let (pidfile, log) = (dir.path().join("age.pid"), dir.path().join("age.log"));
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string()), ("FAKE_AGE_LOG", &log.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(2), "the setup token");
        let mut lines = Vec::new();
        let e = job.wait(|l| lines.push(l.to_string())).unwrap_err();
        assert_eq!(e.exit_code(), 5, "{e}");
        let text = e.to_string();
        assert!(text.contains("no Touch ID within 2 s") && text.contains("the setup token") && text.contains("nothing was started") && text.contains("ai-env vm warm"), "{text}");
        assert!(!lines.is_empty(), "it said it was waiting: {lines:?}");
        // The group signal reached the child: its own TERM trap logged it, and the pid is gone.
        let logged = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(logged.contains("age TERM "), "the decrypt was signalled: {logged:?}");
        // The whole GROUP is gone, not just the leader: the decrypt ran in its own group, so the
        // plugin holding the dialog and the leader's own children went with it.
        let pgid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        for _ in 0..200 {
            // SAFETY: a plain existence check; signal 0 sends nothing.
            if unsafe { libc::killpg(pgid, 0) } != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the decrypting process group {pgid} is still alive");
    }

    #[test]
    fn a_dismissed_dialog_is_exit_3() {
        let dir = tempfile::tempdir().unwrap();
        let age = fake_age(dir.path(), &[("FAKE_AGE_FAIL", "cancel")]);
        let (identity, ct) = sealed(&age, dir.path(), b"CANCELLED\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the setup token");
        let e = job.wait(|_| {}).unwrap_err();
        assert_eq!(e.exit_code(), 3, "{e}");
    }

    /// The point of the job: the caller works while the dialog is up. The fake
    /// holds the decrypt until a file appears, and the file is written after
    /// the job started, so the plaintext can only arrive afterwards.
    #[test]
    fn work_overlaps_the_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let release = dir.path().join("release");
        let age = fake_age(dir.path(), &[("FAKE_AGE_WAIT_FILE", &release.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"OVERLAP\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(20), "the test container");
        // Stand in for the provisioning that runs concurrently.
        let mut spun = 0_u32;
        while !job.running() && spun < 500 {
            std::thread::sleep(Duration::from_millis(10));
            spun += 1;
        }
        assert!(job.running(), "the decrypt is up while we work");
        std::fs::write(&release, b"go").unwrap();
        let out = job.wait(|_| {});
        assert_eq!(&out.unwrap()[..], b"OVERLAP\n");
    }

    /// A kill that lands before the child exists is not lost (the audit's
    /// finding): an `AgeKill` already killed spawns nothing, so no dialog
    /// appears for a job that was given up. The fake would hang and log its
    /// start if it ran.
    #[test]
    fn a_kill_before_the_child_exists_spawns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("age.log");
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_LOG", &log.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let before = std::fs::read_to_string(&log).unwrap_or_default().lines().filter(|l| l.contains(" -d ")).count();
        let kill = AgeKill::new();
        kill.kill_group();
        assert!(kill.cancelled() && !kill.running());
        let e = age.decrypt_to_bytes_killable(&identity, &ct, &kill).unwrap_err();
        assert_eq!(e.exit_code(), 3, "{e}");
        let after = std::fs::read_to_string(&log).unwrap_or_default().lines().filter(|l| l.contains(" -d ")).count();
        assert_eq!(after, before, "no decrypt was started");
    }

    /// Giving up closes the dialog: dropping the job kills the decrypt.
    #[test]
    fn dropping_a_job_kills_the_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let (pidfile, log) = (dir.path().join("age.pid"), dir.path().join("age.log"));
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string()), ("FAKE_AGE_LOG", &log.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"ABANDONED\n");
        let pid = {
            let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the test container");
            let mut spun = 0_u32;
            while !pidfile.exists() && spun < 500 {
                std::thread::sleep(Duration::from_millis(10));
                spun += 1;
            }
            let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
            drop(job);
            pid
        };
        for _ in 0..100 {
            // SAFETY: a plain existence check; signal 0 sends nothing.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the abandoned decrypt {pid} is still alive");
    }
}
