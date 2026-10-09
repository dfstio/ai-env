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
//! out is 5 (auth unavailable, with the caller's advice:
//! [`UnsealJob::with_deadline`]), a missing plugin 5. A key the keystore does
//! not hold is 4, decided before any job starts (`select::resolve_for_decrypt`);
//! an identity `age` itself cannot use fails with age's own error, exit 1.
//!
//! Signals stay the caller's: `process_group(0)` means a terminal Ctrl-C no
//! longer reaches `age`, so whoever owns SIGINT ends the job
//! ([`UnsealJob::kill`], or the `stop` of [`UnsealJob::wait_or`]). Giving up
//! any other way closes the dialog too: dropping the job, even before its
//! child exists, or dropping the future of `wait_or`.
use crate::age_cmd::{AgeKill, AgeTool};
use crate::errors::{CliError, Result};
use std::future::Future;
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
/// What the deadline's failure advises unless its caller knows more ([`UnsealJob::with_deadline`]).
const DEADLINE_ADVICE: &str = "answer the dialog sooner or raise [creds].unseal_timeout_s";
/// How the deadline's failure begins ([`is_deadline`]).
const DEADLINE_HEAD: &str = "no Touch ID within ";

/// Whether `e` is an unseal's deadline (exit 5): a caller adds what only it
/// knows, as `vm exec` does with the way to pay the token's prompt ahead of time.
#[must_use]
pub fn is_deadline(e: &CliError) -> bool {
    matches!(e, CliError::AuthUnavailable(m) if m.starts_with(DEADLINE_HEAD))
}

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
    /// What the deadline's failure says after `what` stayed sealed.
    advice: String,
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
        let advice = DEADLINE_ADVICE.to_string();
        if let Err(e) = spawned {
            let (tx2, rx2) = mpsc::channel();
            let _ = tx2.send(Err(CliError::Msg(format!("cannot start the unseal thread: {e}"))));
            return UnsealJob { rx: rx2, kill, started: Instant::now(), budget, what, killed: std::sync::atomic::AtomicBool::new(false), prefix: "ai-env", advice };
        }
        UnsealJob { rx, kill, started: Instant::now(), budget, what, killed: std::sync::atomic::AtomicBool::new(false), prefix: "ai-env", advice }
    }

    /// Speak as `prefix` in the countdown (S8's wrapper passes `ai-env-claude`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: &'static str) -> UnsealJob {
        self.prefix = prefix;
        self
    }

    /// What the deadline's failure says after `what` stayed sealed, in
    /// place of "answer the dialog sooner or raise [creds].unseal_timeout_s":
    /// only the caller knows whether anything was started yet, and whether
    /// `ai-env vm warm` could have spared this prompt.
    #[must_use]
    pub fn with_deadline(mut self, advice: impl Into<String>) -> UnsealJob {
        self.advice = advice.into();
        self
    }

    /// End the decrypt now, closing the Touch ID dialog with it. For the
    /// caller's own signal handling; [`Self::wait`] does it on the deadline and
    /// `Drop` on abandonment.
    pub fn kill(&self) {
        self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.kill.kill_group();
    }

    /// A handle that ends this job's decrypt from elsewhere: an async
    /// caller's signal handler, while [`Self::wait`] runs on a blocking thread.
    #[must_use]
    pub fn kill_handle(&self) -> Arc<AgeKill> {
        Arc::clone(&self.kill)
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
    /// exit 5 with the caller's advice ([`Self::with_deadline`]); a dismissed
    /// dialog is exit 3, a missing plugin 5 and any other age failure exit 1
    /// with age's own error, as `age_cmd::classify_failure` decides.
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
                return Err(CliError::AuthUnavailable(format!("{DEADLINE_HEAD}{budget_s} s, so {} stayed sealed ({})", self.what, self.advice)));
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

    /// [`Self::wait`] for an async caller: on the blocking pool, its countdown
    /// on stderr, ended early by `stop` (the group killed first, then `Err`
    /// with what `stop` gave; a stop that comes with the answer wins, and the
    /// plaintext is dropped). Dropping the returned future kills the group as
    /// well: the job itself lives on the blocking thread, so an outer select
    /// or timeout that gave up on its caller would otherwise leave the dialog
    /// up until the budget ran out, and a runtime's shutdown waiting for it.
    pub async fn wait_or<S>(self, stop: impl Future<Output = S>) -> std::result::Result<Result<Zeroizing<Vec<u8>>>, S> {
        let close = CloseOnDrop(Some(self.kill_handle()));
        let what = self.what.clone();
        let wait = tokio::task::spawn_blocking(move || self.wait(crate::bridge::signals::say));
        tokio::pin!(stop);
        let out = tokio::select! {
            biased;
            s = &mut stop => Err(s),
            joined = wait => Ok(joined.unwrap_or_else(|e| Err(CliError::Msg(format!("the unseal of {what} failed: {e}"))))),
        };
        if out.is_ok() {
            // Answered: the child is reaped, nothing is left to close.
            close.disarm();
        }
        out
    }
}

/// Kills one job's decrypt group when dropped while armed ([`UnsealJob::wait_or`]).
struct CloseOnDrop(Option<Arc<AgeKill>>);

impl CloseOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(kill) = self.0.take() {
            kill.kill_group();
        }
    }
}

impl Drop for UnsealJob {
    fn drop(&mut self) {
        // An abandoned job must not leave a dialog on screen, even one dropped before its child exists:
        // `kill_group` marks the kill first, so that decrypt never spawns, or is killed as it is adopted
        // (with no child, or one already reaped, it returns at once). A job that already killed its own
        // decrypt does not run the ladder again.
        if !self.killed.load(std::sync::atomic::Ordering::SeqCst) {
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

    /// The deadline is exit 5 and kills the whole group; its failure says what
    /// stayed sealed and only the caller's advice ([`UnsealJob::with_deadline`]):
    /// no fixed `vm warm` hint, no fixed "nothing was started" (M55).
    #[test]
    fn an_unanswered_prompt_hits_the_budget_exits_5_and_the_group_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let (pidfile, log) = (dir.path().join("age.pid"), dir.path().join("age.log"));
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string()), ("FAKE_AGE_LOG", &log.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(2), "the setup token").with_deadline("nothing was delivered; THE CALLER'S ADVICE");
        let mut lines = Vec::new();
        let e = job.wait(|l| lines.push(l.to_string())).unwrap_err();
        assert_eq!(e.exit_code(), 5, "{e}");
        assert!(is_deadline(&e), "{e}");
        assert_eq!(e.to_string(), "no Touch ID within 2 s, so the setup token stayed sealed (nothing was delivered; THE CALLER'S ADVICE)");
        assert!(!is_deadline(&CliError::AuthUnavailable("the sealed token was refused".into())) && !is_deadline(&CliError::Msg(e.to_string())), "only an exit-5 deadline");
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

    /// Without a caller's advice the deadline says only what is true wherever
    /// an unseal runs: answer sooner, or allow more time.
    #[test]
    fn the_default_deadline_advice_names_no_command() {
        let dir = tempfile::tempdir().unwrap();
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1")]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let e = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(1), "the runtime key").wait(|_| {}).unwrap_err();
        assert_eq!(e.to_string(), "no Touch ID within 1 s, so the runtime key stayed sealed (answer the dialog sooner or raise [creds].unseal_timeout_s)");
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
            // Its pid once written: the file exists, empty, before the pid is in it.
            let pid = decrypt_group(&pidfile);
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

    /// The process group the fake's hanging decrypt wrote to `pidfile` (it is
    /// the group's leader), once written (within 5 s): the shell creates the
    /// file before it writes the pid, so an empty read is waited past.
    fn decrypt_group(pidfile: &std::path::Path) -> i32 {
        for _ in 0..250 {
            if let Some(pgid) = std::fs::read_to_string(pidfile).ok().and_then(|t| t.trim().parse().ok()) {
                return pgid;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the fake decrypt never started");
    }

    /// Whether group `pgid` is gone within 2 s; one still alive is killed
    /// here, so a failing test leaves no fake dialog behind.
    fn group_ends(pgid: i32) -> bool {
        for _ in 0..100 {
            // SAFETY: a plain existence check; signal 0 sends nothing.
            if unsafe { libc::killpg(pgid, 0) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: the test's own fake decrypt group, still alive.
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
        false
    }

    /// A job dropped before its child exists cancels it (M43): the decrypt
    /// never spawns, or is killed as it is adopted, so no dialog appears that
    /// nobody waits for. The drop comes microseconds after the start, before
    /// the thread could spawn and adopt the hanging fake.
    #[test]
    fn a_job_dropped_before_its_child_exists_leaves_no_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let (pidfile, log) = (dir.path().join("age.pid"), dir.path().join("age.log"));
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string()), ("FAKE_AGE_LOG", &log.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        drop(UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the setup token"));
        std::thread::sleep(Duration::from_millis(1500));
        if let Some(pgid) = std::fs::read_to_string(&pidfile).ok().and_then(|t| t.trim().parse::<i32>().ok()) {
            assert!(group_ends(pgid), "a job dropped before its child existed left decrypt group {pgid} running");
        }
    }

    /// Dropping the future of [`UnsealJob::wait_or`] closes the dialog (M8):
    /// an outer select or timeout that gives up on its caller kills the group
    /// at once, never at the budget, and the runtime then shuts down without
    /// waiting for the blocking thread.
    #[test]
    fn a_dropped_async_wait_closes_the_dialog() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("age.pid");
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the setup token");
        let pgid = decrypt_group(&pidfile);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let given_up = rt.block_on(async { tokio::time::timeout(Duration::from_millis(300), job.wait_or(std::future::pending::<()>())).await });
        assert!(given_up.is_err(), "the wait was given up by the timeout");
        assert!(group_ends(pgid), "the dropped wait left decrypt group {pgid} on screen");
        let t = Instant::now();
        drop(rt);
        assert!(t.elapsed() < Duration::from_secs(3), "the runtime's shutdown waited {:?} for the blocking wait", t.elapsed());
    }

    /// `stop` ends the wait early: the group is killed first, and `Err` carries
    /// what `stop` gave (the caller's signal), never a plaintext.
    #[test]
    fn a_stop_ends_the_async_wait_and_kills_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("age.pid");
        let age = fake_age(dir.path(), &[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", &pidfile.display().to_string())]);
        let (identity, ct) = sealed(&age, dir.path(), b"NEVER\n");
        let job = UnsealJob::start(Arc::clone(&age), identity, ct, Duration::from_secs(30), "the setup token");
        let pgid = decrypt_group(&pidfile);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let stopped = rt.block_on(job.wait_or(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            130
        }));
        assert_eq!(stopped.err(), Some(130));
        assert!(group_ends(pgid), "the stop left decrypt group {pgid} running");
        // Answered before any stop: the plaintext.
        let other = tempfile::tempdir().unwrap();
        let age = fake_age(other.path(), &[]);
        let (identity, ct) = sealed(&age, other.path(), b"ANSWERED\n");
        let answered = rt.block_on(UnsealJob::start(age, identity, ct, Duration::from_secs(30), "the setup token").wait_or(std::future::pending::<i32>()));
        assert_eq!(&answered.ok().unwrap().unwrap()[..], b"ANSWERED\n");
    }
}
