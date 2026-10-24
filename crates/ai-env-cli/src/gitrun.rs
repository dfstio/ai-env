//! `git` as a child process, for the S8 workspace data plane on both sides
//! of the bridge: the Mac's seed, snapshot and code-out (`bridge::workspace`,
//! `bridge::codeout`) and the agent's helper in the VM (`shim::wshelper`).
//! Std only, so every feature set has it.
//!
//! Every run:
//! * is `git` from an absolute `PATH` entry — a relative or empty entry would
//!   resolve against the run's working directory, the workspace — or the
//!   program [`GitRun::with_program`] names (tests, the shim's `--git`);
//! * starts with [`OVERRIDES`], so no config a repository carries (the agent
//!   writes the VM's `.git/config`) runs a hook or an fsmonitor, splits the
//!   index, starts gc or maintenance, colours the output or quotes a path;
//! * on the Mac ([`GitRun::mac`]) inherits the environment minus every
//!   `GIT_*` variable — a `GIT_DIR` or `GIT_INDEX_FILE` the caller inherited
//!   would point the run at another repository or index — and keeps the
//!   user's and the system config; in the VM ([`GitRun::vm`]) starts from an
//!   empty environment: the agent's `HOME`, [`VM_PATH`], `LC_ALL=C`, no
//!   global config, no terminal prompt. What [`GitRun::env`] sets comes last
//!   (a snapshot's `GIT_INDEX_FILE`);
//! * leads its own process group, which a watchdog ends once the run's
//!   timeout passes, or its cancel flag is set ([`GitRun::cancel_on`]):
//!   SIGTERM, then SIGKILL [`KILL_AFTER`] later. The group is
//!   signalled only while its leader is unreaped (its zombie keeps the id
//!   the run's), and the leader is reaped only once every pipe of the run
//!   closed, so a process of the run that holds a pipe past the timeout is
//!   killed with it;
//! * returns stdout byte for byte, at most [`OUTPUT_MAX`]; a failure keeps
//!   the last [`STDERR_LINES`] lines of stderr, scrubbed.
//!
//! Every call blocks its thread until the run ended: async code calls it on
//! a blocking thread (`spawn_blocking`).
use crate::errors::CliError;
use crate::wire::redact::scrub;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

/// The `-c` overrides every run starts with: no hooks (`/dev/null` is no
/// directory), no fsmonitor daemon, no split index, no automatic gc or
/// maintenance, no colour, and non-ASCII paths printed as they are.
pub const OVERRIDES: [&str; 7] = [
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.splitIndex=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "color.ui=false",
    "core.quotePath=false",
];
/// `PATH` of a VM run, where its `git` is found too (the image's is `/usr/bin/git`).
pub const VM_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// The most stdout a run returns; more is [`GitError::TooLarge`] (the group is killed).
pub const OUTPUT_MAX: usize = 64 * 1024 * 1024;
/// The lines of stderr a failure keeps: the last ones, where git's `fatal:` is.
pub const STDERR_LINES: usize = 3;
/// A run's budget unless [`GitRun::timeout`] sets its step's own.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// After the timeout's SIGTERM: how long the group has before SIGKILL.
pub const KILL_AFTER: Duration = Duration::from_secs(2);
/// How often a run's watchdog looks at its cancel flag ([`GitRun::cancel_on`]).
const CANCEL_POLL: Duration = Duration::from_millis(50);
/// The tail of stderr kept while it is read.
const STDERR_KEEP: usize = 16 * 1024;
/// The longest stderr line a failure keeps, in characters.
const STDERR_LINE_CHARS: usize = 200;

/// Why a run gave no answer.
#[derive(Debug)]
pub enum GitError {
    /// No `git` in an absolute `PATH` entry, or the program does not exist.
    Missing,
    /// The run outlived its timeout (whole seconds, rounded up); its group was killed.
    Timeout { secs: u64 },
    /// git exited non-zero (`code`; `None` when a signal ended it). `stderr`
    /// holds the last [`STDERR_LINES`] lines of its stderr, scrubbed, one per line.
    Failed { code: Option<i32>, stderr: String },
    /// stdout passed [`OUTPUT_MAX`]; the group was killed.
    TooLarge,
    /// Spawning, reading or reaping the run failed.
    Io(io::Error),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Missing => f.write_str("git not found (no executable git in an absolute PATH entry)"),
            GitError::Timeout { secs } => write!(f, "git did not finish within {secs} s (stopped)"),
            GitError::Failed { code, stderr } => {
                match code {
                    Some(c) => write!(f, "git exited {c}")?,
                    None => f.write_str("git was ended by a signal")?,
                }
                // One line: the kept lines joined.
                if !stderr.is_empty() {
                    write!(f, ": {}", stderr.replace('\n', " | "))?;
                }
                Ok(())
            }
            GitError::TooLarge => write!(f, "git printed more than {} MiB", OUTPUT_MAX / (1024 * 1024)),
            GitError::Io(e) => write!(f, "git: {e}"),
        }
    }
}

impl std::error::Error for GitError {}

/// A git failure ends a command with exit 1, its text the error's.
impl From<GitError> for CliError {
    fn from(e: GitError) -> Self {
        CliError::Msg(e.to_string())
    }
}

/// Which side of the bridge a run is on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Side {
    Mac,
    Vm { home: PathBuf },
}

/// One kind of git run (program, working directory, environment, timeout),
/// run as many times as needed.
#[derive(Debug, Clone)]
pub struct GitRun {
    program: Option<PathBuf>,
    cwd: PathBuf,
    side: Side,
    env: Vec<(OsString, OsString)>,
    timeout: Duration,
    cancel: Option<Arc<AtomicBool>>,
    /// [`GitRun::without_credentials`].
    no_credentials: bool,
}

impl GitRun {
    /// A run on the Mac in `cwd`: `git` from this process's `PATH` (absolute
    /// entries only), the environment minus every inherited `GIT_*` variable.
    #[must_use]
    pub fn mac(cwd: &Path) -> GitRun {
        GitRun { program: find_git(std::env::var_os("PATH").as_deref()), cwd: cwd.to_path_buf(), side: Side::Mac, env: Vec::new(), timeout: DEFAULT_TIMEOUT, cancel: None, no_credentials: false }
    }

    /// A run in the VM in `cwd`, as the agent whose home is `home`: `git`
    /// from [`VM_PATH`], and only `HOME`, `PATH`, `LC_ALL=C`,
    /// `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_TERMINAL_PROMPT=0` in its
    /// environment (the image's system config, which names the agent, stays).
    #[must_use]
    pub fn vm(cwd: &Path, home: &Path) -> GitRun {
        GitRun { program: find_git(Some(OsStr::new(VM_PATH))), cwd: cwd.to_path_buf(), side: Side::Vm { home: home.to_path_buf() }, env: Vec::new(), timeout: DEFAULT_TIMEOUT, cancel: None, no_credentials: false }
    }

    /// Run this program instead of the `git` found on `PATH` (an absolute
    /// path: tests, the shim's `--git`).
    #[must_use]
    pub fn with_program(mut self, program: &Path) -> GitRun {
        self.program = Some(program.to_path_buf());
        self
    }

    /// Set `key` in every run's environment, after the side's own rules (a
    /// `GIT_*` name too: the Mac strips only what it inherited).
    #[must_use]
    pub fn env(mut self, key: &str, value: impl AsRef<OsStr>) -> GitRun {
        self.env.push((OsString::from(key), value.as_ref().to_os_string()));
        self
    }

    /// On the Mac, also remove what a git run has no business seeing (B3's
    /// review, D16): the variables the age children lose
    /// ([`crate::age_cmd::CHILD_ENV_REMOVED`]: the OAuth token, the API
    /// key, an AWS key, a session token, the stack's passphrase) and the
    /// `ai-env as` marker ([`crate::commands::RUNNER_MARKER`]), so a git
    /// under `ai-env as ops -- ai-env doctor` inherits no credential. (A VM
    /// run starts from an empty environment already.)
    #[must_use]
    pub fn without_credentials(mut self) -> GitRun {
        self.no_credentials = true;
        self
    }

    /// Each run's budget ([`DEFAULT_TIMEOUT`] unless set).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> GitRun {
        self.timeout = timeout;
        self
    }

    /// Give up every run once `flag` is set: a run not started yet never
    /// starts, a running one's group is ended as at its timeout (SIGTERM,
    /// SIGKILL [`KILL_AFTER`] later, the flag looked at every 50 ms); either
    /// is [`GitError::Io`] of kind `Interrupted`. A wrapper's start dropped
    /// during its Touch ID stops its WIP snapshot this way (S8 P1).
    #[must_use]
    pub fn cancel_on(mut self, flag: Arc<AtomicBool>) -> GitRun {
        self.cancel = Some(flag);
        self
    }

    /// The program a run starts, `None` when no `git` was found.
    #[must_use]
    pub fn program(&self) -> Option<&Path> {
        self.program.as_deref()
    }

    /// stdout of `git <args>`, byte for byte (stdin is closed).
    pub fn output<I, S>(&self, args: I) -> Result<Vec<u8>, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let (ended, stdout) = self.run(args, None, true)?;
        ended.success().map(|()| stdout)
    }

    /// [`GitRun::output`] with `stdin` written to the run's stdin, then closed.
    pub fn output_stdin<I, S>(&self, args: I, stdin: &[u8]) -> Result<Vec<u8>, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let (ended, stdout) = self.run(args, Some(stdin), true)?;
        ended.success().map(|()| stdout)
    }

    /// Whether `git <args>` exits 0 (`true`) or 1 (`false`), as `merge-base
    /// --is-ancestor`, `diff --quiet` and `show-ref --verify --quiet` answer;
    /// any other end is an error. stdout is not read.
    pub fn succeeds<I, S>(&self, args: I) -> Result<bool, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let (ended, _) = self.run(args, None, false)?;
        match ended.code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            code => Err(GitError::Failed { code, stderr: ended.stderr }),
        }
    }

    /// `git <args>` with its stdin and stdout the caller's (`cat-file
    /// --batch`), under the same group and deadline as every run.
    pub fn spawn_piped<I, S>(&self, args: I) -> Result<GitChild, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = self.command(args, std::env::vars_os().map(|(k, _)| k))?;
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        Ok(GitChild { run: self.start(cmd)? })
    }

    /// [`Running::start`] for this run: a spawn that failed because the
    /// program does not exist is [`GitError::Missing`]; one that failed on a
    /// working directory that does not exist names that directory.
    fn start(&self, cmd: Command) -> Result<Running, GitError> {
        if self.cancel.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) {
            return Err(cancelled());
        }
        Running::start(cmd, self.timeout, self.cancel.clone()).map_err(|e| match e {
            GitError::Io(io) if io.kind() == io::ErrorKind::NotFound => {
                if self.program.as_deref().is_some_and(is_executable) {
                    GitError::Io(io::Error::new(io.kind(), format!("{}: {io}", self.cwd.display())))
                } else {
                    GitError::Missing
                }
            }
            other => other,
        })
    }

    /// Spawn, feed `stdin`, read stdout (`capture`) and stderr, wait for the
    /// leader (bounded by the watchdog), join the pipes, reap.
    fn run<I, S>(&self, args: I, stdin: Option<&[u8]>, capture: bool) -> Result<(Ended, Vec<u8>), GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = self.command(args, std::env::vars_os().map(|(k, _)| k))?;
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(if capture { Stdio::piped() } else { Stdio::null() });
        let mut run = self.start(cmd)?;
        let (input, output, shared) = (run.stdin.take(), run.stdout.take(), Arc::clone(&run.shared));
        let read = std::thread::scope(|s| {
            let writer = stdin.zip(input).map(|(bytes, mut pipe)| {
                s.spawn(move || {
                    // A run that stops reading closes the pipe: its exit says why, not this write.
                    let _ = pipe.write_all(bytes);
                })
            });
            let reader = output.map(|out| s.spawn(move || read_capped(out, &shared)));
            run.exited();
            if let Some(w) = writer {
                let _ = w.join();
            }
            reader.map(|r| r.join().unwrap_or_else(|_| Err(io::Error::other("the stdout reader panicked"))))
        });
        let tail = run.stderr_tail();
        let status = run.reap()?;
        let ended = run.ended(status, &tail)?;
        let stdout = read.transpose().map_err(GitError::Io)?.unwrap_or_default();
        Ok((ended, stdout))
    }

    /// The command of one run: the program, [`OVERRIDES`], `args`, the
    /// working directory, its own group, and the environment of its side
    /// (`inherited` names this process's variables, for the Mac's strip).
    fn command<I, S>(&self, args: I, inherited: impl IntoIterator<Item = OsString>) -> Result<Command, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let program = self.program.as_deref().ok_or(GitError::Missing)?;
        let mut cmd = Command::new(program);
        for o in OVERRIDES {
            cmd.arg("-c").arg(o);
        }
        cmd.args(args).current_dir(&self.cwd).process_group(0);
        match &self.side {
            Side::Mac => {
                for name in inherited.into_iter().filter(|n| n.as_bytes().starts_with(b"GIT_")) {
                    cmd.env_remove(name);
                }
                if self.no_credentials {
                    for name in crate::age_cmd::CHILD_ENV_REMOVED.iter().chain(&[crate::commands::RUNNER_MARKER]) {
                        cmd.env_remove(name);
                    }
                }
            }
            Side::Vm { home } => {
                cmd.env_clear().env("HOME", home).env("PATH", VM_PATH).env("LC_ALL", "C").env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_TERMINAL_PROMPT", "0");
            }
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        Ok(cmd)
    }
}

/// The first executable `git` in an absolute entry of `path`. A relative or
/// empty entry is skipped: it would resolve against the run's working
/// directory, the workspace.
fn find_git(path: Option<&OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?).filter(|d| d.is_absolute()).map(|d| d.join("git")).find(|p| is_executable(p))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// A run whose stdin and stdout are the caller's ([`GitRun::spawn_piped`]).
/// [`GitChild::finish`] reports it as [`GitRun::output`] does; a child
/// dropped unfinished has its group killed and its leader reaped.
pub struct GitChild {
    run: Running,
}

impl GitChild {
    /// The run's pid, which is also its process group id.
    #[must_use]
    pub fn id(&self) -> u32 {
        u32::try_from(self.run.pid).unwrap_or(0)
    }

    /// The run's stdin, until taken or the run finished.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.run.stdin.as_mut()
    }

    /// The run's stdout, until taken or the run finished.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.run.stdout.as_mut()
    }

    /// Take the run's stdin (drop it to close it).
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.run.stdin.take()
    }

    /// Take the run's stdout; drop it before [`GitChild::finish`], which can
    /// no longer drain it.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.run.stdout.take()
    }

    /// Close stdin, read what stdout still holds to its end (discarded), then
    /// wait for the run within its deadline: `Ok` on exit 0, else as
    /// [`GitRun::output`] fails.
    pub fn finish(mut self) -> Result<(), GitError> {
        self.run.stdin = None;
        if let Some(mut out) = self.run.stdout.take() {
            // What the caller left unread; the watchdog bounds this too.
            let _ = io::copy(&mut out, &mut io::sink());
        }
        self.run.exited();
        let tail = self.run.stderr_tail();
        let status = self.run.reap()?;
        self.run.ended(status, &tail)?.success()
    }
}

/// How a run ended that neither timed out nor printed too much.
struct Ended {
    code: Option<i32>,
    stderr: String,
}

impl Ended {
    /// `Ok` on exit 0, else [`GitError::Failed`].
    fn success(self) -> Result<(), GitError> {
        match self.code {
            Some(0) => Ok(()),
            code => Err(GitError::Failed { code, stderr: self.stderr }),
        }
    }
}

/// What a run's threads share.
struct Shared {
    /// The leader until it is reaped: the group is signalled only with this
    /// lock held, so never under a recycled id.
    child: Mutex<Option<Child>>,
    /// The watchdog's deadline passed (the group was signalled).
    timed_out: AtomicBool,
    /// The run's cancel flag was set (the group was signalled).
    cancelled: AtomicBool,
    /// stdout passed [`OUTPUT_MAX`] (the group was killed).
    too_large: AtomicBool,
}

impl Shared {
    /// Signal the run's group while its leader is unreaped; `false` once reaped.
    fn signal(&self, sig: libc::c_int) -> bool {
        let slot = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pgid) = slot.as_ref().and_then(|c| libc::pid_t::try_from(c.id()).ok()) else {
            return false;
        };
        if pgid > 1 {
            // SAFETY: plain integers; the leader is unreaped while the lock is held, so the id is still its group.
            unsafe { libc::killpg(pgid, sig) };
        }
        true
    }
}

/// One spawned run: its pipes, the stderr reader, the watchdog.
struct Running {
    shared: Arc<Shared>,
    /// The leader's pid, which `process_group(0)` made the group id.
    pid: libc::pid_t,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    cancel: Option<mpsc::Sender<()>>,
    watchdog: Option<JoinHandle<()>>,
    /// The timeout in whole seconds, rounded up (for [`GitError::Timeout`]).
    secs: u64,
}

impl Running {
    /// Spawn `cmd` (stderr piped here), its stderr reader and its watchdog
    /// (`timeout`, and the run's cancel `flag` when it has one).
    fn start(mut cmd: Command, timeout: Duration, flag: Option<Arc<AtomicBool>>) -> Result<Running, GitError> {
        cmd.stderr(Stdio::piped());
        let spawned = {
            #[cfg(test)]
            let _fork = crate::test_locks::forking();
            cmd.spawn()
        };
        let mut child = spawned.map_err(GitError::Io)?;
        let pid = libc::pid_t::try_from(child.id()).unwrap_or(0);
        let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        // From here a failure drops `run`, which kills the group and reaps the leader.
        let mut run = Running {
            shared: Arc::new(Shared { child: Mutex::new(Some(child)), timed_out: AtomicBool::new(false), cancelled: AtomicBool::new(false), too_large: AtomicBool::new(false) }),
            pid,
            stdin,
            stdout,
            stderr: None,
            cancel: None,
            watchdog: None,
            secs: timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0),
        };
        if let Some(err) = stderr {
            run.stderr = Some(thread("git stderr", move || read_tail(err))?);
        }
        let (cancel, cancelled) = mpsc::channel();
        run.cancel = Some(cancel);
        let shared = Arc::clone(&run.shared);
        run.watchdog = Some(thread("git watchdog", move || watchdog(&shared, &cancelled, timeout, flag.as_deref()))?);
        Ok(run)
    }

    /// Block until the leader has exited, leaving it unreaped: its zombie
    /// keeps the group id the run's for the watchdog, which bounds the wait.
    fn exited(&self) {
        let Ok(id) = libc::id_t::try_from(self.pid) else { return };
        loop {
            // SAFETY: an all-zero siginfo_t is a valid value for waitid to fill.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waitid fills `info`; WNOWAIT leaves the leader waitable for `reap`.
            if unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) } == 0 {
                return;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }

    /// The tail of stderr, once its pipe closed (every process of the run let
    /// it go, or the watchdog ended them).
    fn stderr_tail(&mut self) -> Vec<u8> {
        self.stderr.take().and_then(|t| t.join().ok()).unwrap_or_default()
    }

    /// Reap the leader (it has exited: [`Running::exited`]) and end the watchdog.
    fn reap(&mut self) -> Result<ExitStatus, GitError> {
        let child = self.shared.child.lock().unwrap_or_else(PoisonError::into_inner).take();
        let status = match child {
            Some(mut c) => c.wait().map_err(GitError::Io),
            None => Err(GitError::Io(io::Error::other("the git run was reaped already"))),
        };
        self.stop_watchdog();
        status
    }

    /// The run's end once reaped: a timeout or an over-long stdout first (its
    /// group was killed for it), else the exit code and the kept stderr lines.
    fn ended(&self, status: ExitStatus, tail: &[u8]) -> Result<Ended, GitError> {
        if self.shared.cancelled.load(Ordering::SeqCst) {
            return Err(cancelled());
        }
        if self.shared.timed_out.load(Ordering::SeqCst) {
            return Err(GitError::Timeout { secs: self.secs });
        }
        if self.shared.too_large.load(Ordering::SeqCst) {
            return Err(GitError::TooLarge);
        }
        Ok(Ended { code: status.code(), stderr: stderr_lines(tail) })
    }

    fn stop_watchdog(&mut self) {
        self.cancel = None;
        if let Some(w) = self.watchdog.take() {
            let _ = w.join();
        }
    }
}

impl Drop for Running {
    /// A run given up before it was reaped (an error, a [`GitChild`] dropped
    /// unfinished): its group is killed and its leader reaped.
    fn drop(&mut self) {
        let child = {
            let mut slot = self.shared.child.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(pgid) = slot.as_ref().and_then(|c| libc::pid_t::try_from(c.id()).ok()).filter(|p| *p > 1) {
                // SAFETY: plain integers; the leader is unreaped while the lock is held.
                unsafe { libc::killpg(pgid, libc::SIGKILL) };
            }
            slot.take()
        };
        if let Some(mut c) = child {
            let _ = c.wait();
        }
        self.stop_watchdog();
    }
}

/// A named thread; one that cannot start is an I/O error (the run is then
/// dropped: its group killed).
fn thread<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> Result<JoinHandle<T>, GitError> {
    std::thread::Builder::new().name(name.to_string()).spawn(f).map_err(GitError::Io)
}

/// The run's deadline: SIGTERM to the group once `timeout` passed, or once
/// `flag` is set (looked at every [`CANCEL_POLL`]), SIGKILL [`KILL_AFTER`]
/// later; the end of the run (it was reaped) ends the watchdog at once.
fn watchdog(shared: &Shared, reaped: &mpsc::Receiver<()>, timeout: Duration, flag: Option<&AtomicBool>) {
    let deadline = std::time::Instant::now() + timeout;
    let stop = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break &shared.timed_out;
        }
        let wait = if flag.is_some() { left.min(CANCEL_POLL) } else { left };
        if !matches!(reaped.recv_timeout(wait), Err(mpsc::RecvTimeoutError::Timeout)) {
            return;
        }
        if flag.is_some_and(|f| f.load(Ordering::SeqCst)) {
            break &shared.cancelled;
        }
    };
    stop.store(true, Ordering::SeqCst);
    if shared.signal(libc::SIGTERM) && matches!(reaped.recv_timeout(KILL_AFTER), Err(mpsc::RecvTimeoutError::Timeout)) {
        shared.signal(libc::SIGKILL);
    }
}

/// A run given up on its cancel flag ([`GitRun::cancel_on`]).
fn cancelled() -> GitError {
    GitError::Io(io::Error::new(io::ErrorKind::Interrupted, "the run was cancelled"))
}

/// stdout, at most [`OUTPUT_MAX`] bytes: past it the run is over-long and its
/// group killed (its leader is reaped only after this returns).
fn read_capped(out: ChildStdout, shared: &Shared) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let limit = u64::try_from(OUTPUT_MAX).unwrap_or(u64::MAX).saturating_add(1);
    out.take(limit).read_to_end(&mut buf)?;
    if buf.len() > OUTPUT_MAX {
        shared.too_large.store(true, Ordering::SeqCst);
        shared.signal(libc::SIGKILL);
        return Ok(Vec::new());
    }
    Ok(buf)
}

/// The last [`STDERR_KEEP`] bytes of stderr, read to its end.
fn read_tail(mut err: ChildStderr) -> Vec<u8> {
    let mut tail = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match err.read(&mut chunk) {
            Ok(0) => return tail,
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > STDERR_KEEP {
                    tail.drain(..tail.len() - STDERR_KEEP);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return tail,
        }
    }
}

/// The last [`STDERR_LINES`] non-empty lines of `tail`, each scrubbed, then
/// cut to [`STDERR_LINE_CHARS`] characters, joined by newlines.
fn stderr_lines(tail: &[u8]) -> String {
    let text = String::from_utf8_lossy(tail);
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let kept = &lines[lines.len().saturating_sub(STDERR_LINES)..];
    kept.iter().map(|l| scrub(l).chars().take(STDERR_LINE_CHARS).collect::<String>()).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::BufRead as _;
    use std::time::Instant;

    /// A Mac run in `dir` that reads neither the user's nor the system git
    /// config (a developer's signing or default-branch setting never changes
    /// a test) and commits as one author at one date.
    fn mac(dir: &Path) -> GitRun {
        GitRun::mac(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-10-12T10:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-10-12T10:00:00Z")
    }

    /// A fresh repository on `main` in a tempdir.
    fn repo() -> (tempfile::TempDir, GitRun) {
        let d = tempfile::tempdir().unwrap();
        let git = mac(d.path());
        git.output(["init", "-q", "-b", "main"]).unwrap();
        (d, git)
    }

    /// Write `name` and commit it as `msg`; the new commit's id.
    fn commit(dir: &Path, git: &GitRun, name: &str, msg: &str) -> String {
        std::fs::write(dir.join(name), format!("{name}\n")).unwrap();
        git.output(["add", name]).unwrap();
        git.output(["commit", "-q", "-m", msg]).unwrap();
        text(&git.output(["rev-parse", "HEAD"]).unwrap()).trim().to_string()
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// An executable `/bin/sh` script `name` in `dir`.
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Whether `pid` is gone within 5 s.
    fn gone(pid: libc::pid_t) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 only checks for existence.
            if unsafe { libc::kill(pid, 0) } == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            if Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn stdout_is_byte_exact_and_paths_are_printed_as_they_are() {
        let (d, git) = repo();
        let name = "файл.txt";
        let bytes = [0xff_u8, 0xfe, 0x00, b'\n', b'x'];
        std::fs::write(d.path().join(name), bytes).unwrap();
        // The repository asks for quoted paths; the override wins.
        git.output(["config", "core.quotePath", "true"]).unwrap();
        git.output(["add", "-A"]).unwrap();
        git.output(["commit", "-q", "-m", "one"]).unwrap();
        assert_eq!(git.output(["ls-files"]).unwrap(), format!("{name}\n").into_bytes(), "printed as it is, never quoted");
        assert_eq!(git.output(["cat-file", "blob", &format!("HEAD:{name}")]).unwrap(), bytes, "non-UTF-8 and NUL bytes, byte for byte");
    }

    #[test]
    fn the_overrides_beat_the_repositorys_config() {
        let (d, git) = repo();
        let hooks = d.path().join("hooks");
        std::fs::create_dir(&hooks).unwrap();
        let marker = d.path().join("hook-ran");
        script(&hooks, "pre-commit", &format!("touch '{}'\n", marker.display()));
        git.output(["config", "core.hooksPath", hooks.to_str().unwrap()]).unwrap();
        git.output(["config", "color.ui", "always"]).unwrap();
        commit(d.path(), &git, "a", "one");
        assert!(!marker.exists(), "core.hooksPath=/dev/null: the repository's hook never ran");
        let log = git.output(["log", "--oneline"]).unwrap();
        assert!(!log.contains(&0x1b), "color.ui=false: {}", text(&log));
        // The control: the same commit without the overrides runs the hook.
        std::fs::write(d.path().join("b"), "b\n").unwrap();
        git.output(["add", "b"]).unwrap();
        let plain = {
            let _fork = crate::test_locks::forking();
            Command::new(git.program().unwrap())
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "two"])
                .current_dir(d.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap()
        };
        assert!(plain.status.success() && marker.exists(), "without the overrides the hook runs: {}", text(&plain.stderr));
    }

    #[test]
    fn the_mac_strips_inherited_git_variables_and_keeps_its_own() {
        let d = tempfile::tempdir().unwrap();
        let run = GitRun::mac(d.path()).with_program(Path::new("/usr/bin/true")).env("GIT_INDEX_FILE", "/tmp/index.w");
        let inherited = ["GIT_DIR", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT", "HOME", "XGIT_DIR"].map(OsString::from);
        let cmd = run.command(["status"], inherited).unwrap();
        let envs: BTreeMap<String, Option<String>> = cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect();
        let want = BTreeMap::from([("GIT_CONFIG_COUNT".to_string(), None), ("GIT_DIR".to_string(), None), ("GIT_INDEX_FILE".to_string(), Some("/tmp/index.w".to_string()))]);
        assert_eq!(envs, want, "inherited GIT_* removed, the run's own set; HOME and XGIT_DIR untouched");
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let overrides: Vec<String> = OVERRIDES.iter().flat_map(|o| ["-c".to_string(), (*o).to_string()]).collect();
        assert_eq!(args[..overrides.len()], overrides[..], "the overrides come first");
        assert_eq!(args[overrides.len()..], ["status".to_string()]);
        // A real run: nothing of this process's GIT_* reaches it, the run's own does.
        let show = script(d.path(), "show", "env\n");
        let out = text(&GitRun::mac(d.path()).with_program(&show).env("GIT_INDEX_FILE", "/tmp/index.w").output(["status"]).unwrap());
        let git_vars: Vec<&str> = out.lines().filter(|l| l.starts_with("GIT_")).collect();
        assert_eq!(git_vars, ["GIT_INDEX_FILE=/tmp/index.w"], "{out}");
        assert!(out.lines().any(|l| l.starts_with("PATH=")), "the rest is inherited: {out}");
    }

    /// B3's review (D16): `without_credentials` removes every credential
    /// variable and the `ai-env as` marker from a Mac run; a plain run
    /// leaves them as inherited.
    #[test]
    fn a_run_without_credentials_drops_them_and_the_runner_marker() {
        let d = tempfile::tempdir().unwrap();
        let removed = |run: &GitRun| -> Vec<String> {
            let cmd = run.command(["rev-parse", "--git-dir"], Vec::<OsString>::new()).unwrap();
            let mut names: Vec<String> = cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect();
            names.sort_unstable();
            names
        };
        let plain = GitRun::mac(d.path()).with_program(Path::new("/usr/bin/true"));
        assert!(removed(&plain).is_empty());
        let mut want: Vec<String> = crate::age_cmd::CHILD_ENV_REMOVED.iter().chain(&[crate::commands::RUNNER_MARKER]).map(|n| (*n).to_string()).collect();
        want.sort_unstable();
        assert_eq!(removed(&plain.without_credentials()), want);
    }

    #[test]
    fn a_vm_run_starts_from_an_empty_environment() {
        let d = tempfile::tempdir().unwrap();
        let show = script(d.path(), "show", "printf '%s\\n' \"$@\"\necho --\nenv\n");
        let home = d.path().join("home");
        let out = text(&GitRun::vm(d.path(), &home).with_program(&show).output(["status", "-z"]).unwrap());
        let (args, env) = out.split_once("--\n").unwrap();
        let want: Vec<String> = OVERRIDES.iter().flat_map(|o| ["-c".to_string(), (*o).to_string()]).chain(["status".to_string(), "-z".to_string()]).collect();
        assert_eq!(args.lines().collect::<Vec<_>>(), want);
        // What the shell adds by itself aside.
        let mut vars: Vec<&str> = env.lines().filter(|l| !["PWD=", "OLDPWD=", "SHLVL=", "_="].iter().any(|p| l.starts_with(p))).collect();
        vars.sort_unstable();
        let home_var = format!("HOME={}", home.display());
        let path_var = format!("PATH={VM_PATH}");
        assert_eq!(vars, ["GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", home_var.as_str(), "LC_ALL=C", path_var.as_str()]);
        // The VM's git comes from VM_PATH (/usr/bin/git on the Mac too).
        let program = GitRun::vm(d.path(), &home).program().map(Path::to_path_buf).expect("a git in VM_PATH");
        assert!(VM_PATH.split(':').any(|dir| program.parent() == Some(Path::new(dir))), "{}", program.display());
    }

    #[test]
    fn git_is_found_in_absolute_path_entries_only() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        script(&bin, "git", "exit 0\n");
        let abs = bin.canonicalize().unwrap();
        assert_eq!(find_git(Some(abs.as_os_str())), Some(abs.join("git")));
        // The same directory through a relative entry (from this process's working directory), an empty and a `.`
        // entry: never.
        let cwd = std::env::current_dir().unwrap();
        let up = cwd.components().filter(|c| matches!(c, std::path::Component::Normal(_))).count();
        let rel = PathBuf::from("../".repeat(up)).join(abs.strip_prefix("/").unwrap());
        assert!(rel.join("git").is_file(), "the relative entry reaches the script: {}", rel.display());
        let path = std::env::join_paths([rel.as_path(), Path::new(""), Path::new(".")]).unwrap();
        assert_eq!(find_git(Some(&path)), None);
        assert_eq!(find_git(None), None);
        // An explicit program that does not exist is Missing, as no git at all is.
        let e = GitRun::mac(d.path()).with_program(&d.path().join("no-git")).output(["status"]).unwrap_err();
        assert!(matches!(e, GitError::Missing), "{e}");
    }

    #[test]
    fn a_missing_working_directory_is_no_missing_git() {
        let d = tempfile::tempdir().unwrap();
        let e = mac(&d.path().join("no-such-dir")).output(["status"]).unwrap_err();
        assert!(matches!(&e, GitError::Io(io) if io.kind() == io::ErrorKind::NotFound), "{e}");
        assert!(e.to_string().contains("no-such-dir"), "the directory is named: {e}");
    }

    #[test]
    fn succeeds_tells_exit_1_from_a_failure() {
        let (d, git) = repo();
        let a = commit(d.path(), &git, "a", "one");
        let b = commit(d.path(), &git, "b", "two");
        assert!(git.succeeds(["merge-base", "--is-ancestor", &a, &b]).unwrap());
        assert!(!git.succeeds(["merge-base", "--is-ancestor", &b, &a]).unwrap());
        let e = git.succeeds(["merge-base", "--is-ancestor", &a, "no-such-ref"]).unwrap_err();
        assert!(matches!(&e, GitError::Failed { code: Some(128), stderr } if !stderr.is_empty()), "{e}");
    }

    #[test]
    fn output_stdin_feeds_the_run() {
        let (d, git) = repo();
        std::fs::write(d.path().join("f"), b"hello\n").unwrap();
        let from_file = git.output(["hash-object", "f"]).unwrap();
        let from_stdin = git.output_stdin(["hash-object", "--stdin"], b"hello\n").unwrap();
        assert_eq!(from_stdin, from_file);
        assert_eq!(from_stdin.len(), 41, "an object id and a newline: {}", text(&from_stdin));
    }

    #[test]
    fn spawn_piped_streams_cat_file_batch() {
        let (_d, git) = repo();
        let id = text(&git.output_stdin(["hash-object", "-w", "--stdin"], b"payload\0bytes").unwrap()).trim().to_string();
        let mut child = git.spawn_piped(["cat-file", "--batch"]).unwrap();
        child.stdin().unwrap().write_all(format!("{id}\n").as_bytes()).unwrap();
        let mut out = io::BufReader::new(child.take_stdout().unwrap());
        let mut head = String::new();
        out.read_line(&mut head).unwrap();
        assert_eq!(head, format!("{id} blob 13\n"));
        let mut body = vec![0; 14];
        out.read_exact(&mut body).unwrap();
        assert_eq!(body, b"payload\0bytes\n");
        drop(out);
        child.finish().unwrap();
    }

    #[test]
    fn a_failure_keeps_the_last_three_lines_scrubbed() {
        let d = tempfile::tempdir().unwrap();
        // Token-shaped, built from parts at run time.
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "a".repeat(40));
        let noisy = script(d.path(), "noisy", "echo one >&2\necho two >&2\necho three >&2\necho \"token $TOK\" >&2\necho five >&2\nexit 3\n");
        let e = GitRun::mac(d.path()).with_program(&noisy).env("TOK", &token).output(["status"]).unwrap_err();
        let GitError::Failed { code, stderr } = &e else { panic!("not a failure: {e}") };
        assert_eq!(*code, Some(3));
        let masked = format!("token sk-ant-[redacted:len={}]", token.len());
        assert_eq!(stderr.lines().collect::<Vec<_>>(), ["three", masked.as_str(), "five"]);
        let shown = e.to_string();
        assert!(!shown.contains(&token) && !shown.contains('\n') && shown.starts_with("git exited 3: three | token"), "{shown}");
    }

    /// A timing test's deadline: room for a child started late on a loaded Mac.
    const DEADLINE: Duration = Duration::from_secs(1);

    /// A timing test's script: it exits at once under `AI_ENV_TEST_WARM=1`.
    fn timed_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = script(dir, name, &format!("[ -n \"$AI_ENV_TEST_WARM\" ] && exit 0\n{body}"));
        // macOS assesses a new executable at its first exec (200-440 ms measured on this Mac), which must not eat
        // the deadline: one run first.
        let _fork = crate::test_locks::forking();
        assert!(Command::new(&p).env("AI_ENV_TEST_WARM", "1").status().unwrap().success());
        p
    }

    #[test]
    fn the_timeout_ends_the_whole_group() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("bg.pid");
        let slow = timed_script(d.path(), "slow", "sleep 30 &\necho $! > \"$PIDFILE\"\nwait\n");
        let started = Instant::now();
        let e = GitRun::mac(d.path()).with_program(&slow).env("AI_ENV_TEST_WARM", "").env("PIDFILE", &pidfile).timeout(DEADLINE).output(["fetch"]).unwrap_err();
        let took = started.elapsed();
        assert!(matches!(e, GitError::Timeout { secs: 1 }), "{e}");
        assert!(took < DEADLINE + KILL_AFTER, "SIGTERM at the deadline ends it, no SIGKILL needed: {took:?}");
        let bg: libc::pid_t = std::fs::read_to_string(&pidfile).expect("the script ran before its deadline").trim().parse().unwrap();
        assert!(gone(bg), "the run's background sleep went with its group");
    }

    #[test]
    fn a_group_that_ignores_sigterm_is_killed() {
        let d = tempfile::tempdir().unwrap();
        let ready = d.path().join("ready");
        let stubborn = timed_script(d.path(), "stubborn", "trap '' TERM\necho ready > \"$READY\"\nsleep 30\n");
        let started = Instant::now();
        let e = GitRun::mac(d.path()).with_program(&stubborn).env("AI_ENV_TEST_WARM", "").env("READY", &ready).timeout(DEADLINE).output(["fetch"]).unwrap_err();
        let took = started.elapsed();
        assert!(matches!(e, GitError::Timeout { secs: 1 }), "{e}");
        assert!(ready.exists(), "the script ignored SIGTERM before its deadline");
        assert!(took >= DEADLINE + KILL_AFTER && took < DEADLINE + KILL_AFTER + Duration::from_secs(3), "SIGKILL KILL_AFTER after SIGTERM: {took:?}");
    }

    /// A run's cancel flag ends it as its timeout would, well before that
    /// timeout: its whole group goes (SIGTERM, here enough), the error is
    /// `Interrupted`; with the flag set, no run starts at all.
    #[test]
    fn a_cancelled_run_ends_its_group_and_a_cancelled_runner_starts_none() {
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("bg.pid");
        let slow = timed_script(d.path(), "slow", "sleep 30 &\necho $! > \"$PIDFILE\"\nwait\n");
        let flag = Arc::new(AtomicBool::new(false));
        let setter = {
            let (flag, pidfile) = (Arc::clone(&flag), pidfile.clone());
            std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(10);
                while !pidfile.exists() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(10));
                }
                flag.store(true, Ordering::SeqCst);
            })
        };
        let git = GitRun::mac(d.path()).with_program(&slow).env("AI_ENV_TEST_WARM", "").env("PIDFILE", &pidfile).timeout(Duration::from_secs(60)).cancel_on(Arc::clone(&flag));
        let started = Instant::now();
        let e = git.output(["fetch"]).unwrap_err();
        setter.join().unwrap();
        assert!(matches!(&e, GitError::Io(io) if io.kind() == io::ErrorKind::Interrupted), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10), "the cancel, not the 60 s timeout: {:?}", started.elapsed());
        let bg: libc::pid_t = std::fs::read_to_string(&pidfile).expect("the script ran before the cancel").trim().parse().unwrap();
        assert!(gone(bg), "the run's background sleep went with its group");
        std::fs::remove_file(&pidfile).unwrap();
        let e = git.output(["fetch"]).unwrap_err();
        assert!(matches!(&e, GitError::Io(io) if io.kind() == io::ErrorKind::Interrupted), "{e}");
        assert!(!pidfile.exists(), "a cancelled runner starts nothing");
    }

    #[test]
    fn stdout_past_the_cap_is_too_large() {
        let d = tempfile::tempdir().unwrap();
        let big = script(d.path(), "big", &format!("head -c {} /dev/zero\n", OUTPUT_MAX + 1));
        let e = GitRun::mac(d.path()).with_program(&big).output(["cat-file"]).unwrap_err();
        assert!(matches!(e, GitError::TooLarge), "{e}");
        let exact = script(d.path(), "exact", &format!("head -c {OUTPUT_MAX} /dev/zero\n"));
        assert_eq!(GitRun::mac(d.path()).with_program(&exact).output(["cat-file"]).unwrap().len(), OUTPUT_MAX, "the cap itself passes");
    }

    #[test]
    fn a_dropped_child_has_its_group_killed() {
        let d = tempfile::tempdir().unwrap();
        let sleeper = script(d.path(), "sleeper", "sleep 30\n");
        let child = GitRun::mac(d.path()).with_program(&sleeper).spawn_piped(["cat-file", "--batch"]).unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let started = Instant::now();
        drop(child);
        assert!(started.elapsed() < Duration::from_secs(2), "a drop kills, never waits");
        assert!(gone(pid));
    }

    #[test]
    fn errors_render_on_one_line() {
        assert_eq!(GitError::Timeout { secs: 30 }.to_string(), "git did not finish within 30 s (stopped)");
        assert_eq!(GitError::Failed { code: None, stderr: String::new() }.to_string(), "git was ended by a signal");
        assert_eq!(GitError::TooLarge.to_string(), "git printed more than 64 MiB");
        assert_eq!(CliError::from(GitError::Missing).exit_code(), 1);
    }
}
