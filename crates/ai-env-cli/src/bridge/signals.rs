//! The stop signals of the Mac side (SIGINT, SIGTERM, SIGHUP): one helper for
//! every command that listens for them — S6's `vm exec` pump, S7's unseals and
//! the credentialed commands around them.
//!
//! Two facts of tokio shape it. Its handler for a signal is installed with the
//! first listener and never removed, so from then on the signal's default
//! action (the end of the process) is gone; and a signal that comes while no
//! listener lives is lost, since a listener made later never sees it. So a
//! credentialed command listens from its start to its end: [`Stops::take`]
//! hands a phase the listeners an earlier phase kept ([`Stops::keep`]), with
//! any signal that came in between still in them. A phase that must end at
//! once on a stop runs under [`stoppable`]: `vm exec` from GetMicrovm through
//! the gate and the token's unseal (its own line: 130 or 143, nothing was
//! sent), `vm warm`, the smoke and a lab probe. The pump's [`handle`] takes
//! the listeners `vm exec` kept last: a signal the runtime handed over only
//! after that phase last looked waits in them, and the pump answers it as its
//! own "before the command started" stop.
//!
//! A signal ignored when ai-env started (`nohup`, a non-interactive shell's
//! background job) stays ignored, as ssh leaves it: the dispositions are read
//! once, before the first listener could replace them ([`note_dispositions`]),
//! and an ignored signal gets no listener anywhere.
use crate::errors::{CliError, Result};
use futures_util::FutureExt as _;
use std::sync::{Mutex, OnceLock, PoisonError};
use tokio::signal::unix::{Signal, SignalKind};

/// The signals that stop a command, in the order of [`IGNORED_AT_START`] and [`KEPT`].
const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Whether each of [`STOP_SIGNALS`] was ignored when ai-env started, read once.
static IGNORED_AT_START: OnceLock<[bool; 3]> = OnceLock::new();

/// The listeners a phase kept for the next one ([`Stops::keep`]), by [`STOP_SIGNALS`] index.
static KEPT: Mutex<[Option<Signal>; 3]> = Mutex::new([None, None, None]);

fn index(sig: libc::c_int) -> Option<usize> {
    STOP_SIGNALS.iter().position(|s| *s == sig)
}

fn kept() -> std::sync::MutexGuard<'static, [Option<Signal>; 3]> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read SIGINT's, SIGTERM's and SIGHUP's dispositions now, unless already
/// read: called first thing by the commands that listen, so `nohup`'s SIG_IGN
/// is seen before any listener of this process could replace it.
pub fn note_dispositions() {
    let _ = at_start();
}

fn at_start() -> &'static [bool; 3] {
    IGNORED_AT_START.get_or_init(|| STOP_SIGNALS.map(ignored_now))
}

/// Whether `sig` was ignored when ai-env started: SIGINT, SIGTERM and SIGHUP
/// as first read ([`note_dispositions`]), any other signal as it is now.
#[must_use]
pub fn ignored(sig: libc::c_int) -> bool {
    match index(sig) {
        Some(i) => at_start()[i],
        None => ignored_now(sig),
    }
}

/// Whether `sig`'s disposition is `SIG_IGN` right now.
fn ignored_now(sig: libc::c_int) -> bool {
    // SAFETY: a null new action makes sigaction(2) only read the current one
    // into `old`, a zeroed (valid) `struct sigaction`.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &raw mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// A listener for `sig`: the one a phase kept, with any signal that came since,
/// else a new one; none when `sig` was ignored when ai-env started (it then
/// stays ignored, as ssh leaves it).
pub fn handle(sig: libc::c_int, kind: SignalKind) -> Result<Option<Signal>> {
    if let Some(listener) = index(sig).and_then(|i| kept()[i].take()) {
        return Ok(Some(listener));
    }
    if ignored(sig) {
        tracing::info!("signal {sig} was ignored when ai-env started: it stays ignored");
        return Ok(None);
    }
    tokio::signal::unix::signal(kind).map(Some).map_err(|e| CliError::Msg(format!("cannot handle signals: {e}")))
}

/// One line on stderr, never a panic: a stop's own line, or an unseal's
/// countdown from its blocking thread, may come after SIGHUP, when the
/// terminal is gone and `eprintln!` would turn the ending into a crash.
pub(crate) fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// The next delivery of `s`; never while the signal stays ignored.
pub async fn delivered(s: &mut Option<Signal>) -> Option<()> {
    match s {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

/// A stop signal that came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Int,
    Term,
    Hup,
}

impl Stop {
    /// What a command it stopped exits with (S6): 130 after SIGINT, 143 after
    /// SIGTERM or SIGHUP (which stands as TERM, the signal it sends on).
    #[must_use]
    pub fn status(self) -> i32 {
        match self {
            Stop::Int => 128 + libc::SIGINT,
            Stop::Term | Stop::Hup => 128 + libc::SIGTERM,
        }
    }

    /// `interrupted` or `terminated`, for the `ai-env:` line that says so.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Stop::Int => "interrupted",
            Stop::Term | Stop::Hup => "terminated",
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Stop::Int => "SIGINT",
            Stop::Term => "SIGTERM",
            Stop::Hup => "SIGHUP",
        }
    }
}

/// One phase's listeners for the three stop signals (see the module doc).
pub struct Stops {
    int: Option<Signal>,
    term: Option<Signal>,
    hup: Option<Signal>,
}

impl Stops {
    /// The listeners an earlier phase kept, else new ones; none for a signal
    /// ignored when ai-env started.
    pub fn take() -> Result<Stops> {
        Ok(Stops { int: handle(libc::SIGINT, SignalKind::interrupt())?, term: handle(libc::SIGTERM, SignalKind::terminate())?, hup: handle(libc::SIGHUP, SignalKind::hangup())? })
    }

    /// The next stop signal (a pending one at once).
    pub async fn next(&mut self) -> Stop {
        tokio::select! {
            Some(()) = delivered(&mut self.int) => Stop::Int,
            Some(()) = delivered(&mut self.term) => Stop::Term,
            Some(()) = delivered(&mut self.hup) => Stop::Hup,
            else => std::future::pending().await,
        }
    }

    /// A stop signal that already came, without waiting for one. The runtime
    /// hands a signal to the listeners only when it looks for events, so it
    /// looks first (one yield): a signal that came while this thread was busy
    /// (a synchronous `age --version`, the fake API's file reads) counts too.
    pub async fn pending(&mut self) -> Option<Stop> {
        tokio::task::yield_now().await;
        self.next().now_or_never()
    }

    /// Hand the listeners on to the next phase ([`Stops::take`], the pump's
    /// [`handle`]): a signal that comes in between waits in them. A slot an
    /// inner phase filled meanwhile keeps its own, which listened all along too.
    pub fn keep(self) {
        let mut kept = kept();
        for (slot, listener) in kept.iter_mut().zip([self.int, self.term, self.hup]) {
            if slot.is_none() {
                *slot = listener;
            }
        }
    }
}

/// `phase`, unless a stop signal comes first: then `phase` is dropped (an
/// unseal it waited on closes its dialog as it goes) and the signal is the
/// answer. Biased toward the signal, which is looked for before each poll of
/// `phase`: one the runtime handed over while `phase` waited wins over its
/// result. One that came during `phase`'s last stretch without a wait is
/// handed over only after `phase` ended, and stays in the listeners.
pub async fn stoppable<T>(stops: &mut Stops, phase: impl std::future::Future<Output = T>) -> std::result::Result<T, Stop> {
    tokio::pin!(phase);
    tokio::select! {
        biased;
        stop = stops.next() => Err(stop),
        out = &mut phase => Ok(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The statuses and words the `ai-env:` lines and the exits use: SIGHUP
    /// stands as SIGTERM, as the pump has always treated it.
    #[test]
    fn a_stop_exits_130_or_143_and_hup_stands_as_term() {
        assert_eq!((Stop::Int.status(), Stop::Term.status(), Stop::Hup.status()), (130, 143, 143));
        assert_eq!((Stop::Int.word(), Stop::Term.word(), Stop::Hup.word()), ("interrupted", "terminated", "terminated"));
        assert_eq!(Stop::Hup.name(), "SIGHUP");
    }

    /// The dispositions are read once: what `ignored` says for the three is
    /// the first reading, whatever happens to the dispositions later (a
    /// listener replacing `SIG_IGN` must not make it look caught). Read-only:
    /// this test changes no disposition of the test process.
    #[test]
    fn the_dispositions_are_read_once_and_kept() {
        note_dispositions();
        let first = *at_start();
        note_dispositions();
        assert_eq!(*at_start(), first, "a second reading changes nothing");
        for (i, sig) in STOP_SIGNALS.iter().enumerate() {
            assert_eq!(ignored(*sig), first[i]);
        }
        assert_eq!(index(libc::SIGUSR1), None, "another signal is read as it is now");
    }

    /// `sig`'s handler as sigaction(2) reports it, read only.
    fn disposition(sig: libc::c_int) -> libc::sighandler_t {
        // SAFETY: a null new action makes sigaction(2) only read the current
        // one into `old`, a zeroed (valid) `struct sigaction`.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, std::ptr::null(), &raw mut old), 0);
            old.sa_sigaction
        }
    }

    /// The hand-off (M2): a signal the runtime took in while a phase's
    /// listeners were kept, and no phase listened, is in what the next phase
    /// takes, where a listener made afresh would never see it: `Stops::take`
    /// (an unseal's) finds it pending, and the pump's `handle` gets the kept
    /// listener with it. It runs in a child run of this test binary (F26):
    /// the first take installs tokio's handlers for SIGINT, SIGTERM and
    /// SIGHUP, which are never removed, and in the library's test process
    /// they would swallow every Ctrl-C or SIGTERM meant for `cargo test` from
    /// then on. This process's three dispositions are as they were after it.
    #[test]
    fn a_signal_between_phases_waits_in_the_kept_listeners() {
        const TEST: &str = "bridge::signals::tests::a_signal_between_phases_waits_in_the_kept_listeners";
        // The child's mark: its parent's pid, which no exported value matches.
        const PARENT: &str = "AI_ENV_TEST_SIGNALS_PARENT";
        if std::env::var(PARENT).ok() == Some(std::os::unix::process::parent_id().to_string()) {
            return hand_off_in_this_process();
        }
        let before = STOP_SIGNALS.map(disposition);
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([TEST, "--exact", "--test-threads=1"]).env(PARENT, std::process::id().to_string()).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let child = {
            // Held across the spawn, as every fork of these tests holds it (`test_locks`).
            let _fork = crate::test_locks::forking();
            cmd.spawn().unwrap()
        };
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // A filter that matches nothing passes too: the count says it ran.
        assert!(out.status.success() && stdout.contains("test result: ok. 1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(STOP_SIGNALS.map(disposition), before, "this test process keeps its stop signals' dispositions");
    }

    /// The child's half of the hand-off test. SIGHUP is raised in that
    /// process, whose tokio handler, installed by the first take, keeps it alive.
    fn hand_off_in_this_process() {
        use futures_util::FutureExt as _;
        note_dispositions();
        if ignored(libc::SIGHUP) {
            eprintln!("SIGHUP was ignored when these tests started: there is no listener to hand over");
            return;
        }
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let hangup = || async {
                // SAFETY: raise(3) on this process, whose SIGHUP tokio's handler catches (the first take installed it).
                assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
                // The runtime takes it in (a park) while no phase listens.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            };
            Stops::take().unwrap().keep();
            hangup().await;
            let mut stops = Stops::take().unwrap();
            assert_eq!(stops.pending().await, Some(Stop::Hup), "the next phase finds the hangup that came in between");
            assert_eq!(stops.pending().await, None, "once");
            stops.keep();
            hangup().await;
            let mut hup = handle(libc::SIGHUP, SignalKind::hangup()).unwrap();
            assert!(delivered(&mut hup).now_or_never().is_some(), "the pump's handle takes the kept listener, the hangup in it");
            drop(hup);
            // The slots this test filled, emptied for whatever runs next in this process.
            drop(Stops::take().unwrap());
        });
    }
}
