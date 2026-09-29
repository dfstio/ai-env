//! PID-1 duties in their own process.
//!
//! `ai-env shim` as PID 1 (or with the hidden `--supervise`) becomes a tiny
//! init: it marks itself a child subreaper (Linux), blocks its signals, spawns
//! the same binary as the worker (hidden `--init-pid <PID>`), and loops on
//! `sigwait`. SIGCHLD reaps every exited child with `waitpid(-1, WNOHANG)` —
//! orphans reparented to us and, finally, the worker, whose status ends init.
//! TERM/INT/HUP/QUIT/USR1/USR2 are forwarded to the worker; after a TERM, INT
//! or QUIT the worker gets SIGKILL if it is still alive 70 s later (above the
//! 60 s terminate-hook budget).
//!
//! Why two processes: a `waitpid(-1)` reaper inside the tokio worker would
//! steal the children tokio waits for (their `wait` then fails with ECHILD).
//! Init's `waitpid(-1)` only ever sees init's own children. Init builds no
//! runtime and starts no thread.
use crate::errors::{CliError, Result};
use nix::errno::Errno;
use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::ffi::OsString;

/// SIGKILL the worker this long after the first TERM/INT/QUIT.
pub const KILL_AFTER_S: u32 = 70;
const _: () = assert!(KILL_AFTER_S > 60, "the kill timer must outlast the 60 s terminate-hook budget");

/// Signals init takes with `sigwait` (blocked, so the kernel queues them even
/// for PID 1, which drops default-disposition signals).
const WAITED: [Signal; 8] = [
    Signal::SIGCHLD,
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
    Signal::SIGALRM,
];

/// Never runs: every waited signal stays blocked and is taken by
/// `sigwait`. It exists because XNU discards a default-ignored signal
/// (SIGCHLD) at generation time even while it is blocked; with a handler
/// installed it pends on every kernel.
extern "C" fn pend_only(_: libc::c_int) {}

/// Signals relayed to the worker.
#[must_use]
pub fn forwarded(sig: Signal) -> bool {
    matches!(sig, Signal::SIGTERM | Signal::SIGINT | Signal::SIGHUP | Signal::SIGQUIT | Signal::SIGUSR1 | Signal::SIGUSR2)
}

/// Signals that start the kill timer.
#[must_use]
pub fn arms_kill_timer(sig: Signal) -> bool {
    matches!(sig, Signal::SIGTERM | Signal::SIGINT | Signal::SIGQUIT)
}

/// The worker's argv: ours minus `--supervise`, plus `--init-pid <pid>`.
#[must_use]
pub fn worker_args(ours: impl IntoIterator<Item = OsString>, init_pid: u32) -> Vec<OsString> {
    let mut v: Vec<OsString> = ours.into_iter().filter(|a| a != "--supervise").collect();
    v.push("--init-pid".into());
    v.push(init_pid.to_string().into());
    v
}

/// The exit code init ends with for a worker status.
#[must_use]
pub fn exit_code_of(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Exited(_, code) => Some(code),
        WaitStatus::Signaled(_, sig, _) => Some(128 + sig as i32),
        _ => None,
    }
}

/// Unblock every signal on the calling thread: the worker inherits init's
/// blocked mask across fork/exec (std keeps the parent's mask at spawn), so
/// a signal forwarded while it started is pending here and is delivered the
/// moment this runs — the worker sets its dispositions first (`shim::run`).
/// Called before the runtime starts, so no thread or child keeps the mask
/// (a no-op when nothing is blocked).
pub fn unblock_all() {
    let _ = SigSet::all().thread_unblock();
}

/// Run as init until the worker exits; never returns on success (the
/// process exits with the worker's status). `kill_after_s` is
/// [`KILL_AFTER_S`] unless the hidden `--kill-after-s` (tests) says otherwise.
/// Every signal is acted on before it is logged: logging never fails, but
/// forwarding must not depend on it.
pub fn run(kill_after_s: u32) -> Result<()> {
    let me = nix::unistd::getpid();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(e) = nix::sys::prctl::set_child_subreaper(true) {
        errln!("ai-env: init: PR_SET_CHILD_SUBREAPER failed ({e}); orphans reparent past us");
    }
    let mut set = SigSet::empty();
    for s in WAITED {
        set.add(s);
    }
    set.thread_block().map_err(|e| CliError::Msg(format!("init: cannot block signals: {e}")))?;
    for s in WAITED {
        let flags = if s == Signal::SIGCHLD { SaFlags::SA_RESTART | SaFlags::SA_NOCLDSTOP } else { SaFlags::SA_RESTART };
        // SAFETY: the handler does nothing and is async-signal-safe; the
        // worker gets default dispositions back at exec.
        unsafe { sigaction(s, &SigAction::new(SigHandler::Handler(pend_only), flags, SigSet::empty())) }.map_err(|e| CliError::Msg(format!("init: cannot install the {s} disposition: {e}")))?;
    }
    let exe = std::env::current_exe().map_err(|e| CliError::Msg(format!("init: cannot locate our own binary: {e}")))?;
    let args = worker_args(std::env::args_os().skip(1), me.as_raw().unsigned_abs());
    let child = std::process::Command::new(&exe).args(&args).spawn().map_err(|e| CliError::Msg(format!("init: cannot start the worker: {e}")))?;
    let worker = Pid::from_raw(i32::try_from(child.id()).map_err(|_| CliError::Msg("init: worker pid out of range".into()))?);
    // Reaped below with waitpid(-1); std's Child is never waited on.
    drop(child);
    errln!("ai-env: init pid {me} supervising worker pid {worker}");
    let mut timer_armed = false;
    loop {
        let sig = match set.wait() {
            Ok(s) => s,
            Err(Errno::EINTR) => continue,
            Err(e) => {
                errln!("ai-env: init: sigwait failed ({e})");
                continue;
            }
        };
        match sig {
            Signal::SIGCHLD => loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                    Err(Errno::EINTR) => continue,
                    Err(e) => {
                        errln!("ai-env: init: waitpid failed ({e})");
                        break;
                    }
                    Ok(status) => {
                        if status.pid() == Some(worker) {
                            if let Some(code) = exit_code_of(status) {
                                errln!("ai-env: init: worker exited ({status:?}); exiting {code}");
                                std::process::exit(code);
                            }
                        } else if let Some(pid) = status.pid() {
                            if exit_code_of(status).is_some() {
                                errln!("ai-env: init: reaped orphan {pid} ({status:?})");
                            }
                        }
                    }
                }
            },
            Signal::SIGALRM => {
                let _ = kill(worker, Signal::SIGKILL);
                errln!("ai-env: init: worker still alive {kill_after_s} s after the stop signal; SIGKILL");
            }
            s if forwarded(s) => {
                let _ = kill(worker, s);
                if arms_kill_timer(s) && !timer_armed {
                    timer_armed = true;
                    nix::unistd::alarm::set(kill_after_s);
                }
                errln!("ai-env: init: forwarding {s} to the worker");
            }
            other => errln!("ai-env: init: ignoring {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_args_drop_supervise_and_add_the_init_pid() {
        let ours = ["shim", "--supervise", "--claude", "/c", "--app-port", "0"].map(OsString::from);
        assert_eq!(worker_args(ours, 42), ["shim", "--claude", "/c", "--app-port", "0", "--init-pid", "42"].map(OsString::from).to_vec());
    }

    #[test]
    fn exit_codes_follow_the_worker() {
        let p = Pid::from_raw(7);
        assert_eq!(exit_code_of(WaitStatus::Exited(p, 0)), Some(0));
        assert_eq!(exit_code_of(WaitStatus::Exited(p, 3)), Some(3));
        assert_eq!(exit_code_of(WaitStatus::Signaled(p, Signal::SIGKILL, false)), Some(137));
        assert_eq!(exit_code_of(WaitStatus::StillAlive), None);
    }

    #[test]
    fn signal_tables() {
        for s in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP, Signal::SIGQUIT, Signal::SIGUSR1, Signal::SIGUSR2] {
            assert!(forwarded(s), "{s}");
            assert!(WAITED.contains(&s));
        }
        assert!(!forwarded(Signal::SIGCHLD) && !forwarded(Signal::SIGALRM));
        for s in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGQUIT] {
            assert!(arms_kill_timer(s), "{s}");
        }
        for s in [Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGUSR2] {
            assert!(!arms_kill_timer(s), "{s}");
        }
    }
}
