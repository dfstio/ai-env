//! Process hardening for the edit session.
//!
//! Applied before any plaintext exists:
//! * core dumps off (`RLIMIT_CORE = {0,0}` — the hard limit defaults to
//!   unlimited on macOS, so a same-UID attacker could otherwise raise it and
//!   force a dump);
//! * `ptrace(PT_DENY_ATTACH)` — belt-and-suspenders: macOS already denied a
//!   same-user lldb attach against the ad-hoc binary in testing, but this
//!   also covers Developer-Mode-enabled setups (root with SIP off wins
//!   regardless — documented, not defended);
//! * a real TTY on stdin AND stdout (the alternate screen needs one, and a
//!   redirected stdout could siphon revealed values);
//! * refusal under tmux/screen: their SERVER process holds the rendered grid,
//!   outlives ai-env, and is readable via `tmux capture-pane` — the one
//!   terminal copy we can actually refuse to create (`--insecure-terminal`
//!   overrides);
//! * a one-time note under iTerm2, whose SavedState session restoration
//!   persists screen content to disk (verified to exist on this machine).
use crate::bail;
use crate::errors::Result;
use std::io::IsTerminal;

pub fn preflight(insecure_terminal: bool) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("ai-env edit needs an interactive terminal (stdin and stdout must be TTYs)");
    }
    if !insecure_terminal
        && (std::env::var_os("TMUX").is_some() || std::env::var_os("STY").is_some())
    {
        bail!(
            "refusing to run inside tmux/screen: the multiplexer's server process keeps a \
             copy of everything drawn (readable via `tmux capture-pane`) and outlives this \
             editor. Run in a plain terminal, or override with --insecure-terminal"
        );
    }

    // SAFETY: plain libc calls with valid arguments; failures are tolerable
    // (we proceed with reduced hardening rather than refusing to edit).
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &lim);
        #[cfg(target_os = "macos")]
        {
            const PT_DENY_ATTACH: libc::c_int = 31;
            let _ = libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }

    if std::env::var("TERM_PROGRAM").as_deref() == Ok("iTerm.app") {
        eprintln!(
            "note: iTerm2's session restoration (SavedState) may persist screen contents \
             to disk; consider disabling it for windows where you reveal secrets"
        );
    }
    Ok(())
}
