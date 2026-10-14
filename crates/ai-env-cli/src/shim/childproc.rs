//! The child side of every process the shim starts as the agent (S8 §6): the
//! `pre_exec` path the spawn manager uses (`setsid`, `NO_NEW_PRIVS`, the
//! signal dispositions, the working directory entered as the agent, every
//! inherited fd close-on-exec), moved here from `spawn.rs` so the claude
//! spawns (`spawn`) and the workspace helper (`asagent`) share one.
//!
//! Everything a child runs between fork and exec is prepared before the
//! fork ([`cwd_parts`], [`fd_walk_end`]): [`child_setup`] only makes
//! async-signal-safe calls on that data and allocates nothing.
use std::ffi::CString;
use std::io;

/// Longest working directory (PATH_MAX).
pub(crate) const CWD_MAX_BYTES: usize = 4096;
/// `pre_exec` reports a working-directory failure as `CWD_ERRNO_BASE + errno`
/// (std passes only an errno from the child), so it is told from an exec failure.
pub(crate) const CWD_ERRNO_BASE: i32 = 1 << 20;
/// The child's fallback close-on-exec walk (no `close_range`) stops here.
const FD_WALK_MAX: u64 = 4096;
/// The highest signal number to reset (Linux: the realtime range included).
const LAST_SIGNAL: libc::c_int = if cfg!(target_os = "linux") { 64 } else { 31 };

/// The child between fork and exec, after std applied the stdio and the
/// uid/gid: only async-signal-safe calls on data prepared before the fork
/// (nothing is allocated). setsid; NO_NEW_PRIVS (Linux); the working
/// directory, each missing component made 0700 and entered AS THE AGENT;
/// every fd from 3 marked close-on-exec (what the shim opens already is:
/// this catches anything it inherited); the secret's pipe on fd 3.
pub(crate) fn child_setup(cwd: &[CString], secret_fd: Option<libc::c_int>, fd_walk: libc::c_int) -> io::Result<()> {
    // SAFETY: plain syscalls on integers and on NUL-terminated strings the closure owns.
    unsafe {
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        {
            let (one, zero): (libc::c_ulong, libc::c_ulong) = (1, 0);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        default_dispositions();
        enter_cwd(cwd)?;
        cloexec_from_3(fd_walk);
        if let Some(fd) = secret_fd {
            // dup2 gives fd 3 without close-on-exec; a pipe already on 3 just loses the flag.
            let rc = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Every signal the shim had ignored back to its default action: an ignored
/// disposition survives exec (std resets only SIGPIPE and the mask), and an
/// agent process must not start with SIGINT or SIGTERM ignored because of how
/// the shim itself was started.
///
/// # Safety
/// Async-signal-safe; call only in the forked child.
pub(crate) unsafe fn default_dispositions() {
    for sig in 1..=LAST_SIGNAL {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN {
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(sig, &dfl, std::ptr::null_mut());
        }
    }
}

/// `chdir("/")`, then into each component, made (0700) when missing: as the
/// agent, so nothing here can touch what the agent may not.
///
/// # Safety
/// Async-signal-safe; call only in the forked child.
pub(crate) unsafe fn enter_cwd(parts: &[CString]) -> io::Result<()> {
    let errno = || io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let fail = |e: i32| Err(io::Error::from_raw_os_error(CWD_ERRNO_BASE + e));
    if libc::chdir(c"/".as_ptr()) != 0 {
        return fail(errno());
    }
    for p in parts {
        if libc::chdir(p.as_ptr()) == 0 {
            continue;
        }
        let e = errno();
        if e != libc::ENOENT {
            return fail(e);
        }
        if libc::mkdir(p.as_ptr(), 0o700) != 0 && errno() != libc::EEXIST {
            return fail(errno());
        }
        if libc::chdir(p.as_ptr()) != 0 {
            return fail(errno());
        }
    }
    Ok(())
}

/// Mark every fd from 3 close-on-exec: `close_range` on Linux (one call), a
/// bounded `fcntl` walk elsewhere or when it fails.
///
/// # Safety
/// Async-signal-safe; call only in the forked child.
pub(crate) unsafe fn cloexec_from_3(walk_end: libc::c_int) {
    #[cfg(target_os = "linux")]
    {
        let (first, last): (libc::c_uint, libc::c_uint) = (3, libc::c_uint::MAX);
        if libc::syscall(libc::SYS_close_range, first, last, libc::CLOSE_RANGE_CLOEXEC) == 0 {
            return;
        }
    }
    for fd in 3..walk_end {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Where the child's fallback fd walk ends: the soft RLIMIT_NOFILE, at most [`FD_WALK_MAX`].
pub(crate) fn fd_walk_end() -> libc::c_int {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit fills the struct on the stack.
    let cur = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 { rl.rlim_cur } else { FD_WALK_MAX };
    libc::c_int::try_from(cur.min(FD_WALK_MAX)).unwrap_or(1024)
}

/// The CStrings of an absolute working directory's components, prepared
/// before the fork; `.`, `..`, a relative path or more than 4096 bytes are refused.
pub(crate) fn cwd_parts(path: &[u8]) -> Result<Vec<CString>, String> {
    if path.len() > CWD_MAX_BYTES {
        return Err(format!("{} bytes (at most {CWD_MAX_BYTES})", path.len()));
    }
    if path.first() != Some(&b'/') {
        return Err("must be absolute".into());
    }
    let parts: Vec<&[u8]> = path.split(|c| *c == b'/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == b"." || *p == b"..") {
        return Err("must not contain . or .. components".into());
    }
    parts.into_iter().map(|p| CString::new(p).map_err(|_| "holds a NUL byte".to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_rules() {
        assert_eq!(cwd_parts(b"/a//b/").unwrap(), [CString::new("a").unwrap(), CString::new("b").unwrap()]);
        assert!(cwd_parts(b"/").unwrap().is_empty());
        for bad in [&b"a/b"[..], b"", b"/a/./b", b"/a/../b", b"/..", b"/a\0b"] {
            assert!(cwd_parts(bad).is_err(), "{bad:?}");
        }
        assert!(cwd_parts(format!("/{}", "x".repeat(CWD_MAX_BYTES - 1)).as_bytes()).is_ok());
        assert!(cwd_parts(format!("/{}", "x".repeat(CWD_MAX_BYTES)).as_bytes()).is_err());
    }

    #[test]
    fn the_fd_walk_ends_at_the_soft_limit_or_the_cap() {
        let end = fd_walk_end();
        assert!(end > 3 && i64::from(end) <= i64::try_from(FD_WALK_MAX).unwrap(), "{end}");
    }
}
