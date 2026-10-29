//! The child side of every process the shim starts as the agent (S8 §6): the
//! `pre_exec` path the spawn manager uses (`setsid`, `NO_NEW_PRIVS`, the
//! signal dispositions, the working directory entered as the agent, every
//! inherited fd close-on-exec), moved here from `spawn.rs` so the claude
//! spawns (`spawn`) and the workspace helper (`asagent`) share one.
//!
//! Everything a child runs between fork and exec is prepared before the
//! fork ([`cwd_parts`], [`fd_walk_end`]): [`child_setup`] only makes
//! async-signal-safe calls on that data and allocates nothing.
//!
//! S9: curl, which moves the transcript store's bytes ([`spawn_curl`]),
//! starts through the same setup as `ai-env-net` (uid and gid 999), in `/`,
//! its configuration (the presigned URL in it) on fd 3 alone. S13: a relay
//! spawn's relay client ([`spawn_relay_client`]) the same way, its session
//! (the token in it) on fd 3 alone.
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

// ---- curl (S9) -----------------------------------------------------------------------------

/// curl's `PATH` (its environment is otherwise cleared).
const CURL_PATH: &str = "/usr/bin:/bin";
/// The argv after the program: no `.curlrc` (`-q`, first), the configuration from fd 3.
pub(crate) const CURL_ARGS: [&str; 3] = ["-q", "-K", "/dev/fd/3"];

/// A close-on-exec pipe already holding `bytes`, its write end closed: the
/// read end, for a child's fd 3. `bytes` fits the pipe's buffer (a curl
/// configuration is a few KiB), so the write never waits for a reader.
fn preloaded_pipe(bytes: &[u8]) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let mut fds: [libc::c_int; 2] = [-1, -1];
    #[cfg(target_os = "linux")]
    // SAFETY: `fds` is an array of two ints for pipe2 to fill.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: as above.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and belong to nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(target_os = "linux"))]
    for fd in [&read, &write] {
        // SAFETY: a valid fd we own.
        if unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(fd), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    io::Write::write_all(&mut std::fs::File::from(write), bytes)?;
    Ok(read)
}

/// curl for the transcript store's transfers (S9 §3.4): `program -q -K
/// /dev/fd/3`, as `ids` (uid, gid: `ai-env-net`) when given, its environment
/// `PATH` and `LC_ALL` alone, its stdin, stdout and stderr pipes to the root
/// shim, and its configuration (`config`: the presigned URL is in it) on
/// fd 3 from a pipe that already holds it whole: never an argv, an
/// environment or a file, and fd 3 is a descriptor the agent (uid 1000)
/// cannot open in another uid's process. With `ids` the pipe is theirs
/// (0600): curl opens `/dev/fd/3` anew, which checks the pipe's own inode,
/// and a pipe belongs to its maker, the root shim. Started through
/// [`child_setup`] in `/`: setsid, NO_NEW_PRIVS, the signal dispositions,
/// every other descriptor from 3 close-on-exec. Killed when dropped.
pub(crate) fn spawn_curl(program: &std::path::Path, ids: Option<(u32, u32)>, config: &[u8]) -> io::Result<tokio::process::Child> {
    use std::os::fd::AsRawFd as _;
    use std::process::Stdio;
    let pipe = preloaded_pipe(config)?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(CURL_ARGS).env_clear().env("PATH", CURL_PATH).env("LC_ALL", "C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    if let Some((uid, gid)) = ids {
        // SAFETY: fchown(2) on the pipe's read end, a valid fd this function owns.
        if unsafe { libc::fchown(pipe.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        cmd.gid(gid);
        cmd.uid(uid);
    }
    let (fd, fd_walk) = (pipe.as_raw_fd(), fd_walk_end());
    // SAFETY: the closure runs in the forked child, after std applied the
    // stdio and the uid/gid, before exec; it makes only async-signal-safe
    // calls on data prepared here (no allocation, no lock).
    unsafe {
        cmd.pre_exec(move || child_setup(&[], Some(fd), fd_walk));
    }
    let spawned = {
        #[cfg(test)]
        let _fork = crate::test_locks::forking();
        cmd.spawn()
    };
    // The parent's read end: the child has its own on fd 3.
    drop(pipe);
    spawned
}

/// The relay client's `PATH` (its environment is otherwise cleared).
const RELAY_CLIENT_PATH: &str = "/usr/bin:/bin";

/// S13: a spawn's relay client (`shim::relay`): `program <args>`, as `ids` (`ai-env-net`) when given, its
/// environment `PATH=/usr/bin:/bin` and `LC_ALL=C` alone, stdin and stdout `/dev/null`, stderr piped to the shim, and
/// `session` (the token is in it) on fd 3 from a pipe that already holds it whole and is theirs ([`preloaded_pipe`],
/// `fchown`): never an argv, an environment or a file. Started through [`child_setup`] in `/`: setsid,
/// NO_NEW_PRIVS, the signal dispositions, every other descriptor from 3 close-on-exec. Killed when dropped.
pub(crate) fn spawn_relay_client(program: &std::path::Path, args: &[String], ids: Option<(u32, u32)>, session: &[u8]) -> io::Result<tokio::process::Child> {
    use std::os::fd::AsRawFd as _;
    use std::process::Stdio;
    let pipe = preloaded_pipe(session)?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).env_clear().env("PATH", RELAY_CLIENT_PATH).env("LC_ALL", "C").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
    if let Some((uid, gid)) = ids {
        // SAFETY: fchown(2) on the pipe's read end, a valid fd this function owns.
        if unsafe { libc::fchown(pipe.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        cmd.gid(gid);
        cmd.uid(uid);
    }
    let (fd, fd_walk) = (pipe.as_raw_fd(), fd_walk_end());
    // SAFETY: the closure runs in the forked child, after std applied the
    // stdio and the uid/gid, before exec; it makes only async-signal-safe
    // calls on data prepared here (no allocation, no lock).
    unsafe {
        cmd.pre_exec(move || child_setup(&[], Some(fd), fd_walk));
    }
    let spawned = {
        #[cfg(test)]
        let _fork = crate::test_locks::forking();
        cmd.spawn()
    };
    // The parent's read end: the child has its own on fd 3.
    drop(pipe);
    spawned
}

#[cfg(test)]
mod tests {
    use super::*;

    /// curl's start (S9 §3.4), with a script for the program: its argv is
    /// exactly `-q -K /dev/fd/3`, fd 3 holds the configuration and is its
    /// only descriptor past stderr, its environment is `PATH` and `LC_ALL`,
    /// its working directory `/`, its session its own; stdin and stdout are
    /// the caller's pipes.
    #[tokio::test]
    async fn curl_starts_with_its_config_on_fd_3_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("curl");
        let body = "fds=''\nfor n in $(seq 3 63); do [ -e /dev/fd/$n ] && fds=\"$fds$n,\"; done\nvars=$(env | cut -d= -f1 | grep -v -e '^PWD$' -e '^SHLVL$' -e '^_$' -e '^OLDPWD$' | sort | tr '\\n' ,)\nsid=$(ps -o sess= -p $$ 2>/dev/null | tr -d ' ')\nprintf 'argv=%s|fds=%s|vars=%s|cwd=%s|leader=%s\\n' \"$*\" \"$fds\" \"$vars\" \"$(pwd)\" \"$([ \"$sid\" = $$ ] && echo yes || echo no)\"\ncat <&3\ncat\n";
        std::fs::write(&script, format!("#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n{body}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warmed = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(&script).arg("warm").status().unwrap()
        };
        assert!(warmed.success());
        let config = "url = \"https://example.invalid/k\"\nsilent\n";
        let mut child = spawn_curl(&script, None, config.as_bytes()).unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"from stdin\n").await.unwrap();
        drop(stdin);
        let mut out = String::new();
        child.stdout.take().unwrap().read_to_string(&mut out).await.unwrap();
        assert!(child.wait().await.unwrap().success());
        let mut lines = out.lines();
        let facts = lines.next().unwrap();
        assert!(facts.starts_with("argv=-q -K /dev/fd/3|fds=3,|vars=LC_ALL,PATH,|cwd=/|"), "{facts}");
        if cfg!(target_os = "linux") || facts.ends_with("leader=yes") {
            assert!(facts.ends_with("leader=yes"), "its own session: {facts}");
        }
        assert_eq!(lines.collect::<Vec<_>>(), ["url = \"https://example.invalid/k\"", "silent", "from stdin"], "fd 3's configuration, then stdin");
    }

    /// S13: the relay client's start, as curl's above, with a script for the
    /// program (writing its facts to stderr, the one pipe it has): its argv
    /// is the given one, its descriptors past 2 are exactly `3`, its
    /// environment `LC_ALL` and `PATH` (`/usr/bin:/bin`), its working
    /// directory `/`, its own session, fd 3's bytes the session; stdout is
    /// `/dev/null` (`child.stdout` is `None`).
    #[tokio::test]
    async fn the_relay_client_starts_with_its_session_on_fd_3_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::AsyncReadExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("ai-env-relay-client");
        let body = "fds=''\nfor n in $(seq 3 63); do [ -e /dev/fd/$n ] && fds=\"$fds$n,\"; done\nvars=$(env | cut -d= -f1 | grep -v -e '^PWD$' -e '^SHLVL$' -e '^_$' -e '^OLDPWD$' | sort | tr '\\n' ,)\nsid=$(ps -o sess= -p $$ 2>/dev/null | tr -d ' ')\nprintf 'argv=%s|fds=%s|vars=%s|path=%s|cwd=%s|leader=%s\\n' \"$*\" \"$fds\" \"$vars\" \"$PATH\" \"$(pwd)\" \"$([ \"$sid\" = $$ ] && echo yes || echo no)\" >&2\ncat <&3 >&2\n";
        std::fs::write(&script, format!("#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n{body}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warmed = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(&script).arg("warm").status().unwrap()
        };
        assert!(warmed.success());
        // A run-time token (no committed value under `token`, §V-vm's conventions).
        let session = format!(r#"{{"v":1,"token":"relay-test-{:08x}","addr":"10.42.0.20:7443","server_name":"10.42.0.20","ca_der_b64":"MA=="}}"#, std::process::id());
        let session = session.as_bytes();
        let args: Vec<String> = ["serve", "--leader", "42", "--socket", "/run/ai-env/relay/42.sock", "--agent-uid", "1000"].map(str::to_string).to_vec();
        let mut child = spawn_relay_client(&script, &args, None, session).unwrap();
        assert!(child.stdout.is_none() && child.stdin.is_none(), "stdin and stdout are /dev/null");
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).await.unwrap();
        assert!(child.wait().await.unwrap().success());
        let (facts, fd3) = err.split_once('\n').unwrap();
        assert!(facts.starts_with("argv=serve --leader 42 --socket /run/ai-env/relay/42.sock --agent-uid 1000|fds=3,|vars=LC_ALL,PATH,|path=/usr/bin:/bin|cwd=/|"), "{facts}");
        if cfg!(target_os = "linux") || facts.ends_with("leader=yes") {
            assert!(facts.ends_with("leader=yes"), "its own session: {facts}");
        }
        assert_eq!(fd3.as_bytes(), session, "fd 3 holds the session, byte for byte");
    }

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
