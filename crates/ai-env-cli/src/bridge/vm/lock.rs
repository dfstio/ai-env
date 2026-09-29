//! Advisory locks for VM placement (plan S4 D14): `state/workspaces/<slug>.lock`
//! is held from SELECT_VM until the VM is RUNNING (one RunMicrovm per
//! workspace however many wrappers race), `state/vms.lock` only while the
//! `max_concurrent` count is taken and the pending row written (the limit
//! holds across workspaces). `flock(2)` on a file opened
//! `O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC` 0600 in a 0700 directory; the lock
//! dies with the descriptor, so a killed holder never leaves a stale lock.
//! The holder writes its pid into the file for the "waiting for pid N"
//! message; lock files are never deleted (deleting one while another process
//! waits on its descriptor would let a third process lock a new inode).
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::ensure_private_dir;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How often a contended lock is retried.
pub const POLL: Duration = Duration::from_millis(50);

/// After this long, a waiter says once on stderr whom it is waiting for.
pub const NOTICE_AFTER: Duration = Duration::from_secs(2);

/// An exclusive lock; released when dropped (the descriptor closes).
#[derive(Debug)]
pub struct FlockGuard {
    file: File,
    path: PathBuf,
}

impl FlockGuard {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: flock(2) on a descriptor this guard owns; closing it would release the lock anyway.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Open (creating 0600) the lock file, its directory made a real 0700 dir first.
fn open_lock_file(path: &Path) -> Result<File, BridgeError> {
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                BridgeError::Config(format!("{} is a symlink; refusing to lock through it", path.display()))
            } else {
                BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display())))
            }
        })
}

/// One non-blocking attempt: `Ok(true)` when locked.
fn try_flock(file: &File) -> Result<bool, BridgeError> {
    // SAFETY: flock(2) on a descriptor we own.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => Ok(false),
        _ => Err(BridgeError::Io(err)),
    }
}

/// The pid the current holder wrote, if any (best effort, for messages).
fn holder_pid(path: &Path) -> Option<u32> {
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).ok()?;
    let mut text = String::new();
    Read::by_ref(&mut f).take(32).read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

/// Record this process as the holder (the file is ours while locked).
fn stamp(file: &mut File) {
    let _ = file.set_len(0);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = writeln!(file, "{}", std::process::id());
}

/// Take `path` exclusively, polling every [`POLL`] with `tokio::time::sleep`
/// (the runtime is never blocked) for at most `budget`; `what` names the
/// lock in messages. After [`NOTICE_AFTER`] a waiter prints one line
/// `ai-env: waiting for <what> (held by pid N)`; past the budget the result
/// is `Busy` (exit 1) naming the holder.
pub async fn lock_exclusive(path: &Path, budget: Duration, what: &str) -> Result<FlockGuard, BridgeError> {
    let mut file = open_lock_file(path)?;
    let start = Instant::now();
    let mut noticed = false;
    loop {
        if try_flock(&file)? {
            stamp(&mut file);
            return Ok(FlockGuard { file, path: path.to_path_buf() });
        }
        let waited = start.elapsed();
        let holder = || holder_pid(path).map_or_else(|| "another ai-env".to_string(), |p| format!("pid {p}"));
        if waited >= budget {
            return Err(BridgeError::Busy(format!("{what} still held by {} after {} s ({})", holder(), budget.as_secs(), path.display())));
        }
        if !noticed && waited >= NOTICE_AFTER {
            noticed = true;
            eprintln!("ai-env: waiting for {what} (held by {})", holder());
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Blocking variant for synchronous code (the file-backed fake API): waits
/// without a budget; the lock is held for microseconds by its users.
pub fn lock_blocking(path: &Path) -> Result<FlockGuard, BridgeError> {
    let mut file = open_lock_file(path)?;
    loop {
        // SAFETY: flock(2) on a descriptor we own.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc == 0 {
            stamp(&mut file);
            return Ok(FlockGuard { file, path: path.to_path_buf() });
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(BridgeError::Io(err));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn contention_times_out_with_the_holder_named_then_frees() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("workspaces").join("-x.lock");
        let held = lock_exclusive(&path, Duration::from_secs(1), "workspace lock").await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        // A second open file description in the same process contends like another process would.
        let e = lock_exclusive(&path, Duration::from_millis(150), "workspace lock").await.unwrap_err();
        let text = e.to_string();
        assert!(text.contains(&format!("pid {}", std::process::id())), "{text}");
        let c: crate::errors::CliError = e.into();
        assert_eq!(c.exit_code(), 1);
        drop(held);
        let again = lock_exclusive(&path, Duration::from_millis(150), "workspace lock").await.unwrap();
        assert_eq!(again.path(), path.as_path());
    }

    #[tokio::test]
    async fn waits_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vms.lock");
        let held = lock_exclusive(&path, Duration::from_secs(1), "placement lock").await.unwrap();
        let p2 = path.clone();
        let waiter = tokio::spawn(async move { lock_exclusive(&p2, Duration::from_secs(5), "placement lock").await.map(|_| ()) });
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(held);
        waiter.await.unwrap().unwrap();
    }

    #[test]
    fn refuses_a_symlinked_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("vms.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = lock_blocking(&link).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
    }
}
