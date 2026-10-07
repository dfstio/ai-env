//! Subprocess driver for the `age` / `age-keygen` binaries.
//!
//! Invariants:
//! * No shell — ever. `Command` with explicit args, `--` before positionals,
//!   paths starting with `-` are rewritten to `./-…`.
//! * Plaintext and ciphertext travel through PIPES; decrypt-to-stdout uses
//!   `Stdio::inherit` so plaintext never enters ai-env's address space.
//! * EXACTLY ONE `-i` per decrypt invocation (age stable-sorts native
//!   identities ahead of plugin identities — a software recovery identity
//!   passed alongside the SE identity would silently bypass Touch ID).
//! * stderr is classified ONLY for exit 5 (plugin missing) and best-effort
//!   exit 3 (cancel). Never 4 or 6 — those are decided before age is spawned.
use crate::errors::{CliError, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub struct AgeTool {
    age: PathBuf,
    age_keygen: PathBuf,
    pub version: (u32, u32, u32),
}

/// First regular file named `name` in the `:`-separated `path` (also used by
/// the bridge doctor to note a PATH-only `ai-env-claude`).
pub fn find_in_path(name: &str, path: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// PATH with Homebrew's bin appended if missing — age itself resolves
/// `age-plugin-se` from PATH, so the child must see it too.
pub fn effective_path() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    for brew in ["/opt/homebrew/bin", "/usr/local/bin"] {
        if !std::env::split_paths(&path).any(|p| p == Path::new(brew))
            && Path::new(brew).is_dir()
        {
            return format!("{path}:{brew}");
        }
    }
    path
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let v = s.trim().trim_start_matches('v');
    let mut it = v.split('.').map(|p| p.trim_end_matches(|c: char| !c.is_ascii_digit()));
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next().and_then(|p| p.parse().ok()).unwrap_or(0),
    ))
}

/// Rewrite a leading-dash path so it can never be parsed as a flag.
fn safe_path(p: &Path) -> PathBuf {
    if p.to_string_lossy().starts_with('-') {
        Path::new(".").join(p)
    } else {
        p.to_path_buf()
    }
}

impl AgeTool {
    pub fn probe() -> Result<Self> {
        let path = effective_path();
        let age = find_in_path("age", &path).ok_or_else(|| {
            CliError::AuthUnavailable(
                "the `age` binary is not installed — run: brew install age".into(),
            )
        })?;
        let age_keygen = find_in_path("age-keygen", &path).ok_or_else(|| {
            CliError::AuthUnavailable(
                "`age-keygen` is not installed — run: brew install age".into(),
            )
        })?;
        let out = Command::new(&age)
            .arg("--version")
            .output()
            .map_err(|e| CliError::Msg(format!("cannot run age: {e}")))?;
        let version_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let version = parse_version(&version_str)
            .ok_or_else(|| CliError::Msg(format!("cannot parse age version {version_str:?}")))?;
        if version < (1, 3, 0) {
            return Err(CliError::Msg(format!(
                "age {version_str} is too old — ai-env needs >= 1.3.0 for tagged recipients \
                 (brew upgrade age)"
            )));
        }
        Ok(Self { age, age_keygen, version })
    }

    /// An `AgeTool` aimed at explicit binaries, for tests that must not depend
    /// on `PATH` (no `probe()`, so no version check and no race with another
    /// test's environment). Only `bridge::unseal`'s tests use it, so it does
    /// not exist in the shim-only world, where it would be dead code.
    #[cfg(all(test, feature = "bridge"))]
    pub(crate) fn for_tests(age: PathBuf, age_keygen: PathBuf, version: (u32, u32, u32)) -> Self {
        Self { age, age_keygen, version }
    }

    #[must_use]
    pub fn plugin_se_available(&self) -> bool {
        find_in_path("age-plugin-se", &effective_path()).is_some()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.age);
        c.env("PATH", effective_path());
        c
    }

    /// Encrypt via `age -R recipients.txt` (native tag support — no plugin,
    /// no prompt). Returns the binary ciphertext.
    pub fn encrypt(&self, recipients_file: &Path, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut child = self
            .cmd()
            .arg("-e")
            .arg("-R")
            .arg(safe_path(recipients_file))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CliError::Msg(format!("cannot spawn age: {e}")))?;
        // Feed stdin from a thread while wait_with_output drains stdout —
        // a same-thread write_all would deadlock once either side outgrows
        // the 64 KiB pipe buffer.
        let stdin = child.stdin.take().expect("piped stdin");
        let payload = Zeroizing::new(plaintext.to_vec());
        let writer = std::thread::spawn(move || {
            let mut stdin = stdin;
            let _ = stdin.write_all(&payload);
        });
        let out = child.wait_with_output()?;
        let _ = writer.join();
        if !out.status.success() {
            return Err(classify_failure(&out.stderr, "encryption"));
        }
        Ok(out.stdout)
    }

    /// Encrypt via `age -R recipients.txt`, with the PLAINTEXT STREAMED by
    /// the caller directly into age's stdin — used by `edit`'s save path so
    /// at most one unsealed value exists at a time (never a whole-file
    /// plaintext buffer). stdout/stderr are drained on threads (the inverse
    /// of `encrypt`'s threaded-stdin pattern, same 64 KiB pipe-deadlock
    /// rationale). Returns the binary ciphertext.
    pub fn encrypt_streaming(
        &self,
        recipients_file: &Path,
        write_plaintext: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut child = self
            .cmd()
            .arg("-e")
            .arg("-R")
            .arg(safe_path(recipients_file))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CliError::Msg(format!("cannot spawn age: {e}")))?;

        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let out_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = stdout.read_to_end(&mut buf);
            buf
        });
        let err_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = stderr.read_to_end(&mut buf);
            buf
        });

        let mut stdin = child.stdin.take().expect("piped stdin");
        let write_result = write_plaintext(&mut stdin);
        drop(stdin); // EOF to age

        let ciphertext = out_thread.join().unwrap_or_default();
        let errtext = err_thread.join().unwrap_or_default();
        let status = child.wait()?;
        if let Err(e) = write_result {
            // The writer usually fails BECAUSE age died (broken pipe) — age's
            // own stderr is the actionable message, not "broken pipe"
            // (audit fix 21).
            if !errtext.is_empty() {
                return Err(classify_failure(&errtext, "encryption"));
            }
            return Err(e);
        }
        if !status.success() {
            return Err(classify_failure(&errtext, "encryption"));
        }
        Ok(ciphertext)
    }

    /// Decrypt with EXACTLY ONE identity file, capturing plaintext in memory
    /// (for `run`). Touch ID fires here for policy-protected SE identities.
    pub fn decrypt_to_bytes(
        &self,
        identity: &Path,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let out = self.run_decrypt(identity, ciphertext, Stdio::piped())?;
        Ok(Zeroizing::new(out))
    }

    /// [`Self::decrypt_to_bytes`] with the child in its OWN process group, so
    /// `kill` can end it and the Touch ID dialog it is waiting on (S7: an
    /// unseal has a deadline, and `ai-env` must be able to give up on one).
    /// The group takes `age-plugin-se` — the process that actually holds the
    /// dialog — down with age itself.
    ///
    /// The classic paths keep their behaviour: only this one detaches the child
    /// from the caller's group, which also means a terminal Ctrl-C no longer
    /// reaches age by itself, so every caller owns those signals for the length
    /// of the unseal and calls [`AgeKill::kill_group`] when it gives up.
    pub fn decrypt_to_bytes_killable(
        &self,
        identity: &Path,
        ciphertext: &[u8],
        kill: &AgeKill,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let out = self.run_decrypt_with(identity, ciphertext, Stdio::piped(), Some(kill))?;
        Ok(Zeroizing::new(out))
    }

    /// Decrypt with EXACTLY ONE identity file, plaintext flowing straight to
    /// our stdout (never through ai-env's memory) — for `show`.
    pub fn decrypt_to_stdout(&self, identity: &Path, ciphertext: &[u8]) -> Result<()> {
        self.run_decrypt(identity, ciphertext, Stdio::inherit())?;
        Ok(())
    }

    fn run_decrypt(
        &self,
        identity: &Path,
        ciphertext: &[u8],
        stdout: Stdio,
    ) -> Result<Vec<u8>> {
        self.run_decrypt_with(identity, ciphertext, stdout, None)
    }

    /// `run_decrypt`, optionally with the child in its own process group and
    /// registered with `kill` ([`Self::decrypt_to_bytes_killable`]).
    fn run_decrypt_with(
        &self,
        identity: &Path,
        ciphertext: &[u8],
        stdout: Stdio,
        kill: Option<&AgeKill>,
    ) -> Result<Vec<u8>> {
        let mut cmd = self.cmd();
        cmd.arg("-d")
            .arg("-i")
            .arg(safe_path(identity)) // the ONLY -i, by construction
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(Stdio::piped());
        #[cfg(unix)]
        if kill.is_some() {
            use std::os::unix::process::CommandExt as _;
            // Its own group, so one signal reaches age and the plugin holding the dialog.
            cmd.process_group(0);
        }
        // A job given up before its child exists spawns nothing (and so shows no dialog).
        if kill.is_some_and(AgeKill::cancelled) {
            return Err(CliError::Cancelled);
        }
        let mut child = cmd.spawn().map_err(|e| CliError::Msg(format!("cannot spawn age: {e}")))?;
        // Threaded stdin write — see encrypt() for the deadlock rationale.
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout_pipe = child.stdout.take();
        let payload = ciphertext.to_vec();
        let writer = std::thread::spawn(move || {
            let mut stdin = stdin;
            let _ = stdin.write_all(&payload);
        });
        let mut stderr = child.stderr.take().expect("piped stderr");
        let err_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = stderr.read_to_end(&mut buf);
            buf
        });
        // Hand the child over BEFORE draining stdout: that drain is where a Touch ID prompt is waited
        // on, so `kill` must be able to reach the child throughout it (S7).
        let holder = Holder::from(kill);
        holder.adopt(child);

        // Drain stdout OURSELVES into a buffer pre-reserved to the ciphertext
        // size: decrypted output is always smaller, so the Vec NEVER
        // reallocates — `read_to_end`'s geometric growth would strew partial
        // plaintext copies across the heap (audit fix 6). The read chunk is
        // wiped after the loop.
        let plaintext = match stdout_pipe {
            Some(mut out_pipe) => {
                use std::io::Read as _;
                let mut out = Vec::with_capacity(ciphertext.len().max(64));
                let mut chunk = [0u8; 8192];
                let read_result = loop {
                    match out_pipe.read(&mut chunk) {
                        Ok(0) => break Ok(()),
                        Ok(n) => {
                            if out.len() + n > out.capacity() {
                                break Err(CliError::Msg(
                                    "decrypted output larger than ciphertext — refusing".into(),
                                ));
                            }
                            out.extend_from_slice(&chunk[..n]);
                        }
                        Err(e) => break Err(e.into()),
                    }
                };
                // SAFETY: chunk is a live local buffer; volatile wipe.
                unsafe { memsec::memzero(chunk.as_mut_ptr(), chunk.len()) };
                read_result.map(|()| out)
            }
            None => Ok(Vec::new()), // stdout inherited (show): nothing to capture
        };

        let _ = writer.join();
        let errtext = err_thread.join().unwrap_or_default();
        let status = holder.wait()?;
        if !status.success() {
            if let Ok(mut leaked) = plaintext {
                use zeroize::Zeroize as _;
                leaked.zeroize();
            }
            return Err(classify_failure(&errtext, "decryption"));
        }
        plaintext
    }

    /// `age-keygen`: a fresh X25519 identity. Returns (secret identity line,
    /// public recipient). The secret only ever lives in a `Zeroizing` buffer.
    pub fn keygen_x25519(&self) -> Result<(Zeroizing<String>, String)> {
        let out = Command::new(&self.age_keygen)
            .env("PATH", effective_path())
            .output()
            .map_err(|e| CliError::Msg(format!("cannot run age-keygen: {e}")))?;
        if !out.status.success() {
            return Err(CliError::Msg(format!(
                "age-keygen failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
        // "Public key: age1…" on stderr; "# public key: age1…" in the file text.
        let recipient = String::from_utf8_lossy(&out.stderr)
            .lines()
            .chain(text.lines())
            .find_map(|l| l.split("ublic key:").nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("age1"))
            .ok_or_else(|| CliError::Msg("age-keygen output missing public key".into()))?;
        let secret = text
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .map(|l| Zeroizing::new(l.to_string()))
            .ok_or_else(|| CliError::Msg("age-keygen output missing secret key".into()))?;
        Ok((secret, recipient))
    }

    /// `age-keygen -y`: identity line -> recipient, fed through a PIPE (the
    /// identity never touches disk).
    pub fn identity_to_recipient(&self, identity_line: &str) -> Result<String> {
        let mut child = Command::new(&self.age_keygen)
            .env("PATH", effective_path())
            .arg("-y") // with no INPUT, age-keygen -y reads the identity from stdin
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CliError::Msg(format!("cannot run age-keygen -y: {e}")))?;
        {
            let mut stdin = child.stdin.take().expect("piped stdin");
            stdin.write_all(identity_line.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(CliError::Msg(
                "that does not look like a valid AGE-SECRET-KEY identity".into(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Decrypt with an identity provided as a STRING (recovery flow) without
    /// writing it to disk: the identity is streamed into age through an
    /// anonymous pipe exposed as /dev/fd/N.
    pub fn decrypt_with_identity_string(
        &self,
        identity_line: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (fifo_dir, fifo_path) = make_fifo()?;
        let identity = Zeroizing::new(format!("{identity_line}\n"));
        let writer = {
            let path = fifo_path.clone();
            std::thread::spawn(move || {
                // Opens block until age opens the read end.
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                    let _ = f.write_all(identity.as_bytes());
                }
            })
        };
        let result = self.run_decrypt(&fifo_path, ciphertext, Stdio::piped());
        // If age exited without ever opening the FIFO (bad ciphertext, early
        // error), the writer thread may still be blocked in open(2). Open the
        // read end non-blocking to release it, and HOLD the fd until the
        // writer is joined — closing it immediately would re-strand a writer
        // that only reaches open(2) after our close (join would then hang).
        #[cfg(unix)]
        let _unblock: Option<std::fs::File> = if writer.is_finished() {
            None
        } else {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo_path)
                .ok()
        };
        let _ = writer.join();
        let _ = std::fs::remove_file(&fifo_path);
        drop(fifo_dir);
        result.map(Zeroizing::new)
    }
}

/// The handle that ends one [`AgeTool::decrypt_to_bytes_killable`] early: the
/// decrypting child runs in its own process group, and [`Self::kill_group`]
/// signals that group, so `age` and the `age-plugin-se` process holding the
/// Touch ID dialog go together (S7).
///
/// The child is reaped and signalled under the same lock — `killpg` runs with
/// the lock held, and the waiter can only reap while holding it — so a pid the
/// kernel has already recycled can never be signalled. The waiter polls
/// `try_wait` (never blocking in `wait` with the lock held, which would deadlock
/// against a concurrent kill) and takes the child out as it reaps it.
///
/// A kill that arrives before there is a child is remembered (`cancelled`):
/// the decrypt then never spawns, or is killed the moment it is adopted, so no
/// dialog appears that nobody waits for.
#[derive(Debug, Default)]
pub struct AgeKill {
    state: std::sync::Mutex<Option<std::process::Child>>,
    cancelled: std::sync::atomic::AtomicBool,
}

/// How long [`AgeKill::kill_group`] gives the group to end on SIGTERM before
/// SIGKILL.
const KILL_AFTER_TERM: std::time::Duration = std::time::Duration::from_millis(500);
/// How often the waiter asks whether the child has exited.
const REAP_POLL: std::time::Duration = std::time::Duration::from_millis(20);

impl AgeKill {
    #[must_use]
    pub fn new() -> AgeKill {
        AgeKill::default()
    }

    /// Take `child` over, so [`Self::kill_group`] can reach it from any thread.
    /// Called before the caller starts waiting on the child's output, which is
    /// where a Touch ID prompt is waited on.
    fn adopt(&self, child: std::process::Child) {
        let mut slot = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(child);
        // A kill between the caller's `cancelled()` check and here: end the child now, nobody wants its answer.
        // Checked under the lock, after the child is in place, so a concurrent `kill_group` either sees the child
        // or has already set the flag this reads.
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            #[cfg(unix)]
            if let Some(c) = slot.as_ref() {
                // SAFETY: a plain libc call on our own unreaped child's group, under the lock.
                unsafe { libc::killpg(i32::try_from(c.id()).unwrap_or(0), libc::SIGKILL) };
            }
        }
    }

    /// Has [`Self::kill_group`] been called? The decrypt checks it before
    /// spawning, so a job given up before its child exists spawns nothing.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait for the adopted child and return its status. Polls rather than
    /// blocking, so the lock is free between tries and a concurrent
    /// [`Self::kill_group`] can never deadlock against it.
    fn wait(&self) -> Result<std::process::ExitStatus> {
        loop {
            {
                let mut slot = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(c) = slot.as_mut() else {
                    return Err(CliError::Msg("age: the decrypting child was taken away".into()));
                };
                if let Some(status) = c.try_wait()? {
                    // Reaped: drop the handle under the same lock, so no later kill can signal its pid.
                    *slot = None;
                    return Ok(status);
                }
            }
            std::thread::sleep(REAP_POLL);
        }
    }

    /// End the decrypt now: SIGTERM to the child's process group, then SIGKILL
    /// after [`KILL_AFTER_TERM`] if anything is still there. Doing nothing when
    /// the child has already been reaped. Safe to call more than once, and from
    /// any thread.
    pub fn kill_group(&self) {
        // First, so a child adopted after this point is killed by `adopt` itself.
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(unix)]
        {
            if !self.signal_group(libc::SIGTERM) {
                return;
            }
            std::thread::sleep(KILL_AFTER_TERM);
            self.signal_group(libc::SIGKILL);
        }
    }

    /// Send `sig` to the unreaped child's process group (its pid, as
    /// `process_group(0)` made it the leader) WITH THE LOCK HELD, so it cannot be
    /// reaped — and its pid recycled — between the lookup and the signal. Even a
    /// leader that has exited keeps the group id reserved while it is a zombie,
    /// so the plugin it leaves behind is still reached. `false` when there is no
    /// unreaped child.
    #[cfg(unix)]
    fn signal_group(&self, sig: i32) -> bool {
        let slot = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pgid) = slot.as_ref().map(|c| i32::try_from(c.id()).unwrap_or(0)).filter(|p| *p > 0) else {
            return false;
        };
        // SAFETY: a plain libc call on our own child's group, which cannot be reaped while we hold the lock.
        unsafe { libc::killpg(pgid, sig) };
        true
    }

    /// Is a decrypt running right now (for tests and the countdown)?
    #[must_use]
    pub fn running(&self) -> bool {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_some()
    }
}

/// Either the caller's [`AgeKill`] or a private one, so one code path serves
/// both the killable decrypt and the classic ones: the child always lives in a
/// holder, and only the killable form hands that holder out.
enum Holder<'a> {
    Shared(&'a AgeKill),
    Local(AgeKill),
}

impl Holder<'_> {
    fn get(&self) -> &AgeKill {
        match self {
            Holder::Shared(k) => k,
            Holder::Local(k) => k,
        }
    }

    fn adopt(&self, child: std::process::Child) {
        self.get().adopt(child);
    }

    fn wait(&self) -> Result<std::process::ExitStatus> {
        self.get().wait()
    }
}

impl<'a> From<Option<&'a AgeKill>> for Holder<'a> {
    fn from(kill: Option<&'a AgeKill>) -> Holder<'a> {
        match kill {
            Some(k) => Holder::Shared(k),
            None => Holder::Local(AgeKill::new()),
        }
    }
}

/// A FIFO in a fresh 0700 temp dir: the identity travels through a kernel
/// pipe buffer, never through disk blocks.
fn make_fifo() -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("ai-env-")
        .tempdir()
        .map_err(|e| CliError::Msg(format!("cannot create temp dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.path().join("identity.fifo");
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| CliError::Msg("bad temp path".into()))?;
    // SAFETY: plain libc call with a valid NUL-terminated path; no aliasing.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        return Err(CliError::Msg("cannot create FIFO for identity transfer".into()));
    }
    Ok((dir, path))
}

/// Map an age failure to an exit class. ONLY 5 (plugin missing) and
/// best-effort 3 (cancel) may come from stderr — see errors.rs.
fn classify_failure(stderr: &[u8], what: &str) -> CliError {
    let text = String::from_utf8_lossy(stderr);
    if text.contains("plugin not found") || text.contains("awesome#plugins") {
        return CliError::AuthUnavailable(
            "age-plugin-se is not installed — run: brew install age-plugin-se".into(),
        );
    }
    let lower = text.to_lowercase();
    if lower.contains("cancel") || text.contains("-128") {
        return CliError::Cancelled;
    }
    let detail: String = text
        .lines()
        .filter(|l| l.starts_with("age: error:"))
        .collect::<Vec<_>>()
        .join("; ");
    CliError::Msg(format!(
        "age {what} failed: {}",
        if detail.is_empty() { text.trim().to_string() } else { detail }
    ))
}
