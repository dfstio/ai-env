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

fn find_in_path(name: &str, path: &str) -> Option<PathBuf> {
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
        let mut child = self
            .cmd()
            .arg("-d")
            .arg("-i")
            .arg(safe_path(identity)) // the ONLY -i, by construction
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CliError::Msg(format!("cannot spawn age: {e}")))?;
        // Threaded stdin write — see encrypt() for the deadlock rationale.
        let stdin = child.stdin.take().expect("piped stdin");
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

        // Drain stdout OURSELVES into a buffer pre-reserved to the ciphertext
        // size: decrypted output is always smaller, so the Vec NEVER
        // reallocates — `read_to_end`'s geometric growth would strew partial
        // plaintext copies across the heap (audit fix 6). The read chunk is
        // wiped after the loop.
        let plaintext = match child.stdout.take() {
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
        let status = child.wait()?;
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
        // error), the writer thread is still blocked in open(2). Open the
        // read end non-blocking ourselves to release it — otherwise join()
        // would hang the process.
        if !writer.is_finished() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo_path);
            }
        }
        let _ = writer.join();
        let _ = std::fs::remove_file(&fifo_path);
        drop(fifo_dir);
        result.map(Zeroizing::new)
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
