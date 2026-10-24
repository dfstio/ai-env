//! S11 (A.1, A2): a version's admission: the release manifest's signature
//! (`release`), the Linux binary's size and sha256 against it, its markers
//! (`wire::claude::V_MARKERS`), then the claude-facing Docker tests on it
//! (`make claude-admit-docker`), each step recorded (`state/claude/<v>.toml`,
//! through `Record::update` only). A missing precondition (Docker, cargo,
//! this checkout, the local image), a failed fetch or a missing gpgv record
//! nothing and may pass again; a refused signature, bytes that are not the
//! signed manifest's or a missing marker are refusals (exit 9) that stay
//! until `--redo`. `--auto` is the wrapper's detached child (D5): quiet, its
//! lock adopted from fd 3, its outcome written into the lock, never a
//! non-zero exit. A failed Docker run (`failed(docker)`, exit 1) is counted
//! in the record with the make log's excerpt (`docker_excerpt`); `--auto`
//! runs such a record again, every step checked again as `--redo` would,
//! while fewer than `ADMIT_DOCKER_TRIES` Docker failures are recorded and
//! its cooldown is over (Mike's rule, 24 Oct: one Docker failure under load
//! no longer leaves a version unadmitted).
use super::release::{self, LabProgram, ReleaseError};
use super::{AdmissionRow, DownloadRow, Phase, Record, SignatureRow, ADMIT_DOCKER_TRIES, ADMIT_MAKE_BOUND, CLAUDE_GC_KEEP_LOCAL};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::errors::BridgeError;
use crate::bridge::lab::VmKnobs;
use crate::errors::CliError;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The local image the admission's Docker tests run on (the Makefile's `LOCAL_IMAGE`).
pub const LOCAL_IMAGE: &str = "ai-env-agent:local";
/// How long `docker version` and `docker image inspect` may take.
const DOCKER_BOUND: Duration = Duration::from_secs(10);
/// The longest Docker line a record keeps.
const DOCKER_LINE_MAX: usize = 300;
/// The most lines a Docker failure's excerpt keeps ([`docker_excerpt`]).
const DOCKER_EXCERPT_LINES: usize = 12;
/// The most bytes it keeps, a newline counted after each line.
const DOCKER_EXCERPT_BYTES: usize = 4096;
/// The log's last non-empty lines it keeps when no line names a failing test or a panic.
const DOCKER_EXCERPT_TAIL: usize = 5;
/// The longest test name a record keeps as `docker_test` (an id: the audit's `test`, the views' `test NAME failed`;
/// this checkout's Docker tests are named in under 100 characters). A longer one is the log's text, not an id: no name
/// is kept, its line stays in the excerpt, cut there (and an audit row past `MAX_AUDIT_ROW_BYTES` would not be written
/// at all).
const DOCKER_TEST_MAX: usize = 200;
/// How long the binary's download may take (§3.2).
const DOWNLOAD_MAX_TIME_S: u32 = 900;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmitOpts {
    /// Admit again a version already admitted or failed.
    pub redo: bool,
    /// The wrapper's detached child (D5): quiet, its lock on fd 3, never a non-zero exit.
    pub auto: bool,
}

// ---- the per-version lock ----------------------------------------------------------------------------------------

/// `state/claude/<v>.lock` held (a non-blocking `flock`): every command that admits, stages or forgets V holds it
/// (single flight per version). Its `--auto` holder rewrites it with `finished_at=` and `outcome=` at its end, the
/// cooldown D5's trigger reads (LD-11). Dropped, its descriptor is closed and never unlocked: a flock belongs to the
/// open file and goes with its last descriptor, so a detached child holding the same open file on fd 3 keeps it.
#[derive(Debug)]
pub struct VersionLock {
    file: std::fs::File,
    /// `--auto`'s step while its end is unwritten: [`Drop`] writes `error(<step>)` then, so every way out of an
    /// automatic admission (an early `?`, a panic) leaves D5's cooldown a `finished_at=`.
    auto_step: Option<&'static str>,
}

impl VersionLock {
    /// The lock taken without waiting: `Ok(None)` while another process holds it.
    pub fn take(paths: &Paths, version: &str) -> Result<Option<VersionLock>, BridgeError> {
        use std::os::unix::fs::OpenOptionsExt as _;
        crate::bridge::registry::ensure_private_dir(&paths.claude_dir())?;
        let path = paths.claude_lock(version);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))))?;
        // SAFETY: flock(2) on a descriptor this function owns.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(VersionLock { file, auto_step: None }));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => Ok(None),
            _ => Err(BridgeError::Io(err)),
        }
    }

    /// The lock, or exit 1 naming what holds it.
    pub fn take_or_busy(paths: &Paths, version: &str) -> Result<VersionLock, BridgeError> {
        VersionLock::take(paths, version)?.ok_or_else(|| BridgeError::Busy(held_text(version)))
    }

    /// fd 3, when it is `state/claude/<v>.lock` (the same file: device and inode), as D5's trigger hands it over
    /// with the lock already taken on it; made close-on-exec first, so no child of the admission inherits it.
    fn adopt(paths: &Paths, version: &str) -> Option<VersionLock> {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: an all-zero `struct stat` is a valid value of it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat(2) on fd 3 into `st`; it only reads the descriptor, which nothing owns yet.
        if unsafe { libc::fstat(3, &raw mut st) } != 0 {
            return None;
        }
        // Whatever fd 3 is, no child of the admission (curl, gpgv, make) gets it: the trigger's dup2 cleared the
        // flag for this exec only.
        // SAFETY: fcntl(2) F_SETFD on the open descriptor 3; the flag is the descriptor's, the lock the open file's.
        unsafe {
            libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let lock = std::fs::symlink_metadata(paths.claude_lock(version)).ok().filter(std::fs::Metadata::is_file)?;
        if u64::try_from(st.st_dev).ok()? != lock.dev() || st.st_ino != lock.ino() {
            return None;
        }
        // SAFETY: fd 3 is open (fstat above) and is this version's lock file; this process owns it from here on.
        let file = unsafe { std::fs::File::from_raw_fd(3) };
        // Taken again on the same open file (a no-op when the trigger's flock is still on it): held either way.
        // SAFETY: flock(2) on the descriptor just adopted.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        (rc == 0).then_some(VersionLock { file, auto_step: None })
    }

    /// This process's descriptor closed: D5's trigger (A3) calls it once its detached child holds the lock's open
    /// file on fd 3. The same as a drop, which only closes (never `LOCK_UN`): the child keeps the lock until its end.
    pub fn hand_over(self) {
        drop(self);
    }

    /// `finished_at=<unix>` and `outcome=<word>`, written from the file's first byte (the trigger read it through
    /// this open file: its offset may be past the end).
    pub fn finish(&mut self, outcome: &str) {
        self.auto_step = None;
        let _ = self.file.set_len(0);
        let _ = self.file.seek(std::io::SeekFrom::Start(0));
        let _ = write!(self.file, "finished_at={}\noutcome={outcome}\n", crate::wire::time::unix_now());
        let _ = self.file.sync_data();
    }
}

/// The lock's open file, for D5's trigger (A3), which hands it to `ai-env claude admit <v> --auto` on fd 3 (the
/// child adopts it: `VersionLock::adopt`).
impl std::os::fd::AsRawFd for VersionLock {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file.as_raw_fd()
    }
}

/// An `--auto` end not written yet is written as `error(<step>)`; then the file is closed, never unlocked (`LOCK_UN`
/// would unlock the open file for each of its descriptors, a handed-over child's fd 3 included).
impl Drop for VersionLock {
    fn drop(&mut self) {
        if let Some(step) = self.auto_step {
            self.finish(&format!("error({step})"));
        }
    }
}

/// What a held lock says (exit 1).
#[must_use]
pub fn held_text(version: &str) -> String {
    format!("another admission or staging of claude {version} is running: wait for it (ai-env claude status)")
}

// ---- the preconditions ---------------------------------------------------------------------------------------------

/// The checkout admission runs in: the compile-time `CARGO_MANIFEST_DIR/../..`, when it holds `Makefile` and
/// `image/Dockerfile`.
#[must_use]
pub fn repo() -> Option<PathBuf> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    (repo.join("Makefile").is_file() && repo.join("image").join("Dockerfile").is_file()).then_some(repo)
}

/// make: the lab knob's program, else `/usr/bin/make`.
#[must_use]
pub fn admit_make(knobs: &VmKnobs) -> PathBuf {
    knobs.admit_make().ok().flatten().unwrap_or_else(|| PathBuf::from("/usr/bin/make"))
}

/// `program` on the process's PATH (an executable regular file), as `make claude-admit-docker` will find it.
fn on_path(program: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).filter(|d| d.is_absolute()).map(|d| d.join(program)).find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// `docker <args>` from the process's PATH within [`DOCKER_BOUND`]: its trimmed stdout on exit 0.
fn docker(args: &[&str]) -> Option<String> {
    let docker = on_path("docker")?;
    let mut cmd = Command::new(docker);
    cmd.args(args);
    let got = crate::bridge::doctor::capture(cmd, None, DOCKER_BOUND).ok()?;
    got.success.then(|| got.stdout.trim().to_string())
}

/// The local image's id (`docker image inspect -f {{.Id}}`), when Docker names one.
fn local_image_id() -> Option<String> {
    docker(&["image", "inspect", "-f", "{{.Id}}", LOCAL_IMAGE]).filter(|id| !id.is_empty() && !id.contains(char::is_whitespace))
}

/// Step 3's preconditions, before anything is fetched or recorded: Docker answers, cargo resolves (both on the
/// process's PATH), this checkout, the local image (its id, which the Docker tests' end must still name).
/// `Err((word, text))`: `no_docker`, `no_cargo`, `no_checkout`, `no_image`, and the line naming it.
fn preconditions() -> Result<(PathBuf, String), (&'static str, String)> {
    if docker(&["version", "--format", "{{.Server.Version}}"]).is_none_or(|v| v.is_empty()) {
        return Err(("no_docker", "Docker does not answer (docker version, on this process's PATH): start Docker".into()));
    }
    if on_path("cargo").is_none() {
        return Err(("no_cargo", "no cargo on PATH (make claude-admit-docker builds the Docker tests with it)".into()));
    }
    let Some(repo) = repo() else {
        let at = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        return Err(("no_checkout", format!("no checkout at {} (the ai-env tree this binary was built from runs the Docker tests)", at.display())));
    };
    let Some(image) = local_image_id() else {
        return Err(("no_image", format!("{LOCAL_IMAGE} is missing: make image-build-local")));
    };
    Ok((repo, image))
}

// ---- the binary ----------------------------------------------------------------------------------------------------

/// `path`'s size and sha256 (streamed), or `None` when it cannot be read.
fn size_and_sha256(path: &Path) -> Option<(u64, String)> {
    use sha2::Digest as _;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        let got = f.read(&mut buf).ok()?;
        if got == 0 {
            break;
        }
        h.update(&buf[..got]);
        n += got as u64;
    }
    Some((n, hex::encode(h.finalize())))
}

/// The first `V_MARKERS` marker none of whose forms `path`'s bytes hold (std only, one streamed pass), or `None`
/// when every marker is there. An unreadable file names the first marker.
#[must_use]
pub fn missing_marker(path: &Path) -> Option<&'static str> {
    scan_markers(path).unwrap_or_else(|_| crate::wire::claude::V_MARKERS.first().map(|m| m.name))
}

/// [`missing_marker`], with a file that cannot be opened or read an `Err` (the admission's: no answer, never a
/// refusal).
fn scan_markers(path: &Path) -> std::io::Result<Option<&'static str>> {
    let markers = crate::wire::claude::V_MARKERS;
    let forms: Vec<(usize, &[u8])> = markers.iter().enumerate().flat_map(|(i, m)| m.forms.iter().map(move |f| (i, f.as_bytes()))).filter(|(_, f)| !f.is_empty()).collect();
    let longest = forms.iter().map(|(_, f)| f.len()).max().unwrap_or(1);
    // The forms by their first byte: one table look per byte of the file.
    let mut by_first: Vec<Vec<usize>> = vec![Vec::new(); 256];
    for (at, (_, f)) in forms.iter().enumerate() {
        by_first[usize::from(f[0])].push(at);
    }
    let mut found = vec![false; markers.len()];
    let mut file = std::fs::File::open(path)?;
    const CHUNK: usize = 16 << 20;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + longest);
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let got = file.read(&mut chunk)?;
        let end = got == 0;
        buf.extend_from_slice(&chunk[..got]);
        // Every start that a whole form can still fit after (all of them at the end).
        let limit = if end { buf.len() } else { buf.len().saturating_sub(longest - 1) };
        for i in 0..limit {
            for &at in &by_first[usize::from(buf[i])] {
                let (marker, form) = forms[at];
                if !found[marker] && buf[i..].starts_with(form) {
                    found[marker] = true;
                }
            }
        }
        if found.iter().all(|f| *f) {
            return Ok(None);
        }
        if end {
            break;
        }
        buf.drain(..limit);
    }
    Ok(markers.iter().zip(&found).find(|(_, f)| !**f).map(|(m, _)| m.name))
}

// ---- the Docker tests ----------------------------------------------------------------------------------------------

/// What make reads from its environment besides the recipe's own values: its flags (`-n`, `-t`, `-q` would end
/// `claude-admit-docker` without the tests, `-i` past a failed one, `-e` let the environment override the Makefile),
/// extra makefiles and its nesting, and the Makefile's `?=` variables the recipe uses: `LOCAL_IMAGE` (the image its
/// tests run on, whose id the record names: [`LOCAL_IMAGE`]) and `TOOLCHAIN` (its cargo). None of them reaches make.
pub const MAKE_ENV_DROPPED: [&str; 8] = ["MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEOVERRIDES", "MAKELEVEL", "MAKEFILES", "LOCAL_IMAGE", "TOOLCHAIN"];

/// The environment make runs in (LD-12): the process's, minus every credential ai-env knows
/// (`age_cmd::CHILD_ENV_REMOVED`), every name holding a credential word (`agent::exec::CREDENTIAL_WORDS`), every
/// lab knob (`AI_ENV_BRIDGE_LAB_*`), the runner's marker `AI_ENV_BRIDGE_AS` and [`MAKE_ENV_DROPPED`].
#[must_use]
pub fn make_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    make_env_of(std::env::vars_os())
}

/// [`make_env`] of `vars` (pure).
fn make_env_of(vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(k, _)| {
        let name = k.to_string_lossy().to_ascii_uppercase();
        !crate::age_cmd::CHILD_ENV_REMOVED.contains(&name.as_str())
            && !crate::bridge::agent::exec::CREDENTIAL_WORDS.iter().any(|w| name.contains(w))
            && !name.starts_with("AI_ENV_BRIDGE_LAB_")
            && name != "AI_ENV_BRIDGE_AS"
            && !MAKE_ENV_DROPPED.contains(&name.as_str())
    })
    .collect()
}

/// How make ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MakeEnd {
    Passed,
    Failed,
    /// A stop signal came first: make's process group was ended.
    Stopped(crate::bridge::signals::Stop),
}

/// The stop signal that came while make ran (0: none), stored by [`on_stop`].
static STOP_SEEN: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn on_stop(sig: libc::c_int) {
    STOP_SEEN.store(sig, std::sync::atomic::Ordering::SeqCst);
}

/// SIGINT, SIGTERM and SIGHUP caught into [`STOP_SEEN`] while make runs (one ignored when ai-env started stays
/// ignored), their earlier actions put back when dropped. make leads its own process group (the bound kills the
/// group), so the terminal's signals reach ai-env alone: uncaught, a Ctrl-C would end ai-env and its lock and leave
/// make, cargo and the containers running.
struct StopCatch(Vec<(libc::c_int, libc::sigaction)>);

impl StopCatch {
    fn arm() -> StopCatch {
        STOP_SEEN.store(0, std::sync::atomic::Ordering::SeqCst);
        let handler: extern "C" fn(libc::c_int) = on_stop;
        let mut previous = Vec::new();
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if crate::bridge::signals::ignored(sig) {
                continue;
            }
            // SAFETY: sigaction(2) on zeroed (valid) structs; the handler only stores into an atomic
            // (async-signal-safe).
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler as libc::sighandler_t;
                libc::sigemptyset(&raw mut act.sa_mask);
                if libc::sigaction(sig, &raw const act, &raw mut old) == 0 {
                    previous.push((sig, old));
                }
            }
        }
        StopCatch(previous)
    }

    /// The stop that came since [`StopCatch::arm`], if one did.
    fn seen() -> Option<crate::bridge::signals::Stop> {
        use crate::bridge::signals::Stop;
        match STOP_SEEN.load(std::sync::atomic::Ordering::SeqCst) {
            libc::SIGINT => Some(Stop::Int),
            libc::SIGTERM => Some(Stop::Term),
            libc::SIGHUP => Some(Stop::Hup),
            _ => None,
        }
    }
}

impl Drop for StopCatch {
    fn drop(&mut self) {
        for (sig, old) in &self.0 {
            // SAFETY: sigaction(2) putting back the action `arm` read.
            unsafe {
                libc::sigaction(*sig, old, std::ptr::null_mut());
            }
        }
    }
}

/// make's process group ended: SIGTERM (`docker run` hands it to its container), up to 5 s, then SIGKILL to
/// whatever is left of the group; the child reaped.
fn end_group(child: &mut std::process::Child) {
    let group = -(child.id() as libc::pid_t);
    // SAFETY: kill(2) of the process group `run_make` made (process_group(0): the child leads it).
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) && matches!(child.try_wait(), Ok(None)) {
        std::thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: as above; the group outlives its leader while any member is left (none: ESRCH, ignored).
    unsafe {
        libc::kill(group, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// `<make> -C <repo> claude-admit-docker CLAUDE_BIN=… CLAUDE_VERSION=… CLAUDE_SHA256=…` with [`make_env`], its
/// output to `log` (0600, written anew), within [`ADMIT_MAKE_BOUND`] (its process group ended past it, `Failed`); a
/// stop signal ends the group too (`Stopped`).
fn run_make(make: &Path, repo: &Path, bin: &Path, version: &str, sha256: &str, log: &Path) -> Result<MakeEnd, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::process::CommandExt as _;
    if let Some(dir) = log.parent() {
        crate::bridge::registry::ensure_private_dir(dir).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_file(log);
    let out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(log).map_err(|e| format!("cannot write {}: {e}", log.display()))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(make);
    cmd.env_clear()
        .envs(make_env())
        .arg("-C")
        .arg(repo)
        .arg("claude-admit-docker")
        .arg(format!("CLAUDE_BIN={}", bin.display()))
        .arg(format!("CLAUDE_VERSION={version}"))
        .arg(format!("CLAUDE_SHA256={sha256}"))
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .process_group(0);
    let note = |line: String| {
        let _ = std::fs::OpenOptions::new().append(true).open(log).and_then(|mut f| writeln!(f, "{line}"));
    };
    let _catch = StopCatch::arm();
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", make.display()))?;
    let start = Instant::now();
    loop {
        // Looked at after each wait: a stop that came before make's end was seen wins over its status.
        let waited = child.try_wait();
        if let Some(stop) = StopCatch::seen() {
            end_group(&mut child);
            note(format!("ai-env: {} ({}): the Docker tests ended", stop.word(), stop.name()));
            return Ok(MakeEnd::Stopped(stop));
        }
        match waited {
            Ok(Some(status)) => return Ok(if status.success() { MakeEnd::Passed } else { MakeEnd::Failed }),
            Ok(None) if start.elapsed() > ADMIT_MAKE_BOUND => {
                end_group(&mut child);
                note(format!("ai-env: the Docker tests did not end within {} min: killed", ADMIT_MAKE_BOUND.as_secs() / 60));
                return Ok(MakeEnd::Failed);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => {
                end_group(&mut child);
                return Err(format!("{}: {e}", make.display()));
            }
        }
    }
}

/// The log's text (lossy UTF-8), empty when it cannot be read.
fn log_text(log: &Path) -> String {
    std::fs::read(log).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

/// The log's last non-empty line, scrubbed, at most [`DOCKER_LINE_MAX`] characters.
fn last_line(text: &str) -> String {
    let line = text.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("(no output)");
    crate::wire::redact::scrub(line).chars().take(DOCKER_LINE_MAX).collect()
}

/// A test's name as libtest prints it (`l2_x`, `module::l2_x`): ASCII letters, digits, `_` and `:` only.
fn test_name(word: &str) -> Option<&str> {
    (!word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')).then_some(word)
}

/// What a Docker failure keeps of the make log in its record (Mike's rule, 24 Oct: the next run writes the log
/// anew, so the record says which test failed and how): the first failing test's name (none past [`DOCKER_TEST_MAX`]
/// characters or when the scrubber would change it), and the lines that say what failed, in the log's order. Each
/// failing test's `test NAME ... FAILED` (cargo's line); a name only libtest's closing `failures:` list holds (its
/// line split by output the test did not capture) as `failures: NAME`; and each thread's first panic: its
/// `panicked at` line and the line after it (the message's first line, unless blank, libtest's backtrace note or
/// another panic). With none of them (a build that failed, a run killed at its bound), the log's last
/// [`DOCKER_EXCERPT_TAIL`] non-empty lines. Each line trimmed, scrubbed (`wire::redact::scrub`) and cut to
/// [`DOCKER_LINE_MAX`] characters; at most [`DOCKER_EXCERPT_LINES`] lines and [`DOCKER_EXCERPT_BYTES`] bytes, the
/// first ones kept (pure).
pub(crate) fn docker_excerpt(log: &str) -> (Option<String>, Vec<String>) {
    let lines: Vec<&str> = log.lines().collect();
    let mut names: Vec<String> = Vec::new();
    let mut threads: Vec<&str> = Vec::new();
    let mut picked: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if let Some(name) = line.strip_prefix("test ").and_then(|r| r.strip_suffix(" ... FAILED")).and_then(|r| r.split_whitespace().next()).and_then(test_name) {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
                picked.push(line.to_string());
            }
        } else if line == "failures:" {
            // libtest's closing list, one name a line indented by four spaces (its first `failures:` heads the
            // tests' output instead: a blank line follows it).
            while let Some(name) = lines.get(i + 1).and_then(|l| l.strip_prefix("    ")).map(str::trim).and_then(test_name) {
                if !names.iter().any(|n| n == name) {
                    names.push(name.to_string());
                    picked.push(format!("failures: {name}"));
                }
                i += 1;
            }
        } else if let Some(at) = line.find(" panicked at ") {
            // `thread 'NAME' panicked at FILE:LINE:COL:`, its message on the next line; a test's thread is named
            // after it, so the first panic of each thread is each failing test's.
            let thread = &line[..at];
            if !threads.contains(&thread) {
                threads.push(thread);
                picked.push(line.to_string());
                let message = |l: &&str| !l.is_empty() && !l.starts_with("note: run with `RUST_BACKTRACE") && !l.contains(" panicked at ");
                if let Some(message) = lines.get(i + 1).map(|l| l.trim()).filter(message) {
                    picked.push(message.to_string());
                    i += 1;
                }
            }
        }
        i += 1;
    }
    if picked.is_empty() {
        let tail: Vec<&str> = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        picked = tail[tail.len().saturating_sub(DOCKER_EXCERPT_TAIL)..].iter().map(|l| (*l).to_string()).collect();
    }
    let mut kept: Vec<String> = Vec::new();
    let mut bytes = 0;
    for line in picked {
        let line: String = crate::wire::redact::scrub(&line).chars().take(DOCKER_LINE_MAX).collect();
        if kept.len() == DOCKER_EXCERPT_LINES || bytes + line.len() + 1 > DOCKER_EXCERPT_BYTES {
            break;
        }
        bytes += line.len() + 1;
        kept.push(line);
    }
    // A name stays an id (the audit's `test`): one longer than DOCKER_TEST_MAX, or that the scrubber would change, is
    // none.
    let first = names.into_iter().next().filter(|n| n.len() <= DOCKER_TEST_MAX && crate::wire::redact::scrub(n) == n.as_str());
    (first, kept)
}

// ---- the admission ------------------------------------------------------------------------------------------------

/// One `claude_admit` row: `version`, `outcome`, `ms`, then `extra` and `auto`.
fn audit(paths: &Paths, version: &str, outcome: &str, started: Instant, auto: bool, extra: &[(&str, String)]) {
    let mut pairs: Vec<(&str, String)> = vec![("version", version.to_string()), ("outcome", outcome.to_string()), ("ms", started.elapsed().as_millis().to_string())];
    pairs.extend(extra.iter().cloned());
    pairs.push(("auto", auto.to_string()));
    crate::bridge::vm::cmd::audit_event(paths, crate::bridge::remote::audit_event::CLAUDE_ADMIT, &pairs);
}

/// The lock of an admission: fd 3's under `--auto` (D5's trigger took it), else taken here.
fn lock_for(paths: &Paths, version: &str, auto: bool) -> Result<VersionLock, CliError> {
    if auto {
        if let Some(lock) = VersionLock::adopt(paths, version) {
            return Ok(lock);
        }
    }
    Ok(VersionLock::take_or_busy(paths, version)?)
}

/// The versions whose local files [`prune_local`] removes, oldest first: each version directory holding a binary or a
/// `.partial` whose record is decided (admitted, staged, stale or failed) and which is not one of the
/// [`CLAUDE_GC_KEEP_LOCAL`] newest admitted, with its lock taken (`None`: `own`'s, which the caller holds). A version
/// without a decided record, or whose lock another process holds (an admission, a stage or a forget in flight), is
/// skipped: its files may be in use.
pub(crate) fn local_doomed(paths: &Paths, own: Option<&str>) -> Vec<(String, Option<VersionLock>)> {
    let records = super::load_all(paths);
    let mut admitted: Vec<&str> = records.iter().filter(|r| matches!(r.phase(), Phase::Admitted | Phase::Staged | Phase::Stale)).map(|r| r.version.as_str()).collect();
    admitted.sort_by_key(|v| std::cmp::Reverse(super::version_key(v)));
    let keep: Vec<&str> = admitted.into_iter().take(CLAUDE_GC_KEEP_LOCAL).collect();
    let decided: Vec<&str> = records.iter().filter(|r| matches!(r.phase(), Phase::Admitted | Phase::Staged | Phase::Stale | Phase::Failed(_))).map(|r| r.version.as_str()).collect();
    let Ok(dir) = std::fs::read_dir(paths.claude_dir()) else { return Vec::new() };
    let mut versions: Vec<String> = dir
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|v| crate::wire::pin::is_version(v) && !keep.contains(&v.as_str()) && decided.contains(&v.as_str()))
        .filter(|v| paths.claude_bin(v).exists() || paths.claude_bin_dir(v).join(".partial").exists())
        .collect();
    versions.sort_by_key(|v| super::version_key(v));
    versions
        .into_iter()
        .filter_map(|v| {
            if own == Some(v.as_str()) {
                return Some((v, None));
            }
            match VersionLock::take(paths, &v) {
                Ok(Some(lock)) => Some((v, Some(lock))),
                _ => None,
            }
        })
        .collect()
}

/// Local binaries past the [`CLAUDE_GC_KEEP_LOCAL`] newest admitted versions' removed (LD-31; no Touch ID), each
/// under its version's lock ([`local_doomed`]; `own` the version whose lock the caller holds): the versions whose
/// binaries went.
pub fn prune_local(paths: &Paths, own: Option<&str>) -> Vec<String> {
    let mut gone = Vec::new();
    for (v, _lock) in local_doomed(paths, own) {
        let bin = paths.claude_bin(&v);
        if bin.exists() && std::fs::remove_file(&bin).is_ok() {
            gone.push(v.clone());
        }
        let _ = std::fs::remove_file(paths.claude_bin_dir(&v).join(".partial"));
    }
    gone
}

/// `version` admitted: §3.3's steps in order, each failure stopping it and naming its step in the record. The
/// errors carry the exits of the table (LD-29): 1 a failure that may pass again (the lock, a precondition, the
/// fetch, gpgv, the download, the Docker tests, a failed record shown, a lab run without its knobs), 9 a refusal
/// (the signature, the bytes, a marker).
pub fn admit(paths: &Paths, cfg: &BridgeConfig, knobs: &VmKnobs, version: &str, opts: AdmitOpts) -> Result<Record, CliError> {
    let started = Instant::now();
    if !crate::wire::pin::is_version(version) {
        return Err(CliError::Usage(format!("not a claude version (N.N.N): {version:?}")));
    }
    // Under the fake API every program it runs is a knob's: nothing real is run or recorded otherwise.
    release::lab_programs(knobs, &[LabProgram::Curl, LabProgram::Gpgv, LabProgram::Make]).map_err(|e| CliError::Msg(format!("claude admit {version}: {e}")))?;
    let mut lock = lock_for(paths, version, opts.auto)?;
    let end = |lock: &mut VersionLock, word: &str| {
        if opts.auto {
            lock.finish(word);
        }
    };
    // Under --auto, the step an early exit (`?`) leaves in the lock as `error(<step>)` (the lock's Drop): D5's
    // cooldown then holds whatever ended it.
    let at_step = |lock: &mut VersionLock, step: &'static str| {
        if opts.auto {
            lock.auto_step = Some(step);
        }
    };
    at_step(&mut lock, "record");
    // Step 3: a decided record stands without --redo. Under --auto a Docker failure with tries left whose cooldown is
    // over (what D5's trigger read, read again under the lock) is admitted again, every step below checked again as
    // for --redo: the signed manifest fetched and verified anew, the kept binary's size and sha256 held against it
    // (else downloaded again), its markers, then the Docker tests (Mike's rule, 24 Oct).
    if let Some(record) = super::Record::load(paths, version)? {
        let retry = opts.auto && record.auto_retry() && record.auto_retry_from().is_none_or(|from| crate::wire::time::unix_now() >= from);
        if !opts.redo && !retry {
            match record.phase() {
                Phase::Admitted | Phase::Staged | Phase::Stale => {
                    end(&mut lock, "admitted");
                    return Ok(record);
                }
                Phase::Failed(step) => {
                    end(&mut lock, &format!("failed({step})"));
                    return Err(CliError::Msg(failed_line(version, &step, &record)));
                }
                Phase::Seen | Phase::Signed => {}
            }
        }
    }
    let (repo, image) = match preconditions() {
        Ok(got) => got,
        Err((word, text)) => {
            audit(paths, version, "skipped", started, opts.auto, &[("why", word.to_string())]);
            end(&mut lock, &format!("skipped({word})"));
            return Err(CliError::Msg(format!("claude {version}: not admitted: {text}; nothing recorded")));
        }
    };
    let at = crate::bridge::registry::now_rfc3339;
    // Step 4: the signed manifest.
    at_step(&mut lock, "signature");
    let verified = match release::verified_manifest(paths, knobs, version) {
        Ok(v) => v,
        Err(e) if e.may_pass_again() => {
            let step = e.word();
            audit(paths, version, "error", started, opts.auto, &[("step", step.to_string()), ("why", step.to_string())]);
            end(&mut lock, &format!("error({step})"));
            return Err(CliError::Msg(format!("claude {version}: {e}: nothing recorded (it may pass again)")));
        }
        Err(e) => {
            let why = e.word().to_string();
            let manifest_sha256 = None;
            super::Record::update(paths, version, |r| r.signature = Some(SignatureRow { outcome: "failed".into(), why: Some(why.clone()), manifest_sha256, at: at(), ..SignatureRow::default() }))?;
            audit(paths, version, "failed", started, opts.auto, &[("step", "signature".into()), ("why", why)]);
            end(&mut lock, "failed(signature)");
            let text = match &e {
                ReleaseError::Signature(w) => format!("claude {version}: the release manifest's signature is not the release key's ({w}): not admitted"),
                other => format!("claude {version}: {other}: not admitted"),
            };
            return Err(CliError::Policy(text));
        }
    };
    let (size, sha256) = (verified.linux.size, verified.linux.sha256.clone());
    super::Record::update(paths, version, |r| {
        r.signature = Some(SignatureRow {
            outcome: "ok".into(),
            why: None,
            manifest_sha256: Some(verified.manifest_sha256.clone()),
            signer: Some(verified.signer.clone()),
            linux_sha256: Some(sha256.clone()),
            linux_size: Some(size),
            build_date: Some(verified.linux.build_date.clone()),
            darwin_sha256: verified.darwin_sha256.clone(),
            at: at(),
        });
    })?;
    // The verified files stay as evidence beside the binary (LD-28).
    let dir = paths.claude_bin_dir(version);
    crate::bridge::registry::ensure_private_dir(&dir)?;
    crate::bridge::infra::write_atomic_mode(&dir.join("manifest.json"), &verified.json, 0o600)?;
    crate::bridge::infra::write_atomic_mode(&dir.join("manifest.json.sig"), &verified.sig, 0o600)?;
    // Step 5: the binary, unless the one here is already the signed one.
    at_step(&mut lock, "download");
    let bin = paths.claude_bin(version);
    let failed = |step: &str, markers: Option<String>, docker: Option<String>| AdmissionRow { outcome: "failed".into(), step: Some(step.into()), markers, docker, ai_env: env!("CARGO_PKG_VERSION").into(), auto: opts.auto, at: at(), ..AdmissionRow::default() };
    // A binary that cannot be read is no answer, never a refusal: exit 1, nothing recorded past the signature.
    let unreadable = |lock: &mut VersionLock, what: &Path, e: &dyn std::fmt::Display| {
        audit(paths, version, "error", started, opts.auto, &[("step", "download".into()), ("why", "unreadable".into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone())]);
        end(lock, "error(download)");
        CliError::Msg(format!("claude {version}: {} cannot be read ({e}): the signature stays recorded (a retry needs no --redo)", what.display()))
    };
    if size_and_sha256(&bin).as_ref() != Some(&(size, sha256.clone())) {
        let partial = dir.join(".partial");
        let _ = std::fs::remove_file(&partial);
        let fetched = {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&partial).map_err(|e| ReleaseError::Fetch(format!("cannot write {}: {e}", partial.display()))).and_then(|f| {
                drop(f);
                release::fetch(knobs, &crate::wire::pin::binary_url(version), &partial, DOWNLOAD_MAX_TIME_S, Some(size))
            })
        };
        if let Err(e) = fetched {
            let _ = std::fs::remove_file(&partial);
            audit(paths, version, "error", started, opts.auto, &[("step", "download".into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone())]);
            end(&mut lock, "error(download)");
            return Err(CliError::Msg(format!("claude {version}: the download failed: {e}: the signature stays recorded (a retry needs no --redo)")));
        }
        let Some((n, s)) = size_and_sha256(&partial) else {
            let _ = std::fs::remove_file(&partial);
            return Err(unreadable(&mut lock, &partial, &"gone or unreadable after the download"));
        };
        if (n, s.as_str()) != (size, sha256.as_str()) {
            let _ = std::fs::remove_file(&partial);
            super::Record::update(paths, version, |r| r.admission = Some(AdmissionRow { docker_failures: r.docker_failures(), ..failed("download", None, None) }))?;
            audit(paths, version, "failed", started, opts.auto, &[("step", "download".into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone())]);
            end(&mut lock, "failed(download)");
            return Err(CliError::Policy(format!("claude {version}: the downloaded binary is {n} bytes, sha256 {}…, not the signed manifest's {size} bytes, {}…: not admitted", short(&s), short(&sha256))));
        }
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&partial, &bin)?;
    }
    super::Record::update(paths, version, |r| r.download = Some(DownloadRow { sha256: sha256.clone(), size, at: at() }))?;
    // Step 6: the markers.
    at_step(&mut lock, "markers");
    let missing = match scan_markers(&bin) {
        Ok(missing) => missing,
        Err(e) => return Err(unreadable(&mut lock, &bin, &e)),
    };
    if let Some(name) = missing {
        let markers = format!("missing:{name}");
        super::Record::update(paths, version, |r| r.admission = Some(AdmissionRow { docker_failures: r.docker_failures(), ..failed("markers", Some(markers.clone()), None) }))?;
        audit(paths, version, "failed", started, opts.auto, &[("step", "markers".into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone()), ("markers", markers.clone())]);
        end(&mut lock, "failed(markers)");
        return Err(CliError::Policy(format!("claude {version}: its Linux binary lacks the marker {name} (a text the code relies on): not admitted")));
    }
    // Step 7: the Docker tests on it.
    at_step(&mut lock, "docker");
    let make = admit_make(knobs);
    let log = paths.logs().join(format!("claude-admit-{version}.log"));
    let passed = match run_make(&make, &repo, &bin, version, &sha256, &log) {
        Ok(MakeEnd::Passed) => true,
        Ok(MakeEnd::Failed) => false,
        Ok(MakeEnd::Stopped(stop)) => {
            audit(paths, version, "error", started, opts.auto, &[("step", "docker".into()), ("why", stop.word().into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone())]);
            end(&mut lock, "error(docker)");
            if !opts.auto {
                crate::bridge::signals::say(&format!("ai-env: {} ({}): claude {version}'s Docker tests ended, nothing recorded (the log: {})", stop.word(), stop.name(), log.display()));
            }
            return Err(CliError::Exit(stop.status()));
        }
        Err(e) => {
            let _ = std::fs::OpenOptions::new().append(true).open(&log).and_then(|mut f| writeln!(f, "ai-env: {e}"));
            false
        }
    };
    let text = log_text(&log);
    let docker_line = last_line(&text);
    // A failure keeps what failed in the record, since the next run writes the log anew: its first failing test and
    // the log's excerpt.
    let (docker_test, docker_excerpt) = if passed { (None, Vec::new()) } else { docker_excerpt(&text) };
    // The tests ran on the image step 3 named only while the tag still names it at their end: a rebuild (or a
    // Docker gone) meanwhile leaves the run unattributable, so nothing is recorded and it may pass again.
    let after = local_image_id();
    if after.as_deref() != Some(image.as_str()) {
        let now = after.as_deref().unwrap_or("no image");
        audit(paths, version, "error", started, opts.auto, &[("step", "docker".into()), ("why", "image_changed".into()), ("sha256", sha256.clone()), ("signer", verified.signer.clone())]);
        end(&mut lock, "error(docker)");
        return Err(CliError::Msg(format!("claude {version}: {LOCAL_IMAGE} changed during its Docker tests ({image} at the start, {now} at the end): nothing recorded (it may pass again): ai-env claude admit {version}")));
    }
    let docker_image = Some(image);
    let row = AdmissionRow {
        outcome: if passed { "admitted" } else { "failed" }.into(),
        step: (!passed).then(|| "docker".into()),
        markers: Some("ok".into()),
        docker: Some(docker_line.clone()),
        docker_test: docker_test.clone(),
        docker_failures: 0,
        docker_excerpt,
        docker_image: docker_image.clone(),
        ai_env: env!("CARGO_PKG_VERSION").into(),
        auto: opts.auto,
        at: at(),
    };
    // Step 8: recorded, audited; the local binaries past the 2 newest admitted go. A failure is counted on the ones
    // recorded before it (read under the records lock); an admission clears the count (Mike's rule, 24 Oct).
    let record = super::Record::update(paths, version, |r| {
        let failures = if passed { 0 } else { r.docker_failures().saturating_add(1) };
        r.admission = Some(AdmissionRow { docker_failures: failures, ..row });
    })?;
    let attempt = record.admission.as_ref().map_or(0, |a| a.docker_failures);
    let mut extra = vec![("sha256", sha256.clone()), ("signer", verified.signer.clone()), ("markers", "ok".to_string())];
    if let Some(id) = &docker_image {
        extra.push(("docker_image", id.clone()));
    }
    if !passed {
        extra.insert(0, ("step", "docker".to_string()));
        // Which Docker failure of V this is, and its first failing test (ids and numbers only).
        extra.push(("attempt", attempt.to_string()));
        if let Some(test) = &docker_test {
            extra.push(("test", test.clone()));
        }
    }
    audit(paths, version, if passed { "admitted" } else { "failed" }, started, opts.auto, &extra);
    end(&mut lock, if passed { "admitted" } else { "failed(docker)" });
    if passed {
        for v in prune_local(paths, Some(version)) {
            tracing::info!(version = %v, "its local claude binary removed (this Mac keeps the {CLAUDE_GC_KEEP_LOCAL} newest admitted)");
        }
        Ok(record)
    } else {
        let failed_test = docker_test.map(|t| format!("test {t} failed; ")).unwrap_or_default();
        let spent = if attempt >= ADMIT_DOCKER_TRIES { ", no automatic retry left" } else { "" };
        // D5's trigger runs it again only with `[claude].auto_admit` on and the wrapper's mode remote (doctor's T6).
        let auto = cfg.claude.auto_admit && matches!(cfg.wrapper.wrapper_mode(), Ok(crate::bridge::config::WrapperMode::Remote));
        let next = if auto && record.auto_retry() {
            format!("an automatic retry{} (the next remote wrapper starts it), or fix it, then ai-env claude admit {version} --redo", super::retry_when(&record))
        } else {
            format!("fix it, then ai-env claude admit {version} --redo")
        };
        Err(CliError::Msg(format!("claude {version}: its Docker tests failed: {docker_line} (the log: {}): not admitted ({failed_test}{}{spent}); {next}", log.display(), super::attempt_words(attempt))))
    }
}

/// The first 12 hex digits of a sha256.
fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// A failed admission's line: its step and why, and the `--redo` that admits it again (`admit` without `--redo`
/// shows it, exit 1; a stage refuses the version with it, exit 9).
pub(crate) fn failed_line(version: &str, step: &str, record: &Record) -> String {
    format!("claude {version}: admission failed at {step}{}: fix it, then ai-env claude admit {version} --redo", failed_why(record))
}

/// ` (<why>)` of a failed record: the signature's word, the markers', the first failing Docker test, or the Docker
/// line.
fn failed_why(record: &Record) -> String {
    let why = match (&record.signature, &record.admission) {
        (Some(s), _) if s.outcome == "failed" => s.why.clone(),
        (_, Some(a)) => a.markers.clone().filter(|m| m.starts_with("missing:")).or_else(|| a.docker_test.as_ref().map(|t| format!("test {t} failed"))).or_else(|| a.docker.clone()),
        _ => None,
    };
    why.map(|w| format!(" ({w})")).unwrap_or_default()
}

/// The installed Cursor bundle's version (`doctor::pick_bundle` of the installed extension names, as `infra pin
/// --bundle-version` reads it), when it is `N.N.N`.
#[must_use]
pub fn installed_bundle() -> Option<String> {
    let home = std::env::var_os("HOME")?;
    let dir = PathBuf::from(home).join(".cursor").join("extensions");
    crate::bridge::doctor::pick_bundle(&crate::bridge::doctor::installed_extension_names(&dir)).map(|(v, _)| v).filter(|v| crate::wire::pin::is_version(v))
}

/// The version a command acts on: its argument, else the installed bundle's; neither, exit 2.
pub fn version_or_bundle(version: Option<&str>, command: &str) -> Result<String, CliError> {
    match version {
        Some(v) if crate::wire::pin::is_version(v) => Ok(v.to_string()),
        Some(v) => Err(CliError::Usage(format!("not a claude version (N.N.N): {v:?}"))),
        None => installed_bundle().ok_or_else(|| CliError::Usage(format!("no installed Cursor bundle names a claude version (~/.cursor/extensions): ai-env claude {command} <version>"))),
    }
}

/// The JSON document of an admission's end: `outcome` first (§7.1; a struct keeps its fields' order), then the
/// record as it stands: a Docker failure's first failing test, its count since the last admission (0 without one)
/// and the make log's excerpt (`null` without one) after the Docker run's last line.
#[derive(Debug, serde::Serialize)]
struct AdmitDoc {
    outcome: &'static str,
    version: String,
    phase: String,
    sha256: Option<String>,
    size: Option<u64>,
    signer: Option<String>,
    markers: Option<String>,
    docker: Option<String>,
    docker_test: Option<String>,
    docker_failures: u32,
    docker_excerpt: Option<Vec<String>>,
    docker_image: Option<String>,
    at: Option<String>,
}

fn admit_json(paths: &Paths, version: &str, outcome: &'static str) -> AdmitDoc {
    let record = Record::load(paths, version).ok().flatten();
    let sig = record.as_ref().and_then(|r| r.signature.clone());
    let adm = record.as_ref().and_then(|r| r.admission.clone());
    AdmitDoc {
        outcome,
        version: version.to_string(),
        phase: record.as_ref().map_or_else(|| "seen".to_string(), |r| r.phase().word()),
        sha256: sig.as_ref().and_then(|s| s.linux_sha256.clone()),
        size: sig.as_ref().and_then(|s| s.linux_size),
        signer: sig.as_ref().and_then(|s| s.signer.clone()),
        markers: adm.as_ref().and_then(|a| a.markers.clone()),
        docker: adm.as_ref().and_then(|a| a.docker.clone()),
        docker_test: adm.as_ref().and_then(|a| a.docker_test.clone()),
        docker_failures: record.as_ref().map_or(0, Record::docker_failures),
        docker_excerpt: adm.as_ref().map(|a| a.docker_excerpt.clone()).filter(|e| !e.is_empty()),
        docker_image: adm.as_ref().and_then(|a| a.docker_image.clone()),
        at: adm.as_ref().map(|a| a.at.clone()),
    }
}

/// The outcome word of an admission's end, from what `admit` returned and the record.
fn outcome_of(result: &Result<Record, CliError>, paths: &Paths, version: &str) -> &'static str {
    match result {
        Ok(_) => "admitted",
        Err(_) => match Record::load(paths, version).ok().flatten().map(|r| r.phase()) {
            Some(Phase::Failed(_)) => "failed",
            _ => "error",
        },
    }
}

/// `ai-env claude admit [V] [--redo] [--json]` and the hidden `--auto`.
pub fn cmd_admit(version: Option<&str>, redo: bool, auto: bool, json: bool) -> crate::errors::Result<()> {
    if auto {
        // D5's child: quiet (its stdio /dev/null, its lines to the wrapper's log), never a non-zero exit. An ai-env
        // process: its rows say `cli`, `auto` tells their origin (index X-5).
        let Ok(paths) = Paths::resolve() else { return Ok(()) };
        let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.wrapper_log(), rust_log: std::env::var("RUST_LOG").ok() });
        let Ok(version) = version_or_bundle(version, "admit") else {
            tracing::info!("claude admit --auto: no version to admit");
            return Ok(());
        };
        let cfg = BridgeConfig::load(&paths).ok().flatten().unwrap_or_default();
        let knobs = crate::bridge::lab::vm_knobs();
        match admit(&paths, &cfg, &knobs, &version, AdmitOpts { redo, auto: true }) {
            Ok(r) => tracing::info!(version = %version, phase = %r.phase().word(), "claude admit --auto"),
            Err(e) => tracing::info!(version = %version, "claude admit --auto: {e}"),
        }
        return Ok(());
    }
    let paths = Paths::resolve()?;
    let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
    let version = version_or_bundle(version, "admit")?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    let knobs = crate::bridge::lab::vm_knobs();
    let before = Record::load(&paths, &version).ok().flatten().map(|r| r.phase());
    let result = admit(&paths, &cfg, &knobs, &version, AdmitOpts { redo, auto: false });
    if json {
        let outcome = outcome_of(&result, &paths, &version);
        crate::outln!("{}", serde_json::to_string_pretty(&admit_json(&paths, &version, outcome)).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
        return result.map(|_| ());
    }
    let record = result?;
    let sig = record.signature.clone().unwrap_or_default();
    let adm = record.admission.clone().unwrap_or_default();
    let fresh = !matches!(before, Some(Phase::Admitted | Phase::Staged | Phase::Stale)) || redo;
    if fresh {
        crate::outln!(
            "claude {version}: admitted: signed by the release key ({}), linux-arm64 {} bytes, sha256 {}…, markers ok, Docker tests passed on {}",
            sig.signer.as_deref().unwrap_or("-"),
            sig.linux_size.unwrap_or(0),
            short(sig.linux_sha256.as_deref().unwrap_or("")),
            adm.docker_image.as_deref().unwrap_or(LOCAL_IMAGE)
        );
        crate::outln!("claude {version}: next: {}", super::rows::stage_hint(&version, installed_bundle().as_deref()));
    } else {
        crate::outln!("claude {version}: already {} (since {}): ai-env claude admit {version} --redo admits it again", record.phase().word(), adm.at);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One form of every marker, joined: a binary that holds them all.
    fn all_markers() -> Vec<u8> {
        let mut b = b"\x7fELF padding ".to_vec();
        for m in crate::wire::claude::V_MARKERS {
            b.extend_from_slice(m.forms.last().unwrap().as_bytes());
            b.extend_from_slice(b"\0junk\0");
        }
        b
    }

    #[test]
    fn the_markers_are_searched_across_chunks_and_name_the_first_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("claude");
        std::fs::write(&p, all_markers()).unwrap();
        assert_eq!(missing_marker(&p), None);
        // A form split by the 16 MiB chunk boundary is still found.
        let mut big = vec![b'x'; (16 << 20) - 5];
        big.extend_from_slice(&all_markers());
        std::fs::write(&p, &big).unwrap();
        assert_eq!(missing_marker(&p), None);
        let without = String::from_utf8_lossy(&all_markers()).replace("--session-id", "--sessionXid").into_bytes();
        std::fs::write(&p, without).unwrap();
        assert_eq!(missing_marker(&p), Some("session_id"));
        std::fs::write(&p, b"nothing").unwrap();
        assert_eq!(missing_marker(&p), Some("resume_session_at"), "the first in V_MARKERS' order");
        assert_eq!(missing_marker(&dir.path().join("none")), Some("resume_session_at"));
        // Any one of a marker's forms counts (LD-39).
        let utf8 = String::from_utf8_lossy(&all_markers()).replace(" \\u00B7 resets ", crate::wire::ratelimit::RESETS).into_bytes();
        std::fs::write(&p, utf8).unwrap();
        assert_eq!(missing_marker(&p), None);
        let none = String::from_utf8_lossy(&all_markers()).replace(" \\u00B7 resets ", " resets ").into_bytes();
        std::fs::write(&p, none).unwrap();
        assert_eq!(missing_marker(&p), Some("rate_limit_resets"));
    }

    /// The tail of a make log whose Docker test `l2_x` failed, as cargo and libtest print it (B4 (a)'s failure ended
    /// on make's line alone).
    const CARGO_FAILURE: &str = "\
   Compiling ai-env-cli v0.11.0 (/Users/someone/ai-env/crates/ai-env-cli)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2m 01s
     Running tests/docker_exec.rs (target/claude-admit/debug/deps/docker_exec-0123456789abcdef)

running 2 tests
test l2_claude_auth_status_json_is_logged_out_with_no_network ... ok
test l2_x ... FAILED

failures:

---- l2_x stdout ----

thread 'l2_x' panicked at tests/docker_exec.rs:123:5:
assertion `left == right` failed: the pinned claude did not answer
  left: None
 right: Some(\"2.1.310\")
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    l2_x

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 120.04s

error: test failed, to rerun pass `-p ai-env-cli --test docker_exec`
make: *** [claude-admit-docker] Error 101
";

    /// Mike's rule (24 Oct): a Docker failure keeps the failing test's line and its first panic (the location and
    /// the message after it), the first failing test named; a test only the closing `failures:` list names (its
    /// line split by output it did not capture) too; each thread's first panic once; with none of them, the log's
    /// last 5 lines.
    #[test]
    fn the_docker_excerpt_names_the_failing_tests_and_their_first_panic() {
        let (first, excerpt) = docker_excerpt(CARGO_FAILURE);
        assert_eq!(first.as_deref(), Some("l2_x"));
        assert_eq!(excerpt, ["test l2_x ... FAILED", "thread 'l2_x' panicked at tests/docker_exec.rs:123:5:", "assertion `left == right` failed: the pinned claude did not answer"]);
        assert_eq!(last_line(CARGO_FAILURE), "make: *** [claude-admit-docker] Error 101", "the record's `docker` stays the last line");
        // A test whose `test NAME ... ` line the container's own output split: the closing list names it; the old
        // panic format (its message on the line) keeps no backtrace note; a second panic of a thread is not kept.
        let split = "\
running 2 tests
test l2_a ... docker: Error response from daemon: Conflict.
FAILED
test l2_b ... FAILED

failures:

---- l2_a stdout ----
thread 'l2_a' panicked at 'the container did not start', tests/shim_docker.rs:2545:9
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
thread 'l2_a' panicked at tests/shim_docker.rs:2600:1:
a second panic while unwinding
---- l2_b stdout ----
thread 'l2_b' panicked at tests/docker_exec.rs:916:5:
no claude --version

failures:
    l2_a
    l2_b

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 1 filtered out; finished in 9.10s
";
        let (first, excerpt) = docker_excerpt(split);
        assert_eq!(first.as_deref(), Some("l2_b"), "the first named in the log's order");
        assert_eq!(
            excerpt,
            [
                "test l2_b ... FAILED",
                "thread 'l2_a' panicked at 'the container did not start', tests/shim_docker.rs:2545:9",
                "thread 'l2_b' panicked at tests/docker_exec.rs:916:5:",
                "no claude --version",
                "failures: l2_a",
            ]
        );
        // Nothing names a test or a panic (a build that failed): the last 5 non-empty lines.
        let build = "error[E0425]: cannot find value `x` in this scope\n  --> tests/docker_exec.rs:10:5\n\nFor more information about this error, try `rustc --explain E0425`.\nerror: could not compile `ai-env-cli` (test \"docker_exec\") due to 1 previous error\nmake: *** [claude-admit-docker] Error 101\n\n";
        let (first, excerpt) = docker_excerpt(build);
        assert_eq!(first, None);
        assert_eq!(
            excerpt,
            [
                "error[E0425]: cannot find value `x` in this scope",
                "--> tests/docker_exec.rs:10:5",
                "For more information about this error, try `rustc --explain E0425`.",
                "error: could not compile `ai-env-cli` (test \"docker_exec\") due to 1 previous error",
                "make: *** [claude-admit-docker] Error 101",
            ]
        );
        assert_eq!(docker_excerpt(""), (None, Vec::new()));
    }

    /// The excerpt's bounds: each line scrubbed, then cut to 300 characters; at most 12 lines and 4 KiB (a newline
    /// counted after each), the first ones kept; a name past 200 characters, or one the scrubber would change, is
    /// named nowhere.
    #[test]
    fn the_docker_excerpt_is_scrubbed_and_bounded() {
        let secret = format!("sk-ant-oat01-{}", "Q".repeat(40));
        let log = format!("test l2_x ... FAILED\nthread 'l2_x' panicked at tests/docker_exec.rs:1:1:\nthe token {secret} was refused; {}\n", "z".repeat(1000));
        let (_, excerpt) = docker_excerpt(&log);
        assert_eq!(excerpt.len(), 3);
        assert!(!excerpt[2].contains(&secret) && excerpt[2].starts_with("the token sk-ant-[redacted:len="), "{}", excerpt[2]);
        assert_eq!(excerpt[2].chars().count(), DOCKER_LINE_MAX, "cut after the scrub");
        let many: String = (0..20).map(|i| format!("test l2_t{i} ... FAILED\n")).collect();
        let (first, excerpt) = docker_excerpt(&many);
        assert_eq!((first.as_deref(), excerpt.len(), excerpt[11].as_str()), (Some("l2_t0"), DOCKER_EXCERPT_LINES, "test l2_t11 ... FAILED"));
        // Two-byte characters: 4 KiB ends it before 12 lines.
        let wide: String = (0..12).map(|i| format!("thread 't{i}' panicked at {}\n", "é".repeat(400))).collect();
        let (_, excerpt) = docker_excerpt(&wide);
        let bytes: usize = excerpt.iter().map(|l| l.len() + 1).sum();
        assert!(bytes <= DOCKER_EXCERPT_BYTES && excerpt.len() < DOCKER_EXCERPT_LINES && !excerpt.is_empty(), "{} lines, {bytes} bytes", excerpt.len());
        assert!(excerpt.iter().all(|l| l.chars().count() <= DOCKER_LINE_MAX));
        // A name past DOCKER_TEST_MAX characters is the log's text, not an id: named nowhere (a record's `docker_test`,
        // the views' `test NAME failed`, the audit's `test`, whose row past 64 KiB would not be written), its line kept
        // and cut like any other; one of DOCKER_TEST_MAX is named.
        for len in [DOCKER_TEST_MAX + 1, 100_000] {
            let (first, excerpt) = docker_excerpt(&format!("test {} ... FAILED\n", "n".repeat(len)));
            assert_eq!((first, excerpt.len()), (None, 1), "{len}");
            assert!(excerpt[0].starts_with("test nnn") && excerpt[0].chars().count() == ("test ".len() + len + " ... FAILED".len()).min(DOCKER_LINE_MAX), "{len}");
        }
        let (first, _) = docker_excerpt(&format!("failures:\n    {}\n", "n".repeat(DOCKER_TEST_MAX + 1)));
        assert_eq!(first, None, "the closing list's name too");
        let (first, _) = docker_excerpt(&format!("test {} ... FAILED\n", "n".repeat(DOCKER_TEST_MAX)));
        assert_eq!(first.map(|n| n.len()), Some(DOCKER_TEST_MAX));
        // A failing test's name is an id or nothing: `test` in the audit never carries what the scrubber masks.
        let registered = "l2_registered_secret_name_0123456789";
        crate::wire::redact::register_secret(registered);
        let (first, excerpt) = docker_excerpt(&format!("test {registered} ... FAILED\n"));
        assert!(crate::wire::redact::forget_secret(registered));
        assert_eq!(first, None);
        assert!(excerpt[0].contains("[redacted:len=") && !excerpt[0].contains(registered), "{excerpt:?}");
    }

    #[test]
    fn make_runs_without_credentials_knobs_or_the_runners_marker() {
        // The test process's own environment: whatever it holds, none of these names reaches make.
        let names: Vec<String> = make_env().into_iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        for n in &names {
            assert!(!n.starts_with("AI_ENV_BRIDGE_LAB_") && n != "AI_ENV_BRIDGE_AS" && !crate::age_cmd::CHILD_ENV_REMOVED.contains(&n.as_str()), "{n}");
            assert!(!crate::bridge::agent::exec::CREDENTIAL_WORDS.iter().any(|w| n.to_ascii_uppercase().contains(w)), "{n}");
            assert!(!MAKE_ENV_DROPPED.contains(&n.as_str()), "{n}");
        }
        // make's own flags (a dry run, -t, -i, -e) and the Makefile's `?=` variables the recipe uses never steer it:
        // the tests run on ai-env-agent:local, whose id the record names, or the admission fails.
        let os = |k: &str, v: &str| (std::ffi::OsString::from(k), std::ffi::OsString::from(v));
        let given = [
            os("MAKEFLAGS", "-n"),
            os("MFLAGS", "-n"),
            os("GNUMAKEFLAGS", "-i"),
            os("MAKEOVERRIDES", "LOCAL_IMAGE=x"),
            os("MAKELEVEL", "1"),
            os("MAKEFILES", "/tmp/x.mk"),
            os("LOCAL_IMAGE", "x"),
            os("TOOLCHAIN", "nightly"),
            os("AI_ENV_BRIDGE_LAB_FAKE_API", "/tmp/fake.json"),
            os("GITHUB_TOKEN", "t"),
            os("PATH", "/usr/bin:/bin"),
            os("HOME", "/h"),
        ];
        let kept: Vec<(std::ffi::OsString, std::ffi::OsString)> = make_env_of(given.into_iter());
        assert_eq!(kept, [os("PATH", "/usr/bin:/bin"), os("HOME", "/h")]);
    }

    /// The lock, retried for up to 5 s: between its fork and its exec, a child another test of this binary spawns
    /// holds every descriptor of this process (close-on-exec ones too), so a lock this test just let go may read as
    /// held for a moment.
    fn take_soon(p: &Paths, version: &str) -> Option<VersionLock> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(l) = VersionLock::take(p, version).unwrap() {
                return Some(l);
            }
            if std::time::Instant::now() >= until {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn the_version_lock_is_single_flight_and_records_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(dir.path().join("bridge"), None);
        let mut held = VersionLock::take(&p, "2.1.308").unwrap().expect("free");
        assert!(VersionLock::take(&p, "2.1.308").unwrap().is_none(), "held");
        assert!(VersionLock::take(&p, "2.1.309").unwrap().is_some(), "per version");
        let busy = VersionLock::take_or_busy(&p, "2.1.308").unwrap_err().to_string();
        assert!(busy.contains("another admission or staging of claude 2.1.308 is running"), "{busy}");
        held.finish("skipped(no_docker)");
        let text = std::fs::read_to_string(p.claude_lock("2.1.308")).unwrap();
        assert!(text.starts_with("finished_at=") && text.ends_with("\noutcome=skipped(no_docker)\n"), "{text}");
        held.finish("admitted");
        assert!(std::fs::read_to_string(p.claude_lock("2.1.308")).unwrap().ends_with("\noutcome=admitted\n"), "rewritten from its first byte");
        drop(held);
        assert!(take_soon(&p, "2.1.308").is_some(), "released");
        // Handed over (D5): the other descriptor of the open file (the child's fd 3) keeps the lock after this
        // process's copy is dropped (a drop never unlocks); it goes with the last one.
        let lock = take_soon(&p, "2.1.308").expect("free");
        // SAFETY: dup(2) of the lock's open descriptor; the copy is closed below.
        let child = unsafe { libc::dup(std::os::fd::AsRawFd::as_raw_fd(&lock)) };
        assert!(child >= 0);
        drop(lock);
        assert!(VersionLock::take(&p, "2.1.308").unwrap().is_none(), "still held through the child's descriptor");
        // SAFETY: close(2) of the descriptor dup'ed above, once.
        unsafe { libc::close(child) };
        assert!(take_soon(&p, "2.1.308").is_some(), "released with the last descriptor");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(p.claude_lock("2.1.308")).unwrap().permissions().mode() & 0o777, 0o600);
        // --auto: an exit without an outcome (an early `?`, a panic) writes `error(<step>)` from the drop; one
        // with an outcome is left as it is.
        let mut auto = take_soon(&p, "2.1.310").expect("free");
        auto.auto_step = Some("signature");
        drop(auto);
        let text = std::fs::read_to_string(p.claude_lock("2.1.310")).unwrap();
        assert!(text.starts_with("finished_at=") && text.ends_with("\noutcome=error(signature)\n"), "{text}");
        let mut auto = take_soon(&p, "2.1.310").expect("free");
        auto.auto_step = Some("docker");
        auto.finish("admitted");
        drop(auto);
        assert!(std::fs::read_to_string(p.claude_lock("2.1.310")).unwrap().ends_with("\noutcome=admitted\n"));
    }

    /// LD-31 under the locks: past the 2 newest admitted, a decided version's binary and `.partial` go; one whose
    /// lock another holds (an admission, a stage, a forget in flight) or whose record is undecided keeps both; the
    /// caller's own version (its lock held already) goes.
    #[test]
    fn prune_local_spares_versions_in_flight_or_undecided() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(dir.path().join("bridge"), None);
        let sig = || SignatureRow { outcome: "ok".into(), linux_sha256: Some("a".repeat(64)), linux_size: Some(9), at: "t".into(), ..SignatureRow::default() };
        for v in ["2.1.301", "2.1.302", "2.1.303", "2.1.304", "2.1.305", "2.1.306", "2.1.307"] {
            std::fs::create_dir_all(p.claude_bin_dir(v)).unwrap();
            std::fs::write(p.claude_bin(v), b"bin").unwrap();
            std::fs::write(p.claude_bin_dir(v).join(".partial"), b"part").unwrap();
            if v != "2.1.303" {
                Record::update(&p, v, |r| {
                    r.signature = Some(sig());
                    // 2.1.304: signed only (an admission running, or one that crashed).
                    if v != "2.1.304" {
                        r.admission = Some(AdmissionRow { outcome: if v == "2.1.302" { "failed" } else { "admitted" }.into(), step: (v == "2.1.302").then(|| "docker".into()), at: "t".into(), ..AdmissionRow::default() });
                    }
                })
                .unwrap();
            }
        }
        // 2.1.305's admission (a --redo) runs in another process: its lock is held.
        let held = VersionLock::take(&p, "2.1.305").unwrap().expect("free");
        let both = |v: &str| (p.claude_bin(v).exists(), p.claude_bin_dir(v).join(".partial").exists());
        assert_eq!(local_doomed(&p, None).into_iter().map(|(v, _)| v).collect::<Vec<_>>(), ["2.1.301", "2.1.302"], "a dry look");
        assert_eq!(prune_local(&p, None), ["2.1.301", "2.1.302"]);
        assert_eq!((both("2.1.301"), both("2.1.302")), ((false, false), (false, false)), "decided, past the 2 newest admitted");
        for v in ["2.1.303", "2.1.304", "2.1.305", "2.1.306", "2.1.307"] {
            assert_eq!(both(v), (true, true), "{v}: no record, signed only, its lock held, or one of the 2 newest");
        }
        // The caller's own version (its lock held by the caller) goes; another's held lock still keeps its files.
        assert_eq!(prune_local(&p, Some("2.1.305")), ["2.1.305"]);
        drop(held);
        assert_eq!(both("2.1.305"), (false, false));
    }
}
