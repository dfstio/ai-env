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
//! non-zero exit.
use super::release::{self, LabProgram, ReleaseError};
use super::{AdmissionRow, DownloadRow, Phase, Record, SignatureRow, ADMIT_MAKE_BOUND, CLAUDE_GC_KEEP_LOCAL};
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

/// The log's last non-empty line, scrubbed, at most [`DOCKER_LINE_MAX`] characters.
fn last_line(log: &Path) -> String {
    let text = std::fs::read(log).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let line = text.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("(no output)");
    crate::wire::redact::scrub(line).chars().take(DOCKER_LINE_MAX).collect()
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
    let _ = cfg;
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
    // Step 3: a decided record stands without --redo.
    if let Some(record) = super::Record::load(paths, version)? {
        if !opts.redo {
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
            super::Record::update(paths, version, |r| r.admission = Some(failed("download", None, None)))?;
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
        super::Record::update(paths, version, |r| r.admission = Some(failed("markers", Some(markers.clone()), None)))?;
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
    let docker_line = last_line(&log);
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
        docker_image: docker_image.clone(),
        ai_env: env!("CARGO_PKG_VERSION").into(),
        auto: opts.auto,
        at: at(),
    };
    // Step 8: recorded, audited; the local binaries past the 2 newest admitted go.
    let record = super::Record::update(paths, version, |r| r.admission = Some(row))?;
    let mut extra = vec![("sha256", sha256.clone()), ("signer", verified.signer.clone()), ("markers", "ok".to_string())];
    if let Some(id) = &docker_image {
        extra.push(("docker_image", id.clone()));
    }
    if !passed {
        extra.insert(0, ("step", "docker".to_string()));
    }
    audit(paths, version, if passed { "admitted" } else { "failed" }, started, opts.auto, &extra);
    end(&mut lock, if passed { "admitted" } else { "failed(docker)" });
    if passed {
        for v in prune_local(paths, Some(version)) {
            tracing::info!(version = %v, "its local claude binary removed (this Mac keeps the {CLAUDE_GC_KEEP_LOCAL} newest admitted)");
        }
        Ok(record)
    } else {
        Err(CliError::Msg(format!("claude {version}: its Docker tests failed: {docker_line} (the log: {}): not admitted; fix it, then ai-env claude admit {version} --redo", log.display())))
    }
}

/// The first 12 hex digits of a sha256.
fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// ` (<why>)` of a failed record: the signature's word, the markers' or the Docker line.
/// A failed admission's line: its step and why, and the `--redo` that admits it again (`admit` without `--redo`
/// shows it, exit 1; a stage refuses the version with it, exit 9).
pub(crate) fn failed_line(version: &str, step: &str, record: &Record) -> String {
    format!("claude {version}: admission failed at {step}{}: fix it, then ai-env claude admit {version} --redo", failed_why(record))
}

fn failed_why(record: &Record) -> String {
    let why = match (&record.signature, &record.admission) {
        (Some(s), _) if s.outcome == "failed" => s.why.clone(),
        (_, Some(a)) => a.markers.clone().filter(|m| m.starts_with("missing:")).or_else(|| a.docker.clone()),
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
/// record as it stands.
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
        assert!(VersionLock::take(&p, "2.1.308").unwrap().is_some(), "released");
        // Handed over (D5): the other descriptor of the open file (the child's fd 3) keeps the lock after this
        // process's copy is dropped (a drop never unlocks); it goes with the last one.
        let lock = VersionLock::take(&p, "2.1.308").unwrap().expect("free");
        // SAFETY: dup(2) of the lock's open descriptor; the copy is closed below.
        let child = unsafe { libc::dup(std::os::fd::AsRawFd::as_raw_fd(&lock)) };
        assert!(child >= 0);
        drop(lock);
        assert!(VersionLock::take(&p, "2.1.308").unwrap().is_none(), "still held through the child's descriptor");
        // SAFETY: close(2) of the descriptor dup'ed above, once.
        unsafe { libc::close(child) };
        assert!(VersionLock::take(&p, "2.1.308").unwrap().is_some(), "released with the last descriptor");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(p.claude_lock("2.1.308")).unwrap().permissions().mode() & 0o777, 0o600);
        // --auto: an exit without an outcome (an early `?`, a panic) writes `error(<step>)` from the drop; one
        // with an outcome is left as it is.
        let mut auto = VersionLock::take(&p, "2.1.310").unwrap().expect("free");
        auto.auto_step = Some("signature");
        drop(auto);
        let text = std::fs::read_to_string(p.claude_lock("2.1.310")).unwrap();
        assert!(text.starts_with("finished_at=") && text.ends_with("\noutcome=error(signature)\n"), "{text}");
        let mut auto = VersionLock::take(&p, "2.1.310").unwrap().expect("free");
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
