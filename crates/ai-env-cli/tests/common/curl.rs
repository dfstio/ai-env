//! S9's fake curl (`tests/fakes/s3-curl.sh`, plans/s9-contracts.md §8.2):
//! its cached master, [`install_fake_curl`] (a hard link and its knobs file,
//! as the fake git's), and its log read back ([`curl_calls`]: who ran it,
//! the descriptors it started with, the configuration it got on fd 3, its
//! argv), and [`without_stray_fds`] for a test that runs it itself.
//! Self-contained (std, `libc`, `sha2` and `hex`, never a `super::` path):
//! `tests/common/mod.rs` declares it (`pub use curl::*`), and the shim-only
//! `tests/shim_local.rs` includes the same file by `#[path]`, where `mod
//! common` cannot compile.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The fake curl, hard-linked where a test's shim runs it (`ShimOpts.curl`).
pub const FAKE_CURL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/s3-curl.sh");

/// The fake's cached master: one 0755 copy per content under
/// `CARGO_TARGET_TMPDIR` (macOS assesses each new executable's first exec;
/// a hard link shares the inode).
fn curl_master() -> &'static Path {
    static MASTER: OnceLock<PathBuf> = OnceLock::new();
    MASTER.get_or_init(|| {
        use sha2::Digest as _;
        use std::os::unix::fs::PermissionsExt as _;
        let bytes = std::fs::read(FAKE_CURL).unwrap_or_else(|e| panic!("read {FAKE_CURL}: {e}"));
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-s3-curl");
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
        let path = dir.join(format!("curl-{}", &digest[..16]));
        if !path.exists() {
            let tmp = dir.join(format!(".curl-{}.{}.tmp", &digest[..16], std::process::id()));
            std::fs::write(&tmp, &bytes).expect("write the fake curl");
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod the fake curl");
            std::fs::rename(&tmp, &path).expect("install the fake curl");
        }
        path
    })
}

/// `vars` as the knobs file the fake sources: one `export NAME='value'`
/// line each, in order (a later line wins), the value single-quoted.
fn write_curl_knobs(path: &Path, vars: &[(&str, &str)]) {
    let mut text = String::new();
    for (name, value) in vars {
        let ident = name.bytes().next().is_some_and(|b| b == b'_' || b.is_ascii_alphabetic()) && name.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric());
        assert!(ident, "not a shell variable name: {name:?}");
        text.push_str(&format!("export {name}='{}'\n", value.replace('\'', r"'\''")));
    }
    std::fs::write(path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Install the fake curl at `dest`: a hard link of its cached master (a
/// copy on another filesystem; an existing `dest` is kept, never written
/// over) and beside it `<dest>.knobs`: `S3CURL_LOG` at `log`, then `knobs`
/// (`S3CURL_REAL`, `S3CURL_FAIL`, `S3CURL_STATUS`, …): the shim clears
/// curl's environment, so they reach it only through this file. Read the
/// calls back with [`curl_calls`].
pub fn install_fake_curl(dest: &Path, log: &Path, knobs: &[(&str, &str)]) {
    if std::fs::symlink_metadata(dest).is_err() && std::fs::hard_link(curl_master(), dest).is_err() {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::copy(FAKE_CURL, dest).unwrap_or_else(|e| panic!("copy {FAKE_CURL}: {e}"));
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755)).expect("chmod the fake curl");
    }
    let log = log.display().to_string();
    let mut vars = vec![("S3CURL_LOG", log.as_str())];
    vars.extend_from_slice(knobs);
    let mut path = dest.as_os_str().to_owned();
    path.push(".knobs");
    write_curl_knobs(Path::new(&path), &vars);
}

/// `cmd`'s child starts without a descriptor past stderr it did not ask
/// for: before its exec, every fd from 3 (up to the soft `RLIMIT_NOFILE`, at
/// most 4096) that lacks close-on-exec is closed. macOS's std makes a pipe
/// and marks it close-on-exec in two steps, so a spawn on another test's
/// thread in between hands this child that pipe; the fake curl logs the
/// descriptors it starts with (S9 phase 4: the phase-0 flake of
/// `the_fake_curl_logs_its_fd_3_config_and_plays_s3`). What std opens for
/// the child itself is close-on-exec and stays: its stdio is in place by
/// then, and its error pipe closes at the exec.
pub fn without_stray_fds(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit fills the struct on the stack.
    let soft = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 { rl.rlim_cur.min(4096) } else { 4096 };
    let end = libc::c_int::try_from(soft).unwrap_or(4096);
    // SAFETY: fcntl(2) and close(2) are async-signal-safe, and the closure allocates nothing between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            for fd in 3..end {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
}

/// One call the fake curl logged ([`curl_calls`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlCall {
    /// Who ran it (`id -u`).
    pub uid: u32,
    /// The descriptors from 3 to 254 open when it started.
    pub fds: Vec<u32>,
    /// Its configuration, as it came on fd 3.
    pub config: String,
    /// Its arguments, as given.
    pub args: Vec<String>,
}

impl CurlCall {
    /// The values of the configuration's `name = "…"` lines (an unquoted value as it is), in order; `""` for a bare `name`.
    #[must_use]
    pub fn conf(&self, name: &str) -> Vec<String> {
        self.config
            .lines()
            .filter_map(|line| {
                if line == name {
                    return Some(String::new());
                }
                let value = line.strip_prefix(name)?.strip_prefix(" = ")?;
                Some(value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value).to_string())
            })
            .collect()
    }
}

/// The fake's `%25`, `%09` and `%0A` back to `%`, tab and newline.
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let (c, len) = match rest.get(at..at + 3) {
            Some("%25") => ('%', 3),
            Some("%09") => ('\t', 3),
            Some("%0A") => ('\n', 3),
            _ => ('%', 1),
        };
        out.push(c);
        rest = &rest[at + len..];
    }
    out.push_str(rest);
    out
}

/// Every call the fake curl logged to `log`, in order (none when it is absent).
#[must_use]
pub fn curl_calls(log: &Path) -> Vec<CurlCall> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let mut field = |key: &str| fields.next().and_then(|f| f.strip_prefix(key)).unwrap_or_else(|| panic!("fake curl log: {key} expected in {line:?}")).to_string();
            let uid = field("uid=").parse().unwrap_or_else(|_| panic!("fake curl log: a uid in {line:?}"));
            let fds = field("fds=");
            let fds = if fds == "-" { Vec::new() } else { fds.split(',').map(|n| n.parse().unwrap_or_else(|_| panic!("fake curl log: fd {n:?}"))).collect() };
            let config = unescape(&field("config="));
            CurlCall { uid, fds, config, args: fields.map(unescape).collect() }
        })
        .collect()
}

/// S11: the fake claude (`tests/fakes/claude-v2.sh`), whose bytes a staged
/// claude carries ([`fake_claude_bytes`]).
pub const FAKE_CLAUDE_V2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude-v2.sh");

/// claude-v2.sh's bytes with lines after its first: `FAKE_VERSION_PINNED='<version>'`, `FAKE_KNOBS_FILE='<path>'`
/// (when given) and `NAME='value'` per default, each exported: a staged copy that reports `version`, reads the rig's
/// knobs, and (say) dies before its init. Its sha256 is what a test stages.
#[must_use]
pub fn fake_claude_bytes(version: &str, knobs_file: Option<&Path>, defaults: &[(&str, &str)]) -> Vec<u8> {
    let script = std::fs::read(FAKE_CLAUDE_V2).unwrap_or_else(|e| panic!("read {FAKE_CLAUDE_V2}: {e}"));
    let first = script.iter().position(|b| *b == b'\n').map_or(script.len(), |at| at + 1);
    let knobs = knobs_file.map(|p| p.display().to_string());
    let mut vars: Vec<(&str, &str)> = vec![("FAKE_VERSION_PINNED", version)];
    if let Some(path) = knobs.as_deref() {
        vars.push(("FAKE_KNOBS_FILE", path));
    }
    vars.extend_from_slice(defaults);
    let mut out = script[..first].to_vec();
    for (name, value) in vars {
        let ident = name.bytes().next().is_some_and(|b| b == b'_' || b.is_ascii_alphabetic()) && name.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric());
        assert!(ident, "not a shell variable name: {name:?}");
        out.extend_from_slice(format!("export {name}='{}'\n", value.replace('\'', r"'\''")).as_bytes());
    }
    out.extend_from_slice(&script[first..]);
    out
}
