//! `/validate`: the platform calls it on a fresh VM restored from the image
//! snapshot; any failure fails the image build, so a bad image never becomes
//! ACTIVE. Only before `/run`: once a `/run` was accepted the hook answers
//! 409 without running any check (`hooks`). The build VM never gets `/run`,
//! and the agent exists only after it; V3 and V4 read and walk paths under
//! `--home`, which the agent owns, as root. Every call evaluates every check
//! (no cached verdict):
//!
//! - V1 ready: listeners bound and the claude probe cached (`/ready`'s rule).
//! - V2 version: a FRESH `claude --version` prints exactly the version line
//!   of `/etc/ai-env/claude.lock`. Skipped (and failed) while V1 fails, so a
//!   not-ready VM gets its 503 at once instead of after a probe of up to
//!   30 s; V3–V5 still run and are named.
//! - V3 settings: `/etc/claude-code/managed-settings.json` and
//!   `<home>/.claude/settings.json` parse as JSON objects and are readable by
//!   the agent's uid:gid (claude refuses to start on an unreadable or
//!   unparseable managed-settings file), and the managed file carries every
//!   value of `wire::managed::MANAGED_HARDENING` (D6).
//! - V4 hygiene: nothing from the build leaked into the snapshot every clone
//!   shares: no `/root/.claude*`, no legacy `<home>/.claude/.config.json`
//!   (it would take priority), `/etc/machine-id` absent or empty, no
//!   identity key (`userID`, `machineID`, …) and no project entry in either
//!   `.claude.json` (D5 bakes none), and nothing under `<home>/.claude`
//!   beyond the baked subset: the whole tree is walked without following
//!   links, every baked entry has its kind, and no symlink exists.
//! - V5 facts: logged only (boot report).
//! - V6 guard (S6, critic M2): the peer guard tested on this very VM, so a
//!   guard that would refuse the platform or admit the agent never becomes
//!   ACTIVE. Where the guard runs (root on Linux: the image) the hooks
//!   guard must be on: any other `--hook-source` fails (plan T6.6: the
//!   self-test fails when the guard is forced off). Native runs skip V6
//!   outside peer mode. Under `--hook-source peer`: (a) the guard must
//!   admit the `/validate` request's own socket — the platform's hook
//!   client: a local one needs a row whose inode is not 0 and whose uid is
//!   not the agent's (the platform measured local, 127.0.0.1, in S3–S5); a
//!   client from outside the VM (an address the VM does not hold, and no
//!   row of its own here) is admitted, so it passes with a note (it says
//!   nothing about the lookup, and refusing it would only block an image
//!   the guard runs correctly). (b) As the agent (`--uid`/`--gid`; only a
//!   root shim can drop to it), `curl` POSTs `/resume` on the hooks port at
//!   127.0.0.1 and at the first non-loopback IPv4 address of the VM (none:
//!   noted, and only the loopback POST runs); each must answer 403.
//!   `/resume` because it is harmless if a broken guard admits it (a clock
//!   report and a thaw of nothing). A missing curl, a timeout or any other
//!   status fails (fail closed). The refused `hook resume` lines
//!   (`peer_uid` the agent's) are the self-test's own: V6 names their
//!   `peer=` (curl's source address and port).
//!
//! Paths are resolved under `--fs-root` when set (native tests).
use crate::shim::health::ShimState;
use crate::shim::hooks::{HookSource, PREFIX};
use crate::shim::peer::{self, Peer, PeerFacts};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const LOCK: &str = "/etc/ai-env/claude.lock";
pub const MANAGED_SETTINGS: &str = "/etc/claude-code/managed-settings.json";

/// Keys claude generates per installation; a snapshot must not carry them
/// (every clone would share one identity).
pub const IDENTITY_KEYS: [&str; 5] = ["userID", "machineID", "summonSidKey", "remoteControlMachineId", "firstStartTime"];

/// What `<home>/.claude` may hold in the image (the enumerated subset of
/// image/MANIFEST), with its kind: `true` = a real directory, `false` = a
/// regular file.
pub const BAKED_ENTRIES: [(&str, bool); 6] = [("settings.json", false), ("CLAUDE.md", false), (".claude.json", false), ("agents", true), ("skills", true), ("commands", true)];

/// Regular files baked below the directories of [`BAKED_ENTRIES`], relative
/// to `<home>/.claude` (`skills/x/SKILL.md`). None in v0: the three
/// directories ship empty; a stage that bakes content lists it here and in
/// image/MANIFEST.
pub const BAKED_NESTED: [&str; 0] = [];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(id: &'static str, problems: Vec<String>, ok_detail: String) -> Check {
    if problems.is_empty() {
        Check { id, ok: true, detail: ok_detail }
    } else {
        Check { id, ok: false, detail: problems.join("; ") }
    }
}

/// Unix permission rule for one file: may `uid:gid` read (or, for a
/// directory, search) it? Root bypasses the mode bits.
#[must_use]
pub fn permits(owner: u32, group: u32, mode: u32, uid: u32, gid: u32, want_bits: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let bits = if owner == uid {
        (mode >> 6) & 7
    } else if group == gid {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want_bits == want_bits
}

/// Can `uid:gid` read `path` (a regular file), searching every directory
/// from `root` down? Symlinks are refused: the baked files are plain files.
pub fn readable_by(root: &Path, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let rel = path.strip_prefix(root).map_err(|_| format!("{} is outside {}", path.display(), root.display()))?;
    let mut dir = root.to_path_buf();
    for comp in rel.parent().into_iter().flat_map(Path::components) {
        dir.push(comp);
        let m = std::fs::symlink_metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if !m.is_dir() || !permits(m.uid(), m.gid(), m.mode(), uid, gid, 1) {
            return Err(format!("{} is not searchable by {uid}:{gid}", dir.display()));
        }
    }
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if !permits(m.uid(), m.gid(), m.mode(), uid, gid, 4) {
        return Err(format!("{} is not readable by {uid}:{gid} (mode {:o})", path.display(), m.mode() & 0o7777));
    }
    Ok(())
}

fn json_object(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(serde_json::Value::Object(m)) => Ok(m),
        Ok(_) => Err(format!("{} is not a JSON object", path.display())),
        Err(e) => Err(format!("{} does not parse: {e}", path.display())),
    }
}

/// `fresh` is `None` when the probe was skipped because V1 failed.
fn v2(state: &ShimState, fresh: Option<&Result<String, String>>) -> Check {
    let lock_path = state.at(Path::new(LOCK));
    let pin = std::fs::read_to_string(&lock_path).map_err(|e| format!("{}: {e}", lock_path.display())).and_then(|t| crate::wire::pin::parse_lock(&t));
    let mut problems = Vec::new();
    let mut ok = String::new();
    match (&pin, fresh) {
        (Err(e), _) => problems.push(format!("lock: {e}")),
        (_, None) => problems.push("skipped: not ready (no fresh claude --version until V1 holds)".into()),
        (_, Some(Err(e))) => problems.push(format!("claude --version: {e}")),
        (Ok(pin), Some(Ok(line))) if *line != pin.version_line() => problems.push(format!("claude prints {line:?}, the lock pins {:?}", pin.version_line())),
        (Ok(_), Some(Ok(line))) => ok = format!("{line} matches the lock"),
    }
    check("V2", problems, ok)
}

fn v3(state: &ShimState) -> Check {
    let root = state.opts.fs_root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let managed = state.at(Path::new(MANAGED_SETTINGS));
    let files = [managed.clone(), state.at(&state.opts.home.join(".claude/settings.json"))];
    let mut problems = Vec::new();
    for f in &files {
        let doc = match json_object(f) {
            Ok(m) => m,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        if *f == managed {
            for gap in crate::wire::managed::hardening_gaps(&serde_json::Value::Object(doc)) {
                problems.push(format!("{}: {gap} is missing or weakened (D6 hardening)", f.display()));
            }
        }
        if let Err(e) = readable_by(&root, f, state.opts.uid, state.opts.gid) {
            problems.push(e);
        }
    }
    check("V3", problems, format!("{} settings files parse and are readable by {}:{}; the managed hardening is in place", files.len(), state.opts.uid, state.opts.gid))
}

/// Every entry below `dir` (relative to `base`, `/`-joined), depth first,
/// never following a link: (relative path, file type).
fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, std::fs::FileType)>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        // DirEntry::file_type does not follow symlinks.
        let ft = e.file_type().map_err(|err| format!("{}: {err}", e.path().display()))?;
        let rel = e.path().strip_prefix(base).map_or_else(|_| e.path().display().to_string(), |p| p.to_string_lossy().to_string());
        out.push((rel, ft));
        if ft.is_dir() {
            walk(base, &e.path(), out)?;
        }
    }
    Ok(())
}

/// `<home>/.claude` holds exactly the baked subset: each top-level entry is
/// in [`BAKED_ENTRIES`] with its kind, nothing below the directories but
/// [`BAKED_NESTED`] (and the directories leading to it), and no symlink
/// anywhere. Problems name the relative paths.
fn baked_subset_problems(claude_dir: &Path) -> Vec<String> {
    let mut all = Vec::new();
    if let Err(e) = walk(claude_dir, claude_dir, &mut all) {
        return vec![e];
    }
    let (mut extra, mut links, mut kinds) = (Vec::new(), Vec::new(), Vec::new());
    for (rel, ft) in &all {
        if ft.is_symlink() {
            links.push(rel.clone());
            continue;
        }
        match rel.split_once('/') {
            None => match BAKED_ENTRIES.iter().find(|(name, _)| name == rel) {
                None => extra.push(rel.clone()),
                Some((_, true)) if !ft.is_dir() => kinds.push(format!("{rel} is not a directory")),
                Some((_, false)) if !ft.is_file() => kinds.push(format!("{rel} is not a regular file")),
                Some(_) => {}
            },
            Some(_) => {
                let allowed = if ft.is_dir() { BAKED_NESTED.iter().any(|n| n.starts_with(&format!("{rel}/"))) } else { ft.is_file() && BAKED_NESTED.contains(&rel.as_str()) };
                if !allowed {
                    extra.push(rel.clone());
                }
            }
        }
    }
    let mut problems = Vec::new();
    if !extra.is_empty() {
        problems.push(format!("unexpected entries in the claude config dir: {}", extra.join(", ")));
    }
    if !links.is_empty() {
        problems.push(format!("symlinks in the claude config dir: {}", links.join(", ")));
    }
    problems.extend(kinds.into_iter().map(|k| format!("in the claude config dir, {k}")));
    problems
}

fn v4(state: &ShimState) -> Check {
    let mut problems = Vec::new();
    let root_home = state.at(Path::new("/root"));
    if let Ok(entries) = std::fs::read_dir(&root_home) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(".claude") {
                problems.push(format!("/root/{name} exists (build-time claude state)"));
            }
        }
    }
    let claude_dir = state.at(&state.opts.home.join(".claude"));
    if claude_dir.join(".config.json").exists() {
        problems.push(".config.json exists in the claude config dir (it would take priority over .claude.json)".into());
    }
    match std::fs::read(state.at(Path::new("/etc/machine-id"))) {
        Ok(b) if !b.iter().all(u8::is_ascii_whitespace) => problems.push("/etc/machine-id is not empty (every clone would share it)".into()),
        _ => {}
    }
    for cfg in [claude_dir.join(".claude.json"), state.at(&state.opts.home.join(".claude.json"))] {
        if !cfg.exists() {
            continue;
        }
        match json_object(&cfg) {
            Ok(m) => {
                for k in IDENTITY_KEYS {
                    if m.contains_key(k) {
                        problems.push(format!("{} holds the identity key {k}", cfg.display()));
                    }
                }
                // D5: `projects` is absent or an empty object.
                if m.get("projects").is_some_and(|p| p.as_object().is_none_or(|o| !o.is_empty())) {
                    problems.push(format!("{} has project entries (v0 bakes none)", cfg.display()));
                }
            }
            Err(e) => problems.push(e),
        }
    }
    problems.extend(baked_subset_problems(&claude_dir));
    check("V4", problems, "no build-time state, no identity keys, no project entries, only the baked subset".into())
}

/// The agent's self-test client (the image installs curl; V6 fails without it).
pub const CURL: &str = "/usr/bin/curl";
/// One self-test request's budget (curl's own `-m 5` inside it).
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// V6 (a): why the guard would refuse the `/validate` request's own client
/// (the platform's), if it would. A client from outside the VM is admitted
/// without a lookup (the caller notes it).
#[must_use]
pub fn platform_row_problem(facts: Option<&PeerFacts>, agent_uid: u32) -> Option<String> {
    let Some(f) = facts else {
        return Some("the /validate request has no peer address".into());
    };
    if !f.local {
        return None;
    }
    match f.row {
        None => Some("no /proc/net/tcp row for the /validate request's own socket".into()),
        Some((_, r)) if r.inode == 0 => Some("the /validate request's socket shows inode 0 (orphaned)".into()),
        Some((_, r)) if r.uid == agent_uid => Some(format!("the /validate request's socket is owned by the agent uid {agent_uid}")),
        Some(_) => None,
    }
}

/// What curl prints for one agent POST (`-w`): the status, then its own
/// address and port — the `peer=` of the hook line the POST caused.
const CURL_OUT: &str = "%{http_code} %{local_ip}:%{local_port}";

/// V6 (b): curl's output (`CURL_OUT`) for one agent POST; only 403 passes.
/// Either way the result names the hook line's `peer=` when curl connected.
pub fn curl_verdict(addr: IpAddr, out: &std::process::Output) -> Result<String, String> {
    let text = String::from_utf8_lossy(&out.stdout);
    let (code, from) = text.trim().split_once(' ').unwrap_or((text.trim(), ""));
    let line = from.parse::<SocketAddr>().ok().filter(|a| a.port() != 0).map_or(String::new(), |a| format!(" (its hook line: peer={a})"));
    if code == "403" {
        return Ok(format!("the agent's POST /resume via {addr} got 403{line}"));
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let first = err.lines().next().unwrap_or("").chars().take(200).collect::<String>();
    let note = if first.is_empty() { String::new() } else { format!(": {}", crate::wire::redact::scrub(&first)) };
    Err(format!("the agent's POST /resume via {addr} got {} ({}){line}{note}", if code.is_empty() { "no status" } else { code }, out.status))
}

/// One POST `/resume` as the agent uid to `addr:port`, environment cleared.
async fn post_resume_as_agent(state: &ShimState, addr: IpAddr, port: u16) -> Result<String, String> {
    let url = format!("http://{}{PREFIX}/resume", SocketAddr::new(addr, port));
    let mut cmd = tokio::process::Command::new(CURL);
    cmd.args(["-sS", "-m", "5", "-o", "/dev/null", "-w", CURL_OUT, "-X", "POST", url.as_str()])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .uid(state.opts.uid)
        .gid(state.opts.gid)
        .kill_on_drop(true);
    let out = tokio::time::timeout(SELF_TEST_TIMEOUT, cmd.output())
        .await
        .map_err(|_| format!("the agent's POST /resume via {addr} did not finish within {} s", SELF_TEST_TIMEOUT.as_secs()))?
        .map_err(|e| format!("cannot run {CURL} as {}:{}: {e}", state.opts.uid, state.opts.gid))?;
    curl_verdict(addr, &out)
}

/// The first non-loopback IPv4 address of this VM (link-local included: it
/// may be the VM's only one).
fn vm_ipv4(addrs: &[IpAddr]) -> Option<IpAddr> {
    addrs.iter().copied().find(|a| matches!(a, IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified()))
}

async fn v6(state: &ShimState, conn: Option<Peer>) -> Check {
    v6_on(state, conn, peer::guard_host()).await
}

/// V6 where `guard_host` tells whether the guard runs here (root on Linux).
async fn v6_on(state: &ShimState, conn: Option<Peer>, guard_host: bool) -> Check {
    let source = state.opts.hook_source;
    if source != HookSource::Peer {
        if guard_host {
            return Check { id: "V6", ok: false, detail: format!("the hooks guard is off (--hook-source {}): the agent could drive the runtime hooks; the image must run --hook-source peer", source.name()) };
        }
        return Check { id: "V6", ok: true, detail: format!("skipped: hook source {}", source.name()) };
    }
    let facts = conn.map(|c| peer::facts(&c));
    let mut problems: Vec<String> = platform_row_problem(facts.as_ref(), state.opts.uid).into_iter().collect();
    let mut notes = Vec::new();
    if !nix::unistd::geteuid().is_root() {
        problems.push(format!("needs root: the self-test runs curl as the agent uid {}", state.opts.uid));
    } else if let Some(ports) = state.ports.get() {
        let mut targets = vec![IpAddr::from([127, 0, 0, 1])];
        match peer::local_addrs() {
            Ok(addrs) => match vm_ipv4(&addrs) {
                Some(a) => targets.push(a),
                None => notes.push("no non-loopback address".to_string()),
            },
            Err(e) => problems.push(format!("cannot read this VM's addresses: {e}")),
        }
        for addr in targets {
            match post_resume_as_agent(state, addr, ports.hooks).await {
                Ok(note) => notes.push(note),
                Err(e) => problems.push(e),
            }
        }
    } else {
        problems.push("the hooks port is not known yet (listeners not bound)".into());
    }
    let row = match facts {
        Some(PeerFacts { local: false, .. }) => "the platform's /validate request came from outside this VM (admitted without a lookup); ".to_string(),
        _ => facts.and_then(|f| f.row).map_or(String::new(), |(_, r)| format!("the platform's /validate socket is uid {} inode {}; ", r.uid, r.inode)),
    };
    check("V6", problems, format!("{row}{}", notes.join("; ")))
}

/// Run V1–V6; the caller holds the single-flight lock and found no `/run`
/// record. While V1 fails the fresh probe is skipped (V2 fails as skipped),
/// so the 503 is immediate.
/// `conn` is the `/validate` request's own connection (V6).
pub async fn run_checks(state: &ShimState, conn: Option<Peer>) -> Vec<Check> {
    let v1 = match state.ready() {
        Ok(()) => Check { id: "V1", ok: true, detail: "listeners bound, claude probed".into() },
        Err(waiting) => Check { id: "V1", ok: false, detail: format!("not ready: waiting for {}", waiting.join(", ")) },
    };
    let fresh = if v1.ok { Some(state.probe_fresh().await) } else { None };
    let facts = serde_json::to_string(&crate::shim::sys::boot_report(state.sys.as_ref())).unwrap_or_default();
    let v6 = v6(state, conn).await;
    vec![v1, v2(state, fresh.as_ref()), v3(state), v4(state), Check { id: "V5", ok: true, detail: facts }, v6]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::peer::TcpRow;

    #[test]
    fn permission_bits() {
        assert!(permits(1000, 1000, 0o600, 1000, 1000, 4), "owner read");
        assert!(!permits(0, 0, 0o600, 1000, 1000, 4), "root-owned 0600 is closed to the agent");
        assert!(permits(0, 0, 0o644, 1000, 1000, 4), "world-readable");
        assert!(permits(0, 1000, 0o640, 1000, 1000, 4), "group-readable");
        assert!(!permits(1000, 0, 0o044, 1000, 1000, 4), "the owner class wins even when others may read");
        assert!(permits(0, 0, 0o000, 0, 0, 4), "root bypasses");
        assert!(permits(1000, 1000, 0o700, 1000, 1000, 1), "search");
        assert!(!permits(0, 0, 0o700, 1000, 1000, 1));
    }

    #[test]
    fn readable_by_walks_the_directories() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let (uid, gid) = (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw());
        let f = t.path().join("a/b/f.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "{}").unwrap();
        assert_eq!(readable_by(t.path(), &f, uid, gid), Ok(()));
        if uid != 0 {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o200)).unwrap();
            assert!(readable_by(t.path(), &f, uid, gid).unwrap_err().contains("not readable"));
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::set_permissions(t.path().join("a"), std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(readable_by(t.path(), &f, uid, gid).unwrap_err().contains("not searchable"));
            std::fs::set_permissions(t.path().join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let link = t.path().join("a/b/link.json");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(readable_by(t.path(), &link, uid, gid).unwrap_err().contains("not a regular file"));
        assert!(readable_by(t.path(), Path::new("/etc/hosts"), uid, gid).unwrap_err().contains("outside"));
    }

    #[test]
    fn the_guard_must_admit_the_platforms_own_validate_socket() {
        let row = |uid, inode| Some((4, TcpRow { local: "127.0.0.1:40000".parse().unwrap(), remote: "127.0.0.1:9000".parse().unwrap(), state: 1, uid, inode }));
        assert_eq!(platform_row_problem(Some(&PeerFacts { local: true, row: row(0, 77) }), 1000), None, "root with a live socket: the platform");
        assert_eq!(platform_row_problem(Some(&PeerFacts { local: false, row: None }), 1000), None, "from outside the VM: admitted without a lookup");
        let cases = [
            (None, "no peer address"),
            (Some(PeerFacts { local: true, row: None }), "no /proc/net/tcp row"),
            (Some(PeerFacts { local: true, row: row(0, 0) }), "inode 0"),
            (Some(PeerFacts { local: true, row: row(1000, 77) }), "agent uid 1000"),
        ];
        for (facts, want) in cases {
            let p = platform_row_problem(facts.as_ref(), 1000).unwrap_or_else(|| panic!("{facts:?} must fail"));
            assert!(p.contains(want), "{p}");
        }
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output { status: std::process::ExitStatus::from_raw(code << 8), stdout: stdout.as_bytes().to_vec(), stderr: stderr.as_bytes().to_vec() }
    }

    /// Only a 403 passes; the result names the hook line the POST caused
    /// (`peer=` is curl's own address), so the self-test's refused lines
    /// can be told from anything else in the log.
    #[test]
    fn only_a_403_passes_the_agent_post() {
        let lo = IpAddr::from([127, 0, 0, 1]);
        assert_eq!(curl_verdict(lo, &output(0, "403 127.0.0.1:41234", "")), Ok("the agent's POST /resume via 127.0.0.1 got 403 (its hook line: peer=127.0.0.1:41234)".into()));
        let vm = IpAddr::from([10, 0, 0, 5]);
        assert!(curl_verdict(vm, &output(0, "403 10.0.0.5:41236", "")).is_ok_and(|n| n.ends_with("via 10.0.0.5 got 403 (its hook line: peer=10.0.0.5:41236)")));
        for (out, want) in [
            (output(0, "200 127.0.0.1:41235", ""), "got 200 (exit status: 0) (its hook line: peer=127.0.0.1:41235)"),
            (output(0, "401 127.0.0.1:41237", ""), "got 401"),
            (output(7, "000 :0", "curl: (7) Failed to connect"), "got 000 (exit status: 7): curl: (7) Failed to connect"),
            (output(28, "", "curl: (28) Operation timed out"), "no status"),
        ] {
            let e = curl_verdict(lo, &out).unwrap_err();
            assert!(e.contains(want) && e.contains("via 127.0.0.1"), "{e}");
        }
    }

    #[test]
    fn the_vm_address_is_the_first_non_loopback_ipv4() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(vm_ipv4(&[a("127.0.0.1"), a("::1"), a("10.0.0.5"), a("10.0.0.6")]), Some(a("10.0.0.5")));
        assert_eq!(vm_ipv4(&[a("127.0.0.1"), a("169.254.0.2")]), Some(a("169.254.0.2")));
        assert_eq!(vm_ipv4(&[a("127.0.0.1"), a("fe80::1"), a("0.0.0.0")]), None);
    }

    /// Where the guard runs (root on Linux: the image), V6 fails unless the
    /// hooks guard is on, so an image built with it forced off never becomes
    /// ACTIVE; native runs skip it outside peer mode. Natively (not root, no
    /// `/proc/net/tcp` on the Mac) peer mode fails closed.
    #[tokio::test]
    async fn v6_fails_with_the_guard_off_on_a_guard_host_and_skips_natively() {
        use crate::shim::health::{ProbeSpec, ShimOpts};
        use std::sync::Arc;
        let mk = |source| ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts { hook_source: source, ..ShimOpts::default() }, ProbeSpec::default(), Arc::new(crate::shim::sys::RealSys));
        for source in [HookSource::Log, HookSource::Enforce] {
            let c = v6_on(&mk(source), None, true).await;
            assert!(!c.ok && c.detail.starts_with(&format!("the hooks guard is off (--hook-source {})", source.name())), "{c:?}");
            let c = v6_on(&mk(source), None, false).await;
            assert!(c.ok && c.detail == format!("skipped: hook source {}", source.name()), "{c:?}");
        }
        assert_eq!(v6(&mk(HookSource::Log), None).await.ok, !peer::guard_host(), "v6 asks the host");
        if nix::unistd::geteuid().is_root() {
            eprintln!("as root the self-test would run curl: covered in Docker");
            return;
        }
        let c = v6(&mk(HookSource::Peer), None).await;
        assert!(!c.ok, "{c:?}");
        assert!(c.detail.contains("no peer address") && c.detail.contains("needs root"), "{c:?}");
    }
}
