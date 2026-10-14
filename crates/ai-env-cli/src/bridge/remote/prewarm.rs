//! The `auth status` prewarm (S8 §11), std only: run for exactly `auth
//! status --json` in remote mode under the roots, with
//! `[vm].prewarm_on_auth_status` not `never`, the newest `touchid-gui` row
//! `prompted` and the workspace's warm lock free, the wrapper starts the
//! sibling `ai-env vm warm <cwd> --prewarm` detached (a double fork, setsid,
//! stdio on `/dev/null`, the lock's fd kept, no shell, no `PATH` lookup)
//! before it execs the real binary. Built in S8 wave 1 (W2).
//!
//! Every condition is a local file read (a few ms, no runtime, no SDK, no
//! TLS), so `auth status` is never delayed: the wrapper waits for two forks,
//! never for the sibling's exec. In order: the argv and the mode; a usable
//! `bridge.toml` (`[wrapper].mode`, `[vm]`); the cwd under the roots; the
//! setting (`auto`, `always`; `never` skips); the newest `touchid-gui` probe
//! row `prompted` (the Touch ID dialog reaches a detached process: S7's
//! probe); then what a chat there would do, in every setting: the cwd in a
//! git work tree (`not_git`: a session refuses any other at its P0, D6),
//! no `AI_ENV_BRIDGE_VM` pin (`pinned`: the chats take that VM, never the
//! one a warm would), `[vm].reuse_per_workspace` on (`reuse_off`: no chat
//! reuses a warmed VM); for `auto` only, the workspace's VM rows (a row
//! SELECT_VM would reuse for the chat skips it, `token_held` when a
//! running one holds the sealed token: an `auto` prewarm is for a cold
//! start, and costs its own Touch ID under D1; `always` warms and seeds
//! whatever they say); the warm lock
//! taken without waiting (a prewarm running skips, one that finished within
//! [`COOLDOWN`] too); the sibling next to the wrapper (only on `PATH`, or
//! missing: one stderr note, no prewarm). The lock's open file goes to the
//! prewarm on fd 3, at its first byte, and stays locked for its life: the
//! wrapper never unlocks it, its own copies close at its exec. The census
//! start row records what happened ([`Prewarm::census_part`]); a spawn is
//! audited `prewarm`. The sibling's `vm warm --prewarm` judges the
//! workspace again (git itself, the scans) and refuses before its Touch ID.
use crate::bridge::config::{BridgeConfig, Paths, PrewarmMode};
use crate::bridge::egress::ExpectedEcho;
use crate::bridge::route::{cwd_under_roots, Loaded, Mode};
use crate::bridge::sibling::{find_sibling, Sibling, INSTALL_HINT};
use crate::bridge::vm::registry::{self, RowStatus};
use crate::bridge::vm::run::{self, Egress, RunFlags, RunPlan};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

/// The one argv that asks for a prewarm: Cursor's `auth status` probe.
pub const AUTH_STATUS: [&str; 3] = ["auth", "status", "--json"];

/// The probe whose newest verdict must be [`PROMPTED`].
pub const TOUCHID_PROBE: &str = "touchid-gui";

/// `touchid-gui`'s verdict when the Touch ID dialog reaches a detached process.
pub const PROMPTED: &str = "prompted";

/// A prewarm that finished this recently is not started again (a reload's
/// burst of `auth status` costs one Touch ID, not one each).
pub const COOLDOWN: Duration = Duration::from_secs(120);

/// The sibling and its arguments: `ai-env vm warm <cwd> --prewarm`.
const SIBLING: &str = "ai-env";

/// Every word of [`Prewarm::Skipped`].
pub const SKIP_WORDS: [&str; 14] = ["unconfigured", "config", "cwd", "outside_roots", "never", "touchid_gui", "not_git", "pinned", "reuse_off", "token_held", "vm_exists", "warming", "recent", "no_sibling"];

/// What [`maybe_prewarm`] did, for the census start row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prewarm {
    /// `vm warm --prewarm` was started, detached: its pid.
    Spawned(u32),
    /// No prewarm, and why: one of [`SKIP_WORDS`], or `spawn_failed`.
    Skipped(&'static str),
}

impl Prewarm {
    /// `prewarm:spawned(<pid>)` or `prewarm:skipped(<why>)` (`remote::census_part::PREWARM`).
    #[must_use]
    pub fn census_part(&self) -> String {
        let part = crate::bridge::remote::census_part::PREWARM;
        match self {
            Prewarm::Spawned(pid) => format!("{part}:spawned({pid})"),
            Prewarm::Skipped(why) => format!("{part}:skipped({why})"),
        }
    }
}

/// The prewarm for one wrapper invocation (the module doc): `None` when it
/// does not apply (any argv but [`AUTH_STATUS`], any mode but remote), else
/// what happened. Prints at most one stderr line (`ai-env-claude:`), for a
/// sibling missing or only on `PATH`.
#[must_use]
pub fn maybe_prewarm(loaded: &Loaded, mode: Mode, args: &[String], cwd: Option<&Path>) -> Option<Prewarm> {
    if mode != Mode::Remote || args != AUTH_STATUS {
        return None;
    }
    let (Some(paths), Some(cfg)) = (&loaded.paths, &loaded.cfg) else {
        return Some(Prewarm::Skipped("unconfigured"));
    };
    let Some(cwd) = cwd.and_then(|c| std::fs::canonicalize(c).ok()) else {
        return Some(Prewarm::Skipped("cwd"));
    };
    let pinned = std::env::var_os(crate::bridge::remote::PIN_KNOB).is_some_and(|v| !v.is_empty());
    let wanted = match decide(paths, cfg, &cwd, pinned) {
        Ok(setting) => setting,
        Err(why) => return Some(Prewarm::Skipped(why)),
    };
    let Ok(slug) = crate::wire::slug::project_dir_name(&cwd) else {
        return Some(Prewarm::Skipped("cwd"));
    };
    let lock = match warm_lock(paths, &slug) {
        Ok(lock) => lock,
        Err(why) => return Some(Prewarm::Skipped(why)),
    };
    let program = match find_sibling(SIBLING) {
        Sibling::Next(p) => p,
        Sibling::PathOnly(p) => {
            crate::bridge::voice::line(&format!("{SIBLING} is only on PATH ({}), not next to ai-env-claude: no prewarm ({INSTALL_HINT})", p.display()));
            return Some(Prewarm::Skipped("no_sibling"));
        }
        Sibling::Missing => {
            crate::bridge::voice::line(&format!("{SIBLING} is not next to ai-env-claude: no prewarm ({INSTALL_HINT})"));
            return Some(Prewarm::Skipped("no_sibling"));
        }
    };
    match spawn_detached(&program, &cwd, &lock) {
        Ok(pid) => {
            let detail = [("workspace", cwd.display().to_string()), ("pid", pid.to_string()), ("setting", wanted.name().to_string())];
            // Unsynced: `auth status` waits for this row, and its F_FULLFSYNC (about 5 ms) put it past T1.2's 10 ms.
            if let Err(e) = crate::bridge::audit::append_unsynced(&paths.audit(), &crate::bridge::audit::AuditRow::new(crate::bridge::remote::audit_event::PREWARM, None, crate::bridge::audit::detail(&detail))) {
                tracing::warn!("audit prewarm: {e}");
            }
            Some(Prewarm::Spawned(pid))
        }
        Err(e) => {
            tracing::warn!("prewarm: {e}");
            Some(Prewarm::Skipped("spawn_failed"))
        }
    }
}

/// The conditions read from files (the module doc): the setting that holds,
/// or the word of the first that does not. `pinned`: `AI_ENV_BRIDGE_VM` is
/// set in the wrapper's environment (Cursor's).
fn decide(paths: &Paths, cfg: &BridgeConfig, cwd: &Path, pinned: bool) -> Result<PrewarmMode, &'static str> {
    if cfg.wrapper.validate().is_err() || cfg.vm.validate().is_err() {
        return Err("config");
    }
    if !cwd_under_roots(cwd, &cfg.roots()) {
        return Err("outside_roots");
    }
    let setting = cfg.vm.prewarm_mode().map_err(|_| "config")?;
    if setting == PrewarmMode::Never {
        return Err("never");
    }
    if newest_verdict(paths, TOUCHID_PROBE).as_deref() != Some(PROMPTED) {
        return Err("touchid_gui");
    }
    // A VM no chat would use is never warmed, in any setting.
    if !in_git_work_tree(cwd, &cfg.roots()) {
        return Err("not_git");
    }
    if pinned {
        return Err("pinned");
    }
    // The chat's own plan (its P0's: vpc egress, the workspace routes required), as SELECT_VM reads it.
    let flags = RunFlags { workspace: Some(cwd.to_path_buf()), egress: Some(Egress::Vpc), purpose: "session", wait: true, ..RunFlags::default() };
    let mut plan = RunPlan::from_cfg(cfg, &flags).map_err(|_| "config")?;
    plan.workspace_cap = true;
    if !plan.reuse {
        return Err("reuse_off");
    }
    let wanted = ExpectedEcho::for_plan(plan.egress, &plan.egress_connectors).ok_or("config")?;
    let key = plan.workspace.as_ref().map(|(p, _)| run::workspace_key(p)).ok_or("cwd")?;
    let versions = selected_versions(paths, &plan);
    let now = crate::wire::time::unix_now();
    let rows = registry::list_rows(paths).map_err(|_| "config")?;
    // SELECT_VM's own filter (`run::reuse_candidate`) at the version it would resolve.
    let reusable: Vec<_> = rows
        .iter()
        .filter(|r| match versions.as_slice() {
            [] => run::reuse_candidate(r, &plan, &wanted, &key, None, None, now),
            known => known.iter().any(|v| run::reuse_candidate(r, &plan, &wanted, &key, Some(v), None, now)),
        })
        .collect();
    // `auto` is for a cold start (plan §11); `always` warms (and seeds) whatever the rows say.
    if setting == PrewarmMode::Auto && !reusable.is_empty() {
        // A suspend empties the shim's cache: only a running row that names this seal holds it.
        let sealed = crate::bridge::agent::credential::seal_tag(&paths.setup_token_env());
        let held = sealed.is_some() && reusable.iter().any(|r| r.status == RowStatus::Running && r.credential_at.is_some() && r.credential_tag == sealed);
        return Err(if held { "token_held" } else { "vm_exists" });
    }
    Ok(setting)
}

/// Whether `cwd` is in a git work tree, as far as files tell (no git run): a
/// `.git` entry (a directory, or a worktree's file) in it or in a parent, up
/// to the outermost root that holds it, git's ceiling in
/// `workspace::resolve`. Without one, git finds no work tree there either.
fn in_git_work_tree(cwd: &Path, roots: &[&Path]) -> bool {
    let top = roots.iter().filter_map(|r| std::fs::canonicalize(r).ok()).filter(|r| cwd.starts_with(r)).min_by_key(|r| r.components().count());
    let Some(top) = top else {
        // No root resolves to hold it: git decides, in the sibling.
        return true;
    };
    cwd.ancestors().take_while(|d| d.starts_with(&top)).any(|d| std::fs::symlink_metadata(d.join(".git")).is_ok())
}

/// The image versions SELECT_VM would resolve for `plan`, as files tell it
/// (it asks the service live): `N.M` itself; `N` as `N` or `N.0`, as `vm run`
/// reads it; `active` the active version `state/infra.toml` records for the
/// plan's image (the provisional gate's reading). None when that file
/// records none: any version passes, as `vm warm --dry-run` takes it.
fn selected_versions(paths: &Paths, plan: &RunPlan) -> Vec<String> {
    let want = plan.want_version.trim();
    if want == "active" {
        let state = crate::bridge::infra::read_infra_state(paths).ok().flatten().filter(|s| s.image_arn.trim() == plan.image_arn);
        return state.and_then(|s| s.latest_active_image_version).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).into_iter().collect();
    }
    if want.contains('.') {
        vec![want.to_string()]
    } else {
        vec![want.to_string(), format!("{want}.0")]
    }
}

/// The newest verdict of `probe` in `lab/probes.jsonl` (none when there is
/// no such row, or the file cannot be read).
fn newest_verdict(paths: &Paths, probe: &str) -> Option<String> {
    let rows = crate::bridge::census::read_rows(&paths.probes(), None).ok()?;
    rows.iter().rev().find(|r| r.get("probe").and_then(|p| p.as_str()) == Some(probe)).and_then(|r| r.get("verdict")?.as_str().map(str::to_string))
}

/// `state/workspaces/<slug>.warm.lock`, locked without waiting: the open
/// file (close-on-exec), never unlocked here, at its first byte again once
/// read (the prewarm inherits this offset with the open file). `warming`
/// while a prewarm holds it, `recent` when the last one finished within
/// [`COOLDOWN`] (its `finished_at=` line).
fn warm_lock(paths: &Paths, slug: &str) -> Result<File, &'static str> {
    let path = paths.workspace_warm_lock(slug);
    if let Some(dir) = path.parent() {
        crate::bridge::registry::ensure_private_dir(dir).map_err(|_| "config")?;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| "config")?;
    // SAFETY: flock(2) on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("warming");
    }
    let mut text = String::new();
    let _ = file.seek(SeekFrom::Start(0)).and_then(|_| Read::by_ref(&mut file).take(4096).read_to_string(&mut text));
    let finished = text.lines().find_map(|l| l.strip_prefix("finished_at=")).and_then(|v| v.trim().parse::<u64>().ok());
    if finished.is_some_and(|at| crate::wire::time::unix_now().saturating_sub(at) < COOLDOWN.as_secs()) {
        // Dropped: the close releases the lock (nobody else holds this open file).
        return Err("recent");
    }
    file.rewind().map_err(|_| "config")?;
    Ok(file)
}

/// What the prewarm inherits of the wrapper's environment: everything but
/// the credentials ai-env knows (`age_cmd::CHILD_ENV_REMOVED`) and any name
/// that looks like one (TOKEN, KEY, SECRET, PASSWORD), as `vm exec --env`
/// judges them.
fn prewarm_env() -> Vec<CString> {
    std::env::vars_os()
        .filter(|(k, _)| {
            let name = k.to_string_lossy().to_ascii_uppercase();
            !crate::age_cmd::CHILD_ENV_REMOVED.contains(&name.as_str()) && !crate::bridge::agent::exec::CREDENTIAL_WORDS.iter().any(|w| name.contains(w))
        })
        .filter_map(|(k, v)| {
            let mut pair = k.as_bytes().to_vec();
            pair.push(b'=');
            pair.extend_from_slice(v.as_bytes());
            CString::new(pair).ok()
        })
        .collect()
}

/// The descriptors open now above 2 (`/dev/fd`), but `keep`.
fn open_fds(keep: &[RawFd]) -> Vec<RawFd> {
    let Ok(dir) = std::fs::read_dir("/dev/fd") else { return Vec::new() };
    dir.flatten().filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok()).filter(|fd| *fd > 2 && !keep.contains(fd)).collect()
}

/// `fd` duplicated at 10 or above, close-on-exec: out of the way of the
/// child's 0 to 3, whatever the wrapper was started with.
fn dup_high(fd: RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: fcntl(2) F_DUPFD_CLOEXEC on an open descriptor; the new one is owned below.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if new < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `new` is a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Start `program vm warm <cwd> --prewarm` detached, and its pid: a double
/// fork (the intermediate exits at once and is reaped here, so the prewarm
/// is never a child of the claude this wrapper execs), then in the prewarm
/// `setsid`, `chdir("/")`, stdio on `/dev/null`, `lock`'s open file on fd 3
/// (every other descriptor closed), and `execve` of the absolute path: no
/// shell, no `PATH`. Everything it needs is built before the first fork;
/// after it only async-signal-safe calls run. The wrapper waits for the two
/// forks, never for the exec (a failed exec is the prewarm's exit 127).
fn spawn_detached(program: &Path, cwd: &Path, lock: &File) -> std::io::Result<u32> {
    let cstr = |b: &[u8]| CString::new(b).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "a NUL in the prewarm's argv"));
    let path = cstr(program.as_os_str().as_bytes())?;
    let argv_c = [path.clone(), cstr(b"vm")?, cstr(b"warm")?, cstr(cwd.as_os_str().as_bytes())?, cstr(b"--prewarm")?];
    let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let env_c = prewarm_env();
    let mut envp: Vec<*const libc::c_char> = env_c.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    let root = cstr(b"/")?;
    let null = File::options().read(true).write(true).open("/dev/null")?;
    let null_hi = dup_high(null.as_raw_fd())?;
    let lock_hi = dup_high(lock.as_raw_fd())?;
    let (mut pid_r, pid_w) = std::io::pipe()?;
    let (null_fd, lock_fd, w_fd) = (null_hi.as_raw_fd(), lock_hi.as_raw_fd(), pid_w.as_raw_fd());
    let close = open_fds(&[null_fd, lock_fd, w_fd, pid_r.as_raw_fd()]);
    // SAFETY: fork(2); after it the child runs only async-signal-safe calls
    // (fork, setsid, chdir, dup2, close, execve, write, _exit) on data built above.
    let middle = unsafe { libc::fork() };
    if middle < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if middle == 0 {
        // SAFETY: see above; this process only forks once more and exits.
        unsafe {
            let warm = libc::fork();
            if warm == 0 {
                libc::setsid();
                libc::chdir(root.as_ptr());
                for fd in 0..3 {
                    libc::dup2(null_fd, fd);
                }
                libc::dup2(lock_fd, 3);
                for fd in &close {
                    if *fd != 3 {
                        libc::close(*fd);
                    }
                }
                libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            if warm > 0 {
                let bytes = u32::try_from(warm).unwrap_or(0).to_ne_bytes();
                libc::write(w_fd, bytes.as_ptr().cast(), bytes.len());
            }
            libc::_exit(if warm > 0 { 0 } else { 1 });
        }
    }
    drop(pid_w);
    let mut bytes = [0_u8; 4];
    let read = pid_r.read_exact(&mut bytes);
    loop {
        let mut status = 0;
        // SAFETY: waitpid(2) on the intermediate child this process forked.
        if unsafe { libc::waitpid(middle, &raw mut status, 0) } >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
    read.map_err(|_| std::io::Error::other("the prewarm's fork failed"))?;
    Ok(u32::from_ne_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::vm::registry::VmRow;

    #[test]
    fn the_census_part_says_what_happened() {
        assert_eq!(Prewarm::Spawned(4242).census_part(), "prewarm:spawned(4242)");
        assert_eq!(Prewarm::Skipped("touchid_gui").census_part(), "prewarm:skipped(touchid_gui)");
        assert!(SKIP_WORDS.iter().all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    }

    /// The documentation account's made-up egress connector.
    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    /// The world of `decide`: a bridge root, a workspace under the root (a
    /// git work tree as files tell it: its `.git` entry), the fake image and
    /// the connector, a probes file, and a setting (`extra` after it in
    /// `[vm]`).
    struct World {
        _dir: tempfile::TempDir,
        paths: Paths,
        ws: std::path::PathBuf,
        cfg: BridgeConfig,
    }

    fn world(setting: &str, verdict: Option<&str>) -> World {
        world_with(setting, verdict, "")
    }

    fn world_with(setting: &str, verdict: Option<&str>, extra: &str) -> World {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let ws = root.join("work");
        std::fs::create_dir_all(ws.join(".git")).unwrap();
        let paths = Paths::from_root_and_env(root.join("bridge"), None);
        let image = crate::bridge::api::FAKE_IMAGE_ARN;
        let cfg = BridgeConfig::parse(&format!("[aws]\nimage_arn = {image:?}\negress_connector_arn = {CONNECTOR:?}\n[vm]\nprewarm_on_auth_status = {setting:?}\n{extra}[workspaces]\nroots = [{ws:?}]\n")).unwrap();
        if let Some(v) = verdict {
            std::fs::create_dir_all(paths.probes().parent().unwrap()).unwrap();
            let rows = [serde_json::json!({ "probe": TOUCHID_PROBE, "verdict": "terminal-only" }), serde_json::json!({ "probe": TOUCHID_PROBE, "verdict": v }), serde_json::json!({ "probe": "dns-path", "verdict": "no-dns" })];
            std::fs::write(paths.probes(), rows.iter().map(|r| format!("{r}\n")).collect::<String>()).unwrap();
        }
        World { _dir: dir, paths, ws, cfg }
    }

    /// A vpc row of the workspace, as SELECT_VM writes one: the fake image at
    /// 1.0, the connector, two hours of wall left.
    fn row(w: &World, id: &str, status: RowStatus, tag: Option<String>) -> VmRow {
        let r = VmRow {
            id: id.into(),
            status,
            client_token: uuid::Uuid::now_v7().to_string(),
            workspace: Some(w.ws.display().to_string()),
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            wall_deadline: Some(crate::wire::time::unix_now() + 7200),
            egress: "vpc".into(),
            egress_connectors: vec![CONNECTOR.into()],
            credential_at: tag.as_ref().map(|_| 1),
            credential_tag: tag,
            ..VmRow::default()
        };
        registry::write_row(&w.paths, &r).unwrap();
        r
    }

    /// `state/infra.toml` recording `version` as the fake image's active one.
    fn record_active(w: &World, version: &str) {
        std::fs::create_dir_all(w.paths.infra_state().parent().unwrap()).unwrap();
        std::fs::write(w.paths.infra_state(), format!("image_arn = {:?}\nlatest_active_image_version = {version:?}\n", crate::bridge::api::FAKE_IMAGE_ARN)).unwrap();
    }

    /// Plan §11's conditions, read from files: the newest `touchid-gui`
    /// verdict `prompted`, the cwd under the roots, the setting not `never`;
    /// `auto` only with no reusable row of the workspace (`token_held` when
    /// a running one holds the sealed token), `always` despite any.
    #[test]
    fn the_conditions_come_from_files_alone() {
        let w = world("auto", Some(PROMPTED));
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Ok(PrewarmMode::Auto));
        assert_eq!(decide(&w.paths, &w.cfg, w.ws.parent().unwrap(), false), Err("outside_roots"));
        assert_eq!(decide(&world("auto", None).paths, &w.cfg, &w.ws, false), Err("touchid_gui"), "no row");
        let t = world("auto", Some("terminal-only"));
        assert_eq!(decide(&t.paths, &t.cfg, &t.ws, false), Err("touchid_gui"), "the newest row decides");
        let n = world("never", Some(PROMPTED));
        assert_eq!(decide(&n.paths, &n.cfg, &n.ws, false), Err("never"));
        let bad = world("sometimes", Some(PROMPTED));
        assert_eq!(decide(&bad.paths, &bad.cfg, &bad.ws, false), Err("config"));
        // A reusable row: auto skips, always does not.
        row(&w, "microvm-reuse01", RowStatus::Suspended, None);
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("vm_exists"));
        let a = world("always", Some(PROMPTED));
        row(&a, "microvm-reuse02", RowStatus::Suspended, None);
        assert_eq!(decide(&a.paths, &a.cfg, &a.ws, false), Ok(PrewarmMode::Always));
        // The sealed token held by a running VM of the workspace: auto says so; always warms anyway.
        for x in [&w, &a] {
            std::fs::create_dir_all(x.paths.credentials()).unwrap();
            std::fs::write(x.paths.setup_token_env(), "a sealed container's text").unwrap();
        }
        let tag = crate::bridge::agent::credential::seal_tag(&w.paths.setup_token_env());
        row(&w, "microvm-held0001", RowStatus::Suspended, tag.clone());
        row(&w, "microvm-held0002", RowStatus::Running, Some("another-seal".into()));
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("vm_exists"), "a suspended VM's cache is empty, another seal is not this one");
        row(&w, "microvm-held0003", RowStatus::Running, tag.clone());
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("token_held"));
        row(&a, "microvm-held0004", RowStatus::Running, tag);
        assert_eq!(decide(&a.paths, &a.cfg, &a.ws, false), Ok(PrewarmMode::Always), "always: whatever the rows say");
    }

    /// A row that is no reusable VM of this workspace, one SELECT_VM would
    /// pass over (its own `run::reuse_candidate`), never skips `auto`: a
    /// terminated one, another workspace's, an internet or `--shell` VM, one
    /// whose wall is nearly over, an image without `workspace_v1`, another
    /// image or egress connector, another image version than the one it
    /// would run (`active` as `state/infra.toml` records it, any while it
    /// records none; a pinned `N` is `N` or `N.0`).
    #[test]
    fn only_a_reusable_row_of_the_workspace_skips_auto() {
        let w = world("auto", Some(PROMPTED));
        let now = crate::wire::time::unix_now();
        for (id, edit) in [
            ("microvm-x0000001", Box::new(|r: &mut VmRow| r.status = RowStatus::Terminated) as Box<dyn Fn(&mut VmRow)>),
            ("microvm-x0000002", Box::new(|r: &mut VmRow| r.workspace = Some("/elsewhere".into()))),
            ("microvm-x0000003", Box::new(|r: &mut VmRow| r.egress = "internet".into())),
            ("microvm-x0000004", Box::new(|r: &mut VmRow| r.shell = true)),
            ("microvm-x0000005", Box::new(move |r: &mut VmRow| r.wall_deadline = Some(now + 60))),
            ("microvm-x0000006", Box::new(|r: &mut VmRow| r.caps = Some(vec!["credential_cache".into()]))),
            ("microvm-x0000007", Box::new(|r: &mut VmRow| r.image_arn = crate::bridge::api::FAKE_IMAGE_ARN.replace("ai-env-agent", "another-image"))),
            ("microvm-x0000008", Box::new(|r: &mut VmRow| r.egress_connectors = vec![CONNECTOR.replace("ai-env-egress", "another-egress")])),
        ] {
            let mut r = row(&w, id, RowStatus::Running, None);
            edit(&mut r);
            registry::write_row(&w.paths, &r).unwrap();
        }
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Ok(PrewarmMode::Auto));
        // A row at 1.0: reused while nothing says which version is active, or 1.0 is; passed over after a deploy.
        row(&w, "microvm-v1000001", RowStatus::Running, None);
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("vm_exists"), "no version recorded: any");
        record_active(&w, "1.0");
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("vm_exists"));
        record_active(&w, "2.0");
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Ok(PrewarmMode::Auto), "the chat would start a 2.0 VM");
        let mut pinned = world("auto", Some(PROMPTED));
        pinned.cfg.aws.image_version = "1".into();
        row(&pinned, "microvm-v1000002", RowStatus::Running, None);
        assert_eq!(decide(&pinned.paths, &pinned.cfg, &pinned.ws, false), Err("vm_exists"), "1 runs 1.0");
        pinned.cfg.aws.image_version = "2".into();
        assert_eq!(decide(&pinned.paths, &pinned.cfg, &pinned.ws, false), Ok(PrewarmMode::Auto));
    }

    /// What no chat would use is never warmed, in any setting: a cwd in no
    /// git work tree (a `.git` entry in it or a parent, the outermost root
    /// the bound), an `AI_ENV_BRIDGE_VM` pin (the chats take that VM), and
    /// `[vm].reuse_per_workspace` off (no chat reuses a warmed VM).
    #[test]
    fn a_vm_no_chat_would_use_is_never_warmed() {
        for setting in ["auto", "always"] {
            let w = world(setting, Some(PROMPTED));
            let mode = if setting == "auto" { PrewarmMode::Auto } else { PrewarmMode::Always };
            let deep = w.ws.join("src").join("lib");
            std::fs::create_dir_all(&deep).unwrap();
            assert_eq!(decide(&w.paths, &w.cfg, &deep, false), Ok(mode), "{setting}: in the work tree, below its top");
            assert_eq!(decide(&w.paths, &w.cfg, &w.ws, true), Err("pinned"), "{setting}");
            let off = world_with(setting, Some(PROMPTED), "reuse_per_workspace = false\n");
            assert_eq!(decide(&off.paths, &off.cfg, &off.ws, false), Err("reuse_off"), "{setting}");
            std::fs::remove_dir(w.ws.join(".git")).unwrap();
            assert_eq!(decide(&w.paths, &w.cfg, &deep, false), Err("not_git"), "{setting}");
            // A linked worktree's `.git` is a file.
            std::fs::write(w.ws.join(".git"), "gitdir: /elsewhere/.git/worktrees/work\n").unwrap();
            assert_eq!(decide(&w.paths, &w.cfg, &deep, false), Ok(mode), "{setting}: a worktree");
        }
        // The roots bound the search: a repository above the outermost root is not the workspace's (git's ceiling).
        let w = world("auto", Some(PROMPTED));
        std::fs::remove_dir(w.ws.join(".git")).unwrap();
        std::fs::create_dir_all(w.ws.parent().unwrap().join(".git")).unwrap();
        assert_eq!(decide(&w.paths, &w.cfg, &w.ws, false), Err("not_git"));
    }

    /// The warm lock: taken without waiting; `warming` while another holds
    /// it; `recent` within the cool-down of a finish its file records, and
    /// free again once that is older.
    #[test]
    fn the_warm_lock_skips_a_running_or_recent_prewarm() {
        let w = world("auto", Some(PROMPTED));
        let held = warm_lock(&w.paths, "-w").unwrap();
        assert_eq!(warm_lock(&w.paths, "-w").err(), Some("warming"));
        drop(held);
        let path = w.paths.workspace_warm_lock("-w");
        let now = crate::wire::time::unix_now();
        std::fs::write(&path, format!("pid=1\nstarted_at={}\nfinished_at={}\n", now - 30, now - 10)).unwrap();
        assert_eq!(warm_lock(&w.paths, "-w").err(), Some("recent"));
        std::fs::write(&path, format!("pid=1\nstarted_at={}\nfinished_at={}\n", now - 400, now - 300)).unwrap();
        assert!(warm_lock(&w.paths, "-w").is_ok(), "past the cool-down");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// The prewarm inherits the warm lock's open file on fd 3, its offset
    /// with it: read for the cool-down, the file is handed on at its first
    /// byte, so the prewarm's record replaces the last one.
    #[test]
    fn the_warm_lock_is_handed_on_at_its_first_byte() {
        let w = world("auto", Some(PROMPTED));
        let path = w.paths.workspace_warm_lock("-w");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let now = crate::wire::time::unix_now();
        std::fs::write(&path, format!("pid=1\nstarted_at={}\nfinished_at={}\n", now - 400, now - 300)).unwrap();
        let mut lock = warm_lock(&w.paths, "-w").unwrap();
        assert_eq!(lock.stream_position().unwrap(), 0, "read, then rewound");
    }

    /// Nothing that looks like a credential reaches the prewarm's environment.
    #[test]
    fn the_prewarm_env_keeps_no_credential_name() {
        let env = prewarm_env();
        for e in &env {
            let name = e.to_string_lossy().split('=').next().unwrap_or_default().to_ascii_uppercase();
            assert!(!crate::age_cmd::CHILD_ENV_REMOVED.contains(&name.as_str()), "{name}");
            assert!(!["TOKEN", "KEY", "SECRET", "PASSWORD"].iter().any(|w| name.contains(w)), "{name}");
        }
    }

    /// `maybe_prewarm` applies to exactly `auth status --json` in remote mode.
    #[test]
    fn only_auth_status_in_remote_mode_is_considered() {
        let loaded = Loaded::default();
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(maybe_prewarm(&loaded, Mode::Passthrough, &args(&AUTH_STATUS), None), None);
        assert_eq!(maybe_prewarm(&loaded, Mode::LocalChild, &args(&AUTH_STATUS), None), None);
        assert_eq!(maybe_prewarm(&loaded, Mode::Remote, &args(&["auth", "status"]), None), None);
        assert_eq!(maybe_prewarm(&loaded, Mode::Remote, &args(&["auth", "status", "--json", "--x"]), None), None);
        assert_eq!(maybe_prewarm(&loaded, Mode::Remote, &args(&AUTH_STATUS), None), Some(Prewarm::Skipped("unconfigured")));
    }
}
