//! `/validate`: the platform calls it on a fresh VM restored from the image
//! snapshot; any failure fails the image build, so a bad image never becomes
//! ACTIVE. Every call evaluates every check (no cached verdict):
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
//!
//! Paths are resolved under `--fs-root` when set (native tests).
use crate::shim::health::ShimState;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

/// Run V1–V5; the caller holds the single-flight lock. While V1 fails the
/// fresh probe is skipped (V2 fails as skipped), so the 503 is immediate.
pub async fn run_checks(state: &ShimState) -> Vec<Check> {
    let v1 = match state.ready() {
        Ok(()) => Check { id: "V1", ok: true, detail: "listeners bound, claude probed".into() },
        Err(waiting) => Check { id: "V1", ok: false, detail: format!("not ready: waiting for {}", waiting.join(", ")) },
    };
    let fresh = if v1.ok { Some(state.probe_fresh().await) } else { None };
    let facts = serde_json::to_string(&crate::shim::sys::boot_report(state.sys.as_ref())).unwrap_or_default();
    vec![v1, v2(state, fresh.as_ref()), v3(state), v4(state), Check { id: "V5", ok: true, detail: facts }]
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
