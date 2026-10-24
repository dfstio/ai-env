//! tests/workspace.rs area helpers (S8 W4): an isolated git for the library's
//! own runs (no global config of the developer's reaches them), fixture
//! repositories the real git builds at fixed dates, the state of a user's
//! repository for the "never touched" checks, and a git-backed fake VM: a
//! [`DataPlane`] that applies a seed's manifest and pack, answers `GET
//! /seed`, snapshots and packs a code-out, and keeps transcripts (S9: the
//! extended stat, and a pull from the tests' S3 through the presigned URLs
//! as curl sends them), the way the shim's helper does, so what the Mac
//! sends is proven applicable.

use crate::common::git_real;
use ai_env_cli::bridge::agent::AgentTarget;
use ai_env_cli::bridge::api::{AuthToken, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, ENDPOINT_SUFFIX, FAKE_IMAGE_ARN, TOKEN_HEADER};
use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::bridge::dataplane::{CodeoutBody, DataPlane, DpReply, TokenSource};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::workspace::{EnsureCtx, SeedLimits, SeedProgress, WorkspaceRef};
use ai_env_cli::wire::frame::CAP_WORKSPACE_V1;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::workspace::{
    head_line, parse_head, read_head_line, refusal, CodeoutManifest, CodeoutRequest, ObjectFormat, PullPartReport, SeedApplied, SeedManifest, SeedMode, SeedQuery, SeedRecord, SeedReply, SeedState, SettingsCapture, StatQuery,
    TranscriptPull, TranscriptPullReply, TranscriptStat, WsRefusal, HEADS_PREFIX, SEED_REF, SEED_WIP_REF, WIP_REF_PREFIX,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

/// The date every fixture commit carries.
pub const DATE: &str = "2026-10-12T08:00:00+00:00";
/// The fixture's author and committer.
pub const AUTHOR: (&str, &str) = ("ai-env fixture", "fixture@ai-env.invalid");
/// The fake VM's endpoint host and id.
pub const VM: &str = "microvm-00000000-0000-4000-8000-0000000000f1";

/// Once per test process, before anything runs git: no global or XDG git
/// config (a library git run keeps the user's, which here would be the
/// developer's: a global excludes file or a signing setting would change
/// what a test sees) and no inherited `GIT_*`. `HOME` names a directory that
/// does not exist, so nothing is written there either.
pub fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("HOME", "/nonexistent/ai-env-workspace-tests");
        std::env::remove_var("XDG_CONFIG_HOME");
        let git_vars: Vec<std::ffi::OsString> = std::env::vars_os().map(|(k, _)| k).filter(|k| k.to_string_lossy().starts_with("GIT_")).collect();
        for k in git_vars {
            std::env::remove_var(k);
        }
    });
}

/// A runtime-built AWS key id shape (never a literal in the source).
#[must_use]
pub fn key_id() -> String {
    format!("{}{}", "AKIA", "Z3".repeat(8))
}

/// The real git in `dir` with neither the system's nor a global config, the
/// fixture's author and dates, `LC_ALL=C`.
pub fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new(git_real());
    cmd.current_dir(dir)
        .env_clear()
        .env("HOME", "/nonexistent/ai-env-workspace-tests")
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", AUTHOR.0)
        .env("GIT_AUTHOR_EMAIL", AUTHOR.1)
        .env("GIT_AUTHOR_DATE", DATE)
        .env("GIT_COMMITTER_NAME", AUTHOR.0)
        .env("GIT_COMMITTER_EMAIL", AUTHOR.1)
        .env("GIT_COMMITTER_DATE", DATE)
        .stdin(Stdio::null());
    cmd
}

/// How long one fixture git run may take (S8 phase 4's F9: every wait
/// bounded): past it the run is killed and its test fails naming it.
pub const GIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

/// `git args` in `dir` with `stdin` (`None`: /dev/null): its output,
/// whatever its exit, within [`GIT_LIMIT`] (`common::bounded`).
pub fn git_out(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = git_cmd(dir);
    cmd.args(args);
    crate::common::bounded::run_within(cmd, stdin, GIT_LIMIT, &format!("git {args:?}"))
}

/// `git args` in `dir`: its stdout, trimmed; a failure panics with its stderr.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let o = git_out(dir, args, None);
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Whether `git args` exits 0.
pub fn git_ok(dir: &Path, args: &[&str]) -> bool {
    git_out(dir, args, None).status.success()
}

/// A tempdir holding the bridge root (`bridge/`) and the workspaces (`work/`), canonical.
pub struct World {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl World {
    #[must_use]
    pub fn new() -> World {
        init();
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["bridge", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        World { _tmp: tmp, root }
    }

    #[must_use]
    pub fn paths(&self) -> Paths {
        Paths::from_root_and_env(self.root.join("bridge"), None)
    }

    /// The workspaces' root, `[workspaces].roots`.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// bridge.toml's content with `work/` as the one root, then `extra`.
    #[must_use]
    pub fn config_text(&self, extra: &str) -> String {
        format!("[workspaces]\nroots = [{:?}]\n{extra}", self.work().display().to_string())
    }

    /// The parsed config ([`World::config_text`]).
    #[must_use]
    pub fn cfg(&self, extra: &str) -> BridgeConfig {
        BridgeConfig::parse(&self.config_text(extra)).unwrap()
    }

    /// `work/<name>`, a repository on `main` with `README.md` committed.
    #[must_use]
    pub fn repo(&self, name: &str) -> Repo {
        Repo::create(&self.work().join(name))
    }
}

/// A fixture repository.
pub struct Repo {
    pub dir: PathBuf,
}

/// What a user's repository holds that a seed or a fetch must never change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub index: Vec<u8>,
    pub status: String,
    pub stash: String,
    pub refs: String,
    pub objects: String,
}

impl Repo {
    /// `dir` made a repository on `main` with one commit (`README.md`).
    #[must_use]
    pub fn create(dir: &Path) -> Repo {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q", "-b", "main"]);
        let repo = Repo { dir: dir.to_path_buf() };
        repo.write("README.md", "fixture\n");
        repo.commit("fixture");
        repo
    }

    pub fn git(&self, args: &[&str]) -> String {
        git(&self.dir, args)
    }

    pub fn write(&self, rel: &str, text: &str) {
        self.write_bytes(rel, text.as_bytes());
    }

    pub fn write_bytes(&self, rel: &str, bytes: &[u8]) {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    /// `add -A` and a commit: its id.
    pub fn commit(&self, msg: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", msg]);
        self.head()
    }

    #[must_use]
    pub fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
    }

    /// The repository as a seed must leave it: the index's bytes, status
    /// (read without refreshing the index), stash, every ref and the object store's count.
    #[must_use]
    pub fn state(&self) -> RepoState {
        RepoState {
            index: std::fs::read(self.dir.join(".git").join("index")).unwrap_or_default(),
            status: self.git(&["--no-optional-locks", "status", "--porcelain=v2", "--untracked-files=all", "--ignored"]),
            stash: self.git(&["stash", "list"]),
            refs: format!("{}\n{}", self.git(&["for-each-ref"]), self.git(&["rev-parse", "HEAD"])),
            objects: self.git(&["count-objects", "-v"]),
        }
    }
}

/// The fake VM's target: its id, a pinned endpoint host, a session token.
#[must_use]
pub fn target() -> AgentTarget {
    AgentTarget { vm_id: VM.into(), endpoint: format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{ENDPOINT_SUFFIX}"), session_token: Secret::new("s".repeat(64)), vpc: true, shell: false }
}

/// Tokens that are always there (the endpoint is the fake VM itself).
pub struct Tokens;

impl TokenSource for Tokens {
    async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
        Ok(AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("token".into()))]), port, expires_at_unix: u64::MAX })
    }
}

/// A RUNNING VM in a fresh in-memory fake control plane (GetMicrovm after a 502/503).
pub async fn api() -> FakeMicrovmApi {
    let api = FakeMicrovmApi::new();
    let spec = RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
        max_duration_s: 900,
        run_hook_payload: "{}".into(),
        client_token: "01926f2e-0000-7000-8000-0000000000f1".into(),
    };
    api.run(&spec).await.unwrap();
    api.advance_all();
    api
}

/// The caps of an S8 VM.
#[must_use]
pub fn caps() -> Vec<String> {
    vec![CAP_WORKSPACE_V1.to_string()]
}

/// An `EnsureCtx` of `ws` on the fake VM `vm`.
#[allow(clippy::too_many_arguments)]
pub fn ensure_ctx<'a>(api: &'a FakeMicrovmApi, vm: &'a FakeVm, paths: &'a Paths, cfg: &'a BridgeConfig, target: &'a AgentTarget, caps: &'a [String], ws: &'a WorkspaceRef, progress: &'a (dyn Fn(SeedProgress) + Sync)) -> EnsureCtx<'a, FakeMicrovmApi, FakeVm, Tokens> {
    EnsureCtx { api, dp: vm, tokens: &Tokens, paths, cfg, target, caps, ws, lim: SeedLimits::cli(cfg, None), deadline: None, progress }
}

// ---- the fake VM -----------------------------------------------------------------------------

/// A VM's workspace on this disk, driven the way the shim's helper drives
/// the real one (plan §6): a seed applied with git from its manifest and
/// pack, `.git/shallow` the manifest's boundary, the WIP left uncommitted; a
/// code-out snapshotting into `refs/wip/*` and packing what the Mac lacks.
pub struct FakeVm {
    /// The VM's checkout (the workspace's VM path, on this disk).
    pub dir: PathBuf,
    /// The VM's projects directory (transcripts).
    pub projects: PathBuf,
    record: Mutex<Option<SeedRecord>>,
    snapshots: Mutex<u32>,
    /// Every route called, in order (`PUT /seed clone`, …).
    pub calls: Mutex<Vec<String>>,
    /// Bodies the seed routes took (the manifest and the pack's bytes).
    pub bodies: Mutex<Vec<Vec<u8>>>,
    /// Refusals the next `PUT /seed`s answer instead of applying (a race the test stages).
    pub refuse_next: Mutex<std::collections::VecDeque<WsRefusal>>,
    /// S11 (C.1.1): each `POST /codeout`'s `manifest_when_empty`, in order.
    pub flags: Mutex<Vec<bool>>,
    /// S11 (C.1.1): the shim serves `codeout_manifest_v1` (13.0, the
    /// default): asked for it, nothing new is the manifest line alone (200,
    /// no pack byte); `false`, a 12.0 shim's 204 whatever the flag.
    pub manifest_served: std::sync::atomic::AtomicBool,
    /// S11: the manifest the next `POST /codeout` answers without a pack
    /// (200, the line alone), whatever the request and the checkout: a
    /// broken or hostile shim.
    pub forge_next: Mutex<Option<CodeoutManifest>>,
}

fn refused<T>(code: &str, message: &str) -> DpReply<T> {
    DpReply::refused(WsRefusal::new(code, message))
}

impl FakeVm {
    #[must_use]
    pub fn new(dir: &Path, projects: &Path) -> FakeVm {
        FakeVm {
            dir: dir.to_path_buf(),
            projects: projects.to_path_buf(),
            record: Mutex::new(None),
            snapshots: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
            bodies: Mutex::new(Vec::new()),
            refuse_next: Mutex::new(std::collections::VecDeque::new()),
            flags: Mutex::new(Vec::new()),
            manifest_served: std::sync::atomic::AtomicBool::new(true),
            forge_next: Mutex::new(None),
        }
    }

    /// The `manifest_when_empty` of each `POST /codeout` so far.
    #[must_use]
    pub fn flags(&self) -> Vec<bool> {
        self.flags.lock().unwrap().clone()
    }

    fn call(&self, what: String) {
        self.calls.lock().unwrap().push(what);
    }

    /// The calls so far.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// The record of the last seed.
    #[must_use]
    pub fn record(&self) -> Option<SeedRecord> {
        self.record.lock().unwrap().clone()
    }

    /// The tree the worktree holds now (`add -A` into a throwaway index).
    #[must_use]
    pub fn worktree_tree(&self) -> String {
        let idx = self.dir.join(".git").join("fake-vm.index");
        let _ = std::fs::remove_file(&idx);
        let _ = std::fs::copy(self.dir.join(".git").join("index"), &idx);
        let mut add = git_cmd(&self.dir);
        add.env("GIT_INDEX_FILE", &idx).args(["add", "-A"]);
        assert!(add.status().unwrap().success());
        let mut wt = git_cmd(&self.dir);
        let o = wt.env("GIT_INDEX_FILE", &idx).args(["write-tree"]).output().unwrap();
        let _ = std::fs::remove_file(&idx);
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn state(&self) -> SeedState {
        let Some(record) = self.record() else { return SeedState::default() };
        let tip = git(&self.dir, &["rev-parse", "HEAD"]);
        let branch = git_out(&self.dir, &["symbolic-ref", "--quiet", "HEAD"], None).status.success().then(|| git(&self.dir, &["symbolic-ref", "--short", "HEAD"]));
        let clean = git(&self.dir, &["status", "--porcelain", "--untracked-files=all"]).is_empty();
        let head_tree = git(&self.dir, &["rev-parse", "HEAD^{tree}"]);
        let index_tree = git(&self.dir, &["write-tree"]);
        let pristine = tip == record.head && self.worktree_tree() == record.wip_tree.clone().unwrap_or_else(|| head_tree.clone()) && index_tree == record.index_tree.clone().unwrap_or(head_tree);
        SeedState { record: Some(record), tip: Some(tip), branch, clean, pristine, shallow: None }
    }

    /// Leave the WIP of `m` uncommitted: the worktree the WIP's tree, the
    /// index the index commit's (else HEAD's).
    fn apply_wip(&self, m: &SeedManifest) {
        if let Some(w) = &m.wip {
            git(&self.dir, &["read-tree", "-m", "-u", "HEAD", w]);
            git(&self.dir, &["read-tree", m.index.as_deref().unwrap_or("HEAD")]);
            let _ = git_out(&self.dir, &["update-index", "-q", "--refresh"], None);
        }
    }

    fn apply(&self, query: &SeedQuery, body: &[u8]) -> DpReply<SeedReply> {
        let mut input = std::io::Cursor::new(body);
        let Ok(line) = read_head_line(&mut input, ai_env_cli::wire::workspace::HEAD_LINE_MAX) else { return refused(refusal::BAD_PACK, "no manifest line") };
        let pack = &body[input.position() as usize..];
        let m: SeedManifest = match parse_head(&line) {
            Ok(m) => m,
            Err(e) => return refused(refusal::BAD_PACK, &e),
        };
        if let Err(e) = m.check_for(query) {
            return refused(refusal::BAD_REFS, &format!("the manifest {e}"));
        }
        let shallow_file = self.dir.join(".git").join("shallow");
        let outcome = match query.mode {
            SeedMode::Clone => {
                if self.record().is_some() {
                    return refused(refusal::PATH_OCCUPIED, "seeded already");
                }
                std::fs::create_dir_all(&self.dir).unwrap();
                git(&self.dir, &["init", "-q", "--initial-branch", m.branch.as_deref().unwrap_or("main"), &format!("--object-format={}", m.object_format.name())]);
                let o = git_out(&self.dir, &["index-pack", "--stdin"], Some(pack));
                if !o.status.success() {
                    return refused(refusal::BAD_PACK, &String::from_utf8_lossy(&o.stderr));
                }
                std::fs::write(&shallow_file, m.shallow.iter().map(|s| format!("{s}\n")).collect::<String>()).unwrap();
                for (r, id) in &m.refs {
                    git(&self.dir, &["update-ref", r, id]);
                }
                match &m.branch {
                    Some(b) => git(&self.dir, &["symbolic-ref", "HEAD", &format!("{HEADS_PREFIX}{b}")]),
                    None => git(&self.dir, &["update-ref", "--no-deref", "HEAD", &m.head]),
                };
                git(&self.dir, &["reset", "-q", "--hard"]);
                SeedApplied::Cloned
            }
            SeedMode::Update => {
                let st = self.state();
                if !st.clean {
                    return refused(refusal::DIRTY, "changes of its own");
                }
                let tip = st.tip.unwrap_or_default();
                if Some(&tip) != query.expect.as_ref() {
                    return refused(refusal::CHANGED, "the tip moved");
                }
                let o = git_out(&self.dir, &["index-pack", "--stdin", "--fix-thin"], Some(pack));
                if !o.status.success() {
                    return refused(refusal::MISSING_PREREQUISITES, &String::from_utf8_lossy(&o.stderr));
                }
                let mut shallow = std::fs::read_to_string(&shallow_file).unwrap_or_default();
                for s in &m.shallow {
                    shallow.push_str(&format!("{s}\n"));
                }
                std::fs::write(&shallow_file, shallow).unwrap();
                if !git_ok(&self.dir, &["merge-base", "--is-ancestor", &tip, &m.head]) {
                    return refused(refusal::DIVERGED, "not an ancestor");
                }
                if let Some(b) = &m.branch {
                    git(&self.dir, &["update-ref", &format!("{HEADS_PREFIX}{b}"), &m.head, &tip]);
                }
                git(&self.dir, &["read-tree", "-m", "-u", &tip, &m.head]);
                git(&self.dir, &["update-ref", SEED_REF, &m.head]);
                match &m.wip {
                    Some(w) => git(&self.dir, &["update-ref", SEED_WIP_REF, w]),
                    None => git(&self.dir, &["update-ref", "-d", SEED_WIP_REF]),
                };
                SeedApplied::Updated
            }
            SeedMode::Replace => return refused(refusal::NOT_PRISTINE, "the fake VM does not replace"),
        };
        self.apply_wip(&m);
        let head_tree = git(&self.dir, &["rev-parse", "HEAD^{tree}"]);
        let tree_of = |c: &Option<String>| c.as_ref().map(|c| git(&self.dir, &["rev-parse", &format!("{c}^{{tree}}")])).filter(|t| *t != head_tree);
        *self.record.lock().unwrap() = Some(SeedRecord {
            path: query.path.clone(),
            mode: query.mode,
            branch: m.branch.clone(),
            head: m.head.clone(),
            wip: m.wip.clone(),
            wip_tree: tree_of(&m.wip),
            index_tree: tree_of(&m.index),
            object_format: m.object_format,
            at: "2026-10-12T08:00:00Z".into(),
        });
        DpReply::ok(outcome.status(), SeedReply { outcome, head: m.head.clone(), branch: m.branch.clone(), wip: m.wip.clone(), index: m.index.clone(), ms: 1 })
    }

    /// A snapshot of the checkout's uncommitted work (a copy of the index,
    /// `add -A`): `refs/wip/<n>` unless the checkout is HEAD's. As the
    /// helper's `take_snapshot`: the newest snapshot (by its stamp, then its
    /// number) is kept when it holds this tree on this HEAD, none made.
    fn snapshot(&self) -> Option<String> {
        let tree = self.worktree_tree();
        if tree == git(&self.dir, &["rev-parse", "HEAD^{tree}"]) {
            return None;
        }
        let listed = git(&self.dir, &["for-each-ref", "--format=%(refname)", "refs/wip/"]);
        let key = |n: &str| n.rsplit_once('-').map(|(stamp, k)| (stamp.to_string(), k.parse::<u64>().unwrap_or(0)));
        if let Some(newest) = listed.lines().max_by_key(|n| key(n)) {
            let shown = git_out(&self.dir, &["show", "-s", "--format=%T %P", newest], None);
            let words: Vec<String> = String::from_utf8_lossy(&shown.stdout).split_whitespace().map(str::to_string).collect();
            if shown.status.success() && words.first() == Some(&tree) && words.get(1) == Some(&git(&self.dir, &["rev-parse", "HEAD"])) {
                return Some(newest.to_string());
            }
        }
        let commit = git(&self.dir, &["commit-tree", tree.as_str(), "-p", "HEAD", "-m", "wip"]);
        let mut n = self.snapshots.lock().unwrap();
        *n += 1;
        let name = format!("{WIP_REF_PREFIX}20261012T080000Z-{n}");
        git(&self.dir, &["update-ref", &name, &commit]);
        Some(name)
    }

    fn codeout(&self, req: &CodeoutRequest, dest: &Path, cap: u64) -> DpReply<CodeoutBody> {
        if self.record().is_none() {
            return refused(refusal::NOT_SEEDED, "never seeded");
        }
        let wip_ref = if req.wip { self.snapshot() } else { None };
        let listing = git(&self.dir, &["for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/", "refs/wip/", SEED_WIP_REF]);
        let mut refs: BTreeMap<String, String> = listing.lines().filter_map(|l| l.split_once(' ')).map(|(id, r)| (r.to_string(), id.to_string())).collect();
        let detached = !git_ok(&self.dir, &["symbolic-ref", "--quiet", "HEAD"]);
        let head = git(&self.dir, &["rev-parse", "HEAD"]);
        if detached {
            refs.insert("HEAD".into(), head.clone());
        }
        let mut input: String = refs.values().map(|id| format!("{id}\n")).collect();
        for h in req.haves.iter().filter(|h| git_ok(&self.dir, &["cat-file", "-e", &format!("{h}^{{commit}}")])) {
            input.push_str(&format!("^{h}\n"));
        }
        let o = git_out(&self.dir, &["pack-objects", "--revs", "--thin", "--stdout", "-q"], Some(input.as_bytes()));
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let count = u32::from_be_bytes(o.stdout[8..12].try_into().unwrap());
        let had = refs.values().all(|id| req.haves.contains(id));
        let branch = (!detached).then(|| git(&self.dir, &["symbolic-ref", "--short", "HEAD"]));
        let manifest = CodeoutManifest { v: SeedManifest::V, object_format: ObjectFormat::Sha1, refs, head, branch, wip_ref, wip_skipped: None };
        // The helper's rule (wshelper.rs): no pack when it would hold no object and every tip is a have,
        // whatever the snapshot (a kept one the Mac holds is a have).
        if count == 0 && had {
            if !(req.manifest_when_empty && self.manifest_served.load(std::sync::atomic::Ordering::SeqCst)) {
                return DpReply::status(204);
            }
            // S11 (C.1.1): the manifest line alone; the data plane leaves an empty pack file (`write_pack`).
            std::fs::write(dest, b"").unwrap();
            return DpReply::ok(200, CodeoutBody { manifest, pack_bytes: 0 });
        }
        if o.stdout.len() as u64 > cap {
            return DpReply::refused(WsRefusal::new(refusal::TOO_LARGE, "over max_bytes").with_size(o.stdout.len() as u64));
        }
        std::fs::write(dest, &o.stdout).unwrap();
        DpReply::ok(200, CodeoutBody { manifest, pack_bytes: o.stdout.len() as u64 })
    }
}

impl DataPlane for FakeVm {
    async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, path: &str) -> Result<DpReply<SeedState>, BridgeError> {
        self.call(format!("GET /seed {path}"));
        Ok(DpReply::ok(200, self.state()))
    }

    async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, query: &SeedQuery, body: &Path, len: u64) -> Result<DpReply<SeedReply>, BridgeError> {
        self.call(format!("PUT /seed {}", query.mode.name()));
        let bytes = std::fs::read(body).unwrap();
        assert_eq!(bytes.len() as u64, len, "Content-Length is the body's");
        // As the Mac stages every body (T8.1 as D7 built it): 0600, in a 0700 scratch directory.
        let mode = |p: &Path| {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap()
        };
        assert_eq!((mode(body), mode(body.parent().unwrap())), (0o600, 0o700), "the seed body {}", body.display());
        self.bodies.lock().unwrap().push(bytes.clone());
        if let Some(r) = self.refuse_next.lock().unwrap().pop_front() {
            return Ok(DpReply::refused(r));
        }
        Ok(self.apply(query, &bytes))
    }

    async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, req: &CodeoutRequest, dest: &Path, cap: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
        self.call(format!("POST /codeout wip={}", req.wip));
        self.flags.lock().unwrap().push(req.manifest_when_empty);
        assert_eq!(req.check(), Ok(()));
        if let Some(manifest) = self.forge_next.lock().unwrap().take() {
            std::fs::write(dest, b"").unwrap();
            return Ok(DpReply::ok(200, CodeoutBody { manifest, pack_bytes: 0 }));
        }
        Ok(self.codeout(req, dest, cap))
    }

    async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, rel: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
        self.call(format!("GET /transcript {rel}"));
        let p = self.projects.join(rel);
        Ok(DpReply::ok(
            200,
            match std::fs::read(&p) {
                Ok(b) => TranscriptStat { present: true, size: b.len() as u64, sha256: Some(sha256_hex(&b)), mtime: None, ..TranscriptStat::default() },
                Err(_) => TranscriptStat { present: false, size: 0, sha256: None, mtime: None, ..TranscriptStat::default() },
            },
        ))
    }

    async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
        Err(BridgeError::Endpoint("the fake VM keeps no settings".into()))
    }

    /// S9's extended stat of the projects directory's file, as the helper
    /// answers it (the request checked as the shim checks it): its inode, and
    /// with `from` the delta's sha256 and the fingerprints.
    async fn transcript_stat_from(&self, _: &AgentTarget, _: &AuthToken, q: &StatQuery) -> Result<DpReply<TranscriptStat>, BridgeError> {
        use std::os::unix::fs::MetadataExt as _;
        q.check().map_err(BridgeError::Config)?;
        self.call(format!("GET /transcript {} from={}", q.rel, q.from.map_or_else(|| "-".to_string(), |f| f.to_string())));
        let p = self.projects.join(&q.rel);
        let (Ok(bytes), Ok(md)) = (std::fs::read(&p), std::fs::metadata(&p)) else { return Ok(DpReply::ok(200, TranscriptStat::default())) };
        let size = bytes.len() as u64;
        let span = ai_env_cli::wire::s3::FP_SPAN;
        let mut stat = TranscriptStat { present: true, size, ino: Some(md.ino()), ..TranscriptStat::default() };
        if let Some(from) = q.from {
            if from <= size {
                stat.delta_sha256 = Some(sha256_hex(&bytes[from as usize..]));
            }
            stat.end_fp = Some(sha256_hex(&bytes[size.saturating_sub(span) as usize..]));
            if let Some(fp) = &q.fp {
                stat.fp_ok = Some(from <= size && sha256_hex(&bytes[from.saturating_sub(span) as usize..from as usize]) == *fp);
            }
        }
        Ok(DpReply::ok(200, stat))
    }

    /// S9's pull, as the shim and its curl do it: each part a GET of its
    /// presigned URL (the owner sent) from the tests' S3, its length and
    /// sha256 checked; the file written (0700 directories) only when every
    /// part passed: 201, else 200 with nothing written.
    async fn transcript_pull(&self, _: &AgentTarget, _: &AuthToken, req: &TranscriptPull) -> Result<DpReply<TranscriptPullReply>, BridgeError> {
        req.check().map_err(BridgeError::Config)?;
        self.call(format!("POST /transcript/pull {} parts={}", req.rel, req.parts.len()));
        let p = self.projects.join(&req.rel);
        let old = std::fs::metadata(&p).map_or(0, |m| m.len());
        let (mut out, mut reports) = (Vec::new(), Vec::new());
        for part in &req.parts {
            let (status, body) = lab_get(part.url.expose(), &req.owner);
            let got = sha256_hex(&body);
            let ok = status == 200 && body.len() as u64 == part.len && part.sha256.as_ref().is_none_or(|s| *s == got);
            reports.push(PullPartReport { s3_status: status, len: body.len() as u64, sha256: got, ok });
            if !ok {
                return Ok(DpReply::ok(200, TranscriptPullReply { written: false, size: old, sha256: None, parts: reports }));
            }
            out.extend_from_slice(&body);
        }
        let digest = sha256_hex(&out);
        if req.sha256.as_ref().is_some_and(|s| *s != digest) {
            return Ok(DpReply::ok(200, TranscriptPullReply { written: false, size: old, sha256: None, parts: reports }));
        }
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &out).unwrap();
        Ok(DpReply::ok(201, TranscriptPullReply { written: true, size: out.len() as u64, sha256: Some(digest), parts: reports }))
    }
}

/// One GET of a lab URL (`http://127.0.0.1:<port>/<bucket>/<key>?…`, the
/// tests' S3, which answers one request per connection) with the bucket
/// owner's header, as the VM's curl sends a pull's part: the status and the body.
fn lab_get(url: &str, owner: &str) -> (u16, Vec<u8>) {
    use std::io::{Read as _, Write as _};
    let rest = url.strip_prefix("http://").expect("a lab URL");
    let (host, path) = rest.split_at(rest.find('/').expect("a path"));
    let mut s = std::net::TcpStream::connect(host).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nhost: {host}\r\nx-amz-expected-bucket-owner: {owner}\r\nconnection: close\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("an answer's head");
    let status = String::from_utf8_lossy(&resp[..end]).split(' ').nth(1).and_then(|c| c.parse().ok()).expect("a status");
    (status, resp[end + 4..].to_vec())
}

/// sha256 of `bytes`, lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The manifest line and the pack of a seed body.
#[must_use]
pub fn split_body(body: &[u8]) -> (SeedManifest, Vec<u8>) {
    let nl = body.iter().position(|b| *b == b'\n').expect("a manifest line");
    (parse_head(&body[..nl]).expect("the manifest parses"), body[nl + 1..].to_vec())
}

/// The object ids a (complete) pack holds, read by `index-pack` in a throwaway bare repository.
#[must_use]
pub fn pack_objects(pack: &[u8]) -> Vec<String> {
    let tmp = tempfile::tempdir().unwrap();
    git(tmp.path(), &["init", "-q", "--bare", "x.git"]);
    let repo = tmp.path().join("x.git");
    let o = git_out(&repo, &["index-pack", "--stdin"], Some(pack));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let idx = std::fs::read_dir(repo.join("objects/pack")).unwrap().filter_map(Result::ok).map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "idx")).unwrap();
    let o = git_out(&repo, &["show-index"], Some(&std::fs::read(idx).unwrap()));
    let mut ids: Vec<String> = String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| l.split(' ').nth(1)).map(str::to_string).collect();
    ids.sort();
    ids
}

/// A head line, as the wire frames it (for a hand-made body).
#[must_use]
pub fn framed<T: serde::Serialize>(head: &T, payload: &[u8]) -> Vec<u8> {
    let mut out = head_line(head).unwrap();
    out.extend_from_slice(payload);
    out
}
