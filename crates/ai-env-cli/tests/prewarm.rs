//! S8 §11: the `auth status` prewarm. The wrapper, hard-linked beside a fake
//! `ai-env`, runs `auth status --json` in remote mode under the roots: the
//! sibling `vm warm <cwd> --prewarm` starts detached (its own session, stdio
//! on `/dev/null`, no inherited fd but the warm lock, the absolute sibling
//! path, never `PATH`), `auth status` is never delayed, and no prewarm starts
//! under the kill switch, outside the roots, without `touchid-gui` prompted or
//! without the sibling. Built in S8 wave 1 (W2).
//!
//! The fake `ai-env` records how it was started (its argv, pid, process
//! group and terminal through `ps`, its descriptors through
//! `/usr/sbin/lsof`, its environment's names), each probe run as a child of
//! its own so the shell's own descriptors stay as the wrapper left them. A
//! decoy `ai-env` first on `PATH` records that it ran, which no test allows.
mod common;

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Every wait here: the fake's record, a wrapper run.
const LIMIT: Duration = Duration::from_secs(30);
/// A run that pays a new executable's first exec, macOS's assessment
/// queued behind every other process's (up to 25 s seen under load).
const FIRST_EXEC_LIMIT: Duration = Duration::from_secs(120);

/// The sibling: what it was started with, read back from its record.
const FAKE_AI_ENV: &str = r#"#!/bin/sh
# The prewarm test's sibling `ai-env`: records how it was started, holding
# what it inherited (fd 3, the warm lock) for PREWARM_SLEEP seconds first.
log="${PREWARM_LOG:?}"
/usr/sbin/lsof -nP -a -p $$ -d 0-255 -F fn > "$log.lsof" 2>/dev/null
ps -o pid=,pgid=,tty= -p $$ > "$log.ps" 2>/dev/null
env | cut -d= -f1 > "$log.env"
sleep "${PREWARM_SLEEP:-0}"
{
  printf 'argv0=%s\n' "$0"
  for a in "$@"; do printf 'arg=%s\n' "$a"; done
  printf 'cwd=%s\n' "$(pwd)"
} > "$log.tmp" && mv "$log.tmp" "$log"
"#;

/// What a run of `ai-env` from `PATH` would leave: a mark the tests forbid.
const DECOY: &str = "#!/bin/sh\necho ran >> \"${PREWARM_LOG:?}.decoy\"\n";

/// The documentation account's made-up egress connector (a chat's plan needs one).
const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

/// `dir` made a git work tree by the real git (`git init`: no commit, its
/// HEAD unborn), with neither the system's nor a global config.
fn git_init(dir: &Path) {
    let o = Command::new(common::git_real())
        .args(["init", "-q"])
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "git init: {}", text(&o.stderr));
}

/// `script` as a cached 0755 file under the target's tempdir (one per
/// content: macOS assesses each new executable's first exec), hard-linked
/// at `dest` (copied on another filesystem).
fn install_script(script: &str, stem: &str, dest: &Path) {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    let digest = hex::encode(sha2::Sha256::digest(script.as_bytes()));
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("prewarm-fakes");
    std::fs::create_dir_all(&dir).unwrap();
    let master = dir.join(format!("{stem}-{}", &digest[..16]));
    if !master.exists() {
        // A file of its own per writer (tests run in parallel), renamed into place: the same bytes either way.
        let tmp = tempfile::Builder::new().prefix(&format!(".{stem}.")).tempfile_in(&dir).unwrap();
        std::fs::write(tmp.path(), script).unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        tmp.persist(&master).unwrap();
    }
    if std::fs::hard_link(&master, dest).is_err() {
        std::fs::copy(&master, dest).unwrap();
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// One tempdir: the wrapper hard-linked as `bin/ai-env-claude` (with the
/// fake `ai-env` beside it unless asked otherwise), a decoy `ai-env` in
/// `decoy/` first on `PATH`, the fake claude answering `auth status`, a
/// bridge root whose one root is `work/` (a git work tree with no commit)
/// and whose `[aws]` names the fake image and a connector (a chat's plan),
/// a `touchid-gui` row `prompted`.
struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl World {
    fn new(sibling: bool, bridge_toml: &str) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["bin", "decoy", "work", "bridge/lab", "elsewhere"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        git_init(&root.join("work"));
        let wrapper = root.join("bin").join("ai-env-claude");
        if std::fs::hard_link(env!("CARGO_BIN_EXE_ai-env-claude"), &wrapper).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_ai-env-claude"), &wrapper).unwrap();
        }
        if sibling {
            install_script(FAKE_AI_ENV, "ai-env", &root.join("bin").join("ai-env"));
        }
        install_script(DECOY, "decoy", &root.join("decoy").join("ai-env"));
        common::install_fake_v1(&root.join("claude"));
        let image = ai_env_cli::bridge::api::FAKE_IMAGE_ARN;
        let toml = format!("[aws]\nimage_arn = {image:?}\negress_connector_arn = {CONNECTOR:?}\n\n[workspaces]\nroots = [{:?}]\n{bridge_toml}", root.join("work"));
        std::fs::write(root.join("bridge").join("bridge.toml"), toml).unwrap();
        let w = World { _tmp: tmp, root };
        w.touchid_gui("prompted");
        w
    }

    /// The real `ai-env` as the sibling (hard-linked beside the wrapper).
    fn real_sibling(&self) {
        let dest = self.root.join("bin").join("ai-env");
        if std::fs::hard_link(env!("CARGO_BIN_EXE_ai-env"), &dest).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_ai-env"), &dest).unwrap();
        }
    }

    /// `text` appended to bridge.toml.
    fn add_config(&self, text: &str) {
        let path = self.root.join("bridge").join("bridge.toml");
        let mut toml = std::fs::read_to_string(&path).unwrap();
        toml.push_str(&format!("\n{text}"));
        std::fs::write(&path, toml).unwrap();
    }

    /// The workspace's warm lock file.
    fn warm_lock(&self) -> PathBuf {
        self.root.join("bridge").join("state").join("workspaces").join(format!("{}.warm.lock", ai_env_cli::wire::slug::project_dir_name(&self.root.join("work")).unwrap()))
    }

    /// The newest `touchid-gui` row's verdict.
    fn touchid_gui(&self, verdict: &str) {
        let row = serde_json::json!({ "probe": "touchid-gui", "stage": "S7", "verdict": verdict, "expected": "prompted", "ts": "2026-10-12T08:00:00Z" });
        std::fs::write(self.root.join("bridge").join("lab").join("probes.jsonl"), format!("{row}\n")).unwrap();
    }

    fn log(&self) -> PathBuf {
        self.root.join("prewarm.log")
    }

    /// The wrapper run as Cursor runs it for `args` in `cwd`: remote mode
    /// (unless `envs` says otherwise), the fake's knobs, a dummy token and
    /// key in the environment, the developer's knobs removed, and the four
    /// logs the fakes read set under the world's root, as the harness's own
    /// spawns set them (`Prepared::spawn`): a developer's exported
    /// `ARGV_LOG` never reaches a fake here (S9; S8's X1 open point 4).
    fn wrapper(&self, args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(self.root.join("bin").join("ai-env-claude"));
        cmd.arg(self.root.join("claude")).args(args).current_dir(cwd);
        for k in common::REMOVED_ENV {
            cmd.env_remove(k);
        }
        let token = format!("{}-{}-{}", "sk", "ant", "p".repeat(40));
        cmd.env("HOME", &self.root)
            .env("ARGV_LOG", self.root.join("argv.log"))
            .env("FAKE_STDIN_LOG", self.root.join("stdin.log"))
            .env("FAKE_ENV_LOG", self.root.join("env.log"))
            .env("FAKE_SPAWN_COUNT", self.root.join("spawn.count"))
            .env("AI_ENV_BRIDGE_DIR", self.root.join("bridge"))
            .env("PATH", format!("{}:/usr/bin:/bin", self.root.join("decoy").display()))
            .env("AI_ENV_BRIDGE_MODE", "remote")
            .env("PREWARM_LOG", self.log())
            .env("PREWARM_SLEEP", "0")
            .env("FAKE_STDOUT", r#"{"loggedIn":true}"#)
            .env("CLAUDE_CODE_OAUTH_TOKEN", token)
            .env("MY_SERVICE_API_KEY", "a-dummy-value");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd
    }

    /// Run it to its end within [`LIMIT`] (killed and failed past it), and how long it took.
    fn run(&self, args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> (Output, Duration) {
        let mut cmd = self.wrapper(args, cwd, envs);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let t = Instant::now();
        let child = cmd.spawn().unwrap();
        let out = common::bounded::finish_within(child, LIMIT, "the wrapper");
        (out, t.elapsed())
    }

    /// The census rows (the start row of each run).
    fn census(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.join("bridge").join("logs").join("census.jsonl")).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// The last start row's `prewarm:` part, if any.
    fn prewarm_note(&self) -> Option<String> {
        let rows = self.census();
        let note = rows.last()?["note"].as_str()?.to_string();
        note.split("; ").find(|p| p.starts_with("prewarm:")).map(str::to_string)
    }

    /// The fake's record once it finished writing it (within [`LIMIT`]).
    fn record(&self) -> Record {
        let t = Instant::now();
        while !self.log().exists() {
            assert!(t.elapsed() < LIMIT, "the sibling never recorded its start");
            std::thread::sleep(Duration::from_millis(25));
        }
        let read = |p: PathBuf| std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let text = read(self.log());
        let ps = read(self.log().with_extension("log.ps"));
        let mut ps = ps.split_whitespace();
        let (pid, pgid, tty) = (ps.next().unwrap().parse().unwrap(), ps.next().unwrap().parse().unwrap(), ps.next().unwrap_or_default().to_string());
        let mut fds = BTreeMap::new();
        let mut fd = None;
        for line in read(self.log().with_extension("log.lsof")).lines() {
            if let Some(n) = line.strip_prefix('f') {
                fd = n.parse::<u32>().ok();
            } else if let (Some(f), Some(name)) = (fd, line.strip_prefix('n')) {
                fds.insert(f, name.to_string());
            }
        }
        Record {
            argv0: text.lines().find_map(|l| l.strip_prefix("argv0=")).unwrap().to_string(),
            args: text.lines().filter_map(|l| l.strip_prefix("arg=")).map(str::to_string).collect(),
            cwd: text.lines().find_map(|l| l.strip_prefix("cwd=")).unwrap().to_string(),
            pid,
            pgid,
            tty,
            fds,
            env: read(self.log().with_extension("log.env")).lines().map(str::to_string).collect(),
        }
    }

    /// No sibling started: no record within a second, the decoy never ran.
    fn assert_no_prewarm(&self) {
        std::thread::sleep(Duration::from_millis(1000));
        assert!(!self.log().exists() && !self.log().with_extension("log.ps").exists(), "a prewarm started");
        assert!(!self.log().with_extension("log.decoy").exists(), "the decoy on PATH ran");
    }
}

/// How the sibling was started.
struct Record {
    argv0: String,
    args: Vec<String>,
    cwd: String,
    pid: u32,
    pgid: u32,
    tty: String,
    /// Its open descriptors and what each names.
    fds: BTreeMap<u32, String>,
    env: Vec<String>,
}

const AUTH_STATUS: [&str; 3] = ["auth", "status", "--json"];

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A vpc row of the workspace `work` as SELECT_VM writes one: the fake
/// image at `version`, the connector, two hours of wall left.
fn vpc_row(work: &Path, id: &str, status: ai_env_cli::bridge::vm::registry::RowStatus, version: &str) -> ai_env_cli::bridge::vm::registry::VmRow {
    ai_env_cli::bridge::vm::registry::VmRow {
        id: id.into(),
        status,
        client_token: uuid::Uuid::now_v7().to_string(),
        workspace: Some(work.display().to_string()),
        image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(),
        image_version: version.into(),
        wall_deadline: Some(ai_env_cli::wire::time::unix_now() + 7200),
        egress: "vpc".into(),
        egress_connectors: vec![CONNECTOR.into()],
        ..ai_env_cli::bridge::vm::registry::VmRow::default()
    }
}

/// The prewarm: `ai-env vm warm <cwd> --prewarm` from the absolute sibling
/// (never the decoy on `PATH`), in a session of its own with no terminal,
/// stdio on `/dev/null`, fd 3 the workspace's warm lock and no other
/// descriptor, cwd `/`, no credential-shaped name in its environment; the
/// warm lock held while it runs; `auth status` answered as ever. The
/// wrapper's parent here leaves a file open on fd 7 without close-on-exec,
/// as a careless parent may: the wrapper's close loop alone keeps it from
/// the sibling.
#[test]
fn prewarm_spawns_the_sibling_detached_with_null_stdio_and_no_inherited_fds() {
    let w = World::new(true, "");
    let work = w.root.join("work");
    let leaked = w.root.join("inherited-by-the-wrapper.txt");
    std::fs::write(&leaked, "open in the wrapper's parent\n").unwrap();
    // A shell parent opens the file on fd 7 (a redirection: no close-on-exec) and execs the wrapper with the
    // wrapper's own environment and cwd (`World::wrapper`).
    let wrapper = w.wrapper(&AUTH_STATUS, &work, &[("PREWARM_SLEEP", "2")]);
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "exec 7<\"$1\"; shift; exec \"$@\"", "sh"]).arg(&leaked).arg(wrapper.get_program()).args(wrapper.get_args());
    if let Some(dir) = wrapper.get_current_dir() {
        cmd.current_dir(dir);
    }
    for (k, v) in wrapper.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    let o = common::bounded::run_within(cmd, None, LIMIT, "the wrapper under its shell parent");
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "{\"loggedIn\":true}\n", "auth status answered by the real binary");
    assert!(o.stderr.is_empty(), "nothing said: {}", text(&o.stderr));
    // While the prewarm runs, the warm lock is its.
    let lock = w.root.join("bridge").join("state").join("workspaces").join(format!("{}.warm.lock", ai_env_cli::wire::slug::project_dir_name(&work).unwrap()));
    let held = std::fs::File::open(&lock).unwrap();
    use std::os::fd::AsRawFd as _;
    // SAFETY: flock(2) on a descriptor this test owns, without waiting.
    assert_ne!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0, "the prewarm holds the warm lock");
    let r = w.record();
    assert_eq!(r.argv0, w.root.join("bin").join("ai-env").display().to_string(), "the absolute sibling");
    assert_eq!(r.args, ["vm", "warm", work.to_str().unwrap(), "--prewarm"]);
    assert_eq!(r.cwd, "/");
    assert_eq!((r.pgid, r.tty.as_str()), (r.pid, "??"), "setsid: its own session and group, no terminal");
    for fd in 0..3 {
        assert_eq!(r.fds.get(&fd).map(String::as_str), Some("/dev/null"), "fd {fd}: {:?}", r.fds);
    }
    assert_eq!(r.fds.get(&3).map(PathBuf::from), Some(lock.clone()), "fd 3: {:?}", r.fds);
    assert!(!r.fds.values().any(|name| name.ends_with("inherited-by-the-wrapper.txt")), "the wrapper's inherited fd 7 reached the prewarm: {:?}", r.fds);
    let script = |name: &str| Path::new(name).file_name().is_some_and(|f| f.to_string_lossy().starts_with("ai-env"));
    let others: Vec<(&u32, &String)> = r.fds.iter().filter(|(fd, name)| **fd > 3 && !script(name)).collect();
    assert!(others.is_empty(), "nothing else inherited: {others:?}");
    for gone in ["CLAUDE_CODE_OAUTH_TOKEN", "MY_SERVICE_API_KEY"] {
        assert!(!r.env.iter().any(|n| n == gone), "{gone} reached the prewarm");
    }
    assert!(r.env.iter().any(|n| n == "PREWARM_LOG") && r.env.iter().any(|n| n == "AI_ENV_BRIDGE_DIR"), "the rest is inherited");
    assert!(!w.log().with_extension("log.decoy").exists(), "PATH was never searched");
}

/// `auth status` is never delayed: the wrapper waits for two forks, never
/// for the sibling (here sleeping 6 s before it records anything), so it
/// answers long before the sibling is done (the bound leaves room for a
/// loaded Mac: the tests run in parallel). The bound times the prewarm, not
/// macOS: it assesses each new executable at its first exec, one at a time
/// for the whole system (seconds under load), and `cargo test` gives the
/// wrapper a new inode at every run, the target's tempdir the fakes on a
/// fresh clone. So every first exec of the timed run is paid before it,
/// untimed: the kill switch's run execs the wrapper and the fake claude,
/// and the sibling is run once on its own.
#[test]
fn prewarm_never_delays_auth_status() {
    let w = World::new(true, "");
    let work = w.root.join("work");
    let first = common::bounded::run_within(w.wrapper(&AUTH_STATUS, &work, &[("AI_ENV_BRIDGE_LOCAL", "1")]), None, FIRST_EXEC_LIMIT, "the wrapper's first exec");
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    let mut sibling = Command::new(w.root.join("bin").join("ai-env"));
    sibling.env("PREWARM_LOG", w.root.join("first-exec.log")).env("PREWARM_SLEEP", "0");
    let first = common::bounded::run_within(sibling, None, FIRST_EXEC_LIMIT, "the sibling's first exec");
    assert!(first.status.success(), "{}", text(&first.stderr));
    let (o, took) = w.run(&AUTH_STATUS, &work, &[("PREWARM_SLEEP", "6")]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(took < Duration::from_secs(4), "auth status took {took:?}");
    assert!(!w.log().exists(), "the sibling had not finished when auth status answered");
    w.record();
}

/// The census start row says what the prewarm did: `prewarm:spawned(<pid>)`
/// naming the sibling's pid; the spawn is audited `prewarm`.
#[test]
fn prewarm_is_recorded_in_the_census_with_the_siblings_pid() {
    let w = World::new(true, "");
    let (o, _) = w.run(&AUTH_STATUS, &w.root.join("work"), &[]);
    assert_eq!(o.status.code(), Some(0));
    let r = w.record();
    assert_eq!(w.prewarm_note(), Some(format!("prewarm:spawned({})", r.pid)));
    let note = w.census().last().unwrap()["note"].as_str().unwrap().to_string();
    assert!(note.split("; ").any(|p| p == "mode:remote"), "{note}");
    let audit = std::fs::read_to_string(w.root.join("bridge").join("audit.jsonl")).unwrap();
    let row: Value = audit.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).find(|r| r["event"] == "prewarm").expect("a prewarm row");
    assert_eq!((row["detail"]["pid"].as_str(), row["detail"]["setting"].as_str()), (Some(r.pid.to_string().as_str()), Some("auto")));
}

/// No prewarm without `touchid-gui` `prompted` (none, or another verdict
/// newest), nor with the cwd outside the roots; the row says why.
#[test]
fn prewarm_needs_touchid_gui_prompted_and_cwd_under_roots() {
    let w = World::new(true, "");
    w.touchid_gui("terminal-only");
    let (o, _) = w.run(&AUTH_STATUS, &w.root.join("work"), &[]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(touchid_gui)"));
    std::fs::remove_file(w.root.join("bridge").join("lab").join("probes.jsonl")).unwrap();
    w.run(&AUTH_STATUS, &w.root.join("work"), &[]);
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(touchid_gui)"), "no row at all");
    w.touchid_gui("prompted");
    w.run(&AUTH_STATUS, &w.root.join("elsewhere"), &[]);
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(outside_roots)"));
    let never = World::new(true, "[vm]\nprewarm_on_auth_status = \"never\"\n");
    never.run(&AUTH_STATUS, &never.root.join("work"), &[]);
    assert_eq!(never.prewarm_note().as_deref(), Some("prewarm:skipped(never)"));
    w.assert_no_prewarm();
    never.assert_no_prewarm();
}

/// `auto` prewarms a cold start only: a reusable VM row of the workspace
/// skips it (`token_held` when a running VM holds the sealed token, its row
/// naming the seal; `vm_exists` for a suspended one, its cache emptied);
/// `always` prewarms whatever the rows say (plan §11), the VM that holds the
/// token included (its checkout is seeded again).
#[test]
fn prewarm_is_skipped_when_the_vm_already_holds_the_token_or_a_reusable_vm_exists() {
    use ai_env_cli::bridge::config::Paths;
    use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow};
    let row = |work: &Path, id: &str, status: RowStatus, tag: Option<String>| VmRow {
        credential_at: tag.as_ref().map(|_| 1),
        credential_tag: tag,
        ..vpc_row(work, id, status, "1.0")
    };
    let seal = |paths: &Paths| {
        std::fs::create_dir_all(paths.credentials()).unwrap();
        std::fs::write(paths.setup_token_env(), "a sealed container's text").unwrap();
        ai_env_cli::bridge::agent::credential::seal_tag(&paths.setup_token_env())
    };
    let w = World::new(true, "");
    let paths = Paths::from_root_and_env(w.root.join("bridge"), None);
    let work = w.root.join("work");
    let tag = seal(&paths);
    let mut held = row(&work, "microvm-warm00001", RowStatus::Suspended, tag.clone());
    registry::write_row(&paths, &held).unwrap();
    w.run(&AUTH_STATUS, &work, &[]);
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(vm_exists)"), "a suspended VM's cache is empty");
    held.status = RowStatus::Running;
    registry::write_row(&paths, &held).unwrap();
    w.run(&AUTH_STATUS, &work, &[]);
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(token_held)"));
    w.assert_no_prewarm();
    let always = World::new(true, "[vm]\nprewarm_on_auth_status = \"always\"\n");
    let paths = Paths::from_root_and_env(always.root.join("bridge"), None);
    let work = always.root.join("work");
    let tag = seal(&paths);
    registry::write_row(&paths, &row(&work, "microvm-warm00002", RowStatus::Running, tag)).unwrap();
    always.run(&AUTH_STATUS, &work, &[]);
    let r = always.record();
    assert_eq!(always.prewarm_note(), Some(format!("prewarm:spawned({})", r.pid)), "always: warmed though the VM holds the token");
}

/// Without the sibling next to the wrapper: one stderr line naming it, no
/// prewarm, the decoy on `PATH` never run, `auth status` answered as ever.
#[test]
fn a_missing_sibling_is_one_note_and_no_prewarm() {
    let w = World::new(false, "");
    let (o, _) = w.run(&AUTH_STATUS, &w.root.join("work"), &[]);
    assert_eq!((o.status.code(), text(&o.stdout)), (Some(0), "{\"loggedIn\":true}\n".to_string()));
    let err = text(&o.stderr);
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 1, "{err}");
    assert!(lines[0].starts_with("ai-env-claude: ai-env is only on PATH (") && lines[0].contains("no prewarm"), "{err}");
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(no_sibling)"));
    w.assert_no_prewarm();
}

/// The kill switch execs the real binary before anything else: no prewarm,
/// no census row, and no `prewarm` audit row (the wrapper writes that one
/// before its spawn, so a prewarm the fake's record misses still shows:
/// phase 4's mutation check, M44).
#[test]
fn the_kill_switch_never_prewarms() {
    let w = World::new(true, "");
    let (o, _) = w.run(&AUTH_STATUS, &w.root.join("work"), &[("AI_ENV_BRIDGE_LOCAL", "1")]);
    assert_eq!(o.status.code(), Some(0));
    assert!(w.census().is_empty(), "no census row under the kill switch");
    let audit = std::fs::read_to_string(w.root.join("bridge").join("audit.jsonl")).unwrap_or_default();
    assert!(!audit.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).any(|r| r["event"] == "prewarm"), "a prewarm audit row under the kill switch: {audit}");
    w.assert_no_prewarm();
}

/// Only exactly `auth status --json` in remote mode prewarms: passthrough
/// (the default) and another argv leave no `prewarm:` part at all.
#[test]
fn only_auth_status_json_in_remote_mode_prewarms() {
    let w = World::new(true, "");
    let work = w.root.join("work");
    w.run(&AUTH_STATUS, &work, &[("AI_ENV_BRIDGE_MODE", "passthrough")]);
    assert_eq!(w.prewarm_note(), None);
    w.run(&["auth", "status"], &work, &[]);
    assert_eq!(w.prewarm_note(), None);
    w.run(&["mcp", "list"], &work, &[]);
    assert_eq!(w.prewarm_note(), None);
    w.assert_no_prewarm();
    // [wrapper].mode = "remote" without the variable prewarms too.
    let config = World::new(true, "[wrapper]\nmode = \"remote\"\n");
    let mut cmd = config.wrapper(&AUTH_STATUS, &config.root.join("work"), &[]);
    cmd.env_remove("AI_ENV_BRIDGE_MODE");
    assert!(common::bounded::run_within(cmd, None, LIMIT, "the wrapper").status.success());
    let r = config.record();
    assert_eq!(config.prewarm_note(), Some(format!("prewarm:spawned({})", r.pid)));
}

// ---- S8 phase 4 (F3): what no chat would use is never warmed; the cool-down holds -----------

/// A workspace no chat could use gets no prewarm (POLICY-1): under the
/// roots but in no git work tree, a session refuses it at its P0 (D6), so
/// the census says `not_git` and no sibling starts.
#[test]
fn a_cwd_in_no_git_work_tree_is_never_prewarmed() {
    let w = World::new(true, "");
    let plain = w.root.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    w.add_config(&format!("[[workspace]]\npath = {plain:?}\n"));
    let (o, _) = w.run(&AUTH_STATUS, &plain, &[]);
    assert_eq!((o.status.code(), text(&o.stdout)), (Some(0), "{\"loggedIn\":true}\n".to_string()), "{}", text(&o.stderr));
    assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(not_git)"));
    w.assert_no_prewarm();
}

/// `auto` follows SELECT_VM's own rule (POLICY-3): after a deploy
/// (`state/infra.toml` records 2.0 active), a running row of the workspace
/// at 1.0 is a VM the chat passes over, starting one of its own in
/// Cursor's window, so the prewarm warms one; a row at 2.0 is the chat's
/// VM: `vm_exists`.
#[test]
fn a_vm_of_another_image_version_never_skips_auto() {
    use ai_env_cli::bridge::config::Paths;
    use ai_env_cli::bridge::vm::registry::{self, RowStatus};
    let deployed = |w: &World, version: &str| {
        let state = w.root.join("bridge").join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("infra.toml"), format!("image_arn = {:?}\nlatest_active_image_version = \"2.0\"\n", ai_env_cli::bridge::api::FAKE_IMAGE_ARN)).unwrap();
        let work = w.root.join("work");
        registry::write_row(&Paths::from_root_and_env(w.root.join("bridge"), None), &vpc_row(&work, &format!("microvm-v{}0001", version.replace('.', "")), RowStatus::Running, version)).unwrap();
        work
    };
    let old = World::new(true, "");
    let work = deployed(&old, "1.0");
    old.run(&AUTH_STATUS, &work, &[]);
    let note = old.prewarm_note().unwrap_or_default();
    assert!(note.starts_with("prewarm:spawned("), "the chat would start a 2.0 VM: {note}");
    assert_eq!(note, format!("prewarm:spawned({})", old.record().pid));
    let new = World::new(true, "");
    let work = deployed(&new, "2.0");
    new.run(&AUTH_STATUS, &work, &[]);
    assert_eq!(new.prewarm_note().as_deref(), Some("prewarm:skipped(vm_exists)"), "the chat's VM");
    new.assert_no_prewarm();
}

/// What no chat would use is never warmed, whatever the setting
/// (POLICY-3): with `AI_ENV_BRIDGE_VM` in Cursor's environment the chats
/// take that VM (`pinned`); with `[vm] reuse_per_workspace = false` no chat
/// reuses a warmed VM (`reuse_off`). No sibling starts.
#[test]
fn a_pin_or_reuse_off_never_prewarms() {
    let pinned = World::new(true, "[vm]\nprewarm_on_auth_status = \"always\"\n");
    pinned.run(&AUTH_STATUS, &pinned.root.join("work"), &[("AI_ENV_BRIDGE_VM", "microvm-pinned0001")]);
    assert_eq!(pinned.prewarm_note().as_deref(), Some("prewarm:skipped(pinned)"));
    let off = World::new(true, "[vm]\nreuse_per_workspace = false\n");
    off.run(&AUTH_STATUS, &off.root.join("work"), &[]);
    assert_eq!(off.prewarm_note().as_deref(), Some("prewarm:skipped(reuse_off)"));
    pinned.assert_no_prewarm();
    off.assert_no_prewarm();
}

/// The cool-down holds prewarm after prewarm (LIFECYCLE-1). The wrapper
/// reads the warm lock's last record through the open file it hands the
/// prewarm on fd 3, and the real `ai-env vm warm --prewarm` writes its own
/// from the file's first byte, never behind a hole of NULs, so the next
/// `auth status` finds its `finished_at` and is `recent`. The sibling here
/// is the real `ai-env`: `work` has no commit (an unborn HEAD), which it
/// refuses at its prechecks (exit 1, before any Touch ID or AWS call, said
/// in its log), its run recorded all the same. Between rounds two minutes
/// pass: `finished_at` is aged in place, the file's length kept.
#[test]
fn the_cool_down_holds_prewarm_after_prewarm() {
    use std::os::fd::AsRawFd as _;
    let w = World::new(false, "");
    w.real_sibling();
    let work = w.root.join("work");
    let lock = w.warm_lock();
    for round in 1..=3 {
        w.run(&AUTH_STATUS, &work, &[]);
        let note = w.prewarm_note().unwrap_or_default();
        assert!(note.starts_with("prewarm:spawned("), "round {round}: {note}");
        // Its end: the lock free, the record finished.
        let t = Instant::now();
        let record = loop {
            let bytes = std::fs::read(&lock).unwrap_or_default();
            // SAFETY: flock(2) on a descriptor this test owns, without waiting; its close releases it.
            let free = std::fs::File::open(&lock).is_ok_and(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0);
            if free && text(&bytes).contains("finished_at=") {
                break bytes;
            }
            assert!(t.elapsed() < LIMIT, "round {round}: the prewarm never ended: {:?}", text(&bytes));
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(record.starts_with(b"pid=") && !record.contains(&0), "round {round}: the record from the first byte: {:?}", text(&record));
        w.run(&AUTH_STATUS, &work, &[]);
        assert_eq!(w.prewarm_note().as_deref(), Some("prewarm:skipped(recent)"), "round {round}: right after its end");
        let aged: String = text(&record)
            .lines()
            .map(|l| match l.strip_prefix("finished_at=").and_then(|at| at.parse::<u64>().ok()) {
                Some(at) => format!("finished_at={}\n", at - 300),
                None => format!("{l}\n"),
            })
            .collect();
        assert_eq!(aged.len(), record.len(), "{aged}");
        std::fs::write(&lock, aged).unwrap();
    }
    let log = std::fs::read_to_string(w.root.join("bridge").join("logs").join("ai-env.log")).unwrap_or_default();
    assert_eq!(log.matches("no prewarm: workspace failed (unsupported_repo)").count(), 3, "each refused at its prechecks: {log}");
}

// ---- phase 4 F9: the prewarm's cost to auth status (T8.6 offline, make perf-wrapper PREWARM=1) ----

/// The perf test's sibling: it exits at once (only the prewarm's start is
/// on `auth status`'s path; the real `vm warm --prewarm` runs on, detached),
/// so the warm lock is free again by the next run, and it writes no warm
/// record, whose cool-down would skip the next prewarm.
const STAND_IN: &str = "#!/bin/sh\nexit 0\n";

/// The median of `samples` in milliseconds (T1.2's rule, `tests/wrapper.rs`:
/// the mean of the two middle values for an even count).
fn median_ms(samples: &mut [Duration]) -> f64 {
    samples.sort();
    let n = samples.len();
    let mid = if n.is_multiple_of(2) { (samples[n / 2 - 1] + samples[n / 2]) / 2 } else { samples[n / 2] };
    mid.as_secs_f64() * 1000.0
}

/// Until no process holds `lock` (the last prewarm's sibling gone), within [`LIMIT`].
fn wait_until_free(lock: &Path) {
    use std::os::fd::AsRawFd as _;
    let t = Instant::now();
    loop {
        let free = match std::fs::File::open(lock) {
            Err(_) => true,
            Ok(f) => {
                // SAFETY: flock(2) on a descriptor this test owns, without waiting; closing it lets go.
                let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                rc == 0
            }
        };
        if free {
            return;
        }
        assert!(t.elapsed() < LIMIT, "the warm lock stayed held");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// T8.6's offline half (plans/s8-design-tests.md §2.1; `make perf-wrapper
/// PREWARM=1`: release, `AI_ENV_PERF_TESTS=1`): `auth status --json` in
/// remote mode under the roots, `touchid-gui` prompted, the prewarm
/// spawning a stand-in sibling on every run (its census row says so),
/// against the same world with `prewarm_on_auth_status = "never"` and
/// against the fake exec'd by itself: 100 interleaved rounds, each world
/// run once untimed first (macOS assesses a new executable's first exec),
/// the warm lock free again before each round. Two medians are judged,
/// each within 10 ms: with the prewarm against without it (B8's equal
/// latency), and with the prewarm against the bare exec (T1.2's measure:
/// v6 holds `auth status`'s startup cost to it).
#[test]
#[ignore = "perf measurement: make perf-wrapper PREWARM=1 (AI_ENV_PERF_TESTS=1, release)"]
fn t8_6_prewarm_auth_status_overhead_median_100_runs() {
    if std::env::var("AI_ENV_PERF_TESTS").ok().as_deref() != Some("1") {
        eprintln!("t8_6_prewarm_auth_status_overhead_median_100_runs: skipped (set AI_ENV_PERF_TESTS=1)");
        return;
    }
    let on = World::new(false, "");
    let off = World::new(false, "[vm]\nprewarm_on_auth_status = \"never\"\n");
    for w in [&on, &off] {
        install_script(STAND_IN, "stand-in", &w.root.join("bin").join("ai-env"));
    }
    let work = on.root.join("work");
    let lock = on.root.join("bridge").join("state").join("workspaces").join(format!("{}.warm.lock", ai_env_cli::wire::slug::project_dir_name(&work).unwrap()));
    let timed = |w: &World, want: &str| -> Duration {
        let cmd = w.wrapper(&AUTH_STATUS, &w.root.join("work"), &[]);
        let t = Instant::now();
        let o = common::bounded::run_within(cmd, None, FIRST_EXEC_LIMIT, "the wrapper");
        let took = t.elapsed();
        assert_eq!((o.status.code(), text(&o.stdout)), (Some(0), "{\"loggedIn\":true}\n".to_string()), "{}", text(&o.stderr));
        let note = w.prewarm_note().unwrap_or_default();
        assert!(note.starts_with(want), "every run's census row says {want}: {note}");
        took
    };
    // The fake exec'd by itself with the wrapper's environment (T1.2's comparison).
    let bare = |w: &World| -> Duration {
        let wrapped = w.wrapper(&AUTH_STATUS, &w.root.join("work"), &[]);
        let mut cmd = Command::new(w.root.join("claude"));
        cmd.args(AUTH_STATUS).current_dir(w.root.join("work"));
        for (k, v) in wrapped.get_envs() {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        let t = Instant::now();
        let o = common::bounded::run_within(cmd, None, FIRST_EXEC_LIMIT, "the fake claude");
        let took = t.elapsed();
        assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
        took
    };
    let (spawned, never) = ("prewarm:spawned(", "prewarm:skipped(never)");
    // Each world's first exec of its wrapper (a new inode) and of the fakes, untimed.
    timed(&on, spawned);
    timed(&off, never);
    bare(&off);
    let (mut with, mut without, mut alone) = (Vec::with_capacity(100), Vec::with_capacity(100), Vec::with_capacity(100));
    for i in 0..100 {
        wait_until_free(&lock);
        if i % 2 == 0 {
            with.push(timed(&on, spawned));
            without.push(timed(&off, never));
        } else {
            without.push(timed(&off, never));
            with.push(timed(&on, spawned));
        }
        alone.push(bare(&off));
    }
    let (w, wo, b) = (median_ms(&mut with), median_ms(&mut without), median_ms(&mut alone));
    let (delta, over_bare) = (w - wo, w - b);
    println!("T8.6 prewarm overhead: auth status median {w:.2} ms with the prewarm, {wo:.2} ms without, delta {delta:.2} ms; the fake alone {b:.2} ms, the prewarm's run {over_bare:.2} ms over it (budget 10 ms each)");
    assert!(delta <= 10.0, "the prewarm adds {delta:.2} ms to auth status's median, over the 10 ms budget (with {w:.2} ms, without {wo:.2} ms)");
    assert!(over_bare <= 10.0, "auth status with the prewarm is {over_bare:.2} ms over a bare exec of the fake, over T1.2's 10 ms budget (with {w:.2} ms, the fake alone {b:.2} ms)");
}

/// `common::bounded` itself (every wait bounded, S8's rule): a child that
/// never ends fails its test at the bound, killed and reaped, instead of
/// hanging it and the gate; a child that ends while a process it left still
/// holds its stdout fails too, once the readers' last second is up.
#[test]
fn a_hung_child_or_a_held_pipe_fails_at_its_bound() {
    let caught = |child: std::process::Child, limit: Duration, what: &'static str| -> Option<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || common::bounded::finish_within(child, limit, what)));
            let _ = tx.send(r.err().and_then(|e| e.downcast::<String>().ok()).map(|s| *s));
        });
        rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| panic!("{what}: the bound never fired, the wait still runs after 10 s"))
    };
    let hung = Command::new("/bin/sleep").arg("600").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = libc::pid_t::try_from(hung.id()).unwrap();
    assert_eq!(caught(hung, Duration::from_millis(300), "sleep 600").as_deref(), Some("sleep 600 ran past 300ms (killed)"));
    // SAFETY: kill(2) with signal 0 only asks whether the pid exists.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "the hung child was killed and reaped");
    let tmp = tempfile::tempdir().unwrap();
    let left = tmp.path().join("left.pid");
    let held = Command::new("/bin/sh").args(["-c", "/bin/sleep 30 & echo $! > \"$1\"; exit 0", "sh"]).arg(&left).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let said = caught(held, Duration::from_millis(300), "sh");
    let orphan: libc::pid_t = std::fs::read_to_string(&left).unwrap().trim().parse().unwrap();
    // SAFETY: kill(2) of the sleep this test's shell left behind.
    unsafe { libc::kill(orphan, libc::SIGKILL) };
    assert!(said.as_deref().is_some_and(|s| s.starts_with("sh exited (") && s.ends_with("but its stdout stayed open: a process it left holds it")), "{said:?}");
}

// ---- S9 (G7): the fakes' logs --------------------------------------------------------------------

/// S9 (S8's X1 open point 4): the wrapper here runs with the four logs the
/// fakes read set under the world's root, as the harness's own spawns set
/// them (`Prepared::spawn`), so a developer's exported `ARGV_LOG` (or
/// another of them) never reaches this file's fake claude: under the kill
/// switch the fake runs in the wrapper's place and logs its argv in the
/// world's log.
#[test]
fn the_wrapper_sets_the_four_logs_the_fakes_read_under_its_root() {
    let w = World::new(true, "");
    let cmd = w.wrapper(&AUTH_STATUS, &w.root.join("work"), &[("AI_ENV_BRIDGE_LOCAL", "1")]);
    let envs: BTreeMap<String, Option<PathBuf>> = cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(PathBuf::from))).collect();
    for name in ["ARGV_LOG", "FAKE_STDIN_LOG", "FAKE_ENV_LOG", "FAKE_SPAWN_COUNT"] {
        assert!(envs.get(name).and_then(Option::as_ref).is_some_and(|p| p.starts_with(&w.root)), "{name} is not set under the world's root: {envs:?}");
    }
    let o = common::bounded::run_within(cmd, None, LIMIT, "the wrapper under the kill switch");
    assert_eq!((o.status.code(), text(&o.stdout)), (Some(0), "{\"loggedIn\":true}\n".to_string()), "{}", text(&o.stderr));
    let argv = std::fs::read_to_string(w.root.join("argv.log")).unwrap_or_default();
    assert_eq!(argv.lines().collect::<Vec<_>>(), AUTH_STATUS, "the fake claude logged its argv in the world's log");
}
