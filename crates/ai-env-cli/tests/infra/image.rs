//! The S3 Makefile and infra/infra.mk recipes through `make` itself, and the
//! ops.sh image wait through /bin/bash, with every path in a temp dir and
//! every outside tool a fake first on PATH (tests/fakes/: curl, gpg, docker,
//! a stateful aws, cargo-lambda, an `ai-env` stand-in, and logged.sh for the
//! tools that must not run). The make child is isolated like `ai_env`
//! (common::isolate). Nothing reaches AWS, the network, docker, a real gpg
//! keyring or the real keystore. `image-stage-scan` runs on a planted copy of
//! image/ with this test run's binary as AI_ENV. The S5 section drives the
//! egress ops of ops.sh and the new targets with a stateful aws, a pulumi and
//! the `ai-env` stand-in, `make deploy` whole in a planted repo. The S8
//! section drives s8-smoke, test-cursor, doc-test and `make acceptance`
//! (stand-ins for what is live, the real `ai-env` and `ai-env-claude` for
//! what runs offline), and holds the scrub lists to every knob the code and
//! the fakes read. Every child runs under a deadline ([`Bounded`]).
use super::common::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const CLAUDE_VERSION: &str = "2.1.283";
/// How long any child of these tests may run (the real plan check compiles
/// check-plan.ts with tsc first).
const DEADLINE: Duration = Duration::from_secs(240);

/// Every child of these tests runs under [`DEADLINE`]: in a process group of
/// its own, its output drained on two threads, and the whole group (make, its
/// shells, the fakes) killed when the deadline passes.
trait Bounded {
    fn bounded(&mut self) -> Output;
}

impl Bounded for Command {
    fn bounded(&mut self) -> Output {
        run_bounded(self, |_| {})
    }
}

/// [`Bounded::bounded`], with `during` called with the child's pid (its
/// process group) once it runs: a test that signals the group mid-run.
fn run_bounded(cmd: &mut Command, during: impl FnOnce(u32)) -> Output {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    // The program and its arguments only: std's Debug of a Command prints every variable set on it, and these tests set
    // the runner's key on theirs (contracts §4.3).
    let what = std::iter::once(cmd.get_program()).chain(cmd.get_args()).map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ");
    let mut child = cmd.process_group(0).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{what}: {e}"));
    let start = Instant::now();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    };
    let out = drain(Box::new(child.stdout.take().unwrap()));
    let err = drain(Box::new(child.stderr.take().unwrap()));
    let pid = child.id();
    during(pid);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > DEADLINE {
            kill_group(pid);
            let _ = child.wait();
            panic!("{what}: still running after {DEADLINE:?}: its process group was killed");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // A grandchild still holding a pipe (a background sleep) must not hang the test either.
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| match rx.recv_timeout(DEADLINE.saturating_sub(start.elapsed())) {
        Ok(buf) => buf,
        Err(_) => {
            kill_group(pid);
            panic!("{what}: its output was still open after {DEADLINE:?}: its process group was killed");
        }
    };
    Output { status, stdout: collect(out), stderr: collect(err) }
}

fn kill_group(pid: u32) {
    signal_group(pid, libc::SIGKILL);
}

fn signal_group(pid: u32, sig: libc::c_int) {
    // SAFETY: kill(2) of the process group this test created (process_group(0) made the child its leader).
    unsafe { libc::kill(-(pid as libc::pid_t), sig) };
}

/// A child that cannot start (or outlives [`DEADLINE`]) is named by its program and arguments only: std's Debug of a
/// Command prints every variable set on it, and the make tests set the runner's key on theirs (contracts §4.3, A8).
#[test]
fn a_child_is_named_by_its_program_and_arguments_never_its_environment() {
    let secret = super::aws_keys::secret("Zq8+");
    let mut cmd = Command::new("/nonexistent/f1-make");
    cmd.arg("deploy").env("AWS_SECRET_ACCESS_KEY", &secret);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cmd.bounded())).expect_err("a program that does not exist never runs");
    let text = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(text.starts_with("/nonexistent/f1-make deploy: "), "named by its program and arguments: {text}");
    assert!(!text.contains(&secret) && !text.contains("AWS_SECRET_ACCESS_KEY"), "the environment of the command in a panic: {text}");
}

fn fake(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

/// `<tmp>/bin` holding each `(fake, tool name)` of tests/fakes/.
fn bin_with(tmp: &Path, fakes: &[(&str, &str)]) -> PathBuf {
    let bin = tmp.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (src, name) in fakes {
        let dst = bin.join(name);
        std::fs::copy(fake(src), &dst).unwrap_or_else(|e| panic!("{src}: {e}"));
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

/// A small executable script at `path`.
fn script(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `make -s -C <repo> <args>`, isolated (common::isolate), PATH `<bin>:/usr/bin:/bin`.
fn make(tmp: &Path, bin: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("make");
    isolate(&mut cmd, tmp).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    cmd.args(["-s", "--no-print-directory", "-C", REPO]).args(args);
    cmd
}

/// What `$(MAKE)` is in the make these tests run (`make` from PATH; on macOS the xcrun shim runs Xcode's make under
/// its full path, which make then names), as a runner line (`ai-env as T -- $(MAKE) ...`) shows it.
fn make_path() -> String {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("m.mk"), "all:\n\t@echo '$(MAKE)'\n").unwrap();
        let mut cmd = Command::new("make");
        isolate(&mut cmd, t.path()).env("PATH", "/usr/bin:/bin");
        let out = cmd.arg("-s").arg("-f").arg(t.path().join("m.mk")).bounded();
        assert!(out.status.success(), "{}", all(&out));
        stdout(&out).trim().to_string()
    })
    .clone()
}

fn all(o: &Output) -> String {
    format!("{}{}", stdout(o), stderr(o))
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn lines_of(p: &Path) -> Vec<String> {
    read(p).lines().map(str::to_string).collect()
}

// ---- image-stage-scan ----

/// A copy of image/ under `tmp/img`, with a stand-in for the cross-built
/// shim (the real one is not needed to test the wiring).
/// The S3 baseline of `image/claude/settings.json`. The planted images use it
/// whatever the repository's holds, so a rule a T8.7 promotion committed there
/// (`wrapper settings-sync --write`, its allow line in the operator's policy)
/// never changes what these tests see.
const BASE_SETTINGS: &str = "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[]}}\n";

/// The repository's image files under `<tmp>/img`, its settings as the
/// repository holds them, with a stand-in for the cross-built shim.
fn copied_image(tmp: &Path) -> PathBuf {
    let src = Path::new(REPO).join("image");
    let dst = tmp.join("img");
    for rel in ["Dockerfile", "MANIFEST", "claude.lock", "managed-settings.json", "claude/settings.json", "claude/CLAUDE.md", "claude/claude.json"] {
        let to = dst.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(src.join(rel), &to).unwrap_or_else(|e| panic!("{rel}: {e}"));
    }
    std::fs::write(dst.join("ai-env"), "stand-in for the cross-built shim\n").unwrap();
    dst
}

/// [`copied_image`] with the baseline settings ([`BASE_SETTINGS`]): what the
/// tests that plant their own changes start from.
fn planted_image(tmp: &Path) -> PathBuf {
    let dst = copied_image(tmp);
    std::fs::write(dst.join("claude/settings.json"), BASE_SETTINGS).unwrap();
    dst
}

fn stage_scan(tmp: &Path, img: &Path) -> Output {
    let tools = bin_with(tmp, &[]);
    make(tmp, &tools, &["image-stage-scan"])
        .arg(format!("IMAGE_DIR={}", img.display()))
        .arg(format!("IMAGE_OUT={}", tmp.join("out").display()))
        .arg(format!("AI_ENV={}", bin()))
        .bounded()
}

/// A failed stage or scan leaves nothing image-build-local could build.
fn assert_no_stage(tmp: &Path, what: &str) {
    for d in ["out/stage", "out/stage.tmp"] {
        assert!(!tmp.join(d).exists(), "{what}: {d} is left behind");
    }
}

#[test]
fn image_stage_scan_passes_on_the_repo_image_files() {
    let t = tempfile::tempdir().unwrap();
    let img = copied_image(t.path());
    // A rule a T8.7 promotion committed to the repository's settings has its
    // allow line in the operator's policy (settings-sync writes both): here too.
    let settings: Value = serde_json::from_str(&read(&img.join("claude/settings.json"))).unwrap();
    let allow: String = settings["permissions"]["allow"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|rule| format!("allow {rule}\n")).collect();
    if !allow.is_empty() {
        std::fs::create_dir_all(t.path().join("bridge")).unwrap();
        std::fs::write(t.path().join("bridge").join("settings-policy.txt"), allow).unwrap();
    }
    let out = stage_scan(t.path(), &img);
    assert!(out.status.success(), "{}", all(&out));
    assert!(stdout(&out).contains("scan: clean (7 files)"), "{}", stdout(&out));
    let staged = t.path().join("out/stage");
    let mode = |rel: &str| std::fs::metadata(staged.join(rel)).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode("claude/claude.json"), mode("ai-env"), mode("claude/agents")), (0o600, 0o755, 0o755), "MANIFEST modes are applied");
    assert!(!staged.join("MANIFEST").exists(), "the manifest itself is not staged");
    assert!(!t.path().join("out/stage.tmp").exists() && !t.path().join("out/stage.tmp.listed").exists(), "the scanned stage is published whole");
}

#[test]
fn image_stage_scan_aborts_on_a_planted_token() {
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    let clean = stage_scan(t.path(), &img);
    assert!(clean.status.success() && t.path().join("out/stage/Dockerfile").exists(), "{}", all(&clean));
    let token = format!("sk-ant-api03-{}", "Q".repeat(24));
    let md = img.join("claude/CLAUDE.md");
    let text = std::fs::read_to_string(&md).unwrap();
    std::fs::write(&md, format!("{text}Use {token} for the API.\n")).unwrap();
    let line = text.lines().count() + 1;
    let out = stage_scan(t.path(), &img);
    let all = all(&out);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains(&format!("claude/CLAUDE.md:{line}: anthropic-key")), "names file, line and rule: {all}");
    assert!(all.contains("Error 9"), "the scanner's exit 9 stops make: {all}");
    assert!(!all.contains(&token), "the matched text is never printed");
    assert_no_stage(t.path(), "a failed scan (the earlier clean stage is gone too)");
}

#[test]
fn image_stage_scan_aborts_on_bypass_permissions_and_unlisted_files() {
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    std::fs::write(img.join("claude/settings.json"), "{\"permissions\":{\"defaultMode\":\"bypassPermissions\",\"allow\":[]}}\n").unwrap();
    let out = stage_scan(t.path(), &img);
    let all_t = all(&out);
    assert!(!out.status.success() && all_t.contains("claude/settings.json:") && all_t.contains("default-mode"), "{all_t}");
    assert_no_stage(t.path(), "bypassPermissions");

    let u = tempfile::tempdir().unwrap();
    let img = planted_image(u.path());
    std::fs::write(img.join("notes.txt"), "not reviewed\n").unwrap();
    let out = stage_scan(u.path(), &img);
    let all_u = all(&out);
    assert!(!out.status.success() && all_u.contains("not in") && all_u.contains("notes.txt"), "an unlisted file stops staging: {all_u}");
    assert_no_stage(u.path(), "an unlisted file");

    let v = tempfile::tempdir().unwrap();
    let img = planted_image(v.path());
    std::fs::remove_file(img.join("ai-env")).unwrap();
    let out = stage_scan(v.path(), &img);
    let all_v = all(&out);
    assert!(!out.status.success() && all_v.contains("make vm-build"), "a missing shim names the fix: {all_v}");
    assert_no_stage(v.path(), "a missing shim");
}

#[test]
fn image_stage_scan_refuses_symlinks_before_staging() {
    // A linked directory: MANIFEST's `dir claude` matches the link itself, and
    // each `file claude/...` would read the outside files under listed names.
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    let outside = t.path().join("outside");
    std::fs::rename(img.join("claude"), &outside).unwrap();
    std::fs::write(outside.join("CLAUDE.md"), "OUTSIDE-TEXT\n").unwrap();
    std::fs::write(outside.join("history.jsonl"), "{}\n").unwrap();
    std::os::unix::fs::symlink(&outside, img.join("claude")).unwrap();
    let out = stage_scan(t.path(), &img);
    let all_t = all(&out);
    assert!(!out.status.success() && all_t.contains("symlinks in") && all_t.lines().any(|l| l.trim() == "claude"), "a linked directory is refused: {all_t}");
    assert_no_stage(t.path(), "a linked directory");

    // A linked file.
    let u = tempfile::tempdir().unwrap();
    let img = planted_image(u.path());
    std::fs::rename(img.join("claude/CLAUDE.md"), u.path().join("CLAUDE.md")).unwrap();
    std::os::unix::fs::symlink(u.path().join("CLAUDE.md"), img.join("claude/CLAUDE.md")).unwrap();
    let out = stage_scan(u.path(), &img);
    let all_u = all(&out);
    assert!(!out.status.success() && all_u.contains("symlinks in") && all_u.lines().any(|l| l.trim() == "claude/CLAUDE.md"), "a linked file is refused: {all_u}");
    assert_no_stage(u.path(), "a linked file");

    // IMAGE_DIR itself may be a link (find runs from inside it).
    let v = tempfile::tempdir().unwrap();
    let img = planted_image(v.path());
    let link = v.path().join("img-link");
    std::os::unix::fs::symlink(&img, &link).unwrap();
    let out = stage_scan(v.path(), &link);
    assert!(out.status.success() && stdout(&out).contains("scan: clean (7 files)"), "{}", all(&out));
}

// ---- S8 T8.7: settings-sync, then the image scan ----

const SESSION: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

/// A session's two captures in `<tmp>/bridge/quarantine/<session>/settings`:
/// no local settings at the start, `allow` approved by the latest.
fn plant_captures(tmp: &Path, allow: &[&str]) {
    let file = |scope: &str, path: &str, text: Option<&str>| match text {
        Some(t) => json!({"scope": scope, "path": path, "present": true, "size": t.len(), "text": t}),
        None => json!({"scope": scope, "path": path, "present": false, "size": 0}),
    };
    let capture = |local: Option<&str>, at: &str| {
        json!({"path": "/Users/mike/w", "files": [file("user", "/Users/mike/.claude/settings.json", Some("{}")), file("project", "/Users/mike/w/.claude/settings.json", None), file("local", "/Users/mike/w/.claude/settings.local.json", local)], "project": {}, "at": at})
    };
    let local = json!({"permissions": {"allow": allow}}).to_string();
    let dir = tmp.join("bridge").join("quarantine").join(SESSION).join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("start.json"), capture(None, "2026-10-12T10:00:00Z").to_string()).unwrap();
    std::fs::write(dir.join("latest.json"), capture(Some(&local), "2026-10-12T10:30:00Z").to_string()).unwrap();
}

/// `ai-env wrapper settings-sync SESSION --all-safe --write --image-dir IMG`
/// in the tests' isolation (the bridge under `tmp`, where the scan reads
/// its settings policy too).
fn sync_into(tmp: &Path, img: &Path) -> Output {
    run(&mut ai_env(tmp, &["wrapper", "settings-sync", SESSION, "--all-safe", "--write", "--image-dir", img.to_str().unwrap()]))
}

/// T8.7 end to end on the image: the rules settings-sync promotes (into
/// `claude/settings.json`, with their allow lines in the settings policy)
/// pass `make image-stage-scan`, whose `infra scan --profile image` reads
/// that policy; the staged settings carry them.
#[test]
fn synced_settings_pass_the_image_scan() {
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    plant_captures(t.path(), &["Bash(git status)", "Bash(cargo test:*)"]);
    let out = sync_into(t.path(), &img);
    assert!(out.status.success(), "{}", all(&out));
    assert!(stdout(&out).contains("scan: clean (") && stdout(&out).contains("next: make test-docker deploy (") && stdout(&out).contains("then ai-env egress check --if-needed ("), "{}", stdout(&out));
    assert_eq!(read(&t.path().join("bridge").join("settings-policy.txt")), "allow Bash(cargo test:*)\nallow Bash(git status)\n");
    let scan = stage_scan(t.path(), &img);
    assert!(scan.status.success(), "{}", all(&scan));
    assert!(stdout(&scan).contains("scan: clean (7 files)"), "{}", stdout(&scan));
    let staged: Value = serde_json::from_str(&read(&t.path().join("out/stage/claude/settings.json"))).unwrap();
    assert_eq!(staged["permissions"]["allow"], json!(["Bash(cargo test:*)", "Bash(git status)"]), "{staged}");
    assert_eq!(staged["permissions"]["defaultMode"], "default");
}

/// The policy is what lets a synced rule through: the same image with the
/// rule's allow line gone from the policy fails `make image-stage-scan`
/// with the scanner's exit 9, naming the file, the line and the rule
/// (never the rule), and leaves no stage.
#[test]
fn a_rule_missing_from_the_policy_fails_the_image_scan_with_9() {
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    plant_captures(t.path(), &["Bash(git status)"]);
    let out = sync_into(t.path(), &img);
    assert!(out.status.success(), "{}", all(&out));
    let policy = t.path().join("bridge").join("settings-policy.txt");
    assert_eq!(read(&policy), "allow Bash(git status)\n");
    std::fs::write(&policy, "# emptied by hand\n").unwrap();
    let scan = stage_scan(t.path(), &img);
    let text = all(&scan);
    assert!(!scan.status.success(), "{text}");
    assert!(text.contains("claude/settings.json:1: allow-not-in-policy") && text.contains("Error 9"), "{text}");
    assert!(!text.contains("git status"), "the rule itself is never printed: {text}");
    assert_no_stage(t.path(), "a rule missing from the policy");
}

#[test]
fn the_make_child_carries_no_outer_make_or_operator_state() {
    // What an outer `make -i test` and an operator shell would hand down: the
    // inner make must still stop on the scanner's exit 9, and the scanner must
    // not read an operator bridge.toml (here an unparseable one).
    let t = tempfile::tempdir().unwrap();
    let img = planted_image(t.path());
    let token = format!("sk-ant-api03-{}", "Q".repeat(24));
    std::fs::write(img.join("claude/CLAUDE.md"), format!("Use {token}.\n")).unwrap();
    std::fs::write(t.path().join("bridge.toml"), "not toml [\n").unwrap();
    let mut cmd = Command::new("make");
    cmd.env("MAKEFLAGS", "i").env("MFLAGS", "-i").env("MAKELEVEL", "1").env("AI_ENV_BRIDGE_CONFIG", t.path().join("bridge.toml"));
    isolate(&mut cmd, t.path()).env("PATH", "/usr/bin:/bin");
    let out = cmd
        .args(["-s", "--no-print-directory", "-C", REPO, "image-stage-scan"])
        .arg(format!("IMAGE_DIR={}", img.display()))
        .arg(format!("IMAGE_OUT={}", t.path().join("out").display()))
        .arg(format!("AI_ENV={}", bin()))
        .bounded();
    let all = all(&out);
    assert!(!out.status.success() && all.contains("Error 9") && all.contains("anthropic-key"), "{all}");
    assert!(!all.contains("TOML") && !all.contains("bridge.toml"), "the operator config was read: {all}");
}

// ---- make -n: a dry parse ----

const MUST_NOT_RUN: &[&str] = &["aws", "pulumi", "docker", "curl", "gpg", "cargo", "npm", "node", "zip", "shasum", "rustup", "sleep"];

/// `$(LAB_UNSET)` as the live recipes run it: the eighteen lab knobs
/// (`the_scrub_lists_hold_every_knob_the_code_and_the_fakes_read` holds the
/// Makefile's list to every one the code and ops.sh read).
const LAB_UNSET: &str = "env -u AI_ENV_BRIDGE_LAB_FAKE_API -u AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL -u AI_ENV_BRIDGE_LAB_BACKOFF_MS -u AI_ENV_BRIDGE_LAB_FAKE_SHELL -u AI_ENV_BRIDGE_LAB_ASSUME_TTY -u AI_ENV_BRIDGE_LAB_AGENT_ADDR -u AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS -u AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS -u AI_ENV_BRIDGE_LAB_TRANSCRIPT -u AI_ENV_BRIDGE_LAB_EXIT -u AI_ENV_BRIDGE_LAB_IGNORE_EOF -u AI_ENV_BRIDGE_LAB_STDOUT_NOISE -u AI_ENV_BRIDGE_LAB_DELAY_INIT_MS -u AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS -u AI_ENV_BRIDGE_LAB_OSASCRIPT -u AI_ENV_BRIDGE_LAB_S3_ADDR -u AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES -u AI_ENV_BRIDGE_LAB_PARK_AFTER_MS";

/// The stand-in's log line of the operator CLI's keyless build (D18: infra.mk's `$(AI_ENV_BUILD)`, TIER's first
/// step, and ops.sh's need_ai_env): `--version`, with no marker and no lab knob in its environment.
const BUILT: &str = "--version [AI_ENV=unset]";

/// `$(NO_KEY)` as the recipes run it (D18): the six variables no compile may see (the key, its secret, a session
/// token, the marker, and the stack's passphrase either way, A39).
const NO_KEY: &str = "env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AI_ENV_BRIDGE_AS -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE";

#[test]
fn make_n_of_the_part_b_targets_executes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let out = make(t.path(), &bin, &["-n", "deploy", "image-wait", "runtime-key", "destroy", "image-prune", "claude-pin"])
        .arg(format!("CLAUDE_VERSION={CLAUDE_VERSION}"))
        .arg(format!("IMAGE_OUT={}", t.path().join("out").display()))
        .env("FAKE_LOG", &log)
        .bounded();
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(read(&log), "", "make -n ran a tool");
    assert!(!t.path().join("out").exists(), "make -n wrote into IMAGE_OUT");
    let text = stdout(&out);
    for want in ["pulumi up --stack dev", "creds aws-set --check", "pulumi destroy --stack dev", "infra pin --manifest", "--expect-version \"2.1.283\""] {
        assert!(text.contains(want), "{want} missing from the dry run: {text}");
    }
    // runtime-key's lines alone, up to destroy's CONFIRM check: the whole dry run names `encrypt -k` (its first line,
    // deploy's passphrase check).
    let rk = text.lines().skip_while(|l| !l.ends_with("creds aws-set --check")).take_while(|l| !l.contains("= \"destroy-dev\"")).collect::<Vec<_>>().join("\n");
    assert!(!rk.is_empty() && !rk.contains(" -k "), "runtime-key names no keystore key (ai-env run picks the container's): {rk}");
}

// ---- test-docker: both suites before the stamp, and no stamp after a failed step ----

/// `make -n test-docker`: the image build, then the shim-only suite, then
/// `docker_exec` (default features: the real `vm exec`), both `--ignored` on
/// one thread under the same Docker variables; the stamp comes last, after
/// both. Nothing runs. Then the recipe for real, its image targets a logged
/// sub-make (MAKE) and its suites a logged cargo, each step failing in turn:
/// make stops at that step and stamps nothing (a `-` prefix, an `|| true` or
/// a `| tee` on any step would stamp a zip a step failed for); with no step
/// failing it stamps the zip's sha256.
#[test]
fn test_docker_runs_both_docker_suites_before_the_stamp_and_stamps_nothing_after_a_failure() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let out = make(t.path(), &bin, &["-n", "test-docker"]).arg(format!("IMAGE_OUT={}", t.path().join("out").display())).env("FAKE_LOG", &log).bounded();
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(read(&log), "", "make -n ran a tool");
    assert!(!t.path().join("out").exists(), "make -n wrote into IMAGE_OUT");
    // One line per command: a continuation joined to its line.
    let text = stdout(&out).replace("\\\n", " ");
    let at = |want: &str| text.find(want).unwrap_or_else(|| panic!("{want} missing from the dry run: {text}"));
    let suites = ["cargo +1.98.1 test -p ai-env-cli --no-default-features --features shim --test shim_docker -- --ignored --test-threads=1", "cargo +1.98.1 test -p ai-env-cli --test docker_exec -- --ignored --test-threads=1"];
    let order = [at("docker build --platform linux/arm64 -t ai-env-agent:local"), at(suites[0]), at(suites[1]), at("test-docker: ok, stamped")];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "the image, shim_docker, docker_exec, then the stamp: {text}");
    let env: Vec<&str> = suites.iter().map(|s| text.lines().find(|l| l.contains(s)).unwrap().split("cargo +1.98.1").next().unwrap().trim()).collect();
    // Without an operator key or the runner's marker (D18): test-docker needs no AWS, and runs first under a runner too.
    assert!(env[0].starts_with(&format!("{NO_KEY} AI_ENV_DOCKER_TESTS=1 ")) && env[0].contains(" AI_ENV_DOCKER_IMAGE='ai-env-agent:local' "), "{env:?}");
    assert_eq!(env[0], env[1], "both suites see the same Docker variables");

    let steps = ["image-zip", "image-build-local", "shim_docker", "docker_exec"];
    for failing in ["none", "image-zip", "image-build-local", "shim_docker", "docker_exec"] {
        let u = tempfile::tempdir().unwrap();
        // shasum stays real (the stamp); every other outside tool is a logged failure.
        let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().filter(|n| !matches!(**n, "cargo" | "shasum")).map(|n| ("logged.sh", *n)).collect();
        let bin = bin_with(u.path(), &fakes);
        let stub = "echo \"$(basename \"$0\") $*\" >> \"$FAKE_LOG\"\ncase \" $* \" in *\" $FAIL_STEP \"*) exit 2 ;; esac\nexit 0";
        script(&bin.join("cargo"), stub);
        script(&bin.join("sub-make"), stub);
        std::fs::create_dir_all(u.path().join("out")).unwrap();
        std::fs::write(u.path().join("out/image.zip"), "a zip").unwrap();
        let log = u.path().join("tools.log");
        let out = make(u.path(), &bin, &["test-docker"])
            .arg(format!("IMAGE_OUT={}", u.path().join("out").display()))
            .arg(format!("MAKE={}", bin.join("sub-make").display()))
            .env("FAKE_LOG", &log)
            .env("FAIL_STEP", failing)
            .bounded();
        let calls = lines_of(&log);
        let ran: Vec<&str> = calls.iter().map(|l| steps.into_iter().find(|s| l.split(' ').any(|w| w == *s)).unwrap_or(l)).collect();
        let upto = steps.iter().position(|s| *s == failing).map_or(steps.len(), |i| i + 1);
        assert_eq!(ran, steps[..upto], "{failing} failing: the steps in order, none after the failure: {}", all(&out));
        let stamp = u.path().join("out/test-docker.ok");
        if failing == "none" {
            assert!(out.status.success(), "{}", all(&out));
            assert_eq!(read(&stamp), format!("{}\n", ai_env_cli::bridge::egress::value_sha256("a zip")), "the stamp is the zip's sha256");
        } else {
            assert!(!out.status.success() && !stamp.exists(), "a failed {failing} stamped the zip: {}", all(&out));
        }
    }
}

// ---- claude-pin (fake curl and gpg) ----

/// The Claude Code release key the Makefile pins, read from it.
fn release_fpr() -> String {
    let mk = std::fs::read_to_string(Path::new(REPO).join("Makefile")).unwrap();
    let line = mk.lines().find(|l| l.starts_with("CLAUDE_GPG_FPR")).expect("CLAUDE_GPG_FPR in the Makefile");
    line.split_whitespace().last().unwrap().to_string()
}

/// A manifest shaped like the release manifest (checksums built at run time).
fn release_manifest(version: &str) -> String {
    serde_json::json!({
        "version": version,
        "buildDate": "2026-09-25T01:39:37Z",
        "platforms": {
            "darwin-arm64": {"binary": "claude", "checksum": "ef".repeat(32), "size": 225_036_032u64},
            "linux-arm64": {"binary": "claude", "checksum": "cd".repeat(32), "size": 240_902_136u64}
        }
    })
    .to_string()
}

/// A temp tree for claude-pin: the fakes (gpg only when `with_gpg`), the
/// served release files, and `img/claude.lock` holding the repo's lock.
fn pin_tree(with_gpg: bool, manifest_version: &str, with_sig: bool) -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let mut fakes = vec![("curl.sh", "curl")];
    if with_gpg {
        fakes.push(("gpg.sh", "gpg"));
    }
    let bin = bin_with(t.path(), &fakes);
    let rel = t.path().join("release");
    std::fs::create_dir_all(&rel).unwrap();
    std::fs::write(rel.join("manifest.json"), release_manifest(manifest_version)).unwrap();
    if with_sig {
        std::fs::write(rel.join("manifest.json.sig"), "fake detached signature\n").unwrap();
    }
    std::fs::create_dir_all(t.path().join("img")).unwrap();
    std::fs::copy(Path::new(REPO).join("image/claude.lock"), t.path().join("img/claude.lock")).unwrap();
    (t, bin)
}

fn claude_pin(t: &Path, tools: &Path, envs: &[(&str, &str)]) -> Output {
    make(t, tools, &["claude-pin"])
        .arg(format!("CLAUDE_VERSION={CLAUDE_VERSION}"))
        .arg(format!("IMAGE_OUT={}", t.join("out").display()))
        .arg(format!("IMAGE_DIR={}", t.join("img").display()))
        .arg(format!("AI_ENV={}", bin()))
        .env("FAKE_CURL_DIR", t.join("release"))
        .envs(envs.iter().copied())
        .bounded()
}

#[test]
fn claude_pin_fails_closed_when_the_release_key_is_in_the_keyring() {
    let lock_before = std::fs::read_to_string(Path::new(REPO).join("image/claude.lock")).unwrap();
    let fpr = release_fpr();
    let other = "0123456789ABCDEF0123456789ABCDEF01234567";
    type Envs<'a> = &'a [(&'a str, &'a str)];
    // (what, fake knobs, a .sig served, the manifest's version, the refusal)
    let refused: &[(&str, Envs, bool, &str, &str)] = &[
        ("a BAD signature", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "bad")], true, CLAUDE_VERSION, "is not a good signature by the release key"),
        ("a good signature by another key", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "good"), ("FAKE_GPG_PRIMARY", other)], true, CLAUDE_VERSION, "is not a good signature by the release key"),
        ("no manifest.json.sig", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "good")], false, CLAUDE_VERSION, "cannot download manifest.json.sig"),
        ("a signed manifest of another version", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "good"), ("FAKE_GPG_PRIMARY", fpr.as_str())], true, "2.1.282", "not 2.1.283; lock not written"),
        // The release key's own signature is revoked; a good one by some other
        // key must not lend it its GOODSIG (the pair is checked per signature).
        ("a revoked release signature next to another key's good one", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "mixed"), ("FAKE_GPG_PRIMARY", fpr.as_str()), ("FAKE_GPG_OTHER", other)], true, CLAUDE_VERSION, "is not a good signature by the release key"),
        // The same pair in the other order: the GOODSIG must not carry over the NEWSIG.
        ("another key's good signature, then a revoked release one", &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "mixed-other-first"), ("FAKE_GPG_PRIMARY", fpr.as_str()), ("FAKE_GPG_OTHER", other)], true, CLAUDE_VERSION, "is not a good signature by the release key"),
    ];
    for (what, envs, with_sig, version, want) in refused {
        let (t, bin) = pin_tree(true, version, *with_sig);
        let out = claude_pin(t.path(), &bin, envs);
        let all = all(&out);
        assert!(!out.status.success(), "{what}: pinned anyway: {all}");
        assert!(all.contains(want) && all.contains("lock not written"), "{what}: {all}");
        assert_eq!(read(&t.path().join("img/claude.lock")), lock_before, "{what}: the lock changed");
    }
}

#[test]
fn claude_pin_writes_the_lock_on_a_release_signature_or_warns_without_the_key() {
    let fpr = release_fpr();
    // Signed by a subkey of the release key: gpg names the subkey first and the primary key last.
    let (t, bin) = pin_tree(true, CLAUDE_VERSION, true);
    let out = claude_pin(t.path(), &bin, &[("FAKE_GPG_KEY", "1"), ("FAKE_GPG_VERIFY", "good"), ("FAKE_GPG_PRIMARY", fpr.as_str())]);
    let all_t = all(&out);
    assert!(out.status.success() && all_t.contains(&format!("manifest signature verified ({fpr})")), "{all_t}");
    assert!(read(&t.path().join("img/claude.lock")).contains(&format!("CLAUDE_SHA256={}", "cd".repeat(32))), "{all_t}");

    // gpg without the release key: pinned, with the warning.
    let (u, bin) = pin_tree(true, CLAUDE_VERSION, true);
    let out = claude_pin(u.path(), &bin, &[("FAKE_GPG_KEY", "0")]);
    let all_u = all(&out);
    assert!(out.status.success() && all_u.contains("signature NOT verified"), "{all_u}");
    assert!(read(&u.path().join("img/claude.lock")).contains(&format!("CLAUDE_SHA256={}", "cd".repeat(32))), "{all_u}");

    // No gpg at all (only when /usr/bin:/bin has none to hide).
    if ["/usr/bin/gpg", "/bin/gpg"].iter().any(|p| Path::new(p).exists()) {
        eprintln!("skipped the no-gpg case: a system gpg on /usr/bin:/bin cannot be hidden from PATH");
        return;
    }
    let (v, bin) = pin_tree(false, CLAUDE_VERSION, false);
    let out = claude_pin(v.path(), &bin, &[]);
    let all_v = all(&out);
    assert!(out.status.success() && all_v.contains("signature NOT verified (gpg missing"), "{all_v}");
}

// ---- s3-preflight (fake docker, curl; every other tool a logged failure) ----

/// `make s3-preflight <args>`: docker and curl fakes, the other tools logged
/// failures, AI_ENV the stand-in, IMAGE_OUT holding an image.zip that make
/// test-docker never stamped. Returns the output and its `[..]` rows.
fn preflight(t: &Path, args: &[&str], envs: &[(&str, &str)]) -> (Output, Vec<String>) {
    let mut fakes = vec![("docker.sh", "docker"), ("curl.sh", "curl"), ("ai-env.sh", "ai-env-stand-in")];
    fakes.extend(["pulumi", "aws", "node", "npm", "zip", "gpg", "rustup", "cargo"].iter().map(|n| ("logged.sh", *n)));
    let bin = bin_with(t, &fakes);
    std::fs::create_dir_all(t.join("out")).unwrap();
    std::fs::write(t.join("out/image.zip"), "not the zip test-docker stamped\n").unwrap();
    let out = make(t, &bin, &["s3-preflight"])
        .args(args)
        .arg(format!("IMAGE_OUT={}", t.join("out").display()))
        .arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()))
        .env("FAKE_LOG", t.join("tools.log"))
        .env("FAKE_DOCKER_LOG", t.join("docker.log"))
        .envs(envs.iter().copied())
        .bounded();
    let rows = stdout(&out).lines().filter(|l| l.starts_with('[')).map(str::to_string).collect();
    (out, rows)
}

fn row<'a>(rows: &'a [String], id: &str) -> &'a str {
    let tag = format!("] {id} ");
    rows.iter().find(|r| r.contains(&tag)).map(String::as_str).unwrap_or_else(|| panic!("no {id} row: {rows:?}"))
}

#[test]
fn s3_preflight_p12_is_skipped_only_by_a_command_line_expect_build_failure() {
    let t = tempfile::tempdir().unwrap();
    let (_, base) = preflight(t.path(), &["PHASE=b"], &[]);
    assert!(row(&base, "P12").starts_with("[NO ] P12 make test-docker has not passed"), "{base:?}");

    let (out, cmdline) = preflight(t.path(), &["PHASE=b", "EXPECT_BUILD_FAILURE=1"], &[]);
    assert!(row(&cmdline, "P12").starts_with("[-  ] P12 NOT CHECKED: EXPECT_BUILD_FAILURE=1"), "{}", all(&out));
    let others = |rows: &[String]| rows.iter().filter(|r| !r.contains("] P12 ")).cloned().collect::<Vec<_>>();
    assert_eq!(others(&cmdline), others(&base), "every other gate is unchanged");
    assert!(others(&base).len() >= 13, "P1-P11 all ran: {base:?}");

    let (_, env) = preflight(t.path(), &["PHASE=b"], &[("EXPECT_BUILD_FAILURE", "1")]);
    assert_eq!(env, base, "the switch exported in the environment is ignored");

    // `make deploy EXPECT_BUILD_FAILURE=1`: the preflight sub-make inherits it (a dry run).
    let bin = bin_with(t.path(), &[]);
    let dry = |args: &[&str], envs: &[(&str, &str)]| stdout(&make(t.path(), &bin, &["-n", "deploy"]).args(args).envs(envs.iter().copied()).bounded());
    assert!(dry(&["EXPECT_BUILD_FAILURE=1"], &[]).contains("if [ \"1\" = 1 ]; then row \"[-  ]\" \"P12 NOT CHECKED"));
    assert!(dry(&[], &[("EXPECT_BUILD_FAILURE", "1")]).contains("if [ \"\" = 1 ]; then row \"[-  ]\" \"P12 NOT CHECKED"));
}

#[test]
fn s3_preflight_p3_needs_an_arm64_daemon_with_free_disk() {
    let cases: &[(Option<&str>, Option<&str>, &str)] = &[
        (None, None, "[NO ] P3 docker is not running"),
        (Some("29.8.0 amd64"), Some("50125004"), "[NO ] P3 docker 29.8.0 amd64: the server is not arm64"),
        (Some("29.8.0 arm64"), Some("1000"), "[NO ] P3 docker 29.8.0 arm64: 0 MiB free in the Docker VM, need 4096"),
        (Some("29.8.0 arm64"), None, "[NO ] P3 docker 29.8.0 arm64: cannot measure the free disk"),
        (Some("29.8.0 aarch64"), Some("50125004"), "[ok ] P3 docker 29.8.0 aarch64, 48950 MiB free in the Docker VM"),
    ];
    for (version, free, want) in cases {
        let t = tempfile::tempdir().unwrap();
        let mut envs = vec![];
        if let Some(v) = version {
            envs.push(("FAKE_DOCKER_VERSION", *v));
        }
        if let Some(f) = free {
            envs.push(("FAKE_DOCKER_FREE_KB", *f));
        }
        let (out, rows) = preflight(t.path(), &["PHASE=a"], &envs);
        assert!(row(&rows, "P3").starts_with(want), "want {want}: {}", all(&out));
        let calls = lines_of(&t.path().join("docker.log"));
        if version.is_some_and(|v| v.ends_with("arm64") || v.ends_with("aarch64")) {
            assert!(calls.iter().any(|c| c.starts_with("run --rm --network none --platform linux/arm64 --entrypoint df ") && c.ends_with(" -Pk /")), "{calls:?}");
        } else {
            assert!(!calls.iter().any(|c| c.starts_with("run")), "no probe container without an arm64 daemon: {calls:?}");
        }
    }
}

// ---- key-issue: the runtime, ops and deployer keys (ops.sh key-issue; stateful fake aws, the ai-env stand-in) ----
//
// runtime-key's recipe moved into `ops.sh key-issue` (S8 operators, contracts §9.7), which runtime-key, ops-key,
// deployer-key and operator-keys share. These tests run it as infra.mk's KEY_ISSUE does, without the make target's
// runner and identity line (tests of their own below): the label, the user, the mode, and ROTATE and AI_ENV_CLI in the
// environment.

fn key_id(n: u32) -> String {
    format!("AKIAFAKE{n:012}")
}

/// A temp tree for key-issue: the stateful fake aws (state in `aws/`), pulumi and node (the hand-over reads the
/// stack's account from its outputs: `outputs.json`, the S8 stack's), a logged no-op `sleep`, the ai-env stand-in;
/// `keys` access keys of ai-env-runtime exist.
fn rk_tree(keys: u32) -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    bin_with(t.path(), &[("logged.sh", "sleep")]);
    let state = t.path().join("aws");
    std::fs::create_dir_all(&state).unwrap();
    let ids: String = (1..=keys).map(|n| key_id(n) + "\n").collect();
    std::fs::write(state.join("keys"), ids).unwrap();
    std::fs::write(state.join("next"), format!("{}\n", keys + 1)).unwrap();
    write_outputs(t.path(), &with_operators(outputs()));
    (t, bin)
}

/// `ops.sh key-issue <args>` as infra.mk's KEY_ISSUE runs it (ROTATE=1 among `envs` for a rotation).
fn key_issue(t: &Path, bin: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("/bin/bash");
    isolate(&mut cmd, t).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    cmd.arg(Path::new(REPO).join("infra/scripts/ops.sh"))
        .arg("key-issue")
        .args(args)
        .env("REGION", "eu-central-1")
        .env("IMAGE_NAME", "ai-env-agent")
        .env("IMAGE_OUT", t.join("out"))
        .env("STACK", "dev")
        .env("AI_ENV_CLI", bin.join("ai-env-stand-in"))
        .env("FAKE_AWS_STATE", t.join("aws"))
        .env("FAKE_AWS_LOG", t.join("aws.log"))
        .env("FAKE_AIENV_LOG", t.join("ai-env.log"))
        .env("FAKE_PULUMI_OUTPUTS", t.join("outputs.json"))
        .env("FAKE_LOG", t.join("sleep.log"))
        .envs(envs.iter().copied())
        .bounded()
}

/// key-issue of the runtime key (runtime-key's), `envs` as given.
fn runtime_key(t: &Path, bin: &Path, envs: &[(&str, &str)]) -> Output {
    key_issue(t, bin, &["runtime-key", "ai-env-runtime", "sealed"], envs)
}

/// The stand-in's decrypts (`creds aws-verify`), one Touch ID prompt each.
fn decrypts(t: &Path) -> Vec<String> {
    lines_of(&t.join("ai-env.log")).into_iter().filter(|l| l.starts_with("creds aws-verify ")).collect()
}

fn aws_calls(t: &Path, prefix: &str) -> usize {
    lines_of(&t.join("aws.log")).iter().filter(|l| l.starts_with(prefix)).count()
}

fn delete_cmd(id: &str) -> String {
    delete_cmd_of("ai-env-runtime", id)
}

/// The delete command key-issue prints, as it can run on this Mac, where a bare `aws` has no credentials (D13): under
/// the deployer's runner (or none: these tests run key-issue directly), the deployer's.
fn delete_cmd_of(user: &str, id: &str) -> String {
    format!("ai-env as deployer -- aws iam delete-access-key --user-name {user} --access-key-id {id} --region eu-central-1")
}

/// D23: the new key's secret (what the stateful fake's create-access-key prints, built here as the fake builds it)
/// crosses exactly one pipe, into the CLI: it is never in key-issue's output nor in any fake's log of the run in `t`.
fn assert_secret_never_shown(t: &Path, out: &Output) {
    let secret = "Fk9/".repeat(10);
    assert!(!all(out).contains(&secret), "the new key's secret in the output: {}", all(out));
    for log in ["aws.log", "ai-env.log", "calls.log", "sleep.log"] {
        assert!(!read(&t.join(log)).contains(&secret), "the new key's secret in {log}");
    }
}

/// IAM needs two more sts calls to propagate: the retries are aws-verify's own, one decrypt (one Touch ID prompt),
/// and key-issue names no keystore key (the CLI reads the container's).
#[test]
fn runtime_key_verifies_once_in_creds_aws_verify_which_retries_while_iam_propagates() {
    let (t, bin) = rk_tree(0);
    std::fs::write(t.path().join("aws/sts-fails"), "2\n").unwrap();
    let out = runtime_key(t.path(), &bin, &[]);
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("runtime-key: the sealed key ...{} identifies as user/ai-env-runtime", &key_id(1)[16..])), "{all}");
    assert!(!all.contains(&key_id(1)), "a verified key is named by its tail only: {all}");
    assert_secret_never_shown(t.path(), &out);
    let runs = decrypts(t.path());
    assert_eq!(runs, vec!["creds aws-verify --user ai-env-runtime [AI_ENV=unset]".to_string()], "one decrypt, one Touch ID prompt; no keystore key named");
    assert_eq!(aws_calls(t.path(), "sts get-caller-identity"), 3, "the retries run inside aws-verify: {all}");
    assert_eq!(lines_of(&t.path().join("sleep.log")).len(), 2, "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1)]);
    let sealed = read(&t.path().join("bridge/credentials/aws.env"));
    assert_eq!(sealed, format!("FAKE-SEALED {}\n", key_id(1)), "sealed into aws.env");
    assert!(!t.path().join("bridge/credentials/ops.env").exists(), "the runtime key never goes into ops.env");
}

#[test]
fn runtime_key_stops_at_a_failed_decrypt_without_retrying() {
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[("FAKE_AIENV_RUN", "cancel")]);
    let all = all(&out);
    assert!(!out.status.success() && all.contains("runtime-key: ai-env creds aws-verify failed (exit 3)") && all.contains("NOT verified"), "{all}");
    assert!(all.contains("  ai-env creds aws-verify --user ai-env-runtime\n"), "how to verify it again: {all}");
    assert!(!all.contains("IAM propagation"), "a cancelled prompt is not propagation: {all}");
    assert_eq!(decrypts(t.path()).len(), 1, "no second prompt: {all}");
    assert_eq!(aws_calls(t.path(), "sts "), 0, "{all}");
    assert_eq!(aws_calls(t.path(), "iam delete-access-key"), 0, "nothing deleted: {all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1)]);
    assert_secret_never_shown(t.path(), &out);
}

#[test]
fn runtime_key_decides_from_iam_whether_a_key_was_created() {
    // IAM created the key but the response was lost, or the sealer exited
    // before reading (the CLI then fails writing into the closed pipe, or
    // not, by timing): either way the new id is named with its delete command.
    for (what, envs) in [("a lost response", [("FAKE_AWS_CREATE", "lost")]), ("a sealer that never read", [("FAKE_AIENV_SEAL", "early")])] {
        let (t, bin) = rk_tree(0);
        let out = runtime_key(t.path(), &bin, &envs);
        let all = all(&out);
        assert!(!out.status.success(), "{what}: {all}");
        assert!(all.contains(&format!("the new key(s) {} are sealed nowhere", key_id(1))) && all.contains(&delete_cmd(&key_id(1))), "{what}: {all}");
        assert!(!all.contains("none was created") && !all.contains("no key was created"), "{what}: {all}");
        assert_eq!(decrypts(t.path()).len(), 0, "{what}: nothing to verify");
        assert_secret_never_shown(t.path(), &out);
    }
    // Nothing created.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[("FAKE_AWS_CREATE", "fail")]);
    let all = all(&out);
    assert!(!out.status.success() && all.contains("none was created") && !all.contains("delete-access-key --user-name"), "{all}");
}

#[test]
fn runtime_key_rotation_that_does_not_verify_prints_the_full_undo() {
    let setup = || {
        let (t, bin) = rk_tree(1);
        let creds = t.path().join("bridge/credentials");
        std::fs::create_dir_all(&creds).unwrap();
        std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
        (t, bin, creds)
    };
    let (t, bin, creds) = setup();
    let out = runtime_key(t.path(), &bin, &[("ROTATE", "1"), ("FAKE_AWS_KEY_USER", "someone-else")]);
    let all_t = all(&out);
    assert!(!out.status.success(), "{all_t}");
    let baks: Vec<PathBuf> = std::fs::read_dir(&creds).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".bak")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert_eq!(read(&baks[0]), format!("FAKE-SEALED {}\n", key_id(1)), "the backup holds the previous key");
    assert!(all_t.contains(&delete_cmd(&key_id(2))), "{all_t}");
    assert!(all_t.contains(&format!("mv \"{}\" \"{}\"", baks[0].display(), creds.join("aws.env").display())), "the undo restores the backup: {all_t}");
    assert!(all_t.contains(&format!("the previous key {} is still active and sealed in {}", key_id(1), baks[0].display())), "{all_t}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted");
    assert_secret_never_shown(t.path(), &out);

    // The rotation that verifies deletes the old key.
    let (t, bin, _) = setup();
    let out = runtime_key(t.path(), &bin, &[("ROTATE", "1")]);
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("rotated; deleted the old key {}", key_id(1))), "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(2)]);
    assert_secret_never_shown(t.path(), &out);
}

#[test]
fn runtime_key_names_every_extra_new_key_with_its_own_delete_command() {
    // A retried create-access-key left two new keys; aws-set sealed the second.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[("FAKE_AWS_CREATE", "twice")]);
    let all = all(&out);
    assert!(out.status.success(), "the sealed key verifies: {all}");
    assert!(all.contains(&format!("the sealed key ...{} identifies as user/ai-env-runtime", &key_id(2)[16..])), "only the sealed id is named: {all}");
    assert!(all.contains(&format!("besides the sealed {}", key_id(2))) && all.contains(&delete_cmd(&key_id(1))), "the unsealed extra key gets its own delete command: {all}");
    assert!(!all.contains(&delete_cmd(&key_id(2))), "never the sealed one: {all}");
    assert!(!all.contains(&format!("{} {}", key_id(1), key_id(2))), "no two ids in one argument: {all}");
    assert_secret_never_shown(t.path(), &out);

    // The same two keys, and the sealed one does not verify: the undo names
    // only the sealed id, the extra one keeps its own line.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[("FAKE_AWS_CREATE", "twice"), ("FAKE_AWS_KEY_USER", "someone-else")]);
    let text = self::all(&out);
    assert!(!out.status.success(), "{text}");
    assert_eq!(text.matches(&delete_cmd(&key_id(2))).count(), 1, "the undo deletes the sealed key once: {text}");
    assert_eq!(text.matches(&delete_cmd(&key_id(1))).count(), 1, "the extra key: {text}");
    assert!(text.lines().all(|l| !(l.contains(&key_id(1)) && l.contains(&key_id(2)) && l.contains("--access-key-id"))), "no command names both: {text}");
    assert_secret_never_shown(t.path(), &out);
}

/// Under `ai-env as deployer` (as make runs it), key-issue hands the runner's environment to the CLI as it is: the
/// sealing and the verification see the runner's marker (and so its key) unchanged, and the new key never enters
/// key-issue's own environment or any argv but a delete command; the sealed key alone reaching sts is the CLI's own
/// scrub (`apply_key`, unit-tested in src/bridge/identity.rs), which the stand-in only mirrors.
#[test]
fn runtime_key_hands_the_runners_environment_to_the_cli_as_it_is() {
    let (t, bin) = rk_tree(0);
    let envs = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let out = runtime_key(t.path(), &bin, &pairs(&envs));
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("the sealed key ...{} identifies as user/ai-env-runtime", &key_id(1)[16..])), "{all}");
    let cli: Vec<String> = lines_of(&t.path().join("ai-env.log"));
    assert_eq!(
        cli,
        [BUILT, "creds aws-set --user ai-env-runtime [AI_ENV=unset] [AS=deployer:9001]", "creds aws-verify --user ai-env-runtime [AI_ENV=unset] [AS=deployer:9001]"].map(String::from),
        "the CLI built without the key first (D18), then sealing and verification under the runner's marker: {all}"
    );
    assert!(lines_of(&t.path().join("aws.log")).iter().all(|l| !l.contains(&key_id(1))), "the new key in an aws argv: {all}");
    assert_secret_never_shown(t.path(), &out);
}

#[test]
fn runtime_key_never_deletes_the_key_the_verified_container_still_holds() {
    // aws-set sealed somewhere else: the verified container still holds the
    // previous key, so ROTATE=1 must not delete it.
    let (t, bin) = rk_tree(1);
    let creds = t.path().join("bridge/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
    let out = runtime_key(t.path(), &bin, &[("ROTATE", "1"), ("FAKE_AIENV_SEAL_DIR", t.path().join("elsewhere").to_str().unwrap())]);
    let all = all(&out);
    assert!(!out.status.success() && all.contains(&format!("still holds the previous key {}", key_id(1))) && all.contains("Nothing deleted"), "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted: {all}");
    assert_secret_never_shown(t.path(), &out);
}

#[test]
fn runtime_key_verifies_even_when_the_listing_after_sealing_fails() {
    // ROTATE=1: the first listing (before) works, the one after sealing fails.
    let (t, bin) = rk_tree(1);
    let creds = t.path().join("bridge/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
    let out = runtime_key(t.path(), &bin, &[("ROTATE", "1"), ("FAKE_AWS_LIST_FAIL_FROM", "2"), ("FAKE_AWS_KEY_USER", "someone-else")]);
    let all = all(&out);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("cannot list the keys of ai-env-runtime after sealing") && all.contains("verifying the sealed key anyway"), "{all}");
    assert_eq!(decrypts(t.path()).len(), 1, "it still verified: {all}");
    let bak: Vec<PathBuf> = std::fs::read_dir(&creds).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".bak")).collect();
    assert_eq!(bak.len(), 1, "{all}");
    assert!(all.contains(&delete_cmd(&key_id(2))) && all.contains(&format!("mv \"{}\"", bak[0].display())), "the full undo names the sealed id and the backup: {all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted");
    assert_secret_never_shown(t.path(), &out);
}

/// The ops key: sealed into credentials/ops.env (never aws.env), verified as user/ai-env-ops; `first` (operator-keys)
/// skips a user that has a key, ROTATE=1 included; a second key, or one without ROTATE=1, is refused before anything
/// is created; anything but the three (user, mode) pairs is usage, exit 2.
#[test]
fn key_issue_seals_the_ops_key_into_ops_env_and_first_skips_a_user_with_a_key() {
    let (t, bin) = rk_tree(0);
    let ops = |args: &[&str], envs: &[(&str, &str)]| key_issue(t.path(), &bin, args, envs);
    let out = ops(&["ops-key", "ai-env-ops", "sealed"], &[]);
    let text = all(&out);
    assert!(out.status.success() && text.contains(&format!("ops-key: the sealed key ...{} identifies as user/ai-env-ops", &key_id(1)[16..])), "{text}");
    assert_eq!(read(&t.path().join("bridge/credentials/ops.env")), format!("FAKE-SEALED {}\n", key_id(1)));
    assert!(!t.path().join("bridge/credentials/aws.env").exists(), "the ops key never goes into aws.env");
    assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-ops")), vec![key_id(1)]);
    assert_eq!(decrypts(t.path()), vec!["creds aws-verify --user ai-env-ops [AI_ENV=unset]".to_string()]);
    assert_secret_never_shown(t.path(), &out);
    let calls_before = lines_of(&t.path().join("aws.log")).len();
    for envs in [&[][..], &[("ROTATE", "1")][..]] {
        let out = ops(&["ops-key", "ai-env-ops", "sealed", "first"], envs);
        assert!(out.status.success() && all(&out).contains("ops-key: ai-env-ops has its key already: skipped (a rerun resumes)"), "{envs:?}: {}", all(&out));
    }
    assert_eq!(lines_of(&t.path().join("aws.log")).len(), calls_before + 2, "a skip lists the keys and nothing else");
    let out = ops(&["ops-key", "ai-env-ops", "sealed"], &[]);
    assert!(!out.status.success() && all(&out).contains(&format!("ops-key: ai-env-ops already has a key ({}); ROTATE=1 seals a new one, then deletes it", key_id(1))), "{}", all(&out));
    let out = ops(&["ops-key", "ai-env-ops", "sealed"], &[("ROTATE", "1")]);
    assert!(out.status.success() && all(&out).contains(&format!("ops-key: rotated; deleted the old key {}", key_id(1))), "{}", all(&out));
    assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-ops")), vec![key_id(2)]);
    std::fs::write(t.path().join("aws/keys.ai-env-ops"), format!("{}\n{}\n", key_id(2), key_id(7))).unwrap();
    let out = ops(&["ops-key", "ai-env-ops", "sealed"], &[("ROTATE", "1")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("ops-key: ai-env-ops has 2 access keys (the IAM maximum); delete the one that is not sealed first:"), "{text}");
    let bads: [&[&str]; 5] = [&["ops-key", "ai-env-deployer", "sealed"], &["ops-key", "ai-env-ops", "handover"], &["ops-key", "ai-env-ops", "sealed", "twice"], &["", "ai-env-ops", "sealed"], &["ops-key"]];
    for bad in bads {
        let out = ops(bad, &[]);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", all(&out));
        assert!(stderr(&out).starts_with("usage: ops.sh key-issue LABEL "), "{bad:?}: {}", all(&out));
    }
    assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-ops")), vec![key_id(2), key_id(7)], "nothing created by a refusal");
    assert!(!read(&t.path().join("aws.log")).contains(&"Fk9/".repeat(10)) && !read(&t.path().join("ai-env.log")).contains(&"Fk9/".repeat(10)), "the secret in a log");
}

/// key-issue of the deployer key (deployer-key's and operator-keys'): create-access-key piped into `ai-env creds
/// deployer-key --account <the stack's accountId>` (the clipboard, the paste-back and sts are the CLI's own); its `id`
/// line says it took the key, its exit is the verdict: 0 verified, 42 never answered and 9 another principal or
/// account (does not identify: delete it, put the entry's previous values back), anything else (cancelled, a
/// paste-back that never matched, the clipboard) held nowhere: delete it. Without an `id` line nothing was handed over
/// and IAM says what was created. No accountId output: nothing is created.
#[test]
fn key_issue_hands_the_deployer_key_over_and_names_the_undo_of_every_failure() {
    let deployer = |rk: u32, envs: &[(&str, &str)], prep: &dyn Fn(&Path)| {
        let (t, bin) = rk_tree(0);
        let keys: String = (1..=rk).map(|n| key_id(n) + "\n").collect();
        std::fs::write(t.path().join("aws/keys.ai-env-deployer"), keys).unwrap();
        std::fs::write(t.path().join("aws/next"), format!("{}\n", rk + 1)).unwrap();
        prep(t.path());
        let out = key_issue(t.path(), &bin, &["deployer-key", "ai-env-deployer", "handover"], envs);
        assert_secret_never_shown(t.path(), &out);
        (t, out)
    };
    let none = |_: &Path| {};
    let new_id = key_id(1);
    let del = delete_cmd_of("ai-env-deployer", &new_id);

    // Verified: handed over to the stack's account, named by its tail.
    let (t, out) = deployer(0, &[], &none);
    let text = all(&out);
    assert!(out.status.success() && text.contains(&format!("deployer-key: the key ...{} is in Strongbox and identifies as user/ai-env-deployer", &new_id[16..])), "{text}");
    assert!(!stdout(&out).contains(&new_id), "a verified key is named by its tail only: {}", stdout(&out));
    assert_eq!(lines_of(&t.path().join("ai-env.log")), vec![BUILT.to_string(), "creds deployer-key --account 123456789012 [AI_ENV=unset]".to_string()], "the CLI built first, without a key; the account is the stack's, from its outputs");
    assert!(!t.path().join("bridge/credentials").exists(), "the deployer's key is sealed nowhere");

    // The hand-over failed after it took the key: held nowhere you can rely on.
    for (what, mode, rc) in [("cancelled", "cancel", "3"), ("a paste-back that never matched", "mismatch", "1"), ("the clipboard", "clipboard", "1")] {
        let (t, out) = deployer(0, &[("FAKE_AIENV_HANDOVER", mode)], &none);
        let text = all(&out);
        assert!(!out.status.success(), "{what}: {text}");
        assert!(text.contains(&format!("deployer-key: ai-env creds deployer-key failed (exit {rc}): the new key {new_id} is held nowhere you can rely on; delete it:\n  {del}\n")), "{what}: {text}");
        assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-deployer")), vec![new_id.clone()], "{what}: nothing deleted");
    }
    // Under the account root's runner (operator-keys, break-glass: the deployer may have no key at all) the commands are
    // the root's, run in its terminal (D13).
    let (_, out) = deployer(0, &[("FAKE_AIENV_HANDOVER", "cancel"), ("AI_ENV_BRIDGE_AS", "root")], &none);
    let text = all(&out);
    let root_del = format!("ai-env as root -- aws iam delete-access-key --user-name ai-env-deployer --access-key-id {new_id} --region eu-central-1");
    assert!(text.contains(&format!("is held nowhere you can rely on; delete it:\n  {root_del}\n")) && !text.contains("ai-env as deployer --"), "{text}");

    // Never answered (42), or another account (9): it does not identify; the undo names the entry's history.
    let (_, out) = deployer(0, &[], &|t: &Path| std::fs::write(t.join("aws/sts-fails"), "8\n").unwrap());
    let text = all(&out);
    let undo = "If it never verifies, delete the new one and put the previous values back in the Strongbox entry (its history keeps them):";
    assert!(!out.status.success() && text.contains(&format!("deployer-key: the key {new_id} does not identify as user/ai-env-deployer; the previous key (none) is kept. {undo}\n  {del}\n")), "{text}");
    let (_, out) = deployer(0, &[], &|t: &Path| {
        let mut o = with_operators(outputs());
        o["accountId"] = json!("999999999999");
        write_outputs(t, &o);
    });
    let text = all(&out);
    assert!(!out.status.success() && text.contains("does not identify as user/ai-env-deployer") && text.contains(undo) && text.contains(&del), "{text}");

    // A rotation: the old key deleted last, once the new one is in Strongbox and answers.
    let (t, out) = deployer(1, &[("ROTATE", "1")], &none);
    let text = all(&out);
    let new2 = key_id(2);
    assert!(out.status.success() && text.contains(&format!("deployer-key: the key ...{} is in Strongbox and identifies as user/ai-env-deployer", &new2[16..])), "{text}");
    assert!(stdout(&out).ends_with(&format!("deployer-key: rotated; deleted the old key {}\n", key_id(1))), "the old key last: {text}");
    assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-deployer")), vec![new2.clone()]);
    let (_, out) = deployer(1, &[], &none);
    assert!(!out.status.success() && all(&out).contains(&format!("deployer-key: ai-env-deployer already has a key ({}); ROTATE=1 hands a new one over, then deletes it", key_id(1))), "{}", all(&out));
    let (_, out) = deployer(2, &[("ROTATE", "1")], &none);
    let two = "deployer-key: ai-env-deployer has 2 access keys (the IAM maximum); delete the one that is not in Strongbox first:\n  ai-env as deployer -- aws iam list-access-keys --user-name ai-env-deployer --region eu-central-1\n  ai-env as deployer -- aws iam delete-access-key --user-name ai-env-deployer --access-key-id <id> --region eu-central-1\n";
    assert!(!out.status.success() && all(&out).contains(two), "{}", all(&out));

    // A retried create left an extra key: its own delete command, never the handed-over one's.
    let (_, out) = deployer(0, &[("FAKE_AWS_CREATE", "twice")], &none);
    let text = all(&out);
    assert!(out.status.success() && text.contains(&format!("IAM lists new key(s) held nowhere besides the handed-over {new2} (a retried create-access-key). Delete them:\n  {del}\n")), "{text}");
    assert!(!text.contains(&delete_cmd_of("ai-env-deployer", &new2)), "{text}");

    // Nothing handed over (no id line): IAM decides what to delete.
    let (_, out) = deployer(0, &[("FAKE_AWS_CREATE", "lost")], &none);
    let text = all(&out);
    assert!(!out.status.success() && text.contains(&format!("deployer-key: the hand-over failed (create-access-key exit 255, deployer-key exit 1): the new key(s) {new_id} are held nowhere. Delete them:\n  {del}\n")), "{text}");
    let (_, out) = deployer(0, &[("FAKE_AWS_CREATE", "fail")], &none);
    assert!(!out.status.success() && all(&out).contains("deployer-key: create-access-key failed (exit 254) and IAM lists no new key of ai-env-deployer: none was created"), "{}", all(&out));

    // No accountId: nothing created.
    for (what, outputs) in [("no accountId", Some(outputs())), ("unreadable outputs", None)] {
        let (t, out) = deployer(0, &[], &|t: &Path| match &outputs {
            Some(o) => write_outputs(t, o),
            None => std::fs::remove_file(t.join("outputs.json")).unwrap(),
        });
        let text = all(&out);
        assert!(!out.status.success() && text.contains("deployer-key: the outputs of stack dev name no accountId: the hand-over needs the stack's account: nothing created"), "{what}: {text}");
        assert_eq!(aws_calls(t.path(), "iam create-access-key"), 0, "{what}");
        assert_eq!(lines_of(&t.path().join("ai-env.log")), vec![BUILT.to_string()], "{what}: deployer-key never ran (only the keyless build)");
    }
}

/// key-issue's verdict on a sealed key reads aws-verify's `id` line (contracts §9.7 step 6, D9): exit 5 after it (six
/// sts tries, none answered) is a key that does not identify, with its delete command; exit 5 without it (no sealed
/// file where aws-verify looks) is aws-verify's own failure: NOT verified, how to verify it, nothing to delete.
/// ROTATE=1 for a user with no key refuses before anything is created (step 1); a hand-over whose listing fails
/// afterwards still judges the handed-over key (step 4's warning).
#[test]
fn key_issue_tells_a_key_that_never_answered_from_a_failed_verification() {
    // Never answered: the sealed key is named in full, with the delete command; nothing is deleted.
    let (t, bin) = rk_tree(0);
    std::fs::write(t.path().join("aws/sts-fails"), "6\n").unwrap();
    let out = key_issue(t.path(), &bin, &["ops-key", "ai-env-ops", "sealed"], &[]);
    let text = all(&out);
    let id = key_id(1);
    let undo = format!("ops-key: the sealed key {id} does not identify as user/ai-env-ops; the previous key (none) is kept. If it never verifies, delete the new one:\n  {}\n", delete_cmd_of("ai-env-ops", &id));
    assert!(!out.status.success() && text.contains(&undo) && !text.contains("NOT verified"), "{text}");
    assert_eq!(decrypts(t.path()).len(), 1, "one decrypt: {text}");
    assert_eq!(aws_calls(t.path(), "sts get-caller-identity"), 6, "aws-verify's six tries: {text}");
    assert_eq!(lines_of(&t.path().join("aws/keys.ai-env-ops")), vec![id.clone()], "nothing deleted: {text}");
    assert_secret_never_shown(t.path(), &out);

    // No sealed file where aws-verify looks (no id line): its failure, not the key's verdict.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[("FAKE_AIENV_SEAL_DIR", t.path().join("elsewhere").to_str().unwrap())]);
    let text = all(&out);
    let failed = format!("runtime-key: ai-env creds aws-verify failed (exit 5): the sealed key {id} is NOT verified and nothing was deleted. Verify it with:\n  ai-env creds aws-verify --user ai-env-runtime\n");
    assert!(!out.status.success() && text.contains(&failed), "{text}");
    assert!(!text.contains("does not identify") && !text.contains("delete-access-key --user-name"), "nothing to delete for a key that was never checked: {text}");
    assert_eq!(aws_calls(t.path(), "sts "), 0, "{text}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![id.clone()]);
    assert_secret_never_shown(t.path(), &out);

    // ROTATE=1 without a key: refused before anything is created.
    for (label, user, mode) in [("runtime-key", "ai-env-runtime", "sealed"), ("ops-key", "ai-env-ops", "sealed"), ("deployer-key", "ai-env-deployer", "handover")] {
        let (t, bin) = rk_tree(0);
        let out = key_issue(t.path(), &bin, &[label, user, mode], &[("ROTATE", "1")]);
        let text = all(&out);
        assert_eq!(out.status.code(), Some(1), "{label}: {text}");
        let route = if mode == "handover" { "make operator-keys (as the account root)".to_string() } else { format!("make {label}") };
        assert!(stdout(&out).ends_with(&format!("{label}: ROTATE=1, but {user} has no key: {route}\n")), "{label}: {text}");
        assert_eq!(aws_calls(t.path(), "iam create-access-key"), 0, "{label}: nothing created: {text}");
        assert_eq!(lines_of(&t.path().join("ai-env.log")), vec![BUILT.to_string()], "{label}: no CLI call but the keyless build: {text}");
    }

    // The hand-over's listing afterwards fails: a warning, and the handed-over key judged all the same.
    let (t, bin) = rk_tree(0);
    let out = key_issue(t.path(), &bin, &["deployer-key", "ai-env-deployer", "handover"], &[("FAKE_AWS_LIST_FAIL_FROM", "2")]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let said = stdout(&out);
    let warning = "deployer-key: warning: cannot list the keys of ai-env-deployer after the hand-over (exit 254); judging the handed-over key anyway\n";
    let verified = format!("deployer-key: the key ...{} is in Strongbox and identifies as user/ai-env-deployer\n", &id[16..]);
    assert!(said.find(warning).is_some_and(|w| said.find(&verified).is_some_and(|v| w < v)), "the warning, then the verdict: {text}");
    assert_secret_never_shown(t.path(), &out);
}

// ---- ops.sh wait (D29) ----

/// `node` from the test's PATH (ops.sh reads the snapshots with it).
fn node() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join("node")).find(|n| n.is_file()))
}

/// `$S/image/{state,active,failed,updated}` of the stateful fake aws.
fn set_image(t: &Path, state: &str, active: &str, failed: &str, updated: &str) {
    let dir = t.join("aws/image");
    std::fs::create_dir_all(&dir).unwrap();
    for (f, v) in [("state", state), ("active", active), ("failed", failed), ("updated", updated)] {
        std::fs::write(dir.join(f), v).unwrap();
    }
}

fn ops(t: &Path, bin: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("/bin/bash");
    isolate(&mut cmd, t).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    cmd.arg(Path::new(REPO).join("infra/scripts/ops.sh"))
        .args(args)
        .env("REGION", "eu-central-1")
        .env("IMAGE_NAME", "ai-env-agent")
        .env("IMAGE_OUT", t.join("out"))
        .env("STACK", "dev")
        .env("IMAGE_WAIT_TIMEOUT", "5")
        .env("IMAGE_WAIT_POLL", "1")
        .env("VERSIONS_WARN", "40")
        .env("VERSIONS_QUOTA", "50")
        .env("FAKE_AWS_STATE", t.join("aws"))
        .bounded()
}

#[test]
fn image_wait_passes_an_unchanged_failed_image_and_fails_a_new_failure() {
    // node is an S3 precondition (P4): without it this D29 check must fail, not pass silently.
    let node = node().expect("node is required: ops.sh reads the snapshots with it (s3-preflight P4)");
    type Img = (&'static str, &'static str, &'static str, &'static str);
    let (t1, t2) = ("2026-09-29T10:00:00.123000+00:00", "2026-09-29T11:00:00.456000+00:00");
    let failed_before: Img = ("UPDATE_FAILED", "2", "3", t1);
    let cases: &[(&str, Option<Img>, Img, bool, &str)] = &[
        ("no build since the earlier failure", Some(failed_before), failed_before, true, "no new build; the image still carries the earlier failure of version 3"),
        ("a new failed version", Some(failed_before), ("UPDATE_FAILED", "2", "4", t2), false, "image-wait: UPDATE_FAILED"),
        ("the same versions, updated again", Some(failed_before), ("UPDATE_FAILED", "2", "3", t2), false, "image-wait: UPDATE_FAILED"),
        ("a good image that failed", Some(("UPDATED", "2", "", t1)), ("UPDATE_FAILED", "2", "3", t2), false, "image-wait: UPDATE_FAILED"),
        ("failed with no new version", Some(("UPDATED", "2", "", t1)), ("UPDATE_FAILED", "2", "", t2), false, "image-wait: UPDATE_FAILED"),
        ("a new build after the failure", Some(failed_before), ("UPDATED", "3", "3", t2), true, "active version 2 -> 3"),
        ("no pre-deploy snapshot", None, failed_before, false, "image-wait: UPDATE_FAILED"),
    ];
    for (what, pre, now, ok, want) in cases {
        let t = tempfile::tempdir().unwrap();
        let bin = bin_with(t.path(), &[("aws-state.sh", "aws")]);
        std::os::unix::fs::symlink(&node, bin.join("node")).unwrap();
        if let Some((s, a, f, u)) = pre {
            set_image(t.path(), s, a, f, u);
            let snap = ops(t.path(), &bin, &["snapshot", "pre-deploy"]);
            assert!(snap.status.success(), "{what}: {}", all(&snap));
        }
        let (s, a, f, u) = now;
        set_image(t.path(), s, a, f, u);
        let out = ops(t.path(), &bin, &["wait"]);
        let all = all(&out);
        assert_eq!(out.status.success(), *ok, "{what}: {all}");
        assert!(all.contains(want), "{what}: want {want}: {all}");
    }
}

// ---- vm-build: the bootstrap cargo-lambda just built ----

/// A 64-byte ELF header for aarch64 (enough for `file`) plus a marker.
fn arm64_elf(marker: &str) -> Vec<u8> {
    let mut b = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0xb7, 0, 1, 0, 0, 0];
    b.resize(64, 0);
    b.extend_from_slice(marker.as_bytes());
    b
}

#[test]
fn vm_build_copies_the_bootstrap_it_built_whatever_the_cargo_target_dir() {
    // A working tree of its own (vm-build writes target/lambda/ and image/ai-env
    // relative to it); the Makefile under test is the repo's.
    let t = tempfile::tempdir().unwrap();
    let w = t.path().join("w");
    for rel in ["infra/infra.mk", "infra/image-config.json", "image/Dockerfile"] {
        std::fs::create_dir_all(w.join(rel).parent().unwrap()).unwrap();
        std::fs::copy(Path::new(REPO).join(rel), w.join(rel)).unwrap();
    }
    let stale = w.join("target/lambda/ai-env/bootstrap");
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, arm64_elf("stale bootstrap of an earlier build")).unwrap();
    std::fs::write(t.path().join("fresh"), arm64_elf("fresh bootstrap")).unwrap();
    let bin = bin_with(t.path(), &[("cargo-lambda.sh", "cargo-lambda")]);
    script(&bin.join("rustup"), "echo aarch64-unknown-linux-gnu");
    script(&t.path().join("llvm/llvm-nm"), "exit 0");
    script(&t.path().join("llvm/llvm-objdump"), "echo '0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.17) memcpy'");
    let mut cmd = Command::new("make");
    isolate(&mut cmd, t.path()).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    let out = cmd
        .args(["-s", "--no-print-directory", "-f", &format!("{REPO}/Makefile"), "-C"])
        .arg(&w)
        .arg("vm-build")
        .arg(format!("CARGO_LAMBDA={}", bin.join("cargo-lambda").display()))
        .arg(format!("LLVM_BIN={}", t.path().join("llvm").display()))
        .env("CARGO_TARGET_DIR", t.path().join("elsewhere"))
        // A make under `cargo run` (claude-update's passes, logs/test34.txt): cargo hands its child CARGO, a program's
        // path; make must not export its own CARGO (`cargo +1.98.1`) under that name to cargo-lambda.
        .env("CARGO", "/usr/bin/true")
        .env("FAKE_CL_BOOTSTRAP", t.path().join("fresh"))
        .env("FAKE_CL_LOG", t.path().join("cl.log"))
        .bounded();
    let all = all(&out);
    assert!(out.status.success(), "{all}");
    assert_eq!(std::fs::read(w.join("image/ai-env")).unwrap(), arm64_elf("fresh bootstrap"), "image/ai-env is this build's: {all}");
    let cl = lines_of(&t.path().join("cl.log"));
    assert!(cl.iter().any(|l| l.contains("build") && l.contains("--lambda-dir target/lambda")), "{all}");
    assert!(!cl.iter().any(|l| l.ends_with(" [CARGO]")), "no recipe gets CARGO (unexport): {cl:?}");
    assert!(!t.path().join("elsewhere/lambda").exists(), "{all}");
}

// ---- AI_ENV and the image parameters ----

#[test]
fn ai_env_from_the_environment_never_reaches_a_recipe() {
    // A shell that sourced an encrypted .env exports its marker line, AI_ENV=1.
    let t = tempfile::tempdir().unwrap();
    let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in"), ("logged.sh", "cargo")]);
    let default = "cargo +1.98.1 run -q -p ai-env-cli --bin ai-env -- infra scan";
    let tools = t.path().join("tools.log");
    let dry = |args: &[&str]| stdout(&make(t.path(), &bin, &["-n"]).args(args).env("AI_ENV", "1").env("FAKE_LOG", &tools).bounded());
    let scan = dry(&["image-stage-scan"]);
    assert!(scan.contains(default) && !scan.contains("1 infra scan"), "{scan}");
    let zip = dry(&["image-zip"]);
    assert!(zip.contains(default), "the sub-make too: {zip}");
    let zip = dry(&["image-zip", "AI_ENV=/opt/x/ai-env"]);
    assert!(zip.contains("/opt/x/ai-env infra scan"), "a command-line value reaches the sub-make: {zip}");
    // The recipes' children never see the variable, not even a command-line value.
    let log = t.path().join("ai-env.log");
    let stand_in = bin.join("ai-env-stand-in");
    let out = make(t.path(), &bin, &["check-base-image"]).arg(format!("AI_ENV={}", stand_in.display())).env("AI_ENV", "1").env("FAKE_AIENV_LOG", &log).env("FAKE_LOG", &tools).bounded();
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(lines_of(&log), vec![BUILT.to_string(), "infra base-image --name al2023-1 --version 1 [AI_ENV=unset]".to_string()], "built first, without a key (D18), then the check");
    assert_eq!(read(&tools), "", "cargo never ran");
}

/// The upper-case variables of `make -p` (a dry parse), `NAME := value` or
/// `NAME = value` (a recursive or `?=` one), as make holds them.
fn make_vars(t: &Path, args: &[&str]) -> std::collections::HashMap<String, String> {
    let bin = bin_with(t, &[]);
    let out = make(t, &bin, &["-p", "-n", "help"]).args(args).bounded();
    assert!(out.status.success(), "{}", all(&out));
    fn var(l: &str) -> Option<(&str, &str)> {
        l.split_once(" := ").or_else(|| l.split_once(" = ")).filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    }
    stdout(&out).lines().filter_map(var).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn image_and_base_names_come_from_image_config_json() {
    let t = tempfile::tempdir().unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&read(&Path::new(REPO).join("infra/image-config.json"))).unwrap();
    let vars = make_vars(t.path(), &[]);
    let got = |k: &str| vars.get(k).cloned().unwrap_or_default();
    assert_eq!(got("IMAGE_NAME"), cfg["imageName"].as_str().unwrap());
    assert_eq!(got("BASE_NAME"), cfg["baseImage"]["name"].as_str().unwrap());
    assert_eq!(got("BASE_VERSION"), cfg["baseImage"]["version"].as_str().unwrap());
    assert_eq!(got("LOG_GROUP"), cfg["logGroup"].as_str().unwrap());

    // A bumped file is followed (the Makefile holds no copy of the values).
    let bumped = t.path().join("bumped.json");
    let text = read(&Path::new(REPO).join("infra/image-config.json")).replace("\"ai-env-agent\"", "\"ai-env-agent2\"").replace("\"al2023-1\", \"version\": \"1\"", "\"al2023-2\", \"version\": \"2\"");
    std::fs::write(&bumped, text).unwrap();
    let arg = format!("IMAGE_CONFIG={}", bumped.display());
    let vars = make_vars(t.path(), &[&arg]);
    assert_eq!((vars["IMAGE_NAME"].as_str(), vars["BASE_NAME"].as_str(), vars["BASE_VERSION"].as_str()), ("ai-env-agent2", "al2023-2", "2"));

    // A file the one-line sed cannot read fails loudly before anything runs.
    let split = t.path().join("split.json");
    std::fs::write(&split, "{\n  \"image\": \"renamed\",\n  \"baseImage\": {\n    \"name\": \"al2023-1\",\n    \"version\": \"1\"\n  }\n}\n").unwrap();
    let arg = format!("IMAGE_CONFIG={}", split.display());
    let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in"), ("logged.sh", "aws")]);
    let log = t.path().join("ai-env.log");
    let out = make(t.path(), &bin, &["check-base-image", &arg]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_LOG", &log).bounded();
    assert!(!out.status.success() && all(&out).contains("baseImage.name or baseImage.version missing from"), "{}", all(&out));
    assert_eq!(read(&log), "", "ai-env never ran");
    let out = make(t.path(), &bin, &["image-status", &arg]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_LOG", t.path().join("tools.log")).bounded();
    assert!(!out.status.success() && all(&out).contains("IMAGE_NAME is empty"), "{}", all(&out));
    assert_eq!(read(&t.path().join("tools.log")), "", "aws never ran");
}

// ---- S5 egress ops: ops.sh, the new targets, deploy's gate and steps ----
//
// The fakes share one log, `<tmp>/calls.log`, so the order of every call is
// asserted across them: the aws argv, `pulumi <argv>`, the stand-in's
// `<argv> [AI_ENV=…]` and the planted plan check's `check-plan <argv>`. The
// stateful aws refuses a lambda-core, ec2 or logs call without its pinned
// endpoint (exit 252), so every passing case also proves the pins.

const CONNECTOR: &str = "ai-env-egress";
const CONNECTOR_ARN: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
const VM_SUBNET: &str = "subnet-0aaa1111bbbb2222c";
const VM_SG: &str = "sg-0ddd3333eeee4444f";
const PROXY_ID: &str = "i-0123456789abcdef0";
const LAMBDA_PIN: &str = "--region eu-central-1 --endpoint-url https://lambda.eu-central-1.amazonaws.com";

/// `<tmp>/bin` with the stateful aws, pulumi, the ai-env stand-in (as
/// `ai-env-stand-in`) and node (ops.sh reads JSON with it).
fn s5_bin(t: &Path) -> PathBuf {
    let bin = bin_with(t, &[("aws-state.sh", "aws"), ("pulumi.sh", "pulumi"), ("ai-env.sh", "ai-env-stand-in")]);
    let node = node().expect("node is required: ops.sh reads JSON with it (s3-preflight P4)");
    std::os::unix::fs::symlink(node, bin.join("node")).unwrap();
    bin
}

/// The fakes' state and their one log.
fn s5_env<'a>(cmd: &'a mut Command, t: &Path) -> &'a mut Command {
    let log = t.join("calls.log");
    cmd.env("FAKE_AWS_STATE", t.join("aws")).env("FAKE_AWS_LOG", &log).env("FAKE_AIENV_LOG", &log).env("FAKE_PULUMI_LOG", &log).env("FAKE_PULUMI_OUTPUTS", t.join("outputs.json"))
}

fn calls(t: &Path) -> Vec<String> {
    lines_of(&t.join("calls.log"))
}

/// Every lambda-core, ec2, ssm and logs call of the log carries the region and its pinned endpoint (the stateful fake
/// refuses one without, but a refused call can still pass a test that expects a failure); returns how many it saw.
fn assert_pinned(calls: &[String]) -> usize {
    let mut n = 0;
    for c in calls {
        let host = match c.split_whitespace().next() {
            Some("lambda-core") => "lambda",
            Some(s @ ("ec2" | "ssm" | "logs")) => s,
            _ => continue,
        };
        n += 1;
        let pin = format!("--region eu-central-1 --endpoint-url https://{host}.eu-central-1.amazonaws.com");
        assert!(c.contains(&pin), "not pinned to {pin}: {c}");
    }
    n
}

/// The index of the first call containing `want`.
fn at(calls: &[String], want: &str) -> usize {
    calls.iter().position(|c| c.contains(want)).unwrap_or_else(|| panic!("no call {want:?} in {calls:#?}"))
}

/// The text of `s` between `a` and `b`.
fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let rest = &s[s.find(a).unwrap_or_else(|| panic!("{a:?} not in {s}")) + a.len()..];
    &rest[..rest.find(b).unwrap_or(rest.len())]
}

/// The repo's ops.sh as infra.mk runs it, with 1 s polls, 5 s budgets and the stand-in as AI_ENV_CLI.
fn ops5(t: &Path, bin: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("/bin/bash");
    isolate(&mut cmd, t).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    s5_env(&mut cmd, t);
    cmd.arg(Path::new(REPO).join("infra/scripts/ops.sh"))
        .args(args)
        .env("REGION", "eu-central-1")
        .env("IMAGE_NAME", "ai-env-agent")
        .env("IMAGE_OUT", t.join("out"))
        .env("STACK", "dev")
        .env("IMAGE_WAIT_TIMEOUT", "5")
        .env("IMAGE_WAIT_POLL", "1")
        .env("VERSIONS_WARN", "40")
        .env("VERSIONS_QUOTA", "50")
        .env("CONNECTOR_WAIT_TIMEOUT", "5")
        .env("CONNECTOR_WAIT_POLL", "1")
        .env("AI_ENV_CLI", bin.join("ai-env-stand-in"));
    cmd
}

/// A copy of the repo's make files under `<tmp>/w`, for the recipes that
/// write relative to the tree (deploy, s5-smoke) or must not find a file:
/// the Makefile, infra/infra.mk, the parameter files (egress-config.json
/// only when `egress_config`), ops.sh, pass-exec.sh (TIER's guard after the
/// passphrase's unseal) and image/Dockerfile.
fn planted_repo(tmp: &Path, egress_config: bool) -> PathBuf {
    let w = tmp.join("w");
    let mut files = vec!["Makefile", "infra/infra.mk", "infra/image-config.json", "infra/scripts/ops.sh", "infra/scripts/pass-exec.sh", "image/Dockerfile"];
    if egress_config {
        files.push("infra/egress-config.json");
    }
    for rel in files {
        let to = w.join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(Path::new(REPO).join(rel), &to).unwrap_or_else(|e| panic!("{rel}: {e}"));
    }
    w
}

/// `make -s -C <w> <args>`, isolated like [`make`].
fn make_in(tmp: &Path, bin: &Path, w: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("make");
    isolate(&mut cmd, tmp).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    cmd.args(["-s", "--no-print-directory", "-C"]).arg(w).args(args);
    cmd
}

/// Where make and ops.sh look for the stack's sealed passphrase by default (A39: PULUMI_SEALED), under `home`, the
/// HOME of the run ([`isolate`] sets it to the test's temp dir).
fn sealed_path(home: &Path) -> PathBuf {
    home.join(".config/ai-env/pulumi.env")
}

/// The stack's passphrase sealed at `file` as the stand-in reads it (tests/fakes/ai-env.sh `run -f`): `kind` "" seals
/// the fake stack's passphrase (aws_keys::passphrase(), which the fake pulumi accepts), "empty" the README's first line
/// before `ai-env edit` set its value, "none" no PULUMI_CONFIG_PASSPHRASE at all. No file holds the value itself.
fn seal_passphrase(file: &Path, kind: &str) -> PathBuf {
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, if kind.is_empty() { "FAKE-SEALED-PASSPHRASE\n".to_string() } else { format!("FAKE-SEALED-PASSPHRASE {kind}\n") }).unwrap();
    file.to_path_buf()
}

/// A network connector of the stateful aws: `states` its get answers in turn (the last one sticks).
fn seed_connector(t: &Path, name: &str, states: &str) -> PathBuf {
    let d = t.join("aws/connectors").join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("states"), format!("{states}\n")).unwrap();
    d
}

/// The proxy instance of the stateful aws.
fn seed_proxy(t: &Path, state: &str) {
    std::fs::create_dir_all(t.join("aws/proxy")).unwrap();
    std::fs::write(t.join("aws/proxy/state"), state).unwrap();
}

/// What `pulumi stack output --json` prints for an S5 stack (fake ids; the hashes made up).
fn outputs() -> Value {
    json!({
        "region": "eu-central-1",
        "imageArn": "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent",
        "connectorArn": CONNECTOR_ARN,
        "connectorName": CONNECTOR,
        "proxyPrivateIp": "10.42.0.10",
        "proxyInstanceId": PROXY_ID,
        "egressVpcId": "vpc-0123456789abcdef0",
        "vmSubnetId": VM_SUBNET,
        "vmEgressSecurityGroupId": VM_SG,
        "proxySecurityGroupId": "sg-0fff5555aaaa6666b",
        "operatorRoleArn": "arn:aws:iam::123456789012:role/ai-env-egress-operator",
        "egressLogGroup": "/ai-env/egress/squid",
        "dnsMode": "none",
        "parameterPrefix": "/ai-env/proxy",
        "squidConfSha256": "ab".repeat(32),
        "allowSha256": "cd".repeat(32),
    })
}

/// `<tmp>/outputs.json`, which the fake pulumi prints for `stack output`.
fn write_outputs(t: &Path, o: &Value) {
    std::fs::write(t.join("outputs.json"), o.to_string()).unwrap();
}

/// `o` as a stack the S8 operators' bootstrap deployed exports it: its account and the two operator users, which
/// infra.mk's TIER (ops.sh stack-deployer) and ops.sh identity read.
fn with_operators(mut o: Value) -> Value {
    o["accountId"] = json!("123456789012");
    o["deployerUserName"] = json!("ai-env-deployer");
    o["opsUserName"] = json!("ai-env-ops");
    o
}

/// `o` as an S9 stack exports it: the transcripts bucket, the proxy's S3 gateway endpoint and route table, and the
/// canonical hashes of the endpoint's and the bucket's policies (fake ids; the hashes made up), which `ai-env infra
/// status` records and `ai-env egress status` compares with the live store.
fn with_s9(mut o: Value) -> Value {
    o["transcriptsBucket"] = json!("ai-env-transcripts-123456789012");
    o["s3EndpointId"] = json!("vpce-0123456789abcdef0");
    o["s3EndpointPolicySha256"] = json!("e1".repeat(32));
    o["transcriptsBucketPolicySha256"] = json!("b1".repeat(32));
    o["proxyRouteTableId"] = json!("rtb-0a1b2c3d4e5f60002");
    o
}

/// state/infra.toml as the real `ai-env infra status --write` renders `o`
/// (its live reads answered, or refused, by the stateful aws): ops.sh
/// compares the stack outputs with exactly this format.
fn write_infra_state(t: &Path, bin_dir: &Path, o: &Value) {
    let input = t.join("status-in.json");
    std::fs::write(&input, o.to_string()).unwrap();
    let mut cmd = Command::new(bin());
    isolate(&mut cmd, t).env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display())).env("FAKE_AWS_STATE", t.join("aws"));
    let out = cmd.args(["infra", "status", "--write", "--stack", "dev", "--json-in"]).arg(&input).bounded();
    assert!(out.status.success() && t.join("bridge/state/infra.toml").is_file(), "{}", all(&out));
}

/// A state/vms row (only the keys ops.sh reads, as the registry writes them).
fn vm_row(t: &Path, stem: &str, body: &str) {
    let dir = t.join("bridge/state/vms");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{stem}.toml")), body).unwrap();
}

/// A `pulumi preview --json` plan: one step per (op, type, name), the state a
/// step of that op carries (a delete-replaced step only the old one).
fn plan(steps: &[(&str, &str, &str)]) -> Value {
    let steps: Vec<Value> = steps
        .iter()
        .map(|(op, ty, name)| {
            let urn = format!("urn:pulumi:dev::ai-env::{ty}::{name}");
            let state = json!({"type": ty, "urn": urn, "custom": true});
            if *op == "delete-replaced" {
                json!({"op": op, "urn": urn, "oldState": state})
            } else {
                json!({"op": op, "urn": urn, "newState": state})
            }
        })
        .collect();
    json!({"steps": steps, "diagnostics": []})
}

#[test]
fn make_n_of_the_s5_targets_names_their_commands_and_runs_nothing() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make(t.path(), &bin, &["-n"]).args(args).arg(format!("IMAGE_OUT={}", t.path().join("out").display())).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let ai_env = "cargo +1.98.1 run -q -p ai-env-cli --bin ai-env --";
    let lab_unset = LAB_UNSET;
    let probe_cli = format!("{lab_unset} AI_ENV_CLI='{ai_env}'");
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("connector-status", vec!["/bin/bash infra/scripts/ops.sh connector-status".into()]),
        ("connector-wait", vec!["CONNECTOR_WAIT_TIMEOUT=600".into(), "/bin/bash infra/scripts/ops.sh connector-wait".into()]),
        ("connector-probe", vec!["test \"\" = create-probe-connector ||".into(), probe_cli.clone(), "/bin/bash infra/scripts/ops.sh connector-probe".into()]),
        ("connector-delete", vec!["test \"\" = delete-connector ||".into(), "ops.sh vm-guard".into(), "ops.sh connector-delete".into()]),
        ("egress-logs", vec!["aws logs tail /ai-env/egress/squid --since 1h --format short".into(), "--region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com".into()]),
        ("allowlist-reload", vec![format!("{lab_unset} {ai_env} egress reload")]),
        ("proxy-stop", vec![format!("{lab_unset} {ai_env} proxy stop")]),
        ("proxy-start", vec![format!("{lab_unset} {ai_env} proxy start")]),
        ("proxy-patch", vec![format!("{lab_unset} {ai_env} proxy patch")]),
        ("s5-smoke", vec![format!("{lab_unset} {ai_env} vm smoke --egress vpc --max-duration 900 --json"), "grep -q '\"backend\":\"sdk\"'".into(), "grep -q '\"egress_ok\":true'".into(), ">> target/s5/smoke.jsonl".into()]),
        (
            "s6-smoke",
            vec![
                format!("{lab_unset} {ai_env} vm smoke --egress vpc --exec --max-duration 900 --json"),
                "grep -q '\"backend\":\"sdk\"'".into(),
                "grep -q '\"egress_ok\":true'".into(),
                "grep -q '\"exec_ok\":true'".into(),
                ">> target/s6/smoke.jsonl".into(),
            ],
        ),
        (
            "s7-smoke",
            vec![
                format!("{lab_unset} {ai_env} vm smoke --egress vpc --exec --with-credential --max-duration 900 --json"),
                "grep -q '\"backend\":\"sdk\"'".into(),
                "grep -q '\"egress_ok\":true'".into(),
                "grep -q '\"exec_ok\":true'".into(),
                "grep -q '\"cred_ok\":true'".into(),
                ">> target/s7/smoke.jsonl".into(),
            ],
        ),
        ("test-claude", vec![format!("{lab_unset} AI_ENV_CLAUDE_TESTS=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test claude_live -- --ignored --test-threads=1 --nocapture")]),
        ("test-aws", vec![format!("{lab_unset} AI_ENV_AWS_TESTS=1 "), "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored --test-threads=1 --nocapture".into()]),
        (
            "test-egress",
            vec![
                format!("{lab_unset} AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored live_egress_ --test-threads=1 --nocapture"),
                format!("{ai_env} egress allow ai-env-test github.com --remove"),
                "' EXIT;".into(),
            ],
        ),
        ("test-proxy", vec!["AI_ENV_PROXY_TESTS=1 AI_ENV_PROXY_SYSTEMD=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test proxy_docker -- --include-ignored --test-threads=1".into()]),
        // No $(MAKE) on its line: GNU make would run it even under -n (ops.sh runs every step's make itself).
        (
            "claude-update",
            vec![
                format!("{probe_cli} LOCK='image/claude.lock' CLAUDE_RELEASES='https://downloads.claude.ai/claude-code-releases' CLAUDE_GPG_FPR='31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE'"),
                "/bin/bash infra/scripts/ops.sh claude-update".into(),
            ],
        ),
    ];
    for (target, wants) in &cases {
        let text = dry(&[*target], &[]);
        for want in wants {
            assert!(text.contains(want.as_str()), "{target}: {want} missing from the dry run: {text}");
        }
        for never in ["--yes", "--show-secrets", "--follow"] {
            assert!(!text.contains(never), "{target}: {never} in the dry run: {text}");
        }
    }
    let delete = dry(&["connector-delete"], &[]);
    assert!(delete.find("ops.sh vm-guard").unwrap() < delete.find("ops.sh connector-delete").unwrap(), "vm-guard first: {delete}");
    let smoke = dry(&["s5-smoke"], &[]);
    assert!(smoke.find("smoke.jsonl").unwrap() < smoke.find("egress_ok").unwrap(), "every record is kept, then judged (as s4-smoke): {smoke}");
    let smoke = dry(&["s6-smoke"], &[]);
    assert!(smoke.find("smoke.jsonl").unwrap() < smoke.find("exec_ok").unwrap(), "every record is kept, then judged (as s5-smoke): {smoke}");
    let smoke = dry(&["s7-smoke"], &[]);
    assert!(smoke.find("smoke.jsonl").unwrap() < smoke.find("\"backend\":\"sdk\"").unwrap(), "every record is kept before its first judge (as s6-smoke): {smoke}");

    // The switches count only on the command line.
    assert!(dry(&["proxy-stop", "YES=1"], &[]).contains(&format!("{ai_env} proxy stop --yes")));
    assert!(!dry(&["proxy-stop"], &[("YES", "1")]).contains("--yes"), "YES=1 in the environment is ignored");
    assert!(dry(&["egress-logs", "FOLLOW=1", "SINCE=15m"], &[]).contains("--since 15m --format short --follow --region eu-central-1"));
    assert!(!dry(&["egress-logs"], &[("FOLLOW", "1")]).contains("--follow"));
    let no_systemd = dry(&["test-proxy", "SYSTEMD=0"], &[]);
    assert!(no_systemd.contains("AI_ENV_PROXY_TESTS=1 cargo +1.98.1 test") && !no_systemd.contains("AI_ENV_PROXY_SYSTEMD"), "{no_systemd}");
    assert!(dry(&["test-proxy"], &[("SYSTEMD", "0")]).contains("AI_ENV_PROXY_SYSTEMD=1"), "SYSTEMD=0 in the environment is ignored");
    // CRED=1 (S7) adds the live credential tests, whose Touch IDs and model requests a stray export must never start.
    assert!(!dry(&["test-aws"], &[]).contains("AI_ENV_CREDENTIAL_TESTS"));
    assert!(dry(&["test-aws", "CRED=1"], &[]).contains("AI_ENV_CREDENTIAL_TESTS=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored"));
    assert!(!dry(&["test-aws"], &[("CRED", "1")]).contains("AI_ENV_CREDENTIAL_TESTS"), "CRED=1 in the environment is ignored");

    // deploy: check-policies, one preview, the gate, then everything that was there, then the S5 steps.
    let text = dry(&["deploy"], &[]);
    let order = [
        "P16 AWSServiceRoleForLambda",
        "/bin/bash infra/scripts/check-policies.sh",
        "pulumi preview --json --show-sames --show-reads --non-interactive --stack dev)",
        "/bin/bash infra/scripts/ops.sh plan-gate",
        "/bin/bash infra/scripts/ops.sh snapshot pre-deploy",
        "pulumi up --stack dev)",
        "/bin/bash infra/scripts/ops.sh wait",
        "if [ $st -eq 0 ]; then REGION=eu-central-1",
        "/bin/bash infra/scripts/ops.sh connector-wait || st=$?; fi;",
        "if [ $st -eq 0 ]; then after=\"\"; else after=--after-failure; fi;",
        &format!("{probe_cli} REGION=eu-central-1"),
        "/bin/bash infra/scripts/ops.sh post-deploy $after; p=$?;",
        "exit $(( st ? st : p ))",
    ];
    let mut last = 0;
    for want in order {
        let i = text[last..].find(want).unwrap_or_else(|| panic!("{want} missing (or out of order) in the deploy dry run: {text}")) + last;
        last = i;
    }
    assert_eq!(text.matches("pulumi preview --json --show-sames").count(), 1, "one preview: {text}");
    assert!(!text.contains("--yes") && !text.contains("--show-secrets"), "{text}");
    assert!(text.contains("printf '%s' \"$plan\" |") && !text.contains("tee") && !text.contains("> \"$plan") && !text.contains("<<<\"$plan\""), "the plan stays in a variable and goes through pipes: {text}");
    assert_eq!(read(&log), "", "make -n ran a tool");
    assert!(!t.path().join("out").exists(), "make -n wrote into IMAGE_OUT");
}

#[test]
fn the_help_lists_every_preview_scratch_negative_and_the_live_connector_read() {
    let ps = read(&Path::new(REPO).join("infra/scripts/preview-scratch.sh"));
    let line = ps.lines().find(|l| l.starts_with("negatives=\"")).expect("the negatives list of preview-scratch.sh");
    let negatives: Vec<&str> = line.trim_start_matches("negatives=\"").trim_end_matches('"').split_whitespace().collect();
    assert!(negatives.len() >= 13, "{negatives:?}");
    let mk = read(&Path::new(REPO).join("infra/infra.mk"));
    let help = mk.lines().find(|l| l.starts_with("preview-scratch:")).unwrap();
    let listed: Vec<&str> = between(help, "NEGATIVE=", ";").split('|').collect();
    assert_eq!(listed, negatives, "{help}");
    assert!(help.ends_with("; EGRESS_MODE=none|firewall"), "{help}");
    let status = mk.lines().find(|l| l.starts_with("infra-status:")).unwrap();
    assert!(status.contains("get-microvm-image and get-network-connector"), "{status}");
}

#[test]
fn s5_confirm_gates_count_only_on_the_command_line() {
    for (target, value) in [("connector-probe", "create-probe-connector"), ("connector-delete", "delete-connector")] {
        let t = tempfile::tempdir().unwrap();
        let bin = s5_bin(t.path());
        seed_connector(t.path(), CONNECTOR, "ACTIVE");
        let wrong = format!("CONFIRM={value}x");
        for (args, envs) in [(vec![target], vec![]), (vec![target], vec![("CONFIRM", value)]), (vec![target, wrong.as_str()], vec![])] {
            let mut cmd = make(t.path(), &bin, &args);
            let out = s5_env(&mut cmd, t.path()).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).envs(envs.iter().copied()).bounded();
            let text = all(&out);
            assert!(!out.status.success() && text.contains(&format!("set CONFIRM={value} on the command line")), "{target} {args:?} {envs:?}: {text}");
            assert_eq!(calls(t.path()), Vec::<String>::new(), "{target} {args:?} {envs:?}: nothing ran");
        }
        assert!(t.path().join("aws/connectors").join(CONNECTOR).is_dir());
    }
}

/// `ops.sh replace-guard` over `p` on stdin.
fn guard(t: &Path, bin: &Path, p: &str, envs: &[(&str, &str)]) -> Output {
    let file = t.join("plan.json");
    std::fs::write(&file, p).unwrap();
    ops5(t, bin, &["replace-guard"]).stdin(std::fs::File::open(&file).unwrap()).envs(envs.iter().copied()).bounded()
}

/// What the connector's ENIs pin, one resource of each guarded type.
const GUARDED: &[(&str, &str)] = &[
    ("aws:ec2/vpc:Vpc", "ai-env-egress"),
    ("aws:ec2/subnet:Subnet", "ai-env-egress-vms"),
    ("aws:ec2/subnet:Subnet", "ai-env-egress-proxy"),
    ("aws:ec2/securityGroup:SecurityGroup", "ai-env-vm-egress"),
    ("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "ai-env-proxy-from-ai-env-vm-egress-tcp-3128"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-vm-egress-to-10.42.0.10-32-tcp-3128"),
    ("aws:ec2/networkAcl:NetworkAcl", "ai-env-egress-vms"),
    ("aws-native:lambda:NetworkConnector", "ai-env-egress"),
];
const PROXY_INSTANCE: (&str, &str) = ("aws:ec2/instance:Instance", "ai-env-egress-proxy");
const REFUSAL: &str = "would be replaced: run `make connector-delete CONFIRM=delete-connector` first (the connector's ENIs pin them)";

#[test]
fn the_replacement_guard_refuses_what_the_connector_pins_and_names_a_new_proxy() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    let ordinary = [("same", "aws:budgets/budget:Budget", "ai-env-monthly"), ("update", "aws:ssm/parameter:Parameter", "ai-env-proxy-allow"), ("same", "pulumi:pulumi:Stack", "ai-env-dev")];
    for &(ty, name) in GUARDED {
        for op in ["replace", "create-replacement", "delete-replaced"] {
            let mut steps = ordinary.to_vec();
            steps.push((op, ty, name));
            let out = guard(t.path(), &bin, &plan(&steps).to_string(), &[]);
            let text = all(&out);
            assert!(!out.status.success() && text.contains(&format!("replacement guard: {ty} {name} {REFUSAL}")), "{op} {ty} {name}: {text}");
            assert!(text.contains(&format!("{CONNECTOR} ACTIVE {CONNECTOR_ARN}")), "names the connector that pins them: {text}");
        }
    }

    // A replaced proxy instance is allowed and named once for its three steps,
    // with the plan's own reasons (none here); nothing else is listed.
    std::fs::remove_file(t.path().join("calls.log")).unwrap();
    let proxy: Vec<(&str, &str, &str)> = ["create-replacement", "replace", "delete-replaced"].iter().map(|op| (*op, PROXY_INSTANCE.0, PROXY_INSTANCE.1)).collect();
    let out = guard(t.path(), &bin, &plan(&proxy).to_string(), &[]);
    let text = all(&out);
    assert!(out.status.success() && text.contains("replacement guard: aws:ec2/instance:Instance ai-env-egress-proxy will be replaced (the plan names no reason; a change to a file embedded in its user-data is one)"), "{text}");
    assert_eq!(text.matches("will be replaced").count(), 1, "{text}");
    // A real replace step (pulumi 3.266: one step, op replace) carries replaceReasons: the guard names them.
    let mut why = plan(&[("replace", PROXY_INSTANCE.0, PROXY_INSTANCE.1)]);
    why["steps"][0]["replaceReasons"] = json!(["subnetId", "userData"]);
    let text = all(&guard(t.path(), &bin, &why.to_string(), &[]));
    assert!(text.contains("ai-env-egress-proxy will be replaced (subnetId, userData; a change to a file embedded in its user-data is one)"), "{text}");
    assert!(text.contains("nothing the connector's ENIs pin is replaced"), "{text}");
    assert_eq!(calls(t.path()), Vec::<String>::new(), "nothing guarded, nothing listed");

    // Updates in place pass; a proxy and a subnet together are refused, both named.
    let out = guard(t.path(), &bin, &plan(&[("update", "aws:ec2/securityGroup:SecurityGroup", "ai-env-vm-egress"), ("same", "aws:ec2/vpc:Vpc", "ai-env-egress"), ("update", "aws-native:lambda:NetworkConnector", "ai-env-egress")]).to_string(), &[]);
    assert!(out.status.success(), "{}", all(&out));
    let mut both = proxy.clone();
    both.push(("replace", "aws:ec2/subnet:Subnet", "ai-env-egress-vms"));
    let out = guard(t.path(), &bin, &plan(&both).to_string(), &[]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("ai-env-egress-proxy will be replaced") && text.contains(&format!("aws:ec2/subnet:Subnet ai-env-egress-vms {REFUSAL}")), "{text}");

    // After `make connector-delete` nothing pins them: the plan still shows
    // the replacements, and they pass once no connector exists at all...
    let subnet = plan(&[("replace", "aws:ec2/subnet:Subnet", "ai-env-egress-vms"), ("create-replacement", "aws-native:lambda:NetworkConnector", "ai-env-egress")]).to_string();
    std::fs::remove_dir_all(t.path().join("aws/connectors").join(CONNECTOR)).unwrap();
    let out = guard(t.path(), &bin, &subnet, &[]);
    let text = all(&out);
    assert!(out.status.success() && text.contains("aws:ec2/subnet:Subnet ai-env-egress-vms, aws-native:lambda:NetworkConnector ai-env-egress will be replaced: no network connector exists"), "{text}");
    // ...while any connector, a leftover probe one too, still blocks them.
    seed_connector(t.path(), "ai-env-egress-probe-1790000000", "ACTIVE");
    let out = guard(t.path(), &bin, &subnet, &[]);
    assert!(!out.status.success() && all(&out).contains(REFUSAL) && all(&out).contains("ai-env-egress-probe-1790000000"), "{}", all(&out));

    // Fail closed: a listing that fails, a plan that is not one.
    let out = guard(t.path(), &bin, &subnet, &[("FAKE_AWS_FAIL_OP", "lambda-core list-network-connectors")]);
    assert!(!out.status.success() && all(&out).contains("the connectors cannot be listed: refusing"), "{}", all(&out));
    for bad in ["not json", "{\"diagnostics\": []}"] {
        let out = guard(t.path(), &bin, bad, &[]);
        assert!(!out.status.success() && all(&out).contains("cannot read the plan: refusing"), "{bad}: {}", all(&out));
    }
}

/// A plan updating the egress VPC from `old` to `new` DNS attributes (support, hostnames); `outputs` puts the old
/// values in the old state's outputs, else in its inputs.
fn vpc_dns_plan(old: (bool, bool), new: (bool, bool), outputs: bool) -> String {
    let urn = "urn:pulumi:dev::ai-env::aws:ec2/vpc:Vpc::ai-env-egress";
    let attrs = |(s, h): (bool, bool)| json!({"cidrBlock": "10.42.0.0/16", "enableDnsSupport": s, "enableDnsHostnames": h});
    let old_state = if outputs { json!({"type": "aws:ec2/vpc:Vpc", "urn": urn, "inputs": {"cidrBlock": "10.42.0.0/16"}, "outputs": attrs(old)}) } else { json!({"type": "aws:ec2/vpc:Vpc", "urn": urn, "inputs": attrs(old)}) };
    json!({"steps": [{"op": if old == new { "same" } else { "update" }, "urn": urn, "oldState": old_state, "newState": {"type": "aws:ec2/vpc:Vpc", "urn": urn, "inputs": attrs(new)}}], "diagnostics": []}).to_string()
}

#[test]
fn the_plan_gate_refuses_turning_the_vpc_dns_on_under_a_live_connector() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    let refusal = "turning the VPC's Amazon DNS on under a live connector opens DNS until the DNS Firewall exists: make connector-delete first";
    // (old, new, from outputs, the attributes named)
    let refused = [
        ((false, false), (true, false), true, "enableDnsSupport"),
        ((false, false), (false, true), false, "enableDnsHostnames"),
        ((false, false), (true, true), true, "enableDnsSupport and enableDnsHostnames"),
    ];
    for (old, new, outputs, named) in refused {
        let out = guard(t.path(), &bin, &vpc_dns_plan(old, new, outputs), &[]);
        let text = all(&out);
        assert!(!out.status.success() && text.contains(&format!("the plan turns the VPC's {named} on: {refusal}")), "{old:?} -> {new:?}: {text}");
    }
    // Unchanged, already on, or turned off: nothing to refuse (and no listing needed).
    std::fs::remove_file(t.path().join("calls.log")).unwrap();
    for (old, new) in [((false, false), (false, false)), ((true, true), (true, true)), ((true, false), (false, false))] {
        let out = guard(t.path(), &bin, &vpc_dns_plan(old, new, true), &[]);
        assert!(out.status.success() && all(&out).contains("the VPC's Amazon DNS stays as it is"), "{old:?} -> {new:?}: {}", all(&out));
    }
    assert_eq!(calls(t.path()), Vec::<String>::new());
    // No connector at all: DNS on passes with a note.
    std::fs::remove_dir_all(t.path().join("aws/connectors").join(CONNECTOR)).unwrap();
    let out = guard(t.path(), &bin, &vpc_dns_plan((false, false), (true, false), true), &[]);
    assert!(out.status.success() && all(&out).contains("the plan turns the VPC's enableDnsSupport on: no network connector exists"), "{}", all(&out));
    assert_eq!(assert_pinned(&calls(t.path())), 1, "one pinned listing: {:?}", calls(t.path()));
}

#[test]
fn connector_wait_waits_for_active_and_stops_on_failed_inactive_or_its_timeout() {
    type Case<'a> = (&'a str, Option<(&'a str, &'a str)>, &'a str, bool, &'a [&'a str]);
    let cases: &[Case] = &[
        ("PENDING PENDING ACTIVE", None, "10", true, &["connector-wait: PENDING (", "connector-wait: ai-env-egress ACTIVE after"]),
        ("PENDING FAILED", Some(("SubnetOutOfIPAddresses", "the subnet has no free address")), "10", false, &["ai-env-egress is FAILED after", ": SubnetOutOfIPAddresses: the subnet has no free address (make connector-status)"]),
        ("INACTIVE", Some(("Idle", "unused for 14 days")), "10", false, &["ai-env-egress is INACTIVE after", ": Idle: unused for 14 days"]),
        ("PENDING", None, "2", false, &["ai-env-egress still PENDING after", "(CONNECTOR_WAIT_TIMEOUT=2): make connector-status"]),
    ];
    for (states, reason, timeout, ok, wants) in cases {
        let t = tempfile::tempdir().unwrap();
        let bin = s5_bin(t.path());
        let d = seed_connector(t.path(), CONNECTOR, states);
        if let Some((code, text)) = reason {
            std::fs::write(d.join("reason_code"), code).unwrap();
            std::fs::write(d.join("reason"), text).unwrap();
        }
        let out = ops5(t.path(), &bin, &["connector-wait"]).env("CONNECTOR_WAIT_TIMEOUT", timeout).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), *ok, "{states}: {text}");
        for want in *wants {
            assert!(text.contains(want), "{states}: want {want}: {text}");
        }
        let gets: Vec<String> = calls(t.path()).into_iter().filter(|c| c.starts_with("lambda-core get-network-connector")).collect();
        assert!(!gets.is_empty() && gets.iter().all(|c| c.contains(&format!("--identifier {CONNECTOR} {LAMBDA_PIN}"))), "{gets:?}");
    }
    // No connector: refused at once, nothing polled.
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    let out = ops5(t.path(), &bin, &["connector-wait"]).bounded();
    assert!(!out.status.success() && all(&out).contains("connector-wait: no connector ai-env-egress in eu-central-1"), "{}", all(&out));
    assert!(calls(t.path()).iter().all(|c| !c.contains("get-network-connector")), "{:?}", calls(t.path()));
}

/// `ops.sh connector-probe`: the stand-in records the probe connector's state when it is called.
fn probe(t: &Path, bin: &Path, envs: &[(&str, &str)]) -> Output {
    ops5(t, bin, &["connector-probe"]).env("FAKE_AIENV_PEEK", t.join("aws")).envs(envs.iter().copied()).bounded()
}

/// The probe connector's name, from the create call.
fn probe_name(calls: &[String]) -> String {
    let create = &calls[at(calls, "lambda-core create-network-connector")];
    let name = between(create, "--name ", " ").to_string();
    let stamp = name.strip_prefix("ai-env-egress-probe-").unwrap_or_else(|| panic!("{create}"));
    assert!(!stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit()), "ai-env-egress-probe-<unix time>: {name}");
    name
}

/// The wait for the probe connector takes minutes (255 and 265 s live, 2 Oct 2026) and once looked like a hang: it
/// names its limit and says it is still waiting every PROBE_PROGRESS_S (60 s; 1 s here). The connector is held
/// PENDING until the stand-in's `lab run` has ended (create-hold), so its five PENDING polls always fall inside the
/// progress loop: without the hold a slow stand-in on a loaded machine outlasted them, the wait was over before the
/// loop began, and no progress line was due (seen once in a full gate, 7 Oct 2026).
#[test]
fn connector_probe_says_it_is_still_waiting() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    // A stand-in (8 s) far slower than the polls before ACTIVE (two PENDING, about 2-4 s with the fake's per-call cost):
    // without the hold the wait would be over before the progress loop began, so this fails if the hold is dropped.
    std::fs::write(t.path().join("aws/create-states"), "PENDING PENDING ACTIVE\n").unwrap();
    std::fs::write(t.path().join("aws/create-hold"), "").unwrap();
    let out = probe(t.path(), &bin, &[("PROBE_PROGRESS_S", "1"), ("CONNECTOR_WAIT_TIMEOUT", "60"), ("FAKE_AIENV_LAB_SLEEP", "8")]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("(polled every 1s since the create, at most 60s;") && text.contains("connector-probe: still waiting after "), "{text}");
    assert!(text.find("still waiting after ").unwrap() < text.find("became ACTIVE ").unwrap(), "{text}");
    let name = probe_name(&calls(t.path()));
    assert!(text.contains(&format!("connector-probe: deleted {name}")), "{text}");
}

#[test]
fn connector_probe_measures_a_pending_connector_and_deletes_it_on_every_path() {
    let setup = |create_states: &str| {
        let t = tempfile::tempdir().unwrap();
        let bin = s5_bin(t.path());
        seed_connector(t.path(), CONNECTOR, "ACTIVE");
        std::fs::write(t.path().join("aws/create-states"), format!("{create_states}\n")).unwrap();
        (t, bin)
    };
    // The stack connector's subnet, SG and role; the probe while PENDING; the activation polled from the create on;
    // the delete. The fake holds the probe connector PENDING until the stand-in's 3 s `lab run` has ended (create-hold),
    // so the probe sees it PENDING whatever the load, and an activation time measured from the create is at least 3 s.
    let (t, bin) = setup("PENDING ACTIVE");
    std::fs::write(t.path().join("aws/create-hold"), "").unwrap();
    let out = probe(t.path(), &bin, &[("FAKE_AIENV_LAB_SLEEP", "3"), ("CONNECTOR_WAIT_TIMEOUT", "60")]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let secs: u64 = between(&text, "became ACTIVE ", "s after create-network-connector (polled every 1s from the create on)").parse().unwrap_or_else(|e| panic!("{e}: {text}"));
    assert!((3..60).contains(&secs), "the activation time is measured from the create, the 3 s probe included: {secs} s: {text}");
    let c = calls(t.path());
    let name = probe_name(&c);
    let arn = format!("arn:aws:lambda:eu-central-1:123456789012:network-connector:{name}");
    let create = at(&c, "lambda-core create-network-connector");
    let lab = at(&c, &format!("lab run connector-pending {arn} [AI_ENV=unset]"));
    assert!(c[lab].ends_with("[state=PENDING]"), "the probe ran while the connector was PENDING: {}", c[lab]);
    let first_poll = at(&c, &format!("get-network-connector --identifier {arn} {LAMBDA_PIN}"));
    let last_poll = c.iter().rposition(|l| l.contains(&format!("get-network-connector --identifier {arn} "))).unwrap();
    let delete = at(&c, &format!("lambda-core delete-network-connector --identifier {name} {LAMBDA_PIN}"));
    assert!(at(&c, &format!("get-network-connector --identifier {CONNECTOR} ")) < create && create < lab && create < first_poll && last_poll < delete && lab < delete, "{c:#?}");
    assert!(c.iter().filter(|l| l.contains(&format!("get-network-connector --identifier {arn} "))).count() >= 2, "{c:#?}");
    assert!(assert_pinned(&c) >= 5, "{c:#?}");
    let cfg: Value = serde_json::from_str(between(&c[create], "--configuration ", " --operator-role")).unwrap();
    assert_eq!(cfg, json!({"VpcEgressConfiguration": {"SubnetIds": [VM_SUBNET], "SecurityGroupIds": [VM_SG], "NetworkProtocol": "IPv4", "AssociatedComputeResourceTypes": ["MicroVm"]}}));
    assert!(c[create].contains("--operator-role arn:aws:iam::123456789012:role/ai-env-egress-operator"), "{}", c[create]);
    assert!(text.contains(&format!("connector-probe: deleted {name}")), "{text}");
    assert_eq!(lines_of(&t.path().join("aws/deleted")), vec![name.clone()]);
    assert!(!t.path().join("aws/connectors").join(&name).exists() && t.path().join("aws/connectors").join(CONNECTOR).is_dir());

    // A failed probe, a wait that times out, a connector that fails: deleted all the same (the EXIT trap).
    type Path3<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], &'a str);
    let failures: &[Path3] = &[
        ("a failed probe", "PENDING ACTIVE", &[("FAKE_AIENV_LAB_RC", "3")], "ai-env lab run connector-pending failed (exit 3, above)"),
        ("a wait that times out", "PENDING", &[("CONNECTOR_WAIT_TIMEOUT", "2")], "still PENDING after"),
        ("a connector that fails", "PENDING FAILED", &[], "is FAILED after"),
    ];
    for (what, states, envs, want) in failures {
        let (t, bin) = setup(states);
        let out = probe(t.path(), &bin, envs);
        let text = all(&out);
        assert!(!out.status.success() && text.contains(want), "{what}: {text}");
        let name = probe_name(&calls(t.path()));
        assert!(text.contains(&format!("connector-probe: deleted {name}")), "{what}: {text}");
        assert_eq!(lines_of(&t.path().join("aws/deleted")), vec![name.clone()], "{what}");
        assert!(!t.path().join("aws/connectors").join(&name).exists(), "{what}");
    }

    // Ctrl-C during the probe (SIGINT to the whole group): the background poll is stopped, the connector deleted.
    let (t, bin) = setup("PENDING");
    let mut cmd = ops5(t.path(), &bin, &["connector-probe"]);
    cmd.env("CONNECTOR_WAIT_TIMEOUT", "120").env("FAKE_AIENV_LAB_SLEEP", "30");
    let out = run_bounded(&mut cmd, |pid| {
        let start = Instant::now();
        while !calls(t.path()).iter().any(|c| c.starts_with("lab run connector-pending")) {
            assert!(start.elapsed() < Duration::from_secs(60), "the probe never started: {:?}", calls(t.path()));
            std::thread::sleep(Duration::from_millis(20));
        }
        signal_group(pid, libc::SIGINT);
    });
    let name = probe_name(&calls(t.path()));
    assert!(!out.status.success() && all(&out).contains(&format!("connector-probe: deleted {name}")), "{}", all(&out));
    assert_eq!(lines_of(&t.path().join("aws/deleted")), vec![name]);

    // A delete refused while the connector is still busy: retried, then deleted.
    let (t, bin) = setup("PENDING ACTIVE");
    std::fs::write(t.path().join("aws/create-delete-refusals"), "2\n").unwrap();
    let out = probe(t.path(), &bin, &[]);
    let text = all(&out);
    let name = probe_name(&calls(t.path()));
    assert!(out.status.success() && text.contains(&format!("deleting {name} was refused (attempt 1 of 6")) && text.contains("(attempt 2 of 6") && text.contains(&format!("connector-probe: deleted {name}")), "{text}");
    assert_eq!(lines_of(&t.path().join("aws/deleted")), vec![name]);

    // A create that made nothing: no probe run, nothing to delete.
    let (t, bin) = setup("PENDING ACTIVE");
    let out = probe(t.path(), &bin, &[("FAKE_AWS_CREATE_CONNECTOR", "fail")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("create-network-connector ai-env-egress-probe-") && text.contains("(the create made none, or it is gone): nothing to delete"), "{text}");
    assert!(!calls(t.path()).iter().any(|c| c.starts_with("lab run")), "{:?}", calls(t.path()));

    // A delete that keeps failing is loud and fails the run, even after a good measurement.
    let (t, bin) = setup("PENDING ACTIVE");
    let out = probe(t.path(), &bin, &[("FAKE_AWS_DELETE_CONNECTOR", "fail")]);
    let name = probe_name(&calls(t.path()));
    let err = stderr(&out);
    assert!(!out.status.success() && err.contains(&format!("DELETING {name} FAILED 6 times")) && err.contains(&format!("\n  ai-env as deployer -- aws lambda-core delete-network-connector --identifier {name} {LAMBDA_PIN}\n")), "{}", all(&out));
    assert_eq!(calls(t.path()).iter().filter(|l| l.starts_with("lambda-core delete-network-connector")).count(), 6);
}

#[test]
fn vm_guard_refuses_while_a_connector_other_than_the_stacks_exists() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    seed_connector(t.path(), "ai-env-egress-probe-1790000000", "PENDING");
    let hand_made = seed_connector(t.path(), "hand-made", "ACTIVE");
    std::fs::write(hand_made.join("subnet"), VM_SUBNET).unwrap();
    let foreign = seed_connector(t.path(), "other-project", "ACTIVE");
    std::fs::write(foreign.join("subnet"), "subnet-0fff0000aaaa1111b").unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    let text = all(&out);
    assert!(!out.status.success() && text.contains("network connectors other than the stack's ai-env-egress exist"), "{text}");
    assert!(text.contains(&format!("  ai-env-egress-probe-1790000000 PENDING arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress-probe-1790000000 (subnets: {VM_SUBNET})")), "{text}");
    // A delete command for ours only: a probe of the stack's connector, or one on the VM subnet; the deployer's, as it
    // can run on this Mac (D13: a bare aws has no credentials).
    for ours in ["ai-env-egress-probe-1790000000", "hand-made"] {
        assert!(text.contains(&format!("    ai-env as deployer -- aws lambda-core delete-network-connector {LAMBDA_PIN} --identifier {ours}\n")), "{ours}: {text}");
    }
    assert!(text.contains("  other-project ACTIVE ") && text.contains("(subnets: subnet-0fff0000aaaa1111b)"), "{text}");
    assert!(text.contains(&format!("not on the VM subnet {VM_SUBNET} nor a probe of ai-env-egress: it may be another project's (no delete command")), "{text}");
    assert!(!text.contains("--identifier other-project"), "no delete command for another project's connector: {text}");
    let c = calls(t.path());
    assert!(!c.iter().any(|c| c.starts_with("lambda-microvms")), "refused before the VM check");
    assert!(assert_pinned(&c) >= 5 && c.iter().any(|l| l.starts_with("lambda-core list-network-connectors ")), "{c:#?}");
    for name in ["hand-made", "other-project"] {
        std::fs::remove_dir_all(t.path().join("aws/connectors").join(name)).unwrap();
    }

    // make connector-delete (as the deployer) stops there: the stack's connector stays.
    write_outputs(t.path(), &with_operators(outputs()));
    let mut cmd = make(t.path(), &bin, &["connector-delete", "CONFIRM=delete-connector"]);
    let out = s5_env(&mut cmd, t.path()).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).bounded();
    assert!(!out.status.success() && all(&out).contains("other than the stack's"), "{}", all(&out));
    assert!(all(&out).contains("connector-delete: identity user/ai-env-deployer (the deployer of stack dev)"), "{}", all(&out));
    assert!(!t.path().join("aws/deleted").exists() && t.path().join("aws/connectors").join(CONNECTOR).is_dir());

    // The stack's connector alone passes on to the VM check; a failed listing refuses.
    std::fs::remove_dir_all(t.path().join("aws/connectors/ai-env-egress-probe-1790000000")).unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    assert!(out.status.success() && all(&out).contains("vm-guard: no network connector but the stack's ai-env-egress") && all(&out).contains("no image ai-env-agent, hence no VM of it"), "{}", all(&out));
    let out = ops5(t.path(), &bin, &["vm-guard"]).env("FAKE_AWS_FAIL_OP", "lambda-core list-network-connectors").bounded();
    assert!(!out.status.success() && all(&out).contains("list-network-connectors failed"), "{}", all(&out));
}

/// vm-guard's VM check (before destroy, image-delete and connector-delete): a VM of the image that is not TERMINATED
/// refuses, listed, and the hint is the CLI's own terminate (TerminateMicrovm is the runtime key's, A24), never a bare
/// `aws`, which has no credentials on the Mac; once every VM is TERMINATED it passes.
#[test]
fn vm_guard_refuses_a_vm_not_terminated_and_names_ai_env_vm_terminate() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    set_image(t.path(), "UPDATED", "3", "", "2026-10-01T10:00:00.000000+00:00");
    std::fs::write(t.path().join("aws/vms"), "microvm-0aaa 3 RUNNING\nmicrovm-0bbb 2 TERMINATED\nmicrovm-0ccc 2 SUSPENDED\n").unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    let text = all(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    let want = "vm-guard: no network connector but the stack's ai-env-egress\nrefusing: VMs of ai-env-agent are not TERMINATED:\n  microvm-0aaa\tRUNNING\t3\n  microvm-0ccc\tSUSPENDED\t2\nterminate them first, each with the runtime key's Touch ID (--yes for a VM this Mac has no row of): ai-env vm terminate <id>\n";
    assert_eq!(stdout(&out), want, "{text}");
    assert!(!text.contains("terminate-microvm") && !text.contains("aws lambda-microvms"), "never a bare aws: {text}");
    let c = calls(t.path());
    assert_eq!(c.iter().filter(|l| l.starts_with("lambda-microvms list-microvms ")).count(), 1, "{c:#?}");
    // Every VM TERMINATED: it passes.
    std::fs::write(t.path().join("aws/vms"), "microvm-0aaa 3 TERMINATED\nmicrovm-0ccc 2 TERMINATED\n").unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    assert!(out.status.success() && stdout(&out).ends_with("vm-guard: every VM of ai-env-agent is TERMINATED\n"), "{}", all(&out));
}

#[test]
fn vm_guard_refuses_a_foreign_connector_alone_too() {
    // Only the stack's connector and one on another subnet (maybe another project's): still refused, fail closed,
    // listed without a delete command, before any VM check.
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    let foreign = seed_connector(t.path(), "other-project", "ACTIVE");
    std::fs::write(foreign.join("subnet"), "subnet-0fff0000aaaa1111b").unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    let text = all(&out);
    assert!(!out.status.success() && text.contains("network connectors other than the stack's ai-env-egress exist"), "{text}");
    assert!(text.contains("  other-project ACTIVE ") && !text.contains("--identifier other-project"), "{text}");
    let c = calls(t.path());
    assert!(!c.iter().any(|l| l.starts_with("lambda-microvms")), "refused before the VM check: {c:#?}");
    assert!(assert_pinned(&c) >= 1, "{c:#?}");
}

#[test]
fn connector_delete_runs_vm_guard_first_waits_until_gone_and_names_the_state_fix() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    write_outputs(t.path(), &with_operators(outputs()));
    let mut cmd = make(t.path(), &bin, &["connector-delete", "CONFIRM=delete-connector", "CONNECTOR_WAIT_POLL=1"]);
    let out = s5_env(&mut cmd, t.path()).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).bounded();
    let text = all(&out);
    assert!(out.status.success() && text.contains("connector-delete: ai-env-egress is gone after"), "{text}");
    assert!(text.contains("connector-delete: identity user/ai-env-deployer (the deployer of stack dev)"), "as the deployer: {text}");
    assert!(text.contains("cd infra && pulumi state delete '<that urn>' --stack dev"), "{text}");
    let verified = format!("state/egress-verified.toml ({}/state/egress-verified.toml): its records are bound to the deleted connector's Id and no longer admit anything; remove it", t.path().join("bridge").display());
    assert!(text.contains(&verified), "{text}");
    let c = calls(t.path());
    assert!(at(&c, "lambda-microvms list-microvm-images") < at(&c, &format!("lambda-core delete-network-connector --identifier {CONNECTOR} {LAMBDA_PIN}")), "vm-guard first: {c:#?}");
    assert_eq!(lines_of(&t.path().join("aws/deleted")), vec![CONNECTOR.to_string()]);
    assert!(assert_pinned(&c) >= 3, "{c:#?}");

    // Re-run on a connector already DELETING (an earlier run timed out): no second delete, the wait resumes until it is gone.
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    let d = seed_connector(t.path(), CONNECTOR, "DELETING");
    let log = t.path().join("calls.log");
    // Gone once the wait has seen it DELETING (its second listing).
    let gone = std::thread::spawn(move || {
        let start = Instant::now();
        while lines_of(&log).iter().filter(|l| l.starts_with("lambda-core list-network-connectors")).count() < 2 {
            assert!(start.elapsed() < Duration::from_secs(60), "connector-delete never listed twice");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::remove_dir_all(&d).unwrap();
    });
    let out = ops5(t.path(), &bin, &["connector-delete"]).env("CONNECTOR_WAIT_TIMEOUT", "30").bounded();
    gone.join().unwrap();
    let text = all(&out);
    assert!(out.status.success() && text.contains("connector-delete: ai-env-egress is DELETING already: waiting until it is gone") && text.contains("connector-delete: ai-env-egress is gone after"), "{text}");
    assert!(!calls(t.path()).iter().any(|l| l.starts_with("lambda-core delete-network-connector")), "no second delete: {:?}", calls(t.path()));
    // A delete refused while the connector is not deleting fails, naming its state.
    let d = seed_connector(t.path(), CONNECTOR, "ACTIVE");
    std::fs::write(d.join("delete-refusals"), "1\n").unwrap();
    let out = ops5(t.path(), &bin, &["connector-delete"]).bounded();
    assert!(!out.status.success() && all(&out).contains("connector-delete: delete-network-connector ai-env-egress failed (it is ACTIVE)"), "{}", all(&out));
    std::fs::remove_dir_all(&d).unwrap();

    // DELETE_FAILED stops with the service's reason; no connector: nothing to do.
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    let d = seed_connector(t.path(), CONNECTOR, "ACTIVE");
    std::fs::write(d.join("delete-states"), "DELETE_FAILED\n").unwrap();
    std::fs::write(d.join("reason_code"), "EniInUse").unwrap();
    std::fs::write(d.join("reason"), "an ENI is still attached").unwrap();
    let out = ops5(t.path(), &bin, &["connector-delete"]).bounded();
    assert!(!out.status.success() && all(&out).contains("ai-env-egress is DELETE_FAILED: EniInUse: an ENI is still attached"), "{}", all(&out));
    std::fs::remove_dir_all(&d).unwrap();
    let out = ops5(t.path(), &bin, &["connector-delete"]).bounded();
    assert!(out.status.success() && all(&out).contains("connector-delete: no connector ai-env-egress in eu-central-1"), "{}", all(&out));
}

#[test]
fn connector_status_shows_the_connector_the_others_and_the_managed_enis_of_the_vm_subnet() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    seed_connector(t.path(), "ai-env-egress-probe-1790000000", "PENDING");
    let enis = format!(
        "eni-0aaa00000000000a1 10.42.1.17 {VM_SG} {VM_SUBNET} managed\neni-0aaa00000000000a2 10.42.1.18 {VM_SG} {VM_SUBNET} managed\neni-0bbb00000000000b1 10.42.0.10 sg-0fff5555aaaa6666b subnet-0ccc2222dddd3333e\neni-0ccc00000000000c1 10.42.0.20 {VM_SG} subnet-0ccc2222dddd3333e managed\n"
    );
    std::fs::write(t.path().join("aws/enis"), enis).unwrap();
    write_outputs(t.path(), &outputs());
    let out = ops5(t.path(), &bin, &["connector-status"]).bounded();
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    for want in [
        "connector ai-env-egress: ACTIVE, version 1",
        &format!("  subnets {VM_SUBNET}, security groups {VM_SG}, IPv4 for MicroVm"),
        "other network connectors",
        "  ai-env-egress-probe-1790000000 PENDING ",
        &format!("2 ENI(s) in the VM subnet {VM_SUBNET} (managed ones included):"),
        &format!("  eni-0aaa00000000000a1  10.42.1.17  {VM_SG}  in-use lambda"),
        &format!("  eni-0aaa00000000000a2  10.42.1.18  {VM_SG}  in-use lambda"),
    ] {
        assert!(text.contains(want), "want {want}: {text}");
    }
    let c = calls(t.path());
    assert!(c[at(&c, "ec2 describe-network-interfaces")].contains(&format!("--include-managed-resources --filters Name=subnet-id,Values={VM_SUBNET} --region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com")), "{c:#?}");
    assert!(c.iter().any(|l| l.starts_with("pulumi stack output --json --stack dev --cwd ")), "the subnet comes from the stack outputs: {c:#?}");
    // Without the connector (after connector-delete) its subnet's ENIs still show.
    std::fs::remove_dir_all(t.path().join("aws/connectors").join(CONNECTOR)).unwrap();
    let out = ops5(t.path(), &bin, &["connector-status"]).bounded();
    assert!(out.status.success() && all(&out).contains("connector-status: no connector ai-env-egress") && all(&out).contains("2 ENI(s) in the VM subnet"), "{}", all(&out));
}

/// A post-deploy world: the outputs, state/infra.toml rendered from
/// `recorded` (none: no file), the proxy in `proxy`, the D29 snapshots with
/// active versions `pre` and `post`, and four state/vms rows.
fn post_deploy_tree(recorded: Option<&Value>, proxy: &str, pre: &str, post: &str) -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    write_outputs(t.path(), &outputs());
    if let Some(r) = recorded {
        write_infra_state(t.path(), &bin, r);
    }
    seed_proxy(t.path(), proxy);
    std::fs::create_dir_all(t.path().join("out")).unwrap();
    std::fs::write(t.path().join("out/pre-deploy-image.json"), json!({"state": "UPDATED", "latestActiveImageVersion": pre}).to_string()).unwrap();
    std::fs::write(t.path().join("out/post-deploy-image.json"), json!({"state": "UPDATED", "latestActiveImageVersion": post}).to_string()).unwrap();
    vm_row(t.path(), "mvm-a", "v = 1\nstatus = \"running\"\nid = \"mvm-a\"\negress = \"vpc\"\n");
    vm_row(t.path(), "mvm-b", "v = 1\nstatus = \"running\"\nid = \"mvm-b\"\negress = \"internet\"\n");
    vm_row(t.path(), "mvm-c", "not a row\n");
    vm_row(t.path(), "mvm-d", "v = 1\nstatus = \"terminated\"\nid = \"mvm-d\"\negress = \"vpc\"\n");
    (t, bin)
}

#[test]
fn post_deploy_reloads_a_running_proxy_warns_and_checks_drift_in_order() {
    let (t, bin) = post_deploy_tree(Some(&outputs()), "running", "2", "3");
    let out = ops5(t.path(), &bin, &["post-deploy"]).bounded();
    let text = stdout(&out);
    assert!(out.status.success(), "{}", all(&out));
    let c = calls(t.path());
    let order = [
        at(&c, "pulumi stack output --json --stack dev --cwd "),
        at(&c, &format!("ec2 describe-instances --instance-ids {PROXY_ID} --region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com")),
        at(&c, "egress reload --if-changed [AI_ENV=unset]"),
        at(&c, "egress status [AI_ENV=unset]"),
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{c:#?}");
    let lines = [
        &format!("deploy: ai-env egress reload --if-changed (the proxy instance {PROXY_ID} runs)") as &str,
        "deploy: warning: state/vms rows that may still run a vpc VM: mvm-a mvm-c (unreadable);",
        "new image version: run `ai-env egress check` (active version 2 -> 3: the credential gate admits an image version only with its own passing egress check record) and re-run `make test-egress`",
        "deploy: ai-env egress status (the out-of-band drift check: pulumi up does not refresh)",
    ];
    let mut last = 0;
    for want in lines {
        last = text[last..].find(want).unwrap_or_else(|| panic!("{want} missing or out of order: {text}")) + last;
    }
    // The same image version: no re-test line.
    let (t, bin) = post_deploy_tree(Some(&outputs()), "running", "3", "3");
    let out = ops5(t.path(), &bin, &["post-deploy"]).bounded();
    assert!(out.status.success() && !all(&out).contains("new image version"), "{}", all(&out));
}

#[test]
fn post_deploy_skips_what_a_stale_state_or_a_stopped_proxy_cannot_do() {
    let mut replaced = outputs();
    replaced["proxyInstanceId"] = json!("i-0fedcba9876543210");
    let mut new_allow = outputs();
    new_allow["allowSha256"] = json!("ef".repeat(32));
    type Case<'a> = (&'a str, Option<&'a Value>, &'a str, &'a [(&'a str, &'a str)], bool, bool, bool, &'a str);
    // (what, recorded state, proxy, envs, exit 0, reload called, status called, a line)
    let cases: &[Case] = &[
        ("a replaced proxy", Some(&replaced), "running", &[], true, false, false, "predates this deploy (proxy_instance_id differ from the stack outputs)"),
        ("no state/infra.toml", None, "running", &[], true, false, false, "state/infra.toml: make infra-status WRITE=1, then make proxy-start (it waits for a new proxy's first boot: SSM online, squid serving the parameters), then ai-env egress status"),
        ("a new allowlist", Some(&new_allow), "running", &[], true, true, false, "(allow_sha256 differ from the stack outputs): make infra-status WRITE=1"),
        ("a stopped proxy", Some(&outputs()), "stopped", &[], true, false, true, "is stopped: it reads its parameters when it starts (make proxy-start); egress reload skipped"),
        ("a failed reload", Some(&outputs()), "running", &[("FAKE_AIENV_RELOAD_RC", "7")], false, true, true, "deploy: egress reload failed (exit 7, above)"),
        ("drift", Some(&outputs()), "running", &[("FAKE_AIENV_STATUS_RC", "1"), ("FAKE_AIENV_DRIFT", "vm-route-table, sg-vm")], false, true, true, "deploy: DRIFT: ai-env egress status found drift in vm-route-table, sg-vm: something changed outside Pulumi; every other step ran, the deploy fails"),
        ("an unverified check", Some(&outputs()), "running", &[("FAKE_AIENV_STATUS_RC", "7")], true, true, true, "deploy: warning: ai-env egress status exit 7 (above; 7: a check could not be verified)"),
        ("an unreadable proxy", Some(&outputs()), "running", &[("FAKE_AWS_FAIL_OP", "ec2 describe-instances")], false, false, true, "cannot read the state of the proxy instance"),
    ];
    for (what, recorded, proxy, envs, ok, reload, status, want) in cases {
        let (t, bin) = post_deploy_tree(*recorded, proxy, "2", "2");
        let out = ops5(t.path(), &bin, &["post-deploy"]).envs(envs.iter().copied()).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), *ok, "{what}: {text}");
        assert!(text.contains(want), "{what}: want {want}: {text}");
        let c = calls(t.path());
        assert_eq!(c.iter().any(|l| l.starts_with("egress reload")), *reload, "{what}: {c:#?}");
        assert_eq!(c.iter().any(|l| l.starts_with("egress status")), *status, "{what}: {c:#?}");
        if *reload && *status {
            assert!(at(&c, "egress reload") < at(&c, "egress status"), "{what}");
        }
    }
}

/// S9: post-deploy's lag check covers the transcript store. A deploy that only changes the S3 endpoint's policy (an
/// AL2023_REPO_BUCKET fix) leaves state/infra.toml one hash behind: post-deploy names that key and runs no egress
/// status, which would judge the live endpoint by the old hash and fail the deploy on DRIFT before make infra-status
/// WRITE=1 could record the new one. The same for the store's other keys, and for a state from before the S9 deploy
/// (all five); a current state still runs egress status, and its drift fails the deploy.
#[test]
fn post_deploy_names_a_transcript_store_change_as_lag_never_drift() {
    let deployed = with_s9(outputs());
    let before = |changes: &[(&str, String)]| {
        let mut o = deployed.clone();
        for (k, v) in changes {
            o[*k] = json!(v);
        }
        o
    };
    // (what, the recorded state, the lag post-deploy names; none: egress status runs)
    let cases = [
        ("the endpoint's policy alone", before(&[("s3EndpointPolicySha256", "e0".repeat(32))]), "s3_endpoint_policy_sha256"),
        ("the bucket's policy alone", before(&[("transcriptsBucketPolicySha256", "b0".repeat(32))]), "transcripts_bucket_policy_sha256"),
        ("a replaced endpoint (the bucket policy names it)", before(&[("s3EndpointId", "vpce-0fedcba9876543210".into()), ("transcriptsBucketPolicySha256", "b0".repeat(32))]), "s3_endpoint_id transcripts_bucket_policy_sha256"),
        ("a state from before the S9 deploy", outputs(), "transcripts_bucket s3_endpoint_id s3_endpoint_policy_sha256 transcripts_bucket_policy_sha256 proxy_route_table_id"),
        ("a current state", deployed.clone(), ""),
    ];
    for (what, recorded, lag) in &cases {
        let (t, bin) = post_deploy_tree(Some(recorded), "running", "2", "2");
        write_outputs(t.path(), &deployed);
        // What the real egress status finds against an old store: the live endpoint is not the recorded one.
        let out = ops5(t.path(), &bin, &["post-deploy"]).env("FAKE_AIENV_STATUS_RC", "1").env("FAKE_AIENV_DRIFT", "vpc-endpoints").bounded();
        let text = all(&out);
        let c = calls(t.path());
        assert!(c.iter().any(|l| l.starts_with("egress reload --if-changed")), "{what}: the same proxy instance is still reloaded: {c:#?}");
        if lag.is_empty() {
            assert!(!out.status.success() && text.contains("deploy: DRIFT: ai-env egress status found drift in vpc-endpoints"), "{what}: {text}");
            continue;
        }
        assert!(out.status.success(), "{what}: {text}");
        assert!(text.contains(&format!("predates this deploy ({lag} differ from the stack outputs): make infra-status WRITE=1")), "{what}: {text}");
        assert!(!text.contains("DRIFT") && !c.iter().any(|l| l.starts_with("egress status")), "{what}: no egress status against the old state: {text}");
    }
}

/// `o` with the proxy documents' names an S8 operators stack exports, as this ai-env sends them.
fn with_documents(mut o: Value) -> Value {
    o["proxyReloadDocument"] = json!("ai-env-proxy-reload");
    o["proxyStatusDocument"] = json!("ai-env-proxy-status");
    o["proxyPatchDocument"] = json!("ai-env-proxy-patch");
    o
}

/// S10 (F2): post-deploy's lag check covers the connector and the proxy documents' names. egress status judges the
/// connector by the ARN state/infra.toml records, and every egress command refuses a state naming other documents than
/// the ones it sends (exit 1, which post-deploy reads as drift): a deploy that replaced the connector or renamed a
/// document leaves the state behind, so post-deploy names those keys and runs no egress status; a state from before the
/// documents' outputs names all three. A state that names a document the stack no longer exports is refused by the
/// reload too, so post-deploy skips it, saying so (a good deploy never fails on it); a state that names none (from
/// before the documents' outputs) passes the CLI's check, and its reload runs. The connector is compared as egress
/// status compares connectors, a final `:N` version dropped (the state holds the live read's ARN): the same connector
/// with and without one is no lag. A current state still runs egress status, and its drift fails the deploy.
#[test]
fn post_deploy_names_a_replaced_connector_or_renamed_documents_as_lag_never_drift() {
    let deployed = with_documents(with_s9(outputs()));
    let with = |o: &Value, changes: &[(&str, &str)]| {
        let mut o = o.clone();
        for (k, v) in changes {
            o[*k] = json!(v);
        }
        o
    };
    let versioned = format!("{CONNECTOR_ARN}:1");
    // (what, the recorded state, the deployed outputs, the lag post-deploy names; none: egress status runs)
    let cases = [
        ("a replaced connector", deployed.clone(), with(&deployed, &[("connectorArn", "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0fedcba9876543210")]), "connector_arn"),
        ("a renamed document", deployed.clone(), with(&deployed, &[("proxyPatchDocument", "ai-env-proxy-patch-v2")]), "proxy_patch_document"),
        ("a state from before the documents' outputs", with_s9(outputs()), deployed.clone(), "proxy_reload_document proxy_status_document proxy_patch_document"),
        ("a replaced connector and a renamed document", deployed.clone(), with(&deployed, &[("connectorArn", "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0fedcba9876543210"), ("proxyReloadDocument", "ai-env-proxy-reload-v2")]), "connector_arn proxy_reload_document"),
        ("the same connector, a version recorded", with(&deployed, &[("connectorArn", versioned.as_str())]), deployed.clone(), ""),
        ("the same connector, a version deployed", deployed.clone(), with(&deployed, &[("connectorArn", versioned.as_str())]), ""),
        ("a current state", deployed.clone(), deployed.clone(), ""),
    ];
    for (what, recorded, now, lag) in &cases {
        let (t, bin) = post_deploy_tree(Some(recorded), "running", "2", "2");
        if recorded["connectorArn"] != now["connectorArn"] {
            assert!(read(&t.path().join("bridge/state/infra.toml")).contains(&format!("connector_arn = {}\n", recorded["connectorArn"])), "{what}: the state records the connector it was written with");
        }
        write_outputs(t.path(), now);
        // What the real egress status finds against an old state: the recorded connector is not the live one.
        let out = ops5(t.path(), &bin, &["post-deploy"]).env("FAKE_AIENV_STATUS_RC", "1").env("FAKE_AIENV_DRIFT", "connector").bounded();
        let text = all(&out);
        let c = calls(t.path());
        // The documents the state names that the stack no longer exports: the reload would be refused (exit 1).
        let renamed: Vec<&str> = ["proxyReloadDocument", "proxyStatusDocument", "proxyPatchDocument"].into_iter().filter(|k| recorded.get(*k).is_some_and(|v| v.is_string()) && recorded[*k] != now[*k]).collect();
        if renamed.is_empty() {
            assert!(c.iter().any(|l| l.starts_with("egress reload --if-changed")), "{what}: the same proxy instance is still reloaded: {c:#?}");
        } else {
            assert!(!c.iter().any(|l| l.starts_with("egress reload")), "{what}: no reload the CLI would refuse: {c:#?}");
            assert!(text.contains("names other proxy documents than this deploy's (") && text.contains("every egress command refuses it): egress reload skipped; make infra-status WRITE=1, then make allowlist-reload"), "{what}: {text}");
        }
        if lag.is_empty() {
            assert!(!out.status.success() && text.contains("deploy: DRIFT: ai-env egress status found drift in connector"), "{what}: {text}");
            assert!(!text.contains("predates this deploy"), "{what}: {text}");
            continue;
        }
        assert!(out.status.success(), "{what}: {text}");
        assert!(text.contains(&format!("predates this deploy ({lag} differ from the stack outputs): make infra-status WRITE=1")), "{what}: {text}");
        assert!(!text.contains("DRIFT") && !c.iter().any(|l| l.starts_with("egress status")), "{what}: no egress status against the old state: {text}");
    }
}

#[test]
fn post_deploy_after_a_failure_still_reloads_and_warns_but_checks_no_drift() {
    let mut replaced = outputs();
    replaced["proxyInstanceId"] = json!("i-0fedcba9876543210");
    let missing = "/nonexistent/outputs.json";
    type Case<'a> = (&'a str, &'a Value, &'a str, &'a [(&'a str, &'a str)], bool, bool, bool);
    // (what, recorded state, proxy, envs, exit 0, reload called, the loud not-reloaded line)
    let cases: &[Case] = &[
        ("a running proxy", &outputs(), "running", &[], true, true, false),
        ("a stale state/infra.toml", &replaced, "running", &[], true, false, true),
        ("a failed reload", &outputs(), "running", &[("FAKE_AIENV_RELOAD_RC", "7")], false, true, true),
        ("a stopped proxy", &outputs(), "stopped", &[], true, false, false),
        ("no stack outputs (a failed first pulumi up)", &outputs(), "running", &[("FAKE_PULUMI_OUTPUTS", missing)], true, false, true),
    ];
    let loud = "deploy: THE DEPLOY FAILED AFTER pulumi up STARTED, AND THE PROXY WAS NOT RELOADED: it may still serve the pre-deploy parameters: make allowlist-reload";
    for (what, recorded, proxy, envs, ok, reload, warned) in cases {
        let (t, bin) = post_deploy_tree(Some(recorded), proxy, "2", "3");
        let out = ops5(t.path(), &bin, &["post-deploy", "--after-failure"]).envs(envs.iter().copied()).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), *ok, "{what}: {text}");
        let c = calls(t.path());
        assert_eq!(c.iter().any(|l| l.starts_with("egress reload --if-changed")), *reload, "{what}: {c:#?}");
        assert_eq!(text.contains(loud), *warned, "{what}: {text}");
        assert!(text.contains("deploy: warning: state/vms rows that may still run a vpc VM: mvm-a mvm-c (unreadable);"), "{what}: the VM warning: {text}");
        assert!(text.contains("new image version: run `ai-env egress check`"), "{what}: {text}");
        assert!(text.contains("deploy: egress status skipped: the deploy failed") && !c.iter().any(|l| l.starts_with("egress status")), "{what}: no drift check on a half-applied stack: {text}");
    }
    // The first S5 pulumi up failed: the outputs are still S4's and name no proxy. Nothing served anything before, so
    // no reload is asked for (it would only loop on make infra-status WRITE=1).
    let mut s4 = outputs();
    s4.as_object_mut().unwrap().retain(|k, _| !["proxyInstanceId", "proxyPrivateIp", "connectorArn", "connectorName", "egressVpcId", "vmSubnetId"].contains(&k.as_str()));
    let (t, bin) = post_deploy_tree(None, "running", "2", "2");
    write_outputs(t.path(), &s4);
    let out = ops5(t.path(), &bin, &["post-deploy", "--after-failure"]).bounded();
    let text = all(&out);
    assert!(out.status.success() && !text.contains(loud), "{text}");
    assert!(text.contains("deploy: stack dev exports no proxyInstanceId: egress reload skipped") && text.contains("deploy: the stack outputs name no proxy yet (no S5 pulumi up has completed): nothing can be reloaded now"), "{text}");
    let (t, bin) = post_deploy_tree(Some(&outputs()), "running", "2", "2");
    let out = ops5(t.path(), &bin, &["post-deploy", "--bogus"]).bounded();
    assert!(!out.status.success() && all(&out).contains("usage: ops.sh post-deploy [--after-failure]"), "{}", all(&out));
}

#[test]
fn s5_smoke_wants_three_sdk_records_that_echo_exactly_the_connector() {
    let record = |backend: &str, egress_ok: Option<bool>| {
        let mut r = json!({"backend": backend, "id": "mvm-0123456789abcdef0", "image_version": "3", "egress": [CONNECTOR_ARN], "egress_expected": [CONNECTOR_ARN]});
        if let Some(ok) = egress_ok {
            r["egress_ok"] = json!(ok);
        }
        r.to_string()
    };
    let cases = [
        ("three good passes", record("sdk", Some(true)), true, "s5-smoke: 3/3 ok (target/s5/smoke.jsonl)", 3),
        ("egress_ok false", record("sdk", Some(false)), false, "s5-smoke: pass 1: egress_ok is not true", 1),
        ("no egress_ok", record("sdk", None), false, "s5-smoke: pass 1: egress_ok is not true", 1),
        ("the fake backend", record("fake", Some(true)), false, "s5-smoke: pass 1 did not use the SDK backend", 1),
    ];
    for (what, rec, ok, want, runs) in cases {
        let t = tempfile::tempdir().unwrap();
        let w = planted_repo(t.path(), true);
        let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in")]);
        let log = t.path().join("ai-env.log");
        let out = make_in(t.path(), &bin, &w, &["s5-smoke"]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_SMOKE", &rec).env("FAKE_AIENV_LOG", &log).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "{what}: {text}");
        assert!(text.contains(want), "{what}: {text}");
        let smokes = lines_of(&log).iter().filter(|l| l.starts_with("vm smoke --egress vpc --max-duration 900 --json [AI_ENV=unset]")).count();
        assert_eq!(smokes, runs, "{what}: {:?}", lines_of(&log));
        assert_eq!(lines_of(&w.join("target/s5/smoke.jsonl")), vec![rec.clone(); runs], "{what}: every record is kept");
    }
}

#[test]
fn s6_smoke_wants_three_sdk_records_with_egress_and_exec_ok() {
    let record = |backend: &str, egress_ok: bool, exec_ok: Option<bool>| {
        let mut r = json!({"backend": backend, "id": "mvm-0123456789abcdef0", "image_version": "5", "egress_ok": egress_ok, "exec_claude": "2.1.287 (Claude Code)", "exec_uid": "1000"});
        if let Some(ok) = exec_ok {
            r["exec_ok"] = json!(ok);
        }
        r.to_string()
    };
    let cases = [
        ("three good passes", record("sdk", true, Some(true)), true, "s6-smoke: 3/3 ok (target/s6/smoke.jsonl)", 3),
        ("exec_ok false", record("sdk", true, Some(false)), false, "s6-smoke: pass 1: exec_ok is not true", 1),
        ("no exec_ok", record("sdk", true, None), false, "s6-smoke: pass 1: exec_ok is not true", 1),
        ("egress_ok false", record("sdk", false, Some(true)), false, "s6-smoke: pass 1: egress_ok is not true", 1),
        ("the fake backend", record("fake", true, Some(true)), false, "s6-smoke: pass 1 did not use the SDK backend", 1),
    ];
    for (what, rec, ok, want, runs) in cases {
        let t = tempfile::tempdir().unwrap();
        let w = planted_repo(t.path(), true);
        let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in")]);
        let log = t.path().join("ai-env.log");
        let out = make_in(t.path(), &bin, &w, &["s6-smoke"]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_SMOKE", &rec).env("FAKE_AIENV_LOG", &log).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "{what}: {text}");
        assert!(text.contains(want), "{what}: {text}");
        let smokes = lines_of(&log).iter().filter(|l| l.starts_with("vm smoke --egress vpc --exec --max-duration 900 --json [AI_ENV=unset]")).count();
        assert_eq!(smokes, runs, "{what}: {:?}", lines_of(&log));
        assert_eq!(lines_of(&w.join("target/s6/smoke.jsonl")), vec![rec.clone(); runs], "{what}: every record is kept");
    }
}

/// s7-smoke (T7.4's gate) runs the credentialed smoke three times and wants
/// each record from the SDK backend with egress_ok, exec_ok and cred_ok true:
/// a credential step that failed, or never ran (no cred_ok), stops it at that
/// pass, and every record is kept before it is judged.
#[test]
fn s7_smoke_wants_three_sdk_records_with_exec_and_cred_ok() {
    let record = |backend: &str, egress_ok: bool, exec_ok: bool, cred_ok: Option<bool>| {
        let mut r = json!({"backend": backend, "id": "mvm-0123456789abcdef0", "image_version": "6", "egress_ok": egress_ok, "exec_ok": exec_ok});
        if let Some(ok) = cred_ok {
            r["cred_ok"] = json!(ok);
        }
        r.to_string()
    };
    let cases = [
        ("three good passes", record("sdk", true, true, Some(true)), true, "s7-smoke: 3/3 ok (target/s7/smoke.jsonl)", 3),
        ("cred_ok false", record("sdk", true, true, Some(false)), false, "s7-smoke: pass 1: cred_ok is not true", 1),
        ("no cred_ok", record("sdk", true, true, None), false, "s7-smoke: pass 1: cred_ok is not true", 1),
        ("exec_ok false", record("sdk", true, false, Some(true)), false, "s7-smoke: pass 1: exec_ok is not true", 1),
        ("egress_ok false", record("sdk", false, true, Some(true)), false, "s7-smoke: pass 1: egress_ok is not true", 1),
        ("the fake backend", record("fake", true, true, Some(true)), false, "s7-smoke: pass 1 did not use the SDK backend", 1),
    ];
    for (what, rec, ok, want, runs) in cases {
        let t = tempfile::tempdir().unwrap();
        let w = planted_repo(t.path(), true);
        let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in")]);
        let log = t.path().join("ai-env.log");
        let out = make_in(t.path(), &bin, &w, &["s7-smoke"]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_SMOKE", &rec).env("FAKE_AIENV_LOG", &log).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "{what}: {text}");
        assert!(text.contains(want), "{what}: {text}");
        let smokes = lines_of(&log).iter().filter(|l| l.starts_with("vm smoke --egress vpc --exec --with-credential --max-duration 900 --json [AI_ENV=unset]")).count();
        assert_eq!(smokes, runs, "{what}: {:?}", lines_of(&log));
        assert_eq!(lines_of(&w.join("target/s7/smoke.jsonl")), vec![rec.clone(); runs], "{what}: every record is kept");
    }
}

/// `make s3-preflight PHASE=a` with the stateful aws (seeded by `files`, under
/// `<tmp>/aws`) and the S3 fakes; its `[..]` rows.
fn preflight_s5(t: &Path, files: &[(&str, &str)], envs: &[(&str, &str)]) -> (Output, Vec<String>) {
    let mut fakes = vec![("docker.sh", "docker"), ("curl.sh", "curl"), ("ai-env.sh", "ai-env-stand-in"), ("aws-state.sh", "aws")];
    fakes.extend(["pulumi", "node", "npm", "zip", "gpg", "rustup", "cargo"].iter().map(|n| ("logged.sh", *n)));
    let bin = bin_with(t, &fakes);
    std::fs::create_dir_all(t.join("aws")).unwrap();
    for (f, body) in files {
        std::fs::write(t.join("aws").join(f), body).unwrap();
    }
    let out = make(t, &bin, &["s3-preflight", "PHASE=a"])
        .arg(format!("IMAGE_OUT={}", t.join("out").display()))
        .arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()))
        .env("FAKE_LOG", t.join("tools.log"))
        .env("FAKE_AWS_STATE", t.join("aws"))
        .env("FAKE_AWS_LOG", t.join("calls.log"))
        .envs(envs.iter().copied())
        .bounded();
    let rows = stdout(&out).lines().filter(|l| l.starts_with('[')).map(str::to_string).collect();
    (out, rows)
}

#[test]
fn s3_preflight_p13_to_p16_read_the_egress_preconditions() {
    let five = "vpc-01 172.31.0.0/16\nvpc-02 10.1.0.0/16\nvpc-03 10.2.0.0/16\nvpc-04 10.3.0.0/16\nvpc-05 10.4.0.0/16\n";
    let five_with_egress = "vpc-01 172.31.0.0/16\nvpc-02 10.1.0.0/16\nvpc-03 10.2.0.0/16\nvpc-04 10.3.0.0/16\nvpc-05 10.42.0.0/16\n";
    const EGRESS_VPC: &str = "vpc-0e00000000000001 10.42.0.0/16 ai-env\nvpc-01 172.31.0.0/16\n";
    type Case<'a> = (&'a [(&'a str, &'a str)], &'a [(&'a str, &'a str)], &'a str, &'a str);
    // (state files, envs, row, its start)
    let cases: &[Case] = &[
        (&[], &[], "P13", "[ok ] P13 aws lambda-core list-network-connectors answers"),
        (&[], &[("FAKE_AWS_NO_LAMBDA_CORE", "1")], "P13", "[NO ] P13 this aws CLI has no lambda-core service"),
        (&[], &[("FAKE_AWS_FAIL_OP", "lambda-core list-network-connectors")], "P13", "[NO ] P13 aws lambda-core list-network-connectors failed: An error occurred (AccessDeniedException)"),
        (&[], &[], "P14", "[ok ] P14 VPC Block Public Access off"),
        (&[("bpa", "block-ingress")], &[], "P14", "[NO ] P14 VPC Block Public Access is block-ingress: it blocks the proxy's internet gateway (ingress-only lets only NAT gateway and egress-only IGW traffic out): turn it off, or exclude the egress VPC (allow-egress; it must exist first)"),
        (&[("bpa", "block-bidirectional"), ("vpcs", EGRESS_VPC)], &[], "P14", "[NO ] P14 VPC Block Public Access is block-bidirectional: it blocks the proxy's internet gateway (ingress-only lets only NAT gateway and egress-only IGW traffic out): turn it off, or exclude the egress VPC vpc-0e00000000000001"),
        (&[("bpa", "block-ingress"), ("vpcs", EGRESS_VPC), ("bpa-exclusions", "arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0e00000000000001 allow-egress create-complete\n")], &[], "P14", "[ok ] P14 VPC Block Public Access is block-ingress, and the egress VPC vpc-0e00000000000001 is excluded (allow-egress or allow-bidirectional)"),
        (&[("bpa", "block-bidirectional"), ("vpcs", EGRESS_VPC), ("bpa-exclusions", "arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0e00000000000001 allow-bidirectional update-complete\n")], &[], "P14", "[ok ] P14 VPC Block Public Access is block-bidirectional, and the egress VPC vpc-0e00000000000001 is excluded"),
        (&[("bpa", "block-ingress"), ("vpcs", EGRESS_VPC), ("bpa-exclusions", "arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0e00000000000002 allow-egress create-complete\narn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0e00000000000001 allow-egress delete-complete\n")], &[], "P14", "[NO ] P14 VPC Block Public Access is block-ingress: it blocks"),
        (&[("bpa", "block-ingress"), ("vpcs", "vpc-0e00000000000001 10.42.0.0/16 someone-else\n"), ("bpa-exclusions", "arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0e00000000000001 allow-egress create-complete\n")], &[], "P14", "[NO ] P14 VPC Block Public Access is block-ingress: it blocks"),
        (&[("bpa", "block-ingress"), ("vpcs", EGRESS_VPC)], &[("FAKE_AWS_FAIL_OP", "ec2 describe-vpc-block-public-access-exclusions")], "P14", "[NO ] P14 VPC Block Public Access is block-ingress, and its exclusions or the egress VPC cannot be read"),
        (&[], &[("FAKE_AWS_FAIL_OP", "ec2 describe-vpc-block-public-access-options")], "P14", "[NO ] P14 cannot read the VPC Block Public Access options"),
        (&[], &[], "P15", "[ok ] P15 0 of 5 VPCs: room for the egress VPC"),
        (&[("vpcs", five), ("vpc-quota", "5.0")], &[], "P15", "[NO ] P15 5 of 5 VPCs: the egress VPC needs one more"),
        (&[("vpcs", five_with_egress)], &[], "P15", "[ok ] P15 5 of 5 VPCs, one of them 10.42.0.0/16 (the egress VPC exists)"),
        (&[("vpcs", five), ("vpc-quota", "10.0")], &[], "P15", "[ok ] P15 5 of 10 VPCs: room for the egress VPC"),
        (&[("vpcs", "vpc-01 172.31.0.0/16\nvpc-02 10.1.0.0/16\n")], &[("FAKE_AWS_FAIL_OP", "service-quotas get-service-quota")], "P15", "[ok ] P15 2 of 5 VPCs (quota L-F678F1CE unreadable: the default 5): room"),
        (&[], &[("FAKE_AWS_FAIL_OP", "ec2 describe-vpcs")], "P15", "[NO ] P15 cannot count the VPCs"),
        (&[], &[], "P16", "[ok ] P16 AWSServiceRoleForLambda absent: the connector's first create makes it"),
        (&[("slr", "")], &[], "P16", "[ok ] P16 AWSServiceRoleForLambda present"),
        (&[], &[("FAKE_AWS_FAIL_OP", "iam get-role")], "P16", "[-  ] P16 AWSServiceRoleForLambda not determined"),
    ];
    // One preflight per case, side by side (each its own tree).
    let runs: Vec<(Output, Vec<String>)> = std::thread::scope(|s| {
        let handles: Vec<_> = cases
            .iter()
            .map(|(files, envs, _, _)| {
                s.spawn(move || {
                    let t = tempfile::tempdir().unwrap();
                    preflight_s5(t.path(), files, envs)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for ((files, envs, id, want), (out, rows)) in cases.iter().zip(runs) {
        assert!(row(&rows, id).starts_with(want), "{files:?} {envs:?}: want {want}: {}", all(&out));
        if want.starts_with("[NO ]") {
            assert!(!out.status.success(), "a [NO ] row fails the preflight");
        }
    }
    // The pins (a call without them is refused by the fake, so the [ok ] rows above prove them; named here too).
    let t = tempfile::tempdir().unwrap();
    let (_, rows) = preflight_s5(t.path(), &[], &[]);
    assert!(rows.iter().filter(|r| r.contains("] P1") && (r.contains("P13") || r.contains("P14") || r.contains("P15") || r.contains("P16"))).all(|r| r.starts_with("[ok ]")), "{rows:?}");
    let c = calls(t.path());
    assert!(c[at(&c, "lambda-core list-network-connectors")].contains(LAMBDA_PIN), "{c:#?}");
    for op in ["ec2 describe-vpc-block-public-access-options", "ec2 describe-vpcs"] {
        assert!(c[at(&c, op)].contains("--region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com"), "{op}: {c:#?}");
    }
    assert!(c[at(&c, "service-quotas get-service-quota")].contains("--service-code vpc --quota-code L-F678F1CE --region eu-central-1"), "{c:#?}");
    assert!(assert_pinned(&c) >= 3, "{c:#?}");
}

#[test]
fn the_makefile_parses_without_egress_config_json_and_its_egress_targets_refuse() {
    let t = tempfile::tempdir().unwrap();
    let w = planted_repo(t.path(), false);
    let bin = s5_bin(t.path());
    let run = |args: &[&str]| {
        let mut cmd = make_in(t.path(), &bin, &w, args);
        s5_env(&mut cmd, t.path()).bounded()
    };
    let help = run(&["help"]);
    assert!(help.status.success() && stdout(&help).contains("connector-probe") && !all(&help).contains("egress-config.json"), "{}", all(&help));
    let dry = run(&["-n", "egress-logs", "deploy"]);
    assert!(dry.status.success() && stdout(&dry).contains("test -n \"\" || { echo \"egress-logs: no logGroup in infra/egress-config.json\""), "{}", all(&dry));
    let logs = run(&["egress-logs"]);
    assert!(!logs.status.success() && all(&logs).contains("egress-logs: no logGroup in infra/egress-config.json"), "{}", all(&logs));
    assert_eq!(calls(t.path()), Vec::<String>::new(), "the log group's check comes before the runner: nothing ran");
    let stand_in = format!("AI_ENV={}", bin.join("ai-env-stand-in").display());
    let wait = run(&["connector-wait", stand_in.as_str()]);
    assert!(!wait.status.success() && all(&wait).contains("no connectorName in"), "{}", all(&wait));
    let c = calls(t.path());
    assert_eq!(c, [BUILT.to_string(), "as --check ops [AI_ENV=unset]".to_string(), format!("as ops -- {} --no-print-directory connector-wait-run [AI_ENV=unset]", make_path())], "the keyless build, the runner, then nothing ran without the names");
}

#[test]
fn egress_logs_and_the_proxy_targets_call_their_commands() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    let stand_in = format!("AI_ENV={}", bin.join("ai-env-stand-in").display());
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        std::fs::remove_file(t.path().join("calls.log")).ok();
        let mut cmd = make(t.path(), &bin, args);
        let out = s5_env(&mut cmd, t.path()).arg(&stand_in).envs(envs.iter().copied()).bounded();
        (out, calls(t.path()))
    };
    // egress-logs runs as ai-env-ops: the CLI built without a key (D18), the runner (one Touch ID), then the read under
    // its key.
    let runner = [BUILT.to_string(), "as --check ops [AI_ENV=unset]".to_string(), format!("as ops -- {} --no-print-directory egress-logs-run [AI_ENV=unset]", make_path())];
    let (out, c) = run(&["egress-logs"], &[]);
    assert!(out.status.success() && stdout(&out).contains("TCP_TUNNEL/200 5120 CONNECT api.anthropic.com:443"), "{}", all(&out));
    assert_eq!(c, [&runner[..], &["logs tail /ai-env/egress/squid --since 1h --format short --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com".to_string()]].concat());
    let (_, c) = run(&["egress-logs", "FOLLOW=1", "SINCE=15m"], &[]);
    assert_eq!(c, [&runner[..], &["logs tail /ai-env/egress/squid --since 15m --format short --follow --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com".to_string()]].concat(), "the switches reach the make under the runner");
    for (args, want) in [
        (&["allowlist-reload"][..], "egress reload [AI_ENV=unset]"),
        (&["proxy-stop"][..], "proxy stop [AI_ENV=unset]"),
        (&["proxy-stop", "YES=1"][..], "proxy stop --yes [AI_ENV=unset]"),
        (&["proxy-start"][..], "proxy start [AI_ENV=unset]"),
        (&["proxy-patch"][..], "proxy patch [AI_ENV=unset]"),
    ] {
        let (out, c) = run(args, &[]);
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        assert_eq!(c, vec![BUILT.to_string(), want.to_string()], "{args:?}: built first, without a key (D18), then the one command");
    }
    let (_, c) = run(&["proxy-stop"], &[("YES", "1")]);
    assert_eq!(c, vec![BUILT.to_string(), "proxy stop [AI_ENV=unset]".to_string()], "YES=1 in the environment is ignored");
    let (out, _) = run(&["proxy-stop"], &[("FAKE_AIENV_PROXY_RC", "9")]);
    assert!(!out.status.success() && all(&out).contains("Error 9"), "the operator CLI's refusal stops make: {}", all(&out));
}

/// A fake `cargo` for test-egress: logs its argv, the egress switches, any
/// lab knob it sees, and the runner's marker and whether a credential is in its
/// environment (`[KEY]`: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY or AWS_SESSION_TOKEN, never a value); a compile
/// (`--no-run`) then passes;
/// a test run prints a live test's skip line to stderr when FAKE_CARGO_SKIP is
/// set, then exits FAKE_CARGO_RC, or (FAKE_CARGO_MARKER set) touches the
/// marker and sleeps until a signal ends it.
const CARGO_FAKE: &str = r##"lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
k=${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}
printf 'cargo %s [AI_ENV_AWS_TESTS=%s AI_ENV_EGRESS_TESTS=%s]%s%s%s\n' "$*" "${AI_ENV_AWS_TESTS:-}" "${AI_ENV_EGRESS_TESTS:-}" "${lab:+ [LAB=${lab% }]}" "${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}" "${k:+ [KEY]}" >> "$FAKE_AIENV_LOG"
case " $* " in *" --no-run "*) exit 0 ;; esac
if [ -n "${FAKE_CARGO_SKIP:-}" ]; then echo "live_egress_extra_and_removal: skipped: github.com is allowlisted outside this test" >&2; fi
if [ -n "${FAKE_CARGO_MARKER:-}" ]; then touch "$FAKE_CARGO_MARKER"; exec sleep 60; fi
exit "${FAKE_CARGO_RC:-0}""##;

/// test-egress (S8 operators: as the deployer, whose key alone may write the extras its tests add) compiles the
/// tests first, outside the runner and without any key (D18), then runs them under it, and removes the test's entry
/// on every exit, as the deployer too.
#[test]
fn test_egress_removes_the_test_entry_on_every_exit() {
    let removal = "egress allow ai-env-test github.com --remove [AI_ENV=unset] [AS=deployer:9001]";
    let setup = || {
        let t = tempfile::tempdir().unwrap();
        let bin = s5_bin(t.path());
        script(&bin.join("cargo"), CARGO_FAKE);
        write_outputs(t.path(), &with_operators(outputs()));
        (t, bin)
    };
    let test_egress = |t: &Path, bin: &Path| {
        let mut cmd = make(t, bin, &["test-egress"]);
        s5_env(&mut cmd, t).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()));
        cmd
    };
    // The cargo, runner and egress lines (the identity's aws and pulumi reads are in the log too).
    let ours = |t: &Path| calls(t).into_iter().filter(|l| l.starts_with("cargo ") || l.starts_with("as ") || l.starts_with("egress ")).collect::<Vec<_>>();
    // Success and failure: the tests ran with the switches, then the removal.
    for (rc, ok) in [("0", true), ("101", false)] {
        let (t, bin) = setup();
        let out = test_egress(t.path(), &bin).env("FAKE_CARGO_RC", rc).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "cargo exit {rc}: {text}");
        assert!(text.contains("test-egress: removing the test allowlist entry (ai-env egress allow ai-env-test github.com --remove)"), "it says what it does: {text}");
        assert!(text.contains("test-egress: identity user/ai-env-deployer (the deployer of stack dev)"), "{text}");
        let c = ours(t.path());
        assert_eq!(c.len(), 6, "{c:#?}");
        let compile = "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run [AI_ENV_AWS_TESTS= AI_ENV_EGRESS_TESTS=]";
        assert_eq!(c[0], compile, "compiled first, with no key and no marker");
        assert_eq!(c[1..3], ["as --check deployer [AI_ENV=unset]".to_string(), format!("as deployer -- {} --no-print-directory test-egress-run [AI_ENV=unset]", make_path())]);
        assert_eq!(c[3], compile, "test-egress-run checks the build again under the runner, still with no key and no marker (D18)");
        assert_eq!(c[4], "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored live_egress_ --test-threads=1 --nocapture [AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1] [AS=deployer:9001] [KEY]", "run as the deployer");
        assert_eq!(c[5], removal);
    }
    // A live test that skipped its proof (github.com allowlisted outside it) is no pass, though cargo exits 0; the
    // removal runs all the same, and the output's copy is gone.
    let (t, bin) = setup();
    let out = test_egress(t.path(), &bin).env("FAKE_CARGO_SKIP", "1").env("TMPDIR", t.path()).bounded();
    let text = all(&out);
    assert!(!out.status.success() && text.contains("live_egress_extra_and_removal: skipped:") && text.contains("test-egress: a live egress test skipped its proof (its skipped: line above), so this is not a pass"), "{text}");
    assert_eq!(ours(t.path()).last().map(String::as_str), Some(removal), "{text}");
    assert!(std::fs::read_dir(t.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with("ai-env-test-egress.")), "the log is removed on exit");
    // A removal that fails is loud and fails the target.
    let (t, bin) = setup();
    // Its command is the deployer's, which alone may write the extras (D13: ops is refused, a bare command has no key).
    let out = test_egress(t.path(), &bin).env("FAKE_AIENV_ALLOW_RC", "7").bounded();
    let failed = "test-egress: the removal FAILED: github.com may still be allowed for every vpc VM: run ai-env as deployer -- ai-env egress allow ai-env-test github.com --remove";
    assert!(!out.status.success() && all(&out).contains(failed), "{}", all(&out));
    // Ctrl-C while the tests run (SIGINT to the whole foreground group): removed all the same.
    let (t, bin) = setup();
    let marker = t.path().join("running");
    let mut cmd = test_egress(t.path(), &bin);
    cmd.env("FAKE_CARGO_MARKER", &marker);
    let out = run_bounded(&mut cmd, |pid| {
        let start = Instant::now();
        while !marker.exists() {
            assert!(start.elapsed() < Duration::from_secs(60), "the fake cargo never started");
            std::thread::sleep(Duration::from_millis(20));
        }
        signal_group(pid, libc::SIGINT);
    });
    assert!(!out.status.success(), "{}", all(&out));
    assert_eq!(ours(t.path()).last().map(String::as_str), Some(removal), "{:?}: {}", calls(t.path()), all(&out));
    // The compile that fails stops it before the runner asks anything.
    let (t, bin) = setup();
    script(&bin.join("cargo"), "printf 'cargo %s\\n' \"$*\" >> \"$FAKE_AIENV_LOG\"\ncase \" $* \" in *\" --no-run \"*) exit 101 ;; esac\nexit 0");
    let out = test_egress(t.path(), &bin).bounded();
    assert!(!out.status.success(), "{}", all(&out));
    assert_eq!(ours(t.path()), vec!["cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run".to_string()], "nothing after a failed compile: {}", all(&out));
}

#[test]
fn the_live_s5_targets_drop_every_lab_knob() {
    // S7 adds the wrapper's two knobs (the synthetic oauth_token_refresh, the unseal budget of local-scratch and of
    // credentialed vm and lab commands); S8 the transcript knob (a resume that uploads no transcript), S2's pump
    // knobs (S8's live targets run the wrapper: s8-smoke, test-aws CRED=1) and its own live targets.
    let knobs = [
        ("AI_ENV_BRIDGE_LAB_FAKE_API", "1"),
        ("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1"),
        ("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "5"),
        ("AI_ENV_BRIDGE_LAB_FAKE_SHELL", "1"),
        ("AI_ENV_BRIDGE_LAB_ASSUME_TTY", "1"),
        ("AI_ENV_BRIDGE_LAB_AGENT_ADDR", "127.0.0.1:9"),
        ("AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS", "300"),
        ("AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS", "1500"),
        ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip"),
        ("AI_ENV_BRIDGE_LAB_EXIT", "3:boom"),
        ("AI_ENV_BRIDGE_LAB_IGNORE_EOF", "1"),
        ("AI_ENV_BRIDGE_LAB_STDOUT_NOISE", "1"),
        ("AI_ENV_BRIDGE_LAB_DELAY_INIT_MS", "300"),
        ("AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS", "300"),
    ];
    let t = tempfile::tempdir().unwrap();
    let w = planted_repo(t.path(), true);
    let bin = s5_bin(t.path());
    script(&bin.join("cargo"), CARGO_FAKE);
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    // test-egress and connector-probe run as the deployer (S8 operators): its runner, `ai-env as`, is live too.
    write_outputs(t.path(), &with_operators(outputs()));
    let stand_in = format!("AI_ENV={}", bin.join("ai-env-stand-in").display());
    let record = json!({"backend": "sdk", "egress_ok": true, "exec_ok": true, "cred_ok": true}).to_string();
    let run = |args: &[&str]| {
        let mut cmd = make_in(t.path(), &bin, &w, args);
        s5_env(&mut cmd, t.path()).arg(&stand_in).env("FAKE_AIENV_SMOKE", &record).envs(knobs).bounded()
    };
    let live: [&[&str]; 13] = [
        &["s5-smoke"],
        &["s6-smoke"],
        &["s7-smoke"],
        &["test-egress"],
        &["test-claude"],
        &["test-aws", "CRED=1"],
        &["connector-probe", "CONFIRM=create-probe-connector", "CONNECTOR_WAIT_POLL=1"],
        &["allowlist-reload"],
        &["proxy-stop"],
        &["proxy-start"],
        &["proxy-patch"],
        &["s8-smoke"],
        &["test-cursor", "STEP=t8_3", "SINCE=all"],
    ];
    for args in live {
        let out = run(args);
        assert!(out.status.success(), "{args:?}: {}", all(&out));
    }
    let c = calls(t.path());
    let children: Vec<&String> = c.iter().filter(|l| l.contains("[AI_ENV=") || l.starts_with("cargo ")).collect();
    assert_eq!(
        children.len(),
        3 + 3 + 3 + (1 + 1 + 2 + 1 + 1 + 2) + 1 + 2 + (1 + 2 + 1 + 1) + 4 * 2 + 1 + 1,
        "three s5, s6 and s7 smokes, test-egress's compile, keyless build (D18), runner (its check and its run), test-egress-run's compile and keyless build again, cargo and removal, test-claude's cargo, test-aws's keyless compile (D2) and cargo, the probe's keyless build, runner, ops.sh's keyless build and lab run, the four operator calls each after its keyless build, s8-smoke's and test-cursor's cargo: {children:#?}"
    );
    assert_eq!(c.iter().filter(|l| *l == BUILT).count(), 2 + 2 + 4, "{children:#?}");
    assert_eq!(c.iter().filter(|l| l.starts_with("as deployer -- ")).count(), 2, "{children:#?}");
    assert!(children.iter().all(|l| !l.contains("[LAB=")), "a lab knob reached a live command (the runner included): {children:#?}");
    // The control: a target that keeps the knobs hands them on, and the stand-in sees them.
    let out = run(&["check-base-image"]);
    assert!(out.status.success(), "{}", all(&out));
    let last = calls(t.path()).pop().unwrap();
    let mut names: Vec<&str> = knobs.iter().map(|(k, _)| *k).collect();
    names.sort_unstable();
    assert!(last.ends_with(&format!("[LAB={}]", names.join(" "))), "{last}");
}

#[test]
fn the_destroy_checklist_names_the_egress_leftovers() {
    let t = tempfile::tempdir().unwrap();
    let bin = s5_bin(t.path());
    let out = ops5(t.path(), &bin, &["checklist"]).bounded();
    let text = stdout(&out);
    assert!(out.status.success(), "{}", all(&out));
    for want in [
        &format!("  8. no ai-env-egress, no ai-env-egress-probe-* connector:\n     aws lambda-core list-network-connectors {LAMBDA_PIN}\n") as &str,
        "\n     aws ec2 describe-vpcs --filters Name=cidr,Values=10.42.0.0/16 Name=tag:Project,Values=ai-env --region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com\n",
        "aws ec2 describe-network-acls --filters Name=tag:Name,Values=ai-env-egress-vms",
        "Name=tag:Name,Values=ai-env-egress-proxy",
        "aws ssm get-parameters --names /ai-env/proxy/squid.conf /ai-env/proxy/allow /ai-env/proxy/extras /ai-env/proxy/suspended",
        "no /ai-env/egress/squid (nor /ai-env/egress/dns):\n",
        "\n     aws logs describe-log-groups --log-group-name-prefix /ai-env/egress --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com\n",
        "aws iam get-role --role-name ai-env-egress-operator --region eu-central-1; aws iam get-role --role-name ai-env-egress-proxy --region eu-central-1",
        "remove egress_connector_arn and proxy_private_ip",
        &format!("state/egress-verified.toml ({}/state/egress-verified.toml): its records are bound to the deleted connector's Id and no longer admit anything; remove it", t.path().join("bridge").display()),
        // S8 operators: the two operator users, every ai-env-* policy (not only ai-env-deploy), the ops key, the
        // Strongbox entry, and the root's key that ran the destroy.
        "  4. NoSuchEntity for each of the three users (forceDestroy removed their access keys):\n     aws iam get-user --user-name ai-env-runtime --region eu-central-1\n     aws iam get-user --user-name ai-env-deployer --region eu-central-1\n     aws iam get-user --user-name ai-env-ops --region eu-central-1\n",
        "\n     rm \"${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/credentials/aws.env\" \"${AI_ENV_BRIDGE_DIR:-$HOME/.config/ai-env/bridge}/credentials/ops.env\"\n",
        "delete the Strongbox entry ai-env-deployer",
        "\n     aws iam list-policies --scope Local --query \"Policies[?starts_with(PolicyName, 'ai-env-')].PolicyName\" --output text --region eu-central-1\n",
        "no ai-env-* policy left (ai-env-deploy, ai-env-deploy-egress, ai-env-deploy-dns, ai-env-deployer, ai-env-ops)",
        "\n     cd infra && pulumi stack rm dev\n",
        "the account root ran this destroy (BREAKGLASS=1): when done, unset its key and close this terminal (README \"Break-glass\"); delete the key when nothing else uses it (IAM console as the root, with MFA: Security credentials, Access keys)",
    ] {
        assert!(text.contains(want), "want {want}: {text}");
    }
    assert!(!text.contains("PolicyName=='ai-env-deploy'"), "every ai-env-* policy, not ai-env-deploy alone: {text}");
    // Pasted into zsh, whose interactive shell takes a `#` for an argument (no INTERACTIVE_COMMENTS by default), and an
    // unquoted `(`, `*`, `?` or `[` for syntax or a glob (D25): each command stands on a line of its own, after the
    // indent, with none of them outside quotes; what a step should show is its numbered line, which holds no command.
    let unquoted = |l: &str| {
        let (mut sq, mut dq) = (false, false);
        l.chars().any(|ch| match ch {
            '\'' if !dq => {
                sq = !sq;
                false
            }
            '"' if !sq => {
                dq = !dq;
                false
            }
            '#' => true,
            '(' | ')' | '*' | '?' | '[' | ']' => !sq && !dq,
            _ => false,
        })
    };
    let is_command = |l: &str| ["aws ", "rm ", "cd "].iter().any(|c| l.trim_start().starts_with(c));
    let commands: Vec<&str> = text.lines().filter(|l| is_command(l)).collect();
    assert!(commands.len() >= 20, "{text}");
    for line in &commands {
        assert!(line.starts_with("     ") && !unquoted(line), "a command line a paste into zsh would break: {line}");
    }
    for line in text.lines().map(str::trim_start) {
        if let Some((n, rest)) = line.split_once(". ").filter(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
            assert!(!is_command(rest), "step {n}: a command on its numbered line: {line}");
        }
    }
    assert_eq!(calls(t.path()), Vec::<String>::new(), "the checklist only prints");
}

/// A planted repo `make deploy` runs whole in, every outside tool a fake:
/// cargo-lambda, rustup and llvm (vm-build), the stand-in as AI_ENV (scan,
/// pin, base image, versions-diff, egress), docker and curl (preflight),
/// pulumi, the stateful aws. P12 is waived (EXPECT_BUILD_FAILURE=1: the zip
/// is built in the same run); the account holds the image (active version
/// 2), the stack's connector, the running proxy and a vpc VM row, and
/// state/infra.toml is current. `pulumi up` (FAKE_PULUMI_ON_UP) makes image
/// version 3 and a connector that is PENDING once more. The stack's
/// passphrase is sealed where make looks for it (A39), so the deploy unseals
/// it (the stand-in's one Touch ID) before the deployer's paste.
struct DeployTree {
    t: tempfile::TempDir,
    w: PathBuf,
    bin: PathBuf,
}

impl DeployTree {
    /// `check`: the body of the planted infra/scripts/check-plan.sh.
    fn new(check: &str) -> DeployTree {
        let t = tempfile::tempdir().unwrap();
        let w = planted_repo(t.path(), true);
        for rel in ["MANIFEST", "claude.lock", "managed-settings.json", "claude/settings.json", "claude/CLAUDE.md", "claude/claude.json"] {
            let to = w.join("image").join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(Path::new(REPO).join("image").join(rel), &to).unwrap();
        }
        script(&w.join("infra/scripts/check-plan.sh"), check);
        script(&w.join("infra/scripts/check-policies.sh"), CHECK_POLICIES_FAKE);
        let bin = s5_bin(t.path());
        bin_with(t.path(), &[("cargo-lambda.sh", "cargo-lambda"), ("docker.sh", "docker"), ("curl.sh", "curl"), ("logged.sh", "cargo")]);
        script(&bin.join("rustup"), "echo aarch64-unknown-linux-gnu");
        script(&bin.join("npm"), "exit 0");
        script(&t.path().join("llvm/llvm-nm"), "exit 0");
        script(&t.path().join("llvm/llvm-objdump"), "echo '0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.17) memcpy'");
        std::fs::write(t.path().join("fresh"), arm64_elf("fresh bootstrap")).unwrap();
        // The stack's deployer exists (S8 operators): make deploy runs as it.
        write_outputs(t.path(), &with_operators(outputs()));
        seal_passphrase(&sealed_path(t.path()), "");
        write_infra_state(t.path(), &bin, &outputs());
        set_image(t.path(), "UPDATED", "2", "", "2026-09-29T10:00:00.123000+00:00");
        seed_connector(t.path(), CONNECTOR, "ACTIVE");
        seed_proxy(t.path(), "running");
        vm_row(t.path(), "mvm-a", "v = 1\nstatus = \"running\"\nid = \"mvm-a\"\negress = \"vpc\"\n");
        script(
            &t.path().join("on-up.sh"),
            "printf 3 > \"$FAKE_AWS_STATE/image/active\"\nprintf 2026-09-29T11:00:00.456000+00:00 > \"$FAKE_AWS_STATE/image/updated\"\necho 'PENDING ACTIVE' > \"$FAKE_AWS_STATE/connectors/ai-env-egress/states\"",
        );
        DeployTree { t, w, bin }
    }

    fn deploy(&self, p: &Value, envs: &[(&str, &str)]) -> Output {
        self.run("deploy", p, envs)
    }

    /// `make <target>` (deploy, deploy-policies) in the tree, the plan `p` its preview's.
    fn run(&self, target: &str, p: &Value, envs: &[(&str, &str)]) -> Output {
        self.run_with(target, &[], p, envs)
    }

    /// [`DeployTree::run`] with `args` added to make's command line.
    fn run_with(&self, target: &str, args: &[&str], p: &Value, envs: &[(&str, &str)]) -> Output {
        let t = self.t.path();
        std::fs::write(t.join("plan.json"), p.to_string()).unwrap();
        let mut cmd = make_in(t, &self.bin, &self.w, &[target]);
        s5_env(&mut cmd, t)
            .arg(format!("AI_ENV={}", self.bin.join("ai-env-stand-in").display()))
            .arg(format!("CARGO_LAMBDA={}", self.bin.join("cargo-lambda").display()))
            .arg(format!("LLVM_BIN={}", t.join("llvm").display()))
            .args(["EXPECT_BUILD_FAILURE=1", "CONNECTOR_WAIT_POLL=1", "CONNECTOR_WAIT_TIMEOUT=10", "IMAGE_WAIT_POLL=1", "IMAGE_WAIT_TIMEOUT=10"])
            .args(args)
            .env("FAKE_CL_BOOTSTRAP", t.join("fresh"))
            .env("FAKE_DOCKER_VERSION", "29.8.0 arm64")
            .env("FAKE_DOCKER_FREE_KB", "50125004")
            .env("FAKE_PULUMI_PREVIEW", t.join("plan.json"))
            .env("FAKE_PULUMI_ALLOW", "up")
            .env("FAKE_PULUMI_ON_UP", t.join("on-up.sh"))
            .env("FAKE_LOG", t.join("tools.log"))
            .envs(envs.iter().copied())
            .bounded()
    }

    /// Every file under the planted repo (its target/ included).
    fn files(&self) -> Vec<PathBuf> {
        fn walk(d: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() && !p.is_symlink() {
                    walk(&p, out);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
        let mut out = vec![];
        walk(&self.w, &mut out);
        out
    }
}

/// The fake check-policies: logs, exits FAKE_CHECK_POLICIES_RC.
const CHECK_POLICIES_FAKE: &str = "printf 'check-policies %s\\n' \"$REGION\" >> \"$FAKE_AWS_LOG\"\nexit \"${FAKE_CHECK_POLICIES_RC:-0}\"";

/// The fake plan check: logs its argv, reads the plan, exits FAKE_CHECK_PLAN_RC.
const CHECK_PLAN_FAKE: &str = "printf 'check-plan %s\\n' \"$*\" >> \"$FAKE_AWS_LOG\"\ncat >/dev/null\nexit \"${FAKE_CHECK_PLAN_RC:-0}\"";

/// A plan as deploy sees it: the stack, an S3 resource, the connector (its
/// operator role carries the account id) and a replaced proxy instance.
fn deploy_plan(extra: &[(&str, &str, &str)]) -> Value {
    let mut steps = vec![("same", "pulumi:pulumi:Stack", "ai-env-dev"), ("same", "aws:budgets/budget:Budget", "ai-env-monthly"), ("same", "aws-native:lambda:NetworkConnector", "ai-env-egress")];
    steps.extend(["create-replacement", "replace", "delete-replaced"].iter().map(|op| (*op, PROXY_INSTANCE.0, PROXY_INSTANCE.1)));
    steps.extend_from_slice(extra);
    let mut p = plan(&steps);
    p["steps"][2]["newState"]["inputs"] = json!({"name": CONNECTOR, "operatorRole": "arn:aws:iam::123456789012:role/ai-env-egress-operator"});
    p
}

#[test]
fn deploy_runs_the_plan_gate_first_and_the_egress_steps_last() {
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[]);
    let text = stdout(&out);
    assert!(out.status.success(), "{}", all(&out));
    let c = calls(d.t.path());
    let order = [
        "lambda-core list-network-connectors",
        "check-policies eu-central-1",
        "pulumi preview --json --show-sames --show-reads --non-interactive --stack dev",
        "check-plan --mode none",
        "lambda-microvms list-microvm-images",
        "pulumi up --stack dev",
        "lambda-microvms get-microvm-image --image-identifier arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent --region eu-central-1 --query",
        "infra versions-diff --before",
        "lambda-core get-network-connector --identifier ai-env-egress",
        "pulumi stack output --json --stack dev --cwd ",
        &format!("ec2 describe-instances --instance-ids {PROXY_ID}"),
        "egress reload --if-changed [AI_ENV=unset]",
        "egress status [AI_ENV=unset]",
    ];
    let mut last = 0;
    for want in order {
        let i = c[last..].iter().position(|l| l.contains(want)).unwrap_or_else(|| panic!("{want} missing or out of order: {c:#?}")) + last;
        last = i;
    }
    assert_eq!(c.iter().filter(|l| l.starts_with("pulumi preview")).count(), 1, "one preview: {c:#?}");
    assert!(!c.iter().any(|l| l.contains("FORBIDDEN")), "{c:#?}");
    // S8 operators: the zip was built before the runner, which asked once; everything after it ran as the deployer. A39:
    // the stack's passphrase, unsealed (the stand-in's `run -f` of the sealed file) right before the runner, is in the
    // runner's environment and X-run's, never a build's.
    let runner = format!("as deployer -- {} --no-print-directory deploy-run [AI_ENV=unset] [PASS]", make_path());
    assert_eq!(c.iter().filter(|l| l.starts_with("as ")).cloned().collect::<Vec<_>>(), ["as --check deployer [AI_ENV=unset]".to_string(), runner.clone()], "one runner: {c:#?}");
    let r = at(&c, &runner);
    let sealed = sealed_path(d.t.path());
    let unsealed = format!("run -f {} -- /bin/bash infra/scripts/pass-exec.sh deploy {} {} as deployer -- {} --no-print-directory deploy-run [AI_ENV=unset]", sealed.display(), sealed.display(), d.bin.join("ai-env-stand-in").display(), make_path());
    assert_eq!(c[r - 1], unsealed, "the passphrase's unseal right before the runner: {c:#?}");
    assert!(at(&c, "infra scan ") < r, "the zip's scan before the runner: {c:#?}");
    assert_eq!(c.iter().filter(|l| l.starts_with("infra scan ")).count(), 1, "the zip is built once, in the wrapper; deploy-run never builds it again: {c:#?}");
    let asked = at(&c, "as --check deployer");
    assert!(c[asked - 1] == BUILT && c[..asked].iter().filter(|l| *l == BUILT).count() == 2, "the zip's version read, then TIER's keyless build of the CLI (D18), before it asks: {c:#?}");
    for (i, l) in c.iter().enumerate().filter(|(_, l)| l.contains("[AI_ENV=") && !l.starts_with("as ")) {
        if l.starts_with("--version ") || l.starts_with("infra scan ") {
            // The zip's scan and version read, and every keyless build (TIER's, s3-preflight's, ops.sh post-deploy's).
            assert!(!l.contains("[AS=") && !l.contains("[PASS]"), "a build or version read under the marker or the passphrase: {l}: {c:#?}");
            continue;
        }
        assert_eq!(l.contains(" [AS=deployer:9001]"), i > r, "the stand-in's calls after the runner, and only those, as the deployer: {l}: {c:#?}");
        assert_eq!(l.ends_with(" [PASS]"), i > r, "the stand-in's calls after the runner, and only those, under the passphrase: {l}: {c:#?}");
    }
    assert!(c[..r - 1].iter().all(|l| !l.contains("[PASS]")), "nothing before the unseal holds the passphrase: {c:#?}");
    for pulumi in ["pulumi preview --json --show-sames --show-reads --non-interactive --stack dev [PASS]", "pulumi up --stack dev [PASS]"] {
        assert!(c.iter().any(|l| l == pulumi), "{pulumi}: {c:#?}");
    }
    assert!(text.contains("deploy: identity user/ai-env-deployer (the deployer of stack dev)") && text.contains("[ok ] P8 deploy identity user/ai-env-deployer (the deployer of stack dev)"), "{text}");
    let lines = [
        "replacement guard: aws:ec2/instance:Instance ai-env-egress-proxy will be replaced",
        "fake pulumi: up",
        "image-wait: UPDATED after",
        "connector-wait: PENDING (",
        "connector-wait: ai-env-egress ACTIVE after",
        "deploy: ai-env egress reload --if-changed",
        "deploy: warning: state/vms rows that may still run a vpc VM: mvm-a;",
        "new image version: run `ai-env egress check` (active version 2 -> 3: the credential gate admits an image version only with its own passing egress check record) and re-run `make test-egress`",
        "deploy: ai-env egress status",
    ];
    let mut last = 0;
    for want in lines {
        last = text[last..].find(want).unwrap_or_else(|| panic!("{want} missing or out of order: {text}")) + last;
    }
    assert!(!text.contains("THE DEPLOY FAILED") && !all(&out).contains("DRIFT"), "{text}");
    assert_eq!(assert_pinned(&c), 7, "P13-P15, connector-wait's listing and two reads, the proxy's state: {c:#?}");
    // The plan (it carries the account id) was never written anywhere in the tree.
    for f in d.files() {
        let bytes = std::fs::read(&f).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("123456789012"), "{} holds the account id", f.display());
    }
}

#[test]
fn deploy_runs_the_reload_and_the_warnings_on_every_exit_after_pulumi_up_and_fails_on_drift_at_the_end() {
    // The image build fails after `pulumi up` (a new failed version): no connector-wait, no drift check, but the
    // reload, the VM warning and the deploy's failure.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    script(
        &d.t.path().join("on-up.sh"),
        "printf UPDATE_FAILED > \"$FAKE_AWS_STATE/image/state\"\nprintf 3 > \"$FAKE_AWS_STATE/image/failed\"\nprintf 2026-09-29T11:00:00.456000+00:00 > \"$FAKE_AWS_STATE/image/updated\"",
    );
    let out = d.deploy(&deploy_plan(&[]), &[]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("image-wait: UPDATE_FAILED"), "{text}");
    let c = calls(d.t.path());
    assert!(at(&c, "pulumi up --stack dev") < at(&c, "egress reload --if-changed [AI_ENV=unset]"), "{c:#?}");
    assert!(!c.iter().any(|l| l.starts_with("lambda-core get-network-connector") || l.starts_with("egress status")), "no connector-wait, no drift check: {c:#?}");
    assert!(text.contains("deploy: warning: state/vms rows that may still run a vpc VM: mvm-a;") && text.contains("deploy: egress status skipped: the deploy failed"), "{text}");
    assert!(text.contains("*** [deploy-run] Error 1") && text.contains("make: *** [deploy] Error 2"), "the image-wait's failure is the deploy's: {text}");

    // `pulumi up` itself fails: the same egress steps, its exit status.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_PULUMI_UP_RC", "255")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("*** [deploy-run] Error 255") && text.contains("deploy: egress status skipped: the deploy failed"), "{text}");
    assert!(calls(d.t.path()).iter().any(|l| l.starts_with("egress reload --if-changed")), "{:?}", calls(d.t.path()));

    // A connector that never turns ACTIVE: the egress steps all the same.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    script(&d.t.path().join("on-up.sh"), "printf 3 > \"$FAKE_AWS_STATE/image/active\"\necho 'PENDING FAILED' > \"$FAKE_AWS_STATE/connectors/ai-env-egress/states\"");
    let out = d.deploy(&deploy_plan(&[]), &[]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("connector-wait: ai-env-egress is FAILED after") && text.contains("deploy: egress status skipped: the deploy failed"), "{text}");
    assert!(calls(d.t.path()).iter().any(|l| l.starts_with("egress reload --if-changed")), "{:?}", calls(d.t.path()));

    // Drift: every step ran, then the deploy fails naming it; an unverified check stays a warning.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_AIENV_STATUS_RC", "1"), ("FAKE_AIENV_DRIFT", "sg-proxy")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("deploy: DRIFT: ai-env egress status found drift in sg-proxy") && text.contains("new image version"), "{text}");
    assert_eq!(calls(d.t.path()).last().map(String::as_str), Some("egress status [AI_ENV=unset] [AS=deployer:9001] [PASS]"), "the drift check is the last step, as the deployer");
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_AIENV_STATUS_RC", "7")]);
    assert!(out.status.success() && all(&out).contains("deploy: warning: ai-env egress status exit 7"), "{}", all(&out));
}

#[test]
fn deploy_stops_before_pulumi_up_when_the_plan_check_refuses() {
    // The real plan check (scripts/check-plan.sh compiles check-plan.ts) over a plan that is not the stack's.
    let real = format!("exec '{}/infra/scripts/check-plan.sh' \"$@\"", REPO);
    let d = DeployTree::new(&real);
    let out = d.deploy(&deploy_plan(&[]), &[("PLAN_CHECK_OUT", d.t.path().join("plan-check").to_str().unwrap())]);
    let text = all(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("check-plan: the plan does not match the stack inventory and the egress spec (dnsMode none)"), "the real check refused: {text}");
    assert!(text.contains("deploy: the plan check refused the plan (exit 1, above)") && text.contains("deploy: refused before pulumi up: nothing deployed"), "{text}");
    assert!(text.contains("will be replaced"), "the guard's verdict is shown too: {text}");
    let c = calls(d.t.path());
    assert!(c.iter().any(|l| l.starts_with("pulumi preview")) && !c.iter().any(|l| l.starts_with("pulumi up")), "{c:#?}");
    assert!(!c.iter().any(|l| l.starts_with("lambda-microvms list-microvm-images")), "nothing recorded either (no snapshot): {c:#?}");
    assert!(!d.w.join("target/image/pre-deploy-image.json").exists());

    // The fake check refusing works the same (the wiring, without tsc).
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_CHECK_PLAN_RC", "1")]);
    assert!(!out.status.success() && all(&out).contains("deploy: the plan check refused the plan (exit 1, above)"), "{}", all(&out));
    assert!(!calls(d.t.path()).iter().any(|l| l.starts_with("pulumi up")));
}

#[test]
fn deploy_stops_before_pulumi_up_when_the_replacement_guard_refuses_or_the_preview_fails() {
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[("replace", "aws:ec2/securityGroup:SecurityGroup", "ai-env-vm-egress")]), &[]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains(&format!("aws:ec2/securityGroup:SecurityGroup ai-env-vm-egress {REFUSAL}")) && text.contains("deploy: refused before pulumi up"), "{text}");
    let c = calls(d.t.path());
    assert!(at(&c, "check-plan --mode none") > 0 && !c.iter().any(|l| l.starts_with("pulumi up")), "{c:#?}");

    // check-policies refusing stops the deploy before the preview.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_CHECK_POLICIES_RC", "1")]);
    assert!(!out.status.success(), "{}", all(&out));
    let c = calls(d.t.path());
    assert!(c.iter().any(|l| l.starts_with("check-policies")) && !c.iter().any(|l| l.starts_with("pulumi preview") || l.starts_with("pulumi up")), "{c:#?}");

    // A failed preview: its error diagnostics shown, nothing checked or deployed.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let failed = json!({"steps": [], "diagnostics": [{"severity": "error", "message": "error: the program threw: egress guard refused something\n  at index.ts"}]});
    let out = d.deploy(&failed, &[("FAKE_PULUMI_PREVIEW_RC", "255")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("deploy: pulumi preview --json failed (exit 255): nothing deployed") && text.contains("the program threw: egress guard refused something"), "{text}");
    // A39: the failure names where the passphrase comes from and how a wrong or empty sealed one is set again.
    let edit = format!(
        "nothing deployed (Pulumi's error above; its incorrect passphrase: the value in effect is wrong or empty, the sealed one set with ai-env edit {}, which make deploy unseals unless PULUMI_CONFIG_PASSPHRASE or PULUMI_CONFIG_PASSPHRASE_FILE is set (README \"Identities\"))",
        sealed_path(d.t.path()).display()
    );
    assert!(text.contains(&edit), "{text}");
    let c = calls(d.t.path());
    assert!(!c.iter().any(|l| l.starts_with("check-plan") || l.starts_with("pulumi up")), "{c:#?}");

    // A wrong passphrase in the environment (nothing is unsealed then): Pulumi's own error at the plan check, the same
    // text after it; nothing checked or deployed.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let wrong = super::aws_keys::passphrase().to_lowercase();
    let out = d.deploy(&deploy_plan(&[]), &[("PULUMI_CONFIG_PASSPHRASE", &wrong)]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("error: getting stack configuration: get stack secrets manager: incorrect passphrase"), "{text}");
    assert!(text.contains("deploy: pulumi preview --json failed (exit 1): nothing deployed (Pulumi's error above; its incorrect passphrase: the value in effect is wrong or empty"), "{text}");
    assert!(text.contains(&format!("the sealed one set with ai-env edit {}, which make deploy unseals", sealed_path(d.t.path()).display())), "{text}");
    let c = calls(d.t.path());
    assert!(!c.iter().any(|l| l.starts_with("run ") || l.starts_with("check-plan") || l.starts_with("pulumi up")), "set: nothing unsealed, nothing deployed: {c:#?}");
    assert!(!text.contains(&wrong) && c.iter().all(|l| !l.contains(&wrong)), "the value is never shown");
}

/// `make claude-update` (ops.sh claude-update): it follows the installed Cursor bundle, does only what is not current
/// (pin, test-docker unless it passed for the zip, deploy, infra-status, the live active version, proxy-start, the
/// egress check --if-needed), stops at the first failure naming the step, refuses before changing anything without a
/// terminal, the passphrase, Docker, a bundle, or under make -i, -k or -p (whose data base would print the runner's key:
/// an option's argument, -I's directory, is no switch), stops on a rollback or a pin it cannot follow, resumes all of a
/// deploy's steps after a failure past it (the marker), and says what it found on the way (the release site, a
/// downgrade, a proxy it started, VMs on another version, the version count and which old versions no VM runs, a lock to
/// commit: git runs without the key).
/// S8 operators: it asks once for the identity the run needs, ai-env as deployer when a deploy is due, else ai-env as
/// ops: after the steps that need no AWS (pin, test-docker: without any key, as the fake make records) and before the
/// first that does; it runs itself again under the runner, which then sees the lock and test-docker's stamp current
/// and never repeats them, prints the summary once, checks the identity (ops.sh identity; refused after the pass before
/// it pinned or tested, it says what that pass left) and runs every other step as that identity. Under a runner that
/// covers the tier it asks nothing; a cancelled runner changes nothing after it. A deploy due before the bootstrap (no
/// deployer exported, so no deployer key) is the account root's: refused before anything runs, naming what to run
/// instead (the pin and make test-docker when due, then make deploy as the account root).
/// A39: a deploy due with the passphrase not set as Pulumi takes it (neither variable, or an empty
/// PULUMI_CONFIG_PASSPHRASE, which Pulumi takes before the file) unseals the sealed file (PULUMI_SEALED, by default
/// under HOME): one `ai-env run -f` after pin and test-docker and before the runner's ask (the Touch ID before the
/// paste), the only hop under a runner that covers the deployer, whose identity is checked before anything runs; an
/// empty sealed value stops before the paste, saying what the pass before the unseal left; no file refuses before
/// anything runs; nothing to deploy unseals nothing. Only the make deploy step ever holds the passphrase, and the
/// deployer's runner that carries it there: no read of ops.sh's own (the bundle, the outputs, the checks), and neither
/// pin, test-docker, the status, the proxy, the check nor git.
#[test]
fn claude_update_follows_the_cursor_bundle_and_stops_at_the_first_failure() {
    const TTY: (&str, &str) = ("AI_ENV_BRIDGE_LAB_ASSUME_TTY", "1");
    const PASS: (&str, &str) = ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null");
    const PIN288: &str = "make --no-print-directory claude-pin CLAUDE_VERSION=2.1.288";
    const PIN286: &str = "make --no-print-directory claude-pin CLAUDE_VERSION=2.1.286";
    let (test, deploy, status, proxy, check) = (
        "make --no-print-directory test-docker",
        "make --no-print-directory deploy EXPECT_BUILD_FAILURE=",
        "make --no-print-directory infra-status WRITE=1",
        "make --no-print-directory proxy-start",
        "egress check --if-needed",
    );
    /// What a case changes in the default world (the image active at 3.0 as the outputs say, the proxy running).
    #[derive(Clone, Copy, PartialEq)]
    enum World {
        Plain,
        Rollback,
        ProxyStopped,
        Stamped,
        StampedStale,
        StampedOtherClaude,
        OlderVm,
        Pinned,
        PinnedDeployed,
        PinnedUnreadable,
        OtherZip,
        VersionsRun,
        Pending,
        PendingOther,
        PendingDeploy,
        /// The stack before the bootstrap: its outputs name no operator user.
        NoDeployer,
        /// The stack before the bootstrap, and make test-docker passed for the current zip of the bundle (as Stamped).
        NoDeployerStamped,
        /// The lock tracked by git and changed (a fake git, which logs whether a key reached it).
        LockTracked,
        /// The stack's passphrase sealed where ops.sh looks by default (A39).
        Sealed,
        /// The README's first line without `ai-env edit`: the sealed passphrase empty.
        SealedEmpty,
        /// The passphrase sealed in `sealed.env` of the working directory (PULUMI_SEALED names it).
        SealedElsewhere,
    }
    struct Case<'a> {
        what: &'a str,
        bundle: &'a str,
        locked: &'a str,
        deployed: &'a str,
        envs: Vec<(&'a str, &'a str)>,
        world: World,
        code: i32,
        steps: Vec<&'a str>,
        wants: Vec<&'a str>,
        /// The runner the run asks for (`ai-env as <tier> --`), if it gets that far.
        runner: Option<&'a str>,
        /// The marker of a runner the whole run is under (`deployer`, `ops`), whose key the stand-in's tails give.
        under: Option<&'a str>,
        /// The run unseals the sealed passphrase (A39: one `ai-env run -f`, after pin and test-docker, before the ask).
        unsealed: bool,
    }
    let full = vec![TTY, PASS];
    let c = |what, bundle, locked, deployed, envs: Vec<(&'static str, &'static str)>, world, code, steps: Vec<&'static str>, wants: Vec<&'static str>| {
        // The run asks once, after the steps that need no AWS, for the deployer when it deploys, else for ops.
        let runner = if steps.contains(&deploy) || (code == 3 && steps.contains(&test)) {
            Some("deployer")
        } else if steps.iter().any(|s| !s.starts_with("make --no-print-directory claude-pin") && *s != test) {
            Some("ops")
        } else {
            None
        };
        Case { what, bundle, locked, deployed, envs, world, code, steps, wants, runner, under: None, unsealed: false }
    };
    let mut cases: Vec<Case> = vec![
        c("up to date", "2.1.287", "2.1.287", "2.1.287", vec![], World::Plain, 0, vec![status, check], vec!["claude-update: 2.1.287 is pinned and deployed: nothing to build or deploy", "claude-update [2/3] new VMs start the deployed image version", "claude-update: new VMs start image version 3.0, the deployed one, built from ai-env/image-0123456789abcdef.zip", "done: new VMs start image version 3.0 with Claude Code 2.1.287", "claude-update: this run needs ai-env as ops (the status and the egress check): asking once, before the first step that needs AWS", "claude-update: identity user/ai-env-ops (the operator of stack dev)"]),
        c("a new bundle", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update [1/7] make claude-pin CLAUDE_VERSION=2.1.288", "claude-update [2/7] make test-docker", "claude-update: this run needs ai-env as deployer (a deploy is due): asking once, before the first step that needs AWS", "claude-update: make test-docker already passed for", "claude-update: identity user/ai-env-deployer (the deployer of stack dev)", "claude-update [1/5] make deploy", "claude-update [4/5] make proxy-start (squid serving the deployed parameters)", "the new pin rests on the release manifest over HTTPS only", "make test-egress, the broader live test the deploy names, is not part of the daily update"]),
        c("pinned, not deployed", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::Plain, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker", "!the new pin rests"]),
        c("the zip already tested", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::Stamped, 0, vec![deploy, status, proxy, check], vec!["make test-docker already passed for", "claude-update [1/5] make deploy"]),
        c("a failed deploy", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_MAKE_FAIL", "deploy")], World::Plain, 2, vec![PIN288, test, deploy], vec!["claude-update: STOPPED at step 1/5 (make deploy: exit 2)"]),
        c("a failed check", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_AIENV_CHECK_RC", "3")], World::Plain, 3, vec![status, check], vec!["STOPPED at step 3/3 (ai-env egress check --if-needed: exit 3)"]),
        c("a rollback", "2.1.287", "2.1.287", "2.1.287", vec![], World::Rollback, 1, vec![status], vec!["new VMs start image version 3.0, not the deployed 4.0 (a rollback with make image-deactivate or image-activate?)", "make image-activate VERSION=4.0", "STOPPED at step 2/3"]),
        c("no terminal", "2.1.288", "2.1.287", "2.1.287", vec![PASS], World::Plain, 1, vec![], vec!["claude-update: needs a terminal"]),
        // Neither passphrase variable set and nothing sealed to unseal (A39): refused before anything runs, naming the
        // README's two lines and the export (the path, under the test's HOME, is checked below).
        c("no passphrase", "2.1.288", "2.1.287", "2.1.287", vec![TTY], World::Plain, 1, vec![], vec!["claude-update: a deploy is due, and the dev stack's passphrase is in neither PULUMI_CONFIG_PASSPHRASE nor PULUMI_CONFIG_PASSPHRASE_FILE (Pulumi takes PULUMI_CONFIG_PASSPHRASE first, even empty, and an empty one counts as none), and there is no sealed ", "/.config/ai-env/pulumi.env to unseal (make deploy's preview runs --non-interactive): seal it once (README \"Identities\"): printf 'PULUMI_CONFIG_PASSPHRASE=\\n' | ai-env encrypt -k ai-env-bridge - > \"", "/.config/ai-env/pulumi.env\"; or export PULUMI_CONFIG_PASSPHRASE_FILE (a file holding it): nothing changed"]),
        c("Docker down", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_DOCKER_RC", "1")], World::Plain, 1, vec![], vec!["claude-update: Docker does not answer (docker info)"]),
        c("make -k", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", " --no-print-directory -k")], World::Plain, 2, vec![], vec!["claude-update: not under make -i or -k"]),
        c("a variable is no flag", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", "kind=1")], World::Plain, 0, vec![status, check], vec!["is pinned and deployed"]),
        c("no bundle", "", "2.1.287", "2.1.287", full.clone(), World::Plain, 1, vec![], vec!["claude-update: cannot read the Cursor bundle's version (ai-env infra pin --bundle-version: exit 1, above; exit 1 when no bundle is installed): nothing changed"]),
        c("not a version", "2.1.288;id", "2.1.287", "2.1.287", full.clone(), World::Plain, 1, vec![], vec!["printed \"2.1.288;id\", not a version: nothing changed"]),
        c("no stack outputs", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_PULUMI_OUTPUTS", "/nonexistent/outputs.json")], World::Plain, 1, vec![], vec!["claude-update: cannot read the stack outputs of dev"]),
        c("the release site ahead", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_LATEST", "2.1.289")], World::Plain, 0, vec![status, check], vec!["the release site's latest 2.1.289 is newer than the Cursor bundle 2.1.287", "once Cursor updates the extension, run make claude-update again"]),
        c("the bundle ahead", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_LATEST", "2.1.286")], World::Plain, 0, vec![status, check], vec!["the Cursor bundle 2.1.287 is ahead of the release site's latest 2.1.286"]),
        c("a downgrade", "2.1.286", "2.1.287", "2.1.287", full.clone(), World::Plain, 0, vec![PIN286, test, deploy, status, proxy, check], vec!["a DOWNGRADE: the Cursor bundle 2.1.286 is older than the deployed 2.1.287"]),
        // The summary is said under the runner, after the pin made the lock.
        c("no lock", "2.1.288", "", "2.1.287", full.clone(), World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update [1/7] make claude-pin CLAUDE_VERSION=2.1.288", "image/claude.lock 2.1.288; deployed 2.1.287"]),
        c("a stopped proxy", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::ProxyStopped, 0, vec![test, deploy, status, proxy, check], vec!["claude-update: the proxy was stopped before this run and runs now: make proxy-stop when idle"]),
        c("a VM on another version", "2.1.287", "2.1.287", "2.1.287", vec![], World::OlderVm, 0, vec![status, check], vec!["VMs still on another image version, and its claude: microvm-older (2.0)"]),
        c("the deploy left another version", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_DEPLOYS", "2.1.287")], World::Plain, 1, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: the stack now reports Claude Code 2.1.287, not the Cursor bundle's 2.1.288 (did the extension update during the run?): run make claude-update again"]),
        c("built from another zip", "2.1.287", "2.1.287", "2.1.287", vec![], World::OtherZip, 1, vec![status], vec!["image version 3.0 was built from s3://ai-env-artifacts-0000000/ai-env/image-fedcba9876543210.zip, not the zip the stack deployed (s3://ai-env-artifacts-0000000/ai-env/image-0123456789abcdef.zip)", "STOPPED at step 2/3"]),
        c("a pinned image version", "2.1.287", "2.1.287", "2.1.287", vec![], World::Pinned, 1, vec![status], vec!["bridge.toml's [aws].image_version = \"1\" pins new VMs to that version: the deployed 3.0 does not reach them", "STOPPED at step 2/3"]),
        c("many versions", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("VERSIONS_WARN", "0")], World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: 0 of 50 image versions (each update adds one; at 50 a deploy fails)", "make image-prune KEEP=3 YES=1"]),
        c("old versions, one a VM runs", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("VERSIONS_WARN", "0")], World::VersionsRun, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: 6 of 50 image versions", "  (not 1.1: a VM runs it)", "  make image-deactivate VERSION=1.0", "!image-deactivate VERSION=1.1", "!image-deactivate VERSION=2.0", "!image-deactivate VERSION=2.1"]),
        c("old versions, the VMs unlisted", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("VERSIONS_WARN", "0"), ("FAKE_AWS_FAIL_OP", "lambda-microvms list-microvms")], World::VersionsRun, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["  (the VMs could not be listed: make image-versions, then deactivate only an old version no VM runs)", "!make image-deactivate"]),
        c("make -i", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", "i")], World::Plain, 2, vec![], vec!["claude-update: not under make -i or -k"]),
        c("make -k and a variable", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", "k -- AI_ENV=x")], World::Plain, 2, vec![], vec!["claude-update: not under make -i or -k"]),
        c("make -s -i", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", " --no-print-directory -si")], World::Plain, 2, vec![], vec!["claude-update: not under make -i or -k"]),
        c("a long option and a variable", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", " --no-print-directory -- kind=1")], World::Plain, 0, vec![status, check], vec!["is pinned and deployed"]),
        c("make -j", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", " --jobserver-fds=3,4 -j")], World::Plain, 0, vec![status, check], vec!["is pinned and deployed"]),
        // make -p prints every environment variable at the end of every make under it, the runner's key among them (D1).
        c("make -p", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", "p")], World::Plain, 2, vec![], vec!["claude-update: not under make -p (", "!not under make -i"]),
        c("make -s -p", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", " --no-print-directory -sp")], World::Plain, 2, vec![], vec!["claude-update: not under make -p ("]),
        c("make -p with nothing to deploy", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", "p -- kind=1")], World::Plain, 2, vec![], vec!["claude-update: not under make -p ("]),
        // `make -s -I /tmp/kip -p` writes `spI /tmp/kip`: the directory is -I's argument, not switches (no i, k or p).
        c("an option's argument is no switch", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", "sI /tmp/kip")], World::Plain, 0, vec![status, check], vec!["is pinned and deployed"]),
        c("an include directory beside -p", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", "spI /tmp/kip")], World::Plain, 2, vec![], vec!["claude-update: not under make -p ("]),
        // A stale stamp is not honoured: test-docker runs before the runner, and the run under it finds its own stamp.
        c("a stamp of another zip", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::StampedStale, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker", "make test-docker already passed for"]),
        c("a stamp of another claude", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::StampedOtherClaude, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker", "make test-docker already passed for"]),
        c("pinned to the deployed version", "2.1.287", "2.1.287", "2.1.287", vec![], World::PinnedDeployed, 0, vec![status, check], vec!["bridge.toml's [aws].image_version = \"3\" pins new VMs to the deployed 3.0 today, but no later update will reach them"]),
        c("a pin it cannot read", "2.1.287", "2.1.287", "2.1.287", vec![], World::PinnedUnreadable, 1, vec![status], vec!["bridge.toml names image_version in a form this script does not read (aws = { image_version = \"1\" })", "STOPPED at step 2/3"]),
        c("a failed check after a deploy", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_AIENV_CHECK_RC", "3")], World::Plain, 3, vec![PIN288, test, deploy, status, proxy, check], vec!["STOPPED at step 5/5 (ai-env egress check --if-needed: exit 3)"]),
        c("a deploy's run resumed", "2.1.287", "2.1.287", "2.1.287", vec![], World::Pending, 0, vec![status, proxy, check], vec!["claude-update: 2.1.287 is deployed, and the run that deployed it stopped before its end", "claude-update [3/4] make proxy-start", "the proxy was stopped before this run and runs now", "make test-egress, the broader live test the deploy names"]),
        c("another bundle's marker", "2.1.287", "2.1.287", "2.1.287", vec![], World::PendingOther, 0, vec![status, check], vec!["is pinned and deployed", "!stopped before its end", "!make test-egress"]),
        c("a new bundle after an unfinished run", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::PendingDeploy, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["the proxy was stopped before this run and runs now: make proxy-stop when idle"]),
        // The runner refused: the steps before it ran, nothing after it.
        c("a cancelled runner", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_AIENV_AS", "cancel")], World::Plain, 3, vec![PIN288, test], vec!["ai-env: as deployer: nothing was pasted: cancelled, nothing was run", "!claude-update: Cursor bundle"]),
        c("a cancelled Touch ID", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_AIENV_AS", "cancel")], World::Plain, 3, vec![], vec!["ai-env: cancelled", "!claude-update: Cursor bundle"]),
    ];
    cases.last_mut().unwrap().runner = Some("ops");
    // Under a runner that covers the tier: no ask, one pass, the steps numbered as one plan; pin and test-docker
    // still without the key.
    for (what, under, bundle, steps, wants) in [
        ("a deploy under the deployer's runner", "deployer", "2.1.288", vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update [1/7] make claude-pin CLAUDE_VERSION=2.1.288", "claude-update [6/7] make proxy-start", "!asking once"]),
        ("the status under the ops runner", "ops", "2.1.287", vec![status, check], vec!["claude-update [3/3] ai-env egress check --if-needed", "!asking once"]),
        ("the status under the deployer's runner, which covers ops", "deployer", "2.1.287", vec![status, check], vec!["is pinned and deployed", "!asking once"]),
    ] {
        let mut case = c(what, bundle, "2.1.287", "2.1.287", full.clone(), World::Plain, 0, steps, wants);
        case.runner = None;
        case.under = Some(under);
        cases.push(case);
    }
    // A deploy is due, but the run is under the ops key: the deployer is asked (an escalation).
    let mut case = c("a deploy under the ops runner", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: this run needs ai-env as deployer (a deploy is due)"]);
    case.under = Some("ops");
    cases.push(case);
    // A deploy due before the bootstrap: the stack exports no deployer, so there is no key to ask for; that deploy is the
    // account root's (make deploy runs it as the root). Refused before anything runs, the pin and the test included (D15),
    // naming what to run instead from the steps it decided: the pin and make test-docker when they are due, then make
    // deploy as the account root.
    let no_deployer = "claude-update: a deploy is due, but stack dev exports no deployer yet, so there is no deployer key to ask for: that deploy is the bootstrap, the account root's (README \"The bootstrap\"): nothing changed";
    for (what, bundle, locked, deployed, world, instead) in [
        ("a deploy due before the bootstrap", "2.1.288", "2.1.287", "2.1.287", World::NoDeployer, "claude-update: run instead: make claude-pin CLAUDE_VERSION=2.1.288, make test-docker, then make deploy as the account root (the bootstrap)"),
        ("a deploy due before the bootstrap, the bundle pinned", "2.1.287", "2.1.287", "2.1.286", World::NoDeployer, "claude-update: run instead: make test-docker, then make deploy as the account root (the bootstrap)"),
        ("a deploy due before the bootstrap, the zip tested", "2.1.287", "2.1.287", "2.1.286", World::NoDeployerStamped, "claude-update: run instead: make deploy as the account root (the bootstrap)"),
    ] {
        cases.push(c(what, bundle, locked, deployed, full.clone(), world, 1, vec![], vec![no_deployer, instead]));
    }
    // The identity refused under the runner, after the pass before it pinned and tested: that pass's work is said, never
    // "nothing changed" (D24). The deployer's key answers as another user here.
    let refused = "claude-update: the identity of this run is refused: user/rust: not the deployer of stack dev (user/ai-env-deployer)";
    for (what, locked, deployed, steps, left) in [
        ("the identity refused after the pin", "2.1.287", "2.1.287", vec![PIN288, test], "nothing deployed: the pass before the runner pinned image/claude.lock to 2.1.288 and passed make test-docker (kept: make claude-update again resumes)"),
        ("the identity refused after test-docker", "2.1.288", "2.1.287", vec![test], "nothing deployed: the pass before the runner passed make test-docker (kept: make claude-update again resumes)"),
    ] {
        let mut case = c(what, "2.1.288", locked, deployed, vec![TTY, PASS, ("FAKE_AWS_KEY_USERS", "9001:rust 9002:ai-env-ops")], World::Plain, 1, steps, vec![refused, left, "!nothing changed"]);
        case.runner = Some("deployer");
        cases.push(case);
    }
    // The lock tracked and changed: said at the end, git run without the key and without an fsmonitor (D17).
    cases.push(c("a lock to commit", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::LockTracked, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: image/claude.lock changed: review and commit it"]));
    // A39: the stack's passphrase sealed, neither variable set. A deploy due unseals it once, after pin and test-docker
    // and before the deployer's ask (each said on stderr first); the pass under it asks for the runner as before. An
    // empty sealed value stops before the ask, saying what the pass before the unseal left; a dismissed Touch ID is
    // ai-env run's exit, nothing after it. An empty PULUMI_CONFIG_PASSPHRASE beside its file is no passphrase (Pulumi
    // takes the empty one first): unsealed too.
    let unsealing = "claude-update: a deploy is due: the dev stack's passphrase: ai-env run -f ";
    let then_asks = "(one Touch ID), then ai-env as deployer: asking once each, before the first step that needs AWS";
    let empty = "/.config/ai-env/pulumi.env, but it sets neither PULUMI_CONFIG_PASSPHRASE nor PULUMI_CONFIG_PASSPHRASE_FILE (Pulumi takes PULUMI_CONFIG_PASSPHRASE first, even empty, and an empty one counts as none: set it with ai-env edit \"";
    let empty_left = "\", README \"Identities\"): stopped before the first step that needs AWS: nothing deployed: the pass before the unseal pinned image/claude.lock to 2.1.288 and passed make test-docker (kept: make claude-update again resumes)";
    // (what, the environment, the world, the exit, the steps, the wants)
    type Sealed<'a> = (&'a str, Vec<(&'a str, &'a str)>, World, i32, Vec<&'a str>, Vec<&'a str>);
    let sealed_cases: [Sealed; 5] = [
        ("the passphrase sealed", vec![TTY], World::Sealed, 0, vec![PIN288, test, deploy, status, proxy, check], vec![unsealing, then_asks, "claude-update: this run needs ai-env as deployer (a deploy is due): asking once", "claude-update [1/5] make deploy"]),
        ("an empty passphrase beside its file", vec![TTY, ("PULUMI_CONFIG_PASSPHRASE", ""), PASS], World::Sealed, 0, vec![PIN288, test, deploy, status, proxy, check], vec![unsealing, then_asks, "claude-update [1/5] make deploy"]),
        ("the sealed passphrase empty", vec![TTY], World::SealedEmpty, 1, vec![PIN288, test], vec![unsealing, "claude-update: this run is under ai-env run -f ", empty, empty_left, "!claude-update: Cursor bundle", "!this run needs ai-env as"]),
        ("a cancelled unseal", vec![TTY, ("FAKE_AIENV_RUN", "cancel")], World::Sealed, 3, vec![PIN288, test], vec![unsealing, "ai-env: cancelled", "!claude-update: Cursor bundle", "!this run needs ai-env as"]),
        ("PULUMI_SEALED names the file", vec![TTY, ("PULUMI_SEALED", "sealed.env")], World::SealedElsewhere, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update: a deploy is due: the dev stack's passphrase: ai-env run -f sealed.env (one Touch ID), then ai-env as deployer"]),
    ];
    for (what, envs, world, code, steps, wants) in sealed_cases {
        let mut case = c(what, "2.1.288", "2.1.287", "2.1.287", envs, world, code, steps, wants);
        case.unsealed = true;
        if code != 0 {
            case.runner = None;
        }
        cases.push(case);
    }
    // Under the deployer's runner the unseal is the only hop; with nothing to deploy nothing is unsealed.
    let mut case = c("the passphrase sealed under the deployer's runner", "2.1.288", "2.1.287", "2.1.287", vec![TTY], World::Sealed, 0, vec![PIN288, test, deploy, status, proxy, check], vec![unsealing, "(one Touch ID), before the first step that needs AWS", "!then ai-env as", "!this run needs ai-env as"]);
    case.runner = None;
    case.under = Some("deployer");
    case.unsealed = true;
    cases.push(case);
    cases.push(c("nothing to deploy, a sealed file", "2.1.287", "2.1.287", "2.1.287", vec![], World::Sealed, 0, vec![status, check], vec!["is pinned and deployed", "!the dev stack's passphrase"]));
    for case in cases {
        let what = case.what;
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = s5_bin(t);
        // The steps' make: each call logged with the marker, whether a credential (the key, its secret or a session
        // token) and whether the stack's passphrase is in its environment (never a value); claude-pin writes the lock
        // and test-docker the zip, its image.json and its stamp, as the real ones do; a deploy moves the stack outputs'
        // claudeVersion to the version it deployed (FAKE_DEPLOYS).
        script(
            &bin.join("make"),
            r#"k=${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}
p=${PULUMI_CONFIG_PASSPHRASE+x}${PULUMI_CONFIG_PASSPHRASE_FILE+x}
printf 'make %s%s%s%s\n' "$*" "${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}" "${k:+ [KEY]}" "${p:+ [PASS]}" >> "$FAKE_AIENV_LOG"
case " $* " in *" ${FAKE_MAKE_FAIL:-none} "*) exit 2 ;; esac
case " $* " in
  *" claude-pin "*) for a in "$@"; do case "$a" in CLAUDE_VERSION=*) printf 'CLAUDE_VERSION=%s\nCLAUDE_PLATFORM=linux-arm64\n' "${a#CLAUDE_VERSION=}" > "$LOCK" ;; esac; done ;;
  *" test-docker "*) v=$(sed -n 's/^CLAUDE_VERSION=//p' "$LOCK"); mkdir -p "$IMAGE_OUT"; printf 'a zip of %s' "$v" > "$IMAGE_OUT/image.zip"; printf '{"claudeVersion":"%s"}\n' "$v" > "$IMAGE_OUT/image.json"; shasum -a 256 "$IMAGE_OUT/image.zip" | cut -d' ' -f1 > "$IMAGE_OUT/test-docker.ok" ;;
  *" deploy "*) sed -i '' "s/\"claudeVersion\":\"[^\"]*\"/\"claudeVersion\":\"$FAKE_DEPLOYS\"/" "$FAKE_PULUMI_OUTPUTS" ;;
esac
exit 0"#,
        );
        script(&bin.join("docker"), "exit \"${FAKE_DOCKER_RC:-0}\"");
        script(&bin.join("curl"), "test -n \"${FAKE_LATEST:-}\" || exit 6\necho \"$FAKE_LATEST\"");
        std::fs::create_dir_all(t.join("image")).unwrap();
        if !case.locked.is_empty() {
            std::fs::write(t.join("image/claude.lock"), format!("CLAUDE_VERSION={}\nCLAUDE_PLATFORM=linux-arm64\n", case.locked)).unwrap();
        }
        let mut o = outputs();
        o["claudeVersion"] = json!(case.deployed);
        o["latestActiveImageVersion"] = json!(if case.world == World::Rollback { "4.0" } else { "3.0" });
        o["bucket"] = json!("ai-env-artifacts-0000000");
        o["zipKey"] = json!("ai-env/image-0123456789abcdef.zip");
        write_outputs(t, &if matches!(case.world, World::NoDeployer | World::NoDeployerStamped) { o } else { with_operators(o) });
        if case.world == World::LockTracked {
            // git: each call logged with the marker and whether a credential or the stack's passphrase reached it (never
            // a value); the lock is tracked (ls-files) and changed (diff --quiet exits 1).
            script(
                &bin.join("git"),
                "k=${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}\np=${PULUMI_CONFIG_PASSPHRASE+x}${PULUMI_CONFIG_PASSPHRASE_FILE+x}\nprintf 'git %s%s%s%s\\n' \"$*\" \"${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}\" \"${k:+ [KEY]}\" \"${p:+ [PASS]}\" >> \"$FAKE_AIENV_LOG\"\ncase \" $* \" in *\" diff \"*) exit 1 ;; esac\nexit 0",
            );
        }
        // A39: the stack's passphrase sealed, as the stand-in's `ai-env run -f` reads it.
        match case.world {
            World::Sealed => {
                seal_passphrase(&sealed_path(t), "");
            }
            World::SealedEmpty => {
                seal_passphrase(&sealed_path(t), "empty");
            }
            World::SealedElsewhere => {
                seal_passphrase(&t.join("sealed.env"), "");
            }
            _ => {}
        }
        std::fs::create_dir_all(t.join("aws/image")).unwrap();
        std::fs::write(t.join("aws/image/state"), "UPDATED").unwrap();
        std::fs::write(t.join("aws/image/active"), "3.0").unwrap();
        let built_from = if case.world == World::OtherZip { "fedcba9876543210" } else { "0123456789abcdef" };
        std::fs::write(t.join("aws/image/uri"), format!("s3://ai-env-artifacts-0000000/ai-env/image-{built_from}.zip")).unwrap();
        seed_proxy(t, if case.world == World::ProxyStopped { "stopped" } else { "running" });
        if matches!(case.world, World::Stamped | World::StampedStale | World::StampedOtherClaude | World::NoDeployerStamped) {
            std::fs::create_dir_all(t.join("out")).unwrap();
            std::fs::write(t.join("out/image.zip"), "a zip").unwrap();
            let claude = if case.world == World::StampedOtherClaude { "2.1.286" } else { case.bundle };
            std::fs::write(t.join("out/image.json"), json!({"claudeVersion": claude}).to_string()).unwrap();
            let sha = ai_env_cli::bridge::egress::value_sha256(if case.world == World::StampedStale { "another zip" } else { "a zip" });
            std::fs::write(t.join("out/test-docker.ok"), format!("{sha}\n")).unwrap();
        }
        let toml = match case.world {
            World::Pinned => Some("[aws]\nimage_version = \"1\"\n"),
            World::PinnedDeployed => Some("[aws]\nimage_version = \"3\"\n"),
            World::PinnedUnreadable => Some("aws = { image_version = \"1\" }\n"),
            _ => None,
        };
        if let Some(toml) = toml {
            std::fs::create_dir_all(t.join("bridge")).unwrap();
            std::fs::write(t.join("bridge/bridge.toml"), toml).unwrap();
        }
        if case.world == World::VersionsRun {
            std::fs::write(t.join("aws/image/versions"), "1.0 ACTIVE\n1.1 ACTIVE\n2.0 ACTIVE\n2.1 INACTIVE\n2.5 ACTIVE\n3.0 ACTIVE\n").unwrap();
            std::fs::write(t.join("aws/vms"), "microvm-a 1.1 RUNNING\nmicrovm-b 1.0 TERMINATED\n").unwrap();
        }
        // The resume marker a deploy's run leaves until its last step passed.
        let seeded = match case.world {
            World::Pending | World::PendingDeploy => Some("2.1.287 stopped\n"),
            World::PendingOther => Some("2.1.286 running\n"),
            _ => None,
        };
        if let Some(m) = seeded {
            std::fs::create_dir_all(t.join("out")).unwrap();
            std::fs::write(t.join("out/claude-update.pending"), m).unwrap();
        }
        if case.world == World::OlderVm {
            let rows = t.join("bridge/state/vms");
            std::fs::create_dir_all(&rows).unwrap();
            std::fs::write(rows.join("microvm-older.toml"), "v = 1\nstatus = \"running\"\nid = \"microvm-older\"\nimage_version = \"2.0\"\n").unwrap();
            std::fs::write(rows.join("microvm-same.toml"), "v = 1\nstatus = \"running\"\nid = \"microvm-same\"\nimage_version = \"3.0\"\n").unwrap();
            std::fs::write(rows.join("microvm-gone.toml"), "v = 1\nstatus = \"terminated\"\nid = \"microvm-gone\"\nimage_version = \"1.0\"\n").unwrap();
        }
        let under: Vec<(String, String)> = match case.under {
            Some("deployer") => super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL),
            Some(_) => super::aws_keys::identity_env("ops", super::aws_keys::OPS_TAIL),
            None => vec![],
        };
        let out = ops5(t, &bin, &["claude-update"])
            .current_dir(t)
            .env("LOCK", "image/claude.lock")
            .env("CLAUDE_RELEASES", "https://downloads.invalid/claude-code-releases")
            .env("CLAUDE_GPG_FPR", "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE")
            .env("FAKE_AIENV_BUNDLE", case.bundle)
            .env("FAKE_DEPLOYS", case.bundle)
            .envs(under.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .envs(case.envs.iter().copied())
            .bounded();
        let text = all(&out);
        assert_eq!(out.status.code(), Some(case.code), "{what}: {text}");
        for want in &case.wants {
            match want.strip_prefix('!') {
                Some(no) => assert!(!text.contains(no), "{what}: want no {no:?}: {text}"),
                None => assert!(text.contains(want), "{what}: want {want:?}: {text}"),
            }
        }
        // Written before a deploy this run started, kept by any failure after it, gone once the run is done.
        let marker = std::fs::read_to_string(t.join("out/claude-update.pending")).ok();
        let want_marker = if case.code == 0 {
            None
        } else if case.steps.contains(&deploy) {
            Some(format!("{} {}\n", case.bundle, if case.world == World::ProxyStopped { "stopped" } else { "running" }))
        } else {
            seeded.map(String::from)
        };
        assert_eq!(marker, want_marker, "{what}: the resume marker: {text}");
        let c = calls(t);
        let ran: Vec<String> = c.iter().filter(|l| l.starts_with("make ") || l.starts_with("egress check")).map(|l| l.split(" [").next().unwrap().to_string()).collect();
        assert_eq!(ran, case.steps, "{what}: {text}");
        // One ask at most, for the tier the run needs, from the pass outside any runner.
        let asked: Vec<&String> = c.iter().filter(|l| l.starts_with("as ") && !l.starts_with("as --check ")).collect();
        match case.runner {
            Some(tier) => {
                assert_eq!(asked.len(), 1, "{what}: one runner: {c:#?}");
                assert!(asked[0].starts_with(&format!("as {tier} -- env AI_ENV_CLI={} /bin/bash ", bin.join("ai-env-stand-in").display())) && asked[0].contains("/infra/scripts/ops.sh claude-update [AI_ENV=unset]"), "{what}: {}", asked[0]);
            }
            None => assert_eq!(asked, Vec::<&String>::new(), "{what}: no runner"),
        }
        // pin and test-docker never see a key; every other step runs as the identity of the run. A39: only the deploy
        // step holds the stack's passphrase (pin and test-docker without any key or it, the steps after the deploy, the
        // check and git without it), and the deployer's runner that carries it there: no read of ops.sh's own either
        // (the stand-in's bundle, checks and builds, pulumi's stack outputs).
        let marker_of = match (case.under, case.runner) {
            (_, Some("deployer")) | (Some("deployer"), None) => "deployer:9001",
            _ => "ops:9002",
        };
        for l in c.iter().filter(|l| l.starts_with("make ")) {
            let keyless = l.contains(" claude-pin ") || l.contains(" test-docker");
            assert_eq!(!l.contains(" [KEY]") && !l.contains(" [AS="), keyless, "{what}: {l}");
            if !keyless {
                assert!(l.contains(&format!(" [AS={marker_of}] [KEY]")), "{what}: {l}");
            }
            assert_eq!(l.ends_with(" [PASS]"), l.starts_with(&format!("{deploy} ")), "{what}: {l}");
        }
        let held: Vec<&String> = c.iter().filter(|l| l.contains("[PASS]")).collect();
        assert!(held.iter().all(|l| l.starts_with(&format!("{deploy} ")) || l.starts_with("as deployer -- ")), "{what}: only the deploy step and its runner hold the passphrase: {held:#?}");
        // One unseal of the sealed passphrase when the run needs it: after pin and test-docker, before the ask; nothing
        // before it holds the passphrase, and its value is never shown.
        let unseals: Vec<&String> = c.iter().filter(|l| l.starts_with("run -f ")).collect();
        if case.unsealed {
            let file = if case.world == World::SealedElsewhere { "sealed.env".to_string() } else { sealed_path(t).display().to_string() };
            assert_eq!(unseals.len(), 1, "{what}: one unseal: {c:#?}");
            assert!(unseals[0].starts_with(&format!("run -f {file} -- env AI_ENV_CLI={} /bin/bash ", bin.join("ai-env-stand-in").display())) && unseals[0].contains("/infra/scripts/ops.sh claude-update [AI_ENV=unset]"), "{what}: {}", unseals[0]);
            let u = at(&c, "run -f ");
            let before = case.steps.iter().take_while(|s| s.starts_with("make --no-print-directory claude-pin") || **s == test).count();
            assert_eq!(c[..u].iter().filter(|l| l.starts_with("make ")).count(), before, "{what}: pin and test-docker before the unseal, nothing else: {c:#?}");
            assert!(c[..u].iter().all(|l| !l.contains("[PASS]")), "{what}: nothing before the unseal holds the passphrase: {c:#?}");
            if case.runner.is_some() {
                assert!(u < at(&c, "as deployer -- "), "{what}: the Touch ID before the paste: {c:#?}");
            }
        } else {
            assert_eq!(unseals, Vec::<&String>::new(), "{what}: nothing unsealed");
        }
        let passphrase = super::aws_keys::passphrase();
        assert!(!text.contains(&passphrase) && c.iter().all(|l| !l.contains(&passphrase)), "{what}: the passphrase's value shown");
        if what == "no passphrase" {
            assert!(text.contains(&format!("there is no sealed {} to unseal", sealed_path(t).display())), "{what}: the refusal names the default file: {text}");
        }
        if case.code == 0 || case.steps.iter().any(|s| s.starts_with("make --no-print-directory infra-status") || *s == deploy) {
            assert_eq!(text.matches("claude-update: Cursor bundle ").count(), 1, "{what}: the summary once, under the runner: {text}");
        }
        if case.code == 0 {
            assert!(text.contains("claude-update: done: new VMs start image version 3.0 with Claude Code "), "{what}: {text}");
            if case.world != World::LockTracked {
                assert!(!text.contains("review and commit"), "{what}: the lock is outside any work tree here: {text}");
            }
        } else {
            assert!(!text.contains("claude-update: done"), "{what}: {text}");
        }
        if case.world == World::LockTracked {
            // The pass under the deployer's runner: git without its key or marker, and without an fsmonitor hook or
            // daemon (one would outlive the run holding them).
            let git: Vec<&String> = c.iter().filter(|l| l.starts_with("git ")).collect();
            assert_eq!(git, ["git -c core.fsmonitor=false ls-files --error-unmatch -- image/claude.lock", "git -c core.fsmonitor=false diff --quiet -- image/claude.lock"], "{what}: {c:#?}");
        }
        if case.steps.is_empty() && case.code != 3 {
            assert!(text.contains("nothing changed") || text.contains("claude-update: not under make -"), "{what}: a refusal says nothing changed: {text}");
        }
    }

    // The identity of the run is checked under the runner before any step that needs AWS: the account root (an
    // ambient root, the bootstrap's) is refused for an ops run, nothing changed.
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = s5_bin(t);
    script(&bin.join("make"), "printf 'make %s\\n' \"$*\" >> \"$FAKE_AIENV_LOG\"\nexit 0");
    std::fs::create_dir_all(t.join("image")).unwrap();
    std::fs::write(t.join("image/claude.lock"), "CLAUDE_VERSION=2.1.287\n").unwrap();
    let mut o = with_operators(outputs());
    o["claudeVersion"] = json!("2.1.287");
    write_outputs(t, &o);
    let out = ops5(t, &bin, &["claude-update"])
        .current_dir(t)
        .env("LOCK", "image/claude.lock")
        .env("FAKE_AIENV_BUNDLE", "2.1.287")
        .envs(super::aws_keys::marker_env("ambient").iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .env("FAKE_AWS_CALLER", "root")
        .bounded();
    let text = all(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("claude-update: the identity of this run is refused: root: an ops step runs as ai-env-ops or the deployer, never the account root (break-glass: make deploy BREAKGLASS=1, then the remaining steps by hand): nothing changed"), "{text}");
    assert!(!calls(t).iter().any(|l| l.starts_with("make ") || l.starts_with("egress check") || l.starts_with("ec2 ")), "nothing ran: {:?}", calls(t));

    // A deploy is due under the account root's runner (it covers the deployer): once the stack has its deployer the
    // deployer tier refuses the root, and an exported BREAKGLASS=1 is set aside (claude-update is never break-glass:
    // make deploy BREAKGLASS=1, then the steps by hand). Nothing ran, not even pin or test-docker; nothing was asked.
    // A39: whether the passphrase is exported or only sealed (then the unseal is the only hop, after the identity).
    script(&bin.join("docker"), "exit 0");
    seal_passphrase(&sealed_path(t), "");
    for envs in [&[PASS][..], &[PASS, ("BREAKGLASS", "1")][..], &[][..], &[("BREAKGLASS", "1")][..]] {
        std::fs::remove_file(t.join("calls.log")).ok();
        let out = ops5(t, &bin, &["claude-update"])
            .current_dir(t)
            .env("LOCK", "image/claude.lock")
            .env("FAKE_AIENV_BUNDLE", "2.1.288")
            .env("AI_ENV_BRIDGE_LAB_ASSUME_TTY", "1")
            .envs(super::aws_keys::marker_env("root").iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .env("FAKE_AWS_CALLER", "root")
            .envs(envs.iter().copied())
            .bounded();
        let text = all(&out);
        assert_eq!(out.status.code(), Some(1), "{envs:?}: {text}");
        assert!(text.contains("claude-update: the identity of this run is refused: root: stack dev has its deployer (user/ai-env-deployer): make deploy asks for that user's key (Strongbox); the account root only with BREAKGLASS=1 on the make command line: nothing changed"), "{envs:?}: {text}");
        assert!(!text.contains("BREAK-GLASS") && !text.contains("stack's passphrase"), "{envs:?}: {text}");
        assert!(
            !calls(t).iter().any(|l| l.starts_with("make ") || l.starts_with("egress check") || l.starts_with("run -f ") || (l.starts_with("as ") && !l.starts_with("as --check "))),
            "{envs:?}: nothing ran, nothing asked, nothing unsealed: {:?}",
            calls(t)
        );
    }

    // A runner that does not take (it runs the command without a marker that covers the tier): asked for once, never
    // again; the pass under it stops before the first step that needs AWS.
    script(
        &bin.join("ai-env-nomarker"),
        "case \"${1:-} ${2:-}\" in\n  \"as ops\"|\"as deployer\")\n    printf 'nomarker %s\\n' \"$*\" >> \"$FAKE_AIENV_LOG\"\n    shift 2\n    test \"${1:-}\" != -- || shift\n    exec \"$@\" ;;\nesac\nexec \"$(dirname \"$0\")/ai-env-stand-in\" \"$@\"",
    );
    std::fs::remove_file(t.join("calls.log")).ok();
    let out = ops5(t, &bin, &["claude-update"]).current_dir(t).env("LOCK", "image/claude.lock").env("FAKE_AIENV_BUNDLE", "2.1.287").env("AI_ENV_CLI", bin.join("ai-env-nomarker")).bounded();
    let text = all(&out);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("claude-update: this run is under ai-env as ops, but ai-env as --check ops still fails: stopped before the first step that needs AWS"), "{text}");
    let c = calls(t);
    assert_eq!(c.iter().filter(|l| l.starts_with("nomarker as ops -- ")).count(), 1, "asked for once: {c:#?}");
    assert!(!c.iter().any(|l| l.starts_with("make ") || l.starts_with("egress check")), "no step ran: {c:#?}");
}

// ---- S8 operators: TIER, ops.sh identity and stack-deployer, P8, operator-keys, deploy-policies, destroy ----
//
// plans/s8-operators-contracts.md §9. A tiered target X is a wrapper (its help, its prechecks, one line
// `$(call TIER,<tier>,X) $(MAKE) --no-print-directory X-run`) and X-run, the recipe, which runs under `ai-env as
// <tier> --` (here the stand-in: it puts the tail-9001 or 9002 key and its marker in X-run's environment, as the
// runner does). MAKE= a logging stand-in stops a run at the runner's child, to look at the runner alone.

/// Every tiered target of the Makefiles: its tier (`image-prune` with YES=1 is the deployer's), and what its wrapper's
/// prechecks need on the command line.
const TIERED: &[(&str, &str, &[&str])] = &[
    ("deploy", "deployer", &[]),
    ("preview", "deployer", &[]),
    ("deploy-policies", "deployer", &[]),
    ("runtime-key", "deployer", &[]),
    ("ops-key", "deployer", &[]),
    ("deployer-key", "deployer", &["ROTATE=1"]),
    ("image-activate", "deployer", &["VERSION=3"]),
    ("image-deactivate", "deployer", &["VERSION=3"]),
    ("image-prune", "ops", &[]),
    ("image-delete", "deployer", &["CONFIRM=delete-image"]),
    ("connector-probe", "deployer", &["CONFIRM=create-probe-connector"]),
    ("connector-delete", "deployer", &["CONFIRM=delete-connector"]),
    ("test-egress", "deployer", &[]),
    ("image-wait", "ops", &[]),
    ("image-status", "ops", &[]),
    ("image-versions", "ops", &[]),
    ("image-builds", "ops", &[]),
    ("connector-status", "ops", &[]),
    ("connector-wait", "ops", &[]),
    ("logs", "ops", &[]),
    ("egress-logs", "ops", &[]),
    ("acceptance", "ops", &[]),
    ("operator-keys", "root", &[]),
    ("destroy", "root", &["CONFIRM=destroy-dev", "BREAKGLASS=1"]),
];

/// The tiered targets as runs: TIERED, and image-prune with YES=1.
fn tiered_runs() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    let mut runs: Vec<_> = TIERED.iter().map(|(t, tier, args)| (*t, *tier, args.to_vec())).collect();
    runs.push(("image-prune", "deployer", vec!["YES=1"]));
    runs
}

/// The marker the stand-in's runner leaves for a tier.
fn marker_of(tier: &str) -> &'static str {
    match tier {
        "deployer" => "deployer:9001",
        "ops" => "ops:9002",
        _ => "root",
    }
}

/// A `$(MAKE)` (and a `cargo`) that only log, into FAKE_AIENV_LOG: `make <argv>`, then ` [AS=<marker>]` and ` [KEY]`
/// when the runner's marker or a credential (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY or AWS_SESSION_TOKEN) is in its
/// environment, then ` [PASS]` when the stack's passphrase is (either variable, even empty; A39): never a value.
const LOGGED_MAKE: &str = r#"k=${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}
p=${PULUMI_CONFIG_PASSPHRASE+x}${PULUMI_CONFIG_PASSPHRASE_FILE+x}
printf '%s %s%s%s%s\n' "$(basename "$0" | sed 's/^fake-//')" "$*" "${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}" "${k:+ [KEY]}" "${p:+ [PASS]}" >> "$FAKE_AIENV_LOG"
exit "${FAKE_MAKE_RC:-0}""#;

/// A `cargo` whose `run ... -- ARGS` is the stand-in's `ARGS` (the Makefile's default AI_ENV is `cargo run`): every
/// call logged first, as [`LOGGED_MAKE`] logs (`cargo <argv>`, ` [AS=<marker>]`, ` [KEY]`, ` [PASS]`), so a test sees
/// whether a compile (`cargo run` builds the tree when it changed) ever had a credential, the marker or the stack's
/// passphrase in its environment; a `build` or `test` passes.
const CARGO_RUN: &str = r#"k=${AWS_ACCESS_KEY_ID:-}${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:-}
p=${PULUMI_CONFIG_PASSPHRASE+x}${PULUMI_CONFIG_PASSPHRASE_FILE+x}
printf 'cargo %s%s%s%s\n' "$*" "${AI_ENV_BRIDGE_AS:+ [AS=$AI_ENV_BRIDGE_AS]}" "${k:+ [KEY]}" "${p:+ [PASS]}" >> "$FAKE_AIENV_LOG"
case " $* " in *" run "*" -- "*) ;; *) exit 0 ;; esac
while [ "$1" != -- ]; do shift; done
shift
exec "$(dirname "$0")/ai-env-stand-in" "$@""#;

/// A tier world: the S5 fakes (the stateful aws, pulumi, the stand-in, node), a logging `fake-make` and `cargo`, the
/// outputs of a stack that has its deployer, and the stack's passphrase sealed where make looks for it (A39).
fn tier_world(t: &Path) -> PathBuf {
    let bin = s5_bin(t);
    script(&bin.join("fake-make"), LOGGED_MAKE);
    script(&bin.join("cargo"), LOGGED_MAKE);
    bin_with(t, &[("logged.sh", "sleep")]);
    write_outputs(t, &with_operators(outputs()));
    seal_passphrase(&sealed_path(t), "");
    bin
}

/// `make -C <repo> <args> AI_ENV=<stand-in>` in a tier world, `MAKE=<fake-make>` when `fake_make`.
fn tier_make(t: &Path, bin: &Path, args: &[&str], fake_make: bool, envs: &[(&str, &str)]) -> Output {
    let mut cmd = make(t, bin, args);
    s5_env(&mut cmd, t).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()));
    if fake_make {
        cmd.arg(format!("MAKE={}", bin.join("fake-make").display()));
    }
    cmd.envs(envs.iter().copied()).bounded()
}

/// String pairs as `envs` takes them.
fn pairs(v: &[(String, String)]) -> Vec<(&str, &str)> {
    v.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// Each tiered target, run for real with its prechecks met: exactly one runner, `ai-env as <tier> -- $(MAKE)
/// --no-print-directory X-run`, after `ai-env as --check <tier>` (and the root's, for the root tier), its X-run then
/// under that identity's key and marker; the deployer's wrappers that build the image zip (and test-egress, its tests)
/// build first, with no key and no marker. A39: with the stack's passphrase sealed and not set, the four that run pulumi
/// preview, up or destroy of the real stack, and only they, unseal it once, right before the runner (said once on
/// stderr), so the runner and X-run hold it; no other target ever does.
#[test]
fn every_tiered_target_runs_exactly_one_runner_line() {
    let cases = tiered_runs();
    let runs: Vec<(tempfile::TempDir, PathBuf, Output)> = std::thread::scope(|s| {
        let handles: Vec<_> = cases
            .iter()
            .map(|(target, tier, args)| {
                s.spawn(move || {
                    let tmp = tempfile::tempdir().unwrap();
                    let bin = tier_world(tmp.path());
                    let envs: &[(&str, &str)] = if *tier == "root" { &[("FAKE_AWS_CALLER", "root")] } else { &[] };
                    let out = tier_make(tmp.path(), &bin, &[&[*target][..], args.as_slice()].concat(), true, envs);
                    (tmp, bin, out)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for ((target, tier, args), (tmp, bin, out)) in cases.iter().zip(&runs) {
        let what = format!("{target} {}", args.join(" "));
        let text = all(out);
        assert!(out.status.success(), "{what}: {text}");
        let c = calls(tmp.path());
        let fake_make = bin.join("fake-make");
        let passed = ["preview", "deploy", "deploy-policies", "destroy"].contains(target);
        let pass = if passed { " [PASS]" } else { "" };
        let runners: Vec<&String> = c.iter().filter(|l| l.starts_with("as ") && !l.starts_with("as --check ")).collect();
        assert_eq!(runners, [&format!("as {tier} -- {} --no-print-directory {target}-run [AI_ENV=unset]{pass}", fake_make.display())], "{what}: exactly one runner: {c:#?}");
        let unseals: Vec<&String> = c.iter().filter(|l| l.starts_with("run -f ")).collect();
        let note = format!("{target}: the dev stack's passphrase: ai-env run -f {} (one Touch ID)", sealed_path(tmp.path()).display());
        if passed {
            let sealed = sealed_path(tmp.path()).display().to_string();
            let unseal = format!("run -f {sealed} -- /bin/bash infra/scripts/pass-exec.sh {target} {sealed} {} as {tier} -- {} --no-print-directory {target}-run [AI_ENV=unset]", bin.join("ai-env-stand-in").display(), fake_make.display());
            assert_eq!(unseals, [&unseal], "{what}: one unseal: {c:#?}");
            let (u, r) = (at(&c, "run -f "), c.iter().position(|l| l == runners[0]).unwrap());
            assert!(at(&c, "as --check ") < u && u + 1 == r, "{what}: the unseal after the check, right before the runner: {c:#?}");
            assert_eq!(stderr(out).matches(&note).count(), 1, "{what}: said once: {text}");
        } else {
            assert_eq!(unseals, Vec::<&String>::new(), "{what}: nothing unsealed: {c:#?}");
            assert!(!text.contains("stack's passphrase"), "{what}: {text}");
        }
        let checks: Vec<&String> = c.iter().filter(|l| l.starts_with("as --check ")).collect();
        let want_checks: &[&str] = match (*tier, *target) {
            ("root", "destroy") => &["as --check root [AI_ENV=unset]"],
            ("root", _) => &["as --check root [AI_ENV=unset]", "as --check root [AI_ENV=unset]"],
            ("deployer", _) => &["as --check deployer [AI_ENV=unset]"],
            _ => &["as --check ops [AI_ENV=unset]"],
        };
        assert_eq!(checks, want_checks, "{what}: {c:#?}");
        let makes: Vec<&String> = c.iter().filter(|l| l.starts_with("make ") || l.starts_with("cargo ")).collect();
        let key = if *tier == "root" { "" } else { " [KEY]" };
        let run = format!("make --no-print-directory {target}-run [AS={}]{key}{pass}", marker_of(tier));
        let built: Vec<String> = match *target {
            "deploy" | "preview" | "deploy-policies" => vec!["make --no-print-directory image-zip".to_string()],
            "test-egress" => vec!["cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run".to_string()],
            _ => vec![],
        };
        assert_eq!(makes, built.iter().chain([&run]).collect::<Vec<_>>(), "{what}: the build first, keyless; then X-run alone, as the tier: {c:#?}");
        if !built.is_empty() {
            assert!(at(&c, &built[0]) < at(&c, "as --check "), "{what}: built before the runner asks: {c:#?}");
        }
        // TIER's own first step: the operator CLI built without a key or the marker (D18), right before its first
        // `as --check`, and only once.
        assert_eq!(c.iter().filter(|l| *l == BUILT).count(), 1, "{what}: {c:#?}");
        assert_eq!(c[at(&c, "as --check ") - 1], BUILT, "{what}: TIER builds first: {c:#?}");
        // The deployer tier reads whether the stack has its deployer (a local read) before it asks; the others do not.
        let reads = c.iter().filter(|l| l.starts_with("pulumi stack output --json")).count();
        assert_eq!(reads, usize::from(*tier == "deployer"), "{what}: {c:#?}");
        assert_eq!(text.contains("BREAKGLASS=1 on the make command line"), *target == "destroy", "{what}: {text}");
    }
}

/// `make -n` (and --dry-run, --just-print, -s -n, an outer make's MAKEFLAGS=n, -t and -q) of every tiered target
/// asks nothing and runs nothing: no runner, no tool, not even ops.sh's read of the outputs; the -n forms print the
/// runner (`: <ai-env> as <tier> --;`, the root's under BREAKGLASS=1) and X-run's recipe. In a copy of the make files,
/// which none of the forms changes. A39: with the stack's passphrase sealed and not set, the four targets that would
/// unseal it show the unseal before the runner (`: <ai-env> run -f "<file>" -- <ai-env> as <tier> --;`) and unseal
/// nothing. It is shown exactly where TIER would unseal: never with the passphrase set as Pulumi takes it (its file
/// exported, or the passphrase itself, whose value is never shown), but with an empty one beside its file (Pulumi takes
/// the empty one first); never without a sealed file at PULUMI_SEALED (none there, or a directory); HOME's file for a
/// command line's `~/`.
#[test]
fn make_n_and_the_other_dry_forms_never_run_the_runner_or_a_tool() {
    let passphrase = super::aws_keys::passphrase();
    // (what, make's own switches and variables, the environment)
    type Form<'a> = (&'a str, Vec<&'a str>, Vec<(&'a str, &'a str)>);
    let forms: Vec<Form> = vec![
        ("-n", vec!["-n"], vec![]),
        ("--dry-run", vec!["--dry-run"], vec![]),
        ("--just-print", vec!["--just-print"], vec![]),
        ("-s -n", vec!["-s", "-n"], vec![]),
        ("an outer make's n", vec![], vec![("MAKEFLAGS", "n")]),
        ("-t", vec!["-t"], vec![]),
        ("-q", vec!["-q"], vec![]),
        ("-n, the passphrase's file exported", vec!["-n"], vec![("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")]),
        ("-n, the passphrase exported", vec!["-n"], vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())]),
        ("-n, an empty passphrase beside its file", vec!["-n"], vec![("PULUMI_CONFIG_PASSPHRASE", ""), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")]),
        ("-n, no sealed file there", vec!["-n"], vec![("PULUMI_SEALED", "/nonexistent/pulumi.env")]),
        ("-n, PULUMI_SEALED a directory", vec!["-n"], vec![("PULUMI_SEALED", "/")]),
        ("-n, PULUMI_SEALED=~/… on the command line", vec!["-n", "PULUMI_SEALED=~/.config/ai-env/pulumi.env"], vec![]),
    ];
    let (forms, passphrase) = (&forms, passphrase.as_str());
    let cases = tiered_runs();
    std::thread::scope(|s| {
        for (target, tier, args) in &cases {
            s.spawn(move || {
                let tmp = tempfile::tempdir().unwrap();
                let t = tmp.path();
                let w = planted_repo(t, true);
                let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).chain([("ai-env.sh", "ai-env-stand-in")]).collect();
                let bin = bin_with(t, &fakes);
                let stand_in = bin.join("ai-env-stand-in");
                let dry_tier = if args.contains(&"BREAKGLASS=1") { "root" } else { *tier };
                let sealed = seal_passphrase(&sealed_path(t), "");
                let passed = ["preview", "deploy", "deploy-policies", "destroy"].contains(target);
                for (form, flags, envs) in forms {
                    let what = format!("{form} {target} {}", args.join(" "));
                    let out = make_in(t, &bin, &w, flags)
                        .arg(target)
                        .args(args)
                        .arg(format!("AI_ENV={}", stand_in.display()))
                        .env("FAKE_LOG", t.join("tools.log"))
                        .env("FAKE_AIENV_LOG", t.join("runner.log"))
                        .envs(envs.iter().copied())
                        .bounded();
                    assert!(!all(&out).contains(passphrase), "{what}: the passphrase shown");
                    assert_eq!(read(&t.join("tools.log")), "", "{what}: a tool ran: {}", all(&out));
                    assert_eq!(read(&t.join("runner.log")), "", "{what}: the runner ran: {}", all(&out));
                    if !matches!(*form, "-t" | "-q") {
                        assert!(out.status.success(), "{what}: {}", all(&out));
                        let text = stdout(&out);
                        // Pulumi's order: PULUMI_CONFIG_PASSPHRASE when it is there at all (empty is none), else its file.
                        let var = |k: &str| envs.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
                        let set = match var("PULUMI_CONFIG_PASSPHRASE") {
                            Some(v) => !v.is_empty(),
                            None => var("PULUMI_CONFIG_PASSPHRASE_FILE").is_some_and(|v| !v.is_empty()),
                        };
                        let there = var("PULUMI_SEALED").is_none();
                        let unseal = if passed && !set && there { format!("{} run -f \"{}\" -- ", stand_in.display(), sealed.display()) } else { String::new() };
                        let runner = format!(": {unseal}{} as {dry_tier} --; {} --no-print-directory {target}-run\n", stand_in.display(), make_path());
                        assert_eq!(text.matches(&runner).count(), 1, "{what}: the runner shown once: {text}");
                        assert!(!text.contains(" as --check "), "{what}: {text}");
                        assert_eq!(text.contains(" run -f \""), !unseal.is_empty(), "{what}: the unseal shown where it would happen: {text}");
                    }
                }
                assert!(!w.join("target").exists(), "{target}: a dry form made {}", w.join("target").display());
                assert_eq!(std::fs::read_dir(&w).unwrap().count(), 3, "{target}: a dry form wrote into the tree");
            });
        }
    });
}

/// BREAKGLASS=1 counts only on the make command line: there TIER runs X-run as the account root (saying so) and
/// X-run's identity line admits the root, loudly; exported in the environment it changes nothing.
#[test]
fn breakglass_counts_only_on_the_make_command_line() {
    let note = "deployer-key: BREAKGLASS=1 on the make command line: ai-env as root (the account root's own credentials; README \"Break-glass\")";
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["deployer-key", "ROTATE=1", "BREAKGLASS=1"], true, &[("FAKE_AWS_CALLER", "root")]);
    assert!(out.status.success() && stderr(&out).contains(note), "{}", all(&out));
    let c = calls(t);
    assert!(c.contains(&format!("as root -- {} --no-print-directory deployer-key-run [AI_ENV=unset]", bin.join("fake-make").display())) && c.contains(&"make --no-print-directory deployer-key-run [AS=root]".to_string()), "{c:#?}");
    assert!(!c.iter().any(|l| l.starts_with("as --check deployer") || l.starts_with("pulumi ")), "BREAKGLASS=1 neither checks the deployer nor reads the outputs: {c:#?}");

    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["deployer-key", "ROTATE=1"], true, &[("BREAKGLASS", "1"), ("FAKE_AWS_CALLER", "root")]);
    assert!(out.status.success() && !all(&out).contains("BREAKGLASS=1"), "{}", all(&out));
    assert!(calls(t).contains(&"make --no-print-directory deployer-key-run [AS=deployer:9001] [KEY]".to_string()), "{:#?}", calls(t));

    // X-run's identity line, under the root's runner: the command line's BREAKGLASS=1 admits the root (and the preview
    // runs, the stack's passphrase exported in that terminal: an X-run typed by hand never unseals it); the
    // environment's is set aside (the root is refused before anything runs).
    // (the make arguments, the environment, admitted)
    type Run<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], bool);
    let cases: [Run; 2] = [(&["preview-run", "BREAKGLASS=1"], &[], true), (&["preview-run"], &[("BREAKGLASS", "1")], false)];
    for (args, envs, ok) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = tier_world(t);
        let plan = t.join("plan.txt");
        std::fs::write(&plan, "a preview\n").unwrap();
        let mut envs = envs.to_vec();
        envs.extend([("FAKE_AWS_CALLER", "root"), ("AI_ENV_BRIDGE_AS", "root"), ("FAKE_PULUMI_PREVIEW", plan.to_str().unwrap()), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")]);
        let out = tier_make(t, &bin, args, false, &envs);
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "{args:?} {envs:?}: {text}");
        if ok {
            assert!(text.contains("preview: BREAK-GLASS: root, with BREAKGLASS=1 on the make command line: no deploy policy applies; afterwards unset root's key and close this terminal (README \"Break-glass\")") && text.contains("a preview"), "{text}");
        } else {
            assert!(text.contains("preview: identity root: stack dev has its deployer (user/ai-env-deployer): make deploy asks for that user's key (Strongbox); the account root only with BREAKGLASS=1 on the make command line"), "{text}");
            assert!(!calls(t).iter().any(|l| l.starts_with("pulumi preview")), "{:#?}", calls(t));
        }
    }
}

/// The deployer tier runs as the account root only for the bootstrap: when the stack's outputs are read and export
/// no deployer yet. Outputs that cannot be read keep the deployer (its paste), never the shell's own credentials. A
/// runner that already covers the tier (the deployer's, or the root's typed by hand) runs X-run at once; the ops tier
/// never reads the outputs.
#[test]
fn the_bootstrap_runs_as_the_root_only_while_the_stack_exports_no_deployer() {
    let note = "runtime-key: stack dev exports no deployer yet: the bootstrap, as the account root (ai-env as root)";
    let mut no_deployer = outputs();
    no_deployer["accountId"] = json!("123456789012");
    type Case<'a> = (&'a str, Option<Value>, Vec<(String, String)>, &'a [&'a str], &'a str);
    // (what, the outputs (none: unreadable), the environment, the runner's calls, the marker X-run runs under)
    let root_env = vec![("FAKE_AWS_CALLER".to_string(), "root".to_string())];
    let cases: Vec<Case> = vec![
        ("the stack has its deployer", Some(with_operators(outputs())), vec![], &["as --check deployer", "as deployer --"], "deployer:9001"),
        ("the bootstrap", Some(no_deployer.clone()), root_env.clone(), &["as --check deployer", "as --check root", "as root --"], "root"),
        ("unreadable outputs", None, root_env, &["as --check deployer", "as deployer --"], "deployer:9001"),
        ("under the deployer's runner", Some(no_deployer.clone()), super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL), &["as --check deployer"], "deployer:9001"),
        ("the bootstrap under ai-env as root", Some(no_deployer), super::aws_keys::marker_env("root"), &["as --check deployer"], "root"),
    ];
    for (what, outs, env, runner, marker) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = tier_world(t);
        match &outs {
            Some(o) => write_outputs(t, o),
            None => std::fs::remove_file(t.join("outputs.json")).unwrap(),
        }
        let out = tier_make(t, &bin, &["runtime-key"], true, &pairs(&env));
        let text = all(&out);
        assert!(out.status.success(), "{what}: {text}");
        let c = calls(t);
        let asked: Vec<&str> = c.iter().filter(|l| l.starts_with("as ")).map(|l| if l.starts_with("as --check") { l.split(" [").next().unwrap() } else { &l[..l.find(" -- ").unwrap() + 3] }).collect();
        assert_eq!(asked, runner, "{what}: {c:#?}");
        let key = if marker == "root" { "" } else { " [KEY]" };
        assert_eq!(c.iter().filter(|l| l.starts_with("make ")).collect::<Vec<_>>(), [&format!("make --no-print-directory runtime-key-run [AS={marker}]{key}")], "{what}: {c:#?}");
        assert_eq!(text.contains(note), what == "the bootstrap", "{what}: {text}");
        if outs.is_none() {
            assert!(text.contains("ops.sh: pulumi stack output --stack dev failed"), "{what}: the unreadable outputs are named: {text}");
        }
    }
    // The ops tier never reads the outputs (an unreadable stack is no reason to refuse a status).
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    std::fs::remove_file(t.join("outputs.json")).unwrap();
    let out = tier_make(t, &bin, &["image-status"], true, &[]);
    assert!(out.status.success(), "{}", all(&out));
    assert!(!calls(t).iter().any(|l| l.starts_with("pulumi ")), "{:#?}", calls(t));
}

/// `make s3-preflight` with the stateful aws, pulumi (the stack's outputs `outputs`; none: unreadable) and the S3
/// fakes; its `[..]` rows.
fn preflight_p8(t: &Path, outputs: Option<&Value>, args: &[&str], envs: &[(&str, &str)]) -> (Output, Vec<String>) {
    let mut fakes = vec![("docker.sh", "docker"), ("curl.sh", "curl"), ("ai-env.sh", "ai-env-stand-in"), ("aws-state.sh", "aws"), ("pulumi.sh", "pulumi")];
    fakes.extend(["npm", "zip", "gpg", "rustup", "cargo"].iter().map(|n| ("logged.sh", *n)));
    let bin = bin_with(t, &fakes);
    std::os::unix::fs::symlink(node().expect("node is required: ops.sh reads JSON with it (s3-preflight P4)"), bin.join("node")).unwrap();
    std::fs::create_dir_all(t.join("aws")).unwrap();
    if let Some(o) = outputs {
        write_outputs(t, o);
    }
    let out = make(t, &bin, &["s3-preflight"])
        .args(args)
        .arg(format!("IMAGE_OUT={}", t.join("out").display()))
        .arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()))
        .env("FAKE_LOG", t.join("tools.log"))
        .env("FAKE_AWS_STATE", t.join("aws"))
        .env("FAKE_AWS_LOG", t.join("calls.log"))
        .env("FAKE_PULUMI_OUTPUTS", t.join("outputs.json"))
        .envs(envs.iter().copied())
        .bounded();
    let rows = stdout(&out).lines().filter(|l| l.starts_with('[')).map(str::to_string).collect();
    (out, rows)
}

/// P8 (contracts §9.5): PHASE=b's row is ops.sh identity deployer's one line: the stack's deployer, the bootstrap's
/// account root, a loud break-glass row (BREAKGLASS=1 on the command line), and a [NO ] for everything else (the root
/// otherwise, the ops and runtime keys, another user or account, no credentials, a key beside a profile, outputs that
/// cannot be read, a root marker over another caller). PHASE=a only names this shell's own identity.
#[test]
fn p8_admits_only_the_stacks_deployer_the_bootstrap_and_a_loud_break_glass() {
    let s = |v: &str| v.to_string();
    let env = |v: &[(&str, &str)]| v.iter().map(|(k, x)| (s(k), s(x))).collect::<Vec<_>>();
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let root = env(&[("FAKE_AWS_CALLER", "root"), ("AI_ENV_BRIDGE_AS", "root")]);
    let runtime = vec![(s("AWS_ACCESS_KEY_ID"), super::aws_keys::key_id(super::aws_keys::RUNTIME_TAIL)), (s("AWS_SECRET_ACCESS_KEY"), super::aws_keys::secret("Rt5+"))];
    let stack = with_operators(outputs());
    let mut bootstrap = outputs();
    bootstrap["accountId"] = json!("123456789012");
    type Case = (&'static str, Option<Value>, Vec<&'static str>, Vec<(String, String)>, &'static str);
    let cases: Vec<Case> = vec![
        ("the deployer", Some(stack.clone()), vec!["PHASE=b"], deployer.clone(), "[ok ] P8 deploy identity user/ai-env-deployer (the deployer of stack dev)"),
        ("the bootstrap", Some(bootstrap), vec!["PHASE=b"], root.clone(), "[ok ] P8 deploy identity root: the bootstrap deploy (stack dev exports no deployer yet: this deploy creates user/ai-env-deployer and user/ai-env-ops; then make operator-keys, as the account root, once)"),
        ("break-glass", Some(stack.clone()), vec!["PHASE=b", "BREAKGLASS=1"], root.clone(), "[-  ] P8 BREAK-GLASS: root, with BREAKGLASS=1 on the make command line: no deploy policy applies; afterwards unset root's key and close this terminal (README \"Break-glass\")"),
        ("BREAKGLASS=1 in the environment", Some(stack.clone()), vec!["PHASE=b"], [root.clone(), env(&[("BREAKGLASS", "1")])].concat(), "[NO ] P8 deploy identity root: stack dev has its deployer (user/ai-env-deployer): make deploy asks for that user's key (Strongbox); the account root only with BREAKGLASS=1 on the make command line"),
        ("the root without its runner", Some(stack.clone()), vec!["PHASE=b", "BREAKGLASS=1"], env(&[("FAKE_AWS_CALLER", "root")]), "[NO ] P8 deploy identity root: not under ai-env as root (make decides it: the bootstrap, or BREAKGLASS=1 on the make command line): refused"),
        ("the ops key", Some(stack.clone()), vec!["PHASE=b"], super::aws_keys::identity_env("ops", super::aws_keys::OPS_TAIL), "[NO ] P8 deploy identity user/ai-env-ops: the ops key cannot deploy: run the make target itself (not its -run target): it asks for the deployer's key"),
        ("the runtime key", Some(stack.clone()), vec!["PHASE=b"], runtime, "[NO ] P8 deploy identity user/ai-env-runtime: the runtime key cannot deploy: make deploy asks for the deployer's key"),
        ("another user", Some(stack.clone()), vec!["PHASE=b"], vec![], "[NO ] P8 deploy identity user/rust: not the deployer of stack dev (user/ai-env-deployer): make deploy asks for that user's key and never uses this shell's own AWS settings (AWS_PROFILE, ~/.aws)"),
        ("another account", Some(stack.clone()), vec!["PHASE=b"], env(&[("FAKE_AWS_CALLER", "rust@999999999999")]), "[NO ] P8 deploy identity user/rust of another AWS account than stack dev's (its accountId output): make deploy asks for the deployer's key of the stack's account"),
        ("no credentials", Some(stack.clone()), vec!["PHASE=b"], env(&[("FAKE_AWS_CALLER", "none")]), "[NO ] P8 deploy identity none: no AWS credentials answer: make deploy asks for the deployer's key; P8 alone: ai-env as deployer -- make s3-preflight PHASE=b"),
        ("a key and a profile", Some(stack.clone()), vec!["PHASE=b"], [deployer.clone(), env(&[("AWS_PROFILE", "rust")])].concat(), "[NO ] P8 deploy identity AWS_ACCESS_KEY_ID and AWS_PROFILE are both set: the aws CLI takes the key, Pulumi's providers may take the profile: unset AWS_PROFILE"),
        ("unreadable outputs", None, vec!["PHASE=b"], deployer, "[NO ] P8 deploy identity user/ai-env-deployer: the outputs of stack dev cannot be read (pulumi stack output --stack dev): whether it has a deployer, and its account, are unknown: refused"),
        ("a root marker over another caller", Some(stack.clone()), vec!["PHASE=b"], env(&[("AI_ENV_BRIDGE_AS", "root")]), "[NO ] P8 deploy identity user/rust: under ai-env as root, but not the account root: refused"),
        ("PHASE=a", Some(stack.clone()), vec!["PHASE=a"], vec![], "[ok ] P8 identity user/rust (PHASE=a reads only; PHASE=b admits only the stack's deployer)"),
        ("PHASE=a without credentials", Some(stack), vec!["PHASE=a"], env(&[("FAKE_AWS_CALLER", "none")]), "[NO ] P8 no AWS credentials (PHASE=a: this shell's own, the agent's; on this Mac: ai-env as ops -- make s3-preflight)"),
    ];
    let runs: Vec<(Output, Vec<String>)> = std::thread::scope(|sc| {
        let handles: Vec<_> = cases
            .iter()
            .map(|(_, outs, args, envs, _)| {
                sc.spawn(move || {
                    let t = tempfile::tempdir().unwrap();
                    preflight_p8(t.path(), outs.as_ref(), args, &pairs(envs))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for ((what, _, _, _, want), (out, rows)) in cases.iter().zip(runs) {
        assert_eq!(row(&rows, "P8"), *want, "{what}: {}", all(&out));
        assert_eq!(rows.iter().filter(|r| r.contains("] P8 ")).count(), 1, "{what}: one P8 row: {rows:?}");
        if want.starts_with("[NO ]") {
            assert!(!out.status.success(), "{what}: a [NO ] row fails the preflight");
        }
    }
}

/// ops.sh identity TIER [LABEL] beyond the deployer tier P8 shows: the ops tier (claude-update's) admits ai-env-ops
/// and the deployer, refuses the root and any other; root-keys (make operator-keys) admits the account root under its
/// runner once the stack exports both users; breakglass (destroy-run) admits the account root under its runner with
/// BREAKGLASS=1, whatever the stack exports, and refuses every user. With a label each line reads `LABEL: identity
/// <text>`, a break-glass one `LABEL: BREAK-GLASS: ...`; an unknown tier is usage, exit 2, before any call.
#[test]
fn ops_sh_identity_admits_each_tier_by_its_table() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let identity = |args: &[&str], envs: &[(String, String)]| ops5(t, &bin, &[&["identity"][..], args].concat()).envs(pairs(envs)).bounded();
    let s = |v: &str| v.to_string();
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let ops = super::aws_keys::identity_env("ops", super::aws_keys::OPS_TAIL);
    let root = vec![(s("FAKE_AWS_CALLER"), s("root")), (s("AI_ENV_BRIDGE_AS"), s("root"))];
    // (the arguments, the environment, the exit, the one line)
    type Case<'a> = (&'a [&'a str], Vec<(String, String)>, i32, &'a str);
    let cases: Vec<Case> = vec![
        (&["ops"][..], ops.clone(), 0, "user/ai-env-ops (the operator of stack dev)\n"),
        (&["ops", "claude-update"][..], deployer.clone(), 0, "claude-update: identity user/ai-env-deployer (the deployer of stack dev, which covers ops)\n"),
        (&["ops", "claude-update"][..], root.clone(), 1, "claude-update: identity root: an ops step runs as ai-env-ops or the deployer, never the account root (break-glass: make deploy BREAKGLASS=1, then the remaining steps by hand)\n"),
        (&["ops"][..], vec![], 1, "user/rust: not ai-env-ops or the deployer of stack dev\n"),
        (&["root-keys", "operator-keys"][..], root.clone(), 0, "operator-keys: identity root of stack dev's account, which exports user/ai-env-deployer and user/ai-env-ops: the bootstrap keys\n"),
        (&["root-keys", "operator-keys"][..], vec![(s("FAKE_AWS_CALLER"), s("root"))], 1, "operator-keys: identity root: not under ai-env as root (make decides it: the bootstrap, or BREAKGLASS=1 on the make command line): refused\n"),
        (&["root-keys", "operator-keys"][..], deployer.clone(), 1, "operator-keys: identity user/ai-env-deployer: make operator-keys is the account root's, once, after the bootstrap deploy; the deployer rotates: make ops-key ROTATE=1, make deployer-key ROTATE=1\n"),
        (&["deployer", "deploy"][..], deployer, 0, "deploy: identity user/ai-env-deployer (the deployer of stack dev)\n"),
        (&["deployer", "deploy"][..], [root.clone(), vec![(s("BREAKGLASS"), s("1"))]].concat(), 0, "deploy: BREAK-GLASS: root, with BREAKGLASS=1 on the make command line: no deploy policy applies; afterwards unset root's key and close this terminal (README \"Break-glass\")\n"),
        // breakglass (destroy-run): the account root under its runner with BREAKGLASS=1, and nobody else (D5).
        (&["breakglass", "destroy"][..], [root.clone(), vec![(s("BREAKGLASS"), s("1"))]].concat(), 0, "destroy: BREAK-GLASS: root, with BREAKGLASS=1 on the make command line: no deploy policy applies; afterwards unset root's key and close this terminal (README \"Break-glass\")\n"),
        (&["breakglass", "destroy"][..], root.clone(), 1, "destroy: identity root: break-glass only: BREAKGLASS=1 on the make command line (make destroy deletes the operator users themselves; README \"Break-glass\")\n"),
        (&["breakglass", "destroy"][..], vec![(s("FAKE_AWS_CALLER"), s("root")), (s("BREAKGLASS"), s("1"))], 1, "destroy: identity root: not under ai-env as root (make decides it: the bootstrap, or BREAKGLASS=1 on the make command line): refused\n"),
        (&["breakglass", "destroy"][..], [ops.clone(), vec![(s("BREAKGLASS"), s("1"))]].concat(), 1, "destroy: identity user/ai-env-ops: break-glass only: the account root's, with BREAKGLASS=1 on the make command line (make destroy deletes the operator users themselves; README \"Break-glass\")\n"),
        (&["deployer"][..], ops, 1, "user/ai-env-ops: the ops key cannot deploy: run the make target itself (not its -run target): it asks for the deployer's key\n"),
    ];
    for (args, envs, code, want) in &cases {
        let out = identity(args, envs);
        assert_eq!((out.status.code(), stdout(&out).as_str(), stderr(&out).as_str()), (Some(*code), *want, ""), "{args:?} {envs:?}");
    }
    // root-keys before the bootstrap (no deployerUserName), and with the deployer alone (no opsUserName).
    for drop in ["deployerUserName", "opsUserName"] {
        let mut o = with_operators(outputs());
        o.as_object_mut().unwrap().remove(drop);
        write_outputs(t, &o);
        let out = identity(&["root-keys", "operator-keys"], &root);
        assert_eq!((out.status.code(), stdout(&out)), (Some(1), s("operator-keys: identity root: stack dev exports no user/ai-env-deployer yet: run the bootstrap deploy first (make deploy, as the account root)\n")), "{drop}");
    }
    // A stack without its operators (an older one, or a bootstrap half done) is the root's to destroy all the same.
    write_outputs(t, &outputs());
    let out = identity(&["breakglass", "destroy"], &[root.clone(), vec![(s("BREAKGLASS"), s("1"))]].concat());
    assert_eq!(out.status.code(), Some(0), "{}", all(&out));
    assert!(stdout(&out).starts_with("destroy: BREAK-GLASS: root, with BREAKGLASS=1 on the make command line"), "{}", all(&out));
    std::fs::remove_file(t.join("calls.log")).unwrap();
    for bad in [&["bogus"][..], &[][..]] {
        let out = identity(bad, &[]);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", all(&out));
        assert!(stderr(&out).starts_with("usage: ops.sh identity deployer|ops|root-keys|breakglass [LABEL]"), "{}", all(&out));
    }
    assert_eq!(calls(t), Vec::<String>::new(), "usage before any call");
}

/// ops.sh stack-deployer (infra.mk's TIER): the deployerUserName output and a newline, nothing before the bootstrap
/// (exit 0 both); outputs that cannot be read, or are not JSON, exit 1 naming the read.
#[test]
fn stack_deployer_prints_the_deployer_nothing_before_the_bootstrap_and_fails_on_unreadable_outputs() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let run = || ops5(t, &bin, &["stack-deployer"]).bounded();
    let out = run();
    assert_eq!((out.status.code(), stdout(&out)), (Some(0), "ai-env-deployer\n".to_string()), "{}", all(&out));
    write_outputs(t, &outputs());
    let out = run();
    assert_eq!((out.status.code(), stdout(&out)), (Some(0), String::new()), "{}", all(&out));
    std::fs::write(t.join("outputs.json"), "not json").unwrap();
    let out = run();
    assert_eq!(out.status.code(), Some(1), "{}", all(&out));
    std::fs::remove_file(t.join("outputs.json")).unwrap();
    let out = run();
    assert!(out.status.code() == Some(1) && stdout(&out).is_empty() && stderr(&out).contains("ops.sh: pulumi stack output --stack dev failed"), "{}", all(&out));
    assert!(calls(t).iter().all(|l| l.starts_with("pulumi stack output --json --stack dev --cwd ")), "a local read alone: {:#?}", calls(t));
}

/// make operator-keys (the account root's, once, after the bootstrap deploy): under `ai-env as root`, the identity
/// (root-keys), the ops key's sealing check, then the deployer's key handed over and the ops key sealed, each
/// verified; a rerun, or one after a half-done run, resumes (a user with a key is skipped). Refused before anything
/// is created: before the bootstrap, a caller that is not the root (the runner), and its X-run typed under the
/// deployer's key or without the root's runner.
#[test]
fn operator_keys_issues_the_first_keys_as_the_root_and_a_rerun_resumes() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    std::fs::create_dir_all(t.join("aws")).unwrap();
    let root = [("FAKE_AWS_CALLER", "root")];
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        std::fs::remove_file(t.join("calls.log")).ok();
        tier_make(t, &bin, args, false, envs)
    };
    let done = "operator-keys: done. Next (README \"Identities\"): close this terminal; in a new one, make infra-status WRITE=1, then the checks. ai-env no longer needs root's access key: delete it when nothing else uses it";
    let out = run(&["operator-keys"], &root);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let said = stdout(&out);
    let order = [
        "operator-keys: identity root of stack dev's account, which exports user/ai-env-deployer and user/ai-env-ops: the bootstrap keys",
        "[ok ] fake aws-set --check",
        &format!("deployer-key: the key ...{} is in Strongbox and identifies as user/ai-env-deployer", &key_id(1)[16..]),
        &format!("ops-key: the sealed key ...{} identifies as user/ai-env-ops", &key_id(2)[16..]),
        done,
    ];
    let mut last = 0;
    for want in order {
        last = said[last..].find(want).unwrap_or_else(|| panic!("{want} missing or out of order: {text}")) + last;
    }
    let c = calls(t);
    assert_eq!(c.iter().filter(|l| l.starts_with("as root -- ")).count(), 1, "{c:#?}");
    assert!(c.contains(&"creds aws-set --check --user ai-env-ops [AI_ENV=unset] [AS=root]".to_string()) && c.contains(&"creds deployer-key --account 123456789012 [AI_ENV=unset] [AS=root]".to_string()), "{c:#?}");
    assert!(at(&c, "creds deployer-key ") < at(&c, "creds aws-set --user ai-env-ops"), "the deployer's key first: {c:#?}");
    assert_eq!(c[at(&c, "creds aws-set --check --user ai-env-ops") - 1], BUILT, "operator-keys-run builds the CLI without the key before it calls it (D18): {c:#?}");
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-deployer")), vec![key_id(1)]);
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-ops")), vec![key_id(2)]);
    assert_eq!(read(&t.join("bridge/credentials/ops.env")), format!("FAKE-SEALED {}\n", key_id(2)));
    assert!(!t.join("bridge/credentials/aws.env").exists(), "the runtime key is runtime-key's");

    // A rerun: both skipped, done again.
    let out = run(&["operator-keys"], &root);
    let text = all(&out);
    assert!(out.status.success() && text.contains("deployer-key: ai-env-deployer has its key already: skipped (a rerun resumes)") && text.contains("ops-key: ai-env-ops has its key already: skipped (a rerun resumes)") && text.contains(done), "{text}");
    assert!(!calls(t).iter().any(|l| l.starts_with("iam create-access-key")), "{:#?}", calls(t));
    // After a run that stopped between the two: the deployer skipped, the ops key issued.
    std::fs::write(t.join("aws/keys.ai-env-ops"), "").unwrap();
    std::fs::remove_file(t.join("bridge/credentials/ops.env")).unwrap();
    let out = run(&["operator-keys"], &root);
    let text = all(&out);
    assert!(out.status.success() && text.contains("deployer-key: ai-env-deployer has its key already: skipped") && text.contains(&format!("ops-key: the sealed key ...{} identifies as user/ai-env-ops", &key_id(3)[16..])), "{text}");

    // Refusals, nothing created.
    let keys = |t: &Path| (read(&t.join("aws/keys.ai-env-deployer")), read(&t.join("aws/keys.ai-env-ops")));
    let before = keys(t);
    let mut no_users = outputs();
    no_users["accountId"] = json!("123456789012");
    write_outputs(t, &no_users);
    let out = run(&["operator-keys"], &root);
    assert!(!out.status.success() && all(&out).contains("operator-keys: identity root: stack dev exports no user/ai-env-deployer yet: run the bootstrap deploy first (make deploy, as the account root)"), "{}", all(&out));
    write_outputs(t, &with_operators(outputs()));
    let out = run(&["operator-keys"], &[]);
    assert!(!out.status.success() && all(&out).contains("ai-env: as root: the aws CLI's credentials are arn:aws:iam::123456789012:user/rust, not the account root"), "the runner refuses another caller: {}", all(&out));
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let out = run(&["operator-keys-run"], &pairs(&deployer));
    assert!(!out.status.success() && all(&out).contains("operator-keys: identity user/ai-env-deployer: make operator-keys is the account root's, once, after the bootstrap deploy; the deployer rotates: make ops-key ROTATE=1, make deployer-key ROTATE=1"), "{}", all(&out));
    let out = run(&["operator-keys-run"], &root);
    assert!(!out.status.success() && all(&out).contains("operator-keys: identity root: not under ai-env as root"), "{}", all(&out));
    assert_eq!(keys(t), before, "nothing created by a refusal");
}

/// make destroy deletes the operator users themselves: the account root's alone, with BREAKGLASS=1 on the command line
/// after CONFIRM, checked before the runner asks (and again in destroy-run, which is never typed, and whose identity
/// line, the break-glass tier, admits the account root under its runner alone); then, as the root, vm-guard, pulumi
/// destroy and the checklist.
#[test]
fn destroy_is_the_account_roots_with_breakglass_only() {
    let refusal = "destroy: it deletes the operator users themselves: as the account root only: make destroy CONFIRM=destroy-dev BREAKGLASS=1 (README \"Break-glass\")";
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    // (the make arguments, the environment)
    type Run<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)]);
    let cases: [Run; 3] = [(&["destroy", "CONFIRM=destroy-dev"], &[]), (&["destroy", "CONFIRM=destroy-dev"], &[("BREAKGLASS", "1")]), (&["destroy-run", "CONFIRM=destroy-dev"], &[])];
    for (args, envs) in cases {
        let out = tier_make(t, &bin, args, false, envs);
        assert!(!out.status.success() && all(&out).contains(refusal), "{args:?} {envs:?}: {}", all(&out));
        assert_eq!(calls(t), Vec::<String>::new(), "{args:?} {envs:?}: nothing ran");
    }
    let out = tier_make(t, &bin, &["destroy", "BREAKGLASS=1"], false, &[]);
    assert!(!out.status.success() && all(&out).contains("set CONFIRM=destroy-dev on the command line") && !all(&out).contains(refusal), "CONFIRM first: {}", all(&out));
    assert_eq!(calls(t), Vec::<String>::new());

    // destroy-run typed by hand under the deployer's runner, both switches given: the wrapper's root tier never ran, so
    // destroy-run's own identity line refuses every user, the deployer included (L8: it would delete the operator users
    // and its own rights half-way); nothing after it runs (D5).
    seed_connector(t, CONNECTOR, "ACTIVE");
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let mut envs = pairs(&deployer);
    envs.push(("FAKE_PULUMI_ALLOW", "destroy"));
    let out = tier_make(t, &bin, &["destroy-run", "CONFIRM=destroy-dev", "BREAKGLASS=1"], false, &envs);
    let text = all(&out);
    let deployer_refused = "destroy: identity user/ai-env-deployer: break-glass only: the account root's, with BREAKGLASS=1 on the make command line (make destroy deletes the operator users themselves; README \"Break-glass\")";
    assert!(!out.status.success() && text.contains(deployer_refused), "{text}");
    let c = calls(t);
    assert!(!c.iter().any(|l| l.starts_with("pulumi destroy") || l.starts_with("lambda-core ") || l.starts_with("lambda-microvms ")), "nothing after the identity line: {c:#?}");
    std::fs::remove_file(t.join("calls.log")).unwrap();

    // The real thing, as the root: the identity, vm-guard, pulumi destroy (its own confirmation), the checklist. A39: the
    // stack's sealed passphrase unsealed first (pulumi destroy needs it), then the root's runner.
    let out = tier_make(t, &bin, &["destroy", "CONFIRM=destroy-dev", "BREAKGLASS=1"], false, &[("FAKE_AWS_CALLER", "root"), ("FAKE_PULUMI_ALLOW", "destroy")]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let said = stdout(&out);
    let mut last = 0;
    for want in ["destroy: BREAK-GLASS: root, with BREAKGLASS=1 on the make command line", "vm-guard: no network connector but the stack's ai-env-egress", "fake pulumi: destroy --stack dev", "Post-destroy checklist", "aws iam get-user --user-name ai-env-deployer"] {
        last = said[last..].find(want).unwrap_or_else(|| panic!("{want} missing or out of order: {text}")) + last;
    }
    let c = calls(t);
    let runner = format!("as root -- {} --no-print-directory destroy-run [AI_ENV=unset] [PASS]", make_path());
    assert!(c.contains(&runner), "{c:#?}");
    let sealed = sealed_path(t).display().to_string();
    assert_eq!(c[at(&c, &runner) - 1], format!("run -f {sealed} -- /bin/bash infra/scripts/pass-exec.sh destroy {sealed} {} as root -- {} --no-print-directory destroy-run [AI_ENV=unset]", bin.join("ai-env-stand-in").display(), make_path()), "{c:#?}");
    assert!(c.contains(&"pulumi destroy --stack dev [PASS]".to_string()) && !c.iter().any(|l| l.contains("FORBIDDEN")), "no --yes: {c:#?}");
}

/// deploy-policies: the zip first (no key), then as the deployer the identity, deploy's gates (s3-preflight PHASE=b,
/// check-policies, the plan gate over the whole stack), then `pulumi up` of exactly the five stack policies (each by
/// its URN), and its note; nothing else of deploy (no snapshot, no wait, no egress step). preview's REFRESH=1 counts
/// only on the command line.
#[test]
fn deploy_policies_updates_the_five_stack_policies_only_and_preview_refreshes_on_request() {
    let five = ["ai-env-deploy", "ai-env-deploy-egress", "ai-env-deploy-dns", "ai-env-deployer", "ai-env-ops"];
    let urns: Vec<String> = five.iter().map(|p| format!("--target urn:pulumi:dev::ai-env::aws:iam/policy:Policy::{p}")).collect();
    // deploy's plan with the five policies, each document known (a JSON string) but `unknown`'s, which holds Pulumi's
    // unknown value (as while the proxy instance, which ai-env-ops' document names, is replaced), and none of `without`.
    let policies_plan = |unknown: &str, without: &str| {
        let steps: Vec<(&str, &str, &str)> = five.iter().filter(|p| **p != without).map(|p| ("same", "aws:iam/policy:Policy", *p)).collect();
        let mut p = deploy_plan(&steps);
        for s in p["steps"].as_array_mut().unwrap().iter_mut().filter(|s| s["newState"]["type"] == "aws:iam/policy:Policy") {
            let name = s["urn"].as_str().unwrap().rsplit("::").next().unwrap().to_string();
            let doc = if name == unknown { "04da6b54-80e4-46f7-96ec-b56ff0331ba9".to_string() } else { json!({"Version": "2012-10-17", "Statement": [{"Sid": name}]}).to_string() };
            s["newState"]["inputs"] = json!({"name": name, "policy": doc});
        }
        p
    };
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.run("deploy-policies", &policies_plan("", ""), &[]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let c = calls(d.t.path());
    let up: Vec<&String> = c.iter().filter(|l| l.starts_with("pulumi up")).collect();
    // Under the stack's passphrase, unsealed before the runner (A39).
    assert_eq!(up, [&format!("pulumi up --stack dev {} [PASS]", urns.join(" "))], "the five policies and nothing else: {c:#?}");
    let order = ["infra scan ", "as --check deployer", "as deployer -- ", "sts get-caller-identity", "check-policies eu-central-1", "pulumi preview --json --show-sames --show-reads --non-interactive --stack dev", "check-plan --mode none", "pulumi up --stack dev --target "];
    let mut last = 0;
    for want in order {
        last = c[last..].iter().position(|l| l.contains(want)).unwrap_or_else(|| panic!("{want} missing or out of order: {c:#?}")) + last;
    }
    assert!(!c.iter().any(|l| l.starts_with("lambda-microvms") || l.starts_with("egress ") || l.starts_with("lambda-core get-network-connector")), "no snapshot, wait or egress step: {c:#?}");
    assert_eq!(c.iter().filter(|l| l.starts_with("infra scan ")).count(), 1, "the zip built once, in the wrapper, before the runner: {c:#?}");
    let asked = at(&c, "as --check deployer");
    assert!(c[asked - 1] == BUILT && c[..asked].iter().filter(|l| *l == BUILT).count() == 2, "the zip's version read, then TIER's keyless build of the CLI (D18), before it asks: {c:#?}");
    assert!(text.contains("deploy-policies: identity user/ai-env-deployer (the deployer of stack dev)") && stdout(&out).ends_with("deploy-policies: done: wait about 15 s for IAM, then make deploy\n"), "{text}");
    // Its plan gate refuses like deploy's: nothing updated.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.run("deploy-policies", &policies_plan("", ""), &[("FAKE_CHECK_PLAN_RC", "1")]);
    assert!(!out.status.success() && all(&out).contains("deploy: the plan check refused the plan (exit 1, above)"), "{}", all(&out));
    assert!(!calls(d.t.path()).iter().any(|l| l.starts_with("pulumi up")));
    // A document the plan holds unknown (the plan check accepts it while a resource it names is replaced) would be
    // rendered anew by the targeted pulumi up, from the old resource, and applied uncompared: refused (D18), as is a
    // policy the plan does not hold; make deploy takes the same plan whole.
    for (what, unknown, without, said) in [
        ("an unknown document", "ai-env-ops", "", "deploy-policies: the plan holds the document of ai-env-ops unknown"),
        ("a policy missing from the plan", "", "ai-env-deployer", "deploy-policies: the plan holds no step of the policy ai-env-deployer"),
    ] {
        let d = DeployTree::new(CHECK_PLAN_FAKE);
        let out = d.run("deploy-policies", &policies_plan(unknown, without), &[]);
        let text = all(&out);
        assert!(!out.status.success() && text.contains(said) && text.contains("deploy: refused before pulumi up: nothing deployed"), "{what}: {text}");
        assert!(!calls(d.t.path()).iter().any(|l| l.starts_with("pulumi up")), "{what}");
    }
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&policies_plan("ai-env-ops", ""), &[]);
    assert!(out.status.success() && !all(&out).contains("deploy-policies:"), "{}", all(&out));

    // preview: REFRESH=1 on the command line adds --refresh.
    let tmp = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(tmp.path(), &fakes);
    let dry = |args: &[&str], envs: &[(&str, &str)]| stdout(&make(tmp.path(), &bin, &["-n", "preview"]).args(args).envs(envs.iter().copied()).bounded());
    assert!(dry(&["REFRESH=1"], &[]).contains("pulumi preview --diff --stack dev --refresh\n"));
    assert!(dry(&[], &[("REFRESH", "1")]).contains("pulumi preview --diff --stack dev\n"), "REFRESH=1 in the environment is ignored");
    assert_eq!(read(&tmp.path().join("tools.log")), "");
}

/// `make help` lists the new targets and every tiered one with its tier first, never an X-run; and in the make files
/// every recipe line that names $(MAKE) is a sub-make or the one TIER line of a tiered target, whose X-run exists
/// and is phony (GNU make runs a line naming $(MAKE) even under -n: anything else on it would run in a dry run).
#[test]
fn make_help_lists_the_new_targets_and_every_make_line_is_a_sub_make_or_a_tier_line() {
    let t = tempfile::tempdir().unwrap();
    let bin = bin_with(t.path(), &[]);
    let out = make(t.path(), &bin, &["help"]).bounded();
    assert!(out.status.success(), "{}", all(&out));
    let help: Vec<(String, String)> = stdout(&out)
        .lines()
        .map(|l| {
            let l = l.replace("\u{1b}[36m", "").replace("\u{1b}[0m", "");
            let (name, text) = l.split_once(' ').unwrap();
            (name.to_string(), text.trim_start().to_string())
        })
        .collect();
    let text_of = |target: &str| help.iter().find(|(n, _)| n == target).map(|(_, t)| t.clone()).unwrap_or_else(|| panic!("{target} not in make help: {help:#?}"));
    for target in ["deploy-policies", "ops-key", "deployer-key", "operator-keys"] {
        text_of(target);
    }
    for (target, tier, _) in TIERED {
        let text = text_of(target);
        assert!(text.starts_with(&format!("({tier}")), "{target}'s help starts with its tier: {text}");
        assert!(help.iter().all(|(n, _)| *n != format!("{target}-run")), "{target}-run is in make help");
    }

    let mk = format!("{}\n{}", read(&Path::new(REPO).join("Makefile")), read(&Path::new(REPO).join("infra/infra.mk")));
    // The .PHONY lines and their continuations.
    let mut phony: BTreeSet<&str> = BTreeSet::new();
    let mut more = false;
    for line in mk.lines() {
        if line.starts_with(".PHONY:") || more {
            phony.extend(line.trim_start_matches(".PHONY:").split_whitespace().filter(|w| *w != "\\"));
            more = line.ends_with('\\');
        }
    }
    let mut rule = "";
    let mut tier_lines: Vec<(String, String)> = vec![];
    for line in mk.lines() {
        if let Some((name, _)) = line.split_once(':').filter(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
            rule = name;
            continue;
        }
        let Some(cmd) = line.strip_prefix('\t') else { continue };
        if !cmd.contains("$(MAKE)") {
            continue;
        }
        let cmd = cmd.trim_start_matches('@');
        if let Some(rest) = cmd.strip_prefix("$(call TIER,") {
            assert!(rest.ends_with(&format!(",{rule}) $(MAKE) --no-print-directory {rule}-run")), "{rule}: its TIER line: {cmd}");
            tier_lines.push((rule.to_string(), cmd.to_string()));
            continue;
        }
        // A sub-make: `$(MAKE) <options, targets, variables>`, the image zip's under $(NO_KEY) (D18), nothing else.
        let sub = cmd.strip_prefix("$(NO_KEY) ").unwrap_or(cmd);
        let args = sub.strip_prefix("$(MAKE) ").unwrap_or_else(|| panic!("{rule}: a line naming $(MAKE) that is not a sub-make: {cmd}"));
        assert!(!args.contains(['$', ';', '|', '&', '<', '>', '`']), "{rule}: a sub-make line that does more: {cmd}");
    }
    let mut tiered: Vec<&str> = TIERED.iter().map(|(t, _, _)| *t).collect();
    tiered.sort_unstable();
    let mut with_tier: Vec<&str> = tier_lines.iter().map(|(r, _)| r.as_str()).collect();
    with_tier.sort_unstable();
    assert_eq!(with_tier, tiered, "one TIER line per tiered target, and none elsewhere");
    for target in tiered {
        assert!(mk.lines().any(|l| l == format!("{target}-run:")), "{target}-run is not defined");
        assert!(phony.contains(target) && phony.contains(format!("{target}-run").as_str()), "{target} and {target}-run are phony: {phony:?}");
    }

    // The recipe lines of a rule (its tab-indented lines, the tab dropped).
    let recipe = |rule: &str| -> Vec<&str> {
        let mut lines = mk.lines().skip_while(|l| !l.strip_prefix(rule).is_some_and(|r| r == ":" || r.starts_with(": ")));
        assert!(lines.next().is_some(), "no rule {rule}");
        lines.map_while(|l| l.strip_prefix('\t')).collect()
    };
    // Each X-run: its CONFIRM and BREAKGLASS rechecks (nothing that runs), then the identity line of its tier (contracts
    // §9.3: the deployer's; image-prune's with YES=1 alone; destroy's the break-glass tier, the account root's alone;
    // operator-keys' root-keys), then its make -i and -p refusal; an ops X-run, which has no identity line, starts with
    // the refusal (acceptance's with its own -i text, then the -p one). Each wrapper's refusal is the line before its
    // TIER line. The refusal is a $(error) make expands with the whole recipe, before any line runs, wherever it stands.
    let rechecks = ["@$(IMAGE_DELETE_CONFIRM)", "@$(CONNECTOR_PROBE_CONFIRM)", "@$(CONNECTOR_DELETE_CONFIRM)", "@$(DESTROY_CONFIRM)", "@$(DESTROY_BREAKGLASS)"];
    let acceptance_refusal = "@$(if $(findstring i,$(MAKE_SWITCHES)),$(error acceptance: not under make -i ";
    let acceptance_p = "$(call NOT_UNDER_P,acceptance)";
    for (target, tier, _) in TIERED {
        let refusal = format!("@$(call NOT_UNDER_I_OR_P,{target})");
        let run = recipe(&format!("{target}-run"));
        let first = run.iter().position(|l| !rechecks.contains(l)).unwrap_or_else(|| panic!("{target}-run runs nothing: {run:?}"));
        let identity = match (*target, *tier) {
            ("image-prune", _) => Some("$(if $(filter 1,$(call cmdline,YES)),@$(IDENTITY) deployer image-prune)".to_string()),
            ("operator-keys", _) => Some("@$(IDENTITY) root-keys operator-keys".to_string()),
            ("destroy", _) => Some("@$(IDENTITY) breakglass destroy".to_string()),
            (_, "deployer") => Some(format!("@$(IDENTITY) deployer {target}")),
            _ => None,
        };
        match identity {
            Some(id) => {
                assert_eq!(run[first], id, "{target}-run: its first line that runs is its identity line: {run:#?}");
                assert_eq!(run[first + 1], refusal, "{target}-run: the make -i and -p refusal after the identity line: {run:#?}");
            }
            None if *target == "acceptance" => assert!(first == 0 && run[0].starts_with(acceptance_refusal) && run[0].ends_with(acceptance_p), "{run:#?}"),
            None => assert!(first == 0 && run[0] == refusal, "{target}-run: an ops X-run starts with its make -i and -p refusal: {run:#?}"),
        }
        let wrapper = recipe(target);
        let at_tier = wrapper.iter().position(|l| l.starts_with("@$(call TIER,")).unwrap_or_else(|| panic!("{target}: no TIER line: {wrapper:#?}"));
        let before = wrapper[at_tier.saturating_sub(1)];
        assert!(at_tier > 0 && (before == refusal || (*target == "acceptance" && before.starts_with(acceptance_refusal) && before.ends_with(acceptance_p))), "{target}: the make -i and -p refusal right before the runner: {wrapper:#?}");
    }
    // D18: the wrappers' compiles carry $(NO_KEY), first, and NO_KEY unsets all six (the key, its secret, a session
    // token, the marker, and the stack's passphrase either way: A39); so does the keyless build of the operator CLI, and
    // ops.sh's NO_KEY_ENV. A39: deploy and deploy-policies, whose plan check cannot prompt, check the passphrase first,
    // before the build (preview and destroy keep Pulumi's prompt); exactly the four targets that run pulumi preview, up
    // or destroy of the real stack unseal it, and no other wrapper checks it.
    for target in ["deploy", "preview", "deploy-policies"] {
        let zip = usize::from(target != "preview");
        assert_eq!(recipe(target)[zip], "$(NO_KEY) $(MAKE) --no-print-directory image-zip", "{target}: the zip built first, without a key");
    }
    for target in ["deploy", "deploy-policies"] {
        assert_eq!(recipe(target)[0], format!("@$(call PASS_CHECK,{target})"), "{target}: the passphrase checked first");
    }
    let checks: Vec<&str> = mk.lines().filter(|l| l.contains("$(call PASS_CHECK,")).collect();
    assert_eq!(checks, ["\t@$(call PASS_CHECK,deploy)", "\t@$(call PASS_CHECK,deploy-policies)"], "no other wrapper checks the passphrase");
    // A39 (D17): the passphrase is never expanded into a command line (a recipe shell's argv, make -n's output, a log):
    // the make files and the scripts name the two variables only to test whether one is set (the shell's `${NAME:+x}`
    // and `${NAME+x}`, `$${…}` in make), to unset them, in $(origin) and in text; never make's $(NAME), ${NAME} or
    // $(value NAME), nor the shell's $NAME or another ${NAME…}.
    let mut scripts: Vec<PathBuf> = std::fs::read_dir(Path::new(REPO).join("infra/scripts")).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sh")).collect();
    scripts.sort();
    let sources = std::iter::once(("Makefile and infra/infra.mk".to_string(), mk.clone(), true)).chain(scripts.iter().map(|p| (p.display().to_string(), read(p), false)));
    for (file, text, make) in sources {
        for line in text.lines() {
            for (at, _) in line.match_indices("PULUMI_CONFIG_PASSPHRASE") {
                let before = &line[..at];
                let name = if line[at..].starts_with("PULUMI_CONFIG_PASSPHRASE_FILE") { "PULUMI_CONFIG_PASSPHRASE_FILE" } else { "PULUMI_CONFIG_PASSPHRASE" };
                let tested = [":+x}", "+x}"].iter().any(|t| line[at + name.len()..].starts_with(t));
                let only_named = if before.ends_with('{') {
                    tested && before.ends_with(if make { "$${" } else { "${" })
                } else {
                    !before.ends_with('$') && !(make && (before.ends_with("$(") || before.ends_with("$(value ")))
                };
                assert!(only_named, "{file}: the passphrase expanded, not only tested: {line}");
            }
        }
    }
    // D2: the live tests a runner may run build their tests without the key first (the run keeps it), test-aws's probes
    // their CLI too; test-docker, which needs no AWS, drops it from every step, and so do the image's build (image-zip,
    // vm-build) and make install (B0.1 runs it in the root's terminal).
    for target in ["test-aws", "test-aws-readonly"] {
        assert_eq!(recipe(target)[0], "$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run", "{target}: its tests built first, without a key");
    }
    assert!(recipe("test-aws").iter().any(|l| l.contains("$(AI_ENV_BUILD) || exit $$?; rc=0; for p in ")), "test-aws: the probes' CLI built first, without a key");
    let docker = recipe("test-docker");
    let steps: Vec<&&str> = docker.iter().filter(|l| !l.starts_with("  ") && !l.starts_with('@')).collect();
    assert!(steps.len() == 4 && steps.iter().all(|l| l.starts_with("$(NO_KEY) ")), "test-docker: every step without a key: {docker:#?}");
    assert_eq!(recipe("image-zip")[..2], ["$(NO_KEY) $(MAKE) vm-build", "$(NO_KEY) $(MAKE) image-stage-scan"], "image-zip: its sub-makes without a key");
    assert!(recipe("image-zip").iter().any(|l| l.contains(" shim=$$($(NO_KEY) $(AI_ENV) --version | ")), "image-zip: the CLI's version read without a key");
    assert!(recipe("vm-build").iter().any(|l| l.contains("; $(NO_KEY) RUSTUP_TOOLCHAIN=$(TOOLCHAIN) \"$$cl\" lambda build ")), "vm-build: cargo-lambda without a key");
    assert!(recipe("install")[0].starts_with("$(NO_KEY) $(CARGO) install "), "install: without a key");
    assert!(recipe("test-egress")[0].starts_with("$(NO_KEY) $(LAB_UNSET) $(CARGO) test ") && recipe("test-egress")[0].ends_with(" --no-run"), "test-egress: its tests built first, without a key");
    assert_eq!(recipe("gates")[0], "@$(NO_KEY) $(CARGO) build -q -p $(PKG) --bin ai-env", "gates: the tree's ai-env built first, without a key");
    for target in ["infra-status", "allowlist-reload", "proxy-stop", "proxy-start", "proxy-patch", "s3-preflight"] {
        assert_eq!(recipe(target)[0], "@$(AI_ENV_BUILD)", "{target}: the operator CLI built first, without a key");
    }
    assert_eq!(recipe("check-base-image")[1], "@$(AI_ENV_BUILD)", "check-base-image: built after its precheck, before its one command");
    // The X-runs that call the CLI before anything else builds it build it first themselves, so one typed by hand under
    // a runner compiles nothing with the key; test-egress-run checks its tests' build again too.
    for target in ["image-wait", "runtime-key", "ops-key", "operator-keys", "test-egress"] {
        let run = recipe(&format!("{target}-run"));
        let built = run.iter().position(|l| *l == "@$(AI_ENV_BUILD)").unwrap_or_else(|| panic!("{target}-run builds no CLI: {run:#?}"));
        let call = run.iter().position(|l| l.contains("$(AI_ENV) ") || l.contains("$(IMAGE_WAIT_SH)")).unwrap_or_else(|| panic!("{target}-run calls no CLI: {run:#?}"));
        assert!(built < call, "{target}-run: built before its first call: {run:#?}");
    }
    let run = recipe("test-egress-run");
    let tests = run.iter().position(|l| l.contains(" --ignored live_egress_ ")).unwrap();
    assert!(run[..tests].contains(&"$(NO_KEY) $(LAB_UNSET) $(CARGO) test -p $(PKG) --features bridge --test aws --no-run"), "test-egress-run: its tests built without the key before they run: {run:#?}");
    let vars = make_vars(t.path(), &[]);
    assert_eq!(vars["NO_KEY"], NO_KEY);
    assert_eq!(vars["AI_ENV_BUILD"], "$(NO_KEY) $(LAB_UNSET) $(AI_ENV) --version >/dev/null");
    assert!(vars["TIER_SH"].starts_with("tier() { t=$$1; x=$$2; shift 2; $(AI_ENV_BUILD) || return $$?; $(PASS_SH) "), "TIER builds first, then decides the unseal: {}", vars["TIER_SH"]);
    assert_eq!(vars["PASS_TARGETS"], "preview deploy deploy-policies destroy", "the targets whose X-run runs pulumi preview, up or destroy");
    let ops = read(&Path::new(REPO).join("infra/scripts/ops.sh"));
    assert!(ops.contains(&format!("\nNO_KEY_ENV=({NO_KEY})\n")), "ops.sh's NO_KEY_ENV is $(NO_KEY)");
    // A39: claude-update's steps after its deploy (status, proxy, check) run under NO_PASS_ENV, the passphrase's two
    // names, besides the export -n that keeps it from every step but the deploy: either alone keeps it from them.
    assert!(ops.contains("\nNO_PASS_ENV=(env -u PULUMI_CONFIG_PASSPHRASE -u PULUMI_CONFIG_PASSPHRASE_FILE)\n"), "ops.sh's NO_PASS_ENV unsets the passphrase's two names");
    for step in ["status)", "proxy)", "check)"] {
        let line = ops.lines().map(str::trim_start).find(|l| l.starts_with(step) && l.contains(" update_step ")).unwrap_or_else(|| panic!("ops.sh: no claude-update {step} step"));
        assert!(line.contains(" \"${NO_PASS_ENV[@]}\" "), "claude-update's {step} step runs under NO_PASS_ENV: {line}");
    }
    // The two tsc compiles inside deploy-run (the plan check's and check-policies') run under the same six.
    for script in ["check-plan.sh", "check-policies.sh"] {
        assert!(read(&Path::new(REPO).join("infra/scripts").join(script)).contains(&format!("(cd \"$infra\" && {NO_KEY} \\\n")), "{script}: its tsc under $(NO_KEY)'s six");
    }
}

/// D18, nested (contracts §9.3): a make typed under `ai-env as` (`ai-env as deployer -- make preview deploy`,
/// claude-update's make deploy) holds the runner's key, its secret and its marker, here with a session token beside
/// them. No compile sees any of them: the wrapper's image zip and test-egress's test build, then TIER's own build of the
/// operator CLI with the Makefile's default AI_ENV (`cargo run`, which compiles the tree when it changed; here
/// [`CARGO_RUN`]), the first `cargo` call, before `ai-env as --check`, the first that sees the key; X-run then runs as
/// the runner's identity (a logging MAKE). The one-command operator targets, check-base-image, s3-preflight (P9 to P11
/// run the CLI) and gates build first the same way, and so does break-glass, the account root's own key exported in
/// the shell; and ops.sh's own calls of the CLI (key-issue's here: need_ai_env). The live tests a runner may run
/// (test-aws, test-aws-readonly) are built without the key before they run with it, and test-docker, which needs no
/// AWS, runs without it whole, also as the first goal before a deploy.
#[test]
fn a_make_under_a_runner_compiles_nothing_with_the_key() {
    let s = |v: &str| v.to_string();
    let token = (s("AWS_SESSION_TOKEN"), s("a-session-token-of-the-shell"));
    let deployer = [super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL), vec![token.clone()]].concat();
    let ops = [super::aws_keys::identity_env("ops", super::aws_keys::OPS_TAIL), vec![token]].concat();
    // Break-glass: the account root's own access key in the shell (here a key the fakes answer as the root).
    let root = vec![(s("AWS_ACCESS_KEY_ID"), super::aws_keys::key_id("9009")), (s("AWS_SECRET_ACCESS_KEY"), super::aws_keys::secret("Rt5+")), (s("FAKE_AWS_KEY_USERS"), s("9009:root"))];
    let cli = |args: &str| format!("cargo +1.98.1 run -q -p ai-env-cli --bin ai-env -- {args}");
    let build = cli("--version");
    let (d, o) = (" [AS=deployer:9001] [KEY]", " [AS=ops:9002] [KEY]");
    // test-docker's steps as the logging MAKE and cargo record them: the image's two sub-makes, then its two suites.
    let docker = vec![
        s("make image-zip"),
        s("make image-build-local"),
        s("cargo +1.98.1 test -p ai-env-cli --no-default-features --features shim --test shim_docker -- --ignored --test-threads=1"),
        s("cargo +1.98.1 test -p ai-env-cli --test docker_exec -- --ignored --test-threads=1"),
    ];
    // (the make arguments, the environment, a logging MAKE, the `cargo` and `make` calls in order; <bin> the fakes)
    type Case = (Vec<&'static str>, Vec<(String, String)>, bool, Vec<String>);
    // A39: the tier world seals the stack's passphrase, not set here, so deploy, preview and deploy-policies unseal it
    // under the covering runner (`ai-env run -f`, then X-run at once), after every compile; <t> the HOME of the run.
    let unseal = |x: &str| cli(&format!("run -f <t>/.config/ai-env/pulumi.env -- /bin/bash infra/scripts/pass-exec.sh {x} <t>/.config/ai-env/pulumi.env <bin>/fake-make --no-print-directory {x}-run")) + d;
    let mut cases: Vec<Case> = ["deploy", "preview", "deploy-policies"]
        .into_iter()
        .map(|x| (vec![x], deployer.clone(), true, vec![s("make --no-print-directory image-zip"), build.clone(), cli("as --check deployer") + d, unseal(x), format!("make --no-print-directory {x}-run{d} [PASS]")]))
        .collect();
    // A make typed under `ai-env run -f` of the sealed passphrase and the runner (README "Identities"): nothing unsealed
    // again; the zip and the build without the passphrase, the check and X-run with it.
    let passphrase = super::aws_keys::passphrase();
    let under_pass = [deployer.clone(), vec![(s("PULUMI_CONFIG_PASSPHRASE"), passphrase.clone())]].concat();
    let passed_deploy = vec![s("make --no-print-directory image-zip"), build.clone(), cli("as --check deployer") + d + " [PASS]", format!("make --no-print-directory deploy-run{d} [PASS]")];
    cases.push((vec!["deploy"], under_pass.clone(), true, passed_deploy.clone()));
    cases.extend([
        (vec!["test-egress"], deployer.clone(), true, vec![s("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run"), build.clone(), cli("as --check deployer") + d, format!("make --no-print-directory test-egress-run{d}")]),
        (vec!["runtime-key"], deployer.clone(), true, vec![build.clone(), cli("as --check deployer") + d, format!("make --no-print-directory runtime-key-run{d}")]),
        (vec!["image-status"], ops.clone(), true, vec![build.clone(), cli("as --check ops") + o, format!("make --no-print-directory image-status-run{o}")]),
        (vec!["allowlist-reload"], ops.clone(), false, vec![build.clone(), cli("egress reload") + o]),
        (vec!["proxy-start"], ops.clone(), false, vec![build.clone(), cli("proxy start") + o]),
        (vec!["infra-status", "WRITE=1"], ops.clone(), false, vec![build.clone(), cli("infra status --stack dev --write") + o]),
        (vec!["check-base-image"], ops.clone(), false, vec![build.clone(), cli("infra base-image --name al2023-1 --version 1") + o]),
        (vec!["gates"], ops.clone(), false, vec![s("cargo +1.98.1 build -q -p ai-env-cli --bin ai-env"), cli("gates") + o]),
        (vec!["s3-preflight", "PHASE=b"], deployer.clone(), false, vec![build.clone(), cli("creds aws-set --check") + d, cli("infra pin --check-bundle --lock image/claude.lock") + d, cli("infra base-image --name al2023-1 --version 1") + d]),
        // An X-run typed under the runner (here the deployer's key alone: a session token would fail its identity's sts
        // check), for real: it builds before it calls the CLI, and so does key-issue.
        (
            vec!["runtime-key-run"],
            super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL),
            false,
            vec![build.clone(), cli("creds aws-set --check") + d, build.clone(), cli("creds aws-set --user ai-env-runtime") + d, cli("creds aws-verify --user ai-env-runtime") + d],
        ),
        (
            vec!["deployer-key", "ROTATE=1", "BREAKGLASS=1"],
            root,
            true,
            vec![build.clone(), cli("as --check root") + " [KEY]", cli("as root -- <bin>/fake-make --no-print-directory deployer-key-run") + " [KEY]", s("make --no-print-directory deployer-key-run [AS=root] [KEY]")],
        ),
        // The live tests a runner may run (test-aws's help: the suspension's Touch IDs are the runner's then; the part-A
        // reads as ai-env as ops): their tests built first without the key, then run with it (D2); the probes' CLI
        // built first too.
        (
            vec!["test-aws", "PROBES=1"],
            deployer.clone(),
            false,
            [
                vec![s("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run"), s("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored --test-threads=1 --nocapture") + d, build.clone()],
                ["payload-size", "no-traffic-before-run", "snapshot-uniqueness", "idle-policy-limits"].iter().map(|p| cli(&format!("lab run {p}")) + d).collect(),
            ]
            .concat(),
        ),
        (
            vec!["test-aws-readonly"],
            ops.clone(),
            false,
            vec![s("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws --no-run"), s("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored readonly_ --test-threads=1 --nocapture") + o],
        ),
        // test-docker needs no AWS: nothing of it sees the key, alone or as the first goal of `ai-env as deployer --
        // make test-docker deploy` (plan §7's several goals under one ask; B0.3 in the root's terminal alike).
        (vec!["test-docker"], deployer.clone(), true, docker.clone()),
        (
            vec!["test-docker", "deploy"],
            deployer.clone(),
            true,
            [docker.clone(), vec![s("make --no-print-directory image-zip"), build.clone(), cli("as --check deployer") + d, unseal("deploy"), format!("make --no-print-directory deploy-run{d} [PASS]")]].concat(),
        ),
        // The same under the passphrase too: test-docker's steps never carry it either.
        (vec!["test-docker", "deploy"], under_pass, true, [docker, passed_deploy].concat()),
    ]);
    let runs: Vec<(tempfile::TempDir, PathBuf, Output)> = std::thread::scope(|sc| {
        let handles: Vec<_> = cases
            .iter()
            .map(|(args, envs, fake_make, _)| {
                sc.spawn(move || {
                    let tmp = tempfile::tempdir().unwrap();
                    let t = tmp.path();
                    let bin = tier_world(t);
                    script(&bin.join("cargo"), CARGO_RUN);
                    // P3 and P5 of s3-preflight: no daemon, no network.
                    bin_with(t, &[("docker.sh", "docker"), ("curl.sh", "curl")]);
                    // The zip test-docker stamps (its image targets are the logging MAKE's).
                    std::fs::create_dir_all(t.join("out")).unwrap();
                    std::fs::write(t.join("out/image.zip"), "a zip").unwrap();
                    let mut cmd = make(t, &bin, args);
                    s5_env(&mut cmd, t).arg(format!("IMAGE_OUT={}", t.join("out").display()));
                    if *fake_make {
                        cmd.arg(format!("MAKE={}", bin.join("fake-make").display()));
                    }
                    let out = cmd.envs(pairs(envs)).bounded();
                    (tmp, bin, out)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for ((args, _, _, want), (tmp, bin, out)) in cases.iter().zip(&runs) {
        let what = args.join(" ");
        let c: Vec<String> = calls(tmp.path()).into_iter().filter(|l| l.starts_with("cargo ") || l.starts_with("make ")).map(|l| l.replace(&bin.display().to_string(), "<bin>").replace(&tmp.path().display().to_string(), "<t>")).collect();
        assert_eq!(&c, want, "{what}: the compiles first, with no key, no secret, no session token, no marker and no passphrase: {}", all(out));
        if what != "s3-preflight PHASE=b" {
            assert!(out.status.success(), "{what}: {}", all(out));
        }
        assert!(!all(out).contains(&passphrase) && !read(&tmp.path().join("calls.log")).contains(&passphrase), "{what}: the passphrase's value shown");
    }

    // ops.sh's own calls of the CLI (key-issue, post-deploy, connector-probe, claude-update: need_ai_env): the CLI
    // built without the key first.
    let (t, bin) = rk_tree(0);
    script(&bin.join("cargo"), CARGO_RUN);
    let ai_env = format!("{} +1.98.1 run -q -p ai-env-cli --bin ai-env --", bin.join("cargo").display());
    let mut envs = pairs(&deployer);
    envs.push(("AI_ENV_CLI", ai_env.as_str()));
    let out = runtime_key(t.path(), &bin, &envs);
    assert!(out.status.success(), "{}", all(&out));
    let c: Vec<String> = lines_of(&t.path().join("ai-env.log")).into_iter().filter(|l| l.starts_with("cargo ")).collect();
    assert_eq!(c, [build, cli("creds aws-set --user ai-env-runtime") + d, cli("creds aws-verify --user ai-env-runtime") + d], "{}", all(&out));
    assert_secret_never_shown(t.path(), &out);
}

/// make -i would ignore a refused identity, a missing CONFIRM or BREAKGLASS, and run the steps after it (as the account
/// root, or this shell's own credentials): every tiered target refuses it, and so does its X-run typed by hand, before
/// anything runs (a $(error) make expands with the whole recipe), however make got the -i (the switch, an outer make's
/// MAKEFLAGS). Nothing runs: no build, no runner, no tool.
#[test]
fn make_i_is_refused_by_every_tiered_target_and_its_run_before_anything_runs() {
    let cases = tiered_runs();
    std::thread::scope(|sc| {
        for (target, _, args) in &cases {
            let target: &str = target;
            sc.spawn(move || {
                let tmp = tempfile::tempdir().unwrap();
                let t = tmp.path();
                let bin = tier_world(t);
                let refusal = if target == "acceptance" {
                    "*** acceptance: not under make -i (a failed step would be ignored: the next ones would run and the last line say ok): run make acceptance without it.".to_string()
                } else {
                    format!("*** {target}: not under make -i (a refused identity, or a missing CONFIRM or BREAKGLASS, would be ignored and the steps after it run): run make {target} without it.")
                };
                let run = format!("{target}-run");
                // (what, the goal, make's own flags, the environment)
                type Form<'a> = (&'a str, &'a str, &'a [&'a str], &'a [(&'a str, &'a str)]);
                let forms: [Form; 4] = [
                    ("-i", target, &["-i"], &[]),
                    ("an outer make's i", target, &[], &[("MAKEFLAGS", "i")]),
                    ("-i, X-run by hand", run.as_str(), &["-i"], &[]),
                    ("-i, X-run under the deployer's runner", run.as_str(), &["-i"], &[("AI_ENV_BRIDGE_AS", "deployer:9001")]),
                ];
                for (what, goal, flags, envs) in forms {
                    std::fs::remove_file(t.join("calls.log")).ok();
                    let argv: Vec<&str> = flags.iter().copied().chain([goal]).chain(args.iter().copied()).collect();
                    let out = tier_make(t, &bin, &argv, false, envs);
                    let text = all(&out);
                    assert_eq!(out.status.code(), Some(2), "{target} {what}: {text}");
                    assert!(stderr(&out).contains(&refusal), "{target} {what}: {text}");
                    assert_eq!(calls(t), Vec::<String>::new(), "{target} {what}: something ran: {text}");
                }
            });
        }
    });
}

/// make -p prints its data base when it ends, every variable with its value, the environment's among them, and
/// MAKEFLAGS hands the -p to every sub-make: X-run's, under the runner, would print the operator key and its secret, and
/// so would every make nested under it (D1). Every tiered target refuses -p as it refuses -i, before its build, its
/// runner or anything else runs, however make got it (the switch, beside -n or -s, an outer make's MAKEFLAGS), and so
/// does its X-run typed by hand. The real make runs X-run here: a runner that started would leave the stand-in's key
/// in the data base, and an unseal the stack's passphrase (A39: the tier world seals it; the refusal comes before the
/// unseal). (A make typed under a runner holds the key itself, and prints it under -p whatever its makefile says: never
/// -p there.)
#[test]
fn make_p_is_refused_by_every_tiered_target_and_its_run_before_any_key_is_there_to_print() {
    // The stand-in runner's secret and its two key ids (tests/fakes/ai-env.sh), and the passphrase its unseal would set.
    let secret = "Dm7/".repeat(10);
    let ids = [super::aws_keys::key_id(super::aws_keys::DEPLOYER_TAIL), super::aws_keys::key_id(super::aws_keys::OPS_TAIL)];
    let passphrase = super::aws_keys::passphrase();
    let cases = tiered_runs();
    std::thread::scope(|sc| {
        for (target, _, args) in &cases {
            let (target, secret, ids, passphrase): (&str, &str, &[String; 2], &str) = (target, &secret, &ids, &passphrase);
            sc.spawn(move || {
                let tmp = tempfile::tempdir().unwrap();
                let t = tmp.path();
                let bin = tier_world(t);
                let refusal = format!("*** {target}: not under make -p (it prints every variable when it ends, the environment's too: under the runner, the operator key and its secret, and the stack's passphrase once unsealed): run make {target} without it.");
                let run = format!("{target}-run");
                // (what, the goal, make's own flags, the environment)
                type Form<'a> = (&'a str, &'a str, &'a [&'a str], &'a [(&'a str, &'a str)]);
                let forms: [Form; 5] = [
                    ("-p", target, &["-p"], &[]),
                    ("--print-data-base", target, &["--print-data-base"], &[]),
                    ("-p beside -n", target, &["-np"], &[]),
                    ("an outer make's p", target, &[], &[("MAKEFLAGS", "p")]),
                    ("-p, X-run by hand", run.as_str(), &["-p"], &[]),
                ];
                for (what, goal, flags, envs) in forms {
                    std::fs::remove_file(t.join("calls.log")).ok();
                    let argv: Vec<&str> = flags.iter().copied().chain([goal]).chain(args.iter().copied()).collect();
                    let out = tier_make(t, &bin, &argv, false, envs);
                    let text = all(&out);
                    assert!(!text.contains(secret) && ids.iter().all(|id| !text.contains(id.as_str())), "{target} {what}: a key in make's data base");
                    assert!(!text.contains(passphrase), "{target} {what}: the passphrase in make's data base");
                    assert_eq!(out.status.code(), Some(2), "{target} {what}: {}", stderr(&out));
                    assert!(stderr(&out).contains(&refusal), "{target} {what}: {}", stderr(&out));
                    assert_eq!(calls(t), Vec::<String>::new(), "{target} {what}: something ran: {}", stderr(&out));
                }
            });
        }
    });
}

/// AI_ENV_PASTE_STDIN=1 (a test session's leftover) never reaches a runner: the make targets' operator CLI is a debug
/// build (cargo run), whose `ai-env as deployer` would read the key from a stdin that is not a terminal (D11). TIER's
/// two runner calls drop it (its keyless build, which reads no paste, shows it reached make), and so does ops.sh for
/// every command, claude-update's runner among them. A39: so does the passphrase's unseal, and the runner under it.
#[test]
fn the_debug_paste_knob_never_reaches_a_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["runtime-key"], true, &[("AI_ENV_PASTE_STDIN", "1")]);
    assert!(out.status.success(), "{}", all(&out));
    let c = calls(t);
    assert_eq!(c.iter().filter(|l| l.starts_with("--version ")).collect::<Vec<_>>(), ["--version [AI_ENV=unset] [PASTE=1]"], "the knob reached make: {c:#?}");
    let runner: Vec<&String> = c.iter().filter(|l| l.starts_with("as ")).collect();
    assert_eq!(runner.len(), 2, "{c:#?}");
    assert!(runner.iter().all(|l| !l.contains("[PASTE")), "the knob reached the runner: {runner:#?}");

    // preview unseals the sealed passphrase before its runner: neither has the knob.
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["preview"], true, &[("AI_ENV_PASTE_STDIN", "1")]);
    assert!(out.status.success(), "{}", all(&out));
    let c = calls(t);
    assert_eq!(c.iter().filter(|l| l.starts_with("--version ")).collect::<Vec<_>>(), ["--version [AI_ENV=unset] [PASTE=1]"], "the knob reached make: {c:#?}");
    let runner: Vec<&String> = c.iter().filter(|l| l.starts_with("run -f ") || l.starts_with("as ")).collect();
    assert!(runner.len() == 3 && runner[1].starts_with("run -f ") && runner[2].starts_with("as deployer -- "), "the check, the unseal, the runner: {c:#?}");
    assert!(runner.iter().all(|l| !l.contains("[PASTE")), "the knob reached the unseal or the runner: {runner:#?}");

    // claude-update, nothing to deploy: every call of the operator CLI, its runner's included, is without it.
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = s5_bin(t);
    script(&bin.join("make"), "exit 0");
    std::fs::create_dir_all(t.join("image")).unwrap();
    std::fs::write(t.join("image/claude.lock"), "CLAUDE_VERSION=2.1.287\n").unwrap();
    let mut o = with_operators(outputs());
    o["claudeVersion"] = json!("2.1.287");
    write_outputs(t, &o);
    let _ = ops5(t, &bin, &["claude-update"]).current_dir(t).env("LOCK", "image/claude.lock").env("FAKE_AIENV_BUNDLE", "2.1.287").env("AI_ENV_PASTE_STDIN", "1").bounded();
    let c = calls(t);
    assert!(c.iter().any(|l| l.starts_with("as ops -- ")), "{c:#?}");
    assert!(c.iter().filter(|l| l.contains("[AI_ENV=")).all(|l| !l.contains("[PASTE")), "the knob reached the operator CLI: {c:#?}");
}

/// make claude-update is never break-glass: BREAKGLASS=1 on its make command line, which MAKEFLAGS would hand to its
/// nested make deploy (TIER then asks for ai-env as root under the deployer's runner, refused after the paste), stops
/// it before ops.sh runs, exit 2 (D15); exported in the environment it counts for nothing, as everywhere.
#[test]
fn claude_update_refuses_breakglass_on_its_command_line_before_anything_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["claude-update", "BREAKGLASS=1"], false, &[]);
    let text = all(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("claude-update: never break-glass (BREAKGLASS=1 is on the make command line): as the account root, run make deploy BREAKGLASS=1, then the remaining steps by hand (README \"Break-glass\"): nothing changed"), "{text}");
    assert_eq!(calls(t), Vec::<String>::new(), "nothing ran: {text}");
    // Exported, it is no refusal: ops.sh runs (and stops here at the Cursor bundle it cannot read).
    let out = tier_make(t, &bin, &["claude-update"], false, &[("BREAKGLASS", "1")]);
    let text = all(&out);
    assert!(!text.contains("never break-glass") && text.contains("claude-update: cannot read the Cursor bundle's version"), "{text}");
}

// ---- A39: the stack's sealed passphrase, unsealed by make (plans/s8-operators-contracts.md A39) ----

/// make deploy in a terminal that holds neither passphrase variable unseals the stack's sealed passphrase itself: one
/// `ai-env run -f` of make's default file (under HOME), said on stderr first, after the zip's build (its scan and
/// version read) and TIER's keyless build, after `as --check` and the stack-deployer read, and right before the
/// deployer's runner: the Touch ID before the paste. Nothing before it holds the passphrase; the runner, X-run and
/// Pulumi's preview and up do. Its value is never in the output, a fake's log or a file of the tree. A dismissed Touch
/// ID, or a file that is no container (still plaintext), stops it there: no paste, nothing of X-run; a sealed value
/// left empty (or none) stops right after the unseal (pass-exec.sh), before the paste, naming ai-env edit; a cancelled
/// paste stops after the unseal.
#[test]
fn deploy_unseals_the_stack_passphrase_once_after_the_build_and_before_the_paste() {
    let passphrase = super::aws_keys::passphrase();
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let sealed = sealed_path(d.t.path()).display().to_string();
    let out = d.deploy(&deploy_plan(&[]), &[]);
    let text = all(&out);
    assert!(out.status.success(), "{text}");
    let c = calls(d.t.path());
    let x_run = format!("{} --no-print-directory deploy-run", make_path());
    let unsealed = format!("run -f {sealed} -- /bin/bash infra/scripts/pass-exec.sh deploy {sealed} {} as deployer -- {x_run} [AI_ENV=unset]", d.bin.join("ai-env-stand-in").display());
    assert_eq!(c.iter().filter(|l| l.starts_with("run ")).collect::<Vec<_>>(), [&unsealed], "one unseal: {c:#?}");
    let u = at(&c, &unsealed);
    assert_eq!(c[u + 1], format!("as deployer -- {x_run} [AI_ENV=unset] [PASS]"), "the runner (its paste) right after the unseal (its Touch ID): {c:#?}");
    let (scan, checked, outputs_read) = (at(&c, "infra scan "), at(&c, "as --check deployer"), at(&c, "pulumi stack output --json"));
    assert!(scan < checked && checked < outputs_read && outputs_read < u, "after the zip's build, the check and the stack-deployer read: {c:#?}");
    assert_eq!(c[..u].iter().filter(|l| *l == BUILT).count(), 2, "the zip's version read and TIER's keyless build before it: {c:#?}");
    assert!(c[..u].iter().all(|l| !l.contains("[PASS]")), "nothing before the unseal holds the passphrase: {c:#?}");
    for pulumi in ["pulumi preview --json --show-sames --show-reads --non-interactive --stack dev [PASS]", "pulumi up --stack dev [PASS]"] {
        assert!(c.iter().any(|l| l == pulumi), "{pulumi}: {c:#?}");
    }
    let note = format!("deploy: the dev stack's passphrase: ai-env run -f {sealed} (one Touch ID)");
    assert_eq!(stderr(&out).matches(&note).count(), 1, "said once: {text}");
    // The value nowhere: the output, the fakes' logs, any file of the tree.
    assert!(!text.contains(&passphrase), "the passphrase in the output");
    for log in ["calls.log", "tools.log"] {
        assert!(!read(&d.t.path().join(log)).contains(&passphrase), "the passphrase in {log}");
    }
    for f in d.files() {
        assert!(!String::from_utf8_lossy(&std::fs::read(&f).unwrap()).contains(&passphrase), "{} holds the passphrase", f.display());
    }

    // A dismissed Touch ID: ai-env run's own exit, nothing after it (no paste, nothing of X-run).
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_AIENV_RUN", "cancel")]);
    let text = all(&out);
    let c = calls(d.t.path());
    assert!(!out.status.success() && text.contains("ai-env: cancelled") && text.contains("make: *** [deploy] Error 3"), "{text}");
    assert!(c.last().is_some_and(|l| l.starts_with("run -f ")) && !c.iter().any(|l| l.starts_with("as deployer -- ") || l.starts_with("check-policies")), "nothing after the unseal: {c:#?}");

    // A file that is no container (the README's first line, never encrypted): ai-env run's plaintext refusal, exit 6.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    std::fs::write(sealed_path(d.t.path()), "PULUMI_CONFIG_PASSPHRASE=\n").unwrap();
    let out = d.deploy(&deploy_plan(&[]), &[]);
    let text = all(&out);
    let c = calls(d.t.path());
    let plaintext = format!("ai-env: {} is not an ai-env encrypted file (no AI_ENV=1 marker) — is it still plaintext?", sealed_path(d.t.path()).display());
    assert!(!out.status.success() && text.contains(&plaintext) && text.contains("make: *** [deploy] Error 6"), "{text}");
    assert!(c.last().is_some_and(|l| l.starts_with("run -f ")) && !c.iter().any(|l| l.starts_with("as deployer -- ")), "no paste: {c:#?}");

    // The sealed value empty (the README's first line without ai-env edit), or none: stopped right after the Touch ID,
    // before the paste, naming ai-env edit.
    for kind in ["empty", "none"] {
        let d = DeployTree::new(CHECK_PLAN_FAKE);
        let sealed = seal_passphrase(&sealed_path(d.t.path()), kind).display().to_string();
        let out = d.deploy(&deploy_plan(&[]), &[]);
        let text = all(&out);
        let c = calls(d.t.path());
        let stopped = format!("deploy: the passphrase sealed in {sealed} is empty, or not there (PULUMI_CONFIG_PASSPHRASE= has no value until ai-env edit sets one): set it with ai-env edit \"{sealed}\" (README \"Identities\"), then make deploy again: nothing ran against the stack");
        assert!(!out.status.success() && text.contains(&stopped) && text.contains("make: *** [deploy] Error 1"), "{kind}: {text}");
        assert!(c.last().is_some_and(|l| l.starts_with("run -f ")) && !c.iter().any(|l| l.starts_with("as deployer -- ")), "{kind}: no paste: {c:#?}");
    }

    // A cancelled paste after the unseal: the unseal, the paste, then nothing.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_AIENV_AS", "cancel")]);
    let text = all(&out);
    let c = calls(d.t.path());
    assert!(!out.status.success() && text.contains("ai-env: as deployer: nothing was pasted: cancelled, nothing was run"), "{text}");
    assert!(c.len() >= 2 && c[c.len() - 2].starts_with("run -f ") && c[c.len() - 1].starts_with("as deployer -- "), "the unseal, the paste, then nothing: {c:#?}");
}

/// pass-exec.sh, TIER's guard between the unseal and the runner (A39), decides as Pulumi takes the passphrase: CMD runs
/// under a PULUMI_CONFIG_PASSPHRASE that is set and not empty, or, with none set at all, under a
/// PULUMI_CONFIG_PASSPHRASE_FILE that is (a sealed file may hold either); an empty PULUMI_CONFIG_PASSPHRASE stops it
/// whatever the file (Pulumi takes the empty one first), and so does neither: exit 1 before CMD, naming ai-env edit of
/// the sealed file, never a value. Fewer than three arguments: usage, exit 2.
#[test]
fn pass_exec_runs_its_command_only_under_a_passphrase_pulumi_takes() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let passphrase = super::aws_keys::passphrase();
    let ran = t.join("ran");
    let pass_exec = |args: &[&str], envs: &[(&str, &str)]| {
        let mut cmd = Command::new("/bin/bash");
        isolate(&mut cmd, t).env("PATH", "/usr/bin:/bin");
        cmd.arg(Path::new(REPO).join("infra/scripts/pass-exec.sh")).args(args).envs(envs.iter().copied()).bounded()
    };
    let stopped = "deploy: the passphrase sealed in /sealed/pulumi.env is empty, or not there (PULUMI_CONFIG_PASSPHRASE= has no value until ai-env edit sets one): set it with ai-env edit \"/sealed/pulumi.env\" (README \"Identities\"), then make deploy again: nothing ran against the stack\n";
    // (what, the environment, CMD runs)
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, bool);
    let cases: [Case; 7] = [
        ("the passphrase", vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())], true),
        ("the passphrase beside its file", vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str()), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")], true),
        ("its file alone (a sealed PULUMI_CONFIG_PASSPHRASE_FILE)", vec![("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")], true),
        ("an empty passphrase (the README's first line before ai-env edit)", vec![("PULUMI_CONFIG_PASSPHRASE", "")], false),
        ("an empty passphrase beside its file", vec![("PULUMI_CONFIG_PASSPHRASE", ""), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")], false),
        ("an empty file", vec![("PULUMI_CONFIG_PASSPHRASE_FILE", "")], false),
        ("neither", vec![], false),
    ];
    for (what, envs, runs) in cases {
        std::fs::remove_file(&ran).ok();
        let out = pass_exec(&["deploy", "/sealed/pulumi.env", "touch", ran.to_str().unwrap()], &envs);
        let text = all(&out).replace(&passphrase, "<the passphrase>");
        assert!(!text.contains("<the passphrase>"), "{what}: the value shown");
        assert_eq!((out.status.code(), ran.exists(), stderr(&out).as_str()), (Some(if runs { 0 } else { 1 }), runs, if runs { "" } else { stopped }), "{what}: {text}");
    }
    let out = pass_exec(&["deploy", "/sealed/pulumi.env"], &[("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())]);
    assert_eq!((out.status.code(), stderr(&out).as_str()), (Some(2), "usage: pass-exec.sh LABEL FILE CMD...\n"), "usage");
}

/// Without a sealed passphrase and with the passphrase not set as Pulumi takes it (neither variable, an empty one, or
/// an empty PULUMI_CONFIG_PASSPHRASE beside its file: Pulumi takes the empty one first), deploy and deploy-policies,
/// whose plan check runs `pulumi preview --non-interactive` and cannot prompt, refuse as their first line, before the
/// build and anything else, naming the file make looks for, the README's two setup lines and the export.
/// PULUMI_SEALED, on the command line or exported, names another file, a leading `~/` HOME's (zsh passes it on as it
/// is): refused the same way while it is absent, or a directory (which TIER would not unseal either), unsealed once it
/// is there. preview and destroy go on to Pulumi, which asks on the terminal (the fake, which has none, says the
/// passphrase must be set).
#[test]
fn the_passphrase_targets_refuse_without_a_sealed_file_before_anything_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    std::fs::remove_file(sealed_path(t)).unwrap();
    let refusal = |x: &str, f: &Path| {
        let f = f.display();
        format!("{x}: the dev stack's passphrase: neither PULUMI_CONFIG_PASSPHRASE nor PULUMI_CONFIG_PASSPHRASE_FILE is set (Pulumi takes PULUMI_CONFIG_PASSPHRASE first, even empty, and an empty one counts as none), and there is no sealed {f} to unseal (the plan check runs pulumi preview --non-interactive): seal it once (README \"Identities\"): printf 'PULUMI_CONFIG_PASSPHRASE=\\n' | ai-env encrypt -k ai-env-bridge - > \"{f}\", then ai-env edit \"{f}\"; or export PULUMI_CONFIG_PASSPHRASE_FILE (a file holding it): nothing ran")
    };
    let other = t.join("other.env");
    let on_line = format!("PULUMI_SEALED={}", other.display());
    let dir = t.join("sealed.d");
    std::fs::create_dir_all(&dir).unwrap();
    // (the make arguments, the environment, the file the refusal names)
    type Refused<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>, PathBuf);
    for x in ["deploy", "deploy-policies"] {
        let cases: [Refused; 7] = [
            (vec![x], vec![], sealed_path(t)),
            (vec![x], vec![("PULUMI_CONFIG_PASSPHRASE", "")], sealed_path(t)),
            (vec![x], vec![("PULUMI_CONFIG_PASSPHRASE", ""), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")], sealed_path(t)),
            (vec![x, on_line.as_str()], vec![], other.clone()),
            (vec![x], vec![("PULUMI_SEALED", other.to_str().unwrap())], other.clone()),
            (vec![x, "PULUMI_SEALED=~/other.env"], vec![], other.clone()),
            (vec![x], vec![("PULUMI_SEALED", dir.to_str().unwrap())], dir.clone()),
        ];
        for (args, envs, file) in cases {
            std::fs::remove_file(t.join("calls.log")).ok();
            let out = tier_make(t, &bin, &args, true, &envs);
            let text = all(&out);
            assert_eq!(out.status.code(), Some(2), "{args:?} {envs:?}: {text}");
            assert!(stdout(&out).contains(&refusal(x, &file)) && stderr(&out).contains(&format!("[{x}] Error 1")), "{args:?} {envs:?}: {text}");
            assert_eq!(calls(t), Vec::<String>::new(), "{args:?} {envs:?}: something ran");
        }
    }
    // PULUMI_SEALED's file, once there, is the one unsealed (from the command line and from the environment alike), and
    // the one make -n shows.
    seal_passphrase(&other, "");
    for (args, envs) in [(vec!["deploy", on_line.as_str()], vec![]), (vec!["deploy"], vec![("PULUMI_SEALED", other.to_str().unwrap())]), (vec!["deploy", "PULUMI_SEALED=~/other.env"], vec![])] {
        std::fs::remove_file(t.join("calls.log")).ok();
        let out = tier_make(t, &bin, &args, true, &envs);
        assert!(out.status.success(), "{args:?} {envs:?}: {}", all(&out));
        let c = calls(t);
        let unseal = format!("run -f {} -- /bin/bash infra/scripts/pass-exec.sh deploy {} ", other.display(), other.display());
        assert!(c.iter().filter(|l| l.starts_with("run -f ")).count() == 1 && c.iter().any(|l| l.starts_with(&unseal)), "{args:?} {envs:?}: {c:#?}");
        assert!(c.contains(&"make --no-print-directory deploy-run [AS=deployer:9001] [KEY] [PASS]".to_string()), "{args:?} {envs:?}: {c:#?}");
        let dry = tier_make(t, &bin, &[&["-n"][..], &args[..]].concat(), false, &envs);
        assert!(stdout(&dry).contains(&format!(" run -f \"{}\" -- ", other.display())), "{args:?} {envs:?}: make -n shows that unseal: {}", all(&dry));
    }

    // preview and destroy keep Pulumi's own prompt: nothing unsealed, Pulumi asked (here with no terminal to ask on).
    let must = "error: getting stack configuration: get stack secrets manager: passphrase must be set with PULUMI_CONFIG_PASSPHRASE or PULUMI_CONFIG_PASSPHRASE_FILE environment variables";
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    std::fs::remove_file(sealed_path(d.t.path())).unwrap();
    let out = d.run("preview", &deploy_plan(&[]), &[]);
    let text = all(&out);
    let c = calls(d.t.path());
    assert!(!out.status.success() && text.contains(must), "{text}");
    assert!(c.contains(&"pulumi preview --diff --stack dev".to_string()) && !c.iter().any(|l| l.starts_with("run -f ")), "{c:#?}");
    seed_connector(t, CONNECTOR, "ACTIVE");
    std::fs::remove_file(t.join("calls.log")).ok();
    let out = tier_make(t, &bin, &["destroy", "CONFIRM=destroy-dev", "BREAKGLASS=1"], false, &[("FAKE_AWS_CALLER", "root"), ("FAKE_PULUMI_ALLOW", "destroy")]);
    let text = all(&out);
    let c = calls(t);
    assert!(!out.status.success() && text.contains(must), "{text}");
    assert!(c.contains(&"pulumi destroy --stack dev".to_string()) && !c.iter().any(|l| l.starts_with("run -f ")), "{c:#?}");
}

/// A passphrase already in the environment is never unsealed again: its file or the variable itself exported (a make
/// typed under `ai-env run -f`), or a make nested in a run that holds it; nothing is asked for it and nothing said, the
/// runner and X-run run under it, the zip and the build never. Under the deployer's runner as well, X-run runs at
/// once. The same without any sealed file: deploy's first line (PASS_CHECK) lets a passphrase that is set through. An
/// X-run typed by hand never unseals, the sealed file there or not: without the passphrase its plan check fails, naming
/// where it comes from. An empty PULUMI_CONFIG_PASSPHRASE beside its file is none, as Pulumi takes them (the empty one
/// first): unsealed.
#[test]
fn a_passphrase_already_in_the_environment_is_never_unsealed_again() {
    let passphrase = super::aws_keys::passphrase();
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    // (what, the environment, under the deployer's runner)
    type Set<'a> = (&'a str, Vec<(&'a str, &'a str)>, bool);
    let cases: [Set; 3] = [
        ("the file exported", vec![("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")], false),
        ("the passphrase exported", vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())], false),
        ("the passphrase under the deployer's runner", [pairs(&deployer), vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())]].concat(), true),
    ];
    for (what, envs, under) in cases {
        for sealed in [true, false] {
            let what = if sealed { what.to_string() } else { format!("{what}, no sealed file") };
            let tmp = tempfile::tempdir().unwrap();
            let t = tmp.path();
            let bin = tier_world(t);
            if !sealed {
                std::fs::remove_file(sealed_path(t)).unwrap();
            }
            let out = tier_make(t, &bin, &["deploy"], true, &envs);
            let text = all(&out);
            assert!(out.status.success(), "{what}: {text}");
            let c = calls(t);
            assert!(!c.iter().any(|l| l.starts_with("run -f ")) && !text.contains("stack's passphrase"), "{what}: nothing unsealed, nothing said: {c:#?}");
            let runner = format!("as deployer -- {} --no-print-directory deploy-run [AI_ENV=unset] [PASS]", bin.join("fake-make").display());
            assert_eq!(c.contains(&runner), !under, "{what}: the runner under the passphrase, unless one covers the tier: {c:#?}");
            assert!(c.contains(&"make --no-print-directory deploy-run [AS=deployer:9001] [KEY] [PASS]".to_string()), "{what}: X-run under it: {c:#?}");
            assert!(c.contains(&"make --no-print-directory image-zip".to_string()) && c.iter().filter(|l| l.starts_with("--version ")).all(|l| !l.contains("[PASS]")), "{what}: the zip and the build without it: {c:#?}");
            assert!(!text.contains(&passphrase) && c.iter().all(|l| !l.contains(&passphrase)), "{what}: the value shown");
        }
    }
    // An empty PULUMI_CONFIG_PASSPHRASE beside its file: Pulumi would take the empty one, so the sealed one is unsealed.
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let out = tier_make(t, &bin, &["deploy"], true, &[("PULUMI_CONFIG_PASSPHRASE", ""), ("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")]);
    assert!(out.status.success(), "{}", all(&out));
    let c = calls(t);
    let unseal = format!("run -f {} -- /bin/bash infra/scripts/pass-exec.sh deploy ", sealed_path(t).display());
    assert!(c.iter().filter(|l| l.starts_with("run -f ")).count() == 1 && c.iter().any(|l| l.starts_with(&unseal)), "an empty passphrase beside its file: unsealed: {c:#?}");
    assert!(c.contains(&"make --no-print-directory deploy-run [AS=deployer:9001] [KEY] [PASS]".to_string()), "{c:#?}");
    // deploy-run typed by hand under the deployer's runner never unseals: its plan check fails without the passphrase.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.run("deploy-run", &deploy_plan(&[]), &pairs(&deployer));
    let text = all(&out);
    let c = calls(d.t.path());
    assert!(!out.status.success() && text.contains("passphrase must be set with PULUMI_CONFIG_PASSPHRASE or PULUMI_CONFIG_PASSPHRASE_FILE"), "{text}");
    assert!(text.contains("which make deploy unseals unless PULUMI_CONFIG_PASSPHRASE or PULUMI_CONFIG_PASSPHRASE_FILE is set"), "{text}");
    assert!(!c.iter().any(|l| l.starts_with("run -f ") || l.starts_with("as ") || l.starts_with("pulumi up")), "never unsealed, nothing deployed: {c:#?}");
}

/// BREAKGLASS=1 typed under a runner (A39, TIER's root tier): under `ai-env as root`, which covers the root tier, the
/// four passphrase targets unseal the stack's passphrase right after `ai-env as --check root`, then run X-run at once as
/// the root, under it, with no second runner; under another runner's marker `ai-env as root` refuses before it asks
/// anything (it starts only from a terminal of its own), so nothing is unsealed for that refusal: no Touch ID spent.
#[test]
fn breakglass_under_a_runner_unseals_only_where_the_root_runs() {
    let root = super::aws_keys::marker_env("root");
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    for target in ["deploy", "preview", "deploy-policies", "destroy"] {
        let argv: Vec<&str> = if target == "destroy" { vec![target, "CONFIRM=destroy-dev", "BREAKGLASS=1"] } else { vec![target, "BREAKGLASS=1"] };
        let zip: Vec<String> = if target == "destroy" { vec![] } else { vec!["make --no-print-directory image-zip".to_string()] };
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = tier_world(t);
        let fake_make = bin.join("fake-make");
        let out = tier_make(t, &bin, &argv, true, &pairs(&root));
        assert!(out.status.success(), "{target}, under the root's runner: {}", all(&out));
        let sealed = sealed_path(t).display().to_string();
        let ran = [
            BUILT.to_string(),
            "as --check root [AI_ENV=unset] [AS=root]".to_string(),
            format!("run -f {sealed} -- /bin/bash infra/scripts/pass-exec.sh {target} {sealed} {} --no-print-directory {target}-run [AI_ENV=unset] [AS=root]", fake_make.display()),
            format!("make --no-print-directory {target}-run [AS=root] [PASS]"),
        ];
        assert_eq!(calls(t), [zip.clone(), ran.to_vec()].concat(), "{target}, under the root's runner: the unseal, then X-run at once: {}", all(&out));

        std::fs::remove_file(t.join("calls.log")).ok();
        let out = tier_make(t, &bin, &argv, true, &pairs(&deployer));
        let text = all(&out);
        assert_eq!(out.status.code(), Some(2), "{target}, under the deployer's runner: {text}");
        assert!(text.contains("ai-env: as root: already inside ai-env as deployer (AI_ENV_BRIDGE_AS): start it from a terminal of its own") && !text.contains("stack's passphrase"), "{target}: {text}");
        let refused = [
            BUILT.to_string(),
            "as --check root [AI_ENV=unset] [AS=deployer:9001]".to_string(),
            format!("as root -- {} --no-print-directory {target}-run [AI_ENV=unset] [AS=deployer:9001]", fake_make.display()),
        ];
        assert_eq!(calls(t), [zip, refused.to_vec()].concat(), "{target}, under the deployer's runner: refused, nothing unsealed: {text}");
    }
}

/// A39 (D17): the stack's passphrase never reaches a command line make writes, whether make deploy unseals it or finds
/// it exported (as a make nested under claude-update's unseal does): no recipe shell's argv (make runs each recipe line
/// as `$(SHELL) -c LINE`, every sub-make's too, here through a logger of its arguments), and no output, while X-run's
/// Pulumi calls hold it.
#[test]
fn the_stack_passphrase_never_reaches_a_recipe_line() {
    let passphrase = super::aws_keys::passphrase();
    for (what, envs) in [("unsealed", vec![]), ("exported", vec![("PULUMI_CONFIG_PASSPHRASE", passphrase.as_str())])] {
        let d = DeployTree::new(CHECK_PLAN_FAKE);
        let argv = d.t.path().join("argv.log");
        let sh = d.t.path().join("argv-sh");
        script(&sh, &format!("printf '%s\\n' \"$*\" >> '{}'\nexec /bin/bash \"$@\"", argv.display()));
        let shell = format!("SHELL={}", sh.display());
        let out = d.run_with("deploy", &[shell.as_str()], &deploy_plan(&[]), &envs);
        let text = all(&out).replace(&passphrase, "<the passphrase>");
        assert!(out.status.success(), "{what}: {text}");
        let shells = read(&argv);
        assert!(shells.contains("pulumi preview --json") && shells.contains("pulumi up --stack dev"), "{what}: deploy's recipe lines through the logger: {} lines", shells.lines().count());
        assert!(!shells.contains(&passphrase), "{what}: the passphrase in a recipe shell's argv");
        assert!(!text.contains("<the passphrase>"), "{what}: the passphrase in make's output");
        let c = calls(d.t.path());
        assert!(c.iter().all(|l| !l.contains(&passphrase)), "{what}: the passphrase in a fake's log");
        assert!(c.contains(&"pulumi up --stack dev [PASS]".to_string()), "{what}: X-run's Pulumi holds it: {c:#?}");
    }
}

/// The passphrase itself on the make command line is refused before anything runs, whatever the goal: MAKEFLAGS would
/// hand it to every child of make, the builds among them. The refusal never shows the value. (make -p prints the
/// command line's variables whatever a makefile says: README says never so.) So is its file there: a sub-make started
/// under NO_KEY's `env -u` exports its command line's variables again, to the builds too (exported, NO_KEY keeps it
/// from them).
#[test]
fn the_passphrase_on_the_make_command_line_is_refused_before_anything_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let passphrase = super::aws_keys::passphrase();
    let arg = format!("PULUMI_CONFIG_PASSPHRASE={passphrase}");
    for goal in ["deploy", "preview", "image-status", "help"] {
        std::fs::remove_file(t.join("calls.log")).ok();
        let out = tier_make(t, &bin, &[goal, arg.as_str()], true, &[]);
        let text = all(&out).replace(&passphrase, "<the passphrase>");
        assert_eq!(out.status.code(), Some(2), "{goal}: {text}");
        assert!(text.contains("PULUMI_CONFIG_PASSPHRASE on the make command line: MAKEFLAGS would hand it to every child of make, the builds among them: drop it; the targets that need the passphrase unseal "), "{goal}: {text}");
        assert!(!text.contains("<the passphrase>"), "{goal}: the value shown: {text}");
        assert_eq!(calls(t), Vec::<String>::new(), "{goal}: something ran");
        let out = tier_make(t, &bin, &[goal, "PULUMI_CONFIG_PASSPHRASE_FILE=/dev/null"], true, &[]);
        let text = all(&out);
        assert_eq!(out.status.code(), Some(2), "{goal}: {text}");
        assert!(text.contains("PULUMI_CONFIG_PASSPHRASE_FILE on the make command line: MAKEFLAGS would hand it to every child of make, the builds among them, past NO_KEY: export it instead, or drop it and let the targets that need the passphrase unseal "), "{goal}: {text}");
        assert_eq!(calls(t), Vec::<String>::new(), "{goal}: something ran");
    }
}

/// The key targets through make, as Mike types them (contracts §9.8): TIER asks for the deployer (the stand-in's
/// runner); X-run's identity line, the CLI's sealing check (`creds aws-set --check`, ops-key's with `--user
/// ai-env-ops`), then key-issue with its target's label, user and mode. ROTATE=1 counts only on the command line: an
/// exported one rotates nothing, and deployer-key's wrapper refuses without it (exit 2, before anything runs).
/// deployer-key ROTATE=1 hands the new key over, then the running key deletes itself, the last call. An X-run typed
/// under the deployer's runner runs at once.
#[test]
fn the_key_targets_issue_through_make_as_the_deployer() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    std::fs::create_dir_all(t.join("aws")).unwrap();
    std::fs::write(t.join("aws/keys"), format!("{}\n", key_id(1))).unwrap();
    std::fs::write(t.join("aws/next"), "2\n").unwrap();
    let creds = t.join("bridge/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        std::fs::remove_file(t.join("calls.log")).ok();
        let out = tier_make(t, &bin, args, false, envs);
        assert_secret_never_shown(t, &out);
        (all(&out), out, calls(t))
    };
    let in_order = |what: &str, c: &[String], wants: &[String]| {
        let mut last = 0;
        for want in wants {
            last = c[last..].iter().position(|l| l == want).unwrap_or_else(|| panic!("{what}: {want} missing or out of order: {c:#?}")) + last;
        }
    };
    let as_deployer = |x: &str| format!("as deployer -- {} --no-print-directory {x}-run [AI_ENV=unset]", make_path());
    let d = "[AI_ENV=unset] [AS=deployer:9001]";

    // runtime-key ROTATE=1: the runner, the identity, the check, key-issue as the deployer; the old key deleted last.
    let (text, out, c) = run(&["runtime-key", "ROTATE=1"], &[]);
    assert!(out.status.success(), "{text}");
    for want in ["runtime-key: identity user/ai-env-deployer (the deployer of stack dev)", "[ok ] fake aws-set --check", &format!("runtime-key: the sealed key ...{} identifies as user/ai-env-runtime", &key_id(2)[16..]), &format!("runtime-key: rotated; deleted the old key {}", key_id(1))] {
        assert!(text.contains(want), "{want}: {text}");
    }
    in_order(
        "runtime-key",
        &c,
        &[BUILT.to_string(), as_deployer("runtime-key"), format!("creds aws-set --check {d}"), BUILT.to_string(), format!("creds aws-set --user ai-env-runtime {d}"), format!("creds aws-verify --user ai-env-runtime {d}"), format!("iam delete-access-key --user-name ai-env-runtime --access-key-id {} --region eu-central-1", key_id(1))],
    );
    assert_eq!(lines_of(&t.join("aws/keys")), vec![key_id(2)]);
    assert_eq!(read(&creds.join("aws.env")), format!("FAKE-SEALED {}\n", key_id(2)));

    // ops-key, the first: sealed into ops.env, its check names the user.
    let (text, out, c) = run(&["ops-key"], &[]);
    assert!(out.status.success() && text.contains("ops-key: identity user/ai-env-deployer (the deployer of stack dev)") && text.contains(&format!("ops-key: the sealed key ...{} identifies as user/ai-env-ops", &key_id(3)[16..])), "{text}");
    in_order("ops-key", &c, &[as_deployer("ops-key"), format!("creds aws-set --check --user ai-env-ops {d}"), format!("creds aws-set --user ai-env-ops {d}"), format!("creds aws-verify --user ai-env-ops {d}")]);
    assert_eq!(read(&creds.join("ops.env")), format!("FAKE-SEALED {}\n", key_id(3)));
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-ops")), vec![key_id(3)]);

    // ROTATE=1 only exported: refused before anything is created.
    let (text, out, c) = run(&["ops-key"], &[("ROTATE", "1")]);
    assert!(!out.status.success() && text.contains(&format!("ops-key: ai-env-ops already has a key ({}); ROTATE=1 seals a new one, then deletes it", key_id(3))), "{text}");
    assert!(!c.iter().any(|l| l.starts_with("iam create-access-key") || l.starts_with("iam delete-access-key")), "{c:#?}");
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-ops")), vec![key_id(3)]);

    // ops-key ROTATE=1 on the command line: rotated.
    let (text, out, _) = run(&["ops-key", "ROTATE=1"], &[]);
    assert!(out.status.success() && text.contains(&format!("ops-key: rotated; deleted the old key {}", key_id(3))), "{text}");
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-ops")), vec![key_id(4)]);
    assert_eq!(read(&creds.join("ops.env")), format!("FAKE-SEALED {}\n", key_id(4)));

    // ops-key-run typed under the deployer's runner: no runner asked, the same recipe. (The previous rotation's backup
    // goes first: the sealer names a backup by the second, and refuses one that exists.)
    for e in std::fs::read_dir(&creds).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".bak")) {
        std::fs::remove_file(e.path()).unwrap();
    }
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let (text, out, c) = run(&["ops-key-run", "ROTATE=1"], &pairs(&deployer));
    assert!(out.status.success() && text.contains("ops-key: identity user/ai-env-deployer (the deployer of stack dev)") && text.contains(&format!("ops-key: rotated; deleted the old key {}", key_id(4))), "{text}");
    assert!(!c.iter().any(|l| l.starts_with("as ")), "a covered X-run asks nothing: {c:#?}");
    assert_eq!(c[at(&c, &format!("creds aws-set --check --user ai-env-ops {d}")) - 1], BUILT, "X-run builds the CLI without the key before it calls it (D18): {c:#?}");
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-ops")), vec![key_id(5)]);

    // deployer-key without ROTATE=1 on the command line: exit 2 before anything runs.
    for envs in [&[][..], &[("ROTATE", "1")][..]] {
        let (text, out, c) = run(&["deployer-key"], envs);
        assert_eq!(out.status.code(), Some(2), "{envs:?}: {text}");
        assert!(text.contains("deployer-key: ROTATE=1 only (the first deployer key is make operator-keys's, as the account root, once)") && text.contains("[deployer-key] Error 2"), "{envs:?}: {text}");
        assert_eq!(c, Vec::<String>::new(), "{envs:?}: nothing ran");
    }

    // deployer-key ROTATE=1: the new key handed over and verified, then the running key (the runner's) deleted last.
    let running = super::aws_keys::key_id(super::aws_keys::DEPLOYER_TAIL);
    std::fs::write(t.join("aws/keys.ai-env-deployer"), format!("{running}\n")).unwrap();
    let (text, out, c) = run(&["deployer-key", "ROTATE=1"], &[]);
    assert!(out.status.success() && text.contains("deployer-key: identity user/ai-env-deployer (the deployer of stack dev)"), "{text}");
    assert!(text.contains(&format!("deployer-key: the key ...{} is in Strongbox and identifies as user/ai-env-deployer", &key_id(6)[16..])), "{text}");
    assert!(stdout(&out).ends_with(&format!("deployer-key: rotated; deleted the old key {running}\n")), "{text}");
    in_order("deployer-key", &c, &[as_deployer("deployer-key"), format!("creds deployer-key --account 123456789012 {d}")]);
    let delete = format!("iam delete-access-key --user-name ai-env-deployer --access-key-id {running} --region eu-central-1");
    assert_eq!(c.iter().rfind(|l| l.starts_with("iam ") || l.starts_with("sts ")), Some(&delete), "the running key deletes itself, the last call: {c:#?}");
    assert_eq!(lines_of(&t.join("aws/keys.ai-env-deployer")), vec![key_id(6)]);
}

/// The wrappers' prechecks that need no AWS stop before the runner asks (nothing pasted for a typo) and count only on
/// the command line: deployer-key's ROTATE=1 (exit 2), image-delete's CONFIRM, image-activate's and
/// image-deactivate's VERSION (exit 2). The X-runs that delete or create something check their CONFIRM again, so one
/// typed by hand under the deployer's runner runs nothing either, not even its identity line.
#[test]
fn the_wrapper_prechecks_and_the_run_rechecks_stop_before_anything_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let bin = tier_world(t);
    let deployer = super::aws_keys::identity_env("deployer", super::aws_keys::DEPLOYER_TAIL);
    let under = pairs(&deployer);
    let rotate = "deployer-key: ROTATE=1 only (the first deployer key is make operator-keys's, as the account root, once)".to_string();
    let version = |x: &str| format!("{x}: VERSION=<n> is required on the command line (make image-versions lists them)");
    let confirm = |v: &str| format!("set CONFIRM={v} on the command line");
    let s = |v: &str| v.to_string();
    // (the make arguments, the environment, the rule that failed and its exit, the refusal)
    type Case<'a> = (Vec<String>, Vec<(&'a str, &'a str)>, String, String);
    let mut cases: Vec<Case> = vec![
        (vec![s("deployer-key")], vec![], s("[deployer-key] Error 2"), rotate.clone()),
        (vec![s("deployer-key")], vec![("ROTATE", "1")], s("[deployer-key] Error 2"), rotate.clone()),
        (vec![s("deployer-key"), s("ROTATE=yes")], vec![], s("[deployer-key] Error 2"), rotate),
        (vec![s("image-delete")], vec![], s("[image-delete] Error 1"), confirm("delete-image")),
        (vec![s("image-delete")], vec![("CONFIRM", "delete-image")], s("[image-delete] Error 1"), confirm("delete-image")),
        (vec![s("image-delete"), s("CONFIRM=delete-imagex")], vec![], s("[image-delete] Error 1"), confirm("delete-image")),
    ];
    for x in ["image-activate", "image-deactivate"] {
        cases.push((vec![s(x)], vec![], format!("[{x}] Error 2"), version(x)));
        cases.push((vec![s(x)], vec![("VERSION", "3")], format!("[{x}] Error 2"), version(x)));
    }
    for (x, v) in [("image-delete", "delete-image"), ("connector-probe", "create-probe-connector"), ("connector-delete", "delete-connector")] {
        cases.push((vec![format!("{x}-run")], under.clone(), format!("[{x}-run] Error 1"), confirm(v)));
        let mut exported = under.clone();
        exported.push(("CONFIRM", v));
        cases.push((vec![format!("{x}-run")], exported, format!("[{x}-run] Error 1"), confirm(v)));
    }
    cases.push((vec![s("destroy-run"), s("BREAKGLASS=1")], under.clone(), s("[destroy-run] Error 1"), confirm("destroy-dev")));
    for (args, envs, error, refusal) in &cases {
        std::fs::remove_file(t.join("calls.log")).ok();
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = tier_make(t, &bin, &argv, false, envs);
        let text = all(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?} {envs:?}: {text}");
        assert!(text.contains(refusal.as_str()) && text.contains(error.as_str()), "{args:?} {envs:?}: {text}");
        assert_eq!(calls(t), Vec::<String>::new(), "{args:?} {envs:?}: something ran");
    }
}

// ---- S8: s8-smoke, test-cursor, doc-test, test-aws's skip, acceptance, the scrub lists ----

/// The steps of `make acceptance`, one recipe line each, in their order.
const ACCEPT_STEPS: [&str; 12] = ["roots", "doctor", "version", "creds", "outside-roots", "planted-key", "bypass-settings", "egress-required", "kill-switch", "region", "lone-ai-env", "smoke"];

/// `make -n` of S8's targets: s8-smoke runs W7's live_wrapper_smoke alone
/// (`--exact` names a test's whole path: it is a top-level test, whose own
/// output carries the 3/3 line and whose records go where the help says),
/// test-cursor its gate and step and the two filters given on the command
/// line, after the step's check, test-aws CRED=1 skips the smoke, doc-test
/// runs tests/readme.rs, and acceptance shows each step and negative on a
/// line of its own, the Touch IDs last. Nothing runs, nothing is made.
#[test]
fn make_n_of_the_s8_targets_names_their_commands_and_runs_nothing() {
    let t = tempfile::tempdir().unwrap();
    let w = planted_repo(t.path(), true);
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().chain(&["git"]).map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let pair = t.path().join("pair");
    for name in ["ai-env", "ai-env-claude"] {
        script(&pair.join(name), "echo \"$(basename \"$0\") $*\" >> \"$FAKE_LOG\"\nexit 1");
    }
    let log = t.path().join("tools.log");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make_in(t.path(), &bin, &w, &["-n"]).args(args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let cargo = "cargo +1.98.1 test -p ai-env-cli --features bridge";

    let smoke = dry(&["s8-smoke"], &[]);
    assert_eq!(smoke, format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1 AI_ENV_CREDENTIAL_TESTS=1 {cargo} --test aws -- --ignored --exact live_wrapper_smoke --nocapture --test-threads=1\n"));
    let aws = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/aws.rs"));
    assert!(aws.contains("\n#[test]\n#[ignore = ") && aws.contains("\nfn live_wrapper_smoke() {\n"), "live_wrapper_smoke is no longer a top-level test: make s8-smoke's --exact names it by its whole path");
    for want in ["\"s8-smoke: pass {pass} ok\"", "\"s8-smoke: 3/3 ok ({})\"", "join(\"../../target/s8\")).unwrap().join(\"smoke.jsonl\")"] {
        assert!(aws.contains(want), "live_wrapper_smoke no longer has {want}: make s8-smoke's help and comment say what it prints and writes");
    }
    let body = aws.split("\nfn live_wrapper_smoke() {\n").nth(1).and_then(|b| b.split("\n}\n").next()).unwrap_or_default();
    assert!(
        body.find("assert_closed_well(").is_some_and(|close| body.find(".open(&records)").is_some_and(|write| close < write)),
        "live_wrapper_smoke no longer writes a pass's record once its close passed, as make s8-smoke's help and comment say"
    );

    let tail = format!("{cargo} --test cursor_live -- --ignored --nocapture --test-threads=1");
    let gate = format!("{LAB_UNSET} AI_ENV_CURSOR_TESTS=1 AI_ENV_CURSOR_STEP=t8_5 ");
    let text = dry(&["test-cursor", "STEP=t8_5"], &[("SINCE", "2026-10-14T09:00:00Z"), ("WORKSPACE", "/w")]);
    assert!(text.contains(&format!("\n{gate}{tail}\n")), "the filters count only on the command line (egress-logs' SINCE default included): {text}");
    let text = dry(&["test-cursor", "STEP=t8_5", "SINCE=2026-10-14T09:00:00Z", "WORKSPACE=/Users/x/a b"], &[]);
    let run = format!("{gate}AI_ENV_CURSOR_SINCE='2026-10-14T09:00:00Z' AI_ENV_CURSOR_WORKSPACE='/Users/x/a b' {tail}");
    assert!(text.starts_with("step='t8_5'; case \"$step\" in t8_3|t8_4|t8_5|t8_6|t8_7) ;; \\") && text.ends_with(&format!("\n{run}\n")), "the step's check first, then the checks: {text}");

    assert!(dry(&["test-aws", "CRED=1"], &[]).contains(&format!("AI_ENV_CREDENTIAL_TESTS=1 {cargo} --test aws -- --ignored --test-threads=1 --nocapture --skip live_wrapper_smoke\n")), "B3 runs the smoke once");
    assert!(!dry(&["test-aws"], &[]).contains("--skip"));
    assert!(!dry(&["test-aws"], &[("CRED", "1")]).contains("--skip"), "CRED=1 in the environment is ignored");
    assert_eq!(dry(&["doc-test"], &[]), format!("{cargo} --test readme\n"));

    let text = dry(&["acceptance", &format!("ACCEPT_BIN={}", pair.display())], &[]).replace("\\\n", " ");
    // The runner first (S8 operators: the steps run as ai-env-ops), only shown in a dry run; then acceptance-run.
    let (runner, text) = text.split_once('\n').unwrap();
    assert_eq!(runner, format!(": cargo +1.98.1 run -q -p ai-env-cli --bin ai-env -- as ops --; {} --no-print-directory acceptance-run", make_path()));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), ACCEPT_STEPS.len() + 1, "one line per step, then the verdict: {text}");
    let shell = format!("set -uo pipefail; unset {} AI_ENV_BRIDGE_LOCAL AI_ENV_BRIDGE_MODE AI_ENV_BRIDGE_VM AI_ENV_BRIDGE_MIRROR_ROOT; a=\"{}/target/s8/acceptance/", LAB_UNSET.replace("env -u ", "").replace(" -u ", " "), w.canonicalize().unwrap().display());
    let argv = "\"$a/claude\" --output-format stream-json --verbose --input-format stream-json --permission-prompt-tool stdio --permission-mode default)";
    let wants: [&[&str]; 12] = [
        &["test -x \"$ai\" && test -x \"$wrap\" ||", "\"$ai\" box seed \"$a\" --dry-run", "must hold target/s8"],
        &["out=$(\"$ai\" doctor 2>&1)", "region eu-central-1 (pinned in code)"],
        &["v1=$(\"$ai\" --version) && v2=$(\"$wrap\" --version)", "test \"${v1##* }\" = \"${v2##* }\""],
        &["out=$(\"$ai\" creds status 2>&1)", "setup-token.env: sealed", "! grep -qF '[NO ]'"],
        &[&format!("(cd / && exec env AI_ENV_BRIDGE_MODE=remote \"$wrap\" {argv}"), "\"$ai\" wrapper census --json", "'\"reason\":\"outside_roots\"'"],
        &["key=$(printf '%s%s' AKIA \"$(printf 'Q7ZT%.0s' 1 2 3 4)\")", "\"$ai\" box seed \"$a\" --dry-run", "test $rc -eq 9", "HEAD:deploy.conf", "rule aws-access-key-id"],
        &["\"defaultMode\": \"bypassPermissions\"", "\"$ai\" box seed \"$a\" --dry-run", "test $rc -eq 9", "key permissions.defaultMode"],
        &["cfg=\"${AI_ENV_BRIDGE_CONFIG:-$bridge/bridge.toml}\"", &format!("exec env AI_ENV_BRIDGE_CONFIG=\"$a/bridge.toml\" AI_ENV_BRIDGE_MODE=remote \"$wrap\" {argv}"), "test $rc -eq 9", "'\"event\":\"credential_unseal\"'", "step:precheck"],
        &[&format!("exec env AI_ENV_BRIDGE_LOCAL=1 AI_ENV_BRIDGE_MODE=remote \"$wrap\" {argv}"), "test -z \"$hit\""],
        &["out=$(AWS_REGION=eu-west-3 \"$ai\" doctor 2>&1)", "<- env AWS_REGION=eu-west-3 ignored (region pinned to eu-central-1)"],
        &["cp \"$ai\" \"$a/ai-env\"", "PATH=\"$p\" \"$a/ai-env\" doctor", "[NO ] ai-env-claude missing", "PATH=\"$p\" \"$a/ai-env\" wrapper install", "test $rc -eq 5"],
        &["\"$ai\" vm smoke --max-duration 900 --json", "\"$ai\" vm list --json"],
    ];
    for ((line, step), wants) in lines.iter().zip(ACCEPT_STEPS).zip(wants) {
        assert!(line.starts_with(&format!("{shell}{step}\"; ai=\"{}/ai-env\"; wrap=\"{}/ai-env-claude\";", pair.display(), pair.display())), "{step}: its own shell and directory: {line}");
        assert!(line.contains(&format!("fail() {{ echo \"acceptance: {step}: $*\"; exit 1; }};")) && line.contains("trap 'rm -rf \"$a\"; rmdir "), "{step}: {line}");
        for want in wants {
            assert!(line.contains(want), "{step}: {want} missing from its line: {line}");
        }
        assert_eq!(line.contains("vm smoke") || line.contains("vm list"), step == "smoke", "{step}: the Touch IDs only in the last step: {line}");
    }
    assert!(lines[ACCEPT_STEPS.len()].starts_with("echo \"acceptance: ok:"), "{text}");
    // No credential-looking literal: the planted value is put together at run time.
    let mk = read(&Path::new(REPO).join("Makefile"));
    assert!(mk.match_indices("AKIA").all(|(i, _)| !mk[i + 4..].chars().take(16).all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())), "an AKIA literal in the Makefile");
    assert_eq!(read(&log), "", "make -n ran a tool");
    assert!(!w.join("target").exists(), "make -n made {}", w.join("target").display());
}

/// test-cursor checks STEP and SINCE before cargo runs: a missing STEP (also
/// one only the environment names) and one that names no step are exit 2,
/// naming the steps (S8's five, S9's t9_s3, S10's t10_2 to t10_5 and t10_p);
/// a missing or empty SINCE (also one only the environment names) is exit 2
/// too, naming SINCE=all; a step runs the checks with the gate, the step and
/// the filters the command line gives, and no lab knob.
#[test]
fn test_cursor_refuses_a_missing_or_unknown_step_before_cargo() {
    let t = tempfile::tempdir().unwrap();
    let bin = bin_with(t.path(), &[]);
    script(
        &bin.join("cargo"),
        r#"printf 'cargo %s [TESTS=%s STEP=%s SINCE=%s WORKSPACE=%s] [LAB=%s]\n' "$*" "${AI_ENV_CURSOR_TESTS-}" "${AI_ENV_CURSOR_STEP-}" "${AI_ENV_CURSOR_SINCE-unset}" "${AI_ENV_CURSOR_WORKSPACE-unset}" "$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | tr '\n' ' ')" >> "$FAKE_LOG""#,
    );
    let log = t.path().join("cargo.log");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        std::fs::remove_file(&log).ok();
        let out = make(t.path(), &bin, args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        (out, lines_of(&log))
    };
    let steps = "(or t8_4, t8_5, t8_6, t8_7)";
    let s10 = "or STEP=t9_s3 after S9's, or STEP=t10_2 (or t10_3, t10_4, t10_5, t10_p) after S10's";
    let all_steps = "one of t8_3, t8_4, t8_5, t8_6, t8_7, t9_s3, t10_2, t10_3, t10_4, t10_5, t10_p";
    for (what, args, envs, want) in [
        ("no STEP", &["test-cursor"][..], &[][..], format!("test-cursor: STEP is missing: make test-cursor STEP=t8_3 {steps} after that step in Cursor, {s10}")),
        ("STEP in the environment only", &["test-cursor"][..], &[("STEP", "t8_3")][..], "test-cursor: STEP is missing".to_string()),
        ("an unknown step", &["test-cursor", "STEP=t8_8"][..], &[][..], format!("test-cursor: STEP=t8_8 names no step: {all_steps}")),
        ("a test's name", &["test-cursor", "STEP=t8_3_evidence"][..], &[][..], "test-cursor: STEP=t8_3_evidence names no step".to_string()),
        // S10: T10.1 is cargo test's (tests/continuity.rs), never a Cursor step; a step's prefix or a test's name is no step.
        ("T10.1", &["test-cursor", "STEP=t10_1"][..], &[][..], format!("test-cursor: STEP=t10_1 names no step: {all_steps}")),
        ("an S10 step's prefix", &["test-cursor", "STEP=t10"][..], &[][..], "test-cursor: STEP=t10 names no step".to_string()),
        ("an S10 test's name", &["test-cursor", "STEP=t10_3_mid_turn_resends_the_line_once"][..], &[][..], "test-cursor: STEP=t10_3_mid_turn_resends_the_line_once names no step".to_string()),
        ("an S10 step in the environment only", &["test-cursor"][..], &[("STEP", "t10_2")][..], "test-cursor: STEP is missing".to_string()),
    ] {
        let (out, calls) = run(args, envs);
        assert_eq!(out.status.code(), Some(2), "{what}: {}", all(&out));
        assert!(all(&out).contains(&want), "{what}: {}", all(&out));
        assert_eq!(calls, Vec::<String>::new(), "{what}: cargo ran");
    }
    let checks = "cargo +1.98.1 test -p ai-env-cli --features bridge --test cursor_live -- --ignored --nocapture --test-threads=1";
    let (out, calls) = run(&["test-cursor", "STEP=t8_6", "SINCE=2026-10-14T09:00:00Z", "WORKSPACE=/tmp/a b"], &[("AI_ENV_BRIDGE_LAB_TRANSCRIPT", "skip"), ("AI_ENV_BRIDGE_LAB_FAKE_API", "/f.json")]);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(calls, vec![format!("{checks} [TESTS=1 STEP=t8_6 SINCE=2026-10-14T09:00:00Z WORKSPACE=/tmp/a b] [LAB=]")]);
    // SINCE counts only on the command line (S9, L10): none, one only the environment names, and an empty one are
    // all missing, before cargo.
    let since = "test-cursor: SINCE is missing: take the step's start (date -u +%Y-%m-%dT%H:%M:%SZ) before the step in Cursor, or pass SINCE=all to read every row";
    for (what, args, envs) in [
        ("no SINCE", &["test-cursor", "STEP=t8_3"][..], &[][..]),
        ("SINCE in the environment only", &["test-cursor", "STEP=t8_3"][..], &[("SINCE", "2026-10-14T09:00:00Z"), ("WORKSPACE", "/w")][..]),
        ("an empty SINCE", &["test-cursor", "STEP=t8_3", "SINCE="][..], &[][..]),
    ] {
        let (out, calls) = run(args, envs);
        assert_eq!(out.status.code(), Some(2), "{what}: {}", all(&out));
        assert!(all(&out).contains(since), "{what}: {}", all(&out));
        assert_eq!(calls, Vec::<String>::new(), "{what}: cargo ran");
    }
    let (out, calls) = run(&["test-cursor", "STEP=t8_3", "SINCE=all"], &[("WORKSPACE", "/w")]);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(calls, vec![format!("{checks} [TESTS=1 STEP=t8_3 SINCE=all WORKSPACE=unset] [LAB=]")], "the environment's WORKSPACE never reaches the checks");
    // S10's steps (tests/cursor_live.rs reads each one's evidence): each runs the checks as S8's and S9's do, with
    // SINCE required, and no lab knob.
    for step in ["t10_2", "t10_3", "t10_4", "t10_5", "t10_p"] {
        let step_arg = format!("STEP={step}");
        let (out, calls) = run(&["test-cursor", step_arg.as_str(), "SINCE=2026-10-20T09:00:00Z"], &[("AI_ENV_BRIDGE_LAB_PARK_AFTER_MS", "100")]);
        assert!(out.status.success(), "{step}: {}", all(&out));
        assert_eq!(calls, vec![format!("{checks} [TESTS=1 STEP={step} SINCE=2026-10-20T09:00:00Z WORKSPACE=unset] [LAB=]")], "{step}");
        let (out, calls) = run(&["test-cursor", step_arg.as_str()], &[]);
        assert!(out.status.code() == Some(2) && all(&out).contains(since) && calls.is_empty(), "{step}: SINCE is required: {}", all(&out));
    }
}

/// The `ai-env` of the pair `make acceptance` runs (ACCEPT_BIN), a
/// stand-in: each call logged to FAKE_ACCEPT_LOG (its argv, and any lab knob
/// that reached it); what is live on Mike's Mac answered as a green Mac
/// answers it (doctor, creds status, vm smoke, vm list, wrapper install); the
/// offline rest (box seed --dry-run, wrapper census, --version) handed to the
/// real binary (FAKE_ACCEPT_REAL). With no ai-env-claude beside it (negative
/// g's copy, alone), doctor and wrapper install go to FAKE_ACCEPT_LONE, the
/// real binary alone in a directory. The failures a case asks for:
/// FAKE_ACCEPT_DOCTOR_RC (doctor without AWS_REGION) and
/// FAKE_ACCEPT_REGION_RC (with it); FAKE_ACCEPT_VERSION (its own
/// --version); FAKE_ACCEPT_CREDS (`absent`: no token sealed; `refused`: a
/// `[NO ]` row) and FAKE_ACCEPT_CREDS_RC; FAKE_ACCEPT_REGION=ignore (no word
/// of AWS_REGION); FAKE_ACCEPT_SEED_FOR, a box seed of a path holding it
/// answered with FAKE_ACCEPT_SEED_SAY on stderr and FAKE_ACCEPT_SEED_RC;
/// FAKE_ACCEPT_INSTALL_RC, the lone copy's wrapper install;
/// FAKE_ACCEPT_BACKEND, vm smoke's backend; FAKE_ACCEPT_LIST, vm list's
/// answer. FAKE_ACCEPT_CENSUS_TAIL, a census row appended before each
/// wrapper census (another process's, as a Cursor chat writes meanwhile).
const ACCEPT_AI_ENV: &str = r##"lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
printf 'ai-env %s%s\n' "$*" "${lab:+ [LAB=${lab% }]}" >> "$FAKE_ACCEPT_LOG"
here=$(dirname "$0")
case "${1:-} ${2:-}" in
  "--version ")
    if [ -n "${FAKE_ACCEPT_VERSION:-}" ]; then echo "ai-env $FAKE_ACCEPT_VERSION"; exit 0; fi ;;
  "doctor "|"wrapper install")
    if [ ! -e "$here/ai-env-claude" ]; then
      if [ "$1" = wrapper ] && [ -n "${FAKE_ACCEPT_INSTALL_RC:-}" ]; then exit "$FAKE_ACCEPT_INSTALL_RC"; fi
      exec "$FAKE_ACCEPT_LONE" "$@"
    fi
    if [ "$1" = doctor ]; then
      region="[ok ] region eu-central-1 (pinned in code)"
      if [ "${AWS_REGION:-eu-central-1}" != eu-central-1 ] && [ "${FAKE_ACCEPT_REGION:-}" != ignore ]; then
        region="[!! ] region eu-central-1 (pinned in code)  <- env AWS_REGION=$AWS_REGION ignored (region pinned to eu-central-1)"
      fi
      printf '%s\n' "ai-env doctor" "  $region" "  [ok ] ai-env-claude next to ai-env ($here/ai-env-claude)"
      if [ "${AWS_REGION:-eu-central-1}" != eu-central-1 ]; then exit "${FAKE_ACCEPT_REGION_RC:-0}"; fi
      exit "${FAKE_ACCEPT_DOCTOR_RC:-0}"
    fi
    echo "dry run: settings.json not written"
    exit 0 ;;
  "creds status")
    echo "[ok ] [creds] key ai-env-bridge, mode setup-token, deliver fd, Touch ID budget 60 s"
    case "${FAKE_ACCEPT_CREDS:-}" in
      absent) echo "[-  ] setup-token.env: absent" ;;
      refused) printf '%s\n' "[ok ] setup-token.env: sealed, opens with key ai-env-bridge" "[NO ] the sealed setup-token was refused by Anthropic" ;;
      *) echo "[ok ] setup-token.env: sealed, opens with key ai-env-bridge" ;;
    esac
    exit "${FAKE_ACCEPT_CREDS_RC:-0}" ;;
  "vm smoke")
    printf '{"backend":"%s","id":"microvm-0123456789abcdef0","ok":true}\n' "${FAKE_ACCEPT_BACKEND:-sdk}"
    exit 0 ;;
  "vm list")
    none='{"backend":"sdk","vms":[]}'
    printf '%s\n' "${FAKE_ACCEPT_LIST:-$none}"
    exit 0 ;;
  "wrapper census")
    if [ -n "${FAKE_ACCEPT_CENSUS_TAIL:-}" ]; then printf '%s\n' "$FAKE_ACCEPT_CENSUS_TAIL" >> "$AI_ENV_BRIDGE_DIR/logs/census.jsonl"; fi ;;
  "box seed")
    case "${3:-}" in *"${FAKE_ACCEPT_SEED_FOR:-//}"*) printf '%s\n' "${FAKE_ACCEPT_SEED_SAY:-}" >&2; exit "${FAKE_ACCEPT_SEED_RC:-0}" ;; esac ;;
esac
exec "$FAKE_ACCEPT_REAL" "$@""##;

/// The `ai-env-claude` of the pair: each call logged as [`ACCEPT_AI_ENV`]
/// logs, then the real wrapper (FAKE_ACCEPT_WRAPPER) exec'd in its place.
/// The failure a case asks for, FAKE_ACCEPT_DO, acts on a session whose
/// argv[1] holds FAKE_ACCEPT_FOR (a step's directory): `child` (the wrapper
/// runs as a child, so the session is not exec'd in place), `unconfigured`
/// (no bridge.toml: the census row's reason is another), `unseal` (an
/// unseal's audit row of its pid first), `other` (one of another process,
/// as a Cursor chat starting meanwhile writes), `refuse` (negative d's exit and line with no
/// wrapper run, so no census row), `ran` (the stand-in claude run first),
/// `remote` (the kill switch dropped), `passthrough` (the kill switch
/// dropped for passthrough, whose exec writes a census row) and `noisy` (a
/// line on stderr first).
const ACCEPT_WRAPPER: &str = r##"lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
printf 'ai-env-claude %s%s\n' "$*" "${lab:+ [LAB=${lab% }]}" >> "$FAKE_ACCEPT_LOG"
case "${1:-}" in *"${FAKE_ACCEPT_FOR:-//}"*) act=${FAKE_ACCEPT_DO:-} ;; *) act= ;; esac
case "$act" in
  child) "$FAKE_ACCEPT_WRAPPER" "$@"; exit $? ;;
  unconfigured) export AI_ENV_BRIDGE_CONFIG=/nonexistent/bridge.toml ;;
  unseal) echo "{\"v\":1,\"event\":\"credential_unseal\",\"pid\":$$,\"detail\":{\"outcome\":\"ok\"}}" >> "$AI_ENV_BRIDGE_DIR/audit.jsonl" ;;
  other) echo '{"v":1,"event":"credential_unseal","pid":1,"detail":{"outcome":"ok"}}' >> "$AI_ENV_BRIDGE_DIR/audit.jsonl" ;;
  refuse) echo "ai-env-claude: refused before any Touch ID: egress connector required (vpc egress asked for, or [egress].require=true) and none configured: make infra-status WRITE=1 writes [aws].egress_connector_arn" >&2; exit 9 ;;
  ran) "$@" ;;
  remote) unset AI_ENV_BRIDGE_LOCAL ;;
  passthrough) unset AI_ENV_BRIDGE_LOCAL; export AI_ENV_BRIDGE_MODE=passthrough ;;
  noisy) echo "ai-env-claude: noise" >&2 ;;
esac
exec "$FAKE_ACCEPT_WRAPPER" "$@""##;

/// The world `make acceptance` runs in here: a planted repo whose target/s8
/// the bridge root's `[workspaces].roots` holds (its bridge.toml also names
/// an image, the egress connector and `[egress].require`), the tools negative
/// g's doctor probes as logged fakes first on PATH, and ACCEPT_BIN's pair as
/// [`ACCEPT_AI_ENV`] and [`ACCEPT_WRAPPER`]; `lone` is the real `ai-env`
/// alone in a directory (negative g's product). AI_ENV, whose `as` runs the
/// steps as ai-env-ops (S8 operators), is the stand-in, logging to
/// `runner.log`.
struct Acceptance {
    t: tempfile::TempDir,
    w: PathBuf,
    bin: PathBuf,
    pair: PathBuf,
    lone: PathBuf,
}

impl Acceptance {
    fn new(lone: &Path) -> Acceptance {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let w = planted_repo(&root, true);
        std::fs::create_dir_all(w.join("target/s8")).unwrap();
        let mut fakes: Vec<(&str, &str)> = ["aws", "claude", "rustup", "zig", "cargo-lambda", "age", "pulumi", "docker", "curl"].iter().map(|n| ("logged.sh", *n)).collect();
        fakes.push(("ai-env.sh", "ai-env-stand-in"));
        let bin = bin_with(&root, &fakes);
        let pair = root.join("pair");
        script(&pair.join("ai-env"), ACCEPT_AI_ENV);
        script(&pair.join("ai-env-claude"), ACCEPT_WRAPPER);
        let a = Acceptance { t, w, bin, pair, lone: lone.to_path_buf() };
        a.bridge_toml(&format!("[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\negress_connector_arn = \"{CONNECTOR_ARN}\"\n\n[egress]\nrequire = true\n\n"), &a.w.join("target/s8"));
        a
    }

    fn root(&self) -> PathBuf {
        self.t.path().canonicalize().unwrap()
    }

    /// `head` then `[workspaces].roots = [roots]`, as the bridge root's bridge.toml.
    fn bridge_toml(&self, head: &str, roots: &Path) {
        std::fs::create_dir_all(self.root().join("bridge")).unwrap();
        std::fs::write(self.root().join("bridge/bridge.toml"), format!("{head}[workspaces]\nroots = [\"{}\"]\n", roots.display())).unwrap();
    }

    /// `make <flags> acceptance ACCEPT_BIN=<accept_bin>` in w (`accept_bin` the pair's directory, as the operator
    /// spells it; no -C, so `flags` are all of MAKEFLAGS' options), isolated like [`make_in`], with the stand-ins'
    /// knobs, then `envs`.
    fn run(&self, flags: &[&str], accept_bin: &str, envs: &[(&str, String)]) -> Output {
        let root = self.root();
        let mut cmd = Command::new("make");
        isolate(&mut cmd, &root).env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()));
        cmd.current_dir(&self.w)
            .args(flags)
            .arg("acceptance")
            .arg(format!("ACCEPT_BIN={accept_bin}"))
            .arg(format!("AI_ENV={}", self.bin.join("ai-env-stand-in").display()))
            .env("FAKE_AIENV_LOG", root.join("runner.log"))
            .env("FAKE_LOG", root.join("tools.log"))
            .env("FAKE_ACCEPT_LOG", root.join("accept.log"))
            .env("FAKE_ACCEPT_REAL", bin())
            .env("FAKE_ACCEPT_WRAPPER", env!("CARGO_BIN_EXE_ai-env-claude"))
            .env("FAKE_ACCEPT_LONE", &self.lone)
            .envs(envs.iter().map(|(k, v)| (*k, v.as_str())))
            .bounded()
    }

    /// The pair's calls, in order.
    fn calls(&self) -> Vec<String> {
        lines_of(&self.root().join("accept.log"))
    }

    /// The AI_ENV stand-in's calls: the runner's.
    fn runner(&self) -> Vec<String> {
        lines_of(&self.root().join("runner.log"))
    }

    /// The census rows the real wrapper wrote.
    fn census(&self) -> Vec<Value> {
        lines_of(&self.root().join("bridge/logs/census.jsonl")).iter().map(|l| serde_json::from_str(l).unwrap()).collect()
    }
}

/// `make acceptance` whole, with the pair as stand-ins and the real binaries
/// behind them where nothing is live (the roots' and the two tripwires' box
/// seed --dry-run, the wrapper of negatives a, d and e and its census,
/// negative g's doctor and wrapper install of a lone real ai-env): every
/// step passes in order, the Touch IDs last, with the lab knobs, the kill
/// switch and the mode of the caller's shell dropped, target/s8/acceptance
/// gone and the planted value never shown. Then each step and negative made
/// to fail in turn: the target stops at that step, naming it, after the
/// steps before it and before any after it, and still removes its
/// directory. Some cases pass: one with an ai-env-claude on PATH (negative g
/// takes the lone copy's PATH without it), one with a relative ACCEPT_BIN
/// (the steps change directory), one without target/s8 before (the run
/// removes the one it made; one there before stays), and one where another
/// process writes audit and census rows meanwhile, as a Cursor chat would.
#[test]
fn acceptance_runs_each_step_and_negative_and_stops_at_the_first_that_fails() {
    let lone_dir = tempfile::tempdir().unwrap();
    let lone = lone_dir.path().canonicalize().unwrap().join("ai-env");
    std::fs::copy(bin(), &lone).unwrap();
    // S9's negative (h), made to fail: the real ai-env for everything but `vm run`, which goes past its plan (a
    // regression of [egress].require: a VM started), or refuses as it should after writing a VM's audit row.
    let regressed = lone_dir.path().canonicalize().unwrap().join("regressed-ai-env");
    script(&regressed, &format!("case \"${{1:-}} ${{2:-}}\" in \"vm run\") echo '{{\"id\":\"microvm-0123456789abcdef0\"}}'; exit 0 ;; esac\nexec '{}' \"$@\"", bin()));
    let audited = lone_dir.path().canonicalize().unwrap().join("audited-ai-env");
    script(
        &audited,
        &format!("case \"${{1:-}} ${{2:-}}\" in \"vm run\") echo \"{{\\\"v\\\":1,\\\"event\\\":\\\"vm_egress_internet\\\",\\\"pid\\\":$$,\\\"detail\\\":{{}}}}\" >> \"$AI_ENV_BRIDGE_DIR/audit.jsonl\"; echo 'ai-env: egress connector required (vpc egress asked for, or [egress].require=true) and none configured' >&2; exit 9 ;; esac\nexec '{}' \"$@\"", bin()),
    );
    // What the recipe plants (it puts the value together with printf).
    let key = format!("{}{}", "AKIA", "Q7ZT".repeat(4));
    #[derive(Clone, Copy, PartialEq)]
    enum World {
        Green,
        NoPair,
        RootsElsewhere,
        InlineEgress,
        ClaudeOnPath,
        RelativePair,
        NoS8,
    }
    let s = |v: &str| v.to_string();
    let caller = vec![("AI_ENV_BRIDGE_LAB_EXIT", s("7:planted")), ("AI_ENV_BRIDGE_LAB_FAKE_API", s("/nonexistent/fake.json")), ("AI_ENV_BRIDGE_LAB_TRANSCRIPT", s("skip")), ("AI_ENV_BRIDGE_LOCAL", s("1")), ("AI_ENV_BRIDGE_MODE", s("passthrough")), ("AI_ENV_BRIDGE_VM", s("microvm-0123456789abcdef1"))];
    // The wrapper's failure for the session of one step's directory.
    let session = |step: &str, act: &str| vec![("FAKE_ACCEPT_FOR", format!("/{step}/")), ("FAKE_ACCEPT_DO", s(act))];
    let seed = |step: &str, rc: &str, say: String| vec![("FAKE_ACCEPT_SEED_FOR", format!("/{step}")), ("FAKE_ACCEPT_SEED_RC", s(rc)), ("FAKE_ACCEPT_SEED_SAY", say)];
    // Another process's census row, newer than the step's own when the step reads the census.
    let tail = r#"{"v":1,"ts":"2026-10-13T09:00:00Z","start":1,"pid":1,"ppid":1,"ext":null,"route":"remote","reason":"session","argv":["ai-env-claude"],"cwd":"/","env_names":[],"env_selected":{},"note":"mode:remote"}"#;
    // (what, its world, its environment, the step it fails at and what that step says; none: every step passes)
    type Case<'a> = (&'a str, World, Vec<(&'a str, String)>, Option<(&'a str, &'a str)>);
    let cases: Vec<Case> = vec![
        ("every step passes", World::Green, caller, None),
        ("ai-env-claude on PATH too", World::ClaudeOnPath, vec![], None),
        ("other processes write audit and census rows meanwhile", World::Green, [session("egress-required", "other"), vec![("FAKE_ACCEPT_CENSUS_TAIL", s(tail))]].concat(), None),
        ("a relative ACCEPT_BIN", World::RelativePair, vec![], None),
        ("no target/s8 before", World::NoS8, vec![], None),
        ("no pair installed", World::NoPair, vec![], Some(("roots", "no ai-env and ai-env-claude in"))),
        ("roots without target/s8", World::RootsElsewhere, vec![], Some(("roots", "box seed --dry-run of a clean fixture exited 9: [workspaces].roots of"))),
        ("doctor fails", World::Green, vec![("FAKE_ACCEPT_DOCTOR_RC", s("1"))], Some(("doctor", "ai-env doctor exited 1 (its rows above)"))),
        ("a version skew", World::Green, vec![("FAKE_ACCEPT_VERSION", s("0.0.9"))], Some(("version", "version skew: ai-env 0.0.9, ai-env-claude "))),
        ("no token sealed", World::Green, vec![("FAKE_ACCEPT_CREDS", s("absent"))], Some(("creds", "no sealed setup-token (ai-env creds setup-token)"))),
        ("a refused token", World::Green, vec![("FAKE_ACCEPT_CREDS", s("refused"))], Some(("creds", "a [NO ] row above"))),
        ("creds status fails", World::Green, vec![("FAKE_ACCEPT_CREDS_RC", s("1"))], Some(("creds", "ai-env creds status exited 1"))),
        ("(a) not exec'd in place", World::Green, session("outside-roots", "child"), Some(("outside-roots", "the stand-in claude did not run in place of ai-env-claude"))),
        ("(a) another reason", World::Green, session("outside-roots", "unconfigured"), Some(("outside-roots", "is not route local, reason outside_roots: {"))),
        ("(b) not refused", World::Green, seed("planted-key", "0", s("")), Some(("planted-key", "box seed --dry-run exited 0, not 9"))),
        ("(b) the value shown", World::Green, seed("planted-key", "9", format!("ai-env: workspace refused (finding): {key}")), Some(("planted-key", "box seed --dry-run shows the planted value"))),
        ("(c) no key named", World::Green, seed("bypass-settings", "9", s("ai-env: workspace refused (finding): HEAD:.claude/settings.json (blob 0123456789ab) line 1: rule default-mode")), Some(("bypass-settings", "the refusal names neither HEAD:.claude/settings.json nor its key permissions.defaultMode"))),
        ("(d) a form the copy cannot edit", World::InlineEgress, vec![], Some(("egress-required", "bridge.toml still names egress_connector_arn or require (a form this copy does not edit): nothing was run"))),
        ("(d) an unseal", World::Green, session("egress-required", "unseal"), Some(("egress-required", "1 credential_unseal audit row(s) of pid "))),
        ("(d) no precheck row", World::Green, session("egress-required", "refuse"), Some(("egress-required", "shows no refusal at the precheck before any Touch ID: none"))),
        ("(d) the stand-in ran", World::Green, session("egress-required", "ran"), Some(("egress-required", "the stand-in claude ran: a session under the roots in remote mode runs no Mac binary"))),
        ("(h) vm run past its plan", World::Green, vec![("FAKE_ACCEPT_REAL", regressed.display().to_string())], Some(("egress-required", "(h) ai-env vm run without --egress under [egress].require = true exited 0, not 9 naming the egress connector: {\"id\":\"microvm-0123456789abcdef0\"}"))),
        ("(h) a VM's audit row", World::Green, vec![("FAKE_ACCEPT_REAL", audited.display().to_string())], Some(("egress-required", "(h) 1 vm audit row(s) of pid "))),
        ("(e) the switch ignored", World::Green, session("kill-switch", "remote"), Some(("kill-switch", "ai-env-claude exited 5 saying: ai-env-claude: "))),
        ("(e) not exec'd in place", World::Green, session("kill-switch", "child"), Some(("kill-switch", "the stand-in claude did not run in place of ai-env-claude"))),
        ("(e) a census row", World::Green, session("kill-switch", "passthrough"), Some(("kill-switch", "a census row of pid"))),
        ("(e) a word said", World::Green, session("kill-switch", "noisy"), Some(("kill-switch", "ai-env-claude exited 0 saying: ai-env-claude: noise"))),
        ("(f) the variable unnamed", World::Green, vec![("FAKE_ACCEPT_REGION", s("ignore"))], Some(("region", "doctor with AWS_REGION=eu-west-3 does not say the variable is ignored for eu-central-1"))),
        ("(f) doctor fails with the variable", World::Green, vec![("FAKE_ACCEPT_REGION_RC", s("1"))], Some(("region", "doctor with AWS_REGION=eu-west-3 exited 1"))),
        ("(g) ai-env-claude still beside it", World::Green, vec![("FAKE_ACCEPT_LONE", s(bin()))], Some(("lone-ai-env", "doctor of ai-env alone exited 1 (1 with [NO ] ai-env-claude missing wanted)"))),
        ("(g) wrapper install not refused", World::Green, vec![("FAKE_ACCEPT_INSTALL_RC", s("0"))], Some(("lone-ai-env", "wrapper install of ai-env alone exited 0, not 5"))),
        ("the smoke on another backend", World::Green, vec![("FAKE_ACCEPT_BACKEND", s("fake"))], Some(("smoke", "the smoke did not use the SDK backend"))),
        ("the smoke's VM listed", World::Green, vec![("FAKE_ACCEPT_LIST", s(r#"{"backend":"sdk","vms":[{"id":"microvm-0123456789abcdef0","state":"RUNNING"}]}"#))], Some(("smoke", "vm list still holds microvm-0123456789abcdef0"))),
    ];
    // One make per case, side by side (each its own tree).
    let runs: Vec<(Acceptance, Output)> = std::thread::scope(|scope| {
        let handles: Vec<_> = cases
            .iter()
            .map(|(_, world, envs, _)| {
                let lone = &lone;
                scope.spawn(move || {
                    let a = Acceptance::new(lone);
                    let mut envs = envs.clone();
                    let mut accept_bin = a.pair.display().to_string();
                    match world {
                        World::Green => {}
                        World::NoPair => {
                            for name in ["ai-env", "ai-env-claude"] {
                                std::fs::remove_file(a.pair.join(name)).unwrap();
                            }
                        }
                        World::RootsElsewhere => {
                            std::fs::create_dir_all(a.root().join("elsewhere")).unwrap();
                            a.bridge_toml("[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\n\n", &a.root().join("elsewhere"));
                        }
                        World::InlineEgress => a.bridge_toml(&format!("egress = {{ require = false }}\n\n[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\negress_connector_arn = \"{CONNECTOR_ARN}\"\n\n"), &a.w.join("target/s8")),
                        World::ClaudeOnPath => {
                            script(&a.root().join("onpath/ai-env-claude"), "echo \"ai-env-claude 0.1.0\"");
                            envs.push(("PATH", format!("{}:{}:/usr/bin:/bin", a.bin.display(), a.root().join("onpath").display())));
                        }
                        // make runs in w, the pair's sibling.
                        World::RelativePair => accept_bin = "../pair".to_string(),
                        World::NoS8 => std::fs::remove_dir(a.w.join("target/s8")).unwrap(),
                    }
                    let out = a.run(&["-s", "--no-print-directory"], &accept_bin, &envs);
                    (a, out)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for ((what, world, _, fails), (a, out)) in cases.iter().zip(&runs) {
        let text = all(out);
        assert!(!text.contains(&key), "{what}: the planted value in the output");
        assert!(!a.w.join("target/s8/acceptance").exists(), "{what}: target/s8/acceptance is left: {text}");
        assert_eq!(a.w.join("target/s8").exists(), *world != World::NoS8, "{what}: target/s8 stays when it was there before, and goes when the run made it: {text}");
        let calls = a.calls();
        assert!(calls.iter().all(|c| !c.contains("[LAB=")), "{what}: a lab knob reached the pair: {calls:#?}");
        // One runner, ai-env as ops, before any step, after the CLI's keyless build (D18); it drops the caller's lab
        // knobs.
        assert_eq!(a.runner(), [BUILT.to_string(), "as --check ops [AI_ENV=unset]".to_string(), format!("as ops -- {} --no-print-directory acceptance-run [AI_ENV=unset]", make_path())], "{what}: the steps run as ai-env-ops");
        let ok = |step: &str| text.contains(&format!("acceptance: {step}: ok ("));
        match fails {
            None => {
                assert!(out.status.success(), "{what}: {text}");
                let at: Vec<usize> = ACCEPT_STEPS.iter().map(|step| text.find(&format!("acceptance: {step}: ok (")).unwrap_or_else(|| panic!("{what}: no ok line for {step}: {text}"))).collect();
                assert!(at.windows(2).all(|p| p[0] < p[1]), "{what}: the steps in order: {text}");
                assert!(text.ends_with("acceptance: ok: doctor, versions, creds, the negatives (a) to (h), the smoke; target/s8/acceptance removed\n"), "{what}: {text}");
                assert_eq!(calls[calls.len() - 2..], ["ai-env vm smoke --max-duration 900 --json", "ai-env vm list --json"], "{what}: the two Touch IDs last: {calls:#?}");
                // (h): the real vm run, refused by its plan before any Touch ID or AWS call (no backend, no VM row).
                assert!(calls.iter().any(|c| c == "ai-env vm run") && text.contains("(h) [egress].require = true: vm run without --egress refused by its plan, exit 9 before any Touch ID or AWS call)"), "{what}: {text}");
                assert!(!read(&a.root().join("bridge/audit.jsonl")).contains("\"event\":\"vm_"), "{what}: (h)'s vm run wrote a VM's audit row");
                // Its identity probe, in the region it pins. Not the whole line: S8 operators' doctor (W2a) runs its
                // operator identity row under the runner's marker (the steps run under ai-env as ops) through
                // bridge::awscli, which may add its pinned --endpoint-url.
                assert!(
                    lines_of(&a.root().join("tools.log")).iter().any(|l| l.starts_with("aws sts get-caller-identity ") && l.contains(" --region eu-central-1")),
                    "{what}: negative g's doctor is the real one (its probes ran)"
                );
            }
            Some((step, want)) => {
                assert!(!out.status.success(), "{what}: {text}");
                let said = text.lines().rfind(|l| l.starts_with(&format!("acceptance: {step}: "))).unwrap_or_default();
                assert!(said.contains(want), "{what}: want {step}'s last line to say {want}: {text}");
                let at = ACCEPT_STEPS.iter().position(|s| s == step).unwrap();
                assert!(ACCEPT_STEPS[..at].iter().all(|s| ok(s)) && !ACCEPT_STEPS[at..].iter().any(|s| ok(s)), "{what}: the steps before {step} passed, none from it on: {text}");
            }
        }
        let census = a.census();
        let cwd = |r: &Value| r["cwd"].as_str().unwrap_or("").to_string();
        match (*world, *what) {
            (World::Green, "every step passes") => {
                assert!(census.iter().any(|r| r["route"] == "local" && r["reason"] == "outside_roots" && cwd(r) == "/" && r["note"] == "mode:remote"), "(a)'s row: {census:#?}");
                assert!(census.iter().any(|r| r["exit"] == 9 && cwd(r).ends_with("/egress-required/repo") && r["note"].as_str().is_some_and(|n| n.contains("end:spawn_failed") && n.ends_with("step:precheck"))), "(d)'s end row: {census:#?}");
                assert!(!census.iter().any(|r| cwd(r).contains("/kill-switch/")), "(e) wrote a row: {census:#?}");
                assert!(!read(&a.root().join("bridge/audit.jsonl")).contains("credential_unseal"), "nothing was unsealed");
            }
            (World::RootsElsewhere, _) => {
                assert!(text.contains(&format!("its roots: roots = [\"{}\"]", a.root().join("elsewhere").display())) && text.contains("is outside [workspaces].roots"), "{what}: the roots named: {text}");
                assert_eq!(calls.len(), 1, "{what}: nothing after the roots' box seed: {calls:#?}");
            }
            (World::NoPair, _) => assert_eq!(calls, Vec::<String>::new(), "{what}: nothing ran"),
            (World::InlineEgress, _) => assert!(!census.iter().any(|r| cwd(r).contains("/egress-required/")) && !calls.iter().any(|c| c.contains("/egress-required/")), "{what}: the wrapper never ran: {calls:#?}"),
            _ => {}
        }
    }
}

/// `make -i acceptance` stops before any step: under -i a failed step would
/// be ignored, the next ones would run (the two Touch IDs among them) and the
/// last line would say ok. The recipe's first line is a `$(error)` that make
/// expands before any line runs, -i or not, wherever GNU make 3.81 writes
/// the -i: MAKEFLAGS' first word (`make -i`, an outer make's -i), or a word
/// of its own after a long option or after -j. The pair never runs, nothing
/// is made. And `make acceptance` as the operator types it, no option at all
/// (MAKEFLAGS is then the ACCEPT_BIN, which holds an `i`), runs every step;
/// the test above runs with `--no-print-directory`, which holds one too.
#[test]
fn acceptance_refuses_make_i_before_any_step() {
    let lone_dir = tempfile::tempdir().unwrap();
    let lone = lone_dir.path().canonicalize().unwrap().join("ai-env");
    std::fs::copy(bin(), &lone).unwrap();
    let refusal = "*** acceptance: not under make -i (a failed step would be ignored: the next ones would run and the last line say ok): run make acceptance without it.";
    for (what, flags, envs) in [
        ("-i", &["-i"][..], vec![]),
        ("-i after a long option", &["-s", "--no-print-directory", "-i"][..], vec![]),
        ("-i after -j", &["-j2", "-i"][..], vec![]),
        ("an outer make's -i", &[][..], vec![("MAKEFLAGS", "i".to_string())]),
    ] {
        let a = Acceptance::new(&lone);
        let out = a.run(flags, &a.pair.display().to_string(), &envs);
        let text = all(&out);
        assert_eq!(out.status.code(), Some(2), "{what}: {text}");
        assert!(text.contains(refusal) && !text.contains("acceptance: roots"), "{what}: {text}");
        assert_eq!(a.calls(), Vec::<String>::new(), "{what}: the pair ran");
        assert_eq!(a.runner(), Vec::<String>::new(), "{what}: the runner asked before the refusal");
        assert!(!a.w.join("target/s8/acceptance").exists(), "{what}: a step's directory was made");
    }
    let a = Acceptance::new(&lone);
    let out = a.run(&[], &a.pair.display().to_string(), &[]);
    assert!(a.pair.display().to_string().contains('i'));
    assert!(out.status.success() && all(&out).ends_with("acceptance: ok: doctor, versions, creds, the negatives (a) to (h), the smoke; target/s8/acceptance removed\n"), "{}", all(&out));
}

// ---- S8: the scrub lists ----

/// The upper-case names a shell script reads (`$NAME`, `${NAME`).
fn shell_reads(text: &str) -> BTreeSet<String> {
    text.match_indices('$')
        .filter_map(|(i, _)| {
            let rest = &text[i + 1..];
            let rest = rest.strip_prefix('{').unwrap_or(rest);
            let name: String = rest.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
            (name.len() > 1 && name.starts_with(|c: char| c.is_ascii_uppercase())).then_some(name)
        })
        .collect()
}

/// Every `"AI_ENV_BRIDGE_<NAME>"` string literal of the Rust files under
/// `dir`, recursively: the knobs the code reads (a constant's value or a
/// name read in place).
fn bridge_knob_literals(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            bridge_knob_literals(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let text = read(&p);
            for (i, _) in text.match_indices("\"AI_ENV_BRIDGE_") {
                let rest = &text[i + 1..];
                let name: String = rest.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
                if rest[name.len()..].starts_with('"') && !name.ends_with('_') {
                    out.insert(name);
                }
            }
        }
    }
}

/// The string literals of `const NAME: [&str; N] = [...];` in `file`, its
/// comments left out; N, the length its type gives, is checked against them.
fn const_list(file: &Path, name: &str) -> BTreeSet<String> {
    let text = read(file);
    let head = format!("const {name}: [&str; ");
    let start = text.find(&head).unwrap_or_else(|| panic!("no {head} in {}", file.display())) + head.len();
    let n: usize = text[start..start + text[start..].find(']').unwrap()].parse().unwrap();
    let body = &text[start..start + text[start..].find("];").unwrap()];
    let names: Vec<String> = body.lines().map(|l| l.split("//").next().unwrap_or("")).flat_map(|l| l.split('"').skip(1).step_by(2).map(str::to_string).collect::<Vec<_>>()).collect();
    assert_eq!(names.len(), n, "{name} in {}: {names:?}", file.display());
    names.into_iter().collect()
}

/// The scrub lists hold every knob that would steer what they guard.
/// REMOVED_ENV (`tests/common/mod.rs`, every harness spawn): every
/// `AI_ENV_BRIDGE_*` knob the code reads but the bridge root, which each
/// harness sets, and every knob of the harness's fakes (claude-v2.sh,
/// claude.sh, age.sh, git.sh) but the four logs a spawn sets before its
/// removal. WRAPPER_ENV (`tests/wrapper.rs`, the exec tests): the same code
/// knobs, and the exec fake's (claude.sh) but its argv log. LAB_UNSET (the
/// Makefile's live targets): exactly the lab knobs the code and ops.sh read.
/// The census records the transcript knob's value. The code's knobs are its
/// `"AI_ENV_BRIDGE_*"` literals; that scan sees every knob constant.
#[test]
fn the_scrub_lists_hold_every_knob_the_code_and_the_fakes_read() {
    use ai_env_cli::bridge::{agent::conn::Trace, census::CENSUS_VALUE_ALLOWLIST, egress::check::FAKE_SHELL_KNOB, lab::VM_KNOBS, pump, remote, route::MODE_ENV};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut code = BTreeSet::new();
    bridge_knob_literals(&dir.join("src"), &mut code);
    let constants = [remote::TRANSCRIPT_KNOB, remote::PIN_KNOB, pump::SYNTHETIC_OAUTH_KNOB, pump::UNSEAL_TIMEOUT_KNOB, pump::MIRROR_ROOT_ENV, MODE_ENV, FAKE_SHELL_KNOB, Trace::ENV];
    for k in constants.into_iter().chain(VM_KNOBS) {
        assert!(code.contains(k), "the scan of src/ missed the knob constant {k}: {code:?}");
    }
    let knobs: BTreeSet<String> = code.iter().filter(|k| *k != "AI_ENV_BRIDGE_DIR").cloned().collect();
    let fakes = dir.join("tests/fakes");
    let reads = |fake: &str| shell_reads(&read(&fakes.join(fake)));
    let lacks = |list: &BTreeSet<String>, want: &BTreeSet<String>| want.difference(list).cloned().collect::<Vec<String>>();

    let removed = const_list(&dir.join("tests/common/mod.rs"), "REMOVED_ENV");
    let spawn_sets = ["ARGV_LOG", "FAKE_STDIN_LOG", "FAKE_ENV_LOG", "FAKE_SPAWN_COUNT"];
    let mut want = knobs.clone();
    for fake in ["claude-v2.sh", "claude.sh", "age.sh", "git.sh"] {
        want.extend(reads(fake).into_iter().filter(|n| (n.starts_with("FAKE_") || n.starts_with("GIT_") || n == "ARGV_LOG") && !spawn_sets.contains(&n.as_str())));
    }
    assert_eq!(lacks(&removed, &want), Vec::<String>::new(), "REMOVED_ENV (tests/common/mod.rs) lacks these");
    assert!(spawn_sets.iter().all(|n| !removed.contains(*n)), "Prepared::spawn sets {spawn_sets:?} before it removes REMOVED_ENV");

    let wrapper = const_list(&dir.join("tests/wrapper.rs"), "WRAPPER_ENV");
    let mut want = knobs.clone();
    want.extend(reads("claude.sh").into_iter().filter(|n| n.starts_with("FAKE_")));
    assert_eq!(lacks(&wrapper, &want), Vec::<String>::new(), "WRAPPER_ENV (tests/wrapper.rs) lacks these");
    assert!(!wrapper.contains("ARGV_LOG"), "the exec tests set the argv log before they remove WRAPPER_ENV");

    let t = tempfile::tempdir().unwrap();
    let vars = make_vars(t.path(), &[]);
    let unset: BTreeSet<String> = vars["LAB_UNSET"].split(" -u ").skip(1).map(str::to_string).collect();
    let mut want: BTreeSet<String> = knobs.iter().filter(|k| k.starts_with("AI_ENV_BRIDGE_LAB_")).cloned().collect();
    for script in std::fs::read_dir(Path::new(REPO).join("infra/scripts")).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sh")) {
        want.extend(shell_reads(&read(&script)).into_iter().filter(|n| n.starts_with("AI_ENV_BRIDGE_LAB_")));
    }
    assert_eq!(unset, want, "LAB_UNSET drops exactly the lab knobs the code and infra/scripts read");
    assert_eq!(vars["LAB_UNSET"], LAB_UNSET, "the dry-run tests' LAB_UNSET is the Makefile's");
    assert!(CENSUS_VALUE_ALLOWLIST.contains(&remote::TRANSCRIPT_KNOB), "the census records the transcript knob's value (skip forces the resume miss)");
}

// ---- phase 4 F9: make perf-wrapper PREWARM=1 (T8.6's offline half) ----

/// `make -n perf-wrapper`: T1.2's release run of tests/wrapper.rs's
/// overhead test. `PREWARM=1` on the command line adds the release run of
/// tests/prewarm.rs's (the prewarm's cost to `auth status`, T8.6), gated by
/// `AI_ENV_PERF_TESTS=1` like T1.2's; the same name in the environment adds
/// nothing. The `overhead` filter names that test, which is ignored outside
/// this target. Nothing runs.
#[test]
fn make_n_perf_wrapper_adds_the_prewarm_run_only_with_prewarm_1_on_the_command_line() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make(t.path(), &bin, &["-n"]).args(args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let release = "AI_ENV_PERF_TESTS=1 cargo +1.98.1 test --release -p ai-env-cli --features bridge";
    let t1_2 = format!("{release} --test wrapper -- --ignored overhead --nocapture --test-threads=1\n");
    let t8_6 = format!("{release} --test prewarm -- --ignored overhead --nocapture --test-threads=1\n");
    assert_eq!(dry(&["perf-wrapper"], &[]), t1_2);
    assert_eq!(dry(&["perf-wrapper", "PREWARM=1"], &[]), format!("{t1_2}{t8_6}"), "T1.2's run, then T8.6's");
    assert_eq!(dry(&["perf-wrapper"], &[("PREWARM", "1")]), t1_2, "PREWARM=1 in the environment is ignored");
    let prewarm = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/prewarm.rs"));
    let ignored = "#[ignore = \"perf measurement: make perf-wrapper PREWARM=1 (AI_ENV_PERF_TESTS=1, release)\"]\nfn t8_6_prewarm_auth_status_overhead_median_100_runs() {\n";
    assert!(prewarm.contains(ignored), "tests/prewarm.rs's perf test, which the overhead filter names, is no longer ignored as make perf-wrapper's");
    assert_eq!(read(&log), "", "make -n ran a tool");
}

// ---- S9 (G7): claude-update's node_modules ------------------------------------------------------

/// The steps' make of [`claude_update_checks_infra_node_modules_before_test_docker`]: each call logged; claude-pin
/// writes the lock and test-docker the zip, its image.json and its stamp, as the real ones do; a deploy moves the
/// stack outputs' claudeVersion to the version it deployed (FAKE_DEPLOYS).
const CLAUDE_UPDATE_FAKE_MAKE: &str = r#"printf 'make %s\n' "$*" >> "$FAKE_AIENV_LOG"
case " $* " in
  *" claude-pin "*) for a in "$@"; do case "$a" in CLAUDE_VERSION=*) printf 'CLAUDE_VERSION=%s\nCLAUDE_PLATFORM=linux-arm64\n' "${a#CLAUDE_VERSION=}" > "$LOCK" ;; esac; done ;;
  *" test-docker "*) v=$(sed -n 's/^CLAUDE_VERSION=//p' "$LOCK"); mkdir -p "$IMAGE_OUT"; printf 'a zip of %s' "$v" > "$IMAGE_OUT/image.zip"; printf '{"claudeVersion":"%s"}\n' "$v" > "$IMAGE_OUT/image.json"; shasum -a 256 "$IMAGE_OUT/image.zip" | cut -d' ' -f1 > "$IMAGE_OUT/test-docker.ok" ;;
  *" deploy "*) sed -i '' "s/\"claudeVersion\":\"[^\"]*\"/\"claudeVersion\":\"$FAKE_DEPLOYS\"/" "$FAKE_PULUMI_OUTPUTS" ;;
esac
exit 0"#;

/// S9 (S8's B9: claude-update ran make test-docker, then make deploy failed for want of infra/node_modules): with a
/// deploy due, claude-update checks the Pulumi program's `infra/node_modules` among its preconditions, before the
/// pin, make test-docker or any runner: without its tsc (make deploy's check-policies and plan check compile with it)
/// it refuses naming make infra-install, nothing run, nothing changed; with it, the run goes on to its first step. With
/// nothing to deploy it asks for none. ops.sh runs from a copy under the test's tempdir, so the `infra/` it takes for
/// the program's is the test's.
#[test]
fn claude_update_checks_infra_node_modules_before_test_docker() {
    let refusal = "/node_modules is missing (make deploy's check-policies and plan check run its tsc): make infra-install, then make claude-update: nothing changed";
    for (what, bundle, modules, refused) in [("a deploy due, no node_modules", "2.1.288", false, true), ("a deploy due, node_modules installed", "2.1.288", true, false), ("nothing to deploy, no node_modules", "2.1.287", false, false)] {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = s5_bin(t);
        script(&bin.join("make"), CLAUDE_UPDATE_FAKE_MAKE);
        script(&bin.join("docker"), "exit 0");
        script(&bin.join("curl"), "exit 6");
        std::fs::create_dir_all(t.join("image")).unwrap();
        let lock = "CLAUDE_VERSION=2.1.287\nCLAUDE_PLATFORM=linux-arm64\n";
        std::fs::write(t.join("image/claude.lock"), lock).unwrap();
        let mut o = outputs();
        o["claudeVersion"] = json!("2.1.287");
        o["latestActiveImageVersion"] = json!("3.0");
        o["bucket"] = json!("ai-env-artifacts-0000000");
        o["zipKey"] = json!("ai-env/image-0123456789abcdef.zip");
        write_outputs(t, &with_operators(o));
        std::fs::create_dir_all(t.join("aws/image")).unwrap();
        std::fs::write(t.join("aws/image/state"), "UPDATED").unwrap();
        std::fs::write(t.join("aws/image/active"), "3.0").unwrap();
        std::fs::write(t.join("aws/image/uri"), "s3://ai-env-artifacts-0000000/ai-env/image-0123456789abcdef.zip").unwrap();
        seed_proxy(t, "running");
        let ops = t.join("infra/scripts/ops.sh");
        std::fs::create_dir_all(ops.parent().unwrap()).unwrap();
        std::fs::copy(Path::new(REPO).join("infra/scripts/ops.sh"), &ops).unwrap();
        if modules {
            script(&t.join("infra/node_modules/.bin/tsc"), "exit 0");
        }
        let mut cmd = Command::new("/bin/bash");
        isolate(&mut cmd, t).env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
        s5_env(&mut cmd, t);
        let out = cmd
            .arg(&ops)
            .arg("claude-update")
            .current_dir(t)
            .env("REGION", "eu-central-1")
            .env("IMAGE_NAME", "ai-env-agent")
            .env("IMAGE_OUT", t.join("out"))
            .env("STACK", "dev")
            .env("IMAGE_WAIT_TIMEOUT", "5")
            .env("IMAGE_WAIT_POLL", "1")
            .env("VERSIONS_WARN", "40")
            .env("VERSIONS_QUOTA", "50")
            .env("CONNECTOR_WAIT_TIMEOUT", "5")
            .env("CONNECTOR_WAIT_POLL", "1")
            .env("AI_ENV_CLI", bin.join("ai-env-stand-in"))
            .env("LOCK", "image/claude.lock")
            .env("CLAUDE_RELEASES", "https://downloads.invalid/claude-code-releases")
            .env("CLAUDE_GPG_FPR", "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE")
            .env("FAKE_AIENV_BUNDLE", bundle)
            .env("FAKE_DEPLOYS", bundle)
            .env("AI_ENV_BRIDGE_LAB_ASSUME_TTY", "1")
            .env("PULUMI_CONFIG_PASSPHRASE_FILE", "/dev/null")
            .bounded();
        let text = all(&out);
        let c = calls(t);
        assert_eq!(text.contains(refusal), refused, "{what}: {text}");
        if refused {
            assert_eq!(out.status.code(), Some(1), "{what}: {text}");
            assert!(text.contains(&format!("claude-update: {}{refusal}", t.join("infra").display())) || text.contains("/infra/node_modules is missing ("), "{what}: the refusal names the program's directory: {text}");
            assert!(c.iter().all(|l| !l.starts_with("make ") && !l.starts_with("as ") && !l.starts_with("run ")), "{what}: nothing ran (no pin, no test-docker, no runner): {c:#?}");
            assert_eq!(std::fs::read_to_string(t.join("image/claude.lock")).unwrap(), lock, "{what}: the lock untouched");
            assert!(!t.join("out/claude-update.pending").exists(), "{what}: no deploy began");
        } else if modules {
            assert!(text.contains("claude-update [1/7] make claude-pin CLAUDE_VERSION=2.1.288") && c.iter().any(|l| l.starts_with("make --no-print-directory claude-pin CLAUDE_VERSION=2.1.288")), "{what}: past the check, its first step: {text}");
        } else {
            assert!(out.status.success() && text.contains("is pinned and deployed"), "{what}: {text}");
        }
    }
}

/// S9 phase 4 (the surviving mutant M38): the S3 gateway endpoint's policy
/// as `infra/policies.ts` builds it (`s3EndpointPolicy`, printed by
/// `scripts/print-policies.ts`, compiled with the infra's own tsc as
/// check-policies.sh compiles it and run with node, offline) is contracts
/// §7.3's for the example account: its canonical hash, in Rust
/// (`canonical_policy_sha256`) and in TypeScript (`canonicalPolicySha256`),
/// is the one `bridge::infra`'s test pins for §7.3's literal. Nothing else
/// holds policies.ts's document to it offline: the egress guard, the plan
/// check and the stack output compare policies.ts with itself, and
/// check-policies' simulation that our bucket outside `v1/` is denied needs
/// AWS. A widened resource (`<bucket>/*`), an action or a condition more or
/// less, fails here.
#[test]
fn the_endpoint_policy_of_policies_ts_is_the_pinned_one() {
    const PINNED: &str = "0e80ca5ab63a4465e3921f4247d90b35f8c941fdd124370bad974db63765ec27";
    let infra = Path::new(REPO).join("infra");
    let tsc = infra.join("node_modules/.bin/tsc");
    assert!(tsc.exists(), "{} is missing: make infra-install", tsc.display());
    let out = tempfile::tempdir().unwrap();
    let o = Command::new(&tsc)
        .args(["--strict", "--target", "es2022", "--module", "commonjs", "--moduleResolution", "node", "--types", "node", "--rootDir", ".", "--outDir"])
        .arg(out.path())
        .arg("scripts/print-policies.ts")
        .current_dir(&infra)
        .bounded();
    assert!(o.status.success(), "tsc: {}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let o = Command::new("node")
        .arg(out.path().join("scripts/print-policies.js"))
        .args(["--account-id", "123456789012", "--image-config", "image-config.json", "--egress-config", "egress-config.json", "--name", "s3-endpoint"])
        .current_dir(&infra)
        .bounded();
    assert!(o.status.success(), "print-policies: {}", String::from_utf8_lossy(&o.stderr));
    let doc = String::from_utf8(o.stdout).unwrap();
    assert_eq!(ai_env_cli::bridge::infra::canonical_policy_sha256(doc.trim()).unwrap(), PINNED, "policies.ts's endpoint policy is not §7.3's: {doc}");
    let policies = out.path().join("policies.js");
    let script = format!(
        "const p = require({:?}); process.stdout.write(p.canonicalPolicySha256(p.s3EndpointPolicy({{ accountId: '123456789012', transcriptsBucket: p.transcriptsBucketName('123456789012') }})));",
        policies.display().to_string()
    );
    let o = Command::new("node").args(["-e", &script]).bounded();
    assert_eq!(String::from_utf8_lossy(&o.stdout), PINNED, "TypeScript's own hash of it: {}", String::from_utf8_lossy(&o.stderr));
}

// ---- S9: test-aws SLOW=1, the code token's minutes ----

/// `make -n test-aws SLOW=1` (S9's re-mint after expiry, live_smart_http_remints_after_expiry): the keyless compile
/// (D2) sets no lab knob, and the run sets `AI_ENV_AWS_SLOW=1` and `AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2` after
/// `$(LAB_UNSET)`, as operands of its `env` after the `-u` list: env sets them once every knob is unset, so the test
/// process gets the minutes again (the commands and chats it runs drop every knob). Without SLOW=1 on the command
/// line (in the environment it is ignored) no line sets a lab knob or the slow switch. Nothing runs.
#[test]
fn make_n_test_aws_slow_1_sets_the_code_token_minutes_again_after_lab_unset() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make(t.path(), &bin, &["-n", "test-aws"]).args(args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let cargo = "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws";
    let compile = format!("{NO_KEY} {LAB_UNSET} {cargo} --no-run");
    let tail = format!("{cargo} -- --ignored --test-threads=1 --nocapture");
    let run_line = |text: &str| text.lines().find(|l| l.ends_with(&tail)).unwrap_or_else(|| panic!("no test run in the dry run: {text}")).to_string();
    // A knob set, not one an `-u` names: an `AI_ENV_BRIDGE_LAB_*=` word.
    let knobs_set = |text: &str| text.split_whitespace().filter(|w| w.starts_with("AI_ENV_BRIDGE_LAB_") && w.contains('=')).map(str::to_string).collect::<Vec<_>>();

    let slow = dry(&["SLOW=1"], &[]);
    assert_eq!(slow.lines().next(), Some(compile.as_str()), "the keyless compile first, no knob set: {slow}");
    // The `$(if …)`s that expand to nothing (S3, CRED) leave their spaces.
    assert_eq!(
        run_line(&slow),
        format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2  {tail}"),
        "env unsets every knob, then sets the minutes again for the test process"
    );
    assert_eq!(knobs_set(&slow), ["AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2"], "the minutes alone, on the run's line: {slow}");
    for (what, plain) in [("no SLOW", dry(&[], &[])), ("SLOW=1 in the environment, which is ignored", dry(&[], &[("SLOW", "1")]))] {
        assert_eq!(plain.lines().next(), Some(compile.as_str()), "{what}: {plain}");
        assert_eq!(run_line(&plain), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1   {tail}"), "{what}");
        assert!(knobs_set(&plain).is_empty() && !plain.contains("AI_ENV_AWS_SLOW"), "{what}: a lab knob or the slow switch set: {plain}");
    }
    assert_eq!(read(&log), "", "make -n ran a tool");
}

// ---- S10: test-aws S10=1 and S3=1 CHAT=dev ----

/// `make -n test-aws S10=1` (S10's live tests, `live_s10_*`): the keyless compile first (D2), then the run with
/// `AI_ENV_S10_TESTS=1` after `$(LAB_UNSET)` and the `live_s10_` filter. With SLOW=1 the three wall tests' switch,
/// `AI_ENV_AWS_SLOW=1`, alone: no lab knob (the code token's minutes are S9's re-mint test's, which the filter leaves
/// out). With S3=1 the two filters and gates add up. S10=1 in the environment is ignored, and the forms without it are
/// S9's lines unchanged. Nothing runs.
#[test]
fn make_n_test_aws_s10_1_runs_the_s10_tests_and_slow_1_adds_the_slow_switch_alone() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make(t.path(), &bin, &["-n", "test-aws"]).args(args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let cargo = "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws";
    let compile = format!("{NO_KEY} {LAB_UNSET} {cargo} --no-run");
    let tail = format!("{cargo} -- --ignored --test-threads=1 --nocapture");
    // The run's line: the one that starts with the lab knobs' removal (the compile's starts with the key's).
    let run_line = |text: &str| text.lines().find(|l| l.starts_with(LAB_UNSET)).unwrap_or_else(|| panic!("no test run in the dry run: {text}")).to_string();
    let knobs_set = |text: &str| text.split_whitespace().filter(|w| w.starts_with("AI_ENV_BRIDGE_LAB_") && w.contains('=')).map(str::to_string).collect::<Vec<_>>();

    let s10 = dry(&["S10=1"], &[]);
    assert_eq!(s10.lines().next(), Some(compile.as_str()), "the keyless compile first: {s10}");
    assert_eq!(run_line(&s10), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1  AI_ENV_S10_TESTS=1  {tail} live_s10_"));
    assert!(knobs_set(&s10).is_empty() && !s10.contains("AI_ENV_AWS_SLOW"), "{s10}");
    let slow = dry(&["S10=1", "SLOW=1"], &[]);
    assert_eq!(slow.lines().next(), Some(compile.as_str()), "{slow}");
    assert_eq!(run_line(&slow), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 AI_ENV_S10_TESTS=1  {tail} live_s10_"), "the wall tests' switch, no code token minutes");
    assert!(knobs_set(&slow).is_empty(), "a lab knob set for S10's tests: {slow}");
    assert_eq!(run_line(&dry(&["S10=1", "S3=1"], &[])), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1  AI_ENV_S3_TESTS=1 AI_ENV_S10_TESTS=1  {tail} live_s3_ live_s10_"));
    for (what, plain, line) in [
        ("no S10", dry(&[], &[]), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1   {tail}")),
        ("S10=1 in the environment, which is ignored", dry(&[], &[("S10", "1")]), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1   {tail}")),
        ("SLOW=1 without S10", dry(&["SLOW=1"], &[]), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1 AI_ENV_AWS_SLOW=1 AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES=2  {tail}")),
        ("S3=1 without S10", dry(&["S3=1"], &[("S10", "1")]), format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1  AI_ENV_S3_TESTS=1  {tail} live_s3_")),
    ] {
        assert_eq!(run_line(&plain), line, "{what}");
        assert!(!plain.contains("AI_ENV_S10_TESTS") && !plain.contains("live_s10_"), "{what}: {plain}");
    }
    assert_eq!(read(&log), "", "make -n ran a tool");
}

/// S10 (F12): `make test-aws S3=1 CHAT=dev` runs the S3 store's gib test alone (`live_s3_gib_round_trip_timing`, a
/// top-level test of tests/aws.rs and the only one its filter names) with `AI_ENV_S3_CHAT` set to the Makefile's
/// S3_CHAT_DEV, the development chat's shape (names and sizes only, set at part B's P0); a dry run shows the check
/// before it, after the keyless compile (D2). Run (cargo a stand-in that logs): another CHAT, CHAT=dev without S3=1,
/// and an empty or malformed S3_CHAT_DEV are exit 2 after the compile, before the tests; a well-formed one runs them
/// with the shape and no lab knob; CHAT only the environment names is ignored, and so is S3_CHAT_DEV (the Makefile's
/// line or the command line sets it: a stale export never picks the shape).
#[test]
fn test_aws_chat_dev_runs_the_gib_test_alone_on_the_dev_shape_or_refuses_before_the_tests() {
    let t = tempfile::tempdir().unwrap();
    let fakes: Vec<(&str, &str)> = MUST_NOT_RUN.iter().map(|n| ("logged.sh", *n)).collect();
    let bin = bin_with(t.path(), &fakes);
    let log = t.path().join("tools.log");
    let shape = "main=215,subtree=1650,files=40";
    let shape_arg = format!("S3_CHAT_DEV={shape}");
    let cargo = "cargo +1.98.1 test -p ai-env-cli --features bridge --test aws";
    let tail = format!("{cargo} -- --ignored --test-threads=1 --nocapture");
    let dry = |args: &[&str], envs: &[(&str, &str)]| {
        let out = make(t.path(), &bin, &["-n", "test-aws"]).args(args).env("FAKE_LOG", &log).envs(envs.iter().copied()).bounded();
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        stdout(&out)
    };
    let text = dry(&["S3=1", "CHAT=dev", shape_arg.as_str()], &[]);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], format!("{NO_KEY} {LAB_UNSET} {cargo} --no-run"), "the keyless compile first: {text}");
    assert!(lines[1].starts_with(&format!("chat='dev'; shape='{shape}'; case \"$chat\" in dev) ;; ")), "the check next: {text}");
    assert_eq!(lines[2], format!("{LAB_UNSET} AI_ENV_AWS_TESTS=1  AI_ENV_S3_TESTS=1 AI_ENV_S3_CHAT='{shape}'  {tail} live_s3_gib_round_trip_timing"));
    let s3 = dry(&["S3=1"], &[("CHAT", "dev"), ("S3_CHAT_DEV", shape)]);
    assert!(!s3.contains("chat=") && !s3.contains("AI_ENV_S3_CHAT") && s3.contains(&format!("{tail} live_s3_\n")), "CHAT=dev in the environment is ignored: {s3}");
    assert_eq!(read(&log), "", "make -n ran a tool");
    let aws = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/aws.rs"));
    assert!(aws.contains("\n#[test]\n#[ignore = ") && aws.contains("\nfn live_s3_gib_round_trip_timing() {\n"), "live_s3_gib_round_trip_timing is no longer a top-level test: make test-aws S3=1 CHAT=dev's filter names it");
    let named: Vec<&str> = aws.lines().filter(|l| l.starts_with("fn ") && l.contains("live_s3_gib_round_trip_timing")).collect();
    assert_eq!(named.len(), 1, "CHAT=dev's filter names more than the gib test: {named:?}");

    let tools = t.path().join("bin2");
    std::fs::create_dir_all(&tools).unwrap();
    script(
        &tools.join("cargo"),
        r#"printf 'cargo %s [TESTS=%s S3=%s CHAT=%s] [LAB=%s]\n' "$*" "${AI_ENV_AWS_TESTS-}" "${AI_ENV_S3_TESTS-}" "${AI_ENV_S3_CHAT-unset}" "$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | tr '\n' ' ')" >> "$FAKE_LOG""#,
    );
    let calls = t.path().join("cargo.log");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        std::fs::remove_file(&calls).ok();
        let out = make(t.path(), &tools, &["test-aws"]).args(args).env("FAKE_LOG", &calls).envs(envs.iter().copied()).bounded();
        (out, lines_of(&calls))
    };
    let compiled = format!("{cargo} --no-run [TESTS= S3= CHAT=unset] [LAB=]");
    let malformed = "S3_CHAT_DEV=main=215,subtree=1.6G,files=40";
    for (what, args, want) in [
        ("another chat", &["S3=1", "CHAT=gib", shape_arg.as_str()][..], "test-aws: CHAT=gib names no chat shape: make test-aws S3=1 CHAT=dev runs the gib test alone on the development chat's shape (S3_CHAT_DEV)"),
        ("CHAT=dev without S3=1", &["CHAT=dev", shape_arg.as_str()][..], "test-aws: CHAT=dev needs S3=1: make test-aws S3=1 CHAT=dev"),
        ("no shape", &["S3=1", "CHAT=dev"][..], "test-aws: S3_CHAT_DEV is empty: set it at part B's P0 to main=<MiB>,subtree=<MiB>,files=<n>, from the development chat's file names and sizes only (never its content)"),
        ("a malformed shape", &["S3=1", "CHAT=dev", malformed][..], "test-aws: S3_CHAT_DEV=main=215,subtree=1.6G,files=40 is not main=<MiB>,subtree=<MiB>,files=<n>"),
    ] {
        let (out, calls) = run(args, &[("AI_ENV_BRIDGE_LAB_FAKE_API", "/f.json")]);
        assert_eq!(out.status.code(), Some(2), "{what}: {}", all(&out));
        assert!(all(&out).contains(want), "{what}: {}", all(&out));
        assert_eq!(calls, vec![compiled.clone()], "{what}: the keyless compile alone, no test run");
    }
    // A shape only the environment gives (a stale export) is ignored: the run stops as with none.
    let (out, calls) = run(&["S3=1", "CHAT=dev"], &[("S3_CHAT_DEV", shape)]);
    assert_eq!(out.status.code(), Some(2), "{}", all(&out));
    assert!(all(&out).contains("test-aws: S3_CHAT_DEV is empty"), "the environment's S3_CHAT_DEV is ignored: {}", all(&out));
    assert_eq!(calls, vec![compiled.clone()], "the keyless compile alone, no test run");
    let (out, calls) = run(&["S3=1", "CHAT=dev", shape_arg.as_str()], &[("AI_ENV_BRIDGE_LAB_FAKE_API", "/f.json")]);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(calls, vec![compiled.clone(), format!("{tail} live_s3_gib_round_trip_timing [TESTS=1 S3=1 CHAT={shape}] [LAB=]")], "the gib test alone, its shape, no lab knob");
    let (out, calls) = run(&["S3=1"], &[("CHAT", "gib"), ("S3_CHAT_DEV", "x")]);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(calls, vec![compiled, format!("{tail} live_s3_ [TESTS=1 S3=1 CHAT=unset] [LAB=]")], "CHAT in the environment is ignored: the S3 suite, no shape");
}
