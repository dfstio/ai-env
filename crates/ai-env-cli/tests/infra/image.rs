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
    let what = format!("{cmd:?}");
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

/// `$(LAB_UNSET)` as the live recipes run it: the fourteen lab knobs
/// (`the_scrub_lists_hold_every_knob_the_code_and_the_fakes_read` holds the
/// Makefile's list to every one the code and ops.sh read).
const LAB_UNSET: &str = "env -u AI_ENV_BRIDGE_LAB_FAKE_API -u AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL -u AI_ENV_BRIDGE_LAB_BACKOFF_MS -u AI_ENV_BRIDGE_LAB_FAKE_SHELL -u AI_ENV_BRIDGE_LAB_ASSUME_TTY -u AI_ENV_BRIDGE_LAB_AGENT_ADDR -u AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS -u AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS -u AI_ENV_BRIDGE_LAB_TRANSCRIPT -u AI_ENV_BRIDGE_LAB_EXIT -u AI_ENV_BRIDGE_LAB_IGNORE_EOF -u AI_ENV_BRIDGE_LAB_STDOUT_NOISE -u AI_ENV_BRIDGE_LAB_DELAY_INIT_MS -u AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS";

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
    let rk = text.lines().skip_while(|l| !l.ends_with("creds aws-set --check")).take_while(|l| !l.contains("pulumi destroy")).collect::<Vec<_>>().join("\n");
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
    assert!(env[0].starts_with("AI_ENV_DOCKER_TESTS=1 ") && env[0].contains(" AI_ENV_DOCKER_IMAGE='ai-env-agent:local' "), "{env:?}");
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

// ---- runtime-key (stateful fake aws, the ai-env stand-in) ----

fn key_id(n: u32) -> String {
    format!("AKIAFAKE{n:012}")
}

/// A temp tree for runtime-key: the stateful fake aws (state in `aws/`), a
/// logged no-op `sleep`, the ai-env stand-in; `keys` access keys exist.
fn rk_tree(keys: u32) -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let bin = bin_with(t.path(), &[("aws-state.sh", "aws"), ("logged.sh", "sleep"), ("ai-env.sh", "ai-env-stand-in")]);
    let state = t.path().join("aws");
    std::fs::create_dir_all(&state).unwrap();
    let ids: String = (1..=keys).map(|n| key_id(n) + "\n").collect();
    std::fs::write(state.join("keys"), ids).unwrap();
    std::fs::write(state.join("next"), format!("{}\n", keys + 1)).unwrap();
    (t, bin)
}

fn runtime_key(t: &Path, bin: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    make(t, bin, &["runtime-key"])
        .args(args)
        .arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display()))
        .env("FAKE_AWS_STATE", t.join("aws"))
        .env("FAKE_AWS_LOG", t.join("aws.log"))
        .env("FAKE_AIENV_LOG", t.join("ai-env.log"))
        .env("FAKE_LOG", t.join("sleep.log"))
        .envs(envs.iter().copied())
        .bounded()
}

/// The stand-in's decrypts (`ai-env run`), one Touch ID prompt each.
fn decrypts(t: &Path) -> Vec<String> {
    lines_of(&t.join("ai-env.log")).into_iter().filter(|l| l.starts_with("run ")).collect()
}

fn aws_calls(t: &Path, prefix: &str) -> usize {
    lines_of(&t.join("aws.log")).iter().filter(|l| l.starts_with(prefix)).count()
}

fn delete_cmd(id: &str) -> String {
    format!("aws iam delete-access-key --user-name ai-env-runtime --access-key-id {id} --region eu-central-1")
}

#[test]
fn runtime_key_verifies_once_with_the_key_the_container_names() {
    // Sealed to a non-default [creds].key; IAM needs two more sts calls to propagate.
    let (t, bin) = rk_tree(0);
    std::fs::write(t.path().join("aws/sts-fails"), "2\n").unwrap();
    let out = runtime_key(t.path(), &bin, &[], &[("FAKE_AIENV_KEY", "team-key")]);
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("the sealed key ...{} identifies as user/ai-env-runtime", &key_id(1)[16..])), "{all}");
    assert!(!all.contains(&key_id(1)), "a verified key is named by its tail only: {all}");
    let runs = decrypts(t.path());
    assert_eq!(runs.len(), 1, "one decrypt, one Touch ID prompt: {runs:?}");
    assert!(!runs[0].contains(" -k "), "ai-env run picks the key from the container: {runs:?}");
    assert_eq!(aws_calls(t.path(), "sts get-caller-identity"), 3, "the retries run inside the child: {all}");
    assert_eq!(lines_of(&t.path().join("sleep.log")).len(), 2, "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1)]);
}

#[test]
fn runtime_key_stops_at_a_failed_decrypt_without_retrying() {
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[], &[("FAKE_AIENV_RUN", "cancel")]);
    let all = all(&out);
    assert!(!out.status.success() && all.contains("ai-env run failed (exit 3)") && all.contains("NOT verified"), "{all}");
    assert!(!all.contains("IAM propagation"), "a cancelled prompt is not propagation: {all}");
    assert_eq!(decrypts(t.path()).len(), 1, "no second prompt: {all}");
    assert_eq!(aws_calls(t.path(), "sts "), 0, "{all}");
    assert_eq!(aws_calls(t.path(), "iam delete-access-key"), 0, "nothing deleted: {all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1)]);
}

#[test]
fn runtime_key_decides_from_iam_whether_a_key_was_created() {
    // IAM created the key but the response was lost, or the sealer exited
    // before reading (the CLI then fails writing into the closed pipe, or
    // not, by timing): either way the new id is named with its delete command.
    for (what, envs) in [("a lost response", [("FAKE_AWS_CREATE", "lost")]), ("a sealer that never read", [("FAKE_AIENV_SEAL", "early")])] {
        let (t, bin) = rk_tree(0);
        let out = runtime_key(t.path(), &bin, &[], &envs);
        let all = all(&out);
        assert!(!out.status.success(), "{what}: {all}");
        assert!(all.contains(&format!("the new key(s) {} are sealed nowhere", key_id(1))) && all.contains(&delete_cmd(&key_id(1))), "{what}: {all}");
        assert!(!all.contains("none was created") && !all.contains("no key was created"), "{what}: {all}");
        assert_eq!(decrypts(t.path()).len(), 0, "{what}: nothing to verify");
    }
    // Nothing created.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[], &[("FAKE_AWS_CREATE", "fail")]);
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
    let out = runtime_key(t.path(), &bin, &["ROTATE=1"], &[("FAKE_AWS_KEY_USER", "someone-else")]);
    let all_t = all(&out);
    assert!(!out.status.success(), "{all_t}");
    let baks: Vec<PathBuf> = std::fs::read_dir(&creds).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".bak")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert_eq!(read(&baks[0]), format!("FAKE-SEALED {}\n", key_id(1)), "the backup holds the previous key");
    assert!(all_t.contains(&delete_cmd(&key_id(2))), "{all_t}");
    assert!(all_t.contains(&format!("mv \"{}\" \"{}\"", baks[0].display(), creds.join("aws.env").display())), "the undo restores the backup: {all_t}");
    assert!(all_t.contains(&format!("the previous key {} is still active and sealed in {}", key_id(1), baks[0].display())), "{all_t}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted");

    // The rotation that verifies deletes the old key.
    let (t, bin, _) = setup();
    let out = runtime_key(t.path(), &bin, &["ROTATE=1"], &[]);
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("rotated; deleted the old key {}", key_id(1))), "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(2)]);
}

#[test]
fn runtime_key_names_every_extra_new_key_with_its_own_delete_command() {
    // A retried create-access-key left two new keys; aws-set sealed the second.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[], &[("FAKE_AWS_CREATE", "twice")]);
    let all = all(&out);
    assert!(out.status.success(), "the sealed key verifies: {all}");
    assert!(all.contains(&format!("the sealed key ...{} identifies as user/ai-env-runtime", &key_id(2)[16..])), "only the sealed id is named: {all}");
    assert!(all.contains(&format!("besides the sealed {}", key_id(2))) && all.contains(&delete_cmd(&key_id(1))), "the unsealed extra key gets its own delete command: {all}");
    assert!(!all.contains(&delete_cmd(&key_id(2))), "never the sealed one: {all}");
    assert!(!all.contains(&format!("{} {}", key_id(1), key_id(2))), "no two ids in one argument: {all}");

    // The same two keys, and the sealed one does not verify: the undo names
    // only the sealed id, the extra one keeps its own line.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[], &[("FAKE_AWS_CREATE", "twice"), ("FAKE_AWS_KEY_USER", "someone-else")]);
    let text = self::all(&out);
    assert!(!out.status.success(), "{text}");
    assert_eq!(text.matches(&delete_cmd(&key_id(2))).count(), 1, "the undo deletes the sealed key once: {text}");
    assert_eq!(text.matches(&delete_cmd(&key_id(1))).count(), 1, "the extra key: {text}");
    assert!(text.lines().all(|l| !(l.contains(&key_id(1)) && l.contains(&key_id(2)) && l.contains("--access-key-id"))), "no command names both: {text}");
}

#[test]
fn runtime_key_verifies_with_the_sealed_key_alone() {
    // The operator's shell carries a session token (aws-vault, SSO): it must
    // not reach the verification child, or sts rejects the sealed key.
    let (t, bin) = rk_tree(0);
    let out = runtime_key(t.path(), &bin, &[], &[("AWS_SECURITY_TOKEN", "operator-token"), ("AWS_SESSION_TOKEN", "operator-token"), ("AWS_CREDENTIAL_EXPIRATION", "2000-01-01T00:00:00Z")]);
    let all = all(&out);
    assert!(out.status.success() && all.contains(&format!("the sealed key ...{} identifies as user/ai-env-runtime", &key_id(1)[16..])), "{all}");
}

#[test]
fn runtime_key_never_deletes_the_key_the_verified_container_still_holds() {
    // aws-set sealed somewhere else: the verified container still holds the
    // previous key, so ROTATE=1 must not delete it.
    let (t, bin) = rk_tree(1);
    let creds = t.path().join("bridge/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
    let out = runtime_key(t.path(), &bin, &["ROTATE=1"], &[("FAKE_AIENV_SEAL_DIR", t.path().join("elsewhere").to_str().unwrap())]);
    let all = all(&out);
    assert!(!out.status.success() && all.contains(&format!("still holds the previous key {}", key_id(1))) && all.contains("Nothing deleted"), "{all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted: {all}");
}

#[test]
fn runtime_key_verifies_even_when_the_listing_after_sealing_fails() {
    // ROTATE=1: the first listing (before) works, the one after sealing fails.
    let (t, bin) = rk_tree(1);
    let creds = t.path().join("bridge/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("aws.env"), format!("FAKE-SEALED {}\n", key_id(1))).unwrap();
    let out = runtime_key(t.path(), &bin, &["ROTATE=1"], &[("FAKE_AWS_LIST_FAIL_FROM", "2"), ("FAKE_AWS_KEY_USER", "someone-else")]);
    let all = all(&out);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("cannot list the keys of ai-env-runtime after sealing") && all.contains("verifying the sealed key anyway"), "{all}");
    assert_eq!(decrypts(t.path()).len(), 1, "it still verified: {all}");
    let bak: Vec<PathBuf> = std::fs::read_dir(&creds).unwrap().flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".bak")).collect();
    assert_eq!(bak.len(), 1, "{all}");
    assert!(all.contains(&delete_cmd(&key_id(2))) && all.contains(&format!("mv \"{}\"", bak[0].display())), "the full undo names the sealed id and the backup: {all}");
    assert_eq!(lines_of(&t.path().join("aws/keys")), vec![key_id(1), key_id(2)], "nothing deleted");
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
        .env("FAKE_CL_BOOTSTRAP", t.path().join("fresh"))
        .env("FAKE_CL_LOG", t.path().join("cl.log"))
        .bounded();
    let all = all(&out);
    assert!(out.status.success(), "{all}");
    assert_eq!(std::fs::read(w.join("image/ai-env")).unwrap(), arm64_elf("fresh bootstrap"), "image/ai-env is this build's: {all}");
    assert!(lines_of(&t.path().join("cl.log")).iter().any(|l| l.contains("build") && l.contains("--lambda-dir target/lambda")), "{all}");
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
    assert_eq!(lines_of(&log), vec!["infra base-image --name al2023-1 --version 1 [AI_ENV=unset]".to_string()]);
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
    let out = make(t.path(), &bin, &["image-status", &arg]).env("FAKE_LOG", t.path().join("tools.log")).bounded();
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
/// only when `egress_config`), ops.sh and image/Dockerfile.
fn planted_repo(tmp: &Path, egress_config: bool) -> PathBuf {
    let w = tmp.join("w");
    let mut files = vec!["Makefile", "infra/infra.mk", "infra/image-config.json", "infra/scripts/ops.sh", "image/Dockerfile"];
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
    assert!(!out.status.success() && err.contains(&format!("DELETING {name} FAILED 6 times")) && err.contains(&format!("aws lambda-core delete-network-connector --identifier {name} {LAMBDA_PIN}")), "{}", all(&out));
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
    // A delete command for ours only: a probe of the stack's connector, or one on the VM subnet.
    for ours in ["ai-env-egress-probe-1790000000", "hand-made"] {
        assert!(text.contains(&format!("    aws lambda-core delete-network-connector {LAMBDA_PIN} --identifier {ours}\n")), "{ours}: {text}");
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

    // make connector-delete stops there: the stack's connector stays.
    let mut cmd = make(t.path(), &bin, &["connector-delete", "CONFIRM=delete-connector"]);
    let out = s5_env(&mut cmd, t.path()).bounded();
    assert!(!out.status.success() && all(&out).contains("other than the stack's"), "{}", all(&out));
    assert!(!t.path().join("aws/deleted").exists() && t.path().join("aws/connectors").join(CONNECTOR).is_dir());

    // The stack's connector alone passes on to the VM check; a failed listing refuses.
    std::fs::remove_dir_all(t.path().join("aws/connectors/ai-env-egress-probe-1790000000")).unwrap();
    let out = ops5(t.path(), &bin, &["vm-guard"]).bounded();
    assert!(out.status.success() && all(&out).contains("vm-guard: no network connector but the stack's ai-env-egress") && all(&out).contains("no image ai-env-agent, hence no VM of it"), "{}", all(&out));
    let out = ops5(t.path(), &bin, &["vm-guard"]).env("FAKE_AWS_FAIL_OP", "lambda-core list-network-connectors").bounded();
    assert!(!out.status.success() && all(&out).contains("list-network-connectors failed"), "{}", all(&out));
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
    let mut cmd = make(t.path(), &bin, &["connector-delete", "CONFIRM=delete-connector", "CONNECTOR_WAIT_POLL=1"]);
    let out = s5_env(&mut cmd, t.path()).bounded();
    let text = all(&out);
    assert!(out.status.success() && text.contains("connector-delete: ai-env-egress is gone after"), "{text}");
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
    let wait = run(&["connector-wait"]);
    assert!(!wait.status.success() && all(&wait).contains("no connectorName in"), "{}", all(&wait));
    assert_eq!(calls(t.path()), Vec::<String>::new(), "nothing ran without the names");
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
    let (out, c) = run(&["egress-logs"], &[]);
    assert!(out.status.success() && stdout(&out).contains("TCP_TUNNEL/200 5120 CONNECT api.anthropic.com:443"), "{}", all(&out));
    assert_eq!(c, vec!["logs tail /ai-env/egress/squid --since 1h --format short --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com"]);
    let (_, c) = run(&["egress-logs", "FOLLOW=1", "SINCE=15m"], &[]);
    assert_eq!(c, vec!["logs tail /ai-env/egress/squid --since 15m --format short --follow --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com"]);
    for (args, want) in [
        (&["allowlist-reload"][..], "egress reload [AI_ENV=unset]"),
        (&["proxy-stop"][..], "proxy stop [AI_ENV=unset]"),
        (&["proxy-stop", "YES=1"][..], "proxy stop --yes [AI_ENV=unset]"),
        (&["proxy-start"][..], "proxy start [AI_ENV=unset]"),
        (&["proxy-patch"][..], "proxy patch [AI_ENV=unset]"),
    ] {
        let (out, c) = run(args, &[]);
        assert!(out.status.success(), "{args:?}: {}", all(&out));
        assert_eq!(c, vec![want.to_string()], "{args:?}");
    }
    let (_, c) = run(&["proxy-stop"], &[("YES", "1")]);
    assert_eq!(c, vec!["proxy stop [AI_ENV=unset]".to_string()], "YES=1 in the environment is ignored");
    let (out, _) = run(&["proxy-stop"], &[("FAKE_AIENV_PROXY_RC", "9")]);
    assert!(!out.status.success() && all(&out).contains("Error 9"), "the operator CLI's refusal stops make: {}", all(&out));
}

/// A fake `cargo` for test-egress: logs its argv, the egress switches and any
/// lab knob it sees, prints a live test's skip line to stderr when
/// FAKE_CARGO_SKIP is set, then exits FAKE_CARGO_RC, or (FAKE_CARGO_MARKER
/// set) touches the marker and sleeps until a signal ends it.
const CARGO_FAKE: &str = r##"lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
printf 'cargo %s [AI_ENV_AWS_TESTS=%s AI_ENV_EGRESS_TESTS=%s]%s\n' "$*" "${AI_ENV_AWS_TESTS:-}" "${AI_ENV_EGRESS_TESTS:-}" "${lab:+ [LAB=${lab% }]}" >> "$FAKE_AIENV_LOG"
if [ -n "${FAKE_CARGO_SKIP:-}" ]; then echo "live_egress_extra_and_removal: skipped: github.com is allowlisted outside this test" >&2; fi
if [ -n "${FAKE_CARGO_MARKER:-}" ]; then touch "$FAKE_CARGO_MARKER"; exec sleep 60; fi
exit "${FAKE_CARGO_RC:-0}""##;

#[test]
fn test_egress_removes_the_test_entry_on_every_exit() {
    let removal = "egress allow ai-env-test github.com --remove [AI_ENV=unset]";
    let setup = || {
        let t = tempfile::tempdir().unwrap();
        let bin = bin_with(t.path(), &[("ai-env.sh", "ai-env-stand-in")]);
        script(&bin.join("cargo"), CARGO_FAKE);
        (t, bin)
    };
    let test_egress = |t: &Path, bin: &Path| {
        let mut cmd = make(t, bin, &["test-egress"]);
        cmd.arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_LOG", t.join("calls.log"));
        cmd
    };
    // Success and failure: the tests ran with the switches, then the removal.
    for (rc, ok) in [("0", true), ("101", false)] {
        let (t, bin) = setup();
        let out = test_egress(t.path(), &bin).env("FAKE_CARGO_RC", rc).bounded();
        let text = all(&out);
        assert_eq!(out.status.success(), ok, "cargo exit {rc}: {text}");
        assert!(text.contains("test-egress: removing the test allowlist entry (ai-env egress allow ai-env-test github.com --remove)"), "it says what it does: {text}");
        let c = calls(t.path());
        assert_eq!(c.len(), 2, "{c:#?}");
        assert!(c[0].starts_with("cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored live_egress_ --test-threads=1 --nocapture [AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1]"), "{c:#?}");
        assert_eq!(c[1], removal);
    }
    // A live test that skipped its proof (github.com allowlisted outside it) is no pass, though cargo exits 0; the
    // removal runs all the same, and the output's copy is gone.
    let (t, bin) = setup();
    let out = test_egress(t.path(), &bin).env("FAKE_CARGO_SKIP", "1").env("TMPDIR", t.path()).bounded();
    let text = all(&out);
    assert!(!out.status.success() && text.contains("live_egress_extra_and_removal: skipped:") && text.contains("test-egress: a live egress test skipped its proof (its skipped: line above), so this is not a pass"), "{text}");
    assert_eq!(calls(t.path()).last().map(String::as_str), Some(removal), "{text}");
    assert!(std::fs::read_dir(t.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with("ai-env-test-egress.")), "the log is removed on exit");
    // A removal that fails is loud and fails the target.
    let (t, bin) = setup();
    let out = test_egress(t.path(), &bin).env("FAKE_AIENV_ALLOW_RC", "7").bounded();
    assert!(!out.status.success() && all(&out).contains("test-egress: the removal FAILED: github.com may still be allowed for every vpc VM"), "{}", all(&out));
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
    assert_eq!(calls(t.path()).last().map(String::as_str), Some(removal), "{:?}: {}", calls(t.path()), all(&out));
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
        &["test-cursor", "STEP=t8_3"],
    ];
    for args in live {
        let out = run(args);
        assert!(out.status.success(), "{args:?}: {}", all(&out));
    }
    let c = calls(t.path());
    let children: Vec<&String> = c.iter().filter(|l| l.contains("[AI_ENV=") || l.starts_with("cargo ")).collect();
    assert_eq!(children.len(), 3 + 3 + 3 + 2 + 1 + 1 + 1 + 4 + 1 + 1, "three s5, s6 and s7 smokes, test-egress's cargo and removal, test-claude's and test-aws's cargo, the probe's lab run, the four operator calls, s8-smoke's and test-cursor's cargo: {children:#?}");
    assert!(children.iter().all(|l| !l.contains("[LAB=")), "a lab knob reached a live command: {children:#?}");
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
        &format!("aws lambda-core list-network-connectors {LAMBDA_PIN}   # no ai-env-egress, no ai-env-egress-probe-* connector") as &str,
        "aws ec2 describe-vpcs --filters Name=cidr,Values=10.42.0.0/16 Name=tag:Project,Values=ai-env --region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com",
        "aws ec2 describe-network-acls --filters Name=tag:Name,Values=ai-env-egress-vms",
        "Name=tag:Name,Values=ai-env-egress-proxy",
        "aws ssm get-parameters --names /ai-env/proxy/squid.conf /ai-env/proxy/allow /ai-env/proxy/extras /ai-env/proxy/suspended",
        "--log-group-name-prefix /ai-env/egress --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com   # no /ai-env/egress/squid",
        "aws iam get-role --role-name ai-env-egress-operator --region eu-central-1; aws iam get-role --role-name ai-env-egress-proxy --region eu-central-1",
        "remove egress_connector_arn and proxy_private_ip",
        &format!("state/egress-verified.toml ({}/state/egress-verified.toml): its records are bound to the deleted connector's Id and no longer admit anything; remove it", t.path().join("bridge").display()),
    ] {
        assert!(text.contains(want), "want {want}: {text}");
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
/// version 3 and a connector that is PENDING once more.
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
        write_outputs(t.path(), &outputs());
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
        let t = self.t.path();
        std::fs::write(t.join("plan.json"), p.to_string()).unwrap();
        let mut cmd = make_in(t, &self.bin, &self.w, &["deploy"]);
        s5_env(&mut cmd, t)
            .arg(format!("AI_ENV={}", self.bin.join("ai-env-stand-in").display()))
            .arg(format!("CARGO_LAMBDA={}", self.bin.join("cargo-lambda").display()))
            .arg(format!("LLVM_BIN={}", t.join("llvm").display()))
            .args(["EXPECT_BUILD_FAILURE=1", "CONNECTOR_WAIT_POLL=1", "CONNECTOR_WAIT_TIMEOUT=10", "IMAGE_WAIT_POLL=1", "IMAGE_WAIT_TIMEOUT=10"])
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
    assert!(text.contains("make: *** [deploy] Error 1"), "the image-wait's failure is the deploy's: {text}");

    // `pulumi up` itself fails: the same egress steps, its exit status.
    let d = DeployTree::new(CHECK_PLAN_FAKE);
    let out = d.deploy(&deploy_plan(&[]), &[("FAKE_PULUMI_UP_RC", "255")]);
    let text = all(&out);
    assert!(!out.status.success() && text.contains("make: *** [deploy] Error 255") && text.contains("deploy: egress status skipped: the deploy failed"), "{text}");
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
    assert_eq!(calls(d.t.path()).last().map(String::as_str), Some("egress status [AI_ENV=unset]"), "the drift check is the last step");
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
    let c = calls(d.t.path());
    assert!(!c.iter().any(|l| l.starts_with("check-plan") || l.starts_with("pulumi up")), "{c:#?}");
}

/// `make claude-update` (ops.sh claude-update): it follows the installed Cursor bundle, does only what is not current
/// (pin, test-docker unless it passed for the zip, deploy, infra-status, the live active version, proxy-start, the
/// egress check --if-needed), stops at the first failure naming the step, refuses before changing anything without a
/// terminal, the passphrase, Docker, the AWS identity, a bundle, or under make -i or -k, stops on a rollback or a pin
/// it cannot follow, resumes all of a deploy's steps after a failure past it (the marker), and says what it found on
/// the way (the release site, a downgrade, a proxy it started, VMs on another version, the version count and which old
/// versions no VM runs).
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
    }
    let full = vec![TTY, PASS];
    let c = |what, bundle, locked, deployed, envs: Vec<(&'static str, &'static str)>, world, code, steps: Vec<&'static str>, wants: Vec<&'static str>| Case { what, bundle, locked, deployed, envs, world, code, steps, wants };
    let cases: Vec<Case> = vec![
        c("up to date", "2.1.287", "2.1.287", "2.1.287", vec![], World::Plain, 0, vec![status, check], vec!["claude-update: 2.1.287 is pinned and deployed: nothing to build or deploy", "claude-update [2/3] new VMs start the deployed image version", "claude-update: new VMs start image version 3.0, the deployed one, built from ai-env/image-0123456789abcdef.zip", "done: new VMs start image version 3.0 with Claude Code 2.1.287"]),
        c("a new bundle", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["claude-update [1/7] make claude-pin CLAUDE_VERSION=2.1.288", "claude-update [6/7] make proxy-start (squid serving the deployed parameters)", "the new pin rests on the release manifest over HTTPS only", "make test-egress, the broader live test the deploy names, is not part of the daily update"]),
        c("pinned, not deployed", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::Plain, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker"]),
        c("the zip already tested", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::Stamped, 0, vec![deploy, status, proxy, check], vec!["make test-docker already passed for", "claude-update [1/5] make deploy"]),
        c("a failed deploy", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_MAKE_FAIL", "deploy")], World::Plain, 2, vec![PIN288, test, deploy], vec!["claude-update: STOPPED at step 3/7 (make deploy: exit 2)"]),
        c("a failed check", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_AIENV_CHECK_RC", "3")], World::Plain, 3, vec![status, check], vec!["STOPPED at step 3/3 (ai-env egress check --if-needed: exit 3)"]),
        c("a rollback", "2.1.287", "2.1.287", "2.1.287", vec![], World::Rollback, 1, vec![status], vec!["new VMs start image version 3.0, not the deployed 4.0 (a rollback with make image-deactivate or image-activate?)", "make image-activate VERSION=4.0", "STOPPED at step 2/3"]),
        c("no terminal", "2.1.288", "2.1.287", "2.1.287", vec![PASS], World::Plain, 1, vec![], vec!["claude-update: needs a terminal"]),
        c("no passphrase", "2.1.288", "2.1.287", "2.1.287", vec![TTY], World::Plain, 1, vec![], vec!["claude-update: export PULUMI_CONFIG_PASSPHRASE_FILE first"]),
        c("Docker down", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_DOCKER_RC", "1")], World::Plain, 1, vec![], vec!["claude-update: Docker does not answer (docker info)"]),
        c("make -k", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("MAKEFLAGS", " --no-print-directory -k")], World::Plain, 2, vec![], vec!["claude-update: not under make -i or -k"]),
        c("a variable is no flag", "2.1.287", "2.1.287", "2.1.287", vec![("MAKEFLAGS", "kind=1")], World::Plain, 0, vec![status, check], vec!["is pinned and deployed"]),
        c("no bundle", "", "2.1.287", "2.1.287", full.clone(), World::Plain, 1, vec![], vec!["claude-update: cannot read the Cursor bundle's version (ai-env infra pin --bundle-version: exit 1, above; exit 1 when no bundle is installed): nothing changed"]),
        c("not a version", "2.1.288;id", "2.1.287", "2.1.287", full.clone(), World::Plain, 1, vec![], vec!["printed \"2.1.288;id\", not a version: nothing changed"]),
        c("no stack outputs", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_PULUMI_OUTPUTS", "/nonexistent/outputs.json")], World::Plain, 1, vec![], vec!["claude-update: cannot read the stack outputs of dev"]),
        c("the release site ahead", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_LATEST", "2.1.289")], World::Plain, 0, vec![status, check], vec!["the release site's latest 2.1.289 is newer than the Cursor bundle 2.1.287", "once Cursor updates the extension, run make claude-update again"]),
        c("the bundle ahead", "2.1.287", "2.1.287", "2.1.287", vec![("FAKE_LATEST", "2.1.286")], World::Plain, 0, vec![status, check], vec!["the Cursor bundle 2.1.287 is ahead of the release site's latest 2.1.286"]),
        c("a downgrade", "2.1.286", "2.1.287", "2.1.287", full.clone(), World::Plain, 0, vec![PIN286, test, deploy, status, proxy, check], vec!["a DOWNGRADE: the Cursor bundle 2.1.286 is older than the deployed 2.1.287"]),
        c("no lock", "2.1.288", "", "2.1.287", full.clone(), World::Plain, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["image/claude.lock (none)"]),
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
        c("a stamp of another zip", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::StampedStale, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker", "!already passed"]),
        c("a stamp of another claude", "2.1.287", "2.1.287", "2.1.286", full.clone(), World::StampedOtherClaude, 0, vec![test, deploy, status, proxy, check], vec!["claude-update [1/6] make test-docker", "!already passed"]),
        c("pinned to the deployed version", "2.1.287", "2.1.287", "2.1.287", vec![], World::PinnedDeployed, 0, vec![status, check], vec!["bridge.toml's [aws].image_version = \"3\" pins new VMs to the deployed 3.0 today, but no later update will reach them"]),
        c("a pin it cannot read", "2.1.287", "2.1.287", "2.1.287", vec![], World::PinnedUnreadable, 1, vec![status], vec!["bridge.toml names image_version in a form this script does not read (aws = { image_version = \"1\" })", "STOPPED at step 2/3"]),
        c("a failed check after a deploy", "2.1.288", "2.1.287", "2.1.287", vec![TTY, PASS, ("FAKE_AIENV_CHECK_RC", "3")], World::Plain, 3, vec![PIN288, test, deploy, status, proxy, check], vec!["STOPPED at step 7/7 (ai-env egress check --if-needed: exit 3)"]),
        c("a deploy's run resumed", "2.1.287", "2.1.287", "2.1.287", vec![], World::Pending, 0, vec![status, proxy, check], vec!["claude-update: 2.1.287 is deployed, and the run that deployed it stopped before its end", "claude-update [3/4] make proxy-start", "the proxy was stopped before this run and runs now", "make test-egress, the broader live test the deploy names"]),
        c("another bundle's marker", "2.1.287", "2.1.287", "2.1.287", vec![], World::PendingOther, 0, vec![status, check], vec!["is pinned and deployed", "!stopped before its end", "!make test-egress"]),
        c("a new bundle after an unfinished run", "2.1.288", "2.1.287", "2.1.287", full.clone(), World::PendingDeploy, 0, vec![PIN288, test, deploy, status, proxy, check], vec!["the proxy was stopped before this run and runs now: make proxy-stop when idle"]),
    ];
    for case in cases {
        let what = case.what;
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let bin = s5_bin(t);
        // A deploy moves the stack outputs' claudeVersion to the version it deployed (FAKE_DEPLOYS).
        script(
            &bin.join("make"),
            "echo \"make $*\" >> \"$FAKE_AIENV_LOG\"\ncase \" $* \" in *\" ${FAKE_MAKE_FAIL:-none} \"*) exit 2 ;; esac\ncase \" $* \" in *\" deploy \"*) sed -i '' \"s/\\\"claudeVersion\\\":\\\"[^\\\"]*\\\"/\\\"claudeVersion\\\":\\\"$FAKE_DEPLOYS\\\"/\" \"$FAKE_PULUMI_OUTPUTS\" ;; esac\nexit 0",
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
        write_outputs(t, &o);
        std::fs::create_dir_all(t.join("aws/image")).unwrap();
        std::fs::write(t.join("aws/image/state"), "UPDATED").unwrap();
        std::fs::write(t.join("aws/image/active"), "3.0").unwrap();
        let built_from = if case.world == World::OtherZip { "fedcba9876543210" } else { "0123456789abcdef" };
        std::fs::write(t.join("aws/image/uri"), format!("s3://ai-env-artifacts-0000000/ai-env/image-{built_from}.zip")).unwrap();
        seed_proxy(t, if case.world == World::ProxyStopped { "stopped" } else { "running" });
        if matches!(case.world, World::Stamped | World::StampedStale | World::StampedOtherClaude) {
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
        let out = ops5(t, &bin, &["claude-update"])
            .current_dir(t)
            .env("LOCK", "image/claude.lock")
            .env("CLAUDE_RELEASES", "https://downloads.invalid/claude-code-releases")
            .env("CLAUDE_GPG_FPR", "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE")
            .env("FAKE_AIENV_BUNDLE", case.bundle)
            .env("FAKE_DEPLOYS", case.bundle)
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
        let ran: Vec<String> = calls(t).into_iter().filter(|l| l.starts_with("make ") || l.starts_with("egress check")).map(|l| l.split(" [AI_ENV=").next().unwrap().to_string()).collect();
        assert_eq!(ran, case.steps, "{what}: {text}");
        if case.code == 0 {
            assert!(text.contains("claude-update: done: new VMs start image version 3.0 with Claude Code "), "{what}: {text}");
            assert!(!text.contains("review and commit"), "{what}: the lock is outside any work tree here: {text}");
        } else {
            assert!(!text.contains("claude-update: done"), "{what}: {text}");
        }
        if case.steps.is_empty() {
            assert!(text.contains("nothing changed") || text.contains("not under make -i or -k"), "{what}: a refusal says nothing changed: {text}");
        }
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

/// test-cursor checks STEP before cargo runs: a missing STEP (also one only
/// the environment names) and one that names no step are exit 2, naming the
/// five steps; a step runs the checks with the gate, the step and the
/// filters the command line gives, and no lab knob.
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
    for (what, args, envs, want) in [
        ("no STEP", &["test-cursor"][..], &[][..], format!("test-cursor: STEP is missing: make test-cursor STEP=t8_3 {steps} after that step in Cursor")),
        ("STEP in the environment only", &["test-cursor"][..], &[("STEP", "t8_3")][..], "test-cursor: STEP is missing".to_string()),
        ("an unknown step", &["test-cursor", "STEP=t8_8"][..], &[][..], "test-cursor: STEP=t8_8 names no step: one of t8_3, t8_4, t8_5, t8_6, t8_7".to_string()),
        ("a test's name", &["test-cursor", "STEP=t8_3_evidence"][..], &[][..], "test-cursor: STEP=t8_3_evidence names no step".to_string()),
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
    let (out, calls) = run(&["test-cursor", "STEP=t8_3"], &[("SINCE", "2026-10-14T09:00:00Z"), ("WORKSPACE", "/w")]);
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(calls, vec![format!("{checks} [TESTS=1 STEP=t8_3 SINCE=unset WORKSPACE=unset] [LAB=]")], "the environment's filters never reach the checks");
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
      if [ -n "${AWS_REGION:-}" ] && [ "${FAKE_ACCEPT_REGION:-}" != ignore ]; then
        region="[!! ] region eu-central-1 (pinned in code)  <- env AWS_REGION=$AWS_REGION ignored (region pinned to eu-central-1)"
      fi
      printf '%s\n' "ai-env doctor" "  $region" "  [ok ] ai-env-claude next to ai-env ($here/ai-env-claude)"
      if [ -n "${AWS_REGION:-}" ]; then exit "${FAKE_ACCEPT_REGION_RC:-0}"; fi
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
/// alone in a directory (negative g's product).
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
        let fakes: Vec<(&str, &str)> = ["aws", "claude", "rustup", "zig", "cargo-lambda", "age", "pulumi", "docker", "curl"].iter().map(|n| ("logged.sh", *n)).collect();
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
        let ok = |step: &str| text.contains(&format!("acceptance: {step}: ok ("));
        match fails {
            None => {
                assert!(out.status.success(), "{what}: {text}");
                let at: Vec<usize> = ACCEPT_STEPS.iter().map(|step| text.find(&format!("acceptance: {step}: ok (")).unwrap_or_else(|| panic!("{what}: no ok line for {step}: {text}"))).collect();
                assert!(at.windows(2).all(|p| p[0] < p[1]), "{what}: the steps in order: {text}");
                assert!(text.ends_with("acceptance: ok: doctor, versions, creds, the negatives (a) to (g), the smoke; target/s8/acceptance removed\n"), "{what}: {text}");
                assert_eq!(calls[calls.len() - 2..], ["ai-env vm smoke --max-duration 900 --json", "ai-env vm list --json"], "{what}: the two Touch IDs last: {calls:#?}");
                assert!(lines_of(&a.root().join("tools.log")).contains(&"aws sts get-caller-identity --region eu-central-1 --output json".to_string()), "{what}: negative g's doctor is the real one (its probes ran)");
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
        assert!(!a.w.join("target/s8/acceptance").exists(), "{what}: a step's directory was made");
    }
    let a = Acceptance::new(&lone);
    let out = a.run(&[], &a.pair.display().to_string(), &[]);
    assert!(a.pair.display().to_string().contains('i'));
    assert!(out.status.success() && all(&out).ends_with("acceptance: ok: doctor, versions, creds, the negatives (a) to (g), the smoke; target/s8/acceptance removed\n"), "{}", all(&out));
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
