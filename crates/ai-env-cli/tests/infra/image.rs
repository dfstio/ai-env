//! The S3 Makefile and infra/infra.mk recipes through `make` itself, and the
//! ops.sh image wait through /bin/bash, with every path in a temp dir and
//! every outside tool a fake first on PATH (tests/fakes/: curl, gpg, docker,
//! a stateful aws, cargo-lambda, an `ai-env` stand-in, and logged.sh for the
//! tools that must not run). The make child is isolated like `ai_env`
//! (common::isolate). Nothing reaches AWS, the network, docker, a real gpg
//! keyring or the real keystore. `image-stage-scan` runs on a planted copy of
//! image/ with this test run's binary as AI_ENV. The S5 section drives the
//! egress ops of ops.sh and the new targets with a stateful aws, a pulumi and
//! the `ai-env` stand-in, `make deploy` whole in a planted repo. Every child
//! runs under a deadline ([`Bounded`]).
use super::common::*;
use serde_json::{json, Value};
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
fn planted_image(tmp: &Path) -> PathBuf {
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
    let img = planted_image(t.path());
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
    let lab_unset = "env -u AI_ENV_BRIDGE_LAB_FAKE_API -u AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL -u AI_ENV_BRIDGE_LAB_BACKOFF_MS -u AI_ENV_BRIDGE_LAB_FAKE_SHELL";
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
            "test-egress",
            vec![
                format!("{lab_unset} AI_ENV_AWS_TESTS=1 AI_ENV_EGRESS_TESTS=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test aws -- --ignored live_egress_ --test-threads=1 --nocapture"),
                format!("{ai_env} egress allow ai-env-test github.com --remove"),
                "' EXIT;".into(),
            ],
        ),
        ("test-proxy", vec!["AI_ENV_PROXY_TESTS=1 AI_ENV_PROXY_SYSTEMD=1 cargo +1.98.1 test -p ai-env-cli --features bridge --test proxy_docker -- --include-ignored --test-threads=1".into()]),
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

    // The switches count only on the command line.
    assert!(dry(&["proxy-stop", "YES=1"], &[]).contains(&format!("{ai_env} proxy stop --yes")));
    assert!(!dry(&["proxy-stop"], &[("YES", "1")]).contains("--yes"), "YES=1 in the environment is ignored");
    assert!(dry(&["egress-logs", "FOLLOW=1", "SINCE=15m"], &[]).contains("--since 15m --format short --follow --region eu-central-1"));
    assert!(!dry(&["egress-logs"], &[("FOLLOW", "1")]).contains("--follow"));
    let no_systemd = dry(&["test-proxy", "SYSTEMD=0"], &[]);
    assert!(no_systemd.contains("AI_ENV_PROXY_TESTS=1 cargo +1.98.1 test") && !no_systemd.contains("AI_ENV_PROXY_SYSTEMD"), "{no_systemd}");
    assert!(dry(&["test-proxy"], &[("SYSTEMD", "0")]).contains("AI_ENV_PROXY_SYSTEMD=1"), "SYSTEMD=0 in the environment is ignored");

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
/// lab knob it sees, then exits FAKE_CARGO_RC, or (FAKE_CARGO_MARKER set)
/// touches the marker and sleeps until a signal ends it.
const CARGO_FAKE: &str = r##"lab=$(env | sed -n 's/^\(AI_ENV_BRIDGE_LAB_[A-Z_]*\)=.*/\1/p' | sort | tr '\n' ' ')
printf 'cargo %s [AI_ENV_AWS_TESTS=%s AI_ENV_EGRESS_TESTS=%s]%s\n' "$*" "${AI_ENV_AWS_TESTS:-}" "${AI_ENV_EGRESS_TESTS:-}" "${lab:+ [LAB=${lab% }]}" >> "$FAKE_AIENV_LOG"
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
    let knobs = [("AI_ENV_BRIDGE_LAB_FAKE_API", "1"), ("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1"), ("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "5"), ("AI_ENV_BRIDGE_LAB_FAKE_SHELL", "1")];
    let t = tempfile::tempdir().unwrap();
    let w = planted_repo(t.path(), true);
    let bin = s5_bin(t.path());
    script(&bin.join("cargo"), CARGO_FAKE);
    seed_connector(t.path(), CONNECTOR, "ACTIVE");
    let stand_in = format!("AI_ENV={}", bin.join("ai-env-stand-in").display());
    let record = json!({"backend": "sdk", "egress_ok": true}).to_string();
    let run = |args: &[&str]| {
        let mut cmd = make_in(t.path(), &bin, &w, args);
        s5_env(&mut cmd, t.path()).arg(&stand_in).env("FAKE_AIENV_SMOKE", &record).envs(knobs).bounded()
    };
    let live: [&[&str]; 7] = [&["s5-smoke"], &["test-egress"], &["connector-probe", "CONFIRM=create-probe-connector", "CONNECTOR_WAIT_POLL=1"], &["allowlist-reload"], &["proxy-stop"], &["proxy-start"], &["proxy-patch"]];
    for args in live {
        let out = run(args);
        assert!(out.status.success(), "{args:?}: {}", all(&out));
    }
    let c = calls(t.path());
    let children: Vec<&String> = c.iter().filter(|l| l.contains("[AI_ENV=") || l.starts_with("cargo ")).collect();
    assert_eq!(children.len(), 3 + 2 + 1 + 4, "three smokes, cargo and the removal, the probe's lab run, the four operator calls: {children:#?}");
    assert!(children.iter().all(|l| !l.contains("[LAB=")), "a lab knob reached a live command: {children:#?}");
    // The control: a target that keeps the knobs hands them on, and the stand-in sees them.
    let out = run(&["check-base-image"]);
    assert!(out.status.success(), "{}", all(&out));
    let last = calls(t.path()).pop().unwrap();
    assert!(last.ends_with("[LAB=AI_ENV_BRIDGE_LAB_BACKOFF_MS AI_ENV_BRIDGE_LAB_FAKE_API AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL AI_ENV_BRIDGE_LAB_FAKE_SHELL]"), "{last}");
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
