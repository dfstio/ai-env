//! The S3 Makefile and infra/infra.mk recipes through `make` itself, and the
//! ops.sh image wait through /bin/bash, with every path in a temp dir and
//! every outside tool a fake first on PATH (tests/fakes/: curl, gpg, docker,
//! a stateful aws, cargo-lambda, an `ai-env` stand-in, and logged.sh for the
//! tools that must not run). The make child is isolated like `ai_env`
//! (common::isolate). Nothing reaches AWS, the network, docker, a real gpg
//! keyring or the real keystore. `image-stage-scan` runs on a planted copy of
//! image/ with this test run's binary as AI_ENV.
use super::common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const CLAUDE_VERSION: &str = "2.1.283";

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
        .output()
        .expect("make")
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
        .output()
        .unwrap();
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
        .output()
        .unwrap();
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
        .output()
        .unwrap()
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
        .output()
        .unwrap();
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
    let dry = |args: &[&str], envs: &[(&str, &str)]| stdout(&make(t.path(), &bin, &["-n", "deploy"]).args(args).envs(envs.iter().copied()).output().unwrap());
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
        .output()
        .unwrap()
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
    assert!(out.status.success() && all.contains(&format!("the sealed key {} identifies as user/ai-env-runtime", key_id(1))), "{all}");
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
    assert!(all.contains(&format!("the sealed key {} identifies as user/ai-env-runtime", key_id(2))), "only the sealed id is named: {all}");
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
    assert!(out.status.success() && all.contains(&format!("the sealed key {} identifies as user/ai-env-runtime", key_id(1))), "{all}");
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
        .output()
        .unwrap()
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
        .output()
        .unwrap();
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
    let dry = |args: &[&str]| stdout(&make(t.path(), &bin, &["-n"]).args(args).env("AI_ENV", "1").env("FAKE_LOG", &tools).output().unwrap());
    let scan = dry(&["image-stage-scan"]);
    assert!(scan.contains(default) && !scan.contains("1 infra scan"), "{scan}");
    let zip = dry(&["image-zip"]);
    assert!(zip.contains(default), "the sub-make too: {zip}");
    let zip = dry(&["image-zip", "AI_ENV=/opt/x/ai-env"]);
    assert!(zip.contains("/opt/x/ai-env infra scan"), "a command-line value reaches the sub-make: {zip}");
    // The recipes' children never see the variable, not even a command-line value.
    let log = t.path().join("ai-env.log");
    let stand_in = bin.join("ai-env-stand-in");
    let out = make(t.path(), &bin, &["check-base-image"]).arg(format!("AI_ENV={}", stand_in.display())).env("AI_ENV", "1").env("FAKE_AIENV_LOG", &log).env("FAKE_LOG", &tools).output().unwrap();
    assert!(out.status.success(), "{}", all(&out));
    assert_eq!(lines_of(&log), vec!["infra base-image --name al2023-1 --version 1 [AI_ENV=unset]".to_string()]);
    assert_eq!(read(&tools), "", "cargo never ran");
}

/// The upper-case variables of `make -p` (a dry parse), `NAME := value` or
/// `NAME = value` (a recursive or `?=` one), as make holds them.
fn make_vars(t: &Path, args: &[&str]) -> std::collections::HashMap<String, String> {
    let bin = bin_with(t, &[]);
    let out = make(t, &bin, &["-p", "-n", "help"]).args(args).output().unwrap();
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
    let out = make(t.path(), &bin, &["check-base-image", &arg]).arg(format!("AI_ENV={}", bin.join("ai-env-stand-in").display())).env("FAKE_AIENV_LOG", &log).output().unwrap();
    assert!(!out.status.success() && all(&out).contains("baseImage.name or baseImage.version missing from"), "{}", all(&out));
    assert_eq!(read(&log), "", "ai-env never ran");
    let out = make(t.path(), &bin, &["image-status", &arg]).env("FAKE_LOG", t.path().join("tools.log")).output().unwrap();
    assert!(!out.status.success() && all(&out).contains("IMAGE_NAME is empty"), "{}", all(&out));
    assert_eq!(read(&t.path().join("tools.log")), "", "aws never ran");
}
