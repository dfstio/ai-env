//! tests/infra.rs area: pin — `ai-env infra pin --manifest | --check-bundle`
//! and the plain print. The manifest is built here (the checksum at run
//! time), the Cursor extension directory is a fake one under the temp
//! `HOME`, and nothing is downloaded or executed besides `ai-env`.
use super::common::*;
use ai_env_cli::wire::pin::{parse_lock, render_lock, ClaudePin, PLATFORM};
use std::path::{Path, PathBuf};

const VERSION: &str = "2.1.283";
const SIZE: u64 = 240_902_136;
const BUILD_DATE: &str = "2026-09-25T01:39:37Z";

/// A public release checksum's shape, built at run time.
fn checksum() -> String {
    "ab".repeat(32)
}

/// A manifest shaped like the real release manifest (extra keys and platforms included).
fn manifest(version: &str, checksum: &str, size: u64, date: &str) -> String {
    serde_json::json!({
        "version": version,
        "manifestSignatureEnforcement": "warn",
        "buildDate": date,
        "platforms": {
            "darwin-arm64": {"binary": "claude", "checksum": "cd".repeat(32), "size": 225_036_032u64},
            "linux-arm64": {"binary": "claude", "checksum": checksum, "size": size},
            "linux-x64": {"binary": "claude", "checksum": "ef".repeat(32), "size": 241_556_664u64}
        },
        "sdkCompat": {"testedWrapperVersions": [], "harnessSchema": 1}
    })
    .to_string()
}

fn pin(version: &str) -> ClaudePin {
    ClaudePin { version: version.into(), platform: PLATFORM.into(), sha256: checksum(), size: SIZE, build_date: BUILD_DATE.into() }
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// `ai-env <args>` (the environment of [`ai_env`]) under `umask 077`, through
/// `sh` since `Command` has no umask knob: a file created with mode 0644
/// comes out 0600 unless the writer fchmods it.
fn ai_env_umask_077(t: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.args(["-c", "umask 077 && exec \"$0\" \"$@\"", bin()]).args(args).stdin(std::process::Stdio::null());
    for (k, v) in ai_env(t, &[]).get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    cmd
}

/// `<tmp>/image/claude.lock` holding the pin of `version`.
fn lock_with(tmp: &Path, version: &str) -> PathBuf {
    let dir = tmp.join("image");
    std::fs::create_dir_all(&dir).unwrap();
    let lock = dir.join("claude.lock");
    std::fs::write(&lock, render_lock(&pin(version)).unwrap()).unwrap();
    lock
}

/// Fake `~/.cursor/extensions/<name>/` directories under the temp HOME.
fn extensions(tmp: &Path, names: &[&str]) -> PathBuf {
    let dir = tmp.join(".cursor").join("extensions");
    for n in names {
        std::fs::create_dir_all(dir.join(n)).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn pin_from_manifest_writes_the_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    std::fs::create_dir_all(t.join("image")).unwrap();
    let m = t.join("manifest.json");
    std::fs::write(&m, manifest(VERSION, &checksum(), SIZE, BUILD_DATE)).unwrap();
    let lock = t.join("image").join("claude.lock");

    // Under umask 077 the lock still comes out exactly 0644 (fchmod'ed, not left to the umask).
    let o = run(&mut ai_env_umask_077(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--lock", lock.to_str().unwrap()]));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains(&format!("claude {VERSION} ({PLATFORM})")), "{out}");
    assert!(out.contains(&SIZE.to_string()) && out.contains(&checksum()), "{out}");
    assert!(out.contains(&format!("wrote {}", lock.display())), "{out}");
    let text = std::fs::read_to_string(&lock).unwrap();
    assert!(text.starts_with("# Claude Code binary"), "{text}");
    assert_eq!(parse_lock(&text).unwrap(), pin(VERSION));
    assert_eq!(mode_of(&lock), 0o644, "a committed file, whatever the umask");
    let names: Vec<String> = std::fs::read_dir(t.join("image")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec!["claude.lock"], "no temp file left behind");

    // The same manifest again: rewritten, reported unchanged.
    let o = run(&mut ai_env(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--lock", lock.to_str().unwrap()]));
    assert!(o.status.success() && stdout(&o).contains("unchanged"), "{}", stdout(&o));
    // A newer manifest replaces it and names the previous version.
    std::fs::write(&m, manifest("2.1.290", &checksum(), SIZE, BUILD_DATE)).unwrap();
    let o = run(&mut ai_env(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--lock", lock.to_str().unwrap()]));
    assert!(o.status.success() && stdout(&o).contains(&format!("previous: {VERSION}")), "{}", stdout(&o));
    assert_eq!(parse_lock(&std::fs::read_to_string(&lock).unwrap()).unwrap().version, "2.1.290");

    // Neither flag: print the lock at the default path, relative to the working directory.
    let o = run(ai_env(t, &["infra", "pin"]).current_dir(t));
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("claude 2.1.290") && stdout(&o).contains("downloads.claude.ai/claude-code-releases/2.1.290/linux-arm64/claude"), "{}", stdout(&o));
}

#[test]
fn pin_rejects_unsafe_values() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let lock = lock_with(t, VERSION);
    let good = std::fs::read(&lock).unwrap();
    let m = t.join("manifest.json");
    let sum = checksum();
    let cases: Vec<(String, &str)> = vec![
        (manifest("2.1.284;touch pwned", &sum, SIZE, BUILD_DATE), "CLAUDE_VERSION"),
        (manifest("$(id)", &sum, SIZE, BUILD_DATE), "CLAUDE_VERSION"),
        (manifest("2.1.284\nCLAUDE_SIZE=1", &sum, SIZE, BUILD_DATE), "CLAUDE_VERSION"),
        (manifest("2.1.284", &sum.to_uppercase(), SIZE, BUILD_DATE), "CLAUDE_SHA256"),
        (manifest("2.1.284", &format!("{}`id`", "ab".repeat(29)), SIZE, BUILD_DATE), "CLAUDE_SHA256"),
        (manifest("2.1.284", &"ab".repeat(31), SIZE, BUILD_DATE), "CLAUDE_SHA256"),
        (manifest("2.1.284", &sum, 0, BUILD_DATE), "CLAUDE_SIZE"),
        (manifest("2.1.284", &sum, SIZE, "2026-09-25 01:39:37"), "CLAUDE_BUILD_DATE"),
        (manifest("2.1.284", &sum, SIZE, BUILD_DATE).replace("\"linux-arm64\"", "\"linux-arm64-musl\""), "no platform linux-arm64"),
        (manifest("2.1.284", &sum, SIZE, BUILD_DATE).replace("\"binary\":\"claude\",\"checksum\":\"abab", "\"binary\":\"claude.sh\",\"checksum\":\"abab"), "binary is \"claude.sh\""),
        ("not json".to_string(), "manifest"),
    ];
    for (json, needle) in cases {
        std::fs::write(&m, &json).unwrap();
        let o = run(ai_env(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--lock", lock.to_str().unwrap()]).current_dir(t));
        assert_eq!(o.status.code(), Some(1), "{json}: {}{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains(needle), "{needle}: {}", stderr(&o));
        assert_eq!(std::fs::read(&lock).unwrap(), good, "the lock is untouched: {needle}");
    }
    assert!(!t.join("pwned").exists());
    assert_eq!(std::fs::read_dir(t.join("image")).unwrap().count(), 1, "no temp file left behind");

    // The two modes are exclusive (clap usage error).
    let o = run(&mut ai_env(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));

    // An unsafe value already in the lock is refused when it is read, and a missing lock names the fix.
    std::fs::write(&lock, String::from_utf8(good).unwrap().replace(&format!("CLAUDE_VERSION={VERSION}"), "CLAUDE_VERSION=$(id)")).unwrap();
    let o = run(&mut ai_env(t, &["infra", "pin", "--lock", lock.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("CLAUDE_VERSION") && stderr(&o).contains("outside [A-Za-z0-9._:-]"), "{}", stderr(&o));
    let o = run(&mut ai_env(t, &["infra", "pin", "--lock", t.join("none.lock").to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("make claude-pin CLAUDE_VERSION="), "{}", stderr(&o));
}

/// `make claude-pin CLAUDE_VERSION=V` passes `--expect-version V`: a
/// manifest of another version (a validly signed older one, say) is refused
/// and the lock stays byte for byte; the matching version writes it.
#[test]
fn pin_expect_version_refuses_a_manifest_of_another_version() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let lock = lock_with(t, "2.1.278");
    let before = std::fs::read(&lock).unwrap();
    let m = t.join("manifest.json");
    std::fs::write(&m, manifest(VERSION, &checksum(), SIZE, BUILD_DATE)).unwrap();
    let pin_with = |expect: &str| run(&mut ai_env(t, &["infra", "pin", "--manifest", m.to_str().unwrap(), "--lock", lock.to_str().unwrap(), "--expect-version", expect]));

    let o = pin_with("2.1.284");
    assert_eq!(o.status.code(), Some(1), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains(&format!("{}: the manifest is for version {VERSION}, not 2.1.284; lock not written", m.display())), "{}", stderr(&o));
    assert_eq!(stdout(&o), "", "nothing printed as pinned");
    assert_eq!(std::fs::read(&lock).unwrap(), before, "the lock is untouched");
    assert_eq!(std::fs::read_dir(t.join("image")).unwrap().count(), 1, "no temp file left behind");

    let o = pin_with(VERSION);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("previous: 2.1.278") && stdout(&o).contains(&format!("wrote {}", lock.display())), "{}", stdout(&o));
    assert_eq!(parse_lock(&std::fs::read_to_string(&lock).unwrap()).unwrap(), pin(VERSION));

    // Without --manifest the flag is a usage error (clap `requires`).
    let o = run(&mut ai_env(t, &["infra", "pin", "--lock", lock.to_str().unwrap(), "--expect-version", VERSION]));
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

#[test]
fn pin_check_bundle_mismatch_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let lock = lock_with(t, VERSION);
    extensions(t, &["anthropic.claude-code-2.1.283-darwin-arm64", "anthropic.claude-code-2.1.290-darwin-arm64", "anthropic.claude-code-2.1.299-linux-x64", "other.extension-9.9.9"]);
    let o = run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(1), "{}{}", stdout(&o), stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("lock 2.1.283") && err.contains("Cursor bundle 2.1.290"), "the highest darwin-arm64 bundle wins: {err}");
    assert!(err.contains("make claude-update (or make claude-pin CLAUDE_VERSION=2.1.290 && make test-docker)"), "{err}");
    // --bundle-version prints that version and nothing else (make claude-update reads it), the lock untouched.
    let before = std::fs::read(&lock).unwrap();
    let o = run(&mut ai_env(t, &["infra", "pin", "--bundle-version"]));
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), "2.1.290\n");
    assert_eq!(std::fs::read(&lock).unwrap(), before);
    // --check-bundle with --expect-version is a usage error too (else the version would be ignored silently).
    assert_eq!(run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap(), "--expect-version", "2.1.290"])).status.code(), Some(2));
    // It excludes the other modes (clap usage error), --expect-version included (else ignored silently).
    for other in [&["--check-bundle"][..], &["--manifest", "m.json"][..], &["--expect-version", "2.1.290"][..]] {
        let mut args = vec!["infra", "pin", "--bundle-version"];
        args.extend_from_slice(other);
        assert_eq!(run(&mut ai_env(t, &args)).status.code(), Some(2), "{other:?}");
    }
}

#[test]
fn pin_check_bundle_match_exits_0() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let lock = lock_with(t, VERSION);
    extensions(t, &["anthropic.claude-code-2.1.278-darwin-arm64", "anthropic.claude-code-2.1.283-darwin-arm64"]);
    let o = run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), "pin: lock 2.1.283 equals the Cursor bundle");
}

#[test]
fn pin_check_bundle_without_a_bundle_exits_1() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let lock = lock_with(t, VERSION);
    let dir = t.join(".cursor").join("extensions");
    let o = run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains(&dir.display().to_string()), "names the directory: {}", stderr(&o));
    extensions(t, &["other.extension-1.0.0", "anthropic.claude-code-latest-darwin-arm64"]);
    let o = run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("no anthropic.claude-code-<version>-darwin-arm64 bundle"), "{}", stderr(&o));
    let o = run(&mut ai_env(t, &["infra", "pin", "--bundle-version"]));
    assert_eq!((o.status.code(), stdout(&o).as_str()), (Some(1), ""), "no bundle, no version: {}", stderr(&o));
}

/// What Cursor counts as installed: a version `.obsolete` lists (left on disk
/// after installing an older one, until Cursor's next start), a plain file or
/// a symlink named like a bundle is none; a release beats a suffixed name of
/// the same version.
#[test]
fn pin_bundle_version_skips_obsolete_and_non_directory_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let dir = extensions(t, &["anthropic.claude-code-2.1.287-darwin-arm64", "anthropic.claude-code-2.1.288-darwin-arm64"]);
    let version = || {
        let o = run(&mut ai_env(t, &["infra", "pin", "--bundle-version"]));
        assert!(o.status.success(), "{}", stderr(&o));
        stdout(&o).trim().to_string()
    };
    assert_eq!(version(), "2.1.288");
    std::fs::write(dir.join(".obsolete"), r#"{"anthropic.claude-code-2.1.288-darwin-arm64":true}"#).unwrap();
    assert_eq!(version(), "2.1.287", "the downgraded-from version is obsolete");
    std::fs::write(dir.join("anthropic.claude-code-2.1.300-darwin-arm64"), "").unwrap();
    std::os::unix::fs::symlink(t.join("nowhere"), dir.join("anthropic.claude-code-2.1.299-darwin-arm64")).unwrap();
    std::os::unix::fs::symlink(dir.join("anthropic.claude-code-2.1.287-darwin-arm64"), dir.join("anthropic.claude-code-2.1.298-darwin-arm64")).unwrap();
    assert_eq!(version(), "2.1.287", "a file, a dangling and a live symlink are no installed extension");
    std::fs::create_dir(dir.join("anthropic.claude-code-2.1.289-rc1-darwin-arm64")).unwrap();
    std::fs::create_dir(dir.join("anthropic.claude-code-2.1.289-darwin-arm64")).unwrap();
    assert_eq!(version(), "2.1.289", "the release beats the suffixed name");
    // P10 sees the same.
    let lock = lock_with(t, "2.1.289");
    let o = run(&mut ai_env(t, &["infra", "pin", "--check-bundle", "--lock", lock.to_str().unwrap()]));
    assert!(o.status.success(), "{}", stderr(&o));
}
