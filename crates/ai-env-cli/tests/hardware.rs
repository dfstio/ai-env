//! Real-binary Secure Enclave tests for `keys restore`. Ignored by default:
//!
//! ```sh
//! AI_ENV_SE_TESTS=1 cargo test -p ai-env-cli -- --ignored
//! ```
//!
//! Fully automated: keys use `--access-control=none` (no Touch ID prompts)
//! and the restore paste is fed via the documented `AI_ENV_PASTE_STDIN=1`
//! automation path. Needs the real `age`, `age-keygen`, and `age-plugin-se`
//! on PATH — cannot run in CI (physical SEP required).
#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn enabled() -> bool {
    if std::env::var("AI_ENV_SE_TESTS").as_deref() == Ok("1") {
        true
    } else {
        eprintln!("set AI_ENV_SE_TESTS=1 to run Secure Enclave hardware tests");
        false
    }
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-env"))
}

fn ai_env(keystore: &Path, work: &Path, args: &[&str], stdin_text: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(work)
        .env("AI_ENV_DIR", keystore)
        .env("AI_ENV_PASTE_STDIN", "1")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match stdin_text {
        Some(text) => {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
            child.wait_with_output().unwrap()
        }
        None => {
            cmd.stdin(Stdio::null());
            cmd.output().unwrap()
        }
    }
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (exit {:?})\nstderr: {}\nstdout: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
#[ignore = "needs a physical Secure Enclave + age binaries; set AI_ENV_SE_TESTS=1"]
fn restore_roundtrip_with_rekey_sweep() {
    if !enabled() {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");

    // A real recovery identity we control (stand-in for the Strongbox entry).
    let keygen_out = Command::new("age-keygen").output().expect("age-keygen on PATH");
    let identity_text = String::from_utf8(keygen_out.stdout).unwrap();
    let identity_line = identity_text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .expect("identity line")
        .to_string();

    // Key k1 (no prompt policy, no ceremony) + hand-added recovery recipient —
    // simulating a normal key whose recovery half lives in Strongbox.
    assert_ok(
        &ai_env(&keystore, work.path(), &["keygen", "k1", "--access-control=none", "--no-recovery"], None),
        "keygen k1",
    );
    let recipient = {
        let out = Command::new("age-keygen")
            .arg("-y")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(identity_text.as_bytes())?;
                c.wait_with_output()
            })
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let recipients_path = keystore.join("keys/k1/recipients.txt");
    let mut recipients = fs::read_to_string(&recipients_path).unwrap();
    recipients.push_str(&format!("{recipient}\n"));
    fs::write(&recipients_path, recipients).unwrap();

    // Foreign key k2 and two files: mine.env (k1) and other.env (k2).
    assert_ok(
        &ai_env(&keystore, work.path(), &["keygen", "k2", "--access-control=none", "--no-recovery"], None),
        "keygen k2",
    );
    fs::write(work.path().join("mine.env"), "TEST5=hello-restore\n").unwrap();
    fs::write(work.path().join("other.env"), "OTHER=1\n").unwrap();
    assert_ok(&ai_env(&keystore, work.path(), &["encrypt", "mine.env", "-k", "k1", "--force"], None), "encrypt mine");
    assert_ok(&ai_env(&keystore, work.path(), &["encrypt", "other.env", "-k", "k2", "--force"], None), "encrypt other");
    let other_before = fs::read(work.path().join("other.env")).unwrap();

    // Forget k1 — the situation this feature exists for.
    assert_ok(&ai_env(&keystore, work.path(), &["keys", "forget", "k1", "--yes"], None), "forget");
    let out = ai_env(&keystore, work.path(), &["which", "mine.env"], None);
    assert_eq!(out.status.code(), Some(4), "mine.env unopenable after forget");

    // Restore with the sweep: one paste, zero prompts.
    assert_ok(
        &ai_env(
            &keystore,
            work.path(),
            &["keys", "restore", "k1", "--access-control=none", "--rekey", "."],
            Some(&format!("{identity_line}\n")),
        ),
        "keys restore",
    );

    // mine.env is now addressed to the NEW k1 key…
    let out = ai_env(&keystore, work.path(), &["which", "mine.env"], None);
    assert_ok(&out, "which mine.env");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "k1");
    let out = ai_env(&keystore, work.path(), &["show", "mine.env"], None);
    assert_ok(&out, "show mine.env via new SE key");
    assert!(String::from_utf8_lossy(&out.stdout).contains("TEST5=hello-restore"));

    // …and the foreign file was skipped, byte-identical.
    assert_eq!(fs::read(work.path().join("other.env")).unwrap(), other_before);
    let out = ai_env(&keystore, work.path(), &["which", "other.env"], None);
    assert_ok(&out, "which other.env");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "k2");
}
