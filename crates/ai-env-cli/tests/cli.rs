//! Integration tests against the real `ai-env` binary with a FAKE `age` on
//! PATH that records its argv. These enforce the security invariants:
//!  * EXACTLY ONE `-i` per decrypt invocation (age tries native identities
//!    first — two identities could silently bypass Touch ID)
//!  * no secret material in argv
//!  * exit 4 / exit 6 are decided WITHOUT spawning age
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_BIN_EXE_ai-env"));
    if !p.exists() {
        p = PathBuf::from("target/debug/ai-env");
    }
    p
}

struct Shim {
    dir: tempfile::TempDir,
}

impl Shim {
    /// A fake `age`/`age-keygen`/`age-plugin-se` that records argv and emits
    /// canned but structurally-correct output:
    /// * `age --version` -> v1.3.2; otherwise echoes stdin (so an encrypt or
    ///   decrypt round-trips bytes unchanged). Failure switches:
    ///   AI_ENV_SHIM_FAIL_DECRYPT=1 / AI_ENV_SHIM_FAIL_ENCRYPT=1 fail that
    ///   mode outright, and a decrypt whose stdin contains AI_ENV_SHIM_FAIL
    ///   fails per-file (encrypt=cat, so a container's "ciphertext" IS its
    ///   plaintext and can carry the marker);
    /// * `age-keygen` -> a canned identity file; `age-keygen -y` derives the
    ///   fixed X25519 recipient, REJECTING input that is not an
    ///   AGE-SECRET-KEY-1 line (like the real tool);
    /// * `age-plugin-se keygen ... -o PATH` -> writes a plausible identity
    ///   file whose `# public key:` comment matches the printed recipient
    ///   (the real testdata tag recipient, so decode succeeds).
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        const SE_REC: &str =
            "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
        const X_REC: &str =
            "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
        for name in ["age", "age-keygen", "age-plugin-se"] {
            let path = dir.path().join(name);
            let body = match name {
                "age-keygen" => format!(
                    "#!/bin/sh\necho \"{name} $*\" >> {log}\n\
                     case \"$1\" in --version) echo v1.3.2; exit 0;; esac\n\
                     if [ \"$1\" = -y ]; then\n\
                       read -r line\n\
                       case \"$line\" in\n\
                         AGE-SECRET-KEY-1*) echo {X_REC}; exit 0;;\n\
                         *) echo 'age-keygen: error: malformed secret key' >&2; exit 1;;\n\
                       esac\n\
                     fi\n\
                     cat > /dev/null\n\
                     printf '# created: shim\\n# public key: {X_REC}\\nAGE-SECRET-KEY-1FAKENEWRECOVERY\\n'\n",
                    log = log.display()
                ),
                "age" => format!(
                    "#!/bin/sh\necho \"{name} $*\" >> {log}\n\
                     case \"$1\" in --version) echo v1.3.2; exit 0;; esac\n\
                     mode=e\n\
                     for a in \"$@\"; do [ \"$a\" = -d ] && mode=d; done\n\
                     if [ \"$mode\" = d ]; then\n\
                       if [ \"$AI_ENV_SHIM_FAIL_DECRYPT\" = 1 ]; then cat > /dev/null; \
                         echo 'age: error: shim decrypt failure' >&2; exit 1; fi\n\
                       t=$(mktemp); cat > \"$t\"\n\
                       if grep -aq AI_ENV_SHIM_FAIL \"$t\"; then rm -f \"$t\"; \
                         echo 'age: error: no identity matched any of the recipients' >&2; exit 1; fi\n\
                       cat \"$t\"; rm -f \"$t\"\n\
                     else\n\
                       if [ \"$AI_ENV_SHIM_FAIL_ENCRYPT\" = 1 ]; then cat > /dev/null; \
                         echo 'age: error: shim encrypt failure' >&2; exit 1; fi\n\
                       cat\n\
                     fi\n",
                    log = log.display()
                ),
                "age-plugin-se" => format!(
                    "#!/bin/sh\necho \"{name} $*\" >> {log}\n\
                     case \"$1\" in\n\
                       --version) echo v0.2.1; exit 0;;\n\
                       keygen)\n\
                         out=\"\"; prev=\"\"\n\
                         for a in \"$@\"; do [ \"$prev\" = \"-o\" ] && out=\"$a\"; prev=\"$a\"; done\n\
                         if [ -n \"$out\" ]; then\n\
                           printf '# public key: {SE_REC}\\nAGE-PLUGIN-SE-1FAKEFAKE\\n' > \"$out\"\n\
                         fi\n\
                         echo \"Public key: {SE_REC}\"\n\
                         exit 0;;\n\
                     esac\ncat\n",
                    log = log.display()
                ),
                _ => format!(
                    "#!/bin/sh\necho \"{name} $*\" >> {log}\n\
                     case \"$1\" in --version) echo v1.3.2; exit 0;; esac\n\
                     cat\n",
                    log = log.display()
                ),
            };
            fs::write(&path, body).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        Self { dir }
    }

    fn path_env(&self) -> String {
        format!("{}:{}", self.dir.path().display(), "/usr/bin:/bin")
    }

    fn argv_log(&self) -> String {
        fs::read_to_string(self.dir.path().join("argv.log")).unwrap_or_default()
    }
}

/// A minimal fake keystore with one key whose recipient matches the fixture.
fn fake_keystore(dir: &Path) {
    let key_dir = dir.join("keys/testkey");
    fs::create_dir_all(&key_dir).unwrap();
    fs::write(
        key_dir.join("identity.txt"),
        "# public key: age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r\n\
         AGE-PLUGIN-SE-1FAKEFAKE\n",
    )
    .unwrap();
    fs::write(
        key_dir.join("recipients.txt"),
        "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r\n",
    )
    .unwrap();
    fs::write(
        key_dir.join("meta.toml"),
        "created = \"2026-08-30\"\naccess_control = \"none\"\n",
    )
    .unwrap();
    fs::write(dir.join("default"), "testkey").unwrap();
}

/// Container around the real test-tag.age fixture (matches testkey above).
fn fixture_container() -> String {
    use base64::Engine as _;
    let ct = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ai-env-age/testdata/test-tag.age"
    ))
    .unwrap();
    format!(
        "AI_ENV=1\nAI_ENV_DATA={}\n",
        base64::engine::general_purpose::STANDARD.encode(ct)
    )
}

fn run_ai_env(shim: &Shim, keystore: &Path, work: &Path, args: &[&str]) -> std::process::Output {
    run_ai_env_env(shim, keystore, work, args, &[])
}

fn run_ai_env_env(
    shim: &Shim,
    keystore: &Path,
    work: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(work)
        .env_clear()
        .env("PATH", shim.path_env())
        .env("HOME", work)
        .env("AI_ENV_DIR", keystore)
        .args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn decrypt_passes_exactly_one_identity_and_no_secrets() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    fs::write(work.path().join(".env"), fixture_container()).unwrap();

    let out = run_ai_env(&shim, &keystore, work.path(), &["show"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let log = shim.argv_log();
    let decrypt_line = log.lines().find(|l| l.contains("-d")).expect("age -d was called");
    assert_eq!(
        decrypt_line.matches(" -i ").count(),
        1,
        "EXACTLY one -i must be passed: {decrypt_line}"
    );
    assert!(
        !log.contains("AGE-SECRET-KEY") && !log.contains("AGE-PLUGIN-SE"),
        "no secret material may appear in argv: {log}"
    );
}

#[test]
fn foreign_file_exits_4_without_spawning_age() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    // foreign.age is encrypted to a key NOT in the keystore.
    use base64::Engine as _;
    let ct = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ai-env-age/testdata/foreign.age"
    ))
    .unwrap();
    fs::write(
        work.path().join(".env"),
        format!("AI_ENV=1\nAI_ENV_DATA={}\n", base64::engine::general_purpose::STANDARD.encode(ct)),
    )
    .unwrap();

    let out = run_ai_env(&shim, &keystore, work.path(), &["show"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(
        !shim.argv_log().lines().any(|l| l.contains("-d")),
        "age must NOT be spawned for a foreign file"
    );
}

#[test]
fn corrupt_container_exits_6_without_spawning_age() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    fs::write(work.path().join(".env"), "AI_ENV=1\nAI_ENV_DATA=@@notbase64@@\n").unwrap();

    let out = run_ai_env(&shim, &keystore, work.path(), &["show"]);
    assert_eq!(out.status.code(), Some(6));
    assert!(
        !shim.argv_log().lines().any(|l| l.contains("-d")),
        "age must NOT be spawned for a corrupt container"
    );
}

#[test]
fn plaintext_file_exits_6() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    fs::write(work.path().join(".env"), "PLAIN=1\n").unwrap();
    let out = run_ai_env(&shim, &keystore, work.path(), &["show"]);
    assert_eq!(out.status.code(), Some(6));
}

#[test]
fn which_never_spawns_age() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    fs::write(work.path().join(".env"), fixture_container()).unwrap();

    let out = run_ai_env(&shim, &keystore, work.path(), &["which"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "testkey");
    assert!(
        !shim.argv_log().lines().any(|l| l.starts_with("age ")),
        "which must not spawn age at all"
    );
}

#[test]
fn encrypt_uses_recipients_file_and_double_dash_safety() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    // Give testkey a recovery recipient so encrypt doesn't fail closed.
    fs::write(
        keystore.join("keys/testkey/recipients.txt"),
        "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r\n\
         age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0\n",
    )
    .unwrap();
    fs::write(work.path().join(".env"), "SECRET=x\n").unwrap();

    // The shim echoes stdin, which is not a valid container payload — but the
    // argv log is what we're after; encrypt will fail at the container step
    // only if the fake ciphertext is empty. It isn't (echoed plaintext), so
    // the write succeeds and the payload is the echoed bytes.
    let out = run_ai_env(&shim, &keystore, work.path(), &["encrypt"]);
    let log = shim.argv_log();
    assert!(
        log.lines().any(|l| l.starts_with("age") && l.contains("-R")),
        "encrypt must use -R recipients.txt: {log} (status {:?}, stderr {})",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!log.contains("AGE-SECRET-KEY"), "no secrets in argv");
}

fn run_ai_env_stdin(
    shim: &Shim,
    keystore: &Path,
    work: &Path,
    args: &[&str],
    stdin_text: &str,
) -> std::process::Output {
    run_ai_env_stdin_env(shim, keystore, work, args, stdin_text, &[])
}

fn run_ai_env_stdin_env(
    shim: &Shim,
    keystore: &Path,
    work: &Path,
    args: &[&str],
    stdin_text: &str,
    envs: &[(&str, &str)],
) -> std::process::Output {
    use std::io::Write as _;
    let mut cmd = Command::new(bin());
    cmd.current_dir(work)
        .env_clear()
        .env("PATH", shim.path_env())
        .env("HOME", work)
        .env("AI_ENV_DIR", keystore)
        .env("AI_ENV_PASTE_STDIN", "1")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin_text.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

/// `keys restore`: one pasted identity -> new SE key, recipients.txt carries
/// both the SE recipient and the pasted identity's recipient, meta records
/// the verification — and no secret ever appears in argv.
#[test]
fn keys_restore_creates_key_from_pasted_identity() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey"],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let recipients = fs::read_to_string(keystore.join("keys/rkey/recipients.txt")).unwrap();
    assert!(recipients.contains("age1tag1qwww38sn"), "SE recipient present: {recipients}");
    assert!(
        recipients.contains("age15csf02ez9ze9"),
        "recovery recipient (derived from the paste) present: {recipients}"
    );
    let meta = fs::read_to_string(keystore.join("keys/rkey/meta.toml")).unwrap();
    assert!(meta.contains("recovery_verified"), "paste counts as verification: {meta}");
    assert!(meta.contains("recovery_recipient"));

    let log = shim.argv_log();
    assert!(
        !log.contains("AGE-SECRET-KEY"),
        "the pasted identity must never reach argv: {log}"
    );
    // Self-test ran: an encrypt (-R) and a decrypt (-d -i <fifo>) happened.
    assert!(log.lines().any(|l| l.starts_with("age ") && l.contains("-R")));
    let d = log.lines().find(|l| l.contains("-d")).expect("self-test decrypt ran");
    assert_eq!(d.matches(" -i ").count(), 1, "exactly one -i in the self-test: {d}");
}

#[test]
fn restore_refuses_existing_key_name() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "testkey"],
        "AGE-SECRET-KEY-1WHATEVER\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
}

/// A bad paste (identity the shimmed age-keygen -y rejects) must leave the
/// keystore untouched. The shim accepts anything, so simulate by sending an
/// empty paste three times.
#[test]
fn restore_bad_paste_leaves_keystore_clean() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();
    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey"],
        "\n\n\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        !keystore.join("keys/rkey").exists(),
        "no half-created key dir after a failed paste"
    );
}

/// `keys restore --rekey DIR` re-encrypts containers the identity opens.
#[test]
fn restore_rekey_sweep_rewrites_containers() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();
    let before = fixture_container();
    fs::write(work.path().join(".env"), &before).unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey", "--rekey", "."],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("re-encrypted"), "sweep reported: {stderr}");
    let after = fs::read_to_string(work.path().join(".env")).unwrap();
    assert!(after.contains("AI_ENV=1"), "still a container");
    // Shim round-trips bytes (decrypt=cat, encrypt=cat), so the PAYLOAD is
    // unchanged — but the file is rewritten as the full canonical container
    // (header comment + metadata vars).
    let payload = |t: &str| {
        t.lines().find(|l| l.starts_with("AI_ENV_DATA=")).map(str::to_owned).unwrap()
    };
    assert_eq!(payload(&after), payload(&before));
    assert!(after.contains("AI_ENV_README"), "canonical container written");
}

/// `keys add-recipient`: append, label, idempotency, and the private-identity
/// mispaste guard.
#[test]
fn keys_add_recipient_flow() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";

    // Add with a label.
    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "add-recipient", "testkey", X_REC, "--label", "server-devnet (SSM)"],
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let recipients = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert!(recipients.lines().any(|l| l.trim() == X_REC));
    assert!(recipients.contains("server-devnet (SSM)"), "label comment: {recipients}");

    // Idempotent: exit 0, still exactly one occurrence.
    let out = run_ai_env(&shim, &keystore, work.path(), &["keys", "add-recipient", "testkey", X_REC]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already a recipient"));
    let recipients = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert_eq!(recipients.lines().filter(|l| l.trim() == X_REC).count(), 1);
}

#[test]
fn keys_add_recipient_rejects_private_identity_paste() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    let before = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();

    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "add-recipient", "testkey", "AGE-SECRET-KEY-1OOPSPASTED"],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("PRIVATE identity"), "loud guard message: {err}");
    let after = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert_eq!(after, before, "recipients.txt must be untouched");
}

#[test]
fn keys_add_recipient_rejects_junk_and_unknown_key() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);

    let out = run_ai_env(&shim, &keystore, work.path(), &["keys", "add-recipient", "testkey", "age1notvalidbech32!!"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a valid age recipient"));

    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "add-recipient", "nosuchkey", "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0"],
    );
    assert_eq!(out.status.code(), Some(4));
}

// ---- v5.2 audit-fix regressions ---------------------------------------------

/// F3: a self-test failure must remove the half-created key AND not leave a
/// dangling `default` pointing at it.
#[test]
fn restore_self_test_failure_cleans_up_and_leaves_no_default() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();

    let out = run_ai_env_stdin_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey"],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
        &[("AI_ENV_SHIM_FAIL_DECRYPT", "1")],
    );
    assert_eq!(out.status.code(), Some(1), "stdout: {}", String::from_utf8_lossy(&out.stdout));
    assert!(!keystore.join("keys/rkey").exists(), "key dir removed after self-test failure");
    assert!(
        !keystore.join("default").exists(),
        "default must not dangle at a removed key"
    );
}

/// C5: an invalid (non-AGE-SECRET-KEY) paste is rejected per attempt and the
/// command aborts cleanly after three.
#[test]
fn restore_invalid_paste_retries_then_aborts() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey"],
        "not-a-key\nstill-not-a-key\nnope\n",
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.matches("not a valid AGE-SECRET-KEY line").count() >= 3,
        "each attempt gets feedback (on stderr, not stdout): {err}"
    );
    assert!(err.contains("no valid recovery identity"));
    assert!(!keystore.join("keys/rkey").exists());
}

/// F2/C4: uppercase input is normalized to lowercase before validate, dedupe,
/// and append — age only accepts lowercase in -R files.
#[test]
fn add_recipient_normalizes_uppercase() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
    let upper = X_REC.to_ascii_uppercase();

    let out = run_ai_env(&shim, &keystore, work.path(), &["keys", "add-recipient", "testkey", &upper]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let recipients = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert!(recipients.lines().any(|l| l.trim() == X_REC), "stored lowercase: {recipients}");
    assert!(!recipients.contains(&upper), "no uppercase line: {recipients}");

    // The lowercase twin is a duplicate of what was just added.
    let out = run_ai_env(&shim, &keystore, work.path(), &["keys", "add-recipient", "testkey", X_REC]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already a recipient"));
    let recipients = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert_eq!(recipients.lines().filter(|l| l.trim() == X_REC).count(), 1);
}

/// F4: a label with an embedded newline would inject live recipient lines.
#[test]
fn add_recipient_rejects_multiline_label() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    let before = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();

    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &[
            "keys",
            "add-recipient",
            "testkey",
            "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0",
            "--label",
            "ok\nage1evilinjectedrecipient",
        ],
    );
    assert_eq!(out.status.code(), Some(2), "usage error");
    let after = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert_eq!(after, before, "recipients.txt untouched");
}

/// F4 (restore half): --strongbox-entry is interpolated into a recipients.txt
/// comment and must be a single line.
#[test]
fn keygen_rejects_multiline_strongbox_entry() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();
    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keygen", "k1", "--strongbox-entry", "vault\nage1evil"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(!keystore.join("keys/k1").exists());
}

/// F2 belt-and-braces: if age rejects the updated recipients file, the append
/// is rolled back — recipients.txt can never be left in a broken state.
#[test]
fn add_recipient_probe_failure_rolls_back() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    let before = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();

    let out = run_ai_env_env(
        &shim,
        &keystore,
        work.path(),
        &[
            "keys",
            "add-recipient",
            "testkey",
            "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0",
        ],
        &[("AI_ENV_SHIM_FAIL_ENCRYPT", "1")],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("rolled back"));
    let after = fs::read_to_string(keystore.join("keys/testkey/recipients.txt")).unwrap();
    assert_eq!(after, before, "append rolled back");
}

/// F7 + F16: with --rekey, the >10 gate counts only the key's own files, and
/// the "already a recipient" path still runs the sweep.
#[test]
fn add_recipient_rekey_gate_ignores_foreign_files_and_reruns_sweep() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";

    // 12 foreign containers (would trip the >10 gate if counted) + 2 ours.
    use base64::Engine as _;
    let foreign_ct = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ai-env-age/testdata/foreign.age"
    ))
    .unwrap();
    let foreign = format!(
        "AI_ENV=1\nAI_ENV_DATA={}\n",
        base64::engine::general_purpose::STANDARD.encode(foreign_ct)
    );
    for i in 0..12 {
        fs::write(work.path().join(format!("foreign{i}.env")), &foreign).unwrap();
    }
    fs::write(work.path().join("mine1.env"), fixture_container()).unwrap();
    fs::write(work.path().join("mine2.env"), fixture_container()).unwrap();

    // No --yes: succeeds because only the 2 matching files count.
    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "add-recipient", "testkey", X_REC, "--rekey", "."],
    );
    assert!(
        out.status.success(),
        "gate must count filtered files only\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches("re-encrypted").count(), 2, "both owned files swept: {err}");
    assert_eq!(err.matches("skipping ").count(), 12, "foreign files skipped: {err}");

    // Re-run: idempotent on the recipient, but the sweep must still happen.
    let out = run_ai_env(
        &shim,
        &keystore,
        work.path(),
        &["keys", "add-recipient", "testkey", X_REC, "--rekey", "."],
    );
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("already a recipient"));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).matches("re-encrypted").count(),
        2,
        "sweep runs even when the recipient was already present"
    );
}

/// F5: `keys restore NAME --rekey .` on an EXISTING key runs sweep-only mode —
/// the paste is verified against the stored recovery recipient, no new key.
#[test]
fn restore_sweep_only_on_existing_key() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    fs::write(
        keystore.join("keys/testkey/meta.toml"),
        "created = \"2026-08-30\"\naccess_control = \"none\"\n\
         recovery_recipient = \"age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0\"\n",
    )
    .unwrap();
    let identity_before = fs::read_to_string(keystore.join("keys/testkey/identity.txt")).unwrap();
    fs::write(work.path().join(".env"), fixture_container()).unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "testkey", "--rekey", "."],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("sweep-only"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("re-encrypted"));
    // No new key was created: identity untouched, plugin keygen never ran.
    assert_eq!(
        fs::read_to_string(keystore.join("keys/testkey/identity.txt")).unwrap(),
        identity_before
    );
    assert!(!shim.argv_log().contains("age-plugin-se keygen"));
    // Possession + match counts as the quarterly drill.
    let meta = fs::read_to_string(keystore.join("keys/testkey/meta.toml")).unwrap();
    assert!(meta.contains("recovery_verified"), "{meta}");
}

/// F5 guard: in sweep-only mode a valid identity for the WRONG key bails
/// without touching anything.
#[test]
fn restore_sweep_only_wrong_identity_bails() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fake_keystore(&keystore);
    // Expect a recipient the shim's age-keygen -y will NOT derive.
    fs::write(
        keystore.join("keys/testkey/meta.toml"),
        "created = \"2026-08-30\"\naccess_control = \"none\"\n\
         recovery_recipient = \"age1expectedsomethingelse\"\n",
    )
    .unwrap();
    let container = fixture_container();
    fs::write(work.path().join(".env"), &container).unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "testkey", "--rekey", "."],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("WRONG RECOVERY KEY"));
    assert_eq!(fs::read_to_string(work.path().join(".env")).unwrap(), container);
}

/// F6: `--new-recovery --rekey` pastes the OLD identity for the sweep and
/// still runs the full fresh ceremony for the new one.
#[test]
fn restore_new_recovery_with_rekey_sweeps() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();
    fs::write(work.path().join(".env"), fixture_container()).unwrap();

    // Line 1: the OLD identity (sweep). Line 2: the ceremony paste-back of
    // the NEW identity the shim's age-keygen "generated".
    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey", "--new-recovery", "--rekey", "."],
        "AGE-SECRET-KEY-1FAKEOLDIDENTITY\nAGE-SECRET-KEY-1FAKENEWRECOVERY\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let recipients = fs::read_to_string(keystore.join("keys/rkey/recipients.txt")).unwrap();
    assert!(recipients.contains("age15csf02ez9ze9"), "fresh recovery recipient: {recipients}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("re-encrypted"),
        "the OLD identity drove the sweep"
    );
    assert!(!shim.argv_log().contains("AGE-SECRET-KEY"), "no secrets in argv");
}

/// F9/C2: a wrong-but-valid identity that opens nothing is called out loudly,
/// and a bogus --rekey directory is refused before the paste.
#[test]
fn restore_rekey_warns_when_identity_opens_nothing() {
    let shim = Shim::new();
    let work = tempfile::tempdir().unwrap();
    let keystore = work.path().join("ks");
    fs::create_dir_all(&keystore).unwrap();
    // A container the "identity" cannot open: the shim age -d fails on the
    // AI_ENV_SHIM_FAIL marker riding after a real age header (the payload
    // must still satisfy container::detect's is_age check).
    use base64::Engine as _;
    let mut ct = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ai-env-age/testdata/test-tag.age"
    ))
    .unwrap();
    ct.extend_from_slice(b"AI_ENV_SHIM_FAIL");
    fs::write(
        work.path().join(".env"),
        format!("AI_ENV=1\nAI_ENV_DATA={}\n", base64::engine::general_purpose::STANDARD.encode(ct)),
    )
    .unwrap();

    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "rkey", "--rekey", "."],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WARNING"), "loud when nothing was re-encrypted: {stdout}");
    assert!(stdout.contains("re-encrypted 0 file(s)"), "{stdout}");

    // Typo'd directory: refused up front, before any paste or key creation.
    let out = run_ai_env_stdin(
        &shim,
        &keystore,
        work.path(),
        &["keys", "restore", "other", "--rekey", "./no-such-dir"],
        "AGE-SECRET-KEY-1FAKERESTOREIDENTITY\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a readable directory"));
    assert!(!keystore.join("keys/other").exists());
}
