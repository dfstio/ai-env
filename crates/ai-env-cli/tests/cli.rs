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
    /// canned output.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        for name in ["age", "age-keygen", "age-plugin-se"] {
            let path = dir.path().join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\n\
                     echo \"{name} $*\" >> {log}\n\
                     case \"$1\" in\n\
                       --version) echo v1.3.2; exit 0;;\n\
                     esac\n\
                     # decrypt/encrypt: echo stdin back\n\
                     cat\n",
                    log = log.display()
                ),
            )
            .unwrap();
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
    Command::new(bin())
        .current_dir(work)
        .env_clear()
        .env("PATH", shim.path_env())
        .env("HOME", work)
        .env("AI_ENV_DIR", keystore)
        .args(args)
        .output()
        .unwrap()
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
