//! `ai-env creds aws-set` (plan D23) through the binary. PATH is a temp bin
//! dir holding the shared fake age (tests/fakes/age.sh, which hex-encodes, so
//! "no plaintext on disk" is testable) and the fake aws (tests/fakes/aws.sh),
//! then /usr/bin:/bin for the tools those scripts use. The keystore key is a
//! fake key dir built the way tests/cli.rs builds one, with its public test
//! recipients. HOME, AI_ENV_DIR, AI_ENV_BRIDGE_DIR and TMPDIR all live in one
//! temp tree, so walking that tree covers every file the run could write.
//! Every access key id and secret is built at run time.
use super::common::*;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const USER: &str = "ai-env-runtime";
const KEY: &str = "ai-env-bridge";
/// The public SE tag recipient and X25519 recovery recipient of tests/cli.rs.
const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";

fn fake(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

/// One temp tree: `bin/` (the fakes), `keys/` (AI_ENV_DIR), `bridge/`
/// (AI_ENV_BRIDGE_DIR), `tmp/` (TMPDIR) and the two fake logs.
struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    fn new(with_aws: bool) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(tmp.path().join("tmp")).unwrap();
        let install = |src: &str, name: &str| {
            let dst = bin.join(name);
            fs::copy(fake(src), &dst).unwrap();
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();
        };
        for name in ["age", "age-keygen", "age-plugin-se"] {
            install("age.sh", name);
        }
        if with_aws {
            install("aws.sh", "aws");
        }
        Env { tmp }
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn bin(&self) -> PathBuf {
        self.root().join("bin")
    }

    /// `keys/keys/<name>/` with an SE identity stub and, when `recovery`, the
    /// X25519 recovery recipient beside the tag recipient.
    fn keystore(&self, name: &str, recovery: bool) {
        let dir = self.root().join("keys").join("keys").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
        let recipients = if recovery { format!("{SE_REC}\n{X_REC}\n") } else { format!("{SE_REC}\n") };
        fs::write(dir.join("recipients.txt"), recipients).unwrap();
        fs::write(dir.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut all = vec!["creds", "aws-set"];
        all.extend_from_slice(args);
        let mut cmd = ai_env(self.root(), &all);
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("TMPDIR", self.root().join("tmp"))
            .env("FAKE_AGE_LOG", self.age_log())
            .env("FAKE_AWS_LOG", self.aws_log())
            .env_remove("FAKE_AGE_FAIL")
            .env_remove("FAKE_AWS_KEYS")
            .env_remove("FAKE_AWS_FAIL");
        cmd
    }

    fn credentials(&self) -> PathBuf {
        self.root().join("bridge").join("credentials")
    }

    fn aws_env(&self) -> PathBuf {
        self.credentials().join("aws.env")
    }

    fn audit(&self) -> PathBuf {
        self.root().join("bridge").join("audit.jsonl")
    }

    fn age_log(&self) -> PathBuf {
        self.root().join("age.log")
    }

    fn aws_log(&self) -> PathBuf {
        self.root().join("aws.log")
    }

    /// The fake age's `-d`: the sealed container back to its plaintext.
    fn open(&self, container_text: &str) -> String {
        let c = ai_env_cli::container::read(container_text).expect("a valid ai-env container");
        let identity = self.root().join("keys").join("keys").join(KEY).join("identity.txt");
        let mut child = Command::new(self.bin().join("age"))
            .args(["-d", "-i"])
            .arg(&identity)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&c.data).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "fake age -d: {}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    }
}

/// Run with `input` on a pipe that is closed after writing.
fn piped(cmd: &mut Command, input: &[u8]) -> Output {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// A stdout whose reader is gone before the child starts: every write fails
/// with EPIPE (Rust ignores SIGPIPE), the extreme of `--check | head -1`.
fn closed_stdout() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    Stdio::from(writer)
}

/// Wait for `child`, killing it and failing the test after 30 s: a child that
/// reads a stdin nobody writes to would otherwise hang the suite.
fn wait_bounded(mut child: std::process::Child, what: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{what}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// A test access key: `AKIA` + `CREDCRED` + the tag twice (20), and 40
/// characters of the secret alphabet ending in the lowercased tag.
struct TestKey {
    id: String,
    secret: String,
}

fn test_key(tag: &str) -> TestKey {
    assert_eq!(tag.len(), 4);
    TestKey { id: format!("AKIA{}{}", "CRED".repeat(2), tag.repeat(2)), secret: format!("{}{}", "Tq8+".repeat(9), tag.to_lowercase()) }
}

/// What `aws iam create-access-key --output json` prints.
fn key_json(user: &str, key: &TestKey, status: &str) -> String {
    format!(
        "{{\n    \"AccessKey\": {{\n        \"UserName\": \"{user}\",\n        \"AccessKeyId\": \"{}\",\n        \"Status\": \"{status}\",\n        \"SecretAccessKey\": \"{}\",\n        \"CreateDate\": \"2026-09-29T10:00:00+00:00\"\n    }}\n}}\n",
        key.id, key.secret
    )
}

fn expected_env(key: &TestKey) -> String {
    format!("AWS_ACCESS_KEY_ID={}\nAWS_SECRET_ACCESS_KEY={}\n", key.id, key.secret)
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            files_under(&path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

/// `needle` appears in no file anywhere under `root`.
fn assert_nowhere(root: &Path, needle: &str, what: &str) {
    let mut files = Vec::new();
    files_under(root, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let bytes = fs::read(&f).unwrap();
        assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_bytes()), "{what} found in {}", f.display());
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn audit_rows(env: &Env) -> Vec<serde_json::Value> {
    fs::read_to_string(env.audit()).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn delete_command(user: &str, id: &str) -> String {
    format!("aws iam delete-access-key --user-name {user} --access-key-id {id} --region eu-central-1")
}

#[test]
fn creds_check_fails_without_the_keystore_key() {
    let env = Env::new(true);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(5), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l.starts_with("[NO ] keystore key")), "{}", stdout(&out));
    assert!(stderr(&out).contains("ai-env keygen ai-env-bridge"), "{}", stderr(&out));

    // Sealing hits the same preflight after the key was read: nothing is
    // written and the operator gets the command that deletes the new key.
    let key = test_key("NOKY");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(5), "stderr {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("ai-env keygen ai-env-bridge") && err.contains("was NOT stored"), "{err}");
    assert!(err.contains(&delete_command(USER, &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && !stdout(&out).contains(&key.secret));
    assert!(!env.credentials().exists(), "nothing may be created");
}

#[test]
fn creds_check_passes_with_the_fakes_and_never_reads_stdin() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    // stdin stays an open pipe nobody writes to: a read would block until the deadline.
    let mut child = env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "1").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let held = child.stdin.take();
    let out = wait_bounded(child, "--check blocked (reading stdin?)");
    drop(held);
    let text = stdout(&out);
    assert_eq!(out.status.code(), Some(0), "stdout {text} stderr {}", stderr(&out));
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 5, "{text}");
    assert!(rows.iter().all(|r| r.starts_with("[ok ] ")), "{text}");
    for want in ["keystore key ai-env-bridge", "has a recovery recipient", "age v1.3.2", "aws.env (new; ", "has 1 access key(s)"] {
        assert!(text.contains(want), "{want:?} missing from {text}");
    }
    let aws = fs::read_to_string(env.aws_log()).unwrap();
    assert_eq!(aws.trim(), format!("iam list-access-keys --user-name {USER} --region eu-central-1 --output json"));
    assert!(!env.credentials().exists() && !env.audit().exists(), "--check writes nothing");
}

#[test]
fn creds_check_refuses_a_user_that_has_two_keys() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "2"));
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    let row = text.lines().find(|l| l.starts_with("[NO ]")).expect("a failing row");
    assert!(row.contains("already has 2 access keys") && row.contains("delete one first"), "{row}");
    assert!(row.contains(&format!("AKIAFAKE{:012}", 1)) && row.contains(&format!("AKIAFAKE{:012}", 2)), "{row}");
    assert_eq!(text.lines().filter(|l| l.starts_with("[ok ] ")).count(), 4, "{text}");

    // An aws failure (expired session) fails the check as an AWS error.
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_FAIL", "1"));
    assert_eq!(out.status.code(), Some(7), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[NO ] aws iam list-access-keys") && stdout(&out).contains("ExpiredToken"), "{}", stdout(&out));
}

#[test]
fn creds_check_names_a_missing_iam_user() {
    // Before `make deploy` the user does not exist: the row says so instead of
    // echoing the API error, and still fails (runtime-key needs the user).
    let env = Env::new(true);
    env.keystore(KEY, true);
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_FAIL", "nouser"));
    assert_eq!(out.status.code(), Some(7), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    let failing: Vec<&str> = text.lines().filter(|l| l.starts_with("[NO ]")).collect();
    assert_eq!(failing, [format!("[NO ] IAM user {USER} does not exist yet (make deploy creates it)")], "{text}");
    assert_eq!(text.lines().filter(|l| l.starts_with("[ok ] ")).count(), 4, "{text}");
    assert!(!text.contains("NoSuchEntity"), "{text}");
}

#[test]
fn creds_check_fails_on_a_closed_stdout() {
    // `--check | head -1`: the rows cannot be written, yet a failing check
    // keeps its exit class (a broken pipe alone would be exit 0).
    let env = Env::new(true);
    let out = run(env.cmd(&["--check"]).stdout(closed_stdout()));
    assert_eq!(out.status.code(), Some(5), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("ai-env keygen ai-env-bridge"), "{}", stderr(&out));
    // The class is the first failing row's, even when that row is printed last.
    env.keystore(KEY, true);
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "2").stdout(closed_stdout()));
    assert_eq!(out.status.code(), Some(9), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("already has 2 access keys"), "{}", stderr(&out));
    // Every row passed: the closed pipe is the documented silent exit 0.
    let out = run(env.cmd(&["--check"]).env("FAKE_AWS_KEYS", "1").stdout(closed_stdout()));
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(stderr(&out), "");
}

#[test]
fn creds_check_fails_without_the_aws_cli() {
    if ["/usr/bin/aws", "/bin/aws"].iter().any(|p| Path::new(p).exists()) {
        eprintln!("skipped: a system aws on /usr/bin:/bin cannot be hidden from PATH");
        return;
    }
    let env = Env::new(false);
    env.keystore(KEY, true);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(1), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[NO ] aws CLI not found on PATH"), "{}", stdout(&out));
}

#[test]
fn creds_aws_set_seals_without_plaintext_anywhere() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let key = test_key("WXYZ");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert_eq!(stdout(&out), format!("sealed {USER} access key ...WXYZ into {} (key {KEY})\n", env.aws_env().display()));
    assert_eq!(stderr(&out), "");

    // 0600 container in a 0700 dir; it decrypts to exactly render_env's text.
    assert_eq!(mode(&env.aws_env()), 0o600);
    assert_eq!(mode(&env.credentials()), 0o700);
    let text = fs::read_to_string(env.aws_env()).unwrap();
    assert!(ai_env_cli::container::detect(&text));
    let plain = env.open(&text);
    assert_eq!(plain, expected_env(&key));
    let parsed = ai_env_cli::bridge::creds::parse_key_input(key_json(USER, &key, "Active").as_bytes(), USER).unwrap();
    assert_eq!(plain, ai_env_cli::bridge::creds::render_env(&parsed).as_str());
    // Encrypted to the key's recipients file: both recipients, via -R, no secret in argv.
    let data = ai_env_cli::container::read(&text).unwrap().data;
    let header = String::from_utf8_lossy(&data);
    assert!(header.contains(&format!("-> fake-age {SE_REC}")) && header.contains(&format!("-> fake-age {X_REC}")), "{header}");
    let age_log = fs::read_to_string(env.age_log()).unwrap();
    let recipients = env.root().join("keys").join("keys").join(KEY).join("recipients.txt");
    assert!(age_log.lines().any(|l| l == format!("age -e -R {}", recipients.display())), "{age_log}");
    assert!(!age_log.contains(&key.secret));

    // The secret is nowhere on disk in the clear, nor in any output; the full
    // id is nowhere either (the audit row keeps the last four characters).
    assert_nowhere(env.root(), &key.secret, "the secret");
    assert_nowhere(env.root(), &key.id, "the full access key id");
    assert!(!stdout(&out).contains(&key.secret) && !stdout(&out).contains(&key.id));
    let rows = audit_rows(&env);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["event"], "creds_aws_set");
    assert_eq!(rows[0]["detail"]["user"], USER);
    assert_eq!(rows[0]["detail"]["key_id_last4"], "WXYZ");
    assert_eq!(rows[0]["detail"]["key"], KEY);
    assert_eq!(rows[0]["detail"]["rotated"], "false");
    assert!(!fs::read_dir(env.credentials()).unwrap().flatten().any(|e| e.file_name().to_string_lossy().ends_with(".bak")), "no backup on a first seal");
}

#[test]
fn creds_rotation_backs_up_the_previous_container() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let first = test_key("ROT1");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &first, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let before = fs::read_to_string(env.aws_env()).unwrap();

    // The second key comes through the real pipe shape: the fake aws's
    // create-access-key output (key number 2) straight into aws-set.
    let created = run(Command::new(env.bin().join("aws"))
        .args(["iam", "create-access-key", "--user-name", USER, "--region", "eu-central-1", "--output", "json"])
        .env("PATH", "/usr/bin:/bin")
        .env("FAKE_AWS_KEYS", "1"));
    assert!(created.status.success(), "{}", stderr(&created));
    let json: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let second = TestKey {
        id: json["AccessKey"]["AccessKeyId"].as_str().unwrap().to_string(),
        secret: json["AccessKey"]["SecretAccessKey"].as_str().unwrap().to_string(),
    };
    // Backups are named by the second; never let two seals share one.
    std::thread::sleep(Duration::from_millis(1100));
    let out = piped(&mut env.cmd(&[]), &created.stdout);
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with(&format!("sealed {USER} access key ...0002 into ")), "{text}");
    assert!(text.contains("previous container kept as "), "{text}");

    let backups: Vec<PathBuf> = fs::read_dir(env.credentials())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            n.starts_with("aws.env.") && n.ends_with(".bak") && n[8..n.len() - 4].bytes().all(|b| b.is_ascii_digit())
        })
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(mode(&backups[0]), 0o600);
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), before, "the backup is the previous container, byte for byte");
    assert_eq!(env.open(&before), expected_env(&first));
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&second));
    assert_nowhere(env.root(), &first.secret, "the first secret");
    assert_nowhere(env.root(), &second.secret, "the second secret");
    let rows = audit_rows(&env);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["detail"]["key_id_last4"], "0002");
    assert_eq!(rows[1]["detail"]["rotated"], "true");
}

/// A terminal on stdin (the slave side of an `openpty` pair) is refused before
/// anything is read, so the JSON is never pasted into a scrollback; a pipe
/// reaches parsing, where another user's key is refused with the cleanup.
#[test]
fn creds_refuses_a_tty_or_a_foreign_user() {
    use std::io::IsTerminal as _;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let env = Env::new(true);
    env.keystore(KEY, true);
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid for the call; name, termios and winsize may be null.
    let rc = unsafe { libc::openpty(&raw mut master, &raw mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // openpty's descriptors are inheritable: mark both close-on-exec so neither
    // leaks into the child (its stdin is a dup2 copy, which drops the flag) nor
    // into children other tests spawn meanwhile.
    for fd in [master, slave] {
        // SAFETY: fd is one of the two descriptors openpty just returned.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0, "FD_CLOEXEC: {}", std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // What the child tests with `is_terminal()`: the refusal below is the TTY branch.
    assert!(slave.is_terminal(), "the openpty slave must be a terminal");
    // The master stays open until the child is done, so a read of the
    // terminal would block (bounded by wait_bounded) instead of seeing EOF.
    let child = env.cmd(&[]).stdin(Stdio::from(slave)).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let out = wait_bounded(child, "aws-set read the terminal instead of refusing it");
    drop(master);
    assert_eq!(out.status.code(), Some(2), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stderr(&out).contains("stdin is a terminal: pipe the JSON of aws iam create-access-key into this command"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(!env.credentials().exists() && !env.audit().exists(), "nothing may be created");

    let key = test_key("FRGN");
    let out = piped(&mut env.cmd(&[]), key_json("rust", &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("\"rust\"") && err.contains(&format!("\"{USER}\"")), "both user names: {err}");
    assert!(err.contains("was NOT stored") && err.contains(&delete_command("rust", &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && !stdout(&out).contains(&key.secret));
    assert!(!env.credentials().exists() && !env.audit().exists());
    assert!(!env.age_log().exists() || !fs::read_to_string(env.age_log()).unwrap().contains(" -e "), "nothing encrypted");

    // An inactive key of the right user is refused too, with the cleanup.
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Inactive").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("not \"Active\"") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));

    // Garbage names no key: the note says how to find and delete it.
    let out = piped(&mut env.cmd(&[]), b"not json");
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains(&format!("aws iam list-access-keys --user-name {USER} --region eu-central-1")), "{}", stderr(&out));
    // So does an empty stdin (the harness default is /dev/null).
    let out = run(&mut env.cmd(&[]));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("stdin is empty"), "{}", stderr(&out));
    assert!(!env.credentials().exists());
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_refuses_a_key_without_recovery_unless_forced() {
    let env = Env::new(true);
    env.keystore(KEY, false);
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(9), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l.starts_with("[NO ] ") && l.contains("no recovery recipient") && l.contains("--force")), "{}", stdout(&out));

    let key = test_key("NREC");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(9), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("--force") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));
    assert!(!env.aws_env().exists());

    let out = run(&mut env.cmd(&["--check", "--force"]));
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(stdout(&out).contains("[ok ] key ai-env-bridge has NO recovery recipient (accepted by --force)"), "{}", stdout(&out));

    let out = piped(&mut env.cmd(&["--force"]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&key));
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_failure_after_parse_prints_the_cleanup_command() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let key = test_key("FAIL");
    let out = piped(env.cmd(&[]).env("FAKE_AGE_FAIL", "encrypt"), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("fake encryption failure"), "{err}");
    assert!(err.contains("the access key ...FAIL of IAM user ai-env-runtime was NOT stored"), "{err}");
    assert!(err.contains(&delete_command(USER, &key.id)), "{err}");
    assert!(!err.contains(&key.secret) && stdout(&out).is_empty());
    assert!(!env.aws_env().exists() && !env.audit().exists());
    assert_nowhere(env.root(), &key.secret, "the secret");
}

#[test]
fn creds_tightens_a_wider_credentials_dir() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    fs::create_dir_all(env.credentials()).unwrap();
    fs::set_permissions(env.credentials(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(mode(&env.credentials()), 0o755);
    let key = test_key("WIDE");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert_eq!(mode(&env.credentials()), 0o700, "an existing 0755 dir is tightened to 0700");
    assert_eq!(mode(&env.aws_env()), 0o600);
    assert_eq!(env.open(&fs::read_to_string(env.aws_env()).unwrap()), expected_env(&key));
}

#[test]
fn creds_refuses_a_symlinked_credentials_dir() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let elsewhere = env.root().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(env.root().join("bridge")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, env.credentials()).unwrap();
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(1), "stdout {}", stdout(&out));
    assert!(stdout(&out).contains("is a symlink"), "{}", stdout(&out));
    let key = test_key("LINK");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(1), "stderr {}", stderr(&out));
    assert!(stderr(&out).contains("is a symlink") && stderr(&out).contains(&delete_command(USER, &key.id)), "{}", stderr(&out));
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing written through the link");
}

#[test]
fn creds_uses_the_creds_key_from_bridge_toml() {
    let env = Env::new(true);
    env.keystore("team-key", true);
    fs::create_dir_all(env.root().join("bridge")).unwrap();
    fs::write(env.root().join("bridge").join("bridge.toml"), "# operator config\n[creds]\nkey = \"team-key\"\n").unwrap();
    let key = test_key("TEAM");
    let out = piped(&mut env.cmd(&[]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stderr {}", stderr(&out));
    assert!(stdout(&out).ends_with("(key team-key)\n"), "{}", stdout(&out));
    let recipients = env.root().join("keys").join("keys").join("team-key").join("recipients.txt");
    assert!(fs::read_to_string(env.age_log()).unwrap().lines().any(|l| l == format!("age -e -R {}", recipients.display())));
    // Without that key the hint names it.
    fs::write(env.root().join("bridge").join("bridge.toml"), "[creds]\nkey = \"other-key\"\n").unwrap();
    let out = run(&mut env.cmd(&["--check"]));
    assert_eq!(out.status.code(), Some(5));
    assert!(stderr(&out).contains("ai-env keygen other-key"), "{}", stderr(&out));
}
