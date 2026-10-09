//! `ai-env creds setup-token | status | forget` (S7) through the binary, on
//! the `creds aws-set` harness: the fake age (hex "encryption", so "nothing
//! in the clear on disk" is testable, and one `age -d` log line per Touch
//! ID), a fake keystore key, one temp tree. Every token is built at run time
//! with a per-test tail, and every test ends by checking that its random
//! part, and every 16-byte piece of it, is nowhere on disk in the clear and
//! in no output of a run that held it. Assertion messages print lengths, or
//! text the scrubber has masked, never a value.
use super::common::*;
use super::creds::{assert_nowhere, assert_unprinted, audit_rows, expected_env, key_json, mode, piped, test_key, wait_bounded, Env, TestKey, KEY, USER};
use ai_env_cli::container;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const PREFIX: &str = "sk-ant-oat01-";

/// What `creds setup-token --stdin` says on stderr once the token is sealed.
const STDIN_REMINDER: &str = "now clear the clipboard if the token came from it (pbcopy </dev/null), and any file or shell history line that holds it\n";

/// A token of the setup-token shape, ending in `tail`.
fn token(tail: &str) -> String {
    format!("{PREFIX}{}{tail}", "Rr7_".repeat(20))
}

/// The part of `t` after its kind prefix: what must never be seen.
fn random_part(t: &str) -> &str {
    &t[PREFIX.len()..]
}

/// `creds setup-token --stdin <extra>` with `t` on the pipe.
fn seal(env: &Env, t: &str, extra: &[&str]) -> Output {
    let mut args = vec!["setup-token", "--stdin"];
    args.extend_from_slice(extra);
    piped(&mut env.creds(&args), format!("{t}\n").as_bytes())
}

/// `creds aws-set` with `key` on the pipe.
fn aws_set(env: &Env, key: &TestKey) -> Output {
    piped(&mut env.creds(&["aws-set"]), key_json(USER, key, "Active").as_bytes())
}

fn token_env(env: &Env) -> PathBuf {
    env.credentials().join("setup-token.env")
}

fn combined(env: &Env) -> PathBuf {
    env.credentials().join("combined.env")
}

/// The `creds_setup_token` audit rows (each seal also writes a `lab_probe` row).
fn seal_rows(env: &Env) -> Vec<serde_json::Value> {
    audit_rows(env).into_iter().filter(|r| r["event"] == "creds_setup_token").collect()
}

/// The `creds_combined` audit rows: how each rebuild of combined.env ended.
fn combined_rows(env: &Env) -> Vec<serde_json::Value> {
    audit_rows(env).into_iter().filter(|r| r["event"] == "creds_combined").collect()
}

/// How many decrypts (Touch IDs) the fake age has served.
fn decrypts(env: &Env) -> usize {
    fs::read_to_string(env.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
}

fn sha256_of(p: &Path) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(fs::read(p).unwrap()))
}

/// `text` for an assertion message: the scrubber masks any token or key in
/// it, so a failing test never prints one.
fn shown(text: &str) -> String {
    ai_env_cli::wire::redact::scrub(text).into_owned()
}

fn ok(out: &Output) {
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", shown(&stdout(out)), shown(&stderr(out)));
}

/// `got == want` for texts that hold a credential: a failure prints their
/// lengths only.
fn assert_same(got: &str, want: &str, what: &str) {
    assert!(got == want, "{what}: {} bytes where {} were expected", got.len(), want.len());
}

/// What `container` decrypts to with the fake age, as text.
fn opened(env: &Env, container: &Path) -> String {
    env.open(&fs::read_to_string(container).unwrap())
}

/// `--stdin` seals the token, 0600 in the 0700 dir, decrypting to its one
/// dotenv line; the metadata records the kind prefix and length only; the
/// audit row names the source; stderr is the reminder to clear the
/// clipboard and history the token came through; a second seal keeps the
/// first as a backup.
#[test]
fn setup_token_seals_without_the_token_anywhere_in_the_clear() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let t = token("Aa");
    let out = seal(&env, &t, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t), "the token");
    let path = token_env(&env);
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{}", shown(&text));
    assert!(lines[0] == format!("sealed setup-token {PREFIX}… ({} chars) into {} (key {KEY})", t.len(), path.display()), "{}", shown(lines[0]));
    assert!(lines[1] == format!("recorded setup-token-prefix={PREFIX} (expected recorded)"), "{}", shown(lines[1]));
    assert!(lines[2].starts_with(&format!("  chars={}, sealed ", t.len())), "{}", shown(&text));
    assert!(lines[3] == "combined.env not built: no runtime key is sealed yet (`make runtime-key` builds it)", "{}", shown(lines[3]));
    let probe = std::fs::read_to_string(env.root().join("bridge").join("lab").join("probes.jsonl")).unwrap();
    let row: serde_json::Value = serde_json::from_str(probe.lines().last().unwrap()).unwrap();
    assert!((row["probe"].as_str(), row["stage"].as_str(), row["verdict"].as_str()) == (Some("setup-token-prefix"), Some("S7"), Some(PREFIX)), "{}", shown(&row.to_string()));
    assert!(stderr(&out) == STDIN_REMINDER, "{}", shown(&stderr(&out)));
    assert_eq!((mode(&path), mode(&env.credentials())), (0o600, 0o700));
    let text = fs::read_to_string(&path).unwrap();
    assert_same(&env.open(&text), &format!("CLAUDE_CODE_OAUTH_TOKEN={t}\n"), "the sealed plaintext");
    let meta = container::meta(&text);
    assert!((meta["kind"].as_str(), meta["prefix"].as_str(), meta["chars"].as_str()) == ("setup-token", PREFIX, t.len().to_string().as_str()), "{}", shown(&format!("{meta:?}")));
    assert!(meta.contains_key("sealed"), "{}", shown(&format!("{meta:?}")));
    let rows = seal_rows(&env);
    assert_eq!(rows.len(), 1);
    assert!(audit_rows(&env).iter().any(|r| r["event"] == "lab_probe" && r["detail"]["probe"] == "setup-token-prefix"), "the probe row is audited");
    for (k, v) in [("key", KEY), ("prefix", PREFIX), ("source", "stdin"), ("rotated", "false"), ("combined", "skipped")] {
        assert!(rows[0]["detail"][k] == v, "{k}: {}", shown(&rows[0]["detail"][k].to_string()));
    }
    assert_nowhere(env.root(), random_part(&t), "the token");

    let t2 = token("Bb");
    let out = seal(&env, &t2, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t2), "the second token");
    assert!(stdout(&out).contains("previous container kept as "), "{}", shown(&stdout(&out)));
    let baks: Vec<PathBuf> = fs::read_dir(env.credentials()).unwrap().flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("setup-token.env.")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert_eq!(mode(&baks[0]), 0o600);
    assert_same(&opened(&env, &path), &format!("CLAUDE_CODE_OAUTH_TOKEN={t2}\n"), "the second seal");
    assert_eq!(seal_rows(&env)[1]["detail"]["rotated"], "true");
    assert_nowhere(env.root(), random_part(&t), "the first token");
    assert_nowhere(env.root(), random_part(&t2), "the second token");
}

/// `--stdin` takes the whole pipe as the token's one line, read from fd 0
/// itself (never through std's stdin buffer, which is never zeroized): a
/// token wrapped over two lines, or followed by another line, is refused
/// with nothing sealed, never cut to its first line; a token written in two
/// pieces with a pause between them, blank lines around it, is sealed whole.
#[test]
fn setup_token_stdin_takes_the_whole_pipe_as_one_line() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let t = token("Sp");
    let (head, tail) = t.split_at(PREFIX.len() + 40);
    for (input, what) in [(format!("{head}\n{tail}\n"), "a token wrapped over two lines"), (format!("{t}\nthe next line\n"), "a line after the token")] {
        let out = piped(&mut env.creds(&["setup-token", "--stdin", "--no-combined"]), input.as_bytes());
        assert_eq!(out.status.code(), Some(1), "{what}: {}", shown(&stderr(&out)));
        assert!(stderr(&out).contains("the token holds whitespace (one line, one token expected)"), "{what}: {}", shown(&stderr(&out)));
        assert!(!token_env(&env).exists() && seal_rows(&env).is_empty(), "{what}: nothing is sealed");
        assert_unprinted(&out, random_part(&t), "the token");
    }
    let (reader, mut writer) = std::io::pipe().unwrap();
    let child = env.creds(&["setup-token", "--stdin", "--no-combined"]).stdin(Stdio::from(reader)).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    writer.write_all(format!("\n{PREFIX}").as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    writer.write_all(format!("{}\n\n", random_part(&t)).as_bytes()).unwrap();
    drop(writer);
    let out = wait_bounded(child, "setup-token --stdin did not finish");
    ok(&out);
    assert_same(&opened(&env, &token_env(&env)), &format!("CLAUDE_CODE_OAUTH_TOKEN={t}\n"), "the sealed plaintext");
    assert_unprinted(&out, random_part(&t), "the token");
    assert_nowhere(env.root(), random_part(&t), "the token");
}

/// D4: with the runtime key sealed, `creds setup-token` builds combined.env
/// (the key's two lines and the token's), recording both source hashes;
/// rotating the key with `creds aws-set` rebuilds it with one more unseal
/// (the token's), and a derived file is never backed up.
#[test]
fn combined_env_joins_the_runtime_key_and_the_token() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let key = test_key("CMB1");
    let out = aws_set(&env, &key);
    ok(&out);
    assert_unprinted(&out, &key.secret, "the runtime secret");
    assert_eq!(stderr(&out), "", "no token yet: aws-set says nothing of combined.env");
    assert!(!combined(&env).exists());
    let t = token("Cc");
    let before = decrypts(&env);
    let out = seal(&env, &t, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t), "the token");
    assert_unprinted(&out, &key.secret, "the runtime secret");
    assert_eq!(decrypts(&env), before + 1, "one Touch ID: the runtime key");
    assert!(stdout(&out).ends_with(&format!("rebuilt {}: a credentialed command asks for Touch ID once\n", combined(&env).display())), "{}", shown(&stdout(&out)));
    let both = |k: &TestKey, t: &str| format!("{}CLAUDE_CODE_OAUTH_TOKEN={t}\n", expected_env(k));
    let text = fs::read_to_string(combined(&env)).unwrap();
    assert_same(&env.open(&text), &both(&key, &t), "combined.env's plaintext");
    assert_eq!(mode(&combined(&env)), 0o600);
    let meta = container::meta(&text);
    assert_eq!((meta["kind"].as_str(), meta["parts"].as_str()), ("combined", "aws,setup-token"));
    assert_eq!(meta["aws_file_sha256"], sha256_of(&env.aws_env()));
    assert_eq!(meta["token_file_sha256"], sha256_of(&token_env(&env)));
    // The seal's row comes before the rebuild's Touch ID (M47); the rebuild's own row says how it ended.
    assert_eq!(seal_rows(&env).last().unwrap()["detail"]["combined"], "rebuild");
    let rebuilt = combined_rows(&env);
    assert_eq!((rebuilt.len(), rebuilt[0]["detail"]["by"].as_str(), rebuilt[0]["detail"]["outcome"].as_str()), (1, Some("setup-token"), Some("built")));

    let key2 = test_key("CMB2");
    let before = decrypts(&env);
    let out = aws_set(&env, &key2);
    ok(&out);
    assert_unprinted(&out, random_part(&t), "the token");
    assert_unprinted(&out, &key2.secret, "the second runtime secret");
    assert_eq!(decrypts(&env), before + 1, "one Touch ID: the token");
    assert!(stdout(&out).contains(&format!("rebuilt {}", combined(&env).display())), "{}", shown(&stdout(&out)));
    let text = fs::read_to_string(combined(&env)).unwrap();
    assert_same(&env.open(&text), &both(&key2, &t), "combined.env's plaintext after the rotation");
    let rebuilt = combined_rows(&env);
    assert_eq!((rebuilt.len(), rebuilt[1]["detail"]["by"].as_str(), rebuilt[1]["detail"]["outcome"].as_str()), (2, Some("aws-set"), Some("built")));
    assert_eq!(container::meta(&text)["aws_file_sha256"], sha256_of(&env.aws_env()));
    let derived_backups = fs::read_dir(env.credentials()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("combined.env.")).count();
    assert_eq!(derived_backups, 0, "combined.env is never backed up");
    assert_nowhere(env.root(), random_part(&t), "the token");
    assert_nowhere(env.root(), &key.secret, "the first runtime secret");
    assert_nowhere(env.root(), &key2.secret, "the runtime secret");
}

/// A dismissed Touch ID while `creds aws-set` rebuilds combined.env: the new
/// key is still sealed (exit 0), the out-of-date combined.env is removed
/// with a warning, and status then names the two-prompt fallback.
#[test]
fn a_dismissed_unseal_removes_the_out_of_date_combined_env() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let key = test_key("DSM1");
    let out = aws_set(&env, &key);
    ok(&out);
    assert_unprinted(&out, &key.secret, "the first runtime secret");
    let t = token("Dd");
    let out = seal(&env, &t, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t), "the token");
    assert_unprinted(&out, &key.secret, "the first runtime secret");
    assert!(combined(&env).exists());
    let key2 = test_key("DSM2");
    let out = piped(env.creds(&["aws-set"]).env("FAKE_AGE_FAIL", "cancel"), key_json(USER, &key2, "Active").as_bytes());
    ok(&out);
    assert_unprinted(&out, &key2.secret, "the new runtime secret");
    assert_unprinted(&out, random_part(&t), "the token");
    let err = stderr(&out);
    assert!(err.contains("warning: combined.env not built (") && err.contains("the out-of-date one was removed") && err.contains("asks for Touch ID twice"), "{}", shown(&err));
    assert!(!combined(&env).exists());
    assert_same(&opened(&env, &env.aws_env()), &expected_env(&key2), "the new key is sealed all the same");
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    assert!(stdout(&out).contains("[!! ] combined.env: absent (two Touch IDs per credentialed command"), "{}", shown(&stdout(&out)));
    assert_nowhere(env.root(), random_part(&t), "the token");
    assert_nowhere(env.root(), &key.secret, "the first runtime secret");
    assert_nowhere(env.root(), &key2.secret, "the new runtime secret");
}

/// Run `cmd` with `input` on its stdin in a process group of its own, the
/// rebuild's decrypt hanging as an unanswered Touch ID dialog does, and stop
/// it as Ctrl-C at that prompt does: SIGINT to the group, at its default
/// action (no handler runs on the `creds` path). Also whether combined.env
/// was on disk while the prompt was up; the group is gone on return.
fn interrupted_at_the_prompt(env: &Env, cmd: &mut Command, input: &str) -> (Output, bool) {
    use std::os::unix::process::CommandExt as _;
    let pidfile = env.root().join("age.pid");
    let _ = fs::remove_file(&pidfile);
    cmd.env("FAKE_AGE_HANG", "1").env("FAKE_AGE_PIDFILE", &pidfile).process_group(0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // As at a terminal: a `cargo test &` would hand SIGINT down ignored.
    // SAFETY: runs in the forked child before exec; signal(2) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn ai-env");
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    // The fake age writes its pid only on `-d`: here the rebuild's unseal.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !pidfile.exists() && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let asked = pidfile.exists();
    let present = combined(env).exists();
    let group = i32::try_from(child.id()).unwrap();
    // SAFETY: killpg(2) on the group this test made for the child; the fake age is in it too.
    unsafe { libc::killpg(group, libc::SIGINT) };
    let out = wait_bounded(child, "ai-env outlived the SIGINT");
    // SAFETY: as above, for a fake age that outlived the SIGINT.
    unsafe { libc::killpg(group, libc::SIGKILL) };
    assert!(asked, "the rebuild never asked for Touch ID: exit {:?}, stderr {}", out.status.code(), shown(&stderr(&out)));
    (out, present)
}

/// Ctrl-C at the Touch ID of a combined.env rebuild, after `creds
/// setup-token` sealed a new token and after `creds aws-set` sealed a new
/// key: the out-of-date combined.env, which holds the replaced credential,
/// is already gone while the prompt is up, so the interrupted command leaves
/// none behind; the new seal stands. The interrupted `creds setup-token` has
/// already recorded its seal (M47): its audit row, its setup-token-prefix
/// probe row and its "sealed" line come before the rebuild's prompt, and so
/// does the reminder to clear where the token came through.
#[test]
fn an_interrupted_rebuild_leaves_no_out_of_date_combined_env() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let key = test_key("INT1");
    let out = aws_set(&env, &key);
    ok(&out);
    assert_unprinted(&out, &key.secret, "the first runtime secret");
    let (t1, t2) = (token("Ii"), token("Jj"));
    let out = seal(&env, &t1, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t1), "the first token");
    assert_unprinted(&out, &key.secret, "the first runtime secret");
    assert!(combined(&env).exists());
    let (out, present) = interrupted_at_the_prompt(&env, &mut env.creds(&["setup-token", "--stdin"]), &format!("{t2}\n"));
    assert!(!present, "creds setup-token: the out-of-date combined.env was on disk while Touch ID was asked for");
    assert!(!out.status.success() && !combined(&env).exists(), "exit {:?}", out.status.code());
    assert_same(&opened(&env, &token_env(&env)), &format!("CLAUDE_CODE_OAUTH_TOKEN={t2}\n"), "the new token's seal");
    assert_unprinted(&out, random_part(&t2), "the new token");
    // M47: what records the new seal came before the rebuild's Touch ID, which the Ctrl-C ended: its audit row,
    // its probe row and its line; only the rebuild's outcome is missing.
    let rows = seal_rows(&env);
    assert_eq!((rows.len(), rows[1]["detail"]["rotated"].as_str(), rows[1]["detail"]["combined"].as_str()), (2, Some("true"), Some("rebuild")));
    let probes = audit_rows(&env).into_iter().filter(|r| r["event"] == "lab_probe" && r["detail"]["probe"] == "setup-token-prefix").count();
    assert_eq!(probes, 2, "the probe row of each seal");
    assert!(stdout(&out).contains(&format!("sealed setup-token {PREFIX}… ({} chars) into ", t2.len())), "{}", shown(&stdout(&out)));
    assert!(stderr(&out).contains(STDIN_REMINDER), "the reminder, before the prompt: {}", shown(&stderr(&out)));
    assert_eq!(combined_rows(&env).len(), 1, "the first seal's rebuild alone");

    // Backups are named by the second; never let two seals share one.
    std::thread::sleep(Duration::from_millis(1100));
    let out = seal(&env, &t2, &[]);
    ok(&out);
    assert_unprinted(&out, random_part(&t2), "the new token");
    assert_unprinted(&out, &key.secret, "the first runtime secret");
    assert!(combined(&env).exists(), "rebuilt for the next case");
    let key2 = test_key("INT2");
    let (out, present) = interrupted_at_the_prompt(&env, &mut env.creds(&["aws-set"]), &key_json(USER, &key2, "Active"));
    assert!(!present, "creds aws-set: the out-of-date combined.env was on disk while Touch ID was asked for");
    assert!(!out.status.success() && !combined(&env).exists(), "exit {:?}", out.status.code());
    assert_same(&opened(&env, &env.aws_env()), &expected_env(&key2), "the new key's seal");
    assert_unprinted(&out, &key2.secret, "the new runtime secret");
    assert_unprinted(&out, random_part(&t2), "the new token");
    assert_nowhere(env.root(), random_part(&t1), "the first token");
    assert_nowhere(env.root(), random_part(&t2), "the second token");
    assert_nowhere(env.root(), &key.secret, "the first runtime secret");
    assert_nowhere(env.root(), &key2.secret, "the new runtime secret");
}

/// Refusals come before anything is written: no keystore key (exit 5, the
/// token never read), an API key (9), a malformed token (1), `--from-env`
/// without the variable, both sources at once, and `--stdin` on a terminal
/// (2). No message holds the input, and the refused API key is nowhere on
/// disk.
#[test]
fn setup_token_refuses_before_writing_anything() {
    use std::io::IsTerminal as _;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let env = Env::new(false);
    let out = run(&mut env.creds(&["setup-token", "--stdin"]));
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("does not exist: run `ai-env keygen"), "{}", shown(&stderr(&out)));
    env.keystore(KEY, true);
    let api = format!("sk-ant-api03-{}", "Q7".repeat(30));
    for (input, code, says) in [(api.as_str(), 9, "an Anthropic API key"), ("two words in it", 1, "whitespace"), ("", 1, "no token was given")] {
        let out = piped(&mut env.creds(&["setup-token", "--stdin"]), format!("{input}\n").as_bytes());
        assert_eq!(out.status.code(), Some(code), "{says}: {}", shown(&stderr(&out)));
        assert!(stderr(&out).contains(says), "{}", shown(&stderr(&out)));
        assert_unprinted(&out, &api[13..], "the refused API key");
    }
    let out = run(env.creds(&["setup-token", "--from-env"]).env_remove("CLAUDE_CODE_OAUTH_TOKEN"));
    assert_eq!(out.status.code(), Some(2), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("--from-env: CLAUDE_CODE_OAUTH_TOKEN is not set"), "{}", shown(&stderr(&out)));
    let out = run(&mut env.creds(&["setup-token", "--stdin", "--from-env"]));
    assert_eq!(out.status.code(), Some(2), "{}", shown(&stderr(&out)));

    let (mut master, mut slave) = (-1, -1);
    // SAFETY: both out-pointers are valid for the call; name, termios and winsize may be null.
    let rc = unsafe { libc::openpty(&raw mut master, &raw mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    for fd in [master, slave] {
        // SAFETY: fd is one of the two descriptors openpty just returned.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, 0, "FD_CLOEXEC: {}", std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned two open descriptors that nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    assert!(slave.is_terminal());
    let child = env.creds(&["setup-token", "--stdin"]).stdin(Stdio::from(slave)).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let out = wait_bounded(child, "setup-token --stdin read the terminal instead of refusing it");
    drop(master);
    assert_eq!(out.status.code(), Some(2), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("--stdin reads a pipe and stdin is a terminal"), "{}", shown(&stderr(&out)));
    assert!(!token_env(&env).exists(), "nothing sealed");
    assert!(!audit_rows(&env).iter().any(|r| r["event"] == "creds_setup_token"));
    assert_nowhere(env.root(), &api[13..], "the refused API key");
}

/// `--from-env` reads CLAUDE_CODE_OAUTH_TOKEN; without a flag the token is
/// asked for hidden (here on the piped stdin), with a reminder to clear the
/// scrollback and the clipboard.
#[test]
fn setup_token_reads_the_environment_or_a_hidden_paste() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let t = token("Ee");
    let out = run(env.creds(&["setup-token", "--from-env", "--no-combined"]).env("CLAUDE_CODE_OAUTH_TOKEN", &t));
    ok(&out);
    assert_unprinted(&out, random_part(&t), "the first token");
    assert!(stderr(&out).contains("now unset CLAUDE_CODE_OAUTH_TOKEN"), "{}", shown(&stderr(&out)));
    assert_same(&opened(&env, &token_env(&env)), &format!("CLAUDE_CODE_OAUTH_TOKEN={t}\n"), "the first seal");
    assert_eq!(seal_rows(&env)[0]["detail"]["source"], "env");
    let t2 = token("Ff");
    let out = piped(&mut env.creds(&["setup-token", "--no-combined"]), format!("{t2}\n").as_bytes());
    ok(&out);
    let err = stderr(&out);
    assert!(err.contains("(input hidden)") && err.contains("clear the terminal's scrollback and the clipboard"), "{}", shown(&err));
    assert_same(&opened(&env, &token_env(&env)), &format!("CLAUDE_CODE_OAUTH_TOKEN={t2}\n"), "the second seal");
    assert_eq!(seal_rows(&env)[1]["detail"]["source"], "paste");
    assert_unprinted(&out, random_part(&t2), "the second token");
    assert_nowhere(env.root(), random_part(&t), "the first token");
    assert_nowhere(env.root(), random_part(&t2), "the second token");
}

/// `creds status` decrypts nothing (`--unseal` decrypts once); `creds
/// forget` lists first, deletes only with `--yes` — the token, combined.env
/// and their backups, never the runtime key — and names the VMs that
/// received the token. No output holds the token.
#[test]
fn status_needs_no_touch_id_and_forget_lists_before_it_deletes() {
    use ai_env_cli::bridge::vm::registry::{write_row, RowStatus, VmRow};
    let env = Env::new(false);
    env.keystore(KEY, true);
    let key = test_key("STS1");
    let out = aws_set(&env, &key);
    ok(&out);
    assert_unprinted(&out, &key.secret, "the runtime secret");
    let t = token("Gg");
    let mut outs = vec![seal(&env, &t, &[])];
    let t2 = token("Hh");
    outs.push(seal(&env, &t2, &[]));
    outs.iter().for_each(ok);
    let before = decrypts(&env);
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    assert_eq!(decrypts(&env), before, "status asks for no Touch ID");
    let text = stdout(&out);
    // The fake age's header names `fake-age` stanzas, which no keystore key
    // can match without a prompt: the opening key is unknown here (the
    // matching itself is select.rs's, tested with real headers).
    for want in [
        "[!! ] aws.env: sealed; which key opens it is unknown (".to_string(),
        "[!! ] setup-token.env: sealed; which key opens it is unknown (".to_string(),
        format!("; recorded at sealing, not authenticated: {PREFIX}… ({} chars), sealed ", t2.len()),
        "(about 365 days left of its one-year life)".into(),
        "[ok ] combined.env: matches its sources".into(),
        "[-  ] backups: setup-token.env x1".into(),
        "[-  ] VMs that may hold the token: none".into(),
    ] {
        assert!(text.contains(&want), "{want:?} missing from:\n{}", shown(&text));
    }
    outs.push(out);
    let out = run(&mut env.creds(&["status", "--json"]));
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!((v["setup_token_env"]["state"].as_str(), v["setup_token_env"]["recorded"]["prefix"].as_str()), (Some("sealed"), Some(PREFIX)));
    assert_eq!((v["combined_env"]["state"].as_str(), v["backups"]["setup-token.env"].as_u64()), (Some("current"), Some(1)));
    assert!(v["unseal"].is_null());
    outs.push(out);
    let out = run(&mut env.creds(&["status", "--unseal"]));
    ok(&out);
    assert_eq!(decrypts(&env), before + 1, "--unseal: one Touch ID");
    assert!(stdout(&out).contains("unsealed setup-token.env in ") && stdout(&out).contains(&format!("{PREFIX}… ({} chars), as recorded", t2.len())), "{}", shown(&stdout(&out)));
    outs.push(out);

    let paths = ai_env_cli::bridge::config::Paths::from_root_and_env(env.root().join("bridge"), None);
    let id = "microvm-00000000-0000-4000-8000-0000000000c7";
    write_row(&paths, &VmRow { id: id.into(), status: RowStatus::Running, credential_at: Some(1_791_000_000), ..VmRow::default() }).unwrap();
    let out = run(&mut env.creds(&["status"]));
    assert!(stdout(&out).contains(&format!("[!! ] {id} (running) received the token at ")), "{}", shown(&stdout(&out)));

    let bak = fs::read_dir(env.credentials()).unwrap().flatten().map(|e| e.path()).find(|p| p.file_name().unwrap().to_string_lossy().starts_with("setup-token.env.")).unwrap();
    let out = run(&mut env.creds(&["forget"]));
    ok(&out);
    let text = stdout(&out);
    for p in [token_env(&env), combined(&env), bak.clone()] {
        assert!(text.contains(&format!("would delete {}", p.display())), "{}: {}", p.display(), shown(&text));
        assert!(p.exists(), "a dry run deletes nothing");
    }
    assert!(text.contains(&format!("ai-env vm terminate {id}")) && text.contains("ai-env cannot revoke the token") && text.contains("dry run: nothing deleted"), "{}", shown(&text));
    outs.push(out);
    let out = run(&mut env.creds(&["forget", "--yes"]));
    ok(&out);
    assert!(stdout(&out).ends_with("deleted 3 file(s)\n"), "{}", shown(&stdout(&out)));
    assert!(!token_env(&env).exists() && !combined(&env).exists() && !bak.exists());
    assert!(env.aws_env().exists(), "the runtime key is not the token");
    let last = audit_rows(&env).pop().unwrap();
    assert_eq!((last["event"].as_str(), last["detail"]["files"].as_str(), last["detail"]["holders"].as_str()), (Some("creds_forget"), Some("3"), Some("1")));
    outs.push(out);
    let out = run(&mut env.creds(&["status"]));
    assert!(stdout(&out).contains("[-  ] setup-token.env: absent") && stdout(&out).contains("combined.env: not needed (no setup-token is sealed)"), "{}", shown(&stdout(&out)));
    for out in &outs {
        assert_unprinted(out, random_part(&t), "the first token");
        assert_unprinted(out, random_part(&t2), "the second token");
        assert_unprinted(out, &key.secret, "the runtime secret");
    }
    assert_nowhere(env.root(), random_part(&t), "the first token");
    assert_nowhere(env.root(), random_part(&t2), "the second token");
    assert_nowhere(env.root(), &key.secret, "the runtime secret");
}

/// `creds status` shows the credential gate's local preconditions for the
/// image version new VMs run, as doctor judges them with no AWS call (no
/// state recorded: skipped; a version without a passing check: `no_record`,
/// naming `ai-env egress check`), and a refusal of the sealed token recorded
/// in `state/creds.toml`, in text and in `--json`; a `state/creds.toml` that
/// cannot be read is a `[!! ]` row naming it and `rejected_error` (M53),
/// never read as no refusal.
#[test]
fn status_shows_the_gate_preconditions_and_a_refusal() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let t = token("Kk");
    let mut outs = vec![seal(&env, &t, &[])];
    ok(&outs[0]);
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    assert!(stdout(&out).contains("[-  ] credential gate: no state recorded (no state/infra.toml)"), "{}", shown(&stdout(&out)));
    outs.push(out);
    let bridge = env.root().join("bridge");
    fs::create_dir_all(bridge.join("state")).unwrap();
    fs::write(bridge.join("bridge.toml"), "[aws]\negress_connector_arn = \"arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress\"\n").unwrap();
    fs::write(bridge.join("state").join("infra.toml"), "stack = \"dev\"\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\nlatest_active_image_version = \"5.0\"\n").unwrap();
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    let text = stdout(&out);
    assert!(text.contains("[!! ] credential gate: no passing `ai-env egress check` is recorded for image version 5.0") && text.contains("(run `ai-env egress check`) [no_record]"), "{}", shown(&text));
    assert!(!text.contains("refused by Anthropic"), "{}", shown(&text));
    outs.push(out);
    let out = run(&mut env.creds(&["status", "--json"]));
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(v["credential_gate"]["tag"] == "warn" && v["credential_gate"]["text"].as_str().is_some_and(|t| t.ends_with("[no_record]")), "{}", shown(&v["credential_gate"].to_string()));
    assert!(v["rejected"].is_null(), "{}", shown(&v["rejected"].to_string()));
    outs.push(out);

    // The refusal `vm exec` records against this seal (S7 D6).
    let tag = ai_env_cli::bridge::agent::credential::seal_tag(&token_env(&env)).expect("the seal's id");
    let vm = "microvm-00000000-0000-4000-8000-0000000000c9";
    fs::write(bridge.join("state").join("creds.toml"), format!("[[rejected]]\ntag = \"{tag}\"\nat = \"2026-10-07T12:00:00Z\"\nvm = \"{vm}\"\n")).unwrap();
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    assert!(stdout(&out).contains(&format!("[NO ] the sealed setup-token was refused by Anthropic on 2026-10-07T12:00:00Z ({vm})")), "{}", shown(&stdout(&out)));
    outs.push(out);
    let out = run(&mut env.creds(&["status", "--json"]));
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!((v["rejected"]["at"].as_str(), v["rejected"]["vm"].as_str()), (Some("2026-10-07T12:00:00Z"), Some(vm)));
    assert!(v["rejected_error"].is_null());
    outs.push(out);

    // M53: a store that cannot be read is shown as such (credentialed commands refuse every seal then), never as no refusal.
    let state = bridge.join("state").join("creds.toml");
    fs::write(&state, "[[rejected]\n").unwrap();
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    let unknown = format!("[!! ] refusals unknown: {} cannot be parsed (", state.display());
    assert!(stdout(&out).contains(&unknown) && stdout(&out).contains("credentialed commands refuse every seal until it is repaired"), "{}", shown(&stdout(&out)));
    assert!(!stdout(&out).contains("refused by Anthropic") && !stderr(&out).contains("read as no recorded refusal"), "{}", shown(&stderr(&out)));
    outs.push(out);
    let out = run(&mut env.creds(&["status", "--json"]));
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(v["rejected"].is_null() && v["rejected_error"].as_str().is_some_and(|e| e.contains("cannot be parsed")), "{}", shown(&v.to_string()));
    outs.push(out);
    for out in &outs {
        assert_unprinted(out, random_part(&t), "the token");
    }
    assert_nowhere(env.root(), random_part(&t), "the token");
}
