//! S8 operators: `ai-env as` and the AWS operator identity of the CLI's own
//! `aws` children, through the binary (plans/s8-operators-contracts.md §2 to
//! §4). Phase 0 starts it with `ai-env run`'s side of the marker; wave 1
//! (W2a) appends the runner's and the resolver's tests. Keys are built at run
//! time (`aws_keys`); the fakes are the repo's (tests/fakes, through
//! `creds::Env`); nothing touches AWS, the keystore or the bridge directory
//! of this Mac.
use super::aws_keys::{identity_env, DEPLOYER_TAIL};
use super::common::*;
use super::creds::{key_json, piped, test_key, Env, KEY, USER};
use std::path::Path;

/// What the child of `ai-env run` sees, values reduced to what the test needs:
/// the marker, the last four characters of `AWS_ACCESS_KEY_ID` and one plain
/// variable (no secret is printed).
const PROBE: &str = r#"printf 'marker=%s\n' "${AI_ENV_BRIDGE_AS-unset}"; printf 'key=...%s\n' "${AWS_ACCESS_KEY_ID#"${AWS_ACCESS_KEY_ID%????}"}"; printf 'greeting=%s\n' "${GREETING-unset}""#;

/// `ai-env run -f <file> -k <KEY> -- /bin/sh -c PROBE` under `ai-env as
/// deployer` (the deployer key and its marker in the environment), with the
/// fakes on PATH. The key is named, as the recipes name it: the fake age's
/// ciphertext has no age header to match a recipient against.
fn run_under_the_deployer(env: &Env, file: &Path) -> String {
    let file = file.to_str().unwrap();
    let mut cmd = ai_env(env.root(), &["run", "-f", file, "-k", KEY, "--", "/bin/sh", "-c", PROBE]);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", env.root().join("bin").display())).envs(identity_env("deployer", DEPLOYER_TAIL));
    let out = run(&mut cmd);
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    stdout(&out)
}

/// `ai-env run -f credentials/aws.env -- …` under `ai-env as deployer`: the
/// container sets another `AWS_ACCESS_KEY_ID`, so the child loses the marker,
/// which would name the deployer's key, and gets the container's key. A
/// container without a key leaves the inherited marker and key alone, and a
/// marker the container sets itself never reaches the child.
#[test]
fn run_drops_the_runner_marker_when_the_container_sets_a_key() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let sealed = test_key("RUN1");
    let out = piped(&mut env.creds(&["aws-set"]), key_json(USER, &sealed, "Active").as_bytes());
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert_eq!(run_under_the_deployer(&env, &env.aws_env()), "marker=unset\nkey=...RUN1\ngreeting=unset\n");

    // A container of plain variables (and a marker of its own): encrypted in place, no Touch ID.
    let plain = env.root().join("plain.env");
    std::fs::write(&plain, "GREETING=hello\nAI_ENV_BRIDGE_AS=root\n").unwrap();
    let mut encrypt = ai_env(env.root(), &["encrypt", plain.to_str().unwrap(), "-k", KEY]);
    encrypt.env("PATH", format!("{}:/usr/bin:/bin", env.root().join("bin").display()));
    let out = run(&mut encrypt);
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert!(ai_env_cli::container::detect(&std::fs::read_to_string(&plain).unwrap()), "encrypted in place");
    assert_eq!(run_under_the_deployer(&env, &plain), format!("marker=deployer:{DEPLOYER_TAIL}\nkey=...{DEPLOYER_TAIL}\ngreeting=hello\n"));
}

// ---- W2a: the runner `ai-env as` and the resolver (§2 to §4, §8) ----------------------------

use super::aws_keys as keys;
use super::creds::{assert_nowhere, assert_unprinted, audit_rows, holds, TestKey};
use std::fs;
use std::process::{Command, Output};

/// The stack's account and another one (the documentation's).
const STACK: &str = "123456789012";
const OTHER: &str = "999999999999";

/// What a child of `ai-env as` sees, reduced to states, the marker, the key
/// id's tail, the secret's length and the pins: never a key's value.
const SEEN: &str = r#"for n in AWS_PROFILE AWS_SESSION_TOKEN AWS_ENDPOINT_URL_STS AWS_CONTAINER_CREDENTIALS_FULL_URI; do eval "s=\${$n+set}"; echo "$n=${s:-unset}"; done; echo "marker=${AI_ENV_BRIDGE_AS-unset}"; echo "key=...${AWS_ACCESS_KEY_ID#"${AWS_ACCESS_KEY_ID%????}"}"; echo "secret=${#AWS_SECRET_ACCESS_KEY}"; echo "pins=${AWS_CONFIG_FILE-unset} ${AWS_SHARED_CREDENTIALS_FILE-unset} ${AWS_EC2_METADATA_DISABLED-unset} ${AWS_REGION-unset}""#;

/// [`SEEN`]'s output for a child of `ai-env as <role>` with the key of `tail`.
fn seen_as(role: &str, tail: &str) -> String {
    format!(
        "AWS_PROFILE=unset\nAWS_SESSION_TOKEN=unset\nAWS_ENDPOINT_URL_STS=unset\nAWS_CONTAINER_CREDENTIALS_FULL_URI=unset\nmarker={role}:{tail}\nkey=...{tail}\nsecret=40\npins=/dev/null /dev/null true eu-central-1\n"
    )
}

/// `ai-env <args>` in `env`'s tree: the fake age and aws first on PATH, their
/// logs (the aws fake's environment log holds names and pins only), no
/// identity (a test declares one) and no knob of the developer's shell.
fn cli(env: &Env, args: &[&str]) -> Command {
    let mut cmd = ai_env(env.root(), args);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", env.root().join("bin").display()))
        .env("TMPDIR", env.root().join("tmp"))
        .env("FAKE_AGE_LOG", env.age_log())
        .env("FAKE_AWS_LOG", env.root().join("aws.log"))
        .env("FAKE_AWS_ENV_LOG", env.root().join("aws-env.log"));
    cmd
}

/// `ai-env as <args>` (see [`cli`]), the pastes read from stdin (the debug builds' knob).
fn as_cmd(env: &Env, args: &[&str]) -> Command {
    let mut all = vec!["as"];
    all.extend_from_slice(args);
    let mut cmd = cli(env, &all);
    cmd.env("AI_ENV_PASTE_STDIN", "1");
    cmd
}

/// `cmd` with the access key id and the secret pasted, one line each.
fn pasting(cmd: &mut Command, id: &str, secret: &str) -> Output {
    piped(cmd, format!("{id}\n{secret}\n").as_bytes())
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().map(str::to_string).collect()
}

/// The aws calls since the last [`reset`], one argv per line.
fn aws_calls(env: &Env) -> Vec<String> {
    lines(&env.root().join("aws.log"))
}

/// The names and pins of each aws call since the last [`reset`].
fn aws_envs(env: &Env) -> Vec<String> {
    lines(&env.root().join("aws-env.log"))
}

/// The unseals (`age -d`) since the last [`reset`].
fn decrypts(env: &Env) -> usize {
    lines(&env.age_log()).iter().filter(|l| l.starts_with("age ") && l.contains(" -d")).count()
}

/// Forget the fakes' logs (each run is judged on its own calls).
fn reset(env: &Env) {
    for log in [env.root().join("aws.log"), env.root().join("aws-env.log"), env.age_log()] {
        let _ = fs::remove_file(log);
    }
}

/// The audit rows `ai-env as` wrote.
fn as_rows(env: &Env) -> Vec<serde_json::Value> {
    audit_rows(env).into_iter().filter(|r| r["event"] == "as_identity").collect()
}

fn code(out: &Output) -> Option<i32> {
    out.status.code()
}

/// `stderr` holds `line` as one whole line.
fn said(out: &Output, line: &str) -> bool {
    stderr(out).lines().any(|l| l == line)
}

/// `stderr` holds `text` at the end of a line: after a paste read from stdin
/// (the debug builds' knob) the prompts, which end no line, stand before it.
fn said_after_the_prompts(out: &Output, text: &str) -> bool {
    stderr(out).lines().any(|l| l.ends_with(text))
}

/// Environment variables, as `aws_keys` builds them.
type Vars = Vec<(String, String)>;

/// The pins every deployer or ops `aws` child gets, as the fake logs them.
const PINS: &str = "AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_REGION=eu-central-1 AWS_DEFAULT_REGION=eu-central-1 AWS_PAGER=";

/// The deployer key of the fakes (tail 9001) and a secret of its shape.
fn deployer_key() -> (String, String) {
    (keys::key_id(keys::DEPLOYER_TAIL), keys::secret("Pq7+"))
}

/// `state/infra.toml` of `env`, as `make infra-status WRITE=1` writes it after the bootstrap (changed by `f`).
fn write_state(env: &Env, f: impl FnOnce(&mut ai_env_cli::bridge::infra::InfraState)) {
    let mut s = ai_env_cli::bridge::infra::InfraState {
        stack: "dev".into(),
        region: "eu-central-1".into(),
        image_arn: format!("arn:aws:lambda:eu-central-1:{STACK}:microvm-image:ai-env-agent"),
        account_id: Some(STACK.into()),
        deployer_user_name: Some("ai-env-deployer".into()),
        deployer_user_arn: Some(format!("arn:aws:iam::{STACK}:user/ai-env-deployer")),
        ops_user_name: Some("ai-env-ops".into()),
        ops_user_arn: Some(format!("arn:aws:iam::{STACK}:user/ai-env-ops")),
        runtime_user_arn: Some(format!("arn:aws:iam::{STACK}:user/ai-env-runtime")),
        ..Default::default()
    };
    f(&mut s);
    let dir = env.root().join("bridge").join("state");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("infra.toml"), s.render().unwrap()).unwrap();
}

/// A key of `tail` sealed into `credentials/ops.env` as `creds aws-set --user
/// ai-env-ops` leaves it (the keystore key `KEY`, the sealing notes): `creds
/// aws-set` seals it, and its container moves to ops.env with the notes.
fn seal_ops(env: &Env, tail: &str) -> TestKey {
    env.keystore(KEY, true);
    let key = TestKey { id: keys::key_id(tail), secret: keys::secret("Kq3+") };
    let out = piped(&mut env.creds(&["aws-set"]), key_json(USER, &key, "Active").as_bytes());
    assert_eq!(code(&out), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    let data = ai_env_cli::container::read(&fs::read_to_string(env.aws_env()).unwrap()).unwrap().data;
    let notes = ai_env_cli::bridge::identity::KeyNotes::pairs("ai-env-ops", tail, 1_789_804_800);
    let notes: Vec<(&str, &str)> = notes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let ops = env.credentials().join("ops.env");
    fs::write(&ops, ai_env_cli::container::write_annotated(&data, &notes).unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&ops, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(env.aws_env()).unwrap();
    reset(env);
    key
}

/// `ai-env as deployer` (§3.3, §3.6): the two pastes (here the debug
/// builds' stdin), the pinned sts check with only that key, the audit row,
/// then the command runs with exactly the pasted key: every credential
/// selector of the parent gone, the profile files and IMDS pinned off, the
/// marker naming the key's tail. Neither value is ever printed or written.
#[test]
fn as_deployer_runs_the_command_with_only_the_pasted_key() {
    let env = Env::new(true);
    let (id, secret) = deployer_key();
    let mut cmd = as_cmd(&env, &["--account", STACK, "deployer", "--", "/bin/sh", "-c", SEEN]);
    // The parent's own credentials and selectors: none reaches the command. Its secret is 39 characters long, so
    // one left beside the pasted id would show (`secret=39`).
    cmd.env("AWS_PROFILE", "admin")
        .env("AWS_SESSION_TOKEN", "token-of-the-test")
        .env("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:9")
        .env("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/creds")
        .env("AWS_ACCESS_KEY_ID", keys::key_id("9009"))
        .env("AWS_SECRET_ACCESS_KEY", &keys::secret("Zz9/")[..39]);
    let out = pasting(&mut cmd, &id, &secret);
    assert_eq!(code(&out), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert_eq!(stdout(&out), seen_as("deployer", keys::DEPLOYER_TAIL));
    let err = stderr(&out);
    assert!(err.starts_with("ai-env: as ai-env-deployer: paste its access key from Strongbox (nothing you paste is shown)\nai-env-deployer access key id: ai-env-deployer secret access key: "), "{err}");
    let ran = err.split("ai-env-deployer secret access key: ").nth(1).and_then(|rest| rest.lines().next()).unwrap_or_default();
    assert!(ran.starts_with("ai-env: as ai-env-deployer (key ...9001, account …9012, verified): /bin/sh -c for n in"), "{err}");
    assert_eq!(ran.chars().count(), "ai-env: as ai-env-deployer (key ...9001, account …9012, verified): ".chars().count() + 120, "the command cut to 120 characters: {ran}");
    assert!(ran.ends_with('…') && !err.contains(STACK), "the account shows as its last four digits: {err}");
    assert!(!err.contains("clipboard"), "pasted from stdin: no clipboard to clear: {err}");
    // One sts call, pinned, with exactly the pasted key: no selector, the files and IMDS pinned.
    assert_eq!(aws_calls(&env), ["sts get-caller-identity --region eu-central-1 --endpoint-url https://sts.eu-central-1.amazonaws.com --output json"]);
    assert_eq!(aws_envs(&env), [format!("sts get-caller-identity | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")]);
    // The audit row: who, the tail, the account, the command's word; never a value.
    let rows = as_rows(&env);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0]["detail"];
    assert_eq!((d["identity"].as_str(), d["key_id_last4"].as_str(), d["account"].as_str(), d["command"].as_str()), (Some("deployer"), Some("9001"), Some(STACK), Some("sh")), "{}", rows[0]);
    assert_unprinted(&out, &secret, "the pasted secret");
    assert_unprinted(&out, &id, "the pasted key id");
    assert_nowhere(env.root(), &secret, "the pasted secret");
    assert_nowhere(env.root(), &id, "the pasted key id");
    // Pasted with the whitespace a copy brings: trimmed.
    reset(&env);
    let out = pasting(&mut as_cmd(&env, &["--account", STACK, "deployer", "--", "/bin/sh", "-c", SEEN]), &format!("  {id}\t"), &format!(" {secret}  "));
    assert_eq!((code(&out), stdout(&out)), (Some(0), seen_as("deployer", keys::DEPLOYER_TAIL)), "{}", stderr(&out));
}

/// A pasted key that answers as anyone but the stack's deployer is refused
/// before anything runs (§3.6): another user, the account root, the
/// deployer of another account, another ARN than the state records (exit 9);
/// a key AWS refuses (5), one that cannot be checked (7).
#[test]
fn as_deployer_refuses_another_user_the_root_and_another_account() {
    let env = Env::new(true);
    let (id, secret) = deployer_key();
    let ran = env.root().join("ran");
    let touch = format!("touch {}", ran.display());
    let try_as = |env_vars: &[(&str, &str)], account: Option<&str>| {
        reset(&env);
        let mut args = vec![];
        if let Some(a) = account {
            args.extend(["--account", a]);
        }
        args.extend(["deployer", "--", "/bin/sh", "-c", touch.as_str()]);
        let mut cmd = as_cmd(&env, &args);
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        for (k, v) in env_vars {
            cmd.env(k, v);
        }
        pasting(&mut cmd, &id, &secret)
    };
    for (users, want, line) in [
        ("9001:rust", 9, format!("ai-env: as deployer: the key ...9001 answers as arn:aws:iam::{STACK}:user/rust, not ai-env-deployer: nothing was run")),
        ("9001:root", 9, "ai-env: as deployer: the key ...9001 is the account ROOT's: never paste it here (the deployer's key is its own Strongbox entry); delete root's access key: nothing was run".to_string()),
        (
            "9001:ai-env-deployer@999999999999",
            9,
            format!("ai-env: as deployer: the key ...9001 is ai-env-deployer of account {OTHER}, but the stack (--account) is in account {STACK}: nothing was run"),
        ),
        ("9002:ai-env-ops", 5, "ai-env: as deployer: AWS refused the key ...9001 (InvalidClientTokenId): a deleted or deactivated key, or the secret of another key: nothing was run".to_string()),
    ] {
        let out = try_as(&[("FAKE_AWS_KEY_USERS", users)], Some(STACK));
        assert_eq!(code(&out), Some(want), "{users}: {}", stderr(&out));
        assert!(said_after_the_prompts(&out, &line), "{users}: {}", stderr(&out));
        assert_eq!(aws_calls(&env).len(), 1, "{users}: one try: {:?}", aws_calls(&env));
    }
    // The check itself fails (not a refusal): retried once, then exit 7.
    let out = try_as(&[("FAKE_AWS_FAIL_OP", "sts get-caller-identity")], Some(STACK));
    assert_eq!(code(&out), Some(7), "{}", stderr(&out));
    assert!(said_after_the_prompts(&out, "ai-env: the key ...9001 does not answer yet (1/2: An error occurred (AccessDeniedException) when calling the get-caller-identity operation: fake denial)"), "{}", stderr(&out));
    assert!(said(&out, "ai-env: as deployer: the key ...9001 could not be checked (An error occurred (AccessDeniedException) when calling the get-caller-identity operation: fake denial): nothing was run"), "{}", stderr(&out));
    assert_eq!(aws_calls(&env).len(), 2);
    // The state records the deployer under another path: the same name is another user.
    write_state(&env, |s| s.deployer_user_arn = Some(format!("arn:aws:iam::{STACK}:user/team/ai-env-deployer")));
    let out = try_as(&[], None);
    assert_eq!(code(&out), Some(9), "{}", stderr(&out));
    assert!(
        said_after_the_prompts(&out, &format!("ai-env: as deployer: the key ...9001 answers as arn:aws:iam::{STACK}:user/ai-env-deployer, but the stack's deployer is arn:aws:iam::{STACK}:user/team/ai-env-deployer (state/infra.toml): nothing was run")),
        "{}",
        stderr(&out)
    );
    assert!(!ran.exists(), "nothing ran");
    assert!(as_rows(&env).is_empty(), "no audit row for a refused key");
    // The stack's own deployer runs.
    write_state(&env, |_| {});
    let out = try_as(&[], None);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(ran.exists());
}

/// A paste of the wrong shape is refused naming the fault, never the value,
/// before any AWS call (exit 1); an empty paste cancels with its one line
/// (exit 3, no `ai-env: cancelled`, D19).
#[test]
fn as_deployer_refuses_a_malformed_paste_without_echoing_it() {
    let env = Env::new(true);
    let (id, secret) = deployer_key();
    let asia = format!("{}{}", "ASIA", &id[4..]);
    let odd_id = format!("{}x{}", &id[..10], &id[11..]);
    for (paste_id, paste_secret, fault) in [
        (asia.as_str(), secret.as_str(), "access key id is a temporary STS key id (ASIA…), not a long-term IAM user key (AKIA…)"),
        (odd_id.as_str(), secret.as_str(), "access key id has a character outside 0-9 A-Z"),
        (&id[..19], secret.as_str(), "access key id has 19 characters, expected 20"),
        (id.as_str(), &secret[..39], "secret access key has 39 characters, expected 40"),
        (id.as_str(), &format!("{}-", &secret[..39]), "secret access key has a character outside A-Z a-z 0-9 / +"),
    ] {
        reset(&env);
        let out = pasting(&mut as_cmd(&env, &["--account", STACK, "deployer", "--", "true"]), paste_id, paste_secret);
        assert_eq!(code(&out), Some(1), "{fault}: {}", stderr(&out));
        assert!(said_after_the_prompts(&out, &format!("ai-env: as deployer: the pasted {fault} (not echoed): nothing was run")), "{}", stderr(&out));
        assert!(aws_calls(&env).is_empty(), "{fault}: no AWS call");
        for value in [paste_id, paste_secret] {
            assert_unprinted(&out, value, "a pasted value");
        }
    }
    for input in ["\n", &format!("{id}\n\n"), ""] {
        reset(&env);
        let out = piped(&mut as_cmd(&env, &["--account", STACK, "deployer", "--", "true"]), input.as_bytes());
        assert_eq!(code(&out), Some(3), "{input:?}: {}", stderr(&out));
        assert!(said_after_the_prompts(&out, "ai-env: as deployer: nothing was pasted: cancelled, nothing was run") && !stderr(&out).contains("ai-env: cancelled"), "{input:?}: {}", stderr(&out));
        assert!(aws_calls(&env).is_empty());
    }
    assert!(as_rows(&env).is_empty());
}

/// The deployer's key is checked against the stack's account, which comes
/// from `state/infra.toml`, `bridge.toml [aws]` or `--account` (every source
/// present must agree); with none, nothing is asked (exit 1); a malformed
/// `--account` is a usage error (exit 2).
#[test]
fn as_deployer_needs_the_stacks_account_or_account_flag() {
    let env = Env::new(true);
    let (id, secret) = deployer_key();
    let run_as = |args: &[&str]| {
        reset(&env);
        let mut all = args.to_vec();
        all.extend(["deployer", "--", "true"]);
        pasting(&mut as_cmd(&env, &all), &id, &secret)
    };
    let out = run_as(&[]);
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        "ai-env: as deployer: the stack's account is unknown here (no state/infra.toml, no [aws] ARN in bridge.toml): pass --account with its 12 digits, or run `ai-env as root -- make infra-status WRITE=1` after the bootstrap\n",
        "refused before the paste"
    );
    for bad in ["12345678901", "account", "1234567890123"] {
        let out = run_as(&["--account", bad]);
        assert_eq!(code(&out), Some(2), "{bad}: {}", stderr(&out));
        assert_eq!(stderr(&out), format!("ai-env: --account {bad}: expected the 12 digits of an AWS account\n"));
    }
    assert!(aws_calls(&env).is_empty());
    // bridge.toml [aws] names it.
    let bridge = env.root().join("bridge");
    fs::create_dir_all(&bridge).unwrap();
    fs::write(bridge.join("bridge.toml"), format!("[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:{STACK}:microvm-image:ai-env-agent\"\n")).unwrap();
    let out = run_as(&[]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("ai-env: as ai-env-deployer (key ...9001, account …9012, verified): true"), "{}", stderr(&out));
    // Two sources that disagree: exit 1 naming both, before the paste.
    let out = run_as(&["--account", OTHER]);
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    assert!(said(&out, &format!("ai-env: the stack's account is ambiguous: bridge.toml [aws] says {STACK}, --account says {OTHER}: make infra-status WRITE=1 (or fix bridge.toml [aws]), then run it again")), "{}", stderr(&out));
    assert!(aws_calls(&env).is_empty());
    // The state names it (and the deployer's exact ARN).
    fs::remove_file(bridge.join("bridge.toml")).unwrap();
    write_state(&env, |_| {});
    let out = run_as(&[]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
}

/// `ai-env as ops` (§3.3): one Touch ID unseals `credentials/ops.env` (no sts
/// call), the command runs with that key and the marker `ops:<tail>`; every
/// `ai-env` nested in it — `as ops`, `as --check`, an operator command —
/// runs as that identity without another unseal or prompt, and only the
/// outer run writes an audit row.
#[test]
fn as_ops_unseals_ops_env_once_and_never_prompts_twice_when_nested() {
    let env = Env::new(true);
    let key = seal_ops(&env, keys::OPS_TAIL);
    let nested = r#"/bin/sh -c "$SEEN"; "$AI_ENV_BIN" as ops -- /bin/sh -c 'echo "inner=$AI_ENV_BRIDGE_AS"'; "$AI_ENV_BIN" as --check ops && echo checked; "$AI_ENV_BIN" creds aws-set --check --user ai-env-ops >/dev/null && echo listed"#;
    let mut cmd = as_cmd(&env, &["ops", "--", "/bin/sh", "-c", nested]);
    cmd.env("SEEN", SEEN).env("AI_ENV_BIN", bin()).env("AWS_PROFILE", "admin").env("AWS_SESSION_TOKEN", "token-of-the-test");
    let out = run(&mut cmd);
    assert_eq!(code(&out), Some(0), "stdout {} stderr {}", stdout(&out), stderr(&out));
    assert_eq!(stdout(&out), format!("{}inner=ops:9002\nchecked\nlisted\n", seen_as("ops", keys::OPS_TAIL)));
    assert_eq!(decrypts(&env), 1, "one Touch ID for the whole tree: {:?}", lines(&env.age_log()));
    let err = stderr(&out);
    let note = err.lines().find(|l| l.starts_with("ai-env: as ai-env-ops (key ...9002, credentials/ops.env): /bin/sh -c /bin/sh -c \"$SEEN\"; ")).unwrap_or_else(|| panic!("{err}"));
    assert!(note.ends_with('…'), "the command cut to 120 characters: {note}");
    assert_eq!(err.matches("ai-env: as ").count(), 1, "the nested runs say nothing: {err}");
    // No sts call for `as ops`; the nested operator command lists the keys with the key in its environment only.
    assert_eq!(aws_calls(&env), ["iam list-access-keys --user-name ai-env-ops --region eu-central-1 --output json"]);
    assert_eq!(aws_envs(&env), [format!("iam list-access-keys | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")]);
    let rows = as_rows(&env);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0]["detail"];
    assert_eq!((d["identity"].as_str(), d["key_id_last4"].as_str(), d["account"].as_str(), d["command"].as_str()), (Some("ops"), Some("9002"), None, Some("sh")), "{}", rows[0]);
    assert_unprinted(&out, &key.secret, "the ops secret");
    assert_nowhere(env.root(), &key.secret, "the ops secret");
}

/// `ai-env as ops` without its key (§3.6): no ops.env names `make ops-key`,
/// one that is not a container names the rotation (exit 5), a keystore
/// without the key is exit 4, a dismissed Touch ID the plain `cancelled`
/// (exit 3); nothing runs.
#[test]
fn as_ops_without_ops_env_names_make_ops_key() {
    let env = Env::new(true);
    let ran = env.root().join("ran");
    let touch = format!("touch {}", ran.display());
    let ops = env.credentials().join("ops.env");
    let try_ops = |extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = as_cmd(&env, &["ops", "--", "/bin/sh", "-c", touch.as_str()]);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(&mut cmd)
    };
    let out = try_ops(&[]);
    assert_eq!(code(&out), Some(5), "{}", stderr(&out));
    assert_eq!(stderr(&out), format!("ai-env: as ops: {} does not exist: seal the ops key with ai-env as deployer -- make ops-key\n", ops.display()));
    fs::create_dir_all(env.credentials()).unwrap();
    fs::write(&ops, "AWS_ACCESS_KEY_ID=plaintext\n").unwrap();
    let out = try_ops(&[]);
    assert_eq!(code(&out), Some(5), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        format!("ai-env: as ops: {} is not an ai-env container (plaintext?): move it away (and rotate the key it may hold: ai-env as deployer -- make ops-key ROTATE=1)\n", ops.display())
    );
    fs::remove_file(&ops).unwrap();
    seal_ops(&env, keys::OPS_TAIL);
    let out = try_ops(&[("FAKE_AGE_FAIL", "cancel")]);
    assert_eq!((code(&out), stderr(&out).lines().last().map(str::to_string)), (Some(3), Some("ai-env: cancelled".to_string())), "{}", stderr(&out));
    fs::remove_dir_all(env.root().join("keys").join("keys").join(KEY)).unwrap();
    let out = try_ops(&[]);
    assert_eq!(code(&out), Some(4), "{}", stderr(&out));
    assert!(stderr(&out).starts_with("ai-env: as ops: "), "{}", stderr(&out));
    assert!(!ran.exists() && as_rows(&env).is_empty(), "nothing ran");
    assert!(aws_calls(&env).is_empty());
}

/// `ai-env as root` and `as ambient` (§3.3) run the command on the aws CLI's
/// own chain, untouched but for the marker: root only when that chain is the
/// account root (of the stack's account), ambient only when it is not;
/// neither under another marker, and no credentials is exit 5.
#[test]
fn as_root_and_as_ambient_keep_the_ambient_chain_and_refuse_the_wrong_identity() {
    let env = Env::new(true);
    let ran = env.root().join("ran");
    let probe = format!(r#"echo "marker=$AI_ENV_BRIDGE_AS profile=${{AWS_PROFILE-unset}} config=${{AWS_CONFIG_FILE-unset}}"; touch {}"#, ran.display());
    let try_as = |who: &str, extra: &[(&str, &str)]| {
        reset(&env);
        let _ = fs::remove_file(&ran);
        let mut cmd = cli(&env, &["as", who, "--", "/bin/sh", "-c", probe.as_str()]);
        cmd.env("AWS_PROFILE", "shell-profile");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(&mut cmd)
    };
    let sts = "sts get-caller-identity --region eu-central-1 --endpoint-url https://sts.eu-central-1.amazonaws.com --output json";
    // The root: the chain as it is, the marker added.
    let out = try_as("root", &[("FAKE_AWS_CALLER", "root")]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "marker=root profile=shell-profile config=unset\n");
    assert!(stderr(&out).starts_with("ai-env: as the account ROOT of account …9012 (the bootstrap and break-glass only): /bin/sh -c echo"), "{}", stderr(&out));
    assert_eq!(aws_calls(&env), [sts]);
    assert_eq!(aws_envs(&env), ["sts get-caller-identity | AWS_PROFILE | AWS_PAGER="], "the environment untouched");
    let row = as_rows(&env).pop().unwrap();
    assert_eq!((row["detail"]["identity"].as_str(), row["detail"]["account"].as_str(), row["detail"]["key_id_last4"].as_str()), (Some("root"), Some(STACK), None), "{row}");
    // With a deployer in the stack: a warning; of another account than the stack's: refused.
    write_state(&env, |_| {});
    let out = try_as("root", &[("FAKE_AWS_CALLER", "root")]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(said(&out, "ai-env: warning: the stack already has ai-env-deployer: use ai-env as deployer; afterwards unset root's key and close this terminal (README \"Break-glass\")"), "{}", stderr(&out));
    let out = try_as("root", &[("FAKE_AWS_CALLER", "root@999999999999")]);
    assert_eq!(code(&out), Some(9), "{}", stderr(&out));
    assert_eq!(stderr(&out), format!("ai-env: as root: this is the account root of {OTHER}, but the stack (state/infra.toml) is in account {STACK}\n"));
    for (caller, want, line) in [
        ("rust", 9, format!("ai-env: as root: the aws CLI's credentials are arn:aws:iam::{STACK}:user/rust, not the account root: ai-env as root is only for the bootstrap deploy and break-glass")),
        ("none", 5, "ai-env: as root: no AWS credentials answer (Unable to locate credentials. You can configure credentials by running \"aws configure\".): ai-env as root needs the account root's access key in this shell (README \"Break-glass\")".to_string()),
    ] {
        let out = try_as("root", &[("FAKE_AWS_CALLER", caller)]);
        assert_eq!((code(&out), stderr(&out)), (Some(want), format!("{line}\n")), "{caller}");
    }
    // Ambient: any principal but the root, its account unchecked; the ARN's account masked in the note.
    let out = try_as("ambient", &[("FAKE_AWS_CALLER", "agent@999999999999")]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "marker=ambient profile=shell-profile config=unset\n");
    assert!(stderr(&out).starts_with("ai-env: as the ambient aws CLI identity arn:aws:iam::…9999:user/agent (declared; never the root): /bin/sh -c echo"), "{}", stderr(&out));
    let row = as_rows(&env).pop().unwrap();
    assert_eq!((row["detail"]["identity"].as_str(), row["detail"]["account"].as_str()), (Some("ambient"), Some(OTHER)), "{row}");
    for (caller, want, line) in [
        ("root", 9, "ai-env: as ambient: the aws CLI's credentials are the account ROOT: operator commands run as ai-env as ops --, deploys as ai-env as deployer --, the bootstrap alone as ai-env as root --".to_string()),
        ("none", 5, "ai-env: as ambient: no AWS credentials answer (Unable to locate credentials. You can configure credentials by running \"aws configure\".)".to_string()),
    ] {
        let out = try_as("ambient", &[("FAKE_AWS_CALLER", caller)]);
        assert_eq!((code(&out), stderr(&out)), (Some(want), format!("{line}\n")), "{caller}");
    }
    // Under a marker: as root never, as ambient only under its own (then at once, no call, no row).
    let rows = as_rows(&env).len();
    for (who, marker, word) in [("root", keys::marker_env("root"), "root"), ("root", keys::identity_env("ops", keys::OPS_TAIL), "ops"), ("ambient", keys::marker_env("root"), "root"), ("ambient", keys::identity_env("deployer", keys::DEPLOYER_TAIL), "deployer")] {
        let marker: Vec<(&str, &str)> = marker.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let out = try_as(who, &marker);
        assert_eq!(code(&out), Some(9), "{who} under {word}: {}", stderr(&out));
        assert_eq!(stderr(&out), format!("ai-env: as {who}: already inside ai-env as {word} (AI_ENV_BRIDGE_AS): start it from a terminal of its own\n"));
        assert!(aws_calls(&env).is_empty() && !ran.exists());
    }
    let ambient = keys::marker_env("ambient");
    let out = try_as("ambient", &[(ambient[0].0.as_str(), ambient[0].1.as_str()), ("FAKE_AWS_CALLER", "root")]);
    assert_eq!((code(&out), stdout(&out), stderr(&out)), (Some(0), "marker=ambient profile=shell-profile config=unset\n".to_string(), String::new()));
    assert!(aws_calls(&env).is_empty() && as_rows(&env).len() == rows, "a covered run: no call, no row");
}

/// `ai-env as --check <identity>` (the make guard, §3.3): exit 0 and silent
/// exactly when the marker covers the identity (§2.3), else exit 9 with the
/// refusal; a marker without its key or of another value is its own §2.5
/// refusal (for `as ops` too). No Touch ID, no AWS call.
#[test]
fn as_check_is_a_make_guard() {
    let env = Env::new(true);
    seal_ops(&env, keys::OPS_TAIL);
    let identities = ["deployer", "ops", "root", "ambient"];
    let who = |id: &str| match id {
        "deployer" => "ai-env-deployer",
        "ops" => "ai-env-ops",
        "root" => "the account root",
        _ => "the ambient aws CLI identity",
    };
    let none: Vars = vec![];
    let wrong_key = vec![("AI_ENV_BRIDGE_AS".to_string(), "ops:9002".to_string()), ("AWS_ACCESS_KEY_ID".to_string(), keys::key_id("9001")), ("AWS_SECRET_ACCESS_KEY".to_string(), keys::secret("Dm7/"))];
    let cases: [(Vars, &[&str]); 5] = [
        (none, &[]),
        (keys::identity_env("deployer", keys::DEPLOYER_TAIL), &["deployer", "ops"]),
        (keys::identity_env("ops", keys::OPS_TAIL), &["ops"]),
        (keys::marker_env("root"), &["deployer", "ops", "root"]),
        (keys::marker_env("ambient"), &["ops", "ambient"]),
    ];
    for (vars, covered) in &cases {
        for id in identities {
            let mut cmd = cli(&env, &["as", "--check", id]);
            cmd.envs(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            let out = run(&mut cmd);
            let marker = vars.first().map(|(_, v)| v.as_str());
            if covered.contains(&id) {
                assert_eq!((code(&out), stdout(&out), stderr(&out)), (Some(0), String::new(), String::new()), "{marker:?} covers {id}");
            } else {
                assert_eq!(code(&out), Some(9), "{marker:?} does not cover {id}");
                assert_eq!(stderr(&out), format!("ai-env: as --check {id}: this process does not run as {}: run it as ai-env as {id} -- <command>\n", who(id)));
            }
        }
    }
    // A key marker without its key, and a value ai-env never sets: refused, by --check and by a run alike. A run
    // reads its pastes from the null stdin (the debug builds' knob), never this test's terminal: were the marker
    // not refused first, it would end at once (an empty paste), never wait at a prompt.
    for (vars, text) in [
        (wrong_key, "ai-env: AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_ACCESS_KEY_ID holds another key (or none): something between ai-env as and this command changed it; run the command directly under ai-env as ops --\n"),
        (vec![("AI_ENV_BRIDGE_AS".to_string(), "admin".to_string())], "ai-env: AI_ENV_BRIDGE_AS=admin is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it\n"),
    ] {
        for args in [&["as", "--check", "ops"][..], &["as", "--check", "deployer"], &["as", "ops", "--", "true"], &["as", "deployer", "--", "true"]] {
            let mut cmd = if args.contains(&"--check") { cli(&env, args) } else { as_cmd(&env, &args[1..]) };
            cmd.envs(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            let out = run(&mut cmd);
            assert_eq!((code(&out), stderr(&out)), (Some(9), text.to_string()), "{args:?} under {:?}", vars.first());
        }
    }
    let out = run(&mut cli(&env, &["as", "--check", "ops", "--", "true"]));
    assert_eq!(code(&out), Some(2), "--check takes no command: {}", stderr(&out));
    assert_eq!(decrypts(&env), 0, "no Touch ID");
    assert!(aws_calls(&env).is_empty(), "no AWS call");
}

/// What the resolver refuses without an identity (§4.1), after its caller's label.
const NO_OPERATOR: &str = "no AWS operator identity: no ai-env as … runs this command and the ops key is not sealed (credentials/ops.env): seal it with ai-env as deployer -- make ops-key, or run the command under ai-env as deployer --";

/// The stack outputs `infra status --json-in` reads: the image and the connector (two live reads).
fn outputs_file(env: &Env) -> std::path::PathBuf {
    let json = serde_json::json!({
        "region": "eu-central-1",
        "accountId": STACK,
        "imageArn": format!("arn:aws:lambda:eu-central-1:{STACK}:microvm-image:ai-env-agent"),
        "imageState": "CREATED",
        "connectorArn": format!("arn:aws:lambda:eu-central-1:{STACK}:network-connector:ai-env-egress"),
        "proxyPrivateIp": "10.42.0.10",
        "deployerUserArn": format!("arn:aws:iam::{STACK}:user/ai-env-deployer"),
        "opsUserArn": format!("arn:aws:iam::{STACK}:user/ai-env-ops"),
        "proxyStatusDocument": "ai-env-proxy-status",
    });
    let p = env.root().join("outputs.json");
    fs::write(&p, json.to_string()).unwrap();
    p
}

/// No marker and no sealed ops key: every operator command refuses (exit 5,
/// its label first) or, for `infra status`, records its live reads as not
/// made — and none of them calls AWS, though the aws CLI's own chain would
/// answer (§4.1: never a fallback). A marker the resolver refuses is exit 9.
#[test]
fn operator_commands_refuse_without_an_identity_and_never_use_the_ambient_chain() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let check = |args: &[&str], extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = cli(&env, args);
        cmd.current_dir(env.root()).env("AWS_PROFILE", "admin").env("FAKE_AWS_CALLER", "rust");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = run(&mut cmd);
        assert!(aws_calls(&env).is_empty(), "{args:?}: never the aws CLI's own chain: {:?}", aws_calls(&env));
        assert_eq!(decrypts(&env), 0);
        out
    };
    let out = check(&["creds", "aws-set", "--check"], &[]);
    assert_eq!(code(&out), Some(5), "{}{}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l == format!("[NO ] creds aws-set --check: {NO_OPERATOR}")), "{}", stdout(&out));
    let out = check(&["infra", "base-image"], &[]);
    assert_eq!((code(&out), stderr(&out)), (Some(5), format!("ai-env: infra base-image: {NO_OPERATOR}\n")));
    let out = check(&["gates", "--only", "G7", "--json"], &[]);
    assert_eq!(code(&out), Some(5), "{}{}", stdout(&out), stderr(&out));
    let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!((doc["gates"][0]["status"].as_str(), doc["gates"][0]["observed"].as_str()), (Some("skipped"), Some(format!("gates: {NO_OPERATOR}").as_str())));
    let out = check(&["infra", "status", "--json-in", outputs_file(&env).to_str().unwrap()], &[]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(said(&out, "ai-env: no AWS operator identity: the live reads are skipped (ai-env as ops -- make infra-status)"), "{}", stderr(&out));
    assert!(stdout(&out).contains(&format!("image_state_source = \"pulumi outputs (live read failed: {NO_OPERATOR})\"")), "{}", stdout(&out));
    // A marker the resolver refuses: exit 9, still no call.
    let out = check(&["infra", "base-image"], &[("AI_ENV_BRIDGE_AS", "ops:9002")]);
    assert_eq!(code(&out), Some(9), "{}", stderr(&out));
    assert!(stderr(&out).starts_with("ai-env: infra base-image: AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_ACCESS_KEY_ID holds another key (or none)"), "{}", stderr(&out));
}

/// No marker, `credentials/ops.env` sealed: an operator command unseals it
/// once (one Touch ID, its note once) for all its calls, and the key reaches
/// each `aws` child in its environment only — the selectors of the shell
/// (a profile, endpoint overrides) gone, the profile files pinned, no marker
/// — never in an argv, a log or a file.
#[test]
fn a_sealed_ops_key_is_unsealed_once_per_process_and_reaches_aws_only_in_env() {
    let env = Env::new(true);
    let key = seal_ops(&env, keys::OPS_TAIL);
    let mut cmd = cli(&env, &["infra", "status", "--json-in", outputs_file(&env).to_str().unwrap()]);
    cmd.env("AWS_PROFILE", "admin").env("AWS_ENDPOINT_URL_LAMBDA", "http://127.0.0.1:9").env("AWS_CONTAINER_AUTHORIZATION_TOKEN", "token-of-the-test");
    let out = run(&mut cmd);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert_eq!(decrypts(&env), 1, "{:?}", lines(&env.age_log()));
    assert_eq!(stderr(&out).matches("ai-env: operator ai-env-ops (key ...9002, credentials/ops.env)").count(), 1, "{}", stderr(&out));
    let envs = aws_envs(&env);
    assert_eq!(
        envs,
        [
            format!("lambda-microvms get-microvm-image | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}"),
            format!("lambda-core get-network-connector | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")
        ],
        "the sealed key in the environment, nothing else that selects credentials"
    );
    for call in aws_calls(&env) {
        assert!(!holds(call.as_bytes(), &key.id) && !holds(call.as_bytes(), &key.secret), "never in argv: {call}");
    }
    assert_unprinted(&out, &key.secret, "the ops secret");
    assert_unprinted(&out, &key.id, "the ops key id");
    assert_nowhere(env.root(), &key.secret, "the ops secret");
}

/// D21: `infra status --write` with the ops key sealed and its Touch ID
/// dismissed is the operator's cancel, as in every operator command: exit 3
/// (`ai-env: cancelled`), nothing written, no AWS call. Any other failure of
/// the identity still records the live reads as failed and writes, its note
/// naming that failure rather than a missing identity (here a marker without
/// its key).
#[test]
fn infra_status_cancels_on_a_dismissed_touch_id_and_names_any_other_failure() {
    let env = Env::new(true);
    seal_ops(&env, keys::OPS_TAIL);
    let outputs = outputs_file(&env);
    let state = env.root().join("bridge").join("state").join("infra.toml");
    let bridge_toml = env.root().join("bridge").join("bridge.toml");
    let status = |extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = cli(&env, &["infra", "status", "--json-in", outputs.to_str().unwrap(), "--write"]);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(&mut cmd)
    };
    let out = status(&[("FAKE_AGE_FAIL", "cancel")]);
    assert_eq!((code(&out), stderr(&out).lines().last().map(str::to_string)), (Some(3), Some("ai-env: cancelled".to_string())), "{}", stderr(&out));
    assert_eq!(decrypts(&env), 1, "the one dialog, dismissed");
    assert!(aws_calls(&env).is_empty() && stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(!state.exists() && !bridge_toml.exists(), "nothing written");
    // A marker the resolver refuses: recorded, written, the note naming the refusal (no Touch ID).
    let refusal = "AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_ACCESS_KEY_ID holds another key (or none): something between ai-env as and this command changed it; run the command directly under ai-env as ops --";
    let out = status(&[("AI_ENV_BRIDGE_AS", "ops:9002")]);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(said(&out, &format!("ai-env: the live reads are skipped: {refusal}")) && !stderr(&out).contains("no AWS operator identity"), "{}", stderr(&out));
    assert!(stdout(&out).contains(&format!("image_state_source = \"pulumi outputs (live read failed: {refusal})\"")), "{}", stdout(&out));
    assert!(state.exists() && bridge_toml.exists() && aws_calls(&env).is_empty() && decrypts(&env) == 0);
}

/// `tests/fakes/logged.sh` under every tool doctor would otherwise find on
/// this Mac (it also looks in /opt/homebrew/bin): each call logged, exit 1.
fn refuse_tools(env: &Env) {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = env.root().join("bin");
    for name in ["claude", "rustup", "cargo-lambda", "zig", "pulumi", "docker", "curl"] {
        let dest = bin.join(name);
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/logged.sh"), &dest).unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// A tool doctor probes, in place of [`refuse_tools`]' (exit 1 too): one line
/// per call in `FAKE_PROBE_LOG`, `<tool> <argv> | <credential names it
/// inherited>` (` -` for none), never a value.
const TOOL_PROBE: &str = r#"#!/bin/sh
seen=
for n in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AI_ENV_BRIDGE_AS CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY; do
  eval "s=\${$n+set}"
  [ -n "$s" ] && seen="$seen $n"
done
printf '%s %s |%s\n' "$(basename "$0")" "$*" "${seen:- -}" >> "$FAKE_PROBE_LOG"
exit 1
"#;

/// [`TOOL_PROBE`] as the tools doctor probes beside its AWS rows: the
/// toolchain, the cross tools and claude; and git, logged the same way (S11
/// B3-R1: doctor's image scan finds the checkout without running git, so a git
/// that ever runs must inherit no credential either). Each new file runs once
/// here: macOS assesses a new executable at its first exec, which on a busy Mac
/// can outlast doctor's 5 s probes.
fn log_probed_tools(env: &Env) {
    use std::os::unix::fs::PermissionsExt as _;
    for name in ["claude", "rustup", "cargo-lambda", "zig", "git"] {
        let dest = env.root().join("bin").join(name);
        fs::write(&dest, TOOL_PROBE).unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
        let warm = run(Command::new(&dest).env_clear().env("PATH", "/usr/bin:/bin").env("FAKE_PROBE_LOG", "/dev/null"));
        assert_eq!(code(&warm), Some(1), "{name}: {}", stderr(&warm));
    }
}

/// `ai-env doctor` (§8.2) never unseals anything: without a marker its
/// operator row says how to give it one, and one plain sts call only warns
/// that the shell's own credentials are the root's; under `ai-env as root`
/// the root's identity is a warning naming `ai-env as ops`, its access key
/// another; a declared identity that is refused is `[NO ]` (a refused key:
/// exit 5, re-sealing `ops.env` the remedy for the ops runner's). Under
/// `ai-env as ops` its key reaches the AWS rows only, never a probed tool
/// (D16), and a deployer recorded in the state has its keys counted as the
/// operator (D27): one is the norm, none or two need a hand.
#[test]
fn doctor_never_unseals_and_names_ai_env_as_ops_for_a_root_caller() {
    let env = Env::new(true);
    seal_ops(&env, keys::OPS_TAIL);
    refuse_tools(&env);
    log_probed_tools(&env);
    // S11 (B3-R1): a recorded workspace root, so doctor's pre-push row runs git there (`review::hook_state`): the
    // logged stand-in, which must inherit no credential under `ai-env as ops` either.
    let ws_root = env.root().join("work").display().to_string();
    let rows = env.root().join("bridge").join("state").join("workspaces");
    fs::create_dir_all(env.root().join("work")).unwrap();
    fs::create_dir_all(&rows).unwrap();
    fs::write(rows.join("work.toml"), format!("v = 1\n\n[ws.\"{ws_root}\"]\nroot = \"{ws_root}\"\n")).unwrap();
    let probe_log = env.root().join("probes.log");
    let doctor = |extra: &[(&str, &str)]| {
        reset(&env);
        let _ = fs::remove_file(&probe_log);
        let mut cmd = cli(&env, &["doctor"]);
        cmd.current_dir(env.root()).env("FAKE_PROBE_LOG", &probe_log);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = run(&mut cmd);
        assert_eq!(decrypts(&env), 0, "doctor never unseals: {:?}", lines(&env.age_log()));
        out
    };
    // The text report indents its rows.
    let rows = |out: &Output| stdout(out).lines().map(|l| l.trim_start().to_string()).collect::<Vec<_>>();
    let has = |out: &Output, row: &str| rows(out).iter().any(|l| l == row);
    let ops = env.credentials().join("ops.env");
    let out = doctor(&[("FAKE_AWS_CALLER", "root")]);
    assert!(has(&out, "[-  ] operator identity: none declared (doctor never unseals credentials/ops.env)  <- ai-env as ops -- ai-env doctor (one Touch ID)"), "{}", stdout(&out));
    assert!(
        has(&out, "[!! ] the ambient aws CLI credentials are the account ROOT: operator commands never use them, but a plain aws call here runs as the root; outside the bootstrap and break-glass, keep root's key out of a terminal used for ai-env (README \"Identities\")  <- ai-env as ops -- … for operator commands, ai-env as deployer -- … to deploy"),
        "{}",
        stdout(&out)
    );
    assert!(has(&out, &format!("[ok ] ops key sealed ({}): ai-env-ops ...9002, sealed 2026-09-19 (recorded at sealing, not authenticated)", ops.display())), "{}", stdout(&out));
    assert!(has(&out, "[-  ] the account root's access keys: not checked (no operator identity: ai-env as ops -- ai-env doctor)"), "{}", stdout(&out));
    assert_eq!(aws_calls(&env), ["sts get-caller-identity --region eu-central-1 --output json"], "one plain call, only to warn");
    // Under ai-env as root, the root answering: its identity and its access key are warnings.
    let root = keys::marker_env("root");
    let marker = (root[0].0.as_str(), root[0].1.as_str());
    let out = doctor(&[marker, ("FAKE_AWS_CALLER", "root"), ("FAKE_AWS_ROOT_KEYS", "1")]);
    assert!(has(&out, "[!! ] operator identity is the account ROOT (ai-env as root: the bootstrap and break-glass only)  <- ai-env as ops -- ai-env doctor"), "{}", stdout(&out));
    assert!(
        has(&out, "[!! ] the account root has an access key (AccountAccessKeysPresent=1, active or deactivated)  <- ai-env needs it only for the bootstrap and break-glass: delete it when nothing else uses it (IAM console, Security credentials), and never load it into a terminal used for ai-env day to day"),
        "{}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("ambient aws CLI"), "a declared identity: no ambient row: {}", stdout(&out));
    // The root marker on another principal: refused, never used.
    let out = doctor(&[marker, ("FAKE_AWS_CALLER", "rust")]);
    assert_eq!(code(&out), Some(1), "{}", stdout(&out));
    assert!(
        has(&out, &format!("[NO ] operator identity: AI_ENV_BRIDGE_AS=root, but the aws CLI's credentials are arn:aws:iam::{STACK}:user/rust, not the account root: unset it, or run the command under ai-env as root -- again")),
        "{}",
        stdout(&out)
    );
    assert_eq!(aws_calls(&env).len(), 1, "no AWS row runs on a refused identity: {:?}", aws_calls(&env));
    // ai-env as ops: verified, the rows run as it (the shell's own selectors beside its key: none reaches a
    // call, every one pinned); a refused key is exit 5.
    let ops_env = keys::identity_env("ops", keys::OPS_TAIL);
    let mut ops_vars: Vec<(&str, &str)> = ops_env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    ops_vars.extend([("AWS_PROFILE", "admin"), ("AWS_SESSION_TOKEN", "token-of-the-test")]);
    let out = doctor(&ops_vars);
    assert!(has(&out, &format!("[ok ] operator identity arn:aws:iam::{STACK}:user/ai-env-ops (ai-env as ops, key ...9002)")), "{}", stdout(&out));
    assert!(has(&out, "[ok ] the account root has no access key"), "{}", stdout(&out));
    let envs = aws_envs(&env);
    let ops: Vec<&str> = envs.iter().map(|l| l.split(" | ").next().unwrap_or_default()).collect();
    assert_eq!(ops, ["sts get-caller-identity", "iam get-account-summary", "lambda-microvms list-managed-microvm-image-versions"], "{envs:?}");
    assert!(envs.iter().all(|l| l.ends_with(&format!(" | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}"))), "as the operator: {envs:?}");
    // D16: the probed tools (the toolchain, zig, claude --version and auth status) get no key, no marker, no session token.
    let probes = lines(&probe_log);
    for tool in ["rustup run", "zig version", "claude --version", "claude auth status --json"] {
        assert!(probes.iter().any(|l| l.starts_with(tool)), "{tool} was probed: {probes:?}");
    }
    // S11 (B3-R1): and the pre-push row's git on the recorded root (GitRun's `-c` overrides first).
    assert!(probes.iter().any(|l| l.starts_with("git ") && l.contains(" rev-parse --git-dir |")), "git ran on the recorded root: {probes:?}");
    assert!(probes.iter().all(|l| l.ends_with(" | -")), "a probed tool (or git) saw a credential: {probes:?}");
    // The ops runner's key refused: running it again would unseal the same key, so the row says to re-seal it (D23).
    let mut refused = ops_vars.clone();
    refused.push(("FAKE_AWS_KEY_USERS", "9001:ai-env-deployer"));
    let out = doctor(&refused);
    assert_eq!(code(&out), Some(5), "{}", stdout(&out));
    assert!(
        has(&out, "[NO ] operator identity: AWS refused the operator key ...9002 (InvalidClientTokenId): re-seal credentials/ops.env, which ai-env as ops unseals, with ai-env as deployer -- make ops-key ROTATE=1"),
        "{}",
        stdout(&out)
    );
    // D27: a deployer recorded: `iam list-access-keys` of ai-env-deployer as the operator, its count judged.
    write_state(&env, |_| {});
    let listed = "iam list-access-keys --user-name ai-env-deployer --region eu-central-1 --output json";
    for (keys_n, row) in [
        ("1", "[ok ] deployer user/ai-env-deployer: 1 access key (in Strongbox only)"),
        ("0", "[NO ] deployer user/ai-env-deployer has no access key  <- ai-env as root -- make operator-keys"),
        ("2", "[!! ] deployer user/ai-env-deployer has 2 access keys (one left from a rotation?)  <- delete the one not in Strongbox: ai-env as deployer -- aws iam list-access-keys --user-name ai-env-deployer --region eu-central-1"),
    ] {
        let mut vars = ops_vars.clone();
        vars.push(("FAKE_AWS_KEYS", keys_n));
        let out = doctor(&vars);
        assert!(has(&out, row), "{keys_n} key(s): {}", stdout(&out));
        assert_eq!(aws_calls(&env).iter().filter(|c| *c == listed).count(), 1, "{:?}", aws_calls(&env));
        assert!(aws_envs(&env).contains(&format!("iam list-access-keys | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")), "as the operator: {:?}", aws_envs(&env));
    }
    let mut vars = ops_vars.clone();
    vars.push(("FAKE_AWS_FAIL", "nouser"));
    let out = doctor(&vars);
    assert!(has(&out, "[NO ] deployer user/ai-env-deployer does not exist, though state/infra.toml names it  <- make infra-status WRITE=1"), "{}", stdout(&out));
    // Without an identity: the state's deployer named, its keys never listed.
    let out = doctor(&[("FAKE_AWS_CALLER", "rust")]);
    assert!(has(&out, "[ok ] deployer user/ai-env-deployer (stack output; its key is in Strongbox only)"), "{}", stdout(&out));
    assert!(!aws_calls(&env).iter().any(|c| c == listed), "{:?}", aws_calls(&env));
}

/// G7 (§8.1) simulates the stack's users from `state/infra.toml`, never the
/// caller and with no sts call of its own: the deployer's four pairs on
/// their own resources must be allowed and ops' twenty deploy actions
/// denied, in either answer shape; anything else is `?`, naming the pair.
/// Every call runs as the operator, the shell's own selectors gone: under
/// `ai-env as ops`, and with the sealed ops key (one Touch ID, the key in
/// the environment only).
#[test]
fn gates_g7_simulates_the_deployer_per_resource_and_proves_ops_cannot_deploy() {
    let env = Env::new(true);
    write_state(&env, |s| s.budget_name = Some("ai-env-monthly".into()));
    seal_ops(&env, keys::OPS_TAIL);
    let allow = "ai-env-deployer|iam:CreateUser|user/ai-env-runtime ai-env-deployer|iam:CreateAccessKey|user/ai-env-runtime ai-env-deployer|iam:CreateAccessKey|user/ai-env-ops ai-env-deployer|budgets:ModifyBudget|budget/ai-env-monthly";
    let ops_env = keys::identity_env("ops", keys::OPS_TAIL);
    let g7 = |extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = cli(&env, &["gates", "--only", "G7", "--json", "--out", env.root().join("gates.md").to_str().unwrap()]);
        // The shell's own selectors: an operator call that kept one would show it in the environment log.
        cmd.current_dir(env.root()).envs(ops_env.iter().map(|(k, v)| (k.as_str(), v.as_str()))).env("AWS_PROFILE", "admin").env("AWS_SESSION_TOKEN", "token-of-the-test");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = run(&mut cmd);
        assert_eq!(code(&out), Some(0), "G7 never blocks: {}{}", stdout(&out), stderr(&out));
        let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        (doc["gates"][0]["status"].as_str().unwrap().to_string(), doc["gates"][0]["observed"].as_str().unwrap().to_string())
    };
    let pass = "deployer user/ai-env-deployer: iam:CreateUser@user/ai-env-runtime=allowed, iam:CreateAccessKey@user/ai-env-runtime=allowed, iam:CreateAccessKey@user/ai-env-ops=allowed, budgets:ModifyBudget@budget/ai-env-monthly=allowed; ops user/ai-env-ops: 20/20 deploy actions denied".to_string();
    for shape in ["flat", "nested"] {
        assert_eq!(g7(&[("FAKE_AWS_SIM_ALLOW", allow), ("FAKE_AWS_SIM_SHAPE", shape)]), ("pass".to_string(), pass.clone()), "{shape}");
    }
    // Eight calls, the stack's two users, per-resource ARNs; no sts call (the verdict is not the caller's).
    let calls = aws_calls(&env);
    assert_eq!(calls.len(), 8, "{calls:#?}");
    assert!(calls.iter().all(|c| c.starts_with("iam simulate-principal-policy --region eu-central-1 --policy-source-arn arn:aws:iam::123456789012:user/ai-env-") && c.ends_with(" --output json")), "{calls:#?}");
    assert_eq!(calls[0], format!("iam simulate-principal-policy --region eu-central-1 --policy-source-arn arn:aws:iam::{STACK}:user/ai-env-deployer --action-names iam:CreateUser iam:CreateAccessKey --resource-arns arn:aws:iam::{STACK}:user/ai-env-runtime --output json"));
    assert_eq!(calls[6], format!("iam simulate-principal-policy --region eu-central-1 --policy-source-arn arn:aws:iam::{STACK}:user/ai-env-ops --action-names ssm:PutParameter --resource-arns arn:aws:ssm:eu-central-1:{STACK}:parameter/ai-env/proxy/extras arn:aws:ssm:eu-central-1:{STACK}:parameter/ai-env/proxy/allow arn:aws:ssm:eu-central-1:{STACK}:parameter/ai-env/proxy/squid.conf --output json"));
    assert_eq!(calls[7], format!("iam simulate-principal-policy --region eu-central-1 --policy-source-arn arn:aws:iam::{STACK}:user/ai-env-ops --action-names ssm:SendCommand --resource-arns arn:aws:ssm:eu-central-1::document/AWS-RunShellScript --output json"));
    assert_eq!(aws_envs(&env), vec![format!("iam simulate-principal-policy | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}"); 8], "as the runner");
    // No marker: the sealed ops key, unsealed once, in each call's environment only (no marker, no selector).
    let (status, observed) = g7(&[("AI_ENV_BRIDGE_AS", ""), ("AWS_ACCESS_KEY_ID", ""), ("AWS_SECRET_ACCESS_KEY", ""), ("FAKE_AWS_SIM_ALLOW", allow)]);
    assert_eq!((status.as_str(), observed.as_str()), ("pass", pass.as_str()));
    assert_eq!(decrypts(&env), 1, "{:?}", lines(&env.age_log()));
    assert_eq!(aws_envs(&env), vec![format!("iam simulate-principal-policy | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}"); 8], "as the sealed key");
    // Ops may widen egress: ?, the pair named; the deployer lacks a right: ?, its decision shown.
    let (status, observed) = g7(&[("FAKE_AWS_SIM_ALLOW", &format!("{allow} ai-env-ops|ssm:PutParameter|/proxy/extras"))]);
    assert_eq!(status, "manual");
    assert!(observed.ends_with("ops user/ai-env-ops: 19/20 deploy actions denied; allowed: ssm:PutParameter@parameter/ai-env/proxy/extras"), "{observed}");
    let (status, observed) = g7(&[("FAKE_AWS_SIM_ALLOW", allow.replace("budgets:ModifyBudget", "budgets:ViewBudget").as_str())]);
    assert!(status == "manual" && observed.contains("budgets:ModifyBudget@budget/ai-env-monthly=implicitDeny"), "{status}: {observed}");
    // Under ai-env as root (the root answering), the same verdict: the resolver's one identity check is the only sts call.
    let root = keys::marker_env("root");
    let (status, observed) = g7(&[(root[0].0.as_str(), root[0].1.as_str()), ("AWS_ACCESS_KEY_ID", ""), ("AWS_SECRET_ACCESS_KEY", ""), ("FAKE_AWS_CALLER", "root"), ("FAKE_AWS_SIM_ALLOW", allow)]);
    assert_eq!((status.as_str(), observed.as_str()), ("pass", pass.as_str()));
    assert_eq!(aws_calls(&env).iter().filter(|c| c.starts_with("sts ")).count(), 1, "{:?}", aws_calls(&env));
    // The aws CLI's own chain, declared: its selectors kept, only the region and the pager pinned; nothing unsealed.
    let ambient = "| AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_PROFILE AWS_SESSION_TOKEN | AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true AWS_REGION=eu-central-1 AWS_DEFAULT_REGION=eu-central-1 AWS_PAGER=";
    assert!(aws_envs(&env).len() == 9 && aws_envs(&env).iter().all(|l| l.ends_with(ambient)), "{:?}", aws_envs(&env));
    assert_eq!(decrypts(&env), 0);
    // A state before the bootstrap: skipped, naming what it lacks; no call. Even over the ✓ an earlier run wrote
    // into the file: a skipped G7 simulated nothing and never shows an old verdict (D12).
    write_state(&env, |s| {
        s.deployer_user_arn = None;
        s.ops_user_arn = None;
    });
    let recorded = format!("| Gate | Command | Expected | Observed | Status | Date |\n|---|---|---|---|---|---|\n| G7 IAM of the operator identities | `c` | e | {pass} | ✓ | 2026-10-13 |\n");
    fs::write(env.root().join("gates.md"), recorded).unwrap();
    let (status, observed) = g7(&[]);
    assert_eq!((status.as_str(), observed.as_str()), ("skipped", "state/infra.toml lacks deployer_user_arn, ops_user_arn  <- make infra-status WRITE=1 after the bootstrap"));
    assert!(aws_calls(&env).is_empty());
}

/// `creds aws-set --check` counts the named user's keys as the operator
/// identity (the key in the child's environment only, the shell's own
/// selectors gone), never the shell's own chain: under `ai-env as ops`, or
/// with the sealed ops key (one Touch ID); without an identity its row is the
/// resolver's refusal (exit 5).
#[test]
fn creds_check_lists_the_named_users_keys_as_the_operator() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let check = |user: &str, extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = env.creds(&["aws-set", "--check", "--user", user]);
        cmd.env("FAKE_AWS_ENV_LOG", env.root().join("aws-env.log")).env("AWS_PROFILE", "admin");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(&mut cmd)
    };
    for user in ["ai-env-runtime", "ai-env-ops"] {
        let out = check(user, &[]);
        assert_eq!(code(&out), Some(0), "{user}: {}{}", stdout(&out), stderr(&out));
        assert!(stdout(&out).lines().any(|l| l == format!("[ok ] IAM user {user} has 0 access key(s), below the maximum of 2")), "{}", stdout(&out));
        assert_eq!(aws_calls(&env), [format!("iam list-access-keys --user-name {user} --region eu-central-1 --output json")]);
        assert_eq!(aws_envs(&env), [format!("iam list-access-keys | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")], "as the runner");
    }
    // Without an identity: refused, no call.
    let none = [("AI_ENV_BRIDGE_AS", ""), ("AWS_ACCESS_KEY_ID", ""), ("AWS_SECRET_ACCESS_KEY", "")];
    let out = check("ai-env-runtime", &none);
    assert_eq!(code(&out), Some(5), "{}{}", stdout(&out), stderr(&out));
    assert!(stdout(&out).lines().any(|l| l == format!("[NO ] creds aws-set --check: {NO_OPERATOR}")), "{}", stdout(&out));
    assert!(aws_calls(&env).is_empty());
    // No marker, the ops key sealed: unsealed once, the key in the call's environment only (no marker, no selector).
    let key = seal_ops(&env, keys::OPS_TAIL);
    let out = check("ai-env-runtime", &none);
    assert_eq!(code(&out), Some(0), "{}{}", stdout(&out), stderr(&out));
    assert!(said(&out, "ai-env: operator ai-env-ops (key ...9002, credentials/ops.env)"), "{}", stderr(&out));
    assert_eq!(decrypts(&env), 1, "{:?}", lines(&env.age_log()));
    assert_eq!(aws_envs(&env), [format!("iam list-access-keys | AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}")], "as the sealed key");
    for call in aws_calls(&env) {
        assert!(!holds(call.as_bytes(), &key.id) && !holds(call.as_bytes(), &key.secret), "never in argv: {call}");
    }
    assert_unprinted(&out, &key.secret, "the ops secret");
}

// ---- W2a review fixes: the resolver's refusals, G2, covered runs, the runner's failures, egress check and the probes

/// The one identity check of an operator under the markers `root` and
/// `ambient` (§4.1, D20), as the fake logs it.
const STS_CALL: &str = "sts get-caller-identity --region eu-central-1 --endpoint-url https://sts.eu-central-1.amazonaws.com --output json";

/// D20, §4.2: a `root` marker whose aws CLI chain is not the account root,
/// or an `ambient` one whose is, is refused by every operator command that
/// relies on the resolver alone, its one identity check the only AWS call:
/// `infra base-image` and `creds aws-set --check` exit 9, `infra status`
/// records its live reads as failed with that text, `gates` shows G7
/// skipped with it and keeps its class (exit 9).
#[test]
fn a_root_or_ambient_marker_on_another_principal_is_refused_by_every_operator_command() {
    let env = Env::new(true);
    env.keystore(KEY, true);
    let outputs = outputs_file(&env);
    let gates_md = env.root().join("gates.md");
    for (word, caller, text) in [
        ("root", "rust", format!("AI_ENV_BRIDGE_AS=root, but the aws CLI's credentials are arn:aws:iam::{STACK}:user/rust, not the account root: unset it, or run the command under ai-env as root -- again")),
        ("ambient", "root", "the aws CLI's credentials are the account ROOT under ai-env as ambient: operator commands run as ai-env as ops --, the bootstrap alone as ai-env as root --".to_string()),
    ] {
        let refused = |args: &[&str]| {
            reset(&env);
            let mut cmd = cli(&env, args);
            cmd.current_dir(env.root()).envs(keys::marker_env(word)).env("FAKE_AWS_CALLER", caller);
            let out = run(&mut cmd);
            assert_eq!(aws_calls(&env), [STS_CALL], "{args:?} under {word}: the identity check, then nothing");
            assert_eq!(decrypts(&env), 0);
            out
        };
        let out = refused(&["infra", "base-image"]);
        assert_eq!((code(&out), stderr(&out)), (Some(9), format!("ai-env: infra base-image: {text}\n")), "{word}");
        let out = refused(&["creds", "aws-set", "--check"]);
        assert_eq!(code(&out), Some(9), "{word}: {}{}", stdout(&out), stderr(&out));
        assert!(stdout(&out).lines().any(|l| l == format!("[NO ] creds aws-set --check: {text}")), "{word}: {}", stdout(&out));
        let out = refused(&["infra", "status", "--json-in", outputs.to_str().unwrap()]);
        assert_eq!(code(&out), Some(0), "{word}: {}", stderr(&out));
        assert!(stdout(&out).contains(&format!("image_state_source = \"pulumi outputs (live read failed: {text})\"")), "{word}: {}", stdout(&out));
        let out = refused(&["gates", "--only", "G7", "--json", "--out", gates_md.to_str().unwrap()]);
        assert_eq!(code(&out), Some(9), "{word}: {}{}", stdout(&out), stderr(&out));
        let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
        let g7 = (doc["gates"][0]["status"].as_str(), doc["gates"][0]["observed"].as_str(), doc["exit"].as_i64());
        assert_eq!(g7, (Some("skipped"), Some(format!("gates: {text}").as_str()), Some(9)), "{word}");
        assert!(said(&out, &format!("ai-env: gates: {text}")), "{word}: {}", stderr(&out));
    }
}

/// G2 (§8.1) lists the managed images as the operator identity too, the
/// shell's own selectors gone from both calls (its plain `aws --version`
/// probe aside); without an identity G2 is ✗ naming why, the run exits 5,
/// and only the probe ran.
#[test]
fn gates_g2_lists_the_managed_images_as_the_operator() {
    let env = Env::new(true);
    let answers = env.root().join("answers");
    fs::create_dir_all(&answers).unwrap();
    fs::write(answers.join("lambda-microvms.list-managed-microvm-images.json"), r#"{"items": [{"name": "al2023-1"}]}"#).unwrap();
    // The fresh copy of the fake runs once first: macOS assesses a new executable at its first exec, which on a
    // busy Mac can outlast G2's own 5 s `aws --version` probe (then "aws cli not found").
    let warm = run(Command::new(env.root().join("bin").join("aws")).arg("--version").env_clear().env("PATH", "/usr/bin:/bin"));
    assert_eq!(code(&warm), Some(0), "{}", stderr(&warm));
    let g2 = |extra: &[(&str, &str)]| {
        reset(&env);
        let mut cmd = cli(&env, &["gates", "--only", "G2", "--json", "--out", env.root().join("gates.md").to_str().unwrap()]);
        cmd.current_dir(env.root()).env("FAKE_AWS_ANSWERS", &answers).env("AWS_PROFILE", "admin").env("AWS_SESSION_TOKEN", "token-of-the-test");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = run(&mut cmd);
        let doc: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap_or_else(|e| panic!("{e}: {}{}", stdout(&out), stderr(&out)));
        let row = (doc["gates"][0]["status"].as_str().unwrap_or_default().to_string(), doc["gates"][0]["observed"].as_str().unwrap_or_default().to_string());
        (out, row)
    };
    let ops = keys::identity_env("ops", keys::OPS_TAIL);
    let ops: Vec<(&str, &str)> = ops.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (out, (_, observed)) = g2(&ops);
    // (The fake answers only eu-central-1: its eu-west-3 call fails at the fake's region guard, not with a 403.)
    assert!(observed.starts_with("eu-central-1: al2023-1 listed; eu-west-3: "), "{observed}: {}", stderr(&out));
    assert_eq!(aws_calls(&env), ["--version", "lambda-microvms list-managed-microvm-images --region eu-central-1 --output json", "lambda-microvms list-managed-microvm-images --region eu-west-3 --output json"]);
    assert_eq!(aws_envs(&env), vec![format!("lambda-microvms list-managed-microvm-images | AI_ENV_BRIDGE_AS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY | {PINS}"); 2], "as the operator");
    let (out, row) = g2(&[]);
    assert_eq!((code(&out), row), (Some(5), ("fail".to_string(), format!("gates: {NO_OPERATOR}"))), "{}", stderr(&out));
    assert_eq!(aws_calls(&env), ["--version"], "only the plain probe");
    assert!(aws_envs(&env).is_empty());
}

/// A covering marker execs the command at once (§3.3, §3.6), never asking,
/// unsealing, auditing or calling AWS: under another identity it says which
/// one covers it. A key marker's environment is applied again (a selector
/// exported in between is gone, the pins are back); `root` and `ambient`
/// run the command as it is, on the aws CLI's own chain.
#[test]
fn a_covered_run_says_what_covers_it_and_runs_as_that_identity() {
    let env = Env::new(true);
    seal_ops(&env, keys::OPS_TAIL);
    let covered = |who: &str, marker: Vars| {
        reset(&env);
        let mut cmd = as_cmd(&env, &[who, "--", "/bin/sh", "-c", SEEN]);
        cmd.envs(marker).env("AWS_PROFILE", "exported-in-between").env("AWS_SESSION_TOKEN", "token-of-the-test");
        let out = run(&mut cmd);
        assert_eq!(code(&out), Some(0), "{who}: {}", stderr(&out));
        assert!(decrypts(&env) == 0 && as_rows(&env).is_empty() && aws_calls(&env).is_empty(), "{who}: a covered run asks nothing and calls nothing");
        out
    };
    let says = |out: &Output, user: &str, by: &str| {
        let err = stderr(out);
        let start = format!("ai-env: as {user}: already {by}, which covers it: running /bin/sh -c for n in AWS_PROFILE ");
        assert!(err.lines().count() == 1 && err.starts_with(&start) && err.ends_with("… as it is\n"), "{err}");
    };
    // Under ai-env as deployer: as ops runs as the deployer, its key's environment applied again.
    let out = covered("ops", keys::identity_env("deployer", keys::DEPLOYER_TAIL));
    assert_eq!(stdout(&out), seen_as("deployer", keys::DEPLOYER_TAIL));
    says(&out, "ai-env-ops", "ai-env-deployer (key ...9001, ai-env as deployer)");
    // Under ai-env as root and as ambient: the command as it is, the chain's own selectors kept, nothing pinned.
    let as_it_is = |marker: &str| format!("AWS_PROFILE=set\nAWS_SESSION_TOKEN=set\nAWS_ENDPOINT_URL_STS=unset\nAWS_CONTAINER_CREDENTIALS_FULL_URI=unset\nmarker={marker}\nkey=...\nsecret=0\npins=unset unset unset unset\n");
    let out = covered("deployer", keys::marker_env("root"));
    assert_eq!(stdout(&out), as_it_is("root"));
    says(&out, "ai-env-deployer", "the account ROOT (ai-env as root)");
    let out = covered("ops", keys::marker_env("ambient"));
    assert_eq!(stdout(&out), as_it_is("ambient"));
    says(&out, "ai-env-ops", "the ambient aws CLI identity (ai-env as ambient)");
}

/// The runner's own failures (§3.4, §3.6): `as deployer` with no terminal
/// to paste into is exit 5 before any prompt or call (the key is never read
/// from a pipe or the environment); a command that cannot be run is exit 1,
/// `cannot exec "<program>": <error>`, after its unseal and audit row, the
/// line the recipe tests' stand-in (tests/fakes/ai-env.sh) prints too.
#[test]
fn as_says_why_without_a_terminal_or_a_command_it_can_run() {
    use std::os::unix::process::CommandExt as _;
    let env = Env::new(true);
    let mut cmd = cli(&env, &["as", "--account", STACK, "deployer", "--", "true"]);
    // A session of its own: no controlling terminal, so no /dev/tty (stdin is null, the debug knob unset).
    // SAFETY: runs in the forked child before exec; setsid(2) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = run(&mut cmd);
    assert_eq!(code(&out), Some(5), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        "ai-env: as ai-env-deployer: paste its access key from Strongbox (nothing you paste is shown)\nai-env: as deployer: no terminal to paste the key into (it is never read from a file, a pipe or the environment)\n"
    );
    assert!(aws_calls(&env).is_empty() && as_rows(&env).is_empty());
    // A command that cannot be run: the ops key unsealed and the audit row written first.
    seal_ops(&env, keys::OPS_TAIL);
    let out = run(&mut cli(&env, &["as", "ops", "--", "/nonexistent/x"]));
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    let failed = "ai-env: cannot exec \"/nonexistent/x\": No such file or directory (os error 2)";
    let err = stderr(&out);
    let last: Vec<&str> = err.lines().rev().take(2).collect();
    assert_eq!(last, [failed, "ai-env: as ai-env-ops (key ...9002, credentials/ops.env): /nonexistent/x"], "{err}");
    assert_eq!((decrypts(&env), as_rows(&env).len()), (1, 1));
    // The stand-in the recipe tests run says the same.
    let mut standin = Command::new("/bin/sh");
    standin.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/ai-env.sh")).args(["as", "ops", "--", "/nonexistent/x"]);
    standin.env_clear().env("PATH", "/usr/bin:/bin").env("HOME", env.root()).stdin(std::process::Stdio::null());
    let out = run(&mut standin);
    assert_eq!((code(&out), stderr(&out)), (Some(1), format!("{failed}\n")), "tests/fakes/ai-env.sh");
}

/// The stack's egress connector (the fixtures' account, the fakes' default).
const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

/// `env`'s bridge as the vm, lab and egress commands load it: `bridge.toml`
/// naming the stack's image, execution role and egress connector, the
/// stack's `state/infra.toml` (changed by `f`), and the file-backed fake
/// MicroVM API of the debug builds (a VM is RUNNING at its first get),
/// whose file this returns.
fn fake_world(env: &Env, f: impl FnOnce(&mut ai_env_cli::bridge::infra::InfraState)) -> std::path::PathBuf {
    let bridge = env.root().join("bridge");
    fs::create_dir_all(&bridge).unwrap();
    let toml = format!(
        "[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:{STACK}:microvm-image:ai-env-agent\"\nexecution_role_arn = \"arn:aws:iam::{STACK}:role/ai-env-exec\"\negress_connector_arn = \"{CONNECTOR}\"\n"
    );
    fs::write(bridge.join("bridge.toml"), toml).unwrap();
    write_state(env, f);
    let fake = env.root().join("fake.json");
    let mut state = ai_env_cli::bridge::api::FakeState::new();
    state.auto_advance = true;
    fs::write(&fake, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    fake
}

/// [`cli`] against the fake MicroVM API `fake`, polls scaled to milliseconds.
fn cli_fake(env: &Env, fake: &Path, args: &[&str]) -> Command {
    let mut cmd = cli(env, args);
    cmd.env("AI_ENV_BRIDGE_LAB_FAKE_API", fake).env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
    cmd
}

/// The `RunMicrovm` calls the fake `fake` answered.
fn vm_runs(fake: &Path) -> usize {
    let state: ai_env_cli::bridge::api::FakeState = serde_json::from_str(&fs::read_to_string(fake).unwrap()).unwrap();
    state.calls.iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Run { .. })).count()
}

/// `egress check` (§4.1, §7.4): a state naming other proxy documents is
/// refused first (exit 1) whatever identity there is: no Touch ID, no call,
/// no VM. Then the operator identity, before anything else the check reads
/// or starts: before a `--vm`'s row (none: exit 5 naming `egress check`;
/// the sealed ops key: unsealed first) and before the runtime key, whose
/// dialog comes second.
#[test]
fn egress_check_refuses_stale_documents_then_resolves_the_operator_first() {
    let env = Env::new(true);
    let fake = fake_world(&env, |s| s.proxy_reload_document = Some("ai-env-proxy-reload-v2".into()));
    let check = |args: &[&str], extra: &[(&str, &str)]| {
        reset(&env);
        let mut all = vec!["egress", "check"];
        all.extend_from_slice(args);
        let mut cmd = cli_fake(&env, &fake, &all);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(&mut cmd)
    };
    let stale = format!(
        "ai-env: {} names the proxy documents ai-env-proxy-reload-v2, -, -; this ai-env sends ai-env-proxy-reload, ai-env-proxy-status, ai-env-proxy-patch: update ai-env, or make infra-status WRITE=1",
        env.root().join("bridge").join("state").join("infra.toml").display()
    );
    let no_row = "microvm-00000000-0000-4000-8000-0000000000ff";
    for sealed in [false, true] {
        if sealed {
            seal_ops(&env, keys::OPS_TAIL);
        }
        for args in [&[][..], &["--vm", no_row], &["--if-needed"]] {
            let out = check(args, &[]);
            assert_eq!(code(&out), Some(1), "{args:?} (ops.env sealed: {sealed}): {}", stderr(&out));
            assert!(said(&out, &stale), "{args:?}: {}", stderr(&out));
            assert!(aws_calls(&env).is_empty() && decrypts(&env) == 0, "{args:?} (ops.env sealed: {sealed}): no call, no Touch ID");
        }
    }
    assert_eq!(vm_runs(&fake), 0, "no VM");
    // The documents this ai-env sends: the identity first, before the --vm row is read.
    write_state(&env, |_| {});
    let out = check(&["--vm", no_row], &[]);
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    assert_eq!(decrypts(&env), 1, "the ops key first");
    let err = stderr(&out);
    let unsealed = err.find("ai-env: operator ai-env-ops (key ...9002, credentials/ops.env)\n");
    let refused = err.find(&format!("ai-env: egress check --vm {no_row}: no row in state/vms (not started by this ai-env)"));
    assert!(unsealed.is_some() && unsealed < refused, "{err}");
    fs::remove_file(env.credentials().join("ops.env")).unwrap();
    let out = check(&["--vm", no_row], &[]);
    assert_eq!(code(&out), Some(5), "{}", stderr(&out));
    assert!(said(&out, &format!("ai-env: egress check: {NO_OPERATOR}")), "{}", stderr(&out));
    assert!(aws_calls(&env).is_empty() && decrypts(&env) == 0);
    // Both keys sealed (the runtime key unsealed under the fake by the debug knob): the ops key's dialog first.
    seal_ops(&env, keys::OPS_TAIL);
    let runtime = TestKey { id: keys::key_id(keys::RUNTIME_TAIL), secret: keys::secret("Rt5+") };
    let sealed = piped(&mut env.creds(&["aws-set"]), key_json(USER, &runtime, "Active").as_bytes());
    assert_eq!(code(&sealed), Some(0), "{}", stderr(&sealed));
    let out = check(&[], &[("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1")]);
    assert_eq!(code(&out), Some(9), "the fake carries no shell: {}", stderr(&out));
    assert_eq!(decrypts(&env), 2, "{:?}", lines(&env.age_log()));
    let err = stderr(&out);
    let (ops_at, runtime_at) = (err.find("ai-env: operator ai-env-ops (key ...9002, credentials/ops.env)\n"), err.find("ai-env: runtime key …9003 (credentials/aws.env)"));
    assert!(ops_at.is_some() && runtime_at.is_some() && ops_at < runtime_at, "{err}");
    assert_eq!(aws_calls(&env).first().map(String::as_str), Some(STS_CALL), "the account check before the VM");
    assert_eq!(vm_runs(&fake), 1);
}

/// `lab run connector-pending` and `cloudtrail-payload` (without `--log`)
/// resolve the operator before anything else (§4.1): with no identity both
/// are exit 5 naming the probe, and a `root` marker on another principal
/// exit 9 after its one identity check, never a refusal from inside the
/// runtime or the reads; no RunMicrovm, no other AWS call, nothing recorded.
#[test]
fn lab_probes_resolve_the_operator_before_their_runtime_and_reads() {
    let env = Env::new(true);
    let fake = fake_world(&env, |_| {});
    // A VM this ai-env started: cloudtrail-payload reads its row first.
    let out = run(&mut cli_fake(&env, &fake, &["vm", "run", "--egress", "internet", "--json"]));
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    let id = serde_json::from_str::<serde_json::Value>(&stdout(&out)).unwrap()["id"].as_str().unwrap().to_string();
    let runs = vm_runs(&fake);
    let probe = format!("arn:aws:lambda:eu-central-1:{STACK}:network-connector:ai-env-egress-probe");
    let not_root = format!("AI_ENV_BRIDGE_AS=root, but the aws CLI's credentials are arn:aws:iam::{STACK}:user/rust, not the account root: unset it, or run the command under ai-env as root -- again");
    let root = keys::marker_env("root");
    for (name, arg) in [("connector-pending", probe.as_str()), ("cloudtrail-payload", id.as_str())] {
        let lab = |extra: &[(&str, &str)]| {
            reset(&env);
            let mut cmd = cli_fake(&env, &fake, &["lab", "run", name, arg]);
            for (k, v) in extra {
                cmd.env(k, v);
            }
            run(&mut cmd)
        };
        let out = lab(&[]);
        assert_eq!(code(&out), Some(5), "{name}: {}", stderr(&out));
        assert!(said(&out, &format!("ai-env: lab run {name}: {NO_OPERATOR}")), "{name}: {}", stderr(&out));
        assert!(aws_calls(&env).is_empty(), "{name}: {:?}", aws_calls(&env));
        let out = lab(&[(root[0].0.as_str(), root[0].1.as_str()), ("FAKE_AWS_CALLER", "rust")]);
        assert_eq!(code(&out), Some(9), "{name}: {}", stderr(&out));
        assert!(said(&out, &format!("ai-env: lab run {name}: {not_root}")), "{name}: {}", stderr(&out));
        assert_eq!(aws_calls(&env), [STS_CALL], "{name}: the identity check, then nothing");
    }
    // D22: an operator of another account than the probe connector's is refused right after its identity check,
    // before the runtime key is unsealed (exit 1, the probe's label), never by the probe once a runtime runs.
    env.keystore(KEY, true);
    let runtime = TestKey { id: keys::key_id(keys::RUNTIME_TAIL), secret: keys::secret("Rt6+") };
    let sealed = piped(&mut env.creds(&["aws-set"]), key_json(USER, &runtime, "Active").as_bytes());
    assert_eq!(code(&sealed), Some(0), "{}", stderr(&sealed));
    reset(&env);
    let mut cmd = cli_fake(&env, &fake, &["lab", "run", "connector-pending", probe.as_str()]);
    cmd.envs(keys::identity_env("ops", keys::OPS_TAIL)).env("FAKE_AWS_KEY_USERS", format!("{}:ai-env-ops@{OTHER}", keys::OPS_TAIL)).env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1");
    let out = run(&mut cmd);
    assert_eq!(code(&out), Some(1), "{}", stderr(&out));
    let foreign = format!("ai-env: lab run connector-pending: the operator credentials are of account {OTHER}, but {probe} is in account {STACK}: run it under ai-env as ops -- with that account's ops key");
    assert!(said(&out, &foreign), "{}", stderr(&out));
    assert_eq!(aws_calls(&env), [STS_CALL], "the identity check, then nothing");
    assert_eq!(decrypts(&env), 0, "the runtime key is never unsealed: {:?}", lines(&env.age_log()));
    assert_eq!(vm_runs(&fake), runs, "no RunMicrovm");
    assert!(!env.root().join("bridge").join("lab").join("probes.jsonl").exists(), "nothing recorded");
}

// ---- review fixes D6, D7: the clipboard of `as deployer`'s terminal pastes --------------------------------

/// D7 (contracts §3.3 step 4) and D6: `ai-env as deployer` pasted at a
/// terminal (a pty, the debug knob unset, tests/fakes/osascript.sh the
/// pasteboard) clears the clipboard once the second paste is read, with its
/// note: on success, after an empty second paste and after a value of the
/// wrong shape (from the first value on, whatever follows); a refused clear
/// is a warning and the command still runs. Echo is off at both prompts and
/// the terminal shows the prompts alone. A stop at either prompt (Ctrl-C, a
/// SIGTERM, a SIGHUP from a closed window) clears it through the clear
/// spawned before the first prompt, or warns, restores the terminal and ends
/// the run with 128 + the signal, nothing run. The debug knob's stdin path
/// has no clipboard: no osascript at all.
#[cfg(debug_assertions)]
#[test]
fn as_deployer_clears_the_clipboard_after_a_terminal_paste_and_on_a_stop() {
    use super::handover::{Session, World};
    const ID: &str = "ai-env-deployer access key id: ";
    const SECRET: &str = "ai-env-deployer secret access key: ";
    const CLEARED: &str = "ai-env: cleared the clipboard (it held what you pasted)";
    const STOPPED: &str = "ai-env: as deployer: stopped at the paste: nothing was run\n";
    let refused = "execution error: Error: Error: setString:forType: refused (-2700)";
    let w = World::new();
    let (id, secret) = deployer_key();
    let ran = w.env.root().join("ran");
    let touch = format!("touch {}", ran.display());
    let start = |extra: &[(&str, &str)]| {
        reset(&w.env);
        w.fresh_clipboard();
        for done in [&ran, &w.env.audit()] {
            let _ = fs::remove_file(done);
        }
        let mut cmd = cli(&w.env, &["as", "--account", STACK, "deployer", "--", "/bin/sh", "-c", touch.as_str()]);
        cmd.env_remove("AI_ENV_PASTE_STDIN").env("AI_ENV_BRIDGE_LAB_OSASCRIPT", w.env.bin().join("osascript")).env("FAKE_OSA_LOG", w.osa_log());
        for (k, v) in extra {
            cmd.env(k, v);
        }
        Session::start(cmd, b"", true)
    };
    let nothing_ran = || !ran.exists() && aws_calls(&w.env).is_empty() && as_rows(&w.env).is_empty();

    // Both pasted: cleared with its note, then the check, the row and the command.
    let mut s = start(&[]);
    s.answer(ID, 1, &id);
    s.answer(SECRET, 1, &secret);
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    assert!(ran.exists(), "the command ran");
    assert_eq!(w.osa(), ["clear cleared"], "one clear, its environment without a key or the marker");
    let said: Vec<&str> = done.stderr.lines().collect();
    assert_eq!(said[..2], ["ai-env: as ai-env-deployer: paste its access key from Strongbox (nothing you paste is shown)", CLEARED], "{}", done.stderr);
    assert!(said.len() == 3 && said[2].starts_with("ai-env: as ai-env-deployer (key ...9001, account …9012, verified): /bin/sh -c touch "), "{}", done.stderr);
    assert_eq!(done.tty, format!("{ID}\n{SECRET}\n"), "the prompts, nothing pasted");
    assert!(done.echo, "echo is on again");
    done.never_shows(&secret, "the pasted secret");
    done.never_shows_id(&id, 0, "the pasted key id");
    assert_eq!(as_rows(&w.env).len(), 1);

    // An empty second paste, a value of the wrong shape: cleared all the same, then refused; nothing runs.
    for (second, want, line) in [("", 3, "ai-env: as deployer: nothing was pasted: cancelled, nothing was run"), (&secret[..39], 1, "ai-env: as deployer: the pasted secret access key has 39 characters, expected 40 (not echoed): nothing was run")] {
        let mut s = start(&[]);
        s.answer(ID, 1, &id);
        s.answer(SECRET, 1, second);
        let done = s.finish();
        assert_eq!(done.code(), Some(want), "{line}: {}", done.stderr);
        assert_eq!(w.osa(), ["clear cleared"], "{line}");
        assert!(done.stderr.ends_with(&format!("{CLEARED}\n{line}\n")), "{}", done.stderr);
        assert!(nothing_ran() && done.echo, "{line}");
    }

    // osascript refuses the clear: the warning, and the command still runs.
    let mut s = start(&[("FAKE_OSA_FAIL", "clear")]);
    s.answer(ID, 1, &id);
    s.answer(SECRET, 1, &secret);
    let done = s.finish();
    assert_eq!(done.code(), Some(0), "{}", done.stderr);
    assert!(done.stderr.contains(&format!("\nai-env: warning: the clipboard could not be cleared ({refused}): clear it yourself\n")) && !done.stderr.contains(CLEARED), "{}", done.stderr);
    assert!(ran.exists());
    assert_eq!(w.osa(), ["fail clear"]);

    // D6: Ctrl-C at the secret's prompt: the clear spawned before the first prompt clears it, the terminal echoes
    // again, exit 130, nothing run.
    let mut s = start(&[]);
    s.answer(ID, 1, &id);
    s.wait_prompt(SECRET, 1);
    s.ctrl_c();
    let done = s.finish();
    assert_eq!(done.code(), Some(130), "{}", done.stderr);
    assert!(done.stderr.ends_with(STOPPED) && !done.stderr.contains("could not be cleared") && !done.stderr.contains(CLEARED), "{}", done.stderr);
    assert_eq!(w.osa(), ["clear cleared"], "the stop cleared the clipboard");
    assert!(done.echo, "the stop restored the terminal");
    assert!(nothing_ran());
    done.never_shows_id(&id, 0, "the pasted key id");
    // A SIGTERM, and the SIGHUP of a closed window, at the first prompt: the same, 143 and 129.
    for (sig, want) in [(libc::SIGTERM, 143), (libc::SIGHUP, 129)] {
        let mut s = start(&[]);
        s.wait_prompt(ID, 1);
        s.signal(sig);
        let done = s.finish();
        assert_eq!(done.code(), Some(want), "{sig}: {}", done.stderr);
        assert!(done.stderr.ends_with(STOPPED), "{sig}: {}", done.stderr);
        assert_eq!(w.osa(), ["clear cleared"], "{sig}");
        assert!(done.echo && nothing_ran(), "{sig}");
    }
    // The clear refused at a stop: the warning before the line.
    let mut s = start(&[("FAKE_OSA_FAIL", "clear")]);
    s.wait_prompt(ID, 1);
    s.ctrl_c();
    let done = s.finish();
    assert_eq!(done.code(), Some(130), "{}", done.stderr);
    assert!(done.stderr.ends_with(&format!("ai-env: warning: the clipboard could not be cleared: clear it yourself\n{STOPPED}")), "{}", done.stderr);
    assert_eq!(w.osa(), ["fail clear"]);

    // The debug builds' stdin path (the other tests' pipe): no clipboard, so no osascript, not even the clear's.
    reset(&w.env);
    w.fresh_clipboard();
    let mut cmd = as_cmd(&w.env, &["--account", STACK, "deployer", "--", "true"]);
    cmd.env("AI_ENV_BRIDGE_LAB_OSASCRIPT", w.env.bin().join("osascript")).env("FAKE_OSA_LOG", w.osa_log());
    let out = pasting(&mut cmd, &id, &secret);
    assert_eq!(code(&out), Some(0), "{}", stderr(&out));
    assert!(w.osa().is_empty() && !stderr(&out).contains("clipboard"), "{:?}: {}", w.osa(), stderr(&out));
}
