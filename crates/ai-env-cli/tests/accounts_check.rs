//! A1: `ai-env creds account check [NAME…] [--json] [--model M]` through the
//! binary (plans/s10-accounts-plan.md §6), against a fake Cursor bundle under
//! the test's HOME holding tests/fakes/claude-usage.sh (its token's tail picks
//! the outcome; it logs its argv, its environment's names and the token's
//! sha8, never the token) and the fake age (one `age -d` log line per Touch
//! ID). The accounts are sealed by the real `creds account add`, with no
//! runtime key (so no combined container and no Touch ID of their own). No
//! test reaches Anthropic, AWS or the real keystore; every token is built at
//! run time, and none is in an output, the fake's log or a file under the
//! tree. Assertion messages print lengths, or text the scrubber has masked.
#[path = "common/green_world.rs"]
mod green_world;

use ai_env_cli::bridge::config::Paths;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PREFIX: &str = "sk-ant-oat01-";
/// How long one `ai-env` run may take.
const LIMIT: Duration = Duration::from_secs(120);
/// The Cursor bundle the check finds (`lab_mac::mac_claude`).
const BUNDLE: &str = "anthropic.claude-code-2.1.305-darwin-arm64";
/// Where the check records a refusal it saw.
const WHERE: &str = "this Mac (creds account check)";

/// A token of the setup-token shape: `seed` tells two apart, `outcome` (its
/// tail) picks what the fake claude does with it.
fn token(seed: &str, outcome: &str) -> String {
    format!("{PREFIX}{}{seed}-{outcome}", "Kc4_".repeat(20))
}

/// The first 8 hex digits of `t`'s sha256: how the fake logs a token.
fn sha8(t: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(t.as_bytes()))[..8].to_string()
}

fn shown(text: &str) -> String {
    ai_env_cli::wire::redact::scrub(text).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `child` to its end within [`LIMIT`], its pipes drained meanwhile.
fn finish(mut child: Child) -> Output {
    fn drain(pipe: Option<impl std::io::Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    }
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ai-env ran past {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

/// One tree: `bin/` (the fake age), `keys/` (the keystore key), `bridge/`,
/// `tmp/`, and HOME at its root, whose Cursor bundle holds the fake claude
/// (with B7's refused lines beside it) unless `with_claude` is false.
struct World {
    tmp: tempfile::TempDir,
}

impl World {
    fn new(with_claude: bool) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let w = World { tmp };
        fs::create_dir_all(w.bin()).unwrap();
        fs::create_dir_all(w.root().join("tmp")).unwrap();
        for name in ["age", "age-keygen", "age-plugin-se"] {
            let dst = w.bin().join(name);
            fs::copy(green_world::FAKE_AGE, &dst).unwrap();
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let key = w.root().join("keys").join("keys").join("ai-env-bridge");
        fs::create_dir_all(&key).unwrap();
        fs::write(key.join("identity.txt"), format!("# public key: {}\nAGE-PLUGIN-SE-1FAKEFAKE\n", green_world::SE_REC)).unwrap();
        fs::write(key.join("recipients.txt"), format!("{}\n{}\n", green_world::SE_REC, green_world::X_REC)).unwrap();
        fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
        if with_claude {
            let dir = w.claude_dir();
            fs::create_dir_all(&dir).unwrap();
            let fakes = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
            fs::copy(fakes.join("fakes").join("claude-usage.sh"), dir.join("claude")).unwrap();
            fs::set_permissions(dir.join("claude"), fs::Permissions::from_mode(0o755)).unwrap();
            fs::copy(fakes.join("fixtures").join("claude").join("refused-stream-json-2.1.296.jsonl"), dir.join("refused.jsonl")).unwrap();
        }
        w
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn bin(&self) -> PathBuf {
        self.root().join("bin")
    }

    fn paths(&self) -> Paths {
        Paths::from_root_and_env(self.root().join("bridge"), None)
    }

    fn claude_dir(&self) -> PathBuf {
        self.root().join(".cursor").join("extensions").join(BUNDLE).join("resources").join("native-binary")
    }

    /// The fake claude's log: one block of lines per turn.
    fn claude_log(&self) -> String {
        fs::read_to_string(self.claude_dir().join("claude.log")).unwrap_or_default()
    }

    fn age_log(&self) -> PathBuf {
        self.root().join("age.log")
    }

    fn decrypts(&self) -> usize {
        green_world::decrypts(&self.age_log())
    }

    /// `ai-env <args>` in this tree, nothing of the developer's shell
    /// steering it or the fakes (no `AWS_*`, `AI_ENV_*`, `CLAUDE_CODE_*` or
    /// `FAKE_*` but what is set here), the hidden paste read from stdin.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") {
                cmd.env_remove(&k);
            }
        }
        cmd.args(args)
            .env("HOME", self.root())
            .env("AI_ENV_BRIDGE_DIR", self.root().join("bridge"))
            .env("AI_ENV_DIR", self.root().join("keys"))
            .env("AI_ENV_BRIDGE_LAB_OSASCRIPT", "/usr/bin/false")
            .env("AI_ENV_PASTE_STDIN", "1")
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("TMPDIR", self.root().join("tmp"))
            .env("FAKE_AGE_LOG", self.age_log())
            .stdin(Stdio::null());
        cmd
    }

    /// Claude account `name` sealed with `creds account add --stdin`: its token.
    fn add(&self, name: &str, outcome: &str) -> String {
        let t = token(name, outcome);
        let mut child = self.cmd(&["creds", "account", "add", name, "--stdin"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(format!("{t}\n").as_bytes()).unwrap();
        let out = finish(child);
        assert!(out.status.success(), "add {name}: {}", shown(&stderr(&out)));
        t
    }

    fn run(&self, mut cmd: Command) -> Output {
        finish(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap())
    }

    /// `ai-env creds account check <args>`.
    fn check(&self, args: &[&str]) -> Output {
        let mut all = vec!["creds", "account", "check"];
        all.extend_from_slice(args);
        self.run(self.cmd(&all))
    }

    /// The audit rows of `event`.
    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        ai_env_cli::bridge::audit::read_rows(&self.paths().audit(), None).unwrap_or_default().into_iter().filter(|r| r["event"] == event).collect()
    }

    /// No piece of any of `tokens` is in `outs`, the fake's log or any file under the tree.
    fn swept(&self, outs: &[&Output], tokens: &[&String]) {
        let mut files = Vec::new();
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for e in fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                match fs::symlink_metadata(&p) {
                    Ok(m) if m.is_dir() => walk(&p, out),
                    Ok(m) if m.is_file() => out.push(p),
                    _ => {}
                }
            }
        }
        walk(self.root(), &mut files);
        for t in tokens {
            let secret = &t[PREFIX.len()..];
            let pieces: Vec<&[u8]> = secret.as_bytes().windows(16).collect();
            let holds = |hay: &[u8]| pieces.iter().any(|p| hay.windows(16).any(|w| w == *p));
            for o in outs {
                assert!(!holds(&o.stdout) && !holds(&o.stderr), "a token is in an output");
            }
            for f in &files {
                assert!(!holds(&fs::read(f).unwrap()), "a token is in {}", f.display());
            }
        }
    }
}

/// The fake's turns as logged, one per block: (argv, env names, how the token came, its sha8).
fn turns(log: &str) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    let (mut argv, mut env) = (String::new(), String::new());
    for line in log.lines() {
        if let Some(a) = line.strip_prefix("argv") {
            argv = a.trim().to_string();
        } else if let Some(e) = line.strip_prefix("env ") {
            env = e.split_whitespace().filter(|n| !matches!(*n, "PWD" | "SHLVL" | "_" | "OLDPWD")).collect::<Vec<_>>().join(" ");
        } else if let Some(t) = line.strip_prefix("token ") {
            let (how, sha) = t.split_once(' ').unwrap();
            out.push((argv.clone(), env.clone(), how.to_string(), sha.to_string()));
        }
    }
    out
}

/// Three accounts (the active one answers, one is at its weekly limit, one
/// Anthropic refuses): exit 5, three Touch IDs (one each, never two tokens
/// held), a line each in its format; `[usage.<name>]` recorded for the
/// answer and the limit (`source = "check"`), the refusal recorded against
/// its seal; `account_check` and `credential_unseal` audited; every run's
/// HOME removed; and the fake saw the pinned argv, exactly the environment's
/// names (the token's descriptor, never the token) and each token on fd 3.
#[test]
fn three_accounts_answered_limited_and_refused_exit_5_with_one_touch_id_each() {
    let w = World::new(true);
    let (a, b, c) = (w.add("aa", "ok"), w.add("bb", "limited"), w.add("cc", "refused"));
    assert_eq!(w.decrypts(), 0, "sealing asks for no Touch ID");
    let out = w.check(&[]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert_eq!(w.decrypts(), 3, "one Touch ID per account");
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{}", shown(&text));
    assert!(lines[0].starts_with("aa (active): 5h 23% (resets ") && lines[0].contains("Z), 7d 81% (resets "), "{}", shown(lines[0]));
    assert!(lines[1].starts_with("bb: limited: weekly, \"resets 10am (UTC)\" (") && lines[1].ends_with("Z)"), "{}", shown(lines[1]));
    assert_eq!(lines[2], "cc: refused by Anthropic (HTTP 401): seal a fresh token for it (claude setup-token, then ai-env creds account add cc)");
    let err = stderr(&out);
    assert!(err.contains("ai-env: Claude account aa (1 of 3): one Touch ID, then one turn of haiku on claude 2.1.305"), "{}", shown(&err));
    let p = w.paths();
    let state = ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap();
    let ua = &state.usage["aa"];
    assert_eq!((ua["source"].as_str(), ua["status"].as_str(), ua["five_hour"]["utilization"].as_float(), ua["seven_day"]["utilization"].as_float()), (Some("check"), Some("allowed"), Some(0.23), Some(0.81)));
    let ub = &state.usage["bb"];
    assert_eq!((ub["status"].as_str(), ub["limited"]["kind"].as_str(), ub["limited"]["text"].as_str()), (Some("rejected"), Some("seven_day"), Some("You've hit your weekly limit · resets 10am (UTC)")));
    assert!(!state.usage.contains_key("cc"));
    let cc_tag = ai_env_cli::bridge::agent::credential::seal_tag(&p.account_env("cc")).unwrap();
    let refusal = ai_env_cli::bridge::agent::credential::read_rejection(&p, &cc_tag).unwrap().expect("cc's refusal recorded");
    assert_eq!(refusal.vm, WHERE);
    let checks = w.audit("account_check");
    let got: Vec<(&str, &str)> = checks.iter().map(|r| (r["detail"]["account"].as_str().unwrap(), r["detail"]["outcome"].as_str().unwrap())).collect();
    assert_eq!(got, [("aa", "checked"), ("bb", "limited")]);
    assert_eq!((checks[0]["detail"]["five_hour"].as_str(), checks[0]["detail"]["model"].as_str(), checks[0]["detail"]["claude"].as_str()), (Some("23%"), Some("haiku"), Some("2.1.305")));
    let unseals = w.audit("credential_unseal");
    let got: Vec<(&str, &str, &str)> = unseals.iter().map(|r| (r["detail"]["source"].as_str().unwrap(), r["detail"]["account"].as_str().unwrap(), r["detail"]["outcome"].as_str().unwrap())).collect();
    assert_eq!(got, [("account", "aa", "ok"), ("account", "bb", "ok"), ("account", "cc", "ok")]);
    assert_eq!(w.audit("credential_rejected").len(), 1);
    let left: Vec<_> = fs::read_dir(p.tmp()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert!(left.is_empty(), "every run's HOME removed: {left:?}");
    let ran = turns(&w.claude_log());
    let argv = "[-p] [Reply with exactly OK] [--output-format] [stream-json] [--verbose] [--model] [haiku] [--max-turns] [1] [--tools] [] [--strict-mcp-config] [--disable-slash-commands] [--no-session-persistence]";
    let env = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR CLAUDE_CONFIG_DIR DISABLE_AUTOUPDATER HOME PATH TZ";
    assert_eq!(ran, [&a, &b, &c].map(|t| (argv.to_string(), env.to_string(), "fd".to_string(), sha8(t))), "{}", shown(&w.claude_log()));
    w.swept(&[&out], &[&a, &b, &c]);
}

/// A seal whose refusal is recorded is shown with no Touch ID asked for
/// it, and the others are checked (exit 5); a named subset checks only
/// those, each once; an unknown name is exit 2 before any Touch ID.
#[test]
fn a_recorded_refusal_asks_no_touch_id_and_names_choose_the_accounts() {
    let w = World::new(true);
    let (a, b) = (w.add("aa", "ok"), w.add("bb", "ok"));
    let p = w.paths();
    let bb_tag = ai_env_cli::bridge::agent::credential::seal_tag(&p.account_env("bb")).unwrap();
    fs::create_dir_all(p.creds_state().parent().unwrap()).unwrap();
    fs::write(p.creds_state(), format!("[[rejected]]\ntag = \"{bb_tag}\"\nat = \"2026-10-07T12:00:00Z\"\nvm = \"microvm-1\"\n")).unwrap();
    let out = w.check(&[]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert_eq!(w.decrypts(), 1, "aa only");
    assert!(stdout(&out).ends_with("bb: not checked: refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1); no Touch ID asked\n"), "{}", shown(&stdout(&out)));
    fs::remove_file(p.creds_state()).unwrap();
    let out2 = w.check(&["bb", "aa", "bb"]);
    assert_eq!(out2.status.code(), Some(0), "{}", shown(&stderr(&out2)));
    assert_eq!(w.decrypts(), 3, "two more: bb, then aa");
    assert!(stdout(&out2).starts_with("bb: 5h ") && stdout(&out2).contains("\naa (active): 5h "), "{}", shown(&stdout(&out2)));
    let out3 = w.check(&["nope"]);
    assert_eq!(out3.status.code(), Some(2), "{}", shown(&stderr(&out3)));
    assert!(stderr(&out3).contains("no Claude account nope (Claude accounts: aa, bb)"), "{}", shown(&stderr(&out3)));
    assert_eq!(w.decrypts(), 3, "none for an unknown name");
    w.swept(&[&out, &out2, &out3], &[&a, &b]);
}

/// A `credentials/accounts/<name>.env` that is no container (a token in the
/// clear, perhaps) is no account, and is never skipped silently: the check
/// shows it `not_checked` with no Touch ID, named or not, and exits 5; a
/// name no file has is still exit 2.
#[test]
fn a_file_that_is_no_container_is_not_checked() {
    let w = World::new(true);
    let a = w.add("aa", "ok");
    let p = w.paths();
    fs::write(p.account_env("pp"), "CLAUDE_CODE_OAUTH_TOKEN=placeholder\n").unwrap();
    let says = format!("pp: not checked: {} is not an ai-env container (plaintext?): it is no Claude account; move it away (and revoke what it holds); no Touch ID asked\n", p.account_env("pp").display());
    let out = w.check(&[]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert_eq!(w.decrypts(), 1, "aa only");
    assert!(stdout(&out).starts_with("aa (active): 5h ") && stdout(&out).ends_with(&says), "{}", shown(&stdout(&out)));
    let out2 = w.check(&["pp"]);
    assert_eq!(out2.status.code(), Some(5), "{}", shown(&stderr(&out2)));
    assert_eq!((w.decrypts(), stdout(&out2)), (1, says), "no Touch ID for it");
    let out3 = w.check(&["qq"]);
    assert_eq!(out3.status.code(), Some(2), "{}", shown(&stderr(&out3)));
    w.swept(&[&out, &out2, &out3], &[&a]);
}

/// A dismissed dialog ends the check with 3, a Touch ID deadline with 5
/// (the lab knob's budget), the accounts after it unchecked; no claude on
/// this Mac is 1 before any Touch ID.
#[test]
fn a_dismissed_dialog_is_3_a_deadline_5_and_no_claude_1() {
    let w = World::new(true);
    let (a, b) = (w.add("aa", "ok"), w.add("bb", "ok"));
    let out = w.run({
        let mut c = w.cmd(&["creds", "account", "check"]);
        c.env("FAKE_AGE_FAIL", "cancel");
        c
    });
    assert_eq!(out.status.code(), Some(3), "{}", shown(&stderr(&out)));
    assert_eq!((w.decrypts(), stdout(&out).as_str()), (1, ""), "the first dialog ended it");
    assert!(w.claude_log().is_empty(), "no claude ran");
    let out2 = w.run({
        let mut c = w.cmd(&["creds", "account", "check", "--json"]);
        c.env("FAKE_AGE_HANG", "1").env("AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS", "1000");
        c
    });
    assert_eq!(out2.status.code(), Some(5), "{}", shown(&stderr(&out2)));
    assert!(stderr(&out2).contains("no Touch ID within 1 s, so Claude account aa's token stayed sealed"), "{}", shown(&stderr(&out2)));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&out2)).unwrap();
    assert_eq!((doc["exit"].as_i64(), doc["accounts"][0]["outcome"].as_str(), doc["accounts"][1]["outcome"].as_str()), (Some(5), Some("not_checked"), Some("not_checked")));
    let bare = World::new(false);
    bare.add("aa", "ok");
    let out3 = bare.check(&[]);
    assert_eq!(out3.status.code(), Some(1), "{}", shown(&stderr(&out3)));
    assert!(stderr(&out3).contains("no claude on this Mac (the Cursor extension's, or one on PATH)"), "{}", shown(&stderr(&out3)));
    assert_eq!(bare.decrypts(), 0);
    w.swept(&[&out, &out2], &[&a, &b]);
}

/// Ctrl-C while an account's turn runs: the check ends with 130, its claude
/// (its whole group) ended with it; the account checked before it is
/// shown and recorded.
#[test]
fn ctrl_c_during_a_turn_is_130_and_ends_claude() {
    use std::os::unix::process::CommandExt as _;
    let w = World::new(true);
    let (a, h) = (w.add("aa", "ok"), w.add("hh", "hang"));
    let mut cmd = w.cmd(&["creds", "account", "check"]);
    cmd.process_group(0).stdout(Stdio::piped()).stderr(Stdio::piped());
    // As at a terminal: a `cargo test &` would hand SIGINT down ignored.
    // SAFETY: runs in the forked child before exec; signal(2) is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    let group = i32::try_from(child.id()).unwrap();
    let started = Instant::now();
    let pid = loop {
        let pids: Vec<i32> = w.claude_log().lines().filter_map(|l| l.strip_prefix("pid ")?.trim().parse().ok()).collect();
        if pids.len() == 2 {
            break pids[1];
        }
        assert!(started.elapsed() < Duration::from_secs(60), "hh's turn never started: {}", shown(&w.claude_log()));
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: killpg(2) on the group this test made for ai-env (claude has a group of its own).
    unsafe { libc::killpg(group, libc::SIGINT) };
    let out = finish(child);
    assert_eq!(out.status.code(), Some(130), "{}", shown(&stderr(&out)));
    assert!(stdout(&out).starts_with("aa (active): 5h ") && !stdout(&out).contains("hh"), "{}", shown(&stdout(&out)));
    assert!(stderr(&out).contains("ai-env: stopped while Claude account hh's turn ran (SIGINT): its claude was ended"), "{}", shown(&stderr(&out)));
    // SAFETY: signal 0 only asks whether the pid exists.
    let alive = || unsafe { libc::kill(pid, 0) } == 0;
    let until = Instant::now() + Duration::from_secs(5);
    while alive() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(), "hh's claude was ended");
    assert!(ai_env_cli::bridge::accounts::read(&w.paths()).unwrap().unwrap().usage.contains_key("aa"));
    w.swept(&[&out], &[&a, &h]);
}

/// A run that ends with no result fails (exit 1) and records nothing; the
/// other account is still checked and recorded. `--json` gives one
/// document: each outcome, the run's lines (scrubbed), the claude and the
/// exit.
#[test]
fn a_failed_run_is_1_and_the_json_has_every_account() {
    let w = World::new(true);
    let (a, n) = (w.add("aa", "ok"), w.add("nn", "noresult"));
    let out = w.check(&["--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", shown(&stderr(&out)));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!((doc["exit"].as_i64(), doc["model"].as_str(), doc["claude"]["version"].as_str()), (Some(1), Some("haiku"), Some("2.1.305")));
    assert!(doc["claude"]["path"].as_str().is_some_and(|p| p.ends_with("/resources/native-binary/claude")), "{doc}");
    let aa = &doc["accounts"][0];
    assert_eq!((aa["name"].as_str(), aa["active"].as_bool(), aa["outcome"].as_str(), aa["status"].as_str(), aa["five_hour"]["utilization"].as_f64()), (Some("aa"), Some(true), Some("checked"), Some("allowed"), Some(0.23)));
    assert!(aa["lines"]["rate_limit_event"].as_str().is_some_and(|l| l.starts_with("{\"type\":\"rate_limit_event\"")) && aa["lines"]["result"].as_str().is_some_and(|l| l.contains("\"is_error\":false")), "{aa}");
    let nn = &doc["accounts"][1];
    assert_eq!((nn["outcome"].as_str(), nn["why"].as_str()), (Some("failed"), Some("claude exited 0 without a result")));
    assert_eq!(nn["line"].as_str(), Some("nn: check failed: claude exited 0 without a result"));
    let state = ai_env_cli::bridge::accounts::read(&w.paths()).unwrap().unwrap();
    assert!(state.usage.contains_key("aa") && !state.usage.contains_key("nn"));
    w.swept(&[&out], &[&a, &n]);
}

/// Under `[creds] deliver = "env"` the token reaches claude in its
/// environment alone (no descriptor named), and a `--model` given is the
/// one claude is asked for.
#[test]
fn env_delivery_and_the_model() {
    let w = World::new(true);
    let a = w.add("aa", "ok");
    fs::write(w.root().join("bridge").join("bridge.toml"), "[creds]\ndeliver = \"env\"\n").unwrap();
    let out = w.check(&["--model", "sonnet"]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&stderr(&out)));
    let ran = turns(&w.claude_log());
    assert_eq!(ran.len(), 1);
    assert!(ran[0].0.contains("[--model] [sonnet] [--max-turns]"), "{}", ran[0].0);
    assert_eq!((ran[0].1.as_str(), ran[0].2.as_str(), ran[0].3.as_str()), ("CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CONFIG_DIR DISABLE_AUTOUPDATER HOME PATH TZ", "env", sha8(&a).as_str()));
    w.swept(&[&out], &[&a]);
}
