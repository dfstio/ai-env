//! S13 slice M: the Mac side of the relay, through the real `ai-env` with the fake aws and age
//! (plans/s13-contracts.md §WM-worker-mac.8.4, WM-T43 to WM-T48, WM-T48a and WM-T42a). Each test gets a
//! [`World`]: one temp tree under `/tmp` (the agent's socket path stays well under 104 bytes) holding `bin/`
//! (tests/fakes/age.sh as `age`, `age-keygen` and `age-plugin-se`, tests/fakes/aws.sh as `aws`), `keys/` (a
//! keystore key with its public test recipients, as tests/infra/creds.rs makes one), `bridge/` (`bridge.toml`
//! naming the egress connector, `state/infra.toml` naming the relay instance), the fake aws's Parameter Store
//! (`ssm/`) and scripted answers (`answers/`), and the two fakes' logs. No key, token or signature is committed:
//! keys come from the runs themselves or from low-entropy seeds at run time.
use super::aws_keys::{identity_env, DEPLOYER_TAIL, OPS_TAIL};
use super::common::*;
use ai_env_worker::keys::{PublicKey, SigningKey};
use ai_env_worker::policy;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const KEY: &str = "ai-env-bridge";
/// The public SE tag recipient and X25519 recovery recipient of tests/cli.rs (public test recipients).
const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
const INSTANCE: &str = "i-0123456789abcdef0";
const VM: &str = "microvm-0199a1b2-0000-7000-8000-000000000001";
const SPAWN: &str = "0199a1b2-0000-7000-8000-000000000002";
const WORKERS: &str = "/ai-env/relay/workers";
const SIGNERS: &str = "/ai-env/relay/token-signers";
const GRANTS: &str = "/ai-env/relay/grants";
const TLS: &str = "/ai-env/relay/tls";

/// Who runs a command: what `ai-env as` would leave, or nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Who {
    Deployer,
    Ops,
    /// The marker `root` alone (the aws CLI's own chain).
    Root,
    /// The marker `ambient` alone.
    Ambient,
    Nobody,
}

/// One test's tree (see the module doc).
pub(crate) struct World {
    tmp: tempfile::TempDir,
}

fn fake(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

impl World {
    pub(crate) fn new() -> World {
        let tmp = tempfile::Builder::new().prefix("aerm").tempdir_in("/tmp").unwrap();
        let w = World { tmp };
        for dir in ["bin", "tmp", "ssm", "answers", "bridge/state"] {
            fs::create_dir_all(w.root().join(dir)).unwrap();
        }
        let install = |src: &str, name: &str| {
            let dst = w.root().join("bin").join(name);
            fs::copy(fake(src), &dst).unwrap();
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();
        };
        for name in ["age", "age-keygen", "age-plugin-se"] {
            install("age.sh", name);
        }
        install("aws.sh", "aws");
        let key = w.root().join("keys").join("keys").join(KEY);
        fs::create_dir_all(&key).unwrap();
        fs::write(key.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
        fs::write(key.join("recipients.txt"), format!("{SE_REC}\n{X_REC}\n")).unwrap();
        fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
        w.config("");
        w.infra(true);
        w
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub(crate) fn bridge(&self) -> PathBuf {
        self.root().join("bridge")
    }

    pub(crate) fn paths(&self) -> ai_env_cli::bridge::config::Paths {
        ai_env_cli::bridge::config::Paths::from_root_and_env(self.bridge(), None)
    }

    /// `bridge.toml`: the egress connector, then `extra`.
    fn config(&self, extra: &str) {
        fs::write(self.bridge().join("bridge.toml"), format!("[aws]\negress_connector_arn = \"{CONNECTOR}\"\n\n{extra}")).unwrap();
    }

    /// `state/infra.toml`, with the relay's keys when `relay`.
    fn infra(&self, relay: bool) {
        let mut text = String::from("stack = \"dev\"\nwritten = \"2026-10-29T10:00:00Z\"\nregion = \"eu-central-1\"\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\n");
        if relay {
            text.push_str(&format!("relay_instance_id = \"{INSTANCE}\"\nrelay_public_ip = \"127.0.0.1\"\nrelay_private_ip = \"10.42.0.20\"\n"));
        }
        fs::write(self.bridge().join("state").join("infra.toml"), text).unwrap();
    }

    fn age_log(&self) -> PathBuf {
        self.root().join("age.log")
    }

    fn aws_log(&self) -> PathBuf {
        self.root().join("aws.log")
    }

    /// `ai-env relay <args>` with the fakes first on PATH, run as `who`.
    fn cmd(&self, args: &[&str], who: Who) -> Command {
        let all: Vec<&str> = std::iter::once("relay").chain(args.iter().copied()).collect();
        let mut cmd = ai_env(self.root(), &all);
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.root().join("bin").display()))
            .env("TMPDIR", self.root().join("tmp"))
            .env("FAKE_AGE_LOG", self.age_log())
            .env("FAKE_AWS_LOG", self.aws_log())
            .env("FAKE_AWS_SSM_DIR", self.root().join("ssm"))
            .env("FAKE_AWS_ANSWERS", self.root().join("answers"))
            .env("FAKE_AWS_PIN_ALL", "1")
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        match who {
            Who::Deployer => {
                cmd.envs(identity_env("deployer", DEPLOYER_TAIL));
            }
            Who::Ops => {
                cmd.envs(identity_env("ops", OPS_TAIL));
            }
            Who::Root => {
                cmd.env("AI_ENV_BRIDGE_AS", "root");
            }
            Who::Ambient => {
                cmd.env("AI_ENV_BRIDGE_AS", "ambient");
            }
            Who::Nobody => {}
        }
        cmd
    }

    /// One run from clean fake logs and answer counters.
    pub(crate) fn run(&self, args: &[&str], who: Who) -> Output {
        self.reset();
        run(&mut self.cmd(args, who))
    }

    fn reset(&self) {
        let _ = fs::remove_file(self.age_log());
        let _ = fs::remove_file(self.aws_log());
        for e in fs::read_dir(self.root().join("answers")).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with(".count.") {
                fs::remove_file(e.path()).unwrap();
            }
        }
    }

    /// The aws calls of the last run, one argv per line.
    fn aws_calls(&self) -> Vec<String> {
        fs::read_to_string(self.aws_log()).unwrap_or_default().lines().map(str::to_string).collect()
    }

    /// The age calls of the last run that encrypted (`-e`) or decrypted (`-d`).
    fn age_calls(&self, mode: &str) -> usize {
        fs::read_to_string(self.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age ") && l.split_whitespace().any(|w| w == mode)).count()
    }

    /// Parameter `name` as the fake holds it: (value, version).
    pub(crate) fn param(&self, name: &str) -> Option<(String, u64)> {
        let f = self.root().join("ssm").join(name.trim_start_matches('/'));
        let value = fs::read_to_string(&f).ok()?;
        let version = fs::read_to_string(format!("{}.version", f.display())).ok()?.trim().parse().ok()?;
        Some((value, version))
    }

    /// Parameter `name` holds `value` at `version`.
    fn set_param(&self, name: &str, value: &str, version: u64) {
        let f = self.root().join("ssm").join(name.trim_start_matches('/'));
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, value).unwrap();
        fs::write(format!("{}.version", f.display()), format!("{version}\n")).unwrap();
    }

    /// Parameter `name`'s type as the fake records it (`<name>.type`, which a put naming `--type` writes).
    fn set_param_type(&self, name: &str, kind: &str) {
        let f = self.root().join("ssm").join(name.trim_start_matches('/'));
        fs::write(format!("{}.type", f.display()), format!("{kind}\n")).unwrap();
    }

    /// A scripted answer of the fake aws (`answers/<name>`), JSON or raw.
    fn answer(&self, name: &str, text: &str) {
        fs::write(self.root().join("answers").join(name), text).unwrap();
    }

    fn unanswer(&self, name: &str) {
        let _ = fs::remove_file(self.root().join("answers").join(name));
    }

    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        fs::read_to_string(self.bridge().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|r| r["event"] == event)
            .collect()
    }

    fn container(&self, name: &str) -> String {
        fs::read_to_string(self.bridge().join("credentials").join(name)).unwrap()
    }

    /// The fake age's `-d` of a container: its plaintext.
    fn open(&self, container_text: &str) -> String {
        let c = ai_env_cli::container::read(container_text).expect("a valid ai-env container");
        let identity = self.root().join("keys").join("keys").join(KEY).join("identity.txt");
        let mut child = Command::new(self.root().join("bin").join("age"))
            .args(["-d", "-i"])
            .arg(&identity)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&c.data).unwrap();
        let out = finish(child, RUN_LIMIT, "fake age -d");
        assert!(out.status.success(), "fake age -d: {}", stderr(&out));
        String::from_utf8(out.stdout).unwrap()
    }

    /// The notes of a container under `credentials/`.
    fn notes(&self, name: &str) -> BTreeMap<String, String> {
        ai_env_cli::container::meta(&self.container(name))
    }

    /// Every file under the tree holding `needle` (the fakes' logs included).
    fn holding(&self, needle: &str) -> Vec<PathBuf> {
        let (mut todo, mut out) = (vec![self.root().to_path_buf()], Vec::new());
        while let Some(dir) = todo.pop() {
            for e in fs::read_dir(&dir).into_iter().flatten().flatten() {
                match e.file_type() {
                    Ok(t) if t.is_dir() => todo.push(e.path()),
                    Ok(t) if t.is_file() && fs::read(e.path()).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes())) => out.push(e.path()),
                    _ => {}
                }
            }
        }
        out
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn key_text(seed: u8) -> String {
    SigningKey::from_seed(&[seed; 32]).unwrap().public_key().text()
}

fn key_of(seed: u8) -> PublicKey {
    SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
}

/// The longest run of base64 characters in `text`.
fn longest_b64(text: &str) -> usize {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')).map(str::len).max().unwrap_or(0)
}

/// `allow`'s default day: a year from today, UTC.
fn default_day() -> String {
    let now = ai_env_cli::wire::time::unix_now();
    ai_env_cli::wire::time::rfc3339_utc(now - now % 86_400 + 365 * 86_400)[..10].to_string()
}

/// The keys a keygen sealed, from the fake age's plaintext: (worker, session) public keys.
fn sealed_keys(w: &World) -> (PublicKey, PublicKey) {
    use base64::Engine as _;
    let plain = w.open(&w.container("relay-worker.env"));
    let lines: Vec<&str> = plain.lines().collect();
    assert_eq!(lines.len(), 2, "exactly the two variables");
    let key = |line: &str, var: &str| {
        let b64 = line.strip_prefix(var).and_then(|l| l.strip_prefix('=')).unwrap_or_else(|| panic!("{var} first: not {var}"));
        let der = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        SigningKey::from_pkcs8_der(&der).unwrap().public_key()
    };
    assert!(plain.ends_with('\n'));
    (key(lines[0], "AI_ENV_RELAY_WORKER_KEY"), key(lines[1], "AI_ENV_RELAY_SESSION_KEY"))
}

/// WM-T43: `relay keygen` seals both keys with no Touch ID and prints only the public ones.
#[test]
fn relay_keygen_seals_both_keys_and_prints_only_public_ones() {
    let w = World::new();
    let o = w.run(&["keygen"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let notes = w.notes("relay-worker.env");
    assert_eq!((notes.get("kind").map(String::as_str), notes.get("worker_id").map(String::as_str)), (Some("relay-keys"), Some("mac")), "{notes:?}");
    let (worker, session) = sealed_keys(&w);
    assert_eq!((notes["worker_key"].as_str(), notes["session_key"].as_str()), (worker.text().as_str(), session.text().as_str()), "each key matches its note");
    let out = stdout(&o);
    assert!(out.contains(&format!("worker  mac  {}  fp {}", worker.text(), worker.fingerprint())), "{out}");
    assert!(out.contains(&format!("session mac  {}  fp {}", session.text(), session.fingerprint())), "{out}");
    assert!(out.contains(&format!("ai-env as deployer -- ai-env relay allow mac --token-signer --key {}", session.text())), "{out}");
    assert!(out.contains(&format!("ai-env as deployer -- ai-env relay allow mac --key {} --sources '<glob>'", worker.text())), "{out}");
    assert!(longest_b64(&out) <= 44 && longest_b64(&stderr(&o)) <= 44, "no base64 of more than 44 characters: {out}");
    assert_eq!((w.age_calls("-e"), w.age_calls("-d")), (1, 0), "one encrypt, no decrypt (no Touch ID)");
    assert!(w.aws_calls().is_empty(), "no AWS call");
    // A second keygen names --force; --force keeps a .bak and makes new keys.
    let o = w.run(&["keygen"], Who::Nobody);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("already holds this Mac's relay keys (worker mac, worker key fp {}, session key fp {}): ai-env relay keygen --force replaces them", worker.fingerprint(), session.fingerprint())), "{}", stderr(&o));
    let o = w.run(&["keygen", "--force"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let baks: Vec<String> = fs::read_dir(w.bridge().join("credentials")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with("relay-worker.env.") && n.ends_with(".bak")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    let (worker2, session2) = sealed_keys(&w);
    assert!(worker2 != worker && session2 != session, "new keys");
    let rows = w.audit("relay_keygen");
    assert_eq!(rows.len(), 2, "one row per success: {rows:?}");
    assert_eq!((rows[0]["detail"]["worker_fp"].as_str(), rows[0]["detail"]["session_fp"].as_str()), (Some(worker.fingerprint().as_str()), Some(session.fingerprint().as_str())));
    assert_eq!(rows[1]["detail"]["replaced"].as_str(), Some("true"));
    assert!(!rows.iter().any(|r| r.to_string().contains(&worker.b64())), "fingerprints only: {rows:?}");
}

/// WM-T44: `relay pubkey` reads the notes with no Touch ID; `--verify` unseals once and checks them; a file that
/// is no container is exit 5.
#[test]
fn relay_pubkey_reads_notes_without_touch_id() {
    let w = World::new();
    let o = w.run(&["pubkey"], Who::Nobody);
    assert_eq!(code(&o), 5, "no container: {}", stderr(&o));
    assert!(stderr(&o).contains("ai-env relay keygen"), "{}", stderr(&o));
    assert_eq!(code(&w.run(&["keygen"], Who::Nobody)), 0);
    let (worker, session) = sealed_keys(&w);
    let o = w.run(&["pubkey"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("worker  mac  {}  fp {}\nsession mac  {}  fp {}\n", worker.text(), worker.fingerprint(), session.text(), session.fingerprint()));
    assert_eq!(w.age_calls("-d"), 0, "no Touch ID");
    let o = w.run(&["pubkey", "--worker"], Who::Nobody);
    assert_eq!(stdout(&o), format!("{}\n", worker.text()));
    let o = w.run(&["pubkey", "--session"], Who::Nobody);
    assert_eq!(stdout(&o), format!("{}\n", session.text()));
    assert_eq!(w.age_calls("-d"), 0);
    let o = w.run(&["pubkey", "--verify"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one unseal");
    assert!(stderr(&o).contains("the sealed keys match their notes"), "{}", stderr(&o));
    // Notes naming another session key (rewritten here): --verify is exit 9.
    let path = w.bridge().join("credentials").join("relay-worker.env");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replace(&session.text(), &key_text(9))).unwrap();
    let o = w.run(&["pubkey"], Who::Nobody);
    assert!(stdout(&o).contains(&key_text(9)), "pubkey shows the notes as recorded");
    let o = w.run(&["pubkey", "--verify"], Who::Nobody);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("the notes of credentials/relay-worker.env do not match its sealed keys: re-seal it with ai-env relay keygen --force"), "{}", stderr(&o));
    // A file that is no container: exit 5 with its phrase (WM-R37), no Touch ID.
    fs::write(&path, "not a container\n").unwrap();
    let o = w.run(&["pubkey"], Who::Nobody);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay-worker.env is not an ai-env container (plaintext?): move it away, then ai-env relay keygen"), "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 0);
}

/// WM-T45: the lists are written by the deployer only, created at their first write, never overwritten when
/// they do not parse or moved meanwhile, within their limits.
#[test]
fn relay_lists_are_written_by_the_deployer_only() {
    let w = World::new();
    let (k1, k7) = (key_text(1), key_text(7));
    // No marker, or an ops marker: every writer is exit 9 before any unseal or AWS call (WM-R41), naming the
    // command as given (a glob single-quoted).
    let writers: Vec<(Vec<&str>, String)> = vec![
        (vec!["allow", "worker-a", "--key", k1.as_str(), "--sources", "example-*"], format!("allow worker-a --key {k1} --sources 'example-*'")),
        (vec!["revoke", "worker-a"], "revoke worker-a".to_string()),
        (vec!["revoke", "mac", "--token-signer"], "revoke mac --token-signer".to_string()),
        (vec!["grant", "default", "example-*/get"], "grant default 'example-*/get'".to_string()),
        (vec!["grant", "default", "--remove"], "grant default --remove".to_string()),
    ];
    for who in [Who::Nobody, Who::Ops] {
        for (args, given) in &writers {
            let o = w.run(args, who);
            assert_eq!(code(&o), 9, "{who:?} {args:?}: {}", stderr(&o));
            let cmd = args[0];
            assert!(
                stderr(&o).contains(&format!(
                    "relay {cmd}: the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them: run ai-env as deployer -- ai-env relay {given}"
                )),
                "{who:?} {args:?}: {}",
                stderr(&o)
            );
            assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0, "{who:?} {args:?}: {:?}", w.aws_calls());
        }
    }
    // The first allow creates the list: --type String --tier Standard, no --overwrite, version 1.
    let o = w.run(&["allow", "worker-a", "--key", &k1, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let put: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert_eq!(put.len(), 1, "{put:?}");
    assert!(put[0].contains(&format!("--name {WORKERS} ")) && put[0].contains(" --type String ") && put[0].contains(" --tier Standard ") && !put[0].contains("--overwrite"), "{}", put[0]);
    let entry = |id: &str, seed: u8, globs: &[&str]| policy::WorkerEntry { worker_id: id.into(), alg: "ed25519".into(), public_key: key_of(seed).b64(), sources: globs.iter().map(|g| (*g).to_string()).collect(), not_after: format!("{}T23:59:59Z", default_day()), tls_fp: None };
    assert_eq!(w.param(WORKERS), Some((policy::render_workers(&[entry("worker-a", 1, &["example-*"])]).unwrap(), 1)));
    assert!(stdout(&o).contains(&format!("allowed worker worker-a (key fp {}) for sources example-* until {} ({WORKERS} v1, 1 worker(s)); the relay applies it within 60 s", key_of(1).fingerprint(), default_day())), "{}", stdout(&o));
    // Created meanwhile by another writer: exit 7, run it again.
    w.answer("ssm.put-parameter.rc", "254");
    w.answer("ssm.put-parameter.stderr", "\nAn error occurred (ParameterAlreadyExists) when calling the PutParameter operation: The parameter already exists.\n");
    let o = w.run(&["grant", "default", "example-*/get"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay grant: {GRANTS} was created meanwhile (another writer): run the command again")), "{}", stderr(&o));
    w.unanswer("ssm.put-parameter.rc");
    w.unanswer("ssm.put-parameter.stderr");
    // A revoke of a missing list writes nothing (B-4), and nor does `grant --remove` (WM-R45).
    let o = w.run(&["revoke", "mac", "--token-signer"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("mac is not listed in {SIGNERS}; nothing written")), "{}", stdout(&o));
    assert!(!w.aws_calls().iter().any(|l| l.starts_with("ssm put-parameter")));
    let o = w.run(&["grant", "default", "--remove"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("grant default is not in {GRANTS}; nothing written")), "{}", stdout(&o));
    assert!(!w.aws_calls().iter().any(|l| l.starts_with("ssm put-parameter")) && w.param(GRANTS).is_none());
    // The three lists at `[]`, version 1.
    for name in [WORKERS, SIGNERS, GRANTS] {
        w.set_param(name, "[]", 1);
    }
    let o = w.run(&["allow", "worker-a", "--key", &k1, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.param(WORKERS), Some((policy::render_workers(&[entry("worker-a", 1, &["example-*"])]).unwrap(), 2)), "exactly the rendered list at v2");
    assert!(stdout(&o).contains(&format!("({WORKERS} v2, 1 worker(s))")), "{}", stdout(&o));
    let o = w.run(&["allow", "mac", "--token-signer", "--key", &k7], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let signer = policy::SignerEntry { signer_id: "mac".into(), alg: "ed25519".into(), public_key: key_of(7).b64(), not_after: format!("{}T23:59:59Z", default_day()) };
    assert_eq!(w.param(SIGNERS), Some((policy::render_signers(&[signer]).unwrap(), 2)));
    let o = w.run(&["allow", "mac", "--token-signer", "--key", &k7], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).ends_with("; nothing written\n") && !w.aws_calls().iter().any(|l| l.starts_with("ssm put-parameter")), "{}", stdout(&o));
    // One key, one role (Q-WM18), one key, one id: exit 9, nothing written.
    let o = w.run(&["allow", "worker-b", "--key", &k7, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: the key fp {} is already allowed as token signer mac: one key, one role", key_of(7).fingerprint())), "{}", stderr(&o));
    let o = w.run(&["allow", "worker-b", "--key", &k1, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: the key fp {} is already allowed as worker-a: one key, one id", key_of(1).fingerprint())), "{}", stderr(&o));
    assert_eq!(w.param(WORKERS).unwrap().1, 2, "nothing written");
    // Grants: sorted rules.
    let o = w.run(&["grant", "default", "example-*/list", "example-*/get", "example-*/list"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let grant = policy::Grant { grant_id: "default".into(), allow: vec!["example-*/get".into(), "example-*/list".into()] };
    assert_eq!(w.param(GRANTS), Some((policy::render_grants(&[grant]).unwrap(), 2)));
    assert!(stdout(&o).contains(&format!("grant default: 2 rule(s) ({GRANTS} v2)")), "{}", stdout(&o));
    let o = w.run(&["revoke", "worker-a"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.param(WORKERS), Some(("[]".to_string(), 3)), "revoke writes []");
    assert!(stdout(&o).contains(&format!("revoked worker worker-a ({WORKERS} v3): the relay closes its tunnel within 60 s")), "{}", stdout(&o));
    // WM-J3's half in this slice: what M wrote parses back, with the shared `policy` the relay's loader wraps
    // (`ai_env_relay::lists::parse_*`), into the entries it was given.
    assert_eq!(policy::parse_workers(&w.param(WORKERS).unwrap().0).unwrap(), Vec::<policy::WorkerEntry>::new());
    let signer = policy::SignerEntry { signer_id: "mac".into(), alg: "ed25519".into(), public_key: key_of(7).b64(), not_after: format!("{}T23:59:59Z", default_day()) };
    assert_eq!(policy::parse_signers(&w.param(SIGNERS).unwrap().0).unwrap(), [signer]);
    let grant = policy::Grant { grant_id: "default".into(), allow: vec!["example-*/get".into(), "example-*/list".into()] };
    assert_eq!(policy::parse_grants(&w.param(GRANTS).unwrap().0).unwrap(), [grant]);
    let outcomes = |event: &str| w.audit(event).iter().map(|r| r["detail"]["outcome"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>();
    assert_eq!(outcomes("relay_allow"), ["added", "added", "added", "unchanged"]);
    assert_eq!(outcomes("relay_grant"), ["absent", "set"]);
    assert_eq!(outcomes("relay_revoke"), ["absent", "revoked"]);
    assert!(!fs::read_to_string(w.bridge().join("audit.jsonl")).unwrap().contains("example-*"), "no glob or rule in the audit (counts)");
    // A token signer's revoke line (WM-R44), a set grant's `--remove` (WM-R45), the note of `--sources '*'` (WM-R43).
    let o = w.run(&["revoke", "mac", "--token-signer"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.param(SIGNERS), Some(("[]".to_string(), 3)));
    assert!(stdout(&o).contains(&format!("revoked token signer mac ({SIGNERS} v3): the relay refuses its tokens within 60 s")), "{}", stdout(&o));
    let o = w.run(&["grant", "default", "--remove"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.param(GRANTS), Some(("[]".to_string(), 3)));
    assert!(stdout(&o).contains(&format!("removed grant default ({GRANTS} v3): tokens naming it are refused within 60 s")), "{}", stdout(&o));
    let o = w.run(&["allow", "worker-d", "--key", &key_text(4), "--sources", "*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(" for sources * until ") && stdout(&o).ends_with("\nthis worker may register any source name\n"), "{}", stdout(&o));
    assert_eq!(outcomes("relay_grant"), ["absent", "set", "removed"]);
    // A list that does not parse is never overwritten (exit 1).
    w.set_param(GRANTS, "[{\"grant_id\":\"A\"}]", 5);
    let o = w.run(&["grant", "other", "a/b"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay grant: {GRANTS} does not parse (")) && stderr(&o).contains("nothing was written: correct it first (aws ssm put-parameter)"), "{}", stderr(&o));
    assert_eq!(w.param(GRANTS).unwrap(), ("[{\"grant_id\":\"A\"}]".to_string(), 5));
    // A put that jumps a version: exit 7 naming both.
    w.set_param(WORKERS, "[]", 2);
    w.answer("ssm.put-parameter.json", "{\"Version\": 4, \"Tier\": \"Standard\"}\n");
    let o = w.run(&["allow", "worker-c", "--key", &key_text(3), "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: {WORKERS} moved from v2 to v4 while it was written (another writer): run the command again to see what it holds")), "{}", stderr(&o));
    w.unanswer("ssm.put-parameter.json");
    // Over its limits: refused before any write (bytes: workers; entries: grants).
    let mut list = Vec::new();
    for n in 0..70u8 {
        let mut next = list.clone();
        next.push(entry(&format!("w{n:02}"), 100 + n, &["example-*"]));
        if policy::render_workers(&next).is_err() {
            break;
        }
        list = next;
    }
    assert!(list.len() < 70, "the bytes limit comes first");
    w.set_param(WORKERS, &policy::render_workers(&list).unwrap(), 7);
    let o = w.run(&["allow", "w70", "--key", &key_text(250), "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: {WORKERS} would be ")) && stderr(&o).contains("bytes, over its limit of 4096; nothing was written"), "{}", stderr(&o));
    assert!(!w.aws_calls().iter().any(|l| l.starts_with("ssm put-parameter")), "refused before writing");
    let grants: Vec<policy::Grant> = (0..64).map(|n| policy::Grant { grant_id: format!("g{n:02}"), allow: vec!["a/b".into()] }).collect();
    w.set_param(GRANTS, &policy::render_grants(&grants).unwrap(), 9);
    let o = w.run(&["grant", "g64", "a/b"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay grant: {GRANTS} would be 65 entries, over its limit of 64; nothing was written")), "{}", stderr(&o));
    // Usage errors (exit 2) come before the gate.
    for (args, why) in [
        (vec!["allow", "A", "--key", k1.as_str(), "--sources", "x"], "is not an id"),
        (vec!["allow", "w", "--key", "ed25519:short", "--sources", "x"], "--key is not a public key's text"),
        (vec!["allow", "w", "--key", k1.as_str(), "--sources", "a b"], "is not a glob"),
        (vec!["allow", "w", "--key", k1.as_str(), "--sources", "x", "--not-after", "2020-01-01"], "is before today"),
        (vec!["grant", "g", "nope"], "is not a rule"),
    ] {
        let o = w.run(&args, Who::Nobody);
        assert_eq!(code(&o), 2, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{args:?}: {}", stderr(&o));
    }
}

/// The `describe-instances` answer with the relay in `state`.
fn instance_doc(state: &str) -> String {
    let code = match state {
        "pending" => 0,
        "running" => 16,
        "stopping" => 64,
        _ => 80,
    };
    serde_json::json!({"Reservations": [{"Instances": [{"InstanceId": INSTANCE, "State": {"Code": code, "Name": state}, "PrivateIpAddress": "10.42.0.20", "PublicIpAddress": "127.0.0.1"}]}]}).to_string()
}

fn ping_doc(ping: Option<&str>) -> String {
    let list: Vec<serde_json::Value> = ping.map(|p| serde_json::json!({"InstanceId": INSTANCE, "PingStatus": p})).into_iter().collect();
    serde_json::json!({"InstanceInformationList": list}).to_string()
}

/// WM-T46: `relay start`, `stop` and `status` are ops commands.
#[test]
fn relay_start_stop_and_status_are_ops_commands() {
    let w = World::new();
    // start: pending, then running; then SSM Online.
    w.answer("ec2.start-instances.json", &serde_json::json!({"StartingInstances": [{"InstanceId": INSTANCE, "CurrentState": {"Code": 0, "Name": "pending"}}]}).to_string());
    w.answer("ec2.describe-instances.1.json", &instance_doc("pending"));
    w.answer("ec2.describe-instances.json", &instance_doc("running"));
    w.answer("ssm.describe-instance-information.1.json", &ping_doc(None));
    w.answer("ssm.describe-instance-information.json", &ping_doc(Some("Online")));
    let o = w.run(&["start"], Who::Ops);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).starts_with(&format!("relay {INSTANCE} running, SSM online (")), "{}", stdout(&o));
    let ops: Vec<String> = w.aws_calls().iter().map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect();
    assert!(ops.iter().filter(|o| *o == "ec2 describe-instances").count() >= 2 && ops.iter().filter(|o| *o == "ssm describe-instance-information").count() >= 2, "{ops:?}");
    assert_eq!(w.audit("relay_start")[0]["detail"]["outcome"].as_str(), Some("running"));
    // stop: to stopped.
    w.answer("ec2.stop-instances.json", &serde_json::json!({"StoppingInstances": [{"InstanceId": INSTANCE, "CurrentState": {"Code": 64, "Name": "stopping"}}]}).to_string());
    w.answer("ec2.describe-instances.1.json", &instance_doc("stopping"));
    w.answer("ec2.describe-instances.json", &instance_doc("stopped"));
    let o = w.run(&["stop"], Who::Ops);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("relay {INSTANCE} stopped (")) && stdout(&o).contains("workers keep dialing until ai-env relay start"), "{}", stdout(&o));
    assert_eq!(w.audit("relay_stop")[0]["detail"]["outcome"].as_str(), Some("stopped"));
    w.unanswer("ec2.describe-instances.1.json");
    w.unanswer("ssm.describe-instance-information.1.json");
    // A start that never reaches running: exit 7 naming the state last seen (WM-R48), audited as a timeout.
    w.answer("ec2.describe-instances.json", &instance_doc("pending"));
    let o = w.run(&["start"], Who::Ops);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay start: relay {INSTANCE} is not running within 180 s (last seen: pending)")), "{}", stderr(&o));
    assert_eq!(w.audit("relay_start").last().map(|r| r["detail"]["outcome"].clone()), Some(serde_json::json!("timeout")));
    // status: this Mac's session key is not a token signer yet: exit 1; once it is, 0.
    assert_eq!(code(&w.run(&["keygen"], Who::Nobody)), 0);
    let (_, session) = sealed_keys(&w);
    w.answer("ec2.describe-instances.json", &instance_doc("running"));
    let line = serde_json::json!({"ts": "2026-10-29T10:00:00.000Z", "ev": "status", "relay_version": "0.12.0", "protocol": 1, "uptime_s": 600, "tunnels": 2, "sources_live": 3, "sources_offline": 0, "calls_in_flight": 0, "sessions": 1, "workers_version": "0123456789abcdef", "workers_age_s": 30, "signers_version": "1123456789abcdef", "signers_age_s": 31, "grants_version": "2123456789abcdef", "grants_age_s": 32, "tls_loaded": true, "unknown_frames": 0, "log_dropped": 0});
    w.answer("logs.filter-log-events.json", &serde_json::json!({"events": [{"logStreamName": format!("{INSTANCE}/requests"), "timestamp": 1_793_268_000_000u64, "message": line.to_string(), "ingestionTime": 1_793_268_000_100u64, "eventId": "1"}]}).to_string());
    for name in [WORKERS, SIGNERS, GRANTS] {
        w.set_param(name, "[]", 1);
    }
    w.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "office", IN_FORCE)]), 1);
    let o = w.run(&["status"], Who::Ops);
    assert_eq!(code(&o), 1, "not a token signer yet: {}{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    for want in [
        format!("[ok ] instance {INSTANCE}: running (private 10.42.0.20, public 127.0.0.1)"),
        "[ok ] ssm: Online".to_string(),
        format!("[ok ] {WORKERS} v1: 0 worker(s)"),
        format!("[ok ] {SIGNERS} v1: 0 token signer(s)"),
        format!("[ok ] {GRANTS} v1: 0 grant(s)"),
        format!("[ok ] {PEERS} v1: 1 peer(s), 1 in force"),
        format!("[NO ] this Mac's session key (fp {}) is not an in-force token signer as mac", session.fingerprint()),
        "[ok ] relay 0.12.0: 2 tunnel(s), 3 source(s) live; workers 0123456789abcdef (30 s old), token-signers 1123456789abcdef (31 s old), grants 2123456789abcdef (32 s old)".to_string(),
        "[ok ] keys: sealed in credentials/relay-worker.env for worker mac".to_string(),
        "[-  ] agent: not running".to_string(),
    ] {
        assert!(out.contains(&want), "{want}\n{out}");
    }
    assert!(out.contains("[warn] probe: 127.0.0.1:443") || out.contains("[ok ] probe: 127.0.0.1:443"), "{out}");
    // The [NO ] row names the command that allows the session key, its text included; --json carries the rows as
    // printed, so that row's command is the one place its JSON holds a key's text (this Mac's keys and the lists'
    // as fingerprints).
    let no_row = format!("this Mac's session key (fp {}) is not an in-force token signer as mac: ai-env as deployer -- ai-env relay allow mac --token-signer --key {}", session.fingerprint(), session.text());
    assert!(out.contains(&format!("[NO ] {no_row}\n")), "{out}");
    let o = w.run(&["status", "--json"], Who::Ops);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(doc["status"]["verdict"].as_str(), Some("findings"), "{doc}");
    assert!(doc["status"]["rows"].as_array().is_some_and(|rows| rows.contains(&serde_json::json!({"mark": "no", "text": no_row}))), "the row as printed: {doc}");
    assert_eq!(stdout(&o).matches(&session.b64()).count(), 1, "the session key's text in that row alone: {doc}");
    assert_eq!(doc["mac"]["session_fp"].as_str(), Some(session.fingerprint().as_str()));
    let o = w.run(&["allow", "mac", "--token-signer", "--key", &session.text()], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.run(&["status"], Who::Ops);
    assert_eq!(code(&o), 0, "a token signer now: {}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains(&format!("[ok ] this Mac's session key (fp {}) is an in-force token signer as mac", session.fingerprint())), "{}", stdout(&o));
    assert!(stdout(&o).contains("  token signer mac (key fp "), "{}", stdout(&o));
    assert_eq!(w.age_calls("-d"), 0, "status unseals nothing under ai-env as ops");
    let o = w.run(&["status", "--json"], Who::Ops);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    for key in SEVEN_KEYS {
        assert!(doc.get(key).is_some(), "{key}: {doc}");
    }
    assert_eq!(doc.as_object().map(serde_json::Map::len), Some(7), "the seven keys alone: {doc}");
    assert_eq!(doc["peers"], serde_json::json!([{"label": "office", "cidr": "198.51.100.0/24", "not_after": IN_FORCE, "expired": false}]), "{doc}");
    assert_eq!(doc["instance"]["status_line"]["relay_version"].as_str(), Some("0.12.0"), "the relay's status line rides in instance: {doc}");
    assert_eq!(doc["mac"]["session_fp"].as_str(), Some(session.fingerprint().as_str()));
    assert!(!stdout(&o).contains(&session.b64()), "fingerprints, never a key, in --json");
    let o = w.run(&["status", "--local", "--json"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(doc.as_object().map(serde_json::Map::len) == Some(7) && doc["instance"].is_null() && doc["grants"].is_null() && doc["peers"].is_null() && doc["mac"]["session_fp"].is_string(), "{doc}");
    // No status line in 10 minutes: a warning.
    w.answer("logs.filter-log-events.json", "{\"events\": []}");
    let o = w.run(&["status"], Who::Ops);
    assert!(stdout(&o).contains("[warn] relay: no status line in 10 min"), "{}", stdout(&o));
    // --local: no aws call, no unseal.
    let o = w.run(&["status", "--local"], Who::Nobody);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0, "{:?}", w.aws_calls());
    assert!(stdout(&o).contains("[ok ] keys: sealed in credentials/relay-worker.env for worker mac"), "{}", stdout(&o));
    // No relay_instance_id: exit 1 naming the hint, start, stop and status alike.
    w.infra(false);
    for cmd in ["start", "stop", "status"] {
        let o = w.run(&[cmd], Who::Ops);
        assert_eq!(code(&o), 1, "{cmd}: {}", stderr(&o));
        assert!(stderr(&o).contains("state/infra.toml has no relay_instance_id: run make infra-status WRITE=1 after deploying the relay"), "{cmd}: {}", stderr(&o));
    }
    // status shows this Mac's rows before that error (WM-R47); --json prints no partial object.
    let o = w.run(&["status"], Who::Ops);
    assert!(stdout(&o).contains("[ok ] keys: sealed in credentials/relay-worker.env for worker mac") && stdout(&o).contains("[-  ] agent: not running"), "{}", stdout(&o));
    let o = w.run(&["status", "--json"], Who::Ops);
    assert_eq!((code(&o), stdout(&o)), (1, String::new()), "{}", stderr(&o));
}

/// Wait for `cond`, polling, at most `within`.
fn wait_for(what: &str, within: Duration, mut cond: impl FnMut() -> bool) {
    let t = Instant::now();
    while !cond() {
        assert!(t.elapsed() < within, "{what}: not within {within:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// WM-T47: `relay agent` unseals once (one Touch ID), then answers a worker's `AgentSigner` and the wrapper's
/// mint; SIGTERM ends it cleanly; a second agent meanwhile names the first; keys sealed for another worker id
/// are refused before any Touch ID.
#[test]
fn relay_agent_answers_a_worker_and_the_wrapper_with_one_touch_id() {
    use ai_env_cli::bridge::vm::registry::{write_row, RowStatus, VmRow, GATE_PASSED};
    use ai_env_worker::agent::{request, MintRequest, Request, Response};
    use ai_env_worker::signer::Signer as _;
    let w = World::new();
    w.config("[relay]\ngrant = \"default\"\n");
    assert_eq!(code(&w.run(&["keygen"], Who::Nobody)), 0);
    let (worker, session) = sealed_keys(&w);
    let now = ai_env_cli::wire::time::unix_now();
    let row = VmRow { id: VM.into(), status: RowStatus::Running, egress: "vpc".into(), egress_gate: Some(GATE_PASSED.into()), wall_deadline: Some(now + 36_000), client_token: "0199a1b2-0000-7000-8000-0000000000a1".into(), ..VmRow::default() };
    write_row(&w.paths(), &row).unwrap();
    w.reset();
    let agent = w.cmd(&["agent", "--hours", "1"], Who::Nobody).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = agent.id();
    let socket = w.paths().relay_agent_socket();
    wait_for("the agent's socket", Duration::from_secs(20), || socket.exists());
    assert!(socket.as_os_str().len() < 104);
    // The socket appears at its bind, under the agent's 077 umask; the chmod to 0600 follows it.
    wait_for("the agent's socket at 0600", Duration::from_secs(20), || fs::metadata(&socket).is_ok_and(|m| m.permissions().mode() & 0o777 == 0o600));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // A worker on this Mac signs through the agent; the signature verifies with the sealed worker key.
    let signer = rt.block_on(ai_env_worker::signer::AgentSigner::connect(Some(socket.clone()))).unwrap();
    assert_eq!((signer.public_key(), signer.bound_worker_id()), (worker, Some("mac")));
    let challenge = ai_env_worker::signer::AuthChallenge { relay_id: "ai-env-relay".into(), nonce: vec![5; 32], worker_id: "mac".into(), protocol: 1 };
    let sig = rt.block_on(signer.sign_worker_auth(&challenge)).unwrap();
    let transcript = ai_env_worker::ai_env_source::wire::transcript("ai-env-relay", &[5; 32], "mac", 1, worker.bytes(), 1);
    assert!(worker.verify(&transcript, &sig), "the sealed worker key's signature");
    // The wrapper's mint: a token the relay's verify takes with the sealed session key.
    let mint = Request::MintSession(MintRequest { vm_id: VM.into(), session_id: SPAWN.into(), chat_id: None, grant_id: "default".into(), exp: now + 3600 });
    let Response::Minted { token, exp } = rt.block_on(request(&socket, &mint, Duration::from_secs(2))).unwrap() else { panic!("no token") };
    assert_eq!(exp, now + 3600);
    let lookup = |kid: &str| (kid == "mac").then_some(ai_env_worker::session::SignerKey { public_key: session, not_after: now + 86_400 });
    let claims = ai_env_worker::session::verify(&token, now, &lookup).unwrap().claims;
    assert_eq!((claims.vm_id.as_str(), claims.session_id.as_str(), claims.grant_id.as_str()), (VM, SPAWN, "default"));
    assert!(w.holding(&token).is_empty(), "the token is in no file: {:?}", w.holding(&token));
    // A second agent meanwhile: exit 1 naming the first's pid.
    let o = run(&mut w.cmd(&["agent"], Who::Nobody));
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("another relay agent runs (pid {pid}, until ")), "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one Touch ID: the first agent's");
    // SIGTERM: exit 0, the socket gone, `started` then `stopped`.
    // SAFETY: kill(2) of our own child, which has not been waited for.
    assert_eq!(unsafe { libc::kill(i32::try_from(pid).unwrap(), libc::SIGTERM) }, 0);
    let out = finish(agent, RUN_LIMIT, "ai-env relay agent");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!socket.exists(), "the socket is gone");
    let err = stderr(&out);
    assert!(err.contains(&format!("relay agent: worker mac (fp {}), session key fp {}; socket {}; until ", worker.fingerprint(), session.fingerprint(), socket.display())), "{err}");
    assert!(err.contains("relay agent: stopped (1 signed, 1 minted)"), "{err}");
    let rows = w.audit("relay_agent");
    let outcomes: Vec<&str> = rows.iter().map(|r| r["detail"]["outcome"].as_str().unwrap_or_default()).collect();
    assert_eq!(outcomes, ["started", "stopped"], "{rows:?}");
    assert_eq!((rows[1]["detail"]["signed"].as_str(), rows[1]["detail"]["minted"].as_str()), (Some("1"), Some("1")));
    // Keys sealed for another worker than [relay].worker_id: exit 1 naming both, before any Touch ID (WM-R38).
    w.config("[relay]\nworker_id = \"mac-b\"\ngrant = \"default\"\n");
    let o = w.run(&["agent"], Who::Nobody);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("credentials/relay-worker.env was sealed for worker mac, but [relay].worker_id is mac-b"), "{}", stderr(&o));
    assert!(w.age_calls("-d") == 0 && !socket.exists(), "no Touch ID, no socket");
}

/// The PEM blocks of `text`, as (label, base64 body).
fn pem_blocks(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            let body: String = lines.by_ref().take_while(|l| !l.starts_with("-----END ")).collect();
            out.push((label.to_string(), body));
        }
    }
    out
}

/// WM-T48 (B-1): `relay tls init` seals the CA's key, writes its certificate to `state/`, and writes the leaf, the
/// CA and the leaf's key as one SecureString; `rotate` unseals once and writes a new leaf under the same CA, and
/// refuses a CA certificate the sealed key does not match; both refuse no marker and an ops, a root or an ambient
/// marker before any aws call (§Q.8 F5 for root and ambient), and never give a `tls` of another type the key;
/// `relay ca` prints the CA's certificate; an `init` whose write fails leaves the CA, under which `rotate` writes
/// the value.
#[test]
fn relay_tls_init_seals_the_ca_and_writes_one_securestring() {
    use base64::Engine as _;
    let w = World::new();
    let o = w.run(&["ca"], Who::Nobody);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(stderr(&o).contains("ai-env relay tls init"), "{}", stderr(&o));
    // Under an ops marker (or none): init and rotate are exit 9, with no aws call and no unseal (WM-R41); under a
    // root or ambient marker too, whose aws child would read the user's own aws config (§Q.8 F5).
    for who in [Who::Ops, Who::Nobody, Who::Root, Who::Ambient] {
        let why = match who {
            Who::Root | Who::Ambient => "under ai-env as root or ambient the aws CLI reads your own aws config, whose cli_history would record the relay's private key",
            _ => "the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them",
        };
        for args in [["tls", "init"], ["tls", "rotate"]] {
            let o = w.run(&args, who);
            assert_eq!(code(&o), 9, "{who:?} {args:?}: {}", stderr(&o));
            assert!(stderr(&o).contains(&format!("relay {0}: {why}: run ai-env as deployer -- ai-env relay {0}", args.join(" "))), "{}", stderr(&o));
            assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0 && w.age_calls("-e") == 0, "{who:?} {args:?}");
        }
    }
    let o = w.run(&["tls", "init"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let puts: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert!(puts[0].contains(&format!("--name {TLS} ")) && puts[0].contains(" --type SecureString --key-id alias/aws/ssm ") && puts[0].contains(" --tier Standard ") && !puts[0].contains("--overwrite"), "{}", puts[0]);
    let (value, version) = w.param(TLS).unwrap();
    assert_eq!(version, 1);
    assert!(value.len() <= 4096, "{} bytes", value.len());
    let blocks = pem_blocks(&value);
    assert_eq!(blocks.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(), ["CERTIFICATE", "CERTIFICATE", "PRIVATE KEY"], "two certificates, then one key");
    let pem = fs::read_to_string(w.bridge().join("state").join("relay-ca.pem")).unwrap();
    let der = fs::read(w.bridge().join("state").join("relay-ca.der")).unwrap();
    assert_eq!(pem_blocks(&pem), [("CERTIFICATE".to_string(), base64::engine::general_purpose::STANDARD.encode(&der))], "the PEM and the DER are one certificate");
    assert_eq!(blocks[1].1, pem_blocks(&pem)[0].1, "the chain's second certificate is the CA's");
    let notes = w.notes("relay-ca.env");
    let ca_fp: String = {
        use sha2::Digest as _;
        sha2::Sha256::digest(&der)[..8].iter().map(|b| format!("{b:02x}")).collect()
    };
    assert_eq!((notes.get("kind").map(String::as_str), notes.get("ca_fp").map(String::as_str)), (Some("relay-ca"), Some(ca_fp.as_str())), "{notes:?}");
    // The CA's key exists only sealed: its plaintext's base64 is in no file, nor on stdout.
    let plain = w.open(&w.container("relay-ca.env"));
    let ca_key = plain.strip_prefix("AI_ENV_RELAY_CA_KEY=").and_then(|p| p.strip_suffix('\n')).expect("exactly the CA key's variable");
    assert!(w.holding(ca_key).is_empty(), "{:?}", w.holding(ca_key));
    let out = stdout(&o);
    assert!(!out.contains("PRIVATE KEY") && longest_b64(&out) <= 44 && !out.contains(&blocks[2].1[..40]), "{out}");
    assert!(out.contains(&format!("relay CA fp {ca_fp}")) && out.contains(&format!("in {TLS} v1")), "{out}");
    // A second init names --force.
    let o = w.run(&["tls", "init"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("ai-env relay tls init --force"), "{}", stderr(&o));
    // rotate: one unseal, --overwrite, the CA unchanged, the leaf new.
    let o = w.run(&["tls", "rotate"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one Touch ID");
    let puts: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert!(puts.len() == 1 && puts[0].contains("--overwrite"), "{puts:?}");
    let (rotated, version) = w.param(TLS).unwrap();
    assert_eq!(version, 2);
    let after = pem_blocks(&rotated);
    assert_eq!(after[1], blocks[1], "the CA unchanged");
    assert!(after[0] != blocks[0] && after[2] != blocks[2], "a new leaf and key");
    // A CA certificate that is not the sealed key's: rotate is exit 9 naming init --force, and writes nothing.
    let stranger = ai_env_worker::certs::relay_ca(ai_env_cli::wire::time::unix_now()).unwrap();
    fs::write(w.bridge().join("state").join("relay-ca.der"), &stranger.cert_der).unwrap();
    let o = w.run(&["tls", "rotate"], Who::Deployer);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay tls rotate: credentials/relay-ca.env does not hold the key of state/relay-ca.der: make a new CA with ai-env relay tls init --force"), "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one Touch ID");
    assert!(!w.aws_calls().iter().any(|l| l.starts_with("ssm put-parameter")) && w.param(TLS).unwrap().1 == 2, "nothing written");
    fs::write(w.bridge().join("state").join("relay-ca.der"), &der).unwrap();
    // ca: the PEM, or the DER's base64.
    let o = w.run(&["ca"], Who::Nobody);
    assert_eq!((code(&o), stdout(&o)), (0, pem.clone()));
    let o = w.run(&["ca", "--der"], Who::Nobody);
    assert_eq!((code(&o), stdout(&o)), (0, format!("{}\n", base64::engine::general_purpose::STANDARD.encode(&der))));
    assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0);
    // A `tls` that is not a SecureString (a String made by hand): rotate overwrites with `--type SecureString
    // --key-id alias/aws/ssm`, and SSM never changes a parameter's type, so it is exit 7 and the String keeps its
    // value: the leaf's key never lands in a String.
    w.set_param(TLS, "a String made by hand", 5);
    w.set_param_type(TLS, "String");
    let o = w.run(&["tls", "rotate"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay tls rotate: ") && stderr(&o).contains("(HierarchyTypeMismatchException) when calling the PutParameter operation"), "{}", stderr(&o));
    let puts: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert!(puts.len() == 1 && puts[0].contains(" --type SecureString --key-id alias/aws/ssm --overwrite "), "{puts:?}");
    assert_eq!(w.param(TLS), Some(("a String made by hand".to_string(), 5)), "the String untouched");
    // A write of the value that fails (exit 7) leaves the CA made, and says that rotate writes the value under it.
    let w2 = World::new();
    w2.answer("ssm.put-parameter.rc", "254");
    w2.answer("ssm.put-parameter.stderr", "\nAn error occurred (InternalServerError) when calling the PutParameter operation: try again.\n");
    let o = w2.run(&["tls", "init"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("is made and sealed: ai-env relay tls rotate writes {TLS} under it")), "{}", stderr(&o));
    assert!(w2.param(TLS).is_none() && w2.bridge().join("state").join("relay-ca.der").exists() && w2.bridge().join("credentials").join("relay-ca.env").exists());
    w2.unanswer("ssm.put-parameter.rc");
    w2.unanswer("ssm.put-parameter.stderr");
    let o = w2.run(&["tls", "rotate"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w2.param(TLS).map(|(_, v)| v), Some(1), "created under that CA");
}

/// In front of the fake aws (`aws-fake` beside it): a `put-parameter` while one of ai-env's temp files
/// (`.param.*`) is in `@STATE@` is refused like an aws error (exit 254), the file's name appended to `@SEEN@`.
const TEMP_FILE_WATCH: &str = r#"#!/bin/sh
if [ "${1:-} ${2:-}" = 'ssm put-parameter' ]; then
  for f in '@STATE@'/.param.*; do
    if [ -e "$f" ]; then
      printf '%s\n' "${f##*/}" >> '@SEEN@'
      printf '\nAn error occurred (TempFileSeen) when calling the PutParameter operation: %s\n' "${f##*/}" >&2
      exit 254
    fi
  done
fi
exec '@FAKE@' "$@"
"#;

/// WM-T48a (plans/s13-contracts.md §Q.8 F5; WM-R54, WM-R60): the `tls` value never touches the disk. With
/// [`TEMP_FILE_WATCH`] in front of the fake aws, a list's write, which still goes through its temp file in
/// `state/`, is refused (the control: the watch sees the file); `tls init` and `tls rotate` pass, each
/// `put-parameter` reading the value from `file:///dev/stdin` as a SecureString under `alias/aws/ssm`, with
/// `AWS_CLI_AUTO_PROMPT=on` in ai-env's environment (the fake refuses a put from stdin with the prompt on: the
/// control); the value the fake holds is intact (the leaf, the CA of `state/relay-ca.der` and the leaf's own
/// PKCS#8 key, every byte as `certs::pem` renders them), and the leaf key's text is in no file but the fake's
/// Parameter Store.
#[test]
fn relay_tls_value_reaches_ssm_on_stdin_never_through_a_file() {
    use ai_env_worker::certs;
    use base64::Engine as _;
    let w = World::new();
    let (bin, state, seen) = (w.root().join("bin"), w.bridge().join("state"), w.root().join("temp-files-seen.log"));
    fs::rename(bin.join("aws"), bin.join("aws-fake")).unwrap();
    let watch = TEMP_FILE_WATCH.replace("@STATE@", &state.display().to_string()).replace("@SEEN@", &seen.display().to_string()).replace("@FAKE@", &bin.join("aws-fake").display().to_string());
    fs::write(bin.join("aws"), watch).unwrap();
    fs::set_permissions(bin.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
    // The control: a list is a String, written through its 0600 temp file in state/, which the watch sees.
    let o = w.run(&["allow", "worker-a", "--key", &key_text(1), "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("(TempFileSeen) when calling the PutParameter operation: .param."), "{}", stderr(&o));
    assert!(fs::read_to_string(&seen).is_ok_and(|s| s.starts_with(".param.") && s.lines().count() == 1), "the watch saw the list's temp file");
    fs::remove_file(&seen).unwrap();
    // The value as the fake holds it: exactly the leaf, state/relay-ca.der and the leaf's key, nothing else; the
    // key's text in no other file. Its blocks are never printed.
    let intact = |what: &str| -> Vec<Vec<u8>> {
        let (value, _) = w.param(TLS).unwrap_or_else(|| panic!("{what}: no {TLS}"));
        let blocks = pem_blocks(&value);
        assert_eq!(blocks.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(), ["CERTIFICATE", "CERTIFICATE", "PRIVATE KEY"], "{what}: {} bytes", value.len());
        let der: Vec<Vec<u8>> = blocks.iter().map(|(_, b)| base64::engine::general_purpose::STANDARD.decode(b).unwrap()).collect();
        let rendered = format!("{}{}{}", certs::pem("CERTIFICATE", &der[0]), certs::pem("CERTIFICATE", &der[1]), certs::pem("PRIVATE KEY", &der[2]));
        assert!(rendered == value, "{what}: the value is not the three blocks exactly ({} bytes, {} rendered)", value.len(), rendered.len());
        assert!(der[1] == fs::read(state.join("relay-ca.der")).unwrap(), "{what}: the chain's CA is state/relay-ca.der");
        assert!(certs::ca_from_parts(&der[0], &der[2]).is_ok(), "{what}: the key is the leaf's");
        assert_eq!(certs::ca_from_parts(&der[1], &der[2]).err(), Some(certs::CertError::Mismatch), "{what}: and not the CA's");
        assert_eq!(w.holding(&blocks[2].1[..64]), [w.root().join("ssm").join(TLS.trim_start_matches('/'))], "{what}: the leaf key's text is in the Parameter Store alone");
        der
    };
    // The aws CLI's prompt, on in the user's environment, would read its keystrokes from the value's stdin: the
    // fake refuses such a put (the control), and both writes run with it on, the child's pinned off.
    let mut control = Command::new(bin.join("aws-fake"));
    control
        .args(["ssm", "put-parameter", "--name", "/ai-env/relay/control", "--value", "file:///dev/stdin", "--region", "eu-central-1", "--endpoint-url", "https://ssm.eu-central-1.amazonaws.com"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("FAKE_AWS_SSM_DIR", w.root().join("ssm"))
        .env("AWS_CLI_AUTO_PROMPT", "on")
        .stdin(Stdio::null());
    let o = run(&mut control);
    assert!(code(&o) == 255 && stderr(&o).contains("AWS_CLI_AUTO_PROMPT is on") && w.param("/ai-env/relay/control").is_none(), "the fake refuses it: {}", stderr(&o));
    let prompting = |args: &[&str]| {
        w.reset();
        run(w.cmd(args, Who::Deployer).env("AWS_CLI_AUTO_PROMPT", "on"))
    };
    let o = prompting(&["tls", "init"]);
    assert_eq!(code(&o), 0, "a temp file in state/ during tls init's put-parameter, or the prompt left on? {}", stderr(&o));
    let puts: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert!(puts.len() == 1 && puts[0].starts_with(&format!("ssm put-parameter --name {TLS} --value file:///dev/stdin --type SecureString --key-id alias/aws/ssm --tier Standard ")), "{puts:?}");
    assert_eq!(w.param(TLS).map(|(_, v)| v), Some(1));
    let first = intact("init");
    let o = prompting(&["tls", "rotate"]);
    assert_eq!(code(&o), 0, "a temp file in state/ during tls rotate's put-parameter, or the prompt left on? {}", stderr(&o));
    let puts: Vec<String> = w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect();
    assert!(puts.len() == 1 && puts[0].starts_with(&format!("ssm put-parameter --name {TLS} --value file:///dev/stdin --type SecureString --key-id alias/aws/ssm --overwrite ")), "{puts:?}");
    assert_eq!(w.param(TLS).map(|(_, v)| v), Some(2));
    let rotated = intact("rotate");
    assert!(rotated[1] == first[1] && rotated[0] != first[0] && rotated[2] != first[2], "the CA kept, a new leaf and key");
    assert!(!seen.exists(), "the watch saw a temp file: {:?}", fs::read_to_string(&seen));
}

/// WM-T42a (plans/s13-contracts.md §Q.8, the help texts, each checked against the code): what `stop` leaves (VM
/// relay calls answer `unavailable`, workers keep dialing), `revoke`'s and `grant`'s arguments, what `status
/// --json` holds, where `pubkey` reads the keys from, and whose session key `allow` takes until when.
#[test]
fn relay_help_says_what_each_command_does() {
    let w = World::new();
    let rules = format!("Its rules, <source-glob>/<op-glob>, 1 to {} (they replace the grant's whole set; grants are default-deny)", policy::RULES_MAX);
    let wanted: [(&str, Vec<&str>); 6] = [
        ("stop", vec!["Stop the relay instance (as ai-env-ops): VM relay calls answer unavailable and workers keep dialing until ai-env relay start"]),
        ("revoke", vec!["The worker's id (with --token-signer: the token signer's)", "Remove a token signer, not a worker"]),
        ("grant", vec!["The grant's id, as [relay].grant or a workspace's relay_grant names it", rules.as_str(), "Delete the grant"]),
        ("status", vec!["One JSON object: the instance, the lists and this Mac's keys (each key as its fingerprint) and agent, and the verdict with its rows as printed"]),
        ("pubkey", vec!["Print this Mac's relay public keys from the sealed container's notes (no Touch ID; --verify checks them: one Touch ID)"]),
        ("allow", vec!["Allow a worker, or with --token-signer a Mac's session key, in the relay's lists (as ai-env-deployer)", "The last valid day, UTC (default: a year from today; at most two years ahead)"]),
    ];
    let mut missing = Vec::new();
    for (sub, texts) in wanted {
        let o = w.run(&[sub, "--help"], Who::Nobody);
        assert_eq!(code(&o), 0, "relay {sub} --help: {}", stderr(&o));
        assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0, "relay {sub} --help calls nothing");
        let help = stdout(&o).split_whitespace().collect::<Vec<_>>().join(" ");
        missing.extend(texts.into_iter().filter(|t| !help.contains(t)).map(|t| format!("relay {sub} --help lacks {t:?}")));
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

// ---- the relay security plan's slice M: §RS.4, §RS.3.2 ------------------------------------------------------------

const PEERS: &str = "/ai-env/relay/peers";
/// The keys of `relay status --json` (§RS.3.2 row 8).
const SEVEN_KEYS: [&str; 7] = ["instance", "workers", "token_signers", "grants", "peers", "status", "mac"];
/// A `not_after` in force for the life of these tests, and one long lapsed.
const IN_FORCE: &str = "2036-01-01T00:00:00Z";
const LAPSED: &str = "2020-01-01T00:00:00Z";

/// `/ai-env/relay/peers` holding `(cidr, label, not_after)`, as the CLI renders it.
fn peers_value(entries: &[(&str, &str, &str)]) -> String {
    let list: Vec<policy::PeerEntry> = entries.iter().map(|(cidr, label, not_after)| policy::PeerEntry { cidr: (*cidr).into(), label: (*label).into(), not_after: (*not_after).into() }).collect();
    policy::render_peers(&list).unwrap()
}

/// The entries of `/ai-env/relay/peers`, and its version.
fn peers_of(w: &World) -> (Vec<policy::PeerEntry>, u64) {
    let (value, version) = w.param(PEERS).expect("the peers list exists");
    (policy::parse_peers(&value).unwrap(), version)
}

/// The `put-parameter`s of the last run.
fn puts(w: &World) -> Vec<String> {
    w.aws_calls().into_iter().filter(|l| l.starts_with("ssm put-parameter")).collect()
}

/// The keys of an audit row's detail but `actor`, sorted.
fn detail_keys(row: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = row["detail"].as_object().unwrap().keys().filter(|k| *k != "actor" && *k != "purpose").cloned().collect();
    keys.sort();
    keys
}

/// A stand-in for checkip.amazonaws.com on loopback (`AI_ENV_BRIDGE_LAB_CHECKIP`): every request gets the answer set
/// last; the requests' heads are kept. Its thread lives as long as the test process.
struct FakeCheckip {
    addr: std::net::SocketAddr,
    answer: std::sync::Arc<std::sync::Mutex<String>>,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl FakeCheckip {
    fn start() -> FakeCheckip {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let answer = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (give, keep) = (answer.clone(), seen.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                keep.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
                let text = give.lock().unwrap().clone();
                let _ = conn.write_all(text.as_bytes());
            }
        });
        FakeCheckip { addr, answer, seen }
    }

    /// The next answers: this status and body.
    fn says(&self, status: &str, body: &str) {
        *self.answer.lock().unwrap() = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl World {
    /// `relay <args>` with the fake checkip at `addr`, from clean fake logs and answer counters.
    fn with_checkip(&self, addr: &str, args: &[&str], who: Who) -> Output {
        self.reset();
        run(self.cmd(args, who).env("AI_ENV_BRIDGE_LAB_CHECKIP", addr))
    }
}

/// WM-T58 (§RS.4.1 to §RS.4.3, R-97): `allow-ip` and `revoke-ip` edit `/ai-env/relay/peers` as the deployer.
#[test]
fn relay_allow_ip_edits_the_peers_list() {
    let w = World::new();
    let checkip = FakeCheckip::start();
    checkip.says("200 OK", "203.0.113.7\n");
    let knob = checkip.addr.to_string();
    let day = default_day();
    // No marker, or an ops marker: exit 9 with WM-R41's text naming the command as given, no aws call, no checkip.
    let wide_given = format!("allow-ip 198.51.100.0/8 --label wide --not-after {day} --wide");
    let writers: [(&[&str], &str); 5] = [
        (&["allow-ip", "198.51.100.7/24", "--label", "office"], "allow-ip 198.51.100.7/24 --label office"),
        (&["allow-ip", "198.51.100.0/8", "--label", "wide", "--not-after", &day, "--wide"], &wide_given),
        (&["allow-ip", "--mine", "--hours", "2"], "allow-ip --mine --hours 2"),
        (&["revoke-ip", "198.51.100.0/24"], "revoke-ip 198.51.100.0/24"),
        (&["revoke-ip", "--label", "office"], "revoke-ip --label office"),
    ];
    for who in [Who::Nobody, Who::Ops] {
        for (args, given) in &writers {
            let o = w.with_checkip(&knob, args, who);
            assert_eq!(code(&o), 9, "{who:?} {args:?}: {}", stderr(&o));
            let cmd = args[0];
            assert!(stderr(&o).contains(&format!("relay {cmd}: the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them: run ai-env as deployer -- ai-env relay {given}")), "{who:?} {args:?}: {}", stderr(&o));
            assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0, "{who:?} {args:?}: {:?}", w.aws_calls());
        }
    }
    assert!(checkip.requests().is_empty(), "the gate comes before the address");
    // The first allow-ip creates the list: --type String --tier Standard, no --overwrite, version 1, the network
    // truncated, and it says so.
    let o = w.run(&["allow-ip", "198.51.100.7/24", "--label", "office"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let put = puts(&w);
    assert_eq!(put.len(), 1, "{put:?}");
    assert!(put[0].contains(&format!("--name {PEERS} ")) && put[0].contains(" --type String ") && put[0].contains(" --tier Standard ") && !put[0].contains("--overwrite"), "{}", put[0]);
    let until = format!("{day}T23:59:59Z");
    assert_eq!(w.param(PEERS), Some((peers_value(&[("198.51.100.0/24", "office", &until)]), 1)));
    assert_eq!(stdout(&o), format!("allowed peer office 198.51.100.0/24 until {until} ({PEERS} v1, 1 peer(s)); the relay applies it within 60 s (198.51.100.7/24 is written as 198.51.100.0/24)\n"));
    // The same again: nothing written, the given form noted.
    let o = w.run(&["allow-ip", "198.51.100.200/24", "--label", "office"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("(198.51.100.200/24 is written as 198.51.100.0/24)\npeer office 198.51.100.0/24 is already allowed until {until} ({PEERS} v1); nothing written\n"));
    assert!(puts(&w).is_empty());
    let o = w.run(&["allow-ip", "198.51.100.0/24", "--label", "office"], Who::Deployer);
    assert_eq!(stdout(&o), format!("peer office 198.51.100.0/24 is already allowed until {until} ({PEERS} v1); nothing written\n"), "no note without host bits");
    // An address alone is its /32, with no note; the list is sorted by label; the count is the list's.
    let o = w.run(&["allow-ip", "198.51.100.9", "--label", "alpha", "--not-after", &day], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("allowed peer alpha 198.51.100.9/32 until {until} ({PEERS} v2, 2 peer(s)); the relay applies it within 60 s\n"));
    assert_eq!(peers_of(&w).0.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(), ["alpha", "office"], "sorted by label");
    assert!(puts(&w)[0].contains(" --overwrite"), "an existing list is overwritten: {:?}", puts(&w));
    // A network another label holds: exit 9, whatever its text; nothing written.
    let o = w.run(&["allow-ip", "198.51.100.200/24", "--label", "other"], Who::Deployer);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay allow-ip: 198.51.100.0/24 is already allowed as office: one network, one label (ai-env relay revoke-ip --label office first)"), "{}", stderr(&o));
    assert!(puts(&w).is_empty());
    // --mine: this Mac's address as checkip answers it, the /32 labelled mac, until now plus 24 h, to the second.
    let before = ai_env_cli::wire::time::unix_now();
    let o = w.with_checkip(&knob, &["allow-ip", "--mine"], Who::Deployer);
    let after = ai_env_cli::wire::time::unix_now();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("LAB KNOB ACTIVE (AI_ENV_BRIDGE_LAB_CHECKIP)"), "the banner names it: {}", stderr(&o));
    let (list, version) = peers_of(&w);
    assert_eq!(version, 3);
    let mac = list.iter().find(|p| p.label == "mac").expect("the mac entry");
    assert_eq!(mac.cidr, "203.0.113.7/32");
    assert!((before + 86_400..=after + 86_400).contains(&mac.not_after_unix()), "{} not within now plus 24 h", mac.not_after);
    assert_eq!(stdout(&o), format!("this Mac's address is 203.0.113.7 (checkip.amazonaws.com)\nallowed peer mac 203.0.113.7/32 until {} ({PEERS} v3, 3 peer(s)); the relay applies it within 60 s\n", mac.not_after));
    let asked = checkip.requests();
    assert_eq!(asked.len(), 1, "{asked:?}");
    let head = asked[0].to_ascii_lowercase();
    assert!(head.starts_with("get / http/1.1\r\n") && head.contains(&format!("host: checkip.amazonaws.com:{}\r\n", checkip.addr.port())), "{head}");
    // Again, from another network: replaced, one mac entry, and it names the old network; --hours moves the time.
    checkip.says("200 OK", "203.0.113.8");
    let o = w.with_checkip(&knob, &["allow-ip", "--mine", "--hours", "168"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let (list, version) = peers_of(&w);
    assert_eq!((version, list.len()), (4, 3));
    let mac = list.iter().find(|p| p.label == "mac").expect("the mac entry");
    assert_eq!(mac.cidr, "203.0.113.8/32");
    assert!(mac.not_after_unix() >= before + 168 * 3600, "{}", mac.not_after);
    assert!(stdout(&o).ends_with(&format!("({PEERS} v4, 3 peer(s)); the relay applies it within 60 s; replaced 203.0.113.7/32\n")), "{}", stdout(&o));
    // The address again, a later time: replaced, no network moved.
    let o = w.with_checkip(&knob, &["allow-ip", "--mine", "--hours", "1"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).ends_with("; the relay applies it within 60 s\n"), "{}", stdout(&o));
    assert_eq!(peers_of(&w).1, 5);
    // --mine's refusals write nothing: exit 1 for what checkip answers, exit 2 for --hours (no request at all).
    let requests = checkip.requests().len();
    for (status, body) in [("200 OK", "not an address\n"), ("200 OK", "2001:db8::1\n"), ("200 OK", ""), ("200 OK", "203.0.113.7\n198.51.100.1\n"), ("500 Internal Server Error", "203.0.113.7\n")] {
        checkip.says(status, body);
        let o = w.with_checkip(&knob, &["allow-ip", "--mine"], Who::Deployer);
        assert_eq!(code(&o), 1, "{status} {body:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("relay allow-ip --mine: checkip.amazonaws.com answered no IPv4 address"), "{status} {body:?}: {}", stderr(&o));
        assert!(w.aws_calls().iter().all(|c| !c.starts_with("ssm ")), "no list read: {:?}", w.aws_calls());
    }
    checkip.says("200 OK", &format!("203.0.113.7{}\n", " ".repeat(64)));
    let o = w.with_checkip(&knob, &["allow-ip", "--mine"], Who::Deployer);
    assert_eq!(code(&o), 1, "over 64 bytes: {}", stderr(&o));
    assert!(stderr(&o).contains("answered no IPv4 address"), "{}", stderr(&o));
    let nobody = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let o = w.with_checkip(&nobody, &["allow-ip", "--mine"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay allow-ip --mine: checkip.amazonaws.com could not be reached ("), "{}", stderr(&o));
    // A server that takes the request and never answers: the run ends at its 10 s.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let o = w.with_checkip(&silent.local_addr().unwrap().to_string(), &["allow-ip", "--mine"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay allow-ip --mine: checkip.amazonaws.com could not be reached (no answer within 10 s)"), "{}", stderr(&o));
    let o = w.with_checkip("192.0.2.1:8080", &["allow-ip", "--mine"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("AI_ENV_BRIDGE_LAB_CHECKIP=\"192.0.2.1:8080\": expected a loopback ip:port"), "never another address: {}", stderr(&o));
    let requests_then = checkip.requests().len();
    assert_eq!(requests_then, requests + 6, "one request each");
    for hours in ["0", "169"] {
        let o = w.with_checkip(&knob, &["allow-ip", "--mine", "--hours", hours], Who::Deployer);
        assert_eq!(code(&o), 2, "--hours {hours}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("relay allow-ip: --hours {hours}: 1 to 168")), "{}", stderr(&o));
    }
    assert_eq!(checkip.requests().len(), requests_then, "the arguments come first");
    assert_eq!(peers_of(&w).1, 5, "nothing written");
    // A prefix under 16 is exit 2 without --wide, written with it; /16 needs none.
    for (given, network) in [("198.51.100.0/8", "198.0.0.0/8"), ("198.51.100.7/0", "0.0.0.0/0"), ("198.51.100.0/15", "198.50.0.0/15")] {
        let o = w.run(&["allow-ip", given, "--label", "wide"], Who::Nobody);
        assert_eq!(code(&o), 2, "{given}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("relay allow-ip: {network} is wider than /16, which admits much of the internet: pass --wide if that is meant")), "{given}: {}", stderr(&o));
    }
    assert_eq!(peers_of(&w).1, 5, "nothing written");
    let o = w.run(&["allow-ip", "198.51.100.0/8", "--label", "wide", "--wide"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).starts_with("allowed peer wide 198.0.0.0/8 until "), "{}", stdout(&o));
    let o = w.run(&["allow-ip", "192.0.2.0/16", "--label", "broad"], Who::Deployer);
    assert_eq!(code(&o), 0, "/16 is not wider than /16: {}", stderr(&o));
    // Usage errors come before the gate.
    for (args, why) in [
        (vec!["allow-ip", "198.51.100.0/33", "--label", "x"], "relay allow-ip: 198.51.100.0/33 is not an IPv4 address or network (a.b.c.d or a.b.c.d/n, n 0 to 32)"),
        (vec!["allow-ip", "2001:db8::/32", "--label", "x"], "relay allow-ip: 2001:db8::/32 is not an IPv4 address or network"),
        (vec!["allow-ip", "example.invalid", "--label", "x"], "relay allow-ip: example.invalid is not an IPv4 address or network"),
        (vec!["allow-ip", "198.51.100.0/24", "--label", "Not-An-Id"], "is not an id"),
        (vec!["allow-ip", "198.51.100.0/24", "--label", "198.51.100.7"], "relay allow-ip: --label \"198.51.100.7\" reads as an address: a label says what the network is, and the audit never holds an address"),
        (vec!["allow-ip", "198.51.100.0/24", "--label", "x", "--not-after", "2020-01-01"], "is before today"),
        (vec!["revoke-ip", "198.51.100.0/33"], "relay revoke-ip: 198.51.100.0/33 is not an IPv4 address or network"),
        (vec!["revoke-ip", "--label", "Not-An-Id"], "is not an id"),
    ] {
        let o = w.run(&args, Who::Nobody);
        assert_eq!(code(&o), 2, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{args:?}: {}", stderr(&o));
    }
    // A lost race: the put answered two versions on: exit 7 naming both.
    let at = peers_of(&w).1;
    w.answer("ssm.put-parameter.json", &format!("{{\"Version\": {}, \"Tier\": \"Standard\"}}\n", at + 2));
    let o = w.run(&["allow-ip", "192.0.2.0/24", "--label", "race"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow-ip: {PEERS} moved from v{at} to v{} while it was written (another writer): run the command again to see what it holds", at + 2)), "{}", stderr(&o));
    let o = w.run(&["revoke-ip", "--label", "broad"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay revoke-ip: {PEERS} moved from v{at} to v{}", at + 2)), "{}", stderr(&o));
    w.unanswer("ssm.put-parameter.json");
    // A list that does not parse is never overwritten (exit 1).
    let good = w.param(PEERS).unwrap();
    w.set_param(PEERS, "[{\"cidr\":\"not a network\"}]", at);
    for args in [vec!["allow-ip", "192.0.2.0/24", "--label", "x"], vec!["revoke-ip", "--label", "broad"]] {
        let o = w.run(&args, Who::Deployer);
        assert_eq!(code(&o), 1, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("relay {}: {PEERS} does not parse (", args[0])) && stderr(&o).contains("nothing was written: correct it first (aws ssm put-parameter)"), "{}", stderr(&o));
        assert!(puts(&w).is_empty());
    }
    // Over its limits: refused before any write.
    let mut full = Vec::new();
    for n in 0..64u8 {
        let entry = policy::PeerEntry { cidr: format!("192.0.2.{n}/32"), label: format!("a-rather-longer-label-{n:02}"), not_after: IN_FORCE.into() };
        full.push(entry);
        if policy::render_peers(&full).is_err() {
            full.pop();
            break;
        }
    }
    assert!(full.len() < 64, "the bytes limit comes first: {}", full.len());
    w.set_param(PEERS, &policy::render_peers(&full).unwrap(), 20);
    let o = w.run(&["allow-ip", "198.51.100.0/24", "--label", "a-rather-longer-label-that-is-over-the-limit"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow-ip: {PEERS} would be ")) && stderr(&o).contains("bytes, over its limit of 4096; nothing was written"), "{}", stderr(&o));
    assert!(puts(&w).is_empty());
    w.set_param(PEERS, &good.0, good.1);
    // revoke-ip by network, the argument normalised, and by label; each says which it removed.
    let o = w.run(&["revoke-ip", "198.51.100.42/24"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = at + 1;
    assert_eq!(stdout(&o), format!("revoked peer office 198.51.100.0/24 ({PEERS} v{v}): the relay closes its tunnels within 60 s\n"));
    assert!(!peers_of(&w).0.iter().any(|p| p.label == "office"));
    let o = w.run(&["revoke-ip", "--label", "wide"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("revoked peer wide 198.0.0.0/8 ({PEERS} v{}): the relay closes its tunnels within 60 s\n", v + 1));
    // Not listed: nothing written, exit 0, whichever way it is named; a missing list too.
    for (args, given) in [(vec!["revoke-ip", "198.51.100.0/24"], "198.51.100.0/24"), (vec!["revoke-ip", "198.51.100.7/24"], "198.51.100.7/24"), (vec!["revoke-ip", "--label", "gone"], "gone")] {
        let o = w.run(&args, Who::Deployer);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        assert_eq!(stdout(&o), format!("{given} is not listed in {PEERS}; nothing written\n"));
        assert!(puts(&w).is_empty(), "{args:?}");
    }
    let other = World::new();
    let o = other.run(&["revoke-ip", "--label", "gone"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("gone is not listed in {PEERS}; nothing written\n"));
    assert!(puts(&other).is_empty() && other.param(PEERS).is_none(), "a missing list stays missing");
    // A root or ambient marker passes the gate (IAM decides for those).
    for (who, caller, label, cidr) in [(Who::Root, "root", "by-root", "192.0.2.1"), (Who::Ambient, "rust", "by-ambient", "192.0.2.2")] {
        other.reset();
        let o = run(other.cmd(&["allow-ip", cidr, "--label", label], who).env("FAKE_AWS_CALLER", caller));
        assert_eq!(code(&o), 0, "{who:?}: {}", stderr(&o));
        assert!(stdout(&o).starts_with(&format!("allowed peer {label} {cidr}/32 until ")), "{}", stdout(&o));
    }
    // An address inside a wider entry stays admitted (LD-R40): the line as ever, and a note on stderr naming the entry,
    // whether something was removed or not. A lapsed entry admits nothing; an entry inside the named network, not all of it.
    let nested = World::new();
    nested.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "office", IN_FORCE), ("198.51.100.7/32", "host", IN_FORCE), ("198.51.100.8/32", "desk", IN_FORCE), ("203.0.113.0/24", "old", LAPSED)]), 1);
    let stays = |given: &str| format!("note: {given} stays admitted by peer office 198.51.100.0/24\n");
    let o = nested.run(&["revoke-ip", "198.51.100.42"], Who::Deployer);
    assert_eq!((code(&o), stdout(&o)), (0, format!("198.51.100.42 is not listed in {PEERS}; nothing written\n")), "{}", stderr(&o));
    assert!(stderr(&o).contains(&stays("198.51.100.42")) && puts(&nested).is_empty(), "{}", stderr(&o));
    let o = nested.run(&["revoke-ip", "198.51.100.7"], Who::Deployer);
    assert_eq!((code(&o), stdout(&o)), (0, format!("revoked peer host 198.51.100.7/32 ({PEERS} v2): the relay closes its tunnels within 60 s\n")), "{}", stderr(&o));
    assert!(stderr(&o).contains(&stays("198.51.100.7")), "{}", stderr(&o));
    let o = nested.run(&["revoke-ip", "--label", "desk"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(&stays("198.51.100.8/32")), "by label, its network: {}", stderr(&o));
    for given in ["203.0.113.9", "198.51.100.0/23", "192.0.2.1", "198.51.100.0/24"] {
        let o = nested.run(&["revoke-ip", given], Who::Deployer);
        assert_eq!(code(&o), 0, "{given}: {}", stderr(&o));
        assert!(!stderr(&o).contains("stays admitted"), "{given}: {}", stderr(&o));
    }
    // A list corrected by hand may hold a label that reads as an address: its removal's row leaves it out.
    let by_hand = World::new();
    by_hand.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "198.51.100.7", IN_FORCE)]), 1);
    let o = by_hand.run(&["revoke-ip", "--label", "198.51.100.7"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(detail_keys(&by_hand.audit("relay_revoke_ip")[0]), ["not_after", "outcome", "prefix", "version"]);
    assert!(!fs::read_to_string(by_hand.bridge().join("audit.jsonl")).unwrap().contains("198.51.100."), "an address in the audit");
    // Each audit row's keys, as §RS.4.3 has them; the outcomes in order; no row holds an address, nor does any other.
    let rows = w.audit("relay_allow_ip");
    let outcomes: Vec<&str> = rows.iter().map(|r| r["detail"]["outcome"].as_str().unwrap_or_default()).collect();
    assert_eq!(outcomes, ["added", "unchanged", "unchanged", "added", "added", "replaced", "replaced", "added", "added"], "{rows:?}");
    for r in &rows {
        let mine = r["detail"]["label"] == "mac";
        let want: &[&str] = if mine { &["label", "mine", "not_after", "outcome", "prefix", "version"] } else { &["label", "not_after", "outcome", "prefix", "version"] };
        assert_eq!(detail_keys(r), want, "{r}");
        assert_eq!(r["detail"]["mine"].as_str(), mine.then_some("yes"), "{r}");
    }
    assert_eq!(rows[0]["detail"]["label"].as_str(), Some("office"));
    assert_eq!((rows[0]["detail"]["prefix"].as_str(), rows[0]["detail"]["not_after"].as_str(), rows[0]["detail"]["version"].as_str()), (Some("24"), Some(until.as_str()), Some("1")));
    assert_eq!((rows[1]["detail"]["outcome"].as_str(), rows[1]["detail"]["version"].as_str()), (Some("unchanged"), Some("1")), "the version it holds");
    let rows = w.audit("relay_revoke_ip");
    assert_eq!(rows.len(), 5, "{rows:?}");
    assert_eq!(detail_keys(&rows[0]), ["label", "not_after", "outcome", "prefix", "version"]);
    assert_eq!((rows[0]["detail"]["outcome"].as_str(), rows[0]["detail"]["label"].as_str(), rows[0]["detail"]["prefix"].as_str(), rows[0]["detail"]["version"].as_str()), (Some("revoked"), Some("office"), Some("24"), Some(v.to_string().as_str())));
    assert_eq!(rows[0]["detail"]["not_after"].as_str(), Some(until.as_str()), "the removed entry's");
    for r in &rows[2..] {
        assert_eq!(detail_keys(r), ["outcome"], "{r}");
        assert_eq!(r["detail"]["outcome"].as_str(), Some("absent"));
    }
    let audit = fs::read_to_string(w.bridge().join("audit.jsonl")).unwrap();
    for address in ["198.51.100.", "203.0.113.", "198.0.0.", "192.0.2."] {
        assert!(!audit.contains(address), "an address in the audit ({address}): {audit}");
    }
    // Its help (§RS.4.1).
    for (sub, text) in [("allow-ip", "Allow a network on the relay's public face (as ai-env-deployer); --mine allows this Mac's current address"), ("revoke-ip", "Remove a network from the relay's public face (as ai-env-deployer)")] {
        let o = w.run(&[sub, "--help"], Who::Nobody);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(stdout(&o).split_whitespace().collect::<Vec<_>>().join(" ").contains(text), "{}", stdout(&o));
    }
}

/// `allow <id> --key <seed's text> --sources <glob> --tls-key <point>`'s arguments.
fn tls_args<'a>(id: &'a str, key: &'a str, glob: &'a str, point: &'a str) -> Vec<&'a str> {
    vec!["allow", id, "--key", key, "--sources", glob, "--tls-key", point]
}

/// A fresh P-256 public point's text, and its key made at run time, as `tls-keygen` does on a worker.
fn point_text() -> String {
    let key = ai_env_worker::certs::client_key().unwrap();
    ai_env_worker::certs::client_point(&key).unwrap().text()
}

/// The one certificate of a PEM text, its DER: the text is exactly that block.
fn one_certificate(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let blocks = pem_blocks(pem);
    assert_eq!(blocks.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(), ["CERTIFICATE"], "{pem}");
    let der = base64::engine::general_purpose::STANDARD.decode(&blocks[0].1).unwrap();
    assert_eq!(pem, ai_env_worker::certs::pem("CERTIFICATE", &der), "exactly the PEM");
    der
}

/// The SHA-256 of `der`, 64 lowercase hex.
fn sha256_hex(der: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether the client certificate `der` verifies at `unix` under the CA `ca_der` as the relay's public face will verify
/// it (R-124's `WebPkiClientVerifier`).
fn verifies_under(ca_der: &[u8], der: &[u8], unix: u64) -> bool {
    use rustls_pki_types::{CertificateDer, UnixTime};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(std::sync::Arc::new(roots), provider).build().unwrap();
    verifier.verify_client_cert(&CertificateDer::from(der.to_vec()), &[], UnixTime::since_unix_epoch(Duration::from_secs(unix))).is_ok()
}

/// WM-T59 (§RS.4.2, R-131, R-123): `allow --tls-key` issues a worker's client certificate under the sealed CA.
#[test]
fn relay_allow_tls_key_issues_a_client_certificate() {
    let w = World::new();
    assert_eq!(code(&w.run(&["tls", "init"], Who::Deployer)), 0);
    let ca = fs::read(w.bridge().join("state").join("relay-ca.der")).unwrap();
    let (k1, k2) = (key_text(1), key_text(2));
    let point = point_text();
    let args = tls_args("worker-a", &k1, "example-*", &point);
    let given = format!("allow worker-a --key {k1} --sources 'example-*' --tls-key {point}");
    // Under no marker or ops: WM-R41's refusal; under root or ambient: §RS.4.2's own; no aws call and no unseal.
    for (who, why) in [
        (Who::Nobody, "relay allow: the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them"),
        (Who::Ops, "relay allow: the relay's whitelist and grants decide who reaches private data, and only ai-env-deployer writes them"),
        (Who::Root, "relay allow: --tls-key unseals the relay CA's key, which only the deployer uses"),
        (Who::Ambient, "relay allow: --tls-key unseals the relay CA's key, which only the deployer uses"),
    ] {
        let o = w.run(&args, who);
        assert_eq!(code(&o), 9, "{who:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("{why}: run ai-env as deployer -- ai-env relay {given}")), "{who:?}: {}", stderr(&o));
        assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0, "{who:?}: {:?}", w.aws_calls());
    }
    // The first: one Touch ID, stdout exactly the PEM, the entry's tls_fp the SHA-256 of its DER, the audit its first 16.
    let o = w.run(&args, Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one Touch ID");
    let der = one_certificate(&stdout(&o));
    let fp = sha256_hex(&der);
    let day = default_day();
    let (value, version) = w.param(WORKERS).unwrap();
    assert_eq!(version, 1);
    let list = policy::parse_workers(&value).unwrap();
    assert_eq!(list[0].tls_fp.as_deref(), Some(fp.as_str()));
    let line = format!("ai-env: allowed worker worker-a (key fp {}, cert fp {}) for sources example-* until {day} ({WORKERS} v1, 1 worker(s)); the relay applies it within 60 s\n", key_of(1).fingerprint(), &fp[..16]);
    assert!(stderr(&o).contains(&line), "{}\nnot in\n{}", line, stderr(&o));
    assert!(stderr(&o).contains("ai-env: the certificate on stdout goes to the worker's relay_client_cert file (0640, the worker's group)\n"), "{}", stderr(&o));
    // It verifies under the relay CA, up to the entry's not_after and not past it.
    let until = list[0].not_after_unix();
    let now = ai_env_cli::wire::time::unix_now();
    assert!(verifies_under(&ca, &der, now) && verifies_under(&ca, &der, until), "under the CA, to the entry's not_after");
    assert!(!verifies_under(&ca, &der, until + 1), "not past it");
    let stranger = ai_env_worker::certs::relay_ca(now).unwrap();
    assert!(!verifies_under(&stranger.cert_der, &der, now), "another CA's");
    let rows = w.audit("relay_allow");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["detail"]["tls_fp"].as_str(), Some(&fp[..16]));
    assert_eq!(detail_keys(&rows[0]), ["fp", "id", "kind", "not_after", "outcome", "sources", "tls_fp", "version"]);
    assert_eq!(rows[0]["detail"]["outcome"].as_str(), Some("added"));
    // Without --tls-key the entry keeps it: `cert fp … kept` in the line, on a rotation of its key too; no Touch ID.
    let o = w.run(&["allow", "worker-a", "--key", &k1, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("worker worker-a (key fp {}, cert fp {} kept) is already allowed for sources example-* until {day} ({WORKERS} v1); nothing written\n", key_of(1).fingerprint(), &fp[..16]));
    assert!(puts(&w).is_empty() && w.age_calls("-d") == 0);
    let o = w.run(&["allow", "worker-a", "--key", &k2, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("allowed worker worker-a (key fp {}, cert fp {} kept) for sources example-* until {day} ({WORKERS} v2, 1 worker(s)); replaced its key fp {} by fp {}; the relay applies it within 60 s\n", key_of(2).fingerprint(), &fp[..16], key_of(1).fingerprint(), key_of(2).fingerprint()));
    assert!(!stderr(&o).contains("note:"), "the same end, and a certificate: {}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 0, "no Touch ID");
    assert_eq!(policy::parse_workers(&w.param(WORKERS).unwrap().0).unwrap()[0].tls_fp.as_deref(), Some(fp.as_str()), "kept");
    assert!(w.audit("relay_allow").last().unwrap()["detail"].get("tls_fp").is_none(), "tls_fp is the issued certificate's");
    // A later end moves the entry's, not the certificate's: WM-R43's stdout, and a note on stderr. An earlier end says
    // nothing: the certificate outlives the entry, and the entry decides.
    let later = ai_env_cli::wire::time::rfc3339_utc(now - now % 86_400 + 400 * 86_400)[..10].to_string();
    let o = w.run(&["allow", "worker-a", "--key", &k2, "--sources", "example-*", "--not-after", &later], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("cert fp {} kept) for sources example-* until {later} (", &fp[..16])), "{}", stdout(&o));
    assert!(stderr(&o).contains(&format!("note: worker worker-a: this moves the entry's end to {later}, not its client certificate's, which keeps the end it was issued with (ai-env relay allow worker-a … --tls-key p256:… issues a new one)\n")), "{}", stderr(&o));
    let o = w.run(&["allow", "worker-a", "--key", &k2, "--sources", "example-*"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("cert fp {} kept) for sources example-* until {day} (", &fp[..16])) && !stderr(&o).contains("note:"), "{}{}", stdout(&o), stderr(&o));
    // A worker with none: WM-R43's stdout, the note on stderr, whether or not anything was written.
    let k3 = key_text(3);
    let plain = ["allow", "worker-b", "--key", k3.as_str(), "--sources", "example-*"];
    let note = "note: worker worker-b has no client certificate: a relay that requires one refuses it (ai-env relay allow worker-b … --tls-key p256:…, after tls-keygen on the worker)\n";
    let o = w.run(&plain, Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).starts_with(&format!("allowed worker worker-b (key fp {}) for sources example-* until ", key_of(3).fingerprint())) && stdout(&o).ends_with("; the relay applies it within 60 s\n"), "{}", stdout(&o));
    assert!(stderr(&o).contains(note), "{}", stderr(&o));
    let o = w.run(&plain, Who::Deployer);
    assert!(stdout(&o).ends_with("; nothing written\n") && stderr(&o).contains(note), "{}{}", stdout(&o), stderr(&o));
    // A token signer has no certificate, and no note.
    let k7 = key_text(7);
    let o = w.run(&["allow", "mac", "--token-signer", "--key", &k7], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains("note:"), "{}", stderr(&o));
    // A certificate is issued on every run, so the run always writes: a second one replaces the first, naming both.
    let second = point_text();
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &second), Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "one Touch ID");
    let der2 = one_certificate(&stdout(&o));
    let fp2 = sha256_hex(&der2);
    assert!(fp2 != fp);
    assert!(stderr(&o).contains(&format!("; the relay applies it within 60 s; replaced its client certificate fp {} by fp {}\n", &fp[..16], &fp2[..16])), "{}", stderr(&o));
    let (value, _) = w.param(WORKERS).unwrap();
    assert_eq!(policy::parse_workers(&value).unwrap().iter().find(|e| e.worker_id == "worker-a").and_then(|e| e.tls_fp.clone()), Some(fp2.clone()));
    assert_eq!(w.audit("relay_allow").last().unwrap()["detail"]["outcome"].as_str(), Some("replaced"));
    let at = w.param(WORKERS).unwrap().1;
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &second), Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(w.param(WORKERS).unwrap().1, at + 1, "the same point again still writes: a new certificate");
    // `--sources '*'`: stdout stays exactly the PEM.
    let o = w.run(&tls_args("worker-c", &key_text(4), "*", &point_text()), Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    one_certificate(&stdout(&o));
    assert!(stderr(&o).contains("ai-env: this worker may register any source name\n"), "{}", stderr(&o));
    // Refused before the Touch ID, nothing written: a key another id or the other list holds, a list that does not parse.
    for (key, why) in [(k3.as_str(), "is already allowed as worker-b: one key, one id"), (k7.as_str(), "is already allowed as token signer mac: one key, one role")] {
        let o = w.run(&tls_args("worker-z", key, "example-*", &point), Who::Deployer);
        assert_eq!(code(&o), 9, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{}", stderr(&o));
        assert!(w.age_calls("-d") == 0 && puts(&w).is_empty(), "no Touch ID");
    }
    let held = w.param(WORKERS).unwrap();
    w.set_param(WORKERS, "[{\"worker_id\":\"A\"}]", 40);
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: {WORKERS} does not parse (")) && w.age_calls("-d") == 0 && puts(&w).is_empty(), "{}", stderr(&o));
    // Over its limits, with the certificate's fingerprint counted: no Touch ID either.
    let mut full = Vec::new();
    for n in 10..200u8 {
        full.push(policy::WorkerEntry { worker_id: format!("w{n:03}"), alg: "ed25519".into(), public_key: key_of(n).b64(), sources: vec!["example-*".into()], not_after: IN_FORCE.into(), tls_fp: None });
        if policy::render_workers(&full).is_err() {
            full.pop();
            break;
        }
    }
    w.set_param(WORKERS, &policy::render_workers(&full).unwrap(), 41);
    let o = w.run(&tls_args("worker-new", &key_text(250), "example-*", &point), Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("relay allow: {WORKERS} would be ")) && stderr(&o).contains("over its limit"), "{}", stderr(&o));
    assert!(w.age_calls("-d") == 0 && puts(&w).is_empty(), "no Touch ID, nothing written");
    w.set_param(WORKERS, &held.0, held.1);
    // A failed write prints no certificate, and says so.
    let not_printed = "; the certificate it issued was not printed: run the command again";
    w.answer("ssm.put-parameter.rc", "254");
    w.answer("ssm.put-parameter.stderr", "\nAn error occurred (InternalServerError) when calling the PutParameter operation: try again.\n");
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer);
    assert_eq!((code(&o), stdout(&o)), (7, String::new()), "{}", stderr(&o));
    assert!(stderr(&o).contains(not_printed), "{}", stderr(&o));
    w.unanswer("ssm.put-parameter.rc");
    w.unanswer("ssm.put-parameter.stderr");
    assert_eq!(w.param(WORKERS).unwrap(), held, "nothing written");
    // A lost race (the put answered two versions on, WM-T45's case): the list may now name a certificate this run dropped.
    w.answer("ssm.put-parameter.json", &format!("{{\"Version\": {}, \"Tier\": \"Standard\"}}\n", held.1 + 2));
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer);
    assert_eq!((code(&o), stdout(&o)), (7, String::new()), "{}", stderr(&o));
    assert_eq!(w.age_calls("-d"), 1, "the Touch ID was spent");
    assert!(stderr(&o).contains(&format!("relay allow: {WORKERS} moved from v{} to v{} while it was written (another writer): run the command again to see what it holds{not_printed}", held.1, held.1 + 2)), "{}", stderr(&o));
    let o = w.run(&["allow", "worker-a", "--key", &k2, "--sources", "other-*"], Who::Deployer);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("moved from v{} to v{}", held.1, held.1 + 2)) && !stderr(&o).contains(not_printed), "no certificate, no word of one: {}", stderr(&o));
    w.unanswer("ssm.put-parameter.json");
    assert_eq!(w.param(WORKERS).unwrap(), held, "nothing written");
    // A stdout that cannot take the certificate fails the run (never exit 0, a closed pipe's): it held the only copy, and
    // the list and the audit already name that certificate. The next run issues another.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    w.reset();
    let child = w.cmd(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer).stdout(Stdio::from(writer)).stderr(Stdio::piped()).spawn().unwrap();
    let o = finish(child, RUN_LIMIT, "ai-env with a closed stdout");
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let tls_fp_of = |value: &str| policy::parse_workers(value).unwrap().into_iter().find(|e| e.worker_id == "worker-a").and_then(|e| e.tls_fp).unwrap();
    let (value, version) = w.param(WORKERS).unwrap();
    assert_eq!(version, held.1 + 1, "the write came first");
    assert!(stderr(&o).contains("relay allow: the certificate could not be written to stdout (") && stderr(&o).contains(&format!("); {WORKERS} v{version} already names it: run the command again")), "{}", stderr(&o));
    assert_eq!(w.audit("relay_allow").last().unwrap()["detail"]["tls_fp"].as_str(), Some(&tls_fp_of(&value)[..16]));
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(tls_fp_of(&w.param(WORKERS).unwrap().0), sha256_hex(&one_certificate(&stdout(&o))), "the next run's");
    w.set_param(WORKERS, &held.0, held.1);
    // A CA certificate that is not the sealed key's: exit 9 as tls rotate says, nothing written.
    fs::write(w.bridge().join("state").join("relay-ca.der"), &stranger.cert_der).unwrap();
    let o = w.run(&tls_args("worker-a", &k2, "example-*", &point), Who::Deployer);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay allow: credentials/relay-ca.env does not hold the key of state/relay-ca.der: make a new CA with ai-env relay tls init --force"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "", "no certificate");
    assert_eq!(w.param(WORKERS).unwrap(), held, "nothing written");
    fs::write(w.bridge().join("state").join("relay-ca.der"), &ca).unwrap();
    // No CA on this Mac: exit 5 naming tls init, no Touch ID.
    let bare = World::new();
    let o = bare.run(&tls_args("worker-a", &k1, "example-*", &point), Who::Deployer);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(stderr(&o).contains("relay allow: state/relay-ca.der does not exist: make the relay CA with ai-env relay tls init"), "{}", stderr(&o));
    assert!(bare.age_calls("-d") == 0 && bare.param(WORKERS).is_none(), "no Touch ID, nothing written");
    // Exit 2, before the gate: a text that is no point, --tls-key beside --token-signer.
    let off_curve = format!("p256:{}", {
        use base64::Engine as _;
        let mut point = vec![0x04u8];
        point.extend([1u8; 64]);
        base64::engine::general_purpose::STANDARD.encode(point)
    });
    for bad in ["p256:short", "ed25519:AAAA", "", off_curve.as_str()] {
        let o = w.run(&tls_args("worker-a", &k1, "example-*", bad), Who::Nobody);
        assert_eq!(code(&o), 2, "{bad:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("relay allow: --tls-key is not a P-256 public point's text, p256:<base64 of 65 bytes> (93 characters), as tls-keygen prints it"), "{bad:?}: {}", stderr(&o));
    }
    let o = w.run(&["allow", "mac", "--token-signer", "--key", &k7, "--tls-key", &point], Who::Deployer);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(w.aws_calls().is_empty() && w.age_calls("-d") == 0);
    // Its help (§RS.4.1).
    let o = w.run(&["allow", "--help"], Who::Nobody);
    let help = stdout(&o).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(help.contains("--tls-key <P256>") && help.contains("Issue the worker a client certificate for this P-256 point, p256:<base64>, as tls-keygen printed it (one Touch ID: the relay CA)"), "{help}");
    // R-131: a new CA strands every client certificate as it strands every relay_ca file, and init says so.
    let o = w.run(&["tls", "init"], Who::Deployer);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("every worker's relay_ca file and client certificate must then be replaced"), "{}", stderr(&o));
    let o = w.run(&["tls", "init", "--force"], Who::Deployer);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("every worker's relay_ca file and client certificate must then be replaced"), "{}", stdout(&o));
    let new_ca = fs::read(w.bridge().join("state").join("relay-ca.der")).unwrap();
    assert!(!verifies_under(&new_ca, &der2, now), "the old certificate is stranded");
}

/// The `filter-log-events` answer holding these lines of the request log.
fn log_answer(lines: &[serde_json::Value]) -> String {
    let events: Vec<serde_json::Value> = lines.iter().enumerate().map(|(i, l)| serde_json::json!({"logStreamName": format!("{INSTANCE}/requests"), "timestamp": 1_793_268_000_000u64 + i as u64, "message": l.to_string(), "ingestionTime": 1_793_268_000_100u64, "eventId": i.to_string()})).collect();
    serde_json::json!({"events": events}).to_string()
}

/// A status line of a relay: its `client_certs` when given (an older relay's line has no such key, R-132), its peers
/// list's keys when `peers`.
fn status_of(client_certs: Option<bool>, peers: bool) -> serde_json::Value {
    let mut line = serde_json::json!({"ts": "2026-10-29T10:00:00.000Z", "ev": "status", "relay_version": "0.12.0", "protocol": 1, "uptime_s": 600, "tunnels": 2, "sources_live": 3, "sources_offline": 0, "calls_in_flight": 0, "sessions": 1, "workers_version": "0123456789abcdef", "workers_age_s": 30, "signers_version": "1123456789abcdef", "signers_age_s": 31, "grants_version": "2123456789abcdef", "grants_age_s": 32, "tls_loaded": true, "unknown_frames": 0, "log_dropped": 0, "log_suppressed": 0});
    if peers {
        line["peers_version"] = serde_json::json!("3123456789abcdef");
        line["peers_age_s"] = serde_json::json!(33);
    }
    if let Some(on) = client_certs {
        line["client_certs"] = serde_json::json!(on);
    }
    line
}

/// One `relay status` world: the instance running, SSM online, this Mac a token signer, every list valid, the three log
/// reads (the status line, the refused hour, the reload's why=disk) answered in order.
struct StatusWorld {
    w: World,
}

impl StatusWorld {
    fn new() -> StatusWorld {
        let w = World::new();
        w.answer("ec2.describe-instances.json", &instance_doc("running"));
        w.answer("ssm.describe-instance-information.json", &ping_doc(Some("Online")));
        assert_eq!(code(&w.run(&["keygen"], Who::Nobody)), 0);
        let (_, session) = sealed_keys(&w);
        let o = w.run(&["allow", "mac", "--token-signer", "--key", &session.text()], Who::Deployer);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        for name in [WORKERS, GRANTS] {
            w.set_param(name, "[]", 1);
        }
        w.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "office", IN_FORCE)]), 1);
        let s = StatusWorld { w };
        s.logs(status_of(Some(false), true), &[], &[]);
        s
    }

    /// The three log reads' answers: the status line, the lines of the refused hour, the reload's.
    fn logs(&self, status: serde_json::Value, refused: &[serde_json::Value], reload: &[&str]) {
        self.w.answer("logs.filter-log-events.1.json", &log_answer(&[status]));
        self.w.answer("logs.filter-log-events.2.json", &log_answer(refused));
        let events: Vec<serde_json::Value> = reload.iter().enumerate().map(|(i, l)| serde_json::json!({"logStreamName": format!("{INSTANCE}/reload"), "timestamp": 1_793_268_000_000u64 + 60_000 * i as u64, "message": l, "ingestionTime": 1_793_268_000_100u64, "eventId": i.to_string()})).collect();
        self.w.answer("logs.filter-log-events.3.json", &serde_json::json!({"events": events}).to_string());
    }

    /// `relay status` as ops: its exit, its rows.
    fn status(&self) -> (i32, String) {
        let o = self.w.run(&["status"], Who::Ops);
        (code(&o), stdout(&o))
    }

    /// `relay status --json` as ops: its exit, its object.
    fn json(&self) -> (i32, serde_json::Value) {
        let o = self.w.run(&["status", "--json"], Who::Ops);
        let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap_or_else(|e| panic!("{e}: {}\n{}", stdout(&o), stderr(&o)));
        (code(&o), doc)
    }
}

/// WM-T60 (§RS.3.2, R-97, R-139, R-95, R-132, §RS.3.1): `relay status` shows the peers list, the workers' certificates,
/// the refused hour and the disk, from fake lists and fake log lines. The probe's three rows are
/// `ops::tests::the_probe_tells_a_refusal_from_an_open_port_and_no_connect`'s: the command dials port 443 only, which a
/// test cannot bind; here its word and its row agree, whichever 127.0.0.1:443 gives.
#[test]
fn relay_status_shows_the_peers_the_certificates_and_the_refused_hour() {
    let s = StatusWorld::new();
    let w = &s.w;
    // The peers list in force, its rows and its JSON, the probe's word with its row, and the rows in §RS.3.2's order.
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    let order = ["[ok ] keys: sealed", "[-  ] agent:", "[ok ] instance ", "[ok ] ssm: Online", "probe: 127.0.0.1:443", "[ok ] relay 0.12.0: ", "refused in the last hour:", &format!("{WORKERS} v1"), &format!("{SIGNERS} v1"), "this Mac's session key", &format!("{GRANTS} v1"), &format!("[ok ] {PEERS} v1")];
    let at: Vec<usize> = order.iter().map(|t| out.find(t).unwrap_or_else(|| panic!("{t}\n{out}"))).collect();
    assert!(at.windows(2).all(|p| p[0] < p[1]), "not in §RS.3.2's order: {at:?}\n{out}");
    assert!(out.contains(&format!("[ok ] {PEERS} v1: 1 peer(s), 1 in force\n[-  ]   peer office 198.51.100.0/24 until {IN_FORCE}\n")), "{out}");
    assert!(out.contains("grants 2123456789abcdef (32 s old), peers 3123456789abcdef (33 s old)\n"), "{out}");
    let (rc, doc) = s.json();
    assert_eq!(rc, 0, "{doc}");
    assert_eq!(doc.as_object().map(serde_json::Map::len), Some(7), "{doc}");
    for key in SEVEN_KEYS {
        assert!(doc.get(key).is_some(), "{key}: {doc}");
    }
    assert_eq!(doc["peers"], serde_json::json!([{"label": "office", "cidr": "198.51.100.0/24", "not_after": IN_FORCE, "expired": false}]));
    let word = doc["instance"]["probe"].as_str().unwrap();
    let row = match word {
        "refused" => "[warn] probe: 127.0.0.1:443 closed the connection before TLS: this Mac's address is not in /ai-env/relay/peers, or is banned (ai-env relay allow-ip --mine)",
        "open" => "[ok ] probe: 127.0.0.1:443 accepts a TCP connection",
        "closed" => "[warn] probe: 127.0.0.1:443 did not accept a TCP connection within 3 s (",
        "not_listening" => "[warn] probe: 127.0.0.1:443 refused the connection: nothing listens there, so the relay is not running or is still booting (make relay-logs)",
        other => panic!("{other}"),
    };
    let (_, out) = s.status();
    assert!(out.contains(row), "{word}: {out}");
    // An older relay's line: no peers version, and nothing more. A line with an empty one: no peers file loaded, whatever
    // row 8 reads in SSM, so a warning of its own; never the exit code.
    let not_loaded = "[warn] relay: its peers list is not loaded: it admits no worker\n";
    assert!(!out.contains(not_loaded), "{out}");
    s.logs(status_of(None, false), &[], &[]);
    let (_, out) = s.status();
    assert!(out.contains("grants 2123456789abcdef (32 s old), peers -\n") && !out.contains(not_loaded), "{out}");
    let mut unloaded = status_of(None, true);
    unloaded["peers_version"] = serde_json::json!("");
    s.logs(unloaded, &[], &[]);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains(&format!("grants 2123456789abcdef (32 s old), peers -\n{not_loaded}")), "{out}");
    assert!(out.contains(&format!("[ok ] {PEERS} v1: 1 peer(s), 1 in force\n")), "row 8 stands: {out}");
    // The peers list absent: [NO ], exit 1, `[]`.
    let held = w.param(PEERS).unwrap();
    let peers_file = w.root().join("ssm").join(PEERS.trim_start_matches('/'));
    fs::remove_file(&peers_file).unwrap();
    fs::remove_file(format!("{}.version", peers_file.display())).unwrap();
    let (rc, out) = s.status();
    assert_eq!(rc, 1, "{out}");
    assert!(out.contains(&format!("[NO ] {PEERS}: absent: the relay admits no worker (ai-env relay allow-ip creates it)\n")), "{out}");
    let (_, doc) = s.json();
    assert_eq!(doc["peers"], serde_json::json!([]), "{doc}");
    // Not parsing: [NO ], exit 1, `null`.
    w.set_param(PEERS, "[{\"cidr\":\"not a network\"}]", 3);
    let (rc, out) = s.status();
    assert_eq!(rc, 1, "{out}");
    assert!(out.contains(&format!("[NO ] {PEERS} v3 does not parse (")), "{out}");
    let (_, doc) = s.json();
    assert!(doc["peers"].is_null(), "{doc}");
    // No entry in force, mac among them: [NO ], exit 1, each entry shown, its lapse named.
    w.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "office", LAPSED), ("203.0.113.7/32", "mac", LAPSED)]), 4);
    let (rc, out) = s.status();
    assert_eq!(rc, 1, "{out}");
    assert!(out.contains(&format!("[NO ] {PEERS} v4: 2 peer(s), none in force: the relay admits no worker\n")), "{out}");
    assert!(out.contains(&format!("[-  ]   peer office 198.51.100.0/24 until {LAPSED} EXPIRED\n")), "{out}");
    assert!(out.contains(&format!("[warn] peer mac lapsed at {LAPSED}: this Mac's worker is refused (ai-env relay allow-ip --mine)\n")), "{out}");
    // Another in force, mac lapsed: [ok ], and the warning alone; never the exit code.
    w.set_param(PEERS, &peers_value(&[("198.51.100.0/24", "office", IN_FORCE), ("203.0.113.7/32", "mac", LAPSED)]), 5);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains(&format!("[ok ] {PEERS} v5: 2 peer(s), 1 in force\n")), "{out}");
    assert!(out.contains(&format!("[warn] peer mac lapsed at {LAPSED}: this Mac's worker is refused (ai-env relay allow-ip --mine)\n")), "{out}");
    let (_, doc) = s.json();
    assert_eq!(doc["peers"][0], serde_json::json!({"label": "mac", "cidr": "203.0.113.7/32", "not_after": LAPSED, "expired": true}), "{doc}");
    // A /8 entry in force warns, a /16 does not, a lapsed /8 does not.
    w.set_param(PEERS, &peers_value(&[("198.0.0.0/8", "wide", IN_FORCE), ("192.0.0.0/16", "broad", IN_FORCE), ("203.0.0.0/8", "old", LAPSED)]), 6);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("[warn] peer wide 198.0.0.0/8 is wider than /16: it admits much of the internet (ai-env relay revoke-ip --label wide)\n"), "{out}");
    assert!(!out.contains("peer broad 192.0.0.0/16 is wider") && !out.contains("peer old 203.0.0.0/8 is wider"), "{out}");
    w.set_param(PEERS, &held.0, held.1);
    // Row 8's own read: a denial is [?? ] for it alone, exit 7; rows 5 to 7 stand, read by their own call.
    w.answer("ssm.get-parameters.2.rc", "254");
    w.answer("ssm.get-parameters.2.stderr", "\nAn error occurred (AccessDeniedException) when calling the GetParameters operation: not authorized\n");
    let (rc, out) = s.status();
    assert_eq!(rc, 7, "{out}");
    assert!(out.contains(&format!("[?? ] {PEERS} could not be read (")) && out.contains("AccessDeniedException"), "{out}");
    assert_eq!(out.matches("[?? ]").count(), 1, "for it alone: {out}");
    assert!(out.contains(&format!("[ok ] {WORKERS} v1")) && out.contains(&format!("[ok ] {GRANTS} v1")) && out.contains(&format!("[ok ] {SIGNERS} v")), "{out}");
    let names: Vec<String> = w.aws_calls().into_iter().filter(|c| c.starts_with("ssm get-parameters")).collect();
    assert_eq!(names.len(), 2, "two reads: {names:?}");
    assert!(names[0].contains(WORKERS) && names[0].contains(SIGNERS) && names[0].contains(GRANTS) && !names[0].contains(PEERS), "{names:?}");
    assert!(names[1].contains(&format!("--names {PEERS} ")) && !names[1].contains(WORKERS), "{names:?}");
    let (rc, doc) = s.json();
    assert_eq!(rc, 7, "{doc}");
    assert!(doc["peers"].is_null() && doc["workers"].is_array(), "{doc}");
    w.unanswer("ssm.get-parameters.2.rc");
    w.unanswer("ssm.get-parameters.2.stderr");
    // A worker with no certificate: [NO ] under `client_certs: true`, naming the command with its key and globs.
    let entry = |id: &str, seed: u8, not_after: &str, tls_fp: Option<String>| policy::WorkerEntry { worker_id: id.into(), alg: "ed25519".into(), public_key: key_of(seed).b64(), sources: vec!["example-*".into(), "other".into()], not_after: not_after.into(), tls_fp };
    let cert = "ab".repeat(32);
    let list = [entry("worker-a", 1, IN_FORCE, None), entry("worker-b", 2, IN_FORCE, Some(cert.clone())), entry("worker-c", 3, LAPSED, None)];
    w.set_param(WORKERS, &policy::render_workers(&list).unwrap(), 2);
    let command = format!("on the worker: tls-keygen; then ai-env as deployer -- ai-env relay allow worker-a --key {} --sources 'example-*,other' --tls-key <its p256 text>", key_text(1));
    let no = format!("[NO ] worker worker-a has no client certificate: the relay refuses it ({command})\n");
    let warned = format!("[warn] worker worker-a has no client certificate yet: a relay that requires client certificates would refuse it ({command})\n");
    s.logs(status_of(Some(true), true), &[], &[]);
    let (rc, out) = s.status();
    assert_eq!(rc, 1, "a finding: {out}");
    assert!(out.contains(&no) && !out.contains(&warned), "{out}");
    assert!(out.contains(&format!("[-  ]   worker worker-a (key fp {}, no cert fp) for sources example-*,other until {IN_FORCE}\n", key_of(1).fingerprint())), "{out}");
    assert!(out.contains(&format!("[-  ]   worker worker-b (key fp {}, cert fp {}) for sources example-*,other until {IN_FORCE}\n", key_of(2).fingerprint(), &cert[..16])), "{out}");
    assert!(out.contains(&format!("[-  ]   worker worker-c (key fp {}, no cert fp) for sources example-*,other until {LAPSED} EXPIRED\n", key_of(3).fingerprint())), "{out}");
    assert!(!out.contains("worker worker-b has no client") && !out.contains("worker worker-c has no client"), "in force and without one alone: {out}");
    let (_, doc) = s.json();
    let certs: Vec<&serde_json::Value> = doc["workers"].as_array().unwrap().iter().map(|e| &e["cert_fp"]).collect();
    assert_eq!(certs, [&serde_json::Value::Null, &serde_json::json!(cert[..16]), &serde_json::Value::Null], "{doc}");
    assert!(doc["workers"].as_array().unwrap().iter().all(|e| e.get("cert_fp").is_some()), "the key on each: {doc}");
    // [warn] under `false`, without the key, and when the line was not read; never the exit code.
    for status in [status_of(Some(false), true), status_of(None, true)] {
        s.logs(status, &[], &[]);
        let (rc, out) = s.status();
        assert_eq!(rc, 0, "{out}");
        assert!(out.contains(&warned) && !out.contains(&no), "{out}");
    }
    w.answer("logs.filter-log-events.1.json", "{\"events\": []}");
    let (rc, out) = s.status();
    assert!(rc == 0 && out.contains("[warn] relay: no status line in 10 min") && out.contains(&warned), "{out}");
    // A relay from before the plan (no peers_version): no command at all, since running it now would unload that relay's
    // whole whitelist (RO-3).
    s.logs(status_of(None, false), &[], &[]);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("[warn] worker worker-a has no client certificate yet: a relay that requires client certificates would refuse it (not yet: this relay refuses a list with tls_fp and unloads its whole whitelist (RO-3))\n"), "{out}");
    assert!(!out.contains("--tls-key") && !out.contains("tls-keygen"), "{out}");
    w.set_param(WORKERS, "[]", 3);
    // The refused hour from fake lines: N, M, P, B, U and the top reasons, each with its suppressed, in text and JSON;
    // [warn] for N > 0, never the exit code. The two reads name their streams, windows and filters.
    let tunnel = |peer: &str, reason: &str, suppressed: u64| serde_json::json!({"ts": "2026-10-29T10:00:00.000Z", "ev": "tunnel", "tunnel": "", "worker": "", "peer": peer, "sdk": "", "phase": "auth", "outcome": "refused", "reason": reason, "sources": 0, "duration_ms": 0, "suppressed": suppressed});
    let peer = |face: &str, peer: &str, reason: &str, suppressed: u64| serde_json::json!({"ts": "2026-10-29T10:00:00.000Z", "ev": "peer", "face": face, "peer": peer, "reason": reason, "suppressed": suppressed});
    let lines = [
        tunnel("198.51.100.1", "bad_signature", 4),
        tunnel("198.51.100.1", "bad_signature", 0),
        tunnel("198.51.100.2", "unknown_worker", 1),
        peer("public", "203.0.113.50", "not_in_peers", 100),
        peer("public", "203.0.113.51", "no_peers", 2),
        peer("public", "198.51.100.3", "banned", 1),
        peer("public", "198.51.100.3", "banned", 0),
        peer("public", "198.51.100.4", "banned", 0),
        peer("public", "198.51.100.5", "tls_failed", 0),
        peer("private", "192.0.2.9", "auth_timeout", 0),
    ];
    s.logs(status_of(Some(false), true), &lines, &[]);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "never the exit code: {out}");
    assert!(out.contains("[warn] refused in the last hour: 8 handshake(s) from 2 address(es), 6 connection(s) refused or cut, 2 address(es) banned, 104 connection(s) from unlisted addresses; top reasons: banned 3, bad_signature 2, auth_timeout 1\n"), "{out}");
    let logs: Vec<String> = w.aws_calls().into_iter().filter(|c| c.starts_with("logs filter-log-events")).collect();
    assert_eq!(logs.len(), 3, "{logs:?}");
    assert!(logs[1].contains(&format!("--log-group-name /ai-env/relay --log-stream-names {INSTANCE}/requests --start-time ")) && logs[1].contains(r#"--filter-pattern { ($.ev = "peer") || ($.ev = "tunnel" && $.outcome = "refused") }"#), "{}", logs[1]);
    assert!(logs[2].contains(&format!("--log-group-name /ai-env/relay --log-stream-names {INSTANCE}/reload --start-time ")) && logs[2].contains(r#"--filter-pattern "why=disk""#), "{}", logs[2]);
    let start = |call: &str| -> u64 {
        let mut words = call.split_whitespace();
        words.find(|w| *w == "--start-time");
        words.next().unwrap().parse().unwrap()
    };
    let now_ms = ai_env_cli::wire::time::unix_now() * 1000;
    assert!(now_ms.abs_diff(start(&logs[1]) + 3_600_000) < 60_000 && now_ms.abs_diff(start(&logs[2]) + 600_000) < 60_000, "the last 3600 s, the last 600 s: {logs:?}");
    let (rc, doc) = s.json();
    assert_eq!(rc, 0, "{doc}");
    assert_eq!(doc["instance"]["refused"], serde_json::json!({"handshakes": 8, "addresses": 2, "connections": 6, "banned": 2, "unlisted": 104, "top": [{"reason": "banned", "count": 3}, {"reason": "bad_signature", "count": 2}, {"reason": "auth_timeout", "count": 1}]}), "{doc}");
    // [ok ] for unlisted scanners alone, and the private face's cuts; none at all: `top reasons: none`.
    let scanners = [peer("public", "203.0.113.50", "not_in_peers", 5000), peer("public", "203.0.113.51", "no_peers", 0)];
    s.logs(status_of(Some(false), true), &scanners, &[]);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("[ok ] refused in the last hour: 0 handshake(s) from 0 address(es), 0 connection(s) refused or cut, 0 address(es) banned, 5002 connection(s) from unlisted addresses; top reasons: none\n"), "{out}");
    s.logs(status_of(Some(false), true), &[peer("private", "192.0.2.9", "idle", 0)], &[]);
    let (_, out) = s.status();
    assert!(out.contains("[ok ] refused in the last hour: 0 handshake(s) from 0 address(es), 1 connection(s) refused or cut, 0 address(es) banned, 0 connection(s) from unlisted addresses; top reasons: idle 1\n"), "{out}");
    s.logs(status_of(Some(false), true), &[peer("public", "198.51.100.3", "banned", 0)], &[]);
    let (rc, out) = s.status();
    assert!(rc == 0 && out.contains("[warn] refused in the last hour: 0 handshake(s) from 0 address(es), 1 connection(s) refused or cut, 1 address(es) banned, "), "B > 0 warns: {out}");
    // A failed read warns, never the exit code; `null`.
    s.logs(status_of(Some(false), true), &[], &[]);
    let denied = "\nAn error occurred (AccessDeniedException) when calling the FilterLogEvents operation: not authorized\n";
    w.answer("logs.filter-log-events.2.rc", "254");
    w.answer("logs.filter-log-events.2.stderr", denied);
    w.unanswer("logs.filter-log-events.2.json");
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("[warn] relay: the refusals of the last hour could not be read (") && out.contains("AccessDeniedException"), "{out}");
    let (rc, doc) = s.json();
    assert!(rc == 0 && doc["instance"]["refused"].is_null(), "{doc}");
    w.unanswer("logs.filter-log-events.2.rc");
    w.unanswer("logs.filter-log-events.2.stderr");
    // The disk: a fake reload line warns with its time, the newest; none adds no row, `false`; a failed read warns, `null`.
    let reload = "ai-env-relay-reload: ok fetched=2026-10-29T10:00:00Z changed=none absent=none artifact=none tls=present relay=active why=disk";
    s.logs(status_of(Some(false), true), &[], &[reload, reload]);
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "never the exit code: {out}");
    let at = ai_env_cli::wire::time::rfc3339_utc((1_793_268_000_000u64 + 60_000) / 1000);
    assert!(out.contains(&format!("[warn] relay: the root volume is over 90 % full (the reload's why=disk at {at})\n")), "{out}");
    let (rc, doc) = s.json();
    assert!(rc == 0 && doc["instance"]["disk_full"] == serde_json::json!(true), "{doc}");
    s.logs(status_of(Some(false), true), &[], &[]);
    let (rc, out) = s.status();
    assert!(rc == 0 && !out.contains("root volume") && !out.contains("reload's"), "{out}");
    let (_, doc) = s.json();
    assert_eq!(doc["instance"]["disk_full"], serde_json::json!(false), "{doc}");
    w.answer("logs.filter-log-events.3.rc", "254");
    w.answer("logs.filter-log-events.3.stderr", denied);
    w.unanswer("logs.filter-log-events.3.json");
    let (rc, out) = s.status();
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("[warn] relay: the reload's log could not be read (") && out.contains("AccessDeniedException"), "{out}");
    let (rc, doc) = s.json();
    assert!(rc == 0 && doc["instance"]["disk_full"].is_null(), "{doc}");
    // A stopped relay: neither row, nor a read of the log; both keys `null`, not absent.
    let unread = |doc: &serde_json::Value| (doc["instance"].get("refused").cloned(), doc["instance"].get("disk_full").cloned()) == (Some(serde_json::Value::Null), Some(serde_json::Value::Null));
    w.answer("ec2.describe-instances.json", &instance_doc("stopped"));
    let (rc, out) = s.status();
    assert_eq!(rc, 1, "{out}");
    assert!(!out.contains("refused in the last hour") && !w.aws_calls().iter().any(|c| c.starts_with("logs ")), "{out}");
    let (rc, doc) = s.json();
    assert!(rc == 1 && unread(&doc), "{doc}");
    // An instance that could not be read: the same.
    w.unanswer("ec2.describe-instances.json");
    w.answer("ec2.describe-instances.rc", "254");
    w.answer("ec2.describe-instances.stderr", "\nAn error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: not authorized\n");
    let (rc, doc) = s.json();
    assert!(rc == 7 && unread(&doc), "{doc}");
}
