//! A1 (several Claude accounts, one active): `ai-env creds account
//! add|use|list|forget`, and what the sealing commands do with accounts
//! (`creds setup-token`, `creds aws-set`, `creds status`, `creds forget`),
//! through the binary on the `creds aws-set` harness (tests/infra/creds.rs):
//! the fake age (hex "encryption", one `age -d` log line per Touch ID), a
//! fake keystore key, one temp tree. Every token is built at run time with a
//! per-test tail; every test ends by checking that no token's random part,
//! nor any 16-byte piece of it, is on disk in the clear or in an output of a
//! run that held it. Assertion messages print lengths, or text the scrubber
//! has masked, never a value.
use super::common::*;
use super::creds::{assert_nowhere, assert_unprinted, audit_rows, key_json, mode, piped, test_key, wait_bounded, Env, TestKey, KEY, USER};
use ai_env_cli::bridge::config::Paths;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

const PREFIX: &str = "sk-ant-oat01-";

/// A token of the setup-token shape, ending in `tail`.
fn token(tail: &str) -> String {
    format!("{PREFIX}{}{tail}", "Ac7_".repeat(20))
}

/// The part of `t` after its kind prefix: what must never be seen.
fn random_part(t: &str) -> &str {
    &t[PREFIX.len()..]
}

/// `text` for an assertion message: the scrubber masks any token or key in it.
fn shown(text: &str) -> String {
    ai_env_cli::wire::redact::scrub(text).into_owned()
}

fn ok(out: &Output) {
    assert_eq!(out.status.code(), Some(0), "stdout {} stderr {}", shown(&stdout(out)), shown(&stderr(out)));
}

/// `ai-env creds account <args>`.
fn account(env: &Env, args: &[&str]) -> Output {
    let mut all = vec!["account"];
    all.extend_from_slice(args);
    run(&mut env.creds(&all))
}

/// `creds account add NAME --stdin <extra>` with `t` on the pipe.
fn add(env: &Env, name: &str, t: &str, extra: &[&str]) -> Output {
    let mut args = vec!["account", "add", name, "--stdin"];
    args.extend_from_slice(extra);
    piped(&mut env.creds(&args), format!("{t}\n").as_bytes())
}

/// `creds setup-token --stdin` with `t` on the pipe.
fn seal(env: &Env, t: &str) -> Output {
    piped(&mut env.creds(&["setup-token", "--stdin"]), format!("{t}\n").as_bytes())
}

/// `creds aws-set` with `key` on the pipe.
fn aws_set(env: &Env, key: &TestKey) -> Output {
    piped(&mut env.creds(&["aws-set"]), key_json(USER, key, "Active").as_bytes())
}

/// How many decrypts (Touch IDs) the fake age has served.
fn decrypts(env: &Env) -> usize {
    fs::read_to_string(env.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
}

fn paths(env: &Env) -> Paths {
    Paths::from_root_and_env(env.root().join("bridge"), None)
}

fn bytes(p: &Path) -> Option<Vec<u8>> {
    fs::read(p).ok()
}

/// The audit rows of `event`.
fn rows(env: &Env, event: &str) -> Vec<serde_json::Value> {
    audit_rows(env).into_iter().filter(|r| r["event"] == event).collect()
}

/// The seal id of the file at `p`.
fn tag(p: &Path) -> String {
    ai_env_cli::bridge::agent::credential::seal_tag(p).expect("a sealed file")
}

/// What `container` decrypts to with the fake age, as text.
fn opened(env: &Env, container: &Path) -> String {
    env.open(&fs::read_to_string(container).unwrap())
}

/// `got == want` for texts that hold a credential: a failure prints their lengths only.
fn assert_same(got: &str, want: &str, what: &str) {
    assert!(got == want, "{what}: {} bytes where {} were expected", got.len(), want.len());
}

/// No output of `outs` holds a piece of any of `tokens`, nor does a file under the tree.
fn swept(env: &Env, outs: &[Output], tokens: &[&String]) {
    for t in tokens {
        for out in outs {
            assert_unprinted(out, random_part(t), "a token");
        }
        assert_nowhere(env.root(), random_part(t), "a token");
    }
}

/// A tree with the runtime key and Claude account `default` sealed by the
/// real commands (`creds setup-token`, which makes `default`): its token.
fn world(tail: &str) -> (Env, String, Vec<Output>) {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let key = test_key("ACC1");
    let mut outs = vec![aws_set(&env, &key)];
    let t = token(tail);
    outs.push(seal(&env, &t));
    outs.iter().for_each(ok);
    (env, t, outs)
}

/// A legacy tree (`setup-token.env` and its `combined.env` sealed before
/// accounts existed) is adopted by the first `creds account` command as
/// `default`, by byte copy, with no Touch ID and one audit row; `creds
/// status` and doctor's reads never adopt.
#[test]
fn a_legacy_token_is_adopted_with_no_touch_id() {
    let (env, t, mut outs) = world("Lg");
    let p = paths(&env);
    // Back to a legacy tree: the installed pair alone.
    fs::remove_dir_all(p.accounts_dir()).unwrap();
    fs::remove_file(p.accounts_state()).unwrap();
    let (installed, pair) = (bytes(&p.setup_token_env()), bytes(&p.combined_env()));
    let before = decrypts(&env);
    let out = run(&mut env.creds(&["status"]));
    ok(&out);
    assert!(!p.accounts_dir().exists() && !p.accounts_state().exists(), "status never adopts");
    assert!(!stdout(&out).contains("Claude account"), "a legacy tree has no account: {}", shown(&stdout(&out)));
    outs.push(out);
    let out = account(&env, &["list"]);
    ok(&out);
    assert_eq!(decrypts(&env), before, "no Touch ID");
    assert_eq!(bytes(&p.account_env("default")), installed, "a byte copy: the same seal");
    assert_eq!(bytes(&p.account_combined_env("default")), pair, "its current combined.env with it");
    assert_eq!((bytes(&p.setup_token_env()), bytes(&p.combined_env())), (installed, pair), "the installed pair untouched");
    assert!(stdout(&out).starts_with(&format!("[ok ] default (active): seal {}, {PREFIX}… ({} chars), sealed ", tag(&p.setup_token_env()), t.len())), "{}", shown(&stdout(&out)));
    assert!(stdout(&out).contains("; combined.env current"), "{}", shown(&stdout(&out)));
    let adopted = rows(&env, "creds_account_adopt");
    assert_eq!((adopted.len(), adopted[0]["detail"]["name"].as_str(), adopted[0]["detail"]["combined"].as_str()), (1, Some("default"), Some("copied")));
    outs.push(out);
    let out = account(&env, &["list"]);
    ok(&out);
    assert_eq!(rows(&env, "creds_account_adopt").len(), 1, "adopted once");
    outs.push(out);
    swept(&env, &outs, &[&t]);
}

/// `add` seals a second account with one Touch ID (the runtime key, for
/// its own combined container), its notes naming it, 0600 in the 0700
/// directory, and leaves the active account installed; `use` then
/// installs it by byte copy with no Touch ID (combined.env too), and back.
#[test]
fn add_costs_one_touch_id_and_use_none() {
    let (env, t1, mut outs) = world("Ad");
    let p = paths(&env);
    let default = (bytes(&p.setup_token_env()), bytes(&p.combined_env()));
    let t2 = token("Wk");
    let before = decrypts(&env);
    let out = add(&env, "work", &t2, &[]);
    ok(&out);
    assert_eq!(decrypts(&env), before + 1, "one Touch ID: the runtime key");
    let text = stdout(&out);
    assert!(text.starts_with(&format!("sealed setup-token {PREFIX}… ({} chars) into {} (key {KEY}) as Claude account work\n", t2.len(), p.account_env("work").display())), "{}", shown(&text));
    assert!(text.contains("Claude account work is not the active one (default is): `ai-env creds account use work` makes it active\n"), "{}", shown(&text));
    assert!(text.ends_with(&format!("rebuilt {}: Claude account work is not the installed one (`ai-env creds account use work` installs it with this)\n", p.account_combined_env("work").display())), "{}", shown(&text));
    assert_eq!((mode(&p.account_env("work")), mode(&p.accounts_dir()), mode(&p.account_combined_env("work"))), (0o600, 0o700, 0o600));
    let meta = ai_env_cli::container::meta(&fs::read_to_string(p.account_env("work")).unwrap());
    assert_eq!((meta["account"].as_str(), meta["kind"].as_str()), ("work", "setup-token"));
    assert_same(&opened(&env, &p.account_env("work")), &format!("CLAUDE_CODE_OAUTH_TOKEN={t2}\n"), "work's sealed plaintext");
    assert_eq!((bytes(&p.setup_token_env()), bytes(&p.combined_env())), default.clone(), "the active one stays installed");
    let sealed = rows(&env, "creds_setup_token");
    let last = sealed.last().unwrap();
    assert_eq!((last["detail"]["account"].as_str(), last["detail"]["installed"].as_str()), (Some("work"), Some("false")));
    let built = rows(&env, "creds_combined");
    assert_eq!((built.last().unwrap()["detail"]["by"].as_str(), built.last().unwrap()["detail"]["account"].as_str()), (Some("account-add"), Some("work")));
    outs.push(out);

    let before = decrypts(&env);
    let out = account(&env, &["use", "work"]);
    ok(&out);
    assert_eq!(decrypts(&env), before, "no Touch ID");
    assert_eq!(bytes(&p.setup_token_env()), bytes(&p.account_env("work")), "a byte copy");
    assert_eq!(bytes(&p.combined_env()), bytes(&p.account_combined_env("work")), "its combined.env with it");
    assert!(
        stdout(&out) == format!("Claude account work is the active one now, in place of default: installed as {}, with its combined.env: a credentialed command asks for Touch ID once\nnew chats, moves and credentialed commands use it; a running claude keeps its own token until its next start\n", p.setup_token_env().display()),
        "{}",
        shown(&stdout(&out))
    );
    let used = rows(&env, "creds_account_use");
    let d = &used[0]["detail"];
    assert_eq!((d["from"].as_str(), d["to"].as_str(), d["tag"].as_str(), d["combined"].as_str(), d["chats_other"].as_str()), (Some("default"), Some("work"), Some(tag(&p.account_env("work")).as_str()), Some("installed"), Some("0")));
    let status = run(&mut env.creds(&["status"]));
    ok(&status);
    let text = stdout(&status);
    assert!(text.contains("; the installed copy of Claude account work\n") && text.contains("[ok ] combined.env: matches its sources") && text.contains("[ok ] Claude account work (active): ") && text.contains("[ok ] Claude account default: "), "{}", shown(&text));
    assert!(!text.contains("[NO ]"), "{}", shown(&text));
    outs.extend([out, status]);
    let out = account(&env, &["use", "default"]);
    ok(&out);
    assert_eq!((bytes(&p.setup_token_env()), bytes(&p.combined_env())), default, "default's pair again");
    let out2 = account(&env, &["use", "default"]);
    ok(&out2);
    assert!(stdout(&out2).starts_with("Claude account default is the active one already: installed again as "), "{}", shown(&stdout(&out2)));
    outs.extend([out, out2]);
    let out = account(&env, &["list", "--json"]);
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!((v["active"].as_str(), v["store"].as_str(), v["installed"]["account"].as_str(), v["accounts"].as_array().map(Vec::len)), (Some("default"), Some("ok"), Some("default"), Some(2)));
    assert_eq!((v["accounts"][1]["name"].as_str(), v["accounts"][1]["active"].as_bool(), v["accounts"][1]["combined"].as_str()), (Some("work"), Some(false), Some("current")));
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2]);
}

/// L-8: `add --note`, `note NAME [TEXT]` and `rename OLD NEW` take no Touch
/// ID; a rename of the active account moves its files, row, note and mark
/// and keeps its seal and the installed copies byte for byte; the note's
/// text is in `state/accounts.toml` alone (the audit says only that it
/// changed), and `list` shows it after the title.
#[test]
fn rename_and_note_take_no_touch_id_and_keep_the_seal() {
    let (env, t1, mut outs) = world("Rn");
    let p = paths(&env);
    let t2 = token("Sp");
    let out = add(&env, "spare", &t2, &["--note", "second seat"]);
    ok(&out);
    assert!(stdout(&out).contains("Claude account spare's note is kept"), "{}", shown(&stdout(&out)));
    outs.push(out);
    let before = decrypts(&env);
    let installed = (bytes(&p.setup_token_env()), bytes(&p.combined_env()));
    let seal = tag(&p.account_env("default"));

    let out = account(&env, &["note", "default", "mk's Max seat"]);
    ok(&out);
    assert_eq!(stdout(&out), "Claude account default's note: set\n");
    let out2 = account(&env, &["note", "default", "mk's Max seat"]);
    ok(&out2);
    assert_eq!(stdout(&out2), "Claude account default's note: unchanged\n");
    outs.extend([out, out2]);

    let out = account(&env, &["rename", "default", "dfst"]);
    ok(&out);
    assert_eq!(stdout(&out), format!("renamed Claude account default (the active one) to dfst (seal {seal}): its installed copies, refusals and the VMs' caches are unchanged\n"));
    assert!(!p.account_env("default").exists() && !p.account_combined_env("default").exists(), "default's files moved");
    assert_eq!(tag(&p.account_env("dfst")), seal, "the same sealed bytes");
    assert_eq!((bytes(&p.setup_token_env()), bytes(&p.combined_env())), installed, "the installed pair untouched");
    let renamed = rows(&env, "creds_account_rename");
    assert_eq!((renamed[0]["detail"]["from"].as_str(), renamed[0]["detail"]["to"].as_str(), renamed[0]["detail"]["tag"].as_str()), (Some("default"), Some("dfst"), Some(seal.as_str())));
    outs.push(out);

    let out = account(&env, &["list"]);
    ok(&out);
    let text = stdout(&out);
    assert!(text.contains("[ok ] dfst (active) [mk's Max seat]: ") && text.contains("[ok ] spare [second seat]: "), "{}", shown(&text));
    outs.push(out);
    let out = account(&env, &["list", "--json"]);
    ok(&out);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!((v["active"].as_str(), v["accounts"][0]["name"].as_str(), v["accounts"][0]["note"].as_str()), (Some("dfst"), Some("dfst"), Some("mk's Max seat")));
    outs.push(out);

    // The text lives in the store alone; the audit says that it changed.
    let store = fs::read_to_string(p.accounts_state()).unwrap();
    assert!(store.contains("mk's Max seat") && store.contains("second seat"), "{store}");
    let audit = fs::read_to_string(p.audit()).unwrap();
    assert!(!audit.contains("Max seat") && !audit.contains("second seat"), "no note text in the audit");
    let noted = rows(&env, "creds_account_note");
    assert!(noted.iter().all(|r| r["detail"]["set"] == "set" || r["detail"]["set"] == "cleared"), "{noted:?}");

    let out = account(&env, &["note", "dfst"]);
    ok(&out);
    assert_eq!(stdout(&out), "Claude account dfst's note: cleared\n");
    assert!(!fs::read_to_string(p.accounts_state()).unwrap().contains("Max seat"), "cleared");
    let bad = account(&env, &["rename", "dfst", "spare"]);
    assert_eq!(bad.status.code(), Some(1), "an existing name: {}", shown(&stderr(&bad)));
    let bad2 = account(&env, &["note", "spare", &"x".repeat(121)]);
    assert_eq!(bad2.status.code(), Some(2), "a note over 120 characters");
    assert!(!stderr(&bad2).contains(&"x".repeat(121)), "never echoed");
    outs.extend([out, bad, bad2]);
    assert_eq!(decrypts(&env), before, "no Touch ID for rename or note");
    swept(&env, &outs, &[&t1, &t2]);
}

/// `creds aws-set` (`make runtime-key`) rebuilds every account's combined
/// container, one Touch ID each, the active one first, and installs the
/// active one's; a dismissed dialog leaves that account's absent (its row
/// says so) and the others built, and `use` of it installs no combined.env.
#[test]
fn aws_set_rebuilds_every_account_one_touch_id_each() {
    let (env, t1, mut outs) = world("Rb");
    let p = paths(&env);
    let (t2, t3) = (token("Rc"), token("Rd"));
    outs.push(add(&env, "spare", &t2, &[]));
    outs.push(add(&env, "work", &t3, &["--use"]));
    outs.iter().for_each(ok);
    std::thread::sleep(Duration::from_millis(1100));
    let key = test_key("ACC2");
    let before = (decrypts(&env), rows(&env, "creds_combined").len());
    let out = aws_set(&env, &key);
    ok(&out);
    assert_eq!(decrypts(&env), before.0 + 3, "one Touch ID per account");
    let built: Vec<serde_json::Value> = rows(&env, "creds_combined").split_off(before.1);
    let order: Vec<(&str, &str)> = built.iter().map(|r| (r["detail"]["account"].as_str().unwrap(), r["detail"]["outcome"].as_str().unwrap())).collect();
    assert_eq!(order, [("work", "built"), ("default", "built"), ("spare", "built")], "the active one first");
    let aws_sha = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(fs::read(p.aws_env()).unwrap()))
    };
    for name in ["default", "spare", "work"] {
        let meta = ai_env_cli::container::meta(&fs::read_to_string(p.account_combined_env(name)).unwrap());
        assert_eq!((meta["aws_file_sha256"].as_str(), meta["account"].as_str()), (aws_sha.as_str(), name), "{name}");
    }
    assert_eq!(bytes(&p.combined_env()), bytes(&p.account_combined_env("work")), "the active one's installed");
    assert!(stdout(&out).contains(&format!("rebuilt {}: a credentialed command asks for Touch ID once", p.combined_env().display())), "{}", shown(&stdout(&out)));
    outs.push(out);
    // A dismissed dialog: every combined container goes before any prompt, none is built. (The backup of
    // aws.env is named by a second of its own.)
    std::thread::sleep(Duration::from_millis(1100));
    let key3 = test_key("ACC3");
    let out = piped(env.creds(&["aws-set"]).env("FAKE_AGE_FAIL", "cancel"), key_json(USER, &key3, "Active").as_bytes());
    ok(&out);
    assert!(!p.combined_env().exists() && ["default", "spare", "work"].iter().all(|n| !p.account_combined_env(n).exists()), "none left pairing the replaced key");
    let err = stderr(&out);
    assert!(err.contains("warning: combined.env not built (") && err.contains("warning: accounts/spare.combined.env not built ("), "{}", shown(&err));
    outs.push(out);
    let out = account(&env, &["use", "spare"]);
    ok(&out);
    assert!(stdout(&out).contains(", without a current combined.env: a credentialed command asks for Touch ID twice until `make runtime-key` rebuilds it"), "{}", shown(&stdout(&out)));
    assert!(!p.combined_env().exists());
    assert_eq!(rows(&env, "creds_account_use").last().unwrap()["detail"]["combined"].as_str(), Some("absent"));
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2, &t3]);
}

/// `creds setup-token` seals the active account anew, its old seal kept as
/// its backup under `accounts/`, and installs it; the other accounts stay.
/// With accounts but none active it refuses (exit 9) before the token is
/// asked for.
#[test]
fn setup_token_seals_the_active_account_anew() {
    let (env, t1, mut outs) = world("Sa");
    let p = paths(&env);
    let t2 = token("Sb");
    outs.push(add(&env, "work", &t2, &["--use"]));
    ok(&outs[2]);
    let default = bytes(&p.account_env("default"));
    let t3 = token("Sc");
    // The backup of work.env is named by a second of its own.
    std::thread::sleep(Duration::from_millis(1100));
    let out = seal(&env, &t3);
    ok(&out);
    assert!(stdout(&out).contains(&format!("into {} (key {KEY}) as Claude account work\n", p.account_env("work").display())) && stdout(&out).contains("Claude account work stays the active one"), "{}", shown(&stdout(&out)));
    assert_same(&opened(&env, &p.setup_token_env()), &format!("CLAUDE_CODE_OAUTH_TOKEN={t3}\n"), "the installed copy");
    assert_eq!(bytes(&p.setup_token_env()), bytes(&p.account_env("work")));
    let baks: Vec<PathBuf> = fs::read_dir(p.accounts_dir()).unwrap().flatten().map(|e| e.path()).filter(|f| f.file_name().unwrap().to_string_lossy().starts_with("work.env.")).collect();
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert_same(&opened(&env, &baks[0]), &format!("CLAUDE_CODE_OAUTH_TOKEN={t2}\n"), "work's old seal");
    assert_eq!(bytes(&p.account_env("default")), default, "the other account stays");
    assert_eq!(bytes(&p.combined_env()), bytes(&p.account_combined_env("work")), "rebuilt and installed");
    outs.push(out);
    // None active: a forgotten one, and a token that would be a guess.
    let out = account(&env, &["forget", "work", "--yes"]);
    ok(&out);
    assert!(!p.setup_token_env().exists() && stdout(&out).ends_with("no Claude account is active: new chats and moves refuse (exit 5) until `ai-env creds account use OTHER` (`ai-env creds account list` names them)\n"), "{}", shown(&stdout(&out)));
    outs.push(out);
    let t4 = token("Sd");
    let out = seal(&env, &t4);
    assert_eq!(out.status.code(), Some(9), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("no Claude account is active (credentials/setup-token.env is absent; Claude accounts: default): `ai-env creds account use NAME` makes one active"), "{}", shown(&stderr(&out)));
    assert!(!stderr(&out).contains("now clear"), "refused before the token was read");
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2, &t3, &t4]);
}

/// `forget NAME` lists first (its files, the VMs that received one of its
/// seals, revoke advice), deletes with `--yes` (its row and usage too);
/// forgetting the active one leaves none active, which `creds status` and
/// `list` say; `creds forget --yes` then removes every account and the
/// store.
#[test]
fn forget_lists_then_deletes_one_account_and_creds_forget_all() {
    use ai_env_cli::bridge::vm::registry::{write_row, RowStatus, VmRow};
    let (env, t1, mut outs) = world("Fa");
    let p = paths(&env);
    let t2 = token("Fb");
    outs.push(add(&env, "work", &t2, &["--use"]));
    ok(&outs[2]);
    let work_tag = tag(&p.account_env("work"));
    ai_env_cli::bridge::accounts::update(&p, |s| _ = s.usage.insert("work".into(), toml::Value::Integer(1))).unwrap();
    let id = "microvm-00000000-0000-4000-8000-0000000000a1";
    write_row(&p, &VmRow { id: id.into(), status: RowStatus::Running, credential_at: Some(1_791_000_000), credential_tag: Some(work_tag.clone()), ..VmRow::default() }).unwrap();
    let other = "microvm-00000000-0000-4000-8000-0000000000a2";
    write_row(&p, &VmRow { id: other.into(), status: RowStatus::Running, credential_at: Some(1_791_000_000), credential_tag: Some(tag(&p.account_env("default"))), ..VmRow::default() }).unwrap();
    let status = run(&mut env.creds(&["status"]));
    assert!(stdout(&status).contains(&format!("[!! ] {id} (running) received Claude account work's token (seal {work_tag}) at ")), "{}", shown(&stdout(&status)));
    outs.push(status);
    let files = [p.account_env("work"), p.account_combined_env("work"), p.setup_token_env(), p.combined_env()];
    let out = account(&env, &["forget", "work"]);
    ok(&out);
    let text = stdout(&out);
    for f in &files {
        assert!(text.contains(&format!("would delete {}\n", f.display())) && f.exists(), "{}: {}", f.display(), shown(&text));
    }
    assert!(text.contains(&format!("{id} (running) received Claude account work's token (seal {work_tag}) at ")) && !text.contains(other), "only work's holder: {}", shown(&text));
    assert!(text.contains("ai-env cannot revoke Claude account work's token") && text.ends_with("dry run: nothing deleted; pass --yes to delete\n"), "{}", shown(&text));
    outs.push(out);
    let out = account(&env, &["forget", "work", "--yes"]);
    ok(&out);
    assert!(files.iter().all(|f| !f.exists()) && p.account_env("default").exists(), "work's files and the installed pair, never default's");
    assert!(stdout(&out).contains("\ndeleted 4 file(s)\nno Claude account is active: "), "{}", shown(&stdout(&out)));
    let state = ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap();
    assert!(state.active.is_none() && state.account.iter().all(|r| r.name != "work") && !state.usage.contains_key("work"), "{state:?}");
    let forgot = rows(&env, "creds_account_forget");
    let d = &forgot[0]["detail"];
    assert_eq!((d["name"].as_str(), d["files"].as_str(), d["holders"].as_str(), d["was_active"].as_str()), (Some("work"), Some("4"), Some("1"), Some("true")));
    outs.push(out);
    let status = run(&mut env.creds(&["status"]));
    ok(&status);
    assert!(stdout(&status).contains(&format!("[!! ] {}", ai_env_cli::bridge::accounts::NO_ACTIVE)) && !stdout(&status).contains("[NO ]"), "{}", shown(&stdout(&status)));
    outs.push(status);
    let list = account(&env, &["list"]);
    ok(&list);
    assert!(stdout(&list).starts_with(&format!("[!! ] {}\n[ok ] default: ", ai_env_cli::bridge::accounts::NO_ACTIVE)), "{}", shown(&stdout(&list)));
    outs.push(list);
    let out = account(&env, &["forget", "work"]);
    assert_eq!(out.status.code(), Some(1), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("no Claude account work (Claude accounts: default)"), "{}", shown(&stderr(&out)));
    outs.push(out);
    let out = run(&mut env.creds(&["forget", "--yes"]));
    ok(&out);
    assert!(!p.accounts_dir().exists() && !p.accounts_state().exists() && p.aws_env().exists(), "every account and the store; the runtime key stays");
    assert_eq!(rows(&env, "creds_forget").last().unwrap()["detail"]["accounts"].as_str(), Some("1"));
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2]);
}

/// `forget` of an account that is not the installed one deletes its own
/// files only: neither its dry run nor its deletion names the installed
/// pair, which stays byte for byte, the active account with it, and its
/// audit row says `was_active=false`. Before it, `creds status --json`
/// names each holder's seal and account (`unknown` for a seal no account
/// holds).
#[test]
fn forgetting_another_account_leaves_the_installed_one() {
    use ai_env_cli::bridge::vm::registry::{write_row, RowStatus, VmRow};
    let (env, t1, mut outs) = world("Fn");
    let p = paths(&env);
    let t2 = token("Fo");
    outs.push(add(&env, "spare", &t2, &[]));
    ok(&outs[2]);
    let (default_tag, spare_tag) = (tag(&p.account_env("default")), tag(&p.account_env("spare")));
    let vm = |n: u8, tag: &str| {
        let id = format!("microvm-00000000-0000-4000-8000-0000000000b{n}");
        write_row(&p, &VmRow { id: id.clone(), status: RowStatus::Running, credential_at: Some(1_791_000_000), credential_tag: Some(tag.into()), ..VmRow::default() }).unwrap();
        id
    };
    let ids = [vm(1, &default_tag), vm(2, &spare_tag), vm(3, "0123456789abcdef")];
    let status = run(&mut env.creds(&["status", "--json"]));
    ok(&status);
    let v: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    let mut holders: Vec<(String, String, String)> = v["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let field = |k: &str| h[k].as_str().unwrap_or("-").to_string();
            (field("id"), field("tag"), field("account"))
        })
        .collect();
    holders.sort();
    let want = [(ids[0].clone(), default_tag.clone(), "default"), (ids[1].clone(), spare_tag.clone(), "spare"), (ids[2].clone(), "0123456789abcdef".to_string(), "unknown")].map(|(id, tag, account)| (id, tag, account.to_string()));
    assert_eq!(holders, want);
    outs.push(status);
    let installed = (bytes(&p.setup_token_env()), bytes(&p.combined_env()));
    let out = account(&env, &["forget", "spare"]);
    ok(&out);
    let text = stdout(&out);
    for f in [p.account_env("spare"), p.account_combined_env("spare")] {
        assert!(text.contains(&format!("would delete {}\n", f.display())), "{}: {}", f.display(), shown(&text));
    }
    assert!(!text.contains("setup-token.env") && !text.contains(&p.combined_env().display().to_string()), "the installed pair is not spare's: {}", shown(&text));
    assert!(text.contains(&format!("{} (running) received Claude account spare's token (seal {spare_tag}) at ", ids[1])) && !text.contains(&ids[0]) && !text.contains(&ids[2]), "only spare's holder: {}", shown(&text));
    outs.push(out);
    let out = account(&env, &["forget", "spare", "--yes"]);
    ok(&out);
    let text = stdout(&out);
    assert!(!text.contains("setup-token.env") && !text.contains("no Claude account is active") && text.ends_with("\ndeleted 2 file(s)\n"), "{}", shown(&text));
    assert!(!p.account_env("spare").exists() && !p.account_combined_env("spare").exists());
    assert!((bytes(&p.setup_token_env()), bytes(&p.combined_env())) == installed, "the installed pair untouched");
    let d = &rows(&env, "creds_account_forget")[0]["detail"];
    assert_eq!((d["name"].as_str(), d["files"].as_str(), d["holders"].as_str(), d["was_active"].as_str()), (Some("spare"), Some("2"), Some("1"), Some("false")));
    let state = ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap();
    assert!(state.active.as_deref() == Some("default") && state.account.iter().map(|r| r.name.as_str()).eq(["default"]), "{state:?}");
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2]);
}

/// Design §5: `creds setup-token` chooses the account it seals before the
/// token is asked for, and installs it again only while it still is the
/// installed one, judged under the store's lock once it is sealed: a
/// `creds account use` made while the paste was awaited stays (the account
/// is sealed anew all the same, `installed=false`, and the line says how
/// to make it active).
#[test]
fn a_use_made_while_the_token_is_asked_for_stays() {
    let (env, t1, mut outs) = world("Ws");
    let p = paths(&env);
    let t2 = token("Wt");
    outs.push(add(&env, "spare", &t2, &[]));
    ok(&outs[2]);
    let probes = || fs::read_to_string(env.age_log()).unwrap_or_default().lines().filter(|l| *l == "age --version").count();
    let before = probes();
    let mut child = env.creds(&["setup-token", "--stdin"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // Its age probe is its preflight's: it has chosen default, the active account, and reads the pipe next.
    let started = std::time::Instant::now();
    while probes() == before {
        assert!(started.elapsed() < Duration::from_secs(30), "creds setup-token never reached its preflight");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = account(&env, &["use", "spare"]);
    ok(&out);
    outs.push(out);
    let t3 = token("Wu");
    child.stdin.take().unwrap().write_all(format!("{t3}\n").as_bytes()).unwrap();
    let out = wait_bounded(child, "creds setup-token with a piped stdin");
    ok(&out);
    let spare = (bytes(&p.account_env("spare")), bytes(&p.account_combined_env("spare")));
    assert!((bytes(&p.setup_token_env()), bytes(&p.combined_env())) == spare, "spare stays installed, its combined.env with it");
    assert_same(&opened(&env, &p.account_env("default")), &format!("CLAUDE_CODE_OAUTH_TOKEN={t3}\n"), "default sealed anew");
    let text = stdout(&out);
    assert!(text.contains("Claude account default is not the active one (spare is): `ai-env creds account use default` makes it active\n") && !text.contains("installed as"), "{}", shown(&text));
    let last = rows(&env, "creds_setup_token").pop().unwrap();
    assert_eq!((last["detail"]["account"].as_str(), last["detail"]["installed"].as_str()), (Some("default"), Some("false")));
    let state = ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap();
    let default_row = state.account.iter().find(|r| r.name == "default").map(|r| r.tag.clone());
    assert_eq!((state.active.as_deref(), default_row), (Some("spare"), Some(tag(&p.account_env("default")))), "the store follows the files");
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2, &t3]);
}

/// A seal Anthropic refused is never made active (exit 5, before anything
/// changes), nor is any while the refusals cannot be read (M53); a file in
/// an account's place that is no container is refused too (5), and `creds
/// status` and `list` say it is there (`[!! ]`: it may hold a token in the
/// clear); an unknown name is 1. `creds status` shows the refused account
/// `[!! ]`, never `[NO ]` (C13), and `list` `[NO ]`.
#[test]
fn a_refused_account_is_never_made_active() {
    let (env, t1, mut outs) = world("Ra");
    let p = paths(&env);
    let t2 = token("Rx");
    outs.push(add(&env, "old", &t2, &[]));
    ok(&outs[2]);
    let old = tag(&p.account_env("old"));
    let creds_toml = env.root().join("bridge").join("state").join("creds.toml");
    fs::write(&creds_toml, format!("[[rejected]]\ntag = \"{old}\"\nat = \"2026-10-07T12:00:00Z\"\nvm = \"microvm-1\"\n")).unwrap();
    let installed = bytes(&p.setup_token_env());
    let out = account(&env, &["use", "old"]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains(&format!("Claude account old's token (seal {old}) was refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1): it is not made active")), "{}", shown(&stderr(&out)));
    assert_eq!(bytes(&p.setup_token_env()), installed, "nothing changed");
    assert!(rows(&env, "creds_account_use").is_empty());
    outs.push(out);
    let status = run(&mut env.creds(&["status"]));
    ok(&status);
    assert!(stdout(&status).contains("[!! ] Claude account old: ") && stdout(&status).contains("; refused by Anthropic on 2026-10-07T12:00:00Z (microvm-1)") && !stdout(&status).contains("[NO ]"), "{}", shown(&stdout(&status)));
    outs.push(status);
    let list = account(&env, &["list"]);
    ok(&list);
    assert!(stdout(&list).contains("[NO ] old: "), "{}", shown(&stdout(&list)));
    outs.push(list);
    fs::write(&creds_toml, "[[rejected]\n").unwrap();
    let out = account(&env, &["use", "default"]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("which tokens Anthropic refused is unknown, so Claude account default is not made active"), "{}", shown(&stderr(&out)));
    outs.push(out);
    fs::remove_file(&creds_toml).unwrap();
    fs::write(p.account_env("bad"), "CLAUDE_CODE_OAUTH_TOKEN=placeholder\n").unwrap();
    let out = account(&env, &["use", "bad"]);
    assert_eq!(out.status.code(), Some(5), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("is not an ai-env container (plaintext?): move it away (and revoke what it holds)"), "{}", shown(&stderr(&out)));
    outs.push(out);
    let says = format!("[!! ] {} is not an ai-env container (plaintext?): it is no Claude account; move it away (and revoke what it holds)\n", p.account_env("bad").display());
    let status = run(&mut env.creds(&["status"]));
    ok(&status);
    assert!(stdout(&status).contains(&says) && !stdout(&status).contains("[NO ]"), "{}", shown(&stdout(&status)));
    let list = account(&env, &["list"]);
    ok(&list);
    assert!(stdout(&list).contains(&says), "{}", shown(&stdout(&list)));
    outs.extend([status, list]);
    let out = account(&env, &["use", "nope"]);
    assert_eq!(out.status.code(), Some(1), "{}", shown(&stderr(&out)));
    assert!(stderr(&out).contains("no Claude account nope (Claude accounts: default, old): `ai-env creds account add nope` seals one"), "{}", shown(&stderr(&out)));
    outs.push(out);
    assert_eq!(bytes(&p.setup_token_env()), installed);
    swept(&env, &outs, &[&t1, &t2]);
}

/// L-2: a `state/accounts.toml` that cannot be read is never written: the
/// writers refuse (exit 1, the repair hint) with its bytes kept and the
/// installed pair untouched (what a spawn reads, as before accounts);
/// `list` exits 0 showing it and the accounts read from their files;
/// `creds status` shows it `[!! ]`. Removed, `list` rebuilds it.
#[test]
fn an_unreadable_store_is_never_written() {
    let (env, t1, mut outs) = world("Ua");
    let p = paths(&env);
    fs::write(p.accounts_state(), "[[account]\n").unwrap();
    let pair = (bytes(&p.setup_token_env()), bytes(&p.combined_env()));
    let t2 = token("Ub");
    let hint = "Claude account names are unknown; remove it, and `ai-env creds account list` rebuilds it from credentials/accounts/ (without its usage)";
    for out in [add(&env, "work", &t2, &[]), account(&env, &["use", "default"]), account(&env, &["forget", "default", "--yes"]), seal(&env, &t2)] {
        assert_eq!(out.status.code(), Some(1), "{}", shown(&stderr(&out)));
        assert!(stderr(&out).contains("cannot be parsed") && stderr(&out).contains(hint), "{}", shown(&stderr(&out)));
        assert!(!stderr(&out).contains("now clear"), "refused before any token was read");
        outs.push(out);
    }
    assert_eq!(fs::read_to_string(p.accounts_state()).unwrap(), "[[account]\n", "never written");
    assert_eq!((bytes(&p.setup_token_env()), bytes(&p.combined_env())), pair, "the installed pair untouched");
    assert!(!p.account_env("work").exists());
    let list = account(&env, &["list"]);
    ok(&list);
    assert!(stdout(&list).starts_with("[!! ] ") && stdout(&list).contains(hint) && stdout(&list).contains("[ok ] default (active): "), "{}", shown(&stdout(&list)));
    outs.push(list);
    let status = run(&mut env.creds(&["status"]));
    ok(&status);
    assert!(stdout(&status).contains(&format!("[!! ] {}", p.accounts_state().display())) && stdout(&status).contains(hint), "{}", shown(&stdout(&status)));
    outs.push(status);
    fs::remove_file(p.accounts_state()).unwrap();
    let list = account(&env, &["list"]);
    ok(&list);
    assert_eq!(ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap().active.as_deref(), Some("default"), "rebuilt from the files");
    outs.push(list);
    swept(&env, &outs, &[&t1, &t2]);
}

/// A bad name is refused (exit 2) before anything is read: no token asked
/// for, nothing written.
#[test]
fn a_bad_name_is_refused_before_anything_is_read() {
    let env = Env::new(false);
    env.keystore(KEY, true);
    let t = token("Bn");
    let mut outs = vec![add(&env, "Work", &t, &[]), add(&env, "unknown", &t, &[]), account(&env, &["use", "a.b"]), account(&env, &["forget", "../x"]), account(&env, &["check", "UP"])];
    for out in &outs {
        assert_eq!(out.status.code(), Some(2), "{}", shown(&stderr(out)));
        assert!(stderr(out).contains("is not a Claude account name"), "{}", shown(&stderr(out)));
    }
    outs.push(account(&env, &["check", "--model", "a;b"]));
    assert_eq!(outs[5].status.code(), Some(2), "{}", shown(&stderr(&outs[5])));
    assert!(!env.root().join("bridge").exists(), "nothing written");
    swept(&env, &outs, &[&t]);
}

/// A name added again is sealed anew with its old seal kept as a backup,
/// and what was seen of its usage goes (the new token may be another
/// login, C9); the active one added again is installed again.
#[test]
fn an_account_added_again_is_sealed_anew_and_its_usage_cleared() {
    let (env, t1, mut outs) = world("Aa");
    let p = paths(&env);
    let t2 = token("Ab");
    outs.push(add(&env, "work", &t2, &[]));
    ok(&outs[2]);
    ai_env_cli::bridge::accounts::update(&p, |s| {
        s.usage.insert("work".into(), toml::Value::Integer(1));
        s.usage.insert("default".into(), toml::Value::Integer(2));
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let t3 = token("Ac");
    let out = add(&env, "work", &t3, &[]);
    ok(&out);
    assert!(stdout(&out).contains("previous container kept as "), "{}", shown(&stdout(&out)));
    let usage = ai_env_cli::bridge::accounts::read(&p).unwrap().unwrap().usage;
    assert!(!usage.contains_key("work") && usage.contains_key("default"), "{usage:?}");
    assert_same(&opened(&env, &p.account_env("work")), &format!("CLAUDE_CODE_OAUTH_TOKEN={t3}\n"), "the new seal");
    outs.push(out);
    // The active one added again: its installed copy follows.
    std::thread::sleep(Duration::from_millis(1100));
    let t4 = token("Ad");
    let out = add(&env, "default", &t4, &[]);
    ok(&out);
    assert_eq!(bytes(&p.setup_token_env()), bytes(&p.account_env("default")));
    assert!(stdout(&out).contains("Claude account default stays the active one"), "{}", shown(&stdout(&out)));
    outs.push(out);
    swept(&env, &outs, &[&t1, &t2, &t3, &t4]);
}

/// The environment variable that makes [`wrapper_stand_in`] wait.
const STAND_IN: &str = "AI_ENV_TEST_WRAPPER_STAND_IN";

/// Not a test of its own: the live wrapper of a remote chat `creds account
/// use` finds alive, this binary run under the wrapper's name by
/// [`LiveWrapper::start`] (`registry::confirm_wrapper` reads a process's
/// executable name). It waits until its parent kills it.
#[test]
#[ignore = "a helper process: LiveWrapper::start runs it"]
fn wrapper_stand_in() {
    if std::env::var_os(STAND_IN).is_some() {
        std::thread::sleep(Duration::from_secs(120));
    }
}

/// A copy of this test binary named `ai-env-claude`, running
/// [`wrapper_stand_in`]: a live process the registry takes for a chat's
/// wrapper; killed when dropped.
struct LiveWrapper(std::process::Child);

impl LiveWrapper {
    fn start(dir: &Path) -> LiveWrapper {
        let exe = dir.join("ai-env-claude");
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let child = Command::new(&exe).args(["accounts::wrapper_stand_in", "--exact", "--ignored", "--test-threads=1"]).env(STAND_IN, "1").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        LiveWrapper(child)
    }
}

impl Drop for LiveWrapper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `use` (and `add --use`) names each live remote chat whose last
/// generation still runs on another account, with its way on (`session
/// migrate` now, or a reopen), and counts them in its audit row; a chat
/// whose wrapper is gone is not named.
#[test]
fn use_names_the_live_chats_on_another_account() {
    use ai_env_cli::bridge::registry::{self, SessionRow, VmEntry};
    let (env, t1, mut outs) = world("Lc");
    let p = paths(&env);
    let default_tag = tag(&p.account_env("default"));
    let live = LiveWrapper::start(env.root());
    // The row is written after its wrapper started (its pid would be a later process's otherwise).
    std::thread::sleep(Duration::from_millis(1100));
    let entry = toml::Value::try_from(VmEntry { gen: 1, vm: "microvm-1".into(), from: "2026-10-21T10:00:00Z".into(), pid: live.0.id(), tag: Some(default_tag), account: Some("default".into()), ..VmEntry::default() }).unwrap();
    let now = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now());
    let row = |sid: &str, pid: u32| SessionRow { v: registry::REGISTRY_SCHEMA_V, session_id: sid.into(), cwd: Some("/w/project".into()), created: now.clone(), last_seen: now.clone(), status: "active".into(), mode: "remote".into(), pid, vms: vec![entry.clone()], ..SessionRow::default() };
    let sid = "0a403528-1afc-4bdf-97a7-d9a67c42d89a";
    registry::write(&p, &row(sid, live.0.id())).unwrap();
    registry::write(&p, &row("0a403528-1afc-4bdf-97a7-d9a67c42d89b", 1)).unwrap();
    let t2 = token("Ld");
    let out = add(&env, "work", &t2, &["--use"]);
    ok(&out);
    let text = stdout(&out);
    assert!(
        text.contains(&format!("1 live chat(s) still run as another Claude account:\n  {sid} (/w/project) as default: `ai-env session migrate {sid}` moves it now (one Touch ID), or reopen it; its next restart or move takes work\n")),
        "{}",
        shown(&text)
    );
    outs.push(out);
    let out = account(&env, &["use", "default"]);
    ok(&out);
    assert!(!stdout(&out).contains("live chat"), "the chat runs on default's seal: {}", shown(&stdout(&out)));
    assert_eq!(rows(&env, "creds_account_use").last().unwrap()["detail"]["chats_other"].as_str(), Some("0"));
    outs.push(out);
    let out = account(&env, &["use", "work"]);
    ok(&out);
    assert!(stdout(&out).contains(&format!("  {sid} (/w/project) as default: ")), "{}", shown(&stdout(&out)));
    assert_eq!(rows(&env, "creds_account_use").last().unwrap()["detail"]["chats_other"].as_str(), Some("1"));
    outs.push(out);
    drop(live);
    swept(&env, &outs, &[&t1, &t2]);
}
