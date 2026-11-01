//! §RS.13 (R-151, R-152): the panel's `relay-allow` and `relay-remove` are `ai-env relay access`, run as a child: the real
//! `ai-env`, with the fake aws's Parameter Store and the fake age behind it. The ops key is sealed by the real `creds
//! aws-set` into `credentials/ops.env`, so each child's unseal is one Touch ID the fake age logs; the panel itself holds
//! a deployer's marker and key here, which no child may inherit, and never the ops key.
use super::{aws_keys, dead_pid, Panel, World, SID, SID_LOCAL, T};
use ai_env_worker::policy;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
const KEY: &str = "ai-env-bridge";
/// The public test recipients of tests/cli.rs.
const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
const ACCESS: &str = "/ai-env/relay/access";
const GRANTS: &str = "/ai-env/relay/grants";
const CHAT: &str = "0199a1b2-0000-7000-8000-0000000012a1";
/// Another live chat on the same VM.
const SID_OTHER: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60";
/// A remote chat with no token, one whose workspace opts out, and one with no access id.
const SID_NO_TOKEN: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61";
const SID_OFF: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a63";
const SID_NO_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a62";
/// One whose hand-edited row holds no uuid, and a chat that goes back to this Mac.
const SID_BAD_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a64";
const SID_BACK: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a65";
const CHAT_BACK: &str = "0199a1b2-0000-7000-8000-0000000012a5";

fn fake(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

/// A panel world with the fakes in `bin/`, the keystore key, `offer` and the connector in bridge.toml, `state/infra.toml`,
/// and the ops key sealed; `/ai-env/relay/grants` holds `g-a` and `g-b`.
fn world() -> World {
    let w = World::with_toml("[panel]\nenabled = true\n\n[relay]\noffer = [\"g-a\", \"g-b\", \"g-c\"]\n");
    let toml = w.bridge().join("bridge.toml");
    let text = std::fs::read_to_string(&toml).unwrap();
    std::fs::write(&toml, text.replacen("[aws]\n", &format!("[aws]\negress_connector_arn = \"{CONNECTOR}\"\n"), 1)).unwrap();
    std::fs::create_dir_all(w.bridge().join("state")).unwrap();
    std::fs::write(w.bridge().join("state").join("infra.toml"), "stack = \"dev\"\nwritten = \"2026-10-29T10:00:00Z\"\nregion = \"eu-central-1\"\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent\"\n").unwrap();
    for dir in ["bin", "tmp", "ssm", "answers"] {
        std::fs::create_dir_all(w.root().join(dir)).unwrap();
    }
    let install = |src: &str, name: &str| {
        let dst = w.root().join("bin").join(name);
        std::fs::copy(fake(src), &dst).unwrap();
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    for name in ["age", "age-keygen", "age-plugin-se"] {
        install("age.sh", name);
    }
    install("aws.sh", "aws");
    let key = w.root().join("keys").join("keys").join(KEY);
    std::fs::create_dir_all(&key).unwrap();
    std::fs::write(key.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
    std::fs::write(key.join("recipients.txt"), format!("{SE_REC}\n{X_REC}\n")).unwrap();
    std::fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
    // The ops key, by the real command, run as `ai-env as ops` would leave it.
    let mut seal = w.cmd(&["creds", "aws-set", "--user", "ai-env-ops"]);
    for (k, v) in fakes(&w) {
        seal.env(k, v);
    }
    seal.env("AI_ENV_PASTE_STDIN", "1").envs(aws_keys::identity_env("ops", aws_keys::OPS_TAIL));
    let paste = aws_keys::create_access_key_json("ai-env-ops", &aws_keys::key_id(aws_keys::OPS_TAIL), &aws_keys::secret("Op7/"));
    let o = crate::common::bounded::run_within(seal, Some(paste.as_bytes()), T, "creds aws-set");
    assert_eq!(o.status.code(), Some(0), "creds aws-set: {}", String::from_utf8_lossy(&o.stderr));
    set_param(&w, GRANTS, &grants(&["g-a", "g-b"]), 4);
    w
}

/// What the fakes need of a process's environment.
fn fakes(w: &World) -> Vec<(&'static str, String)> {
    let at = |rel: &str| w.root().join(rel).display().to_string();
    vec![
        ("PATH", format!("{}:/usr/bin:/bin", at("bin"))),
        ("TMPDIR", at("tmp")),
        ("FAKE_AGE_LOG", at("age.log")),
        ("FAKE_AWS_LOG", at("aws.log")),
        ("FAKE_AWS_ENV_LOG", at("aws-env.log")),
        ("FAKE_AWS_SSM_DIR", at("ssm")),
        ("FAKE_AWS_ANSWERS", at("answers")),
        ("FAKE_AWS_PIN_ALL", "1".to_string()),
    ]
}

fn grants(ids: &[&str]) -> String {
    let list: Vec<policy::Grant> = ids.iter().map(|g| policy::Grant { grant_id: (*g).into(), allow: vec!["example-*/*".into()] }).collect();
    policy::render_grants(&list).unwrap()
}

fn set_param(w: &World, name: &str, value: &str, version: u64) {
    let f = w.root().join("ssm").join(name.trim_start_matches('/'));
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(&f, value).unwrap();
    std::fs::write(format!("{}.version", f.display()), format!("{version}\n")).unwrap();
}

/// `/ai-env/relay/access` as the fake holds it: its entries and its version.
fn access(w: &World) -> (Vec<policy::AccessEntry>, u64) {
    let f = w.root().join("ssm").join(ACCESS.trim_start_matches('/'));
    let value = std::fs::read_to_string(&f).expect("the access list");
    let version = std::fs::read_to_string(format!("{}.version", f.display())).unwrap().trim().parse().unwrap();
    (policy::parse_access(&value).unwrap(), version)
}

/// The panel, under a deployer's marker and key, what a child must not inherit, its keystore named by `--key-dir` with
/// `AI_ENV_DIR` naming none, which a child must not inherit either.
fn serve(w: &World) -> Panel {
    let keys = w.root().join("keys").display().to_string();
    let mut cmd = w.cmd(&["--key-dir", &keys, "panel", "serve", "--port", "0"]);
    for (k, v) in fakes(w) {
        cmd.env(k, v);
    }
    cmd.env("AI_ENV_DIR", w.root().join("no-such-keystore")).envs(aws_keys::identity_env("deployer", aws_keys::DEPLOYER_TAIL));
    Panel::start(cmd)
}

/// How many decrypts (Touch IDs) the fake age has served.
fn touch_ids(w: &World) -> usize {
    std::fs::read_to_string(w.root().join("age.log")).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
}

/// The last valid day `days` from today, UTC.
fn day(days: u64) -> String {
    let now = ai_env_cli::wire::time::unix_now();
    ai_env_cli::wire::time::rfc3339_utc(now - now % 86_400 + days * 86_400)[..10].to_string()
}

/// The audit's `relay_access` rows.
fn rows_of(w: &World) -> Vec<serde_json::Value> {
    w.audit().into_iter().filter(|r| r["event"] == "relay_access").collect()
}

/// A `relay agent` killed with its test.
struct Agent(std::process::Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// R-151, R-152 (M-WM92, M-WM93): two actions are two children, each with one Touch ID of the ops key, neither holding the
/// panel's marker or key, each audited `actor=panel` under its own pid; the action's line is the CLI's. The pages show what a
/// chat holds, as of the cache's version; each confirm page names the twin and the other chats on the VM; a child's failure
/// is the action's, with its line and code. The pages read the agent's state from its socket, with no Touch ID. A confirm page
/// names the day an approval runs to and the entry's one end for all its grants. A chat back on this Mac can leave the list
/// and takes nothing new. A write that fails may have landed, so the pages then say the list has not been read.
#[test]
fn relay_access_runs_its_cli_twin_as_a_child() {
    let w = world();
    let vm = w.vm(&[]);
    let title = "<script>alert(1)</script>";
    w.session(SID, "remote", Some(&vm), "remote", "/w/remote");
    w.set_access(SID, CHAT, "minted");
    w.set_title(SID, title, "custom");
    w.session(SID_OTHER, "remote", Some(&vm), "remote", "/w/remote");
    for sid in [SID, SID_OTHER] {
        let mut row = ai_env_cli::bridge::registry::read(&w.paths(), sid).unwrap().unwrap();
        row.status = "active".into();
        row.pid = dead_pid();
        ai_env_cli::bridge::registry::write(&w.paths(), &row).unwrap();
    }
    w.session(SID_NO_TOKEN, "remote", Some(&vm), "remote", "/w/remote");
    w.set_access(SID_NO_TOKEN, "0199a1b2-0000-7000-8000-0000000012a2", "no_agent");
    w.session(SID_OFF, "remote", Some(&vm), "remote", "/w/remote");
    w.set_access(SID_OFF, "0199a1b2-0000-7000-8000-0000000012a4", "off");
    w.session(SID_NO_ID, "remote", None, "remote", "/w/remote");
    w.session(SID_BAD_ID, "remote", None, "remote", "/w/remote");
    w.set_access(SID_BAD_ID, "not a uuid", "minted");
    w.session(SID_LOCAL, "local-child", None, "local", "/w/local");
    let before = touch_ids(&w);
    let p = serve(&w);
    // Before any read: each offered grant to allow, the mint word, the agent's state, no list yet.
    let allow_a = format!("{SID}_g-a");
    let allow_b = format!("{SID}_g-b");
    let page = p.get("").text();
    for want in [
        format!("[ ] g-a <a href=\"./confirm?action=relay-allow&amp;target={allow_a}\">Allow</a>"),
        format!("[ ] g-b <a href=\"./confirm?action=relay-allow&amp;target={allow_b}\">Allow</a>"),
        "<td class=\"relay\">minted<br>[ ] g-a ".to_string(),
        "<td class=\"relay\">no token (no_agent)<br>".to_string(),
        "no access id: it last ran before this ai-env, so reopen the chat".to_string(),
        "Relay agent: not running (ai-env relay agent): a chat spawned now holds no session token.".to_string(),
        "Access list: not read yet (ai-env relay status); the relay remains the gate.".to_string(),
    ] {
        assert!(page.contains(&want), "{want}\n{page}");
    }
    assert!(!page.contains("<script>alert"), "{page}");
    let session = p.get(&format!("session/{SID}")).text();
    for want in ["<h2>Relay</h2>\n<p>Session token: minted</p>".to_string(), format!("<li>[ ] g-a <a href=\"../confirm?action=relay-allow&amp;target={allow_a}\">Allow</a></li>"), "Access list: not read yet".to_string()] {
        assert!(session.contains(&want), "{want}\n{session}");
    }
    // A chat on this Mac has none of it.
    let local = p.get(&format!("session/{SID_LOCAL}")).text();
    assert!(!local.contains("<h2>Relay</h2>") && !local.contains("relay-allow"), "{local}");
    // The confirm page: its twin, the ops key's Touch ID, the other chats on the VM, the session id beside its title, the
    // chat's id; an HTML page escapes the title; a chat with no token hears when an approval reaches it.
    let doc = p.get(&format!("confirm?action=relay-allow&target={allow_a}&json=1")).json();
    assert_eq!(doc["twin"].as_str(), Some(format!("ai-env relay access {SID} --allow g-a").as_str()), "{doc}");
    assert!(doc["touch_ids"].as_str().is_some_and(|t| t.starts_with("one Touch ID on this Mac (the ops key)")), "{doc}");
    assert_eq!(doc["chats"], serde_json::json!([SID_OTHER]), "the others on its VM, a closed one no chat, and not itself: {doc}");
    let what = doc["what"].as_str().expect("what");
    assert!(what.contains(SID) && what.contains(title) && what.contains(CHAT) && what.contains("no restart"), "{what}");
    assert!(what.contains(&format!("grant g-a until {}:", day(30))), "the day, never a span an entry's end could outrun: {what}");
    assert!(!what.contains("holds no session token") && !what.contains("Its entry"), "no entry yet: {what}");
    let page = p.get(&format!("confirm?action=relay-allow&target={allow_a}")).text();
    assert!(page.contains("Other chats on this chat&#39;s VM") || page.contains("Other chats on this chat's VM"), "{page}");
    assert!(page.contains(&format!("<li>{SID_OTHER}</li>")) && !page.contains("<script>alert") && page.contains(&format!("<code>ai-env relay access {SID} --allow g-a</code>")), "{page}");
    let doc = p.get(&format!("confirm?action=relay-allow&target={SID_NO_TOKEN}_g-a&json=1")).json();
    assert!(doc["what"].as_str().is_some_and(|t| t.contains("latest spawn holds no session token (no_agent), so it reaches the grant from its next spawn")), "{doc}");
    let doc = p.get(&format!("confirm?action=relay-allow&target={SID_OFF}_g-a&json=1")).json();
    assert!(doc["what"].as_str().is_some_and(|t| t.contains("latest spawn holds no session token (off): [relay].grant or its workspace's relay_grant names none")), "{doc}");
    // What its form takes and what it refuses: a bad target, a chat on this Mac or with no id, a grant not offered, a `.`.
    for (target, status) in [
        (SID.to_string(), 400),
        (format!("{SID}_"), 400),
        (format!("{SID}_G"), 400),
        (format!("{SID}_g.a"), 400),
        ("not-a-session_g-a".to_string(), 400),
        (format!("{SID_LOCAL}_g-a"), 400),
        (format!("{SID_NO_ID}_g-a"), 400),
        (format!("{SID_BAD_ID}_g-a"), 400),
        (format!("{SID}_g-z"), 400),
        ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4aff_g-a".to_string(), 404),
    ] {
        let r = p.get(&format!("confirm?action=relay-allow&target={target}"));
        assert_eq!(r.status, status, "{target}: {}", r.text());
    }
    assert_eq!(p.get(&format!("confirm?action=relay-remove&target={SID}_g-z")).status, 200, "a grant off the offer must stay removable");
    assert_eq!(p.get(&format!("confirm?action=relay-remove&target={SID_LOCAL}_g-a")).status, 400, "on this Mac with no id, nothing to take back");
    assert_eq!(p.get(&format!("confirm?action=relay-remove&target={SID_BAD_ID}_g-a")).status, 400, "no uuid is no id");
    assert_eq!(p.post(&format!("nonce=x&action=relay-allow&target={SID}_g.a")).status, 400, "a form value refuses a `.`");
    assert_eq!(touch_ids(&w), before, "no page asks a Touch ID");
    // Two actions: two children, two Touch IDs (M-WM93: in process, the first's key serves the second).
    let (n1, done1) = p.act("relay-allow", &allow_a);
    // Its page names the entry it joins, as the cache has it: one end covers all its grants.
    let what = p.get(&format!("confirm?action=relay-allow&target={allow_b}&json=1")).json()["what"].as_str().expect("what").to_string();
    assert!(what.contains(&format!("grant g-b until {}:", day(30))) && what.contains(&format!(" Its entry ends {} and holds g-a: one end covers all its grants, the later of the two.", day(30))), "{what}");
    let (n2, done2) = p.act("relay-allow", &allow_b);
    assert_eq!(touch_ids(&w) - before, 2, "one Touch ID per action: {done1}\n{done2}\n{}", p.stderr());
    let rows = rows_of(&w);
    assert_eq!(rows.len(), 2, "{rows:?}");
    for row in &rows {
        assert_eq!(row["detail"]["actor"].as_str(), Some("panel"), "the child's rows say panel (M-WM92): {row}");
        assert_ne!(row["pid"].as_u64(), Some(u64::from(p.pid())), "a child's row: {row}");
    }
    assert_ne!(rows[0]["pid"], rows[1]["pid"], "a child each");
    let end = format!("{}T23:59:59Z", day(30));
    assert_eq!(access(&w), (vec![policy::AccessEntry { chat: CHAT.into(), grants: vec!["g-a".into(), "g-b".into()], not_after: end.clone() }], 2));
    assert_eq!((done1["state"].as_str(), done1["code"].as_i64(), done1["id"].as_str()), (Some("done"), Some(0), Some(n1.as_str())), "{done1}\n{}", p.stderr());
    assert_eq!(done1["twin"].as_str(), Some(format!("ai-env relay access {SID} --allow g-a").as_str()));
    assert_eq!(done1["line"].as_str(), Some(format!("allowed chat {CHAT} (session {SID}) grant g-a until {end} ({ACCESS} v1, 1 chat(s)); the relay applies it within about 70 s, with no restart").as_str()), "the CLI's line: {done1}");
    assert_eq!((done2["state"].as_str(), done2["id"].as_str()), (Some("done"), Some(n2.as_str())), "{done2}");
    assert_eq!(done2["line"].as_str(), Some(format!("note: chat {CHAT}'s entry holds g-a too: one end, {end}, covers them all\nallowed chat {CHAT} (session {SID}) grant g-b until {end} ({ACCESS} v2, 1 chat(s)); the relay applies it within about 70 s, with no restart").as_str()), "the CLI's note reaches the action: {done2}");
    // An entry that ends later than the page's own day, as the cache has it: both days, the entry's the later. Lapsed: none.
    let cache = w.bridge().join("state").join("relay-access.json");
    let kept = std::fs::read(&cache).unwrap();
    let cached = |not_after: String| serde_json::to_vec(&serde_json::json!({"version": 2, "at": "2026-10-22T10:00:00Z", "entries": [{"chat": CHAT, "grants": ["g-a", "g-b"], "not_after": not_after}]})).unwrap();
    let confirm_c = format!("confirm?action=relay-allow&target={SID}_g-c&json=1");
    std::fs::write(&cache, cached(format!("{}T23:59:59Z", day(89)))).unwrap();
    let what = p.get(&confirm_c).json()["what"].as_str().expect("what").to_string();
    assert!(what.contains(&format!("grant g-c until {}:", day(30))) && what.contains(&format!(" Its entry ends {} and holds g-a,g-b: one end covers all its grants, the later of the two.", day(89))), "{what}");
    std::fs::write(&cache, cached("2020-01-01T23:59:59Z".to_string())).unwrap();
    let what = p.get(&confirm_c).json()["what"].as_str().expect("what").to_string();
    assert!(!what.contains("Its entry"), "a lapsed entry is pruned by the write: {what}");
    std::fs::write(&cache, &kept).unwrap();
    // The child held neither the panel's marker nor its key: its aws calls name no marker, and sign as ai-env-ops.
    let env_log = std::fs::read_to_string(w.root().join("aws-env.log")).unwrap();
    assert!(!env_log.is_empty() && env_log.lines().all(|l| !l.contains("AI_ENV_BRIDGE_AS")), "{env_log}");
    assert!(env_log.lines().all(|l| l.contains("AWS_ACCESS_KEY_ID")), "{env_log}");
    // The pages now: what it holds, as of the cache; the document stays the CLI's.
    let page = p.get("").text();
    let until = day(30);
    for want in [
        format!("[x] g-a until {until} <a href=\"./confirm?action=relay-remove&amp;target={allow_a}\">Remove</a>"),
        format!("[x] g-b until {until} <a href=\"./confirm?action=relay-remove&amp;target={allow_b}\">Remove</a>"),
        format!("[ ] g-c <a href=\"./confirm?action=relay-allow&amp;target={SID}_g-c\">Allow</a>"),
        "Access list: as of v2, ".to_string(),
    ] {
        assert!(page.contains(&want), "{want}\n{page}");
    }
    let session = p.get(&format!("session/{SID}")).text();
    assert!(session.contains(&format!("<li>[x] g-a until {until} <a href=\"../confirm?action=relay-remove&amp;target={allow_a}\">Remove</a></li>")), "{session}");
    let cache = w.bridge().join("state").join("relay-access.json");
    assert_eq!(std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777, 0o600);
    // A removal: its own Touch ID, one grant, then the other, and the entry goes.
    let (_, done) = p.act("relay-remove", &allow_a);
    assert_eq!((done["state"].as_str(), done["code"].as_i64()), (Some("done"), Some(0)), "{done}");
    assert_eq!(done["twin"].as_str(), Some(format!("ai-env relay access {SID} --remove g-a").as_str()));
    assert!(done["line"].as_str().is_some_and(|l| l.starts_with(&format!("removed grant g-a from chat {CHAT} (session {SID})"))), "{done}");
    assert_eq!(touch_ids(&w) - before, 3);
    let row = rows_of(&w).pop().unwrap();
    assert_eq!((row["detail"]["op"].as_str(), row["detail"]["outcome"].as_str(), row["detail"]["grant"].as_str(), row["detail"]["actor"].as_str()), (Some("remove"), Some("removed"), Some("g-a"), Some("panel")), "{row}");
    let (_, done) = p.act("relay-remove", &allow_b);
    assert_eq!(done["state"].as_str(), Some("done"), "{done}");
    assert_eq!(access(&w), (Vec::new(), 4), "an entry left empty goes");
    // A child's failure is the action's: its line and its code; offered, but in no grant list: exit 9.
    let (_, done) = p.act("relay-allow", &format!("{SID}_g-c"));
    assert_eq!((done["state"].as_str(), done["code"].as_i64()), (Some("failed"), Some(9)), "{done}");
    assert_eq!(done["line"].as_str(), Some(format!("relay access: grant g-c is not in {GRANTS} v4, so this chat would reach nothing through it: ai-env as deployer -- ai-env relay grant g-c '<source-glob>/<op-glob>'").as_str()), "{done}");
    // A chat with no token: allowed, and the action's line says when it reaches the chat, first.
    let (_, done) = p.act("relay-allow", &format!("{SID_NO_TOKEN}_g-a"));
    assert_eq!(done["state"].as_str(), Some("done"), "{done}");
    let line = done["line"].as_str().expect("its line");
    assert!(line.starts_with(&format!("note: session {SID_NO_TOKEN}'s latest spawn holds no session token (relay=no_agent)")) && line.contains("\nallowed chat "), "{line}");
    // A chat back on this Mac (`[wrapper] mode` changed, the chat reopened): the row keeps its id, so a later remote --resume
    // keeps what it holds. Nothing to allow; what it holds stays on the pages, with its Remove, and its confirm page and child work.
    w.session(SID_BACK, "remote", Some(&vm), "remote", "/w/remote");
    w.set_access(SID_BACK, CHAT_BACK, "minted");
    let (_, done) = p.act("relay-allow", &format!("{SID_BACK}_g-a"));
    assert_eq!(done["state"].as_str(), Some("done"), "{done}");
    let mut row = ai_env_cli::bridge::registry::read(&w.paths(), SID_BACK).unwrap().unwrap();
    row.mode = "local-child".into();
    row.relay = None;
    ai_env_cli::bridge::registry::write(&w.paths(), &row).unwrap();
    let remove_back = format!("[x] g-a until {until} <a href=\"./confirm?action=relay-remove&amp;target={SID_BACK}_g-a\">Remove</a>");
    let page = p.get("").text();
    assert!(page.contains(&format!("<td class=\"relay\">{remove_back}</td>")), "the Remove and nothing to allow: {page}");
    let session = p.get(&format!("session/{SID_BACK}")).text();
    assert!(session.contains("<h2>Relay</h2>\n<p>This chat runs on this Mac now; a later remote --resume still reaches what it holds.</p>") && session.contains(&remove_back.replace("./confirm", "../confirm")) && !session.contains("relay-allow") && !session.contains("Session token"), "{session}");
    assert_eq!(p.get(&format!("confirm?action=relay-allow&target={SID_BACK}_g-b")).status, 400, "it takes nothing new");
    assert_eq!(p.get(&format!("confirm?action=relay-remove&target={SID_BACK}_g-a")).status, 200);
    let (_, done) = p.act("relay-remove", &format!("{SID_BACK}_g-a"));
    assert_eq!(done["state"].as_str(), Some("done"), "{done}");
    assert!(!access(&w).0.iter().any(|a| a.chat == CHAT_BACK), "{:?}", access(&w));
    let session = p.get(&format!("session/{SID_BACK}")).text();
    assert!(!session.contains("<h2>Relay</h2>"), "nothing left to show: {session}");
    let page = p.get("").text();
    assert!(!page.contains(&format!("target={SID_BACK}_")), "{page}");
    // A write that fails may have landed: the action fails with the CLI's line and code, the audit says `unknown`, and the
    // pages say the list has not been read, rather than what the run no longer knows.
    assert!(p.get("").text().contains("Access list: as of v"));
    let answers = w.root().join("answers");
    std::fs::write(answers.join("ssm.put-parameter.json"), "{\"Version\": 77, \"Tier\": \"Standard\"}\n").unwrap();
    let (_, done) = p.act("relay-remove", &format!("{SID_NO_TOKEN}_g-a"));
    std::fs::remove_file(answers.join("ssm.put-parameter.json")).unwrap();
    assert_eq!((done["state"].as_str(), done["code"].as_i64()), (Some("failed"), Some(7)), "{done}");
    assert!(done["line"].as_str().is_some_and(|l| l.starts_with(&format!("relay access: {ACCESS} moved from v")) && l.contains("to v77 while it was written")), "{done}");
    let row = rows_of(&w).pop().unwrap();
    assert_eq!((row["detail"]["op"].as_str(), row["detail"]["outcome"].as_str(), row["detail"]["actor"].as_str()), (Some("remove"), Some("unknown"), Some("panel")), "{row}");
    let page = p.get("").text();
    assert!(page.contains("Access list: not read yet (ai-env relay status)") && !page.contains("[x] "), "{page}");
    // The agent's state, as its socket answers: M's own `relay agent`.
    let run_fakes = |args: &[&str]| {
        let mut cmd = w.cmd(args);
        for (k, v) in fakes(&w) {
            cmd.env(k, v);
        }
        cmd
    };
    let o = crate::common::bounded::run_within(run_fakes(&["relay", "keygen"]), None, T, "relay keygen");
    assert_eq!(o.status.code(), Some(0), "relay keygen: {}", String::from_utf8_lossy(&o.stderr));
    let mut agent = Agent(run_fakes(&["relay", "agent", "--hours", "1"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("ai-env relay agent"));
    let running = format!("Relay agent: running (pid {}, until ", agent.0.id());
    let t0 = std::time::Instant::now();
    while !p.get("").text().contains(&running) {
        assert!(t0.elapsed() < T && agent.0.try_wait().unwrap().is_none(), "{running}: {}", p.get("").text());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(p.get(&format!("session/{SID}")).text().contains(&running));
    assert_eq!(p.stop().0, Some(0));
}
