//! S13 (plans/s13-contracts.md §V-vm.8.2): a spawn's relay session on native shims. A shim with no relay programs
//! names no `relay_v1` and refuses a relay spawn; one with `--fs-root` and both relay files (the fake relay client,
//! `tests/fakes/relay-client.sh`, a copy with its knobs file, and a planted MCP config) names it last, gives a relay
//! `claude` the config as its argv[1] and starts the fake with the session on fd 3. `/validate` checks the relay files
//! when the tree holds them (V3, V4); the image's MANIFEST and Dockerfile bake them (V-R36, V-R37).
use super::{bare_caps, fake_claude, hello_view, next_frame, opts, plant_vm_tree, send_frame, serve_app, serve_code, serve_hooks_at, spawn_refused, state_with, HookSource, ShimOpts, Stack};
use ai_env_cli::wire::frame::{Deliver, Frame, SpawnErrCode, SpawnId, CAP_RELAY_V1};
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::relay::{RelaySpawn, MCP_CONFIG_JSON};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const RELAY_FAKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/relay-client.sh");
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// A run-time relay session (its token low-entropy parts, never a committed value).
fn relay_session() -> RelaySpawn {
    let token = format!("relay-test-{:08x}-0001", std::process::id());
    RelaySpawn { token: Secret::new(token), addr: "10.42.0.20:7443".into(), server_name: "10.42.0.20".into(), ca_der_b64: "MA==".into() }
}

/// A `spawn` frame of `argv` carrying `relay`.
fn relay_spawn(id: &SpawnId, argv: &[&str], relay: Option<RelaySpawn>) -> Frame {
    Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: None, claude: Vec::new(), relay }
}

/// A native shim without relay programs: `hello_ok.caps` are `bare_caps()` (no `relay_v1`), and a relay spawn is
/// `spawn_err` `bad_request` naming the missing cap. Kills M-V20.
#[tokio::test]
async fn a_relay_spawn_is_refused_where_no_relay_is_served() {
    let s = Stack::log().await;
    s.run(true).await;
    let (mut w, _, caps, _) = hello_view(s.app).await;
    assert_eq!(caps, bare_caps(), "no relay_v1 without its programs");
    let id = SpawnId::new_v7();
    let (code, message) = spawn_refused(&mut w, &relay_spawn(&id, &["claude", "--print"], Some(relay_session()))).await;
    assert_eq!((code, message.as_str()), (SpawnErrCode::BadRequest, "relay: this shim serves no relay (it names no relay_v1)"));
}

/// A shim with `--fs-root`, `--relay-client` a copy of the fake (its knobs file beside it), `--relay-mcp-config` a
/// planted file, and a stand-in claude printing its argv: the caps end `relay_v1` (and with either file missing, the
/// same shim names none); the relay spawn of `["claude", "--print"]` prints `--mcp-config=<cfg> --print`; the fake's
/// `.session` is the session JSON; `<root>/run/ai-env/relay` is 0750; after the spawn's exit the fake's `.term` exists
/// within 2 s. Kills M-V9, M-V12, M-V16.
#[tokio::test]
async fn a_relay_spawn_through_the_agent_starts_the_fake_client() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let (vm, home) = (root.join("vm"), root.join("vm/Users/agent"));
    std::fs::create_dir_all(&home).unwrap();
    let client = root.join("ai-env-relay-client");
    std::fs::copy(RELAY_FAKE, &client).unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
    // macOS assesses a new file's first exec (about 200 ms): here, not while the leader runs (no --socket: exit 64).
    assert_eq!(std::process::Command::new(&client).stderr(std::process::Stdio::null()).status().unwrap().code(), Some(64));
    std::fs::write(root.join("ai-env-relay-client.knobs"), "export RELAYFAKE_MODE='serve'\n").unwrap();
    let config = root.join("relay-mcp.json");
    std::fs::write(&config, format!("{MCP_CONFIG_JSON}\n")).unwrap();
    // The stand-in claude: answers the probe, else prints its argv and waits a moment (its client starts beside it).
    let claude = root.join("claude");
    std::fs::write(&claude, "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '2.1.283 (Claude Code)'; exit 0; fi\necho \"$*\"\nsleep 1.5\n").unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = ShimOpts { fs_root: Some(vm.clone()), home: home.clone(), relay_client: client.clone(), relay_mcp_config: config.clone(), ..opts(None, HookSource::Log, 0) };
    // The same shim with either relay file missing names no relay_v1 (M-V9: one blind to their presence would).
    for missing in [ShimOpts { relay_client: root.join("no-relay-client"), ..o.clone() }, ShimOpts { relay_mcp_config: root.join("no-relay-mcp.json"), ..o.clone() }] {
        let without = state_with(claude.clone(), missing).await;
        assert!(!without.serves_relay() && !without.caps().iter().any(|c| c == CAP_RELAY_V1), "{:?}", without.caps());
    }
    let state = state_with(claude, o).await;
    let (hooks, app, code) = (serve_hooks_at(state.clone(), "127.0.0.1").await, serve_app(state.clone()).await, serve_code(state.clone()).await);
    let s = Stack { state, hooks, app, code, _dir: tempfile::tempdir().unwrap() };
    s.run(true).await;
    let (mut w, _, caps, _) = hello_view(s.app).await;
    assert_eq!(caps.last().map(String::as_str), Some(CAP_RELAY_V1), "relay_v1 last: {caps:?}");
    let relay = relay_session();
    let session = relay.session();
    let id = SpawnId::new_v7();
    send_frame(&mut w, &relay_spawn(&id, &["claude", "--print"], Some(relay))).await;
    let pid = match next_frame(&mut w).await {
        Ok(Frame::Spawned { spawn_id, pid, .. }) if spawn_id == id => pid,
        other => panic!("spawned, got {other:?}"),
    };
    let (out, exit) = super::run_to_exit(&mut w, &id).await;
    assert_eq!((String::from_utf8_lossy(&out).as_ref(), exit), (format!("--mcp-config={} --print\n", config.display()).as_str(), Some(0)));
    let sock = vm.join(format!("run/ai-env/relay/{pid}.sock"));
    let fact = |name: &str| PathBuf::from(format!("{}.{name}", sock.display()));
    let until = Instant::now() + Duration::from_secs(5);
    while !fact("session").exists() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read(fact("session")).unwrap(), session.as_slice(), "the fake's fd 3: the session JSON");
    assert_eq!(std::fs::read_to_string(fact("argv")).unwrap().lines().collect::<Vec<_>>(), ["serve", "--leader", &pid.to_string(), "--socket", sock.to_str().unwrap(), "--agent-uid", &super::uid_gid().0.to_string()]);
    let mode = std::fs::metadata(vm.join("run/ai-env/relay")).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o750);
    let until = Instant::now() + Duration::from_secs(2);
    while !fact("term").exists() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(fact("term").exists(), "the client was TERMed with its leader");
}

/// `run_checks` on `root` (a native tree): each check's id, verdict and detail.
async fn checks_of(root: &Path) -> Vec<(String, bool, String)> {
    let state = state_with(fake_claude(root, ""), opts(Some(root), HookSource::Log, 0)).await;
    ai_env_cli::shim::validate::run_checks(&state, None).await.into_iter().map(|c| (c.id.to_string(), c.ok, c.detail)).collect()
}

/// The relay files planted as the image holds them: the client and the MCP server (stand-ins, 0755) and the config.
fn plant_relay(root: &Path) {
    let bin = root.join("usr/local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    for b in ["ai-env-relay-client", "ai-env-relay-mcp"] {
        std::fs::write(bin.join(b), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(bin.join(b), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(root.join("etc/ai-env")).unwrap();
    std::fs::write(root.join("etc/ai-env/relay-mcp.json"), format!("{MCP_CONFIG_JSON}\n")).unwrap();
}

/// `plant_vm_tree` alone passes, V4 ending `, no relay programs and no /run/ai-env`; with the three relay files, V3
/// ends `; the relay MCP config is the shim's` and V4 `, the relay programs 0755 and no /run/ai-env`. Each bad case
/// fails its check alone, naming its problem. Kills M-V23, M-V24, M-V25.
#[tokio::test]
async fn validate_checks_the_relay_files_when_the_image_holds_them() {
    let detail = |checks: &[(String, bool, String)], id: &str| checks.iter().find(|c| c.0 == id).map(|c| c.2.clone()).unwrap();
    let failing = |checks: &[(String, bool, String)]| checks.iter().filter(|c| !c.1).map(|c| c.0.clone()).collect::<Vec<_>>();
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let checks = checks_of(t.path()).await;
    assert_eq!(failing(&checks), Vec::<String>::new(), "{checks:?}");
    assert!(detail(&checks, "V4").ends_with(", no relay programs and no /run/ai-env"), "{checks:?}");
    assert!(!detail(&checks, "V3").contains("relay"), "{checks:?}");
    let (s, b) = super::validate_in(t.path(), "").await;
    assert_eq!(s, 200, "{b}");
    plant_relay(t.path());
    let checks = checks_of(t.path()).await;
    assert_eq!(failing(&checks), Vec::<String>::new(), "{checks:?}");
    assert!(detail(&checks, "V3").ends_with("; the relay MCP config is the shim's"), "{checks:?}");
    assert!(detail(&checks, "V4").ends_with(", the relay programs 0755 and no /run/ai-env"), "{checks:?}");
    type Plant = fn(&Path);
    let cases: [(&str, &str, Plant); 7] = [
        ("V3", "/etc/ai-env/relay-mcp.json is not the shim's relay MCP config", |r| std::fs::write(r.join("etc/ai-env/relay-mcp.json"), "{}").unwrap()),
        ("V3", "/etc/ai-env/relay-mcp.json: ", |r| std::fs::write(r.join("etc/ai-env/relay-mcp.json"), "{").unwrap()),
        ("V4", "/etc/ai-env/relay-mcp.json is missing", |r| std::fs::remove_file(r.join("etc/ai-env/relay-mcp.json")).unwrap()),
        ("V4", "/usr/local/bin/ai-env-relay-client is mode 0775, not 0755", |r| std::fs::set_permissions(r.join("usr/local/bin/ai-env-relay-client"), std::fs::Permissions::from_mode(0o775)).unwrap()),
        ("V4", "/usr/local/bin/ai-env-relay-mcp is missing", |r| std::fs::remove_file(r.join("usr/local/bin/ai-env-relay-mcp")).unwrap()),
        ("V4", "/etc/ai-env/relay-mcp.json is in the image without its relay client", |r| {
            std::fs::remove_file(r.join("usr/local/bin/ai-env-relay-client")).unwrap();
            std::fs::remove_file(r.join("usr/local/bin/ai-env-relay-mcp")).unwrap();
        }),
        ("V4", "/run/ai-env exists (a relay session baked into the image)", |r| std::fs::create_dir_all(r.join("run/ai-env")).unwrap()),
    ];
    for (id, want, plant) in cases {
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        plant_relay(t.path());
        plant(t.path());
        let checks = checks_of(t.path()).await;
        assert_eq!(failing(&checks), [id], "{want}: its check alone: {checks:?}");
        assert!(detail(&checks, id).contains(want), "{want}: {checks:?}");
        let (s, b) = super::validate_in(t.path(), "").await;
        assert!(s == 503 && b.contains(id) && b.contains(want), "{want}: {s} {b}");
    }
}

/// MANIFEST lists the three relay files right after the shim; the Dockerfile's relay block (its two COPY lines, the
/// version loop, which compares each binary's whole `--version` line to `<name> <the shim's version>`, the three
/// `stat` tests, the config's `grep`, `/run/ai-env`'s absence and the gate's `echo`) sits after the claude-cache
/// gate's `echo` and before `EXPOSE`; the ENTRYPOINT names neither relay flag. Kills M-V26, M-V27, M-V64.
#[test]
fn the_image_bakes_the_relay_programs_and_their_config() {
    let manifest = std::fs::read_to_string(format!("{REPO}/image/MANIFEST")).unwrap();
    assert!(
        manifest.contains("file    ai-env                  0755\nfile    ai-env-relay-client     0755\nfile    ai-env-relay-mcp        0755\nfile    relay-mcp.json          0644\n"),
        "{manifest}"
    );
    let df = std::fs::read_to_string(format!("{REPO}/image/Dockerfile")).unwrap();
    let at = |what: &str| df.find(what).unwrap_or_else(|| panic!("{what} missing from image/Dockerfile"));
    let cache = at("echo \"claude-cache gate: /opt/ai-env/claude root 0755, empty\"");
    let (copy_bins, copy_config) = (at("\nCOPY ai-env-relay-client ai-env-relay-mcp /usr/local/bin/\n"), at("\nCOPY relay-mcp.json /etc/ai-env/relay-mcp.json\n"));
    let block = [
        "chmod 0755 /usr/local/bin/ai-env-relay-client /usr/local/bin/ai-env-relay-mcp;",
        "chmod 0644 /etc/ai-env/relay-mcp.json;",
        "shim=$(/usr/local/bin/ai-env --version); shim=${shim##* };",
        "for b in ai-env-relay-client ai-env-relay-mcp; do",
        "v=$(\"/usr/local/bin/$b\" --version); \\\n",
        "test \"$v\" = \"$b $shim\" || { echo \"$b --version printed $v, not $b $shim\"; exit 1; };",
        "test \"$(stat -c '%u:%g %a' \"/usr/local/bin/$b\")\" = \"0:0 755\"",
        "test \"$(stat -c '%u:%g %a' /etc/ai-env/relay-mcp.json)\" = \"0:0 644\"",
        "grep -qF '\"command\":\"/usr/local/bin/ai-env-relay-mcp\"' /etc/ai-env/relay-mcp.json",
        "test ! -e /run/ai-env ||",
        "echo \"relay gate: ai-env-relay-client and ai-env-relay-mcp $shim, root 0755; relay-mcp.json root 0644; no /run/ai-env\"",
    ];
    let expose = at("\nEXPOSE ");
    assert!(cache < copy_bins && copy_bins < copy_config && copy_config < expose, "the relay block after the cache gate, before EXPOSE");
    let mut last = copy_config;
    for want in block {
        let i = at(want);
        assert!(i > last && i < expose, "{want}: in order, in the relay block");
        last = i;
    }
    let entry = df.lines().find_map(|l| l.strip_prefix("ENTRYPOINT ")).unwrap();
    assert!(!entry.contains("--relay-client") && !entry.contains("--relay-mcp-config"), "{entry}");
}
