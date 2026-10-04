//! `ai-env vm exec|attach|health --detail` as processes (plan S6, W4): flag
//! and row validation before any Touch ID or AWS-shaped call (the fake
//! records no call at all), the `--env` refusals (the value never echoed),
//! `--shell` rows refused, the agent knob refused without the fake API or off
//! loopback, the fake endpoint's own refusals (an image older than S6, a
//! draining VM) mapped to their exits, and `vm health --detail` through the
//! file-backed fake (`FakeState::get_health_detail`). The interop through a
//! real shim is `tests/shim_bridge_local.rs`. Every process here ends within
//! [`LIMIT`] (killed and failed past it): some dial, and a reconnect loop
//! that ignored its budget must fail the test, not hang it.
use crate::cli::{code, stderr, stdout, World};
use crate::fake_endpoint::{Action, FakeEndpoint};
use ai_env_cli::bridge::api::Call;
use std::fs;
use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Every process of these tests.
const LIMIT: Duration = Duration::from_secs(60);

/// `cmd` to its end, stdout and stderr read meanwhile; killed and failed past [`LIMIT`].
fn bounded(mut cmd: Command) -> Output {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = r.read_to_end(&mut v);
            v
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let t = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if t.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ai-env {:?} ran past {LIMIT:?}", cmd.get_args().collect::<Vec<_>>());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

/// `ai-env <args>` in `w`, bounded.
fn run(w: &World, args: &[&str]) -> Output {
    bounded(w.cmd(args))
}

/// [`run`] with these variables set (`Some`) or removed (`None`).
fn run_env(w: &World, args: &[&str], vars: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = w.cmd(args);
    for (k, v) in vars {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    bounded(cmd)
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(o)).unwrap_or_else(|e| panic!("not JSON ({e}): {}\nstderr: {}", stdout(o), stderr(o)))
}

/// A VM `vm run` started (internet egress; `extra` flags added).
fn started(w: &World, extra: &[&str]) -> String {
    let mut args = vec!["vm", "run", "--egress", "internet", "--json"];
    args.extend_from_slice(extra);
    let o = run(w, &args);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    json(&o)["id"].as_str().unwrap().to_string()
}

fn calls(w: &World) -> Vec<Call> {
    w.state().calls
}

/// Rewrite the row of `id` (`state/vms/<id>.toml`).
fn edit_row(w: &World, id: &str, f: impl FnOnce(&mut toml::Table)) {
    let path = w.bridge().join("state").join("vms").join(format!("{id}.toml"));
    let mut row: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    f(&mut row);
    fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
}

/// A loopback address nothing listens on.
fn closed_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

#[test]
fn exec_refusals_happen_before_any_call_and_never_echo_a_value() {
    let w = World::new("");
    let id = started(&w, &[]);
    let before = calls(&w);
    let cases: Vec<(Vec<String>, i32, &str)> = vec![
        (vec!["not/an-id".into(), "--".into(), "true".into()], 2, "not a microvm id"),
        (vec!["microvm-00000000-0000-4000-8000-0000000000ff".into(), "--".into(), "true".into()], 1, "only VMs `ai-env vm run` started"),
        (vec![id.clone(), "--cwd".into(), "relative/dir".into(), "--".into(), "true".into()], 2, "absolute path"),
        (vec![id.clone(), "--cwd".into(), "/home/../etc".into(), "--".into(), "true".into()], 2, "absolute path"),
        (vec![id.clone(), "--".into(), String::new()], 2, "argv[0]"),
        (vec![id.clone(), "--env".into(), "value-must-not-echo-0".into(), "--".into(), "true".into()], 2, "expected NAME=VALUE"),
        (vec![id.clone(), "--env".into(), "BAD-NAME=value-must-not-echo-1".into(), "--".into(), "true".into()], 2, "[A-Za-z_]"),
        (vec![id.clone(), "--env".into(), "LANG=a".into(), "--env".into(), "LANG=b".into(), "--".into(), "true".into()], 2, "given twice"),
    ];
    for (args, want, says) in &cases {
        let mut all = vec!["vm", "exec"];
        all.extend(args.iter().map(String::as_str));
        let o = run(&w, &all);
        assert_eq!(code(&o), *want, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(says), "{args:?}: {}", stderr(&o));
        assert!(!stderr(&o).contains("value-must-not-echo"), "{args:?}: {}", stderr(&o));
    }
    let o = run(&w, &["vm", "exec", &id, "--"]);
    assert_eq!(code(&o), 2, "no command: clap's usage error: {}", stderr(&o));
    for (n, name) in ["CLAUDECODE", "NODE_OPTIONS", "AWS_ACCESS_KEY_ID", "aws_region", "GITHUB_TOKEN", "Api_Key", "MY_SECRET", "DB_PASSWORD", "HOME", "PATH", "CLAUDE_CONFIG_DIR"].iter().enumerate() {
        let kv = format!("{name}=value-must-not-echo-{n}");
        let o = run(&w, &["vm", "exec", &id, "--env", &kv, "--", "true"]);
        assert_eq!(code(&o), 9, "{name}: {}", stderr(&o));
        let err = stderr(&o);
        assert!(err.contains(&format!("--env {name}")) && !err.contains("value-must-not-echo"), "{name}: {err}");
    }
    assert_eq!(calls(&w), before, "nothing reached the fake: no GetMicrovm, no token, no run");
}

#[test]
fn rows_without_a_session_token_or_with_shell_are_refused_before_any_call() {
    let w = World::new("");
    let shell = started(&w, &["--shell"]);
    let plain = started(&w, &[]);
    edit_row(&w, &plain, |row| {
        row.remove("session_token");
    });
    let spawn = uuid::Uuid::now_v7().to_string();
    let before = calls(&w);
    let o = run(&w, &["vm", "exec", &shell, "--", "true"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("in-vm-firewall") && stderr(&o).contains("without --shell"), "{}", stderr(&o));
    assert_eq!(code(&run(&w, &["vm", "attach", &shell, "--spawn", &spawn])), 9);
    let o = run(&w, &["vm", "exec", &plain, "--", "true"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("no session token"), "{}", stderr(&o));
    assert_eq!(code(&run(&w, &["vm", "health", &plain, "--detail"])), 1);
    let o = run(&w, &["vm", "attach", &plain, "--spawn", "not-a-uuid"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert_eq!(code(&run(&w, &["vm", "attach", &plain, "--spawn", &spawn, "--from-seq", "0"])), 2);
    assert_eq!(calls(&w), before, "nothing reached the fake");
}

#[test]
fn the_agent_knob_needs_the_fake_api_and_a_loopback_address() {
    let w = World::new("");
    let id = started(&w, &[]);
    let before = calls(&w);
    let o = run_env(&w, &["vm", "exec", &id, "--", "true"], &[("AI_ENV_BRIDGE_LAB_FAKE_API", None), ("AI_ENV_BRIDGE_LAB_AGENT_ADDR", Some("127.0.0.1:18080"))]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("needs AI_ENV_BRIDGE_LAB_FAKE_API"), "{}", stderr(&o));
    let o = run_env(&w, &["vm", "exec", &id, "--", "true"], &[("AI_ENV_BRIDGE_LAB_AGENT_ADDR", Some("10.0.0.5:8080"))]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("loopback"), "{}", stderr(&o));
    assert_eq!(calls(&w), before, "nothing reached the fake");
}

/// The six proxy names are ai-env's own on vpc rows only: on an internet row
/// they pass validation and the command reaches the dial (here a closed
/// loopback port through the knob: no shim answers, exit 8 once the scaled
/// reconnect budget is spent — never a network call).
#[test]
fn proxy_names_are_refused_on_vpc_rows_only() {
    let w = World::new("");
    let id = started(&w, &[]);
    let o = run_env(&w, &["vm", "exec", &id, "--env", "https_proxy=http://127.0.0.1:9", "--", "true"], &[("AI_ENV_BRIDGE_LAB_AGENT_ADDR", Some(&closed_port().to_string()))]);
    assert_eq!(code(&o), 8, "validation passed, the dial found nothing: {}", stderr(&o));
    assert!(stderr(&o).contains("no lasting /agent connection"), "{}", stderr(&o));
    let st = w.state();
    let mints = st.calls.iter().filter(|c| matches!(c, Call::Token { id: t, port: 8080, minutes: 60 } if *t == id)).count();
    assert_eq!(mints, 1, "one 60-minute Port(8080) token for the session");
    assert!(w.audit().contains("\"vm_exec\"") && w.audit().contains("\"argv0\":\"true\""), "{}", w.audit());
    edit_row(&w, &id, |row| {
        row.insert("egress".into(), "vpc".into());
    });
    let before = calls(&w);
    for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"] {
        let kv = format!("{name}=http://127.0.0.1:9");
        let o = run(&w, &["vm", "exec", &id, "--env", &kv, "--", "true"]);
        assert_eq!(code(&o), 9, "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains("proxy variables itself"), "{}", stderr(&o));
    }
    assert_eq!(calls(&w), before);
}

#[test]
fn health_detail_through_the_fake_and_a_stale_bearer() {
    let w = World::new("");
    let id = started(&w, &[]);
    let o = run(&w, &["vm", "health", &id, "--detail", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["backend"], "fake");
    assert_eq!(v["id"], id.as_str());
    assert_eq!((v["detail"]["hook_source"].as_str(), v["detail"]["agent_guard"].as_str()), (Some("peer"), Some("on")));
    assert_eq!(v["detail"]["microvm_id"], id.as_str(), "the Health fields are flattened in");
    let o = run(&w, &["vm", "health", &id, "--detail"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("hook_source peer, agent_guard on") && stdout(&o).contains("spawns     none"), "{}", stdout(&o));
    let row: toml::Table = toml::from_str(&fs::read_to_string(w.bridge().join("state").join("vms").join(format!("{id}.toml"))).unwrap()).unwrap();
    let session = row["session_token"].as_str().unwrap().to_string();
    assert!(!stdout(&o).contains(&session) && !stderr(&o).contains(&session));
    let details = calls(&w).iter().filter(|c| matches!(c, Call::HealthDetail { port: 8080, .. })).count();
    assert_eq!(details, 2);
    // A row whose token is not the one /run committed to: the bearer is refused.
    edit_row(&w, &id, |row| {
        row.insert("session_token".into(), "z".repeat(64).into());
    });
    let o = run(&w, &["vm", "health", &id, "--detail"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("refused this Mac's session bearer (stale row?)"), "{}", stderr(&o));
    assert!(!stderr(&o).contains(&"z".repeat(64)));
}

#[test]
fn health_detail_of_a_terminated_vm_is_exit_8() {
    let w = World::new("");
    let id = started(&w, &[]);
    w.update(|s| s.vms.get_mut(&id).unwrap().state = ai_env_cli::bridge::api::VmState::Terminated);
    let o = run(&w, &["vm", "health", &id, "--detail"]);
    assert_eq!(code(&o), 8, "{}", stderr(&o));
    assert!(stderr(&o).contains("TERMINATED"), "{}", stderr(&o));
    assert!(!calls(&w).iter().any(|c| matches!(c, Call::HealthDetail { .. })), "no request to a terminated VM");
    let o = run(&w, &["vm", "exec", &id, "--", "true"]);
    assert_eq!(code(&o), 8, "GetMicrovm first: {}", stderr(&o));
}

/// The endpoint's own refusals through the binary (no shim behind it): a 404
/// is an image older than S6 (exit 7), a 503 `draining` a VM going away (exit 8).
#[test]
fn agent_refusals_map_to_their_exits() {
    let w = World::new("");
    let id = started(&w, &[]);
    let ep = FakeEndpoint::start(&w.fake(), closed_port());
    let draining = Action::Respond { status: 503, headers: vec![("content-type".into(), "application/json".into())], body: r#"{"status":"draining"}"#.into() };
    ep.script([Action::status(404, &[]), draining]);
    let exec = || run_env(&w, &["vm", "exec", &id, "--", "true"], &[("AI_ENV_BRIDGE_LAB_AGENT_ADDR", Some(&ep.addr.to_string()))]);
    let o = exec();
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("older than S6"), "{}", stderr(&o));
    let o = exec();
    assert_eq!(code(&o), 8, "{}", stderr(&o));
    assert!(stderr(&o).contains("draining"), "{}", stderr(&o));
    assert_eq!(ep.attempts().iter().map(|a| (a.status, a.path.as_str())).collect::<Vec<_>>(), vec![(404, "/agent"), (503, "/agent")]);
}
