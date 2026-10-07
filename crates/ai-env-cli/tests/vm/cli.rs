//! `ai-env vm …` / `ai-env lab …` as processes against the file-backed fake
//! (`AI_ENV_BRIDGE_LAB_FAKE_API`, debug builds; plan S4 D23, D25): T4.4 —
//! three concurrent `vm run --workspace` → exactly one RunMicrovm; the
//! cross-workspace `max_concurrent`; gc classes and actions — plus the CLI
//! contract of §6 (exit codes, hidden tokens, audit rows), the container
//! unseal path with the fake age, and S5's `vm smoke --egress` echo
//! assertions and the `vm run --egress vpc` connector-state line. Every
//! process gets its own bridge root,
//! keystore and HOME under one temp tree; polls are scaled to milliseconds
//! (`AI_ENV_BRIDGE_LAB_BACKOFF_MS=1`).
use crate::common::CONNECTOR;
use ai_env_cli::bridge::api::{FakeState, IdleSpec, VmInfo, VmState, FAKE_IMAGE_ARN, ENDPOINT_SUFFIX};
use ai_env_cli::bridge::infra::InfraState;
use ai_env_cli::wire::frame::{Health, HealthStatus};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// One isolated world: `bridge/` (bridge.toml, state, audit), `keys/`,
/// `ws/` and `ws2/` (workspaces under the roots), `fake.json`.
pub struct World {
    tmp: tempfile::TempDir,
}

impl World {
    pub fn new(vm_toml: &str) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for d in ["bridge", "keys", "ws", "ws2", "outside"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let roots = [root.join("ws"), root.join("ws2")].map(|p| format!("{:?}", fs::canonicalize(p).unwrap().display().to_string()));
        let toml = format!(
            "[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\nexecution_role_arn = \"arn:aws:iam::123456789012:role/ai-env-exec\"\n\n[workspaces]\nroots = [{}]\n\n[vm]\n{vm_toml}\n",
            roots.join(", ")
        );
        fs::write(root.join("bridge").join("bridge.toml"), toml).unwrap();
        let w = World { tmp };
        w.update(|s| s.auto_advance = true);
        w
    }

    pub fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub fn ws(&self) -> PathBuf {
        self.root().join("ws")
    }

    pub fn fake(&self) -> PathBuf {
        self.root().join("fake.json")
    }

    pub fn bridge(&self) -> PathBuf {
        self.root().join("bridge")
    }

    /// `ai-env <args>` in this world, against the fake, polls in milliseconds.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .env("HOME", self.root())
            .env("AI_ENV_BRIDGE_DIR", self.bridge())
            .env("AI_ENV_DIR", self.root().join("keys"))
            .env_remove("AI_ENV_BRIDGE_CONFIG")
            .env_remove("AI_ENV_BRIDGE_TRACE")
            .env_remove("RUST_LOG")
            .stdin(Stdio::null());
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AWS_") || k.starts_with("PULUMI_") || k.starts_with("AI_ENV_BRIDGE_LAB_") {
                c.env_remove(&k);
            }
        }
        c.env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake()).env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        c
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("spawn ai-env")
    }

    pub fn state(&self) -> FakeState {
        serde_json::from_str(&fs::read_to_string(self.fake()).unwrap()).unwrap()
    }

    pub fn update(&self, f: impl FnOnce(&mut FakeState)) {
        let mut s = fs::read_to_string(self.fake()).ok().filter(|t| !t.trim().is_empty()).map_or_else(FakeState::new, |t| serde_json::from_str(&t).unwrap());
        f(&mut s);
        fs::write(self.fake(), serde_json::to_string_pretty(&s).unwrap()).unwrap();
    }

    pub fn runs(&self) -> usize {
        self.state().calls.iter().filter(|c| matches!(c, ai_env_cli::bridge::api::Call::Run { .. })).count()
    }

    pub fn audit(&self) -> String {
        fs::read_to_string(self.bridge().join("audit.jsonl")).unwrap_or_default()
    }

    /// Every file under the temp tree except the VM rows (which hold the
    /// session token by design), concatenated.
    pub fn all_files_except_rows(&self) -> String {
        let mut out = String::new();
        let rows = self.bridge().join("state").join("vms");
        let mut stack = vec![self.root().to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.starts_with(&rows) {
                    continue;
                }
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    stack.push(p);
                } else if t.is_file() {
                    out.push_str(&String::from_utf8_lossy(&fs::read(&p).unwrap()));
                }
            }
        }
        out
    }
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(o)).unwrap_or_else(|e| panic!("not JSON ({e}): {}\nstderr: {}", stdout(o), stderr(o)))
}

pub fn foreign_vm(n: u64, owner: Option<&str>, state: VmState, age_s: i64) -> (VmInfo, Option<Health>) {
    let id = format!("microvm-11111111-0000-4000-8000-{n:012x}");
    let now = ai_env_cli::wire::time::unix_now() as i64;
    let vm = VmInfo {
        id: id.clone(),
        state,
        endpoint: format!("eeeeeeee-0000-4000-8000-{n:012x}{ENDPOINT_SUFFIX}"),
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        started_at_unix: Some(now - age_s),
        max_duration_s: 28_800,
        state_reason: None,
        execution_role_arn: None,
        idle: Some(IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true }),
        ingress: vec![],
        egress: vec![],
        terminated_at_unix: None,
    };
    let health = owner.map(|o| Health {
        status: HealthStatus::Ok,
        shim_version: "0.1.0".into(),
        claude_version: Some("2.1.284".into()),
        microvm_id: Some(id.clone()),
        owner: Some(o.into()),
        created: Some("2026-09-29T08:00:00.000Z".into()),
        boot_nonce: Some(format!("{n:032x}")),
        run_hook_seen: true,
        uptime_s: 1,
        wire: None,
    });
    (vm, health)
}

// ---- T4.4 ------------------------------------------------------------------------------------

#[test]
fn cli_three_concurrent_runs_same_workspace_one_run_microvm() {
    let w = World::new("");
    let ws = w.ws().display().to_string();
    let children: Vec<_> = (0..3)
        .map(|_| w.cmd(&["vm", "run", "--workspace", &ws, "--max-duration", "3600", "--egress", "internet", "--json"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap())
        .collect();
    let outs: Vec<Output> = children.into_iter().map(|c| c.wait_with_output().unwrap()).collect();
    for o in &outs {
        assert_eq!(code(o), 0, "{}", stderr(o));
    }
    let ids: Vec<String> = outs.iter().map(|o| json(o)["id"].as_str().unwrap().to_string()).collect();
    assert!(ids.windows(2).all(|p| p[0] == p[1]), "one VM for the workspace: {ids:?}");
    assert_eq!(w.runs(), 1, "exactly one RunMicrovm");
    assert_eq!(outs.iter().filter(|o| json(o)["reused"] == true).count(), 2);
}

#[test]
fn cli_max_concurrent_1_second_workspace_exits_9() {
    let w = World::new("max_concurrent = 1");
    let ws = w.ws().display().to_string();
    let ws2 = w.root().join("ws2").display().to_string();
    assert_eq!(code(&w.run(&["vm", "run", "--workspace", &ws, "--egress", "internet"])), 0);
    let o = w.run(&["vm", "run", "--workspace", &ws2, "--egress", "internet"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("max_concurrent"), "{}", stderr(&o));
    assert_eq!(w.runs(), 1);
}

#[test]
fn cli_gc_dry_run_yes_include_orphans() {
    let w = World::new("");
    let me = ai_env_cli::bridge::vm::owner();
    // A registry VM whose wall is (almost) over: max duration 60 s.
    let o = w.run(&["vm", "run", "--max-duration", "60", "--egress", "internet", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let expired = json(&o)["id"].as_str().unwrap().to_string();
    let (orphan, oh) = foreign_vm(1, Some(&me), VmState::Running, 7200);
    let (foreign, fh) = foreign_vm(2, Some("someone@elsewhere"), VmState::Running, 7200);
    let (suspended, _) = foreign_vm(3, None, VmState::Suspended, 7200);
    w.update(|s| {
        for (vm, h) in [(orphan.clone(), oh), (foreign.clone(), fh), (suspended.clone(), None)] {
            if let Some(h) = h {
                s.health_override.insert(vm.id.clone(), h);
            }
            s.insert_vm(vm);
        }
    });
    let before = fs::read_to_string(w.fake()).unwrap();
    let dry = w.run(&["vm", "gc", "--json"]);
    assert_eq!(code(&dry), 0, "{}", stderr(&dry));
    let classes: Vec<(String, String)> = json(&dry)["items"].as_array().unwrap().iter().map(|i| (i["id"].as_str().unwrap_or("").to_string(), i["class"].as_str().unwrap().to_string())).collect();
    for (id, class) in [(&expired, "registry:expired"), (&orphan.id, "orphan:mine"), (&foreign.id, "foreign"), (&suspended.id, "unprobed")] {
        assert!(classes.contains(&(id.clone(), class.to_string())), "{id} {class}: {classes:?}");
    }
    assert!(!fs::read_to_string(w.fake()).unwrap().contains("\"Terminate\""), "a dry run terminates nothing");
    drop(before);
    let yes = w.run(&["vm", "gc", "--yes"]);
    assert_eq!(code(&yes), 0, "{}", stderr(&yes));
    let st = w.state();
    assert!(st.vms[&expired].state.is_terminal(), "the expired registry VM is terminated");
    assert_eq!(st.vms[&orphan.id].state, VmState::Running, "orphans only with --include-orphans");
    let with_orphans = w.run(&["vm", "gc", "--yes", "--include-orphans", "1h"]);
    assert_eq!(code(&with_orphans), 0, "{}", stderr(&with_orphans));
    let st = w.state();
    assert!(st.vms[&orphan.id].state.is_terminal(), "own orphan older than 1h terminated");
    assert_eq!(st.vms[&foreign.id].state, VmState::Running, "never another owner's VM");
    assert_eq!(st.vms[&suspended.id].state, VmState::Suspended, "never a suspended VM");
    let probed_suspended = st.calls.iter().any(|c| matches!(c, ai_env_cli::bridge::api::Call::Token { id, .. } if id == &suspended.id));
    assert!(!probed_suspended, "a SUSPENDED VM is never probed (a request would resume it)");
    assert!(w.audit().contains("\"vm_gc\""));
}

// ---- the CLI contract ---------------------------------------------------------------------------

#[test]
fn cli_run_without_connector_exits_9_unless_egress_internet_audited() {
    let w = World::new("");
    let o = w.run(&["vm", "run"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(w.runs(), 0);
    let o = w.run(&["vm", "run", "--egress", "internet"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(w.audit().contains("\"vm_egress_internet\""), "{}", w.audit());
    let o = w.run(&["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 9, "vpc without a connector: {}", stderr(&o));
}

#[test]
fn cli_run_outside_roots_exits_9() {
    let w = World::new("");
    let o = w.run(&["vm", "run", "--workspace", &w.root().join("outside").display().to_string(), "--egress", "internet"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(w.runs(), 0);
}

/// A `[creds]` value only the credential path acts on never blocks a command
/// that carries no credential (the S7 audit's finding: `Ctx::load` validated
/// `[creds]`, so a Tier-B mode or a bad budget broke `vm list` too).
#[test]
fn creds_settings_never_block_an_uncredentialed_command() {
    for creds in ["mode = \"reverse-refresh\"\n", "deliver = \"stdin\"\n", "unseal_timeout_s = 5\n"] {
        let w = World::new("");
        let path = w.bridge().join("bridge.toml");
        let toml = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{toml}\n[creds]\n{creds}")).unwrap();
        let o = w.run(&["vm", "list"]);
        assert_eq!(code(&o), 0, "{creds}: {}", stderr(&o));
    }
}

#[test]
fn cli_list_hides_terminated_without_all() {
    let w = World::new("");
    let o = w.run(&["vm", "run", "--egress", "internet", "--json"]);
    let id = json(&o)["id"].as_str().unwrap().to_string();
    assert!(stdout(&w.run(&["vm", "list"])).contains(&id));
    assert_eq!(code(&w.run(&["vm", "terminate", &id])), 0);
    let l = w.run(&["vm", "list"]);
    assert!(!stdout(&l).contains(&id), "{}", stdout(&l));
    let all = stdout(&w.run(&["vm", "list", "--all"]));
    let line = all.lines().find(|l| l.starts_with(&id)).unwrap_or_else(|| panic!("{all}"));
    // ID STATE AGE WALL-LEFT WHERE SOURCE: a terminated VM has no wall left (live 30 Sep 2026 it counted down).
    let cells: Vec<&str> = line.split_whitespace().collect();
    assert_eq!((cells[1], cells[3]), ("TERMINATED", "-"), "{line}");
}

#[test]
fn cli_token_hidden_unless_reveal_and_expiry_recorded() {
    let w = World::new("");
    let id = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let o = w.run(&["vm", "token", &id]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stdout(&o).contains("eyJ") && !stderr(&o).contains("eyJ"), "hidden: {}", stdout(&o));
    let r = w.run(&["vm", "token", &id, "--reveal", "--minutes", "5"]);
    assert_eq!(code(&r), 0);
    let value = stdout(&r).trim().to_string();
    assert!(value.starts_with("eyJ") && value.lines().count() == 1, "alone on stdout: {value}");
    assert!(!w.all_files_except_rows().contains(&value), "the revealed token is written nowhere");
    let row = fs::read_to_string(w.bridge().join("state").join("vms").join(format!("{id}.toml"))).unwrap();
    let parsed: toml::Value = toml::from_str(&row).unwrap();
    let expiry = parsed["token_expiries"]["8080"].as_integer().expect("token_expiries.8080 recorded");
    assert!(expiry >= ai_env_cli::wire::time::unix_now() as i64 + 240, "a 5-minute expiry: {expiry}");
    assert!(!row.contains(&value), "never the value");
    let bad = w.run(&["vm", "token", &id, "--port", "9000"]);
    assert_eq!(code(&bad), 9, "{}", stderr(&bad));
    assert_eq!(code(&w.run(&["vm", "token", &id, "--minutes", "61"])), 2);
    assert!(w.audit().contains("\"vm_token\""));
}

#[test]
fn cli_terminate_all_needs_yes() {
    let w = World::new("");
    let id = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let o = w.run(&["vm", "terminate", "--all"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stdout(&o).contains(&id));
    assert_eq!(w.state().vms[&id].state, VmState::Running);
    assert_eq!(code(&w.run(&["vm", "terminate", "--all", "--yes"])), 0);
    assert!(w.state().vms[&id].state.is_terminal());
}

#[test]
fn cli_terminate_rowless_vm_needs_yes_and_foreign_image_is_policy() {
    let w = World::new("");
    let (vm, _) = foreign_vm(7, None, VmState::Running, 10);
    let mut other = foreign_vm(8, None, VmState::Running, 10).0;
    other.image_arn = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:other".into();
    w.update(|s| {
        s.insert_vm(vm.clone());
        s.insert_vm(other.clone());
    });
    assert_eq!(code(&w.run(&["vm", "terminate", &vm.id])), 1);
    assert_eq!(code(&w.run(&["vm", "terminate", &vm.id, "--yes"])), 0);
    assert_eq!(code(&w.run(&["vm", "terminate", &other.id, "--yes"])), 9);
}

#[test]
fn cli_smoke_passes_against_the_fake_and_leaves_no_vm() {
    let w = World::new("");
    let o = w.run(&["vm", "smoke", "--json"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let rec = json(&o);
    assert_eq!(rec["backend"], "fake");
    assert_eq!(rec["ok"], true);
    assert_eq!(rec["max_duration_s"], 900);
    assert_eq!(rec["health"]["run_hook_seen"], true);
    let id = rec["id"].as_str().unwrap();
    assert!(w.state().vms[id].state.is_terminal());
    assert!(stderr(&o).contains("LAB KNOBS ACTIVE"), "the fake is announced: {}", stderr(&o));
    assert!(stdout(&w.run(&["vm", "list"])).contains("no VMs"));
}

#[test]
fn cli_smoke_failure_still_terminates() {
    let w = World::new("");
    let first = "microvm-00000000-0000-4000-8000-000000000001";
    let (_, h) = foreign_vm(1, Some("someone@elsewhere"), VmState::Running, 0);
    let mut h = h.unwrap();
    h.microvm_id = Some(first.into());
    w.update(|s| {
        s.health_override.insert(first.into(), h);
    });
    let o = w.run(&["vm", "smoke"]);
    assert_eq!(code(&o), 1, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("owner"), "{}", stderr(&o));
    assert!(w.state().vms[first].state.is_terminal(), "terminated after the failed assertion");
}

#[test]
fn cli_smoke_adopts_after_ambiguous_run_failure() {
    let w = World::new("");
    w.update(|s| {
        let f = |after| ai_env_cli::bridge::api::FakeFailure { kind: "ambiguous".into(), message: "timeout".into(), on: Some("run".into()), after_effect: after };
        s.failures.push_back(f(true));
        s.failures.push_back(f(false));
    });
    let o = w.run(&["vm", "smoke"]);
    assert_eq!(code(&o), 7, "{}\n{}", stdout(&o), stderr(&o));
    let st = w.state();
    assert_eq!(st.vms.len(), 1);
    assert!(st.vms.values().all(|v| v.state.is_terminal()), "the VM the ambiguous call created is found and terminated: {}", stderr(&o));
}

#[test]
fn cli_outputs_never_contain_a_token_or_session_token() {
    let w = World::new("");
    let mut all = String::new();
    let run = w.run(&["vm", "run", "--egress", "internet", "--json"]);
    all.push_str(&stdout(&run));
    all.push_str(&stderr(&run));
    let id = json(&run)["id"].as_str().unwrap().to_string();
    for args in [vec!["vm", "list", "--json"], vec!["vm", "status", &id, "--json"], vec!["vm", "health", &id, "--json"], vec!["vm", "token", &id], vec!["vm", "gc", "--json"], vec!["vm", "smoke", "--json"]] {
        let o = w.run(&args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        all.push_str(&stdout(&o));
        all.push_str(&stderr(&o));
    }
    let row: toml::Value = toml::from_str(&fs::read_to_string(w.bridge().join("state").join("vms").join(format!("{id}.toml"))).unwrap()).unwrap();
    let session = row["session_token"].as_str().unwrap().to_string();
    assert_eq!(session.len(), 64);
    all.push_str(&w.all_files_except_rows());
    assert!(!all.contains(&session), "the session token leaked");
    assert!(!all.contains("eyJ") || !all.lines().any(|l| l.contains("eyJ") && !l.contains("[redacted")), "an endpoint token leaked");
}

#[test]
fn cli_suspend_resume_status_and_health() {
    let w = World::new("");
    let id = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let s = w.run(&["vm", "suspend", &id]);
    assert_eq!(code(&s), 0, "{}", stderr(&s));
    assert!(stdout(&s).contains("SUSPENDED"));
    assert_eq!(code(&w.run(&["vm", "suspend", &id])), 7, "Conflict: already suspended");
    assert_eq!(code(&w.run(&["vm", "resume", &id])), 0);
    let st = w.run(&["vm", "status", &id, "--json"]);
    assert_eq!(json(&st)["vm"]["state"], "Running");
    let h = w.run(&["vm", "health", &id]);
    assert_eq!(code(&h), 0, "{}", stderr(&h));
    assert!(stdout(&h).starts_with("ok shim"), "{}", stdout(&h));
    assert_eq!(code(&w.run(&["vm", "status", "microvm-nope"])), 8);
    assert!(w.audit().contains("\"vm_suspend\"") && w.audit().contains("\"vm_resume\""));
}

/// `[egress] accept_platform_dns = <value>` appended to this world's bridge.toml (its last section is `[vm]`).
fn with_dns_pin(w: &World, value: &str) {
    let path = w.bridge().join("bridge.toml");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{text}\n[egress]\naccept_platform_dns = {value}\n")).unwrap();
}

/// `[egress].accept_platform_dns` as `ai-env vm`, `lab` and `egress check` take it: a value that is not a platform
/// resolver's address is refused before anything (exit 1 naming the key, no RunMicrovm, no aws call); the legacy
/// `true` is said, never refused, with the line to write for the newest dns-path verdict; the pin is silent.
#[test]
fn cli_refuses_an_invalid_dns_pin_and_says_what_true_accepts() {
    for bad in ["\"8.8.8.8\"", "\"resolver\"", "[\"fd00:ec2::253\", \"1.1.1.1\"]"] {
        let w = World::new("");
        with_connector(&w);
        with_dns_pin(&w, bad);
        for args in [&["vm", "run", "--egress", "internet"][..], &["lab", "run", "dns-path"][..], &["egress", "check"][..], &["vm", "list"][..]] {
            let o = run_pinned(&w, args);
            assert_eq!(code(&o), 1, "{bad} {args:?}: {}", stderr(&o));
            assert!(stderr(&o).contains("[egress].accept_platform_dns") && !stderr(&o).contains("stub aws"), "{bad} {args:?}: {}", stderr(&o));
        }
        assert_eq!(w.runs(), 0, "{bad}: refused before any RunMicrovm");
        assert!(w.state().calls.is_empty(), "{bad}: no call at all");
    }
    // The legacy `true`: every command works and says it accepts nothing, with the line to write.
    let w = World::new("");
    with_dns_pin(&w, "true");
    let o = run_pinned(&w, &["vm", "list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let config = w.bridge().join("bridge.toml").display().to_string();
    assert!(
        stderr(&o).contains(&format!("ai-env: warning: [egress].accept_platform_dns = true accepts no resolver (it names none); only no-dns passes the credential gate: in {config}: accept_platform_dns = \"<the resolver you tested>\"")),
        "{}",
        stderr(&o)
    );
    // With Mike's newest dns-path row, the exact line.
    fs::create_dir_all(w.bridge().join("lab")).unwrap();
    let row = serde_json::json!({"probe": "dns-path", "stage": "S5", "ext": null, "sdk": null, "verdict": "platform-dns:fd00:ec2::253", "expected": "no-dns", "ts": "2026-10-02T10:00:00Z"});
    fs::write(w.bridge().join("lab").join("probes.jsonl"), format!("{row}\n")).unwrap();
    let o = run_pinned(&w, &["vm", "list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("in {config}: accept_platform_dns = \"fd00:ec2::253\"")), "{}", stderr(&o));
    let o = run_pinned(&w, &["vm", "run", "--egress", "internet"]);
    assert_eq!(code(&o), 0, "a warning, never a refusal: {}", stderr(&o));
    assert_eq!(stderr(&o).matches("accepts no resolver").count(), 1, "said once: {}", stderr(&o));
    // The pin: silent.
    let w = World::new("");
    with_dns_pin(&w, "\"fd00:ec2::253\"");
    let o = run_pinned(&w, &["vm", "list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains("accept_platform_dns"), "{}", stderr(&o));
}

#[test]
fn cli_without_bridge_toml_exits_1_naming_infra_status() {
    let w = World::new("");
    fs::remove_file(w.bridge().join("bridge.toml")).unwrap();
    let o = w.run(&["vm", "images"]);
    assert_eq!(code(&o), 1);
    assert!(stderr(&o).contains("make infra-status WRITE=1"), "{}", stderr(&o));
}

#[test]
fn cli_images_marks_the_active_version() {
    let w = World::new("");
    let o = w.run(&["vm", "images"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("1.0") && stdout(&o).contains("← vm run"), "{}", stdout(&o));
}

// ---- the container unseal path (plan S4 §8) ----------------------------------------------------

fn fake_script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(name)
}

/// `bin/` with the shared fake age (as age, age-keygen, age-plugin-se) and
/// the fake aws; the `ai-env-bridge` keystore key with the public test
/// recipients of tests/cli.rs (an SE tag and an X25519 recovery recipient).
fn install_age_and_keystore(w: &World) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = w.root().join("bin");
    fs::create_dir_all(&bin).unwrap();
    for (src, name) in [("age.sh", "age"), ("age.sh", "age-keygen"), ("age.sh", "age-plugin-se"), ("aws.sh", "aws")] {
        fs::copy(fake_script(src), bin.join(name)).unwrap();
        fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let key = w.root().join("keys").join("keys").join("ai-env-bridge");
    fs::create_dir_all(&key).unwrap();
    let se = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
    let x = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
    fs::write(key.join("identity.txt"), format!("# public key: {se}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
    fs::write(key.join("recipients.txt"), format!("{se}\n{x}\n")).unwrap();
    fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
    bin
}

#[test]
fn cli_container_unseal_one_age_call_no_plaintext_anywhere() {
    use std::io::Write as _;
    let w = World::new("");
    let bin = install_age_and_keystore(&w);
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let age_log = w.root().join("age.log");
    let id = format!("AKIA{}{}", "CRED".repeat(2), "VMTS".repeat(2));
    let secret = format!("{}{}", "Tq8+".repeat(9), "vmts");
    let json = format!("{{\"AccessKey\": {{\"UserName\": \"ai-env-runtime\", \"AccessKeyId\": \"{id}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{secret}\", \"CreateDate\": \"2026-09-29T10:00:00+00:00\"}}}}");
    let mut seal = w.cmd(&["creds", "aws-set", "--user", "ai-env-runtime"]);
    seal.env("PATH", &path).env("TMPDIR", w.root()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = seal.spawn().unwrap();
    child.stdin.take().unwrap().write_all(json.as_bytes()).unwrap();
    let sealed = child.wait_with_output().unwrap();
    assert_eq!(code(&sealed), 0, "{}", stderr(&sealed));
    let _ = fs::remove_file(&age_log);
    let o = w.cmd(&["vm", "images"]).env("PATH", &path).env("FAKE_AGE_LOG", &age_log).env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1").output().unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("runtime key …{}", &id[id.len() - 4..])), "{}", stderr(&o));
    let log = fs::read_to_string(&age_log).unwrap();
    let decrypts: Vec<&str> = log.lines().filter(|l| l.split_whitespace().any(|a| a == "-d")).collect();
    assert_eq!(decrypts.len(), 1, "exactly one decrypt (one Touch ID): {log}");
    assert_eq!(decrypts[0].matches(" -i ").count(), 1, "exactly one identity: {log}");
    let everything = format!("{}{}{}{log}", stdout(&o), stderr(&o), w.all_files_except_rows());
    assert!(!everything.contains(&id) && !everything.contains(&id[4..]), "the access key id leaked");
    assert!(!everything.contains(&secret), "the secret leaked");
}

#[test]
fn cli_without_sealed_key_exits_5() {
    let w = World::new("");
    let o = w.cmd(&["vm", "images"]).env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1").output().unwrap();
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(stderr(&o).contains("make runtime-key"), "{}", stderr(&o));
}

#[test]
fn cli_with_plaintext_aws_env_exits_5() {
    let w = World::new("");
    let creds = w.bridge().join("credentials");
    fs::create_dir_all(&creds).unwrap();
    let id = format!("AKIA{}", "PLAIN".repeat(3) + "X");
    fs::write(creds.join("aws.env"), format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={}\n", "p".repeat(40))).unwrap();
    let o = w.cmd(&["vm", "images"]).env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1").output().unwrap();
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(!stderr(&o).contains(&id[4..]), "the plaintext is never echoed: {}", stderr(&o));
}

// ---- review fixes (plan S4 §16) ------------------------------------------------------------------

#[test]
fn cli_every_json_output_says_backend_fake_under_the_knob() {
    let w = World::new("");
    let run = w.run(&["vm", "run", "--egress", "internet", "--json"]);
    let id = json(&run)["id"].as_str().unwrap().to_string();
    for args in [vec!["vm", "images", "--json"], vec!["vm", "run", "--egress", "internet", "--json"], vec!["vm", "list", "--json"], vec!["vm", "status", &id, "--json"], vec!["vm", "health", &id, "--json"], vec!["vm", "gc", "--json"]] {
        let o = w.run(&args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        assert_eq!(json(&o)["backend"], "fake", "{args:?}");
        assert!(stderr(&o).contains("LAB KNOBS ACTIVE"), "{args:?}: the knob is announced");
    }
}

#[test]
fn cli_refused_smoke_never_terminates_another_runs_vm() {
    let w = World::new("max_concurrent = 1");
    // Another run of the same owner holds the only slot, labelled like a smoke and
    // stamped AFTER this smoke starts (as when two smokes race): the old
    // owner/label/time sweep matched exactly such a row.
    let other = json(&w.run(&["vm", "run", "--egress", "internet", "--label", "smoke", "--json"]))["id"].as_str().unwrap().to_string();
    let row_path = w.bridge().join("state/vms").join(format!("{other}.toml"));
    let later = ai_env_cli::wire::time::rfc3339_utc_ms(ai_env_cli::wire::time::unix_now_ms() + 120_000);
    let mut row: toml::Value = toml::from_str(&fs::read_to_string(&row_path).unwrap()).unwrap();
    row["created"] = toml::Value::String(later);
    fs::write(&row_path, toml::to_string(&row).unwrap()).unwrap();
    let o = w.run(&["vm", "smoke"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(w.state().vms[&other].state, VmState::Running, "the refused smoke touched another run's VM: {}", stderr(&o));
    assert!(!stderr(&o).contains("terminated"), "{}", stderr(&o));
}

#[test]
fn cli_gc_yes_reports_failed_actions_and_exits_7() {
    let w = World::new("");
    let o = w.run(&["vm", "run", "--max-duration", "60", "--egress", "internet", "--json"]);
    let id = json(&o)["id"].as_str().unwrap().to_string();
    w.update(|s| {
        s.failures.push_back(ai_env_cli::bridge::api::FakeFailure { kind: "access_denied".into(), message: "not allowed".into(), on: Some("terminate".into()), after_effect: false });
    });
    let g = w.run(&["vm", "gc", "--yes", "--json"]);
    assert_eq!(code(&g), 7, "{}\n{}", stdout(&g), stderr(&g));
    assert!(json(&g)["errors"].as_array().is_some_and(|e| e.len() == 1 && e[0].as_str().unwrap().contains("not allowed")), "{}", stdout(&g));
    assert!(stderr(&g).contains("not allowed"), "the failure is named: {}", stderr(&g));
    assert_eq!(w.state().vms[&id].state, VmState::Running);
    w.update(|s| {
        s.failures.push_back(ai_env_cli::bridge::api::FakeFailure { kind: "access_denied".into(), message: "not allowed".into(), on: Some("terminate".into()), after_effect: false });
    });
    let text = w.run(&["vm", "gc", "--yes"]);
    assert_eq!(code(&text), 7);
    assert!(!stdout(&text).contains("nothing to terminate"), "{}", stdout(&text));
}

#[test]
fn cli_terminate_all_tries_every_vm_and_names_failures() {
    let w = World::new("");
    let a = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let b = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    w.update(|s| {
        s.failures.push_back(ai_env_cli::bridge::api::FakeFailure { kind: "throttled".into(), message: "Rate exceeded".into(), on: Some("terminate".into()), after_effect: false });
    });
    let o = w.run(&["vm", "terminate", "--all", "--yes"]);
    assert_eq!(code(&o), 7, "{}\n{}", stdout(&o), stderr(&o));
    let st = w.state();
    let terminated = [&a, &b].iter().filter(|id| st.vms[**id].state.is_terminal()).count();
    assert_eq!(terminated, 1, "the second VM is still tried after the first failed");
}

#[test]
fn cli_terminate_rowless_without_yes_refuses_before_any_aws_call() {
    let w = World::new("");
    let (vm, _) = foreign_vm(9, None, VmState::Running, 10);
    w.update(|s| s.insert_vm(vm.clone()));
    let calls_before = w.state().calls.len();
    let o = w.run(&["vm", "terminate", &vm.id]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(w.state().calls.len(), calls_before, "refused before the backend (no Touch ID, no call)");
}

#[test]
fn cli_terminate_own_vm_of_another_image_by_id() {
    let w = World::new("");
    let toml_path = w.bridge().join("bridge.toml");
    let other = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent-v2";
    // The operator's configured image is now another one; the VM was started with --image.
    let text = fs::read_to_string(&toml_path).unwrap().replace(FAKE_IMAGE_ARN, other);
    fs::write(&toml_path, text).unwrap();
    let o = w.run(&["vm", "run", "--image", FAKE_IMAGE_ARN, "--egress", "internet", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let id = json(&o)["id"].as_str().unwrap().to_string();
    let t = w.run(&["vm", "terminate", &id]);
    assert_eq!(code(&t), 0, "its own row names the image: {}", stderr(&t));
    assert!(w.state().vms[&id].state.is_terminal());
}

#[test]
fn cli_terminate_rowless_needs_the_configured_image() {
    let w = World::new("");
    let toml_path = w.bridge().join("bridge.toml");
    let text: String = fs::read_to_string(&toml_path).unwrap().lines().filter(|l| !l.starts_with("image_arn")).map(|l| format!("{l}\n")).collect();
    fs::write(&toml_path, text).unwrap();
    let (vm, _) = foreign_vm(10, None, VmState::Running, 10);
    w.update(|s| s.insert_vm(vm.clone()));
    let o = w.run(&["vm", "terminate", &vm.id, "--yes"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("image_arn"), "{}", stderr(&o));
    assert_eq!(w.state().vms[&vm.id].state, VmState::Running);
}

#[test]
fn cli_terminate_no_wait_says_requested() {
    let w = World::new("");
    let id = json(&w.run(&["vm", "run", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let o = w.run(&["vm", "terminate", &id, "--no-wait"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("terminate requested"), "{}", stdout(&o));
}

#[test]
fn cli_gc_dry_run_when_clean_says_nothing_to_terminate() {
    let w = World::new("");
    let o = w.run(&["vm", "gc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("nothing to terminate"), "{}", stdout(&o));
}

#[test]
fn cli_smoke_fails_on_a_health_without_the_vm_id() {
    let w = World::new("");
    let first = "microvm-00000000-0000-4000-8000-000000000001";
    let me = ai_env_cli::bridge::vm::owner();
    let (_, h) = foreign_vm(1, Some(&me), VmState::Running, 0);
    let mut h = h.unwrap();
    h.microvm_id = None;
    w.update(|s| {
        s.health_override.insert(first.into(), h);
    });
    let o = w.run(&["vm", "smoke"]);
    assert_eq!(code(&o), 1, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("microvm_id"), "{}", stderr(&o));
    assert!(w.state().vms[first].state.is_terminal());
}

#[test]
fn cli_auto_gc_terminates_expired_registry_vms_but_never_the_one_just_started() {
    let w = World::new("auto_gc = true");
    let old = json(&w.run(&["vm", "run", "--max-duration", "60", "--egress", "internet", "--json"]))["id"].as_str().unwrap().to_string();
    let o = w.run(&["vm", "run", "--max-duration", "60", "--egress", "internet", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let new = json(&o)["id"].as_str().unwrap().to_string();
    let st = w.state();
    assert!(st.vms[&old].state.is_terminal(), "the older expired VM is collected: {}", stderr(&o));
    assert_eq!(st.vms[&new].state, VmState::Running, "never the VM this run just started");
}

#[test]
fn cli_run_names_the_kept_pending_row_after_two_ambiguous_failures() {
    let w = World::new("");
    w.update(|s| {
        for _ in 0..2 {
            s.failures.push_back(ai_env_cli::bridge::api::FakeFailure { kind: "ambiguous".into(), message: "timeout".into(), on: Some("run".into()), after_effect: false });
        }
    });
    let o = w.run(&["vm", "run", "--egress", "internet"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("is kept: ai-env vm gc"), "{}", stderr(&o));
}

#[test]
fn cli_run_warns_when_the_image_memory_differs_from_the_config() {
    let w = World::new("");
    w.update(|s| {
        for v in &mut s.versions {
            v.memory_mib = Some(4096);
        }
    });
    let o = w.run(&["vm", "run", "--egress", "internet"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("[vm].memory_mib = 2048 but version 1.0 has 4096"), "{}", stderr(&o));
}

#[test]
fn cli_run_refuses_an_image_that_is_not_a_canonical_arn() {
    let w = World::new("");
    let o = w.run(&["vm", "run", "--image", "ai-env-agent", "--egress", "internet"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(w.runs(), 0);
}

// ---- S5: the egress echo gate ---------------------------------------------------------------------

/// `[aws].egress_connector_arn = CONNECTOR` in this world's bridge.toml.
fn with_connector(w: &World) {
    let path = w.bridge().join("bridge.toml");
    let text = fs::read_to_string(&path).unwrap().replacen("[aws]\n", &format!("[aws]\negress_connector_arn = \"{CONNECTOR}\"\n"), 1);
    fs::write(&path, text).unwrap();
}

/// `state/infra.toml` recording the configured connector in `state` (none: no `connector_state`).
fn write_connector_state(w: &World, state: Option<&str>) {
    let s = InfraState { stack: "dev".into(), connector_arn: Some(CONNECTOR.into()), connector_state: state.map(str::to_string), ..InfraState::default() };
    let dir = w.bridge().join("state");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("infra.toml"), s.render().unwrap()).unwrap();
}

/// `bin/` of stubs that fail loudly (exit 99) should anything call the real `aws` or `claude`.
fn stub_bin(w: &World) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = w.root().join("stub-bin");
    if !bin.exists() {
        fs::create_dir_all(&bin).unwrap();
        for name in ["aws", "claude"] {
            fs::write(bin.join(name), format!("#!/bin/sh\necho \"stub {name}: must never run in this test\" >&2\nexit 99\n")).unwrap();
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    bin
}

/// [`World::run`] with `PATH` pinned: the stubs first, then the system directories.
fn run_pinned(w: &World, args: &[&str]) -> Output {
    let mut c = w.cmd(args);
    c.env("PATH", format!("{}:/usr/bin:/bin", stub_bin(w).display()));
    let child = c.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("spawn ai-env");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    // Every S5 process test is bounded: a gate regression must fail, never hang `make test`.
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(out) => out.expect("ai-env output"),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("ai-env {args:?} did not finish within 120 s");
        }
    }
}

fn internet() -> String {
    ai_env_cli::bridge::egress::internet_egress_arn()
}

fn fake_failure(kind: &str, on: &str, after_effect: bool) -> ai_env_cli::bridge::api::FakeFailure {
    ai_env_cli::bridge::api::FakeFailure { kind: kind.into(), message: format!("{kind} (test)"), on: Some(on.into()), after_effect }
}

/// The audit rows of `event`, parsed.
fn events(w: &World, event: &str) -> Vec<serde_json::Value> {
    w.audit().lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
}

/// `by` of every `vm_terminate` audit row.
fn terminated_by(w: &World) -> Vec<String> {
    events(w, "vm_terminate").iter().map(|r| r["detail"]["by"].as_str().unwrap().to_string()).collect()
}

/// No VM of the fake is left non-terminal.
fn none_alive(w: &World, why: &str) {
    let alive: Vec<String> = w.state().vms.values().filter(|v| !v.state.is_terminal()).map(|v| v.id.clone()).collect();
    assert!(alive.is_empty(), "left running ({why}): {alive:?}");
}

#[test]
fn cli_smoke_egress_vpc_asserts_exactly_the_connector() {
    let w = World::new("");
    with_connector(&w);
    for args in [vec!["vm", "smoke", "--egress", "vpc", "--json"], vec!["vm", "smoke", "--json"]] {
        let o = run_pinned(&w, &args);
        assert_eq!(code(&o), 0, "{args:?}\n{}\n{}", stdout(&o), stderr(&o));
        let rec = json(&o);
        assert_eq!((rec["egress_ok"].clone(), rec["egress_expected"].clone(), rec["egress"].clone()), (serde_json::json!(true), serde_json::json!([CONNECTOR]), serde_json::json!([CONNECTOR])), "{args:?}: a configured connector means vpc");
        assert!(stderr(&o).contains(&format!("smoke: egress {CONNECTOR} (vpc egress: exactly as required)")), "{}", stderr(&o));
        assert!(w.state().vms[rec["id"].as_str().unwrap()].state.is_terminal());
    }
    assert_eq!(w.state().specs.iter().map(|s| s.egress_connectors.clone()).collect::<Vec<_>>(), [vec![CONNECTOR.to_string()], vec![CONNECTOR.to_string()]]);
    assert!(!w.audit().contains("vm_egress_mismatch") && !w.audit().contains("vm_egress_internet"), "{}", w.audit());
}

#[test]
fn cli_smoke_egress_internet_expects_internet_egress() {
    let w = World::new("");
    with_connector(&w);
    let o = run_pinned(&w, &["vm", "smoke", "--egress", "internet", "--json"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let rec = json(&o);
    assert_eq!((rec["egress_ok"].clone(), rec["egress_expected"].clone(), rec["egress"].clone()), (serde_json::json!(true), serde_json::json!([internet()]), serde_json::json!([internet()])));
    assert!(w.state().specs[0].egress_connectors.is_empty(), "internet sends no connector");
    assert!(w.audit().contains("\"vm_egress_internet\""));
    // Without a connector and without --egress, the smoke implies internet (audited), as before.
    let w = World::new("");
    let o = run_pinned(&w, &["vm", "smoke", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(json(&o)["egress_expected"], serde_json::json!([internet()]));
    // --egress vpc without a connector is refused before any call.
    let o = run_pinned(&w, &["vm", "smoke", "--egress", "vpc"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(w.runs(), 1);
}

#[test]
fn cli_smoke_with_the_wrong_egress_echo_exits_9_and_leaves_no_vm() {
    for (terminate_fails, keep) in [(false, false), (true, false), (true, true)] {
        let w = World::new("");
        with_connector(&w);
        w.update(|s| {
            s.egress_echo = Some(vec![internet()]);
            if terminate_fails {
                s.failures.push_back(fake_failure("throttled", "terminate", false));
            }
        });
        let mut args = vec!["vm", "smoke", "--egress", "vpc", "--json"];
        if keep {
            args.push("--keep");
        }
        let o = run_pinned(&w, &args);
        let case = format!("terminate_fails={terminate_fails} keep={keep}");
        assert_eq!(code(&o), 9, "{case}\n{}\n{}", stdout(&o), stderr(&o));
        assert!(stdout(&o).trim().is_empty(), "no record for a failed smoke: {}", stdout(&o));
        assert!(stderr(&o).contains("egress mismatch"), "{}", stderr(&o));
        assert_eq!(w.state().vms.len(), 1);
        none_alive(&w, &case);
        let mismatch = events(&w, "vm_egress_mismatch");
        assert_eq!(mismatch.len(), 1, "{case}: {}", w.audit());
        assert_eq!(mismatch[0]["detail"]["terminated"], (!terminate_fails).to_string());
        assert_eq!(terminated_by(&w), ["policy"], "{case}: exactly one termination, by the egress policy (the smoke's own when the gate's was refused), --keep or not");
    }
}

#[test]
fn cli_smoke_never_keeps_a_vm_whose_running_answer_fails_the_gate() {
    // RunMicrovm echoes the connector, the RUNNING answer echoes nothing: the smoke's own assertion fails.
    for terminate_fails in [false, true] {
        let w = World::new("");
        with_connector(&w);
        w.update(|s| {
            s.get_egress_echo = Some(vec![]);
            if terminate_fails {
                s.failures.push_back(fake_failure("throttled", "terminate", false));
            }
        });
        let o = run_pinned(&w, &["vm", "smoke", "--egress", "vpc", "--keep", "--json"]);
        assert_eq!(code(&o), 9, "{}\n{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("smoke: egress (none echoed) (vpc egress: NOT exactly"), "{}", stderr(&o));
        none_alive(&w, "--keep never keeps a VM that failed the gate");
        let mismatch = events(&w, "vm_egress_mismatch");
        assert_eq!(mismatch.len(), 1, "{}", w.audit());
        let d = &mismatch[0]["detail"];
        assert_eq!((d["via"].as_str(), d["purpose"].as_str(), d["echoed"].as_str()), (Some("run"), Some("smoke"), Some("")));
        assert_eq!(terminated_by(&w), ["policy"]);
        let row = w.bridge().join("state/vms").join(format!("{}.toml", w.state().vms.keys().next().unwrap()));
        let row: toml::Value = toml::from_str(&fs::read_to_string(row).unwrap()).unwrap();
        assert_eq!((row["terminated_by"].as_str(), row["egress_gate"].as_str()), (Some("policy"), Some("mismatch")));
    }
}

/// Two ambiguous RunMicrovm failures (the first creates the VM), a VM that echoes INTERNET_EGRESS, and
/// one refused TerminateMicrovm: the adoption sweep finds the VM, its gate rejects it and cannot terminate it.
fn swept_mismatch_world() -> World {
    let w = World::new("");
    with_connector(&w);
    w.update(|s| {
        s.failures.push_back(fake_failure("ambiguous", "run", true));
        s.failures.push_back(fake_failure("ambiguous", "run", false));
        s.failures.push_back(fake_failure("throttled", "terminate", false));
        s.egress_echo = Some(vec![internet()]);
    });
    w
}

#[test]
fn cli_smoke_terminates_a_swept_vm_its_gate_could_not() {
    let w = swept_mismatch_world();
    let o = run_pinned(&w, &["vm", "smoke", "--egress", "vpc"]);
    assert_eq!(code(&o), 7, "the run's own failure (ambiguous) is reported: {}\n{}", stdout(&o), stderr(&o));
    assert_eq!(w.state().vms.len(), 1);
    none_alive(&w, "smoke adopt(): a mismatch the gate could not terminate goes to the smoke's terminate");
    let mismatch = events(&w, "vm_egress_mismatch");
    assert_eq!(mismatch.len(), 1, "{}", w.audit());
    let d = &mismatch[0]["detail"];
    assert_eq!((d["via"].as_str(), d["purpose"].as_str(), d["terminated"].as_str()), (Some("sweep"), Some("smoke"), Some("false")));
    assert_eq!(terminated_by(&w), ["policy"]);
}

#[test]
fn cli_lab_probe_terminates_a_swept_vm_its_gate_could_not() {
    let w = swept_mismatch_world();
    let o = run_pinned(&w, &["lab", "run", "no-traffic-before-run"]);
    assert_eq!(code(&o), 7, "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(w.state().vms.len(), 1);
    none_alive(&w, "lab guard_failure: a mismatch the gate could not terminate goes to the probe's terminate guard");
    let mismatch = events(&w, "vm_egress_mismatch");
    assert_eq!(mismatch.len(), 1, "{}", w.audit());
    let d = &mismatch[0]["detail"];
    assert_eq!((d["via"].as_str(), d["purpose"].as_str(), d["terminated"].as_str()), (Some("sweep"), Some("probe"), Some("false")));
    assert_eq!(terminated_by(&w), ["probe"]);
}

#[test]
fn cli_run_retries_the_terminate_of_a_vm_that_failed_the_gate() {
    // Both TerminateMicrovm refused: exit 9 naming the VM; the row says mismatch, and `vm gc --yes` finishes it.
    let w = World::new("");
    with_connector(&w);
    w.update(|s| {
        s.egress_echo = Some(vec![internet()]);
        s.failures.push_back(fake_failure("throttled", "terminate", false));
        s.failures.push_back(fake_failure("throttled", "terminate", false));
    });
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    let id = w.state().vms.keys().next().unwrap().clone();
    assert!(stderr(&o).contains(&format!("{id} may still be running: ai-env vm terminate {id}")), "{}", stderr(&o));
    assert!(stderr(&o).contains("failed again") && stderr(&o).contains("NOT confirmed terminated"), "{}", stderr(&o));
    assert_eq!(w.state().vms[&id].state, VmState::Pending, "alive");
    let g = run_pinned(&w, &["vm", "gc", "--yes"]);
    assert_eq!(code(&g), 0, "{}\n{}", stdout(&g), stderr(&g));
    none_alive(&w, "gc terminates a mismatch row");
    assert_eq!(terminated_by(&w), ["policy"]);
    // One refused: the run's second try terminates it; still exit 9, and nothing left to terminate by hand.
    let w = World::new("");
    with_connector(&w);
    w.update(|s| {
        s.egress_echo = Some(vec![internet()]);
        s.failures.push_back(fake_failure("throttled", "terminate", false));
    });
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    let id = w.state().vms.keys().next().unwrap().clone();
    assert!(stderr(&o).contains(&format!("terminated {id} on the second try")) && stderr(&o).contains("; terminated"), "{}", stderr(&o));
    assert!(!stderr(&o).contains("may still be running"), "{}", stderr(&o));
    none_alive(&w, "the run's retry");
    assert_eq!(terminated_by(&w), ["policy"]);
}

#[test]
fn cli_gc_exits_9_when_a_vm_fails_the_egress_gate() {
    let w = World::new("");
    with_connector(&w);
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let id = json(&o)["id"].as_str().unwrap().to_string();
    // As if ai-env had died between RunMicrovm and the gate, and the VM echoes internet egress.
    let path = w.bridge().join("state/vms").join(format!("{id}.toml"));
    let mut row: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(row["egress_gate"].as_str(), Some("passed"));
    row["egress_gate"] = toml::Value::String("pending".into());
    fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
    w.update(|s| s.egress_echo = Some(vec![internet()]));
    let g = run_pinned(&w, &["vm", "gc", "--yes"]);
    assert_eq!(code(&g), 9, "{}\n{}", stdout(&g), stderr(&g));
    assert!(stderr(&g).contains("failed the egress gate") && stderr(&g).contains(&id), "{}", stderr(&g));
    none_alive(&w, "gc");
    assert_eq!(events(&w, "vm_egress_mismatch")[0]["detail"]["via"], "gc");
}

#[test]
fn cli_run_vpc_warns_unless_the_connector_is_active() {
    let warning = "RunMicrovm needs an ACTIVE connector; make connector-status";
    let hint = "connector state unknown";
    // No state/infra.toml: a hint to record it.
    let w = World::new("max_concurrent = 10");
    with_connector(&w);
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(hint) && stderr(&o).contains("make infra-status WRITE=1"), "{}", stderr(&o));
    assert_eq!(stderr(&o).matches(hint).count(), 1, "one line: {}", stderr(&o));
    // A state file without connector_state: the same hint.
    write_connector_state(&w, None);
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert!(stderr(&o).contains(hint) && !stderr(&o).contains(warning), "{}", stderr(&o));
    // PENDING: one warning naming the state; the run goes ahead (never a failure).
    write_connector_state(&w, Some("PENDING"));
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let err = stderr(&o);
    let lines: Vec<&str> = err.lines().filter(|l| l.contains(warning)).map(str::trim).collect();
    assert_eq!(lines.len(), 1, "{err}");
    assert!(lines[0].starts_with("ai-env: warning: the egress connector is PENDING"), "{}", lines[0]);
    assert!(!stderr(&o).contains(hint));
    // ACTIVE: silent.
    write_connector_state(&w, Some("ACTIVE"));
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains(warning) && !stderr(&o).contains(hint), "{}", stderr(&o));
    // The state of another connector (even PENDING) says nothing about this one: the hint.
    let other = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-other";
    let s = InfraState { stack: "dev".into(), connector_arn: Some(other.into()), connector_state: Some("PENDING".into()), ..InfraState::default() };
    fs::write(w.bridge().join("state").join("infra.toml"), s.render().unwrap()).unwrap();
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(hint) && stderr(&o).contains(&format!("records the connector {other}")) && !stderr(&o).contains(warning), "{}", stderr(&o));
    // An unreadable state file: the hint, naming why; never a failure.
    fs::write(w.bridge().join("state").join("infra.toml"), "connector_state = [unclosed\n").unwrap();
    let o = run_pinned(&w, &["vm", "run", "--egress", "vpc"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains(hint) && stderr(&o).contains("infra.toml"), "{}", stderr(&o));
    // internet egress never asks.
    fs::remove_file(w.bridge().join("state").join("infra.toml")).unwrap();
    let o = run_pinned(&w, &["vm", "run", "--egress", "internet"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains(warning) && !stderr(&o).contains(hint), "{}", stderr(&o));
    assert_eq!(w.runs(), 7);
}
