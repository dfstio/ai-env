//! `ai-env vm …` / `ai-env lab …` as processes against the file-backed fake
//! (`AI_ENV_BRIDGE_LAB_FAKE_API`, debug builds; plan S4 D23, D25): T4.4 —
//! three concurrent `vm run --workspace` → exactly one RunMicrovm; the
//! cross-workspace `max_concurrent`; gc classes and actions — plus the CLI
//! contract of §6 (exit codes, hidden tokens, audit rows) and the container
//! unseal path with the fake age. Every process gets its own bridge root,
//! keystore and HOME under one temp tree; polls are scaled to milliseconds
//! (`AI_ENV_BRIDGE_LAB_BACKOFF_MS=1`).
use ai_env_cli::bridge::api::{FakeState, IdleSpec, VmInfo, VmState, FAKE_IMAGE_ARN, ENDPOINT_SUFFIX};
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

fn foreign_vm(n: u64, owner: Option<&str>, state: VmState, age_s: i64) -> (VmInfo, Option<Health>) {
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
