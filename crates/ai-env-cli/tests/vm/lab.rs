//! `ai-env lab …` as processes (plan S4 §8): the log probes over the
//! synthetic fixtures in tests/fixtures/s4 (the shim's hook-line and
//! run-report formats behind `make logs` timestamps), the CloudTrail probe
//! over the fake aws, manual rows, the catalog, and the four live probes
//! against the file-backed fake — each of which must leave no VM running.
use super::cli::{code, stderr, stdout, World};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("s4").join(name).display().to_string()
}

fn rows(w: &World, probe: &str) -> Vec<serde_json::Value> {
    let text = fs::read_to_string(w.bridge().join("lab").join("probes.jsonl")).unwrap_or_default();
    text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["probe"] == probe).collect()
}

fn no_vm_left(w: &World) {
    let st = w.state();
    let alive: Vec<&String> = st.vms.values().filter(|v| !v.state.is_terminal()).map(|v| &v.id).collect();
    assert!(alive.is_empty(), "left running: {alive:?}");
}

#[test]
fn lab_hooks_from_log_fixture_records_9000_and_loopback() {
    let w = World::new("");
    let log = fixture("hooks.log");
    let o = w.run(&["lab", "run", "hooks-port", "--log", &log]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("recorded hooks-port=9000 (expected 9000)"), "{}", stdout(&o));
    assert_eq!(rows(&w, "hooks-port")[0]["stage"], "S4");
    let o = w.run(&["lab", "run", "hooks-source-ip", "--log", &log]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(rows(&w, "hooks-source-ip")[0]["verdict"], "loopback");
    let note = rows(&w, "hooks-port")[0]["note"].as_str().unwrap().to_string();
    assert!(note.contains("run×1") && note.contains("resume×1") && !note.contains("ready"), "{note}");
}

#[test]
fn lab_run_report_fixture_records_env_and_disk() {
    let w = World::new("");
    let log = fixture("run-report.log");
    let o = w.run(&["lab", "run", "runtime-env", "--log", &log]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let r = &rows(&w, "runtime-env")[0];
    assert_eq!(r["verdict"], "aws-credentials:absent");
    assert!(r["note"].as_str().unwrap().contains("HOME=/root"), "{r}");
    let o = w.run(&["lab", "run", "disk-budget", "--log", &log]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(rows(&w, "disk-budget")[0]["verdict"], "used=300MiB total=8192MiB");
    let hooks_only = w.run(&["lab", "run", "disk-budget", "--log", &fixture("hooks.log")]);
    assert_eq!(code(&hooks_only), 1, "no run report: nothing recorded");
    assert_eq!(rows(&w, "disk-budget").len(), 1);
    assert_eq!(code(&w.run(&["lab", "run", "runtime-env"])), 2, "a log probe needs --log");
}

#[test]
fn lab_live_probes_against_the_fake_leave_no_vm() {
    let w = World::new("");
    for (probe, verdict) in [("payload-size", Some("4096=accepted 4097=rejected")), ("no-traffic-before-run", Some("health-after-run")), ("snapshot-uniqueness", Some("nonce-differs")), ("idle-policy-limits", None)] {
        let o = w.run(&["lab", "run", probe]);
        assert_eq!(code(&o), 0, "{probe}: {}\n{}", stdout(&o), stderr(&o));
        let row = rows(&w, probe).pop().unwrap();
        if let Some(v) = verdict {
            assert_eq!(row["verdict"], v, "{probe}: {row}");
        }
        assert!(row["claude"].as_str().is_some() || probe == "idle-policy-limits", "{probe}: {row}");
        no_vm_left(&w);
    }
    let idle = rows(&w, "idle-policy-limits").pop().unwrap();
    assert!(idle["verdict"].as_str().unwrap().starts_with("900=accepted"), "{idle}");
    // The snapshot pass 2 pairs the run reports of the two VMs of pass 1 (the fake's ids 5 and 6 here).
    let ids = rows(&w, "snapshot-uniqueness")[0]["note"].as_str().unwrap().split_whitespace().find_map(|t| t.strip_prefix("ids=")).unwrap().to_string();
    let text = fs::read_to_string(fixture("run-report.log")).unwrap();
    let mut ids_iter = ids.split(',');
    let (a, b) = (ids_iter.next().unwrap(), ids_iter.next().unwrap());
    let log: PathBuf = w.root().join("snap.log");
    fs::write(&log, text.replace("microvm-00000000-0000-4000-8000-000000000001", a).replace("microvm-00000000-0000-4000-8000-000000000002", b)).unwrap();
    let o = w.run(&["lab", "run", "snapshot-uniqueness", "--log", &log.display().to_string()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let last = rows(&w, "snapshot-uniqueness").pop().unwrap();
    assert!(last["note"].as_str().unwrap().contains("boot_ids identical"), "{last}");
}

#[test]
fn lab_snapshot_log_pass_needs_the_live_pass_first() {
    let w = World::new("");
    let o = w.run(&["lab", "run", "snapshot-uniqueness", "--log", &fixture("run-report.log")]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(rows(&w, "snapshot-uniqueness").is_empty());
}

#[test]
fn lab_cloudtrail_fixture_verdicts() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = World::new("");
    let bin = w.root().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/aws.sh"), bin.join("aws")).unwrap();
    fs::set_permissions(bin.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let run = w.run(&["vm", "run", "--egress", "internet", "--json"]);
    let id = serde_json::from_str::<serde_json::Value>(&stdout(&run)).unwrap()["id"].as_str().unwrap().to_string();
    let row: toml::Value = toml::from_str(&fs::read_to_string(w.bridge().join("state/vms").join(format!("{id}.toml"))).unwrap()).unwrap();
    let (ct, session) = (row["client_token"].as_str().unwrap().to_string(), row["session_token"].as_str().unwrap().to_string());
    let events = |payload: &str| {
        let inner = serde_json::json!({"eventID": "e-1", "requestParameters": {"clientToken": ct, "runHookPayload": payload}, "responseElements": {"microvmId": id}});
        serde_json::json!({"Events": [{"EventName": "RunMicrovm", "CloudTrailEvent": inner.to_string()}]}).to_string()
    };
    let file = w.root().join("ct.json");
    let lab = |doc: Option<String>| {
        if let Some(d) = &doc {
            fs::write(&file, d).unwrap();
        }
        let mut c = w.cmd(&["lab", "run", "cloudtrail-payload", &id]);
        c.env("PATH", &path);
        if doc.is_some() {
            c.env("FAKE_AWS_CLOUDTRAIL_FILE", &file);
        }
        c.output().unwrap()
    };
    let none = lab(None);
    assert_eq!(code(&none), 1, "not yet visible: {}", stderr(&none));
    assert!(rows(&w, "cloudtrail-payload").is_empty(), "nothing recorded while CloudTrail has no event");
    let hidden = lab(Some(events("HIDDEN_DUE_TO_SECURITY_REASONS")));
    assert_eq!(code(&hidden), 0, "{}", stderr(&hidden));
    assert_eq!(rows(&w, "cloudtrail-payload").pop().unwrap()["verdict"], "hidden");
    let leaked = lab(Some(events(&format!("{{\"token\":\"{session}\"}}"))));
    assert_eq!(code(&leaked), 1, "a leak fails, after writing");
    assert_eq!(rows(&w, "cloudtrail-payload").pop().unwrap()["verdict"], "LEAKED");
    assert!(!fs::read_to_string(w.bridge().join("lab/probes.jsonl")).unwrap().contains(&session), "the probe row never carries the token");
    assert_eq!(code(&w.run(&["lab", "run", "cloudtrail-payload"])), 2, "needs an id");
}

#[test]
fn lab_manual_record_and_show() {
    let w = World::new("");
    let o = w.run(&["lab", "run", "disk-budget", "--manual", "used=310MiB total=8192MiB", "--note", "df -h / in the shell"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let show = w.run(&["lab", "show", "disk-budget", "--json"]);
    assert_eq!(code(&show), 0);
    let shown: serde_json::Value = serde_json::from_str(&stdout(&show)).unwrap();
    assert_eq!(shown[0]["verdict"], "used=310MiB total=8192MiB");
    assert_eq!(shown[0]["note"], "df -h / in the shell");
}

#[test]
fn lab_unknown_probe_exit_2_and_s1_s3_probes_point_to_their_command() {
    let w = World::new("");
    assert_eq!(code(&w.run(&["lab", "run", "nope"])), 2);
    assert_eq!(code(&w.run(&["lab", "show", "nope"])), 2);
    let o = w.run(&["lab", "run", "entrypoint"]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("ai-env wrapper census --record-probes"), "{}", stderr(&o));
}

#[test]
fn probe_rows_of_the_old_schema_parse_in_lab_list() {
    let w = World::new("");
    let lab = w.bridge().join("lab");
    fs::create_dir_all(&lab).unwrap();
    fs::write(lab.join("probes.jsonl"), "{\"probe\":\"entrypoint\",\"stage\":\"S1\",\"ext\":\"2.1.282\",\"sdk\":null,\"verdict\":\"claude-vscode\",\"expected\":\"claude-vscode\",\"ts\":\"2026-09-23T10:00:00Z\"}\n").unwrap();
    let o = w.run(&["lab", "list", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let list: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let entry = list.as_array().unwrap().iter().find(|r| r["probe"] == "entrypoint").unwrap();
    assert_eq!(entry["last_verdict"], "claude-vscode");
    assert_eq!(list.as_array().unwrap().len(), 12);
}

#[test]
fn lab_snapshot_probe_terminates_the_other_vm_when_one_run_fails() {
    let w = World::new("");
    w.update(|s| {
        s.failures.push_back(ai_env_cli::bridge::api::FakeFailure { kind: "validation".into(), message: "bad run".into(), on: Some("run".into()), after_effect: false });
    });
    let o = w.run(&["lab", "run", "snapshot-uniqueness"]);
    assert_eq!(code(&o), 7, "{}\n{}", stdout(&o), stderr(&o));
    no_vm_left(&w);
    assert!(rows(&w, "snapshot-uniqueness").is_empty(), "nothing recorded on failure");
}

#[test]
fn lab_refuses_arguments_a_probe_does_not_take() {
    let w = World::new("");
    assert_eq!(code(&w.run(&["lab", "run", "payload-size", "--log", &fixture("hooks.log")])), 2);
    assert_eq!(code(&w.run(&["lab", "run", "hooks-port", "microvm-x", "--log", &fixture("hooks.log")])), 2);
    assert_eq!(w.state().calls.len(), 0, "refused before any call");
}

#[test]
fn lab_snapshot_log_pass_can_be_re_run_and_probes_are_audited() {
    let w = World::new("");
    assert_eq!(code(&w.run(&["lab", "run", "snapshot-uniqueness"])), 0);
    let ids = rows(&w, "snapshot-uniqueness")[0]["note"].as_str().unwrap().split_whitespace().find_map(|t| t.strip_prefix("ids=")).unwrap().to_string();
    let mut it = ids.split(',');
    let (a, b) = (it.next().unwrap().to_string(), it.next().unwrap().to_string());
    let log = w.root().join("snap.log");
    let text = fs::read_to_string(fixture("run-report.log")).unwrap().replace("microvm-00000000-0000-4000-8000-000000000001", &a).replace("microvm-00000000-0000-4000-8000-000000000002", &b);
    fs::write(&log, text).unwrap();
    for _ in 0..2 {
        let o = w.run(&["lab", "run", "snapshot-uniqueness", "--log", &log.display().to_string()]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    }
    assert_eq!(rows(&w, "snapshot-uniqueness").len(), 3);
    let audit = fs::read_to_string(w.bridge().join("audit.jsonl")).unwrap();
    assert_eq!(audit.matches("\"lab_probe\"").count(), 3, "{audit}");
}
