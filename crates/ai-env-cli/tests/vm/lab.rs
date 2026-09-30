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
fn lab_no_traffic_probe_measures_the_window_before_run() {
    // Live (30 Sep 2026): the endpoint answered /health from a shim that had not seen /run yet.
    let w = World::new("");
    w.update(|s| s.pre_run_health = 2);
    let o = w.run(&["lab", "run", "no-traffic-before-run"]);
    assert_eq!(code(&o), 0, "recorded, not an expectation miss: {}\n{}", stdout(&o), stderr(&o));
    let row = rows(&w, "no-traffic-before-run").pop().unwrap();
    assert_eq!(row["verdict"], "health-before-run");
    assert_eq!(row["expected"], "recorded");
    let note = row["note"].as_str().unwrap();
    // The fake answers twice without /run, then with it: the window closes within its own budget (timing-free).
    assert!(note.starts_with("first 200 without /run") && note.contains("; run_hook_seen ") && !note.contains("still false"), "{note}");
    no_vm_left(&w);
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
    let aws_log = w.root().join("aws.log");
    let write = |name: &str, doc: serde_json::Value| {
        let p = w.root().join(name);
        fs::write(&p, doc.to_string()).unwrap();
        p
    };
    let lab = |env: &[(&str, &Path)], log: Option<&Path>| {
        let mut args = vec!["lab", "run", "cloudtrail-payload", id.as_str()];
        let log_arg = log.map(|p| p.display().to_string());
        if let Some(l) = &log_arg {
            args.extend(["--log", l.as_str()]);
        }
        let mut c = w.cmd(&args);
        c.env("PATH", &path).env("FAKE_AWS_LOG", &aws_log);
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    // No trail and no store visible from eu-central-1: the probe still records nothing (stores homed in other Regions
    // and organization stores are invisible from here) and prints the --manual command for the operator.
    let none = lab(&[], None);
    assert_eq!(code(&none), 1, "{}", stderr(&none));
    assert!(stderr(&none).contains("0 checked") && stderr(&none).contains("other Regions") && stderr(&none).contains("organization"), "{}", stderr(&none));
    assert!(rows(&w, "cloudtrail-payload").is_empty(), "never a verdict for what it could not see");
    let manual = stderr(&none).split(&format!("ai-env lab run cloudtrail-payload {id} --manual not-logged --note \"")).nth(1).and_then(|t| t.split('"').next()).map(str::to_string).expect("the printed --manual command");
    let o = w.run(&["lab", "run", "cloudtrail-payload", &id, "--manual", "not-logged", "--note", &manual]);
    assert_eq!(code(&o), 0, "the printed command records: {}", stderr(&o));
    let row = rows(&w, "cloudtrail-payload").pop().unwrap();
    assert_eq!(row["verdict"], "not-logged");
    assert!(row["note"].as_str().unwrap().contains("data event (AWS::Lambda::MicrovmImage)"), "{row}");
    // A trail with management events only (the fake's default selectors): the same answer, counted.
    let trails = write(
        "trails.json",
        serde_json::json!({"trailList": [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:eu-central-1:123456789012:trail/t", "HomeRegion": "eu-central-1", "S3BucketName": "trail-bucket", "S3KeyPrefix": "p"}]}),
    );
    let mgmt = lab(&[("FAKE_AWS_TRAILS_FILE", &trails)], None);
    assert_eq!(code(&mgmt), 1, "{}", stderr(&mgmt));
    assert!(stderr(&mgmt).contains("no trail (1 checked"), "{}", stderr(&mgmt));
    // The same trail selecting MicroVM data events (the AWS docs' selector): the record lives in its S3 log files.
    let selectors = write(
        "selectors.json",
        serde_json::json!({"AdvancedEventSelectors": [{"Name": "microvm", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Lambda::MicrovmImage"]}]}]}),
    );
    let before = rows(&w, "cloudtrail-payload").len();
    let logged = lab(&[("FAKE_AWS_TRAILS_FILE", &trails), ("FAKE_AWS_SELECTORS_FILE", &selectors)], None);
    assert_eq!(code(&logged), 1, "{}", stderr(&logged));
    assert!(stderr(&logged).contains("s3://trail-bucket/p/AWSLogs/") && stderr(&logged).contains("--log FILE"), "{}", stderr(&logged));
    // An event data store that logs them, even a stopped one (it keeps what it ingested): the exact Lake query.
    let stores = write("stores.json", serde_json::json!({"EventDataStores": [{"EventDataStoreArn": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-1"}]}));
    for status in ["ENABLED", "STOPPED_INGESTION", "PENDING_DELETION"] {
        let store = write("store.json", serde_json::json!({"Status": status, "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "StartsWith": ["AWS::Lambda::"]}]}]}));
        let by_store = lab(&[("FAKE_AWS_STORES_FILE", &stores), ("FAKE_AWS_STORE_FILE", &store)], None);
        assert_eq!(code(&by_store), 1, "{status}: {}", stderr(&by_store));
        let err = stderr(&by_store);
        assert!(err.contains(&format!("({status})")) && err.contains("FROM eds-1 WHERE eventName = 'RunMicrovm'") && err.contains(&format!("--log ~/ct-{id}.json")), "{status}: {err}");
    }
    // A store that logs something else is counted and does not keep the record.
    let s3_only = write("store-s3.json", serde_json::json!({"Status": "ENABLED", "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}]}]}));
    let other_store = lab(&[("FAKE_AWS_STORES_FILE", &stores), ("FAKE_AWS_STORE_FILE", &s3_only)], None);
    assert_eq!(code(&other_store), 1, "{}", stderr(&other_store));
    assert!(stderr(&other_store).contains("(1 checked)") && stderr(&other_store).contains("--manual not-logged"), "{}", stderr(&other_store));
    // What cannot be read fails closed (exit 7, nothing recorded): the listings, a trail's selectors, a store.
    for (op, env) in [
        ("cloudtrail describe-trails", vec![]),
        ("cloudtrail list-event-data-stores", vec![]),
        ("cloudtrail get-event-selectors", vec![("FAKE_AWS_TRAILS_FILE", trails.as_path())]),
        ("cloudtrail get-event-data-store", vec![("FAKE_AWS_STORES_FILE", stores.as_path()), ("FAKE_AWS_STORE_FILE", s3_only.as_path())]),
    ] {
        let mut c = w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
        c.env("PATH", &path).env("FAKE_AWS_LOG", &aws_log).env("FAKE_AWS_FAIL_OP", op);
        for (k, v) in &env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        assert_eq!(code(&o), 7, "{op}: {}", stderr(&o));
        assert!(stderr(&o).contains("nothing recorded"), "{op}: {}", stderr(&o));
    }
    assert_eq!(rows(&w, "cloudtrail-payload").len(), before, "nothing recorded while the record is elsewhere or unknown");
    // The trail's log file, passed with --log: the RunMicrovm record of this VM (a TerminateMicrovm record answering
    // with the same id is skipped).
    let records = |payload: &str| {
        serde_json::json!({"Records": [
            {"eventName": "TerminateMicrovm", "eventID": "e-0", "responseElements": {"microvmId": id}},
            {"eventName": "RunMicrovm", "eventID": "e-1", "requestParameters": {"clientToken": ct, "runHookPayload": payload}, "responseElements": {"microvmId": id}},
        ]})
    };
    let hidden = lab(&[], Some(&write("ct-hidden.json", records("HIDDEN_DUE_TO_SECURITY_REASONS"))));
    assert_eq!(code(&hidden), 0, "{}", stderr(&hidden));
    assert_eq!(rows(&w, "cloudtrail-payload").pop().unwrap()["verdict"], "hidden");
    let only_terminate = write("ct-terminate.json", serde_json::json!({"Records": [{"eventName": "TerminateMicrovm", "responseElements": {"microvmId": id}}]}));
    let other = lab(&[], Some(&only_terminate));
    assert_eq!(code(&other), 1, "{}", stderr(&other));
    assert!(stderr(&other).contains("no RunMicrovm record"), "{}", stderr(&other));
    let leaked = lab(&[], Some(&write("ct-leaked.json", records(&format!("{{\"token\":\"{session}\"}}")))));
    assert_eq!(code(&leaked), 1, "a leak fails, after writing");
    assert_eq!(rows(&w, "cloudtrail-payload").pop().unwrap()["verdict"], "LEAKED");
    assert!(!fs::read_to_string(w.bridge().join("lab/probes.jsonl")).unwrap().contains(&session), "the probe row never carries the token");
    assert_eq!(code(&w.run(&["lab", "run", "cloudtrail-payload"])), 2, "needs an id");
    // A Lake query result (the printed query's columns), passed with --log.
    let lake = serde_json::json!({"QueryStatus": "FINISHED", "QueryResultRows": [[
        {"eventID": "e-9"}, {"eventName": "RunMicrovm"}, {"clientToken": ct}, {"runHookPayload": "HIDDEN_DUE_TO_SECURITY_REASONS"}, {"microvmId": id},
        {"requestParameters": "{}"}, {"responseElements": "{}"}]]});
    let from_lake = lab(&[], Some(&write("ct-lake.json", lake)));
    assert_eq!(code(&from_lake), 0, "{}", stderr(&from_lake));
    assert!(rows(&w, "cloudtrail-payload").pop().unwrap()["note"].as_str().unwrap().contains("event e-9"));
    // Every aws call carried --region eu-central-1 (the fake refuses others) and the pinned CloudTrail endpoint, even
    // with AWS_ENDPOINT_URL set; only read-only CloudTrail calls were made.
    let mut c = w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
    c.env("PATH", &path).env("FAKE_AWS_LOG", &aws_log).env("AWS_ENDPOINT_URL", "http://127.0.0.1:9");
    assert_eq!(code(&c.output().unwrap()), 1);
    let calls = fs::read_to_string(&aws_log).unwrap();
    assert!(calls.lines().all(|l| ["cloudtrail describe-trails", "cloudtrail get-event-selectors", "cloudtrail list-event-data-stores", "cloudtrail get-event-data-store"].iter().any(|p| l.starts_with(p))), "{calls}");
    assert!(calls.lines().all(|l| l.contains("--endpoint-url https://cloudtrail.eu-central-1.amazonaws.com")), "{calls}");
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
