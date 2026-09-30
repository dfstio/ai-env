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

/// The cloudtrail-payload probe over the fake aws: one VM row, the fake on PATH, every call logged.
struct Ct {
    w: World,
    path: String,
    aws_log: PathBuf,
    id: String,
    ct: String,
    session: String,
    commit: String,
    created: String,
}

impl Ct {
    fn new() -> Ct {
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
        let s = |k: &str| row[k].as_str().unwrap().to_string();
        let (ct, session, commit, created) = (s("client_token"), s("session_token"), s("commit"), s("created"));
        let aws_log = w.root().join("aws.log");
        Ct { w, path, aws_log, id, ct, session, commit, created }
    }

    fn write(&self, name: &str, doc: serde_json::Value) -> PathBuf {
        let p = self.w.root().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, doc.to_string()).unwrap();
        p
    }

    fn lab(&self, env: &[(&str, &Path)], log: Option<&Path>) -> std::process::Output {
        let mut args = vec!["lab", "run", "cloudtrail-payload", self.id.as_str()];
        let log_arg = log.map(|p| p.display().to_string());
        if let Some(l) = &log_arg {
            args.extend(["--log", l.as_str()]);
        }
        let mut c = self.w.cmd(&args);
        c.env("PATH", &self.path).env("FAKE_AWS_LOG", &self.aws_log);
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn rows(&self) -> Vec<serde_json::Value> {
        rows(&self.w, "cloudtrail-payload")
    }

    /// The aws calls since the last `reset_calls`.
    fn calls(&self) -> String {
        fs::read_to_string(&self.aws_log).unwrap_or_default()
    }

    fn reset_calls(&self) {
        let _ = fs::remove_file(&self.aws_log);
    }

    /// A channel's get-channel document under FAKE_AWS_CHANNEL_DIR, named by the ARN's last segment.
    fn channel(&self, dir: &str, last: &str, doc: serde_json::Value) -> String {
        let arn = format!("arn:aws:cloudtrail:eu-central-1:123456789012:channel/{last}");
        let mut doc = doc;
        doc["ChannelArn"] = serde_json::json!(arn);
        self.write(&format!("{dir}/{last}.json"), doc);
        arn
    }
}

fn data_selectors() -> serde_json::Value {
    serde_json::json!([{"Name": "microvm", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}, {"Field": "resources.type", "Equals": ["AWS::Lambda::MicrovmImage"]}]}])
}

#[test]
fn lab_cloudtrail_fixture_verdicts() {
    let t = Ct::new();
    let id = t.id.clone();
    // No trail and no channel visible from eu-central-1: the probe still records nothing (Lake stores, channels homed
    // in other Regions and organization-level configuration are invisible from here) and prints the --manual command.
    let none = t.lab(&[], None);
    assert_eq!(code(&none), 1, "{}", stderr(&none));
    let err = stderr(&none);
    assert!(err.contains("0 checked") && err.contains("other Regions") && err.contains("organization") && err.contains("no channel (0 checked") && err.contains("CloudTrail Lake event data stores"), "{err}");
    assert!(t.rows().is_empty(), "never a verdict for what it could not see");
    let manual = err.split(&format!("ai-env lab run cloudtrail-payload {id} --manual not-logged --note \"")).nth(1).and_then(|s| s.split('"').next()).map(str::to_string).expect("the printed --manual command");
    let o = t.w.run(&["lab", "run", "cloudtrail-payload", &id, "--manual", "not-logged", "--note", &manual]);
    assert_eq!(code(&o), 0, "the printed command records: {}", stderr(&o));
    let row = t.rows().pop().unwrap();
    assert_eq!(row["verdict"], "not-logged");
    assert!(row["note"].as_str().unwrap().contains("data event (AWS::Lambda::MicrovmImage)"), "{row}");
    // A trail with management events only (the fake's default selectors): the same answer, counted.
    let trail = |extra: serde_json::Value| {
        let mut tr = serde_json::json!({"Name": "t", "TrailARN": "arn:aws:cloudtrail:eu-central-1:123456789012:trail/t", "HomeRegion": "eu-central-1", "S3BucketName": "trail-bucket", "S3KeyPrefix": "p"});
        for (k, v) in extra.as_object().unwrap() {
            tr[k] = v.clone();
        }
        t.write("trails.json", serde_json::json!({"trailList": [tr]}))
    };
    let trails = trail(serde_json::json!({}));
    let mgmt = t.lab(&[("FAKE_AWS_TRAILS_FILE", &trails)], None);
    assert_eq!(code(&mgmt), 1, "{}", stderr(&mgmt));
    assert!(stderr(&mgmt).contains("no trail (1 checked"), "{}", stderr(&mgmt));
    // The same trail selecting MicroVM data events (the AWS docs' selector): the record lives in its S3 log files.
    let selectors = t.write("selectors.json", serde_json::json!({"AdvancedEventSelectors": data_selectors()}));
    let before = t.rows().len();
    let logged = t.lab(&[("FAKE_AWS_TRAILS_FILE", &trails), ("FAKE_AWS_SELECTORS_FILE", &selectors)], None);
    assert_eq!(code(&logged), 1, "{}", stderr(&logged));
    assert!(stderr(&logged).contains("s3://trail-bucket/p/AWSLogs/") && stderr(&logged).contains("--log FILE") && !stderr(&logged).contains("--manual not-logged"), "{}", stderr(&logged));
    // It also forwards to a CloudWatch Logs group in eu-central-1: the exact filter-log-events command, `:*` stripped,
    // and no logs call of the probe's own (the group comes from describe-trails).
    let to_cw = trail(serde_json::json!({"CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-central-1:123456789012:log-group:aws-cloudtrail-logs-1:*"}));
    t.reset_calls();
    let cw = t.lab(&[("FAKE_AWS_TRAILS_FILE", &to_cw), ("FAKE_AWS_SELECTORS_FILE", &selectors)], None);
    assert_eq!(code(&cw), 1, "{}", stderr(&cw));
    let err = stderr(&cw);
    assert!(err.contains(&format!("--log-group-name 'aws-cloudtrail-logs-1' --filter-pattern '\"{id}\"'")) && !err.contains("aws-cloudtrail-logs-1:*"), "{err}");
    assert!(err.contains("s3://trail-bucket/p/AWSLogs/"), "the S3 route stays next to the CloudWatch command: {err}");
    assert!(!t.calls().lines().any(|l| l.starts_with("logs ")), "{}", t.calls());
    // A group in another Region: no command, never another --region.
    let far = trail(serde_json::json!({"CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:far-group:*"}));
    let o = t.lab(&[("FAKE_AWS_TRAILS_FILE", &far), ("FAKE_AWS_SELECTORS_FILE", &selectors)], None);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("far-group in us-east-1, outside the eu-central-1 pin") && err.contains("s3://trail-bucket/p/AWSLogs/") && !err.contains("filter-log-events --region") && !err.contains("--region us-east-1"), "{err}");
    // An organization trail: its bucket and group belong to the owner account, so both routes say so.
    let org = trail(serde_json::json!({"IsOrganizationTrail": true, "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-central-1:123456789012:log-group:aws-cloudtrail-logs-org:*"}));
    let o = t.lab(&[("FAKE_AWS_TRAILS_FILE", &org), ("FAKE_AWS_SELECTORS_FILE", &selectors)], None);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("an organization trail owned by account 123456789012") && err.contains("run it with credentials of account 123456789012") && err.contains("--log-group-name 'aws-cloudtrail-logs-org'"), "{err}");
    // A trail entry without TrailARN, and a covering trail next to an unreadable channel: exit 7, no hints.
    let nameless = t.write("trails-noarn.json", serde_json::json!({"trailList": [{"Name": "t"}]}));
    let o = t.lab(&[("FAKE_AWS_TRAILS_FILE", &nameless)], None);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    let unreadable = t.write("l-unreadable.json", serde_json::json!({"Channels": [{"ChannelArn": "arn:aws:cloudtrail:eu-central-1:123456789012:channel/nodoc", "Name": "aws-service-channel/listed/nodoc-name"}]}));
    let o = t.lab(&[("FAKE_AWS_TRAILS_FILE", &trails), ("FAKE_AWS_SELECTORS_FILE", &selectors), ("FAKE_AWS_CHANNELS_FILE", &unreadable)], None);
    assert_eq!(code(&o), 7, "unreadable wins over a keeper's hints: {}", stderr(&o));
    assert!(!stderr(&o).contains("s3://"), "{}", stderr(&o));
    // What cannot be read fails closed (exit 7, nothing recorded): the listings and a trail's selectors.
    for (op, env) in [("cloudtrail describe-trails", vec![]), ("cloudtrail list-channels", vec![]), ("cloudtrail get-event-selectors", vec![("FAKE_AWS_TRAILS_FILE", trails.as_path())])] {
        let mut c = t.w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
        c.env("PATH", &t.path).env("FAKE_AWS_LOG", &t.aws_log).env("FAKE_AWS_FAIL_OP", op);
        for (k, v) in &env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        assert_eq!(code(&o), 7, "{op}: {}", stderr(&o));
        assert!(stderr(&o).contains("nothing recorded"), "{op}: {}", stderr(&o));
    }
    assert_eq!(t.rows().len(), before, "nothing recorded while the record is elsewhere or unknown");
    // The trail's log file, passed with --log: the RunMicrovm record of this VM (a TerminateMicrovm record answering
    // with the same id is skipped).
    let records = |payload: &str| {
        serde_json::json!({"Records": [
            {"eventName": "TerminateMicrovm", "eventID": "e-0", "responseElements": {"microvmId": id}},
            {"eventName": "RunMicrovm", "eventID": "e-1", "requestParameters": {"clientToken": t.ct, "runHookPayload": payload}, "responseElements": {"microvmId": id}},
        ]})
    };
    let hidden = t.lab(&[], Some(&t.write("ct-hidden.json", records("HIDDEN_DUE_TO_SECURITY_REASONS"))));
    assert_eq!(code(&hidden), 0, "{}", stderr(&hidden));
    assert_eq!(t.rows().pop().unwrap()["verdict"], "hidden");
    let only_terminate = t.write("ct-terminate.json", serde_json::json!({"Records": [{"eventName": "TerminateMicrovm", "responseElements": {"microvmId": id}}]}));
    let other = t.lab(&[], Some(&only_terminate));
    assert_eq!(code(&other), 1, "{}", stderr(&other));
    assert!(stderr(&other).contains("no RunMicrovm record"), "{}", stderr(&other));
    let leaked = t.lab(&[], Some(&t.write("ct-leaked.json", records(&format!("{{\"token\":\"{}\"}}", t.session)))));
    assert_eq!(code(&leaked), 1, "a leak fails, after writing");
    assert_eq!(t.rows().pop().unwrap()["verdict"], "LEAKED");
    assert!(!fs::read_to_string(t.w.bridge().join("lab/probes.jsonl")).unwrap().contains(&t.session), "the probe row never carries the token");
    assert_eq!(code(&t.w.run(&["lab", "run", "cloudtrail-payload"])), 2, "needs an id");
}

#[test]
fn lab_cloudtrail_channels_and_cloudwatch() {
    let t = Ct::new();
    let id = t.id.clone();
    let chan_dir = t.w.root().join("channels");
    let listing = |name: &str, arns: &[&str], next: Option<&str>| {
        // A realistic listed Name whose last segment differs from the ARN's: get-channel must be given the ARN.
        let channels: Vec<serde_json::Value> = arns.iter().map(|a| serde_json::json!({"ChannelArn": a, "Name": format!("aws-service-channel/listed/n-{}", a.rsplit('/').next().unwrap())})).collect();
        let mut doc = serde_json::json!({"Channels": channels});
        if let Some(n) = next {
            doc["NextToken"] = serde_json::json!(n);
        }
        t.write(name, doc)
    };
    let service = |kind: &str, sources: Option<serde_json::Value>| {
        let mut doc = serde_json::json!({"Name": format!("aws-service-channel/{kind}/x"), "Source": "CloudTrail", "Destinations": [{"Type": "AWS_SERVICE", "Location": kind}]});
        if let Some(s) = sources {
            doc["SourceConfig"] = serde_json::json!({"ApplyToAllRegions": true, "AdvancedEventSelectors": s});
        }
        doc
    };
    let rex = t.channel("channels", "rex", service("resource-explorer-2", Some(serde_json::json!([{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]))));
    let cw = t.channel("channels", "cw", service("cloudwatch", Some(data_selectors())));
    let sl = t.channel("channels", "sl", service("security-lake", Some(data_selectors())));
    let blind = t.channel("channels", "blind", service("sdmp", None));
    let integration = t.channel("channels", "int", serde_json::json!({"Name": "partner", "Destinations": [{"Type": "EVENT_DATA_STORE", "Location": "arn:aws:cloudtrail:eu-central-1:123456789012:eventdatastore/eds-1"}]}));
    // A pattern query answers names only; the class comes from one query per class (the fake serves each from its
    // own file), and a name no class query returned is of an unknown class.
    let names = |ns: &[&str]| serde_json::json!({"logGroups": ns.iter().map(|n| serde_json::json!({"logGroupName": n, "arn": format!("arn:aws:logs:eu-central-1:123456789012:log-group:{n}:*"), "creationTime": 1})).collect::<Vec<_>>()});
    let standard = t.write("groups-standard.json", names(&["aws/cloudtrail/data", "aws-cloudtrail-logs-7", "cloudtrail bad'name"]));
    let ia = t.write("groups-ia.json", names(&["aws/cloudtrail/ia"]));
    let delivery = t.write("groups-delivery.json", names(&["aws/cloudtrail/fast"]));
    let all_names = t.write("groups-all.json", names(&["aws/cloudtrail/data", "aws-cloudtrail-logs-7", "cloudtrail bad'name", "aws/cloudtrail/ia", "aws/cloudtrail/fast", "aws/cloudtrail/newclass"]));
    let groups: Vec<(&str, &Path)> = vec![
        ("FAKE_AWS_LOG_GROUPS_STANDARD_FILE", standard.as_path()),
        ("FAKE_AWS_LOG_GROUPS_INFREQUENT_ACCESS_FILE", ia.as_path()),
        ("FAKE_AWS_LOG_GROUPS_DELIVERY_FILE", delivery.as_path()),
        ("FAKE_AWS_LOG_GROUPS_FILE", all_names.as_path()),
    ];
    let with = |list: &Path, extra: &[(&str, &Path)]| {
        let mut env: Vec<(&str, &Path)> = vec![("FAKE_AWS_CHANNELS_FILE", list), ("FAKE_AWS_CHANNEL_DIR", chan_dir.as_path())];
        env.extend_from_slice(extra);
        t.lab(&env, None)
    };
    // A management-only service channel (the live Resource Explorer shape): counted, no keeper, no logs call.
    t.reset_calls();
    let o = with(&listing("l-rex.json", &[&rex], None), &[]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("no channel (1 checked") && stderr(&o).contains("--manual not-logged"), "{}", stderr(&o));
    assert!(!t.calls().lines().any(|l| l.starts_with("logs ")), "logs only for a CloudWatch keeper: {}", t.calls());
    // CloudWatch's ingestion channel: one command per searchable group, each into its own file, from the row's created.
    let o = with(&listing("l-cw.json", &[&rex, &cw], None), &groups);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    let err = stderr(&o);
    let start_ms = (ai_env_cli::wire::time::parse_rfc3339_utc(&t.created).unwrap() - 300) * 1000;
    for (g, n) in [("aws/cloudtrail/data", 1), ("aws-cloudtrail-logs-7", 2)] {
        let cmd = format!(
            "aws logs filter-log-events --region eu-central-1 --endpoint-url https://logs.eu-central-1.amazonaws.com --log-group-name '{g}' --filter-pattern '\"{id}\"' --start-time {start_ms} --unmask --output json > ~/ct-{id}-{n}.json && ai-env lab run cloudtrail-payload {id} --log ~/ct-{id}-{n}.json"
        );
        assert!(err.contains(&cmd), "{g}: {err}");
    }
    assert!(err.contains("aws/cloudtrail/fast (log class DELIVERY") && !err.contains("--log-group-name 'aws/cloudtrail/fast'"), "{err}");
    assert!(err.contains("aws/cloudtrail/ia (log class INFREQUENT_ACCESS") && err.contains("Logs Insights") && !err.contains("--log-group-name 'aws/cloudtrail/ia'"), "{err}");
    assert!(err.contains("aws/cloudtrail/newclass (log class unknown") && !err.contains("--log-group-name 'aws/cloudtrail/newclass'"), "{err}");
    assert!(err.contains("a name this probe does not print into a command") && !err.contains("bad'name'"), "an unsafe name never reaches a command: {err}");
    assert!(!err.contains("--manual not-logged"), "{err}");
    // No group found: find it by hand, never the not-logged command.
    let o = with(&listing("l-cw2.json", &[&cw], None), &[]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("find its log group") && !stderr(&o).contains("--manual not-logged"), "{}", stderr(&o));
    // Security Lake, and a service channel whose selectors cannot be read: read it there, record by hand — and
    // no logs call (the log groups are only asked for with a CloudWatch keeper).
    for (arn, why) in [(&sl, "its selectors take RunMicrovm"), (&blind, "its selectors cannot be read")] {
        t.reset_calls();
        let o = with(&listing("l-svc.json", &[arn], None), &[]);
        assert!(!t.calls().lines().any(|l| l.starts_with("logs ")), "{}", t.calls());
        assert_eq!(code(&o), 1, "{}", stderr(&o));
        let err = stderr(&o);
        assert!(err.contains(why) && err.contains("--manual VERDICT") && !err.contains("--manual not-logged"), "{err}");
    }
    // A Lake integration channel is no keeper, but its event data store is named.
    let o = with(&listing("l-int.json", &[&integration], None), &[]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("eventdatastore/eds-1") && stderr(&o).contains("--manual not-logged"), "{}", stderr(&o));
    // list-channels pages: the covering channel on page 2 is found through NextToken.
    t.reset_calls();
    let page2 = listing("l-p2.json", &[&cw], None);
    let mut env: Vec<(&str, &Path)> = vec![("FAKE_AWS_CHANNELS_FILE_2", page2.as_path()), ("FAKE_AWS_CHANNELS_TOKEN", Path::new("tok-2"))];
    env.extend(groups.iter().copied());
    let o = with(&listing("l-p1.json", &[&rex], Some("tok-2")), &env);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("aws/cloudtrail/data") && t.calls().contains("list-channels --next-token tok-2"), "{}\n{}", stderr(&o), t.calls());
    // …and the keeper on page 1 is kept when page 2 has none (the pages accumulate).
    let page2_rex = listing("l-p2rex.json", &[&rex], None);
    let mut env: Vec<(&str, &Path)> = vec![("FAKE_AWS_CHANNELS_FILE_2", page2_rex.as_path()), ("FAKE_AWS_CHANNELS_TOKEN", Path::new("tok-2"))];
    env.extend(groups.iter().copied());
    let o = with(&listing("l-p1cw.json", &[&cw], Some("tok-2")), &env);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("aws/cloudtrail/data") && !stderr(&o).contains("--manual not-logged"), "{}", stderr(&o));
    // Endless pages: the bound fails closed.
    let mut c = t.w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
    c.env("PATH", &t.path).env("FAKE_AWS_LOG", &t.aws_log).env("FAKE_AWS_CHANNELS_ENDLESS", "1");
    let o = c.output().unwrap();
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("more than 50 pages"), "{}", stderr(&o));
    // A listed channel without ChannelArn: exit 7.
    let arnless = t.write("l-arnless.json", serde_json::json!({"Channels": [{"Name": "aws-service-channel/cloudwatch/x"}]}));
    let o = with(&arnless, &[]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    // A page that repeats its token: exit 7.
    let looping = listing("l-loop.json", &[&rex], Some("tok-2"));
    let o = with(&listing("l-p1b.json", &[&rex], Some("tok-2")), &[("FAKE_AWS_CHANNELS_FILE_2", &looping), ("FAKE_AWS_CHANNELS_TOKEN", Path::new("tok-2"))]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("repeated NextToken"), "{}", stderr(&o));
    // Unreadable: a channel document, the log groups (only asked for with a CloudWatch keeper).
    let missing = listing("l-missing.json", &["arn:aws:cloudtrail:eu-central-1:123456789012:channel/nodoc"], None);
    let o = with(&missing, &[]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    let mut c = t.w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
    c.env("PATH", &t.path).env("FAKE_AWS_LOG", &t.aws_log).env("FAKE_AWS_CHANNELS_FILE", listing("l-cw3.json", &[&cw], None)).env("FAKE_AWS_CHANNEL_DIR", &chan_dir).env("FAKE_AWS_FAIL_OP", "logs describe-log-groups");
    let o = c.output().unwrap();
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(t.rows().is_empty(), "nothing recorded so far");
    // --log with filter-log-events output: raw, OCSF (JSON-string data), a LEAKED OCSF record, a non-JSON message.
    let events = |messages: Vec<String>| serde_json::json!({"events": messages.iter().enumerate().map(|(i, m)| serde_json::json!({"message": m, "eventId": format!("ev{i}")})).collect::<Vec<_>>()});
    let raw = serde_json::json!({"eventName": "RunMicrovm", "eventID": "r-1", "requestParameters": {"clientToken": t.ct, "runHookPayload": "HIDDEN_DUE_TO_SECURITY_REASONS"}, "responseElements": {"microvmId": id}}).to_string();
    let o = t.lab(&[], Some(&t.write("cw-raw.json", events(vec![raw]))));
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let row = t.rows().pop().unwrap();
    assert!(row["verdict"] == "hidden" && row["note"].as_str().unwrap().contains("CloudWatch Logs, raw"), "{row}");
    let ocsf = |data: String| serde_json::json!({"metadata": {"uid": "o-1"}, "api": {"operation": "RunMicrovm", "request": {"data": data}, "response": {"data": {"microvmId": id}}}}).to_string();
    let payload = serde_json::json!({"clientToken": t.ct, "runHookPayload": format!("{{\"v\":1,\"commit\":\"{}\"}}", t.commit)}).to_string();
    let o = t.lab(&[], Some(&t.write("cw-ocsf.json", events(vec![ocsf(payload)]))));
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let row = t.rows().pop().unwrap();
    assert!(row["verdict"] == "commitment-only" && row["note"].as_str().unwrap().contains("CloudWatch Logs, OCSF"), "{row}");
    let leaky = serde_json::json!({"note": t.session}).to_string();
    let o = t.lab(&[], Some(&t.write("cw-leak.json", events(vec![ocsf(leaky)]))));
    assert_eq!(code(&o), 1, "a leak fails, after writing: {}", stderr(&o));
    assert_eq!(t.rows().pop().unwrap()["verdict"], "LEAKED");
    assert!(!fs::read_to_string(t.w.bridge().join("lab/probes.jsonl")).unwrap().contains(&t.session), "the probe row never carries the token");
    let n = t.rows().len();
    let o = t.lab(&[], Some(&t.write("cw-bad.json", events(vec!["not json".to_string()]))));
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("not JSON") && t.rows().len() == n, "{}", stderr(&o));
    // Every aws call: one of the five read-only operations, --region eu-central-1, its service's pinned endpoint —
    // with AWS_ENDPOINT_URL set.
    t.reset_calls();
    let mut c = t.w.cmd(&["lab", "run", "cloudtrail-payload", id.as_str()]);
    c.env("PATH", &t.path).env("FAKE_AWS_LOG", &t.aws_log).env("AWS_ENDPOINT_URL", "http://127.0.0.1:9");
    let selectors = t.write("selectors-all.json", serde_json::json!({"AdvancedEventSelectors": data_selectors()}));
    let trails = t.write("trails-all.json", serde_json::json!({"trailList": [{"Name": "t", "TrailARN": "arn:aws:cloudtrail:eu-central-1:123456789012:trail/t", "HomeRegion": "eu-central-1", "S3BucketName": "b"}]}));
    c.env("FAKE_AWS_CHANNELS_FILE", listing("l-all.json", &[&rex, &cw], None)).env("FAKE_AWS_CHANNEL_DIR", &chan_dir).env("FAKE_AWS_TRAILS_FILE", &trails).env("FAKE_AWS_SELECTORS_FILE", &selectors);
    for (k, v) in &groups {
        c.env(k, v);
    }
    assert_eq!(code(&c.output().unwrap()), 1);
    let calls = t.calls();
    let ops = ["cloudtrail describe-trails", "cloudtrail get-event-selectors", "cloudtrail list-channels", "cloudtrail get-channel", "logs describe-log-groups"];
    assert!(calls.lines().all(|l| ops.iter().any(|p| l.starts_with(p)) && l.contains("--region eu-central-1")), "{calls}");
    assert!(calls.lines().filter(|l| l.starts_with("cloudtrail ")).all(|l| l.contains("--endpoint-url https://cloudtrail.eu-central-1.amazonaws.com")), "{calls}");
    assert!(calls.lines().any(|l| l.starts_with("logs ")) && calls.lines().filter(|l| l.starts_with("logs ")).all(|l| l.contains("--endpoint-url https://logs.eu-central-1.amazonaws.com") && l.contains("--log-group-name-pattern cloudtrail")), "{calls}");
    assert!(calls.lines().any(|l| l.starts_with("cloudtrail get-event-selectors")) && calls.lines().any(|l| l.starts_with("cloudtrail get-channel --channel arn:aws:cloudtrail:")), "every operation was exercised: {calls}");
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
