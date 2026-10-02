//! `ai-env lab …` as processes (plan S4 §8): the log probes over the
//! synthetic fixtures in tests/fixtures/s4 (the shim's hook-line and
//! run-report formats behind `make logs` timestamps), the CloudTrail probe
//! over the fake aws, manual rows, the catalog, and the four live probes
//! against the file-backed fake — each of which must leave no VM running.
//! S5: the two egress probes (`connector-pending ARN` over the fake's run
//! failure and echo knobs and the operator's view of the connector;
//! `dns-path`, which like `ai-env egress check` stops at the fake's refusal
//! to carry a shell) and `egress check`: its checks before and around that
//! refusal, and — with the debug transcript knob standing in for the shell,
//! the fake aws serving a green network (tests/fixtures/egress) and squid's
//! log — its decision: a pass records, any failure revokes, `--vm` does
//! neither.
use super::cli::{code, stderr, stdout, World};
use crate::common::CONNECTOR;
use ai_env_cli::bridge::api::{Call, FakeFailure};
use ai_env_cli::bridge::egress::check::{denied_host, CASES, FAKE_SHELL_KNOB};
use ai_env_cli::bridge::egress::{param_name, value_sha256, EgressVerified, VerifiedRecord, EXTRAS_HEADER, PARAMS, SUSPENDED_HEADER};
use ai_env_cli::bridge::infra::InfraState;
use ai_env_cli::wire::time::unix_now;
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
    assert_eq!(list.as_array().unwrap().len(), 14);
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

// ---- S5: connector-pending, dns-path, egress check ----------------------------------------------

/// The throw-away connector of `make connector-probe` (documentation account).
const PROBE_CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress-probe";

/// Wait for `c` (stdout and stderr captured), killing it after 120 s.
fn bounded(mut c: std::process::Command) -> std::process::Output {
    let child = c.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().expect("spawn ai-env");
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(out) => out.expect("ai-env output"),
        Err(_) => {
            let _ = std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            panic!("ai-env did not finish within 120 s");
        }
    }
}

/// The fake aws of `w`: `bin/aws` and the `answers/` directory (seeded with a PENDING probe connector).
fn fake_aws(w: &World) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let (bin, answers) = (w.root().join("bin"), w.root().join("answers"));
    if !bin.join("aws").exists() {
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&answers).unwrap();
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/aws.sh"), bin.join("aws")).unwrap();
        fs::set_permissions(bin.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
        probe_connector_state(w, "PENDING");
    }
    (bin, answers)
}

/// `ai-env <args>` in `w` with the fake aws first on a pinned PATH (each
/// call logged to `aws.log`; sts must carry its endpoint too), its answers,
/// a Parameter Store, and `env`.
fn s5_run_env(w: &World, args: &[&str], env: &[(&str, &Path)]) -> std::process::Output {
    let (bin, answers) = fake_aws(w);
    // Every run starts the per-operation call counters (`<op>.N.json` answers) afresh.
    for e in fs::read_dir(&answers).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with(".count.") {
            fs::remove_file(e.path()).unwrap();
        }
    }
    let mut c = w.cmd(args);
    c.env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("FAKE_AWS_LOG", w.root().join("aws.log")).env("FAKE_AWS_PIN_ALL", "1").env("FAKE_AWS_ANSWERS", &answers).env("FAKE_AWS_SSM_DIR", w.root().join("ssm"));
    for (k, v) in env {
        c.env(k, v);
    }
    bounded(c)
}

fn s5_run(w: &World, args: &[&str]) -> std::process::Output {
    s5_run_env(w, args, &[])
}

fn aws_calls(w: &World) -> String {
    fs::read_to_string(w.root().join("aws.log")).unwrap_or_default()
}

/// The probe connector's `get-network-connector` answer: the golden one, renamed, in `state`.
fn probe_connector_state(w: &World, state: &str) {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress/lambda-core.get-network-connector.json");
    let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(golden).unwrap()).unwrap();
    doc["Arn"] = serde_json::json!(PROBE_CONNECTOR);
    doc["Name"] = serde_json::json!("ai-env-egress-probe");
    doc["State"] = serde_json::json!(state);
    doc["StateReason"] = serde_json::json!(if state == "PENDING" { "creating ENIs" } else { "" });
    fs::write(w.root().join("answers").join("lambda-core.get-network-connector.json"), doc.to_string()).unwrap();
}

/// `[aws].egress_connector_arn = arn` in this world's bridge.toml.
fn connect(w: &World, arn: &str) {
    let path = w.bridge().join("bridge.toml");
    let text = fs::read_to_string(&path).unwrap().replacen("[aws]\n", &format!("[aws]\negress_connector_arn = \"{arn}\"\n"), 1);
    fs::write(&path, text).unwrap();
}

fn alive(w: &World) -> Vec<String> {
    w.state().vms.values().filter(|v| !v.state.is_terminal()).map(|v| v.id.clone()).collect()
}

fn audit_rows(w: &World) -> Vec<serde_json::Value> {
    w.audit().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

fn shell_tokens(w: &World) -> usize {
    w.state().calls.iter().filter(|c| matches!(c, Call::ShellToken { .. })).count()
}

fn vm_row(w: &World, id: &str) -> toml::Value {
    toml::from_str(&fs::read_to_string(w.bridge().join("state/vms").join(format!("{id}.toml"))).unwrap()).unwrap()
}

#[test]
fn lab_connector_pending_records_what_run_microvm_did() {
    let w = World::new("");
    // Accepted: RunMicrovm takes the throw-away connector (no configured one needed) and echoes it.
    let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let row = rows(&w, "connector-pending").pop().unwrap();
    assert_eq!((row["verdict"].as_str(), row["expected"].as_str(), row["stage"].as_str()), (Some("accepted"), Some("recorded"), Some("S5")), "{row}");
    let note = row["note"].as_str().unwrap();
    assert!(note.contains(&format!("echoed egress {PROBE_CONNECTOR}")) && note.contains("RUNNING"), "{note}");
    assert!(note.ends_with("connector PENDING (creating ENIs) before RunMicrovm, PENDING (creating ENIs) after"), "the operator's view before and after: {note}");
    let spec = w.state().specs.last().unwrap().clone();
    assert_eq!(spec.egress_connectors, [PROBE_CONNECTOR], "the probe's plan: vpc with exactly that ARN");
    assert!(spec.ingress_connectors.is_empty());
    no_vm_left(&w);
    assert!(!w.audit().contains("vm_egress_internet"), "a vpc run is never audited as internet egress");
    // The operator's calls: the account check, then the connector before and after, pinned.
    let calls: Vec<String> = aws_calls(&w).lines().map(str::to_string).collect();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert!(calls[0].starts_with("sts get-caller-identity --region eu-central-1 --endpoint-url https://sts.eu-central-1.amazonaws.com"), "{calls:?}");
    for c in &calls[1..] {
        assert!(c.starts_with(&format!("lambda-core get-network-connector --identifier {PROBE_CONNECTOR} --region eu-central-1 --endpoint-url https://lambda.eu-central-1.amazonaws.com")), "{c}");
    }
    // Refused: the code of RunMicrovm's error, the message in the note; no VM was created.
    for (kind, message, verdict) in [
        ("validation", "Network connector ai-env-egress-probe is not ACTIVE", "rejected:ValidationException"),
        ("sdk", "ResourceConflictException: the connector is PENDING", "rejected:ResourceConflictException"),
        ("sdk", "the connector is still being created", "rejected:unknown"),
    ] {
        let runs = w.runs();
        w.update(|s| s.failures.push_back(FakeFailure { kind: kind.into(), message: message.into(), on: Some("run".into()), after_effect: false }));
        let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
        assert_eq!(code(&o), 0, "{message}: {}\n{}", stdout(&o), stderr(&o));
        let row = rows(&w, "connector-pending").pop().unwrap();
        assert_eq!(row["verdict"], verdict, "{row}");
        assert!(row["note"].as_str().unwrap().contains(message.rsplit(": ").next().unwrap()) && row["note"].as_str().unwrap().contains("before RunMicrovm"), "{row}");
        assert_eq!(w.runs(), runs + 1);
        no_vm_left(&w);
    }
    assert_eq!(w.state().vms.len(), 1, "a refused RunMicrovm created nothing");
    // Throttling, a quota, the runtime policy: no verdict on the connector — an error, nothing recorded.
    for (kind, message) in [("throttled", "Rate exceeded"), ("quota", "Max allocated ARM_64 MicroVM memory"), ("access_denied", "run_microvm: not authorized to perform lambda:PassNetworkConnector")] {
        let n = rows(&w, "connector-pending").len();
        w.update(|s| s.failures.push_back(FakeFailure { kind: kind.into(), message: message.into(), on: Some("run".into()), after_effect: false }));
        let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
        assert_eq!(code(&o), 7, "{kind}: {}", stderr(&o));
        assert!(stderr(&o).contains(message), "the error is named: {}", stderr(&o));
        assert_eq!(rows(&w, "connector-pending").len(), n, "{kind}: nothing recorded");
    }
    // Accepted, but echoed in the Id form: the gate (which knows only the configured connector's alias) rejects
    // and terminates it; RunMicrovm still accepted the connector.
    let id_form = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0a1b2c3d";
    w.update(|s| s.egress_echo = Some(vec![id_form.into()]));
    let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let row = rows(&w, "connector-pending").pop().unwrap();
    assert_eq!(row["verdict"], "accepted:echo-mismatch", "{row}");
    let note = row["note"].as_str().unwrap();
    assert!(note.contains(&format!("echoed egress {id_form}")) && note.contains("terminated by the egress gate"), "{note}");
    no_vm_left(&w);
    let mismatch = audit_rows(&w).into_iter().filter(|r| r["event"] == "vm_egress_mismatch").collect::<Vec<_>>();
    assert_eq!(mismatch.len(), 1);
    assert_eq!((mismatch[0]["detail"]["purpose"].as_str(), mismatch[0]["detail"]["terminated"].as_str()), (Some("probe"), Some("true")), "{}", mismatch[0]);
    // Echoed INTERNET_EGRESS instead: its own verdict.
    w.update(|s| s.egress_echo = Some(vec!["arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS".into()]));
    assert_eq!(code(&s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR])), 0);
    assert_eq!(rows(&w, "connector-pending").pop().unwrap()["verdict"], "accepted:internet");
    no_vm_left(&w);
    // The gate's terminate fails: the probe's terminate guard ends the VM.
    w.update(|s| {
        s.egress_echo = Some(vec![id_form.into()]);
        s.failures.push_back(FakeFailure { kind: "sdk".into(), message: "InternalError: try again".into(), on: Some("terminate".into()), after_effect: false });
    });
    let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(rows(&w, "connector-pending").pop().unwrap()["note"].as_str().unwrap().contains("left to the terminate guard"));
    assert!(stderr(&o).contains("lab: terminated"), "{}", stderr(&o));
    no_vm_left(&w);
    // The service never finds the VM RunMicrovm returned (the RUNNING budget runs out): accepted, then gone.
    w.update(|s| {
        s.egress_echo = None;
        s.run_echo_empty = true;
        for _ in 0..400 {
            s.failures.push_back(FakeFailure { kind: "not_found".into(), message: "MicroVM not found".into(), on: Some("get".into()), after_effect: false });
        }
    });
    let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let row = rows(&w, "connector-pending").pop().unwrap();
    assert_eq!(row["verdict"], "accepted:terminated", "{row}");
    w.update(|s| {
        s.failures.clear();
        s.run_echo_empty = false;
    });
}

#[test]
fn lab_connector_pending_needs_a_pending_connector_and_a_good_arn() {
    let w = World::new("");
    fake_aws(&w);
    probe_connector_state(&w, "ACTIVE");
    let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("is ACTIVE, not PENDING: nothing recorded"), "{}", stderr(&o));
    assert_eq!(w.runs(), 0, "no RunMicrovm against an ACTIVE connector");
    assert!(rows(&w, "connector-pending").is_empty());
    let before = w.state().calls.len();
    for args in [
        vec!["lab", "run", "connector-pending"],
        vec!["lab", "run", "connector-pending", "not-an-arn"],
        vec!["lab", "run", "connector-pending", "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS"],
        vec!["lab", "run", "connector-pending", "arn:aws:lambda:us-east-1:123456789012:network-connector:x"],
    ] {
        let o = s5_run(&w, &args);
        assert_eq!(code(&o), 2, "{args:?}: {}", stderr(&o));
    }
    assert_eq!(w.state().calls.len(), before, "no call at all");
    assert!(w.state().vms.is_empty() && rows(&w, "connector-pending").is_empty());
}

#[test]
fn lab_dns_path_stops_at_the_fakes_refusal_and_ends_its_vm() {
    let w = World::new("");
    let o = s5_run(&w, &["lab", "run", "dns-path"]);
    assert_eq!(code(&o), 1, "a vpc probe needs the connector: {}", stderr(&o));
    assert!(stderr(&o).contains("egress_connector_arn"), "{}", stderr(&o));
    assert_eq!(w.runs(), 0);
    connect(&w, CONNECTOR);
    let o = s5_run(&w, &["lab", "run", "dns-path"]);
    assert_eq!(code(&o), 9, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("dns-path: the file-backed fake cannot carry a shell"), "{}", stderr(&o));
    assert!(rows(&w, "dns-path").is_empty(), "nothing recorded");
    no_vm_left(&w);
    let st = w.state();
    let spec = st.specs.last().unwrap();
    assert_eq!(spec.egress_connectors, [CONNECTOR]);
    assert!(spec.ingress_connectors.iter().any(|c| c.ends_with(":SHELL_INGRESS")), "{:?}", spec.ingress_connectors);
    assert!(st.calls.iter().any(|c| matches!(c, Call::Health { .. })), "the VM's /health first");
    assert_eq!(shell_tokens(&w), 0, "refused before any shell token or dial");
    assert!(st.calls.iter().any(|c| matches!(c, Call::Terminate(_))));
    assert!(aws_calls(&w).is_empty());
}

#[test]
fn egress_check_under_the_fake_ends_its_vm_and_records_nothing() {
    let w = World::new("");
    let o = s5_run(&w, &["egress", "check"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("[aws].egress_connector_arn is not set"), "{}", stderr(&o));
    assert!(aws_calls(&w).is_empty() && w.runs() == 0, "refused before any call");
    connect(&w, CONNECTOR);
    // Exit 9: the fake cannot carry a shell; the VM the check started is ended first.
    let o = s5_run(&w, &["egress", "check", "--json"]);
    assert_eq!(code(&o), 9, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("egress check: the file-backed fake cannot carry a shell"), "{}", stderr(&o));
    assert!(stdout(&o).is_empty(), "no report: nothing was judged");
    no_vm_left(&w);
    assert_eq!(shell_tokens(&w), 0, "refused before any shell token or dial");
    let st = w.state();
    let spec = st.specs.last().unwrap();
    assert_eq!((spec.egress_connectors.clone(), spec.max_duration_s), (vec![CONNECTOR.to_string()], 900));
    assert!(spec.ingress_connectors.iter().any(|c| c.ends_with(":SHELL_INGRESS")));
    assert!(st.calls.iter().any(|c| matches!(c, Call::Health { .. })), "the VM's /health first");
    let id = st.vms.values().next().unwrap().id.clone();
    let row = vm_row(&w, &id);
    assert_eq!((row["label"].as_str(), row["terminated_by"].as_str(), row["egress"].as_str(), row["egress_gate"].as_str()), (Some("egress-check"), Some("test"), Some("vpc"), Some("passed")), "{row}");
    assert!(row.get("workspace").is_none(), "no workspace: {row}");
    let audit = audit_rows(&w);
    assert!(audit.iter().any(|r| r["event"] == "vm_run" && r["detail"]["purpose"] == "test" && r["detail"]["shell"] == "true"), "{audit:?}");
    assert!(audit.iter().any(|r| r["event"] == "vm_terminate" && r["detail"]["by"] == "test"), "{audit:?}");
    // A check of its own VM that fails before its transcript is judged still revokes, and is audited as a failed check.
    let checks: Vec<&serde_json::Value> = audit.iter().filter(|r| r["event"] == "egress_check").collect();
    assert_eq!(checks.len(), 1, "{audit:?}");
    let d = &checks[0]["detail"];
    assert_eq!((d["id"].as_str(), d["image_version"].as_str(), d["verdict"].as_str(), d["revoked"].as_str()), (Some(id.as_str()), Some("1.0"), Some("fail"), Some("0")), "{}", checks[0]);
    assert!(d["reason"].as_str().unwrap().contains("cannot carry a shell"), "{}", checks[0]);
    assert!(stderr(&o).contains("egress check FAILED: revoked 0 earlier passes of this connector"), "{}", stderr(&o));
    assert!(verified(&w).records.is_empty(), "nothing recorded");
    // The operator account was checked first, pinned like every operator call.
    assert_eq!(aws_calls(&w).trim(), "sts get-caller-identity --region eu-central-1 --endpoint-url https://sts.eu-central-1.amazonaws.com --output json");
    // --keep leaves the check's VM running, on the refusal path too.
    let o = s5_run(&w, &["egress", "check", "--keep"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("--keep:") && stderr(&o).contains("left running"), "{}", stderr(&o));
    assert_eq!(alive(&w).len(), 1);
}

#[test]
fn egress_check_refuses_another_account_and_unsuitable_vms() {
    let w = World::new("");
    connect(&w, "arn:aws:lambda:eu-central-1:999999999999:network-connector:ai-env-egress");
    let o = s5_run(&w, &["egress", "check"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("account 123456789012") && stderr(&o).contains("account 999999999999"), "{}", stderr(&o));
    assert_eq!(w.runs(), 0, "before any VM");
    let w = World::new("");
    connect(&w, CONNECTOR);
    let started = |args: &[&str]| -> String {
        let o = s5_run(&w, args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        serde_json::from_str::<serde_json::Value>(&stdout(&o)).unwrap()["id"].as_str().unwrap().to_string()
    };
    let internet = started(&["vm", "run", "--egress", "internet", "--json"]);
    let no_shell = started(&["vm", "run", "--egress", "vpc", "--json"]);
    let ok = started(&["vm", "run", "--egress", "vpc", "--shell", "--json"]);
    assert_eq!(code(&s5_run(&w, &["egress", "check", "--vm", "../x"])), 2, "not a VM id");
    for (id, why) in [("microvm-00000000-0000-4000-8000-0000000000ff", "no row"), (internet.as_str(), "not vpc"), (no_shell.as_str(), "without --shell")] {
        let o = s5_run(&w, &["egress", "check", "--vm", id]);
        assert_eq!(code(&o), 1, "{why}: {}", stderr(&o));
        assert!(stderr(&o).contains(why) && stderr(&o).contains("vm run --egress vpc --shell"), "{}", stderr(&o));
    }
    assert_eq!(shell_tokens(&w), 0);
    // A suitable VM: checked live, then the fake's refusal; the operator's VM is not the check's to end.
    let o = s5_run(&w, &["egress", "check", "--vm", &ok]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("cannot carry a shell") && !stderr(&o).contains("terminated"), "{}", stderr(&o));
    assert!(alive(&w).contains(&ok));
    // Its live echo no longer what its row requires: the gate's reject path (terminated by policy), exit 9.
    w.update(|s| s.egress_echo = Some(vec!["arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS".into()]));
    let o = s5_run(&w, &["egress", "check", "--vm", &ok]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert!(stderr(&o).contains("egress mismatch"), "{}", stderr(&o));
    assert!(!alive(&w).contains(&ok));
    assert_eq!(vm_row(&w, &ok)["terminated_by"].as_str(), Some("policy"));
    assert!(audit_rows(&w).iter().any(|r| r["event"] == "vm_egress_mismatch" && r["detail"]["via"] == "check" && r["detail"]["id"] == ok.as_str()));
    // Its row says terminated now.
    let o = s5_run(&w, &["egress", "check", "--vm", &ok]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(shell_tokens(&w), 0);
}

// ---- egress check's decision, through the transcript knob and a green network -------------------

/// The stack's ids, as in tests/fixtures/egress/ops (a network without drift).
const NET_SQUID_CONF: &str = "http_port 10.42.0.10:3128\n";
const NET_ALLOW: &str = "api.anthropic.com\nplatform.claude.com\nindex.crates.io\nstatic.crates.io\n";
const RUN_NONCE: &str = "5eed5eed5eed5eed";

/// A world whose network verification is green: `[aws].egress_connector_arn`, `state/infra.toml` of the
/// fixtures' stack, the fixtures as aws answers, the proxy's parameters and its `--status` answer.
fn green_network() -> World {
    green_network_with("")
}

/// [`green_network`] with `vm_toml` as the `[vm]` section.
fn green_network_with(vm_toml: &str) -> World {
    let w = World::new(vm_toml);
    connect(&w, CONNECTOR);
    let (_, answers) = fake_aws(&w);
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress");
    fs::copy(fixtures.join("lambda-core.get-network-connector.json"), answers.join("lambda-core.get-network-connector.json")).unwrap();
    for e in fs::read_dir(fixtures.join("ops")).unwrap().flatten() {
        fs::copy(e.path(), answers.join(e.file_name())).unwrap();
    }
    let ssm = w.root().join("ssm");
    let mut values = Vec::new();
    for (p, v) in [("squid.conf", NET_SQUID_CONF), ("allow", NET_ALLOW), ("extras", EXTRAS_HEADER), ("suspended", SUSPENDED_HEADER)] {
        let f = ssm.join(param_name(p).trim_start_matches('/'));
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, v).unwrap();
        fs::write(format!("{}.version", f.display()), "1\n").unwrap();
        values.push((p, v));
    }
    let sums: Vec<String> = PARAMS.iter().map(|p| format!("sha256_{p}={}", value_sha256(values.iter().find(|(q, _)| q == p).unwrap().1))).collect();
    let status = format!("squid-6.13-1.amzn2023.0.1.aarch64\nsquid=active allowed=4 extras=0 suspended=0 {} parse=ok applied=yes\n", sums.join(" "));
    let invocation = serde_json::json!({
        "CommandId": "0b1c2d3e-0000-4000-8000-000000000001", "InstanceId": "i-0123456789abcdef0", "Comment": "ai-env", "DocumentName": "AWS-RunShellScript",
        "DocumentVersion": "$DEFAULT", "PluginName": "aws:runShellScript", "ResponseCode": 0, "ExecutionStartDateTime": "2026-10-01T10:00:00.100Z",
        "ExecutionElapsedTime": "PT0.4S", "ExecutionEndDateTime": "2026-10-01T10:00:00.500Z", "Status": "Success", "StatusDetails": "Success",
        "StandardOutputContent": status, "StandardOutputUrl": "", "StandardErrorContent": "", "StandardErrorUrl": "",
        "CloudWatchOutputConfig": {"CloudWatchLogGroupName": "", "CloudWatchOutputEnabled": false}
    });
    fs::write(answers.join("ssm.get-command-invocation.json"), invocation.to_string()).unwrap();
    let state = InfraState {
        stack: "dev".into(),
        written: "2026-10-01T10:00:00Z".into(),
        region: "eu-central-1".into(),
        image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(),
        connector_arn: Some(CONNECTOR.into()),
        connector_name: Some("ai-env-egress".into()),
        proxy_private_ip: Some("10.42.0.10".into()),
        proxy_instance_id: Some("i-0123456789abcdef0".into()),
        egress_vpc_id: Some("vpc-0123456789abcdef0".into()),
        vm_subnet_id: Some("subnet-0aaa1111bbbb2222c".into()),
        vm_egress_security_group_id: Some("sg-0ddd3333eeee4444f".into()),
        proxy_security_group_id: Some("sg-0fff5555aaaa6666b".into()),
        dns_mode: Some("none".into()),
        parameter_prefix: Some("/ai-env/proxy".into()),
        connector_id: Some("nc-0a1b2c3d4e5f60718".into()),
        connector_state: Some("ACTIVE".into()),
        squid_conf_sha256: Some(value_sha256(NET_SQUID_CONF)),
        allow_sha256: Some(value_sha256(NET_ALLOW)),
        ..InfraState::default()
    };
    fs::create_dir_all(w.bridge().join("state")).unwrap();
    fs::write(w.bridge().join("state").join("infra.toml"), toml::to_string(&state).unwrap()).unwrap();
    w
}

/// A transcript in which every case of a closed VPC printed its marker (`case`'s line replaced by `line`).
fn transcript_file(w: &World, replace: Option<(&str, &str)>) -> PathBuf {
    let mut out = String::from("bash-5.2# aienv_c allowed https://api.anthropic.com/v1/models\r\n");
    for c in &CASES {
        let line = match c.name {
            "allowed" | "allowed-last" => "rc=0 code=401 size=86 conn=1 hc=200 t403=no sq=no".to_string(),
            "direct-name" => "rc=6 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv6" => "rc=7 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "direct-ipv4" | "direct-http" | "proxy-other-port" => "rc=28 code=000 size=0 conn=0 hc=000 t403=no sq=no".to_string(),
            "imds" | "imds-v6" => "rc=0 code=401 size=0 conn=1 hc=000 t403=no sq=no".to_string(),
            "proxy-http-8080" => "rc=0 code=403 size=3900 conn=1 hc=000 t403=no sq=yes".to_string(),
            n if n.starts_with("proxy-") || n == "denied" => "rc=56 code=000 size=0 conn=1 hc=403 t403=yes sq=no".to_string(),
            n if n.starts_with("dns-public") => format!("rc=9 ns={} res=no st=none ra=none", if n == "dns-public-port" { "208.67.222.222" } else { "1.1.1.1" }),
            n if n.starts_with("dns-platform6") => "rc=9 ns=fd00:ec2::253 res=no st=none ra=none".to_string(),
            _ => "rc=9 ns=10.42.0.2 res=no st=none ra=none".to_string(),
        };
        let line = match replace {
            Some((name, other)) if name == c.name => other.to_string(),
            _ => line,
        };
        out.push_str(&format!("@@AIENV{RUN_NONCE} {} {line}\r\n", c.name));
    }
    out.push_str(&format!("@@AIENV{RUN_NONCE} end\r\nbash-5.2# exit\r\n"));
    let p = w.root().join("transcript.txt");
    fs::write(&p, out).unwrap();
    p
}

/// squid's log of the run in CloudWatch (`logs filter-log-events`), stamped now, from client `client`.
fn squid_log(w: &World, client: &str, skip: Option<&str>) {
    let t = unix_now();
    let host = denied_host(RUN_NONCE);
    let lines = [
        "TCP_TUNNEL/200 1 CONNECT api.anthropic.com:443".to_string(),
        "TCP_DENIED/403 3900 CONNECT 1.1.1.1:443".to_string(),
        "TCP_DENIED/403 3900 GET api.anthropic.com:8080".to_string(),
        "TCP_DENIED/403 3900 CONNECT api.anthropic.com:8443".to_string(),
        "TCP_DENIED/403 3900 CONNECT github.com:443".to_string(),
        format!("TCP_DENIED/403 3900 CONNECT {host}:443"),
        "TCP_TUNNEL/200 1 CONNECT api.anthropic.com:443".to_string(),
    ];
    let events: Vec<serde_json::Value> = lines
        .iter()
        .filter(|l| skip.is_none_or(|s| !l.contains(s)))
        .enumerate()
        .map(|(i, l)| serde_json::json!({"logStreamName": "i-0123456789abcdef0", "timestamp": t * 1000, "message": format!("aienv {t}.{i:03} 5 {client} {l}"), "ingestionTime": t * 1000, "eventId": format!("e{i}")}))
        .collect();
    fs::write(w.root().join("answers").join("logs.filter-log-events.json"), serde_json::json!({"events": events, "searchedLogStreams": []}).to_string()).unwrap();
}

fn check_with(w: &World, args: &[&str], transcript: &Path) -> std::process::Output {
    s5_run_env(w, args, &[(FAKE_SHELL_KNOB, transcript)])
}

fn verified(w: &World) -> EgressVerified {
    toml::from_str(&fs::read_to_string(w.bridge().join("state/egress-verified.toml")).unwrap_or_default()).unwrap()
}

fn seed_verified(w: &World) {
    let rec = |image_version: &str, connector: &str| VerifiedRecord { image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(), image_version: image_version.into(), connector: connector.into(), vm_id: "microvm-old".into(), at: "2026-09-30T10:00:00Z".into(), dns: "no-dns".into(), ..VerifiedRecord::default() };
    let v = EgressVerified { records: vec![rec("0.9", CONNECTOR), rec("1.0", CONNECTOR), rec("1.0", "arn:aws:lambda:eu-central-1:123456789012:network-connector:other")], ..EgressVerified::default() };
    fs::create_dir_all(w.bridge().join("state")).unwrap();
    fs::write(w.bridge().join("state/egress-verified.toml"), toml::to_string(&v).unwrap()).unwrap();
}

fn check_audit(w: &World) -> Vec<serde_json::Value> {
    audit_rows(w).into_iter().filter(|r| r["event"] == "egress_check").collect()
}

#[test]
fn egress_check_records_a_pass_resting_on_the_network_and_squids_log() {
    let w = green_network();
    squid_log(&w, "10.42.1.17", None);
    let t = transcript_file(&w, None);
    let o = check_with(&w, &["egress", "check"], &t);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("note: the case results are reported by the VM itself; a record rests on the network verification and squid's log"), "{out}");
    assert!(out.contains("network: 19 checks ok: connector, connector-enis") && out.contains("squid log: from 10.42.1.17: 2 tunnels"), "{out}");
    assert!(out.contains("egress check passed: recorded for image version 1.0"), "{out}");
    let v = verified(&w);
    assert_eq!(v.records.len(), 1, "{v:?}");
    let rec = &v.records[0];
    assert_eq!((rec.image_arn.as_str(), rec.image_version.as_str(), rec.connector.as_str(), rec.dns.as_str()), (ai_env_cli::bridge::api::FAKE_IMAGE_ARN, "1.0", CONNECTOR, "no-dns"));
    assert!(rec.network.starts_with("19 checks ok: connector") && rec.squid_log.contains("TCP_DENIED/403 for CONNECT n5eed5eed5eed5eed.example.com:443") && rec.cases.contains("allowed-last=pass"), "{rec:?}");
    // Bound to the connector's live facts (the golden get-network-connector) and the image version's created_at (the fake's 1.0).
    assert_eq!(
        (rec.connector_facts.id.as_str(), rec.connector_facts.version.as_str(), rec.connector_facts.subnet_ids.clone(), rec.connector_facts.security_group_ids.clone(), rec.image_created_at),
        ("nc-0a1b2c3d4e5f60718", "1", vec!["subnet-0aaa1111bbbb2222c".to_string()], vec!["sg-0ddd3333eeee4444f".to_string()], Some(1_789_804_800))
    );
    let audit = check_audit(&w);
    assert_eq!(audit.len(), 1);
    assert_eq!((audit[0]["detail"]["verdict"].as_str(), audit[0]["detail"]["image_version"].as_str()), (Some("pass"), Some("1.0")), "{}", audit[0]);
    no_vm_left(&w);
    // The evidence: every network call and the squid query, pinned; the window and the quoted pattern.
    let calls = aws_calls(&w);
    assert!(calls.lines().all(|l| l.contains(" --region eu-central-1 ") && l.contains(" --endpoint-url https://")), "{calls}");
    let logs: Vec<&str> = calls.lines().filter(|l| l.starts_with("logs filter-log-events")).collect();
    assert_eq!(logs.len(), 1, "complete at the first poll: {calls}");
    assert!(logs[0].contains("--log-group-name /ai-env/egress/squid --filter-pattern \"aienv\" --start-time ") && logs[0].contains(" --end-time "), "{}", logs[0]);
    for op in ["ec2 describe-route-tables", "ec2 describe-security-groups", "ec2 describe-network-acls", "ssm send-command", "lambda-core get-network-connector"] {
        assert!(calls.lines().any(|l| l.starts_with(op)), "{op}: {calls}");
    }
    assert_eq!(calls.lines().filter(|l| l.starts_with(&format!("lambda-core get-network-connector --identifier {CONNECTOR} "))).count(), 1, "one read: the record binds the answer the network verification judged: {calls}");
    // --json: one document with every case, the evidence and the decision.
    let o = check_with(&w, &["egress", "check", "--json"], &t);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!((doc["verdict"].as_str(), doc["recorded"].as_bool(), doc["report_only"].as_bool()), (Some("pass"), Some(true), Some(false)));
    assert_eq!(doc["cases"].as_array().unwrap().len(), CASES.len());
    assert_eq!((doc["network"]["ok"].as_bool(), doc["squid_log"]["ok"].as_bool()), (Some(true), Some(true)));
}

/// What the first live check met (1 Oct 2026): a `get-network-connector` answer without `Version`, a script that
/// waited for the proxy before its first case, and `fd00:ec2::253` replying without an address. The pass is
/// recorded (bound to the facts the answer has), the wait and dig's status are reported, and the run's DNS verdict
/// is the platform resolver's.
#[test]
fn egress_check_records_a_pass_for_the_live_connector_shape_and_reports_the_wait() {
    let w = green_network();
    let answer = w.root().join("answers").join("lambda-core.get-network-connector.json");
    let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&answer).unwrap()).unwrap();
    doc.as_object_mut().unwrap().remove("Version");
    doc["StateReason"] = serde_json::json!("Initial creation");
    fs::write(&answer, doc.to_string()).unwrap();
    squid_log(&w, "10.42.1.158", None);
    let t = transcript_file(&w, Some(("dns-platform6-udp", "rc=0 ns=fd00:ec2::253 res=no st=REFUSED ra=no")));
    let text = fs::read_to_string(&t).unwrap().replacen("@@AIENV", &format!("@@AIENV{RUN_NONCE} ready try=4 s=6 ok=yes\r\n@@AIENV"), 1);
    fs::write(&t, text).unwrap();
    let o = check_with(&w, &["egress", "check"], &t);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("ready: the VM reached the proxy's port 6 s after the script began (4 attempts)"), "{out}");
    assert!(out.contains("dns-platform6-udp   fd00:ec2::253 replied (status REFUSED, no recursion) and resolved nothing") && out.contains("dns: platform-dns:fd00:ec2::253"), "{out}");
    assert!(out.contains("egress check passed: recorded for image version 1.0"), "{out}");
    let rec = &verified(&w).records[0];
    assert_eq!((rec.connector_facts.id.as_str(), rec.connector_facts.version.as_str(), rec.connector_facts.network_protocol.as_str()), ("nc-0a1b2c3d4e5f60718", "", "IPv4"), "no Version answered: bound to the rest");
    assert_eq!(rec.dns, "platform-dns:fd00:ec2::253");
    let audit = check_audit(&w);
    assert_eq!((audit[0]["detail"]["verdict"].as_str(), audit[0]["detail"]["ready"].as_str()), (Some("pass"), Some("6s/4/ok")), "{}", audit[0]);
    no_vm_left(&w);
}

#[test]
fn egress_check_revokes_on_any_failure_and_vm_is_report_only() {
    let w = green_network();
    let other = "arn:aws:lambda:eu-central-1:123456789012:network-connector:other";
    let fail = |o: &std::process::Output, why: &str| {
        assert_eq!(code(o), 9, "{why}: {}\n{}", stdout(o), stderr(o));
        assert!(stderr(o).contains(why), "{why}: {}", stderr(o));
        let v = verified(&w);
        assert!(v.records.iter().all(|r| r.connector == other), "{why}: every record of the connector revoked: {v:?}");
        assert_eq!(v.records.len(), 1, "{why}: another connector's record stays");
        let last = check_audit(&w).pop().unwrap();
        assert_eq!((last["detail"]["verdict"].as_str(), last["detail"]["revoked"].as_str()), (Some("fail"), Some("2")), "{why}: {last}");
        no_vm_left(&w);
    };
    // A case fails (direct egress answered): the VM's word is enough to fail.
    squid_log(&w, "10.42.1.17", None);
    seed_verified(&w);
    let o = check_with(&w, &["egress", "check"], &transcript_file(&w, Some(("direct-ipv4", "rc=0 code=200 size=9 conn=1 hc=000 t403=no sq=no"))));
    fail(&o, "direct-ipv4: OPEN");
    assert!(stdout(&o).contains("revoked 2 earlier passes of this connector"), "{}", stdout(&o));
    // Every case passes, but squid's log lacks the run's GET :8080 denial (budget scaled to milliseconds).
    seed_verified(&w);
    squid_log(&w, "10.42.1.17", Some("GET api.anthropic.com:8080"));
    fail(&check_with(&w, &["egress", "check"], &transcript_file(&w, None)), "TCP_DENIED/403 GET api.anthropic.com:8080 from 10.42.1.17");
    // squid's log shows the run from outside the VM subnet.
    seed_verified(&w);
    squid_log(&w, "10.42.0.99", None);
    fail(&check_with(&w, &["egress", "check"], &transcript_file(&w, None)), "outside the VM subnet");
    // The network drifted (a VPC endpoint appeared): squid's log is not even asked.
    seed_verified(&w);
    squid_log(&w, "10.42.1.17", None);
    let endpoints = w.root().join("answers").join("ec2.describe-vpc-endpoints.json");
    let green = fs::read_to_string(&endpoints).unwrap();
    fs::write(&endpoints, serde_json::json!({"VpcEndpoints": [{"VpcEndpointId": "vpce-0123456789abcdef0", "ServiceName": "com.amazonaws.eu-central-1.s3", "State": "available"}]}).to_string()).unwrap();
    let _ = fs::remove_file(w.root().join("aws.log"));
    fail(&check_with(&w, &["egress", "check"], &transcript_file(&w, None)), "network verification: DRIFT vpc-endpoints");
    assert!(!aws_calls(&w).contains("logs filter-log-events"), "{}", aws_calls(&w));
    fs::write(&endpoints, green).unwrap();
    // --vm: report only — a pass is not recorded, a failure revokes nothing.
    let started = s5_run(&w, &["vm", "run", "--egress", "vpc", "--shell", "--json"]);
    assert_eq!(code(&started), 0, "{}", stderr(&started));
    let id = serde_json::from_str::<serde_json::Value>(&stdout(&started)).unwrap()["id"].as_str().unwrap().to_string();
    seed_verified(&w);
    let before = verified(&w);
    let o = check_with(&w, &["egress", "check", "--vm", &id], &transcript_file(&w, None));
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("report only: `--vm` never records a pass and never revokes one"), "{}", stdout(&o));
    assert_eq!(verified(&w), before, "nothing recorded");
    let o = check_with(&w, &["egress", "check", "--vm", &id], &transcript_file(&w, Some(("denied", "rc=0 code=200 size=9 conn=1 hc=200 t403=no sq=no"))));
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    assert_eq!(verified(&w), before, "nothing revoked");
    let last = check_audit(&w).pop().unwrap();
    assert_eq!((last["detail"]["verdict"].as_str(), last["detail"]["report_only"].as_str(), last["detail"].get("revoked")), (Some("fail"), Some("true"), None), "{last}");
    assert!(alive(&w).contains(&id), "the operator's VM is not the check's to end");
}

#[test]
fn egress_check_revokes_and_records_nothing_when_a_network_row_is_unknown() {
    let w = green_network();
    squid_log(&w, "10.42.1.17", None);
    seed_verified(&w);
    let t = transcript_file(&w, None);
    let o = s5_run_env(&w, &["egress", "check"], &[(FAKE_SHELL_KNOB, t.as_path()), ("FAKE_AWS_FAIL_OP", Path::new("ec2 describe-nat-gateways"))]);
    assert_eq!(code(&o), 9, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("network verification: unknown nat-gateways"), "{}", stderr(&o));
    let v = verified(&w);
    assert!(v.records.iter().all(|r| r.connector != CONNECTOR) && v.records.len() == 1, "revoked, nothing recorded: {v:?}");
    let last = check_audit(&w).pop().unwrap();
    assert_eq!((last["detail"]["verdict"].as_str(), last["detail"]["revoked"].as_str()), (Some("fail"), Some("2")), "{last}");
    assert!(!aws_calls(&w).contains("logs filter-log-events"), "squid's log is not asked once the network failed");
    no_vm_left(&w);
}

#[test]
fn egress_check_ends_its_gate_rejected_vm_even_with_keep_and_revokes() {
    for keep in [false, true] {
        let w = World::new("");
        connect(&w, CONNECTOR);
        seed_verified(&w);
        // The VM echoes INTERNET_EGRESS: the gate rejects it, and its terminate is throttled once.
        w.update(|s| {
            s.egress_echo = Some(vec!["arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS".into()]);
            s.failures.push_back(FakeFailure { kind: "throttled".into(), message: "Rate exceeded".into(), on: Some("terminate".into()), after_effect: false });
        });
        let args: &[&str] = if keep { &["egress", "check", "--keep"] } else { &["egress", "check"] };
        let o = s5_run(&w, args);
        assert_eq!(code(&o), 9, "keep {keep}: {}\n{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("egress mismatch") && stderr(&o).contains("its egress gate did not pass"), "keep {keep}: {}", stderr(&o));
        assert!(alive(&w).is_empty(), "keep {keep}: a gate-rejected VM is never left running: {:?}", alive(&w));
        let id = w.state().vms.values().next().unwrap().id.clone();
        assert_eq!(vm_row(&w, &id)["terminated_by"].as_str(), Some("policy"), "keep {keep}");
        assert_eq!(shell_tokens(&w), 0);
        // A failure before the transcript is judged: revoked and audited all the same.
        let v = verified(&w);
        assert!(v.records.iter().all(|r| r.connector != CONNECTOR) && v.records.len() == 1, "keep {keep}: {v:?}");
        let last = check_audit(&w).pop().unwrap();
        assert_eq!((last["detail"]["id"].as_str(), last["detail"]["verdict"].as_str(), last["detail"]["revoked"].as_str()), (Some(id.as_str()), Some("fail"), Some("2")), "keep {keep}: {last}");
        assert!(last["detail"]["reason"].as_str().unwrap().contains("egress mismatch"), "keep {keep}: {last}");
        assert!(stderr(&o).contains("revoked 2 earlier passes of this connector"), "keep {keep}: {}", stderr(&o));
    }
}

#[test]
fn egress_check_vm_refuses_a_row_whose_gate_did_not_pass() {
    let w = World::new("");
    connect(&w, CONNECTOR);
    let o = s5_run(&w, &["vm", "run", "--egress", "vpc", "--shell", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let id = serde_json::from_str::<serde_json::Value>(&stdout(&o)).unwrap()["id"].as_str().unwrap().to_string();
    let path = w.bridge().join("state/vms").join(format!("{id}.toml"));
    let passed = fs::read_to_string(&path).unwrap();
    assert!(passed.contains("egress_gate = \"passed\""), "{passed}");
    for gate in ["pending", "mismatch"] {
        fs::write(&path, passed.replace("egress_gate = \"passed\"", &format!("egress_gate = \"{gate}\""))).unwrap();
        let o = s5_run(&w, &["egress", "check", "--vm", &id]);
        assert_eq!(code(&o), 1, "{gate}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("its egress gate is {gate}, not passed")), "{gate}: {}", stderr(&o));
    }
    assert_eq!(shell_tokens(&w), 0);
    assert!(check_audit(&w).is_empty(), "refused before anything ran");
}

#[test]
fn lab_connector_pending_judges_the_running_answer_too() {
    let w = World::new("");
    for (echo, verdict) in [
        ("arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS", "accepted:internet"),
        ("arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0a1b2c3d", "accepted:echo-mismatch"),
    ] {
        // RunMicrovm echoes the probe's connector; the RUNNING answer (GetMicrovm) echoes something else.
        w.update(|s| s.get_egress_echo = Some(vec![echo.into()]));
        let o = s5_run(&w, &["lab", "run", "connector-pending", PROBE_CONNECTOR]);
        assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
        let row = rows(&w, "connector-pending").pop().unwrap();
        assert_eq!(row["verdict"], verdict, "{row}");
        assert!(row["note"].as_str().unwrap().contains(&format!("echoing egress {echo} (not this ARN)")), "{row}");
        no_vm_left(&w);
    }
}

#[test]
fn egress_check_never_claims_a_pass_whose_record_a_newer_revocation_refused() {
    let w = green_network();
    squid_log(&w, "10.42.1.17", None);
    // A failing check revoked the connector after this check began (an hour from now: later than any start).
    let v = EgressVerified { records: vec![], revocations: std::collections::BTreeMap::from([(CONNECTOR.to_string(), unix_now() + 3600)]) };
    fs::create_dir_all(w.bridge().join("state")).unwrap();
    fs::write(w.bridge().join("state/egress-verified.toml"), toml::to_string(&v).unwrap()).unwrap();
    let o = check_with(&w, &["egress", "check"], &transcript_file(&w, None));
    assert_eq!(code(&o), 9, "a refused record is no pass: {}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("a failing check revoked this connector's passes after this check began"), "{}", stderr(&o));
    assert!(!stdout(&o).contains("egress check passed"), "{}", stdout(&o));
    assert!(verified(&w).records.is_empty(), "nothing recorded");
    let last = check_audit(&w).pop().unwrap();
    assert_eq!(last["detail"]["verdict"].as_str(), Some("fail"), "{last}");
    no_vm_left(&w);
}

/// `egress check --if-needed` (what `make claude-update` runs after a deploy): no VM when the image version a new VM
/// runs — read live as the operator — already has a pass bound to that very build and to the connector's live facts;
/// the full check when the build, the connector or the version differ, or the live read fails. A DNS verdict the gate
/// does not accept is said, and starts nothing (another check would see the same).
#[test]
fn egress_check_if_needed_starts_nothing_for_a_version_already_verified() {
    let w = green_network();
    let answers = w.root().join("answers");
    let live_image = |active: &str| fs::write(answers.join("lambda-microvms.get-microvm-image.json"), serde_json::json!({"imageArn": ai_env_cli::bridge::api::FAKE_IMAGE_ARN, "state": "UPDATED", "latestActiveImageVersion": active}).to_string()).unwrap();
    let versions = |items: serde_json::Value| fs::write(answers.join("lambda-microvms.list-microvm-image-versions.json"), serde_json::json!({"items": items}).to_string()).unwrap();
    // The record's build: 1_789_804_800 = 2026-09-19T08:00:00Z, as the aws CLI prints createdAt (an offset, microseconds).
    const BUILD: &str = "2026-09-19T11:00:00.059000+03:00";
    let v10 = |created: &str| serde_json::json!({"imageVersion": "1.0", "state": "SUCCESSFUL", "status": "ACTIVE", "createdAt": created});
    live_image("1.0");
    versions(serde_json::json!([v10(BUILD)]));
    let golden: serde_json::Value = serde_json::from_str(&fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress/lambda-core.get-network-connector.json")).unwrap()).unwrap();
    let facts = ai_env_cli::bridge::egress::ConnectorFacts::from_get(&golden).unwrap();
    let rec = VerifiedRecord { image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(), image_version: "1.0".into(), connector: CONNECTOR.into(), vm_id: "microvm-earlier".into(), at: "2026-10-02T06:10:00Z".into(), dns: "no-dns".into(), connector_facts: facts, image_created_at: Some(1_789_804_800), ..VerifiedRecord::default() };
    let seed = |records: Vec<VerifiedRecord>| fs::write(w.bridge().join("state/egress-verified.toml"), toml::to_string(&EgressVerified { records, ..EgressVerified::default() }).unwrap()).unwrap();
    seed(vec![rec.clone()]);
    let t = transcript_file(&w, None);
    squid_log(&w, "10.42.1.158", None);
    let skipped = |o: &std::process::Output| code(o) == 0 && stdout(o).contains("nothing started");

    // The pass of the version new VMs run, this build, these connector facts: nothing started, three operator reads.
    let o = check_with(&w, &["egress", "check", "--if-needed"], &t);
    assert!(skipped(&o), "{}\n{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("egress check: image version 1.0, the one a new VM runs, already has a passing check with") && stdout(&o).contains("(VM microvm-earlier, 2026-10-02T06:10:00Z), bound to this build and to the connector's live facts"), "{}", stdout(&o));
    assert!(!stdout(&o).contains("note:"), "no-dns needs no acceptance: {}", stdout(&o));
    assert!(w.state().vms.is_empty() && shell_tokens(&w) == 0, "no VM, no shell");
    let calls = aws_calls(&w);
    for (op, n) in [("lambda-microvms get-microvm-image ", 1), ("lambda-microvms list-microvm-image-versions ", 1), ("lambda-core get-network-connector ", 1)] {
        assert_eq!(calls.lines().filter(|l| l.starts_with(op)).count(), n, "{op}: {calls}");
    }
    assert!(calls.lines().all(|l| l.contains(" --region eu-central-1")), "{calls}");
    assert!(check_audit(&w).is_empty(), "a skip is no check");
    let o = check_with(&w, &["egress", "check", "--if-needed", "--json"], &t);
    let doc: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!((doc["skipped"].as_bool(), doc["image_version"].as_str(), doc["recorded_vm"].as_str(), doc["dns_accepted"].as_bool()), (Some(true), Some("1.0"), Some("microvm-earlier"), Some(true)), "{doc}");
    for extra in [&["--vm", "microvm-x"][..], &["--keep"][..]] {
        let mut args = vec!["egress", "check", "--if-needed"];
        args.extend_from_slice(extra);
        assert_eq!(code(&check_with(&w, &args, &t)), 2, "{extra:?}");
    }

    // A pass whose DNS verdict the gate does not accept yet: still nothing started, and it says so.
    seed(vec![VerifiedRecord { dns: "platform-dns:fd00:ec2::253".into(), ..rec.clone() }]);
    let o = check_with(&w, &["egress", "check", "--if-needed"], &t);
    assert!(skipped(&o) && stdout(&o).contains("egress check: note: its DNS verdict platform-dns:fd00:ec2::253 is not accepted ([egress].accept_platform_dns = false): the credential gate refuses this pass until it is"), "{}", stdout(&o));
    seed(vec![rec.clone()]);

    // Each difference runs the full check: another build of 1.0 (created 5 s later, the image created again), the
    // connector changed, a new active version without a pass, the live read failing.
    let runs = |what: &str| {
        let o = check_with(&w, &["egress", "check", "--if-needed"], &t);
        assert!(!stdout(&o).contains("nothing started") && stdout(&o).contains("egress check of microvm-"), "{what}: {}\n{}", stdout(&o), stderr(&o));
        seed(vec![rec.clone()]);
    };
    versions(serde_json::json!([v10("2026-09-19T11:00:05+03:00")]));
    runs("another build");
    versions(serde_json::json!([v10(BUILD)]));
    let answer = answers.join("lambda-core.get-network-connector.json");
    let mut changed = golden.clone();
    changed["Configuration"]["VpcEgressConfiguration"]["SecurityGroupIds"] = serde_json::json!(["sg-0eee9999aaaa8888b"]);
    fs::write(&answer, changed.to_string()).unwrap();
    runs("the connector changed");
    fs::write(&answer, golden.to_string()).unwrap();
    live_image("2.0");
    versions(serde_json::json!([v10(BUILD), {"imageVersion": "2.0", "state": "SUCCESSFUL", "status": "ACTIVE", "createdAt": "2026-10-02T09:00:00+03:00"}]));
    runs("a new version");
    live_image("1.0");
    fs::write(answers.join("lambda-microvms.get-microvm-image.rc"), "254\n").unwrap();
    runs("the live read failing");
    no_vm_left(&w);
}

/// A check through a stopped proxy can only fail, and a failing check of its own VM revokes every pass of the
/// connector: it is refused before any VM, revoking nothing.
#[test]
fn egress_check_refuses_a_stopped_proxy_before_any_vm_and_revokes_nothing() {
    let w = green_network();
    let instances = w.root().join("answers").join("ec2.describe-instances.json");
    let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&instances).unwrap()).unwrap();
    doc["Reservations"][0]["Instances"][0]["State"] = serde_json::json!({"Code": 80, "Name": "stopped"});
    fs::write(&instances, doc.to_string()).unwrap();
    seed_verified(&w);
    let before = verified(&w);
    let t = transcript_file(&w, None);
    let o = check_with(&w, &["egress", "check"], &t);
    assert_eq!(code(&o), 1, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("egress check: the egress proxy i-0123456789abcdef0 is stopped: make proxy-start, then run the check again (nothing started, nothing revoked)"), "{}", stderr(&o));
    assert!(w.state().vms.is_empty(), "no VM");
    assert_eq!(verified(&w), before, "nothing revoked");
    assert!(check_audit(&w).is_empty());
}

/// A refusal before RunMicrovm ([vm].max_concurrent reached: one VM of another owner runs) proves nothing about egress:
/// the check fails without revoking the connector's passes.
#[test]
fn egress_check_refused_before_runmicrovm_revokes_nothing() {
    let w = green_network_with("max_concurrent = 1");
    let (vm, _) = super::cli::foreign_vm(9, Some("someone@elsewhere"), ai_env_cli::bridge::api::VmState::Running, 60);
    w.update(|s| s.insert_vm(vm));
    seed_verified(&w);
    let before = verified(&w);
    let t = transcript_file(&w, None);
    let o = check_with(&w, &["egress", "check"], &t);
    assert_ne!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("max_concurrent"), "{}", stderr(&o));
    assert!(!stderr(&o).contains("revoked"), "{}", stderr(&o));
    assert_eq!(verified(&w), before, "nothing revoked");
    assert_eq!(w.runs(), 0, "no RunMicrovm");
}

/// Once RunMicrovm made the check's own VM, a failure revokes the connector's passes even when nothing of the VM is
/// left alive to name: the egress gate rejected it and its terminate went through at once, or it never reached
/// RUNNING and was terminated. The audit row names the VM all the same.
#[test]
fn egress_check_revokes_once_runmicrovm_made_its_vm_even_when_it_is_gone() {
    let internet = "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS";
    for (what, why) in [("echo", "egress mismatch"), ("never running", "terminated it")] {
        let w = World::new("");
        connect(&w, CONNECTOR);
        seed_verified(&w);
        match what {
            "echo" => w.update(|s| s.egress_echo = Some(vec![internet.into()])),
            _ => w.update(|s| s.auto_advance = false),
        }
        let o = s5_run(&w, &["egress", "check"]);
        assert_ne!(code(&o), 0, "{what}: {}\n{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains(why), "{what}: {}", stderr(&o));
        assert!(alive(&w).is_empty(), "{what}: {:?}", alive(&w));
        let id = w.state().vms.values().next().unwrap().id.clone();
        let v = verified(&w);
        assert!(v.records.iter().all(|r| r.connector != CONNECTOR) && v.records.len() == 1, "{what}: revoked: {v:?}");
        let last = check_audit(&w).pop().unwrap_or_else(|| panic!("{what}: no egress_check audit row"));
        assert_eq!((last["detail"]["id"].as_str(), last["detail"]["verdict"].as_str(), last["detail"]["revoked"].as_str()), (Some(id.as_str()), Some("fail"), Some("2")), "{what}: {last}");
        assert!(stderr(&o).contains("revoked 2 earlier passes of this connector"), "{what}: {}", stderr(&o));
    }
}

/// A definite RunMicrovm refusal made no VM: it proves nothing about egress, and revokes nothing.
#[test]
fn egress_check_refused_by_runmicrovm_revokes_nothing() {
    let w = World::new("");
    connect(&w, CONNECTOR);
    seed_verified(&w);
    let before = verified(&w);
    w.update(|s| s.failures.push_back(FakeFailure { kind: "validation".into(), message: "fake refusal of the run".into(), on: Some("run".into()), after_effect: false }));
    let o = s5_run(&w, &["egress", "check"]);
    assert_ne!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("fake refusal of the run"), "{}", stderr(&o));
    assert!(!stderr(&o).contains("revoked"), "{}", stderr(&o));
    assert!(w.state().vms.is_empty(), "no VM");
    assert_eq!(verified(&w), before, "nothing revoked");
    assert!(check_audit(&w).is_empty(), "{:?}", check_audit(&w));
}

/// `--if-needed` resolves the version from exactly what the check's own RunMicrovm would get: an `[aws].image_version`
/// with a blank around it (RunMicrovm refuses it) never matches the recorded pass of the trimmed version.
#[test]
fn egress_check_if_needed_never_skips_for_a_padded_image_version() {
    let w = green_network();
    let path = w.bridge().join("bridge.toml");
    let text = fs::read_to_string(&path).unwrap().replacen("[aws]\n", "[aws]\nimage_version = \" 1.0\"\n", 1);
    fs::write(&path, text).unwrap();
    let answers = w.root().join("answers");
    fs::write(answers.join("lambda-microvms.get-microvm-image.json"), serde_json::json!({"imageArn": ai_env_cli::bridge::api::FAKE_IMAGE_ARN, "state": "UPDATED", "latestActiveImageVersion": "1.0"}).to_string()).unwrap();
    fs::write(answers.join("lambda-microvms.list-microvm-image-versions.json"), serde_json::json!({"items": [{"imageVersion": "1.0", "state": "SUCCESSFUL", "status": "ACTIVE", "createdAt": "2026-09-19T08:00:00Z"}]}).to_string()).unwrap();
    let golden: serde_json::Value = serde_json::from_str(&fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress/lambda-core.get-network-connector.json")).unwrap()).unwrap();
    let rec = VerifiedRecord {
        image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        connector: CONNECTOR.into(),
        vm_id: "microvm-earlier".into(),
        at: "2026-10-02T06:10:00Z".into(),
        dns: "no-dns".into(),
        connector_facts: ai_env_cli::bridge::egress::ConnectorFacts::from_get(&golden).unwrap(),
        image_created_at: Some(1_789_804_800),
        ..VerifiedRecord::default()
    };
    let seeded = EgressVerified { records: vec![rec], ..EgressVerified::default() };
    fs::write(w.bridge().join("state/egress-verified.toml"), toml::to_string(&seeded).unwrap()).unwrap();
    let o = check_with(&w, &["egress", "check", "--if-needed"], &transcript_file(&w, None));
    assert_ne!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(!stdout(&o).contains("nothing started"), "{}", stdout(&o));
    assert!(stderr(&o).contains("\" 1.0\""), "RunMicrovm's own refusal names the value: {}", stderr(&o));
    assert!(w.state().vms.is_empty(), "refused before any VM");
    assert_eq!(verified(&w), seeded, "nothing revoked");
}

/// A proxy id in state/infra.toml that EC2 no longer has (terminated, shutting down, unknown): refused before any VM
/// with the state file's hint, revoking nothing.
#[test]
fn egress_check_refuses_a_gone_proxy_before_any_vm_and_revokes_nothing() {
    for gone in ["terminated", "shutting-down", "unknown"] {
        let w = green_network();
        let instances = w.root().join("answers").join("ec2.describe-instances.json");
        if gone == "unknown" {
            fs::remove_file(&instances).unwrap();
            fs::write(w.root().join("answers").join("ec2.describe-instances.rc"), "254\n").unwrap();
            fs::write(w.root().join("answers").join("ec2.describe-instances.stderr"), "\nAn error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID 'i-0123456789abcdef0' does not exist\n").unwrap();
        } else {
            let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&instances).unwrap()).unwrap();
            doc["Reservations"][0]["Instances"][0]["State"] = serde_json::json!({"Code": 48, "Name": gone});
            fs::write(&instances, doc.to_string()).unwrap();
        }
        seed_verified(&w);
        let before = verified(&w);
        let o = check_with(&w, &["egress", "check"], &transcript_file(&w, None));
        assert_eq!(code(&o), 1, "{gone}: {}\n{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("egress check: state/infra.toml names a proxy that no longer exists (i-0123456789abcdef0)"), "{gone}: {}", stderr(&o));
        assert!(stderr(&o).contains("then make proxy-start if it is stopped, and run the check again (nothing started, nothing revoked)"), "{gone}: {}", stderr(&o));
        assert!(w.state().vms.is_empty(), "{gone}: no VM");
        assert_eq!(verified(&w), before, "{gone}: nothing revoked");
        assert!(check_audit(&w).is_empty(), "{gone}");
    }
}
