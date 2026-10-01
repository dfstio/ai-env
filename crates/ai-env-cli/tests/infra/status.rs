//! tests/infra.rs area: status — `ai-env infra status` (from `--json-in`,
//! never pulumi; its live `get-microvm-image` and, with S5's
//! `connectorArn`, `lambda-core get-network-connector` reads go to the fake
//! aws of tests/fakes/aws.sh, first on a PATH of
//! `<tmp>/fakebin:/usr/bin:/bin`), `infra base-image` and
//! `infra versions-diff` (from files, never aws). Every run owns a temp
//! `HOME`, `AI_ENV_BRIDGE_DIR` and `AI_ENV_DIR`, and every [`run`] is under
//! a deadline; the account id is the documentation one.
//!
//! The connector answers come from a per-test `FAKE_AWS_ANSWERS` directory
//! (the fake keeps call counters there): a copy of the golden
//! tests/fixtures/egress/lambda-core.get-network-connector.json, variants of
//! it built at run time (another `State`, another `Arn`), or an `.rc` +
//! `.stderr` pair for a failed read. No fixture file is added for them.
use super::common::*;
use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::bridge::doctor::{row_egress, row_infra_state};
use ai_env_cli::bridge::egress::{internet_egress_arn, ConnectorAlias};
use ai_env_cli::bridge::infra::read_infra_state;
use ai_env_cli::bridge::wrapper::ProbeRow;
use ai_env_cli::commands::{DoctorLine, Tag};
use ai_env_cli::wire::time::parse_rfc3339_utc;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const ARN: &str = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent";
const EXEC_ROLE: &str = "arn:aws:iam::123456789012:role/ai-env-microvm-exec";
const BASE_ARN: &str = "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1";
/// The golden fixture's connector (its `Arn`).
const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
const PROXY_IP: &str = "10.42.0.10";
/// The pinned call `ai-env infra status` makes for [`CONNECTOR`], as the fake logs it.
const CONNECTOR_CALL: &str = "lambda-core get-network-connector --identifier arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress --region eu-central-1 --endpoint-url https://lambda.eu-central-1.amazonaws.com --output json";

/// The S5 outputs of `infra/egress.ts` (camelCase), all twelve.
const S5_OUTPUTS: [&str; 12] =
    ["connectorArn", "connectorName", "proxyPrivateIp", "proxyInstanceId", "egressVpcId", "vmSubnetId", "vmEgressSecurityGroupId", "proxySecurityGroupId", "operatorRoleArn", "egressLogGroup", "dnsMode", "parameterPrefix"];

/// The S3 and S5 programs' outputs, plus one a later stage may add.
fn outputs(region: &str) -> serde_json::Value {
    serde_json::json!({
        "region": region,
        "accountId": "123456789012",
        "imageName": "ai-env-agent",
        "imageArn": ARN,
        "imageState": "CREATED",
        "latestActiveImageVersion": "1",
        "latestFailedImageVersion": 2,
        "executionRoleArn": EXEC_ROLE,
        "buildRoleArn": "arn:aws:iam::123456789012:role/ai-env-image-build",
        "runtimeUserName": "ai-env-runtime",
        "runtimeUserArn": "arn:aws:iam::123456789012:user/ai-env-runtime",
        "deployPolicyArn": "arn:aws:iam::123456789012:policy/ai-env-deploy",
        "budgetName": "ai-env-monthly",
        "bucket": "ai-env-images-example",
        "zipKey": "ai-env/image-0123456789abcdef.zip",
        "zipSha256": "ab".repeat(32),
        "logGroup": "/aws/lambda-microvms/ai-env-agent",
        "claudeVersion": "2.1.283",
        "shimVersion": "0.1.0",
        "connectorArn": CONNECTOR,
        "connectorName": "ai-env-egress",
        "proxyPrivateIp": PROXY_IP,
        "proxyInstanceId": "i-0123456789abcdef0",
        "egressVpcId": "vpc-0123456789abcdef0",
        "vmSubnetId": "subnet-0aaa1111bbbb2222c",
        "vmEgressSecurityGroupId": "sg-0ddd3333eeee4444f",
        "proxySecurityGroupId": "sg-0fff5555aaaa6666b",
        "operatorRoleArn": "arn:aws:iam::123456789012:role/ai-env-egress-operator",
        "egressLogGroup": "/ai-env/egress/squid",
        "dnsMode": "none",
        "parameterPrefix": "/ai-env/proxy",
        "aLaterStageOutput": "x"
    })
}

/// The S3 program's outputs alone (a stack deployed before S5).
fn s3_outputs(region: &str) -> serde_json::Value {
    let mut v = outputs(region);
    for k in S5_OUTPUTS {
        v.as_object_mut().unwrap().remove(k);
    }
    v
}

/// How long any process of this file may run.
const DEADLINE: Duration = Duration::from_secs(120);

/// `common::run` under [`DEADLINE`] (this shadows it for the whole file): the
/// output is drained on two threads, the child killed when the deadline
/// passes and the test failed naming the command.
fn run(cmd: &mut Command) -> Output {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    };
    let out = drain(Box::new(child.stdout.take().unwrap()));
    let err = drain(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} still running after {DEADLINE:?}: killed");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

fn write_json(t: &Path, name: &str, v: &serde_json::Value) -> PathBuf {
    let p = t.join(name);
    std::fs::write(&p, v.to_string()).unwrap();
    p
}

fn bridge(t: &Path) -> PathBuf {
    t.join("bridge")
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Every entry under `dir` (relative path, mode, file bytes), sorted.
fn tree(dir: &Path) -> Vec<(PathBuf, u32, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(dir).unwrap().to_path_buf();
            if p.is_dir() {
                out.push((rel, mode_of(&p), None));
                stack.push(p);
            } else {
                out.push((rel, mode_of(&p), Some(std::fs::read(&p).unwrap())));
            }
        }
    }
    out.sort();
    out
}

/// A private bridge dir holding `bridge.toml` = `text` (0600).
fn bridge_toml(t: &Path, text: &str) -> PathBuf {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(bridge(t)).unwrap();
    let p = bridge(t).join("bridge.toml");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn backups(t: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(bridge(t)).unwrap().flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().ends_with(".ai-env.bak")).collect()
}

/// `<t>/fakebin/aws`: tests/fakes/aws.sh, installed once per temp dir.
fn fake_bin(t: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = t.join("fakebin");
    let aws = bin.join("aws");
    if !aws.exists() {
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join("aws.sh"), &aws).unwrap();
        std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

/// `ai-env infra status <args>` with the fake aws first on PATH (then
/// /usr/bin:/bin for its tools), so the live reads never reach AWS. The
/// fake holds no image (ResourceNotFoundException) unless a test sets
/// `FAKE_AWS_IMAGE_STATE`, and answers no `get-network-connector` (exit 2,
/// "unsupported command") unless a test sets `FAKE_AWS_ANSWERS` (see
/// [`answers`]); no `FAKE_AWS_*` of the developer's shell leaks in.
fn infra_status(t: &Path, args: &[&str]) -> Command {
    let mut all = vec!["infra", "status"];
    all.extend_from_slice(args);
    let mut cmd = ai_env(t, &all);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", fake_bin(t).display()));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("FAKE_AWS_") {
            cmd.env_remove(&k);
        }
    }
    cmd
}

/// The golden `get-network-connector` answer (ACTIVE), as JSON.
fn golden_connector() -> serde_json::Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("egress").join("lambda-core.get-network-connector.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// A fresh `FAKE_AWS_ANSWERS` directory `<t>/<name>` holding `files`
/// (`(file name, contents)`): the fake serves `<service>.<op>[.<N>].json`
/// (the Nth call), with an optional `.rc` exit code and `.stderr`.
fn answers(t: &Path, name: &str, files: &[(&str, String)]) -> PathBuf {
    let dir = t.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    for (f, text) in files {
        std::fs::write(dir.join(f), text).unwrap();
    }
    dir
}

/// The golden answer with `key` set to `value`.
fn connector_with(key: &str, value: &str) -> String {
    let mut v = golden_connector();
    v[key] = serde_json::json!(value);
    v.to_string()
}

fn status(t: &Path, json: &Path, write: bool) -> std::process::Output {
    let mut args = vec!["--json-in", json.to_str().unwrap()];
    if write {
        args.push("--write");
    }
    run(&mut infra_status(t, &args))
}

const COMMENTED: &str = "# ai-env bridge configuration\n[vm]\nmemory_mib = 4096 # bigger VMs\n\n# AWS: filled by `ai-env infra status --write`\n[aws] # stack outputs land here\n# the region is pinned in code\nregion = \"eu-central-1\" # pinned\ncredentials = \"container\"\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:scratch\" # the scratch image\nimage_version = \"active\"\n\n# wrapper knobs\n[wrapper]\nlocal_fallback = true # keep\n";

#[test]
fn status_without_write_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));

    // No bridge dir at all: the dry run shows the new file and creates nothing.
    let o = status(t, &json, false);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("(will be created)"), "{out}");
    assert!(out.contains(&format!("image_arn: unset -> \"{ARN}\"")), "{out}");
    assert!(out.contains(&format!("egress_connector_arn: unset -> \"{CONNECTOR}\"\n")) && out.contains(&format!("proxy_private_ip: unset -> \"{PROXY_IP}\"\n")), "{out}");
    assert!(out.contains("stack = \"dev\"") && out.contains("latest_failed_image_version = \"2\""), "the state/infra.toml text is shown: {out}");
    assert!(out.contains(&format!("egress connector: {CONNECTOR}, state unknown: the live get-network-connector failed: ")), "the dry run reads it too: {out}");
    assert!(out.trim_end().ends_with("re-run with --write"), "{out}");
    assert!(!bridge(t).exists(), "nothing created");

    // An existing bridge.toml: every file, mode and byte is the same afterwards.
    bridge_toml(t, COMMENTED);
    let before = tree(t);
    let o = status(t, &json, false);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("region: \"eu-central-1\" (unchanged)"), "{out}");
    assert!(out.contains(&format!("image_arn: \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:scratch\" -> \"{ARN}\"")), "{out}");
    assert!(out.contains(&format!("execution_role_arn: unset -> \"{EXEC_ROLE}\"")), "{out}");
    assert!(out.contains(&format!("egress_connector_arn: unset -> \"{CONNECTOR}\"")), "{out}");
    assert_eq!(tree(t), before);
}

#[test]
fn status_write_splices_aws_and_keeps_comments() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
    let path = bridge_toml(t, COMMENTED);

    let o = status(t, &json, true);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let text = std::fs::read_to_string(&path).unwrap();
    let expected = COMMENTED.replace("microvm-image:scratch\"", "microvm-image:ai-env-agent\"").replace(
        "image_version = \"active\"\n",
        &format!("image_version = \"active\"\nexecution_role_arn = \"{EXEC_ROLE}\"\negress_connector_arn = \"{CONNECTOR}\"\nproxy_private_ip = \"{PROXY_IP}\"\nbudget_name = \"ai-env-monthly\"\n"),
    );
    assert_eq!(text, expected, "only [aws] values changed; comments, order and the other tables are intact");
    assert_eq!(mode_of(&path), 0o600, "the mode is kept");

    let baks = backups(t);
    assert_eq!(baks.len(), 1, "{baks:?}");
    assert_eq!(std::fs::read_to_string(&baks[0]).unwrap(), COMMENTED);
    assert!(stdout(&o).contains(&format!("backup: {}", baks[0].display())), "{}", stdout(&o));

    let cfg = BridgeConfig::parse(&text).unwrap();
    assert_eq!(cfg.aws.region.as_deref(), Some("eu-central-1"));
    assert_eq!(cfg.aws.image_arn.as_deref(), Some(ARN));
    assert_eq!(cfg.aws.execution_role_arn.as_deref(), Some(EXEC_ROLE));
    assert_eq!(cfg.aws.budget_name.as_deref(), Some("ai-env-monthly"));
    assert_eq!((cfg.aws.credentials.as_str(), cfg.aws.image_version.as_str()), ("container", "active"), "never touched");
    assert_eq!(cfg.vm.memory_mib, 4096);
    assert_eq!(cfg.aws.egress_connector_arn.as_deref(), Some(CONNECTOR), "connectorArn is the S5 [aws] key");
    assert_eq!(cfg.aws.proxy_private_ip.as_deref(), Some(PROXY_IP), "and proxyPrivateIp");
    cfg.aws.validate_egress().unwrap();

    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    let rows: Vec<serde_json::Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(rows.len(), 1, "{audit}");
    assert_eq!(rows[0]["event"], "infra_status_write");
    assert_eq!(rows[0]["detail"]["keys_changed"], "image_arn,execution_role_arn,egress_connector_arn,proxy_private_ip,budget_name");
    assert_eq!(rows[0]["detail"]["bridge_toml"], "updated");

    // A second run: nothing to change, no second backup, one more audit row.
    let o = status(t, &json, true);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("already up to date"), "{}", stdout(&o));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    assert_eq!(backups(t).len(), 1);
    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    let last: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!((last["detail"]["keys_changed"].as_str(), last["detail"]["bridge_toml"].as_str()), (Some("none"), Some("unchanged")));
}

#[test]
fn status_refuses_a_foreign_region() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    bridge_toml(t, COMMENTED);
    let before = tree(t);
    let json = write_json(t, "west.json", &outputs("eu-west-3"));
    for write in [false, true] {
        let o = status(t, &json, write);
        assert_eq!(o.status.code(), Some(7), "{}{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("\"eu-west-3\" is not eu-central-1"), "{}", stderr(&o));
    }
    // The right region but an image ARN elsewhere.
    let mut v = outputs("eu-central-1");
    v["imageArn"] = serde_json::json!("arn:aws:lambda:eu-west-3:123456789012:microvm-image:ai-env-agent");
    let json = write_json(t, "west-arn.json", &v);
    let o = status(t, &json, true);
    assert_eq!(o.status.code(), Some(7), "{}", stderr(&o));
    assert!(stderr(&o).contains("imageArn"), "{}", stderr(&o));
    // Unparseable outputs are an infra failure too.
    let bad = t.join("bad.json");
    std::fs::write(&bad, "{\"imageArn\": 1").unwrap();
    assert_eq!(status(t, &bad, true).status.code(), Some(7));
    let now = tree(t);
    let written: Vec<_> = now.iter().filter(|(p, _, _)| p.starts_with("bridge")).collect();
    assert_eq!(written, before.iter().filter(|(p, _, _)| p.starts_with("bridge")).collect::<Vec<_>>(), "nothing under the bridge dir changed");
}

#[test]
fn status_refuses_dotted_or_inline_aws_tables() {
    let json_v = outputs("eu-central-1");
    let cases = [
        ("aws.image_arn = \"x\"\n[vm]\nmemory_mib = 4096\n", "dotted key aws.image_arn"),
        ("aws = { region = \"eu-central-1\" }\n", "inline table"),
        ("[[aws]]\nregion = \"eu-central-1\"\n", "[[aws]]"),
        ("[aws.extra]\nx = 1\n", "sub-table"),
        ("[aws]\nregion = \"eu-central-1\"\n\n[vm]\n\n[aws]\nimage_arn = \"x\"\n", "second [aws]"),
    ];
    for (text, needle) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let json = write_json(t, "outputs.json", &json_v);
        let path = bridge_toml(t, text);
        let before = tree(&bridge(t));
        let o = status(t, &json, true);
        assert_eq!(o.status.code(), Some(1), "{text:?}: {}{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains(needle), "{needle}: {}", stderr(&o));
        assert!(stdout(&o).contains(&format!("set these values in {} by hand:\n[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"", path.display())), "the snippet to paste: {}", stdout(&o));
        assert_eq!(tree(&bridge(t)), before, "{needle}: nothing written, no backup, no state");
    }
}

#[test]
fn status_writes_infra_state() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
    let o = run(&mut infra_status(t, &["--json-in", json.to_str().unwrap(), "--stack", "dev", "--write"]));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));

    // bridge.toml did not exist: created with only [aws], 0600, in a 0700 directory.
    let cfg_path = bridge(t).join("bridge.toml");
    assert_eq!(
        std::fs::read_to_string(&cfg_path).unwrap(),
        format!("[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\nexecution_role_arn = \"{EXEC_ROLE}\"\negress_connector_arn = \"{CONNECTOR}\"\nproxy_private_ip = \"{PROXY_IP}\"\nbudget_name = \"ai-env-monthly\"\n")
    );
    assert_eq!(mode_of(&cfg_path), 0o600);
    assert_eq!(mode_of(&bridge(t)), 0o700);
    assert!(backups(t).is_empty(), "nothing to back up");

    let state_path = bridge(t).join("state").join("infra.toml");
    assert_eq!(mode_of(&state_path), 0o600);
    assert_eq!(mode_of(state_path.parent().unwrap()), 0o700);
    let paths = Paths::from_root_and_env(bridge(t), None);
    let s = read_infra_state(&paths).unwrap().expect("state/infra.toml");
    assert_eq!((s.stack.as_str(), s.region.as_str(), s.image_arn.as_str()), ("dev", "eu-central-1", ARN));
    assert!(parse_rfc3339_utc(&s.written).is_some(), "{}", s.written);
    assert_eq!(s.account_id.as_deref(), Some("123456789012"));
    assert_eq!(s.image_state.as_deref(), Some("CREATED"));
    assert_eq!((s.latest_active_image_version.as_deref(), s.latest_failed_image_version.as_deref()), (Some("1"), Some("2")), "a numeric output becomes text");
    // The fake account holds no image: the outputs stand, and the state says so.
    let source = s.image_state_source.as_deref().unwrap();
    assert!(source.starts_with("pulumi outputs (live read failed: An error occurred (ResourceNotFoundException)"), "{source}");
    assert_eq!(s.zip_sha256, Some("ab".repeat(32)));
    assert_eq!((s.claude_version.as_deref(), s.shim_version.as_deref()), (Some("2.1.283"), Some("0.1.0")));
    assert_eq!(s.log_group.as_deref(), Some("/aws/lambda-microvms/ai-env-agent"));
    assert_eq!(s.runtime_user_name.as_deref(), Some("ai-env-runtime"));
    // No connector answer from the fake: the outputs' ARN stands, no Id, no state, and the source says why.
    assert_eq!((s.connector_arn.as_deref(), s.connector_id.as_deref(), s.connector_state.as_deref()), (Some(CONNECTOR), None, None));
    let source = s.connector_state_source.as_deref().unwrap();
    assert!(source.starts_with("pulumi outputs (live read failed: aws lambda-core get-network-connector: fake aws: unsupported command"), "{source}");
    let names: Vec<String> = std::fs::read_dir(state_path.parent().unwrap()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec!["infra.toml"], "no temp file left behind");

    // A later run with fewer outputs rewrites the state (absent outputs drop out) and leaves bridge.toml keys the outputs omit.
    let json = write_json(t, "minimal.json", &serde_json::json!({"region": "eu-central-1", "imageArn": ARN, "imageState": "UPDATED"}));
    let o = run(&mut infra_status(t, &["--json-in", json.to_str().unwrap(), "--stack", "org/ai-env/dev", "--write"]));
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains(&format!("execution_role_arn: \"{EXEC_ROLE}\" (not in the outputs; left alone)")), "{}", stdout(&o));
    assert!(stdout(&o).contains(&format!("egress_connector_arn: \"{CONNECTOR}\" (not in the outputs; left alone)")) && !stdout(&o).contains("egress connector: "), "{}", stdout(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.stack.as_str(), s.image_state.as_deref(), s.claude_version.as_deref()), ("org/ai-env/dev", Some("UPDATED"), None));
    // No connector in the outputs: no live read, but [aws] still names one, so the state says so (and a warning was printed).
    assert_eq!((s.connector_arn.as_deref(), s.connector_state_source.as_deref(), s.proxy_instance_id.as_deref()), (None, Some("not in the stack outputs"), None));
    assert!(stderr(&o).contains("ai-env: warning: the stack exports no egress connector"), "{}", stderr(&o));
    let cfg = BridgeConfig::parse(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    assert_eq!((cfg.aws.execution_role_arn.as_deref(), cfg.aws.egress_connector_arn.as_deref(), cfg.aws.proxy_private_ip.as_deref()), (Some(EXEC_ROLE), Some(CONNECTOR), Some(PROXY_IP)));
}

fn row_text(line: &DoctorLine) -> (Tag, String) {
    match line {
        DoctorLine::Row { tag, text } => (*tag, text.clone()),
        DoctorLine::Plain(text) => panic!("a plain line: {text}"),
    }
}

/// The outputs say CREATED, active 1, failed 2 (what the last successful
/// `pulumi up` saw); the image is now UPDATED with version 3 active and no
/// failure (a later deploy, a rollback): the live read wins, its source is
/// recorded, and doctor shows it. A failed read keeps the outputs and says
/// why. A stack without S5 outputs gets no connector read.
#[test]
fn status_overlays_the_live_image_state() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &s3_outputs("eu-central-1"));
    let log = t.join("aws.log");
    let paths = Paths::from_root_and_env(bridge(t), None);
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_IMAGE_STATE", "UPDATED").env("FAKE_AWS_IMAGE_ACTIVE", "3").env("FAKE_AWS_LOG", &log));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("image state: UPDATED (live get-microvm-image)\n"), "{}", stdout(&o));
    assert_eq!(std::fs::read_to_string(&log).unwrap(), format!("lambda-microvms get-microvm-image --image-identifier {ARN} --region eu-central-1 --output json\n"), "one read-only call, region pinned");
    assert!(stdout(&o).contains("egress_connector_arn: unset (not in the outputs; left alone)\n"), "{}", stdout(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.image_state.as_deref(), s.latest_active_image_version.as_deref(), s.latest_failed_image_version.as_deref()), (Some("UPDATED"), Some("3"), None));
    let source = s.image_state_source.clone().unwrap();
    let at = source.strip_prefix("live ").unwrap_or_else(|| panic!("{source}"));
    assert!(parse_rfc3339_utc(at).is_some(), "{source}");
    assert_eq!(s.claude_version.as_deref(), Some("2.1.283"), "everything else still comes from the outputs");
    let (tag, text) = row_text(&row_infra_state(&Ok(Some(s)), &paths.infra_state()));
    assert_eq!(tag, Tag::Ok, "{text}");
    assert!(text.contains("ai-env-agent UPDATED, active version 3") && text.ends_with(&format!("; image state from live {at}")), "{text}");

    // The session expired: the outputs stand, the source names the failure, the command still succeeds.
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_IMAGE_STATE", "UPDATED").env("FAKE_AWS_FAIL", "1"));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("image state: CREATED from the stack outputs; the live get-microvm-image failed: An error occurred (ExpiredToken)"), "{}", stdout(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.image_state.as_deref(), s.latest_active_image_version.as_deref(), s.latest_failed_image_version.as_deref()), (Some("CREATED"), Some("1"), Some("2")));
    let source = s.image_state_source.clone().unwrap();
    assert!(source.starts_with("pulumi outputs (live read failed: An error occurred (ExpiredToken)") && source.ends_with(')'), "{source}");
    let (_, text) = row_text(&row_infra_state(&Ok(Some(s)), &paths.infra_state()));
    assert!(text.contains("; image state from pulumi outputs (live read failed: "), "{text}");
}

/// S5: the outputs carry `connectorArn` and `proxyPrivateIp`. Both land in
/// `[aws]`; `state/infra.toml` carries every S5 output plus what one live
/// `get-network-connector` (as the operator) answered: the connector PENDING
/// on the first run, ACTIVE on the second (the fake's per-call answers), with
/// its Id and the read's time. Doctor's egress row and the echo gate's Id
/// alias follow. Every aws call carries the region, the connector call its
/// pinned endpoint.
#[test]
fn status_writes_the_egress_keys_and_the_live_connector() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
    let dir = answers(t, "answers", &[("lambda-core.get-network-connector.1.json", connector_with("State", "PENDING")), ("lambda-core.get-network-connector.json", golden_connector().to_string())]);
    let log = t.join("aws.log");
    let paths = Paths::from_root_and_env(bridge(t), None);
    let status_run = || run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_ANSWERS", &dir).env("FAKE_AWS_LOG", &log).env("FAKE_AWS_IMAGE_STATE", "UPDATED"));

    let o = status_run();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains(&format!("egress connector: {CONNECTOR} PENDING (live get-network-connector)\n")), "{}", stdout(&o));
    let cfg = BridgeConfig::parse(&std::fs::read_to_string(bridge(t).join("bridge.toml")).unwrap()).unwrap();
    assert_eq!((cfg.aws.egress_connector_arn.as_deref(), cfg.aws.proxy_private_ip.as_deref()), (Some(CONNECTOR), Some(PROXY_IP)));
    cfg.aws.validate_egress().unwrap();

    let s = read_infra_state(&paths).unwrap().unwrap();
    // Every S5 output, snake_case.
    assert_eq!((s.connector_arn.as_deref(), s.connector_name.as_deref(), s.proxy_private_ip.as_deref(), s.proxy_instance_id.as_deref()), (Some(CONNECTOR), Some("ai-env-egress"), Some(PROXY_IP), Some("i-0123456789abcdef0")));
    assert_eq!((s.egress_vpc_id.as_deref(), s.vm_subnet_id.as_deref()), (Some("vpc-0123456789abcdef0"), Some("subnet-0aaa1111bbbb2222c")));
    assert_eq!((s.vm_egress_security_group_id.as_deref(), s.proxy_security_group_id.as_deref()), (Some("sg-0ddd3333eeee4444f"), Some("sg-0fff5555aaaa6666b")));
    assert_eq!(s.operator_role_arn.as_deref(), Some("arn:aws:iam::123456789012:role/ai-env-egress-operator"));
    assert_eq!((s.egress_log_group.as_deref(), s.dns_mode.as_deref(), s.parameter_prefix.as_deref()), (Some("/ai-env/egress/squid"), Some("none"), Some("/ai-env/proxy")));
    // The live read: the golden Id, the first answer's state, a `live <time>` source.
    assert_eq!((s.connector_id.as_deref(), s.connector_state.as_deref()), (Some("nc-0a1b2c3d4e5f60718"), Some("PENDING")));
    let source = s.connector_state_source.clone().unwrap();
    assert!(source.strip_prefix("live ").is_some_and(|at| parse_rfc3339_utc(at).is_some()), "{source}");
    let (tag, text) = row_text(&row_egress(&cfg.egress, &cfg.aws, &Ok(Some(s.clone()))));
    assert!(tag == Tag::Warn && text.contains("ai-env-egress is PENDING (state from live ") && text.contains("needs it ACTIVE"), "{text}");
    let raw = std::fs::read_to_string(paths.infra_state()).unwrap();
    for k in ["connector_arn", "connector_name", "proxy_private_ip", "proxy_instance_id", "egress_vpc_id", "vm_subnet_id", "vm_egress_security_group_id", "proxy_security_group_id", "operator_role_arn", "egress_log_group", "dns_mode", "parameter_prefix", "connector_id", "connector_state", "connector_state_source"] {
        assert!(raw.contains(&format!("\n{k} = ")), "{k} in state/infra.toml: {raw}");
    }

    // The second run: ACTIVE; doctor says so, and the echo gate may accept the Id form.
    let o = status_run();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains(&format!("egress connector: {CONNECTOR} ACTIVE (live get-network-connector)\n")), "{}", stdout(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!(s.connector_state.as_deref(), Some("ACTIVE"));
    let (tag, text) = row_text(&row_egress(&cfg.egress, &cfg.aws, &Ok(Some(s.clone()))));
    assert!(tag == Tag::Ok && text.starts_with(&format!("egress connector {CONNECTOR} ACTIVE (id nc-0a1b2c3d4e5f60718; state from live ")), "{text}");
    assert_eq!(ConnectorAlias::from_state(&s, CONNECTOR).map(|a| a.id), Some("nc-0a1b2c3d4e5f60718".to_string()));

    // Two runs, two calls each: the image read, then the pinned connector read.
    let calls = std::fs::read_to_string(&log).unwrap();
    let image_call = format!("lambda-microvms get-microvm-image --image-identifier {ARN} --region eu-central-1 --output json");
    assert_eq!(calls.lines().collect::<Vec<_>>(), [image_call.as_str(), CONNECTOR_CALL, image_call.as_str(), CONNECTOR_CALL], "{calls}");
    assert!(calls.lines().all(|l| l.contains(" --region eu-central-1 ")), "{calls}");
    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    let last: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(last["detail"]["keys_changed"], "none", "the second run changes no key: {audit}");
}

/// A `connectorArn` that is not a customer connector of the stack's account
/// in eu-central-1 (the managed INTERNET_EGRESS one, another region, a name,
/// another account) and a `proxyPrivateIp` outside RFC 1918 are refused like
/// a foreign region: exit 7, before any aws call, nothing written, dry run
/// or not.
#[test]
fn status_refuses_a_foreign_or_managed_connector_and_a_public_proxy_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    bridge_toml(t, COMMENTED);
    let before = tree(&bridge(t));
    let log = t.join("aws.log");
    let managed = internet_egress_arn();
    let foreign = "arn:aws:lambda:eu-central-1:999999999999:network-connector:ai-env-egress";
    let cases = [
        ("connectorArn", managed.as_str(), "is not "),
        ("connectorArn", "arn:aws:lambda:eu-west-3:123456789012:network-connector:ai-env-egress", "is not "),
        ("connectorArn", "ai-env-egress", "is not "),
        ("connectorArn", foreign, "is in account 999999999999, but the stack's imageArn is in account 123456789012"),
        ("proxyPrivateIp", "8.8.8.8", "is not "),
        ("proxyPrivateIp", "100.64.0.10", "is not "),
    ];
    for (i, (key, bad, why)) in cases.into_iter().enumerate() {
        let mut v = outputs("eu-central-1");
        v[key] = serde_json::json!(bad);
        let json = write_json(t, &format!("bad-{i}.json"), &v);
        for write in [false, true] {
            let mut args = vec!["--json-in", json.to_str().unwrap()];
            if write {
                args.push("--write");
            }
            let o = run(infra_status(t, &args).env("FAKE_AWS_LOG", &log).env("FAKE_AWS_IMAGE_STATE", "UPDATED"));
            assert_eq!(o.status.code(), Some(7), "{key} {bad} (write {write}): {}{}", stdout(&o), stderr(&o));
            assert!(stderr(&o).contains(&format!("stack output {key} {bad:?} {why}")) && stderr(&o).trim_end().ends_with("; nothing written"), "{}", stderr(&o));
            assert_eq!(stdout(&o), "", "{key} {bad}: nothing shown either");
        }
    }
    // The stack's accountId binds too (here the image is in the connector's account, the stack says otherwise).
    let mut v = outputs("eu-central-1");
    v["connectorArn"] = serde_json::json!(foreign);
    v["imageArn"] = serde_json::json!("arn:aws:lambda:eu-central-1:999999999999:microvm-image:ai-env-agent");
    let json = write_json(t, "bad-account-id.json", &v);
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_LOG", &log));
    assert_eq!(o.status.code(), Some(7), "{}{}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("is in account 999999999999, but the stack's accountId is in account 123456789012; nothing written"), "{}", stderr(&o));
    assert!(!log.exists(), "no aws call");
    assert_eq!(tree(&bridge(t)), before, "nothing under the bridge dir changed");
}

/// The live connector read fails (the fake answers exit 254 with the CLI's
/// error), or answers about another connector: the write still happens with
/// the outputs' ARN, no Id and no state, and the recorded source names the
/// failure; doctor's egress row says the state is unknown and why.
#[test]
fn status_writes_even_when_the_connector_read_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
    let paths = Paths::from_root_and_env(bridge(t), None);
    let log = t.join("aws.log");
    let denied = "An error occurred (ResourceNotFoundException) when calling the GetNetworkConnector operation: Network connector ai-env-egress not found";
    let dir = answers(t, "answers", &[("lambda-core.get-network-connector.rc", "254\n".into()), ("lambda-core.get-network-connector.stderr", format!("\n{denied}\n"))]);
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_ANSWERS", &dir).env("FAKE_AWS_LOG", &log));
    assert!(o.status.success(), "a failed read never blocks the write: {}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains(&format!("egress connector: {CONNECTOR}, state unknown: the live get-network-connector failed: aws lambda-core get-network-connector: {denied}\n")), "{}", stdout(&o));
    let cfg = BridgeConfig::parse(&std::fs::read_to_string(bridge(t).join("bridge.toml")).unwrap()).unwrap();
    assert_eq!((cfg.aws.egress_connector_arn.as_deref(), cfg.aws.proxy_private_ip.as_deref()), (Some(CONNECTOR), Some(PROXY_IP)));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.connector_arn.as_deref(), s.connector_id.as_deref(), s.connector_state.as_deref()), (Some(CONNECTOR), None, None));
    assert_eq!(s.connector_state_source.as_deref(), Some(format!("pulumi outputs (live read failed: aws lambda-core get-network-connector: {denied})").as_str()));
    assert_eq!(s.proxy_instance_id.as_deref(), Some("i-0123456789abcdef0"), "the outputs are all there");
    let (tag, text) = row_text(&row_egress(&cfg.egress, &cfg.aws, &Ok(Some(s.clone()))));
    assert!(tag == Tag::Skip && text.contains(&format!(": no state recorded (state/infra.toml: pulumi outputs (live read failed: aws lambda-core get-network-connector: {denied}))")) && text.ends_with("<- make infra-status WRITE=1"), "{text}");
    assert!(ConnectorAlias::from_state(&s, CONNECTOR).is_none(), "no Id, no alias");
    assert!(std::fs::read_to_string(&log).unwrap().lines().any(|l| l == CONNECTOR_CALL), "the pinned call was made");

    // An answer about another connector is no answer: its Id is never recorded.
    let other = "arn:aws:lambda:eu-central-1:123456789012:network-connector:someone-else";
    let dir = answers(t, "answers-other", &[("lambda-core.get-network-connector.json", connector_with("Arn", other))]);
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_ANSWERS", &dir));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.connector_arn.as_deref(), s.connector_id.as_deref(), s.connector_state.as_deref()), (Some(CONNECTOR), None, None));
    assert_eq!(s.connector_state_source.as_deref(), Some(format!("pulumi outputs (live read failed: get-network-connector answered for {other:?}, not {CONNECTOR})").as_str()));

    // An Id the echo gate would drop (a managed connector's name) is not recorded (the source says why); the state still is.
    let dir = answers(t, "answers-id", &[("lambda-core.get-network-connector.json", connector_with("Id", "INTERNET_EGRESS"))]);
    let o = run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("FAKE_AWS_ANSWERS", &dir));
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(stdout(&o).contains("is not usable as an alias: Id-form echoes will be refused\n"), "{}", stdout(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.connector_id.as_deref(), s.connector_state.as_deref()), (None, Some("ACTIVE")));
    assert!(s.connector_state_source.as_deref().is_some_and(|src| src.starts_with("live ") && src.ends_with(" (Id not recorded: get-network-connector answered with the Id \"INTERNET_EGRESS\", which is not usable as an alias: Id-form echoes will be refused)")), "{s:?}");
    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    assert_eq!(audit.lines().count(), 3, "every run wrote and audited: {audit}");
}

/// The stack exports no connector (no S5, or its egress destroyed), but
/// `[aws]` still names one: the keys are left as they are, with a warning;
/// the state records it, so doctor's egress row names the stale key (a
/// `[!! ]` infra-status records, not a skip it can never clear).
#[test]
fn status_warns_when_bridge_toml_names_a_connector_the_stack_does_not_export() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let paths = Paths::from_root_and_env(bridge(t), None);
    let text = format!("[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\negress_connector_arn = \"{CONNECTOR}\" # from S5\nproxy_private_ip = \"{PROXY_IP}\"\n");
    let path = bridge_toml(t, &text);
    let json = write_json(t, "s3.json", &s3_outputs("eu-central-1"));
    let log = t.join("aws.log");
    let warning = "ai-env: warning: the stack exports no egress connector; [aws].egress_connector_arn (and proxy_private_ip) are left as they are: remove them by hand if the stack really has none\n";
    for write in [false, true] {
        let mut args = vec!["--json-in", json.to_str().unwrap()];
        if write {
            args.push("--write");
        }
        let o = run(infra_status(t, &args).env("FAKE_AWS_LOG", &log));
        assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
        assert_eq!(stderr(&o), warning, "write {write}");
        assert!(stdout(&o).contains(&format!("egress_connector_arn: \"{CONNECTOR}\" (not in the outputs; left alone)")) && stdout(&o).contains("connector_state_source = \"not in the stack outputs\""), "{}", stdout(&o));
    }
    assert!(std::fs::read_to_string(&path).unwrap().contains(&format!("egress_connector_arn = \"{CONNECTOR}\" # from S5\nproxy_private_ip = \"{PROXY_IP}\"\n")), "left as it was");
    assert!(!std::fs::read_to_string(&log).unwrap().contains("lambda-core"), "no connector to read");
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!((s.connector_arn.as_deref(), s.connector_state.as_deref(), s.connector_state_source.as_deref()), (None, None, Some("not in the stack outputs")));
    let cfg = BridgeConfig::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let (tag, text) = row_text(&row_egress(&cfg.egress, &cfg.aws, &Ok(Some(s))));
    assert_eq!(tag, Tag::Warn, "{text}");
    assert!(text.ends_with(": the stack exports no connector: remove [aws].egress_connector_arn (and proxy_private_ip) from bridge.toml"), "{text}");

    // Removed by hand: no warning, nothing recorded, and doctor's row is the plain unset one.
    let path = bridge_toml(t, &format!("[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\negress_connector_arn = \"\"\n"));
    let o = run(&mut infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]));
    assert!(o.status.success() && stderr(&o).is_empty(), "{}{}", stdout(&o), stderr(&o));
    let s = read_infra_state(&paths).unwrap().unwrap();
    assert_eq!(s.connector_state_source, None);
    let cfg = BridgeConfig::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(row_text(&row_egress(&cfg.egress, &cfg.aws, &Ok(Some(s)))).1.starts_with("[aws].egress_connector_arn unset, but [egress].require = true"));
}

/// A stack that was inited but never deployed prints `{}`: the refusal says
/// what to run (not serde's `missing field`), exit 7, and nothing is written.
#[test]
fn status_on_a_stack_without_outputs_says_to_deploy_first() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let empty = t.join("empty.json");
    std::fs::write(&empty, "{}\n").unwrap();
    let partial = write_json(t, "partial.json", &serde_json::json!({"region": "eu-central-1"}));
    let log = t.join("aws.log");
    for write in [false, true] {
        let mut args = vec!["--json-in", empty.to_str().unwrap(), "--stack", "dev"];
        if write {
            args.push("--write");
        }
        let o = run(infra_status(t, &args).env("FAKE_AWS_LOG", &log));
        assert_eq!(o.status.code(), Some(7), "{}{}", stdout(&o), stderr(&o));
        assert_eq!(stderr(&o), "ai-env: stack dev: the stack has no outputs yet: run make deploy first, then make infra-status; nothing written\n");
        assert_eq!(stdout(&o), "");
    }
    let o = run(&mut infra_status(t, &["--json-in", partial.to_str().unwrap(), "--write"]));
    assert_eq!(o.status.code(), Some(7), "{}", stderr(&o));
    assert!(stderr(&o).contains("no imageArn") && stderr(&o).contains("run make deploy first"), "{}", stderr(&o));
    assert!(!bridge(t).exists(), "nothing written");
    assert!(!log.exists(), "no aws call either");
}

#[test]
fn status_write_never_narrows_a_config_directory_outside_the_bridge_root() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
    let with_config = |cfg: &Path| run(infra_status(t, &["--json-in", json.to_str().unwrap(), "--write"]).env("AI_ENV_BRIDGE_CONFIG", cfg));

    // AI_ENV_BRIDGE_CONFIG=$HOME/bridge.toml, HOME 0755: HOME keeps its mode.
    std::fs::set_permissions(t, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = t.join("bridge.toml");
    let o = with_config(&cfg);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(mode_of(t), 0o755, "the operator's directory is never chmod'ed");
    assert_eq!(mode_of(&cfg), 0o600);
    assert_eq!(BridgeConfig::parse(&std::fs::read_to_string(&cfg).unwrap()).unwrap().aws.image_arn.as_deref(), Some(ARN));
    // The bridge root (state, audit) is still the bridge's own and private.
    assert_eq!(mode_of(&bridge(t)), 0o700);
    assert!(bridge(t).join("state").join("infra.toml").is_file());
    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    let row: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(row["detail"]["bridge_toml"], "created");

    // A missing operator directory is created 0700 with its parents, the rest left alone.
    let nested = t.join("etc").join("ai-env").join("bridge.toml");
    let o = with_config(&nested);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!((mode_of(&t.join("etc")), mode_of(nested.parent().unwrap()), mode_of(&nested)), (0o700, 0o700, 0o600));
    assert_eq!(mode_of(t), 0o755);

    // The bridge root itself, when wider, is narrowed as before.
    std::fs::set_permissions(bridge(t), std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = status(t, &json, true);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!((mode_of(&bridge(t)), mode_of(&bridge(t).join("bridge.toml"))), (0o700, 0o600));
}

#[test]
fn status_write_checks_the_state_dir_and_audit_file_before_editing_bridge_toml() {
    for breakage in ["state is a file", "audit.jsonl is a symlink"] {
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        let json = write_json(t, "outputs.json", &outputs("eu-central-1"));
        let path = bridge_toml(t, COMMENTED);
        let elsewhere = t.join("elsewhere.jsonl");
        std::fs::write(&elsewhere, "").unwrap();
        if breakage == "state is a file" {
            std::fs::write(bridge(t).join("state"), "not a directory").unwrap();
        } else {
            std::os::unix::fs::symlink(&elsewhere, bridge(t).join("audit.jsonl")).unwrap();
        }
        let o = status(t, &json, true);
        assert_eq!(o.status.code(), Some(1), "{breakage}: {}{}", stdout(&o), stderr(&o));
        let err = stderr(&o);
        let needle = if breakage == "state is a file" { format!("{} is not a directory", bridge(t).join("state").display()) } else { format!("cannot open {}", bridge(t).join("audit.jsonl").display()) };
        assert!(err.contains(&needle), "{breakage}: {err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), COMMENTED, "{breakage}: bridge.toml untouched");
        assert!(backups(t).is_empty(), "{breakage}: no backup");
        assert!(!bridge(t).join("state").join("infra.toml").exists(), "{breakage}: no state written");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "", "{breakage}: the symlink is not followed");
        assert!(!stdout(&o).contains("wrote:"), "{breakage}: {}", stdout(&o));
    }
}

#[test]
fn status_write_never_clobbers_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let path = bridge_toml(t, COMMENTED);
    let first = write_json(t, "first.json", &outputs("eu-central-1"));
    let mut v = outputs("eu-central-1");
    v["budgetName"] = serde_json::json!("ai-env-monthly-2");
    let second = write_json(t, "second.json", &v);
    // Squat the plain backup names of the next few seconds, so both runs take
    // the same-second path and must pick numbered names.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let squatters: Vec<PathBuf> = (0..5).map(|k| bridge(t).join(format!("bridge.toml.{}.ai-env.bak", now + k))).collect();
    for s in &squatters {
        std::fs::write(s, "squatter").unwrap();
    }
    let o = status(t, &first, true);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let after_first = std::fs::read_to_string(&path).unwrap();
    let o = status(t, &second, true);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert!(std::fs::read_to_string(&path).unwrap().contains("budget_name = \"ai-env-monthly-2\""));
    let mut baks: Vec<(PathBuf, String)> = backups(t).into_iter().filter(|p| !squatters.contains(p)).map(|p| (p.clone(), std::fs::read_to_string(&p).unwrap())).collect();
    baks.sort_by_key(|(_, text)| text.len());
    assert_eq!(baks.iter().map(|(_, text)| text.as_str()).collect::<Vec<_>>(), vec![COMMENTED, after_first.as_str()], "{baks:?}");
    for s in &squatters {
        assert_eq!(std::fs::read_to_string(s).unwrap(), "squatter");
    }
    let audit = std::fs::read_to_string(bridge(t).join("audit.jsonl")).unwrap();
    assert_eq!(audit.lines().count(), 2, "{audit}");
}

fn managed(version_1_status: &str) -> serde_json::Value {
    serde_json::json!({"items": [
        {"imageArn": BASE_ARN, "imageVersion": "1", "status": version_1_status, "createdAt": "2026-07-31T19:21:07.059000+03:00", "updatedAt": "2026-07-31T19:24:07.527000+03:00"},
        {"imageArn": BASE_ARN, "imageVersion": "0", "status": "AVAILABLE", "createdAt": "2026-06-29T20:11:01.714000+03:00"}
    ]})
}

#[test]
fn base_image_available_passes_others_fail() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let base = |json: &Path, version: &str| run(&mut ai_env(t, &["infra", "base-image", "--version", version, "--json-in", json.to_str().unwrap()]));
    let ok = write_json(t, "available.json", &managed("AVAILABLE"));
    let o = base(&ok, "1");
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o).trim(), format!("base image {BASE_ARN} version 1: AVAILABLE"));
    for status in ["DEPRECATED", "EXPIRING", "EXPIRED", "RECALLED", "UNHEARD_OF"] {
        let json = write_json(t, &format!("{status}.json"), &managed(status));
        let o = base(&json, "1");
        assert_eq!(o.status.code(), Some(1), "{status}");
        assert!(stderr(&o).contains(&format!("version 1 is {status}")), "{status}: {}", stderr(&o));
    }
    let o = base(&ok, "7");
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("version 7 not listed"), "{}", stderr(&o));
    let o = run(&mut ai_env(t, &["infra", "base-image", "--name", "al2023-1 --x", "--json-in", ok.to_str().unwrap()]));
    assert_eq!(o.status.code(), Some(2), "a name that is not an image name is a usage error: {}", stderr(&o));
}

fn versions(rows: &[(&str, &str, &str)]) -> serde_json::Value {
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|(v, state, status)| serde_json::json!({"imageArn": ARN, "imageVersion": v, "state": state, "status": status, "baseImageArn": BASE_ARN, "baseImageVersion": "1", "createdAt": "2026-09-29T10:00:00.000000+00:00"}))
        .collect();
    serde_json::json!({"items": items})
}

fn probe_rows(t: &Path) -> Vec<ProbeRow> {
    let text = std::fs::read_to_string(bridge(t).join("lab").join("probes.jsonl")).unwrap_or_default();
    text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn versions_diff_records_the_probe() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let diff = |before: &Path, after: &Path, record: bool| {
        let mut args = vec!["infra", "versions-diff", "--before", before.to_str().unwrap(), "--after", after.to_str().unwrap()];
        if record {
            args.push("--record-probe");
        }
        run(&mut ai_env(t, &args))
    };
    // The image's claude version stamps the row when state/infra.toml has it.
    std::fs::create_dir_all(bridge(t).join("state")).unwrap();
    std::fs::write(bridge(t).join("state").join("infra.toml"), format!("stack = \"dev\"\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\nclaude_version = \"2.1.283\"\n")).unwrap();

    // An update: version 2 added, version 1 kept (now inactive).
    let before = write_json(t, "before.json", &versions(&[("1", "SUCCESSFUL", "ACTIVE")]));
    let after = write_json(t, "after.json", &versions(&[("1", "SUCCESSFUL", "INACTIVE"), ("2", "SUCCESSFUL", "ACTIVE")]));
    let o = diff(&before, &after, true);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("added:     2 (state SUCCESSFUL, status ACTIVE)"), "{out}");
    assert!(out.contains("changed:   1 (state SUCCESSFUL, status ACTIVE) -> 1 (state SUCCESSFUL, status INACTIVE)"), "{out}");
    assert!(out.contains("probe image-version-delete: kept"), "{out}");
    let rows = probe_rows(t);
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].probe.as_str(), rows[0].stage.as_str(), rows[0].verdict.as_str(), rows[0].expected.as_str()), ("image-version-delete", "S3", "kept", "kept"));
    assert_eq!((rows[0].ext.as_deref(), rows[0].sdk.as_deref()), (Some("2.1.283"), None));
    assert!(parse_rfc3339_utc(&rows[0].ts).is_some());
    assert_eq!(mode_of(&bridge(t).join("lab").join("probes.jsonl")), 0o600);

    // Without --record-probe nothing is written, even for a deletion.
    let gone = write_json(t, "gone.json", &versions(&[("2", "SUCCESSFUL", "ACTIVE"), ("3", "FAILED", "INACTIVE")]));
    let o = diff(&after, &gone, false);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("removed:   1 (state SUCCESSFUL, status INACTIVE)") && stdout(&o).contains("probe image-version-delete: deleted:1"), "{}", stdout(&o));
    assert_eq!(probe_rows(t).len(), 1);

    // Recorded, a deletion is written first and then fails the command.
    let o = diff(&after, &gone, true);
    assert_eq!(o.status.code(), Some(1), "{}", stdout(&o));
    assert!(stdout(&o).contains("probe image-version-delete: kept -> deleted:1"), "{}", stdout(&o));
    assert!(stderr(&o).contains("differs from the expectation kept"), "{}", stderr(&o));
    let rows = probe_rows(t);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].verdict, "deleted:1");

    // Before the first deploy the snapshot is empty (or `{}`): everything is added, nothing deleted.
    let empty = t.join("empty.json");
    std::fs::write(&empty, "").unwrap();
    let o = diff(&empty, &after, false);
    assert!(o.status.success() && stdout(&o).contains("probe image-version-delete: kept"), "{}", stdout(&o));
    let o = diff(&t.join("missing.json"), &after, false);
    assert_eq!(o.status.code(), Some(1), "a missing snapshot file is an error");
}

fn versions_diff_cmd(t: &Path, before: &str, after: &str, record: bool) -> std::process::Output {
    let mut args = vec!["infra", "versions-diff", "--before", before, "--after", after];
    if record {
        args.push("--record-probe");
    }
    run(&mut ai_env(t, &args))
}

#[test]
fn versions_diff_counts_a_version_being_deleted_as_deleted() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let before = write_json(t, "before.json", &versions(&[("1", "SUCCESSFUL", "ACTIVE"), ("2", "FAILED", "INACTIVE")]));
    for (i, state) in ["DELETING", "DELETED", "DELETE_FAILED"].into_iter().enumerate() {
        // Still listed, but its delete was requested during the deploy.
        let after = write_json(t, &format!("after-{state}.json"), &versions(&[("1", state, "INACTIVE"), ("2", "FAILED", "INACTIVE"), ("3", "SUCCESSFUL", "ACTIVE")]));
        let o = versions_diff_cmd(t, before.to_str().unwrap(), after.to_str().unwrap(), true);
        assert_eq!(o.status.code(), Some(1), "{state}: {}{}", stdout(&o), stderr(&o));
        assert!(stdout(&o).contains("removed:   none") && stdout(&o).contains(&format!("changed:   1 (state SUCCESSFUL, status ACTIVE) -> 1 (state {state}, status INACTIVE)")), "{state}: {}", stdout(&o));
        assert!(stderr(&o).contains("image-version-delete=deleted:1 differs from the expectation kept"), "{state}: {}", stderr(&o));
        let rows = probe_rows(t);
        assert_eq!(rows.len(), i + 1, "{state}");
        assert_eq!(rows[i].verdict, "deleted:1", "{state}");
    }
}

#[test]
fn versions_diff_refuses_a_vacuous_probe_and_stdin_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let after = write_json(t, "after.json", &versions(&[("1", "SUCCESSFUL", "ACTIVE")]));
    let empty = t.join("empty.json");
    std::fs::write(&empty, "").unwrap();
    let braces = t.join("braces.json");
    std::fs::write(&braces, "{}").unwrap();
    let only_deleted = write_json(t, "only-deleted.json", &versions(&[("7", "DELETED", "INACTIVE")]));

    // --record-probe on an empty (or failed, or all-deleted) before snapshot: exit 1, nothing appended.
    for before in [&empty, &braces, &only_deleted] {
        let o = versions_diff_cmd(t, before.to_str().unwrap(), after.to_str().unwrap(), true);
        assert_eq!(o.status.code(), Some(1), "{}: {}{}", before.display(), stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("lists no image version") && stderr(&o).contains("vacuous") && stderr(&o).contains(&before.display().to_string()), "{}", stderr(&o));
        assert!(!stdout(&o).contains("probe image-version-delete"), "no verdict printed: {}", stdout(&o));
        assert!(!bridge(t).join("lab").join("probes.jsonl").exists(), "nothing appended");
    }
    // The plain diff still accepts them (the first deploy), and says the verdict is vacuous.
    for before in [&empty, &braces] {
        let o = versions_diff_cmd(t, before.to_str().unwrap(), after.to_str().unwrap(), false);
        assert!(o.status.success(), "{}", stderr(&o));
        assert!(stdout(&o).contains("added:     1 (state SUCCESSFUL, status ACTIVE)") && stdout(&o).contains("probe image-version-delete: kept (vacuous: no earlier version)"), "{}", stdout(&o));
    }

    // `-` for both would read stdin twice: a usage error before anything is read.
    for record in [false, true] {
        let o = versions_diff_cmd(t, "-", "-", record);
        assert_eq!(o.status.code(), Some(2), "{}{}", stdout(&o), stderr(&o));
        assert!(stderr(&o).contains("--before and --after cannot both be -"), "{}", stderr(&o));
    }
    assert!(!bridge(t).join("lab").join("probes.jsonl").exists());
    // One `-` is fine.
    let mut child = ai_env(t, &["infra", "versions-diff", "--before", "-", "--after", after.to_str().unwrap(), "--record-probe"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(versions(&[("1", "SUCCESSFUL", "ACTIVE")]).to_string().as_bytes()).unwrap();
    }
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(probe_rows(t).iter().map(|r| r.verdict.as_str()).collect::<Vec<_>>(), vec!["kept"]);
}

/// A set-but-empty AI_ENV_BRIDGE_DIR counts as unset (as the Makefile's
/// `${AI_ENV_BRIDGE_DIR:-…}` reads it): the state goes under HOME, never
/// under the working directory.
#[test]
fn an_empty_bridge_dir_counts_as_unset() {
    let t = tempfile::tempdir().unwrap();
    let cwd = t.path().join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    let o = run(ai_env(t.path(), &["wrapper", "census"]).env("AI_ENV_BRIDGE_DIR", "").env("AI_ENV_BRIDGE_CONFIG", "").current_dir(&cwd));
    assert!(o.status.success(), "{}", stderr(&o));
    let want = t.path().join(".config/ai-env/bridge/logs/census.jsonl");
    assert_eq!(stdout(&o).trim(), format!("no census yet at {}", want.display()));
}
