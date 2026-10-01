//! `ai-env egress …` and `ai-env proxy …` as processes (plan S5, W5) over the
//! fake aws CLI (tests/fakes/aws.sh, first on a pinned PATH): every call
//! pinned to eu-central-1 and its endpoint, the operator-account check, the
//! allowlist grammar and the 4 KB cap, drift in `egress status`.
//!
//! Each test gets a [`World`] (its own bridge root) with `[aws]
//! egress_connector_arn` and a `state/infra.toml` of S5 ids, a temp bin with
//! the fake as `aws` (`PATH=<bin>:/usr/bin:/bin`, `FAKE_AWS_PIN_ALL=1`), a
//! `FAKE_AWS_ANSWERS` directory seeded from tests/fixtures/egress (the golden
//! connector) and tests/fixtures/egress/ops (a stack without drift, in the
//! CLI's answer shapes), and a `FAKE_AWS_SSM_DIR` holding the four proxy
//! parameters (version 1 each). The `get-command-invocation` answers are
//! written per test: the `--status` hashes are computed from the parameters
//! at run time. Every run is bounded and asserts, over `FAKE_AWS_LOG`, that
//! each call carried `--region eu-central-1` and its service's pinned
//! `--endpoint-url`.
use super::cli::{code, stderr, stdout, World};
use crate::common::CONNECTOR;
use ai_env_cli::bridge::awscli::endpoint;
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::egress::{param_name, value_sha256, EXTRAS_HEADER, PARAMS, SUSPENDED_HEADER};
use ai_env_cli::bridge::infra::InfraState;
use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow};
use serde_json::{json, Value};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const INSTANCE: &str = "i-0123456789abcdef0";
const VPC: &str = "vpc-0123456789abcdef0";
const VM_SUBNET: &str = "subnet-0aaa1111bbbb2222c";
const VM_SG: &str = "sg-0ddd3333eeee4444f";
const PROXY_SG: &str = "sg-0fff5555aaaa6666b";
const STILL_ALLOWED: &str = "STILL ALLOWED on the proxy; `make proxy-stop` to fail closed";
const STATE_UNKNOWN: &str = "the proxy's state is unknown: `make proxy-stop` to fail closed";
const SQUID_CONF: &str = "http_port 10.42.0.10:3128\n";
const ALLOW: &str = "api.anthropic.com\nplatform.claude.com\nindex.crates.io\nstatic.crates.io\n";
/// What a reload sends (its `--status` is a command of its own).
const RELOAD_SCRIPT: &str = r#""commands":["/usr/local/sbin/ai-env-proxy-reload"],"executionTimeout":["1500"]"#;
const STATUS_SCRIPT: &str = r#""commands":["/usr/local/sbin/ai-env-proxy-reload --status"],"executionTimeout":["400"]"#;
const APPLIED: &str = "ai-env-proxy-reload: applied (reconfigured): allowed=4 extras=0 suspended=0\n";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("egress")
}

/// Run `c` with a 60 s bound (killed and failed past it), stdout piped.
fn bounded(c: Command) -> Output {
    bounded_with(c, Stdio::piped())
}

/// A stdout whose reader is gone before the child starts (`… | head -0`): every write fails with EPIPE.
fn closed_stdout() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    Stdio::from(writer)
}

fn bounded_with(mut c: Command, stdout: Stdio) -> Output {
    let what = format!("{c:?}");
    let mut child = c.stdin(Stdio::null()).stdout(stdout).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{what}: {e}"));
    let (so, mut se) = (child.stdout.take(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(mut so) = so {
            let _ = so.read_to_end(&mut b);
        }
        b
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait().unwrap() {
            Some(status) => return Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() },
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what}: no exit within 60 s");
            }
        }
    }
}

/// One operator's world: the bridge root, the fake aws, its answers and Parameter Store.
struct Eg {
    w: World,
    path: String,
    log: PathBuf,
    answers: PathBuf,
    ssm: PathBuf,
}

impl Eg {
    fn new() -> Eg {
        use std::os::unix::fs::PermissionsExt as _;
        let w = World::new("");
        let toml = fs::read_to_string(w.bridge().join("bridge.toml")).unwrap();
        fs::write(w.bridge().join("bridge.toml"), toml.replacen("[aws]\n", &format!("[aws]\negress_connector_arn = \"{CONNECTOR}\"\n"), 1)).unwrap();
        let bin = w.root().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/aws.sh"), bin.join("aws")).unwrap();
        fs::set_permissions(bin.join("aws"), fs::Permissions::from_mode(0o755)).unwrap();
        let answers = w.root().join("answers");
        fs::create_dir_all(&answers).unwrap();
        fs::copy(fixtures().join("lambda-core.get-network-connector.json"), answers.join("lambda-core.get-network-connector.json")).unwrap();
        for e in fs::read_dir(fixtures().join("ops")).unwrap().flatten() {
            fs::copy(e.path(), answers.join(e.file_name())).unwrap();
        }
        let eg = Eg { path: format!("{}:/usr/bin:/bin", bin.display()), log: w.root().join("aws.log"), ssm: w.root().join("ssm"), answers, w };
        for (p, v) in [("squid.conf", SQUID_CONF), ("allow", ALLOW), ("extras", EXTRAS_HEADER), ("suspended", SUSPENDED_HEADER)] {
            eg.set_param(p, v);
        }
        eg.write_state(|_| {});
        eg.reload_answer(0, "", APPLIED);
        eg
    }

    /// `state/infra.toml` as `make infra-status WRITE=1` writes it for the stack, changed by `f`.
    fn write_state(&self, f: impl FnOnce(&mut InfraState)) {
        let mut s = InfraState {
            stack: "dev".into(),
            written: "2026-10-01T10:00:00Z".into(),
            region: "eu-central-1".into(),
            image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(),
            connector_arn: Some(CONNECTOR.into()),
            connector_name: Some("ai-env-egress".into()),
            proxy_private_ip: Some("10.42.0.10".into()),
            proxy_instance_id: Some(INSTANCE.into()),
            egress_vpc_id: Some(VPC.into()),
            vm_subnet_id: Some(VM_SUBNET.into()),
            vm_egress_security_group_id: Some(VM_SG.into()),
            proxy_security_group_id: Some(PROXY_SG.into()),
            dns_mode: Some("none".into()),
            parameter_prefix: Some("/ai-env/proxy".into()),
            connector_id: Some("nc-0a1b2c3d4e5f60718".into()),
            connector_state: Some("ACTIVE".into()),
            squid_conf_sha256: Some(value_sha256(SQUID_CONF)),
            allow_sha256: Some(value_sha256(ALLOW)),
            ..InfraState::default()
        };
        f(&mut s);
        fs::create_dir_all(self.w.bridge().join("state")).unwrap();
        fs::write(self.w.bridge().join("state").join("infra.toml"), toml::to_string(&s).unwrap()).unwrap();
    }

    fn paths(&self) -> Paths {
        Paths::from_root_and_env(self.w.bridge(), None)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.w.cmd(args);
        c.env("PATH", &self.path).env("FAKE_AWS_LOG", &self.log).env("FAKE_AWS_ANSWERS", &self.answers).env("FAKE_AWS_SSM_DIR", &self.ssm).env("FAKE_AWS_PIN_ALL", "1");
        c
    }

    /// `ai-env <args>`, bounded, from a clean call log and per-op counters;
    /// every call it made must be pinned.
    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.reset();
        let mut c = self.cmd(args);
        for (k, v) in env {
            c.env(k, v);
        }
        let o = bounded(c);
        self.assert_pinned();
        o
    }

    /// [`Eg::run`] with stdout closed: a closed pipe must not end the command early.
    fn run_closed(&self, args: &[&str]) -> Output {
        self.reset();
        let o = bounded_with(self.cmd(args), closed_stdout());
        self.assert_pinned();
        o
    }

    fn reset(&self) {
        let _ = fs::remove_file(&self.log);
        for e in fs::read_dir(&self.answers).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with(".count.") {
                fs::remove_file(e.path()).unwrap();
            }
        }
    }

    /// The aws calls of the last run, one argv per line.
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log).unwrap_or_default().lines().map(str::to_string).collect()
    }

    fn ops(&self) -> Vec<String> {
        self.calls().iter().map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).collect()
    }

    fn has_op(&self, op: &str) -> bool {
        self.ops().iter().any(|o| o == op)
    }

    fn assert_pinned(&self) {
        for l in self.calls() {
            let service = l.split_whitespace().next().unwrap_or("");
            let url = endpoint(service).unwrap_or_else(|| panic!("an unpinned service: {l}"));
            assert!(l.contains(" --region eu-central-1 ") && l.contains(&format!(" --endpoint-url {url} ")), "not pinned: {l}");
        }
    }

    fn answer(&self, name: &str, doc: &Value) {
        fs::write(self.answers.join(name), serde_json::to_string_pretty(doc).unwrap()).unwrap();
    }

    fn remove_answer(&self, name: &str) {
        let _ = fs::remove_file(self.answers.join(name));
    }

    fn fixture(&self, name: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(fixtures().join("ops").join(name)).unwrap()).unwrap()
    }

    /// The green fixture `name`, changed by `f`, as the answer.
    fn mutate(&self, name: &str, f: impl FnOnce(&mut Value)) {
        let mut doc = self.fixture(name);
        f(&mut doc);
        self.answer(name, &doc);
    }

    fn restore(&self, name: &str) {
        fs::copy(fixtures().join("ops").join(name), self.answers.join(name)).unwrap();
    }

    fn param(&self, p: &str) -> String {
        fs::read_to_string(self.ssm.join(param_name(p).trim_start_matches('/'))).unwrap()
    }

    /// Parameter `p` holds `v`, version 1.
    fn set_param(&self, p: &str, v: &str) {
        let f = self.ssm.join(param_name(p).trim_start_matches('/'));
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, v).unwrap();
        fs::write(format!("{}.version", f.display()), "1\n").unwrap();
    }

    /// The `get-command-invocation` answer `name` (`ssm.get-command-invocation[.N].json`) in the real shape.
    fn invocation_as(&self, name: &str, status: &str, code: i64, out: &str, err: &str) {
        self.answer(
            name,
            &json!({
                "CommandId": "0b1c2d3e-0000-4000-8000-000000000001", "InstanceId": INSTANCE, "Comment": "ai-env", "DocumentName": "AWS-RunShellScript",
                "DocumentVersion": "$DEFAULT", "PluginName": "aws:runShellScript", "ResponseCode": code, "ExecutionStartDateTime": "2026-10-01T10:00:00.100Z",
                "ExecutionElapsedTime": "PT0.4S", "ExecutionEndDateTime": "2026-10-01T10:00:00.500Z", "Status": status, "StatusDetails": status,
                "StandardOutputContent": out, "StandardOutputUrl": "", "StandardErrorContent": err, "StandardErrorUrl": "",
                "CloudWatchOutputConfig": {"CloudWatchLogGroupName": "", "CloudWatchOutputEnabled": false}
            }),
        );
    }

    fn invocation(&self, name: &str, code: i64, out: &str, err: &str) {
        self.invocation_as(name, if code == 0 { "Success" } else { "Failed" }, code, out, err);
    }

    /// Every `get-command-invocation`: the script's exit `code` with this output.
    fn reload_answer(&self, code: i64, out: &str, err: &str) {
        self.invocation("ssm.get-command-invocation.json", code, out, err);
    }

    /// `ai-env-proxy-reload --status` over the parameters as they are now, `with` some replaced (`tail` ends the line).
    fn status_line_with(&self, with: &[(&str, &str)], tail: &str) -> String {
        let sums: Vec<String> = PARAMS
            .iter()
            .map(|p| {
                let v = with.iter().find(|(q, _)| q == p).map_or_else(|| self.param(p), |(_, v)| (*v).to_string());
                format!("sha256_{p}={}", value_sha256(&v))
            })
            .collect();
        format!("squid=active allowed=4 extras=0 suspended=0 {} parse=ok{tail}", sums.join(" "))
    }

    fn status_line(&self, tail: &str) -> String {
        self.status_line_with(&[], tail)
    }

    /// The status command's answer: the rpm line, then the status line.
    fn status_answer(&self, tail: &str) {
        self.reload_answer(0, &format!("squid-6.13-1.amzn2023.0.1.aarch64\n{}\n", self.status_line(tail)), "");
    }

    /// A reload that applies and whose `--status` proves `param` now holds `value`.
    fn reload_proves(&self, param: &str, value: &str) {
        self.reload_answer(0, &format!("{}\n", self.status_line_with(&[(param, value)], " applied=yes")), APPLIED);
    }

    fn audit_rows(&self, event: &str) -> Vec<Value> {
        self.w.audit().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    fn instance_state(&self, name: &str, state: &str) {
        let code = match state {
            "pending" => 0,
            "running" => 16,
            "shutting-down" => 32,
            "terminated" => 48,
            "stopping" => 64,
            _ => 80,
        };
        let mut doc = self.fixture("ec2.describe-instances.json");
        doc["Reservations"][0]["Instances"][0]["State"] = json!({"Code": code, "Name": state});
        self.answer(name, &doc);
    }

    fn proxy(&self, state: &str) {
        self.instance_state("ec2.describe-instances.json", state);
    }
}

/// `stderr` has `line` as one whole line.
fn has_line(o: &Output, line: &str) -> bool {
    stderr(o).lines().any(|l| l == line)
}

/// The rows of a status run, `(status, check)`.
fn rows(o: &Output) -> Vec<(String, String)> {
    stdout(o)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

fn row(o: &Output, check: &str) -> String {
    stdout(o).lines().find(|l| l.split_whitespace().nth(1) == Some(check)).unwrap_or_default().to_string()
}

const GREEN_ROWS: [&str; 19] = [
    "connector",
    "connector-enis",
    "vm-route-table",
    "vm-nacl",
    "vm-sg",
    "proxy-sg",
    "default-sg",
    "vpc",
    "vpc-dns",
    "dhcp-options",
    "vpc-endpoints",
    "vpc-peering",
    "nat-gateways",
    "proxy-instance",
    "proxy-ssm",
    "squid-rpm",
    "proxy-config",
    "parameters",
    "stack-params",
];

#[test]
fn status_all_green_checks_every_part_and_pins_every_call() {
    let t = Eg::new();
    t.status_answer(" applied=yes");
    let o = t.run(&["egress", "status"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    let checks: Vec<String> = rows(&o)
        .iter()
        .map(|(s, c)| {
            assert_eq!(s, "ok", "{}", stdout(&o));
            c.clone()
        })
        .collect();
    assert_eq!(checks, GREEN_ROWS);
    assert!(stdout(&o).contains("10.42.1.17, 10.42.1.18") && stdout(&o).contains("squid-6.13-1"), "{}", stdout(&o));
    assert!(row(&o, "stack-params").contains("squid.conf and allow are what the stack rendered"), "{}", stdout(&o));
    // The operator check first; the managed ENIs asked for; one status command with the rpm and --status lines.
    let calls = t.calls();
    assert_eq!(t.ops()[0], "sts get-caller-identity", "{calls:?}");
    assert!(calls.iter().any(|l| l.starts_with("ec2 describe-network-interfaces --include-managed-resources --filters Name=subnet-id,Values=subnet-0aaa1111bbbb2222c ")), "{calls:?}");
    assert!(calls.iter().any(|l| l.starts_with("ec2 describe-network-acls --filters Name=association.subnet-id,Values=subnet-0aaa1111bbbb2222c ")), "{calls:?}");
    assert!(calls.iter().any(|l| l.starts_with(&format!("lambda-core get-network-connector --identifier {CONNECTOR} "))), "{calls:?}");
    let send: Vec<&String> = calls.iter().filter(|l| l.starts_with("ssm send-command")).collect();
    assert_eq!(send.len(), 1, "{calls:?}");
    assert!(send[0].contains("--document-name AWS-RunShellScript") && send[0].contains(r#""commands":["rpm -q squid || true","/usr/local/sbin/ai-env-proxy-reload --status"]"#), "{}", send[0]);
    assert!(calls.iter().any(|l| l.starts_with("ssm get-parameters --names /ai-env/proxy/squid.conf /ai-env/proxy/allow /ai-env/proxy/extras /ai-env/proxy/suspended ")), "{calls:?}");
    assert!(!calls.iter().any(|l| l.contains("put-parameter") || l.contains("start-instances") || l.contains("stop-instances") || l.starts_with("route53resolver")), "status writes nothing; no DNS Firewall in mode none: {calls:?}");
    // --json: one document with every row.
    let o = t.run(&["egress", "status", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let doc: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["rows"].as_array().unwrap().len(), GREEN_ROWS.len());
    assert!(doc["rows"].as_array().unwrap().iter().all(|r| r["status"] == "ok"), "{doc}");
}

#[test]
fn status_flags_drift_by_name_and_exits_1() {
    let t = Eg::new();
    t.status_answer(" applied=yes");
    let drift = |o: &Output, check: &str, detail: &str| {
        assert_eq!(code(o), 1, "{check}: {}\n{}", stdout(o), stderr(o));
        assert!(stderr(o).contains(&format!("egress status: drift in {check}")), "{check}: {}", stderr(o));
        let line = row(o, check);
        assert!(line.starts_with("DRIFT") && line.contains(detail), "{check}: {line}\n{}", stdout(o));
    };
    // An extra route in the VM subnet's table.
    t.mutate("ec2.describe-route-tables.json", |d| {
        d["RouteTables"][2]["Routes"].as_array_mut().unwrap().push(json!({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0123456789abcdef0", "Origin": "CreateRoute", "State": "active"}));
    });
    drift(&t.run(&["egress", "status"]), "vm-route-table", "0.0.0.0/0 → igw-0123456789abcdef0");
    assert_eq!(code(&t.run_closed(&["egress", "status"])), 1, "a closed stdout never hides drift");
    // Route propagation from a virtual private gateway.
    t.mutate("ec2.describe-route-tables.json", |d| d["RouteTables"][2]["PropagatingVgws"] = json!([{"GatewayId": "vgw-0123456789abcdef0"}]));
    drift(&t.run(&["egress", "status"]), "vm-route-table", "virtual private gateway");
    // Its explicit association gone: the subnet falls back to the main table — fine while it is local only, drift once it routes out.
    t.mutate("ec2.describe-route-tables.json", |d| {
        d["RouteTables"].as_array_mut().unwrap().remove(2);
    });
    let o = t.run(&["egress", "status"]);
    assert!(code(&o) == 0 && row(&o, "vm-route-table").starts_with("ok") && row(&o, "vm-route-table").contains("the VPC's main table"), "{}", stdout(&o));
    t.mutate("ec2.describe-route-tables.json", |d| {
        d["RouteTables"].as_array_mut().unwrap().remove(2);
        d["RouteTables"][0]["Routes"].as_array_mut().unwrap().push(json!({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0123456789abcdef0"}));
    });
    drift(&t.run(&["egress", "status"]), "vm-route-table", "the VPC's main table");
    t.restore("ec2.describe-route-tables.json");
    // The VM subnet on the VPC's default NACL; an extra allow on its own.
    t.mutate("ec2.describe-network-acls.json", |d| d["NetworkAcls"][0]["IsDefault"] = json!(true));
    drift(&t.run(&["egress", "status"]), "vm-nacl", "default network ACL");
    t.mutate("ec2.describe-network-acls.json", |d| {
        d["NetworkAcls"][0]["Entries"].as_array_mut().unwrap().push(json!({"CidrBlock": "0.0.0.0/0", "Egress": true, "PortRange": {"From": 443, "To": 443}, "Protocol": "6", "RuleAction": "allow", "RuleNumber": 110}));
    });
    drift(&t.run(&["egress", "status"]), "vm-nacl", "unexpected egress allow tcp 443 cidr:0.0.0.0/0");
    t.restore("ec2.describe-network-acls.json");
    // A wider CIDR on the VM SG's egress, then an extra rule on the proxy SG.
    t.mutate("ec2.describe-security-groups.json", |d| d["SecurityGroups"][0]["IpPermissionsEgress"][0]["IpRanges"].as_array_mut().unwrap().push(json!({"CidrIp": "0.0.0.0/0"})));
    drift(&t.run(&["egress", "status"]), "vm-sg", "unexpected tcp 3128 cidr:0.0.0.0/0");
    t.mutate("ec2.describe-security-groups.json", |d| {
        d["SecurityGroups"][1]["IpPermissions"].as_array_mut().unwrap().push(json!({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "UserIdGroupPairs": [], "Ipv6Ranges": [], "PrefixListIds": []}));
    });
    drift(&t.run(&["egress", "status"]), "proxy-sg", "ingress: unexpected tcp 22 cidr:0.0.0.0/0");
    t.restore("ec2.describe-security-groups.json");
    // DNS support on in dnsMode none; a VPC endpoint; the connector still PENDING; an ACTIVE connector without ENIs.
    t.answer("ec2.describe-vpc-attribute.1.json", &json!({"VpcId": VPC, "EnableDnsSupport": {"Value": true}}));
    drift(&t.run(&["egress", "status"]), "vpc-dns", "enableDnsSupport true");
    t.restore("ec2.describe-vpc-attribute.1.json");
    t.answer("ec2.describe-vpc-endpoints.json", &json!({"VpcEndpoints": [{"VpcEndpointId": "vpce-0123456789abcdef0", "VpcEndpointType": "Gateway", "VpcId": VPC, "ServiceName": "com.amazonaws.eu-central-1.s3", "State": "available"}]}));
    drift(&t.run(&["egress", "status"]), "vpc-endpoints", "vpce-0123456789abcdef0");
    t.restore("ec2.describe-vpc-endpoints.json");
    let mut pending: Value = serde_json::from_str(&fs::read_to_string(fixtures().join("lambda-core.get-network-connector.json")).unwrap()).unwrap();
    pending["State"] = json!("PENDING");
    t.answer("lambda-core.get-network-connector.json", &pending);
    drift(&t.run(&["egress", "status"]), "connector", "State PENDING");
    fs::copy(fixtures().join("lambda-core.get-network-connector.json"), t.answers.join("lambda-core.get-network-connector.json")).unwrap();
    // No connector ENI: skipped while no vpc VM runs (they may exist only then), drift while one does.
    t.answer("ec2.describe-network-interfaces.json", &json!({"NetworkInterfaces": []}));
    let paths = t.paths();
    registry::write_row(&paths, &vm_row(1, "vpc", RowStatus::Running, -10)).unwrap();
    registry::write_row(&paths, &vm_row(2, "internet", RowStatus::Running, 3000)).unwrap();
    let o = t.run(&["egress", "status", "--json"]);
    assert_eq!(code(&o), 0, "an idle stack is never drift: {}", stdout(&o));
    let doc: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(doc["ok"] == true && doc["unknown"] == json!(["connector-enis"]), "{doc}");
    let live = vm_row(3, "vpc", RowStatus::Running, 3000);
    registry::write_row(&paths, &live).unwrap();
    drift(&t.run(&["egress", "status"]), "connector-enis", &format!("the connector is ACTIVE and the vpc VM {} runs", live.id));
    registry::remove_row(&paths, &live).unwrap();
    t.restore("ec2.describe-network-interfaces.json");
    // The state names a proxy the stack replaced.
    t.proxy("terminated");
    drift(&t.run(&["egress", "status"]), "proxy-instance", "names a proxy that no longer exists (i-0123456789abcdef0)");
    t.restore("ec2.describe-instances.json");
    // A parameter changed since the proxy's status line was taken: its hash differs.
    let old = t.status_line(" applied=yes");
    t.set_param("extras", &format!("{EXTRAS_HEADER}github.com\tai-env\n"));
    t.reload_answer(0, &format!("squid-6.13-1.amzn2023.0.1.aarch64\n{old}\n"), "");
    drift(&t.run(&["egress", "status"]), "parameters", "extras: the proxy reads sha256");
    // applied=no: the proxy still serves an older config.
    t.status_answer(" applied=no");
    drift(&t.run(&["egress", "status"]), "proxy-config", "the proxy serves an older config: ai-env egress reload");
    // squid.conf edited outside `make deploy` (the proxy serves it, hashes agree): not what the stack rendered.
    t.set_param("squid.conf", &format!("{SQUID_CONF}http_access allow all\n"));
    t.status_answer(" applied=yes");
    drift(&t.run(&["egress", "status"]), "stack-params", "squid.conf differs from what the stack rendered");
    t.set_param("squid.conf", SQUID_CONF);
    t.status_answer(" applied=yes");
    assert_eq!(code(&t.run(&["egress", "status"])), 0, "green again");
}

#[test]
fn status_skips_a_stopped_proxy_and_never_passes_what_it_could_not_verify() {
    let t = Eg::new();
    t.proxy("stopped");
    let o = t.run(&["egress", "status", "--json"]);
    assert_eq!(code(&o), 0, "a stopped proxy is closed, not drift: {}\n{}", stdout(&o), stderr(&o));
    let doc: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(doc["ok"], true, "{doc}");
    assert_eq!(doc["unknown"], json!(["proxy-ssm", "squid-rpm", "proxy-config"]), "{doc}");
    assert!(!t.has_op("ssm send-command") && !t.has_op("ssm describe-instance-information"), "{:?}", t.calls());
    // Still starting: nothing about squid can be verified now → exit 7, ok false.
    t.proxy("pending");
    let o = t.run(&["egress", "status", "--json"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert_eq!(serde_json::from_str::<Value>(&stdout(&o)).unwrap()["ok"], false);
    t.proxy("running");
    // A call that fails is unknown and exit 7 (never a silent pass).
    t.status_answer(" applied=yes");
    let o = t.run_env(&["egress", "status"], &[("FAKE_AWS_FAIL_OP", "ec2 describe-nat-gateways")]);
    assert_eq!(code(&o), 7, "{}\n{}", stdout(&o), stderr(&o));
    assert!(row(&o, "nat-gateways").starts_with("unknown") && stderr(&o).contains("nat-gateways could not be verified"), "{}\n{}", stdout(&o), stderr(&o));
    // --status could not fetch the parameters (exit 2, no line): unknown, exit 7, not drift.
    t.reload_answer(2, "squid-6.13-1.amzn2023.0.1.aarch64\n", "ai-env-proxy-reload: fetch failed; nothing changed\n");
    let o = t.run(&["egress", "status"]);
    assert_eq!(code(&o), 7, "{}", stdout(&o));
    assert!(row(&o, "proxy-config").starts_with("unknown") && row(&o, "proxy-config").contains("printed no status line"), "{}", stdout(&o));
    // A state written before the stack's parameter hashes: the content cannot be verified.
    t.status_answer(" applied=yes");
    t.write_state(|s| s.squid_conf_sha256 = None);
    let o = t.run(&["egress", "status"]);
    assert_eq!(code(&o), 7, "{}", stdout(&o));
    assert!(row(&o, "stack-params").starts_with("unknown") && row(&o, "stack-params").contains("make infra-status WRITE=1"), "{}", stdout(&o));
}

#[test]
fn status_in_firewall_mode_needs_a_closed_dns_firewall() {
    let t = Eg::new();
    t.write_state(|s| s.dns_mode = Some("firewall".into()));
    t.answer("ec2.describe-vpc-attribute.1.json", &json!({"VpcId": VPC, "EnableDnsSupport": {"Value": true}}));
    t.status_answer(" applied=yes");
    let o = t.run(&["egress", "status"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert!(row(&o, "dns-firewall").starts_with("ok") && row(&o, "vpc-dns").contains("dnsMode firewall"), "{}", stdout(&o));
    let calls = t.calls();
    for op in ["list-firewall-rule-group-associations --vpc-id vpc-0123456789abcdef0 ", "get-firewall-config --resource-id vpc-0123456789abcdef0 ", "list-firewall-rules --firewall-rule-group-id rslvr-frg-0123456789abcdef ", "list-firewall-domains --firewall-domain-list-id rslvr-fdl-0123456789abcdef "] {
        assert!(calls.iter().any(|l| l.starts_with(&format!("route53resolver {op}"))), "{op}: {calls:?}");
    }
    let drift = |what: &str| {
        let o = t.run(&["egress", "status"]);
        assert_eq!(code(&o), 1, "{what}: {}", stdout(&o));
        assert!(row(&o, "dns-firewall").starts_with("DRIFT") && row(&o, "dns-firewall").contains(what), "{what}: {}", row(&o, "dns-firewall"));
    };
    t.mutate("route53resolver.get-firewall-config.json", |d| d["FirewallConfig"]["FirewallFailOpen"] = json!("ENABLED"));
    drift("FirewallFailOpen ENABLED");
    t.restore("route53resolver.get-firewall-config.json");
    t.answer("route53resolver.list-firewall-rule-group-associations.json", &json!({"FirewallRuleGroupAssociations": []}));
    drift("no DNS Firewall rule group");
    t.restore("route53resolver.list-firewall-rule-group-associations.json");
    t.mutate("route53resolver.list-firewall-rules.json", |d| d["FirewallRules"][0]["Qtype"] = json!("A"));
    drift("query type A");
    t.mutate("route53resolver.list-firewall-rules.json", |d| {
        let mut allow = d["FirewallRules"][0].clone();
        allow["Action"] = json!("ALLOW");
        allow["Priority"] = json!(50);
        d["FirewallRules"].as_array_mut().unwrap().insert(0, allow);
    });
    drift("holds 2 rules");
    t.restore("route53resolver.list-firewall-rules.json");
    t.answer("route53resolver.list-firewall-domains.json", &json!({"Domains": ["example.com."]}));
    drift("not exactly *");
    t.restore("route53resolver.list-firewall-domains.json");
    // DNS support off in firewall mode is drift of its own row.
    t.restore("ec2.describe-vpc-attribute.1.json");
    let o = t.run(&["egress", "status"]);
    assert!(code(&o) == 1 && row(&o, "vpc-dns").starts_with("DRIFT"), "{}", stdout(&o));
}

#[test]
fn every_command_checks_the_operator_account_before_any_other_call() {
    let t = Eg::new();
    t.answer("sts.get-caller-identity.json", &json!({"Account": "999999999999", "Arn": "arn:aws:iam::999999999999:user/rust"}));
    for args in [
        &["egress", "status"][..],
        &["egress", "allow", "ai-env", "github.com"],
        &["egress", "allow", "ai-env", "github.com", "--remove"],
        &["egress", "suspend", "example.com"],
        &["egress", "suspend", "example.com", "--restore"],
        &["egress", "reload"],
        &["proxy", "stop"],
        &["proxy", "start"],
        &["proxy", "patch"],
    ] {
        let o = t.run(args);
        assert_eq!(code(&o), 1, "{args:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("999999999999") && stderr(&o).contains("123456789012"), "{args:?}: {}", stderr(&o));
        assert_eq!(t.ops(), ["sts get-caller-identity"], "{args:?}");
    }
    assert_eq!(t.param("extras"), EXTRAS_HEADER);
    assert!(t.w.audit().is_empty(), "{}", t.w.audit());
}

#[test]
fn missing_state_config_s5_fields_or_another_prefix_exit_1_with_no_call() {
    let t = Eg::new();
    let commands: [&[&str]; 7] = [&["egress", "status"], &["egress", "allow", "ai-env", "github.com"], &["egress", "suspend", "example.com"], &["egress", "reload"], &["proxy", "stop"], &["proxy", "start"], &["proxy", "patch"]];
    let refused = |o: &Output, args: &[&str], what: &str| {
        assert_eq!(code(o), 1, "{args:?}: {}", stderr(o));
        assert!(stderr(o).contains("make infra-status WRITE=1") && stderr(o).contains(what), "{args:?}: {}", stderr(o));
        assert!(t.calls().is_empty(), "{args:?}: {:?}", t.calls());
    };
    fs::remove_file(t.w.bridge().join("state/infra.toml")).unwrap();
    for args in commands {
        refused(&t.run(args), args, "infra.toml not found");
    }
    t.write_state(|s| s.proxy_instance_id = None);
    for args in commands {
        refused(&t.run(args), args, "has no proxy_instance_id");
    }
    t.write_state(|s| s.vm_subnet_id = Some("--subnet-ids".into()));
    refused(&t.run(&["egress", "status"]), &["egress", "status"], "is not a subnet-… id");
    // The parameters this ai-env edits are not the stack's: never touch them.
    t.write_state(|s| s.parameter_prefix = Some("/other/proxy".into()));
    for args in [&["egress", "status"][..], &["egress", "allow", "ai-env", "github.com"], &["egress", "allow", "ai-env", "github.com", "--remove"], &["egress", "suspend", "example.com"], &["egress", "suspend", "example.com", "--restore"]] {
        refused(&t.run(args), args, "parameter_prefix = \"/other/proxy\"");
    }
    t.write_state(|_| {});
    let toml = fs::read_to_string(t.w.bridge().join("bridge.toml")).unwrap();
    fs::write(t.w.bridge().join("bridge.toml"), toml.replace(&format!("egress_connector_arn = \"{CONNECTOR}\"\n"), "")).unwrap();
    for args in commands {
        refused(&t.run(args), args, "[aws].egress_connector_arn is not set");
    }
    fs::write(t.w.bridge().join("bridge.toml"), toml.replace(CONNECTOR, "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS")).unwrap();
    let o = t.run(&["egress", "status"]);
    assert!(code(&o) == 1 && stderr(&o).contains("egress_connector_arn") && t.calls().is_empty(), "a managed connector is refused: {}", stderr(&o));
}

#[test]
fn allow_adds_normalised_hosts_and_says_what_the_other_lists_keep() {
    let t = Eg::new();
    let o = t.run(&["egress", "allow", "ai-env", " GitHub.COM. "]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(t.param("extras"), format!("{EXTRAS_HEADER}github.com\tai-env\n"));
    assert!(stdout(&o).contains("allowed github.com for ai-env") && stdout(&o).contains("proxy: reloaded"), "{}", stdout(&o));
    assert_eq!(t.ops(), ["sts get-caller-identity", "ssm get-parameters", "ssm put-parameter", "ec2 describe-instances", "ssm send-command", "ssm get-command-invocation"]);
    let calls = t.calls();
    assert!(calls[1].starts_with("ssm get-parameters --names /ai-env/proxy/allow /ai-env/proxy/extras /ai-env/proxy/suspended "), "{}", calls[1]);
    // The value goes through a file in the private state/ dir, removed afterwards.
    let put = &calls[2];
    let state = fs::canonicalize(t.w.bridge().join("state")).unwrap();
    let file = put.split_whitespace().find_map(|a| a.strip_prefix("file://")).unwrap();
    assert!(fs::canonicalize(Path::new(file).parent().unwrap()).unwrap() == state && put.contains("--name /ai-env/proxy/extras ") && put.contains("--overwrite") && !put.contains("github.com"), "{put}");
    assert!(!fs::read_dir(&state).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with(".param.")), "the temp file is gone");
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(calls[4].contains(RELOAD_SCRIPT) && calls[4].contains(&format!("--instance-ids {INSTANCE}")), "{}", calls[4]);
    assert!(!stdout(&o).contains("the proxy denies"), "an add claims nothing about the proxy: {}", stdout(&o));
    let a = t.audit_rows("egress_allow");
    assert_eq!((a[0]["detail"]["slug"].as_str(), a[0]["detail"]["host"].as_str(), a[0]["detail"]["action"].as_str()), (Some("ai-env"), Some("github.com"), Some("add")));
    assert_eq!(t.audit_rows("egress_reload")[0]["detail"]["result"], "applied");
    // A second workspace on the same host; the first removes it: the host stays.
    assert_eq!(code(&t.run(&["egress", "allow", "other-ws", "github.com"])), 0);
    assert_eq!(t.param("extras"), format!("{EXTRAS_HEADER}github.com\tai-env,other-ws\n"));
    t.reload_proves("extras", &format!("{EXTRAS_HEADER}github.com\tother-ws\n"));
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(t.param("extras"), format!("{EXTRAS_HEADER}github.com\tother-ws\n"));
    assert!(stdout(&o).contains("it stays allowed: still listed by other-ws"), "{}", stdout(&o));
    // Unchanged: nothing written, the reload still runs (a rerun after a failed reload completes it).
    let o = t.run(&["egress", "allow", "other-ws", "github.com"]);
    assert!(code(&o) == 0 && stdout(&o).contains("already allowed"), "{}", stdout(&o));
    assert!(!t.has_op("ssm put-parameter") && t.has_op("ssm send-command"), "{:?}", t.ops());
    // The last slug goes: exactly the header the stack created the parameter with, proved by a --status of its own,
    // and only then a word about the proxy.
    t.reload_proves("extras", EXTRAS_HEADER);
    let o = t.run(&["egress", "allow", "other-ws", "github.com", "--remove"]);
    assert!(code(&o) == 0 && stdout(&o).contains("no workspace lists it any more"), "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(t.param("extras"), EXTRAS_HEADER);
    assert_eq!(t.ops(), ["sts get-caller-identity", "ssm get-parameters", "ssm put-parameter", "ec2 describe-instances", "ssm send-command", "ssm get-command-invocation", "ssm send-command", "ssm get-command-invocation"]);
    let sends: Vec<String> = t.calls().into_iter().filter(|l| l.starts_with("ssm send-command")).collect();
    assert!(sends[0].contains(RELOAD_SCRIPT) && sends[1].contains(STATUS_SCRIPT), "{sends:?}");
    let out = stdout(&o);
    let (verified, claim) = (out.find("proxy: reloaded and verified").unwrap(), out.find("the proxy denies github.com now").unwrap());
    assert!(verified < claim, "{out}");
    // A host of the base allowlist: removing its extra does not deny it.
    t.reload_answer(0, "", APPLIED);
    let o = t.run(&["egress", "allow", "ai-env", "api.anthropic.com"]);
    assert!(code(&o) == 0 && stdout(&o).contains("in the base allowlist too"), "{}", stdout(&o));
    t.reload_proves("extras", EXTRAS_HEADER);
    let o = t.run(&["egress", "allow", "ai-env", "api.anthropic.com", "--remove"]);
    assert!(code(&o) == 0 && stdout(&o).contains("it stays allowed: in the base allowlist"), "{}\n{}", stdout(&o), stderr(&o));
    // A suspended host: an extra does not allow it.
    t.set_param("suspended", &format!("{SUSPENDED_HEADER}example.com\n"));
    t.reload_answer(0, "", APPLIED);
    let o = t.run(&["egress", "allow", "ai-env", "example.com"]);
    assert!(code(&o) == 0 && stdout(&o).contains("it stays denied: suspended"), "{}", stdout(&o));
    let actions: Vec<String> = t.audit_rows("egress_allow").iter().map(|r| r["detail"]["action"].as_str().unwrap().to_string()).collect();
    assert_eq!(actions, ["add", "add", "remove", "remove", "add", "remove", "add"]);
    assert_eq!(t.audit_rows("egress_reload").len(), 8, "every allow audits its reload");
}

#[test]
fn allow_refuses_what_is_not_an_exact_host_or_a_slug_as_usage_errors() {
    let t = Eg::new();
    for (slug, host) in [("ai-env", "1.2.3.4"), ("ai-env", "*.example.com"), ("ai-env", "example.com:443"), ("ai-env", "https://example.com"), ("ai-env", "a_b.example.com"), ("ai-env", "[::1]"), ("a/b", "example.com"), ("..", "example.com"), ("", "example.com")] {
        let o = t.run(&["egress", "allow", slug, host]);
        assert_eq!(code(&o), 2, "{slug} {host}: {}", stderr(&o));
        assert!(t.calls().is_empty(), "{slug} {host}: {:?}", t.calls());
    }
    for host in ["10.42.0.10", "*.github.com"] {
        assert_eq!(code(&t.run(&["egress", "suspend", host])), 2, "{host}");
    }
    assert_eq!(t.param("extras"), EXTRAS_HEADER);
}

/// `header`, then `host-NNNN.example.com<tail>` lines up to 4000 bytes or more (≤ 4030).
fn near_cap(header: &str, tail: &str) -> String {
    let mut value = header.to_string();
    let mut n = 0;
    while value.len() < 4000 {
        value.push_str(&format!("host-{n:04}.example.com{tail}\n"));
        n += 1;
    }
    value
}

#[test]
fn the_4k_cap_is_refused_before_any_put_for_extras_and_suspended() {
    let t = Eg::new();
    let long = format!("{}.{}.example.com", "x".repeat(63), "y".repeat(63));
    let value = near_cap(EXTRAS_HEADER, "\tws");
    t.set_param("extras", &value);
    let o = t.run(&["egress", "allow", "ai-env", &long]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("4096") && stderr(&o).contains("nothing was written"), "{}", stderr(&o));
    assert!(!t.has_op("ssm put-parameter") && !t.has_op("ssm send-command"), "{:?}", t.calls());
    assert_eq!(t.param("extras"), value);
    let value = near_cap(SUSPENDED_HEADER, "");
    t.set_param("suspended", &value);
    let o = t.run(&["egress", "suspend", &long]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("4096") && !t.has_op("ssm put-parameter"), "{}", stderr(&o));
    assert_eq!(t.param("suspended"), value);
    assert!(t.audit_rows("egress_allow").is_empty() && t.audit_rows("egress_suspend").is_empty());
}

#[test]
fn a_list_that_does_not_parse_is_never_overwritten() {
    let t = Eg::new();
    for bad in ["github.com\n", "github.com\tbad/slug\n", "1.2.3.4\tai-env\n"] {
        t.set_param("extras", bad);
        let o = t.run(&["egress", "allow", "ai-env", "example.com"]);
        assert_eq!(code(&o), 1, "{bad:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("does not parse") && stderr(&o).contains("nothing was written"), "{}", stderr(&o));
        assert!(!t.has_op("ssm put-parameter"), "{:?}", t.calls());
        assert_eq!(t.param("extras"), bad);
    }
    t.set_param("extras", EXTRAS_HEADER);
    t.set_param("suspended", "*.example.com\n");
    for args in [&["egress", "suspend", "example.com"][..], &["egress", "allow", "ai-env", "example.com"]] {
        let o = t.run(args);
        assert!(code(&o) == 1 && stderr(&o).contains("/ai-env/proxy/suspended does not parse") && !t.has_op("ssm put-parameter"), "{args:?}: {}", stderr(&o));
    }
    assert_eq!(t.param("suspended"), "*.example.com\n");
}

#[test]
fn a_removal_that_is_not_proved_on_the_proxy_says_still_allowed_and_exits_7() {
    let t = Eg::new();
    let listed = format!("{EXTRAS_HEADER}github.com\tai-env\n");
    t.set_param("extras", &listed);
    t.reload_answer(1, "", "ai-env-proxy-reload: squid -k parse failed (exit 1, 1 error lines, squid.conf lines: 12 )\nai-env-proxy-reload: refused; the running config is unchanged\n");
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(has_line(&o, STILL_ALLOWED), "{}", stderr(&o));
    assert!(stderr(&o).contains("the proxy kept its old config") && stderr(&o).contains("refused; the running config is unchanged"), "{}", stderr(&o));
    assert_eq!(t.param("extras"), EXTRAS_HEADER, "the parameter is written");
    assert_eq!(t.audit_rows("egress_reload")[0]["detail"]["result"], "refused");
    // A rerun with nothing left to remove still reloads, and still says so when that fails.
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED), "{}", stderr(&o));
    // A closed stdout (`| head -0`) ends nothing early: the reload runs, its failure is still exit 7.
    t.set_param("extras", &listed);
    let o = t.run_closed(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED), "{}", stderr(&o));
    assert!(t.has_op("ssm send-command"), "{:?}", t.ops());
    // The reload exits 0 but its --status does not show the new value applied: not proved.
    t.set_param("extras", &listed);
    t.reload_answer(0, &format!("{}\n", t.status_line_with(&[("extras", EXTRAS_HEADER)], " applied=no")), APPLIED);
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("applied=no"), "{}", stderr(&o));
    t.set_param("extras", &listed);
    t.reload_answer(0, &format!("{}\n", t.status_line(" applied=yes")), APPLIED);
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("another extras than the one written"), "{}", stderr(&o));
    t.set_param("extras", &listed);
    t.reload_answer(0, "", APPLIED);
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("no --status line"), "{}", stderr(&o));
    // Another writer between the read and the put: the version jumped. Its newest version (8, from the history)
    // had removed example.org; this overwrite (built on version 1) allows it again — whatever this edit was.
    let both = format!("{EXTRAS_HEADER}example.org\tother-ws\ngithub.com\tai-env\n");
    let history = |v8: &str| json!({"Parameters": [
        {"Name": "/ai-env/proxy/extras", "Type": "String", "Value": both, "Version": 1, "Tier": "Standard", "DataType": "text"},
        {"Name": "/ai-env/proxy/extras", "Type": "String", "Value": v8, "Version": 8, "Tier": "Standard", "DataType": "text"}
    ]});
    t.set_param("extras", &both);
    t.answer("ssm.put-parameter.json", &json!({"Version": 9, "Tier": "Standard"}));
    t.answer("ssm.get-parameter-history.json", &history(&format!("{EXTRAS_HEADER}github.com\tai-env\n")));
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("another writer changed /ai-env/proxy/extras") && stderr(&o).contains("it allowed again example.org"), "{}", stderr(&o));
    assert!(!t.has_op("ssm send-command") && t.calls().iter().any(|l| l.starts_with("ssm get-parameter-history --name /ai-env/proxy/extras --no-with-decryption ")), "{:?}", t.calls());
    let o = t.run(&["egress", "allow", "ai-env", "example.com"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && has_line(&o, "ai-env: example.org: allowed again by this overwrite (the other writer had removed or suspended it)"), "an add that re-allows: {}", stderr(&o));
    assert!(!stderr(&o).contains("example.com: allowed again"), "its own host is not allowed again: {}", stderr(&o));
    // The other writer only added a host: nothing is allowed again by this add (its own host is not "again").
    t.answer("ssm.get-parameter-history.json", &history(&format!("{EXTRAS_HEADER}example.org\tother-ws\ngithub.com\tai-env\nnew.example\tthird\n")));
    let o = t.run(&["egress", "allow", "ai-env", "example.com"]);
    assert!(code(&o) == 7 && !stderr(&o).contains("STILL ALLOWED") && stderr(&o).contains("re-run"), "{}", stderr(&o));
    // The history cannot be read: what came back is unknown, so the line.
    let o = t.run_env(&["egress", "allow", "ai-env", "example.com"], &[("FAKE_AWS_FAIL_OP", "ssm get-parameter-history")]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("is unknown"), "{}", stderr(&o));
    t.remove_answer("ssm.put-parameter.json");
    t.remove_answer("ssm.get-parameter-history.json");
    // A put that fails (a timeout may have landed it): a removal says STILL ALLOWED, an add does not.
    t.set_param("extras", &listed);
    let o = t.run_env(&["egress", "allow", "ai-env", "github.com", "--remove"], &[("FAKE_AWS_FAIL_OP", "ssm put-parameter")]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && !t.has_op("ssm send-command"), "{}", stderr(&o));
    let o = t.run_env(&["egress", "allow", "ai-env", "example.com"], &[("FAKE_AWS_FAIL_OP", "ssm put-parameter")]);
    assert!(code(&o) == 7 && !stderr(&o).contains("STILL ALLOWED"), "{}", stderr(&o));
    // After an add: exit 7 with the reload error, never the removal line.
    t.set_param("extras", EXTRAS_HEADER);
    t.reload_answer(1, "", "ai-env-proxy-reload: refused; the running config is unchanged\n");
    let o = t.run(&["egress", "allow", "ai-env", "example.com"]);
    assert_eq!(code(&o), 7);
    assert!(!stderr(&o).contains("STILL ALLOWED") && !has_line(&o, STATE_UNKNOWN) && stderr(&o).contains("`ai-env egress reload` retries"), "{}", stderr(&o));
    // Exit 3, a timeout, an exit outside the script's: the state line after an add, the removal line after a removal.
    for (status, rc) in [("Failed", 3), ("TimedOut", -1), ("Failed", 5), ("Cancelled", -1)] {
        t.invocation_as("ssm.get-command-invocation.json", status, rc, "", "ai-env-proxy-reload: rollback failed\n");
        let o = t.run(&["egress", "allow", "ai-env", "example.org"]);
        assert!(code(&o) == 7 && has_line(&o, STATE_UNKNOWN) && !stderr(&o).contains("STILL ALLOWED"), "{status} {rc}: {}", stderr(&o));
        let o = t.run(&["egress", "allow", "ai-env", "example.org", "--remove"]);
        assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && !has_line(&o, STATE_UNKNOWN), "{status} {rc}: {}", stderr(&o));
    }
    // SSM cannot run the command at all: the same.
    t.answer("ssm.send-command.rc", &json!(254));
    fs::write(t.answers.join("ssm.send-command.stderr"), "\nAn error occurred (InvalidInstanceId) when calling the SendCommand operation: Instances not in a valid state for account\n").unwrap();
    let o = t.run(&["egress", "allow", "ai-env", "example.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("InvalidInstanceId"), "{}", stderr(&o));
}

#[test]
fn a_stopped_proxy_gets_the_parameter_and_a_note_a_stopping_one_still_serves() {
    let t = Eg::new();
    t.proxy("stopped");
    let o = t.run(&["egress", "allow", "ai-env", "github.com"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("the proxy is stopped: the change applies at its next start"), "{}", stdout(&o));
    assert_eq!(t.param("extras"), format!("{EXTRAS_HEADER}github.com\tai-env\n"));
    assert!(t.has_op("ssm put-parameter") && !t.has_op("ssm send-command"), "{:?}", t.ops());
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 0 && stdout(&o).contains("applies at its next start"), "a stopped proxy serves nothing: {}", stderr(&o));
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 0 && stdout(&o).contains("it reads its parameters when it starts"), "{}", stdout(&o));
    assert_eq!(t.audit_rows("egress_reload").last().unwrap()["detail"]["result"], "proxy-stopped");
    // Stopping: fine for an add, but it still serves the old lists, so a removal or a suspension is not done.
    t.proxy("stopping");
    let o = t.run(&["egress", "allow", "ai-env", "github.com"]);
    assert!(code(&o) == 0 && stdout(&o).contains("the proxy is stopping"), "{}", stdout(&o));
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("is stopping"), "{}", stderr(&o));
    let o = t.run(&["egress", "suspend", "example.com"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("is stopping"), "{}", stderr(&o));
    // Still starting: not reloaded either.
    t.proxy("pending");
    t.set_param("extras", &format!("{EXTRAS_HEADER}github.com\tai-env\n"));
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("is pending"), "{}", stderr(&o));
}

#[test]
fn a_removal_whose_put_jumped_a_version_says_still_allowed_even_when_nothing_was_reallowed() {
    let t = Eg::new();
    let listed = format!("{EXTRAS_HEADER}github.com\tai-env\n");
    t.set_param("extras", &listed);
    t.answer("ssm.put-parameter.json", &json!({"Version": 9, "Tier": "Standard"}));
    t.answer(
        "ssm.get-parameter-history.json",
        &json!({"Parameters": [
            {"Name": "/ai-env/proxy/extras", "Type": "String", "Value": listed, "Version": 1, "Tier": "Standard", "DataType": "text"},
            {"Name": "/ai-env/proxy/extras", "Type": "String", "Value": listed, "Version": 8, "Tier": "Standard", "DataType": "text"}
        ]}),
    );
    let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(has_line(&o, STILL_ALLOWED) && stderr(&o).contains("another writer changed"), "{}", stderr(&o));
}

#[test]
fn a_proxy_the_stack_replaced_means_a_stale_state_file() {
    let t = Eg::new();
    let gone = "state/infra.toml names a proxy that no longer exists (i-0123456789abcdef0): run `make infra-status WRITE=1` (the stack's current proxy may still serve the old list)";
    let not_found = || {
        t.remove_answer("ec2.describe-instances.json");
        t.answer("ec2.describe-instances.rc", &json!(254));
        fs::write(t.answers.join("ec2.describe-instances.stderr"), "\nAn error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: The instance ID 'i-0123456789abcdef0' does not exist\n").unwrap();
    };
    for (state, setup) in [("terminated", None), ("shutting-down", None), ("not found", Some(&not_found))] {
        match setup {
            Some(f) => f(),
            None => t.proxy(state),
        }
        // A removal: the parameter is written, nothing is claimed about the proxy, and it may still serve the host.
        t.set_param("extras", &format!("{EXTRAS_HEADER}github.com\tai-env\n"));
        let o = t.run(&["egress", "allow", "ai-env", "github.com", "--remove"]);
        assert_eq!(code(&o), 7, "{state}: {}", stderr(&o));
        assert!(has_line(&o, STILL_ALLOWED) && stderr(&o).contains(gone) && !stdout(&o).contains("the proxy denies") && !stderr(&o).contains("make deploy"), "{state}: {}\n{}", stdout(&o), stderr(&o));
        assert_eq!(t.param("extras"), EXTRAS_HEADER);
        let o = t.run(&["egress", "reload"]);
        assert!(code(&o) == 7 && stderr(&o).contains(gone), "{state}: {}", stderr(&o));
        assert_eq!(t.audit_rows("egress_reload").last().unwrap()["detail"]["result"], "proxy-gone");
        // The proxy commands refuse before they act (exit 1: the state file is stale).
        for args in [&["proxy", "stop", "--yes"][..], &["proxy", "start"], &["proxy", "patch"]] {
            let o = t.run(args);
            assert!(code(&o) == 1 && stderr(&o).contains(gone), "{state} {args:?}: {}", stderr(&o));
            assert!(!t.has_op("ec2 stop-instances") && !t.has_op("ec2 start-instances") && !t.has_op("ssm send-command"), "{state} {args:?}: {:?}", t.ops());
        }
        let o = t.run(&["egress", "status"]);
        assert!(code(&o) == 1 && row(&o, "proxy-instance").starts_with("DRIFT") && row(&o, "proxy-instance").contains("no longer exists"), "{state}: {}", stdout(&o));
        for f in ["ec2.describe-instances.rc", "ec2.describe-instances.stderr"] {
            t.remove_answer(f);
        }
        t.restore("ec2.describe-instances.json");
    }
}

#[test]
fn suspend_and_restore() {
    let t = Eg::new();
    t.reload_proves("suspended", &format!("{SUSPENDED_HEADER}example.com\n"));
    let o = t.run(&["egress", "suspend", "Example.COM"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(t.param("suspended"), format!("{SUSPENDED_HEADER}example.com\n"));
    assert!(stdout(&o).contains("suspended example.com"), "{}", stdout(&o));
    t.reload_proves("suspended", &format!("{SUSPENDED_HEADER}api.anthropic.com\nexample.com\n"));
    assert_eq!(code(&t.run(&["egress", "suspend", "api.anthropic.com"])), 0);
    assert_eq!(t.param("suspended"), format!("{SUSPENDED_HEADER}api.anthropic.com\nexample.com\n"));
    t.reload_answer(0, "", APPLIED);
    let o = t.run(&["egress", "suspend", "api.anthropic.com", "--restore"]);
    assert!(code(&o) == 0 && stdout(&o).contains("restored api.anthropic.com: an allowlist lists it"), "{}", stdout(&o));
    let o = t.run(&["egress", "suspend", "example.com", "--restore"]);
    assert!(code(&o) == 0 && stdout(&o).contains("restored example.com; it is in no allowlist") && !stdout(&o).contains("the proxy"), "{}", stdout(&o));
    assert_eq!(t.param("suspended"), SUSPENDED_HEADER);
    let actions: Vec<(String, String)> = t.audit_rows("egress_suspend").iter().map(|r| (r["detail"]["host"].as_str().unwrap().to_string(), r["detail"]["action"].as_str().unwrap().to_string())).collect();
    assert_eq!(actions, [("example.com".into(), "suspend".into()), ("api.anthropic.com".into(), "suspend".into()), ("api.anthropic.com".into(), "restore".into()), ("example.com".into(), "restore".into())]);
    assert_eq!(t.audit_rows("egress_reload").len(), 4);
    // A failed reload after a suspension: the host is still served.
    t.reload_answer(2, "", "ai-env-proxy-reload: fetch failed; nothing changed\n");
    let o = t.run(&["egress", "suspend", "example.com"]);
    assert!(code(&o) == 7 && has_line(&o, STILL_ALLOWED) && stderr(&o).contains("could not fetch its parameters"), "{}", stderr(&o));
    // After a restore: exit 7, the host stays suspended (closed), no removal line.
    let o = t.run(&["egress", "suspend", "example.com", "--restore"]);
    assert!(code(&o) == 7 && !stderr(&o).contains("STILL ALLOWED"), "{}", stderr(&o));
}

#[test]
fn reload_maps_the_script_exit_and_audits_the_result() {
    let t = Eg::new();
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 0 && stdout(&o).contains(&format!("proxy {INSTANCE}: applied")), "{}\n{}", stdout(&o), stderr(&o));
    let send = t.calls().into_iter().find(|l| l.starts_with("ssm send-command")).unwrap();
    assert!(send.contains(RELOAD_SCRIPT) && send.contains("--timeout-seconds 60 "), "{send}");
    t.reload_answer(0, "", "ai-env-proxy-reload: parameters unchanged since the last apply; nothing to do\n");
    let o = t.run(&["egress", "reload", "--if-changed"]);
    assert!(code(&o) == 0 && stdout(&o).contains("unchanged since the last apply"), "{}", stdout(&o));
    let send = t.calls().into_iter().find(|l| l.starts_with("ssm send-command")).unwrap();
    assert!(send.contains(r#""commands":["/usr/local/sbin/ai-env-proxy-reload --if-changed"]"#), "{send}");
    t.reload_answer(1, "", "ai-env-proxy-reload: refused; the running config is unchanged\n");
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 7 && stderr(&o).contains("the proxy kept its old config") && !has_line(&o, STATE_UNKNOWN), "{}", stderr(&o));
    t.reload_answer(2, "", "ai-env-proxy-reload: fetch failed; nothing changed\n");
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 7 && stderr(&o).contains("could not fetch its parameters") && !has_line(&o, STATE_UNKNOWN), "{}", stderr(&o));
    t.reload_answer(3, "", "ai-env-proxy-reload: install failed, rollback failed\n");
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 7 && has_line(&o, STATE_UNKNOWN), "{}", stderr(&o));
    // Applied only on Success and exit 0: a timeout is unknown.
    t.invocation_as("ssm.get-command-invocation.json", "TimedOut", 0, "", "");
    let o = t.run(&["egress", "reload"]);
    assert!(code(&o) == 7 && has_line(&o, STATE_UNKNOWN) && stderr(&o).contains("TimedOut"), "{}", stderr(&o));
    let results: Vec<String> = t.audit_rows("egress_reload").iter().map(|r| r["detail"]["result"].as_str().unwrap().to_string()).collect();
    assert_eq!(results, ["applied", "unchanged", "refused", "fetch-failed", "state-unknown", "state-unknown"]);
    // The command keeps being polled while it runs (pending, then in progress, then done).
    t.reload_answer(0, "", APPLIED);
    t.answer("ssm.get-command-invocation.1.json", &json!({"CommandId": "0b1c2d3e-0000-4000-8000-000000000001", "InstanceId": INSTANCE, "Status": "Pending", "StatusDetails": "Pending", "ResponseCode": -1}));
    t.answer("ssm.get-command-invocation.2.json", &json!({"CommandId": "0b1c2d3e-0000-4000-8000-000000000001", "InstanceId": INSTANCE, "Status": "InProgress", "StatusDetails": "InProgress", "ResponseCode": -1}));
    let o = t.run(&["egress", "reload"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(t.ops().iter().filter(|op| *op == "ssm get-command-invocation").count(), 3);
}

#[test]
fn env_prints_the_proxy_environment_without_any_call() {
    let t = Eg::new();
    let o = t.run(&["egress", "env"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let url = "http://10.42.0.10:3128";
    assert_eq!(stdout(&o), format!("https_proxy={url}\nHTTPS_PROXY={url}\nhttp_proxy={url}\nHTTP_PROXY={url}\nno_proxy=localhost,127.0.0.1,::1\nNO_PROXY=localhost,127.0.0.1,::1\n"));
    let o = t.run(&["egress", "env", "--shell"]);
    assert_eq!(stdout(&o).lines().next(), Some(format!("export https_proxy='{url}'").as_str()));
    assert_eq!(stdout(&o).lines().last(), Some("export NO_PROXY='localhost,127.0.0.1,::1'"));
    assert!(t.calls().is_empty(), "{:?}", t.calls());
    // [aws].proxy_private_ip wins; without it the state's; without state the stack's constant.
    let toml = fs::read_to_string(t.w.bridge().join("bridge.toml")).unwrap();
    fs::write(t.w.bridge().join("bridge.toml"), toml.replacen("[aws]\n", "[aws]\nproxy_private_ip = \"10.42.0.99\"\n", 1)).unwrap();
    assert!(stdout(&t.run(&["egress", "env"])).starts_with("https_proxy=http://10.42.0.99:3128\n"));
    fs::write(t.w.bridge().join("bridge.toml"), &toml).unwrap();
    t.write_state(|s| s.proxy_private_ip = Some("10.42.0.11".into()));
    assert!(stdout(&t.run(&["egress", "env"])).starts_with("https_proxy=http://10.42.0.11:3128\n"));
    fs::remove_file(t.w.bridge().join("state/infra.toml")).unwrap();
    assert!(stdout(&t.run(&["egress", "env"])).starts_with("https_proxy=http://10.42.0.10:3128\n"));
    fs::write(t.w.bridge().join("bridge.toml"), toml.replacen("[aws]\n", "[aws]\nproxy_private_ip = \"8.8.8.8\"\n", 1)).unwrap();
    let o = t.run(&["egress", "env"]);
    assert!(code(&o) == 1 && stderr(&o).contains("proxy_private_ip"), "{}", stderr(&o));
}

fn vm_row(n: u64, egress: &str, status: RowStatus, wall_in: i64) -> VmRow {
    let now = ai_env_cli::wire::time::unix_now();
    VmRow {
        status,
        id: format!("microvm-22222222-0000-4000-8000-{n:012x}"),
        client_token: format!("33333333-0000-4000-8000-{n:012x}"),
        image_arn: ai_env_cli::bridge::api::FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        owner: "test@host".into(),
        created: "2026-10-01T10:00:00.000Z".into(),
        started_at: Some(now - 60),
        wall_deadline: Some(now.saturating_add_signed(wall_in)),
        max_duration_s: 3600,
        egress: egress.into(),
        ..VmRow::default()
    }
}

#[test]
fn proxy_stop_refuses_while_any_row_may_run_a_vpc_vm_then_waits_for_stopped() {
    let t = Eg::new();
    let paths = t.paths();
    t.instance_state("ec2.describe-instances.1.json", "running");
    t.instance_state("ec2.describe-instances.2.json", "stopping");
    t.instance_state("ec2.describe-instances.3.json", "stopped");
    // Not counted: an internet VM, a terminated vpc row.
    registry::write_row(&paths, &vm_row(1, "internet", RowStatus::Running, 3000)).unwrap();
    registry::write_row(&paths, &vm_row(2, "vpc", RowStatus::Terminated, 3000)).unwrap();
    let o = t.run(&["proxy", "stop"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(t.ops(), ["sts get-caller-identity", "ec2 describe-instances", "ec2 stop-instances", "ec2 describe-instances", "ec2 describe-instances"]);
    assert!(stdout(&o).contains(&format!("proxy {INSTANCE}: stopped")), "{}", stdout(&o));
    // Counted, each refused before any aws call and named: running, past its wall (the registry may lag), suspended, pending, unreadable.
    let past = vm_row(3, "vpc", RowStatus::Running, -10);
    let suspended = vm_row(4, "vpc", RowStatus::Suspended, 3000);
    let pending = VmRow { id: String::new(), status: RowStatus::Pending, wall_deadline: None, started_at: None, ..vm_row(5, "vpc", RowStatus::Pending, 0) };
    let running = vm_row(6, "vpc", RowStatus::Running, 3000);
    let mut names = Vec::new();
    for r in [&past, &suspended, &running] {
        registry::write_row(&paths, r).unwrap();
        names.push(r.id.clone());
    }
    registry::write_pending(&paths, &pending).unwrap();
    names.push(pending.stem());
    fs::write(paths.vms().join("microvm-22222222-0000-4000-8000-000000000007.toml"), "status = [not toml").unwrap();
    names.push("microvm-22222222-0000-4000-8000-000000000007 (unreadable)".into());
    let o = t.run(&["proxy", "stop"]);
    assert_eq!(code(&o), 9, "{}", stderr(&o));
    for n in &names {
        assert!(stderr(&o).contains(n.as_str()), "{n}: {}", stderr(&o));
    }
    assert!(stderr(&o).contains("5 row(s)") && stderr(&o).contains("--yes") && !stderr(&o).contains("000000000001") && !stderr(&o).contains("000000000002"), "{}", stderr(&o));
    assert!(t.calls().is_empty(), "{:?}", t.calls());
    let o = t.run(&["proxy", "stop", "--yes"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(t.calls()[2].starts_with(&format!("ec2 stop-instances --instance-ids {INSTANCE} ")), "{:?}", t.calls());
    let audit = t.audit_rows("proxy_stop");
    assert_eq!((audit.len(), audit[1]["detail"]["vpc_vms"].as_str()), (2, Some("5")));
    // It never gets to stopped: bounded, exit 7.
    for n in 1..=3 {
        t.remove_answer(&format!("ec2.describe-instances.{n}.json"));
    }
    t.proxy("stopping");
    let o = t.run(&["proxy", "stop", "--yes"]);
    assert!(code(&o) == 7 && stderr(&o).contains("is not stopped after"), "{}", stderr(&o));
    assert_eq!(t.ops().iter().filter(|op| *op == "ec2 describe-instances").count(), 61, "the live check, then bounded");
}

#[test]
fn proxy_start_waits_for_running_then_ssm_then_squid_serving() {
    let t = Eg::new();
    t.instance_state("ec2.describe-instances.1.json", "stopped");
    t.instance_state("ec2.describe-instances.2.json", "pending");
    t.instance_state("ec2.describe-instances.3.json", "running");
    t.answer("ssm.describe-instance-information.1.json", &json!({"InstanceInformationList": []}));
    // Right after the start SSM refuses the command once; then squid is active with an older config; then it serves.
    t.answer("ssm.send-command.1.rc", &json!(254));
    fs::write(t.answers.join("ssm.send-command.1.stderr"), "\nAn error occurred (InvalidInstanceId) when calling the SendCommand operation: Instances not in a valid state for account\n").unwrap();
    t.invocation("ssm.get-command-invocation.1.json", 0, &format!("{}\n", t.status_line(" applied=no")), "");
    t.status_answer(" applied=yes");
    let o = t.run(&["proxy", "start"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(
        t.ops(),
        [
            "sts get-caller-identity",
            "ec2 describe-instances",
            "ec2 start-instances",
            "ec2 describe-instances",
            "ec2 describe-instances",
            "ssm describe-instance-information",
            "ssm describe-instance-information",
            "ssm send-command",
            "ssm send-command",
            "ssm get-command-invocation",
            "ssm send-command",
            "ssm get-command-invocation"
        ]
    );
    assert!(t.calls().iter().filter(|l| l.starts_with("ssm send-command")).all(|l| l.contains(r#""commands":["/usr/local/sbin/ai-env-proxy-reload --status"]"#)));
    assert!(stdout(&o).contains("running, SSM Online") && stdout(&o).contains("applied=yes"), "{}", stdout(&o));
    assert_eq!(t.audit_rows("proxy_start").len(), 1);
    // squid never serves (a refused boot reload keeps it stopped): bounded, exit 7.
    for f in ["ec2.describe-instances.1.json", "ec2.describe-instances.2.json", "ec2.describe-instances.3.json", "ssm.describe-instance-information.1.json", "ssm.get-command-invocation.1.json", "ssm.send-command.1.rc", "ssm.send-command.1.stderr"] {
        t.remove_answer(f);
    }
    t.reload_answer(0, &format!("{}\n", t.status_line(" applied=no").replace("squid=active", "squid=inactive")), "");
    let o = t.run(&["proxy", "start"]);
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert!(stderr(&o).contains("does not serve the current parameters") && stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert_eq!(t.ops().iter().filter(|op| *op == "ssm send-command").count(), 36, "bounded");
}

#[test]
fn proxy_patch_upgrades_then_restarts_squid_and_proves_it_serves() {
    let t = Eg::new();
    let before = "before: system-release-2023.6.20241010-0.amzn2023.noarch squid-6.10-1.amzn2023.0.1.aarch64";
    let after = "after: system-release-2023.9.20251001-0.amzn2023.noarch squid-6.13-1.amzn2023.0.1.aarch64";
    t.invocation("ssm.get-command-invocation.1.json", 0, &format!("{before}\nLast metadata expiration check: 0:01:02 ago.\nDependencies resolved.\nComplete!\n{after}\n"), "");
    t.status_answer(" applied=yes");
    let o = t.run(&["proxy", "patch"]);
    assert_eq!(code(&o), 0, "{}\n{}", stdout(&o), stderr(&o));
    assert_eq!(t.ops(), ["sts get-caller-identity", "ec2 describe-instances", "ssm send-command", "ssm get-command-invocation", "ssm send-command", "ssm get-command-invocation"]);
    let sends: Vec<String> = t.calls().into_iter().filter(|l| l.starts_with("ssm send-command")).collect();
    // The newest release's security updates (the AMI's locked release alone has none), the release and squid before and after, then the restart.
    assert!(
        sends[0].contains(r#""commands":["set -e","echo \"before: $(rpm -q system-release) $(rpm -q squid)\"","dnf -y upgrade --security --releasever=latest","echo \"after: $(rpm -q system-release) $(rpm -q squid)\"","systemctl restart squid"]"#)
            && sends[0].contains(r#""executionTimeout":["1800"]"#),
        "{}",
        sends[0]
    );
    assert!(sends[1].contains(STATUS_SCRIPT), "{}", sends[1]);
    let out = stdout(&o);
    assert!(out.contains("before: system-release-2023.6.20241010") && out.contains("after:  system-release-2023.9.20251001") && !out.contains("unchanged") && out.contains("squid=active"), "{out}");
    assert_eq!(t.audit_rows("proxy_patch")[0]["detail"]["result"], "ok");
    // Nothing newer: said so.
    t.invocation("ssm.get-command-invocation.1.json", 0, &format!("{before}\nNothing to do.\nComplete!\n{}\n", before.replace("before:", "after:")), "");
    let o = t.run(&["proxy", "patch"]);
    assert!(code(&o) == 0 && stdout(&o).contains("(the release and squid unchanged)"), "{}", stdout(&o));
    t.invocation("ssm.get-command-invocation.1.json", 0, &format!("{before}\nComplete!\n{after}\n"), "");
    // After the restart squid runs, but not the current parameters: not done.
    t.status_answer(" applied=no");
    let o = t.run(&["proxy", "patch"]);
    assert!(code(&o) == 7 && stderr(&o).contains("does not serve the current parameters"), "{}", stderr(&o));
    // A failed upgrade: exit 7, audited.
    t.invocation("ssm.get-command-invocation.1.json", 1, "", "Error: Failed to download metadata for repo 'amazonlinux'\n");
    let o = t.run(&["proxy", "patch"]);
    assert!(code(&o) == 7 && stderr(&o).contains("Failed to download metadata"), "{}", stderr(&o));
    assert_eq!(t.audit_rows("proxy_patch")[3]["detail"]["result"], "Failed exit 1");
    // A stopped proxy is not patched.
    t.proxy("stopped");
    let o = t.run(&["proxy", "patch"]);
    assert!(code(&o) == 7 && stderr(&o).contains("`ai-env proxy start` first"), "{}", stderr(&o));
    assert!(!t.has_op("ssm send-command"));
}
