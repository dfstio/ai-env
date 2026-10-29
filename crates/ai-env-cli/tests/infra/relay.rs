//! S13 slice I: the relay instance, its reload unit and the egress changes (plans/s13-contracts.md §I-infra.6.1 and
//! 6.2), offline. infra/scripts/print-policies.ts and infra/relay-spec.ts (with policies.ts and egress-spec.ts, which
//! they import) are compiled once per test run ([`compiled`]) with infra/'s own tsc and check-policies.sh's flags, and
//! run with node; the plan check runs as `make deploy` runs it, through infra/scripts/check-plan.sh (its own compile,
//! into a `PLAN_CHECK_OUT` of the test's). The reload unit, infra/relay/reload.py, runs under the Mac's
//! `/usr/bin/python3 -I` (Q-I4) in a planted §I-infra.3.3 tree (`AI_ENV_RELAY_ROOT`, [`World`]): its aws is
//! tests/fakes/aws.sh (a Parameter Store and a bucket in files), its systemctl the logging fake [`SYSTEMCTL`]. The list
//! documents are I-R77's placeholders; every TLS pair is built at run time from parts around a low-entropy body
//! (I-R78). Nothing reaches AWS or the network, and every child runs under common's deadline.
use super::common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
/// The account every printed and planned document is built for (the documentation one).
const ACCOUNT: &str = "123456789012";

fn infra() -> PathBuf {
    Path::new(REPO).join("infra")
}

/// `cmd` to the end, its output captured, under common's deadline ([`RUN_LIMIT`]); its stdin is the caller's to set.
fn bounded(cmd: &mut Command, what: &str) -> Output {
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{what}: {e}"));
    finish(child, RUN_LIMIT, what)
}

fn all(o: &Output) -> String {
    format!("{}{}", stdout(o), stderr(o))
}

fn text(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).permissions().mode() & 0o777
}

fn executable(p: &Path, body: &str) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// ---- the TypeScript spec and documents (§I-infra.6.1) ----

/// The tsc output of scripts/print-policies.ts and relay-spec.ts, compiled once per test run with check-policies.sh's
/// flags into a directory of this process under cargo's test tmpdir.
fn compiled() -> &'static Path {
    static OUT: OnceLock<PathBuf> = OnceLock::new();
    OUT.get_or_init(|| {
        let infra = infra();
        let tsc = infra.join("node_modules/.bin/tsc");
        assert!(tsc.exists(), "{} is missing: make infra-install", tsc.display());
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("relay-tsc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let mut cmd = Command::new(&tsc);
        cmd.args(["--strict", "--target", "es2022", "--module", "commonjs", "--moduleResolution", "node", "--types", "node", "--rootDir", ".", "--outDir"])
            .arg(&out)
            .args(["scripts/print-policies.ts", "relay-spec.ts"])
            .current_dir(&infra)
            .stdin(Stdio::null());
        let o = bounded(&mut cmd, "tsc");
        assert!(o.status.success(), "tsc: {}", all(&o));
        out
    })
}

/// `node -e`: a prelude loads the compiled modules as `spec` (egress-spec), `pol` (policies) and `rs` (relay-spec), and
/// infra/egress-config.json as `cfg`; `body` prints one JSON value on stdout, which is returned.
fn node(body: &str, envs: &[(&str, &str)]) -> Value {
    let prelude = format!(
        "const path = require('path'); const fs = require('fs'); const out = {:?}; const infra = {:?};\n\
         const spec = require(path.join(out, 'egress-spec.js')), pol = require(path.join(out, 'policies.js')), rs = require(path.join(out, 'relay-spec.js'));\n\
         const cfg = spec.loadEgressConfig(path.join(infra, 'egress-config.json'));\n",
        compiled().display().to_string(),
        infra().display().to_string()
    );
    let mut cmd = Command::new("node");
    cmd.arg("-e").arg(format!("{prelude}{body}")).envs(envs.iter().copied()).stdin(Stdio::null());
    let o = bounded(&mut cmd, "node");
    assert!(o.status.success(), "node: {}", all(&o));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("node printed no JSON ({e}): {}", all(&o)))
}

/// print-policies.js for [`ACCOUNT`] and infra/'s parameter files (every stack id the printer's placeholder), `args` added.
fn pp(args: &[&str]) -> String {
    let infra = infra();
    let mut cmd = Command::new("node");
    cmd.arg(compiled().join("scripts/print-policies.js"))
        .args(["--account-id", ACCOUNT, "--image-config"])
        .arg(infra.join("image-config.json"))
        .arg("--egress-config")
        .arg(infra.join("egress-config.json"))
        .args(args)
        .stdin(Stdio::null());
    let o = bounded(&mut cmd, "print-policies");
    assert!(o.status.success(), "print-policies {args:?}: {}", all(&o));
    stdout(&o)
}

/// The printed document `name`, parsed.
fn document(name: &str) -> Value {
    serde_json::from_str(pp(&["--name", name]).trim()).unwrap()
}

/// `d`'s statement `sid`.
fn statement<'a>(d: &'a Value, sid: &str) -> &'a Value {
    d["Statement"].as_array().unwrap().iter().find(|s| s["Sid"] == sid).unwrap_or_else(|| panic!("no statement {sid}: {d}"))
}

/// A policy element (`Action`, `Resource`) as a list: an array, or one string.
fn list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

/// I-T1: the spec takes the relay; each wider path is refused with its rule's text: the VM group's relay rule widened
/// or moved to 443, the relay's private port open to the internet, port 22, the relay group or the NACL short of a rule,
/// the NACL's relay entry widened, and every relay value of the config that I-R2 or I-R8 refuses.
#[test]
fn the_egress_spec_takes_the_relay_and_refuses_wider_paths() {
    let configs: [(&str, Value, &str); 12] = [
        ("relayIp", json!("10.42.1.20"), "relayIp 10.42.1.20 is not inside proxySubnetCidr 10.42.0.0/24 (the relay shares the proxy's subnet and route)"),
        ("relayIp", json!("10.42.0.2"), "relayIp 10.42.0.2 is reserved by AWS (the first four addresses of the subnet)"),
        ("relayIp", json!("10.42.0.255"), "relayIp 10.42.0.255 is the subnet's broadcast address (reserved by AWS)"),
        ("relayIp", json!("10.42.0.10"), "relayIp and proxyIp must differ (10.42.0.10)"),
        ("relayPort", json!(443), "relayPort 443 must be an unprivileged port (1024–65535) other than proxyPort 3128"),
        ("relayPort", json!(3128), "relayPort 3128 must be an unprivileged port (1024–65535) other than proxyPort 3128"),
        ("relayPort", json!(22), "relayPort 22 must be an unprivileged port (1024–65535) other than proxyPort 3128"),
        (
            "relayParameterPrefix",
            json!("/ai-env/proxy/relay"),
            "relayParameterPrefix /ai-env/proxy/relay must be an absolute /a/b path outside /aws and /ssm, without a trailing /, neither inside parameterPrefix /ai-env/proxy nor containing it (the proxy's role reads /ai-env/proxy/*)",
        ),
        (
            "relayParameterPrefix",
            json!("/ai-env"),
            "relayParameterPrefix /ai-env must be an absolute /a/b path outside /aws and /ssm, without a trailing /, neither inside parameterPrefix /ai-env/proxy nor containing it (the proxy's role reads /ai-env/proxy/*)",
        ),
        ("relayLogGroup", json!("/ai-env/egress/squid"), "relayLogGroup /ai-env/egress/squid must be an absolute /a/b path other than logGroup"),
        ("relayLogRetentionDays", json!(10), "relayLogRetentionDays 10 is not a CloudWatch Logs retention"),
        ("relaySecurityGroupName", json!("ai-env-proxy-x"), "no security group name may prefix another (rule names are <sg name>-…)"),
    ];
    let cases = Value::Array(configs.iter().map(|(k, v, _)| json!([k, v])).collect()).to_string();
    let r = node(
        r#"const allow = spec.readAllowText(path.join(infra, 'proxy'));
const refused = (s) => { try { spec.assertEgressSpec(s, allow); return ''; } catch (e) { return e.message; } };
const edited = (f) => { const s = spec.egressSpec(cfg); f(s); return refused(s); };
const relay = (s) => s.securityGroups.relay.rules;
console.log(JSON.stringify({
  spec: refused(spec.egressSpec(cfg)),
  edits: {
    'the VM relay rule to 10.42.0.0/24': edited((s) => { s.securityGroups.vm.rules[1].peer = { cidr: '10.42.0.0/24' }; }),
    'a VM rule TCP 443 to 10.42.0.20/32': edited((s) => { s.securityGroups.vm.rules[1].port = 443; }),
    'the relay private ingress from 0.0.0.0/0': edited((s) => { relay(s)[1].peer = { cidr: '0.0.0.0/0' }; }),
    'a relay rule on port 22': edited((s) => { relay(s).push({ direction: 'ingress', protocol: 'tcp', port: 22, peer: { cidr: '0.0.0.0/0' }, description: 'ssh' }); }),
    'the relay group without its DNS rules': edited((s) => { s.securityGroups.relay.rules = relay(s).filter((r) => r.port !== 53); }),
    'the NACL without the relay ingress entry': edited((s) => { s.nacl.ingress = s.nacl.ingress.filter((r) => r.ruleNo !== 110); }),
    'the NACL relay egress entry to 10.42.0.0/16': edited((s) => { s.nacl.egress.find((r) => r.ruleNo === 110).cidr = '10.42.0.0/16'; }),
  },
  configs: JSON.parse(process.env.RT_CASES).map(([k, v]) => refused(spec.egressSpec({ ...cfg, [k]: v }))),
}));"#,
        &[("RT_CASES", &cases)],
    );
    assert_eq!(r["spec"], "", "the spec with the relay passes");
    for (edit, want) in [
        ("the VM relay rule to 10.42.0.0/24", "the VM security group allows exactly two rules, egress TCP 3128 to 10.42.0.10/32 and TCP 7443 to 10.42.0.20/32"),
        ("a VM rule TCP 443 to 10.42.0.20/32", "the VM security group allows exactly two rules"),
        ("the relay private ingress from 0.0.0.0/0", "the relay security group allows only TCP 443 from 0.0.0.0/0, TCP 7443 from the VM security group"),
        ("a relay rule on port 22", "no port 22"),
        ("the relay group without its DNS rules", "the relay security group must have exactly 7 distinct rules"),
        ("the NACL without the relay ingress entry", "the VM subnet's network ACL must allow exactly two ingress rules"),
        ("the NACL relay egress entry to 10.42.0.0/16", "the VM subnet's network ACL must allow exactly two egress rules"),
    ] {
        let got = r["edits"][edit].as_str().unwrap();
        assert!(got.contains(want), "{edit}: want {want:?} in {got:?}");
    }
    for ((k, v, want), got) in configs.iter().zip(r["configs"].as_array().unwrap()) {
        let got = got.as_str().unwrap();
        assert!(got.contains(want), "{k} {v}: want {want:?} in {got:?}");
    }
}

/// I-T2: the VM subnet's NACL is compared as a set per direction (the provider's order is not the program's): I-R5's
/// entries pass in either order; a third entry, a missing one, rule 120 for 110 and a narrower ephemeral range are refused.
#[test]
fn check_nacl_compares_the_entries_as_a_set() {
    let r = node(
        r#"const s = spec.egressSpec(cfg);
const [i, e] = [s.nacl.ingress, s.nacl.egress];
const rev = (xs) => [...xs].reverse();
const c = (ing, eg) => spec.checkNacl(cfg, ing, eg) ?? '';
const third = { ruleNo: 120, protocol: 'tcp', action: 'allow', cidr: '10.42.0.30/32', fromPort: 1024, toPort: 65535 };
const renumbered = (xs) => xs.map((x) => (x.ruleNo === 110 ? { ...x, ruleNo: 120 } : x));
console.log(JSON.stringify({
  ordered: c(i, e), reversedIn: c(rev(i), e), reversedOut: c(i, rev(e)), reversedBoth: c(rev(i), rev(e)),
  thirdIn: c([...i, third], e), missingIn: c(i.slice(0, 1), e), renumberedIn: c(renumbered(i), e),
  narrowIn: c(i.map((x) => (x.ruleNo === 110 ? { ...x, toPort: 65534 } : x)), e),
  thirdOut: c(i, [...e, { ...third, fromPort: 443, toPort: 443 }]), missingOut: c(i, e.slice(1)), renumberedOut: c(i, renumbered(e)),
}));"#,
        &[],
    );
    let ingress = "the VM subnet's network ACL must allow exactly two ingress rules, TCP 1024-65535 from 10.42.0.10/32 (100) and from 10.42.0.20/32 (110), got ";
    let egress = "the VM subnet's network ACL must allow exactly two egress rules, TCP 3128 to 10.42.0.10/32 (100) and TCP 7443 to 10.42.0.20/32 (110), got ";
    for k in ["ordered", "reversedIn", "reversedOut", "reversedBoth"] {
        assert_eq!(r[k], "", "{k}: the same entries in another order pass");
    }
    for (k, want) in [("thirdIn", ingress), ("missingIn", ingress), ("renumberedIn", ingress), ("narrowIn", ingress), ("thirdOut", egress), ("missingOut", egress), ("renumberedOut", egress)] {
        let got = r[k].as_str().unwrap();
        assert!(got.starts_with(want), "{k}: {got}");
    }
}

/// I-T3: the endpoint's, the relay role's and its trust policy's documents for the example account are the pinned ones
/// (I-R40, I-R42, I-R43), their sizes I-R45's, in Rust (`canonical_policy_sha256`) and in TypeScript alike.
#[test]
fn the_relay_documents_of_policies_ts_are_the_pinned_ones() {
    for (name, pinned, size) in [
        ("s3-endpoint", "1e30d2178ae4648b2aca53e97c05e22c42d207c2295e1478ded56de73034cc47", 842),
        ("relay", "b48ef84bf578a98b04b86fb2580401f0987b5b5702ecf51be69c545c9a7d9cfd", 1523),
        ("relay-trust", "131984e3027c5a54ad8ffbf5d543bf4c11a2eebdb7113e021f229772960667b9", 146),
    ] {
        let printed = pp(&["--name", name]);
        let doc = printed.trim();
        assert_eq!(ai_env_cli::bridge::infra::canonical_policy_sha256(doc).unwrap(), pinned, "{name}: {doc}");
        assert_eq!(doc.chars().count(), size, "{name}'s size: {doc}");
        let ts = node("console.log(JSON.stringify(pol.canonicalPolicySha256(JSON.parse(process.env.RT_DOC))));", &[("RT_DOC", doc)]);
        assert_eq!(ts, pinned, "{name}: TypeScript's own hash");
    }
}

/// I-T4: every document the printer lists is within its IAM quota, counted as check-policies.sh counts it (managed and
/// inline 6 144, trust policies and `runtime` 2 048, the endpoint's and the bucket's 20 480): a statement too many fails
/// here, offline, before part B.
#[test]
fn every_document_fits_its_quota_offline() {
    let listed = pp(&[]);
    for line in listed.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let (name, kind) = (fields[0], fields[1]);
        let max = if name == "s3-endpoint" || name == "transcripts-bucket" {
            20_480
        } else if name == "runtime" || kind == "RESOURCE_POLICY" {
            2_048
        } else {
            6_144
        };
        let size = pp(&["--name", name]).trim().chars().count();
        assert!(size <= max, "{name}: {size} characters, over its {max}");
    }
    assert!(listed.contains("\nrelay-trust\tRESOURCE_POLICY\t") && listed.contains("\nrelay\tIDENTITY_POLICY\t"), "{listed}");
}

/// I-T5: ai-env-ops starts and stops the relay instance and reads its four non-secret parameters, and nothing more of
/// it: never the TLS pair, never a relay parameter by a wildcard, never a command or a session on the relay instance;
/// it reads the relay's log group and lists the account's addresses.
#[test]
fn ops_starts_the_relay_and_reads_its_parameters_but_the_tls_pair() {
    let ops = document("ops");
    let parameter = |p: &str| format!("arn:aws:ssm:eu-central-1:{ACCOUNT}:parameter/ai-env/relay/{p}");
    let relay = statement(&ops, "RelayInstance");
    assert_eq!((relay["Effect"].as_str(), list(&relay["Action"])), (Some("Allow"), vec!["ec2:StartInstances".to_string(), "ec2:StopInstances".to_string()]));
    assert_eq!(list(&relay["Resource"]), [format!("arn:aws:ec2:eu-central-1:{ACCOUNT}:instance/i-0123456789abcdef1")]);
    let read = statement(&ops, "ReadRelayParameters");
    assert_eq!(list(&read["Action"]), ["ssm:GetParameters"]);
    assert_eq!(list(&read["Resource"]), ["artifact", "workers", "grants", "token-signers"].map(parameter));
    for s in ops["Statement"].as_array().unwrap() {
        let sid = s["Sid"].as_str().unwrap_or("(no Sid)");
        let actions = list(&s["Action"]);
        let reaches_instances = actions.iter().any(|a| a == "ssm:SendCommand" || a == "ssm:StartSession");
        for r in list(&s["Resource"]) {
            assert!(!r.contains("/ai-env/relay/tls"), "{sid} names the TLS pair: {r}");
            assert!(!(r.contains(":parameter/ai-env/relay") && r.contains('*')), "{sid} names the relay's parameters by a wildcard: {r}");
            if reaches_instances {
                assert!(!r.contains("i-0123456789abcdef1") && !r.contains("instance/*") && r != "*", "{sid} reaches the relay instance with {actions:?}: {r}");
            }
        }
    }
    let logs = list(&statement(&ops, "ReadLogs")["Resource"]);
    let group = format!("arn:aws:logs:eu-central-1:{ACCOUNT}:log-group:/ai-env/relay");
    assert!(logs.contains(&group) && logs.contains(&format!("{group}:*")), "{logs:?}");
    assert!(list(&statement(&ops, "OpsUnscoped")["Action"]).iter().any(|a| a == "ec2:DescribeAddresses"));
}

/// I-T6: ai-env-deploy-egress lets the deployer build the relay (its address, its parameters, its log group, its
/// instance profile, the SSM agent's policy on its role, its role passed to EC2 only) and change the VM subnet's NACL
/// entries; Q-I12: the relay role's attach right is a statement of its own, the SSM agent's policy alone. `deploy` is
/// byte for byte S12's.
#[test]
fn the_deployer_can_build_the_relay_and_change_the_vm_nacl() {
    let d = document("deploy-egress");
    let iam = |rest: &str| format!("arn:aws:iam::{ACCOUNT}:{rest}");
    let network = list(&statement(&d, "Ec2EgressNetwork")["Action"]);
    for a in ["ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress", "ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry", "ec2:ReplaceNetworkAclEntry"] {
        assert!(network.iter().any(|x| x == a), "Ec2EgressNetwork without {a}");
    }
    let unscoped = list(&statement(&d, "EgressUnscoped")["Action"]);
    for a in ["ec2:DescribeAddresses", "ec2:DescribeAddressesAttribute"] {
        assert!(unscoped.iter().any(|x| x == a), "EgressUnscoped without {a}");
    }
    assert!(list(&statement(&d, "ProxyParameters")["Resource"]).contains(&format!("arn:aws:ssm:eu-central-1:{ACCOUNT}:parameter/ai-env/relay/*")));
    let logs = list(&statement(&d, "EgressLogGroup")["Resource"]);
    let group = format!("arn:aws:logs:eu-central-1:{ACCOUNT}:log-group:/ai-env/relay");
    assert!(logs.contains(&group) && logs.contains(&format!("{group}:*")), "{logs:?}");
    assert!(list(&statement(&d, "ProxyInstanceProfile")["Resource"]).contains(&iam("instance-profile/ai-env-relay")));
    let attach = statement(&d, "AttachRelayManagedPolicy");
    assert_eq!(list(&attach["Resource"]), [iam("role/ai-env-relay")]);
    assert_eq!(list(&attach["Action"]), ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]);
    assert_eq!(attach["Condition"], json!({"ArnEquals": {"iam:PolicyARN": ["arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy"]}}));
    assert!(!list(&statement(&d, "AttachManagedPolicies")["Resource"]).contains(&iam("role/ai-env-relay")), "the connector operator's policy never on the relay's role");
    let pass = statement(&d, "PassProxyRole");
    assert!(list(&pass["Resource"]).contains(&iam("role/ai-env-relay")));
    assert_eq!(pass["Condition"], json!({"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}));
    let deploy = pp(&["--name", "deploy"]);
    assert_eq!(ai_env_cli::bridge::infra::canonical_policy_sha256(deploy.trim()).unwrap(), "0a29b2cf283dd70409ef596daecbd93ada5924ee5bcf0f26ea14ce922fa644bc", "deploy gains no right");
    assert_eq!(deploy.trim().chars().count(), 5929);
}

/// The stack inventory (egress-spec.ts stackInventory) of infra/'s parameter files in each mode, type → names: `none`,
/// `firewall`, `queryLog` (firewall with the query log).
fn inventories() -> Value {
    node(
        r#"const image = JSON.parse(fs.readFileSync(path.join(infra, 'image-config.json'), 'utf-8'));
const names = { imageName: String(image.imageName), logGroup: String(image.logGroup) };
const inv = (c) => Object.fromEntries(spec.stackInventory(c, names));
console.log(JSON.stringify({ none: inv(cfg), firewall: inv({ ...cfg, dnsMode: 'firewall' }), queryLog: inv({ ...cfg, dnsMode: 'firewall', enableDnsQueryLog: true }) }));"#,
        &[],
    )
}

/// I-R9's nineteen: what S13 adds to the stack in every mode.
const RELAY_INVENTORY: [(&str, &str); 19] = [
    ("aws:s3/bucketObjectv2:BucketObjectv2", "relay-artifact"),
    ("aws:cloudwatch/logGroup:LogGroup", "relay-log-group"),
    ("aws:iam/role:Role", "ai-env-relay"),
    ("aws:iam/rolePolicy:RolePolicy", "ai-env-relay"),
    ("aws:ec2/securityGroup:SecurityGroup", "ai-env-relay"),
    ("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "ai-env-relay-from-0.0.0.0-0-tcp-443"),
    ("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "ai-env-relay-from-ai-env-vm-egress-tcp-7443"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-relay-to-0.0.0.0-0-tcp-443"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-relay-to-1.1.1.1-32-udp-53"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-relay-to-1.1.1.1-32-tcp-53"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-relay-to-9.9.9.9-32-udp-53"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-relay-to-9.9.9.9-32-tcp-53"),
    ("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule", "ai-env-vm-egress-to-10.42.0.20-32-tcp-7443"),
    ("aws:iam/rolePolicyAttachment:RolePolicyAttachment", "ai-env-relay-ssm"),
    ("aws:iam/instanceProfile:InstanceProfile", "ai-env-relay"),
    ("aws:ec2/instance:Instance", "ai-env-relay"),
    ("aws:ec2/eip:Eip", "ai-env-relay"),
    ("aws:ec2/eipAssociation:EipAssociation", "ai-env-relay"),
    ("aws:ssm/parameter:Parameter", "ai-env-relay-artifact"),
];

/// I-T7: the inventory holds I-R9's nineteen in every mode, and with the stack counts 94, 99 and 102 (S12: 75, 80, 83).
#[test]
fn the_inventory_counts_the_relay_19_more() {
    let inv = inventories();
    let total = |mode: &str| 1 + inv[mode].as_object().unwrap().values().map(|names| names.as_array().unwrap().len()).sum::<usize>();
    assert_eq!((total("none"), total("firewall"), total("queryLog")), (94, 99, 102));
    for mode in ["none", "firewall", "queryLog"] {
        for (ty, name) in RELAY_INVENTORY {
            assert!(inv[mode][ty].as_array().is_some_and(|names| names.iter().any(|n| n == name)), "{mode}: {ty} {name} missing");
        }
    }
}

/// The lines between `base64 -d <<'AIENV_RELAY_RELOAD_EOF' …` and its delimiter (reload.py.gz in base64, in which any
/// word may occur), and the rest of the user data.
fn split_reload_block(user_data: &str) -> (Vec<String>, String) {
    let (mut block, mut rest, mut inside) = (vec![], String::new(), false);
    for line in user_data.lines() {
        if inside && line != "AIENV_RELAY_RELOAD_EOF" {
            block.push(line.to_string());
            continue;
        }
        inside = line.starts_with("base64 -d <<'AIENV_RELAY_RELOAD_EOF'");
        rest.push_str(line);
        rest.push('\n');
    }
    (block, rest)
}

/// The first `@[A-Z_]+@` of `text`.
fn placeholder_in(text: &str) -> Option<String> {
    text.match_indices('@').find_map(|(i, _)| {
        let rest = &text[i + 1..];
        let n = rest.bytes().take_while(|c| c.is_ascii_uppercase() || *c == b'_').count();
        (n > 0 && rest.as_bytes().get(n) == Some(&b'@')).then(|| text[i..i + n + 2].to_string())
    })
}

/// `bytes` gunzipped (`/usr/bin/gzip -dc`).
fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("x.gz"), bytes).unwrap();
    let mut cmd = Command::new("/usr/bin/gzip");
    cmd.arg("-dc").arg(t.path().join("x.gz")).stdin(Stdio::null());
    let o = bounded(&mut cmd, "gzip -dc");
    assert!(o.status.success(), "gzip -dc: {}", stderr(&o));
    o.stdout
}

/// `dir`'s files copied into `to` (flat: the relay's directories have no subdirectory).
fn copy_dir(dir: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// `file` without its lines containing `what`.
fn drop_lines(file: &Path, what: &str) {
    let kept: String = text(file).lines().filter(|l| !l.contains(what)).map(|l| format!("{l}\n")).collect();
    std::fs::write(file, kept).unwrap();
}

fn append(file: &Path, more: &str) {
    std::fs::write(file, format!("{}{more}", text(file))).unwrap();
}

/// I-T8: the relay's user data, rendered from the tree (R's files through relayDeployDir()), fits EC2's limit, leaves
/// no placeholder, parses, and carries reload.py (gzipped, base64), the CloudWatch file and R's three files byte for
/// byte, every line slice I rests on, relay.env's lines (R's example less AI_ENV_RELAY_ID), the timers, the relay's
/// user, the swapfile, the packages and the units enabled, and no update, fetch tool or port 22. Copies are refused
/// with I-R25's texts: over the limit, a stale .gz, a placeholder in reload.py, a required line of R's missing (the
/// guard's IPv4, SYN or non-TCP rule among them), a rule ahead of the guard's holding a verdict or conntrack (each of
/// accept, return, jump, goto, queue, ct and notrack), a heredoc delimiter in R's unit, R's guard.nft missing; the
/// same words in a comment are no statement (the control).
#[test]
fn the_relay_files_render_small_whole_and_hardened() {
    let deploy = Path::new(REPO).join("crates/ai-env-relay/deploy");
    let relay_dir = infra().join("relay");
    let r = node(
        "console.log(JSON.stringify({ files: rs.renderRelayFiles(cfg, 'eu-central-1', path.join(infra, 'relay')), required: rs.RELAY_REQUIRED_LINES }));",
        &[("AI_ENV_REPO_ROOT", REPO)],
    );
    let ud = r["files"]["userData"].as_str().unwrap();
    assert!(ud.len() <= 16_384, "{} bytes", ud.len());
    assert_eq!(placeholder_in(ud), None);
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("user-data.sh"), ud).unwrap();
    let mut cmd = Command::new("/bin/bash");
    cmd.arg("-n").arg(t.path().join("user-data.sh")).stdin(Stdio::null());
    let o = bounded(&mut cmd, "bash -n");
    assert!(o.status.success(), "bash -n: {}", all(&o));

    let (block, rest) = split_reload_block(ud);
    assert!(!block.is_empty() && block.iter().all(|l| l.len() <= 76), "base64 in lines of 76: {block:?}");
    use base64::Engine as _;
    let gz = base64::engine::general_purpose::STANDARD.decode(block.concat()).unwrap();
    assert_eq!(gunzip(&gz), std::fs::read(relay_dir.join("reload.py")).unwrap(), "the embedded reload unit is reload.py");
    let unit = text(&deploy.join("ai-env-relay.service")).replace("@RELAY_IP@", "10.42.0.20").replace("@RELAY_PORT@", "7443");
    let cw = text(&relay_dir.join("cloudwatch-agent.json")).replace("@LOG_GROUP@", "/ai-env/relay");
    for (delimiter, file) in [
        ("AIENV_RELAY_UNIT_EOF", unit),
        ("AIENV_RELAY_UNIT_EOF", text(&deploy.join("ai-env-relay-guard.service"))),
        ("AIENV_RELAY_UNIT_EOF", text(&deploy.join("guard.nft"))),
        ("AIENV_RELAY_CW_EOF", cw),
    ] {
        assert!(file.ends_with('\n') && ud.contains(&format!("<<'{delimiter}'\n{file}{delimiter}\n")), "not embedded byte for byte:\n{file}");
    }
    for (file, lines) in r["required"].as_object().unwrap() {
        for want in lines.as_array().unwrap() {
            assert!(ud.lines().any(|l| l.trim() == want), "{file}'s line {want} is not a line of the user data");
        }
    }
    let example = text(&deploy.join("relay.env.example"));
    let example: Vec<&str> = example.lines().filter(|l| l.starts_with("AI_ENV_RELAY_")).collect();
    let written: Vec<&str> = rest.split('\'').filter(|w| w.starts_with("AI_ENV_RELAY_")).collect();
    assert_eq!(written.len(), 5, "{written:?}");
    for w in &written {
        assert!(example.contains(w), "relay.env's {w} is not a line of R's relay.env.example");
    }
    let unwritten: Vec<&str> = example.iter().filter(|l| !written.contains(l)).map(|l| l.split('=').next().unwrap()).collect();
    assert_eq!(unwritten, ["AI_ENV_RELAY_ID"], "R's example names nothing else");
    for line in [
        "OnBootSec=15s",
        "OnCalendar=*-*-* *:*:00",
        "AccuracySec=1s",
        "Type=oneshot",
        "EnvironmentFile=/etc/ai-env-relay/reload.env",
        "ExecStart=/usr/local/sbin/ai-env-relay-reload",
        "TimeoutStartSec=300",
        "Nice=5",
        "Wants=network-online.target",
        "After=network-online.target",
        "WantedBy=timers.target",
        "OnCalendar=Sun *-*-* 03:30:00 UTC",
        "RandomizedDelaySec=1800",
        "Persistent=true",
        "ExecStart=/usr/local/sbin/ai-env-relay-patch",
        "TimeoutStartSec=1800",
        "systemctl enable ai-env-relay-guard.service ai-env-relay.service",
        "systemctl enable --now ai-env-relay-reload.timer ai-env-relay-patch.timer logrotate.timer",
    ] {
        assert!(ud.lines().any(|l| l == line), "no line {line}");
    }
    for want in ["useradd --system", "dd if=/dev/zero of=/swapfile.new bs=1M count=512", "swapon /swapfile", "dnf -y install amazon-cloudwatch-agent logrotate nftables dnf-plugins-core"] {
        assert!(ud.contains(want), "{want}");
    }
    for never in ["dnf update", "curl", "wget", "ssh", "22"] {
        assert!(!rest.contains(never), "{never} in the user data (outside reload.py's base64)");
    }

    // The refusals, each on a copy of infra/relay and R's deploy/ with one change.
    let case = |name: &str| -> (PathBuf, PathBuf) {
        let (dir, deploy_dir) = (t.path().join(name).join("relay"), t.path().join(name).join("deploy"));
        copy_dir(&relay_dir, &dir);
        copy_dir(&deploy, &deploy_dir);
        (dir, deploy_dir)
    };
    let mut cases: Vec<(&str, PathBuf, PathBuf, String)> = vec![];
    // reload.py padded past the limit with 24 KiB of a SHA-256 chain's hex, its .gz regenerated (incompressible enough).
    let (dir, d) = case("padded");
    let mut h = Sha256::digest(b"ai-env relay padding").to_vec();
    let mut pad = String::new();
    while pad.len() < 24 * 1024 {
        pad.push_str(&format!("# {}\n", hex::encode(&h)));
        h = Sha256::digest(&h).to_vec();
    }
    append(&dir.join("reload.py"), &pad);
    let mut cmd = Command::new("/usr/bin/gzip");
    cmd.args(["-9", "-n", "-c"]).arg(dir.join("reload.py")).stdin(Stdio::null());
    let o = bounded(&mut cmd, "gzip");
    assert!(o.status.success(), "gzip: {}", stderr(&o));
    std::fs::write(dir.join("reload.py.gz"), &o.stdout).unwrap();
    cases.push(("padded", dir.clone(), d, format!("{}/user-data.sh: rendered ", dir.display())));
    let (dir, d) = case("stale-gz");
    append(&dir.join("reload.py"), "# changed\n");
    cases.push(("stale-gz", dir.clone(), d, format!("{}/reload.py.gz is not reload.py compressed: run make relay-reload-gz", dir.display())));
    let (dir, d) = case("placeholder");
    append(&dir.join("reload.py"), "# @X@\n");
    cases.push(("placeholder", dir.clone(), d, format!("{}/reload.py: holds the placeholder @X@, which nothing fills", dir.display())));
    let missing = |d: &Path, file: &str, line: &str| format!("{}/{file}: the line \"{line}\" is missing: slice I's layout or the plan's IMDS block rests on it (plans/s13-contracts.md §I-infra.4.5)", d.display());
    let (dir, d) = case("no-ip-address-deny");
    drop_lines(&d.join("ai-env-relay.service"), "IPAddressDeny=");
    cases.push(("no-ip-address-deny", dir, d.clone(), missing(&d, "ai-env-relay.service", "IPAddressDeny=169.254.0.0/16 fd00:ec2::/32")));
    let (dir, d) = case("no-user");
    drop_lines(&d.join("ai-env-relay.service"), "User=ai-env-relay");
    cases.push(("no-user", dir, d.clone(), missing(&d, "ai-env-relay.service", "User=ai-env-relay")));
    let (dir, d) = case("no-ipv4-guard");
    drop_lines(&d.join("guard.nft"), "ip daddr 169.254.0.0/16");
    cases.push(("no-ipv4-guard", dir, d.clone(), missing(&d, "guard.nft", "meta skuid \"ai-env-relay\" ip daddr 169.254.0.0/16 counter reject")));
    // §Q.8 F4's two stateless rules: the relay's user sends no SYN without ACK and no packet but TCP.
    let (dir, d) = case("no-syn-guard");
    drop_lines(&d.join("guard.nft"), "tcp flags");
    cases.push(("no-syn-guard", dir, d.clone(), missing(&d, "guard.nft", "meta skuid \"ai-env-relay\" tcp flags & (syn | ack) == syn counter reject with tcp reset")));
    let (dir, d) = case("no-non-tcp-guard");
    drop_lines(&d.join("guard.nft"), "l4proto");
    cases.push(("no-non-tcp-guard", dir, d.clone(), missing(&d, "guard.nft", "meta skuid \"ai-env-relay\" meta l4proto != tcp counter reject")));
    // Nothing may decide before the guard's rules or load conntrack: each word in a rule put first in the chain (the
    // review's `accept` to IMDS; §Q.8 F4's old `ct state new` rule).
    let weakened = |d: &Path, rule: &str, word: &str| format!("{}/guard.nft: the line \"{rule}\" holds \"{word}\": the guard takes no verdict but its chain's policy (one before the rules lets the relay's user past them) and no conntrack (§Q.8 F4) (plans/s13-contracts.md §I-infra.4.5)", d.display());
    for (name, word, rule) in [
        ("accept-first", "accept", "ip daddr 169.254.169.254 accept"),
        ("return-first", "return", "meta skuid \"ai-env-relay\" return"),
        ("jump-first", "jump", "meta skuid \"ai-env-relay\" jump allowed"),
        ("goto-first", "goto", "meta skuid \"ai-env-relay\" goto allowed"),
        ("queue-first", "queue", "meta skuid \"ai-env-relay\" queue flags bypass"),
        ("ct-state-new", "ct", "meta skuid \"ai-env-relay\" ct state new counter reject"),
        ("notrack-first", "notrack", "meta skuid \"ai-env-relay\" notrack"),
    ] {
        let (dir, d) = case(name);
        let (nft, hook) = (text(&d.join("guard.nft")), "policy accept;\n");
        assert!(nft.contains(hook), "{name}: R's guard.nft has no {hook:?}");
        std::fs::write(d.join("guard.nft"), nft.replacen(hook, &format!("{hook}        {rule}\n"), 1)).unwrap();
        cases.push((name, dir, d.clone(), weakened(&d, rule, word)));
    }
    // The control: the same words in a comment (in place of R's first, so the user data does not grow) are accepted.
    let (dir, d) = case("words-in-a-comment");
    let nft = text(&d.join("guard.nft"));
    let first = nft.lines().find(|l| l.starts_with("# ")).expect("a comment line in R's guard.nft").to_string();
    std::fs::write(d.join("guard.nft"), nft.replacen(&first, "# accept, return, jump, goto, queue, ct, notrack", 1)).unwrap();
    cases.push(("words-in-a-comment", dir, d, String::new()));
    let (dir, d) = case("delimiter");
    append(&d.join("ai-env-relay.service"), "# AIENV_RELAY_UNIT_EOF\n");
    cases.push(("delimiter", dir, d.clone(), format!("{}/ai-env-relay.service contains AIENV_RELAY_UNIT_EOF, a heredoc delimiter of user-data.sh: the embedded copy would end early", d.display())));
    let (dir, d) = case("no-guard-nft");
    std::fs::remove_file(d.join("guard.nft")).unwrap();
    cases.push(("no-guard-nft", dir, d.clone(), format!("{}/guard.nft not found (the relay's unit and IMDS guard, crates/ai-env-relay/deploy)", d.display())));
    let list = Value::Array(cases.iter().map(|(name, dir, d, _)| json!([name, dir, d])).collect()).to_string();
    let got = node(
        r#"const refusals = {};
for (const [name, dir, deploy] of JSON.parse(process.env.RT_CASES)) {
  try { rs.renderRelayFiles(cfg, 'eu-central-1', dir, deploy); refusals[name] = ''; } catch (e) { refusals[name] = e.message; }
}
console.log(JSON.stringify(refusals));"#,
        &[("RT_CASES", &list)],
    );
    for (name, _, _, want) in &cases {
        let message = got[name].as_str().unwrap();
        if *name == "padded" {
            assert!(message.starts_with(want) && message.ends_with("bytes, over EC2's 16384-byte user data limit"), "{name}: {message}");
        } else {
            assert_eq!(message, want, "{name}");
        }
    }
}

/// reload.py's list `name` (`NAME = [...]`, one line, JSON-shaped).
fn reload_py_list(name: &str) -> Vec<String> {
    let source = text(&infra().join("relay/reload.py"));
    let line = source.lines().find(|l| l.starts_with(&format!("{name} = ["))).unwrap_or_else(|| panic!("reload.py has no {name}"));
    serde_json::from_str(line.split_once(" = ").unwrap().1).unwrap()
}

/// I-T9: policies.ts's, reload.py's and Rust's parameter lists are the same five in one order, `tls` alone the secret
/// in each (the one that is neither the artifact nor a list document), and Rust's names of the three lists are the
/// worker SDK's (B-16).
#[test]
fn the_relay_parameter_lists_agree() {
    use ai_env_cli::bridge::egress::{relay_param_name, RELAY_PARAMETERS};
    let ts = node("console.log(JSON.stringify({ params: pol.RELAY_PARAMETERS, tls: pol.RELAY_TLS }));", &[]);
    let rust: Vec<String> = RELAY_PARAMETERS.iter().map(|p| p.to_string()).collect();
    let (py, lists) = (reload_py_list("PARAMETERS"), reload_py_list("LISTS"));
    assert_eq!(ts["params"], json!(rust), "policies.ts RELAY_PARAMETERS");
    assert_eq!(py, rust, "reload.py PARAMETERS");
    assert_eq!(ts["tls"], "tls", "policies.ts RELAY_TLS");
    let worker = [ai_env_worker::policy::WORKERS, ai_env_worker::policy::GRANTS, ai_env_worker::policy::TOKEN_SIGNERS];
    assert_eq!(["workers", "grants", "token-signers"].map(relay_param_name), worker.map(String::from));
    assert_eq!(lists, ["workers", "grants", "token-signers"], "reload.py LISTS");
    let secret_py: Vec<&String> = py.iter().filter(|p| *p != "artifact" && !lists.contains(p)).collect();
    assert_eq!(secret_py, ["tls"]);
    let secret_rust: Vec<&&str> = RELAY_PARAMETERS.iter().filter(|p| **p != "artifact" && !worker.contains(&relay_param_name(p).as_str())).collect();
    assert_eq!(secret_rust, [&"tls"]);
}

/// I-T10: relayArtifactValue writes exactly the four keys in their order and parseRelayArtifactValue takes it back;
/// a key not the sha256's, an uppercase sha256, another bucket prefix, an extra key, a missing one, a version with a
/// space are refused by both.
#[test]
fn the_relay_artifact_value_is_exact() {
    let r = node(
        r#"const sha = '0123456789abcdef'.repeat(4);
const good = { bucket: 'ai-env-artifacts-0000000', key: 'relay/ai-env-relay-0123456789abcdef', sha256: sha, version: '0.12.0' };
const value = (a) => { try { return rs.relayArtifactValue(a); } catch (e) { return 'refused: ' + e.message; } };
const { version, ...noVersion } = good;
const bad = {
  "a key not the sha256's": { ...good, key: 'relay/ai-env-relay-fedcba9876543210' },
  'an uppercase sha256': { ...good, sha256: sha.toUpperCase() },
  'another bucket prefix': { ...good, bucket: 'other-artifacts-0000000' },
  'an extra key': { ...good, extra: 'x' },
  'a missing key': noVersion,
  'a version with a space': { ...good, version: '0.12.0 beta' },
};
console.log(JSON.stringify({
  value: value(good), back: rs.parseRelayArtifactValue(value(good)),
  bad: Object.fromEntries(Object.entries(bad).map(([k, a]) => [k, [value(a), rs.parseRelayArtifactValue(JSON.stringify(a))]])),
}));"#,
        &[],
    );
    let want = format!(
        "{{\"bucket\":\"ai-env-artifacts-0000000\",\"key\":\"relay/ai-env-relay-0123456789abcdef\",\"sha256\":\"{}\",\"version\":\"0.12.0\"}}",
        "0123456789abcdef".repeat(4)
    );
    assert_eq!(r["value"], want.as_str());
    assert_eq!(r["back"], serde_json::from_str::<Value>(&want).unwrap());
    let bad = r["bad"].as_object().unwrap();
    assert_eq!(bad.len(), 6);
    for (what, pair) in bad {
        assert!(pair[0].as_str().is_some_and(|v| v.starts_with("refused: relay artifact: ")), "{what}: relayArtifactValue took it: {pair}");
        assert!(pair[1].is_string(), "{what}: parseRelayArtifactValue took it: {pair}");
    }
}

/// The stack's URN in the synthetic plans.
const STACK_URN: &str = "urn:pulumi:dev::ai-env::pulumi:pulumi:Stack::ai-env-dev";
/// How a preview spells a value it does not know yet (check-plan.ts UNKNOWN).
const UNKNOWN: &str = "04da6b54-80e4-46f7-96ec-b56ff0331ba9";

fn urn(ty: &str, name: &str) -> String {
    format!("urn:pulumi:dev::ai-env::{ty}::{name}")
}

/// A create step of `ty` `name`: its inputs empty (a provider's: its region), a child of the stack under its package's
/// pinned provider.
fn create(ty: &str, name: &str) -> Value {
    let u = urn(ty, name);
    let mut state = json!({"urn": u, "type": ty, "custom": true, "parent": STACK_URN, "inputs": {}, "propertyDependencies": {}});
    if ty.starts_with("pulumi:providers:") {
        state["inputs"] = json!({"region": "eu-central-1"});
    } else {
        let (package, provider) = if ty.starts_with("aws-native:") { ("aws-native", "aws-native-eu-central-1") } else { ("aws", "aws-eu-central-1") };
        state["provider"] = json!(format!("{}::{UNKNOWN}", urn(&format!("pulumi:providers:{package}"), provider)));
    }
    json!({"op": "create", "urn": u, "newState": state})
}

/// A `pulumi preview --json` plan's steps creating the whole dnsMode none inventory, then the stack.
fn inventory_plan() -> Vec<Value> {
    let inv = inventories();
    let mut steps: Vec<Value> = vec![];
    for (ty, names) in inv["none"].as_object().unwrap() {
        steps.extend(names.as_array().unwrap().iter().map(|n| create(ty, n.as_str().unwrap())));
    }
    steps.push(json!({"op": "create", "urn": STACK_URN, "newState": {"urn": STACK_URN, "type": "pulumi:pulumi:Stack", "custom": false}}));
    steps
}

/// The new state of `ty` `name`'s step, its inputs and property dependencies replaced.
fn set_state(steps: &mut [Value], ty: &str, name: &str, inputs: Value, deps: Value) {
    let u = urn(ty, name);
    let step = steps.iter_mut().find(|s| s["urn"] == u.as_str()).unwrap_or_else(|| panic!("no step {u}"));
    step["newState"]["inputs"] = inputs;
    step["newState"]["propertyDependencies"] = deps;
}

/// infra/scripts/check-plan.sh --mode none --account-id 123456789012 over the plan of `steps` on stdin, as make deploy
/// runs it, its compile under a PLAN_CHECK_OUT of its own.
fn check_plan(steps: &[Value]) -> Output {
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("plan.json");
    std::fs::write(&file, json!({"steps": steps, "diagnostics": []}).to_string()).unwrap();
    let mut cmd = Command::new("/bin/bash");
    isolate(&mut cmd, t.path());
    cmd.arg(infra().join("scripts/check-plan.sh"))
        .args(["--mode", "none", "--account-id", ACCOUNT])
        .env("PLAN_CHECK_OUT", t.path().join("out"))
        .stdin(std::fs::File::open(&file).unwrap());
    bounded(&mut cmd, "check-plan.sh")
}

/// I-T11: a plan creating every inventory entry (empty inputs: refused, exit 1) is counted whole: no type or name the
/// inventory lacks, nothing missing, the totals and the pin agreeing. Without the association's step its row is
/// missing; a second Elastic IP is not in the inventory.
#[test]
fn the_plan_check_counts_the_relay_in_a_complete_plan() {
    let steps = inventory_plan();
    let counted = |o: &Output| -> Vec<String> {
        let words = ["not in the stack inventory", "missing from the plan", "resources, expected", "the stack inventory holds"];
        stderr(o).lines().filter(|l| words.iter().any(|w| l.contains(w))).map(str::to_string).collect()
    };
    let out = check_plan(&steps);
    assert_eq!(out.status.code(), Some(1), "empty inputs are refused: {}", all(&out));
    assert_eq!(counted(&out), Vec::<String>::new(), "{}", all(&out));
    let association = urn("aws:ec2/eipAssociation:EipAssociation", "ai-env-relay");
    let without: Vec<Value> = steps.iter().filter(|s| s["urn"] != association.as_str()).cloned().collect();
    let out = check_plan(&without);
    assert!(stderr(&out).contains("aws:ec2/eipAssociation:EipAssociation: missing from the plan: ai-env-relay"), "{}", all(&out));
    let mut more = steps.clone();
    more.push(create("aws:ec2/eip:Eip", "ai-env-relay-2"));
    let out = check_plan(&more);
    assert!(stderr(&out).contains("aws:ec2/eip:Eip: not in the stack inventory: ai-env-relay-2"), "{}", all(&out));
}

/// I-T12: over I-T11's plan with the relay's own inputs as the program plans them, each widening prints its line: the
/// relay's IMDS hop limit 2, its private port open to the internet, the Elastic IP on the proxy, an artifact parameter
/// naming another key than the object's, ai-env-ops' document built without the relay instance. The plan as planned
/// prints none of them.
#[test]
fn the_plan_check_refuses_a_widened_relay() {
    const INSTANCE: &str = "aws:ec2/instance:Instance";
    const RULE: (&str, &str) = ("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "ai-env-relay-from-ai-env-vm-egress-tcp-7443");
    const ASSOCIATION: &str = "aws:ec2/eipAssociation:EipAssociation";
    const PARAMETER: &str = "aws:ssm/parameter:Parameter";
    const POLICY: &str = "aws:iam/policy:Policy";
    let (relay, proxy) = (urn(INSTANCE, "ai-env-relay"), urn(INSTANCE, "ai-env-egress-proxy"));
    let (relay_sg, vm_sg) = (urn("aws:ec2/securityGroup:SecurityGroup", "ai-env-relay"), urn("aws:ec2/securityGroup:SecurityGroup", "ai-env-vm-egress"));
    let sha = "0123456789abcdef".repeat(4);
    let artifact = |key: &str, sha: &str| json!({"bucket": "ai-env-artifacts-0000000", "key": key, "sha256": sha, "version": "0.12.0"}).to_string();
    let imds = |hops: u32| json!({"metadataOptions": {"httpTokens": "required", "httpPutResponseHopLimit": hops}});
    let parameter = |value: String| json!({"name": "/ai-env/relay/artifact", "type": "String", "tier": "Standard", "insecureValue": value});
    let mut base = inventory_plan();
    set_state(&mut base, INSTANCE, "ai-env-relay", imds(1), json!({}));
    set_state(
        &mut base,
        RULE.0,
        RULE.1,
        json!({"ipProtocol": "tcp", "fromPort": 7443, "toPort": 7443, "referencedSecurityGroupId": UNKNOWN}),
        json!({"securityGroupId": [relay_sg], "referencedSecurityGroupId": [vm_sg]}),
    );
    set_state(&mut base, ASSOCIATION, "ai-env-relay", json!({}), json!({"allocationId": [urn("aws:ec2/eip:Eip", "ai-env-relay")], "instanceId": [relay]}));
    set_state(
        &mut base,
        "aws:s3/bucketObjectv2:BucketObjectv2",
        "relay-artifact",
        json!({"key": "relay/ai-env-relay-0123456789abcdef", "contentType": "application/octet-stream", "source": {"hash": sha}}),
        json!({"bucket": [urn("aws:s3/bucket:Bucket", "ai-env-artifacts")]}),
    );
    set_state(&mut base, PARAMETER, "ai-env-relay-artifact", parameter(artifact("relay/ai-env-relay-0123456789abcdef", &sha)), json!({}));
    set_state(&mut base, POLICY, "ai-env-ops", json!({}), json!({"policy": [proxy, relay]}));

    let mut widened: Vec<(&str, Vec<Value>)> = vec![];
    let mut p = base.clone();
    set_state(&mut p, INSTANCE, "ai-env-relay", imds(2), json!({}));
    widened.push(("relay instance IMDS: [\"required\",2], expected [\"required\",1]", p));
    let mut p = base.clone();
    set_state(&mut p, RULE.0, RULE.1, json!({"ipProtocol": "tcp", "fromPort": 7443, "toPort": 7443, "cidrIpv4": "0.0.0.0/0"}), json!({"securityGroupId": [relay_sg]}));
    widened.push(("the relay security group allows only", p));
    let mut p = base.clone();
    set_state(&mut p, ASSOCIATION, "ai-env-relay", json!({}), json!({"allocationId": [urn("aws:ec2/eip:Eip", "ai-env-relay")], "instanceId": [proxy]}));
    widened.push(("instanceId depends on aws:ec2/instance:Instance::ai-env-egress-proxy, expected aws:ec2/instance:Instance::ai-env-relay", p));
    let mut p = base.clone();
    set_state(&mut p, PARAMETER, "ai-env-relay-artifact", parameter(artifact("relay/ai-env-relay-ffffffffffffffff", &"f".repeat(64))), json!({}));
    widened.push(("relay artifact parameter: key", p));
    let mut p = base.clone();
    set_state(&mut p, POLICY, "ai-env-ops", json!({}), json!({"policy": [proxy]}));
    widened.push(("policy does not depend on aws:ec2/instance:Instance::ai-env-relay", p));

    let planned = stderr(&check_plan(&base));
    for (line, _) in &widened {
        assert!(!planned.contains(line), "the plan as planned: {line}\n{planned}");
    }
    for (line, steps) in &widened {
        let out = check_plan(steps);
        assert!(out.status.code() == Some(1) && stderr(&out).contains(line), "want {line}: {}", all(&out));
    }
}

/// I-T13: renderTemplate (moved from egress.ts, LD-I14) renders in one pass (a value holding a token is not rendered
/// again), refuses a missing token, an unknown leftover and values for other tokens with S5's texts, and keeps a kept one.
#[test]
fn render_template_is_one_pass_and_refuses_leftovers() {
    let t = tempfile::tempdir().unwrap();
    for (file, body) in [("one.txt", "x=@A@ y=@B@\n"), ("missing.txt", "x=@A@\n"), ("left.txt", "x=@A@ @C@\n"), ("kept.txt", "x=@A@ @DIR@\n")] {
        std::fs::write(t.path().join(file), body).unwrap();
    }
    let dir = t.path().display().to_string();
    let r = node(
        r#"const dir = process.env.RT_DIR;
const r = (f, tokens, values, keep) => { try { return { ok: spec.renderTemplate(dir, f, tokens, values, keep) }; } catch (e) { return { err: e.message }; } };
console.log(JSON.stringify({
  onePass: r('one.txt', ['A', 'B'], { A: '@B@', B: 'bee' }, ['@B@']),
  missing: r('missing.txt', ['A', 'B'], { A: 'a', B: 'b' }),
  leftover: r('left.txt', ['A'], { A: 'a' }),
  leftoverKeeping: r('left.txt', ['A'], { A: 'a' }, ['@DIR@']),
  otherValues: r('one.txt', ['A', 'B'], { A: 'a', Z: 'z' }),
  kept: r('kept.txt', ['A'], { A: 'a' }, ['@DIR@']),
}));"#,
        &[("RT_DIR", &dir)],
    );
    assert_eq!(r["onePass"], json!({"ok": "x=@B@ y=bee\n"}), "one pass");
    assert_eq!(r["missing"], json!({"err": format!("{dir}/missing.txt: the placeholder(s) @B@ are missing (contract 3)")}));
    assert_eq!(r["leftover"], json!({"err": format!("{dir}/left.txt: unknown placeholder(s) @C@ left after rendering (none is filled later)")}));
    assert_eq!(r["leftoverKeeping"], json!({"err": format!("{dir}/left.txt: unknown placeholder(s) @C@ left after rendering (only @DIR@ is filled on the proxy)")}));
    assert_eq!(r["otherValues"], json!({"err": "egress: render one.txt: values for A, Z, expected A, B"}));
    assert_eq!(r["kept"], json!({"ok": "x=a @DIR@\n"}));
}

// ---- the reload unit (§I-infra.6.2) ----

/// The bucket the tests' artifact names (the printer's placeholder suffix).
const BUCKET: &str = "ai-env-artifacts-0000000";
/// The one `get-parameters` of every run (I-R30), as the fake aws logs it.
const GET_PARAMETERS: &str = "ssm get-parameters --names /ai-env/relay/artifact /ai-env/relay/workers /ai-env/relay/grants /ai-env/relay/token-signers /ai-env/relay/tls --with-decryption --region eu-central-1 --endpoint-url https://ssm.eu-central-1.amazonaws.com --output json";
/// The parameters published into live/, and their files.
const PUBLISHED: [(&str, &str); 4] = [("workers", "workers.json"), ("grants", "grants.json"), ("token-signers", "token-signers.json"), ("tls", "tls.pem")];
/// Everything live/ may ever hold.
const LIVE: [&str; 5] = ["fetched", "grants.json", "tls.pem", "token-signers.json", "workers.json"];
/// The binaries the artifact names in turn (any bytes: the unit only hashes them).
const V1: &[u8] = b"ai-env-relay test binary, version one\n";
const V2: &[u8] = b"ai-env-relay test binary, version two\n";
const V3: &[u8] = b"ai-env-relay test binary, version three\n";

/// A list document as I-R77 has the tests write them: a low-entropy placeholder, `n` telling them apart.
fn placeholder(n: u32) -> String {
    format!("{{\"placeholder\":\"0199a1b2-0000-7000-8000-{n:012}\"}}")
}

/// A PEM block built at run time (I-R78: no key block in any file), its body one base64 line of `body` repeated.
fn pem(label: &str, body: &str) -> String {
    let dashes = "-".repeat(5);
    format!("{dashes}BEGIN {label}{dashes}\n{}\n{dashes}END {label}{dashes}\n", body.repeat(16))
}

fn key_block(body: &str) -> String {
    pem(&["PRIVATE", "KEY"].join(" "), body)
}

/// A `tls` value as I-R31 wants it: a certificate block, then one PKCS#8 key block.
fn tls_pair(body: &str) -> String {
    format!("{}{}", pem("CERTIFICATE", body), key_block(body))
}

fn binary_name(sha16: &str) -> String {
    format!("ai-env-relay-{sha16}")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// `body` after infra/relay/reload.py is loaded as the module `m` (`/usr/bin/python3 -I -B -c`: imported, never run, so
/// nothing is fetched or written but what `body` writes, and no bytecode lands in infra/relay), in `dir`, with `args`
/// after reload.py's path in `sys.argv`; its stdout.
fn reload_module(dir: &Path, body: &str, args: &[&str]) -> String {
    let prelude = "import importlib.util, json, os, sys\n\
        spec = importlib.util.spec_from_file_location('ai_env_relay_reload', sys.argv[1])\n\
        m = importlib.util.module_from_spec(spec)\n\
        spec.loader.exec_module(m)\n";
    let mut cmd = Command::new("/usr/bin/python3");
    isolate(&mut cmd, dir);
    cmd.args(["-I", "-B", "-c"]).arg(format!("{prelude}{body}")).arg(infra().join("relay/reload.py")).args(args).current_dir(dir).env("PATH", "/usr/bin:/bin");
    let o = bounded(&mut cmd, "reload.py as a module");
    assert!(o.status.success(), "{}", all(&o));
    assert!(!infra().join("relay/__pycache__").exists(), "bytecode written into infra/relay");
    stdout(&o)
}

/// The systemctl the reload unit runs (`AI_ENV_RELAY_SYSTEMCTL`): logs `$*`; `restart` records what `current` points at;
/// `is-active` answers `FAKE_SYSTEMCTL_INITIAL` (default inactive) before any restart, then `active` (exit 0) when
/// `FAKE_SYSTEMCTL_GOOD` lists the recorded binary, else `failed` (exit 3).
const SYSTEMCTL: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
case "$1" in
  restart) readlink "$AI_ENV_RELAY_ROOT/usr/local/libexec/ai-env-relay/current" > "$FAKE_SYSTEMCTL_STATE" || : > "$FAKE_SYSTEMCTL_STATE" ;;
  is-active)
    if [ -f "$FAKE_SYSTEMCTL_STATE" ]; then
      ran=$(cat "$FAKE_SYSTEMCTL_STATE"); word=failed
      for good in ${FAKE_SYSTEMCTL_GOOD:-}; do test "$good" = "$ran" && word=active; done
    else
      word=${FAKE_SYSTEMCTL_INITIAL:-inactive}
    fi
    echo "$word"
    test "$word" = active || exit 3 ;;
esac
exit 0
"#;

/// A relay instance as its reload unit sees it: the §I-infra.3.3 tree under `root/` (AI_ENV_RELAY_ROOT), the fake
/// aws's Parameter Store (`ssm/`) and bucket (`s3/`), the systemctl fake's log and state, and every value written.
struct World {
    t: tempfile::TempDir,
    /// `FAKE_SYSTEMCTL_GOOD`: the binaries (`ai-env-relay-<sha16>`) that come up.
    good: String,
    /// Every parameter value written so far, none of which may reach a log line (I-T21).
    values: Vec<String>,
}

/// One run of the reload unit.
struct Ran {
    code: i32,
    /// Its one line (stderr, the journal's).
    line: String,
    /// This run's systemctl and aws calls.
    systemctl: Vec<String>,
    aws: Vec<String>,
    /// Unix seconds before and after it.
    from: u64,
    to: u64,
}

impl World {
    fn new() -> World {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        for d in ["etc/ai-env-relay", "usr/local/libexec/ai-env-relay", "var/lib/ai-env-relay/live", "var/lib/ai-env-relay/stage", "var/log/ai-env-relay/requests"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("etc/ai-env-relay/reload.env"), "PARAM_PREFIX=/ai-env/relay\nREGION=eu-central-1\n").unwrap();
        std::fs::create_dir_all(t.path().join("bin")).unwrap();
        executable(&t.path().join("bin/aws"), &text(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/aws.sh")));
        executable(&t.path().join("bin/systemctl"), SYSTEMCTL);
        World { t, good: String::new(), values: vec![] }
    }

    fn root(&self) -> PathBuf {
        self.t.path().join("root")
    }

    fn live(&self, file: &str) -> PathBuf {
        self.root().join("var/lib/ai-env-relay/live").join(file)
    }

    fn libexec(&self, file: &str) -> PathBuf {
        self.root().join("usr/local/libexec/ai-env-relay").join(file)
    }

    /// What `current` points at ("" when nothing).
    fn current(&self) -> String {
        std::fs::read_link(self.libexec("current")).map(|p| p.display().to_string()).unwrap_or_default()
    }

    /// What `previous` records.
    fn previous(&self) -> String {
        text(&self.root().join("var/lib/ai-env-relay/previous"))
    }

    fn parameter(&self, p: &str) -> PathBuf {
        self.t.path().join("ssm/ai-env/relay").join(p)
    }

    /// `/ai-env/relay/<p>` of the fake Parameter Store holds `value`.
    fn set(&mut self, p: &str, value: &str) {
        std::fs::create_dir_all(self.parameter(p).parent().unwrap()).unwrap();
        std::fs::write(self.parameter(p), value).unwrap();
        self.values.push(value.to_string());
    }

    fn delete(&self, p: &str) {
        std::fs::remove_file(self.parameter(p)).unwrap();
    }

    fn value(&self, p: &str) -> String {
        text(&self.parameter(p))
    }

    fn object(&self, key: &str) -> PathBuf {
        self.t.path().join("s3").join(BUCKET).join(key)
    }

    /// `bytes` as the bucket's object under its hash-keyed key, and the artifact parameter naming it; its sha16.
    fn binary(&mut self, bytes: &[u8]) -> String {
        let sha = hex::encode(Sha256::digest(bytes));
        let key = format!("relay/ai-env-relay-{}", &sha[..16]);
        std::fs::create_dir_all(self.object(&key).parent().unwrap()).unwrap();
        std::fs::write(self.object(&key), bytes).unwrap();
        self.set("artifact", &json!({"bucket": BUCKET, "key": key, "sha256": sha, "version": "0.12.0"}).to_string());
        sha[..16].to_string()
    }

    /// The three lists, the TLS pair and V1 in the bucket, V1 the binary that comes up; V1's sha16.
    fn complete(&mut self) -> String {
        for (p, n) in [("workers", 1), ("grants", 2), ("token-signers", 3)] {
            self.set(p, &placeholder(n));
        }
        self.set("tls", &tls_pair("QUFB"));
        let v1 = self.binary(V1);
        self.good = binary_name(&v1);
        v1
    }

    /// live/'s files, each with its bytes and inode (a write is a new file renamed over the old one).
    fn snapshot(&self) -> BTreeMap<String, (Vec<u8>, u64)> {
        std::fs::read_dir(self.live(""))
            .unwrap()
            .flatten()
            .map(|e| (e.file_name().to_string_lossy().to_string(), (std::fs::read(e.path()).unwrap(), e.metadata().unwrap().ino())))
            .collect()
    }

    /// One run of reload.py as its unit runs it (reload.env's two names in its environment), the test knobs set; then
    /// I-T21's check of its line and the whole reload.log.
    fn run(&mut self, envs: &[(&str, &str)]) -> Ran {
        let t = self.t.path();
        let (systemctl_log, aws_log) = (t.join("systemctl.log"), t.join("aws.log"));
        let lines = |p: &Path| -> Vec<String> { text(p).lines().map(str::to_string).collect() };
        let (systemctl_before, aws_before) = (lines(&systemctl_log).len(), lines(&aws_log).len());
        let from = now();
        let mut cmd = Command::new("/usr/bin/python3");
        isolate(&mut cmd, t);
        cmd.arg("-I")
            .arg(infra().join("relay/reload.py"))
            .env("PATH", "/usr/bin:/bin")
            .env("PARAM_PREFIX", "/ai-env/relay")
            .env("REGION", "eu-central-1")
            .env("AI_ENV_RELAY_ROOT", self.root())
            .env("AI_ENV_RELAY_AWS", t.join("bin/aws"))
            .env("AI_ENV_RELAY_SYSTEMCTL", t.join("bin/systemctl"))
            .env("AI_ENV_RELAY_WAIT_S", "2")
            .env("FAKE_AWS_SSM_DIR", t.join("ssm"))
            .env("FAKE_AWS_S3_DIR", t.join("s3"))
            .env("FAKE_AWS_LOG", &aws_log)
            .env("FAKE_AWS_PIN_ALL", "1")
            .env("FAKE_SYSTEMCTL_LOG", &systemctl_log)
            .env("FAKE_SYSTEMCTL_STATE", t.join("systemctl.state"))
            .env("FAKE_SYSTEMCTL_GOOD", &self.good)
            .envs(envs.iter().copied());
        let o = bounded(&mut cmd, "reload.py");
        let to = now();
        let line = stderr(&o);
        assert_eq!(stdout(&o), "", "the unit writes its one line to stderr: {line}");
        assert_eq!(line.lines().count(), 1, "one line per run: {line}");
        self.never_logged(&line);
        assert!(std::fs::read_dir(self.live("")).unwrap().flatten().all(|e| LIVE.contains(&e.file_name().to_string_lossy().as_ref())), "live/ holds only its five files");
        Ran {
            code: o.status.code().unwrap_or(-1),
            line: line.trim_end().to_string(),
            systemctl: lines(&systemctl_log)[systemctl_before..].to_vec(),
            aws: lines(&aws_log)[aws_before..].to_vec(),
            from,
            to,
        }
    }

    /// I-T21: neither a run's line nor reload.log holds a parameter's value, the placeholders' or the pairs' bodies, a
    /// PEM marker or a hash of a `tls` value.
    fn never_logged(&self, line: &str) {
        let log = text(&self.root().join("var/log/ai-env-relay/reload.log"));
        let mut words: Vec<String> = ["0199a1b2-0000-7000-8000", "QUFB", "QkJC", "BEGIN", "PRIVATE"].map(String::from).to_vec();
        for v in self.values.iter().filter(|v| v.len() >= 8) {
            words.push(v.clone());
            if v.contains("BEGIN") {
                let h = hex::encode(Sha256::digest(v.as_bytes()));
                words.push(h[..16].to_string());
                words.push(h);
            }
        }
        for w in &words {
            assert!(!line.contains(w.as_str()) && !log.contains(w.as_str()), "I-T21: {w:?} in a log line:\n{line}{log}");
        }
    }
}

/// I-T14: all five parameters valid: the four files published byte for byte (0640), `fetched` stamped within the run,
/// one get-parameters, the binary downloaded, hashed, installed (0755) and started; a second run writes nothing but
/// `fetched`, and neither restarts nor reloads the relay.
#[test]
fn reload_publishes_the_parameters_and_stamps_the_fetch() {
    let mut w = World::new();
    let v1 = w.complete();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    for (p, file) in PUBLISHED {
        assert_eq!(text(&w.live(file)), w.value(p), "{file}");
        assert_eq!(mode(&w.live(file)), 0o640, "{file}");
    }
    let fetched: u64 = text(&w.live("fetched")).trim().parse().unwrap();
    assert!((ran.from..=ran.to).contains(&fetched) && mode(&w.live("fetched")) == 0o640, "fetched {fetched}");
    assert_eq!(ran.aws.iter().filter(|l| l.starts_with("ssm ")).cloned().collect::<Vec<_>>(), [GET_PARAMETERS]);
    let download = w.root().join("var/lib/ai-env-relay/stage/download");
    let get = format!("s3api get-object --bucket {BUCKET} --key relay/ai-env-relay-{v1} --region eu-central-1 --endpoint-url https://s3.eu-central-1.amazonaws.com {}", download.display());
    assert!(ran.aws.contains(&get), "{:#?}", ran.aws);
    assert!(!download.exists());
    assert_eq!(w.current(), binary_name(&v1));
    assert_eq!(std::fs::read(w.libexec(&binary_name(&v1))).unwrap(), V1);
    assert_eq!(mode(&w.libexec(&binary_name(&v1))), 0o755);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reset-failed ai-env-relay.service", "restart ai-env-relay.service", "is-active ai-env-relay.service"]);
    assert!(
        ran.line.starts_with("ai-env-relay-reload: ok fetched=") && ran.line.ends_with(&format!(" changed=workers,grants,token-signers,tls absent=none artifact={v1} tls=present relay=active")),
        "{}",
        ran.line
    );

    let before: Vec<u64> = PUBLISHED.iter().map(|(_, f)| std::fs::metadata(w.live(f)).unwrap().ino()).collect();
    let again = w.run(&[]);
    assert_eq!(again.code, 0, "{}", again.line);
    assert_eq!(PUBLISHED.iter().map(|(_, f)| std::fs::metadata(w.live(f)).unwrap().ino()).collect::<Vec<_>>(), before, "nothing written but fetched");
    assert_eq!(again.systemctl, ["is-active ai-env-relay.service"], "neither a restart nor a reload");
    assert!(!again.aws.iter().any(|l| l.starts_with("s3api")), "the installed binary is not fetched again");
    assert!(again.line.contains(" changed=none absent=none "), "{}", again.line);

    // A state directory gone is made again in §3.3's modes, not the unit's umask (077): itself and live/ 0750, stage/ 0700.
    let state = w.root().join("var/lib/ai-env-relay");
    std::fs::remove_dir_all(&state).unwrap();
    let third = w.run(&[]);
    assert_eq!(third.code, 0, "{}", third.line);
    assert_eq!([mode(&state), mode(&state.join("live")), mode(&state.join("stage"))], [0o750, 0o750, 0o700]);
    assert_eq!(text(&w.live("workers.json")), w.value("workers"), "published again");
}

/// I-T15: a list document deleted from SSM is removed from live/ (the relay told to reload), as is an invalid one (the
/// run then fails, naming it): `{`, a 4097-byte value, a value with a NUL. A removed whitelist never stays in force.
#[test]
fn reload_removes_a_deleted_authorization_document_and_an_invalid_one() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    w.delete("workers");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(!w.live("workers.json").exists() && ran.line.contains(" changed=workers absent=workers "), "{}", ran.line);
    assert!(ran.systemctl.contains(&"reload ai-env-relay.service".to_string()), "{:?}", ran.systemctl);
    w.set("grants", "{");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(!w.live("grants.json").exists() && ran.line.contains(" why=grants: not JSON"), "{}", ran.line);
    w.set("grants", &placeholder(2));
    assert_eq!(w.run(&[]).code, 0);
    for (value, why) in [(format!("[{}0]", "0,".repeat(2047)), "token-signers: over 4096 bytes"), (format!("{}\u{0}", placeholder(3)), "token-signers: not printable ASCII")] {
        w.set("token-signers", &placeholder(3));
        assert_eq!(w.run(&[]).code, 0);
        assert!(w.live("token-signers.json").exists());
        w.set("token-signers", &value);
        let ran = w.run(&[]);
        assert_eq!(ran.code, 1, "{}", ran.line);
        assert!(!w.live("token-signers.json").exists() && ran.line.contains(&format!(" why={why}")), "{why}: {}", ran.line);
    }
}

/// I-T16: an invalid new pair (no key block, two key blocks, a certificate after the key) leaves tls.pem as it was and
/// fails the run; a deleted pair is removed and the relay waits for one (no start); a new valid pair replaces the file
/// and reloads the relay. live/ never holds a certificate or a key of its own ([`World::run`]).
#[test]
fn reload_keeps_the_tls_pair_whole() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let pair = text(&w.live("tls.pem"));
    let (cert, key) = (pem("CERTIFICATE", "QUFB"), key_block("QUFB"));
    for (what, value) in [("no key block", cert.clone()), ("two key blocks", format!("{cert}{key}{key}")), ("a certificate after the key", format!("{cert}{key}{cert}"))] {
        w.set("tls", &value);
        let ran = w.run(&[]);
        assert_eq!(ran.code, 1, "{what}: {}", ran.line);
        assert_eq!(text(&w.live("tls.pem")), pair, "{what}: tls.pem unchanged");
        assert!(ran.line.contains(" why=tls: not certificates then one PKCS#8 key block"), "{what}: {}", ran.line);
    }
    w.delete("tls");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(!w.live("tls.pem").exists() && ran.line.ends_with(" tls=absent relay=waiting-for-tls"), "{}", ran.line);
    assert!(!ran.systemctl.iter().any(|c| c.starts_with("restart ") || c.starts_with("start ")), "no start: {:?}", ran.systemctl);
    let renewed = tls_pair("QkJC");
    w.set("tls", &renewed);
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(text(&w.live("tls.pem")), renewed);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);
}

/// I-T17: a binary is installed only when its SHA-256 is the parameter's: another object's bytes, an object over 64
/// MiB and a missing object each install nothing and fail the run; a good one is installed 0755 under its sha16,
/// `current` switched to it and `previous` naming the old one, through one pinned `s3api get-object`.
#[test]
fn reload_installs_a_new_binary_only_with_its_hash() {
    let mut w = World::new();
    let v1 = w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let v2 = w.binary(V2);
    let object = w.object(&format!("relay/ai-env-relay-{v2}"));
    let download = w.root().join("var/lib/ai-env-relay/stage/download");
    let get = format!("s3api get-object --bucket {BUCKET} --key relay/ai-env-relay-{v2} --region eu-central-1 --endpoint-url https://s3.eu-central-1.amazonaws.com {}", download.display());
    for what in ["another object's bytes", "an object over 64 MiB", "no object"] {
        let why = match what {
            "another object's bytes" => {
                std::fs::write(&object, V1).unwrap();
                "the artifact's SHA-256 is not the parameter's: nothing installed"
            }
            "an object over 64 MiB" => {
                std::fs::File::create(&object).unwrap().set_len((64 << 20) + 1).unwrap();
                "the artifact is over 64 MiB: nothing installed"
            }
            _ => {
                std::fs::remove_file(&object).unwrap();
                "get-object: An error occurred (NoSuchKey)"
            }
        };
        let ran = w.run(&[]);
        assert_eq!(ran.code, 1, "{what}: {}", ran.line);
        assert!(ran.line.contains(why) && ran.line.contains(": nothing installed"), "{what}: {}", ran.line);
        assert_eq!(ran.aws.iter().filter(|l| l.starts_with("s3api")).cloned().collect::<Vec<_>>(), std::slice::from_ref(&get), "{what}");
        assert_eq!(w.current(), binary_name(&v1), "{what}: current unchanged");
        assert!(!w.libexec(&binary_name(&v2)).exists() && !download.exists(), "{what}: nothing installed");
    }
    std::fs::write(&object, V2).unwrap();
    w.good = format!("{} {}", binary_name(&v1), binary_name(&v2));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(std::fs::read(w.libexec(&binary_name(&v2))).unwrap(), V2);
    assert_eq!(mode(&w.libexec(&binary_name(&v2))), 0o755);
    assert_eq!((w.current(), w.previous()), (binary_name(&v2), format!("{}\n", binary_name(&v1))));
    assert!(ran.line.ends_with(&format!(" artifact={v2} tls=present relay=active")), "{}", ran.line);

    // The cap holds while the download is written (RLIMIT_FSIZE in the child), so an object over it never fills the
    // disk: a writer of 5000 bytes under a cap of 1001 stops there, and fails.
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("object"), [b'a'; 5000]).unwrap();
    let capped = reload_module(t.path(), "code, _, _ = m.call(['/bin/sh', '-c', 'cat object > download'], 10, 1001)\nprint(json.dumps([code, os.path.getsize('download')]))", &[]);
    let capped: Value = serde_json::from_str(capped.trim()).unwrap();
    assert!(capped[0] != 0 && capped[1] == 1001, "{capped}");
}

/// I-T18: a new binary that does not come up within the wait is rolled back to the old one (restarted again, the run
/// failed, `rollback=<old sha16>`) and refused; with neither coming up the relay is `failed`, the old binary restarted
/// alone. A binary beyond `current` and `previous` is removed only after a run that succeeded: here the next
/// artifact's, which is tried.
#[test]
fn reload_rolls_back_a_binary_that_does_not_start() {
    let mut w = World::new();
    let v1 = w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let stale = w.libexec("ai-env-relay-00000000000000aa");
    std::fs::write(&stale, b"an older relay").unwrap();
    let v2 = w.binary(V2);
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.ends_with(&format!(" relay=active rollback={v1} why=the new binary did not come up: rolled back")), "{}", ran.line);
    assert_eq!(ran.systemctl.iter().filter(|c| *c == "restart ai-env-relay.service").count(), 2, "{:?}", ran.systemctl);
    assert!(w.current() == binary_name(&v1) && w.libexec(&binary_name(&v2)).exists(), "back on the old binary");
    assert!(stale.exists(), "nothing pruned after a failed run");
    w.good = String::new();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.contains(" relay=failed ") && !ran.line.contains(" rollback="), "{}", ran.line);
    assert_eq!(ran.systemctl.iter().filter(|c| *c == "restart ai-env-relay.service").count(), 1, "the old binary alone: {:?}", ran.systemctl);
    assert!(w.current() == binary_name(&v1) && stale.exists());
    let v3 = w.binary(V3);
    w.good = format!("{} {}", binary_name(&v1), binary_name(&v3));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!((w.current(), w.previous()), (binary_name(&v3), format!("{}\n", binary_name(&v1))));
    assert!(!stale.exists() && !w.libexec(&binary_name(&v2)).exists() && w.libexec(&binary_name(&v1)).exists(), "pruned to current and previous");
}

/// I-T54: a binary rolled back is refused until the artifact names another: the runs after the rollback download
/// nothing, switch nothing and leave the old binary running (each fails, naming the refused one; a changed list still
/// reaches the relay); a binary the artifact names next is tried, and its success ends the refusal.
#[test]
fn reload_never_switches_again_to_a_binary_it_rolled_back() {
    let mut w = World::new();
    let v1 = w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let v2 = w.binary(V2);
    let ran = w.run(&[]);
    assert!(ran.code == 1 && ran.line.contains(&format!(" rollback={v1} ")), "{}", ran.line);
    let state = w.root().join("var/lib/ai-env-relay");
    assert_eq!(text(&state.join("refused")), format!("{}\n", binary_name(&v2)));
    assert!(!state.join("trying").exists(), "the verdict is in");
    for changed in [false, true] {
        if changed {
            w.set("grants", &placeholder(4));
        }
        let ran = w.run(&[]);
        assert_eq!(ran.code, 1, "{}", ran.line);
        let why = format!(" artifact={v2} tls=present relay=active why={v2} did not come up: not switched to again until the artifact names another binary");
        assert!(ran.line.ends_with(&why), "{}", ran.line);
        let reload = if changed { vec!["reload ai-env-relay.service"] } else { vec![] };
        assert_eq!(ran.systemctl, [vec!["is-active ai-env-relay.service"], reload].concat(), "the old binary left running");
        assert!(!ran.aws.iter().any(|l| l.starts_with("s3api")) && w.current() == binary_name(&v1), "nothing downloaded or switched");
    }
    let v3 = w.binary(V3);
    w.good = format!("{} {}", binary_name(&v1), binary_name(&v3));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(w.current(), binary_name(&v3));
    assert!(!state.join("refused").exists() && !state.join("trying").exists());
}

/// I-T55: a run cut off between the switch and its verdict (the unit's TimeoutStartSec, a reboot, a stop) leaves
/// `trying` naming the new, current binary while the old one still runs; the next run judges that trial: the new binary
/// restarted, then kept when it comes up, else rolled back and refused.
#[test]
fn reload_judges_the_trial_a_cut_off_run_left() {
    for comes_up in [true, false] {
        let mut w = World::new();
        let v1 = w.complete();
        assert_eq!(w.run(&[]).code, 0);
        let v2 = w.binary(V2);
        let state = w.root().join("var/lib/ai-env-relay");
        std::fs::write(w.libexec(&binary_name(&v2)), V2).unwrap();
        std::fs::write(state.join("previous"), format!("{}\n", binary_name(&v1))).unwrap();
        std::fs::write(state.join("trying"), format!("{}\n", binary_name(&v2))).unwrap();
        std::fs::remove_file(w.libexec("current")).unwrap();
        std::os::unix::fs::symlink(binary_name(&v2), w.libexec("current")).unwrap();
        if comes_up {
            w.good = format!("{} {}", binary_name(&v1), binary_name(&v2));
        }
        let ran = w.run(&[]);
        assert!(ran.systemctl.contains(&"restart ai-env-relay.service".to_string()), "{comes_up}: the trial judged: {:?}", ran.systemctl);
        assert!(!ran.aws.iter().any(|l| l.starts_with("s3api")) && !state.join("trying").exists(), "{comes_up}: {:?}", ran.aws);
        if comes_up {
            assert_eq!((ran.code, w.current()), (0, binary_name(&v2)), "{}", ran.line);
        } else {
            assert!(ran.code == 1 && ran.line.contains(&format!(" relay=active rollback={v1} ")), "{}", ran.line);
            assert_eq!((w.current(), text(&state.join("refused"))), (binary_name(&v1), format!("{}\n", binary_name(&v2))));
        }
    }
}

/// I-T19: without a TLS pair the binary is installed but the relay neither started nor restarted (it waits for the
/// pair); the run after the pair arrives starts it.
#[test]
fn reload_waits_for_the_tls_pair_before_starting_the_relay() {
    let mut w = World::new();
    for (p, n) in [("workers", 1), ("grants", 2), ("token-signers", 3)] {
        w.set(p, &placeholder(n));
    }
    let v1 = w.binary(V1);
    w.good = binary_name(&v1);
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(w.current(), binary_name(&v1));
    assert!(ran.line.contains(" absent=tls ") && ran.line.ends_with(" tls=absent relay=waiting-for-tls"), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service"], "no restart or start");
    w.set("tls", &tls_pair("QUFB"));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.systemctl.contains(&"restart ai-env-relay.service".to_string()) && ran.line.ends_with(" tls=present relay=active"), "{}: {:?}", ran.line, ran.systemctl);
}

/// I-T20: with the relay active on the current binary, a changed list sends exactly one `systemctl reload`, an
/// unchanged run none.
#[test]
fn reload_reloads_the_relay_on_a_change_and_only_then() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    w.set("grants", &placeholder(4));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);
    assert!(ran.line.contains(" changed=grants "), "{}", ran.line);
    let ran = w.run(&[]);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service"]);
}

/// I-T21: every run of I-T14 to I-T22 checks its line and the whole reload.log ([`World::never_logged`]); this one walks
/// the lines that name a parameter (an invalid list, an invalid pair, a failed fetch, a rollback) and reads reload.log
/// itself: one line per run, each word after the verdict a key of I-R36's.
#[test]
fn reload_never_logs_a_value() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    w.set("grants", "{\"placeholder\": NaN}");
    w.set("tls", &format!("{}{}", tls_pair("QkJC"), key_block("QkJC")));
    let ran = w.run(&[]);
    assert!(ran.code == 1 && ran.line.contains(" why=grants: not JSON; tls: not certificates then one PKCS#8 key block"), "{}", ran.line);
    assert_eq!(w.run(&[("FAKE_AWS_FAIL_OP", "ssm get-parameters")]).code, 1);
    w.binary(V2);
    assert_eq!(w.run(&[]).code, 1);
    let log = text(&w.root().join("var/log/ai-env-relay/reload.log"));
    assert_eq!(log.lines().count(), 4, "{log}");
    let keys = ["fetched", "changed", "absent", "artifact", "tls", "relay", "rollback", "why"];
    for line in log.lines() {
        let words: Vec<&str> = line.split(' ').collect();
        assert!(words[0] == "ai-env-relay-reload:" && (words[1] == "ok" || words[1] == "FAILED"), "{line}");
        let named: Vec<&str> = words[2..].iter().take_while(|word| !word.starts_with("why=")).map(|word| word.split('=').next().unwrap()).collect();
        assert!(named.iter().all(|k| keys.contains(k)), "{line}");
    }
}

/// I-T22: a fetch that fails three times fails the run closed: `fetched=none`, live/ as it was (not even the stamp),
/// no systemctl call.
#[test]
fn reload_fails_closed_on_a_failed_fetch() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let before = w.snapshot();
    let ran = w.run(&[("FAKE_AWS_FAIL_OP", "ssm get-parameters")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert_eq!(ran.aws, [GET_PARAMETERS; 3], "three tries");
    assert!(ran.line.contains(" fetched=none ") && ran.line.contains(" why=get-parameters: An error occurred (AccessDeniedException)"), "{}", ran.line);
    assert_eq!(w.snapshot(), before, "live/ untouched");
    assert_eq!(ran.systemctl, Vec::<String>::new());
}

/// I-T23: outside a test root every knob is ignored: a bad environment exits 2 with I-R29's text, and the aws and
/// systemctl the knobs name are never run; the unit's `Run`, built from every knob without `AI_ENV_RELAY_ROOT`, takes
/// none of them (the instance's paths, `aws`, `systemctl`, 60 s), and with it takes them all.
#[test]
fn reload_ignores_its_knobs_outside_a_test_root() {
    let t = tempfile::tempdir().unwrap();
    let fake = t.path().join("logged");
    executable(&fake, &format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> {:?}\n", t.path().join("called").display().to_string()));
    for (prefix, region) in [(None, "eu-central-1"), (Some("ai-env/relay"), "eu-central-1"), (Some("/ai-env/relay"), "eu-central")] {
        let mut cmd = Command::new("/usr/bin/python3");
        isolate(&mut cmd, t.path());
        cmd.arg("-I")
            .arg(infra().join("relay/reload.py"))
            .env("PATH", "/usr/bin:/bin")
            .env("REGION", region)
            .env("AI_ENV_RELAY_AWS", &fake)
            .env("AI_ENV_RELAY_SYSTEMCTL", &fake)
            .env("AI_ENV_RELAY_WAIT_S", "2");
        match prefix {
            Some(p) => cmd.env("PARAM_PREFIX", p),
            None => cmd.env_remove("PARAM_PREFIX"),
        };
        let o = bounded(&mut cmd, "reload.py");
        assert_eq!(o.status.code(), Some(2), "{prefix:?} {region}: {}", all(&o));
        assert_eq!(stderr(&o), "ai-env-relay-reload: reload.env: PARAM_PREFIX or REGION missing or malformed\n");
    }
    assert!(!t.path().join("called").exists(), "the fake was run");

    // The runs above stop at the environment check, before any knob is read: the knobs themselves, on the unit's Run.
    let root = t.path().join("root").display().to_string();
    let runs = reload_module(
        t.path(),
        "knobs = {'AI_ENV_RELAY_AWS': 'fake-aws', 'AI_ENV_RELAY_SYSTEMCTL': 'fake-systemctl', 'AI_ENV_RELAY_WAIT_S': '2'}\n\
         for env in (knobs, dict(knobs, AI_ENV_RELAY_ROOT=sys.argv[2])):\n    \
             r = m.Run(env)\n    \
             print(json.dumps([r.aws, r.systemctl, r.wait_s, r.libexec, r.state, r.log]))",
        &[root.as_str()],
    );
    let runs: Vec<Value> = runs.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let run = |aws: &str, systemctl: &str, wait: u32, r: &str| {
        json!([aws, systemctl, wait, format!("{r}/usr/local/libexec/ai-env-relay"), format!("{r}/var/lib/ai-env-relay"), format!("{r}/var/log/ai-env-relay/reload.log")])
    };
    assert_eq!(runs, [run("aws", "systemctl", 60, ""), run("fake-aws", "fake-systemctl", 2, &root)], "without the root, then with it");
}
