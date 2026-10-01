//! The aws CLI calls behind `ai-env egress …` and `ai-env proxy …` (S5),
//! as the operator through `bridge::awscli`: connector, VPC, route table,
//! network ACL, security group, DNS Firewall, instance, SSM parameter and
//! SSM command reads and writes.
//!
//! Every call goes through [`aws_json`] (region, pinned endpoint, `--output
//! json`, no OAuth token); an `Err` is the aws error's first line, naming the
//! operation. Parameter values never reach an argument list (they go
//! through a 0600 temp file in the private `state/` directory, `--value
//! file://…`), a log or an error. Polls are bounded by a number of tries
//! ([`Wait`]), scaled like `vm::run::Poll` by the debug-build lab knob, so a
//! process test runs in milliseconds whatever its machine's speed; a wait
//! on an SSM command outlasts the command's execution timeout plus its
//! delivery timeout.
use crate::bridge::awscli::aws_json;
use crate::bridge::registry::ensure_private_dir;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

/// The proxy's reload script (`infra/proxy/reload.sh`, installed by user-data).
pub const RELOAD: &str = "/usr/local/sbin/ai-env-proxy-reload";

/// `send-command --timeout-seconds`: how long SSM may take to deliver a
/// command before it gives up (it then never runs).
pub const DELIVERY_S: u32 = 60;
/// `executionTimeout` of a reload: above the script's worst case under
/// systemd (≈ 1 070 s: its lock wait 120, the fetch retries 310, a squid
/// restart 300 with its confirmation, a rollback start 300 with its
/// confirmation). The `--status` that proves it is a command of its own.
pub const RELOAD_EXEC_S: u32 = 1500;
/// `executionTimeout` of `ai-env-proxy-reload --status` (and `rpm -q
/// squid`): above its fetch retries (≈ 310 s).
pub const STATUS_EXEC_S: u32 = 400;
/// `executionTimeout` of `dnf -y upgrade --security --releasever=latest` and the squid restart.
pub const PATCH_EXEC_S: u32 = 1800;

/// A bounded poll: at most `tries` looks, `step` apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    pub step: Duration,
    pub tries: u32,
}

impl Wait {
    /// A reload: 5 s steps for 1600 s, over [`RELOAD_EXEC_S`] + [`DELIVERY_S`].
    pub const RELOAD: Wait = Wait { step: Duration::from_secs(5), tries: 320 };
    /// A `--status` run: 2 s steps for 480 s, over [`STATUS_EXEC_S`] + [`DELIVERY_S`].
    pub const STATUS: Wait = Wait { step: Duration::from_secs(2), tries: 240 };
    /// The patch: 5 s steps for 1900 s, over [`PATCH_EXEC_S`] + [`DELIVERY_S`].
    pub const PATCH: Wait = Wait { step: Duration::from_secs(5), tries: 380 };
    /// The instance reaching `running` or `stopped`: 5 s steps for 5 minutes.
    pub const INSTANCE: Wait = Wait { step: Duration::from_secs(5), tries: 60 };
    /// The SSM agent reporting Online after a start: 5 s steps for 5 minutes.
    pub const SSM_ONLINE: Wait = Wait { step: Duration::from_secs(5), tries: 60 };
    /// squid serving the current parameters after a start (the boot reload
    /// runs before it; SSM may refuse commands for a while): 5 s steps for 3 minutes.
    pub const SQUID: Wait = Wait { step: Duration::from_secs(5), tries: 36 };

    /// Every second of `step` becomes `ms_per_second` milliseconds
    /// (`AI_ENV_BRIDGE_LAB_BACKOFF_MS`, debug builds); the tries stay.
    #[must_use]
    pub fn scaled(self, ms_per_second: Option<u64>) -> Wait {
        let Some(ms) = ms_per_second else {
            return self;
        };
        Wait { step: Duration::from_micros(u64::try_from(self.step.as_micros()).unwrap_or(u64::MAX).saturating_mul(ms) / 1000), tries: self.tries }
    }

    /// The whole bound, for messages.
    #[must_use]
    pub fn budget(&self) -> Duration {
        self.step.saturating_mul(self.tries)
    }
}

/// The JSON array at `key` (empty when absent or not an array).
#[must_use]
pub fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// The string at `key` (empty when absent).
#[must_use]
pub fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// An id an answer handed back, before it goes on an argument list: `Err`
/// unless it is 1–128 of `[A-Za-z0-9-]` not starting with `-` (never an option).
pub fn answer_id<'a>(what: &str, id: &'a str) -> Result<&'a str, String> {
    if (1..=128).contains(&id.len()) && !id.starts_with('-') && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        Ok(id)
    } else {
        Err(format!("{what}: the answer names an unexpected id {id:?}"))
    }
}

// ---- reads ------------------------------------------------------------------------------

/// `lambda-core get-network-connector`: the unwrapped connector document.
pub fn get_connector(arn: &str) -> Result<Value, String> {
    aws_json("lambda-core", &["get-network-connector", "--identifier", arn])
}

/// Every ENI in `subnet`, the hidden managed ones included (the connector's).
pub fn subnet_enis(subnet: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-network-interfaces", "--include-managed-resources", "--filters", &format!("Name=subnet-id,Values={subnet}")])
}

/// Every route table of `vpc` (the effective table of a subnet is chosen by the caller).
pub fn route_tables(vpc: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-route-tables", "--filters", &format!("Name=vpc-id,Values={vpc}")])
}

/// The network ACL associated with `subnet` (every subnet has exactly one).
pub fn subnet_network_acls(subnet: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-network-acls", "--filters", &format!("Name=association.subnet-id,Values={subnet}")])
}

/// Every security group of `vpc` (the VM's, the proxy's and the default one).
pub fn security_groups(vpc: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-security-groups", "--filters", &format!("Name=vpc-id,Values={vpc}")])
}

/// The VPC itself (CIDRs, IPv6 associations, DHCP option set).
pub fn vpc(vpc: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-vpcs", "--vpc-ids", vpc])
}

/// One boolean VPC attribute (`enableDnsSupport`, `enableDnsHostnames`);
/// `None` when the answer does not carry it.
pub fn vpc_attribute(vpc: &str, attribute: &str) -> Result<Option<bool>, String> {
    let doc = aws_json("ec2", &["describe-vpc-attribute", "--vpc-id", vpc, "--attribute", attribute])?;
    let mut key = attribute.to_string();
    if let Some(first) = key.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    Ok(doc.get(&key).and_then(|a| a.get("Value")).and_then(Value::as_bool))
}

/// One DHCP option set.
pub fn dhcp_options(id: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-dhcp-options", "--dhcp-options-ids", answer_id("aws ec2 describe-vpcs", id)?])
}

/// The VPC endpoints of `vpc`.
pub fn vpc_endpoints(vpc: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-vpc-endpoints", "--filters", &format!("Name=vpc-id,Values={vpc}")])
}

/// Every peering connection of the account in the region (the caller keeps
/// those with the VPC on either side: one call instead of a requester and
/// an accepter query).
pub fn peering_connections() -> Result<Value, String> {
    aws_json("ec2", &["describe-vpc-peering-connections"])
}

/// The NAT gateways of `vpc` (DescribeNatGateways names its filter `Filter`).
pub fn nat_gateways(vpc: &str) -> Result<Value, String> {
    aws_json("ec2", &["describe-nat-gateways", "--filter", &format!("Name=vpc-id,Values={vpc}")])
}

/// The DNS Firewall rule groups associated with `vpc` (`dnsMode` firewall).
pub fn firewall_associations(vpc: &str) -> Result<Value, String> {
    aws_json("route53resolver", &["list-firewall-rule-group-associations", "--vpc-id", vpc])
}

/// The rules of one DNS Firewall rule group.
pub fn firewall_rules(group: &str) -> Result<Value, String> {
    aws_json("route53resolver", &["list-firewall-rules", "--firewall-rule-group-id", answer_id("aws route53resolver list-firewall-rule-group-associations", group)?])
}

/// The domains of one DNS Firewall domain list.
pub fn firewall_domains(list: &str) -> Result<Value, String> {
    aws_json("route53resolver", &["list-firewall-domains", "--firewall-domain-list-id", answer_id("aws route53resolver list-firewall-rules", list)?])
}

/// The VPC's DNS Firewall configuration (`FirewallFailOpen`).
pub fn firewall_config(vpc: &str) -> Result<Value, String> {
    aws_json("route53resolver", &["get-firewall-config", "--resource-id", vpc])
}

/// The instance document of `id` (`Err` when the answer does not list it).
pub fn instance(id: &str) -> Result<Value, String> {
    let doc = aws_json("ec2", &["describe-instances", "--instance-ids", id])?;
    arr(&doc, "Reservations").iter().flat_map(|r| arr(r, "Instances")).find(|i| text(i, "InstanceId") == id).cloned().ok_or_else(|| format!("aws ec2 describe-instances: {id} is not in the answer"))
}

/// `State.Name` of the instance (`pending`, `running`, `stopping`, `stopped`, …).
pub fn instance_state(id: &str) -> Result<String, String> {
    let i = instance(id)?;
    let state = i.get("State").map(|s| text(s, "Name")).unwrap_or("");
    if state.is_empty() {
        Err(format!("aws ec2 describe-instances: {id} has no State.Name"))
    } else {
        Ok(state.to_string())
    }
}

/// The SSM agent's `PingStatus` for `id` (`Online`, `ConnectionLost`, …);
/// `None` when the instance is not registered with SSM.
pub fn ssm_ping(id: &str) -> Result<Option<String>, String> {
    let doc = aws_json("ssm", &["describe-instance-information", "--filters", &format!("Key=InstanceIds,Values={id}")])?;
    Ok(arr(&doc, "InstanceInformationList").iter().find(|i| text(i, "InstanceId") == id).map(|i| text(i, "PingStatus").to_string()))
}

/// One parameter as SSM holds it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The exact `Value`.
    pub value: String,
    /// Its `Version` (a put that overwrites it answers `version + 1`).
    pub version: u64,
}

/// Several parameters in one call: name → [`Param`], and the names SSM does not know.
pub fn get_parameters(names: &[String]) -> Result<(BTreeMap<String, Param>, Vec<String>), String> {
    let mut args = vec!["get-parameters", "--names"];
    args.extend(names.iter().map(String::as_str));
    let doc = aws_json("ssm", &args)?;
    let mut values = BTreeMap::new();
    for p in arr(&doc, "Parameters") {
        let (Some(name), Some(value)) = (p.get("Name").and_then(Value::as_str), p.get("Value").and_then(Value::as_str)) else { continue };
        values.insert(name.to_string(), Param { value: value.to_string(), version: p.get("Version").and_then(Value::as_u64).unwrap_or(0) });
    }
    let missing = arr(&doc, "InvalidParameters").iter().filter_map(Value::as_str).map(str::to_string).collect();
    Ok((values, missing))
}

/// Every stored version of one parameter: version → exact `Value`.
pub fn parameter_history(name: &str) -> Result<BTreeMap<u64, String>, String> {
    let doc = aws_json("ssm", &["get-parameter-history", "--name", name, "--no-with-decryption"])?;
    Ok(arr(&doc, "Parameters").iter().filter_map(|p| Some((p.get("Version")?.as_u64()?, p.get("Value")?.as_str()?.to_string()))).collect())
}

// ---- writes -----------------------------------------------------------------------------

/// `put-parameter --overwrite` of an existing parameter (its type and tier
/// stay). The value goes through a 0600 temp file in `dir` (made a real
/// 0700 directory first: the bridge's `state/`), never the argument list;
/// the file is removed on every path. `Ok` is the new version.
pub fn put_parameter(dir: &Path, name: &str, value: &str) -> Result<u64, String> {
    ensure_private_dir(dir).map_err(|e| format!("cannot prepare {}: {e}", dir.display()))?;
    let mut tmp = tempfile::Builder::new().prefix(".param.").suffix(".tmp").tempfile_in(dir).map_err(|e| format!("cannot create a temp file for {name} in {}: {e}", dir.display()))?;
    tmp.write_all(value.as_bytes()).and_then(|()| tmp.flush()).map_err(|e| format!("cannot write the temp file for {name}: {e}"))?;
    let file_arg = format!("file://{}", tmp.path().display());
    let doc = aws_json("ssm", &["put-parameter", "--name", name, "--value", &file_arg, "--overwrite"]);
    drop(tmp);
    Ok(doc?.get("Version").and_then(Value::as_u64).unwrap_or(0))
}

/// `start-instances`: the instance's state after the call.
pub fn start_instance(id: &str) -> Result<String, String> {
    let doc = aws_json("ec2", &["start-instances", "--instance-ids", id])?;
    Ok(state_change(&doc, "StartingInstances", id))
}

/// `stop-instances`: the instance's state after the call.
pub fn stop_instance(id: &str) -> Result<String, String> {
    let doc = aws_json("ec2", &["stop-instances", "--instance-ids", id])?;
    Ok(state_change(&doc, "StoppingInstances", id))
}

fn state_change(doc: &Value, key: &str, id: &str) -> String {
    arr(doc, key).iter().find(|c| text(c, "InstanceId") == id).and_then(|c| c.get("CurrentState")).map(|s| text(s, "Name").to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "unknown".to_string())
}

// ---- SSM Run Command --------------------------------------------------------------------

/// A finished `AWS-RunShellScript` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// `Success`, `Failed`, `TimedOut`, `Cancelled`.
    pub status: String,
    /// The script's exit code (`ResponseCode`; -1 when SSM reported none).
    pub code: i64,
    pub stdout: String,
    pub stderr: String,
}

impl Invocation {
    /// The last non-empty line of the script's stderr (the reload script
    /// logs there, never a parameter value), or of its stdout.
    #[must_use]
    pub fn last_line(&self) -> &str {
        fn last(s: &str) -> Option<&str> {
            s.lines().map(str::trim).rev().find(|l| !l.is_empty())
        }
        last(&self.stderr).or_else(|| last(&self.stdout)).unwrap_or("")
    }

    /// SSM says `Success` and the script exited 0.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == "Success" && self.code == 0
    }
}

/// The `--parameters` document of `AWS-RunShellScript`.
#[must_use]
pub fn shell_parameters(commands: &[&str], execution_timeout_s: u32) -> String {
    serde_json::json!({ "commands": commands, "executionTimeout": [execution_timeout_s.to_string()] }).to_string()
}

/// `send-command` of `commands` as one `AWS-RunShellScript` script on
/// `instance`: the command id.
pub fn send_shell(instance: &str, commands: &[&str], comment: &str, execution_timeout_s: u32) -> Result<String, String> {
    let params = shell_parameters(commands, execution_timeout_s);
    let delivery = DELIVERY_S.to_string();
    let doc = aws_json("ssm", &["send-command", "--instance-ids", instance, "--document-name", "AWS-RunShellScript", "--comment", comment, "--timeout-seconds", &delivery, "--parameters", &params])?;
    let id = doc.get("Command").map(|c| text(c, "CommandId")).unwrap_or("");
    answer_id("aws ssm send-command", id).map(str::to_string)
}

/// Poll `get-command-invocation` until the command ends, at most `wait`
/// (an `InvocationDoesNotExist` right after the send is retried too).
pub fn wait_invocation(command_id: &str, instance: &str, wait: Wait) -> Result<Invocation, String> {
    let mut last = String::from("no answer");
    for n in 0..wait.tries.max(1) {
        if n > 0 {
            std::thread::sleep(wait.step);
        }
        match aws_json("ssm", &["get-command-invocation", "--command-id", command_id, "--instance-id", instance]) {
            Ok(doc) => {
                let status = text(&doc, "Status").to_string();
                match status.as_str() {
                    "Success" | "Failed" | "TimedOut" | "Cancelled" => {
                        return Ok(Invocation {
                            code: doc.get("ResponseCode").and_then(Value::as_i64).unwrap_or(-1),
                            stdout: text(&doc, "StandardOutputContent").to_string(),
                            stderr: text(&doc, "StandardErrorContent").to_string(),
                            status,
                        });
                    }
                    other => last = format!("status {}", if other.is_empty() { "?" } else { other }),
                }
            }
            Err(e) if e.contains("InvocationDoesNotExist") => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(format!("SSM command {command_id} on {instance} did not finish within {} s ({last})", wait.budget().as_secs()))
}

/// [`send_shell`] then [`wait_invocation`].
pub fn run_shell(instance: &str, commands: &[&str], comment: &str, execution_timeout_s: u32, wait: Wait) -> Result<Invocation, String> {
    let id = send_shell(instance, commands, comment, execution_timeout_s)?;
    wait_invocation(&id, instance, wait)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_scale_the_step_and_outlast_their_commands() {
        let w = Wait::INSTANCE.scaled(Some(1));
        assert_eq!(w, Wait { step: Duration::from_millis(5), tries: 60 });
        assert_eq!(Wait::RELOAD.scaled(None), Wait::RELOAD);
        for (wait, exec) in [(Wait::RELOAD, RELOAD_EXEC_S), (Wait::STATUS, STATUS_EXEC_S), (Wait::PATCH, PATCH_EXEC_S)] {
            assert!(wait.budget() >= Duration::from_secs(u64::from(exec + DELIVERY_S)), "{wait:?} < {exec} + {DELIVERY_S}");
        }
        const { assert!(RELOAD_EXEC_S >= 1500 && STATUS_EXEC_S >= 310) };
    }

    #[test]
    fn shell_parameters_are_one_json_document() {
        let p = shell_parameters(&["rpm -q squid || true", "/usr/local/sbin/ai-env-proxy-reload --status"], 300);
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["commands"][1], "/usr/local/sbin/ai-env-proxy-reload --status");
        assert_eq!(v["executionTimeout"][0], "300");
    }

    #[test]
    fn the_last_line_prefers_stderr_and_success_needs_both() {
        let inv = Invocation { status: "Failed".into(), code: 1, stdout: "out\n".into(), stderr: "a\nai-env-proxy-reload: refused; the running config is unchanged\n\n".into() };
        assert_eq!(inv.last_line(), "ai-env-proxy-reload: refused; the running config is unchanged");
        assert!(!inv.succeeded());
        let quiet = Invocation { stderr: " \n".into(), ..inv };
        assert_eq!(quiet.last_line(), "out");
        assert!(Invocation { status: "Success".into(), code: 0, ..quiet.clone() }.succeeded());
        assert!(!Invocation { status: "TimedOut".into(), code: 0, ..quiet }.succeeded());
    }

    #[test]
    fn ids_from_answers_never_become_options() {
        assert_eq!(answer_id("x", "rslvr-frg-0123456789abcdef"), Ok("rslvr-frg-0123456789abcdef"));
        for bad in ["", "-x", "--parameters", "a b", "a/b", &"a".repeat(129)] {
            assert!(answer_id("x", bad).is_err(), "{bad:?}");
        }
    }
}
