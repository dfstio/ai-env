//! The aws CLI as the operator (S4 CloudTrail probe, S5 egress commands):
//! one place builds every call. Each one carries `--region eu-central-1`, the
//! service's eu-central-1 endpoint as `--endpoint-url` (it overrides
//! `AWS_ENDPOINT_URL[_<SERVICE>]` and a profile's `endpoint_url`, so a stub
//! endpoint cannot answer for AWS), `--output json`, `AWS_PAGER=""`, and runs
//! without `CLAUDE_CODE_OAUTH_TOKEN` in its environment. A service without a
//! pinned endpoint is refused before anything runs.
//!
//! S8 operators: every operator call runs as the operator identity of
//! `bridge::identity` ([`operator_cmd`], [`operator_program`]): the key of
//! `ai-env as deployer|ops` in its environment, else `credentials/ops.env`
//! (one Touch ID per process), else no call at all (exit 5); the aws CLI's
//! own chain only under `ai-env as root|ambient`. A `Command` these return
//! may hold the key in its environment: it is never Debug-formatted (std's
//! `Debug` prints every variable set on it); an error names its program and
//! arguments only.
//!
//! The MicroVM data plane never goes through here (the SDK client pins its
//! own); these are the operator's calls the SDK crate does not model: the
//! `lambda-core` connector API, EC2/VPC, SSM, CloudWatch Logs, STS and
//! CloudTrail.
use crate::bridge::config::REGION;
use crate::bridge::doctor::run_capture_cmd;
use crate::bridge::identity::{self, Operator};
use crate::errors::CliError;
use std::process::Command;
use std::time::Duration;

/// `aws lambda-core …`: the network-connector API (botocore `lambda-core/2026-04-30`).
pub const LAMBDA_CORE_URL: &str = "https://lambda.eu-central-1.amazonaws.com";
pub const EC2_URL: &str = "https://ec2.eu-central-1.amazonaws.com";
pub const SSM_URL: &str = "https://ssm.eu-central-1.amazonaws.com";
pub const LOGS_URL: &str = "https://logs.eu-central-1.amazonaws.com";
pub const STS_URL: &str = "https://sts.eu-central-1.amazonaws.com";
pub const CLOUDTRAIL_URL: &str = "https://cloudtrail.eu-central-1.amazonaws.com";
/// DNS Firewall (`dnsMode: "firewall"` only): the rule-group association and its fail-open setting.
pub const ROUTE53RESOLVER_URL: &str = "https://route53resolver.eu-central-1.amazonaws.com";

/// The default bound on one call.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The pinned endpoint of `service` (the aws CLI's service name); `None` for
/// a service this module does not call.
#[must_use]
pub fn endpoint(service: &str) -> Option<&'static str> {
    Some(match service {
        "lambda-core" => LAMBDA_CORE_URL,
        "ec2" => EC2_URL,
        "ssm" => SSM_URL,
        "logs" => LOGS_URL,
        "sts" => STS_URL,
        "cloudtrail" => CLOUDTRAIL_URL,
        "route53resolver" => ROUTE53RESOLVER_URL,
        _ => return None,
    })
}

/// `aws <service> <args…> --region eu-central-1 --endpoint-url <pinned>
/// --output json`, `AWS_PAGER=""`, without the OAuth token. `args[0]` is the
/// operation. `Err` for a service without a pinned endpoint or no operation.
pub fn aws_cmd(service: &str, args: &[&str]) -> Result<Command, String> {
    let url = endpoint(service).ok_or_else(|| format!("aws {service}: no pinned endpoint for this service"))?;
    if args.is_empty() {
        return Err(format!("aws {service}: no operation"));
    }
    let mut cmd = Command::new("aws");
    cmd.arg(service).args(args).args(["--region", REGION, "--endpoint-url", url, "--output", "json"]).env("AWS_PAGER", "").env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    Ok(cmd)
}

/// `aws <service> <op>` as named in errors.
fn what(service: &str, args: &[&str]) -> String {
    format!("aws {service} {}", args.first().copied().unwrap_or(""))
}

/// [`aws_cmd`] as `op` ([`identity::apply`]). Never Debug-formatted.
pub fn aws_cmd_as(service: &str, args: &[&str], op: &Operator) -> Result<Command, String> {
    let mut cmd = aws_cmd(service, args)?;
    identity::apply(&mut cmd, op);
    Ok(cmd)
}

/// [`aws_cmd`] as this process's operator ([`identity::operator`]: resolved
/// once per process; a command resolves it first, so its Touch ID comes before
/// any work and its failure keeps its exit class — here it is only a text).
/// Never Debug-formatted.
pub fn operator_cmd(service: &str, args: &[&str]) -> Result<Command, String> {
    let op = identity::operator().map_err(|e| e.to_string())?;
    aws_cmd_as(service, args, &op)
}

/// `aws <args>` for a service without a pinned endpoint (iam,
/// lambda-microvms, service-quotas): `AWS_PAGER=""`, without the OAuth token;
/// the caller's args carry `--region eu-central-1`. Pure.
#[must_use]
pub fn program_cmd(args: &[&str]) -> Command {
    let mut cmd = Command::new("aws");
    cmd.args(args).env("AWS_PAGER", "").env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    cmd
}

/// [`program_cmd`] as `op` ([`identity::apply`]). Never Debug-formatted.
#[must_use]
pub fn program_as(args: &[&str], op: &Operator) -> Command {
    let mut cmd = program_cmd(args);
    identity::apply(&mut cmd, op);
    cmd
}

/// [`program_cmd`] as this process's operator (see [`operator_cmd`]). Never Debug-formatted.
pub fn operator_program(args: &[&str]) -> Result<Command, String> {
    let op = identity::operator().map_err(|e| e.to_string())?;
    Ok(program_as(args, &op))
}

/// [`operator_program`] run under `timeout`: `Ok(stdout)` (trimmed) on exit
/// 0, else the aws error's first line (or why it did not run).
pub fn operator_capture(args: &[&str], timeout: Duration) -> Result<String, String> {
    run_capture_cmd(operator_program(args)?, None, timeout)
}

/// Run [`operator_cmd`] under `timeout`, feeding `stdin` when given:
/// `Ok(stdout)` (trimmed) on exit 0, else `Err` with the operation and the
/// aws error's first line — a crashed CLI's Python exception, not its
/// traceback's header — (or the exit code, the timeout, a missing CLI, no
/// operator identity).
pub fn aws_run(service: &str, args: &[&str], stdin: Option<&[u8]>, timeout: Duration) -> Result<String, String> {
    let cmd = operator_cmd(service, args)?;
    run_capture_cmd(cmd, stdin, timeout).map_err(|e| format!("{}: {e}", what(service, args)))
}

/// [`aws_run`] with [`CALL_TIMEOUT`] and no stdin, parsed as JSON (an empty
/// answer — e.g. a delete — is `null`).
pub fn aws_json(service: &str, args: &[&str]) -> Result<serde_json::Value, String> {
    let out = aws_run(service, args, None, CALL_TIMEOUT)?;
    if out.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&out).map_err(|e| format!("{}: unexpected output: {e}", what(service, args)))
}

/// The 12-digit account of the operator's credentials: [`identity::verified`]'s
/// (one `sts get-caller-identity` per process, cached).
pub fn operator_account() -> Result<String, String> {
    identity::verified().map(|v| v.account.clone()).map_err(|e| e.to_string())
}

/// The account field of an ARN (`arn:aws:<svc>:<region>:<account>:…`).
#[must_use]
pub fn arn_account(arn: &str) -> Option<&str> {
    let mut it = arn.split(':');
    (it.next()? == "arn").then_some(())?;
    it.nth(3).filter(|a| !a.is_empty())
}

/// Refuse to act unless the operator's credentials belong to the account of
/// `arn` (the configured connector): the identity's own refusals keep their
/// class (§4.2: 5, 9, 1); another account, or an `arn` that names none, is
/// exit 1 (a config problem). The caller puts its label before the text.
pub fn require_operator_account(arn: &str) -> Result<String, CliError> {
    let want = arn_account(arn).ok_or_else(|| CliError::Msg(format!("{arn:?} names no account")))?;
    let have = identity::verified()?.account.clone();
    if have == want {
        Ok(have)
    } else {
        Err(CliError::Msg(format!("the operator credentials are of account {have}, but {arn} is in account {want}: run it under ai-env as ops -- with that account's ops key")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_is_pinned_to_eu_central_1() {
        for s in ["lambda-core", "ec2", "ssm", "logs", "sts", "cloudtrail", "route53resolver"] {
            let url = endpoint(s).unwrap();
            assert!(url.starts_with("https://") && url.ends_with(".eu-central-1.amazonaws.com"), "{s}: {url}");
        }
        assert_eq!(endpoint("lambda-core"), Some("https://lambda.eu-central-1.amazonaws.com"));
        assert!(endpoint("s3").is_none() && endpoint("iam").is_none());
    }

    #[test]
    fn the_command_carries_region_endpoint_output_and_no_token() {
        let cmd = aws_cmd("ssm", &["get-parameters", "--names", "/ai-env/proxy/allow"]).unwrap();
        assert_eq!(cmd.get_program(), "aws");
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["ssm", "get-parameters", "--names", "/ai-env/proxy/allow", "--region", "eu-central-1", "--endpoint-url", SSM_URL, "--output", "json"]);
        assert!(cmd.get_envs().any(|(k, v)| k == "CLAUDE_CODE_OAUTH_TOKEN" && v.is_none()));
        assert!(cmd.get_envs().any(|(k, v)| k == "AWS_PAGER" && v.is_some_and(|v| v.is_empty())));
        assert!(aws_cmd("s3", &["ls"]).unwrap_err().contains("no pinned endpoint"));
        assert!(aws_cmd("ssm", &[]).is_err());
    }

    /// S8 operators: the operator's commands carry its identity in their
    /// environment only (the sealed key: the selectors gone, the files
    /// pinned, the key set; an ambient operator: the chain kept, the region
    /// pinned); a service without a pinned endpoint keeps its own args.
    #[test]
    fn operator_commands_carry_the_identity_in_their_environment_only() {
        use crate::bridge::identity::{EnvKey, Operator, Role};
        let env = |cmd: &Command, name: &str| cmd.get_envs().find(|(k, _)| *k == name).map(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()));
        let args = |cmd: &Command| cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let (id, secret) = (format!("{}FAKE{}9002", "AKIA", "0".repeat(8)), "Kq3+".repeat(10));
        let sealed = Operator::Sealed { key: EnvKey::new(id.clone(), zeroize::Zeroizing::new(secret.clone())).unwrap() };
        let list = ["iam", "list-access-keys", "--user-name", "ai-env-ops", "--region", "eu-central-1", "--output", "json"];
        let plain = program_cmd(&list);
        assert_eq!((plain.get_program().to_string_lossy().into_owned(), args(&plain)), ("aws".to_string(), list.map(String::from).to_vec()));
        assert_eq!((env(&plain, "AWS_PAGER"), env(&plain, "CLAUDE_CODE_OAUTH_TOKEN")), (Some(Some(String::new())), Some(None)));
        let cmd = program_as(&list, &sealed);
        assert_eq!(args(&cmd), list.map(String::from).to_vec(), "the key is never in argv");
        assert_eq!((env(&cmd, "AWS_ACCESS_KEY_ID"), env(&cmd, "AWS_SECRET_ACCESS_KEY")), (Some(Some(id.clone())), Some(Some(secret.clone()))));
        assert_eq!((env(&cmd, "AWS_PROFILE"), env(&cmd, "AWS_CONFIG_FILE"), env(&cmd, "AWS_REGION")), (Some(None), Some(Some("/dev/null".into())), Some(Some("eu-central-1".into()))));
        let cmd = aws_cmd_as("ssm", &["get-parameters", "--names", "/ai-env/proxy/allow"], &Operator::Runner { role: Role::Ops, tail: "9002".into() }).unwrap();
        assert!(args(&cmd).windows(2).any(|w| w == ["--endpoint-url", SSM_URL]), "{:?}", args(&cmd));
        assert_eq!((env(&cmd, "AWS_ACCESS_KEY_ID"), env(&cmd, "AWS_SHARED_CREDENTIALS_FILE")), (None, Some(Some("/dev/null".into()))), "a runner's key stays inherited");
        let cmd = aws_cmd_as("sts", &["get-caller-identity"], &Operator::Ambient { root: false }).unwrap();
        assert_eq!((env(&cmd, "AWS_PROFILE"), env(&cmd, "AWS_CONFIG_FILE"), env(&cmd, "AWS_REGION")), (None, None, Some(Some("eu-central-1".into()))), "the ambient chain is kept");
        assert!(aws_cmd_as("s3", &["ls"], &sealed).is_err());
    }

    #[test]
    fn arn_accounts() {
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1:123456789012:network-connector:x"), Some("123456789012"));
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:HTTP_INGRESS"), Some("aws"));
        assert_eq!(arn_account("nope:aws:lambda:eu-central-1:1:x"), None);
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1::x"), None);
        assert_eq!(arn_account("arn:aws"), None);
    }
}
