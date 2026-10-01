//! The aws CLI as the operator (S4 CloudTrail probe, S5 egress commands):
//! one place builds every call. Each one carries `--region eu-central-1`, the
//! service's eu-central-1 endpoint as `--endpoint-url` (it overrides
//! `AWS_ENDPOINT_URL[_<SERVICE>]` and a profile's `endpoint_url`, so a stub
//! endpoint cannot answer for AWS), `--output json`, `AWS_PAGER=""`, and runs
//! without `CLAUDE_CODE_OAUTH_TOKEN` in its environment. A service without a
//! pinned endpoint is refused before anything runs.
//!
//! The MicroVM data plane never goes through here (the SDK client pins its
//! own); these are the operator's calls the SDK crate does not model: the
//! `lambda-core` connector API, EC2/VPC, SSM, CloudWatch Logs, STS and
//! CloudTrail.
use crate::bridge::config::REGION;
use crate::bridge::doctor::run_capture_cmd;
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

/// Run [`aws_cmd`] under `timeout`, feeding `stdin` when given: `Ok(stdout)`
/// (trimmed) on exit 0, else `Err` with the operation and the aws error's
/// first line (or the exit code, the timeout, a missing CLI).
pub fn aws_run(service: &str, args: &[&str], stdin: Option<&[u8]>, timeout: Duration) -> Result<String, String> {
    let cmd = aws_cmd(service, args)?;
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

/// The 12-digit account of the operator's credentials (`sts
/// get-caller-identity`).
pub fn operator_account() -> Result<String, String> {
    let doc = aws_json("sts", &["get-caller-identity"])?;
    let account = doc.get("Account").and_then(|a| a.as_str()).unwrap_or_default();
    if account.len() == 12 && account.bytes().all(|c| c.is_ascii_digit()) {
        Ok(account.to_string())
    } else {
        Err(format!("aws sts get-caller-identity: no 12-digit Account in the answer ({account:?})"))
    }
}

/// The account field of an ARN (`arn:aws:<svc>:<region>:<account>:…`).
#[must_use]
pub fn arn_account(arn: &str) -> Option<&str> {
    let mut it = arn.split(':');
    (it.next()? == "arn").then_some(())?;
    it.nth(3).filter(|a| !a.is_empty())
}

/// Refuse to act unless the operator's credentials belong to the account of
/// `arn` (the configured connector): `Err` names both accounts, or why the
/// identity could not be read. Exit 1 for the caller (a config problem).
pub fn require_operator_account(arn: &str) -> Result<String, String> {
    let want = arn_account(arn).ok_or_else(|| format!("{arn:?} names no account"))?;
    let have = operator_account()?;
    if have == want {
        Ok(have)
    } else {
        Err(format!("the aws CLI's credentials are of account {have}, but {arn} is in account {want}: use the operator profile of that account (AWS_PROFILE)"))
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

    #[test]
    fn arn_accounts() {
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1:123456789012:network-connector:x"), Some("123456789012"));
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:HTTP_INGRESS"), Some("aws"));
        assert_eq!(arn_account("nope:aws:lambda:eu-central-1:1:x"), None);
        assert_eq!(arn_account("arn:aws:lambda:eu-central-1::x"), None);
        assert_eq!(arn_account("arn:aws"), None);
    }
}
