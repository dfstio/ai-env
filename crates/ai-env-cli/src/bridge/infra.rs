//! `ai-env infra status | base-image | versions-diff` (S3 step 11, plan D24,
//! D29 and §8): the Mac side of the Pulumi stack.
//!
//! `status` turns `pulumi stack output --json` into the six `[aws]` keys of
//! `bridge.toml` (`region`, `image_arn`, `execution_role_arn`,
//! `egress_connector_arn`, `proxy_private_ip`, `budget_name`) and into
//! `state/infra.toml` (every output, for doctor, with the image state,
//! active and failed versions overlaid from one read-only
//! `get-microvm-image` and their source recorded: the outputs only move on a
//! successful `pulumi up`; with S5's `connectorArn`, the connector's Arn, Id
//! and state from one read-only `lambda-core get-network-connector` as the
//! operator, their source recorded the same way). A stack without outputs
//! yet is named as such, with what to run. The
//! operator's `bridge.toml` carries hand-written comments and other tables,
//! so the edit is a textual splice of the `[aws]` table only
//! ([`splice_toml_table`]): values are replaced in place, missing keys are
//! inserted after the table's last key, and the result must re-parse — as
//! TOML equal to the old file plus the new values, and as a `BridgeConfig`
//! yielding exactly those values — before anything is written. Shapes the
//! splice cannot edit safely (a dotted `aws.x = …`, an inline `aws = {…}`,
//! `[[aws]]`, `[aws.sub]`, two `[aws]` headers) are refused, never guessed
//! at. `image_version` and `credentials` are never touched, a region other
//! than the pinned one, a `connectorArn` that is not a customer network
//! connector in it and a `proxyPrivateIp` outside RFC 1918 are refused
//! before anything is read live or written, and the stack is read without
//! `--show-secrets` (no passphrase needed, none printed).
//!
//! `base-image` is the preflight for the pinned managed base image version
//! (AVAILABLE or exit 1); `versions-diff` compares two
//! `list-microvm-image-versions` snapshots taken around a deploy and records
//! the `image-version-delete` probe: whether the update handler, which holds
//! `lambda:DeleteMicrovmImageVersion`, removed any earlier version.
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::awscli::{arn_account, aws_json};
use crate::bridge::config::{is_connector_arn, is_rfc1918, AwsCfg, BridgeConfig, Paths, REGION};
use crate::bridge::doctor::run_capture_cmd;
use crate::bridge::errors::BridgeError;
use crate::bridge::logging::open_log_file;
use crate::bridge::probes::{append_row, Expectation, ProbeRow};
use crate::bridge::wrapper::commit_settings;
use crate::errors::{CliError, Result};
use crate::outln;
use crate::wire::time::{rfc3339_utc, unix_now};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Both external calls (`pulumi stack output`, `aws … list-…-versions`) get this long.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// The stage stamped on the probe row `versions-diff --record-probe` writes.
const PROBE_STAGE: &str = "S3";
const PROBE_NAME: &str = "image-version-delete";
/// What the plan assumes (D29 prunes versions because they accumulate); a
/// `deleted` verdict is recorded and then fails the command, as S1 does.
const PROBE_EXPECTED: &str = "kept";

// ---- stack outputs -------------------------------------------------------------------

/// A string, a number or null (`latestFailedImageVersion` is any of the
/// three); an empty string reads as absent. Objects and arrays are refused.
fn scalar<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<String>, D::Error> {
    use serde::de::Error;
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) if s.is_empty() => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        serde_json::Value::Number(n) => Ok(Some(n.to_string())),
        serde_json::Value::Bool(b) => Ok(Some(b.to_string())),
        other => Err(D::Error::custom(format!("expected a string, a number or null, got {}", if other.is_array() { "an array" } else { "an object" }))),
    }
}

fn required<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    use serde::de::Error;
    scalar(d)?.ok_or_else(|| D::Error::custom("must be a non-empty string"))
}

/// `pulumi stack output --json` of the S3 program (camelCase outputs).
/// Unknown outputs are ignored; everything but `region` and `imageArn` may
/// be absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackOutputs {
    #[serde(deserialize_with = "required")]
    pub region: String,
    #[serde(deserialize_with = "required")]
    pub image_arn: String,
    #[serde(default, deserialize_with = "scalar")]
    pub account_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub image_name: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub image_state: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub latest_active_image_version: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub latest_failed_image_version: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub execution_role_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub build_role_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub runtime_user_name: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub runtime_user_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub deploy_policy_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub budget_name: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub bucket: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub zip_key: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub zip_sha256: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub log_group: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub claude_version: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub shim_version: Option<String>,
    // S5 egress (infra/egress.ts).
    #[serde(default, deserialize_with = "scalar")]
    pub connector_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub connector_name: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub proxy_private_ip: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub proxy_instance_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub egress_vpc_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub vm_subnet_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub vm_egress_security_group_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub proxy_security_group_id: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub operator_role_arn: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub egress_log_group: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub dns_mode: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub parameter_prefix: Option<String>,
    /// SHA-256 of the exact `squid.conf` and `allow` parameter values the stack rendered (S5): `egress status` compares the live parameters with them.
    #[serde(default, deserialize_with = "scalar")]
    pub squid_conf_sha256: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub allow_sha256: Option<String>,
}

/// What to do when the outputs lack the two keys every successful deploy
/// exports: `pulumi stack output --json` prints `{}` after `stack init` and
/// after a failed first `pulumi up` (outputs register only on success).
const NO_OUTPUTS_HINT: &str = "run make deploy first, then make infra-status; nothing written";

/// Parse the outputs JSON (an object; `region` and `imageArn` required). An
/// empty object, or one without a non-empty `region` or `imageArn`, is a
/// stack that has not been deployed yet: the message says so and what to
/// run, instead of serde's `missing field`.
pub fn parse_outputs(json: &str) -> std::result::Result<StackOutputs, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("stack outputs: {e}"))?;
    let Some(o) = v.as_object() else {
        return Err("stack outputs: not a JSON object".into());
    };
    if o.is_empty() {
        return Err(format!("the stack has no outputs yet: {NO_OUTPUTS_HINT}"));
    }
    let missing: Vec<&str> = ["region", "imageArn"].into_iter().filter(|k| o.get(*k).is_none_or(|x| x.is_null() || x.as_str() == Some(""))).collect();
    if !missing.is_empty() {
        return Err(format!("the stack outputs have no {} (not deployed yet, or the last deploy failed): {NO_OUTPUTS_HINT}", missing.join(" and ")));
    }
    serde_json::from_value(v).map_err(|e| format!("stack outputs: {e}"))
}

/// The region pin, applied before anything is written: `region` must be
/// [`REGION`] and `imageArn` must be an image ARN in it.
pub fn check_region(o: &StackOutputs) -> std::result::Result<(), String> {
    if o.region != REGION {
        return Err(format!("stack output region {:?} is not {REGION}: the MicroVM bridge is pinned to {REGION}; nothing written", o.region));
    }
    let prefix = format!("arn:aws:lambda:{REGION}:");
    if !o.image_arn.starts_with(&prefix) || !o.image_arn.contains(":microvm-image:") {
        return Err(format!("stack output imageArn {:?} is not a MicroVM image ARN in {REGION}; nothing written", o.image_arn));
    }
    Ok(())
}

/// The S5 pins, applied with [`check_region`] before anything is read live
/// or written: a `connectorArn` must be a customer network connector in
/// [`REGION`] ([`is_connector_arn`]: never a managed `aws` one, never another
/// region) of the stack's own account (that of `imageArn`, and `accountId`
/// when exported), a `proxyPrivateIp` an RFC 1918 address ([`is_rfc1918`]).
/// Both land in `[aws]`: `ai-env vm` passes the first to `RunMicrovm`, and
/// the VMs' proxy environment names the second. Absent outputs pass (an S3
/// stack).
pub fn check_egress(o: &StackOutputs) -> std::result::Result<(), String> {
    if let Some(arn) = o.connector_arn.as_deref() {
        if !is_connector_arn(arn) {
            return Err(format!("stack output connectorArn {arn:?} is not a network connector of an account in {REGION} (arn:aws:lambda:{REGION}:<12-digit account>:network-connector:<name>); nothing written"));
        }
        let account = arn_account(arn).unwrap_or_default();
        let stack_accounts = [("imageArn", arn_account(&o.image_arn)), ("accountId", o.account_id.as_deref())];
        if let Some((key, other)) = stack_accounts.into_iter().filter_map(|(k, a)| a.map(|a| (k, a))).find(|(_, a)| *a != account) {
            return Err(format!("stack output connectorArn {arn:?} is in account {account}, but the stack's {key} is in account {other}; nothing written"));
        }
    }
    if let Some(ip) = o.proxy_private_ip.as_deref().filter(|ip| !is_rfc1918(ip)) {
        return Err(format!("stack output proxyPrivateIp {ip:?} is not an RFC 1918 IPv4 address (10/8, 172.16/12, 192.168/16); nothing written"));
    }
    Ok(())
}

/// The `[aws]` entries the outputs supply, in the order they are written
/// (§8): `region`, `image_arn`, then `execution_role_arn`,
/// `egress_connector_arn` (`connectorArn`), `proxy_private_ip`
/// (`proxyPrivateIp`) and `budget_name` when present. `image_version` and
/// `credentials` never appear.
#[must_use]
pub fn aws_entries(o: &StackOutputs) -> Vec<(&'static str, String)> {
    let mut out = vec![("region", o.region.clone()), ("image_arn", o.image_arn.clone())];
    let optional = [("execution_role_arn", &o.execution_role_arn), ("egress_connector_arn", &o.connector_arn), ("proxy_private_ip", &o.proxy_private_ip), ("budget_name", &o.budget_name)];
    out.extend(optional.into_iter().filter_map(|(k, v)| v.clone().map(|v| (k, v))));
    out
}

// ---- live image state ----------------------------------------------------------------

/// The image fields of `aws lambda-microvms get-microvm-image`: what the
/// image is now, where the stack outputs only change on a successful
/// `pulumi up` (a rollback with `image-activate`/`image-deactivate`, a failed
/// build or a destroy leaves them behind).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveImage {
    #[serde(deserialize_with = "required")]
    pub state: String,
    #[serde(default, deserialize_with = "scalar")]
    pub latest_active_image_version: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub latest_failed_image_version: Option<String>,
}

/// Parse a `get-microvm-image` response (an object with a non-empty
/// `state`; other keys ignored).
pub fn parse_live_image(json: &str) -> std::result::Result<LiveImage, String> {
    serde_json::from_str(json).map_err(|e| format!("get-microvm-image printed unexpected output: {e}"))
}

/// `aws lambda-microvms get-microvm-image` of `arn`: read-only, pinned to
/// [`REGION`], no pager, without the OAuth token.
fn live_image_cmd(arn: &str) -> Command {
    let mut cmd = Command::new("aws");
    cmd.args(["lambda-microvms", "get-microvm-image", "--image-identifier", arn, "--region", REGION, "--output", "json"]).env_remove("CLAUDE_CODE_OAUTH_TOKEN").env("AWS_PAGER", "");
    cmd
}

/// The live image state of `arn`; `Err` names why it could not be read
/// (the aws error's first line, a timeout, a missing CLI, a bad response).
pub(crate) fn read_live_image(arn: &str) -> std::result::Result<LiveImage, String> {
    run_capture_cmd(live_image_cmd(arn), None, CALL_TIMEOUT).and_then(|json| parse_live_image(&json))
}

/// One version of `aws lambda-microvms list-microvm-image-versions` (the
/// fields `ai-env egress check --if-needed` compares; others ignored).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveImageVersion {
    #[serde(default, deserialize_with = "scalar")]
    pub image_version: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub state: Option<String>,
    #[serde(default, deserialize_with = "scalar")]
    pub status: Option<String>,
    /// As the CLI prints it (`2026-10-01T14:29:09.636000+03:00`).
    #[serde(default, deserialize_with = "scalar")]
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
struct LiveImageVersions {
    items: Vec<LiveImageVersion>,
}

/// Parse a `list-microvm-image-versions` response (`items`, the CLI's
/// paginated pages joined).
pub fn parse_live_image_versions(json: &str) -> std::result::Result<Vec<LiveImageVersion>, String> {
    serde_json::from_str::<LiveImageVersions>(json).map(|d| d.items).map_err(|e| format!("list-microvm-image-versions printed unexpected output: {e}"))
}

/// The live versions of `arn` (`aws lambda-microvms
/// list-microvm-image-versions`, read-only, pinned to [`REGION`], no pager,
/// without the OAuth token, as [`read_live_image`]).
pub(crate) fn read_live_image_versions(arn: &str) -> std::result::Result<Vec<LiveImageVersion>, String> {
    let mut cmd = Command::new("aws");
    cmd.args(["lambda-microvms", "list-microvm-image-versions", "--image-identifier", arn, "--region", REGION, "--output", "json"]).env_remove("CLAUDE_CODE_OAUTH_TOKEN").env("AWS_PAGER", "");
    run_capture_cmd(cmd, None, CALL_TIMEOUT).and_then(|json| parse_live_image_versions(&json))
}

/// The six `[aws]` keys `status` may write (the ones the outputs can
/// omit are listed as "left alone" when absent), in [`aws_entries`] order.
const AWS_KEYS: [&str; 6] = ["region", "image_arn", "execution_role_arn", "egress_connector_arn", "proxy_private_ip", "budget_name"];

/// The typed value of a string-valued `[aws]` key, for the round-trip check.
fn aws_value<'a>(aws: &'a AwsCfg, key: &str) -> Option<&'a str> {
    match key {
        "region" => aws.region.as_deref(),
        "credentials" => Some(aws.credentials.as_str()),
        "image_arn" => aws.image_arn.as_deref(),
        "image_version" => Some(aws.image_version.as_str()),
        "execution_role_arn" => aws.execution_role_arn.as_deref(),
        "egress_connector_arn" => aws.egress_connector_arn.as_deref(),
        "proxy_private_ip" => aws.proxy_private_ip.as_deref(),
        "budget_name" => aws.budget_name.as_deref(),
        _ => None,
    }
}

// ---- live connector state ------------------------------------------------------------

/// The connector fields of `aws lambda-core get-network-connector` (the CLI
/// model's unwrapped PascalCase answer; other keys ignored): what the
/// connector is now, where the stack outputs carry no state at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LiveConnector {
    #[serde(deserialize_with = "required")]
    pub arn: String,
    #[serde(default, deserialize_with = "scalar")]
    pub id: Option<String>,
    /// `PENDING`, `ACTIVE`, `INACTIVE`, `FAILED`, `DELETING`, `DELETE_FAILED`.
    #[serde(deserialize_with = "required")]
    pub state: String,
    /// Why the answer's `Id` was dropped ([`parse_live_connector`]); the state still counts.
    #[serde(skip)]
    pub id_refused: Option<String>,
}

/// A `get-network-connector` answer for `requested` (the stack's
/// `connectorArn`): a non-empty `Arn` and `State`, and the `Arn` must be a
/// customer connector in [`REGION`] naming the requested one (a `:N` version
/// on either side ignored). An answer about any other connector is refused,
/// so its Id never becomes an alias of the configured connector. An `Id`
/// the echo gate would drop ([`ConnectorAlias::from_state`]: not
/// `[A-Za-z0-9_-]{1,64}`, a managed connector's name) is not recorded
/// (`id_refused` says why), but the state still is: doctor and `vm run`
/// keep seeing ACTIVE/PENDING. An `Id` that is the ARN's own resource name
/// (the ARN in the Id form, measured 1 Oct 2026) is recorded: the echo
/// carries the ARN itself, and `from_state` never makes it an alias.
///
/// [`ConnectorAlias::from_state`]: crate::bridge::egress::ConnectorAlias::from_state
pub fn parse_live_connector(doc: serde_json::Value, requested: &str) -> std::result::Result<LiveConnector, String> {
    let mut live: LiveConnector = serde_json::from_value(doc).map_err(|e| format!("get-network-connector printed unexpected output: {e}"))?;
    let norm = crate::bridge::egress::normalize_connector;
    if !is_connector_arn(&live.arn) || norm(&live.arn) != norm(requested) {
        return Err(format!("get-network-connector answered for {:?}, not {requested}", live.arn));
    }
    if let Some(id) = &live.id {
        // The ARN may name the connector by its Id (measured 1 Oct 2026: a connector Pulumi creates is
        // `…:network-connector:nc-<uuid>`): the echo then carries the ARN itself, no alias is needed, and the Id is kept.
        let own = norm(&live.arn).rsplit_once(":network-connector:").is_some_and(|(_, n)| n == id);
        let probe = InfraState { connector_arn: Some(live.arn.clone()), connector_id: Some(id.clone()), ..InfraState::default() };
        if !own && !crate::bridge::egress::ConnectorAlias::from_state(&probe, requested).is_some_and(|a| a.id == *id) {
            live.id_refused = Some(format!("get-network-connector answered with the Id {id:?}, which is not usable as an alias: Id-form echoes will be refused"));
            live.id = None;
        }
    }
    Ok(live)
}

/// `aws lambda-core <these>`: the read-only connector lookup.
fn live_connector_args(arn: &str) -> [&str; 3] {
    ["get-network-connector", "--identifier", arn]
}

/// The live state of the connector `arn`: one `aws lambda-core
/// get-network-connector` as the operator ([`aws_json`]: region, pinned
/// endpoint, no pager, no OAuth token); `Err` names why it could not be read.
fn read_live_connector(arn: &str) -> std::result::Result<LiveConnector, String> {
    aws_json("lambda-core", &live_connector_args(arn)).and_then(|doc| parse_live_connector(doc, arn))
}

/// `connector_state_source` when the outputs name no connector but `[aws]`
/// still does (doctor's egress row then says to remove the key).
pub const CONNECTOR_NOT_IN_OUTPUTS: &str = "not in the stack outputs";

// ---- state/infra.toml ------------------------------------------------------------------

/// `state/infra.toml`: every stack output (snake_case), when it was written
/// and from which stack. Doctor reads it for "image claude vs bundle", the
/// image state, the egress connector's state and the proxy instance; unknown
/// keys are ignored so later stages can add some.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InfraState {
    pub stack: String,
    /// RFC 3339 UTC.
    pub written: String,
    pub region: String,
    pub image_arn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_active_image_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_failed_image_version: Option<String>,
    /// Where the three image fields above come from: `live <RFC 3339>` (a
    /// `get-microvm-image` at that time, [`InfraState::overlay`]) or `pulumi
    /// outputs (live read failed: …)` (the last successful `pulumi up`, which
    /// a rollback, a failed build or a destroy leaves stale).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_state_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_role_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_role_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_user_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_policy_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claude_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_version: Option<String>,
    // S5 egress: the stack outputs above, then what a live `lambda-core
    // get-network-connector` reported (`connector_arn` overwritten by its Arn).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_vpc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_subnet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_egress_security_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_security_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_role_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_log_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_prefix: Option<String>,
    /// SHA-256 of the `squid.conf` and `allow` values the stack rendered (outputs `squidConfSha256`, `allowSha256`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub squid_conf_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_sha256: Option<String>,
    /// The connector's Id, from the live read (the echo gate accepts the Id
    /// form only when `connector_arn` equals `[aws].egress_connector_arn`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// `ACTIVE`, `PENDING`, … from the live read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_state: Option<String>,
    /// Where the three connector fields above come from, as
    /// `image_state_source`: `live <RFC 3339>` (a `get-network-connector` at
    /// that time, [`InfraState::overlay_connector`]) or `pulumi outputs (live
    /// read failed: …)` (`connector_arn` from the outputs, no Id, no state);
    /// [`CONNECTOR_NOT_IN_OUTPUTS`] when the outputs name none but `[aws]` does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_state_source: Option<String>,
}

impl InfraState {
    #[must_use]
    pub fn from_outputs(o: &StackOutputs, stack: &str, written: String) -> InfraState {
        InfraState {
            stack: stack.to_string(),
            written,
            region: o.region.clone(),
            image_arn: o.image_arn.clone(),
            account_id: o.account_id.clone(),
            image_name: o.image_name.clone(),
            image_state: o.image_state.clone(),
            latest_active_image_version: o.latest_active_image_version.clone(),
            latest_failed_image_version: o.latest_failed_image_version.clone(),
            image_state_source: None,
            execution_role_arn: o.execution_role_arn.clone(),
            build_role_arn: o.build_role_arn.clone(),
            runtime_user_name: o.runtime_user_name.clone(),
            runtime_user_arn: o.runtime_user_arn.clone(),
            deploy_policy_arn: o.deploy_policy_arn.clone(),
            budget_name: o.budget_name.clone(),
            bucket: o.bucket.clone(),
            zip_key: o.zip_key.clone(),
            zip_sha256: o.zip_sha256.clone(),
            log_group: o.log_group.clone(),
            claude_version: o.claude_version.clone(),
            shim_version: o.shim_version.clone(),
            connector_arn: o.connector_arn.clone(),
            connector_name: o.connector_name.clone(),
            proxy_private_ip: o.proxy_private_ip.clone(),
            proxy_instance_id: o.proxy_instance_id.clone(),
            egress_vpc_id: o.egress_vpc_id.clone(),
            vm_subnet_id: o.vm_subnet_id.clone(),
            vm_egress_security_group_id: o.vm_egress_security_group_id.clone(),
            proxy_security_group_id: o.proxy_security_group_id.clone(),
            operator_role_arn: o.operator_role_arn.clone(),
            egress_log_group: o.egress_log_group.clone(),
            dns_mode: o.dns_mode.clone(),
            parameter_prefix: o.parameter_prefix.clone(),
            squid_conf_sha256: o.squid_conf_sha256.clone(),
            allow_sha256: o.allow_sha256.clone(),
            connector_id: None,
            connector_state: None,
            connector_state_source: None,
        }
    }

    /// Put the live image state over the stack outputs' copy and record the
    /// source: `Ok` replaces all three fields (a version the live read does
    /// not report is none) and records `live <at>`; `Err(reason)` keeps the
    /// outputs and records that the live read failed and why.
    pub fn overlay(&mut self, live: std::result::Result<LiveImage, String>, at: &str) {
        match live {
            Ok(l) => {
                self.image_state = Some(l.state);
                self.latest_active_image_version = l.latest_active_image_version;
                self.latest_failed_image_version = l.latest_failed_image_version;
                self.image_state_source = Some(format!("live {at}"));
            }
            Err(reason) => self.image_state_source = Some(format!("pulumi outputs (live read failed: {reason})")),
        }
    }

    /// Put the live connector over the stack outputs' `connectorArn` and
    /// record the source: `Ok` sets `connector_arn` to the live Arn and
    /// `connector_id`/`connector_state` to what the read reported, and
    /// records `live <at>`; `Err(reason)` keeps the outputs' ARN, leaves the
    /// Id and state unknown (the outputs carry neither) and records why.
    pub fn overlay_connector(&mut self, live: std::result::Result<LiveConnector, String>, at: &str) {
        match live {
            Ok(l) => {
                self.connector_arn = Some(l.arn);
                self.connector_id = l.id;
                self.connector_state = Some(l.state);
                self.connector_state_source = Some(match l.id_refused {
                    Some(why) => format!("live {at} (Id not recorded: {why})"),
                    None => format!("live {at}"),
                });
            }
            Err(reason) => {
                self.connector_id = None;
                self.connector_state = None;
                self.connector_state_source = Some(format!("pulumi outputs (live read failed: {reason})"));
            }
        }
    }

    /// The file text: a header comment, then the TOML.
    pub fn render(&self) -> std::result::Result<String, String> {
        let body = toml::to_string_pretty(self).map_err(|e| format!("state/infra.toml: {e}"))?;
        Ok(format!("# Written by `ai-env infra status --write` from `pulumi stack output --json`, a live `get-microvm-image` and a live `get-network-connector`; read by `ai-env doctor`.\n{body}"))
    }
}

/// `state/infra.toml`, `Ok(None)` when it does not exist. A symlink, a
/// non-regular file or a file that does not parse is an error naming the
/// file. One `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` open, fstat'ed and read
/// through the same descriptor (the `registry::read` pattern): a swapped-in
/// symlink is never followed and a FIFO never blocks doctor.
pub fn read_infra_state(paths: &Paths) -> std::result::Result<Option<InfraState>, BridgeError> {
    let path = paths.infra_state();
    let io_at = |what: &str, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())));
    let opened = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&path);
    let mut file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(BridgeError::Config(format!("{} is a symlink; refusing to read it", path.display()))),
        Err(e) => return Err(io_at("cannot open", e)),
    };
    if !file.metadata().map_err(|e| io_at("cannot stat", e))?.is_file() {
        return Err(BridgeError::Config(format!("{} is not a regular file", path.display())));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| io_at("cannot read", e))?;
    toml::from_str(&text).map(Some).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.message())))
}

// ---- files -----------------------------------------------------------------------------

/// Make `dir` a real 0700 directory (missing parents created 0700); a
/// symlink or a non-directory is refused, a wider existing mode is narrowed
/// (it is the bridge's own state directory). Mirrors `registry::ensure_private_dir`.
fn ensure_private_dir(dir: &Path) -> std::result::Result<(), BridgeError> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(BridgeError::Config(format!("{} is a symlink; refusing to write through it", dir.display()))),
        Ok(m) if !m.is_dir() => Err(BridgeError::Config(format!("{} is not a directory", dir.display()))),
        Ok(m) => {
            if m.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(BridgeError::from),
        Err(e) => Err(BridgeError::Io(e)),
    }
}

/// The directory a new `bridge.toml` goes in. The bridge root is the
/// bridge's own: [`ensure_private_dir`]. Any other directory
/// (`AI_ENV_BRIDGE_CONFIG=$HOME/bridge.toml`) is the operator's: created
/// 0700 (with missing parents) when absent, otherwise never chmod'ed; a
/// non-directory is refused.
fn prepare_config_dir(dir: &Path, root: &Path) -> std::result::Result<(), BridgeError> {
    if dir == root {
        return ensure_private_dir(dir);
    }
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(BridgeError::Config(format!("{} is not a directory", dir.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot create {}: {e}", dir.display())))),
        Err(e) => Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot stat {}: {e}", dir.display())))),
    }
}

/// Atomically replace `target` with `data`, leaving exactly `mode` (the
/// registry pattern): a `.<name>.<pid>.tmp` sibling — this pid's leftover
/// removed first, another pid's never touched — created `create_new`,
/// `O_NOFOLLOW|O_CLOEXEC`, fchmod'ed to `mode` (the umask does not decide),
/// written and fsync'ed, then renamed over the target (refused when the
/// target is a symlink) and the directory fsync'ed (best effort). The temp
/// file is removed on any error. The parent directory must exist.
pub(crate) fn write_atomic_mode(target: &Path, data: &[u8], mode: u32) -> std::result::Result<(), BridgeError> {
    let dir = target.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).ok_or_else(|| BridgeError::Config(format!("{} has no file name", target.display())))?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot remove {}: {e}", tmp.display())))),
    }
    let io_at = |what: &str, p: &Path, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("{what} {}: {e}", p.display())));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp).map_err(|e| io_at("cannot create", &tmp, e))?;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| io_at("cannot chmod", &tmp, e))?;
        f.write_all(data).map_err(|e| io_at("cannot write", &tmp, e))?;
        f.sync_all().map_err(|e| io_at("cannot fsync", &tmp, e))?;
        drop(f);
        if std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(BridgeError::Config(format!("{} is a symlink; refusing to replace it", target.display())));
        }
        std::fs::rename(&tmp, target).map_err(|e| io_at("cannot rename onto", target, e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The text of `--json-in FILE` (`-` reads stdin).
fn read_input(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    std::fs::read_to_string(path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))
}

// ---- TOML splice -------------------------------------------------------------------------

/// Where the structure stands at a point of the text: inside a multi-line
/// string, and how many `[`/`{` are open. A line that starts with neither is
/// a "top" line: a header, a key, a comment or blank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ScanState {
    ml: Ml,
    depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Ml {
    #[default]
    None,
    Basic,
    Literal,
}

impl ScanState {
    fn top(self) -> bool {
        self.ml == Ml::None && self.depth == 0
    }
}

/// Advance `s` over one line (without its terminator): strings, comments,
/// brackets and braces. Approximate on invalid TOML, which the caller has
/// already refused.
fn advance(line: &str, s: &mut ScanState) {
    let b = line.as_bytes();
    let at = |i: usize, pat: &[u8]| b.len() >= i + pat.len() && &b[i..i + pat.len()] == pat;
    let mut i = 0;
    while i < b.len() {
        match s.ml {
            Ml::Basic => {
                if b[i] == b'\\' {
                    i += 2;
                } else if at(i, b"\"\"\"") {
                    i += 3;
                    // Up to two more quotes belong to the content (`""""` ends a string with `"`).
                    let mut extra = 0;
                    while extra < 2 && i < b.len() && b[i] == b'"' {
                        i += 1;
                        extra += 1;
                    }
                    s.ml = Ml::None;
                } else {
                    i += 1;
                }
            }
            Ml::Literal => {
                if at(i, b"'''") {
                    i += 3;
                    let mut extra = 0;
                    while extra < 2 && i < b.len() && b[i] == b'\'' {
                        i += 1;
                        extra += 1;
                    }
                    s.ml = Ml::None;
                } else {
                    i += 1;
                }
            }
            Ml::None => match b[i] {
                b'#' => break,
                b'"' if at(i, b"\"\"\"") => {
                    s.ml = Ml::Basic;
                    i += 3;
                }
                b'\'' if at(i, b"'''") => {
                    s.ml = Ml::Literal;
                    i += 3;
                }
                b'"' => i = skip_basic(b, i),
                b'\'' => i = skip_literal(b, i),
                b'[' | b'{' => {
                    s.depth += 1;
                    i += 1;
                }
                b']' | b'}' => {
                    s.depth = s.depth.saturating_sub(1);
                    i += 1;
                }
                _ => i += 1,
            },
        }
    }
}

/// The index just past the single-line basic string opening at `i`.
fn skip_basic(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

/// The index just past the literal string opening at `i`.
fn skip_literal(b: &[u8], i: usize) -> usize {
    b[i + 1..].iter().position(|&c| c == b'\'').map_or(b.len(), |p| i + p + 2)
}

/// A TOML basic string's escapes, decoded (for comparing quoted key names).
fn unescape_basic(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let esc = it.next()?;
        match esc {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            'e' => out.push('\u{1b}'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'u' | 'U' => {
                let n = if esc == 'u' { 4 } else { 8 };
                let hex: String = (0..n).map(|_| it.next()).collect::<Option<String>>()?;
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// A dotted key (`a`, `a.b`, `"a" . 'b'`) at the start of `s` (leading
/// whitespace allowed): its parts and the rest of `s` after the key and
/// any whitespace. `None` when no key starts there.
fn parse_dotted(s: &str) -> Option<(Vec<String>, &str)> {
    let mut parts = Vec::new();
    let mut rest = s.trim_start();
    loop {
        let b = rest.as_bytes();
        let (part, after) = match b.first()? {
            b'"' => {
                let end = skip_basic(b, 0);
                if end < 2 || b[end - 1] != b'"' {
                    return None;
                }
                (unescape_basic(&rest[1..end - 1])?, &rest[end..])
            }
            b'\'' => {
                let end = skip_literal(b, 0);
                if end < 2 || b[end - 1] != b'\'' {
                    return None;
                }
                (rest[1..end - 1].to_string(), &rest[end..])
            }
            _ => {
                let n = b.iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_' || **c == b'-').count();
                if n == 0 {
                    return None;
                }
                (rest[..n].to_string(), &rest[n..])
            }
        };
        parts.push(part);
        rest = after.trim_start();
        match rest.strip_prefix('.') {
            Some(r) => rest = r.trim_start(),
            None => return Some((parts, rest)),
        }
    }
}

/// What a top line is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// Blank or a comment.
    Other,
    /// `[name]` (`array` for `[[name]]`), with an optional trailing comment.
    Header { name: Vec<String>, array: bool },
    /// `key = value`: the key's parts and the byte offset of the value.
    Key { parts: Vec<String>, value_at: usize },
}

fn classify(content: &str) -> std::result::Result<Kind, String> {
    let t = content.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return Ok(Kind::Other);
    }
    if let Some(inner) = t.strip_prefix('[') {
        let (array, inner) = match inner.strip_prefix('[') {
            Some(i) => (true, i),
            None => (false, inner),
        };
        let (name, rest) = parse_dotted(inner).ok_or_else(|| format!("cannot read the table header {:?}", t.trim_end()))?;
        let rest = rest.strip_prefix(if array { "]]" } else { "]" }).ok_or_else(|| format!("cannot read the table header {:?}", t.trim_end()))?;
        let rest = rest.trim_start();
        if !rest.is_empty() && !rest.starts_with('#') {
            return Err(format!("unexpected text after the table header {:?}", t.trim_end()));
        }
        return Ok(Kind::Header { name, array });
    }
    let (parts, rest) = parse_dotted(t).ok_or_else(|| format!("cannot read the key of {:?}", t.trim_end()))?;
    let after_eq = rest.strip_prefix('=').ok_or_else(|| format!("expected `=` after the key in {:?}", t.trim_end()))?;
    let value = after_eq.trim_start();
    Ok(Kind::Key { parts, value_at: content.len() - value.len() })
}

/// The index just past the multi-line string (`"""…"""` when `q` is `"`,
/// `'''…'''` when it is `'`) opening at `i` and closing on the same line:
/// escapes skipped in the basic form, and up to two more quotes after the
/// closer belong to the content. `b.len()` when it does not close.
fn skip_multiline(b: &[u8], i: usize, q: u8) -> usize {
    let mut j = i + 3;
    while j < b.len() {
        if q == b'"' && b[j] == b'\\' {
            j += 2;
        } else if b[j..].starts_with(&[q, q, q]) {
            j += 3;
            let mut extra = 0;
            while extra < 2 && j < b.len() && b[j] == q {
                j += 1;
                extra += 1;
            }
            return j;
        } else {
            j += 1;
        }
    }
    b.len()
}

/// The end of the single-line value starting at `start`: before a comment
/// and the whitespace in front of it. A multi-line string that opens and
/// closes on this line (`"""x"y"""`, `'''it's'''`) is one string, not
/// several single-line ones.
fn value_end(content: &str, start: usize) -> usize {
    let b = content.as_bytes();
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'#' => break,
            b'"' if b[i..].starts_with(b"\"\"\"") => i = skip_multiline(b, i, b'"'),
            b'\'' if b[i..].starts_with(b"'''") => i = skip_multiline(b, i, b'\''),
            b'"' => i = skip_basic(b, i),
            b'\'' => i = skip_literal(b, i),
            _ => i += 1,
        }
    }
    let i = i.min(b.len());
    start + content[start..i].trim_end().len()
}

/// `value` as a TOML basic string: `"`, `\` and control characters escaped.
#[must_use]
pub fn toml_basic_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn is_bare_key(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Set `entries` in the `[table]` table of a TOML document, textually:
/// comments, blank lines, key order and every other table stay as they are.
///
/// The `[table]` header may carry surrounding whitespace and a trailing
/// `#` comment. Inside its body (up to the next header) an existing
/// single-line `key = …` has its value replaced, keeping an inline comment;
/// missing keys are inserted, in `entries` order, right after the table's
/// last key line (right after the header when it has none). Without a
/// `[table]` header one is appended at the end, after a blank line. Values
/// are written as basic strings; CRLF files get CRLF lines.
///
/// `Err`, and nothing to write, for: a top-level dotted `table.<key> = …`,
/// an inline `table = {…}` (or any top-level value named `table`),
/// `[[table]]`, a `[table.<sub>]` table, more than one `[table]` header, a
/// value to replace that spans several lines, a file that is not TOML, and
/// a result that is not the old document plus exactly the new values or
/// that `BridgeConfig::parse` refuses (for `aws`, the typed values must
/// equal the new ones).
pub fn splice_toml_table(text: &str, table: &str, entries: &[(&str, String)]) -> std::result::Result<String, String> {
    if let Some((k, _)) = entries.iter().find(|(k, _)| !is_bare_key(k)) {
        return Err(format!("key {k:?} is not a bare TOML key"));
    }
    let eol = match text.find('\n') {
        Some(i) if i > 0 && text.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    };
    // Lines as (content, terminator); `top` = the line starts outside any
    // multi-line string, array or inline table.
    let mut lines: Vec<(String, String, bool)> = Vec::new();
    let mut state = ScanState::default();
    for raw in text.split_inclusive('\n') {
        let (body, term) = match raw.strip_suffix("\r\n") {
            Some(b) => (b, "\r\n"),
            None => match raw.strip_suffix('\n') {
                Some(b) => (b, "\n"),
                None => (raw, ""),
            },
        };
        let top = state.top();
        advance(body, &mut state);
        lines.push((body.to_string(), term.to_string(), top));
    }
    if !state.top() {
        return Err("the file ends inside a multi-line string or array".into());
    }

    // Structure: the one [table] header and its body; refusals.
    let mut header: Option<usize> = None;
    let mut body_end = lines.len();
    let mut seen_header = false;
    for (i, (content, _, top)) in lines.iter().enumerate() {
        if !*top {
            continue;
        }
        match classify(content).map_err(|e| format!("line {}: {e}", i + 1))? {
            Kind::Header { name, array } => {
                seen_header = true;
                if header.is_some() && body_end == lines.len() {
                    body_end = i;
                }
                if name.first().map(String::as_str) != Some(table) {
                    continue;
                }
                if array {
                    return Err(format!("line {}: [[{table}]] is an array of tables; edit [{table}] by hand", i + 1));
                }
                if name.len() > 1 {
                    return Err(format!("line {}: [{}] is a sub-table of [{table}]; edit [{table}] by hand", i + 1, name.join(".")));
                }
                if header.is_some() {
                    return Err(format!("line {}: a second [{table}] header; merge them by hand", i + 1));
                }
                header = Some(i);
                body_end = lines.len();
            }
            Kind::Key { parts, value_at } if !seen_header && parts[0] == table => {
                return Err(if parts.len() > 1 {
                    format!("line {}: the dotted key {} defines [{table}] outside a [{table}] header; edit it by hand", i + 1, parts.join("."))
                } else if content[value_at..].starts_with('{') {
                    format!("line {}: [{table}] is an inline table `{table} = {{…}}`; rewrite it as a [{table}] section", i + 1)
                } else {
                    format!("line {}: a top-level value named {table}; edit it by hand", i + 1)
                });
            }
            _ => {}
        }
    }

    // Parse the old document only now, so the refusals above keep their own messages.
    let old: toml::Table = toml::from_str(text).map_err(|e| format!("not valid TOML: {}", e.message()))?;

    let mut pending: Vec<(&str, &str)> = entries.iter().map(|(k, v)| (*k, v.as_str())).collect();
    match header {
        Some(h) => {
            let mut last_key = h;
            for i in h + 1..body_end {
                let (content, _, top) = &lines[i];
                if !*top {
                    if last_key == i - 1 {
                        last_key = i;
                    }
                    continue;
                }
                let Kind::Key { parts, value_at } = classify(content).map_err(|e| format!("line {}: {e}", i + 1))? else {
                    continue;
                };
                last_key = i;
                let Some(pos) = pending.iter().position(|(k, _)| *k == parts[0]) else {
                    continue;
                };
                if parts.len() > 1 {
                    return Err(format!("line {}: the dotted key {}.{} inside [{table}]; edit it by hand", i + 1, table, parts.join(".")));
                }
                if lines.get(i + 1).is_some_and(|l| !l.2) {
                    return Err(format!("line {}: the value of {table}.{} spans several lines; edit it by hand", i + 1, parts[0]));
                }
                let (_, value) = pending.remove(pos);
                let end = value_end(content, value_at);
                let replaced = format!("{}{}{}", &content[..value_at], toml_basic_string(value), &content[end..]);
                lines[i].0 = replaced;
            }
            if !pending.is_empty() {
                if lines[last_key].1.is_empty() {
                    lines[last_key].1 = eol.to_string();
                }
                let new: Vec<(String, String, bool)> = pending.iter().map(|(k, v)| (format!("{k} = {}", toml_basic_string(v)), eol.to_string(), true)).collect();
                lines.splice(last_key + 1..last_key + 1, new);
            }
        }
        None => {
            if let Some(last) = lines.last_mut() {
                if last.1.is_empty() {
                    last.1 = eol.to_string();
                }
            }
            let blank_before = !text.trim().is_empty() && !text.ends_with(&format!("{eol}{eol}")) && !text.ends_with("\n\n");
            if blank_before {
                lines.push((String::new(), eol.to_string(), true));
            }
            lines.push((format!("[{table}]"), eol.to_string(), true));
            for (k, v) in &pending {
                lines.push((format!("{k} = {}", toml_basic_string(v)), eol.to_string(), true));
            }
        }
    }
    let out: String = lines.iter().map(|(c, t, _)| format!("{c}{t}")).collect();

    // Verification: the old document plus exactly the new values.
    let mut expected = old;
    let slot = expected.entry(table.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let slot = slot.as_table_mut().ok_or_else(|| format!("{table} is not a table"))?;
    for (k, v) in entries {
        slot.insert((*k).to_string(), toml::Value::String(v.clone()));
    }
    let got: toml::Table = toml::from_str(&out).map_err(|e| format!("splice verification failed: the result is not valid TOML: {}", e.message()))?;
    if got != expected {
        return Err("splice verification failed: the result is not the old file plus the new values".into());
    }
    let cfg = BridgeConfig::parse(&out).map_err(|e| format!("the result is not a valid bridge.toml: {e}"))?;
    if table == "aws" {
        for (k, v) in entries {
            if aws_value(&cfg.aws, k) != Some(v.as_str()) {
                return Err(format!("splice verification failed: BridgeConfig reads [aws].{k} as {:?}", aws_value(&cfg.aws, k)));
            }
        }
    }
    Ok(out)
}

// ---- status ------------------------------------------------------------------------------

/// `pulumi stack output --json --stack <stack> --cwd <cwd>`: never
/// `--show-secrets` (no passphrase needed; no secret exists in the outputs).
fn pulumi_outputs_cmd(stack: &str, cwd: &Path) -> Command {
    let mut cmd = Command::new("pulumi");
    cmd.args(["stack", "output", "--json", "--stack", stack, "--cwd"]).arg(cwd).env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    cmd
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'/'))
}

/// The snippet an operator pastes when the splice refuses the file.
fn aws_snippet(entries: &[(&str, String)]) -> String {
    let mut s = String::from("[aws]\n");
    for (k, v) in entries {
        s.push_str(&format!("{k} = {}\n", toml_basic_string(v)));
    }
    s
}

/// `ai-env infra status [--write] [--json-in FILE] [--stack S] [--cwd DIR]`
/// (D24): read the outputs, refuse a foreign region, connector or proxy
/// address ([`check_region`], [`check_egress`]), read the image's live
/// state (`get-microvm-image`, also with `--json-in`; a failed read keeps
/// the outputs' copy and says so) and, when the outputs name a connector,
/// its live state (`get-network-connector`, likewise), show current vs
/// proposed `[aws]` values and the `state/infra.toml` text; with `--write` write
/// `state/infra.toml`, splice `bridge.toml` (backup first; when absent
/// created 0600 with only `[aws]`, in the bridge root made 0700 or in the
/// operator's `AI_ENV_BRIDGE_CONFIG` directory, which is created 0700 when
/// missing and never chmod'ed) and append one `infra_status_write` audit row.
pub fn cmd_status(write: bool, json_in: Option<&Path>, stack: &str, cwd: &Path) -> Result<()> {
    if !safe_name(stack) {
        return Err(CliError::Usage(format!("--stack {stack:?}: letters, digits, '.', '_', '-' and '/' only")));
    }
    let json = match json_in {
        Some(p) => read_input(p)?,
        None => run_capture_cmd(pulumi_outputs_cmd(stack, cwd), None, CALL_TIMEOUT).map_err(|e| CliError::Aws(format!("pulumi stack output --stack {stack}: {e}")))?,
    };
    let outputs = parse_outputs(&json).map_err(|e| CliError::Aws(format!("stack {stack}: {e}")))?;
    check_region(&outputs).map_err(CliError::Aws)?;
    check_egress(&outputs).map_err(CliError::Aws)?;
    let entries = aws_entries(&outputs);

    let paths = Paths::resolve()?;
    let path = paths.config.clone();
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => return Err(CliError::Msg(format!("{} is a symlink; refusing to edit it", path.display()))),
        Ok(m) => Some(m),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(CliError::Msg(format!("cannot stat {}: {e}", path.display()))),
    };
    let before = meta.as_ref().map(|m| (m.len(), m.modified().ok()));
    let old_text = match &meta {
        Some(_) => std::fs::read_to_string(&path).map_err(|e| CliError::Msg(format!("cannot read {}: {e}", path.display())))?,
        None => String::new(),
    };
    let new_text = match splice_toml_table(&old_text, "aws", &entries) {
        Ok(t) => t,
        Err(e) => {
            outln!("set these values in {} by hand:", path.display());
            outln!("{}", aws_snippet(&entries).trim_end());
            return Err(CliError::Msg(format!("{}: {e}", path.display())));
        }
    };
    let current: BTreeMap<String, String> = toml::from_str::<toml::Table>(&old_text)
        .ok()
        .and_then(|t| t.get("aws").and_then(|a| a.as_table()).cloned())
        .map(|a| a.into_iter().filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string()))).collect())
        .unwrap_or_default();
    let changed: Vec<&str> = entries.iter().filter(|(k, v)| current.get(*k) != Some(v)).map(|(k, _)| *k).collect();

    // The live reads (after every refusal above): the image fields of the
    // outputs are those of the last successful `pulumi up`.
    let live = read_live_image(&outputs.image_arn);
    let now = rfc3339_utc(unix_now());
    let mut state = InfraState::from_outputs(&outputs, stack, now.clone());
    let live_note = match &live {
        Ok(l) => format!("{} (live get-microvm-image)", l.state),
        Err(e) => format!("{} from the stack outputs; the live get-microvm-image failed: {e}", outputs.image_state.as_deref().unwrap_or("?")),
    };
    state.overlay(live, &now);
    // S5: the connector's Id and state exist only live (the outputs carry
    // neither); a failed read is recorded, never a reason not to write.
    let connector_note = outputs.connector_arn.as_deref().map(|arn| {
        let live = read_live_connector(arn);
        let note = match &live {
            Ok(l) => format!("{} {} (live get-network-connector){}", l.arn, l.state, l.id_refused.as_deref().map(|w| format!("; Id not recorded: {w}")).unwrap_or_default()),
            Err(e) => format!("{arn}, state unknown: the live get-network-connector failed: {e}"),
        };
        state.overlay_connector(live, &now);
        note
    });
    // The outputs name no connector, but `[aws]` still does (a stack without
    // S5, or one whose egress was destroyed): never removed silently, but
    // recorded, so doctor names the stale key instead of "no state recorded".
    let stale_connector = outputs.connector_arn.is_none() && current.get("egress_connector_arn").is_some_and(|a| !a.trim().is_empty());
    if stale_connector {
        let _ = writeln!(
            std::io::stderr().lock(),
            "ai-env: warning: the stack exports no egress connector; [aws].egress_connector_arn (and proxy_private_ip) are left as they are: remove them by hand if the stack really has none"
        );
        state.connector_state_source = Some(CONNECTOR_NOT_IN_OUTPUTS.to_string());
    }
    let state_text = state.render().map_err(CliError::Msg)?;
    let state_path = paths.infra_state();

    outln!("stack {stack}: image {}", outputs.image_arn);
    outln!("image state: {live_note}");
    if let Some(note) = connector_note {
        outln!("egress connector: {note}");
    }
    outln!("bridge.toml: {}{}", path.display(), if meta.is_some() { "" } else { " (will be created)" });
    outln!("[aws]");
    for key in AWS_KEYS {
        let cur = current.get(key);
        match (entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v), cur) {
            (Some(new), Some(c)) if c == new => outln!("  {key}: {c:?} (unchanged)"),
            (Some(new), Some(c)) => outln!("  {key}: {c:?} -> {new:?}"),
            (Some(new), None) => outln!("  {key}: unset -> {new:?}"),
            (None, Some(c)) => outln!("  {key}: {c:?} (not in the outputs; left alone)"),
            (None, None) => outln!("  {key}: unset (not in the outputs; left alone)"),
        }
    }
    outln!("{}:", state_path.display());
    outln!("{}", state_text.trim_end());

    if !write {
        outln!("dry run: nothing written; re-run with --write");
        return Ok(());
    }

    // Everything that can refuse is checked before bridge.toml changes: the
    // state directory, the audit file and the directory of a new bridge.toml.
    // Then state/infra.toml, bridge.toml and, right after it, the audit row,
    // so a bridge.toml edit never stands without its state file or its row.
    if let Some(dir) = state_path.parent() {
        ensure_private_dir(dir)?;
    }
    let audit_path = paths.audit();
    open_log_file(&audit_path).map_err(|e| CliError::Msg(format!("cannot open {} for the audit row: {e}; nothing written", audit_path.display())))?;
    if meta.is_none() {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            prepare_config_dir(dir, &paths.root)?;
        }
    }
    write_atomic_mode(&state_path, state_text.as_bytes(), 0o600)?;
    outln!("wrote: {}", state_path.display());
    let bridge_toml = match &meta {
        Some(_) if new_text == old_text => {
            outln!("bridge.toml: [aws] already up to date");
            "unchanged"
        }
        Some(m) => {
            if let Some(bak) = commit_settings(&path, Some(m), before, &old_text, &new_text)? {
                outln!("backup: {}", bak.display());
            }
            outln!("wrote: {}", path.display());
            "updated"
        }
        None => {
            commit_settings(&path, None, None, &old_text, &new_text)?;
            outln!("wrote: {} (new, 0600)", path.display());
            "created"
        }
    };
    let keys = if changed.is_empty() { "none".to_string() } else { changed.join(",") };
    let row = AuditRow::new("infra_status_write", None, audit::detail(&[("keys_changed", keys), ("stack", stack.to_string()), ("bridge_toml", bridge_toml.to_string())]));
    audit::append(&audit_path, &row)?;
    Ok(())
}

// ---- base image --------------------------------------------------------------------------

/// `aws lambda-microvms list-managed-microvm-image-versions` for the managed
/// base image `name`, pinned to [`REGION`] (the CLI default is elsewhere).
fn base_image_cmd(name: &str) -> Command {
    let mut cmd = Command::new("aws");
    cmd.args(["lambda-microvms", "list-managed-microvm-image-versions", "--image-identifier", &format!("arn:aws:lambda:{REGION}:aws:microvm-image:{name}"), "--region", REGION, "--output", "json"])
        .env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    cmd
}

/// The `items` of a list-versions response (a bare array is accepted too;
/// an empty document or `{}` is no versions). A response that carries a
/// pagination token (`nextToken` from the API, `NextToken` from the CLI's
/// `--max-items`) is only one page, and versions on the others would read
/// as missing: refused.
fn version_items(json: &str) -> std::result::Result<Vec<serde_json::Value>, String> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    match v {
        serde_json::Value::Array(a) => Ok(a),
        serde_json::Value::Object(mut o) => {
            if let Some(k) = ["nextToken", "NextToken"].into_iter().find(|k| o.get(*k).is_some_and(|t| !t.is_null())) {
                return Err(format!("snapshot is truncated (it carries a {k}); re-list without --max-items"));
            }
            match o.remove("items") {
                None | Some(serde_json::Value::Null) => Ok(Vec::new()),
                Some(serde_json::Value::Array(a)) => Ok(a),
                Some(_) => Err("`items` is not an array".into()),
            }
        }
        _ => Err("expected an object with `items`".into()),
    }
}

/// A field as text: strings as they are, numbers rendered.
fn text_of(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The verdict on `list-managed-microvm-image-versions` JSON for `version`:
/// `Ok` when that version's status is `AVAILABLE`, else `Err` naming the
/// status (DEPRECATED, EXPIRING, EXPIRED, RECALLED or anything else) or
/// saying the version is not listed.
pub fn base_image_verdict(json: &str, version: &str) -> std::result::Result<String, String> {
    let items = version_items(json)?;
    let Some(item) = items.iter().find(|i| text_of(i, "imageVersion").as_deref() == Some(version)) else {
        let listed: Vec<String> = items.iter().filter_map(|i| text_of(i, "imageVersion")).collect();
        return Err(format!("version {version} not listed (listed: {})", if listed.is_empty() { "none".to_string() } else { listed.join(", ") }));
    };
    let arn = text_of(item, "imageArn").unwrap_or_else(|| "base image".to_string());
    match text_of(item, "status") {
        Some(s) if s == "AVAILABLE" => Ok(format!("{arn} version {version}: AVAILABLE")),
        Some(s) => Err(format!("{arn} version {version} is {s}, not AVAILABLE  <- pin an AVAILABLE version (make check-base-image lists them)")),
        None => Err(format!("{arn} version {version} has no status, not AVAILABLE")),
    }
}

/// `ai-env infra base-image [--name N] [--version V] [--json-in FILE]`:
/// exit 0 when the pinned version is AVAILABLE, 1 otherwise, 7 when the
/// listing itself fails.
pub fn cmd_base_image(name: &str, version: &str, json_in: Option<&Path>) -> Result<()> {
    if !safe_name(name) || name.contains('/') {
        return Err(CliError::Usage(format!("--name {name:?}: letters, digits, '.', '_' and '-' only")));
    }
    let json = match json_in {
        Some(p) => read_input(p)?,
        None => run_capture_cmd(base_image_cmd(name), None, CALL_TIMEOUT).map_err(|e| CliError::Aws(format!("list-managed-microvm-image-versions {name}: {e}")))?,
    };
    match base_image_verdict(&json, version) {
        Ok(line) => {
            outln!("base image {line}");
            Ok(())
        }
        Err(e) => Err(CliError::Msg(format!("base image {name}: {e}"))),
    }
}

// ---- versions diff -----------------------------------------------------------------------

/// One image version of a `list-microvm-image-versions` snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionInfo {
    pub version: String,
    /// PENDING, IN_PROGRESS, SUCCESSFUL, FAILED, DELETING, DELETED, DELETE_FAILED.
    pub state: Option<String>,
    /// ACTIVE or INACTIVE.
    pub status: Option<String>,
}

/// Two snapshots compared by version number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionsDiff {
    pub added: Vec<VersionInfo>,
    pub removed: Vec<VersionInfo>,
    /// `(before, after)` for each version whose state or status moved.
    pub changed: Vec<(VersionInfo, VersionInfo)>,
    pub unchanged: Vec<VersionInfo>,
}

impl VersionsDiff {
    /// The earlier versions the deploy deleted, in version order: each one
    /// listed before outside a deletion state that is no longer listed, or
    /// whose state is now DELETING, DELETED or DELETE_FAILED (a requested
    /// delete stays listed a while). A version already in a deletion state
    /// before the deploy is not the deploy's doing.
    #[must_use]
    pub fn deleted(&self) -> Vec<&VersionInfo> {
        let mut out: Vec<&VersionInfo> = self.removed.iter().filter(|v| !v.in_deletion()).collect();
        out.extend(self.changed.iter().filter(|(old, new)| !old.in_deletion() && new.in_deletion()).map(|(old, _)| old));
        out.sort_by_key(|v| version_key(&v.version));
        out
    }

    /// The `image-version-delete` verdict: `kept` when no earlier version
    /// was deleted ([`VersionsDiff::deleted`]), else `deleted:<v>,<v>…`.
    #[must_use]
    pub fn probe_verdict(&self) -> String {
        let deleted = self.deleted();
        if deleted.is_empty() {
            "kept".to_string()
        } else {
            format!("deleted:{}", deleted.iter().map(|v| v.version.as_str()).collect::<Vec<_>>().join(","))
        }
    }

    /// How many versions the before snapshot lists outside a deletion state.
    #[must_use]
    pub fn live_before(&self) -> usize {
        self.removed.iter().chain(self.changed.iter().map(|(old, _)| old)).chain(&self.unchanged).filter(|v| !v.in_deletion()).count()
    }
}

impl VersionInfo {
    /// DELETING, DELETED or DELETE_FAILED: a delete was requested.
    #[must_use]
    pub fn in_deletion(&self) -> bool {
        self.state.as_deref().is_some_and(|s| DELETION_STATES.contains(&s))
    }
}

/// The states of a version whose delete was requested (it may stay listed a while).
const DELETION_STATES: [&str; 3] = ["DELETING", "DELETED", "DELETE_FAILED"];

/// The service's versions (`N.0`, or a bare `N`) in numeric order, anything
/// else after them in text order.
type VersionKey = (bool, Option<(u64, u64)>, String);

fn version_key(v: &str) -> VersionKey {
    let k = crate::bridge::doctor::image_version_key(v);
    (k.is_none(), k, v.to_string())
}

fn snapshot(json: &str, which: &str) -> std::result::Result<BTreeMap<VersionKey, VersionInfo>, String> {
    let mut out = BTreeMap::new();
    for item in version_items(json).map_err(|e| format!("{which}: {e}"))? {
        let version = text_of(&item, "imageVersion").ok_or_else(|| format!("{which}: an item has no imageVersion"))?;
        let info = VersionInfo { version: version.clone(), state: text_of(&item, "state"), status: text_of(&item, "status") };
        if out.insert(version_key(&version), info).is_some() {
            return Err(format!("{which}: version {version} is listed twice"));
        }
    }
    Ok(out)
}

/// Compare two `list-microvm-image-versions` snapshots (an empty document
/// or `{}` is "no versions", e.g. before the first deploy).
pub fn versions_diff(before: &str, after: &str) -> std::result::Result<VersionsDiff, String> {
    let b = snapshot(before, "before")?;
    let a = snapshot(after, "after")?;
    let mut d = VersionsDiff::default();
    for (k, old) in &b {
        match a.get(k) {
            None => d.removed.push(old.clone()),
            Some(new) if new.state != old.state || new.status != old.status => d.changed.push((old.clone(), new.clone())),
            Some(_) => d.unchanged.push(old.clone()),
        }
    }
    d.added = a.iter().filter(|(k, _)| !b.contains_key(*k)).map(|(_, v)| v.clone()).collect();
    Ok(d)
}

fn describe(v: &VersionInfo) -> String {
    format!("{} (state {}, status {})", v.version, v.state.as_deref().unwrap_or("?"), v.status.as_deref().unwrap_or("?"))
}

/// Append the probe row (the S1 `ProbeRow` shape, stage S3) with one
/// `write`; `ext` carries the image's claude version from
/// `state/infra.toml` when recorded (the pin follows the bundle, so it is
/// the same version stamp S1 uses).
fn append_probe_row(paths: &Paths, verdict: &str) -> Result<()> {
    let probes = paths.probes();
    let ext = read_infra_state(paths).ok().flatten().and_then(|s| s.claude_version);
    let row = ProbeRow { ext, ..ProbeRow::new(PROBE_NAME, PROBE_STAGE, verdict, &Expectation::Exact(PROBE_EXPECTED.to_string())) };
    append_row(&probes, &row)?;
    outln!("recorded {PROBE_NAME}={verdict} (expected {PROBE_EXPECTED}) in {}", probes.display());
    Ok(())
}

/// `ai-env infra versions-diff --before FILE --after FILE [--record-probe]`:
/// print the diff and the `image-version-delete` verdict; with
/// `--record-probe` append it to `lab/probes.jsonl` and exit 1 (after
/// writing) when it is not the expected `kept`. At most one of the two may
/// be `-` (stdin). The plain diff accepts an empty before snapshot (the
/// first deploy); `--record-probe` refuses one (exit 1, nothing appended),
/// since `kept` would be vacuous and an empty file is also what a failed
/// listing leaves behind.
pub fn cmd_versions_diff(before: &Path, after: &Path, record_probe: bool) -> Result<()> {
    let stdin = Path::new("-");
    if before == stdin && after == stdin {
        return Err(CliError::Usage("--before and --after cannot both be - (stdin); save one snapshot to a file".into()));
    }
    let b = read_input(before)?;
    let a = read_input(after)?;
    let d = versions_diff(&b, &a).map_err(CliError::Msg)?;
    let list = |v: &[VersionInfo]| if v.is_empty() { "none".to_string() } else { v.iter().map(describe).collect::<Vec<_>>().join(", ") };
    outln!("added:     {}", list(&d.added));
    outln!("removed:   {}", list(&d.removed));
    if d.changed.is_empty() {
        outln!("changed:   none");
    }
    for (old, new) in &d.changed {
        outln!("changed:   {} -> {}", describe(old), describe(new));
    }
    outln!("unchanged: {}", if d.unchanged.is_empty() { "none".to_string() } else { d.unchanged.iter().map(|v| v.version.as_str()).collect::<Vec<_>>().join(", ") });
    let verdict = d.probe_verdict();
    let vacuous = d.live_before() == 0;
    if record_probe && vacuous {
        return Err(CliError::Msg(format!(
            "probe {PROBE_NAME}: the before snapshot {} lists no image version (outside a deletion state), so `kept` would be vacuous; nothing recorded. Is it empty because the listing failed? Snapshot again after a deploy has left a version",
            before.display()
        )));
    }
    outln!("probe {PROBE_NAME}: {verdict}{}", if vacuous { " (vacuous: no earlier version)" } else { "" });
    if record_probe {
        let paths = Paths::resolve()?;
        append_probe_row(&paths, &verdict)?;
        if verdict != PROBE_EXPECTED {
            return Err(CliError::Msg(format!("probe {PROBE_NAME}={verdict} differs from the expectation {PROBE_EXPECTED}: the deploy removed earlier image versions")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_image_versions_parse_the_cli_shape() {
        let json = r#"{"items": [{"imageArn": "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent", "imageVersion": "3.0", "state": "SUCCESSFUL", "status": "ACTIVE", "createdAt": "2026-10-01T14:29:09.636000+03:00", "memoryMib": 2048}, {"imageVersion": 2, "state": "SUCCESSFUL", "status": "INACTIVE"}]}"#;
        let v = parse_live_image_versions(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].image_version.as_deref(), v[0].state.as_deref(), v[0].status.as_deref(), v[0].created_at.as_deref()), (Some("3.0"), Some("SUCCESSFUL"), Some("ACTIVE"), Some("2026-10-01T14:29:09.636000+03:00")));
        assert_eq!((v[1].image_version.as_deref(), v[1].created_at.as_deref()), (Some("2"), None), "a number is text, a missing time none");
        assert_eq!(parse_live_image_versions(r#"{"items": []}"#).unwrap(), vec![]);
        for bad in ["", "[]", "{}", r#"{"items": "x"}"#] {
            assert!(parse_live_image_versions(bad).is_err(), "{bad:?}");
        }
    }

    const ARN: &str = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent";
    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    fn e(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        pairs.iter().map(|(k, v)| (*k, (*v).to_string())).collect()
    }

    fn cfg(text: &str) -> AwsCfg {
        BridgeConfig::parse(text).unwrap().aws
    }

    #[test]
    fn splice_appends_a_table_when_there_is_none() {
        let out = splice_toml_table("", "aws", &e(&[("region", "eu-central-1"), ("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\n"), "an empty file gets no leading blank line");
        let src = "# top comment\n[vm]\nmemory_mib = 4096 # four\n";
        let out = splice_toml_table(src, "aws", &e(&[("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("{src}\n[aws]\nimage_arn = \"{ARN}\"\n"));
        // Missing final newline: one is added before the blank line.
        let out = splice_toml_table("[vm]\nmemory_mib = 4096", "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, "[vm]\nmemory_mib = 4096\n\n[aws]\nregion = \"eu-central-1\"\n");
        // Already ends with a blank line: no second one.
        let out = splice_toml_table("[vm]\nmemory_mib = 4096\n\n", "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, "[vm]\nmemory_mib = 4096\n\n[aws]\nregion = \"eu-central-1\"\n");
        assert_eq!(cfg(&out).region.as_deref(), Some("eu-central-1"));
    }

    #[test]
    fn splice_fills_an_empty_table_right_after_its_header() {
        let src = "[aws]\n[vm]\nmemory_mib = 4096\n";
        let out = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1"), ("budget_name", "ai-env-monthly")])).unwrap();
        assert_eq!(out, "[aws]\nregion = \"eu-central-1\"\nbudget_name = \"ai-env-monthly\"\n[vm]\nmemory_mib = 4096\n");
        // A trailing comment and whitespace on the header; comments in the empty body stay below the new keys.
        let src = "  [ aws ]   # filled by ai-env infra status\n# nothing yet\n\n[vm]\n";
        let out = splice_toml_table(src, "aws", &e(&[("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("  [ aws ]   # filled by ai-env infra status\nimage_arn = \"{ARN}\"\n# nothing yet\n\n[vm]\n"));
        // Last line of the file, no newline.
        let out = splice_toml_table("[aws]", "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, "[aws]\nregion = \"eu-central-1\"\n");
        // A quoted header name is the same table.
        let out = splice_toml_table("[\"aws\"]\n", "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, "[\"aws\"]\nregion = \"eu-central-1\"\n");
    }

    #[test]
    fn splice_replaces_values_in_place_keeping_comments_and_order() {
        let src = "# bridge\n[aws] # stack outputs\n# pinned\nregion = \"eu-central-1\"   # keep me\ncredentials = \"container\"\nimage_arn = 'old' # was the scratch image\nimage_version = \"active\"\n\n# the VM\n[vm]\nmemory_mib = 4096\n";
        let out = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1"), ("image_arn", ARN), ("execution_role_arn", "arn:aws:iam::123456789012:role/ai-env-exec")])).unwrap();
        assert_eq!(
            out,
            format!("# bridge\n[aws] # stack outputs\n# pinned\nregion = \"eu-central-1\"   # keep me\ncredentials = \"container\"\nimage_arn = \"{ARN}\" # was the scratch image\nimage_version = \"active\"\nexecution_role_arn = \"arn:aws:iam::123456789012:role/ai-env-exec\"\n\n# the VM\n[vm]\nmemory_mib = 4096\n")
        );
        let a = cfg(&out);
        assert_eq!((a.image_arn.as_deref(), a.credentials.as_str(), a.image_version.as_str()), (Some(ARN), "container", "active"));
        // A `#` inside the old string value is not a comment.
        let out = splice_toml_table("[aws]\nbudget_name = \"a # b\" # real\n", "aws", &e(&[("budget_name", "c")])).unwrap();
        assert_eq!(out, "[aws]\nbudget_name = \"c\" # real\n");
        // The last line without a newline is replaced and stays without one.
        let out = splice_toml_table("[aws]\nregion = \"eu-central-1\"", "aws", &e(&[("region", "eu-central-1"), ("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("[aws]\nregion = \"eu-central-1\"\nimage_arn = \"{ARN}\"\n"));
        let out = splice_toml_table("[aws]\nimage_arn = \"x\"", "aws", &e(&[("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("[aws]\nimage_arn = \"{ARN}\""));
    }

    #[test]
    fn splice_keeps_crlf() {
        let src = "[vm]\r\nmemory_mib = 4096\r\n\r\n[aws] # x\r\nregion = \"eu-central-1\" # pinned\r\n";
        let out = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1"), ("image_arn", ARN)])).unwrap();
        assert_eq!(out, format!("[vm]\r\nmemory_mib = 4096\r\n\r\n[aws] # x\r\nregion = \"eu-central-1\" # pinned\r\nimage_arn = \"{ARN}\"\r\n"));
        let out = splice_toml_table("[vm]\r\nmemory_mib = 4096\r\n", "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, "[vm]\r\nmemory_mib = 4096\r\n\r\n[aws]\r\nregion = \"eu-central-1\"\r\n");
        assert!(!out.replace("\r\n", "").contains('\n'), "no bare LF");
    }

    #[test]
    fn splice_escapes_values() {
        let v = "a \"quoted\" \\ path\twith\nnewline and \u{1} and é";
        assert_eq!(toml_basic_string(v), "\"a \\\"quoted\\\" \\\\ path\\twith\\nnewline and \\u0001 and é\"");
        let out = splice_toml_table("[aws]\nbudget_name = \"x\"\n", "aws", &e(&[("budget_name", v)])).unwrap();
        assert_eq!(cfg(&out).budget_name.as_deref(), Some(v));
        assert_eq!(out.lines().count(), 2, "the newline is escaped, not written");
    }

    #[test]
    fn splice_is_not_fooled_by_headers_inside_strings_or_arrays() {
        let src = "[wrapper]\nenv_extra = [\n  \"[aws]\",\n]\nenv_forward = [\"\"\"\n[aws]\nregion = \"x\"\n\"\"\"]\n";
        let out = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1")])).unwrap();
        assert_eq!(out, format!("{src}\n[aws]\nregion = \"eu-central-1\"\n"));
        // Another table's dotted key that starts with `aws` is that table's: the
        // structure scan lets it through, and only the BridgeConfig round trip
        // (which knows no `vm.aws`) refuses the result.
        for src in ["[vm]\naws.x = 1\n", "[vm]\n\"aws\" . x = 1 # quoted\n"] {
            let err = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1")])).unwrap_err();
            assert!(!err.contains("outside a [aws] header"), "{src:?}: {err}");
            assert!(err.contains("not a valid bridge.toml"), "{src:?}: {err}");
        }
    }

    #[test]
    fn splice_keeps_the_comment_after_a_one_line_multiline_string() {
        let src = "[aws]\nimage_arn = \"\"\"x\"y\"\"\" # keep\nbudget_name = '''it's''' # mine\n";
        let out = splice_toml_table(src, "aws", &e(&[("image_arn", ARN), ("budget_name", "b")])).unwrap();
        assert_eq!(out, format!("[aws]\nimage_arn = \"{ARN}\" # keep\nbudget_name = \"b\" # mine\n"));
        // An escaped quote inside, and up to two quotes of content before the closer.
        let src = "[aws]\nimage_arn = \"\"\"a\\\"\"\"b\"\"\"   # esc\nbudget_name = \"\"\"\"q\"\"\"\" # extra\n";
        let out = splice_toml_table(src, "aws", &e(&[("image_arn", ARN), ("budget_name", "b")])).unwrap();
        assert_eq!(out, format!("[aws]\nimage_arn = \"{ARN}\"   # esc\nbudget_name = \"b\" # extra\n"));
        let out = splice_toml_table("[aws]\nbudget_name = '''''x''''' # five\n", "aws", &e(&[("budget_name", "b")])).unwrap();
        assert_eq!(out, "[aws]\nbudget_name = \"b\" # five\n");
    }

    #[test]
    fn splice_refuses_shapes_it_cannot_edit() {
        let cases = [
            ("aws.image_arn = \"x\"\n[vm]\n", "dotted key aws.image_arn"),
            ("aws = { region = \"eu-central-1\" }\n", "inline table"),
            ("aws = \"x\"\n", "top-level value named aws"),
            ("[[aws]]\nregion = \"eu-central-1\"\n", "[[aws]]"),
            ("[aws.extra]\nx = 1\n", "[aws.extra] is a sub-table"),
            ("[aws]\nregion = \"eu-central-1\"\n[vm]\n[aws]\nimage_arn = \"x\"\n", "a second [aws] header"),
            ("[aws]\nimage_arn = \"\"\"\nx\"\"\"\n", "spans several lines"),
            ("[aws]\nimage_arn.x = \"y\"\n", "dotted key aws.image_arn.x"),
            ("[aws]\nregion = \n", "not valid TOML"),
            ("[aws]\nunknown_key = \"x\"\n", "not a valid bridge.toml"),
            ("[vm]\nmemory_mib = \"\"\"\n", "ends inside a multi-line string"),
        ];
        for (src, needle) in cases {
            let err = splice_toml_table(src, "aws", &e(&[("region", "eu-central-1"), ("image_arn", ARN)])).unwrap_err();
            assert!(err.contains(needle), "{src:?}: {err}");
        }
        // The duplicate key TOML would reject, and a non-bare key.
        assert!(splice_toml_table("[aws]\nregion = \"a\"\nregion = \"b\"\n", "aws", &e(&[("region", "eu-central-1")])).is_err());
        assert!(splice_toml_table("", "aws", &e(&[("a b", "x")])).unwrap_err().contains("not a bare TOML key"));
        // A foreign region never passes the BridgeConfig round trip.
        assert!(splice_toml_table("", "aws", &e(&[("region", "eu-west-3")])).unwrap_err().contains("not a valid bridge.toml"));
    }

    fn outputs_json() -> serde_json::Value {
        serde_json::json!({
            "region": "eu-central-1",
            "accountId": "123456789012",
            "imageName": "ai-env-agent",
            "imageArn": ARN,
            "imageState": "CREATED",
            "latestActiveImageVersion": "1",
            "latestFailedImageVersion": null,
            "executionRoleArn": "arn:aws:iam::123456789012:role/ai-env-exec",
            "budgetName": "ai-env-monthly",
            "zipSha256": "ab".repeat(32),
            "somethingNew": {"nested": [1, 2]}
        })
    }

    #[test]
    fn outputs_parse_leniently_and_map_to_aws() {
        let o = parse_outputs(&outputs_json().to_string()).unwrap();
        assert_eq!(o.image_arn, ARN);
        assert_eq!(o.latest_failed_image_version, None);
        assert_eq!(o.zip_sha256, Some("ab".repeat(32)));
        assert_eq!(o.bucket, None);
        check_region(&o).unwrap();
        assert_eq!(
            aws_entries(&o),
            e(&[("region", "eu-central-1"), ("image_arn", ARN), ("execution_role_arn", "arn:aws:iam::123456789012:role/ai-env-exec"), ("budget_name", "ai-env-monthly")])
        );
        let mut j = outputs_json();
        j["latestFailedImageVersion"] = serde_json::json!(3);
        j["latestActiveImageVersion"] = serde_json::json!("2");
        j["budgetName"] = serde_json::json!("");
        let o = parse_outputs(&j.to_string()).unwrap();
        assert_eq!((o.latest_failed_image_version.as_deref(), o.latest_active_image_version.as_deref()), (Some("3"), Some("2")));
        assert_eq!(aws_entries(&o).len(), 3, "an empty budget name is absent");
        let minimal = parse_outputs(&serde_json::json!({"region": "eu-central-1", "imageArn": ARN}).to_string()).unwrap();
        assert_eq!(aws_entries(&minimal), e(&[("region", "eu-central-1"), ("image_arn", ARN)]));
    }

    #[test]
    fn a_stack_without_outputs_says_what_to_run() {
        let e = parse_outputs("{}").unwrap_err();
        assert_eq!(e, "the stack has no outputs yet: run make deploy first, then make infra-status; nothing written");
        let e = parse_outputs(" {\n} ").unwrap_err();
        assert!(e.starts_with("the stack has no outputs yet"), "{e}");
        for (json, missing) in [
            ("{\"imageArn\": \"x\"}", "no region "),
            ("{\"region\": \"eu-central-1\"}", "no imageArn "),
            ("{\"region\": \"eu-central-1\", \"imageArn\": null}", "no imageArn "),
            ("{\"region\": \"\", \"imageArn\": \"\"}", "no region and imageArn "),
            ("{\"accountId\": \"123456789012\"}", "no region and imageArn "),
        ] {
            let e = parse_outputs(json).unwrap_err();
            assert!(e.contains(missing) && e.ends_with("run make deploy first, then make infra-status; nothing written"), "{json}: {e}");
            assert!(!e.contains("missing field"), "{json}: {e}");
        }
    }

    #[test]
    fn outputs_refusals() {
        assert!(parse_outputs("{\"imageArn\": \"x\"}").unwrap_err().contains("region"));
        assert!(parse_outputs("{\"region\": \"eu-central-1\"}").unwrap_err().contains("imageArn"));
        assert!(parse_outputs("{\"region\": \"eu-central-1\", \"imageArn\": null}").is_err());
        assert!(parse_outputs("{\"region\": \"eu-central-1\", \"imageArn\": 7}").is_ok_and(|o| o.image_arn == "7"), "a number is text (check_region refuses it)");
        assert_eq!(parse_outputs("[]").unwrap_err(), "stack outputs: not a JSON object");
        assert!(parse_outputs("{\"region\": \"eu-central-1\", \"imageArn\": \"x\", \"bucket\": [1]}").unwrap_err().contains("an array"));
        assert!(parse_outputs("[]").is_err());
        assert!(parse_outputs("").is_err());
        let mut o = parse_outputs(&outputs_json().to_string()).unwrap();
        o.region = "eu-west-3".into();
        assert!(check_region(&o).unwrap_err().contains("\"eu-west-3\" is not eu-central-1"));
        o.region = REGION.into();
        o.image_arn = "arn:aws:lambda:eu-west-3:123456789012:microvm-image:ai-env-agent".into();
        assert!(check_region(&o).unwrap_err().contains("imageArn"));
    }

    #[test]
    fn infra_state_round_trips_and_reads_none_when_missing() {
        let o = parse_outputs(&outputs_json().to_string()).unwrap();
        let s = InfraState::from_outputs(&o, "dev", "2026-09-29T10:00:00Z".into());
        let text = s.render().unwrap();
        assert!(text.starts_with("# Written by `ai-env infra status --write`"), "{text}");
        assert!(text.contains("stack = \"dev\"\n") && !text.contains("bucket"), "{text}");
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        assert_eq!(read_infra_state(&paths).unwrap(), None);
        std::fs::create_dir_all(paths.infra_state().parent().unwrap()).unwrap();
        write_atomic_mode(&paths.infra_state(), text.as_bytes(), 0o600).unwrap();
        assert_eq!(read_infra_state(&paths).unwrap(), Some(s));
        std::fs::write(paths.infra_state(), "stack = [").unwrap();
        assert!(read_infra_state(&paths).is_err());
    }

    #[test]
    fn the_live_image_state_overlays_the_outputs_and_names_its_source() {
        let live = parse_live_image(&serde_json::json!({"imageArn": ARN, "imageName": "ai-env-agent", "state": "UPDATED", "latestActiveImageVersion": 3, "latestFailedImageVersion": null, "extra": {"x": [1]}}).to_string()).unwrap();
        assert_eq!(live, LiveImage { state: "UPDATED".into(), latest_active_image_version: Some("3".into()), latest_failed_image_version: None });
        assert!(parse_live_image("{\"latestActiveImageVersion\": \"1\"}").unwrap_err().contains("state"));
        assert!(parse_live_image("{\"state\": \"\"}").is_err(), "an empty state is no state");
        assert!(parse_live_image("nope").unwrap_err().starts_with("get-microvm-image printed unexpected output"));

        let o = parse_outputs(&outputs_json().to_string()).unwrap();
        let from_outputs = InfraState::from_outputs(&o, "dev", "2026-09-29T10:00:00Z".into());
        assert_eq!((from_outputs.image_state.as_deref(), from_outputs.image_state_source.as_deref()), (Some("CREATED"), None));
        // A live read replaces all three fields, a version it does not report included.
        let mut s = InfraState { latest_failed_image_version: Some("2".into()), ..from_outputs.clone() };
        s.overlay(Ok(live), "2026-09-29T10:00:05Z");
        assert_eq!((s.image_state.as_deref(), s.latest_active_image_version.as_deref(), s.latest_failed_image_version.as_deref()), (Some("UPDATED"), Some("3"), None));
        assert_eq!(s.image_state_source.as_deref(), Some("live 2026-09-29T10:00:05Z"));
        assert!(s.render().unwrap().contains("image_state_source = \"live 2026-09-29T10:00:05Z\"\n"));
        // A failed read keeps the outputs and says why.
        let mut s = from_outputs.clone();
        s.overlay(Err("An error occurred (ResourceNotFoundException) when calling the GetMicrovmImage operation".into()), "2026-09-29T10:00:05Z");
        assert_eq!((s.image_state.as_deref(), s.latest_active_image_version.as_deref()), (Some("CREATED"), Some("1")));
        assert_eq!(s.image_state_source.as_deref(), Some("pulumi outputs (live read failed: An error occurred (ResourceNotFoundException) when calling the GetMicrovmImage operation)"));
        // A file written before the source existed still reads.
        let old = "stack = \"dev\"\nregion = \"eu-central-1\"\nimage_state = \"UPDATED\"\n";
        assert_eq!(toml::from_str::<InfraState>(old).unwrap().image_state_source, None);
    }

    /// The S5 outputs of `infra/egress.ts` on top of the S3 ones.
    fn s5_outputs_json() -> serde_json::Value {
        let mut j = outputs_json();
        for (k, v) in [
            ("connectorArn", CONNECTOR),
            ("connectorName", "ai-env-egress"),
            ("proxyPrivateIp", "10.42.0.10"),
            ("proxyInstanceId", "i-0123456789abcdef0"),
            ("egressVpcId", "vpc-0123456789abcdef0"),
            ("vmSubnetId", "subnet-0aaa1111bbbb2222c"),
            ("vmEgressSecurityGroupId", "sg-0ddd3333eeee4444f"),
            ("proxySecurityGroupId", "sg-0fff5555aaaa6666b"),
            ("operatorRoleArn", "arn:aws:iam::123456789012:role/ai-env-egress-operator"),
            ("egressLogGroup", "/ai-env/egress/squid"),
            ("dnsMode", "none"),
            ("parameterPrefix", "/ai-env/proxy"),
        ] {
            j[k] = serde_json::json!(v);
        }
        j
    }

    #[test]
    fn s5_outputs_map_to_the_two_egress_keys_in_section_8_order() {
        let o = parse_outputs(&s5_outputs_json().to_string()).unwrap();
        check_region(&o).unwrap();
        check_egress(&o).unwrap();
        assert_eq!(
            aws_entries(&o),
            e(&[
                ("region", "eu-central-1"),
                ("image_arn", ARN),
                ("execution_role_arn", "arn:aws:iam::123456789012:role/ai-env-exec"),
                ("egress_connector_arn", CONNECTOR),
                ("proxy_private_ip", "10.42.0.10"),
                ("budget_name", "ai-env-monthly")
            ])
        );
        assert_eq!(aws_entries(&o).iter().map(|(k, _)| *k).collect::<Vec<_>>(), AWS_KEYS, "AWS_KEYS lists every key in the same order");
        // The splice writes both, and BridgeConfig reads them back as the egress seam expects.
        let out = splice_toml_table("", "aws", &aws_entries(&o)).unwrap();
        let a = cfg(&out);
        assert_eq!((a.egress_connector_arn.as_deref(), a.proxy_private_ip.as_deref()), (Some(CONNECTOR), Some("10.42.0.10")));
        a.validate_egress().unwrap();
        // One without the other: only the one present; empty strings are absent.
        let mut j = s5_outputs_json();
        j["proxyPrivateIp"] = serde_json::json!("");
        let o = parse_outputs(&j.to_string()).unwrap();
        assert!(aws_entries(&o).iter().any(|(k, _)| *k == "egress_connector_arn") && !aws_entries(&o).iter().any(|(k, _)| *k == "proxy_private_ip"));
        // The state carries every S5 output.
        let s = InfraState::from_outputs(&parse_outputs(&s5_outputs_json().to_string()).unwrap(), "dev", "2026-10-01T10:00:00Z".into());
        assert_eq!((s.connector_arn.as_deref(), s.connector_name.as_deref(), s.proxy_private_ip.as_deref(), s.proxy_instance_id.as_deref()), (Some(CONNECTOR), Some("ai-env-egress"), Some("10.42.0.10"), Some("i-0123456789abcdef0")));
        assert_eq!((s.egress_vpc_id.as_deref(), s.vm_subnet_id.as_deref(), s.vm_egress_security_group_id.as_deref(), s.proxy_security_group_id.as_deref()), (Some("vpc-0123456789abcdef0"), Some("subnet-0aaa1111bbbb2222c"), Some("sg-0ddd3333eeee4444f"), Some("sg-0fff5555aaaa6666b")));
        assert_eq!((s.operator_role_arn.as_deref(), s.egress_log_group.as_deref(), s.dns_mode.as_deref(), s.parameter_prefix.as_deref()), (Some("arn:aws:iam::123456789012:role/ai-env-egress-operator"), Some("/ai-env/egress/squid"), Some("none"), Some("/ai-env/proxy")));
        assert_eq!((s.connector_id.as_deref(), s.connector_state.as_deref(), s.connector_state_source.as_deref()), (None, None, None), "only a live read knows them");
    }

    #[test]
    fn check_egress_refuses_a_managed_foreign_or_malformed_connector_and_a_public_proxy_ip() {
        let with = |k: &str, v: &str| {
            let mut j = s5_outputs_json();
            j[k] = serde_json::json!(v);
            parse_outputs(&j.to_string()).unwrap()
        };
        let managed = crate::bridge::egress::internet_egress_arn();
        for bad in [
            managed.as_str(),
            "arn:aws:lambda:eu-west-3:123456789012:network-connector:ai-env-egress",
            "arn:aws:lambda:eu-central-1:12345678901:network-connector:ai-env-egress",
            "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-egress",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress:v1",
            "ai-env-egress",
            " arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress",
        ] {
            let err = check_egress(&with("connectorArn", bad)).unwrap_err();
            assert!(err.starts_with(&format!("stack output connectorArn {bad:?} is not a network connector")) && err.ends_with("; nothing written"), "{bad}: {err}");
        }
        check_egress(&with("connectorArn", &format!("{CONNECTOR}:3"))).unwrap();
        // Another account's connector: refused against imageArn's account, and against accountId when exported.
        let foreign = "arn:aws:lambda:eu-central-1:999999999999:network-connector:ai-env-egress";
        assert_eq!(check_egress(&with("connectorArn", foreign)).unwrap_err(), format!("stack output connectorArn {foreign:?} is in account 999999999999, but the stack's imageArn is in account 123456789012; nothing written"));
        let mut j = s5_outputs_json();
        j["connectorArn"] = serde_json::json!(foreign);
        j["imageArn"] = serde_json::json!("arn:aws:lambda:eu-central-1:999999999999:microvm-image:ai-env-agent");
        assert_eq!(check_egress(&parse_outputs(&j.to_string()).unwrap()).unwrap_err(), format!("stack output connectorArn {foreign:?} is in account 999999999999, but the stack's accountId is in account 123456789012; nothing written"));
        j.as_object_mut().unwrap().remove("accountId");
        check_egress(&parse_outputs(&j.to_string()).unwrap()).unwrap();
        let mut j = s5_outputs_json();
        j.as_object_mut().unwrap().remove("accountId");
        check_egress(&parse_outputs(&j.to_string()).unwrap()).unwrap();
        j["connectorArn"] = serde_json::json!(foreign);
        assert!(check_egress(&parse_outputs(&j.to_string()).unwrap()).unwrap_err().contains("imageArn is in account 123456789012"), "without accountId the image's account still binds");
        for bad in ["8.8.8.8", "100.64.0.10", "169.254.169.254", "10.42.0.10/32", "010.42.0.10", "fd00::10", "proxy"] {
            let err = check_egress(&with("proxyPrivateIp", bad)).unwrap_err();
            assert!(err.starts_with(&format!("stack output proxyPrivateIp {bad:?} is not an RFC 1918")), "{bad}: {err}");
        }
        for good in ["10.42.0.10", "172.16.0.1", "192.168.1.1"] {
            check_egress(&with("proxyPrivateIp", good)).unwrap();
        }
        check_egress(&parse_outputs(&outputs_json().to_string()).unwrap()).unwrap();
    }

    fn golden_connector() -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/egress/lambda-core.get-network-connector.json")).unwrap()).unwrap()
    }

    #[test]
    fn the_live_connector_overlays_the_outputs_and_names_its_source() {
        let live = parse_live_connector(golden_connector(), CONNECTOR).unwrap();
        assert_eq!(live, LiveConnector { arn: CONNECTOR.into(), id: Some("nc-0a1b2c3d4e5f60718".into()), state: "ACTIVE".into(), id_refused: None });
        // A versioned ARN on either side is the same connector.
        assert_eq!(parse_live_connector(golden_connector(), &format!("{CONNECTOR}:1")).unwrap().state, "ACTIVE");
        let mut v = golden_connector();
        v["Arn"] = serde_json::json!(format!("{CONNECTOR}:2"));
        assert_eq!(parse_live_connector(v, CONNECTOR).unwrap().arn, format!("{CONNECTOR}:2"));

        let o = parse_outputs(&s5_outputs_json().to_string()).unwrap();
        let from_outputs = InfraState::from_outputs(&o, "dev", "2026-10-01T10:00:00Z".into());
        let mut s = from_outputs.clone();
        s.overlay_connector(Ok(live), "2026-10-01T10:00:05Z");
        assert_eq!((s.connector_arn.as_deref(), s.connector_id.as_deref(), s.connector_state.as_deref()), (Some(CONNECTOR), Some("nc-0a1b2c3d4e5f60718"), Some("ACTIVE")));
        assert_eq!(s.connector_state_source.as_deref(), Some("live 2026-10-01T10:00:05Z"));
        let text = s.render().unwrap();
        assert!(text.contains("connector_id = \"nc-0a1b2c3d4e5f60718\"\nconnector_state = \"ACTIVE\"\nconnector_state_source = \"live 2026-10-01T10:00:05Z\"\n"), "{text}");
        assert_eq!(toml::from_str::<InfraState>(&text).unwrap(), s, "round trip");
        // The echo gate trusts the recorded Id for the configured connector.
        assert!(crate::bridge::egress::ConnectorAlias::from_state(&s, CONNECTOR).is_some_and(|a| a.id == "nc-0a1b2c3d4e5f60718"));

        // A failed read keeps the outputs' ARN, knows no Id or state, and says why (also over an earlier success).
        s.overlay_connector(Err("aws lambda-core get-network-connector: An error occurred (AccessDeniedException)".into()), "2026-10-01T10:01:00Z");
        assert_eq!((s.connector_id.as_deref(), s.connector_state.as_deref()), (None, None));
        assert_eq!(s.connector_state_source.as_deref(), Some("pulumi outputs (live read failed: aws lambda-core get-network-connector: An error occurred (AccessDeniedException))"));
        let mut s = from_outputs;
        s.overlay_connector(Err("x".into()), "2026-10-01T10:00:05Z");
        assert_eq!(s.connector_arn.as_deref(), Some(CONNECTOR));
        // A file written before S5 still reads.
        assert_eq!(toml::from_str::<InfraState>("stack = \"dev\"\nregion = \"eu-central-1\"\n").unwrap().connector_state_source, None);
    }

    #[test]
    fn a_live_connector_answer_about_another_connector_or_without_a_state_is_refused() {
        let other = "arn:aws:lambda:eu-central-1:123456789012:network-connector:someone-else";
        let mut v = golden_connector();
        v["Arn"] = serde_json::json!(other);
        assert_eq!(parse_live_connector(v, CONNECTOR).unwrap_err(), format!("get-network-connector answered for {other:?}, not {CONNECTOR}"));
        let mut v = golden_connector();
        v["Arn"] = serde_json::json!(crate::bridge::egress::internet_egress_arn());
        assert!(parse_live_connector(v, CONNECTOR).unwrap_err().contains("answered for"), "a managed connector is never ours");
        // Arns that normalise to ours but are no connector ARN: only the is_connector_arn guard refuses them.
        for arn in [format!(" {CONNECTOR}"), format!("{CONNECTOR}:12345678901")] {
            assert_eq!(crate::bridge::egress::normalize_connector(&arn), CONNECTOR, "{arn:?}");
            let mut v = golden_connector();
            v["Arn"] = serde_json::json!(arn);
            assert_eq!(parse_live_connector(v, CONNECTOR).unwrap_err(), format!("get-network-connector answered for {arn:?}, not {CONNECTOR}"));
        }
        for (k, bad) in [("State", serde_json::json!("")), ("State", serde_json::Value::Null), ("Arn", serde_json::json!("")), ("Arn", serde_json::json!(["x"]))] {
            let mut v = golden_connector();
            v[k] = bad.clone();
            let err = parse_live_connector(v, CONNECTOR).unwrap_err();
            assert!(err.starts_with("get-network-connector printed unexpected output"), "{k} = {bad}: {err}");
        }
        assert!(parse_live_connector(serde_json::Value::Null, CONNECTOR).unwrap_err().starts_with("get-network-connector printed unexpected output"), "an empty answer");
        let mut v = golden_connector();
        v.as_object_mut().unwrap().remove("Id");
        assert_eq!(parse_live_connector(v, CONNECTOR).unwrap().id, None, "no Id is no alias");
    }

    /// An Id the echo gate would drop (`ConnectorAlias::from_state`) is not
    /// recorded (and the source says why), but the live state still is.
    #[test]
    fn a_live_connector_id_that_cannot_be_an_alias_is_refused() {
        let long = "n".repeat(65);
        for id in ["bad id", "nc/1", " nc-1", "nc-1 ", long.as_str(), "INTERNET_EGRESS", "shell_ingress", "HTTP_INGRESS", "aws-network-connector", "x-aws-network-connector-y"] {
            let mut v = golden_connector();
            v["Id"] = serde_json::json!(id);
            let live = parse_live_connector(v, CONNECTOR).unwrap();
            assert_eq!(live.id, None, "{id}");
            assert_eq!(live.id_refused.as_deref(), Some(format!("get-network-connector answered with the Id {id:?}, which is not usable as an alias: Id-form echoes will be refused").as_str()));
            let mut s = InfraState::default();
            s.overlay_connector(Ok(live), "2026-10-01T10:00:05Z");
            assert!(s.connector_state_source.as_deref().is_some_and(|src| src.starts_with("live 2026-10-01T10:00:05Z (Id not recorded: ") && src.contains("is not usable as an alias: Id-form echoes will be refused")), "{s:?}");
            assert_eq!((s.connector_id.as_deref(), s.connector_state.as_deref()), (None, Some("ACTIVE")), "{id}: the state still counts");
        }
        for id in ["nc-0a1b2c3d4e5f60718", "a", &"n".repeat(64), "ai-env-egress-2"] {
            let mut v = golden_connector();
            v["Id"] = serde_json::json!(id);
            assert_eq!(parse_live_connector(v, CONNECTOR).unwrap().id.as_deref(), Some(id), "{id}");
        }
        // The Id is the ARN's own resource name (the connector's ARN in the Id form, measured 1 Oct 2026): the echo
        // carries the ARN itself, so no alias is needed and nothing is refused; the Id is recorded.
        let id_arn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-f0b942fe-0612-44a7-9183-16942c532410";
        for (arn, id) in [(id_arn, "nc-f0b942fe-0612-44a7-9183-16942c532410"), (CONNECTOR, "ai-env-egress")] {
            let mut v = golden_connector();
            v["Arn"] = serde_json::json!(arn);
            v["Id"] = serde_json::json!(id);
            v.as_object_mut().unwrap().remove("Version");
            let live = parse_live_connector(v, arn).unwrap();
            assert_eq!((live.id.as_deref(), live.id_refused.as_deref()), (Some(id), None), "{arn}");
            let mut s = InfraState::default();
            s.overlay_connector(Ok(live), "2026-10-01T10:00:05Z");
            assert_eq!((s.connector_id.as_deref(), s.connector_state_source.as_deref()), (Some(id), Some("live 2026-10-01T10:00:05Z")), "{arn}");
            assert!(crate::bridge::egress::ConnectorAlias::from_state(&s, arn).is_none(), "{arn}: its own name is never an alias");
        }
    }

    #[test]
    fn infra_state_read_refuses_a_fifo_without_blocking_and_a_symlink() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let state = paths.infra_state();
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        let c = std::ffi::CString::new(state.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // A plain open of a FIFO without a writer blocks: read on a thread and give up after a while.
        let (tx, rx) = std::sync::mpsc::channel();
        let p = paths.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_infra_state(&p).map_err(|e| e.to_string()));
        });
        let got = rx.recv_timeout(Duration::from_secs(5)).expect("read_infra_state blocked on a FIFO");
        assert!(got.as_ref().unwrap_err().contains("not a regular file"), "{got:?}");
        std::fs::remove_file(&state).unwrap();
        let real = d.path().join("real.toml");
        std::fs::write(&real, "stack = \"dev\"\n").unwrap();
        std::os::unix::fs::symlink(&real, &state).unwrap();
        let err = read_infra_state(&paths).unwrap_err().to_string();
        assert!(err.contains("symlink") && err.contains("infra.toml"), "{err}");
        std::fs::remove_file(&state).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(read_infra_state(&paths).unwrap_err().to_string().contains("infra.toml"), "a directory is refused");
    }

    #[test]
    fn atomic_write_sets_the_exact_mode_and_refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("claude.lock");
        // Modes the usual umasks (022, 002, 027, 077) would strip: only the fchmod gets them exactly.
        write_atomic_mode(&p, b"one", 0o666).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o666);
        write_atomic_mode(&p, b"one", 0o664).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o664);
        write_atomic_mode(&p, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(write_atomic_mode(&link, b"x", 0o600).unwrap_err().to_string().contains("symlink"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2, "no temp file left behind");
    }

    #[test]
    fn external_commands_are_pinned() {
        let args = |c: &Command| c.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let p = pulumi_outputs_cmd("dev", Path::new("infra"));
        assert_eq!(args(&p), ["stack", "output", "--json", "--stack", "dev", "--cwd", "infra"]);
        assert!(!args(&p).iter().any(|a| a.contains("secret")));
        let a = base_image_cmd("al2023-1");
        assert_eq!(args(&a), ["lambda-microvms", "list-managed-microvm-image-versions", "--image-identifier", "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "--region", "eu-central-1", "--output", "json"]);
        let l = live_image_cmd(ARN);
        assert_eq!(args(&l), ["lambda-microvms", "get-microvm-image", "--image-identifier", ARN, "--region", "eu-central-1", "--output", "json"]);
        assert!(l.get_envs().any(|(k, v)| k == "CLAUDE_CODE_OAUTH_TOKEN" && v.is_none()), "no OAuth token for aws");
        let c = crate::bridge::awscli::aws_cmd("lambda-core", &live_connector_args(CONNECTOR)).unwrap();
        assert_eq!(args(&c), ["lambda-core", "get-network-connector", "--identifier", CONNECTOR, "--region", "eu-central-1", "--endpoint-url", "https://lambda.eu-central-1.amazonaws.com", "--output", "json"]);
        assert!(c.get_envs().any(|(k, v)| k == "CLAUDE_CODE_OAUTH_TOKEN" && v.is_none()), "no OAuth token for aws");
        assert!(safe_name("dev") && safe_name("org/ai-env/dev") && !safe_name("-x") && !safe_name("a b") && !safe_name(""));
    }

    fn managed(status_of_1: &str) -> String {
        serde_json::json!({"items": [
            {"imageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "imageVersion": "1", "status": status_of_1, "createdAt": "2026-07-31T19:21:07.059000+03:00"},
            {"imageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "imageVersion": "0", "status": "AVAILABLE", "createdAt": "2026-06-29T20:11:01.714000+03:00"}
        ]})
        .to_string()
    }

    #[test]
    fn base_image_available_passes_every_other_status_fails() {
        assert_eq!(base_image_verdict(&managed("AVAILABLE"), "1").unwrap(), "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1 version 1: AVAILABLE");
        for status in ["DEPRECATED", "EXPIRING", "EXPIRED", "RECALLED", "SOMETHING_NEW"] {
            let err = base_image_verdict(&managed(status), "1").unwrap_err();
            assert!(err.contains(&format!("version 1 is {status}")), "{status}: {err}");
        }
        assert!(base_image_verdict(&managed("AVAILABLE"), "0").is_ok());
        assert_eq!(base_image_verdict(&managed("AVAILABLE"), "2").unwrap_err(), "version 2 not listed (listed: 1, 0)");
        assert_eq!(base_image_verdict("{\"items\": []}", "1").unwrap_err(), "version 1 not listed (listed: none)");
        assert!(base_image_verdict("{\"items\": [{\"imageVersion\": 1}]}", "1").unwrap_err().contains("no status"), "a numeric version still matches");
        assert!(base_image_verdict("nope", "1").unwrap_err().starts_with("not JSON"));
    }

    fn versions(rows: &[(&str, &str, &str)]) -> String {
        let items: Vec<serde_json::Value> = rows.iter().map(|(v, state, status)| serde_json::json!({"imageArn": ARN, "imageVersion": v, "state": state, "status": status, "baseImageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1"})).collect();
        serde_json::json!({"items": items}).to_string()
    }

    #[test]
    fn versions_diff_added_removed_changed() {
        let before = versions(&[("1", "SUCCESSFUL", "ACTIVE"), ("2", "SUCCESSFUL", "ACTIVE"), ("10", "FAILED", "INACTIVE")]);
        let after = versions(&[("2", "SUCCESSFUL", "INACTIVE"), ("3", "SUCCESSFUL", "ACTIVE"), ("10", "FAILED", "INACTIVE")]);
        let d = versions_diff(&before, &after).unwrap();
        let v = |x: &str, s: &str, t: &str| VersionInfo { version: x.into(), state: Some(s.into()), status: Some(t.into()) };
        assert_eq!(d.added, vec![v("3", "SUCCESSFUL", "ACTIVE")]);
        assert_eq!(d.removed, vec![v("1", "SUCCESSFUL", "ACTIVE")]);
        assert_eq!(d.changed, vec![(v("2", "SUCCESSFUL", "ACTIVE"), v("2", "SUCCESSFUL", "INACTIVE"))]);
        assert_eq!(d.unchanged, vec![v("10", "FAILED", "INACTIVE")], "10 sorts after 2 numerically");
        assert_eq!(d.probe_verdict(), "deleted:1");
        let kept = versions_diff(&versions(&[("1", "SUCCESSFUL", "ACTIVE")]), &versions(&[("1", "SUCCESSFUL", "ACTIVE"), ("2", "IN_PROGRESS", "INACTIVE")])).unwrap();
        assert_eq!(kept.probe_verdict(), "kept");
        assert_eq!(kept.added.len(), 1);
    }

    #[test]
    fn versions_diff_orders_the_services_n0_versions_numerically() {
        let d = versions_diff(&versions(&[("10.0", "SUCCESSFUL", "ACTIVE"), ("9.0", "SUCCESSFUL", "INACTIVE"), ("x", "FAILED", "INACTIVE")]), "{}").unwrap();
        let order: Vec<&str> = d.removed.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(order, ["9.0", "10.0", "x"], "9.0 before 10.0, non-numbers last");
        let mixed = versions_diff(&versions(&[("10.0", "SUCCESSFUL", "ACTIVE"), ("9", "SUCCESSFUL", "ACTIVE")]), "{}").unwrap();
        assert_eq!(mixed.removed.iter().map(|v| v.version.as_str()).collect::<Vec<_>>(), ["9", "10.0"]);
    }

    #[test]
    fn versions_diff_accepts_empty_snapshots_and_refuses_bad_ones() {
        let after = versions(&[("1", "SUCCESSFUL", "ACTIVE")]);
        for empty in ["", "  \n", "{}", "{\"items\": []}", "{\"items\": null}", "[]"] {
            let d = versions_diff(empty, &after).unwrap();
            assert_eq!((d.added.len(), d.probe_verdict().as_str()), (1, "kept"), "{empty:?}");
        }
        let d = versions_diff(&after, "{}").unwrap();
        assert_eq!(d.probe_verdict(), "deleted:1");
        assert!(versions_diff("{\"items\": [{\"state\": \"x\"}]}", "{}").unwrap_err().contains("before: an item has no imageVersion"));
        assert!(versions_diff("{}", &versions(&[("1", "A", "B"), ("1", "A", "B")])).unwrap_err().contains("after: version 1 is listed twice"));
        assert!(versions_diff("nope", "{}").unwrap_err().starts_with("before: not JSON"));
        assert!(versions_diff("{}", "{\"items\": 3}").unwrap_err().contains("not an array"));
    }

    #[test]
    fn probe_counts_a_version_moving_into_a_deletion_state_as_deleted() {
        let before = versions(&[("1", "SUCCESSFUL", "ACTIVE"), ("2", "SUCCESSFUL", "INACTIVE"), ("10", "FAILED", "INACTIVE")]);
        for state in ["DELETING", "DELETED", "DELETE_FAILED"] {
            let after = versions(&[("1", state, "INACTIVE"), ("2", "SUCCESSFUL", "INACTIVE"), ("3", "SUCCESSFUL", "ACTIVE"), ("10", "FAILED", "INACTIVE")]);
            let d = versions_diff(&before, &after).unwrap();
            assert!(d.removed.is_empty(), "{state}: still listed");
            assert_eq!(d.probe_verdict(), "deleted:1", "{state}");
        }
        // One gone and one deleting: both, in version order.
        let after = versions(&[("2", "SUCCESSFUL", "INACTIVE"), ("3", "SUCCESSFUL", "ACTIVE"), ("10", "DELETING", "INACTIVE")]);
        assert_eq!(versions_diff(&before, &after).unwrap().probe_verdict(), "deleted:1,10");
        // A version already being deleted (or deleted) before the deploy is not the deploy's doing.
        let before = versions(&[("1", "DELETED", "INACTIVE"), ("2", "DELETING", "INACTIVE"), ("3", "SUCCESSFUL", "ACTIVE")]);
        let after = versions(&[("1", "DELETED", "INACTIVE"), ("3", "SUCCESSFUL", "INACTIVE"), ("4", "SUCCESSFUL", "ACTIVE")]);
        let d = versions_diff(&before, &after).unwrap();
        assert_eq!((d.probe_verdict().as_str(), d.live_before()), ("kept", 1));
        assert_eq!(versions_diff("{}", &after).unwrap().live_before(), 0);
    }

    #[test]
    fn a_truncated_listing_is_refused() {
        let page = versions(&[("1", "SUCCESSFUL", "ACTIVE")]);
        for key in ["nextToken", "NextToken"] {
            let mut v: serde_json::Value = serde_json::from_str(&page).unwrap();
            v[key] = serde_json::json!("page-2");
            let truncated = v.to_string();
            let err = versions_diff(&truncated, &page).unwrap_err();
            assert!(err.starts_with("before: ") && err.contains("snapshot is truncated") && err.contains("re-list without --max-items"), "{key}: {err}");
            assert!(versions_diff(&page, &truncated).unwrap_err().starts_with("after: "), "{key}");
            assert!(base_image_verdict(&truncated, "1").unwrap_err().contains("truncated"), "{key}");
            v[key] = serde_json::Value::Null;
            assert_eq!(versions_diff(&v.to_string(), &page).unwrap().probe_verdict(), "kept", "{key}: a null token is the last page");
        }
    }
}
