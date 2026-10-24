//! The AWS operator identities (S8 operators): who every `aws` child of an
//! operator command runs as, and the marker [`RUNNER_MARKER`]
//! (`AI_ENV_BRIDGE_AS`) that `ai-env as` leaves in its command's environment.
//!
//! Pulumi makes three IAM users and never a key: `ai-env-deployer` (its key
//! lives only in Strongbox and is pasted per command), `ai-env-ops` (its key
//! is sealed in `credentials/ops.env` and opened by one Touch ID) and
//! `ai-env-runtime` (the key of VMs and sessions, `credentials/aws.env`). The
//! marker says which identity a process tree runs as: `deployer:TAIL` or
//! `ops:TAIL` (that role's key is in `AWS_ACCESS_KEY_ID` and
//! `AWS_SECRET_ACCESS_KEY`, its id ending in `TAIL`), `root` (the aws CLI's
//! own chain, declared as the account root: the bootstrap and break-glass)
//! or `ambient` (the aws CLI's own chain, declared, never the root).
//!
//! A deployer or ops child loses every variable that could select other
//! credentials, and gets the profile files pinned to `/dev/null`, IMDS off
//! and the region pinned ([`apply_with`]), so a descendant that loses the key
//! finds no other one; an ambient child keeps the aws CLI's chain and gets
//! only the region, the pager and the configured endpoints pinned. A key
//! reaches a child through its environment only, never its argv or a file.
//!
//! First the foundation: the marker, a key in memory ([`EnvKey`]), the
//! environment of a child, the caller's identity and how it is judged
//! against the stack's account ([`parse_caller`], [`judge`], [`expected`]),
//! the sts check of a key ([`check_key`]), and a sealed key's notes and its
//! unseal ([`KeyNotes`], [`unseal_key`]). After it: the runner `ai-env as`
//! and the in-process resolver of an operator command's identity.
use crate::age_cmd::AgeTool;
use crate::bridge::awscli::{arn_account, aws_cmd};
use crate::bridge::config::{BridgeConfig, Paths, REGION};
use crate::bridge::creds::{aws_env_state, key_id_fault, secret_fault, AwsEnvState};
use crate::bridge::doctor::{capture, Captured};
use crate::bridge::infra::read_infra_state;
use crate::bridge::unseal::UnsealJob;
use crate::bridge::voice;
use crate::errors::{CliError, Result};
use crate::store::{validate_key_name, Keystore};
use crate::wire::redact::{register_secret, scrub};
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// `AI_ENV_BRIDGE_AS` (defined beside `ai-env run`, which drops it from a
/// child that gets another key).
pub use crate::commands::RUNNER_MARKER;

/// The deploy identity: the stack's three deploy policies, its supplement and
/// `ai-env-ops`; its key lives in Strongbox only (`ai-env as deployer`).
pub const DEPLOYER_USER: &str = "ai-env-deployer";
/// The daily operator: proxy start and stop, the proxy's SSM documents, the
/// suspended list, read-only status; its key is `credentials/ops.env`.
pub const OPS_USER: &str = "ai-env-ops";
/// The runtime principal of VMs and sessions (`credentials/aws.env`).
pub const RUNTIME_USER: &str = "ai-env-runtime";

/// Removed from the runner's CMD and from every deployer or ops `aws` child.
pub const CREDENTIAL_SELECTORS: [&str; 14] = [
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ACCOUNT_ID",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
];
/// And every inherited name that starts with one of these.
pub const SELECTOR_PREFIXES: [&str; 2] = ["AWS_CONTAINER_", "AWS_ENDPOINT_URL"];
/// Set on the runner's CMD and on every deployer or ops `aws` child.
pub const IDENTITY_PINS: [(&str, &str); 7] = [
    ("AWS_CONFIG_FILE", "/dev/null"),
    ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
    ("AWS_EC2_METADATA_DISABLED", "true"),
    ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"),
    ("AWS_REGION", REGION),
    ("AWS_DEFAULT_REGION", REGION),
    ("AWS_PAGER", ""),
];
/// Set on every `aws` child of an ambient operator (root or ambient); no credential variable is touched.
pub const AMBIENT_PINS: [(&str, &str); 4] = [("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"), ("AWS_REGION", REGION), ("AWS_DEFAULT_REGION", REGION), ("AWS_PAGER", "")];

// ---- identities and the marker ---------------------------------------------------------

/// Who `ai-env as` runs a command as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Identity {
    /// ai-env-deployer, its key pasted from Strongbox
    Deployer,
    /// ai-env-ops, its key unsealed from credentials/ops.env (one Touch ID)
    Ops,
    /// the account root through the aws CLI's own credentials: the bootstrap and break-glass only
    Root,
    /// the aws CLI's own credentials, declared; never the root
    Ambient,
}

impl Identity {
    /// `deployer`, `ops`, `root` or `ambient`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Identity::Deployer => "deployer",
            Identity::Ops => "ops",
            Identity::Root => "root",
            Identity::Ambient => "ambient",
        }
    }
}

/// The identities whose key is in the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Deployer,
    Ops,
}

impl Role {
    /// [`DEPLOYER_USER`] or [`OPS_USER`].
    #[must_use]
    pub fn user(self) -> &'static str {
        match self {
            Role::Deployer => DEPLOYER_USER,
            Role::Ops => OPS_USER,
        }
    }

    /// `deployer` or `ops`.
    #[must_use]
    pub fn word(self) -> &'static str {
        self.identity().word()
    }

    #[must_use]
    pub fn identity(self) -> Identity {
        match self {
            Role::Deployer => Identity::Deployer,
            Role::Ops => Identity::Ops,
        }
    }
}

/// The value of [`RUNNER_MARKER`]; only `ai-env as` sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Marker {
    /// `deployer:TAIL` or `ops:TAIL`: the role's key is in this environment,
    /// its id ending in `TAIL` (four of `0-9 A-Z`).
    Key { role: Role, tail: String },
    /// `root`: the aws CLI's own chain, declared as the account root.
    Root,
    /// `ambient`: the aws CLI's own chain, declared, never the root.
    Ambient,
}

/// Four of `0-9 A-Z`: the last characters of an `AKIA` key id.
fn is_tail(tail: &str) -> bool {
    tail.len() == 4 && tail.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// The refusal of a marker value ai-env never sets (exit 9 for the caller):
/// the value scrubbed, without control characters, cut to 40 characters.
fn unparseable(value: &str) -> String {
    let shown: String = scrub(value).chars().map(|c| if c.is_control() { '?' } else { c }).take(40).collect();
    format!("{RUNNER_MARKER}={shown} is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it")
}

impl Marker {
    /// `deployer:TAIL`, `ops:TAIL`, `root` or `ambient`, exactly; anything
    /// else is the refusal text.
    pub fn parse(value: &str) -> std::result::Result<Marker, String> {
        let key = |role: Role, tail: &str| is_tail(tail).then(|| Marker::Key { role, tail: tail.to_string() });
        let parsed = match value.split_once(':') {
            Some(("deployer", tail)) => key(Role::Deployer, tail),
            Some(("ops", tail)) => key(Role::Ops, tail),
            Some(_) => None,
            None if value == "root" => Some(Marker::Root),
            None if value == "ambient" => Some(Marker::Ambient),
            None => None,
        };
        parsed.ok_or_else(|| unparseable(value))
    }

    /// `deployer:ABCD`, `ops:WXYZ`, `root` or `ambient`.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Marker::Key { role, tail } => format!("{}:{tail}", role.word()),
            Marker::Root | Marker::Ambient => self.word().to_string(),
        }
    }

    /// The marker of this process: `None` when [`RUNNER_MARKER`] is unset or
    /// empty (no marker), else its parse. Reads the environment only: it never
    /// unseals anything (doctor relies on that).
    #[must_use]
    pub fn from_env() -> Option<std::result::Result<Marker, String>> {
        marker_of(std::env::var_os(RUNNER_MARKER))
    }

    /// Is a key marker's key in the environment? `id` and `secret` are this
    /// process's `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`: an `AKIA` id
    /// ending in the marker's tail and a secret access key, both registered
    /// with the scrubber here. `root` and `ambient` need nothing. A session
    /// token beside the key is not a fault: every child loses it anyway.
    pub fn check_env(&self, id: Option<&str>, secret: Option<&str>) -> std::result::Result<(), String> {
        let Marker::Key { role, tail } = self else {
            return Ok(());
        };
        for value in [id, secret].into_iter().flatten() {
            register_secret(value);
        }
        let (word, named) = (role.word(), format!("{RUNNER_MARKER} names the {} key ...{tail}", role.word()));
        if !id.is_some_and(|id| key_id_fault(id).is_none() && id.ends_with(tail.as_str())) {
            return Err(format!("{named}, but AWS_ACCESS_KEY_ID holds another key (or none): something between ai-env as and this command changed it; run the command directly under ai-env as {word} --"));
        }
        if !secret.is_some_and(|s| secret_fault(s).is_none()) {
            return Err(format!("{named}, but AWS_SECRET_ACCESS_KEY is missing or not a secret access key: run the command directly under ai-env as {word} --"));
        }
        Ok(())
    }

    /// Whether a process under this marker already runs as `want`: the
    /// deployer covers ops, the root covers the deployer and ops, and an
    /// ambient identity covers ops. A key marker's key is [`Marker::check_env`]'s.
    #[must_use]
    pub fn covers(&self, want: Identity) -> bool {
        match self {
            Marker::Key { role: Role::Deployer, .. } => matches!(want, Identity::Deployer | Identity::Ops),
            Marker::Key { role: Role::Ops, .. } => want == Identity::Ops,
            Marker::Root => matches!(want, Identity::Deployer | Identity::Ops | Identity::Root),
            Marker::Ambient => matches!(want, Identity::Ops | Identity::Ambient),
        }
    }

    /// `deployer`, `ops`, `root` or `ambient`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Marker::Key { role, .. } => role.word(),
            Marker::Root => "root",
            Marker::Ambient => "ambient",
        }
    }
}

/// [`Marker::from_env`] over a value read from the environment.
fn marker_of(value: Option<OsString>) -> Option<std::result::Result<Marker, String>> {
    let value = value.filter(|v| !v.is_empty())?;
    Some(match value.to_str() {
        Some(v) => Marker::parse(v),
        None => Err(unparseable(&value.to_string_lossy())),
    })
}

// ---- a key in memory and the environment of a child ----------------------------------

/// A long-term key in memory; the secret is zeroized on drop. `Debug` shows
/// `EnvKey(...ABCD)`, the last four characters of the id; there is no
/// `Display` and no `Clone`.
pub struct EnvKey {
    id: String,
    secret: Zeroizing<String>,
}

impl EnvKey {
    /// Both values are registered with the scrubber first, then checked: an
    /// `AKIA` id of 20 characters and a 40-character secret access key. The
    /// refusal names the fault (`access key id …`, `secret access key …`),
    /// never a value.
    pub fn new(id: String, secret: Zeroizing<String>) -> std::result::Result<EnvKey, String> {
        register_secret(&id);
        register_secret(&secret);
        if let Some(fault) = key_id_fault(&id) {
            return Err(format!("access key id {fault}"));
        }
        if let Some(fault) = secret_fault(&secret) {
            return Err(format!("secret access key {fault}"));
        }
        Ok(EnvKey { id, secret })
    }

    /// The access key id (not a secret; shown only in a delete command).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The id's last four characters: all of it that notes and rows show.
    #[must_use]
    pub fn tail(&self) -> &str {
        &self.id[self.id.len() - 4..]
    }

    /// The secret access key: its only read, for a child's environment.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for EnvKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EnvKey(...{})", self.tail())
    }
}

/// The identity an operator command's `aws` children run as.
#[derive(Debug)]
pub enum Operator {
    /// A valid key marker: the key is in this process's environment.
    Runner { role: Role, tail: String },
    /// `credentials/ops.env`, unsealed by this process.
    Sealed { key: EnvKey },
    /// The marker `root` (`root: true`) or `ambient`: the aws CLI's own chain.
    Ambient { root: bool },
}

impl Operator {
    /// The role whose key the children get: a runner's, or ops for the sealed key.
    #[must_use]
    pub fn role(&self) -> Option<Role> {
        match self {
            Operator::Runner { role, .. } => Some(*role),
            Operator::Sealed { .. } => Some(Role::Ops),
            Operator::Ambient { .. } => None,
        }
    }

    /// `ai-env-deployer (key ...ABCD, ai-env as deployer)`, `ai-env-ops (key
    /// ...WXYZ, credentials/ops.env)`, `the account ROOT (ai-env as root)`, …
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Operator::Runner { role, tail } => format!("{} (key ...{tail}, ai-env as {})", role.user(), role.word()),
            Operator::Sealed { key } => format!("{OPS_USER} (key ...{}, credentials/ops.env)", key.tail()),
            Operator::Ambient { root: true } => "the account ROOT (ai-env as root)".to_string(),
            Operator::Ambient { root: false } => "the ambient aws CLI identity (ai-env as ambient)".to_string(),
        }
    }

    /// How a command printed for a person to run starts when it needs more
    /// than ops may do (an IAM write, the deployer's unmasked CloudTrail read,
    /// A11): on this Mac a bare `aws` has no credentials once root's key is
    /// retired, so it names the runner that can run it: `ai-env as root -- `
    /// for the account root's operator, `ai-env as ambient -- ` for an ambient
    /// one (another account's own credentials, where the stack's deployer does
    /// not exist), else `ai-env as deployer -- ` (ops.sh's `as_writer`, A24).
    #[must_use]
    pub fn writer_runner(&self) -> &'static str {
        match self {
            Operator::Ambient { root: true } => AS_ROOT,
            Operator::Ambient { root: false } => AS_AMBIENT,
            Operator::Runner { .. } | Operator::Sealed { .. } => AS_DEPLOYER,
        }
    }
}

/// The runners a printed command starts with ([`Operator::writer_runner`], [`writer_runner`]).
const AS_ROOT: &str = "ai-env as root -- ";
const AS_AMBIENT: &str = "ai-env as ambient -- ";
const AS_DEPLOYER: &str = "ai-env as deployer -- ";

/// [`Operator::writer_runner`] from this process's marker alone, for a
/// command that resolves no operator (sealing a key, the hand-over): the
/// account root's runner under `root` (the bootstrap, `make operator-keys`,
/// break-glass: the deployer may have no key yet), the ambient one under
/// `ambient`, else (a key marker, an unparseable one, none) the deployer's,
/// who writes the keys in every other run. Reads the environment only.
#[must_use]
pub fn writer_runner() -> &'static str {
    writer_runner_of(Marker::from_env())
}

/// [`writer_runner`] of a marker as [`Marker::from_env`] reads it.
fn writer_runner_of(marker: Option<std::result::Result<Marker, String>>) -> &'static str {
    match marker {
        Some(Ok(Marker::Root)) => AS_ROOT,
        Some(Ok(Marker::Ambient)) => AS_AMBIENT,
        _ => AS_DEPLOYER,
    }
}

/// Every [`CREDENTIAL_SELECTORS`] name, and every one of `names` that starts
/// with a [`SELECTOR_PREFIXES`] entry, removed from `cmd`.
fn remove_selectors(cmd: &mut Command, names: impl IntoIterator<Item = OsString>) {
    for name in CREDENTIAL_SELECTORS {
        cmd.env_remove(name);
    }
    for name in names {
        if SELECTOR_PREFIXES.iter().any(|p| name.as_encoded_bytes().starts_with(p.as_bytes())) {
            cmd.env_remove(name);
        }
    }
}

fn pin(cmd: &mut Command, pins: &[(&str, &str)]) {
    for (name, value) in pins {
        cmd.env(name, value);
    }
}

/// The sealed key's environment: the selectors and the marker gone, the
/// pins, then the key.
fn apply_sealed(cmd: &mut Command, key: &EnvKey, names: impl IntoIterator<Item = OsString>) {
    remove_selectors(cmd, names);
    cmd.env_remove(RUNNER_MARKER);
    pin(cmd, &IDENTITY_PINS);
    cmd.env("AWS_ACCESS_KEY_ID", key.id()).env("AWS_SECRET_ACCESS_KEY", key.expose_secret());
}

/// Give `cmd` the environment of `op`, `names` being the variables it would
/// inherit (this process's, for the prefixed selectors). A runner's child
/// keeps the inherited key and marker; the sealed key's child gets its key
/// and loses the marker; an ambient child only gets [`AMBIENT_PINS`]. Pure:
/// nothing is read from this process.
///
/// After this (and [`apply_key`]) the secret may sit in `cmd`, and std's
/// `Debug` of a `Command` prints every variable set on it: such a command is
/// never Debug-formatted (no `{:?}`, no tracing `?cmd`, no `dbg!`); an error
/// names `cmd.get_program()` only.
pub fn apply_with(cmd: &mut Command, op: &Operator, names: impl IntoIterator<Item = OsString>) {
    match op {
        Operator::Runner { .. } => {
            remove_selectors(cmd, names);
            pin(cmd, &IDENTITY_PINS);
        }
        Operator::Sealed { key } => apply_sealed(cmd, key, names),
        Operator::Ambient { .. } => pin(cmd, &AMBIENT_PINS),
    }
}

/// [`apply_with`]'s sealed row for `key`, over this process's variables: the
/// runner's command, and every check of a key that is not the operator's.
/// The secret is then in `cmd`: never Debug-format it ([`apply_with`]).
pub fn apply_key(cmd: &mut Command, key: &EnvKey) {
    apply_sealed(cmd, key, std::env::vars_os().map(|(name, _)| name));
}

// ---- the caller and the stack's account ------------------------------------------------

/// What `aws sts get-caller-identity` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub arn: String,
    /// The 12-digit `Account`.
    pub account: String,
    /// The IAM user's name (the last segment of its path); `None` for the
    /// root and anything that is not a user of `account` (an assumed role).
    pub user: Option<String>,
}

impl Verified {
    /// `arn:aws:iam::<account>:root`.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.arn == format!("arn:aws:iam::{}:root", self.account)
    }

    /// `user/<name>`, `root`, or the ARN's resource part.
    #[must_use]
    pub fn short(&self) -> String {
        match &self.user {
            Some(name) => format!("user/{name}"),
            None if self.is_root() => "root".to_string(),
            None => self.arn.splitn(6, ':').nth(5).unwrap_or(&self.arn).to_string(),
        }
    }
}

/// Twelve ASCII digits.
fn is_account(text: &str) -> bool {
    text.len() == 12 && text.bytes().all(|b| b.is_ascii_digit())
}

/// The JSON of `aws sts get-caller-identity --output json`: `Account` must be
/// 12 digits and `Arn` start with `arn:aws:`.
pub fn parse_caller(json: &str) -> std::result::Result<Verified, String> {
    let doc: serde_json::Value = serde_json::from_str(json).map_err(|_| "unreadable answer: not JSON".to_string())?;
    let field = |name: &str| doc.get(name).and_then(serde_json::Value::as_str);
    let account = field("Account").filter(|a| is_account(a)).ok_or("unreadable answer: no 12-digit Account")?;
    let arn = field("Arn").filter(|a| a.starts_with("arn:aws:")).ok_or("unreadable answer: no Arn starting arn:aws:")?;
    let user = arn.strip_prefix(&format!("arn:aws:iam::{account}:user/")).and_then(|path| path.rsplit('/').next()).filter(|name| !name.is_empty()).map(str::to_string);
    Ok(Verified { arn: arn.to_string(), account: account.to_string(), user })
}

/// Who a key must answer as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Want<'a> {
    pub user: &'a str,
    /// The stack's account, when known.
    pub account: Option<&'a str>,
    /// The exact user ARN `state/infra.toml` records, when it does.
    pub arn: Option<&'a str>,
    /// Where `account` and `arn` come from (`state/infra.toml`, `bridge.toml [aws]`, `--account`).
    pub source: &'static str,
}

/// Why an answer is not [`Want`]'s identity: every one is a policy refusal (exit 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// The account root's own key.
    Root { account: String },
    /// Another user, or not a user at all.
    OtherPrincipal { arn: String },
    /// The right user name in another account.
    OtherAccount { arn: String, account: String, want: String, source: &'static str },
    /// The right user name and account, but not the user the stack records.
    OtherArn { arn: String, want: String, source: &'static str },
}

/// Judge an answer, in this order: the root, the user name, the account (when
/// `want` names one), the exact ARN (when it names one).
pub fn judge(v: &Verified, want: &Want<'_>) -> std::result::Result<(), Mismatch> {
    if v.is_root() {
        return Err(Mismatch::Root { account: v.account.clone() });
    }
    if v.user.as_deref() != Some(want.user) {
        return Err(Mismatch::OtherPrincipal { arn: v.arn.clone() });
    }
    if let Some(account) = want.account.filter(|a| *a != v.account) {
        return Err(Mismatch::OtherAccount { arn: v.arn.clone(), account: v.account.clone(), want: account.to_string(), source: want.source });
    }
    if let Some(arn) = want.arn.filter(|a| *a != v.arn) {
        return Err(Mismatch::OtherArn { arn: v.arn.clone(), want: arn.to_string(), source: want.source });
    }
    Ok(())
}

/// The stack's account and operator users as this Mac knows them, with no AWS call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    pub account: Option<String>,
    /// The first source present: `state/infra.toml`, `bridge.toml [aws]` or `--account`.
    pub source: Option<&'static str>,
    /// `state/infra.toml`'s `deployer_user_arn` and `ops_user_arn`.
    pub deployer_arn: Option<String>,
    pub ops_arn: Option<String>,
}

impl Expected {
    /// What a key of `user` must answer as: the stack's account, and the user's
    /// exact ARN for the deployer and ops when the state records it.
    #[must_use]
    pub fn want<'a>(&'a self, user: &'a str) -> Want<'a> {
        let arn = match user {
            DEPLOYER_USER => self.deployer_arn.as_deref(),
            OPS_USER => self.ops_arn.as_deref(),
            _ => None,
        };
        Want { user, account: self.account.as_deref(), arn, source: self.source.unwrap_or("no source") }
    }
}

/// `account_id <a>` or `<field> in <a>`.
fn account_of_field(field: &str, account: &str) -> String {
    if field == "account_id" {
        format!("account_id {account}")
    } else {
        format!("{field} in {account}")
    }
}

/// The account `fields` of one source agree on (the first present one), or
/// `None` when none is present; two that differ are exit 1 naming both.
fn one_account(source: &str, fields: &[(&str, Option<&str>)], fix: &str) -> Result<Option<String>> {
    let present: Vec<(&str, &str)> = fields.iter().filter_map(|(field, account)| account.map(|a| (*field, a))).collect();
    let Some(&(first_field, first)) = present.first() else {
        return Ok(None);
    };
    if let Some(&(field, other)) = present.iter().find(|(_, account)| *account != first) {
        return Err(CliError::Msg(format!("{source} disagrees with itself ({}, {}): {fix}", account_of_field(first_field, first), account_of_field(field, other))));
    }
    Ok(Some(first.to_string()))
}

/// An ARN's account, for an ARN that names one.
fn account_in(arn: Option<&str>) -> Option<&str> {
    arn.and_then(arn_account)
}

/// The stack's account and operator users, read with no AWS call, in this
/// order: `state/infra.toml` (`account_id` and the accounts of
/// `deployer_user_arn`, `ops_user_arn` and `image_arn`; the two user ARNs
/// also become [`Expected::deployer_arn`] and [`Expected::ops_arn`]), then
/// `bridge.toml [aws]` (the accounts of `image_arn`, `egress_connector_arn`
/// and `execution_role_arn`), then `flag` (`--account`). Every source present
/// must agree; none gives no account. A malformed `flag` is a usage error
/// (exit 2); two accounts that differ are exit 1, as is a state or a
/// `bridge.toml` that cannot be read.
pub fn expected(paths: &Paths, flag: Option<&str>) -> Result<Expected> {
    if let Some(flag) = flag.filter(|f| !is_account(f)) {
        return Err(CliError::Usage(format!("--account {}: expected the 12 digits of an AWS account", scrub(flag))));
    }
    let mut sources: Vec<(&'static str, String)> = Vec::new();
    let mut out = Expected::default();
    if let Some(state) = read_infra_state(paths)? {
        let arn = |a: &Option<String>| a.clone().filter(|a| arn_account(a).is_some());
        let (deployer, ops) = (arn(&state.deployer_user_arn), arn(&state.ops_user_arn));
        let fields = [
            ("account_id", state.account_id.as_deref().filter(|a| !a.is_empty())),
            ("deployer_user_arn", account_in(deployer.as_deref())),
            ("ops_user_arn", account_in(ops.as_deref())),
            ("image_arn", arn_account(&state.image_arn)),
        ];
        if let Some(account) = one_account("state/infra.toml", &fields, "make infra-status WRITE=1")? {
            sources.push(("state/infra.toml", account));
        }
        (out.deployer_arn, out.ops_arn) = (deployer, ops);
    }
    if let Some(cfg) = BridgeConfig::load(paths)? {
        let aws = &cfg.aws;
        let fields = [
            ("image_arn", account_in(aws.image_arn.as_deref())),
            ("egress_connector_arn", account_in(aws.egress_connector_arn.as_deref())),
            ("execution_role_arn", account_in(aws.execution_role_arn.as_deref())),
        ];
        if let Some(account) = one_account("bridge.toml [aws]", &fields, "make infra-status WRITE=1 (or fix bridge.toml [aws])")? {
            sources.push(("bridge.toml [aws]", account));
        }
    }
    if let Some(flag) = flag {
        sources.push(("--account", flag.to_string()));
    }
    let Some((source, account)) = sources.first().cloned() else {
        return Ok(out);
    };
    if let Some((other, theirs)) = sources.iter().find(|(_, a)| *a != account) {
        return Err(CliError::Msg(format!(
            "the stack's account is ambiguous: {source} says {account}, {other} says {theirs}: make infra-status WRITE=1 (or fix bridge.toml [aws]), then run it again"
        )));
    }
    out.account = Some(account);
    out.source = Some(source);
    Ok(out)
}

// ---- the sts check of a key ------------------------------------------------------------

/// How long one `aws sts get-caller-identity` of a key may take.
const STS_TIMEOUT: Duration = Duration::from_secs(20);
/// The error codes of a key AWS does not accept (yet): deleted, deactivated,
/// not propagated, a wrong secret, an expired session.
const REFUSED_CODES: [&str; 6] = ["InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException", "AuthFailure", "InvalidAccessKeyId", "ExpiredToken"];

/// How long a new key may take to answer: at most `tries` sts calls, `step`
/// apart; a refusal ends it when `refused_is_final`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyWait {
    pub tries: u32,
    pub step: Duration,
    pub refused_is_final: bool,
}

impl KeyWait {
    /// A pasted deployer key (`ai-env as deployer`): it exists already, so a refusal is final.
    pub const PASTED: KeyWait = KeyWait { tries: 2, step: Duration::from_secs(2), refused_is_final: true };
    /// A deployer key just created (`creds deployer-key`): IAM takes a while to propagate it.
    pub const NEW_KEY: KeyWait = KeyWait { tries: 8, step: Duration::from_secs(5), refused_is_final: false };
    /// A key just sealed (`creds aws-verify`).
    pub const SEALED: KeyWait = KeyWait { tries: 6, step: Duration::from_secs(5), refused_is_final: false };

    /// Every second of `step` becomes `ms_per_second` milliseconds
    /// (`AI_ENV_BRIDGE_LAB_BACKOFF_MS`, debug builds); the tries stay.
    fn scaled(self, ms_per_second: Option<u64>) -> KeyWait {
        let Some(ms) = ms_per_second else {
            return self;
        };
        KeyWait { step: Duration::from_micros(u64::try_from(self.step.as_micros()).unwrap_or(u64::MAX).saturating_mul(ms) / 1000), ..self }
    }
}

/// Why a key's check ended without a verdict, or with the wrong identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCheck {
    /// AWS refused the key: one of the codes above.
    Refused(String),
    /// No answer: no aws CLI, a timeout, throttling, a network error, an
    /// unreadable answer (the first error line).
    Failed(String),
    /// It answered as another identity.
    Mismatch(Verified, Mismatch),
}

/// One sts call with only `key`.
enum Try {
    Answered(Verified),
    Refused(String),
    Failed(String),
}

/// What a note or an error carries of a failure: one line, scrubbed, at most 300 characters.
fn one_line(text: &str) -> String {
    scrub(text.trim().lines().next().unwrap_or_default().trim()).chars().take(300).collect()
}

fn sts_try(key: &EnvKey, run: &mut dyn FnMut(Command) -> std::result::Result<Captured, String>) -> Try {
    let mut cmd = match aws_cmd("sts", &["get-caller-identity"]) {
        Ok(cmd) => cmd,
        Err(e) => return Try::Failed(e),
    };
    apply_key(&mut cmd, key);
    let answer = match run(cmd) {
        Ok(answer) => answer,
        Err(e) => return Try::Failed(one_line(&e)),
    };
    if answer.success {
        return match parse_caller(&answer.stdout) {
            Ok(v) => Try::Answered(v),
            Err(e) => Try::Failed(e),
        };
    }
    if let Some(code) = REFUSED_CODES.iter().find(|code| answer.stderr.contains(*code)) {
        return Try::Refused((*code).to_string());
    }
    let line = one_line(&answer.stderr);
    Try::Failed(if line.is_empty() { answer.code.map_or_else(|| "aws: killed by a signal".to_string(), |code| format!("aws: exit {code}")) } else { line })
}

/// Check that `key` answers as `user` of the stack ([`Expected::want`]):
/// `aws sts get-caller-identity` with only this key ([`apply_key`]), through
/// `doctor::capture` with a 20 s timeout, at most `wait.tries` times,
/// `wait.step` apart (scaled in debug builds by the lab's backoff knob). Before
/// each retry the note `<label> ...<tail> does not answer yet (<n>/<tries>:
/// IAM propagation)`, or the failure's first line in place of `IAM
/// propagation`. The answer is judged once.
// KeyCheck is large (a mismatch carries the answer and why): one per check, so not worth a box.
#[allow(clippy::result_large_err)]
pub fn check_key(key: &EnvKey, user: &str, exp: &Expected, wait: KeyWait, label: &str) -> std::result::Result<Verified, KeyCheck> {
    let wait = wait.scaled(crate::bridge::lab::vm_knobs().backoff_ms);
    check_key_with(key, user, exp, wait, label, &mut |cmd| capture(cmd, None, STS_TIMEOUT), &mut std::thread::sleep)
}

/// [`check_key`] with its runner and its sleep given (the tests'), and `wait` as it is.
#[allow(clippy::result_large_err)] // as check_key
pub fn check_key_with(
    key: &EnvKey,
    user: &str,
    exp: &Expected,
    wait: KeyWait,
    label: &str,
    run: &mut dyn FnMut(Command) -> std::result::Result<Captured, String>,
    sleep: &mut dyn FnMut(Duration),
) -> std::result::Result<Verified, KeyCheck> {
    let tries = wait.tries.max(1);
    let mut last = KeyCheck::Failed(String::new());
    for n in 1..=tries {
        let (failure, why) = match sts_try(key, run) {
            Try::Answered(v) => {
                return match judge(&v, &exp.want(user)) {
                    Ok(()) => Ok(v),
                    Err(m) => Err(KeyCheck::Mismatch(v, m)),
                };
            }
            Try::Refused(code) if wait.refused_is_final => return Err(KeyCheck::Refused(code)),
            Try::Refused(code) => (KeyCheck::Refused(code), "IAM propagation".to_string()),
            Try::Failed(line) => (KeyCheck::Failed(line.clone()), line),
        };
        if n < tries {
            voice::note(&format!("{label} ...{} does not answer yet ({n}/{tries}: {why})", key.tail()));
            sleep(wait.step);
        }
        last = failure;
    }
    Err(last)
}

// ---- sealed keys ----------------------------------------------------------------------

/// What a sealed key's container records in its `# ai-env-meta:` line:
/// unauthenticated, for display only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyNotes {
    pub kind: Option<String>,
    pub user: Option<String>,
    pub key_id_last4: Option<String>,
    /// Unix seconds.
    pub sealed_at: Option<u64>,
}

impl KeyNotes {
    /// The notes of a container's text ([`crate::container::meta`]); a tail
    /// that is not four of `0-9 A-Z` or a time that does not parse is absent.
    #[must_use]
    pub fn of(container_text: &str) -> KeyNotes {
        let meta = crate::container::meta(container_text);
        KeyNotes {
            kind: meta.get("kind").cloned(),
            user: meta.get("user").cloned(),
            key_id_last4: meta.get("key_id_last4").filter(|t| is_tail(t)).cloned(),
            sealed_at: meta.get("sealed").and_then(|s| parse_rfc3339_utc(s)),
        }
    }

    /// `kind=aws-key user=<user> key_id_last4=<tail> sealed=<RFC 3339 UTC>`:
    /// what a sealed key's container records.
    #[must_use]
    pub fn pairs(user: &str, tail: &str, sealed_at: u64) -> Vec<(&'static str, String)> {
        vec![("kind", "aws-key".to_string()), ("user", user.to_string()), ("key_id_last4", tail.to_string()), ("sealed", rfc3339_utc(sealed_at))]
    }

    /// The day of [`KeyNotes::sealed_at`], in UTC, as `YYYY-MM-DD`: what
    /// `creds status` and doctor show (`sealed 2026-10-14`), the same day
    /// in both whatever the local time zone.
    #[must_use]
    pub fn sealed_day(&self) -> Option<String> {
        self.sealed_at.map(|t| {
            let mut day = rfc3339_utc(t);
            if let Some(at) = day.find('T') {
                day.truncate(at);
            }
            day
        })
    }
}

/// The two sealed AWS keys of `credentials/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFile {
    /// `credentials/aws.env`, `ai-env-runtime`'s.
    Runtime,
    /// `credentials/ops.env`, `ai-env-ops`'s.
    Ops,
}

impl KeyFile {
    #[must_use]
    pub fn path(self, paths: &Paths) -> PathBuf {
        match self {
            KeyFile::Runtime => paths.aws_env(),
            KeyFile::Ops => paths.ops_env(),
        }
    }

    #[must_use]
    pub fn user(self) -> &'static str {
        match self {
            KeyFile::Runtime => RUNTIME_USER,
            KeyFile::Ops => OPS_USER,
        }
    }

    /// What the Touch ID countdown names.
    #[must_use]
    pub fn what(self) -> &'static str {
        match self {
            KeyFile::Runtime => "the runtime key (credentials/aws.env)",
            KeyFile::Ops => "the ops key (credentials/ops.env)",
        }
    }

    /// How the key is sealed (anew, with ` ROTATE=1`).
    #[must_use]
    pub fn seal_hint(self) -> &'static str {
        match self {
            KeyFile::Runtime => "make runtime-key",
            KeyFile::Ops => "ai-env as deployer -- make ops-key",
        }
    }

    /// The file under the bridge root.
    fn file(self) -> &'static str {
        match self {
            KeyFile::Runtime => "credentials/aws.env",
            KeyFile::Ops => "credentials/ops.env",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            KeyFile::Runtime => "the runtime key",
            KeyFile::Ops => "the ops key",
        }
    }
}

/// Unseal the key of `file` (one Touch ID): the file must be a sealed
/// container (absent or not one: exit 5 naming the seal hint), opened with
/// the explicit `[creds].key` of `bridge.toml` (a key the keystore lacks:
/// exit 4) as an [`UnsealJob`] of `[creds].unseal_timeout_s` with its
/// countdown on stderr (a dismissed dialog: exit 3; the deadline: exit 5);
/// the plaintext must be exactly the two variables `creds aws-set` seals
/// (else exit 5), and stays in zeroizing memory. A stop signal ends this
/// process as it would without the dialog; `age` runs in its own process
/// group, so its dialog then stays up until it is answered or dismissed.
pub fn unseal_key(store: &Keystore, paths: &Paths, file: KeyFile) -> Result<EnvKey> {
    unseal_key_with(store, paths, file, &AgeTool::probe)
}

/// [`unseal_key`] with the age tool given (the tests' fake).
fn unseal_key_with(store: &Keystore, paths: &Paths, file: KeyFile, probe: &dyn Fn() -> Result<AgeTool>) -> Result<EnvKey> {
    let path = file.path(paths);
    let absent = || CliError::AuthUnavailable(format!("{} does not exist: seal {} with {}", path.display(), file.noun(), file.seal_hint()));
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return Err(absent()),
        AwsEnvState::NotSealed(why) => {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and rotate the key it may hold: {} ROTATE=1)", path.display(), file.seal_hint())));
        }
    }
    let cfg = BridgeConfig::load(paths)?.unwrap_or_default();
    validate_key_name(&cfg.creds.key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = crate::bridge::registry::read_regular_file(&path)?.ok_or_else(absent)?;
    let cont = crate::container::read(&text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(cfg.creds.key.as_str()), &cont)?;
    let age = Arc::new(probe()?);
    let plain = UnsealJob::start(age, store.identity_path(&name), cont.data, cfg.creds.unseal_budget(), file.what())
        .with_prefix(voice::prefix())
        .wait(crate::bridge::signals::say)?;
    let reseal = format!("re-seal it with {} ROTATE=1", file.seal_hint());
    let (id, secret) = crate::bridge::vm::client::parse_key_env(&plain, file.file(), &reseal)?;
    drop(plain);
    EnvKey::new(id, secret).map_err(|e| CliError::AuthUnavailable(format!("{}: {e} ({reseal})", file.file())))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod foundation_tests {
    use super::*;
    use std::path::Path;

    const STACK: &str = "123456789012";
    const OTHER: &str = "999999999999";

    /// `AKIA`, `FAKE`, eight zeros and `tail`: the shape `tests/fakes/aws.sh`
    /// builds, made at run time (no key-shaped literal in the sources).
    fn key_id(tail: &str) -> String {
        format!("{}FAKE{}{tail}", "AKIA", "0".repeat(8))
    }

    /// 40 characters of the secret alphabet: `block` ten times.
    fn secret(block: &str) -> String {
        block.repeat(10)
    }

    fn env_key(tail: &str, block: &str) -> EnvKey {
        EnvKey::new(key_id(tail), Zeroizing::new(secret(block))).unwrap()
    }

    fn user_arn(account: &str, path: &str) -> String {
        format!("arn:aws:iam::{account}:user/{path}")
    }

    /// `(name, value)` of every variable `cmd` sets (`Some`) or removes (`None`).
    fn envs(cmd: &Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect()
    }

    fn set(envs: &[(String, Option<String>)], name: &str) -> Option<String> {
        envs.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.clone())
    }

    fn removed(envs: &[(String, Option<String>)], name: &str) -> bool {
        envs.iter().any(|(k, v)| k == name && v.is_none())
    }

    fn touched(envs: &[(String, Option<String>)], name: &str) -> bool {
        envs.iter().any(|(k, _)| k == name)
    }

    #[test]
    fn the_marker_parses_renders_and_refuses_anything_else() {
        for (text, marker) in [
            ("deployer:9001", Marker::Key { role: Role::Deployer, tail: "9001".into() }),
            ("ops:AB12", Marker::Key { role: Role::Ops, tail: "AB12".into() }),
            ("ops:ZZZZ", Marker::Key { role: Role::Ops, tail: "ZZZZ".into() }),
            ("root", Marker::Root),
            ("ambient", Marker::Ambient),
        ] {
            assert_eq!(Marker::parse(text), Ok(marker.clone()), "{text}");
            assert_eq!(marker.render(), text, "the render is the value ai-env as sets");
        }
        let words: Vec<&str> = [Marker::parse("deployer:9001"), Marker::parse("ops:9002"), Marker::parse("root"), Marker::parse("ambient")].iter().map(|m| m.as_ref().unwrap().word()).collect();
        assert_eq!(words, ["deployer", "ops", "root", "ambient"]);
        for bad in [
            "deployer", "ops", "deployer:", "ops:", "deployer:900", "deployer:90012", "deployer:ab12", "ops:AB-1", "deployer:9001:x", "runtime:9003", "root:9001", "ambient:9001", "Root", "ROOT",
            " root", "root ", "ambient\n", "deployer :9001", "deployer: 9001", "",
        ] {
            let e = Marker::parse(bad).expect_err(bad);
            assert!(e.starts_with("AI_ENV_BRIDGE_AS=") && e.ends_with(" is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it"), "{bad:?}: {e}");
        }
        assert_eq!(Marker::parse("runtime:9003").unwrap_err(), "AI_ENV_BRIDGE_AS=runtime:9003 is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it");
        // The value is scrubbed, has no control character left, and is cut to 40 characters.
        let id = format!("{}{}", "AKIA", "QZ".repeat(8));
        let e = Marker::parse(&format!("deployer:{id}")).unwrap_err();
        assert!(!e.contains(&id) && e.contains("AKIA[redacted:len=20]"), "{e}");
        let e = Marker::parse(&format!("x\ny{}", "z".repeat(60))).unwrap_err();
        assert_eq!(e, format!("AI_ENV_BRIDGE_AS=x?y{} is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it", "z".repeat(37)));
        // From the environment: unset and empty are no marker; a value that is not UTF-8 is refused.
        assert_eq!(marker_of(None), None);
        assert_eq!(marker_of(Some(OsString::new())), None);
        assert_eq!(marker_of(Some(OsString::from("ops:9002"))), Some(Ok(Marker::Key { role: Role::Ops, tail: "9002".into() })));
        assert!(marker_of(Some(OsString::from("nope"))).is_some_and(|m| m.is_err()));
        use std::os::unix::ffi::OsStringExt as _;
        let not_utf8 = marker_of(Some(OsString::from_vec(vec![b'r', 0xff, b't']))).unwrap().unwrap_err();
        assert!(not_utf8.starts_with("AI_ENV_BRIDGE_AS=r\u{fffd}t is not one ai-env sets"), "{not_utf8}");
    }

    #[test]
    fn coverage_follows_the_table() {
        use Identity::{Ambient, Deployer, Ops, Root};
        let deployer = Marker::Key { role: Role::Deployer, tail: "9001".into() };
        let ops = Marker::Key { role: Role::Ops, tail: "9002".into() };
        let table: [(&Marker, &[Identity]); 4] = [(&deployer, &[Deployer, Ops]), (&ops, &[Ops]), (&Marker::Root, &[Deployer, Ops, Root]), (&Marker::Ambient, &[Ops, Ambient])];
        for (marker, covered) in table {
            for want in [Deployer, Ops, Root, Ambient] {
                assert_eq!(marker.covers(want), covered.contains(&want), "{} covers {}?", marker.render(), want.word());
            }
        }
        assert_eq!([Deployer, Ops, Root, Ambient].map(Identity::word), ["deployer", "ops", "root", "ambient"]);
        assert_eq!((Role::Deployer.user(), Role::Ops.user()), (DEPLOYER_USER, OPS_USER));
        assert_eq!((Role::Deployer.identity(), Role::Ops.identity()), (Deployer, Ops));
        // The operators: their role and the phrases the runner and the resolver print.
        let runner = Operator::Runner { role: Role::Deployer, tail: "9001".into() };
        let sealed = Operator::Sealed { key: env_key("T002", "Kv6+") };
        assert_eq!((runner.role(), sealed.role(), Operator::Ambient { root: true }.role()), (Some(Role::Deployer), Some(Role::Ops), None));
        assert_eq!(runner.describe(), "ai-env-deployer (key ...9001, ai-env as deployer)");
        assert_eq!(Operator::Runner { role: Role::Ops, tail: "9002".into() }.describe(), "ai-env-ops (key ...9002, ai-env as ops)");
        assert_eq!(sealed.describe(), "ai-env-ops (key ...T002, credentials/ops.env)");
        assert_eq!(Operator::Ambient { root: true }.describe(), "the account ROOT (ai-env as root)");
        assert_eq!(Operator::Ambient { root: false }.describe(), "the ambient aws CLI identity (ai-env as ambient)");
    }

    /// D13 (recheck): a command printed for a person to run starts with the
    /// runner that can run it on this Mac, where a bare `aws` has no
    /// credentials: the account root's under `root`, the ambient one under
    /// `ambient`, the deployer's under a key marker, an unparseable one or
    /// none; an operator resolved from the same marker says the same.
    #[test]
    fn printed_commands_start_with_the_runner_that_can_run_them() {
        let deployer = Marker::Key { role: Role::Deployer, tail: "9001".into() };
        let ops = Marker::Key { role: Role::Ops, tail: "9002".into() };
        let unparseable = Marker::parse("runtime:9003");
        assert!(unparseable.is_err());
        for (marker, want) in [
            (None, "ai-env as deployer -- "),
            (Some(Ok(deployer)), "ai-env as deployer -- "),
            (Some(Ok(ops)), "ai-env as deployer -- "),
            (Some(unparseable), "ai-env as deployer -- "),
            (Some(Ok(Marker::Root)), "ai-env as root -- "),
            (Some(Ok(Marker::Ambient)), "ai-env as ambient -- "),
        ] {
            let shown = format!("{marker:?}");
            assert_eq!(writer_runner_of(marker), want, "{shown}");
        }
        for (op, want) in [
            (Operator::Runner { role: Role::Deployer, tail: "9001".into() }, "ai-env as deployer -- "),
            (Operator::Runner { role: Role::Ops, tail: "9002".into() }, "ai-env as deployer -- "),
            (Operator::Sealed { key: env_key("T003", "Wr5+") }, "ai-env as deployer -- "),
            (Operator::Ambient { root: true }, "ai-env as root -- "),
            (Operator::Ambient { root: false }, "ai-env as ambient -- "),
        ] {
            assert_eq!(op.writer_runner(), want, "{}", op.describe());
        }
    }

    #[test]
    fn a_key_marker_needs_its_key_in_the_environment() {
        let (id, other_id, sec) = (key_id("9001"), key_id("9009"), secret("Jm4/"));
        let deployer = Marker::Key { role: Role::Deployer, tail: "9001".into() };
        assert_eq!(deployer.check_env(Some(&id), Some(&sec)), Ok(()));
        let wrong_id = "AI_ENV_BRIDGE_AS names the deployer key ...9001, but AWS_ACCESS_KEY_ID holds another key (or none): something between ai-env as and this command changed it; run the command directly under ai-env as deployer --";
        let asia = format!("{}{}", "ASIA", &id[4..]);
        for bad_id in [None, Some(other_id.as_str()), Some(asia.as_str()), Some(&id[..19]), Some("9001")] {
            assert_eq!(deployer.check_env(bad_id, Some(&sec)).unwrap_err(), wrong_id, "{bad_id:?}");
        }
        let wrong_secret = "AI_ENV_BRIDGE_AS names the deployer key ...9001, but AWS_SECRET_ACCESS_KEY is missing or not a secret access key: run the command directly under ai-env as deployer --";
        let (short, odd) = (sec[..39].to_string(), format!("{}-", &sec[..39]));
        for bad_secret in [None, Some(short.as_str()), Some(odd.as_str()), Some("")] {
            assert_eq!(deployer.check_env(Some(&id), bad_secret).unwrap_err(), wrong_secret, "{bad_secret:?}");
        }
        // The id is checked first; the ops marker names its own role.
        let ops = Marker::Key { role: Role::Ops, tail: "9002".into() };
        assert!(ops.check_env(None, None).unwrap_err().starts_with("AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_ACCESS_KEY_ID"));
        assert!(ops.check_env(Some(&key_id("9002")), None).unwrap_err().ends_with("run the command directly under ai-env as ops --"));
        // The values read are registered with the scrubber, a refused one too.
        assert!(!scrub(&format!("x {short} y")).contains(&short), "the refused secret is masked");
        assert!(!scrub(&sec).contains(&sec));
        // root and ambient need nothing.
        for marker in [Marker::Root, Marker::Ambient] {
            assert_eq!(marker.check_env(None, None), Ok(()));
        }
    }

    #[test]
    fn apply_removes_every_selector_and_pins_the_files() {
        let inherited = ["AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "PATH", "HOME", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", RUNNER_MARKER, "XAWS_ENDPOINT_URL"];
        let names = || inherited.iter().map(OsString::from);
        let pins_set = |e: &[(String, Option<String>)], pins: &[(&str, &str)]| {
            for (name, value) in pins {
                assert_eq!(set(e, name).as_deref(), Some(*value), "{name} pinned");
            }
        };
        let selectors_gone = |e: &[(String, Option<String>)]| {
            for name in CREDENTIAL_SELECTORS.iter().chain(&["AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI"]) {
                assert!(removed(e, name), "{name} removed: {e:?}");
            }
            for name in ["PATH", "HOME", "XAWS_ENDPOINT_URL"] {
                assert!(!touched(e, name), "{name} is not a selector: {e:?}");
            }
        };
        // A runner's child keeps the inherited key and marker.
        let mut cmd = Command::new("aws");
        apply_with(&mut cmd, &Operator::Runner { role: Role::Ops, tail: "9002".into() }, names());
        let e = envs(&cmd);
        selectors_gone(&e);
        pins_set(&e, &IDENTITY_PINS);
        for name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", RUNNER_MARKER] {
            assert!(!touched(&e, name), "{name} stays inherited: {e:?}");
        }
        // The sealed key's child gets that key and loses the marker.
        let key = env_key("T003", "Kv6+");
        let mut cmd = Command::new("aws");
        cmd.arg("sts").arg("get-caller-identity");
        apply_with(&mut cmd, &Operator::Sealed { key: env_key("T003", "Kv6+") }, names());
        let e = envs(&cmd);
        selectors_gone(&e);
        pins_set(&e, &IDENTITY_PINS);
        assert!(removed(&e, RUNNER_MARKER), "{e:?}");
        assert_eq!((set(&e, "AWS_ACCESS_KEY_ID"), set(&e, "AWS_SECRET_ACCESS_KEY")), (Some(key.id().to_string()), Some(key.expose_secret().to_string())));
        let argv: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(argv, ["sts", "get-caller-identity"], "the key never reaches argv");
        // apply_key is the same over this process's variables.
        let mut cmd = Command::new("aws");
        apply_key(&mut cmd, &key);
        let e = envs(&cmd);
        pins_set(&e, &IDENTITY_PINS);
        assert!(CREDENTIAL_SELECTORS.iter().chain(&[RUNNER_MARKER]).all(|n| removed(&e, n)), "{e:?}");
        assert_eq!(set(&e, "AWS_ACCESS_KEY_ID").as_deref(), Some(key.id()));
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            if SELECTOR_PREFIXES.iter().any(|p| name.starts_with(p)) {
                assert!(removed(&e, &name), "{name} of this process is removed");
            }
        }
        // An ambient child keeps the aws CLI's chain: only the region, the pager and the endpoints are pinned.
        for root in [true, false] {
            let mut cmd = Command::new("aws");
            apply_with(&mut cmd, &Operator::Ambient { root }, names());
            let e = envs(&cmd);
            pins_set(&e, &AMBIENT_PINS);
            assert_eq!(e.len(), AMBIENT_PINS.len(), "nothing else is touched: {e:?}");
            assert!(!touched(&e, "AWS_EC2_METADATA_DISABLED") && !touched(&e, "AWS_CONFIG_FILE"), "IMDS and the profile files stay the chain's");
        }
        assert_eq!(IDENTITY_PINS.iter().filter(|(n, _)| n.ends_with("REGION")).map(|(_, v)| *v).collect::<Vec<_>>(), ["eu-central-1", "eu-central-1"]);
    }

    #[test]
    fn env_keys_are_shape_checked_registered_and_never_shown() {
        let (id, sec) = (key_id("T001"), secret("Jm4/"));
        let key = EnvKey::new(id.clone(), Zeroizing::new(sec.clone())).unwrap();
        assert_eq!((key.id(), key.tail(), key.expose_secret()), (id.as_str(), "T001", sec.as_str()));
        assert_eq!(format!("{key:?}"), "EnvKey(...T001)", "Debug shows the tail only");
        assert!(!scrub(&format!("[{sec}]")).contains(&sec), "the secret is registered with the scrubber");
        let asia = format!("{}{}", "ASIA", &id[4..]);
        let cases = [
            (asia.as_str(), sec.as_str(), "access key id is a temporary STS key id (ASIA…), not a long-term IAM user key (AKIA…)"),
            ("ZKIA", sec.as_str(), "access key id does not start with AKIA"),
            (&id[..19], sec.as_str(), "access key id has 19 characters, expected 20"),
            (&sec[..39], sec.as_str(), "access key id does not start with AKIA"),
            (id.as_str(), &sec[..39], "secret access key has 39 characters, expected 40"),
            (id.as_str(), "short-secret-of-the-test", "secret access key has a character outside A-Z a-z 0-9 / +"),
        ];
        for (bad_id, bad_secret, want) in cases {
            let e = EnvKey::new(bad_id.to_string(), Zeroizing::new(bad_secret.to_string())).unwrap_err();
            assert_eq!(e, want);
            assert!(!e.contains(bad_secret) && (bad_id.len() < 8 || !e.contains(bad_id)), "never a value: {e}");
        }
        let odd = format!("{}x{}", &sec[..20], &sec[21..]);
        let refused = EnvKey::new(id.clone(), Zeroizing::new(format!("{}é", &odd[..38]))).unwrap_err();
        assert!(refused.starts_with("secret access key has a character outside"), "{refused}");
        assert!(!scrub(&format!("{}é", &odd[..38])).contains(&odd[..38]), "a refused secret is registered too");
    }

    #[test]
    fn the_caller_is_parsed_and_judged() {
        let answer = |arn: &str, account: &str| format!("{{\n    \"UserId\": \"AIDAEXAMPLEUSER\",\n    \"Account\": \"{account}\",\n    \"Arn\": \"{arn}\"\n}}\n");
        let deployer = parse_caller(&answer(&user_arn(STACK, DEPLOYER_USER), STACK)).unwrap();
        assert_eq!(deployer, Verified { arn: user_arn(STACK, DEPLOYER_USER), account: STACK.into(), user: Some(DEPLOYER_USER.into()) });
        assert_eq!((deployer.short(), deployer.is_root()), ("user/ai-env-deployer".to_string(), false));
        let pathed = parse_caller(&answer(&user_arn(STACK, "ops/team/ai-env-ops"), STACK)).unwrap();
        assert_eq!((pathed.user.as_deref(), pathed.short()), (Some(OPS_USER), "user/ai-env-ops".to_string()), "the last path segment");
        let root = parse_caller(&answer(&format!("arn:aws:iam::{STACK}:root"), STACK)).unwrap();
        assert_eq!((root.user.as_deref(), root.is_root(), root.short()), (None, true, "root".to_string()));
        let role = parse_caller(&answer(&format!("arn:aws:sts::{STACK}:assumed-role/admin/session"), STACK)).unwrap();
        assert_eq!((role.user.as_deref(), role.is_root(), role.short()), (None, false, "assumed-role/admin/session".to_string()));
        let foreign_root = parse_caller(&answer(&format!("arn:aws:iam::{OTHER}:root"), STACK)).unwrap();
        assert!(!foreign_root.is_root() && foreign_root.user.is_none(), "an ARN of another account than Account is no user and no root of it");
        let unreadable: [(String, &str); 6] = [
            (String::new(), "not JSON"),
            ("[]".to_string(), "no 12-digit Account"),
            (answer(&user_arn(STACK, OPS_USER), "12345678901"), "no 12-digit Account"),
            (format!("{{\"Account\": 123456789012, \"Arn\": \"{}\"}}", user_arn(STACK, OPS_USER)), "no 12-digit Account"),
            (answer("aws:iam::123456789012:user/ai-env-ops", STACK), "no Arn starting arn:aws:"),
            (format!("{{\"Account\": \"{STACK}\"}}"), "no Arn starting arn:aws:"),
        ];
        for (bad, why) in &unreadable {
            assert_eq!(parse_caller(bad).unwrap_err(), format!("unreadable answer: {why}"), "{bad}");
        }

        let want = Want { user: DEPLOYER_USER, account: Some(STACK), arn: None, source: "state/infra.toml" };
        assert_eq!(judge(&deployer, &want), Ok(()));
        assert_eq!(judge(&root, &want), Err(Mismatch::Root { account: STACK.into() }));
        let rust = parse_caller(&answer(&user_arn(STACK, "rust"), STACK)).unwrap();
        assert_eq!(judge(&rust, &want), Err(Mismatch::OtherPrincipal { arn: user_arn(STACK, "rust") }));
        assert_eq!(judge(&role, &want), Err(Mismatch::OtherPrincipal { arn: role.arn.clone() }), "an assumed role is never the deployer");
        assert_eq!(judge(&pathed, &want), Err(Mismatch::OtherPrincipal { arn: pathed.arn.clone() }), "ops is not the deployer");
        let elsewhere = parse_caller(&answer(&user_arn(OTHER, DEPLOYER_USER), OTHER)).unwrap();
        assert_eq!(
            judge(&elsewhere, &want),
            Err(Mismatch::OtherAccount { arn: user_arn(OTHER, DEPLOYER_USER), account: OTHER.into(), want: STACK.into(), source: "state/infra.toml" })
        );
        assert_eq!(judge(&elsewhere, &Want { account: None, ..want }), Ok(()), "no account known: the user name decides");
        let other_root = parse_caller(&answer(&format!("arn:aws:iam::{OTHER}:root"), OTHER)).unwrap();
        assert_eq!(judge(&other_root, &want), Err(Mismatch::Root { account: OTHER.into() }), "the root comes first");
        // The exact ARN the state records: the same name under another path is another user.
        let exact = Want { arn: Some(&deployer.arn), ..want };
        assert_eq!(judge(&deployer, &exact), Ok(()));
        let moved = parse_caller(&answer(&user_arn(STACK, "x/ai-env-deployer"), STACK)).unwrap();
        assert_eq!(judge(&moved, &exact), Err(Mismatch::OtherArn { arn: moved.arn.clone(), want: deployer.arn.clone(), source: "state/infra.toml" }));
    }

    /// A bridge root under `dir` with the state and bridge.toml given (`None`: no file).
    fn root_with(dir: &Path, state: Option<&crate::bridge::infra::InfraState>, bridge: Option<&str>) -> Paths {
        let paths = Paths::from_root_and_env(dir.join("bridge"), None);
        std::fs::create_dir_all(paths.infra_state().parent().unwrap()).unwrap();
        if let Some(state) = state {
            std::fs::write(paths.infra_state(), state.render().unwrap()).unwrap();
        }
        if let Some(text) = bridge {
            std::fs::write(&paths.config, text).unwrap();
        }
        paths
    }

    #[test]
    fn the_expected_account_agrees_across_sources_or_names_the_conflict() {
        use crate::bridge::infra::InfraState;
        let image = |account: &str| format!("arn:aws:lambda:eu-central-1:{account}:microvm-image:ai-env-agent");
        let state = InfraState {
            stack: "dev".into(),
            image_arn: image(STACK),
            account_id: Some(STACK.into()),
            deployer_user_arn: Some(user_arn(STACK, DEPLOYER_USER)),
            ops_user_arn: Some(user_arn(STACK, OPS_USER)),
            ..InfraState::default()
        };
        let bridge = |account: &str| format!("[aws]\nimage_arn = \"{}\"\negress_connector_arn = \"arn:aws:lambda:eu-central-1:{account}:network-connector:ai-env-egress\"\n", image(account));
        let t = tempfile::tempdir().unwrap();
        let at = |name: &str, state: Option<&InfraState>, bridge: Option<&str>| root_with(&t.path().join(name), state, bridge);

        // No source: no account (as deployer then needs --account).
        assert_eq!(expected(&at("none", None, None), None).unwrap(), Expected::default());
        let flag = expected(&at("flag", None, None), Some(OTHER)).unwrap();
        assert_eq!((flag.account.as_deref(), flag.source), (Some(OTHER), Some("--account")));
        for bad in ["12345678901", "1234567890123", "12345678901x", "", " 123456789012"] {
            let e = expected(&at("flag", None, None), Some(bad)).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad:?}");
            assert_eq!(e.to_string(), format!("--account {bad}: expected the 12 digits of an AWS account"));
        }

        // The state: its account, the source, and the users' exact ARNs.
        let full = expected(&at("state", Some(&state), None), None).unwrap();
        assert_eq!(full, Expected { account: Some(STACK.into()), source: Some("state/infra.toml"), deployer_arn: Some(user_arn(STACK, DEPLOYER_USER)), ops_arn: Some(user_arn(STACK, OPS_USER)) });
        let want = full.want(DEPLOYER_USER);
        assert_eq!((want.account, want.arn, want.source), (Some(STACK), Some(user_arn(STACK, DEPLOYER_USER).as_str()), "state/infra.toml"));
        assert_eq!(full.want(OPS_USER).arn, Some(user_arn(STACK, OPS_USER).as_str()));
        assert_eq!(full.want(RUNTIME_USER).arn, None, "only the operators' ARNs are recorded");
        // Every source agrees: the first one present is named.
        let all = expected(&at("all", Some(&state), Some(&bridge(STACK))), Some(STACK)).unwrap();
        assert_eq!((all.account.as_deref(), all.source), (Some(STACK), Some("state/infra.toml")));
        let only_bridge = expected(&at("bridge", None, Some(&bridge(STACK))), Some(STACK)).unwrap();
        assert_eq!((only_bridge.account.as_deref(), only_bridge.source, only_bridge.deployer_arn), (Some(STACK), Some("bridge.toml [aws]"), None));
        // An S5-era state: the image's account alone.
        let s5 = InfraState { account_id: None, deployer_user_arn: None, ops_user_arn: None, ..state.clone() };
        assert_eq!(expected(&at("s5", Some(&s5), None), None).unwrap().account.as_deref(), Some(STACK));

        // Two sources that differ: exit 1 naming both.
        let e = expected(&at("conflict", Some(&state), Some(&bridge(OTHER))), None).unwrap_err();
        assert_eq!(e.exit_code(), 1);
        assert_eq!(e.to_string(), format!("the stack's account is ambiguous: state/infra.toml says {STACK}, bridge.toml [aws] says {OTHER}: make infra-status WRITE=1 (or fix bridge.toml [aws]), then run it again"));
        let e = expected(&at("conflict-flag", None, Some(&bridge(STACK))), Some(OTHER)).unwrap_err();
        assert_eq!(e.to_string(), format!("the stack's account is ambiguous: bridge.toml [aws] says {STACK}, --account says {OTHER}: make infra-status WRITE=1 (or fix bridge.toml [aws]), then run it again"));
        // A state that disagrees with itself.
        let split = InfraState { deployer_user_arn: Some(user_arn(OTHER, DEPLOYER_USER)), ..state.clone() };
        let e = expected(&at("split", Some(&split), None), None).unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (1, format!("state/infra.toml disagrees with itself (account_id {STACK}, deployer_user_arn in {OTHER}): make infra-status WRITE=1")));
        let split_image = InfraState { account_id: None, image_arn: image(OTHER), ..state.clone() };
        let e = expected(&at("split-image", Some(&split_image), None), None).unwrap_err();
        assert_eq!(e.to_string(), format!("state/infra.toml disagrees with itself (deployer_user_arn in {STACK}, image_arn in {OTHER}): make infra-status WRITE=1"));
        let mixed = format!("[aws]\nimage_arn = \"{}\"\nexecution_role_arn = \"arn:aws:iam::{OTHER}:role/ai-env-exec\"\n", image(STACK));
        let e = expected(&at("mixed", None, Some(&mixed)), None).unwrap_err();
        assert_eq!(e.to_string(), format!("bridge.toml [aws] disagrees with itself (image_arn in {STACK}, execution_role_arn in {OTHER}): make infra-status WRITE=1 (or fix bridge.toml [aws])"));

        // Unreadable files: their own read errors, exit 1.
        let paths = at("garbage", None, Some("[aws\n"));
        let e = expected(&paths, None).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("bridge.toml"), "{e}");
        let paths = at("garbage-state", None, None);
        std::fs::write(paths.infra_state(), "stack = [").unwrap();
        let e = expected(&paths, Some(STACK)).unwrap_err();
        assert!(e.exit_code() == 1 && e.to_string().contains("infra.toml"), "{e}");
    }

    /// A scripted sts: each call pops the next answer and records the command.
    struct Sts {
        answers: Vec<std::result::Result<Captured, String>>,
        calls: Vec<Command>,
        slept: Vec<Duration>,
    }

    impl Sts {
        fn new(answers: Vec<std::result::Result<Captured, String>>) -> Sts {
            Sts { answers, calls: Vec::new(), slept: Vec::new() }
        }

        #[allow(clippy::result_large_err)] // as check_key
        fn check(&mut self, key: &EnvKey, exp: &Expected, wait: KeyWait) -> std::result::Result<Verified, KeyCheck> {
            let (answers, calls, slept) = (&mut self.answers, &mut self.calls, &mut self.slept);
            let mut run = |cmd: Command| {
                calls.push(cmd);
                if answers.is_empty() {
                    Err("no answer scripted".to_string())
                } else {
                    answers.remove(0)
                }
            };
            check_key_with(key, DEPLOYER_USER, exp, wait, "the key", &mut run, &mut |d| slept.push(d))
        }
    }

    fn answered(arn: &str, account: &str) -> std::result::Result<Captured, String> {
        Ok(Captured { code: Some(0), success: true, stdout: format!("{{\"UserId\": \"AIDAEXAMPLEUSER\", \"Account\": \"{account}\", \"Arn\": \"{arn}\"}}"), stderr: String::new() })
    }

    fn failed(stderr: &str) -> std::result::Result<Captured, String> {
        Ok(Captured { code: Some(254), success: false, stdout: String::new(), stderr: stderr.to_string() })
    }

    fn refused(code: &str) -> std::result::Result<Captured, String> {
        failed(&format!("\nAn error occurred ({code}) when calling the GetCallerIdentity operation: The security token included in the request is invalid.\n"))
    }

    #[test]
    fn check_key_retries_per_its_wait_and_classifies() {
        let key = env_key("T004", "Kv6+");
        let exp = Expected { account: Some(STACK.into()), source: Some("--account"), ..Expected::default() };
        let wait = KeyWait { tries: 4, step: Duration::from_millis(7), refused_is_final: false };

        // A new key: refused while IAM propagates, then the deployer.
        let mut sts = Sts::new(vec![refused("InvalidClientTokenId"), refused("InvalidClientTokenId"), answered(&user_arn(STACK, DEPLOYER_USER), STACK)]);
        let v = sts.check(&key, &exp, wait).unwrap();
        assert_eq!((v.user.as_deref(), sts.calls.len()), (Some(DEPLOYER_USER), 3));
        assert_eq!(sts.slept, [Duration::from_millis(7); 2], "a step between tries");
        // Every call is the pinned sts call with only this key, in its environment.
        for cmd in &sts.calls {
            assert_eq!(cmd.get_program(), "aws");
            let argv: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
            assert_eq!(argv, ["sts", "get-caller-identity", "--region", "eu-central-1", "--endpoint-url", "https://sts.eu-central-1.amazonaws.com", "--output", "json"]);
            let e = envs(cmd);
            assert_eq!((set(&e, "AWS_ACCESS_KEY_ID").as_deref(), set(&e, "AWS_SECRET_ACCESS_KEY").as_deref()), (Some(key.id()), Some(key.expose_secret())));
            assert!(removed(&e, "AWS_PROFILE") && removed(&e, "AWS_SESSION_TOKEN") && removed(&e, RUNNER_MARKER), "{e:?}");
            assert_eq!(set(&e, "AWS_CONFIG_FILE").as_deref(), Some("/dev/null"));
        }

        // A pasted key: a refusal is final, with its code.
        for code in REFUSED_CODES {
            let mut sts = Sts::new(vec![refused(code)]);
            assert_eq!(sts.check(&key, &exp, KeyWait::PASTED), Err(KeyCheck::Refused(code.to_string())), "{code}");
            assert_eq!((sts.calls.len(), sts.slept.len()), (1, 0));
        }
        // Never answered: the last refusal after every try, one sleep fewer than tries.
        let mut sts = Sts::new(vec![refused("ExpiredToken"); 4]);
        assert_eq!(sts.check(&key, &exp, wait), Err(KeyCheck::Refused("ExpiredToken".into())));
        assert_eq!((sts.calls.len(), sts.slept.len()), (4, 3));
        // Failures are retried and end as the last one's first line: throttling, no aws CLI, a timeout, an unreadable answer.
        let throttled = "\nAn error occurred (Throttling) when calling the GetCallerIdentity operation (reached max retries: 2): Rate exceeded\nmore\n";
        let mut sts = Sts::new(vec![failed(throttled), Err("aws: No such file or directory (os error 2)".into()), Err("aws: timed out after 20s".into()), Ok(Captured { code: Some(0), success: true, stdout: "{}".into(), stderr: String::new() })]);
        assert_eq!(sts.check(&key, &exp, wait), Err(KeyCheck::Failed("unreadable answer: no 12-digit Account".into())));
        assert_eq!(sts.calls.len(), 4);
        let mut sts = Sts::new(vec![failed(throttled)]);
        assert_eq!(sts.check(&key, &exp, KeyWait { tries: 1, ..wait }), Err(KeyCheck::Failed("An error occurred (Throttling) when calling the GetCallerIdentity operation (reached max retries: 2): Rate exceeded".into())));
        let mut sts = Sts::new(vec![failed(""), Ok(Captured { code: None, success: false, stdout: String::new(), stderr: String::new() })]);
        assert_eq!(sts.check(&key, &exp, KeyWait { tries: 2, ..KeyWait::PASTED }), Err(KeyCheck::Failed("aws: killed by a signal".into())), "a failure is retried even when a refusal is final");
        let mut sts = Sts::new(vec![failed("")]);
        assert_eq!(sts.check(&key, &exp, KeyWait { tries: 1, ..wait }), Err(KeyCheck::Failed("aws: exit 254".into())));
        // A failure and then a refusal: the refusal ends a pasted key's check.
        let mut sts = Sts::new(vec![failed(throttled), refused("SignatureDoesNotMatch")]);
        assert_eq!(sts.check(&key, &exp, KeyWait::PASTED), Err(KeyCheck::Refused("SignatureDoesNotMatch".into())));
        assert_eq!(sts.slept, [KeyWait::PASTED.step]);

        // An answer is judged once, never retried.
        let mut sts = Sts::new(vec![answered(&user_arn(STACK, "rust"), STACK), answered(&user_arn(STACK, DEPLOYER_USER), STACK)]);
        assert_eq!(sts.check(&key, &exp, wait).unwrap_err(), KeyCheck::Mismatch(parse_caller(&answered(&user_arn(STACK, "rust"), STACK).unwrap().stdout).unwrap(), Mismatch::OtherPrincipal { arn: user_arn(STACK, "rust") }));
        assert_eq!(sts.calls.len(), 1);
        let mut sts = Sts::new(vec![answered(&format!("arn:aws:iam::{STACK}:root"), STACK)]);
        assert!(matches!(sts.check(&key, &exp, wait), Err(KeyCheck::Mismatch(_, Mismatch::Root { .. }))));
        let mut sts = Sts::new(vec![answered(&user_arn(OTHER, DEPLOYER_USER), OTHER)]);
        assert!(matches!(sts.check(&key, &exp, wait), Err(KeyCheck::Mismatch(_, Mismatch::OtherAccount { source: "--account", .. }))));

        // The waits of the three callers, and the lab's scaling: a second becomes a millisecond.
        assert_eq!([KeyWait::PASTED, KeyWait::NEW_KEY, KeyWait::SEALED].map(|w| (w.tries, w.step.as_secs(), w.refused_is_final)), [(2, 2, true), (8, 5, false), (6, 5, false)]);
        assert_eq!(KeyWait::NEW_KEY.scaled(Some(1)), KeyWait { step: Duration::from_millis(5), ..KeyWait::NEW_KEY });
        assert_eq!(KeyWait::NEW_KEY.scaled(None), KeyWait::NEW_KEY);
    }

    #[test]
    fn key_notes_round_trip() {
        let pairs = KeyNotes::pairs(OPS_USER, "T005", 1_789_804_800);
        let shown: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(shown, [("kind", "aws-key"), ("user", "ai-env-ops"), ("key_id_last4", "T005"), ("sealed", "2026-09-19T08:00:00Z")]);
        let text = crate::container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &shown).unwrap();
        assert!(text.contains("\n# ai-env-meta: kind=aws-key user=ai-env-ops key_id_last4=T005 sealed=2026-09-19T08:00:00Z\nAI_ENV=1\n"), "{text}");
        assert!(crate::container::detect(&text), "still a container");
        assert_eq!(KeyNotes::of(&text), KeyNotes { kind: Some("aws-key".into()), user: Some(OPS_USER.into()), key_id_last4: Some("T005".into()), sealed_at: Some(1_789_804_800) });
        // The sealing day is the UTC one, up to its last second.
        assert_eq!(KeyNotes::of(&text).sealed_day().as_deref(), Some("2026-09-19"));
        for (at, day) in [(1_789_776_000, "2026-09-19"), (1_789_862_399, "2026-09-19"), (1_789_862_400, "2026-09-20")] {
            assert_eq!(KeyNotes { sealed_at: Some(at), ..KeyNotes::default() }.sealed_day().as_deref(), Some(day), "{at}");
        }
        assert_eq!(KeyNotes::default().sealed_day(), None);
        // A container without notes, and notes that are not a key's shape.
        assert_eq!(KeyNotes::of(&crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")), KeyNotes::default());
        let odd = crate::container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &[("kind", "aws-key"), ("key_id_last4", "t005"), ("sealed", "yesterday")]).unwrap();
        assert_eq!(KeyNotes::of(&odd), KeyNotes { kind: Some("aws-key".into()), ..KeyNotes::default() });
        // The two key files.
        let paths = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!((KeyFile::Runtime.path(&paths), KeyFile::Ops.path(&paths)), (PathBuf::from("/r/credentials/aws.env"), PathBuf::from("/r/credentials/ops.env")));
        assert_eq!((KeyFile::Runtime.user(), KeyFile::Ops.user()), (RUNTIME_USER, OPS_USER));
        assert_eq!((KeyFile::Runtime.what(), KeyFile::Ops.what()), ("the runtime key (credentials/aws.env)", "the ops key (credentials/ops.env)"));
        assert_eq!((KeyFile::Runtime.seal_hint(), KeyFile::Ops.seal_hint()), ("make runtime-key", "ai-env as deployer -- make ops-key"));
    }

    /// The repo's fake age (`tests/fakes/age.sh`, read only) behind a wrapper in `dir`.
    fn fake_age(dir: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fakes/age.sh");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let (age, keygen) = (bin.join("age"), bin.join("age-keygen"));
        for p in [&age, &keygen] {
            std::fs::write(p, format!("#!/bin/sh\nexec /bin/sh {} \"$@\"\n", src.display())).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        (age, keygen)
    }

    #[test]
    fn unseal_key_opens_the_sealed_file_and_names_its_seal_hint() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(t.path().join("bridge"), None);
        let store = Keystore::resolve(Some(t.path().join("keystore"))).unwrap();
        let (age, keygen) = fake_age(t.path());
        let probe = || -> Result<AgeTool> { Ok(AgeTool::for_tests(age.clone(), keygen.clone(), (1, 3, 2))) };
        let ops = paths.ops_env();
        let unseal = |file: KeyFile| unseal_key_with(&store, &paths, file, &probe);

        let e = unseal(KeyFile::Ops).unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (5, format!("{} does not exist: seal the ops key with ai-env as deployer -- make ops-key", ops.display())));
        let e = unseal(KeyFile::Runtime).unwrap_err();
        assert_eq!(e.to_string(), format!("{} does not exist: seal the runtime key with make runtime-key", paths.aws_env().display()));
        std::fs::create_dir_all(paths.credentials()).unwrap();
        std::fs::write(&ops, "AWS_ACCESS_KEY_ID=plaintext\n").unwrap();
        let e = unseal(KeyFile::Ops).unwrap_err();
        assert_eq!(
            (e.exit_code(), e.to_string()),
            (5, format!("{} is not an ai-env container (plaintext?): move it away (and rotate the key it may hold: ai-env as deployer -- make ops-key ROTATE=1)", ops.display()))
        );

        // Sealed to the [creds].key the keystore lacks: exit 4, before any dialog.
        let (id, sec) = (key_id("T006"), secret("Op7/"));
        let recipients = t.path().join("recipients.txt");
        std::fs::write(&recipients, "age1fake\n").unwrap();
        let seal = |plain: &str| {
            let ct = AgeTool::for_tests(age.clone(), keygen.clone(), (1, 3, 2)).encrypt(&recipients, plain.as_bytes()).unwrap();
            let notes = KeyNotes::pairs(OPS_USER, "T006", 1_789_804_800);
            let notes: Vec<(&str, &str)> = notes.iter().map(|(k, v)| (*k, v.as_str())).collect();
            std::fs::write(&ops, crate::container::write_annotated(&ct, &notes).unwrap()).unwrap();
        };
        seal(&format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={sec}\n"));
        assert_eq!(unseal(KeyFile::Ops).unwrap_err().exit_code(), 4);
        std::fs::create_dir_all(store.key_dir("ai-env-bridge")).unwrap();
        std::fs::write(store.identity_path("ai-env-bridge"), "AGE-PLUGIN-SE-FAKE\n").unwrap();

        // One unseal gives the key.
        let key = unseal(KeyFile::Ops).unwrap();
        assert_eq!((key.id(), key.tail(), key.expose_secret()), (id.as_str(), "T006", sec.as_str()));
        assert_eq!(KeyNotes::of(&std::fs::read_to_string(&ops).unwrap()).key_id_last4.as_deref(), Some("T006"));
        // A plaintext of another shape: exit 5 naming the file and how to seal it anew, never a value.
        for (plain, why) in [
            (format!("AWS_SECRET_ACCESS_KEY={sec}\n"), "AWS_ACCESS_KEY_ID is missing".to_string()),
            (format!("AWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={}\n", &sec[..39]), "AWS_SECRET_ACCESS_KEY has 39 characters, expected 40".to_string()),
            (format!("AWS_ACCESS_KEY_ID={id}\nAWS_SESSION_TOKEN=x\n"), "line 2: unexpected key AWS_SESSION_TOKEN (expected exactly AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)".to_string()),
            (format!("{sec}\n"), "line 1 is not KEY=VALUE".to_string()),
            (String::new(), "the unsealed plaintext is empty".to_string()),
        ] {
            seal(&plain);
            let e = unseal(KeyFile::Ops).unwrap_err();
            assert_eq!(e.exit_code(), 5, "{why}");
            assert_eq!(e.to_string(), format!("credentials unavailable: credentials/ops.env: {why} (re-seal it with ai-env as deployer -- make ops-key ROTATE=1)"));
            assert!(!e.to_string().contains(&sec[..39]), "never a value: {e}");
        }
    }
}

// ---- the runner and the resolver (W2a) ----
//
// `ai-env as` (`cmd_as`, §3) execs a command as one identity and leaves the
// marker; the resolver (`operator`, `verified`, §4) gives every `aws` child
// of an operator command its identity: the runner's key, else
// `credentials/ops.env` (one Touch ID, once per process), else exit 5. The
// aws CLI's own chain is used only under the markers `root` and `ambient`,
// never as a fallback.

use crate::bridge::doctor::run_capture_cmd;
use crate::ceremony::{read_secret_tty_only, trim_in_place, NO_TTY};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Why an operator command has no identity (exit 5; the caller's label goes before it).
pub(crate) const NO_OPERATOR: &str =
    "no AWS operator identity: no ai-env as … runs this command and the ops key is not sealed (credentials/ops.env): seal it with ai-env as deployer -- make ops-key, or run the command under ai-env as deployer --";

/// A runner's or the sealed key answering as the account root (exit 9).
const OPERATOR_ROOT: &str = "the operator credentials are the account ROOT's: operator commands never run as root after the bootstrap (ai-env as ops --, ai-env as deployer --)";

/// `ai-env as deployer` without the stack's account (exit 1).
const UNKNOWN_ACCOUNT: &str =
    "as deployer: the stack's account is unknown here (no state/infra.toml, no [aws] ARN in bridge.toml): pass --account with its 12 digits, or run `ai-env as root -- make infra-status WRITE=1` after the bootstrap";

/// What a stop signal at `ai-env as deployer`'s pastes says before the
/// process ends with 128 + the signal (after the clipboard's warning when it
/// could not be cleared).
const PASTE_STOPPED: &str = "as deployer: stopped at the paste: nothing was run";

/// The longest command a note shows (its words joined, scrubbed), `…` included.
const SHOWN_MAX: usize = 120;

// ---- labels and the per-process cache ----------------------------------------------------

/// `e` as the command `what` reports it: `<what>: ` before its text, its exit
/// class kept (a cancel stays the plain `cancelled`, a passed-through status
/// stays silent).
#[must_use]
pub fn labelled(what: &str, e: CliError) -> CliError {
    let with = |m: String| format!("{what}: {m}");
    match e {
        CliError::Msg(m) => CliError::Msg(with(m)),
        CliError::Usage(m) => CliError::Usage(with(m)),
        CliError::NoKey(m) => CliError::NoKey(with(m)),
        CliError::AuthUnavailable(m) => CliError::AuthUnavailable(with(m)),
        CliError::Corrupt(m) => CliError::Corrupt(with(m)),
        CliError::Aws(m) => CliError::Aws(with(m)),
        CliError::VmLost(m) => CliError::VmLost(with(m)),
        CliError::Policy(m) => CliError::Policy(with(m)),
        other @ (CliError::Cancelled | CliError::BrokenPipe | CliError::Exit(_)) => other,
    }
}

/// A copy of `e`: every caller of a cached resolution gets its own.
fn copy_error(e: &CliError) -> CliError {
    match e {
        CliError::Msg(m) => CliError::Msg(m.clone()),
        CliError::Usage(m) => CliError::Usage(m.clone()),
        CliError::Cancelled => CliError::Cancelled,
        CliError::NoKey(m) => CliError::NoKey(m.clone()),
        CliError::AuthUnavailable(m) => CliError::AuthUnavailable(m.clone()),
        CliError::Corrupt(m) => CliError::Corrupt(m.clone()),
        CliError::Aws(m) => CliError::Aws(m.clone()),
        CliError::VmLost(m) => CliError::VmLost(m.clone()),
        CliError::Policy(m) => CliError::Policy(m.clone()),
        CliError::BrokenPipe => CliError::BrokenPipe,
        CliError::Exit(code) => CliError::Exit(*code),
    }
}

/// The keystore root [`init`] remembered: the lazy unseal of `credentials/ops.env` opens it.
static STORE: Mutex<Option<PathBuf>> = Mutex::new(None);
/// This process's operator, a failure included: a dismissed Touch ID is not asked again.
static OPERATOR: Mutex<Option<std::result::Result<Arc<Operator>, CliError>>> = Mutex::new(None);
/// This process's one `sts get-caller-identity` as the operator, a failure included.
static VERIFIED: Mutex<Option<std::result::Result<Arc<Verified>, CliError>>> = Mutex::new(None);

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a cache slot hands out: the same `Arc`, or a copy of the failure.
fn cached<T>(slot: &std::result::Result<Arc<T>, CliError>) -> Result<Arc<T>> {
    slot.as_ref().map(Arc::clone).map_err(copy_error)
}

/// Remember the keystore of this run (`cli::run`, right after it is
/// resolved): an operator command without a marker unseals
/// `credentials/ops.env` with it, lazily, at most once.
pub fn init(store: &Keystore) {
    *locked(&STORE) = Some(store.root().to_path_buf());
}

/// Drop the cached operator and answer (the end of `cli::run`): the last
/// reference to a sealed key goes, and its secret is zeroized.
pub fn forget() {
    drop(locked(&OPERATOR).take());
    drop(locked(&VERIFIED).take());
}

/// This process's `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (a value that is not UTF-8 is none).
fn key_variables() -> (Option<String>, Option<String>) {
    (std::env::var("AWS_ACCESS_KEY_ID").ok(), std::env::var("AWS_SECRET_ACCESS_KEY").ok())
}

// ---- the resolver (§4) ---------------------------------------------------------------------

/// The operator a parsed marker declares, `id` and `secret` being this
/// process's key variables (a key marker must find its key there, §2.2):
/// `Runner` for a key marker, `Ambient` for `root` and `ambient`. `Err` is
/// the §2.5 refusal (exit 9 for the caller).
pub fn declared_operator(marker: std::result::Result<Marker, String>, id: Option<&str>, secret: Option<&str>) -> std::result::Result<Operator, String> {
    let marker = marker?;
    marker.check_env(id, secret)?;
    Ok(match marker {
        Marker::Key { role, tail } => Operator::Runner { role, tail },
        Marker::Root => Operator::Ambient { root: true },
        Marker::Ambient => Operator::Ambient { root: false },
    })
}

/// The identity this process declares, from the marker alone: `None`
/// without one. Never unseals anything and makes no AWS call (doctor's).
#[must_use]
pub fn declared() -> Option<std::result::Result<Operator, String>> {
    let marker = Marker::from_env()?;
    let (id, secret) = key_variables();
    Some(declared_operator(marker, id.as_deref(), secret.as_deref()))
}

/// The identity of this process's operator `aws` children (§4.1), resolved
/// once and cached, a failure included: the marker's (a `root` or
/// `ambient` one checked with this process's one [`verified`] call, D20),
/// else `credentials/ops.env` unsealed (one Touch ID, the countdown, then
/// the note `operator ai-env-ops (key ...WXYZ, credentials/ops.env)`), else
/// exit 5. The aws CLI's own chain is never a fallback. Errors carry no
/// label: callers put theirs before them ([`labelled`]).
pub fn operator() -> Result<Arc<Operator>> {
    let mut slot = locked(&OPERATOR);
    if let Some(done) = slot.as_ref() {
        return cached(done);
    }
    let resolved = resolve().map(Arc::new);
    let out = cached(&resolved);
    *slot = Some(resolved);
    out
}

fn resolve() -> Result<Operator> {
    let Some(marker) = Marker::from_env() else {
        return sealed_operator();
    };
    let (id, secret) = key_variables();
    let op = declared_operator(marker, id.as_deref(), secret.as_deref()).map_err(CliError::Policy)?;
    if matches!(op, Operator::Ambient { .. }) {
        // A leftover or exported `root`/`ambient` marker never runs a command on another principal.
        verified_of(&op)?;
    }
    Ok(op)
}

/// No marker: `credentials/ops.env`, unsealed by this process, or exit 5.
fn sealed_operator() -> Result<Operator> {
    let paths = Paths::resolve()?;
    if matches!(aws_env_state(&paths.ops_env()), AwsEnvState::Absent) {
        return Err(CliError::AuthUnavailable(NO_OPERATOR.to_string()));
    }
    // Not sealed: unseal_key names the file and the rotation.
    let key = unseal_key(&remembered_store()?, &paths, KeyFile::Ops)?;
    voice::note(&format!("operator {OPS_USER} (key ...{}, credentials/ops.env)", key.tail()));
    Ok(Operator::Sealed { key })
}

/// The keystore [`init`] remembered, else the one `--key-dir` would name (`AI_ENV_DIR`, else the default).
fn remembered_store() -> Result<Keystore> {
    let root = locked(&STORE).clone().or_else(|| std::env::var_os("AI_ENV_DIR").filter(|d| !d.is_empty()).map(PathBuf::from));
    Keystore::resolve(root)
}

/// Who this process's operator is, as AWS answers (§4.2): one `aws sts
/// get-caller-identity` as [`operator`], made once and cached, a failure
/// included. A runner's or the sealed key must answer as its user and never
/// as the account root; `ambient` must not be the root and `root` must be it.
pub fn verified() -> Result<Arc<Verified>> {
    let op = operator()?;
    verified_of(&op)
}

/// [`verified`] for `op` (the operator of this process: [`operator`] holds its
/// lock while it calls this for `root` and `ambient`, so the order is always
/// OPERATOR, then VERIFIED).
fn verified_of(op: &Operator) -> Result<Arc<Verified>> {
    let mut slot = locked(&VERIFIED);
    if let Some(done) = slot.as_ref() {
        return cached(done);
    }
    let checked = verify_operator(op).map(Arc::new);
    let out = cached(&checked);
    *slot = Some(checked);
    out
}

/// One `aws sts get-caller-identity` as `op` (pinned region and endpoint,
/// [`apply`]), judged by [`judge_operator`]: a refused runner's or sealed key
/// is exit 5, another principal exit 9, any other failure exit 1 (`aws sts
/// get-caller-identity: <first error line>`). Uncached: doctor's row calls it
/// for the identity it declares.
pub fn verify_operator(op: &Operator) -> Result<Verified> {
    verify_operator_with(op, &mut |cmd| run_capture_cmd(cmd, None, STS_TIMEOUT))
}

/// [`verify_operator`] with its runner given (the tests'). The command holds
/// the key: never Debug-formatted.
fn verify_operator_with(op: &Operator, run: &mut dyn FnMut(Command) -> std::result::Result<String, String>) -> Result<Verified> {
    let failed = |line: &str| CliError::Msg(format!("aws sts get-caller-identity: {line}"));
    let mut cmd = aws_cmd("sts", &["get-caller-identity"]).map_err(|e| failed(&e))?;
    apply(&mut cmd, op);
    let answer = match run(cmd) {
        Ok(answer) => answer,
        Err(e) => {
            let refused = op.role().and(REFUSED_CODES.iter().find(|code| e.contains(*code)));
            return Err(match refused {
                Some(code) => CliError::AuthUnavailable(refused_key(op, code)),
                None => failed(&one_line(&e)),
            });
        }
    };
    let v = parse_caller(&answer).map_err(|e| failed(&e))?;
    judge_operator(op, &v).map_err(CliError::Policy)?;
    Ok(v)
}

/// What fixes a runner's key that AWS refused or that answers as another
/// user: the deployer's is pasted again; the ops runner's came from
/// `credentials/ops.env` (only `ai-env as ops` sets an `ops:` marker, and
/// running it again would unseal the same key), which is re-sealed.
fn runner_fix(role: Role) -> &'static str {
    match role {
        Role::Deployer => "run the command under ai-env as deployer -- again",
        Role::Ops => "re-seal credentials/ops.env, which ai-env as ops unseals, with ai-env as deployer -- make ops-key ROTATE=1",
    }
}

/// AWS refused the operator's key (exit 5).
fn refused_key(op: &Operator, code: &str) -> String {
    match op {
        Operator::Sealed { key } => {
            format!("AWS refused the sealed key ...{} of credentials/ops.env ({code}): re-seal it with ai-env as deployer -- make ops-key ROTATE=1", key.tail())
        }
        Operator::Runner { role, tail } => format!("AWS refused the operator key ...{tail} ({code}): {}", runner_fix(*role)),
        Operator::Ambient { .. } => format!("AWS refused the aws CLI's credentials ({code})"),
    }
}

/// Is `v` who `op` must be (§4.2)? `Err` is the refusal (exit 9).
pub fn judge_operator(op: &Operator, v: &Verified) -> std::result::Result<(), String> {
    match op {
        Operator::Runner { .. } | Operator::Sealed { .. } if v.is_root() => Err(OPERATOR_ROOT.to_string()),
        Operator::Sealed { .. } if v.user.as_deref() != Some(OPS_USER) => {
            Err(format!("credentials/ops.env holds a key of {}, not {OPS_USER}: re-seal it with ai-env as deployer -- make ops-key ROTATE=1", v.arn))
        }
        Operator::Runner { role, .. } if v.user.as_deref() != Some(role.user()) => Err(format!("{RUNNER_MARKER} says {}, but its key answers as {}: {}", role.user(), v.arn, runner_fix(*role))),
        Operator::Ambient { root: false } if v.is_root() => {
            Err("the aws CLI's credentials are the account ROOT under ai-env as ambient: operator commands run as ai-env as ops --, the bootstrap alone as ai-env as root --".to_string())
        }
        Operator::Ambient { root: true } if !v.is_root() => {
            Err(format!("{RUNNER_MARKER}=root, but the aws CLI's credentials are {}, not the account root: unset it, or run the command under ai-env as root -- again", v.arn))
        }
        _ => Ok(()),
    }
}

/// Give `cmd` the environment of `op` over this process's variables
/// ([`apply_with`]). The secret may then sit in `cmd`: never Debug-format it.
pub fn apply(cmd: &mut Command, op: &Operator) {
    apply_with(cmd, op, std::env::vars_os().map(|(name, _)| name));
}

// ---- the runner (§3) -----------------------------------------------------------------------

/// `ai-env as [--account A] [--check] <IDENTITY> -- CMD…` (§3.3): exec `CMD`
/// as `who`, or (`--check`) only say whether this process runs as `who`
/// already (exit 0 silently, else 9). A covering marker execs at once: no
/// prompt, no Touch ID, no audit row. Returns only on a refusal or a failed
/// exec; otherwise `CMD` replaces this process and keeps its own status.
pub fn cmd_as(store: &Keystore, who: Identity, account: Option<&str>, check: bool, command: &[String]) -> Result<()> {
    if let Some(flag) = account.filter(|a| !is_account(a)) {
        return Err(CliError::Usage(format!("--account {}: expected the 12 digits of an AWS account", scrub(flag))));
    }
    let marker = Marker::from_env();
    let (id, secret) = key_variables();
    if check {
        return runs_as(who, marker, id.as_deref(), secret.as_deref()).map_err(CliError::Policy);
    }
    let Some(program) = command.first() else {
        return Err(CliError::Usage(format!("as {}: no command: ai-env as {} -- <command>", who.word(), who.word())));
    };
    let shown = shown_command(command);
    match start(who, marker, id.as_deref(), secret.as_deref(), &shown).map_err(CliError::Policy)? {
        Start::Covered { note, runner } => {
            if let Some(note) = note {
                voice::note(&note);
            }
            let mut cmd = command_for(command);
            if let Some(op) = runner {
                apply(&mut cmd, &op);
            }
            Err(exec(cmd, program))
        }
        Start::Fresh => match who {
            Identity::Deployer => as_deployer(account, command, &shown),
            Identity::Ops => as_ops(store, command, &shown),
            Identity::Root => as_root(account, command, &shown),
            Identity::Ambient => as_ambient(command, &shown),
        },
    }
}

/// How `ai-env as --check` names who a process does not run as.
fn who_phrase(who: Identity) -> &'static str {
    match who {
        Identity::Deployer => DEPLOYER_USER,
        Identity::Ops => OPS_USER,
        Identity::Root => "the account root",
        Identity::Ambient => "the ambient aws CLI identity",
    }
}

/// `--check`'s verdict (§3.3): `Ok` exactly when the marker covers `who`
/// (§2.3); a marker ai-env never sets or a key marker without its key is its
/// §2.5 refusal, anything else the `--check` text.
fn runs_as(who: Identity, marker: Option<std::result::Result<Marker, String>>, id: Option<&str>, secret: Option<&str>) -> std::result::Result<(), String> {
    let refusal = || format!("as --check {}: this process does not run as {}: run it as ai-env as {} -- <command>", who.word(), who_phrase(who), who.word());
    let Some(marker) = marker else {
        return Err(refusal());
    };
    let marker = marker?;
    marker.check_env(id, secret)?;
    if marker.covers(who) {
        Ok(())
    } else {
        Err(refusal())
    }
}

/// What `ai-env as` does under this process's marker before anything else.
#[derive(Debug)]
enum Start {
    /// Exec the command at once: `note` is the covered-run note (none under
    /// the marker's own identity), `runner` the key marker's environment to
    /// apply again (none for `root` and `ambient`: the command runs as it is).
    Covered { note: Option<String>, runner: Option<Operator> },
    /// No marker, or an escalation (`as deployer` under `ops:` or `ambient`).
    Fresh,
}

/// The marker's say on `ai-env as <who>` (§3.3 step 1, §3.5); `Err` is a
/// refusal (exit 9).
fn start(who: Identity, marker: Option<std::result::Result<Marker, String>>, id: Option<&str>, secret: Option<&str>, shown: &str) -> std::result::Result<Start, String> {
    let Some(marker) = marker else {
        return Ok(Start::Fresh);
    };
    let marker = marker?;
    if matches!(who, Identity::Root | Identity::Ambient) {
        if who == Identity::Ambient && marker == Marker::Ambient {
            return Ok(Start::Covered { note: None, runner: None });
        }
        return Err(format!("as {}: already inside ai-env as {} ({RUNNER_MARKER}): start it from a terminal of its own", who.word(), marker.word()));
    }
    marker.check_env(id, secret)?;
    if !marker.covers(who) {
        return Ok(Start::Fresh);
    }
    let own = matches!(&marker, Marker::Key { role, .. } if role.identity() == who);
    let op = declared_operator(Ok(marker), id, secret)?;
    let user = if who == Identity::Deployer { DEPLOYER_USER } else { OPS_USER };
    let note = (!own).then(|| format!("as {user}: already {}, which covers it: running {shown} as it is", op.describe()));
    let runner = matches!(op, Operator::Runner { .. }).then_some(op);
    Ok(Start::Covered { note, runner })
}

/// The command as a note shows it: its words joined by spaces, scrubbed,
/// control characters as `?`, at most [`SHOWN_MAX`] characters (the last one
/// `…` when cut).
fn shown_command(command: &[String]) -> String {
    let text: String = scrub(&command.join(" ")).chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    if text.chars().count() > SHOWN_MAX {
        format!("{}…", text.chars().take(SHOWN_MAX - 1).collect::<String>())
    } else {
        text
    }
}

/// `…` and the last four digits of an account: all a note shows of it (D22).
fn masked_account(account: &str) -> String {
    let tail: String = account.chars().skip(account.chars().count().saturating_sub(4)).collect();
    format!("…{tail}")
}

/// `arn` with its account masked ([`masked_account`]).
fn masked_arn(arn: &str, account: &str) -> String {
    if account.is_empty() {
        return arn.to_string();
    }
    arn.replacen(&format!(":{account}:"), &format!(":{}:", masked_account(account)), 1)
}

/// `CMD…` as a child, its environment inherited.
fn command_for(command: &[String]) -> Command {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd
}

/// Replace this process with `cmd`; the error when that fails (exit 1).
fn exec(mut cmd: Command, program: &str) -> CliError {
    use std::os::unix::process::CommandExt as _;
    let err = cmd.exec();
    CliError::Msg(format!("cannot exec {program:?}: {err}"))
}

/// The audit row `as_identity` (§3.7), written just before the exec; a
/// failed write is a warning, never a refusal.
fn audit_as(identity: &str, tail: Option<&str>, account: Option<&str>, command: &[String]) {
    let word = std::path::Path::new(&command[0]).file_name().map_or_else(|| command[0].clone(), |n| n.to_string_lossy().into_owned());
    let mut pairs = vec![("identity", identity.to_string())];
    if let Some(tail) = tail {
        pairs.push(("key_id_last4", tail.to_string()));
    }
    if let Some(account) = account {
        pairs.push(("account", account.to_string()));
    }
    pairs.push(("command", word));
    let row = crate::bridge::audit::AuditRow::new(crate::bridge::audit::event::AS_IDENTITY, None, crate::bridge::audit::detail(&pairs));
    let written = Paths::resolve().map_err(|e| e.to_string()).and_then(|paths| crate::bridge::audit::append(&paths.audit(), &row).map_err(|e| e.to_string()));
    if let Err(e) = written {
        voice::warn(&format!("the audit row was not written: {e}"));
    }
}

/// Does this paste come from the debug builds' stdin knob (no clipboard to clear then)?
fn pastes_from_stdin() -> bool {
    use std::io::IsTerminal as _;
    cfg!(debug_assertions) && std::env::var("AI_ENV_PASTE_STDIN").as_deref() == Ok("1") && !std::io::stdin().is_terminal()
}

/// One value pasted at `prompt` (on `/dev/tty`, echo off), trimmed: `None`
/// when nothing was pasted (the caller cancels with [`nothing_pasted`]).
fn paste(prompt: &str) -> Result<Option<Zeroizing<String>>> {
    let mut value = read_secret_tty_only(prompt).map_err(|e| match e {
        CliError::AuthUnavailable(text) if text == NO_TTY => {
            CliError::AuthUnavailable("as deployer: no terminal to paste the key into (it is never read from a file, a pipe or the environment)".into())
        }
        other => labelled("as deployer", other),
    })?;
    trim_in_place(&mut value);
    Ok((!value.is_empty()).then_some(value))
}

/// An empty paste: its one line, then exit 3 with no `ai-env: cancelled`
/// after it (D19).
fn nothing_pasted() -> CliError {
    voice::line("as deployer: nothing was pasted: cancelled, nothing was run");
    CliError::Exit(3)
}

/// Clear the clipboard after a paste from the terminal: best effort, a
/// failure is a warning and never stops the run (§3.3 step 4).
fn clear_clipboard() {
    match crate::bridge::pasteboard::clear() {
        Ok(()) => voice::note("cleared the clipboard (it held what you pasted)"),
        Err(e) => voice::warn(&format!("the clipboard could not be cleared ({e}): clear it yourself")),
    }
}

/// The two pasted values as one key; a value of the wrong shape is exit 1,
/// naming its fault, never the value. The id is judged in its zeroizing
/// buffer first: a secret pasted at the id's prompt by mistake is never
/// copied into the plain `String` an [`EnvKey`] keeps its id in.
fn pasted_key(id: Zeroizing<String>, secret: Zeroizing<String>) -> Result<EnvKey> {
    let refused = |fault: String| CliError::Msg(format!("as deployer: the pasted {fault} (not echoed): nothing was run"));
    if let Some(fault) = key_id_fault(&id) {
        return Err(refused(format!("access key id {fault}")));
    }
    EnvKey::new(id.as_str().to_string(), secret).map_err(refused)
}

/// Why a pasted deployer key is not run (§3.6).
fn key_refusal(tail: &str, e: KeyCheck) -> CliError {
    match e {
        KeyCheck::Refused(code) => {
            CliError::AuthUnavailable(format!("as deployer: AWS refused the key ...{tail} ({code}): a deleted or deactivated key, or the secret of another key: nothing was run"))
        }
        KeyCheck::Failed(line) => CliError::Aws(format!("as deployer: the key ...{tail} could not be checked ({line}): nothing was run")),
        KeyCheck::Mismatch(_, m) => CliError::Policy(format!("as deployer: {}: nothing was run", mismatch_text(tail, &m))),
    }
}

/// A deployer key that answered as someone else (§3.6, the four exit-9 texts without their ends).
fn mismatch_text(tail: &str, m: &Mismatch) -> String {
    match m {
        Mismatch::Root { .. } => format!("the key ...{tail} is the account ROOT's: never paste it here (the deployer's key is its own Strongbox entry); delete root's access key"),
        Mismatch::OtherPrincipal { arn } => format!("the key ...{tail} answers as {arn}, not {DEPLOYER_USER}"),
        Mismatch::OtherAccount { account, want, source, .. } => format!("the key ...{tail} is {DEPLOYER_USER} of account {account}, but the stack ({source}) is in account {want}"),
        Mismatch::OtherArn { arn, want, source } => format!("the key ...{tail} answers as {arn}, but the stack's deployer is {want} ({source})"),
    }
}

/// The pastes from the terminal guarded: from the first prompt until the
/// clipboard is cleared, a stop signal (Ctrl-C, a closed window, SIGTERM)
/// restores the terminal's settings, clears the clipboard through a clear
/// spawned now (a warning when it could not), says [`PASTE_STOPPED`] and ends
/// the run with 128 + the signal (`handover::stop`, the hand-over's handler).
/// `None` without a terminal, where nothing is read.
fn guard_the_pastes() -> Option<crate::bridge::handover::stop::Armed> {
    let mut armed = crate::bridge::handover::stop::arm(&[PASTE_STOPPED.to_string(), PASTE_STOPPED.to_string()], None);
    if !armed.has_terminal() {
        return None;
    }
    armed.guard_clipboard(crate::bridge::pasteboard::janitor().ok());
    Some(armed)
}

/// `as deployer` without a covering marker (§3.3): the stack's account, the
/// two pastes (a stop signal there clears the clipboard and ends the run
/// with 128 + the signal), the clipboard cleared, the sts check, the audit
/// row, the exec.
fn as_deployer(account: Option<&str>, command: &[String], shown: &str) -> Result<()> {
    let paths = Paths::resolve()?;
    let exp = expected(&paths, account)?;
    if exp.account.is_none() {
        return Err(CliError::Msg(UNKNOWN_ACCOUNT.into()));
    }
    voice::note(&format!("as {DEPLOYER_USER}: paste its access key from Strongbox (nothing you paste is shown)"));
    let from_terminal = !pastes_from_stdin();
    // The debug builds' stdin path has no clipboard to guard.
    let guarded = if from_terminal { guard_the_pastes() } else { None };
    let Some(id) = paste(&format!("{DEPLOYER_USER} access key id: "))? else {
        return Err(nothing_pasted());
    };
    // From the first value on, the clipboard held what was pasted: it is cleared whatever follows (the second
    // paste empty or failed, a value of the wrong shape), before that outcome is told.
    let secret = paste(&format!("{DEPLOYER_USER} secret access key: "));
    if from_terminal {
        clear_clipboard();
    }
    // Disarmed once the clipboard is cleared: a stop during the sts check takes its usual course again.
    drop(guarded);
    let Some(secret) = secret? else {
        return Err(nothing_pasted());
    };
    let key = pasted_key(id, secret)?;
    let v = check_key(&key, DEPLOYER_USER, &exp, KeyWait::PASTED, "the key").map_err(|e| key_refusal(key.tail(), e))?;
    audit_as("deployer", Some(key.tail()), Some(&v.account), command);
    voice::note(&format!("as {DEPLOYER_USER} (key ...{}, account {}, verified): {shown}", key.tail(), masked_account(&v.account)));
    let mut cmd = command_for(command);
    apply_key(&mut cmd, &key);
    cmd.env(RUNNER_MARKER, Marker::Key { role: Role::Deployer, tail: key.tail().to_string() }.render());
    drop(key);
    Err(exec(cmd, &command[0]))
}

/// `as ops` without a marker (§3.3): `credentials/ops.env` unsealed (one
/// Touch ID), no sts call, the audit row, the exec.
fn as_ops(store: &Keystore, command: &[String], shown: &str) -> Result<()> {
    let paths = Paths::resolve()?;
    let key = unseal_key(store, &paths, KeyFile::Ops).map_err(|e| labelled("as ops", e))?;
    audit_as("ops", Some(key.tail()), None, command);
    voice::note(&format!("as {OPS_USER} (key ...{}, credentials/ops.env): {shown}", key.tail()));
    let mut cmd = command_for(command);
    apply_key(&mut cmd, &key);
    cmd.env(RUNNER_MARKER, Marker::Key { role: Role::Ops, tail: key.tail().to_string() }.render());
    drop(key);
    Err(exec(cmd, &command[0]))
}

/// The aws CLI's own caller, the environment untouched (`as root`, `as
/// ambient`): `Err` is the first error line.
fn ambient_caller() -> std::result::Result<Verified, String> {
    let cmd = aws_cmd("sts", &["get-caller-identity"])?;
    let answer = run_capture_cmd(cmd, None, STS_TIMEOUT).map_err(|e| one_line(&e))?;
    parse_caller(&answer)
}

/// Does `state/infra.toml` name the stack's deployer?
fn stack_has_deployer(paths: &Paths) -> bool {
    read_infra_state(paths).ok().flatten().is_some_and(|s| s.deployer_user_name.is_some() || s.deployer_user_arn.is_some())
}

/// `as root` without a marker (§3.3): the aws CLI's chain must be the account
/// root (of the stack's account, when known); exec with `AI_ENV_BRIDGE_AS=root`.
fn as_root(account: Option<&str>, command: &[String], shown: &str) -> Result<()> {
    let v = ambient_caller().map_err(|line| {
        CliError::AuthUnavailable(format!("as root: no AWS credentials answer ({line}): ai-env as root needs the account root's access key in this shell (README \"Break-glass\")"))
    })?;
    if !v.is_root() {
        return Err(CliError::Policy(format!("as root: the aws CLI's credentials are {}, not the account root: ai-env as root is only for the bootstrap deploy and break-glass", v.arn)));
    }
    let paths = Paths::resolve()?;
    let exp = expected(&paths, account)?;
    if let Some(want) = exp.account.as_deref().filter(|want| *want != v.account) {
        return Err(CliError::Policy(format!("as root: this is the account root of {}, but the stack ({}) is in account {want}", v.account, exp.source.unwrap_or("no source"))));
    }
    if stack_has_deployer(&paths) {
        voice::warn("the stack already has ai-env-deployer: use ai-env as deployer; afterwards unset root's key and close this terminal (README \"Break-glass\")");
    }
    audit_as("root", None, Some(&v.account), command);
    voice::note(&format!("as the account ROOT of account {} (the bootstrap and break-glass only): {shown}", masked_account(&v.account)));
    let mut cmd = command_for(command);
    cmd.env(RUNNER_MARKER, Marker::Root.render());
    Err(exec(cmd, &command[0]))
}

/// `as ambient` without a marker (§3.3): the aws CLI's chain, never the
/// root (its account is not checked); exec with `AI_ENV_BRIDGE_AS=ambient`.
fn as_ambient(command: &[String], shown: &str) -> Result<()> {
    let v = ambient_caller().map_err(|line| CliError::AuthUnavailable(format!("as ambient: no AWS credentials answer ({line})")))?;
    if v.is_root() {
        return Err(CliError::Policy(
            "as ambient: the aws CLI's credentials are the account ROOT: operator commands run as ai-env as ops --, deploys as ai-env as deployer --, the bootstrap alone as ai-env as root --".into(),
        ));
    }
    audit_as("ambient", None, Some(&v.account), command);
    voice::note(&format!("as the ambient aws CLI identity {} (declared; never the root): {shown}", masked_arn(&v.arn, &v.account)));
    let mut cmd = command_for(command);
    cmd.env(RUNNER_MARKER, Marker::Ambient.render());
    Err(exec(cmd, &command[0]))
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    const STACK: &str = "123456789012";
    const OTHER: &str = "999999999999";

    /// `AKIA`, `FAKE`, eight zeros and `tail`, built at run time (no key-shaped literal in the sources).
    fn key_id(tail: &str) -> String {
        format!("{}FAKE{}{tail}", "AKIA", "0".repeat(8))
    }

    fn secret(block: &str) -> String {
        block.repeat(10)
    }

    fn caller(arn: &str, account: &str) -> Verified {
        parse_caller(&format!("{{\"UserId\": \"AIDAEXAMPLE\", \"Account\": \"{account}\", \"Arn\": \"{arn}\"}}")).unwrap()
    }

    fn user(name: &str) -> String {
        format!("arn:aws:iam::{STACK}:user/{name}")
    }

    fn root_arn(account: &str) -> String {
        format!("arn:aws:iam::{account}:root")
    }

    fn key(role: Role, tail: &str) -> Option<std::result::Result<Marker, String>> {
        Some(Ok(Marker::Key { role, tail: tail.into() }))
    }

    /// `--check` (the make guard): exit 0 exactly when the marker covers the identity (§2.3); a bad marker or a
    /// key marker without its key is its §2.5 text, anything else the --check text, which names the identity.
    #[test]
    fn check_follows_the_coverage_and_refuses_a_bad_marker() {
        use Identity::{Ambient, Deployer, Ops, Root};
        let (d, o, s) = (key_id("9001"), key_id("9002"), secret("Dm7/"));
        let deployer = || key(Role::Deployer, "9001");
        let ops = || key(Role::Ops, "9002");
        for (marker, id, covered) in [
            (deployer(), d.as_str(), &[Deployer, Ops][..]),
            (ops(), o.as_str(), &[Ops]),
            (Some(Ok(Marker::Root)), "", &[Deployer, Ops, Root]),
            (Some(Ok(Marker::Ambient)), "", &[Ops, Ambient]),
            (None, "", &[]),
        ] {
            for who in [Deployer, Ops, Root, Ambient] {
                let got = runs_as(who, marker.clone(), Some(id).filter(|i| !i.is_empty()), Some(&s));
                if covered.contains(&who) {
                    assert_eq!(got, Ok(()), "{marker:?} covers {}", who.word());
                } else {
                    let phrase = who_phrase(who);
                    assert_eq!(got.unwrap_err(), format!("as --check {0}: this process does not run as {phrase}: run it as ai-env as {0} -- <command>", who.word()), "{marker:?}");
                }
            }
        }
        assert_eq!(runs_as(Root, None, None, None).unwrap_err(), "as --check root: this process does not run as the account root: run it as ai-env as root -- <command>");
        // A key marker whose key is gone, and a value ai-env never sets: their own refusals, for every identity.
        for who in [Deployer, Ops] {
            let e = runs_as(who, ops(), Some(&d), Some(&s)).unwrap_err();
            assert!(e.starts_with("AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_ACCESS_KEY_ID holds another key"), "{e}");
            let e = runs_as(who, ops(), Some(&o), None).unwrap_err();
            assert!(e.starts_with("AI_ENV_BRIDGE_AS names the ops key ...9002, but AWS_SECRET_ACCESS_KEY is missing"), "{e}");
            let e = runs_as(who, Some(Marker::parse("admin")), None, None).unwrap_err();
            assert!(e.starts_with("AI_ENV_BRIDGE_AS=admin is not one ai-env sets"), "{e}");
        }
    }

    /// The marker's say on `ai-env as` (§3.3, §3.5): a covering marker execs at once (silently under its own
    /// identity, else with the covered-run note; a key marker's environment applied again), `as deployer` under
    /// `ops:` or `ambient` asks (an escalation), `as root` is refused under every marker and `as ambient` under
    /// every one but its own.
    #[test]
    fn a_covering_marker_execs_at_once_and_an_escalation_asks() {
        use Identity::{Ambient, Deployer, Ops, Root};
        let (d, o, s) = (key_id("9001"), key_id("9002"), secret("Dm7/"));
        let covered = |who, marker, id: &str| match start(who, marker, Some(id), Some(&s), "make deploy") {
            Ok(Start::Covered { note, runner }) => (note, runner.map(|r| r.describe())),
            other => panic!("{other:?}"),
        };
        assert_eq!(covered(Deployer, key(Role::Deployer, "9001"), &d), (None, Some("ai-env-deployer (key ...9001, ai-env as deployer)".into())));
        assert_eq!(covered(Ops, key(Role::Ops, "9002"), &o), (None, Some("ai-env-ops (key ...9002, ai-env as ops)".into())));
        assert_eq!(
            covered(Ops, key(Role::Deployer, "9001"), &d),
            (Some("as ai-env-ops: already ai-env-deployer (key ...9001, ai-env as deployer), which covers it: running make deploy as it is".into()), Some("ai-env-deployer (key ...9001, ai-env as deployer)".into()))
        );
        assert_eq!(covered(Deployer, Some(Ok(Marker::Root)), ""), (Some("as ai-env-deployer: already the account ROOT (ai-env as root), which covers it: running make deploy as it is".into()), None));
        assert_eq!(covered(Ops, Some(Ok(Marker::Root)), ""), (Some("as ai-env-ops: already the account ROOT (ai-env as root), which covers it: running make deploy as it is".into()), None));
        assert_eq!(covered(Ops, Some(Ok(Marker::Ambient)), ""), (Some("as ai-env-ops: already the ambient aws CLI identity (ai-env as ambient), which covers it: running make deploy as it is".into()), None));
        assert_eq!(covered(Ambient, Some(Ok(Marker::Ambient)), ""), (None, None));
        // Escalations and no marker: the flow itself.
        for (who, marker, id) in [(Deployer, key(Role::Ops, "9002"), o.as_str()), (Deployer, Some(Ok(Marker::Ambient)), ""), (Deployer, None, ""), (Ops, None, ""), (Root, None, ""), (Ambient, None, "")] {
            assert!(matches!(start(who, marker.clone(), Some(id), Some(&s), "x"), Ok(Start::Fresh)), "{} under {marker:?}", who.word());
        }
        // Refusals.
        for (who, marker, word) in [(Root, Some(Ok(Marker::Root)), "root"), (Root, Some(Ok(Marker::Ambient)), "ambient"), (Root, key(Role::Deployer, "9001"), "deployer"), (Ambient, Some(Ok(Marker::Root)), "root"), (Ambient, key(Role::Ops, "9002"), "ops")] {
            let e = start(who, marker, Some(&d), Some(&s), "x").unwrap_err();
            assert_eq!(e, format!("as {}: already inside ai-env as {word} (AI_ENV_BRIDGE_AS): start it from a terminal of its own", who.word()));
        }
        let e = start(Ops, key(Role::Ops, "9002"), Some(&d), Some(&s), "x").unwrap_err();
        assert!(e.starts_with("AI_ENV_BRIDGE_AS names the ops key ...9002"), "an invalid key marker is refused, never covered: {e}");
        let e = start(Deployer, key(Role::Ops, "9002"), Some(&d), Some(&s), "x").unwrap_err();
        assert!(e.starts_with("AI_ENV_BRIDGE_AS names the ops key ...9002"), "nor escalated from: {e}");
        for who in [Deployer, Ops, Root, Ambient] {
            assert!(start(who, Some(Marker::parse("ops:9")), None, None, "x").unwrap_err().ends_with("is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it"));
        }
    }

    /// §4.2: a runner's or the sealed key answers as its role's user and never as the root; `ambient` is never
    /// the root and `root` is always it.
    #[test]
    fn the_operator_must_answer_as_its_user_and_never_as_the_wrong_root() {
        let runner = |role, tail: &str| Operator::Runner { role, tail: tail.into() };
        let sealed = Operator::Sealed { key: EnvKey::new(key_id("9002"), Zeroizing::new(secret("Kq3+"))).unwrap() };
        let (ops, deployer, rust, root) = (caller(&user(OPS_USER), STACK), caller(&user(DEPLOYER_USER), STACK), caller(&user("rust"), STACK), caller(&root_arn(STACK), STACK));
        assert_eq!(judge_operator(&runner(Role::Ops, "9002"), &ops), Ok(()));
        assert_eq!(judge_operator(&runner(Role::Deployer, "9001"), &deployer), Ok(()));
        assert_eq!(judge_operator(&sealed, &ops), Ok(()));
        assert_eq!(judge_operator(&runner(Role::Ops, "9002"), &caller(&format!("arn:aws:iam::{OTHER}:user/ai-env-ops"), OTHER)), Ok(()), "the account is the caller's to check");
        let root_text = "the operator credentials are the account ROOT's: operator commands never run as root after the bootstrap (ai-env as ops --, ai-env as deployer --)";
        for op in [&runner(Role::Ops, "9002"), &runner(Role::Deployer, "9001"), &sealed] {
            assert_eq!(judge_operator(op, &root).unwrap_err(), root_text);
        }
        assert_eq!(
            judge_operator(&sealed, &rust).unwrap_err(),
            format!("credentials/ops.env holds a key of {}, not ai-env-ops: re-seal it with ai-env as deployer -- make ops-key ROTATE=1", user("rust"))
        );
        // The ops runner's key came from credentials/ops.env (only ai-env as ops sets an ops: marker): running it
        // again would unseal the same key, so the text says to re-seal it; the deployer's is pasted again.
        assert_eq!(
            judge_operator(&runner(Role::Ops, "9002"), &deployer).unwrap_err(),
            format!("AI_ENV_BRIDGE_AS says ai-env-ops, but its key answers as {}: re-seal credentials/ops.env, which ai-env as ops unseals, with ai-env as deployer -- make ops-key ROTATE=1", user(DEPLOYER_USER))
        );
        assert_eq!(
            judge_operator(&runner(Role::Deployer, "9001"), &rust).unwrap_err(),
            format!("AI_ENV_BRIDGE_AS says ai-env-deployer, but its key answers as {}: run the command under ai-env as deployer -- again", user("rust"))
        );
        assert_eq!(judge_operator(&Operator::Ambient { root: false }, &rust), Ok(()));
        assert_eq!(
            judge_operator(&Operator::Ambient { root: false }, &root).unwrap_err(),
            "the aws CLI's credentials are the account ROOT under ai-env as ambient: operator commands run as ai-env as ops --, the bootstrap alone as ai-env as root --"
        );
        assert_eq!(judge_operator(&Operator::Ambient { root: true }, &root), Ok(()));
        assert_eq!(
            judge_operator(&Operator::Ambient { root: true }, &rust).unwrap_err(),
            format!("AI_ENV_BRIDGE_AS=root, but the aws CLI's credentials are {}, not the account root: unset it, or run the command under ai-env as root -- again", user("rust"))
        );
    }

    /// One pinned sts call as the operator: refused keys are exit 5 (a runner's or the sealed key's text), a
    /// failure of any other kind exit 1 with its first line, another principal exit 9; the key reaches the call
    /// in its environment only.
    #[test]
    fn verify_classifies_refusals_failures_and_other_principals() {
        let sealed = Operator::Sealed { key: EnvKey::new(key_id("9002"), Zeroizing::new(secret("Kq3+"))).unwrap() };
        let runner = Operator::Runner { role: Role::Ops, tail: "9002".into() };
        let answer = |arn: &str, account: &str| format!("{{\"UserId\": \"AIDAEXAMPLE\", \"Account\": \"{account}\", \"Arn\": \"{arn}\"}}");
        let refused = "An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.";
        let verify = |op: &Operator, reply: std::result::Result<String, String>| {
            let mut seen = Vec::new();
            let got = verify_operator_with(op, &mut |cmd: Command| {
                let argv: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
                let envs: Vec<(String, Option<String>)> = cmd.get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect();
                seen.push((argv, envs));
                reply.clone()
            });
            (got, seen)
        };
        let (got, seen) = verify(&sealed, Ok(answer(&user(OPS_USER), STACK)));
        assert_eq!(got.unwrap().user.as_deref(), Some(OPS_USER));
        assert_eq!(seen.len(), 1, "one call");
        let (argv, envs) = &seen[0];
        assert_eq!(argv, &["sts", "get-caller-identity", "--region", "eu-central-1", "--endpoint-url", "https://sts.eu-central-1.amazonaws.com", "--output", "json"]);
        assert!(envs.iter().any(|(k, v)| k == "AWS_ACCESS_KEY_ID" && v.as_deref() == Some(key_id("9002").as_str())), "the sealed key goes in the environment");
        assert!(envs.iter().any(|(k, v)| k == "AWS_CONFIG_FILE" && v.as_deref() == Some("/dev/null")), "{envs:?}");
        assert!(!argv.iter().any(|a| a.contains(&key_id("9002")) || a.contains(&secret("Kq3+"))), "never in argv");
        let (got, seen) = verify(&runner, Ok(answer(&user(OPS_USER), STACK)));
        assert!(got.is_ok());
        assert!(!seen[0].1.iter().any(|(k, _)| k == "AWS_ACCESS_KEY_ID" || k == "AWS_SECRET_ACCESS_KEY"), "a runner's key stays inherited");
        // Refused keys: exit 5, naming what to do.
        let e = verify(&sealed, Err(refused.into())).0.unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (5, "AWS refused the sealed key ...9002 of credentials/ops.env (InvalidClientTokenId): re-seal it with ai-env as deployer -- make ops-key ROTATE=1".to_string()));
        let e = verify(&runner, Err(refused.into())).0.unwrap_err();
        assert_eq!(
            (e.exit_code(), e.to_string()),
            (5, "AWS refused the operator key ...9002 (InvalidClientTokenId): re-seal credentials/ops.env, which ai-env as ops unseals, with ai-env as deployer -- make ops-key ROTATE=1".to_string())
        );
        let e = verify(&Operator::Runner { role: Role::Deployer, tail: "9001".into() }, Err(refused.into())).0.unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (5, "AWS refused the operator key ...9001 (InvalidClientTokenId): run the command under ai-env as deployer -- again".to_string()), "the deployer's key is pasted again");
        // Any other failure: exit 1, its first line; the ambient chain's refusals are failures too.
        let e = verify(&runner, Err("Could not connect to the endpoint URL: \"https://sts.eu-central-1.amazonaws.com/\"".into())).0.unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (1, "aws sts get-caller-identity: Could not connect to the endpoint URL: \"https://sts.eu-central-1.amazonaws.com/\"".to_string()));
        let e = verify(&Operator::Ambient { root: false }, Err(refused.into())).0.unwrap_err();
        assert_eq!(e.exit_code(), 1, "{e}");
        let e = verify(&Operator::Ambient { root: true }, Err("Unable to locate credentials. You can configure credentials by running \"aws configure\".".into())).0.unwrap_err();
        assert_eq!(e.to_string(), "aws sts get-caller-identity: Unable to locate credentials. You can configure credentials by running \"aws configure\".");
        let e = verify(&runner, Ok("{}".into())).0.unwrap_err();
        assert_eq!((e.exit_code(), e.to_string()), (1, "aws sts get-caller-identity: unreadable answer: no 12-digit Account".to_string()));
        // Another principal: exit 9.
        let e = verify(&runner, Ok(answer(&root_arn(STACK), STACK))).0.unwrap_err();
        assert!(e.exit_code() == 9 && e.to_string().starts_with("the operator credentials are the account ROOT's"), "{e}");
        let e = verify(&Operator::Ambient { root: true }, Ok(answer(&user("rust"), STACK))).0.unwrap_err();
        assert!(e.exit_code() == 9 && e.to_string().starts_with("AI_ENV_BRIDGE_AS=root, but"), "{e}");
    }

    /// Labels keep the exit class (a cancel stays the plain `cancelled`), cached failures are copied whole; the
    /// notes show an account as its last four digits and a command scrubbed and cut to 120 characters.
    #[test]
    fn labels_keep_the_class_and_notes_mask_the_account_and_cut_the_command() {
        for e in [
            CliError::Msg("m".into()),
            CliError::Usage("m".into()),
            CliError::NoKey("m".into()),
            CliError::AuthUnavailable("m".into()),
            CliError::Corrupt("m".into()),
            CliError::Aws("m".into()),
            CliError::VmLost("m".into()),
            CliError::Policy("m".into()),
        ] {
            let code = e.exit_code();
            let copy = copy_error(&e);
            assert_eq!((copy.exit_code(), copy.to_string()), (code, "m".to_string()));
            let l = labelled("egress status", e);
            assert_eq!((l.exit_code(), l.to_string()), (code, "egress status: m".to_string()));
        }
        for e in [CliError::Cancelled, CliError::BrokenPipe, CliError::Exit(42)] {
            let (code, text) = (e.exit_code(), e.to_string());
            assert_eq!((copy_error(&e).exit_code(), copy_error(&e).to_string()), (code, text.clone()));
            let l = labelled("gates", e);
            assert_eq!((l.exit_code(), l.to_string()), (code, text), "unlabelled");
        }
        assert_eq!(masked_account(STACK), "…9012");
        assert_eq!(masked_arn(&user("rust"), STACK), "arn:aws:iam::…9012:user/rust");
        assert_eq!(masked_arn("arn:aws:sts::123456789012:assumed-role/a/123456789012", STACK), "arn:aws:sts::…9012:assumed-role/a/123456789012", "only the account field");
        assert_eq!(shown_command(&["make".into(), "deploy".into()]), "make deploy");
        let long: Vec<String> = (0..40).map(|n| format!("arg{n:02}")).collect();
        let shown = shown_command(&long);
        assert_eq!(shown.chars().count(), 120);
        assert!(shown.ends_with('…') && shown.starts_with("arg00 arg01"), "{shown}");
        let id = key_id("9007");
        register_secret(&id);
        let shown = shown_command(&["aws".into(), format!("--key={id}"), "a\nb".into()]);
        assert!(!shown.contains(&id) && shown.ends_with("a?b"), "scrubbed, one line: {shown}");
    }

    /// The marker's operator: a key marker with its key is the runner, `root` and `ambient` the aws CLI's own
    /// chain; anything else is the §2.5 refusal.
    #[test]
    fn declared_operators_follow_the_marker() {
        let (id, s) = (key_id("9001"), secret("Dm7/"));
        let runner = declared_operator(Marker::parse("deployer:9001"), Some(&id), Some(&s)).unwrap();
        assert_eq!((runner.role(), runner.describe()), (Some(Role::Deployer), "ai-env-deployer (key ...9001, ai-env as deployer)".to_string()));
        assert!(matches!(declared_operator(Ok(Marker::Root), None, None), Ok(Operator::Ambient { root: true })));
        assert!(matches!(declared_operator(Ok(Marker::Ambient), None, None), Ok(Operator::Ambient { root: false })));
        assert!(declared_operator(Marker::parse("deployer:9001"), None, Some(&s)).unwrap_err().contains("AWS_ACCESS_KEY_ID holds another key"));
        assert!(declared_operator(Marker::parse("nobody"), None, None).unwrap_err().contains("is not one ai-env sets"));
    }

    /// `as deployer`'s two pastes as one key (§3.6): a value of the wrong
    /// shape is exit 1 naming its fault, never the value, the id judged
    /// before the secret (a secret pasted at the id's prompt is refused as an
    /// id, from its zeroizing buffer).
    #[test]
    fn a_pasted_key_of_the_wrong_shape_names_its_fault_never_the_value() {
        let (id, s) = (key_id("9001"), secret("Pq7+"));
        let pasted = |id: &str, s: &str| pasted_key(Zeroizing::new(id.to_string()), Zeroizing::new(s.to_string()));
        assert_eq!(pasted(&id, &s).unwrap().tail(), "9001");
        for (pid, ps, fault) in [
            (s.as_str(), s.as_str(), "access key id does not start with AKIA"),
            (&id[..19], "x", "access key id has 19 characters, expected 20"),
            (id.as_str(), &s[..39], "secret access key has 39 characters, expected 40"),
        ] {
            let e = pasted(pid, ps).unwrap_err();
            assert_eq!((e.exit_code(), e.to_string()), (1, format!("as deployer: the pasted {fault} (not echoed): nothing was run")));
            assert!(!e.to_string().contains(&s[..16]) && !e.to_string().contains(&id[..16]), "never a value: {e}");
        }
    }
}
