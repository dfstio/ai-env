//! The real control-plane client (`SdkMicrovmApi`) and the runtime credentials (plan S4 D3, step 4).
//!
//! Credentials: `[aws].credentials = "container"` (the default) unseals
//! `credentials/aws.env` in-process — one age call with exactly one `-i` (the
//! explicit `[creds].key`, one Touch ID), the plaintext parsed inside the
//! zeroizing buffer, both values registered with the scrubber — while
//! `"profile:<name>"` reads exactly that profile of `~/.aws` through a
//! provider that keeps the bridge's TLS client. No child process ever
//! receives the key.
//!
//! Every SDK configuration comes from [`sdk_config_for`], which pins what the
//! environment could otherwise redirect (plan §3 "SDK environment leaks"):
//! region, control-plane URL, FIPS and dual-stack off, retries, timeouts and
//! the HTTP client (`bridge::tls`). In container mode the profile files are
//! empty and in memory, so `~/.aws` is never read. The one hop no setter can
//! pin — the STS call of an assume-role profile — is guarded by [`connect`]
//! instead (see [`PROFILE_REFUSED_ENV`]).
use crate::age_cmd::AgeTool;
use crate::bridge::api::{
    idle_policy, normalize_endpoint, AuthToken, IdleSpec, ImageInfo, ImageVersion, ManagedImage, MicrovmApi, RunSpec, VmInfo, VmState, VmSummary, SHELL_PORT, TOKEN_HEADER,
};
use crate::bridge::config::{BridgeConfig, CredentialsSource, Paths, REGION};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::errors::{classify_service, map_sdk_error, sdk_ambiguous, BridgeError};
use crate::container;
use crate::errors::{CliError, Result};
use crate::select::resolve_for_decrypt;
use crate::store::{validate_key_name, Keystore};
use crate::wire::redact::{register_secret, scrub, Secret};
use crate::wire::time::unix_now;
use aws_sdk_lambdamicrovms::config::interceptors::BeforeSerializationInterceptorContextRef;
use aws_sdk_lambdamicrovms::config::http::HttpResponse;
use aws_sdk_lambdamicrovms::config::{ConfigBag, Credentials, Intercept, Region};
use aws_sdk_lambdamicrovms::error::{BoxError, DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_lambdamicrovms::operation::run_microvm::builders::RunMicrovmFluentBuilder;
use aws_sdk_lambdamicrovms::operation::run_microvm::RunMicrovmError;
use aws_sdk_lambdamicrovms::types::{IdlePolicy, PortSpecification};
use aws_sdk_lambdamicrovms::Client;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

/// The MicroVM control plane in the pinned region: what the SDK's own
/// endpoint rules resolve for `eu-central-1` without FIPS or dual-stack
/// (`https://lambda.{region}.amazonaws.com`, asserted against the SDK
/// resolver by `control_plane_url_is_what_the_sdk_resolves`). Pinned so no
/// `AWS_ENDPOINT_URL*`, profile `endpoint_url` or FIPS/dual-stack switch can
/// move the runtime key's requests elsewhere (an `http://` one would bypass TLS).
pub const CONTROL_PLANE_URL: &str = "https://lambda.eu-central-1.amazonaws.com";

/// SDK attempts per call (the first try included), standard retry mode.
pub const SDK_MAX_ATTEMPTS: u32 = 3;
/// TCP + TLS connect budget of one SDK attempt.
pub const SDK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// One SDK attempt, connect to last response byte.
pub const SDK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
/// One SDK call, all attempts and their backoff included.
pub const SDK_OPERATION_TIMEOUT: Duration = Duration::from_secs(40);

/// `provider_name` of the credentials unsealed from `credentials/aws.env`.
const CONTAINER_PROVIDER: &str = "ai-env-container";
/// The two variables `creds aws-set` seals (`creds::render_env`), nothing else.
const ID_KEY: &str = "AWS_ACCESS_KEY_ID";
const SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
/// A long-term IAM user key id: `AKIA` + 16 of `[A-Z0-9]`.
const KEY_ID_PREFIX: &str = "AKIA";
const KEY_ID_LEN: usize = 20;
const SECRET_LEN: usize = 40;

// ---- credentials ----------------------------------------------------------------------

/// Where the runtime principal's AWS credentials come from for one command.
/// `Debug` is hand-written and never prints key material (the SDK's own
/// `Credentials` debug output shows the access key id).
#[derive(Clone)]
pub enum RuntimeCreds {
    /// Unsealed from `credentials/aws.env` (`[aws] credentials = "container"`).
    Static(Credentials),
    /// Exactly this profile of `~/.aws/{config,credentials}` (`"profile:<name>"`).
    Profile(String),
    /// The SDK's default chain: only the read-only live tests (`make
    /// test-aws-readonly`) and `api::sdk_config()` use it, never `ai-env vm`.
    #[doc(hidden)]
    DefaultChainForReadOnlyTests,
}

impl fmt::Debug for RuntimeCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeCreds::Static(_) => f.write_str("RuntimeCreds::Static([redacted])"),
            RuntimeCreds::Profile(name) => write!(f, "RuntimeCreds::Profile({name:?})"),
            RuntimeCreds::DefaultChainForReadOnlyTests => f.write_str("RuntimeCreds::DefaultChainForReadOnlyTests"),
        }
    }
}

impl RuntimeCreds {
    /// The one stderr line naming the credentials in use: `runtime key …ABCD
    /// (credentials/aws.env)` (the last four characters of the access key id,
    /// all of it that is ever shown), `profile <name>`, or `default chain
    /// (read-only tests)`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            RuntimeCreds::Static(c) => {
                let id = c.access_key_id();
                let tail: String = id.chars().skip(id.chars().count().saturating_sub(4)).collect();
                format!("runtime key \u{2026}{tail} (credentials/aws.env)")
            }
            RuntimeCreds::Profile(name) => format!("profile {name}"),
            RuntimeCreds::DefaultChainForReadOnlyTests => "default chain (read-only tests)".to_string(),
        }
    }
}

/// The runtime credentials `[aws].credentials` names (plan S4 D3). Profile
/// mode returns the name without touching `~/.aws` (the SDK reads it on the
/// first call; [`connect`] first refuses a configuration that would move the
/// assume-role STS call). Container mode: `credentials/aws.env` must be a sealed
/// container (absent or plaintext → exit 5 naming `make runtime-key`); the key
/// is the explicit `[creds].key` (never tag matching; missing → exit 4); `age
/// -d` runs once with exactly that identity (one Touch ID; cancel → exit 3);
/// the plaintext is parsed by [`parse_runtime_env`] inside its zeroizing
/// buffer. Anything but `"container"` / `"profile:<name>"` is exit 1.
pub fn runtime_credentials(store: &Keystore, paths: &Paths, cfg: &BridgeConfig) -> Result<RuntimeCreds> {
    match CredentialsSource::parse(&cfg.aws.credentials)? {
        CredentialsSource::Profile(name) => Ok(RuntimeCreds::Profile(name)),
        CredentialsSource::Container => unseal(store, paths, &cfg.creds.key),
    }
}

fn unseal(store: &Keystore, paths: &Paths, key_name: &str) -> Result<RuntimeCreds> {
    let path = paths.aws_env();
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => {
            return Err(CliError::AuthUnavailable(format!("{} does not exist: seal the runtime key with `make runtime-key` (or set [aws] credentials = \"profile:<name>\")", path.display())));
        }
        AwsEnvState::NotSealed(why) => {
            return Err(CliError::AuthUnavailable(format!("{} {why}: move it away (and rotate the key it holds), then seal the runtime key with `make runtime-key`", path.display())));
        }
    }
    validate_key_name(key_name).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let text = crate::bridge::registry::read_regular_file(&path)?.ok_or_else(|| CliError::AuthUnavailable(format!("{} vanished while it was read: run `make runtime-key`", path.display())))?;
    let cont = container::read(&text)?;
    let key = resolve_for_decrypt(store, Some(key_name), &cont)?;
    let age = AgeTool::probe()?;
    let plain = age.decrypt_to_bytes(&store.identity_path(&key), &cont.data)?;
    let (id, secret) = parse_runtime_env(&plain)?;
    drop(plain);
    Ok(RuntimeCreds::Static(Credentials::new(id, secret.as_str(), None, None, CONTAINER_PROVIDER)))
}

/// Parse the plaintext `creds aws-set` sealed (`creds::render_env`): exactly
/// the lines `AWS_ACCESS_KEY_ID=<AKIA + 16 of [A-Z0-9]>` and
/// `AWS_SECRET_ACCESS_KEY=<40 of [A-Za-z0-9/+]>`, in either order, each once,
/// with an optional final newline. Both values are registered with the
/// scrubber as soon as they are found (it keeps a copy for the life of the
/// process, plan D3). Any other shape is `CredentialsUnavailable` (exit 5)
/// naming the problem — a line number, a key name, a length — never a value.
pub fn parse_runtime_env(plain: &[u8]) -> std::result::Result<(String, Zeroizing<String>), BridgeError> {
    let bad = |why: String| BridgeError::CredentialsUnavailable(format!("credentials/aws.env: {why} (re-seal the runtime key with `make runtime-key`)"));
    let text = std::str::from_utf8(plain).map_err(|_| bad("the unsealed plaintext is not UTF-8".into()))?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err(bad("the unsealed plaintext is empty".into()));
    }
    let (mut id, mut secret): (Option<&str>, Option<&str>) = (None, None);
    for (n, line) in body.split('\n').enumerate() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(bad(format!("line {} is not KEY=VALUE", n + 1)));
        };
        let slot = match key {
            ID_KEY => &mut id,
            SECRET_KEY => &mut secret,
            other => return Err(bad(format!("line {}: {} (expected exactly {ID_KEY} and {SECRET_KEY})", n + 1, unexpected_key(other)))),
        };
        register_secret(value);
        if slot.replace(value).is_some() {
            return Err(bad(format!("{key} appears twice")));
        }
    }
    let id = id.ok_or_else(|| bad(format!("{ID_KEY} is missing")))?;
    let secret = secret.ok_or_else(|| bad(format!("{SECRET_KEY} is missing")))?;
    if let Some(fault) = key_id_fault(id) {
        return Err(bad(format!("{ID_KEY} {fault}")));
    }
    if let Some(fault) = secret_fault(secret) {
        return Err(bad(format!("{SECRET_KEY} {fault}")));
    }
    Ok((id.to_string(), Zeroizing::new(secret.to_string())))
}

/// An unexpected key, named only when it is an `AWS_*` variable name (a key
/// name is not secret; anything else might be a pasted value).
fn unexpected_key(key: &str) -> String {
    let named = key.starts_with("AWS_") && key.len() <= 64 && key.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if named {
        format!("unexpected key {key}")
    } else {
        "an unexpected key".to_string()
    }
}

/// Why `id` is not a long-term access key id; never echoes the value.
fn key_id_fault(id: &str) -> Option<String> {
    if !id.starts_with(KEY_ID_PREFIX) {
        return Some(if id.starts_with("ASIA") {
            "is a temporary STS key id (ASIA\u{2026}): the runtime key must be a long-term IAM user key (AKIA\u{2026})".into()
        } else {
            format!("does not start with {KEY_ID_PREFIX}")
        });
    }
    if !id.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()) {
        return Some("has a character outside 0-9 A-Z".into());
    }
    if id.len() != KEY_ID_LEN {
        return Some(format!("has {} characters, expected {KEY_ID_LEN}", id.len()));
    }
    None
}

/// Why `secret` is not a secret access key; never echoes the value.
fn secret_fault(secret: &str) -> Option<String> {
    if !secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+') {
        return Some("has a character outside A-Z a-z 0-9 / +".into());
    }
    if secret.len() != SECRET_LEN {
        return Some(format!("has {} characters, expected {SECRET_LEN}", secret.len()));
    }
    None
}

// ---- SDK configuration ----------------------------------------------------------------

/// Profile files that hold nothing and live in memory: with them the loader
/// never opens `~/.aws/config`, `~/.aws/credentials`, `AWS_CONFIG_FILE` or
/// `AWS_SHARED_CREDENTIALS_FILE` (container mode has no use for any of them).
#[allow(deprecated)] // aws-config 1.12 re-exports these under deprecated aliases (plan D21)
fn empty_profile_files() -> aws_config::profile::profile_file::ProfileFiles {
    use aws_config::profile::profile_file::{ProfileFileKind, ProfileFiles};
    ProfileFiles::builder().with_contents(ProfileFileKind::Config, "").with_contents(ProfileFileKind::Credentials, "").build()
}

/// The SDK configuration every bridge call uses (plan S4 D3): region
/// `eu-central-1`, endpoint [`CONTROL_PLANE_URL`], FIPS and dual-stack off,
/// standard retries ([`SDK_MAX_ATTEMPTS`]), timeouts connect 5 s / attempt
/// 15 s / operation 40 s, the HTTP client from `tls::sdk_http_client()`
/// (Amazon roots only, proxy environment ignored) and the credentials of
/// `creds`: static ones with empty in-memory profile files (`~/.aws` is never
/// read), a profile through a `ProfileFileCredentialsProvider` configured with
/// the same TLS client, region, FIPS/dual-stack switches, retries and timeouts
/// (so an assume-role hop keeps the policy), or the default chain for the
/// read-only tests. None of these pins can be overridden by `AWS_REGION`,
/// `AWS_ENDPOINT_URL[_LAMBDA_MICROVMS]`, `AWS_USE_FIPS_ENDPOINT`,
/// `AWS_USE_DUALSTACK_ENDPOINT` or a profile. The ENDPOINT of that STS hop is
/// the exception no setter reaches: [`connect`] refuses the configurations
/// that would move it ([`PROFILE_REFUSED_ENV`], [`PROFILE_REFUSED_KEYS`]), so
/// profile mode is safe only through [`connect`].
pub async fn sdk_config_for(creds: &RuntimeCreds) -> aws_config::SdkConfig {
    use aws_config::retry::RetryConfig;
    use aws_config::timeout::TimeoutConfig;
    let timeouts = TimeoutConfig::builder().connect_timeout(SDK_CONNECT_TIMEOUT).operation_attempt_timeout(SDK_ATTEMPT_TIMEOUT).operation_timeout(SDK_OPERATION_TIMEOUT).build();
    let retries = RetryConfig::standard().with_max_attempts(SDK_MAX_ATTEMPTS);
    let loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(REGION))
        .endpoint_url(CONTROL_PLANE_URL)
        .use_fips(false)
        .use_dual_stack(false)
        .retry_config(retries.clone())
        .timeout_config(timeouts.clone())
        .http_client(crate::bridge::tls::sdk_http_client());
    let loader = match creds {
        RuntimeCreds::Static(c) => loader.profile_files(empty_profile_files()).credentials_provider(c.clone()),
        RuntimeCreds::Profile(name) => {
            use aws_config::profile::ProfileFileCredentialsProvider;
            use aws_config::provider_config::ProviderConfig;
            let conf = ProviderConfig::default()
                .with_http_client(crate::bridge::tls::sdk_http_client())
                .with_region(Some(Region::new(REGION)))
                .with_use_fips(Some(false))
                .with_use_dual_stack(Some(false))
                .with_retry_config(retries)
                .with_timeout_config(timeouts);
            let provider = ProfileFileCredentialsProvider::builder().profile_name(name.as_str()).configure(&conf).build();
            loader.profile_name(name.as_str()).credentials_provider(provider)
        }
        RuntimeCreds::DefaultChainForReadOnlyTests => loader,
    };
    loader.load().await
}

// ---- profile mode: the STS hop no setter can pin -------------------------------------

/// Environment variables that move the STS call of an assume-role (or
/// web-identity) profile. aws-config builds that STS client from its
/// `ProviderConfig` with `ignore_configured_endpoint_urls: false` hard-coded
/// and the real process environment (aws-config 1.12 `client_config()`; no
/// public setter overrides either), so `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`
/// does not help, and `tls::sdk_http_client()` dials `http://` as readily as
/// `https://`: the SigV4-signed source key would travel in clear text and the
/// credentials would come back unauthenticated. [`connect`] refuses profile
/// mode while either is set (exit 1).
pub const PROFILE_REFUSED_ENV: [&str; 2] = ["AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS"];

/// Profile keys that move the same STS call from the shared config files
/// (`endpoint_url`, or a `services` section that may name `sts`). [`connect`]
/// refuses a profile when it, or any profile of its `source_profile` chain,
/// sets one of them, in the config or the credentials file (exit 1).
pub const PROFILE_REFUSED_KEYS: [&str; 2] = ["endpoint_url", "services"];

/// Profiles followed through `source_profile` before the walk gives up (a
/// cycle is cut earlier; the SDK refuses one on its own).
const MAX_PROFILE_CHAIN: usize = 32;

/// The top-level property names (lowercased) of every section of an AWS
/// shared file that defines profile `name`, and the `source_profile` it names
/// (first word). A config file spells the section `[profile <name>]` (and
/// `[default]` for `default`), a credentials file `[<name>]`. Comments,
/// blank lines and indented (continuation / sub-property) lines are skipped.
/// No other value is kept: a credentials file holds secrets.
fn profile_section(text: &str, credentials_file: bool, name: &str) -> (Vec<String>, Option<String>) {
    let (mut keys, mut source, mut inside) = (Vec::new(), None, false);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let words: Vec<&str> = header.split(']').next().unwrap_or_default().split_whitespace().collect();
            inside = match words.as_slice() {
                [n] if credentials_file => *n == name,
                ["default"] => name == "default",
                ["profile", n] => !credentials_file && *n == name,
                _ => false,
            };
            continue;
        }
        if !inside || raw.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            if key == "source_profile" {
                source = value.split_whitespace().next().map(str::to_string);
            }
            keys.push(key);
        }
    }
    (keys, source)
}

/// Why profile `name` must not be used, or `None` (pure: `env_set` answers
/// "is this variable set?", the file texts are passed in): a variable of
/// [`PROFILE_REFUSED_ENV`] is set, or `name` or a profile of its
/// `source_profile` chain sets a key of [`PROFILE_REFUSED_KEYS`] in either
/// file. Names variables, keys and profiles only, never a value.
fn profile_refusal(name: &str, env_set: &dyn Fn(&str) -> bool, config: Option<&str>, credentials: Option<&str>) -> Option<String> {
    const FIX: &str = "or use [aws] credentials = \"container\" (`make runtime-key`)";
    if let Some(var) = PROFILE_REFUSED_ENV.into_iter().find(|v| env_set(v)) {
        return Some(format!(
            "{var} is set: in profile mode aws-config would send the assume-role STS call of profile {name} to it (in clear text for an http:// URL), and ai-env cannot pin that call; unset {var} for ai-env, {FIX}"
        ));
    }
    let files = [("the config file", config, false), ("the credentials file", credentials, true)];
    let (mut todo, mut seen) = (vec![name.to_string()], BTreeSet::new());
    while let Some(profile) = todo.pop() {
        if seen.len() >= MAX_PROFILE_CHAIN || !seen.insert(profile.clone()) {
            continue;
        }
        for (file, text, credentials_file) in files {
            let Some(text) = text else { continue };
            let (keys, source) = profile_section(text, credentials_file, &profile);
            if let Some(key) = keys.iter().find(|k| PROFILE_REFUSED_KEYS.contains(&k.as_str())) {
                let whose = if profile == name { format!("profile {name}") } else { format!("profile {profile} (source_profile chain of {name})") };
                return Some(format!("{whose} sets {key} in {file}: aws-config would send the assume-role STS call there, and ai-env cannot pin that call; use a profile without {key}, {FIX}"));
            }
            todo.extend(source);
        }
    }
    None
}

/// `AWS_CONFIG_FILE` / `AWS_SHARED_CREDENTIALS_FILE` (a leading `~/` expanded)
/// or `~/.aws/<default>`, as the SDK locates them.
fn shared_file(var: &str, default: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match std::env::var_os(var) {
        Some(p) => match p.to_str().and_then(|s| s.strip_prefix("~/")) {
            Some(rest) => home.map(|h| h.join(rest)),
            None => Some(PathBuf::from(p)),
        },
        None => home.map(|h| h.join(".aws").join(default)),
    }
}

/// [`profile_refusal`] against the real environment and shared files. The
/// credentials file is read into a zeroizing buffer and only its key names
/// and `source_profile` values are looked at; an unreadable file counts as
/// absent (the SDK reports it).
fn profile_mode_refusal(name: &str) -> Option<String> {
    let env_set = |var: &str| std::env::var_os(var).is_some();
    let config = shared_file("AWS_CONFIG_FILE", "config").and_then(|p| std::fs::read_to_string(p).ok());
    let credentials = shared_file("AWS_SHARED_CREDENTIALS_FILE", "credentials").and_then(|p| std::fs::read_to_string(p).ok()).map(Zeroizing::new);
    profile_refusal(name, &env_set, config.as_deref(), credentials.as_ref().map(|c| c.as_str()))
}

/// Fails every request of a client whose profile [`profile_mode_refusal`]
/// refused, in `read_before_execution` — before serialization, so before any
/// credential resolution and therefore before any STS call.
#[derive(Debug)]
struct RefuseProfile(String);

impl Intercept for RefuseProfile {
    fn name(&self) -> &'static str {
        "ai-env-refuse-profile"
    }

    fn read_before_execution(&self, _ctx: &BeforeSerializationInterceptorContextRef<'_>, _cfg: &mut ConfigBag) -> std::result::Result<(), BoxError> {
        Err(self.0.clone().into())
    }
}

// ---- the client -----------------------------------------------------------------------

/// `MicrovmApi` over `aws-sdk-lambdamicrovms`, configured by [`sdk_config_for`].
///
/// Use it only inside the tokio runtime that ran [`connect`]: the SDK's HTTP
/// client keeps pooled connections and timers bound to that runtime, and a
/// call from another runtime can hang or fail. A process that needs a second
/// runtime (the live tests) connects again there.
pub struct SdkMicrovmApi {
    client: Client,
    /// The credentials this client signs with, kept for the one call the SDK
    /// does not model ([`GET_CONNECTOR_PATH`]); `None` only when the loader
    /// resolved no provider at all.
    credentials: Option<aws_sdk_lambdamicrovms::config::SharedCredentialsProvider>,
    /// The profile name in profile mode (for the SSO hint).
    profile: Option<String>,
    /// Why this client's profile is refused ([`PROFILE_REFUSED_ENV`],
    /// [`PROFILE_REFUSED_KEYS`]): every call fails with it (exit 1) before
    /// anything is resolved or sent.
    refusal: Option<String>,
}

/// The client for `creds` (see [`SdkMicrovmApi`] for the runtime rule). The
/// service configuration re-applies the region, endpoint, FIPS and
/// dual-stack pins on top of [`sdk_config_for`]. For a profile (and the
/// default chain of the read-only tests, whose profile is `AWS_PROFILE` or
/// `default`) it first reads the environment and the shared config files:
/// when they would move the assume-role STS call ([`PROFILE_REFUSED_ENV`],
/// [`PROFILE_REFUSED_KEYS`]), every call of the client — [`SdkMicrovmApi::client`]
/// included — fails with `Config` (exit 1) naming the variable or key, before
/// any credential is resolved.
pub async fn connect(creds: &RuntimeCreds) -> SdkMicrovmApi {
    let sdk = sdk_config_for(creds).await;
    let (profile, refusal) = match creds {
        RuntimeCreds::Static(_) => (None, None),
        RuntimeCreds::Profile(name) => (Some(name.clone()), profile_mode_refusal(name)),
        RuntimeCreds::DefaultChainForReadOnlyTests => {
            let name = std::env::var("AWS_PROFILE").ok().filter(|p| !p.is_empty()).unwrap_or_else(|| "default".to_string());
            (None, profile_mode_refusal(&name))
        }
    };
    let mut conf = aws_sdk_lambdamicrovms::config::Builder::from(&sdk).region(Region::new(REGION)).endpoint_url(CONTROL_PLANE_URL).use_fips(false).use_dual_stack(false);
    if let Some(why) = &refusal {
        conf = conf.interceptor(RefuseProfile(why.clone()));
    }
    let credentials = sdk.credentials_provider();
    SdkMicrovmApi { client: Client::from_conf(conf.build()), credentials, profile, refusal }
}

/// The REST path of `GetNetworkConnector`, from the aws CLI's own `lambda-core`
/// model (2.37.9, API version 2026-04-30): the date in the path is the
/// resource's, not the API's, so it is pinned here and compared with the
/// installed model by a test. `{Identifier}` is a non-greedy label (no `/`).
pub const GET_CONNECTOR_PATH: &str = "/2026-04-04/network-connectors/";

/// The SigV4 signing name of the control plane (`lambda`, as the model's
/// `signingName`), not the SDK's service id.
pub const SIGNING_NAME: &str = "lambda";

/// The largest `GetNetworkConnector` answer read (the `/health/detail` cap).
const CONNECTOR_BODY_MAX: usize = 1024 * 1024;

/// A connector identifier safe to place in a URL path: an ARN
/// (`arn:aws:lambda:…:network-connector:…`) or an `nc-…` id, so letters,
/// digits and `:._-` only. Anything else — a `/`, `%`, `?`, `#`, a space, a
/// non-ASCII byte — is refused before the request is built, so no identifier
/// can change the path it is pasted into.
fn connector_path_safe(identifier: &str) -> bool {
    !identifier.is_empty() && identifier.len() <= 2048 && identifier.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b':' | b'.' | b'_' | b'-'))
}

/// `identifier` as the path label the SDKs send: percent-encoded as
/// `aws-smithy-http`'s `label::fmt_string` does, whose own comment says AWS
/// services percent-encode `:` in a path and that "signing will fail if these
/// values are not percent encoded". Of the characters [`connector_path_safe`]
/// admits, `:` is the only one in that set, so this is exact for every
/// identifier that reaches it — an ARN's colons become `%3A`, an `nc-…` id is
/// unchanged. The signer then encodes the path once more (double encoding,
/// as the SDK signs every non-S3 service), matching what the service computes.
fn connector_path_label(identifier: &str) -> String {
    identifier.replace(':', "%3A")
}

impl SdkMicrovmApi {
    /// The underlying SDK client (the live suite calls operations the trait
    /// does not expose); a refused profile's client refuses every call too.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn map<E, R>(&self, op: &'static str, e: SdkError<E, R>) -> BridgeError
    where
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
        R: fmt::Debug,
    {
        if let Some(why) = &self.refusal {
            return BridgeError::Config(why.clone());
        }
        with_profile_hint(self.profile.as_deref(), map_sdk_error(op, e))
    }

    /// `RunMicrovm`'s error (plan D16, D18): `Ambiguous` — retry with the same
    /// client token — only when the request may have reached the service
    /// ([`sdk_ambiguous`], or a service error whose raw HTTP status is 5xx,
    /// except `InsufficientCapacityException`, which is definite). A
    /// credential-resolution failure is excluded: the SDK resolves identity
    /// just before transmitting and reports its failure as a dispatch failure
    /// although nothing was sent, so it maps like any other call
    /// (`CredentialsUnavailable`, exit 5, with the SSO hint).
    fn run_error(&self, e: SdkError<RunMicrovmError, HttpResponse>) -> BridgeError {
        const OP: &str = "run_microvm";
        if self.refusal.is_none() && (sdk_ambiguous(&e) || server_side(&e)) && !credentials_failure(&e) {
            BridgeError::Ambiguous { op: OP, message: scrub(&DisplayErrorContext(&e).to_string()).into_owned() }
        } else {
            self.map(OP, e)
        }
    }

    /// `GetNetworkConnector`, signed by hand (S7 D5): no SDK operation models
    /// it, so the request is built from [`GET_CONNECTOR_PATH`], SigV4-signed
    /// with this client's own credentials ([`SIGNING_NAME`], [`REGION`]) and
    /// sent by `tls::reqwest_client()` — the same policy as every other side
    /// channel (Amazon roots only, https only, no proxy, no redirect). The
    /// answer is the connector document `egress::ConnectorFacts::from_get`
    /// reads. A refused profile fails before anything is resolved, as every
    /// other call of such a client does.
    async fn get_connector(&self, identifier: &str) -> std::result::Result<serde_json::Value, BridgeError> {
        const OP: &str = "get_network_connector";
        if let Some(why) = &self.refusal {
            return Err(BridgeError::Config(why.clone()));
        }
        if !connector_path_safe(identifier) {
            return Err(BridgeError::Validation(format!("{OP}: {identifier:?} is not a network connector ARN or id")));
        }
        let provider = self.credentials.as_ref().ok_or_else(|| BridgeError::CredentialsUnavailable(format!("{OP}: this client resolved no credentials provider")))?;
        let creds = {
            use aws_sdk_lambdamicrovms::config::ProvideCredentials as _;
            provider.provide_credentials().await.map_err(|e| with_profile_hint(self.profile.as_deref(), BridgeError::CredentialsUnavailable(format!("{OP}: {}", scrub(&e.to_string())))))?
        };
        let url = format!("{CONTROL_PLANE_URL}{GET_CONNECTOR_PATH}{}", connector_path_label(identifier));
        // `identity` is the signer's `Identity`, inferred from `.identity()`; the signer derives `host` from the URI
        // and adds `x-amz-security-token` itself when the credentials are temporary.
        let identity = creds.into();
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(REGION)
            .name(SIGNING_NAME)
            .time(std::time::SystemTime::now())
            .settings(aws_sigv4::http_request::SigningSettings::default())
            .build()
            .map_err(|e| BridgeError::Sdk { op: OP, message: format!("signing parameters: {e}") })?
            .into();
        let signable = aws_sigv4::http_request::SignableRequest::new("GET", url.as_str(), std::iter::empty(), aws_sigv4::http_request::SignableBody::Bytes(&[]))
            .map_err(|e| BridgeError::Sdk { op: OP, message: format!("signable request: {e}") })?;
        let (signed, _signature) = aws_sigv4::http_request::sign(signable, &params).map_err(|e| BridgeError::Sdk { op: OP, message: format!("signing: {e}") })?.into_parts();
        let client = crate::bridge::tls::reqwest_client().map_err(|e| BridgeError::Sdk { op: "tls", message: format!("cannot build the HTTPS client: {e}") })?;
        let mut req = client.get(&url).timeout(SDK_ATTEMPT_TIMEOUT);
        for (name, value) in signed.headers() {
            req = req.header(name, value);
        }
        let mut reply = req.send().await.map_err(|e| BridgeError::Endpoint(format!("{OP}: {}", scrub(&e.to_string()))))?;
        let status = reply.status();
        let errortype = reply.headers().get("x-amzn-errortype").and_then(|v| v.to_str().ok()).map(str::to_string);
        // Bounded like `/health/detail`'s body: a connector document is a few hundred bytes.
        let mut body = Vec::new();
        while let Some(chunk) = reply.chunk().await.map_err(|e| BridgeError::Endpoint(format!("{OP}: reading the answer: {}", scrub(&e.to_string()))))? {
            if body.len() + chunk.len() > CONNECTOR_BODY_MAX {
                return Err(BridgeError::Sdk { op: OP, message: format!("the answer is larger than {CONNECTOR_BODY_MAX} bytes: refused") });
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&body);
        if !status.is_success() {
            return Err(connector_error(OP, status.as_u16(), errortype, &body));
        }
        serde_json::from_str(&body).map_err(|e| BridgeError::Sdk { op: OP, message: format!("the answer is not JSON: {e}") })
    }
}

/// A non-2xx `GetNetworkConnector` answer as a [`BridgeError`], classified like
/// an SDK service error ([`classify_service`]): the error code comes from
/// `x-amzn-errortype` (whose value may carry a trailing `:<url>`), else the
/// body's `__type`, else the status. The message is the body's `message`,
/// scrubbed and bounded — never the request's headers.
fn connector_error(op: &'static str, status: u16, errortype: Option<String>, body: &str) -> BridgeError {
    let doc: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let field = |k: &str| doc.get(k).and_then(serde_json::Value::as_str).map(str::to_string);
    let message = field("message").or_else(|| field("Message")).map(|m| scrub(&m).chars().take(512).collect()).unwrap_or_else(|| {
        let text = scrub(body.trim()).into_owned();
        if text.is_empty() { format!("HTTP {status}") } else { text.chars().take(512).collect() }
    });
    let code = errortype
        .map(|v| v.split([':', '/']).next().unwrap_or(&v).trim().to_string())
        .filter(|c| !c.is_empty())
        .or_else(|| field("__type").map(|t| t.rsplit('#').next().unwrap_or(&t).to_string()))
        .or_else(|| match status {
            403 => Some("AccessDeniedException".to_string()),
            404 => Some("ResourceNotFoundException".to_string()),
            429 => Some("ThrottlingException".to_string()),
            _ => None,
        });
    classify_service(op, code.as_deref(), message)
}

/// A service error answered with a 5xx status (the service may have acted
/// before failing), except `InsufficientCapacityException`: no VM was placed.
fn server_side(e: &SdkError<RunMicrovmError, HttpResponse>) -> bool {
    matches!(e, SdkError::ServiceError(se) if se.raw().status().is_server_error() && se.err().code() != Some("InsufficientCapacityException"))
}

/// The start of 2020-01-01 UTC: an earlier `startedAt` is not a real start.
/// The SDK fills a required timestamp the service left out with epoch 0.
const EARLIEST_START_UNIX: i64 = 1_577_836_800;

/// `startedAt` as Unix seconds, `None` when missing (epoch 0) or implausible.
fn start_secs(t: &aws_sdk_lambdamicrovms::primitives::DateTime) -> Option<i64> {
    Some(t.secs()).filter(|s| *s >= EARLIEST_START_UNIX)
}

/// A failure to resolve the credentials, which the SDK surfaces as a dispatch
/// failure of kind "other" (nothing was transmitted). Recognised by the text
/// of its source chain, as `map_sdk_error` recognises credential failures.
fn credentials_failure<E, R>(e: &SdkError<E, R>) -> bool
where
    E: std::error::Error + 'static,
    R: fmt::Debug,
{
    matches!(e, SdkError::DispatchFailure(d) if d.is_other()) && DisplayErrorContext(e).to_string().to_ascii_lowercase().contains("credential")
}

/// `RunMicrovm` created VM `id` but returned an endpoint outside the pin
/// (`refused`): nothing can reach it through the bridge (no `/health`, so gc
/// could never adopt it), so it is terminated at once, best effort, and the
/// failure is definite (the caller drops its pending row). The error names the
/// id, the endpoint as returned and whether the termination went through.
async fn refuse_foreign_endpoint<A: MicrovmApi>(api: &A, id: &str, refused: BridgeError) -> BridgeError {
    let why = match refused {
        BridgeError::Endpoint(m) => m,
        other => other.to_string(),
    };
    match api.terminate(id).await {
        Ok(()) => BridgeError::Endpoint(format!("{id} was created, but {why}: it was terminated")),
        Err(e) => BridgeError::Endpoint(format!(
            "{id} was created, but {why}; terminating it failed too ({e}): terminate {id} in the AWS console, or it runs (and bills) until its maximum duration"
        )),
    }
}

/// An SSO profile fails inside the SDK (this build has no `sso` feature):
/// say so, and what to use instead, as exit 5.
fn with_profile_hint(profile: Option<&str>, e: BridgeError) -> BridgeError {
    let Some(name) = profile else { return e };
    let text = e.to_string();
    if text.contains("enabled: sso") || text.contains("sso_") || text.contains("sso-session") {
        BridgeError::CredentialsUnavailable(format!(
            "{text} (profile {name} uses AWS SSO, which ai-env does not support: use [aws] credentials = \"container\" with `make runtime-key`, or a profile with static keys or credential_process)"
        ))
    } else {
        e
    }
}

/// `RunMicrovm` exactly as the bridge sends it (offline-inspectable through
/// `.as_input()`): image, version, idle policy (all three fields; a builder
/// failure is a config error), maximum duration, payload and client token
/// always; the execution role when set; the connector lists only when
/// non-empty (an empty list would not mean "the platform default"). Logging
/// is never passed (plan §3).
pub fn run_request(client: &Client, spec: &RunSpec) -> std::result::Result<RunMicrovmFluentBuilder, BridgeError> {
    let idle: IdlePolicy = idle_policy(&spec.idle).map_err(|e| BridgeError::Config(format!("idle policy {}/{}/{}: {e}", spec.idle.max_idle_s, spec.idle.suspended_s, spec.idle.auto_resume)))?;
    let mut req = client
        .run_microvm()
        .image_identifier(&spec.image_arn)
        .image_version(&spec.image_version)
        .idle_policy(idle)
        .maximum_duration_in_seconds(spec.max_duration_s)
        .run_hook_payload(&spec.run_hook_payload)
        .client_token(&spec.client_token);
    if let Some(role) = &spec.execution_role_arn {
        req = req.execution_role_arn(role);
    }
    if !spec.ingress_connectors.is_empty() {
        req = req.set_ingress_network_connectors(Some(spec.ingress_connectors.clone()));
    }
    if !spec.egress_connectors.is_empty() {
        req = req.set_egress_network_connectors(Some(spec.egress_connectors.clone()));
    }
    Ok(req)
}

/// The endpoint as stored: empty stays empty (no endpoint yet, e.g. while
/// PENDING), anything else must normalise to a pinned bare host.
fn endpoint_host(raw: &str) -> std::result::Result<String, BridgeError> {
    if raw.trim().is_empty() {
        Ok(String::new())
    } else {
        normalize_endpoint(raw)
    }
}

fn idle_spec(p: &IdlePolicy) -> IdleSpec {
    IdleSpec { max_idle_s: p.max_idle_duration_seconds(), suspended_s: p.suspended_duration_seconds(), auto_resume: p.auto_resume_enabled() }
}

/// `VmInfo` from a `RunMicrovm` or `GetMicrovm` output (same field set);
/// `Err` when the endpoint is not a pinned host.
macro_rules! vm_info_from {
    ($out:expr) => {{
        let o = $out;
        endpoint_host(&o.endpoint).map(|endpoint| VmInfo {
            idle: o.idle_policy.as_ref().map(idle_spec),
            id: o.microvm_id,
            state: VmState::from(&o.state),
            endpoint,
            image_arn: o.image_arn,
            image_version: o.image_version,
            started_at_unix: start_secs(&o.started_at),
            max_duration_s: o.maximum_duration_in_seconds,
            state_reason: o.state_reason,
            execution_role_arn: o.execution_role_arn,
            ingress: o.ingress_network_connectors.unwrap_or_default(),
            egress: o.egress_network_connectors.unwrap_or_default(),
            terminated_at_unix: o.terminated_at.map(|t| t.secs()),
        })
    }};
}

/// The token map as `AuthToken`: every value registered with the scrubber and
/// wrapped in `Secret`; a map without [`TOKEN_HEADER`] is an `Endpoint` error
/// naming the keys only. `expires_at_unix` is computed by the caller from the
/// clock BEFORE the call (the output carries no expiry), so it never
/// overstates the token's life.
fn auth_token(map: HashMap<String, String>, port: u16, expires_at_unix: u64, op: &str) -> std::result::Result<AuthToken, BridgeError> {
    let mut headers = BTreeMap::new();
    for (k, v) in map {
        register_secret(&v);
        headers.insert(k, Secret::new(v));
    }
    if !headers.contains_key(TOKEN_HEADER) {
        let keys: Vec<&str> = headers.keys().map(String::as_str).collect();
        return Err(BridgeError::Endpoint(format!("{op} returned no {TOKEN_HEADER} (keys: {})", if keys.is_empty() { "none".to_string() } else { keys.join(", ") })));
    }
    Ok(AuthToken { headers, port, expires_at_unix })
}

fn expiry(minutes: u16) -> u64 {
    unix_now() + u64::from(minutes) * 60
}

impl MicrovmApi for SdkMicrovmApi {
    async fn run(&self, spec: &RunSpec) -> std::result::Result<VmInfo, BridgeError> {
        let out = run_request(&self.client, spec)?.send().await.map_err(|e| self.run_error(e))?;
        let id = out.microvm_id.clone();
        match vm_info_from!(out) {
            Ok(vm) => Ok(vm),
            Err(refused) => Err(refuse_foreign_endpoint(self, &id, refused).await),
        }
    }

    async fn get(&self, id: &str) -> std::result::Result<VmInfo, BridgeError> {
        let out = self.client.get_microvm().microvm_identifier(id).send().await.map_err(|e| self.map("get_microvm", e))?;
        vm_info_from!(out)
    }

    async fn suspend(&self, id: &str) -> std::result::Result<(), BridgeError> {
        self.client.suspend_microvm().microvm_identifier(id).send().await.map_err(|e| self.map("suspend_microvm", e))?;
        Ok(())
    }

    async fn resume(&self, id: &str) -> std::result::Result<(), BridgeError> {
        self.client.resume_microvm().microvm_identifier(id).send().await.map_err(|e| self.map("resume_microvm", e))?;
        Ok(())
    }

    async fn terminate(&self, id: &str) -> std::result::Result<(), BridgeError> {
        self.client.terminate_microvm().microvm_identifier(id).send().await.map_err(|e| self.map("terminate_microvm", e))?;
        Ok(())
    }

    async fn list(&self, image_arn: Option<&str>) -> std::result::Result<Vec<VmSummary>, BridgeError> {
        let mut req = self.client.list_microvms();
        if let Some(arn) = image_arn {
            req = req.image_identifier(arn);
        }
        let items = req.into_paginator().items().send().try_collect().await.map_err(|e| self.map("list_microvms", e))?;
        Ok(items
            .into_iter()
            .map(|i| VmSummary { id: i.microvm_id, state: VmState::from(&i.state), image_arn: i.image_arn, image_version: i.image_version, started_at_unix: start_secs(&i.started_at) })
            .collect())
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> std::result::Result<AuthToken, BridgeError> {
        const OP: &str = "create_microvm_auth_token";
        let expires = expiry(minutes);
        let out = self
            .client
            .create_microvm_auth_token()
            .microvm_identifier(id)
            .expiration_in_minutes(i32::from(minutes))
            .allowed_ports(PortSpecification::Port(i32::from(port)))
            .send()
            .await
            .map_err(|e| self.map(OP, e))?;
        auth_token(out.auth_token, port, expires, OP)
    }

    async fn create_shell_token(&self, id: &str, minutes: u16) -> std::result::Result<AuthToken, BridgeError> {
        const OP: &str = "create_microvm_shell_auth_token";
        let expires = expiry(minutes);
        let out = self.client.create_microvm_shell_auth_token().microvm_identifier(id).expiration_in_minutes(i32::from(minutes)).send().await.map_err(|e| self.map(OP, e))?;
        auth_token(out.auth_token, SHELL_PORT, expires, OP)
    }

    async fn get_image(&self, arn: &str) -> std::result::Result<ImageInfo, BridgeError> {
        let o = self.client.get_microvm_image().image_identifier(arn).send().await.map_err(|e| self.map("get_microvm_image", e))?;
        Ok(ImageInfo { arn: o.image_arn, name: o.name, state: o.state.as_str().to_string(), latest_active: o.latest_active_image_version, latest_failed: o.latest_failed_image_version })
    }

    async fn list_image_versions(&self, arn: &str) -> std::result::Result<Vec<ImageVersion>, BridgeError> {
        let items = self.client.list_microvm_image_versions().image_identifier(arn).into_paginator().items().send().try_collect().await.map_err(|e| self.map("list_microvm_image_versions", e))?;
        Ok(items
            .into_iter()
            .map(|v| ImageVersion {
                memory_mib: v.resources.as_ref().and_then(|r| r.first()).map(|r| r.minimum_memory_in_mib),
                version: v.image_version,
                state: v.state.as_str().to_string(),
                status: v.status.as_str().to_string(),
                created_at_unix: Some(v.created_at.secs()),
            })
            .collect())
    }

    async fn list_managed_images(&self) -> std::result::Result<Vec<ManagedImage>, BridgeError> {
        let items = self.client.list_managed_microvm_images().into_paginator().items().send().try_collect().await.map_err(|e| self.map("list_managed_microvm_images", e))?;
        Ok(items.into_iter().map(|i| ManagedImage { arn: i.image_arn }).collect())
    }

    async fn get_network_connector(&self, identifier: &str) -> std::result::Result<serde_json::Value, BridgeError> {
        self.get_connector(identifier).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AKIA` + 16 of `[A-Z0-9]`, built at run time (no credential-shaped literal).
    fn key_id(tail: &str) -> String {
        format!("{KEY_ID_PREFIX}{}{tail}", "CLNT".repeat(3))
    }

    /// 40 characters of the secret alphabet, built at run time.
    fn secret(block: &str) -> String {
        format!("{}{}", block.repeat(9), "Zq9+")
    }

    fn env(id: &str, secret: &str) -> String {
        format!("{ID_KEY}={id}\n{SECRET_KEY}={secret}\n")
    }

    #[test]
    fn parse_runtime_env_accepts_what_the_sealer_writes() {
        let (i, s) = (key_id("A1B2"), secret("pQ3/"));
        let (id, sec) = parse_runtime_env(env(&i, &s).as_bytes()).unwrap();
        assert_eq!((id.as_str(), sec.as_str()), (i.as_str(), s.as_str()));
        let swapped = format!("{SECRET_KEY}={s}\n{ID_KEY}={i}");
        assert_eq!(parse_runtime_env(swapped.as_bytes()).unwrap().0, i, "either order, final newline optional");
        let logged = format!("key {i} secret {s}");
        let masked = scrub(&logged);
        assert!(!masked.contains(&i) && !masked.contains(&s), "both registered with the scrubber: {masked}");
    }

    #[test]
    fn parse_runtime_env_refuses_other_shapes_without_echoing_values() {
        let (i, s) = (key_id("C3D4"), secret("rS5+"));
        let temp = format!("ASIA{}", &i[4..]);
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "is empty"),
            ("\n".into(), "is empty"),
            (format!("{ID_KEY}={i}\n"), "AWS_SECRET_ACCESS_KEY is missing"),
            (format!("{SECRET_KEY}={s}\n"), "AWS_ACCESS_KEY_ID is missing"),
            (format!("{}{SECRET_KEY}={s}\n", env(&i, &s)), "appears twice"),
            (format!("{}AWS_SESSION_TOKEN={s}\n", env(&i, &s)), "unexpected key AWS_SESSION_TOKEN"),
            (format!("{}{s}={i}\n", env(&i, &s)), "an unexpected key"),
            (format!("{}\n{}", env(&i, &s), "junk"), "not KEY=VALUE"),
            (format!("{ID_KEY}={i}\n\n{SECRET_KEY}={s}\n"), "line 2 is not KEY=VALUE"),
            (env(&i, &s).replace('\n', "\r\n"), "character outside"),
            (env(&temp, &s), "temporary STS key"),
            (env(&i.to_ascii_lowercase().replacen("akia", "AKIA", 1), &s), "outside 0-9 A-Z"),
            (env(&format!("{i}Q"), &s), "has 21 characters, expected 20"),
            (env(&i, &s[..39]), "has 39 characters, expected 40"),
            (env(&i, &format!("{}-", &s[..39])), "outside A-Z a-z 0-9 / +"),
            (format!("export {ID_KEY}={i}\n{SECRET_KEY}={s}\n"), "an unexpected key"),
        ];
        for (input, want) in &cases {
            let e = parse_runtime_env(input.as_bytes()).unwrap_err();
            let text = e.to_string();
            assert!(matches!(e, BridgeError::CredentialsUnavailable(_)), "{text}");
            assert!(text.contains(want), "{input:?}: want {want:?} in {text}");
            assert!(text.contains("make runtime-key"), "{text}");
            assert!(!text.contains(&s[..20]) && !text.contains(&i[4..]) && !text.contains(&temp[4..]), "a value leaked: {text}");
            let c: CliError = e.into();
            assert_eq!(c.exit_code(), 5);
        }
        assert!(parse_runtime_env(&[0xff, 0xfe]).unwrap_err().to_string().contains("not UTF-8"));
    }

    #[test]
    fn runtime_creds_debug_and_describe_never_show_key_material() {
        let (i, s) = (key_id("E5F6"), secret("tU7/"));
        let creds = RuntimeCreds::Static(Credentials::new(i.clone(), s.clone(), None, None, CONTAINER_PROVIDER));
        let debug = format!("{creds:?}");
        assert_eq!(debug, "RuntimeCreds::Static([redacted])");
        assert_eq!(creds.describe(), "runtime key \u{2026}E5F6 (credentials/aws.env)");
        assert!(!creds.describe().contains(&i[..16]));
        assert_eq!(RuntimeCreds::Profile("ops".into()).describe(), "profile ops");
        assert_eq!(format!("{:?}", RuntimeCreds::Profile("ops".into())), "RuntimeCreds::Profile(\"ops\")");
        assert_eq!(RuntimeCreds::DefaultChainForReadOnlyTests.describe(), "default chain (read-only tests)");
        let nested = format!("{:?}", Some(creds.clone()));
        assert!(!nested.contains(&i) && !nested.contains(&s), "{nested}");
    }

    #[test]
    fn runtime_credentials_profile_mode_and_config_errors() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let store = Keystore::resolve(Some(dir.path().join("keystore"))).unwrap();
        let mut cfg = BridgeConfig::default();
        cfg.aws.credentials = "profile:ai-env-ops".into();
        assert_eq!(runtime_credentials(&store, &paths, &cfg).unwrap().describe(), "profile ai-env-ops");
        cfg.aws.credentials = "keychain".into();
        assert_eq!(runtime_credentials(&store, &paths, &cfg).unwrap_err().exit_code(), 1);
    }

    #[test]
    fn runtime_credentials_container_needs_a_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let store = Keystore::resolve(Some(dir.path().join("keystore"))).unwrap();
        let cfg = BridgeConfig::default();
        let e = runtime_credentials(&store, &paths, &cfg).unwrap_err();
        assert_eq!(e.exit_code(), 5, "{e}");
        assert!(e.to_string().contains("make runtime-key"), "{e}");
        std::fs::create_dir_all(paths.credentials()).unwrap();
        let (i, s) = (key_id("G7H8"), secret("vW9+"));
        std::fs::write(paths.aws_env(), env(&i, &s)).unwrap();
        let e = runtime_credentials(&store, &paths, &cfg).unwrap_err();
        assert_eq!(e.exit_code(), 5, "{e}");
        let text = e.to_string();
        assert!(text.contains("plaintext") && text.contains("make runtime-key") && !text.contains(&s), "{text}");
    }

    #[test]
    fn auth_token_registers_values_and_names_only_keys() {
        let value = format!("{}{}", "tokv".repeat(6), "Z9");
        let mut map = HashMap::new();
        map.insert(TOKEN_HEADER.to_string(), value.clone());
        let t = auth_token(map, 8080, 42, "create_microvm_auth_token").unwrap();
        assert_eq!((t.port, t.expires_at_unix), (8080, 42));
        assert_eq!(t.value().unwrap().expose(), &value);
        assert!(!scrub(&format!("x {value} y")).contains(&value), "registered with the scrubber");
        let other = format!("{}{}", "othr".repeat(6), "Q1");
        let mut map = HashMap::new();
        map.insert("x-aws-proxy-auth".to_string(), other.clone());
        let e = auth_token(map, 8080, 42, "create_microvm_auth_token").unwrap_err();
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Endpoint(_)), "{text}");
        assert!(text.contains("x-aws-proxy-auth") && text.contains(TOKEN_HEADER) && !text.contains(&other), "{text}");
        assert!(auth_token(HashMap::new(), 8022, 1, "create_microvm_shell_auth_token").unwrap_err().to_string().contains("keys: none"));
    }

    #[test]
    fn endpoint_host_keeps_empty_and_refuses_foreign_hosts() {
        assert_eq!(endpoint_host("").unwrap(), "");
        assert_eq!(endpoint_host("  ").unwrap(), "");
        let host = format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{}", crate::bridge::api::ENDPOINT_SUFFIX);
        assert_eq!(endpoint_host(&format!("https://{host}/")).unwrap(), host);
        assert!(matches!(endpoint_host("evil.example.com"), Err(BridgeError::Endpoint(_))));
        assert!(matches!(endpoint_host(&format!("http://{host}")), Err(BridgeError::Endpoint(_))));
    }

    #[test]
    fn sso_profiles_get_a_hint_and_exit_5() {
        let e = with_profile_hint(Some("corp"), BridgeError::Sdk { op: "list_microvms", message: "This behavior requires following cargo feature(s) enabled: sso. ".into() });
        let text = e.to_string();
        assert!(matches!(e, BridgeError::CredentialsUnavailable(_)), "{text}");
        assert!(text.contains("profile corp uses AWS SSO") && text.contains("container"), "{text}");
        let plain = with_profile_hint(None, BridgeError::Sdk { op: "x", message: "enabled: sso".into() });
        assert!(matches!(plain, BridgeError::Sdk { .. }), "container mode is untouched");
        let other = with_profile_hint(Some("corp"), BridgeError::Throttled("slow".into()));
        assert!(matches!(other, BridgeError::Throttled(_)));
    }

    #[tokio::test]
    async fn control_plane_url_is_what_the_sdk_resolves() {
        use aws_sdk_lambdamicrovms::config::endpoint::{DefaultResolver, Params, ResolveEndpoint};
        let params = Params::builder().region(REGION).use_fips(false).use_dual_stack(false).build().unwrap();
        let ep = DefaultResolver::new().resolve_endpoint(&params).await.unwrap();
        assert_eq!(ep.url(), CONTROL_PLANE_URL);
    }

    #[tokio::test]
    async fn sdk_config_for_static_pins_everything() {
        let creds = RuntimeCreds::Static(Credentials::new(key_id("J9K0"), secret("xY1/"), None, None, CONTAINER_PROVIDER));
        let cfg = sdk_config_for(&creds).await;
        assert_eq!(cfg.region().map(|r| r.as_ref().to_string()).as_deref(), Some(REGION));
        assert_eq!(cfg.endpoint_url(), Some(CONTROL_PLANE_URL));
        assert_eq!((cfg.use_fips(), cfg.use_dual_stack()), (Some(false), Some(false)));
        assert!(cfg.http_client().is_some(), "the bridge's TLS client, never the SDK default");
        assert!(cfg.credentials_provider().is_some());
        let retry = cfg.retry_config().unwrap();
        assert_eq!(retry.max_attempts(), SDK_MAX_ATTEMPTS);
        assert_eq!(retry.mode(), aws_config::retry::RetryMode::Standard);
        let t = cfg.timeout_config().unwrap();
        assert_eq!(t.connect_timeout(), Some(SDK_CONNECT_TIMEOUT));
        assert_eq!(t.operation_attempt_timeout(), Some(SDK_ATTEMPT_TIMEOUT));
        assert_eq!(t.operation_timeout(), Some(SDK_OPERATION_TIMEOUT));
        let api = connect(&creds).await;
        let conf = api.client().config();
        assert_eq!(conf.region().map(|r| r.as_ref().to_string()).as_deref(), Some(REGION));
        assert_eq!(conf.retry_config().map(aws_config::retry::RetryConfig::max_attempts), Some(SDK_MAX_ATTEMPTS));
    }

    fn static_creds(tail: &str) -> RuntimeCreds {
        RuntimeCreds::Static(Credentials::new(key_id(tail), secret("bC4/"), None, None, CONTAINER_PROVIDER))
    }

    #[test]
    fn profile_refusal_names_the_variable_or_the_key_never_a_value() {
        let unset = |_: &str| false;
        let config = "[default]\nregion = eu-central-1\n\n[profile ops]\nrole_arn = arn:aws:iam::123456789012:role/ops\nsource_profile = base # the keys\n\n[profile base]\nregion = eu-central-1\n";
        assert_eq!(profile_refusal("ops", &unset, Some(config), None), None, "a plain assume-role chain is fine");
        assert_eq!(profile_refusal("absent", &unset, None, None), None, "no files: the SDK reports the missing profile");
        for var in PROFILE_REFUSED_ENV {
            let set = |v: &str| v == var;
            let why = profile_refusal("ops", &set, Some(config), None).unwrap();
            assert!(why.contains(&format!("{var} is set")) && why.contains("profile ops") && why.contains("container"), "{why}");
        }
        let direct = format!("{config}\n[profile direct]\nrole_arn = arn:aws:iam::123456789012:role/ops\nsource_profile = base\nendpoint_url = http://127.0.0.1:4566\n");
        let why = profile_refusal("direct", &unset, Some(&direct), None).unwrap();
        assert!(why.contains("profile direct sets endpoint_url in the config file") && !why.contains("4566"), "{why}");

        // Two hops down, in the credentials file (bare section names there).
        let id = key_id("P1Q2");
        let chain = "[profile top]\nrole_arn = x\nsource_profile = mid\n[profile mid]\nrole_arn = y\nsource_profile = leaf\n";
        let creds = format!("[leaf]\naws_access_key_id = {id}\naws_secret_access_key = {}\nservices = local\n", secret("dE5+"));
        let why = profile_refusal("top", &unset, Some(chain), Some(&creds)).unwrap();
        assert!(why.contains("profile leaf (source_profile chain of top) sets services in the credentials file"), "{why}");
        assert!(!why.contains(&id[4..]), "{why}");

        // What the SDK would not read as a key of that profile is not one here either.
        for quiet in [
            "[profile ops]\n# endpoint_url = http://x\n; services = y\n",
            "[profile ops]\nrole_arn = x\n  endpoint_url = http://x\n",
            "[profile ops]\nregion = eu-central-1\n[services local]\nsts =\n  endpoint_url = http://x\n",
            "[ops]\nendpoint_url = http://x\n",
            "[profile opsx]\nendpoint_url = http://x\n",
        ] {
            assert_eq!(profile_refusal("ops", &unset, Some(quiet), None), None, "{quiet:?}");
        }
        assert!(profile_refusal("ops", &unset, None, Some("[ops]\nendpoint_url = http://x\n")).is_some(), "credentials-file sections are bare names");
        assert!(profile_refusal("ops", &unset, Some("[ profile   ops ]\nEndpoint_URL = http://x\n"), None).is_some(), "spacing and case");
        assert!(profile_refusal("default", &unset, Some("[default]\nservices = s\n"), None).is_some());
        assert!(profile_refusal("default", &unset, Some("[profile default]\nendpoint_url = http://x\n"), None).is_some());
        let cycle = "[profile a]\nsource_profile = b\n[profile b]\nsource_profile = a\n";
        assert_eq!(profile_refusal("a", &unset, Some(cycle), None), None, "a cycle ends the walk");
    }

    /// Stops a request before transmission (nothing is ever sent by these tests).
    #[derive(Debug)]
    struct StopBeforeTransmit;

    impl Intercept for StopBeforeTransmit {
        fn name(&self) -> &'static str {
            "StopBeforeTransmit"
        }

        fn read_before_transmit(
            &self,
            _ctx: &aws_sdk_lambdamicrovms::config::interceptors::BeforeTransmitInterceptorContextRef<'_>,
            _rc: &aws_sdk_lambdamicrovms::config::RuntimeComponents,
            _cfg: &mut ConfigBag,
        ) -> std::result::Result<(), BoxError> {
            Err("stopped before transmit".into())
        }
    }

    /// The hand-signed `GetNetworkConnector` (S7 D5): the path and signing name
    /// are the aws CLI model's (2.37.9, `lambda-core`), the identifier can only
    /// be an ARN or an `nc-…` id, and a non-2xx answer is classified like any
    /// other service error. Part B compares the path with the live service.
    #[test]
    fn the_connector_read_is_pinned_and_its_identifier_bounded() {
        assert_eq!(GET_CONNECTOR_PATH, "/2026-04-04/network-connectors/");
        assert_eq!(SIGNING_NAME, "lambda");
        assert!(GET_CONNECTOR_PATH.starts_with('/') && GET_CONNECTOR_PATH.ends_with('/'), "a path the identifier is appended to");
        assert_eq!(format!("{CONTROL_PLANE_URL}{GET_CONNECTOR_PATH}nc-1"), "https://lambda.eu-central-1.amazonaws.com/2026-04-04/network-connectors/nc-1");
        for ok in ["nc-0a1b2c3d4e5f60718", "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress", "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-1", "a.b_c-1:2"] {
            assert!(connector_path_safe(ok), "{ok}");
        }
        // Nothing that could change the path it is pasted into, or leave the host.
        for bad in ["", "nc-1/..", "nc 1", "nc-1?x=1", "nc-1#f", "%2e%2e", "nc-1/../../vms", "../x", "nc-1\n", "nc-é", &"n".repeat(2049)] {
            assert!(!connector_path_safe(bad), "{bad:?}");
        }
        // The label is sent as the SDKs send it: an ARN's colons percent-encoded (aws-smithy-http's label set: an
        // unencoded `:` fails the signature), an `nc-` id unchanged. The audit found the raw form first.
        let arn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-f0b942fe-0612-44a7-9183-16942c532410";
        assert_eq!(connector_path_label(arn), "arn%3Aaws%3Alambda%3Aeu-central-1%3A123456789012%3Anetwork-connector%3Anc-f0b942fe-0612-44a7-9183-16942c532410");
        assert_eq!(connector_path_label("nc-0a1b2c3d4e5f60718"), "nc-0a1b2c3d4e5f60718");
        // Every other character `connector_path_safe` admits is outside that set, so nothing else is touched.
        assert_eq!(connector_path_label("a.b_c-1"), "a.b_c-1");
        // The URL the signer and reqwest both see: no raw colon after the scheme.
        let url = format!("{CONTROL_PLANE_URL}{GET_CONNECTOR_PATH}{}", connector_path_label(arn));
        assert!(!url["https://".len()..].contains(':'), "{url}");
        let signable = aws_sigv4::http_request::SignableRequest::new("GET", url.as_str(), std::iter::empty(), aws_sigv4::http_request::SignableBody::Bytes(&[]));
        assert!(signable.is_ok(), "the encoded URL parses for signing");
        // An error message from the service is scrubbed and bounded too, not only a non-JSON body.
        let long = connector_error("get_network_connector", 400, None, &format!("{{\"message\":\"{}\"}}", "m".repeat(4096)));
        assert!(long.to_string().len() < 700, "{} chars", long.to_string().len());
        // A non-2xx: the error type header, else the body's __type, else the status.
        let header = connector_error("get_network_connector", 403, Some("AccessDeniedException:http://internal".into()), "{\"message\":\"not authorized\"}");
        assert!(matches!(&header, BridgeError::AccessDenied(m) if m.contains("not authorized")), "{header}");
        assert_eq!(CliError::from(header).exit_code(), 7);
        let typed = connector_error("get_network_connector", 400, None, "{\"__type\":\"com.amazon#ThrottlingException\",\"message\":\"slow down\"}");
        assert!(matches!(&typed, BridgeError::Throttled(m) if m == "slow down"), "{typed}");
        let by_status = connector_error("get_network_connector", 404, None, "{}");
        assert!(matches!(&by_status, BridgeError::Sdk { message, .. } if message.contains("ResourceNotFoundException")), "{by_status}");
        let no_body = connector_error("get_network_connector", 500, None, "");
        assert!(matches!(&no_body, BridgeError::Sdk { message, .. } if message.contains("HTTP 500")), "{no_body}");
        // A body that is not JSON is bounded and scrubbed, never echoed whole.
        let html = connector_error("get_network_connector", 502, None, &format!("<html>{}</html>", "x".repeat(4096)));
        let text = html.to_string();
        assert!(text.len() < 700 && !text.contains(&"x".repeat(600)), "{} chars", text.len());
    }

    #[tokio::test]
    async fn a_refused_profile_fails_every_call_before_anything_is_resolved() {
        let api = connect(&static_creds("R3S4")).await;
        let why = "AWS_ENDPOINT_URL_STS is set: refused for the test".to_string();
        let refused = SdkMicrovmApi { client: api.client.clone(), credentials: api.credentials.clone(), profile: Some("ops".into()), refusal: Some(why.clone()) };
        let conf = api.client.config().to_builder().interceptor(RefuseProfile(why.clone())).build();
        let e = Client::from_conf(conf).list_microvms().customize().interceptor(StopBeforeTransmit).send().await.unwrap_err();
        assert!(matches!(e, SdkError::ConstructionFailure(_)), "refused before serialization: {}", DisplayErrorContext(&e));
        let mapped = refused.map("list_microvms", e);
        assert_eq!(mapped.to_string(), format!("config: {why}"));
        assert_eq!(CliError::from(mapped).exit_code(), 1);
        let io = SdkError::<RunMicrovmError, HttpResponse>::dispatch_failure(aws_sdk_lambdamicrovms::error::ConnectorError::io("reset".into()));
        assert!(matches!(refused.run_error(io), BridgeError::Config(_)), "never ambiguous: nothing was resolved or sent");
    }

    #[tokio::test]
    async fn run_error_is_ambiguous_only_when_the_request_may_have_been_sent() {
        use aws_sdk_lambdamicrovms::error::ConnectorError;
        type E = SdkError<RunMicrovmError, HttpResponse>;
        let api = connect(&static_creds("T5U6")).await;
        let creds = E::dispatch_failure(ConnectorError::other("failed to load credentials: profile ai-env-missing-profile was not defined".into(), None));
        assert!(credentials_failure(&creds));
        let e = api.run_error(creds);
        assert!(matches!(e, BridgeError::CredentialsUnavailable(_)), "nothing was sent: {e}");
        assert_eq!(CliError::from(e).exit_code(), 5);
        for sent in [E::dispatch_failure(ConnectorError::io("connection reset".into())), E::dispatch_failure(ConnectorError::other("connection closed before message completed".into(), None)), E::timeout_error("operation timeout")] {
            assert!(!credentials_failure(&sent));
            assert!(matches!(api.run_error(sent), BridgeError::Ambiguous { op: "run_microvm", .. }));
        }
        let io_mentioning = E::dispatch_failure(ConnectorError::io("credential helper socket reset".into()));
        assert!(!credentials_failure(&io_mentioning), "only the kind the identity resolver produces");
        assert!(matches!(api.run_error(E::construction_failure("bad input")), BridgeError::Sdk { .. }), "never sent: definite");
    }

    /// A `RunMicrovm` service error as the SDK builds it: the code and message in the metadata, the raw response with `status`.
    fn run_service_error(code: &str, status: u16) -> SdkError<RunMicrovmError, HttpResponse> {
        let meta = aws_sdk_lambdamicrovms::error::ErrorMetadata::builder().code(code).message("the service said no").build();
        let raw = HttpResponse::new(status.try_into().expect("a valid status"), "{}".into());
        SdkError::service_error(RunMicrovmError::generic(meta), raw)
    }

    #[tokio::test]
    async fn run_error_treats_a_5xx_service_error_as_ambiguous_except_insufficient_capacity() {
        let api = connect(&static_creds("V7W8")).await;
        for (code, status) in [("InternalServerException", 500), ("SomethingNewException", 503), ("ServiceUnavailableException", 503), ("BadGatewayException", 502)] {
            let e = api.run_error(run_service_error(code, status));
            assert!(matches!(e, BridgeError::Ambiguous { op: "run_microvm", .. }), "{code} {status}: {e}");
        }
        let e = api.run_error(run_service_error("InsufficientCapacityException", 500));
        assert!(matches!(e, BridgeError::Sdk { op: "run_microvm", .. }) && e.to_string().contains("retry later"), "definite: {e}");
        for (code, status) in [("ValidationException", 400), ("ServiceQuotaExceededException", 402), ("ConflictException", 409), ("ResourceNotFoundException", 404)] {
            assert!(!matches!(api.run_error(run_service_error(code, status)), BridgeError::Ambiguous { .. }), "{code} {status}: definite");
        }
        let e = api.run_error(run_service_error("ResourceNotFoundException", 404));
        assert!(matches!(e, BridgeError::Sdk { op: "run_microvm", .. }) && e.to_string().contains("ResourceNotFoundException: the service said no"), "the image version, connector or role: exit 7, not a lost VM: {e}");
        assert_eq!(CliError::from(e).exit_code(), 7);
    }

    #[test]
    fn a_start_before_2020_is_no_start() {
        use aws_sdk_lambdamicrovms::primitives::DateTime;
        assert_eq!(start_secs(&DateTime::from_secs(0)), None, "the SDK's default for a missing required timestamp");
        assert_eq!(start_secs(&DateTime::from_secs(EARLIEST_START_UNIX - 1)), None);
        assert_eq!(start_secs(&DateTime::from_secs(1_790_000_000)), Some(1_790_000_000));
    }

    fn run_spec(token: &str) -> RunSpec {
        RunSpec {
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: token.into(),
        }
    }

    #[tokio::test]
    async fn a_foreign_endpoint_after_run_terminates_the_vm_and_is_definite() {
        use crate::bridge::api::{Call, FakeMicrovmApi};
        let api = FakeMicrovmApi::new();
        let vm = api.run(&run_spec("01926f2e-0000-7000-8000-0000000000f1")).await.unwrap();
        let e = refuse_foreign_endpoint(&api, &vm.id, normalize_endpoint("https://x.lambda-microvm.eu-west-3.on.aws/").unwrap_err()).await;
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Endpoint(_)), "definite (not Ambiguous): run.rs drops the pending row: {text}");
        assert!(text.contains(&vm.id) && text.contains("x.lambda-microvm.eu-west-3.on.aws") && text.ends_with("it was terminated"), "{text}");
        assert_eq!(api.calls().last(), Some(&Call::Terminate(vm.id.clone())));
        assert_eq!(CliError::from(e).exit_code(), 7);

        let api = FakeMicrovmApi::new();
        let vm = api.run(&run_spec("01926f2e-0000-7000-8000-0000000000f2")).await.unwrap();
        api.fail_on("terminate", BridgeError::Throttled("slow down".into()), false);
        let text = refuse_foreign_endpoint(&api, &vm.id, normalize_endpoint("evil.example.com").unwrap_err()).await.to_string();
        assert!(text.contains("terminating it failed too") && text.contains("slow down") && text.contains(&format!("terminate {} in the AWS console", vm.id)), "{text}");
    }

    #[tokio::test]
    async fn run_request_refuses_nothing_valid_and_omits_empty_connector_lists() {
        let creds = RuntimeCreds::Static(Credentials::new(key_id("L1M2"), secret("zA3+"), None, None, CONTAINER_PROVIDER));
        let client = connect(&creds).await;
        let spec = RunSpec {
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "01926f2e-0000-7000-8000-000000000001".into(),
        };
        let req = run_request(client.client(), &spec).unwrap();
        let input = req.as_input();
        assert_eq!(input.get_ingress_network_connectors(), &None, "empty = the platform default: never sent as []");
        assert_eq!(input.get_egress_network_connectors(), &None);
        assert_eq!(input.get_execution_role_arn(), &None);
        assert_eq!(input.get_logging(), &None, "logging is never passed (plan §3)");
    }
}
