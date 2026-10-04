//! `~/.config/ai-env/bridge/bridge.toml` — the bridge's operator configuration
//! (§2.4 of the plan). The AWS region is pinned in code: a differing value in
//! the file is an error and the environment is never consulted.
use crate::bridge::errors::BridgeError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The only region the MicroVM API is available in for this account (eu-west-3
/// answers 403). Pinned in code; `AWS_REGION` is ignored on purpose.
pub const REGION: &str = "eu-central-1";

/// State root and config file location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub root: PathBuf,
    pub config: PathBuf,
}

impl Paths {
    /// `AI_ENV_BRIDGE_DIR` | `$HOME/.config/ai-env/bridge`; config from
    /// `AI_ENV_BRIDGE_CONFIG` | `<root>/bridge.toml`.
    pub fn resolve() -> Result<Paths, BridgeError> {
        // Set-but-empty counts as unset, as the Makefile's `${AI_ENV_BRIDGE_DIR:-…}`
        // reads it: an empty root would put the state under the working directory.
        let root = match std::env::var_os("AI_ENV_BRIDGE_DIR").filter(|d| !d.is_empty()) {
            Some(d) => PathBuf::from(d),
            None => {
                let home = std::env::var_os("HOME").ok_or_else(|| BridgeError::Config("HOME is not set".into()))?;
                PathBuf::from(home).join(".config").join("ai-env").join("bridge")
            }
        };
        Ok(Self::from_root_and_env(root, std::env::var_os("AI_ENV_BRIDGE_CONFIG").filter(|c| !c.is_empty()).map(PathBuf::from)))
    }

    #[must_use]
    pub fn from_root_and_env(root: PathBuf, config_override: Option<PathBuf>) -> Paths {
        let config = config_override.unwrap_or_else(|| root.join("bridge.toml"));
        Paths { root, config }
    }

    #[must_use]
    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// The invocation census (one JSON line per wrapper invocation).
    #[must_use]
    pub fn census(&self) -> PathBuf {
        self.logs().join("census.jsonl")
    }

    /// Version-stamped probe verdicts.
    #[must_use]
    pub fn probes(&self) -> PathBuf {
        self.root.join("lab").join("probes.jsonl")
    }

    /// The wrapper's own log (the S2 pump is its first writer).
    #[must_use]
    pub fn wrapper_log(&self) -> PathBuf {
        self.logs().join("wrapper.log")
    }

    /// `state/sessions`: one `<uuid>.toml` per session the wrapper registered.
    #[must_use]
    pub fn sessions(&self) -> PathBuf {
        self.root.join("state").join("sessions")
    }

    /// `state/scratch`: per-session scratch `CLAUDE_CONFIG_DIR`s (`local-scratch` mode).
    #[must_use]
    pub fn scratch(&self) -> PathBuf {
        self.root.join("state").join("scratch")
    }

    /// `audit.jsonl`: one JSON line per audited event, fsync'ed per line.
    #[must_use]
    pub fn audit(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// `credentials/`: ai-env containers sealed to the `[creds].key` keystore key.
    #[must_use]
    pub fn credentials(&self) -> PathBuf {
        self.root.join("credentials")
    }

    /// `credentials/aws.env`: the runtime principal's access key (S3 `make runtime-key`).
    #[must_use]
    pub fn aws_env(&self) -> PathBuf {
        self.credentials().join("aws.env")
    }

    /// `state/infra.toml`: what `ai-env infra status --write` learned from the stack
    /// (image state and versions, zip hash, bucket, log group) for doctor.
    #[must_use]
    pub fn infra_state(&self) -> PathBuf {
        self.root.join("state").join("infra.toml")
    }

    /// `state/vms`: one `<microvm id>.toml` per VM `ai-env vm` started, plus
    /// `pending-<client_token>.toml` rows written before `RunMicrovm` (S4).
    #[must_use]
    pub fn vms(&self) -> PathBuf {
        self.root.join("state").join("vms")
    }

    /// `state/vms.lock`: held while counting VMs against `[vm].max_concurrent`
    /// and writing the pending row, so the limit holds across workspaces.
    #[must_use]
    pub fn placement_lock(&self) -> PathBuf {
        self.root.join("state").join("vms.lock")
    }

    /// `state/workspaces`: the per-workspace locks (S4) and rows (S8).
    #[must_use]
    pub fn workspaces(&self) -> PathBuf {
        self.root.join("state").join("workspaces")
    }

    /// `state/workspaces/<slug>.lock`, held from SELECT_VM until the VM is
    /// RUNNING. `slug` must already be a project dir name (`[A-Za-z0-9-]`).
    #[must_use]
    pub fn workspace_lock(&self, slug: &str) -> PathBuf {
        self.workspaces().join(format!("{slug}.lock"))
    }

    /// `logs/ai-env.log`: the operator CLI's own log (`ai-env vm|lab`).
    #[must_use]
    pub fn cli_log(&self) -> PathBuf {
        self.logs().join("ai-env.log")
    }

    /// `state/egress.lock`: held by `ai-env egress allow|suspend|reload` around
    /// every read-modify-write of the proxy's SSM parameters (S5).
    #[must_use]
    pub fn egress_lock(&self) -> PathBuf {
        self.root.join("state").join("egress.lock")
    }

    /// `state/egress-verified.toml`: the passing `ai-env egress check` runs, one
    /// per (image, image version, connector); `egress::credential_gate` reads it (S5).
    #[must_use]
    pub fn egress_verified(&self) -> PathBuf {
        self.root.join("state").join("egress-verified.toml")
    }
}

/// `arn:aws:lambda:eu-central-1:<12 digits>:network-connector:<name>[:<N>]`,
/// `<name>` 1–64 of `[A-Za-z0-9_-]`, `<N>` a version of digits: a customer
/// connector in the pinned region. The managed connectors (account `aws`)
/// never match.
#[must_use]
pub fn is_connector_arn(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(&format!("arn:aws:lambda:{REGION}:")) else { return false };
    let Some((account, tail)) = rest.split_once(":network-connector:") else { return false };
    let (name, version) = match tail.split_once(':') {
        Some((n, v)) => (n, Some(v)),
        None => (tail, None),
    };
    let digits = |v: &str| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit());
    account.len() == 12
        && digits(account)
        && (1..=64).contains(&name.len())
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        && version.is_none_or(|v| digits(v) && v.len() <= 10)
}

/// Is `ip` an IPv4 address in RFC 1918 space (10/8, 172.16/12, 192.168/16)?
#[must_use]
pub fn is_rfc1918(ip: &str) -> bool {
    // `Ipv4Addr` refuses octets with leading zeros (no octal ambiguity).
    ip.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.is_private())
}

/// Is `ip` an address the platform's own resolver can have: a private (RFC
/// 1918) or link-local IPv4, or an IPv6 address in the VPC's `fd00:ec2::/32`
/// (`fd00:ec2::253`)? The address class only, never an acceptance: a public
/// resolver that answers a `vpc` VM is open DNS. No zone (`%eth0`), no
/// brackets, no surrounding spaces, no IPv4 leading zeros: exactly what
/// `IpAddr` parses (zero-padded IPv6 groups, `fd00:0ec2::0253`, are fine).
#[must_use]
pub fn is_platform_address(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok_and(|a| is_platform_ip(&a))
}

fn is_platform_ip(a: &std::net::IpAddr) -> bool {
    match a {
        std::net::IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        std::net::IpAddr::V6(a) => a.segments()[0] == 0xfd00 && a.segments()[1] == 0x0ec2,
    }
}

impl AwsCfg {
    /// The S5 keys `ai-env vm|lab|egress|proxy` and doctor rely on: a set
    /// `egress_connector_arn` must be [`is_connector_arn`], a set
    /// `proxy_private_ip` must be [`is_rfc1918`]. Checked by those commands
    /// only, never by [`BridgeConfig::parse`] (the wrapper routes on a file
    /// S1–S4 already accepted). A violation is exit 1 naming the key.
    pub fn validate_egress(&self) -> Result<(), BridgeError> {
        if let Some(arn) = self.egress_connector_arn.as_deref().filter(|a| !a.trim().is_empty()) {
            if !is_connector_arn(arn) {
                return Err(BridgeError::Config(format!(
                    "[aws].egress_connector_arn = {arn:?}: expected arn:aws:lambda:{REGION}:<12-digit account>:network-connector:<name>[:<version>] (run `make infra-status WRITE=1`)"
                )));
            }
        }
        if let Some(ip) = self.proxy_private_ip.as_deref().filter(|a| !a.trim().is_empty()) {
            if !is_rfc1918(ip) {
                return Err(BridgeError::Config(format!("[aws].proxy_private_ip = {ip:?}: expected an RFC 1918 IPv4 address (10/8, 172.16/12, 192.168/16)")));
            }
        }
        Ok(())
    }
}

/// Where `ai-env vm` gets the runtime principal's AWS credentials
/// (`[aws].credentials`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialsSource {
    /// `credentials/aws.env`, an ai-env container sealed to `[creds].key`,
    /// unsealed in-process (one Touch ID per command).
    Container,
    /// Exactly this profile of `~/.aws/{config,credentials}`.
    Profile(String),
}

impl CredentialsSource {
    /// `"container"` or `"profile:<name>"` (`<name>` of `[A-Za-z0-9_.-]`);
    /// anything else is a config error naming the key.
    pub fn parse(value: &str) -> Result<CredentialsSource, BridgeError> {
        if value == "container" {
            return Ok(CredentialsSource::Container);
        }
        match value.strip_prefix("profile:") {
            Some(name) if !name.is_empty() && name.len() <= 128 && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')) => {
                Ok(CredentialsSource::Profile(name.to_string()))
            }
            _ => Err(BridgeError::Config(format!("[aws].credentials = {value:?}: expected \"container\" or \"profile:<name>\""))),
        }
    }
}

impl VmCfg {
    /// The ranges `ai-env vm`/`lab` need (plan §2.8 timing budgets). Checked by
    /// those commands only, never by [`BridgeConfig::parse`]: the wrapper
    /// routes on a file S1–S3 already accepted.
    pub fn validate(&self) -> Result<(), BridgeError> {
        let bad = |key: &str, why: &str| Err(BridgeError::Config(format!("[vm].{key}: {why}")));
        if self.max_concurrent == 0 {
            return bad("max_concurrent", "must be at least 1");
        }
        if !(1..=28_800).contains(&self.max_duration_s) {
            return bad("max_duration_s", "must be 1..=28800 (the service maximum, 8 h)");
        }
        if !(300..=28_800).contains(&self.max_idle_s) {
            return bad("max_idle_s", "must be 300..=28800 (plan §2.8: suspending sooner costs more than it saves)");
        }
        if self.suspended_s.is_some_and(|s| s == 0 || s > 28_800) {
            return bad("suspended_s", "must be 1..=28800");
        }
        if self.memory_mib == 0 {
            return bad("memory_mib", "must be positive");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AwsCfg {
    pub region: Option<String>,
    pub credentials: String,
    pub image_arn: Option<String>,
    pub image_version: String,
    pub execution_role_arn: Option<String>,
    pub egress_connector_arn: Option<String>,
    pub proxy_private_ip: Option<String>,
    pub budget_name: Option<String>,
}

impl Default for AwsCfg {
    fn default() -> Self {
        AwsCfg {
            region: None,
            credentials: "container".into(),
            image_arn: None,
            image_version: "active".into(),
            execution_role_arn: None,
            egress_connector_arn: None,
            proxy_private_ip: None,
            budget_name: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct VmCfg {
    pub memory_mib: u32,
    pub max_duration_s: u32,
    pub max_idle_s: u32,
    pub suspended_s: Option<u32>,
    pub auto_resume: bool,
    pub reuse_per_workspace: bool,
    pub suspend_on_close: bool,
    pub max_concurrent: u32,
    pub migrate_before_wall_s: u32,
    pub prewarm_on_auth_status: String,
    pub auto_gc: bool,
}

impl Default for VmCfg {
    fn default() -> Self {
        VmCfg {
            memory_mib: 2048,
            max_duration_s: 28_800,
            max_idle_s: 300,
            suspended_s: None,
            auto_resume: true,
            reuse_per_workspace: true,
            suspend_on_close: true,
            max_concurrent: 3,
            migrate_before_wall_s: 1200,
            prewarm_on_auth_status: "auto".into(),
            auto_gc: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WrapperCfg {
    pub local_fallback: bool,
    pub strip_add_dir: bool,
    pub strip_debug: bool,
    pub env_forward: Vec<String>,
    pub env_extra: Vec<String>,
    pub initial_permission_mode: String,
}

impl Default for WrapperCfg {
    fn default() -> Self {
        WrapperCfg {
            local_fallback: true,
            strip_add_dir: true,
            strip_debug: true,
            env_forward: [
                "CLAUDE_CODE_ENTRYPOINT",
                "CLAUDE_AGENT_SDK_VERSION",
                "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
                "MCP_CONNECTION_NONBLOCKING",
                "CLAUDE_CODE_ENABLE_TASKS",
                "LANG",
                "TERM",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            env_extra: Vec::new(),
            initial_permission_mode: "default".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspacesCfg {
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceCfg {
    pub path: PathBuf,
    pub branch: Option<String>,
    pub memory_mib: Option<u32>,
    pub egress_allow: Vec<String>,
    pub seed_allow_dirty: bool,
    pub trust_repo_settings: bool,
}

impl Default for WorkspaceCfg {
    fn default() -> Self {
        WorkspaceCfg {
            path: PathBuf::new(),
            branch: None,
            memory_mib: None,
            egress_allow: Vec::new(),
            seed_allow_dirty: false,
            trust_repo_settings: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CredsCfg {
    pub mode: String,
    pub deliver: String,
    pub key: String,
}

impl Default for CredsCfg {
    fn default() -> Self {
        CredsCfg { mode: "setup-token".into(), deliver: "fd".into(), key: "ai-env-bridge".into() }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EgressCfg {
    pub require: bool,
    pub disable_nonessential: bool,
    /// The operator's recorded acceptance of the platform resolvers they
    /// tested (S5): `egress::credential_gate` passes a `platform-dns:<ip>[,…]`
    /// verdict only when it names these and nothing else; without a resolver
    /// named only `no-dns` passes ([`EgressCfg::accepted_resolvers`]).
    pub accept_platform_dns: AcceptPlatformDns,
}

impl Default for EgressCfg {
    fn default() -> Self {
        EgressCfg { require: true, disable_nonessential: true, accept_platform_dns: AcceptPlatformDns::default() }
    }
}

/// `[egress].accept_platform_dns`: `false` (or absent), the resolver tested
/// (`"fd00:ec2::253"`), or a list of them. `true` (S5's first form) still
/// parses — the wrapper routes on bridge.toml, so the value already written
/// must keep parsing (an older binary cannot read the string form: install
/// before editing) — but names no resolver and so accepts nothing; doctor and
/// every `vm`/`lab`/`egress check` command say so with the line to write. Any
/// other type is a parse error naming the forms.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged, expecting = "a platform resolver address (\"fd00:ec2::253\"), a list of them, or false")]
pub enum AcceptPlatformDns {
    Flag(bool),
    One(String),
    Many(Vec<String>),
}

impl Default for AcceptPlatformDns {
    fn default() -> Self {
        AcceptPlatformDns::Flag(false)
    }
}

/// What the legacy `accept_platform_dns = true` means now, as every message
/// about it starts.
pub const TRUE_ACCEPTS_NOTHING: &str = "[egress].accept_platform_dns = true accepts no resolver (it names none)";

impl EgressCfg {
    /// The entries of `accept_platform_dns` as written (none for either flag).
    fn pinned_entries(&self) -> &[String] {
        match &self.accept_platform_dns {
            AcceptPlatformDns::Flag(_) => &[],
            AcceptPlatformDns::One(s) => std::slice::from_ref(s),
            AcceptPlatformDns::Many(v) => v,
        }
    }

    /// The first entry that is not a platform resolver's address, with why.
    fn bad_entry(&self) -> Option<(&str, &'static str)> {
        self.pinned_entries().iter().find_map(|e| match e.parse::<std::net::IpAddr>() {
            Err(_) => Some((e.as_str(), "not an IP address (name the platform resolver you tested by its address, as `ai-env lab run dns-path` prints it: \"fd00:ec2::253\")")),
            Ok(ip) if !is_platform_ip(&ip) => Some((e.as_str(), "not a platform resolver (a private or link-local IPv4, or fd00:ec2::/32; a public resolver that answers is open DNS, never acceptable)")),
            Ok(_) => None,
        })
    }

    /// The platform resolvers the operator named, parsed (so `FD00:0EC2::0253`
    /// is `fd00:ec2::253`): empty for `false` and for `true`, and empty when
    /// any entry is invalid — a half-applied list must never widen anything.
    #[must_use]
    pub fn accepted_resolvers(&self) -> Vec<std::net::IpAddr> {
        if self.bad_entry().is_some() {
            return Vec::new();
        }
        let mut out: Vec<std::net::IpAddr> = Vec::new();
        for ip in self.pinned_entries().iter().filter_map(|e| e.parse::<std::net::IpAddr>().ok()) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
    }

    /// Every entry an IP address of the platform's class
    /// ([`is_platform_address`]). Checked by `ai-env vm|lab|egress check`
    /// (`vm::cmd::Ctx::load`) and doctor, never by [`BridgeConfig::parse`]: the
    /// wrapper routes on the file. A violation is exit 1 naming the key.
    pub fn validate(&self) -> Result<(), BridgeError> {
        match (self.bad_entry(), &self.accept_platform_dns) {
            (None, _) => Ok(()),
            (Some((e, why)), AcceptPlatformDns::Many(_)) => Err(BridgeError::Config(format!("[egress].accept_platform_dns lists {e:?}: {why}"))),
            (Some((e, why)), _) => Err(BridgeError::Config(format!("[egress].accept_platform_dns = {e:?}: {why}"))),
        }
    }

    /// The legacy `accept_platform_dns = true`: it parses, and accepts nothing.
    #[must_use]
    pub fn names_no_resolver(&self) -> bool {
        self.accept_platform_dns == AcceptPlatformDns::Flag(true)
    }

    /// What the configuration in force accepts, for every message that
    /// explains an acceptance or a refusal (the credential gate, `egress
    /// check` and its `--if-needed` note, `lab run dns-path`, doctor).
    #[must_use]
    pub fn dns_acceptance(&self) -> String {
        if let Some((e, why)) = self.bad_entry() {
            return format!("[egress].accept_platform_dns is invalid and accepts nothing ({e:?}: {why})");
        }
        if self.names_no_resolver() {
            return format!("{TRUE_ACCEPTS_NOTHING}: name the one you tested, accept_platform_dns = \"<ip>\"");
        }
        let accepted = self.accepted_resolvers();
        if accepted.is_empty() {
            return "[egress].accept_platform_dns accepts no platform resolver (only no-dns passes)".to_string();
        }
        format!("[egress].accept_platform_dns accepts only {}", accepted.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
    }
}

/// `[review] tripwires settings_policy` — the two scan lists `box review`,
/// seed and `make image-zip` read. Both default to files under the bridge
/// root, so an empty table is the documented setup.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ReviewCfg {
    pub tripwires: Option<PathBuf>,
    pub settings_policy: Option<PathBuf>,
}

impl ReviewCfg {
    /// `[review].tripwires` | `<root>/tripwires.txt`.
    #[must_use]
    pub fn tripwires_path(&self, paths: &Paths) -> PathBuf {
        self.tripwires.clone().unwrap_or_else(|| paths.root.join("tripwires.txt"))
    }

    /// `[review].settings_policy` | `<root>/settings-policy.txt`.
    #[must_use]
    pub fn settings_policy_path(&self, paths: &Paths) -> PathBuf {
        self.settings_policy.clone().unwrap_or_else(|| paths.root.join("settings-policy.txt"))
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PanelCfg {
    pub port: u16,
    pub enabled: bool,
}

impl Default for PanelCfg {
    fn default() -> Self {
        PanelCfg { port: 7391, enabled: false }
    }
}

/// `[transport]` (S6): how `vm exec` and `vm attach` keep their `/agent` socket.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TransportCfg {
    /// `proactive` (default): 10 min before the endpoint token expires, mint
    /// and open a second socket, then close the first; `lazy`: a new token
    /// only at the next reconnect (safe when probe e1 recorded `survives`).
    pub rotation: Rotation,
    /// `http` (default): a bearer-less `GET /health` every max_idle/3 while a
    /// spawn is attached and unfinished keeps the VM from idling into
    /// suspend; `frames`: pings only (when probe e5 shows frames count).
    pub keepalive: Keepalive,
    /// After the VM was suspended under a client (`event hook_suspend`), how
    /// long it waits for someone to resume the VM — it never resumes one
    /// itself — before exit 8 (10..=3600).
    pub suspend_wait_s: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rotation {
    #[default]
    Proactive,
    Lazy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Keepalive {
    #[default]
    Http,
    Frames,
}

impl Default for TransportCfg {
    fn default() -> Self {
        TransportCfg { rotation: Rotation::Proactive, keepalive: Keepalive::Http, suspend_wait_s: 600 }
    }
}

impl TransportCfg {
    pub fn validate(&self) -> Result<(), BridgeError> {
        if !(10..=3600).contains(&self.suspend_wait_s) {
            return Err(BridgeError::Config(format!("[transport].suspend_wait_s = {} is outside 10..=3600", self.suspend_wait_s)));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeConfig {
    pub aws: AwsCfg,
    pub vm: VmCfg,
    pub wrapper: WrapperCfg,
    pub workspaces: WorkspacesCfg,
    #[serde(rename = "workspace")]
    pub workspace_overrides: Vec<WorkspaceCfg>,
    pub creds: CredsCfg,
    pub egress: EgressCfg,
    pub review: ReviewCfg,
    pub panel: PanelCfg,
    pub transport: TransportCfg,
}

impl BridgeConfig {
    pub fn parse(text: &str) -> Result<Self, BridgeError> {
        let cfg: BridgeConfig = toml::from_str(text).map_err(|e| BridgeError::Config(format!("bridge.toml: {e}")))?;
        if let Some(r) = &cfg.aws.region {
            if r != REGION {
                return Err(BridgeError::Config(format!(
                    "[aws].region = {r:?} but the MicroVM bridge is pinned to {REGION} (eu-west-3 is not supported)"
                )));
            }
        }
        Ok(cfg)
    }

    /// `Ok(None)` when the file does not exist.
    pub fn load(paths: &Paths) -> Result<Option<Self>, BridgeError> {
        match std::fs::read_to_string(&paths.config) {
            Ok(text) => Self::parse(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BridgeError::Config(format!("cannot read {}: {e}", paths.config.display()))),
        }
    }

    /// Every approved workspace root: `[workspaces].roots` followed by each
    /// `[[workspace]].path`, without duplicates, in file order. The pinned
    /// region lives in `bridge::api::region` (the only SDK-typed value), so
    /// this module stays SDK-free for the wrapper binary.
    #[must_use]
    pub fn roots(&self) -> Vec<&Path> {
        let mut out: Vec<&Path> = Vec::new();
        for r in self.workspaces.roots.iter().chain(self.workspace_overrides.iter().map(|w| &w.path)) {
            if !r.as_os_str().is_empty() && !out.contains(&r.as_path()) {
                out.push(r.as_path());
            }
        }
        out
    }

    /// One budget covers running + suspended unless overridden.
    #[must_use]
    pub fn suspended_s(&self) -> u32 {
        self.vm.suspended_s.unwrap_or(self.vm.max_duration_s)
    }

    /// Is `path` under one of the approved workspace roots?
    #[must_use]
    pub fn under_roots(&self, path: &Path) -> bool {
        self.workspaces.roots.iter().any(|r| path.starts_with(r))
    }
}

/// A note when `AWS_REGION`/`AWS_DEFAULT_REGION` disagree with the pin.
#[must_use]
pub fn env_region_warning() -> Option<String> {
    for var in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() && v != REGION {
                return Some(format!("env {var}={v} ignored (region pinned to {REGION})"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_derive_state_dirs() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!(p.config, PathBuf::from("/r/bridge.toml"));
        assert_eq!(p.census(), PathBuf::from("/r/logs/census.jsonl"));
        assert_eq!(p.wrapper_log(), PathBuf::from("/r/logs/wrapper.log"));
        assert_eq!(p.sessions(), PathBuf::from("/r/state/sessions"));
        assert_eq!(p.scratch(), PathBuf::from("/r/state/scratch"));
        assert_eq!(p.audit(), PathBuf::from("/r/audit.jsonl"));
        assert_eq!(p.probes(), PathBuf::from("/r/lab/probes.jsonl"));
        assert_eq!(p.credentials(), PathBuf::from("/r/credentials"));
        assert_eq!(p.aws_env(), PathBuf::from("/r/credentials/aws.env"));
        assert_eq!(p.infra_state(), PathBuf::from("/r/state/infra.toml"));
        assert_eq!(p.egress_lock(), PathBuf::from("/r/state/egress.lock"));
        assert_eq!(p.egress_verified(), PathBuf::from("/r/state/egress-verified.toml"));
    }

    #[test]
    fn connector_arns_of_the_pinned_region_only() {
        for good in [
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress:3",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:A_b-9",
            &format!("arn:aws:lambda:eu-central-1:123456789012:network-connector:{}", "n".repeat(64)),
        ] {
            assert!(is_connector_arn(good), "{good}");
        }
        for bad in [
            "",
            "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS",
            "arn:aws:lambda:eu-west-3:123456789012:network-connector:ai-env-egress",
            "arn:aws:lambda:eu-central-1:12345678901:network-connector:x",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:a.b",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:x:",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:x:v1",
            "arn:aws:lambda:eu-central-1:123456789012:network-connector:x:1:2",
            "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent",
            &format!("arn:aws:lambda:eu-central-1:123456789012:network-connector:{}", "n".repeat(65)),
            " arn:aws:lambda:eu-central-1:123456789012:network-connector:x",
        ] {
            assert!(!is_connector_arn(bad), "{bad}");
        }
    }

    #[test]
    fn egress_keys_are_validated_only_on_request() {
        let ok = BridgeConfig::parse("[aws]\negress_connector_arn = \"arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress:1\"\nproxy_private_ip = \"10.42.0.10\"\n").unwrap();
        ok.aws.validate_egress().unwrap();
        BridgeConfig::parse("[aws]\negress_connector_arn = \"\"\n").unwrap().aws.validate_egress().unwrap();
        let managed = BridgeConfig::parse("[aws]\negress_connector_arn = \"arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS\"\n").unwrap();
        let e = managed.aws.validate_egress().unwrap_err();
        assert!(e.to_string().contains("[aws].egress_connector_arn"), "{e}");
        for ip in ["8.8.8.8", "169.254.169.254", "10.42.0", "010.42.0.10", "fd00::1", "172.32.0.1"] {
            let c = BridgeConfig::parse(&format!("[aws]\nproxy_private_ip = \"{ip}\"\n")).unwrap();
            let e = c.aws.validate_egress().unwrap_err();
            assert!(e.to_string().contains("[aws].proxy_private_ip"), "{ip}: {e}");
        }
        for ip in ["10.0.0.1", "172.16.5.4", "192.168.1.1"] {
            assert!(is_rfc1918(ip), "{ip}");
        }
    }

    /// `[egress].accept_platform_dns`: every form parses (the wrapper routes on the file), only a named platform
    /// resolver is accepted, compared parsed; `true` accepts nothing and says so; an invalid entry is refused only
    /// where it is validated, naming the key, and accepts nothing in the meantime.
    #[test]
    fn the_dns_acceptance_names_the_tested_resolver() {
        let egress = |v: &str| BridgeConfig::parse(&format!("[egress]\naccept_platform_dns = {v}\n")).unwrap().egress;
        let fd00: std::net::IpAddr = "fd00:ec2::253".parse().unwrap();
        // The legacy `true`: parses and validates, accepts nothing, and says what to write instead.
        let legacy = egress("true");
        legacy.validate().unwrap();
        assert!(legacy.names_no_resolver() && legacy.accepted_resolvers().is_empty());
        assert_eq!(legacy.dns_acceptance(), "[egress].accept_platform_dns = true accepts no resolver (it names none): name the one you tested, accept_platform_dns = \"<ip>\"");
        // Absent and false: nothing.
        for cfg in [BridgeConfig::default().egress, BridgeConfig::parse("").unwrap().egress, egress("false"), egress("[]")] {
            cfg.validate().unwrap();
            assert!(!cfg.names_no_resolver() && cfg.accepted_resolvers().is_empty(), "{cfg:?}");
            assert_eq!(cfg.dns_acceptance(), "[egress].accept_platform_dns accepts no platform resolver (only no-dns passes)");
        }
        assert_eq!(BridgeConfig::default().egress.accept_platform_dns, AcceptPlatformDns::Flag(false));
        // The tested resolver, in any spelling IpAddr reads.
        for v in ["\"fd00:ec2::253\"", "\"FD00:0EC2::0253\"", "[\"fd00:ec2::253\"]", "[\"fd00:ec2::253\", \"fd00:0ec2::253\"]"] {
            let cfg = egress(v);
            cfg.validate().unwrap();
            assert_eq!(cfg.accepted_resolvers(), [fd00], "{v}");
            assert_eq!(cfg.dns_acceptance(), "[egress].accept_platform_dns accepts only fd00:ec2::253", "{v}");
        }
        let two = egress("[\"169.254.169.253\", \"fd00:ec2::253\"]");
        two.validate().unwrap();
        assert_eq!(two.accepted_resolvers(), ["169.254.169.253".parse::<std::net::IpAddr>().unwrap(), fd00]);
        assert_eq!(two.dns_acceptance(), "[egress].accept_platform_dns accepts only 169.254.169.253, fd00:ec2::253");
        // Not a platform resolver, not an address, one bad entry in a list: refused naming the key, and nothing accepted.
        for (v, why) in [
            ("\"8.8.8.8\"", "[egress].accept_platform_dns = \"8.8.8.8\": not a platform resolver"),
            ("\"resolver\"", "[egress].accept_platform_dns = \"resolver\": not an IP address"),
            ("\"\"", "[egress].accept_platform_dns = \"\": not an IP address"),
            ("\" fd00:ec2::253\"", "not an IP address"),
            ("\"fd00:ec2::253%eth0\"", "not an IP address"),
            ("[\"fd00:ec2::253\", \"1.1.1.1\"]", "[egress].accept_platform_dns lists \"1.1.1.1\": not a platform resolver"),
        ] {
            let cfg = egress(v);
            let e = cfg.validate().unwrap_err().to_string();
            assert!(e.contains(why) && e.contains("[egress].accept_platform_dns"), "{v}: {e}");
            assert!(cfg.accepted_resolvers().is_empty() && !cfg.names_no_resolver(), "{v}: an invalid pin accepts nothing");
            assert!(cfg.dns_acceptance().starts_with("[egress].accept_platform_dns is invalid and accepts nothing ("), "{v}: {}", cfg.dns_acceptance());
        }
        // A wrong type is a parse error, as for every key, naming the forms.
        for v in ["3", "[1]", "{ ip = \"fd00:ec2::253\" }", "[\"fd00:ec2::253\", true]"] {
            let e = BridgeConfig::parse(&format!("[egress]\naccept_platform_dns = {v}\n")).unwrap_err().to_string();
            assert!(e.contains("a platform resolver address (\"fd00:ec2::253\"), a list of them, or false"), "{v}: {e}");
        }
    }

    #[test]
    fn platform_addresses_are_the_platform_resolvers_class_only() {
        for ip in ["10.42.1.2", "10.42.0.2", "172.16.0.2", "192.168.0.2", "169.254.169.253", "fd00:ec2::253", "FD00:0EC2::0253"] {
            assert!(is_platform_address(ip), "{ip}");
        }
        for ip in ["127.0.0.2", "1.1.1.1", "8.8.8.8", "::1", "fd00:ec3::253", "fd01:ec2::253", "fe80::1", "100.64.0.2", "", "x", "fd00:ec2::253%eth0", "[fd00:ec2::253]", " 10.42.1.2", "010.42.1.2"] {
            assert!(!is_platform_address(ip), "{ip}");
        }
    }

    #[test]
    fn defaults_from_empty() {
        let c = BridgeConfig::parse("").unwrap();
        assert_eq!(c.vm.memory_mib, 2048);
        assert_eq!(c.vm.max_duration_s, 28_800);
        assert_eq!(c.suspended_s(), 28_800);
        assert_eq!(c.creds.key, "ai-env-bridge");
        assert!(c.egress.require);
        assert_eq!(crate::bridge::api::region(&c).as_ref(), "eu-central-1");
    }

    #[test]
    fn region_mismatch_is_error() {
        let e = BridgeConfig::parse("[aws]\nregion = \"eu-west-3\"\n").unwrap_err();
        assert!(e.to_string().contains("pinned to eu-central-1"), "{e}");
        assert!(BridgeConfig::parse("[aws]\nregion = \"eu-central-1\"\n").is_ok());
    }

    #[test]
    fn unknown_key_is_error() {
        assert!(BridgeConfig::parse("[vm]\nmemroy_mib = 4096\n").is_err());
    }

    #[test]
    fn suspended_override_and_workspaces() {
        let c = BridgeConfig::parse(
            "[vm]\nsuspended_s = 600\n[workspaces]\nroots = [\"/Users/mike/Documents/DeFi\"]\n[[workspace]]\npath = \"/Users/mike/Documents/DeFi/ai-env\"\negress_allow = [\"github.com\"]\n",
        )
        .unwrap();
        assert_eq!(c.suspended_s(), 600);
        assert!(c.under_roots(Path::new("/Users/mike/Documents/DeFi/ai-env")));
        assert!(!c.under_roots(Path::new("/tmp/x")));
        assert_eq!(c.workspace_overrides[0].egress_allow, vec!["github.com".to_string()]);
        assert_eq!(c.roots(), vec![Path::new("/Users/mike/Documents/DeFi"), Path::new("/Users/mike/Documents/DeFi/ai-env")], "[[workspace]].path counts as a root");
        let d = BridgeConfig::parse("[workspaces]\nroots = [\"/a\", \"/b\"]\n[[workspace]]\npath = \"/a\"\n[[workspace]]\npath = \"\"\n").unwrap();
        assert_eq!(d.roots(), vec![Path::new("/a"), Path::new("/b")], "deduped, empty path ignored, order kept");
        assert!(BridgeConfig::default().roots().is_empty());
    }

    #[test]
    fn paths_default_and_override() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!(p.config, PathBuf::from("/r/bridge.toml"));
        let q = Paths::from_root_and_env(PathBuf::from("/r"), Some(PathBuf::from("/x/b.toml")));
        assert_eq!(q.config, PathBuf::from("/x/b.toml"));
        assert_eq!(q.logs(), PathBuf::from("/r/logs"));
    }

    #[test]
    fn review_paths_override_and_default() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        let c = BridgeConfig::parse("[review]\ntripwires = \"/x/t.txt\"\n").unwrap();
        assert_eq!(c.review.tripwires, Some(PathBuf::from("/x/t.txt")));
        assert_eq!(c.review.tripwires_path(&p), PathBuf::from("/x/t.txt"));
        assert_eq!(c.review.settings_policy, None);
        assert_eq!(c.review.settings_policy_path(&p), PathBuf::from("/r/settings-policy.txt"));
        let d = BridgeConfig::parse("").unwrap();
        assert_eq!(d.review, ReviewCfg::default());
        assert_eq!(d.review.tripwires_path(&p), PathBuf::from("/r/tripwires.txt"));
        assert_eq!(d.review.settings_policy_path(&p), PathBuf::from("/r/settings-policy.txt"));
        let e = BridgeConfig::parse("[review]\nsettings_policy = \"/x/p.toml\"\n").unwrap();
        assert_eq!(e.review.settings_policy_path(&p), PathBuf::from("/x/p.toml"));
    }

    #[test]
    fn review_pre_push_hook_is_unknown() {
        let e = BridgeConfig::parse("[review]\npre_push_hook = true\n").unwrap_err();
        assert!(e.to_string().contains("pre_push_hook"), "{e}");
    }

    #[test]
    fn load_missing_is_none() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(d.path().to_path_buf(), None);
        assert_eq!(BridgeConfig::load(&p).unwrap(), None);
        std::fs::write(&p.config, "[panel]\nport = 1\n").unwrap();
        assert_eq!(BridgeConfig::load(&p).unwrap().unwrap().panel.port, 1);
    }
}
