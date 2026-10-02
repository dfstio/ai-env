//! The S5 egress allowlist, Mac side: the shared contract every part works
//! from. MicroVMs with `--egress vpc` get the stack's network connector,
//! whose subnet has no route out; the only way out is TCP 3128 to a squid
//! CONNECT allowlist (`infra/egress.ts`, `infra/proxy/*`).
//!
//! Here: the constants of `infra/egress-config.json` (a test keeps both in
//! step), the echo gate's matching rules ([`ExpectedEcho`]: a VM must echo
//! exactly the connectors its egress requires, or it is terminated), the
//! proxy environment ([`proxy_env`]), the hostname and parameter grammar the
//! proxy's reload script enforces too ([`is_valid_host`], [`parse_hosts`],
//! [`parse_extras`]), the squid access-log line ([`parse_squid_line`]), the
//! parameter hashes `ai-env-proxy-reload --status` prints
//! ([`value_sha256`]), the record of passing `ai-env egress check` runs
//! ([`EgressVerified`]), and [`credential_gate`], which S7's credential
//! delivery calls: no credential ever enters a VM that is not on the
//! verified VPC path.
//!
//! The operator commands live in `cli` (`ai-env egress …`, `ai-env proxy
//! …`) and `ops` (the aws CLI calls); `ai-env egress check` in `check`.
pub mod check;
pub mod cli;
pub mod ops;

use crate::bridge::api::managed_connector_arn;
use crate::bridge::config::{is_connector_arn, is_rfc1918, BridgeConfig, Paths};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::{read_infra_state, write_atomic_mode, InfraState};
use crate::bridge::registry::{ensure_private_dir, read_regular_file};
use crate::bridge::vm::registry::VmRow;
use crate::bridge::vm::run::Egress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---- infra/egress-config.json -------------------------------------------------------------

/// The proxy's fixed private address in the proxy subnet.
pub const PROXY_IP: &str = "10.42.0.10";
/// squid's port; the VM security group's only egress rule.
pub const PROXY_PORT: u16 = 3128;
pub const VPC_CIDR: &str = "10.42.0.0/16";
pub const PROXY_SUBNET_CIDR: &str = "10.42.0.0/24";
/// The connector's subnet: route table `local` only.
pub const VM_SUBNET_CIDR: &str = "10.42.1.0/24";
/// The only DNS servers the proxy may reach (UDP/TCP 53); the VMs reach none.
pub const RESOLVERS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];
pub const CONNECTOR_NAME: &str = "ai-env-egress";
/// SSM parameters `<prefix>/{squid.conf,allow,extras,suspended}`.
pub const PARAMETER_PREFIX: &str = "/ai-env/proxy";
/// The squid access log in CloudWatch Logs (the CloudWatch agent ships it).
pub const LOG_GROUP: &str = "/ai-env/egress/squid";
/// The four proxy parameters, in the order `--status` prints their hashes.
pub const PARAMS: [&str; 4] = ["squid.conf", "allow", "extras", "suspended"];
/// Standard-tier SSM parameters hold at most 4 KB; a longer value is refused before any `put-parameter`.
pub const PARAM_MAX_BYTES: usize = 4096;

/// Every key of `infra/egress-config.json` with its value as Rust sees it
/// (numbers and booleans as text, arrays joined with `,`); a unit test reads
/// the JSON and requires both to agree, key for key.
pub const EGRESS_CONSTS: [(&str, &str); 19] = [
    ("vpcCidr", VPC_CIDR),
    ("proxySubnetCidr", PROXY_SUBNET_CIDR),
    ("vmSubnetCidr", VM_SUBNET_CIDR),
    ("azId", "euc1-az1"),
    ("proxyIp", PROXY_IP),
    ("proxyPort", "3128"),
    ("instanceType", "t4g.nano"),
    ("resolvers", "1.1.1.1,9.9.9.9"),
    ("dnsMode", "none"),
    ("enableDnsQueryLog", "false"),
    ("logGroup", LOG_GROUP),
    ("logRetentionDays", "14"),
    ("parameterPrefix", PARAMETER_PREFIX),
    ("connectorName", CONNECTOR_NAME),
    ("proxyRoleName", "ai-env-egress-proxy"),
    ("operatorRoleName", "ai-env-egress-operator"),
    ("proxyInstanceProfileName", "ai-env-egress-proxy"),
    ("vmSecurityGroupName", "ai-env-vm-egress"),
    ("proxySecurityGroupName", "ai-env-proxy"),
];

/// `<prefix>/<param>` (`/ai-env/proxy/allow`).
#[must_use]
pub fn param_name(param: &str) -> String {
    format!("{PARAMETER_PREFIX}/{param}")
}

// ---- connectors and the echo gate ---------------------------------------------------------

/// The managed `INTERNET_EGRESS` connector: what an `internet` VM must echo.
#[must_use]
pub fn internet_egress_arn() -> String {
    managed_connector_arn("INTERNET_EGRESS")
}

/// A connector ARN as the gate compares it: trimmed, and a final all-digit
/// version segment (`:N`) dropped — only after the resource name, so a
/// connector named `123` keeps its name. Anything else is kept as is.
#[must_use]
pub fn normalize_connector(arn: &str) -> String {
    let arn = arn.trim();
    let parts: Vec<&str> = arn.split(':').collect();
    match parts.last() {
        Some(last) if parts.len() >= 8 && !last.is_empty() && last.bytes().all(|c| c.is_ascii_digit()) => parts[..parts.len() - 1].join(":"),
        _ => arn.to_string(),
    }
}

/// The configured connector's Id, from `state/infra.toml` (the live
/// `get-network-connector` read of `ai-env infra status`): the echo may name
/// the connector by Id instead of name. Only trusted when the state's
/// `connector_arn` is the configured connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorAlias {
    /// The configured connector, normalised.
    pub arn: String,
    /// Its Id (`[A-Za-z0-9_-]`, 1–64).
    pub id: String,
}

impl ConnectorAlias {
    /// `Some` when `state` records `connector_id` and its `connector_arn`
    /// equals `configured` (both normalised). An Id that is a managed
    /// connector's name (`INTERNET_EGRESS`, …) or the configured connector's
    /// own name is never an alias. Residual, accepted: a second connector in
    /// the same account NAMED like our Id would match the Id form; creating
    /// one needs the rights to repoint ours anyway (`UpdateNetworkConnector`).
    #[must_use]
    pub fn from_state(state: &InfraState, configured: &str) -> Option<ConnectorAlias> {
        let id = state.connector_id.as_deref()?.trim();
        let recorded = state.connector_arn.as_deref()?;
        let name = normalize_connector(configured).rsplit_once(":network-connector:").map(|(_, n)| n.to_string()).unwrap_or_default();
        let managed = ["HTTP_INGRESS", "SHELL_INGRESS", "INTERNET_EGRESS"].iter().any(|m| id.eq_ignore_ascii_case(m)) || id.to_ascii_lowercase().contains("aws-network-connector");
        let id_ok = (1..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) && !managed && id != name;
        (id_ok && is_connector_arn(configured) && normalize_connector(recorded) == normalize_connector(configured)).then(|| ConnectorAlias { arn: normalize_connector(configured), id: id.to_string() })
    }

    /// [`ConnectorAlias::from_state`] over `state/infra.toml`; `None` when it
    /// is missing or unreadable.
    #[must_use]
    pub fn load(paths: &Paths, configured: &str) -> Option<ConnectorAlias> {
        read_infra_state(paths).ok().flatten().and_then(|s| ConnectorAlias::from_state(&s, configured))
    }

    /// `entry` (normalised) in the alias's name form when it is the Id form
    /// (the bare Id, or the ARN with the Id as its resource name).
    fn resolve(&self, entry: &str) -> Option<String> {
        let prefix = self.arn.rsplit_once(":network-connector:").map(|(p, _)| p)?;
        (entry == self.id || entry == format!("{prefix}:network-connector:{}", self.id)).then(|| self.arn.clone())
    }
}

/// The connectors a VM must echo, exactly: `[INTERNET_EGRESS]` for
/// `internet`, the planned connectors for `vpc` (normalised, sorted, without
/// duplicates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEcho {
    connectors: Vec<String>,
}

impl ExpectedEcho {
    /// For a run of `egress` that sends `planned`; `None` for `vpc` without
    /// a connector (fail closed).
    #[must_use]
    pub fn for_plan(egress: Egress, planned: &[String]) -> Option<ExpectedEcho> {
        let connectors: Vec<String> = match egress {
            Egress::Internet => vec![internet_egress_arn()],
            Egress::Vpc => planned.iter().map(|a| normalize_connector(a)).filter(|a| !a.is_empty()).collect::<BTreeSet<_>>().into_iter().collect(),
        };
        (!connectors.is_empty()).then_some(ExpectedEcho { connectors })
    }

    /// For a VM row: its `egress` (`internet` | `vpc`) and, for `vpc`, its
    /// `egress_connectors`. `None` for a `vpc` row without connectors (a row
    /// written before S5) or an unknown egress: fail closed.
    #[must_use]
    pub fn for_row(row: &VmRow) -> Option<ExpectedEcho> {
        let egress = row.egress.parse::<Egress>().ok()?;
        ExpectedEcho::for_plan(egress, &row.egress_connectors)
    }

    /// The expected connectors (normalised, sorted).
    #[must_use]
    pub fn connectors(&self) -> &[String] {
        &self.connectors
    }

    /// Is `echoed` exactly the expected set? Each entry is normalised and an
    /// Id-form entry of `alias` becomes its name form; an empty echo never
    /// matches (the caller asks `GetMicrovm` first), nor does a missing or an
    /// extra connector.
    #[must_use]
    pub fn matches(&self, echoed: &[String], alias: Option<&ConnectorAlias>) -> bool {
        if echoed.is_empty() {
            return false;
        }
        let got: BTreeSet<String> = echoed
            .iter()
            .map(|e| {
                let n = normalize_connector(e);
                alias.and_then(|a| a.resolve(&n)).unwrap_or(n)
            })
            .collect();
        got.into_iter().eq(self.connectors.iter().cloned())
    }
}

/// [`ExpectedEcho::for_plan`].
#[must_use]
pub fn expected_echo(egress: Egress, planned: &[String]) -> Option<ExpectedEcho> {
    ExpectedEcho::for_plan(egress, planned)
}

/// [`ExpectedEcho::matches`].
#[must_use]
pub fn echo_matches(expected: &ExpectedEcho, echoed: &[String], alias: Option<&ConnectorAlias>) -> bool {
    expected.matches(echoed, alias)
}

// ---- proxy environment --------------------------------------------------------------------

/// `http://<ip>:<port>`.
#[must_use]
pub fn proxy_url(ip: &str, port: u16) -> String {
    format!("http://{ip}:{port}")
}

/// The environment a process in a `vpc` VM needs to reach the allowlist:
/// both spellings of `https_proxy`/`http_proxy` (curl reads `http_proxy` in
/// lowercase only) and `no_proxy` for loopback. S6 sets them at spawn;
/// `ai-env egress env` prints them.
#[must_use]
pub fn proxy_env(ip: &str, port: u16) -> Vec<(&'static str, String)> {
    let url = proxy_url(ip, port);
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    vec![("https_proxy", url.clone()), ("HTTPS_PROXY", url.clone()), ("http_proxy", url.clone()), ("HTTP_PROXY", url), ("no_proxy", no_proxy.clone()), ("NO_PROXY", no_proxy)]
}

/// The proxy address the VMs are told (`egress env`, S6's spawn env) and
/// doctor compares the running proxy with: `[aws].proxy_private_ip`, else
/// `state/infra.toml`'s, else [`PROXY_IP`] — each only when RFC 1918
/// (trimmed); with the source it came from.
#[must_use]
pub fn effective_proxy_ip<'a>(configured: Option<&'a str>, state: Option<&'a InfraState>) -> (&'a str, &'static str) {
    let rfc = |v: Option<&'a str>| v.map(str::trim).filter(|ip| is_rfc1918(ip));
    match (rfc(configured), rfc(state.and_then(|s| s.proxy_private_ip.as_deref()))) {
        (Some(ip), _) => (ip, "[aws].proxy_private_ip"),
        (None, Some(ip)) => (ip, "state/infra.toml"),
        (None, None) => (PROXY_IP, "the default"),
    }
}

// ---- hostnames and parameter lines --------------------------------------------------------

/// A host the proxy may allow: lowercase LDH labels of 1–63 characters (no
/// leading or trailing `-`), at least two labels, at most 253 characters, no
/// trailing dot, and a last label that starts with a letter — so no IP
/// literal in any notation, no wildcard, port, scheme, path or `_`.
/// `infra/proxy/reload.sh` applies the same rule to every parameter line.
#[must_use]
pub fn is_valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    let label_ok = |l: &str| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    labels.len() >= 2 && labels.iter().all(|l| label_ok(l)) && labels.last().is_some_and(|l| l.as_bytes()[0].is_ascii_lowercase())
}

/// What `ai-env egress allow` accepts from the operator: trimmed, one
/// trailing dot dropped, lowercased, then [`is_valid_host`]. `Err` says why.
pub fn normalize_host(input: &str) -> Result<String, String> {
    let t = input.trim_matches(|c: char| c.is_ascii_whitespace());
    let t = t.strip_suffix('.').unwrap_or(t);
    if !t.is_ascii() {
        return Err(format!("{input:?}: not ASCII (use the punycode form, xn--…)"));
    }
    let h = t.to_ascii_lowercase();
    if is_valid_host(&h) {
        Ok(h)
    } else {
        Err(format!("{input:?}: not an exact host name (lowercase letters, digits and dashes in dot-separated labels; no IP literal, wildcard, port, scheme, path or _)"))
    }
}

/// A workspace slug in `extras`: 1–64 of `[A-Za-z0-9._-]`, never `.` or `..`.
#[must_use]
pub fn is_valid_slug(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The line number of the first byte outside printable ASCII, TAB, CR and LF
/// anywhere in `value` (comments included), as `infra/proxy/reload.sh`
/// refuses it (a NUL, a form feed, any non-ASCII byte).
fn bad_byte_line(value: &str) -> Option<usize> {
    value.lines().position(|l| l.bytes().any(|b| !(b == b'\t' || b == b'\r' || (0x20..0x7f).contains(&b)))).map(|i| i + 1)
}

/// The meaningful lines of a parameter value: ASCII whitespace trimmed (as
/// `infra/proxy/reload.sh` does under `LC_ALL=C`), blank lines and `#`
/// comments skipped, each with its 1-based line number. Callers refuse the
/// value first when [`bad_byte_line`] finds a byte the script refuses.
fn lines(value: &str) -> impl Iterator<Item = (usize, &str)> {
    value.lines().enumerate().map(|(i, l)| (i + 1, l.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r'))).filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// `Err` naming the line of the first byte the reload script refuses.
fn printable(value: &str) -> Result<(), String> {
    match bad_byte_line(value) {
        Some(n) => Err(format!("line {n}: a byte outside printable ASCII, TAB, CR and LF")),
        None => Ok(()),
    }
}

/// The hosts of an `allow` or `suspended` value (one per line); `Err` names
/// the first invalid line by number only (a parameter value never reaches an
/// error text, a log or an audit row).
pub fn parse_hosts(value: &str) -> Result<Vec<String>, String> {
    printable(value)?;
    lines(value).map(|(n, l)| if is_valid_host(l) { Ok(l.to_string()) } else { Err(format!("line {n}: not a valid host")) }).collect()
}

/// One `extras` line: a host and the workspaces that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extra {
    pub host: String,
    pub slugs: BTreeSet<String>,
}

/// The `extras` value: `host<TAB>slug[,slug…]` per line. `Err` names the
/// first invalid line (bad host, bad or no slug, a host twice).
pub fn parse_extras(value: &str) -> Result<Vec<Extra>, String> {
    printable(value)?;
    let mut out: Vec<Extra> = Vec::new();
    for (n, l) in lines(value) {
        let Some((host, slugs)) = l.split_once('\t') else {
            return Err(format!("line {n}: not host<TAB>slug[,slug…]"));
        };
        if !is_valid_host(host) {
            return Err(format!("line {n}: not a valid host"));
        }
        let slugs: BTreeSet<String> = slugs.split(',').map(str::to_string).collect();
        if slugs.iter().any(|s| !is_valid_slug(s)) {
            return Err(format!("line {n}: not a list of workspace slugs"));
        }
        if out.iter().any(|e| e.host == host) {
            return Err(format!("line {n}: a host listed twice"));
        }
        out.push(Extra { host: host.to_string(), slugs });
    }
    Ok(out)
}

/// The first line of the `extras` parameter, exactly as `infra/egress.ts`
/// creates it: SSM refuses an empty value, so an empty list is this line alone.
pub const EXTRAS_HEADER: &str = "# ai-env egress extras: host<TAB>slug[,slug...] per line, written by `ai-env egress allow`\n";
/// The first line of the `suspended` parameter, as `infra/egress.ts` creates it.
pub const SUSPENDED_HEADER: &str = "# ai-env egress suspended hosts: one per line, written by `ai-env egress suspend`\n";

/// The `extras` value: [`EXTRAS_HEADER`], then the extras sorted by host
/// (hosts without a slug dropped).
#[must_use]
pub fn render_extras(extras: &[Extra]) -> String {
    let mut sorted: Vec<&Extra> = extras.iter().filter(|e| !e.slugs.is_empty()).collect();
    sorted.sort_by(|a, b| a.host.cmp(&b.host));
    let body: String = sorted.iter().map(|e| format!("{}\t{}\n", e.host, e.slugs.iter().cloned().collect::<Vec<_>>().join(","))).collect();
    format!("{EXTRAS_HEADER}{body}")
}

/// One host per line, sorted, no duplicates (no header).
#[must_use]
pub fn render_hosts(hosts: &[String]) -> String {
    hosts.iter().collect::<BTreeSet<_>>().into_iter().map(|h| format!("{h}\n")).collect()
}

/// The `suspended` value: [`SUSPENDED_HEADER`], then [`render_hosts`].
#[must_use]
pub fn render_suspended(hosts: &[String]) -> String {
    format!("{SUSPENDED_HEADER}{}", render_hosts(hosts))
}

/// Does `value` fit a standard-tier parameter ([`PARAM_MAX_BYTES`])?
#[must_use]
pub fn fits_parameter(value: &str) -> bool {
    value.len() <= PARAM_MAX_BYTES
}

// ---- squid's access log -------------------------------------------------------------------

/// One access-log line of the `aienv` format
/// (`aienv %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %>rd:%>rP`): hosts only,
/// never a path or a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquidLine {
    /// `<unix seconds>.<ms>` as logged.
    pub ts: String,
    pub elapsed_ms: u64,
    /// The client address (`%>a`): a VM's connector ENI.
    pub client: String,
    /// `TCP_TUNNEL`, `TCP_DENIED`, …
    pub code: String,
    pub status: u16,
    pub bytes: u64,
    /// `CONNECT`, `GET`, …
    pub method: String,
    /// The requested host (`-` when squid logged none).
    pub host: String,
    pub port: Option<u16>,
}

/// Parse one line (anything before the `aienv` marker — a CloudWatch or
/// `aws logs tail` prefix — is ignored); `None` for any other line.
#[must_use]
pub fn parse_squid_line(line: &str) -> Option<SquidLine> {
    let start = line.match_indices("aienv ").map(|(i, _)| i).find(|&i| i == 0 || line.as_bytes()[i - 1].is_ascii_whitespace())?;
    let f: Vec<&str> = line[start..].split_whitespace().collect();
    let [_, ts, elapsed, client, code_status, bytes, method, dest] = f.as_slice() else { return None };
    let (code, status) = code_status.split_once('/')?;
    let (host, port) = match dest.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (h, p.parse().ok()),
        _ => (*dest, None),
    };
    Some(SquidLine {
        ts: (*ts).to_string(),
        elapsed_ms: elapsed.parse().ok()?,
        client: (*client).to_string(),
        code: code.to_string(),
        status: status.parse().ok()?,
        bytes: bytes.parse().unwrap_or(0),
        method: (*method).to_string(),
        host: host.to_string(),
        port,
    })
}

// ---- parameter hashes ---------------------------------------------------------------------

/// Hex SHA-256 over a parameter's exact `Value` bytes (the JSON string of
/// `aws ssm get-parameters`, decoded): what `ai-env-proxy-reload --status`
/// prints as `sha256_<param>` and `ai-env egress status` compares.
#[must_use]
pub fn value_sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The golden vectors both sides assert (`egress::tests` and
/// `tests/proxy_docker.rs`): a value and its [`value_sha256`].
pub const GOLDEN: [(&str, &str); 2] = [
    ("api.anthropic.com\nplatform.claude.com\n", "2df4d969a180eafe40445c26b5c439ca4ca81dd005a80eb037684d7690f40afd"),
    ("github.com\tai-env,other-ws\n", "75850efa8e6afa06e89f536a9a5a6b46c053661d50d9b3d1aa72b0f17c418588"),
];

/// The one line `ai-env-proxy-reload --status` prints, as `key=value`
/// pairs (`squid=active allowed=4 … sha256_allow=<hex> … parse=ok`); `Err`
/// for a token without `=`, an empty or odd key, or a key twice.
pub fn parse_reload_status(line: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for tok in line.split_whitespace() {
        let (k, v) = tok.split_once('=').ok_or_else(|| format!("reload --status: {tok:?} is not key=value"))?;
        if k.is_empty() || !k.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.')) {
            return Err(format!("reload --status: bad key {k:?}"));
        }
        if out.insert(k.to_string(), v.to_string()).is_some() {
            return Err(format!("reload --status: {k} twice"));
        }
    }
    if out.is_empty() {
        return Err("reload --status printed nothing".into());
    }
    Ok(out)
}

// ---- passing `egress check` runs ----------------------------------------------------------

/// The configured connector as a live `lambda-core get-network-connector`
/// answered: what a passing check is bound to. A recreated connector (same
/// name, same ARN) has another Id; an `UpdateNetworkConnector` that changes
/// what the VMs' traffic meets (subnets, security groups, the protocol)
/// changes these facts, as it bumps a `Version` when the answer carries one;
/// either way an earlier pass no longer applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectorFacts {
    pub id: String,
    /// `Version` as answered (a number, kept as text); empty when the answer
    /// carries none (measured 1 Oct 2026: the connector Pulumi created
    /// answers without one, unlike the CLI model).
    pub version: String,
    /// `Configuration.VpcEgressConfiguration.NetworkProtocol` (`IPv4`): a
    /// switch to dual stack must void a pass.
    pub network_protocol: String,
    /// `Configuration.VpcEgressConfiguration.SubnetIds`, sorted.
    pub subnet_ids: Vec<String>,
    /// `Configuration.VpcEgressConfiguration.SecurityGroupIds`, sorted.
    pub security_group_ids: Vec<String>,
}

impl ConnectorFacts {
    /// The facts of a `get-network-connector` answer; `None` when any is
    /// missing or malformed (a non-string id or protocol, no subnet, no
    /// security group, a `Version` that is neither a number nor text), or the
    /// connector is not ACTIVE or has an update that did not succeed
    /// (`LastUpdateStatus` other than `Successful`: the configuration answered
    /// may not be the one in force). A missing or null `Version` is empty.
    #[must_use]
    pub fn from_get(doc: &serde_json::Value) -> Option<ConnectorFacts> {
        if doc.get("State").and_then(serde_json::Value::as_str) != Some("ACTIVE") {
            return None;
        }
        match doc.get("LastUpdateStatus") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(s)) if s == "Successful" => {}
            Some(_) => return None,
        }
        let id = doc.get("Id")?.as_str()?.trim().to_string();
        let version = match doc.get("Version") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(serde_json::Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            Some(_) => return None,
        };
        let vpc = doc.get("Configuration")?.get("VpcEgressConfiguration")?;
        let list = |k: &str| -> Option<Vec<String>> {
            let mut v: Vec<String> = vpc.get(k)?.as_array()?.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<_>>()?;
            v.sort();
            (!v.is_empty()).then_some(v)
        };
        let network_protocol = vpc.get("NetworkProtocol")?.as_str()?.trim().to_string();
        let facts = ConnectorFacts { id, version, network_protocol, subnet_ids: list("SubnetIds")?, security_group_ids: list("SecurityGroupIds")? };
        facts.complete().then_some(facts)
    }

    /// Every fact a pass is bound to present (`version` may be empty: the
    /// service does not always answer one).
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.id.is_empty() && !self.network_protocol.is_empty() && !self.subnet_ids.is_empty() && !self.security_group_ids.is_empty()
    }
}

/// One passing `ai-env egress check`: valid for exactly this image, image
/// version and connector — a new version or another connector needs a new
/// check — and bound to the connector's live facts and the image version's
/// creation time, so a recreated connector or a rebuilt version of the same
/// number never inherits it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VerifiedRecord {
    pub image_arn: String,
    /// The version the VM echoed.
    pub image_version: String,
    /// The connector, normalised ([`normalize_connector`]).
    pub connector: String,
    pub vm_id: String,
    /// RFC 3339 UTC.
    pub at: String,
    /// One line: every case with its verdict.
    pub cases: String,
    /// The DNS verdict of the run (`no-dns` | `platform-dns:<ip>`).
    pub dns: String,
    /// What the squid-log cross-check found.
    pub squid_log: String,
    /// The VM-independent network verification the check ran before
    /// recording (route table, security groups, NACL, VPC, connector, the
    /// proxy's parameters): one line. The case markers are VM-reported; this
    /// and the squid log are not.
    pub network: String,
    /// The configured connector's live facts when the check ran.
    pub connector_facts: ConnectorFacts,
    /// The image version's `created_at` (`ListMicrovmImageVersions`, Unix
    /// seconds) when the check ran.
    pub image_created_at: Option<i64>,
}

/// `state/egress-verified.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressVerified {
    pub records: Vec<VerifiedRecord>,
    /// Normalised connector → the last time (Unix seconds) a failing check
    /// revoked its records: a pass from a check that started before that is
    /// never recorded.
    pub revocations: BTreeMap<String, u64>,
}

impl EgressVerified {
    /// The file, or an empty set when it does not exist. A symlink, a
    /// non-regular file or a file that does not parse is an error.
    pub fn load(paths: &Paths) -> Result<EgressVerified, BridgeError> {
        let path = paths.egress_verified();
        match read_regular_file(&path)? {
            None => Ok(EgressVerified::default()),
            Some(text) => toml::from_str(&text).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.message()))),
        }
    }

    /// Write the file atomically, 0600, in a 0700 `state/`.
    pub fn save(&self, paths: &Paths) -> Result<(), BridgeError> {
        let path = paths.egress_verified();
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        let body = toml::to_string_pretty(self).map_err(|e| BridgeError::Config(format!("{}: {e}", path.display())))?;
        write_atomic_mode(&path, format!("# Written by `ai-env egress check` (passing runs only); read by the S5 credential gate.\n{body}").as_bytes(), 0o600)
    }

    /// The record of (image, version, connector), the connector compared normalised.
    #[must_use]
    pub fn find(&self, image_arn: &str, image_version: &str, connector: &str) -> Option<&VerifiedRecord> {
        let c = normalize_connector(connector);
        self.records.iter().find(|r| r.image_arn == image_arn && r.image_version == image_version && r.connector == c)
    }

    /// Remove every record of `connector` (normalised), whatever its image:
    /// the network is shared, so a failing check of any image revokes them
    /// all; remember `at_unix` so no pass of a check that started earlier is
    /// recorded later. Returns how many were removed.
    pub fn revoke_connector(&mut self, connector: &str, at_unix: u64) -> usize {
        let c = normalize_connector(connector);
        let before = self.records.len();
        self.records.retain(|r| r.connector != c);
        let last = self.revocations.entry(c).or_default();
        *last = (*last).max(at_unix);
        before - self.records.len()
    }

    /// Add `rec` (its connector normalised), replacing the record of the same
    /// key — unless the check started (`started_unix`) at or before the
    /// connector's last revocation: then nothing is recorded (`false`).
    pub fn record(&mut self, mut rec: VerifiedRecord, started_unix: u64) -> bool {
        rec.connector = normalize_connector(&rec.connector);
        if self.revocations.get(&rec.connector).is_some_and(|&at| started_unix <= at) {
            return false;
        }
        self.records.retain(|r| !(r.image_arn == rec.image_arn && r.image_version == rec.image_version && r.connector == rec.connector));
        self.records.push(rec);
        true
    }

    /// Load, apply `f`, save — under `flock(state/egress-verified.toml.lock)`,
    /// so a record and a revocation never undo each other.
    pub fn update<T>(paths: &Paths, f: impl FnOnce(&mut EgressVerified) -> T) -> Result<T, BridgeError> {
        let path = paths.egress_verified();
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        let mut name = path.file_name().map(std::ffi::OsStr::to_os_string).unwrap_or_default();
        name.push(".lock");
        let _guard = crate::bridge::vm::lock::lock_blocking(&path.with_file_name(name))?;
        let mut v = EgressVerified::load(paths)?;
        let out = f(&mut v);
        v.save(paths)?;
        Ok(out)
    }
}

// ---- the credential gate ------------------------------------------------------------------

/// The `dns-path` probe's verdict when no name resolves from a `vpc` VM.
pub const DNS_NONE: &str = "no-dns";
/// The prefix of the verdict when the platform's resolver answers (`platform-dns:<ip>`).
pub const DNS_PLATFORM_PREFIX: &str = "platform-dns:";

/// Does `verdict` let credentials in? `no-dns` always; `platform-dns:<ip>`
/// only with the operator's recorded acceptance AND a platform address
/// (an RFC 1918 or link-local IPv4, or the VPC's IPv6 `fd00:ec2::/32`): a
/// public resolver that answers is open DNS, never acceptable; anything else
/// never.
#[must_use]
pub fn dns_verdict_ok(verdict: &str, accept_platform_dns: bool) -> bool {
    let platform = |ip: &str| match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_private() || a.is_link_local(),
        Ok(std::net::IpAddr::V6(a)) => a.segments()[0] == 0xfd00 && a.segments()[1] == 0x0ec2,
        Err(_) => false,
    };
    verdict == DNS_NONE || (accept_platform_dns && verdict.strip_prefix(DNS_PLATFORM_PREFIX).is_some_and(platform))
}

/// The newest `dns-path` row of `lab/probes.jsonl` through
/// [`dns_verdict_ok`] with `[egress].accept_platform_dns`; false when there
/// is none or the file cannot be read (fail closed).
#[must_use]
pub fn dns_ok(paths: &Paths, cfg: &BridgeConfig) -> bool {
    let Ok(rows) = crate::bridge::census::read_rows(&paths.probes(), None) else { return false };
    rows.iter().rev().find(|r| r.get("probe").and_then(|p| p.as_str()) == Some("dns-path")).and_then(|r| r.get("verdict").and_then(|v| v.as_str())).is_some_and(|v| dns_verdict_ok(v, cfg.egress.accept_platform_dns))
}

/// What the credential gate compares with, read live by its caller (S7) just
/// before delivery: the VM's egress as `GetMicrovm` reports it, the
/// configured connector's Id alias ([`ConnectorAlias::load`]) when known, the
/// connector's facts from a `lambda-core get-network-connector` made now, and
/// the VM's image version's `created_at` from `ListMicrovmImageVersions`.
#[derive(Debug, Clone, Copy)]
pub struct LiveEcho<'a> {
    pub connectors: &'a [String],
    pub alias: Option<&'a ConnectorAlias>,
    pub connector: Option<&'a ConnectorFacts>,
    pub image_created_at: Option<i64>,
}

/// May a credential enter the VM of `row` (S7 calls this before any
/// delivery)? Only when all hold: a valid `[aws].egress_connector_arn` is
/// configured; the row's egress is `vpc` (credentials never enter an
/// `internet` VM); the live echo is exactly that connector; a passing
/// `ai-env egress check` is recorded for the row's image, image version and
/// that connector, for the same live connector facts (Id, Version when
/// answered, network protocol, subnet, security group) and the same image build (`created_at`); its DNS verdict
/// and `dns_ok` ([`dns_ok`]) pass. `Err(Policy)` (exit 9) names the first
/// condition that failed and what to run.
pub fn credential_gate(cfg: &BridgeConfig, row: &VmRow, live: &LiveEcho<'_>, verified: &EgressVerified, dns_ok: bool) -> Result<(), BridgeError> {
    let refuse = |why: String| Err(BridgeError::Policy(format!("no credential for {}: {why}", if row.id.is_empty() { "this VM" } else { &row.id })));
    let Some(configured) = cfg.aws.egress_connector_arn.as_deref().map(str::trim).filter(|a| !a.is_empty()) else {
        return refuse("[aws].egress_connector_arn is not set (run `make infra-status WRITE=1`)".into());
    };
    if !is_connector_arn(configured) {
        return refuse(format!("[aws].egress_connector_arn {configured:?} is not a connector ARN"));
    }
    if row.egress != Egress::Vpc.as_str() {
        return refuse(format!("its egress is {:?}, not vpc: credentials never enter a VM with internet egress", row.egress));
    }
    let expected = ExpectedEcho::for_plan(Egress::Vpc, &[configured.to_string()]).expect("a configured connector");
    if !expected.matches(live.connectors, live.alias) {
        let got = if live.connectors.is_empty() { "nothing".to_string() } else { live.connectors.join(", ") };
        return refuse(format!("GetMicrovm echoes egress {got}, not exactly {configured}"));
    }
    let Some(record) = verified.find(&row.image_arn, &row.image_version, configured) else {
        return refuse(format!("no passing `ai-env egress check` is recorded for image version {} with {configured} (run `ai-env egress check`)", row.image_version));
    };
    match live.connector {
        Some(now) if now.complete() && record.connector_facts.complete() && *now == record.connector_facts => {}
        Some(_) => return refuse(format!("{configured} is not the connector the recorded check verified (its Id, Version, network protocol, subnet or security group changed): run `ai-env egress check`")),
        None => return refuse("the connector's live facts were not read (get-network-connector)".into()),
    }
    if record.image_created_at.is_none() || live.image_created_at != record.image_created_at {
        return refuse(format!("image version {} is not the build the recorded check verified (created_at differs or unknown): run `ai-env egress check`", row.image_version));
    }
    if !dns_verdict_ok(&record.dns, cfg.egress.accept_platform_dns) {
        return refuse(format!("the recorded `ai-env egress check` saw DNS {:?} (run `ai-env egress check` again; [egress].accept_platform_dns covers only a platform resolver)", record.dns));
    }
    if !dns_ok {
        return refuse(format!("the newest dns-path verdict is not {DNS_NONE} and [egress].accept_platform_dns is false (run `ai-env lab run dns-path`)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONN: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn the_constants_match_infra_egress_config_json() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/egress-config.json");
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let obj = doc.as_object().unwrap();
        for (k, want) in EGRESS_CONSTS {
            let v = obj.get(k).unwrap_or_else(|| panic!("{k} missing from {}", path.display()));
            let got = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(a) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>().join(","),
                other => other.to_string(),
            };
            assert_eq!(got, want, "{k}");
        }
        assert_eq!(obj.len(), EGRESS_CONSTS.len(), "every key of egress-config.json has a Rust constant");
        assert_eq!(RESOLVERS.join(","), EGRESS_CONSTS.iter().find(|(k, _)| *k == "resolvers").unwrap().1);
        assert_eq!(PROXY_PORT.to_string(), "3128");
        // One scalar key per line: the Makefile reads it with sed.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().filter(|l| l.trim_start().starts_with('"')).count(), EGRESS_CONSTS.len());
        assert_eq!(param_name("allow"), "/ai-env/proxy/allow");
    }

    #[test]
    fn normalisation_drops_only_a_trailing_version() {
        assert_eq!(normalize_connector(&format!("{CONN}:3")), CONN);
        assert_eq!(normalize_connector(&format!(" {CONN} ")), CONN);
        assert_eq!(normalize_connector(CONN), CONN);
        let numeric = "arn:aws:lambda:eu-central-1:123456789012:network-connector:123";
        assert_eq!(normalize_connector(numeric), numeric, "a name of digits is a name");
        assert_eq!(normalize_connector(&internet_egress_arn()), internet_egress_arn());
        assert_eq!(normalize_connector(&format!("{}:1", internet_egress_arn())), internet_egress_arn());
        assert_eq!(normalize_connector(&format!("{CONN}:v2")), format!("{CONN}:v2"), "only digits are a version");
    }

    #[test]
    fn the_echo_must_be_exactly_the_expected_connectors() {
        let vpc = ExpectedEcho::for_plan(Egress::Vpc, &s(&[CONN])).unwrap();
        assert!(vpc.matches(&s(&[CONN]), None));
        assert!(vpc.matches(&s(&[&format!("{CONN}:7")]), None), ":N stripped");
        assert!(vpc.matches(&s(&[CONN, &format!("{CONN}:1")]), None), "the same connector twice");
        assert!(!vpc.matches(&[internet_egress_arn()], None), "INTERNET_EGRESS instead");
        assert!(!vpc.matches(&s(&[CONN, &internet_egress_arn()]), None), "an extra connector");
        assert!(!vpc.matches(&[], None), "an empty echo never matches");
        assert!(!vpc.matches(&s(&["arn:aws:lambda:eu-central-1:123456789012:network-connector:other"]), None));
        let internet = ExpectedEcho::for_plan(Egress::Internet, &[]).unwrap();
        assert_eq!(internet.connectors(), [internet_egress_arn()]);
        assert!(internet.matches(&[internet_egress_arn()], None));
        assert!(!internet.matches(&s(&[CONN]), None));
        assert!(!internet.matches(&[internet_egress_arn(), CONN.to_string()], None));
        assert!(ExpectedEcho::for_plan(Egress::Vpc, &[]).is_none(), "vpc without a connector fails closed");
        assert_eq!(expected_echo(Egress::Vpc, &s(&[CONN])), Some(vpc.clone()));
        assert!(echo_matches(&vpc, &s(&[CONN]), None));
    }

    #[test]
    fn the_id_form_counts_only_through_a_matching_alias() {
        let vpc = ExpectedEcho::for_plan(Egress::Vpc, &s(&[CONN])).unwrap();
        let id_arn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0a1b2c3d";
        assert!(!vpc.matches(&s(&[id_arn]), None), "no alias: the Id form is another connector");
        let mut state = InfraState { connector_arn: Some(format!("{CONN}:2")), connector_id: Some("nc-0a1b2c3d".into()), ..InfraState::default() };
        let alias = ConnectorAlias::from_state(&state, CONN).unwrap();
        assert_eq!(alias, ConnectorAlias { arn: CONN.to_string(), id: "nc-0a1b2c3d".into() });
        assert!(vpc.matches(&s(&[id_arn]), Some(&alias)));
        assert!(vpc.matches(&s(&[&format!("{id_arn}:2")]), Some(&alias)));
        assert!(vpc.matches(&s(&["nc-0a1b2c3d"]), Some(&alias)), "the bare Id");
        assert!(!vpc.matches(&s(&["arn:aws:lambda:eu-central-1:999999999999:network-connector:nc-0a1b2c3d"]), Some(&alias)), "another account");
        state.connector_arn = Some("arn:aws:lambda:eu-central-1:123456789012:network-connector:other".into());
        assert!(ConnectorAlias::from_state(&state, CONN).is_none(), "the state is of another connector");
        state.connector_arn = Some(CONN.into());
        state.connector_id = Some("bad id".into());
        assert!(ConnectorAlias::from_state(&state, CONN).is_none());
        state.connector_id = None;
        assert!(ConnectorAlias::from_state(&state, CONN).is_none());
        for bad in ["INTERNET_EGRESS", "shell_ingress", "aws-network-connector", "ai-env-egress"] {
            state.connector_id = Some(bad.into());
            assert!(ConnectorAlias::from_state(&state, CONN).is_none(), "{bad}: a managed name or our own name is never an alias");
        }
    }

    #[test]
    fn rows_expect_by_egress_and_legacy_vpc_rows_fail_closed() {
        let internet = VmRow { egress: "internet".into(), ..VmRow::default() };
        assert_eq!(ExpectedEcho::for_row(&internet).unwrap().connectors(), [internet_egress_arn()]);
        let vpc = VmRow { egress: "vpc".into(), egress_connectors: s(&[CONN]), ..VmRow::default() };
        assert_eq!(ExpectedEcho::for_row(&vpc).unwrap().connectors(), [CONN]);
        let legacy = VmRow { egress: "vpc".into(), ..VmRow::default() };
        assert!(ExpectedEcho::for_row(&legacy).is_none());
        assert!(ExpectedEcho::for_row(&VmRow::default()).is_none(), "no egress recorded");
    }

    #[test]
    fn proxy_env_has_both_spellings() {
        let env = proxy_env(PROXY_IP, PROXY_PORT);
        let get = |k: &str| env.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str());
        for k in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
            assert_eq!(get(k), Some("http://10.42.0.10:3128"), "{k}");
        }
        assert_eq!(get("no_proxy"), Some("localhost,127.0.0.1,::1"));
        assert_eq!(get("NO_PROXY"), Some("localhost,127.0.0.1,::1"));
        let state = InfraState { proxy_private_ip: Some("10.42.0.11".into()), ..InfraState::default() };
        assert_eq!(effective_proxy_ip(None, None), (PROXY_IP, "the default"));
        assert_eq!(effective_proxy_ip(None, Some(&state)), ("10.42.0.11", "state/infra.toml"));
        assert_eq!(effective_proxy_ip(Some(" 192.168.1.5 "), Some(&state)), ("192.168.1.5", "[aws].proxy_private_ip"));
        let public = InfraState { proxy_private_ip: Some("8.8.8.8".into()), ..InfraState::default() };
        assert_eq!(effective_proxy_ip(Some("8.8.4.4"), Some(&public)), (PROXY_IP, "the default"), "never a public address");
    }

    #[test]
    fn hostnames() {
        for good in ["api.anthropic.com", "static.crates.io", "a.b", "xn--bcher-kva.example", "a-b.c1.io", &format!("{}.com", "a".repeat(63))] {
            assert!(is_valid_host(good), "{good}");
        }
        for bad in [
            "",
            "localhost",
            "1.2.3.4",
            "10.42.0.10",
            "0x7f.1",
            "example.123",
            "*.example.com",
            ".example.com",
            "example.com.",
            "example.com:443",
            "https://example.com",
            "example.com/x",
            "a_b.example.com",
            "-a.example.com",
            "a-.example.com",
            "Example.com",
            "a..b",
            "[::1]",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}com", "a.".repeat(126)),
        ] {
            assert!(!is_valid_host(bad), "{bad}");
        }
        assert_eq!(normalize_host(" GitHub.COM. ").unwrap(), "github.com");
        assert!(normalize_host("bücher.example").unwrap_err().contains("punycode"));
        assert!(normalize_host("1.2.3.4").is_err());
        assert!(normalize_host("example.com..").is_err());
        assert!(normalize_host("example.com\u{a0}").is_err(), "no Unicode trimming");
        for good in ["ai-env", "a.b_c-1", &"x".repeat(64)] {
            assert!(is_valid_slug(good), "{good}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "a,b", &"x".repeat(65)] {
            assert!(!is_valid_slug(bad), "{bad}");
        }
    }

    #[test]
    fn parameter_lines() {
        assert_eq!(parse_hosts("# base\napi.anthropic.com\n\n  static.crates.io  \n").unwrap(), s(&["api.anthropic.com", "static.crates.io"]));
        assert!(parse_hosts("api.anthropic.com\n1.2.3.4\n").unwrap_err().starts_with("line 2:"));
        // The same bytes the reload script refuses: a NUL, a non-ASCII space (no Unicode trimming).
        for bad in ["api.anthrop\0ic.com\n", "api.anthropic.com\u{a0}\n", "api.anthropic.com\u{85}\n", "\u{2003}api.anthropic.com\n"] {
            assert!(parse_hosts(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_hosts(" api.anthropic.com\t\r\n").unwrap(), s(&["api.anthropic.com"]), "spaces, TABs and CRLF are trimmed");
        for bad in ["# caf\u{e9}\napi.anthropic.com\n", "api.anthropic.com\x0c\n", "api.anthropic.com\x0b\n", "#\0\n"] {
            assert!(parse_hosts(bad).unwrap_err().ends_with("a byte outside printable ASCII, TAB, CR and LF"), "{bad:?}: as the reload script, comments included");
            assert!(parse_extras(bad).is_err(), "{bad:?}");
        }
        let ex = parse_extras("github.com\tai-env,other\n# c\nobjects.githubusercontent.com\tai-env\n").unwrap();
        assert_eq!(ex.len(), 2);
        assert_eq!(ex[0].slugs.iter().cloned().collect::<Vec<_>>(), s(&["ai-env", "other"]));
        for bad in ["github.com\n", "github.com\t\n", "github.com\tbad/slug\n", "x\tai-env\n", "github.com\ta\ngithub.com\tb\n", "github.com\ta,,b\n"] {
            let e = parse_extras(bad).unwrap_err();
            assert!(e.starts_with("line ") && !e.contains("github") && !e.contains("slug\"") && !e.contains("bad/"), "no value in the error: {e}");
        }
        assert!(!parse_hosts("evil.example\n1.2.3.4\n").unwrap_err().contains("1.2.3.4"));
        let rendered = render_extras(&[
            Extra { host: "z.example".into(), slugs: ["b".to_string(), "a".to_string()].into() },
            Extra { host: "gone.example".into(), slugs: BTreeSet::new() },
            Extra { host: "a.example".into(), slugs: ["w".to_string()].into() },
        ]);
        assert_eq!(rendered, format!("{EXTRAS_HEADER}a.example\tw\nz.example\ta,b\n"));
        assert_eq!(parse_extras(&rendered).unwrap().len(), 2, "round trip");
        assert_eq!(render_extras(&[]), EXTRAS_HEADER, "never an empty value (SSM refuses one)");
        assert!(parse_extras(EXTRAS_HEADER).unwrap().is_empty());
        assert_eq!(render_hosts(&s(&["b.io", "a.io", "b.io"])), "a.io\nb.io\n");
        assert_eq!(render_suspended(&[]), SUSPENDED_HEADER);
        assert_eq!(parse_hosts(&render_suspended(&s(&["x.io"]))).unwrap(), s(&["x.io"]));
        // The same bytes `infra/egress.ts` creates the parameters with: removing the last entry restores them.
        let ts = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/egress.ts")).unwrap();
        for header in [EXTRAS_HEADER, SUSPENDED_HEADER] {
            let literal = format!("\"{}\\n\"", header.trim_end_matches('\n'));
            assert!(ts.contains(&literal), "infra/egress.ts does not create a parameter with {literal}");
        }
        assert!(fits_parameter(&"x".repeat(PARAM_MAX_BYTES)));
        assert!(!fits_parameter(&"x".repeat(PARAM_MAX_BYTES + 1)));
    }

    #[test]
    fn squid_lines() {
        let l = parse_squid_line("aienv 1790000000.123     42 10.42.1.17 TCP_TUNNEL/200 3456 CONNECT api.anthropic.com:443").unwrap();
        assert_eq!(
            l,
            SquidLine {
                ts: "1790000000.123".into(),
                elapsed_ms: 42,
                client: "10.42.1.17".into(),
                code: "TCP_TUNNEL".into(),
                status: 200,
                bytes: 3456,
                method: "CONNECT".into(),
                host: "api.anthropic.com".into(),
                port: Some(443)
            }
        );
        let denied = parse_squid_line("2026-10-01T10:00:00.000Z i-0abc aienv 1790000000.001 0 10.42.1.17 TCP_DENIED/403 3900 CONNECT example.com:443").unwrap();
        assert_eq!((denied.code.as_str(), denied.status, denied.host.as_str()), ("TCP_DENIED", 403, "example.com"));
        let get = parse_squid_line("aienv 1790000000.001 0 10.42.1.17 TCP_DENIED/403 3900 GET example.com:8080").unwrap();
        assert_eq!((get.method.as_str(), get.port), ("GET", Some(8080)));
        let v6 = parse_squid_line("aienv 1.000 0 10.42.1.17 TCP_DENIED/403 0 CONNECT [2606:4700::1111]:443").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("[2606:4700::1111]", Some(443)));
        let none = parse_squid_line("aienv 1.000 0 10.42.1.17 NONE_NONE/400 0 NONE -").unwrap();
        assert_eq!((none.host.as_str(), none.port), ("-", None));
        for bad in ["", "noise", "xaienv 1.0 0 a B/1 0 C d:1", "aienv 1.0 0 a TCP_TUNNEL 0 CONNECT h:443", "aienv 1.0 x a T/200 0 CONNECT h:443", "aienv 1.0 0 a T/200 0 CONNECT h:443 extra"] {
            assert!(parse_squid_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn golden_hashes_and_the_status_line() {
        for (value, hex) in GOLDEN {
            assert_eq!(value_sha256(value), hex, "{value:?}");
        }
        let st = parse_reload_status("squid=active allowed=4 extras=1 suspended=0 sha256_squid.conf=ab sha256_allow=cd sha256_extras=ef sha256_suspended=01 parse=ok").unwrap();
        assert_eq!(st["squid"], "active");
        assert_eq!(st["sha256_squid.conf"], "ab");
        assert_eq!(st.len(), 9);
        for bad in ["", "squid", "a=1 a=2", "Bad=1", "=x"] {
            assert!(parse_reload_status(bad).is_err(), "{bad:?}");
        }
    }

    fn facts() -> ConnectorFacts {
        ConnectorFacts { id: "nc-1".into(), version: "1".into(), network_protocol: "IPv4".into(), subnet_ids: s(&["subnet-0aaa1111bbbb2222c"]), security_group_ids: s(&["sg-0ddd3333eeee4444f"]) }
    }

    fn rec(version: &str, connector: &str) -> VerifiedRecord {
        VerifiedRecord {
            image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            image_version: version.into(),
            connector: connector.into(),
            vm_id: "microvm-1".into(),
            at: "2026-10-01T10:00:00Z".into(),
            dns: DNS_NONE.into(),
            connector_facts: facts(),
            image_created_at: Some(1_790_000_000),
            ..VerifiedRecord::default()
        }
    }

    #[test]
    fn connector_facts_from_the_golden_answer() {
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/egress/lambda-core.get-network-connector.json")).unwrap()).unwrap();
        let f = ConnectorFacts::from_get(&doc).unwrap();
        assert_eq!(f, ConnectorFacts { id: "nc-0a1b2c3d4e5f60718".into(), version: "1".into(), network_protocol: "IPv4".into(), subnet_ids: s(&["subnet-0aaa1111bbbb2222c"]), security_group_ids: s(&["sg-0ddd3333eeee4444f"]) });
        assert!(f.complete());
        let mut broken = doc.clone();
        broken["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] = serde_json::json!([]);
        assert!(ConnectorFacts::from_get(&broken).is_none(), "no subnet");
        let mut no_id = doc.clone();
        no_id["Id"] = serde_json::json!("");
        assert!(ConnectorFacts::from_get(&no_id).is_none());
        for (k, v) in [("NetworkProtocol", serde_json::json!("")), ("NetworkProtocol", serde_json::json!(4)), ("NetworkProtocol", serde_json::Value::Null)] {
            let mut bad = doc.clone();
            bad["Configuration"]["VpcEgressConfiguration"][k] = v.clone();
            assert!(ConnectorFacts::from_get(&bad).is_none(), "{k}={v}");
        }
        let mut text_version = doc.clone();
        text_version["Version"] = serde_json::json!("7");
        assert_eq!(ConnectorFacts::from_get(&text_version).unwrap().version, "7");
        let mut odd_version = doc.clone();
        odd_version["Version"] = serde_json::json!({"n": 1});
        assert!(ConnectorFacts::from_get(&odd_version).is_none(), "a Version that is neither a number nor text");
        // Only an ACTIVE connector whose last update (if any) succeeded: the configuration answered is the one in force.
        for (k, v) in [("State", serde_json::json!("PENDING")), ("State", serde_json::json!("FAILED")), ("State", serde_json::Value::Null), ("LastUpdateStatus", serde_json::json!("InProgress")), ("LastUpdateStatus", serde_json::json!("Failed"))] {
            let mut not_in_force = doc.clone();
            not_in_force[k] = v.clone();
            assert!(ConnectorFacts::from_get(&not_in_force).is_none(), "{k}={v}");
        }
        let mut no_update = doc.clone();
        no_update.as_object_mut().unwrap().remove("LastUpdateStatus");
        assert!(ConnectorFacts::from_get(&no_update).is_some(), "no update yet");
        // As measured live (1 Oct 2026): no Version at all, the ARN in the Id form; a null one reads the same.
        let mut live = doc;
        live.as_object_mut().unwrap().remove("Version");
        live["Arn"] = serde_json::json!("arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-0a1b2c3d4e5f60718");
        let f = ConnectorFacts::from_get(&live).unwrap();
        assert_eq!((f.version.as_str(), f.network_protocol.as_str(), f.complete()), ("", "IPv4", true));
        live["Version"] = serde_json::Value::Null;
        assert_eq!(ConnectorFacts::from_get(&live).unwrap(), f);
    }

    #[test]
    fn verified_records_round_trip_and_key_on_image_version_and_connector() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().join("bridge"), None);
        assert_eq!(EgressVerified::load(&paths).unwrap(), EgressVerified::default());
        let mut v = EgressVerified::default();
        assert!(v.record(rec("2.0", &format!("{CONN}:1")), 100));
        assert!(v.record(rec("2.0", CONN), 100));
        assert_eq!(v.records.len(), 1, "the same key replaces");
        v.save(&paths).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(paths.egress_verified()).unwrap().permissions().mode() & 0o777, 0o600);
        let back = EgressVerified::load(&paths).unwrap();
        assert_eq!(back, v);
        assert!(back.find(crate::bridge::api::FAKE_IMAGE_ARN, "2.0", &format!("{CONN}:4")).is_some());
        assert!(back.find(crate::bridge::api::FAKE_IMAGE_ARN, "3.0", CONN).is_none(), "a new image version needs a new check");
        assert!(back.find(crate::bridge::api::FAKE_IMAGE_ARN, "2.0", "arn:aws:lambda:eu-central-1:123456789012:network-connector:other").is_none());
        std::fs::write(paths.egress_verified(), "records = 3").unwrap();
        assert!(EgressVerified::load(&paths).is_err());
        let mut v = EgressVerified::default();
        v.record(rec("2.0", CONN), 100);
        v.record(rec("3.0", &format!("{CONN}:2")), 100);
        v.record(rec("3.0", "arn:aws:lambda:eu-central-1:123456789012:network-connector:other"), 100);
        assert_eq!(v.revoke_connector(&format!("{CONN}:9"), 200), 2, "every image of the connector");
        assert_eq!(v.records.len(), 1);
        assert_eq!(v.revoke_connector(CONN, 150), 0);
        assert_eq!(v.revocations[CONN], 200, "the latest revocation is kept");
        assert!(!v.record(rec("2.0", CONN), 199), "a check that started before the revocation records nothing");
        assert!(!v.record(rec("2.0", CONN), 200));
        assert!(v.record(rec("2.0", CONN), 201));
    }

    #[test]
    fn locked_updates_never_undo_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().join("bridge"), None);
        EgressVerified::update(&paths, |v| v.record(rec("1.0", CONN), 100)).unwrap();
        std::thread::scope(|sc| {
            for i in 0..8u64 {
                let paths = &paths;
                sc.spawn(move || {
                    EgressVerified::update(paths, |v| {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        v.record(rec(&format!("{}.0", i + 2), CONN), 100)
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(EgressVerified::load(&paths).unwrap().records.len(), 9, "every writer's record survives");
        assert_eq!(EgressVerified::update(&paths, |v| v.revoke_connector(CONN, 300)).unwrap(), 9);
        assert!(EgressVerified::load(&paths).unwrap().records.is_empty());
    }

    #[test]
    fn dns_verdicts() {
        assert!(dns_verdict_ok("no-dns", false));
        assert!(!dns_verdict_ok("platform-dns:10.42.1.2", false));
        assert!(dns_verdict_ok("platform-dns:10.42.1.2", true));
        assert!(dns_verdict_ok("platform-dns:169.254.169.253", true));
        assert!(dns_verdict_ok("platform-dns:fd00:ec2::253", true));
        assert!(!dns_verdict_ok("platform-dns:9.9.9.9", true), "a public resolver that answers is open DNS");
        assert!(!dns_verdict_ok("platform-dns:2620:fe::fe", true));
        assert!(!dns_verdict_ok("platform-dns:resolver", true));
        assert!(!dns_verdict_ok("platform-dns:", true));
        assert!(!dns_verdict_ok("unknown", true));
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let cfg = BridgeConfig::default();
        assert!(!dns_ok(&paths, &cfg), "no row: closed");
        std::fs::create_dir_all(paths.probes().parent().unwrap()).unwrap();
        let row = |v: &str| format!("{{\"probe\":\"dns-path\",\"stage\":\"S5\",\"ext\":null,\"sdk\":null,\"verdict\":\"{v}\",\"expected\":\"no-dns\",\"ts\":\"2026-10-01T10:00:00Z\"}}\n");
        std::fs::write(paths.probes(), format!("{}{}", row("platform-dns:10.42.1.2"), row("no-dns"))).unwrap();
        assert!(dns_ok(&paths, &cfg), "the newest row decides");
        std::fs::write(paths.probes(), format!("{}{}", row("no-dns"), row("platform-dns:10.42.1.2"))).unwrap();
        assert!(!dns_ok(&paths, &cfg));
        let accepting = BridgeConfig::parse("[egress]\naccept_platform_dns = true\n").unwrap();
        assert!(dns_ok(&paths, &accepting));
    }

    #[test]
    fn the_credential_gate_needs_every_condition() {
        let cfg = BridgeConfig::parse(&format!("[aws]\negress_connector_arn = \"{CONN}:1\"\n")).unwrap();
        let row = VmRow { id: "microvm-1".into(), egress: "vpc".into(), egress_connectors: s(&[CONN]), image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(), image_version: "2.0".into(), ..VmRow::default() };
        let mut verified = EgressVerified::default();
        verified.record(rec("2.0", CONN), 100);
        let echo = s(&[CONN]);
        let now = facts();
        let live = LiveEcho { connectors: &echo, alias: None, connector: Some(&now), image_created_at: Some(1_790_000_000) };
        credential_gate(&cfg, &row, &live, &verified, true).unwrap();
        let why = |r: Result<(), BridgeError>| match r {
            Err(BridgeError::Policy(m)) => m,
            other => panic!("expected a policy refusal, got {other:?}"),
        };
        assert!(why(credential_gate(&BridgeConfig::default(), &row, &live, &verified, true)).contains("egress_connector_arn is not set"));
        let internet_row = VmRow { egress: "internet".into(), ..row.clone() };
        assert!(why(credential_gate(&cfg, &internet_row, &live, &verified, true)).contains("never enter a VM with internet egress"));
        let open = [internet_egress_arn()];
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { connectors: &open, ..live }, &verified, true)).contains("not exactly"));
        let both = [internet_egress_arn(), CONN.to_string()];
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { connectors: &both, ..live }, &verified, true)).contains("not exactly"));
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { connectors: &[], ..live }, &verified, true)).contains("echoes egress nothing"));
        let newer = VmRow { image_version: "3.0".into(), ..row.clone() };
        assert!(why(credential_gate(&cfg, &newer, &live, &verified, true)).contains("run `ai-env egress check`"));
        assert!(why(credential_gate(&cfg, &row, &live, &EgressVerified::default(), true)).contains("run `ai-env egress check`"));
        assert!(why(credential_gate(&cfg, &row, &live, &verified, false)).contains("dns-path"));
        let mut leaky = EgressVerified::default();
        leaky.record(VerifiedRecord { dns: "platform-dns:9.9.9.9".into(), ..rec("2.0", CONN) }, 100);
        assert!(why(credential_gate(&cfg, &row, &live, &leaky, true)).contains("saw DNS"), "the check's own DNS verdict counts too");
        // Bound to the connector's live facts: a recreated connector (another Id), an update (Version, also one appearing
        // where none was answered), dual stack, another subnet or SG.
        for changed in [
            ConnectorFacts { id: "nc-2".into(), ..facts() },
            ConnectorFacts { version: "2".into(), ..facts() },
            ConnectorFacts { version: String::new(), ..facts() },
            ConnectorFacts { network_protocol: "DualStack".into(), ..facts() },
            ConnectorFacts { subnet_ids: s(&["subnet-0bbb"]), ..facts() },
            ConnectorFacts { security_group_ids: s(&["sg-0bbb", "sg-0ddd3333eeee4444f"]), ..facts() },
            ConnectorFacts::default(),
        ] {
            assert!(why(credential_gate(&cfg, &row, &LiveEcho { connector: Some(&changed), ..live }, &verified, true)).contains("is not the connector the recorded check verified"), "{changed:?}");
        }
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { connector: None, ..live }, &verified, true)).contains("live facts were not read"));
        let mut unbound = EgressVerified::default();
        unbound.record(VerifiedRecord { connector_facts: ConnectorFacts::default(), ..rec("2.0", CONN) }, 100);
        assert!(why(credential_gate(&cfg, &row, &live, &unbound, true)).contains("is not the connector"), "a record without facts binds nothing");
        // Bound to the image build: a rebuilt version of the same number (destroy + redeploy) or an unknown created_at.
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { image_created_at: Some(1_790_000_001), ..live }, &verified, true)).contains("is not the build"));
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { image_created_at: None, ..live }, &verified, true)).contains("is not the build"));
        let mut no_build = EgressVerified::default();
        no_build.record(VerifiedRecord { image_created_at: None, ..rec("2.0", CONN) }, 100);
        assert!(why(credential_gate(&cfg, &row, &LiveEcho { image_created_at: None, ..live }, &no_build, true)).contains("is not the build"));
        let bad_cfg = BridgeConfig::parse("[aws]\negress_connector_arn = \"arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:INTERNET_EGRESS\"\n").unwrap();
        assert!(why(credential_gate(&bad_cfg, &row, &LiveEcho { connectors: &open, ..live }, &verified, true)).contains("not a connector ARN"));
        let id_echo = s(&["arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-1"]);
        let alias = ConnectorAlias { arn: CONN.into(), id: "nc-1".into() };
        credential_gate(&cfg, &row, &LiveEcho { connectors: &id_echo, alias: Some(&alias), ..live }, &verified, true).unwrap();
        assert!(credential_gate(&cfg, &row, &LiveEcho { connectors: &id_echo, alias: None, ..live }, &verified, true).is_err());
        // As measured live (1 Oct 2026): the connector's ARN is in the Id form and its answer carries no Version.
        let id_conn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:nc-f0b942fe-0612-44a7-9183-16942c532410";
        let id_cfg = BridgeConfig::parse(&format!("[aws]\negress_connector_arn = \"{id_conn}\"\n")).unwrap();
        let id_row = VmRow { egress_connectors: s(&[id_conn]), ..row.clone() };
        let no_version = ConnectorFacts { version: String::new(), ..facts() };
        let mut measured = EgressVerified::default();
        measured.record(VerifiedRecord { connector_facts: no_version.clone(), ..rec("2.0", id_conn) }, 100);
        let id_live = s(&[id_conn]);
        credential_gate(&id_cfg, &id_row, &LiveEcho { connectors: &id_live, alias: None, connector: Some(&no_version), ..live }, &measured, true).unwrap();
    }
}
