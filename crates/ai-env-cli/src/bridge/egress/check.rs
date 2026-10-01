//! `ai-env egress check` (S5, T5.2–T5.4): from a `--egress vpc --shell` VM,
//! through the platform shell, prove direct egress and DNS closed and the
//! allowlist working; verify the network and squid's log independently of
//! the VM; record a pass in `state/egress-verified.toml` for the credential
//! gate, and revoke every earlier pass of the connector when a check of its
//! own VM fails.
//!
//! **What the record rests on.** The case results are reported by the VM
//! itself (a compromised image could print anything), so they are never
//! the evidence on their own. A pass also needs, from outside the VM: the
//! network verification — every check of `ai-env egress status` (connector,
//! ENIs, the VM subnet's route table and NACL, the security groups, the
//! VPC's DNS attributes, DHCP options, endpoints, NAT and peering, the proxy
//! and its parameters, the stack's hashes, `applied=yes`) `ok`, none drifted
//! or unknown — and squid's own log in CloudWatch, from the VM subnet within
//! the script's window: the run's two `allowed` tunnels and a `TCP_DENIED`
//! line for every request the proxy had to refuse, and no tunnel to any of
//! those hosts ([`squid_evidence`]). Only a VM the check started itself
//! (purpose `test`, label `egress-check`, no workspace) can record; `--vm`
//! is report-only (it never records and never revokes). A record is bound
//! to what the credential gate reads live again: the connector's facts
//! (Id, Version, subnet, security group: `get-network-connector` as the
//! operator) and the image version's `created_at`; without them nothing is
//! recorded. It is refused when a failing check revoked the connector after
//! this check began.
//!
//! **Revocation.** Once a check has asked for its own VM, any failure but
//! Ctrl-C revokes every record of the connector (all images) and is audited
//! `egress_check {id, image_version, verdict=fail, reason, revoked}`: a
//! failing case, the network or squid's log, a missing binding, and also a
//! failure before the transcript is judged — the VM's start or its egress
//! gate, `/health`, the shell token or dial, the fake's refusal. A failure
//! before that (the configuration, the operator's account, the backend)
//! revokes nothing.
//!
//! The script ([`render_script`]) is rendered on the Mac, the proxy exports
//! of [`proxy_env`] included (the VM's `ai-env` has no `egress` command),
//! and sent once through the scripted shell (`vm::shell::run_script`) after
//! the VM's `/health` answered; it ends with `exit`. It drops aliases and
//! shell functions, calls `command curl -q` (no `.curlrc`) and `command dig
//! -r` (no `.digrc`), and each case prints one marker line,
//! `@@AIENV<nonce> <case> rc=… code=… size=… conn=… hc=… t403=… sq=…`
//! (curl: exit code, HTTP code, body size with `-o /dev/null`, connects
//! made, the proxy's CONNECT answer, whether curl said [`CONNECT_403`],
//! whether squid's `X-Squid-Error: ERR_ACCESS_DENIED` came) or `… rc=… ns=…
//! res=…` (dig: exit code, server, whether an address came back) — never a
//! body, header value, token or IMDS answer. Markers are built at run time
//! (`printf '%s%s …' '@@' "$R"`), so the shell's echo of the script never
//! parses as one ([`parse_markers`]). The transcript itself is never
//! printed, logged or persisted. [`judge`] is pure; `allowed` runs first and
//! last, and the direct, DNS and other-port cases count only when both
//! passed, so a VM whose networking is dead (or died midway) cannot pass. A
//! direct case is closed only when curl made no connection at all.
//! [`decide`] turns the evidence into the verdict, the record and the
//! revocation.
//!
//! Exit codes: 0 pass; 9 any judged failure (every one named), and also
//! under the file-backed fake, which cannot carry a shell
//! (`vm::shell::fake_backend_refusal`: the VM the check started is
//! terminated first); a failure before the judgement keeps its own class (7
//! AWS, 8 the VM lost, 9 the egress gate); 1 a configuration problem (no
//! connector, a `--vm` whose row is not a `vpc` + `--shell` VM that passed
//! the egress gate, the aws CLI's credentials of another account); 3 Ctrl-C
//! (the check's VM is terminated; nothing recorded or revoked).
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState};
use crate::bridge::awscli;
use crate::bridge::config::{is_rfc1918, BridgeConfig, Paths};
use crate::bridge::egress::{normalize_connector, parse_squid_line, proxy_env, ConnectorFacts, EgressVerified, SquidLine, VerifiedRecord, LOG_GROUP, PROXY_IP, PROXY_PORT, VM_SUBNET_CIDR, VPC_CIDR};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::read_infra_state;
use crate::bridge::probes::{is_platform_resolver, verdict_dns_path, DnsReply};
use crate::bridge::transport::ShellAuth;
use crate::bridge::vm::cmd::{audit_event, backend, runtime, with_backend, Backend, Ctx};
use crate::bridge::vm::registry::{self, RowStatus, VmRow, GATE_PASSED};
use crate::bridge::vm::{health, run, shell};
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::time::{rfc3339_utc, unix_now};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

// ---- the cases --------------------------------------------------------------------------------

/// Every marker line starts with this, then the run's nonce.
const MARK: &str = "@@AIENV";
/// The name every DNS case asks for (it has an address record).
pub const DNS_NAME: &str = "example.com";
/// What curl prints when the proxy refuses a CONNECT with 403. Its exit code
/// changed (56 up to curl 8.19, 7 from 8.20); the text did not.
pub const CONNECT_403: &str = "CONNECT tunnel failed, response 403";
/// Each case's share of the script budget: curl's `--max-time 10` (dig's
/// `+time=2 +tries=1` is shorter) and slack.
pub const CASE_BUDGET: Duration = Duration::from_secs(12);
/// The check's own VM: `vm run --egress vpc --shell --max-duration 900`.
pub const CHECK_MAX_DURATION_S: u32 = 900;
/// How long squid's log may take to reach CloudWatch (the agent ships every
/// few seconds); polled every [`SQUID_LOG_STEP`]. Scaled by the lab's poll knob.
pub const SQUID_LOG_BUDGET: Duration = Duration::from_secs(120);
pub const SQUID_LOG_STEP: Duration = Duration::from_secs(5);
/// How far squid's clock and the Mac's may differ: the log window is widened by it.
pub const CLOCK_SKEW_S: u64 = 60;
/// Debug builds, under the file-backed fake only: a file that stands in for
/// the shell's transcript (its markers' nonce is the run's), so process tests
/// reach the judgement, the network verification, squid's log and the record.
pub const FAKE_SHELL_KNOB: &str = "AI_ENV_BRIDGE_LAB_FAKE_SHELL";

/// How a case is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// curl without the proxy to the internet: closed only when curl made no
    /// connection (`num_connects` 0), nothing answered (HTTP 000) and it gave
    /// up connecting (rc 6, 7 or 28).
    Direct,
    /// curl without the proxy to another port of the proxy host: closed only
    /// on a connect timeout without a connection (rc 28: the security group
    /// drops it; a refusal would mean the packet reached the host).
    OtherPort,
    /// dig (see [`DnsServer`]).
    Dns(DnsServer),
    /// Recorded, never judged (IMDS).
    Recorded,
    /// Through the proxy, an allowlisted host: the tunnel opened (the proxy's
    /// CONNECT answer 200) and the API answered 401 (no API key).
    Allowed,
    /// Through the proxy, a CONNECT squid must refuse: the proxy's CONNECT
    /// answer 403 and curl's [`CONNECT_403`].
    Connect403,
    /// Through the proxy, a plain-http request squid must refuse: HTTP 403
    /// with squid's `X-Squid-Error: ERR_ACCESS_DENIED`.
    Get403,
}

/// Who a DNS case asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsServer {
    /// A public resolver: it must not reply at all (any reply is an open path).
    Public,
    /// `/etc/resolv.conf`'s first nameserver: judged as a platform resolver
    /// when its address is one (`probes::is_platform_resolver`), else as public.
    ResolvConf,
    /// The platform's resolvers (link-local, `fd00:ec2::253`, the VPC's and
    /// the subnet's +2): they must not resolve the name; a reply that
    /// resolves nothing (DNS Firewall) is noted, and the dns-path probe
    /// records it.
    Platform,
}

/// One case of the script.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    pub name: &'static str,
    /// `direct` | `dns` | `other` | `proxy`.
    pub group: &'static str,
    kind: Kind,
    /// What is asked, for the reasons.
    pub what: &'static str,
    /// The script arguments after the case name: curl options and URL, or
    /// dig's server and options. `@P@` is the proxy address, `@V@` the VPC's
    /// +2, `@S@` the VM subnet's +2, `@H@` the run's denied host.
    args: &'static str,
}

impl Case {
    fn proxied(&self) -> bool {
        matches!(self.kind, Kind::Allowed | Kind::Connect403 | Kind::Get403)
    }

    fn is_dns(&self) -> bool {
        matches!(self.kind, Kind::Dns(_))
    }

    /// Counted only when the run's `allowed` cases passed (non-vacuous).
    fn needs_allowed(&self) -> bool {
        matches!(self.kind, Kind::Direct | Kind::OtherPort | Kind::Dns(_))
    }
}

/// The two liveness cases: the VM reaches the proxy before everything else
/// and after it.
pub const ALLOWED_CASES: [&str; 2] = ["allowed", "allowed-last"];

/// The cases, in script order. The proxy exports come right before the
/// first case (`allowed`); `allowed-last` closes the run.
pub const CASES: [Case; 27] = [
    Case { name: "allowed", group: "proxy", kind: Kind::Allowed, what: "api.anthropic.com through the proxy (first)", args: "https://api.anthropic.com/v1/models" },
    Case { name: "direct-name", group: "direct", kind: Kind::Direct, what: "api.anthropic.com without the proxy", args: "--noproxy '*' https://api.anthropic.com/v1/models" },
    Case { name: "direct-ipv4", group: "direct", kind: Kind::Direct, what: "1.1.1.1:443 without the proxy", args: "--noproxy '*' https://1.1.1.1/" },
    Case { name: "direct-http", group: "direct", kind: Kind::Direct, what: "1.1.1.1:80 without the proxy", args: "--noproxy '*' http://1.1.1.1/" },
    Case { name: "direct-ipv6", group: "direct", kind: Kind::Direct, what: "[2606:4700:4700::1111] without the proxy", args: "--noproxy '*' -g https://[2606:4700:4700::1111]/" },
    Case { name: "dns-public-udp", group: "dns", kind: Kind::Dns(DnsServer::Public), what: "dig @1.1.1.1", args: "1.1.1.1" },
    Case { name: "dns-public-tcp", group: "dns", kind: Kind::Dns(DnsServer::Public), what: "dig +tcp @1.1.1.1", args: "1.1.1.1 +tcp" },
    Case { name: "dns-public-port", group: "dns", kind: Kind::Dns(DnsServer::Public), what: "dig -p 443 @208.67.222.222 (UDP 443; OpenDNS answers there)", args: "208.67.222.222 -p 443" },
    Case { name: "dns-resolv-udp", group: "dns", kind: Kind::Dns(DnsServer::ResolvConf), what: "dig @<resolv.conf nameserver>", args: "\"$S\"" },
    Case { name: "dns-resolv-tcp", group: "dns", kind: Kind::Dns(DnsServer::ResolvConf), what: "dig +tcp @<resolv.conf nameserver>", args: "\"$S\" +tcp" },
    Case { name: "dns-platform-udp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig @169.254.169.253", args: "169.254.169.253" },
    Case { name: "dns-platform-tcp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig +tcp @169.254.169.253", args: "169.254.169.253 +tcp" },
    Case { name: "dns-platform6-udp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig @fd00:ec2::253", args: "fd00:ec2::253" },
    Case { name: "dns-platform6-tcp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig +tcp @fd00:ec2::253", args: "fd00:ec2::253 +tcp" },
    Case { name: "dns-vpc-udp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig @<the VPC's +2>", args: "@V@" },
    Case { name: "dns-vpc-tcp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig +tcp @<the VPC's +2>", args: "@V@ +tcp" },
    Case { name: "dns-subnet-udp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig @<the VM subnet's +2>", args: "@S@" },
    Case { name: "dns-subnet-tcp", group: "dns", kind: Kind::Dns(DnsServer::Platform), what: "dig +tcp @<the VM subnet's +2>", args: "@S@ +tcp" },
    Case { name: "proxy-other-port", group: "other", kind: Kind::OtherPort, what: "the proxy host on port 22, not 3128", args: "--noproxy '*' http://@P@:22/" },
    Case { name: "imds", group: "other", kind: Kind::Recorded, what: "IMDS (169.254.169.254)", args: "--noproxy '*' http://169.254.169.254/latest/meta-data/" },
    Case { name: "imds-v6", group: "other", kind: Kind::Recorded, what: "IMDS over IPv6 ([fd00:ec2::254])", args: "--noproxy '*' -g http://[fd00:ec2::254]/latest/meta-data/" },
    Case { name: "proxy-ip-literal", group: "proxy", kind: Kind::Connect403, what: "1.1.1.1 through the proxy", args: "https://1.1.1.1/" },
    Case { name: "proxy-http-8080", group: "proxy", kind: Kind::Get403, what: "plain http to api.anthropic.com:8080 through the proxy", args: "http://api.anthropic.com:8080/" },
    Case { name: "proxy-connect-8443", group: "proxy", kind: Kind::Connect403, what: "CONNECT api.anthropic.com:8443 through the proxy", args: "https://api.anthropic.com:8443/" },
    Case { name: "proxy-github", group: "proxy", kind: Kind::Connect403, what: "github.com through the proxy", args: "https://github.com/" },
    Case { name: "denied", group: "proxy", kind: Kind::Connect403, what: "the run's nonce host through the proxy", args: "https://@H@/" },
    Case { name: "allowed-last", group: "proxy", kind: Kind::Allowed, what: "api.anthropic.com through the proxy (last)", args: "https://api.anthropic.com/v1/models" },
];

/// The cases of the dns-path probe: every resolver the check asks over UDP
/// and TCP (the public one too: a reply there is `open-dns`), between the
/// two `allowed` cases (the VM's networking must work throughout, or
/// `no-dns` proves nothing).
pub const DNS_PATH_CASES: [&str; 15] = [
    "allowed",
    "dns-public-udp",
    "dns-public-tcp",
    "dns-public-port",
    "dns-resolv-udp",
    "dns-resolv-tcp",
    "dns-platform-udp",
    "dns-platform-tcp",
    "dns-platform6-udp",
    "dns-platform6-tcp",
    "dns-vpc-udp",
    "dns-vpc-tcp",
    "dns-subnet-udp",
    "dns-subnet-tcp",
    "allowed-last",
];

fn case(name: &str) -> Option<&'static Case> {
    CASES.iter().find(|c| c.name == name)
}

/// The whole script's budget: [`CASE_BUDGET`] per case, plus 30 s.
#[must_use]
pub fn script_budget(cases: usize) -> Duration {
    CASE_BUDGET * u32::try_from(cases).unwrap_or(u32::MAX) + Duration::from_secs(30)
}

// ---- the script -------------------------------------------------------------------------------

/// A fresh run nonce: 16 lowercase hex digits from the OS random source.
#[must_use]
pub fn new_nonce() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("getrandom: the OS random source failed");
    hex::encode(b)
}

/// 8–32 lowercase hex digits.
fn is_nonce(s: &str) -> bool {
    (8..=32).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The host the `denied` case asks the proxy for: it carries the run's
/// nonce, so its squid log line belongs to this run exactly.
#[must_use]
pub fn denied_host(nonce: &str) -> String {
    format!("n{nonce}.example.com")
}

/// The network address of `cidr` plus two (`10.42.1.0/24` → `10.42.1.2`).
#[must_use]
pub fn cidr_plus_two(cidr: &str) -> Option<String> {
    let (ip, bits) = cidr.split_once('/')?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 30)?;
    let base = u32::from(ip.parse::<std::net::Ipv4Addr>().ok()?) & (u32::MAX << (32 - bits));
    Some(std::net::Ipv4Addr::from(base + 2).to_string())
}

/// Is `ip` an IPv4 address inside `cidr`?
#[must_use]
pub fn in_cidr(ip: &str, cidr: &str) -> bool {
    let (Some((net, bits)), Ok(addr)) = (cidr.split_once('/'), ip.parse::<std::net::Ipv4Addr>()) else { return false };
    let (Ok(net), Ok(bits)) = (net.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>()) else { return false };
    let mask = if bits == 0 { 0 } else if bits >= 32 { u32::MAX } else { u32::MAX << (32 - bits) };
    u32::from(addr) & mask == u32::from(net) & mask
}

/// The proxy address the script exports: `[aws].proxy_private_ip`, else
/// `state/infra.toml`'s, else [`PROXY_IP`] (RFC 1918 values only).
#[must_use]
pub fn proxy_ip(cfg: &BridgeConfig, paths: &Paths) -> String {
    let rfc = |v: Option<&str>| v.map(str::trim).filter(|ip| is_rfc1918(ip)).map(str::to_string);
    let state = read_infra_state(paths).ok().flatten();
    rfc(cfg.aws.proxy_private_ip.as_deref()).or_else(|| rfc(state.as_ref().and_then(|s| s.proxy_private_ip.as_deref()))).unwrap_or_else(|| PROXY_IP.to_string())
}

/// The shell helpers: `aienv_c NAME CURL-ARGS…` and `aienv_d NAME SERVER
/// [DIG-OPTS…]` each run one case and print its marker; nothing else they
/// see is printed (squid's error header is reduced to yes/no in the VM).
/// `R` is `AIENV<nonce>`, `S` the first resolv.conf nameserver.
const HELPERS: [&str; 2] = [
    r#"aienv_c() { local n=$1 e rc o=000 s=0 c=- h=000 t=no q=no; shift; e=$(command curl -q -sS -o /dev/null -w 'W=%{http_code},%{size_download},%{num_connects},%{http_connect}=W X=%header{x-squid-error}=X' --connect-timeout 5 --max-time 10 "$@" 2>&1 </dev/null); rc=$?; [[ $e =~ W=([0-9]+),([0-9]+),([0-9]+),([0-9]+)=W ]] && o=${BASH_REMATCH[1]} s=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} h=${BASH_REMATCH[4]}; [[ $e == *'CONNECT tunnel failed, response 403'* ]] && t=yes; [[ $e == *'X=ERR_ACCESS_DENIED'* ]] && q=yes; printf '%s%s %s rc=%s code=%s size=%s conn=%s hc=%s t403=%s sq=%s\n' '@@' "$R" "$n" "$rc" "$o" "$s" "$c" "$h" "$t" "$q"; }"#,
    r#"aienv_d() { local n=$1 s=$2 o rc r=no l; shift 2; if [ -z "$s" ]; then printf '%s%s %s rc=none ns=none res=no\n' '@@' "$R" "$n"; return; fi; o=$(command dig -r +short +time=2 +tries=1 "$@" "@$s" example.com A 2>&1 </dev/null); rc=$?; while IFS= read -r l; do [[ $l =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && r=yes; done <<<"$o"; printf '%s%s %s rc=%s ns=%s res=%s\n' '@@' "$R" "$n" "$rc" "$s" "$r"; }"#,
];

/// The script of `cases` for one run: no alias, no function named like a
/// tool it calls, a fresh command hash, no history file, no `!` expansion;
/// `R` and `S`; the helpers; one short line per case (the proxy exports
/// before the first proxied case); the `end` marker; `exit`. No tab, no
/// `!`, under 4 KB (a terminal's line buffer).
fn render(nonce: &str, proxy_ip: &str, cases: &[&Case]) -> String {
    let fill = |args: &str| {
        args.replace("@P@", proxy_ip).replace("@V@", &cidr_plus_two(VPC_CIDR).unwrap_or_default()).replace("@S@", &cidr_plus_two(VM_SUBNET_CIDR).unwrap_or_default()).replace("@H@", &denied_host(nonce))
    };
    let mut lines = vec![
        r"\unalias -a; unset -f command curl dig printf 2>/dev/null; hash -r; unset HISTFILE; set +H".to_string(),
        format!(r#"R={MARK_BODY}{nonce}; S=; while read -r k v x; do [ "$k" = nameserver ] && [ -z "$S" ] && S=$v; done 2>/dev/null </etc/resolv.conf"#, MARK_BODY = &MARK[2..]),
    ];
    lines.extend(HELPERS.iter().map(|h| (*h).to_string()));
    let mut exported = false;
    for c in cases {
        if c.proxied() && !exported {
            let pairs: Vec<String> = proxy_env(proxy_ip, PROXY_PORT).into_iter().map(|(k, v)| format!("{k}='{v}'")).collect();
            lines.push(format!("export {}", pairs.join(" ")));
            exported = true;
        }
        lines.push(format!("{} {} {}", if c.is_dns() { "aienv_d" } else { "aienv_c" }, c.name, fill(c.args)));
    }
    lines.push(r#"printf '%s%s end\n' '@@' "$R""#.to_string());
    lines.push("exit".to_string());
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// The `ai-env egress check` script: every case of [`CASES`].
#[must_use]
pub fn render_script(nonce: &str, proxy_ip: &str) -> String {
    render(nonce, proxy_ip, &CASES.iter().collect::<Vec<_>>())
}

/// The script of the named cases only, in [`CASES`] order (unknown names
/// are skipped): the dns-path probe's, and the live tests' partial runs.
#[must_use]
pub fn render_cases(nonce: &str, proxy_ip: &str, names: &[&str]) -> String {
    render(nonce, proxy_ip, &CASES.iter().filter(|c| names.contains(&c.name)).collect::<Vec<_>>())
}

/// The dns-path probe's script: [`DNS_PATH_CASES`].
#[must_use]
pub fn render_dns_script(nonce: &str, proxy_ip: &str) -> String {
    render_cases(nonce, proxy_ip, &DNS_PATH_CASES)
}

// ---- markers ----------------------------------------------------------------------------------

/// One case's marker line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseResult {
    pub name: String,
    /// curl's or dig's exit code; `None` for `rc=none` (a DNS case with no
    /// resolv.conf nameserver to ask).
    pub rc: Option<i32>,
    /// curl: `%{http_code}` (0 for `000`, no HTTP answer).
    pub code: Option<u16>,
    /// curl: `%{size_download}` (the body itself went to /dev/null).
    pub size: Option<u64>,
    /// curl: `%{num_connects}`, the connections it made (`None`: not reported).
    pub conn: Option<u32>,
    /// curl: `%{http_connect}`, the proxy's answer to CONNECT (0: none).
    pub hc: Option<u16>,
    /// curl: whether its error said [`CONNECT_403`].
    pub t403: Option<bool>,
    /// curl: whether the answer carried squid's `X-Squid-Error: ERR_ACCESS_DENIED`.
    pub sq: Option<bool>,
    /// dig: the server asked (`None` for `none`).
    pub ns: Option<String>,
    /// dig: whether the reply carried an address.
    pub resolves: Option<bool>,
}

/// What a transcript said: the case markers, and whether the script's
/// `end` marker came (the script ran to its end).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Markers {
    pub cases: Vec<CaseResult>,
    pub finished: bool,
}

impl Markers {
    /// The result of case `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CaseResult> {
        self.cases.iter().find(|c| c.name == name)
    }
}

/// A transcript token as an error may quote it: at most 40 printable ASCII characters.
fn shown(s: &str) -> String {
    s.chars().take(40).map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect()
}

/// A dig server value: an IP address (an IPv6 one may carry a `%zone`).
fn is_server(s: &str) -> bool {
    let addr = s.split_once('%').map_or(s, |(a, zone)| if zone.bytes().all(|c| c.is_ascii_alphanumeric()) && !zone.is_empty() { a } else { "" });
    addr.parse::<std::net::IpAddr>().is_ok()
}

const CURL_FIELDS: [&str; 7] = ["rc", "code", "size", "conn", "hc", "t403", "sq"];
const DIG_FIELDS: [&str; 3] = ["rc", "ns", "res"];

/// The marker lines of run `nonce` in `output` (the remote's transcript:
/// the shell's echo of the script, prompts, the markers). A line holds a
/// marker when it contains `@@AIENV`; the echoed script never does (its
/// markers are built at run time). Each case may appear once; `Err` for a
/// marker of another nonce, an unknown case, a case twice, a missing,
/// repeated or malformed field, `end` twice. Missing cases are [`judge`]'s
/// to name.
pub fn parse_markers(output: &str, nonce: &str) -> std::result::Result<Markers, String> {
    if !is_nonce(nonce) {
        return Err(format!("{:?} is not a run nonce", shown(nonce)));
    }
    let mut m = Markers::default();
    for line in output.split('\n') {
        let Some(at) = line.find(MARK) else { continue };
        let rest = &line[at + MARK.len()..];
        let (tag, body) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if tag != nonce {
            return Err(format!("a marker of another run ({MARK}{})", shown(tag)));
        }
        if body.contains(MARK) {
            return Err("two markers on one line".into());
        }
        let mut words = body.split_whitespace();
        let name = words.next().ok_or("a marker without a case")?;
        if name == "end" {
            if m.finished {
                return Err("the end marker twice".into());
            }
            if let Some(w) = words.next() {
                return Err(format!("the end marker carries {:?}", shown(w)));
            }
            m.finished = true;
            continue;
        }
        let spec = case(name).ok_or_else(|| format!("unknown case {:?}", shown(name)))?;
        if m.get(name).is_some() {
            return Err(format!("case {name} twice"));
        }
        let fields: &[&str] = if spec.is_dns() { &DIG_FIELDS } else { &CURL_FIELDS };
        let mut r = CaseResult { name: name.to_string(), ..CaseResult::default() };
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let digits = |v: &str| !v.is_empty() && v.len() <= 10 && v.bytes().all(|c| c.is_ascii_digit());
        for w in words {
            let (k, v) = w.split_once('=').ok_or_else(|| format!("{name}: {:?} is not key=value", shown(w)))?;
            let Some(key) = fields.iter().copied().find(|f| *f == k) else {
                return Err(format!("{name}: unexpected field {:?}", shown(k)));
            };
            if !seen.insert(key) {
                return Err(format!("{name}: {k} twice"));
            }
            let bad = || format!("{name}: bad {k}={:?}", shown(v));
            let yes_no = || match v {
                "yes" => Ok(true),
                "no" => Ok(false),
                _ => Err(format!("{name}: {k}={:?} is not yes|no", shown(v))),
            };
            match key {
                "rc" if v == "none" && spec.is_dns() => r.rc = None,
                "rc" => r.rc = Some(v.parse().map_err(|_| bad())?),
                "code" | "hc" => {
                    let n: u16 = if v.len() == 3 && digits(v) { v.parse().map_err(|_| bad())? } else { return Err(bad()) };
                    if key == "code" { r.code = Some(n) } else { r.hc = Some(n) }
                }
                "size" if digits(v) || v == "0" => r.size = Some(v.parse().map_err(|_| bad())?),
                "conn" if v == "-" => r.conn = None,
                "conn" if digits(v) => r.conn = Some(v.parse().map_err(|_| bad())?),
                "t403" => r.t403 = Some(yes_no()?),
                "sq" => r.sq = Some(yes_no()?),
                "ns" if v == "none" => r.ns = None,
                "ns" if is_server(v) => r.ns = Some(v.to_string()),
                "res" => r.resolves = Some(yes_no()?),
                _ => return Err(bad()),
            }
        }
        if let Some(missing) = fields.iter().find(|f| !seen.contains(*f)) {
            return Err(format!("{name}: the {missing} field is missing"));
        }
        if spec.is_dns() && (r.rc.is_none() != r.ns.is_none()) {
            return Err(format!("{name}: rc and ns disagree on whether a server was asked"));
        }
        m.cases.push(r);
    }
    Ok(m)
}

// ---- the judgement ----------------------------------------------------------------------------

/// A case's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    /// Measured, not judged (IMDS).
    Recorded,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Recorded => "recorded",
        }
    }
}

/// One case, judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseVerdict {
    pub name: &'static str,
    pub group: &'static str,
    pub verdict: Verdict,
    pub reason: String,
    /// The marker, when the case reported one.
    pub result: Option<CaseResult>,
}

/// Every case of [`CASES`], judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    pub cases: Vec<CaseVerdict>,
    /// The script's `end` marker came.
    pub finished: bool,
    /// The run's DNS verdict by the dns-path rule (`no-dns` |
    /// `platform-dns:<ip>` | `platform-dns-resolves:<ip>` | `open-dns:<ip>`)
    /// over its DNS cases, or `unknown (…)`.
    pub dns: String,
}

impl Judgement {
    /// The script finished and no case failed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.finished && self.cases.iter().all(|c| c.verdict != Verdict::Fail)
    }

    /// `case: reason` of every failing case, and the missing end marker.
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self.cases.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| format!("{}: {}", c.name, c.reason)).collect();
        if !self.finished {
            out.push("the script did not finish (no end marker)".into());
        }
        out
    }

    /// One line: every case with its verdict (`imds=recorded:<HTTP code>`).
    #[must_use]
    pub fn summary(&self) -> String {
        self.cases
            .iter()
            .map(|c| match (c.verdict, &c.result) {
                (Verdict::Recorded, Some(r)) => format!("{}=recorded:{:03}", c.name, r.code.unwrap_or(0)),
                (v, _) => format!("{}={}", c.name, v.as_str()),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn rc_said(rc: i32) -> &'static str {
    match rc {
        0 => "ok",
        6 => "could not resolve the host",
        7 => "could not connect",
        28 => "timed out",
        35 => "TLS handshake failed",
        52 => "empty reply",
        56 => "receive failure",
        60 => "certificate not trusted",
        127 => "not in the image",
        _ => "error",
    }
}

/// What curl saw, without anything the remote said.
fn curl_seen(r: &CaseResult) -> String {
    let rc = r.rc.unwrap_or(-1);
    let conn = r.conn.map_or_else(|| "connects unknown".to_string(), |c| format!("{c} connect{}", if c == 1 { "" } else { "s" }));
    match r.code.unwrap_or(0) {
        0 => format!("no HTTP answer (rc {rc}: {}; {conn})", rc_said(rc)),
        code => format!("HTTP {code} (rc {rc}, {} bytes; {conn})", r.size.unwrap_or(0)),
    }
}

/// Does the `allowed` case `r` show a working path through the proxy (its
/// tunnel opened, the API answered 401)?
fn allowed_passed(r: Option<&CaseResult>) -> bool {
    r.is_some_and(|r| r.code == Some(401) && r.hc == Some(200))
}

/// One case on its own (the non-vacuous rule is [`judge`]'s).
fn judge_case(c: &Case, r: &CaseResult) -> (Verdict, String) {
    let rc = r.rc.unwrap_or(-1);
    let code = r.code.unwrap_or(0);
    let hc = r.hc.unwrap_or(0);
    let connected = r.conn.is_some_and(|n| n > 0);
    match c.kind {
        Kind::Direct if connected || code != 0 => (Verdict::Fail, format!("OPEN: curl reached {}: {}", c.what, curl_seen(r))),
        Kind::Direct if r.conn.is_none() => (Verdict::Fail, format!("not proven closed: curl reported no connect count ({})", curl_seen(r))),
        Kind::Direct if matches!(rc, 6 | 7 | 28) => (Verdict::Pass, format!("closed: {}", curl_seen(r))),
        Kind::Direct => (Verdict::Fail, format!("not proven closed: {} (curl did not run, or failed otherwise)", curl_seen(r))),
        Kind::OtherPort if connected || code != 0 => (Verdict::Fail, format!("OPEN: curl reached {}: {}", c.what, curl_seen(r))),
        Kind::OtherPort if r.conn == Some(0) && rc == 28 => (Verdict::Pass, "closed: timed out without a connection (the security group drops it)".into()),
        Kind::OtherPort if rc == 7 => (Verdict::Fail, "not proven closed: rc 7 (refused or unreachable: a refusal means the packet reached the proxy host on a port other than 3128)".into()),
        Kind::OtherPort => (Verdict::Fail, format!("not proven closed: {}", curl_seen(r))),
        Kind::Dns(server) => {
            let ns = r.ns.as_deref().unwrap_or("none");
            let public = match server {
                DnsServer::Public => true,
                DnsServer::ResolvConf | DnsServer::Platform => !is_platform_resolver(ns),
            };
            match r.rc {
                None => (Verdict::Pass, "not asked: /etc/resolv.conf names no nameserver".into()),
                Some(9) => (Verdict::Pass, format!("closed: no reply from {ns}")),
                Some(0) if r.resolves == Some(true) => (Verdict::Fail, format!("OPEN: {ns} resolved {DNS_NAME}")),
                Some(0) if public => (Verdict::Fail, format!("OPEN: {ns}, not a platform resolver, replied (it resolved nothing, but the path is open)")),
                Some(0) => (Verdict::Pass, format!("{ns} replied and resolved nothing (platform DNS: `ai-env lab run dns-path` records it)")),
                Some(rc) => (Verdict::Fail, format!("not proven closed: dig exited {rc} asking {ns}{}", if rc == 127 { " (dig is not in the image)" } else { "" })),
            }
        }
        Kind::Recorded => (Verdict::Recorded, format!("recorded: {}", curl_seen(r))),
        Kind::Allowed if code == 401 && hc == 200 => (Verdict::Pass, "HTTP 401 through the proxy's tunnel (CONNECT 200)".into()),
        Kind::Allowed if hc == 403 || r.t403 == Some(true) => (Verdict::Fail, "the proxy refused it (CONNECT 403): is api.anthropic.com allowed and not suspended? (ai-env egress status)".into()),
        Kind::Allowed if code == 0 && matches!(rc, 7 | 28) => (Verdict::Fail, format!("the proxy did not answer: {} (is it running? make proxy-start; ai-env egress status)", curl_seen(r))),
        Kind::Allowed => (Verdict::Fail, format!("expected HTTP 401 through a tunnel the proxy opened (CONNECT 200): {}, CONNECT {hc:03}", curl_seen(r))),
        Kind::Connect403 if hc == 403 && r.t403 == Some(true) => (Verdict::Pass, "the proxy refused the CONNECT (403)".into()),
        Kind::Connect403 if code != 0 || hc == 200 => {
            let hint = if c.name == "proxy-github" { " (is github.com among the extras? ai-env egress status; ai-env egress allow <workspace> github.com --remove)" } else { "" };
            (Verdict::Fail, format!("OPEN: the proxy opened a tunnel: {}, CONNECT {hc:03}{hint}", curl_seen(r)))
        }
        Kind::Connect403 => (Verdict::Fail, format!("no 403 from the proxy: {}, CONNECT {hc:03}", curl_seen(r))),
        Kind::Get403 if code == 403 && r.sq == Some(true) => (Verdict::Pass, "squid's 403 (X-Squid-Error ERR_ACCESS_DENIED)".into()),
        Kind::Get403 if code == 403 => (Verdict::Fail, "a 403 without squid's X-Squid-Error ERR_ACCESS_DENIED: not the proxy's refusal".into()),
        Kind::Get403 => (Verdict::Fail, format!("expected squid's 403 for a plain-http request: {}", curl_seen(r))),
    }
}

/// The DNS cases of `m` as [`DnsReply`]s, with the resolv.conf nameserver.
fn dns_replies(m: &Markers) -> (Option<String>, Vec<DnsReply>) {
    let mut out = Vec::new();
    for c in CASES.iter().filter(|c| c.is_dns()) {
        if let Some(r) = m.get(c.name) {
            out.push(DnsReply { server: r.ns.clone().unwrap_or_default(), transport: if c.name.ends_with("-tcp") { "tcp" } else { "udp" }, rc: r.rc, resolves: r.resolves == Some(true) });
        }
    }
    let resolv = m.get("dns-resolv-udp").or_else(|| m.get("dns-resolv-tcp")).and_then(|r| r.ns.clone());
    (resolv, out)
}

/// Judge every case of [`CASES`] (pure). A missing case fails; a direct,
/// DNS or other-port case that passed on its own still fails unless both
/// `allowed` cases of the same run passed (a VM whose networking is dead,
/// or died midway, proves nothing closed). `dns` is the run's dns-path
/// verdict.
#[must_use]
pub fn judge(m: &Markers) -> Judgement {
    let allowed_ok = ALLOWED_CASES.iter().all(|n| allowed_passed(m.get(n)));
    let cases = CASES
        .iter()
        .map(|c| {
            let Some(r) = m.get(c.name) else {
                return CaseVerdict { name: c.name, group: c.group, verdict: Verdict::Fail, reason: "no result: the script did not reach it".into(), result: None };
            };
            let (mut verdict, mut reason) = judge_case(c, r);
            if verdict == Verdict::Pass && c.needs_allowed() && !allowed_ok {
                verdict = Verdict::Fail;
                reason = format!("{reason} — not counted: `allowed` and `allowed-last` did not both pass in this run, so this VM's networking proved nothing");
            }
            CaseVerdict { name: c.name, group: c.group, verdict, reason, result: Some(r.clone()) }
        })
        .collect();
    let (resolv, replies) = dns_replies(m);
    let dns = match verdict_dns_path(resolv.as_deref(), &replies) {
        Ok((v, _)) => v,
        Err(e) => format!("unknown ({e})"),
    };
    Judgement { cases, finished: m.finished, dns }
}

/// The dns-path probe's verdict and note from its transcript's markers: the
/// script must have finished with every case of [`DNS_PATH_CASES`], and
/// both `allowed` cases must have passed (`no-dns` from a VM whose
/// networking is dead would prove nothing); then
/// `probes::verdict_dns_path` (`open-dns:<ip>` when a resolver that is not
/// the platform's replied).
pub fn dns_path_outcome(m: &Markers) -> std::result::Result<(String, String), String> {
    if let Some(missing) = DNS_PATH_CASES.iter().find(|n| m.get(n).is_none()) {
        return Err(format!("no result for {missing}: the script did not reach it"));
    }
    if !m.finished {
        return Err("the script did not finish (no end marker)".into());
    }
    for name in ALLOWED_CASES {
        let r = m.get(name).ok_or_else(|| format!("no result for {name}"))?;
        if !allowed_passed(Some(r)) {
            return Err(format!("the VM did not reach the proxy ({name}: {}): no verdict, a VM without working networking proves nothing", curl_seen(r)));
        }
    }
    let (resolv, replies) = dns_replies(m);
    let (verdict, note) = verdict_dns_path(resolv.as_deref(), &replies)?;
    Ok((verdict, format!("{note}; the proxy answered before and after (allowed, allowed-last: HTTP 401)")))
}

// ---- squid's log ------------------------------------------------------------------------------

/// The squid lines of a `logs filter-log-events` answer (`events[].message`);
/// messages of another format are skipped.
pub fn squid_lines(doc: &serde_json::Value) -> std::result::Result<Vec<SquidLine>, String> {
    let events = doc.get("events").and_then(|e| e.as_array()).ok_or("logs filter-log-events: no events in the answer")?;
    Ok(events.iter().filter_map(|e| e.get("message").and_then(|m| m.as_str())).filter_map(parse_squid_line).collect())
}

fn line_text(l: &SquidLine) -> String {
    format!("{}/{} {} {}:{} from {}", l.code, l.status, l.method, l.host, l.port.map_or_else(|| "-".to_string(), |p| p.to_string()), l.client)
}

/// The allowlisted host the `allowed` cases ask (port 443 through the proxy).
const ALLOWED_HOST: &str = "api.anthropic.com";

/// The requests of a run the proxy had to refuse: (method, host, port).
#[must_use]
pub fn refused_requests(nonce: &str) -> Vec<(&'static str, String, u16)> {
    vec![
        ("CONNECT", denied_host(nonce), 443),
        ("CONNECT", "1.1.1.1".to_string(), 443),
        ("CONNECT", "api.anthropic.com".to_string(), 8443),
        ("CONNECT", "github.com".to_string(), 443),
        ("GET", "api.anthropic.com".to_string(), 8080),
    ]
}

/// What squid's log says about a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SquidEvidence {
    /// Everything required is there.
    Complete(String),
    /// Not (yet) in the log: these lines.
    Missing(Vec<String>),
    /// The log contradicts the run: a tunnel to a refused host, the run's
    /// host let through, or requested from outside the VM subnet.
    Violation(String),
}

/// The squid lines that prove a run (pure). Only lines whose squid time
/// lies in `[from_s, to_s]` count. The run's nonce host must show
/// `TCP_DENIED/403 CONNECT …:443` from a client in the VM subnet (the run's
/// client: the connector's address) — a tunnel or a 2xx for it, or a request
/// from outside the subnet, is a violation. From that client: at least
/// `tunnels` `TCP_TUNNEL/200 CONNECT api.anthropic.com:443` lines (the run's
/// `allowed` cases), a `TCP_DENIED/403` line for every other refused request
/// ([`refused_requests`]), and no `TCP_TUNNEL` to any of them.
#[must_use]
pub fn squid_evidence(lines: &[SquidLine], nonce: &str, from_s: u64, to_s: u64, tunnels: usize) -> SquidEvidence {
    let at = |l: &SquidLine| l.ts.split('.').next().and_then(|s| s.parse::<u64>().ok());
    let window: Vec<&SquidLine> = lines.iter().filter(|l| at(l).is_some_and(|t| (from_s..=to_s).contains(&t))).collect();
    let host = denied_host(nonce);
    let mine: Vec<&&SquidLine> = window.iter().filter(|l| l.host == host).collect();
    if let Some(l) = mine.iter().find(|l| l.code == "TCP_TUNNEL" || (200..300).contains(&l.status)) {
        return SquidEvidence::Violation(format!("squid let the run's denied host through: {}", line_text(l)));
    }
    if let Some(l) = mine.iter().find(|l| !in_cidr(&l.client, VM_SUBNET_CIDR)) {
        return SquidEvidence::Violation(format!("the run's request came from {}, outside the VM subnet {VM_SUBNET_CIDR}: {}", l.client, line_text(l)));
    }
    let Some(client) = mine.iter().find(|l| l.code == "TCP_DENIED" && l.status == 403 && l.method == "CONNECT" && l.port == Some(443)).map(|l| l.client.clone()) else {
        return SquidEvidence::Missing(vec![format!("TCP_DENIED/403 CONNECT {host}:443 from {VM_SUBNET_CIDR}")]);
    };
    let from: Vec<&&SquidLine> = window.iter().filter(|l| l.client == client).collect();
    let refused = refused_requests(nonce);
    // A refused host, on any port — but the allowlisted API host only on the ports it was refused on.
    let refused_tunnel = |l: &SquidLine| refused.iter().any(|(_, h, p)| l.host == *h && (h != ALLOWED_HOST || l.port == Some(*p)));
    let bad: Vec<String> = from.iter().filter(|l| l.code == "TCP_TUNNEL" && refused_tunnel(l)).map(|l| line_text(l)).collect();
    if !bad.is_empty() {
        return SquidEvidence::Violation(format!("squid opened tunnels to hosts this run was refused: {}", bad.join("; ")));
    }
    let mut missing = Vec::new();
    let opened = from.iter().filter(|l| l.code == "TCP_TUNNEL" && l.status == 200 && l.method == "CONNECT" && l.host == ALLOWED_HOST && l.port == Some(443)).count();
    if opened < tunnels {
        missing.push(format!("{tunnels} × TCP_TUNNEL/200 CONNECT api.anthropic.com:443 from {client} ({opened} found)"));
    }
    for (method, h, port) in &refused {
        if !from.iter().any(|l| l.code == "TCP_DENIED" && l.status == 403 && l.method == *method && l.host == *h && l.port == Some(*port)) {
            missing.push(format!("TCP_DENIED/403 {method} {h}:{port} from {client}"));
        }
    }
    if !missing.is_empty() {
        return SquidEvidence::Missing(missing);
    }
    SquidEvidence::Complete(format!(
        "from {client}: {opened} tunnels to api.anthropic.com:443; TCP_DENIED/403 for {}; no tunnel to a refused host",
        refused.iter().map(|(m, h, p)| format!("{m} {h}:{p}")).collect::<Vec<_>>().join(", ")
    ))
}

/// Poll squid's log in CloudWatch (the operator's aws CLI: `logs
/// filter-log-events --filter-pattern '"aienv"'` over the script's window,
/// widened by [`CLOCK_SKEW_S`]) until [`squid_evidence`] is complete, a
/// violation shows, or `budget` passes (then what is missing is the error).
pub async fn squid_poll(nonce: &str, started_s: u64, ended_s: u64, budget: Duration, step: Duration) -> std::result::Result<String, String> {
    let (from_s, to_s) = (started_s.saturating_sub(CLOCK_SKEW_S), ended_s.saturating_add(CLOCK_SKEW_S));
    let start = from_s.saturating_mul(1000).to_string();
    let end = to_s.saturating_add(5 * CLOCK_SKEW_S).saturating_mul(1000).to_string();
    let t0 = Instant::now();
    loop {
        let (s, e) = (start.clone(), end.clone());
        let doc = tokio::task::spawn_blocking(move || awscli::aws_json("logs", &["filter-log-events", "--log-group-name", LOG_GROUP, "--filter-pattern", "\"aienv\"", "--start-time", &s, "--end-time", &e]))
            .await
            .map_err(|e| format!("internal: {e}"))??;
        match squid_evidence(&squid_lines(&doc)?, nonce, from_s, to_s, ALLOWED_CASES.len()) {
            SquidEvidence::Complete(found) => return Ok(format!("{found} (after {} s)", t0.elapsed().as_secs())),
            SquidEvidence::Violation(v) => return Err(v),
            SquidEvidence::Missing(m) if t0.elapsed() >= budget => {
                return Err(format!("not in squid's log within {} s: {} (is the CloudWatch agent shipping {LOG_GROUP}? make egress-logs)", budget.as_secs(), m.join("; ")));
            }
            SquidEvidence::Missing(_) => tokio::time::sleep(step).await,
        }
    }
}

/// The network verification for the record: `Ok(summary)` when every row
/// of `egress status`'s checks is `ok`, else `Err` naming each row that
/// drifted or could not be verified (or why none could run).
fn network_verdict() -> std::result::Result<String, String> {
    let rows = super::cli::network_verification().map_err(|e| format!("not run: {e}"))?;
    let bad: Vec<String> = rows.iter().filter(|r| r.status != "ok").map(|r| format!("{} {}: {}", r.status, r.check, r.detail)).collect();
    if rows.is_empty() {
        return Err("no check ran".into());
    }
    if bad.is_empty() {
        Ok(format!("{} checks ok: {}", rows.len(), rows.iter().map(|r| r.check).collect::<Vec<_>>().join(", ")))
    } else {
        Err(bad.join("; "))
    }
}

// ---- the decision -----------------------------------------------------------------------------

/// Everything one check gathered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: String,
    /// The check started this VM itself (fresh, purpose `test`, label
    /// `egress-check`, no workspace); `false` for `--vm` (report only).
    pub own: bool,
    /// The image ARN and version the VM's row was started with.
    pub row_image_arn: String,
    pub row_image_version: String,
    /// The image ARN and version the VM echoed.
    pub vm_image_arn: String,
    pub vm_image_version: String,
    pub judgement: Judgement,
    /// `Err` when the transcript's markers could not be read.
    pub transcript: std::result::Result<(), String>,
    /// [`network_verdict`]; `None` when not run.
    pub network: Option<std::result::Result<String, String>>,
    /// [`squid_poll`]; `None` when not run (a case or the network failed first).
    pub squid: Option<std::result::Result<String, String>>,
    /// The configured connector's live facts (`get-network-connector` as the
    /// operator) the record is bound to; `None` when not read (the check of
    /// another VM, or a failure first).
    pub connector_facts: Option<std::result::Result<ConnectorFacts, String>>,
    /// The echoed image version's `created_at` (`ListMicrovmImageVersions`)
    /// the record is bound to; `None` when not read.
    pub image_created_at: Option<std::result::Result<i64, String>>,
    /// When the check began (Unix seconds): a revocation of the connector at
    /// or after it refuses the record (`EgressVerified::record`).
    pub started_s: u64,
    pub denied_host: String,
}

/// What [`decide`] concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub passed: bool,
    /// The record to write (a pass of the check's own VM only).
    pub record: Option<VerifiedRecord>,
    /// Revoke every record of the connector (a failed check of its own VM).
    pub revoke: bool,
    /// Every reason it did not pass.
    pub failures: Vec<String>,
}

/// The verdict (pure): a pass needs the transcript read, every case passed
/// (or recorded) and the script finished, the network verification and
/// squid's log both `Ok`, and the VM's echoed image ARN and version equal to
/// its row's; a pass of the check's own VM also needs what its record is
/// bound to — the connector's live facts (all present) and the image
/// version's `created_at`. Only the check's own VM records (a pass) or
/// revokes (any failure); `--vm` does neither.
#[must_use]
pub fn decide(ev: &Evidence, connector: &str, at: &str) -> Decision {
    let mut failures = Vec::new();
    match &ev.transcript {
        Err(e) => failures.push(format!("the transcript could not be read: {e}")),
        Ok(()) => failures.extend(ev.judgement.failures()),
    }
    match &ev.network {
        Some(Err(e)) => failures.push(format!("network verification: {e}")),
        None => failures.push("network verification: not run".into()),
        Some(Ok(_)) => {}
    }
    match &ev.squid {
        Some(Err(e)) => failures.push(format!("squid log: {e}")),
        None if failures.is_empty() => failures.push("squid log: not checked".into()),
        _ => {}
    }
    if ev.vm_image_arn != ev.row_image_arn || ev.vm_image_version != ev.row_image_version {
        failures.push(format!("the VM echoed image {} version {}, but its row was started with {} version {}", ev.vm_image_arn, ev.vm_image_version, ev.row_image_arn, ev.row_image_version));
    }
    // What the record is bound to (the check's own VM only: `--vm` records nothing).
    let mut facts = ConnectorFacts::default();
    let mut created = None;
    if ev.own && failures.is_empty() {
        match &ev.connector_facts {
            Some(Ok(f)) if f.complete() => facts = f.clone(),
            Some(Ok(_)) => failures.push("the connector's facts are incomplete (Id, Version, subnet, security group): nothing to bind the record to".into()),
            Some(Err(e)) => failures.push(format!("the connector's facts could not be read: {e}")),
            None => failures.push("the connector's facts were not read".into()),
        }
        match &ev.image_created_at {
            Some(Ok(t)) => created = Some(*t),
            Some(Err(e)) => failures.push(format!("the image version's created_at could not be read: {e}")),
            None => failures.push("the image version's created_at was not read".into()),
        }
    }
    let passed = failures.is_empty();
    let ok_text = |r: &Option<std::result::Result<String, String>>| r.as_ref().and_then(|r| r.as_ref().ok()).cloned().unwrap_or_default();
    let record = (passed && ev.own).then(|| VerifiedRecord {
        image_arn: ev.row_image_arn.clone(),
        image_version: ev.vm_image_version.clone(),
        connector: normalize_connector(connector),
        vm_id: ev.id.clone(),
        at: at.to_string(),
        cases: ev.judgement.summary(),
        dns: ev.judgement.dns.clone(),
        squid_log: ok_text(&ev.squid),
        network: ok_text(&ev.network),
        connector_facts: facts,
        image_created_at: created,
    });
    Decision { passed, record, revoke: !passed && ev.own, failures }
}

// ---- `ai-env egress check` --------------------------------------------------------------------

/// The VM the check runs on.
enum Target {
    /// `--vm ID`: a `vm run --egress vpc --shell` VM of the operator's (never
    /// terminated here; report only).
    Existing(Box<VmRow>),
    /// A VM of the check's own (purpose `test`, label `egress-check`, 900 s).
    Start(Box<run::RunPlan>),
}

/// The VMs to end after the check: its own (unless `--keep`), and VMs the
/// egress gate rejected but could not terminate (always); and whether the
/// check asked for a VM of its own (from then on any failure revokes).
#[derive(Default)]
struct Guard {
    since: u64,
    ours: Vec<String>,
    gate: Vec<String>,
    asked: bool,
    image_version: Option<String>,
}

/// A check that ended before its transcript was judged: the error, and the
/// check's own VM as far as it was known.
struct Early {
    error: CliError,
    asked: bool,
    id: Option<String>,
    image_version: Option<String>,
}

/// `[aws].egress_connector_arn` (`Ctx::load` validated its form), or exit 1.
fn configured_connector(cfg: &BridgeConfig) -> Result<String> {
    cfg.aws
        .egress_connector_arn
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .ok_or_else(|| CliError::Msg("egress check: [aws].egress_connector_arn is not set: run `make infra-status WRITE=1` (it records the stack's connector)".into()))
}

/// `--vm ID`, checked before any AWS call: its row must be of a running
/// `vpc` VM with `--shell`, whose egress gate passed for exactly the
/// configured connector (exit 1 otherwise; a malformed id is exit 2).
fn existing_vm(ctx: &Ctx, id: &str, connector: &str) -> Result<VmRow> {
    if !registry::is_vm_id(id) {
        return Err(CliError::Usage(format!("--vm: not a microvm id: {id:?}")));
    }
    let refuse = |why: String| CliError::Msg(format!("egress check --vm {id}: {why}: start one with `ai-env vm run --egress vpc --shell`, or run `ai-env egress check` without --vm"));
    let row = registry::read_row(&ctx.paths, id)?.ok_or_else(|| refuse("no row in state/vms (not started by this ai-env)".into()))?;
    if row.status == RowStatus::Terminated {
        return Err(refuse("its row says terminated".into()));
    }
    if row.egress != run::Egress::Vpc.as_str() {
        return Err(refuse(format!("its egress is {:?}, not vpc", row.egress)));
    }
    if !row.shell {
        return Err(refuse("it was started without --shell (no SHELL_INGRESS)".into()));
    }
    if row.egress_gate.as_deref() != Some(GATE_PASSED) {
        return Err(refuse(format!("its egress gate is {}, not passed", row.egress_gate.as_deref().unwrap_or("unknown"))));
    }
    let have: BTreeSet<String> = row.egress_connectors.iter().map(|c| normalize_connector(c)).collect();
    if have != BTreeSet::from([normalize_connector(connector)]) {
        return Err(refuse(format!("its connectors are [{}], not exactly [aws].egress_connector_arn", have.into_iter().collect::<Vec<_>>().join(", "))));
    }
    Ok(row)
}

/// The check's own VM: `vm run --egress vpc --shell` with purpose `test`,
/// label `egress-check`, max duration 900 s, no workspace, waited for
/// RUNNING; its own client token, so a Ctrl-C finds exactly its rows.
fn check_plan(ctx: &Ctx) -> Result<run::RunPlan> {
    let flags = run::RunFlags {
        max_duration_s: Some(CHECK_MAX_DURATION_S),
        egress: Some(run::Egress::Vpc),
        shell: true,
        label: Some("egress-check".into()),
        wait: true,
        purpose: "test",
        ..run::RunFlags::default()
    };
    let mut plan = run::RunPlan::from_cfg(&ctx.cfg, &flags)?;
    plan.client_token = Some(uuid::Uuid::now_v7().to_string());
    Ok(plan)
}

/// `ai-env egress check [--vm ID] [--keep] [--json]` (see the module doc).
pub fn cmd_check(store: &Keystore, vm: Option<&str>, keep: bool, json: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    let connector = configured_connector(&ctx.cfg)?;
    let target = match vm {
        Some(id) => Target::Existing(Box::new(existing_vm(&ctx, id, &connector)?)),
        None => Target::Start(Box::new(check_plan(&ctx)?)),
    };
    awscli::require_operator_account(&connector).map_err(|e| CliError::Msg(format!("egress check: {e}")))?;
    let rt = runtime()?;
    let outcome = rt.block_on(async {
        let b = backend(store, &ctx).await?;
        let fake = matches!(b, Backend::Fake(_));
        Ok::<_, CliError>(with_backend!(&b, |api, ep| run_check(&ctx, api, ep, &target, fake, keep, &connector).await))
    });
    // A blocking aws call a Ctrl-C left behind is not waited for.
    rt.shutdown_background();
    match outcome? {
        Ok(evidence) => report(&ctx, &connector, &evidence, json),
        Err(early) => Err(early_failure(&ctx, &connector, early)),
    }
}

/// The check on the target VM, under Ctrl-C (exit 3, nothing recorded or
/// revoked); whatever this check started is ended afterwards on every path
/// — success, failure, Ctrl-C (then the VM is found through the rows of the
/// plan's client token) — unless `--keep`; a VM whose egress gate did not
/// pass is ended whatever `--keep` says.
async fn run_check<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, target: &Target, fake: bool, keep: bool, connector: &str) -> std::result::Result<Evidence, Early> {
    let mut guard = Guard { since: unix_now(), ..Guard::default() };
    let work = gather(ctx, api, ep, target, fake, connector, &mut guard);
    let outcome = tokio::select! {
        r = work => r,
        _ = tokio::signal::ctrl_c() => Err(CliError::Cancelled),
    };
    if matches!(outcome, Err(CliError::Cancelled)) {
        if let Target::Start(plan) = target {
            if let Some((id, failed_gate)) = own_vm(ctx, api, ep, plan.client_token.as_deref().unwrap_or_default(), guard.since).await {
                if failed_gate { guard.gate.push(id) } else { guard.ours.push(id) }
            }
        }
    }
    cleanup(ctx, api, &guard, keep).await;
    outcome.map_err(|error| Early { error, asked: guard.asked, id: guard.gate.first().or(guard.ours.first()).cloned(), image_version: guard.image_version.clone() })
}

/// A check of its own VM that failed before its transcript was judged (the
/// VM's start or its egress gate, `/health`, the shell token or dial, the
/// fake's refusal): revoke the connector's records and audit `egress_check
/// {id, image_version, verdict=fail, reason, revoked}` like any failing
/// check, and say so after the error (whose exit code stays). Ctrl-C, a
/// `--vm` check and a failure before the check asked for its VM revoke
/// nothing.
fn early_failure(ctx: &Ctx, connector: &str, early: Early) -> CliError {
    if !early.asked || matches!(early.error, CliError::Cancelled) {
        return early.error;
    }
    let reason: String = early.error.to_string().chars().take(300).collect();
    let revoked = EgressVerified::update(&ctx.paths, |v| v.revoke_connector(connector, unix_now()));
    let pairs = [
        ("id", early.id.unwrap_or_else(|| "-".to_string())),
        ("image_version", early.image_version.unwrap_or_else(|| "-".to_string())),
        ("verdict", "fail".to_string()),
        ("reason", reason),
        ("revoked", revoked.as_ref().map_or_else(|_| "error".to_string(), ToString::to_string)),
    ];
    audit_event(&ctx.paths, "egress_check", &pairs);
    let note = match revoked {
        Ok(n) => format!("egress check FAILED: revoked {n} earlier pass{} of this connector", if n == 1 { "" } else { "es" }),
        Err(e) => format!("egress check FAILED and COULD NOT REVOKE the earlier passes of this connector: {e} (fix or remove {})", ctx.paths.egress_verified().display()),
    };
    crate::bridge::creds::with_note(early.error, &note)
}

/// Acquire the VM and wait for its `/health`, refuse the fake (unless its
/// transcript knob stands in for the shell), run the script, judge it, then
/// the VM-independent evidence: the network verification (always, once a
/// transcript exists) and squid's log (only when every case and the network
/// passed).
async fn gather<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, target: &Target, fake: bool, connector: &str, guard: &mut Guard) -> Result<Evidence> {
    let (row, vm, own) = match target {
        Target::Existing(row) => ((**row).clone(), live_vm(ctx, api, row).await?, false),
        Target::Start(plan) => {
            guard.asked = true;
            let (row, vm) = start_vm(ctx, api, ep, plan, guard).await?;
            guard.image_version = Some(vm.image_version.clone());
            (row, vm, true)
        }
    };
    health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
    let started_s = unix_now();
    let (nonce, output) = if fake {
        fake_transcript()?
    } else {
        let nonce = new_nonce();
        let script = render_script(&nonce, &proxy_ip(&ctx.cfg, &ctx.paths));
        let budget = script_budget(CASES.len());
        eprintln!("egress check: {} cases on {} through the platform shell (at most {} s)", CASES.len(), vm.id, budget.as_secs());
        let output = shell::run_script(api, &vm.id, &script, budget, ShellAuth::Header).await?;
        (nonce, output)
    };
    let ended_s = unix_now();
    let (judgement, transcript) = match parse_markers(&output, &nonce) {
        Ok(m) => (judge(&m), Ok(())),
        Err(e) => (judge(&Markers::default()), Err(e)),
    };
    eprintln!("egress check: verifying the network (every check of `ai-env egress status`)");
    let network = tokio::task::spawn_blocking(network_verdict).await.unwrap_or_else(|e| Err(format!("internal: {e}")));
    let squid = if transcript.is_ok() && judgement.passed() && network.is_ok() {
        let (budget, step) = (scaled(SQUID_LOG_BUDGET, ctx.knobs.backoff_ms), scaled(SQUID_LOG_STEP, ctx.knobs.backoff_ms));
        eprintln!("egress check: every case passed; reading squid's log in CloudWatch (at most {} s)", budget.as_secs());
        Some(squid_poll(&nonce, started_s, ended_s, budget, step).await)
    } else {
        None
    };
    // What a record of its own VM is bound to, read only when it could record.
    let (connector_facts, image_created_at) = if own && matches!(squid, Some(Ok(_))) {
        let arn = connector.to_string();
        let facts = tokio::task::spawn_blocking(move || read_connector_facts(&arn)).await.unwrap_or_else(|e| Err(format!("internal: {e}")));
        (Some(facts), Some(image_created_at(api, &row.image_arn, &vm.image_version).await))
    } else {
        (None, None)
    };
    Ok(Evidence {
        id: vm.id.clone(),
        own,
        row_image_arn: row.image_arn.clone(),
        row_image_version: row.image_version.clone(),
        vm_image_arn: vm.image_arn.clone(),
        vm_image_version: vm.image_version.clone(),
        judgement,
        transcript,
        network: Some(network),
        squid,
        connector_facts,
        image_created_at,
        started_s: guard.since,
        denied_host: denied_host(&nonce),
    })
}

/// The configured connector's facts as the operator's aws CLI reads them
/// now (`aws lambda-core get-network-connector`, region and endpoint pinned).
fn read_connector_facts(arn: &str) -> std::result::Result<ConnectorFacts, String> {
    let doc = awscli::aws_json("lambda-core", &["get-network-connector", "--identifier", arn])?;
    ConnectorFacts::from_get(&doc).ok_or_else(|| format!("aws lambda-core get-network-connector {arn}: no Id, Version, subnet or security group in the answer"))
}

/// The `created_at` of `version` of `image_arn` (`ListMicrovmImageVersions`).
async fn image_created_at<A: MicrovmApi>(api: &A, image_arn: &str, version: &str) -> std::result::Result<i64, String> {
    let versions = api.list_image_versions(image_arn).await.map_err(|e| e.to_string())?;
    let v = versions.iter().find(|v| v.version == version).ok_or_else(|| format!("version {version} of {image_arn} is not listed"))?;
    v.created_at_unix.ok_or_else(|| format!("version {version} of {image_arn} reports no created_at"))
}

/// A poll duration under the lab's `AI_ENV_BRIDGE_LAB_BACKOFF_MS` (1 s → n ms).
fn scaled(d: Duration, ms_per_second: Option<u64>) -> Duration {
    match ms_per_second {
        Some(n) => Duration::from_millis(u64::try_from(d.as_millis().saturating_mul(u128::from(n)) / 1000).unwrap_or(u64::MAX)),
        None => d,
    }
}

/// Under the file-backed fake: the refusal (it cannot carry a shell), or —
/// debug builds, with [`FAKE_SHELL_KNOB`] set — the transcript that file
/// holds and the nonce of its markers.
fn fake_transcript() -> Result<(String, String)> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os(FAKE_SHELL_KNOB).filter(|p| !p.is_empty()) {
        let text = std::fs::read_to_string(&path).map_err(|e| CliError::Msg(format!("{FAKE_SHELL_KNOB}: cannot read {}: {e}", std::path::Path::new(&path).display())))?;
        let nonce: String = text.split(MARK).nth(1).map(|rest| rest.chars().take_while(char::is_ascii_hexdigit).collect()).unwrap_or_default();
        if !is_nonce(&nonce) {
            return Err(CliError::Msg(format!("{FAKE_SHELL_KNOB}: no {MARK}<nonce> marker in the file")));
        }
        eprintln!("ai-env: LAB KNOB ACTIVE ({FAKE_SHELL_KNOB}): the shell's transcript is read from a file (debug build)");
        return Ok((nonce, text));
    }
    Err(shell::fake_backend_refusal("egress check").into())
}

/// `--vm ID` live: RUNNING, and its echo still exactly what its row
/// requires — else the gate's reject path (row `mismatch`, terminated by
/// `policy`, audit `vm_egress_mismatch` via `check`; exit 9).
async fn live_vm<A: MicrovmApi>(ctx: &Ctx, api: &A, row: &VmRow) -> Result<VmInfo> {
    let vm = api.get(&row.id).await?;
    if vm.state.is_terminal() {
        return Err(BridgeError::Terminated(format!("{} is {}", row.id, vm.state.as_str())).into());
    }
    if vm.state != VmState::Running {
        return Err(CliError::Msg(format!("egress check --vm {0}: it is {1}, not RUNNING (ai-env vm resume {0})", row.id, vm.state.as_str())));
    }
    let (expected, alias) = run::row_gate(&ctx.paths, row);
    if !run::echo_passes(expected.as_ref(), &vm.egress, alias.as_ref()) {
        return Err(run::reject_echo(api, &ctx.paths, &row.id, expected.as_ref(), &vm.egress, "check", "test").await.into());
    }
    Ok(vm)
}

/// SELECT_VM for the check's own VM; whatever may be alive after a failure
/// goes into the guard (the started VM, a gate-rejected one, the VM of an
/// ambiguous run found by the adoption sweep).
async fn start_vm<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, plan: &run::RunPlan, guard: &mut Guard) -> Result<(VmRow, VmInfo)> {
    for w in &plan.warnings {
        eprintln!("ai-env: warning: {w}");
    }
    let poll = run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms);
    match run::select_vm_detailed(api, &ctx.paths, plan, poll).await {
        Ok(run::Selected::Started { row, vm, .. }) => {
            guard.ours.push(vm.id.clone());
            eprintln!("egress check: started {} (egress {})", vm.id, vm.egress.join(", "));
            Ok((row, vm))
        }
        Ok(run::Selected::Reused { vm, .. }) => Err(CliError::Msg(format!("egress check reused {} (internal)", vm.id))),
        Err(f) => {
            let gate_failed = matches!(f.error, BridgeError::EgressMismatch(_));
            if let Some(id) = &f.started {
                if gate_failed { guard.gate.push(id.clone()) } else { guard.ours.push(id.clone()) }
            }
            if let Some(pending) = &f.kept_pending {
                match run::adopt_after_ambiguous_for(api, ep, &ctx.paths, pending, guard.since, poll, "test").await {
                    Ok(run::Adoption::Adopted(id)) => guard.ours.push(id),
                    Err(BridgeError::EgressMismatch(m)) if !m.terminated => guard.gate.push(m.id.clone()),
                    _ => eprintln!("egress check: the pending row {} is kept: ai-env vm gc", pending.stem()),
                }
            }
            Err(f.error.into())
        }
    }
}

/// After a Ctrl-C: the VM of this check, found only through the rows of its
/// client token (an id row; a pending row through the adoption sweep), and
/// whether its egress gate failed to pass (any verdict but `passed`, pending
/// included: such a VM is ended whatever `--keep` says).
async fn own_vm<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, client_token: &str, since: u64) -> Option<(String, bool)> {
    if client_token.is_empty() {
        return None;
    }
    let rows = registry::list_rows(&ctx.paths).ok()?;
    let mine: Vec<&VmRow> = rows.iter().filter(|r| r.client_token == client_token).collect();
    if let Some(r) = mine.iter().find(|r| !r.is_pending_row() && r.status != RowStatus::Terminated) {
        return Some((r.id.clone(), r.egress_gate.as_deref() != Some(GATE_PASSED)));
    }
    let pending = mine.iter().find(|r| r.is_pending_row())?;
    match run::adopt_after_ambiguous_for(api, ep, &ctx.paths, pending, since, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms), "test").await {
        Ok(run::Adoption::Adopted(id)) => Some((id, false)),
        Err(BridgeError::EgressMismatch(m)) if !m.terminated => Some((m.id.clone(), true)),
        _ => None,
    }
}

/// End the guard's VMs (each once): gate-rejected ones by `policy` always,
/// the check's own by `test` unless `--keep`.
async fn cleanup<A: MicrovmApi>(ctx: &Ctx, api: &A, guard: &Guard, keep: bool) {
    let settle = Some(run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms));
    let mut done: BTreeSet<&str> = BTreeSet::new();
    for id in &guard.gate {
        if !done.insert(id) {
            continue;
        }
        match run::terminate_and_record(api, &ctx.paths, id, "policy", settle).await {
            Ok(_) => eprintln!("egress check: terminated {id}: its egress gate did not pass{}", if keep { " (--keep never keeps such a VM)" } else { "" }),
            Err(e) => eprintln!("egress check: could not terminate {id}, whose egress gate did not pass: {e} — run: ai-env vm terminate {id} (or ai-env vm gc --yes)"),
        }
    }
    for id in &guard.ours {
        if !done.insert(id) {
            continue;
        }
        if keep {
            eprintln!("egress check: --keep: {id} left running (ai-env vm terminate {id})");
            continue;
        }
        match run::terminate_and_record(api, &ctx.paths, id, "test", settle).await {
            Ok(_) => eprintln!("egress check: terminated {id}"),
            Err(e) => eprintln!("egress check: could not terminate {id}: {e} — run: ai-env vm terminate {id}"),
        }
    }
}

/// The line every report carries: what a record rests on.
pub const EVIDENCE_NOTE: &str = "the case results are reported by the VM itself; a record rests on the network verification and squid's log, which the VM cannot write";

/// [`decide`], then act on it: record a pass of the check's own VM, or
/// revoke every record of the connector after any failure of it (`--vm`:
/// neither); audit `egress_check {id, image_version, verdict[, revoked]}`;
/// print (one JSON document with `--json`); exit 9 naming every failure.
fn report(ctx: &Ctx, connector: &str, ev: &Evidence, json: bool) -> Result<()> {
    let mut d = decide(ev, connector, &rfc3339_utc(unix_now()));
    // The record (under the file's lock) is refused when a failing check revoked the connector after this one began.
    if let Some(rec) = &d.record {
        if !EgressVerified::update(&ctx.paths, |v| v.record(rec.clone(), ev.started_s))? {
            d.passed = false;
            d.record = None;
            d.failures.push("a failing check revoked this connector's passes after this check began: nothing recorded (run `ai-env egress check` again)".into());
        }
    }
    let revoked: Option<std::result::Result<usize, String>> = d.revoke.then(|| EgressVerified::update(&ctx.paths, |v| v.revoke_connector(connector, unix_now())).map_err(|e| e.to_string()));
    let verdict = if d.passed { "pass" } else { "fail" };
    let mut pairs = vec![("id", ev.id.clone()), ("image_version", ev.vm_image_version.clone()), ("verdict", verdict.to_string())];
    if let Some(first) = d.failures.first() {
        pairs.push(("reason", first.chars().take(300).collect()));
    }
    match &revoked {
        Some(Ok(n)) => pairs.push(("revoked", n.to_string())),
        Some(Err(_)) => pairs.push(("revoked", "error".to_string())),
        None => {}
    }
    if !ev.own {
        pairs.push(("report_only", "true".to_string()));
    }
    audit_event(&ctx.paths, "egress_check", &pairs);
    let revoked_text = match &revoked {
        Some(Ok(n)) => format!("revoked {n} earlier pass{} of this connector", if *n == 1 { "" } else { "es" }),
        Some(Err(e)) => format!("COULD NOT REVOKE the earlier passes of this connector: {e} (the credential gate cannot read the file either; fix or remove {})", ctx.paths.egress_verified().display()),
        None => String::new(),
    };
    let ok_or = |r: &Option<std::result::Result<String, String>>| match r {
        Some(Ok(s)) => (Some(true), s.clone()),
        Some(Err(e)) => (Some(false), e.clone()),
        None => (None, "not checked".to_string()),
    };
    let (network_ok, network_text) = ok_or(&ev.network);
    let (squid_ok, squid_text) = ok_or(&ev.squid);
    if json {
        let cases: Vec<serde_json::Value> = ev
            .judgement
            .cases
            .iter()
            .map(|c| {
                let r = c.result.clone().unwrap_or_default();
                serde_json::json!({
                    "name": c.name, "group": c.group, "verdict": c.verdict.as_str(), "reason": c.reason, "rc": r.rc, "code": r.code, "size": r.size,
                    "connects": r.conn, "connect_code": r.hc, "t403": r.t403, "squid_error": r.sq, "ns": r.ns, "resolves": r.resolves,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "backend": ctx.backend_name(), "id": ev.id, "report_only": !ev.own, "image_arn": ev.row_image_arn, "image_version": ev.vm_image_version,
            "echoed_image_arn": ev.vm_image_arn, "row_image_version": ev.row_image_version, "connector": normalize_connector(connector),
            "denied_host": ev.denied_host, "finished": ev.judgement.finished, "transcript_error": ev.transcript.as_ref().err(), "cases": cases,
            "dns": ev.judgement.dns, "network": { "ok": network_ok, "detail": network_text }, "squid_log": { "ok": squid_ok, "detail": squid_text },
            "evidence": EVIDENCE_NOTE, "verdict": verdict, "recorded": d.record.is_some(),
            "revoked": revoked.as_ref().map(|r| r.as_ref().map_or_else(|e| serde_json::json!({"error": e}), |n| serde_json::json!(n))), "failures": d.failures,
        });
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        outln!("egress check of {} (image version {}; connector {}){}", ev.id, ev.vm_image_version, normalize_connector(connector), if ev.own { "" } else { " — report only (--vm)" });
        outln!("note: {EVIDENCE_NOTE}");
        for c in &ev.judgement.cases {
            let tag = match c.verdict {
                Verdict::Pass => "pass",
                Verdict::Fail => "FAIL",
                Verdict::Recorded => "recorded",
            };
            outln!("  {tag:<9} {:<19} {}", c.name, c.reason);
        }
        if let Err(e) = &ev.transcript {
            outln!("transcript: {e}");
        }
        outln!("dns: {}", ev.judgement.dns);
        outln!("network: {network_text}");
        outln!("squid log: {squid_text}");
        if d.record.is_some() {
            outln!("egress check passed: recorded for image version {} with {} in {}", ev.vm_image_version, normalize_connector(connector), ctx.paths.egress_verified().display());
        } else if !ev.own {
            outln!("report only: `--vm` never records a pass and never revokes one (`ai-env egress check` without --vm checks a VM of its own and records)");
        }
        if !revoked_text.is_empty() {
            outln!("{revoked_text}");
        }
    }
    if d.passed {
        return Ok(());
    }
    let revoked_part = if revoked_text.is_empty() { String::new() } else { format!(" ({revoked_text})") };
    Err(CliError::Policy(format!("egress check FAILED on {} (nothing recorded){revoked_part}: {}", ev.id, d.failures.join("; "))))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef";

    /// One curl marker: `rc`, HTTP code, connects, the proxy's CONNECT code, curl's 403 text, squid's error header.
    fn curl(name: &str, rc: i32, code: &str, conn: &str, hc: &str, t403: bool, sq: bool) -> String {
        let yn = |b: bool| if b { "yes" } else { "no" };
        format!("@@AIENV{NONCE} {name} rc={rc} code={code} size=0 conn={conn} hc={hc} t403={} sq={}", yn(t403), yn(sq))
    }

    fn dig(name: &str, rc: &str, ns: &str, res: bool) -> String {
        format!("@@AIENV{NONCE} {name} rc={rc} ns={ns} res={}", if res { "yes" } else { "no" })
    }

    /// Every case's marker in a closed, working VPC.
    fn passing() -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = CASES
            .iter()
            .map(|c| {
                let line = match c.name {
                    "allowed" | "allowed-last" => curl(c.name, 0, "401", "1", "200", false, false),
                    "direct-name" => curl(c.name, 6, "000", "0", "000", false, false),
                    "direct-ipv6" => curl(c.name, 7, "000", "0", "000", false, false),
                    "direct-ipv4" | "direct-http" | "proxy-other-port" => curl(c.name, 28, "000", "0", "000", false, false),
                    "imds" | "imds-v6" => curl(c.name, 0, "401", "1", "000", false, false),
                    "proxy-http-8080" => curl(c.name, 0, "403", "1", "000", false, true),
                    n if n.starts_with("proxy-") || n == "denied" => curl(c.name, 56, "000", "1", "403", true, false),
                    n if n.starts_with("dns-public") => dig(n, "9", if n == "dns-public-port" { "208.67.222.222" } else { "1.1.1.1" }, false),
                    n if n.starts_with("dns-platform6") => dig(n, "9", "fd00:ec2::253", false),
                    n if n.starts_with("dns-platform") => dig(n, "9", "169.254.169.253", false),
                    n if n.starts_with("dns-subnet") => dig(n, "9", "10.42.1.2", false),
                    n => dig(n, "9", "10.42.0.2", false),
                };
                (c.name.to_string(), line)
            })
            .collect();
        v.push(("end".to_string(), format!("@@AIENV{NONCE} end")));
        v
    }

    /// A transcript as a terminal returns it: the echoed script (prompts, CRLF), then the markers.
    fn transcript(lines: &[(String, String)]) -> String {
        let echo: String = render_script(NONCE, PROXY_IP).lines().map(|l| format!("bash-5.2# {l}\r\n")).collect();
        let markers: String = lines.iter().map(|(_, l)| format!("{l}\r\n")).collect();
        format!("{echo}{markers}bash-5.2# exit\r\n")
    }

    fn with(name: &str, line: String) -> Vec<(String, String)> {
        passing().into_iter().map(|(k, l)| if k == name { (k, line.clone()) } else { (k, l) }).collect()
    }

    fn judged(lines: &[(String, String)]) -> Judgement {
        judge(&parse_markers(&transcript(lines), NONCE).unwrap())
    }

    fn verdict_of<'a>(j: &'a Judgement, name: &str) -> &'a CaseVerdict {
        j.cases.iter().find(|c| c.name == name).unwrap()
    }

    fn failing(j: &Judgement) -> Vec<&'static str> {
        j.cases.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| c.name).collect()
    }

    #[test]
    fn the_script_is_small_plain_and_never_parses_as_markers() {
        let s = render_script(NONCE, PROXY_IP);
        assert!(s.len() < 4096, "{} bytes: over a terminal's line buffer", s.len());
        assert!(!s.contains('\t') && !s.contains('!'), "no tab (completion) and no ! (history expansion)");
        assert!(s.lines().all(|l| l.len() < 1024), "short lines");
        assert!(s.starts_with("\\unalias -a; unset -f command curl dig printf 2>/dev/null; hash -r; unset HISTFILE; set +H\n") && s.ends_with("\nexit\n"), "{s}");
        assert!(s.contains("command curl -q -sS ") && s.contains("command dig -r "), "no .curlrc, no .digrc, no alias or function");
        assert!(!s.contains(MARK), "the echoed script carries no marker");
        assert_eq!(parse_markers(&s, NONCE).unwrap(), Markers::default(), "the echo of the script is not a marker");
        for c in &CASES {
            let line = s.lines().find(|l| l.split_whitespace().nth(1) == Some(c.name)).unwrap_or_else(|| panic!("{} has no line", c.name));
            assert!(line.starts_with(if c.is_dns() { "aienv_d " } else { "aienv_c " }), "{line}");
            assert!(!line.contains('@'), "every placeholder filled: {line}");
        }
        assert!(s.contains("aienv_d dns-vpc-udp 10.42.0.2\n") && s.contains("aienv_d dns-subnet-tcp 10.42.1.2 +tcp\n") && s.contains("aienv_d dns-platform6-udp fd00:ec2::253\n"), "{s}");
        assert!(s.contains("aienv_d dns-public-port 208.67.222.222 -p 443\n") && s.contains("aienv_c direct-http --noproxy '*' http://1.1.1.1/\n"), "{s}");
        assert!(s.contains(&format!("aienv_c denied https://n{NONCE}.example.com/\n")), "{s}");
        assert!(s.contains("aienv_c proxy-other-port --noproxy '*' http://10.42.0.10:22/\n"));
        // The proxy exports (both spellings, no_proxy) come right before the first case; allowed runs first and last.
        let lines: Vec<&str> = s.lines().collect();
        let export = lines.iter().position(|l| l.starts_with("export ")).unwrap();
        assert_eq!(lines[export], "export https_proxy='http://10.42.0.10:3128' HTTPS_PROXY='http://10.42.0.10:3128' http_proxy='http://10.42.0.10:3128' HTTP_PROXY='http://10.42.0.10:3128' no_proxy='localhost,127.0.0.1,::1' NO_PROXY='localhost,127.0.0.1,::1'");
        assert!(lines[export + 1].starts_with("aienv_c allowed ") && lines[export - 1].starts_with("aienv_d() "), "{s}");
        assert_eq!(s.matches("export ").count(), 1);
        assert!(lines[lines.len() - 3].starts_with("aienv_c allowed-last "), "allowed is the last case too");
        assert!(render_script(NONCE, "10.42.0.99").contains("http://10.42.0.99:3128"), "the configured proxy address");
        // The dns-path script: its cases, in order, nothing else.
        let d = render_dns_script(NONCE, PROXY_IP);
        let names: Vec<&str> = d.lines().filter(|l| l.starts_with("aienv_c ") || l.starts_with("aienv_d ")).filter_map(|l| l.split_whitespace().nth(1)).collect();
        let want: Vec<&str> = CASES.iter().map(|c| c.name).filter(|n| DNS_PATH_CASES.contains(n)).collect();
        assert_eq!(names, want);
        assert_eq!((names.first(), names.last()), (Some(&"allowed"), Some(&"allowed-last")));
        assert!(d.len() < 4096 && d.ends_with("\nexit\n") && d.contains("export https_proxy="));
        assert_eq!(script_budget(CASES.len()), Duration::from_secs(27 * 12 + 30));
    }

    #[test]
    fn nonces_hosts_and_addresses() {
        let a = new_nonce();
        assert!(is_nonce(&a) && a.len() == 16 && a != new_nonce(), "{a}");
        assert!(crate::bridge::egress::is_valid_host(&denied_host(&a)), "the denied host is a valid host");
        assert!(!is_nonce("ABCDEF0123") && !is_nonce("short") && !is_nonce(&"a".repeat(33)) && !is_nonce("0123456789abcdeg"));
        assert_eq!(cidr_plus_two(VM_SUBNET_CIDR).as_deref(), Some("10.42.1.2"));
        assert_eq!(cidr_plus_two(VPC_CIDR).as_deref(), Some("10.42.0.2"));
        assert_eq!(cidr_plus_two("10.42.1.77/24").as_deref(), Some("10.42.1.2"));
        assert_eq!(cidr_plus_two("10.0.0.0/31"), None);
        assert_eq!(cidr_plus_two("nonsense"), None);
        assert!(in_cidr("10.42.1.17", VM_SUBNET_CIDR) && in_cidr("10.42.1.255", VM_SUBNET_CIDR) && !in_cidr("10.42.0.17", VM_SUBNET_CIDR) && !in_cidr("10.42.2.1", VM_SUBNET_CIDR));
        assert!(!in_cidr("fe80::1", VM_SUBNET_CIDR) && !in_cidr("x", VM_SUBNET_CIDR) && in_cidr("1.2.3.4", "0.0.0.0/0") && !in_cidr("10.42.1.1", "bad"));
        assert!(is_server("fe80::1%eth0") && is_server("10.42.0.2") && !is_server("x;y") && !is_server("fe80::1%") && !is_server("10.42.0.2%a b"));
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        assert_eq!(proxy_ip(&BridgeConfig::default(), &paths), PROXY_IP);
        let cfg = BridgeConfig::parse("[aws]\nproxy_private_ip = \"10.42.0.11\"\n").unwrap();
        assert_eq!(proxy_ip(&cfg, &paths), "10.42.0.11");
        let public = BridgeConfig::parse("[aws]\nproxy_private_ip = \"8.8.8.8\"\n").unwrap();
        assert_eq!(proxy_ip(&public, &paths), PROXY_IP, "never a public address");
        assert_eq!(scaled(SQUID_LOG_BUDGET, Some(1)), Duration::from_millis(120));
        assert_eq!(scaled(SQUID_LOG_STEP, None), SQUID_LOG_STEP);
    }

    #[test]
    fn markers_are_parsed_and_the_echo_ignored() {
        let m = parse_markers(&transcript(&passing()), NONCE).unwrap();
        assert!(m.finished);
        assert_eq!(m.cases.len(), CASES.len());
        assert_eq!(
            m.get("allowed").unwrap(),
            &CaseResult { name: "allowed".into(), rc: Some(0), code: Some(401), size: Some(0), conn: Some(1), hc: Some(200), t403: Some(false), sq: Some(false), ..CaseResult::default() }
        );
        assert_eq!(m.get("dns-platform-tcp").unwrap(), &CaseResult { name: "dns-platform-tcp".into(), rc: Some(9), ns: Some("169.254.169.253".into()), resolves: Some(false), ..CaseResult::default() });
        // A marker anywhere in a line (a prompt before it), no resolv.conf nameserver, and an unreported connect count.
        let none = parse_markers(&format!("x# {}\n{}\n", dig("dns-resolv-udp", "none", "none", false), curl("imds", 127, "000", "-", "000", false, false)), NONCE).unwrap();
        assert_eq!(none.get("dns-resolv-udp").unwrap(), &CaseResult { name: "dns-resolv-udp".into(), resolves: Some(false), ..CaseResult::default() });
        assert_eq!(none.get("imds").unwrap().conn, None);
        assert!(!none.finished);
        assert_eq!(parse_markers("", NONCE).unwrap(), Markers::default());
    }

    #[test]
    fn malformed_markers_are_refused() {
        let other = "fedcba9876543210";
        let ok = curl("allowed", 0, "401", "1", "200", false, false);
        let bad = [
            (ok.replace(NONCE, other), "another run"),
            (format!("{ok}\n{ok}"), "twice"),
            (format!("@@AIENV{NONCE} nope rc=0"), "unknown case"),
            (format!("@@AIENV{NONCE} end\n@@AIENV{NONCE} end"), "end marker twice"),
            (format!("@@AIENV{NONCE} end now"), "end marker carries"),
            (format!("@@AIENV{NONCE}"), "without a case"),
            (ok.replace(" sq=no", ""), "sq field is missing"),
            (ok.replace(" conn=1", ""), "conn field is missing"),
            (ok.replace("code=401", "code=41"), "bad code"),
            (ok.replace("hc=200", "hc=2x0"), "bad hc"),
            (ok.replace("conn=1", "conn=x"), "bad conn"),
            (ok.replace("rc=0", "rc=x"), "bad rc"),
            (ok.replace("rc=0", "rc=none"), "bad rc"),
            (ok.replace("size=0", "size=-1"), "bad size"),
            (ok.replace("t403=no", "t403=maybe"), "yes|no"),
            (ok.replace("rc=0", "rc=0 rc=0"), "rc twice"),
            (format!("{ok} body=x"), "unexpected field"),
            (format!("{ok} ns=1.1.1.1"), "unexpected field"),
            (format!("{ok} junk"), "not key=value"),
            (dig("dns-platform-udp", "9", "evil;rm", false), "bad ns"),
            (format!("{} code=401", dig("dns-platform-udp", "9", "169.254.169.253", false)), "unexpected field"),
            (dig("dns-platform-udp", "none", "169.254.169.253", false), "disagree"),
            (dig("dns-platform-udp", "9", "none", false), "disagree"),
            (format!("{ok} {}", curl("denied", 56, "000", "1", "403", true, false)), "two markers"),
        ];
        for (text, why) in bad {
            let e = parse_markers(&text, NONCE).unwrap_err();
            assert!(e.contains(why), "{text:?}: {e}");
        }
        assert!(parse_markers("x", "NOTANONCE").is_err(), "a bad nonce");
        // The transcript never reaches an error text beyond a short token.
        let long = format!("@@AIENV{NONCE} {}", "y".repeat(500));
        assert!(parse_markers(&long, NONCE).unwrap_err().len() < 100);
    }

    #[test]
    fn a_closed_vpc_passes_and_records_no_dns() {
        let j = judged(&passing());
        assert!(j.passed(), "{:?}", j.failures());
        assert_eq!(j.dns, "no-dns");
        assert_eq!(verdict_of(&j, "imds").verdict, Verdict::Recorded);
        assert!(j.summary().starts_with("allowed=pass direct-name=pass") && j.summary().contains("imds=recorded:401") && j.summary().ends_with("allowed-last=pass"), "{}", j.summary());
        assert!(j.failures().is_empty());
    }

    #[test]
    fn each_case_fails_on_what_would_open_it() {
        let fails = [
            ("direct-name", curl("direct-name", 0, "401", "1", "000", false, false), "OPEN"),
            // Exit 28 after a connection (a TLS handshake that hung): connected, so open.
            ("direct-ipv4", curl("direct-ipv4", 28, "000", "1", "000", false, false), "OPEN: curl reached"),
            ("direct-http", curl("direct-http", 60, "000", "1", "000", false, false), "OPEN"),
            ("direct-ipv4", curl("direct-ipv4", 28, "000", "-", "000", false, false), "no connect count"),
            ("direct-ipv6", curl("direct-ipv6", 127, "000", "0", "000", false, false), "did not run"),
            ("dns-public-udp", dig("dns-public-udp", "0", "1.1.1.1", false), "1.1.1.1, not a platform resolver, replied"),
            ("dns-public-port", dig("dns-public-port", "0", "208.67.222.222", false), "not a platform resolver"),
            ("dns-public-tcp", dig("dns-public-tcp", "0", "1.1.1.1", true), "resolved example.com"),
            ("dns-resolv-udp", dig("dns-resolv-udp", "0", "9.9.9.9", false), "9.9.9.9, not a platform resolver"),
            ("dns-resolv-tcp", dig("dns-resolv-tcp", "0", "127.0.0.53", false), "127.0.0.53, not a platform resolver"),
            ("dns-platform-udp", dig("dns-platform-udp", "0", "169.254.169.253", true), "OPEN: 169.254.169.253 resolved"),
            ("dns-platform6-tcp", dig("dns-platform6-tcp", "0", "fd00:ec2::253", true), "OPEN: fd00:ec2::253 resolved"),
            ("dns-subnet-tcp", dig("dns-subnet-tcp", "10", "10.42.1.2", false), "dig exited 10"),
            ("proxy-other-port", curl("proxy-other-port", 7, "000", "0", "000", false, false), "reached the proxy host"),
            ("proxy-other-port", curl("proxy-other-port", 28, "000", "1", "000", false, false), "OPEN"),
            ("proxy-other-port", curl("proxy-other-port", 0, "200", "1", "000", false, false), "OPEN"),
            ("proxy-ip-literal", curl("proxy-ip-literal", 0, "200", "1", "200", false, false), "opened a tunnel"),
            ("proxy-github", curl("proxy-github", 0, "200", "1", "200", false, false), "github.com --remove"),
            // curl's 403 text without the proxy's CONNECT 403, and the other way round: not squid's refusal.
            ("proxy-connect-8443", curl("proxy-connect-8443", 56, "000", "1", "000", true, false), "no 403"),
            ("denied", curl("denied", 56, "000", "1", "403", false, false), "no 403"),
            ("denied", curl("denied", 7, "000", "0", "000", false, false), "no 403"),
            ("proxy-http-8080", curl("proxy-http-8080", 0, "200", "1", "000", false, false), "plain-http"),
            ("proxy-http-8080", curl("proxy-http-8080", 0, "403", "1", "000", false, false), "not the proxy's refusal"),
        ];
        for (name, line, why) in fails {
            let j = judged(&with(name, line.clone()));
            let v = verdict_of(&j, name);
            assert_eq!(v.verdict, Verdict::Fail, "{line}");
            assert!(v.reason.contains(why), "{name}: {}", v.reason);
            assert!(!j.passed());
            assert!(j.failures().iter().any(|f| f.starts_with(&format!("{name}: "))), "{:?}", j.failures());
            assert_eq!(failing(&j), [name], "only {name} fails: {:?}", j.failures());
        }
        // A public resolver that replies makes the run's DNS verdict open-dns.
        assert_eq!(judged(&with("dns-public-udp", dig("dns-public-udp", "0", "1.1.1.1", false))).dns, "open-dns:1.1.1.1");
        // A platform resolver that resolves fails, and the run's DNS verdict says so.
        assert_eq!(judged(&with("dns-platform-udp", dig("dns-platform-udp", "0", "169.254.169.253", true))).dns, "platform-dns-resolves:169.254.169.253");
        // The platform resolver replying without resolving (DNS Firewall) passes, and is the run's DNS verdict.
        let j = judged(&with("dns-platform-udp", dig("dns-platform-udp", "0", "169.254.169.253", false)));
        assert!(j.passed(), "{:?}", j.failures());
        assert_eq!(j.dns, "platform-dns:169.254.169.253");
        // So does a private resolv.conf nameserver; and none at all.
        assert!(judged(&with("dns-resolv-udp", dig("dns-resolv-udp", "0", "10.42.0.2", false))).passed());
        let j = judged(&with("dns-resolv-udp", dig("dns-resolv-udp", "none", "none", false)));
        assert!(j.passed() && verdict_of(&j, "dns-resolv-udp").reason.contains("not asked"));
    }

    #[test]
    fn allowed_failing_first_or_last_voids_the_closed_cases() {
        for name in ALLOWED_CASES {
            for line in [curl(name, 7, "000", "0", "000", false, false), curl(name, 56, "000", "1", "403", true, false), curl(name, 0, "200", "1", "200", false, false), curl(name, 0, "401", "1", "000", false, false)] {
                let j = judged(&with(name, line.clone()));
                assert!(!j.passed());
                for c in &j.cases {
                    let expect_fail = c.name == name || matches!(case(c.name).unwrap().kind, Kind::Direct | Kind::OtherPort | Kind::Dns(_));
                    assert_eq!(c.verdict == Verdict::Fail, expect_fail, "{line}: {} {:?} {}", c.name, c.verdict, c.reason);
                    if expect_fail && c.name != name {
                        assert!(c.reason.contains("not counted: `allowed` and `allowed-last` did not both pass"), "{}", c.reason);
                    }
                }
            }
        }
        let dead = judged(&with("allowed-last", curl("allowed-last", 28, "000", "0", "000", false, false)));
        assert!(verdict_of(&dead, "allowed-last").reason.contains("make proxy-start"));
        let refused = judged(&with("allowed", curl("allowed", 56, "000", "1", "403", true, false)));
        assert!(verdict_of(&refused, "allowed").reason.contains("CONNECT 403"));
        let no_tunnel = judged(&with("allowed", curl("allowed", 0, "401", "1", "000", false, false)));
        assert!(verdict_of(&no_tunnel, "allowed").reason.contains("a tunnel the proxy opened"), "a 401 not through the proxy's tunnel");
    }

    #[test]
    fn missing_cases_and_an_unfinished_script_fail() {
        let some: Vec<(String, String)> = passing().into_iter().filter(|(k, _)| k != "dns-vpc-tcp").collect();
        let j = judged(&some);
        assert!(!j.passed());
        assert!(verdict_of(&j, "dns-vpc-tcp").reason.contains("no result"));
        let unfinished: Vec<(String, String)> = passing().into_iter().filter(|(k, _)| k != "end").collect();
        let j = judged(&unfinished);
        assert!(!j.passed() && j.cases.iter().all(|c| c.verdict != Verdict::Fail));
        assert_eq!(j.failures(), ["the script did not finish (no end marker)"]);
        let nothing = judge(&Markers::default());
        assert!(!nothing.passed() && nothing.failures().len() == CASES.len() + 1);
        assert!(nothing.dns.starts_with("unknown ("), "{}", nothing.dns);
    }

    #[test]
    fn the_dns_path_outcome() {
        let only = |lines: Vec<(String, String)>| -> Markers {
            let keep: Vec<(String, String)> = lines.into_iter().filter(|(k, _)| k == "end" || DNS_PATH_CASES.contains(&k.as_str())).collect();
            parse_markers(&keep.iter().map(|(_, l)| format!("{l}\n")).collect::<String>(), NONCE).unwrap()
        };
        let (v, note) = dns_path_outcome(&only(passing())).unwrap();
        assert_eq!(v, "no-dns");
        assert!(note.starts_with("resolves=no resolv.conf nameserver 10.42.0.2;") && note.ends_with("; the proxy answered before and after (allowed, allowed-last: HTTP 401)"), "{note}");
        let (v, note) = dns_path_outcome(&only(with("dns-subnet-udp", dig("dns-subnet-udp", "0", "10.42.1.2", true)))).unwrap();
        assert_eq!(v, "platform-dns-resolves:10.42.1.2", "a platform resolver that resolves names: never plain platform-dns");
        assert!(note.starts_with("resolves=yes"), "{note}");
        let (v, _) = dns_path_outcome(&only(with("dns-subnet-udp", dig("dns-subnet-udp", "0", "10.42.1.2", false)))).unwrap();
        assert_eq!(v, "platform-dns:10.42.1.2", "answers without resolving (DNS Firewall)");
        let (v, _) = dns_path_outcome(&only(with("dns-public-tcp", dig("dns-public-tcp", "0", "1.1.1.1", false)))).unwrap();
        assert_eq!(v, "open-dns:1.1.1.1", "a public resolver that replies is open DNS, never platform DNS");
        let (v, _) = dns_path_outcome(&only(with("dns-resolv-udp", dig("dns-resolv-udp", "0", "9.9.9.9", false)))).unwrap();
        assert_eq!(v, "open-dns:9.9.9.9");
        for name in ALLOWED_CASES {
            let dead = dns_path_outcome(&only(with(name, curl(name, 28, "000", "0", "000", false, false)))).unwrap_err();
            assert!(dead.contains("proves nothing") && dead.contains(name), "{dead}");
        }
        let unfinished: Vec<(String, String)> = passing().into_iter().filter(|(k, _)| k != "end").collect();
        assert!(dns_path_outcome(&only(unfinished)).unwrap_err().contains("did not finish"));
        let missing: Vec<(String, String)> = passing().into_iter().filter(|(k, _)| k != "dns-vpc-udp").collect();
        assert!(dns_path_outcome(&only(missing)).unwrap_err().contains("dns-vpc-udp"));
        assert!(dns_path_outcome(&only(with("dns-platform-udp", dig("dns-platform-udp", "127", "169.254.169.253", false)))).unwrap_err().contains("exited 127"));
    }

    /// squid's log of a passing run from client `c` at time `t`, the nonce host's line included.
    fn squid_run(c: &str, t: u64) -> Vec<String> {
        let host = denied_host(NONCE);
        let l = |code: &str, method: &str, dest: &str| format!("aienv {t}.123 5 {c} {code} 3900 {method} {dest}");
        vec![
            l("TCP_TUNNEL/200", "CONNECT", "api.anthropic.com:443"),
            l("TCP_DENIED/403", "CONNECT", "1.1.1.1:443"),
            l("TCP_DENIED/403", "GET", "api.anthropic.com:8080"),
            l("TCP_DENIED/403", "CONNECT", "api.anthropic.com:8443"),
            l("TCP_DENIED/403", "CONNECT", "github.com:443"),
            l("TCP_DENIED/403", "CONNECT", &format!("{host}:443")),
            l("TCP_TUNNEL/200", "CONNECT", "api.anthropic.com:443"),
        ]
    }

    fn lines_of(msgs: &[String]) -> Vec<SquidLine> {
        let doc = serde_json::json!({"events": msgs.iter().map(|m| serde_json::json!({"message": m, "logStreamName": "i-0abc"})).collect::<Vec<_>>(), "searchedLogStreams": []});
        squid_lines(&doc).unwrap()
    }

    #[test]
    fn squid_evidence_needs_every_line_from_the_runs_client_in_its_window() {
        let t = 1_790_000_000;
        let ev = |msgs: &[String]| squid_evidence(&lines_of(msgs), NONCE, t - 60, t + 60, 2);
        let SquidEvidence::Complete(found) = ev(&squid_run("10.42.1.17", t)) else { panic!("{:?}", ev(&squid_run("10.42.1.17", t))) };
        assert!(found.starts_with("from 10.42.1.17: 2 tunnels to api.anthropic.com:443") && found.contains("GET api.anthropic.com:8080"), "{found}");
        assert!(squid_lines(&serde_json::json!({})).is_err());
        assert_eq!(lines_of(&["some other line".to_string()]).len(), 0, "other lines are skipped");
        // Each required line missing: named, not complete (the poll keeps asking).
        for (i, want) in [(0usize, "2 × TCP_TUNNEL/200"), (1, "CONNECT 1.1.1.1:443"), (2, "GET api.anthropic.com:8080"), (3, "api.anthropic.com:8443"), (4, "github.com:443")] {
            let mut msgs = squid_run("10.42.1.17", t);
            msgs.remove(i);
            match ev(&msgs) {
                SquidEvidence::Missing(m) => assert!(m.iter().any(|x| x.contains(want)), "{want}: {m:?}"),
                other => panic!("{want}: {other:?}"),
            }
        }
        // The run's nonce line missing, outside the window, or another client's lines only: missing.
        let mut no_nonce = squid_run("10.42.1.17", t);
        no_nonce.remove(5);
        assert!(matches!(ev(&no_nonce), SquidEvidence::Missing(m) if m[0].contains(&denied_host(NONCE))));
        assert!(matches!(ev(&squid_run("10.42.1.17", t + 3600)), SquidEvidence::Missing(_)), "outside the window");
        let mut other_client = squid_run("10.42.1.17", t);
        for l in &mut other_client[..5] {
            *l = l.replace("10.42.1.17", "10.42.1.18");
        }
        assert!(matches!(ev(&other_client), SquidEvidence::Missing(_)), "the evidence must come from the run's client");
        // Violations: the nonce host tunnelled or let through, a request from outside the VM subnet, a tunnel to a refused host.
        let mut tunnelled = squid_run("10.42.1.17", t);
        tunnelled.push(format!("aienv {t}.500 9 10.42.1.17 TCP_TUNNEL/200 5000 CONNECT {}:443", denied_host(NONCE)));
        assert!(matches!(ev(&tunnelled), SquidEvidence::Violation(v) if v.contains("let the run's denied host through")));
        assert!(matches!(ev(&squid_run("10.42.0.99", t)), SquidEvidence::Violation(v) if v.contains("outside the VM subnet")));
        for host in ["github.com:443", "github.com:8443", "1.1.1.1:443", "api.anthropic.com:8443", "api.anthropic.com:8080"] {
            let mut msgs = squid_run("10.42.1.17", t);
            msgs.push(format!("aienv {t}.900 9 10.42.1.17 TCP_TUNNEL/200 5000 CONNECT {host}"));
            assert!(matches!(ev(&msgs), SquidEvidence::Violation(v) if v.contains("tunnels to hosts this run was refused")), "{host}");
        }
        // Another client's tunnel to github.com in the window is not this run's.
        let mut others = squid_run("10.42.1.17", t);
        others.push(format!("aienv {t}.900 9 10.42.1.30 TCP_TUNNEL/200 5000 CONNECT github.com:443"));
        assert!(matches!(ev(&others), SquidEvidence::Complete(_)));
        // Zero tunnels is never a pass.
        let no_tunnels: Vec<String> = squid_run("10.42.1.17", t).into_iter().filter(|l| !l.contains("TCP_TUNNEL")).collect();
        assert!(matches!(ev(&no_tunnels), SquidEvidence::Missing(m) if m[0].contains("(0 found)")));
        // Every CONNECT case the proxy must refuse, and the plain-http one, is a required squid line.
        let refused = refused_requests(NONCE);
        for c in CASES.iter().filter(|c| matches!(c.kind, Kind::Connect403 | Kind::Get403)) {
            let url = c.args.replace("@H@", &denied_host(NONCE));
            let (scheme, rest) = url.split_once("://").unwrap();
            let hostport = rest.trim_end_matches('/');
            let (h, p) = hostport.rsplit_once(':').map_or((hostport, if scheme == "https" { 443 } else { 80 }), |(h, p)| (h, p.parse::<u16>().unwrap()));
            let method = if scheme == "https" { "CONNECT" } else { "GET" };
            assert!(refused.iter().any(|(m, rh, rp)| *m == method && rh == h && *rp == p), "{}: {method} {h}:{p}", c.name);
        }
    }

    fn evidence(lines: &[(String, String)]) -> Evidence {
        Evidence {
            id: "microvm-00000000-0000-4000-8000-000000000001".into(),
            own: true,
            row_image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            row_image_version: "1.0".into(),
            vm_image_arn: crate::bridge::api::FAKE_IMAGE_ARN.into(),
            vm_image_version: "1.0".into(),
            judgement: judged(lines),
            transcript: Ok(()),
            network: Some(Ok("21 checks ok: connector, vm-route-table".into())),
            squid: Some(Ok("from 10.42.1.17: 2 tunnels".into())),
            connector_facts: Some(Ok(facts())),
            image_created_at: Some(Ok(1_789_804_800)),
            started_s: 1_790_000_000,
            denied_host: denied_host(NONCE),
        }
    }

    fn facts() -> ConnectorFacts {
        ConnectorFacts { id: "nc-0a1b2c3d4e5f60718".into(), version: "1".into(), subnet_ids: vec!["subnet-0aaa1111bbbb2222c".into()], security_group_ids: vec!["sg-0ddd3333eeee4444f".into()] }
    }

    const CONN: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    #[test]
    fn decide_records_a_full_pass_of_its_own_vm_only() {
        let ev = evidence(&passing());
        let d = decide(&ev, &format!("{CONN}:3"), "2026-10-01T10:00:00Z");
        assert!(d.passed && !d.revoke && d.failures.is_empty(), "{:?}", d.failures);
        let rec = d.record.unwrap();
        assert_eq!((rec.image_arn.as_str(), rec.image_version.as_str(), rec.connector.as_str(), rec.vm_id.as_str()), (crate::bridge::api::FAKE_IMAGE_ARN, "1.0", CONN, ev.id.as_str()));
        assert_eq!((rec.dns.as_str(), rec.network.as_str(), rec.squid_log.as_str(), rec.at.as_str()), ("no-dns", "21 checks ok: connector, vm-route-table", "from 10.42.1.17: 2 tunnels", "2026-10-01T10:00:00Z"));
        assert!(rec.cases.contains("denied=pass"));
        assert_eq!((rec.connector_facts.clone(), rec.image_created_at), (facts(), Some(1_789_804_800)), "bound to the connector's live facts and the image build");
        // --vm needs no binding (it records nothing).
        let d = decide(&Evidence { own: false, connector_facts: None, image_created_at: None, ..ev.clone() }, CONN, "t");
        assert!(d.passed && d.record.is_none());
        // --vm: the same evidence, report only.
        let d = decide(&Evidence { own: false, ..ev.clone() }, CONN, "t");
        assert!(d.passed && d.record.is_none() && !d.revoke);
    }

    #[test]
    fn decide_never_records_and_revokes_on_any_failure() {
        let base = evidence(&passing());
        let failing_cases = evidence(&with("direct-ipv4", curl("direct-ipv4", 0, "200", "1", "000", false, false)));
        let cases_ok_squid = |squid| Evidence { squid, ..base.clone() };
        let variants: Vec<(Evidence, &str)> = vec![
            (failing_cases, "direct-ipv4: OPEN"),
            (Evidence { transcript: Err("case allowed twice".into()), ..base.clone() }, "the transcript could not be read"),
            (Evidence { network: Some(Err("DRIFT vm-sg: unexpected tcp 443".into())), squid: None, ..base.clone() }, "network verification: DRIFT vm-sg"),
            (Evidence { network: Some(Err("unknown proxy-ssm: Offline".into())), squid: None, ..base.clone() }, "network verification: unknown"),
            (Evidence { network: None, squid: None, ..base.clone() }, "network verification: not run"),
            (cases_ok_squid(Some(Err("not in squid's log within 120 s".into()))), "squid log: not in squid's log"),
            (cases_ok_squid(None), "squid log: not checked"),
            (Evidence { vm_image_version: "2.0".into(), ..base.clone() }, "echoed image"),
            (Evidence { vm_image_arn: "arn:aws:lambda:eu-central-1:123456789012:microvm-image:other".into(), ..base.clone() }, "echoed image"),
        ];
        for (ev, why) in variants {
            let d = decide(&ev, CONN, "t");
            assert!(!d.passed && d.record.is_none() && d.revoke, "{why}: {d:?}");
            assert!(d.failures.iter().any(|f| f.contains(why)), "{why}: {:?}", d.failures);
            let report_only = decide(&Evidence { own: false, ..ev }, CONN, "t");
            assert!(!report_only.passed && report_only.record.is_none() && !report_only.revoke, "--vm never revokes: {why}");
        }
        // Nothing to bind the record to: the check of its own VM fails (and revokes); --vm, which records nothing, does not need it.
        let unbound = [
            (Evidence { connector_facts: None, ..base.clone() }, "the connector's facts were not read"),
            (Evidence { connector_facts: Some(Err("AccessDenied".into())), ..base.clone() }, "the connector's facts could not be read: AccessDenied"),
            (Evidence { connector_facts: Some(Ok(ConnectorFacts { security_group_ids: vec![], ..facts() })), ..base.clone() }, "facts are incomplete"),
            (Evidence { image_created_at: None, ..base.clone() }, "created_at was not read"),
            (Evidence { image_created_at: Some(Err("version 1.0 is not listed".into())), ..base.clone() }, "created_at could not be read"),
        ];
        for (ev, why) in unbound {
            let d = decide(&ev, CONN, "t");
            assert!(!d.passed && d.record.is_none() && d.revoke, "{why}: {d:?}");
            assert!(d.failures.iter().any(|f| f.contains(why)), "{why}: {:?}", d.failures);
            assert!(decide(&Evidence { own: false, ..ev }, CONN, "t").passed, "{why}");
        }
        // A failed transcript is one failure, not one per case.
        let d = decide(&Evidence { transcript: Err("x".into()), judgement: judge(&Markers::default()), squid: None, ..base }, CONN, "t");
        assert_eq!(d.failures, ["the transcript could not be read: x"]);
    }
}
