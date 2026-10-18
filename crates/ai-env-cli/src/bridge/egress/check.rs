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
//! those hosts that can be the run's (every VM shares the connector's
//! address: a tunnel to github.com that squid logged before the run's own
//! refusal is an earlier run's) ([`squid_evidence`]). Only a VM the check started itself
//! (purpose `test`, label `egress-check`, no workspace) can record; `--vm`
//! is report-only (it never records and never revokes). A record is bound
//! to what the credential gate reads live again: the connector's facts
//! (Id, network protocol, subnet, security group, and Version when the
//! answer carries one) from the very `get-network-connector` answer the
//! network verification judged, and the image version's `created_at`;
//! without them nothing is recorded. It is refused when a failing check
//! revoked the connector after this check began. `--if-needed` starts
//! nothing when the version a new VM runs (`[aws].image_version` resolved
//! live, as RunMicrovm does) already has such a pass, bound to that build and
//! to the connector's live facts, and judged by the current DNS and egress
//! rules (`egress::DNS_RULE`, `egress::EGRESS_RULE`: a pass recorded before
//! either never counts, and the check runs again, saying why) (`make
//! claude-update`).
//!
//! **Allowlisted hosts.** github.com (`proxy-github`, [`ALLOWLISTABLE`]) is
//! a host the proxy refuses until an operator allowlists it (`ai-env egress
//! allow SLUG github.com`). The check judges it by what squid serves: the
//! effective allowlist ((allow ∪ extras) − suspended,
//! `egress::effective_hosts`) of the very parameter values the network
//! verification proved against the proxy's `--status` line (its
//! `parameters` row ok, and the line saying squid serves them: active,
//! parse ok, `applied=yes`), read after the cases ran. While that list
//! holds the host, its case is recorded, not judged
//! (`proxy-github=recorded:allowlisted`), squid's log need not show it
//! refused (its tunnel on 443 is no violation), and the report, the audit
//! row and the record name it (`allowlisted`: the record does not show it
//! refused). A case with no result is judged all the same, and fails. A
//! removal during the check fails closed (the case is judged, and OPEN);
//! an addition only keeps the record from claiming the host refused;
//! without a proven list every case is judged strictly. An IP literal,
//! another port, plain http and the run's nonce host are never
//! allowlisted.
//!
//! **Revocation.** Once a check has asked for its own VM — RunMicrovm made
//! one, or may have (a pending row) — any failure but Ctrl-C revokes every
//! record of the connector (all images) and is audited `egress_check {id,
//! image_version, verdict=fail, reason, revoked}`: a failing case, the
//! network or squid's log, a missing binding, and also a failure before the
//! transcript is judged — the VM's egress gate, `/health`, the shell token or
//! dial, the fake's refusal. A failure before that (the configuration, the
//! operator's account, a proxy that is not running, the backend, a refusal
//! before RunMicrovm such as `[vm].max_concurrent`) revokes nothing.
//!
//! **The S3 cases** (S9, §7.7). Five cases of group `s3` probe the
//! transcripts bucket (`state/infra.toml`'s, resolved before the check asks
//! for its VM) through the proxy, judged on S3's status and `<Code>`, never
//! its wording. `s3-own` and `s3-own-outside-prefix` use URLs the Mac
//! presigns with the runtime key; the script reads them on its stdin, and the
//! Mac types them only once the script, its terminal's echo off, asks
//! ([`run_check_script`]). The two fronting cases count only when the Mac
//! read [`FRONT_OBJECT_BUCKET`]'s object anonymously first ([`front_object`]);
//! `s3-imds-role` signs with the check VM's own role credentials, and is
//! recorded `no_role` only when that VM runs without an execution role
//! ([`S3Facts`]).
//!
//! The script ([`render_script`]) is rendered on the Mac, the proxy exports
//! of [`proxy_env`] included (the VM's `ai-env` has no `egress` command),
//! and sent through the scripted shell ([`run_check_script`]) after the VM's
//! `/health` answered; it ends with `exit`. It drops aliases and
//! shell functions, calls `command curl -q` (no `.curlrc`) and `command dig
//! -r` (no `.digrc`), and each case prints one marker line,
//! `@@AIENV<nonce> <case> rc=… code=… size=… conn=… hc=… t403=… sq=…`
//! (curl: exit code, HTTP code, body size with `-o /dev/null`, connects
//! made, the proxy's CONNECT answer, whether curl said [`CONNECT_403`],
//! whether squid's `X-Squid-Error: ERR_ACCESS_DENIED` came) or `… rc=… ns=…
//! res=… st=… ra=… an=… au=…` (dig, asking the run's fresh name
//! [`dns_name`], which exists nowhere, and example.com of a server that
//! replied: exit code, server, whether an address came back, and of the
//! fresh name's reply its status (`NOEXAMPLE` instead when example.com got no
//! reply), recursion flag, ANSWER and AUTHORITY counts) — never a body,
//! header value, record, token or IMDS answer.
//! Markers are built at run time
//! (`printf '%s%s …' '@@' "$R"`), so the shell's echo of the script never
//! parses as one ([`parse_markers`]). The transcript itself is never
//! printed, logged or persisted. [`judge_with`] is pure; `allowed` runs first and
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
//! the egress gate, the operator's credentials of another account, a
//! `state/infra.toml` naming other proxy documents than this ai-env sends);
//! 3 Ctrl-C (the check's VM is terminated; nothing recorded or revoked).
//! S8 operators: the operator identity (`ai-env as …`, else
//! `credentials/ops.env` and its Touch ID, before the runtime key's) is
//! resolved right after the connector; without one the check is exit 5, and
//! its refusals keep their class.
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo, VmState};
use crate::bridge::awscli;
use crate::bridge::config::{is_rfc1918, BridgeConfig, Paths};
use crate::bridge::egress::{dns_accepted, is_aws_service_host, is_valid_host, normalize_connector, parse_squid_line, proxy_env, ConnectorFacts, EgressVerified, SquidLine, VerifiedRecord, DNS_RULE, EGRESS_RULE, LOG_GROUP, PROXY_IP, PROXY_PORT, VM_SUBNET_CIDR, VPC_CIDR};
use crate::bridge::errors::BridgeError;
use crate::bridge::identity;
use crate::bridge::infra::read_infra_state;
use crate::bridge::probes::{is_empty_noerror, is_platform_resolver, verdict_dns_path, DnsReply, DNS_NO_EXAMPLE, DNS_NO_EXAMPLE_SAID};
use crate::bridge::transport::ShellAuth;
use crate::bridge::vm::cmd::{audit_event, backend, runtime, with_backend, Backend, Ctx};
use crate::bridge::vm::registry::{self, RowStatus, VmRow, GATE_PASSED};
use crate::bridge::vm::{health, run, shell};
use crate::errors::{CliError, Result};
use crate::outln;
use crate::store::Keystore;
use crate::wire::redact::Secret;
use crate::wire::time::{rfc3339_utc, unix_now};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

// ---- the cases --------------------------------------------------------------------------------

/// Every marker line starts with this, then the run's nonce.
const MARK: &str = "@@AIENV";
/// What curl prints when the proxy refuses a CONNECT with 403. Its exit code
/// changed (56 up to curl 8.19, 7 from 8.20); the text did not.
pub const CONNECT_403: &str = "CONNECT tunnel failed, response 403";
/// Each case's share of the script budget: curl's `--max-time 10` (dig's
/// `+time=2 +tries=1` is shorter) and slack.
pub const CASE_BUDGET: Duration = Duration::from_secs(12);
/// The check's own VM: `vm run --egress vpc --shell --max-duration 900`.
pub const CHECK_MAX_DURATION_S: u32 = 900;
/// How long the script waits, before its first case, for the VM to reach
/// the proxy's port at all (a plain TCP connection, retried every 2 s):
/// measured 1 Oct 2026, a VM's VPC egress may come up after its shell — the
/// first `allowed` failed with rc 7 and no connection, every later proxied
/// case of the same run passed. The wait only delays the cases: `allowed`
/// and `allowed-last` must still both pass.
pub const READY_WAIT_S: u64 = 60;
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
/// What the note of a dns-path row says when [`FAKE_SHELL_KNOB`] stood in for
/// the VM's shell: that row proves nothing about the network, so the readers
/// of the newest dns-path verdict (`egress::newest_dns_path_row`: the
/// credential gate, doctor, the `true` warning) skip it, and `lab run
/// --note` may not carry it.
pub const FAKE_SHELL_NOTE: &str = "LAB KNOB: transcript from AI_ENV_BRIDGE_LAB_FAKE_SHELL";

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
    /// A presigned PUT then GET of our bucket's `v1/_egress-check/<nonce>`
    /// through the proxy: both 200 (CONNECT 200). The GET's 200 proves the
    /// proxy's S3 traffic goes through the gateway endpoint — the bucket
    /// policy refuses reads outside it (§7.4). The URLs reach the script on
    /// its stdin (`AIENV_U`), and curl's argv only inside the check's VM (its
    /// own, or the `--shell` VM `--vm` names), which runs no agent.
    S3Own,
    /// Through the proxy to our bucket's host, a request the endpoint policy
    /// or IAM must refuse with S3 status 403 and `<Code>` `AccessDenied` (its
    /// code, never its wording): a fronting GET of a public object
    /// ([`S3Req::Get`]: it counts only when the Mac read that object
    /// anonymously first, [`S3Facts::front`]), or a presigned PUT outside the
    /// `v1/` prefix ([`S3Req::Put`]). The tunnel must open first (CONNECT
    /// 200): a 403 from the endpoint, not squid.
    S3Denied(S3Req),
    /// The check VM's own role credentials (AccessKeyId, SecretAccessKey and
    /// Token from IMDSv2, never on an argv or printed) sign (`curl
    /// --aws-sigv4`) a PUT of `v1/_egress-check/<nonce>` through the proxy:
    /// the same 403 `AccessDenied` (the endpoint policy admits only the
    /// runtime user). When IMDS gave no credentials (its `s3=` says `noimds`,
    /// `norole` or `nocreds`): `recorded:no_role` if the check VM runs without
    /// an execution role ([`S3Facts::has_role`]: nothing to try), else a
    /// failure (the role was never tried).
    S3ImdsRole,
}

/// Which request an [`Kind::S3Denied`] case makes (the marker field it
/// reports its status in: `get` or `put`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum S3Req {
    Get,
    Put,
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
    /// the subnet's +2): no reply passes; a reply passes only as the empty
    /// NOERROR the platform's stub gives (no answer, no authority section:
    /// `probes::is_empty_noerror`) to the run's fresh name, and a reply to
    /// example.com A without an address. Anything else fails: an address (a
    /// path out), an SOA (a recursor that went upstream), another status (the
    /// platform is not what was tested), no reply to example.com (the stub
    /// answers both at once). Blind spot: a forwarder that strips the SOA and
    /// answers example.com without an address (whatever that reply's status:
    /// only its address is read). The run's DNS verdict names the replying
    /// servers, and only `[egress].accept_platform_dns` accepts them.
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
        matches!(self.kind, Kind::Allowed | Kind::Connect403 | Kind::Get403 | Kind::S3Own | Kind::S3Denied(_) | Kind::S3ImdsRole)
    }

    fn is_dns(&self) -> bool {
        matches!(self.kind, Kind::Dns(_))
    }

    /// An S3 case (its marker reports [`S3_FIELDS`], not curl's or dig's).
    fn is_s3(&self) -> bool {
        matches!(self.kind, Kind::S3Own | Kind::S3Denied(_) | Kind::S3ImdsRole)
    }

    /// Counted only when the run's `allowed` cases passed (non-vacuous).
    fn needs_allowed(&self) -> bool {
        matches!(self.kind, Kind::Direct | Kind::OtherPort | Kind::Dns(_))
    }

    /// A fronting case: counted only when the Mac read [`FRONT_OBJECT_BUCKET`]'s object anonymously ([`S3Facts::front`]).
    fn fronts(&self) -> bool {
        self.kind == Kind::S3Denied(S3Req::Get)
    }

    /// It asks the transcripts bucket (its host or a presigned URL), so only a full check renders it ([`render_cases`]).
    fn needs_bucket(&self) -> bool {
        self.is_s3() || self.args.contains("@B@")
    }
}

/// The two liveness cases: the VM reaches the proxy before everything else
/// and after it.
pub const ALLOWED_CASES: [&str; 2] = ["allowed", "allowed-last"];

/// A public object in eu-central-1, neither ours nor the AL2023 repository's
/// (§7.7). `s3-front-bucket` and `s3-front-path` ask for it through a tunnel
/// to our bucket's host; readable anonymously from outside the VPC but
/// refused through the endpoint proves the endpoint confines the tunnel. The
/// Mac GETs it anonymously first ([`front_object`]); only a 200 (or 206 for
/// the one byte it asks) lets the two fronting cases count: S3 refuses an
/// anonymous GET of an object that is not public (private, requester-pays,
/// or missing) with the same 403 `AccessDenied` on every path. The Copernicus
/// DEM's open-data bucket answered an anonymous one-byte GET with 206,
/// virtual-hosted and path-style, on 18 Oct 2026 (the first choice,
/// `deutsche-boerse-xetra-pds`, had gone private: 403); B1 checks it again
/// before the live check.
pub const FRONT_OBJECT_BUCKET: &str = "copernicus-dem-30m";
pub const FRONT_OBJECT_KEY: &str = "tileList.txt";

/// How long the Mac's anonymous GET of the front object may take.
pub const FRONT_OBJECT_TIMEOUT: Duration = Duration::from_secs(10);

/// `https://<FRONT_OBJECT_BUCKET>.s3.eu-central-1.amazonaws.com/<FRONT_OBJECT_KEY>`: what the Mac GETs anonymously.
#[must_use]
pub fn front_object_url() -> String {
    format!("https://{}/{FRONT_OBJECT_KEY}", crate::wire::s3::bucket_host(FRONT_OBJECT_BUCKET))
}

/// What the Mac's anonymous GET of the front object answered ([`front_object`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontObject {
    /// S3's HTTP status: 200, or 206 for the one-byte range asked, is readable.
    Status(u16),
    /// No HTTP answer: why (at most 200 characters).
    Unreachable(String),
    /// Debug builds, under the file-backed fake ([`FAKE_SHELL_KNOB`] stands in
    /// for the VM's shell): not asked, and counted as readable (a release
    /// build never counts it).
    Lab,
}

impl FrontObject {
    /// Does it let the fronting cases count?
    #[must_use]
    pub fn readable(&self) -> bool {
        match self {
            FrontObject::Status(s) => matches!(s, 200 | 206),
            FrontObject::Unreachable(_) => false,
            FrontObject::Lab => cfg!(debug_assertions),
        }
    }

    /// What it said, for the reasons and the report.
    #[must_use]
    pub fn said(&self) -> String {
        match self {
            FrontObject::Status(s) if self.readable() => format!("answered the Mac's anonymous GET with HTTP {s} (readable)"),
            FrontObject::Status(s) => format!("answered the Mac's anonymous GET with HTTP {s}, not 200 or 206 (not readable)"),
            FrontObject::Unreachable(e) => format!("could not be read from the Mac ({e})"),
            FrontObject::Lab => "was not asked (lab: the shell's transcript is a file, AI_ENV_BRIDGE_LAB_FAKE_SHELL)".to_string(),
        }
    }
}

/// The Mac's anonymous GET of the front object ([`front_object_url`]):
/// `Range: bytes=0-0`, through the one TLS client (no proxy, https only,
/// redirects never followed), at most [`FRONT_OBJECT_TIMEOUT`]; never fails,
/// whatever came back is the answer.
pub async fn front_object() -> FrontObject {
    let short = |e: &dyn std::fmt::Display| e.to_string().chars().take(200).collect::<String>();
    let client = match crate::bridge::tls::reqwest_client() {
        Ok(c) => c,
        Err(e) => return FrontObject::Unreachable(short(&e)),
    };
    match client.get(front_object_url()).header("Range", "bytes=0-0").timeout(FRONT_OBJECT_TIMEOUT).send().await {
        Ok(resp) => FrontObject::Status(resp.status().as_u16()),
        Err(e) => FrontObject::Unreachable(short(&e)),
    }
}

/// What the Mac knows that the S3 cases are judged by, besides their markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Facts {
    /// The check VM runs with an execution role: its run plan's
    /// (`[aws].execution_role_arn`), or its echo of one. Only without one is
    /// `s3-imds-role` recorded `no_role` when IMDS gave no credentials.
    pub has_role: bool,
    /// The Mac's anonymous GET of the front object: only a readable one lets
    /// `s3-front-bucket` and `s3-front-path` count.
    pub front: FrontObject,
}

impl S3Facts {
    /// What the offline judge ([`judge`]) assumes: a check VM with an
    /// execution role, and the front object read (HTTP 200). The check itself
    /// judges by what it found ([`judge_with`]).
    #[must_use]
    pub fn assumed() -> S3Facts {
        S3Facts { has_role: true, front: FrontObject::Status(200) }
    }

    /// One line for the report.
    #[must_use]
    pub fn said(&self) -> String {
        format!(
            "s3: the front object {FRONT_OBJECT_BUCKET}/{FRONT_OBJECT_KEY} {}; the check VM runs {} execution role",
            self.front.said(),
            if self.has_role { "with an" } else { "without an" }
        )
    }
}

/// `s3.eu-central-1.amazonaws.com`: the regional S3 host (`s3-front-path`'s
/// path-style `Host`, and `proxy-s3-other-host`'s CONNECT target).
pub const S3_REGIONAL_HOST: &str = "s3.eu-central-1.amazonaws.com";

/// How many presigned URLs the Mac sends on the script's stdin: `s3-own`'s
/// PUT and GET, and `s3-own-outside-prefix`'s PUT (in `CASES` order).
pub const URL_SLOTS: usize = 3;

/// The cases, in script order. The proxy exports come right before the
/// first case (`allowed`); `allowed-last` closes the run. The seven S9 S3
/// cases (§7.7): `s3-direct` after `direct-ipv6`, `proxy-s3-other-host` after
/// `proxy-github`, and the five `s3`-group cases before `allowed-last`.
pub const CASES: [Case; 34] = [
    Case { name: "allowed", group: "proxy", kind: Kind::Allowed, what: "api.anthropic.com through the proxy (first)", args: "https://api.anthropic.com/v1/models" },
    Case { name: "direct-name", group: "direct", kind: Kind::Direct, what: "api.anthropic.com without the proxy", args: "--noproxy '*' https://api.anthropic.com/v1/models" },
    Case { name: "direct-ipv4", group: "direct", kind: Kind::Direct, what: "1.1.1.1:443 without the proxy", args: "--noproxy '*' https://1.1.1.1/" },
    Case { name: "direct-http", group: "direct", kind: Kind::Direct, what: "1.1.1.1:80 without the proxy", args: "--noproxy '*' http://1.1.1.1/" },
    Case { name: "direct-ipv6", group: "direct", kind: Kind::Direct, what: "[2606:4700:4700::1111] without the proxy", args: "--noproxy '*' -g https://[2606:4700:4700::1111]/" },
    Case { name: "s3-direct", group: "direct", kind: Kind::Direct, what: "our transcripts bucket's host without the proxy", args: "--noproxy '*' https://@B@/" },
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
    Case { name: "proxy-s3-other-host", group: "proxy", kind: Kind::Connect403, what: "CONNECT s3.eu-central-1.amazonaws.com (another S3 host) through the proxy", args: "https://@S3H@/" },
    Case { name: "denied", group: "proxy", kind: Kind::Connect403, what: "the run's nonce host through the proxy", args: "https://@H@/" },
    // The five `s3`-group cases (§7.7), before `allowed-last`. `s3-own` and
    // `s3-own-outside-prefix` carry a presigned URL read from stdin (their
    // `args` is the helper mode); the fronting cases ask the public object.
    Case { name: "s3-own", group: "s3", kind: Kind::S3Own, what: "a presigned PUT then GET of v1/_egress-check/<nonce> through the proxy", args: "own" },
    Case { name: "s3-front-bucket", group: "s3", kind: Kind::S3Denied(S3Req::Get), what: "a public object fronted by our bucket's virtual-hosted name through the proxy", args: "frontv" },
    Case { name: "s3-front-path", group: "s3", kind: Kind::S3Denied(S3Req::Get), what: "a public object fronted path-style (Host s3.eu-central-1.amazonaws.com) through the proxy", args: "frontp" },
    Case { name: "s3-own-outside-prefix", group: "s3", kind: Kind::S3Denied(S3Req::Put), what: "a presigned PUT of x/_egress-check/<nonce> (outside the v1/ prefix) through the proxy", args: "outside" },
    Case { name: "s3-imds-role", group: "s3", kind: Kind::S3ImdsRole, what: "the VM's execution-role credentials PUT v1/_egress-check/<nonce> through the proxy", args: "imds" },
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

/// The cases that ask the proxy, CONNECT on 443, for a host an operator may
/// allowlist (`ai-env egress allow SLUG github.com`), with that host: while
/// the effective allowlist the network verification proved holds it, the
/// case is recorded, not judged ([`judge_with`]), and squid's log need not
/// show it refused ([`refused_requests`]). Only these: an IP literal,
/// another port, plain http and the run's nonce host are never allowlisted.
pub const ALLOWLISTABLE: [(&str, &str); 1] = [("proxy-github", "github.com")];

/// The hosts of [`ALLOWLISTABLE`] that `effective` holds (the proxy's
/// effective allowlist, `egress::effective_hosts`): what [`judge_with`] and
/// [`squid_poll`] take.
#[must_use]
pub fn allowlisted_hosts(effective: &BTreeSet<String>) -> BTreeSet<String> {
    ALLOWLISTABLE.iter().map(|(_, h)| (*h).to_string()).filter(|h| effective.contains(h)).collect()
}

/// Does the allowlist let `method host:port` through, so that this run need
/// not show squid refusing it: `CONNECT` to port 443 of an [`ALLOWLISTABLE`]
/// host that `allowlisted` holds. Nothing else ever is (squid tunnels port
/// 443 only).
fn allowlisted_request(method: &str, host: &str, port: Option<u16>, allowlisted: &BTreeSet<String>) -> bool {
    method == "CONNECT" && port == Some(443) && ALLOWLISTABLE.iter().any(|(_, h)| *h == host) && allowlisted.contains(host)
}

/// The host of `case` when it is an [`ALLOWLISTABLE`] case whose host
/// `allowlisted` holds.
fn allowlisted_case(case: &str, allowlisted: &BTreeSet<String>) -> Option<&'static str> {
    ALLOWLISTABLE.iter().find(|(c, h)| *c == case && allowlisted.contains(*h)).map(|(_, h)| *h)
}

fn case(name: &str) -> Option<&'static Case> {
    CASES.iter().find(|c| c.name == name)
}

/// The whole script's budget: [`CASE_BUDGET`] per case, the wait for the
/// proxy ([`READY_WAIT_S`] and one more attempt), plus 30 s.
#[must_use]
pub fn script_budget(cases: usize) -> Duration {
    CASE_BUDGET * u32::try_from(cases).unwrap_or(u32::MAX) + Duration::from_secs(READY_WAIT_S + 5 + 30)
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

/// The name every DNS case asks (`N` in the script): fresh per run, so no
/// resolver has it cached and any real one must go upstream, where it does
/// not exist — a recursor's negative answer then carries the zone's SOA,
/// which the platform's stub never sends. Not [`denied_host`]: the proxy's
/// log of that host must stay the `denied` case's alone.
#[must_use]
pub fn dns_name(nonce: &str) -> String {
    format!("d{nonce}.example.com")
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
/// see is printed (squid's error header is reduced to yes/no in the VM; of
/// dig's replies only the fresh name's status, recursion-available flag and
/// ANSWER and AUTHORITY counts, and whether either reply carried an address;
/// `TRUNCATED` when a UDP reply came truncated and dig's TCP retry got
/// nothing). `aienv_d` asks `N` (the run's fresh name, [`dns_name`]) with
/// dig's header, and only of a server that replied (exit 0) `example.com A`,
/// whose address alone counts (`res`): a forwarder that drops the authority
/// section looks like the platform's stub on the fresh name, but hands out
/// example.com's addresses. example.com's output is read first, so a stray
/// `;; Truncated` of it never overwrites the fresh name's status; when dig got
/// no reply to example.com at all (its exit code `q`), the status is
/// `NOEXAMPLE` instead (`probes::DNS_NO_EXAMPLE`), which fails the case: the
/// stub answers both at once, so a server that answers only the fresh name
/// (a forwarder whose upstream does not answer in time) is not the one
/// tested; a reply to example.com is never read for its status (its exit
/// code is 0 for SERVFAIL too), only for an address. A
/// count dig did not print stays `none`, which fails the case (fail closed). It runs
/// under macOS bash 3.2 too (the bash-run tests). `aienv_r IP:PORT` waits
/// for a TCP connection to the proxy (at most [`READY_WAIT_S`], 30 attempts;
/// a dot per failed one, so the shell is never silent for long) and prints
/// the `ready` marker. `R` is `AIENV<nonce>`, `N` the run's fresh name, `S`
/// the first resolv.conf nameserver.
const HELPERS: [&str; 3] = [
    r#"aienv_c() { local n=$1 e rc o=000 s=0 c=- h=000 t=no q=no; shift; e=$(command curl -q -sS -o /dev/null -w 'W=%{http_code},%{size_download},%{num_connects},%{http_connect}=W X=%header{x-squid-error}=X' --connect-timeout 5 --max-time 10 "$@" 2>&1 </dev/null); rc=$?; [[ $e =~ W=([0-9]+),([0-9]+),([0-9]+),([0-9]+)=W ]] && o=${BASH_REMATCH[1]} s=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} h=${BASH_REMATCH[4]}; [[ $e == *'CONNECT tunnel failed, response 403'* ]] && t=yes; [[ $e == *'X=ERR_ACCESS_DENIED'* ]] && q=yes; printf '%s%s %s rc=%s code=%s size=%s conn=%s hc=%s t403=%s sq=%s\n' '@@' "$R" "$n" "$rc" "$o" "$s" "$c" "$h" "$t" "$q"; }"#,
    r#"aienv_d() { local n=$1 s=$2 o e rc q=0 r=no t=none a=none c=none d=none l x='status: ([A-Z]+)' y='^;; flags:([a-z ]*);.* ANSWER: ([0-9]+), AUTHORITY: ([0-9]+),' z='[[:space:]]A[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; shift 2; if [ -z "$s" ]; then printf '%s%s %s rc=none ns=none res=no st=none ra=none an=none au=none\n' '@@' "$R" "$n"; return; fi; o=$(command dig -r +noall +comments +answer +time=2 +tries=1 "$@" "@$s" "$N" A 2>&1 </dev/null); rc=$?; [ $rc = 0 ] && { e=$(command dig -r +noall +answer +time=2 +tries=1 "$@" "@$s" example.com A 2>&1 </dev/null); q=$?; }; while IFS= read -r l; do [[ $l == ';; Truncated'* ]] && t=TRUNCATED; [[ $l =~ $x ]] && t=${BASH_REMATCH[1]}; [[ $l =~ $y ]] && { a=no c=${BASH_REMATCH[2]} d=${BASH_REMATCH[3]}; [[ " ${BASH_REMATCH[1]} " == *' ra '* ]] && a=yes; }; [[ $l =~ $z ]] && r=yes; done <<<"$e"$'\n'"$o"; [ $q = 0 ] || t=NOEXAMPLE; printf '%s%s %s rc=%s ns=%s res=%s st=%s ra=%s an=%s au=%s\n' '@@' "$R" "$n" "$rc" "$s" "$r" "$t" "$a" "$c" "$d"; }"#,
    r#"aienv_r() { local i=0 c=0 t=$SECONDS; while [ $i -lt 30 ] && [ $((SECONDS-t)) -lt 60 ]; do i=$((i+1)); c=$(command curl -q -s -o /dev/null -w '%{num_connects}' --noproxy '*' --connect-timeout 2 --max-time 4 "http://$1/" 2>/dev/null </dev/null); [ "${c:-0}" = 0 ] || break; printf .; command sleep 2; done; [ "${c:-0}" = 0 ] && c=no || c=yes; printf '%s%s ready try=%s s=%s ok=%s\n' '@@' "$R" "$i" "$((SECONDS-t))" "$c"; }"#,
];

/// The bucket and object the S3 cases (§7.7) need filled into the script:
/// our transcripts bucket (its host and owner) and the public fronting
/// object. The lab default ([`S3Probe::lab`]) names [`crate::bridge::s3::LAB_BUCKET`];
/// a real check builds one from the resolved target (`gather`).
#[derive(Debug, Clone)]
pub struct S3Probe {
    /// Our bucket's virtual-hosted host (`<bucket>.s3.eu-central-1.amazonaws.com`).
    pub bucket_host: String,
    /// The bucket's owner (12 digits): `x-amz-expected-bucket-owner`.
    pub owner: String,
}

impl S3Probe {
    /// The lab bucket's host and owner (the fakes' identity; debug and tests).
    #[must_use]
    pub fn lab() -> S3Probe {
        S3Probe { bucket_host: crate::wire::s3::bucket_host(crate::bridge::s3::LAB_BUCKET), owner: crate::bridge::s3::LAB_OWNER.to_string() }
    }

    /// The probe of `target`: its bucket's virtual-hosted host and its owner.
    #[must_use]
    pub fn of(target: &crate::bridge::s3::S3Target) -> S3Probe {
        S3Probe { bucket_host: crate::wire::s3::bucket_host(&target.bucket), owner: target.owner.clone() }
    }
}

/// The S3 cases' shell helpers (§7.7), added only to a script that has an S3
/// case. Each keeps the presigned URL (read into `AIENV_U`, never echoed) and
/// the owner off the captured output; `aienv_s3do` leaves the HTTP code, the
/// proxy's CONNECT answer and S3's `<Code>` in globals, and each case prints
/// one marker with the `put`, `get`, `hc` and `s3` fields [`S3_FIELDS`] names.
/// `aienv_s3cred` asks IMDSv2 (every request `-f`, its exit code checked) for
/// a session token, the role it lists and that role's credentials, leaving
/// them in globals and `aienv_cr` `ok`, else what was missing (`noimds`,
/// `norole`, `nocreds`); `aienv_imds` sends the token in a config on a file
/// descriptor, and `aienv_s3imds` the credentials (`user`, the
/// `x-amz-security-token` header), so neither is ever on an argv, and clears
/// them after its one PUT.
const S3_HELPERS: [&str; 6] = [
    r#"aienv_s3do() { local m=$1 u=$2 ct=$3 eh=$4 o c3='<Code>([A-Za-z]+)</Code>'; local -a a; a=(command curl -q -sS -X "$m" -w ' W=%{http_code},%{http_connect}=W' --connect-timeout 5 --max-time 10); [ "$ct" = - ] || a+=(--connect-to "$ct"); [ "$eh" = - ] || a+=(-H "$eh"); [ "$m" = PUT ] && a+=(-H 'Content-Length: 0' -H 'x-amz-checksum-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' -H 'If-None-Match: *' -H 'Transfer-Encoding:' -H 'Expect:'); o=$("${a[@]}" "$u" 2>&1 </dev/null); aienv_code=000; aienv_hc=000; aienv_s3=-; [[ $o =~ W=([0-9]+),([0-9]+)=W ]] && { aienv_code=${BASH_REMATCH[1]}; aienv_hc=${BASH_REMATCH[2]}; }; [[ $o =~ $c3 ]] && aienv_s3=${BASH_REMATCH[1]}; }"#,
    r#"aienv_s3own() { local n=$1 p g h; aienv_s3do PUT "$2" - "x-amz-expected-bucket-owner: $O"; p=$aienv_code; h=$aienv_hc; aienv_s3do GET "$3" - "x-amz-expected-bucket-owner: $O"; g=$aienv_code; [ "$h" = 000 ] && h=$aienv_hc; printf '%s%s %s rc=0 put=%s get=%s hc=%s s3=-\n' '@@' "$R" "$n" "$p" "$g" "$h"; }"#,
    r#"aienv_s3deny() { local n=$1 u=$2 ct=$3 f=$4; if [ "$f" = put ]; then aienv_s3do PUT "$u" "$ct" "x-amz-expected-bucket-owner: $O"; printf '%s%s %s rc=0 put=%s get=000 hc=%s s3=%s\n' '@@' "$R" "$n" "$aienv_code" "$aienv_hc" "$aienv_s3"; else aienv_s3do GET "$u" "$ct" -; printf '%s%s %s rc=0 put=000 get=%s hc=%s s3=%s\n' '@@' "$R" "$n" "$aienv_code" "$aienv_hc" "$aienv_s3"; fi; }"#,
    r#"aienv_imds() { command curl -q -sSf -K <(printf 'header = "X-aws-ec2-metadata-token: %s"\n' "$aienv_it") --noproxy '*' --max-time 5 "http://169.254.169.254/latest/meta-data/iam/security-credentials/$1" 2>/dev/null </dev/null; }"#,
    r#"aienv_s3cred() { local r o v='^[A-Za-z0-9+=,.@_-]+$' x='"AccessKeyId"[[:space:]]*:[[:space:]]*"([^"]+)"' y='"SecretAccessKey"[[:space:]]*:[[:space:]]*"([^"]+)"' z='"Token"[[:space:]]*:[[:space:]]*"([^"]+)"'; aienv_ak=; aienv_sk=; aienv_tk=; aienv_cr=noimds; aienv_it=$(command curl -q -sSf -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' --noproxy '*' --max-time 5 http://169.254.169.254/latest/api/token 2>/dev/null </dev/null) && [ -n "$aienv_it" ] || return 0; aienv_cr=norole; r=$(aienv_imds) && [[ $r =~ $v ]] || return 0; aienv_cr=nocreds; o=$(aienv_imds "$r") || return 0; [[ $o =~ $x ]] && aienv_ak=${BASH_REMATCH[1]}; [[ $o =~ $y ]] && aienv_sk=${BASH_REMATCH[1]}; [[ $o =~ $z ]] && aienv_tk=${BASH_REMATCH[1]}; [ -n "$aienv_ak" ] && [ -n "$aienv_sk" ] && [ -n "$aienv_tk" ] && aienv_cr=ok; return 0; }"#,
    r#"aienv_s3imds() { local n=$1 o code=000 hc=000 s3=- c3='<Code>([A-Za-z]+)</Code>'; aienv_s3cred; if [ "$aienv_cr" = ok ]; then o=$(command curl -q -sS -K <(printf 'user = "%s:%s"\nheader = "x-amz-security-token: %s"\n' "$aienv_ak" "$aienv_sk" "$aienv_tk") -X PUT --aws-sigv4 'aws:amz:eu-central-1:s3' -H "x-amz-expected-bucket-owner: $O" -H 'x-amz-content-sha256: UNSIGNED-PAYLOAD' -H 'Content-Length: 0' -w ' W=%{http_code},%{http_connect}=W' --connect-timeout 5 --max-time 10 "$EC" 2>&1 </dev/null); [[ $o =~ W=([0-9]+),([0-9]+)=W ]] && { code=${BASH_REMATCH[1]}; hc=${BASH_REMATCH[2]}; }; [[ $o =~ $c3 ]] && s3=${BASH_REMATCH[1]}; else s3=$aienv_cr; fi; aienv_ak=; aienv_sk=; aienv_tk=; aienv_it=; printf '%s%s %s rc=0 put=%s get=000 hc=%s s3=%s\n' '@@' "$R" "$n" "$code" "$hc" "$s3"; }"#,
];

/// What `s3-imds-role`'s `s3=` says when IMDS gave the check VM no
/// credentials to try (`aienv_s3cred`): no session token, no role listed, or
/// a role without all three of AccessKeyId, SecretAccessKey and Token.
const IMDS_GAVE_NOTHING: [&str; 3] = ["noimds", "norole", "nocreds"];

/// The script line that reads the presigned URLs from stdin into `AIENV_U`:
/// it saves the terminal's settings and turns its echo off, then prints the
/// `urls` marker ([`urls_marker`], built at run time) — the Mac types the
/// URLs only once it shows ([`run_check_script`]): a terminal echoes input
/// as it receives it, so typed earlier they would be echoed into the output,
/// or run as commands by a line still running — reads them silently (`read
/// -rs`), and restores the settings. `@URLN@` is the count (`1 2 …`).
const URL_READ_LOOP: &str = r#"aienv_t=$(command stty -g 2>/dev/null); command stty -echo 2>/dev/null; printf '%s%s urls\n' '@@' "$R"; AIENV_U=(); for aienv_i in @URLN@; do IFS= read -rs aienv_l; AIENV_U+=("$aienv_l"); done; aienv_l=; [ -n "$aienv_t" ] && command stty "$aienv_t" 2>/dev/null"#;

/// How many presigned URLs `c` reads from stdin: `s3-own` (a PUT and a GET),
/// `s3-own-outside-prefix` (a PUT); the others sign in the VM or ask a public
/// object.
fn url_slots_of(c: &Case) -> usize {
    match c.name {
        "s3-own" => 2,
        "s3-own-outside-prefix" => 1,
        _ => 0,
    }
}

/// The script line for an S3 case (`c.is_s3()`): the tailored helper call
/// (using the `B`/`FV`/`FP`/`EC` vars the script sets). `url_at` is the index
/// of its first stdin URL in `AIENV_U`.
fn s3_case_line(c: &Case, url_at: usize) -> String {
    let fvh = crate::wire::s3::bucket_host(FRONT_OBJECT_BUCKET);
    match c.name {
        "s3-own" => format!(r#"aienv_s3own s3-own "${{AIENV_U[{url_at}]}}" "${{AIENV_U[{}]}}""#, url_at + 1),
        "s3-front-bucket" => format!(r#"aienv_s3deny s3-front-bucket "$FV" "{fvh}:443:$B:443" get"#),
        "s3-front-path" => format!(r#"aienv_s3deny s3-front-path "$FP" "{S3_REGIONAL_HOST}:443:$B:443" get"#),
        "s3-own-outside-prefix" => format!(r#"aienv_s3deny s3-own-outside-prefix "${{AIENV_U[{url_at}]}}" - put"#),
        "s3-imds-role" => "aienv_s3imds s3-imds-role".to_string(),
        other => format!("aienv_s3own {other}"),
    }
}

/// Where `script`'s URL read loop line is: its start, and the end of its line.
fn url_loop(script: &str) -> Option<(usize, usize)> {
    let prefix = &URL_READ_LOOP[..URL_READ_LOOP.find("@URLN@").unwrap_or(0)];
    let at = script.find(prefix)?;
    let end = script[at..].find('\n')? + at + 1;
    Some((at, end))
}

/// How many presigned URLs `script` reads from its stdin: its read loop's
/// count (0 without one).
#[must_use]
pub fn url_reads(script: &str) -> usize {
    let Some((at, end)) = url_loop(script) else { return 0 };
    let list = script[at..end].split_once("for aienv_i in ").and_then(|(_, rest)| rest.split_once(';')).map_or("", |(list, _)| list);
    list.split_whitespace().count()
}

/// `(up to and including the URL read loop's line, the rest)` when the
/// script reads URLs from stdin; `None` when it reads none (no S3 URL case:
/// the dns-path probe, [`render_cases`]).
#[must_use]
pub fn split_url_reads(script: &str) -> Option<(&str, &str)> {
    let (_, end) = url_loop(script)?;
    Some((&script[..end], &script[end..]))
}

/// The marker a check script prints, once its terminal's echo is off, when it
/// is about to read the presigned URLs ([`URL_READ_LOOP`]):
/// `@@AIENV<nonce> urls`. The script builds it at run time, so its echo never
/// shows it.
#[must_use]
pub fn urls_marker(nonce: &str) -> String {
    format!("{MARK}{nonce} urls")
}

/// What the Mac types for a check `script`: the first part at once — the
/// whole script, or up to and including its URL read loop's line — then,
/// when it reads presigned URLs, `urls`, one per line, and the rest of the
/// script, held as a [`Secret`] and typed only once the output shows
/// [`urls_marker`] ([`run_check_script`]). `Err` unless `urls` holds exactly
/// as many one-line URLs as the loop reads (none without one): one URL too
/// few or too many would shift every read, and run a URL or a script line as
/// the other.
pub fn script_frames<'a>(script: &'a str, urls: &[&str]) -> std::result::Result<(&'a str, Option<Secret<String>>), String> {
    let want = url_reads(script);
    if urls.len() != want {
        return Err(format!("the script reads {want} presigned URL{} from its stdin, not {}", if want == 1 { "" } else { "s" }, urls.len()));
    }
    if let Some(i) = urls.iter().position(|u| u.is_empty() || u.contains(['\n', '\r'])) {
        return Err(format!("presigned URL {} is not one line", i + 1));
    }
    let Some((first, rest)) = split_url_reads(script) else { return Ok((script, None)) };
    let mut then = String::with_capacity(urls.iter().map(|u| u.len() + 1).sum::<usize>() + rest.len());
    for u in urls {
        then.push_str(u);
        then.push('\n');
    }
    then.push_str(rest);
    Ok((first, Some(Secret::new(then))))
}

/// The script of `cases` for one run: no alias, no function named like a
/// tool it calls, a fresh command hash, no history file, no `!` expansion;
/// `R`, `N` and `S`; the helpers; the S3 probe's bucket and object (`B`, `O`,
/// `FV`, `FP`, `EC`) and the URL read loop ([`URL_READ_LOOP`]) when an S3
/// case needs one; one short line per case (the proxy exports and the wait
/// for the proxy before the first proxied case); the `end` marker; `exit`.
/// No tab, no `!`; each line under 1 KiB (a terminal's canonical buffer).
fn render(nonce: &str, proxy_ip: &str, probe: &S3Probe, cases: &[&Case]) -> String {
    let fill = |args: &str| {
        args.replace("@P@", proxy_ip)
            .replace("@V@", &cidr_plus_two(VPC_CIDR).unwrap_or_default())
            .replace("@S@", &cidr_plus_two(VM_SUBNET_CIDR).unwrap_or_default())
            .replace("@H@", &denied_host(nonce))
            .replace("@B@", &probe.bucket_host)
            .replace("@S3H@", S3_REGIONAL_HOST)
    };
    let mut lines = vec![
        r"\unalias -a; unset -f command curl dig printf 2>/dev/null; hash -r; unset HISTFILE; set +H".to_string(),
        format!(r#"R={MARK_BODY}{nonce}; N={name}; S=; while read -r k v x; do [ "$k" = nameserver ] && [ -z "$S" ] && S=$v; done 2>/dev/null </etc/resolv.conf"#, MARK_BODY = &MARK[2..], name = dns_name(nonce)),
    ];
    lines.extend(HELPERS.iter().map(|h| (*h).to_string()));
    let url_slots: usize = cases.iter().map(|c| url_slots_of(c)).sum();
    if cases.iter().any(|c| c.is_s3()) {
        let fv = format!("https://{}/{FRONT_OBJECT_KEY}", crate::wire::s3::bucket_host(FRONT_OBJECT_BUCKET));
        let fp = format!("https://{S3_REGIONAL_HOST}/{FRONT_OBJECT_BUCKET}/{FRONT_OBJECT_KEY}");
        let ec = format!("https://{}/{}", probe.bucket_host, crate::wire::s3::S3Key::EgressCheck { nonce: nonce.to_string() }.render());
        lines.push(format!("B='{}'; O='{}'; FV='{fv}'; FP='{fp}'; EC='{ec}'", probe.bucket_host, probe.owner));
        lines.extend(S3_HELPERS.iter().map(|h| (*h).to_string()));
        if url_slots > 0 {
            let seq: Vec<String> = (1..=url_slots).map(|i| i.to_string()).collect();
            lines.push(URL_READ_LOOP.replace("@URLN@", &seq.join(" ")));
        }
    }
    let mut exported = false;
    let mut url_at = 0;
    for c in cases {
        if c.proxied() && !exported {
            let pairs: Vec<String> = proxy_env(proxy_ip, PROXY_PORT).into_iter().map(|(k, v)| format!("{k}='{v}'")).collect();
            lines.push(format!("export {}", pairs.join(" ")));
            lines.push(format!("aienv_r {proxy_ip}:{PROXY_PORT}"));
            exported = true;
        }
        if c.is_s3() {
            lines.push(s3_case_line(c, url_at));
            url_at += url_slots_of(c);
        } else {
            lines.push(format!("{} {} {}", if c.is_dns() { "aienv_d" } else { "aienv_c" }, c.name, fill(c.args)));
        }
    }
    lines.push(r#"printf '%s%s end\n' '@@' "$R""#.to_string());
    lines.push("exit".to_string());
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// The `ai-env egress check` script: every case of [`CASES`], for the lab
/// probe (the tests, debug). A real check uses [`render_script_with`]. It
/// reads presigned URLs from its stdin: run it with [`run_check_script`].
#[must_use]
pub fn render_script(nonce: &str, proxy_ip: &str) -> String {
    render(nonce, proxy_ip, &S3Probe::lab(), &CASES.iter().collect::<Vec<_>>())
}

/// The `ai-env egress check` script for `probe` ([`S3Probe::of`] the resolved
/// transcripts bucket): the S3 cases ask that bucket's host. It reads
/// presigned URLs from its stdin: run it with [`run_check_script`].
#[must_use]
pub fn render_script_with(nonce: &str, proxy_ip: &str, probe: &S3Probe) -> String {
    render(nonce, proxy_ip, probe, &CASES.iter().collect::<Vec<_>>())
}

/// The script of the named cases only, in [`CASES`] order, sent in one frame
/// (`vm::shell::run_script`): the dns-path probe's, and the live tests'
/// partial runs. Unknown names are skipped, and so is every case that asks
/// the transcripts bucket (`Case::needs_bucket`: the `s3` group and
/// `s3-direct`, §7.7): this script names no bucket and never reads presigned
/// URLs from its stdin — a read loop with nothing behind it would swallow the
/// script's next lines. Those cases run in a full check
/// ([`render_script_with`], [`run_check_script`]).
#[must_use]
pub fn render_cases(nonce: &str, proxy_ip: &str, names: &[&str]) -> String {
    render(nonce, proxy_ip, &S3Probe::lab(), &CASES.iter().filter(|c| names.contains(&c.name) && !c.needs_bucket()).collect::<Vec<_>>())
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
    /// dig: whether a reply carried an address (the fresh name's, or
    /// example.com's of a server that replied).
    pub resolves: Option<bool>,
    /// dig: the fresh name's reply's status (`NOERROR`, `REFUSED`,
    /// `SERVFAIL`, …; `TRUNCATED`: a UDP reply came truncated and dig's TCP
    /// retry got nothing; `NOEXAMPLE`: the fresh name got a reply, example.com
    /// none; `None`: no reply, or none printed).
    pub status: Option<String>,
    /// dig: whether the reply's flags said recursion available (`ra`; `None`:
    /// no reply, or no flags printed).
    pub ra: Option<bool>,
    /// dig: the header's `ANSWER:` count (`None`: no reply, or no header printed).
    pub answers: Option<u16>,
    /// dig: the header's `AUTHORITY:` count (`None`: no reply, or no header
    /// printed). A recursor's negative answer carries the zone's SOA here.
    pub authority: Option<u16>,
    /// S3 case: the PUT's HTTP status (`s3-own`, `s3-own-outside-prefix`,
    /// `s3-imds-role`; 0 for `000`, no HTTP answer; `None`: not reported).
    pub put: Option<u16>,
    /// S3 case: the GET's HTTP status (`s3-own`, the fronting cases).
    pub get: Option<u16>,
    /// S3 case: S3's `<Code>` of the judged response (`[A-Za-z]{1,64}`; for
    /// `s3-imds-role` when IMDS gave the VM no credentials, what was missing:
    /// `noimds`, `norole` or `nocreds`; `None` for `-`).
    pub s3: Option<String>,
}

/// The script's wait for the proxy before its first case (`aienv_r`): the
/// attempts it took, the seconds it waited, and whether a TCP connection to
/// the proxy's port opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ready {
    pub tries: u32,
    pub secs: u32,
    pub ok: bool,
}

/// What a transcript said: the case markers, the wait for the proxy, whether
/// the script asked for its presigned URLs (the `urls` marker,
/// [`urls_marker`]), and whether its `end` marker came (the script ran to its
/// end).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Markers {
    pub cases: Vec<CaseResult>,
    pub ready: Option<Ready>,
    pub urls: bool,
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
const DIG_FIELDS: [&str; 7] = ["rc", "ns", "res", "st", "ra", "an", "au"];
const S3_FIELDS: [&str; 5] = ["rc", "put", "get", "hc", "s3"];
const READY_FIELDS: [&str; 3] = ["try", "s", "ok"];

/// The marker lines of run `nonce` in `output` (the remote's transcript:
/// the shell's echo of the script, prompts, the markers). A line holds a
/// marker when it contains `@@AIENV`; the echoed script never does (its
/// markers are built at run time). Each case may appear once; `Err` for a
/// marker of another nonce, an unknown case, a case twice, a missing,
/// repeated or malformed field, `end`, `ready` or `urls` twice, `end` or
/// `urls` with a field. Missing cases are [`judge`]'s to name.
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
        if name == "ready" {
            if m.ready.is_some() {
                return Err("the ready marker twice".into());
            }
            m.ready = Some(parse_ready(words)?);
            continue;
        }
        if name == "urls" {
            if m.urls {
                return Err("the urls marker twice".into());
            }
            if let Some(w) = words.next() {
                return Err(format!("the urls marker carries {:?}", shown(w)));
            }
            m.urls = true;
            continue;
        }
        let spec = case(name).ok_or_else(|| format!("unknown case {:?}", shown(name)))?;
        if m.get(name).is_some() {
            return Err(format!("case {name} twice"));
        }
        let fields: &[&str] = if spec.is_dns() {
            &DIG_FIELDS
        } else if spec.is_s3() {
            &S3_FIELDS
        } else {
            &CURL_FIELDS
        };
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
                "code" | "hc" | "put" | "get" => {
                    let n: u16 = if v.len() == 3 && digits(v) { v.parse().map_err(|_| bad())? } else { return Err(bad()) };
                    match key {
                        "code" => r.code = Some(n),
                        "hc" => r.hc = Some(n),
                        "put" => r.put = Some(n),
                        _ => r.get = Some(n),
                    }
                }
                "s3" if v == "-" => r.s3 = None,
                "s3" if (1..=64).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_alphabetic()) => r.s3 = Some(v.to_string()),
                "size" if digits(v) || v == "0" => r.size = Some(v.parse().map_err(|_| bad())?),
                "conn" if v == "-" => r.conn = None,
                "conn" if digits(v) => r.conn = Some(v.parse().map_err(|_| bad())?),
                "t403" => r.t403 = Some(yes_no()?),
                "sq" => r.sq = Some(yes_no()?),
                "ns" if v == "none" => r.ns = None,
                "ns" if is_server(v) => r.ns = Some(v.to_string()),
                "res" => r.resolves = Some(yes_no()?),
                "st" if v == "none" => r.status = None,
                "st" if (1..=16).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_uppercase()) => r.status = Some(v.to_string()),
                "ra" if v == "none" => r.ra = None,
                "ra" => r.ra = Some(yes_no()?),
                "an" | "au" => {
                    let n: Option<u16> = match v {
                        "none" => None,
                        _ if (1..=5).contains(&v.len()) && digits(v) => Some(v.parse().map_err(|_| bad())?),
                        _ => return Err(bad()),
                    };
                    if key == "an" { r.answers = n } else { r.authority = n }
                }
                _ => return Err(bad()),
            }
        }
        if let Some(missing) = fields.iter().find(|f| !seen.contains(*f)) {
            return Err(format!("{name}: the {missing} field is missing"));
        }
        if spec.is_dns() && (r.rc.is_none() != r.ns.is_none()) {
            return Err(format!("{name}: rc and ns disagree on whether a server was asked"));
        }
        if spec.is_dns() && r.rc.is_none() && (r.status.is_some() || r.ra.is_some() || r.answers.is_some() || r.authority.is_some()) {
            return Err(format!("{name}: a status, flags or counts, but no server was asked"));
        }
        m.cases.push(r);
    }
    Ok(m)
}

/// The fields of the `ready` marker: `try=<n> s=<seconds> ok=yes|no`, each once.
fn parse_ready<'a>(words: impl Iterator<Item = &'a str>) -> std::result::Result<Ready, String> {
    let mut r = Ready::default();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for w in words {
        let (k, v) = w.split_once('=').ok_or_else(|| format!("ready: {:?} is not key=value", shown(w)))?;
        let Some(key) = READY_FIELDS.iter().copied().find(|f| *f == k) else {
            return Err(format!("ready: unexpected field {:?}", shown(k)));
        };
        if !seen.insert(key) {
            return Err(format!("ready: {k} twice"));
        }
        let bad = || format!("ready: bad {k}={:?}", shown(v));
        let number = || -> std::result::Result<u32, String> { if !v.is_empty() && v.len() <= 6 && v.bytes().all(|c| c.is_ascii_digit()) { v.parse().map_err(|_| bad()) } else { Err(bad()) } };
        match key {
            "try" => r.tries = number()?,
            "s" => r.secs = number()?,
            _ => {
                r.ok = match v {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(bad()),
                }
            }
        }
    }
    if let Some(missing) = READY_FIELDS.iter().find(|f| !seen.contains(*f)) {
        return Err(format!("ready: the {missing} field is missing"));
    }
    Ok(r)
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
    /// The script's wait for the proxy, when its marker came.
    pub ready: Option<Ready>,
    /// The script's `end` marker came.
    pub finished: bool,
    /// The run's DNS verdict by the dns-path rule (`no-dns` |
    /// `platform-dns:<ips>` | `platform-dns-answered:<ips>` |
    /// `platform-dns-resolves:<ips>` | `open-dns:<ips>`, each listing every
    /// server of its class) over its DNS cases, or `unknown (…)`.
    pub dns: String,
    /// The hosts of [`ALLOWLISTABLE`] whose cases were recorded, not judged,
    /// because the proxy's effective allowlist held them ([`judge_with`]; a
    /// case without a marker fails, and is not one).
    pub allowlisted: Vec<String>,
    /// What the S3 cases were judged by besides their markers.
    pub s3: S3Facts,
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

    /// One line: every case with its verdict (`imds=recorded:<HTTP code>`;
    /// `proxy-github=recorded:allowlisted` while its host is allowlisted;
    /// `s3-imds-role=recorded:no_role` when the check VM ran without an
    /// execution role).
    #[must_use]
    pub fn summary(&self) -> String {
        let allowlisted = |name: &str| ALLOWLISTABLE.iter().any(|(c, h)| *c == name && self.allowlisted.iter().any(|a| a == h));
        self.cases
            .iter()
            .map(|c| match (c.verdict, &c.result) {
                (Verdict::Recorded, Some(_)) if allowlisted(c.name) => format!("{}=recorded:allowlisted", c.name),
                // judge_case records s3-imds-role only for a VM without an execution role.
                (Verdict::Recorded, Some(_)) if case(c.name).is_some_and(|k| k.kind == Kind::S3ImdsRole) => format!("{}=recorded:no_role", c.name),
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

/// What a DNS reply said beyond its address, for the reasons: ` (status
/// NOERROR, answer 0, authority 0, recursion available)`, with `example.com A
/// unanswered` in place of the status for `NOEXAMPLE`; what dig did not print
/// is left out, and nothing at all is empty.
fn dns_said(r: &CaseResult) -> String {
    let parts: Vec<String> = [
        r.status.as_deref().map(|s| if s == DNS_NO_EXAMPLE { DNS_NO_EXAMPLE_SAID.to_string() } else { format!("status {s}") }),
        r.answers.map(|n| format!("answer {n}")),
        r.authority.map(|n| format!("authority {n}")),
        r.ra.map(|a| (if a { "recursion available" } else { "no recursion" }).to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

/// Does the `allowed` case `r` show a working path through the proxy (its
/// tunnel opened, the API answered 401)?
fn allowed_passed(r: Option<&CaseResult>) -> bool {
    r.is_some_and(|r| r.code == Some(401) && r.hc == Some(200))
}

/// One case on its own, by `s3` where it needs it (the non-vacuous rule and
/// the fronting cases' are [`judge_with`]'s).
fn judge_case(c: &Case, r: &CaseResult, s3: &S3Facts) -> (Verdict, String) {
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
                // A truncated UDP reply whose TCP retry failed: the UDP path answered.
                Some(9) if r.status.is_some() && public => (Verdict::Fail, format!("OPEN: {ns}, not a platform resolver, replied over UDP (truncated; dig's TCP retry got nothing)")),
                Some(9) if r.status.is_some() => (Verdict::Fail, format!("not proven closed: {ns} sent a truncated UDP reply and dig's TCP retry got nothing")),
                Some(9) => (Verdict::Pass, format!("closed: no reply from {ns}")),
                Some(0) if r.resolves == Some(true) => (Verdict::Fail, format!("OPEN: {ns} returned an address (the run's name, which exists nowhere, or example.com){}", dns_said(r))),
                Some(0) if public => (Verdict::Fail, format!("OPEN: {ns}, not a platform resolver, replied{} (it resolved nothing, but the path is open)", dns_said(r))),
                // Only the reply the operator tested passes: another status, a record or an SOA means the resolver is
                // not the stub that was tested (a recursor's negative answer carries the SOA); a count not printed fails
                // too (fail closed).
                Some(0) if !is_empty_noerror(r.status.as_deref(), r.answers, r.authority) => (
                    Verdict::Fail,
                    format!("{ns} replied{}: not the platform stub's empty reply (NOERROR, answer 0, authority 0), the only one accepted: the resolver is not what was tested (`ai-env lab run dns-path` records what it says)", dns_said(r)),
                ),
                Some(0) => (Verdict::Pass, format!("{ns} replied with an empty NOERROR{} and no address for example.com (platform DNS: the run's DNS verdict names it, and only [egress].accept_platform_dns accepts it)", dns_said(r))),
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
            // An allowlisted host's case never gets here (judge_with records it): this host was not on the effective
            // allowlist the network verification proved, or no list was proved — said, not prescribed.
            let hint = ALLOWLISTABLE
                .iter()
                .find(|(n, _)| *n == c.name)
                .map(|(_, h)| format!(" ({h} was not on the proxy's effective allowlist as this check read it, or that list could not be verified: ai-env egress status)"))
                .unwrap_or_default();
            (Verdict::Fail, format!("OPEN: the proxy opened a tunnel: {}, CONNECT {hc:03}{hint}", curl_seen(r)))
        }
        Kind::Connect403 => (Verdict::Fail, format!("no 403 from the proxy: {}, CONNECT {hc:03}", curl_seen(r))),
        Kind::Get403 if code == 403 && r.sq == Some(true) => (Verdict::Pass, "squid's 403 (X-Squid-Error ERR_ACCESS_DENIED)".into()),
        Kind::Get403 if code == 403 => (Verdict::Fail, "a 403 without squid's X-Squid-Error ERR_ACCESS_DENIED: not the proxy's refusal".into()),
        Kind::Get403 => (Verdict::Fail, format!("expected squid's 403 for a plain-http request: {}", curl_seen(r))),
        Kind::S3Own => judge_s3_own(r),
        Kind::S3Denied(req) => judge_s3_denied(r, req),
        Kind::S3ImdsRole => match r.s3.as_deref().filter(|w| IMDS_GAVE_NOTHING.contains(w)) {
            Some(w) if !s3.has_role => (
                Verdict::Recorded,
                format!("recorded:no_role: the check VM ran without an execution role ([aws].execution_role_arn unset), so there were no credentials to try (IMDS: {w})"),
            ),
            Some(w) => {
                let what = match w {
                    "noimds" => "no session token",
                    "norole" => "no role",
                    _ => "a role without all of AccessKeyId, SecretAccessKey and Token",
                };
                (Verdict::Fail, format!("the check VM runs with an execution role, but IMDS gave it {what} ({w}): the role's credentials were never tried against our bucket"))
            }
            None => judge_s3_denied(r, S3Req::Put),
        },
    }
}

/// What an S3 case saw, for the reasons (never the URL or the body).
fn s3_seen(r: &CaseResult) -> String {
    let hc = r.hc.unwrap_or(0);
    let code = r.s3.as_deref().unwrap_or("-");
    format!("CONNECT {hc:03}, put {:03}, get {:03}, <Code> {code}", r.put.unwrap_or(0), r.get.unwrap_or(0))
}

/// `s3-own`: the presigned PUT and GET of `v1/_egress-check/<nonce>` both 200
/// through the proxy's tunnel (CONNECT 200). The GET's 200 is the proof that
/// the proxy's S3 traffic goes through the endpoint.
fn judge_s3_own(r: &CaseResult) -> (Verdict, String) {
    let (put, get, hc) = (r.put.unwrap_or(0), r.get.unwrap_or(0), r.hc.unwrap_or(0));
    if hc != 200 {
        (Verdict::Fail, format!("the proxy did not open a tunnel to our bucket's host (CONNECT {hc:03}): {}", s3_seen(r)))
    } else if put != 200 {
        (Verdict::Fail, format!("the presigned PUT of v1/_egress-check/<nonce> did not store (HTTP {put:03}): {}", s3_seen(r)))
    } else if get != 200 {
        (Verdict::Fail, format!("OPEN or MISCONFIGURED: the GET of the object just stored did not return 200 (HTTP {get:03}): the proxy's S3 traffic is not confined to the endpoint, or the endpoint policy is wrong ({})", s3_seen(r)))
    } else {
        (Verdict::Pass, "stored and read it back through the proxy's tunnel (CONNECT 200): the proxy's S3 traffic goes through the endpoint".into())
    }
}

/// An `S3Denied` request (`req` reports in `get` for a fronting GET, `put` for
/// a PUT): the tunnel must open (CONNECT 200) and S3 must answer 403 with
/// `<Code>` `AccessDenied` — the endpoint's refusal, judged on the status and
/// the code, never the wording.
fn judge_s3_denied(r: &CaseResult, req: S3Req) -> (Verdict, String) {
    let hc = r.hc.unwrap_or(0);
    let status = match req {
        S3Req::Get => r.get,
        S3Req::Put => r.put,
    }
    .unwrap_or(0);
    let code = r.s3.as_deref().unwrap_or("-");
    if hc != 200 {
        (Verdict::Fail, format!("the proxy did not open a tunnel to our bucket's host (CONNECT {hc:03}): the case cannot show the endpoint refusing it ({})", s3_seen(r)))
    } else if status == 403 && code == "AccessDenied" {
        (Verdict::Pass, "the endpoint refused it: S3 403 AccessDenied through the proxy's tunnel (CONNECT 200)".into())
    } else if (200..300).contains(&status) {
        (Verdict::Fail, format!("OPEN: the endpoint served it (HTTP {status:03}): a request it must refuse went through ({})", s3_seen(r)))
    } else if status == 403 {
        (Verdict::Fail, format!("403 without <Code> AccessDenied ({code}): not the endpoint's refusal ({})", s3_seen(r)))
    } else {
        (Verdict::Fail, format!("expected S3 403 AccessDenied through the tunnel: {}", s3_seen(r)))
    }
}

/// The DNS cases of `m` as [`DnsReply`]s, with the resolv.conf nameserver.
fn dns_replies(m: &Markers) -> (Option<String>, Vec<DnsReply>) {
    let mut out = Vec::new();
    for c in CASES.iter().filter(|c| c.is_dns()) {
        if let Some(r) = m.get(c.name) {
            out.push(DnsReply {
                server: r.ns.clone().unwrap_or_default(),
                transport: if c.name.ends_with("-tcp") { "tcp" } else { "udp" },
                rc: r.rc,
                resolves: r.resolves == Some(true),
                status: r.status.clone(),
                ra: r.ra,
                answers: r.answers,
                authority: r.authority,
            });
        }
    }
    let resolv = m.get("dns-resolv-udp").or_else(|| m.get("dns-resolv-tcp")).and_then(|r| r.ns.clone());
    (resolv, out)
}

/// [`judge_with`] with no host allowlisted and the S3 facts it assumes
/// ([`S3Facts::assumed`]: an execution role, the front object read): the
/// offline tests' judge (the bash-run tests). The check judges by what it
/// proved.
#[must_use]
pub fn judge(m: &Markers) -> Judgement {
    judge_with(m, &BTreeSet::new(), &S3Facts::assumed())
}

/// Judge every case of [`CASES`] (pure). A missing case fails; a direct,
/// DNS or other-port case that passed on its own still fails unless both
/// `allowed` cases of the same run passed (a VM whose networking is dead,
/// or died midway, proves nothing closed); a failing `allowed` says when
/// the script's wait never reached the proxy. An [`ALLOWLISTABLE`] case
/// whose host `allowlisted` holds (the proxy's effective allowlist as the
/// network verification proved it, [`allowlisted_hosts`]) is recorded, not
/// judged, whatever its marker says — a tunnel, or a refusal from before
/// the host was added — and a missing marker still fails. A fronting case
/// that passed on its own still fails unless `s3.front` is readable (a 403
/// for an object nobody may read anonymously proves nothing about the
/// endpoint), and `s3-imds-role` is recorded `no_role` for want of
/// credentials only when `s3.has_role` is false. `dns` is the run's dns-path
/// verdict.
#[must_use]
pub fn judge_with(m: &Markers, allowlisted: &BTreeSet<String>, s3: &S3Facts) -> Judgement {
    let allowed_ok = ALLOWED_CASES.iter().all(|n| allowed_passed(m.get(n)));
    let cases: Vec<CaseVerdict> = CASES
        .iter()
        .map(|c| {
            let Some(r) = m.get(c.name) else {
                return CaseVerdict { name: c.name, group: c.group, verdict: Verdict::Fail, reason: "no result: the script did not reach it".into(), result: None };
            };
            if let Some(host) = allowlisted_case(c.name, allowlisted) {
                let reason = format!("not judged: {host} is allowlisted on the proxy (its effective allowlist, as the network verification read it); curl saw {}, CONNECT {:03}; this check does not show squid refusing it", curl_seen(r), r.hc.unwrap_or(0));
                return CaseVerdict { name: c.name, group: c.group, verdict: Verdict::Recorded, reason, result: Some(r.clone()) };
            }
            let (mut verdict, mut reason) = judge_case(c, r, s3);
            if let Some(w) = m.ready.filter(|w| c.name == "allowed" && verdict == Verdict::Fail && !w.ok) {
                reason = format!("{reason} — the script waited {} s ({} attempts) and never opened a connection to the proxy's port", w.secs, w.tries);
            }
            if verdict == Verdict::Pass && c.needs_allowed() && !allowed_ok {
                verdict = Verdict::Fail;
                reason = format!("{reason} — not counted: `allowed` and `allowed-last` did not both pass in this run, so this VM's networking proved nothing");
            }
            if verdict == Verdict::Pass && c.fronts() {
                if s3.front.readable() {
                    reason = format!("{reason}; the object it fronted {}", s3.front.said());
                } else {
                    verdict = Verdict::Fail;
                    reason = format!("{reason} — not counted: the front object {FRONT_OBJECT_BUCKET}/{FRONT_OBJECT_KEY} {}: S3 refuses an object nobody may read anonymously with the same 403 AccessDenied on every path, so this proves nothing about the endpoint (B1 names a readable one)", s3.front.said());
                }
            }
            CaseVerdict { name: c.name, group: c.group, verdict, reason, result: Some(r.clone()) }
        })
        .collect();
    let (resolv, replies) = dns_replies(m);
    let dns = match verdict_dns_path(resolv.as_deref(), &replies) {
        Ok((v, _)) => v,
        Err(e) => format!("unknown ({e})"),
    };
    // Only an allowlisted case is recorded with a host of ALLOWLISTABLE (judge_case records the IMDS cases and
    // s3-imds-role's no_role alone).
    let allowlisted = cases.iter().filter(|c| c.verdict == Verdict::Recorded).filter_map(|c| allowlisted_case(c.name, allowlisted)).map(str::to_string).collect();
    Judgement { cases, ready: m.ready, finished: m.finished, dns, allowlisted, s3: s3.clone() }
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
    let ready = m.ready.map(|w| format!(", reached {} s after the script began", w.secs)).unwrap_or_default();
    Ok((verdict, format!("{note}; the proxy answered before and after (allowed, allowed-last: HTTP 401){ready}")))
}

// ---- squid's log ------------------------------------------------------------------------------

/// The squid lines of a `logs filter-log-events` answer (`events[].message`);
/// messages of another format are skipped.
pub fn squid_lines(doc: &serde_json::Value) -> std::result::Result<Vec<SquidLine>, String> {
    let events = doc.get("events").and_then(|e| e.as_array()).ok_or("logs filter-log-events: no events in the answer")?;
    Ok(events.iter().filter_map(|e| e.get("message").and_then(|m| m.as_str())).filter_map(parse_squid_line).collect())
}

/// When squid logged `l` (`%ts.%03tu`: a transaction is logged when it ends), in milliseconds; `None` when the time
/// does not parse (squid always writes `<seconds>.<3 digits>`).
fn squid_ms(l: &SquidLine) -> Option<u64> {
    let (secs, frac) = l.ts.split_once('.').unwrap_or((l.ts.as_str(), ""));
    let ms: String = frac.chars().chain(std::iter::repeat('0')).take(3).collect();
    secs.parse::<u64>().ok()?.checked_mul(1000)?.checked_add(ms.parse().ok()?)
}

fn line_text(l: &SquidLine) -> String {
    format!("{}/{} {} {}:{} from {}", l.code, l.status, l.method, l.host, l.port.map_or_else(|| "-".to_string(), |p| p.to_string()), l.client)
}

/// The allowlisted host the `allowed` cases ask (port 443 through the proxy).
const ALLOWED_HOST: &str = "api.anthropic.com";

/// The requests of a run the proxy had to refuse: (method, host, port) —
/// all but those the allowlist lets through ([`allowlisted_request`]:
/// CONNECT github.com:443 while `allowlisted` holds github.com). The nonce
/// host, the IP literal, the other ports, the other S3 host
/// (`proxy-s3-other-host`, S9) and plain http stay, whatever `allowlisted`
/// says.
#[must_use]
pub fn refused_requests(nonce: &str, allowlisted: &BTreeSet<String>) -> Vec<(&'static str, String, u16)> {
    let all = vec![
        ("CONNECT", denied_host(nonce), 443),
        ("CONNECT", "1.1.1.1".to_string(), 443),
        ("CONNECT", "api.anthropic.com".to_string(), 8443),
        ("CONNECT", "github.com".to_string(), 443),
        ("CONNECT", S3_REGIONAL_HOST.to_string(), 443),
        ("GET", "api.anthropic.com".to_string(), 8080),
    ];
    all.into_iter().filter(|(m, h, p)| !allowlisted_request(m, h, Some(*p), allowlisted)).collect()
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
/// ([`refused_requests`]), and no `TCP_TUNNEL` to any of them that can be
/// this run's: every VM shares the connector's address, so a tunnel to a host
/// an operator may allowlist for a while (github.com) that squid logged
/// before the run's own refusal of that host is an earlier run's (see below).
/// An AWS service host (the other S3 host) is never allowlisted (`ai-env
/// egress allow` refuses one, S7 D2): a tunnel to it is a violation whenever
/// squid logged it. While `allowlisted` (the run's [`allowlisted_hosts`])
/// holds such a host, its CONNECT on 443 is neither required refused nor,
/// tunnelled, a violation ([`allowlisted_request`]); a tunnel to it on
/// another port still is.
#[must_use]
pub fn squid_evidence(lines: &[SquidLine], nonce: &str, from_s: u64, to_s: u64, tunnels: usize, allowlisted: &BTreeSet<String>) -> SquidEvidence {
    let at = |l: &SquidLine| l.ts.split('.').next().and_then(|s| s.parse::<u64>().ok());
    let window: Vec<&SquidLine> = lines.iter().filter(|l| at(l).is_some_and(|t| (from_s..=to_s).contains(&t))).collect();
    let host = denied_host(nonce);
    let mine: Vec<&&SquidLine> = window.iter().filter(|l| l.host == host).collect();
    if let Some(l) = mine.iter().find(|l| l.code.starts_with("TCP_TUNNEL") || (200..300).contains(&l.status)) {
        return SquidEvidence::Violation(format!("squid let the run's denied host through: {}", line_text(l)));
    }
    if let Some(l) = mine.iter().find(|l| !in_cidr(&l.client, VM_SUBNET_CIDR)) {
        return SquidEvidence::Violation(format!("the run's request came from {}, outside the VM subnet {VM_SUBNET_CIDR}: {}", l.client, line_text(l)));
    }
    let Some(anchor) = mine.iter().find(|l| l.code == "TCP_DENIED" && l.status == 403 && l.method == "CONNECT" && l.port == Some(443)) else {
        return SquidEvidence::Missing(vec![format!("TCP_DENIED/403 CONNECT {host}:443 from {VM_SUBNET_CIDR}")]);
    };
    let (client, nonce_ms) = (anchor.client.clone(), squid_ms(anchor));
    let from: Vec<&&SquidLine> = window.iter().filter(|l| l.client == client).collect();
    // What squid must have refused in this run (the allowlist's CONNECTs aside), and the hosts it must not have
    // tunnelled to: every host the run asked it to refuse.
    let refused = refused_requests(nonce, allowlisted);
    let asked = refused_requests(nonce, &BTreeSet::new());
    // A refused host, on any port — but the allowlisted API host only on the ports it was refused on, and never a
    // tunnel the allowlist lets through (CONNECT github.com:443 while it is allowlisted).
    let refused_tunnel = |l: &SquidLine| !allowlisted_request(&l.method, &l.host, l.port, allowlisted) && asked.iter().any(|(_, h, p)| l.host == *h && (h != ALLOWED_HOST || l.port == Some(*p)));
    // Every VM reaches squid from the connector's one address (measured 2 Oct 2026: two VMs at once, both
    // 10.42.1.158), so `from` holds other runs' lines too. A tunnel squid must never open (an IP literal, a port other
    // than 443) is a violation whoever opened it. A host an operator may allowlist for a while (`ai-env egress allow`:
    // github.com; the API host is refused only on other ports, and a tunnel to the nonce host returned above) may have
    // been tunnelled by an earlier run while it was allowed (`make test-egress` does it). Removing a host restarts
    // squid (reload.sh), which ends and logs every tunnel, so such a tunnel is logged before squid refuses the host
    // again: a tunnel to it counts unless squid logged it before this run's own refusal of the host — the run's
    // CONNECT 403 from its client within one case's budget before its nonce line (the cases just before, each refused
    // at once; the earliest there, should another run's refusal fall in the slot too: a tunnel logged after it was
    // open while squid refused the host). While no such refusal is in the log (CloudWatch may deliver it after the
    // nonce line), the evidence is missing. An AWS service host (the other S3 host, S9) is never allowlisted (S7 D2):
    // a tunnel to it is a violation whenever it was logged.
    let allowlistable = |l: &SquidLine| l.port == Some(443) && is_valid_host(&l.host) && !is_aws_service_host(&l.host);
    let slot_ms = u64::try_from(CASE_BUDGET.as_millis()).unwrap_or(u64::MAX);
    let run_refusal = |h: &str| {
        from.iter()
            .filter(|l| l.code == "TCP_DENIED" && l.status == 403 && l.method == "CONNECT" && l.host == h && l.port == Some(443))
            .filter_map(|l| squid_ms(l))
            .filter(|t| nonce_ms.and_then(|n| n.checked_sub(*t)).is_some_and(|before| before <= slot_ms))
            .min()
    };
    let (mut bad, mut unplaced, mut earlier) = (Vec::new(), Vec::<String>::new(), Vec::<String>::new());
    for l in from.iter().filter(|l| l.code.starts_with("TCP_TUNNEL") && refused_tunnel(l)) {
        if !allowlistable(l) {
            bad.push(line_text(l));
            continue;
        }
        match run_refusal(&l.host) {
            Some(refusal) if squid_ms(l).is_some_and(|end| end < refusal) => earlier.push(l.host.clone()),
            Some(_) => bad.push(line_text(l)),
            None => unplaced.push(l.host.clone()),
        }
    }
    if !bad.is_empty() {
        return SquidEvidence::Violation(format!("squid opened tunnels to hosts this run was refused: {}", bad.join("; ")));
    }
    unplaced.sort();
    unplaced.dedup();
    let mut missing: Vec<String> = unplaced
        .iter()
        .map(|h| format!("TCP_DENIED/403 CONNECT {h}:443 from {client} within {} s before the run's nonce line (a tunnel to {h} is logged: squid's own refusal of it in this run places it)", CASE_BUDGET.as_secs()))
        .collect();
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
    earlier.sort();
    earlier.dedup_by(|a, b| a == b);
    let not_ours = match earlier.len() {
        0 => String::new(),
        _ => format!(" (tunnels to {} logged before this run refused it: an earlier run's, not counted)", earlier.join(", ")),
    };
    let skipped: Vec<&str> = asked.iter().filter(|r| !refused.contains(r)).map(|(_, h, _)| h.as_str()).collect();
    let skipped = if skipped.is_empty() { String::new() } else { format!("; allowlisted, not required refused: {}", skipped.join(", ")) };
    SquidEvidence::Complete(format!(
        "from {client}: {opened} tunnels to api.anthropic.com:443; TCP_DENIED/403 for {}; no tunnel to a refused host{not_ours}{skipped}",
        refused.iter().map(|(m, h, p)| format!("{m} {h}:{p}")).collect::<Vec<_>>().join(", ")
    ))
}

/// Poll squid's log in CloudWatch (the operator's aws CLI: `logs
/// filter-log-events --filter-pattern '"aienv"'` over the script's window,
/// widened by [`CLOCK_SKEW_S`]) until [`squid_evidence`] is complete, a
/// violation shows, or `budget` passes (then what is missing is the error).
/// `allowlisted`: the hosts the cases were judged with ([`judge_with`]).
pub async fn squid_poll(nonce: &str, started_s: u64, ended_s: u64, budget: Duration, step: Duration, allowlisted: &BTreeSet<String>) -> std::result::Result<String, String> {
    let (from_s, to_s) = (started_s.saturating_sub(CLOCK_SKEW_S), ended_s.saturating_add(CLOCK_SKEW_S));
    let start = from_s.saturating_mul(1000).to_string();
    let end = to_s.saturating_add(5 * CLOCK_SKEW_S).saturating_mul(1000).to_string();
    let t0 = Instant::now();
    loop {
        let (s, e) = (start.clone(), end.clone());
        let doc = tokio::task::spawn_blocking(move || awscli::aws_json("logs", &["filter-log-events", "--log-group-name", LOG_GROUP, "--filter-pattern", "\"aienv\"", "--start-time", &s, "--end-time", &e]))
            .await
            .map_err(|e| format!("internal: {e}"))??;
        match squid_evidence(&squid_lines(&doc)?, nonce, from_s, to_s, ALLOWED_CASES.len(), allowlisted) {
            SquidEvidence::Complete(found) => return Ok(format!("{found} (after {} s)", t0.elapsed().as_secs())),
            SquidEvidence::Violation(v) => return Err(v),
            SquidEvidence::Missing(m) if t0.elapsed() >= budget => {
                return Err(format!("not in squid's log within {} s: {} (is the CloudWatch agent shipping {LOG_GROUP}? make egress-logs)", budget.as_secs(), m.join("; ")));
            }
            SquidEvidence::Missing(_) => tokio::time::sleep(step).await,
        }
    }
}

/// What the network verification gave the check.
struct NetworkVerdict {
    /// `Ok(summary)` when every row of `egress status`'s checks is `ok`, else
    /// `Err` naming each row that drifted or could not be verified (or why
    /// none could run).
    result: std::result::Result<String, String>,
    /// The facts of the connector answer it judged ok, when every row is (a
    /// pass binds exactly those: a configuration change after the
    /// verification then shows at the credential gate as live facts that
    /// differ from the record's).
    facts: Option<ConnectorFacts>,
    /// The proxy's effective allowlist, what squid serves (the `parameters`
    /// row ok against a status line saying squid serves them: active, parse
    /// ok, `applied=yes`): `Some` whatever another row says, so a failing
    /// report judges `proxy-github` as a passing one would; `None` when not
    /// proved.
    allowlist: Option<BTreeSet<String>>,
}

/// The network verification for the record ([`NetworkVerdict`]).
fn network_verdict() -> NetworkVerdict {
    let v = match super::cli::network_verification() {
        Ok(v) => v,
        Err(e) => return NetworkVerdict { result: Err(format!("not run: {e}")), facts: None, allowlist: None },
    };
    let bad: Vec<String> = v.rows.iter().filter(|r| r.status != "ok").map(|r| format!("{} {}: {}", r.status, r.check, r.detail)).collect();
    let (result, facts) = if v.rows.is_empty() {
        (Err("no check ran".into()), None)
    } else if bad.is_empty() {
        (Ok(format!("{} checks ok: {}", v.rows.len(), v.rows.iter().map(|r| r.check).collect::<Vec<_>>().join(", "))), v.connector_facts)
    } else {
        (Err(bad.join("; ")), None)
    };
    NetworkVerdict { result, facts, allowlist: v.allowlist }
}

/// The proxy's effective allowlist as SSM holds it now — `allow`, `extras` and
/// `suspended` in one light `get-parameters` (the operator's aws CLI),
/// (allow ∪ extras) − suspended — for the live tests only, which judge
/// `proxy-github` by it ([`judge_with`] over [`allowlisted_hosts`]). Unlike
/// the check's, nothing proves the proxy serves it (no `--status`); `Err`
/// when a list is missing or does not parse.
pub fn live_allowlist() -> std::result::Result<BTreeSet<String>, String> {
    super::cli::read_effective("the live allowlist").map_err(|e| e.to_string())
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
    /// The fresh name the DNS cases asked ([`dns_name`]).
    pub dns_name: String,
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
            Some(Ok(_)) => failures.push("the connector's facts are incomplete (Id, network protocol, subnet, security group): nothing to bind the record to".into()),
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
        allowlisted: ev.judgement.allowlisted.clone(),
        dns: ev.judgement.dns.clone(),
        dns_rule: DNS_RULE,
        // S9: the seven §7.7 S3 cases run, so the pass is EGRESS_RULE-verified (passes recorded before S9, rule 0, stop counting: B1 runs the check again).
        egress_rule: EGRESS_RULE,
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
/// check asked for a VM of its own — RunMicrovm made one or may have (from
/// then on any failure revokes).
#[derive(Default)]
struct Guard {
    since: u64,
    ours: Vec<String>,
    gate: Vec<String>,
    asked: bool,
    image_version: Option<String>,
    /// The VM RunMicrovm made for this check, also when it is gone already (the audit row names it).
    ran: Option<String>,
}

/// A check that ended before its transcript was judged: the error, and the
/// check's own VM as far as it was known.
struct Early {
    error: CliError,
    asked: bool,
    id: Option<String>,
    image_version: Option<String>,
}

/// `--if-needed`: the image version a new VM runs now and its recorded pass,
/// when the credential gate would take that pass as it stands — `None` (run
/// the check) unless all of these hold, read live as the operator (the aws
/// CLI, no Touch ID): the version is the check's own plan's (`[aws].image_arn`
/// and `[aws].image_version` exactly as RunMicrovm gets them) resolved the way
/// RunMicrovm resolves it (`active`: `get-microvm-image`'s
/// latestActiveImageVersion; `N`: `N` or `N.0`; `N.M`) and is runnable
/// (`list-microvm-image-versions`: SUCCESSFUL, ACTIVE); a pass is recorded
/// for it with `connector`, judged by the current DNS rule (a pass judged by
/// an earlier one does not count: its DNS evidence cannot be told from the
/// new, so the full check runs, and stderr says why — every record written
/// before rule 1 is such a pass) and by the current egress rule
/// ([`EGRESS_RULE`]: a pass recorded before S9's S3 cases, rule 0, does not
/// count either); the pass is bound to this very build (its
/// `created_at` the version's `createdAt`, to the second) and to the
/// connector's live facts (`get-network-connector`); and the pass is younger
/// than [`MAX_RECORD_AGE_S`](crate::bridge::egress::MAX_RECORD_AGE_S), the age
/// at which the gate stops taking it (S7 D7). The third value notes a DNS
/// verdict the gate does not accept (`[egress].accept_platform_dns` as
/// configured now), which another check would not change.
fn already_verified(ctx: &Ctx, plan: &run::RunPlan, connector: &str) -> Option<(String, VerifiedRecord, Option<String>)> {
    let image_arn = plan.image_arn.as_str();
    let versions = crate::bridge::infra::read_live_image_versions(image_arn).ok()?;
    let listed = |v: &str| versions.iter().any(|x| x.image_version.as_deref() == Some(v));
    let want = plan.want_version.as_str();
    let version = match want {
        "active" => crate::bridge::infra::read_live_image(image_arn).ok()?.latest_active_image_version.filter(|v| !v.trim().is_empty())?,
        w if w.contains('.') || listed(w) => w.to_string(),
        w => format!("{w}.0"),
    };
    let live = versions.iter().find(|x| x.image_version.as_deref() == Some(version.as_str()))?;
    if live.state.as_deref() != Some("SUCCESSFUL") || live.status.as_deref() != Some("ACTIVE") {
        return None;
    }
    let created = crate::wire::time::parse_rfc3339(live.created_at.as_deref()?)?;
    let rec = EgressVerified::load(&ctx.paths).ok()?.find(image_arn, &version, connector)?.clone();
    if rec.dns_rule < DNS_RULE {
        // Said, because the first `make claude-update` after an install that raised the rule starts a VM for a
        // version that has a recorded pass.
        eprintln!("egress check: the recorded pass of image version {version} was judged by an earlier DNS rule ({}, now {DNS_RULE}): checking again", rec.dns_rule);
        return None;
    }
    if rec.egress_rule < EGRESS_RULE {
        // Likewise for the cases a pass ran (S9: rule 1 adds the S3 cases, §7.7), so `--if-needed` never skips on a
        // pass the credential gate stops taking once it compares the rule too.
        eprintln!("egress check: the recorded pass of image version {version} was judged by an earlier egress rule ({}, now {EGRESS_RULE}): checking again", rec.egress_rule);
        return None;
    }
    if rec.image_created_at.is_none_or(|t| (t - created).abs() > 1) {
        return None;
    }
    // S7 D7: the gate takes a pass only while it is younger than MAX_RECORD_AGE_S, so `--if-needed` must check
    // again once it ages out — otherwise the gate would say "run `ai-env egress check`" and this would skip.
    let age = crate::wire::time::parse_rfc3339_utc(&rec.at).map(|at| crate::wire::time::unix_now().saturating_sub(at));
    if age.is_none_or(|a| a > crate::bridge::egress::MAX_RECORD_AGE_S) {
        let days = crate::bridge::egress::MAX_RECORD_AGE_S / (24 * 60 * 60);
        eprintln!("egress check: the recorded pass of image version {version} ({}) is older than {days} days, which the credential gate no longer takes: checking again", rec.at);
        return None;
    }
    let doc = awscli::aws_json("lambda-core", &["get-network-connector", "--identifier", connector]).ok()?;
    let facts = ConnectorFacts::from_get(&doc)?;
    if !rec.connector_facts.complete() || facts != rec.connector_facts {
        return None;
    }
    let note = (!dns_accepted(&rec.dns, &ctx.cfg.egress))
        .then(|| format!("its DNS verdict {} is not accepted ({}): the credential gate refuses this pass until it is (another check would see the same)", rec.dns, ctx.cfg.egress.dns_acceptance()));
    Some((version, rec, note))
}

/// Before the check asks for a VM: the egress proxy (state/infra.toml's
/// proxy_instance_id, as the operator) must be running — a check through a
/// stopped proxy can only fail, and a failure of the check's own VM revokes
/// every pass of the connector. `Err` when it is in another state (gone —
/// terminated, shutting down, unknown to EC2 — means the state file is stale,
/// as `proxy start` says); an unreadable state lets the check go on (its
/// network verification reads it again).
fn proxy_running(ctx: &Ctx) -> Result<()> {
    let Some(id) = read_infra_state(&ctx.paths).ok().flatten().and_then(|s| s.proxy_instance_id).filter(|id| !id.trim().is_empty()) else {
        return Ok(());
    };
    let id = id.trim();
    match super::cli::proxy_state(id) {
        Ok(super::cli::ProxyState::Live(state)) if state != "running" => {
            Err(CliError::Msg(format!("egress check: the egress proxy {id} is {state}: make proxy-start, then run the check again (nothing started, nothing revoked)")))
        }
        Ok(super::cli::ProxyState::Gone) => Err(CliError::Msg(format!("egress check: {}; then make proxy-start if it is stopped, and run the check again (nothing started, nothing revoked)", super::cli::proxy_gone(id)))),
        _ => Ok(()),
    }
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

/// `ai-env egress check [--vm ID] [--keep] [--json] [--if-needed]` (see the module doc).
pub fn cmd_check(store: &Keystore, vm: Option<&str>, keep: bool, json: bool, if_needed: bool) -> Result<()> {
    let ctx = Ctx::load()?;
    let connector = configured_connector(&ctx.cfg)?;
    // S8 operators: the check's network verification sends the proxy's status document, so a stale ai-env is
    // refused before any VM or Touch ID (an unreadable state lets the check go on: that verification reads it
    // again); then the operator identity, its Touch ID before the runtime key's.
    if let Ok(Some(state)) = read_infra_state(&ctx.paths) {
        super::cli::check_documents_of(&ctx.paths, &state)?;
    }
    identity::operator().map_err(|e| identity::labelled("egress check", e))?;
    if if_needed {
        // Resolved from exactly what the check's own RunMicrovm would get (a value it refuses never skips).
        let plan = check_plan(&ctx)?;
        if let Some((version, rec, dns_note)) = already_verified(&ctx, &plan, &connector) {
            if json {
                let doc = serde_json::json!({
                    "skipped": true, "image_version": version, "connector": normalize_connector(&connector), "recorded_vm": rec.vm_id, "recorded_at": rec.at, "dns": rec.dns,
                    "dns_accepted": dns_note.is_none(),
                });
                outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
            } else {
                outln!("egress check: image version {version}, the one a new VM runs, already has a passing check with {} (VM {}, {}), bound to this build and to the connector's live facts: nothing started (without --if-needed it checks again)", normalize_connector(&connector), rec.vm_id, rec.at);
                if let Some(note) = dns_note {
                    outln!("egress check: note: {note}");
                }
            }
            return Ok(());
        }
    }
    let target = match vm {
        Some(id) => Target::Existing(Box::new(existing_vm(&ctx, id, &connector)?)),
        None => Target::Start(Box::new(check_plan(&ctx)?)),
    };
    awscli::require_operator_account(&connector).map_err(|e| identity::labelled("egress check", e))?;
    proxy_running(&ctx)?;
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
async fn run_check<A: MicrovmApi + crate::bridge::s3::S3Sign, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, target: &Target, fake: bool, keep: bool, connector: &str) -> std::result::Result<Evidence, Early> {
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
    outcome.map_err(|error| Early { error, asked: guard.asked, id: guard.gate.first().or(guard.ours.first()).or(guard.ran.as_ref()).cloned(), image_version: guard.image_version.clone() })
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

/// The three presigned URLs the S3 cases read from the shell's stdin, in the
/// order the script reads them into `AIENV_U` (CASES order): `s3-own`'s PUT
/// then GET of `v1/_egress-check/<nonce>`, and `s3-own-outside-prefix`'s PUT
/// of `x/_egress-check/<nonce>` (IAM refuses the prefix). Each writes a
/// zero-byte object, signed only by the runtime key; `x-amz-expected-bucket-owner`
/// is signed in every one. They expire [`PRESIGN_EXPIRY`](crate::wire::s3::PRESIGN_EXPIRY)
/// after the script starts: a run whose earlier cases take longer fails `s3-own`.
pub async fn s3_probe_urls<A: crate::bridge::s3::S3Sign>(api: &A, target: &crate::bridge::s3::S3Target, nonce: &str) -> std::result::Result<Vec<crate::wire::s3::PresignedUrl>, BridgeError> {
    use crate::bridge::s3::{presign, S3Method};
    use crate::wire::s3::{S3Key, PRESIGN_EXPIRY};
    /// sha256 of the empty body every probe PUT writes.
    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let own = S3Key::EgressCheck { nonce: nonce.to_string() }.render();
    let outside = S3Key::OutsideProbe { nonce: nonce.to_string() }.render();
    let put_h = presign::write_headers(0, EMPTY_SHA, true)?;
    let reqs = [
        presign::request(S3Method::Put, target, Some(own.clone()), vec![], put_h.clone(), PRESIGN_EXPIRY),
        presign::request(S3Method::Get, target, Some(own), vec![], vec![], PRESIGN_EXPIRY),
        presign::request(S3Method::Put, target, Some(outside), vec![], put_h, PRESIGN_EXPIRY),
    ];
    let mut out = Vec::with_capacity(reqs.len());
    for r in &reqs {
        out.push(api.presign(r).await?);
    }
    Ok(out)
}

/// Run a check `script` (of run `nonce`) on VM `id` through the platform
/// shell and return what it printed, never printing or logging it. A script
/// without a URL read loop ([`url_reads`] 0: [`render_cases`]) goes out at
/// once (`vm::shell::run_script`). One with it — every full check
/// ([`render_script_with`]) — needs `target` (`Config` without it): `api`
/// presigns exactly the URLs the loop reads ([`s3_probe_urls`]), the script
/// goes out up to and including the loop's line, and the URLs, one per line,
/// then the rest of the script, only once the output shows [`urls_marker`]
/// (`vm::shell::run_script_frames`): the script has turned its terminal's
/// echo off by then and reads them silently, so they are never in the script
/// text, the shell's argv or environment, or the returned output (§2.2's
/// third `expose()`); `aienv_s3do` then hands each to curl as its URL
/// argument, an argv inside the VM only, which runs no agent (the check's
/// own VM, or the `--shell` VM `--vm` names, on which every spawn is
/// refused). When the marker never shows, no URL is typed and the S3 cases
/// have no result.
pub async fn run_check_script<A: MicrovmApi + crate::bridge::s3::S3Sign>(api: &A, id: &str, script: &str, nonce: &str, target: Option<&crate::bridge::s3::S3Target>, budget: Duration, auth: ShellAuth) -> std::result::Result<String, BridgeError> {
    if url_reads(script) == 0 {
        return shell::run_script(api, id, script, budget, auth).await;
    }
    let target = target.ok_or_else(|| BridgeError::Config("egress check: the script reads presigned URLs, but no transcripts bucket was resolved (make infra-status WRITE=1)".into()))?;
    let urls = s3_probe_urls(api, target, nonce).await?;
    let exposed: Vec<&str> = urls.iter().map(crate::wire::s3::PresignedUrl::expose).collect();
    let (first, then) = script_frames(script, &exposed).map_err(|e| BridgeError::Config(format!("egress check (internal): {e}")))?;
    let marker = urls_marker(nonce);
    let gated: Vec<shell::Gated<'_>> = then.iter().map(|t| shell::Gated { after: &marker, text: t.expose() }).collect();
    shell::run_script_frames(api, id, first, &gated, budget, auth).await
}

/// Resolve the transcripts bucket before anything starts (a configuration
/// failure revokes nothing), acquire the VM and wait for its `/health`,
/// refuse the fake (unless its transcript knob stands in for the shell), GET
/// the front object anonymously ([`front_object`]), run the script
/// ([`run_check_script`]), read its markers, then the network verification
/// (always, once a transcript exists), judge the markers by the effective
/// allowlist it proved and the S3 facts ([`judge_with`]), and squid's log
/// (only when every case and the network passed).
async fn gather<A: MicrovmApi + crate::bridge::s3::S3Sign, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, target: &Target, fake: bool, connector: &str, guard: &mut Guard) -> Result<Evidence> {
    // The transcripts bucket the S3 cases (§7.7) probe, resolved before the check asks for its VM: a state/infra.toml
    // that records none (before the S9 deploy and `make infra-status WRITE=1`), or another, is a configuration failure,
    // which revokes nothing. The file-backed fake runs no script.
    let bucket = if fake { None } else { Some(crate::bridge::s3::S3Target::resolve(&ctx.paths, &ctx.knobs)?) };
    let (row, vm, own) = match target {
        Target::Existing(row) => ((**row).clone(), live_vm(ctx, api, row).await?, false),
        Target::Start(plan) => {
            let (row, vm) = start_vm(ctx, api, ep, plan, guard).await?;
            guard.image_version = Some(vm.image_version.clone());
            (row, vm, true)
        }
    };
    health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
    // The check VM's execution role, as its run plan gave it (the row) or the VM echoes it: without one, s3-imds-role
    // has nothing to try; with one, IMDS must hand its credentials over.
    let named = |r: Option<&str>| r.is_some_and(|r| !r.trim().is_empty());
    let has_role = named(row.execution_role.as_deref()) || named(vm.execution_role_arn.as_deref());
    let started_s = unix_now();
    let (nonce, output, front) = match &bucket {
        None => {
            let (nonce, output) = fake_transcript("egress check")?;
            (nonce, output, FrontObject::Lab)
        }
        Some(bucket) => {
            let nonce = new_nonce();
            // First, from the Mac: is the object the fronting cases ask readable by anyone (§7.7)?
            let front = front_object().await;
            eprintln!("egress check: the front object {} {}", front_object_url(), front.said());
            // The script asks the bucket's host; the Mac presigns the URLs it reads from its stdin and types them only
            // once it asks (run_check_script).
            let script = render_script_with(&nonce, &proxy_ip(&ctx.cfg, &ctx.paths), &S3Probe::of(bucket));
            let budget = script_budget(CASES.len());
            eprintln!("egress check: {} cases on {} through the platform shell (at most {} s)", CASES.len(), vm.id, budget.as_secs());
            let output = run_check_script(api, &vm.id, &script, &nonce, Some(bucket), budget, ShellAuth::Header).await?;
            (nonce, output, front)
        }
    };
    let ended_s = unix_now();
    let markers = parse_markers(&output, &nonce);
    eprintln!("egress check: verifying the network (every check of `ai-env egress status`)");
    let net = tokio::task::spawn_blocking(network_verdict).await.unwrap_or_else(|e| NetworkVerdict { result: Err(format!("internal: {e}")), facts: None, allowlist: None });
    // Judged by what squid serves, read after the cases ran: a host removed in between fails closed (judged, and
    // OPEN); one added in between only keeps the record from claiming it refused. Not proved: every case strictly.
    let skip = allowlisted_hosts(&net.allowlist.unwrap_or_default());
    let s3 = S3Facts { has_role, front };
    let (judgement, transcript) = match markers {
        Ok(m) => (judge_with(&m, &skip, &s3), Ok(())),
        Err(e) => (judge_with(&Markers::default(), &skip, &s3), Err(e)),
    };
    // Said once judged, never from `skip` alone: only a case with a result is recorded, not judged — an unreadable
    // transcript, or a script that died before the case, leaves it judged, and failing.
    if !judgement.allowlisted.is_empty() {
        eprintln!("egress check: allowlisted: {}", allowlisted_text(&judgement.allowlisted));
    }
    for host in skip.iter().filter(|h| !judgement.allowlisted.contains(h)) {
        let why = if transcript.is_err() { "the transcript could not be read" } else { "the script did not reach it" };
        eprintln!("egress check: {host} is on the proxy's effective allowlist as the network verification read it, but its case has no result ({why}): it is judged, and fails");
    }
    let (network, verified_facts) = (net.result, net.facts);
    let squid = if transcript.is_ok() && judgement.passed() && network.is_ok() {
        let (budget, step) = (scaled(SQUID_LOG_BUDGET, ctx.knobs.backoff_ms), scaled(SQUID_LOG_STEP, ctx.knobs.backoff_ms));
        eprintln!("egress check: every case passed; reading squid's log in CloudWatch (at most {} s)", budget.as_secs());
        Some(squid_poll(&nonce, started_s, ended_s, budget, step, &skip).await)
    } else {
        None
    };
    // What a record of its own VM is bound to, only when it could record: the connector answer the network
    // verification judged (never a later read, which a change in between would make the record's), and the image
    // version's created_at.
    let (connector_facts, image_created_at) = if own && matches!(squid, Some(Ok(_))) {
        let facts = verified_facts.ok_or_else(|| format!("the get-network-connector answer for {connector} that the network verification judged has no Id, network protocol, subnet or security group"));
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
        dns_name: dns_name(&nonce),
    })
}

/// The `created_at` of `version` of `image_arn` (`ListMicrovmImageVersions`).
async fn image_created_at<A: MicrovmApi>(api: &A, image_arn: &str, version: &str) -> std::result::Result<i64, String> {
    let versions = api.list_image_versions(image_arn).await.map_err(|e| e.to_string())?;
    let v = versions.iter().find(|v| v.version == version).ok_or_else(|| format!("version {version} of {image_arn} is not listed"))?;
    v.created_at_unix.ok_or_else(|| format!("version {version} of {image_arn} reports no created_at"))
}

/// The report's line about the script's wait for the proxy.
fn ready_text(ready: Option<Ready>) -> String {
    match ready {
        Some(w) if w.ok => format!("ready: the VM reached the proxy's port {} s after the script began ({} attempt{})", w.secs, w.tries, if w.tries == 1 { "" } else { "s" }),
        Some(w) => format!("ready: the VM did NOT reach the proxy's port in {} s ({} attempts)", w.secs, w.tries),
        None => "ready: no marker (the script did not get that far)".to_string(),
    }
}

/// What a run's allowlisted hosts mean (the report's `allowlisted:` line, and stderr): the hosts whose cases were
/// recorded, not judged ([`Judgement::allowlisted`]), never merely those on the effective allowlist.
fn allowlisted_text(hosts: &[String]) -> String {
    let (case, it) = if hosts.len() == 1 { ("its case is", "it") } else { ("their cases are", "them") };
    format!("{} (on the proxy's effective allowlist as the network verification read it: {case} recorded, not judged, and this check does not show squid refusing {it})", hosts.join(", "))
}

/// A poll duration under the lab's `AI_ENV_BRIDGE_LAB_BACKOFF_MS` (1 s → n ms).
fn scaled(d: Duration, ms_per_second: Option<u64>) -> Duration {
    match ms_per_second {
        Some(n) => Duration::from_millis(u64::try_from(d.as_millis().saturating_mul(u128::from(n)) / 1000).unwrap_or(u64::MAX)),
        None => d,
    }
}

/// Under the file-backed fake, for `label` (`egress check`, `dns-path`): the
/// refusal (it cannot carry a shell), or — debug builds, with
/// [`FAKE_SHELL_KNOB`] set — the transcript that file holds and the nonce of
/// its markers, so process tests reach the judgement (an unreadable or
/// marker-less file is exit 1).
pub(crate) fn fake_transcript(label: &str) -> std::result::Result<(String, String), BridgeError> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os(FAKE_SHELL_KNOB).filter(|p| !p.is_empty()) {
        let text = std::fs::read_to_string(&path).map_err(|e| BridgeError::Config(format!("{FAKE_SHELL_KNOB}: cannot read {}: {e}", std::path::Path::new(&path).display())))?;
        let nonce: String = text.split(MARK).nth(1).map(|rest| rest.chars().take_while(char::is_ascii_hexdigit).collect()).unwrap_or_default();
        if !is_nonce(&nonce) {
            return Err(BridgeError::Config(format!("{FAKE_SHELL_KNOB}: no {MARK}<nonce> marker in the file")));
        }
        eprintln!("ai-env: LAB KNOB ACTIVE ({FAKE_SHELL_KNOB}): the shell's transcript of {label} is read from a file (debug build)");
        return Ok((nonce, text));
    }
    Err(shell::fake_backend_refusal(label))
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
            guard.asked = true;
            guard.ours.push(vm.id.clone());
            eprintln!("egress check: started {} (egress {})", vm.id, vm.egress.join(", "));
            Ok((row, vm))
        }
        Ok(run::Selected::Reused { vm, .. }) => Err(CliError::Msg(format!("egress check reused {} (internal)", vm.id))),
        Err(f) => {
            // The check has asked for its VM once RunMicrovm made one — alive or not: the egress gate may have
            // rejected and terminated it — or may have (a kept pending row). A refusal before that (the
            // [vm].max_concurrent placement, a bad image version, a definite RunMicrovm refusal) proves nothing about
            // egress and revokes nothing.
            if f.ran.is_some() || f.started.is_some() || f.kept_pending.is_some() {
                guard.asked = true;
            }
            if guard.ran.is_none() {
                guard.ran = f.ran.as_deref().map(str::to_string);
            }
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
/// neither); audit `egress_check {id, image_version, verdict[, revoked][,
/// allowlisted]}`; print (one JSON document with `--json`), with the hosts
/// recorded, not judged, named (`allowlisted:`); exit 9 naming every failure.
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
    if let Some(w) = ev.judgement.ready {
        pairs.push(("ready", format!("{}s/{}/{}", w.secs, w.tries, if w.ok { "ok" } else { "never" })));
    }
    if !ev.judgement.allowlisted.is_empty() {
        pairs.push(("allowlisted", ev.judgement.allowlisted.join(",")));
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
    // What the credential gate would do with the run's DNS verdict under the configuration in force (a pass is
    // recorded either way: the record keeps the evidence, the gate reads the pin when it decides).
    let dns_ok = dns_accepted(&ev.judgement.dns, &ctx.cfg.egress);
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
                    "dns_status": r.status, "recursion_available": r.ra, "dns_answers": r.answers, "dns_authority": r.authority,
                    "put": r.put, "get": r.get, "s3_code": r.s3,
                })
            })
            .collect();
        let s3 = &ev.judgement.s3;
        let front = serde_json::json!({
            "bucket": FRONT_OBJECT_BUCKET, "key": FRONT_OBJECT_KEY, "readable": s3.front.readable(),
            "status": match s3.front { FrontObject::Status(st) => Some(st), _ => None }, "detail": s3.front.said(),
        });
        let doc = serde_json::json!({
            "backend": ctx.backend_name(), "id": ev.id, "report_only": !ev.own, "image_arn": ev.row_image_arn, "image_version": ev.vm_image_version,
            "echoed_image_arn": ev.vm_image_arn, "row_image_version": ev.row_image_version, "connector": normalize_connector(connector),
            "denied_host": ev.denied_host, "finished": ev.judgement.finished, "transcript_error": ev.transcript.as_ref().err(), "cases": cases,
            "front_object": front, "execution_role": s3.has_role,
            "ready": ev.judgement.ready.map(|w| serde_json::json!({"tries": w.tries, "secs": w.secs, "ok": w.ok})),
            "dns": ev.judgement.dns, "dns_name": ev.dns_name, "dns_accepted": dns_ok, "dns_acceptance": ctx.cfg.egress.dns_acceptance(),
            "allowlisted": ev.judgement.allowlisted,
            "network": { "ok": network_ok, "detail": network_text }, "squid_log": { "ok": squid_ok, "detail": squid_text },
            "evidence": EVIDENCE_NOTE, "verdict": verdict, "recorded": d.record.is_some(),
            "revoked": revoked.as_ref().map(|r| r.as_ref().map_or_else(|e| serde_json::json!({"error": e}), |n| serde_json::json!(n))), "failures": d.failures,
        });
        outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        outln!("egress check of {} (image version {}; connector {}){}", ev.id, ev.vm_image_version, normalize_connector(connector), if ev.own { "" } else { " — report only (--vm)" });
        outln!("note: {EVIDENCE_NOTE}");
        outln!("{}", ready_text(ev.judgement.ready));
        outln!("{}", ev.judgement.s3.said());
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
        if !ev.judgement.allowlisted.is_empty() {
            outln!("allowlisted: {}", allowlisted_text(&ev.judgement.allowlisted));
        }
        outln!("dns: {} (asked {} A; the credential gate {} it: {})", ev.judgement.dns, ev.dns_name, if dns_ok { "accepts" } else { "does NOT accept" }, ctx.cfg.egress.dns_acceptance());
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
        format!("@@AIENV{NONCE} {name} rc={rc} ns={ns} res={} st=none ra=none an=none au=none", if res { "yes" } else { "no" })
    }

    /// The platform stub's reply as measured on 2 Oct 2026: NOERROR, no answer, no authority, recursion offered.
    fn stub(name: &str, ns: &str) -> String {
        format!("@@AIENV{NONCE} {name} rc=0 ns={ns} res=no st=NOERROR ra=yes an=0 au=0")
    }

    /// An S3 case marker (§7.7): `put`, `get`, `hc` and `s3` (the `<Code>`, or `-`).
    fn s3line(name: &str, put: &str, get: &str, hc: &str, s3: &str) -> String {
        format!("@@AIENV{NONCE} {name} rc=0 put={put} get={get} hc={hc} s3={s3}")
    }

    /// Every case's marker in a closed, working VPC: the S3 cases with a role
    /// (s3-own stored and read back through the endpoint, the rest refused 403
    /// AccessDenied, s3-direct not connected, proxy-s3-other-host CONNECT 403).
    fn passing() -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = CASES
            .iter()
            .map(|c| {
                let line = match c.name {
                    "allowed" | "allowed-last" => curl(c.name, 0, "401", "1", "200", false, false),
                    "direct-name" | "s3-direct" => curl(c.name, 6, "000", "0", "000", false, false),
                    "direct-ipv6" => curl(c.name, 7, "000", "0", "000", false, false),
                    "direct-ipv4" | "direct-http" | "proxy-other-port" => curl(c.name, 28, "000", "0", "000", false, false),
                    "imds" | "imds-v6" => curl(c.name, 0, "401", "1", "000", false, false),
                    "proxy-http-8080" => curl(c.name, 0, "403", "1", "000", false, true),
                    "s3-own" => s3line(c.name, "200", "200", "200", "-"),
                    "s3-front-bucket" | "s3-front-path" => s3line(c.name, "000", "403", "200", "AccessDenied"),
                    "s3-own-outside-prefix" | "s3-imds-role" => s3line(c.name, "403", "000", "200", "AccessDenied"),
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

    /// [`judged`] by these S3 facts, nothing allowlisted.
    fn judged_by(lines: &[(String, String)], s3: &S3Facts) -> Judgement {
        judge_with(&parse_markers(&transcript(lines), NONCE).unwrap(), &BTreeSet::new(), s3)
    }

    /// The bounds of the script's two typed parts (bytes; 6182 and 2059 as rendered here): up to and including the URL
    /// read loop, typed at once, and the rest, typed after the URLs (about 1.5 KB).
    const PRE_MAX: usize = 6400;
    const POST_MAX: usize = 2200;

    fn verdict_of<'a>(j: &'a Judgement, name: &str) -> &'a CaseVerdict {
        j.cases.iter().find(|c| c.name == name).unwrap()
    }

    fn failing(j: &Judgement) -> Vec<&'static str> {
        j.cases.iter().filter(|c| c.verdict == Verdict::Fail).map(|c| c.name).collect()
    }

    #[test]
    fn the_script_is_small_plain_and_never_parses_as_markers() {
        let s = render_script(NONCE, PROXY_IP);
        // Each line stays under a terminal's canonical buffer. The script is typed in two parts (run_check_script): up
        // to and including its URL read loop at once, then — once it asks, its terminal's echo off — the presigned
        // URLs (about 1.5 KB) and the rest. S5 measured the platform shell taking a 3.9 KB script at once; the first
        // live check of S9 (B1) confirms it takes these.
        let (pre, post) = split_url_reads(&s).expect("the script reads URLs from stdin");
        assert!(pre.len() < PRE_MAX && post.len() < POST_MAX && s.len() < PRE_MAX + POST_MAX, "{} + {} bytes: too large", pre.len(), post.len());
        assert!(!s.contains('\t') && !s.contains('!'), "no tab (completion) and no ! (history expansion)");
        assert!(s.lines().all(|l| l.len() < 1024), "short lines");
        assert!(s.starts_with("\\unalias -a; unset -f command curl dig printf 2>/dev/null; hash -r; unset HISTFILE; set +H\n") && s.ends_with("\nexit\n"), "{s}");
        assert!(s.contains("command curl -q -sS ") && s.contains("command dig -r "), "no .curlrc, no .digrc, no alias or function");
        // The DNS cases ask the run's fresh name; example.com only in the second, address-only query.
        assert!(s.lines().nth(1).unwrap().starts_with(&format!("R=AIENV{NONCE}; N=d{NONCE}.example.com; S=;")), "{s}");
        assert!(s.contains("+noall +comments +answer +time=2 +tries=1 \"$@\" \"@$s\" \"$N\" A 2>&1"), "the fresh name with dig's header: {s}");
        assert_eq!(s.matches("example.com A").count(), 1, "example.com is asked once, without the header: {s}");
        assert!(s.contains("[ $rc = 0 ] && { e=$(command dig -r +noall +answer +time=2 +tries=1 \"$@\" \"@$s\" example.com A 2>&1 </dev/null); q=$?; }; "), "only of a server that replied, its exit code kept: {s}");
        assert!(s.contains(&format!("done <<<\"$e\"$'\\n'\"$o\"; [ $q = 0 ] || t={DNS_NO_EXAMPLE}; printf ")), "example.com's output first, so the fresh name's status wins, unless example.com got no reply at all: {s}");
        assert!(HELPERS[1].len() < 1024, "the helper is {} characters", HELPERS[1].len());
        assert!(S3_HELPERS.iter().all(|h| h.len() < 1024), "each S3 helper fits a line");
        assert_eq!(dns_name(NONCE), format!("d{NONCE}.example.com"));
        assert!(dns_name(NONCE) != denied_host(NONCE) && crate::bridge::egress::is_valid_host(&dns_name(NONCE)));
        assert!(!s.contains(MARK), "the echoed script carries no marker");
        assert_eq!(parse_markers(&s, NONCE).unwrap(), Markers::default(), "the echo of the script is not a marker");
        for c in &CASES {
            let line = s.lines().find(|l| l.split_whitespace().nth(1) == Some(c.name)).unwrap_or_else(|| panic!("{} has no line", c.name));
            let want = if c.is_dns() {
                "aienv_d "
            } else if c.is_s3() {
                "aienv_s3"
            } else {
                "aienv_c "
            };
            assert!(line.starts_with(want), "{line}");
            assert!(!line.contains('@'), "every placeholder filled: {line}");
        }
        // The S9 S3 cases (§7.7): their helper lines, with the lab bucket host filled and the presigned URLs read from
        // stdin (never in the script text), the fronting object asked, and the regional host for proxy-s3-other-host.
        assert!(s.contains(r#"aienv_s3own s3-own "${AIENV_U[0]}" "${AIENV_U[1]}""#), "{s}");
        assert!(s.contains(r#"aienv_s3deny s3-own-outside-prefix "${AIENV_U[2]}" - put"#), "{s}");
        assert!(s.contains("aienv_s3deny s3-front-bucket ") && s.contains("aienv_s3deny s3-front-path ") && s.contains("aienv_s3imds s3-imds-role\n"), "{s}");
        assert!(s.contains("aienv_c s3-direct --noproxy '*' https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/\n"), "{s}");
        assert!(s.contains("aienv_c proxy-s3-other-host https://s3.eu-central-1.amazonaws.com/\n"), "{s}");
        // The URLs reach the script on its stdin: the read loop is there, and splits the script so the Mac can send the
        // URLs after it; the loop reads exactly URL_SLOTS of them. It turns the terminal's echo off before it prints the
        // `urls` marker the Mac waits for (built at run time, so the echo of the script never shows it), and restores the
        // terminal's settings after.
        let loop_line = pre.lines().last().unwrap();
        assert!(loop_line.starts_with("aienv_t=$(command stty -g 2>/dev/null); command stty -echo 2>/dev/null; printf '%s%s urls\\n' '@@' \"$R\"; AIENV_U=(); for aienv_i in 1 2 3; do IFS= read -rs aienv_l; "), "{loop_line}");
        assert!(loop_line.ends_with("; [ -n \"$aienv_t\" ] && command stty \"$aienv_t\" 2>/dev/null") && post.starts_with("export ") && pre.len() + post.len() == s.len(), "pre ends at the read loop, post is the rest: {loop_line}");
        assert_eq!((URL_SLOTS, url_reads(&s)), (3, 3));
        assert!(!s.contains(&urls_marker(NONCE)) && urls_marker(NONCE) == format!("@@AIENV{NONCE} urls"), "{s}");
        // s3-imds-role: every IMDS request fails on an HTTP error (-f), and neither the IMDS token nor the role's
        // credentials are ever on an argv: each goes in a curl config on a file descriptor; the signed PUT carries a length.
        assert_eq!(s.matches("command curl -q -sSf ").count(), 2, "the token PUT and aienv_imds' GET: {s}");
        assert!(s.contains("-K <(printf 'header = \"X-aws-ec2-metadata-token: %s\"\\n' \"$aienv_it\")"), "{s}");
        assert!(s.contains("-K <(printf 'user = \"%s:%s\"\\nheader = \"x-amz-security-token: %s\"\\n' \"$aienv_ak\" \"$aienv_sk\" \"$aienv_tk\") -X PUT --aws-sigv4 'aws:amz:eu-central-1:s3' "), "{s}");
        assert!(S3_HELPERS[5].contains("-H 'Content-Length: 0'") && !s.contains("-H \"X-aws-ec2-metadata-token") && !s.contains("-H \"x-amz-security-token") && !s.contains("--user"), "{s}");
        assert!(S3_HELPERS[5].contains("aienv_ak=; aienv_sk=; aienv_tk=; aienv_it=; printf "), "the credentials are cleared once used");
        assert!(s.contains("aienv_d dns-vpc-udp 10.42.0.2\n") && s.contains("aienv_d dns-subnet-tcp 10.42.1.2 +tcp\n") && s.contains("aienv_d dns-platform6-udp fd00:ec2::253\n"), "{s}");
        assert!(s.contains("aienv_d dns-public-port 208.67.222.222 -p 443\n") && s.contains("aienv_c direct-http --noproxy '*' http://1.1.1.1/\n"), "{s}");
        assert!(s.contains(&format!("aienv_c denied https://n{NONCE}.example.com/\n")), "{s}");
        assert!(s.contains("aienv_c proxy-other-port --noproxy '*' http://10.42.0.10:22/\n"));
        // The proxy exports (both spellings, no_proxy) come right before the first case; allowed runs first and last.
        let lines: Vec<&str> = s.lines().collect();
        let export = lines.iter().position(|l| l.starts_with("export ")).unwrap();
        assert_eq!(lines[export], "export https_proxy='http://10.42.0.10:3128' HTTPS_PROXY='http://10.42.0.10:3128' http_proxy='http://10.42.0.10:3128' HTTP_PROXY='http://10.42.0.10:3128' no_proxy='localhost,127.0.0.1,::1' NO_PROXY='localhost,127.0.0.1,::1'");
        assert!(lines[export + 1] == "aienv_r 10.42.0.10:3128" && lines[export + 2].starts_with("aienv_c allowed "), "{s}");
        assert!(s.contains("aienv_r() {"), "the wait helper is defined");
        assert_eq!(s.matches("aienv_r 10.42.0.10:3128\n").count(), 1, "one wait, right before the first case");
        assert!(s.contains("command sleep 2") && s.contains("--noproxy '*' --connect-timeout 2 --max-time 4 \"http://$1/\""), "a plain TCP connection to the proxy, without the proxy: {s}");
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
        assert_eq!(script_budget(CASES.len()), Duration::from_secs(34 * 12 + 60 + 5 + 30), "the cases, the wait for the proxy, slack");
        assert!(d.contains("aienv_r 10.42.0.10:3128\naienv_c allowed "), "the dns-path script waits too: {d}");
        // render_cases (one frame): every case named but those that ask the transcripts bucket — no read loop, no S3
        // helper, no bucket; proxy-s3-other-host asks none and stays.
        let all: Vec<&str> = CASES.iter().map(|c| c.name).collect();
        let r = render_cases(NONCE, PROXY_IP, &all);
        assert!(url_reads(&r) == 0 && split_url_reads(&r).is_none(), "{r}");
        assert!(!r.contains("AIENV_U") && !r.contains("aienv_s3") && !r.contains(".s3.eu-central-1.amazonaws.com") && !r.contains("stty"), "{r}");
        let rendered: Vec<&str> = r.lines().filter(|l| l.starts_with("aienv_c ") || l.starts_with("aienv_d ")).filter_map(|l| l.split_whitespace().nth(1)).collect();
        let want: Vec<&str> = CASES.iter().filter(|c| !c.needs_bucket()).map(|c| c.name).collect();
        assert_eq!(rendered, want);
        assert_eq!(CASES.iter().filter(|c| c.needs_bucket()).map(|c| c.name).collect::<Vec<_>>(), ["s3-direct", "s3-own", "s3-front-bucket", "s3-front-path", "s3-own-outside-prefix", "s3-imds-role"]);
        assert!(rendered.contains(&"proxy-s3-other-host") && r.len() < 4096, "{} bytes", r.len());
    }

    /// What the Mac types for a check script (`script_frames`): the script up to and including its read loop's line,
    /// then — gated on the `urls` marker — exactly as many one-line URLs as the loop reads, then the rest; a script
    /// without a loop is one part; any other count, or a URL that is not one line, is refused before anything is typed.
    #[test]
    fn script_frames_type_exactly_the_urls_the_loop_reads() {
        let s = render_script(NONCE, PROXY_IP);
        let urls = ["https://u1/a?x=1", "https://u2/b?x=2", "https://u3/c?x=3"];
        let (first, then) = script_frames(&s, &urls).unwrap();
        let then = then.expect("the URLs and the rest");
        let (pre, post) = split_url_reads(&s).unwrap();
        assert_eq!(first, pre);
        assert_eq!(then.expose(), &format!("https://u1/a?x=1\nhttps://u2/b?x=2\nhttps://u3/c?x=3\n{post}"));
        assert!(!first.contains("https://u") && format!("{then:?}").starts_with("[redacted"), "the URLs only in the gated part, which never prints");
        for bad in [&urls[..2], &[urls[0], urls[1], urls[2], urls[0]][..], &[]] {
            assert!(script_frames(&s, bad).unwrap_err().contains("reads 3 presigned URLs from its stdin, not"), "{}", bad.len());
        }
        for bad in [["https://u1/a", "https://u2/b\nexit", "https://u3/c"], ["https://u1/a", "", "https://u3/c"], ["https://u1/a", "https://u2/b\r", "https://u3/c"]] {
            assert!(script_frames(&s, &bad).unwrap_err().contains("presigned URL 2 is not one line"), "{bad:?}");
        }
        // A script without a read loop (render_cases, the dns-path probe): one part, and no URL taken.
        let d = render_dns_script(NONCE, PROXY_IP);
        let (first, then) = script_frames(&d, &[]).unwrap();
        assert!(first == d && then.is_none());
        assert!(script_frames(&d, &urls[..1]).unwrap_err().contains("reads 0 presigned URLs from its stdin, not 1"));
        // The marker the Mac waits for is parsed once, without fields.
        let m = parse_markers(&format!("bash-5.2# x\r\n{}\r\n", urls_marker(NONCE)), NONCE).unwrap();
        assert!(m.urls && m.cases.is_empty() && !m.finished, "{m:?}");
    }

    #[test]
    fn nonces_hosts_and_addresses() {
        let a = new_nonce();
        assert!(is_nonce(&a) && a.len() == 16 && a != new_nonce(), "{a}");
        assert!(crate::bridge::egress::is_valid_host(&denied_host(&a)), "the denied host is a valid host");
        assert!(crate::bridge::egress::is_valid_host(&dns_name(&a)) && dns_name(&a) != denied_host(&a) && dns_name(&a) != dns_name(&new_nonce()), "a fresh name per run, never the denied host");
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

    /// The wait for the proxy (`ready`) and dig's status and recursion flag,
    /// as measured live 1 Oct 2026: the first `allowed` could not connect at
    /// all (rc 7), every later proxied case passed, and `fd00:ec2::253`
    /// replied without an address.
    #[test]
    fn the_wait_for_the_proxy_and_the_dns_status_are_parsed_and_reported() {
        let ready = |line: &str| -> Vec<(String, String)> {
            let mut v = passing();
            v.insert(0, ("ready".to_string(), format!("@@AIENV{NONCE} ready {line}")));
            v
        };
        let m = parse_markers(&transcript(&ready("try=4 s=6 ok=yes")), NONCE).unwrap();
        assert_eq!(m.ready, Some(Ready { tries: 4, secs: 6, ok: true }));
        let j = judge(&m);
        assert!(j.passed() && j.ready == m.ready, "{:?}", j.failures());
        assert_eq!(ready_text(j.ready), "ready: the VM reached the proxy's port 6 s after the script began (4 attempts)");
        assert_eq!(ready_text(Some(Ready { tries: 1, secs: 0, ok: true })), "ready: the VM reached the proxy's port 0 s after the script began (1 attempt)");
        assert!(ready_text(None).contains("no marker"));
        // The live failure: no connection at first. With the wait it says the proxy never came up; without it, it does not.
        let dead = curl("allowed", 7, "000", "0", "000", false, false);
        let mut lines = ready("try=30 s=60 ok=no");
        lines = lines.into_iter().map(|(k, l)| if k == "allowed" { (k, dead.clone()) } else { (k, l) }).collect();
        let j = judged(&lines);
        let allowed = verdict_of(&j, "allowed");
        assert!(allowed.reason.contains("did not answer") && allowed.reason.contains("waited 60 s (30 attempts) and never opened a connection"), "{}", allowed.reason);
        assert!(ready_text(j.ready).contains("did NOT reach the proxy's port in 60 s"));
        assert!(verdict_of(&judged(&with("allowed", dead.clone())), "allowed").reason.contains("did not answer") && !verdict_of(&judged(&with("allowed", dead)), "allowed").reason.contains("waited"));
        // dig's status, counts and flags reach the reasons and the dns-path note. The stub's empty NOERROR (as
        // measured 2 Oct 2026) passes, and is the run's DNS verdict.
        let m = parse_markers(&transcript(&with("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253"))), NONCE).unwrap();
        let r = m.get("dns-platform6-udp").unwrap();
        assert_eq!((r.status.as_deref(), r.ra, r.answers, r.authority), (Some("NOERROR"), Some(true), Some(0), Some(0)));
        let j = judge(&m);
        assert!(j.passed(), "{:?}", j.failures());
        assert_eq!(verdict_of(&j, "dns-platform6-udp").reason, "fd00:ec2::253 replied with an empty NOERROR (status NOERROR, answer 0, authority 0, recursion available) and no address for example.com (platform DNS: the run's DNS verdict names it, and only [egress].accept_platform_dns accepts it)");
        assert_eq!(j.dns, "platform-dns:fd00:ec2::253");
        // REFUSED (what S5 first accepted) is not the reply that was tested: it fails, and the verdict is answered.
        let platform6 = format!("@@AIENV{NONCE} dns-platform6-udp rc=0 ns=fd00:ec2::253 res=no st=REFUSED ra=no an=0 au=0");
        let j = judged(&with("dns-platform6-udp", platform6));
        assert_eq!(failing(&j), ["dns-platform6-udp"], "{:?}", j.failures());
        assert_eq!(verdict_of(&j, "dns-platform6-udp").reason, "fd00:ec2::253 replied (status REFUSED, answer 0, authority 0, no recursion): not the platform stub's empty reply (NOERROR, answer 0, authority 0), the only one accepted: the resolver is not what was tested (`ai-env lab run dns-path` records what it says)");
        assert_eq!(j.dns, "platform-dns-answered:fd00:ec2::253");
        // A truncated UDP reply whose TCP retry got nothing (dig exit 9, `st=TRUNCATED`): open for a public resolver, unproven for the platform's.
        let j = judged(&with("dns-public-udp", format!("@@AIENV{NONCE} dns-public-udp rc=9 ns=1.1.1.1 res=no st=TRUNCATED ra=none an=none au=none")));
        assert!(verdict_of(&j, "dns-public-udp").verdict == Verdict::Fail && verdict_of(&j, "dns-public-udp").reason.starts_with("OPEN: 1.1.1.1"), "{:?}", verdict_of(&j, "dns-public-udp"));
        assert_eq!(j.dns, "open-dns:1.1.1.1");
        let j = judged(&with("dns-platform6-udp", format!("@@AIENV{NONCE} dns-platform6-udp rc=9 ns=fd00:ec2::253 res=no st=TRUNCATED ra=none an=none au=none")));
        assert!(verdict_of(&j, "dns-platform6-udp").reason.starts_with("not proven closed: fd00:ec2::253 sent a truncated UDP reply") && !j.passed(), "{:?}", j.failures());
        assert_eq!(j.dns, "platform-dns-answered:fd00:ec2::253", "the judge's FAIL and the verdict agree: a reply, not the empty NOERROR");
        // The fresh name answered, but example.com got no reply at all (`st=NOEXAMPLE`): not the stub, which answers
        // both at once.
        let j = judged(&with("dns-platform6-udp", format!("@@AIENV{NONCE} dns-platform6-udp rc=0 ns=fd00:ec2::253 res=no st={DNS_NO_EXAMPLE} ra=yes an=0 au=0")));
        assert_eq!(failing(&j), ["dns-platform6-udp"], "{:?}", j.failures());
        assert!(verdict_of(&j, "dns-platform6-udp").reason.starts_with("fd00:ec2::253 replied (example.com A unanswered, answer 0, authority 0, recursion available): not the platform stub's empty reply"), "{}", verdict_of(&j, "dns-platform6-udp").reason);
        assert_eq!(j.dns, "platform-dns-answered:fd00:ec2::253");
        let servfail = format!("@@AIENV{NONCE} dns-public-udp rc=0 ns=1.1.1.1 res=no st=SERVFAIL ra=yes an=0 au=0");
        assert!(verdict_of(&judged(&with("dns-public-udp", servfail)), "dns-public-udp").reason.contains("replied (status SERVFAIL, answer 0, authority 0, recursion available) (it resolved nothing"));
        let (v, note) = dns_path_outcome(&parse_markers(&transcript(&ready("try=1 s=0 ok=yes").into_iter().map(|(k, l)| if k == "dns-platform6-tcp" { (k, stub("dns-platform6-tcp", "fd00:ec2::253")) } else { (k, l) }).collect::<Vec<_>>()), NONCE).unwrap()).unwrap();
        assert_eq!(v, "platform-dns:fd00:ec2::253");
        assert!(note.contains("fd00:ec2::253 udp no reply, tcp replied (NOERROR, answer 0, authority 0, recursion available)") && note.ends_with("(allowed, allowed-last: HTTP 401), reached 0 s after the script began"), "{note}");
    }

    /// The judge and the dns-path verdict agree on every reply a platform resolver can give: the case passes exactly
    /// for NOERROR with no answer, no authority and no address — the reply the operator tested — and the run's verdict
    /// is that reply's class.
    #[test]
    fn the_judge_and_the_verdict_agree_on_every_platform_reply() {
        let mut passes = 0;
        for st in ["none", "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "NOTIMP", "TRUNCATED", DNS_NO_EXAMPLE] {
            for an in ["none", "0", "1"] {
                for au in ["none", "0", "1"] {
                    for res in ["no", "yes"] {
                        let line = format!("@@AIENV{NONCE} dns-platform6-udp rc=0 ns=fd00:ec2::253 res={res} st={st} ra=yes an={an} au={au}");
                        let j = judged(&with("dns-platform6-udp", line.clone()));
                        let empty = (st, an, au, res) == ("NOERROR", "0", "0", "no");
                        assert_eq!(j.passed(), empty, "{line}: {:?}", j.failures());
                        assert_eq!(failing(&j), if empty { vec![] } else { vec!["dns-platform6-udp"] }, "{line}");
                        let class = match (res, empty) {
                            ("yes", _) => "platform-dns-resolves:",
                            (_, true) => "platform-dns:",
                            _ => "platform-dns-answered:",
                        };
                        assert_eq!(j.dns, format!("{class}fd00:ec2::253"), "{line}");
                        passes += usize::from(empty);
                    }
                }
            }
        }
        assert_eq!(passes, 1);
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
            (dig("dns-platform-udp", "0", "169.254.169.253", false).replace("st=none", "st=refused"), "bad st"),
            (dig("dns-platform-udp", "0", "169.254.169.253", false).replace("st=none", "st=NO_ERROR"), "bad st"),
            (dig("dns-platform-udp", "0", "169.254.169.253", false).replace("ra=none", "ra=maybe"), "yes|no"),
            (dig("dns-platform-udp", "0", "169.254.169.253", false).replace(" st=none", ""), "st field is missing"),
            (dig("dns-resolv-udp", "none", "none", false).replace("st=none", "st=REFUSED"), "no server was asked"),
            (dig("dns-resolv-udp", "none", "none", false).replace("an=none", "an=0"), "no server was asked"),
            (dig("dns-resolv-udp", "none", "none", false).replace("au=none", "au=1"), "no server was asked"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace(" an=0", ""), "an field is missing"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace(" au=0", ""), "au field is missing"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("an=0", "an=x"), "bad an"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("au=0", "au=123456"), "bad au"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("au=0", "au=99999"), "bad au"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("an=0", "an=-1"), "bad an"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("an=0", "an="), "bad an"),
            (stub("dns-platform6-udp", "fd00:ec2::253").replace("an=0", "an=0 an=0"), "an twice"),
            (format!("{} an=0", curl("allowed", 0, "401", "1", "200", false, false)), "unexpected field"),
            (format!("@@AIENV{NONCE} ready try=1 s=0 ok=yes\n@@AIENV{NONCE} ready try=1 s=0 ok=yes"), "ready marker twice"),
            (format!("@@AIENV{NONCE} ready try=1 s=0"), "ok field is missing"),
            (format!("@@AIENV{NONCE} ready try=1 s=0 ok=yes x=1"), "unexpected field"),
            (format!("@@AIENV{NONCE} ready try=1 s=-1 ok=yes"), "bad s"),
            (format!("@@AIENV{NONCE} ready try=1 s=0 ok=sure"), "bad ok"),
            (format!("@@AIENV{NONCE} ready try=1 try=2 s=0 ok=yes"), "try twice"),
            (format!("@@AIENV{NONCE} ready junk"), "not key=value"),
            (format!("@@AIENV{NONCE} urls\n@@AIENV{NONCE} urls"), "urls marker twice"),
            (format!("@@AIENV{NONCE} urls 3"), "urls marker carries"),
        ];
        // The wait's keepalive dots before a marker are harmless.
        assert_eq!(parse_markers(&format!("...@@AIENV{NONCE} ready try=4 s=6 ok=yes"), NONCE).unwrap().ready, Some(Ready { tries: 4, secs: 6, ok: true }));
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

    /// The seven S3 cases (§7.7) are judged on the status and the `<Code>`,
    /// never the wording: `s3-own` stores then reads back through the proxy
    /// (both 200, CONNECT 200); each `S3Denied` case needs the tunnel open
    /// (CONNECT 200) and S3 403 `AccessDenied`; `s3-imds-role` records
    /// `no_role` only when the check VM runs without an execution role.
    #[test]
    fn the_s3_cases_are_judged_on_status_and_code() {
        let j = judged(&passing());
        for n in ["s3-own", "s3-front-bucket", "s3-front-path", "s3-own-outside-prefix", "s3-imds-role", "proxy-s3-other-host", "s3-direct"] {
            assert_eq!(verdict_of(&j, n).verdict, Verdict::Pass, "{n}: {}", verdict_of(&j, n).reason);
        }
        assert!(j.summary().contains(" s3-own=pass ") && j.summary().contains(" s3-imds-role=pass "), "{}", j.summary());
        // s3-own fails if the read is refused: the proxy's S3 traffic is not confined to the endpoint.
        let j = judged(&with("s3-own", s3line("s3-own", "200", "403", "200", "AccessDenied")));
        assert_eq!(failing(&j), ["s3-own"], "{:?}", j.failures());
        assert!(verdict_of(&j, "s3-own").reason.contains("did not return 200"), "{}", verdict_of(&j, "s3-own").reason);
        let open = judged(&with("s3-own", s3line("s3-own", "000", "403", "000", "AccessDenied")));
        assert!(verdict_of(&open, "s3-own").reason.contains("did not open a tunnel"), "{}", verdict_of(&open, "s3-own").reason);
        // A denied case the endpoint SERVED is OPEN; a 403 without AccessDenied is not the endpoint's; a tunnel that
        // never opened cannot show the refusal.
        for (name, line, why) in [
            ("s3-front-bucket", s3line("s3-front-bucket", "000", "200", "200", "-"), "OPEN"),
            ("s3-own-outside-prefix", s3line("s3-own-outside-prefix", "403", "000", "200", "NoSuchKey"), "without <Code> AccessDenied"),
            ("s3-front-path", s3line("s3-front-path", "000", "403", "403", "AccessDenied"), "did not open a tunnel"),
        ] {
            let j = judged(&with(name, line));
            assert_eq!(failing(&j), [name], "{name}");
            assert!(verdict_of(&j, name).reason.contains(why), "{name}: {}", verdict_of(&j, name).reason);
        }
        // s3-imds-role without credentials from IMDS: recorded:no_role only for a VM without an execution role (the
        // next test has every case of it).
        let lines = with("s3-imds-role", s3line("s3-imds-role", "000", "000", "000", "norole"));
        let j = judged_by(&lines, &S3Facts { has_role: false, front: FrontObject::Status(200) });
        assert!(j.passed() && verdict_of(&j, "s3-imds-role").verdict == Verdict::Recorded, "{:?}", j.failures());
        assert!(j.summary().contains(" s3-imds-role=recorded:no_role "), "{}", j.summary());
        assert_eq!(failing(&judged(&lines)), ["s3-imds-role"], "with a role, IMDS must hand its credentials over");
    }

    /// `s3-imds-role` when IMDS gave the VM no credentials (no session token, no role, a role without all three
    /// values): recorded `no_role` only when the check VM runs without an execution role; with one, each fails, naming
    /// what was missing. A PUT that was made is judged like any `S3Denied` PUT, role or not.
    #[test]
    fn the_imds_role_case_records_no_role_only_without_a_role() {
        let none = S3Facts { has_role: false, front: FrontObject::Status(200) };
        for (w, what) in [("noimds", "no session token"), ("norole", "no role"), ("nocreds", "a role without all of AccessKeyId, SecretAccessKey and Token")] {
            let lines = with("s3-imds-role", s3line("s3-imds-role", "000", "000", "000", w));
            let j = judged_by(&lines, &none);
            assert!(j.passed(), "{w}: {:?}", j.failures());
            let v = verdict_of(&j, "s3-imds-role");
            assert!(v.verdict == Verdict::Recorded && v.reason.starts_with("recorded:no_role: the check VM ran without an execution role") && v.reason.ends_with(&format!("(IMDS: {w})")), "{w}: {v:?}");
            assert!(j.summary().contains(" s3-imds-role=recorded:no_role "), "{}", j.summary());
            let j = judged(&lines);
            assert_eq!(failing(&j), ["s3-imds-role"], "{w}");
            assert_eq!(verdict_of(&j, "s3-imds-role").reason, format!("the check VM runs with an execution role, but IMDS gave it {what} ({w}): the role's credentials were never tried against our bucket"));
        }
        assert_eq!(IMDS_GAVE_NOTHING, ["noimds", "norole", "nocreds"]);
        // A PUT signed with what IMDS gave is judged either way: refused passes, served is OPEN.
        for s3 in [&none, &S3Facts::assumed()] {
            assert_eq!(verdict_of(&judged_by(&passing(), s3), "s3-imds-role").verdict, Verdict::Pass);
            let open = judged_by(&with("s3-imds-role", s3line("s3-imds-role", "200", "000", "200", "-")), s3);
            assert_eq!(failing(&open), ["s3-imds-role"]);
            assert!(verdict_of(&open, "s3-imds-role").reason.starts_with("OPEN"), "{}", verdict_of(&open, "s3-imds-role").reason);
            // Any other word is S3's <Code>: judged.
            let other = judged_by(&with("s3-imds-role", s3line("s3-imds-role", "403", "000", "200", "InvalidToken")), s3);
            assert!(failing(&other) == ["s3-imds-role"] && verdict_of(&other, "s3-imds-role").reason.contains("without <Code> AccessDenied"), "{:?}", other.failures());
        }
    }

    /// The fronting cases count only when the Mac read the front object anonymously (§7.7): a 403 AccessDenied through
    /// the tunnel for an object nobody may read proves nothing about the endpoint, so with the object unreadable —
    /// another status, no answer — both fail even with passing markers; readable (200, or 206 for the byte asked),
    /// they pass and say so. No other case depends on it.
    #[test]
    fn the_fronting_cases_count_only_when_the_front_object_is_readable() {
        for front in [FrontObject::Status(403), FrontObject::Status(404), FrontObject::Status(301), FrontObject::Status(500), FrontObject::Unreachable("timed out".into())] {
            let j = judged_by(&passing(), &S3Facts { has_role: true, front: front.clone() });
            assert!(!j.passed() && failing(&j) == ["s3-front-bucket", "s3-front-path"], "{front:?}: {:?}", j.failures());
            for n in ["s3-front-bucket", "s3-front-path"] {
                let r = &verdict_of(&j, n).reason;
                assert!(r.contains(" — not counted: the front object copernicus-dem-30m/tileList.txt ") && r.contains(&front.said()), "{n}: {r}");
            }
            assert!(!front.readable());
        }
        for (front, status) in [(FrontObject::Status(200), 200), (FrontObject::Status(206), 206)] {
            let j = judged_by(&passing(), &S3Facts { has_role: true, front });
            assert!(j.passed(), "{status}: {:?}", j.failures());
            assert!(verdict_of(&j, "s3-front-path").reason.ends_with(&format!("; the object it fronted answered the Mac's anonymous GET with HTTP {status} (readable)")), "{}", verdict_of(&j, "s3-front-path").reason);
        }
        // An OPEN fronting case fails as OPEN, whatever the object.
        let open = judged_by(&with("s3-front-bucket", s3line("s3-front-bucket", "000", "200", "200", "-")), &S3Facts { has_role: true, front: FrontObject::Status(403) });
        assert!(verdict_of(&open, "s3-front-bucket").reason.starts_with("OPEN"), "{}", verdict_of(&open, "s3-front-bucket").reason);
        // The lab's stand-in counts in a debug build only.
        assert_eq!(FrontObject::Lab.readable(), cfg!(debug_assertions));
        assert_eq!(front_object_url(), "https://copernicus-dem-30m.s3.eu-central-1.amazonaws.com/tileList.txt");
        assert_eq!(
            S3Facts { has_role: false, front: FrontObject::Status(206) }.said(),
            "s3: the front object copernicus-dem-30m/tileList.txt answered the Mac's anonymous GET with HTTP 206 (readable); the check VM runs without an execution role"
        );
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
            ("dns-public-tcp", dig("dns-public-tcp", "0", "1.1.1.1", true), "OPEN: 1.1.1.1 returned an address (the run's name, which exists nowhere, or example.com)"),
            ("dns-resolv-udp", dig("dns-resolv-udp", "0", "9.9.9.9", false), "9.9.9.9, not a platform resolver"),
            ("dns-resolv-tcp", dig("dns-resolv-tcp", "0", "127.0.0.53", false), "127.0.0.53, not a platform resolver"),
            ("dns-platform-udp", dig("dns-platform-udp", "0", "169.254.169.253", true), "OPEN: 169.254.169.253 returned an address"),
            ("dns-platform6-tcp", dig("dns-platform6-tcp", "0", "fd00:ec2::253", true), "OPEN: fd00:ec2::253 returned an address"),
            // The stub's reply with an address (the fresh name's or example.com's: a forwarder that strips the SOA).
            ("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253").replace("res=no", "res=yes"), "OPEN: fd00:ec2::253 returned an address"),
            // Anything but the stub's empty NOERROR: an SOA (a recursor's black lie), a record, another status, no header.
            ("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253").replace("au=0", "au=1"), "fd00:ec2::253 replied (status NOERROR, answer 0, authority 1, recursion available): not the platform stub's empty reply"),
            ("dns-platform6-tcp", stub("dns-platform6-tcp", "fd00:ec2::253").replace("an=0", "an=1"), "not the platform stub's empty reply"),
            ("dns-platform-udp", stub("dns-platform-udp", "169.254.169.253").replace("st=NOERROR", "st=NXDOMAIN").replace("au=0", "au=1"), "status NXDOMAIN"),
            ("dns-vpc-tcp", stub("dns-vpc-tcp", "10.42.0.2").replace("st=NOERROR", "st=SERVFAIL"), "not the platform stub's empty reply"),
            ("dns-subnet-udp", stub("dns-subnet-udp", "10.42.1.2").replace("st=NOERROR", "st=REFUSED"), "not the platform stub's empty reply"),
            ("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253").replace("st=NOERROR", "st=none"), "fd00:ec2::253 replied (answer 0, authority 0, recursion available): not the platform stub's empty reply"),
            ("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253").replace("an=0", "an=none").replace("au=0", "au=none"), "replied (status NOERROR, recursion available): not the platform stub's empty reply"),
            ("dns-resolv-udp", stub("dns-resolv-udp", "10.42.0.2").replace("au=0", "au=1"), "not the platform stub's empty reply"),
            ("dns-subnet-tcp", dig("dns-subnet-tcp", "10", "10.42.1.2", false), "dig exited 10"),
            ("proxy-other-port", curl("proxy-other-port", 7, "000", "0", "000", false, false), "reached the proxy host"),
            ("proxy-other-port", curl("proxy-other-port", 28, "000", "1", "000", false, false), "OPEN"),
            ("proxy-other-port", curl("proxy-other-port", 0, "200", "1", "000", false, false), "OPEN"),
            ("proxy-ip-literal", curl("proxy-ip-literal", 0, "200", "1", "200", false, false), "opened a tunnel"),
            // Judged strictly (no allowlist proved, or github.com not on it): said, not prescribed.
            ("proxy-github", curl("proxy-github", 0, "200", "1", "200", false, false), "(github.com was not on the proxy's effective allowlist as this check read it, or that list could not be verified: ai-env egress status)"),
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
        // A platform resolver's empty NOERROR (the stub's reply) passes, and is the run's DNS verdict; the same reply
        // without the status dig prints, or without its counts, fails (fail closed).
        let j = judged(&with("dns-platform-udp", stub("dns-platform-udp", "169.254.169.253")));
        assert!(j.passed(), "{:?}", j.failures());
        assert_eq!(j.dns, "platform-dns:169.254.169.253");
        for broken in [stub("dns-platform-udp", "169.254.169.253").replace("st=NOERROR", "st=none"), dig("dns-platform-udp", "0", "169.254.169.253", false)] {
            let j = judged(&with("dns-platform-udp", broken.clone()));
            assert_eq!(failing(&j), ["dns-platform-udp"], "{broken}");
            assert_eq!(j.dns, "platform-dns-answered:169.254.169.253", "{broken}");
        }
        // So does a private resolv.conf nameserver's; and none at all.
        assert!(judged(&with("dns-resolv-udp", stub("dns-resolv-udp", "10.42.0.2"))).passed());
        assert_eq!(failing(&judged(&with("dns-resolv-udp", stub("dns-resolv-udp", "10.42.0.2").replace("st=NOERROR", "st=none")))), ["dns-resolv-udp"]);
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

    /// While the proxy's effective allowlist holds github.com, `proxy-github` is recorded, not judged — whatever its
    /// marker says — and a missing marker still fails. Nothing else changes: other hosts in the set, or github.com with
    /// another proxy case opened, judge exactly as the strict judge.
    #[test]
    fn an_allowlisted_host_is_recorded_not_judged() {
        let github: BTreeSet<String> = ["github.com".to_string()].into();
        let tunnel = curl("proxy-github", 0, "200", "1", "200", false, false);
        // Strictly, github.com's tunnel is OPEN, with a hint that says why without prescribing a removal.
        let strict = judged(&with("proxy-github", tunnel.clone()));
        assert_eq!(failing(&strict), ["proxy-github"]);
        let reason = &verdict_of(&strict, "proxy-github").reason;
        assert!(reason.ends_with("CONNECT 200 (github.com was not on the proxy's effective allowlist as this check read it, or that list could not be verified: ai-env egress status)") && !reason.contains("--remove"), "{reason}");
        assert!(strict.allowlisted.is_empty() && strict.summary().contains(" proxy-github=fail "), "{}", strict.summary());
        // Allowlisted: recorded, and the run passes.
        let m = parse_markers(&transcript(&with("proxy-github", tunnel)), NONCE).unwrap();
        let j = judge_with(&m, &github, &S3Facts::assumed());
        assert!(j.passed(), "{:?}", j.failures());
        let v = verdict_of(&j, "proxy-github");
        assert_eq!((v.verdict, v.result.as_ref().and_then(|r| r.hc)), (Verdict::Recorded, Some(200)), "the marker is kept");
        assert_eq!(v.reason, "not judged: github.com is allowlisted on the proxy (its effective allowlist, as the network verification read it); curl saw HTTP 200 (rc 0, 0 bytes; 1 connect), CONNECT 200; this check does not show squid refusing it");
        assert_eq!(j.allowlisted, ["github.com"]);
        assert!(j.summary().contains(" proxy-github=recorded:allowlisted ") && j.summary().contains(" imds=recorded:401 "), "{}", j.summary());
        assert_eq!(j.cases.iter().filter(|c| c.verdict == Verdict::Recorded).count(), 3, "imds, imds-v6, proxy-github");
        // A refusal (github.com added after its case ran) is recorded too: the record never claims it refused.
        let j = judge_with(&parse_markers(&transcript(&passing()), NONCE).unwrap(), &github, &S3Facts::assumed());
        let v = verdict_of(&j, "proxy-github");
        assert!(j.passed() && v.verdict == Verdict::Recorded && v.reason.contains("curl saw no HTTP answer (rc 56: receive failure; 1 connect), CONNECT 403;"), "{v:?}");
        // A missing marker still fails, and nothing was recorded for the allowlist.
        let gone: Vec<(String, String)> = passing().into_iter().filter(|(k, _)| k != "proxy-github").collect();
        let j = judge_with(&parse_markers(&transcript(&gone), NONCE).unwrap(), &github, &S3Facts::assumed());
        assert_eq!(failing(&j), ["proxy-github"]);
        assert!(verdict_of(&j, "proxy-github").reason.contains("no result") && j.allowlisted.is_empty() && !j.summary().contains("allowlisted"), "{}", j.summary());
        assert!(judge_with(&Markers::default(), &github, &S3Facts::assumed()).allowlisted.is_empty(), "an unreadable transcript records nothing");
        // An allowlist of other hosts — the API host, the IP literal, the nonce host among them — changes nothing.
        let nonce_host = denied_host(NONCE);
        let others: BTreeSet<String> = ["api.anthropic.com", "1.1.1.1", nonce_host.as_str(), "example.org"].iter().map(|h| (*h).to_string()).collect();
        for lines in [passing(), with("proxy-github", curl("proxy-github", 0, "200", "1", "200", false, false))] {
            let m = parse_markers(&transcript(&lines), NONCE).unwrap();
            assert_eq!(judge_with(&m, &others, &S3Facts::assumed()), judge(&m));
        }
        // With github.com allowlisted (alone, or with every other host), any other case the proxy let through fails
        // exactly as it would strictly.
        let both: BTreeSet<String> = others.union(&github).cloned().collect();
        for (name, line) in [
            ("proxy-ip-literal", curl("proxy-ip-literal", 0, "200", "1", "200", false, false)),
            ("proxy-connect-8443", curl("proxy-connect-8443", 0, "200", "1", "200", false, false)),
            ("proxy-http-8080", curl("proxy-http-8080", 0, "200", "1", "000", false, false)),
            ("denied", curl("denied", 0, "200", "1", "200", false, false)),
        ] {
            let m = parse_markers(&transcript(&with(name, line.clone())), NONCE).unwrap();
            for set in [&github, &both] {
                let j = judge_with(&m, set, &S3Facts::assumed());
                assert_eq!(failing(&j), [name], "{line}");
                assert_eq!(verdict_of(&j, name), verdict_of(&judge(&m), name), "{line}");
                assert!(verdict_of(&j, name).reason.starts_with("OPEN") || name == "proxy-http-8080", "{}", verdict_of(&j, name).reason);
            }
        }
    }

    /// Only github.com's CONNECT on 443 can be allowlisted: the hosts taken from the effective allowlist, the requests
    /// squid must refuse, and the one predicate both rest on (squid's log too).
    #[test]
    fn allowlisted_hosts_and_the_requests_squid_must_refuse() {
        let set = |hosts: &[&str]| -> BTreeSet<String> { hosts.iter().map(|h| (*h).to_string()).collect() };
        assert!(allowlisted_hosts(&BTreeSet::new()).is_empty());
        assert_eq!(allowlisted_hosts(&set(&["github.com", "api.anthropic.com", "x.example"])), set(&["github.com"]));
        assert!(allowlisted_hosts(&set(&["api.anthropic.com", "gist.github.com", "github.com.example"])).is_empty(), "exact names only");
        let all = refused_requests(NONCE, &BTreeSet::new());
        let nonce_host = denied_host(NONCE);
        assert_eq!(
            all,
            [
                ("CONNECT", nonce_host.clone(), 443),
                ("CONNECT", "1.1.1.1".to_string(), 443),
                ("CONNECT", "api.anthropic.com".to_string(), 8443),
                ("CONNECT", "github.com".to_string(), 443),
                ("CONNECT", "s3.eu-central-1.amazonaws.com".to_string(), 443),
                ("GET", "api.anthropic.com".to_string(), 8080)
            ]
        );
        assert_eq!(refused_requests(NONCE, &set(&["api.anthropic.com", "1.1.1.1", nonce_host.as_str(), "s3.eu-central-1.amazonaws.com"])), all, "never the API host's other ports, the IP literal, the nonce host or the other S3 host");
        let without: Vec<(&str, String, u16)> = all.iter().filter(|(_, h, _)| h != "github.com").cloned().collect();
        assert_eq!(refused_requests(NONCE, &set(&["github.com"])), without);
        assert_eq!(refused_requests(NONCE, &set(&["github.com", "api.anthropic.com", "1.1.1.1", nonce_host.as_str()])), without);
        // The predicate: CONNECT, port 443, an allowlistable host, held by the set — each of the four needed.
        let github = set(&["github.com"]);
        assert!(allowlisted_request("CONNECT", "github.com", Some(443), &github));
        for (method, host, port, s) in [
            ("GET", "github.com", Some(443), &github),
            ("CONNECT", "github.com", Some(8443), &github),
            ("CONNECT", "github.com", None, &github),
            ("CONNECT", "github.com", Some(443), &BTreeSet::new()),
            ("CONNECT", "1.1.1.1", Some(443), &set(&["1.1.1.1"])),
            ("CONNECT", nonce_host.as_str(), Some(443), &set(&[nonce_host.as_str()])),
            ("CONNECT", "api.anthropic.com", Some(443), &set(&["api.anthropic.com"])),
        ] {
            assert!(!allowlisted_request(method, host, port, s), "{method} {host}:{port:?}");
        }
        assert_eq!((allowlisted_case("proxy-github", &github), allowlisted_case("proxy-github", &BTreeSet::new()), allowlisted_case("denied", &github)), (Some("github.com"), None, None));
        // Every allowlistable case asks the proxy for its host with CONNECT on 443, as the request list does.
        for (name, host) in ALLOWLISTABLE {
            let c = case(name).unwrap();
            assert!(c.kind == Kind::Connect403 && c.args == format!("https://{host}/"), "{name}");
            assert!(all.contains(&("CONNECT", host.to_string(), 443)), "{name}");
        }
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
        let (v, _) = dns_path_outcome(&only(with("dns-subnet-udp", stub("dns-subnet-udp", "10.42.1.2")))).unwrap();
        assert_eq!(v, "platform-dns:10.42.1.2", "the platform's empty reply");
        let (v, note) = dns_path_outcome(&only(with("dns-subnet-udp", stub("dns-subnet-udp", "10.42.1.2").replace("st=NOERROR", "st=NXDOMAIN").replace("au=0", "au=1")))).unwrap();
        assert_eq!(v, "platform-dns-answered:10.42.1.2", "a recursor's negative answer: {note}");
        assert!(note.contains("10.42.1.2 udp replied (NXDOMAIN, answer 0, authority 1, recursion available), tcp no reply"), "{note}");
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
            l("TCP_DENIED/403", "CONNECT", "s3.eu-central-1.amazonaws.com:443"),
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
        let ev = |msgs: &[String]| squid_evidence(&lines_of(msgs), NONCE, t - 60, t + 60, 2, &BTreeSet::new());
        let SquidEvidence::Complete(found) = ev(&squid_run("10.42.1.17", t)) else { panic!("{:?}", ev(&squid_run("10.42.1.17", t))) };
        assert!(found.starts_with("from 10.42.1.17: 2 tunnels to api.anthropic.com:443") && found.contains("GET api.anthropic.com:8080"), "{found}");
        assert!(squid_lines(&serde_json::json!({})).is_err());
        assert_eq!(lines_of(&["some other line".to_string()]).len(), 0, "other lines are skipped");
        // Each required line missing: named, not complete (the poll keeps asking).
        for (i, want) in [(0usize, "2 × TCP_TUNNEL/200"), (1, "CONNECT 1.1.1.1:443"), (2, "GET api.anthropic.com:8080"), (3, "api.anthropic.com:8443"), (4, "github.com:443"), (5, "CONNECT s3.eu-central-1.amazonaws.com:443")] {
            let mut msgs = squid_run("10.42.1.17", t);
            msgs.remove(i);
            match ev(&msgs) {
                SquidEvidence::Missing(m) => assert!(m.iter().any(|x| x.contains(want)), "{want}: {m:?}"),
                other => panic!("{want}: {other:?}"),
            }
        }
        // The run's nonce line missing, outside the window, or another client's lines only: missing.
        let mut no_nonce = squid_run("10.42.1.17", t);
        no_nonce.remove(6);
        assert!(matches!(ev(&no_nonce), SquidEvidence::Missing(m) if m[0].contains(&denied_host(NONCE))));
        assert!(matches!(ev(&squid_run("10.42.1.17", t + 3600)), SquidEvidence::Missing(_)), "outside the window");
        let mut other_client = squid_run("10.42.1.17", t);
        for l in &mut other_client[..6] {
            *l = l.replace("10.42.1.17", "10.42.1.18");
        }
        assert!(matches!(ev(&other_client), SquidEvidence::Missing(_)), "the evidence must come from the run's client");
        // Violations: the nonce host tunnelled or let through, a request from outside the VM subnet, a tunnel to a refused host.
        let mut tunnelled = squid_run("10.42.1.17", t);
        tunnelled.push(format!("aienv {t}.500 9 10.42.1.17 TCP_TUNNEL/200 5000 CONNECT {}:443", denied_host(NONCE)));
        assert!(matches!(ev(&tunnelled), SquidEvidence::Violation(v) if v.contains("let the run's denied host through")));
        assert!(matches!(ev(&squid_run("10.42.0.99", t)), SquidEvidence::Violation(v) if v.contains("outside the VM subnet")));
        for host in ["github.com:443", "github.com:8443", "1.1.1.1:443", "api.anthropic.com:8443", "api.anthropic.com:8080", "s3.eu-central-1.amazonaws.com:443"] {
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
        // Every CONNECT case the proxy must refuse, and the plain-http one, is a required squid line (proxy-s3-other-host,
        // S9, too: squid's own log is the evidence from outside the VM).
        let refused = refused_requests(NONCE, &BTreeSet::new());
        for c in CASES.iter().filter(|c| matches!(c.kind, Kind::Connect403 | Kind::Get403)) {
            let url = c.args.replace("@H@", &denied_host(NONCE)).replace("@S3H@", S3_REGIONAL_HOST);
            let (scheme, rest) = url.split_once("://").unwrap();
            let hostport = rest.trim_end_matches('/');
            let (h, p) = hostport.rsplit_once(':').map_or((hostport, if scheme == "https" { 443 } else { 80 }), |(h, p)| (h, p.parse::<u16>().unwrap()));
            let method = if scheme == "https" { "CONNECT" } else { "GET" };
            assert!(refused.iter().any(|(m, rh, rp)| *m == method && rh == h && *rp == p), "{}: {method} {h}:{p}", c.name);
        }
    }

    /// Every VM shares the connector's address (measured live on 2 Oct 2026). Removing a host restarts squid, which ends
    /// and logs every tunnel, so a tunnel to github.com that squid logged before this run refused it is an earlier run's,
    /// opened while an operator allowed it: `make test-egress` failed its next test on exactly that
    /// (live_egress_extra_and_removal's tunnel). One logged at or after the refusal (open while the run was refused) is
    /// a violation, and so is any tunnel squid must never open (an IP literal, a refused port), whenever it was logged.
    /// The refusal that decides is the run's own, within one case's budget before its nonce line; while it is not in the
    /// log, the evidence is missing.
    #[test]
    fn squid_evidence_attributes_the_shared_address_by_squids_clock() {
        let t = 1_790_000_000;
        let c = "10.42.1.158";
        let ev = |msgs: &[String]| squid_evidence(&lines_of(msgs), NONCE, t - 60, t + 60, 2, &BTreeSet::new());
        let at = |secs: u64, ms: u64, dur: u64, code: &str, dest: &str| format!("aienv {secs}.{ms:03} {dur} {c} {code} 4000 CONNECT {dest}");
        let with = |extra: &[String]| squid_run(c, t).into_iter().chain(extra.iter().cloned()).collect::<Vec<_>>();
        // live_egress_extra_and_removal 35 s earlier: refused, allowed (a tunnel of 0.9 s), refused again.
        let earlier = [at(t - 40, 0, 1, "TCP_DENIED/403", "github.com:443"), at(t - 35, 400, 900, "TCP_TUNNEL/200", "github.com:443"), at(t - 34, 0, 1, "TCP_DENIED/403", "github.com:443")];
        match ev(&with(&earlier)) {
            SquidEvidence::Complete(found) => assert!(found.ends_with("no tunnel to a refused host (tunnels to github.com logged before this run refused it: an earlier run's, not counted)"), "{found}"),
            other => panic!("{other:?}"),
        }
        // Logged at or after this run's refusal (t.123): open while the run was refused, or opened after: this run's.
        for (secs, ms, dur) in [(t, 123, 0), (t, 900, 9), (t, 500, 70_000), (t + 30, 0, 1000)] {
            assert!(matches!(ev(&with(&[at(secs, ms, dur, "TCP_TUNNEL/200", "github.com:443")])), SquidEvidence::Violation(v) if v.contains("github.com")), "{secs}.{ms} {dur}");
        }
        // A refusal logged after the run's nonce line is a later run's: it never places a tunnel logged after the run's.
        let later = with(&[at(t + 5, 0, 900, "TCP_TUNNEL/200", "github.com:443"), at(t + 10, 0, 1, "TCP_DENIED/403", "github.com:443")]);
        assert!(matches!(ev(&later), SquidEvidence::Violation(v) if v.contains("github.com")), "{:?}", ev(&later));
        // Without the run's own refusal in the log (an earlier run's, more than a case's budget before the nonce line,
        // is not it), a tunnel to github.com cannot be placed: missing, so the poll goes on and its budget fails closed.
        let without_own = |extra: &[String]| with(extra).into_iter().filter(|l| !(l.contains(&format!("{t}.123")) && l.contains("github.com"))).collect::<Vec<_>>();
        for msgs in [without_own(&earlier), without_own(&[at(t - 35, 400, 900, "TCP_TUNNEL/200", "github.com:443")])] {
            assert!(matches!(ev(&msgs), SquidEvidence::Missing(m) if m.iter().any(|x| x.contains("github.com:443 from 10.42.1.158 within 12 s before the run's nonce line"))), "{:?}", ev(&msgs));
        }
        // Two refusals in the run's slot (another run's too): a tunnel logged between them was open while squid refused it.
        let slot = without_own(&[at(t - 10, 0, 1, "TCP_DENIED/403", "github.com:443"), at(t - 5, 0, 900, "TCP_TUNNEL/200", "github.com:443"), at(t - 1, 0, 1, "TCP_DENIED/403", "github.com:443")]);
        assert!(matches!(ev(&slot), SquidEvidence::Violation(v) if v.contains("github.com")), "{:?}", ev(&slot));
        // Only a refusal like the run's own (CONNECT github.com:443, 403, from the run's client) places a tunnel: a
        // plain-http one, one on another port, with another status or from another client, in the run's slot, does not.
        for other in [format!("{c} TCP_DENIED/403 4000 GET github.com:443"), format!("{c} TCP_DENIED/403 4000 CONNECT github.com:8443"), format!("{c} TCP_DENIED/407 4000 CONNECT github.com:443"), "10.42.1.30 TCP_DENIED/403 4000 CONNECT github.com:443".to_string()] {
            let msgs = without_own(&[at(t - 10, 0, 1, "TCP_DENIED/403", "github.com:443"), at(t - 4, 100, 900, "TCP_TUNNEL/200", "github.com:443"), format!("aienv {}.000 1 {other}", t - 3)]);
            assert!(matches!(ev(&msgs), SquidEvidence::Violation(v) if v.contains("github.com:443")), "{other}: {:?}", ev(&msgs));
        }
        // Tunnels squid must never open count whenever they were logged, as does github.com on another port and a
        // tunnel tag with a suffix — and the other S3 host, which is never allowlisted (an AWS service host, S7 D2), even
        // logged before the run refused it.
        for dest in ["1.1.1.1:443", "api.anthropic.com:8443", "github.com:8443", "s3.eu-central-1.amazonaws.com:443"] {
            assert!(matches!(ev(&with(&[at(t - 50, 0, 900, "TCP_TUNNEL/200", dest)])), SquidEvidence::Violation(v) if v.contains(dest)), "{dest}");
        }
        assert!(matches!(ev(&with(&[at(t - 50, 0, 900, "TCP_TUNNEL_ABORTED/200", "1.1.1.1:443")])), SquidEvidence::Violation(_)));
        // A tunnel whose squid time does not parse counts (fail closed); without the nonce line's time nothing places one.
        assert!(matches!(ev(&with(&[format!("aienv {t}.9x9 9 {c} TCP_TUNNEL/200 4000 CONNECT github.com:443")])), SquidEvidence::Violation(v) if v.contains("github.com")));
        let garbled_nonce: Vec<String> = with(&earlier).into_iter().map(|l| if l.contains(&denied_host(NONCE)) { l.replace(&format!("{t}.123"), &format!("{t}.1x3")) } else { l }).collect();
        assert!(matches!(ev(&garbled_nonce), SquidEvidence::Missing(_)), "{:?}", ev(&garbled_nonce));
        // squid writes milliseconds; a missing or short fraction still reads as milliseconds.
        assert_eq!(squid_ms(&lines_of(&[at(t, 7, 0, "TCP_DENIED/403", "github.com:443")])[0]), Some(t * 1000 + 7));
        assert_eq!(squid_ms(&lines_of(&[format!("aienv {t} 0 {c} TCP_DENIED/403 4000 CONNECT github.com:443")])[0]), Some(t * 1000));
        assert_eq!(squid_ms(&lines_of(&[format!("aienv {t}.5 0 {c} TCP_DENIED/403 4000 CONNECT github.com:443")])[0]), Some(t * 1000 + 500));
    }

    /// With github.com allowlisted, squid's log need not show it refused, and a tunnel to it on 443 — whenever logged,
    /// whoever's — is no violation; everything else holds: a tunnel to the IP literal, to the API host's or github.com's
    /// other port, and every other denial missing. An allowlist of other hosts changes nothing.
    #[test]
    fn squid_evidence_with_github_allowlisted() {
        let t = 1_790_000_000;
        let c = "10.42.1.17";
        let github: BTreeSet<String> = ["github.com".to_string()].into();
        let none = BTreeSet::new();
        let ev = |msgs: &[String], set: &BTreeSet<String>| squid_evidence(&lines_of(msgs), NONCE, t - 60, t + 60, 2, set);
        let tunnel = |secs: u64, dest: &str| format!("aienv {secs}.900 900 {c} TCP_TUNNEL/200 5000 CONNECT {dest}");
        let plus = |base: &[String], extra: &[String]| base.iter().chain(extra).cloned().collect::<Vec<String>>();
        let no_denial: Vec<String> = squid_run(c, t).into_iter().filter(|l| !l.contains("github.com")).collect();
        match ev(&no_denial, &github) {
            SquidEvidence::Complete(found) => assert!(found.ends_with("; no tunnel to a refused host; allowlisted, not required refused: github.com") && !found.contains("CONNECT github.com:443"), "{found}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(ev(&no_denial, &none), SquidEvidence::Missing(m) if m == ["TCP_DENIED/403 CONNECT github.com:443 from 10.42.1.17"]), "strictly, the denial is required");
        // github.com tunnels on 443 — the run's own after its case, an earlier one, a later one — with or without the
        // run's denial in the log (github.com added after its case ran): complete, never a violation.
        for extra in [vec![tunnel(t, "github.com:443")], vec![tunnel(t - 50, "github.com:443"), tunnel(t + 30, "github.com:443")]] {
            for base in [&no_denial, &squid_run(c, t)] {
                let msgs = plus(base, &extra);
                assert!(matches!(ev(&msgs, &github), SquidEvidence::Complete(ref f) if f.ends_with("allowlisted, not required refused: github.com")), "{extra:?}: {:?}", ev(&msgs, &github));
            }
            // Strictly, a tunnel logged after the run's refusal is a violation, and one without it cannot be placed.
            assert!(matches!(ev(&plus(&squid_run(c, t), &extra), &none), SquidEvidence::Violation(v) if v.contains("github.com:443")), "{extra:?}");
            assert!(matches!(ev(&plus(&no_denial, &extra), &none), SquidEvidence::Missing(_)), "{extra:?}");
        }
        // Every other tunnel is still a violation: the IP literal, the API host's other port, github.com on another port.
        for dest in ["1.1.1.1:443", "api.anthropic.com:8443", "github.com:8443", "github.com:80", "s3.eu-central-1.amazonaws.com:443"] {
            assert!(matches!(ev(&plus(&no_denial, &[tunnel(t, dest)]), &github), SquidEvidence::Violation(v) if v.contains(dest)), "{dest}");
        }
        // Every other denial is still required.
        let nonce_denial = format!("CONNECT {}:443", denied_host(NONCE));
        for gone in ["CONNECT api.anthropic.com:8443", "CONNECT 1.1.1.1:443", "GET api.anthropic.com:8080", "CONNECT s3.eu-central-1.amazonaws.com:443", nonce_denial.as_str()] {
            let msgs: Vec<String> = no_denial.iter().filter(|l| !l.ends_with(gone)).cloned().collect();
            assert!(matches!(ev(&msgs, &github), SquidEvidence::Missing(m) if m.iter().any(|x| x.contains(gone))), "{gone}: {:?}", ev(&msgs, &github));
        }
        // An allowlist of other hosts changes nothing.
        let nonce_host = denied_host(NONCE);
        let others: BTreeSet<String> = ["api.anthropic.com", "1.1.1.1", nonce_host.as_str()].iter().map(|h| (*h).to_string()).collect();
        for msgs in [squid_run(c, t), no_denial.clone(), plus(&squid_run(c, t), &[tunnel(t, "1.1.1.1:443")]), plus(&squid_run(c, t), &[tunnel(t, "github.com:443")])] {
            assert_eq!(ev(&msgs, &others), ev(&msgs, &none));
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
            dns_name: dns_name(NONCE),
        }
    }

    fn facts() -> ConnectorFacts {
        ConnectorFacts { id: "nc-0a1b2c3d4e5f60718".into(), version: "1".into(), network_protocol: "IPv4".into(), subnet_ids: vec!["subnet-0aaa1111bbbb2222c".into()], security_group_ids: vec!["sg-0ddd3333eeee4444f".into()] }
    }

    const CONN: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

    /// The transcripts bucket is resolved before the check asks for its VM: a state/infra.toml that records none (before
    /// the S9 deploy and `make infra-status WRITE=1`) stops the check with a configuration error before RunMicrovm, so
    /// the failure revokes nothing (`early_failure` revokes only once the check asked for its VM).
    #[tokio::test]
    async fn the_bucket_is_resolved_before_the_check_asks_for_its_vm() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Ctx {
            paths: Paths::from_root_and_env(dir.path().to_path_buf(), None),
            cfg: BridgeConfig::parse(&format!("[aws]\nimage_arn = \"{}\"\negress_connector_arn = \"{CONN}\"\n", crate::bridge::api::FAKE_IMAGE_ARN)).unwrap(),
            knobs: crate::bridge::lab::VmKnobs::default(),
        };
        let api = crate::bridge::api::FakeMicrovmApi::new();
        let mut guard = Guard::default();
        let target = Target::Start(Box::new(check_plan(&ctx).unwrap()));
        let e = gather(&ctx, &api, &api, &target, false, CONN, &mut guard).await.expect_err("no transcripts bucket recorded");
        assert!(e.to_string().contains("make infra-status WRITE=1") && e.exit_code() == 1, "{e}");
        assert!(!guard.asked && guard.ours.is_empty() && guard.ran.is_none(), "the check never asked for its VM");
        assert!(api.calls().iter().all(|c| !matches!(c, crate::bridge::api::Call::Run { .. })), "{:?}", api.calls());
    }

    #[test]
    fn decide_records_a_full_pass_of_its_own_vm_only() {
        let ev = evidence(&passing());
        let d = decide(&ev, &format!("{CONN}:3"), "2026-10-01T10:00:00Z");
        assert!(d.passed && !d.revoke && d.failures.is_empty(), "{:?}", d.failures);
        let rec = d.record.unwrap();
        assert_eq!((rec.image_arn.as_str(), rec.image_version.as_str(), rec.connector.as_str(), rec.vm_id.as_str()), (crate::bridge::api::FAKE_IMAGE_ARN, "1.0", CONN, ev.id.as_str()));
        assert_eq!((rec.dns.as_str(), rec.network.as_str(), rec.squid_log.as_str(), rec.at.as_str()), ("no-dns", "21 checks ok: connector, vm-route-table", "from 10.42.1.17: 2 tunnels", "2026-10-01T10:00:00Z"));
        assert!(rec.cases.contains("denied=pass"));
        assert_eq!((rec.dns_rule, rec.egress_rule), (DNS_RULE, EGRESS_RULE), "judged by the current DNS and egress rules (§13 P0-4: the S3 cases ran)");
        // The stub's empty reply is recorded as the run's verdict (the gate decides with the pin).
        let platform = decide(&evidence(&with("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253"))), CONN, "t");
        assert!(platform.passed, "{:?}", platform.failures);
        assert_eq!(platform.record.map(|r| (r.dns, r.dns_rule)), Some(("platform-dns:fd00:ec2::253".to_string(), DNS_RULE)));
        assert_eq!((rec.connector_facts.clone(), rec.image_created_at), (facts(), Some(1_789_804_800)), "bound to the connector's live facts and the image build");
        // --vm needs no binding (it records nothing).
        let d = decide(&Evidence { own: false, connector_facts: None, image_created_at: None, ..ev.clone() }, CONN, "t");
        assert!(d.passed && d.record.is_none());
        // --vm: the same evidence, report only.
        let d = decide(&Evidence { own: false, ..ev.clone() }, CONN, "t");
        assert!(d.passed && d.record.is_none() && !d.revoke);
        // An allowlisted host's case was recorded, not judged: the record says so, in `allowlisted` and in its cases.
        let opened = parse_markers(&transcript(&with("proxy-github", curl("proxy-github", 0, "200", "1", "200", false, false))), NONCE).unwrap();
        let allowlisted = decide(&Evidence { judgement: judge_with(&opened, &["github.com".to_string()].into(), &S3Facts::assumed()), ..ev.clone() }, CONN, "t").record.unwrap();
        assert_eq!(allowlisted.allowlisted, ["github.com"]);
        assert!(allowlisted.cases.contains(" proxy-github=recorded:allowlisted "), "{}", allowlisted.cases);
        assert!(rec.allowlisted.is_empty() && rec.cases.contains(" proxy-github=pass "), "nothing allowlisted, nothing said: {rec:?}");
    }

    #[test]
    fn decide_never_records_and_revokes_on_any_failure() {
        let base = evidence(&passing());
        let failing_cases = evidence(&with("direct-ipv4", curl("direct-ipv4", 0, "200", "1", "000", false, false)));
        let cases_ok_squid = |squid| Evidence { squid, ..base.clone() };
        let answered = evidence(&with("dns-platform6-udp", stub("dns-platform6-udp", "fd00:ec2::253").replace("au=0", "au=1")));
        assert_eq!(answered.judgement.dns, "platform-dns-answered:fd00:ec2::253");
        let variants: Vec<(Evidence, &str)> = vec![
            (failing_cases, "direct-ipv4: OPEN"),
            (answered, "dns-platform6-udp: fd00:ec2::253 replied (status NOERROR, answer 0, authority 1, recursion available): not the platform stub's empty reply"),
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
