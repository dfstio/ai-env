//! The relay instance as ai-env-ops (S13, WM-R47 to WM-R49): `ai-env relay status|start|stop`.
//!
//! `status` shows this Mac's side first, with no AWS call and no Touch ID (the sealed keys' notes, the agent's
//! `status` answer within a second); `--local` stops there. Then, as the operator (the `ai-env as` key, else
//! `credentials/ops.env` and its one Touch ID): the instance (state, addresses), SSM's ping and a plain TCP
//! connect to `<public ip>:443` when it runs (informational, LD-WM15: no TLS dial, and no byte sent, so no fault,
//! R-102), the newest `ev:"status"` line of the relay's request log in CloudWatch (B-12), what the relay refused in
//! the last hour and a root volume near full (§RS.3.2 row 4, never the exit code), the three lists in one
//! `get-parameters`, and the peers list and the access list in one each of their own (until a deploy the ops policy
//! cannot read them, and IAM refuses a whole call for one such name).
//! Findings are `[NO ]` and exit 1: this Mac's session key is not an in-force token signer under
//! `[relay].worker_id`, a list does not parse, the instance is not running, the peers list is absent or holds no
//! entry in force, a worker in force has no client certificate under a relay that requires one, this Mac's token signer
//! holds grants that leave out `[relay].grant`; with `[relay].restricted` naming a grant (R-157), a token signer other than
//! `<worker_id>-sole` that reaches one, this Mac's sole key not an in-force token signer as `<worker_id>-sole`, or that
//! signer's grants leaving out `[relay].grant`, a `sole_vm` workspace's own grant or a restricted id; an absent access list is
//! no finding, since no chat is then more than its token's grant (R-146). A read that failed
//! is `[?? ]` and exit 7 when nothing was found first. `start` and `stop` wait as `proxy start|stop` do, their polls
//! scaled by the lab knob; a relay that stops answers VM relay tools `unavailable`, and workers keep dialing until it
//! starts again.
use super::cli::{audit, note, runtime, say, shell_word, RelayCtx};
use super::keys::{read_notes, MacKeyNotes};
use super::params::{access_day, fp16, restricted_in, restricted_mark, restricted_reached, write_access_cache, MAC_LABEL, RESTRICTED_DAYS_MAX, WIDE_BELOW};
use crate::bridge::audit::event::{RELAY_START, RELAY_STOP};
use crate::bridge::awscli::aws_json;
use crate::bridge::config::{BridgeConfig, Paths, RelayCfg};
use crate::bridge::egress::ops::{self, arr, text, Wait};
use crate::bridge::egress::RELAY_LOG_GROUP;
use crate::errors::{CliError, Result};
use crate::wire::time::{rfc3339_utc, unix_now, unix_now_ms};
use ai_env_worker::agent::{request, AgentStatus, Request, Response};
use ai_env_worker::globs::{glob_match, valid_id};
use ai_env_worker::keys::PublicKey;
use ai_env_worker::policy::{self, ACCESS, GRANTS, PEERS, TOKEN_SIGNERS, WORKERS};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// `start`'s waits (WM-R48): `running` within 180 s, then SSM `Online` within 120 s, 5 s steps.
const START_RUNNING: Wait = Wait { step: Duration::from_secs(5), tries: 36 };
const START_ONLINE: Wait = Wait { step: Duration::from_secs(5), tries: 24 };
/// `stop`'s wait (WM-R49): `stopped` within 300 s.
const STOP_STOPPED: Wait = Wait { step: Duration::from_secs(5), tries: 60 };
/// The TCP probe of the public face (LD-WM15).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a connected probe waits, sending nothing, for the relay to close it (§RS.3.2 row 2).
const PROBE_CLOSE_WAIT: Duration = Duration::from_secs(1);
/// How far back the status line is looked for (B-12; the relay writes one every 300 s).
const STATUS_WINDOW_MS: u64 = 600_000;
/// How far back the refusals are counted (§RS.3.2 row 4).
const REFUSED_WINDOW_MS: u64 = 3_600_000;
/// What is counted: every peer line, and the refused tunnel lines (R-66 bounds them to 14 400 lines an hour).
const REFUSED_FILTER: &str = r#"{ ($.ev = "peer") || ($.ev = "tunnel" && $.outcome = "refused") }"#;
/// How far back the reload's `why=disk` is looked for (§RS.3.2 row 4; it runs every minute).
const DISK_WINDOW_MS: u64 = 600_000;
/// The word of the reload's run line (R-95).
const DISK_WORD: &str = "why=disk";
/// The public face's allowlist refusals: the internet's noise, counted apart (R-66, §RS.3.2 row 4).
const UNLISTED_REASONS: [&str; 2] = ["no_peers", "not_in_peers"];
/// A failed TLS handshake on the public face, the one line a worker refused at TLS writes (R-124, §RS.3.2 row 4).
const TLS_FAILED_REASON: &str = "tls_failed";
/// How many of them in the hour warn (§RS.3.2 row 4): such a worker writes about one a minute and, alone on its address,
/// never reaches a ban (R-101), while each `relay status` probe writes one with no fault (R-102).
const TLS_FAILED_WARN: u64 = 10;
/// What the agent has to answer `status` in (WM-R47).
const AGENT_WAIT: Duration = Duration::from_secs(1);

/// What a row says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    Ok,
    /// A finding: exit 1.
    No,
    /// A read that failed: exit 7 unless a finding came first.
    Unknown,
    /// Informational only, never the exit code.
    Warn,
    Note,
}

impl Mark {
    fn bracket(self) -> &'static str {
        match self {
            Mark::Ok => "[ok ]",
            Mark::No => "[NO ]",
            Mark::Unknown => "[?? ]",
            Mark::Warn => "[warn]",
            Mark::Note => "[-  ]",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Mark::Ok => "ok",
            Mark::No => "no",
            Mark::Unknown => "unknown",
            Mark::Warn => "warn",
            Mark::Note => "note",
        }
    }
}

/// The rows of one `status` run, and its JSON (WM-R47, §RS.3.2, R-146): always the eight keys `instance`, `workers`,
/// `token_signers`, `grants`, `peers`, `access`, `status` and `mac`, `null` for what was not read (`--local`, a failed
/// read, a list that does not parse). `status` is the verdict and the rows; the relay's newest status line (B-12) rides in
/// `instance.status_line`, the refused hour in `instance.refused`, the disk in `instance.disk_full`.
#[derive(Default)]
struct Report {
    rows: Vec<(Mark, String)>,
    doc: serde_json::Map<String, Value>,
}

/// The keys of `--json`'s object.
const JSON_KEYS: [&str; 8] = ["instance", "workers", "token_signers", "grants", "peers", "access", "status", "mac"];

impl Report {
    fn row(&mut self, mark: Mark, line: impl Into<String>) {
        self.rows.push((mark, line.into()));
    }

    fn has(&self, mark: Mark) -> bool {
        self.rows.iter().any(|(m, _)| *m == mark)
    }

    /// `findings` with a finding, else `unknown` with a failed read, else `ok`.
    fn verdict(&self) -> &'static str {
        if self.has(Mark::No) {
            "findings"
        } else if self.has(Mark::Unknown) {
            "unknown"
        } else {
            "ok"
        }
    }

    /// The rows, one per line.
    fn print_rows(&self) {
        for (mark, line) in &self.rows {
            say(&format!("{} {line}", mark.bracket()));
        }
    }

    /// The rows (or the JSON), then the exit: 1 for a finding, else 7 for a failed read, else 0.
    fn finish(mut self, json: bool) -> Result<()> {
        let verdict = self.verdict();
        if json {
            self.doc.insert("status".into(), json!({"verdict": verdict, "rows": self.rows.iter().map(|(m, l)| json!({"mark": m.word(), "text": l})).collect::<Vec<_>>()}));
            for key in JSON_KEYS {
                self.doc.entry(key).or_insert(Value::Null);
            }
            say(&serde_json::to_string_pretty(&Value::Object(std::mem::take(&mut self.doc))).unwrap_or_default());
        } else {
            self.print_rows();
        }
        match verdict {
            "findings" => Err(CliError::Msg("relay status: see the [NO ] rows".into())),
            "unknown" => Err(CliError::Aws("relay status: some reads failed (the [?? ] rows)".into())),
            _ => Ok(()),
        }
    }
}

/// This Mac's rows (no AWS call, no Touch ID): the sealed keys' notes and the agent's answer.
fn mac_rows(paths: &Paths, report: &mut Report) -> Option<MacKeyNotes> {
    let notes = match read_notes(paths) {
        Ok(n) => {
            let day = n.sealed_day().unwrap_or_else(|| "on an unrecorded day".into());
            let sole = n.sole_key.as_ref().map_or_else(String::new, |k| format!(", sole key fp {}", k.fingerprint()));
            report.row(Mark::Ok, format!("keys: sealed in credentials/relay-worker.env for worker {}, worker key fp {}, session key fp {}{sole}, sealed {day}", n.worker_id, n.worker_key.fingerprint(), n.session_key.fingerprint()));
            Some(n)
        }
        Err(e) if !paths.relay_worker_env().exists() => {
            report.row(Mark::Note, format!("keys: none sealed on this Mac ({e})"));
            None
        }
        Err(e) => {
            report.row(Mark::No, format!("keys: {e}"));
            None
        }
    };
    let agent = agent_status(paths);
    match &agent {
        Some(s) => report.row(Mark::Ok, format!("agent: running (pid {}, worker {}, until {}, {} signed, {} minted)", s.pid, s.worker_id, rfc3339_utc(s.until), s.signed, s.minted)),
        None => report.row(Mark::Note, "agent: not running (ai-env relay agent: one Touch ID, then it signs and mints until --hours)".to_string()),
    }
    report.doc.insert(
        "mac".into(),
        json!({
            "worker_id": notes.as_ref().map(|n| n.worker_id.clone()),
            "worker_fp": notes.as_ref().map(|n| n.worker_key.fingerprint()),
            "session_fp": notes.as_ref().map(|n| n.session_key.fingerprint()),
            "sole_fp": notes.as_ref().and_then(|n| n.sole_key.as_ref()).map(PublicKey::fingerprint),
            "sealed": notes.as_ref().and_then(MacKeyNotes::sealed_day),
            "agent": agent.as_ref().map(|s| json!({"pid": s.pid, "until": s.until, "signed": s.signed, "minted": s.minted})),
        }),
    );
    notes
}

/// The agent's `status` answer within [`AGENT_WAIT`], if one answers on this Mac's socket (no Touch ID: the panel's
/// pages read it too, R-151).
pub(crate) fn agent_status(paths: &Paths) -> Option<AgentStatus> {
    let socket = paths.relay_agent_socket();
    if !socket.exists() {
        return None;
    }
    match runtime().ok()?.block_on(request(&socket, &Request::Status, AGENT_WAIT)) {
        Ok(Response::Status(s)) => Some(s),
        _ => None,
    }
}

/// `ai-env relay status [--json] [--local]` (WM-R47).
pub fn cmd_status(json: bool, local: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?.unwrap_or_default();
    let mut report = Report::default();
    let notes = mac_rows(&paths, &mut report);
    if local {
        return report.finish(json);
    }
    // This Mac's rows stand whatever stops the rest (no stack record, no operator): they are shown before the
    // error says why. `--json` prints no partial object; its exit and stderr say why, and `--local` shows them.
    let remote = RelayCtx::load().and_then(|ctx| {
        let instance = ctx.instance()?;
        ctx.operator("relay status")?;
        Ok((ctx, instance))
    });
    let (ctx, instance) = match remote {
        Ok(found) => found,
        Err(e) => {
            if !json {
                report.print_rows();
            }
            return Err(e);
        }
    };
    let stance = instance_rows(&ctx, &instance, &mut report);
    list_rows(&cfg, notes.as_ref(), stance, &mut report);
    peer_rows(&mut report);
    access_rows(&paths, &cfg.relay, &mut report);
    report.finish(json)
}

/// What the newest status line says of the workers' client certificates (R-132, RO-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertStance {
    /// `client_certs: true`: the relay refuses a worker without one.
    Required,
    /// No `peers_version`: a relay from before the relay security plan, which refuses a list with `tls_fp` and unloads
    /// its whole whitelist, so no certificate may be issued yet (RO-3).
    TooEarly,
    /// A `peers_version` and no `client_certs` key: a relay that asks for no client certificate, so part D's is not
    /// running. Right during RO-4's steps 3 to 5, and for up to 5 minutes after the new relay starts (the reload's next run
    /// after the apply), plus the log agent's delivery, until its first status line; past that, a rollback (`list_rows`'s row).
    Unasked,
    /// `client_certs: false`, or no line read.
    Later,
}

impl CertStance {
    fn of(line: Option<&Value>) -> CertStance {
        match line {
            Some(l) if l.get("client_certs").and_then(Value::as_bool) == Some(true) => CertStance::Required,
            Some(l) if l.get("peers_version").is_none() => CertStance::TooEarly,
            Some(l) if l.get("client_certs").is_none() => CertStance::Unasked,
            _ => CertStance::Later,
        }
    }
}

/// The instance, and when it runs, SSM's ping, the TCP probe, the status line, the refused hour and the disk: what
/// the newest status line says of the workers' certificates.
fn instance_rows(ctx: &RelayCtx, instance: &str, report: &mut Report) -> CertStance {
    let doc = match ops::instance(instance) {
        Ok(d) => d,
        Err(e) => {
            report.row(Mark::Unknown, format!("instance {instance}: {e}"));
            report.doc.insert("instance".into(), json!({"id": instance, "refused": null, "disk_full": null}));
            return CertStance::Later;
        }
    };
    let state = doc.get("State").map(|s| text(s, "Name").to_string()).unwrap_or_default();
    let private_ip = text(&doc, "PrivateIpAddress").to_string();
    let public_ip = Some(text(&doc, "PublicIpAddress")).filter(|ip| !ip.is_empty()).map(str::to_string).or_else(|| ctx.state.relay_public_ip.clone()).unwrap_or_default();
    let shown = |ip: &str| if ip.is_empty() { "-".to_string() } else { ip.to_string() };
    let mut inst = json!({"id": instance, "state": state, "private_ip": private_ip, "public_ip": public_ip, "refused": null, "disk_full": null});
    if state != "running" {
        report.row(Mark::No, format!("instance {instance}: {state} (private {}, public {}): {}", shown(&private_ip), shown(&public_ip), not_running_cure(&state)));
        report.doc.insert("instance".into(), inst);
        return CertStance::Later;
    }
    report.row(Mark::Ok, format!("instance {instance}: running (private {}, public {})", shown(&private_ip), shown(&public_ip)));
    match ops::ssm_ping(instance) {
        Ok(Some(ping)) if ping == "Online" => report.row(Mark::Ok, "ssm: Online".to_string()),
        Ok(Some(ping)) => report.row(Mark::Warn, format!("ssm: {ping}")),
        Ok(None) => report.row(Mark::Warn, "ssm: the instance is not registered with SSM".to_string()),
        Err(e) => report.row(Mark::Unknown, format!("ssm: {e}")),
    }
    inst["probe"] = json!(probe(&public_ip, report));
    let line = status_line(instance, report);
    let stance = CertStance::of(line.as_ref());
    inst["status_line"] = line.unwrap_or(Value::Null);
    inst["refused"] = refused_hour(instance, report).unwrap_or(Value::Null);
    inst["disk_full"] = disk_full(instance, report);
    report.doc.insert("instance".into(), inst);
    stance
}

/// A plain TCP probe of `<public ip>:443` (LD-WM15, §RS.3.2 row 2): informational, never the exit code.
fn probe(public_ip: &str, report: &mut Report) -> &'static str {
    let Ok(ip) = public_ip.parse::<std::net::IpAddr>() else {
        report.row(Mark::Warn, "probe: no public address recorded (state/infra.toml relay_public_ip)".to_string());
        return "none";
    };
    probe_at(std::net::SocketAddr::new(ip, 443), report)
}

/// [`probe`] of `at`: a connect within 3 s, then up to 1 s without sending a byte, so it is no fault (R-102). A relay
/// that closes it within that second refuses this Mac's address before TLS; one that keeps it open would go on to TLS.
fn probe_at(at: std::net::SocketAddr, report: &mut Report) -> &'static str {
    match std::net::TcpStream::connect_timeout(&at, PROBE_TIMEOUT) {
        Ok(stream) => {
            if closed_within(&stream, PROBE_CLOSE_WAIT) {
                report.row(Mark::Warn, format!("probe: {at} closed the connection before TLS: this Mac's address is not in {PEERS}, or is banned (ai-env relay allow-ip --mine)"));
                "refused"
            } else {
                report.row(Mark::Ok, format!("probe: {at} accepts a TCP connection"));
                "open"
            }
        }
        Err(e) => probe_failed(at, &e, report),
    }
}

/// A connect that failed. The security group admits 443 and R-94 drops an unlisted SYN, so a reset comes from the instance
/// itself, with nothing listening: a relay stopped, failed or still booting, never this Mac's address (LD-R66).
fn probe_failed(at: std::net::SocketAddr, e: &std::io::Error, report: &mut Report) -> &'static str {
    if e.kind() == std::io::ErrorKind::ConnectionRefused {
        report.row(Mark::Warn, format!("probe: {at} refused the connection: nothing listens there, so the relay is not running or is still booting (make relay-logs)"));
        return "not_listening";
    }
    report.row(Mark::Warn, format!("probe: {at} did not accept a TCP connection within 3 s ({e}); this Mac's network may block it, or its address is not in {PEERS} (ai-env relay allow-ip --mine)"));
    "closed"
}

/// What a state other than `running` asks for: a terminated instance cannot start, and state/infra.toml names the old
/// one after a deploy replaced it (LD-R66).
fn not_running_cure(state: &str) -> &'static str {
    if matches!(state, "terminated" | "shutting-down") {
        "state/infra.toml names an instance a deploy replaced: make infra-status WRITE=1"
    } else {
        "ai-env relay start"
    }
}

/// Whether the peer closes `stream` within `wait`, this end sending nothing: an end of stream or a reset. A byte from
/// the peer, or the wait running out, says it stays open; dropping `stream` then closes it.
fn closed_within(stream: &std::net::TcpStream, wait: Duration) -> bool {
    use std::io::{ErrorKind, Read as _};
    let deadline = Instant::now() + wait;
    let mut reader = stream;
    let mut byte = [0u8; 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        match reader.read(&mut byte) {
            Ok(0) => return true,
            Ok(_) => return false,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        }
    }
}

/// The newest `ev:"status"` line of the relay's request log in the last 10 minutes (B-12, R-67): its row, and
/// the line itself for `--json` (ids, versions, counts and ages only).
fn status_line(instance: &str, report: &mut Report) -> Option<Value> {
    let doc = match log_events(instance, "requests", STATUS_WINDOW_MS, r#"{ $.ev = "status" }"#) {
        Ok(d) => d,
        Err(e) => {
            report.row(Mark::Unknown, format!("relay: the status line could not be read ({e})"));
            return None;
        }
    };
    let newest = arr(&doc, "events")
        .iter()
        .filter_map(|e| Some((e.get("timestamp").and_then(Value::as_u64).unwrap_or(0), serde_json::from_str::<Value>(e.get("message")?.as_str()?).ok()?)))
        .filter(|(_, line)| line.get("ev").and_then(Value::as_str) == Some("status"))
        .max_by_key(|(at, _)| *at);
    let Some((_, line)) = newest else {
        report.row(Mark::Warn, "relay: no status line in 10 min".to_string());
        return None;
    };
    let field = |k: &str| line.get(k).map_or_else(|| "-".to_string(), |v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
    // An older relay's line has no `peers_version`; one with no peers file loaded holds it empty (§RS.3.1).
    let peers = match line.get("peers_version").and_then(Value::as_str) {
        Some(version) if !version.is_empty() => format!("{version} ({} s old)", field("peers_age_s")),
        _ => "-".to_string(),
    };
    // R-132: the row that tells part D's relay from the first deploy's, whose `relay_version` can be the same.
    let required = if line.get("client_certs").and_then(Value::as_bool) == Some(true) { "; client certificates required" } else { "" };
    report.row(
        Mark::Ok,
        format!(
            "relay {}: {} tunnel(s), {} source(s) live; workers {} ({} s old), token-signers {} ({} s old), grants {} ({} s old), peers {peers}{required}",
            field("relay_version"),
            field("tunnels"),
            field("sources_live"),
            field("workers_version"),
            field("workers_age_s"),
            field("signers_version"),
            field("signers_age_s"),
            field("grants_version"),
            field("grants_age_s")
        ),
    );
    // Its version empty, not missing: every admission is `no_peers` and every tunnel closed (R-89, R-90), whatever row 8
    // reads in SSM.
    if line.get("peers_version").and_then(Value::as_str) == Some("") {
        report.row(Mark::Warn, "relay: its peers list is not loaded: it admits no worker".to_string());
    }
    // No TLS config, so both faces refuse `no_tls`: a first load that refused `tls.pem`, which nothing rolls back (R-124), or
    // the file gone (R-4).
    if line.get("tls_loaded").and_then(Value::as_bool) == Some(false) {
        report.row(Mark::Warn, "relay: it holds no TLS config: it serves nobody (make relay-logs: a live file was refused, or relay=waiting-for-tls)".to_string());
    }
    Some(line)
}

/// One `filter-log-events` of the relay's log group: `<instance>/<stream>`, the last `window_ms`, `pattern`.
fn log_events(instance: &str, stream: &str, window_ms: u64, pattern: &str) -> std::result::Result<Value, String> {
    let start = unix_now_ms().saturating_sub(window_ms).to_string();
    let stream = format!("{instance}/{stream}");
    aws_json("logs", &["filter-log-events", "--log-group-name", RELAY_LOG_GROUP, "--log-stream-names", stream.as_str(), "--start-time", start.as_str(), "--filter-pattern", pattern])
}

/// What the relay refused or cut in the last hour (§RS.3.2 row 4, R-139).
#[derive(Debug, Default, PartialEq, Eq)]
struct Refused {
    /// `N`: the refused tunnel lines, plus their `suppressed`.
    handshakes: u64,
    /// `M`: distinct `peer` values among those tunnel lines.
    addresses: usize,
    /// `P`: the peer lines but the public face's allowlist refusals, plus their `suppressed`.
    connections: u64,
    /// `B`: distinct `peer` values of the peer lines whose reason is `banned`.
    banned: usize,
    /// `U`: the public face's `no_peers` and `not_in_peers` lines, plus their `suppressed`.
    unlisted: u64,
    /// `T`: the public face's `tls_failed` lines, plus their `suppressed` (they count in `P` too).
    tls_failed: u64,
    /// The three most frequent reasons of the tunnel lines and of `P`'s lines, by line count, ties by name.
    top: Vec<(String, u64)>,
}

impl Refused {
    /// The counts of request-log lines. Any other line (the filter's to leave out) counts nothing.
    fn of<'a>(lines: impl Iterator<Item = &'a Value>) -> Refused {
        let word = |line: &'a Value, key: &str| line.get(key).and_then(Value::as_str).unwrap_or("");
        let (mut out, mut addresses, mut banned) = (Refused::default(), BTreeSet::new(), BTreeSet::new());
        let mut reasons: BTreeMap<&str, u64> = BTreeMap::new();
        for line in lines {
            let counted = 1 + line.get("suppressed").and_then(Value::as_u64).unwrap_or(0);
            let (peer, reason) = (word(line, "peer"), word(line, "reason"));
            match word(line, "ev") {
                "tunnel" if word(line, "outcome") == "refused" => {
                    out.handshakes += counted;
                    addresses.insert(peer);
                }
                "peer" if word(line, "face") == "public" && UNLISTED_REASONS.contains(&reason) => {
                    out.unlisted += counted;
                    continue;
                }
                "peer" => {
                    out.connections += counted;
                    if reason == "banned" {
                        banned.insert(peer);
                    }
                    if reason == TLS_FAILED_REASON && word(line, "face") == "public" {
                        out.tls_failed += counted;
                    }
                }
                _ => continue,
            }
            *reasons.entry(reason).or_default() += 1;
        }
        addresses.remove("");
        banned.remove("");
        reasons.remove("");
        (out.addresses, out.banned) = (addresses.len(), banned.len());
        let mut top: Vec<(&str, u64)> = reasons.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out.top = top.into_iter().take(3).map(|(reason, count)| (reason.to_string(), count)).collect();
        out
    }

    /// Its row: `[warn]` with a refused handshake, a banned address or `T` at [`TLS_FAILED_WARN`], the allowlist's noise
    /// (`U`) never.
    fn row(&self) -> (Mark, String) {
        let top = if self.top.is_empty() { "none".to_string() } else { self.top.iter().map(|(reason, count)| format!("{reason} {count}")).collect::<Vec<_>>().join(", ") };
        let mark = if self.handshakes > 0 || self.banned > 0 || self.tls_failed >= TLS_FAILED_WARN { Mark::Warn } else { Mark::Ok };
        let text = format!(
            "refused in the last hour: {} handshake(s) from {} address(es), {} connection(s) refused or cut, {} address(es) banned, {} connection(s) from unlisted addresses; top reasons: {top}",
            self.handshakes, self.addresses, self.connections, self.banned, self.unlisted
        );
        (mark, text)
    }

    /// `instance.refused`.
    fn doc(&self) -> Value {
        let top: Vec<Value> = self.top.iter().map(|(reason, count)| json!({"reason": reason, "count": count})).collect();
        json!({"handshakes": self.handshakes, "addresses": self.addresses, "connections": self.connections, "banned": self.banned, "unlisted": self.unlisted, "tls_failed": self.tls_failed, "top": top})
    }
}

/// The refused hour's row, never the exit code, and `instance.refused`; `None` when it could not be read.
fn refused_hour(instance: &str, report: &mut Report) -> Option<Value> {
    let doc = match log_events(instance, "requests", REFUSED_WINDOW_MS, REFUSED_FILTER) {
        Ok(d) => d,
        Err(e) => {
            report.row(Mark::Warn, format!("relay: the refusals of the last hour could not be read ({e})"));
            return None;
        }
    };
    let lines: Vec<Value> = arr(&doc, "events").iter().filter_map(|e| serde_json::from_str(e.get("message")?.as_str()?).ok()).collect();
    let refused = Refused::of(lines.iter());
    let (mark, text) = refused.row();
    report.row(mark, text);
    Some(refused.doc())
}

/// R-95: the reload's `why=disk` in the last 10 minutes: its row, never the exit code, and `instance.disk_full`
/// (`null` when it could not be read).
fn disk_full(instance: &str, report: &mut Report) -> Value {
    let doc = match log_events(instance, "reload", DISK_WINDOW_MS, &format!("\"{DISK_WORD}\"")) {
        Ok(d) => d,
        Err(e) => {
            report.row(Mark::Warn, format!("relay: the reload's log could not be read ({e})"));
            return Value::Null;
        }
    };
    let newest = arr(&doc, "events").iter().filter(|e| text(e, "message").contains(DISK_WORD)).map(|e| e.get("timestamp").and_then(Value::as_u64).unwrap_or(0)).max();
    if let Some(at) = newest {
        report.row(Mark::Warn, format!("relay: the root volume is over 90 % full (the reload's {DISK_WORD} at {})", rfc3339_utc(at / 1000)));
    }
    json!(newest.is_some())
}

/// The three lists in one `get-parameters`, each entry shown, and this Mac's session key judged, its grants against what
/// `cfg` names; `stance` is what the newest status line says of the workers' certificates.
fn list_rows(cfg: &BridgeConfig, notes: Option<&MacKeyNotes>, stance: CertStance, report: &mut Report) {
    let worker_id = cfg.relay.worker_id.as_str();
    let names: Vec<String> = [WORKERS, TOKEN_SIGNERS, GRANTS].iter().map(|n| (*n).to_string()).collect();
    let (got, _) = match ops::get_parameters(&names) {
        Ok(g) => g,
        Err(e) => {
            report.row(Mark::Unknown, format!("lists: {e}"));
            return;
        }
    };
    let now = unix_now();
    let expired = |t: u64| if now > t { " EXPIRED" } else { "" };
    let fp = |b64: &str| PublicKey::parse_b64(b64).map_or_else(|_| "?".to_string(), |k| k.fingerprint());
    let value = |name: &str| got.get(name).map(|p| (p.value.clone(), p.version));
    // workers
    match value(WORKERS).map(|(v, n)| (policy::parse_workers(&v), n)) {
        None => {
            report.row(Mark::Note, format!("{WORKERS}: absent (ai-env relay allow creates it)"));
            report.doc.insert("workers".into(), json!([]));
        }
        Some((Err(e), n)) => report.row(Mark::No, format!("{WORKERS} v{n} does not parse ({e})")),
        Some((Ok(list), n)) => {
            report.row(Mark::Ok, format!("{WORKERS} v{n}: {} worker(s)", list.len()));
            for w in &list {
                let cert = w.tls_fp.as_deref().map_or_else(|| "no cert fp".to_string(), |t| format!("cert fp {}", fp16(t)));
                report.row(Mark::Note, format!("  worker {} (key fp {}, {cert}) for sources {} until {}{}", w.worker_id, fp(&w.public_key), w.sources.join(","), w.not_after, expired(w.not_after_unix())));
                if w.tls_fp.is_none() && now <= w.not_after_unix() {
                    let (mark, text) = no_cert_row(w, stance);
                    report.row(mark, text);
                }
            }
            let holding = list.iter().filter(|w| w.tls_fp.is_some() && now <= w.not_after_unix()).count();
            if stance == CertStance::Unasked && holding > 0 {
                report.row(Mark::Warn, format!("relay: this relay asks for no client certificate, though {holding} worker(s) hold one: part D's relay is not running (make relay-logs: rollback=)"));
            }
            let docs: Vec<Value> = list.iter().map(|w| json!({"id": w.worker_id, "fp": fp(&w.public_key), "cert_fp": w.tls_fp.as_deref().map(fp16), "sources": w.sources, "not_after": w.not_after, "expired": now > w.not_after_unix()})).collect();
            report.doc.insert("workers".into(), Value::Array(docs));
        }
    }
    // token signers, and this Mac's session key and sole key among them
    let mut in_force = false;
    let mut sole_in_force = false;
    let mut signers: Vec<policy::SignerEntry> = Vec::new();
    let sole_id = RelayCfg::sole_id_of(worker_id);
    // RO-6, RO-8: part D's deploy carries part H, so a status line with `client_certs` (R-132) is a relay that parses a
    // signer's `grants`. A line without it is one that refuses them; with none read, it is not known.
    let status_line = report.doc.get("instance").and_then(|i| i.get("status_line")).filter(|line| line.is_object());
    let parses_grants = status_line.is_some_and(|line| line.get("client_certs").is_some());
    let refuses_grants = status_line.is_some_and(|line| line.get("client_certs").is_none());
    match value(TOKEN_SIGNERS).map(|(v, n)| (policy::parse_signers(&v), n)) {
        None => {
            report.row(Mark::Note, format!("{TOKEN_SIGNERS}: absent (ai-env relay allow --token-signer creates it)"));
            report.doc.insert("token_signers".into(), json!([]));
        }
        Some((Err(e), n)) => report.row(Mark::No, format!("{TOKEN_SIGNERS} v{n} does not parse ({e})")),
        Some((Ok(list), n)) => {
            report.row(Mark::Ok, format!("{TOKEN_SIGNERS} v{n}: {} token signer(s)", list.len()));
            for s in &list {
                let reach = s.grants.as_ref().map_or_else(|| "every grant".to_string(), |globs| format!("grants {}", globs.join(",")));
                report.row(Mark::Note, format!("  token signer {} (key fp {}) for {reach} until {}{}", s.signer_id, fp(&s.public_key), s.not_after, expired(s.not_after_unix())));
                if now > s.not_after_unix() {
                    continue;
                }
                let mine = s.signer_id == worker_id;
                if let Some(text) = every_grant_row(s, parses_grants, mine.then_some(cfg.relay.grant.as_str())) {
                    report.row(Mark::Warn, text);
                }
                // R-157: the restricted grants are the sole signer's alone, and it must carry what its chats' tokens name.
                if s.signer_id == sole_id {
                    if !refuses_grants {
                        sole_grant_rows(s, cfg, report);
                    }
                } else if let Some(text) = restricted_row(s, cfg, mine, refuses_grants) {
                    report.row(Mark::No, text);
                }
                if mine && !refuses_grants {
                    own_grant_rows(s, cfg, report);
                }
            }
            // RO-6: one entry with `grants`, a lapsed one too, and that relay refuses the whole list.
            let bound: Vec<&str> = list.iter().filter(|s| s.grants.is_some()).map(|s| s.signer_id.as_str()).collect();
            if refuses_grants && !bound.is_empty() {
                report.row(Mark::No, format!("{TOKEN_SIGNERS} holds grants (token signer {}), but this relay refuses such a list, so every token fails (RO-6): deploy part D's relay, or ai-env as deployer -- ai-env relay revoke <id> --token-signer for each and allow it again without --grants", bound.join(",")));
            }
            in_force = notes.is_some_and(|n| list.iter().any(|s| s.signer_id == worker_id && s.public_key == n.session_key.b64() && now <= s.not_after_unix()));
            sole_in_force = notes.and_then(|n| n.sole_key.as_ref()).is_some_and(|k| list.iter().any(|s| s.signer_id == sole_id && s.public_key == k.b64() && now <= s.not_after_unix()));
            let docs: Vec<Value> = list.iter().map(|s| json!({"id": s.signer_id, "fp": fp(&s.public_key), "grants": s.grants, "not_after": s.not_after, "expired": now > s.not_after_unix()})).collect();
            report.doc.insert("token_signers".into(), Value::Array(docs));
            signers = list;
        }
    }
    match notes {
        Some(n) if in_force => report.row(Mark::Ok, format!("this Mac's session key (fp {}) is an in-force token signer as {worker_id}", n.session_key.fingerprint())),
        Some(n) => report.row(
            Mark::No,
            format!("this Mac's session key (fp {}) is not an in-force token signer as {worker_id}: ai-env as deployer -- ai-env relay allow {worker_id} --token-signer --key {}", n.session_key.fingerprint(), n.session_key.text()),
        ),
        None => report.row(Mark::No, format!("this Mac has no relay keys, so no token signer as {worker_id}: ai-env relay keygen")),
    }
    sole_key_row(cfg, notes, sole_in_force, report);
    // grants
    match value(GRANTS).map(|(v, n)| (policy::parse_grants(&v), n)) {
        None => {
            report.row(Mark::Note, format!("{GRANTS}: absent (ai-env relay grant creates it)"));
            report.doc.insert("grants".into(), json!([]));
        }
        Some((Err(e), n)) => report.row(Mark::No, format!("{GRANTS} v{n} does not parse ({e})")),
        Some((Ok(list), n)) => {
            report.row(Mark::Ok, format!("{GRANTS} v{n}: {} grant(s)", list.len()));
            for g in &list {
                report.row(Mark::Note, format!("  grant {}: {}", g.grant_id, g.allow.join(" ")));
            }
            overlap_rows(&list, &signers, cfg, now, report);
            let docs: Vec<Value> = list.iter().map(|g| json!({"id": g.grant_id, "rules": g.allow})).collect();
            report.doc.insert("grants".into(), Value::Array(docs));
        }
    }
}

/// The row of an in-force worker with no `tls_fp` (§RS.3.2 row 5, R-132): `[NO ]` when the newest status line says the
/// relay requires client certificates, `[warn]` when it says not, lacks the key or was not read. The command names the
/// worker's key and globs from the list; its P-256 point only the worker holds. A relay from before the plan gets no
/// command at all: running it now would unload that relay's whole whitelist (RO-3).
fn no_cert_row(w: &policy::WorkerEntry, stance: CertStance) -> (Mark, String) {
    let key = PublicKey::parse_b64(&w.public_key).map_or_else(|_| "<its key>".to_string(), |k| k.text());
    // Its day: with no `--not-after`, `allow` would move the entry and the new certificate a year from today (WM-R43).
    let day = entry_day(&w.not_after);
    let command = format!("on the worker: tls-keygen; then ai-env as deployer -- ai-env relay allow {} --key {key} --sources {} --tls-key <its p256 text> --not-after {day}", w.worker_id, shell_word(&w.sources.join(",")));
    match stance {
        CertStance::Required => (Mark::No, format!("worker {} has no client certificate: the relay refuses it ({command})", w.worker_id)),
        CertStance::Unasked | CertStance::Later => (Mark::Warn, format!("worker {} has no client certificate yet: a relay that requires client certificates would refuse it ({command})", w.worker_id)),
        CertStance::TooEarly => (Mark::Warn, format!("worker {} has no client certificate yet: a relay that requires client certificates would refuse it (not yet: this relay refuses a list with tls_fp and unloads its whole whitelist (RO-3))", w.worker_id)),
    }
}

/// The day of an entry's `not_after`, as `--not-after` takes it.
fn entry_day(not_after: &str) -> &str {
    not_after.get(..10).unwrap_or(not_after)
}

/// A key's text as a command takes it.
fn signer_key_text(s: &policy::SignerEntry) -> String {
    PublicKey::parse_b64(&s.public_key).map_or_else(|_| "<its key>".to_string(), |k| k.text())
}

/// A grant `bridge.toml` names, if it names one: empty is none, and a value that is no id mints nothing (`RelayCfg::validate`).
fn named_grant(grant: &str) -> Option<&str> {
    valid_id(grant).then_some(grant)
}

/// The `[warn]` of an in-force token signer that reaches every grant (§RS.3.2 row 6), `None` when its `grants` set a limit.
/// With no `grants` it names the command with its key and its day: with no `--not-after`, `allow` would move the entry's
/// end a year from today (WM-R43). A relay older than wave 4 refuses a list with `grants`, and every token then fails
/// (RO-6), so `parses_grants` false gets no command at all, as RO-3 does for a worker's certificate. `mac_grant` is
/// `[relay].grant` for this Mac's own entry, which the set must keep or this Mac's tokens are refused (R-135). A glob of
/// nothing but `*` matches every grant, so a set holding one limits nothing.
fn every_grant_row(s: &policy::SignerEntry, parses_grants: bool, mac_grant: Option<&str>) -> Option<String> {
    let id = &s.signer_id;
    if let Some(globs) = &s.grants {
        return globs.iter().any(|glob| glob.bytes().all(|b| b == b'*')).then(|| format!("token signer {id} may mint tokens for every grant (its grants hold *)"));
    }
    if !parses_grants {
        return Some(format!("token signer {id} may mint tokens for every grant (not yet: a relay before part H refuses a list with grants, and every token then fails (RO-6))"));
    }
    let key = signer_key_text(s);
    let day = entry_day(&s.not_after);
    let first = mac_grant.and_then(named_grant).map_or_else(String::new, |grant| format!("{grant},"));
    Some(format!("token signer {id} may mint tokens for every grant (ai-env as deployer -- ai-env relay allow {id} --token-signer --key {key} --grants {first}<grant globs> --not-after {day})"))
}

/// This Mac's own token signer, in force, against what `bridge.toml` names (§RS.3.2 row 6): its `grants` bind every token
/// it mints (R-135) and every grant an approval adds (R-145). No glob matching `[relay].grant` refuses every token, a
/// finding; none matching a `[[workspace]].relay_grant` or a `[relay].offer` id leaves a chat with nothing through it, but a
/// `[relay].restricted` id, which it must never reach ([`restricted_row`]).
fn own_grant_rows(s: &policy::SignerEntry, cfg: &BridgeConfig, report: &mut Report) {
    let Some(globs) = &s.grants else {
        return;
    };
    let id = &s.signer_id;
    let held = globs.join(",");
    let matched = |name: &str| globs.iter().any(|glob| glob_match(glob, name));
    let grant = named_grant(&cfg.relay.grant);
    if let Some(grant) = grant.filter(|g| !matched(g)) {
        let (key, day, set) = (signer_key_text(s), entry_day(&s.not_after), shell_word(&format!("{grant},{held}")));
        report.row(Mark::No, format!("token signer {id} holds grants {held}, none of which matches [relay].grant {grant}: every token this Mac mints is refused 7 not granted (R-135) (ai-env as deployer -- ai-env relay allow {id} --token-signer --key {key} --grants {set} --not-after {day})"));
    }
    let named: BTreeSet<&str> = cfg.workspace_overrides.iter().filter_map(|w| w.relay_grant.as_deref()).chain(cfg.relay.offer.iter().map(String::as_str)).filter_map(named_grant).filter(|name| Some(*name) != grant && !cfg.relay.is_restricted(name)).collect();
    for name in named.into_iter().filter(|name| !matched(name)) {
        report.row(Mark::Warn, format!("token signer {id} holds grants {held}, none of which matches {name}: a chat reaches nothing through it"));
    }
}

/// R-157: the `[NO ]` of an in-force token signer other than this Mac's sole signer that reaches a `[relay].restricted` grant
/// (no `grants`, or a glob matching one): a token it mints on a VM chats share reaches that grant through any approval
/// (R-145), which `<worker_id>-sole` alone may carry. `None` when it reaches none. The command binds this Mac's own signer to
/// [`BridgeConfig::session_signer_grants`], another to globs of the user's choosing; a relay that refuses a list with grants
/// gets none (RO-6).
fn restricted_row(s: &policy::SignerEntry, cfg: &BridgeConfig, mine: bool, refuses_grants: bool) -> Option<String> {
    let reached = restricted_reached(s.grants.as_deref(), &cfg.relay.restricted);
    if reached.is_empty() {
        return None;
    }
    let id = &s.signer_id;
    let held = s.grants.as_ref().map_or_else(|| "no grants".to_string(), |globs| format!("grants {}", globs.join(",")));
    let cure = if refuses_grants {
        "not yet: a relay before part H refuses a list with grants, and every token then fails (RO-6)".to_string()
    } else {
        let set = if mine { cfg.session_signer_grants() } else { Vec::new() };
        let set = if set.is_empty() { "<grant globs>".to_string() } else { shell_word(&set.join(",")) };
        format!("ai-env as deployer -- ai-env relay allow {id} --token-signer --key {} --grants {set} --not-after {}", signer_key_text(s), entry_day(&s.not_after))
    };
    Some(format!("token signer {id} reaches the [relay].restricted grant {} ({held}), which only {} may: a token it mints on a VM chats share reaches it through an approval ({cure})", reached.join(","), cfg.relay.sole_id()))
}

/// R-157, by the grants' rules: a grant other than a `[relay].restricted` one that an in-force token signer other than this
/// Mac's sole signer reaches (its `grants` match the id, or it has none), one of whose rules meets one of a restricted grant's
/// ([`rules_meet`]): such a signer's token, minted on a VM chats share, reaches the restricted grant's sources through it,
/// whatever the ids say, since the relay serves a grant by its rules. `[NO ]` for each such pair, naming the first rules that
/// meet and the command that sets the grant's rules anew; the guard and the other rows compare ids alone.
fn overlap_rows(grants: &[policy::Grant], signers: &[policy::SignerEntry], cfg: &BridgeConfig, now: u64, report: &mut Report) {
    let sole_id = cfg.relay.sole_id();
    let restricted: Vec<&policy::Grant> = grants.iter().filter(|g| cfg.relay.is_restricted(&g.grant_id)).collect();
    if restricted.is_empty() {
        return;
    }
    let reaching = |grant: &str| -> Vec<&str> {
        signers
            .iter()
            .filter(|s| s.signer_id != sole_id && now <= s.not_after_unix())
            .filter(|s| s.grants.as_ref().is_none_or(|globs| globs.iter().any(|glob| glob_match(glob, grant))))
            .map(|s| s.signer_id.as_str())
            .collect()
    };
    for g in grants.iter().filter(|g| !cfg.relay.is_restricted(&g.grant_id)) {
        let by = reaching(&g.grant_id);
        if by.is_empty() {
            continue;
        }
        for r in &restricted {
            let Some((ours, theirs)) = g.allow.iter().find_map(|a| r.allow.iter().find(|b| rules_meet(a, b)).map(|b| (a, b))) else { continue };
            report.row(
                Mark::No,
                format!(
                    "grant {0} (rule {ours}) reaches the sources of the [relay].restricted grant {1} (rule {theirs}), and token signer {2} reaches {0}: a token it mints on a VM chats share reaches those sources through it (ai-env as deployer -- ai-env relay grant {0} '<rules that leave them out>')",
                    g.grant_id,
                    r.grant_id,
                    by.join(",")
                ),
            );
        }
    }
}

/// Whether two rules (`<source-glob>/<op-glob>`) match a source and an op in common: each half's globs meet
/// ([`globs_meet`]). A rule that is no rule meets nothing.
fn rules_meet(a: &str, b: &str) -> bool {
    match (a.split_once('/').filter(|_| ai_env_worker::globs::valid_rule(a)), b.split_once('/').filter(|_| ai_env_worker::globs::valid_rule(b))) {
        (Some((a_source, a_op)), Some((b_source, b_op))) => globs_meet(a_source, b_source) && globs_meet(a_op, b_op),
        _ => false,
    }
}

/// Whether two globs (`*` any run of name characters, the empty one too) match a name in common: `meet[i][j]` says
/// whether `a[i..]` and `b[j..]` do, from the ends back. A `*` stands for nothing, or takes the other's next character
/// (two `*` that both take one may each take one fewer, so one of them standing for nothing is enough). The name's own
/// grammar (its first character, its length) is not asked: a finding errs toward saying so.
fn globs_meet(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut meet = vec![vec![false; b.len() + 1]; a.len() + 1];
    for i in (0..=a.len()).rev() {
        for j in (0..=b.len()).rev() {
            meet[i][j] = match (a.get(i), b.get(j)) {
                (None, None) => true,
                (Some(b'*'), _) => meet[i + 1][j] || (j < b.len() && meet[i][j + 1]),
                (_, Some(b'*')) => meet[i][j + 1] || (i < a.len() && meet[i + 1][j]),
                (Some(x), Some(y)) => x == y && meet[i + 1][j + 1],
                _ => false,
            };
        }
    }
    meet[0][0]
}

/// R-157: this Mac's sole signer (`<worker_id>-sole`), in force, against what `bridge.toml` names, when `[relay].restricted`
/// names a grant (the agent signs with it then alone). Its tokens name `[relay].grant` or a `sole_vm` workspace's own grant,
/// which its `grants` must match or the relay refuses them 7 not granted (R-135), and it alone carries the restricted ids:
/// each it leaves out is `[NO ]`, naming the command that adds every one it leaves out. An offered id it leaves out is
/// `[warn]`: a chat on a VM of its own reaches nothing through it. With no `grants`, [`every_grant_row`] says it.
fn sole_grant_rows(s: &policy::SignerEntry, cfg: &BridgeConfig, report: &mut Report) {
    let Some(globs) = s.grants.as_ref().filter(|_| !cfg.relay.restricted.is_empty()) else {
        return;
    };
    let id = &s.signer_id;
    let held = globs.join(",");
    let missing: Vec<String> = cfg.sole_signer_grants().into_iter().filter(|name| !globs.iter().any(|glob| glob_match(glob, name))).collect();
    if missing.is_empty() {
        return;
    }
    let set: BTreeSet<&str> = globs.iter().chain(&missing).map(String::as_str).collect();
    let set = shell_word(&set.into_iter().collect::<Vec<_>>().join(","));
    let command = format!("ai-env as deployer -- ai-env relay allow {id} --token-signer --key {} --grants {set} --not-after {}", signer_key_text(s), entry_day(&s.not_after));
    for name in &missing {
        let own = cfg.workspace_overrides.iter().find(|w| w.sole_vm && w.relay_grant.as_deref() == Some(name.as_str()));
        let finding = if *name == cfg.relay.grant {
            Some(format!("[relay].grant {name}: every token it mints is refused 7 not granted (R-135)"))
        } else if let Some(w) = own {
            Some(format!("{name}, the own grant of [[workspace]] {}: every token of its chats is refused 7 not granted (R-135)", w.path.display()))
        } else if cfg.relay.is_restricted(name) {
            Some(format!("the [relay].restricted grant {name}: no chat reaches it"))
        } else {
            None
        };
        match finding {
            Some(what) => report.row(Mark::No, format!("token signer {id} holds grants {held}, none of which matches {what} ({command})")),
            None => report.row(Mark::Warn, format!("token signer {id} holds grants {held}, none of which matches {name}: a chat on a VM of its own reaches nothing through it")),
        }
    }
}

/// R-157: this Mac's sole key against the token signers: `[ok ]` an in-force signer as `<worker_id>-sole`; with
/// `[relay].restricted` naming a grant, `[NO ]` otherwise, since no chat then reaches one, naming the command (the sole
/// signer's, with its grants, or `relay keygen --sole`); without, a sole key not allowed is a note, and none says nothing.
fn sole_key_row(cfg: &BridgeConfig, notes: Option<&MacKeyNotes>, in_force: bool, report: &mut Report) {
    let id = cfg.relay.sole_id();
    let restricted = cfg.relay.restricted.join(",");
    match notes.and_then(|n| n.sole_key.as_ref()) {
        Some(k) if in_force => report.row(Mark::Ok, format!("this Mac's sole key (fp {}) is an in-force token signer as {id}", k.fingerprint())),
        Some(k) => {
            let set = cfg.sole_signer_grants();
            let set = if set.is_empty() { "<grant globs>".to_string() } else { set.join(",") };
            let command = format!("ai-env as deployer -- ai-env relay allow {id} --token-signer --key {} --grants {set}", k.text());
            if restricted.is_empty() {
                report.row(Mark::Note, format!("this Mac's sole key (fp {}) is not a token signer as {id}, which the relay agent signs with once [relay].restricted names a grant ({command})", k.fingerprint()));
            } else {
                report.row(Mark::No, format!("this Mac's sole key (fp {}) is not an in-force token signer as {id}, so no chat reaches [relay].restricted {restricted}: {command}", k.fingerprint()));
            }
        }
        None if !restricted.is_empty() => report.row(Mark::No, format!("this Mac has no sole key, so no token signer as {id}, and no chat reaches [relay].restricted {restricted}: ai-env relay keygen --sole")),
        None => {}
    }
}

/// The peers list (§RS.3.2 row 8, R-97), in a `get-parameters` of its own: until RO-1's deploy the ops policy reads
/// only S13's names, and IAM refuses a whole call for one name it does not allow, so a shared call would turn the other
/// lists' rows into `[?? ]` too.
fn peer_rows(report: &mut Report) {
    let (got, _) = match ops::get_parameters(&[PEERS.to_string()]) {
        Ok(g) => g,
        Err(e) => {
            report.row(Mark::Unknown, format!("{PEERS} could not be read ({e})"));
            return;
        }
    };
    let Some(param) = got.get(PEERS) else {
        report.row(Mark::No, format!("{PEERS}: absent: the relay admits no worker (ai-env relay allow-ip creates it)"));
        report.doc.insert("peers".into(), json!([]));
        return;
    };
    let n = param.version;
    let list = match policy::parse_peers(&param.value) {
        Ok(list) => list,
        Err(e) => {
            report.row(Mark::No, format!("{PEERS} v{n} does not parse ({e})"));
            return;
        }
    };
    let now = unix_now();
    let in_force = list.iter().filter(|p| now <= p.not_after_unix()).count();
    if in_force == 0 {
        report.row(Mark::No, format!("{PEERS} v{n}: {} peer(s), none in force: the relay admits no worker", list.len()));
    } else {
        report.row(Mark::Ok, format!("{PEERS} v{n}: {} peer(s), {in_force} in force", list.len()));
    }
    for p in &list {
        let lapsed = now > p.not_after_unix();
        report.row(Mark::Note, format!("  peer {} {} until {}{}", p.label, p.cidr, p.not_after, if lapsed { " EXPIRED" } else { "" }));
        if lapsed && p.label == MAC_LABEL {
            report.row(Mark::Warn, format!("peer {MAC_LABEL} lapsed at {}: this Mac's worker is refused (ai-env relay allow-ip --mine)", p.not_after));
        }
        if !lapsed && p.network().1 < WIDE_BELOW {
            report.row(Mark::Warn, format!("peer {} {} is wider than /16: it admits much of the internet (ai-env relay revoke-ip --label {})", p.label, p.cidr, p.label));
        }
    }
    let docs: Vec<Value> = list.iter().map(|p| json!({"label": p.label, "cidr": p.cidr, "not_after": p.not_after, "expired": now > p.not_after_unix()})).collect();
    report.doc.insert("peers".into(), Value::Array(docs));
}

/// The access list (R-146), in a `get-parameters` of its own as row 8's: until the deploy that names it the ops policy
/// cannot read it, and IAM refuses a whole call for one such name. What it reads goes in the panel's cache (R-152). R-157:
/// each entry's `[relay].restricted` grants are marked (`restricted` in its JSON), and one in force holding any past the
/// latest end their approval writes today, 30 days out, is `[warn]`.
fn access_rows(paths: &Paths, relay: &RelayCfg, report: &mut Report) {
    let (got, _) = match ops::get_parameters(&[ACCESS.to_string()]) {
        Ok(g) => g,
        Err(e) => {
            report.row(Mark::Unknown, format!("{ACCESS} could not be read ({e})"));
            return;
        }
    };
    let Some(param) = got.get(ACCESS) else {
        report.row(Mark::Note, format!("{ACCESS}: absent: no chat has more than its token's grant"));
        report.doc.insert("access".into(), json!([]));
        write_access_cache(paths, 0, &[]);
        return;
    };
    let n = param.version;
    let list = match policy::parse_access(&param.value) {
        Ok(list) => list,
        Err(e) => {
            report.row(Mark::No, format!("{ACCESS} v{n} does not parse ({e})"));
            return;
        }
    };
    let now = unix_now();
    let in_force = list.iter().filter(|a| now <= a.not_after_unix()).count();
    report.row(Mark::Ok, format!("{ACCESS} v{n}: {} chat(s), {in_force} in force", list.len()));
    // The latest end an approval of a restricted grant writes today (R-156).
    let latest = policy::not_after_of_day(&access_day(now, RESTRICTED_DAYS_MAX)).ok().and_then(|t| policy::unix_of(&t).ok()).unwrap_or(u64::MAX);
    for a in &list {
        report.row(Mark::Note, format!("  chat {} grants {} until {}{}{}", a.chat, a.grants.join(","), a.not_after, if now > a.not_after_unix() { " EXPIRED" } else { "" }, restricted_mark(&a.grants, &relay.restricted)));
        let held = restricted_in(&a.grants, &relay.restricted);
        if let Some(first) = held.first().filter(|_| now <= a.not_after_unix() && a.not_after_unix() > latest) {
            report.row(
                Mark::Warn,
                format!("chat {} holds the [relay].restricted grant {} until {}, past the {RESTRICTED_DAYS_MAX} days an approval of one writes (ai-env relay access <session> --allow {first} sets its end again)", a.chat, held.join(","), a.not_after),
            );
        }
    }
    let docs: Vec<Value> = list
        .iter()
        .map(|a| {
            let mut doc = json!({"chat": a.chat, "grants": a.grants, "not_after": a.not_after, "expired": now > a.not_after_unix()});
            let held = restricted_in(&a.grants, &relay.restricted);
            if !held.is_empty() {
                doc["restricted"] = json!(held);
            }
            doc
        })
        .collect();
    report.doc.insert("access".into(), Value::Array(docs));
    write_access_cache(paths, n, &list);
}

/// An aws failure of `what`: exit 7.
fn aws(what: &str) -> impl Fn(String) -> CliError + '_ {
    move |e| CliError::Aws(format!("{what}: {e}"))
}

/// Poll the instance's state until it is `want` (the first look at once), within `wait`: `Err` the last state seen.
fn wait_state(instance: &str, want: &str, wait: Wait) -> std::result::Result<(), String> {
    let mut seen = String::from("unknown");
    for i in 0..wait.tries {
        match ops::instance_state(instance) {
            Ok(s) if s == want => return Ok(()),
            Ok(s) => seen = s,
            Err(e) => seen = format!("unreadable ({e})"),
        }
        if i + 1 < wait.tries {
            std::thread::sleep(wait.step);
        }
    }
    Err(seen)
}

/// Poll SSM's ping until it is `Online`, within `wait`: `Err` the last ping seen.
fn wait_online(instance: &str, wait: Wait) -> std::result::Result<(), String> {
    let mut seen = String::from("not registered");
    for i in 0..wait.tries {
        match ops::ssm_ping(instance) {
            Ok(Some(p)) if p == "Online" => return Ok(()),
            Ok(Some(p)) => seen = p,
            Ok(None) => seen = "not registered".into(),
            Err(e) => seen = format!("unreadable ({e})"),
        }
        if i + 1 < wait.tries {
            std::thread::sleep(wait.step);
        }
    }
    Err(seen)
}

/// `ai-env relay start` (WM-R48): `start-instances`, then `running` within 180 s and SSM `Online` within 120 s.
pub fn cmd_start() -> Result<()> {
    let ctx = RelayCtx::load()?;
    let instance = ctx.instance()?;
    ctx.operator("relay start")?;
    let t0 = Instant::now();
    let now = ops::start_instance(&instance).map_err(aws("relay start"))?;
    note(&format!("relay {instance}: {now}; waiting for running, then SSM Online"));
    let ms = || t0.elapsed().as_millis().to_string();
    let timed_out = |what: &str, budget: Wait, seen: String| {
        audit(&ctx.paths, RELAY_START, &[("id", instance.clone()), ("outcome", "timeout".into()), ("ms", ms())]);
        CliError::Aws(format!("relay start: relay {instance} {what} within {} s (last seen: {seen})", budget.budget().as_secs()))
    };
    let running = START_RUNNING.scaled(ctx.backoff_ms);
    wait_state(&instance, "running", running).map_err(|seen| timed_out("is not running", START_RUNNING, seen))?;
    let online = START_ONLINE.scaled(ctx.backoff_ms);
    wait_online(&instance, online).map_err(|seen| timed_out("runs, but SSM is not Online", START_ONLINE, seen))?;
    let took = ms();
    audit(&ctx.paths, RELAY_START, &[("id", instance.clone()), ("outcome", "running".into()), ("ms", took.clone())]);
    say(&format!("relay {instance} running, SSM online ({took} ms)"));
    Ok(())
}

/// `ai-env relay stop` (WM-R49): `stop-instances`, then `stopped` within 300 s. No refusal.
pub fn cmd_stop() -> Result<()> {
    let ctx = RelayCtx::load()?;
    let instance = ctx.instance()?;
    ctx.operator("relay stop")?;
    let t0 = Instant::now();
    let now = ops::stop_instance(&instance).map_err(aws("relay stop"))?;
    note(&format!("relay {instance}: {now}; waiting for stopped"));
    let ms = || t0.elapsed().as_millis().to_string();
    if let Err(seen) = wait_state(&instance, "stopped", STOP_STOPPED.scaled(ctx.backoff_ms)) {
        audit(&ctx.paths, RELAY_STOP, &[("id", instance.clone()), ("outcome", "timeout".into()), ("ms", ms())]);
        return Err(CliError::Aws(format!("relay stop: relay {instance} is not stopped within {} s (last seen: {seen})", STOP_STOPPED.budget().as_secs())));
    }
    let took = ms();
    audit(&ctx.paths, RELAY_STOP, &[("id", instance.clone()), ("outcome", "stopped".into()), ("ms", took.clone())]);
    say(&format!("relay {instance} stopped ({took} ms): VM relay tools answer unavailable and workers keep dialing until ai-env relay start"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};

    fn rows(report: &Report) -> Vec<(Mark, &str)> {
        report.rows.iter().map(|(m, l)| (*m, l.as_str())).collect()
    }

    /// R-157, by the grants' rules: two globs meet when a name matches both (a `*` takes any run, the empty one too), in
    /// either order; two rules when both halves meet. A rule that is no rule meets nothing.
    #[test]
    fn globs_and_rules_meet_where_a_name_matches_both() {
        for (a, b) in [("*", "vault-a"), ("*", "*"), ("vault-*", "vault-a"), ("vault-*", "*-a"), ("v*t-*", "vault-*"), ("*a*", "*b*"), ("a*", "*a"), ("ab", "a*b"), ("a*b", "ab"), ("x*y*z", "x*z")] {
            assert!(globs_meet(a, b) && globs_meet(b, a), "{a} {b}");
        }
        for (a, b) in [("vault-*", "public-*"), ("mac-*", "silo-*"), ("a", "b"), ("a*", "b*"), ("*a", "*b"), ("ab", "a"), ("a*b", "a*c"), ("x*y", "x*z")] {
            assert!(!globs_meet(a, b) && !globs_meet(b, a), "{a} {b}");
        }
        assert!(rules_meet("*/*", "vault-*/list") && rules_meet("vault-*/l*", "*-a/list"));
        assert!(!rules_meet("vault-*/get", "vault-*/list") && !rules_meet("public-*/*", "vault-*/list"));
        assert!(!rules_meet("*", "*/*") && !rules_meet("*/*", "a/b/c") && !rules_meet("*****/*", "*/*"), "no rule meets nothing");
    }

    /// WM-T60's probe (§RS.3.2 row 2): the real command only dials port 443, which a test cannot bind without root, so
    /// `probe_at` meets three loopback servers: one that closes the connection at once (`refused`, within the second),
    /// one that keeps it open and reads no byte from it, the probe having sent none (`open`, after the second), and
    /// a port nothing listens on (`closed`). Each row's text and its JSON word.
    #[test]
    fn the_probe_tells_a_refusal_from_an_open_port_and_no_connect() {
        // Closes at once.
        let closer = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let at = closer.local_addr().unwrap();
        let t = std::thread::spawn(move || drop(closer.accept().unwrap()));
        let mut report = Report::default();
        assert_eq!(probe_at(at, &mut report), "refused");
        t.join().unwrap();
        assert_eq!(rows(&report), [(Mark::Warn, format!("probe: {at} closed the connection before TLS: this Mac's address is not in /ai-env/relay/peers, or is banned (ai-env relay allow-ip --mine)").as_str())]);
        // Keeps it open; the probe sends nothing, and closes it itself.
        let keeper = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let at = keeper.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            use std::io::Read as _;
            let (mut conn, _) = keeper.accept().unwrap();
            let mut seen = Vec::new();
            conn.read_to_end(&mut seen).unwrap();
            seen
        });
        let mut report = Report::default();
        let started = Instant::now();
        assert_eq!(probe_at(at, &mut report), "open");
        assert!(started.elapsed() >= PROBE_CLOSE_WAIT, "it waits out the second: {:?}", started.elapsed());
        assert_eq!(t.join().unwrap(), Vec::<u8>::new(), "no byte sent, so no fault (R-102)");
        assert_eq!(rows(&report), [(Mark::Ok, format!("probe: {at} accepts a TCP connection").as_str())]);
        // Nothing listens.
        let gone = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let at = gone.local_addr().unwrap();
        drop(gone);
        let mut report = Report::default();
        assert_eq!(probe_at(at, &mut report), "not_listening");
        assert_eq!(rows(&report), [(Mark::Warn, format!("probe: {at} refused the connection: nothing listens there, so the relay is not running or is still booting (make relay-logs)").as_str())]);
        // Every other failure: a dropped SYN times out.
        let mut report = Report::default();
        let late = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(probe_failed(at, &late, &mut report), "closed");
        let (mark, text) = report.rows[0].clone();
        assert_eq!(mark, Mark::Warn);
        assert!(text.starts_with(&format!("probe: {at} did not accept a TCP connection within 3 s (")) && text.ends_with("); this Mac's network may block it, or its address is not in /ai-env/relay/peers (ai-env relay allow-ip --mine)"), "{text}");
        // A state other than running: a stopped instance starts; a replaced one cannot.
        assert_eq!(not_running_cure("stopped"), "ai-env relay start");
        assert_eq!(not_running_cure("terminated"), "state/infra.toml names an instance a deploy replaced: make infra-status WRITE=1");
        assert_eq!(not_running_cure("shutting-down"), not_running_cure("terminated"));
        // A server that writes first (no relay does) is open, and the wait for it ends the wait.
        let talker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let at: SocketAddr = talker.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            use std::io::Write as _;
            let (mut conn, _) = talker.accept().unwrap();
            conn.write_all(b"x").unwrap();
            conn
        });
        let stream = TcpStream::connect(at).unwrap();
        assert!(!closed_within(&stream, Duration::from_secs(5)));
        drop(t.join().unwrap());
    }

    /// §RS.3.2 row 4's counts over hand-made lines, each with what R-66 suppressed before it.
    #[test]
    fn the_refused_hour_counts_its_lines_and_their_suppressed() {
        let tunnel = |peer: &str, reason: &str, suppressed: u64| json!({"ev": "tunnel", "phase": "auth", "outcome": "refused", "peer": peer, "reason": reason, "suppressed": suppressed});
        let line = |face: &str, peer: &str, reason: &str, suppressed: u64| json!({"ev": "peer", "face": face, "peer": peer, "reason": reason, "suppressed": suppressed});
        let lines = [
            tunnel("198.51.100.1", "bad_signature", 2),
            tunnel("198.51.100.1", "bad_signature", 0),
            tunnel("198.51.100.2", "unknown_cert", 0),
            // Neither refused nor a peer line: nothing (the filter's own, kept out here too).
            json!({"ev": "tunnel", "phase": "auth", "outcome": "ok", "peer": "198.51.100.3", "reason": "", "suppressed": 9}),
            json!({"ev": "status", "tunnels": 2}),
            line("public", "203.0.113.1", "not_in_peers", 40),
            line("public", "203.0.113.2", "no_peers", 1),
            line("public", "198.51.100.4", "banned", 3),
            line("public", "198.51.100.4", "banned", 0),
            line("public", "198.51.100.5", "tls_failed", 0),
            line("private", "192.0.2.9", "auth_timeout", 0),
            // A private address outside private_peers is no scanner of the internet: `P`, not `U`.
            line("private", "192.0.2.99", "not_in_peers", 0),
        ];
        let refused = Refused::of(lines.iter());
        assert_eq!((refused.handshakes, refused.addresses, refused.connections, refused.banned, refused.unlisted), (5, 2, 8, 1, 43));
        // Ties by name; by line count, whatever each line suppressed; the allowlist's lines never.
        assert_eq!(refused.top, [("bad_signature".to_string(), 2), ("banned".to_string(), 2), ("auth_timeout".to_string(), 1)]);
        let (mark, text) = refused.row();
        assert_eq!(mark, Mark::Warn);
        assert_eq!(text, "refused in the last hour: 5 handshake(s) from 2 address(es), 8 connection(s) refused or cut, 1 address(es) banned, 43 connection(s) from unlisted addresses; top reasons: bad_signature 2, banned 2, auth_timeout 1");
        assert_eq!(refused.doc(), json!({"handshakes": 5, "addresses": 2, "connections": 8, "banned": 1, "unlisted": 43, "tls_failed": 1, "top": [{"reason": "bad_signature", "count": 2}, {"reason": "banned", "count": 2}, {"reason": "auth_timeout", "count": 1}]}));
        // Nothing: no reason. Scanners alone: `[ok ]`, whatever their number. A cut alone: `[ok ]` too (`N` and `B` warn).
        let (mark, text) = Refused::of([].iter()).row();
        assert!(mark == Mark::Ok && text.ends_with("; top reasons: none"), "{text}");
        let scanners = [line("public", "203.0.113.1", "not_in_peers", 1000)];
        let (mark, text) = Refused::of(scanners.iter()).row();
        assert!(mark == Mark::Ok && text.contains("1001 connection(s) from unlisted addresses; top reasons: none"), "{text}");
        let cut = [line("private", "192.0.2.9", "idle", 0)];
        assert_eq!(Refused::of(cut.iter()).row().0, Mark::Ok);
        // One banned line warns; fewer reasons when fewer exist.
        let ban = [line("public", "198.51.100.4", "banned", 0)];
        let (mark, text) = Refused::of(ban.iter()).row();
        assert!(mark == Mark::Warn && text.ends_with("; top reasons: banned 1"), "{text}");
        // `T`: from part D a worker refused at TLS writes only the public face's `tls_failed` lines, so ten in the hour warn, a
        // line's `suppressed` counting; nine do not, since each `relay status` probe writes one with no fault. The private
        // face's never, nor another reason's. They stay in `P`.
        let failed = |face: &str, reason: &str, lines: usize, suppressed: u64| (0..lines).map(|_| line(face, "198.51.100.5", reason, suppressed)).collect::<Vec<Value>>();
        let t = |lines: &[Value]| {
            let refused = Refused::of(lines.iter());
            (refused.tls_failed, refused.connections, refused.row().0)
        };
        assert_eq!(t(&failed("public", "tls_failed", 9, 0)), (9, 9, Mark::Ok));
        assert_eq!(t(&failed("public", "tls_failed", 10, 0)), (10, 10, Mark::Warn));
        assert_eq!(t(&failed("public", "tls_failed", 1, 8)), (9, 9, Mark::Ok));
        assert_eq!(t(&failed("public", "tls_failed", 1, 9)), (10, 10, Mark::Warn));
        assert_eq!(t(&failed("private", "tls_failed", 50, 0)), (0, 50, Mark::Ok));
        assert_eq!(t(&failed("public", "tls_timeout", 50, 0)), (0, 50, Mark::Ok));
    }
}
