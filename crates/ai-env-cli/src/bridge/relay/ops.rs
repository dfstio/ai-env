//! The relay instance as ai-env-ops (S13, WM-R47 to WM-R49): `ai-env relay status|start|stop`.
//!
//! `status` shows this Mac's side first, with no AWS call and no Touch ID (the sealed keys' notes, the agent's
//! `status` answer within a second); `--local` stops there. Then, as the operator (the `ai-env as` key, else
//! `credentials/ops.env` and its one Touch ID): the instance (state, addresses), SSM's ping and a plain TCP
//! connect to `<public ip>:443` when it runs (informational, LD-WM15: no TLS dial), the three lists in one
//! `get-parameters`, and the newest `ev:"status"` line of the relay's request log in CloudWatch (B-12).
//! Findings are `[NO ]` and exit 1: this Mac's session key is not an in-force token signer under
//! `[relay].worker_id`, a list does not parse, the instance is not running. A read that failed is `[?? ]` and
//! exit 7 when nothing was found first. `start` and `stop` wait as `proxy start|stop` do, their polls scaled by
//! the lab knob; a relay that stops answers VM relay tools `unavailable`, and workers keep dialing until it
//! starts again.
use super::cli::{audit, note, runtime, say, RelayCtx};
use super::keys::{read_notes, MacKeyNotes};
use crate::bridge::audit::event::{RELAY_START, RELAY_STOP};
use crate::bridge::awscli::aws_json;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::egress::ops::{self, arr, text, Wait};
use crate::bridge::egress::RELAY_LOG_GROUP;
use crate::errors::{CliError, Result};
use crate::wire::time::{rfc3339_utc, unix_now, unix_now_ms};
use ai_env_worker::agent::{request, AgentStatus, Request, Response};
use ai_env_worker::keys::PublicKey;
use ai_env_worker::policy::{self, GRANTS, TOKEN_SIGNERS, WORKERS};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// `start`'s waits (WM-R48): `running` within 180 s, then SSM `Online` within 120 s, 5 s steps.
const START_RUNNING: Wait = Wait { step: Duration::from_secs(5), tries: 36 };
const START_ONLINE: Wait = Wait { step: Duration::from_secs(5), tries: 24 };
/// `stop`'s wait (WM-R49): `stopped` within 300 s.
const STOP_STOPPED: Wait = Wait { step: Duration::from_secs(5), tries: 60 };
/// The TCP probe of the public face (LD-WM15).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How far back the status line is looked for (B-12; the relay writes one every 300 s).
const STATUS_WINDOW_MS: u64 = 600_000;
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

/// The rows of one `status` run, and its JSON (WM-R47): always the six keys `instance`, `workers`,
/// `token_signers`, `grants`, `status` and `mac`, `null` for what was not read (`--local`, a failed read, a list
/// that does not parse). `status` is the verdict and the rows; the relay's newest status line (B-12) rides in
/// `instance.status_line`.
#[derive(Default)]
struct Report {
    rows: Vec<(Mark, String)>,
    doc: serde_json::Map<String, Value>,
}

/// The keys of `--json`'s object.
const JSON_KEYS: [&str; 6] = ["instance", "workers", "token_signers", "grants", "status", "mac"];

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
            report.row(Mark::Ok, format!("keys: sealed in credentials/relay-worker.env for worker {}, worker key fp {}, session key fp {}, sealed {day}", n.worker_id, n.worker_key.fingerprint(), n.session_key.fingerprint()));
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
            "sealed": notes.as_ref().and_then(MacKeyNotes::sealed_day),
            "agent": agent.as_ref().map(|s| json!({"pid": s.pid, "until": s.until, "signed": s.signed, "minted": s.minted})),
        }),
    );
    notes
}

/// The agent's `status` answer within [`AGENT_WAIT`], if one answers on this Mac's socket.
fn agent_status(paths: &Paths) -> Option<AgentStatus> {
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
    let worker_id = BridgeConfig::load(&paths)?.unwrap_or_default().relay.worker_id;
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
    instance_rows(&ctx, &instance, &mut report);
    list_rows(&worker_id, notes.as_ref(), &mut report);
    report.finish(json)
}

/// The instance, and when it runs, SSM's ping, the TCP probe and the status line.
fn instance_rows(ctx: &RelayCtx, instance: &str, report: &mut Report) {
    let doc = match ops::instance(instance) {
        Ok(d) => d,
        Err(e) => {
            report.row(Mark::Unknown, format!("instance {instance}: {e}"));
            report.doc.insert("instance".into(), json!({"id": instance}));
            return;
        }
    };
    let state = doc.get("State").map(|s| text(s, "Name").to_string()).unwrap_or_default();
    let private_ip = text(&doc, "PrivateIpAddress").to_string();
    let public_ip = Some(text(&doc, "PublicIpAddress")).filter(|ip| !ip.is_empty()).map(str::to_string).or_else(|| ctx.state.relay_public_ip.clone()).unwrap_or_default();
    let shown = |ip: &str| if ip.is_empty() { "-".to_string() } else { ip.to_string() };
    let mut inst = json!({"id": instance, "state": state, "private_ip": private_ip, "public_ip": public_ip});
    if state != "running" {
        report.row(Mark::No, format!("instance {instance}: {state} (private {}, public {}): ai-env relay start", shown(&private_ip), shown(&public_ip)));
        report.doc.insert("instance".into(), inst);
        return;
    }
    report.row(Mark::Ok, format!("instance {instance}: running (private {}, public {})", shown(&private_ip), shown(&public_ip)));
    match ops::ssm_ping(instance) {
        Ok(Some(ping)) if ping == "Online" => report.row(Mark::Ok, "ssm: Online".to_string()),
        Ok(Some(ping)) => report.row(Mark::Warn, format!("ssm: {ping}")),
        Ok(None) => report.row(Mark::Warn, "ssm: the instance is not registered with SSM".to_string()),
        Err(e) => report.row(Mark::Unknown, format!("ssm: {e}")),
    }
    inst["probe"] = json!(probe(&public_ip, report));
    inst["status_line"] = status_line(instance, report).unwrap_or(Value::Null);
    report.doc.insert("instance".into(), inst);
}

/// A plain TCP connect to `<public ip>:443` within 3 s (LD-WM15): informational, never the exit code.
fn probe(public_ip: &str, report: &mut Report) -> &'static str {
    let Ok(ip) = public_ip.parse::<std::net::IpAddr>() else {
        report.row(Mark::Warn, "probe: no public address recorded (state/infra.toml relay_public_ip)".to_string());
        return "none";
    };
    match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, 443), PROBE_TIMEOUT) {
        Ok(_) => {
            report.row(Mark::Ok, format!("probe: {ip}:443 accepts a TCP connection"));
            "open"
        }
        Err(e) => {
            report.row(Mark::Warn, format!("probe: {ip}:443 did not accept a TCP connection within 3 s ({e}); this Mac's network may block it"));
            "closed"
        }
    }
}

/// The newest `ev:"status"` line of the relay's request log in the last 10 minutes (B-12, R-67): its row, and
/// the line itself for `--json` (ids, versions, counts and ages only).
fn status_line(instance: &str, report: &mut Report) -> Option<Value> {
    let start = unix_now_ms().saturating_sub(STATUS_WINDOW_MS).to_string();
    let stream = format!("{instance}/requests");
    let args = ["filter-log-events", "--log-group-name", RELAY_LOG_GROUP, "--log-stream-names", stream.as_str(), "--start-time", start.as_str(), "--filter-pattern", r#"{ $.ev = "status" }"#];
    let doc = match aws_json("logs", &args) {
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
    report.row(
        Mark::Ok,
        format!(
            "relay {}: {} tunnel(s), {} source(s) live; workers {} ({} s old), token-signers {} ({} s old), grants {} ({} s old)",
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
    Some(line)
}

/// The three lists in one `get-parameters`, each entry shown, and this Mac's session key judged.
fn list_rows(worker_id: &str, notes: Option<&MacKeyNotes>, report: &mut Report) {
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
                report.row(Mark::Note, format!("  worker {} (key fp {}) for sources {} until {}{}", w.worker_id, fp(&w.public_key), w.sources.join(","), w.not_after, expired(w.not_after_unix())));
            }
            let docs: Vec<Value> = list.iter().map(|w| json!({"id": w.worker_id, "fp": fp(&w.public_key), "sources": w.sources, "not_after": w.not_after, "expired": now > w.not_after_unix()})).collect();
            report.doc.insert("workers".into(), Value::Array(docs));
        }
    }
    // token signers, and this Mac's session key among them
    let mut in_force = false;
    match value(TOKEN_SIGNERS).map(|(v, n)| (policy::parse_signers(&v), n)) {
        None => {
            report.row(Mark::Note, format!("{TOKEN_SIGNERS}: absent (ai-env relay allow --token-signer creates it)"));
            report.doc.insert("token_signers".into(), json!([]));
        }
        Some((Err(e), n)) => report.row(Mark::No, format!("{TOKEN_SIGNERS} v{n} does not parse ({e})")),
        Some((Ok(list), n)) => {
            report.row(Mark::Ok, format!("{TOKEN_SIGNERS} v{n}: {} token signer(s)", list.len()));
            for s in &list {
                report.row(Mark::Note, format!("  token signer {} (key fp {}) until {}{}", s.signer_id, fp(&s.public_key), s.not_after, expired(s.not_after_unix())));
            }
            in_force = notes.is_some_and(|n| list.iter().any(|s| s.signer_id == worker_id && s.public_key == n.session_key.b64() && now <= s.not_after_unix()));
            let docs: Vec<Value> = list.iter().map(|s| json!({"id": s.signer_id, "fp": fp(&s.public_key), "not_after": s.not_after, "expired": now > s.not_after_unix()})).collect();
            report.doc.insert("token_signers".into(), Value::Array(docs));
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
            let docs: Vec<Value> = list.iter().map(|g| json!({"id": g.grant_id, "rules": g.allow})).collect();
            report.doc.insert("grants".into(), Value::Array(docs));
        }
    }
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
