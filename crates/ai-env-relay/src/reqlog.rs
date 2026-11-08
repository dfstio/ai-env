//! The request log: its lines, sinks, digest and refusal limiter (R-60 to R-68). Ids and hashes only: never a
//! param, a chunk's data, a token, a key or a chat's id (R-145). And relay.log's own bounds (F23): its level filter and
//! its cap.
//!
//! One JSON object per line, each kind with exactly its key set (`CALL_KEYS` … `STATUS_KEYS`), every key on every
//! line (an empty string or 0 when unknown). Values are ids, words and numbers (R-62): source and op names only when
//! they are ids, worker ids only when the handshake parsed them as such, and the peer's IP only on the tunnel and
//! peer lines.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use tokio::time::Instant;

use crate::calls::Outcome;
use crate::limits::TokenBucket;
use crate::serve::Clock;

/// Where the lines go.
pub trait Sink: Send + Sync + 'static {
    /// One line.
    fn write_line(&self, line: &str);
}

/// Lines a sink failed to write, for the status line's `log_dropped` (R-68). One relay runs per process.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// O_APPEND, one write per line; a failed write is counted, never fatal (R-68).
pub struct FileSink {
    file: File,
}

impl FileSink {
    /// The file at `path`, opened for appending, 0640 (R-96): set on the open file, so neither the unit's `UMask=0077`
    /// nor an older relay's 0600 file keeps it from the CloudWatch agent (`cwagent`, in the relay's group).
    pub fn open(path: &Path) -> std::io::Result<FileSink> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        Ok(FileSink { file })
    }
}

impl Sink for FileSink {
    fn write_line(&self, line: &str) {
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        // One write: with O_APPEND a line is never split or interleaved; I's logrotate truncates in place (R-68).
        match (&self.file).write(&buf) {
            Ok(n) if n == buf.len() => {}
            _ => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The lines in memory (tests).
#[derive(Default)]
pub struct MemorySink {
    lines: Mutex<Vec<String>>,
}

impl MemorySink {
    /// Every line so far.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl Sink for MemorySink {
    fn write_line(&self, line: &str) {
        self.lines.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    }
}

/// A call line's keys (R-60).
pub const CALL_KEYS: [&str; 20] = [
    "ts", "ev", "request_id", "caller", "session", "vm", "grant", "source", "op", "worker", "tunnel", "params_hmac", "params_bytes", "bytes", "chunks",
    "truncated", "duration_ms", "outcome", "code", "suppressed",
];
/// A list line's keys (R-61).
pub const LIST_KEYS: [&str; 12] = ["ts", "ev", "request_id", "caller", "session", "vm", "grant", "sources", "duration_ms", "outcome", "code", "suppressed"];
/// A tunnel line's keys (R-65).
pub const TUNNEL_KEYS: [&str; 12] = ["ts", "ev", "tunnel", "worker", "peer", "sdk", "phase", "outcome", "reason", "sources", "duration_ms", "suppressed"];
/// A reload line's keys.
pub const RELOAD_KEYS: [&str; 7] = ["ts", "ev", "file", "outcome", "version", "entries", "age_s"];
/// A peer line's keys.
pub const PEER_KEYS: [&str; 6] = ["ts", "ev", "face", "peer", "reason", "suppressed"];
/// The status line's keys (R-67; `log_suppressed`, F23; `peers_version`, `peers_age_s` and `client_certs`, §RS.3.1;
/// `access_version` and `access_age_s`, R-146).
pub const STATUS_KEYS: [&str; 25] = [
    "ts", "ev", "relay_version", "protocol", "uptime_s", "tunnels", "sources_live", "sources_offline", "calls_in_flight", "sessions", "workers_version",
    "workers_age_s", "signers_version", "signers_age_s", "grants_version", "grants_age_s", "peers_version", "peers_age_s", "access_version", "access_age_s",
    "tls_loaded", "client_certs", "unknown_frames", "log_dropped", "log_suppressed",
];

/// R-63: the first 16 hex characters of HMAC-SHA256(key, params).
pub fn params_digest(key: &[u8; 32], params: &[u8]) -> String {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = aws_lc_rs::hmac::sign(&key, params);
    hex::encode(&tag.as_ref()[..8])
}

/// The status line's values: `STATUS_KEYS` but `ts` and `ev` (R's fields).
#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusLine {
    /// `RELAY_VERSION`.
    pub relay_version: String,
    /// `PROTOCOL`.
    pub protocol: u32,
    /// Seconds since the relay was built.
    pub uptime_s: u64,
    /// Live tunnels.
    pub tunnels: u64,
    /// Sources with a live tunnel.
    pub sources_live: u64,
    /// Sources whose tunnel went.
    pub sources_offline: u64,
    /// The relay permits held (R-106), each until hyper drops its call's stream.
    pub calls_in_flight: u64,
    /// Sessions kept (R-58).
    pub sessions: u64,
    /// `workers.json`'s version (16 hex), or "" when not loaded.
    pub workers_version: String,
    /// Seconds since its last confirmed fetch.
    pub workers_age_s: u64,
    /// `token-signers.json`'s version.
    pub signers_version: String,
    /// Seconds since its last confirmed fetch.
    pub signers_age_s: u64,
    /// `grants.json`'s version.
    pub grants_version: String,
    /// Seconds since its last confirmed fetch.
    pub grants_age_s: u64,
    /// `peers.json`'s version, or "" when not loaded (§RS.3.1).
    pub peers_version: String,
    /// Seconds since its last confirmed fetch.
    pub peers_age_s: u64,
    /// `access.json`'s version, or "" when not loaded (R-146).
    pub access_version: String,
    /// Seconds since its last confirmed fetch.
    pub access_age_s: u64,
    /// Whether a TLS config is loaded.
    pub tls_loaded: bool,
    /// Whether a TLS config is loaded and its public face requires client certificates (R-132).
    pub client_certs: bool,
    /// WorkerFrames with no known variant (P-R17).
    pub unknown_frames: u64,
    /// Lines a sink failed to write (R-68).
    pub log_dropped: u64,
    /// relay.log lines its cap suppressed (F23, `LogCap`).
    pub log_suppressed: u64,
}

/// The kinds R-66 limits, each to its own `log_refusals_per_min` with its own `suppressed` count. The peer lines are
/// three kinds, so the internet's noise that the allowlist refuses never suppresses a `banned` line or a private
/// face's line (§RS.9's R-66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Limited {
    /// Private-face request lines with outcome `unauthenticated`, `rate_limited`, `denied` or `too_many`: every refusal
    /// a request reaches before its session's bucket (R-135, R-136) has one of these words.
    Request,
    /// Tunnel lines with outcome `refused`.
    Tunnel,
    /// The public face's allowlist refusals: peer lines `no_peers` and `not_in_peers` (R-89).
    Unlisted,
    /// The public face's other peer lines.
    PublicPeer,
    /// The private face's peer lines.
    PrivatePeer,
}

impl Limited {
    /// A call or list line's kind, by its outcome, if R-66 limits it.
    fn of_request(outcome: &str) -> Option<Limited> {
        matches!(outcome, "unauthenticated" | "rate_limited" | "denied" | "too_many").then_some(Limited::Request)
    }

    /// A peer line's kind, by its face and reason.
    fn of_peer(face: &str, reason: &str) -> Limited {
        match (face, reason) {
            ("public", "no_peers" | "not_in_peers") => Limited::Unlisted,
            ("public", _) => Limited::PublicPeer,
            _ => Limited::PrivatePeer,
        }
    }
}

/// One kind's budget (R-66): its bucket, and the lines it refused since that kind's last written one.
struct Budget {
    bucket: TokenBucket,
    suppressed: u64,
}

/// Each kind's budget, a field a kind.
struct Limiter {
    request: Budget,
    tunnel: Budget,
    unlisted: Budget,
    public_peer: Budget,
    private_peer: Budget,
}

impl Limiter {
    /// `kind`'s budget. The match has no wildcard arm, so a new kind does not build until it has a budget of its own
    /// (an index into arrays sized by hand would panic on a refusal's line instead).
    fn budget(&mut self, kind: Limited) -> &mut Budget {
        match kind {
            Limited::Request => &mut self.request,
            Limited::Tunnel => &mut self.tunnel,
            Limited::Unlisted => &mut self.unlisted,
            Limited::PublicPeer => &mut self.public_peer,
            Limited::PrivatePeer => &mut self.private_peer,
        }
    }
}

/// The request log.
pub struct RequestLog {
    sink: Arc<dyn Sink>,
    key: [u8; 32],
    limiter: Mutex<Limiter>,
}

/// A JSON line built key by key, in the order written.
struct Line(String);

impl Line {
    fn new(ts: SystemTime, ev: &str) -> Line {
        let mut l = Line(String::with_capacity(256));
        l.0.push('{');
        l.str("ts", &rfc3339_ms(ts)).str("ev", ev);
        l
    }

    fn key(&mut self, k: &str) -> &mut Line {
        if self.0.len() > 1 {
            self.0.push(',');
        }
        self.0.push('"');
        self.0.push_str(k);
        self.0.push_str("\":");
        self
    }

    fn str(&mut self, k: &str, v: &str) -> &mut Line {
        self.key(k);
        self.0.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into()));
        self
    }

    fn num(&mut self, k: &str, v: impl Into<i128>) -> &mut Line {
        self.key(k);
        self.0.push_str(&v.into().to_string());
        self
    }

    fn bool(&mut self, k: &str, v: bool) -> &mut Line {
        self.key(k);
        self.0.push_str(if v { "true" } else { "false" });
        self
    }

    fn done(&mut self) -> String {
        self.0.push('}');
        std::mem::take(&mut self.0)
    }
}

/// `ts`: RFC 3339 UTC with milliseconds and `Z` (R-60).
pub(crate) fn rfc3339_ms(t: SystemTime) -> String {
    let since = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, since.subsec_millis())
}

/// A call line's fixed values; its outcome, bytes, chunks and duration come when it ends.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallFields {
    pub(crate) request_id: String,
    pub(crate) caller: String,
    pub(crate) session: String,
    pub(crate) vm: String,
    pub(crate) grant: String,
    pub(crate) source: String,
    pub(crate) op: String,
    pub(crate) worker: String,
    pub(crate) tunnel: String,
    pub(crate) params_hmac: String,
    pub(crate) params_bytes: u64,
}

/// What a call keeps to write its own line when it ends (`CallState::conclude`).
pub(crate) struct CallLog {
    pub(crate) log: Arc<RequestLog>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) fields: CallFields,
}

impl CallLog {
    /// The call's one line (R-61).
    pub(crate) fn write(&self, outcome: Outcome, bytes: u64, chunks: u64, duration_ms: u64) {
        let truncated = outcome == Outcome::Truncated;
        self.log.call(self.clock.now(), &self.fields, outcome.word(), outcome.code(), bytes, chunks, truncated, duration_ms);
    }
}

/// A list line's values.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListFields {
    pub(crate) request_id: String,
    pub(crate) caller: String,
    pub(crate) session: String,
    pub(crate) vm: String,
    pub(crate) grant: String,
    pub(crate) sources: u64,
}

/// A tunnel line's values.
#[derive(Debug, Clone, Default)]
pub(crate) struct TunnelFields {
    pub(crate) tunnel: String,
    pub(crate) worker: String,
    pub(crate) peer: String,
    pub(crate) sdk: String,
    pub(crate) phase: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) sources: u64,
    pub(crate) duration_ms: u64,
}

impl RequestLog {
    /// A log into `sink`, digesting params with `key`, at most `refusals_per_min` refusal lines a minute.
    pub fn new(sink: Arc<dyn Sink>, key: [u8; 32], refusals_per_min: u32) -> RequestLog {
        let now = tokio::time::Instant::now();
        let budget = || Budget { bucket: TokenBucket::new(refusals_per_min, refusals_per_min, now), suppressed: 0 };
        let limiter = Limiter { request: budget(), tunnel: budget(), unlisted: budget(), public_peer: budget(), private_peer: budget() };
        RequestLog { sink, key, limiter: Mutex::new(limiter) }
    }

    /// R-63 with this process's key.
    pub(crate) fn digest(&self, params: &[u8]) -> String {
        params_digest(&self.key, params)
    }

    /// R-66: whether a line of `kind` may be written now, and the count it carries in `suppressed`.
    fn admit(&self, kind: Option<Limited>) -> Option<u64> {
        let Some(kind) = kind else { return Some(0) };
        let mut l = self.limiter.lock().unwrap_or_else(PoisonError::into_inner);
        let budget = l.budget(kind);
        if budget.bucket.take(tokio::time::Instant::now()) {
            Some(std::mem::take(&mut budget.suppressed))
        } else {
            budget.suppressed += 1;
            None
        }
    }

    /// One `ev:"call"` line (R-61, R-64).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call(&self, ts: SystemTime, f: &CallFields, outcome: &str, code: i32, bytes: u64, chunks: u64, truncated: bool, duration_ms: u64) {
        let Some(suppressed) = self.admit(Limited::of_request(outcome)) else { return };
        let line = Line::new(ts, "call")
            .str("request_id", &f.request_id)
            .str("caller", &f.caller)
            .str("session", &f.session)
            .str("vm", &f.vm)
            .str("grant", &f.grant)
            .str("source", &f.source)
            .str("op", &f.op)
            .str("worker", &f.worker)
            .str("tunnel", &f.tunnel)
            .str("params_hmac", &f.params_hmac)
            .num("params_bytes", f.params_bytes)
            .num("bytes", bytes)
            .num("chunks", chunks)
            .bool("truncated", truncated)
            .num("duration_ms", duration_ms)
            .str("outcome", outcome)
            .num("code", code)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"list"` line (R-61); its refusals share the call lines' limit (R-66).
    pub(crate) fn list(&self, ts: SystemTime, f: &ListFields, outcome: &str, code: i32, duration_ms: u64) {
        let Some(suppressed) = self.admit(Limited::of_request(outcome)) else { return };
        let line = Line::new(ts, "list")
            .str("request_id", &f.request_id)
            .str("caller", &f.caller)
            .str("session", &f.session)
            .str("vm", &f.vm)
            .str("grant", &f.grant)
            .num("sources", f.sources)
            .num("duration_ms", duration_ms)
            .str("outcome", outcome)
            .num("code", code)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"tunnel"` line (R-65).
    pub(crate) fn tunnel(&self, ts: SystemTime, f: &TunnelFields) {
        let limited = (f.outcome == "refused").then_some(Limited::Tunnel);
        let Some(suppressed) = self.admit(limited) else { return };
        let line = Line::new(ts, "tunnel")
            .str("tunnel", &f.tunnel)
            .str("worker", &f.worker)
            .str("peer", &f.peer)
            .str("sdk", &f.sdk)
            .str("phase", f.phase)
            .str("outcome", f.outcome)
            .str("reason", f.reason)
            .num("sources", f.sources)
            .num("duration_ms", f.duration_ms)
            .num("suppressed", suppressed)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"reload"` line (R-67).
    pub(crate) fn reload(&self, ts: SystemTime, file: &str, outcome: &str, version: &str, entries: u64, age_s: u64) {
        let line = Line::new(ts, "reload")
            .str("file", file)
            .str("outcome", outcome)
            .str("version", version)
            .num("entries", entries)
            .num("age_s", age_s)
            .done();
        self.sink.write_line(&line);
    }

    /// One `ev:"peer"` line (R-2, R-66), limited as its kind (`Limited::of_peer`).
    pub(crate) fn peer(&self, ts: SystemTime, face: &str, peer: &str, reason: &str) {
        let Some(suppressed) = self.admit(Some(Limited::of_peer(face, reason))) else { return };
        let line = Line::new(ts, "peer").str("face", face).str("peer", peer).str("reason", reason).num("suppressed", suppressed).done();
        self.sink.write_line(&line);
    }

    /// One `ev:"status"` line (R-67).
    pub(crate) fn status(&self, ts: SystemTime, s: &StatusLine) {
        let line = Line::new(ts, "status")
            .str("relay_version", &s.relay_version)
            .num("protocol", s.protocol)
            .num("uptime_s", s.uptime_s)
            .num("tunnels", s.tunnels)
            .num("sources_live", s.sources_live)
            .num("sources_offline", s.sources_offline)
            .num("calls_in_flight", s.calls_in_flight)
            .num("sessions", s.sessions)
            .str("workers_version", &s.workers_version)
            .num("workers_age_s", s.workers_age_s)
            .str("signers_version", &s.signers_version)
            .num("signers_age_s", s.signers_age_s)
            .str("grants_version", &s.grants_version)
            .num("grants_age_s", s.grants_age_s)
            .str("peers_version", &s.peers_version)
            .num("peers_age_s", s.peers_age_s)
            .str("access_version", &s.access_version)
            .num("access_age_s", s.access_age_s)
            .bool("tls_loaded", s.tls_loaded)
            .bool("client_certs", s.client_certs)
            .num("unknown_frames", s.unknown_frames)
            .num("log_dropped", s.log_dropped)
            .num("log_suppressed", s.log_suppressed)
            .done();
        self.sink.write_line(&line);
    }
}

/// Lines a sink failed to write so far.
pub(crate) fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// relay.log lines a `LogCap` suppressed, for the status line's `log_suppressed` (F23). One relay runs per process.
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// The transport crates relay.log holds at `error` (F23): none of their `warn` lines is operator-actionable, and h2
/// writes one for every PING ACK a peer sends that answers no ping of its own. A directive's target is a prefix, so
/// `hyper` holds hyper-util too.
pub const TRANSPORT_TARGETS: [&str; 5] = ["h2", "hyper", "rustls", "tonic", "tower"];

/// relay.log's level filter: `spec` (`RUST_LOG`; `info` when absent or unreadable), then each of `TRANSPORT_TARGETS`
/// at `error`, which replaces what `spec` said of that same target. A directive for a module inside one is more
/// specific and still wins (an operator's explicit choice); `LogCap` bounds what it lets through.
pub fn log_filter(spec: Option<&str>) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    let mut filter = spec.and_then(|s| EnvFilter::try_new(s).ok()).unwrap_or_else(|| EnvFilter::new("info"));
    for target in TRANSPORT_TARGETS {
        if let Ok(d) = format!("{target}=error").parse() {
            filter = filter.add_directive(d);
        }
    }
    filter
}

/// relay.log's cap (F23): the lines of any target but the relay's own, at most `per_min` a minute for each target
/// crate (a target's first path segment, as `TRANSPORT_TARGETS` names them); the excess is not written, only counted
/// (`log_suppressed`). Outside the formatter, so a suppressed line is never formatted.
pub struct LogCap {
    per_min: u32,
    buckets: Mutex<HashMap<&'static str, TokenBucket>>,
    suppressed: AtomicU64,
}

impl LogCap {
    /// `per_min` lines a minute (and a burst of as many) for each target crate.
    pub fn new(per_min: u32) -> LogCap {
        LogCap { per_min, buckets: Mutex::new(HashMap::new()), suppressed: AtomicU64::new(0) }
    }

    /// Whether a line of `target` is written at `now`: always the relay's own (`ai_env_relay`, the library's and the
    /// binary's modules); else one token of its crate's bucket. The map holds one bucket per crate with a callsite in
    /// the binary (targets are static), so it stays small.
    fn admit(&self, target: &'static str, now: Instant) -> bool {
        let krate = target.split("::").next().unwrap_or(target);
        if krate == "ai_env_relay" {
            return true;
        }
        let taken = {
            let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
            buckets.entry(krate).or_insert_with(|| TokenBucket::new(self.per_min, self.per_min, now)).take(now)
        };
        if !taken {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        }
        taken
    }

    /// The lines this cap suppressed.
    pub fn suppressed(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCap {
    fn event_enabled(&self, event: &tracing::Event<'_>, _cx: tracing_subscriber::layer::Context<'_, S>) -> bool {
        self.admit(event.metadata().target(), Instant::now())
    }
}

/// relay.log's subscriber (F23): `log_filter(spec)`, `LogCap::new(per_min)` around the formatter, lines without ANSI
/// to `writer`. `ai-env-relay` installs it with stderr (`main.rs` `logging`); a test with a writer of its own.
pub fn log_subscriber<W>(spec: Option<&str>, per_min: u32, writer: W) -> impl tracing::Subscriber + Send + Sync + 'static
where
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt as _;
    tracing_subscriber::fmt().with_env_filter(log_filter(spec)).with_ansi(false).with_writer(writer).finish().with(LogCap::new(per_min))
}

/// relay.log lines suppressed so far.
pub(crate) fn log_suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn keys(line: &str) -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(line).expect("one JSON object");
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    fn sorted(set: &[&str]) -> Vec<String> {
        let mut k: Vec<String> = set.iter().map(|s| s.to_string()).collect();
        k.sort();
        k
    }

    fn ts_shape(ts: &str) -> bool {
        let b = ts.as_bytes();
        b.len() == 24
            && b.iter().enumerate().all(|(i, c)| match i {
                4 | 7 => *c == b'-',
                10 => *c == b'T',
                13 | 16 => *c == b':',
                19 => *c == b'.',
                23 => *c == b'Z',
                _ => c.is_ascii_digit(),
            })
    }

    /// Unit 48's child: the file to open (unset, the child does nothing).
    const UNIT48_LOG: &str = "RELAY_UNIT48_REQUEST_LOG";

    /// Unit 48 (R-96): `requests.log` is 0640 whatever the umask: a file an older relay left 0600 (the unit's
    /// `UMask=0077`) is made 0640 and appended to, and one created under a 077 umask is 0640 too. The crate forbids
    /// `unsafe`, so the umask is a child's: this test binary again, under a shell that set it, running
    /// [`open_under_its_parents_umask`] alone, whose probe file (0600) proves the umask held there.
    #[test]
    fn the_request_log_is_0640_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).permissions().mode() & 0o777;
        let t = tempfile::tempdir().unwrap();
        let old = t.path().join("old.log");
        std::fs::write(&old, b"{}\n").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
        FileSink::open(&old).unwrap().write_line("{}");
        assert_eq!(mode(&old), 0o640, "an existing 0600 file");
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "{}\n{}\n", "appended to, never truncated");

        let new = t.path().join("requests.log");
        let o = std::process::Command::new("/bin/sh")
            .args(["-c", "umask 077 && exec \"$0\" \"$@\""])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "reqlog::tests::open_under_its_parents_umask", "--ignored", "--test-threads=1"])
            .env(UNIT48_LOG, &new)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(o.status.success(), "the child: {}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert_eq!(mode(&new.with_extension("probe")), 0o600, "the child's umask was 077");
        assert_eq!(mode(&new), 0o640, "created under a 077 umask");
    }

    /// Unit 48's child, run by it alone (under a 077 umask): opens `UNIT48_LOG`'s file, and creates a probe beside it
    /// with std's default mode (0666 less the umask).
    #[test]
    #[ignore = "unit 48's child: the_request_log_is_0640_whatever_the_umask runs it under a 077 umask"]
    fn open_under_its_parents_umask() {
        if let Some(path) = std::env::var_os(UNIT48_LOG) {
            let path = Path::new(&path);
            FileSink::open(path).unwrap();
            std::fs::write(path.with_extension("probe"), b"").unwrap();
        }
    }

    /// Unit 23.
    #[test]
    fn a_line_of_each_kind_has_exactly_its_keys() {
        let sink = Arc::new(MemorySink::default());
        let log = RequestLog::new(sink.clone(), [9; 32], 60);
        let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(1_800_000_000_123);
        log.call(ts, &CallFields::default(), "ok", 0, 1, 1, false, 5);
        log.list(ts, &ListFields::default(), "ok", 0, 1);
        log.tunnel(ts, &TunnelFields { phase: "auth", outcome: "ok", ..TunnelFields::default() });
        log.reload(ts, "workers", "loaded", "0123456789abcdef", 1, 0);
        log.peer(ts, "public", "198.51.100.7", "rate_limited");
        log.status(ts, &StatusLine {
            relay_version: "0.0.0".into(),
            protocol: 1,
            uptime_s: 0,
            tunnels: 0,
            sources_live: 0,
            sources_offline: 0,
            calls_in_flight: 0,
            sessions: 0,
            workers_version: String::new(),
            workers_age_s: 0,
            signers_version: String::new(),
            signers_age_s: 0,
            grants_version: String::new(),
            grants_age_s: 0,
            peers_version: "0123456789abcdef".into(),
            peers_age_s: 7,
            access_version: "fedcba9876543210".into(),
            access_age_s: 9,
            tls_loaded: false,
            client_certs: true,
            unknown_frames: 0,
            log_dropped: 0,
            log_suppressed: 0,
        });
        let lines = sink.lines();
        assert_eq!(lines.len(), 6);
        assert_eq!(STATUS_KEYS.len(), 25, "§RS.3.1: F's log_suppressed, L's peers_version and peers_age_s, T-relay's client_certs; R-146: access_version and access_age_s");
        assert_eq!(STATUS_KEYS[16..20], ["peers_version", "peers_age_s", "access_version", "access_age_s"], "R-146: right after peers_age_s");
        // The peers, access and client_certs keys in their place, each with its own value.
        assert!(
            lines[5].contains(
                r#""grants_age_s":0,"peers_version":"0123456789abcdef","peers_age_s":7,"access_version":"fedcba9876543210","access_age_s":9,"tls_loaded":false,"client_certs":true,"unknown_frames":0"#
            ),
            "{}",
            lines[5]
        );
        let sets: [&[&str]; 6] = [&CALL_KEYS, &LIST_KEYS, &TUNNEL_KEYS, &RELOAD_KEYS, &PEER_KEYS, &STATUS_KEYS];
        for (line, set) in lines.iter().zip(sets) {
            assert_eq!(keys(line), sorted(set), "{line}");
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let ts = v["ts"].as_str().unwrap();
            assert!(ts_shape(ts), "{ts}");
        }
        assert!(lines[0].contains("\"ts\":\"2027-01-15T08:00:00.123Z\""), "{}", lines[0]);
        assert_eq!(params_digest(&[9u8; 32], b"{\"n\":1}"), "adab7941a49a5256");
        assert_eq!(log.digest(b"{\"n\":1}"), "adab7941a49a5256");
    }

    /// Unit 24 (paused).
    #[tokio::test(start_paused = true)]
    async fn refusal_lines_are_limited_with_a_count() {
        let sink = Arc::new(MemorySink::default());
        let log = RequestLog::new(sink.clone(), [9; 32], 60);
        let ts = SystemTime::UNIX_EPOCH;
        for _ in 0..100 {
            log.call(ts, &CallFields::default(), "unauthenticated", 16, 0, 0, false, 0);
        }
        assert_eq!(sink.lines().len(), 60);
        for _ in 0..5 {
            log.call(ts, &CallFields::default(), "ok", 0, 0, 0, false, 0);
        }
        assert_eq!(sink.lines().len(), 65, "ok lines are never limited");
        // R-66's other two kinds, each with its own 60: tunnel lines with outcome `refused`, and peer lines.
        let refused = TunnelFields { phase: "auth", outcome: "refused", reason: "bad_signature", ..TunnelFields::default() };
        for _ in 0..70 {
            log.tunnel(ts, &refused);
            log.peer(ts, "public", "198.51.100.7", "rate_limited");
        }
        log.tunnel(ts, &TunnelFields { phase: "auth", outcome: "ok", ..TunnelFields::default() });
        assert_eq!(sink.lines().len(), 65 + 60 + 60 + 1, "60 of each kind; a tunnel line `ok` is never limited");
        tokio::time::sleep(Duration::from_secs(60)).await;
        log.call(ts, &CallFields::default(), "unauthenticated", 16, 0, 0, false, 0);
        log.tunnel(ts, &refused);
        log.peer(ts, "public", "198.51.100.7", "rate_limited");
        let lines = sink.lines();
        let last: Vec<serde_json::Value> = lines[lines.len() - 3..].iter().map(|l| serde_json::from_str(l).unwrap()).collect();
        let counts: Vec<(&str, u64)> = last.iter().map(|v| (v["ev"].as_str().unwrap(), v["suppressed"].as_u64().unwrap())).collect();
        assert_eq!(counts, [("call", 40), ("tunnel", 10), ("peer", 10)]);
        assert!(lines[..65].iter().all(|l| l.contains("\"suppressed\":0")));
    }

    /// Unit 53 (paused; R-66 amended): `denied` and `too_many` lines share the request lines' budget, call and list alike:
    /// R-135's refusal and a new session past its share come before the session's bucket, so nothing else bounds what a
    /// token holder writes with them. Refusals behind the bucket with other words are not limited.
    #[tokio::test(start_paused = true)]
    async fn a_refusal_before_the_session_bucket_is_limited() {
        for outcome in ["denied", "too_many"] {
            let sink = Arc::new(MemorySink::default());
            let log = RequestLog::new(sink.clone(), [9; 32], 60);
            let ts = SystemTime::UNIX_EPOCH;
            for _ in 0..50 {
                log.call(ts, &CallFields::default(), outcome, 7, 0, 0, false, 0);
                log.list(ts, &ListFields::default(), outcome, 7, 0);
            }
            assert_eq!(sink.lines().len(), 60, "{outcome}: call and list lines take one budget");
            for other in ["not_found", "invalid", "busy", "ok"] {
                log.call(ts, &CallFields::default(), other, 5, 0, 0, false, 0);
            }
            assert_eq!(sink.lines().len(), 64, "{outcome}: these are never limited");
            tokio::time::sleep(Duration::from_secs(60)).await;
            log.call(ts, &CallFields::default(), "unauthenticated", 16, 0, 0, false, 0);
            let lines = sink.lines();
            let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
            assert_eq!((lines.len(), last["suppressed"].as_u64()), (65, Some(40)), "{outcome}: the next written line of the kind carries the count");
        }
    }

    /// Unit 49 (paused; R-66 amended): the peer lines are three kinds, each with its own 60 a minute and its own
    /// count. The public face's allowlist refusals (`no_peers` and `not_in_peers`, one kind) fill their budget and
    /// the next written one carries their count; meanwhile a public `banned` line and private lines (`auth_timeout`,
    /// and the private face's own `not_in_peers`) are written with `suppressed` 0.
    #[tokio::test(start_paused = true)]
    async fn peer_lines_are_limited_per_kind() {
        let sink = Arc::new(MemorySink::default());
        let log = RequestLog::new(sink.clone(), [9; 32], 60);
        let ts = SystemTime::UNIX_EPOCH;
        let lines = || -> Vec<serde_json::Value> { sink.lines().iter().map(|l| serde_json::from_str(l).unwrap()).collect() };
        for _ in 0..100 {
            log.peer(ts, "public", "192.0.2.7", "not_in_peers");
        }
        assert_eq!(lines().len(), 60, "60 of 100 within the minute");
        log.peer(ts, "public", "192.0.2.8", "no_peers");
        assert_eq!(lines().len(), 60, "no_peers shares not_in_peers' budget");
        log.peer(ts, "public", "198.51.100.7", "banned");
        log.peer(ts, "private", "10.42.1.10", "auth_timeout");
        log.peer(ts, "private", "192.0.2.9", "not_in_peers");
        let written = lines();
        assert_eq!(written.len(), 63);
        let last: Vec<(&str, &str, u64)> = written[60..].iter().map(|v| (v["face"].as_str().unwrap(), v["reason"].as_str().unwrap(), v["suppressed"].as_u64().unwrap())).collect();
        assert_eq!(last, [("public", "banned", 0), ("private", "auth_timeout", 0), ("private", "not_in_peers", 0)], "the other kinds' budgets are their own");
        for _ in 0..100 {
            log.peer(ts, "public", "198.51.100.7", "tls_failed");
        }
        assert_eq!(lines().len(), 63 + 59, "the public face's other lines: 60 a minute, `banned` among them");
        tokio::time::sleep(Duration::from_secs(60)).await;
        log.peer(ts, "public", "192.0.2.7", "not_in_peers");
        log.peer(ts, "public", "198.51.100.7", "banned");
        log.peer(ts, "private", "10.42.1.10", "idle");
        let written = lines();
        let next: Vec<(&str, u64)> = written[written.len() - 3..].iter().map(|v| (v["reason"].as_str().unwrap(), v["suppressed"].as_u64().unwrap())).collect();
        assert_eq!(next, [("not_in_peers", 41), ("banned", 41), ("idle", 0)], "each kind's next line carries its own count");
    }

    /// relay.log's lines, as the formatter wrote them (a `MakeWriter` for `log_subscriber`).
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Written {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Written {
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap().lines().map(str::to_string).collect()
        }
    }

    /// F23 (the cap, on explicit instants): the relay's own lines are never capped; any other target crate gets
    /// `per_min` lines a minute, its modules sharing one bucket, each crate its own; the excess is counted.
    #[test]
    fn relay_log_caps_every_target_but_the_relays_own() {
        let cap = LogCap::new(3);
        let t = Instant::now();
        assert!((0..100).all(|_| cap.admit("ai_env_relay::tunnel", t) && cap.admit("ai_env_relay", t)), "the relay's own");
        let h2: Vec<bool> = (0..5).map(|_| cap.admit("h2::proto::ping_pong", t)).collect();
        assert_eq!(h2, [true, true, true, false, false]);
        assert!(!cap.admit("h2::codec::framed_read", t), "one bucket for the crate's modules");
        assert!((0..3).all(|_| cap.admit("hyper_util::server", t)), "another crate, its own bucket");
        assert!((0..3).all(|_| cap.admit("ai_env_relay_proto", t)) && !cap.admit("ai_env_relay_proto::v1", t), "not the relay's own");
        assert_eq!(cap.suppressed(), 4);
        let later = t + std::time::Duration::from_secs(60);
        assert!((0..3).all(|_| cap.admit("h2::proto::ping_pong", later)) && !cap.admit("h2", later), "refilled after a minute");
        assert_eq!(cap.suppressed(), 5);
        assert!(log_suppressed() >= 5, "the status line's count");
    }

    /// F23 (the subscriber `logging()` installs): `RUST_LOG` cannot raise any of `TRANSPORT_TARGETS` above `error`
    /// (each has a `warn` below, hyper-util held by `hyper`'s prefix); a module directive inside one can, and the cap
    /// then holds it to its budget; the relay's own lines all pass.
    #[test]
    fn relay_log_holds_the_transport_crates() {
        assert_eq!(TRANSPORT_TARGETS, ["h2", "hyper", "rustls", "tonic", "tower"], "each crate's warn line below");
        let written = Written::default();
        let w = written.clone();
        let spec = "info,h2=warn,hyper=debug,rustls=warn,tonic=warn,tower=warn";
        tracing::subscriber::with_default(log_subscriber(Some(spec), 2, move || w.clone()), || {
            for _ in 0..10 {
                tracing::warn!(target: "h2::proto::ping_pong", "recv PING ack that we never sent");
                tracing::warn!(target: "hyper::proto", "a transport warning");
                tracing::warn!(target: "hyper_util::server::conn", "a transport warning");
                tracing::warn!(target: "rustls::server", "a transport warning");
                tracing::warn!(target: "tonic::transport", "a transport warning");
                tracing::warn!(target: "tower::buffer", "a transport warning");
                tracing::error!(target: "tonic::transport", "a transport error");
            }
            tracing::info!(target: "ai_env_relay::serve", "the relay's own");
        });
        let lines = written.lines();
        assert!(lines.iter().all(|l| !l.contains("PING") && !l.contains("transport warning")), "every transport crate held at error: {lines:?}");
        assert_eq!(lines.iter().filter(|l| l.contains("a transport error")).count(), 2, "an error line, capped: {lines:?}");
        assert_eq!(lines.iter().filter(|l| l.contains("the relay's own")).count(), 1);
        assert!(lines.iter().all(|l| !l.contains('\u{1b}')), "no ANSI");

        let written = Written::default();
        let w = written.clone();
        tracing::subscriber::with_default(log_subscriber(Some("info,h2::proto=warn"), 2, move || w.clone()), || {
            for _ in 0..10 {
                tracing::warn!(target: "h2::proto::ping_pong", "recv PING ack that we never sent");
            }
        });
        assert_eq!(written.lines().len(), 2, "a module directive wins, and the cap holds it: {:?}", written.lines());
    }
}
