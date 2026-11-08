//! `Config`, `Limits`, the env file's parser and checks (§R-relay.3.2, §R-relay.4, D-1 to D-3).
//!
//! The config is the environment systemd builds from I's `/etc/ai-env-relay/relay.env` (`EnvironmentFile=`):
//! five required `AI_ENV_RELAY_*` names and the optional `AI_ENV_RELAY_ID`. The limits are compiled in (D-3):
//! production runs §R-relay.4's defaults, and a test builds `Config` in code.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The public face's address (D-1).
pub const PUBLIC_ADDR: &str = "AI_ENV_RELAY_PUBLIC_ADDR";
/// The private face's address (D-1, D-2).
pub const PRIVATE_ADDR: &str = "AI_ENV_RELAY_PRIVATE_ADDR";
/// The networks the private face admits, comma-separated CIDRs (D-2).
pub const PRIVATE_PEERS: &str = "AI_ENV_RELAY_PRIVATE_PEERS";
/// The live directory (§R-relay.3.5).
pub const LIVE_DIR: &str = "AI_ENV_RELAY_LIVE_DIR";
/// The request log (R-60).
pub const REQUEST_LOG: &str = "AI_ENV_RELAY_REQUEST_LOG";
/// The relay's id, `Challenge.relay_id` (optional).
pub const RELAY_ID: &str = "AI_ENV_RELAY_ID";
/// `AI_ENV_RELAY_ID` when absent.
pub const DEFAULT_RELAY_ID: &str = "ai-env-relay";
/// The default of `ai-env-relay check --env-file`.
pub const DEFAULT_ENV_FILE: &str = "/etc/ai-env-relay/relay.env";

const PREFIX: &str = "AI_ENV_RELAY_";
const KNOWN: [&str; 6] = [PUBLIC_ADDR, PRIVATE_ADDR, PRIVATE_PEERS, LIVE_DIR, REQUEST_LOG, RELAY_ID];
const PEERS_MAX: usize = 8;
const ENV_FILE_MAX: u64 = 65_536;

/// The relay's config.
#[derive(Debug, Clone)]
pub struct Config {
    /// The relay's id (P-R40), `ai-env-relay` by default: the `aud` of the tokens it takes (R-137).
    pub relay_id: String,
    /// The public face's address (443).
    pub public_addr: SocketAddr,
    /// The private face's address (7443).
    pub private_addr: SocketAddr,
    /// The networks the private face admits.
    pub private_peers: Vec<ipnet::IpNet>,
    /// The live directory.
    pub live_dir: PathBuf,
    /// The request log's file.
    pub request_log: PathBuf,
    /// The limits.
    pub limits: Limits,
}

/// §R-relay.4's table: every field, its default (`Default`), its range (`validate`). Times are in the unit
/// their name ends with; the rule each binds is §R-relay.4's.
#[derive(Debug, Clone)]
pub struct Limits {
    /// R-2a and R-9, one budget from a public connection's TLS accept (F24): its first `Open`, then the `Hello` and
    /// the `AuthProof`.
    pub handshake_timeout_ms: u32,
    /// R-12: the first `Catalog`, from the `AuthOk`.
    pub catalog_timeout_ms: u32,
    /// R-2: the TLS handshake of an admitted connection (two round trips; a worker's own connect budget is 10 s).
    pub tls_handshake_timeout_ms: u32,
    /// R-2: the public face's connections.
    pub public_conns_max: u32,
    /// R-2: one peer's live connections on the public face.
    pub public_conns_per_ip: u32,
    /// R-2: one peer's accept bucket on the public face, its burst.
    pub public_accepts_burst: u32,
    /// R-2: the same bucket's refill a minute.
    pub public_accepts_per_min: u32,
    /// R-98, R-101: faults of one public peer within `ban_window_s` that ban it.
    pub ban_faults: u32,
    /// R-98: the window `ban_faults` are counted in, from its first fault.
    pub ban_window_s: u32,
    /// R-98: a ban's length.
    pub ban_s: u32,
    /// R-2: the private face's connections (each at most 16 streams, R-5).
    pub private_conns_max: u32,
    /// R-104: the private face's one accept bucket, its burst.
    pub private_accepts_burst: u32,
    /// R-104: the same bucket's refill a minute.
    pub private_accepts_per_min: u32,
    /// R-103: a private connection with no request pending is cut this long after its last request.
    pub private_idle_s: u32,
    /// R-105: refused tokens on one private connection that fault it.
    pub private_faults_max: u32,
    /// R-12: live tunnels.
    pub tunnels_max: u32,
    /// R-38: frames queued toward one worker.
    pub tunnel_queue: u32,
    /// R-107: inbound frames of one tunnel a minute from its AuthOk, its burst the same; a live call's chunks take no
    /// token (LD-R53).
    pub tunnel_frames_per_min: u32,
    /// R-107: inbound bytes of one tunnel's connection a minute from its AuthOk (every HTTP/2 frame), its burst the
    /// same; at least `call_bytes_max`; a live call's chunks' decoded lengths go back (LD-R53).
    pub tunnel_bytes_per_min: u32,
    /// R-38, R-43: an `Invoke` or a later `Cancel` waits this long for the queue; at most half the private face's
    /// request timeout (R-5), so a call's handler always answers before it.
    pub enqueue_timeout_ms: u32,
    /// R-41, R-111: one caller's buffer, in chunks; a chunk that finds it full after one yield evicts the call.
    pub call_buffer_chunks: u32,
    /// R-29: a `Ping` this often.
    pub ping_interval_ms: u32,
    /// R-29: no inbound frame this long closes the tunnel.
    pub ping_dead_ms: u32,
    /// R-5: the HTTP/2 keepalive interval, 0 for none.
    pub h2_keepalive_s: u32,
    /// R-57, R-106: calls in flight in all, each holding its relay permit until hyper drops its stream.
    pub calls_in_flight_max: u32,
    /// R-57: calls in flight on one tunnel.
    pub calls_per_tunnel: u32,
    /// R-57: calls in flight of one session.
    pub calls_per_session: u32,
    /// R-57: one session's bucket, its burst.
    pub session_burst: u32,
    /// R-57: the same bucket's refill a minute.
    pub session_per_min: u32,
    /// R-57: sessions.
    pub sessions_max: u32,
    /// R-136: the sessions of one token signer, so one key cannot fill `sessions_max`.
    pub sessions_per_signer: u32,
    /// R-112: a session's charged evictions in its 600 s window that refuse its new calls.
    pub session_evictions_per_10min: u32,
    /// R-34: `params_json`.
    pub params_max_bytes: u32,
    /// R-36: `deadline_ms` 0 means this.
    pub deadline_default_ms: u32,
    /// R-36: the shortest deadline.
    pub deadline_min_ms: u32,
    /// R-36: the longest deadline.
    pub deadline_max_ms: u32,
    /// R-35: a call's bytes when nothing asks for fewer.
    pub call_bytes_default: u64,
    /// R-35: no call gets more bytes.
    pub call_bytes_max: u64,
    /// R-35: a call's rows when nothing asks for fewer.
    pub call_rows_default: u32,
    /// R-35: no call gets more rows.
    pub call_rows_max: u32,
    /// R-35: a call's chunks when nothing asks for fewer.
    pub call_chunks_default: u32,
    /// R-35: no call gets more chunks.
    pub call_chunks_max: u32,
    /// R-5, R-21: one decoded `WorkerFrame`, the catalog's included (`wire::FRAME_MAX`, A-M2).
    pub catalog_max_bytes: u32,
    /// R-49: one encoded `ListSources` answer; at most LD-R50's 496 KiB a stream, since hyper may park it unread (unit 28).
    pub list_max_bytes: u32,
    /// R-15: the live files are polled this often.
    pub files_poll_ms: u32,
    /// R-17: a JSON list older than this fails closed.
    pub max_stale_s: u32,
    /// R-67: one status line this often.
    pub status_log_s: u32,
    /// R-66: refusal lines of one kind a minute.
    pub log_refusals_per_min: u32,
}

impl Default for Limits {
    /// §R-relay.4's defaults.
    fn default() -> Self {
        Limits {
            handshake_timeout_ms: 5000,
            catalog_timeout_ms: 5000,
            tls_handshake_timeout_ms: 3000,
            public_conns_max: 64,
            public_conns_per_ip: 8,
            public_accepts_burst: 20,
            public_accepts_per_min: 20,
            ban_faults: 20,
            ban_window_s: 600,
            ban_s: 900,
            private_conns_max: 32,
            private_accepts_burst: 64,
            private_accepts_per_min: 120,
            private_idle_s: 600,
            private_faults_max: 8,
            tunnels_max: 64,
            tunnel_queue: 16,
            tunnel_frames_per_min: 600,
            tunnel_bytes_per_min: 33_554_432,
            enqueue_timeout_ms: 2000,
            call_buffer_chunks: 4,
            ping_interval_ms: 15_000,
            ping_dead_ms: 45_000,
            h2_keepalive_s: 15,
            calls_in_flight_max: 100,
            calls_per_tunnel: 32,
            calls_per_session: 8,
            session_burst: 20,
            session_per_min: 120,
            sessions_max: 1024,
            sessions_per_signer: 256,
            session_evictions_per_10min: 3,
            params_max_bytes: 65_536,
            deadline_default_ms: 30_000,
            deadline_min_ms: 1000,
            deadline_max_ms: 600_000,
            call_bytes_default: 1_048_576,
            call_bytes_max: 16_777_216,
            call_rows_default: 1000,
            call_rows_max: 100_000,
            call_chunks_default: 16,
            call_chunks_max: 256,
            catalog_max_bytes: ai_env_source::wire::FRAME_MAX as u32,
            list_max_bytes: 507_904,
            files_poll_ms: 5000,
            max_stale_s: 900,
            status_log_s: 300,
            log_refusals_per_min: 60,
        }
    }
}

/// Milliseconds of a limit as a `Duration`.
pub(crate) fn ms(v: u32) -> Duration {
    Duration::from_millis(u64::from(v))
}

/// F28: a face's HTTP/2 windows exceed its largest message by this much.
pub(crate) const WINDOW_SLACK: u32 = 16_384;

impl Limits {
    /// F28: the public face's HTTP/2 windows, each connection's and each stream's: its largest message
    /// (`catalog_max_bytes`, R-5) and 16 KiB.
    pub(crate) fn public_window(&self) -> u32 {
        self.catalog_max_bytes.saturating_add(WINDOW_SLACK)
    }

    /// R-5: the private face's largest message, its decode cap: `params_max_bytes` and 16 KiB.
    pub(crate) fn private_message_max(&self) -> u32 {
        self.params_max_bytes.saturating_add(16_384)
    }

    /// F28: the private face's: its largest message (`private_message_max`) and 16 KiB, so a request of the decode
    /// cap and its 5-byte prefix fits one window, as on the public face.
    pub(crate) fn private_window(&self) -> u32 {
        self.private_message_max().saturating_add(WINDOW_SLACK)
    }
}

impl Limits {
    /// §R-relay.4's ranges, each field on its own, then the ranges that name another field.
    fn validate(&self) -> Result<(), String> {
        let fixed: [(&str, u64, u64, u64); 38] = [
            ("handshake_timeout_ms", self.handshake_timeout_ms.into(), 1000, 30_000),
            ("catalog_timeout_ms", self.catalog_timeout_ms.into(), 1000, 30_000),
            ("tls_handshake_timeout_ms", self.tls_handshake_timeout_ms.into(), 100, 60_000),
            ("public_conns_max", self.public_conns_max.into(), 1, 4096),
            ("public_conns_per_ip", self.public_conns_per_ip.into(), 1, 1024),
            ("public_accepts_burst", self.public_accepts_burst.into(), 1, 1000),
            ("public_accepts_per_min", self.public_accepts_per_min.into(), 1, 6000),
            ("ban_faults", self.ban_faults.into(), 1, 1000),
            ("ban_window_s", self.ban_window_s.into(), 10, 3600),
            ("ban_s", self.ban_s.into(), 60, 86_400),
            ("private_conns_max", self.private_conns_max.into(), 1, 4096),
            ("private_accepts_burst", self.private_accepts_burst.into(), 1, 1000),
            ("private_accepts_per_min", self.private_accepts_per_min.into(), 1, 6000),
            ("private_idle_s", self.private_idle_s.into(), 60, 3600),
            ("private_faults_max", self.private_faults_max.into(), 1, 1000),
            ("tunnels_max", self.tunnels_max.into(), 1, 1024),
            ("tunnel_queue", self.tunnel_queue.into(), 4, 1024),
            ("tunnel_frames_per_min", self.tunnel_frames_per_min.into(), 60, 60_000),
            ("enqueue_timeout_ms", self.enqueue_timeout_ms.into(), 100, crate::serve::PRIVATE_REQUEST_TIMEOUT.as_secs() * 1000 / 2),
            ("call_buffer_chunks", self.call_buffer_chunks.into(), 1, 64),
            ("ping_interval_ms", self.ping_interval_ms.into(), 1000, 60_000),
            ("calls_in_flight_max", self.calls_in_flight_max.into(), 1, 4096),
            ("calls_per_tunnel", self.calls_per_tunnel.into(), 1, 1024),
            ("calls_per_session", self.calls_per_session.into(), 1, 1024),
            ("session_burst", self.session_burst.into(), 1, 10_000),
            ("session_per_min", self.session_per_min.into(), 1, 60_000),
            ("sessions_max", self.sessions_max.into(), 1, 65_536),
            ("session_evictions_per_10min", self.session_evictions_per_10min.into(), 1, 1000),
            ("params_max_bytes", self.params_max_bytes.into(), 1024, 1_048_576),
            ("call_bytes_max", self.call_bytes_max, 1, 268_435_456),
            ("call_rows_max", self.call_rows_max.into(), 1, 10_000_000),
            ("call_chunks_max", self.call_chunks_max.into(), 1, 65_536),
            ("catalog_max_bytes", self.catalog_max_bytes.into(), 4096, 4_194_304),
            ("list_max_bytes", self.list_max_bytes.into(), 65_536, 507_904),
            ("files_poll_ms", self.files_poll_ms.into(), 100, 60_000),
            ("max_stale_s", self.max_stale_s.into(), 120, 3600),
            ("status_log_s", self.status_log_s.into(), 10, 3600),
            ("log_refusals_per_min", self.log_refusals_per_min.into(), 1, 6000),
        ];
        let relative: [(&str, u64, u64, u64); 9] = [
            ("ping_dead_ms", self.ping_dead_ms.into(), 2 * u64::from(self.ping_interval_ms), 300_000),
            ("deadline_min_ms", self.deadline_min_ms.into(), 100, self.deadline_max_ms.into()),
            ("deadline_max_ms", self.deadline_max_ms.into(), self.deadline_min_ms.into(), 3_600_000),
            ("deadline_default_ms", self.deadline_default_ms.into(), self.deadline_min_ms.into(), self.deadline_max_ms.into()),
            ("call_bytes_default", self.call_bytes_default, 1, self.call_bytes_max),
            // R-107: one permitted call within a minute never closes its tunnel (Q-R20), and the bucket holds the
            // largest frame.
            ("tunnel_bytes_per_min", self.tunnel_bytes_per_min.into(), self.call_bytes_max, 1_073_741_824),
            ("sessions_per_signer", self.sessions_per_signer.into(), 1, self.sessions_max.into()),
            ("call_rows_default", self.call_rows_default.into(), 1, self.call_rows_max.into()),
            ("call_chunks_default", self.call_chunks_default.into(), 1, self.call_chunks_max.into()),
        ];
        for (name, v, lo, hi) in fixed.into_iter().chain(relative) {
            if v < lo || v > hi {
                return Err(format!("limits: {name} {v} is outside {lo} to {hi}"));
            }
        }
        let ka = self.h2_keepalive_s;
        if ka != 0 && !(5..=300).contains(&ka) {
            return Err(format!("limits: h2_keepalive_s {ka} is neither 0 nor 5 to 300"));
        }
        Ok(())
    }
}

impl Config {
    /// The `AI_ENV_RELAY_*` names of §R-relay.3.2 from (name, value) pairs: the process environment for `run`
    /// (systemd's `EnvironmentFile=`), an env file's lines for `check`. Other names are skipped; an unknown
    /// `AI_ENV_RELAY_*` name gives one warning (D-1 to D-3).
    pub fn from_vars(vars: impl IntoIterator<Item = (String, String)>) -> Result<(Config, Vec<String>), String> {
        let mut warnings = Vec::new();
        let mut got: BTreeMap<&'static str, String> = BTreeMap::new();
        for (name, value) in vars {
            if !name.starts_with(PREFIX) {
                continue;
            }
            match KNOWN.iter().find(|k| **k == name) {
                Some(k) => {
                    if got.insert(k, value).is_some() {
                        return Err(format!("{name} is given twice"));
                    }
                }
                // D-1: a newer user data never stops an older binary.
                None => warnings.push(format!("{name} is not a name this relay knows; ignored")),
            }
        }
        let need = |k: &'static str| got.get(k).map(String::as_str).ok_or_else(|| format!("{k} is missing"));
        let addr = |k: &'static str| -> Result<SocketAddr, String> {
            let v = need(k)?;
            v.parse().map_err(|_| format!("{k}: {v:?} is not an address and port"))
        };
        let path = |k: &'static str| -> Result<PathBuf, String> {
            let v = PathBuf::from(need(k)?);
            if v.is_absolute() {
                Ok(v)
            } else {
                Err(format!("{k}: {} is not an absolute path", v.display()))
            }
        };
        let public_addr = addr(PUBLIC_ADDR)?;
        let private_addr = addr(PRIVATE_ADDR)?;
        let private_peers = parse_peers(need(PRIVATE_PEERS)?)?;
        let live_dir = path(LIVE_DIR)?;
        let request_log = path(REQUEST_LOG)?;
        let relay_id = got.get(RELAY_ID).cloned().unwrap_or_else(|| DEFAULT_RELAY_ID.to_string());
        let cfg = Config { relay_id, public_addr, private_addr, private_peers, live_dir, request_log, limits: Limits::default() };
        cfg.validate()?;
        Ok((cfg, warnings))
    }

    /// KEY=VALUE lines, `#` comments and blank lines (systemd's EnvironmentFile syntax, values unquoted).
    pub fn read_env_file(path: &Path) -> Result<Vec<(String, String)>, String> {
        let shown = path.display();
        let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
        if meta.len() > ENV_FILE_MAX {
            return Err(format!("{shown}: over {ENV_FILE_MAX} bytes"));
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.strip_prefix("export").is_some_and(|rest| rest.starts_with(char::is_whitespace)) {
                return Err(format!("{shown}:{n}: `export` is not EnvironmentFile syntax"));
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("{shown}:{n}: not KEY=VALUE"));
            };
            let (key, value) = (key.trim(), value.trim());
            let name_ok = key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !name_ok {
                return Err(format!("{shown}:{n}: {key:?} is not a variable name"));
            }
            if value.starts_with('"') || value.starts_with('\'') {
                return Err(format!("{shown}:{n}: {key} has a quoted value (values are unquoted)"));
            }
            if !seen.insert(key.to_string()) {
                return Err(format!("{shown}:{n}: {key} is given twice"));
            }
            out.push((key.to_string(), value.to_string()));
        }
        Ok(out)
    }

    /// §R-relay.4's ranges, and D-2's shapes for a config built in code.
    pub fn validate(&self) -> Result<(), String> {
        if !ai_env_worker::globs::valid_id(&self.relay_id) {
            return Err(format!("{RELAY_ID}: {:?} is not an id ({})", self.relay_id, ai_env_source::names::NAME_RULE));
        }
        if self.private_addr.ip().is_unspecified() {
            return Err(format!("{PRIVATE_ADDR}: {} binds every address; the private face binds the private IP only", self.private_addr));
        }
        if self.private_peers.is_empty() || self.private_peers.len() > PEERS_MAX {
            return Err(format!("{PRIVATE_PEERS}: 1 to {PEERS_MAX} networks, not {}", self.private_peers.len()));
        }
        for (k, p) in [(LIVE_DIR, &self.live_dir), (REQUEST_LOG, &self.request_log)] {
            if !p.is_absolute() {
                return Err(format!("{k}: {} is not an absolute path", p.display()));
            }
        }
        self.limits.validate()
    }
}

/// D-2: 1 to 8 comma-separated CIDRs.
fn parse_peers(v: &str) -> Result<Vec<ipnet::IpNet>, String> {
    let parts: Vec<&str> = v.split(',').map(str::trim).collect();
    if parts.is_empty() || parts.len() > PEERS_MAX || parts.iter().any(|p| p.is_empty()) {
        return Err(format!("{PRIVATE_PEERS}: 1 to {PEERS_MAX} comma-separated networks"));
    }
    parts
        .into_iter()
        .map(|p| p.parse::<ipnet::IpNet>().map(|n| n.trunc()).map_err(|_| format!("{PRIVATE_PEERS}: {p:?} is not a network (a.b.c.d/n)")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Vec<(String, String)> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/relay.env.example");
        Config::read_env_file(&path).expect("the example reads")
    }

    fn with(mut vars: Vec<(String, String)>, name: &str, value: Option<&str>) -> Vec<(String, String)> {
        vars.retain(|(k, _)| k != name);
        if let Some(v) = value {
            vars.push((name.to_string(), v.to_string()));
        }
        vars
    }

    /// Unit 26.
    #[test]
    fn the_env_example_loads_and_refuses() {
        let (cfg, warnings) = Config::from_vars(example()).expect("the example loads");
        assert_eq!(cfg.public_addr, "0.0.0.0:443".parse().unwrap());
        assert_eq!(cfg.private_addr, "10.42.0.20:7443".parse().unwrap());
        assert_eq!(cfg.private_peers, vec!["10.42.1.0/24".parse::<ipnet::IpNet>().unwrap()]);
        assert_eq!(cfg.live_dir, PathBuf::from("/var/lib/ai-env-relay/live"));
        assert_eq!(cfg.request_log, PathBuf::from("/var/log/ai-env-relay/requests/requests.log"));
        assert_eq!(cfg.relay_id, "ai-env-relay");
        assert_eq!(format!("{:?}", cfg.limits), format!("{:?}", Limits::default()), "every limit at its default");
        assert!(warnings.is_empty(), "{warnings:?}");

        let mut more = example();
        more.push(("AI_ENV_RELAY_X".into(), "1".into()));
        more.push(("PATH".into(), "/bin".into()));
        let (again, warnings) = Config::from_vars(more).expect("an unknown name never stops the relay");
        assert_eq!(format!("{again:?}"), format!("{cfg:?}"));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("AI_ENV_RELAY_X"), "{warnings:?}");

        let refused = [
            with(example(), LIVE_DIR, None),
            with(example(), PRIVATE_PEERS, None),
            with(example(), PRIVATE_ADDR, Some("0.0.0.0:7443")),
            with(example(), PRIVATE_PEERS, Some("10.42.1.0/33")),
            with(example(), PRIVATE_PEERS, Some(&(1..=9).map(|i| format!("10.42.{i}.0/24")).collect::<Vec<_>>().join(","))),
            with(example(), REQUEST_LOG, Some("requests.log")),
            with(example(), RELAY_ID, Some("Bad")),
        ];
        for vars in refused {
            assert!(Config::from_vars(vars.clone()).is_err(), "{vars:?} must be refused");
        }

        let dir = tempfile::tempdir().unwrap();
        for (i, body) in ["AI_ENV_RELAY_ID=\"quoted\"\n", "export AI_ENV_RELAY_ID=x\n", "AI_ENV_RELAY_ID=a\nAI_ENV_RELAY_ID=b\n"].iter().enumerate() {
            let p = dir.path().join(format!("{i}.env"));
            std::fs::write(&p, body).unwrap();
            assert!(Config::read_env_file(&p).is_err(), "{body:?} must be refused");
        }

        let mut stale = cfg.clone();
        stale.limits.max_stale_s = 60;
        assert!(stale.validate().unwrap_err().contains("max_stale_s"));
        let mut deadlines = cfg.clone();
        deadlines.limits.deadline_min_ms = deadlines.limits.deadline_default_ms + 1;
        assert!(deadlines.validate().is_err());
        assert!(cfg.validate().is_ok());

        // §RS.2's new limits (R-98 to R-112): each taken at both ends of its range and refused one past either.
        type Field = fn(&mut Limits) -> &mut u32;
        let ranges: [(&str, Field, u32, u32, u32); 11] = [
            ("ban_faults", |l| &mut l.ban_faults, 20, 1, 1000),
            ("ban_window_s", |l| &mut l.ban_window_s, 600, 10, 3600),
            ("ban_s", |l| &mut l.ban_s, 900, 60, 86_400),
            ("private_idle_s", |l| &mut l.private_idle_s, 600, 60, 3600),
            ("private_accepts_burst", |l| &mut l.private_accepts_burst, 64, 1, 1000),
            ("private_accepts_per_min", |l| &mut l.private_accepts_per_min, 120, 1, 6000),
            ("private_faults_max", |l| &mut l.private_faults_max, 8, 1, 1000),
            ("tunnel_frames_per_min", |l| &mut l.tunnel_frames_per_min, 600, 60, 60_000),
            ("tunnel_bytes_per_min", |l| &mut l.tunnel_bytes_per_min, 33_554_432, 16_777_216, 1_073_741_824),
            ("session_evictions_per_10min", |l| &mut l.session_evictions_per_10min, 3, 1, 1000),
            // R-136's ceiling is `sessions_max`, 1024 here.
            ("sessions_per_signer", |l| &mut l.sessions_per_signer, 256, 1, 1024),
        ];
        for (name, field, default, lo, hi) in ranges {
            assert_eq!(*field(&mut Limits::default()), default, "{name}'s default");
            for (v, taken) in [(lo - 1, false), (lo, true), (hi, true), (hi + 1, false)] {
                let mut c = cfg.clone();
                *field(&mut c.limits) = v;
                match c.validate() {
                    Ok(()) => assert!(taken, "{name} {v} must be refused"),
                    Err(e) => assert!(!taken && e.contains(name), "{name} {v}: {e}"),
                }
            }
        }
        // R-136's ceiling follows `sessions_max`.
        let mut share = cfg.clone();
        (share.limits.sessions_max, share.limits.sessions_per_signer) = (8, 8);
        assert!(share.validate().is_ok());
        share.limits.sessions_max = 7;
        assert!(share.validate().unwrap_err().contains("sessions_per_signer"));
        // The bytes floor is `call_bytes_max` (Q-R20): one permitted call within a minute never closes its tunnel.
        let mut floor = cfg.clone();
        (floor.limits.call_bytes_max, floor.limits.call_bytes_default, floor.limits.tunnel_bytes_per_min) = (1 << 20, 1 << 20, 1 << 20);
        assert!(floor.validate().is_ok());
        floor.limits.tunnel_bytes_per_min -= 1;
        assert!(floor.validate().unwrap_err().contains("tunnel_bytes_per_min"));
        // `calls_in_flight_max` 100 (unit 28's budget, R-106); `handoff_timeout_ms` is gone (R-111: the hand-off never
        // waits), `call_buffer_chunks` stays the eviction threshold.
        assert_eq!((Limits::default().calls_in_flight_max, Limits::default().call_buffer_chunks), (100, 4));
        assert!(!format!("{:?}", Limits::default()).contains("handoff"));
    }

    /// Unit 28: the faces' defaults, and what a peer with no token or handshake pins with them (R-5, R-2a, R-9 and
    /// §R-relay.4's budget). tonic reserves a request message's announced length at its 5-byte prefix; one DATA frame
    /// past the message doubles that buffer, and the decoded message waits beside it for the stream's end; and each
    /// connection parks at most its HTTP/2 flow-control window of DATA unread, its streams' windows within it (F28:
    /// the face's largest message and 16 KiB). Private: 32 connections of 16 streams, each a message of up to
    /// `params_max_bytes` + 16 KiB and a 4096-byte header list, for at most the 10 s request timeout, which a call's
    /// one wait (`enqueue_timeout_ms`) stays within half of. Public: 64 connections of one stream, each a message of
    /// up to `catalog_max_bytes` (a `Hello` decoded from one) and a 16 KiB header list, until its handshake ends, at
    /// most 3 + 5 + 1 s from its accept (F24). Both at most: about 191 MiB beside the relay's own 127 MiB (§RS.2: its
    /// queues, `calls_in_flight_max` calls of five chunks each, its catalogs), about 1.7 MiB under the unit's
    /// `MemoryMax=320M` (Q-R19). hyper and h2 hold part of a stream's answer too: the frame hyper took (up to 96 KiB:
    /// tonic packs chunks up to 32 KiB) and h2's unsent tail, up to the client's window and at most its 400 KiB send
    /// buffer. They come after the stream's request buffers went, so the stream's share above (about 244 KiB) holds
    /// them for a client that reads and grants little. One that stops reading passes that share until the keepalive
    /// cuts it, about 25 s later: R-57 records that transient, about 125 MiB over the sum at worst (LD-R50). A
    /// `ListSources` answer holds no permit and no mark (R-32), so hyper parks it for a client that grants no window until
    /// the connection's idle cut, renewably: `list_max_bytes` holds it to that same 496 KiB a stream, the same 125 MiB
    /// over the sum. Before its `AuthOk` a public connection's read budget is `2 * public_window()` of decrypted bytes,
    /// with about 9 KiB a second of refill (LD-R60): two frames of `catalog_max_bytes`, a header list and their framing,
    /// the most a handshake takes. None of these, and none of R-108's eight remembered Pings (about 64 bytes a tunnel),
    /// adds a term.
    #[test]
    fn the_private_face_bounds_a_caller_without_a_token() {
        use crate::serve::{PRIVATE_HEADER_LIST, PRIVATE_STREAMS, PUBLIC_HEADER_LIST};
        let l = Limits::default();
        assert_eq!((l.private_conns_max, l.public_conns_max), (32, 64));
        assert_eq!((l.tls_handshake_timeout_ms, l.handshake_timeout_ms), (3000, 5000), "F24: 3 s of TLS, then one 5 s budget from the accept");
        assert_eq!(crate::serve::TUNNEL_END_GRACE, Duration::from_secs(1), "R-81: an unauthenticated slot lives 3 + 5 + 1 = 9 s at most");
        let streams = u64::from(l.private_conns_max) * u64::from(PRIVATE_STREAMS);
        let message = u64::from(l.params_max_bytes) + 16_384;
        assert_eq!(u64::from(l.private_message_max()), message, "R-5's decode cap");
        assert_eq!(streams * (message + u64::from(PRIVATE_HEADER_LIST)), 44_040_192, "42 MiB for a 5-byte prefix a stream");
        assert_eq!(streams * (2 * (message + 5) + message + u64::from(PRIVATE_HEADER_LIST)), 127_931_392, "122 MiB at most");
        assert_eq!(l.private_window(), 98_304, "the private face's windows: its decode cap and 16 KiB");
        let private_windows = u64::from(l.private_conns_max) * u64::from(l.private_window());
        assert_eq!(private_windows, 3_145_728, "3 MiB parked in the private face's windows");
        let private = streams * (2 * (message + 5) + message + u64::from(PRIVATE_HEADER_LIST)) + private_windows;
        assert_eq!(private, 131_077_120, "125 MiB at most with the windows");
        let conns = u64::from(l.public_conns_max);
        let frame = u64::from(l.catalog_max_bytes);
        assert_eq!(conns * (frame + u64::from(PUBLIC_HEADER_LIST)), 17_825_792, "17 MiB for a 5-byte prefix a connection");
        assert_eq!(conns * (2 * (frame + 5) + frame + u64::from(PUBLIC_HEADER_LIST)), 51_380_864, "49 MiB at most");
        assert_eq!(l.public_window(), 278_528, "the public face's windows: catalog_max_bytes and 16 KiB");
        let public_windows = conns * u64::from(l.public_window());
        assert_eq!(public_windows, 17_825_792, "17 MiB parked in the public face's windows (64 MiB at 1 MiB each)");
        assert_eq!(2 * l.public_window(), 557_056, "LD-R60: a public connection's read budget before its AuthOk, its burst");
        assert!(2 * frame + u64::from(PUBLIC_HEADER_LIST) + 16_384 <= 2 * u64::from(l.public_window()), "two frames of the decode cap, a header list and their framing fit it");
        let public = conns * (2 * (frame + 5) + frame + u64::from(PUBLIC_HEADER_LIST)) + public_windows;
        assert_eq!(public, 69_206_656, "66 MiB at most with the windows");
        // The relay's own buffers (§RS.2): 64 tunnels of 16 queued frames, each up to an Invoke of `params_max_bytes`
        // and its envelope (80 KiB); `calls_in_flight_max` calls of five chunks of 64 KiB each (four buffered and R-42's
        // kept last), bounded because a call's relay permit stays with its stream until hyper drops the stream, and
        // R-103's undrained cut drops it 10 s after its call ended (R-106); 64 catalogs of 256 KiB.
        assert_eq!(l.calls_in_flight_max, 100, "R-106: the permit outlives the call until its stream is dropped");
        let queued = u64::from(l.tunnels_max) * u64::from(l.tunnel_queue) * (u64::from(l.params_max_bytes) + 16_384);
        let calls = u64::from(l.calls_in_flight_max) * (u64::from(l.call_buffer_chunks) + 1) * crate::calls::CHUNK_MAX as u64;
        let catalogs = u64::from(l.tunnels_max) * u64::from(l.catalog_max_bytes);
        assert_eq!((queued, calls, catalogs), (83_886_080, 32_768_000, 16_777_216));
        let own = queued + calls + catalogs;
        assert_eq!(own, 133_431_296, "127 MiB of the relay's own");
        assert_eq!(private + public, 200_283_776, "191 MiB beside it");
        let all = private + public + own;
        assert_eq!(all, 333_715_072, "318.3 MiB in all");
        assert!(all <= 320 * 1_048_576, "under MemoryMax=320M");
        // The process's baseline (binary, allocator, runtime, lists) is not counted: a later budget re-sums here.
        assert_eq!(320 * 1_048_576 - all, 1_829_248, "about 1.7 MiB of headroom left");
        // A list's parked frame (R-49), a stream's share of LD-R50's residual, and the range stops there.
        assert!(l.list_max_bytes <= 496 * 1024, "{}", l.list_max_bytes);
        assert_eq!(l.list_max_bytes, 507_904);
        let mut over = Config::from_vars(example()).expect("the example loads").0;
        over.limits.list_max_bytes = 507_905;
        assert!(over.validate().unwrap_err().contains("list_max_bytes"));
        assert_eq!(crate::serve::PRIVATE_REQUEST_TIMEOUT, Duration::from_secs(10));
        let mut wait = l.clone();
        wait.enqueue_timeout_ms = 5000;
        assert!(wait.validate().is_ok());
        wait.enqueue_timeout_ms = 5001;
        assert!(wait.validate().unwrap_err().contains("enqueue_timeout_ms"));
    }
}
