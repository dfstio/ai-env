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
    /// The relay's id (P-R40), `ai-env-relay` by default.
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
    /// R-9: the `Hello` and the `AuthProof`, from `open()`; R-2a: a public connection's first `Open`, from its accept.
    pub handshake_timeout_ms: u32,
    /// R-12: the first `Catalog`, from the `AuthOk`.
    pub catalog_timeout_ms: u32,
    /// R-2: the TLS handshake of an admitted connection.
    pub tls_handshake_timeout_ms: u32,
    /// R-2: the public face's connections.
    pub public_conns_max: u32,
    /// R-2: one peer's live connections on the public face.
    pub public_conns_per_ip: u32,
    /// R-2: one peer's accept bucket on the public face, its burst.
    pub public_accepts_burst: u32,
    /// R-2: the same bucket's refill a minute.
    pub public_accepts_per_min: u32,
    /// R-2: the private face's connections (each at most 16 streams, R-5).
    pub private_conns_max: u32,
    /// R-12: live tunnels.
    pub tunnels_max: u32,
    /// R-38: frames queued toward one worker.
    pub tunnel_queue: u32,
    /// R-38, R-43: an `Invoke` or a later `Cancel` waits this long for the queue; at most half the private face's
    /// request timeout (R-5), so a call's handler always answers before it.
    pub enqueue_timeout_ms: u32,
    /// R-41: a chunk waits this long for room in its caller's buffer.
    pub handoff_timeout_ms: u32,
    /// R-41: one caller's buffer, in chunks.
    pub call_buffer_chunks: u32,
    /// R-29: a `Ping` this often.
    pub ping_interval_ms: u32,
    /// R-29: no inbound frame this long closes the tunnel.
    pub ping_dead_ms: u32,
    /// R-5: the HTTP/2 keepalive interval, 0 for none.
    pub h2_keepalive_s: u32,
    /// R-57: calls in flight in all.
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
    /// R-49: one encoded `ListSources` answer.
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
            tls_handshake_timeout_ms: 10_000,
            public_conns_max: 64,
            public_conns_per_ip: 8,
            public_accepts_burst: 20,
            public_accepts_per_min: 20,
            private_conns_max: 32,
            tunnels_max: 64,
            tunnel_queue: 16,
            enqueue_timeout_ms: 2000,
            handoff_timeout_ms: 2000,
            call_buffer_chunks: 4,
            ping_interval_ms: 15_000,
            ping_dead_ms: 45_000,
            h2_keepalive_s: 15,
            calls_in_flight_max: 128,
            calls_per_tunnel: 32,
            calls_per_session: 8,
            session_burst: 20,
            session_per_min: 120,
            sessions_max: 1024,
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
            list_max_bytes: 4_194_304,
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

impl Limits {
    /// §R-relay.4's ranges, each field on its own, then the ranges that name another field.
    fn validate(&self) -> Result<(), String> {
        let fixed: [(&str, u64, u64, u64); 30] = [
            ("handshake_timeout_ms", self.handshake_timeout_ms.into(), 1000, 30_000),
            ("catalog_timeout_ms", self.catalog_timeout_ms.into(), 1000, 30_000),
            ("tls_handshake_timeout_ms", self.tls_handshake_timeout_ms.into(), 100, 60_000),
            ("public_conns_max", self.public_conns_max.into(), 1, 4096),
            ("public_conns_per_ip", self.public_conns_per_ip.into(), 1, 1024),
            ("public_accepts_burst", self.public_accepts_burst.into(), 1, 1000),
            ("public_accepts_per_min", self.public_accepts_per_min.into(), 1, 6000),
            ("private_conns_max", self.private_conns_max.into(), 1, 4096),
            ("tunnels_max", self.tunnels_max.into(), 1, 1024),
            ("tunnel_queue", self.tunnel_queue.into(), 4, 1024),
            ("enqueue_timeout_ms", self.enqueue_timeout_ms.into(), 100, crate::serve::PRIVATE_REQUEST_TIMEOUT.as_secs() * 1000 / 2),
            ("handoff_timeout_ms", self.handoff_timeout_ms.into(), 100, 30_000),
            ("call_buffer_chunks", self.call_buffer_chunks.into(), 1, 64),
            ("ping_interval_ms", self.ping_interval_ms.into(), 1000, 60_000),
            ("calls_in_flight_max", self.calls_in_flight_max.into(), 1, 4096),
            ("calls_per_tunnel", self.calls_per_tunnel.into(), 1, 1024),
            ("calls_per_session", self.calls_per_session.into(), 1, 1024),
            ("session_burst", self.session_burst.into(), 1, 10_000),
            ("session_per_min", self.session_per_min.into(), 1, 60_000),
            ("sessions_max", self.sessions_max.into(), 1, 65_536),
            ("params_max_bytes", self.params_max_bytes.into(), 1024, 1_048_576),
            ("call_bytes_max", self.call_bytes_max, 1, 268_435_456),
            ("call_rows_max", self.call_rows_max.into(), 1, 10_000_000),
            ("call_chunks_max", self.call_chunks_max.into(), 1, 65_536),
            ("catalog_max_bytes", self.catalog_max_bytes.into(), 4096, 4_194_304),
            ("list_max_bytes", self.list_max_bytes.into(), 65_536, 16_777_216),
            ("files_poll_ms", self.files_poll_ms.into(), 100, 60_000),
            ("max_stale_s", self.max_stale_s.into(), 120, 3600),
            ("status_log_s", self.status_log_s.into(), 10, 3600),
            ("log_refusals_per_min", self.log_refusals_per_min.into(), 1, 6000),
        ];
        let relative: [(&str, u64, u64, u64); 7] = [
            ("ping_dead_ms", self.ping_dead_ms.into(), 2 * u64::from(self.ping_interval_ms), 300_000),
            ("deadline_min_ms", self.deadline_min_ms.into(), 100, self.deadline_max_ms.into()),
            ("deadline_max_ms", self.deadline_max_ms.into(), self.deadline_min_ms.into(), 3_600_000),
            ("deadline_default_ms", self.deadline_default_ms.into(), self.deadline_min_ms.into(), self.deadline_max_ms.into()),
            ("call_bytes_default", self.call_bytes_default, 1, self.call_bytes_max),
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
    }

    /// Unit 28: the faces' defaults, and what a peer with no token or handshake pins with them (R-5, R-2a, R-9 and
    /// §R-relay.4's budget). tonic reserves a request message's announced length at its 5-byte prefix; one DATA frame
    /// past the message doubles that buffer, and the decoded message waits beside it for the stream's end. Private:
    /// 32 connections of 16 streams, each a message of up to `params_max_bytes` + 16 KiB and a 4096-byte header list,
    /// for at most the 10 s request timeout, which a call's one wait (`enqueue_timeout_ms`) stays within half of.
    /// Public: 64 connections of one stream, each a message of up to `catalog_max_bytes` (a `Hello` decoded from one)
    /// and a 16 KiB header list, until its handshake ends. Both at most: about 171 MiB beside the relay's own 128 MiB,
    /// under the unit's `MemoryMax=320M` (Q-R19).
    #[test]
    fn the_private_face_bounds_a_caller_without_a_token() {
        use crate::serve::{PRIVATE_HEADER_LIST, PRIVATE_STREAMS, PUBLIC_HEADER_LIST};
        let l = Limits::default();
        assert_eq!((l.private_conns_max, l.public_conns_max), (32, 64));
        let streams = u64::from(l.private_conns_max) * u64::from(PRIVATE_STREAMS);
        let message = u64::from(l.params_max_bytes) + 16_384;
        assert_eq!(streams * (message + u64::from(PRIVATE_HEADER_LIST)), 44_040_192, "42 MiB for a 5-byte prefix a stream");
        assert_eq!(streams * (2 * (message + 5) + message + u64::from(PRIVATE_HEADER_LIST)), 127_931_392, "122 MiB at most");
        let conns = u64::from(l.public_conns_max);
        let frame = u64::from(l.catalog_max_bytes);
        assert_eq!(conns * (frame + u64::from(PUBLIC_HEADER_LIST)), 17_825_792, "17 MiB for a 5-byte prefix a connection");
        assert_eq!(conns * (2 * (frame + 5) + frame + u64::from(PUBLIC_HEADER_LIST)), 51_380_864, "49 MiB at most");
        assert_eq!(crate::serve::PRIVATE_REQUEST_TIMEOUT, Duration::from_secs(10));
        let mut wait = l.clone();
        wait.enqueue_timeout_ms = 5000;
        assert!(wait.validate().is_ok());
        wait.enqueue_timeout_ms = 5001;
        assert!(wait.validate().unwrap_err().contains("enqueue_timeout_ms"));
    }
}
