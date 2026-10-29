//! The relay's private face (V-R20 to V-R25). The dial is this module's alone (`make lint`): TCP to the session's
//! address (no proxy, no environment read), TLS 1.3 under [`crate::tls::client_config`] with the session's server
//! name, ALPN `h2` required, each step bounded; a tonic `Channel` over that connector, built lazily at the first call
//! and dropped after [`CHANNEL_IDLE`] without one, so a VM that slept dials anew (LD-V9). Every RPC carries the
//! session token in [`SESSION_HEADER`] and nothing else of the session (V-R21). No automatic retry.
use crate::convert::{failure_of_chunk, failure_of_status, request_id_of, source_entry};
use crate::local::{Answer, Code, SourceEntry, CATALOG_MAX, DEADLINE_CAP_MS, LOCAL_V, MAX_BYTES_CAP, PARAMS_MAX};
use crate::session::Session;
use ai_env_relay_proto::v1;
use ai_env_relay_proto::v1::relay_client::RelayClient;
use rustls::pki_types::ServerName;
use std::future::Future;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint};

/// The session token's metadata key (the proto's, `relay.proto:20-21`).
pub const SESSION_HEADER: &str = "x-ai-env-session";
/// The relay's request id's metadata key (R-30: a refusal's status and a call stream's initial metadata carry it).
pub(crate) const REQUEST_ID_HEADER: &str = "x-ai-env-request-id";
/// TCP connect to the relay's address.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The TLS handshake after it.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// HTTP/2 keepalive pings while the channel lives, idle or not ...
pub const KEEPALIVE: Duration = Duration::from_secs(20);
/// ... each answered within this, or the connection is dropped.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// The channel is dropped after this long without a call (the binary's hidden `--channel-idle-ms`).
pub const CHANNEL_IDLE: Duration = Duration::from_secs(60);
/// `ListSources`' ceiling.
pub const CATALOG_CEILING: Duration = Duration::from_secs(30);

/// A failed catalog or call: its local code, a message that holds no session value, and the relay's request id once
/// the relay named the call (a refusal's status, an in-band error chunk, else the call stream's initial metadata, which
/// also names the client's own failures after it: a bad `seq`, a stream without `final`, the local ceiling, a cancel);
/// `None` when it never did (a failed dial, the client's own refusals, any failure before that metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: Code,
    pub message: String,
    pub request_id: Option<String>,
}

impl Failure {
    /// A failure the relay did not name.
    pub(crate) fn new(code: Code, message: impl Into<String>) -> Failure {
        Failure { code, message: message.into(), request_id: None }
    }

    /// The same failure, named `id` when it has no request id of its own.
    fn or_request_id(mut self, id: Option<String>) -> Failure {
        if self.request_id.is_none() {
            self.request_id = id;
        }
        self
    }
}

/// A call's output: the first chunk's request id, the first non-empty content type, the bytes up to `limit`, and
/// whether the relay or the cut truncated them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOut {
    pub request_id: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub truncated: bool,
    pub limit: u64,
}

/// The dials of one link: how many ended, and the last one's error (`None` after a success).
#[derive(Default)]
struct DialState {
    attempts: u64,
    last_error: Option<String>,
}

/// How a link reaches the relay: the TLS configuration, the address and the name its certificate must carry.
struct Dialer {
    tls: Arc<rustls::ClientConfig>,
    addr: SocketAddrV4,
    name: ServerName<'static>,
    state: Mutex<DialState>,
}

impl Dialer {
    /// One dial, its outcome recorded (V-R25 answers a failed call with it).
    async fn dial(&self) -> std::io::Result<hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<TcpStream>>> {
        let r = self.connect().await;
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.attempts += 1;
        st.last_error = r.as_ref().err().cloned();
        drop(st);
        r.map(hyper_util::rt::TokioIo::new).map_err(std::io::Error::other)
    }

    /// TCP within [`CONNECT_TIMEOUT`], TLS within [`HANDSHAKE_TIMEOUT`], `h2` negotiated: the error is the dial's
    /// own (`connect <addr>: <why>` or `tls: <why>`).
    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr)).await {
            Err(_) => return Err(format!("connect {}: no answer within {} s", self.addr, CONNECT_TIMEOUT.as_secs())),
            Ok(Err(e)) => return Err(format!("connect {}: {e}", self.addr)),
            Ok(Ok(s)) => s,
        };
        let _ = tcp.set_nodelay(true);
        let handshake = tokio_rustls::TlsConnector::from(self.tls.clone()).connect(self.name.clone(), tcp);
        let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
            Err(_) => return Err(format!("tls: no handshake within {} s", HANDSHAKE_TIMEOUT.as_secs())),
            Ok(Err(e)) => return Err(format!("tls: {e}")),
            Ok(Ok(s)) => s,
        };
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err("tls: the relay did not negotiate h2".to_string());
        }
        Ok(tls)
    }
}

/// The link's channel: built at a call, kept while calls come, dropped after `idle` without one.
struct Slot {
    channel: Option<Channel>,
    /// Bumped at each new channel: an older reaper leaves the newer one alone.
    generation: u64,
    /// Calls on the channel now.
    busy: usize,
    last_used: Instant,
}

/// A call's hold on the channel: its end is a use.
struct Busy(Arc<Mutex<Slot>>);

impl Drop for Busy {
    fn drop(&mut self) {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        slot.busy = slot.busy.saturating_sub(1);
        slot.last_used = Instant::now();
    }
}

/// The relay's private face, for one session (or over a channel the caller made).
pub struct RelayLink {
    /// `None` over a caller's channel ([`RelayLink::over`]): it is never dropped.
    dialer: Option<Arc<Dialer>>,
    /// The session token as the one metadata value (V-R21; never logged: it is sensitive).
    token: MetadataValue<Ascii>,
    channel_idle: Duration,
    slot: Arc<Mutex<Slot>>,
}

impl RelayLink {
    /// From a session: the TLS config is built now (a bad CA fails here); no connection yet. A failure's message
    /// starts with the session field it refuses: `ca_der_b64: `, `server_name: ` or `token: ` (the client's
    /// `refused: session <field>`, V-R16).
    pub fn new(session: &Session, channel_idle: Duration) -> Result<RelayLink, Failure> {
        let tls = crate::tls::client_config(&session.ca_der).map_err(|e| Failure::new(Code::BadRequest, format!("ca_der_b64: {e}")))?;
        let name = crate::tls::server_name(&session.server_name).map_err(|e| Failure::new(Code::BadRequest, format!("server_name: {e}")))?;
        let token = metadata(session.token()).map_err(|f| Failure::new(f.code, format!("token: {}", f.message)))?;
        let dialer = Dialer { tls: Arc::new(tls), addr: session.addr, name, state: Mutex::new(DialState::default()) };
        Ok(RelayLink { dialer: Some(Arc::new(dialer)), token, channel_idle, slot: Arc::new(Mutex::new(Slot { channel: None, generation: 0, busy: 0, last_used: Instant::now() })) })
    }

    /// Over a channel the caller made (the tests' and the lead's integration, e.g. over `tokio::io::duplex`).
    pub fn over(channel: tonic::transport::Channel, token: &str) -> Result<RelayLink, Failure> {
        let token = metadata(token)?;
        Ok(RelayLink { dialer: None, token, channel_idle: Duration::MAX, slot: Arc::new(Mutex::new(Slot { channel: Some(channel), generation: 0, busy: 0, last_used: Instant::now() })) })
    }

    /// `ListSources` within [`CATALOG_CEILING`] (V-R22): each status with a descriptor as an entry, `source` keeping
    /// that name alone; sources dropped from the end until the answer's line fits [`CATALOG_MAX`] (`true`).
    pub async fn catalog(&self, source: Option<&str>) -> Result<(Vec<SourceEntry>, bool), Failure> {
        let (channel, _busy, before) = self.channel();
        let mut client = RelayClient::new(channel);
        let mut req = tonic::Request::new(v1::ListSourcesRequest {});
        req.metadata_mut().insert(SESSION_HEADER, self.token.clone());
        let reply = match tokio::time::timeout(CATALOG_CEILING, client.list_sources(req)).await {
            Err(_) => return Err(Failure::new(Code::DeadlineExceeded, format!("the relay did not list its sources within {} s", CATALOG_CEILING.as_secs()))),
            Ok(Err(status)) => return Err(self.failure(&status, before)),
            Ok(Ok(r)) => r.into_inner(),
        };
        let mut entries: Vec<SourceEntry> = reply.sources.iter().filter_map(source_entry).filter(|e| source.is_none_or(|s| e.name == s)).collect();
        let truncated = fit_catalog(&mut entries);
        Ok((entries, truncated))
    }

    /// `Call` (V-R23): `params` compact (at most [`PARAMS_MAX`] bytes), `deadline_ms` (0: the op's own), the byte cap
    /// `max_bytes` clamped to 1 to [`MAX_BYTES_CAP`] as the call's limit; the stream read in order, cut at the limit
    /// (the stream dropped, which cancels the call at the relay). Past `min(deadline_ms + 5 s, DEADLINE_CAP_MS + 5 s)`
    /// (300 s without a deadline): `deadline_exceeded`. `cancel` resolving drops the call (V-R24). A failure once the
    /// stream's initial metadata named the call carries that request id unless it has its own.
    pub async fn call(&self, source: &str, op: &str, params: &serde_json::Value, max_bytes: u64, deadline_ms: u32, cancel: impl Future<Output = ()>) -> Result<CallOut, Failure> {
        let params_json = serde_json::to_vec(params).map_err(|e| Failure::new(Code::BadRequest, format!("params: {e}")))?;
        if params_json.len() > PARAMS_MAX {
            return Err(Failure::new(Code::BadRequest, format!("params are {} bytes (at most {PARAMS_MAX})", params_json.len())));
        }
        let limit = max_bytes.clamp(1, MAX_BYTES_CAP);
        let ceiling = local_ceiling(deadline_ms);
        let (channel, _busy, before) = self.channel();
        let request = v1::CallRequest { source: source.to_string(), op: op.to_string(), params_json, deadline_ms, limits: Some(v1::Limits { max_bytes: limit, max_rows: 0, max_chunks: 0 }) };
        let mut head = None;
        let r = {
            let run = self.stream(channel, request, limit, before, &mut head);
            tokio::select! {
                biased;
                () = cancel => Err(Failure::new(Code::Cancelled, "the caller went away")),
                r = tokio::time::timeout(ceiling, run) => r.unwrap_or_else(|_| Err(Failure::new(Code::DeadlineExceeded, format!("no answer from the relay within {} ms", ceiling.as_millis())))),
            }
        };
        r.map_err(|f| f.or_request_id(head))
    }

    /// The call's stream, read in order: the first chunk's `seq` 0, each next the previous plus one (else
    /// `internal`); an in-band error ends it, named by its chunk's request id when that is not empty (else by the
    /// head's, in [`RelayLink::call`]); data up to `limit`; `final` ends it, a stream without one is `internal`.
    /// `head` takes the request id of the stream's initial metadata (R-30) as soon as it arrives.
    async fn stream(&self, channel: Channel, request: v1::CallRequest, limit: u64, before: u64, head: &mut Option<String>) -> Result<CallOut, Failure> {
        let mut client = RelayClient::new(channel);
        let mut req = tonic::Request::new(request);
        req.metadata_mut().insert(SESSION_HEADER, self.token.clone());
        let response = client.call(req).await.map_err(|s| self.failure(&s, before))?;
        *head = request_id_of(response.metadata());
        let mut stream = response.into_inner();
        let mut out = CallOut { request_id: String::new(), content_type: String::new(), data: Vec::new(), truncated: false, limit };
        let mut next: u64 = 0;
        loop {
            let chunk = match stream.message().await {
                Ok(Some(c)) => c,
                Ok(None) => return Err(Failure::new(Code::Internal, "the relay ended the call without its final chunk")),
                Err(status) => return Err(self.failure(&status, before)),
            };
            if chunk.seq != next {
                return Err(Failure::new(Code::Internal, format!("the relay sent chunk {} where {next} was due", chunk.seq)));
            }
            if next == 0 {
                out.request_id.clone_from(&chunk.request_id);
            }
            next += 1;
            if let Some(e) = &chunk.error {
                return Err(Failure { request_id: Some(chunk.request_id).filter(|id| !id.is_empty()), ..failure_of_chunk(e) });
            }
            if out.content_type.is_empty() && !chunk.content_type.is_empty() {
                out.content_type.clone_from(&chunk.content_type);
            }
            out.truncated |= chunk.truncated;
            let room = usize::try_from(limit).unwrap_or(usize::MAX).saturating_sub(out.data.len());
            if chunk.data.len() > room {
                out.data.extend_from_slice(&chunk.data[..room]);
                out.truncated = true;
                // Dropping the stream resets it: the relay sees its caller go.
                return Ok(out);
            }
            out.data.extend_from_slice(&chunk.data);
            if chunk.r#final {
                return Ok(out);
            }
        }
    }

    /// The channel for one call (built now when none lives), the call's hold on it, and how many dials had ended.
    fn channel(&self) -> (Channel, Busy, u64) {
        let before = self.dialer.as_ref().map_or(0, |d| d.state.lock().unwrap_or_else(PoisonError::into_inner).attempts);
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        let channel = match (&slot.channel, &self.dialer) {
            (Some(c), _) => c.clone(),
            (None, Some(dialer)) => {
                let c = lazy_channel(dialer.clone());
                slot.channel = Some(c.clone());
                slot.generation += 1;
                tokio::spawn(reap(Arc::downgrade(&self.slot), slot.generation, self.channel_idle));
                c
            }
            (None, None) => unreachable!("a link over a caller's channel always has it"),
        };
        slot.busy += 1;
        slot.last_used = Instant::now();
        (channel, Busy(self.slot.clone()), before)
    }

    /// A status as its failure, named by the request id the status carries (R-30: every refusal's); when a dial
    /// ended since the call began and failed, the dial's own message (`unavailable`, no request id), never tonic's
    /// wrapper text (V-R25).
    fn failure(&self, status: &tonic::Status, before: u64) -> Failure {
        if let Some(d) = &self.dialer {
            let st = d.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let (true, Some(e)) = (st.attempts > before, &st.last_error) {
                return Failure::new(Code::Unavailable, e.clone());
            }
        }
        failure_of_status(status)
    }
}

/// The token as a metadata value, marked sensitive (HTTP/2 never indexes it).
fn metadata(token: &str) -> Result<MetadataValue<Ascii>, Failure> {
    let mut value: MetadataValue<Ascii> = token.parse().map_err(|_| Failure::new(Code::BadRequest, "the session token is not a metadata value"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// A channel over the dialer, connecting at its first call: `http://<addr>` (the TLS is the connector's own), HTTP/2
/// keepalive while idle.
fn lazy_channel(dialer: Arc<Dialer>) -> Channel {
    let endpoint = Endpoint::from_shared(format!("http://{}", dialer.addr)).expect("an IPv4 socket address is a URI").http2_keep_alive_interval(KEEPALIVE).keep_alive_timeout(KEEPALIVE_TIMEOUT).keep_alive_while_idle(true);
    let connector = tower::service_fn(move |_: http::Uri| {
        let dialer = dialer.clone();
        async move { dialer.dial().await }
    });
    endpoint.connect_with_connector_lazy(connector)
}

/// Drops the slot's channel of `generation` once it went `idle` without a call (its connection closes with it).
async fn reap(slot: Weak<Mutex<Slot>>, generation: u64, idle: Duration) {
    loop {
        let due = {
            let Some(slot) = slot.upgrade() else { return };
            let mut s = slot.lock().unwrap_or_else(PoisonError::into_inner);
            if s.generation != generation || s.channel.is_none() {
                return;
            }
            let due = s.last_used.checked_add(idle);
            if s.busy == 0 && due.is_some_and(|d| d <= Instant::now()) {
                s.channel = None;
                return;
            }
            // While calls run, look again after one more idle period.
            if s.busy > 0 {
                Instant::now().checked_add(idle)
            } else {
                due
            }
        };
        match due {
            Some(at) => tokio::time::sleep_until(at).await,
            None => return,
        }
    }
}

/// A call's local ceiling: `min(deadline_ms + 5 s, DEADLINE_CAP_MS + 5 s)`, so the relay's own deadline fires first
/// (its line then says `deadline`, not that its caller went) unless the dial and the request's transit take over 5 s;
/// 300 s without a deadline.
pub(crate) fn local_ceiling(deadline_ms: u32) -> Duration {
    let cap = Duration::from_millis(u64::from(DEADLINE_CAP_MS));
    if deadline_ms == 0 {
        return cap;
    }
    let margin = Duration::from_secs(5);
    (Duration::from_millis(u64::from(deadline_ms)) + margin).min(cap + margin)
}

/// Drops sources from the end until the catalog answer's line fits [`CATALOG_MAX`]; whether any went.
fn fit_catalog(entries: &mut Vec<SourceEntry>) -> bool {
    let empty = serde_json::to_vec(&Answer::Catalog { v: LOCAL_V, sources: Vec::new(), truncated: false }).map_or(0, |v| v.len());
    let sizes: Vec<usize> = entries.iter().map(|e| serde_json::to_vec(e).map_or(usize::MAX / 2, |v| v.len())).collect();
    // Each entry, and a comma between two.
    let mut total = empty + sizes.iter().sum::<usize>() + entries.len().saturating_sub(1);
    let mut cut = false;
    while total > CATALOG_MAX {
        let Some(size) = sizes.get(entries.len().wrapping_sub(1)).copied() else { break };
        entries.pop();
        total -= size + usize::from(!entries.is_empty());
        cut = true;
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The local ceiling is the deadline and 5 s, at most `DEADLINE_CAP_MS` and 5 s (305 s), so the top of the range
    /// keeps the 5 s margin too; 300 s without a deadline. Kills M-V61.
    #[test]
    fn the_local_ceiling_is_the_deadline_and_five_seconds() {
        assert_eq!(local_ceiling(0), Duration::from_secs(300));
        assert_eq!(local_ceiling(100), Duration::from_millis(5_100));
        assert_eq!(local_ceiling(30_000), Duration::from_secs(35));
        assert_eq!(local_ceiling(296_000), Duration::from_secs(301));
        assert_eq!(local_ceiling(DEADLINE_CAP_MS), Duration::from_secs(305));
        assert_eq!(local_ceiling(DEADLINE_CAP_MS + 1), Duration::from_secs(305), "never past the cap and 5 s");
        assert_eq!(local_ceiling(u32::MAX), Duration::from_secs(305));
    }

    /// The catalog's cut keeps a prefix and the line under its bound, measured as the line is written. Control.
    #[test]
    fn a_catalog_is_cut_from_its_end_to_fit_its_line() {
        let entry = |i: usize| SourceEntry {
            name: format!("test-{i}"),
            version: "0.1.0".into(),
            description: "d".repeat(2048),
            kind: "other".into(),
            env: "test".into(),
            sensitivity: "internal".into(),
            available: true,
            last_seen_unix_ms: 1,
            ops: Vec::new(),
        };
        let mut all: Vec<SourceEntry> = (0..300).map(entry).collect();
        assert!(fit_catalog(&mut all));
        let line = serde_json::to_vec(&Answer::Catalog { v: LOCAL_V, sources: all.clone(), truncated: true }).unwrap();
        assert!(line.len() <= CATALOG_MAX, "{}", line.len());
        assert!(all.len() > 100 && all.iter().enumerate().all(|(i, e)| e.name == format!("test-{i}")), "a prefix: {}", all.len());
        let mut one_more = all.clone();
        one_more.push(entry(all.len()));
        let over = serde_json::to_vec(&Answer::Catalog { v: LOCAL_V, sources: one_more, truncated: true }).unwrap();
        assert!(over.len() > CATALOG_MAX, "the next one would not fit");
        let mut few: Vec<SourceEntry> = (0..3).map(entry).collect();
        assert!(!fit_catalog(&mut few) && few.len() == 3);
    }
}
