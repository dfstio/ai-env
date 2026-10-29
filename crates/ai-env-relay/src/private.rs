//! `PrivateSvc` (`Relay`), the limits and deadline arithmetic, the catalog filter (R-30 to R-57).
//!
//! Every request carries a session token that W/M's verifier checks first (R-51 to R-53); the caller is the token's,
//! never the request's (R-54). A refusal before the stream is a gRPC status (R-31, LD-R14); once the stream starts,
//! the call ends with exactly one final chunk (R-42). Each call gets one call line (R-61), each list one list line.

use std::sync::Arc;
use std::time::Duration;

use ai_env_relay_proto::prost::Message;
use ai_env_relay_proto::v1::relay_server;
use ai_env_relay_proto::v1::{relay_frame, CallRequest, Caller, Invoke, Limits, ListSourcesRequest, ListSourcesResponse, OpDescriptor, RelayFrame, SourceStatus};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tonic::metadata::{MetadataMap, MetadataValue};

use crate::calls::{CallState, CallStream, CallTable, Caps, Outcome, Permits};
use crate::config;
use crate::limits::Refusal;
use crate::lists::Grant;
use crate::registry::Route;
use crate::reqlog::{CallFields, CallLog, ListFields};
use crate::serve::RelayState;
use crate::session::{self, SessionClaims};
use crate::tls::PeerInfo;

/// The response metadata key of the relay's id of a call (one definition in ai-env-source's `wire`, review A-L11).
pub const REQUEST_ID_HEADER: &str = ai_env_source::wire::REQUEST_ID_HEADER;

/// The private face's service.
pub struct PrivateSvc {
    state: Arc<RelayState>,
}

impl PrivateSvc {
    /// The service of the relay `state`.
    pub(crate) fn new(state: Arc<RelayState>) -> PrivateSvc {
        PrivateSvc { state }
    }
}

/// A refusal before the stream: its gRPC status and its line's outcome word (R-31, R-64).
struct Refused {
    code: tonic::Code,
    message: String,
    outcome: &'static str,
    /// The call's one line is written already (R-61): a fail-all concluded the call first.
    written: bool,
}

impl Refused {
    fn new(code: tonic::Code, message: impl Into<String>, outcome: &'static str) -> Box<Refused> {
        Box::new(Refused { code, message: message.into(), outcome, written: false })
    }

    /// The same refusal, whose call needs no line of its own.
    fn written(mut self: Box<Self>) -> Box<Refused> {
        self.written = true;
        self
    }

    fn status(&self, request_id: &str) -> tonic::Status {
        let mut status = tonic::Status::new(self.code, self.message.clone());
        tag(status.metadata_mut(), request_id);
        status
    }
}

/// R-30: every answer names its request id.
fn tag(metadata: &mut MetadataMap, request_id: &str) {
    if let Ok(v) = MetadataValue::try_from(request_id) {
        metadata.insert(REQUEST_ID_HEADER, v);
    }
}

fn unauthenticated() -> Box<Refused> {
    Refused::new(tonic::Code::Unauthenticated, "authentication failed", "unauthenticated")
}

fn session_refusal(r: Refusal) -> Box<Refused> {
    match r {
        Refusal::RateLimited => Refused::new(tonic::Code::ResourceExhausted, "rate limited", "rate_limited"),
        Refusal::TooManySessions => Refused::new(tonic::Code::ResourceExhausted, "too many sessions", "too_many"),
        Refusal::TooManyInFlight | Refusal::TooManyConnections => Refused::new(tonic::Code::ResourceExhausted, "too many calls in flight", "too_many"),
    }
}

impl RelayState {
    /// R-51 to R-53 on a request's metadata: exactly one token, the signers fresh, W/M's verifier.
    fn caller_of(&self, metadata: &MetadataMap) -> Result<SessionClaims, Box<Refused>> {
        // A value that is not visible ASCII is still a value: it fails the verifier as malformed.
        let values: Vec<&str> = metadata.get_all(session::SESSION_HEADER).iter().map(|v| v.to_str().unwrap_or("")).collect();
        let signers = self.live.signers.fresh(self.now(), self.max_stale());
        session::verify_request(&values, signers.as_deref(), self.now_unix()).map_err(|fault| {
            // R-53: the variant to relay.log (the caller and the request log see only `unauthenticated`).
            if self.fault_log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take(Instant::now()) {
                tracing::info!(fault = fault.word(), "private face: a session token was refused");
            }
            unauthenticated()
        })
    }
}

#[tonic::async_trait]
impl relay_server::Relay for PrivateSvc {
    async fn list_sources(&self, request: tonic::Request<ListSourcesRequest>) -> Result<tonic::Response<ListSourcesResponse>, tonic::Status> {
        let st = &self.state;
        let started = Instant::now();
        let request_id = uuid::Uuid::now_v7().to_string();
        let mut line = ListFields { request_id: request_id.clone(), ..ListFields::default() };
        let answer = list(st, &request, &mut line);
        let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match answer {
            Ok(response) => {
                line.sources = response.sources.len() as u64;
                st.log.list(st.now(), &line, "ok", 0, millis);
                let mut r = tonic::Response::new(response);
                tag(r.metadata_mut(), &request_id);
                Ok(r)
            }
            Err(refused) => {
                st.log.list(st.now(), &line, refused.outcome, refused.code as i32, millis);
                Err(refused.status(&request_id))
            }
        }
    }

    type CallStream = crate::calls::CallStream;

    async fn call(&self, request: tonic::Request<CallRequest>) -> Result<tonic::Response<crate::calls::CallStream>, tonic::Status> {
        let st = &self.state;
        let started = Instant::now();
        let request_id = uuid::Uuid::now_v7().to_string();
        let mut fields = CallFields { request_id: request_id.clone(), ..CallFields::default() };
        match call(st, request, &mut fields, started).await {
            Ok(stream) => {
                let mut r = tonic::Response::new(stream);
                tag(r.metadata_mut(), &request_id);
                Ok(r)
            }
            Err(refused) => {
                if !refused.written {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    st.log.call(st.now(), &fields, refused.outcome, refused.code as i32, 0, 0, false, millis);
                }
                Err(refused.status(&request_id))
            }
        }
    }
}

/// R-32: the token, the session's bucket, the grants, then R-49.
fn list(st: &RelayState, request: &tonic::Request<ListSourcesRequest>, line: &mut ListFields) -> Result<ListSourcesResponse, Box<Refused>> {
    if request.extensions().get::<PeerInfo>().is_none() {
        return Err(Refused::new(tonic::Code::Internal, "no peer", "invalid"));
    }
    let claims = st.caller_of(request.metadata())?;
    line.caller = claims.caller_id.clone();
    line.session = claims.session_id.clone();
    line.vm = claims.vm_id.clone();
    line.grant = claims.grant_id.clone();
    st.sessions.enter(&claims.session_id, false, Instant::now()).map_err(session_refusal)?;
    let grants = st.live.grants.fresh(st.now(), st.max_stale()).ok_or_else(|| Refused::new(tonic::Code::Unavailable, "grants not loaded", "not_ready"))?;
    let sources = filter_catalog(st.registry.statuses(), grants.get(&claims.grant_id));
    let response = ListSourcesResponse { sources };
    if response.encoded_len() > st.cfg.limits.list_max_bytes as usize {
        return Err(Refused::new(tonic::Code::ResourceExhausted, "catalog too large", "too_large"));
    }
    Ok(response)
}

/// R-30 to R-46, in R-31's order; the stream when every step passes.
async fn call(st: &Arc<RelayState>, request: tonic::Request<CallRequest>, fields: &mut CallFields, started: Instant) -> Result<CallStream, Box<Refused>> {
    let l = &st.cfg.limits;
    if request.extensions().get::<PeerInfo>().is_none() {
        return Err(Refused::new(tonic::Code::Internal, "no peer", "invalid"));
    }
    let claims = st.caller_of(request.metadata())?;
    let req = request.into_inner();
    let valid = |s: &str| ai_env_worker::globs::valid_id(s);
    // R-62: names reach the log only when they are ids.
    if valid(&req.source) {
        fields.source = req.source.clone();
    }
    if valid(&req.op) {
        fields.op = req.op.clone();
    }
    fields.caller = claims.caller_id.clone();
    fields.session = claims.session_id.clone();
    fields.vm = claims.vm_id.clone();
    fields.grant = claims.grant_id.clone();
    fields.params_hmac = st.log.digest(&req.params_json);
    fields.params_bytes = req.params_json.len() as u64;

    let session_pass = st.sessions.enter(&claims.session_id, true, Instant::now()).map_err(session_refusal)?;
    if !valid(&req.source) || !valid(&req.op) {
        return Err(Refused::new(tonic::Code::InvalidArgument, "invalid source or op name", "invalid"));
    }
    let grants = st.live.grants.fresh(st.now(), st.max_stale()).ok_or_else(|| Refused::new(tonic::Code::Unavailable, "grants not loaded", "not_ready"))?;
    // R-48: the grant before the lookup, so a caller learns nothing of sources it may not use.
    if !grants.get(&claims.grant_id).is_some_and(|g| g.allows(&req.source, &req.op)) {
        return Err(Refused::new(tonic::Code::PermissionDenied, "not granted", "denied"));
    }
    let (live, descriptor) = match st.registry.route(&req.source) {
        Route::Unknown => return Err(Refused::new(tonic::Code::NotFound, "no such source", "not_found")),
        Route::Live(h, d) => (Some(h), Some(d)),
        // R-31's order puts the op before `Offline`: an offline source keeps its descriptor (R-26).
        Route::Offline => (None, st.registry.descriptor(&req.source)),
    };
    let op = descriptor.as_deref().and_then(|d| d.ops.iter().find(|o| o.name == req.op));
    if descriptor.is_some() && op.is_none() {
        return Err(Refused::new(tonic::Code::NotFound, "no such op", "not_found"));
    }
    let (Some(handle), Some(op)) = (live, op) else {
        return Err(Refused::new(tonic::Code::Unavailable, "source offline", "offline"));
    };
    let params = check_params(&req.params_json, l.params_max_bytes as usize)
        .ok_or_else(|| Refused::new(tonic::Code::InvalidArgument, format!("params must be a JSON object of at most {} bytes", l.params_max_bytes), "invalid"))?;
    let relay_permit = Arc::clone(&st.in_flight)
        .try_acquire_owned()
        .map_err(|_| Refused::new(tonic::Code::ResourceExhausted, "too many calls in flight", "too_many"))?;
    fields.worker = handle.worker_id.clone();
    fields.tunnel = handle.tunnel_id.to_string();

    let limits = effective_limits(req.limits.as_ref(), op, l);
    let deadline_ms = effective_deadline_ms(req.deadline_ms, l);
    let deadline = started + Duration::from_millis(u64::from(deadline_ms));
    let log = CallLog { log: Arc::clone(&st.log), clock: Arc::clone(&st.clock), fields: fields.clone() };
    let state = Arc::new(CallState::new(fields.request_id.clone(), Some(log)));
    let caps = Caps { max_bytes: limits.max_bytes, max_chunks: limits.max_chunks };
    let rx = handle.calls.insert(Arc::clone(&state), caps, l.call_buffer_chunks as usize).map_err(|_| {
        if handle.calls.is_closed() {
            Refused::new(tonic::Code::Unavailable, "source offline", "offline")
        } else {
            Refused::new(tonic::Code::Unavailable, "worker busy", "busy")
        }
    })?;
    let enqueueing = Enqueueing { table: Arc::clone(&handle.calls), state: Arc::clone(&state), armed: true };
    // R-54: the caller is the token's; `chat_id` has no field and is not forwarded.
    let caller = Caller { caller_id: claims.caller_id, session_id: claims.session_id, grant_id: claims.grant_id, vm_id: claims.vm_id };
    let left = deadline.saturating_duration_since(Instant::now()).as_millis();
    let invoke = Invoke {
        request_id: fields.request_id.clone(),
        source: req.source,
        op: req.op,
        params_json: params,
        caller: Some(caller),
        deadline_ms: u32::try_from(left).unwrap_or(u32::MAX).max(1),
        limits: Some(limits),
    };
    // R-38: a bounded enqueue.
    let sent = handle.tx.send_timeout(Ok(RelayFrame { msg: Some(relay_frame::Msg::Invoke(invoke)) }), config::ms(l.enqueue_timeout_ms)).await;
    enqueueing.defuse();
    if let Err(e) = sent {
        // A tunnel that ended during the wait has concluded the call already, its fail-all writing the call's one
        // line (R-44, R-61): the caller still hears `source offline`, with no second line.
        if !handle.calls.discard(&fields.request_id) {
            return Err(Refused::new(tonic::Code::Unavailable, "source offline", "offline").written());
        }
        return Err(match e {
            mpsc::error::SendTimeoutError::Timeout(_) => Refused::new(tonic::Code::Unavailable, "worker busy", "busy"),
            mpsc::error::SendTimeoutError::Closed(_) => Refused::new(tonic::Code::Unavailable, "source offline", "offline"),
        });
    }
    arm_deadline(&handle.calls, &handle.tx, &state, deadline, config::ms(l.enqueue_timeout_ms));
    let permits = Permits { _session: session_pass, _relay: Some(relay_permit) };
    Ok(CallStream::new(rx, state, Arc::downgrade(&handle.calls), handle.tx.clone(), permits, config::ms(l.enqueue_timeout_ms)))
}

/// A call in its tunnel's table whose Invoke is not queued yet (R-38). hyper drops the handler at the enqueue's
/// `.await` when the caller resets its stream; the guard then ends the call `Cancelled`, which removes its entry and
/// writes its one line (R-61). No `Cancel` follows: `send_timeout` is cancel-safe, so no Invoke went out.
struct Enqueueing {
    table: Arc<CallTable>,
    state: Arc<CallState>,
    armed: bool,
}

impl Enqueueing {
    /// The enqueue came back, queued or refused: what follows handles the entry.
    fn defuse(mut self) {
        self.armed = false;
    }
}

impl Drop for Enqueueing {
    fn drop(&mut self) {
        if self.armed {
            self.table.finish(self.state.request_id(), Outcome::Cancelled);
        }
    }
}

/// R-34: at most `max` bytes; empty becomes `{}`; anything else a JSON object, forwarded byte for byte.
fn check_params(params: &[u8], max: usize) -> Option<Vec<u8>> {
    if params.len() > max {
        return None;
    }
    if params.is_empty() {
        return Some(b"{}".to_vec());
    }
    let object = serde_json::from_slice::<std::collections::BTreeMap<String, serde::de::IgnoredAny>>(params).is_ok();
    object.then(|| params.to_vec())
}

/// R-45: a timer per call; if the call is still pending at its deadline, it ends `Deadline` and the worker gets
/// `Cancel{"deadline"}`. The timer stops when the call ends first.
fn arm_deadline(
    table: &Arc<crate::calls::CallTable>,
    tx: &mpsc::Sender<Result<RelayFrame, tonic::Status>>,
    state: &Arc<CallState>,
    at: Instant,
    within: Duration,
) {
    let (table, tx, ended) = (Arc::downgrade(table), tx.clone(), state.ended());
    let request_id = state.request_id().to_string();
    tokio::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep_until(at) => {
                if let Some(table) = table.upgrade() {
                    if table.finish(&request_id, Outcome::Deadline) {
                        let frame = crate::tunnel::cancel_frame(&request_id, ai_env_source::wire::cancel::DEADLINE);
                        if let Err(mpsc::error::TrySendError::Full(Ok(f))) = tx.try_send(Ok(frame)) {
                            crate::tunnel::send_later(tx, f, within);
                        }
                    }
                }
            }
            () = ended.cancelled() => {}
        }
    });
}

/// R-35, each of the three limits on its own (P's `Limits::resolve` with the relay's defaults and ceiling).
pub fn effective_limits(requested: Option<&Limits>, op: &OpDescriptor, cfg: &config::Limits) -> Limits {
    fn one<T: Copy + Ord + Default>(requested: T, default: T, max: T, relay_default: T, relay_max: T) -> T {
        let zero = T::default();
        let want = if requested > zero {
            requested
        } else if default > zero {
            default
        } else {
            relay_default
        };
        let cap = if max > zero { max.min(relay_max) } else { relay_max };
        want.min(cap)
    }
    let r = requested.copied().unwrap_or_default();
    let d = op.default_limits.unwrap_or_default();
    let m = op.max_limits.unwrap_or_default();
    Limits {
        max_bytes: one(r.max_bytes, d.max_bytes, m.max_bytes, cfg.call_bytes_default, cfg.call_bytes_max),
        max_rows: one(r.max_rows, d.max_rows, m.max_rows, cfg.call_rows_default, cfg.call_rows_max),
        max_chunks: one(r.max_chunks, d.max_chunks, m.max_chunks, cfg.call_chunks_default, cfg.call_chunks_max),
    }
}

/// R-36.
pub fn effective_deadline_ms(requested: u32, cfg: &config::Limits) -> u32 {
    let want = if requested == 0 { cfg.deadline_default_ms } else { requested };
    want.clamp(cfg.deadline_min_ms, cfg.deadline_max_ms)
}

/// R-49.
pub fn filter_catalog(statuses: Vec<SourceStatus>, grant: Option<&Grant>) -> Vec<SourceStatus> {
    let Some(grant) = grant else { return Vec::new() };
    let mut out: Vec<SourceStatus> = statuses
        .into_iter()
        .filter_map(|mut s| {
            let d = s.descriptor.as_mut()?;
            let name = d.name.clone();
            d.ops.retain(|op| grant.allows(&name, &op.name));
            (!d.ops.is_empty()).then_some(s)
        })
        .collect();
    out.sort_by(|a, b| a.descriptor.as_ref().map(|d| &d.name).cmp(&b.descriptor.as_ref().map(|d| &d.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_env_relay_proto::v1::SourceDescriptor;

    fn op(default: Limits, max: Limits) -> OpDescriptor {
        OpDescriptor { name: "get".into(), default_limits: Some(default), max_limits: Some(max), ..Default::default() }
    }

    const MIB: u64 = 1 << 20;

    fn lim(max_bytes: u64, max_rows: u32, max_chunks: u32) -> Limits {
        Limits { max_bytes, max_rows, max_chunks }
    }

    /// Unit 18.
    #[test]
    fn effective_limits_take_the_smallest_cap() {
        let cfg = config::Limits::default();
        let zero = lim(0, 0, 0);
        assert_eq!(effective_limits(None, &op(zero, zero), &cfg), lim(MIB, 1000, 16), "the relay's defaults");
        assert_eq!(effective_limits(Some(&lim(5 * MIB, 0, 0)), &op(zero, lim(2 * MIB, 0, 0)), &cfg).max_bytes, 2 * MIB);
        assert_eq!(effective_limits(Some(&lim(100 * MIB, 0, 0)), &op(zero, zero), &cfg).max_bytes, 16 * MIB);
        assert_eq!(effective_limits(None, &op(lim(3 * MIB, 0, 0), zero), &cfg).max_bytes, 3 * MIB);
        assert_eq!(effective_limits(Some(&lim(0, 50_000, 0)), &op(zero, zero), &cfg).max_rows, 50_000, "op max 0: no op cap");
        assert_eq!(effective_limits(Some(&lim(0, 500_000, 0)), &op(zero, lim(0, 200, 0)), &cfg).max_rows, 200);
        assert_eq!(effective_limits(Some(&lim(0, 0, 999)), &op(lim(0, 0, 3), zero), &cfg).max_chunks, 256);
        assert_eq!(effective_limits(None, &op(lim(0, 0, 3), zero), &cfg).max_chunks, 3);
        // With the defaults, P's `Limits::resolve` exactly, on 50 combinations of P's constants.
        use ai_env_source::Limits as P;
        let bytes = [0, 1, P::DEFAULT.max_bytes, P::CEILING.max_bytes, P::CEILING.max_bytes + 1, 3 * MIB, 7];
        let rows = [0, 1, P::DEFAULT.max_rows, P::CEILING.max_rows, P::CEILING.max_rows + 1, 500, 9];
        let chunks = [0, 1, P::DEFAULT.max_chunks, P::CEILING.max_chunks, P::CEILING.max_chunks + 1, 2, 64];
        let mut x = 0x9e37_79b9u32;
        let mut pick = |n: usize| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as usize % n
        };
        for _ in 0..50 {
            let mut three = || lim(bytes[pick(bytes.len())], rows[pick(rows.len())], chunks[pick(chunks.len())]);
            let (r, d, m) = (three(), three(), three());
            let ours = effective_limits(Some(&r), &op(d, m), &cfg);
            let theirs = P::resolve(P::new(r.max_bytes, r.max_rows, r.max_chunks), P::new(d.max_bytes, d.max_rows, d.max_chunks), P::new(m.max_bytes, m.max_rows, m.max_chunks));
            assert_eq!((ours.max_bytes, ours.max_rows, ours.max_chunks), (theirs.max_bytes, theirs.max_rows, theirs.max_chunks), "{r:?} {d:?} {m:?}");
        }
    }

    /// Unit 19.
    #[test]
    fn deadlines_default_and_clamp() {
        let cfg = config::Limits::default();
        assert_eq!(effective_deadline_ms(0, &cfg), 30_000);
        assert_eq!(effective_deadline_ms(500, &cfg), 1000);
        assert_eq!(effective_deadline_ms(1_000_000, &cfg), 600_000);
        assert_eq!(effective_deadline_ms(45_000, &cfg), 45_000);
    }

    fn status(name: &str, ops: &[&str], available: bool) -> SourceStatus {
        SourceStatus {
            descriptor: Some(SourceDescriptor {
                name: name.into(),
                ops: ops.iter().map(|o| OpDescriptor { name: o.to_string(), ..Default::default() }).collect(),
                ..Default::default()
            }),
            available,
            last_seen_unix_ms: 1,
        }
    }

    /// Unit 20.
    #[test]
    fn the_catalog_filter_keeps_granted_ops_only() {
        let statuses = vec![status("other.gamma", &["get"], true), status("example.beta", &["get"], false), status("example.alpha", &["get", "list", "put"], true)];
        let grant = Grant { grant_id: "g".into(), allow: vec!["example.*/get".into(), "example.*/list".into()] };
        let out = filter_catalog(statuses.clone(), Some(&grant));
        let view: Vec<(String, Vec<String>, bool)> = out
            .iter()
            .map(|s| {
                let d = s.descriptor.as_ref().unwrap();
                (d.name.clone(), d.ops.iter().map(|o| o.name.clone()).collect(), s.available)
            })
            .collect();
        assert_eq!(
            view,
            vec![("example.alpha".to_string(), vec!["get".to_string(), "list".to_string()], true), ("example.beta".to_string(), vec!["get".to_string()], false)]
        );
        assert!(filter_catalog(statuses, None).is_empty(), "no grant: nothing");
    }

    #[test]
    fn params_are_objects_kept_byte_for_byte() {
        assert_eq!(check_params(b"", 10).as_deref(), Some(&b"{}"[..]));
        assert_eq!(check_params(b"{\"n\": 1}", 64).as_deref(), Some(&b"{\"n\": 1}"[..]), "byte for byte, never re-serialized");
        assert!(check_params(b"[1]", 64).is_none());
        assert!(check_params(b"not json", 64).is_none());
        assert!(check_params(b"{\"n\":1}", 3).is_none());
    }
}
