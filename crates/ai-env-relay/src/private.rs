//! `PrivateSvc` (`Relay`), the limits and deadline arithmetic, the catalog filter (R-30 to R-57), a token's effective
//! grants (R-145).
//!
//! Every request carries a session token that W/M's verifier checks first (R-51 to R-53); the caller is the token's,
//! never the request's (R-54). A refusal before the stream is a gRPC status (R-31, LD-R14); once the stream starts,
//! the call ends with exactly one final chunk (R-42). Each call gets one call line (R-61), each list one list line.
//! What a token reaches is worked out per request, with no cache: its own grant, and what the access list adds for its
//! chat as the list is now (R-145).
//!
//! Each request is one of its connection's (R-103): pending from its handler's start to its answer or its call's
//! conclusion, so the connection's watch knows when it is idle; its refused tokens count against the connection,
//! and at `private_faults_max` every later request is refused before any token is verified (R-105).

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
use crate::lists::{Access, Grant, Grants};
use crate::registry::Route;
use crate::reqlog::{CallFields, CallLog, ListFields};
use crate::serve::RelayState;
use crate::session::{self, SessionClaims, SessionFault};
use crate::tls::{PeerInfo, PrivateConn};

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
        // Never a session's: a ban is the public face's (R-98).
        Refusal::TooManyInFlight | Refusal::TooManyConnections | Refusal::Banned => {
            Refused::new(tonic::Code::ResourceExhausted, "too many calls in flight", "too_many")
        }
    }
}

impl RelayState {
    /// R-51 to R-53 on a request's metadata: exactly one token, the signers fresh, W/M's verifier. R-105: a faulted
    /// connection's request is refused before anything is verified; a refused token (`Missing` or `Token`, never
    /// `NotLoaded`, the relay's own) counts against the connection; a verified one meets its deadline (R-103).
    fn caller_of(&self, metadata: &MetadataMap, conn: &PrivateConn) -> Result<SessionClaims, Box<Refused>> {
        if conn.faulted() {
            return Err(unauthenticated());
        }
        // A value that is not visible ASCII is still a value: it fails the verifier as malformed.
        let values: Vec<&str> = metadata.get_all(session::SESSION_HEADER).iter().map(|v| v.to_str().unwrap_or("")).collect();
        let signers = self.live.signers.fresh(self.now(), self.max_stale());
        match session::verify_request(&values, signers.as_deref(), self.now_unix()) {
            Ok(claims) => {
                conn.verified();
                Ok(claims)
            }
            Err(fault) => {
                // R-53: the variant to relay.log (the caller and the request log see only `unauthenticated`).
                if self.fault_log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take(Instant::now()) {
                    tracing::info!(fault = fault.word(), "private face: a session token was refused");
                }
                if fault != SessionFault::NotLoaded {
                    conn.refused(self.cfg.limits.private_faults_max, Instant::now());
                }
                Err(unauthenticated())
            }
        }
    }

    /// The request's connection (R-103): its watch registered it before tonic saw it. None only for a request that
    /// reached its handler after its connection's watch ended (the connection is cut or gone).
    fn connection_of<T>(&self, request: &tonic::Request<T>) -> Option<Arc<PrivateConn>> {
        request.extensions().get::<PeerInfo>().and_then(|p| self.private_conns.get(p.conn_seq))
    }
}

#[tonic::async_trait]
impl relay_server::Relay for PrivateSvc {
    async fn list_sources(&self, request: tonic::Request<ListSourcesRequest>) -> Result<tonic::Response<ListSourcesResponse>, tonic::Status> {
        let st = &self.state;
        let started = Instant::now();
        let request_id = uuid::Uuid::now_v7().to_string();
        let mut line = ListFields { request_id: request_id.clone(), ..ListFields::default() };
        // R-103: pending from here to the answer.
        let conn = st.connection_of(&request);
        let _pending = conn.as_ref().map(|c| c.request(started));
        let answer = list(st, &request, conn.as_deref(), &mut line);
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
        // R-103: pending from here to the refusal, or to the call's conclusion (its permits, R-106).
        let conn = st.connection_of(&request);
        let pending = conn.as_ref().map(|c| c.request(started));
        match call(st, request, conn, pending, &mut fields, started).await {
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
fn list(st: &RelayState, request: &tonic::Request<ListSourcesRequest>, conn: Option<&PrivateConn>, line: &mut ListFields) -> Result<ListSourcesResponse, Box<Refused>> {
    if request.extensions().get::<PeerInfo>().is_none() {
        return Err(Refused::new(tonic::Code::Internal, "no peer", "invalid"));
    }
    // A request whose connection is no longer watched is cut with it: refused unverified.
    let claims = st.caller_of(request.metadata(), conn.ok_or_else(unauthenticated)?)?;
    line.caller = claims.caller_id.clone();
    line.session = claims.session_id.clone();
    line.vm = claims.vm_id.clone();
    line.grant = claims.grant_id.clone();
    st.sessions.enter(&claims.session_id, false, Instant::now()).map_err(session_refusal)?;
    let grants = st.live.grants.fresh(st.now(), st.max_stale()).ok_or_else(|| Refused::new(tonic::Code::Unavailable, "grants not loaded", "not_ready"))?;
    // R-145: through `fresh`, so a list that is absent, refused or stale adds nothing. The list line keeps the token's.
    let access = st.live.access.fresh(st.now(), st.max_stale());
    let sources = filter_catalog(st.registry.statuses(), &effective(&grants, access.as_deref(), &claims, st.now_unix()));
    let response = ListSourcesResponse { sources };
    if response.encoded_len() > st.cfg.limits.list_max_bytes as usize {
        return Err(Refused::new(tonic::Code::ResourceExhausted, "catalog too large", "too_large"));
    }
    Ok(response)
}

/// R-30 to R-46, in R-31's order; the stream when every step passes. `pending` is the request's on its connection
/// (R-103): the call holds it until it concludes (R-106).
async fn call(
    st: &Arc<RelayState>,
    request: tonic::Request<CallRequest>,
    conn: Option<Arc<PrivateConn>>,
    pending: Option<crate::tls::Pending>,
    fields: &mut CallFields,
    started: Instant,
) -> Result<CallStream, Box<Refused>> {
    let l = &st.cfg.limits;
    if request.extensions().get::<PeerInfo>().is_none() {
        return Err(Refused::new(tonic::Code::Internal, "no peer", "invalid"));
    }
    // A request whose connection is no longer watched is cut with it: refused unverified.
    let Some(conn) = conn else { return Err(unauthenticated()) };
    let claims = st.caller_of(request.metadata(), &conn)?;
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
    // R-145: through `fresh`, so a list that is absent, refused or stale adds nothing.
    let access = st.live.access.fresh(st.now(), st.max_stale());
    // R-48: the grant before the lookup, so a caller learns nothing of sources it may not use.
    let Some(granted) = effective(&grants, access.as_deref(), &claims, st.now_unix()).into_iter().find(|g| g.allows(&req.source, &req.op)) else {
        return Err(Refused::new(tonic::Code::PermissionDenied, "not granted", "denied"));
    };
    // R-145: the line and the worker name the grant the call went through, from here on.
    fields.grant = granted.grant_id.clone();
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
    let state = Arc::new(CallState::new(fields.request_id.clone(), claims.session_id.clone(), Some(log)));
    let caps = Caps { max_bytes: limits.max_bytes, max_chunks: limits.max_chunks };
    let rx = handle.calls.insert(Arc::clone(&state), caps, l.call_buffer_chunks as usize).map_err(|_| {
        if handle.calls.is_closed() {
            Refused::new(tonic::Code::Unavailable, "source offline", "offline")
        } else {
            Refused::new(tonic::Code::Unavailable, "worker busy", "busy")
        }
    })?;
    let enqueueing = Enqueueing { table: Arc::clone(&handle.calls), state: Arc::clone(&state), armed: true };
    // R-54: the caller is the token's; `chat_id` has no field and is not forwarded. R-145: the grant, the one that
    // allowed this call.
    let caller = Caller { caller_id: claims.caller_id, session_id: claims.session_id, grant_id: fields.grant.clone(), vm_id: claims.vm_id };
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
    // R-106: the session's pass and the connection's pending request end with the call; the relay's permit and the
    // stream's mark on the connection's watch stay with the stream until hyper drops it.
    let mark = Arc::new(conn.stream());
    state.hold(Permits { _session: session_pass, _request: pending, stream: Some(Arc::clone(&mark)) });
    Ok(CallStream::new(rx, state, Arc::downgrade(&handle.calls), handle.tx.clone(), Some(relay_permit), Some(mark), config::ms(l.enqueue_timeout_ms)))
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

/// R-145: what a token reaches, in the order a call tries them: its own grant, then the grants of the entry in force that
/// names its chat. A token with no `chat_id` matches no entry, and a name `grants` does not hold adds nothing.
fn effective<'a>(grants: &'a Grants, access: Option<&Access>, c: &SessionClaims, now: u64) -> Vec<&'a Grant> {
    let more = c.chat_id.as_deref().and_then(|chat| access?.grants_of(chat, now)).unwrap_or_default();
    grants.get(&c.grant_id).into_iter().chain(more.iter().filter(|g| **g != c.grant_id).filter_map(|g| grants.get(g))).collect()
}

/// R-49: the ops any of `grants` allows, in the catalog's order; with none, nothing.
pub fn filter_catalog(statuses: Vec<SourceStatus>, grants: &[&Grant]) -> Vec<SourceStatus> {
    let mut out: Vec<SourceStatus> = statuses
        .into_iter()
        .filter_map(|mut s| {
            let d = s.descriptor.as_mut()?;
            let name = d.name.clone();
            d.ops.retain(|op| grants.iter().any(|g| g.allows(&name, &op.name)));
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
        let view = |out: Vec<SourceStatus>| -> Vec<(String, Vec<String>, bool)> {
            out.iter()
                .map(|s| {
                    let d = s.descriptor.as_ref().unwrap();
                    (d.name.clone(), d.ops.iter().map(|o| o.name.clone()).collect(), s.available)
                })
                .collect()
        };
        let row = |name: &str, ops: &[&str], available: bool| (name.to_string(), ops.iter().map(|o| o.to_string()).collect::<Vec<String>>(), available);
        assert_eq!(view(filter_catalog(statuses.clone(), &[&grant])), [row("example.alpha", &["get", "list"], true), row("example.beta", &["get"], false)]);
        // R-145: the union of two grants, each source's ops in the catalog's order whichever grant allows them.
        let put = Grant { grant_id: "g-put".into(), allow: vec!["example.alpha/put".into(), "other.*/get".into()] };
        let get = Grant { grant_id: "g-get".into(), allow: vec!["example.alpha/get".into()] };
        let want = [row("example.alpha", &["get", "put"], true), row("other.gamma", &["get"], true)];
        assert_eq!(view(filter_catalog(statuses.clone(), &[&put, &get])), want);
        assert_eq!(view(filter_catalog(statuses.clone(), &[&get, &put])), want, "either order");
        assert_eq!(view(filter_catalog(statuses.clone(), &[&get])), [row("example.alpha", &["get"], true)]);
        assert!(filter_catalog(statuses, &[]).is_empty(), "no grant: nothing");
    }

    /// R-145: the token's own grant first, then its entry's in the entry's order; its own grant named again by the entry
    /// comes once; a name no grant holds adds nothing; no chat, no list, another chat's entry or a lapsed one, nothing more.
    #[test]
    fn a_token_reaches_its_own_grant_then_its_entrys() {
        const CHAT: &str = "0199a1b2-0000-7000-8000-0000000012a3";
        const OTHER: &str = "0199a1b2-0000-7000-8000-0000000012a4";
        let grant = |id: &str| Grant { grant_id: id.into(), allow: vec!["example.*/*".into()] };
        let grants = Grants { entries: vec![grant("g-a"), grant("g-b"), grant("g-own")] };
        let claims = |own: &str, chat: Option<&str>| SessionClaims {
            kid: "mac".into(),
            aud: session::SESSION_AUD.into(),
            caller_id: "mac".into(),
            session_id: "0199a1b2-0000-7000-8000-0000000012a5".into(),
            chat_id: chat.map(str::to_string),
            grant_id: own.into(),
            vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
            iat: 0,
            exp: 3600,
        };
        const NOT_AFTER: &str = "2027-01-01T23:59:59Z";
        let until = ai_env_worker::policy::unix_of(NOT_AFTER).unwrap();
        let access = Access {
            entries: vec![ai_env_worker::policy::AccessEntry { chat: CHAT.into(), grants: vec!["g-a".into(), "g-gone".into(), "g-own".into(), "g-b".into()], not_after: NOT_AFTER.into() }],
        };
        let reach = |c: &SessionClaims, access: Option<&Access>, now: u64| -> Vec<String> { effective(&grants, access, c, now).iter().map(|g| g.grant_id.clone()).collect() };
        assert_eq!(reach(&claims("g-own", Some(CHAT)), Some(&access), until), ["g-own", "g-a", "g-b"], "own first, once");
        assert_eq!(reach(&claims("g-b", Some(CHAT)), Some(&access), until), ["g-b", "g-a", "g-own"]);
        assert_eq!(reach(&claims("no-grant", Some(CHAT)), Some(&access), until), ["g-a", "g-own", "g-b"], "a token's name in no list adds nothing, and costs nothing");
        for c in [claims("g-own", None), claims("g-own", Some(OTHER))] {
            assert_eq!(reach(&c, Some(&access), until), ["g-own"], "no entry names it");
        }
        assert_eq!(reach(&claims("g-own", Some(CHAT)), None, until), ["g-own"], "no list");
        assert_eq!(reach(&claims("g-own", Some(CHAT)), Some(&access), until + 1), ["g-own"], "lapsed");
        assert!(reach(&claims("no-grant", None), Some(&access), until).is_empty());
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
