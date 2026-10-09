//! The platform lifecycle hooks on `--hooks-port` (9000): POST
//! `/aws/lambda-microvms/runtime/v1/{ready,validate,run,resume,suspend,terminate}`.
//!
//! Image hooks: `/ready` (503 until the listeners are bound and one claude
//! probe succeeded; the snapshot is taken after the first 200) and
//! `/validate` (checks on a fresh VM; any failure fails the image build).
//! Once `/run` was accepted (a run record exists) `/validate` answers 409
//! `already run` at once and checks nothing: the platform validates only
//! build VMs, which never get `/run`, and the agent exists only after it —
//! its checks would read and walk the agent's own paths under `--home` as
//! root.
//! VM hooks: `/run` once per clone with the Mac's payload (first-wins, see
//! `state`), then `/resume`, `/suspend`, `/terminate`. A 503 on ready or
//! validate is answered at once (the platform retries); a failed or
//! timed-out `/run` may terminate the VM, so `/run` never waits on anything
//! but `--delay-run`.
//!
//! Run report (plan S4 D19): one `ai-env: run-report <json>` line after the
//! first `/run` that answers 200 (never on a replay or a refusal; written
//! off the hook's path) and one per `/terminate` (before its answer, bounded:
//! it is the zombie sample, and the shim stops soon after). See
//! [`sys::run_report`].
//!
//! The agent transport (S6): `/suspend` freezes the spawns' detach graces,
//! sends `event hook_suspend` to every `/agent` socket and closes them
//! (1001, at most 1 s); `/resume` reports the clock, then thaws the graces;
//! `/terminate` drains, sends `event hook_terminate` and closes every
//! socket, stops the spawns (TERM every process group, at most 5 s for the
//! leaders, then KILL the groups whose leader still runs, at most 1 s: the
//! spawn manager's `terminate`), then writes the run report — well inside
//! the 60 s terminate budget. The `/run` and `/resume` clock reports are
//! kept for `/health/detail`.
//!
//! Source policy: every hook arrives from 127.0.0.1 (S4's `hooks-source-ip`
//! probe and every live run since), so an address cannot tell the platform
//! from a process in the VM. `--hook-source peer` (the S6 image default)
//! decides by socket ownership instead (`peer`): a local client owned by the
//! agent uid, or orphaned, is refused 403 `forbidden_peer`. `log` refuses
//! nothing and logs each request's origin and what the guard would decide;
//! `enforce` (S3) refuses runtime hooks from this VM's own addresses and is
//! kept for the native tests, which POST `/run` from outside. Where the guard
//! runs (root on Linux: the image) `/validate` fails under either (V6). `/ready` and
//! `/validate` are never filtered by the source policy (`/validate` refuses
//! by itself after `/run`, above). In every mode each hook line carries the
//! client row's facts (`peer_uid`, `ino`, `st`, `fam`) and the decision, and
//! `/health/detail` keeps the last peer of each runtime hook.
use crate::shim::health::ShimState;
use crate::shim::peer::{self, Decision, PeerFacts};
use crate::shim::state::{Claim, RunRecord};
use crate::shim::sys;
use crate::wire::frame::{CredentialErrCode, EventKind, Frame, HookPeerSeen, RunHookPayload, CLOSE_GOING_AWAY};
use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PREFIX: &str = "/aws/lambda-microvms/runtime/v1";

/// Largest hook body accepted (the payload inside is capped at 4096 bytes).
pub const MAX_BODY: usize = 32 * 1024;

/// `/terminate`'s bound on stopping the spawns: the manager's terminate
/// ladder (TERM, at most 5 s for the leaders, KILL, at most 1 s) with room
/// to spare, well inside the platform's 60 s terminate budget.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HookSource {
    /// Log every hook's origin, refuse nothing (S3 v0)
    Log,
    /// Refuse run/resume/suspend/terminate from this VM itself (loopback or our own address)
    Enforce,
    /// Refuse run/resume/suspend/terminate from a local client owned by the agent uid, or orphaned (S6; Linux)
    Peer,
}

impl HookSource {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            HookSource::Log => "log",
            HookSource::Enforce => "enforce",
            HookSource::Peer => "peer",
        }
    }
}

/// Both ends of a hook connection (the `ConnectInfo` every router shares).
pub use crate::shim::peer::Peer as HookPeer;

/// Where a hook request came from, relative to this VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Loopback,
    /// Our own (non-loopback) address: a process inside the VM.
    SelfAddr,
    Remote,
}

impl Origin {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Origin::Loopback => "loopback",
            Origin::SelfAddr => "self",
            Origin::Remote => "remote",
        }
    }
}

#[must_use]
pub fn origin_of(peer: SocketAddr, local: SocketAddr) -> Origin {
    let (p, l) = (peer::canonical(peer.ip()), peer::canonical(local.ip()));
    if p.is_loopback() {
        Origin::Loopback
    } else if p == l {
        Origin::SelfAddr
    } else {
        Origin::Remote
    }
}

/// The hooks the policy may refuse (the VM hooks; never the image hooks).
#[must_use]
pub fn is_runtime_hook(hook: &str) -> bool {
    matches!(hook, "run" | "resume" | "suspend" | "terminate")
}

/// Is `hook` from `origin` admitted under `policy`? (`peer` is decided by the
/// peer guard, `peer::decide`, not by the origin: see [`gate`].)
#[must_use]
pub fn admit(policy: HookSource, hook: &str, origin: Origin) -> bool {
    policy != HookSource::Enforce || !is_runtime_hook(hook) || origin == Origin::Remote
}

/// What the source policy does with one hook request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Passed: an image hook, or a runtime hook the policy admits.
    Admit,
    /// `log`: passed; the peer guard's decision is only logged.
    Logged(Decision),
    /// `peer`: refused 403 `forbidden_peer`.
    RefusePeer(&'static str),
    /// `enforce`: refused 403 `forbidden_origin`.
    RefuseOrigin(Origin),
}

impl Gate {
    /// The log's `decision=` value.
    #[must_use]
    pub fn shown(self) -> String {
        match self {
            Gate::Admit => "admit".into(),
            Gate::Logged(d) => d.shown(false),
            Gate::RefusePeer(r) => Decision::Refuse(r).shown(true),
            Gate::RefuseOrigin(_) => "refuse:origin".into(),
        }
    }

    /// `HookPeerSeen::decision`.
    #[must_use]
    pub fn recorded(self) -> &'static str {
        match self {
            Gate::Admit => "admitted",
            Gate::Logged(_) => "logged",
            Gate::RefusePeer(_) | Gate::RefuseOrigin(_) => "refused",
        }
    }
}

/// Pure: the gate of `hook` under `policy`, from the client row's facts and
/// the origin (`None` without `ConnectInfo`: `enforce` then admits, as in
/// S3, and `peer` sees no row and refuses).
#[must_use]
pub fn gate(policy: HookSource, hook: &str, facts: &PeerFacts, origin: Option<Origin>, agent_uid: u32) -> Gate {
    if !is_runtime_hook(hook) {
        return Gate::Admit;
    }
    match policy {
        HookSource::Log => Gate::Logged(peer::decide(facts, agent_uid)),
        HookSource::Enforce => match origin {
            Some(o) if !admit(policy, hook, o) => Gate::RefuseOrigin(o),
            _ => Gate::Admit,
        },
        HookSource::Peer => match peer::decide(facts, agent_uid) {
            Decision::Admit => Gate::Admit,
            Decision::Refuse(r) => Gate::RefusePeer(r),
        },
    }
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

/// `/health/detail`'s last peer of a runtime hook.
fn record_hook_peer(state: &ShimState, hook: &str, hp: Option<HookPeer>, facts: &PeerFacts, gate: Gate) {
    let row = facts.row;
    let seen = HookPeerSeen {
        peer: hp.map_or("-".into(), |h| h.peer.to_string()),
        family: row.map(|(f, _)| f),
        uid: row.map(|(_, r)| r.uid),
        inode: row.map(|(_, r)| r.inode),
        decision: gate.recorded().into(),
        at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
    };
    // A refusal is kept apart: it never replaces the platform's admitted record.
    let map = if matches!(gate, Gate::RefusePeer(_) | Gate::RefuseOrigin(_)) { &state.hook_refusals } else { &state.hook_peers };
    map.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(hook.to_string(), seen);
}

/// Every hook request: the source policy ([`gate`]); one log line with both
/// addresses, the origin, body length, status, latency, the client row's
/// facts and the decision; `Connection: close` on every response (no
/// keep-alive socket survives a suspend).
async fn frame(State(state): State<Arc<ShimState>>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let hp = req.extensions().get::<ConnectInfo<HookPeer>>().map(|c| c.0);
    // The lookup comes first: the client's row is surest while its request is in flight.
    let facts = hp.map_or(PeerFacts::UNKNOWN, |h| peer::facts(&h));
    let hook = req.uri().path().strip_prefix(PREFIX).map(|p| p.trim_start_matches('/').to_string()).unwrap_or_else(|| req.uri().path().to_string());
    let len = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let origin = hp.map(|h| origin_of(h.peer, h.local));
    let gate = gate(state.opts.hook_source, &hook, &facts, origin, state.opts.uid);
    if is_runtime_hook(&hook) {
        record_hook_peer(&state, &hook, hp, &facts, gate);
    }
    let mut res = match gate {
        // Drain (bounded) before refusing, as the handlers do: see `ready`.
        Gate::RefusePeer(reason) => {
            peer::count_refusal(&state, hp.map_or(0, |h| h.local.port()));
            let _ = axum::body::to_bytes(req.into_body(), MAX_BODY).await;
            peer::forbidden(reason)
        }
        Gate::RefuseOrigin(o) => {
            let _ = axum::body::to_bytes(req.into_body(), MAX_BODY).await;
            reply(StatusCode::FORBIDDEN, serde_json::json!({"status": "forbidden_origin", "origin": o.name()}))
        }
        Gate::Admit | Gate::Logged(_) => next.run(req).await,
    };
    res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    let (peer, local) = hp.map_or(("-".to_string(), "-".to_string()), |h| (h.peer.to_string(), h.local.to_string()));
    errln!(
        "ai-env: hook {hook} peer={peer} local={local} origin={} len={len} status={} ms={} {} decision={}",
        origin.map_or("-", Origin::name),
        res.status().as_u16(),
        start.elapsed().as_millis(),
        peer::log_fields(Some(&facts)),
        gate.shown()
    );
    res
}

/// An `event` frame for the `/agent` sockets, stamped now.
fn event(kind: EventKind) -> Frame {
    Frame::Event { kind, at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), reference: None }
}

/// Keep `report` as `/health/detail`'s last clock report.
fn keep_clock(state: &ShimState, report: &sys::ClockReport) {
    *state.last_clock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = serde_json::to_value(report).ok();
}

// Every handler takes the body even when it ignores it: answering with
// `Connection: close` while request bytes sit unread makes the kernel send
// RST, and the caller may lose the response.

async fn ready(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    match state.ready() {
        Ok(()) => reply(StatusCode::OK, serde_json::json!({"status": "ready"})),
        Err(waiting) => reply(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "not_ready", "waiting": waiting})),
    }
}

/// The image checks, before `/run` only (see the module doc): after it, 409
/// at once, before the single-flight lock and without any check.
async fn validate(State(state): State<Arc<ShimState>>, conn: Option<Extension<ConnectInfo<HookPeer>>>, _body: Bytes) -> Response {
    if state.run.view().at.is_some() {
        return reply(StatusCode::CONFLICT, serde_json::json!({"status": "already run"}));
    }
    let Ok(_guard) = state.validating.try_lock() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "busy"}));
    };
    let checks = crate::shim::validate::run_checks(&state, conn.map(|Extension(ConnectInfo(p))| p)).await;
    let failed: Vec<String> = checks.iter().filter(|c| !c.ok).map(|c| format!("{}: {}", c.id, c.detail)).collect();
    for c in &checks {
        errln!("ai-env: validate {} {} {}", c.id, if c.ok { "ok" } else { "FAILED" }, c.detail);
    }
    if failed.is_empty() {
        reply(StatusCode::OK, serde_json::json!({"status": "valid"}))
    } else {
        reply(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "invalid", "failed": failed}))
    }
}

/// The `/run` body. Both fields are optional in the platform's model; extra
/// fields are ignored (the platform may add some). Neither is ever a reason
/// to refuse beyond D13's rules: `microvmId` is advisory (stored only when
/// [`sane_id`], else dropped and logged by length), and a missing, null,
/// empty or blank `runHookPayload` is absent (fail-closed 200).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunBody {
    // Values, not strings: an id of an unexpected JSON type must not refuse
    // /run (a refused /run may terminate the VM); a payload of the wrong type
    // is a bad payload, not a bad body.
    microvm_id: Option<serde_json::Value>,
    run_hook_payload: Option<serde_json::Value>,
}

/// An id safe to store, log and show on `/health` (the platform's own shape
/// is "the ARN or ID", up to 256 characters, no pattern).
fn sane_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

async fn run(State(state): State<Arc<ShimState>>, body: Bytes) -> Response {
    let parsed: RunBody = if body.iter().all(u8::is_ascii_whitespace) {
        RunBody { microvm_id: None, run_hook_payload: None }
    } else {
        // An object only (serde's derive would also read a JSON array by
        // position), decided on the first byte so that unknown fields are
        // still skipped unread, whatever they hold.
        let object = body.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'{');
        match if object { serde_json::from_slice::<RunBody>(&body).map_err(|e| e.to_string()) } else { Err("not a JSON object".into()) } {
            Ok(b) => b,
            Err(e) => {
                errln!("ai-env: run body is not the expected JSON object ({e})");
                return reply(StatusCode::BAD_REQUEST, serde_json::json!({"status": "bad_body"}));
            }
        }
    };
    // The raw id never reaches the log or /health (the body hash still
    // covers it, so the nonce stays per-VM).
    let (microvm_id, microvm_log) = match &parsed.microvm_id {
        Some(serde_json::Value::String(id)) if sane_id(id) => (Some(id.clone()), id.clone()),
        Some(serde_json::Value::String(id)) => (None, format!("<unsafe id, {} bytes>", id.len())),
        // (JSON null arrives as None.)
        None => (None, "-".to_string()),
        Some(_) => (None, "<unsafe id, not a string>".to_string()),
    };
    let payload_text = match &parsed.run_hook_payload {
        Some(serde_json::Value::String(text)) if !text.trim().is_empty() => Some(text.as_str()),
        Some(serde_json::Value::String(_)) | None => None,
        Some(_) => {
            errln!("ai-env: run payload refused: runHookPayload is not a string");
            return reply(StatusCode::BAD_REQUEST, serde_json::json!({"status": "bad_payload"}));
        }
    };
    let payload = match payload_text {
        None => None,
        Some(text) => match RunHookPayload::from_json(text) {
            Ok(p) => Some(p),
            Err(crate::wire::frame::WireError::PayloadTooLarge(n)) => {
                return reply(StatusCode::PAYLOAD_TOO_LARGE, serde_json::json!({"status": "payload_too_large", "bytes": n}));
            }
            Err(e) => {
                errln!("ai-env: run payload refused: {e}");
                return reply(StatusCode::BAD_REQUEST, serde_json::json!({"status": "bad_payload"}));
            }
        },
    };
    let body_sha256: [u8; 32] = Sha256::digest(&body).into();
    match state.run.peek(&body_sha256) {
        Some(Claim::Replay) => return reply(StatusCode::OK, serde_json::json!({"status": "ok", "replay": true})),
        Some(Claim::Conflict) => return reply(StatusCode::CONFLICT, serde_json::json!({"status": "already run"})),
        _ => {}
    }
    let id = microvm_id.as_deref().unwrap_or_default();
    let created = payload.as_ref().and_then(|p| crate::wire::time::parse_rfc3339_utc(&p.created));
    // Per-VM material first, so the kernel bytes the nonce draws come after it.
    let (_, now_ns) = state.sys.now();
    let rtc = state.sys.rtc();
    let mut material = Vec::with_capacity(body.len() + 64);
    material.extend_from_slice(&body);
    material.extend_from_slice(id.as_bytes());
    material.extend_from_slice(&now_ns.to_be_bytes());
    material.extend_from_slice(&rtc.unwrap_or(0).to_be_bytes());
    let entropy = sys::refresh_entropy(state.sys.as_ref(), &material);
    let clock = sys::clock_report(state.sys.as_ref(), "run", state.opts.clock, created);
    let boot_nonce = sys::nonce_from(&state.sys.kernel_random(), id, &body_sha256, now_ns, rtc);
    let fail_closed = payload.is_none();
    let claim = state.run.claim(&body_sha256, || RunRecord {
        microvm_id: microvm_id.clone(),
        payload,
        body_sha256,
        at: Instant::now(),
        boot_nonce,
    });
    match claim {
        Claim::Replay => return reply(StatusCode::OK, serde_json::json!({"status": "ok", "replay": true})),
        Claim::Conflict => return reply(StatusCode::CONFLICT, serde_json::json!({"status": "already run"})),
        Claim::First => {}
    }
    errln!("ai-env: run microvm={microvm_log} payload={} {entropy}", if fail_closed { "absent (fail-closed: every hello will be refused)" } else { "ok" });
    errln!("ai-env: clock {}", serde_json::to_string(&clock).unwrap_or_default());
    keep_clock(&state, &clock);
    if state.opts.delay_run > 0 {
        errln!("ai-env: run delayed {} s (--delay-run)", state.opts.delay_run);
        tokio::time::sleep(Duration::from_secs(state.opts.delay_run)).await;
    }
    state.run.mark_seen();
    // Detached: the report reads /proc and statvfs, and /run waits on
    // nothing but --delay-run. Only this (first, accepted) /run gets here.
    drop(tokio::task::spawn_blocking(move || errln!("ai-env: run-report {}", sys::run_report("run", microvm_id.as_deref()))));
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

async fn resume(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    // First: no credential survives a suspend, even one whose hook never ran (S7).
    state.spawns.credential().reopen("resume");
    // Bounded: a stuck clock step must not eat the 30 s resume budget.
    let s = state.clone();
    let report = tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || sys::clock_report(s.sys.as_ref(), "resume", s.opts.clock, None))).await;
    match report {
        Ok(Ok(r)) => {
            errln!("ai-env: clock {}", serde_json::to_string(&r).unwrap_or_default());
            keep_clock(&state, &r);
        }
        _ => errln!("ai-env: clock report on resume did not finish within 5 s"),
    }
    state.spawns.thaw();
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

/// Drop the cached credential and close the cache until `/resume` (S7), then
/// freeze the detach graces, then tell every `/agent` socket and close it (no
/// socket survives a suspend), then answer.
async fn suspend(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    // First: the cached credential goes before the snapshot can take it, and none is accepted until /resume (S7).
    state.spawns.credential().close(CredentialErrCode::Suspended, "suspend");
    state.spawns.freeze();
    state.agents.close_all_with(CLOSE_GOING_AWAY, "suspend", Some(event(EventKind::HookSuspend))).await;
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

/// The first step of both stops, `/terminate` and the shutdown (a stop
/// signal, or init gone): the cached credential goes and the cache closes
/// for good (S7), then the shim drains (new `/agent` upgrades and
/// `credential` frames are refused). One function, so the shutdown runs what
/// `/terminate`'s tests check.
pub(crate) fn begin_stop(state: &ShimState, why: &str) {
    state.spawns.credential().close(CredentialErrCode::Draining, why);
    state.set_draining();
}

async fn terminate(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    // First: the cached credential goes, and none is accepted from here on (S7).
    begin_stop(&state, "terminate");
    state.agents.close_all_with(CLOSE_GOING_AWAY, "terminate", Some(event(EventKind::HookTerminate))).await;
    if tokio::time::timeout(SHUTDOWN_WAIT, state.spawns.terminate()).await.is_err() {
        errln!("ai-env: stopping the spawns on terminate did not finish within {} s", SHUTDOWN_WAIT.as_secs());
    }
    // Logged before the answer (the platform stops the VM soon after), with
    // the id of the accepted /run; bounded like resume's clock report.
    let id = state.run.view().microvm_id;
    let report = tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(move || sys::run_report("terminate", id.as_deref()))).await;
    match report {
        Ok(Ok(r)) => errln!("ai-env: run-report {r}"),
        _ => errln!("ai-env: run report on terminate did not finish within 5 s"),
    }
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

/// The hooks router. Serve it with
/// `into_make_service_with_connect_info::<HookPeer>()` so the log line and
/// the source policy see both addresses.
pub fn router(state: Arc<ShimState>) -> Router {
    Router::new()
        .route(&format!("{PREFIX}/ready"), post(ready))
        .route(&format!("{PREFIX}/validate"), post(validate))
        .route(&format!("{PREFIX}/run"), post(run))
        .route(&format!("{PREFIX}/resume"), post(resume))
        .route(&format!("{PREFIX}/suspend"), post(suspend))
        .route(&format!("{PREFIX}/terminate"), post(terminate))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(state.clone(), frame))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn origin_classification() {
        assert_eq!(origin_of(sa("127.0.0.1:5000"), sa("127.0.0.1:9000")), Origin::Loopback);
        assert_eq!(origin_of(sa("127.0.0.9:5000"), sa("10.0.0.5:9000")), Origin::Loopback);
        assert_eq!(origin_of(sa("[::1]:5000"), sa("[::1]:9000")), Origin::Loopback);
        assert_eq!(origin_of(sa("[::ffff:127.0.0.1]:5000"), sa("10.0.0.5:9000")), Origin::Loopback, "v4-mapped loopback");
        assert_eq!(origin_of(sa("10.0.0.5:5000"), sa("10.0.0.5:9000")), Origin::SelfAddr);
        assert_eq!(origin_of(sa("[::ffff:10.0.0.5]:5000"), sa("10.0.0.5:9000")), Origin::SelfAddr);
        assert_eq!(origin_of(sa("169.254.0.1:5000"), sa("10.0.0.5:9000")), Origin::Remote);
    }

    #[test]
    fn admit_matrix() {
        for hook in ["run", "resume", "suspend", "terminate", "ready", "validate"] {
            for o in [Origin::Loopback, Origin::SelfAddr, Origin::Remote] {
                assert!(admit(HookSource::Log, hook, o), "log admits {hook} from {o:?}");
            }
            assert!(admit(HookSource::Enforce, hook, Origin::Remote), "enforce admits remote {hook}");
        }
        for hook in ["run", "resume", "suspend", "terminate"] {
            assert!(!admit(HookSource::Enforce, hook, Origin::Loopback));
            assert!(!admit(HookSource::Enforce, hook, Origin::SelfAddr));
        }
        for hook in ["ready", "validate"] {
            assert!(admit(HookSource::Enforce, hook, Origin::Loopback), "{hook} is never filtered");
            assert!(admit(HookSource::Enforce, hook, Origin::SelfAddr));
        }
    }

    /// The source policies over the guard's facts: `peer` refuses a local
    /// agent-uid, orphaned or row-less client on the runtime hooks only;
    /// `log` passes everything and reports what `peer` would do; `enforce`
    /// keeps S3's origin rule and ignores the facts.
    #[test]
    fn gate_matrix() {
        use crate::shim::peer::TcpRow;
        let row = |uid, inode| Some((4, TcpRow { local: sa("127.0.0.1:40000"), remote: sa("127.0.0.1:9000"), state: 1, uid, inode }));
        let platform = PeerFacts { local: true, row: row(0, 9) };
        let agent = PeerFacts { local: true, row: row(1000, 9) };
        let orphan = PeerFacts { local: true, row: row(0, 0) };
        let remote = PeerFacts { local: false, row: None };
        let lo = Some(Origin::Loopback);
        for hook in ["run", "resume", "suspend", "terminate"] {
            assert_eq!(gate(HookSource::Peer, hook, &platform, lo, 1000), Gate::Admit, "{hook}: the platform (root, live socket)");
            assert_eq!(gate(HookSource::Peer, hook, &agent, lo, 1000), Gate::RefusePeer("agent_uid"), "{hook}");
            assert_eq!(gate(HookSource::Peer, hook, &orphan, lo, 1000), Gate::RefusePeer("orphaned"), "{hook}");
            assert_eq!(gate(HookSource::Peer, hook, &PeerFacts::UNKNOWN, None, 1000), Gate::RefusePeer("no_row"), "{hook}: no ConnectInfo fails closed");
            assert_eq!(gate(HookSource::Peer, hook, &remote, Some(Origin::Remote), 1000), Gate::Admit, "{hook}: a remote client");
            assert_eq!(gate(HookSource::Log, hook, &agent, lo, 1000), Gate::Logged(Decision::Refuse("agent_uid")), "{hook}");
            assert_eq!(gate(HookSource::Log, hook, &platform, lo, 1000), Gate::Logged(Decision::Admit), "{hook}");
            assert_eq!(gate(HookSource::Enforce, hook, &platform, lo, 1000), Gate::RefuseOrigin(Origin::Loopback), "{hook}: enforce ignores the row");
            assert_eq!(gate(HookSource::Enforce, hook, &agent, Some(Origin::Remote), 1000), Gate::Admit, "{hook}");
            assert_eq!(gate(HookSource::Enforce, hook, &agent, None, 1000), Gate::Admit, "{hook}: S3 admits without ConnectInfo");
        }
        for hook in ["ready", "validate", "nope"] {
            for policy in [HookSource::Log, HookSource::Enforce, HookSource::Peer] {
                assert_eq!(gate(policy, hook, &agent, lo, 1000), Gate::Admit, "{hook} is never filtered under {}", policy.name());
            }
        }
        let shown: Vec<(String, &str)> = [Gate::Admit, Gate::Logged(Decision::Admit), Gate::Logged(Decision::Refuse("no_row")), Gate::RefusePeer("agent_uid"), Gate::RefuseOrigin(Origin::SelfAddr)].iter().map(|g| (g.shown(), g.recorded())).collect();
        assert_eq!(
            shown,
            [("admit".to_string(), "admitted"), ("admit".into(), "logged"), ("would-refuse:no_row".into(), "logged"), ("refuse:agent_uid".into(), "refused"), ("refuse:origin".into(), "refused")]
        );
    }

    #[test]
    fn microvm_ids() {
        assert!(sane_id("mvm-0123abc"));
        assert!(!sane_id(""));
        assert!(!sane_id("mvm 1"));
        assert!(!sane_id(&"a".repeat(129)));
    }
}
