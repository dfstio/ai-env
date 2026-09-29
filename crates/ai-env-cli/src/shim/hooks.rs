//! The platform lifecycle hooks on `--hooks-port` (9000): POST
//! `/aws/lambda-microvms/runtime/v1/{ready,validate,run,resume,suspend,terminate}`.
//!
//! Image hooks: `/ready` (503 until the listeners are bound and one claude
//! probe succeeded; the snapshot is taken after the first 200) and
//! `/validate` (checks on a fresh VM; any failure fails the image build).
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
//! Source policy: where hook requests come from is documented nowhere, so S3
//! only LOGS each request's origin (`--hook-source log`, the image default).
//! `enforce` refuses runtime hooks from this VM itself (loopback or our own
//! address) and is exercised by the tests; S6 turns it on once S4's
//! `hooks-source-ip` probe has data and an untrusted process first runs in
//! the VM. `/ready` and `/validate` are never filtered.
use crate::shim::health::ShimState;
use crate::shim::state::{Claim, RunRecord};
use crate::shim::sys;
use crate::wire::frame::RunHookPayload;
use axum::body::Bytes;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::serve::IncomingStream;
use axum::{Json, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

pub const PREFIX: &str = "/aws/lambda-microvms/runtime/v1";

/// Largest hook body accepted (the payload inside is capped at 4096 bytes).
pub const MAX_BODY: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HookSource {
    /// Log every hook's origin, refuse nothing (S3 v0)
    Log,
    /// Refuse run/resume/suspend/terminate from this VM itself (loopback or our own address)
    Enforce,
}

/// Both ends of a hook connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookPeer {
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

impl Connected<IncomingStream<'_, TcpListener>> for HookPeer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        let peer = *stream.remote_addr();
        let local = stream.io().local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        HookPeer { peer, local }
    }
}

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

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[must_use]
pub fn origin_of(peer: SocketAddr, local: SocketAddr) -> Origin {
    let (p, l) = (canonical(peer.ip()), canonical(local.ip()));
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

/// Is `hook` from `origin` admitted under `policy`?
#[must_use]
pub fn admit(policy: HookSource, hook: &str, origin: Origin) -> bool {
    policy == HookSource::Log || !is_runtime_hook(hook) || origin == Origin::Remote
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    (status, Json(body)).into_response()
}

/// Every hook request: one log line with both addresses, the origin, body
/// length, status and latency; `Connection: close` on every response (no
/// keep-alive socket survives a suspend); the source policy.
async fn frame(State(state): State<Arc<ShimState>>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let hook = req.uri().path().strip_prefix(PREFIX).map(|p| p.trim_start_matches('/').to_string()).unwrap_or_else(|| req.uri().path().to_string());
    let hp = req.extensions().get::<ConnectInfo<HookPeer>>().map(|c| c.0);
    let len = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let origin = hp.map(|h| origin_of(h.peer, h.local));
    let mut res = match origin {
        Some(o) if !admit(state.opts.hook_source, &hook, o) => {
            // Drain (bounded) before refusing, as the handlers do: see `ready`.
            let _ = axum::body::to_bytes(req.into_body(), MAX_BODY).await;
            reply(StatusCode::FORBIDDEN, serde_json::json!({"status": "forbidden_origin", "origin": o.name()}))
        }
        _ => next.run(req).await,
    };
    res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    let (peer, local) = hp.map_or(("-".to_string(), "-".to_string()), |h| (h.peer.to_string(), h.local.to_string()));
    errln!(
        "ai-env: hook {hook} peer={peer} local={local} origin={} len={len} status={} ms={}",
        origin.map_or("-", Origin::name),
        res.status().as_u16(),
        start.elapsed().as_millis()
    );
    res
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

async fn validate(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    let Ok(_guard) = state.validating.try_lock() else {
        return reply(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({"status": "busy"}));
    };
    let checks = crate::shim::validate::run_checks(&state).await;
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
    if state.opts.delay_run > 0 {
        errln!("ai-env: run delayed {} s (--delay-run)", state.opts.delay_run);
        tokio::time::sleep(std::time::Duration::from_secs(state.opts.delay_run)).await;
    }
    state.run.mark_seen();
    // Detached: the report reads /proc and statvfs, and /run waits on
    // nothing but --delay-run. Only this (first, accepted) /run gets here.
    drop(tokio::task::spawn_blocking(move || errln!("ai-env: run-report {}", sys::run_report("run", microvm_id.as_deref()))));
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

async fn resume(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    // Bounded: a stuck clock step must not eat the 30 s resume budget.
    let s = state.clone();
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), tokio::task::spawn_blocking(move || sys::clock_report(s.sys.as_ref(), "resume", s.opts.clock, None))).await;
    match report {
        Ok(Ok(r)) => errln!("ai-env: clock {}", serde_json::to_string(&r).unwrap_or_default()),
        _ => errln!("ai-env: clock report on resume did not finish within 5 s"),
    }
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

async fn suspend(_body: Bytes) -> Response {
    reply(StatusCode::OK, serde_json::json!({"status": "ok"}))
}

async fn terminate(State(state): State<Arc<ShimState>>, _body: Bytes) -> Response {
    state.set_draining();
    // Logged before the answer (the platform stops the VM soon after), with
    // the id of the accepted /run; bounded like resume's clock report.
    let id = state.run.view().microvm_id;
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), tokio::task::spawn_blocking(move || sys::run_report("terminate", id.as_deref()))).await;
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

    #[test]
    fn microvm_ids() {
        assert!(sane_id("mvm-0123abc"));
        assert!(!sane_id(""));
        assert!(!sane_id("mvm 1"));
        assert!(!sane_id(&"a".repeat(129)));
    }
}
