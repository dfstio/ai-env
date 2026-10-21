//! `--code-port` (9418): the code channel. S3 binds the port so the image's
//! listener set is final; S6 puts the peer guard and then the session
//! bearer in front of every path; S8 serves the workspace routes behind
//! them (`wire::workspace`), each run by the agent's helper (`asagent`), and
//! only on a shim that has one (it then names `CAP_WORKSPACE_V1`; without
//! one they answer 404, as an older shim's do):
//! * `GET /seed?path=`: the workspace's `SeedState` (D3's inputs; S10: with
//!   the VM's `.git/shallow`, so the helper answers in the payload form);
//! * `PUT /seed?path=&mode=&branch=|detached=true&expect=`: a
//!   `SeedManifest` line, then the pack; `Content-Length` required (else
//!   411 `bad_request`), at most `SEED_BODY_MAX` (else 413), streamed to the
//!   helper, never buffered; a `SeedReply` (201, or 200 when up to date);
//! * `POST /codeout`: a `CodeoutRequest` (at most `CODEOUT_REQUEST_MAX`);
//!   a `CodeoutManifest` line, then the pack (200), or 204 when nothing is new.
//!
//! One workspace per VM: seed, code-out and snapshot hold the shim's
//! workspace lock (`budget::BUSY_WAIT`, then 409 `busy`), and the shim keeps
//! the last seed's record in memory (`ShimState.workspace`): a seed at
//! another path is 409 `other_workspace`, a clone of a seeded VM 409
//! `changed`, an update or a replace of an unseeded one 409 `not_seeded`.
//!
//! S9 adds git smart-HTTP (`gitcgi`), as `CAP_GIT_HTTP_V1` is named: the
//! literal routes `GET /workspace.git/info/refs?service=git-upload-pack` and
//! `POST /workspace.git/git-upload-pack`, and `/workspace.git/git-receive-pack`
//! (403). Every other path answers 404 `NO_SUCH_ROUTE`.
use crate::shim::asagent::{self, flag, AgentCmd, AgentProc, AgentProcError};
use crate::shim::health::ShimState;
use crate::wire::workspace::{
    budget, refusal, vm_path_check, CodeoutManifest, CodeoutRequest, PathQuery, SeedMode, SeedQuery, SeedReply, SeedState, WsRefusal, CODEOUT_REQUEST_MAX, CODEOUT_ROUTE, SEED_BODY_MAX, SEED_ROUTE,
};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use std::ffi::OsString;
use std::sync::Arc;
use std::time::Instant;

/// The code-port router. Serve it with `into_make_service_with_connect_info::<peer::Peer>()`.
pub fn router(state: Arc<ShimState>) -> Router {
    let mut routes = Router::new();
    if state.serves_workspace() {
        let not_allowed = crate::shim::health::method_not_allowed;
        routes = routes.route(SEED_ROUTE, get(get_seed).put(put_seed).fallback(not_allowed)).route(CODEOUT_ROUTE, post(post_codeout).fallback(not_allowed));
    }
    // S9: git smart-HTTP, as its cap is named (`ShimState::caps`). Every method reaches the
    // handlers, which take §1.3's checks in their order (a receive-pack query before a 405).
    if state.serves_workspace() && crate::shim::gitcgi::SERVED {
        use crate::shim::gitcgi;
        use crate::wire::workspace::{GIT_INFO_REFS_ROUTE, GIT_RECEIVE_PACK_ROUTE, GIT_UPLOAD_PACK_ROUTE};
        routes = routes
            .route(GIT_INFO_REFS_ROUTE, axum::routing::any(gitcgi::info_refs))
            .route(GIT_UPLOAD_PACK_ROUTE, axum::routing::any(gitcgi::upload_pack))
            .route(GIT_RECEIVE_PACK_ROUTE, axum::routing::any(gitcgi::receive_pack));
    }
    // The last layer runs first: the guard, then the bearer.
    routes
        .fallback(crate::shim::auth::not_implemented)
        .layer(from_fn_with_state(state.clone(), crate::shim::auth::code_bearer))
        .layer(from_fn_with_state(state.clone(), crate::shim::peer::guard))
        .with_state(state)
}

// ---- request helpers (both ports) ----------------------------------------------------------

/// The request's query as `T`: 400 `bad_request` naming why.
pub(crate) fn query<T: DeserializeOwned>(req: &Request) -> Result<T, Box<WsRefusal>> {
    axum::extract::Query::<T>::try_from_uri(req.uri()).map(|q| q.0).map_err(|e| Box::new(WsRefusal::new(refusal::BAD_REQUEST, &format!("the query does not parse: {}", e.body_text()))))
}

/// Why a body's length is refused.
pub(crate) enum Length {
    /// No `Content-Length` (a chunked body): 411 with `bad_request`.
    Missing,
    /// Over the route's cap: 413 `too_large` with the size.
    TooLarge(u64, u64),
}

impl Length {
    pub(crate) fn respond(&self, op: &str, started: Instant) -> Response {
        match self {
            Length::Missing => {
                let r = WsRefusal::new(refusal::BAD_REQUEST, "the body has no Content-Length: send its length");
                asagent::log(op, 411, Some(&r.code), started);
                (StatusCode::LENGTH_REQUIRED, Json(r)).into_response()
            }
            Length::TooLarge(len, max) => asagent::refuse(op, started, &WsRefusal::new(refusal::TOO_LARGE, &format!("the body is {len} bytes (at most {max})")).with_size(*len)),
        }
    }
}

/// The body's `Content-Length`, required, at most `max`.
pub(crate) fn content_length(req: &Request, max: u64) -> Result<u64, Length> {
    if req.headers().contains_key(header::TRANSFER_ENCODING) {
        return Err(Length::Missing);
    }
    let len = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()).ok_or(Length::Missing)?;
    if len > max {
        return Err(Length::TooLarge(len, max));
    }
    Ok(len)
}

/// Refuse with `r` after reading the body as every early refusal does (at
/// most `peer::DRAIN_MAX`: the length is not trusted yet).
pub(crate) async fn refuse_draining(op: &str, started: Instant, req: Request, r: &WsRefusal) -> Response {
    crate::shim::peer::drain(req).await;
    asagent::refuse(op, started, r)
}

/// Refuse with `r` after reading the whole body (its `len` bytes, within
/// their transfer time), so the client reads the answer rather than a reset.
pub(crate) async fn refuse_after_body(op: &str, started: Instant, req: Request, len: u64, r: &WsRefusal) -> Response {
    let mut body = req.into_body().into_data_stream();
    let _ = tokio::time::timeout(asagent::transfer(len), async {
        while let Some(Ok(_)) = body.next().await {}
    })
    .await;
    asagent::refuse(op, started, r)
}

fn seeded_elsewhere(record: &crate::wire::workspace::SeedRecord) -> WsRefusal {
    WsRefusal::new(refusal::OTHER_WORKSPACE, &format!("the VM was seeded at {} (one workspace per VM)", record.path)).with_state(SeedState { record: Some(record.clone()), ..SeedState::default() })
}

// ---- GET and PUT /seed ---------------------------------------------------------------------

/// `GET /seed?path=`: the workspace's state, under the workspace lock.
async fn get_seed(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("seed-state", Instant::now());
    let q: PathQuery = match query(&req) {
        Ok(q) => q,
        Err(r) => return asagent::refuse(op, started, &r),
    };
    if let Err(e) = vm_path_check(&q.path) {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the workspace path {e}")));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let Some(_held) = state.workspace.acquire(op).await else { return asagent::refuse(op, started, &asagent::busy(op, asagent::WORKSPACE_HELD, state.workspace.busy_wait())) };
    let record = state.workspace.record();
    if let Some(r) = record.as_ref().filter(|r| r.path != q.path) {
        return asagent::refuse(op, started, &seeded_elsewhere(r));
    }
    let mut args = vec![flag("path", &q.path)];
    if let Some(r) = &record {
        args.push(flag("record", serde_json::to_string(r).unwrap_or_default()));
    }
    let cmd = AgentCmd { op, args, budget: budget::SEED_STATE, stdin: false, during_stop: false };
    // S10: the helper answers in the payload form (`SeedState.shallow` can pass a head line).
    match asagent::run_op_payload::<SeedState>(&state, cmd).await {
        Ok(reply) => {
            asagent::log(op, 200, None, started);
            asagent::answered(200, &reply)
        }
        Err(r) => asagent::refuse(op, started, &r),
    }
}

/// `PUT /seed?…`: the body streamed to the helper's `seed-apply`; the new
/// record kept from its head's state. The run is a task of its own
/// (`asagent::detached`): a client gone meanwhile neither kills the helper
/// before its rollback nor loses the record of a seed that went in.
async fn put_seed(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("seed-apply", Instant::now());
    let q: SeedQuery = match query(&req) {
        Ok(q) => q,
        Err(r) => return refuse_draining(op, started, req, &r).await,
    };
    if let Err(e) = q.check() {
        return refuse_draining(op, started, req, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the seed query {e}"))).await;
    }
    let len = match content_length(&req, SEED_BODY_MAX) {
        Ok(len) => len,
        Err(stop) => {
            crate::shim::peer::drain(req).await;
            return stop.respond(op, started);
        }
    };
    if state.is_draining() {
        return refuse_draining(op, started, req, &AgentProcError::Draining.refusal(op)).await;
    }
    let Some(held) = state.workspace.acquire(op).await else { return refuse_after_body(op, started, req, len, &asagent::busy(op, asagent::WORKSPACE_HELD, state.workspace.busy_wait())).await };
    let record = state.workspace.record();
    let early = match (&record, q.mode) {
        (Some(r), _) if r.path != q.path => Some(seeded_elsewhere(r)),
        (Some(r), SeedMode::Clone) => Some(WsRefusal::new(refusal::CHANGED, "the VM was seeded meanwhile: read its state again").with_state(SeedState { record: Some(r.clone()), ..SeedState::default() })),
        (None, SeedMode::Update | SeedMode::Replace) => Some(WsRefusal::new(refusal::NOT_SEEDED, &format!("the VM was never seeded: nothing to {}", q.mode.name()))),
        _ => None,
    };
    if let Some(r) = early {
        drop(held);
        return refuse_after_body(op, started, req, len, &r).await;
    }
    let mut args: Vec<OsString> = vec![flag("path", &q.path), flag("mode", q.mode.name())];
    match &q.branch {
        Some(b) => args.push(flag("branch", b)),
        None => args.push("--detached".into()),
    }
    if let Some(e) = &q.expect {
        args.push(flag("expect", e));
    }
    args.push(flag("len", len.to_string()));
    if let Some(r) = &record {
        args.push(flag("record", serde_json::to_string(r).unwrap_or_default()));
    }
    let cmd = AgentCmd { op, args, budget: q.mode.budget() + asagent::transfer(len), stdin: true, during_stop: false };
    let body = req.into_body();
    asagent::detached(op, started, async move {
        let out = asagent::run_with_body::<SeedReply>(&state, cmd, body).await;
        if let Ok(head) = &out {
            // The helper runs as the agent: only a record of this very seed is kept.
            if let (true, Some(SeedState { record: Some(r), .. })) = (head.ok, &head.state) {
                if r.path == q.path && r.mode == q.mode {
                    state.workspace.set_record(r.clone());
                } else {
                    errln!("ai-env: workspace {op}: the helper's record names another seed: not kept");
                }
            }
        }
        drop(held);
        asagent::respond(op, started, out, |r| r.outcome.status())
    })
    .await
}

// ---- POST /codeout -------------------------------------------------------------------------

/// `POST /codeout`: the helper's snapshot (with `wip`) and pack; its
/// manifest line, then the pack streamed from it, the workspace held until
/// the run ended; 204 when nothing is new. Up to its head the run is a task
/// of its own (`asagent::detached`): a client gone meanwhile never ends it
/// mid-snapshot; past the head, a body dropped ends it (its pack already
/// left the inbox). A head announcing more than `max_bytes` is 413: the
/// helper runs as the agent.
async fn post_codeout(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("codeout", Instant::now());
    let body = match axum::body::to_bytes(req.into_body(), CODEOUT_REQUEST_MAX).await {
        Ok(b) => b,
        Err(_) => return asagent::refuse(op, started, &WsRefusal::new(refusal::TOO_LARGE, &format!("the code-out request is over {CODEOUT_REQUEST_MAX} bytes"))),
    };
    let creq: CodeoutRequest = match serde_json::from_slice(&body) {
        Ok(c) => c,
        Err(e) => return asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the code-out request does not parse: {e}"))),
    };
    if let Err(e) = creq.check() {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the code-out request {e}")));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let Some(held) = state.workspace.acquire(op).await else { return asagent::refuse(op, started, &asagent::busy(op, asagent::WORKSPACE_HELD, state.workspace.busy_wait())) };
    match state.workspace.record() {
        None => return asagent::refuse(op, started, &WsRefusal::new(refusal::NOT_SEEDED, "the VM was never seeded: nothing to code out")),
        Some(r) if r.path != creq.path => return asagent::refuse(op, started, &seeded_elsewhere(&r)),
        Some(_) => {}
    }
    let mut args: Vec<OsString> = vec![flag("path", &creq.path)];
    if creq.wip {
        args.push("--wip".into());
    }
    args.push(flag("max-bytes", creq.max_bytes.to_string()));
    let cmd = AgentCmd { op, args, budget: budget::CODEOUT, stdin: true, during_stop: false };
    asagent::detached(op, started, async move {
        let mut proc = match AgentProc::start(&state, cmd).await {
            Ok(p) => p,
            Err(e) => return asagent::refuse(op, started, &e.refusal(op)),
        };
        if let Some(mut w) = proc.take_stdin() {
            use tokio::io::AsyncWriteExt as _;
            let haves = serde_json::to_vec(&creq.haves).unwrap_or_default();
            let _ = tokio::time::timeout_at(proc.deadline(), w.write_all(&haves)).await;
        }
        let head = match proc.head::<CodeoutManifest>().await {
            Ok(h) => h,
            Err(e) => {
                proc.stop().await;
                return asagent::refuse(op, started, &e.refusal(op));
            }
        };
        match head.outcome() {
            Some(Ok((manifest, len))) => {
                if let Some(w) = &manifest.wip_ref {
                    state.workspace.wip_made(w);
                }
                let Some(len) = len else {
                    if let Err(e) = proc.finish().await {
                        return asagent::refuse(op, started, &e.refusal(op));
                    }
                    asagent::log(op, 204, None, started);
                    return StatusCode::NO_CONTENT.into_response();
                };
                if len > creq.max_bytes {
                    proc.stop().await;
                    return asagent::refuse(op, started, &WsRefusal::new(refusal::TOO_LARGE, &format!("the code-out pack is {len} bytes (at most {} asked)", creq.max_bytes)).with_size(len));
                }
                let line = match asagent::framed_head(&manifest) {
                    Ok(l) => l,
                    Err(e) => {
                        proc.stop().await;
                        return asagent::refuse(op, started, &WsRefusal::new(refusal::GIT_FAILED, &format!("the code-out manifest does not frame: {e}")));
                    }
                };
                let total = line.len() as u64 + len;
                asagent::log(op, 200, None, started);
                let mut res = Response::new(proc.into_body(line, len, Some(held)));
                res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
                res.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(total));
                res
            }
            Some(Err(r)) => {
                if let Err(e) = proc.finish().await {
                    errln!("ai-env: workspace {op} helper ended badly after its refusal: {}", e.refusal(op).message);
                }
                asagent::refuse(op, started, &r)
            }
            None => {
                proc.stop().await;
                asagent::refuse(op, started, &AgentProcError::BadHead("neither a reply nor a refusal".into()).refusal(op))
            }
        }
    })
    .await
}
