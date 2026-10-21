//! The data-plane client (S8 §10): the seed, code-out, transcript and
//! settings routes of a VM's shim through the MicroVM endpoint (9418 and
//! 8080, one client per port, bodies streamed with `Content-Length`), the
//! endpoint tokens they need (minted in memory, never written), and the
//! mapping of each status onto the bridge's errors and exit codes. Built in
//! S8 wave 1 (W4) on what S8 phase 0 froze here: the [`TokenSource`] and
//! [`DataPlane`] traits ([`HttpsEndpoint`] and [`MintingTokens`] implement
//! them, the tests' fakes too), a route's answer ([`DpReply`]), the pure
//! status mapper ([`verdict`]) and the client's budgets; the exchange that
//! acts on each verdict (re-mint, wait, retry, ask GetMicrovm) is
//! `exchange`. The wire's types and its refusal codes are
//! `wire::workspace`'s; a URL with a query is `vm::health::endpoint_url_query`.
//!
//! S9 (frozen in S9 phase 0): the transcript store's five routes join
//! [`DataPlane`] as default methods that fail closed (an implementation that
//! serves them overrides them; `HttpsEndpoint`'s are G4's), each exchange
//! names the capability a 404 means the VM lacks (`Exchange.cap`,
//! [`verdict_cap`]), and [`HttpsEndpoint`] sends a raw body with extra
//! headers (`send_with`, `Payload::Bytes`) for git smart-HTTP's client
//! (`gitsmart::GitHttp`, G2's).
use crate::bridge::agent::AgentTarget;
use crate::bridge::api::AuthToken;
use crate::bridge::errors::BridgeError;
use crate::bridge::workspace::KeptReason;
use crate::wire::frame::CAP_WORKSPACE_V1;
use crate::wire::workspace::{
    known_refusal, refusal, CodeoutManifest, CodeoutRequest, SeedQuery, SeedReply, SeedState, SettingsCapture, TranscriptStat, WsRefusal,
};
use crate::wire::workspace::{StatQuery, TranscriptPull, TranscriptPullReply, TranscriptPush, TranscriptPushReply, TranscriptTail, ViewQuery};
use std::future::Future;
use std::path::Path;
use std::time::Duration;

/// The base of a request's budget, before the transfer and the helper's
/// own budget ([`request_timeout`]).
pub const REQUEST_BASE: Duration = Duration::from_secs(30);
/// The slowest transfer a budget allows for, in bytes per second (1 MB/s).
pub const MIN_RATE: u64 = 1_000_000;
/// The minutes of a `Port(9418)` token for a seed (a first seed may take
/// `wire::workspace::budget::SEED_CLONE` and its upload).
pub const TOKEN_MINUTES_SEED: u16 = 15;
/// The minutes of every other data-plane token (9418 for a state or a
/// code-out, 8080 for a transcript or the settings).
pub const TOKEN_MINUTES: u16 = 5;
/// A cached token with less than this left is minted again before use.
pub const REMINT_BELOW: Duration = Duration::from_secs(60);
/// How long a 409 `busy` is retried, in all, before it is the error (exit 1).
pub const BUSY_RETRY: Duration = Duration::from_secs(30);

/// The budget of one data-plane request (plan §10): [`REQUEST_BASE`], plus
/// `bytes` at [`MIN_RATE`] (the body sent or the most that may come back),
/// plus the helper's budget in the VM (`wire::workspace::budget`).
#[must_use]
pub fn request_timeout(bytes: u64, helper: Duration) -> Duration {
    REQUEST_BASE + Duration::from_secs(bytes.div_ceil(MIN_RATE)) + helper
}

/// How long the Mac waits for `POST /transcript/pull` (S10): the pull's
/// budget as the shim counts its deadline and the presigned GETs their
/// lifetime (`wire::workspace::budget::pull_budget` of its parts' bytes
/// and its `share`, the pulls running beside it, which split the VM's
/// downlink). At share 1 it is S9's [`request_timeout`] of those bytes and
/// `budget::TRANSCRIPT_PULL`.
#[must_use]
pub fn pull_timeout(req: &TranscriptPull) -> Duration {
    crate::wire::workspace::budget::pull_budget(req.parts.iter().map(|p| p.len).sum::<u64>(), req.share)
}

/// The endpoint tokens of one VM, by port. W4's `MintingTokens` keeps them
/// in memory only (never in a row or a file), mints with the wrapper's own
/// API object (D1), and mints again below [`REMINT_BELOW`].
pub trait TokenSource: Send + Sync {
    /// A token for `port` (`wire::workspace::CODE_PORT` or `APP_PORT`).
    fn token(&self, port: u16) -> impl Future<Output = Result<AuthToken, BridgeError>> + Send;

    /// Drop `port`'s cached token (the endpoint answered 401 or 403), so the
    /// next [`TokenSource::token`] mints a new one. The default keeps
    /// nothing to drop.
    fn forget(&self, port: u16) {
        let _ = port;
    }
}

/// One answer of a workspace route: any HTTP status is `Ok(DpReply)`, so
/// [`verdict`] decides; an `Err` is a transport failure (connect, TLS, a
/// timeout) as `EndpointClient`'s: `Endpoint` may be retried, any other is final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpReply<T> {
    pub status: u16,
    /// The parsed body of a 200 or 201 (none for a 204).
    pub body: Option<T>,
    /// The parsed [`WsRefusal`] of a 4xx or 5xx the shim answered (none
    /// when the endpoint's proxy answered, or the body did not parse).
    pub refusal: Option<WsRefusal>,
    /// The proxy's `x-aws-proxy-error`, scrubbed.
    pub proxy_error: Option<String>,
    /// `Retry-After` in seconds.
    pub retry_after_s: Option<u64>,
}

impl<T> DpReply<T> {
    /// A status with nothing else (a 204, a bare proxy answer).
    #[must_use]
    pub fn status(status: u16) -> DpReply<T> {
        DpReply { status, body: None, refusal: None, proxy_error: None, retry_after_s: None }
    }

    /// A 200 or 201 with its body.
    #[must_use]
    pub fn ok(status: u16, body: T) -> DpReply<T> {
        DpReply { body: Some(body), ..DpReply::status(status) }
    }

    /// The shim's refusal, with its code's status.
    #[must_use]
    pub fn refused(refusal: WsRefusal) -> DpReply<T> {
        DpReply { refusal: Some(refusal.clone()), ..DpReply::status(refusal.status()) }
    }
}

/// What a 200 to `POST /codeout` left: its manifest line, parsed, and the
/// pack written to the destination file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeoutBody {
    pub manifest: CodeoutManifest,
    /// The pack's bytes in the destination file.
    pub pack_bytes: u64,
}

/// The workspace routes of a VM's shim (`wire::workspace`), through the
/// endpoint with `token`'s headers and the session bearer of `target`. W4's
/// `HttpsEndpoint` implements it (one `reqwest` client per port, from
/// `tls::reqwest_client()`; `tls::lab_http_client` under the lab's agent
/// address); every call answers by [`request_timeout`].
pub trait DataPlane: Send + Sync {
    /// `GET /seed?path=` (9418).
    fn seed_state(&self, target: &AgentTarget, token: &AuthToken, path: &str) -> impl Future<Output = Result<DpReply<SeedState>, BridgeError>> + Send;

    /// `PUT /seed?…` (9418) with `body` as the body (a `SeedManifest` line,
    /// then the pack), `len` bytes, streamed with `Content-Length`.
    fn put_seed(&self, target: &AgentTarget, token: &AuthToken, query: &SeedQuery, body: &Path, len: u64) -> impl Future<Output = Result<DpReply<SeedReply>, BridgeError>> + Send;

    /// `POST /codeout` (9418): a 200's manifest line is parsed and checked,
    /// its pack written to `dest` (created 0600, never past `cap` bytes:
    /// more is `WorkspaceRefused { too_large }`); a 204 leaves `dest` alone.
    fn post_codeout(&self, target: &AgentTarget, token: &AuthToken, req: &CodeoutRequest, dest: &Path, cap: u64) -> impl Future<Output = Result<DpReply<CodeoutBody>, BridgeError>> + Send;

    /// `GET /transcript?rel=` (8080).
    fn transcript_stat(&self, target: &AgentTarget, token: &AuthToken, rel: &str) -> impl Future<Output = Result<DpReply<TranscriptStat>, BridgeError>> + Send;

    /// `GET /settings?path=` (8080).
    fn get_settings(&self, target: &AgentTarget, token: &AuthToken, path: &str) -> impl Future<Output = Result<DpReply<SettingsCapture>, BridgeError>> + Send;

    // S9: the transcript store's routes, each `cap` transcript_s3_v1. The
    // defaults fail closed (`Config`, exit 1): a data plane that serves one
    // overrides it.

    /// `GET /transcript?rel=&from=&fp=&subtree=` (8080), `cap` transcript_s3_v1.
    fn transcript_stat_from(&self, target: &AgentTarget, token: &AuthToken, q: &StatQuery) -> impl Future<Output = Result<DpReply<TranscriptStat>, BridgeError>> + Send {
        let _ = (target, token, q);
        async { Err(unserved("GET /transcript")) }
    }

    /// `POST /transcript/push` (8080).
    fn transcript_push(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptPush) -> impl Future<Output = Result<DpReply<TranscriptPushReply>, BridgeError>> + Send {
        let _ = (target, token, req);
        async { Err(unserved("POST /transcript/push")) }
    }

    /// `POST /transcript/pull` (8080): 200 and 201 both carry the reply.
    fn transcript_pull(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptPull) -> impl Future<Output = Result<DpReply<TranscriptPullReply>, BridgeError>> + Send {
        let _ = (target, token, req);
        async { Err(unserved("POST /transcript/pull")) }
    }

    /// `GET /transcript/view?rel=&n=` (8080).
    fn transcript_view(&self, target: &AgentTarget, token: &AuthToken, q: &ViewQuery) -> impl Future<Output = Result<DpReply<crate::wire::view::TranscriptViewReply>, BridgeError>> + Send {
        let _ = (target, token, q);
        async { Err(unserved("GET /transcript/view")) }
    }

    /// `POST /transcript/tail` (8080): 204.
    fn transcript_tail(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptTail) -> impl Future<Output = Result<DpReply<()>, BridgeError>> + Send {
        let _ = (target, token, req);
        async { Err(unserved("POST /transcript/tail")) }
    }
}

/// What a data plane answers for a route it does not serve (S9's defaults).
fn unserved(route: &str) -> BridgeError {
    BridgeError::Config(format!("{route}: this data plane does not serve it (S9)"))
}

/// What the caller does with one answer (plan §10).
#[derive(Debug)]
pub enum Verdict {
    /// 200, 201 or 204: the answer stands.
    Done,
    /// 401 or 403: [`TokenSource::forget`] the port's token and send once
    /// more with a new one; a second refusal is `error` (exit 7).
    Remint { error: BridgeError },
    /// 409 `dirty` or `diverged`: the VM keeps its state (D3), not an error;
    /// `state` is the VM's as the refusal carried it.
    Kept { reason: KeptReason, state: Option<SeedState> },
    /// 409 `changed`: the tip moved between `GET /seed` and the write: read
    /// the state once more and decide again; a second `changed` is `error` (exit 9).
    Reread { error: BridgeError },
    /// 409 `busy`: another seed, code-out or snapshot holds the workspace:
    /// send again for at most [`BUSY_RETRY`]; then `error` (exit 1).
    Busy { error: BridgeError },
    /// 429: wait `Retry-After` (else a second), then send once more; a
    /// second 429 is `error` (exit 7).
    Throttled { retry_after_s: Option<u64>, error: BridgeError },
    /// 502 or 503, the shim's `draining` included (a suspend drains it as a
    /// terminate does, and the next request resumes the VM): ask GetMicrovm;
    /// a VM gone (TERMINATING, TERMINATED, not found) is exit 8, else `error`
    /// (exit 7).
    CheckVm { error: BridgeError },
    /// Final: this error, with the bridge's exit code (7, 8, 9 or 1).
    Fail(BridgeError),
}

/// The code a refusal carries, as a constant (`unknown` for a code this
/// build does not know, or none), and the refusal's text.
fn code_and_message<T>(reply: &DpReply<T>, route: &str) -> (&'static str, String) {
    let proxy = reply.proxy_error.as_deref().map(|p| format!(" (x-aws-proxy-error: {p})")).unwrap_or_default();
    match &reply.refusal {
        Some(r) => match known_refusal(&r.code) {
            Some(code) => (code, format!("{route}: {}", r.message)),
            None => ("unknown", format!("{route}: {} ({})", r.message, r.code)),
        },
        None => ("unknown", format!("{route} answered HTTP {}{proxy}", reply.status)),
    }
}

/// How one answer of `route` (`"PUT /seed"`, …) on `port` is acted on
/// (plan §10): 401/403 re-mint once, then exit 7; 404 is an image without
/// [`CAP_WORKSPACE_V1`] (`NoCapability`, exit 7); 409 `dirty` and `diverged`
/// keep the VM's state, `changed` re-reads once, `busy` retries for 30 s, any other code is
/// `WorkspaceRefused` (exit 9); 400, and 411 (no `Content-Length`), are
/// `WorkspaceRefused { bad_request }` (the VM refused what the Mac had
/// checked: a version skew, exit 9); 413 is `WorkspaceRefused { too_large }`
/// (9); 422, 500 and 504 are `WorkspaceFailed` (1) with the refusal's code
/// (else `bad_pack`, `git_failed`, `timeout`); 429 waits `Retry-After`, then
/// exit 7; 502 and 503 (the shim's `draining` too) ask GetMicrovm (gone: 8),
/// then exit 7; any other status is `Http` (7). Pure: no I/O. Its 404 names
/// `workspace_v1` ([`verdict_cap`] names another capability).
#[must_use]
pub fn verdict<T>(route: &str, port: u16, reply: &DpReply<T>) -> Verdict {
    verdict_cap(route, port, CAP_WORKSPACE_V1, reply)
}

/// [`verdict`]'s table with a 404 naming `cap` (S9): the capability the
/// route's VM lacks, `NoCapability` (exit 7, `make deploy`).
#[must_use]
pub fn verdict_cap<T>(route: &str, port: u16, cap: &'static str, reply: &DpReply<T>) -> Verdict {
    let status = reply.status;
    let (code, message) = code_and_message(reply, route);
    let refused = |fallback: &'static str| BridgeError::WorkspaceRefused { code: if code == "unknown" { fallback } else { code }, message: message.clone() };
    let failed = |fallback: &'static str| BridgeError::WorkspaceFailed { code: if code == "unknown" { fallback } else { code }, message: message.clone() };
    match status {
        200 | 201 | 204 => Verdict::Done,
        400 | 411 => Verdict::Fail(refused(refusal::BAD_REQUEST)),
        401 | 403 => Verdict::Remint { error: BridgeError::TokenRejected { port, status, proxy_error: reply.proxy_error.clone() } },
        404 => Verdict::Fail(BridgeError::NoCapability { cap, message: format!("{route} answered 404") }),
        409 => match code {
            refusal::DIRTY => Verdict::Kept { reason: KeptReason::Dirty, state: reply.refusal.as_ref().and_then(|r| r.state.clone()) },
            refusal::DIVERGED => Verdict::Kept { reason: KeptReason::Diverged, state: reply.refusal.as_ref().and_then(|r| r.state.clone()) },
            refusal::CHANGED => Verdict::Reread { error: refused(refusal::CHANGED) },
            refusal::BUSY => Verdict::Busy { error: BridgeError::Busy(message) },
            _ => Verdict::Fail(refused("conflict")),
        },
        413 => Verdict::Fail(refused(refusal::TOO_LARGE)),
        422 => Verdict::Fail(failed(refusal::BAD_PACK)),
        500 => Verdict::Fail(failed(refusal::GIT_FAILED)),
        504 => Verdict::Fail(failed(refusal::TIMEOUT)),
        429 => Verdict::Throttled { retry_after_s: reply.retry_after_s, error: BridgeError::EndpointThrottled { retry_after_s: reply.retry_after_s } },
        502 | 503 => Verdict::CheckVm { error: BridgeError::Http { status, body: message } },
        _ => Verdict::Fail(BridgeError::Http { status, body: message }),
    }
}

// ---- the driver ----------------------------------------------------------------------------

/// What one data-plane exchange needs besides the request itself: the
/// control plane (GetMicrovm after a 502 or 503), the tokens, the VM, the
/// port and the route (its name in errors), the deadline it answers by.
pub(crate) struct Exchange<'a, A, T> {
    pub api: &'a A,
    pub tokens: &'a T,
    pub vm_id: &'a str,
    pub port: u16,
    /// The capability a 404 means the VM lacks (`workspace_v1`, S9's `git_http_v1` or `transcript_s3_v1`).
    pub cap: &'static str,
    pub route: &'static str,
    pub deadline: Option<tokio::time::Instant>,
    /// A transport failure (connect, reset) is tried once more: only for a
    /// request that changes nothing in the VM (a `GET`).
    pub idempotent: bool,
}

/// Send one request through `send` (handed a token each time) until its
/// answer stands, as plan §10 drives it: a 401 or 403 forgets the port's
/// token and sends once more, a 429 waits its `Retry-After` (else a second)
/// and sends once more, a 409 `busy` is sent again every second for
/// [`BUSY_RETRY`], a 502 or 503 asks GetMicrovm (a VM that is gone is exit
/// 8, else the answer's error, exit 7); a transport failure of an
/// idempotent request is tried once more. The answer and its verdict come
/// back for [`Verdict::Done`], [`Verdict::Kept`] and [`Verdict::Reread`];
/// every other verdict is its error. Past the
/// deadline nothing more is sent: `WorkspaceFailed { too_slow_for_init }`.
pub(crate) async fn exchange<A, T, R, F, Fut>(x: &Exchange<'_, A, T>, mut send: F) -> Result<(DpReply<R>, Verdict), BridgeError>
where
    A: crate::bridge::api::MicrovmApi,
    T: TokenSource,
    F: FnMut(AuthToken) -> Fut,
    Fut: Future<Output = Result<DpReply<R>, BridgeError>>,
{
    let late = || BridgeError::WorkspaceFailed {
        code: crate::bridge::workspace::code::TOO_SLOW_FOR_INIT,
        message: format!("{} did not answer before the session's deadline: `ai-env vm warm` or `ai-env box seed` from a terminal prepares the VM ahead", x.route),
    };
    let (mut reminted, mut throttled, mut transport) = (false, false, false);
    let mut busy_since: Option<tokio::time::Instant> = None;
    loop {
        if x.deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            return Err(late());
        }
        let token = x.tokens.token(x.port).await?;
        let reply = match x.deadline {
            Some(d) => tokio::time::timeout_at(d, send(token)).await.map_err(|_| late())?,
            None => send(token).await,
        };
        let reply = match reply {
            Ok(r) => r,
            Err(BridgeError::Endpoint(m)) if x.idempotent && !transport => {
                transport = true;
                tracing::info!("{}: {m}; trying once more", x.route);
                pause(x.deadline, Duration::from_secs(1)).await.map_err(|()| late())?;
                continue;
            }
            Err(e) => return Err(e),
        };
        match verdict_cap(x.route, x.port, x.cap, &reply) {
            v @ (Verdict::Done | Verdict::Kept { .. } | Verdict::Reread { .. }) => return Ok((reply, v)),
            Verdict::Remint { error } => {
                if reminted {
                    return Err(error);
                }
                reminted = true;
                x.tokens.forget(x.port);
            }
            Verdict::Throttled { retry_after_s, error } => {
                if throttled {
                    return Err(error);
                }
                throttled = true;
                pause(x.deadline, throttle_wait(retry_after_s)).await.map_err(|()| error)?;
            }
            Verdict::Busy { error } => {
                let since = *busy_since.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= BUSY_RETRY {
                    return Err(error);
                }
                pause(x.deadline, Duration::from_secs(1)).await.map_err(|()| error)?;
            }
            Verdict::CheckVm { error } => {
                return Err(match x.api.get(x.vm_id).await {
                    Ok(vm) if vm.state.is_terminal() => BridgeError::Terminated(format!("{} is {} ({} answered HTTP {})", x.vm_id, vm.state.as_str(), x.route, reply.status)),
                    Err(e @ BridgeError::VmNotFound(_)) => e,
                    _ => error,
                });
            }
            Verdict::Fail(e) => return Err(e),
        }
    }
}

/// The longest a 429's `Retry-After` is waited (a longer one is cut to it).
pub const THROTTLE_WAIT_MAX: Duration = Duration::from_secs(30);

/// How long a 429 is waited before the request goes once more: its
/// `Retry-After` (else a second), at least a second and at most
/// [`THROTTLE_WAIT_MAX`]: the VM's number would otherwise hold the caller,
/// and the locks it holds (the fetch lock, a manifest's), for as long as it
/// says.
fn throttle_wait(retry_after_s: Option<u64>) -> Duration {
    Duration::from_secs(retry_after_s.unwrap_or(1).clamp(1, THROTTLE_WAIT_MAX.as_secs()))
}

/// Sleep `d`, or `Err` when that would pass `deadline` (or no instant is `d` away).
async fn pause(deadline: Option<tokio::time::Instant>, d: Duration) -> Result<(), ()> {
    let Some(until) = tokio::time::Instant::now().checked_add(d) else { return Err(()) };
    if deadline.is_some_and(|dl| until > dl) {
        return Err(());
    }
    tokio::time::sleep_until(until).await;
    Ok(())
}

// ---- the tokens ----------------------------------------------------------------------------

/// The endpoint tokens of one VM, minted with the caller's own API object
/// (D1: `api`, an `Arc` for the code-out trigger's task, a borrow for a
/// command) and kept in memory only (never in a row or a file: the row
/// records their expiry, `vm::token::mint`), by port; one with less than
/// [`REMINT_BELOW`] left is minted again. A 9418 token lasts
/// [`TOKEN_MINUTES_SEED`] for a seed (`seeding`), every other
/// [`TOKEN_MINUTES`]. S9: [`MintingTokens::unrecorded`] mints without the
/// row's expiry, for a dry run.
pub struct MintingTokens<P> {
    api: P,
    paths: crate::bridge::config::Paths,
    vm_id: String,
    code_minutes: u16,
    /// Each mint's expiry recorded in the VM's row (`vm::token::mint`); not for a dry run.
    record: bool,
    cache: std::sync::Mutex<std::collections::BTreeMap<u16, AuthToken>>,
}

impl<P> MintingTokens<P>
where
    P: std::ops::Deref + Send + Sync,
    P::Target: crate::bridge::api::MicrovmApi + Sized,
{
    /// The tokens of `vm_id`; `seeding`: its 9418 tokens outlast a first seed.
    /// S9: `AI_ENV_BRIDGE_LAB_CODE_TOKEN_MINUTES` (debug builds; the live
    /// re-mint test) sets every 9418 token's minutes instead ([`code_minutes`]).
    #[must_use]
    pub fn new(api: P, paths: &crate::bridge::config::Paths, vm_id: &str, seeding: bool) -> MintingTokens<P> {
        let code_minutes = code_minutes(crate::bridge::lab::vm_knobs().code_token_minutes(), seeding);
        MintingTokens { api, paths: paths.clone(), vm_id: vm_id.to_string(), code_minutes, record: true, cache: std::sync::Mutex::new(std::collections::BTreeMap::new()) }
    }

    /// These tokens minted without their expiry in the VM's row
    /// (`vm::token::mint_unrecorded`, S9): what `box fetch --dry-run` mints
    /// with, which changes nothing on the Mac.
    #[must_use]
    pub fn unrecorded(self) -> MintingTokens<P> {
        MintingTokens { record: false, ..self }
    }

    fn cached(&self, port: u16) -> Option<AuthToken> {
        let now = crate::wire::time::unix_now();
        let cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.get(&port).filter(|t| t.expires_at_unix > now.saturating_add(REMINT_BELOW.as_secs())).cloned()
    }
}

/// A 9418 token's minutes: the lab knob's when set (`VmKnobs::code_token_minutes`:
/// 1 to 15, debug builds only, the fake API not needed: the live re-mint
/// test's short tokens), else [`TOKEN_MINUTES_SEED`] for a seed and
/// [`TOKEN_MINUTES`] for the rest.
fn code_minutes(knob: Option<u16>, seeding: bool) -> u16 {
    knob.unwrap_or(if seeding { TOKEN_MINUTES_SEED } else { TOKEN_MINUTES })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod g8_tests {
    use super::*;
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, FAKE_IMAGE_ARN};

    /// S9: the knob's minutes win for every 9418 token, a seed's too; without
    /// it a seed's last 15 minutes and the rest 5. The knob's own range (1 to
    /// 15, else none) is `VmKnobs::code_token_minutes`'.
    #[test]
    fn the_code_token_knob_sets_every_9418_tokens_minutes() {
        assert_eq!((code_minutes(None, true), code_minutes(None, false)), (TOKEN_MINUTES_SEED, TOKEN_MINUTES));
        assert_eq!((code_minutes(Some(2), true), code_minutes(Some(2), false)), (2, 2));
        let knobs = |m: u16| crate::bridge::lab::VmKnobs { code_token_minutes: Some(m), ..crate::bridge::lab::VmKnobs::default() };
        assert_eq!((knobs(0).code_token_minutes(), knobs(1).code_token_minutes(), knobs(15).code_token_minutes(), knobs(16).code_token_minutes()), (None, Some(1), Some(15), None));
        assert_eq!(code_minutes(knobs(16).code_token_minutes(), false), TOKEN_MINUTES, "out of range: the default");
    }

    /// The minutes reach the mint: an 8080 token stays 5 minutes whatever a
    /// 9418 one lasts (the knob is the 9418 tokens' alone).
    #[tokio::test]
    async fn a_code_token_is_minted_for_its_minutes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::bridge::config::Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let api = FakeMicrovmApi::new();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "01926f2e-0000-7000-8000-0000000000c8".into(),
        };
        let id = api.run(&spec).await.unwrap().id;
        api.advance_all();
        let mut tokens = MintingTokens::new(&api, &paths, &id, false);
        tokens.code_minutes = code_minutes(Some(2), false);
        tokens.token(crate::wire::workspace::CODE_PORT).await.unwrap();
        tokens.token(crate::wire::workspace::APP_PORT).await.unwrap();
        let minted: Vec<(u16, u16)> = api.calls().iter().filter_map(|c| if let Call::Token { port, minutes, .. } = c { Some((*port, *minutes)) } else { None }).collect();
        assert_eq!(minted, [(9418, 2), (8080, TOKEN_MINUTES)], "the 9418 token for its 2 minutes, the 8080 one for its 5");
    }
}

impl<P> TokenSource for MintingTokens<P>
where
    P: std::ops::Deref + Send + Sync,
    P::Target: crate::bridge::api::MicrovmApi + Sized,
{
    async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
        if let Some(t) = self.cached(port) {
            return Ok(t);
        }
        let minutes = if port == crate::wire::workspace::CODE_PORT { self.code_minutes } else { TOKEN_MINUTES };
        let token = if self.record {
            crate::bridge::vm::token::mint(&*self.api, &self.paths, &self.vm_id, port, minutes).await?
        } else {
            crate::bridge::vm::token::mint_unrecorded(&*self.api, &self.vm_id, port, minutes).await?
        };
        self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(port, token.clone());
        Ok(token)
    }

    fn forget(&self, port: u16) {
        self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&port);
    }
}

// ---- the HTTPS client ----------------------------------------------------------------------

/// The largest JSON answer a route reads (a settings capture carries three
/// files of at most 256 KiB).
pub const MAX_JSON: usize = 2 * 1024 * 1024;
/// The size of each chunk a streamed body is read in.
const CHUNK: usize = 64 * 1024;

/// The data plane through the MicroVM endpoint: one `reqwest` client per
/// port over `tls::reqwest_client()` (a pooled connection never carries
/// another port's token), the token's headers and the session bearer
/// marked sensitive, no redirect ever followed, a body streamed from its
/// file with its `Content-Length`. Under the lab's agent address (debug
/// builds, with the fake API, loopback only: `VmKnobs::agent_addr`) every
/// port goes in plain http to that address instead (`tls::lab_http_client`),
/// each VM's endpoint host resolved to it so the Host stays the endpoint's.
pub struct HttpsEndpoint {
    lab: Option<std::net::SocketAddr>,
    clients: std::sync::Mutex<std::collections::BTreeMap<(u16, String), reqwest::Client>>,
}

impl HttpsEndpoint {
    /// The data plane under `knobs` (release builds: no knob, always HTTPS).
    pub fn new(knobs: &crate::bridge::lab::VmKnobs) -> Result<HttpsEndpoint, BridgeError> {
        let lab = knobs.agent_addr().map_err(BridgeError::Config)?;
        let mut clients = std::collections::BTreeMap::new();
        if lab.is_none() {
            for port in [crate::wire::workspace::CODE_PORT, crate::wire::workspace::APP_PORT] {
                let c = crate::bridge::tls::reqwest_client().map_err(|e| BridgeError::Sdk { op: "tls", message: format!("cannot build the HTTPS client: {e}") })?;
                clients.insert((port, String::new()), c);
            }
        }
        Ok(HttpsEndpoint { lab, clients: std::sync::Mutex::new(clients) })
    }

    /// The client for `port` (and, in the lab, the endpoint `host`).
    fn client(&self, port: u16, host: &str) -> Result<reqwest::Client, BridgeError> {
        let key = (port, if self.lab.is_some() { host.to_string() } else { String::new() });
        let mut clients = self.clients.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(c) = clients.get(&key) {
            return Ok(c.clone());
        }
        let c = self.lab_client(host)?;
        clients.insert(key, c.clone());
        Ok(c)
    }

    #[cfg(debug_assertions)]
    fn lab_client(&self, host: &str) -> Result<reqwest::Client, BridgeError> {
        match self.lab {
            Some(addr) => crate::bridge::tls::lab_http_client(addr, host),
            None => Err(BridgeError::Config("no client for this port".into())),
        }
    }

    #[cfg(not(debug_assertions))]
    fn lab_client(&self, _host: &str) -> Result<reqwest::Client, BridgeError> {
        Err(BridgeError::Config("no client for this port".into()))
    }

    /// `https://<endpoint><path>?<pairs>` (`vm::health::endpoint_url_query`'s
    /// pin and path rules), `http://` in the lab.
    fn url<K: AsRef<str>, V: AsRef<str>>(&self, target: &AgentTarget, path: &str, pairs: &[(K, V)]) -> Result<reqwest::Url, BridgeError> {
        let mut url = crate::bridge::vm::health::endpoint_url_query(&target.endpoint, path, pairs)?;
        if self.lab.is_some() {
            url.set_scheme("http").map_err(|()| BridgeError::Config("cannot make a lab URL plain http".into()))?;
        }
        Ok(url)
    }

    /// One request to `url` on `token.port` with `token`'s header and the
    /// session bearer, within `timeout`: its response once its head came;
    /// a redirect is refused, never followed.
    async fn send(&self, method: reqwest::Method, target: &AgentTarget, token: &AuthToken, url: reqwest::Url, timeout: Duration, payload: Payload) -> Result<reqwest::Response, BridgeError> {
        self.send_with(method, target, token, url, timeout, payload, &[]).await
    }

    /// [`Self::send`] with `extra` headers besides its own (S9: git
    /// smart-HTTP's `Git-Protocol` and `Accept`; never a sensitive one).
    #[allow(clippy::too_many_arguments)]
    async fn send_with(&self, method: reqwest::Method, target: &AgentTarget, token: &AuthToken, url: reqwest::Url, timeout: Duration, payload: Payload, extra: &[(&'static str, String)]) -> Result<reqwest::Response, BridgeError> {
        use crate::bridge::vm::health::{bearer_header, redirect_refusal_for, transport_error_for};
        let host = url.host_str().unwrap_or_default().to_string();
        let shown = url.as_str().to_string();
        let value = token.value()?;
        let mut auth = reqwest::header::HeaderValue::from_str(value.expose()).map_err(|_| BridgeError::Sdk { op: "workspace", message: "the endpoint token is not a valid header value".into() })?;
        auth.set_sensitive(true);
        let mut req = self.client(token.port, &host)?.request(method.clone(), url).header("x-aws-proxy-auth", auth).header("x-aws-proxy-port", token.port.to_string()).header(reqwest::header::AUTHORIZATION, bearer_header(&target.session_token)?).timeout(timeout);
        for (name, value) in extra {
            req = req.header(*name, value.as_str());
        }
        match payload {
            Payload::None => {}
            Payload::File(body, len) => req = req.header(reqwest::header::CONTENT_LENGTH, len).body(body),
            Payload::Json(json) => req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(json),
            Payload::Bytes { content_type, body } => req = req.header(reqwest::header::CONTENT_TYPE, content_type).header(reqwest::header::CONTENT_LENGTH, body.len()).body(body),
        }
        let resp = req.send().await.map_err(|e| transport_error_for(method.as_str(), "workspace", &shown, &e))?;
        if resp.url().as_str() != shown {
            return Err(BridgeError::Sdk { op: "workspace", message: format!("{method} {shown} was redirected to another URL: refused (the endpoint token must be treated as exposed)") });
        }
        if let Some(refused) = redirect_refusal_for(method.as_str(), "workspace", &shown, resp.status().as_u16(), resp.headers().get(reqwest::header::LOCATION)) {
            return Err(refused);
        }
        Ok(resp)
    }
}

impl HttpsEndpoint {
    /// `POST /codeout` read only to its manifest line (`box fetch
    /// --dry-run`): the VM's refs as a code-out would bring them, the pack
    /// never read (the connection is dropped after the line; nothing is
    /// imported). `req` should ask for no snapshot: a dry run changes nothing.
    pub async fn codeout_refs(&self, target: &AgentTarget, token: &AuthToken, req: &CodeoutRequest) -> Result<DpReply<CodeoutManifest>, BridgeError> {
        use crate::wire::workspace::{CODEOUT_ROUTE, HEAD_LINE_MAX};
        req.check().map_err(|e| BridgeError::Config(format!("POST /codeout: the request {e}")))?;
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, CODEOUT_ROUTE, &none)?;
        let shown = url.as_str().to_string();
        let json = serde_json::to_vec(req).map_err(|e| BridgeError::Config(format!("POST /codeout: {e}")))?;
        let mut resp = self.send(reqwest::Method::POST, target, token, url, request_timeout(0, crate::wire::workspace::budget::CODEOUT), Payload::Json(json)).await?;
        match resp.status().as_u16() {
            200 => {}
            204 => return Ok(DpReply::status(204)),
            _ => return refusal_of(resp, "POST", &shown).await,
        }
        let mut head: Vec<u8> = Vec::new();
        while !head.contains(&b'\n') && head.len() <= HEAD_LINE_MAX {
            let Some(chunk) = resp.chunk().await.map_err(|e| crate::bridge::vm::health::transport_error_for("POST", "workspace", &shown, &e))? else { break };
            head.extend_from_slice(&chunk);
        }
        let Some(nl) = head.iter().position(|b| *b == b'\n').filter(|nl| *nl < HEAD_LINE_MAX) else {
            return Err(BridgeError::Protocol(format!("POST {shown}: no manifest line within {HEAD_LINE_MAX} bytes")));
        };
        let manifest: CodeoutManifest = crate::wire::workspace::parse_head(&head[..nl]).map_err(|e| BridgeError::Protocol(format!("POST {shown}: {e}")))?;
        manifest.check().map_err(|e| BridgeError::WorkspaceFailed { code: refusal::BAD_REFS, message: format!("POST /codeout: the manifest {e}") })?;
        Ok(DpReply::ok(200, manifest))
    }
}

/// What a request carries.
enum Payload {
    None,
    /// A file's bytes, streamed, with their `Content-Length`.
    File(reqwest::Body, u64),
    /// A JSON document.
    Json(Vec<u8>),
    /// S9: bytes of a given type, with their `Content-Length` (a git upload-pack request; G2 sends it).
    #[allow(dead_code)]
    Bytes { content_type: &'static str, body: Vec<u8> },
}

/// `path`'s first `len` bytes as a request body, read in [`CHUNK`]s (never buffered whole).
async fn file_body(path: &Path, len: u64) -> Result<reqwest::Body, BridgeError> {
    use tokio::io::AsyncReadExt as _;
    let file = tokio::fs::File::open(path).await.map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot open {}: {e}", path.display()))))?;
    let stream = futures_util::stream::unfold((file.take(len), vec![0u8; CHUNK]), |(mut file, mut buf)| async move {
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => Some((Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::copy_from_slice(&buf[..n])), (file, buf))),
            Err(e) => Some((Err(e), (file, buf))),
        }
    });
    Ok(reqwest::Body::wrap_stream(stream))
}

/// The body of `resp`, at most `cap` bytes; `true` when more came.
async fn read_capped(resp: &mut reqwest::Response, cap: usize, method: &str, url: &str) -> Result<(Vec<u8>, bool), BridgeError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| crate::bridge::vm::health::transport_error_for(method, "workspace", url, &e))? {
        if crate::bridge::vm::health::keep_capped(&mut body, &chunk, cap) {
            return Ok((body, true));
        }
    }
    Ok((body, false))
}

/// An answer as a [`DpReply`]: a status in `ok` carries a `R` (a 204 none),
/// any other its [`WsRefusal`] when the body is one (normalised through
/// [`WsRefusal::new`]: one scrubbed line).
async fn reply_of<R: serde::de::DeserializeOwned>(mut resp: reqwest::Response, ok: &[u16], method: &str, url: &str) -> Result<DpReply<R>, BridgeError> {
    use crate::bridge::vm::health::{proxy_error_of, retry_after_of};
    let status = resp.status().as_u16();
    let (proxy_error, retry_after_s) = (proxy_error_of(resp.headers()), retry_after_of(resp.headers()));
    let base = |r: DpReply<R>| DpReply { proxy_error: proxy_error.clone(), retry_after_s, ..r };
    if status == 204 {
        return Ok(base(DpReply::status(204)));
    }
    if !ok.contains(&status) {
        return refusal_of(resp, method, url).await;
    }
    let (bytes, truncated) = read_capped(&mut resp, MAX_JSON, method, url).await?;
    if truncated {
        return Err(BridgeError::Http { status, body: format!("{method} {url}: the answer exceeds {} KiB", MAX_JSON / 1024) });
    }
    let body: R = serde_json::from_slice(&bytes).map_err(|e| BridgeError::Http { status, body: format!("{method} {url}: unparseable answer: {}", crate::wire::redact::scrub(e.to_string().lines().next().unwrap_or("unparseable"))) })?;
    Ok(base(DpReply::ok(status, body)))
}

/// An answer that carries no `R` (a 4xx or 5xx, an unexpected status) as a
/// [`DpReply`]: its [`WsRefusal`] when the body is one.
async fn refusal_of<R>(mut resp: reqwest::Response, method: &str, url: &str) -> Result<DpReply<R>, BridgeError> {
    use crate::bridge::vm::health::{proxy_error_of, retry_after_of};
    let status = resp.status().as_u16();
    let (proxy_error, retry_after_s) = (proxy_error_of(resp.headers()), retry_after_of(resp.headers()));
    let (bytes, _) = read_capped(&mut resp, MAX_JSON, method, url).await?;
    let refusal = serde_json::from_slice::<WsRefusal>(&bytes).ok().map(|r| WsRefusal { code: refusal_code(&r.code), state: r.state, size: r.size, ..WsRefusal::new("", &r.message) });
    Ok(DpReply { refusal, proxy_error, retry_after_s, ..DpReply::status(status) })
}

/// A refusal's code as the VM sent it, kept when it is a code word (1 to 64
/// bytes of `[a-z0-9_]`: a newer shim's code shows as itself), else
/// `unknown`: it is echoed in errors, and the VM's bytes never reach the
/// terminal unchecked (an escape sequence, a key id, a megabyte).
fn refusal_code(c: &str) -> String {
    if (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        c.to_string()
    } else {
        "unknown".to_string()
    }
}

impl DataPlane for HttpsEndpoint {
    async fn seed_state(&self, target: &AgentTarget, token: &AuthToken, path: &str) -> Result<DpReply<SeedState>, BridgeError> {
        let url = self.url(target, crate::wire::workspace::SEED_ROUTE, &crate::wire::workspace::PathQuery { path: path.to_string() }.pairs())?;
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::GET, target, token, url, request_timeout(0, crate::wire::workspace::budget::SEED_STATE), Payload::None).await?;
        reply_of(resp, &[200], "GET", &shown).await
    }

    async fn put_seed(&self, target: &AgentTarget, token: &AuthToken, query: &SeedQuery, body: &Path, len: u64) -> Result<DpReply<SeedReply>, BridgeError> {
        query.check().map_err(|e| BridgeError::Config(format!("PUT /seed: the query {e}")))?;
        let url = self.url(target, crate::wire::workspace::SEED_ROUTE, &query.pairs())?;
        let shown = url.as_str().to_string();
        let timeout = request_timeout(len, query.mode.budget());
        let resp = self.send(reqwest::Method::PUT, target, token, url, timeout, Payload::File(file_body(body, len).await?, len)).await?;
        reply_of(resp, &[200, 201], "PUT", &shown).await
    }

    async fn post_codeout(&self, target: &AgentTarget, token: &AuthToken, req: &CodeoutRequest, dest: &Path, cap: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
        use crate::wire::workspace::{HEAD_LINE_MAX, CODEOUT_ROUTE};
        req.check().map_err(|e| BridgeError::Config(format!("POST /codeout: the request {e}")))?;
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, CODEOUT_ROUTE, &none)?;
        let shown = url.as_str().to_string();
        let json = serde_json::to_vec(req).map_err(|e| BridgeError::Config(format!("POST /codeout: {e}")))?;
        let mut resp = self.send(reqwest::Method::POST, target, token, url, request_timeout(cap, crate::wire::workspace::budget::CODEOUT), Payload::Json(json)).await?;
        if resp.status().as_u16() != 200 {
            return if resp.status().as_u16() == 204 { Ok(DpReply { proxy_error: crate::bridge::vm::health::proxy_error_of(resp.headers()), ..DpReply::status(204) }) } else { refusal_of(resp, "POST", &shown).await };
        }
        let (proxy_error, retry_after_s) = (crate::bridge::vm::health::proxy_error_of(resp.headers()), crate::bridge::vm::health::retry_after_of(resp.headers()));
        // The manifest line first, then the pack into `dest`, never past `cap`.
        let mut head: Vec<u8> = Vec::new();
        let mut rest: Vec<u8> = Vec::new();
        while !head.contains(&b'\n') {
            let Some(chunk) = resp.chunk().await.map_err(|e| crate::bridge::vm::health::transport_error_for("POST", "workspace", &shown, &e))? else { break };
            head.extend_from_slice(&chunk);
            if head.len() > HEAD_LINE_MAX && !head[..HEAD_LINE_MAX].contains(&b'\n') {
                return Err(BridgeError::Protocol(format!("POST {shown}: the manifest line is longer than {HEAD_LINE_MAX} bytes")));
            }
        }
        let Some(nl) = head.iter().position(|b| *b == b'\n') else {
            return Err(BridgeError::Protocol(format!("POST {shown}: the answer ended before its manifest line did")));
        };
        rest.extend_from_slice(&head[nl + 1..]);
        head.truncate(nl);
        let manifest: CodeoutManifest = crate::wire::workspace::parse_head(&head).map_err(|e| BridgeError::Protocol(format!("POST {shown}: {e}")))?;
        manifest.check().map_err(|e| BridgeError::WorkspaceFailed { code: refusal::BAD_REFS, message: format!("POST /codeout: the manifest {e}") })?;
        let written = write_pack(&mut resp, dest, cap, rest, &shown).await;
        let pack_bytes = match written {
            Ok(Some(n)) => n,
            Ok(None) => {
                let _ = std::fs::remove_file(dest);
                return Err(BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: format!("POST /codeout: the code-out pack is over {} (box fetch --max-mib, [seed].max_fetch_mib)", crate::bridge::workspace::snapshot::human_bytes(cap)) });
            }
            Err(e) => {
                let _ = std::fs::remove_file(dest);
                return Err(e);
            }
        };
        Ok(DpReply { proxy_error, retry_after_s, ..DpReply::ok(200, CodeoutBody { manifest, pack_bytes }) })
    }

    async fn transcript_stat(&self, target: &AgentTarget, token: &AuthToken, rel: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_ROUTE, &crate::wire::workspace::RelQuery { rel: rel.to_string() }.pairs())?;
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::GET, target, token, url, request_timeout(0, crate::wire::workspace::budget::TRANSCRIPT), Payload::None).await?;
        reply_of(resp, &[200], "GET", &shown).await
    }

    async fn get_settings(&self, target: &AgentTarget, token: &AuthToken, path: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
        let url = self.url(target, crate::wire::workspace::SETTINGS_ROUTE, &crate::wire::workspace::PathQuery { path: path.to_string() }.pairs())?;
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::GET, target, token, url, request_timeout(0, crate::wire::workspace::budget::SETTINGS), Payload::None).await?;
        let reply: DpReply<SettingsCapture> = reply_of(resp, &[200], "GET", &shown).await?;
        if let Some(c) = &reply.body {
            c.check().map_err(|e| BridgeError::Protocol(format!("GET {shown}: the capture {e}")))?;
        }
        Ok(reply)
    }

    // S9's transcript routes (G4 builds them: JSON bodies through `send`'s `Payload::Json`, budgets
    // `request_timeout(len, budget::…)`, `reply_of(resp, &[200], …)`, `&[200, 201]` for the pull, 204 for the tail).

    // Each request is checked first (the VM refuses what its `check` refuses: a version skew, never sent), its URLs
    // travel in the JSON body only (behind the bearer, never in the query or a log line), and its wait is
    // `request_timeout` over what may cross and the shim's own budget.

    async fn transcript_stat_from(&self, target: &AgentTarget, token: &AuthToken, q: &StatQuery) -> Result<DpReply<TranscriptStat>, BridgeError> {
        q.check().map_err(|e| BridgeError::Config(format!("GET /transcript: the query {e}")))?;
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_ROUTE, &q.pairs())?;
        let shown = url.as_str().to_string();
        let hashed = if q.subtree { crate::wire::workspace::SUBTREE_BYTES_MAX } else { 0 };
        let resp = self.send(reqwest::Method::GET, target, token, url, request_timeout(hashed, crate::wire::workspace::budget::TRANSCRIPT), Payload::None).await?;
        reply_of(resp, &[200], "GET", &shown).await
    }

    async fn transcript_push(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptPush) -> Result<DpReply<TranscriptPushReply>, BridgeError> {
        req.check().map_err(|e| BridgeError::Config(format!("POST /transcript/push: the request {e}")))?;
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_PUSH_ROUTE, &none)?;
        let json = serde_json::to_vec(req).map_err(|e| BridgeError::Config(format!("POST /transcript/push: {e}")))?;
        if json.len() > crate::wire::workspace::TRANSFER_REQUEST_MAX {
            return Err(BridgeError::Config(format!("POST /transcript/push: a {}-byte request (at most {})", json.len(), crate::wire::workspace::TRANSFER_REQUEST_MAX)));
        }
        let shown = url.as_str().to_string();
        let timeout = request_timeout(req.len, crate::wire::workspace::budget::TRANSCRIPT_PUSH);
        let resp = self.send(reqwest::Method::POST, target, token, url, timeout, Payload::Json(json)).await?;
        reply_of(resp, &[200], "POST", &shown).await
    }

    async fn transcript_pull(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptPull) -> Result<DpReply<TranscriptPullReply>, BridgeError> {
        req.check().map_err(|e| BridgeError::Config(format!("POST /transcript/pull: the request {e}")))?;
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_PULL_ROUTE, &none)?;
        let json = serde_json::to_vec(req).map_err(|e| BridgeError::Config(format!("POST /transcript/pull: {e}")))?;
        if json.len() > crate::wire::workspace::TRANSFER_REQUEST_MAX {
            return Err(BridgeError::Config(format!("POST /transcript/pull: a {}-byte request (at most {})", json.len(), crate::wire::workspace::TRANSFER_REQUEST_MAX)));
        }
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::POST, target, token, url, pull_timeout(req), Payload::Json(json)).await?;
        reply_of(resp, &[200, 201], "POST", &shown).await
    }

    async fn transcript_view(&self, target: &AgentTarget, token: &AuthToken, q: &ViewQuery) -> Result<DpReply<crate::wire::view::TranscriptViewReply>, BridgeError> {
        q.check().map_err(|e| BridgeError::Config(format!("GET /transcript/view: the query {e}")))?;
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_VIEW_ROUTE, &q.pairs())?;
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::GET, target, token, url, request_timeout(crate::wire::workspace::JSON_PAYLOAD_MAX as u64, crate::wire::workspace::budget::TRANSCRIPT_VIEW), Payload::None).await?;
        reply_of(resp, &[200], "GET", &shown).await
    }

    async fn transcript_tail(&self, target: &AgentTarget, token: &AuthToken, req: &TranscriptTail) -> Result<DpReply<()>, BridgeError> {
        req.check().map_err(|e| BridgeError::Config(format!("POST /transcript/tail: the request {e}")))?;
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, crate::wire::workspace::TRANSCRIPT_TAIL_ROUTE, &none)?;
        let json = serde_json::to_vec(req).map_err(|e| BridgeError::Config(format!("POST /transcript/tail: {e}")))?;
        if json.len() > crate::wire::workspace::TRANSFER_REQUEST_MAX {
            return Err(BridgeError::Config(format!("POST /transcript/tail: a {}-byte request (at most {})", json.len(), crate::wire::workspace::TRANSFER_REQUEST_MAX)));
        }
        let shown = url.as_str().to_string();
        let resp = self.send(reqwest::Method::POST, target, token, url, request_timeout(0, crate::wire::workspace::budget::TRANSCRIPT), Payload::Json(json)).await?;
        if resp.status().as_u16() == 204 {
            return Ok(DpReply { proxy_error: crate::bridge::vm::health::proxy_error_of(resp.headers()), ..DpReply::status(204) });
        }
        refusal_of(resp, "POST", &shown).await
    }
}

/// Git smart-HTTP v2 on the code port (S9 §2.1): through `send_with`, with
/// `Git-Protocol: version=2` and `Accept` (the advertisement's type for the
/// `GET`, the result's for the `POST`, whose one v2 command goes as
/// `Payload::Bytes` of the request's type with its `Content-Length`); never
/// a `Content-Encoding` nor an `Accept-Encoding`. A status other than 200
/// comes back as a [`DpReply`] with its refusal (`refusal_of`), which
/// `exchange` decides on; a 200's body is read to its end, never past its
/// cap (more: `too_large`, exit 9), and one cut short is `Endpoint`.
impl crate::bridge::gitsmart::GitHttp for HttpsEndpoint {
    async fn info_refs(&self, target: &AgentTarget, token: &AuthToken) -> Result<DpReply<Vec<u8>>, BridgeError> {
        use crate::bridge::gitsmart::{ADVERT_MAX, INFO_REFS};
        use crate::wire::workspace::{budget, GIT_ADVERTISEMENT_TYPE, GIT_INFO_REFS_ROUTE, GIT_PROTOCOL_V2, GIT_UPLOAD_PACK_QUERY};
        // `service=git-upload-pack`, its one pair.
        let query: Vec<(&str, &str)> = GIT_UPLOAD_PACK_QUERY.split_once('=').into_iter().collect();
        let url = self.url(target, GIT_INFO_REFS_ROUTE, &query)?;
        let shown = url.as_str().to_string();
        let extra = [("Git-Protocol", GIT_PROTOCOL_V2.to_string()), ("Accept", GIT_ADVERTISEMENT_TYPE.to_string())];
        let mut resp = self.send_with(reqwest::Method::GET, target, token, url, request_timeout(ADVERT_MAX, budget::GIT_ADVERTISE), Payload::None, &extra).await?;
        if resp.status().as_u16() != 200 {
            return refusal_of(resp, "GET", &shown).await;
        }
        let (proxy_error, retry_after_s) = (crate::bridge::vm::health::proxy_error_of(resp.headers()), crate::bridge::vm::health::retry_after_of(resp.headers()));
        let (body, over) = read_capped(&mut resp, usize::try_from(ADVERT_MAX).unwrap_or(usize::MAX), "GET", &shown).await?;
        if over {
            return Err(BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: format!("{INFO_REFS}: the advertisement is over {}", crate::bridge::workspace::snapshot::human_bytes(ADVERT_MAX)) });
        }
        Ok(DpReply { proxy_error, retry_after_s, ..DpReply::ok(200, body) })
    }

    async fn upload_pack<W: std::io::Write + Send>(&self, target: &AgentTarget, token: &AuthToken, body: &[u8], sink: &mut W, cap: u64) -> Result<DpReply<u64>, BridgeError> {
        use crate::bridge::gitsmart::UPLOAD_PACK;
        use crate::wire::workspace::{budget, GIT_PROTOCOL_V2, GIT_UPLOAD_PACK_REQUEST_TYPE, GIT_UPLOAD_PACK_RESULT_TYPE, GIT_UPLOAD_PACK_ROUTE};
        let none: [(&str, &str); 0] = [];
        let url = self.url(target, GIT_UPLOAD_PACK_ROUTE, &none)?;
        let shown = url.as_str().to_string();
        let extra = [("Git-Protocol", GIT_PROTOCOL_V2.to_string()), ("Accept", GIT_UPLOAD_PACK_RESULT_TYPE.to_string())];
        let timeout = request_timeout(cap.saturating_add(body.len() as u64), budget::GIT_UPLOAD_PACK);
        let payload = Payload::Bytes { content_type: GIT_UPLOAD_PACK_REQUEST_TYPE, body: body.to_vec() };
        let mut resp = self.send_with(reqwest::Method::POST, target, token, url, timeout, payload, &extra).await?;
        if resp.status().as_u16() != 200 {
            return refusal_of(resp, "POST", &shown).await;
        }
        let (proxy_error, retry_after_s) = (crate::bridge::vm::health::proxy_error_of(resp.headers()), crate::bridge::vm::health::retry_after_of(resp.headers()));
        let mut written = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| crate::bridge::vm::health::transport_error_for("POST", "workspace", &shown, &e))? {
            written = written.saturating_add(chunk.len() as u64);
            if written > cap {
                return Err(BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: format!("{UPLOAD_PACK}: the answer is over {}", crate::bridge::workspace::snapshot::human_bytes(cap)) });
            }
            sink.write_all(&chunk)?;
        }
        Ok(DpReply { proxy_error, retry_after_s, ..DpReply::ok(200, written) })
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod g2_tests {
    use super::*;
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, FAKE_IMAGE_ARN};

    /// S9: tokens made `unrecorded` mint as the others do (once per port, a
    /// 9418 one for 5 minutes), and the VM's row, which a recorded mint
    /// writes, stays byte for byte as it was.
    #[tokio::test]
    async fn unrecorded_tokens_leave_the_vms_row_as_it_was() {
        use crate::bridge::vm::registry::{read_row, write_row, RowStatus, VmRow};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::bridge::config::Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let api = FakeMicrovmApi::new();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "01926f2e-0000-7000-8000-0000000000c2".into(),
        };
        let id = api.run(&spec).await.unwrap().id;
        api.advance_all();
        write_row(&paths, &VmRow { id: id.clone(), status: RowStatus::Running, client_token: spec.client_token.clone(), ..VmRow::default() }).unwrap();
        let file = paths.vms().join(format!("{id}.toml"));
        let before = std::fs::read(&file).unwrap();
        let dry = MintingTokens::new(&api, &paths, &id, false).unrecorded();
        dry.token(9418).await.unwrap();
        dry.token(9418).await.unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), before, "nothing recorded");
        let minted = |api: &FakeMicrovmApi| api.calls().iter().filter(|c| matches!(c, Call::Token { port: 9418, minutes: 5, .. })).count();
        assert_eq!(minted(&api), 1, "minted once, then kept in memory");
        MintingTokens::new(&api, &paths, &id, false).token(9418).await.unwrap();
        assert!(read_row(&paths, &id).unwrap().unwrap().token_expiries.contains_key("9418"), "the plain tokens still record");
        assert_eq!(minted(&api), 2);
    }
}

/// The pack after a code-out's manifest line: `first` (what came with the
/// line), then the rest of `resp`, into `dest` (created 0600, never through
/// a symlink); `None` once it passes `cap` bytes.
async fn write_pack(resp: &mut reqwest::Response, dest: &Path, cap: u64, first: Vec<u8>, url: &str) -> Result<Option<u64>, BridgeError> {
    use tokio::io::AsyncWriteExt as _;
    let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dest).await?;
    let mut written = 0u64;
    let mut chunk = bytes::Bytes::from(first);
    loop {
        written += chunk.len() as u64;
        if written > cap {
            return Ok(None);
        }
        file.write_all(&chunk).await?;
        match resp.chunk().await.map_err(|e| crate::bridge::vm::health::transport_error_for("POST", "workspace", url, &e))? {
            Some(next) => chunk = next,
            None => break,
        }
    }
    file.sync_all().await?;
    Ok(Some(written))
}

/// A data plane and a token source no phase-0 stub reaches (the shape the
/// wave-1 fakes take): every call is a transport error.
#[cfg(test)]
pub(crate) struct Unreached;

#[cfg(test)]
impl TokenSource for Unreached {
    async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
        Err(BridgeError::Endpoint(format!("no token for port {port} in this test")))
    }
}

#[cfg(test)]
impl DataPlane for Unreached {
    async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SeedState>, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }

    async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> Result<DpReply<SeedReply>, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }

    async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }

    async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }

    async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CliError;

    fn exit(e: BridgeError) -> i32 {
        CliError::from(e).exit_code()
    }

    fn refused(code: &str) -> DpReply<SeedReply> {
        DpReply::refused(WsRefusal::new(code, "the shim's words"))
    }

    fn fail_code(v: Verdict) -> (i32, String) {
        match v {
            Verdict::Fail(e) => {
                let text = e.to_string();
                (exit(e), text)
            }
            other => panic!("not final: {other:?}"),
        }
    }

    /// Plan §10's table, row by row, with the exit code each error takes.
    #[test]
    fn every_status_maps_to_its_action_and_exit_code() {
        for s in [200, 201, 204] {
            assert!(matches!(verdict("PUT /seed", 9418, &DpReply::<SeedReply>::status(s)), Verdict::Done), "{s}");
        }
        let mut denied = DpReply::<SeedReply>::status(403);
        denied.proxy_error = Some("UNAUTHORIZED".into());
        match verdict("GET /seed", 9418, &denied) {
            Verdict::Remint { error } => {
                assert!(matches!(&error, BridgeError::TokenRejected { port: 9418, status: 403, proxy_error: Some(p) } if p == "UNAUTHORIZED"));
                assert_eq!(exit(error), 7);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(verdict("GET /seed", 9418, &DpReply::<SeedState>::status(401)), Verdict::Remint { .. }));
        let (code, text) = fail_code(verdict("GET /seed", 9418, &DpReply::<SeedState>::status(404)));
        assert_eq!(code, 7);
        assert!(text.contains("lacks workspace_v1") && text.contains("GET /seed answered 404") && text.contains("make deploy"), "{text}");
        let state = SeedState { tip: Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".into()), ..SeedState::default() };
        let dirty = DpReply::<SeedReply>::refused(WsRefusal::new(refusal::DIRTY, "changes of its own").with_state(state.clone()));
        assert!(matches!(verdict("PUT /seed", 9418, &dirty), Verdict::Kept { reason: KeptReason::Dirty, state: Some(s) } if s == state));
        assert!(matches!(verdict("PUT /seed", 9418, &refused(refusal::DIVERGED)), Verdict::Kept { reason: KeptReason::Diverged, state: None }));
        match verdict("PUT /seed", 9418, &refused(refusal::CHANGED)) {
            Verdict::Reread { error } => assert_eq!(exit(error), 9),
            other => panic!("{other:?}"),
        }
        match verdict("POST /codeout", 9418, &refused(refusal::BUSY)) {
            Verdict::Busy { error } => assert_eq!(exit(error), 1),
            other => panic!("{other:?}"),
        }
        for code in [refusal::SYMLINK_COMPONENT, refusal::PATH_OCCUPIED, refusal::NOT_CREATABLE, refusal::OTHER_WORKSPACE, refusal::NOT_PRISTINE, refusal::NOT_SEEDED] {
            let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &refused(code)));
            assert_eq!(exit_code, 9, "{code}");
            assert!(text.starts_with(&format!("workspace refused ({code}): PUT /seed: the shim's words")), "{text}");
        }
        assert_eq!(fail_code(verdict("PUT /seed", 9418, &refused(refusal::BAD_REQUEST))), (9, "workspace refused (bad_request): PUT /seed: the shim's words".to_string()));
        // A body without Content-Length is the wire's 411 `bad_request`; a body over its cap 413 `too_large`.
        for (s, word) in [(411, refusal::BAD_REQUEST), (413, refusal::TOO_LARGE)] {
            let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &DpReply::<SeedReply>::status(s)));
            assert_eq!(exit_code, 9);
            assert!(text.starts_with(&format!("workspace refused ({word}): PUT /seed answered HTTP {s}")), "{text}");
        }
        let missing = DpReply::<SeedReply> { refusal: Some(WsRefusal::new(refusal::BAD_REQUEST, "Content-Length required")), ..DpReply::status(411) };
        assert_eq!(fail_code(verdict("PUT /seed", 9418, &missing)), (9, "workspace refused (bad_request): PUT /seed: Content-Length required".to_string()));
        for (code, s) in [(refusal::BAD_PACK, 422), (refusal::MISSING_PREREQUISITES, 422), (refusal::BAD_REFS, 422), (refusal::GIT_FAILED, 500), (refusal::TIMEOUT, 504)] {
            let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &refused(code)));
            assert_eq!((exit_code, refused(code).status), (1, s), "{code}");
            assert!(text.starts_with(&format!("workspace failed ({code})")), "{text}");
        }
        for (s, word) in [(422, "bad_pack"), (500, "git_failed"), (504, "timeout")] {
            let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &DpReply::<SeedReply>::status(s)));
            assert!(exit_code == 1 && text.starts_with(&format!("workspace failed ({word}): PUT /seed answered HTTP {s}")), "{s}: {text}");
        }
        let mut throttled = DpReply::<SeedState>::status(429);
        throttled.retry_after_s = Some(3);
        match verdict("GET /seed", 9418, &throttled) {
            Verdict::Throttled { retry_after_s: Some(3), error } => assert_eq!(exit(error), 7),
            other => panic!("{other:?}"),
        }
        for s in [502, 503] {
            match verdict("GET /seed", 9418, &DpReply::<SeedState>::status(s)) {
                Verdict::CheckVm { error } => assert_eq!(exit(error), 7),
                other => panic!("{s}: {other:?}"),
            }
        }
        // A suspend drains the shim as a terminate does: GetMicrovm decides between 8 and 7.
        match verdict("POST /codeout", 9418, &DpReply::<CodeoutBody>::refused(WsRefusal::new(refusal::DRAINING, "suspending"))) {
            Verdict::CheckVm { error } => {
                assert_eq!(error.to_string(), "endpoint HTTP 503: POST /codeout: suspending");
                assert_eq!(exit(error), 7);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fail_code(verdict("GET /seed", 9418, &DpReply::<SeedState>::status(418))).0, 7, "an unexpected status is Http");
    }

    /// A code this build does not know keeps its text and gets the status's
    /// fallback; no message ever carries a secret the shim quoted.
    #[test]
    fn unknown_codes_fall_back_by_status_and_texts_stay_scrubbed() {
        let key_id = format!("{}{}", "AKIA", "R".repeat(16));
        let odd = DpReply::<SeedReply>::refused(WsRefusal { code: "from_the_future".into(), message: format!("saw {key_id}"), state: None, size: None });
        assert_eq!(odd.status, 500);
        let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &odd));
        assert!(exit_code == 1 && text.starts_with("workspace failed (git_failed): PUT /seed: saw ") && text.contains("(from_the_future)"), "{text}");
        assert!(!text.contains(&key_id), "{text}");
        let conflict = DpReply::<SeedReply> { refusal: Some(WsRefusal::new("from_the_future", "x")), ..DpReply::status(409) };
        let (exit_code, text) = fail_code(verdict("PUT /seed", 9418, &conflict));
        assert!(exit_code == 9 && text.starts_with("workspace refused (conflict)"), "{text}");
    }

    /// S9 phase 4 (F1): what a refusal's body carries reaches no error text
    /// raw: a code that is no code word (a key id, an escape, a megabyte) is
    /// `unknown`, the message is one scrubbed line, and an `Http` error's
    /// body is scrubbed as it prints; a well-formed code this build does not
    /// know still shows.
    #[tokio::test]
    async fn a_refusals_code_and_text_never_carry_the_vms_bytes() {
        let key_id = format!("{}{}", "AKIA", "R".repeat(16));
        let body = |code: &str| serde_json::json!({"code": code, "message": format!("saw {key_id} \u{1b}[31m")}).to_string();
        for status in [503u16, 418, 500, 409] {
            for code in [format!("{key_id}\u{1b}[2J"), "x".repeat(1 << 20)] {
                let resp = reqwest::Response::from(http::Response::builder().status(status).body(body(&code)).unwrap());
                let reply: DpReply<SeedReply> = refusal_of(resp, "GET", "/workspace.git/info/refs").await.unwrap();
                assert_eq!(reply.refusal.as_ref().map(|r| r.code.as_str()), Some("unknown"), "{status}");
                let error = match verdict_cap("GET /workspace.git/info/refs", 9418, CAP_WORKSPACE_V1, &reply) {
                    Verdict::CheckVm { error } | Verdict::Fail(error) => error,
                    other => panic!("{status}: {other:?}"),
                };
                let text = error.to_string();
                assert!(!text.contains(&key_id) && !text.contains('\u{1b}') && text.len() < 2048, "{status}: {text}");
            }
        }
        let resp = reqwest::Response::from(http::Response::builder().status(500).body(body("from_the_future")).unwrap());
        let reply: DpReply<SeedReply> = refusal_of(resp, "GET", "/x").await.unwrap();
        let (_, text) = fail_code(verdict("PUT /seed", 9418, &reply));
        assert!(text.contains("(from_the_future)") && !text.contains(&key_id), "{text}");
        let shown = BridgeError::Http { status: 418, body: format!("saw {key_id}") }.to_string();
        assert!(shown.starts_with("endpoint HTTP 418: saw ") && !shown.contains(&key_id), "{shown}");
        assert_eq!((refusal_code("too_large"), refusal_code(""), refusal_code("Bad"), refusal_code(&"a".repeat(65))), ("too_large".into(), "unknown".into(), "unknown".into(), "unknown".into()));
    }

    /// S9 phase 4 (F2): a `Retry-After` past [`THROTTLE_WAIT_MAX`] is waited
    /// that long at most (none or 0: a second); `pause` refuses a wait no
    /// instant is that far away, with a deadline or none (`u64::MAX` once
    /// panicked adding to an instant, before the deadline was looked at).
    #[tokio::test]
    async fn a_huge_retry_after_waits_the_cap_and_never_panics() {
        assert_eq!([throttle_wait(None), throttle_wait(Some(0)), throttle_wait(Some(7)), throttle_wait(Some(31)), throttle_wait(Some(u64::MAX))], [Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(7), THROTTLE_WAIT_MAX, THROTTLE_WAIT_MAX]);
        assert_eq!(THROTTLE_WAIT_MAX, Duration::from_secs(30));
        let far = Some(tokio::time::Instant::now() + Duration::from_secs(3600));
        for deadline in [None, far] {
            assert_eq!(pause(deadline, Duration::from_secs(u64::MAX)).await, Err(()), "{deadline:?}");
        }
        assert_eq!(pause(Some(tokio::time::Instant::now()), Duration::from_secs(1)).await, Err(()), "past the deadline");
        assert_eq!(pause(far, Duration::from_millis(1)).await, Ok(()));
    }

    #[test]
    fn the_request_budget_adds_the_transfer_and_the_helper() {
        use crate::wire::workspace::budget;
        assert_eq!(request_timeout(0, budget::SEED_STATE), Duration::from_secs(60));
        assert_eq!(request_timeout(64 * 1024 * 1024, budget::SEED_CLONE), Duration::from_secs(30 + 68 + 600), "64 MiB at 1 MB/s, rounded up");
        assert_eq!(request_timeout(1, Duration::ZERO), Duration::from_secs(31));
        assert_eq!((TOKEN_MINUTES_SEED, TOKEN_MINUTES, REMINT_BELOW, BUSY_RETRY), (15, 5, Duration::from_secs(60), Duration::from_secs(30)), "plan §10");
    }

    /// S10 (§1.3): the Mac waits for a transcript pull as long as the shim
    /// gives it and its presigned GETs live (`pull_budget` of its parts'
    /// bytes and its share): alone, S9's wait (30 s, the bytes at 1 MB/s,
    /// the helper's 60 s); one of four pulls at once (the subtree's
    /// `restore_subtree`), its bytes four times over, so a pull sharing the
    /// VM's downlink is not cut while the shim still waits for it.
    #[test]
    fn a_pull_waits_by_the_shared_pull_budget() {
        use crate::wire::workspace::{budget, PullPart};
        let url = || {
            let key = crate::wire::s3::S3Key::Base { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(), gen: 1 }.render();
            let credential = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z";
            let text = format!("https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com/{key}?{credential}&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={}", crate::wire::s3::SIGNED_HEADERS_GET.replace(';', "%3B"), "e".repeat(64));
            crate::wire::s3::PresignedUrl::new(text).unwrap()
        };
        let pull = |lens: &[u64], share: u32| TranscriptPull {
            rel: "-w/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/subagents/a.jsonl".into(),
            parts: lens.iter().map(|len| PullPart { url: url(), len: *len, sha256: None }).collect(),
            sha256: None,
            owner: "123456789012".into(),
            proxy: None,
            share,
        };
        for bytes in [0u64, 1, 52_000, 300_000_000] {
            assert_eq!(pull_timeout(&pull(&[bytes], 1)), request_timeout(bytes, budget::TRANSCRIPT_PULL), "{bytes} bytes alone: S9's wait");
        }
        assert_eq!(pull_timeout(&pull(&[200_000_000, 100_000_000], 1)), Duration::from_secs(30 + 300 + 60), "the parts' bytes summed");
        assert_eq!(pull_timeout(&pull(&[300_000_000], 4)), Duration::from_secs(30 + 1200 + 60), "one of four: its bytes four times over");
        assert_eq!(pull_timeout(&pull(&[300_000_000], 4)), budget::pull_budget(300_000_000, 4), "the shim's and the presign's budget");
        assert!(pull_timeout(&pull(&[300_000_000], 4)) > pull_timeout(&pull(&[300_000_000], 1)));
    }

    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, FAKE_IMAGE_ARN};

    /// A RUNNING VM in a fresh in-memory fake.
    async fn running() -> (FakeMicrovmApi, String) {
        let api = FakeMicrovmApi::new();
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "01926f2e-0000-7000-8000-0000000000c1".into(),
        };
        let id = api.run(&spec).await.unwrap().id;
        api.advance_all();
        (api, id)
    }

    fn mints(api: &FakeMicrovmApi) -> Vec<(u16, u16)> {
        api.calls().iter().filter_map(|c| if let Call::Token { minutes, port, .. } = c { Some((*port, *minutes)) } else { None }).collect()
    }

    /// The tokens: minted once per port and kept in memory, a seed's 9418
    /// token for 15 minutes, every other for 5; forgetting one mints again.
    #[tokio::test]
    async fn minting_tokens_mint_once_per_port_and_again_once_forgotten() {
        let (api, id) = running().await;
        let paths = crate::bridge::config::Paths::from_root_and_env("/nonexistent/bridge".into(), None);
        let seeding = MintingTokens::new(&api, &paths, &id, true);
        let a = seeding.token(9418).await.unwrap();
        let b = seeding.token(9418).await.unwrap();
        assert_eq!(a.value().unwrap().expose(), b.value().unwrap().expose(), "kept, not minted again");
        seeding.token(8080).await.unwrap();
        assert_eq!(mints(&api), vec![(9418, 15), (8080, 5)]);
        seeding.forget(9418);
        seeding.token(9418).await.unwrap();
        assert_eq!(mints(&api).len(), 3);
        let plain = MintingTokens::new(std::sync::Arc::new(FakeMicrovmApi::new()), &paths, "microvm-x", false);
        assert!(plain.token(9418).await.is_err(), "no such VM: the mint's own error");
        let (api2, id2) = running().await;
        MintingTokens::new(&api2, &paths, &id2, false).token(9418).await.unwrap();
        assert_eq!(mints(&api2), vec![(9418, 5)]);
    }

    /// The exchange: a 403 forgets the token and sends once more; a second
    /// 403 is the error (7); a 429 waits its Retry-After; `busy` is sent
    /// again; a 502 asks GetMicrovm (a VM gone is 8); a transport failure of
    /// a GET is tried once more; past the deadline nothing more is sent.
    #[tokio::test]
    async fn the_exchange_retries_as_the_table_says() {
        use std::sync::Mutex;
        let (api, id) = running().await;
        let paths = crate::bridge::config::Paths::from_root_and_env("/nonexistent/bridge".into(), None);
        let tokens = MintingTokens::new(&api, &paths, &id, false);
        let x = Exchange { api: &api, tokens: &tokens, vm_id: &id, port: 9418, cap: CAP_WORKSPACE_V1, route: "GET /seed", deadline: None, idempotent: true };
        let xr = &x;
        let run = |script: Vec<Result<DpReply<SeedState>, BridgeError>>| {
            let script = Mutex::new(std::collections::VecDeque::from(script));
            let sent = Mutex::new(0u32);
            async move {
                let r = exchange(xr, |_t| {
                    *sent.lock().unwrap() += 1;
                    let next = script.lock().unwrap().pop_front().unwrap_or_else(|| Ok(DpReply::status(200)));
                    async move { next }
                })
                .await;
                (r.map(|(reply, _)| reply.status), *sent.lock().unwrap())
            }
        };
        let (r, sent) = run(vec![Ok(DpReply::status(403)), Ok(DpReply::status(200))]).await;
        assert_eq!((r.unwrap(), sent), (200, 2));
        let before = mints(&api).len();
        let (r, sent) = run(vec![Ok(DpReply::status(403)), Ok(DpReply::status(401))]).await;
        assert_eq!((CliError::from(r.unwrap_err()).exit_code(), sent), (7, 2));
        assert_eq!(mints(&api).len(), before + 1, "forgotten once, minted again");
        let t = std::time::Instant::now();
        let mut throttled = DpReply::status(429);
        throttled.retry_after_s = Some(1);
        let (r, sent) = run(vec![Ok(throttled), Ok(DpReply::status(200))]).await;
        assert!(r.is_ok() && sent == 2 && t.elapsed() >= Duration::from_secs(1), "{:?}", t.elapsed());
        let (r, sent) = run(vec![Ok(DpReply::refused(WsRefusal::new(refusal::BUSY, "a seed runs"))), Ok(DpReply::status(200))]).await;
        assert_eq!((r.unwrap(), sent), (200, 2));
        let (r, sent) = run(vec![Err(BridgeError::Endpoint("reset".into())), Ok(DpReply::status(200))]).await;
        assert_eq!((r.unwrap(), sent), (200, 2));
        let (r, _) = run(vec![Ok(DpReply::status(502))]).await;
        assert_eq!(CliError::from(r.unwrap_err()).exit_code(), 7, "the VM runs: the endpoint's trouble");
        api.terminate(&id).await.unwrap();
        api.advance_all();
        let (r, _) = run(vec![Ok(DpReply::status(503))]).await;
        let e = r.unwrap_err();
        assert!(matches!(e, BridgeError::Terminated(_)), "{e:?}");
        assert_eq!(CliError::from(e).exit_code(), 8);
        let late = Exchange { api: &api, tokens: &tokens, vm_id: &id, port: 9418, cap: CAP_WORKSPACE_V1, route: "GET /seed", deadline: Some(tokio::time::Instant::now()), idempotent: true };
        let e = exchange(&late, |_t| async { Ok::<DpReply<SeedState>, BridgeError>(DpReply::status(200)) }).await.unwrap_err();
        assert!(matches!(&e, BridgeError::WorkspaceFailed { code: c, .. } if *c == crate::bridge::workspace::code::TOO_SLOW_FOR_INIT), "{e:?}");
    }

    /// S9: a 404 names the capability the route needs (`verdict` stays
    /// `workspace_v1`'s, its text byte for byte); every other status maps as
    /// before; a data plane that does not serve a transcript route fails
    /// closed; the shim's JSON payload is this client's own cap.
    #[tokio::test]
    async fn a_404_names_the_routes_cap_and_unserved_routes_fail_closed() {
        use crate::wire::frame::{CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1};
        let (_, old) = fail_code(verdict("GET /seed", 9418, &DpReply::<SeedState>::status(404)));
        let (_, same) = fail_code(verdict_cap("GET /seed", 9418, CAP_WORKSPACE_V1, &DpReply::<SeedState>::status(404)));
        assert_eq!(old, same);
        assert!(old.contains("older than S8"), "{old}");
        for (cap, route) in [(CAP_GIT_HTTP_V1, "GET /workspace.git/info/refs"), (CAP_TRANSCRIPT_S3_V1, "POST /transcript/push")] {
            match verdict_cap(route, 8080, cap, &DpReply::<SeedState>::status(404)) {
                Verdict::Fail(e @ BridgeError::NoCapability { .. }) => {
                    let text = e.to_string();
                    assert!(text.contains(cap) && text.contains("older than S9") && text.contains(&format!("{route} answered 404")), "{text}");
                    assert_eq!(exit(e), 7);
                }
                other => panic!("{other:?}"),
            }
            assert!(matches!(verdict_cap(route, 8080, cap, &DpReply::<SeedState>::status(403)), Verdict::Remint { .. }));
            assert!(matches!(verdict_cap(route, 8080, cap, &DpReply::<SeedState>::status(200)), Verdict::Done));
        }
        let target = AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: crate::wire::redact::Secret::new("t".into()), vpc: true, shell: false };
        let token = AuthToken { headers: std::collections::BTreeMap::new(), port: 8080, expires_at_unix: 0 };
        let q = ViewQuery { rel: "s/u.jsonl".into(), n: 10 };
        let e = Unreached.transcript_view(&target, &token, &q).await.unwrap_err();
        assert!(matches!(&e, BridgeError::Config(m) if m == "GET /transcript/view: this data plane does not serve it (S9)"), "{e:?}");
        assert_eq!(exit(e), 1);
        assert_eq!(MAX_JSON, crate::wire::workspace::JSON_PAYLOAD_MAX, "the helper's payload fits the client's read");
    }
}
