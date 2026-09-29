//! `GET /health` through the MicroVM endpoint (plan S4 D4, D30, step 5).
//!
//! [`HttpsEndpoint`] is the only real `EndpointClient`: it dials through
//! `tls::reqwest_client()` (TLS 1.3, Amazon Root CA 1–4 only, proxy
//! environment ignored) to `https://<bare host>/health` with the host pinned
//! by [`endpoint_url`], the token in a sensitive `x-aws-proxy-auth` header and
//! `x-aws-proxy-port`; a redirect is refused, never followed. [`read_health`]
//! is the retrying reader every command uses (D30): it asks the control plane
//! first, mints a 5-minute `Port(8080)` token, retries what can heal within a
//! budget ([`Backoff`]) that also bounds the request in flight, and records
//! what the shim reported in the VM row.
use crate::bridge::api::{normalize_endpoint, AuthToken, EndpointClient, HealthReply, MicrovmApi, VmInfo, VmState};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::registry::{is_vm_id, update_row};
use crate::bridge::vm::token::mint_internal;
use crate::wire::frame::{Health, HealthStatus};
use crate::wire::redact::scrub;
use crate::wire::time::unix_now;
use serde::Serialize;
use std::error::Error as StdError;
use std::time::Duration;
use tokio::time::{sleep, timeout, Instant};

/// Budget of one `/health` request: connect, TLS, headers and body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest `/health` body read (the shim's is a few hundred bytes).
pub const MAX_BODY: usize = 64 * 1024;
/// Bytes of a non-200 body kept (scrubbed) in [`HealthReply::body`].
pub const MAX_ERROR_BODY: usize = 512;
/// Longest `x-aws-proxy-error` value kept.
const MAX_PROXY_ERROR: usize = 128;

/// `https://<bare host><path>` for a MicroVM endpoint: the host must
/// normalise under the pin (`api::normalize_endpoint`: one label +
/// `.lambda-microvm.eu-central-1.on.aws`, optional `https://`), a plaintext
/// `http://` endpoint is refused by name, and `path` must be an absolute path
/// of `[A-Za-z0-9/_.-]` without `..`. Errors are `Endpoint` (exit 7) naming
/// the raw input.
pub fn endpoint_url(endpoint: &str, path: &str) -> Result<String, BridgeError> {
    if endpoint.trim_start().get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://")) {
        return Err(BridgeError::Endpoint(format!("refusing plaintext endpoint {endpoint:?}: MicroVM endpoints are https only")));
    }
    let host = normalize_endpoint(endpoint)?;
    let path_ok = path.starts_with('/') && !path.contains("..") && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'));
    if !path_ok {
        return Err(BridgeError::Endpoint(format!("refusing endpoint path {path:?}")));
    }
    Ok(format!("https://{host}{path}"))
}

// ---- the HTTPS client -----------------------------------------------------------------

/// The MicroVM endpoint over HTTPS, built on `tls::reqwest_client()` (the one
/// TLS policy; no other client is ever built).
pub struct HttpsEndpoint {
    client: reqwest::Client,
}

impl HttpsEndpoint {
    /// The client over `tls::reqwest_client()`; a failure to build it is final.
    pub fn new() -> Result<HttpsEndpoint, BridgeError> {
        let client = crate::bridge::tls::reqwest_client().map_err(|e| BridgeError::Sdk { op: "tls", message: format!("cannot build the HTTPS client: {e}") })?;
        Ok(HttpsEndpoint { client })
    }
}

impl EndpointClient for HttpsEndpoint {
    /// One `GET https://<endpoint>/health` ([`REQUEST_TIMEOUT`], body capped at
    /// [`MAX_BODY`]). Any HTTP status but a redirect is `Ok` (parsed as
    /// `reply_from_parts` describes); a 3xx is never followed and is a final
    /// `Sdk { op: "health" }` naming the `Location` origin; connect, timeout
    /// and reset failures are `Endpoint` (transient); a certificate or
    /// TLS-version failure is `Sdk { op: "tls" }` (final); a host outside the
    /// pin is refused before anything is sent (final).
    async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        let url = endpoint_url(endpoint, "/health").map_err(|e| BridgeError::Sdk { op: "health", message: e.to_string() })?;
        let value = token.value().map_err(|e| BridgeError::Sdk { op: "health", message: e.to_string() })?;
        let mut auth = reqwest::header::HeaderValue::from_str(value.expose()).map_err(|_| BridgeError::Sdk { op: "health", message: "the endpoint token is not a valid header value".into() })?;
        auth.set_sensitive(true);
        let mut resp = self
            .client
            .get(&url)
            .header("x-aws-proxy-auth", auth)
            .header("x-aws-proxy-port", port_header.to_string())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| transport_error(&url, &e))?;
        // The token must reach the pinned host only, so the client must never
        // follow a redirect (plan D4: `tls::reqwest_client()` with
        // `redirect::Policy::none()` and `https_only`). This check cannot undo
        // a redirect a client did follow — that request, token included, has
        // already gone out — it only refuses to trust its answer.
        if resp.url().as_str() != url {
            return Err(BridgeError::Sdk { op: "health", message: format!("GET {url} was redirected to another URL: refused (the endpoint token must be treated as exposed)") });
        }
        let status = resp.status().as_u16();
        if let Some(refused) = redirect_refusal(&url, status, resp.headers().get(reqwest::header::LOCATION)) {
            return Err(refused);
        }
        let headers = resp.headers().clone();
        let mut body = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp.chunk().await.map_err(|e| transport_error(&url, &e))? {
            let room = MAX_BODY - body.len();
            if chunk.len() > room {
                body.extend_from_slice(&chunk[..room]);
                truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        reply_from_parts(status, &headers, &body, truncated)
    }
}

/// Longest `Location` origin named in a redirect refusal.
const MAX_LOCATION: usize = 200;

/// A 3xx answer to `GET url` as a final `Sdk { op: "health" }` naming where
/// it pointed (the `Location` resolved against `url`, as `scheme://host[:port]`,
/// scrubbed; never its path or query), `None` for any other status. Nothing
/// is ever followed: the token goes to the pinned host only.
fn redirect_refusal(url: &str, status: u16, location: Option<&reqwest::header::HeaderValue>) -> Option<BridgeError> {
    if !(300..400).contains(&status) {
        return None;
    }
    let target = location
        .and_then(|v| v.to_str().ok())
        .and_then(|l| reqwest::Url::parse(url).ok()?.join(l.trim()).ok())
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null")
        .map_or_else(|| "no usable Location".to_string(), |o| scrub(&o.chars().take(MAX_LOCATION).collect::<String>()).into_owned());
    Some(BridgeError::Sdk { op: "health", message: format!("GET {url} answered HTTP {status} redirecting to {target}: refused (the bridge never follows a redirect with the endpoint token)") })
}

/// A `/health` response as a [`HealthReply`]: `x-aws-proxy-error` (printable
/// ASCII, at most 128 characters, scrubbed), `Retry-After` in seconds (the
/// HTTP-date form is ignored); a 200 must carry the shim's `Health` JSON
/// (unparseable or over [`MAX_BODY`] → `Http { status: 200 }` with the first
/// line of the reason, final); any other status keeps at most
/// [`MAX_ERROR_BODY`] bytes of its body, scrubbed.
fn reply_from_parts(status: u16, headers: &reqwest::header::HeaderMap, body: &[u8], truncated: bool) -> Result<HealthReply, BridgeError> {
    let proxy_error = headers.get("x-aws-proxy-error").map(|v| {
        let text: String = String::from_utf8_lossy(v.as_bytes()).chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(MAX_PROXY_ERROR).collect();
        scrub(&text).into_owned()
    });
    let retry_after_s = headers.get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<u64>().ok());
    if status == 200 {
        if truncated {
            return Err(BridgeError::Http { status, body: format!("the /health body exceeds {} KiB", MAX_BODY / 1024) });
        }
        let health: Health = serde_json::from_slice(body).map_err(|e| {
            let text = e.to_string();
            BridgeError::Http { status, body: format!("unparseable /health body: {}", scrub(text.lines().next().unwrap_or("unparseable"))) }
        })?;
        return Ok(HealthReply { status, proxy_error, retry_after_s, health: Some(health), body: String::new() });
    }
    let kept = &body[..body.len().min(MAX_ERROR_BODY)];
    let body = scrub(&String::from_utf8_lossy(kept)).into_owned();
    Ok(HealthReply { status, proxy_error, retry_after_s, health: None, body })
}

/// `e` and its sources, joined with `: `.
fn error_chain(e: &(dyn StdError + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut cur = e.source();
    while let Some(s) = cur {
        let text = s.to_string();
        if !parts.last().is_some_and(|p| p.contains(&text)) {
            parts.push(text);
        }
        cur = s.source();
    }
    parts.join(": ")
}

/// A TLS failure no retry can heal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsFailure {
    /// The certificate did not verify against the bridge's roots.
    Certificate(String),
    /// The peer cannot speak the bridge's TLS (1.3 only).
    Protocol(String),
}

fn classify_rustls(e: &rustls::Error) -> Option<TlsFailure> {
    match e {
        rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented | rustls::Error::UnsupportedNameType | rustls::Error::InvalidCertRevocationList(_) => {
            Some(TlsFailure::Certificate(e.to_string()))
        }
        rustls::Error::PeerIncompatible(_) => Some(TlsFailure::Protocol(e.to_string())),
        _ => None,
    }
}

/// Find the rustls error in `e`'s source chain (an `io::Error` hides its inner
/// error from `source()`, so each one is opened with `get_ref`), with the
/// rendered text as a fallback.
fn tls_failure(e: &(dyn StdError + 'static)) -> Option<TlsFailure> {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(r) = err.downcast_ref::<rustls::Error>() {
            if let Some(f) = classify_rustls(r) {
                return Some(f);
            }
        }
        if let Some(inner) = err.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref) {
            if let Some(f) = inner.downcast_ref::<rustls::Error>().and_then(classify_rustls) {
                return Some(f);
            }
        }
        cur = err.source();
    }
    let text = error_chain(e);
    text.contains("invalid peer certificate").then_some(TlsFailure::Certificate(text))
}

/// A transport failure of `GET url` as the bridge taxonomy: TLS verification
/// or version → final `Sdk { op: "tls" }`; a request that could not be built
/// or a redirect loop → final `Sdk { op: "health" }`; everything else
/// (connect, timeout, reset, a body cut short) → `Endpoint` (transient).
fn transport_error(url: &str, e: &reqwest::Error) -> BridgeError {
    let host = url.trim_start_matches("https://").split('/').next().unwrap_or(url);
    match tls_failure(e) {
        Some(TlsFailure::Certificate(m)) => return BridgeError::Sdk { op: "tls", message: format!("{host}: {} (bridge trusts Amazon Root CA 1\u{2013}4 only)", scrub(&m)) },
        Some(TlsFailure::Protocol(m)) => return BridgeError::Sdk { op: "tls", message: format!("{host}: {} (bridge speaks TLS 1.3 only)", scrub(&m)) },
        None => {}
    }
    let text = scrub(&error_chain(e)).into_owned();
    if e.is_builder() || e.is_redirect() {
        BridgeError::Sdk { op: "health", message: format!("GET {url}: {text}") }
    } else {
        BridgeError::Endpoint(format!("GET {url}: {text}"))
    }
}

// ---- read_health (D30) ----------------------------------------------------------------

/// How long [`read_health`] keeps trying: `step` between attempts (also the
/// unit a `Retry-After` of one second maps to) and the total `budget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The wait between attempts (and per second of `Retry-After`).
    pub step: Duration,
    /// Total time from the first `GetMicrovm`; no wait that would end past it is started.
    pub budget: Duration,
}

impl Backoff {
    /// Plan D30: every second, for up to 15 s.
    pub const HEALTH: Backoff = Backoff { step: Duration::from_secs(1), budget: Duration::from_secs(15) };

    /// `AI_ENV_BRIDGE_LAB_BACKOFF_MS=<n>` (plan D23): every second becomes
    /// `n` milliseconds, step and budget alike; `None` keeps `self`.
    #[must_use]
    pub fn scaled(self, ms_per_second: Option<u64>) -> Backoff {
        let Some(n) = ms_per_second else { return self };
        let scale = |d: Duration| Duration::from_nanos(u64::try_from(d.as_nanos().saturating_mul(u128::from(n)) / 1000).unwrap_or(u64::MAX));
        Backoff { step: scale(self.step), budget: scale(self.budget) }
    }

    /// The wait a `Retry-After: <secs>` asks for, in this backoff's units.
    fn retry_after(self, secs: u64) -> Duration {
        self.step.saturating_mul(u32::try_from(secs.max(1)).unwrap_or(u32::MAX))
    }
}

/// How a successful [`read_health`] went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct HealthStats {
    /// `/health` requests sent.
    pub attempts: u32,
    /// From the first `GetMicrovm` to the 200.
    pub elapsed_ms: u64,
    /// A 401/403 made it mint a second token.
    pub reminted: bool,
    /// The VM was SUSPENDED/SUSPENDING with auto-resume: the request resumed it.
    pub resumed_note: bool,
}

fn terminated(vm: &VmInfo) -> BridgeError {
    let reason = vm.state_reason.as_deref().map(|r| format!(" ({})", scrub(r))).unwrap_or_default();
    BridgeError::Terminated(format!("{} is {}{reason}", vm.id, vm.state.as_str()))
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

/// Read `/health` of VM `id` (plan D30):
///
/// 1. `GetMicrovm`: not found → `VmNotFound`, TERMINATING/TERMINATED →
///    `Terminated` (both exit 8); SUSPENDED/SUSPENDING with auto-resume is
///    noted (`resumed_note`: the request resumes it), without auto-resume it
///    is a `Conflict` naming `ai-env vm resume`; PENDING or an empty endpoint
///    is asked again every step within the budget; a foreign endpoint host is
///    exit 7.
/// 2. A 5-minute `Port(8080)` token ([`mint_internal`], expiry in the row).
/// 3. `GET /health`, each request cut off at what is left of the budget (at
///    least one step; a cut-off counts as a transient failure), so no request
///    outlives it: 502/503/504 and transient transport errors are retried
///    every step, 429 after its `Retry-After`, a 200 with `status = booting`
///    every step, all within the budget; 401/403 → one re-mint, then
///    `TokenRejected` with `x-aws-proxy-error`; `draining` → `Terminated`
///    (exit 8); a `microvm_id` other than `id` → `Endpoint` (exit 7); any
///    other status → `Http` (exit 7). When the budget runs out the control
///    plane is asked once more (a VM that died meanwhile is exit 8), else
///    `Endpoint` naming the attempts and the last answer (exit 7).
///
/// On success the row `state/vms/<id>.toml`, when it exists, records
/// `last_health_at`, `boot_nonce`, `claude_version` and `shim_version` (a row
/// that cannot be updated costs a `warn!`, never the answer).
pub async fn read_health<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, id: &str, backoff: Backoff) -> Result<(Health, HealthStats), BridgeError> {
    let start = Instant::now();
    let deadline = start + backoff.budget;
    let mut stats = HealthStats::default();
    let endpoint = loop {
        let vm = api.get(id).await?;
        if vm.state.is_terminal() {
            return Err(terminated(&vm));
        }
        if matches!(vm.state, VmState::Suspended | VmState::Suspending) {
            if vm.idle.is_some_and(|i| !i.auto_resume) {
                return Err(BridgeError::Conflict(format!("{id} is {} without auto-resume: `ai-env vm resume {id}` first", vm.state.as_str())));
            }
            stats.resumed_note = true;
        }
        if !vm.endpoint.is_empty() && vm.state != VmState::Pending {
            break vm.endpoint;
        }
        if Instant::now() + backoff.step > deadline {
            let what = if vm.endpoint.is_empty() { "has no endpoint yet" } else { "is still PENDING" };
            return Err(BridgeError::Endpoint(format!("{id} {what} (state {}) after {}", vm.state.as_str(), secs(start.elapsed()))));
        }
        sleep(backoff.step).await;
    };
    endpoint_url(&endpoint, "/health")?;
    let mut token = mint_internal(api, paths, id).await?;
    loop {
        stats.attempts += 1;
        // No request outlives the budget (D30): the one in flight gets what is left of it, at least one step.
        let room = deadline.saturating_duration_since(Instant::now()).max(backoff.step);
        let answer = match timeout(room, ep.get_health(&endpoint, &token, token.port)).await {
            Ok(answer) => answer,
            Err(_) => Err(BridgeError::Endpoint(format!("no /health answer within {}", secs(room)))),
        };
        let (wait, last) = match answer {
            Ok(reply) => match reply.status {
                200 => {
                    let Some(h) = reply.health else {
                        return Err(BridgeError::Http { status: 200, body: "no /health body".into() });
                    };
                    if let Some(other) = h.microvm_id.as_deref().filter(|m| *m != id) {
                        return Err(BridgeError::Endpoint(format!("{endpoint} answered for {other}, not {id}")));
                    }
                    match h.status {
                        HealthStatus::Ok => {
                            stats.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                            record_health(paths, id, &h);
                            return Ok((h, stats));
                        }
                        HealthStatus::Draining => return Err(BridgeError::Terminated(format!("{id}: the shim is draining (the VM is shutting down)"))),
                        HealthStatus::Booting => (backoff.step, "HTTP 200, the shim is booting".to_string()),
                    }
                }
                401 | 403 => {
                    if stats.reminted {
                        return Err(BridgeError::TokenRejected { port: token.port, status: reply.status, proxy_error: reply.proxy_error });
                    }
                    stats.reminted = true;
                    token = mint_internal(api, paths, id).await?;
                    continue;
                }
                429 => {
                    let n = reply.retry_after_s.unwrap_or(1).max(1);
                    (backoff.retry_after(n), format!("HTTP 429, Retry-After {n} s"))
                }
                502..=504 => (backoff.step, format!("HTTP {}{}", reply.status, reply.proxy_error.as_deref().map(|p| format!(" ({p})")).unwrap_or_default())),
                status => {
                    let mut body = reply.proxy_error.map(|p| format!("x-aws-proxy-error: {p}")).unwrap_or_default();
                    if !reply.body.is_empty() {
                        body = if body.is_empty() { reply.body } else { format!("{body}; {}", reply.body) };
                    }
                    return Err(BridgeError::Http { status, body });
                }
            },
            Err(BridgeError::Endpoint(m)) => (backoff.step, m),
            Err(e) => return Err(e),
        };
        if Instant::now() + wait > deadline {
            let vm = api.get(id).await?;
            if vm.state.is_terminal() {
                return Err(terminated(&vm));
            }
            return Err(BridgeError::Endpoint(format!("{id}: /health not ready after {} and {} attempt(s) (last: {last})", secs(start.elapsed()), stats.attempts)));
        }
        sleep(wait).await;
    }
}

/// The row's view of the shim, refreshed after a 200 (under the rows lock, `registry::update_row`).
fn record_health(paths: &Paths, id: &str, h: &Health) {
    let update = || -> Result<(), BridgeError> {
        if !is_vm_id(id) {
            return Ok(());
        }
        let now = unix_now();
        update_row(paths, id, |row| {
            row.last_health_at = Some(now);
            if h.boot_nonce.is_some() {
                row.boot_nonce.clone_from(&h.boot_nonce);
            }
            if h.claude_version.is_some() {
                row.claude_version.clone_from(&h.claude_version);
            }
            row.shim_version = Some(h.shim_version.clone());
        })?;
        Ok(())
    };
    if let Err(e) = update() {
        tracing::warn!("vm {id}: /health answered, but the row was not updated: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, RunSpec, ENDPOINT_SUFFIX, FAKE_IMAGE_ARN};
    use crate::bridge::vm::registry::{read_row, write_row, RowStatus, VmRow};
    use crate::errors::CliError;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Milliseconds instead of seconds: step 2 ms, budget 30 ms (for tests that run it out).
    fn fast() -> Backoff {
        Backoff::HEALTH.scaled(Some(2))
    }

    /// Step 2 ms with a budget no loaded machine exhausts (for tests that must succeed after retries).
    fn roomy() -> Backoff {
        Backoff { step: Duration::from_millis(2), budget: Duration::from_secs(10) }
    }

    fn paths(dir: &std::path::Path) -> Paths {
        Paths::from_root_and_env(dir.to_path_buf(), None)
    }

    fn spec(token: &str) -> RunSpec {
        RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: token.into(),
        }
    }

    /// A RUNNING VM in a fresh fake.
    async fn running() -> (FakeMicrovmApi, String) {
        let api = FakeMicrovmApi::new();
        let vm = api.run(&spec("01926f2e-0000-7000-8000-0000000000b1")).await.unwrap();
        api.advance_all();
        (api, vm.id)
    }

    fn health(id: &str, status: HealthStatus) -> Health {
        Health {
            status,
            shim_version: "0.1.0".into(),
            claude_version: Some("2.1.284".into()),
            microvm_id: Some(id.into()),
            owner: Some("mike@host".into()),
            created: None,
            boot_nonce: Some("ab".repeat(16)),
            run_hook_seen: true,
            uptime_s: 1,
        }
    }

    fn exit(e: BridgeError) -> i32 {
        CliError::from(e).exit_code()
    }

    fn token_calls(api: &FakeMicrovmApi) -> usize {
        api.calls().iter().filter(|c| matches!(c, Call::Token { .. })).count()
    }

    /// Answers from a script first, then from the fake (which also sees every call).
    struct Scripted<'a> {
        fake: &'a FakeMicrovmApi,
        replies: Mutex<VecDeque<Result<HealthReply, BridgeError>>>,
    }

    impl<'a> Scripted<'a> {
        fn new(fake: &'a FakeMicrovmApi, replies: Vec<Result<HealthReply, BridgeError>>) -> Self {
            Scripted { fake, replies: Mutex::new(replies.into()) }
        }
    }

    impl EndpointClient for Scripted<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            let next = self.replies.lock().unwrap().pop_front();
            match next {
                Some(r) => r,
                None => self.fake.get_health(endpoint, token, port_header).await,
            }
        }
    }

    fn reply(status: u16, health: Option<Health>, retry_after_s: Option<u64>) -> Result<HealthReply, BridgeError> {
        Ok(HealthReply { status, proxy_error: None, retry_after_s, health, body: String::new() })
    }

    #[test]
    fn endpoint_url_pins_host_scheme_and_path() {
        let host = format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{ENDPOINT_SUFFIX}");
        assert_eq!(endpoint_url(&host, "/health").unwrap(), format!("https://{host}/health"));
        assert_eq!(endpoint_url(&format!("https://{host}/"), "/health").unwrap(), format!("https://{host}/health"));
        let e = endpoint_url(&format!("http://{host}"), "/health").unwrap_err();
        assert!(e.to_string().contains("plaintext"), "{e}");
        assert!(endpoint_url(&format!("HTTP://{host}"), "/health").unwrap_err().to_string().contains("plaintext"));
        for bad in ["evil.example.com".to_string(), format!("{host}:8443"), format!("{host}.evil.com"), String::new()] {
            assert!(matches!(endpoint_url(&bad, "/health"), Err(BridgeError::Endpoint(_))), "{bad}");
        }
        for bad in ["health", "/../x", "/a?b=c", "/a b", "//x/../y"] {
            assert!(matches!(endpoint_url(&host, bad), Err(BridgeError::Endpoint(_))), "{bad}");
        }
        assert_eq!(exit(endpoint_url("evil.example.com", "/health").unwrap_err()), 7);
    }

    #[test]
    fn backoff_scaling() {
        assert_eq!(Backoff::HEALTH, Backoff { step: Duration::from_secs(1), budget: Duration::from_secs(15) });
        assert_eq!(Backoff::HEALTH.scaled(None), Backoff::HEALTH);
        assert_eq!(Backoff::HEALTH.scaled(Some(10)), Backoff { step: Duration::from_millis(10), budget: Duration::from_millis(150) });
        assert_eq!(Backoff::HEALTH.scaled(Some(1000)), Backoff::HEALTH);
        let odd = Backoff { step: Duration::from_millis(1500), budget: Duration::from_secs(90) }.scaled(Some(4));
        assert_eq!(odd, Backoff { step: Duration::from_millis(6), budget: Duration::from_millis(360) });
        assert_eq!(Backoff::HEALTH.scaled(Some(0)).budget, Duration::ZERO);
        assert_eq!(fast().retry_after(3), Duration::from_millis(6), "Retry-After counts in steps (one step = one second)");
        assert_eq!(fast().retry_after(0), fast().step);
    }

    #[test]
    fn replies_from_parts() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("x-aws-proxy-error", HeaderValue::from_static("UNAUTHORIZED"));
        h.insert("retry-after", HeaderValue::from_static("7"));
        let r = reply_from_parts(403, &h, &vec![b'x'; 2000], false).unwrap();
        assert_eq!((r.status, r.proxy_error.as_deref(), r.retry_after_s), (403, Some("UNAUTHORIZED"), Some(7)));
        assert_eq!(r.body.len(), MAX_ERROR_BODY);
        assert!(r.health.is_none());
        let secret_body = format!("session_token={}", "q".repeat(40));
        let r = reply_from_parts(500, &HeaderMap::new(), secret_body.as_bytes(), false).unwrap();
        assert!(!r.body.contains(&"q".repeat(40)), "scrubbed: {}", r.body);
        let mut dated = HeaderMap::new();
        dated.insert("retry-after", HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"));
        assert_eq!(reply_from_parts(429, &dated, b"", false).unwrap().retry_after_s, None);

        let good = serde_json::to_vec(&health("microvm-1", HealthStatus::Ok)).unwrap();
        let r = reply_from_parts(200, &HeaderMap::new(), &good, false).unwrap();
        assert_eq!(r.health.unwrap().microvm_id.as_deref(), Some("microvm-1"));
        let e = reply_from_parts(200, &HeaderMap::new(), b"{\"status\":\"ok\"}\n", false).unwrap_err();
        assert!(matches!(e, BridgeError::Http { status: 200, .. }), "{e}");
        assert!(e.to_string().contains("unparseable /health body") && !e.to_string().contains('\n'), "{e}");
        let e = reply_from_parts(200, &HeaderMap::new(), &good, true).unwrap_err();
        assert!(e.to_string().contains("exceeds 64 KiB"), "{e}");
    }

    #[test]
    fn redirects_are_refused_naming_only_the_location_origin() {
        use reqwest::header::HeaderValue;
        let url = format!("https://bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{ENDPOINT_SUFFIX}/health");
        for status in [200, 204, 403, 404, 502] {
            assert!(redirect_refusal(&url, status, Some(&HeaderValue::from_static("http://127.0.0.1:1/"))).is_none(), "{status}");
        }
        let plain = HeaderValue::from_static("http://127.0.0.1:9999/elsewhere?session=abc");
        let e = redirect_refusal(&url, 302, Some(&plain)).unwrap();
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Sdk { op: "health", .. }), "final, not retried: {text}");
        assert!(text.contains("HTTP 302 redirecting to http://127.0.0.1:9999: refused") && !text.contains("elsewhere") && !text.contains("session"), "{text}");
        assert_eq!(exit(e), 7);
        let relative = redirect_refusal(&url, 307, Some(&HeaderValue::from_static("/other"))).unwrap().to_string();
        assert!(relative.contains(&format!("redirecting to https://bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{ENDPOINT_SUFFIX}: refused")), "{relative}");
        for (status, loc) in [(301, None), (308, Some(HeaderValue::from_static("data:text/plain,x")))] {
            assert!(redirect_refusal(&url, status, loc.as_ref()).unwrap().to_string().contains("no usable Location"), "{status}");
        }
    }

    #[derive(Debug)]
    struct Wrapper(std::io::Error);
    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("client error (Connect)")
        }
    }
    impl StdError for Wrapper {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn tls_failures_are_found_behind_io_errors() {
        let cert = Wrapper(std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)));
        assert!(matches!(tls_failure(&cert), Some(TlsFailure::Certificate(m)) if m.contains("UnknownIssuer")));
        let version = Wrapper(std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::PeerIncompatible(rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig)));
        assert!(matches!(tls_failure(&version), Some(TlsFailure::Protocol(_))));
        let reset = Wrapper(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert_eq!(tls_failure(&reset), None);
        let other = Wrapper(std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::DecryptError));
        assert_eq!(tls_failure(&other), None, "not a verification failure: transient");
        let texty = Wrapper(std::io::Error::other("invalid peer certificate: Expired"));
        assert!(matches!(tls_failure(&texty), Some(TlsFailure::Certificate(_))), "text fallback");
    }

    #[tokio::test]
    async fn https_endpoint_refuses_foreign_hosts_before_sending() {
        let ep = HttpsEndpoint::new().unwrap();
        let (api, id) = running().await;
        let token = api.create_auth_token(&id, 5, 8080).await.unwrap();
        for host in ["evil.example.com", "http://x.lambda-microvm.eu-central-1.on.aws", "127.0.0.1"] {
            let e = ep.get_health(host, &token, 8080).await.unwrap_err();
            assert!(matches!(e, BridgeError::Sdk { op: "health", .. }), "final, not retried: {e}");
            assert_eq!(exit(e), 7);
        }
    }

    #[tokio::test]
    async fn health_ok_first_try_updates_the_row_and_records_the_token_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let (api, id) = running().await;
        write_row(&p, &VmRow { id: id.clone(), status: RowStatus::Running, client_token: "01926f2e-0000-7000-8000-0000000000b1".into(), ..VmRow::default() }).unwrap();
        let (h, stats) = read_health(&api, &api, &p, &id, fast()).await.unwrap();
        assert_eq!(h.status, HealthStatus::Ok);
        assert_eq!((stats.attempts, stats.reminted, stats.resumed_note), (1, false, false));
        let row = read_row(&p, &id).unwrap().unwrap();
        assert!(row.last_health_at.is_some());
        assert_eq!(row.boot_nonce, h.boot_nonce);
        assert_eq!(row.claude_version.as_deref(), Some("2.1.284"));
        assert_eq!(row.shim_version.as_deref(), Some("0.1.0"));
        let exp = *row.token_expiries.get("8080").expect("the internal token's expiry is recorded");
        assert!(exp >= unix_now() + 290);
        assert_eq!(api.calls()[1..3], [Call::Get(id.clone()), Call::Token { id: id.clone(), minutes: 5, port: 8080 }], "GetMicrovm first, then one 5-minute Port(8080) token");
    }

    #[tokio::test]
    async fn health_retries_502_503_504_and_booting_then_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        api.script_health(&id, &[502, 503, 504]);
        let booting = health(&id, HealthStatus::Booting);
        let ep = Scripted::new(&api, vec![Err(BridgeError::Endpoint("connection reset".into()))]);
        let first = read_health(&api, &ep, &paths(dir.path()), &id, roomy()).await.unwrap();
        assert_eq!(first.1.attempts, 5, "reset + 502 + 503 + 504 + 200");
        let ep = Scripted::new(&api, vec![reply(200, Some(booting.clone()), None), reply(200, Some(booting), None)]);
        let (h, stats) = read_health(&api, &ep, &paths(dir.path()), &id, roomy()).await.unwrap();
        assert_eq!((h.status, stats.attempts), (HealthStatus::Ok, 3));
        assert!(stats.elapsed_ms < 1000);
    }

    #[tokio::test]
    async fn health_budget_exhausted_is_exit_7() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        api.script_health(&id, &[502; 200]);
        let e = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap_err();
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Endpoint(_)), "{text}");
        assert!(text.contains("/health not ready after") && text.contains("(last: HTTP 502)"), "{text}");
        assert_eq!(exit(e), 7);
        assert!(matches!(api.calls().last(), Some(Call::Get(_))), "the control plane is asked once more at the end");
    }

    #[tokio::test]
    async fn health_403_remints_once_then_token_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        api.expire_tokens();
        let e = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap_err();
        match &e {
            BridgeError::TokenRejected { port, status, proxy_error } => assert_eq!((*port, *status, proxy_error.as_deref()), (8080, 403, Some("UNAUTHORIZED"))),
            other => panic!("{other}"),
        }
        assert_eq!(exit(e), 7);
        assert_eq!(token_calls(&api), 2, "exactly one re-mint");
        let health_calls = api.calls().iter().filter(|c| matches!(c, Call::Health { .. })).count();
        assert_eq!(health_calls, 2);

        let (api, id) = running().await;
        let ep = Scripted::new(&api, vec![reply(401, None, None)]);
        let (_, stats) = read_health(&api, &ep, &paths(dir.path()), &id, fast()).await.unwrap();
        assert!(stats.reminted, "a fresh token heals a 401");
        assert_eq!(token_calls(&api), 2);
    }

    #[tokio::test]
    async fn health_terminated_or_draining_is_exit_8() {
        let dir = tempfile::tempdir().unwrap();
        for state in [VmState::Terminating, VmState::Terminated] {
            let (api, id) = running().await;
            api.set_state(&id, state);
            let e = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap_err();
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            assert_eq!(exit(e), 8);
            assert_eq!(token_calls(&api), 0, "no token for a terminal VM");
        }
        let (api, id) = running().await;
        api.set_health(&id, health(&id, HealthStatus::Draining));
        let e = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap_err();
        assert!(e.to_string().contains("draining"), "{e}");
        assert_eq!(exit(e), 8);
        let api = FakeMicrovmApi::new();
        let e = read_health(&api, &api, &paths(dir.path()), "microvm-00000000-0000-4000-8000-00000000dead", fast()).await.unwrap_err();
        assert!(matches!(e, BridgeError::VmNotFound(_)), "{e}");
        assert_eq!(exit(e), 8);
    }

    /// The platform terminates the VM while `/health` answers 502.
    struct DiesOnFirstRequest<'a>(&'a FakeMicrovmApi, String);

    impl EndpointClient for DiesOnFirstRequest<'_> {
        async fn get_health(&self, _endpoint: &str, _token: &AuthToken, _port_header: u16) -> Result<HealthReply, BridgeError> {
            self.0.set_state(&self.1, VmState::Terminated);
            reply(502, None, None)
        }
    }

    #[tokio::test]
    async fn health_terminated_during_retries_is_exit_8() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        let e = read_health(&api, &DiesOnFirstRequest(&api, id.clone()), &paths(dir.path()), &id, fast()).await.unwrap_err();
        assert!(matches!(e, BridgeError::Terminated(_)), "the last look at the control plane decides: {e}");
        assert_eq!(exit(e), 8);
        assert_eq!(token_calls(&api), 1);
    }

    /// A proxy that accepts and never answers.
    struct Hangs;

    impl EndpointClient for Hangs {
        async fn get_health(&self, _endpoint: &str, _token: &AuthToken, _port_header: u16) -> Result<HealthReply, BridgeError> {
            sleep(Duration::from_secs(60)).await;
            reply(503, None, None)
        }
    }

    #[tokio::test]
    async fn health_budget_bounds_the_request_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        let backoff = Backoff { step: Duration::from_millis(10), budget: Duration::from_millis(80) };
        let t0 = std::time::Instant::now();
        let e = read_health(&api, &Hangs, &paths(dir.path()), &id, backoff).await.unwrap_err();
        let took = t0.elapsed();
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Endpoint(_)), "{text}");
        assert!(text.contains("1 attempt(s) (last: no /health answer within 0.1 s)"), "{text}");
        assert!(took < Duration::from_secs(5), "no request outlives the budget: {took:?}");
        assert_eq!(exit(e), 7);
    }

    #[tokio::test]
    async fn health_microvm_id_mismatch_is_exit_7() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        api.set_health(&id, health("microvm-00000000-0000-4000-8000-0000000000ff", HealthStatus::Ok));
        let e = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap_err();
        let text = e.to_string();
        assert!(matches!(e, BridgeError::Endpoint(_)) && text.contains("answered for microvm-00000000-0000-4000-8000-0000000000ff"), "{text}");
        assert_eq!(exit(e), 7);
        let mut anonymous = health(&id, HealthStatus::Ok);
        anonymous.microvm_id = None;
        api.set_health(&id, anonymous);
        assert!(read_health(&api, &api, &paths(dir.path()), &id, fast()).await.is_ok(), "no id reported is not a mismatch");
    }

    #[tokio::test]
    async fn health_429_honours_retry_after_within_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        let slow = Backoff { step: Duration::from_millis(5), budget: Duration::from_secs(10) };
        let ep = Scripted::new(&api, vec![reply(429, None, Some(4))]);
        let (_, stats) = read_health(&api, &ep, &paths(dir.path()), &id, slow).await.unwrap();
        assert_eq!(stats.attempts, 2);
        assert!(stats.elapsed_ms >= 20, "waited Retry-After 4 × 5 ms: {} ms", stats.elapsed_ms);
        let ep = Scripted::new(&api, vec![reply(429, None, Some(3600))]);
        let e = read_health(&api, &ep, &paths(dir.path()), &id, slow).await.unwrap_err();
        assert!(e.to_string().contains("Retry-After 3600 s"), "a wait beyond the budget is not taken: {e}");
        assert_eq!(exit(e), 7);
        api.script_health(&id, &[429]);
        assert_eq!(read_health(&api, &api, &paths(dir.path()), &id, roomy()).await.unwrap().1.attempts, 2, "the fake's Retry-After: 1");
    }

    #[tokio::test]
    async fn health_final_errors_are_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        let tls = BridgeError::Sdk { op: "tls", message: "x (bridge trusts Amazon Root CA 1\u{2013}4 only)".into() };
        let ep = Scripted::new(&api, vec![Err(tls)]);
        let e = read_health(&api, &ep, &paths(dir.path()), &id, fast()).await.unwrap_err();
        assert!(matches!(e, BridgeError::Sdk { op: "tls", .. }), "{e}");
        let ep = Scripted::new(&api, vec![Ok(HealthReply { status: 404, proxy_error: Some("NOT_FOUND".into()), retry_after_s: None, health: None, body: "nope".into() })]);
        let e = read_health(&api, &ep, &paths(dir.path()), &id, fast()).await.unwrap_err();
        assert_eq!(e.to_string(), "endpoint HTTP 404: x-aws-proxy-error: NOT_FOUND; nope");
    }

    #[tokio::test]
    async fn health_notes_a_suspended_vm_and_refuses_one_without_auto_resume() {
        let dir = tempfile::tempdir().unwrap();
        let (api, id) = running().await;
        api.suspend(&id).await.unwrap();
        let (_, stats) = read_health(&api, &api, &paths(dir.path()), &id, fast()).await.unwrap();
        assert!(stats.resumed_note);
        assert_eq!(api.get(&id).await.unwrap().state, VmState::Running, "the request resumed it");

        let api = FakeMicrovmApi::new();
        let vm = api.run(&RunSpec { idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: false }, ..spec("01926f2e-0000-7000-8000-0000000000b2") }).await.unwrap();
        api.advance_all();
        api.suspend(&vm.id).await.unwrap();
        let e = read_health(&api, &api, &paths(dir.path()), &vm.id, fast()).await.unwrap_err();
        assert!(matches!(e, BridgeError::Conflict(_)) && e.to_string().contains("ai-env vm resume"), "{e}");
    }

    #[tokio::test]
    async fn health_waits_for_pending_and_an_endpoint_within_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let api = FakeMicrovmApi::new();
        let vm = api.run(&spec("01926f2e-0000-7000-8000-0000000000b3")).await.unwrap();
        let e = read_health(&api, &api, &paths(dir.path()), &vm.id, fast()).await.unwrap_err();
        assert!(e.to_string().contains("still PENDING"), "{e}");
        assert_eq!(exit(e), 7);
        api.set_auto_advance(true);
        assert!(read_health(&api, &api, &paths(dir.path()), &vm.id, fast()).await.is_ok(), "PENDING → RUNNING on the next look");

        let mut bare = api.get(&vm.id).await.unwrap();
        bare.id = "microvm-00000000-0000-4000-8000-0000000000e0".into();
        bare.endpoint = String::new();
        api.insert_vm(bare.clone());
        let e = read_health(&api, &api, &paths(dir.path()), &bare.id, fast()).await.unwrap_err();
        assert!(e.to_string().contains("has no endpoint yet"), "{e}");
        assert!(api.calls().iter().filter(|c| **c == Call::Get(bare.id.clone())).count() > 1, "asked again within the budget");

        bare.id = "microvm-00000000-0000-4000-8000-0000000000e1".into();
        bare.endpoint = "evil.example.com".into();
        api.insert_vm(bare.clone());
        let e = read_health(&api, &api, &paths(dir.path()), &bare.id, fast()).await.unwrap_err();
        assert!(matches!(e, BridgeError::Endpoint(_)) && e.to_string().contains("evil.example.com"), "{e}");
        assert!(!api.calls().contains(&Call::Token { id: bare.id.clone(), minutes: 5, port: 8080 }), "no token for a foreign host");
    }
}
