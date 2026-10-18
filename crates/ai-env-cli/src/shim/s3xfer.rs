//! The transcript store's transfers in the VM (S9 plan §5, M2 to M4; the
//! app port, behind the bearer): `POST /transcript/push` streams a range of
//! the agent's transcript (the helper's `transcript-read`, uid 1000) into
//! curl (uid 999 `ai-env-net`, its presigned URL on fd 3 only) and on to S3;
//! `POST /transcript/pull` streams each part curl reads into the helper's
//! `transcript-write`, every part's length and sha256 checked before the
//! `commit` line lets it rename; `GET /transcript/view` answers the helper's
//! `transcript-view`; `POST /transcript/tail` keeps one URL per session's
//! main transcript for `/suspend` and `/terminate` ([`tail_push`]; never a
//! subtree file's, which `TranscriptTail::check` refuses: its key names no
//! file, and a subtree file goes up whole at the next sync). The root shim
//! pipes and checks; it never reads or writes a path the agent can write,
//! and a URL never reaches an argv, an environment, a file or a log line
//! (`wire::s3::PresignedUrl`). At most `TRANSFERS_MAX` runs at once, one per
//! rel; none holds the workspace lock or uses the inbox.
//!
//! The routes are mounted (`health::router`) and `CAP_TRANSCRIPT_S3_V1`
//! named (`ShimState::caps`) exactly when [`SERVED`] is true. curl runs as
//! `childproc::spawn_curl` starts it (S9 §3.4): `-q -K /dev/fd/3`, its
//! configuration ([`curl_config`], pinned line by line: the one place the
//! VM reads a URL, `PresignedUrl::expose`) on fd 3, its status, version id
//! and checksum on one `ai-env-curl` stderr line its write-out prints. A
//! push answers 200 whenever curl reported an HTTP status, S3's own in the
//! reply (412, 400 `BadDigest`, 403 … are the Mac's to judge); a pull
//! answers 201 written, 200 not (a part's status, length or sha256 wrong:
//! nothing renamed); `transfer_failed` (500) is curl without a status (the
//! proxy, a connection) or the helper's bytes cut short. A run waits for
//! its rel's turn and a slot at most the workspace's `busy_wait` (then 409
//! `busy`), and ends with its budget (`budget::TRANSCRIPT_PUSH` or `_PULL`
//! plus the bytes' transfer time; 504 past it).
use crate::shim::health::ShimState;
use crate::wire::workspace::{refusal, WsRefusal};
use axum::extract::{Request, State};
use axum::response::Response;
use std::sync::Arc;
use std::time::Instant;

use crate::shim::asagent::{self, flag, AgentCmd, AgentProc, AgentProcError, EOF_GRACE};
use crate::wire::s3::{sha256_b64, PresignedUrl, PUSH_MAX};
use crate::wire::view::TranscriptViewReply;
use crate::wire::workspace::{budget, HelperHead, JsonPayloadReply, PullPartReport, TranscriptPull, TranscriptPullReply, TranscriptPush, TranscriptPushReply, TranscriptReadReply, TranscriptStat, TranscriptTail, TranscriptWriteReply, ViewQuery};
use crate::wire::workspace::{JSON_PAYLOAD_MAX, PULL_MAX, TRANSFERS_MAX, TRANSFER_REQUEST_MAX};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::task::JoinHandle;

/// Whether this build serves the transfer routes and the extended stat (and names `transcript_s3_v1`).
pub const SERVED: bool = true;

/// A push's stdout kept, for S3's `<Code>` (its error document).
const CURL_STDOUT_MAX: usize = 16 * 1024;
/// One stderr line of curl as it is read and logged, at most.
const CURL_LINE_MAX: usize = 4096;
/// One logged line of curl's, in characters.
const CURL_SHOWN_MAX: usize = 300;
/// curl's own wait for its connection (the proxy's, or the lab's S3).
const CONNECT_TIMEOUT_S: u64 = 20;
/// The first word of the line curl's write-out prints on its stderr.
const STATUS_WORD: &str = "ai-env-curl ";
/// curl's write-out (S9 §3.4): S3's status, version id, checksum and ETag, one line on stderr.
const WRITE_OUT: &str = r#"write-out = "%{stderr}ai-env-curl status=%{http_code} version=%header{x-amz-version-id} checksum=%header{x-amz-checksum-sha256} etag=%header{etag}\n""#;
/// One read of a part.
const CHUNK: usize = 64 * 1024;

// ---- the runs and the tails ------------------------------------------------------------------

/// What the shim holds of the transfers: the runs under way, the tails waiting for a hook.
#[derive(Debug)]
pub struct Transfers {
    /// Push, pull and tail runs at once: at most `TRANSFERS_MAX`.
    runs: Arc<tokio::sync::Semaphore>,
    /// Each rel's turn (one run per rel), made at its first run, let go once nobody holds or waits for it.
    rels: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// The tail kept per main transcript's rel (`POST /transcript/tail`), until it expires or a hook pushed it.
    tails: Mutex<BTreeMap<String, TranscriptTail>>,
}

impl Default for Transfers {
    fn default() -> Self {
        Transfers { runs: Arc::new(tokio::sync::Semaphore::new(TRANSFERS_MAX)), rels: Mutex::default(), tails: Mutex::default() }
    }
}

/// A run's hold: its rel's turn and one slot, let go when dropped.
struct Slot {
    _turn: tokio::sync::OwnedMutexGuard<()>,
    _run: tokio::sync::OwnedSemaphorePermit,
}

impl Transfers {
    /// `rel`'s turn, then a slot, each waited for until `until`; `Err` says what was held.
    async fn slot(&self, rel: &str, until: tokio::time::Instant) -> Result<Slot, &'static str> {
        let turn = {
            let mut rels = self.rels.lock().unwrap_or_else(PoisonError::into_inner);
            rels.retain(|r, t| r == rel || Arc::strong_count(t) > 1);
            Arc::clone(rels.entry(rel.to_string()).or_default())
        };
        let turn = tokio::time::timeout_at(until, turn.lock_owned()).await.map_err(|_| "another transfer of this transcript is under way")?;
        let run = tokio::time::timeout_at(until, Arc::clone(&self.runs).acquire_owned()).await.ok().and_then(Result::ok).ok_or("every transfer slot is taken")?;
        Ok(Slot { _turn: turn, _run: run })
    }

    /// Keep `tail` for its rel, in place of the one before; the expired go.
    fn keep_tail(&self, tail: TranscriptTail, now: u64) {
        let mut tails = self.tails.lock().unwrap_or_else(PoisonError::into_inner);
        tails.retain(|_, t| t.expires_at > now);
        tails.insert(tail.rel.clone(), tail);
    }

    /// The tails a hook may push now: every one not expired (the expired go).
    fn tails_due(&self, now: u64) -> Vec<TranscriptTail> {
        let mut tails = self.tails.lock().unwrap_or_else(PoisonError::into_inner);
        tails.retain(|_, t| t.expires_at > now);
        tails.values().cloned().collect()
    }

    /// `tail` is pushed now, at most once: it goes, unless another replaced it meanwhile.
    fn take_tail(&self, tail: &TranscriptTail) {
        let mut tails = self.tails.lock().unwrap_or_else(PoisonError::into_inner);
        if tails.get(&tail.rel) == Some(tail) {
            tails.remove(&tail.rel);
        }
    }
}

// ---- the routes ------------------------------------------------------------------------------

/// The request's JSON body as `T` (S9 §1.4): `Content-Type:
/// application/json` and a `Content-Length` (411 without one) of at most
/// `TRANSFER_REQUEST_MAX` (413 past it); a body of another type, one that
/// does not arrive whole within its transfer time, or one that does not
/// parse is 400. The `Err` is the refusal, answered and logged.
async fn json_body<T: DeserializeOwned>(op: &'static str, started: Instant, req: Request) -> Result<T, Box<Response>> {
    let len = match crate::shim::code::content_length(&req, TRANSFER_REQUEST_MAX as u64) {
        Ok(len) => len,
        Err(stop) => {
            crate::shim::peer::drain(req).await;
            return Err(Box::new(stop.respond(op, started)));
        }
    };
    let json = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).and_then(|v| v.split(';').next()).is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err(Box::new(crate::shim::code::refuse_after_body(op, started, req, len, &WsRefusal::new(refusal::BAD_REQUEST, "the body is not application/json")).await));
    }
    let body = match tokio::time::timeout(asagent::transfer(len), axum::body::to_bytes(req.into_body(), TRANSFER_REQUEST_MAX)).await {
        Ok(Ok(body)) if body.len() as u64 == len => body,
        _ => return Err(Box::new(asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the body did not arrive whole ({len} bytes)"))))),
    };
    serde_json::from_slice(&body).map_err(|e| Box::new(asagent::refuse(op, started, &WsRefusal::new(refusal::BAD_REQUEST, &format!("the body does not parse: {}", parse_error(&e))))))
}

/// A body's parse error as a refusal names it: where, and what, unless the
/// text quotes a value (a value may be a presigned URL).
fn parse_error(e: &serde_json::Error) -> String {
    let what = e.to_string();
    if what.contains('"') {
        format!("invalid at line {} column {}", e.line(), e.column())
    } else {
        what
    }
}

/// A request's `check` refusal, named after the request (its rel's message is already whole).
fn checked(what: &str, e: String) -> WsRefusal {
    let message = if e.starts_with("the ") { e } else { format!("the {what} {e}") };
    WsRefusal::new(refusal::BAD_REQUEST, &message)
}

/// A refusal a run ends with, boxed (as `code::query`'s: a `WsRefusal` is large).
type Refused = Box<WsRefusal>;

/// 500 `transfer_failed` (§1.6): the transfer to or from S3 did not happen.
fn transfer_failed(message: &str) -> Refused {
    Box::new(WsRefusal::new(refusal::TRANSFER_FAILED, message))
}

/// The whole seconds left before `deadline`, at least 1 (curl's `max-time`).
fn seconds_left(deadline: tokio::time::Instant) -> u64 {
    deadline.saturating_duration_since(tokio::time::Instant::now()).as_secs().max(1)
}

/// The run's budget left before `deadline`.
fn left(deadline: tokio::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// 504 `timeout`: `op` did not finish within its budget.
fn timed_out(op: &str) -> Refused {
    Box::new(AgentProcError::Timeout.refusal(op))
}

/// Why a helper gave no head (or failed after it), as its route refuses.
fn failed_as(op: &str) -> impl Fn(AgentProcError) -> Refused + '_ {
    move |e| Box::new(e.refusal(op))
}

/// `POST /transcript/push` (`TranscriptPush`): a 200 `TranscriptPushReply` whenever curl reported an HTTP status.
pub async fn push(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("transcript-push", Instant::now());
    let p: TranscriptPush = match json_body(op, started, req).await {
        Ok(p) => p,
        Err(res) => return *res,
    };
    if p.len > PUSH_MAX {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::TOO_LARGE, &format!("the push is {} bytes (at most {PUSH_MAX})", p.len)).with_size(p.len));
    }
    if let Err(e) = p.check() {
        return asagent::refuse(op, started, &checked("push", e));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let wait = state.workspace.busy_wait();
    let _slot = match state.transfers.slot(&p.rel, tokio::time::Instant::now() + wait).await {
        Ok(slot) => slot,
        Err(held) => return asagent::refuse(op, started, &asagent::busy(op, held, wait)),
    };
    let deadline = tokio::time::Instant::now() + budget::TRANSCRIPT_PUSH + asagent::transfer(p.len);
    let checksum = sha256_b64(&p.sha256);
    let kind = Kind::Put { len: p.len, checksum: checksum.as_deref(), owner: &p.owner };
    let run = PushRun { op, rel: &p.rel, from: p.from, len: p.len, deadline, during_stop: false };
    match push_range(&state, run, |max_time| curl_config(&p.url, p.proxy.as_deref(), max_time, &kind)).await {
        Ok(reply) => {
            errln!("ai-env: transcript_push rel={} from={} len={} status={} ms={}", p.rel, p.from, reply.len, reply.s3_status, started.elapsed().as_millis());
            asagent::log(op, 200, None, started);
            asagent::answered(200, &reply)
        }
        Err(r) => asagent::refuse(op, started, &r),
    }
}

/// One push's bytes: `len` bytes of `rel` from `from`, by `deadline`, for
/// the route `op` (a tail's at a hook while the shim stops: `during_stop`).
struct PushRun<'a> {
    op: &'static str,
    rel: &'a str,
    from: u64,
    len: u64,
    deadline: tokio::time::Instant,
    during_stop: bool,
}

/// A push's bytes ([`PushRun`]): the helper's `transcript-read` (as the
/// agent) piped into curl (as `ai-env-net`, its configuration
/// `config(max-time)` on fd 3), hashed and counted on the way, all by the
/// deadline. S3's answer (`len` and `sha256` what curl took: short of `len`
/// when it stopped reading, S3 having answered); else the refusal: the
/// helper's own, 500 `transfer_failed` (curl reported no HTTP status, or the
/// helper's bytes stopped short), 504 past the deadline.
async fn push_range(state: &ShimState, run: PushRun<'_>, config: impl Fn(u64) -> String) -> Result<TranscriptPushReply, Refused> {
    let PushRun { op, rel, from, len, deadline, during_stop } = run;
    let read = "transcript-read";
    let args = vec![flag("projects", crate::shim::health::projects(state)), flag("rel", rel), flag("from", from.to_string()), flag("len", len.to_string())];
    let cmd = AgentCmd { op: read, args, budget: left(deadline), stdin: false, during_stop };
    let mut proc = AgentProc::start(state, cmd).await.map_err(failed_as(read))?;
    let head = match proc.head::<TranscriptReadReply>().await {
        Ok(h) => h,
        Err(e) => {
            proc.stop().await;
            return Err(failed_as(read)(e));
        }
    };
    match head.outcome() {
        Some(Ok((_, Some(n)))) if n == len => {}
        Some(Err(r)) => {
            finish_quietly(proc, read).await;
            return Err(Box::new(r));
        }
        _ => {
            proc.stop().await;
            return Err(failed_as(read)(AgentProcError::BadHead(format!("no payload of {len} bytes announced"))));
        }
    }
    let payload = proc.into_body(Vec::new(), len, None);
    let mut curl = Curl::start(state, op, &config(seconds_left(deadline)))?;
    let run = async {
        let (mut stdin, mut stdout) = (curl.stdin.take(), curl.stdout.take());
        let feed = async {
            let mut h = Sha256::new();
            let (mut sent, mut cut) = (0u64, None);
            let mut stream = payload.into_data_stream();
            while let Some(chunk) = stream.next().await {
                let bytes = match chunk {
                    Ok(b) => b,
                    Err(e) => {
                        cut = Some(e.to_string());
                        break;
                    }
                };
                let Some(w) = stdin.as_mut() else { break };
                // curl stopped reading: S3 answered already (its status says what), the rest is not sent.
                if w.write_all(&bytes).await.is_err() {
                    break;
                }
                h.update(&bytes);
                sent += bytes.len() as u64;
            }
            drop(stdin);
            (hex::encode(h.finalize()), sent, cut)
        };
        let ((sha256, sent, cut), body) = tokio::join!(feed, read_capped(stdout.as_mut(), CURL_STDOUT_MAX));
        if let Some(why) = cut {
            curl.kill().await;
            return Err(transfer_failed(&format!("the transcript's bytes stopped after {sent} of {len}: {why}")));
        }
        let (code, said) = curl.finish().await;
        let Some(status) = said.status.as_deref().and_then(parse_status).filter(|s| s.http != 0) else { return Err(transfer_failed(&no_status(code, &said))) };
        let s3_code = (!(200..300).contains(&status.http)).then(|| s3_code(&body)).flatten();
        let version_id = (status.http == 200).then_some(status.version).flatten();
        Ok(TranscriptPushReply { s3_status: status.http, s3_code, version_id, len: sent, sha256 })
    };
    tokio::time::timeout_at(deadline, run).await.unwrap_or_else(|_| Err(timed_out(op)))
}

/// `POST /transcript/pull` (`TranscriptPull`): 201 written, 200 not, with the parts' reports.
pub async fn pull(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("transcript-pull", Instant::now());
    let p: TranscriptPull = match json_body(op, started, req).await {
        Ok(p) => p,
        Err(res) => return *res,
    };
    let total = match p.parts.iter().try_fold(0u64, |sum, part| sum.checked_add(part.len)) {
        Some(total) if total <= PULL_MAX => total,
        sum => {
            let r = WsRefusal::new(refusal::TOO_LARGE, &format!("the parts sum to more than {PULL_MAX} bytes"));
            let r = match sum {
                Some(s) => r.with_size(s),
                None => r,
            };
            return asagent::refuse(op, started, &r);
        }
    };
    if let Err(e) = p.check() {
        return asagent::refuse(op, started, &checked("pull", e));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    // A task of its own: a client gone meanwhile never ends the helper before it removed its temp file.
    asagent::detached(op, started, async move {
        let wait = state.workspace.busy_wait();
        let _slot = match state.transfers.slot(&p.rel, tokio::time::Instant::now() + wait).await {
            Ok(slot) => slot,
            Err(held) => return asagent::refuse(op, started, &asagent::busy(op, held, wait)),
        };
        let deadline = tokio::time::Instant::now() + budget::TRANSCRIPT_PULL + asagent::transfer(total);
        match pull_parts(&state, &p, total, deadline).await {
            Ok(reply) => {
                let status = if reply.written { 201 } else { 200 };
                errln!("ai-env: transcript_pull rel={} parts={}/{} written={} size={} ms={}", p.rel, reply.parts.len(), p.parts.len(), reply.written, reply.size, started.elapsed().as_millis());
                asagent::log(op, status, None, started);
                asagent::answered(status, &reply)
            }
            Err(r) => asagent::refuse(op, started, &r),
        }
    })
    .await
}

/// How a pull's streaming ended.
enum Streamed {
    /// The helper answered before its `commit`: a refusal (or a bad head).
    Early(Box<Result<HelperHead<TranscriptWriteReply>, AgentProcError>>),
    /// Every part tried: their reports and the sha256 of every byte sent; or why it stopped.
    Done(Result<(Vec<PullPartReport>, String), PullStop>),
    /// The deadline passed.
    Timeout,
}

/// Why a pull's streaming stopped short of its reports.
enum PullStop {
    /// curl reported no HTTP status for a part: why.
    NoStatus(String),
    /// The helper stopped reading (it refused, or failed).
    Helper,
}

/// The parts of `p` (`total` bytes) into the helper's `transcript-write` by
/// `deadline`: each part's curl GET (as `ai-env-net`) streamed into the
/// helper's stdin, its status, length and sha256 checked as it ends; the
/// first bad part ends the pull. Only when every part checked (and the
/// whole file's sha256, when the Mac knows it) does the `commit` line go:
/// written. Else the helper's refusal (`transfer_failed` with the old copy's
/// size) means nothing was renamed: not written.
async fn pull_parts(state: &ShimState, p: &TranscriptPull, total: u64, deadline: tokio::time::Instant) -> Result<TranscriptPullReply, Refused> {
    let write = "transcript-write";
    let mut args = vec![flag("projects", crate::shim::health::projects(state)), flag("rel", &p.rel), flag("len", total.to_string())];
    if let Some(sum) = &p.sha256 {
        args.push(flag("sha256", sum));
    }
    let cmd = AgentCmd { op: write, args, budget: left(deadline), stdin: true, during_stop: false };
    let mut proc = AgentProc::start(state, cmd).await.map_err(failed_as(write))?;
    let Some(mut stdin) = proc.take_stdin() else {
        proc.stop().await;
        return Err(failed_as(write)(AgentProcError::Spawn("the helper has no stdin".into())));
    };
    let streamed = tokio::select! {
        biased;
        head = proc.head::<TranscriptWriteReply>() => Streamed::Early(Box::new(head)),
        done = tokio::time::timeout_at(deadline, stream_parts(state, p, &mut stdin, deadline)) => done.map_or(Streamed::Timeout, Streamed::Done),
    };
    let (reports, whole) = match streamed {
        Streamed::Early(head) => {
            drop(stdin);
            return Err(match head.map(HelperHead::outcome) {
                Ok(Some(Err(r))) => {
                    finish_quietly(proc, write).await;
                    Box::new(r)
                }
                Ok(_) => {
                    proc.stop().await;
                    failed_as(write)(AgentProcError::BadHead("a reply before the commit line".into()))
                }
                Err(e) => {
                    proc.stop().await;
                    failed_as(write)(e)
                }
            });
        }
        Streamed::Timeout => {
            // Its stdin closed without the commit line: it removes its temp file itself.
            drop(stdin);
            proc.stop_after(EOF_GRACE).await;
            return Err(timed_out("transcript-pull"));
        }
        Streamed::Done(Err(PullStop::NoStatus(why))) => {
            drop(stdin);
            let _ = written_head(proc, write).await;
            return Err(transfer_failed(&why));
        }
        Streamed::Done(Err(PullStop::Helper)) => {
            drop(stdin);
            return Err(match written_head(proc, write).await {
                Ok(Err(r)) | Err(r) => r,
                Ok(Ok(_)) => failed_as(write)(AgentProcError::BadHead("a reply before the commit line".into())),
            });
        }
        Streamed::Done(Ok(done)) => done,
    };
    let all_ok = reports.len() == p.parts.len() && reports.iter().all(|r| r.ok) && p.sha256.as_ref().is_none_or(|s| *s == whole);
    if all_ok && stdin.write_all(format!("{}\n", crate::shim::wshelper::COMMIT).as_bytes()).await.is_ok() {
        drop(stdin);
        return match written_head(proc, write).await? {
            Ok(w) => Ok(TranscriptPullReply { written: true, size: w.size, sha256: Some(w.sha256), parts: reports }),
            Err(r) => Err(r),
        };
    }
    drop(stdin);
    match written_head(proc, write).await? {
        // Nothing renamed: the VM's copy, and its size, as they were.
        Err(r) if r.code == refusal::TRANSFER_FAILED && !all_ok => Ok(TranscriptPullReply { written: false, size: r.size.unwrap_or(0), sha256: None, parts: reports }),
        Err(r) => Err(r),
        Ok(_) => Err(failed_as(write)(AgentProcError::BadHead("a reply without the commit line".into()))),
    }
}

/// The helper's head once its stdin is closed, then its run finished: its
/// reply or its refusal (`Ok`), or why it gave neither (`Err`).
async fn written_head(mut proc: AgentProc, op: &'static str) -> Result<Result<TranscriptWriteReply, Refused>, Refused> {
    let head = match proc.head::<TranscriptWriteReply>().await {
        Ok(h) => h,
        Err(e) => {
            proc.stop().await;
            return Err(failed_as(op)(e));
        }
    };
    match head.outcome() {
        Some(Ok((reply, _))) => {
            proc.finish().await.map_err(failed_as(op))?;
            Ok(Ok(reply))
        }
        Some(Err(r)) => {
            finish_quietly(proc, op).await;
            Ok(Err(Box::new(r)))
        }
        None => {
            proc.stop().await;
            Err(failed_as(op)(AgentProcError::BadHead("neither a reply nor a refusal".into())))
        }
    }
}

/// Finish a run whose refusal is already in hand (a failure after it is logged, never answered).
async fn finish_quietly(proc: AgentProc, op: &str) {
    if let Err(e) = proc.finish().await {
        errln!("ai-env: transcript {op} helper ended badly after its refusal: {}", e.refusal(op).message);
    }
}

/// Each part in order: curl's GET (as `ai-env-net`) into `stdin`, its
/// status, length and sha256 checked as it ends (a part longer than its
/// `len` is cut there, never sent past it: its report's `len` counts the
/// chunk that passed it); the first bad part ends the pull, its report last.
/// The reports, and the sha256 of every byte sent.
async fn stream_parts(state: &ShimState, p: &TranscriptPull, stdin: &mut ChildStdin, deadline: tokio::time::Instant) -> Result<(Vec<PullPartReport>, String), PullStop> {
    let mut whole = Sha256::new();
    let mut reports = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    for part in &p.parts {
        let config = curl_config(&part.url, p.proxy.as_deref(), seconds_left(deadline), &Kind::Get { owner: &p.owner });
        let mut curl = Curl::start(state, "transcript-pull", &config).map_err(|r| PullStop::NoStatus(r.message.clone()))?;
        let mut h = Sha256::new();
        let (mut got, mut over) = (0u64, false);
        if let Some(out) = curl.stdout.as_mut() {
            loop {
                let k = match out.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(k) => k,
                };
                if got + k as u64 > part.len {
                    got += k as u64;
                    over = true;
                    break;
                }
                if stdin.write_all(&buf[..k]).await.is_err() {
                    return Err(PullStop::Helper);
                }
                h.update(&buf[..k]);
                whole.update(&buf[..k]);
                got += k as u64;
            }
        }
        // A part longer than its len: its stdout closed here, curl ends on its next write, its status line still said.
        let (code, said) = curl.finish().await;
        let Some(status) = said.status.as_deref().and_then(parse_status).filter(|s| s.http != 0) else { return Err(PullStop::NoStatus(no_status(code, &said))) };
        let sha256 = hex::encode(h.finalize());
        let ok = status.http == 200 && !over && got == part.len && part.sha256.as_ref().is_none_or(|s| *s == sha256);
        reports.push(PullPartReport { s3_status: status.http, len: got, sha256, ok });
        if !ok {
            break;
        }
    }
    Ok((reports, hex::encode(whole.finalize())))
}

/// `GET /transcript/view?rel=&n=` (`ViewQuery`): a `wire::view::TranscriptViewReply`.
pub async fn view(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("transcript-view", Instant::now());
    let q: ViewQuery = match crate::shim::code::query(&req) {
        Ok(q) => q,
        Err(r) => return asagent::refuse(op, started, &r),
    };
    if let Err(e) = q.check() {
        return asagent::refuse(op, started, &checked("view query", e));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let args = vec![flag("projects", crate::shim::health::projects(&state)), flag("rel", &q.rel), flag("n", q.n.to_string())];
    let cmd = AgentCmd { op, args, budget: budget::TRANSCRIPT_VIEW, stdin: false, during_stop: false };
    match run_payload::<TranscriptViewReply>(&state, cmd).await {
        // The helper runs as the agent: only the shape the Mac takes goes out.
        Ok(reply) => match reply.check(q.n) {
            Ok(()) => {
                asagent::log(op, 200, None, started);
                asagent::answered(200, &reply)
            }
            Err(e) => asagent::refuse(op, started, &AgentProcError::BadHead(format!("the view {e}")).refusal(op)),
        },
        Err(r) => asagent::refuse(op, started, &r),
    }
}

/// An op that answers in the payload form (§3.2: the view, a subtree stat):
/// its head (a `JsonPayloadReply`, or a refusal), then exactly `len` bytes,
/// at most `JSON_PAYLOAD_MAX`, of the reply's JSON, whose sha256 the head
/// names. The reply, or the refusal: the helper's own, or 500 `git_failed`
/// for a `len` over the cap, a short payload, another sha256 or a reply that
/// does not parse, as for a bad head.
pub(crate) async fn run_payload<T: DeserializeOwned>(state: &ShimState, cmd: AgentCmd) -> Result<T, Box<WsRefusal>> {
    let op = cmd.op;
    let bad = |why: String| failed_as(op)(AgentProcError::BadHead(why));
    let mut proc = AgentProc::start(state, cmd).await.map_err(failed_as(op))?;
    let head = match proc.head::<JsonPayloadReply>().await {
        Ok(h) => h,
        Err(e) => {
            proc.stop().await;
            return Err(failed_as(op)(e));
        }
    };
    let (sums, len) = match head.outcome() {
        Some(Ok((sums, Some(len)))) if len <= JSON_PAYLOAD_MAX as u64 => (sums, len),
        Some(Err(r)) => {
            finish_quietly(proc, op).await;
            return Err(Box::new(r));
        }
        _ => {
            proc.stop().await;
            return Err(bad(format!("no payload of at most {JSON_PAYLOAD_MAX} bytes announced")));
        }
    };
    let bytes = axum::body::to_bytes(proc.into_body(Vec::new(), len, None), JSON_PAYLOAD_MAX).await.map_err(|e| bad(format!("the payload: {e}")))?;
    if bytes.len() as u64 != len || hex::encode(Sha256::digest(&bytes)) != sums.sha256 {
        return Err(bad(format!("a payload of {} bytes that is not the {len} announced", bytes.len())));
    }
    serde_json::from_slice(&bytes).map_err(|e| bad(format!("a payload that does not parse: {}", parse_error(&e))))
}

/// `POST /transcript/tail` (`TranscriptTail`): 204, the URL kept for its rel
/// (a session's main transcript: another rel is 400 `bad_request`) until it expires.
pub async fn tail(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = ("transcript-tail", Instant::now());
    let t: TranscriptTail = match json_body(op, started, req).await {
        Ok(t) => t,
        Err(res) => return *res,
    };
    if let Err(e) = t.check() {
        return asagent::refuse(op, started, &checked("tail", e));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    state.transfers.keep_tail(t, crate::wire::time::unix_now());
    asagent::log(op, 204, None, started);
    StatusCode::NO_CONTENT.into_response()
}

/// `/suspend` (after the WIP snapshot) and `/terminate` (after the spawns
/// stopped): each main transcript's kept tail pushed once, within
/// `budget::TRANSCRIPT_TAIL`, when the file grew past its `from`; logged as
/// `ai-env: transcript_tail <why> …`, never the URL. A tail whose file did
/// not grow stays for the next hook; an expired one is dropped. A subtree
/// file has no tail: one changed since the last sync is not pushed here.
pub async fn tail_push(state: &ShimState, why: &str) {
    if !(SERVED && state.serves_workspace()) {
        return;
    }
    let tails = state.transfers.tails_due(crate::wire::time::unix_now());
    if tails.is_empty() {
        return;
    }
    let deadline = tokio::time::Instant::now() + budget::TRANSCRIPT_TAIL;
    futures_util::future::join_all(tails.iter().map(|t| tail_one(state, why, t, deadline))).await;
}

/// One kept tail at a hook (§1.4, X8): when the file grew past `from`,
/// `[from, size)` PUT once to its tail key (no checksum: its bytes were
/// unknown when it was signed), by `deadline`.
async fn tail_one(state: &ShimState, why: &str, tail: &TranscriptTail, deadline: tokio::time::Instant) {
    let op = "transcript-tail";
    let run = async {
        let _slot = state.transfers.slot(&tail.rel, deadline).await.map_err(|held| format!("skipped: {held}"))?;
        let Some(size) = tail_size(state, tail, deadline).await?.filter(|size| *size > tail.from) else { return Ok(None) };
        state.transfers.take_tail(tail);
        let len = (size - tail.from).min(PUSH_MAX);
        let kind = Kind::Put { len, checksum: None, owner: &tail.owner };
        let push = PushRun { op, rel: &tail.rel, from: tail.from, len, deadline, during_stop: true };
        let reply = push_range(state, push, |max_time| curl_config(&tail.url, tail.proxy.as_deref(), max_time, &kind)).await.map_err(|r| format!("failed: {} ({})", r.code, r.message))?;
        Ok::<_, String>(Some((len, reply.s3_status)))
    };
    let (rel, from) = (&tail.rel, tail.from);
    match tokio::time::timeout_at(deadline, run).await {
        Ok(Ok(Some((len, status)))) => errln!("ai-env: transcript_tail {why} rel={rel} from={from} len={len} status={status}"),
        Ok(Ok(None)) => errln!("ai-env: transcript_tail {why} rel={rel} from={from} skipped: nothing past from"),
        Ok(Err(what)) => errln!("ai-env: transcript_tail {why} rel={rel} from={from} {what}"),
        Err(_) => errln!("ai-env: transcript_tail {why} rel={rel} from={from} failed: not within {} s", budget::TRANSCRIPT_TAIL.as_secs()),
    }
}

/// The tail's file's size now (`None`: absent), by the helper's extended stat (`--from`: its delta alone is hashed).
async fn tail_size(state: &ShimState, tail: &TranscriptTail, deadline: tokio::time::Instant) -> Result<Option<u64>, String> {
    let stat = "transcript-stat";
    let args = vec![flag("projects", crate::shim::health::projects(state)), flag("rel", &tail.rel), flag("from", tail.from.to_string())];
    let cmd = AgentCmd { op: stat, args, budget: left(deadline), stdin: false, during_stop: true };
    match asagent::run_op::<TranscriptStat>(state, cmd, None).await.map(HelperHead::outcome) {
        Ok(Some(Ok((s, _)))) => Ok(s.present.then_some(s.size)),
        Ok(Some(Err(r))) => Err(format!("skipped: {} ({})", r.code, r.message)),
        Ok(None) => Err("failed: the stat answered neither a reply nor a refusal".into()),
        Err(e) => Err(format!("failed: {}", e.refusal(stat).message)),
    }
}

// ---- curl ------------------------------------------------------------------------------------

/// What a curl run does (S9 §3.4).
enum Kind<'a> {
    /// A PUT of `len` bytes from stdin: a push (its checksum) or a tail (none).
    Put { len: u64, checksum: Option<&'a str>, owner: &'a str },
    /// A pull part's GET.
    Get { owner: &'a str },
}

/// curl's configuration (S9 §3.4, pinned line by line), for its fd 3 and
/// nowhere else: the URL (the VM's one read of it), the common lines
/// (`max_time` the route's budget left, whole seconds; `proto` `=http` for a
/// lab URL), the proxy when the request names one, then the request's own.
fn curl_config(url: &PresignedUrl, proxy: Option<&str>, max_time: u64, kind: &Kind<'_>) -> String {
    let proto = if url.is_lab() { "=http" } else { "=https" };
    let mut lines = vec![
        format!("url = \"{}\"", url.expose()),
        "silent".to_string(),
        "show-error".to_string(),
        format!("proto = \"{proto}\""),
        format!("connect-timeout = {CONNECT_TIMEOUT_S}"),
        format!("max-time = {max_time}"),
        WRITE_OUT.to_string(),
    ];
    if let Some(p) = proxy {
        lines.push(format!("proxy = \"{p}\""));
    }
    let header = |h: &str| format!("header = \"{h}\"");
    match kind {
        Kind::Put { len, checksum, owner } => {
            lines.extend(["request = \"PUT\"".to_string(), "upload-file = \"-\"".to_string(), header(&format!("Content-Length: {len}")), header("Transfer-Encoding:"), header("Expect:")]);
            if let Some(sum) = checksum {
                lines.push(header(&format!("x-amz-checksum-sha256: {sum}")));
            }
            lines.extend([header("If-None-Match: *"), header(&format!("x-amz-expected-bucket-owner: {owner}")), "output = \"-\"".to_string()]);
        }
        Kind::Get { owner } => lines.extend(["request = \"GET\"".to_string(), header(&format!("x-amz-expected-bucket-owner: {owner}")), "fail".to_string(), "output = \"-\"".to_string()]),
    }
    lines.join("\n") + "\n"
}

/// What curl said on its stderr: its last status line (after `ai-env-curl `), its last other line (scrubbed).
#[derive(Debug, Default)]
struct CurlSaid {
    status: Option<String>,
    last: Option<String>,
}

/// One curl run: its pipes, its stderr read by a task of its own (the
/// status line kept, every other line logged scrubbed). Killed when dropped.
struct Curl {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    said: Option<JoinHandle<CurlSaid>>,
}

impl Curl {
    /// curl as `ai-env-net` when the shim is root (as the shim's own uid otherwise: the native tests), `config` on its fd 3.
    fn start(state: &ShimState, op: &'static str, config: &str) -> Result<Curl, Refused> {
        let ids = nix::unistd::geteuid().is_root().then_some((state.opts.net_uid, state.opts.net_gid));
        let mut child = crate::shim::childproc::spawn_curl(&state.opts.curl, ids, config.as_bytes()).map_err(|e| transfer_failed(&format!("curl did not start: {e}")))?;
        let said = child.stderr.take().map(|err| tokio::spawn(read_stderr(err, op)));
        Ok(Curl { stdin: child.stdin.take(), stdout: child.stdout.take(), child, said })
    }

    /// End it now.
    async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }

    /// Its stdin closed, its stdout dropped, its exit code (`None`: a signal) and what its stderr said.
    async fn finish(mut self) -> (Option<i32>, CurlSaid) {
        drop(self.stdin.take());
        drop(self.stdout.take());
        let code = self.child.wait().await.ok().and_then(|s| s.code());
        let said = match self.said.take() {
            Some(task) => task.await.unwrap_or_default(),
            None => CurlSaid::default(),
        };
        (code, said)
    }
}

/// curl's stderr to its end: the last status line kept, every other line logged scrubbed and the last one kept.
async fn read_stderr(err: ChildStderr, op: &'static str) -> CurlSaid {
    let mut said = CurlSaid::default();
    let mut reader = tokio::io::BufReader::new(err);
    let mut line = Vec::new();
    loop {
        line.clear();
        match (&mut reader).take(CURL_LINE_MAX as u64).read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end();
        if text.is_empty() {
            continue;
        }
        if let Some(rest) = text.strip_prefix(STATUS_WORD) {
            said.status = Some(rest.to_string());
        } else {
            let shown: String = crate::wire::redact::scrub(text).chars().take(CURL_SHOWN_MAX).collect();
            errln!("ai-env: transcript {op} curl: {shown}");
            said.last = Some(shown);
        }
    }
    said
}

/// At most `max` bytes of `out` kept, the rest read away (curl never waits on a full pipe).
async fn read_capped(out: Option<&mut ChildStdout>, max: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let Some(out) = out else { return kept };
    let mut buf = vec![0u8; 8192];
    loop {
        match out.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                let room = max.saturating_sub(kept.len()).min(k);
                kept.extend_from_slice(&buf[..room]);
            }
        }
    }
    kept
}

/// The fields of curl's status line that the shim reads.
struct CurlStatus {
    /// `%{http_code}`: 0 when no HTTP exchange happened.
    http: u16,
    /// `x-amz-version-id`, when it is one (`[A-Za-z0-9._+/=-]`, at most 1024 bytes).
    version: Option<String>,
}

/// `status=<code> version=<id> checksum=<b64> etag=<etag>`.
fn parse_status(fields: &str) -> Option<CurlStatus> {
    let (mut http, mut version) = (None, None);
    for field in fields.split(' ') {
        if let Some(v) = field.strip_prefix("status=") {
            http = v.parse::<u16>().ok();
        } else if let Some(v) = field.strip_prefix("version=") {
            version = Some(v.to_string()).filter(|v| !v.is_empty() && v.len() <= 1024 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+/=-".contains(&b)));
        }
    }
    Some(CurlStatus { http: http?, version })
}

/// S3's `<Code>` in an error document: 1 to 64 characters of `[A-Za-z0-9]`.
fn s3_code(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let code = &text[start..start + text[start..].find("</Code>")?];
    ((1..=64).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| code.to_string())
}

/// Why there is no HTTP status: curl's exit and its last other stderr line (scrubbed, without its `curl: (N) `).
fn no_status(code: Option<i32>, said: &CurlSaid) -> String {
    let line = said.last.as_deref().map_or("nothing on stderr", |l| l.strip_prefix("curl: ").map_or(l, |rest| rest.split_once(") ").filter(|(n, _)| n.starts_with('(')).map_or(rest, |(_, msg)| msg)));
    match code {
        Some(c) => format!("curl exited {c} before an HTTP status ({line})"),
        None => format!("curl was ended by a signal before an HTTP status ({line})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A presigned URL of the store at `key` (its signature made at run time).
    fn url(key: &str, signed: &str, lab: bool) -> PresignedUrl {
        let sig = hex::encode(Sha256::digest(key.as_bytes()));
        let base = if lab { "http://127.0.0.1:9000/ai-env-transcripts-123456789012".to_string() } else { "https://ai-env-transcripts-123456789012.s3.eu-central-1.amazonaws.com".to_string() };
        let query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={sig}", signed.replace(';', "%3B"));
        PresignedUrl::new(format!("{base}/{key}?{query}")).unwrap()
    }

    /// The configuration of each request kind, line by line (S9 §3.4): a
    /// push with its checksum and the proxy, a tail without either, a part's
    /// GET; a lab URL speaks plain http.
    #[test]
    fn the_curl_config_is_the_contracts() {
        use crate::wire::s3::{SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT};
        let key = "v1/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b/vm/g1/base";
        let put = url(key, SIGNED_HEADERS_PUT, false);
        let sum = sha256_b64(&"ab".repeat(32)).unwrap();
        let text = curl_config(&put, Some("http://10.42.0.10:3128"), 61, &Kind::Put { len: 7, checksum: Some(&sum), owner: "123456789012" });
        let want = format!(
            "url = \"{}\"\nsilent\nshow-error\nproto = \"=https\"\nconnect-timeout = 20\nmax-time = 61\n{WRITE_OUT}\nproxy = \"http://10.42.0.10:3128\"\nrequest = \"PUT\"\nupload-file = \"-\"\nheader = \"Content-Length: 7\"\nheader = \"Transfer-Encoding:\"\nheader = \"Expect:\"\nheader = \"x-amz-checksum-sha256: {sum}\"\nheader = \"If-None-Match: *\"\nheader = \"x-amz-expected-bucket-owner: 123456789012\"\noutput = \"-\"\n",
            put.expose()
        );
        assert_eq!(text, want);
        assert!(WRITE_OUT.ends_with(r#"etag=%header{etag}\n""#), "the config's \\n, which curl reads as a newline");
        let tail = curl_config(&put, None, 8, &Kind::Put { len: 7, checksum: None, owner: "123456789012" });
        assert!(!tail.contains("header = \"x-amz-checksum-sha256") && !tail.contains("proxy") && tail.contains("max-time = 8\n"), "{tail}");
        let get = url(key, SIGNED_HEADERS_GET, true);
        let text = curl_config(&get, None, 9, &Kind::Get { owner: "123456789012" });
        assert_eq!(text, format!("url = \"{}\"\nsilent\nshow-error\nproto = \"=http\"\nconnect-timeout = 20\nmax-time = 9\n{WRITE_OUT}\nrequest = \"GET\"\nheader = \"x-amz-expected-bucket-owner: 123456789012\"\nfail\noutput = \"-\"\n", get.expose()));
    }

    /// curl's status line, S3's `<Code>` and the words of a run without a status.
    #[test]
    fn curls_answer_is_read_from_its_status_line() {
        let s = parse_status("status=200 version=3/L4kqtJlcp+X.x_y-z= checksum=abc= etag=\"e\"").unwrap();
        assert_eq!((s.http, s.version.as_deref()), (200, Some("3/L4kqtJlcp+X.x_y-z=")));
        let s = parse_status("status=000 version= checksum= etag=").unwrap();
        assert_eq!((s.http, s.version), (0, None));
        assert!(parse_status("version=x").is_none());
        assert_eq!(parse_status("status=412 version=a\"b").unwrap().version, None, "a version that is none of S3's characters is dropped");
        assert_eq!(s3_code(b"<?xml version=\"1.0\"?><Error><Code>PreconditionFailed</Code><Message>x</Message></Error>").as_deref(), Some("PreconditionFailed"));
        for bad in [&b"<Error><Code>Bad Code</Code></Error>"[..], b"<Error><Code></Code></Error>", b"no error", b"<Code>unterminated"] {
            assert_eq!(s3_code(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        let said = CurlSaid { status: None, last: Some("curl: (7) Failed to connect to 10.42.0.10 port 3128".into()) };
        assert_eq!(no_status(Some(7), &said), "curl exited 7 before an HTTP status (Failed to connect to 10.42.0.10 port 3128)");
        assert_eq!(no_status(None, &CurlSaid::default()), "curl was ended by a signal before an HTTP status (nothing on stderr)");
    }

    /// One run per rel, `TRANSFERS_MAX` at once: a second run of a rel
    /// waits, then is refused naming what was held; the slots free with
    /// their holders; a tail replaces its rel's, is dropped once expired,
    /// and is taken only while it is still the one kept.
    #[tokio::test]
    async fn runs_take_their_rels_turn_and_a_slot() {
        use crate::wire::s3::SIGNED_HEADERS_TAIL;
        use std::time::Duration;
        let t = Transfers::default();
        let soon = || tokio::time::Instant::now() + Duration::from_millis(50);
        let first = t.slot("a", soon()).await.unwrap();
        assert_eq!(t.slot("a", soon()).await.err(), Some("another transfer of this transcript is under way"));
        let more: Vec<Slot> = futures_util::future::join_all(["b", "c", "d"].map(|r| t.slot(r, soon()))).await.into_iter().map(Result::unwrap).collect();
        assert_eq!(t.slot("e", soon()).await.err(), Some("every transfer slot is taken"));
        drop(first);
        assert!(t.slot("a", soon()).await.is_ok(), "freed with its holder");
        drop(more);
        let z = t.slot("z", soon()).await.unwrap();
        assert_eq!(t.rels.lock().unwrap().keys().collect::<Vec<_>>(), ["z"], "the turns nobody holds or waits for go");
        drop(z);
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let rel = format!("-Users-mike-ws/{sid}.jsonl");
        let tail = |from: u64, expires_at: u64| TranscriptTail { rel: rel.clone(), from, url: url(&format!("v1/{sid}/vm/g1/t/{from:016x}"), SIGNED_HEADERS_TAIL, false), owner: "123456789012".into(), proxy: None, expires_at };
        t.keep_tail(tail(10, 100), 50);
        t.keep_tail(tail(20, 100), 50);
        assert_eq!(t.tails_due(60).iter().map(|t| t.from).collect::<Vec<_>>(), [20], "the newest replaces");
        t.take_tail(&tail(10, 100));
        assert_eq!(t.tails_due(60).len(), 1, "a tail replaced meanwhile is not taken");
        t.take_tail(&tail(20, 100));
        assert!(t.tails_due(60).is_empty());
        t.keep_tail(tail(30, 100), 50);
        assert!(t.tails_due(100).is_empty(), "expired at its expires_at");
    }
}
