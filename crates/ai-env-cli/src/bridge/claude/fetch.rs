//! S11 (A.4, A3): V's fetch into a VM's claude cache: after a generation's
//! first output, ahead of a chat (`vm warm`, the prewarm), and in a
//! migration's phase A; the VM's answer judged and applied to the record
//! ([`super::Record::update`]) and audited (`claude_fetch`,
//! `claude_object_bad`). Only `vm warm` waits for one (`WARM_CLAUDE_WAIT`);
//! the others post `wait_s` 0 and poll in the background (LD-7). The fetch
//! takes no Touch ID: the caller's API object holds the runtime key
//! (presigning is local) and the endpoint tokens are minted with it.
use super::Record;
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo};
use crate::bridge::config::Paths;
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::pipeline::{AfterOutput, SessionPlan};
use crate::bridge::remote::{audit_event as event, CLAUDE_POLL_EVERY, CLAUDE_POLL_FOR, WARM_CLAUDE_WAIT};
use crate::bridge::s3::S3Sign;
use crate::bridge::vm::cmd::{audit_event, Ctx};
use crate::bridge::vm::registry::VmRow;
use crate::wire::frame::CAP_CLAUDE_STAGE_V1;
use crate::wire::workspace::{refusal, ClaudeRef, ClaudeSrc, ClaudeStage, ClaudeStageQuery, ClaudeStageReply, ClaudeStageState, APP_PORT, CLAUDE_WAIT_MAX_S};
use std::time::Duration;

/// Where a fetch was asked from (`claude_fetch`'s `why`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchWhy {
    AfterOutput,
    Warm,
    Prewarm,
    PhaseA,
}

impl FetchWhy {
    /// `after_output`, `warm`, `prewarm`, `phase_a`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            FetchWhy::AfterOutput => "after_output",
            FetchWhy::Warm => "warm",
            FetchWhy::Prewarm => "prewarm",
            FetchWhy::PhaseA => "phase_a",
        }
    }
}

/// V's fetch into `vm` (its row, its info), its result judged and audited: a presigned GET (`CLAUDE_EXPIRY`),
/// `POST /claude/stage` with `wait_s`, then `GET /claude/stage` every `CLAUDE_POLL_EVERY` until `poll_for` from the
/// fetch's start ends, the POST's wait counted in it (both scaled by the lab's backoff knob). A VM whose recorded caps lack `claude_stage_v1` is `NoCap`, nothing sent.
/// The row names `session()` as it reads once the fetch ended (a new chat's id comes with its init, which may follow
/// the fetch's start) and `gen`.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_into<A: MicrovmApi + S3Sign + 'static>(ctx: &Ctx, api: &std::sync::Arc<A>, row: &VmRow, vm: &VmInfo, want: &ClaudeRef, size: u64, wait_s: u32, poll_for: std::time::Duration, why: FetchWhy, session: &dyn Fn() -> Option<String>, gen: Option<u32>) -> FetchOutcome {
    let t0 = std::time::Instant::now();
    let mut got_len = None;
    let outcome = if row_has_cap(row) {
        match fetch(ctx, api, row, vm, want, size, wait_s.min(CLAUDE_WAIT_MAX_S), poll_for, &mut got_len).await {
            Ok(o) => o,
            Err(e) => outcome_of_error(&e, got_len),
        }
    } else {
        FetchOutcome::NoCap
    };
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(vm = %vm.id, version = %want.version, outcome = outcome.word(), why = why.word(), ms, "claude fetch");
    let target = crate::bridge::s3::S3Target::resolve(&ctx.paths, &ctx.knobs);
    let key = want.key().render();
    let delete = move || async move {
        let target = target?;
        crate::bridge::s3::client::S3Client::new(&**api, &target)?.delete(&key).await
    };
    apply(&ctx.paths, &vm.id, want, &outcome, ms, why, session().as_deref(), gen, delete).await;
    outcome
}

/// Whether `row`'s recorded caps name `claude_stage_v1`.
fn row_has_cap(row: &VmRow) -> bool {
    row.caps.as_ref().is_some_and(|caps| caps.iter().any(|c| c == CAP_CLAUDE_STAGE_V1))
}

/// The lab's backoff knob over `d` (a second is that many ms), as a poll's steps are scaled.
fn scaled(ctx: &Ctx, d: Duration) -> Duration {
    crate::bridge::vm::run::Poll { step: d, budget: d, ramp: [Duration::ZERO; 3] }.scaled(ctx.knobs.backoff_ms).step
}

/// squid for curl in the VM, as `s3::TranscriptSync` gives it: none for the lab's loopback S3.
fn proxy_of(ctx: &Ctx, target: &crate::bridge::s3::S3Target) -> Option<String> {
    match target.endpoint {
        crate::bridge::s3::S3Endpoint::Lab(_) => None,
        crate::bridge::s3::S3Endpoint::Aws => {
            let state = crate::bridge::infra::read_infra_state(&ctx.paths).ok().flatten();
            let (ip, _) = crate::bridge::egress::effective_proxy_ip(ctx.cfg.aws.proxy_private_ip.as_deref(), state.as_ref());
            Some(crate::bridge::egress::proxy_url(ip, crate::bridge::egress::PROXY_PORT))
        }
    }
}

/// The POST and its polls, all within `poll_for` of its start (the POST's own wait counts in it); `got_len` takes a
/// refusal's size (a 422's: what came).
#[allow(clippy::too_many_arguments)]
async fn fetch<A: MicrovmApi + S3Sign + 'static>(ctx: &Ctx, api: &std::sync::Arc<A>, row: &VmRow, vm: &VmInfo, want: &ClaudeRef, size: u64, wait_s: u32, poll_for: Duration, got_len: &mut Option<u64>) -> Result<FetchOutcome, BridgeError> {
    use crate::bridge::s3::{presign, S3Method};
    let t0 = std::time::Instant::now();
    let until = tokio::time::Instant::now() + scaled(ctx, poll_for);
    let target = crate::bridge::s3::S3Target::resolve(&ctx.paths, &ctx.knobs)?;
    let url = api.presign(&presign::request(S3Method::Get, &target, Some(want.key().render()), Vec::new(), Vec::new(), crate::wire::s3::CLAUDE_EXPIRY)).await?;
    let req = ClaudeStage { version: want.version.clone(), sha256: want.sha256.clone(), size, url, owner: target.owner.clone(), proxy: proxy_of(ctx, &target), wait_s };
    req.check().map_err(|e| BridgeError::Config(format!("POST /claude/stage: the request {e}")))?;
    let agent = crate::bridge::remote::pipeline::target_of(row, vm)?;
    let (dp, tokens) = crate::bridge::remote::pipeline::data_plane(ctx, api, &vm.id, false)?;
    let refused_len = std::cell::Cell::new(None);
    let x = Exchange { api: &**api, tokens: &*tokens, vm_id: &vm.id, port: APP_PORT, cap: CAP_CLAUDE_STAGE_V1, route: "POST /claude/stage", deadline: None, idempotent: false };
    let posted = exchange(&x, |t| {
        let (req, dp, agent, refused_len) = (&req, &dp, &agent, &refused_len);
        async move {
            let reply = dp.claude_stage(agent, &t, req).await;
            if let Ok(r) = &reply {
                refused_len.set(r.refusal.as_ref().and_then(|r| r.size));
            }
            reply
        }
    })
    .await;
    *got_len = refused_len.get();
    let (reply, _) = posted?;
    let status = reply.status;
    let body = reply.body.ok_or_else(|| BridgeError::Protocol(format!("POST /claude/stage answered HTTP {status} without a reply")))?;
    match judge(status, &body, t0) {
        Some(outcome) => return Ok(outcome),
        None => tracing::info!(vm = %vm.id, version = %want.version, "the VM fetches claude: polling"),
    }
    let q = ClaudeStageQuery { sha256: want.sha256.clone() };
    let every = scaled(ctx, CLAUDE_POLL_EVERY);
    let g = Exchange { api: &**api, tokens: &*tokens, vm_id: &vm.id, port: APP_PORT, cap: CAP_CLAUDE_STAGE_V1, route: "GET /claude/stage", deadline: None, idempotent: true };
    loop {
        let now = tokio::time::Instant::now();
        if now >= until {
            return Ok(FetchOutcome::Fetching);
        }
        tokio::time::sleep(every.min(until - now)).await;
        let (reply, verdict) = exchange(&g, |t| {
            let (q, dp, agent) = (&q, &dp, &agent);
            async move { dp.claude_stage_state(agent, &t, q).await }
        })
        .await?;
        let state = match (verdict, reply.body) {
            (Verdict::Done, Some(state)) => state,
            _ => return Err(BridgeError::Protocol(format!("GET /claude/stage answered HTTP {} without a state", reply.status))),
        };
        if let Some(outcome) = judge(201, &state, t0) {
            if let FetchOutcome::ChecksumMismatch { got_len: len } = &outcome {
                *got_len = *len;
            }
            return Ok(outcome);
        }
    }
}

/// An answer's outcome (`status` 200 or 201 for a POST's; a poll's is judged as a 201's: what it reads `ready` was
/// fetched meanwhile); `None` while the VM is still fetching.
fn judge(status: u16, reply: &ClaudeStageReply, t0: std::time::Instant) -> Option<FetchOutcome> {
    let ms = || reply.ms.unwrap_or_else(|| u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX));
    match reply.state {
        ClaudeStageState::Fetching => None,
        ClaudeStageState::Ready if reply.src == Some(ClaudeSrc::Image) => Some(FetchOutcome::Image),
        ClaudeStageState::Ready if status == 200 => Some(FetchOutcome::Cached),
        ClaudeStageState::Ready => Some(FetchOutcome::Fetched { ms: ms() }),
        ClaudeStageState::Failed => Some(outcome_of_code(reply.why.as_deref().unwrap_or("failed"), reply.got_len)),
        // The shim lost the fetch (a restart): the record stays as it is.
        ClaudeStageState::Absent => Some(FetchOutcome::Failed("absent".into())),
    }
}

/// A refusal's code as an outcome (§4.3's table).
fn outcome_of_code(code: &str, got_len: Option<u64>) -> FetchOutcome {
    match code {
        refusal::NOT_STAGED => FetchOutcome::NotStaged,
        refusal::CHECKSUM_MISMATCH => FetchOutcome::ChecksumMismatch { got_len },
        refusal::VERSION_MISMATCH => FetchOutcome::VersionMismatch,
        refusal::DISK_FULL => FetchOutcome::DiskFull,
        other => FetchOutcome::Failed(other.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(40).collect()),
    }
}

/// An error's outcome: a refusal's code, a missing cap, else a word of its kind (never its text: no URL).
fn outcome_of_error(e: &BridgeError, got_len: Option<u64>) -> FetchOutcome {
    match e {
        BridgeError::WorkspaceFailed { code, .. } | BridgeError::WorkspaceRefused { code, .. } => outcome_of_code(code, got_len),
        BridgeError::NoCapability { .. } => FetchOutcome::NoCap,
        BridgeError::Http { status, .. } => FetchOutcome::Failed(format!("http_{status}")),
        BridgeError::Terminated(_) | BridgeError::VmNotFound(_) => FetchOutcome::Failed("vm_gone".into()),
        BridgeError::Config(_) => FetchOutcome::Failed("config".into()),
        BridgeError::Protocol(_) => FetchOutcome::Failed("protocol".into()),
        _ => FetchOutcome::Failed("transport".into()),
    }
}

/// `claude_fetch`'s `outcome` words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    Cached,
    Image,
    Fetched { ms: u64 },
    Fetching,
    NotStaged,
    ChecksumMismatch { got_len: Option<u64> },
    VersionMismatch,
    DiskFull,
    Failed(String),
    NoCap,
}

impl FetchOutcome {
    /// `cached`, `image`, `fetched`, `fetching`, `not_staged`, `checksum_mismatch`, `version_mismatch`,
    /// `disk_full`, `failed`, `no_cap`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            FetchOutcome::Cached => "cached",
            FetchOutcome::Image => "image",
            FetchOutcome::Fetched { .. } => "fetched",
            FetchOutcome::Fetching => "fetching",
            FetchOutcome::NotStaged => "not_staged",
            FetchOutcome::ChecksumMismatch { .. } => "checksum_mismatch",
            FetchOutcome::VersionMismatch => "version_mismatch",
            FetchOutcome::DiskFull => "disk_full",
            FetchOutcome::Failed(_) => "failed",
            FetchOutcome::NoCap => "no_cap",
        }
    }
}

/// The verdict applied (§4.3's table) and audited: `cached` and `image` change nothing and write no row; a 201
/// resets `bad_stages`; a 404 marks the object absent; a 422 `checksum_mismatch` deletes the object first
/// (`delete`), marks it stale, counts the report and (only while it was staged) the stage, and at 2 bad stages
/// fails the admission (`failed(stage)`), audited `claude_object_bad`; a 422 `version_mismatch` fails the
/// admission (`failed(version)`); anything else leaves the record as it is. Every other outcome writes
/// `claude_fetch`.
#[allow(clippy::too_many_arguments)]
async fn apply<F, Fut>(paths: &Paths, vm: &str, want: &ClaudeRef, outcome: &FetchOutcome, ms: u64, why: FetchWhy, session: Option<&str>, gen: Option<u32>, delete: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), BridgeError>>,
{
    let v = want.version.as_str();
    let this_object = |r: &Record| r.claude_ref().is_some_and(|c| c.sha256 == want.sha256);
    let update = |f: &dyn Fn(&mut Record)| {
        // Only the record of this very binary, and only while it exists: another sha256 under the version is no
        // object of this fetch, and a version forgotten while its fetch ran stays forgotten.
        if let Err(e) = Record::update_existing(paths, v, |r| {
            let mine = this_object(r);
            if mine {
                f(r);
            }
            mine
        }) {
            tracing::warn!(version = v, "the claude record was not updated: {e}");
        }
    };
    let now = crate::bridge::registry::now_rfc3339();
    match outcome {
        FetchOutcome::Cached | FetchOutcome::Image => return,
        FetchOutcome::Fetched { .. } => update(&|r| {
            if let Some(s) = r.staging.as_mut() {
                s.bad_stages = 0;
            }
        }),
        FetchOutcome::NotStaged => update(&|r| {
            if let Some(s) = r.staging.as_mut() {
                s.state = "absent".into();
                s.at.clone_from(&now);
            }
        }),
        FetchOutcome::ChecksumMismatch { got_len } => {
            let deleted = match delete().await {
                Ok(()) => "deleted",
                Err(e) => {
                    tracing::warn!(version = v, vm, "the claude object a VM refused was not deleted: {e}");
                    "delete_failed"
                }
            };
            let bad_stages = std::cell::Cell::new(0);
            update(&|r| {
                let s = r.staging.get_or_insert_with(|| crate::bridge::claude::StagingRow { s3_key: want.key().render(), ..crate::bridge::claude::StagingRow::default() });
                if s.state == "staged" {
                    // One stage counts once, whichever VMs report it.
                    s.bad_stages += 1;
                }
                s.bad_reports += 1;
                s.state = "stale".into();
                s.at.clone_from(&now);
                bad_stages.set(s.bad_stages);
                if s.bad_stages >= 2 {
                    if let Some(a) = r.admission.as_mut() {
                        a.outcome = "failed".into();
                        a.step = Some("stage".into());
                        a.at.clone_from(&now);
                    }
                }
            });
            let mut pairs = vec![("version", v.to_string()), ("sha256", want.sha256.clone()), ("vm", vm.to_string()), ("outcome", deleted.to_string())];
            pairs.extend(got_len.map(|n| ("got_len", n.to_string())));
            pairs.push(("bad_stages", bad_stages.get().to_string()));
            audit_event(paths, event::CLAUDE_OBJECT_BAD, &pairs);
        }
        FetchOutcome::VersionMismatch => update(&|r| {
            if let Some(a) = r.admission.as_mut() {
                a.outcome = "failed".into();
                a.step = Some("version".into());
                a.at.clone_from(&now);
            }
        }),
        FetchOutcome::Fetching | FetchOutcome::DiskFull | FetchOutcome::Failed(_) | FetchOutcome::NoCap => {}
    }
    let mut pairs = vec![("vm", vm.to_string()), ("version", v.to_string()), ("sha256", want.sha256.clone()), ("outcome", outcome.word().to_string()), ("ms", ms.to_string())];
    pairs.extend(session.map(|s| ("session", s.to_string())));
    pairs.extend(gen.map(|g| ("gen", g.to_string())));
    pairs.push(("why", why.word().to_string()));
    if let FetchOutcome::ChecksumMismatch { got_len: Some(n) } = outcome {
        pairs.push(("got_len", n.to_string()));
    }
    audit_event(paths, event::CLAUDE_FETCH, &pairs);
}

/// A copy of `ctx` for a task of its own.
fn ctx_of(ctx: &Ctx) -> Ctx {
    Ctx { paths: ctx.paths.clone(), cfg: ctx.cfg.clone(), knobs: ctx.knobs.clone() }
}

/// V's ref and size, when V is nameable now (the records read again: a stage may have finished since P0) and its
/// size is known.
fn nameable_v(paths: &Paths, plan: &SessionPlan) -> Option<(ClaudeRef, u64)> {
    let v = plan.claude.ext.as_deref()?;
    let now = super::plan_for(paths, Some(v));
    let want = now.prefs.first().filter(|r| r.version == v && now.why_not.is_none())?.clone();
    let size = *now.sizes.get(&want.sha256)?;
    Some((want, size))
}

/// The generation's fetch after its first output (`PipelineEnd.after_output`): `Some` only when V is nameable and the
/// VM names the cap; the link starts it only when V did not run (LD-6). `wait_s` 0, polled up to `CLAUDE_POLL_FOR`.
/// Its row names generation `gen` and the chat's session as `session` reads it once the fetch ended: a new chat's id
/// comes with its first turn's init, after the first output (the answer to the host's `initialize`) started the fetch.
#[must_use]
pub fn after_output<A: MicrovmApi + S3Sign + 'static>(plan: &SessionPlan, ctx: &Ctx, api: std::sync::Arc<A>, row: &VmRow, vm: &VmInfo, gen: u32, session: impl Fn() -> Option<String> + 'static) -> Option<AfterOutput> {
    if !row_has_cap(row) {
        return None;
    }
    let (want, size) = nameable_v(&plan.paths, plan)?;
    let (ctx, row, vm) = (ctx_of(ctx), row.clone(), vm.clone());
    Some(AfterOutput(Box::pin(async move {
        fetch_into(&ctx, &api, &row, &vm, &want, size, 0, CLAUDE_POLL_FOR, FetchWhy::AfterOutput, &session, Some(gen)).await;
    })))
}

/// A migration's phase A, after its delivery: the same fetch into the prepared VM, as a task of its own, never
/// awaited by phase A (LD-7); nothing unless V is nameable and the VM names the cap.
pub fn prefetch_phase_a<A: MicrovmApi + S3Sign + 'static>(plan: &SessionPlan, ctx: &Ctx, api: std::sync::Arc<A>, row: &VmRow, vm: &VmInfo) {
    if !row_has_cap(row) {
        return;
    }
    let Some((want, size)) = nameable_v(&plan.paths, plan) else { return };
    let (ctx, row, vm, session) = (ctx_of(ctx), row.clone(), vm.clone(), plan.resume.clone());
    tokio::task::spawn_local(async move {
        fetch_into(&ctx, &api, &row, &vm, &want, size, 0, CLAUDE_POLL_FOR, FetchWhy::PhaseA, &|| session.clone(), None).await;
    });
}

/// What `vm warm`'s claude step did (§4.6), for its line and its JSON field.
#[derive(Debug, Clone, PartialEq)]
pub struct WarmClaude {
    /// `cached`, `image`, `fetched`, `fetching`, `not_admitted`, `stage_failed`, `failed`, `no_cap`, `no_version`.
    pub word: &'static str,
    /// The text line `vm warm` prints (none when it prints JSON).
    pub line: Option<String>,
    /// `{"version","outcome","staged","ms"}`.
    pub json: serde_json::Value,
}

/// `vm warm`'s claude step (§4.6): stage V when admitted and not staged (`stage::ensure_staged`), then fetch it,
/// waiting at most `WARM_CLAUDE_WAIT` in all. A failure is a line, never the warm's exit. The two parts in a row:
/// [`warm_stage`], then [`warm_fetch`].
#[allow(clippy::too_many_arguments)]
pub async fn warm_claude<A: MicrovmApi + S3Sign + 'static, E: EndpointClient>(ctx: &Ctx, api: &std::sync::Arc<A>, ep: &E, row: &VmRow, vm: &VmInfo, caps: &[String], want: Option<&str>, prewarm: bool) -> WarmClaude {
    match warm_stage(ctx, api, ep, vm, caps, want).await {
        Ok(staged) => warm_fetch(ctx, api, row, vm, staged, prewarm).await,
        Err(said) => said,
    }
}

/// What the claude step's first part ([`warm_stage`]) leaves its fetch ([`warm_fetch`]): V, how long its staging
/// took (none when nothing was staged) and the step's start, which `WARM_CLAUDE_WAIT` counts from.
#[derive(Debug, Clone)]
pub struct WarmStaged {
    version: String,
    staged_in: Option<Duration>,
    t0: std::time::Instant,
}

/// The claude step's first part: V checked (a version, the image's cap), then staged when admitted and not staged.
/// `Err` is the step's outcome already (`no_version`, `no_cap`, `stage_failed`). It runs to its end under a stop
/// (`vm warm`): `ensure_staged` ends its stager VM.
pub async fn warm_stage<A: MicrovmApi + S3Sign + 'static, E: EndpointClient>(ctx: &Ctx, api: &std::sync::Arc<A>, ep: &E, vm: &VmInfo, caps: &[String], want: Option<&str>) -> Result<WarmStaged, WarmClaude> {
    let t0 = std::time::Instant::now();
    let Some(v) = want.filter(|v| crate::wire::pin::is_version(v)) else {
        return Err(warm_said("no_version", None, false, t0, "claude: no Cursor bundle; nothing to fetch".into()));
    };
    let id = vm.id.as_str();
    if !caps.iter().any(|c| c == CAP_CLAUDE_STAGE_V1) {
        return Err(warm_said("no_cap", Some(v), false, t0, format!("claude {v}: {id}'s image cannot fetch it (make deploy)")));
    }
    let mut staged_in = None;
    if super::needs_staging(&ctx.paths, v) {
        let t = std::time::Instant::now();
        match super::stage::ensure_staged(ctx, api, ep, v, false).await {
            Ok(_) => staged_in = Some(t.elapsed()),
            Err(e) => {
                tracing::warn!(version = v, "vm warm: staging claude failed: {e}");
                let why = outcome_of_error(&e, None);
                let why = match &why {
                    FetchOutcome::Failed(w) => w.clone(),
                    other => other.word().to_string(),
                };
                return Err(warm_said("stage_failed", Some(v), false, t0, format!("claude {v}: staging failed ({why}); {id} keeps its claude")));
            }
        }
    }
    Ok(WarmStaged { version: v.to_string(), staged_in, t0 })
}

/// The claude step's second part: V fetched into the VM, waiting what is left of `WARM_CLAUDE_WAIT`. A stop may
/// drop it (`vm warm`): the VM goes on fetching. A version not admitted names what admits it; a failed admission,
/// its step and the `--redo` (`admit::failed_line`).
pub async fn warm_fetch<A: MicrovmApi + S3Sign + 'static>(ctx: &Ctx, api: &std::sync::Arc<A>, row: &VmRow, vm: &VmInfo, staged: WarmStaged, prewarm: bool) -> WarmClaude {
    let WarmStaged { version, staged_in, t0 } = staged;
    let v = version.as_str();
    let id = vm.id.as_str();
    let plan = super::plan_for(&ctx.paths, Some(v));
    let Some((cref, size)) = plan.prefs.first().filter(|r| r.version == v && plan.why_not.is_none()).and_then(|r| plan.sizes.get(&r.sha256).map(|s| (r.clone(), *s))) else {
        let failed = plan.why_not.filter(|w| *w == "failed").and_then(|_| Record::load(&ctx.paths, v).ok().flatten()).and_then(|r| match r.phase() {
            super::Phase::Failed(step) => Some(super::admit::failed_line(v, &step, &r)),
            _ => None,
        });
        let line = match failed {
            Some(failed) => format!("{failed}; {id} keeps its claude"),
            None => format!("claude {v}: not admitted (ai-env claude admit {v}); {id} keeps its claude"),
        };
        return warm_said("not_admitted", Some(v), staged_in.is_some(), t0, line);
    };
    let left = WARM_CLAUDE_WAIT.saturating_sub(t0.elapsed());
    let wait_s = u32::try_from(left.as_secs()).unwrap_or(u32::MAX).min(CLAUDE_WAIT_MAX_S);
    let why = if prewarm { FetchWhy::Prewarm } else { FetchWhy::Warm };
    let outcome = fetch_into(ctx, api, row, vm, &cref, size, wait_s, left, why, &|| None, None).await;
    let secs = |d: Duration| format!("{:.1}", d.as_secs_f64());
    let staged = staged_in.is_some();
    match outcome {
        FetchOutcome::Cached => warm_said("cached", Some(v), staged, t0, format!("claude {v}: already cached on {id}")),
        FetchOutcome::Image => warm_said("image", Some(v), staged, t0, format!("claude {v}: the image's own (nothing to fetch)")),
        FetchOutcome::Fetched { ms } => {
            let fetched = secs(Duration::from_millis(ms));
            let line = match staged_in {
                Some(s) => format!("claude {v}: staged in {} s, fetched into {id} in {fetched} s", secs(s)),
                None => format!("claude {v}: fetched into {id} in {fetched} s"),
            };
            warm_said("fetched", Some(v), staged, t0, line)
        }
        FetchOutcome::Fetching => warm_said("fetching", Some(v), staged, t0, format!("claude {v}: still fetching after {} s; {id} goes on fetching it", secs(t0.elapsed()))),
        FetchOutcome::NoCap => warm_said("no_cap", Some(v), staged, t0, format!("claude {v}: {id}'s image cannot fetch it (make deploy)")),
        other => warm_said("failed", Some(v), staged, t0, format!("claude {v}: fetching into {id} failed ({}); {id} keeps its claude", other.word())),
    }
}

/// A [`WarmClaude`] of `word`: its line, and `{"version","outcome","staged","ms"}`.
fn warm_said(word: &'static str, version: Option<&str>, staged: bool, t0: std::time::Instant, line: String) -> WarmClaude {
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    WarmClaude { word, line: Some(line), json: serde_json::json!({ "version": version, "outcome": word, "staged": staged, "ms": ms }) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::claude::tests::put;
    use crate::bridge::claude::Phase;

    const VM: &str = "microvm-claude01";
    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn paths(dir: &std::path::Path) -> Paths {
        Paths::from_root_and_env(dir.join("bridge"), None)
    }

    fn rows(p: &Paths, event: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(p.audit()).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    fn want(v: &str, c: char) -> ClaudeRef {
        ClaudeRef { version: v.into(), sha256: c.to_string().repeat(64) }
    }

    fn on_local<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    /// Applies `outcome` for `w` with a delete that records its call and answers `ok`.
    fn applied(p: &Paths, w: &ClaudeRef, outcome: &FetchOutcome, ok: bool) -> bool {
        let called = std::cell::Cell::new(false);
        on_local(apply(p, VM, w, outcome, 1234, FetchWhy::AfterOutput, Some(SID), Some(1), || {
            called.set(true);
            async move {
                if ok {
                    Ok(())
                } else {
                    Err(BridgeError::Http { status: 403, body: "denied".into() })
                }
            }
        }));
        called.get()
    }

    /// A VM's 422 `checksum_mismatch`: the object deleted (the runtime key's DeleteObject), the record `stale`
    /// with the report and the stage counted, `claude_object_bad` and `claude_fetch` written (its session, in the
    /// envelope too, and its generation); a failed delete says so. `cached` and `image` change nothing and write
    /// nothing.
    #[test]
    fn a_422_deletes_the_object_and_marks_it_stale() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        put(&p, "2.1.310", 'b', "staged");
        let w = want("2.1.310", 'b');
        for quiet in [FetchOutcome::Cached, FetchOutcome::Image] {
            assert!(!applied(&p, &w, &quiet, true));
        }
        assert!(rows(&p, "claude_fetch").is_empty(), "no row for cached or image");
        assert!(applied(&p, &w, &FetchOutcome::ChecksumMismatch { got_len: Some(17) }, true), "the object is deleted");
        let r = Record::load(&p, "2.1.310").unwrap().unwrap();
        assert_eq!(r.phase(), Phase::Stale);
        let s = r.staging.unwrap();
        assert_eq!((s.state.as_str(), s.bad_reports, s.bad_stages), ("stale", 1, 1));
        let bad = rows(&p, "claude_object_bad");
        assert_eq!(bad.len(), 1);
        let mut detail = bad[0]["detail"].clone();
        detail.as_object_mut().unwrap().remove("actor");
        assert_eq!(detail, serde_json::json!({"version": "2.1.310", "sha256": "b".repeat(64), "vm": VM, "outcome": "deleted", "got_len": "17", "bad_stages": "1"}));
        let fetch = rows(&p, "claude_fetch");
        assert_eq!(fetch.len(), 1);
        assert_eq!((fetch[0]["detail"]["outcome"].as_str(), fetch[0]["detail"]["why"].as_str(), fetch[0]["detail"]["got_len"].as_str()), (Some("checksum_mismatch"), Some("after_output"), Some("17")));
        assert_eq!((fetch[0]["session_id"].as_str(), fetch[0]["detail"]["session"].as_str(), fetch[0]["detail"]["gen"].as_str()), (Some(SID), Some(SID), Some("1")));
        // A second VM's report of the same stage: counted as a report, never as a second stage; its delete failing is said.
        assert!(applied(&p, &w, &FetchOutcome::ChecksumMismatch { got_len: None }, false));
        let s = Record::load(&p, "2.1.310").unwrap().unwrap().staging.unwrap();
        assert_eq!((s.bad_reports, s.bad_stages), (2, 1));
        assert_eq!(rows(&p, "claude_object_bad")[1]["detail"]["outcome"], "delete_failed");
        // Another binary under the version is no object of this fetch: its record is left alone.
        put(&p, "2.1.311", 'c', "staged");
        applied(&p, &want("2.1.311", 'd'), &FetchOutcome::ChecksumMismatch { got_len: None }, true);
        assert_eq!(Record::load(&p, "2.1.311").unwrap().unwrap().phase(), Phase::Staged);
    }

    /// Two stages in a row a VM refused: the admission fails at `stage`, so a restage cannot loop; a VM's 201 in
    /// between resets the count.
    #[test]
    fn two_bad_stages_fail_the_stage() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        put(&p, "2.1.310", 'b', "staged");
        let w = want("2.1.310", 'b');
        let restage = |p: &Paths| Record::update(p, "2.1.310", |r| r.staging.as_mut().unwrap().state = "staged".into()).unwrap();
        applied(&p, &w, &FetchOutcome::ChecksumMismatch { got_len: None }, true);
        restage(&p);
        applied(&p, &w, &FetchOutcome::Fetched { ms: 900 }, true);
        assert_eq!(Record::load(&p, "2.1.310").unwrap().unwrap().staging.unwrap().bad_stages, 0, "a 201 resets the count");
        applied(&p, &w, &FetchOutcome::ChecksumMismatch { got_len: None }, true);
        assert_eq!(Record::load(&p, "2.1.310").unwrap().unwrap().phase(), Phase::Stale);
        restage(&p);
        applied(&p, &w, &FetchOutcome::ChecksumMismatch { got_len: None }, true);
        let r = Record::load(&p, "2.1.310").unwrap().unwrap();
        assert_eq!((r.phase().word(), r.nameable()), ("failed(stage)".to_string(), false));
        assert_eq!(rows(&p, "claude_object_bad").last().unwrap()["detail"]["bad_stages"], "2");
        assert_eq!(rows(&p, "claude_fetch").iter().filter(|r| r["detail"]["outcome"] == "fetched").count(), 1);
    }

    /// S3 answered the VM's GET 404: the object is absent, the version admitted again (not nameable), until a stage.
    #[test]
    fn a_404_marks_the_object_absent() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        put(&p, "2.1.310", 'b', "staged");
        assert!(!applied(&p, &want("2.1.310", 'b'), &FetchOutcome::NotStaged, true), "nothing to delete");
        let r = Record::load(&p, "2.1.310").unwrap().unwrap();
        assert_eq!((r.phase(), r.staging.unwrap().state.as_str()), (Phase::Admitted, "absent"));
        assert!(crate::bridge::claude::needs_staging(&p, "2.1.310"));
        assert_eq!(rows(&p, "claude_fetch")[0]["detail"]["outcome"], "not_staged");
        // A disk full, a cut transfer, a missing cap: a row, the record as it was.
        for o in [FetchOutcome::DiskFull, FetchOutcome::Failed("transfer_failed".into()), FetchOutcome::NoCap, FetchOutcome::Fetching] {
            applied(&p, &want("2.1.310", 'b'), &o, true);
        }
        assert_eq!(Record::load(&p, "2.1.310").unwrap().unwrap().phase(), Phase::Admitted);
        let words: Vec<String> = rows(&p, "claude_fetch").iter().map(|r| r["detail"]["outcome"].as_str().unwrap().to_string()).collect();
        assert_eq!(words, ["not_staged", "disk_full", "failed", "no_cap", "fetching"]);
        // A version forgotten while its fetch ran: no verdict writes its record back.
        for o in [FetchOutcome::NotStaged, FetchOutcome::Fetched { ms: 5 }, FetchOutcome::ChecksumMismatch { got_len: None }, FetchOutcome::VersionMismatch] {
            applied(&p, &want("2.1.399", 'e'), &o, true);
            assert_eq!(Record::load(&p, "2.1.399").unwrap(), None, "{o:?}");
        }
    }

    /// The VM found another version in the binary: its admission fails at `version`, never named again.
    #[test]
    fn a_version_mismatch_fails_the_admission() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        put(&p, "2.1.310", 'b', "staged");
        applied(&p, &want("2.1.310", 'b'), &FetchOutcome::VersionMismatch, true);
        let r = Record::load(&p, "2.1.310").unwrap().unwrap();
        assert_eq!((r.phase().word(), r.nameable()), ("failed(version)".to_string(), false));
        assert_eq!(super::super::plan_for(&p, Some("2.1.310")).why_not, Some("failed"));
        assert_eq!(rows(&p, "claude_fetch")[0]["detail"]["outcome"], "version_mismatch");
        // The answers judged: a 200 ready from the cache or the image, a 201, a poll's states, the refusals' codes.
        let t0 = std::time::Instant::now();
        let reply = |state, src, why: Option<&str>| ClaudeStageReply { state, src, why: why.map(str::to_string), got_len: Some(5), got_sha256: None, ms: Some(42) };
        assert_eq!(judge(200, &reply(ClaudeStageState::Ready, Some(ClaudeSrc::Cache), None), t0), Some(FetchOutcome::Cached));
        assert_eq!(judge(200, &reply(ClaudeStageState::Ready, Some(ClaudeSrc::Image), None), t0), Some(FetchOutcome::Image));
        assert_eq!(judge(201, &reply(ClaudeStageState::Ready, Some(ClaudeSrc::Cache), None), t0), Some(FetchOutcome::Fetched { ms: 42 }));
        assert_eq!(judge(202, &reply(ClaudeStageState::Fetching, None, None), t0), None);
        assert_eq!(judge(201, &reply(ClaudeStageState::Failed, None, Some("checksum_mismatch")), t0), Some(FetchOutcome::ChecksumMismatch { got_len: Some(5) }));
        assert_eq!(judge(201, &reply(ClaudeStageState::Failed, None, Some("version_mismatch")), t0), Some(FetchOutcome::VersionMismatch));
        assert_eq!(judge(201, &reply(ClaudeStageState::Absent, None, None), t0), Some(FetchOutcome::Failed("absent".into())));
        let failed = |code: &'static str| BridgeError::WorkspaceFailed { code, message: "x".into() };
        assert_eq!(outcome_of_error(&failed(refusal::NOT_STAGED), None), FetchOutcome::NotStaged);
        assert_eq!(outcome_of_error(&failed(refusal::DISK_FULL), None), FetchOutcome::DiskFull);
        assert_eq!(outcome_of_error(&failed(refusal::CHECKSUM_MISMATCH), Some(9)), FetchOutcome::ChecksumMismatch { got_len: Some(9) });
        assert_eq!(outcome_of_error(&BridgeError::NoCapability { cap: CAP_CLAUDE_STAGE_V1, message: "x".into() }, None), FetchOutcome::NoCap);
        assert_eq!(outcome_of_error(&BridgeError::Endpoint("https://bucket/key?X-Amz-Signature=s".into()), None), FetchOutcome::Failed("transport".into()), "a word, never the text");
    }
}
