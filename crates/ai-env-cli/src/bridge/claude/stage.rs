//! S11 (A.2, D1, A2): the stager: an admitted version's linux-arm64 binary
//! relayed from the release into S3 (`v1/_claude/mac/<v>/<sha256>`) by a
//! fresh credential-less internet VM (`POST /claude/relay`), then the VM
//! ended whatever came of it. One ListObjectsV2 first: an object S3 holds
//! already is recorded, no VM started. A stale object (a VM refused it) or
//! `--force` deletes it first. The Mac never moves the bytes itself: S3
//! stores only what matches the signed length and sha256 (the presigned PUT
//! signs both, and `If-None-Match: *`).
use super::admit::{self, VersionLock};
use super::{Phase, Record, StagingRow, STAGER_MAX_DURATION_S};
use crate::bridge::api::{EndpointClient, MicrovmApi, VmInfo};
use crate::bridge::errors::BridgeError;
use crate::bridge::s3::client::S3Client;
use crate::bridge::s3::{S3Method, S3Sign, S3Target};
use crate::bridge::vm::cmd::Ctx;
use crate::bridge::vm::registry::VmRow;
use crate::bridge::vm::run::{self, Egress, Poll, RunFlags, RunPlan};
use crate::errors::CliError;
use crate::store::Keystore;
use crate::wire::frame::CAP_CLAUDE_STAGE_V1;
use crate::wire::workspace::{ClaudeRef, ClaudeRelay, ClaudeRelayReply, APP_PORT, CLAUDE_RELAY_ROUTE};
use std::sync::Arc;
use std::time::Instant;

/// The run purpose and the `terminated_by` word of a stager VM (LD-3).
pub const STAGER_PURPOSE: &str = "claude-stage";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// S3 answered 200 to the relay's PUT, and the listing holds it.
    Staged { version_id: Option<String> },
    /// 412: the key holds an object already; counted as staged, unverified (a VM's 422 later deletes a bad one).
    Exists,
    /// Already `staged`, nothing done (`--force` stages again: the object deleted first).
    AlreadyStaged,
}

impl StageOutcome {
    /// `staged`, `exists`, `already_staged`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            StageOutcome::Staged { .. } => "staged",
            StageOutcome::Exists => "exists",
            StageOutcome::AlreadyStaged => "already_staged",
        }
    }
}

/// What a stage needs of V's record: admitted (or staged, or stale), its ref and its signed size. Not admitted:
/// exit 9 naming the commands that admit it; a failed admission, exit 9 naming the `--redo` (neither `admit` nor
/// `update` admits it again without it).
fn admitted(paths: &crate::bridge::config::Paths, version: &str) -> Result<(Record, ClaudeRef, u64), BridgeError> {
    let not = || BridgeError::Cli(CliError::Policy(format!("claude {version} is not admitted: ai-env claude admit {version} (or ai-env claude update {version})")));
    let record = Record::load(paths, version)?.ok_or_else(not)?;
    match record.phase() {
        Phase::Admitted | Phase::Staged | Phase::Stale => {}
        Phase::Failed(step) => return Err(BridgeError::Cli(CliError::Policy(admit::failed_line(version, &step, &record)))),
        Phase::Seen | Phase::Signed => return Err(not()),
    }
    let r = record.claude_ref().ok_or_else(not)?;
    let size = record.signature.as_ref().and_then(|s| s.linux_size).filter(|s| *s > 0).ok_or_else(not)?;
    Ok((record, r, size))
}

/// One `claude_stage` row: `version`, `sha256`, `outcome`, `ms`, then `extra`.
pub(crate) fn audit(paths: &crate::bridge::config::Paths, version: &str, sha256: &str, outcome: &str, started: Instant, extra: &[(&str, String)]) {
    let mut pairs: Vec<(&str, String)> = vec![("version", version.to_string()), ("sha256", sha256.to_string()), ("outcome", outcome.to_string()), ("ms", started.elapsed().as_millis().to_string())];
    pairs.extend(extra.iter().cloned());
    crate::bridge::vm::cmd::audit_event(paths, crate::bridge::remote::audit_event::CLAUDE_STAGE, &pairs);
}

/// V's record staged at `key` (S3's version id, the stager), `bad_stages` kept, `bad_reports` cleared.
fn record_staged(paths: &crate::bridge::config::Paths, version: &str, key: &str, version_id: Option<String>, stager: Option<String>) -> Result<Record, BridgeError> {
    Record::update(paths, version, |r| {
        let prev = r.staging.take().unwrap_or_default();
        let same = prev.s3_key == key;
        r.staging = Some(StagingRow {
            state: "staged".into(),
            s3_key: key.to_string(),
            s3_version_id: version_id.or(if same && stager.is_none() { prev.s3_version_id } else { None }),
            stager_vm: stager.or(if same { prev.stager_vm } else { None }),
            bad_reports: 0,
            bad_stages: prev.bad_stages,
            at: crate::bridge::registry::now_rfc3339(),
        });
    })
}

/// The stager VM ended (TerminateMicrovm, its row `claude-stage`), whatever came of the relay; a failure is a
/// warning naming the command that ends it.
async fn end_stager<A: MicrovmApi>(ctx: &Ctx, api: &A, id: &str) {
    if let Err(e) = run::terminate_and_record(api, &ctx.paths, id, STAGER_PURPOSE, None).await {
        crate::bridge::voice::warn(&format!("the stager {id} was not terminated: {e}: ai-env vm terminate {id}"));
    }
}

/// The stager's part: `/health` naming `claude_stage_v1`, the presigned PUT of V's object, `POST /claude/relay`.
/// `Err` carries the step's word (`health`, `cap`, `presign`, `relay`).
#[allow(clippy::too_many_arguments)]
async fn relay_on<A: MicrovmApi + S3Sign + 'static, E: EndpointClient>(ctx: &Ctx, api: &Arc<A>, ep: &E, row: &VmRow, vm: &VmInfo, target: &S3Target, r: &ClaudeRef, size: u64) -> Result<ClaudeRelayReply, (&'static str, BridgeError)> {
    use crate::bridge::dataplane::{exchange, Exchange, Verdict};
    let (health, _) = crate::bridge::vm::health::read_health(&**api, ep, &ctx.paths, &vm.id, ctx.backoff()).await.map_err(|e| ("health", e))?;
    if !health.caps.iter().any(|c| c == CAP_CLAUDE_STAGE_V1) {
        let message = format!("{} (image version {}) cannot relay a claude: make deploy (an S11 image serves POST {CLAUDE_RELAY_ROUTE})", vm.id, vm.image_version);
        return Err(("cap", BridgeError::NoCapability { cap: CAP_CLAUDE_STAGE_V1, message }));
    }
    let headers = crate::bridge::s3::presign::write_headers(size, &r.sha256, true).map_err(|e| ("presign", e))?;
    let req = crate::bridge::s3::presign::request(S3Method::Put, target, Some(r.key().render()), Vec::new(), headers, crate::wire::s3::CLAUDE_EXPIRY);
    let put = api.presign(&req).await.map_err(|e| ("presign", e))?;
    let relay = ClaudeRelay { version: r.version.clone(), sha256: r.sha256.clone(), size, put, owner: target.owner.clone() };
    let mut row = row.clone();
    if row.endpoint.as_deref().is_none_or(str::is_empty) && !vm.endpoint.is_empty() {
        row.endpoint = Some(vm.endpoint.clone());
    }
    let agent = crate::bridge::agent::AgentTarget::from_row(&row).map_err(|e| ("relay", e))?;
    let dp = crate::bridge::dataplane::HttpsEndpoint::new(&ctx.knobs).map_err(|e| ("relay", e))?;
    let tokens = crate::bridge::dataplane::MintingTokens::new(Arc::clone(api), &ctx.paths, &vm.id, false);
    let route = "POST /claude/relay";
    let x = Exchange { api: &**api, tokens: &tokens, vm_id: &vm.id, port: APP_PORT, cap: CAP_CLAUDE_STAGE_V1, route, deadline: None, idempotent: false };
    let answer = exchange(&x, |t| {
        let (dp, agent, relay) = (&dp, &agent, &relay);
        async move { crate::bridge::dataplane::DataPlane::claude_relay(dp, agent, &t, relay).await }
    })
    .await
    .map_err(|e| ("relay", e))?;
    match answer {
        (reply, Verdict::Done) => reply.body.ok_or_else(|| ("relay", BridgeError::Protocol(format!("{route} answered HTTP {} without S3's answer", reply.status)))),
        (reply, _) => Err(("relay", BridgeError::Protocol(format!("{route} answered HTTP {} where S3's answer was due", reply.status)))),
    }
}

/// V staged, its lock held by the caller (the record read under it): §3.5.
async fn stage_locked<A: MicrovmApi + S3Sign + 'static, E: EndpointClient>(ctx: &Ctx, api: &Arc<A>, ep: &E, version: &str, force: bool) -> Result<StageOutcome, BridgeError> {
    let started = Instant::now();
    let (record, r, size) = admitted(&ctx.paths, version)?;
    let target = S3Target::resolve(&ctx.paths, &ctx.knobs)?;
    let key = r.key().render();
    let client = S3Client::new(&**api, &target)?;
    let stale = record.phase() == Phase::Stale;
    // One ListObjectsV2 first: what S3 holds already needs no VM.
    if client.holds(&key, size).await? && !stale && !force {
        record_staged(&ctx.paths, version, &key, None, None)?;
        return Ok(StageOutcome::AlreadyStaged);
    }
    if stale || force {
        client.delete(&key).await?;
        audit(&ctx.paths, version, &r.sha256, "deleted", started, &[("why", if force { "force" } else { "bad" }.to_string())]);
        // The record no longer names an object S3 holds: `absent` until the stager's answer, so a failure below
        // leaves no VM offered the deleted key (a stale record names none already).
        if !stale {
            Record::update(&ctx.paths, version, |r| {
                if let Some(s) = r.staging.as_mut() {
                    s.state = "absent".into();
                    s.at = crate::bridge::registry::now_rfc3339();
                }
            })?;
        }
    }
    // The stager: a fresh internet VM, never a credential (LD-38), against [vm].max_concurrent like any other.
    let flags = RunFlags {
        egress: Some(Egress::Internet),
        new: true,
        max_duration_s: Some(STAGER_MAX_DURATION_S),
        purpose: STAGER_PURPOSE,
        label: Some(format!("{STAGER_PURPOSE}:{version}")),
        workspace: None,
        ..RunFlags::default()
    };
    let plan = RunPlan::from_cfg(&ctx.cfg, &flags)?;
    let selected = match run::select_vm_detailed(&**api, &ctx.paths, &plan, ctx.poll(Poll::RUNNING)).await {
        Ok(s) => s,
        Err(f) => {
            let f = crate::bridge::vm::cmd::retry_gate_terminate(ctx, &**api, f).await;
            if let Some(id) = f.started.as_deref() {
                end_stager(ctx, &**api, id).await;
            }
            audit(&ctx.paths, version, &r.sha256, "failed", started, &[("step", "vm".to_string())]);
            return Err(f.error);
        }
    };
    let (row, vm) = match selected {
        run::Selected::Started { row, vm, .. } | run::Selected::Reused { row, vm, .. } => (row, vm),
    };
    let relayed = relay_on(ctx, api, ep, &row, &vm, &target, &r, size).await;
    end_stager(ctx, &**api, &vm.id).await;
    let reply = match relayed {
        Ok(reply) => reply,
        Err((step, e)) => {
            audit(&ctx.paths, version, &r.sha256, "failed", started, &[("vm", vm.id.clone()), ("step", step.to_string())]);
            return Err(e);
        }
    };
    let status = reply.s3_status.to_string();
    match reply.s3_status {
        200 if client.holds(&key, size).await? => {
            let version_id = reply.version_id.clone().filter(|v| !v.is_empty());
            record_staged(&ctx.paths, version, &key, version_id.clone(), Some(vm.id.clone()))?;
            audit(&ctx.paths, version, &r.sha256, "staged", started, &[("vm", vm.id.clone()), ("s3_status", status)]);
            Ok(StageOutcome::Staged { version_id })
        }
        200 => {
            audit(&ctx.paths, version, &r.sha256, "failed", started, &[("vm", vm.id.clone()), ("s3_status", status), ("step", "list".to_string())]);
            Err(BridgeError::Cli(CliError::Msg(format!("claude {version}: S3 answered 200 to the relay's PUT, but its listing does not hold {key} at {size} bytes: not staged"))))
        }
        412 => {
            record_staged(&ctx.paths, version, &key, None, Some(vm.id.clone()))?;
            audit(&ctx.paths, version, &r.sha256, "exists", started, &[("vm", vm.id.clone()), ("s3_status", status)]);
            Ok(StageOutcome::Exists)
        }
        s => {
            let code = reply.s3_code.as_deref().map(|c| format!(" {c}")).unwrap_or_default();
            audit(&ctx.paths, version, &r.sha256, "failed", started, &[("vm", vm.id.clone()), ("s3_status", status), ("step", "relay".to_string())]);
            Err(BridgeError::Cli(CliError::Msg(format!("claude {version}: S3 answered HTTP {s}{code} to the relay's PUT ({} of {size} bytes streamed): not staged", reply.len))))
        }
    }
}

/// V staged when admitted and not staged (or stale, or `force`): one ListObjectsV2 first, then a stager VM, the
/// relay, the VM's end, `holds()`. `cmd_stage`, `cmd_update` and `vm warm` (`fetch::warm_claude`) call it. Not
/// admitted: exit 9; the lock held: exit 1 (single flight per version).
pub async fn ensure_staged<A: MicrovmApi + S3Sign + 'static, E: EndpointClient>(ctx: &Ctx, api: &std::sync::Arc<A>, ep: &E, version: &str, force: bool) -> Result<StageOutcome, BridgeError> {
    admitted(&ctx.paths, version)?;
    let _lock = VersionLock::take_or_busy(&ctx.paths, version)?;
    stage_locked(ctx, api, ep, version, force).await
}

/// The stage of `cmd_stage` and `cmd_update`: the record and the lock before the Touch ID, then one Touch ID (the
/// runtime key) and [`stage_locked`]. Its outcome and the ms it took.
fn stage_now(store: &Keystore, version: &str, force: bool) -> crate::errors::Result<(StageOutcome, u64)> {
    let paths = crate::bridge::config::Paths::resolve()?;
    admitted(&paths, version)?;
    let _lock = VersionLock::take_or_busy(&paths, version)?;
    let ctx = Ctx::load()?;
    let started = Instant::now();
    let rt = crate::bridge::vm::cmd::runtime()?;
    let outcome = rt.block_on(async {
        let b = crate::bridge::vm::cmd::backend(store, &ctx).await?;
        let staged = match &b {
            crate::bridge::vm::cmd::Backend::Sdk(api, ep) => stage_locked(&ctx, api, &**ep, version, force).await,
            crate::bridge::vm::cmd::Backend::Fake(f) => stage_locked(&ctx, &Arc::new(f.clone()), f, version, force).await,
        };
        staged.map_err(CliError::from)
    });
    rt.shutdown_background();
    Ok((outcome?, u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)))
}

/// The JSON document of `stage` and `update`: `outcome` first (§7.1; a struct keeps its fields' order), `admitted`
/// only for `update`.
#[derive(Debug, serde::Serialize)]
struct StageDoc {
    outcome: &'static str,
    version: String,
    key: String,
    version_id: Option<String>,
    vm: Option<String>,
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    admitted: Option<&'static str>,
}

/// The outcome's line and JSON document, from the record as it stands.
fn said(version: &str, outcome: &StageOutcome, ms: u64) -> (String, StageDoc) {
    let paths = crate::bridge::config::Paths::resolve().ok();
    let staging = paths.as_ref().and_then(|p| Record::load(p, version).ok().flatten()).and_then(|r| r.staging);
    let key = staging.as_ref().map(|s| s.s3_key.clone()).unwrap_or_default();
    let vm = staging.as_ref().and_then(|s| s.stager_vm.clone());
    let line = match outcome {
        StageOutcome::Staged { version_id } => format!(
            "claude {version}: staged in S3 ({key}{}) through {} in {} s; VMs fetch it after a chat's first output",
            version_id.as_deref().map(|v| format!(", version {v}")).unwrap_or_default(),
            vm.as_deref().unwrap_or("the stager"),
            ms.div_ceil(1000)
        ),
        StageOutcome::Exists => format!("claude {version}: S3 already held {key} (412): counted as staged, unverified (a VM that refuses the object has it deleted)"),
        StageOutcome::AlreadyStaged => format!("claude {version}: already staged ({key}): nothing done (ai-env claude stage {version} --force stages it again)"),
    };
    let version_id = match outcome {
        StageOutcome::Staged { version_id } => version_id.clone(),
        _ => None,
    };
    let doc = StageDoc { outcome: outcome.word(), version: version.to_string(), key, version_id, vm, ms, admitted: None };
    (line, doc)
}

fn json_out(v: &impl serde::Serialize) -> crate::errors::Result<()> {
    crate::outln!("{}", serde_json::to_string_pretty(v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    Ok(())
}

/// `ai-env claude stage [V] [--force] [--json]`: exit 0 staged; 1 the relay or S3 failed, or the lock held; 3 or
/// 5 the Touch ID; 7 AWS or no cap; 8 the stager lost; 9 not admitted (before the Touch ID) or `max_concurrent`.
pub fn cmd_stage(store: &Keystore, version: Option<&str>, force: bool, json: bool) -> crate::errors::Result<()> {
    let version = admit::version_or_bundle(version, "stage")?;
    let (outcome, ms) = stage_now(store, &version, force)?;
    let (line, doc) = said(&version, &outcome, ms);
    if json {
        json_out(&doc)
    } else {
        crate::outln!("{line}");
        Ok(())
    }
}

/// `ai-env claude update [V] [--json]`: `admit` when the record is not admitted, then `ensure_staged` (one Touch ID):
/// `admit`'s exits, then `stage`'s.
pub fn cmd_update(store: &Keystore, version: Option<&str>, json: bool) -> crate::errors::Result<()> {
    let version = admit::version_or_bundle(version, "update")?;
    let paths = crate::bridge::config::Paths::resolve()?;
    let phase = Record::load(&paths, &version)?.map(|r| r.phase());
    let admitted_now = !matches!(phase, Some(Phase::Admitted | Phase::Staged | Phase::Stale));
    if admitted_now {
        let _ = crate::bridge::logging::init(&crate::bridge::logging::LogOpts { path: paths.cli_log(), rust_log: std::env::var("RUST_LOG").ok() });
        let cfg = crate::bridge::config::BridgeConfig::load(&paths)?.unwrap_or_default();
        let knobs = crate::bridge::lab::vm_knobs();
        admit::admit(&paths, &cfg, &knobs, &version, admit::AdmitOpts::default())?;
        if !json {
            crate::outln!("claude {version}: admitted (the release signature, the binary, its markers, the Docker tests)");
        }
    }
    let (outcome, ms) = stage_now(store, &version, false)?;
    let (line, mut doc) = said(&version, &outcome, ms);
    if json {
        doc.admitted = Some(if admitted_now { "now" } else { "already" });
        json_out(&doc)
    } else {
        crate::outln!("{line}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::claude::tests::put;
    use crate::bridge::config::Paths;

    /// Exit 9 before anything for a version not admitted: none, seen or signed names `admit` (or `update`); a failed
    /// admission names its step, why and the `--redo`, which neither of them runs by itself (T5).
    #[test]
    fn a_stage_refuses_an_unadmitted_version_naming_what_admits_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::from_root_and_env(dir.path().join("bridge"), None);
        put(&p, "2.1.307", 'b', "signed");
        put(&p, "2.1.306", 'a', "seen");
        put(&p, "2.1.309", 'd', "failed");
        put(&p, "2.1.310", 'e', "staged");
        let refusal = |v: &str| match admitted(&p, v) {
            Err(BridgeError::Cli(CliError::Policy(m))) => m,
            other => panic!("{v}: {other:?}"),
        };
        for v in ["2.1.305", "2.1.306", "2.1.307"] {
            assert_eq!(refusal(v), format!("claude {v} is not admitted: ai-env claude admit {v} (or ai-env claude update {v})"));
        }
        assert_eq!(refusal("2.1.309"), "claude 2.1.309: admission failed at markers (missing:auto_mode): fix it, then ai-env claude admit 2.1.309 --redo");
        let (record, r, size) = admitted(&p, "2.1.310").unwrap();
        assert_eq!((record.phase(), r.version.as_str(), size), (Phase::Staged, "2.1.310", 290));
    }
}
