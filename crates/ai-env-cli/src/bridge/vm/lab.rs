//! The live platform probes `ai-env lab run` drives (plan S4 §8): each starts
//! its own short VMs (max duration 900 s, audited internet egress, label
//! `probe:<name>`), measures, and terminates every VM it started on every
//! path — success, failure or error — before the verdict is recorded.
use crate::bridge::api::{EndpointClient, IdleSpec, MicrovmApi, VmInfo, APP_PORT};
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::cmd::Ctx;
use crate::bridge::vm::{health, run};
use crate::wire::frame::RunHookPayload;
use crate::wire::time::unix_now;
use std::time::{Duration, Instant};

/// What a live probe measured.
#[derive(Debug, Clone, Default)]
pub struct ProbeOutcome {
    pub verdict: String,
    pub note: String,
    pub claude: Option<String>,
    pub shim: Option<String>,
    pub image_version: Option<String>,
}

/// Run the live probe `name`.
pub async fn run_probe<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, name: &str) -> Result<ProbeOutcome, BridgeError> {
    let mut started: Vec<String> = Vec::new();
    let result = match name {
        "payload-size" => payload_size(ctx, api, ep, &mut started).await,
        "no-traffic-before-run" => no_traffic_before_run(ctx, api, ep, &mut started).await,
        "snapshot-uniqueness" => snapshot_uniqueness(ctx, api, ep, &mut started).await,
        "idle-policy-limits" => idle_policy_limits(ctx, api, ep, &mut started).await,
        other => Err(BridgeError::Config(format!("{other} is not a live probe"))),
    };
    // The terminate guard: every VM this probe started, whatever happened.
    for id in &started {
        match run::terminate_and_record(api, &ctx.paths, id, "probe", Some(run::Poll::SETTLE.scaled(ctx.knobs.backoff_ms))).await {
            Ok(_) => eprintln!("lab: terminated {id}"),
            Err(e) => eprintln!("lab: could not terminate {id}: {e} — run: ai-env vm terminate {id}"),
        }
    }
    result
}

fn flags(name: &str, idle_s: Option<u32>, suspended_s: Option<u32>, wait: bool) -> run::RunFlags {
    run::RunFlags {
        max_duration_s: Some(900),
        idle_s,
        suspended_s,
        label: Some(format!("probe:{name}")),
        wait,
        purpose: "probe",
        imply_internet: true,
        allow_out_of_range_idle: idle_s.is_some() || suspended_s.is_some(),
        ..run::RunFlags::default()
    }
}

fn plan(ctx: &Ctx, f: &run::RunFlags) -> Result<run::RunPlan, BridgeError> {
    run::RunPlan::from_cfg(&ctx.cfg, f)
}

/// SELECT_VM for a probe: whatever may be alive afterwards goes into
/// `started` (the terminate guard) — the VM of a success, the VM a failure
/// after RunMicrovm left behind, and the VM an ambiguous run turns out to
/// have created (the adoption sweep).
async fn start<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, p: &run::RunPlan, started: &mut Vec<String>) -> Result<VmInfo, BridgeError> {
    let since = unix_now();
    match run::select_vm_detailed(api, &ctx.paths, p, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await {
        Ok(run::Selected::Started { vm, .. }) => {
            started.push(vm.id.clone());
            Ok(vm)
        }
        Ok(run::Selected::Reused { vm, .. }) => Err(BridgeError::Config(format!("the probe reused {} (internal)", vm.id))),
        Err(f) => {
            guard_failure(ctx, api, ep, &f, since, started).await;
            Err(f.error)
        }
    }
}

async fn guard_failure<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, f: &run::SelectFailure, since: u64, started: &mut Vec<String>) {
    if let Some(id) = &f.started {
        started.push(id.clone());
    }
    if let Some(pending) = &f.kept_pending {
        if let Ok(run::Adoption::Adopted(id)) = run::adopt_after_ambiguous(api, ep, &ctx.paths, pending, since, run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms)).await {
            started.push(id);
        }
    }
}

async fn payload_size<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    let mut out = ProbeOutcome::default();
    let mut notes = Vec::new();
    let mut verdicts = Vec::new();
    for len in [RunHookPayload::MAX_BYTES, RunHookPayload::MAX_BYTES + 1] {
        let oversized = len > RunHookPayload::MAX_BYTES;
        // The normal placement path (count, pending row, adoption key) with the payload
        // padded to `len` bytes. The oversized run does not wait for RUNNING: the shim
        // refuses its /run (413), and the state that follows is what gets recorded.
        let mut p = plan(ctx, &flags("payload-size", None, None, !oversized))?;
        p.pad_payload_to = Some(len);
        let verdict = match start(ctx, api, ep, &p, started).await {
            Ok(vm) if !oversized => {
                let (h, _) = health::read_health(api, ep, &ctx.paths, &vm.id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
                notes.push(format!("{len}: {} RUNNING, /health run_hook_seen={}", vm.id, h.run_hook_seen));
                out.claude.clone_from(&h.claude_version);
                out.shim = Some(h.shim_version.clone());
                out.image_version = Some(vm.image_version.clone());
                if h.run_hook_seen { "accepted" } else { "accepted-but-no-run" }
            }
            Ok(vm) => {
                tokio::time::sleep(Duration::from_millis(ctx.knobs.backoff_ms.map_or(10_000, |ms| ms * 10))).await;
                let after = api.get(&vm.id).await.map_or_else(|e| e.to_string(), |v| format!("{}{}", v.state.as_str(), v.state_reason.map(|r| format!(" ({r})")).unwrap_or_default()));
                notes.push(format!("{len}: accepted by the API; {} then {after}", vm.id));
                "accepted"
            }
            Err(BridgeError::Validation(m)) => {
                notes.push(format!("{len}: ValidationException {m}"));
                "rejected"
            }
            Err(e) => return Err(e),
        };
        verdicts.push(format!("{len}={verdict}"));
    }
    out.verdict = verdicts.join(" ");
    out.note = notes.join("; ");
    Ok(out)
}

async fn no_traffic_before_run<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("no-traffic-before-run", None, None, false))?;
    let t_run = Instant::now();
    let vm = start(ctx, api, ep, &p, started).await?;
    // The budget starts when RunMicrovm answered; the note counts from the call.
    let t0 = Instant::now();
    let id = vm.id.clone();
    let step = Duration::from_millis(ctx.knobs.backoff_ms.map_or(250, |ms| (ms / 4).max(1)));
    let budget = Duration::from_millis(ctx.knobs.backoff_ms.map_or(60_000, |ms| ms * 60));
    let (mut attempts, mut states, mut token) = (0u32, Vec::<String>::new(), None);
    let mut out = ProbeOutcome::default();
    while attempts == 0 || t0.elapsed() < budget {
        attempts += 1;
        let cur = api.get(&id).await?;
        if states.last().map(String::as_str) != Some(cur.state.as_str()) {
            states.push(cur.state.as_str().to_string());
        }
        if cur.state.is_terminal() {
            return Err(BridgeError::Terminated(format!("{id} is {}", cur.state.as_str())));
        }
        if token.is_none() && !cur.endpoint.is_empty() {
            token = api.create_auth_token(&id, 5, APP_PORT).await.ok();
        }
        if let Some(tok) = &token {
            match ep.get_health(&cur.endpoint, tok, APP_PORT).await {
                Ok(r) if r.status == 200 => {
                    let h = r.health.ok_or_else(|| BridgeError::Http { status: 200, body: "no /health body".into() })?;
                    out.claude.clone_from(&h.claude_version);
                    out.shim = Some(h.shim_version.clone());
                    out.image_version = Some(cur.image_version.clone());
                    out.verdict = if h.run_hook_seen { "health-after-run" } else { "health-before-run" }.to_string();
                    out.note = format!("first 200 {} ms after RunMicrovm was called, {attempts} attempts; states seen {}", t_run.elapsed().as_millis(), states.join("→"));
                    return Ok(out);
                }
                Ok(r) if r.status == 401 || r.status == 403 => token = api.create_auth_token(&id, 5, APP_PORT).await.ok(),
                Ok(_) | Err(BridgeError::Endpoint(_)) => {}
                Err(e) => return Err(e),
            }
        }
        tokio::time::sleep(step).await;
    }
    Err(BridgeError::Sdk { op: "probe", message: format!("no /health 200 within {} s (states seen {})", budget.as_secs(), states.join("→")) })
}

async fn snapshot_uniqueness<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    let p = plan(ctx, &flags("snapshot-uniqueness", None, None, true))?;
    let poll = run::Poll::RUNNING.scaled(ctx.knobs.backoff_ms);
    let since = unix_now();
    let (a, b) = tokio::join!(run::select_vm_detailed(api, &ctx.paths, &p, poll), run::select_vm_detailed(api, &ctx.paths, &p, poll));
    // Every VM either run started is guarded before any error is returned.
    let mut ids = Vec::new();
    let mut first_error = None;
    for r in [a, b] {
        match r {
            Ok(run::Selected::Started { vm, .. }) => {
                started.push(vm.id.clone());
                ids.push(vm.id);
            }
            Ok(run::Selected::Reused { vm, .. }) => {
                first_error.get_or_insert(BridgeError::Config(format!("the probe reused {} (internal)", vm.id)));
            }
            Err(f) => {
                guard_failure(ctx, api, ep, &f, since, started).await;
                first_error.get_or_insert(f.error);
            }
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }
    let mut nonces = Vec::new();
    let mut out = ProbeOutcome::default();
    for id in &ids {
        let (h, _) = health::read_health(api, ep, &ctx.paths, id, health::Backoff::HEALTH.scaled(ctx.knobs.backoff_ms)).await?;
        nonces.push(h.boot_nonce.clone().unwrap_or_default());
        out.claude.clone_from(&h.claude_version);
        out.shim = Some(h.shim_version.clone());
    }
    out.image_version = Some(run::resolve_image_version(api, &p.image_arn, &p.want_version).await?.0.version);
    out.verdict = if nonces.iter().any(String::is_empty) {
        "nonce-missing"
    } else if nonces[0] != nonces[1] {
        "nonce-differs"
    } else {
        "nonce-same"
    }
    .to_string();
    out.note = format!("ids={} nonces={} (boot_ids: make logs SINCE=30m > FILE; ai-env lab run snapshot-uniqueness --log FILE)", ids.join(","), nonces.join(","));
    Ok(out)
}

async fn idle_policy_limits<A: MicrovmApi, E: EndpointClient>(ctx: &Ctx, api: &A, ep: &E, started: &mut Vec<String>) -> Result<ProbeOutcome, BridgeError> {
    let mut parts = Vec::new();
    let mut notes = Vec::new();
    for suspended in [900u32, 86_400] {
        let p = plan(ctx, &flags("idle-policy-limits", Some(300), Some(suspended), true))?;
        match start(ctx, api, ep, &p, started).await {
            Ok(vm) => {
                let echo = vm.idle.map(|i: IdleSpec| i.suspended_s);
                parts.push(match echo {
                    Some(e) if u32::try_from(e).ok() == Some(suspended) => format!("{suspended}=accepted"),
                    Some(e) => format!("{suspended}=accepted(echo {e})"),
                    None => format!("{suspended}=accepted(no echo)"),
                });
                notes.push(format!("{suspended}: {}", vm.id));
            }
            Err(BridgeError::Validation(m)) => {
                parts.push(format!("{suspended}=rejected"));
                notes.push(format!("{suspended}: ValidationException {m}"));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ProbeOutcome { verdict: parts.join(" "), note: format!("max duration 900 s, max idle 300 s; {}", notes.join("; ")), ..ProbeOutcome::default() })
}
